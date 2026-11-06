//! The version 185 signing and signature verification sequences: `TPM2_SignSequenceStart`,
//! `TPM2_SignSequenceComplete`, `TPM2_VerifySequenceStart` and `TPM2_VerifySequenceComplete`
//! (TPM 2.0 Part 3, "Hash/HMAC/Event Sequences" and "Signing and Signature Verification").
//!
//! A sequence object of these commands ([`crate::SequenceType::Sign`] /
//! [`crate::SequenceType::Verify`]) is bound to the signing scheme and the Name of the key that
//! started it ([`crate::SignatureSequence`]) and accumulates the message with
//! `TPM2_SequenceUpdate`: as a running hash for a scheme that signs a digest of the message, or
//! as a running HMAC for `TPM_ALG_HMAC`, which signs the message itself. A verification sequence
//! also accumulates the running HMAC of its `TPM_ST_MESSAGE_VERIFIED` ticket, which covers the
//! message itself (Part 2, TPMT_TK_VERIFIED: HMAC(proof, (*tag* || *digestOrMessage* ||
//! *keyName* || *metadata*))), keyed with the proof of the hierarchy of the key at the start of
//! the sequence.

use crate::Platform;
use crate::handle_checks::{Tpmi, check};
use crate::handler::crypt_ops::{SignPositions, SignatureBuffers};
use crate::handler::sign_digest::{
    ecdaa_scheme_with_context, is_signing_object, key_sign_scheme, signature_matches_scheme,
    verified_ticket_hierarchy,
};
use crate::owned::{OwnedPublicParmsAndId, OwnedSensitiveData};
use crate::{SequenceType, SignatureSequence};
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::crypto::Crypto;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2bDigest, TpmaObject, TpmtSigScheme, TpmtSignature, TpmtTkVerified};

use super::TransientObject;
use super::sequence::{first_block_was_safe, ticket_is_safe};

/// Which kind of sequence a `TPM2_*SequenceStart` creates.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SequenceKind {
    Sign,
    Verify,
}

impl<'b, C: Crypto, P: Platform<Crypto = C>> CommandHandler<'b, P> {
    /// Handles the [TpmCc::SignSequenceStart] (`0x1AA`) command.
    ///
    /// # Description
    /// Starts a sequence that `TPM2_SignSequenceComplete` completes to sign a message with the
    /// scheme of `keyHandle`. The key's authorization is checked by
    /// `TPM2_SignSequenceComplete`, not here.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, version 185, Part 3: Commands, TPM2_SignSequenceStart:
    /// "If *keyHandle* does not refer to a signing key, the TPM shall return `TPM_RC_KEY`. If
    /// *keyHandle* refers to a key whose scheme is `TPM_ALG_NULL`, the TPM shall return
    /// `TPM_RC_SCHEME`." The errata for version 185 permit checking *x509sign* here ("it is
    /// acceptable for an implementation to perform this attribute check at the time of
    /// TPM2_SignSequenceStart()").
    ///
    /// # Response codes (in the order they are checked; the order and the codes the
    /// specification leaves open follow the TCG reference of version 185)
    /// - `TPM_RC_KEY` (`keyHandle`): not a signing key, or a restricted keyed-hash key ("it is
    ///   not possible to support *restricted* HMAC keys with `TPM2_SignSequenceComplete()`").
    /// - `TPM_RC_ATTRIBUTES` (`keyHandle`): *x509sign* is SET.
    /// - `TPM_RC_SCHEME` (`keyHandle`): no signing scheme of its own.
    /// - `TPM_RC_VALUE` (`context`): for an ECDAA key, a *context* that is not the 2-octet
    ///   commit counter ("If the scheme of *keyHandle* uses a counter value (e.g.,
    ///   TPM\_ALG\_ECDAA), then *context* shall contain the counter value from `TPM2_Commit()`");
    ///   for any other key but SM2 (whose *context* is `ID_A`), a non-empty *context*.
    /// - `TPM_RC_OBJECT_MEMORY`: no free sequence slot.
    pub fn sign_sequence_start(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<tpm2::commands::SignSequenceStart>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<tpm2::commands::SignSequenceStart>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let obj = self.resolve_object(key_handle.0, Position::handle(1))?;
        // Parameter 2: `context` (parameter 1 is `auth`): the commit counter of an ECDAA key,
        // empty for every other scheme.
        let scheme = signature_sequence_scheme(&obj, SequenceKind::Sign, cmd.context.get_buffer())?;
        if !scheme_takes_context(&scheme) && !cmd.context.get_buffer().is_empty() {
            return Err(TpmRc::VALUE.with(Position::parameter(2)));
        }
        let za = self.sm2_za(&obj, &scheme, cmd.context.get_buffer())?;

        let sequence = SignatureSequence {
            scheme,
            key_name: obj.name,
            hmac_key: hmac_key_of(&obj, &scheme)?,
            ticket_hierarchy: None,
            pre_hash: hash_mldsa_pre_hash(&obj),
        };
        let mu_state = mldsa_mu_prefix(&obj, cmd.context.get_buffer());
        let handle = self.start_signature_sequence(
            crate::owned::OwnedAuth::from(cmd.auth),
            SequenceType::Sign(sequence),
            None,
            za.as_ref().map(|(za, len)| &za[..*len]),
            mu_state,
        )?;

        let rsp = responses::SignSequenceStart {
            sequence_handle: Handle(handle),
        };
        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::VerifySequenceStart] (`0x1A9`) command.
    ///
    /// # Description
    /// Starts a sequence that `TPM2_VerifySequenceComplete` completes to verify a signature
    /// over a message with the scheme of `keyHandle`.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, version 185, Part 3: Commands,
    /// TPM2_VerifySequenceStart: "For `TPM_ALG_EDDSA`, *hint* contains the R value from the
    /// signature. For all other algorithms, *hint* must be zero-length. [...] If *keyHandle* does
    /// not refer to a signing key, the TPM shall return `TPM_RC_KEY`. If *keyHandle* refers to a
    /// key whose scheme is `TPM_ALG_NULL`, the TPM shall return `TPM_RC_SCHEME`."
    ///
    /// # Response codes (in the order they are checked; the order and the codes the
    /// specification leaves open follow the TCG reference of version 185)
    /// - `TPM_RC_KEY` (`keyHandle`): not a signing key, or a restricted keyed-hash key.
    /// - `TPM_RC_SCHEME` (`keyHandle`): no signing scheme of its own, or a split scheme.
    /// - `TPM_RC_KEY` (`keyHandle`): an HMAC key whose sensitive area is not loaded (the running
    ///   HMAC needs it).
    /// - `TPM_RC_VALUE` (`context`, then `hint`): a non-empty *context*/*hint* for a scheme
    ///   without a use for it.
    /// - The error of the hierarchy proof of the ticket (`TPM_RC_FW_LIMITED`,
    ///   `TPM_RC_SVN_LIMITED`).
    /// - `TPM_RC_OBJECT_MEMORY`: no free sequence slot.
    pub fn verify_sequence_start(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<tpm2::commands::VerifySequenceStart>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<tpm2::commands::VerifySequenceStart>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let obj = self.resolve_object(key_handle.0, Position::handle(1))?;
        let scheme = signature_sequence_scheme(&obj, SequenceKind::Verify, &[])?;
        // A keyed-hash key computes the running HMAC from its sensitive area.
        if matches!(scheme, TpmtSigScheme::Hmac(_)) && obj.public_only {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }
        // Parameters: `auth` (1), `hint` (2), `context` (3).
        if !scheme_takes_context(&scheme) && !cmd.context.get_buffer().is_empty() {
            return Err(TpmRc::VALUE.with(Position::parameter(3)));
        }
        if !cmd.hint.get_buffer().is_empty() {
            return Err(TpmRc::VALUE.with(Position::parameter(2)));
        }

        // The ticket covers the message, so its HMAC runs alongside the sequence, keyed with
        // the proof of the key's hierarchy now.
        let ticket_hierarchy = verified_ticket_hierarchy(&obj);
        let ticket_key = match ticket_hierarchy {
            Some(hierarchy) => Some(self.resolve_hierarchy_proof(hierarchy)?.0),
            None => None,
        };

        let sequence = SignatureSequence {
            scheme,
            key_name: obj.name,
            hmac_key: hmac_key_of(&obj, &scheme)?,
            ticket_hierarchy,
            pre_hash: hash_mldsa_pre_hash(&obj),
        };
        let mu_state = mldsa_mu_prefix(&obj, cmd.context.get_buffer());
        let za = self.sm2_za(&obj, &scheme, cmd.context.get_buffer())?;
        let handle = self.start_signature_sequence(
            crate::owned::OwnedAuth::from(cmd.auth),
            SequenceType::Verify(sequence),
            ticket_key.as_ref().map(|proof| proof.as_bytes()),
            za.as_ref().map(|(za, len)| &za[..*len]),
            mu_state,
        )?;

        let rsp = responses::VerifySequenceStart {
            sequence_handle: Handle(handle),
        };
        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Allocates the sequence object of a `TPM2_*SequenceStart` (`TPM_RC_OBJECT_MEMORY` if no
    /// slot is free), runs the self tests of the hashes it uses and, for a verification sequence
    /// with a ticket, starts the running ticket HMAC keyed with `ticket_key` (the hierarchy
    /// proof) with the ticket's *tag*. An SM2 sequence starts its message hash with `sm2_za`
    /// (`e := H(Z_A || M)`). Returns the handle of the new sequence.
    fn start_signature_sequence(
        &mut self,
        auth: crate::owned::OwnedAuth,
        sequence_type: SequenceType,
        ticket_key: Option<&[u8]>,
        sm2_za: Option<&[u8]>,
        mu_state: Option<crate::shake256::Shake256>,
    ) -> Result<u32, TpmRc> {
        let (index, handle) = self.context.state.find_empty_sequence_slot()?;
        self.context.self_test_sequence_start(&sequence_type)?;
        // `CryptoMldsa_SignSequenceStart()`/`CryptoMldsa_VerifySequenceStart()` test ML-DSA
        // before the message is absorbed.
        if mu_state.is_some() {
            self.do_self_test(tpm2::Alg::MLDSA)?;
        }
        let mut sequence = crate::ActiveSequence::new(handle, auth, sequence_type);
        sequence.mu_state = mu_state;
        if let Some(za) = sm2_za {
            sequence.hash_states[0].update(za);
        }
        if let Some(key) = ticket_key {
            let ticket_alg = super::context_integrity_hash_alg();
            self.context
                .crypto()
                .do_self_test(tpm2::Alg::from(ticket_alg))
                .map_err(|_| TpmRc::FAILURE)?;
            let mut inner = crate::hash_state::init_hmac_inner_state(ticket_alg, key);
            inner.update(&tpm2::TpmSt::MESSAGE_VERIFIED.id().to_be_bytes());
            sequence.hash_states[SignatureSequence::TICKET_INNER_STATE] = inner;
            sequence.hash_states[SignatureSequence::TICKET_OUTER_STATE] =
                crate::hash_state::init_hmac_outer_state(ticket_alg, key);
        }
        self.context.state.active_sequences[index] = Some(sequence);
        Ok(handle)
    }

    /// Handles the [TpmCc::SignSequenceComplete] (`0x1A4`) command.
    ///
    /// # Description
    /// Appends *buffer* to the message of the signing sequence `sequenceHandle` and signs the
    /// message with `keyHandle`, which must be the key that started the sequence. The sequence
    /// object is flushed.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, version 185, Part 3: Commands,
    /// TPM2_SignSequenceComplete: "The *x509sign* attribute of *keyHandle* must not be SET
    /// (`TPM_RC_ATTRIBUTES`). If the *restricted* attribute of *keyHandle* is SET, then
    /// *message* must not begin with `TPM_GENERATED_VALUE`. [...] If *keyHandle* refers to a key
    /// that is not the same as the key that was used to start the signature context, the TPM
    /// shall return `TPM_RC_SIGN_CONTEXT_KEY`." TPM2_SequenceUpdate: "If the sequence is intended
    /// to produce a digest that will be signed by a restricted signing key, then the first block
    /// of data shall contain at least size of(`TPM_GENERATED`) octets and the first octets shall
    /// not be `TPM_GENERATED_VALUE`."
    ///
    /// # Response codes (in the order they are checked)
    /// - `TPM_RC_MODE` (`sequenceHandle`): not a signing sequence.
    /// - `TPM_RC_SIGN_CONTEXT_KEY` (`keyHandle`): not the key (Name) that started the sequence.
    /// - `TPM_RC_ATTRIBUTES` (`keyHandle`): *x509sign* is SET.
    /// - `TPM_RC_VALUE` (`buffer`): a restricted key and a first block that is shorter than
    ///   `TPM_GENERATED_VALUE` or begins with it.
    ///
    /// After these checks the sequence is consumed (flushed) whether or not a signature is
    /// produced, as in the TCG reference.
    pub fn sign_sequence_complete(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<tpm2::commands::SignSequenceComplete>()?;
        let [sequence_handle, key_handle] = handles;
        check(sequence_handle, Tpmi::DhObject, Position::handle(1))?;
        check(key_handle, Tpmi::DhObject, Position::handle(2))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<tpm2::commands::SignSequenceComplete>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }
        let buffer = cmd.buffer.get_buffer();

        let (sequence, state, first_block_safe, mu_state) = {
            let seq = self.signature_sequence(sequence_handle.0)?;
            let SequenceType::Sign(sequence) = seq.sequence_type else {
                return Err(TpmRc::MODE.with(Position::handle(1)));
            };
            // The first block decides whether a restricted key may sign the message; if no
            // block was added yet, *buffer* is the first block.
            let safe = if seq.first_block {
                first_block_was_safe(seq)
            } else {
                ticket_is_safe(buffer)
            };
            (sequence, seq.hash_states[0], safe, seq.mu_state.clone())
        };
        let obj = self.sequence_key(key_handle.0, &sequence)?;
        if obj.public.object_attributes.contains(TpmaObject::X509_SIGN) {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(2)));
        }
        if obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED)
            && !first_block_safe
        {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }

        // The sequence is consumed from here on, whether or not a signature is produced (the
        // reference marks it `evict` before it finishes the running state).
        self.context
            .state
            .remove_active_sequence(sequence_handle.0)?;
        let mut state = state;
        state.update(buffer);

        let mut bufs = SignatureBuffers::new();
        let hmac;
        let mut mldsa_signature = [0u8; tpm2::TPM2_MAX_MLDSA_SIG_SIZE];
        let signature = match sequence.scheme {
            TpmtSigScheme::Mldsa | TpmtSigScheme::HashMldsa => {
                let mut mu = mu_state.ok_or(TpmRc::FAILURE)?;
                if let Some(pre_hash) = sequence.pre_hash {
                    #[cfg(feature = "mldsa")]
                    mu.update(crate::mldsa::pre_hash_oid(pre_hash).ok_or(TpmRc::FAILURE)?);
                    let (digest, len) = state.finalize();
                    mu.update(&digest[..len]);
                    let _ = pre_hash;
                } else {
                    mu.update(buffer);
                }
                let mut mu_bytes = [0u8; tpm2::TpmiMldsaParms::MU_BYTES];
                mu.finalize_into(&mut mu_bytes);
                let len = self.mldsa_sign_mu(&obj, &mu_bytes, &mut mldsa_signature)?;
                let sig = tpm2::Tpm2bSignatureMldsa::from_bytes(&mldsa_signature[..len])
                    .map_err(|_| TpmRc::FAILURE)?;
                match sequence.pre_hash {
                    Some(hash) => TpmtSignature::HashMldsa(tpm2::TpmsSignatureHashMldsa {
                        hash,
                        signature: sig,
                    }),
                    None => TpmtSignature::Mldsa(sig),
                }
            }
            TpmtSigScheme::Hmac(hash_alg) => {
                let (bytes, len) = crate::hash_state::finalize_hmac_from_inner_state(
                    hash_alg,
                    sequence.hmac_key.get_buffer(),
                    &state,
                );
                hmac = bytes;
                TpmtSignature::Hmac(
                    tpm2::TpmtHa::new(hash_alg, &hmac[..len]).ok_or(TpmRc::FAILURE)?,
                )
            }
            scheme => {
                let (digest, len) = state.finalize();
                // Defense in depth: a public-only object cannot be authorized for the USER role.
                if obj.private_len == 0 {
                    return Err(TpmRc::AUTH_UNAVAILABLE);
                }
                self.sign_with_scheme(
                    &obj,
                    &scheme,
                    &digest[..len],
                    SignPositions {
                        key: Position::handle(2),
                        digest: Position::parameter(1),
                        scheme: Position::handle(2),
                    },
                    &mut bufs,
                )?
            }
        };

        let rsp = responses::SignSequenceComplete { signature };
        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::VerifySequenceComplete] (`0x1A3`) command.
    ///
    /// # Description
    /// Verifies *signature* over the message of the verification sequence `sequenceHandle` with
    /// `keyHandle`, which must be the key that started the sequence, and returns a
    /// `TPM_ST_MESSAGE_VERIFIED` ticket. The sequence object is flushed if the signature is
    /// genuine; otherwise the command has no effect.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, version 185, Part 3: Commands,
    /// TPM2_VerifySequenceComplete: "If *keyHandle* refers to a key that is not the same as the
    /// key that was used to start the signature context, the TPM shall return
    /// `TPM_RC_SIGN_CONTEXT_KEY`. If the signature check succeeds, then the TPM will produce a
    /// `TPMT_TK_VERIFIED`. Otherwise, the TPM shall return `TPM_RC_SIGNATURE`. If the key is in
    /// the NULL hierarchy, then *hmac* in the ticket will be the Empty Buffer." and "The
    /// ticket's *tag* is `TPM_ST_MESSAGE_VERIFIED`." The signature is checked with the scheme of
    /// the key (Part 3, TPM2_PolicyAuthorize: "In all other cases, the signature scheme is as
    /// determined by the public parameters of the key"), so a signature of another scheme or
    /// hash is `TPM_RC_SCHEME`.
    ///
    /// # Response codes (in the order they are checked)
    /// - `TPM_RC_MODE` (`sequenceHandle`): not a verification sequence.
    /// - `TPM_RC_SIGN_CONTEXT_KEY` (`keyHandle`): not the key (Name) that started the sequence.
    /// - `TPM_RC_SCHEME` (`signature`): *signature* is not of the sequence's scheme and hash.
    /// - `TPM_RC_SIGNATURE` (`signature`): the signature is not genuine.
    pub fn verify_sequence_complete(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<tpm2::commands::VerifySequenceComplete>()?;
        let [sequence_handle, key_handle] = handles;
        check(sequence_handle, Tpmi::DhObject, Position::handle(1))?;
        check(key_handle, Tpmi::DhObject, Position::handle(2))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd =
            request.try_unmarshal_command::<tpm2::commands::VerifySequenceComplete>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let (sequence, message_state, ticket_inner, ticket_outer, mu_state) = {
            let seq = self.signature_sequence(sequence_handle.0)?;
            let SequenceType::Verify(sequence) = seq.sequence_type else {
                return Err(TpmRc::MODE.with(Position::handle(1)));
            };
            (
                sequence,
                seq.hash_states[0],
                seq.hash_states[SignatureSequence::TICKET_INNER_STATE],
                seq.hash_states[SignatureSequence::TICKET_OUTER_STATE],
                seq.mu_state.clone(),
            )
        };
        let obj = self.sequence_key(key_handle.0, &sequence)?;

        // The running states are finished on copies, so that a failed verification leaves the
        // sequence unchanged.
        if !signature_matches_scheme(&cmd.signature, &sequence.scheme)
            || !mldsa_signature_matches(&cmd.signature, sequence.pre_hash)
        {
            return Err(TpmRc::SCHEME.with(Position::parameter(1)));
        }
        match sequence.scheme {
            TpmtSigScheme::Mldsa | TpmtSigScheme::HashMldsa => {
                let mut mu = mu_state.ok_or(TpmRc::FAILURE)?;
                if let Some(pre_hash) = sequence.pre_hash {
                    #[cfg(feature = "mldsa")]
                    mu.update(crate::mldsa::pre_hash_oid(pre_hash).ok_or(TpmRc::FAILURE)?);
                    let (digest, len) = message_state.finalize();
                    mu.update(&digest[..len]);
                    let _ = pre_hash;
                }
                let mut mu_bytes = [0u8; tpm2::TpmiMldsaParms::MU_BYTES];
                mu.finalize_into(&mut mu_bytes);
                let sig = match &cmd.signature {
                    TpmtSignature::Mldsa(sig) => sig.get_buffer(),
                    TpmtSignature::HashMldsa(sig) => sig.signature.get_buffer(),
                    _ => return Err(TpmRc::SCHEME.with(Position::parameter(1))),
                };
                if !self.mldsa_verify_mu(&obj, &mu_bytes, sig)? {
                    return Err(TpmRc::SIGNATURE.with(Position::parameter(1)));
                }
            }
            TpmtSigScheme::Hmac(hash_alg) => {
                let (expected, len) = crate::hash_state::finalize_hmac_from_inner_state(
                    hash_alg,
                    sequence.hmac_key.get_buffer(),
                    &message_state,
                );
                let TpmtSignature::Hmac(ha) = &cmd.signature else {
                    return Err(TpmRc::SCHEME.with(Position::parameter(1)));
                };
                if !crate::util::constant_time_eq(ha.digest(), &expected[..len]) {
                    return Err(TpmRc::SIGNATURE.with(Position::parameter(1)));
                }
            }
            _ => {
                let (digest, len) = message_state.finalize();
                self.validate_signature(&obj, &digest[..len], &cmd.signature)
                    .map_err(|rc| rc.with_position(Position::parameter(1)))?;
            }
        }

        // The ticket: HMAC(proof, (TPM_ST_MESSAGE_VERIFIED || message || keyName)), whose
        // running HMAC (keyed when the sequence was started) already holds the tag and the
        // message. As for any ticket, the proof of a limited hierarchy must still be available
        // (`TPM_RC_FW_LIMITED`/`TPM_RC_SVN_LIMITED`).
        let ticket_hmac;
        let validation = match sequence.ticket_hierarchy {
            Some(hierarchy) => {
                self.resolve_hierarchy_proof(hierarchy)?;
                let mut inner = ticket_inner;
                inner.update(sequence.key_name.get_buffer());
                let (bytes, len) =
                    crate::hash_state::finalize_hmac_with_outer_state(&inner, &ticket_outer);
                ticket_hmac = bytes;
                TpmtTkVerified::MessageVerified(
                    Handle(hierarchy),
                    Tpm2bDigest::from_bytes(&ticket_hmac[..len]).map_err(|_| TpmRc::FAILURE)?,
                )
            }
            None => TpmtTkVerified::MessageVerified(Handle::RH_NULL, Tpm2bDigest::default()),
        };

        // The signature is genuine: the sequence has done its job.
        self.context
            .state
            .remove_active_sequence(sequence_handle.0)?;

        let rsp = responses::VerifySequenceComplete { validation };
        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// `Z_A` of an SM2 sequence (TPM 2.0 Part 1, "SM2 Sign"): `H(ENTL_A || ID_A || a || b || x_G
    /// || y_G || x_A || y_A)` with the scheme's hash `H`, the identity `ID_A` = *context*, `ENTL_A`
    /// "two octets containing the length of *ID_A* in octets", the curve coefficients and base
    /// point, and the key's public point (each coordinate the size of the field). `None` for any
    /// other scheme.
    fn sm2_za(
        &self,
        obj: &TransientObject,
        scheme: &TpmtSigScheme,
        id: &[u8],
    ) -> Result<Option<([u8; 64], usize)>, TpmRc> {
        if scheme.algorithm() != tpm2::Alg::SM2 {
            return Ok(None);
        }
        let (Some(hash_alg), OwnedPublicParmsAndId::Ecc(parms, point)) =
            (scheme.hash_alg(), &obj.public.parms_and_id)
        else {
            return Err(TpmRc::SCHEME.with(Position::handle(1)));
        };
        let curve = tpm2::crypto::ecc_curve_params(parms.curve_id).ok_or(TpmRc::CURVE.to_rc())?;
        let size = curve.p.len();
        let mut x = [0u8; 128];
        let mut y = [0u8; 128];
        for (out, coordinate) in [
            (&mut x, point.x.get_buffer()),
            (&mut y, point.y.get_buffer()),
        ] {
            if coordinate.len() > size {
                return Err(TpmRc::KEY.with(Position::handle(1)));
            }
            out[size - coordinate.len()..size].copy_from_slice(coordinate);
        }
        let entl = u16::try_from(id.len())
            .map_err(|_| TpmRc::VALUE.to_rc())?
            .to_be_bytes();
        self.compute_hash(
            hash_alg,
            &[
                &entl,
                id,
                curve.a,
                curve.b,
                curve.gx,
                curve.gy,
                &x[..size],
                &y[..size],
            ],
        )
        .map(Some)
    }

    /// The sequence object `handle` of a `TPM2_*SequenceComplete`: `TPM_RC_MODE` if `handle`
    /// is a loaded object that is not a sequence, `TPM_RC_HANDLE` if nothing is loaded there (as
    /// `TPM2_SequenceComplete`).
    fn signature_sequence(&mut self, handle: u32) -> Result<&crate::ActiveSequence, TpmRc> {
        if self.context.state.find_active_sequence(handle).is_none() {
            return Err(
                if self.resolve_object(handle, Position::handle(1)).is_ok() {
                    TpmRc::MODE.with(Position::handle(1))
                } else {
                    TpmRc::HANDLE.with(Position::handle(1))
                },
            );
        }
        self.context
            .state
            .find_active_sequence(handle)
            .ok_or(TpmRc::HANDLE.with(Position::handle(1)))
    }

    /// The key `handle` of a `TPM2_*SequenceComplete`, which must have the Name of the key that
    /// started `sequence` (`TPM_RC_SIGN_CONTEXT_KEY`; a sequence object's Name is the Empty
    /// Buffer, which never matches).
    fn sequence_key(
        &mut self,
        handle: u32,
        sequence: &SignatureSequence,
    ) -> Result<TransientObject, TpmRc> {
        if self.context.state.find_active_sequence(handle).is_some() {
            return Err(TpmRc::SIGN_CONTEXT_KEY.with(Position::handle(2)));
        }
        let obj = self.resolve_object(handle, Position::handle(2))?;
        if obj.name.get_buffer() != sequence.key_name.get_buffer() {
            return Err(TpmRc::SIGN_CONTEXT_KEY.with(Position::handle(2)));
        }
        Ok(obj)
    }
}

/// The key checks and the scheme of a `TPM2_SignSequenceStart` / `TPM2_VerifySequenceStart`
/// with the key `obj` (see their response codes). A signing sequence of an ECDAA key takes the
/// commit counter from `context` (2 octets, else `TPM_RC_VALUE` on `context`); the TPM cannot
/// verify ECDAA signatures (they are anonymous), so a verification sequence of an ECDAA key is
/// `TPM_RC_SCHEME`, like `TPM2_VerifySignature` of an ECDAA signature.
fn signature_sequence_scheme(
    obj: &TransientObject,
    kind: SequenceKind,
    context: &[u8],
) -> Result<TpmtSigScheme, TpmRc> {
    if !is_signing_object(obj) {
        return Err(TpmRc::KEY.with(Position::handle(1)));
    }
    // A restricted keyed-hash key signs digests (`TPM2_Sign` with a ticket), not messages.
    if matches!(
        obj.public.parms_and_id,
        OwnedPublicParmsAndId::KeyedHash(..)
    ) && obj
        .public
        .object_attributes
        .contains(TpmaObject::RESTRICTED)
    {
        return Err(TpmRc::KEY.with(Position::handle(1)));
    }
    if kind == SequenceKind::Sign && obj.public.object_attributes.contains(TpmaObject::X509_SIGN) {
        return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
    }
    if kind == SequenceKind::Sign
        && let Some(scheme) = ecdaa_scheme_with_context(obj, context)
    {
        return scheme.map_err(|()| TpmRc::VALUE.with(Position::parameter(2)));
    }
    key_sign_scheme(obj).ok_or_else(|| TpmRc::SCHEME.with(Position::handle(1)))
}

/// Whether a sequence with `scheme` takes a non-empty *context*: ECDAA (the commit counter,
/// checked by `signature_sequence_scheme`) and SM2 (the identity `ID_A`, Part 3 "SM2 ...
/// Signs/verifies the message using the provided *context* as *ID_A*").
fn scheme_takes_context(scheme: &TpmtSigScheme) -> bool {
    matches!(
        scheme.algorithm(),
        tpm2::Alg::ECDAA | tpm2::Alg::SM2 | tpm2::Alg::MLDSA | tpm2::Alg::HASH_MLDSA
    )
}

/// The pre-hash function of a HashML-DSA key (its `hashAlg`), `None` for any other key.
fn hash_mldsa_pre_hash(obj: &TransientObject) -> Option<tpm2::TpmiAlgHash> {
    match &obj.public.parms_and_id {
        OwnedPublicParmsAndId::HashMldsa(parms, _) => Some(parms.hash_alg),
        _ => None,
    }
}

/// The start of the computation of `mu` (FIPS 204 Algorithm 7 line 6) for an ML-DSA or
/// HashML-DSA key with the context string `context` (*context*, up to 255 octets): `tr || 0 ||
/// len(ctx) || ctx`, to which pure ML-DSA adds the message (Algorithm 2), or `tr || 1 || len(ctx)
/// || ctx`, to which HashML-DSA adds `OID || PH(M)` at the end (Algorithm 4). `None` for any other
/// key.
fn mldsa_mu_prefix(obj: &TransientObject, context: &[u8]) -> Option<crate::shake256::Shake256> {
    #[cfg(feature = "mldsa")]
    {
        let (_, public_key) = super::pqc::mldsa_key(obj)?;
        let domain: u8 = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::HashMldsa(..) => 1,
            _ => 0,
        };
        let mut shake = crate::mldsa::mu_start(public_key);
        shake.update(&[domain, u8::try_from(context.len()).ok()?]);
        shake.update(context);
        Some(shake)
    }
    #[cfg(not(feature = "mldsa"))]
    {
        let _ = (obj, context);
        None
    }
}

/// The HMAC key of a sequence with scheme `scheme` and key `obj`: the key's sensitive area for
/// `TPM_ALG_HMAC`, empty otherwise.
fn hmac_key_of(obj: &TransientObject, scheme: &TpmtSigScheme) -> Result<OwnedSensitiveData, TpmRc> {
    if matches!(scheme, TpmtSigScheme::Hmac(_)) {
        OwnedSensitiveData::from_bytes(&obj.private[..obj.private_len]).map_err(|_| TpmRc::FAILURE)
    } else {
        Ok(OwnedSensitiveData::default())
    }
}

/// For a HashML-DSA sequence (pre-hash `pre_hash`), whether `signature` is a HashML-DSA
/// signature with that pre-hash (`TpmtSignature::hash_alg` does not cover it); `true` for the other
/// sequences, whose scheme `signature_matches_scheme` checks.
fn mldsa_signature_matches(
    signature: &TpmtSignature<'_>,
    pre_hash: Option<tpm2::TpmiAlgHash>,
) -> bool {
    match (pre_hash, signature) {
        (Some(hash), TpmtSignature::HashMldsa(sig)) => sig.hash == hash,
        (Some(_), _) => false,
        (None, _) => true,
    }
}
