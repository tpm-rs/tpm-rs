//! The version 185 digest signing commands `TPM2_SignDigest` and `TPM2_VerifyDigestSignature`
//! (TPM 2.0 Part 3, "Signing and Signature Verification"), and the key and scheme checks they
//! share with the signing and verification sequences (`signature_sequence.rs`).
//!
//! Unlike the deprecated `TPM2_Sign`/`TPM2_VerifySignature`, these commands always use the
//! scheme of the key ("Overriding the scheme of the key is not supported"), only accept keys
//! whose scheme signs a digest (Part 3, @tbl:signing-commands-overview: HMAC is "Not supported"),
//! take a signing *context* (which only ML-DSA uses) and, for verification, produce a
//! `TPM_ST_DIGEST_VERIFIED` ticket that records the hash algorithm of the verified digest.

use crate::handle_checks::{Tpmi, check};
use crate::handler::crypt_ops::{SignPositions, SignatureBuffers, select_sign_scheme};
use crate::owned::OwnedPublicParmsAndId;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::crypto::{Crypto, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, Tpm2bDigest, TpmaObject, TpmtSigScheme, TpmtSignature, TpmtTkVerified};

use super::TransientObject;

/// `IsSigningObject()`: the object has the *sign* attribute and is not a symmetric cipher key.
pub(crate) fn is_signing_object(obj: &TransientObject) -> bool {
    obj.public
        .object_attributes
        .contains(TpmaObject::SIGN_ENCRYPT)
        && !matches!(obj.public.parms_and_id, OwnedPublicParmsAndId::Sym(..))
}

/// The signing scheme of the key itself (`CryptSelectSignScheme()` with a `TPM_ALG_NULL`
/// *inScheme*): `None` if the key has no signing scheme of its own, if its scheme is not valid
/// for its type or if it is a split signing scheme (ECDAA), whose counter the version 185
/// signing commands take from *context* ([`ecdaa_scheme_with_context`]).
pub(crate) fn key_sign_scheme(obj: &TransientObject) -> Option<TpmtSigScheme> {
    match &obj.public.parms_and_id {
        // An ML-DSA key has no scheme selector: its parameter set describes how it signs.
        OwnedPublicParmsAndId::Mldsa(..) => Some(TpmtSigScheme::Mldsa),
        OwnedPublicParmsAndId::HashMldsa(..) => Some(TpmtSigScheme::HashMldsa),
        parms => select_sign_scheme(parms, None),
    }
}

/// The ECDAA scheme of an ECDAA key `obj` with the commit counter in `context`: TPM 2.0 Part 2,
/// TPMU_SIGNATURE_CTX: "commitCount\[sizeof(UINT16)\] | BYTE | `TPM_ALG_ECDAA` | the counter
/// value that is used between `TPM2_Commit()` and the sign operation" (big-endian, like the
/// `count` of a `TPMS_SCHEME_ECDAA`). `None` if the key's scheme is not ECDAA; `Some(Err(()))`
/// if `context` is not a counter (2 octets).
pub(crate) fn ecdaa_scheme_with_context(
    obj: &TransientObject,
    context: &[u8],
) -> Option<Result<TpmtSigScheme, ()>> {
    let OwnedPublicParmsAndId::Ecc(parms, _) = &obj.public.parms_and_id else {
        return None;
    };
    let Some(tpm2::TpmtEccScheme::Ecdaa(key_scheme)) = parms.scheme else {
        return None;
    };
    let Ok(count) = <[u8; 2]>::try_from(context) else {
        return Some(Err(()));
    };
    let scheme = TpmtSigScheme::Ecdaa(tpm2::TpmsSchemeEcdaa {
        hash_alg: key_scheme.hash_alg,
        count: u16::from_be_bytes(count),
    });
    // The key's scheme with the caller's counter (`CryptSelectSignScheme()` keeps the counter of
    // a matching input scheme), which also checks the hash.
    Some(select_sign_scheme(&obj.public.parms_and_id, Some(scheme)).ok_or(()))
}

/// Whether `signature` was made with the scheme `scheme` (the same algorithm and the same hash
/// algorithm).
pub(crate) fn signature_matches_scheme(
    signature: &TpmtSignature<'_>,
    scheme: &TpmtSigScheme,
) -> bool {
    signature.sig_alg() == scheme.algorithm() && signature.hash_alg() == scheme.hash_alg()
}

/// The hierarchy of the ticket that a signature verification with `obj` produces, or `None`
/// for a NULL Ticket.
///
/// TPM 2.0 Part 3, TPM2_VerifyDigestSignature/TPM2_VerifySequenceComplete (like
/// TPM2_VerifySignature): "If the key is in the NULL hierarchy, then *hmac* in the ticket will be
/// the Empty Buffer"; a key with nameAlg `TPM_ALG_NULL` has no Name to put in the ticket. A key
/// in a firmware-limited or SVN-limited hierarchy (including their NULL hierarchies) gets a
/// ticket of that hierarchy, with its derived proof (C `GetHierarchy()` returns the object's own
/// hierarchy).
pub(crate) fn verified_ticket_hierarchy(obj: &TransientObject) -> Option<u32> {
    let hierarchy = obj.hierarchy;
    let real = matches!(
        Handle(hierarchy),
        Handle::RH_OWNER | Handle::RH_PLATFORM | Handle::RH_ENDORSEMENT
    ) || crate::hierarchy::is_limited(hierarchy);
    (real && obj.public.name_alg.is_some()).then_some(hierarchy)
}

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::SignDigest] (`0x1A6`) command.
    ///
    /// # Description
    /// Signs an externally provided digest with the scheme of the signing key `keyHandle`.
    /// Signing with a restricted key requires a valid `TPMT_TK_HASHCHECK` *validation* showing
    /// that the TPM computed *digest* over a message that does not begin with
    /// `TPM_GENERATED_VALUE`.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, version 185, Part 3: Commands, TPM2_SignDigest: "This
    /// command is like `TPM2_SignSequenceComplete()`, except that it signs a digest of a message
    /// instead of the raw message. [...] The scheme of *keyHandle* must be a signing scheme that
    /// supports signing a digest (e.g., TPM\_ALG\_ECDSA, but not TPM\_ALG\_HMAC). The size of
    /// *digest* must match the size of the hash algorithm of the signing scheme."
    ///
    /// # Response codes (in the order they are checked)
    /// - `TPM_RC_KEY` (`keyHandle`): not a signing key.
    /// - `TPM_RC_ATTRIBUTES` (`keyHandle`): the key has *x509sign* SET (as `TPM2_Sign`).
    /// - `TPM_RC_VALUE` (`context`): for an ECDAA key, a *context* that is not the 2-octet
    ///   commit counter (Part 2, TPMU_SIGNATURE_CTX `commitCount`); for any other key, a
    ///   non-empty *context* (no other scheme has a use for it).
    /// - `TPM_RC_SCHEME` (`keyHandle`): the key has no signing scheme of its own, or
    ///   `TPM_ALG_HMAC`, which signs a message, not a digest.
    /// - `TPM_RC_TICKET` (`validation`) / `TPM_RC_SIZE` (`digest`): as `TPM2_Sign`.
    ///
    /// # Relationships
    /// - Shares the signing core with [TpmCc::Sign](crypt_ops.rs) (`sign_with_scheme`).
    /// - The `validation` ticket comes from [TpmCc::Hash](sequence.rs) or
    ///   [TpmCc::SequenceComplete](sequence.rs).
    pub fn sign_digest(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<tpm2::commands::SignDigest>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<tpm2::commands::SignDigest>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // A sequence object is not a signing key (`resolve_object` reports `TPM_RC_KEY`).
        let obj = self.resolve_object(key_handle.0, Position::handle(1))?;
        if !is_signing_object(&obj) {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }
        // "A key that will be used for x.509 signatures can't be used in TPM2_SignDigest()."
        if obj.public.object_attributes.contains(TpmaObject::X509_SIGN) {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }
        #[cfg(feature = "mldsa")]
        if super::pqc::mldsa_key(&obj).is_some() {
            let mut buf = [0u8; tpm2::TPM2_MAX_MLDSA_SIG_SIZE];
            let signature = self.sign_digest_mldsa(&obj, &cmd, &mut buf)?;
            let rsp = responses::SignDigest { signature };
            let response = request.into_response();
            self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
            return Ok(());
        }
        // *context* "requires a supporting signing scheme": ECDAA takes its commit counter from
        // it; no other scheme of an RSA, ECC or keyed-hash key has a use for it.
        let scheme = match ecdaa_scheme_with_context(&obj, cmd.context.get_buffer()) {
            Some(scheme) => scheme.map_err(|()| TpmRc::VALUE.with(Position::parameter(1)))?,
            None => {
                if !cmd.context.get_buffer().is_empty() {
                    return Err(TpmRc::VALUE.with(Position::parameter(1)));
                }
                key_sign_scheme(&obj)
                    .filter(|scheme| !matches!(scheme, TpmtSigScheme::Hmac(_)))
                    .ok_or_else(|| TpmRc::SCHEME.with(Position::handle(1)))?
            }
        };
        let hash_alg = scheme
            .hash_alg()
            .ok_or_else(|| TpmRc::SCHEME.with(Position::handle(1)))?;

        // As in TPM2_Sign: a provided ticket, or any ticket for a restricted key, must be a valid
        // TPMT_TK_HASHCHECK for *digest* with the hash of the scheme; otherwise the digest must at
        // least have the size of that hash.
        let restricted = obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED);
        if cmd.validation.digest().get_size() != 0 || restricted {
            let ticket_hmac = self.compute_hashcheck_ticket(
                cmd.validation.hierarchy(),
                hash_alg,
                cmd.digest.get_buffer(),
            )?;
            if cmd.validation.digest().get_buffer() != ticket_hmac.get_buffer() {
                return Err(TpmRc::TICKET.with(Position::parameter(3)));
            }
        } else if cmd.digest.get_size() as usize != hash_alg.digest_size() {
            return Err(TpmRc::SIZE.with(Position::parameter(2)));
        }

        // Defense in depth: a public-only object cannot be authorized for the USER role.
        if obj.private_len == 0 {
            return Err(TpmRc::AUTH_UNAVAILABLE);
        }

        let mut bufs = SignatureBuffers::new();
        let signature = self.sign_with_scheme(
            &obj,
            &scheme,
            cmd.digest.get_buffer(),
            SignPositions {
                key: Position::handle(1),
                digest: Position::parameter(2),
                scheme: Position::handle(1),
            },
            &mut bufs,
        )?;

        let rsp = responses::SignDigest { signature };
        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::VerifyDigestSignature] (`0x1A5`) command.
    ///
    /// # Description
    /// Verifies a signature over a digest with the scheme of the loaded key `keyHandle` and
    /// returns a `TPM_ST_DIGEST_VERIFIED` ticket.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, version 185, Part 3: Commands,
    /// TPM2_VerifyDigestSignature: "The scheme of *keyHandle* must be a signing scheme that
    /// supports signing a digest (e.g., TPM\_ALG\_ECDSA). The size of *digest* must match the size
    /// of the hash algorithm of the signing scheme. The TPM will verify that the signing scheme
    /// (including the hash or XOF algorithm) in *signature* matches the signing scheme of
    /// *keyHandle* (TPM_RC_SCHEME)." and "*tag* will be `TPM_ST_DIGEST_VERIFIED`". Part 2,
    /// TPMT_TK_VERIFIED: the ticket is HMAC(proof, (*tag* || *digestOrMessage* || *keyName* ||
    /// *metadata*)), the *metadata* of `TPM_ST_DIGEST_VERIFIED` being "The hash algorithm or XOF
    /// used to produce the digest that was verified".
    ///
    /// # Response codes (in the order they are checked)
    /// - `TPM_RC_ATTRIBUTES` (`keyHandle`): the key does not have *sign* SET (as
    ///   `TPM2_VerifySignature`).
    /// - `TPM_RC_VALUE` (`context`): a non-empty *context*.
    /// - `TPM_RC_SCHEME` (`keyHandle`): the key has no signing scheme of its own, a split scheme
    ///   (ECDAA) or `TPM_ALG_HMAC`.
    /// - `TPM_RC_SIZE` (`digest`): *digest* is not the size of the scheme's hash.
    /// - `TPM_RC_SCHEME` (`signature`): *signature* is not of the key's scheme and hash.
    /// - `TPM_RC_SIGNATURE` (`signature`): the signature is not genuine.
    ///
    /// # Relationships
    /// - Verifies like [TpmCc::VerifySignature](crypt_ops.rs) (`validate_signature`).
    /// - The ticket is accepted by [TpmCc::PolicyAuthorize](policy_authorize.rs).
    pub fn verify_digest_signature(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<tpm2::commands::VerifyDigestSignature>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd =
            request.try_unmarshal_command::<tpm2::commands::VerifyDigestSignature>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // A sequence object has no *sign* attribute (as in TPM2_VerifySignature).
        if self
            .context
            .state
            .find_active_sequence(key_handle.0)
            .is_some()
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }
        let obj = self.resolve_object(key_handle.0, Position::handle(1))?;
        // The object to validate the signature must be a signing key.
        if !obj
            .public
            .object_attributes
            .contains(TpmaObject::SIGN_ENCRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }
        #[cfg(feature = "mldsa")]
        if super::pqc::mldsa_key(&obj).is_some() {
            let ticket_hmac;
            let validation = match self.verify_digest_mldsa(&obj, &cmd)? {
                // HashML-DSA: an ordinary `TPM_ST_DIGEST_VERIFIED` ticket of the pre-hash.
                Some(hash_alg) => match verified_ticket_hierarchy(&obj) {
                    Some(hierarchy) => {
                        ticket_hmac = self.compute_verified_ticket_with_meta(
                            hierarchy,
                            tpm2::TpmSt::DIGEST_VERIFIED.id(),
                            cmd.digest.get_buffer(),
                            obj.name.get_buffer(),
                            &tpm2::Alg::from(hash_alg).id().to_be_bytes(),
                        )?;
                        TpmtTkVerified::DigestVerified(
                            Handle(hierarchy),
                            hash_alg,
                            Tpm2bDigest::from_bytes(ticket_hmac.get_buffer())
                                .map_err(|_| TpmRc::FAILURE)?,
                        )
                    }
                    None => TpmtTkVerified::DigestVerified(
                        Handle::RH_NULL,
                        hash_alg,
                        Tpm2bDigest::default(),
                    ),
                },
                // External mu: a NULL Ticket (errata for version 185, "Ticket produced by
                // `TPM2_VerifyDigestSignature()` for ML-DSA": a mu ticket "is not useful to
                // [...] `TPM2_PolicyAuthorize()`", so "it is preferable for the TPM to return a
                // NULL `TPMT_TK_VERIFIED` ticket instead"). Its metadata would be SHAKE256, which
                // is not a `TPMI_ALG_HASH` of this TPM; it is the key's nameAlg (or the context
                // integrity hash for a key without one).
                None => TpmtTkVerified::DigestVerified(
                    Handle::RH_NULL,
                    obj.public
                        .name_alg
                        .unwrap_or_else(super::context_integrity_hash_alg),
                    Tpm2bDigest::default(),
                ),
            };
            let rsp = responses::VerifyDigestSignature { validation };
            let response = request.into_response();
            self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
            return Ok(());
        }
        if !cmd.context.get_buffer().is_empty() {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }
        let scheme = key_sign_scheme(&obj)
            .filter(|scheme| !matches!(scheme, TpmtSigScheme::Hmac(_)))
            .ok_or_else(|| TpmRc::SCHEME.with(Position::handle(1)))?;
        let hash_alg = scheme
            .hash_alg()
            .ok_or_else(|| TpmRc::SCHEME.with(Position::handle(1)))?;
        if cmd.digest.get_size() as usize != hash_alg.digest_size() {
            return Err(TpmRc::SIZE.with(Position::parameter(2)));
        }
        if !signature_matches_scheme(&cmd.signature, &scheme) {
            return Err(TpmRc::SCHEME.with(Position::parameter(3)));
        }

        // CryptValidateSignature(): TPM_RC_SCHEME, TPM_RC_HANDLE or TPM_RC_SIGNATURE, reported
        // against the `signature` parameter.
        self.validate_signature(&obj, cmd.digest.get_buffer(), &cmd.signature)
            .map_err(|rc| rc.with_position(Position::parameter(3)))?;

        let ticket_hmac;
        let validation = match verified_ticket_hierarchy(&obj) {
            Some(hierarchy) => {
                ticket_hmac = self.compute_verified_ticket_with_meta(
                    hierarchy,
                    tpm2::TpmSt::DIGEST_VERIFIED.id(),
                    cmd.digest.get_buffer(),
                    obj.name.get_buffer(),
                    &tpm2::Alg::from(hash_alg).id().to_be_bytes(),
                )?;
                TpmtTkVerified::DigestVerified(
                    Handle(hierarchy),
                    hash_alg,
                    Tpm2bDigest::from_bytes(ticket_hmac.get_buffer())
                        .map_err(|_| TpmRc::FAILURE)?,
                )
            }
            None => {
                TpmtTkVerified::DigestVerified(Handle::RH_NULL, hash_alg, Tpm2bDigest::default())
            }
        };

        let rsp = responses::VerifyDigestSignature { validation };
        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// TPM2_SignDigest with an ML-DSA or HashML-DSA key `obj` (after the *sign*/*x509sign*
    /// checks). Writes the signature into `buf`.
    ///
    /// - ML-DSA (Part 3: "Unrestricted ML-DSA keys can only be used with `TPM2_SignDigest()` if
    ///   *allowExternalMu* is TRUE. Restricted ML-DSA keys cannot be used [...]"): *digest* is the
    ///   message representative mu; `TPM_RC_ATTRIBUTES` (`keyHandle`) without *allowExternalMu* or
    ///   for a restricted key, `TPM_RC_VALUE` (`context`) for a non-empty context (it is an input
    ///   of mu), `TPM_RC_SIZE` (`digest`) if *digest* is not 64 octets.
    /// - HashML-DSA ("Signs/verifies the digest"): *digest* is `PH(M)` with the key's
    ///   *hashAlg*, *context* the context string; the hash-check ticket and the digest size are
    ///   checked as for the other digest schemes.
    #[cfg(feature = "mldsa")]
    fn sign_digest_mldsa<'s>(
        &mut self,
        obj: &TransientObject,
        cmd: &tpm2::commands::SignDigest<'_>,
        buf: &'s mut [u8; tpm2::TPM2_MAX_MLDSA_SIG_SIZE],
    ) -> Result<TpmtSignature<'s>, TpmRc> {
        let restricted = obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED);
        let digest = cmd.digest.get_buffer();
        let (mu, pre_hash) = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Mldsa(parms, _) => {
                if !parms.allow_external_mu || restricted {
                    return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
                }
                if !cmd.context.get_buffer().is_empty() {
                    return Err(TpmRc::VALUE.with(Position::parameter(1)));
                }
                let mu: [u8; tpm2::TpmiMldsaParms::MU_BYTES] = digest
                    .try_into()
                    .map_err(|_| TpmRc::SIZE.with(Position::parameter(2)))?;
                (mu, None)
            }
            OwnedPublicParmsAndId::HashMldsa(parms, public_key) => {
                let hash_alg = parms.hash_alg;
                if cmd.validation.digest().get_size() != 0 || restricted {
                    let ticket_hmac = self.compute_hashcheck_ticket(
                        cmd.validation.hierarchy(),
                        hash_alg,
                        digest,
                    )?;
                    if cmd.validation.digest().get_buffer() != ticket_hmac.get_buffer() {
                        return Err(TpmRc::TICKET.with(Position::parameter(3)));
                    }
                } else if digest.len() != hash_alg.digest_size() {
                    return Err(TpmRc::SIZE.with(Position::parameter(2)));
                }
                let mu = crate::mldsa::hash_mu(
                    public_key.get_buffer(),
                    cmd.context.get_buffer(),
                    hash_alg,
                    digest,
                )
                .ok_or_else(|| TpmRc::SCHEME.with(Position::handle(1)))?;
                (mu, Some(hash_alg))
            }
            _ => return Err(TpmRc::KEY.with(Position::handle(1))),
        };
        if obj.private_len == 0 {
            return Err(TpmRc::AUTH_UNAVAILABLE);
        }
        let len = self.mldsa_sign_mu(obj, &mu, buf)?;
        let sig = tpm2::Tpm2bSignatureMldsa::from_bytes(&buf[..len]).map_err(|_| TpmRc::FAILURE)?;
        Ok(match pre_hash {
            Some(hash) => TpmtSignature::HashMldsa(tpm2::TpmsSignatureHashMldsa {
                hash,
                signature: sig,
            }),
            None => TpmtSignature::Mldsa(sig),
        })
    }

    /// TPM2_VerifyDigestSignature with an ML-DSA or HashML-DSA key `obj` (after the *sign*
    /// check): verifies the signature and returns the pre-hash of a HashML-DSA key (`None` for an
    /// external mu).
    ///
    /// - ML-DSA: `TPM_RC_ATTRIBUTES` (`keyHandle`) without *allowExternalMu*, `TPM_RC_VALUE`
    ///   (`context`) for a non-empty context, `TPM_RC_SIZE` (`digest`) if *digest* (mu) is not 64
    ///   octets, `TPM_RC_SCHEME` (`signature`) for another signature algorithm.
    /// - HashML-DSA: `TPM_RC_SIZE` (`digest`) if *digest* is not the size of the key's
    ///   *hashAlg*, `TPM_RC_SCHEME` (`signature`) for another algorithm or pre-hash.
    ///
    /// A signature that is not genuine is `TPM_RC_SIGNATURE` (`signature`).
    #[cfg(feature = "mldsa")]
    fn verify_digest_mldsa(
        &mut self,
        obj: &TransientObject,
        cmd: &tpm2::commands::VerifyDigestSignature<'_>,
    ) -> Result<Option<tpm2::TpmiAlgHash>, TpmRc> {
        let digest = cmd.digest.get_buffer();
        let (mu, pre_hash, sig) = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Mldsa(parms, _) => {
                if !parms.allow_external_mu {
                    return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
                }
                if !cmd.context.get_buffer().is_empty() {
                    return Err(TpmRc::VALUE.with(Position::parameter(1)));
                }
                let mu: [u8; tpm2::TpmiMldsaParms::MU_BYTES] = digest
                    .try_into()
                    .map_err(|_| TpmRc::SIZE.with(Position::parameter(2)))?;
                let TpmtSignature::Mldsa(sig) = &cmd.signature else {
                    return Err(TpmRc::SCHEME.with(Position::parameter(3)));
                };
                (mu, None, sig.get_buffer())
            }
            OwnedPublicParmsAndId::HashMldsa(parms, public_key) => {
                let hash_alg = parms.hash_alg;
                if digest.len() != hash_alg.digest_size() {
                    return Err(TpmRc::SIZE.with(Position::parameter(2)));
                }
                let sig = match &cmd.signature {
                    TpmtSignature::HashMldsa(sig) if sig.hash == hash_alg => {
                        sig.signature.get_buffer()
                    }
                    _ => return Err(TpmRc::SCHEME.with(Position::parameter(3))),
                };
                let mu = crate::mldsa::hash_mu(
                    public_key.get_buffer(),
                    cmd.context.get_buffer(),
                    hash_alg,
                    digest,
                )
                .ok_or_else(|| TpmRc::SCHEME.with(Position::handle(1)))?;
                (mu, Some(hash_alg), sig)
            }
            _ => return Err(TpmRc::KEY.with(Position::handle(1))),
        };
        if !self.mldsa_verify_mu(obj, &mu, sig)? {
            return Err(TpmRc::SIGNATURE.with(Position::parameter(3)));
        }
        Ok(pre_hash)
    }
}
