//! Message signing sequences: `TPM2_SignSequenceStart`, `TPM2_SignSequenceComplete`,
//! `TPM2_VerifySequenceStart` and `TPM2_VerifySequenceComplete`.

use super::crypt_ops::{
    PaddedEccPoint, ecc_param_size, left_pad, load_ecc_private, load_ecc_public, load_rsa_private,
    load_rsa_public, pad_ecc_signature,
};
use super::sequence::is_sequence_hash;
use crate::handle_checks::{Tpmi, check};
use crate::owned::{OwnedAuth, OwnedPublicParmsAndId, OwnedSensitiveComposite, OwnedSignatureCtx};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{Crypto, MAX_SEQUENCE_BUFFER};
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{
    SignSequenceComplete, SignSequenceStart, VerifySequenceComplete, VerifySequenceStart, responses,
};
use tpm2::crypto::{self, Mldsa, MldsaMessage, SignatureBuffer, SigningKey, VerifyingKey};
use tpm2::errors::{Position, TpmRc};
use tpm2::limits::MAX_2B_BUFFER_SIZE;
use tpm2::{
    Tpm2b, Tpm2bDigest, Tpm2bPublicKeyRsa, TpmEccCurve, TpmSt, TpmaObject, TpmiMldsaParms,
    TpmiRsaKeyBits, TpmsSignatureHashMldsa, TpmsSignatureRsa, TpmtEccScheme, TpmtHa,
    TpmtKeyedHashScheme, TpmtRsaScheme, TpmtSigScheme, TpmtSignature, TpmtTkVerified,
};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Selects the signature scheme for `SignSequenceStart` / `VerifySequenceStart` from a signing key's public parameters.
    fn select_sequence_scheme(parms_and_id: &OwnedPublicParmsAndId) -> Option<TpmtSigScheme> {
        match parms_and_id {
            OwnedPublicParmsAndId::Mldsa(..) => Some(TpmtSigScheme::Mldsa),
            OwnedPublicParmsAndId::HashMldsa(..) => Some(TpmtSigScheme::HashMldsa),
            OwnedPublicParmsAndId::Rsa(parms, _) => match parms.scheme {
                Some(TpmtRsaScheme::Rsassa(h)) if is_sequence_hash(h) => {
                    Some(TpmtSigScheme::Rsassa(h))
                }
                Some(TpmtRsaScheme::Rsapss(h)) if is_sequence_hash(h) => {
                    Some(TpmtSigScheme::Rsapss(h))
                }
                _ => None,
            },
            OwnedPublicParmsAndId::Ecc(parms, _) => match parms.scheme {
                Some(TpmtEccScheme::Ecdsa(h)) if is_sequence_hash(h) => {
                    Some(TpmtSigScheme::Ecdsa(h))
                }
                _ => None,
            },
            OwnedPublicParmsAndId::KeyedHash(Some(TpmtKeyedHashScheme::Hmac(h)), _)
                if is_sequence_hash(*h) =>
            {
                Some(TpmtSigScheme::Hmac(*h))
            }
            _ => None,
        }
    }

    /// Handles the [TpmCc::SignSequenceStart] (`0x1AA`) command.
    pub fn sign_sequence_start(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<SignSequenceStart>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<SignSequenceStart>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let obj = self.resolve_object(key_handle.0, Position::handle(1))?;
        if !obj
            .public
            .object_attributes
            .contains(TpmaObject::SIGN_ENCRYPT)
            || matches!(obj.public.parms_and_id, OwnedPublicParmsAndId::Sym(..))
            || obj.sensitive.as_bytes().is_empty()
            || (matches!(
                obj.public.parms_and_id,
                OwnedPublicParmsAndId::KeyedHash(..)
            ) && obj
                .public
                .object_attributes
                .contains(TpmaObject::RESTRICTED))
        {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }

        if obj.public.object_attributes.contains(TpmaObject::X509_SIGN) {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        let scheme = Self::select_sequence_scheme(&obj.public.parms_and_id)
            .ok_or(TpmRc::SCHEME.with(Position::handle(1)))?;

        if !cmd.context.as_slice().is_empty()
            && !matches!(scheme, TpmtSigScheme::Mldsa | TpmtSigScheme::HashMldsa)
        {
            return Err(TpmRc::VALUE.with(Position::parameter(2)));
        }

        let (index, handle) = self.global_state.find_empty_sequence_slot()?;
        let slot = self
            .global_state
            .active_sequences
            .get_mut(index)
            .ok_or(TpmRc::FAILURE)?;
        *slot = Some(crate::ActiveSequence::new(
            handle,
            OwnedAuth::from(cmd.auth),
            crate::SequenceType::Sign {
                associated_name: obj.name,
                scheme,
                context: OwnedSignatureCtx::from(cmd.context),
            },
        ));

        let sequence_handle = Handle(handle);
        let response = request.into_response();
        self.write_response_handles(
            response,
            &sequence_handle,
            &session_responses[..num_sessions],
        )?;
        Ok(())
    }

    /// Handles the [TpmCc::SignSequenceComplete] (`0x1A4`) command.
    pub fn sign_sequence_complete(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<SignSequenceComplete>()?;
        let [sequence_handle, key_handle] = handles;
        check(sequence_handle, Tpmi::DhObject, Position::handle(1))?;
        check(key_handle, Tpmi::DhObject, Position::handle(2))?;
        let sequence_handle = sequence_handle.0;
        let key_handle = key_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<SignSequenceComplete>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        if self
            .global_state
            .find_active_sequence(sequence_handle)
            .is_none()
        {
            if self
                .resolve_object(sequence_handle, Position::handle(1))
                .is_ok()
            {
                return Err(TpmRc::MODE.with(Position::handle(1)));
            }
            return Err(TpmRc::HANDLE.with(Position::handle(1)));
        }

        let key_obj = self.resolve_object(key_handle, Position::handle(2))?;
        let final_chunk = cmd.buffer.as_slice();

        let (
            associated_name,
            scheme,
            context,
            first_bytes,
            first_bytes_len,
            state,
            seq_buf,
            seq_len,
        ) = {
            let seq_obj = self
                .global_state
                .find_active_sequence(sequence_handle)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;
            let crate::SequenceType::Sign {
                associated_name,
                scheme,
                context,
            } = seq_obj.sequence_type
            else {
                return Err(TpmRc::MODE.with(Position::handle(1)));
            };
            (
                associated_name,
                scheme,
                context,
                seq_obj.first_bytes,
                seq_obj.first_bytes_len,
                seq_obj.hash_states[0],
                seq_obj.sequence_buffer,
                seq_obj.sequence_len,
            )
        };

        if associated_name != key_obj.name {
            return Err(TpmRc::SIGN_CONTEXT_KEY.with(Position::handle(2)));
        }
        // The Name only covers the public area: a public-only copy of the key (e.g. from
        // TPM2_LoadExternal) has the same Name but no private key.
        if key_obj.sensitive.as_bytes().is_empty() {
            return Err(TpmRc::KEY.with(Position::handle(2)));
        }

        if key_obj
            .public
            .object_attributes
            .contains(TpmaObject::X509_SIGN)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(2)));
        }

        if key_obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED)
        {
            let first_len = first_bytes_len.min(4);
            let sequence_bytes = first_bytes.iter().take(first_len).chain(final_chunk);
            let mut first4 = [0u8; 4];
            let mut first4_len = 0;
            for (dst, src) in first4.iter_mut().zip(sequence_bytes) {
                *dst = *src;
                first4_len += 1;
            }
            if first4_len < 4 || first4 == [0xFF, b'T', b'C', b'G'] {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
        }

        let mut sig_buf: SignatureBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        let mut sig_r = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
        let mut sig_s = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
        let mut mldsa_sig_buf = [0u8; TpmiMldsaParms::MAX_SIG_BYTES];
        let hmac_bytes;
        let signature = match scheme {
            TpmtSigScheme::Mldsa => {
                let OwnedPublicParmsAndId::Mldsa(parms, _) = &key_obj.public.parms_and_id else {
                    return Err(TpmRc::KEY.with(Position::handle(2)));
                };
                let OwnedSensitiveComposite::Mldsa(seed) = &key_obj.sensitive else {
                    return Err(TpmRc::KEY.with(Position::handle(2)));
                };
                // Pure ML-DSA needs the whole message, which SequenceUpdate buffered. Computing
                // `mu` incrementally (`Mldsa::mu_start`) is optional for backends.
                let mut message = [0u8; MAX_SEQUENCE_BUFFER + MAX_2B_BUFFER_SIZE];
                let message_len = seq_len + final_chunk.len();
                let message = message.get_mut(..message_len).ok_or(TpmRc::FAILURE)?;
                let (buffered, last) = message.split_at_mut(seq_len);
                buffered.copy_from_slice(&seq_buf[..seq_len]);
                last.copy_from_slice(final_chunk);
                let crypto = self.crypto();
                let priv_key = Mldsa::derive_key(crypto, parms.parameter_set, Tpm2b(seed))
                    .map_err(|_| TpmRc::FAILURE)?;
                let sig = Mldsa::sign(
                    crypto,
                    &mut self.context.platform.rng,
                    &priv_key,
                    MldsaMessage::Pure {
                        context: context.as_tpm2b(),
                        message,
                    },
                    &mut mldsa_sig_buf,
                )
                .map_err(|_| TpmRc::FAILURE)?
                .ok_or(TpmRc::NO_RESULT)?;
                TpmtSignature::Mldsa(sig)
            }
            TpmtSigScheme::HashMldsa => {
                let OwnedPublicParmsAndId::HashMldsa(parms, _) = &key_obj.public.parms_and_id
                else {
                    return Err(TpmRc::KEY.with(Position::handle(2)));
                };
                let OwnedSensitiveComposite::HashMldsa(seed) = &key_obj.sensitive else {
                    return Err(TpmRc::KEY.with(Position::handle(2)));
                };
                let hash_alg = parms.hash_alg;
                let (digest_buf, digest_len) =
                    self.compute_hash(hash_alg, &[&seq_buf[..seq_len], final_chunk])?;
                let tpmt_ha =
                    TpmtHa::new(hash_alg, &digest_buf[..digest_len]).ok_or(TpmRc::FAILURE)?;
                let crypto = self.crypto();
                let priv_key = Mldsa::derive_key(crypto, parms.parameter_set, Tpm2b(seed))
                    .map_err(|_| TpmRc::FAILURE)?;
                let sig = Mldsa::sign(
                    crypto,
                    &mut self.context.platform.rng,
                    &priv_key,
                    MldsaMessage::PreHash {
                        context: context.as_tpm2b(),
                        digest: tpmt_ha,
                    },
                    &mut mldsa_sig_buf,
                )
                .map_err(|_| TpmRc::FAILURE)?
                .ok_or(TpmRc::NO_RESULT)?;
                TpmtSignature::HashMldsa(TpmsSignatureHashMldsa {
                    hash: hash_alg,
                    signature: sig,
                })
            }
            TpmtSigScheme::Hmac(hash_alg) => {
                let (computed_hmac, len) = self.compute_hmac(
                    hash_alg,
                    key_obj.sensitive.as_bytes(),
                    &[&seq_buf[..seq_len], final_chunk],
                )?;
                hmac_bytes = computed_hmac;
                let tpmt_ha = TpmtHa::new(hash_alg, &hmac_bytes[..len]).ok_or(TpmRc::FAILURE)?;
                TpmtSignature::Hmac(tpmt_ha)
            }
            TpmtSigScheme::Rsassa(_) | TpmtSigScheme::Rsapss(_) | TpmtSigScheme::Ecdsa(_) => {
                let mut state = state;
                state.update(final_chunk);
                let (digest_buf, digest_len) = state.finalize();
                let digest = digest_buf.get(..digest_len).ok_or(TpmRc::FAILURE)?;
                let crypto = self.crypto();
                let rng = &mut self.context.platform.rng;
                let signature = match &key_obj.public.parms_and_id {
                    OwnedPublicParmsAndId::Rsa(parms, unique) => {
                        let key = load_rsa_private(
                            crypto,
                            parms,
                            unique.get_buffer(),
                            &key_obj.sensitive,
                        )
                        .ok_or(TpmRc::VALUE.with(Position::handle(2)))?;
                        crypto::sign(
                            crypto,
                            rng,
                            SigningKey::Rsa(&key),
                            scheme,
                            digest,
                            &mut sig_buf,
                        )
                    }
                    OwnedPublicParmsAndId::Ecc(parms, point) => {
                        let key =
                            load_ecc_private(crypto, parms.curve_id, point, &key_obj.sensitive)
                                .ok_or(TpmRc::VALUE.with(Position::handle(2)))?;
                        crypto::sign(
                            crypto,
                            rng,
                            SigningKey::Ecc(&key),
                            scheme,
                            digest,
                            &mut sig_buf,
                        )
                    }
                    _ => return Err(TpmRc::KEY.with(Position::handle(2))),
                }
                .map_err(|_| TpmRc::VALUE.with(Position::handle(2)))?;

                match signature {
                    TpmtSignature::Rsassa(_) | TpmtSignature::Rsapss(_) => signature,
                    TpmtSignature::Ecdsa(sig) => {
                        let curve = match &key_obj.public.parms_and_id {
                            OwnedPublicParmsAndId::Ecc(parms, _) => parms.curve_id,
                            _ => return Err(TpmRc::FAILURE),
                        };
                        let param_size = ecc_param_size(curve).ok_or(TpmRc::FAILURE)?;
                        TpmtSignature::Ecdsa(
                            pad_ecc_signature(&sig, param_size, &mut sig_r, &mut sig_s)
                                .ok_or(TpmRc::FAILURE)?,
                        )
                    }
                    _ => return Err(TpmRc::SCHEME.with(Position::handle(2))),
                }
            }
            _ => return Err(TpmRc::SCHEME.with(Position::handle(2))),
        };

        // Only flush the sequence once the signature exists, so that a failure (e.g.
        // TPM_RC_NO_RESULT from ML-DSA) leaves it usable.
        self.global_state.remove_active_sequence(sequence_handle)?;

        let rsp = responses::SignSequenceComplete { signature };
        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::VerifySequenceStart] (`0x1A9`) command.
    pub fn verify_sequence_start(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<VerifySequenceStart>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<VerifySequenceStart>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let obj = self.resolve_object(key_handle.0, Position::handle(1))?;
        if !obj
            .public
            .object_attributes
            .contains(TpmaObject::SIGN_ENCRYPT)
            || matches!(obj.public.parms_and_id, OwnedPublicParmsAndId::Sym(..))
            || (matches!(
                obj.public.parms_and_id,
                OwnedPublicParmsAndId::KeyedHash(..)
            ) && obj
                .public
                .object_attributes
                .contains(TpmaObject::RESTRICTED))
        {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }

        let scheme = Self::select_sequence_scheme(&obj.public.parms_and_id)
            .ok_or(TpmRc::SCHEME.with(Position::handle(1)))?;

        if matches!(scheme, TpmtSigScheme::Hmac(_)) && obj.sensitive.as_bytes().is_empty() {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }

        if !cmd.context.as_slice().is_empty()
            && !matches!(scheme, TpmtSigScheme::Mldsa | TpmtSigScheme::HashMldsa)
        {
            return Err(TpmRc::VALUE.with(Position::parameter(3)));
        }

        if !cmd.hint.as_slice().is_empty() {
            return Err(TpmRc::VALUE.with(Position::parameter(2)));
        }

        let (index, handle) = self.global_state.find_empty_sequence_slot()?;
        let slot = self
            .global_state
            .active_sequences
            .get_mut(index)
            .ok_or(TpmRc::FAILURE)?;
        *slot = Some(crate::ActiveSequence::new(
            handle,
            OwnedAuth::from(cmd.auth),
            crate::SequenceType::Verify {
                associated_name: obj.name,
                scheme,
                context: OwnedSignatureCtx::from(cmd.context),
            },
        ));

        let sequence_handle = Handle(handle);
        let response = request.into_response();
        self.write_response_handles(
            response,
            &sequence_handle,
            &session_responses[..num_sessions],
        )?;
        Ok(())
    }

    /// Handles the [TpmCc::VerifySequenceComplete] (`0x1A3`) command.
    pub fn verify_sequence_complete(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<VerifySequenceComplete>()?;
        let [sequence_handle, key_handle] = handles;
        check(sequence_handle, Tpmi::DhObject, Position::handle(1))?;
        check(key_handle, Tpmi::DhObject, Position::handle(2))?;
        let sequence_handle = sequence_handle.0;
        let key_handle = key_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<VerifySequenceComplete>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        if self
            .global_state
            .find_active_sequence(sequence_handle)
            .is_none()
        {
            if self
                .resolve_object(sequence_handle, Position::handle(1))
                .is_ok()
            {
                return Err(TpmRc::MODE.with(Position::handle(1)));
            }
            return Err(TpmRc::HANDLE.with(Position::handle(1)));
        }

        let key_obj = self.resolve_object(key_handle, Position::handle(2))?;

        let (associated_name, scheme, context, state, seq_buf, seq_len) = {
            let seq_obj = self
                .global_state
                .find_active_sequence(sequence_handle)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;
            let crate::SequenceType::Verify {
                associated_name,
                scheme,
                context,
            } = seq_obj.sequence_type
            else {
                return Err(TpmRc::MODE.with(Position::handle(1)));
            };
            (
                associated_name,
                scheme,
                context,
                seq_obj.hash_states[0],
                seq_obj.sequence_buffer,
                seq_obj.sequence_len,
            )
        };

        if associated_name != key_obj.name {
            return Err(TpmRc::SIGN_CONTEXT_KEY.with(Position::handle(2)));
        }

        match scheme {
            TpmtSigScheme::Mldsa => {
                let TpmtSignature::Mldsa(sig) = cmd.signature else {
                    return Err(TpmRc::SCHEME.with(Position::parameter(1)));
                };
                let OwnedPublicParmsAndId::Mldsa(parms, unique) = &key_obj.public.parms_and_id
                else {
                    return Err(TpmRc::KEY.with(Position::handle(2)));
                };
                let pub_key =
                    Mldsa::load_public(self.crypto(), parms.parameter_set, unique.as_tpm2b())
                        .ok()
                        .flatten()
                        .ok_or(TpmRc::SIGNATURE.with(Position::parameter(1)))?;
                let verified = Mldsa::verify(
                    self.crypto(),
                    &pub_key,
                    MldsaMessage::Pure {
                        context: context.as_tpm2b(),
                        message: &seq_buf[..seq_len],
                    },
                    sig,
                )
                .unwrap_or(false);
                if !verified {
                    return Err(TpmRc::SIGNATURE.with(Position::parameter(1)));
                }
            }
            TpmtSigScheme::HashMldsa => {
                let TpmtSignature::HashMldsa(sig) = cmd.signature else {
                    return Err(TpmRc::SCHEME.with(Position::parameter(1)));
                };
                let OwnedPublicParmsAndId::HashMldsa(parms, unique) = &key_obj.public.parms_and_id
                else {
                    return Err(TpmRc::KEY.with(Position::handle(2)));
                };
                if sig.hash != parms.hash_alg {
                    return Err(TpmRc::SIGNATURE.with(Position::parameter(1)));
                }
                let (digest_buf, digest_len) =
                    self.compute_hash(sig.hash, &[&seq_buf[..seq_len]])?;
                let tpmt_ha = TpmtHa::new(sig.hash, &digest_buf[..digest_len])
                    .ok_or(TpmRc::SIGNATURE.with(Position::parameter(1)))?;
                let pub_key =
                    Mldsa::load_public(self.crypto(), parms.parameter_set, unique.as_tpm2b())
                        .ok()
                        .flatten()
                        .ok_or(TpmRc::SIGNATURE.with(Position::parameter(1)))?;
                let verified = Mldsa::verify(
                    self.crypto(),
                    &pub_key,
                    MldsaMessage::PreHash {
                        context: context.as_tpm2b(),
                        digest: tpmt_ha,
                    },
                    sig.signature,
                )
                .unwrap_or(false);
                if !verified {
                    return Err(TpmRc::SIGNATURE.with(Position::parameter(1)));
                }
            }
            TpmtSigScheme::Hmac(hash_alg) => {
                let TpmtSignature::Hmac(ha) = &cmd.signature else {
                    return Err(TpmRc::SCHEME.with(Position::parameter(1)));
                };
                if ha.hash_alg() != hash_alg {
                    return Err(TpmRc::SCHEME.with(Position::parameter(1)));
                }
                // A public-only copy of the key has the same Name but no HMAC key.
                if key_obj.sensitive.as_bytes().is_empty() {
                    return Err(TpmRc::KEY.with(Position::handle(2)));
                }
                let (hmac_bytes, hmac_len) = self.compute_hmac(
                    hash_alg,
                    key_obj.sensitive.as_bytes(),
                    &[&seq_buf[..seq_len]],
                )?;
                if !hmac_bytes
                    .get(..hmac_len)
                    .is_some_and(|hmac| crate::util::constant_time_eq(ha.digest(), hmac))
                {
                    return Err(TpmRc::SIGNATURE.with(Position::parameter(1)));
                }
            }
            TpmtSigScheme::Rsassa(expected_hash)
            | TpmtSigScheme::Rsapss(expected_hash)
            | TpmtSigScheme::Ecdsa(expected_hash) => {
                let (digest_buf, digest_len) = state.finalize();
                let digest = digest_buf.get(..digest_len).ok_or(TpmRc::FAILURE)?;
                match &key_obj.public.parms_and_id {
                    OwnedPublicParmsAndId::Rsa(parms, unique) => {
                        let sig_rsa = match (&scheme, &cmd.signature) {
                            (TpmtSigScheme::Rsassa(_), TpmtSignature::Rsassa(s))
                            | (TpmtSigScheme::Rsapss(_), TpmtSignature::Rsapss(s)) => s,
                            _ => return Err(TpmRc::SCHEME.with(Position::parameter(1))),
                        };
                        if sig_rsa.hash != expected_hash {
                            return Err(TpmRc::SIGNATURE.with(Position::parameter(1)));
                        }
                        let key_size = usize::from(parms.key_bits.as_u16() / 8);
                        if unique.get_buffer().len() > key_size {
                            return Err(TpmRc::KEY.with(Position::handle(2)));
                        }
                        let mut sig_buf = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
                        left_pad(&mut sig_buf, sig_rsa.sig.as_slice(), key_size)
                            .ok_or(TpmRc::SIGNATURE.with(Position::parameter(1)))?;
                        let padded = TpmsSignatureRsa {
                            hash: sig_rsa.hash,
                            sig: sig_buf
                                .get(..key_size)
                                .and_then(Tpm2bPublicKeyRsa::new)
                                .ok_or(TpmRc::FAILURE)?,
                        };
                        let signature = if matches!(cmd.signature, TpmtSignature::Rsassa(_)) {
                            TpmtSignature::Rsassa(padded)
                        } else {
                            TpmtSignature::Rsapss(padded)
                        };
                        let crypto = self.crypto();
                        let verified =
                            load_rsa_public(crypto, parms, unique.get_buffer()).map(|key| {
                                crypto::verify(crypto, VerifyingKey::Rsa(&key), digest, signature)
                            });
                        if verified != Some(Ok(true)) {
                            return Err(TpmRc::SIGNATURE.with(Position::parameter(1)));
                        }
                    }
                    OwnedPublicParmsAndId::Ecc(parms, point) => {
                        let sig_ecc = match (&scheme, &cmd.signature) {
                            (TpmtSigScheme::Ecdsa(_), TpmtSignature::Ecdsa(s)) => s,
                            _ => return Err(TpmRc::SCHEME.with(Position::parameter(1))),
                        };
                        if sig_ecc.hash != expected_hash {
                            return Err(TpmRc::SIGNATURE.with(Position::parameter(1)));
                        }
                        let curve = parms.curve_id;
                        let param_size =
                            ecc_param_size(curve).ok_or(TpmRc::KEY.with(Position::handle(2)))?;
                        let public = PaddedEccPoint::new(
                            point.x.get_buffer(),
                            point.y.get_buffer(),
                            param_size,
                        )
                        .ok_or(TpmRc::KEY.with(Position::handle(2)))?;
                        let mut r_buf = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
                        let mut s_buf = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
                        let signature = TpmtSignature::Ecdsa(
                            pad_ecc_signature(sig_ecc, param_size, &mut r_buf, &mut s_buf)
                                .ok_or(TpmRc::SIGNATURE.with(Position::parameter(1)))?,
                        );
                        let crypto = self.crypto();
                        let verified = load_ecc_public(crypto, curve, &public).map(|key| {
                            crypto::verify(crypto, VerifyingKey::Ecc(&key), digest, signature)
                        });
                        if verified != Some(Ok(true)) {
                            return Err(TpmRc::SIGNATURE.with(Position::parameter(1)));
                        }
                    }
                    _ => return Err(TpmRc::KEY.with(Position::handle(2))),
                }
            }
            _ => return Err(TpmRc::SCHEME.with(Position::parameter(1))),
        }

        // Only flush the sequence if the signature is genuine.
        self.global_state.remove_active_sequence(sequence_handle)?;

        // Part 3, TPM2_VerifySequenceComplete: the ticket is a TPM_ST_MESSAGE_VERIFIED ticket,
        // whose HMAC covers the whole message (Part 2, TPMT_TK_VERIFIED). Keys in the NULL
        // hierarchy or with a NULL nameAlg get a NULL ticket.
        let ticket_hmac;
        let (hierarchy, digest) = match Handle(key_obj.hierarchy) {
            Handle::RH_OWNER | Handle::RH_PLATFORM | Handle::RH_ENDORSEMENT
                if key_obj.public.name_alg.is_some() =>
            {
                ticket_hmac = self.compute_verified_ticket_with_meta(
                    key_obj.hierarchy,
                    TpmSt::MESSAGE_VERIFIED.id(),
                    &seq_buf[..seq_len],
                    key_obj.name.get_buffer(),
                    &[],
                )?;
                (
                    Handle(key_obj.hierarchy),
                    Tpm2bDigest::new(&ticket_hmac).ok_or(TpmRc::FAILURE)?,
                )
            }
            _ => (Handle::RH_NULL, Tpm2bDigest::default()),
        };

        let rsp = responses::VerifySequenceComplete {
            validation: TpmtTkVerified::MessageVerified(hierarchy, digest),
        };
        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }
}
