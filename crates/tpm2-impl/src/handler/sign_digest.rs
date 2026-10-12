//! Digest signing commands: `TPM2_SignDigest` and `TPM2_VerifyDigestSignature`.

use super::crypt_ops::{
    PaddedEccPoint, ecc_param_size, is_signing_hash, left_pad, load_ecc_private, load_ecc_public,
    load_rsa_private, load_rsa_public, pad_ecc_signature,
};
use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::owned::{OwnedPublicParmsAndId, OwnedSensitiveComposite};
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::TpmEccCurve;
#[allow(deprecated)]
use tpm2::commands::{SignDigest, VerifyDigestSignature, responses};
use tpm2::crypto::{CryptoError, Mldsa, MldsaMessage, SignatureBuffer, SigningKey, VerifyingKey};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Alg, Tpm2b, Tpm2bDigest, Tpm2bPublicKeyRsa, TpmSt, TpmaObject, TpmiAlgHash, TpmiMldsaParms,
    TpmiRsaKeyBits, TpmsSignatureHashMldsa, TpmsSignatureRsa, TpmtEccScheme, TpmtHa, TpmtRsaScheme,
    TpmtSigScheme, TpmtSignature, TpmtTkVerified,
};
use tpm2::{Ticket, crypto};

use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::SignDigest] (`0x1A6`) command.
    pub fn sign_digest(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<SignDigest>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<SignDigest>(handles)?;
        check(
            cmd.validation.hierarchy(),
            Tpmi::RhHierarchy,
            Position::parameter(3),
        )?;
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
        {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }

        if obj.public.object_attributes.contains(TpmaObject::X509_SIGN) {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        if let OwnedPublicParmsAndId::Mldsa(parms, _) = &obj.public.parms_and_id {
            if !parms.allow_external_mu
                || obj
                    .public
                    .object_attributes
                    .contains(TpmaObject::RESTRICTED)
            {
                return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
            }
            if !cmd.context.as_slice().is_empty() {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
            let Ok(mu) = <&[u8; TpmiMldsaParms::MU_BYTES]>::try_from(cmd.digest.as_slice()) else {
                return Err(TpmRc::SIZE.with(Position::parameter(2)));
            };
            let OwnedSensitiveComposite::Mldsa(seed) = &obj.sensitive else {
                return Err(TpmRc::KEY.with(Position::handle(1)));
            };
            let crypto = self.crypto();
            let priv_key = Mldsa::derive_key(crypto, parms.parameter_set, Tpm2b(seed))
                .map_err(|_| TpmRc::FAILURE)?;
            let mut mldsa_sig_buf = [0u8; TpmiMldsaParms::MAX_SIG_BYTES];
            let sig = Mldsa::sign(
                crypto,
                &mut self.context.platform.rng,
                &priv_key,
                MldsaMessage::ExternalMu(mu),
                &mut mldsa_sig_buf,
            )
            .map_err(|_| TpmRc::FAILURE)?
            .ok_or(TpmRc::NO_RESULT)?;

            let rsp = responses::SignDigest {
                signature: TpmtSignature::Mldsa(sig),
            };
            let response = request.into_response();
            self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
            return Ok(());
        }

        if !matches!(
            obj.public.parms_and_id,
            OwnedPublicParmsAndId::HashMldsa(..)
        ) && !cmd.context.as_slice().is_empty()
        {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }

        let (selected_scheme, scheme_hash_alg) = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(parms, _) => match parms.scheme {
                Some(TpmtRsaScheme::Rsassa(h)) => (TpmtSigScheme::Rsassa(h), h),
                Some(TpmtRsaScheme::Rsapss(h)) => (TpmtSigScheme::Rsapss(h), h),
                _ => return Err(TpmRc::SCHEME.with(Position::handle(1))),
            },
            OwnedPublicParmsAndId::Ecc(parms, _) => match parms.scheme {
                Some(TpmtEccScheme::Ecdsa(h)) => (TpmtSigScheme::Ecdsa(h), h),
                _ => return Err(TpmRc::SCHEME.with(Position::handle(1))),
            },
            // HMAC is not supported by TPM2_SignDigest (Part 3, "Signing overview").
            OwnedPublicParmsAndId::HashMldsa(parms, _) => {
                (TpmtSigScheme::HashMldsa, parms.hash_alg)
            }
            _ => return Err(TpmRc::SCHEME.with(Position::handle(1))),
        };

        if !is_signing_hash(scheme_hash_alg) {
            return Err(TpmRc::SCHEME.with(Position::handle(1)));
        }

        let is_restricted = obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED);

        if !cmd.validation.digest().as_slice().is_empty() || is_restricted {
            let ticket_hmac = self.compute_hashcheck_ticket(
                cmd.validation.hierarchy(),
                scheme_hash_alg,
                cmd.digest.as_slice(),
            )?;
            if !crate::util::constant_time_eq(cmd.validation.digest().as_slice(), &ticket_hmac) {
                return Err(TpmRc::TICKET.with(Position::parameter(3)));
            }
        } else if cmd.digest.as_slice().len() != scheme_hash_alg.digest_size() {
            return Err(TpmRc::SIZE.with(Position::parameter(2)));
        }

        let mut sig_buf: SignatureBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        let mut sig_r = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
        let mut sig_s = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
        let mut mldsa_sig_buf = [0u8; TpmiMldsaParms::MAX_SIG_BYTES];
        let signature = if let OwnedPublicParmsAndId::HashMldsa(parms, _) = &obj.public.parms_and_id
        {
            let tpmt_ha = TpmtHa::new(scheme_hash_alg, cmd.digest.as_slice())
                .ok_or(TpmRc::SIZE.with(Position::parameter(2)))?;
            let OwnedSensitiveComposite::HashMldsa(seed) = &obj.sensitive else {
                return Err(TpmRc::KEY.with(Position::handle(1)));
            };
            let crypto = self.crypto();
            let priv_key = Mldsa::derive_key(crypto, parms.parameter_set, Tpm2b(seed))
                .map_err(|_| TpmRc::FAILURE)?;
            let sig = Mldsa::sign(
                crypto,
                &mut self.context.platform.rng,
                &priv_key,
                MldsaMessage::PreHash {
                    context: cmd.context,
                    digest: tpmt_ha,
                },
                &mut mldsa_sig_buf,
            )
            .map_err(|_| TpmRc::FAILURE)?
            .ok_or(TpmRc::NO_RESULT)?;
            TpmtSignature::HashMldsa(TpmsSignatureHashMldsa {
                hash: scheme_hash_alg,
                signature: sig,
            })
        } else {
            if TpmtHa::new(scheme_hash_alg, cmd.digest.as_slice()).is_none() {
                return Err(TpmRc::SIZE.with(Position::parameter(2)));
            }
            let crypto = self.crypto();
            let rng = &mut self.context.platform.rng;
            let digest = cmd.digest.as_slice();
            let signature = match &obj.public.parms_and_id {
                OwnedPublicParmsAndId::Rsa(parms, unique) => {
                    let key = load_rsa_private(crypto, parms, unique.get_buffer(), &obj.sensitive)
                        .ok_or(TpmRc::VALUE.with(Position::handle(1)))?;
                    crypto::sign(
                        crypto,
                        rng,
                        SigningKey::Rsa(&key),
                        selected_scheme,
                        digest,
                        &mut sig_buf,
                    )
                }
                OwnedPublicParmsAndId::Ecc(parms, point) => {
                    let key = load_ecc_private(crypto, parms.curve_id, point, &obj.sensitive)
                        .ok_or(TpmRc::VALUE.with(Position::handle(1)))?;
                    crypto::sign(
                        crypto,
                        rng,
                        SigningKey::Ecc(&key),
                        selected_scheme,
                        digest,
                        &mut sig_buf,
                    )
                }
                _ => Err(CryptoError::Unsupported),
            }
            .map_err(|_| TpmRc::VALUE.with(Position::handle(1)))?;

            match signature {
                TpmtSignature::Rsassa(_) | TpmtSignature::Rsapss(_) => signature,
                TpmtSignature::Ecdsa(sig) => {
                    let curve = match &obj.public.parms_and_id {
                        OwnedPublicParmsAndId::Ecc(parms, _) => parms.curve_id,
                        _ => return Err(TpmRc::FAILURE),
                    };
                    let param_size = ecc_param_size(curve).ok_or(TpmRc::FAILURE)?;
                    TpmtSignature::Ecdsa(
                        pad_ecc_signature(&sig, param_size, &mut sig_r, &mut sig_s)
                            .ok_or(TpmRc::FAILURE)?,
                    )
                }
                _ => return Err(TpmRc::SCHEME.with(Position::handle(1))),
            }
        };

        let rsp = responses::SignDigest { signature };
        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::VerifyDigestSignature] (`0x1A5`) command.
    pub fn verify_digest_signature(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<VerifyDigestSignature>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<VerifyDigestSignature>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let obj = self.resolve_object(key_handle.0, Position::handle(1))?;

        if !obj
            .public
            .object_attributes
            .contains(TpmaObject::SIGN_ENCRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        if let OwnedPublicParmsAndId::Mldsa(parms, unique) = &obj.public.parms_and_id {
            if !parms.allow_external_mu {
                return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
            }
            if !cmd.context.as_slice().is_empty() {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
            let Ok(mu) = <&[u8; TpmiMldsaParms::MU_BYTES]>::try_from(cmd.digest.as_slice()) else {
                return Err(TpmRc::SIZE.with(Position::parameter(2)));
            };
            let TpmtSignature::Mldsa(sig) = cmd.signature else {
                return Err(TpmRc::SCHEME.with(Position::parameter(3)));
            };
            let pub_key = Mldsa::load_public(self.crypto(), parms.parameter_set, unique.as_tpm2b())
                .ok()
                .flatten()
                .ok_or(TpmRc::SIGNATURE.with(Position::parameter(3)))?;
            let verified =
                Mldsa::verify(self.crypto(), &pub_key, MldsaMessage::ExternalMu(mu), sig)
                    .unwrap_or(false);
            if !verified {
                return Err(TpmRc::SIGNATURE.with(Position::parameter(3)));
            }
        } else {
            if !matches!(
                obj.public.parms_and_id,
                OwnedPublicParmsAndId::HashMldsa(..)
            ) && !cmd.context.as_slice().is_empty()
            {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }

            // HMAC is not supported by TPM2_VerifyDigestSignature (Part 3, "Signing overview").
            if matches!(
                obj.public.parms_and_id,
                OwnedPublicParmsAndId::KeyedHash(..)
            ) {
                return Err(TpmRc::SCHEME.with(Position::handle(1)));
            }
            if !matches!(
                obj.public.parms_and_id,
                OwnedPublicParmsAndId::Rsa(..)
                    | OwnedPublicParmsAndId::Ecc(..)
                    | OwnedPublicParmsAndId::HashMldsa(..)
            ) {
                return Err(TpmRc::TYPE.with(Position::handle(1)));
            }

            match &obj.public.parms_and_id {
                OwnedPublicParmsAndId::Rsa(parms, unique) => {
                    match &parms.scheme {
                        Some(TpmtRsaScheme::Rsassa(expected_hash)) => {
                            let TpmtSignature::Rsassa(sig_rsa) = &cmd.signature else {
                                return Err(TpmRc::SIGNATURE.with(Position::parameter(3)));
                            };
                            if sig_rsa.hash != *expected_hash {
                                return Err(TpmRc::SIGNATURE.with(Position::parameter(3)));
                            }
                        }
                        Some(TpmtRsaScheme::Rsapss(expected_hash)) => {
                            let TpmtSignature::Rsapss(sig_rsa) = &cmd.signature else {
                                return Err(TpmRc::SIGNATURE.with(Position::parameter(3)));
                            };
                            if sig_rsa.hash != *expected_hash {
                                return Err(TpmRc::SIGNATURE.with(Position::parameter(3)));
                            }
                        }
                        None => match &cmd.signature {
                            TpmtSignature::Rsassa(_) | TpmtSignature::Rsapss(_) => {}
                            _ => return Err(TpmRc::SCHEME.with(Position::parameter(3))),
                        },
                        _ => return Err(TpmRc::KEY.with(Position::handle(1))),
                    }

                    let key_size = usize::from(parms.key_bits.as_u16() / 8);
                    if unique.get_buffer().len() > key_size {
                        return Err(TpmRc::KEY.with(Position::handle(1)));
                    }
                    let mut sig_buf = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
                    let signature = match &cmd.signature {
                        TpmtSignature::Rsassa(sig_rsa) | TpmtSignature::Rsapss(sig_rsa) => {
                            left_pad(&mut sig_buf, sig_rsa.sig.as_slice(), key_size)
                                .ok_or(TpmRc::SIGNATURE.with(Position::parameter(3)))?;
                            let padded = TpmsSignatureRsa {
                                hash: sig_rsa.hash,
                                sig: sig_buf
                                    .get(..key_size)
                                    .and_then(Tpm2bPublicKeyRsa::new)
                                    .ok_or(TpmRc::FAILURE)?,
                            };
                            if matches!(cmd.signature, TpmtSignature::Rsassa(_)) {
                                TpmtSignature::Rsassa(padded)
                            } else {
                                TpmtSignature::Rsapss(padded)
                            }
                        }
                        _ => return Err(TpmRc::SCHEME.with(Position::parameter(3))),
                    };
                    let crypto = self.crypto();
                    let verified = load_rsa_public(crypto, parms, unique.get_buffer()).map(|key| {
                        crypto::verify(
                            crypto,
                            VerifyingKey::Rsa(&key),
                            cmd.digest.as_slice(),
                            signature,
                        )
                    });
                    if verified != Some(Ok(true)) {
                        return Err(TpmRc::SIGNATURE.with(Position::parameter(3)));
                    }
                }
                OwnedPublicParmsAndId::Ecc(parms, point) => {
                    match &parms.scheme {
                        Some(TpmtEccScheme::Ecdsa(expected_hash)) => {
                            let TpmtSignature::Ecdsa(sig_ecc) = &cmd.signature else {
                                return Err(TpmRc::SIGNATURE.with(Position::parameter(3)));
                            };
                            if sig_ecc.hash != *expected_hash {
                                return Err(TpmRc::SIGNATURE.with(Position::parameter(3)));
                            }
                        }
                        Some(TpmtEccScheme::Ecdaa(s)) => {
                            let TpmtSignature::Ecdaa(sig_ecc) = &cmd.signature else {
                                return Err(TpmRc::SIGNATURE.with(Position::parameter(3)));
                            };
                            if sig_ecc.hash != s.hash_alg {
                                return Err(TpmRc::SIGNATURE.with(Position::parameter(3)));
                            }
                        }
                        None => match &cmd.signature {
                            TpmtSignature::Ecdsa(_)
                            | TpmtSignature::Ecdaa(_)
                            | TpmtSignature::Ecschnorr(_) => {}
                            _ => return Err(TpmRc::SCHEME.with(Position::parameter(3))),
                        },
                        _ => return Err(TpmRc::KEY.with(Position::handle(1))),
                    }

                    let curve = parms.curve_id;
                    let param_size =
                        ecc_param_size(curve).ok_or(TpmRc::KEY.with(Position::handle(1)))?;
                    let public =
                        PaddedEccPoint::new(point.x.get_buffer(), point.y.get_buffer(), param_size)
                            .ok_or(TpmRc::KEY.with(Position::handle(1)))?;
                    let mut r_buf = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
                    let mut s_buf = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
                    let signature = match &cmd.signature {
                        TpmtSignature::Ecdsa(sig_ecc) | TpmtSignature::Ecdaa(sig_ecc) => {
                            TpmtSignature::Ecdsa(
                                pad_ecc_signature(sig_ecc, param_size, &mut r_buf, &mut s_buf)
                                    .ok_or(TpmRc::SIGNATURE.with(Position::parameter(3)))?,
                            )
                        }
                        _ => return Err(TpmRc::SCHEME.with(Position::parameter(3))),
                    };
                    let crypto = self.crypto();
                    let verified = load_ecc_public(crypto, curve, &public).map(|key| {
                        crypto::verify(
                            crypto,
                            VerifyingKey::Ecc(&key),
                            cmd.digest.as_slice(),
                            signature,
                        )
                    });
                    if verified != Some(Ok(true)) {
                        return Err(TpmRc::SIGNATURE.with(Position::parameter(3)));
                    }
                }
                OwnedPublicParmsAndId::HashMldsa(parms, unique) => {
                    let TpmtSignature::HashMldsa(sig) = cmd.signature else {
                        return Err(TpmRc::SCHEME.with(Position::parameter(3)));
                    };
                    if sig.hash != parms.hash_alg {
                        return Err(TpmRc::SIGNATURE.with(Position::parameter(3)));
                    }
                    let tpmt_ha = TpmtHa::new(sig.hash, cmd.digest.as_slice())
                        .ok_or(TpmRc::SIGNATURE.with(Position::parameter(3)))?;
                    let pub_key =
                        Mldsa::load_public(self.crypto(), parms.parameter_set, unique.as_tpm2b())
                            .ok()
                            .flatten()
                            .ok_or(TpmRc::SIGNATURE.with(Position::parameter(3)))?;
                    let verified = Mldsa::verify(
                        self.crypto(),
                        &pub_key,
                        MldsaMessage::PreHash {
                            context: cmd.context,
                            digest: tpmt_ha,
                        },
                        sig.signature,
                    )
                    .unwrap_or(false);
                    if !verified {
                        return Err(TpmRc::SIGNATURE.with(Position::parameter(3)));
                    }
                }
                _ => return Err(TpmRc::TYPE.with(Position::handle(1))),
            }
        }

        // Part 3, TPM2_VerifyDigestSignature: the ticket is a TPM_ST_DIGEST_VERIFIED ticket whose
        // metadata is the digest's hash algorithm (Part 2, TPMT_TK_VERIFIED). ML-DSA over an
        // external µ has no such algorithm and gets a NULL ticket (errata 185), as do keys in the
        // NULL hierarchy or with a NULL nameAlg.
        let digest_hash = digest_verified_hash(&cmd.signature);
        let ticket_hmac;
        let (hierarchy, digest) = match (Handle(obj.hierarchy), digest_hash) {
            (Handle::RH_OWNER | Handle::RH_PLATFORM | Handle::RH_ENDORSEMENT, Some(hash))
                if obj.public.name_alg.is_some() =>
            {
                ticket_hmac = self.compute_verified_ticket_with_meta(
                    obj.hierarchy,
                    TpmSt::DIGEST_VERIFIED.id(),
                    cmd.digest.as_slice(),
                    obj.name.get_buffer(),
                    &Alg::from(hash).id().to_be_bytes(),
                )?;
                (
                    Handle(obj.hierarchy),
                    Tpm2bDigest::new(&ticket_hmac).ok_or(TpmRc::FAILURE)?,
                )
            }
            _ => (Handle::RH_NULL, Tpm2bDigest::default()),
        };
        // The metadata of a NULL ticket is not checked; use the key's nameAlg for ML-DSA.
        let ticket_hash = digest_hash
            .or(obj.public.name_alg)
            .unwrap_or(TpmiAlgHash::Sha256);

        let rsp = responses::VerifyDigestSignature {
            validation: TpmtTkVerified::DigestVerified(hierarchy, ticket_hash, digest),
        };
        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }
}

/// Returns the hash algorithm of the digest that a verified `signature` covers, which the
/// `TPM_ST_DIGEST_VERIFIED` ticket records, or `None` for ML-DSA over an external µ.
fn digest_verified_hash(signature: &TpmtSignature<'_>) -> Option<TpmiAlgHash> {
    match signature {
        TpmtSignature::Rsassa(sig) | TpmtSignature::Rsapss(sig) => Some(sig.hash),
        TpmtSignature::Ecdsa(sig) => Some(sig.hash),
        TpmtSignature::HashMldsa(sig) => Some(sig.hash),
        _ => None,
    }
}
