use crate::owned::OwnedPublicParmsAndId;
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::TpmEccCurve;
use tpm2::commands::responses;
use tpm2::commands::{
    ECDHZGen, ECDHZGenHandles, Hmac, HmacHandles, RSADecrypt, RSADecryptHandles, RSAEncrypt,
    RSAEncryptHandles, Sign, SignHandles, VerifySignature, VerifySignatureHandles,
};
use tpm2::crypto::CryptoError;
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Tpm2bDigest, Tpm2bEccParameter, Tpm2bPublicKeyRsa, TpmaObject, TpmiAlgHash, TpmsEccPoint,
    TpmsSignatureEcc, TpmsSignatureRsa, TpmtEccScheme, TpmtKeyedHashScheme, TpmtRsaDecrypt,
    TpmtRsaScheme, TpmtSigScheme, TpmtSignature, TpmtTkVerified,
};

use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Alg;
use tpm2::crypto::{CryptoProvider, Rng};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::VerifySignature] (`0x177`) command.
    ///
    /// # Description
    /// This command uses a loaded public key to verify a signature on a message digest.
    /// If the verification succeeds, the TPM can generate a verification ticket (`TpmtTkVerified`).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 20.2 (TPM2_VerifySignature).
    ///
    /// # Relationships
    /// - The ticket produced by this command can be consumed by [TpmCc::PolicySigned](policy_signed.rs)
    ///   or [TpmCc::PolicyTicket] to validate authorizations.
    /// - The key used for verification must be loaded in the TPM (created by [TpmCc::Create] or [TpmCc::CreatePrimary] and loaded).
    pub fn verify_signature(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal::<VerifySignatureHandles>()?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal::<VerifySignature>()?;

        let _obj = self.resolve_object(handles.key_handle.0, Position::handle(1))?;

        if !_obj
            .public
            .object_attributes
            .contains(TpmaObject::SIGN_ENCRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }

        if !matches!(
            _obj.public.parms_and_id,
            OwnedPublicParmsAndId::Rsa(..)
                | OwnedPublicParmsAndId::Ecc(..)
                | OwnedPublicParmsAndId::KeyedHash(..)
        ) {
            return Err(TpmRc::TYPE.to_rc());
        }

        if matches!(
            _obj.public.parms_and_id,
            OwnedPublicParmsAndId::KeyedHash(..)
        ) && _obj.private_len == 0
        {
            return Err(TpmRc::HANDLE.to_rc());
        }

        // Validate scheme and digest consistency against key parameters
        match &_obj.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(parms, _) => match &parms.scheme {
                Some(TpmtRsaScheme::Rsassa(expected_hash)) => {
                    let sig_rsa = match &cmd.signature {
                        TpmtSignature::Rsassa(sig) => sig,
                        _ => return Err(TpmRc::SIGNATURE.to_rc()),
                    };
                    if sig_rsa.hash != *expected_hash {
                        return Err(TpmRc::SIGNATURE.to_rc());
                    }
                }
                Some(TpmtRsaScheme::Rsapss(expected_hash)) => {
                    let sig_rsa = match &cmd.signature {
                        TpmtSignature::Rsapss(sig) => sig,
                        _ => return Err(TpmRc::SIGNATURE.to_rc()),
                    };
                    if sig_rsa.hash != *expected_hash {
                        return Err(TpmRc::SIGNATURE.to_rc());
                    }
                }
                None => match &cmd.signature {
                    TpmtSignature::Rsassa(_) | TpmtSignature::Rsapss(_) => {}
                    _ => return Err(TpmRc::SCHEME.to_rc()),
                },
                _ => {
                    return Err(TpmRc::KEY.with(Position::handle(1)));
                }
            },
            OwnedPublicParmsAndId::Ecc(parms, _) => match &parms.scheme {
                Some(TpmtEccScheme::Ecdsa(expected_hash)) => {
                    let sig_ecc = match &cmd.signature {
                        TpmtSignature::Ecdsa(sig) => sig,
                        _ => return Err(TpmRc::SIGNATURE.to_rc()),
                    };
                    if sig_ecc.hash != *expected_hash {
                        return Err(TpmRc::SIGNATURE.to_rc());
                    }
                }
                Some(TpmtEccScheme::Ecdaa(s)) => {
                    let sig_ecc = match &cmd.signature {
                        TpmtSignature::Ecdaa(sig) => sig,
                        _ => return Err(TpmRc::SIGNATURE.to_rc()),
                    };
                    if sig_ecc.hash != s.hash_alg {
                        return Err(TpmRc::SIGNATURE.to_rc());
                    }
                }
                None => match &cmd.signature {
                    TpmtSignature::Ecdsa(_)
                    | TpmtSignature::Ecdaa(_)
                    | TpmtSignature::Ecschnorr(_) => {}
                    _ => return Err(TpmRc::SCHEME.to_rc()),
                },
                _ => {
                    return Err(TpmRc::KEY.with(Position::handle(1)));
                }
            },
            OwnedPublicParmsAndId::KeyedHash(scheme, _) => match scheme {
                Some(TpmtKeyedHashScheme::Hmac(expected_hash)) => {
                    let ha = match &cmd.signature {
                        TpmtSignature::Hmac(h) => h,
                        _ => return Err(TpmRc::SIGNATURE.to_rc()),
                    };
                    if ha.hash_alg() != *expected_hash {
                        return Err(TpmRc::SIGNATURE.to_rc());
                    }
                    let (hmac_bytes, hmac_len) = self.compute_hmac(
                        ha.hash_alg(),
                        &_obj.private[.._obj.private_len],
                        &[cmd.digest.get_buffer()],
                    )?;
                    if ha.digest() != &hmac_bytes[..hmac_len] {
                        return Err(TpmRc::SIGNATURE.to_rc());
                    }
                    let hierarchy = if _obj.hierarchy == Handle::RH_NULL.0 {
                        Handle::RH_NULL
                    } else {
                        Handle(_obj.hierarchy)
                    };
                    let rsp = responses::VerifySignature {
                        validation: tpm2::TpmtTkVerified::Verified(hierarchy, cmd.digest),
                    };
                    let response = request.into_response();
                    self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
                    return Ok(());
                }
                None => match &cmd.signature {
                    TpmtSignature::Hmac(ha) => {
                        let (hmac_bytes, hmac_len) = self.compute_hmac(
                            ha.hash_alg(),
                            &_obj.private[.._obj.private_len],
                            &[cmd.digest.get_buffer()],
                        )?;
                        if ha.digest() != &hmac_bytes[..hmac_len] {
                            return Err(TpmRc::SIGNATURE.to_rc());
                        }
                        let hierarchy = if _obj.hierarchy == Handle::RH_NULL.0 {
                            Handle::RH_NULL
                        } else {
                            Handle(_obj.hierarchy)
                        };
                        let rsp = responses::VerifySignature {
                            validation: tpm2::TpmtTkVerified::Verified(hierarchy, cmd.digest),
                        };
                        let response = request.into_response();
                        self.write_response_rsp(
                            response,
                            &rsp,
                            &session_responses[..num_sessions],
                        )?;
                        return Ok(());
                    }
                    _ => return Err(TpmRc::SCHEME.to_rc()),
                },
                _ => {
                    return Err(TpmRc::KEY.with(Position::handle(1)));
                }
            },
            _ => return Err(TpmRc::TYPE.to_rc()),
        }

        // Reconstruct public key bytes based on type
        let mut rsa_pub_key = [0u8; 512];
        let mut ecc_pub_key = [0u8; 256];
        let public_key_bytes = match &_obj.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(parms, unique) => {
                let key_size = (u16::from(parms.key_bits) / 8) as usize;
                let u_buf = unique.get_buffer();
                if u_buf.len() > key_size || key_size > rsa_pub_key.len() {
                    return Err(TpmRc::KEY.to_rc());
                }
                let offset = key_size - u_buf.len();
                rsa_pub_key[offset..key_size].copy_from_slice(u_buf);
                &rsa_pub_key[..key_size]
            }
            OwnedPublicParmsAndId::Ecc(parms, point) => {
                let curve = parms.curve_id;
                let param_size = match curve {
                    TpmEccCurve::NistP224 => 28,
                    TpmEccCurve::NistP256 | TpmEccCurve::BNP256 => 32,
                    TpmEccCurve::NistP384 => 48,
                    TpmEccCurve::NistP521 => 66,
                    _ => return Err(TpmRc::KEY.to_rc()),
                };
                let x_buf = point.x.get_buffer();
                let y_buf = point.y.get_buffer();
                if x_buf.len() > param_size || y_buf.len() > param_size {
                    return Err(TpmRc::KEY.to_rc());
                }
                ecc_pub_key[param_size - x_buf.len()..param_size].copy_from_slice(x_buf);
                ecc_pub_key[param_size * 2 - y_buf.len()..param_size * 2].copy_from_slice(y_buf);
                &ecc_pub_key[..param_size * 2]
            }
            _ => return Err(TpmRc::TYPE.to_rc()),
        };

        // Extract signature info
        let mut sig_buf = [0u8; 512];
        let (sign_alg, hash_alg, sig_len) = match &cmd.signature {
            TpmtSignature::Rsassa(sig_rsa) => {
                let bytes = sig_rsa.sig.get_buffer();
                let key_len = public_key_bytes.len();
                if bytes.len() > key_len || key_len > sig_buf.len() {
                    return Err(TpmRc::SIGNATURE.with(Position::handle(2)));
                }
                let offset = key_len - bytes.len();
                sig_buf[offset..key_len].copy_from_slice(bytes);
                (Alg::RSASSA, Alg::from(sig_rsa.hash), key_len)
            }
            TpmtSignature::Rsapss(sig_rsa) => {
                let bytes = sig_rsa.sig.get_buffer();
                let key_len = public_key_bytes.len();
                if bytes.len() > key_len || key_len > sig_buf.len() {
                    return Err(TpmRc::SIGNATURE.with(Position::handle(2)));
                }
                let offset = key_len - bytes.len();
                sig_buf[offset..key_len].copy_from_slice(bytes);
                (Alg::RSAPSS, Alg::from(sig_rsa.hash), key_len)
            }
            TpmtSignature::Ecdsa(sig_ecc) => {
                let param_size = if !public_key_bytes.is_empty() {
                    public_key_bytes.len() / 2
                } else {
                    32
                };
                let r_bytes = sig_ecc.signature_r.get_buffer();
                let s_bytes = sig_ecc.signature_s.get_buffer();
                if r_bytes.len() > param_size || s_bytes.len() > param_size {
                    return Err(TpmRc::SIGNATURE.with(Position::handle(2)));
                }
                sig_buf[param_size - r_bytes.len()..param_size].copy_from_slice(r_bytes);
                sig_buf[param_size * 2 - s_bytes.len()..param_size * 2].copy_from_slice(s_bytes);
                (Alg::ECDSA, Alg::from(sig_ecc.hash), param_size * 2)
            }
            TpmtSignature::Ecdaa(sig_ecc) => {
                let param_size = if !public_key_bytes.is_empty() {
                    public_key_bytes.len() / 2
                } else {
                    32
                };
                let r_bytes = sig_ecc.signature_r.get_buffer();
                let s_bytes = sig_ecc.signature_s.get_buffer();
                if r_bytes.len() > param_size || s_bytes.len() > param_size {
                    return Err(TpmRc::SIGNATURE.with(Position::handle(2)));
                }
                sig_buf[param_size - r_bytes.len()..param_size].copy_from_slice(r_bytes);
                sig_buf[param_size * 2 - s_bytes.len()..param_size * 2].copy_from_slice(s_bytes);
                (Alg::ECDSA, Alg::from(sig_ecc.hash), param_size * 2)
            }
            _ => {
                return Err(TpmRc::SCHEME.with(Position::handle(2)));
            }
        };

        let mut hash_alg = hash_alg;
        if hash_alg == Alg::NULL {
            hash_alg = Alg::from(_obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?);
        }

        let digest_ha = tpm2::TpmtHa::from_alg(hash_alg, cmd.digest.get_buffer())
            .ok_or_else(|| TpmRc::SIGNATURE.with(Position::handle(2)))?;

        self.crypto()
            .verify_inner(sign_alg, public_key_bytes, digest_ha, &sig_buf[..sig_len])
            .map_err(|_| TpmRc::SIGNATURE.with(Position::handle(2)))?;

        // If key is in TPM_RH_NULL or nameAlg is TPM_ALG_NULL, return NULL ticket
        let ticket_hmac;
        let (hierarchy, digest) = match Handle(_obj.hierarchy) {
            Handle::RH_OWNER | Handle::RH_PLATFORM | Handle::RH_ENDORSEMENT
                if _obj.public.name_alg.is_some() =>
            {
                ticket_hmac = self.compute_verified_ticket(
                    _obj.hierarchy,
                    cmd.digest.get_buffer(),
                    _obj.name.get_buffer(),
                )?;
                (
                    Handle(_obj.hierarchy),
                    Tpm2bDigest::from_bytes(&ticket_hmac).unwrap(),
                )
            }
            _ => (Handle::RH_NULL, Tpm2bDigest::default()),
        };

        let rsp = responses::VerifySignature {
            validation: TpmtTkVerified::Verified(hierarchy, digest),
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::Sign] (`0x15D`) command.
    ///
    /// # Description
    /// This command signs an externally provided message digest using a loaded private key and returns the signature.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 20.1 (TPM2_Sign).
    ///
    /// # Relationships
    /// - The key referenced by `key_handle` must be a loaded signing key with the `sign` attribute set.
    /// - For ECDAA schemes, the signing process requires a commit counter generated by [TpmCc::Commit](commit.rs).
    pub fn sign(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal::<SignHandles>()?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal::<Sign>()?;

        let _obj = self.resolve_object(handles.key_handle.0, Position::handle(1))?;

        if !_obj
            .public
            .object_attributes
            .contains(TpmaObject::SIGN_ENCRYPT)
        {
            return Err(TpmRc::KEY.to_rc());
        }

        if _obj
            .public
            .object_attributes
            .contains(TpmaObject::X509_SIGN)
        {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }

        let (object_has_default, object_scheme_id, object_hash_alg) =
            match &_obj.public.parms_and_id {
                OwnedPublicParmsAndId::Rsa(parms, _) => match &parms.scheme {
                    Some(tpm2::TpmtRsaScheme::Rsassa(h)) => (true, Alg::RSASSA, Some(*h)),
                    Some(tpm2::TpmtRsaScheme::Rsapss(h)) => (true, Alg::RSAPSS, Some(*h)),
                    None => (false, Alg::NULL, None),
                    _ => (true, Alg::NULL, None),
                },
                OwnedPublicParmsAndId::Ecc(parms, _) => match &parms.scheme {
                    Some(tpm2::TpmtEccScheme::Ecdsa(h)) => (true, Alg::ECDSA, Some(*h)),
                    Some(tpm2::TpmtEccScheme::Ecdaa(s)) => (true, Alg::ECDAA, Some(s.hash_alg)),
                    Some(tpm2::TpmtEccScheme::Ecschnorr(h)) => (true, Alg::ECSCHNORR, Some(*h)),
                    Some(tpm2::TpmtEccScheme::Sm2(h)) => (true, Alg::SM2, Some(*h)),
                    None => (false, Alg::NULL, None),
                    _ => (true, Alg::NULL, None),
                },
                OwnedPublicParmsAndId::KeyedHash(scheme, _) => match scheme {
                    Some(tpm2::TpmtKeyedHashScheme::Hmac(h)) => (true, Alg::HMAC, Some(*h)),
                    None => (false, Alg::NULL, None),
                    _ => (true, Alg::NULL, None),
                },
                _ => (true, Alg::NULL, None),
            };

        if let Some(in_scheme) = &cmd.in_scheme {
            if let Some(h) = in_scheme.hash_alg()
                && h != TpmiAlgHash::Sha1
                && h != TpmiAlgHash::Sha256
                && h != TpmiAlgHash::Sha384
                && h != TpmiAlgHash::Sha512
                && h != TpmiAlgHash::Sm3_256
            {
                return Err(TpmRc::VALUE.with(Position::parameter(2)));
            }
        } else if !object_has_default {
            return Err(TpmRc::SCHEME.with(Position::parameter(2)));
        }

        let selected_scheme = if object_has_default {
            match cmd.in_scheme {
                None => match &_obj.public.parms_and_id {
                    OwnedPublicParmsAndId::Rsa(parms, _) => match parms.scheme {
                        Some(tpm2::TpmtRsaScheme::Rsassa(h)) => TpmtSigScheme::Rsassa(h),
                        Some(tpm2::TpmtRsaScheme::Rsapss(h)) => TpmtSigScheme::Rsapss(h),
                        _ => return Err(TpmRc::SCHEME.to_rc()),
                    },
                    OwnedPublicParmsAndId::Ecc(parms, _) => match parms.scheme {
                        Some(tpm2::TpmtEccScheme::Ecdsa(h)) => TpmtSigScheme::Ecdsa(h),
                        Some(tpm2::TpmtEccScheme::Ecdaa(s)) => TpmtSigScheme::Ecdaa(s),
                        _ => return Err(TpmRc::SCHEME.to_rc()),
                    },
                    OwnedPublicParmsAndId::KeyedHash(
                        Some(tpm2::TpmtKeyedHashScheme::Hmac(h)),
                        _,
                    ) => TpmtSigScheme::Hmac(*h),
                    _ => return Err(TpmRc::SCHEME.to_rc()),
                },
                Some(in_scheme) => {
                    let in_scheme_id = in_scheme.algorithm();
                    if in_scheme_id != object_scheme_id {
                        return Err(TpmRc::SCHEME.to_rc());
                    }
                    let in_hash_alg = in_scheme.hash_alg();
                    if object_hash_alg.is_some() && object_hash_alg != in_hash_alg {
                        return Err(TpmRc::SCHEME.to_rc());
                    }
                    in_scheme
                }
            }
        } else {
            cmd.in_scheme.ok_or(TpmRc::SCHEME.to_rc())?
        };

        // Validate selected scheme against key type
        match &_obj.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(..) => match &selected_scheme {
                TpmtSigScheme::Rsassa(_) | TpmtSigScheme::Rsapss(_) => {}
                _ => return Err(TpmRc::SCHEME.to_rc()),
            },
            OwnedPublicParmsAndId::Ecc(..) => match &selected_scheme {
                TpmtSigScheme::Ecdsa(_)
                | TpmtSigScheme::Ecdaa(_)
                | TpmtSigScheme::Sm2(_)
                | TpmtSigScheme::Ecschnorr(_) => {}
                _ => return Err(TpmRc::SCHEME.to_rc()),
            },
            OwnedPublicParmsAndId::KeyedHash(..) => match &selected_scheme {
                TpmtSigScheme::Hmac(_) => {}
                _ => return Err(TpmRc::VALUE.to_rc()),
            },
            _ => return Err(TpmRc::SCHEME.to_rc()),
        }

        let scheme_hash_alg = selected_scheme
            .hash_alg()
            .ok_or_else(|| TpmRc::SCHEME.to_rc())?;
        if scheme_hash_alg != TpmiAlgHash::Sha1
            && scheme_hash_alg != TpmiAlgHash::Sha256
            && scheme_hash_alg != TpmiAlgHash::Sha384
            && scheme_hash_alg != TpmiAlgHash::Sha512
            && scheme_hash_alg != TpmiAlgHash::Sm3_256
        {
            return Err(TpmRc::VALUE.with(Position::parameter(2)));
        }

        let is_restricted = _obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED);

        if cmd.validation.digest().get_size() != 0 || is_restricted {
            let ticket_hmac = self.compute_hashcheck_ticket(
                cmd.validation.hierarchy(),
                scheme_hash_alg,
                cmd.digest.get_buffer(),
            )?;
            if cmd.validation.digest().get_buffer() != ticket_hmac {
                return Err(TpmRc::TICKET.with(Position::parameter(3)));
            }
        } else {
            let expected_digest_len = match scheme_hash_alg {
                TpmiAlgHash::Sha1 => 20,
                TpmiAlgHash::Sha256 => 32,
                TpmiAlgHash::Sha384 => 48,
                TpmiAlgHash::Sha512 => 64,
                TpmiAlgHash::Sm3_256 => 32,
                _ => {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
            };
            if cmd.digest.get_size() as usize != expected_digest_len {
                return Err(TpmRc::SIZE.with(Position::parameter(1)));
            }
        }

        let hmac_bytes = if let TpmtSigScheme::Hmac(_) = &selected_scheme {
            let (computed_hmac, _) = self
                .compute_hmac(
                    scheme_hash_alg,
                    &_obj.private[.._obj.private_len],
                    &[cmd.digest.get_buffer()],
                )
                .map_err(|_| TpmRc::VALUE.with(Position::handle(1)))?;
            computed_hmac
        } else {
            [0u8; 64]
        };

        let mut sig_r = [0u8; 128];
        let mut sig_s = [0u8; 128];
        let mut sig_buf = [0u8; 512];
        let signature = if let TpmtSigScheme::Ecdaa(ecdaa_s) = &selected_scheme {
            let hash_alg = ecdaa_s.hash_alg;
            if ecdaa_s.count != self.global_state.commit_counter || ecdaa_s.count == 0 {
                return Err(TpmRc::VALUE.with(Position::parameter(2)));
            }
            let curve = match &_obj.public.parms_and_id {
                OwnedPublicParmsAndId::Ecc(parms, _) => parms.curve_id,
                _ => {
                    return Err(TpmRc::KEY.with(Position::handle(1)));
                }
            };
            let param_size = match curve {
                TpmEccCurve::NistP224 => 28,
                TpmEccCurve::NistP256 | TpmEccCurve::BNP256 => 32,
                TpmEccCurve::NistP384 => 48,
                TpmEccCurve::NistP521 => 66,
                _ => return Err(TpmRc::VALUE.to_rc()),
            };
            let commit_r =
                self.compute_commit_r(ecdaa_s.count, _obj.name.get_buffer(), param_size)?;
            self.crypto()
                .ecdaa_sign(
                    curve,
                    &commit_r[..param_size],
                    &self.global_state.commit_x[..param_size.min(32)],
                    &self.global_state.commit_p1[..(param_size * 2).min(64)],
                    &_obj.private[.._obj.private_len],
                    cmd.digest.get_buffer(),
                    &mut sig_r[..param_size],
                    &mut sig_s[..param_size],
                )
                .map_err(|_| TpmRc::VALUE.with(Position::handle(1)))?;
            TpmtSignature::Ecdaa(TpmsSignatureEcc {
                hash: hash_alg,
                signature_r: Tpm2bEccParameter::from_bytes(&sig_r[..param_size])
                    .map_err(|_| TpmRc::FAILURE)?,
                signature_s: Tpm2bEccParameter::from_bytes(&sig_s[..param_size])
                    .map_err(|_| TpmRc::FAILURE)?,
            })
        } else if let TpmtSigScheme::Hmac(_) = &selected_scheme {
            let tpmt_ha = tpm2::TpmtHa::new(
                scheme_hash_alg,
                &hmac_bytes[..scheme_hash_alg.digest_size()],
            )
            .ok_or_else(|| TpmRc::VALUE.with(Position::parameter(2)))?;
            TpmtSignature::Hmac(tpmt_ha)
        } else {
            let (sign_alg, resolved_hash_alg_tpmi) = match selected_scheme {
                TpmtSigScheme::Rsassa(h) => (Alg::RSASSA, h),
                TpmtSigScheme::Rsapss(h) => (Alg::RSAPSS, h),
                TpmtSigScheme::Ecdsa(h) => (Alg::ECDSA, h),
                _ => return Err(TpmRc::SCHEME.to_rc()),
            };

            let digest_ha = tpm2::TpmtHa::new(resolved_hash_alg_tpmi, cmd.digest.get_buffer())
                .ok_or_else(|| TpmRc::SIZE.with(Position::parameter(1)))?;

            let sig_len = self
                .crypto()
                .sign_inner(
                    sign_alg,
                    &_obj.private[.._obj.private_len],
                    digest_ha,
                    &mut sig_buf,
                )
                .map_err(|_| TpmRc::VALUE.with(Position::handle(1)))?;

            match selected_scheme {
                TpmtSigScheme::Rsassa(_) => TpmtSignature::Rsassa(TpmsSignatureRsa {
                    hash: resolved_hash_alg_tpmi,
                    sig: Tpm2bPublicKeyRsa::from_bytes(&sig_buf[..sig_len])
                        .map_err(|_| TpmRc::FAILURE)?,
                }),
                TpmtSigScheme::Rsapss(_) => TpmtSignature::Rsapss(TpmsSignatureRsa {
                    hash: resolved_hash_alg_tpmi,
                    sig: Tpm2bPublicKeyRsa::from_bytes(&sig_buf[..sig_len])
                        .map_err(|_| TpmRc::FAILURE)?,
                }),
                TpmtSigScheme::Ecdsa(_) => {
                    let param_size = sig_len / 2;
                    let signature_r = Tpm2bEccParameter::from_bytes(&sig_buf[..param_size])
                        .map_err(|_| TpmRc::FAILURE)?;
                    let signature_s = Tpm2bEccParameter::from_bytes(&sig_buf[param_size..sig_len])
                        .map_err(|_| TpmRc::FAILURE)?;
                    TpmtSignature::Ecdsa(TpmsSignatureEcc {
                        hash: resolved_hash_alg_tpmi,
                        signature_r,
                        signature_s,
                    })
                }
                _ => return Err(TpmRc::SCHEME.to_rc()),
            }
        };

        let rsp = responses::Sign { signature };
        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::RSAEncrypt] (`0x150`) command.
    ///
    /// # Description
    /// This command performs RSA encryption on a message using the public key of a loaded RSA key object.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 14.1 (TPM2_RSA_Encrypt).
    ///
    /// # Relationships
    /// - The key referenced by `key_handle` must be an RSA key.
    /// - Does not require authorization sessions, as it only uses public key parameters.
    pub fn rsa_encrypt(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal::<RSAEncryptHandles>()?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<RSAEncrypt>()?;

        let obj = self.resolve_object(handles.key_handle.0, Position::handle(1))?;

        // Validate the key referenced by key_handle is an RSA key
        let (key_bits, key_scheme, pub_key) = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(parms, pub_key) => {
                (parms.key_bits, parms.scheme, pub_key.get_buffer())
            }
            _ => {
                return Err(TpmRc::KEY.with(Position::handle(1)));
            }
        };

        // Validate attributes (RESTRICTED or !DECRYPT return TPM_RC_ATTRIBUTES)
        if obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED)
            || !obj.public.object_attributes.contains(TpmaObject::DECRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        // Resolve the padding scheme
        let (resolved_scheme, resolved_hash_alg) =
            self.resolve_rsa_scheme(key_scheme, cmd.in_scheme)?;

        // Check label constraints (must be zero-terminated if not empty)
        let label_bytes = cmd.label.get_buffer();
        if !label_bytes.is_empty() && label_bytes.last() != Some(&0) {
            return Err(TpmRc::VALUE.with(Position::handle(3)));
        }

        // Call self.crypto().encrypt(...) using resolved scheme/hash alg
        let key_size = (u16::from(key_bits) / 8) as usize;
        if cmd.message.get_buffer().len() > key_size {
            return Err(TpmRc::SIZE.with(Position::handle(1)));
        }
        let mut encrypted_data = [0u8; 512];
        let encrypted_len = self
            .crypto()
            .encrypt(
                resolved_scheme,
                resolved_hash_alg,
                pub_key,
                cmd.message.get_buffer(),
                &mut encrypted_data[..key_size],
                label_bytes,
            )
            .map_err(|_| TpmRc::VALUE.with(Position::handle(1)))?;

        let rsp = responses::RSAEncrypt {
            out_data: Tpm2bPublicKeyRsa::from_bytes(&encrypted_data[..encrypted_len])
                .map_err(|_| TpmRc::FAILURE)?,
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::RSADecrypt] (`0x159`) command.
    ///
    /// # Description
    /// This command performs RSA decryption on a ciphertext using the private key of a loaded RSA decryption key.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 14.2 (TPM2_RSA_Decrypt).
    ///
    /// # Relationships
    /// - The key referenced by `key_handle` must be an unrestricted decryption RSA key.
    /// - Requires USER authorization for the decryption key.
    pub fn rsa_decrypt(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal::<RSADecryptHandles>()?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<RSADecrypt>()?;

        let obj = self.resolve_object(handles.key_handle.0, Position::handle(1))?;

        if obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED)
        {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }

        if !obj.public.object_attributes.contains(TpmaObject::DECRYPT) {
            return Err(TpmRc::KEY.to_rc());
        }

        let (key_bits, key_scheme) = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(parms, _) => (parms.key_bits, parms.scheme),
            _ => return Err(TpmRc::KEY.to_rc()),
        };

        let (resolved_scheme, resolved_hash_alg) =
            self.resolve_rsa_scheme(key_scheme, cmd.in_scheme)?;

        // Check label constraints (must be zero-terminated if not empty)
        let label_bytes = cmd.label.get_buffer();
        if !label_bytes.is_empty() && label_bytes.last() != Some(&0) {
            return Err(TpmRc::VALUE.with(Position::handle(3)));
        }

        let key_size = (u16::from(key_bits) / 8) as usize;
        let mut decrypted_message = [0u8; 512];
        let decrypted_len = self
            .crypto()
            .decrypt(
                resolved_scheme,
                resolved_hash_alg,
                &obj.private[..obj.private_len],
                cmd.cipher_text.get_buffer(),
                &mut decrypted_message,
                label_bytes,
            )
            .map_err(|_| TpmRc::VALUE.with(Position::handle(1)))?;

        let mut m_bytes = &decrypted_message[..decrypted_len];
        let mut padded = [0u8; 512];
        if resolved_scheme == Alg::NULL && m_bytes.len() < key_size {
            padded[key_size - m_bytes.len()..key_size].copy_from_slice(m_bytes);
            m_bytes = &padded[..key_size];
        }

        let rsp = responses::RSADecrypt {
            message: Tpm2bPublicKeyRsa::from_bytes(m_bytes).map_err(|_| TpmRc::FAILURE)?,
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    fn resolve_rsa_scheme(
        &self,
        key_scheme: Option<TpmtRsaScheme>,
        in_scheme: Option<TpmtRsaDecrypt>,
    ) -> Result<(Alg, Alg), TpmRc> {
        let (resolved_scheme, resolved_hash_alg) = match (key_scheme, in_scheme) {
            (None, None) => (Alg::NULL, Alg::NULL),
            (None, Some(TpmtRsaDecrypt::Oaep(details))) => (Alg::OAEP, Alg::from(details)),
            (None, Some(TpmtRsaDecrypt::Rsaes)) => (Alg::RSAES, Alg::NULL),
            (Some(TpmtRsaScheme::Oaep(key_details)), None) => (Alg::OAEP, Alg::from(key_details)),
            (Some(TpmtRsaScheme::Oaep(key_details)), Some(TpmtRsaDecrypt::Oaep(cmd_details))) => {
                if cmd_details != key_details {
                    return Err(TpmRc::SCHEME.with(Position::handle(2)));
                }
                (Alg::OAEP, Alg::from(key_details))
            }
            (Some(TpmtRsaScheme::Rsaes), None)
            | (Some(TpmtRsaScheme::Rsaes), Some(TpmtRsaDecrypt::Rsaes)) => (Alg::RSAES, Alg::NULL),
            _ => {
                return Err(TpmRc::SCHEME.with(Position::handle(2)));
            }
        };

        Ok((resolved_scheme, resolved_hash_alg))
    }

    /// Handles the [TpmCc::Hmac] (`0x187`) command.
    ///
    /// # Description
    /// This command performs an HMAC or MAC operation on a message buffer using a loaded Keyed Hash object.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 15.2 (TPM2_HMAC / TPM2_MAC).
    ///
    /// # Relationships
    /// - The key referenced by `handle` must be a loaded Keyed Hash signing object.
    /// - For sequence-based HMAC operations, use [TpmCc::HmacStart] instead.
    pub fn mac(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal::<HmacHandles>()?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal::<Hmac>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let obj = self.resolve_object(handles.handle.0, Position::handle(1))?;

        let scheme = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::KeyedHash(scheme, _) => scheme,
            _ => return Err(TpmRc::TYPE.with(Position::handle(1))),
        };

        let key_hash_alg = match scheme {
            Some(TpmtKeyedHashScheme::Hmac(scheme_hash)) => {
                let key_hash_alg = Alg::from(*scheme_hash);
                let cmd_hash_alg = cmd.hash_alg.map(Alg::from).unwrap_or(Alg::NULL);
                if cmd_hash_alg != Alg::NULL && cmd_hash_alg != key_hash_alg {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
                key_hash_alg
            }
            None => {
                let key_hash_alg = cmd.hash_alg.map(Alg::from).unwrap_or(Alg::NULL);
                if key_hash_alg == Alg::NULL {
                    return Err(TpmRc::VALUE.with(Position::parameter(2)));
                }
                key_hash_alg
            }
            _ => return Err(TpmRc::TYPE.with(Position::handle(1))),
        };

        if obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }
        if !obj
            .public
            .object_attributes
            .contains(TpmaObject::SIGN_ENCRYPT)
        {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }
        if obj.private_len == 0 {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }

        if key_hash_alg != Alg::SHA1
            && key_hash_alg != Alg::SHA256
            && key_hash_alg != Alg::SHA384
            && key_hash_alg != Alg::SHA512
        {
            return Err(TpmRc::HASH.with(Position::parameter(2)));
        }
        let key_hash_alg = TpmiAlgHash::try_from(key_hash_alg)
            .map_err(|_| TpmRc::HASH.with(Position::parameter(2)))?;

        let key = &obj.private[..obj.private_len];
        let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
        let digest = tpm2::crypto::hmac(
            self.crypto(),
            key_hash_alg,
            key,
            cmd.buffer.get_buffer(),
            &mut digest_buf,
        )
        .map_err(|_| TpmRc::FAILURE)?;
        let out_hmac = Tpm2bDigest::from_bytes(digest.digest()).map_err(|_| TpmRc::FAILURE)?;

        let rsp = responses::Hmac { out_hmac };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::ECDHZGen] (`0x186`) command.
    ///
    /// # Description
    /// This command performs an ECDH point multiplication between a loaded private ECC key and an external public ECC point
    /// to generate a shared secret `Z`.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 14.4 (TPM2_ECDH_ZGen).
    ///
    /// # Relationships
    /// - The key referenced by `key_handle` must be a loaded ECC decryption key with the scheme set to ECDH (or Null).
    /// - Used in ECDH key exchange protocols to derive symmetric encryption keys.
    pub fn ecdh_zgen(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal::<ECDHZGenHandles>()?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<ECDHZGen>()?;

        let obj_holder;
        let obj = if handles.key_handle.0 >> 24 == 0x80 {
            self.global_state
                .find_transient_object(handles.key_handle.0)
                .ok_or(TpmRc::HANDLE.to_rc())?
        } else if handles.key_handle.0 >> 24 == 0x81 {
            obj_holder = self
                .context
                .load_persistent_object(self.global_state, handles.key_handle.0)
                .map_err(|_| TpmRc::HANDLE.to_rc())?;
            &obj_holder
        } else {
            return Err(TpmRc::HANDLE.to_rc());
        };

        if obj.private_len == 0 {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }

        if obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED)
            || !obj.public.object_attributes.contains(TpmaObject::DECRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        let curve = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Ecc(ecc_parms, _) => {
                match ecc_parms.scheme {
                    Some(TpmtEccScheme::Ecdh(_)) | None => {}
                    _ => return Err(TpmRc::SCHEME.with(Position::handle(1))),
                }
                ecc_parms.curve_id
            }
            _ => return Err(TpmRc::KEY.with(Position::handle(1))),
        };

        let in_point_struct = cmd
            .in_point
            .to_struct()
            .map_err(|_| TpmRc::SIZE.with(Position::parameter(1)))?;

        let in_x = in_point_struct.x.get_buffer();
        let in_y = in_point_struct.y.get_buffer();
        let param_size = match curve {
            TpmEccCurve::NistP224 => 28,
            TpmEccCurve::NistP256 | TpmEccCurve::BNP256 => 32,
            TpmEccCurve::NistP384 => 48,
            TpmEccCurve::NistP521 => 66,
            _ => return Err(TpmRc::CURVE.with(Position::handle(1))),
        };

        if in_x.len() > param_size || in_y.len() > param_size {
            return Err(TpmRc::ECC_POINT.with(Position::parameter(1)));
        }

        let mut raw_point = [0u8; 256];
        raw_point[param_size - in_x.len()..param_size].copy_from_slice(in_x);
        raw_point[param_size * 2 - in_y.len()..param_size * 2].copy_from_slice(in_y);

        self.crypto()
            .validate_point(curve, &raw_point[..param_size * 2])
            .map_err(|_| TpmRc::ECC_POINT.with(Position::parameter(1)))?;

        let mut z_buf = [0u8; 256];
        self.crypto()
            .point_multiply(
                curve,
                &obj.private[..obj.private_len],
                &raw_point[..param_size * 2],
                &mut z_buf[..param_size * 2],
            )
            .map_err(|e| match e {
                CryptoError::InvalidData => TpmRc::NO_RESULT,
                _ => TpmRc::ECC_POINT.with(Position::parameter(1)),
            })?;

        let z_x =
            Tpm2bEccParameter::from_bytes(&z_buf[..param_size]).map_err(|_| TpmRc::FAILURE)?;
        let z_y = Tpm2bEccParameter::from_bytes(&z_buf[param_size..param_size * 2])
            .map_err(|_| TpmRc::FAILURE)?;

        let rsp = responses::ECDHZGen {
            out_point: tpm2::Tpm2b(TpmsEccPoint { x: z_x, y: z_y }),
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }
}
