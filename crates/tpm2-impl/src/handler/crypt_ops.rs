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
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let _obj = self.resolve_object(handles.key_handle.0, Position::handle(1))?;

        // The object to validate the signature must be a signing key.
        if !_obj
            .public
            .object_attributes
            .contains(TpmaObject::SIGN_ENCRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        // CryptValidateSignature(): TPM_RC_SCHEME, TPM_RC_HANDLE or TPM_RC_SIGNATURE, all
        // reported against the `signature` parameter (RcSafeAddToResult).
        self.validate_signature(&_obj, cmd.digest.get_buffer(), &cmd.signature)
            .map_err(|rc| rc.with_position(Position::parameter(2)))?;

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

    /// Verifies `signature` over `digest` with the loaded key `obj`, mirroring
    /// `CryptValidateSignature` (`CryptUtil.c`) and the per-type validators it dispatches to.
    ///
    /// As in C, no consistency between the key's default scheme and the signature scheme is
    /// required for asymmetric keys (a caller can load any public key with any scheme);
    /// only keyed-hash keys with a non-NULL scheme restrict the accepted HMAC scheme.
    ///
    /// Returns bare (position-less) response codes:
    /// - `TPM_RC_SCHEME`: the signature algorithm is not supported for the key type
    ///   (including ECDAA, which can't be verified by the TPM, and the unimplemented
    ///   `TPM_ALG_SM2` / `TPM_ALG_ECSCHNORR`);
    /// - `TPM_RC_HANDLE`: a keyed-hash key whose sensitive area is not loaded;
    /// - `TPM_RC_SIGNATURE`: the signature is malformed or not genuine;
    /// - `TPM_RC_VALUE`: the key's curve is not supported.
    fn validate_signature(
        &self,
        obj: &super::TransientObject,
        digest: &[u8],
        signature: &TpmtSignature<'_>,
    ) -> Result<(), TpmRc> {
        let mut pub_key = [0u8; 512];
        let mut sig_buf = [0u8; 512];
        let (sign_alg, hash_alg, pub_len, sig_len) = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(parms, unique) => {
                // CryptRsaValidateSignature()
                let (sign_alg, sig_rsa) = match signature {
                    TpmtSignature::Rsassa(sig) => (Alg::RSASSA, sig),
                    TpmtSignature::Rsapss(sig) => (Alg::RSAPSS, sig),
                    _ => return Err(TpmRc::SCHEME.to_rc()),
                };
                let modulus = unique.get_buffer();
                let sig_bytes = sig_rsa.sig.get_buffer();
                if sig_bytes.len() != modulus.len() {
                    return Err(TpmRc::SIGNATURE.to_rc());
                }
                let key_size = (u16::from(parms.key_bits) / 8) as usize;
                if modulus.len() > key_size || key_size > pub_key.len() {
                    return Err(TpmRc::SIGNATURE.to_rc());
                }
                let offset = key_size - modulus.len();
                pub_key[offset..key_size].copy_from_slice(modulus);
                sig_buf[offset..key_size].copy_from_slice(sig_bytes);
                (sign_alg, Alg::from(sig_rsa.hash), key_size, key_size)
            }
            OwnedPublicParmsAndId::Ecc(parms, point) => {
                // CryptEccValidateSignature()
                let order =
                    super::commit::curve_order(parms.curve_id).ok_or(TpmRc::VALUE.to_rc())?;
                let param_size = match parms.curve_id {
                    TpmEccCurve::NistP224 => 28,
                    TpmEccCurve::NistP256 | TpmEccCurve::BNP256 => 32,
                    TpmEccCurve::NistP384 => 48,
                    TpmEccCurve::NistP521 => 66,
                    _ => return Err(TpmRc::VALUE.to_rc()),
                };
                let sig_ecc = match signature {
                    TpmtSignature::Ecdsa(sig) => sig,
                    _ => return Err(TpmRc::SCHEME.to_rc()),
                };
                let x_buf = point.x.get_buffer();
                let y_buf = point.y.get_buffer();
                if x_buf.len() > param_size || y_buf.len() > param_size {
                    return Err(TpmRc::SIGNATURE.to_rc());
                }
                pub_key[param_size - x_buf.len()..param_size].copy_from_slice(x_buf);
                pub_key[param_size * 2 - y_buf.len()..param_size * 2].copy_from_slice(y_buf);

                // r and s have to be greater than 0 but less than the curve order.
                for (i, component) in [&sig_ecc.signature_r, &sig_ecc.signature_s]
                    .into_iter()
                    .enumerate()
                {
                    let bytes = strip_leading_zeros(component.get_buffer());
                    if bytes.is_empty() || bytes.len() > param_size {
                        return Err(TpmRc::SIGNATURE.to_rc());
                    }
                    let slot = &mut sig_buf[i * param_size..(i + 1) * param_size];
                    slot[param_size - bytes.len()..].copy_from_slice(bytes);
                    if *slot >= *order {
                        return Err(TpmRc::SIGNATURE.to_rc());
                    }
                }
                (
                    Alg::ECDSA,
                    Alg::from(sig_ecc.hash),
                    param_size * 2,
                    param_size * 2,
                )
            }
            OwnedPublicParmsAndId::KeyedHash(key_scheme, _) => {
                if obj.private_len == 0 {
                    return Err(TpmRc::HANDLE.to_rc());
                }
                // CryptHMACVerifySignature()
                let ha = match signature {
                    TpmtSignature::Hmac(ha) => ha,
                    _ => return Err(TpmRc::SCHEME.to_rc()),
                };
                match key_scheme {
                    None => {}
                    Some(TpmtKeyedHashScheme::Hmac(h)) if *h == ha.hash_alg() => {}
                    Some(_) => return Err(TpmRc::SIGNATURE.to_rc()),
                }
                let (hmac_bytes, hmac_len) = self
                    .compute_hmac(ha.hash_alg(), &obj.private[..obj.private_len], &[digest])
                    .map_err(|_| TpmRc::SIGNATURE.to_rc())?;
                if ha.digest() != &hmac_bytes[..hmac_len] {
                    return Err(TpmRc::SIGNATURE.to_rc());
                }
                return Ok(());
            }
            _ => return Err(TpmRc::SCHEME.to_rc()),
        };

        let digest_ha =
            tpm2::TpmtHa::from_alg(hash_alg, digest).ok_or_else(|| TpmRc::SIGNATURE.to_rc())?;
        self.crypto()
            .verify_inner(
                sign_alg,
                &pub_key[..pub_len],
                digest_ha,
                &sig_buf[..sig_len],
            )
            .map_err(|_| TpmRc::SIGNATURE.to_rc())
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
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let _obj = self.resolve_object(handles.key_handle.0, Position::handle(1))?;

        // IsSigningObject(): the key must have `sign` set and must not be a symmetric cipher.
        if !_obj
            .public
            .object_attributes
            .contains(TpmaObject::SIGN_ENCRYPT)
            || matches!(_obj.public.parms_and_id, OwnedPublicParmsAndId::Sym(..))
        {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }

        // A key that will be used for x.509 signatures can't be used in TPM2_Sign().
        if _obj
            .public
            .object_attributes
            .contains(TpmaObject::X509_SIGN)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        // CryptSelectSignScheme(): any failure is TPM_RC_SCHEME + RC_Sign_inScheme.
        let selected_scheme = select_sign_scheme(&_obj.public.parms_and_id, cmd.in_scheme)
            .ok_or_else(|| TpmRc::SCHEME.with(Position::parameter(2)))?;
        let scheme_hash_alg = selected_scheme
            .hash_alg()
            .ok_or_else(|| TpmRc::SCHEME.with(Position::parameter(2)))?;

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
        } else if cmd.digest.get_size() as usize != scheme_hash_alg.digest_size() {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }

        // Defense in depth: a public-only object (e.g. loaded by TPM2_LoadExternal without a
        // sensitive area) cannot be authorized for USER role in C (`IsAuthValueAvailable` /
        // `IsAuthPolicyAvailable`), so it never reaches TPM2_Sign. Never sign with an empty key.
        if _obj.private_len == 0 {
            return Err(TpmRc::AUTH_UNAVAILABLE);
        }

        let mut sig_r = [0u8; 128];
        let mut sig_s = [0u8; 128];
        let mut sig_buf = [0u8; 512];
        let hmac_bytes: [u8; 64];
        let signature = if let TpmtSigScheme::Ecdaa(ecdaa_s) = &selected_scheme {
            let hash_alg = ecdaa_s.hash_alg;
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
            // CryptGenerateR(): the count must reference an outstanding commitment
            // (TPM_RC_VALUE otherwise, as returned by TpmEcc_SignEcdaa()).
            let (commit_r, r_len) =
                self.generate_committed_r(ecdaa_s.count, _obj.name.get_buffer(), curve)?;
            debug_assert_eq!(r_len, param_size);
            self.crypto()
                .ecdaa_sign(
                    curve,
                    &commit_r[..param_size],
                    &self.global_state.commit_x[..param_size],
                    &self.global_state.commit_p1[..param_size * 2],
                    &_obj.private[.._obj.private_len],
                    cmd.digest.get_buffer(),
                    &mut sig_r[..param_size],
                    &mut sig_s[..param_size],
                )
                .map_err(|_| TpmRc::VALUE.with(Position::handle(1)))?;
            let signature = TpmtSignature::Ecdaa(TpmsSignatureEcc {
                hash: hash_alg,
                signature_r: Tpm2bEccParameter::from_bytes(&sig_r[..param_size])
                    .map_err(|_| TpmRc::FAILURE)?,
                signature_s: Tpm2bEccParameter::from_bytes(&sig_s[..param_size])
                    .map_err(|_| TpmRc::FAILURE)?,
            });
            // CryptEndCommit(): the signature succeeded, so the commitment can never be
            // used again (reusing `r` would reveal the private key).
            self.end_commit(ecdaa_s.count);
            signature
        } else if let TpmtSigScheme::Hmac(_) = &selected_scheme {
            (hmac_bytes, _) = self
                .compute_hmac(
                    scheme_hash_alg,
                    &_obj.private[.._obj.private_len],
                    &[cmd.digest.get_buffer()],
                )
                .map_err(|_| TpmRc::VALUE.with(Position::handle(1)))?;
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
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

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

        // The key must have the decryption attribute. Only the public portion is used, so
        // (unlike TPM2_RSA_Decrypt) restricted keys are allowed (`RSA_Encrypt.c`).
        if !obj.public.object_attributes.contains(TpmaObject::DECRYPT) {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        // Check label constraints (must be zero-terminated if not empty)
        let label_bytes = cmd.label.get_buffer();
        if !label_bytes.is_empty() && label_bytes.last() != Some(&0) {
            return Err(TpmRc::VALUE.with(Position::parameter(3)));
        }

        // Resolve the padding scheme
        let (resolved_scheme, resolved_hash_alg) =
            self.resolve_rsa_scheme(key_scheme, cmd.in_scheme)?;

        // Call self.crypto().encrypt(...) using resolved scheme/hash alg. CryptRsaEncrypt()
        // errors are returned without a position; a message that is too large for the key is
        // TPM_RC_VALUE.
        let key_size = (u16::from(key_bits) / 8) as usize;
        if cmd.message.get_buffer().len() > key_size {
            return Err(TpmRc::VALUE.to_rc());
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
            .map_err(|_| TpmRc::VALUE.to_rc())?;

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
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let obj = self.resolve_object(handles.key_handle.0, Position::handle(1))?;

        // The selected key must be an RSA key...
        let (key_bits, key_scheme, modulus_len) = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(parms, unique) => {
                (parms.key_bits, parms.scheme, unique.get_buffer().len())
            }
            _ => return Err(TpmRc::KEY.with(Position::handle(1))),
        };

        // ...and an unrestricted decryption key (`RSA_Decrypt.c`).
        if obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED)
            || !obj.public.object_attributes.contains(TpmaObject::DECRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        // Check label constraints (must be zero-terminated if not empty)
        let label_bytes = cmd.label.get_buffer();
        if !label_bytes.is_empty() && label_bytes.last() != Some(&0) {
            return Err(TpmRc::VALUE.with(Position::parameter(3)));
        }

        let (resolved_scheme, resolved_hash_alg) =
            self.resolve_rsa_scheme(key_scheme, cmd.in_scheme)?;

        // CryptRsaDecrypt(): the ciphertext must be exactly the size of the modulus. Its
        // errors are returned without a position.
        if cmd.cipher_text.get_buffer().len() != modulus_len {
            return Err(TpmRc::SIZE.to_rc());
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
            .map_err(|_| TpmRc::VALUE.to_rc())?;

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
                    return Err(TpmRc::SCHEME.with(Position::parameter(2)));
                }
                (Alg::OAEP, Alg::from(key_details))
            }
            (Some(TpmtRsaScheme::Rsaes), None)
            | (Some(TpmtRsaScheme::Rsaes), Some(TpmtRsaDecrypt::Rsaes)) => (Alg::RSAES, Alg::NULL),
            _ => {
                return Err(TpmRc::SCHEME.with(Position::parameter(2)));
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

        // HMAC.c order: key type, then `restricted`, then `sign`, and only then the hash
        // algorithm selection.
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
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let obj = self.resolve_object(handles.key_handle.0, Position::handle(1))?;

        // ECDH_ZGen.c order: the key must be an ECC key, then an unrestricted decryption key,
        // then its scheme must be ECDH or NULL.
        let (curve, scheme) = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Ecc(ecc_parms, _) => (ecc_parms.curve_id, ecc_parms.scheme),
            _ => return Err(TpmRc::KEY.with(Position::handle(1))),
        };

        if obj
            .public
            .object_attributes
            .contains(TpmaObject::RESTRICTED)
            || !obj.public.object_attributes.contains(TpmaObject::DECRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        match scheme {
            Some(TpmtEccScheme::Ecdh(_)) | None => {}
            _ => return Err(TpmRc::SCHEME.with(Position::handle(1))),
        }

        // Defense in depth: a public-only key cannot be authorized in C (AUTH_UNAVAILABLE), so
        // it never reaches the point multiplication with the (missing) private scalar.
        if obj.private_len == 0 {
            return Err(TpmRc::KEY.with(Position::handle(1)));
        }

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

/// Returns `true` if `hash_alg` is a hash algorithm implemented (and advertised in
/// `TPM_CAP_ALGS`) by this TPM, i.e. `CryptHashIsValidAlg(hash_alg, FALSE)`.
fn is_implemented_hash(hash_alg: TpmiAlgHash) -> bool {
    matches!(
        hash_alg,
        TpmiAlgHash::Sha1 | TpmiAlgHash::Sha256 | TpmiAlgHash::Sha384 | TpmiAlgHash::Sha512
    )
}

/// Selects the signing scheme for `TPM2_Sign`, mirroring `CryptSelectSignScheme` and
/// `CryptIsValidSignScheme` (`CryptUtil.c`).
///
/// - If the key has no default scheme (`TPM_ALG_NULL`), the input scheme is used and must not
///   be `TPM_ALG_NULL`.
/// - If the input scheme is `TPM_ALG_NULL`, the key's default scheme is used, unless it is a
///   split-signing scheme (ECDAA), which requires caller-provided data (the commit count).
/// - Otherwise both schemes must have the same algorithm and hash.
///
/// The resulting scheme must be a signing scheme valid for the key type, and its hash must be
/// an implemented hash. Signing schemes that this TPM does not implement (`TPM_ALG_SM2`,
/// `TPM_ALG_ECSCHNORR`, EdDSA; none are listed in `TPM_CAP_ALGS`) are treated as invalid, as
/// in a C build without those algorithms.
///
/// Returns `None` on any failure; the caller reports `TPM_RC_SCHEME + RC_Sign_inScheme`.
fn select_sign_scheme(
    parms: &OwnedPublicParmsAndId,
    in_scheme: Option<TpmtSigScheme>,
) -> Option<TpmtSigScheme> {
    // `Ok(None)`: the key has a NULL scheme. `Err(())`: the key's scheme is not a signing
    // scheme (e.g. OAEP, ECDH, XOR), so neither copying it nor matching it can succeed.
    let object_scheme: Result<Option<TpmtSigScheme>, ()> = match parms {
        OwnedPublicParmsAndId::Rsa(p, _) => match p.scheme {
            None => Ok(None),
            Some(TpmtRsaScheme::Rsassa(h)) => Ok(Some(TpmtSigScheme::Rsassa(h))),
            Some(TpmtRsaScheme::Rsapss(h)) => Ok(Some(TpmtSigScheme::Rsapss(h))),
            Some(_) => Err(()),
        },
        OwnedPublicParmsAndId::Ecc(p, _) => match p.scheme {
            None => Ok(None),
            Some(TpmtEccScheme::Ecdsa(h)) => Ok(Some(TpmtSigScheme::Ecdsa(h))),
            Some(TpmtEccScheme::Ecdaa(s)) => Ok(Some(TpmtSigScheme::Ecdaa(s))),
            Some(TpmtEccScheme::Sm2(h)) => Ok(Some(TpmtSigScheme::Sm2(h))),
            Some(TpmtEccScheme::Ecschnorr(h)) => Ok(Some(TpmtSigScheme::Ecschnorr(h))),
            Some(_) => Err(()),
        },
        OwnedPublicParmsAndId::KeyedHash(scheme, _) => match scheme {
            None => Ok(None),
            Some(TpmtKeyedHashScheme::Hmac(h)) => Ok(Some(TpmtSigScheme::Hmac(*h))),
            Some(_) => Err(()),
        },
        // Only RSA, ECC and keyed-hash objects can sign.
        _ => return None,
    };

    let selected = match (object_scheme.ok()?, in_scheme) {
        // Input and default can't both be NULL.
        (None, None) => return None,
        (None, Some(input)) => input,
        // ECDAA is a split-signing scheme: the caller must provide the commit count.
        (Some(TpmtSigScheme::Ecdaa(_)), None) => return None,
        (Some(default), None) => default,
        (Some(default), Some(input)) => {
            if default.algorithm() != input.algorithm() || default.hash_alg() != input.hash_alg() {
                return None;
            }
            // Keep the input scheme: it may carry split-signing data (the ECDAA count).
            input
        }
    };

    let valid_for_key = match parms {
        OwnedPublicParmsAndId::Rsa(..) => {
            matches!(
                selected,
                TpmtSigScheme::Rsassa(_) | TpmtSigScheme::Rsapss(_)
            )
        }
        OwnedPublicParmsAndId::Ecc(..) => {
            matches!(selected, TpmtSigScheme::Ecdsa(_) | TpmtSigScheme::Ecdaa(_))
        }
        OwnedPublicParmsAndId::KeyedHash(..) => matches!(selected, TpmtSigScheme::Hmac(_)),
        _ => false,
    };
    if !valid_for_key || !selected.hash_alg().is_some_and(is_implemented_hash) {
        return None;
    }
    Some(selected)
}

/// Returns `bytes` without its leading zero bytes (the magnitude of a big-endian integer).
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_non_zero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first_non_zero..]
}
