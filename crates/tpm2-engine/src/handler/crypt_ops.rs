use crate::Platform;
use crate::handle_checks::{Tpmi, check};
use crate::owned::OwnedPublicParmsAndId;
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::TpmEccCurve;
use tpm2::commands::responses;
#[allow(deprecated)] // TPM2_Sign / TPM2_VerifySignature are deprecated in the `tpm2` crate.
use tpm2::commands::{ECDHZGen, HMAC, RSADecrypt, RSAEncrypt, Sign, VerifySignature};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Tpm2bDigest, Tpm2bEccParameter, Tpm2bPublicKeyRsa, TpmaObject, TpmiAlgHash, TpmsEccPoint,
    TpmsSignatureEcc, TpmsSignatureRsa, TpmtEccScheme, TpmtKeyedHashScheme, TpmtRsaDecrypt,
    TpmtRsaScheme, TpmtSigScheme, TpmtSignature, TpmtTkVerified,
};

use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Alg;
#[cfg(not(feature = "reference-rng"))]
use tpm2::crypto::Rng;
use tpm2::crypto::{Crypto, EccPrivateKey, RsaPrivateKey};

impl<'b, P: Platform> CommandHandler<'b, P> {
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
    #[allow(deprecated)] // TPM2_VerifySignature is deprecated in the `tpm2` crate.
    pub fn verify_signature(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<VerifySignature>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<VerifySignature>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // A sequence object is a loaded object without the *sign* attribute (C
        // `AllocateSequenceSlot()` sets only *noDA*), so it is rejected like any other
        // non-signing object (`TPM_RC_ATTRIBUTES` + `RC_VerifySignature_keyHandle` in the
        // reference; TPM 2.0 Part 3, TPM2_VerifySignature, gives no code for it).
        if self
            .context
            .state
            .find_active_sequence(key_handle.0)
            .is_some()
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }
        let _obj = self.resolve_object(key_handle.0, Position::handle(1))?;

        // The object to validate the signature must be a signing key.
        if !_obj
            .public
            .object_attributes
            .contains(TpmaObject::SIGN_ENCRYPT)
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
        }

        // TPM 2.0 Part 3, "Signing commands overview": `TPM2_VerifySignature()` with (pure) ML-DSA
        // and HashML-DSA keys is "Not supported" (they verify messages, external-mu digests or
        // pre-hashed digests with `TPM2_VerifySequenceComplete()`/`TPM2_VerifyDigestSignature()`
        // instead): no scheme of the key can verify a `TPM2_VerifySignature()` digest.
        if super::pqc::mldsa_key(&_obj).is_some() {
            return Err(TpmRc::SCHEME.with(Position::parameter(2)));
        }

        // CryptValidateSignature(): TPM_RC_SCHEME, TPM_RC_HANDLE or TPM_RC_SIGNATURE, all
        // reported against the `signature` parameter (RcSafeAddToResult).
        self.validate_signature(&_obj, cmd.digest.get_buffer(), &cmd.signature)
            .map_err(|rc| rc.with_position(Position::parameter(2)))?;

        // If key is in TPM_RH_NULL or nameAlg is TPM_ALG_NULL, return NULL ticket. A key in a
        // firmware-limited or SVN-limited hierarchy (including `TPM_RH_FW_NULL` and the
        // SVN-limited NULL hierarchies) gets a ticket of that hierarchy, with its derived proof
        // (C `GetHierarchy()` returns the object's own hierarchy).
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
                    Tpm2bDigest::from_bytes(ticket_hmac.get_buffer()).unwrap(),
                )
            }
            h if crate::hierarchy::is_limited(h.0) && _obj.public.name_alg.is_some() => {
                ticket_hmac = self.compute_verified_ticket(
                    h.0,
                    cmd.digest.get_buffer(),
                    _obj.name.get_buffer(),
                )?;
                (
                    h,
                    Tpm2bDigest::from_bytes(ticket_hmac.get_buffer()).unwrap(),
                )
            }
            _ => (Handle::RH_NULL, Tpm2bDigest::default()),
        };

        let rsp = responses::VerifySignature {
            validation: TpmtTkVerified::Verified(hierarchy, digest),
        };

        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
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
    ///   (including ECDAA, which can't be verified by the TPM, and `TPM_ALG_SM2` /
    ///   `TPM_ALG_ECSCHNORR` in a build without the `sm2` / `ecschnorr` feature);
    /// - `TPM_RC_HANDLE`: a keyed-hash key whose sensitive area is not loaded;
    /// - `TPM_RC_SIGNATURE`: the signature is malformed or not genuine;
    /// - `TPM_RC_VALUE`: the key's curve is not supported.
    pub(crate) fn validate_signature(
        &mut self,
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
                let key_size = (parms.key_bits.as_u16() / 8) as usize;
                if modulus.len() > key_size || key_size > pub_key.len() {
                    return Err(TpmRc::SIGNATURE.to_rc());
                }
                let offset = key_size - modulus.len();
                pub_key[offset..key_size].copy_from_slice(modulus);
                sig_buf[offset..key_size].copy_from_slice(sig_bytes);
                // `CryptRsaValidateSignature()` tests the scheme (the RSASSA-PSS test draws
                // from the TPM's DRBG), then `RSAEP()` rejects a signature that is not below the
                // modulus before `PssDecode()` hashes with the signature's hash algorithm.
                self.do_self_test(sign_alg)?;
                if sign_alg == Alg::RSAPSS && sig_bytes < modulus {
                    self.do_self_test(Alg::from(sig_rsa.hash))?;
                }
                (sign_alg, Alg::from(sig_rsa.hash), key_size, key_size)
            }
            OwnedPublicParmsAndId::Ecc(parms, point) => {
                // CryptEccValidateSignature()
                let curve = parms.curve_id;
                let order = super::commit::curve_order(curve).ok_or(TpmRc::VALUE.to_rc())?;
                let param_size =
                    crate::ecc_curves::param_size(curve).ok_or(TpmRc::VALUE.to_rc())?;
                let (sign_alg, sig_ecc) = match signature {
                    TpmtSignature::Ecdsa(sig) => (Alg::ECDSA, sig),
                    #[cfg(feature = "sm2")]
                    TpmtSignature::Sm2(sig) => (Alg::SM2, sig),
                    #[cfg(feature = "ecschnorr")]
                    TpmtSignature::Ecschnorr(sig) => (Alg::ECSCHNORR, sig),
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
                // `TpmEcc_ValidateSignatureEcdsa()` and `TpmEcc_ValidateSignatureEcSchnorr()`
                // multiply points with `TpmEcc_PointMult()`, which tests ECDH;
                // `TpmEcc_ValidateSignatureEcSm2()` multiplies without it. The signature schemes
                // themselves are tested by signing only.
                if sign_alg != Alg::SM2 {
                    self.crypto()
                        .do_self_test(Alg::ECDH)
                        .map_err(|_| TpmRc::FAILURE)?;
                }
                if sign_alg != Alg::ECDSA || !provider_ecdsa_curve(curve) {
                    // The schemes and curves the crypto backend's verification does not cover.
                    let (r, s) = sig_buf[..2 * param_size].split_at(param_size);
                    let q = &pub_key[..2 * param_size];
                    let crypto = self.crypto();
                    let verified = match sign_alg {
                        Alg::ECDSA => {
                            crate::ecc_schemes::ecdsa_verify::<P::Crypto>(curve, q, digest, r, s)
                        }
                        Alg::SM2 => {
                            crate::ecc_schemes::sm2_verify::<P::Crypto>(curve, q, digest, r, s)
                        }
                        _ => crate::ecc_schemes::schnorr_verify(
                            &crypto,
                            curve,
                            sig_ecc.hash,
                            q,
                            digest,
                            r,
                            s,
                        ),
                    };
                    return match verified {
                        Ok(true) => Ok(()),
                        Ok(false) | Err(_) => Err(TpmRc::SIGNATURE.to_rc()),
                    };
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
        let verified = verify_signature_with_backend::<P::Crypto>(
            sign_alg,
            &obj.public.parms_and_id,
            &pub_key[..pub_len],
            digest_ha,
            &sig_buf[..sig_len],
        );
        match verified {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(TpmRc::SIGNATURE.to_rc()),
        }
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
    #[allow(deprecated)] // TPM2_Sign is deprecated in the `tpm2` crate.
    pub fn sign(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<Sign>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<Sign>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let _obj = self.resolve_object(key_handle.0, Position::handle(1))?;

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

        // TPM 2.0 Part 3, "Signing commands overview": `TPM2_Sign()` with (pure) ML-DSA and
        // HashML-DSA keys is "Not supported" (they sign with `TPM2_SignSequenceComplete()` and
        // `TPM2_SignDigest()`): no signing scheme can be selected, `TPM_RC_SCHEME + RC_Sign_inScheme`.
        if super::pqc::mldsa_key(&_obj).is_some() {
            return Err(TpmRc::SCHEME.with(Position::parameter(2)));
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
            if cmd.validation.digest().get_buffer() != ticket_hmac.get_buffer() {
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

        let mut bufs = SignatureBuffers::new();
        let signature = self.sign_with_scheme(
            &_obj,
            &selected_scheme,
            cmd.digest.get_buffer(),
            SignPositions {
                key: Position::handle(1),
                digest: Position::parameter(1),
                scheme: Position::parameter(2),
            },
            &mut bufs,
        )?;

        let rsp = responses::Sign { signature };
        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Signs `digest` with the loaded key `obj` and the already selected and validated scheme
    /// `selected_scheme` (`CryptSign()`): the core of `TPM2_Sign`, shared by `TPM2_SignDigest`
    /// and `TPM2_SignSequenceComplete`. The caller has checked the key (a signing key with its
    /// private part), the scheme (`select_sign_scheme`) and the digest size or ticket.
    ///
    /// The returned signature borrows from `bufs`; `pos` gives the positions the errors are
    /// reported against (the key handle, the digest and the scheme parameter of the command).
    pub(crate) fn sign_with_scheme<'s>(
        &mut self,
        obj: &super::TransientObject,
        selected_scheme: &TpmtSigScheme,
        digest: &[u8],
        pos: SignPositions,
        bufs: &'s mut SignatureBuffers,
    ) -> Result<TpmtSignature<'s>, TpmRc> {
        let scheme_hash_alg = selected_scheme
            .hash_alg()
            .ok_or_else(|| TpmRc::SCHEME.with(pos.scheme))?;
        let SignatureBuffers {
            r: sig_r,
            s: sig_s,
            sig: sig_buf,
            hmac: hmac_bytes,
        } = bufs;
        let signature = if let TpmtSigScheme::Ecdaa(ecdaa_s) = selected_scheme {
            let hash_alg = ecdaa_s.hash_alg;
            let curve = match &obj.public.parms_and_id {
                OwnedPublicParmsAndId::Ecc(parms, _) => parms.curve_id,
                _ => {
                    return Err(TpmRc::KEY.with(pos.key));
                }
            };
            let param_size = match crate::ecc_curves::param_size(curve) {
                Some(size) => size,
                None => return Err(TpmRc::VALUE.to_rc()),
            };
            // CryptGenerateR(): the count must reference an outstanding commitment
            // (TPM_RC_VALUE otherwise, as returned by TpmEcc_SignEcdaa()).
            let (commit_r, r_len) =
                self.generate_committed_r(ecdaa_s.count, obj.name.get_buffer(), curve)?;
            debug_assert_eq!(r_len, param_size);
            let (k_len, s_len) = self.ecdaa_sign(
                curve,
                hash_alg,
                &commit_r[..param_size],
                &obj.private[..obj.private_len],
                digest,
                &mut sig_r[..param_size],
                &mut sig_s[..param_size],
            )?;
            let signature = TpmtSignature::Ecdaa(TpmsSignatureEcc {
                hash: hash_alg,
                signature_r: Tpm2bEccParameter::from_bytes(&sig_r[..k_len])
                    .map_err(|_| TpmRc::FAILURE)?,
                signature_s: Tpm2bEccParameter::from_bytes(&sig_s[..s_len])
                    .map_err(|_| TpmRc::FAILURE)?,
            });
            // CryptEndCommit(): the signature succeeded, so the commitment can never be
            // used again (reusing `r` would reveal the private key).
            self.end_commit(ecdaa_s.count);
            signature
        } else if let TpmtSigScheme::Hmac(_) = selected_scheme {
            let (hmac_out, _) = self
                .compute_hmac(scheme_hash_alg, &obj.private[..obj.private_len], &[digest])
                .map_err(|_| TpmRc::VALUE.with(pos.key))?;
            *hmac_bytes = hmac_out;
            let tpmt_ha = tpm2::TpmtHa::new(
                scheme_hash_alg,
                &hmac_bytes[..scheme_hash_alg.digest_size()],
            )
            .ok_or_else(|| TpmRc::VALUE.with(pos.scheme))?;
            TpmtSignature::Hmac(tpmt_ha)
        } else {
            let (sign_alg, resolved_hash_alg_tpmi) = match *selected_scheme {
                TpmtSigScheme::Rsassa(h) => (Alg::RSASSA, h),
                TpmtSigScheme::Rsapss(h) => (Alg::RSAPSS, h),
                TpmtSigScheme::Ecdsa(h) => (Alg::ECDSA, h),
                #[cfg(feature = "sm2")]
                TpmtSigScheme::Sm2(h) => (Alg::SM2, h),
                #[cfg(feature = "ecschnorr")]
                TpmtSigScheme::Ecschnorr(h) => (Alg::ECSCHNORR, h),
                _ => return Err(TpmRc::SCHEME.to_rc()),
            };

            let digest_ha = tpm2::TpmtHa::new(resolved_hash_alg_tpmi, digest)
                .ok_or_else(|| TpmRc::SIZE.with(pos.digest))?;

            let sig_len = match self.sign_asymmetric(
                sign_alg,
                &obj.public.parms_and_id,
                &obj.private[..obj.private_len],
                digest_ha,
                &mut sig_buf[..],
            ) {
                Ok(Some(len)) => len,
                Ok(None) | Err(_) => return Err(TpmRc::VALUE.with(pos.key)),
            };

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
                TpmtSigScheme::Ecdsa(_) => TpmtSignature::Ecdsa(ecc_signature(
                    resolved_hash_alg_tpmi,
                    &sig_buf[..sig_len],
                )?),
                #[cfg(feature = "sm2")]
                TpmtSigScheme::Sm2(_) => {
                    TpmtSignature::Sm2(ecc_signature(resolved_hash_alg_tpmi, &sig_buf[..sig_len])?)
                }
                #[cfg(feature = "ecschnorr")]
                TpmtSigScheme::Ecschnorr(_) => TpmtSignature::Ecschnorr(ecc_signature(
                    resolved_hash_alg_tpmi,
                    &sig_buf[..sig_len],
                )?),
                _ => return Err(TpmRc::SCHEME.to_rc()),
            }
        };
        Ok(signature)
    }

    /// Signs `digest` with the asymmetric scheme `sign_alg` (RSASSA, RSAPSS or ECDSA) and the
    /// private key of an object with public parameters `key` (`CryptSign()`), writing the
    /// signature (`r || s` for ECDSA) to `out`.
    ///
    /// With `reference-rng`, the random parts (the ECDSA nonce, the PSS salt) are drawn from the
    /// TPM's DRBG exactly as in the reference code; otherwise the crypto backend signs.
    pub(crate) fn sign_asymmetric(
        &mut self,
        sign_alg: Alg,
        key: &OwnedPublicParmsAndId,
        private_key: &[u8],
        digest: tpm2::TpmtHa<'_>,
        out: &mut [u8],
    ) -> Result<Option<usize>, tpm2::crypto::CryptoError> {
        // `CryptRsaSign()`/`CryptEccSign()` test the signature scheme first (the RSASSA-PSS and
        // ECDSA tests draw from the TPM's DRBG).
        self.do_self_test(sign_alg)
            .map_err(|_| tpm2::crypto::CryptoError::Internal)?;
        let signed = self.sign_asymmetric_tested(sign_alg, key, private_key, digest, out);
        // `PssEncode()` hashes with the signature's hash algorithm (RSASSA's encoding does not
        // hash).
        if sign_alg == Alg::RSAPSS && matches!(signed, Ok(Some(_))) {
            self.do_self_test(Alg::from(digest.hash_alg()))
                .map_err(|_| tpm2::crypto::CryptoError::Internal)?;
        }
        signed
    }

    /// [`Self::sign_asymmetric`] after the self test of `sign_alg`.
    fn sign_asymmetric_tested(
        &mut self,
        sign_alg: Alg,
        key: &OwnedPublicParmsAndId,
        private_key: &[u8],
        digest: tpm2::TpmtHa<'_>,
        out: &mut [u8],
    ) -> Result<Option<usize>, tpm2::crypto::CryptoError> {
        #[cfg(feature = "reference-rng")]
        match (sign_alg, key) {
            (Alg::ECDSA | Alg::SM2 | Alg::ECSCHNORR, OwnedPublicParmsAndId::Ecc(parms, _)) => {
                const MAX: usize = TpmEccCurve::MAX_ECC_KEY_BYTES;
                let (mut r, mut s) = ([0u8; MAX], [0u8; MAX]);
                let len = self
                    .reference_ecc_sign(
                        sign_alg,
                        digest.hash_alg(),
                        parms.curve_id,
                        private_key,
                        digest.digest(),
                        &mut r,
                        &mut s,
                    )
                    .map_err(|_| tpm2::crypto::CryptoError::Internal)?;
                let out = out
                    .get_mut(..2 * len)
                    .ok_or(tpm2::crypto::CryptoError::Internal)?;
                out[..len].copy_from_slice(&r[..len]);
                out[len..].copy_from_slice(&s[..len]);
                return Ok(Some(2 * len));
            }
            (Alg::RSAPSS, OwnedPublicParmsAndId::Rsa(parms, unique)) => {
                let hash = digest.hash_alg();
                return self
                    .reference_rsa_pss_sign(
                        hash,
                        parms,
                        unique.get_buffer(),
                        private_key,
                        digest.digest(),
                        out,
                    )
                    .map_err(|_| tpm2::crypto::CryptoError::Internal);
            }
            _ => {}
        }
        #[cfg(not(feature = "reference-rng"))]
        if let OwnedPublicParmsAndId::Ecc(parms, _) = key {
            // The schemes and curves the crypto backend's signing interface cannot express, with
            // nonces from the backend's random number generator.
            let curve = parms.curve_id;
            let crypto = crate::self_test::Tested::<P::Crypto>::new(&self.context.self_test);
            let rng = &mut self.context.crypto_rng;
            let nonce = |buf: &mut [u8]| rng.fill_bytes(buf);
            match sign_alg {
                Alg::ECDSA if !provider_ecdsa_curve(curve) => {
                    return crate::ecc_schemes::ecdsa_sign::<P::Crypto>(
                        curve,
                        private_key,
                        digest.digest(),
                        nonce,
                        out,
                    );
                }
                Alg::SM2 => {
                    return crate::ecc_schemes::sm2_sign::<P::Crypto>(
                        curve,
                        private_key,
                        digest.digest(),
                        nonce,
                        out,
                    );
                }
                Alg::ECSCHNORR => {
                    return crate::ecc_schemes::schnorr_sign(
                        &crypto,
                        curve,
                        digest.hash_alg(),
                        private_key,
                        digest.digest(),
                        nonce,
                        out,
                    );
                }
                _ => {}
            }
        }
        let hash = digest.hash_alg();
        let scheme = match sign_alg {
            Alg::RSASSA => TpmtSigScheme::Rsassa(hash),
            Alg::RSAPSS => TpmtSigScheme::Rsapss(hash),
            Alg::ECDSA => TpmtSigScheme::Ecdsa(hash),
            _ => return Err(tpm2::crypto::CryptoError::Unsupported),
        };
        let rng = &mut self.context.crypto_rng;
        let mut sig = [0u8; tpm2::crypto::MAX_SIGNATURE_BYTES];
        let signature = match key {
            OwnedPublicParmsAndId::Rsa(parms, unique) => {
                let Some(private) =
                    super::rsa_private_key::<P::Crypto>(parms, unique.get_buffer(), private_key)?
                else {
                    return Ok(None);
                };
                private.sign(rng, scheme, digest.digest(), &mut sig)?
            }
            OwnedPublicParmsAndId::Ecc(parms, _) => {
                let Some(private) =
                    EccPrivateKey::<P::Crypto>::from_scalar(parms.curve_id, private_key)?
                else {
                    return Ok(None);
                };
                private.sign(rng, scheme, digest.digest(), &mut sig)?
            }
            _ => return Err(tpm2::crypto::CryptoError::Unsupported),
        };
        write_signature(&signature, out)
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
        let handles = request.try_unmarshal_handles::<RSAEncrypt>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<RSAEncrypt>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let obj = self.resolve_object(key_handle.0, Position::handle(1))?;

        // Validate the key referenced by key_handle is an RSA key
        let (key_bits, key_scheme, exponent, pub_key) = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(parms, pub_key) => (
                parms.key_bits,
                parms.scheme,
                parms.exponent,
                pub_key.get_buffer(),
            ),
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
        // `CryptRsaEncrypt()` tests the scheme first (the RSAES and OAEP tests draw from the
        // TPM's DRBG; `TPM_ALG_NULL` is raw RSA, which needs no test of its own here).
        self.do_self_test(resolved_scheme)?;

        // Encrypt with the resolved scheme/hash alg (`crate::rsa::rsa_encrypt`). CryptRsaEncrypt()
        // errors are returned without a position; a message that is too large for the key is
        // TPM_RC_VALUE.
        let key_size = (key_bits.as_u16() / 8) as usize;
        if cmd.message.get_buffer().len() > key_size {
            return Err(TpmRc::VALUE.to_rc());
        }
        let mut encrypted_data = [0u8; 512];
        // With `reference-rng`, OAEP and RSAES padding are drawn from the TPM's DRBG exactly as
        // in the reference code (`OaepEncode()`, `RSAES_PKCS1v1_5Encode()`).
        #[cfg(feature = "reference-rng")]
        let encrypted = match resolved_scheme {
            Alg::OAEP | Alg::RSAES => {
                let hash = if resolved_scheme == Alg::OAEP {
                    Some(
                        tpm2::TpmiAlgHash::try_from(resolved_hash_alg)
                            .map_err(|_| TpmRc::HASH.to_rc())?,
                    )
                } else {
                    None
                };
                match self.reference_rsa_encrypt(
                    hash,
                    pub_key,
                    exponent,
                    label_bytes,
                    cmd.message.get_buffer(),
                    &mut encrypted_data[..key_size],
                ) {
                    Ok(r) => Ok(r),
                    Err(e) if e == TpmRc::VALUE.to_rc() || e == TpmRc::HASH.to_rc() => Ok(None),
                    Err(e) => return Err(e),
                }
            }
            _ => Self::rsa_encrypt_with(
                &mut self.context.crypto_rng,
                &obj,
                resolved_scheme,
                resolved_hash_alg,
                label_bytes,
                cmd.message.get_buffer(),
                &mut encrypted_data[..key_size],
            ),
        };
        #[cfg(not(feature = "reference-rng"))]
        let encrypted = Self::rsa_encrypt_with(
            &mut self.context.crypto_rng,
            &obj,
            resolved_scheme,
            resolved_hash_alg,
            label_bytes,
            cmd.message.get_buffer(),
            &mut encrypted_data[..key_size],
        );
        #[cfg(not(feature = "reference-rng"))]
        let _ = (exponent, pub_key);
        let encrypted_len = match encrypted {
            Ok(Some(len)) => len,
            Ok(None) | Err(_) => return Err(TpmRc::VALUE.to_rc()),
        };
        // `OaepEncode()` hashes the label once its size checks passed.
        if resolved_scheme == Alg::OAEP {
            self.do_self_test(resolved_hash_alg)?;
        }

        let rsp = responses::RSAEncrypt {
            out_data: Tpm2bPublicKeyRsa::from_bytes(&encrypted_data[..encrypted_len])
                .map_err(|_| TpmRc::FAILURE)?,
        };

        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
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
        let handles = request.try_unmarshal_handles::<RSADecrypt>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<RSADecrypt>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let obj = self.resolve_object(key_handle.0, Position::handle(1))?;

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

        // CryptRsaDecrypt(): the ciphertext must be exactly the size of the modulus, and RSADP
        // rejects a value that is not below the modulus (`TPM_RC_SIZE` as well). Its errors are
        // returned without a position. TPM 2.0 Part 3, TPM2_RSA_Decrypt, only assigns
        // `TPM_RC_VALUE` to padding failures ("It will then validate the padding according to
        // the selected scheme. If the padding checks fail, `TPM_RC_VALUE` is returned."); RFC
        // 8017 RSADP's "ciphertext representative out of range" has no code there, so the
        // reference's is used.
        let modulus = match &obj.public.parms_and_id {
            OwnedPublicParmsAndId::Rsa(_, unique) => unique.get_buffer(),
            _ => &[],
        };
        if cmd.cipher_text.get_buffer().len() != modulus_len {
            return Err(TpmRc::SIZE.to_rc());
        }
        // The scheme's self test follows the size check (the RSAES and OAEP tests draw from the
        // TPM's DRBG), and precedes `RSADP()`.
        self.do_self_test(resolved_scheme)?;
        if cmd.cipher_text.get_buffer() >= modulus {
            return Err(TpmRc::SIZE.to_rc());
        }

        let key_size = (key_bits.as_u16() / 8) as usize;
        let mut decrypted_message = [0u8; 512];
        let private_key = obj.rsa_private_key::<P::Crypto>();
        let decrypted = match &private_key {
            Ok(Some(key)) => crate::rsa::rsa_decrypt::<P::Crypto>(
                &mut self.context.crypto_rng,
                key,
                resolved_scheme,
                resolved_hash_alg,
                label_bytes,
                cmd.cipher_text.get_buffer(),
                &mut decrypted_message,
            ),
            Ok(None) => Ok(None),
            Err(e) => Err(*e),
        };
        if resolved_scheme == Alg::OAEP
            && let Ok(Some(key)) = &private_key
        {
            self.oaep_decode_hash_test(
                key,
                cmd.cipher_text.get_buffer(),
                resolved_hash_alg,
                matches!(decrypted, Ok(Some(_))),
            )?;
        }
        let decrypted_len = match decrypted {
            Ok(Some(len)) => len,
            Ok(None) | Err(_) => return Err(TpmRc::VALUE.to_rc()),
        };

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
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// The hash self test of `OaepDecode()`, which hashes (MGF1, the label) unless the decrypted
    /// block is too small for two digests or does not start with a zero octet. `decoded`: the
    /// OAEP decryption succeeded (so the block was well formed); otherwise the raw RSA
    /// decryption of `ciphertext` with `key` decides.
    pub(crate) fn oaep_decode_hash_test(
        &mut self,
        key: &RsaPrivateKey<P::Crypto>,
        ciphertext: &[u8],
        hash_alg: Alg,
        decoded: bool,
    ) -> Result<(), TpmRc> {
        let hash_runs = decoded || {
            let digest_size = tpm2::TpmiAlgHash::try_from(hash_alg)
                .map(|h| h.digest_size())
                .unwrap_or(0);
            let mut block = [0u8; 512];
            // A `TPM_ALG_NULL` decryption is the size of the modulus.
            ciphertext.len() >= 2 * digest_size + 2
                && matches!(
                    crate::rsa::rsa_decrypt::<P::Crypto>(
                        &mut self.context.crypto_rng,
                        key,
                        Alg::NULL,
                        Alg::NULL,
                        &[],
                        ciphertext,
                        &mut block,
                    ),
                    Ok(Some(_)) if block[0] == 0
                )
        };
        if hash_runs {
            self.do_self_test(hash_alg)?;
        }
        Ok(())
    }

    /// Encrypts `message` with the RSA public key of `obj` (`crate::rsa::rsa_encrypt`, with the
    /// same arguments); `Ok(None)` for an invalid public key.
    #[allow(clippy::too_many_arguments)]
    fn rsa_encrypt_with(
        rng: &mut <P::Crypto as tpm2::crypto::Random>::Rng,
        obj: &super::TransientObject,
        scheme: Alg,
        hash_alg: Alg,
        label: &[u8],
        message: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, tpm2::crypto::CryptoError> {
        match obj.rsa_public_key::<P::Crypto>()? {
            Some(key) => crate::rsa::rsa_encrypt::<P::Crypto>(
                rng, &key, scheme, hash_alg, label, message, out,
            ),
            None => Ok(None),
        }
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

    /// Handles the [TpmCc::HMAC] (`0x155`) command.
    ///
    /// # Description
    /// This command performs an HMAC or MAC operation on a message buffer using a loaded Keyed Hash object.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 15.2 (TPM2_HMAC / TPM2_MAC).
    ///
    /// # Relationships
    /// - The key referenced by `handle` must be a loaded Keyed Hash signing object.
    /// - For sequence-based HMAC operations, use [TpmCc::HMACStart] instead.
    pub fn mac(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal_handles::<HMAC>()?;
        let [handle] = handles;
        check(handle, Tpmi::DhObject, Position::handle(1))?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let cmd = request.try_unmarshal_command::<HMAC>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // A sequence object is a loaded object of type `TPM_ALG_NULL` (C
        // `AllocateSequenceSlot()`), not a MAC key. TPM 2.0 Part 3: "If the key type is neither
        // `TPM_ALG_KEYEDHASH` nor `TPM_ALG_SYMCIPHER` then the TPM shall return `TPM_RC_TYPE`."
        // (the text does not order this against the *sign* check; the reference checks the type
        // first).
        if self.context.state.find_active_sequence(handle.0).is_some() {
            return Err(TpmRc::TYPE.with(Position::handle(1)));
        }
        let obj = self.resolve_object(handle.0, Position::handle(1))?;

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
        let mut digest_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let digest = self
            .crypto()
            .hmac(
                key_hash_alg,
                key,
                &[cmd.buffer.get_buffer()],
                &mut digest_buf,
            )
            .map_err(|_| TpmRc::FAILURE)?;
        let out_hmac = Tpm2bDigest::from_bytes(digest.digest()).map_err(|_| TpmRc::FAILURE)?;

        let rsp = responses::HMAC { out_hmac };

        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
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
        let handles = request.try_unmarshal_handles::<ECDHZGen>()?;
        let [key_handle] = handles;
        check(key_handle, Tpmi::DhObject, Position::handle(1))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<ECDHZGen>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let obj = self.resolve_object(key_handle.0, Position::handle(1))?;

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
        let param_size = match crate::ecc_curves::param_size(curve) {
            Some(size) => size,
            None => return Err(TpmRc::CURVE.with(Position::handle(1))),
        };

        if in_x.len() > param_size || in_y.len() > param_size {
            return Err(TpmRc::ECC_POINT.with(Position::parameter(1)));
        }

        let mut raw_point = [0u8; 256];
        raw_point[param_size - in_x.len()..param_size].copy_from_slice(in_x);
        raw_point[param_size * 2 - in_y.len()..param_size * 2].copy_from_slice(in_y);

        if !matches!(
            crate::ecc_curves::validate_point::<P::Crypto>(curve, &raw_point[..param_size * 2]),
            Ok(true)
        ) {
            return Err(TpmRc::ECC_POINT.with(Position::parameter(1)));
        }

        let mut z_buf = [0u8; 256];
        // exp mapped `CryptoError::InvalidData` (point at infinity) to `TPM_RC_NO_RESULT` and
        // every other error to `TPM_RC_ECC_POINT`; the former is now reported as `Ok(None)`.
        match self.crypto().point_multiply(
            curve,
            &obj.private[..obj.private_len],
            &raw_point[..param_size * 2],
            &mut z_buf[..param_size * 2],
        ) {
            Ok(Some(_)) => {}
            Ok(None) => return Err(TpmRc::NO_RESULT),
            Err(_) => return Err(TpmRc::ECC_POINT.with(Position::parameter(1))),
        }

        let z_x =
            Tpm2bEccParameter::from_bytes(&z_buf[..param_size]).map_err(|_| TpmRc::FAILURE)?;
        let z_y = Tpm2bEccParameter::from_bytes(&z_buf[param_size..param_size * 2])
            .map_err(|_| TpmRc::FAILURE)?;

        let rsp = responses::ECDHZGen {
            out_point: tpm2::Tpm2b(TpmsEccPoint { x: z_x, y: z_y }),
        };

        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }
}

/// Buffers backing the signature built by [`CommandHandler::sign_with_scheme`] (the `r` and
/// `s` halves of an ECC signature, the RSA signature and the HMAC).
pub(crate) struct SignatureBuffers {
    r: [u8; 128],
    s: [u8; 128],
    sig: [u8; 512],
    hmac: [u8; 64],
}

impl SignatureBuffers {
    /// Zeroed buffers.
    pub(crate) fn new() -> Self {
        Self {
            r: [0; 128],
            s: [0; 128],
            sig: [0; 512],
            hmac: [0; 64],
        }
    }
}

/// The positions that the errors of [`CommandHandler::sign_with_scheme`] are reported against.
#[derive(Clone, Copy)]
pub(crate) struct SignPositions {
    /// The signing key handle.
    pub(crate) key: Position,
    /// The digest parameter.
    pub(crate) digest: Position,
    /// The scheme parameter (the key handle for commands that have none).
    pub(crate) scheme: Position,
}

/// Returns `true` if `hash_alg` is a hash algorithm implemented (and advertised in
/// `TPM_CAP_ALGS`) by this TPM, i.e. `CryptHashIsValidAlg(hash_alg, FALSE)`.
fn is_implemented_hash(hash_alg: TpmiAlgHash) -> bool {
    crate::handler::capability::is_implemented_algorithm(tpm2::Alg::from(hash_alg))
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
/// an implemented hash. Signing schemes that this TPM does not implement (EdDSA, and SM2 or
/// EC-Schnorr without the `sm2`/`ecschnorr` features; not listed in `TPM_CAP_ALGS`) are treated
/// as invalid, as in a C build without those algorithms.
///
/// Returns `None` on any failure; the caller reports `TPM_RC_SCHEME + RC_Sign_inScheme`.
pub(crate) fn select_sign_scheme(
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
            #[cfg(feature = "sm2")]
            Some(TpmtEccScheme::Sm2(h)) => Ok(Some(TpmtSigScheme::Sm2(h))),
            #[cfg(feature = "ecschnorr")]
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
        OwnedPublicParmsAndId::Ecc(..) => match selected {
            TpmtSigScheme::Ecdsa(_) | TpmtSigScheme::Ecdaa(_) => true,
            #[cfg(feature = "sm2")]
            TpmtSigScheme::Sm2(_) => true,
            #[cfg(feature = "ecschnorr")]
            TpmtSigScheme::Ecschnorr(_) => true,
            _ => false,
        },
        OwnedPublicParmsAndId::KeyedHash(..) => matches!(selected, TpmtSigScheme::Hmac(_)),
        _ => false,
    };
    if !valid_for_key || !selected.hash_alg().is_some_and(is_implemented_hash) {
        return None;
    }
    Some(selected)
}

/// Verifies the signature `signature` (the RSA signature, or `r || s` with each component the
/// size of the curve) with the scheme `sign_alg` (RSASSA, RSAPSS or ECDSA on the curves of
/// [`provider_ecdsa_curve`]) over `digest` with the crypto backend, for the key with the public
/// parameters `key` and the public key `public` (the modulus, or `x || y` with each coordinate the
/// size of the curve). `Ok(false)`: the signature does not verify or the public key is not valid.
pub(crate) fn verify_signature_with_backend<C: Crypto>(
    sign_alg: Alg,
    key: &OwnedPublicParmsAndId,
    public: &[u8],
    digest: tpm2::TpmtHa<'_>,
    signature: &[u8],
) -> Result<bool, tpm2::crypto::CryptoError> {
    let hash = digest.hash_alg();
    match (sign_alg, key) {
        (Alg::RSASSA | Alg::RSAPSS, OwnedPublicParmsAndId::Rsa(parms, _)) => {
            let Some(sig) = Tpm2bPublicKeyRsa::new(signature) else {
                return Ok(false);
            };
            let sig = TpmsSignatureRsa { hash, sig };
            let signature = if sign_alg == Alg::RSAPSS {
                TpmtSignature::Rsapss(sig)
            } else {
                TpmtSignature::Rsassa(sig)
            };
            match super::rsa_public_key::<C>(parms, public)? {
                Some(key) => key.verify(digest.digest(), signature),
                None => Ok(false),
            }
        }
        (Alg::ECDSA, OwnedPublicParmsAndId::Ecc(parms, _)) => {
            let (r, s) = signature.split_at(signature.len() / 2);
            let (Some(signature_r), Some(signature_s)) =
                (Tpm2bEccParameter::new(r), Tpm2bEccParameter::new(s))
            else {
                return Ok(false);
            };
            let signature = TpmtSignature::Ecdsa(TpmsSignatureEcc {
                hash,
                signature_r,
                signature_s,
            });
            match crate::ecc_curves::load_point::<C>(parms.curve_id, public)? {
                Some(key) => key.verify(digest.digest(), signature),
                None => Ok(false),
            }
        }
        _ => Err(tpm2::crypto::CryptoError::Unsupported),
    }
}

/// Writes the RSA signature or the ECC signature `r || s` (each component the size of the curve)
/// of `signature` to `out`, returning its length.
fn write_signature(
    signature: &TpmtSignature<'_>,
    out: &mut [u8],
) -> Result<Option<usize>, tpm2::crypto::CryptoError> {
    let parts: [&[u8]; 2] = match signature {
        TpmtSignature::Rsassa(s) | TpmtSignature::Rsapss(s) => [s.sig.as_slice(), &[]],
        TpmtSignature::Ecdsa(s) => [s.signature_r.as_slice(), s.signature_s.as_slice()],
        _ => return Err(tpm2::crypto::CryptoError::Internal),
    };
    let mut len = 0;
    for part in parts {
        out.get_mut(len..len + part.len())
            .ok_or(tpm2::crypto::CryptoError::Internal)?
            .copy_from_slice(part);
        len += part.len();
    }
    Ok(Some(len))
}

/// The `TPMS_SIGNATURE_ECC` with the scheme hash `hash` of the signature `rs` (`r || s`, two
/// halves of the order size).
pub(crate) fn ecc_signature(hash: TpmiAlgHash, rs: &[u8]) -> Result<TpmsSignatureEcc<'_>, TpmRc> {
    let (r, s) = rs.split_at(rs.len() / 2);
    Ok(TpmsSignatureEcc {
        hash,
        signature_r: Tpm2bEccParameter::from_bytes(r).map_err(|_| TpmRc::FAILURE)?,
        signature_s: Tpm2bEccParameter::from_bytes(s).map_err(|_| TpmRc::FAILURE)?,
    })
}

/// Whether the crypto backend's ECDSA (the [`EccPrivateKey::sign`]/[`tpm2::crypto::EccPublicKey::verify`]
/// dispatch used by [`CommandHandler::sign_asymmetric`] and [`CommandHandler::validate_signature`])
/// signs and verifies on `curve`: the NIST curves P-224 to P-521. ECDSA on the other curves (BN
/// P-256, NIST P-192, BN P-638, SM2 P-256) is computed by [`crate::ecc_schemes`].
pub(crate) fn provider_ecdsa_curve(curve: TpmEccCurve) -> bool {
    matches!(
        curve,
        TpmEccCurve::NistP224
            | TpmEccCurve::NistP256
            | TpmEccCurve::NistP384
            | TpmEccCurve::NistP521
    )
}

/// Whether the ECDSA signature components `r` and `s` are in `[1, n - 1]` for the order `n` of
/// `curve` (`CryptEccValidateSignature()` rejects other values before it multiplies points).
pub(crate) fn ecdsa_signature_in_range(curve: TpmEccCurve, r: &[u8], s: &[u8]) -> bool {
    let Some(order) = super::commit::curve_order(curve) else {
        return false;
    };
    [r, s].into_iter().all(|component| {
        let bytes = strip_leading_zeros(component);
        let order = strip_leading_zeros(order);
        !bytes.is_empty()
            && (bytes.len() < order.len() || (bytes.len() == order.len() && bytes < order))
    })
}

/// Returns `bytes` without its leading zero bytes (the magnitude of a big-endian integer).
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_non_zero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first_non_zero..]
}
