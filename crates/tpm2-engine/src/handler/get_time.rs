use crate::Platform;
use crate::handle_checks::{Tpmi, check};
use crate::{
    handler::{CommandHandler, TransientObject},
    owned::{
        OwnedEccParameter, OwnedPublic, OwnedPublicKeyRsa, OwnedPublicParmsAndId, OwnedSignature,
    },
    req_resp::RequestThenResponse,
};
use tpm2::Alg;
use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::GetTime;
use tpm2::commands::responses;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmGenerated};
use tpm2::{
    TpmaObject, TpmiAlgHash, TpmsAttest, TpmsTimeAttestInfo, TpmtEccScheme, TpmtKeyedHashScheme,
    TpmtRsaScheme, TpmtSigScheme, TpmuAttest,
};

/// The default signing scheme of a key, as seen by `CryptSelectSignScheme()`.
enum KeySignScheme {
    /// The key has no default scheme (`TPM_ALG_NULL`).
    Null,
    /// The key's default scheme is a signing scheme.
    Sign(TpmtSigScheme),
    /// The key's default scheme is not a signing scheme (e.g. OAEP, ECDH, XOR), so no signing
    /// scheme can ever be compatible with it.
    NonSign,
}

/// Returns `true` if `hash_alg` is a hash algorithm implemented by this TPM for signing
/// (`CryptHashIsValidAlg(hashAlg, FALSE)`).
fn is_implemented_sign_hash(hash_alg: TpmiAlgHash) -> bool {
    crate::handler::capability::is_implemented_algorithm(tpm2::Alg::from(hash_alg))
}

impl<'b, P: Platform> CommandHandler<'b, P> {
    /// Handles the [TpmCc::GetTime] (`0x14C`) command.
    ///
    /// # Description
    /// This command returns the current value of the TPM clock and time, signed by a signing key loaded in the TPM.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 18.6 (TPM2_GetTime).
    ///
    /// # Relationships
    /// - The `sign_handle` must reference a loaded (transient or persistent) signing key, or be
    ///   `TPM_RH_NULL`.
    /// - Requires authorization from the privacy administrator: `privacy_admin_handle` is a
    ///   `TPMI_RH_ENDORSEMENT` and therefore must be `TPM_RH_ENDORSEMENT`.
    pub fn get_time(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<GetTime>()?;
        let [privacy_admin_handle, sign_handle] = handles;
        check(
            privacy_admin_handle,
            Tpmi::RhEndorsement,
            Position::handle(1),
        )?;
        check(sign_handle, Tpmi::DhObjectOrNull, Position::handle(2))?;

        // TPMI_RH_ENDORSEMENT (no `+`): only TPM_RH_ENDORSEMENT is a valid value.
        if privacy_admin_handle.0 != Handle::RH_ENDORSEMENT.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<GetTime>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Resolve the signing key (transient or persistent; TPMI_DH_OBJECT+).
        let signer_obj_opt = if sign_handle.0 == Handle::RH_NULL.0 {
            None
        } else {
            Some(self.resolve_object(sign_handle.0, Position::handle(2))?)
        };

        // 2. Both the privacy administrator and a non-NULL signing key need an authorization.
        let expected_sessions = if signer_obj_opt.is_some() { 2 } else { 1 };
        if num_sessions < expected_sessions {
            return Err(TpmRc::AUTH_MISSING);
        }

        // 3. IsSigningObject() / CryptSelectSignScheme().
        let actual_in_scheme = self.resolve_attest_scheme(
            signer_obj_opt.as_ref().map(|s| &s.public),
            cmd.in_scheme,
            Position::handle(2),
            Position::parameter(2),
        )?;

        // 4. Build the attestation structure. The attested time info carries the plain clock and
        //    firmware version; only the header copies are obfuscated.
        let header = self.compute_attest_fields(
            signer_obj_opt.as_ref(),
            &actual_in_scheme,
            &cmd.qualifying_data,
        )?;
        let time_attest_info = TpmsTimeAttestInfo {
            time: self.get_time_info(),
            firmware_version: self.context.platform.info().attest_firmware_version(),
        };

        let attest = TpmsAttest {
            magic: TpmGenerated,
            qualified_signer: header.qualified_signer,
            extra_data: header.extra_data,
            clock_info: header.clock_info,
            firmware_version: header.firmware_version,
            attested: TpmuAttest::Time(time_attest_info),
        };

        let mut attest_buf = [0u8; TpmsAttest::MAX_SIZE];
        let attest_len = attest.marshal(&mut attest_buf);

        // 5. Sign the attestation payload.
        let owned_sig = self.sign_attestation_block(
            signer_obj_opt.as_ref(),
            actual_in_scheme,
            &attest_buf[..attest_len],
            cmd.qualifying_data.get_buffer(),
        )?;

        let rsp = responses::GetTime {
            time_info: tpm2::Tpm2b(attest),
            signature: owned_sig.as_ref().map(|s| s.as_tpmt()),
        };

        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Validates the signing key and selects the signing scheme for an attestation command,
    /// mirroring `IsSigningObject()` (`Attest_spt.c`) followed by `CryptSelectSignScheme()`
    /// (`CryptUtil.c`).
    ///
    /// - `signer_public` is `None` when `signHandle` is `TPM_RH_NULL`: the NULL scheme is then
    ///   selected regardless of `in_scheme` and `Ok(None)` is returned.
    /// - A key without `sign` set, or a `TPM_ALG_SYMCIPHER` key, fails with
    ///   `TPM_RC_KEY + sign_pos`.
    /// - If both `in_scheme` and the key's default scheme are NULL, if `in_scheme` is NULL while the
    ///   key's default is a split-signing scheme (ECDAA), if both are set but differ in scheme or
    ///   hash, or if the selected scheme is not valid for the key type (RSA: RSASSA/RSAPSS,
    ///   ECC: ECDSA/ECDAA, KEYEDHASH: HMAC) or uses an unimplemented hash, the command fails with
    ///   `TPM_RC_SCHEME + scheme_pos`.
    pub(crate) fn resolve_attest_scheme(
        &self,
        signer_public: Option<&OwnedPublic>,
        in_scheme: Option<TpmtSigScheme>,
        sign_pos: Position,
        scheme_pos: Position,
    ) -> Result<Option<TpmtSigScheme>, TpmRc> {
        let Some(public_area) = signer_public else {
            return Ok(None);
        };

        // IsSigningObject()
        if !public_area
            .object_attributes
            .contains(TpmaObject::SIGN_ENCRYPT)
            || matches!(public_area.parms_and_id, OwnedPublicParmsAndId::Sym(..))
        {
            return Err(TpmRc::KEY.with(sign_pos));
        }

        let scheme_err = TpmRc::SCHEME.with(scheme_pos);
        // An ML-DSA or HashML-DSA key has no scheme selector: its parameter set (and the
        // HashML-DSA key's hash) determine how it signs (the version 185 reference's
        // `SelectAttestSignScheme()`: "The caller may name the key's scheme but may not choose
        // a different one").
        let immutable = match &public_area.parms_and_id {
            OwnedPublicParmsAndId::Mldsa(..) => Some(TpmtSigScheme::Mldsa),
            OwnedPublicParmsAndId::HashMldsa(..) => Some(TpmtSigScheme::HashMldsa),
            _ => None,
        };
        if let Some(key_scheme) = immutable {
            return match in_scheme {
                Some(input) if input.algorithm() != key_scheme.algorithm() => Err(scheme_err),
                _ => Ok(Some(key_scheme)),
            };
        }
        let key_scheme = match &public_area.parms_and_id {
            OwnedPublicParmsAndId::Rsa(parms, _) => match parms.scheme {
                None => KeySignScheme::Null,
                Some(TpmtRsaScheme::Rsassa(h)) => KeySignScheme::Sign(TpmtSigScheme::Rsassa(h)),
                Some(TpmtRsaScheme::Rsapss(h)) => KeySignScheme::Sign(TpmtSigScheme::Rsapss(h)),
                Some(_) => KeySignScheme::NonSign,
            },
            OwnedPublicParmsAndId::Ecc(parms, _) => match parms.scheme {
                None => KeySignScheme::Null,
                Some(TpmtEccScheme::Ecdsa(h)) => KeySignScheme::Sign(TpmtSigScheme::Ecdsa(h)),
                Some(TpmtEccScheme::Ecdaa(s)) => KeySignScheme::Sign(TpmtSigScheme::Ecdaa(s)),
                #[cfg(feature = "sm2")]
                Some(TpmtEccScheme::Sm2(h)) => KeySignScheme::Sign(TpmtSigScheme::Sm2(h)),
                #[cfg(feature = "ecschnorr")]
                Some(TpmtEccScheme::Ecschnorr(h)) => {
                    KeySignScheme::Sign(TpmtSigScheme::Ecschnorr(h))
                }
                Some(_) => KeySignScheme::NonSign,
            },
            OwnedPublicParmsAndId::KeyedHash(scheme, _) => match scheme {
                None => KeySignScheme::Null,
                Some(TpmtKeyedHashScheme::Hmac(h)) => KeySignScheme::Sign(TpmtSigScheme::Hmac(*h)),
                Some(_) => KeySignScheme::NonSign,
            },
            // Only asymmetric keys and keyed hashes can sign.
            _ => return Err(scheme_err),
        };

        let selected = match (key_scheme, in_scheme) {
            // Input and default can't both be NULL.
            (KeySignScheme::Null, None) => return Err(scheme_err),
            (KeySignScheme::Null, Some(input)) => input,
            // A non-signing default can neither be copied nor match a signing input scheme.
            (KeySignScheme::NonSign, _) => return Err(scheme_err),
            // A split-signing default requires caller-provided scheme data (the commit count).
            (KeySignScheme::Sign(TpmtSigScheme::Ecdaa(_)), None) => return Err(scheme_err),
            (KeySignScheme::Sign(default), None) => default,
            (KeySignScheme::Sign(default), Some(input)) => {
                if default.algorithm() != input.algorithm()
                    || default.hash_alg() != input.hash_alg()
                {
                    return Err(scheme_err);
                }
                // Keep the input scheme: it may carry split-signing data (ECDAA count).
                input
            }
        };

        // CryptIsValidSignScheme(): scheme compatible with the key type, valid hash algorithm.
        let valid_for_type = match (&public_area.parms_and_id, selected) {
            (
                OwnedPublicParmsAndId::Rsa(..),
                TpmtSigScheme::Rsassa(_) | TpmtSigScheme::Rsapss(_),
            )
            | (OwnedPublicParmsAndId::Ecc(..), TpmtSigScheme::Ecdsa(_) | TpmtSigScheme::Ecdaa(_))
            | (OwnedPublicParmsAndId::KeyedHash(..), TpmtSigScheme::Hmac(_)) => true,
            #[cfg(feature = "sm2")]
            (OwnedPublicParmsAndId::Ecc(..), TpmtSigScheme::Sm2(_)) => true,
            #[cfg(feature = "ecschnorr")]
            (OwnedPublicParmsAndId::Ecc(..), TpmtSigScheme::Ecschnorr(_)) => true,
            _ => false,
        };
        let valid_hash = selected.hash_alg().is_some_and(is_implemented_sign_hash);
        if !valid_for_type || !valid_hash {
            return Err(scheme_err);
        }

        Ok(Some(selected))
    }

    /// Signs a marshaled attestation structure, mirroring `SignAttestInfo()` (`Attest_spt.c`).
    ///
    /// - When `signer` is `None` (`signHandle == TPM_RH_NULL`), no signature is produced and
    ///   `Ok(None)` is returned (the response carries a `TPM_ALG_NULL` signature).
    /// - Otherwise the digest `H(attest_bytes)` is signed with `scheme` (RSASSA, RSAPSS, ECDSA,
    ///   ECDAA, SM2, EC-Schnorr, HMAC or HashML-DSA), or for ML-DSA the attestation block itself.
    ///   Errors from the signing operation are returned without a position, as in
    ///   the reference implementation.
    /// - Because a signed attestation reveals the current clock, a successful signature clears
    ///   the NV orderly state (`NvClearOrderly()`), which fails with `TPM_RC_NV_UNAVAILABLE` when
    ///   the TPM is orderly and NV is unavailable.
    pub(crate) fn sign_attestation_block(
        &mut self,
        signer: Option<&TransientObject>,
        scheme: Option<TpmtSigScheme>,
        attest_bytes: &[u8],
        qualifying_data: &[u8],
    ) -> Result<Option<OwnedSignature>, TpmRc> {
        let Some(signer) = signer else {
            return Ok(None);
        };
        let scheme = scheme.ok_or_else(|| TpmRc::SCHEME.to_rc())?;
        let priv_key = &signer.private[..signer.private_len];

        let signature = if let TpmtSigScheme::Mldsa = scheme {
            self.sign_attestation_mldsa(signer, attest_bytes)?
        } else if let TpmtSigScheme::HashMldsa = scheme {
            self.sign_attestation_hash_mldsa(signer, attest_bytes)?
        } else if let TpmtSigScheme::Ecdaa(ecdaa_s) = scheme {
            let hash_alg = ecdaa_s.hash_alg;
            let curve = match &signer.public.parms_and_id {
                OwnedPublicParmsAndId::Ecc(parms, _) => parms.curve_id,
                _ => return Err(TpmRc::KEY.to_rc()),
            };
            let param_size = match crate::ecc_curves::param_size(curve) {
                Some(size) => size,
                None => return Err(TpmRc::VALUE.to_rc()),
            };
            // CryptGenerateR(): the count must reference an outstanding commitment
            // (bare TPM_RC_VALUE otherwise, as returned by TpmEcc_SignEcdaa()).
            let (commit_r, r_len) =
                self.generate_committed_r(ecdaa_s.count, signer.name.get_buffer(), curve)?;
            // For the anonymous scheme FillInAttestInfo() keeps qualifyingData out of the
            // attestation, so SignAttestInfo() signs H(qualifyingData || H(attest)) when
            // qualifyingData is non-empty, and H(attest) otherwise.
            let (mut digest_buf, mut digest_len) = self.compute_hash(hash_alg, &[attest_bytes])?;
            if !qualifying_data.is_empty() {
                (digest_buf, digest_len) =
                    self.compute_hash(hash_alg, &[qualifying_data, &digest_buf[..digest_len]])?;
            }
            let mut sig_r = [0u8; 128];
            let mut sig_s = [0u8; 128];
            let (k_len, s_len) = self.ecdaa_sign(
                curve,
                hash_alg,
                &commit_r[..r_len],
                priv_key,
                &digest_buf[..digest_len],
                &mut sig_r[..param_size],
                &mut sig_s[..param_size],
            )?;
            let signature = OwnedSignature::Ecdaa {
                hash: hash_alg,
                signature_r: OwnedEccParameter::from_bytes(&sig_r[..k_len])
                    .map_err(|_| TpmRc::FAILURE)?,
                signature_s: OwnedEccParameter::from_bytes(&sig_s[..s_len])
                    .map_err(|_| TpmRc::FAILURE)?,
            };
            // CryptEndCommit(): a commitment can only be used for one signature (reusing `r`
            // for two different digests reveals the private key).
            self.end_commit(ecdaa_s.count);
            signature
        } else if let TpmtSigScheme::Hmac(hash_alg) = scheme {
            // CryptHmacSign(): an HMAC (keyed with the sensitive bits) over the digest.
            if !is_implemented_sign_hash(hash_alg) {
                return Err(TpmRc::HASH.to_rc());
            }
            let (digest_buf, digest_len) = self.compute_hash(hash_alg, &[attest_bytes])?;
            let (hmac, _) = self.compute_hmac(hash_alg, priv_key, &[&digest_buf[..digest_len]])?;
            OwnedSignature::Hmac {
                hash: hash_alg,
                digest: hmac,
            }
        } else {
            let (hash_alg, sig_alg) = match scheme {
                TpmtSigScheme::Rsassa(h) => (h, Alg::RSASSA),
                TpmtSigScheme::Rsapss(h) => (h, Alg::RSAPSS),
                TpmtSigScheme::Ecdsa(h) => (h, Alg::ECDSA),
                #[cfg(feature = "sm2")]
                TpmtSigScheme::Sm2(h) => (h, Alg::SM2),
                #[cfg(feature = "ecschnorr")]
                TpmtSigScheme::Ecschnorr(h) => (h, Alg::ECSCHNORR),
                _ => return Err(TpmRc::SCHEME.to_rc()),
            };

            if !is_implemented_sign_hash(hash_alg) {
                return Err(TpmRc::HASH.to_rc());
            }

            let (digest_buf, digest_len) = self.compute_hash(hash_alg, &[attest_bytes])?;
            let digest_ha =
                tpm2::TpmtHa::new(hash_alg, &digest_buf[..digest_len]).ok_or(TpmRc::FAILURE)?;

            let mut sig_bytes = [0u8; 512];
            // Exp mapped every signing failure to `TPM_RC_FAILURE`; a key that cannot sign the
            // digest is now reported as `Ok(None)`.
            let sig_len = match self.sign_asymmetric(
                sig_alg,
                &signer.public.parms_and_id,
                priv_key,
                digest_ha,
                &mut sig_bytes,
            ) {
                Ok(Some(sig_len)) => sig_len,
                Ok(None) | Err(_) => return Err(TpmRc::FAILURE),
            };

            match scheme {
                TpmtSigScheme::Rsassa(_) => {
                    let sig_buf = OwnedPublicKeyRsa::from_bytes(&sig_bytes[..sig_len])
                        .map_err(|_| TpmRc::FAILURE)?;
                    OwnedSignature::Rsassa {
                        hash: hash_alg,
                        sig: sig_buf,
                    }
                }
                TpmtSigScheme::Rsapss(_) => {
                    let sig_buf = OwnedPublicKeyRsa::from_bytes(&sig_bytes[..sig_len])
                        .map_err(|_| TpmRc::FAILURE)?;
                    OwnedSignature::Rsapss {
                        hash: hash_alg,
                        sig: sig_buf,
                    }
                }
                TpmtSigScheme::Ecdsa(_) => {
                    let (signature_r, signature_s) = owned_ecc_signature(&sig_bytes[..sig_len])?;
                    OwnedSignature::Ecdsa {
                        hash: hash_alg,
                        signature_r,
                        signature_s,
                    }
                }
                #[cfg(feature = "sm2")]
                TpmtSigScheme::Sm2(_) => {
                    let (signature_r, signature_s) = owned_ecc_signature(&sig_bytes[..sig_len])?;
                    OwnedSignature::Sm2 {
                        hash: hash_alg,
                        signature_r,
                        signature_s,
                    }
                }
                #[cfg(feature = "ecschnorr")]
                TpmtSigScheme::Ecschnorr(_) => {
                    let (signature_r, signature_s) = owned_ecc_signature(&sig_bytes[..sig_len])?;
                    OwnedSignature::Ecschnorr {
                        hash: hash_alg,
                        signature_r,
                        signature_s,
                    }
                }
                _ => return Err(TpmRc::SCHEME.to_rc()),
            }
        };

        // The attestation exposes the current clock, so NV is no longer orderly with respect to
        // the RAM state.
        self.nv_clear_orderly()?;

        Ok(Some(signature))
    }

    /// The ML-DSA signature of an attestation block: pure ML-DSA signs the message rather than
    /// a digest of it, with an empty context (an attestation has no caller-supplied context;
    /// the version 185 reference's `SignAttestMessageMldsa()`).
    #[cfg(feature = "mldsa")]
    fn sign_attestation_mldsa(
        &mut self,
        signer: &TransientObject,
        attest_bytes: &[u8],
    ) -> Result<OwnedSignature, TpmRc> {
        let mut signature = [0u8; tpm2::TPM2_MAX_MLDSA_SIG_SIZE];
        let len = self.mldsa_sign_message(signer, &[attest_bytes], &mut signature)?;
        Ok(OwnedSignature::Mldsa(
            crate::owned::OwnedSignatureMldsa::from_bytes(&signature[..len])
                .map_err(|_| TpmRc::FAILURE)?,
        ))
    }

    #[cfg(not(feature = "mldsa"))]
    fn sign_attestation_mldsa(
        &mut self,
        _signer: &TransientObject,
        _attest_bytes: &[u8],
    ) -> Result<OwnedSignature, TpmRc> {
        Err(TpmRc::SCHEME.to_rc())
    }

    /// The HashML-DSA signature of an attestation block: the digest of the block with the key's
    /// pre-hash algorithm, signed with an empty context (FIPS 204, Algorithm 4).
    #[cfg(feature = "mldsa")]
    fn sign_attestation_hash_mldsa(
        &mut self,
        signer: &TransientObject,
        attest_bytes: &[u8],
    ) -> Result<OwnedSignature, TpmRc> {
        let OwnedPublicParmsAndId::HashMldsa(parms, public_key) = &signer.public.parms_and_id
        else {
            return Err(TpmRc::SCHEME.to_rc());
        };
        let hash_alg = parms.hash_alg;
        let (digest, digest_len) = self.compute_hash(hash_alg, &[attest_bytes])?;
        let mu = crate::mldsa::hash_mu(
            public_key.get_buffer(),
            &[],
            hash_alg,
            &digest[..digest_len],
        )
        .ok_or(TpmRc::SCHEME.to_rc())?;
        let mut signature = [0u8; tpm2::TPM2_MAX_MLDSA_SIG_SIZE];
        let len = self.mldsa_sign_mu(signer, &mu, &mut signature)?;
        Ok(OwnedSignature::HashMldsa {
            hash: hash_alg,
            sig: crate::owned::OwnedSignatureMldsa::from_bytes(&signature[..len])
                .map_err(|_| TpmRc::FAILURE)?,
        })
    }

    #[cfg(not(feature = "mldsa"))]
    fn sign_attestation_hash_mldsa(
        &mut self,
        _signer: &TransientObject,
        _attest_bytes: &[u8],
    ) -> Result<OwnedSignature, TpmRc> {
        Err(TpmRc::SCHEME.to_rc())
    }
}

/// The components `r` and `s` of the ECC signature `rs` (`r || s`, two halves of the order size).
fn owned_ecc_signature(rs: &[u8]) -> Result<(OwnedEccParameter, OwnedEccParameter), TpmRc> {
    if !rs.len().is_multiple_of(2) {
        return Err(TpmRc::FAILURE);
    }
    let (r, s) = rs.split_at(rs.len() / 2);
    Ok((
        OwnedEccParameter::from_bytes(r).map_err(|_| TpmRc::FAILURE)?,
        OwnedEccParameter::from_bytes(s).map_err(|_| TpmRc::FAILURE)?,
    ))
}
