use super::crypt_ops::{ecc_param_size, left_pad, load_ecc_private, load_rsa_private};
use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{
    handler::{CommandHandler, TransientObject},
    owned::{
        OwnedEccParameter, OwnedPublic, OwnedPublicKeyRsa, OwnedPublicParmsAndId, OwnedSignature,
    },
    req_resp::RequestThenResponse,
};
use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{GetTime, responses};
use tpm2::crypto::{self, SignatureBuffer, SigningKey};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmGenerated};
use tpm2::{
    TpmEccCurve, TpmaObject, TpmiAlgHash, TpmiRsaKeyBits, TpmsAttest, TpmsTimeAttestInfo,
    TpmtEccScheme, TpmtRsaScheme, TpmtSigScheme, TpmtSignature, TpmuAttest,
};

/// Left-pads an ECC signature component to `size` bytes.
///
/// PORTING: exp's crypto provider always produced fixed-size `r` / `s` values.
fn padded_ecc_parameter(src: &[u8], size: usize) -> Option<OwnedEccParameter> {
    let mut buf = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    left_pad(&mut buf, src, size)?;
    OwnedEccParameter::new(buf.get(..size)?)
}

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::GetTime] (`0x14C`) command.
    ///
    /// # Description
    /// This command returns the current value of the TPM clock and time, signed by a signing key loaded in the TPM.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 18.6 (TPM2_GetTime).
    ///
    /// # Relationships
    /// - The `sign_handle` must reference a loaded signing key (created by [TpmCc::Create](create.rs)
    ///   or [TpmCc::CreatePrimary](create_primary.rs) and loaded).
    /// - Requires authorization from the privacy administrator (Endorsement hierarchy) specified by
    ///   `privacy_admin_handle`.
    ///
    /// PORTING: exp also accepted the Owner hierarchy (and `TPM_RH_NULL`) as
    /// `privacy_admin_handle`; it is now range-checked as `TPMI_RH_ENDORSEMENT`.
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

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<GetTime>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Validate Admin and Signer authorization
        let creds =
            self.validate_get_time_sessions(sign_handle, privacy_admin_handle, num_sessions)?;
        let signer = creds.signer;
        let public_opt = signer.as_ref().map(|s| &s.public);

        // 2. Read timer and build attest structure
        let time_info = self.get_time_info();
        let clock_info = time_info.clock_info;

        let time_attest_info = TpmsTimeAttestInfo {
            time: time_info,
            firmware_version: 0x00010001,
        };

        let actual_in_scheme =
            self.resolve_attest_scheme(sign_handle, public_opt, cmd.in_scheme)?;
        let (qualified_signer, extra_data) =
            self.compute_attest_fields(signer.as_ref(), &actual_in_scheme, &cmd.qualifying_data)?;

        let attest = TpmsAttest {
            magic: TpmGenerated,
            qualified_signer,
            extra_data,
            clock_info,
            firmware_version: 0x00010001,
            attested: TpmuAttest::Time(time_attest_info),
        };

        let mut attest_buf = [0u8; TpmsAttest::MAX_SIZE];
        let attest_len = attest.marshal(&mut attest_buf);
        let attest_bytes = attest_buf.get(..attest_len).ok_or(TpmRc::FAILURE)?;

        // 4. Sign the attestation payload
        let owned_sig = self.sign_attestation_block(
            sign_handle,
            signer.as_ref(),
            actual_in_scheme,
            attest_bytes,
            cmd.qualifying_data.as_slice(),
        )?;

        let rsp = responses::GetTime {
            time_info: tpm2::Tpm2b(attest),
            signature: owned_sig.as_ref().map(|s| s.as_tpmt()),
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Validates the privacy_admin and sign handles/sessions and returns the resolved
    /// objects credentials.
    ///
    /// PORTING: exp also accepted `TPM_RH_OWNER` and `TPM_RH_NULL` as `privacy_admin_handle`
    /// here (`TPM_RC_VALUE` otherwise); it is now range-checked as `TPMI_RH_ENDORSEMENT`
    /// (handle 1) before session validation. exp's unused `auths` parameter and its no-op
    /// lookups of the expected authorization values are dropped.
    fn validate_get_time_sessions(
        &self,
        sign_handle: Handle,
        privacy_admin_handle: Handle,
        num_sessions: usize,
    ) -> Result<SignerCredentials, TpmRc> {
        let signer = if sign_handle != Handle::RH_NULL {
            let obj = self
                .global_state
                .find_transient_object(sign_handle.0)
                .ok_or(TpmRc::VALUE.to_rc())?;
            Some(obj.clone())
        } else {
            None
        };

        let privacy_admin_auth_required = privacy_admin_handle != Handle::RH_NULL;
        let sign_auth_required = sign_handle != Handle::RH_NULL;

        let mut expected_sessions = 0;
        if privacy_admin_auth_required {
            expected_sessions += 1;
        }
        if sign_auth_required {
            expected_sessions += 1;
        }

        if num_sessions < expected_sessions {
            return Err(TpmRc::AUTH_MISSING);
        }

        Ok(SignerCredentials { signer })
    }

    /// Resolves the signature scheme to use for attestation (either using key-defined scheme
    /// or mapping the input scheme, and checking cryptographic requirements).
    ///
    /// `public_opt` is the public area of the key referenced by `sign_handle` (`None` iff
    /// `sign_handle` is `TPM_RH_NULL`).
    pub(crate) fn resolve_attest_scheme(
        &self,
        sign_handle: Handle,
        public_opt: Option<&OwnedPublic>,
        in_scheme: Option<TpmtSigScheme>,
    ) -> Result<Option<TpmtSigScheme>, TpmRc> {
        if sign_handle == Handle::RH_NULL {
            if in_scheme.is_some() {
                return Err(TpmRc::SCHEME.to_rc());
            }
            return Ok(None);
        }

        // PORTING: exp `expect`ed `public_opt` to be populated for a non-null `sign_handle`.
        let public_area = public_opt.ok_or(TpmRc::FAILURE)?;
        if !public_area
            .object_attributes
            .contains(TpmaObject::SIGN_ENCRYPT)
        {
            return Err(TpmRc::KEY.to_rc());
        }

        let actual_in_scheme = match &public_area.parms_and_id {
            OwnedPublicParmsAndId::Rsa(rsa_parms, _) => match in_scheme {
                None => match rsa_parms.scheme {
                    Some(TpmtRsaScheme::Rsassa(h)) => Some(TpmtSigScheme::Rsassa(h)),
                    Some(TpmtRsaScheme::Rsapss(h)) => Some(TpmtSigScheme::Rsapss(h)),
                    _ => return Err(TpmRc::SCHEME.to_rc()),
                },
                Some(in_s) => {
                    if let Some(key_scheme) = rsa_parms.scheme {
                        let scheme_match = match (in_s, key_scheme) {
                            (TpmtSigScheme::Rsassa(s1), TpmtRsaScheme::Rsassa(s2)) => s1 == s2,
                            (TpmtSigScheme::Rsapss(s1), TpmtRsaScheme::Rsapss(s2)) => s1 == s2,
                            _ => false,
                        };
                        if !scheme_match {
                            return Err(TpmRc::SCHEME.to_rc());
                        }
                    } else {
                        match in_s {
                            TpmtSigScheme::Rsassa(_) | TpmtSigScheme::Rsapss(_) => {}
                            _ => return Err(TpmRc::SCHEME.to_rc()),
                        }
                    }
                    Some(in_s)
                }
            },
            // TODO(pqc): EdDSA (`TPM_ALG_EDDSA` / `TPM_ALG_HASH_EDDSA`) schemes are rejected
            // with TPM_RC_SCHEME below, as in exp.
            OwnedPublicParmsAndId::Ecc(ecc_parms, _) => match in_scheme {
                None => match ecc_parms.scheme {
                    Some(TpmtEccScheme::Ecdsa(h)) => Some(TpmtSigScheme::Ecdsa(h)),
                    Some(TpmtEccScheme::Ecdaa(s)) => Some(TpmtSigScheme::Ecdaa(s)),
                    Some(TpmtEccScheme::Sm2(h)) => Some(TpmtSigScheme::Sm2(h)),
                    Some(TpmtEccScheme::Ecschnorr(h)) => Some(TpmtSigScheme::Ecschnorr(h)),
                    _ => return Err(TpmRc::SCHEME.to_rc()),
                },
                Some(in_s) => {
                    if let Some(key_scheme) = ecc_parms.scheme {
                        let scheme_match = match (in_s, key_scheme) {
                            (TpmtSigScheme::Ecdsa(s1), TpmtEccScheme::Ecdsa(s2)) => s1 == s2,
                            (TpmtSigScheme::Ecdaa(s1), TpmtEccScheme::Ecdaa(s2)) => {
                                s1.hash_alg == s2.hash_alg
                            }
                            (TpmtSigScheme::Sm2(s1), TpmtEccScheme::Sm2(s2)) => s1 == s2,
                            (TpmtSigScheme::Ecschnorr(s1), TpmtEccScheme::Ecschnorr(s2)) => {
                                s1 == s2
                            }
                            _ => false,
                        };
                        if !scheme_match {
                            return Err(TpmRc::SCHEME.to_rc());
                        }
                    } else {
                        match in_s {
                            TpmtSigScheme::Ecdsa(_)
                            | TpmtSigScheme::Ecdaa(_)
                            | TpmtSigScheme::Sm2(_)
                            | TpmtSigScheme::Ecschnorr(_) => {}
                            _ => return Err(TpmRc::SCHEME.to_rc()),
                        }
                    }
                    Some(in_s)
                }
            },
            // TODO(pqc): ML-DSA / HashML-DSA signing keys are rejected with TPM_RC_KEY, as in exp.
            _ => return Err(TpmRc::KEY.to_rc()),
        };

        Ok(actual_in_scheme)
    }

    /// Sign the attestation structure if a signer handle was provided, returning
    /// the serialized signature object.
    ///
    /// PORTING: exp took the signer's opaque private key blob (`actual_priv_key_opt`). This now
    /// takes the resolved signing object (`signer`, `None` for `TPM_RH_NULL`), loads its private
    /// key from its `sensitive` area and signs with `tpm2::crypto::sign`. It takes `&mut self`
    /// because signing draws from the TPM's global RNG.
    pub(crate) fn sign_attestation_block(
        &mut self,
        sign_handle: Handle,
        signer: Option<&TransientObject>,
        actual_in_scheme: Option<TpmtSigScheme>,
        attest_bytes: &[u8],
        qualifying_data: &[u8],
    ) -> Result<Option<OwnedSignature>, TpmRc> {
        let actual_in_scheme = match actual_in_scheme {
            None => {
                if sign_handle != Handle::RH_NULL {
                    return Err(TpmRc::SCHEME.to_rc());
                }
                return Ok(None);
            }
            Some(s) => s,
        };

        if sign_handle == Handle::RH_NULL {
            return Err(TpmRc::SCHEME.to_rc());
        }

        let mut sig_buf: SignatureBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        let signature = if let TpmtSigScheme::Ecdaa(ecdaa_s) = actual_in_scheme {
            let hash_alg = ecdaa_s.hash_alg;
            let obj = self
                .global_state
                .find_transient_object(sign_handle.0)
                .ok_or(TpmRc::HANDLE.to_rc())?;
            let (curve, point) = match &obj.public.parms_and_id {
                OwnedPublicParmsAndId::Ecc(parms, point) => (parms.curve_id, *point),
                _ => return Err(TpmRc::KEY.to_rc()),
            };
            let sensitive = obj.sensitive;
            let param_size = ecc_param_size(curve).ok_or(TpmRc::VALUE.to_rc())?;
            // PORTING: exp computed the commit random `r` (`compute_commit_r`) and passed it,
            // `commit_x`, `commit_p1` and `qualifyingData[..64] || H(attest)` to its
            // `ecdaa_sign`. The new `Signing::ecc_sign` only receives the commit `count`
            // (`EccSigScheme::Ecdaa`) and a `TPMT_HA` digest, so the ECDAA computation is left
            // to the backend (as in `TPM2_Sign`), and the digest is the reference
            // implementation's `H(qualifyingData || H(attest))` (`H(attest)` if
            // `qualifyingData` is empty; `SignAttestInfo` in `Attest_spt.c`).
            let (mut digest_buf, mut digest_len) = self.compute_hash(hash_alg, &[attest_bytes])?;
            if !qualifying_data.is_empty() {
                let attest_digest = digest_buf.get(..digest_len).ok_or(TpmRc::FAILURE)?;
                (digest_buf, digest_len) =
                    self.compute_hash(hash_alg, &[qualifying_data, attest_digest])?;
            }
            let digest = digest_buf.get(..digest_len).ok_or(TpmRc::FAILURE)?;
            let crypto = self.crypto();
            let key = load_ecc_private(crypto, curve, &point, &sensitive).ok_or(TpmRc::FAILURE)?;
            let signature = crypto::sign(
                crypto,
                &mut self.context.platform.rng,
                SigningKey::Ecc(&key),
                actual_in_scheme,
                digest,
                &mut sig_buf,
            )
            .map_err(|_| TpmRc::FAILURE)?;
            let TpmtSignature::Ecdaa(sig) = signature else {
                return Err(TpmRc::FAILURE);
            };
            OwnedSignature::Ecdaa {
                hash: hash_alg,
                signature_r: padded_ecc_parameter(sig.signature_r.as_slice(), param_size)
                    .ok_or(TpmRc::FAILURE)?,
                signature_s: padded_ecc_parameter(sig.signature_s.as_slice(), param_size)
                    .ok_or(TpmRc::FAILURE)?,
            }
        } else {
            let hash_alg = match actual_in_scheme {
                TpmtSigScheme::Rsassa(h) | TpmtSigScheme::Rsapss(h) | TpmtSigScheme::Ecdsa(h) => h,
                _ => return Err(TpmRc::SCHEME.to_rc()),
            };

            if !matches!(
                hash_alg,
                TpmiAlgHash::Sha1 | TpmiAlgHash::Sha256 | TpmiAlgHash::Sha384 | TpmiAlgHash::Sha512
            ) {
                return Err(TpmRc::HASH.to_rc());
            }

            let (digest_buf, digest_len) = self.compute_hash(hash_alg, &[attest_bytes])?;
            let digest = digest_buf.get(..digest_len).ok_or(TpmRc::FAILURE)?;

            // PORTING: exp's `sign_inner(sig_alg, private, TpmtHa)` is now `crypto::sign` with
            // the private key loaded from the signer's sensitive area. A missing signer, a key
            // that fails to load and a backend error are all reported like a failing
            // `sign_inner` (TPM_RC_FAILURE); `crypto::sign` also does exp's `TpmtHa::new` check.
            let signer = signer.ok_or(TpmRc::FAILURE)?;
            let crypto = self.crypto();
            let rng = &mut self.context.platform.rng;
            match &signer.public.parms_and_id {
                OwnedPublicParmsAndId::Rsa(parms, unique) => {
                    let key =
                        load_rsa_private(crypto, parms, unique.get_buffer(), &signer.sensitive)
                            .ok_or(TpmRc::FAILURE)?;
                    let signature = crypto::sign(
                        crypto,
                        rng,
                        SigningKey::Rsa(&key),
                        actual_in_scheme,
                        digest,
                        &mut sig_buf,
                    )
                    .map_err(|_| TpmRc::FAILURE)?;
                    match signature {
                        TpmtSignature::Rsassa(sig) => OwnedSignature::Rsassa {
                            hash: hash_alg,
                            sig: OwnedPublicKeyRsa::new(sig.sig.as_slice())
                                .ok_or(TpmRc::FAILURE)?,
                        },
                        TpmtSignature::Rsapss(sig) => OwnedSignature::Rsapss {
                            hash: hash_alg,
                            sig: OwnedPublicKeyRsa::new(sig.sig.as_slice())
                                .ok_or(TpmRc::FAILURE)?,
                        },
                        _ => return Err(TpmRc::SCHEME.to_rc()),
                    }
                }
                OwnedPublicParmsAndId::Ecc(parms, point) => {
                    let curve = parms.curve_id;
                    let key = load_ecc_private(crypto, curve, point, &signer.sensitive)
                        .ok_or(TpmRc::FAILURE)?;
                    let param_size = ecc_param_size(curve).ok_or(TpmRc::FAILURE)?;
                    let signature = crypto::sign(
                        crypto,
                        rng,
                        SigningKey::Ecc(&key),
                        actual_in_scheme,
                        digest,
                        &mut sig_buf,
                    )
                    .map_err(|_| TpmRc::FAILURE)?;
                    match signature {
                        TpmtSignature::Ecdsa(sig) => OwnedSignature::Ecdsa {
                            hash: hash_alg,
                            signature_r: padded_ecc_parameter(
                                sig.signature_r.as_slice(),
                                param_size,
                            )
                            .ok_or(TpmRc::FAILURE)?,
                            signature_s: padded_ecc_parameter(
                                sig.signature_s.as_slice(),
                                param_size,
                            )
                            .ok_or(TpmRc::FAILURE)?,
                        },
                        _ => return Err(TpmRc::SCHEME.to_rc()),
                    }
                }
                _ => return Err(TpmRc::FAILURE),
            }
        };
        Ok(Some(signature))
    }
}

/// The signing key resolved by `validate_get_time_sessions`.
///
/// PORTING: exp copied the signer's auth value, public area, private key blob and qualified
/// name into separate fields; the resolved object is now kept whole.
struct SignerCredentials {
    signer: Option<TransientObject>,
}
