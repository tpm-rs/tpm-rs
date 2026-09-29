use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{
    handler::CommandHandler,
    owned::{
        OwnedAuth, OwnedAuthCommand, OwnedEccParameter, OwnedName, OwnedPublic, OwnedPublicKeyRsa,
        OwnedPublicParmsAndId, OwnedSignature,
    },
    req_resp::RequestThenResponse,
};
use tpm2::Alg;
use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::commands::{GetTime, GetTimeHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::TpmRc;
use tpm2::{Handle, TpmGenerated};
use tpm2::{
    TpmEccCurve, TpmaObject, TpmiAlgHash, TpmsAttest, TpmsTimeAttestInfo, TpmtEccScheme,
    TpmtRsaScheme, TpmtSigScheme, TpmuAttest,
};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
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
    /// - Requires authorization from the Endorsement or Owner hierarchy admin specified by `privacy_admin_handle`.
    pub fn get_time(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<GetTimeHandles>()?;
        let sign_handle = handles.sign_handle;
        let privacy_admin_handle = handles.privacy_admin_handle;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let auths = &self.global_state.parsed_auths[..self.global_state.parsed_auths_len];

        let cmd = request.try_unmarshal::<GetTime>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Validate Admin and Signer authorization
        let creds = self.validate_get_time_sessions(
            sign_handle,
            privacy_admin_handle,
            auths,
            num_sessions,
        )?;
        let public_opt = creds.signer_public;
        let actual_priv_key_opt = creds.signer_private;
        let _qualified_signer = creds.signer_qualified_name;

        // 2. Read timer and build attest structure
        let time_info = self.get_time_info();
        let clock_info = time_info.clock_info;

        let time_attest_info = TpmsTimeAttestInfo {
            time: time_info,
            firmware_version: 0x00010001,
        };

        let actual_in_scheme =
            self.resolve_attest_scheme(sign_handle, public_opt.as_ref(), cmd.in_scheme)?;
        let signer_obj_opt = if sign_handle.0 != 0x40000007 {
            self.global_state.find_transient_object(sign_handle.0)
        } else {
            None
        };
        let (qualified_signer, extra_data) =
            self.compute_attest_fields(signer_obj_opt, &actual_in_scheme, &cmd.qualifying_data)?;

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

        // 4. Sign the attestation payload
        let owned_sig = self.sign_attestation_block(
            sign_handle,
            actual_priv_key_opt.as_ref(),
            actual_in_scheme,
            &attest_buf[..attest_len],
            cmd.qualifying_data.get_buffer(),
        )?;

        let rsp = responses::GetTime {
            time_info: tpm2::Tpm2b(attest),
            signature: owned_sig.as_ref().map(|s| s.as_tpmt()),
        };

        let response = request.into_response();
        self.write_response_all(response, &(), &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Validates the privacy_admin and sign handles/sessions and returns the resolved
    /// objects credentials.
    fn validate_get_time_sessions(
        &self,
        sign_handle: Handle,
        privacy_admin_handle: Handle,
        _auths: &[OwnedAuthCommand],
        num_sessions: usize,
    ) -> Result<SignerCredentials, TpmRc> {
        if privacy_admin_handle.0 != Handle::RH_ENDORSEMENT.0
            && privacy_admin_handle.0 != Handle::RH_OWNER.0
            && privacy_admin_handle.0 != Handle::RH_NULL.0
        {
            return Err(TpmRc::VALUE.to_rc());
        }

        let mut priv_opt = None;
        let mut actual_priv_key_opt = None;
        let mut public_opt = None;
        let mut qualified_signer = OwnedName::default();

        if sign_handle.0 != 0x40000007 {
            let obj = self
                .global_state
                .find_transient_object(sign_handle.0)
                .ok_or(TpmRc::VALUE.to_rc())?;
            qualified_signer = obj.qualified_name;
            priv_opt = Some(obj.auth);
            public_opt = Some(obj.public);
            actual_priv_key_opt = Some((obj.private, obj.private_len));
        }

        let privacy_admin_auth_required = privacy_admin_handle.0 != Handle::RH_NULL.0;
        let sign_auth_required = sign_handle.0 != 0x40000007;

        let mut expected_sessions = 0;
        let privacy_admin_session_idx = if privacy_admin_auth_required {
            let idx = expected_sessions;
            expected_sessions += 1;
            Some(idx)
        } else {
            None
        };
        let sign_session_idx = if sign_auth_required {
            let idx = expected_sessions;
            expected_sessions += 1;
            Some(idx)
        } else {
            None
        };

        if num_sessions < expected_sessions {
            return Err(TpmRc::AUTH_MISSING);
        }

        if let Some(_idx) = privacy_admin_session_idx {
            let _expected_auth = if privacy_admin_handle.0 == Handle::RH_OWNER.0 {
                self.global_state.owner_auth.get_buffer()
            } else if privacy_admin_handle.0 == Handle::RH_ENDORSEMENT.0 {
                self.global_state.endorsement_auth.get_buffer()
            } else {
                &[]
            };
        }

        if let Some(_idx) = sign_session_idx {
            let _expected_auth = priv_opt.expect("sign_handle is not null, so auth is populated");
        }

        Ok(SignerCredentials {
            privacy_admin_auth: priv_opt,
            signer_public: public_opt,
            signer_private: actual_priv_key_opt,
            signer_qualified_name: qualified_signer,
        })
    }

    /// Resolves the signature scheme to use for attestation (either using key-defined scheme
    /// or mapping the input scheme, and checking cryptographic requirements).
    pub(crate) fn resolve_attest_scheme(
        &self,
        sign_handle: Handle,
        public_opt: Option<&OwnedPublic>,
        in_scheme: Option<TpmtSigScheme>,
    ) -> Result<Option<TpmtSigScheme>, TpmRc> {
        if sign_handle.0 == 0x40000007 {
            if in_scheme.is_some() {
                return Err(TpmRc::SCHEME.to_rc());
            }
            return Ok(None);
        }

        let public_area = public_opt.expect("sign_handle is not null, so public_area is populated");
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
            _ => return Err(TpmRc::KEY.to_rc()),
        };

        Ok(actual_in_scheme)
    }

    /// Sign the attestation structure if a signer handle was provided, returning
    /// the serialized signature object.
    pub(crate) fn sign_attestation_block(
        &self,
        sign_handle: Handle,
        actual_priv_key_opt: Option<&([u8; 1536], usize)>,
        actual_in_scheme: Option<TpmtSigScheme>,
        attest_bytes: &[u8],
        qualifying_data: &[u8],
    ) -> Result<Option<OwnedSignature>, TpmRc> {
        let actual_in_scheme = match actual_in_scheme {
            None => {
                if sign_handle.0 != 0x40000007 {
                    return Err(TpmRc::SCHEME.to_rc());
                }
                return Ok(None);
            }
            Some(s) => s,
        };

        if sign_handle.0 == 0x40000007 {
            return Err(TpmRc::SCHEME.to_rc());
        }

        let signature = if let TpmtSigScheme::Ecdaa(ecdaa_s) = actual_in_scheme {
            let hash_alg = ecdaa_s.hash_alg;
            let obj = self
                .global_state
                .find_transient_object(sign_handle.0)
                .ok_or(TpmRc::HANDLE.to_rc())?;
            let curve = match &obj.public.parms_and_id {
                OwnedPublicParmsAndId::Ecc(parms, _) => parms.curve_id,
                _ => return Err(TpmRc::KEY.to_rc()),
            };
            let param_size = match curve {
                TpmEccCurve::NistP224 => 28,
                TpmEccCurve::NistP256 | TpmEccCurve::BNP256 => 32,
                TpmEccCurve::NistP384 => 48,
                TpmEccCurve::NistP521 => 66,
                _ => return Err(TpmRc::VALUE.to_rc()),
            };
            let commit_r =
                self.compute_commit_r(ecdaa_s.count, obj.name.get_buffer(), param_size)?;
            let (digest_buf, digest_len) = self.compute_hash(hash_alg, &[attest_bytes])?;
            let mut ecdaa_digest = [0u8; 128];
            let q_len = qualifying_data.len().min(64);
            ecdaa_digest[..q_len].copy_from_slice(&qualifying_data[..q_len]);
            ecdaa_digest[q_len..q_len + digest_len].copy_from_slice(&digest_buf[..digest_len]);
            let total_digest_len = q_len + digest_len;
            let mut sig_r = [0u8; 128];
            let mut sig_s = [0u8; 128];
            let priv_buf = &actual_priv_key_opt
                .expect("sign_handle is not null, so priv_key is populated")
                .0;
            let priv_len = actual_priv_key_opt
                .expect("sign_handle is not null, so priv_key is populated")
                .1;
            self.crypto()
                .ecdaa_sign(
                    curve,
                    &commit_r[..param_size],
                    &self.global_state.commit_x[..param_size.min(32)],
                    &self.global_state.commit_p1[..(param_size * 2).min(64)],
                    &priv_buf[..priv_len],
                    &ecdaa_digest[..total_digest_len],
                    &mut sig_r[..param_size],
                    &mut sig_s[..param_size],
                )
                .map_err(|_| TpmRc::FAILURE)?;
            OwnedSignature::Ecdaa {
                hash: hash_alg,
                signature_r: OwnedEccParameter::from_bytes(&sig_r[..param_size])
                    .map_err(|_| TpmRc::FAILURE)?,
                signature_s: OwnedEccParameter::from_bytes(&sig_s[..param_size])
                    .map_err(|_| TpmRc::FAILURE)?,
            }
        } else {
            let (hash_alg, sig_alg) = match actual_in_scheme {
                TpmtSigScheme::Rsassa(h) => (h, Alg::RSASSA),
                TpmtSigScheme::Rsapss(h) => (h, Alg::RSAPSS),
                TpmtSigScheme::Ecdsa(h) => (h, Alg::ECDSA),
                _ => return Err(TpmRc::SCHEME.to_rc()),
            };

            if !matches!(
                hash_alg,
                TpmiAlgHash::Sha1 | TpmiAlgHash::Sha256 | TpmiAlgHash::Sha384 | TpmiAlgHash::Sha512
            ) {
                return Err(TpmRc::HASH.to_rc());
            }

            let (digest_buf, digest_len) = self.compute_hash(hash_alg, &[attest_bytes])?;
            let digest_ha =
                tpm2::TpmtHa::new(hash_alg, &digest_buf[..digest_len]).ok_or(TpmRc::FAILURE)?;

            let mut sig_bytes = [0u8; 512];
            let sig_len = self
                .crypto()
                .sign_inner(
                    sig_alg,
                    &actual_priv_key_opt
                        .expect("sign_handle is not null, so priv_key is populated")
                        .0[..actual_priv_key_opt
                        .expect("sign_handle is not null, so priv_key is populated")
                        .1],
                    digest_ha,
                    &mut sig_bytes,
                )
                .map_err(|_| TpmRc::FAILURE)?;

            match actual_in_scheme {
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
                    if sig_len % 2 != 0 {
                        return Err(TpmRc::FAILURE);
                    }
                    let param_size = sig_len / 2;
                    let signature_r = OwnedEccParameter::from_bytes(&sig_bytes[..param_size])
                        .map_err(|_| TpmRc::FAILURE)?;
                    let signature_s =
                        OwnedEccParameter::from_bytes(&sig_bytes[param_size..sig_len])
                            .map_err(|_| TpmRc::FAILURE)?;
                    OwnedSignature::Ecdsa {
                        hash: hash_alg,
                        signature_r,
                        signature_s,
                    }
                }
                _ => return Err(TpmRc::SCHEME.to_rc()),
            }
        };
        Ok(Some(signature))
    }
}

struct SignerCredentials {
    privacy_admin_auth: Option<OwnedAuth>,
    signer_public: Option<OwnedPublic>,
    signer_private: Option<([u8; 1536], usize)>,
    signer_qualified_name: OwnedName,
}
