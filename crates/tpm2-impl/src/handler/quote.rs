use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, owned::OwnedDigest, req_resp::RequestThenResponse};
use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::TpmGenerated;
use tpm2::commands::responses;
use tpm2::commands::{Quote, QuoteHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{TpmsAttest, TpmsQuoteInfo, TpmtSigScheme, TpmuAttest};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::Quote] (`0x158`) command.
    ///
    /// # Description
    /// This command is used to quote PCR values.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 18.4 (TPM2_Quote).
    pub fn quote(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<QuoteHandles>()?;
        let sign_handle = handles.sign_handle;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<Quote>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Resolve signer key
        let signer_obj_opt = if sign_handle.0 == 0x40000007 {
            None
        } else {
            Some(self.resolve_object(sign_handle.0, Position::handle(1))?)
        };

        let _auths = &self.global_state.parsed_auths[..self.global_state.parsed_auths_len];

        // 2. Verify authorizations
        let expected_sessions = if sign_handle.0 == 0x40000007 { 0 } else { 1 };
        if num_sessions < expected_sessions {
            return Err(TpmRc::AUTH_MISSING);
        }

        // 3. Resolve signature scheme and verify consistency with public attributes
        let public_opt = signer_obj_opt.as_ref().map(|s| &s.public);
        let actual_in_scheme =
            self.resolve_attest_scheme(sign_handle, public_opt, cmd.in_scheme)?;

        // 4. Compute PCR digest across pcr_select using the hash algorithm from actual_in_scheme
        let hash_alg = match actual_in_scheme {
            Some(tpm2::TpmtSigScheme::Rsassa(h))
            | Some(tpm2::TpmtSigScheme::Rsapss(h))
            | Some(tpm2::TpmtSigScheme::Ecdsa(h)) => Some(h),
            Some(tpm2::TpmtSigScheme::Ecdaa(s)) => Some(s.hash_alg),
            None => {
                if sign_handle.0 != 0x40000007 {
                    return Err(TpmRc::SCHEME.to_rc());
                }
                None
            }
            _ => return Err(TpmRc::SCHEME.to_rc()),
        };

        let pcr_digest = if let Some(hash_alg) = hash_alg {
            self.compute_pcr_digest(&cmd.pcr_select, hash_alg)?
        } else {
            if sign_handle.0 != 0x40000007 {
                return Err(TpmRc::SCHEME.to_rc());
            }
            OwnedDigest::default()
        };

        // 5. Construct attestation structure
        let clock_info = self.get_clock_info();

        let (qualified_signer, extra_data) = self.compute_attest_fields(
            signer_obj_opt.as_ref(),
            &actual_in_scheme,
            &cmd.qualifying_data,
        )?;

        let attest = TpmsAttest {
            magic: TpmGenerated,
            qualified_signer,
            extra_data,
            clock_info,
            firmware_version: 0x00010001,
            attested: TpmuAttest::Quote(TpmsQuoteInfo {
                pcr_select: cmd.pcr_select,
                pcr_digest: pcr_digest.as_tpm2b(),
            }),
        };

        let mut attest_buf = [0u8; TpmsAttest::MAX_SIZE];
        let attest_len = attest.marshal(&mut attest_buf);

        // 6. Sign the attestation payload
        let priv_key_opt = signer_obj_opt.as_ref().map(|s| (s.private, s.private_len));
        if let Some(TpmtSigScheme::Ecdaa(ecdaa_s)) = actual_in_scheme {
            if let Ok((digest_buf, digest_len)) =
                self.compute_hash(ecdaa_s.hash_alg, &[&attest_buf[..attest_len]])
            {
                let mut ecdaa_digest = [0u8; 128];
                let q_len = cmd.qualifying_data.get_buffer().len().min(64);
                ecdaa_digest[..q_len].copy_from_slice(&cmd.qualifying_data.get_buffer()[..q_len]);
                ecdaa_digest[q_len..q_len + digest_len].copy_from_slice(&digest_buf[..digest_len]);
                let dlen = (q_len + digest_len).min(64);
                self.global_state.debug_provided_auth[..dlen]
                    .copy_from_slice(&ecdaa_digest[..dlen]);
                self.global_state.debug_provided_auth_len = dlen;
            }
        }
        let owned_sig = self.sign_attestation_block(
            sign_handle,
            priv_key_opt.as_ref(),
            actual_in_scheme,
            &attest_buf[..attest_len],
            cmd.qualifying_data.get_buffer(),
        )?;

        let rsp = responses::Quote {
            quoted: tpm2::Tpm2b(attest),
            signature: owned_sig.as_ref().map(|s| s.as_tpmt()),
        };

        let response = request.into_response();
        self.write_response_all(response, &(), &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
