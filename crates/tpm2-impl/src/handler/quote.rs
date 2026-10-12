use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, owned::OwnedDigest, req_resp::RequestThenResponse};
use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{Quote, responses};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmGenerated};
use tpm2::{TpmsAttest, TpmsPcrSelect, TpmsQuoteInfo, TpmtSigScheme, TpmuAttest};

/// Maximum `sizeofSelect` of a `TPMS_PCR_SELECT` (`PCR_SELECT_MAX` for this TPM's 24 PCRs).
///
/// PORTING: exp's typed `TPMS_PCR_SELECT` unmarshal rejected larger selections with
/// `TPM_RC_VALUE`; the new [`TpmsPcrSelect`] accepts up to [`TpmsPcrSelect::MAX`] (32 PCRs).
const PCR_SELECT_MAX: usize = TpmsPcrSelect::PLATFORM_PCRS.div_ceil(8);

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::Quote] (`0x158`) command.
    ///
    /// # Description
    /// This command is used to quote PCR values.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 18.4 (TPM2_Quote).
    pub fn quote(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<Quote>()?;
        let [sign_handle] = handles;
        check(sign_handle, Tpmi::DhObjectOrNull, Position::handle(1))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<Quote>(handles)?;
        if cmd
            .pcr_select
            .as_slice()
            .iter()
            .any(|sel| sel.selection.pcrs().len() > PCR_SELECT_MAX)
        {
            return Err(TpmRc::VALUE.with(Position::parameter(3)));
        }
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Resolve signer key
        let signer_obj_opt = if sign_handle == Handle::RH_NULL {
            None
        } else {
            Some(self.resolve_object(sign_handle.0, Position::handle(1))?)
        };

        // 2. Verify authorizations
        let expected_sessions = if sign_handle == Handle::RH_NULL { 0 } else { 1 };
        if num_sessions < expected_sessions {
            return Err(TpmRc::AUTH_MISSING);
        }

        // 3. Resolve signature scheme and verify consistency with public attributes
        let public_opt = signer_obj_opt.as_ref().map(|s| &s.public);
        let actual_in_scheme =
            self.resolve_attest_scheme(sign_handle, public_opt, cmd.in_scheme)?;

        // 4. Compute PCR digest across pcr_select using the hash algorithm from actual_in_scheme
        let hash_alg = match actual_in_scheme {
            Some(TpmtSigScheme::Rsassa(h))
            | Some(TpmtSigScheme::Rsapss(h))
            | Some(TpmtSigScheme::Ecdsa(h)) => Some(h),
            Some(TpmtSigScheme::Ecdaa(s)) => Some(s.hash_alg),
            Some(TpmtSigScheme::Mldsa) => Some(
                signer_obj_opt
                    .as_ref()
                    .and_then(|s| s.public.name_alg)
                    .ok_or(TpmRc::SCHEME.to_rc())?,
            ),
            Some(TpmtSigScheme::HashMldsa) => {
                match signer_obj_opt.as_ref().map(|s| &s.public.parms_and_id) {
                    Some(crate::owned::OwnedPublicParmsAndId::HashMldsa(p, _)) => Some(p.hash_alg),
                    _ => return Err(TpmRc::SCHEME.to_rc()),
                }
            }
            None => {
                if sign_handle != Handle::RH_NULL {
                    return Err(TpmRc::SCHEME.to_rc());
                }
                None
            }
            _ => return Err(TpmRc::SCHEME.to_rc()),
        };

        let pcr_digest = if let Some(hash_alg) = hash_alg {
            self.compute_pcr_digest(&cmd.pcr_select, hash_alg)?
        } else {
            if sign_handle != Handle::RH_NULL {
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
        let attest_bytes = attest_buf.get(..attest_len).ok_or(TpmRc::FAILURE)?;

        // 6. Sign the attestation payload
        let owned_sig = self.sign_attestation_block(
            sign_handle,
            signer_obj_opt.as_ref(),
            actual_in_scheme,
            attest_bytes,
            cmd.qualifying_data.as_slice(),
        )?;

        let rsp = responses::Quote {
            quoted: tpm2::Tpm2b(attest),
            signature: owned_sig.as_ref().map(|s| s.as_tpmt()),
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
