use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::errors::{Position, TpmRc};

use crate::handle_checks::{Tpmi, check};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, owned::OwnedDigest, req_resp::RequestThenResponse};
use tpm2::commands::GetCommandAuditDigest;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::{Alg, Handle, TpmGenerated};
use tpm2::{TpmsAttest, TpmsCommandAuditInfo, TpmuAttest};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::GetCommandAuditDigest] (`0x133`) command.
    pub fn get_command_audit_digest(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<GetCommandAuditDigest>()?;
        let [privacy_handle, sign_handle] = handles;
        check(privacy_handle, Tpmi::RhEndorsement, Position::handle(1))?;
        check(sign_handle, Tpmi::DhObjectOrNull, Position::handle(2))?;

        // TPMI_RH_ENDORSEMENT (no `+`): only TPM_RH_ENDORSEMENT is a valid value.
        if privacy_handle.0 != Handle::RH_ENDORSEMENT.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<GetCommandAuditDigest>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Resolve signer key
        let signer_obj_opt = if sign_handle.0 == 0x40000007 {
            None
        } else {
            Some(self.resolve_object(sign_handle.0, Position::handle(2))?)
        };

        // 2. Verify authorizations
        let expected_sessions = if sign_handle.0 == 0x40000007 { 1 } else { 2 };
        if num_sessions < expected_sessions {
            return Err(TpmRc::AUTH_MISSING);
        }

        // 3. IsSigningObject() (TPM_RC_KEY + RC_GetCommandAuditDigest_signHandle) and
        //    CryptSelectSignScheme() (TPM_RC_SCHEME + RC_GetCommandAuditDigest_inScheme).
        let public_opt = signer_obj_opt.as_ref().map(|s| &s.public);
        let actual_in_scheme = self.resolve_attest_scheme(
            public_opt,
            cmd.in_scheme,
            Position::handle(2),
            Position::parameter(2),
        )?;

        let header = self.compute_attest_fields(
            signer_obj_opt.as_ref(),
            &actual_in_scheme,
            &cmd.qualifying_data,
        )?;

        // `commandDigest`: digest of the list of audited commands (`CommandAuditGetDigest`).
        let audit_hash_alg = self.context.state.command_audit_hash_alg();
        let command_digest = self.context.command_audit_list_digest()?;

        let saved_audit_digest = self.context.state.command_audit_digest;
        let command_audit_info = TpmsCommandAuditInfo {
            audit_counter: self.context.state.audit_counter,
            digest_alg: Alg::from(audit_hash_alg),
            audit_digest: saved_audit_digest.as_tpm2b(),
            command_digest: command_digest.as_tpm2b(),
        };

        let attest = TpmsAttest {
            magic: TpmGenerated,
            qualified_signer: header.qualified_signer,
            extra_data: header.extra_data,
            clock_info: header.clock_info,
            firmware_version: header.firmware_version,
            attested: TpmuAttest::CommandAudit(command_audit_info),
        };

        let mut attest_buf = [0u8; TpmsAttest::MAX_SIZE];
        let attest_len = attest.marshal(&mut attest_buf);

        // 4. Sign the attestation payload
        let owned_sig = self.sign_attestation_block(
            signer_obj_opt.as_ref(),
            actual_in_scheme,
            &attest_buf[..attest_len],
            cmd.qualifying_data.get_buffer(),
        )?;

        // Reset log if sign_handle != RH_Null
        if sign_handle.0 != 0x40000007 {
            self.context.state.command_audit_digest = OwnedDigest::default();
        }

        let rsp = responses::GetCommandAuditDigest {
            audit_info: tpm2::Tpm2b(attest),
            signature: owned_sig.as_ref().map(|s| s.as_tpmt()),
        };

        let response = request.into_response();
        self.write_response_message(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
