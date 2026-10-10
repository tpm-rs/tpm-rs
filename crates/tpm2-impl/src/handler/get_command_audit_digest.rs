use tpm2::Marshal;
use tpm2::TpmCc;
use tpm2::commands::{GetCommandAuditDigest, responses};
use tpm2::errors::{Position, TpmRc};

use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, owned::OwnedDigest, req_resp::RequestThenResponse};
use tpm2::{Alg, Handle, TpmGenerated};
use tpm2::{Tpm2bDigest, TpmiAlgHash, TpmsAttest, TpmsCommandAuditInfo, TpmuAttest};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::GetCommandAuditDigest] (`0x133`) command.
    pub fn get_command_audit_digest(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<GetCommandAuditDigest>()?;
        let [privacy_admin_handle, sign_handle] = handles;
        check(
            privacy_admin_handle,
            Tpmi::RhEndorsement,
            Position::handle(1),
        )?;
        check(sign_handle, Tpmi::DhObjectOrNull, Position::handle(2))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<GetCommandAuditDigest>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Resolve signer key
        let signer_obj_opt = if sign_handle == Handle::RH_NULL {
            None
        } else {
            Some(self.resolve_object(sign_handle.0, Position::handle(2))?)
        };

        // PORTING: exp validated `privacy_admin_handle` here against TPM_RH_ENDORSEMENT,
        // TPM_RH_OWNER, TPM_RH_PLATFORM and TPM_RH_NULL (TPM_RC_VALUE + handle 1); it is now
        // range-checked as `TPMI_RH_ENDORSEMENT` (handle 1) before session validation.

        // 2. Verify authorizations
        let expected_sessions = if sign_handle == Handle::RH_NULL { 1 } else { 2 };
        if num_sessions < expected_sessions {
            return Err(TpmRc::AUTH_MISSING);
        }

        let clock_info = self.get_clock_info();

        // 3. Resolve signature scheme and verify consistency with public attributes
        let public_opt = signer_obj_opt.as_ref().map(|s| &s.public);
        let actual_in_scheme =
            self.resolve_attest_scheme(sign_handle, public_opt, cmd.in_scheme)?;

        let (qualified_signer, extra_data) = self.compute_attest_fields(
            signer_obj_opt.as_ref(),
            &actual_in_scheme,
            &cmd.qualifying_data,
        )?;

        // Compute command audit digest for audited commands (default: TPM_CC_SetCommandCodeAuditStatus = 0x00000140)
        let audit_hash_alg = TpmiAlgHash::try_from(Alg::from(self.global_state.audit_hash_alg))
            .unwrap_or(TpmiAlgHash::Sha256);
        let command_code_bytes = TpmCc::SetCommandCodeAuditStatus.code().to_be_bytes();
        let (command_digest_buf, command_digest_len) =
            self.compute_hash(audit_hash_alg, &[&command_code_bytes])?;
        let command_digest = command_digest_buf
            .get(..command_digest_len)
            .and_then(Tpm2bDigest::new)
            .ok_or(TpmRc::FAILURE)?;

        let saved_audit_digest = self.global_state.command_audit_digest;
        let command_audit_info = TpmsCommandAuditInfo {
            audit_counter: self.global_state.audit_counter,
            digest_alg: Alg::from(audit_hash_alg),
            audit_digest: saved_audit_digest.as_tpm2b(),
            command_digest,
        };

        let attest = TpmsAttest {
            magic: TpmGenerated,
            qualified_signer,
            extra_data,
            clock_info,
            firmware_version: 0x00010001,
            attested: TpmuAttest::CommandAudit(command_audit_info),
        };

        let mut attest_buf = [0u8; TpmsAttest::MAX_SIZE];
        let attest_len = attest.marshal(&mut attest_buf);
        let attest_bytes = attest_buf.get(..attest_len).ok_or(TpmRc::FAILURE)?;

        // 4. Sign the attestation payload
        let owned_sig = self.sign_attestation_block(
            sign_handle,
            signer_obj_opt.as_ref(),
            actual_in_scheme,
            attest_bytes,
            cmd.qualifying_data.as_slice(),
        )?;

        // Reset log if sign_handle != RH_Null
        if sign_handle != Handle::RH_NULL {
            self.global_state.command_audit_digest = OwnedDigest::default();
        }

        let rsp = responses::GetCommandAuditDigest {
            audit_info: tpm2::Tpm2b(attest),
            signature: owned_sig.as_ref().map(|s| s.as_tpmt()),
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
