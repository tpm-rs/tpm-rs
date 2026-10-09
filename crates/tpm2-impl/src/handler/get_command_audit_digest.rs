use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::errors::{Position, TpmRc};

use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, owned::OwnedDigest, req_resp::RequestThenResponse};
use tpm2::commands::{GetCommandAuditDigest, GetCommandAuditDigestHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::{Alg, Handle, TpmGenerated};
use tpm2::{Tpm2bDigest, TpmiAlgHash, TpmsAttest, TpmsCommandAuditInfo, TpmuAttest};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::GetCommandAuditDigest] (`0x133`) command.
    pub fn get_command_audit_digest(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<GetCommandAuditDigestHandles>()?;
        let privacy_admin_handle = handles.privacy_admin_handle;
        let sign_handle = handles.sign_handle;

        // TPMI_RH_ENDORSEMENT (no `+`): only TPM_RH_ENDORSEMENT is a valid value.
        if privacy_admin_handle.0 != Handle::RH_ENDORSEMENT.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<GetCommandAuditDigest>()?;
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

        // Compute command audit digest for audited commands (default: TPM_CC_SetCommandCodeAuditStatus = 0x00000140)
        let audit_hash_alg =
            TpmiAlgHash::try_from(self.global_state.audit_hash_alg).unwrap_or(TpmiAlgHash::Sha256);
        let command_code_bytes = (tpm2::TpmCc::SetCommandCodeAuditStatus.code()).to_be_bytes();
        let (command_digest_buf, command_digest_len) =
            self.compute_hash(audit_hash_alg, &[&command_code_bytes])?;
        let command_digest = Tpm2bDigest::from_bytes(&command_digest_buf[..command_digest_len])
            .map_err(|_| TpmRc::FAILURE)?;

        let saved_audit_digest = self.global_state.command_audit_digest;
        let command_audit_info = TpmsCommandAuditInfo {
            audit_counter: self.global_state.audit_counter,
            digest_alg: Alg::from(audit_hash_alg),
            audit_digest: saved_audit_digest.as_tpm2b(),
            command_digest,
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
            self.global_state.command_audit_digest = OwnedDigest::default();
        }

        let rsp = responses::GetCommandAuditDigest {
            audit_info: tpm2::Tpm2b(attest),
            signature: owned_sig.as_ref().map(|s| s.as_tpmt()),
        };

        let response = request.into_response();
        self.write_response_all(response, &(), &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
