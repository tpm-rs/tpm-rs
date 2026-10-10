use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{GetSessionAuditDigest, responses};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmGenerated};
use tpm2::{Tpm2bDigest, TpmsAttest, TpmsSessionAuditInfo, TpmuAttest};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::GetSessionAuditDigest] (`0x14D`) command.
    ///
    /// # Description
    /// This command returns the current value of the session audit digest for a specified audit session,
    /// signed by a signing key loaded in the TPM.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 18.4 (TPM2_GetSessionAuditDigest).
    ///
    /// # Relationships
    /// - The `session_handle` must reference an active audit session created using [TpmCc::StartAuthSession](session.rs).
    /// - The `sign_handle` must be a loaded signing key (created by [TpmCc::Create](create.rs)
    ///   or [TpmCc::CreatePrimary](create_primary.rs) and loaded).
    pub fn get_session_audit_digest(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<GetSessionAuditDigest>()?;
        let [privacy_admin_handle, sign_handle, session_handle] = handles;
        check(
            privacy_admin_handle,
            Tpmi::RhEndorsement,
            Position::handle(1),
        )?;
        check(sign_handle, Tpmi::DhObjectOrNull, Position::handle(2))?;
        check(session_handle, Tpmi::ShHmac, Position::handle(3))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal_command::<GetSessionAuditDigest>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Resolve signer key
        let signer_obj_opt = if sign_handle == Handle::RH_NULL {
            None
        } else {
            Some(self.resolve_object(sign_handle.0, Position::handle(2))?)
        };

        // PORTING: exp validated `privacy_admin_handle` here against TPM_RH_ENDORSEMENT and
        // TPM_RH_NULL (TPM_RC_VALUE + handle 1); it is now range-checked as
        // `TPMI_RH_ENDORSEMENT` (handle 1) before session validation.

        // 2. Verify authorizations
        let expected_sessions = if sign_handle == Handle::RH_NULL { 1 } else { 2 };
        if num_sessions < expected_sessions {
            return Err(TpmRc::AUTH_MISSING);
        }

        // PORTING: exp's no-op lookups of the expected privacy admin and signer authorization
        // values are dropped (authorization is checked by the engine).

        // 3. Look up target audit session
        let audit_session = self
            .global_state
            .session(session_handle.0)
            .ok_or(TpmRc::HANDLE.with(Position::handle(3)))?;

        let Some(digest_bytes) = audit_session.audit_digest else {
            return Err(TpmRc::TYPE.with(Position::handle(3)));
        };
        let digest_len = audit_session.audit_digest_len;

        let clock_info = self.get_clock_info();

        // 5. Resolve signature scheme and verify consistency with public attributes
        let public_opt = signer_obj_opt.as_ref().map(|s| &s.public);
        let actual_in_scheme =
            self.resolve_attest_scheme(sign_handle, public_opt, cmd.in_scheme)?;

        let (qualified_signer, extra_data) = self.compute_attest_fields(
            signer_obj_opt.as_ref(),
            &actual_in_scheme,
            &cmd.qualifying_data,
        )?;

        let session_digest = digest_bytes
            .get(..digest_len)
            .and_then(Tpm2bDigest::new)
            .ok_or(TpmRc::FAILURE)?;

        let exclusive_session = self.global_state.exclusive_audit_session == Some(session_handle.0);

        let session_audit_info = TpmsSessionAuditInfo {
            exclusive_session,
            session_digest,
        };

        let attest = TpmsAttest {
            magic: TpmGenerated,
            qualified_signer,
            extra_data,
            clock_info,
            firmware_version: 0x00010001,
            attested: TpmuAttest::SessionAudit(session_audit_info),
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

        let rsp = responses::GetSessionAuditDigest {
            audit_info: tpm2::Tpm2b(attest),
            signature: owned_sig.as_ref().map(|s| s.as_tpmt()),
        };

        let response = request.into_response();
        self.write_response_rsp(response, &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
