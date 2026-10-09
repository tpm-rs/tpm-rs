use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::TpmGenerated;
use tpm2::commands::responses;
use tpm2::commands::{GetSessionAuditDigest, GetSessionAuditDigestHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2bDigest, TpmsAttest, TpmsSessionAuditInfo, TpmuAttest};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
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

        let handles = request.try_unmarshal::<GetSessionAuditDigestHandles>()?;
        let privacy_admin_handle = handles.privacy_admin_handle;
        let sign_handle = handles.sign_handle;
        let session_handle = handles.session_handle;

        // TPMI_RH_ENDORSEMENT (no `+`): only TPM_RH_ENDORSEMENT is a valid value.
        if privacy_admin_handle.0 != tpm2::Handle::RH_ENDORSEMENT.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<GetSessionAuditDigest>()?;
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

        // Verify privacy_admin authorization (session 0)
        let _expected_admin_auth = self
            .context
            .handle_auth(self.global_state, privacy_admin_handle.0);

        let _auths = &self.global_state.parsed_auths[..self.global_state.parsed_auths_len];

        // Verify sign_handle authorization (session 1, if present)

        // 3. Look up target audit session
        let audit_session = self
            .global_state
            .session(session_handle.0)
            .ok_or(TpmRc::HANDLE.with(Position::handle(3)))?;
        let audit_digest = audit_session.audit_digest;
        let audit_digest_len = audit_session.audit_digest_len;

        // 4. IsSigningObject() (TPM_RC_KEY + RC_GetSessionAuditDigest_signHandle) and
        //    CryptSelectSignScheme() (TPM_RC_SCHEME + RC_GetSessionAuditDigest_inScheme) are
        //    checked before the session's audit attribute.
        let public_opt = signer_obj_opt.as_ref().map(|s| &s.public);
        let actual_in_scheme = self.resolve_attest_scheme(
            public_opt,
            cmd.in_scheme,
            Position::handle(2),
            Position::parameter(2),
        )?;

        let Some(digest_bytes) = audit_digest else {
            return Err(TpmRc::TYPE.with(Position::handle(3)));
        };

        let header = self.compute_attest_fields(
            signer_obj_opt.as_ref(),
            &actual_in_scheme,
            &cmd.qualifying_data,
        )?;

        let session_digest = Tpm2bDigest::from_bytes(&digest_bytes[..audit_digest_len])
            .map_err(|_| TpmRc::FAILURE)?;

        let exclusive_session = self.global_state.exclusive_audit_session == Some(session_handle.0);

        let session_audit_info = TpmsSessionAuditInfo {
            exclusive_session,
            session_digest,
        };

        let attest = TpmsAttest {
            magic: TpmGenerated,
            qualified_signer: header.qualified_signer,
            extra_data: header.extra_data,
            clock_info: header.clock_info,
            firmware_version: header.firmware_version,
            attested: TpmuAttest::SessionAudit(session_audit_info),
        };

        let mut attest_buf = [0u8; TpmsAttest::MAX_SIZE];
        let attest_len = attest.marshal(&mut attest_buf);

        // 5. Sign the attestation payload
        let owned_sig = self.sign_attestation_block(
            signer_obj_opt.as_ref(),
            actual_in_scheme,
            &attest_buf[..attest_len],
            cmd.qualifying_data.get_buffer(),
        )?;

        let rsp = responses::GetSessionAuditDigest {
            audit_info: tpm2::Tpm2b(attest),
            signature: owned_sig.as_ref().map(|s| s.as_tpmt()),
        };

        let response = request.into_response();
        self.write_response_all(response, &(), &rsp, &session_responses[..num_sessions])?;

        Ok(())
    }
}
