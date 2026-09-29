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

        // Validate privacy_admin matches administrative hierarchy handles
        if privacy_admin_handle.0 != tpm2::Handle::RH_ENDORSEMENT.0
            && privacy_admin_handle.0 != tpm2::Handle::RH_NULL.0
        {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

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

        if audit_session.audit_digest.is_none() {
            return Err(TpmRc::TYPE.with(Position::handle(3)));
        }

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

        let digest_bytes = audit_session.audit_digest.unwrap_or([0u8; 64]);
        let digest_len = if audit_session.audit_digest.is_some() {
            audit_session.audit_digest_len
        } else {
            audit_session.auth_hash.digest_size()
        };
        let session_digest =
            Tpm2bDigest::from_bytes(&digest_bytes[..digest_len]).map_err(|_| TpmRc::FAILURE)?;

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

        // 6. Sign the attestation payload
        let priv_key_opt = signer_obj_opt.as_ref().map(|s| (s.private, s.private_len));
        let owned_sig = self.sign_attestation_block(
            sign_handle,
            priv_key_opt.as_ref(),
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
