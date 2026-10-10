use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::storage::manager::StorageManager;
use crate::storage::{NvStorage, Tpm2Storage};
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Alg;
use tpm2::commands::PolicyAuthorizeNV;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmCc, TpmSe};
use tpm2::{TpmaNv, TpmiAlgHash};

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Handles the [TpmCc::PolicyAuthorizeNV] (`0x192`) command.
    ///
    /// # Description
    /// This command allows a policy to be authorized dynamically based on the contents of an NV Index.
    /// It compares the session's policy digest to a digest stored in the NV Index; if they match,
    /// it resets the policy digest and extends it with the NV Index's name.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 23.22 (TPM2_PolicyAuthorizeNV).
    ///
    /// # Relationships
    /// - Behaves similarly to [TpmCc::PolicyAuthorize](policy_authorize.rs) but uses an NV Index value instead of a signature verification ticket.
    /// - The NV Index (`nv_index`) must have been defined (via [TpmCc::NvDefineSpace](nv_storage.rs)),
    ///   written to (via [TpmCc::NvWrite](nv_storage.rs)), and must not be locked (via [TpmCc::NvReadLock](nv_storage.rs)).
    pub fn policy_authorize_nv(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<PolicyAuthorizeNV>()?;
        let [auth_handle, nv_index, policy_session] = handles;
        check(auth_handle, Tpmi::RhNvAuth, Position::handle(1))?;
        check(nv_index, Tpmi::RhNvIndex, Position::handle(2))?;
        check(policy_session, Tpmi::ShPolicy, Position::handle(3))?;
        let nv_index = nv_index.0;
        let policy_session = policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal_command::<PolicyAuthorizeNV>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Validate session expiration
        self.validate_policy_session(policy_session, Position::handle(3))?;

        // 1. Retrieve policy session state details

        let (auth_hash, policy_digest, policy_digest_len, session_type) = {
            let session_state = self
                .global_state
                .session(policy_session)
                .ok_or(TpmRc::HANDLE.with(Position::handle(3)))?;
            if session_state.session_type != TpmSe::Policy
                && session_state.session_type != TpmSe::Trial
            {
                return Err(TpmRc::HANDLE.with(Position::handle(3)));
            }
            (
                session_state.auth_hash,
                session_state.policy_digest,
                session_state.policy_digest_len,
                session_state.session_type,
            )
        };

        // 2. Resolve NV Index metadata from storage
        let mut read_buf = [0u8; 1536];
        let (metadata_size, nv_public, nv_auth, public_bytes, metadata) = {
            let storage = StorageManager::new(&mut *self.context.platform.storage);
            let metadata = storage
                .get_metadata(nv_index)
                .map_err(|_| TpmRc::HANDLE.to_rc())?;

            // Metadata header is usually up to 512 bytes
            let read_len = usize::from(metadata.data_size).min(read_buf.len());
            storage
                .read_item(nv_index, 0, &mut read_buf[..read_len])
                .map_err(|_| TpmRc::FAILURE)?;
            let (metadata_size, nv_public, nv_auth, _public_info, public_bytes) =
                crate::handler::unmarshal_nv_header_bytes(&read_buf[..read_len])?;
            (
                u16::try_from(metadata_size).map_err(|_| TpmRc::FAILURE)?,
                nv_public,
                nv_auth,
                public_bytes,
                metadata,
            )
        };

        // 3. Compute NV Index Name
        let nv_name = self.compute_name(Some(nv_public.name_alg), public_bytes)?;

        // 4. If not Trial session, perform checks and authorizations
        if session_type == TpmSe::Policy {
            // Check WRITTEN attribute
            if !nv_public.attributes.contains(TpmaNv::WRITTEN) {
                return Err(TpmRc::NV_UNINITIALIZED);
            }

            // Check READLOCKED attribute
            if nv_public.attributes.contains(TpmaNv::READLOCKED) {
                return Err(TpmRc::NV_LOCKED);
            }

            // Perform read authorization checks
            let is_owner_or_platform =
                auth_handle == Handle::RH_OWNER || auth_handle == Handle::RH_PLATFORM;
            let hierarchy_auth = if is_owner_or_platform {
                self.context.handle_auth(self.global_state, auth_handle.0)
            } else {
                Default::default()
            };

            let auths = &self.global_state.parsed_auths[..self.global_state.parsed_auths_len];
            let Some(auth) = auths.first() else {
                return Err(TpmRc::AUTH_MISSING);
            };

            // PORTING: exp unwrapped an `Option` holding the hierarchy auth for the
            // owner/platform cases; the read attribute and expected auth are now selected
            // together (same checks, same order).
            let (read_attribute, expected_auth) = if auth_handle.0 == nv_index {
                (TpmaNv::AUTHREAD, nv_auth.as_slice())
            } else if auth_handle == Handle::RH_OWNER {
                (TpmaNv::OWNERREAD, hierarchy_auth.get_buffer())
            } else if auth_handle == Handle::RH_PLATFORM {
                (TpmaNv::PPREAD, hierarchy_auth.get_buffer())
            } else {
                return Err(TpmRc::HANDLE.to_rc());
            };
            if !nv_public.attributes.contains(read_attribute) {
                return Err(TpmRc::NV_AUTHORIZATION);
            }
            if !self.verify_password_auth(auth, expected_auth) {
                return Err(TpmRc::AUTH_FAIL.to_rc());
            }

            // Read TPMT_HA (2 bytes alg + digest) from the NV Index
            let digest_size = match auth_hash {
                TpmiAlgHash::Sha1 => 20,
                TpmiAlgHash::Sha256 => 32,
                TpmiAlgHash::Sha384 => 48,
                TpmiAlgHash::Sha512 => 64,
                _ => return Err(TpmRc::VALUE.to_rc()),
            };

            if usize::from(metadata.data_size) < usize::from(metadata_size) + 2 + digest_size {
                return Err(TpmRc::INSUFFICIENT.to_rc());
            }

            let mut val_buf = [0u8; 128];
            let read_data_len = 2 + digest_size;
            {
                let storage = StorageManager::new(&mut *self.context.platform.storage);
                storage
                    .read_item(nv_index, metadata_size, &mut val_buf[..read_data_len])
                    .map_err(|_| TpmRc::FAILURE)?;
            }

            let alg_id = u16::from_be_bytes([val_buf[0], val_buf[1]]);
            if alg_id != Alg::from(auth_hash).id() {
                return Err(TpmRc::HASH.to_rc());
            }

            // Compare policyDigest to the contents of the NV Index (after the TPM_ALG_ID)
            let nv_digest = &val_buf[2..2 + digest_size];
            if nv_digest != &policy_digest[..policy_digest_len] {
                return Err(TpmRc::VALUE.to_rc());
            }
        }

        // 5. Update the session state policyDigest. Part 3: "If the comparison is successful, the
        // TPM will reset policySession->policyDigest to a Zero Digest" and then extend it, so
        // policyDigest_new = H_policyAlg(ZeroDigest || TPM_CC_PolicyAuthorizeNV || nvIndex->Name).
        let digest_size = match auth_hash {
            TpmiAlgHash::Sha1 => 20,
            TpmiAlgHash::Sha256 => 32,
            TpmiAlgHash::Sha384 => 48,
            TpmiAlgHash::Sha512 => 64,
            _ => return Err(TpmRc::VALUE.to_rc()),
        };
        let zero_digest = [0u8; 64];
        let zero_slice = &zero_digest[..digest_size];

        let (new_digest, new_digest_len) = self.compute_hash(
            auth_hash,
            &[
                zero_slice,
                &(TpmCc::PolicyAuthorizeNV.code()).to_be_bytes(),
                nv_name.get_buffer(),
            ],
        )?;

        {
            let session_state = self
                .global_state
                .session_mut(policy_session)
                .ok_or(TpmRc::HANDLE.with(Position::handle(3)))?;
            session_state.policy_digest[..new_digest_len]
                .copy_from_slice(&new_digest[..new_digest_len]);
            session_state.policy_digest_len = new_digest_len;
        }

        // 6. Write the response
        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }
}
