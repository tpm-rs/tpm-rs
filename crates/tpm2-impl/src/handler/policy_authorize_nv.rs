use crate::storage::manager::StorageManager;
use crate::storage::{NvStorage, Tpm2Storage};
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::TpmiAlgHash;
use tpm2::commands::{PolicyAuthorizeNV, PolicyAuthorizeNVHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{TpmCc, TpmSe};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::PolicyAuthorizeNV] (`0x177`) command.
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

        let handles = request.try_unmarshal::<PolicyAuthorizeNVHandles>()?;
        let auth_handle = handles.auth_handle;
        let nv_index = handles.nv_index.0;
        let policy_session = handles.policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal::<PolicyAuthorizeNV>()?;
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
        let (metadata_size, nv_public, public_bytes) = {
            let storage = StorageManager::new(&mut *self.context.platform.storage);
            let metadata = storage
                .get_metadata(nv_index)
                .map_err(|_| TpmRc::HANDLE.with(Position::handle(2)))?;

            // Metadata header is usually up to 512 bytes
            let read_len = core::cmp::min(metadata.data_size as usize, 1536);
            storage
                .read_item(nv_index, 0, &mut read_buf[..read_len])
                .map_err(|_| TpmRc::FAILURE)?;
            let (metadata_size, nv_public, _nv_auth, _public_info, public_bytes) =
                crate::handler::nv_storage::unmarshal_nv_header_bytes(&read_buf[..read_len])?;
            (metadata_size as u16, nv_public, public_bytes)
        };

        // 3. Compute NV Index Name
        let nv_name = self.compute_name(Some(nv_public.name_alg), public_bytes)?;

        // 4. If not Trial session, perform checks and authorizations
        if session_type == TpmSe::Policy {
            // Common read access checks (C `NvReadAccessChecks`): READLOCKED, then whether
            // `authHandle` may read the index, then WRITTEN. The authorization itself (password,
            // HMAC or policy) was already verified by the engine for `authHandle`.
            super::policy_nv::nv_read_access_checks(auth_handle.0, nv_index, nv_public.attributes)?;

            // Read `MIN(dataSize, sizeof(TPMT_HA))` bytes and unmarshal them as a TPMT_HA (C
            // `TPMT_HA_Unmarshal`): the hash algorithm first (`TPM_RC_HASH` if it is not a valid
            // hash), then its digest (`TPM_RC_INSUFFICIENT` if the data is too short).
            let mut val_buf = [0u8; 2 + tpm2::TpmtHa::MAX_DIGEST_SIZE];
            let read_data_len = core::cmp::min(nv_public.data_size as usize, val_buf.len());
            {
                let storage = StorageManager::new(&mut *self.context.platform.storage);
                storage
                    .read_item(nv_index, metadata_size, &mut val_buf[..read_data_len])
                    .map_err(|_| TpmRc::FAILURE)?;
            }
            let val = &val_buf[..read_data_len];
            if val.len() < 2 {
                return Err(TpmRc::INSUFFICIENT.to_rc());
            }
            let nv_hash_alg = TpmiAlgHash::try_from(u16::from_be_bytes([val[0], val[1]]))
                .map_err(|_| TpmRc::HASH.to_rc())?;
            let nv_digest_size = nv_hash_alg.digest_size();
            if val.len() < 2 + nv_digest_size {
                return Err(TpmRc::INSUFFICIENT.to_rc());
            }

            // The stored policy must use the session's hash algorithm.
            if nv_hash_alg != auth_hash {
                return Err(TpmRc::HASH.to_rc());
            }

            // Compare policyDigest to the contents of the NV Index (after the TPM_ALG_ID)
            let nv_digest = &val[2..2 + nv_digest_size];
            if nv_digest != &policy_digest[..policy_digest_len] {
                return Err(TpmRc::VALUE.to_rc());
            }
        }

        // 5. Update the session state policyDigest
        // policyDigest_new = H_policyAlg(policyDigest_old || TPM_CC_PolicyAuthorizeNV || nvIndex->Name)
        // Wait, does it reset policySession->policyDigest to Zero Digest first?
        // Spec: "If the comparison is successful, the TPM will reset policySession->policyDigest to a Zero Digest. Then it will update..."
        // Ah! "reset to a Zero Digest" means policyDigest_old is replaced by a Zero digest BEFORE hashing!
        // Wait, let's verify if "policyDigestold" in the formula is the zero digest or the old digest.
        // Spec: "If the comparison is successful, the TPM will reset policySession->policyDigest to a Zero Digest. Then it will update policySession->policyDigest with:
        // policyDigestnew = HpolicyAlg(policyDigestold || TPM_CC_PolicyAuthorizeNV || nvIndex->Name)"
        // Wait! If policyDigest has been reset to Zero Digest, then `policyDigestold` in the formula IS the Zero Digest!
        // Yes, because "Then it will update policySession->policyDigest" uses the current state (which was just reset to Zero Digest).
        // Let's check:
        // H_policyAlg(ZeroDigest || TPM_CC_PolicyAuthorizeNV || nvIndex->Name)
        // Yes, this is correct!
        let digest_size = auth_hash.digest_size();
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
