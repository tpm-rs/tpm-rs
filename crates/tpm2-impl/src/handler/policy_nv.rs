use crate::storage::manager::StorageManager;
use crate::storage::{NvStorage, Tpm2Storage};
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::TpmaNv;
use tpm2::commands::{PolicyNV, PolicyNVHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmCc, TpmEo, TpmSe};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::PolicyNV] (`0x149`) command.
    ///
    /// # Description
    /// This command makes a policy conditional on the result of a comparison between a value stored in an NV Index
    /// and a provided input operand.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 23.9 (TPM2_PolicyNV).
    ///
    /// # Relationships
    /// - Operates on an NV Index defined by [TpmCc::NvDefineSpace](nv_storage.rs) and written to by [TpmCc::NvWrite](nv_storage.rs).
    /// - Extends the policy digest of an active policy session created via [TpmCc::StartAuthSession](session.rs).
    pub fn policy_nv(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<PolicyNVHandles>()?;
        let nv_index = handles.nv_index;
        let policy_session = handles.policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<PolicyNV>()?;
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

        // `nvIndex` (handle 2) must reference a defined NV Index for every session type (C checks
        // the handle with `EntityGetLoadStatus` before the command runs); otherwise the trial
        // policy digest would be extended with a Name no NV Index has.
        if Handle(nv_index.0).handle_type() != Some(tpm2::TpmHt::NVIndex) {
            return Err(TpmRc::VALUE.with(Position::handle(2)));
        }
        let mut read_buf = [0u8; 1536];
        let (metadata_size, nv_public) = {
            let storage = StorageManager::new(&mut *self.context.platform.storage);
            let metadata = storage
                .get_metadata(nv_index.0)
                .map_err(|_| TpmRc::HANDLE.with(Position::handle(2)))?;

            let read_len = core::cmp::min(metadata.data_size as usize, 1536);
            storage
                .read_item(nv_index.0, 0, &mut read_buf[..read_len])
                .map_err(|_| TpmRc::FAILURE)?;
            let (metadata_size, nv_public, _, _) =
                crate::handler::nv_storage::unmarshal_nv_header(&read_buf[..read_len])?;
            (metadata_size as u16, nv_public)
        };

        if session_type != TpmSe::Trial {
            // Common read access checks (C `NvReadAccessChecks`): READLOCKED, then whether
            // `authHandle` may read the index, then WRITTEN.
            nv_read_access_checks(handles.auth_handle.0, nv_index.0, nv_public.attributes)?;

            // Make sure that offset is within range (`TPM_RCS_VALUE + RC_PolicyNV_offset`), and
            // that the NV data starting at offset is at least as large as operandB
            // (`TPM_RCS_SIZE + RC_PolicyNV_operandB`).
            if cmd.offset > nv_public.data_size {
                return Err(TpmRc::VALUE.with(Position::parameter(2)));
            }
            let operand_b_len = cmd.operand_b.get_size() as usize;
            if ((nv_public.data_size - cmd.offset) as usize) < operand_b_len {
                return Err(TpmRc::SIZE.with(Position::parameter(1)));
            }

            // Read the data from NV index
            let mut operand_a = [0u8; 64];
            {
                let storage = StorageManager::new(&mut *self.context.platform.storage);
                storage
                    .read_item(
                        nv_index.0,
                        metadata_size + cmd.offset,
                        &mut operand_a[..operand_b_len],
                    )
                    .map_err(|_| TpmRc::FAILURE)?;
            }

            // Perform arithmetic comparison
            let is_valid = match cmd.operation {
                TpmEo::Eq => {
                    unsigned_compare(&operand_a[..operand_b_len], cmd.operand_b.get_buffer())
                        == core::cmp::Ordering::Equal
                }
                TpmEo::Neq => {
                    unsigned_compare(&operand_a[..operand_b_len], cmd.operand_b.get_buffer())
                        != core::cmp::Ordering::Equal
                }
                TpmEo::SignedGT => {
                    signed_compare(&operand_a[..operand_b_len], cmd.operand_b.get_buffer())
                        == core::cmp::Ordering::Greater
                }
                TpmEo::UnsignedGT => {
                    unsigned_compare(&operand_a[..operand_b_len], cmd.operand_b.get_buffer())
                        == core::cmp::Ordering::Greater
                }
                TpmEo::SignedLT => {
                    signed_compare(&operand_a[..operand_b_len], cmd.operand_b.get_buffer())
                        == core::cmp::Ordering::Less
                }
                TpmEo::UnsignedLT => {
                    unsigned_compare(&operand_a[..operand_b_len], cmd.operand_b.get_buffer())
                        == core::cmp::Ordering::Less
                }
                TpmEo::SignedGE => {
                    signed_compare(&operand_a[..operand_b_len], cmd.operand_b.get_buffer())
                        != core::cmp::Ordering::Less
                }
                TpmEo::UnsignedGE => {
                    unsigned_compare(&operand_a[..operand_b_len], cmd.operand_b.get_buffer())
                        != core::cmp::Ordering::Less
                }
                TpmEo::SignedLE => {
                    signed_compare(&operand_a[..operand_b_len], cmd.operand_b.get_buffer())
                        != core::cmp::Ordering::Greater
                }
                TpmEo::UnsignedLE => {
                    unsigned_compare(&operand_a[..operand_b_len], cmd.operand_b.get_buffer())
                        != core::cmp::Ordering::Greater
                }
                TpmEo::BitSet => {
                    let mut valid = true;
                    for (a, b) in operand_a[..operand_b_len]
                        .iter()
                        .zip(cmd.operand_b.get_buffer().iter())
                    {
                        if (a & b) != *b {
                            valid = false;
                            break;
                        }
                    }
                    valid
                }
                TpmEo::BitClear => {
                    let mut valid = true;
                    for (a, b) in operand_a[..operand_b_len]
                        .iter()
                        .zip(cmd.operand_b.get_buffer().iter())
                    {
                        if (a & b) != 0 {
                            valid = false;
                            break;
                        }
                    }
                    valid
                }
            };

            if !is_valid {
                return Err(TpmRc::POLICY);
            }
        }

        // Compute args = H_policyAlg(operandB.buffer || offset || operation)
        let offset_bytes = cmd.offset.to_be_bytes();
        let operation_bytes = u16::from(cmd.operation).to_be_bytes();
        let (args, args_len) = self.compute_hash(
            auth_hash,
            &[cmd.operand_b.get_buffer(), &offset_bytes, &operation_bytes],
        )?;

        // Compute new policy digest
        let nv_name = self.context.handle_name(self.global_state, nv_index.0);
        let (new_digest, new_digest_len) = self.compute_hash(
            auth_hash,
            &[
                &policy_digest[..policy_digest_len],
                &(TpmCc::PolicyNV.code()).to_be_bytes(),
                &args[..args_len],
                nv_name.get_buffer(),
            ],
        )?;

        // 4. Update session state
        {
            let session_state = self
                .global_state
                .session_mut(policy_session)
                .ok_or(TpmRc::HANDLE.with(Position::handle(3)))?;
            session_state.policy_digest[..new_digest_len]
                .copy_from_slice(&new_digest[..new_digest_len]);
            session_state.policy_digest_len = new_digest_len;
        }

        // 5. Write response
        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }
}

fn unsigned_compare(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    a.cmp(b)
}

fn signed_compare(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    if a.is_empty() || b.is_empty() {
        return unsigned_compare(a, b);
    }
    let sign_a = a[0] & 0x80;
    let sign_b = b[0] & 0x80;
    if sign_a != sign_b {
        if sign_a != 0 {
            core::cmp::Ordering::Less
        } else {
            core::cmp::Ordering::Greater
        }
    } else {
        unsigned_compare(a, b)
    }
}

/// Common read access checks for an NV Index, as C `NvReadAccessChecks` (NV_spt.c).
///
/// - A read-locked index cannot be read (`TPM_RC_NV_LOCKED`).
/// - `TPM_RH_OWNER` requires `TPMA_NV_OWNERREAD` and `TPM_RH_PLATFORM` requires `TPMA_NV_PPREAD`;
///   any other `auth_handle` must be the index itself (whose `AUTHREAD`/`POLICYREAD` requirement
///   was enforced during session authorization), otherwise `TPM_RC_NV_AUTHORIZATION`.
/// - An index that has not been written cannot be read (`TPM_RC_NV_UNINITIALIZED`); checked last.
pub(crate) fn nv_read_access_checks(
    auth_handle: u32,
    nv_index: u32,
    attributes: TpmaNv,
) -> Result<(), TpmRc> {
    if attributes.contains(TpmaNv::READLOCKED) {
        return Err(TpmRc::NV_LOCKED);
    }
    if auth_handle == Handle::RH_OWNER.0 {
        if !attributes.contains(TpmaNv::OWNERREAD) {
            return Err(TpmRc::NV_AUTHORIZATION);
        }
    } else if auth_handle == Handle::RH_PLATFORM.0 {
        if !attributes.contains(TpmaNv::PPREAD) {
            return Err(TpmRc::NV_AUTHORIZATION);
        }
    } else if auth_handle != nv_index {
        return Err(TpmRc::NV_AUTHORIZATION);
    }
    if !attributes.contains(TpmaNv::WRITTEN) {
        return Err(TpmRc::NV_UNINITIALIZED);
    }
    Ok(())
}
