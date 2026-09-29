use tpm2::Marshal;

use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::commands::{PolicyCounterTimer, PolicyCounterTimerHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{TpmCc, TpmEo, TpmSe};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::PolicyCounterTimer] (`0x16D`) command.
    ///
    /// # Description
    /// This command is used to cause conditional gating of a policy based on the contents of the
    /// `TPMS_TIME_INFO` structure (`time`, `clock`, `resetCount`, `restartCount`, `safe`).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 23.10 (TPM2_PolicyCounterTimer).
    pub fn policy_counter_timer(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<PolicyCounterTimerHandles>()?;
        let policy_session = handles.policy_session.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<PolicyCounterTimer>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Validate session expiration
        self.validate_policy_session(policy_session, Position::handle(1))?;

        // Retrieve policy session state details
        let (
            auth_hash,
            policy_digest,
            policy_digest_len,
            session_type,
            start_time,
            current_timeout,
        ) = {
            let session_state = self
                .global_state
                .session(policy_session)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;
            if session_state.session_type != TpmSe::Policy
                && session_state.session_type != TpmSe::Trial
            {
                return Err(TpmRc::HANDLE.with(Position::handle(1)));
            }
            (
                session_state.auth_hash,
                session_state.policy_digest,
                session_state.policy_digest_len,
                session_state.session_type,
                session_state.start_time,
                session_state.timeout,
            )
        };

        // Marshal TPMS_TIME_INFO structure
        let time_info = self.get_time_info();
        let mut time_info_buf = [0u8; tpm2::TpmsTimeInfo::MAX_SIZE];
        let _ = time_info.marshal(&mut time_info_buf);
        // Canonical TpmsTimeInfo size is exactly 25 bytes.
        let info_data_size = 25usize;

        // Perform offset and bounds checks per TCG Part 3 Section 23.10 and C reference implementation.
        if cmd.offset as usize > info_data_size {
            return Err(TpmRc::VALUE.with(Position::parameter(2)));
        }
        let operand_b_len = cmd.operand_b.get_size() as usize;
        if (cmd.offset as usize) + operand_b_len > info_data_size {
            return Err(TpmRc::RANGE.to_rc());
        }

        if session_type != TpmSe::Trial {
            let operand_a =
                &time_info_buf[cmd.offset as usize..(cmd.offset as usize + operand_b_len)];
            let operand_b = cmd.operand_b.get_buffer();

            let is_valid = match cmd.operation {
                TpmEo::Eq => unsigned_compare(operand_a, operand_b) == core::cmp::Ordering::Equal,
                TpmEo::Neq => unsigned_compare(operand_a, operand_b) != core::cmp::Ordering::Equal,
                TpmEo::SignedGT => {
                    signed_compare(operand_a, operand_b) == core::cmp::Ordering::Greater
                }
                TpmEo::UnsignedGT => {
                    unsigned_compare(operand_a, operand_b) == core::cmp::Ordering::Greater
                }
                TpmEo::SignedLT => {
                    signed_compare(operand_a, operand_b) == core::cmp::Ordering::Less
                }
                TpmEo::UnsignedLT => {
                    if cmd.offset == 0 && operand_b_len == 8 {
                        // 1.83 special case: expiration check against Time
                        let mut limit_bytes = [0u8; 8];
                        limit_bytes.copy_from_slice(operand_b);
                        let limit_seconds = u64::from_be_bytes(limit_bytes);
                        let limit = limit_seconds
                            .saturating_mul(1000)
                            .saturating_add(start_time);
                        if limit < time_info.time {
                            return Err(TpmRc::EXPIRED.to_rc());
                        }
                        true
                    } else {
                        unsigned_compare(operand_a, operand_b) == core::cmp::Ordering::Less
                    }
                }
                TpmEo::SignedGE => {
                    signed_compare(operand_a, operand_b) != core::cmp::Ordering::Less
                }
                TpmEo::UnsignedGE => {
                    unsigned_compare(operand_a, operand_b) != core::cmp::Ordering::Less
                }
                TpmEo::SignedLE => {
                    signed_compare(operand_a, operand_b) != core::cmp::Ordering::Greater
                }
                TpmEo::UnsignedLE => {
                    unsigned_compare(operand_a, operand_b) != core::cmp::Ordering::Greater
                }
                TpmEo::BitSet => {
                    let mut valid = true;
                    for (a, b) in operand_a.iter().zip(operand_b.iter()) {
                        if (a & b) != *b {
                            valid = false;
                            break;
                        }
                    }
                    valid
                }
                TpmEo::BitClear => {
                    let mut valid = true;
                    for (a, b) in operand_a.iter().zip(operand_b.iter()) {
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

        // Compute arg_hash = H(operandB.buffer || offset || operation)
        let offset_bytes = cmd.offset.to_be_bytes();
        let operation_bytes = u16::from(cmd.operation).to_be_bytes();

        let (arg_hash, arg_hash_len) = self.compute_hash(
            auth_hash,
            &[cmd.operand_b.get_buffer(), &offset_bytes, &operation_bytes],
        )?;

        // Compute new policy digest
        // policyDigest_new = H(policyDigest_old || TPM_CC_PolicyCounterTimer || arg_hash)
        let (new_digest, new_digest_len) = self.compute_hash(
            auth_hash,
            &[
                &policy_digest[..policy_digest_len],
                &(TpmCc::PolicyCounterTimer.code()).to_be_bytes(),
                &arg_hash[..arg_hash_len],
            ],
        )?;

        // Update session state
        {
            let session_state = self
                .global_state
                .session_mut(policy_session)
                .ok_or(TpmRc::VALUE.with(Position::handle(1)))?;
            session_state.policy_digest[..new_digest_len]
                .copy_from_slice(&new_digest[..new_digest_len]);
            session_state.policy_digest_len = new_digest_len;

            if session_type != TpmSe::Trial
                && cmd.operation == TpmEo::UnsignedLT
                && cmd.offset == 0
                && operand_b_len == 8
            {
                let mut limit_bytes = [0u8; 8];
                limit_bytes.copy_from_slice(cmd.operand_b.get_buffer());
                let limit_seconds = u64::from_be_bytes(limit_bytes);
                let limit = limit_seconds
                    .saturating_mul(1000)
                    .saturating_add(start_time);
                if current_timeout == 0 || limit < current_timeout {
                    session_state.timeout = limit;
                }
            }
        }

        // Write response
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
