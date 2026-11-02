use crate::act::act_index;
use crate::handle_checks::{Tpmi, check};
use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::ACTSetTimeout;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};

/// `SU_DA_USED_VALUE`: the orderly states below it are orderly (`NV_IS_ORDERLY`).
const SU_DA_USED_VALUE: u16 = 0xFFFE;

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::ACTSetTimeout] (`0x198`) command.
    ///
    /// # Description
    /// Sets the time remaining before an Authenticated Countdown Timer expires: the ACT Timeout
    /// becomes `startTimeout` (seconds) at the next once-per-second tick (see [`crate::act`]).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, TPM2_ACT_SetTimeout.
    ///
    /// # Behavior
    /// - `startTimeout` `0xFFFFFFFF` "will clear *signaled* and stop the counting" when the ACT
    ///   has signaled. The specification is silent on it otherwise; as the TCG reference, it is
    ///   then `TPM_RC_VALUE + RC_P1` ("attempt to disable signaling from an ACT that has not
    ///   expired").
    /// - The update clears the orderly state, so an orderly TPM needs NV
    ///   (`TPM_RC_NV_UNAVAILABLE`).
    /// - An update that is still waiting for the tick is `TPM_RC_RETRY` (the reference's
    ///   `_plat__ACT_UpdateCounter()` "returns 'false' if the update is not accepted. If this
    ///   occurs, then TPM_RC_RETRY should be sent to the caller so that they can retry the
    ///   operation later").
    /// - On success the ACT has been written since `TPM2_Startup()` (so
    ///   `TPM2_Shutdown(TPM_SU_STATE)` saves its timeout unhalved) and "*preserveSignaled* will
    ///   be CLEAR".
    pub fn act_set_timeout(
        &mut self,
        mut request: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let handles = request.try_unmarshal_handles::<ACTSetTimeout>()?;
        let [act_handle] = handles;
        check(act_handle, Tpmi::RhAct, Position::handle(1))?;
        // The engine has rejected the ACTs that are not implemented (their load status).
        let index = act_index(act_handle.0).ok_or(TpmRc::VALUE.with(Position::handle(1)))?;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        if num_sessions == 0 {
            return Err(TpmRc::AUTH_MISSING);
        }

        let cmd = request.try_unmarshal_command::<ACTSetTimeout>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let state = &mut self.context.state;
        if cmd.start_timeout == u32::MAX && !state.act.counters[index].signaled {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }
        // `if(NV_IS_ORDERLY) RETURN_IF_NV_IS_NOT_AVAILABLE;`: the orderly state is cleared below.
        if state.orderly_state < SU_DA_USED_VALUE && !state.nv_available {
            return Err(TpmRc::NV_UNAVAILABLE);
        }
        if !state.act.counters[index].update(cmd.start_timeout) {
            return Err(TpmRc::RETRY);
        }
        state.act.record_set_timeout(index);
        state.clear_orderly = true;
        state.state_saved = false;

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        Ok(())
    }
}
