use tpm2::TpmSu;
use tpm2::commands::{Shutdown, Startup};
use tpm2::crypto::Random;
use tpm2::errors::{Position, TpmRc};

use crate::handler::unmarshal_command;
use crate::platform::Platform;
use crate::state::{ClearData, Nv, Phase, ResetData, State};

/// The three `TPM2_Startup` transitions (Part 1, Section 12).
enum StartupKind {
    Reset { next_total_reset_count: u64 },
    Restart,
    Resume,
}

/// Handles `TPM2_Startup` (Part 3, Section 9.3).
///
/// Implicitly assumes locality 0 until platform locality tracking is added.
#[doc(alias = "TPM2_Startup")]
pub(crate) fn startup<P: Platform>(state: &mut State<P>, params: &[u8]) -> Result<usize, TpmRc> {
    let cmd = unmarshal_command::<Startup>(params)?;

    let prev_orderly = state.nv.persistent.orderly_state;
    let kind = match (prev_orderly, cmd.startup_type) {
        (Some(TpmSu::State), TpmSu::State) => StartupKind::Resume,
        (Some(TpmSu::State), TpmSu::Clear) => StartupKind::Restart,
        (None | Some(TpmSu::Clear), TpmSu::Clear) => {
            // Leave `total_reset_count` untouched on overflow so subsequent
            // resets also enter failure mode (matching the TCG reference).
            let next_total_reset_count = state
                .nv
                .persistent
                .total_reset_count
                .checked_add(1)
                .ok_or(TpmRc::FAILURE)?;
            StartupKind::Reset {
                next_total_reset_count,
            }
        }
        (None | Some(TpmSu::Clear), TpmSu::State) => {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }
    };

    // Instantiate the RNG before committing any state transitions so that a
    // crypto failure leaves the counters and `orderly_state` unchanged.
    let rng = <P::Crypto as Random>::from_entropy().map_err(|_| TpmRc::FAILURE)?;

    match kind {
        StartupKind::Reset {
            next_total_reset_count,
        } => {
            state.nv.reset = ResetData::default();
            state.nv.clear = ClearData::default();
            state.nv.persistent.reset_count = state.nv.persistent.reset_count.wrapping_add(1);
            state.nv.persistent.total_reset_count = next_total_reset_count;
        }
        StartupKind::Restart => {
            state.nv.clear = ClearData::default();
            state.nv.reset.clear_count = state.nv.reset.clear_count.wrapping_add(1);
            state.nv.reset.restart_count = state.nv.reset.restart_count.wrapping_add(1);
        }
        StartupKind::Resume => {
            state.nv.reset.restart_count = state.nv.reset.restart_count.wrapping_add(1);
        }
    }

    state.nv.persistent.orderly_state = None;
    state.phase = Phase::Started(rng);
    Ok(0)
}

/// Handles `TPM2_Shutdown` (Part 3, Section 9.4).
///
/// Leaving the TPM in the `Started` phase is required by the specification: a
/// subsequent `TPM2_Startup` without an intervening `_TPM_Init` must still fail
/// with `TPM_RC_INITIALIZE`. Future commands that modify NV/saved state will
/// clear `orderly_state` back to `None`; neither `TPM2_GetRandom` nor
/// `TPM2_StirRandom` clears it in the reference.
#[doc(alias = "TPM2_Shutdown")]
pub(crate) fn shutdown<P: Platform>(nv: &mut Nv<P>, params: &[u8]) -> Result<usize, TpmRc> {
    let cmd = unmarshal_command::<Shutdown>(params)?;
    nv.persistent.orderly_state = Some(cmd.shutdown_type);
    Ok(0)
}
