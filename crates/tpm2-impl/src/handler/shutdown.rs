use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::Shutdown;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};

/// Flag bit matching the TCG reference code implementation. It is combined with the orderly
/// state representation in NV storage to indicate that the TPM has not yet received a startup
/// command (`_TPM_Init`).
const PRE_STARTUP_FLAG: u16 = 0x8000;

/// Flag bit matching the TCG reference code implementation. It is combined with the orderly
/// state representation in NV storage to indicate that the startup command was processed at Locality 3.
const STARTUP_LOCALITY_3: u16 = 0x4000;

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::Shutdown] (`0x145`) command.
    ///
    /// # Description
    /// This command prepares the TPM for a planned power shutdown. It configures the orderly state of the TPM
    /// (either `SU_CLEAR` or `SU_STATE`).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 9.4 (TPM2_Shutdown).
    ///
    /// # Relationships
    /// - Followed by a platform reset and [TpmCc::Startup](startup.rs) to resume operation.
    /// - If `shutdown_type` is `SU_STATE`, the TPM saves volatile states (like loaded session contexts)
    ///   so that they can be restored upon the next startup with `SU_STATE`.
    pub fn shutdown(&mut self, request_response: RequestThenResponse<'_, '_>) -> Result<(), TpmRc> {
        let mut request = request_response;

        // Parameters are unmarshaled (and trailing bytes rejected) before the command action runs.
        let cmd = request.try_unmarshal::<Shutdown>()?;
        let shutdown_type = cmd.shutdown_type as u16;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // The command needs NV update (`RETURN_IF_NV_IS_NOT_AVAILABLE`, `Shutdown.c`).
        self.return_if_nv_is_not_available()?;

        if shutdown_type != 0x0000 && shutdown_type != 0x0001 {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }

        // If PCR bank has been reconfigured, a CLEAR state save is required
        if self.global_state.pcr_reconfig && shutdown_type == 0x0001 {
            return Err(TpmRc::TYPE.with(Position::parameter(1))); // TPM_RCS_TYPE + RC_Shutdown_shutdownType equivalent
        }

        self.global_state.orderly_state = shutdown_type;
        self.global_state.da_used = false;
        if shutdown_type == 0x0001 {
            // Save the STATE_RESET and STATE_CLEAR data for a subsequent TPM Restart / Resume.
            // If it cannot be saved, the next TPM2_Startup(STATE) reports
            // TPM_RC_NV_UNINITIALIZED and Startup(CLEAR) performs a TPM Reset.
            let _ = self.context.save_state_data(self.global_state);
            if self.global_state.drtm_pre_startup {
                self.global_state.orderly_state = 0x0001 | PRE_STARTUP_FLAG;
            } else if self.global_state.startup_locality_3 {
                self.global_state.orderly_state = 0x0001 | STARTUP_LOCALITY_3;
            }
        }

        self.nv_sync_persistent_orderly_state()?;
        self.nv_sync_persistent_drbg_state()?;
        self.nv_sync_persistent_da_timers()?;
        self.context.save_hierarchy_auths(self.global_state);
        self.global_state.state_saved = true;

        let _response = request.into_response();
        Ok(())
    }
}
