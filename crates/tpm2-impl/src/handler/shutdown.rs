use crate::Crypto;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::Shutdown;
use tpm2::errors::{Position, TpmRc};

/// Flag bit matching the TCG reference code implementation. It is combined with the orderly
/// state representation in NV storage to indicate that the TPM has not yet received a startup
/// command (`_TPM_Init`).
const PRE_STARTUP_FLAG: u16 = 0x8000;

/// Flag bit matching the TCG reference code implementation. It is combined with the orderly
/// state representation in NV storage to indicate that the startup command was processed at Locality 3.
const STARTUP_LOCALITY_3: u16 = 0x4000;

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
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

        if !self.global_state.nv_available {
            return Err(TpmRc::NV_UNINITIALIZED);
        }

        let cmd = request.try_unmarshal_command::<Shutdown>([])?;
        let shutdown_type = crate::util::tpm_su_value(cmd.shutdown_type);

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        if shutdown_type != 0x0000 && shutdown_type != 0x0001 {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }

        // If PCR bank has been reconfigured, a CLEAR state save is required
        if self.global_state.pcr_reconfig && shutdown_type == 0x0001 {
            return Err(TpmRc::TYPE.with(Position::parameter(1)));
        }

        self.global_state.orderly_state = shutdown_type;
        self.global_state.da_used = false;
        if shutdown_type == 0x0001 {
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

#[cfg(test)]
mod tests {
    use crate::GlobalState;
    use crate::test_support::{TestEngine, execute, with_test_engine};
    use alloc::vec::Vec;
    use tpm2::TpmCc;
    use tpm2::errors::{Position, TpmRc};

    fn startup(tpm: &mut TestEngine<'_>, gs: &mut GlobalState) {
        assert_eq!(execute(tpm, gs, TpmCc::Startup, &[0, 0]).0, 0);
    }

    #[test]
    fn shutdown_records_orderly_state() {
        with_test_engine(|tpm, gs| {
            startup(tpm, gs);
            assert_eq!(execute(tpm, gs, TpmCc::Shutdown, &[0, 0]), (0, Vec::new()));
            assert_eq!(gs.orderly_state, 0x0000);
            assert!(gs.state_saved);

            assert_eq!(execute(tpm, gs, TpmCc::Shutdown, &[0, 1]), (0, Vec::new()));
            assert_eq!(gs.orderly_state, 0x0001);
        });
    }

    #[test]
    fn shutdown_rejects_invalid_type() {
        with_test_engine(|tpm, gs| {
            startup(tpm, gs);
            let (rc, _) = execute(tpm, gs, TpmCc::Shutdown, &[0, 2]);
            assert_eq!(rc, TpmRc::VALUE.with(Position::parameter(1)).get());
        });
    }

    #[test]
    fn shutdown_requires_nv() {
        with_test_engine(|tpm, gs| {
            startup(tpm, gs);
            gs.nv_available = false;
            let (rc, _) = execute(tpm, gs, TpmCc::Shutdown, &[0, 0]);
            assert_eq!(rc, TpmRc::NV_UNINITIALIZED.get());
        });
    }

    #[test]
    fn shutdown_state_after_pcr_reconfig_is_rejected() {
        with_test_engine(|tpm, gs| {
            startup(tpm, gs);
            gs.pcr_reconfig = true;
            let (rc, _) = execute(tpm, gs, TpmCc::Shutdown, &[0, 1]);
            assert_eq!(rc, TpmRc::TYPE.with(Position::parameter(1)).get());
        });
    }
}
