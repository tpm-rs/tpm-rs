use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{HierarchyControl, HierarchyControlHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::HierarchyControl] (`0x121`) command.
    ///
    /// # Description
    /// This command enables or disables the use of a hierarchy and/or its associated NV storage.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 24.2 (TPM2_HierarchyControl).
    pub fn hierarchy_control(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<HierarchyControlHandles>()?;
        let auth_handle = handles.auth_handle.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        if auth_handle != Handle::RH_PLATFORM.0
            && auth_handle != Handle::RH_OWNER.0
            && auth_handle != Handle::RH_ENDORSEMENT.0
        {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let cmd = request.try_unmarshal::<HierarchyControl>()?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let enable = cmd.enable.0;
        let state = cmd.state;

        if enable == Handle::RH_ENDORSEMENT.0 {
            if !state {
                if auth_handle != Handle::RH_PLATFORM.0 && auth_handle != Handle::RH_ENDORSEMENT.0 {
                    return Err(TpmRc::AUTH_TYPE);
                }
            } else if auth_handle != Handle::RH_PLATFORM.0 {
                return Err(TpmRc::AUTH_TYPE);
            }
            self.global_state.eh_enable = state;
        } else if enable == Handle::RH_OWNER.0 {
            if !state {
                if auth_handle != Handle::RH_OWNER.0 && auth_handle != Handle::RH_PLATFORM.0 {
                    return Err(TpmRc::AUTH_TYPE);
                }
            } else if auth_handle != Handle::RH_PLATFORM.0 {
                return Err(TpmRc::AUTH_TYPE);
            }
            self.global_state.sh_enable = state;
        } else if enable == Handle::RH_PLATFORM.0 {
            if auth_handle != Handle::RH_PLATFORM.0 {
                return Err(TpmRc::AUTH_TYPE);
            }
            if state && !self.global_state.ph_enable {
                return Err(TpmRc::AUTH_TYPE);
            }
            self.global_state.ph_enable = state;
        } else if enable == Handle::RH_PLATFORM_NV.0 {
            if auth_handle != Handle::RH_PLATFORM.0 {
                return Err(TpmRc::AUTH_TYPE);
            }
            if state && !self.global_state.ph_enable_nv {
                return Err(TpmRc::AUTH_TYPE);
            }
            self.global_state.ph_enable_nv = state;
        } else {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }

        if !state
            && (enable == Handle::RH_ENDORSEMENT.0
                || enable == Handle::RH_OWNER.0
                || enable == Handle::RH_PLATFORM.0)
        {
            for slot in self.global_state.transient_objects.iter_mut() {
                if let Some(obj) = slot
                    && obj.hierarchy == enable
                {
                    *slot = None;
                }
            }
        }

        self.nv_clear_orderly()?;
        self.global_state.state_saved = false;
        self.context.save_hierarchy_auths(self.global_state);

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        Ok(())
    }
}
