use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::TpmiAlgHash;
use tpm2::commands::{HierarchyChangeAuth, HierarchyChangeAuthHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::HierarchyChangeAuth] (`0x129`) command.
    ///
    /// # Description
    /// This command allows changing the authorization value of Owner, Endorsement, Platform, or Lockout hierarchies.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 24.3 (TPM2_HierarchyChangeAuth).
    ///
    /// # Relationships
    /// - Modifies the authorization requirements for commands that operate under the target hierarchy (such as [TpmCc::CreatePrimary](create_primary.rs)
    ///   or [TpmCc::Clear](clear.rs)).
    /// - The new authorization value is saved persistently on the TPM.
    pub fn hierarchy_change_auth(
        &mut self,
        mut request: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let handles = request.try_unmarshal::<HierarchyChangeAuthHandles>()?;
        let auth_handle = handles.auth_handle.0;
        if auth_handle != Handle::RH_OWNER.0
            && auth_handle != Handle::RH_ENDORSEMENT.0
            && auth_handle != Handle::RH_PLATFORM.0
            && auth_handle != Handle::RH_LOCKOUT.0
        {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        if num_sessions == 0 {
            return Err(TpmRc::AUTH_MISSING);
        }
        let cmd = request.try_unmarshal::<HierarchyChangeAuth>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // The command needs NV update for every hierarchy (`RETURN_IF_NV_IS_NOT_AVAILABLE`).
        self.return_if_nv_is_not_available()?;

        let new_auth_slice = cmd.new_auth.get_buffer();
        let new_auth_stripped = crate::util::strip_trailing_zeros(new_auth_slice);
        if new_auth_stripped.len() > TpmiAlgHash::Sha256.digest_size() {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }

        let new_auth = crate::owned::OwnedAuth::from_bytes(new_auth_stripped)
            .map_err(|_| TpmRc::SIZE.with(Position::parameter(1)))?;

        if auth_handle == Handle::RH_OWNER.0 {
            self.global_state.owner_auth = new_auth;
        } else if auth_handle == Handle::RH_ENDORSEMENT.0 {
            self.global_state.endorsement_auth = new_auth;
        } else if auth_handle == Handle::RH_PLATFORM.0 {
            self.nv_clear_orderly()?;
            self.global_state.platform_auth = new_auth;
        } else if auth_handle == Handle::RH_LOCKOUT.0 {
            self.global_state.lockout_auth = new_auth;
        }

        self.global_state.state_saved = false;
        self.context.save_hierarchy_auths(self.global_state);

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }
}
