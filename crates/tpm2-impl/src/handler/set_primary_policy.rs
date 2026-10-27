use crate::handle_checks::{Tpmi, check};
use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::SetPrimaryPolicy;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::SetPrimaryPolicy] (`0x12E`) command.
    ///
    /// # Description
    /// This command allows setting of the authorization policy for the lockout (`lockoutPolicy`),
    /// the platform hierarchy (`platformPolicy`), the storage hierarchy (`ownerPolicy`), the
    /// endorsement hierarchy (`endorsementPolicy`) and the implemented Authenticated Countdown
    /// Timers (the ACT-specific `authPolicy`, see [`crate::act`]).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 24.3 (TPM2_SetPrimaryPolicy).
    ///
    /// # Relationships
    /// - Modifies the primary policy digest associated with a primary hierarchy (`authHandle`).
    /// - The modified policy is saved persistently across power cycles and resets (except for platform policy
    ///   which resets to empty upon cold boot).
    pub fn set_primary_policy(
        &mut self,
        mut request: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let handles = request.try_unmarshal_handles::<SetPrimaryPolicy>()?;
        let [auth_handle] = handles;
        check(auth_handle, Tpmi::RhHierarchyPolicy, Position::handle(1))?;
        let auth_handle = auth_handle.0;

        if auth_handle == Handle::RH_OWNER.0 {
            if !self.context.state.sh_enable {
                return Err(TpmRc::HIERARCHY.with(Position::handle(1)));
            }
        } else if auth_handle == Handle::RH_ENDORSEMENT.0 {
            if !self.context.state.eh_enable {
                return Err(TpmRc::HIERARCHY.with(Position::handle(1)));
            }
        } else if auth_handle == Handle::RH_PLATFORM.0 {
            if !self.context.state.ph_enable {
                return Err(TpmRc::HIERARCHY.with(Position::handle(1)));
            }
        } else if auth_handle != Handle::RH_LOCKOUT.0
            && !crate::act::is_implemented_act(auth_handle)
        {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        if num_sessions == 0 {
            return Err(TpmRc::AUTH_MISSING);
        }

        let cmd = request.try_unmarshal_command::<SetPrimaryPolicy>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let expected_size = match cmd.hash_alg {
            None => 0,
            Some(alg) => alg.digest_size(),
        };
        if cmd.auth_policy.get_size() as usize != expected_size {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }

        // Owner/endorsement/lockout policies are NV-persistent and the platform update clears the
        // orderly state, so NV must be available for every hierarchy.
        self.return_if_nv_is_not_available()?;

        let policy = crate::owned::OwnedDigest::from(cmd.auth_policy);
        if auth_handle == Handle::RH_OWNER.0 {
            self.context.state.owner_policy = policy;
            self.context.state.owner_alg = cmd.hash_alg;
        } else if auth_handle == Handle::RH_ENDORSEMENT.0 {
            self.context.state.endorsement_policy = policy;
            self.context.state.endorsement_alg = cmd.hash_alg;
        } else if auth_handle == Handle::RH_PLATFORM.0 {
            self.nv_clear_orderly()?;
            self.context.state.platform_policy = policy;
            self.context.state.platform_alg = cmd.hash_alg;
        } else if auth_handle == Handle::RH_LOCKOUT.0 {
            self.context.state.lockout_policy = policy;
            self.context.state.lockout_alg = cmd.hash_alg;
        } else if let Some(index) = crate::act::act_index(auth_handle) {
            // The ACT policies are orderly data, saved by TPM2_Shutdown(TPM_SU_STATE) and kept by
            // TPM Resume only (Part 1, "Authenticated Countdown Timer (ACT)": "The *authPolicy*
            // of an ACT is initialized to an Empty Policy by TPM Reset or TPM Restart but is
            // preserved during TPM Resume"), so changing one clears the orderly state.
            self.nv_clear_orderly()?;
            self.context.state.act.policies[index] = crate::act::ActPolicy {
                hash_alg: cmd.hash_alg,
                auth_policy: policy,
            };
        }

        self.context.state.state_saved = false;
        self.context.save_hierarchy_auths();

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }
}
