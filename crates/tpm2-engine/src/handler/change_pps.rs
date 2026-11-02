use crate::handle_checks::{Tpmi, check};
use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::ChangePPS;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::ChangePPS] (`0x125`) command.
    ///
    /// # Description
    /// This command replaces the current Platform Primary Seed (PPS) with a new value from the RNG,
    /// invalidating all objects in the Platform hierarchy. It also flushes all platform objects,
    /// clears platform policy, and generates a new `phProof` value.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 24.2 (TPM2_ChangePPS).
    pub fn change_pps(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal_handles::<ChangePPS>()?;
        let [auth_handle] = handles;
        check(auth_handle, Tpmi::RhPlatform, Position::handle(1))?;
        let auth_handle = auth_handle.0;

        if auth_handle != Handle::RH_PLATFORM.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal_command::<ChangePPS>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Check if NV is available (`RETURN_IF_NV_IS_NOT_AVAILABLE`, `ChangePPS.c`).
        self.return_if_nv_is_not_available()?;

        let mut new_pp_seed = [0u8; 64];
        let mut new_ph_proof = [0u8; 64];

        self.context.random_platform(&mut new_pp_seed)?;
        self.context.random_platform(&mut new_ph_proof)?;

        self.nv_clear_orderly()?;

        // Update state
        self.context.state.pp_seed.copy_from_slice(&new_pp_seed);
        self.context.state.pp_seed_size = 64;

        self.context.state.ph_proof.copy_from_slice(&new_ph_proof);
        self.context.state.ph_proof_size = 64;

        self.context.state.platform_policy = crate::owned::OwnedDigest::default();
        self.context.state.platform_alg = None;
        self.context.state.pcr_policy_alg = None;
        self.context.state.pcr_policy = crate::owned::OwnedDigest::default();

        // Flush loaded objects in platform hierarchy
        for (i, slot) in self.context.state.transient_objects.iter_mut().enumerate() {
            if let Some(obj) = slot
                && crate::hierarchy::normalize(obj.hierarchy) == Handle::RH_PLATFORM.0
            {
                *slot = None;
                self.context.state.transient_parents[i] = None;
            }
        }

        // Flush platform evict objects stored in NV (`NvFlushHierarchy(TPM_RH_PLATFORM)`; NV
        // indices are not affected).
        self.nv_flush_hierarchy(Handle::RH_PLATFORM.0)?;

        self.context.save_hierarchy_auths();

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        Ok(())
    }
}
