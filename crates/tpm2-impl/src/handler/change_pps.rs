use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{ChangePPS, ChangePPSHandles};
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

        let handles = request.try_unmarshal::<ChangePPSHandles>()?;
        let auth_handle = handles.auth_handle.0;

        if auth_handle != Handle::RH_PLATFORM.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal::<ChangePPS>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Check if NV is available (`RETURN_IF_NV_IS_NOT_AVAILABLE`, `ChangePPS.c`).
        self.return_if_nv_is_not_available()?;

        let mut new_pp_seed = [0u8; 64];
        let mut new_ph_proof = [0u8; 64];

        self.context
            .platform
            .rng
            .get_random(&mut new_pp_seed)
            .map_err(|_| TpmRc::FAILURE)?;
        self.context
            .platform
            .rng
            .get_random(&mut new_ph_proof)
            .map_err(|_| TpmRc::FAILURE)?;

        self.nv_clear_orderly()?;

        // Update state
        self.global_state.pp_seed.copy_from_slice(&new_pp_seed);
        self.global_state.pp_seed_size = 64;

        self.global_state.ph_proof.copy_from_slice(&new_ph_proof);
        self.global_state.ph_proof_size = 64;

        self.global_state.platform_policy = crate::owned::OwnedDigest::default();
        self.global_state.platform_alg = None;
        self.global_state.pcr_policy_alg = None;
        self.global_state.pcr_policy = crate::owned::OwnedDigest::default();

        // Flush loaded objects in platform hierarchy
        for (i, slot) in self.global_state.transient_objects.iter_mut().enumerate() {
            if let Some(obj) = slot
                && obj.hierarchy == Handle::RH_PLATFORM.0
            {
                *slot = None;
                self.global_state.transient_parents[i] = None;
            }
        }

        // Flush platform evict objects stored in NV (`NvFlushHierarchy(TPM_RH_PLATFORM)`; NV
        // indices are not affected).
        self.nv_flush_hierarchy(Handle::RH_PLATFORM.0)?;

        self.context.save_hierarchy_auths(self.global_state);

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        Ok(())
    }
}
