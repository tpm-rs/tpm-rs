use crate::handler::CommandHandler;
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use tpm2::Handle;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{ChangeEPS, ChangeEPSHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::ChangeEPS] (`0x124`) command.
    ///
    /// # Description
    /// This command replaces the current Endorsement Primary Seed (EPS) with a new value from the RNG,
    /// invalidating all objects in the Endorsement hierarchy. It also flushes all endorsement objects,
    /// clears endorsement auth and policy, enables endorsement hierarchy, and generates a new `ehProof`.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 24.3 (TPM2_ChangeEPS).
    pub fn change_eps(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<ChangeEPSHandles>()?;
        let auth_handle = handles.auth_handle.0;

        if auth_handle != Handle::RH_PLATFORM.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal::<ChangeEPS>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // The command needs NV update (`RETURN_IF_NV_IS_NOT_AVAILABLE`, `ChangeEPS.c`).
        self.return_if_nv_is_not_available()?;

        let mut new_ep_seed = [0u8; 64];
        let mut new_eh_proof = [0u8; 64];

        self.context
            .platform
            .rng
            .get_random(&mut new_ep_seed)
            .map_err(|_| TpmRc::FAILURE)?;
        self.context
            .platform
            .rng
            .get_random(&mut new_eh_proof)
            .map_err(|_| TpmRc::FAILURE)?;

        self.nv_clear_orderly()?;

        // Update state
        self.global_state.ep_seed.copy_from_slice(&new_ep_seed);
        self.global_state.ep_seed_size = 64;

        self.global_state.eh_proof.copy_from_slice(&new_eh_proof);
        self.global_state.eh_proof_size = 64;

        self.global_state.eh_enable = true;
        self.global_state.endorsement_auth = crate::owned::OwnedAuth::default();
        self.global_state.endorsement_policy = crate::owned::OwnedDigest::default();
        self.global_state.endorsement_alg = None;

        // Flush loaded objects in endorsement hierarchy
        for (i, slot) in self.global_state.transient_objects.iter_mut().enumerate() {
            if let Some(obj) = slot
                && obj.hierarchy == Handle::RH_ENDORSEMENT.0
            {
                *slot = None;
                self.global_state.transient_parents[i] = None;
            }
        }

        // Flush evict objects of the endorsement hierarchy stored in NV (`NvFlushHierarchy`).
        self.nv_flush_hierarchy(Handle::RH_ENDORSEMENT.0)?;

        self.context.save_hierarchy_auths(self.global_state);

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;
        Ok(())
    }
}
