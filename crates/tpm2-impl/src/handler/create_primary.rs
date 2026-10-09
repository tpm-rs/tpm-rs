use super::{KeyDerivationArgs, TransientObject};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
use tpm2::Handle;
use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles, CreatePrimaryRespHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Alg, Tpm2bDigest, Tpm2bName, TpmaLocality, TpmsCreationData, TpmtTkCreation};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::CreatePrimary] (`0x131`) command.
    ///
    /// # Description
    /// This command creates a Primary Object (a key or data object at the root of a hierarchy)
    /// from the primary seed of the specified hierarchy (Owner, Endorsement, Platform, or Null) and loads it.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 24.1 (TPM2_CreatePrimary).
    ///
    /// # Relationships
    /// - Creates a root key for a hierarchy. Child keys can then be created under it using [TpmCc::Create](create.rs)
    ///   or [TpmCc::CreateLoaded](create_loaded.rs).
    /// - The key is created deterministically based on the hierarchy's primary seed and the unique parameters in the public template.
    /// - If the primary seed is changed (e.g. by running [TpmCc::Clear](clear.rs)),
    ///   subsequent calls to [TpmCc::CreatePrimary] with the same template will produce a different key.
    pub fn create_primary(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<CreatePrimaryHandles>()?;
        let primary_handle = handles.primary_handle;

        if primary_handle.0 != Handle::RH_OWNER.0
            && primary_handle.0 != Handle::RH_ENDORSEMENT.0
            && primary_handle.0 != Handle::RH_PLATFORM.0
            && primary_handle.0 != Handle::RH_NULL.0
        {
            return Err(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let cmd = request.try_unmarshal::<CreatePrimary>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // C `CreatePrimary.c`: `FindEmptyObjectSlot` is the first check of the action code
        // (`TPM_RC_OBJECT_MEMORY` takes precedence over template/attribute errors). The
        // command never touches NV, so it does not clear the orderly state.
        let (index, handle) = self.global_state.find_empty_transient_slot(true)?;

        let in_sensitive_struct = cmd
            .in_sensitive
            .to_struct()
            .map_err(|e| e.in_parameter(1).to_rc())?;
        let raw_in_public_struct = cmd
            .in_public
            .to_struct()
            .map_err(|e| e.in_parameter(2).to_rc())?;
        let mut _in_public_struct = crate::owned::OwnedPublic::from(raw_in_public_struct);

        self.validate_create_loaded_parameters(
            &_in_public_struct.as_tpmt(),
            &in_sensitive_struct,
            primary_handle.0,
            primary_handle.0,
            None,
            false,
            None,
        )?;

        // 1. Resolve parent seed value and length
        let mut parent_seed_val = [0u8; 64];
        let parent_seed_len =
            self.resolve_primary_parent_seed(primary_handle, &mut parent_seed_val);

        let name_alg = _in_public_struct
            .name_alg
            .ok_or(TpmRc::HASH.with(Position::parameter(2)))?;

        // 2. Derive object seed, private key, and update public key template unique area
        let fallback_sensitive_data = if (_in_public_struct.object_attributes.0
            & tpm2::TpmaObject::SENSITIVE_DATA_ORIGIN.0)
            == 0
        {
            Some(in_sensitive_struct.data.get_buffer())
        } else {
            None
        };
        let mut obj_seed = [0u8; 64];
        let obj_seed_len = if parent_seed_len > 0 {
            self.derive_primary_object_seed(
                &parent_seed_val[..parent_seed_len],
                &_in_public_struct.as_tpmt(),
                in_sensitive_struct.data.get_buffer(),
                &mut obj_seed,
            )?
        } else {
            0
        };
        let gen_seed_arg = (obj_seed_len > 0).then_some(&obj_seed[..obj_seed_len]);
        let mut actual_private_key = [0u8; 1536];
        let actual_private_key_len = self.generate_key_and_unique(
            name_alg,
            &mut _in_public_struct.parms_and_id,
            KeyDerivationArgs {
                gen_seed: gen_seed_arg,
                obj_seed: gen_seed_arg.unwrap_or(&[]),
                get_random_fallback: fallback_sensitive_data.is_none(),
                fallback_sensitive_data,
            },
            &mut actual_private_key,
        )?;
        let (stored_seed, stored_seed_len) = TransientObject::seed_from_bytes(
            Self::object_seed_value(&_in_public_struct.as_tpmt(), &obj_seed[..obj_seed_len]),
        );

        let mut pub_buf = [0u8; tpm2::TpmtPublic::MAX_SIZE];
        let pub_len = _in_public_struct.marshal(&mut pub_buf);
        let name = self.compute_name(_in_public_struct.name_alg, &pub_buf[..pub_len])?;

        let out_public = _in_public_struct.as_tpm2b();

        let resp_handles = CreatePrimaryRespHandles {
            object_handle: Handle(handle),
        };
        let primary_handle_bytes = primary_handle.0.to_be_bytes();
        let parent_name =
            Tpm2bName::from_bytes(&primary_handle_bytes).map_err(|_| TpmRc::FAILURE)?;
        let parent_qualified_name = parent_name;

        let pcr_digest = self.compute_pcr_digest(
            &cmd.creation_pcr,
            _in_public_struct.name_alg.ok_or(TpmRc::HASH.to_rc())?,
        )?;

        let creation_data_struct = TpmsCreationData {
            // C `FillInCreationData`: the reported selection is the filtered one.
            pcr_select: self.filter_pcr_selection(&cmd.creation_pcr),
            pcr_digest: pcr_digest.as_tpm2b(),
            locality: TpmaLocality(if self.global_state.locality <= 4 {
                1 << self.global_state.locality
            } else {
                self.global_state.locality
            }),
            parent_name_alg: Alg::NULL,
            parent_name,
            parent_qualified_name,
            outside_info: cmd.outside_info,
        };

        let mut cd_buf = [0u8; TpmsCreationData::MAX_SIZE];
        let cd_len = creation_data_struct.marshal(&mut cd_buf);
        let creation_data = tpm2::Tpm2b(creation_data_struct);

        let (creation_hash_bytes, creation_hash_len) = self.compute_hash(
            _in_public_struct.name_alg.ok_or(TpmRc::HASH.to_rc())?,
            &[&cd_buf[..cd_len]],
        )?;

        let creation_hash = Tpm2bDigest::from_bytes(&creation_hash_bytes[..creation_hash_len])
            .map_err(|_| TpmRc::FAILURE)?;

        let computed_digest =
            self.compute_creation_ticket(primary_handle.0, &name, &creation_hash)?;
        let creation_ticket = TpmtTkCreation::Creation(
            primary_handle,
            Tpm2bDigest::from_bytes(&computed_digest).unwrap(),
        );

        let rsp = responses::CreatePrimary {
            out_public,
            creation_data,
            creation_hash,
            creation_ticket,
            name: name.as_tpm2b(),
        };

        let response = request.into_response();
        self.write_response_all(
            response,
            &resp_handles,
            &rsp,
            &session_responses[..num_sessions],
        )?;

        let mut hierarchy_name = [0u8; 4];
        hierarchy_name.copy_from_slice(&primary_handle.0.to_be_bytes());
        let qualified_name = self.compute_qualified_name(
            _in_public_struct.name_alg,
            &hierarchy_name,
            name.get_buffer(),
        )?;

        self.global_state.transient_parents[index] = Some(primary_handle.0);
        self.global_state.transient_objects[index] = Some(TransientObject {
            handle,
            seed: stored_seed,
            seed_len: stored_seed_len,
            external: false,
            public_only: false,
            name,
            auth: crate::owned::OwnedAuth::from(in_sensitive_struct.user_auth),
            public: _in_public_struct,
            private: actual_private_key,
            private_len: actual_private_key_len,
            qualified_name,
            hierarchy: primary_handle.0,
            st_clear: false,
        });

        Ok(())
    }

    /// Resolves the storage primary seed values forOwner, Platform, or Endorsement hierarchies.
    fn resolve_primary_parent_seed(
        &self,
        primary_handle: Handle,
        parent_seed_val: &mut [u8; 64],
    ) -> usize {
        if primary_handle.0 == Handle::RH_PLATFORM.0 {
            let seed_len = self.global_state.pp_seed_size as usize;
            parent_seed_val[..seed_len].copy_from_slice(&self.global_state.pp_seed[..seed_len]);
            seed_len
        } else if primary_handle.0 == Handle::RH_OWNER.0 {
            let seed_len = self.global_state.sp_seed_size as usize;
            parent_seed_val[..seed_len].copy_from_slice(&self.global_state.sp_seed[..seed_len]);
            seed_len
        } else if primary_handle.0 == Handle::RH_ENDORSEMENT.0 {
            let seed_len = self.global_state.ep_seed_size as usize;
            parent_seed_val[..seed_len].copy_from_slice(&self.global_state.ep_seed[..seed_len]);
            seed_len
        } else if primary_handle.0 == Handle::RH_NULL.0 {
            let seed_len = self.global_state.null_seed_size as usize;
            parent_seed_val[..seed_len].copy_from_slice(&self.global_state.null_seed[..seed_len]);
            seed_len
        } else {
            0
        }
    }
}
