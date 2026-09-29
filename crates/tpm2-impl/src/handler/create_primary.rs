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
use tpm2::crypto::kdf::kdfa;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::TpmRc;
use tpm2::{
    Alg, Tpm2bDigest, Tpm2bName, TpmaLocality, TpmiAlgHash, TpmsCreationData, TpmtTkCreation,
};

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

        self.nv_clear_orderly()?;

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
        )?;

        // 1. Resolve parent seed value and length
        let mut parent_seed_val = [0u8; 64];
        let parent_seed_len =
            self.resolve_primary_parent_seed(primary_handle, &mut parent_seed_val);

        // Copy unique buffer contents to avoid mutable borrow conflicts
        let mut unique_copy = [0u8; tpm2::TpmuPublicId::MAX_SIZE];
        let unique_len = match &_in_public_struct.parms_and_id {
            crate::owned::OwnedPublicParmsAndId::KeyedHash(_, unique) => {
                let b = unique.get_buffer();
                unique_copy[..b.len()].copy_from_slice(b);
                b.len()
            }
            crate::owned::OwnedPublicParmsAndId::Sym(_, unique) => {
                let b = unique.get_buffer();
                unique_copy[..b.len()].copy_from_slice(b);
                b.len()
            }
            crate::owned::OwnedPublicParmsAndId::Rsa(_, unique) => {
                let b = unique.get_buffer();
                unique_copy[..b.len()].copy_from_slice(b);
                b.len()
            }
            crate::owned::OwnedPublicParmsAndId::Ecc(_, point) => {
                let x = point.x.get_buffer();
                let y = point.y.get_buffer();
                unique_copy[..x.len()].copy_from_slice(x);
                unique_copy[x.len()..x.len() + y.len()].copy_from_slice(y);
                x.len() + y.len()
            }
            crate::owned::OwnedPublicParmsAndId::Mldsa(_, unique)
            | crate::owned::OwnedPublicParmsAndId::HashMldsa(_, unique) => {
                let b = unique.get_buffer();
                unique_copy[..b.len()].copy_from_slice(b);
                b.len()
            }
            crate::owned::OwnedPublicParmsAndId::Mlkem(_, unique) => {
                let b = unique.get_buffer();
                unique_copy[..b.len()].copy_from_slice(b);
                b.len()
            }
        };

        let name_alg = _in_public_struct.name_alg.ok_or(TpmRc::HASH.to_rc())?;
        if name_alg != TpmiAlgHash::Sha1
            && name_alg != TpmiAlgHash::Sha256
            && name_alg != TpmiAlgHash::Sha384
            && name_alg != TpmiAlgHash::Sha512
        {
            return Err(TpmRc::VALUE.to_rc());
        }

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
        let mut actual_private_key = [0u8; 1536];
        let (actual_private_key_len, stored_seed) = self.derive_primary_key(
            name_alg,
            &parent_seed_val[..parent_seed_len],
            &unique_copy[..unique_len],
            &mut _in_public_struct.parms_and_id,
            fallback_sensitive_data,
            &mut obj_seed,
            &mut actual_private_key,
        )?;

        let mut pub_buf = [0u8; tpm2::TpmtPublic::MAX_SIZE];
        let pub_len = _in_public_struct.marshal(&mut pub_buf);
        let name = self.compute_name(_in_public_struct.name_alg, &pub_buf[..pub_len])?;

        // Allocate transient object slot
        let (index, handle) = self.global_state.find_empty_transient_slot(true)?;

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
            pcr_select: cmd.creation_pcr,
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
            name,
            auth: crate::owned::OwnedAuth::from(in_sensitive_struct.user_auth),
            public: _in_public_struct,
            private: actual_private_key,
            private_len: actual_private_key_len,
            qualified_name,
            hierarchy: primary_handle.0,
            st_clear: false,
        });

        self.update_aliased_transient_objects(handle, &name, &qualified_name);

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

    /// Derives object seeds using KDFA and generates cryptographic key/unique properties.
    #[allow(clippy::too_many_arguments)]
    fn derive_primary_key(
        &self,
        name_alg: TpmiAlgHash,
        parent_seed_val: &[u8],
        unique_buf: &[u8],
        parms_and_id: &mut crate::owned::OwnedPublicParmsAndId,
        fallback_sensitive_data: Option<&[u8]>,
        obj_seed: &mut [u8; 64],
        actual_private_key: &mut [u8; 1536],
    ) -> Result<(usize, [u8; 32]), TpmRc> {
        let parent_seed_len = parent_seed_val.len();
        let gen_seed_arg = if parent_seed_len > 0 {
            kdfa(
                self.crypto(),
                TpmiAlgHash::Sha256,
                parent_seed_val,
                b"Primary Object Creation",
                unique_buf,
                &[],
                256,
                obj_seed,
            )
            .map_err(|_| TpmRc::FAILURE)?;
            Some(&obj_seed[..32])
        } else {
            None
        };

        let actual_private_key_len = self.generate_key_and_unique(
            name_alg,
            parms_and_id,
            KeyDerivationArgs {
                gen_seed: gen_seed_arg,
                obj_seed: gen_seed_arg.unwrap_or(&[]),
                get_random_fallback: fallback_sensitive_data.is_none(),
                fallback_sensitive_data,
            },
            actual_private_key,
        )?;

        let mut stored_seed = [0u8; 32];
        stored_seed.copy_from_slice(&obj_seed[..32]);

        Ok((actual_private_key_len, stored_seed))
    }
}
