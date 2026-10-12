use super::{KeyDerivationArgs, TransientObject};
use crate::Crypto;
use crate::handle_checks::{Tpmi, check};
use crate::handler::object_helpers::{null_name_alg_error, unique_parts};
use crate::owned::{
    OwnedAuth, OwnedDigest, OwnedPublic, OwnedPublicParmsAndId, OwnedSensitiveComposite,
};
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{handler::CommandHandler, req_resp::RequestThenResponse};
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::{CreatePrimary, responses};
use tpm2::crypto::kdfa;
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Marshal, Tpm2b, Tpm2bDigest, Tpm2bName, Tpm2bSensitiveCreate, TpmaLocality, TpmaObject,
    TpmiAlgHash, TpmsCreationData, TpmtPublic, TpmtTkCreation,
};

/// Length of the seed of a primary object: KDFa(SHA-256, ..., 256 bits).
const PRIMARY_SEED_BYTES: usize = 32;

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
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
    /// - Creates a root key for a hierarchy. Child keys can then be created under it using [TpmCc::Create](create.rs).
    /// - The key is created deterministically based on the hierarchy's primary seed and the unique parameters in the public template.
    /// - If the primary seed is changed (e.g. by running [TpmCc::Clear](clear.rs)),
    ///   subsequent calls to [TpmCc::CreatePrimary] with the same template will produce a different key.
    pub fn create_primary(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let [primary_handle] = request.try_unmarshal_handles::<CreatePrimary>()?;
        check(primary_handle, Tpmi::RhHierarchy, Position::handle(1))?;

        if primary_handle != Handle::RH_OWNER
            && primary_handle != Handle::RH_ENDORSEMENT
            && primary_handle != Handle::RH_PLATFORM
            && primary_handle != Handle::RH_NULL
        {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        if let Some(rc) = null_name_alg_error::<Tpm2bSensitiveCreate>(
            request.remaining_slice(),
            Position::parameter(2),
        ) {
            return Err(rc);
        }
        let cmd = request.try_unmarshal_command::<CreatePrimary>([primary_handle])?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        self.nv_clear_orderly()?;

        let in_sensitive_struct = cmd.in_sensitive.0;
        let mut in_public_struct = OwnedPublic::from(cmd.in_public.0);

        self.validate_create_loaded_parameters(
            &in_public_struct.as_tpmt(),
            &in_sensitive_struct,
            primary_handle.0,
            primary_handle.0,
            None,
        )?;

        // 1. Resolve parent seed value and length
        let mut parent_seed_val = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let parent_seed_len =
            self.resolve_primary_parent_seed(primary_handle, &mut parent_seed_val)?;

        let name_alg = in_public_struct.name_alg.ok_or(TpmRc::HASH.to_rc())?;
        if !matches!(
            name_alg,
            TpmiAlgHash::Sha1 | TpmiAlgHash::Sha256 | TpmiAlgHash::Sha384 | TpmiAlgHash::Sha512
        ) {
            return Err(TpmRc::VALUE.to_rc());
        }

        // 2. Derive object seed, private key, and update public key template unique area
        let fallback_sensitive_data = if in_public_struct
            .object_attributes
            .contains(TpmaObject::SENSITIVE_DATA_ORIGIN)
        {
            None
        } else {
            Some(in_sensitive_struct.data.as_slice())
        };
        let mut obj_seed = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let (sensitive, stored_seed) = self.derive_primary_key(
            name_alg,
            &parent_seed_val[..parent_seed_len],
            &mut in_public_struct.parms_and_id,
            fallback_sensitive_data,
            &mut obj_seed,
        )?;

        let mut pub_buf = [0u8; TpmtPublic::MAX_SIZE];
        let pub_len = in_public_struct.marshal(&mut pub_buf);
        let name = self.compute_name(in_public_struct.name_alg, &pub_buf[..pub_len])?;

        // Allocate transient object slot
        let (index, handle) = self.global_state.find_empty_transient_slot(true)?;

        let out_public = in_public_struct.as_tpm2b();

        let primary_handle_bytes = primary_handle.0.to_be_bytes();
        let parent_name = Tpm2bName::new(&primary_handle_bytes).ok_or(TpmRc::FAILURE)?;
        let parent_qualified_name = parent_name;

        let pcr_digest = self.compute_pcr_digest(&cmd.creation_pcr, name_alg)?;

        let locality = self.global_state.locality;
        let creation_data_struct = TpmsCreationData {
            pcr_select: cmd.creation_pcr,
            pcr_digest: pcr_digest.as_tpm2b(),
            locality: TpmaLocality(if locality <= 4 {
                1 << locality
            } else {
                locality
            }),
            parent_name_alg: None,
            parent_name,
            parent_qualified_name,
            outside_info: cmd.outside_info,
        };

        let mut cd_buf = [0u8; TpmsCreationData::MAX_SIZE];
        let cd_len = creation_data_struct.marshal(&mut cd_buf);
        let creation_data = Tpm2b(creation_data_struct);

        let (creation_hash_bytes, creation_hash_len) =
            self.compute_hash(name_alg, &[&cd_buf[..cd_len]])?;

        let creation_hash = creation_hash_bytes
            .get(..creation_hash_len)
            .and_then(Tpm2bDigest::new)
            .ok_or(TpmRc::FAILURE)?;

        let computed_digest =
            self.compute_creation_ticket(primary_handle.0, &name, &creation_hash)?;
        let creation_ticket = TpmtTkCreation::Creation(
            primary_handle,
            Tpm2bDigest::new(&computed_digest).ok_or(TpmRc::FAILURE)?,
        );

        let rsp = responses::CreatePrimary {
            object_handle: Handle(handle),
            out_public,
            creation_data,
            creation_hash,
            creation_ticket,
            name: name.as_tpm2b(),
        };

        let response = request.into_response();
        self.write_response_all(
            response,
            &rsp.object_handle,
            &rsp,
            &session_responses[..num_sessions],
        )?;

        let hierarchy_name = primary_handle.0.to_be_bytes();
        let qualified_name = self.compute_qualified_name(
            in_public_struct.name_alg,
            &hierarchy_name,
            name.get_buffer(),
        )?;

        self.global_state.transient_parents[index] = Some(primary_handle.0);
        self.global_state.transient_objects[index] = Some(TransientObject {
            handle,
            seed: OwnedDigest::new(&stored_seed).ok_or(TpmRc::FAILURE)?,
            name,
            auth: OwnedAuth::from(in_sensitive_struct.user_auth),
            public: in_public_struct,
            sensitive,
            qualified_name,
            hierarchy: primary_handle.0,
            st_clear: false,
        });

        self.update_aliased_transient_objects(handle, &name, &qualified_name);

        Ok(())
    }

    /// Resolves the storage primary seed values forOwner, Platform, or Endorsement hierarchies.
    ///
    /// Returns the seed length (`0` for other handles).
    fn resolve_primary_parent_seed(
        &self,
        primary_handle: Handle,
        parent_seed_val: &mut [u8; TpmiAlgHash::MAX_DIGEST_BYTES],
    ) -> Result<usize, TpmRc> {
        let state = &*self.global_state;
        let (seed, seed_size) = match primary_handle {
            Handle::RH_PLATFORM => (&state.pp_seed, state.pp_seed_size),
            Handle::RH_OWNER => (&state.sp_seed, state.sp_seed_size),
            Handle::RH_ENDORSEMENT => (&state.ep_seed, state.ep_seed_size),
            Handle::RH_NULL => (&state.null_seed, state.null_seed_size),
            _ => return Ok(0),
        };
        let seed_len = usize::from(seed_size);
        parent_seed_val
            .get_mut(..seed_len)
            .ok_or(TpmRc::FAILURE)?
            .copy_from_slice(seed.get(..seed_len).ok_or(TpmRc::FAILURE)?);
        Ok(seed_len)
    }

    /// Derives object seeds using KDFA and generates cryptographic key/unique properties.
    ///
    /// Returns the sensitive area of the new object and the seed to store with it.
    ///
    /// PORTING: exp copied the template's `unique` field into a buffer first (KDFa now
    /// reads it from `parms_and_id`, see `unique_parts`) and wrote the private key into an
    /// out-buffer; takes `&mut self` (key generation may use the global RNG).
    fn derive_primary_key(
        &mut self,
        name_alg: TpmiAlgHash,
        parent_seed_val: &[u8],
        parms_and_id: &mut OwnedPublicParmsAndId,
        fallback_sensitive_data: Option<&[u8]>,
        obj_seed: &mut [u8; TpmiAlgHash::MAX_DIGEST_BYTES],
    ) -> Result<(OwnedSensitiveComposite, [u8; PRIMARY_SEED_BYTES]), TpmRc> {
        let derived_seed = !parent_seed_val.is_empty();
        if derived_seed {
            let (unique_u, unique_v) = unique_parts(parms_and_id.as_borrowed());
            kdfa(
                self.crypto(),
                TpmiAlgHash::Sha256,
                parent_seed_val,
                c"Primary Object Creation",
                unique_u,
                unique_v,
                &mut obj_seed[..PRIMARY_SEED_BYTES],
            )
            .map_err(|_| TpmRc::FAILURE)?;
        }

        let stored_seed: &[u8; PRIMARY_SEED_BYTES] =
            obj_seed.first_chunk().ok_or(TpmRc::FAILURE)?;
        let gen_seed_arg = derived_seed.then_some(&stored_seed[..]);

        let sensitive = self.generate_key_and_unique(
            name_alg,
            parms_and_id,
            KeyDerivationArgs {
                gen_seed: gen_seed_arg,
                obj_seed: gen_seed_arg.unwrap_or(&[]),
                get_random_fallback: fallback_sensitive_data.is_none(),
                fallback_sensitive_data,
            },
        )?;

        Ok((sensitive, *stored_seed))
    }
}
