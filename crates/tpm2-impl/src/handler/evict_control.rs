use crate::handler::{CommandHandler, TransientObject};
use crate::owned::OwnedAuthCommand;
use crate::req_resp::RequestThenResponse;
use crate::storage::manager::StorageManager;
use crate::storage::{NvStorage, Tpm2Storage};
use crate::timer::TpmTimer;
use tpm2::Marshal;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::TpmaObject;
use tpm2::commands::{EvictControl, EvictControlHandles};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, Tpm2bDigest, TpmHt};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::EvictControl] (`0x120`) command.
    ///
    /// # Description
    /// This command makes a transient object persistent (by copying it into non-volatile storage under a persistent handle)
    /// or evicts (deletes) a persistent object from non-volatile storage.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 24.2 (TPM2_EvictControl).
    ///
    /// # Relationships
    /// - Transient objects must be loaded (created by [TpmCc::CreatePrimary](create_primary.rs)
    ///   or loaded by [TpmCc::Load](load.rs)) before they can be persisted.
    /// - Persistent objects do not require context reloading and can be referenced directly by their persistent handle.
    /// - Authorization must be provided by either the Owner hierarchy ([Handle::RH_OWNER]) or Platform hierarchy ([Handle::RH_PLATFORM]).
    pub fn evict_control(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<EvictControlHandles>()?;
        let object_handle = handles.object_handle.0;
        let auth_handle = handles.auth.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let provided_auth = self.global_state.parsed_auths[..self.global_state.parsed_auths_len]
            .first()
            .cloned();

        // 1. Verify authority session auth
        self.validate_evict_control_auth(auth_handle, provided_auth)?;

        let cmd = request.try_unmarshal::<EvictControl>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let persistent_handle = cmd.persistent_handle.0;

        // Sequence objects are `temporary` in C and can not be made persistent
        // (`TPM_RC_ATTRIBUTES + RC_EvictControl_objectHandle`).
        if self
            .global_state
            .find_active_sequence(object_handle)
            .is_some()
        {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(2)));
        }

        let is_transient_range = (object_handle >> 24) == (TpmHt::Transient as u8) as u32;
        let is_persistent_handle = (object_handle >> 24) == (TpmHt::Persistent as u8) as u32;
        if !is_transient_range && !is_persistent_handle {
            return Err(TpmRc::VALUE.with(Position::handle(2)));
        }

        if is_transient_range {
            let obj = self
                .global_state
                .find_transient_object(object_handle)
                .cloned()
                .ok_or(TpmRc::REFERENCE_H1)?;
            // Temporary (NULL hierarchy or external), stClear or public-only objects can not
            // be made persistent.
            if obj.public_only || obj.external {
                return Err(TpmRc::ATTRIBUTES.with(Position::handle(2)));
            }
            let is_st_clear = obj.public.object_attributes.contains(TpmaObject::ST_CLEAR);

            // 2. Validate transient object hierarchy rules and attributes consistency
            Self::validate_transient_object_hierarchy_attributes(
                auth_handle,
                obj.hierarchy,
                persistent_handle,
                is_st_clear,
                obj.st_clear,
            )?;

            // 3. Persist the transient object to NV storage. C checks `TPM_RC_NV_DEFINED`
            // before `NvAddEvictObject`, which fails with `TPM_RC_NV_UNAVAILABLE` before NV
            // is modified.
            if StorageManager::new(&mut *self.context.platform.storage)
                .get_metadata(persistent_handle)
                .is_ok()
            {
                return Err(TpmRc::NV_DEFINED);
            }
            self.return_if_nv_is_not_available()?;
            self.nv_clear_orderly()?;
            let mut storage = StorageManager::new(&mut *self.context.platform.storage);
            Self::persist_transient_object(persistent_handle, &obj, &mut storage)?;
        } else {
            // 4. Evict persistent object from storage
            // C ObjectLoadEvict exempts EvictControl from the ehEnable check, so read the
            // persistent record without hierarchy-enable checks (the engine already validated
            // the handle).
            let obj = self
                .context
                .read_persistent_object(object_handle)
                .map_err(|_| TpmRc::HANDLE.with(Position::handle(2)))?;
            Self::validate_persistent_object_eviction(
                auth_handle,
                obj.hierarchy,
                object_handle,
                persistent_handle,
            )?;
            // `NvDeleteEvict` fails with `TPM_RC_NV_UNAVAILABLE` before NV is modified.
            self.return_if_nv_is_not_available()?;
            self.nv_clear_orderly()?;
            StorageManager::new(&mut *self.context.platform.storage)
                .undefine_space(object_handle)
                .map_err(|_| TpmRc::HANDLE.with(Position::handle(2)))?;
        }

        self.global_state.update_nv |= crate::engine::UT_NV;

        let response = request.into_response();
        self.write_response_none(response, &session_responses[..num_sessions])?;

        Ok(())
    }

    /// Verifies password auth credentials against the target provision authority.
    fn validate_evict_control_auth(
        &mut self,
        auth_handle: u32,
        provided_auth: Option<OwnedAuthCommand>,
    ) -> Result<(), TpmRc> {
        if auth_handle != Handle::RH_PLATFORM.0 && auth_handle != Handle::RH_OWNER.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let expected_auth_struct = self.context.handle_auth(self.global_state, auth_handle);
        let expected_auth = expected_auth_struct.get_buffer();

        if let Some(auth) = provided_auth {
            if !self.verify_password_auth(&auth, expected_auth) {
                return Err(TpmRc::AUTH_FAIL.with(Position::session(1)));
            }
            Ok(())
        } else {
            Err(TpmRc::AUTH_MISSING)
        }
    }

    /// Performs hierarchy and clearing/permanent attributes validation on transient objects.
    fn validate_transient_object_hierarchy_attributes(
        auth_handle: u32,
        object_hierarchy: u32,
        persistent_handle: u32,
        is_st_clear: bool,
        ancestor_has_st_clear: bool,
    ) -> Result<(), TpmRc> {
        if is_st_clear || ancestor_has_st_clear || object_hierarchy == Handle::RH_NULL.0 {
            return Err(TpmRc::ATTRIBUTES.with(Position::handle(2)));
        }

        if auth_handle == Handle::RH_PLATFORM.0 {
            if object_hierarchy != Handle::RH_PLATFORM.0 {
                return Err(TpmRc::HIERARCHY.with(Position::handle(2)));
            }
            if !(0x81800000..=0x81FFFFFF).contains(&persistent_handle) {
                return Err(TpmRc::RANGE.with(Position::parameter(1)));
            }
        } else if auth_handle == Handle::RH_OWNER.0 {
            if object_hierarchy != Handle::RH_OWNER.0
                && object_hierarchy != Handle::RH_ENDORSEMENT.0
            {
                return Err(TpmRc::HIERARCHY.with(Position::handle(2)));
            }
            if !(0x81000000..=0x817FFFFF).contains(&persistent_handle) {
                return Err(TpmRc::RANGE.with(Position::parameter(1)));
            }
        } else {
            return Err(TpmRc::HANDLE.to_rc());
        }

        Ok(())
    }

    /// Serializes and writes a transient object's fields to NV space.
    fn persist_transient_object(
        persistent_handle: u32,
        obj: &TransientObject,
        storage: &mut StorageManager<'_>,
    ) -> Result<(), TpmRc> {
        let mut buf = [0u8; 4096];
        let mut offset = 0;

        // seedValue: TPM2B (2-byte size followed by the full nameAlg-sized seed).
        offset += Tpm2bDigest::from_bytes(obj.seed_bytes())
            .map_err(|_| TpmRc::FAILURE)?
            .marshal(
                (&mut buf[offset..offset + Tpm2bDigest::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );

        offset += obj.name.marshal(
            (&mut buf[offset..offset + tpm2::Tpm2bName::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset += obj.auth.marshal(
            (&mut buf[offset..offset + tpm2::Tpm2bAuth::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset += obj.public.marshal(
            (&mut buf[offset..offset + tpm2::TpmtPublic::MAX_SIZE])
                .try_into()
                .unwrap(),
        );

        let priv_len = obj.private_len;
        offset += (priv_len as u16).marshal((&mut buf[offset..offset + 2]).try_into().unwrap());
        buf[offset..offset + priv_len].copy_from_slice(&obj.private[..priv_len]);
        offset += priv_len;

        offset += obj.qualified_name.marshal(
            (&mut buf[offset..offset + tpm2::Tpm2bName::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset += obj.hierarchy.marshal(
            (&mut buf[offset..offset + tpm2::Handle::MAX_SIZE])
                .try_into()
                .unwrap(),
        );

        storage
            .define_space(persistent_handle, offset as u16, 0)
            .map_err(|_| TpmRc::NV_SPACE)?;
        if storage
            .write_item(persistent_handle, 0, &buf[..offset])
            .is_err()
        {
            let _ = storage.undefine_space(persistent_handle);
            return Err(TpmRc::FAILURE);
        }
        Ok(())
    }

    /// Validates the eviction of a persistent object (C `EvictControl.c` order): the
    /// persistent handle must equal the object handle (`TPM_RC_HANDLE + RC_H2`) before the
    /// owner may be refused for platform-hierarchy objects (`TPM_RC_HIERARCHY + RC_H2`).
    fn validate_persistent_object_eviction(
        auth_handle: u32,
        object_hierarchy: u32,
        object_handle: u32,
        persistent_handle: u32,
    ) -> Result<(), TpmRc> {
        if persistent_handle != object_handle {
            return Err(TpmRc::HANDLE.with(Position::handle(2)));
        }
        if auth_handle == Handle::RH_PLATFORM.0 {
            // Platform can evict any valid persistent object handle
        } else if auth_handle == Handle::RH_OWNER.0 {
            if object_hierarchy == Handle::RH_PLATFORM.0 {
                return Err(TpmRc::HIERARCHY.with(Position::handle(2)));
            }
        } else {
            return Err(TpmRc::HANDLE.to_rc());
        }
        Ok(())
    }
}
