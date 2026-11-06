use crate::Platform;
use crate::handle_checks::{Tpmi, check};
use crate::handler::{CommandHandler, TransientObject};
use crate::owned::OwnedAuthCommand;
use crate::req_resp::RequestThenResponse;
use crate::storage::Tpm2Storage;
use crate::storage::manager::StorageManager;
use crate::storage::nv_capacity;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::TpmaObject;
use tpm2::commands::EvictControl;
use tpm2::crypto::Crypto;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmHt};

impl<'b, C: Crypto, P: Platform<Crypto = C>> CommandHandler<'b, P> {
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

        let handles = request.try_unmarshal_handles::<EvictControl>()?;
        let [auth, object] = handles;
        check(auth, Tpmi::RhProvision, Position::handle(1))?;
        check(object, Tpmi::DhObject, Position::handle(2))?;
        let object_handle = object.0;
        let auth_handle = auth.0;

        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;
        let provided_auth = self.context.state.parsed_auths[..self.context.state.parsed_auths_len]
            .first()
            .cloned();

        // 1. Verify authority session auth
        self.validate_evict_control_auth(auth_handle, provided_auth)?;

        let cmd = request.try_unmarshal_command::<EvictControl>(handles)?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let persistent_handle = cmd.persistent_handle.0;

        // Sequence objects are `temporary` in C and can not be made persistent
        // (`TPM_RC_ATTRIBUTES + RC_EvictControl_objectHandle`).
        if self
            .context
            .state
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
                .context
                .state
                .find_transient_object(object_handle)
                .cloned()
                .ok_or(TpmRc::REFERENCE_H1)?;
            // Public-only objects (including the public-only objects of `TPM2_LoadExternal`
            // in a hierarchy other than `TPM_RH_NULL`) may be made persistent. Part 3
            // TPM2_EvictControl: "Older versions of the specification did not allow an object
            // to be persisted when only the public portion of the object was loaded (for NV
            // space efficiency). Support for persisting public-only objects was added in
            // version 185." Only objects "in the hierarchy of `TPM_RH_NULL`" or with
            // "*stClear* ... SET in the object or in an ancestor key" are rejected with
            // `TPM_RC_ATTRIBUTES` (checked below). An external object with a sensitive area
            // is always in the NULL hierarchy (TPM2_LoadExternal: "If the public and sensitive
            // portions of the object are loaded, *hierarchy* is required to be
            // `TPM_RH_NULL`."), like the C reference's `temporary` objects.
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
            if StorageManager::new(self.context.platform.storage_mut())
                .get_metadata(persistent_handle)
                .is_ok()
            {
                return Err(TpmRc::NV_DEFINED);
            }
            // `NvAddEvictObject()` tests the NV space (`NvTestSpace()`, TPM_RC_NV_SPACE) before
            // `NvAdd()` checks NV availability. NV capacity is implementation-specific (Part 3
            // TPM2_EvictControl: "TPM_RC_NV_SPACE | no space in NV memory"; Part 2
            // TPM_PT_HR_PERSISTENT_AVAIL: "This value is an estimate"), so tpm-rs accounts NV
            // like the reference (`storage::nv_capacity`): every persistent object takes
            // `NV_EVICT_OBJECT_SIZE` bytes whatever its type.
            let usage =
                nv_capacity::scan(&StorageManager::new(self.context.platform.storage_mut()))
                    .map_err(|_| TpmRc::FAILURE)?;
            if !usage.can_add_evict_object() {
                return Err(TpmRc::NV_SPACE);
            }
            self.return_if_nv_is_not_available()?;
            self.nv_clear_orderly()?;
            let mut storage = StorageManager::new(self.context.platform.storage_mut());
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
            StorageManager::new(self.context.platform.storage_mut())
                .undefine_space(object_handle)
                .map_err(|_| TpmRc::HANDLE.with(Position::handle(2)))?;
        }

        self.context.state.update_nv |= crate::engine::UT_NV;

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

        let expected_auth_struct = self.context.handle_auth(auth_handle);
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
        // TPM 2.0 Part 3, TPM2_EvictControl: "The TPM shall return `TPM_RC_ATTRIBUTES` if it is
        // in the hierarchy of `TPM_RH_NULL` or a firmware-limited or SVN-limited hierarchy, or
        // the *stClear* is SET in the object or in an ancestor key". Part 1, "EvictControl of
        // objects in firmware-limited and SVN-limited hierarchies": "Objects in a
        // firmware-limited or SVN-limited hierarchy (including objects without
        // *firmwareLimited/svnLimited* SET), cannot be made persistent". (The TCG references
        // return `TPM_RC_HIERARCHY` for the limited hierarchies, which the differential tests
        // fix: `bug-fix-svn-fw-limited-evict-control.patch`.)
        if is_st_clear
            || ancestor_has_st_clear
            || object_hierarchy == Handle::RH_NULL.0
            || crate::hierarchy::is_limited(object_hierarchy)
        {
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

    /// Writes `obj` as the persistent object `persistent_handle`
    /// ([`crate::storage::nv::NvPersistentObjectRecord`]).
    fn persist_transient_object(
        persistent_handle: u32,
        obj: &TransientObject,
        storage: &mut StorageManager<'_>,
    ) -> Result<(), TpmRc> {
        crate::storage::nv::NvPersistentObjectRecord::from_object(obj)
            .write(storage, persistent_handle)
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
