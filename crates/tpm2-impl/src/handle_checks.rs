//! Range checks for the handle interface types (`TPMI_DH_*`, `TPMI_SH_*`, `TPMI_RH_*`) defined in
//! TPM 2.0 Part 2, Section 9 ("Interface Types").
//!
//! Every handle area entry and handle-typed parameter / structure field in Part 3 has one of these
//! interface types. A handle outside the type's set of values must be rejected with the type's
//! `#TPM_RC_*` response code, which is `TPM_RC_VALUE` for every handle interface type in Part 2,
//! qualified with the [`Position`] of the offending handle or parameter.
//!
//! PORTING: exp's old `tpm2` crate typed these fields (`TpmiShPolicy`, `TpmiDhObject<ALLOW_NULL>`,
//! `TpmiRhHierarchy`, ...) and rejected out-of-range handles while unmarshaling. The new `tpm2`
//! crate represents all of them as a plain [`Handle`], so handlers validate them explicitly:
//!
//! ```ignore
//! let [auth_object, policy_session] = request.try_unmarshal_handles::<PolicySigned>()?;
//! check(auth_object, Tpmi::DhObject, Position::handle(1))?;
//! check(policy_session, Tpmi::ShPolicy, Position::handle(2))?;
//! ```
//!
//! The sets below match exp's old `tpm2::Tpmi*` types (so that response codes are unchanged).
//! Where those differ from Part 2 (v1.85) this is called out on the variant.

use crate::{MAX_ACTIVE_SESSIONS, MAX_LOADED_OBJECTS};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmHt, TpmsPcrSelect};

/// `HR_HANDLE_MASK`: the low 24 bits of a handle, i.e. its index within its [`TpmHt`] range.
const HR_HANDLE_MASK: u32 = 0x00FF_FFFF;

/// `TPM_RH_AUTH_FF`, the last vendor authorization handle (Part 2, Section 7.4, Table 30).
const RH_AUTH_FF: Handle = Handle(0x4000_010F);

/// `SVN_NULL_LAST` (`TPM_RH_SVN_NULL_BASE + 0xFFFF`), the last SVN-limited hierarchy handle.
const SVN_NULL_LAST: Handle = Handle(Handle::RH_SVN_NULL_BASE.0 + 0xFFFF);

/// A handle interface type (`TPMI_*` with a `TPM_HANDLE` base type).
///
/// Variants ending in `OrNull` are the `+` forms (e.g. `TPMI_DH_OBJECT+`), which additionally
/// accept `TPM_RH_NULL`. Ranges use the implementation values of this TPM:
/// `TRANSIENT_LAST = TRANSIENT_FIRST + MAX_LOADED_OBJECTS - 1` (`0x8000_000F`),
/// `HMAC_SESSION_LAST` / `POLICY_SESSION_LAST = *_FIRST + MAX_ACTIVE_SESSIONS - 1`
/// (`0x0200_003F` / `0x0300_003F`), and `PCR_LAST = 23` (24 PCRs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // Lists every TPMI handle type, including ones no command checks yet.
pub(crate) enum Tpmi {
    /// `TPMI_DH_OBJECT` (Part 2, Table 44): transient objects
    /// `{TRANSIENT_FIRST:TRANSIENT_LAST}` and persistent objects
    /// `{PERSISTENT_FIRST:PERSISTENT_LAST}` (`0x8100_0000..=0x81FF_FFFF`).
    DhObject,
    /// `TPMI_DH_OBJECT+`: [`Tpmi::DhObject`] or `TPM_RH_NULL`.
    DhObjectOrNull,
    /// `TPMI_DH_PARENT` (Part 2, Table 45): transient and persistent objects, or any
    /// [`Tpmi::RhHierarchy`] value.
    DhParent,
    /// `TPMI_DH_PERSISTENT` (Part 2, Table 46): `{PERSISTENT_FIRST:PERSISTENT_LAST}`.
    DhPersistent,
    /// `TPMI_DH_ENTITY` (Part 2, Table 47): `TPM_RH_OWNER`, `TPM_RH_ENDORSEMENT`,
    /// `TPM_RH_PLATFORM`, `TPM_RH_LOCKOUT`, transient and persistent objects,
    /// `{NV_INDEX_FIRST:NV_INDEX_LAST}`, `{PCR_FIRST:PCR_LAST}` and
    /// `{TPM_RH_AUTH_00:TPM_RH_AUTH_FF}` (`0x4000_0010..=0x4000_010F`).
    ///
    /// Part 2 v1.85 also lists `{TPM_RH_ACT_0:TPM_RH_ACT_F}`, external NV and permanent NV
    /// Indexes; exp's `TpmiDhEntity` did not accept them, so neither does this.
    DhEntity,
    /// `TPMI_DH_ENTITY+`: [`Tpmi::DhEntity`] or `TPM_RH_NULL`.
    DhEntityOrNull,
    /// `TPMI_DH_PCR` (Part 2, Table 48): `{PCR_FIRST:PCR_LAST}`.
    DhPcr,
    /// `TPMI_DH_PCR+`: [`Tpmi::DhPcr`] or `TPM_RH_NULL`.
    DhPcrOrNull,
    /// `TPMI_DH_CONTEXT` (Part 2, Table 52): HMAC sessions, policy sessions and transient
    /// objects.
    DhContext,
    /// `TPMI_DH_SAVED` (Part 2, Table 53): HMAC sessions, policy sessions, and the saved object
    /// context handles `0x8000_0000` (object), `0x8000_0001` (sequence) and `0x8000_0002`
    /// (`stClear` object).
    DhSaved,
    /// `TPMI_SH_AUTH_SESSION` (Part 2, Table 49): `{HMAC_SESSION_FIRST:HMAC_SESSION_LAST}` and
    /// `{POLICY_SESSION_FIRST:POLICY_SESSION_LAST}`.
    ShAuthSession,
    /// `TPMI_SH_AUTH_SESSION+`: [`Tpmi::ShAuthSession`] or `TPM_RS_PW`.
    ShAuthSessionOrPw,
    /// `TPMI_SH_HMAC` (Part 2, Table 50): `{HMAC_SESSION_FIRST:HMAC_SESSION_LAST}`.
    ShHmac,
    /// `TPMI_SH_POLICY` (Part 2, Table 51): `{POLICY_SESSION_FIRST:POLICY_SESSION_LAST}`.
    ShPolicy,
    /// `TPMI_RH_HIERARCHY` (Part 2, Table 54): `TPM_RH_OWNER`, `TPM_RH_PLATFORM`,
    /// `TPM_RH_ENDORSEMENT`, `TPM_RH_NULL`, the firmware-limited hierarchies
    /// `TPM_RH_FW_{OWNER,ENDORSEMENT,PLATFORM,NULL}` (`0x4000_0140..=0x4000_0143`) and the
    /// SVN-limited hierarchies `{SVN_OWNER_FIRST:SVN_NULL_LAST}` (`0x4001_0000..=0x4004_FFFF`).
    ///
    /// `TPM_RH_NULL` is an unconditional member in Part 2 v1.85, so `TPMI_RH_HIERARCHY+`
    /// (used by older Part 3 / ticket definitions) is the same set.
    RhHierarchy,
    /// `TPMI_RH_ENABLES` (Part 2, Table 55): `TPM_RH_OWNER`, `TPM_RH_PLATFORM`,
    /// `TPM_RH_ENDORSEMENT` and `TPM_RH_PLATFORM_NV`.
    RhEnables,
    /// `TPMI_RH_ENABLES+`: [`Tpmi::RhEnables`] or `TPM_RH_NULL`.
    RhEnablesOrNull,
    /// `TPMI_RH_HIERARCHY_AUTH` (Part 2, Table 56): `TPM_RH_OWNER`, `TPM_RH_PLATFORM`,
    /// `TPM_RH_ENDORSEMENT` and `TPM_RH_LOCKOUT`.
    RhHierarchyAuth,
    /// `TPMI_RH_HIERARCHY_AUTH+`: [`Tpmi::RhHierarchyAuth`] or `TPM_RH_NULL`.
    RhHierarchyAuthOrNull,
    /// `TPMI_RH_HIERARCHY_POLICY` (Part 2, Table 57): `TPM_RH_OWNER`, `TPM_RH_PLATFORM`,
    /// `TPM_RH_ENDORSEMENT`, `TPM_RH_LOCKOUT` and `{TPM_RH_ACT_0:TPM_RH_ACT_F}`.
    RhHierarchyPolicy,
    /// `TPMI_RH_BASE_HIERARCHY` (Part 2, Table 58): `TPM_RH_OWNER`, `TPM_RH_PLATFORM` and
    /// `TPM_RH_ENDORSEMENT`.
    RhBaseHierarchy,
    /// `TPMI_RH_PLATFORM` (Part 2, Table 59): `TPM_RH_PLATFORM`.
    RhPlatform,
    /// `TPMI_RH_OWNER` (Part 2, Table 60): `TPM_RH_OWNER`.
    RhOwner,
    /// `TPMI_RH_OWNER+`: `TPM_RH_OWNER` or `TPM_RH_NULL`.
    RhOwnerOrNull,
    /// `TPMI_RH_ENDORSEMENT` (Part 2, Table 61): `TPM_RH_ENDORSEMENT`.
    RhEndorsement,
    /// `TPMI_RH_ENDORSEMENT+`: `TPM_RH_ENDORSEMENT` or `TPM_RH_NULL`.
    RhEndorsementOrNull,
    /// `TPMI_RH_PROVISION` (Part 2, Table 62): `TPM_RH_OWNER` and `TPM_RH_PLATFORM`.
    RhProvision,
    /// `TPMI_RH_CLEAR` (Part 2, Table 63): `TPM_RH_LOCKOUT` and `TPM_RH_PLATFORM`.
    RhClear,
    /// `TPMI_RH_NV_AUTH` (Part 2, Table 64): `TPM_RH_PLATFORM`, `TPM_RH_OWNER` and
    /// `{NV_INDEX_FIRST:NV_INDEX_LAST}`.
    ///
    /// Part 2 v1.85 also lists external NV and permanent NV Indexes; exp's `TpmiRhNvAuth` did
    /// not accept them, so neither does this.
    RhNvAuth,
    /// `TPMI_RH_LOCKOUT` (Part 2, Table 65): `TPM_RH_LOCKOUT`.
    RhLockout,
    /// `TPMI_RH_NV_INDEX` (Part 2, Table 66): `{NV_INDEX_FIRST:NV_INDEX_LAST}`,
    /// `{EXTERNAL_NV_FIRST:EXTERNAL_NV_LAST}` (`0x1100_0000..=0x11FF_FFFF`) and
    /// `{PERMANENT_NV_FIRST:PERMANENT_NV_LAST}` (`0x1200_0000..=0x12FF_FFFF`).
    RhNvIndex,
    /// `TPMI_RH_NV_DEFINED_INDEX` (Part 2, Table 67): `{NV_INDEX_FIRST:NV_INDEX_LAST}` and
    /// `{EXTERNAL_NV_FIRST:EXTERNAL_NV_LAST}`.
    RhNvDefinedIndex,
    /// `TPMI_RH_NV_LEGACY_INDEX` (Part 2, Table 68): `{NV_INDEX_FIRST:NV_INDEX_LAST}`.
    RhNvLegacyIndex,
    /// `TPMI_RH_NV_EXP_INDEX` (Part 2, Table 69): `{EXTERNAL_NV_FIRST:EXTERNAL_NV_LAST}`.
    RhNvExpIndex,
    /// `TPMI_RH_AC` (Part 2, Table 70): `{AC_FIRST:AC_LAST}` (`0x9000_0000..=0x9000_FFFF`).
    RhAc,
    /// `TPMI_RH_ACT` (Part 2, Table 71): `{TPM_RH_ACT_0:TPM_RH_ACT_F}`
    /// (`0x4000_0110..=0x4000_011F`).
    RhAct,
}

impl Tpmi {
    /// Returns `true` if `handle` is a member of this interface type.
    pub(crate) fn contains(self, handle: Handle) -> bool {
        let is_null = handle == Handle::RH_NULL;
        match self {
            Self::DhObject => is_object(handle),
            Self::DhObjectOrNull => is_object(handle) || is_null,
            Self::DhParent => is_object(handle) || is_hierarchy(handle),
            Self::DhPersistent => is_type(handle, TpmHt::Persistent),
            Self::DhEntity => is_entity(handle),
            Self::DhEntityOrNull => is_entity(handle) || is_null,
            Self::DhPcr => is_pcr(handle),
            Self::DhPcrOrNull => is_pcr(handle) || is_null,
            Self::DhContext => is_session(handle) || is_transient(handle),
            Self::DhSaved => {
                is_session(handle) || (Handle(0x8000_0000)..=Handle(0x8000_0002)).contains(&handle)
            }
            Self::ShAuthSession => is_session(handle),
            Self::ShAuthSessionOrPw => is_session(handle) || handle == Handle::RS_PW,
            Self::ShHmac => is_session_of(handle, TpmHt::HMACSession),
            Self::ShPolicy => is_session_of(handle, TpmHt::PolicySession),
            Self::RhHierarchy => is_hierarchy(handle),
            Self::RhEnables => is_enables(handle),
            Self::RhEnablesOrNull => is_enables(handle) || is_null,
            Self::RhHierarchyAuth => is_hierarchy_auth(handle),
            Self::RhHierarchyAuthOrNull => is_hierarchy_auth(handle) || is_null,
            Self::RhHierarchyPolicy => is_hierarchy_auth(handle) || is_act(handle),
            Self::RhBaseHierarchy => matches!(
                handle,
                Handle::RH_OWNER | Handle::RH_PLATFORM | Handle::RH_ENDORSEMENT
            ),
            Self::RhPlatform => handle == Handle::RH_PLATFORM,
            Self::RhOwner => handle == Handle::RH_OWNER,
            Self::RhOwnerOrNull => handle == Handle::RH_OWNER || is_null,
            Self::RhEndorsement => handle == Handle::RH_ENDORSEMENT,
            Self::RhEndorsementOrNull => handle == Handle::RH_ENDORSEMENT || is_null,
            Self::RhProvision => matches!(handle, Handle::RH_OWNER | Handle::RH_PLATFORM),
            Self::RhClear => matches!(handle, Handle::RH_LOCKOUT | Handle::RH_PLATFORM),
            Self::RhNvAuth => {
                matches!(handle, Handle::RH_OWNER | Handle::RH_PLATFORM)
                    || is_type(handle, TpmHt::NVIndex)
            }
            Self::RhLockout => handle == Handle::RH_LOCKOUT,
            Self::RhNvIndex => matches!(
                handle.handle_type(),
                Some(TpmHt::NVIndex | TpmHt::ExternalNV | TpmHt::PermanentNV)
            ),
            Self::RhNvDefinedIndex => matches!(
                handle.handle_type(),
                Some(TpmHt::NVIndex | TpmHt::ExternalNV)
            ),
            Self::RhNvLegacyIndex => is_type(handle, TpmHt::NVIndex),
            Self::RhNvExpIndex => is_type(handle, TpmHt::ExternalNV),
            Self::RhAc => is_type(handle, TpmHt::AC) && index(handle) <= 0xFFFF,
            Self::RhAct => is_act(handle),
        }
    }
}

/// Checks that `handle` is a member of the interface type `ty`.
///
/// Returns `handle` on success, or `TPM_RC_VALUE` (the `#TPM_RC_*` response code of every handle
/// interface type in Part 2) qualified with `pos` (the [`Position::handle`] or
/// [`Position::parameter`] of `handle` in the command).
pub(crate) fn check(handle: Handle, ty: Tpmi, pos: Position) -> Result<Handle, TpmRc> {
    if ty.contains(handle) {
        Ok(handle)
    } else {
        Err(TpmRc::VALUE.with(pos))
    }
}

fn is_type(handle: Handle, ht: TpmHt) -> bool {
    handle.handle_type() == Some(ht)
}

fn index(handle: Handle) -> u32 {
    handle.0 & HR_HANDLE_MASK
}

/// `{TRANSIENT_FIRST:TRANSIENT_LAST}`.
fn is_transient(handle: Handle) -> bool {
    is_type(handle, TpmHt::Transient)
        && usize::try_from(index(handle)).is_ok_and(|i| i < MAX_LOADED_OBJECTS)
}

/// `{TRANSIENT_FIRST:TRANSIENT_LAST}` or `{PERSISTENT_FIRST:PERSISTENT_LAST}`.
fn is_object(handle: Handle) -> bool {
    is_transient(handle) || is_type(handle, TpmHt::Persistent)
}

/// `{PCR_FIRST:PCR_LAST}`.
fn is_pcr(handle: Handle) -> bool {
    is_type(handle, TpmHt::PCR)
        && usize::try_from(index(handle)).is_ok_and(|i| i < TpmsPcrSelect::PLATFORM_PCRS)
}

/// `{HMAC_SESSION_FIRST:HMAC_SESSION_LAST}` (`ht == HMACSession`) or
/// `{POLICY_SESSION_FIRST:POLICY_SESSION_LAST}` (`ht == PolicySession`).
fn is_session_of(handle: Handle, ht: TpmHt) -> bool {
    is_type(handle, ht) && index(handle) < MAX_ACTIVE_SESSIONS
}

/// HMAC or policy session.
fn is_session(handle: Handle) -> bool {
    is_session_of(handle, TpmHt::HMACSession) || is_session_of(handle, TpmHt::PolicySession)
}

/// `{TPM_RH_ACT_0:TPM_RH_ACT_F}`.
fn is_act(handle: Handle) -> bool {
    (Handle::RH_ACT_0..=Handle::RH_ACT_F).contains(&handle)
}

/// Members of [`Tpmi::RhHierarchy`].
fn is_hierarchy(handle: Handle) -> bool {
    matches!(
        handle,
        Handle::RH_OWNER
            | Handle::RH_PLATFORM
            | Handle::RH_ENDORSEMENT
            | Handle::RH_NULL
            | Handle::RH_FW_OWNER
            | Handle::RH_FW_ENDORSEMENT
            | Handle::RH_FW_PLATFORM
            | Handle::RH_FW_NULL
    ) || (Handle::RH_SVN_OWNER_BASE..=SVN_NULL_LAST).contains(&handle)
}

/// Members of [`Tpmi::RhEnables`].
fn is_enables(handle: Handle) -> bool {
    matches!(
        handle,
        Handle::RH_OWNER | Handle::RH_PLATFORM | Handle::RH_ENDORSEMENT | Handle::RH_PLATFORM_NV
    )
}

/// Members of [`Tpmi::RhHierarchyAuth`].
fn is_hierarchy_auth(handle: Handle) -> bool {
    matches!(
        handle,
        Handle::RH_OWNER | Handle::RH_PLATFORM | Handle::RH_ENDORSEMENT | Handle::RH_LOCKOUT
    )
}

/// Members of [`Tpmi::DhEntity`].
fn is_entity(handle: Handle) -> bool {
    is_hierarchy_auth(handle)
        || is_object(handle)
        || is_type(handle, TpmHt::NVIndex)
        || is_pcr(handle)
        || (crate::util::RH_AUTH_00..=RH_AUTH_FF).contains(&handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NULL: Handle = Handle::RH_NULL;
    const OWNER: Handle = Handle::RH_OWNER;
    const PLATFORM: Handle = Handle::RH_PLATFORM;
    const ENDORSEMENT: Handle = Handle::RH_ENDORSEMENT;
    const LOCKOUT: Handle = Handle::RH_LOCKOUT;
    const PLATFORM_NV: Handle = Handle::RH_PLATFORM_NV;
    const TRANSIENT_FIRST: Handle = Handle(0x8000_0000);
    const TRANSIENT_LAST: Handle = Handle(0x8000_000F);
    const PERSISTENT_FIRST: Handle = Handle(0x8100_0000);
    const PERSISTENT_LAST: Handle = Handle(0x81FF_FFFF);
    const NV_FIRST: Handle = Handle(0x0100_0000);
    const NV_LAST: Handle = Handle(0x01FF_FFFF);
    const EXTERNAL_NV: Handle = Handle(0x1100_0000);
    const PERMANENT_NV: Handle = Handle(0x12FF_FFFF);
    const PCR_FIRST: Handle = Handle(0);
    const PCR_LAST: Handle = Handle(23);
    const HMAC_FIRST: Handle = Handle(0x0200_0000);
    const HMAC_LAST: Handle = Handle(0x0200_003F);
    const POLICY_FIRST: Handle = Handle(0x0300_0000);
    const POLICY_LAST: Handle = Handle(0x0300_003F);
    const AUTH_00: Handle = Handle(0x4000_0010);
    const AUTH_FF: Handle = Handle(0x4000_010F);
    const ACT_0: Handle = Handle(0x4000_0110);
    const ACT_F: Handle = Handle(0x4000_011F);
    const AC_FIRST: Handle = Handle(0x9000_0000);
    const AC_LAST: Handle = Handle(0x9000_FFFF);

    /// Handles that are in no interface type at all.
    const NEVER: &[Handle] = &[
        Handle(0x4000_0000),
        Handle(0x4000_0002),
        Handle(0xFFFF_FFFF),
        Handle(0x9001_0000),
        Handle(0x2000_0000),
    ];

    /// Asserts that `ty` accepts exactly `members` among `members`, `non_members` and [`NEVER`].
    fn assert_set(ty: Tpmi, members: &[Handle], non_members: &[Handle]) {
        for &h in members {
            assert!(ty.contains(h), "{ty:?} should accept {h:?}");
        }
        for &h in non_members.iter().chain(NEVER) {
            assert!(!ty.contains(h), "{ty:?} should reject {h:?}");
        }
    }

    #[test]
    fn objects() {
        let objects = [
            TRANSIENT_FIRST,
            TRANSIENT_LAST,
            PERSISTENT_FIRST,
            PERSISTENT_LAST,
        ];
        let not_objects = [
            Handle(0x8000_0010),
            Handle(0x80FF_FFFF),
            OWNER,
            NV_FIRST,
            PCR_FIRST,
        ];
        assert_set(
            Tpmi::DhObject,
            &objects,
            &[&not_objects[..], &[NULL]].concat(),
        );
        assert_set(
            Tpmi::DhObjectOrNull,
            &[&objects[..], &[NULL]].concat(),
            &not_objects,
        );
        assert_set(
            Tpmi::DhPersistent,
            &[PERSISTENT_FIRST, PERSISTENT_LAST],
            &[TRANSIENT_FIRST, NULL, OWNER],
        );
        assert_set(
            Tpmi::DhParent,
            &[
                TRANSIENT_LAST,
                PERSISTENT_FIRST,
                OWNER,
                NULL,
                Handle::RH_FW_NULL,
            ],
            &[LOCKOUT, Handle(0x8000_0010), NV_FIRST],
        );
    }

    #[test]
    fn entities() {
        let entities = [
            OWNER,
            ENDORSEMENT,
            PLATFORM,
            LOCKOUT,
            TRANSIENT_FIRST,
            PERSISTENT_LAST,
            NV_FIRST,
            NV_LAST,
            PCR_FIRST,
            PCR_LAST,
            AUTH_00,
            AUTH_FF,
        ];
        let not_entities = [
            Handle(24),
            ACT_0,
            EXTERNAL_NV,
            PERMANENT_NV,
            PLATFORM_NV,
            HMAC_FIRST,
            Handle(0x8000_0010),
        ];
        assert_set(
            Tpmi::DhEntity,
            &entities,
            &[&not_entities[..], &[NULL]].concat(),
        );
        assert_set(
            Tpmi::DhEntityOrNull,
            &[&entities[..], &[NULL]].concat(),
            &not_entities,
        );
        assert_set(
            Tpmi::DhPcr,
            &[PCR_FIRST, PCR_LAST],
            &[Handle(24), NULL, NV_FIRST],
        );
        assert_set(
            Tpmi::DhPcrOrNull,
            &[PCR_FIRST, PCR_LAST, NULL],
            &[Handle(24)],
        );
    }

    #[test]
    fn sessions_and_contexts() {
        let sessions = [HMAC_FIRST, HMAC_LAST, POLICY_FIRST, POLICY_LAST];
        let not_sessions = [Handle(0x0200_0040), Handle(0x0300_0040), TRANSIENT_FIRST];
        assert_set(
            Tpmi::ShAuthSession,
            &sessions,
            &[&not_sessions[..], &[Handle::RS_PW]].concat(),
        );
        assert_set(
            Tpmi::ShAuthSessionOrPw,
            &[&sessions[..], &[Handle::RS_PW]].concat(),
            &not_sessions,
        );
        assert_set(
            Tpmi::ShHmac,
            &[HMAC_FIRST, HMAC_LAST],
            &[POLICY_FIRST, Handle(0x0200_0040)],
        );
        assert_set(
            Tpmi::ShPolicy,
            &[POLICY_FIRST, POLICY_LAST],
            &[HMAC_FIRST, Handle(0x0300_0040), Handle::RS_PW],
        );
        assert_set(
            Tpmi::DhContext,
            &[HMAC_FIRST, POLICY_LAST, TRANSIENT_FIRST, TRANSIENT_LAST],
            &[Handle(0x8000_0010), PERSISTENT_FIRST, Handle(0x0300_0040)],
        );
        assert_set(
            Tpmi::DhSaved,
            &[
                HMAC_LAST,
                POLICY_FIRST,
                Handle(0x8000_0000),
                Handle(0x8000_0002),
            ],
            &[Handle(0x8000_0003), PERSISTENT_FIRST],
        );
    }

    #[test]
    fn hierarchies() {
        assert_set(
            Tpmi::RhHierarchy,
            &[
                OWNER,
                PLATFORM,
                ENDORSEMENT,
                NULL,
                Handle::RH_FW_OWNER,
                Handle::RH_FW_NULL,
                Handle(0x4001_0000),
                Handle(0x4004_FFFF),
            ],
            &[
                LOCKOUT,
                PLATFORM_NV,
                Handle(0x4005_0000),
                Handle(0x4000_FFFF),
            ],
        );
        assert_set(
            Tpmi::RhEnables,
            &[OWNER, PLATFORM, ENDORSEMENT, PLATFORM_NV],
            &[NULL, LOCKOUT],
        );
        assert_set(Tpmi::RhEnablesOrNull, &[PLATFORM_NV, NULL], &[LOCKOUT]);
        assert_set(
            Tpmi::RhHierarchyAuth,
            &[OWNER, PLATFORM, ENDORSEMENT, LOCKOUT],
            &[NULL, PLATFORM_NV],
        );
        assert_set(
            Tpmi::RhHierarchyAuthOrNull,
            &[LOCKOUT, NULL],
            &[PLATFORM_NV],
        );
        assert_set(
            Tpmi::RhHierarchyPolicy,
            &[OWNER, LOCKOUT, ACT_0, ACT_F],
            &[NULL, Handle(0x4000_0120)],
        );
        assert_set(
            Tpmi::RhBaseHierarchy,
            &[OWNER, PLATFORM, ENDORSEMENT],
            &[NULL, LOCKOUT],
        );
        assert_set(Tpmi::RhPlatform, &[PLATFORM], &[OWNER, NULL]);
        assert_set(Tpmi::RhOwner, &[OWNER], &[PLATFORM, NULL]);
        assert_set(Tpmi::RhOwnerOrNull, &[OWNER, NULL], &[PLATFORM]);
        assert_set(Tpmi::RhEndorsement, &[ENDORSEMENT], &[OWNER, NULL]);
        assert_set(Tpmi::RhEndorsementOrNull, &[ENDORSEMENT, NULL], &[OWNER]);
        assert_set(Tpmi::RhProvision, &[OWNER, PLATFORM], &[ENDORSEMENT, NULL]);
        assert_set(Tpmi::RhClear, &[LOCKOUT, PLATFORM], &[OWNER, NULL]);
        assert_set(Tpmi::RhLockout, &[LOCKOUT], &[OWNER, NULL]);
        assert_set(Tpmi::RhAct, &[ACT_0, ACT_F], &[Handle(0x4000_0120), OWNER]);
        assert_set(
            Tpmi::RhAc,
            &[AC_FIRST, AC_LAST],
            &[Handle(0x9001_0000), OWNER],
        );
    }

    #[test]
    fn nv() {
        assert_set(
            Tpmi::RhNvAuth,
            &[OWNER, PLATFORM, NV_FIRST, NV_LAST],
            &[ENDORSEMENT, NULL, EXTERNAL_NV, PERMANENT_NV],
        );
        assert_set(
            Tpmi::RhNvIndex,
            &[NV_FIRST, NV_LAST, EXTERNAL_NV, PERMANENT_NV],
            &[OWNER, Handle(0x1300_0000)],
        );
        assert_set(
            Tpmi::RhNvDefinedIndex,
            &[NV_FIRST, EXTERNAL_NV],
            &[PERMANENT_NV, OWNER],
        );
        assert_set(Tpmi::RhNvLegacyIndex, &[NV_FIRST, NV_LAST], &[EXTERNAL_NV]);
        assert_set(
            Tpmi::RhNvExpIndex,
            &[EXTERNAL_NV],
            &[NV_FIRST, PERMANENT_NV],
        );
    }

    #[test]
    fn check_reports_value_at_position() {
        assert_eq!(
            check(POLICY_FIRST, Tpmi::ShPolicy, Position::handle(1)),
            Ok(POLICY_FIRST)
        );
        assert_eq!(
            check(HMAC_FIRST, Tpmi::ShPolicy, Position::handle(2)),
            Err(TpmRc::VALUE.with(Position::handle(2)))
        );
        assert_eq!(
            check(LOCKOUT, Tpmi::RhHierarchy, Position::parameter(4)),
            Err(TpmRc::VALUE.with(Position::parameter(4)))
        );
    }
}
