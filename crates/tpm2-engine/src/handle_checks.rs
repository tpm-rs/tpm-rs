//! Range checks for the handle interface types (`TPMI_DH_*`, `TPMI_SH_*`, `TPMI_RH_*`) defined in
//! TPM 2.0 Part 2, Section 9 ("Interface Types").
//!
//! Every handle area entry and handle-typed parameter / structure field in Part 3 has one of these
//! interface types. A handle outside the type's set of values must be rejected with the type's
//! `#TPM_RC_*` response code, which is `TPM_RC_VALUE` for every handle interface type in Part 2,
//! qualified with the [`Position`] of the offending handle or parameter.
//!
//! PORTING: exp's `tpm2` crate typed the command handle areas: each `XxxHandles` struct
//! unmarshaled its fields through a `tpm2::Tpmi*` type (for example
//! `TpmiDhObject::<false>::unmarshal(src).map_err(|e| e.in_handle(1))`), so out-of-range handles
//! were rejected while unmarshaling. In the upstream command design every handle is a plain
//! [`Handle`] (`Message::Handles = [Handle; N]`), so handlers re-check them explicitly, in handle
//! order, at the point where exp called `request.try_unmarshal::<XxxHandles>()`:
//!
//! ```text
//! let [auth_object, policy_session] = request.try_unmarshal_handles::<PolicySigned>()?;
//! check(auth_object, Tpmi::DhObject, Position::handle(1))?;
//! check(policy_session, Tpmi::ShPolicy, Position::handle(2))?;
//! ```
//!
//! Each [`Tpmi`] variant accepts exactly the handles that the corresponding exp type accepted (its
//! `TryFrom<Handle>` impl), using the same `Handle` range constants, and [`check`] returns exactly
//! the response code exp produced (`UnmarshalError::VALUE.in_handle(n)` converted to a
//! [`TpmRc`]). Exp's types and their variants:
//!
//! | exp type | variant | exp type | variant |
//! |---|---|---|---|
//! | `TpmiDhObject<false>` | [`Tpmi::DhObject`] | `TpmiRhHierarchyAuth<false>` | [`Tpmi::RhHierarchyAuth`] |
//! | `TpmiDhObject<true>` | [`Tpmi::DhObjectOrNull`] | `TpmiRhHierarchyAuth<true>` | [`Tpmi::RhHierarchyAuthOrNull`] |
//! | `TpmiDhParent` | [`Tpmi::DhParent`] | `TpmiRhHierarchyPolicy` | [`Tpmi::RhHierarchyPolicy`] |
//! | `TpmiDhPersistent` | [`Tpmi::DhPersistent`] | `TpmiRhBaseHierarchy` | [`Tpmi::RhBaseHierarchy`] |
//! | `TpmiDhEntity<false>` | [`Tpmi::DhEntity`] | `TpmiRhPlatform` | [`Tpmi::RhPlatform`] |
//! | `TpmiDhEntity<true>` | [`Tpmi::DhEntityOrNull`] | `TpmiRhOwner<false>` | [`Tpmi::RhOwner`] |
//! | `TpmiDhPcr<false>` | [`Tpmi::DhPcr`] | `TpmiRhOwner<true>` | [`Tpmi::RhOwnerOrNull`] |
//! | `TpmiDhPcr<true>` | [`Tpmi::DhPcrOrNull`] | `TpmiRhEndorsement<false>` | [`Tpmi::RhEndorsement`] |
//! | `TpmiDhContext` | [`Tpmi::DhContext`] | `TpmiRhEndorsement<true>` | [`Tpmi::RhEndorsementOrNull`] |
//! | `TpmiDhSaved` | [`Tpmi::DhSaved`] | `TpmiRhProvision` | [`Tpmi::RhProvision`] |
//! | `TpmiShAuthSession<false>` | [`Tpmi::ShAuthSession`] | `TpmiRhClear` | [`Tpmi::RhClear`] |
//! | `TpmiShAuthSession<true>` | [`Tpmi::ShAuthSessionOrPw`] | `TpmiRhNvAuth` | [`Tpmi::RhNvAuth`] |
//! | `TpmiShHmac` | [`Tpmi::ShHmac`] | `TpmiRhLockout` | [`Tpmi::RhLockout`] |
//! | `TpmiShPolicy` | [`Tpmi::ShPolicy`] | `TpmiRhNvIndex` | [`Tpmi::RhNvIndex`] |
//! | `TpmiRhHierarchy` | [`Tpmi::RhHierarchy`] | `TpmiRhNvDefinedIndex` | [`Tpmi::RhNvDefinedIndex`] |
//! | `TpmiRhEnables<false>` | [`Tpmi::RhEnables`] | `TpmiRhNvLegacyIndex` | [`Tpmi::RhNvLegacyIndex`] |
//! | `TpmiRhEnables<true>` | [`Tpmi::RhEnablesOrNull`] | `TpmiRhNvExpIndex` | [`Tpmi::RhNvExpIndex`] |
//! | | | `TpmiRhAc` | [`Tpmi::RhAc`] |
//! | | | `TpmiRhAct` | [`Tpmi::RhAct`] |
//!
//! These checks only replace exp's typed `XxxHandles` unmarshaling. Handle-typed request
//! *parameters* (for example `TPM2_FlushContext.flushHandle`) are still validated by the command's
//! `unmarshal_with_handles` in the `tpm2` crate, and the engine's own command-level handle
//! validation is unchanged.

use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmCc};

/// The last of the three saved object context handles of `TPMI_DH_SAVED` (Part 2, Table 53):
/// `0x8000_0000` (an ordinary transient object), `0x8000_0001` (a sequence object) and
/// `0x8000_0002` (a transient object with the `stClear` attribute SET).
const SAVED_OBJECT_CONTEXT_LAST: Handle = Handle(0x8000_0002);

/// A handle interface type (`TPMI_*` with a `TPM_HANDLE` base type).
///
/// Variants ending in `OrNull` are the `+` forms (e.g. `TPMI_DH_OBJECT+`), which additionally
/// accept `TPM_RH_NULL`; [`Tpmi::ShAuthSessionOrPw`] (`TPMI_SH_AUTH_SESSION+`) additionally accepts
/// `TPM_RS_PW`. Ranges use the implementation values of this TPM (the `Handle` constants of the
/// `tpm2` crate): `TRANSIENT_LAST = TRANSIENT_FIRST + MAX_LOADED_OBJECTS - 1` (`0x8000_0002`),
/// `HMAC_SESSION_LAST` / `POLICY_SESSION_LAST = *_FIRST + MAX_ACTIVE_SESSIONS - 1`
/// (`0x0200_003F` / `0x0300_003F`), and `PCR_LAST = PCR_FIRST + IMPLEMENTATION_PCR - 1` (`23`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // Lists every TPMI handle type, including ones no command checks yet.
pub(crate) enum Tpmi {
    /// `TPMI_DH_OBJECT` (Part 2, Table 44), exp's `TpmiDhObject<false>`: transient objects
    /// `{TRANSIENT_FIRST:TRANSIENT_LAST}` and persistent objects
    /// `{PERSISTENT_FIRST:PERSISTENT_LAST}` (`0x8100_0000..=0x81FF_FFFF`).
    DhObject,
    /// `TPMI_DH_OBJECT+`, exp's `TpmiDhObject<true>`: [`Tpmi::DhObject`] or `TPM_RH_NULL`.
    DhObjectOrNull,
    /// `TPMI_DH_PARENT` (Part 2, Table 45), exp's `TpmiDhParent`: transient and persistent
    /// objects, or any [`Tpmi::RhHierarchy`] value.
    DhParent,
    /// `TPMI_DH_PERSISTENT` (Part 2, Table 46), exp's `TpmiDhPersistent`:
    /// `{PERSISTENT_FIRST:PERSISTENT_LAST}`.
    DhPersistent,
    /// `TPMI_DH_ENTITY` (Part 2, Table 47), exp's `TpmiDhEntity<false>`: `TPM_RH_OWNER`,
    /// `TPM_RH_ENDORSEMENT`, `TPM_RH_PLATFORM`, `TPM_RH_LOCKOUT`, transient and persistent
    /// objects, `{NV_INDEX_FIRST:NV_INDEX_LAST}` (`0x0100_0000..=0x01FF_FFFF`),
    /// `{PCR_FIRST:PCR_LAST}` and `{TPM_RH_AUTH_00:TPM_RH_AUTH_FF}` (`0x4000_0010..=0x4000_010F`).
    DhEntity,
    /// `TPMI_DH_ENTITY+`, exp's `TpmiDhEntity<true>`: [`Tpmi::DhEntity`] or `TPM_RH_NULL`.
    DhEntityOrNull,
    /// `TPMI_DH_PCR` (Part 2, Table 48), exp's `TpmiDhPcr<false>`: `{PCR_FIRST:PCR_LAST}`.
    DhPcr,
    /// `TPMI_DH_PCR+`, exp's `TpmiDhPcr<true>`: [`Tpmi::DhPcr`] or `TPM_RH_NULL`.
    DhPcrOrNull,
    /// `TPMI_DH_CONTEXT` (Part 2, Table 52), exp's `TpmiDhContext`: HMAC sessions, policy
    /// sessions and transient objects.
    DhContext,
    /// `TPMI_DH_SAVED` (Part 2, Table 53), exp's `TpmiDhSaved`: HMAC sessions, policy sessions,
    /// and the saved object context handles `0x8000_0000` (object), `0x8000_0001` (sequence) and
    /// `0x8000_0002` (`stClear` object).
    DhSaved,
    /// `TPMI_SH_AUTH_SESSION` (Part 2, Table 49), exp's `TpmiShAuthSession<false>`:
    /// `{HMAC_SESSION_FIRST:HMAC_SESSION_LAST}` and `{POLICY_SESSION_FIRST:POLICY_SESSION_LAST}`.
    ShAuthSession,
    /// `TPMI_SH_AUTH_SESSION+`, exp's `TpmiShAuthSession<true>`: [`Tpmi::ShAuthSession`] or
    /// `TPM_RS_PW`.
    ShAuthSessionOrPw,
    /// `TPMI_SH_HMAC` (Part 2, Table 50), exp's `TpmiShHmac`:
    /// `{HMAC_SESSION_FIRST:HMAC_SESSION_LAST}`.
    ShHmac,
    /// `TPMI_SH_POLICY` (Part 2, Table 51), exp's `TpmiShPolicy`:
    /// `{POLICY_SESSION_FIRST:POLICY_SESSION_LAST}`.
    ShPolicy,
    /// `TPMI_RH_HIERARCHY` (Part 2, Table 54), exp's `TpmiRhHierarchy` (`Handle::is_hierarchy`):
    /// `TPM_RH_OWNER`, `TPM_RH_PLATFORM`, `TPM_RH_ENDORSEMENT`, `TPM_RH_NULL`, the
    /// firmware-limited hierarchies `TPM_RH_FW_{OWNER,ENDORSEMENT,PLATFORM,NULL}`
    /// (`0x4000_0140..=0x4000_0143`) and the SVN-limited hierarchies
    /// `{SVN_OWNER_FIRST:SVN_NULL_LAST}` (`0x4001_0000..=0x4004_FFFF`).
    ///
    /// `TPM_RH_NULL` is an unconditional member, so `TPMI_RH_HIERARCHY+` is the same set.
    RhHierarchy,
    /// `TPMI_RH_ENABLES` (Part 2, Table 55), exp's `TpmiRhEnables<false>`: `TPM_RH_OWNER`,
    /// `TPM_RH_PLATFORM`, `TPM_RH_ENDORSEMENT` and `TPM_RH_PLATFORM_NV`.
    RhEnables,
    /// `TPMI_RH_ENABLES+`, exp's `TpmiRhEnables<true>`: [`Tpmi::RhEnables`] or `TPM_RH_NULL`.
    RhEnablesOrNull,
    /// `TPMI_RH_HIERARCHY_AUTH` (Part 2, Table 56), exp's `TpmiRhHierarchyAuth<false>`:
    /// `TPM_RH_OWNER`, `TPM_RH_PLATFORM`, `TPM_RH_ENDORSEMENT` and `TPM_RH_LOCKOUT`.
    RhHierarchyAuth,
    /// `TPMI_RH_HIERARCHY_AUTH+`, exp's `TpmiRhHierarchyAuth<true>`: [`Tpmi::RhHierarchyAuth`]
    /// or `TPM_RH_NULL`.
    RhHierarchyAuthOrNull,
    /// `TPMI_RH_HIERARCHY_POLICY` (Part 2, Table 57), exp's `TpmiRhHierarchyPolicy`:
    /// `TPM_RH_OWNER`, `TPM_RH_PLATFORM`, `TPM_RH_ENDORSEMENT`, `TPM_RH_LOCKOUT` and
    /// `{TPM_RH_ACT_0:TPM_RH_ACT_F}`.
    RhHierarchyPolicy,
    /// `TPMI_RH_BASE_HIERARCHY` (Part 2, Table 58), exp's `TpmiRhBaseHierarchy`:
    /// `TPM_RH_OWNER`, `TPM_RH_PLATFORM` and `TPM_RH_ENDORSEMENT`.
    RhBaseHierarchy,
    /// `TPMI_RH_PLATFORM` (Part 2, Table 59), exp's `TpmiRhPlatform`: `TPM_RH_PLATFORM`.
    RhPlatform,
    /// `TPMI_RH_OWNER` (Part 2, Table 60), exp's `TpmiRhOwner<false>`: `TPM_RH_OWNER`.
    RhOwner,
    /// `TPMI_RH_OWNER+`, exp's `TpmiRhOwner<true>`: `TPM_RH_OWNER` or `TPM_RH_NULL`.
    RhOwnerOrNull,
    /// `TPMI_RH_ENDORSEMENT` (Part 2, Table 61), exp's `TpmiRhEndorsement<false>`:
    /// `TPM_RH_ENDORSEMENT`.
    RhEndorsement,
    /// `TPMI_RH_ENDORSEMENT+`, exp's `TpmiRhEndorsement<true>`: `TPM_RH_ENDORSEMENT` or
    /// `TPM_RH_NULL`.
    RhEndorsementOrNull,
    /// `TPMI_RH_PROVISION` (Part 2, Table 62), exp's `TpmiRhProvision`: `TPM_RH_OWNER` and
    /// `TPM_RH_PLATFORM`.
    RhProvision,
    /// `TPMI_RH_CLEAR` (Part 2, Table 63), exp's `TpmiRhClear`: `TPM_RH_LOCKOUT` and
    /// `TPM_RH_PLATFORM`.
    RhClear,
    /// `TPMI_RH_NV_AUTH` (Part 2, Table 64), exp's `TpmiRhNvAuth`: `TPM_RH_PLATFORM`,
    /// `TPM_RH_OWNER` and `{NV_INDEX_FIRST:NV_INDEX_LAST}`.
    RhNvAuth,
    /// `TPMI_RH_LOCKOUT` (Part 2, Table 65), exp's `TpmiRhLockout`: `TPM_RH_LOCKOUT`.
    RhLockout,
    /// `TPMI_RH_NV_INDEX` (Part 2, Table 66), exp's `TpmiRhNvIndex`:
    /// `{NV_INDEX_FIRST:NV_INDEX_LAST}`, `{EXTERNAL_NV_FIRST:EXTERNAL_NV_LAST}`
    /// (`0x1100_0000..=0x11FF_FFFF`) and `{PERMANENT_NV_FIRST:PERMANENT_NV_LAST}`
    /// (`0x1200_0000..=0x12FF_FFFF`).
    RhNvIndex,
    /// `TPMI_RH_NV_DEFINED_INDEX` (Part 2, Table 67), exp's `TpmiRhNvDefinedIndex`:
    /// `{NV_INDEX_FIRST:NV_INDEX_LAST}` and `{EXTERNAL_NV_FIRST:EXTERNAL_NV_LAST}`.
    RhNvDefinedIndex,
    /// `TPMI_RH_NV_LEGACY_INDEX` (Part 2, Table 68), exp's `TpmiRhNvLegacyIndex`:
    /// `{NV_INDEX_FIRST:NV_INDEX_LAST}`.
    RhNvLegacyIndex,
    /// `TPMI_RH_NV_EXP_INDEX` (Part 2, Table 69), exp's `TpmiRhNvExpIndex`:
    /// `{EXTERNAL_NV_FIRST:EXTERNAL_NV_LAST}`.
    RhNvExpIndex,
    /// `TPMI_RH_AC` (Part 2, Table 70), exp's `TpmiRhAc`: `{AC_FIRST:AC_LAST}`
    /// (`0x9000_0000..=0x9000_FFFF`).
    RhAc,
    /// `TPMI_RH_ACT` (Part 2, Table 71), exp's `TpmiRhAct`: `{TPM_RH_ACT_0:TPM_RH_ACT_F}`
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
            Self::DhParent => is_object(handle) || handle.is_hierarchy(),
            Self::DhPersistent => is_persistent(handle),
            Self::DhEntity => is_entity(handle),
            Self::DhEntityOrNull => is_entity(handle) || is_null,
            Self::DhPcr => is_pcr(handle),
            Self::DhPcrOrNull => is_pcr(handle) || is_null,
            Self::DhContext => is_session(handle) || is_transient(handle),
            Self::DhSaved => {
                is_session(handle)
                    || (Handle::TRANSIENT_FIRST..=SAVED_OBJECT_CONTEXT_LAST).contains(&handle)
            }
            Self::ShAuthSession => is_session(handle),
            Self::ShAuthSessionOrPw => is_session(handle) || handle == Handle::RS_PW,
            Self::ShHmac => is_hmac_session(handle),
            Self::ShPolicy => is_policy_session(handle),
            Self::RhHierarchy => handle.is_hierarchy(),
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
                matches!(handle, Handle::RH_OWNER | Handle::RH_PLATFORM) || is_nv_index(handle)
            }
            Self::RhLockout => handle == Handle::RH_LOCKOUT,
            Self::RhNvIndex => {
                is_nv_index(handle)
                    || is_external_nv(handle)
                    || (Handle::PERMANENT_NV_FIRST..=Handle::PERMANENT_NV_LAST).contains(&handle)
            }
            Self::RhNvDefinedIndex => is_nv_index(handle) || is_external_nv(handle),
            Self::RhNvLegacyIndex => is_nv_index(handle),
            Self::RhNvExpIndex => is_external_nv(handle),
            Self::RhAc => (Handle::AC_FIRST..=Handle::AC_LAST).contains(&handle),
            Self::RhAct => is_act(handle),
        }
    }
}

/// Checks that `handle` is a member of the interface type `ty`.
///
/// Returns `handle` on success, or `TPM_RC_VALUE` (the `#TPM_RC_*` response code of every handle
/// interface type in Part 2) qualified with `pos` (the [`Position::handle`] or
/// [`Position::parameter`] of `handle` in the command). This is the value exp returned for an
/// out-of-range handle, `UnmarshalError::VALUE.in_handle(n)` converted to a [`TpmRc`].
pub(crate) fn check(handle: Handle, ty: Tpmi, pos: Position) -> Result<Handle, TpmRc> {
    if ty.contains(handle) {
        Ok(handle)
    } else {
        Err(TpmRc::VALUE.with(pos))
    }
}

/// The interface types of the handle area of command `cc` (TPM 2.0 Part 3, the `Handles`
/// of each command's request table), in handle order; empty for a command without handles or
/// an unknown command code.
///
/// The engine checks every handle against its type before it checks whether any handle
/// references an available entity, as the C reference's `ParseHandleBuffer` unmarshals the
/// whole handle area before `EntityGetLoadStatus` runs.
///
/// The types are the `Handles` rows of each command table, e.g. TPM 2.0 Part 3,
/// TPM2_CreateLoaded: "TPMI_DH_PARENT | \@parentHandle | Handle of a transient storage key, a
/// persistent storage key, TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP}, or
/// TPM_RH_NULL", and TPM2_RSA_Decrypt: "TPMI_DH_OBJECT | \@keyHandle | RSA key to use for
/// decryption" (no `+`, so `TPM_RH_NULL` is `TPM_RC_VALUE`).
pub(crate) fn command_handle_types(cc: TpmCc) -> &'static [Tpmi] {
    match cc {
        TpmCc::NVUndefineSpaceSpecial => &[Tpmi::RhNvDefinedIndex, Tpmi::RhPlatform],
        TpmCc::EvictControl => &[Tpmi::RhProvision, Tpmi::DhObject],
        TpmCc::HierarchyControl => &[Tpmi::RhBaseHierarchy],
        TpmCc::NVUndefineSpace => &[Tpmi::RhProvision, Tpmi::RhNvDefinedIndex],
        TpmCc::ChangeEPS => &[Tpmi::RhPlatform],
        TpmCc::ChangePPS => &[Tpmi::RhPlatform],
        TpmCc::Clear => &[Tpmi::RhClear],
        TpmCc::ClearControl => &[Tpmi::RhClear],
        TpmCc::ClockSet => &[Tpmi::RhProvision],
        TpmCc::HierarchyChangeAuth => &[Tpmi::RhHierarchyAuth],
        TpmCc::NVDefineSpace => &[Tpmi::RhProvision],
        TpmCc::PCRAllocate => &[Tpmi::RhPlatform],
        TpmCc::PCRSetAuthPolicy => &[Tpmi::RhPlatform],
        TpmCc::PPCommands => &[Tpmi::RhPlatform],
        TpmCc::SetPrimaryPolicy => &[Tpmi::RhHierarchyPolicy],
        TpmCc::FieldUpgradeStart => &[Tpmi::RhPlatform, Tpmi::DhObject],
        TpmCc::ClockRateAdjust => &[Tpmi::RhProvision],
        TpmCc::CreatePrimary => &[Tpmi::RhHierarchy],
        TpmCc::NVGlobalWriteLock => &[Tpmi::RhProvision],
        TpmCc::GetCommandAuditDigest => &[Tpmi::RhEndorsement, Tpmi::DhObjectOrNull],
        TpmCc::NVIncrement => &[Tpmi::RhNvAuth, Tpmi::RhNvIndex],
        TpmCc::NVSetBits => &[Tpmi::RhNvAuth, Tpmi::RhNvIndex],
        TpmCc::NVExtend => &[Tpmi::RhNvAuth, Tpmi::RhNvIndex],
        TpmCc::NVWrite => &[Tpmi::RhNvAuth, Tpmi::RhNvIndex],
        TpmCc::NVWriteLock => &[Tpmi::RhNvAuth, Tpmi::RhNvIndex],
        TpmCc::DictionaryAttackLockReset => &[Tpmi::RhLockout],
        TpmCc::DictionaryAttackParameters => &[Tpmi::RhLockout],
        TpmCc::NVChangeAuth => &[Tpmi::RhNvIndex],
        TpmCc::PCREvent => &[Tpmi::DhPcrOrNull],
        TpmCc::PCRReset => &[Tpmi::DhPcr],
        TpmCc::SequenceComplete => &[Tpmi::DhObject],
        TpmCc::SetAlgorithmSet => &[Tpmi::RhPlatform],
        TpmCc::SetCommandCodeAuditStatus => &[Tpmi::RhProvision],
        TpmCc::ActivateCredential => &[Tpmi::DhObject, Tpmi::DhObject],
        TpmCc::Certify => &[Tpmi::DhObject, Tpmi::DhObjectOrNull],
        TpmCc::PolicyNV => &[Tpmi::RhNvAuth, Tpmi::RhNvIndex, Tpmi::ShPolicy],
        TpmCc::CertifyCreation => &[Tpmi::DhObjectOrNull, Tpmi::DhObject],
        TpmCc::Duplicate => &[Tpmi::DhObject, Tpmi::DhObjectOrNull],
        TpmCc::GetTime => &[Tpmi::RhEndorsement, Tpmi::DhObjectOrNull],
        TpmCc::GetSessionAuditDigest => &[Tpmi::RhEndorsement, Tpmi::DhObjectOrNull, Tpmi::ShHmac],
        TpmCc::NVRead => &[Tpmi::RhNvAuth, Tpmi::RhNvIndex],
        TpmCc::NVReadLock => &[Tpmi::RhNvAuth, Tpmi::RhNvIndex],
        TpmCc::ObjectChangeAuth => &[Tpmi::DhObject, Tpmi::DhObject],
        TpmCc::PolicySecret => &[Tpmi::DhEntity, Tpmi::ShPolicy],
        TpmCc::Rewrap => &[Tpmi::DhObjectOrNull, Tpmi::DhObjectOrNull],
        TpmCc::Create => &[Tpmi::DhObject],
        TpmCc::ECDHZGen => &[Tpmi::DhObject],
        TpmCc::MAC => &[Tpmi::DhObject],
        TpmCc::Import => &[Tpmi::DhObject],
        TpmCc::Load => &[Tpmi::DhObject],
        TpmCc::Quote => &[Tpmi::DhObjectOrNull],
        // `TPMI_DH_OBJECT` (Part 3, TPM2_RSA_Decrypt).
        TpmCc::RSADecrypt => &[Tpmi::DhObject],
        TpmCc::MACStart => &[Tpmi::DhObject],
        TpmCc::SequenceUpdate => &[Tpmi::DhObject],
        TpmCc::Sign => &[Tpmi::DhObject],
        TpmCc::Unseal => &[Tpmi::DhObject],
        TpmCc::PolicySigned => &[Tpmi::DhObject, Tpmi::ShPolicy],
        TpmCc::ContextSave => &[Tpmi::DhContext],
        TpmCc::ECDHKeyGen => &[Tpmi::DhObject],
        TpmCc::EncryptDecrypt => &[Tpmi::DhObject],
        TpmCc::MakeCredential => &[Tpmi::DhObject],
        TpmCc::NVReadPublic => &[Tpmi::RhNvIndex],
        TpmCc::PolicyAuthorize => &[Tpmi::ShPolicy],
        TpmCc::PolicyAuthValue => &[Tpmi::ShPolicy],
        TpmCc::PolicyCommandCode => &[Tpmi::ShPolicy],
        TpmCc::PolicyCounterTimer => &[Tpmi::ShPolicy],
        TpmCc::PolicyCpHash => &[Tpmi::ShPolicy],
        TpmCc::PolicyLocality => &[Tpmi::ShPolicy],
        TpmCc::PolicyNameHash => &[Tpmi::ShPolicy],
        TpmCc::PolicyOR => &[Tpmi::ShPolicy],
        TpmCc::PolicyTicket => &[Tpmi::ShPolicy],
        TpmCc::ReadPublic => &[Tpmi::DhObject],
        TpmCc::RSAEncrypt => &[Tpmi::DhObject],
        TpmCc::StartAuthSession => &[Tpmi::DhObjectOrNull, Tpmi::DhEntityOrNull],
        TpmCc::VerifySignature => &[Tpmi::DhObject],
        TpmCc::PolicyPCR => &[Tpmi::ShPolicy],
        TpmCc::PolicyRestart => &[Tpmi::ShPolicy],
        TpmCc::PCRExtend => &[Tpmi::DhPcrOrNull],
        TpmCc::PCRSetAuthValue => &[Tpmi::DhPcr],
        TpmCc::NVCertify => &[Tpmi::DhObjectOrNull, Tpmi::RhNvAuth, Tpmi::RhNvIndex],
        TpmCc::EventSequenceComplete => &[Tpmi::DhPcrOrNull, Tpmi::DhObject],
        TpmCc::PolicyPhysicalPresence => &[Tpmi::ShPolicy],
        TpmCc::PolicyDuplicationSelect => &[Tpmi::ShPolicy],
        TpmCc::PolicyGetDigest => &[Tpmi::ShPolicy],
        TpmCc::Commit => &[Tpmi::DhObject],
        TpmCc::PolicyPassword => &[Tpmi::ShPolicy],
        TpmCc::ZGen2Phase => &[Tpmi::DhObject],
        TpmCc::PolicyNvWritten => &[Tpmi::ShPolicy],
        TpmCc::PolicyTemplate => &[Tpmi::ShPolicy],
        // `TPMI_DH_PARENT+` (Part 3, TPM2_CreateLoaded).
        TpmCc::CreateLoaded => &[Tpmi::DhParent],
        TpmCc::PolicyAuthorizeNV => &[Tpmi::RhNvAuth, Tpmi::RhNvIndex, Tpmi::ShPolicy],
        TpmCc::EncryptDecrypt2 => &[Tpmi::DhObject],
        TpmCc::ACTSetTimeout => &[Tpmi::RhAct],
        TpmCc::ECCEncrypt => &[Tpmi::DhObject],
        TpmCc::ECCDecrypt => &[Tpmi::DhObject],
        TpmCc::PolicyCapability => &[Tpmi::ShPolicy],
        TpmCc::PolicyParameters => &[Tpmi::ShPolicy],
        TpmCc::NVDefineSpace2 => &[Tpmi::RhProvision],
        TpmCc::NVReadPublic2 => &[Tpmi::RhNvIndex],
        TpmCc::SetCapability => &[Tpmi::RhHierarchyAuth],
        TpmCc::ReadOnlyControl => &[Tpmi::RhPlatform],
        TpmCc::PolicyTransportSPDM => &[Tpmi::ShPolicy],
        _ => &[],
    }
}

/// `{TRANSIENT_FIRST:TRANSIENT_LAST}`.
fn is_transient(handle: Handle) -> bool {
    (Handle::TRANSIENT_FIRST..=Handle::TRANSIENT_LAST).contains(&handle)
}

/// `{PERSISTENT_FIRST:PERSISTENT_LAST}`.
fn is_persistent(handle: Handle) -> bool {
    (Handle::PERSISTENT_FIRST..=Handle::PERSISTENT_LAST).contains(&handle)
}

/// `{TRANSIENT_FIRST:TRANSIENT_LAST}` or `{PERSISTENT_FIRST:PERSISTENT_LAST}`.
fn is_object(handle: Handle) -> bool {
    is_transient(handle) || is_persistent(handle)
}

/// `{PCR_FIRST:PCR_LAST}`.
fn is_pcr(handle: Handle) -> bool {
    (Handle::PCR_FIRST..=Handle::PCR_LAST).contains(&handle)
}

/// `{NV_INDEX_FIRST:NV_INDEX_LAST}`.
fn is_nv_index(handle: Handle) -> bool {
    (Handle::NV_INDEX_FIRST..=Handle::NV_INDEX_LAST).contains(&handle)
}

/// `{EXTERNAL_NV_FIRST:EXTERNAL_NV_LAST}`.
fn is_external_nv(handle: Handle) -> bool {
    (Handle::EXTERNAL_NV_FIRST..=Handle::EXTERNAL_NV_LAST).contains(&handle)
}

/// `{HMAC_SESSION_FIRST:HMAC_SESSION_LAST}`.
fn is_hmac_session(handle: Handle) -> bool {
    (Handle::HMAC_SESSION_FIRST..=Handle::HMAC_SESSION_LAST).contains(&handle)
}

/// `{POLICY_SESSION_FIRST:POLICY_SESSION_LAST}`.
fn is_policy_session(handle: Handle) -> bool {
    (Handle::POLICY_SESSION_FIRST..=Handle::POLICY_SESSION_LAST).contains(&handle)
}

/// HMAC or policy session.
fn is_session(handle: Handle) -> bool {
    is_hmac_session(handle) || is_policy_session(handle)
}

/// `{TPM_RH_ACT_0:TPM_RH_ACT_F}`.
fn is_act(handle: Handle) -> bool {
    (Handle::RH_ACT_0..=Handle::RH_ACT_F).contains(&handle)
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
        || is_nv_index(handle)
        || is_pcr(handle)
        || (Handle::RH_AUTH_00..=Handle::RH_AUTH_FF).contains(&handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpm2::errors::UnmarshalError;
    use tpm2::{
        TpmiDhContext, TpmiDhEntity, TpmiDhObject, TpmiDhParent, TpmiDhPcr, TpmiDhPersistent,
        TpmiDhSaved, TpmiRhAc, TpmiRhAct, TpmiRhBaseHierarchy, TpmiRhClear, TpmiRhEnables,
        TpmiRhEndorsement, TpmiRhHierarchy, TpmiRhHierarchyAuth, TpmiRhHierarchyPolicy,
        TpmiRhLockout, TpmiRhNvAuth, TpmiRhNvDefinedIndex, TpmiRhNvExpIndex, TpmiRhNvIndex,
        TpmiRhNvLegacyIndex, TpmiRhOwner, TpmiRhPlatform, TpmiRhProvision, TpmiShAuthSession,
        TpmiShHmac, TpmiShPolicy,
    };

    const NULL: Handle = Handle::RH_NULL;
    const OWNER: Handle = Handle::RH_OWNER;
    const PLATFORM: Handle = Handle::RH_PLATFORM;
    const ENDORSEMENT: Handle = Handle::RH_ENDORSEMENT;
    const LOCKOUT: Handle = Handle::RH_LOCKOUT;
    const PLATFORM_NV: Handle = Handle::RH_PLATFORM_NV;
    const TRANSIENT_FIRST: Handle = Handle(0x8000_0000);
    const TRANSIENT_LAST: Handle = Handle(0x8000_0002);
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

    /// Every [`Tpmi`] variant.
    const ALL: [Tpmi; 36] = [
        Tpmi::DhObject,
        Tpmi::DhObjectOrNull,
        Tpmi::DhParent,
        Tpmi::DhPersistent,
        Tpmi::DhEntity,
        Tpmi::DhEntityOrNull,
        Tpmi::DhPcr,
        Tpmi::DhPcrOrNull,
        Tpmi::DhContext,
        Tpmi::DhSaved,
        Tpmi::ShAuthSession,
        Tpmi::ShAuthSessionOrPw,
        Tpmi::ShHmac,
        Tpmi::ShPolicy,
        Tpmi::RhHierarchy,
        Tpmi::RhEnables,
        Tpmi::RhEnablesOrNull,
        Tpmi::RhHierarchyAuth,
        Tpmi::RhHierarchyAuthOrNull,
        Tpmi::RhHierarchyPolicy,
        Tpmi::RhBaseHierarchy,
        Tpmi::RhPlatform,
        Tpmi::RhOwner,
        Tpmi::RhOwnerOrNull,
        Tpmi::RhEndorsement,
        Tpmi::RhEndorsementOrNull,
        Tpmi::RhProvision,
        Tpmi::RhClear,
        Tpmi::RhNvAuth,
        Tpmi::RhLockout,
        Tpmi::RhNvIndex,
        Tpmi::RhNvDefinedIndex,
        Tpmi::RhNvLegacyIndex,
        Tpmi::RhNvExpIndex,
        Tpmi::RhAc,
        Tpmi::RhAct,
    ];

    /// Handles that are in no interface type at all.
    const NEVER: &[Handle] = &[
        Handle(0x4000_0000),
        Handle(0x4000_0002),
        Handle(0xFFFF_FFFF),
        Handle(0x9001_0000),
        Handle(0x2000_0000),
    ];

    /// Converts `handle` with the exp `tpm2::Tpmi*` type that `ty` mirrors, i.e. performs the
    /// check exp's `XxxHandles::unmarshal` did (`TpmiXxx::unmarshal` is
    /// `Handle::unmarshal(src)?.try_into()`).
    fn exp_try_from(ty: Tpmi, h: Handle) -> Result<(), UnmarshalError> {
        match ty {
            Tpmi::DhObject => TpmiDhObject::<false>::try_from(h).map(drop),
            Tpmi::DhObjectOrNull => TpmiDhObject::<true>::try_from(h).map(drop),
            Tpmi::DhParent => TpmiDhParent::try_from(h).map(drop),
            Tpmi::DhPersistent => TpmiDhPersistent::try_from(h).map(drop),
            Tpmi::DhEntity => TpmiDhEntity::<false>::try_from(h).map(drop),
            Tpmi::DhEntityOrNull => TpmiDhEntity::<true>::try_from(h).map(drop),
            Tpmi::DhPcr => TpmiDhPcr::<false>::try_from(h).map(drop),
            Tpmi::DhPcrOrNull => TpmiDhPcr::<true>::try_from(h).map(drop),
            Tpmi::DhContext => TpmiDhContext::try_from(h).map(drop),
            Tpmi::DhSaved => TpmiDhSaved::try_from(h).map(drop),
            Tpmi::ShAuthSession => TpmiShAuthSession::<false>::try_from(h).map(drop),
            Tpmi::ShAuthSessionOrPw => TpmiShAuthSession::<true>::try_from(h).map(drop),
            Tpmi::ShHmac => TpmiShHmac::try_from(h).map(drop),
            Tpmi::ShPolicy => TpmiShPolicy::try_from(h).map(drop),
            Tpmi::RhHierarchy => TpmiRhHierarchy::try_from(h).map(drop),
            Tpmi::RhEnables => TpmiRhEnables::<false>::try_from(h).map(drop),
            Tpmi::RhEnablesOrNull => TpmiRhEnables::<true>::try_from(h).map(drop),
            Tpmi::RhHierarchyAuth => TpmiRhHierarchyAuth::<false>::try_from(h).map(drop),
            Tpmi::RhHierarchyAuthOrNull => TpmiRhHierarchyAuth::<true>::try_from(h).map(drop),
            Tpmi::RhHierarchyPolicy => TpmiRhHierarchyPolicy::try_from(h).map(drop),
            Tpmi::RhBaseHierarchy => TpmiRhBaseHierarchy::try_from(h).map(drop),
            Tpmi::RhPlatform => TpmiRhPlatform::try_from(h).map(drop),
            Tpmi::RhOwner => TpmiRhOwner::<false>::try_from(h).map(drop),
            Tpmi::RhOwnerOrNull => TpmiRhOwner::<true>::try_from(h).map(drop),
            Tpmi::RhEndorsement => TpmiRhEndorsement::<false>::try_from(h).map(drop),
            Tpmi::RhEndorsementOrNull => TpmiRhEndorsement::<true>::try_from(h).map(drop),
            Tpmi::RhProvision => TpmiRhProvision::try_from(h).map(drop),
            Tpmi::RhClear => TpmiRhClear::try_from(h).map(drop),
            Tpmi::RhNvAuth => TpmiRhNvAuth::try_from(h).map(drop),
            Tpmi::RhLockout => TpmiRhLockout::try_from(h).map(drop),
            Tpmi::RhNvIndex => TpmiRhNvIndex::try_from(h).map(drop),
            Tpmi::RhNvDefinedIndex => TpmiRhNvDefinedIndex::try_from(h).map(drop),
            Tpmi::RhNvLegacyIndex => TpmiRhNvLegacyIndex::try_from(h).map(drop),
            Tpmi::RhNvExpIndex => TpmiRhNvExpIndex::try_from(h).map(drop),
            Tpmi::RhAc => TpmiRhAc::try_from(h).map(drop),
            Tpmi::RhAct => TpmiRhAct::try_from(h).map(drop),
        }
    }

    /// Calls `f` with a large set of handles covering both sides of every range boundary of every
    /// handle interface type: all permanent handles `0x4000_0000..=0x4000_01FF`, and every
    /// combination of a handle type byte (`TPM_HT`) with interesting 24-bit indexes.
    fn for_each_sample(mut f: impl FnMut(Handle)) {
        const TYPES: [u32; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x10, 0x11, 0x12, 0x13, 0x40, 0x7F, 0x80, 0x81, 0x82,
            0x90, 0xFF,
        ];
        const INDEXES: [u32; 30] = [
            0x00_0000, 0x00_0001, 0x00_0002, 0x00_0003, 0x00_000F, 0x00_0010, 0x00_0017, 0x00_0018,
            0x00_003F, 0x00_0040, 0x00_00FF, 0x00_0100, 0x00_010F, 0x00_0110, 0x00_011F, 0x00_0120,
            0x00_0143, 0x00_0144, 0x00_FFFF, 0x01_0000, 0x01_FFFF, 0x02_0000, 0x03_FFFF, 0x04_0000,
            0x04_FFFF, 0x05_0000, 0x7F_FFFF, 0x80_0000, 0xFF_FFFE, 0xFF_FFFF,
        ];
        for ht in TYPES {
            for index in INDEXES {
                f(Handle((ht << 24) | index));
            }
        }
        for h in 0x4000_0000..=0x4000_01FF {
            f(Handle(h));
        }
    }

    /// Asserts that `ty` accepts exactly `members` among `members`, `non_members` and [`NEVER`].
    fn assert_set(ty: Tpmi, members: &[Handle], non_members: &[Handle]) {
        for &h in members {
            assert!(ty.contains(h), "{ty:?} should accept {h:?}");
        }
        for &h in non_members.iter().chain(NEVER) {
            assert!(!ty.contains(h), "{ty:?} should reject {h:?}");
        }
    }

    /// The sets and response codes are exactly those of exp's `tpm2::Tpmi*` handle types.
    #[test]
    fn matches_exp_tpmi_types() {
        for ty in ALL {
            let mut accepted = 0;
            for_each_sample(|h| {
                let exp = exp_try_from(ty, h);
                assert_eq!(
                    ty.contains(h),
                    exp.is_ok(),
                    "{ty:?} disagrees with exp on {h:?}"
                );
                match exp {
                    Ok(()) => {
                        accepted += 1;
                        assert_eq!(check(h, ty, Position::handle(1)), Ok(h));
                    }
                    Err(e) => {
                        assert_eq!(e, UnmarshalError::VALUE, "{ty:?} on {h:?}");
                        for n in 1..=3 {
                            assert_eq!(
                                check(h, ty, Position::handle(n)),
                                Err(e.in_handle(n).to_rc()),
                                "{ty:?} on {h:?} as handle {n}"
                            );
                            assert_eq!(
                                check(h, ty, Position::parameter(n)),
                                Err(e.in_parameter(n).to_rc()),
                                "{ty:?} on {h:?} as parameter {n}"
                            );
                        }
                    }
                }
            });
            assert!(accepted > 0, "no sample handle is a member of {ty:?}");
        }
    }

    #[test]
    fn objects() {
        let not_objects = [
            Handle(0x8000_0010),
            Handle(0x80FF_FFFF),
            OWNER,
            NV_FIRST,
            PCR_FIRST,
        ];
        let objects = [
            TRANSIENT_FIRST,
            TRANSIENT_LAST,
            PERSISTENT_FIRST,
            PERSISTENT_LAST,
        ];
        assert_set(Tpmi::DhObject, &objects, &not_objects);
        assert_set(Tpmi::DhObject, &[], &[NULL]);
        assert_set(Tpmi::DhObjectOrNull, &objects, &not_objects);
        assert_set(Tpmi::DhObjectOrNull, &[NULL], &[]);
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
        assert_set(Tpmi::DhEntity, &entities, &not_entities);
        assert_set(Tpmi::DhEntity, &[], &[NULL]);
        assert_set(Tpmi::DhEntityOrNull, &entities, &not_entities);
        assert_set(Tpmi::DhEntityOrNull, &[NULL], &[]);
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
        assert_set(Tpmi::ShAuthSession, &sessions, &not_sessions);
        assert_set(Tpmi::ShAuthSession, &[], &[Handle::RS_PW]);
        assert_set(Tpmi::ShAuthSessionOrPw, &sessions, &not_sessions);
        assert_set(Tpmi::ShAuthSessionOrPw, &[Handle::RS_PW], &[]);
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

    /// Every command handle type entry matches the number of handles the dispatcher reads (for
    /// the implemented commands; `command_handles_count` is 0 for the others).
    #[test]
    fn command_handle_types_match_the_handle_counts() {
        for code in 0x11Fu32..=0x1AA {
            let cc = TpmCc::new(code);
            let types = command_handle_types(cc);
            if !types.is_empty() && crate::command_handles_count(cc) != 0 {
                assert_eq!(
                    types.len(),
                    crate::command_handles_count(cc),
                    "handle count of command {code:#x}"
                );
            }
        }
        assert_eq!(
            command_handle_types(TpmCc::NVRead),
            [Tpmi::RhNvAuth, Tpmi::RhNvIndex]
        );
        assert_eq!(command_handle_types(TpmCc::CreateLoaded), [Tpmi::DhParent]);
        assert!(command_handle_types(TpmCc::GetRandom).is_empty());
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
        // `TPM_RC_VALUE` (0x084) + `TPM_RC_H` + `TPM_RC_2` (0x200).
        assert_eq!(
            check(NULL, Tpmi::DhObject, Position::handle(2)),
            Err(TpmRc::new(0x284).unwrap())
        );
    }
}
