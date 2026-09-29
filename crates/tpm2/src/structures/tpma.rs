use crate::{
    errors::{TpmRc, UnmarshalError},
    *,
};
use bitflags::bitflags;

/// Returns an attribute field built by applying the mask/shift to the value.
pub(crate) const fn new_attribute_field(value: u32, mask: u32, shift: u32) -> u32 {
    (value << shift) & mask
}
/// Returns the attribute field retrieved from the value with the mask/shift.
pub(crate) const fn get_attribute_field(value: u32, mask: u32, shift: u32) -> u32 {
    (value & mask) >> shift
}
/// Sets the attribute field defined by mask/shift in the value to the field value, and returns the result.
pub(crate) const fn set_attribute_field(
    value: u32,
    field_value: u32,
    mask: u32,
    shift: u32,
) -> u32 {
    (value & !mask) | new_attribute_field(field_value, mask, shift)
}

/// `TPMA_LOCALITY` attribute structure defined in TPM 2.0 Part 2: Structures, Section 8.4 (Table 11).
///
/// This bitfield indicates the locality at which a command may be executed or was executed.
/// It is used in `TPMS_CREATION_DATA` to record the creation locality of an object and in session / authorization checks.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(transparent)]
pub struct TpmaLocality(pub u8);
bitflags! {
    impl TpmaLocality : u8 {
        const LOC_ZERO = 1 << 0;
        const LOC_ONE = 1 << 1;
        const LOC_TWO = 1 << 2;
        const LOC_THREE = 1 << 3;
        const LOC_FOUR = 1 << 4;
        // If any other bits are set, an extended locality is indicated.
        const _ = !0;
    }
}

impl TpmaLocality {
    /// TPM 2.0 Part 2: Structures, Section 8.4, Table 11 (TPMA_LOCALITY) - Bits 5..7 (0xE0) indicate Extended Locality (32..255).
    const EXTENDED_LOCALITY_MASK: u8 = 0xE0;
    /// Returns whether this attribute indicates an extended locality.
    pub fn is_extended(&self) -> bool {
        (self.0 & Self::EXTENDED_LOCALITY_MASK) != 0
    }
}

impl Marshal for TpmaLocality {
    const MAX_SIZE: usize = u8::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmaLocality {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Unmarshal::unmarshal(src).map(Self)
    }
}

/// `TPMA_NV` attribute structure defined in TPM 2.0 Part 2: Structures, Section 13.2 (Table 204).
///
/// This bitfield defines the access controls, write/read locking rules, authorization requirements,
/// and index type (TPM_NT) for an NV Index in Non-Volatile storage.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(transparent)]
pub struct TpmaNv(pub u32);
bitflags! {
    impl TpmaNv : u32 {
        /// Whether the index data can be written if platform authorization is provided.
        const PPWRITE = 1 << 0;
        /// Whether the index data can be written if owner authorization is provided.
        const OWNERWRITE = 1 <<  1;
        /// Whether authorizations to change the index contents that require USER role may be provided with an HMAC session or password.
        const AUTHWRITE = 1 << 2;
        /// Whether authorizations to change the index contents that require USER role may be provided with a policy session.
        const POLICYWRITE = 1 << 3;
        /// If set, the index may not be deteled unless the auth_policy is satisfied using nv_undefined_space_special.
        /// If clear, the index may be deleted with proper platform/owner authorization using nv_undefine_space.
        const POLICY_DELETE = 1 << 10;
        /// Whether the index can NOT be written.
        const WRITELOCKED = 1 << 11;
        /// Whether a partial write of the index data is NOT allowed.
        const WRITEALL = 1 << 12;
        /// Whether nv_write_lock may be used to prevent futher writes to this location.
        const WRITEDEFINE = 1 << 13;
        /// Whether nv_write_lock may be used to prevent further writes to this location until the next TPM reset/restart.
        const WRITE_STCLEAR = 1 << 14;
        /// Whether WRITELOCKED is set if nv_global_write_lock is successful.
        const GLOBALLOCK = 1 << 15;
        /// Whether the index data can be read if platform authorization is provided.
        const PPREAD = 1 << 16;
        /// Whether the index data can be read if owner authorization is provided.
        const OWNERREAD = 1 << 17;
        /// Whether the index data can be read if auth_value is provided.
        const AUTHREAD = 1 << 18;
        /// Whether the index data can be read if the auth_policy is satisfied.
        const POLICYREAD = 1 << 19;
        /// If set, authorizationn failures of the index do not affect the DA logic and authorization of the index is not blocked when the TPM is in Lockout mode.
        /// If clear, authorization failures of the index will increment the authorization failure counter and authorizations of this index are not allowed when the TPM is in Lockout mode.
        const NO_DA = 1 << 25;
        /// Whether NV index state is required to be saved only when the TPM performs an orderly shutdown.
        const ORDERLY = 1 << 26;
        /// Whether WRITTEN is cleared by TPM reset/restart.
        const CLEAR_STCLEAR = 1 << 27;
        /// Whether reads of the index are blocked  until the next TPM reset/restart.
        const READLOCKED = 1 << 28;
        /// Whether the index has been written.
        const WRITTEN = 1 << 29;
        /// If set, the index may be undefined with platform authorization but not owner authorization.
        /// If clear, the index may be undefined with owner authorization but not platform authorization.
        const PLATFORMCREATE = 1 << 30;
        /// Whether nv_read_lock may be used to set READLOCKED for this index.
        const READ_STCLEAR = 1 << 31;
        // See multi-bit type field below.
        const _ = !0;
    }
}

impl TpmaNv {
    /// Reserved bits mask for `TPMA_NV` (TPM 2.0 Part 2, Section 13.4, Table 204): bits 9:8 and 24:20 (`0x01f0_0300`).
    pub const RESERVED_BITS_MASK: u32 = 0x01f0_0300;
    /// TPM 2.0 Part 2: Structures, Section 13.2, Table 204 (TPMA_NV) - Bits 4..7 (0xF0) specify TPM_NT (Index Type).
    const NT_MASK: u32 = 0xF0;
    /// Shift of the index type field.
    const NT_SHIFT: u32 = 4;

    /// Returns the attribute for an index type (with all other field clear).
    pub(crate) const fn from_index_type(index_type: TpmNt) -> TpmaNv {
        TpmaNv(new_attribute_field(
            index_type as u32,
            Self::NT_MASK,
            Self::NT_SHIFT,
        ))
    }

    /// Returns the type of the index.
    pub fn get_index_type(&self) -> Result<TpmNt, TpmRc> {
        TpmNt::try_from(get_attribute_field(self.0, Self::NT_MASK, Self::NT_SHIFT) as u8)
            .map_err(|_| TpmRc::ATTRIBUTES.to_rc())
    }
    /// Sets the type of the index.
    pub fn set_type(&mut self, index_type: TpmNt) {
        self.0 = set_attribute_field(self.0, index_type as u32, Self::NT_MASK, Self::NT_SHIFT);
    }
}

impl From<TpmNt> for TpmaNv {
    fn from(value: TpmNt) -> Self {
        Self::from_index_type(value)
    }
}

impl Marshal for TpmaNv {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmaNv {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let val: u32 = Unmarshal::unmarshal(src)?;
        if (val & Self::RESERVED_BITS_MASK) != 0 {
            return Err(UnmarshalError::RESERVED_BITS);
        }
        Ok(Self(val))
    }
}

/// `TPMA_NV_EXP` attribute structure defined in TPM 2.0 Part 2: Structures, Section 13.5 (Table 250).
///
/// This 64-bit bitfield describes expanded attributes that apply to certain types of NV indices.
/// The low 32 bits correspond to [`TpmaNv`], while bits 32..34 define external NV security attributes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(transparent)]
pub struct TpmaNvExp(pub u64);
bitflags! {
    impl TpmaNvExp : u64 {
        /// Whether the index data can be written if platform authorization is provided.
        const PPWRITE = 1 << 0;
        /// Whether the index data can be written if owner authorization is provided.
        const OWNERWRITE = 1 << 1;
        /// Whether authorizations to change the index contents that require USER role may be provided with an HMAC session or password.
        const AUTHWRITE = 1 << 2;
        /// Whether authorizations to change the index contents that require USER role may be provided with a policy session.
        const POLICYWRITE = 1 << 3;
        /// If set, the index may not be deleted unless the auth_policy is satisfied using nv_undefine_space_special.
        const POLICY_DELETE = 1 << 10;
        /// Whether the index can NOT be written.
        const WRITELOCKED = 1 << 11;
        /// Whether a partial write of the index data is NOT allowed.
        const WRITEALL = 1 << 12;
        /// Whether nv_write_lock may be used to prevent further writes to this location.
        const WRITEDEFINE = 1 << 13;
        /// Whether nv_write_lock may be used to prevent further writes to this location until the next TPM reset/restart.
        const WRITE_STCLEAR = 1 << 14;
        /// Whether WRITELOCKED is set if nv_global_write_lock is successful.
        const GLOBALLOCK = 1 << 15;
        /// Whether the index data can be read if platform authorization is provided.
        const PPREAD = 1 << 16;
        /// Whether the index data can be read if owner authorization is provided.
        const OWNERREAD = 1 << 17;
        /// Whether the index data can be read if auth_value is provided.
        const AUTHREAD = 1 << 18;
        /// Whether the index data can be read if the auth_policy is satisfied.
        const POLICYREAD = 1 << 19;
        /// If set, authorization failures of the index do not affect the DA logic and authorization of the index is not blocked when the TPM is in Lockout mode.
        const NO_DA = 1 << 25;
        /// Whether NV index state is required to be saved only when the TPM performs an orderly shutdown.
        const ORDERLY = 1 << 26;
        /// Whether WRITTEN is cleared by TPM reset/restart.
        const CLEAR_STCLEAR = 1 << 27;
        /// Whether reads of the index are blocked until the next TPM reset/restart.
        const READLOCKED = 1 << 28;
        /// Whether the index has been written.
        const WRITTEN = 1 << 29;
        /// If set, the index may be undefined with platform authorization but not owner authorization.
        const PLATFORMCREATE = 1 << 30;
        /// Whether nv_read_lock may be used to set READLOCKED for this index.
        const READ_STCLEAR = 1 << 31;
        /// Whether external NV index contents are encrypted (bit 32).
        const EXTERNAL_NV_ENCRYPTION = 1 << 32;
        /// Whether external NV index contents are integrity-protected (bit 33).
        const EXTERNAL_NV_INTEGRITY = 1 << 33;
        /// Whether external NV index contents are rollback-protected (bit 34).
        const EXTERNAL_NV_ANTIROLLBACK = 1 << 34;
        // See multi-bit type field below.
        const _ = !0;
    }
}

impl TpmaNvExp {
    /// Reserved bits mask for `TPMA_NV_EXP` (TPM 2.0 Part 2, Section 13.5, Table 250): bits 63:35, 24:20, and 9:8 (`0xffff_fff8_01f0_0300`).
    pub const RESERVED_BITS_MASK: u64 = 0xffff_fff8_01f0_0300;
    /// Bits 4..7 (`0xF0`) specify `TPM_NT` (Index Type).
    const NT_MASK: u64 = 0xF0;
    /// Shift of the index type field.
    const NT_SHIFT: u32 = 4;

    /// Returns the expanded attribute for an index type (with all other fields clear).
    pub const fn from_index_type(index_type: TpmNt) -> TpmaNvExp {
        TpmaNvExp(((index_type as u64) << Self::NT_SHIFT) & Self::NT_MASK)
    }

    /// Returns the type of the index.
    pub fn get_index_type(&self) -> Result<TpmNt, TpmRc> {
        TpmNt::try_from(((self.0 & Self::NT_MASK) >> Self::NT_SHIFT) as u8)
            .map_err(|_| TpmRc::ATTRIBUTES.to_rc())
    }

    /// Sets the type of the index.
    pub fn set_type(&mut self, index_type: TpmNt) {
        self.0 =
            (self.0 & !Self::NT_MASK) | (((index_type as u64) << Self::NT_SHIFT) & Self::NT_MASK);
    }
}

impl From<TpmNt> for TpmaNvExp {
    fn from(value: TpmNt) -> Self {
        Self::from_index_type(value)
    }
}

impl From<TpmaNv> for TpmaNvExp {
    fn from(value: TpmaNv) -> Self {
        Self(value.0 as u64)
    }
}

impl TryFrom<TpmaNvExp> for TpmaNv {
    type Error = TpmRc;

    fn try_from(value: TpmaNvExp) -> Result<Self, Self::Error> {
        if (value.0 >> 32) != 0 || ((value.0 as u32) & Self::RESERVED_BITS_MASK) != 0 {
            return Err(TpmRc::ATTRIBUTES.to_rc());
        }
        Ok(Self(value.0 as u32))
    }
}

impl Marshal for TpmaNvExp {
    const MAX_SIZE: usize = u64::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmaNvExp {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let val: u64 = Unmarshal::unmarshal(src)?;
        if (val & Self::RESERVED_BITS_MASK) != 0 {
            return Err(UnmarshalError::RESERVED_BITS);
        }
        Ok(Self(val))
    }
}

/// `TPMA_ALGORITHM` attribute structure defined in TPM 2.0 Part 2: Structures, Section 8.2 (Table 9).
///
/// This bitfield defines the properties and capabilities of an algorithm implemented on the TPM
/// (such as whether it is asymmetric, symmetric, a hash algorithm, an object type, a signing scheme, an encryption scheme, or a KDF method).
/// It is reported in response to `TPM2_GetCapability`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(transparent)]
pub struct TpmaAlgorithm(pub u32);
bitflags! {
    impl TpmaAlgorithm : u32 {
        /// Indicates an asymmetric algorithm with public and private portions.
        const ASYMMETRIC = 1 << 0;
        /// Indicates a symmetric block cipher.
        const SYMMETRIC = 1 << 1;
        /// Indicates a hash algorithm.
        const HASH = 1 << 2;
        /// Indicates an algorithm that may be used as an object type.
        const OBJECT = 1 << 3;
        /// Indicates a signing algorithm.
        const SIGNING = 1 << 8;
        /// Indicates an encryption/decryption algorithm.
        const ENCRYPTING = 1 << 9;
        /// Indicates a method such as a key derivative function.
        const METHOD = 1 << 10;
    }
}

impl TpmaAlgorithm {
    /// Reserved bits mask for `TPMA_ALGORITHM` (TPM 2.0 Part 2, Section 8.2): `0xffff_f8f0`.
    pub const RESERVED_BITS_MASK: u32 = 0xffff_f8f0;
}

impl Marshal for TpmaAlgorithm {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmaAlgorithm {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let val: u32 = Unmarshal::unmarshal(src)?;
        if (val & Self::RESERVED_BITS_MASK) != 0 {
            return Err(UnmarshalError::RESERVED_BITS);
        }
        Ok(Self(val))
    }
}

/// `TPMA_SESSION` attribute structure defined in TPM 2.0 Part 2: Structures, Section 8.4 (Table 12).
///
/// This bitfield defines the operational attributes for an authorization session in command and response headers.
/// It controls session persistence (`continueSession`), auditing (`auditExclusive`, `auditReset`, `audit`),
/// and parameter encryption (`decrypt`, `encrypt`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(transparent)]
pub struct TpmaSession(pub u8);
bitflags! {
    impl TpmaSession : u8 {
        /// Indicates if the session is to remain active (in commands) or does remain active (in reponses) after successful completion of the command.
        const CONTINUE_SESSION = 1 << 0;
        /// Indicates if the command should only be executed if the session is exclusive at the start of the command (in commands) or is exclusive (in responses).
        const AUDIT_EXCLUSIVE = 1 << 1;
        /// Indicates if the audit digest of the session should be initialized and exclusive status set in commands.
        const AUDIT_RESET = 1 << 2;
        /// Indicates if the first parameter in the command is symmetrically encrpyted.
        const DECRYPT = 1 << 5;
        /// Indicates if the session should (in commands) or did (in responses) encrypt the first parameter in the response.
        const ENCRYPT = 1 << 6;
        /// Indicates that the session is for audit, and that AUDIT_EXLCUSIVE/AUDIT_RESET have meaning.
        const AUDIT = 1 << 7;
    }
}

impl TpmaSession {
    /// Reserved bits mask for `TPMA_SESSION` (TPM 2.0 Part 2, Section 8.4): bits 4:3 (`0x18`).
    pub const RESERVED_BITS_MASK: u8 = 0x18;
}

impl Marshal for TpmaSession {
    const MAX_SIZE: usize = u8::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmaSession {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let val: u8 = Unmarshal::unmarshal(src)?;
        if (val & Self::RESERVED_BITS_MASK) != 0 {
            return Err(UnmarshalError::RESERVED_BITS);
        }
        Ok(Self(val))
    }
}

/// `TPMA_PERMANENT` attribute structure defined in TPM 2.0 Part 2: Structures, Section 8.6 (Table 36).
///
/// Persistent attributes that are not changed as a result of `_TPM_Init` or any `TPM2_Startup()`.
/// Returned in response to `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, TPM_PT_PERMANENT)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(transparent)]
pub struct TpmaPermanent(pub u32);
bitflags! {
    impl TpmaPermanent : u32 {
        /// Whether `TPM2_HierarchyChangeAuth()` with `ownerAuth` has been executed since the last `TPM2_Clear()`.
        const OWNER_AUTH_SET = 1 << 0;
        /// Whether `TPM2_HierarchyChangeAuth()` with `endorsementAuth` has been executed since the last `TPM2_Clear()`.
        const ENDORSEMENT_AUTH_SET = 1 << 1;
        /// Whether `TPM2_HierarchyChangeAuth()` with `lockoutAuth` has been executed since the last `TPM2_Clear()`.
        const LOCKOUT_AUTH_SET = 1 << 2;
        /// Whether `TPM2_Clear()` is disabled.
        const DISABLE_CLEAR = 1 << 8;
        /// Whether the TPM is in lockout (`failedTries == maxTries`).
        const IN_LOCKOUT = 1 << 9;
        /// Whether the endorsement primary seed (EPS) was created by the TPM.
        const TPM_GENERATED_EPS = 1 << 10;
    }
}

impl TpmaPermanent {
    /// Reserved bits mask for `TPMA_PERMANENT` (TPM 2.0 Part 2, Section 8.6): `0xffff_f8f8`.
    pub const RESERVED_BITS_MASK: u32 = 0xffff_f8f8;
}

impl Marshal for TpmaPermanent {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmaPermanent {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let val: u32 = Unmarshal::unmarshal(src)?;
        if (val & Self::RESERVED_BITS_MASK) != 0 {
            return Err(UnmarshalError::RESERVED_BITS);
        }
        Ok(Self(val))
    }
}

/// `TPMA_STARTUP_CLEAR` attribute structure defined in TPM 2.0 Part 2: Structures, Section 8.7 (Table 37).
///
/// Attributes reset or preserved on `TPM2_Startup()`.
/// Returned in response to `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, TPM_PT_STARTUP_CLEAR)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(transparent)]
pub struct TpmaStartupClear(pub u32);
bitflags! {
    impl TpmaStartupClear : u32 {
        /// Whether the platform hierarchy is enabled.
        const PH_ENABLE = 1 << 0;
        /// Whether the storage hierarchy is enabled.
        const SH_ENABLE = 1 << 1;
        /// Whether the endorsement hierarchy is enabled.
        const EH_ENABLE = 1 << 2;
        /// Whether NV indices with `TPMA_NV_PLATFORMCREATE` set may be accessed.
        const PH_ENABLE_NV = 1 << 3;
        /// Whether all enabled hierarchies, including the NULL hierarchy, are Read-Only.
        const READ_ONLY = 1 << 4;
        /// Whether the TPM received a `TPM2_Shutdown()` and a matching `TPM2_Startup()`.
        const ORDERLY = 1 << 31;
    }
}

impl TpmaStartupClear {
    /// Reserved bits mask for `TPMA_STARTUP_CLEAR` (TPM 2.0 Part 2, Section 8.7): `0x7fff_ffe0`.
    pub const RESERVED_BITS_MASK: u32 = 0x7fff_ffe0;
}

impl Marshal for TpmaStartupClear {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmaStartupClear {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let val: u32 = Unmarshal::unmarshal(src)?;
        if (val & Self::RESERVED_BITS_MASK) != 0 {
            return Err(UnmarshalError::RESERVED_BITS);
        }
        Ok(Self(val))
    }
}

/// `TPMA_MEMORY` attribute structure defined in TPM 2.0 Part 2: Structures, Section 8.8 (Table 38).
///
/// Reports the memory management method used by the TPM for transient objects and authorization sessions.
/// Returned in response to `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, TPM_PT_MEMORY)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(transparent)]
pub struct TpmaMemory(pub u32);
bitflags! {
    impl TpmaMemory : u32 {
        /// Indicates that RAM memory used for authorization session contexts is shared with transient objects.
        const SHARED_RAM = 1 << 0;
        /// Indicates that NV memory used for persistent objects is shared with NV Index values.
        const SHARED_NV = 1 << 1;
        /// Indicates that the TPM copies persistent objects to a transient-object slot in RAM when referenced.
        const OBJECT_COPIED_TO_RAM = 1 << 2;
    }
}

impl TpmaMemory {
    /// Reserved bits mask for `TPMA_MEMORY` (TPM 2.0 Part 2, Section 8.8): `0xffff_fff8`.
    pub const RESERVED_BITS_MASK: u32 = 0xffff_fff8;
}

impl Marshal for TpmaMemory {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmaMemory {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let val: u32 = Unmarshal::unmarshal(src)?;
        if (val & Self::RESERVED_BITS_MASK) != 0 {
            return Err(UnmarshalError::RESERVED_BITS);
        }
        Ok(Self(val))
    }
}

/// `TPMA_CC` attribute structure defined in TPM 2.0 Part 2: Structures, Section 8.9 (Table 39).
///
/// This bitfield describes the attributes of a TPM command code, including the command index,
/// number of input handles, whether it writes to NV, whether context flushing occurs, and if it is vendor-specific.
/// It is returned in response to `TPM2_GetCapability(TPM_CAP_COMMANDS)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(transparent)]
pub struct TpmaCc(pub u32);
bitflags! {
    impl TpmaCc : u32 {
        /// Whether the command may write to NV.
        const NV  = 1 << 22;
        /// Whether the command could flush any number of loaded contexts.
        const EXTENSIVE = 1 << 23;
        /// Whether the conext associated with any transient handle in the command will be flushed when this command completes.
        const FLUSHED = 1 << 24;
        /// Wether there is a handle area in the response.
        const R_HANDLE = 1 << 28;
        /// Whether the command is vendor-specific.
        const V = 1 << 29;
        // See multi-bit fields below.
        const _ = !0;
    }
}

impl TpmaCc {
    /// Reserved bits mask for `TPMA_CC` (TPM 2.0 Part 2, Section 8.9): bits 31:30 and 21:16 (`0xc03f_0000`).
    pub const RESERVED_BITS_MASK: u32 = 0xc03f_0000;
    /// Shift for the command index field.
    const COMMAND_INDEX_SHIFT: u32 = 0;
    /// TPM 2.0 Part 2: Structures, Section 13.5, Table 207 (TPMA_CC) - Bits 0..15 (0xFFFF) specify commandIndex.
    const COMMAND_INDEX_MASK: u32 = 0xFFFF;
    /// Shift for the command handles field.
    const C_HANDLES_SHIFT: u32 = 25;
    /// TPM 2.0 Part 2: Structures, Section 13.5, Table 207 (TPMA_CC) - Bits 25..27 (0x7 shifted) specify cHandles (number of command handles).
    const C_HANDLES_MASK: u32 = 0x7 << TpmaCc::C_HANDLES_SHIFT;

    /// Creates a TpmaCc with the command index field set to the provided value.
    pub const fn command_index(index: u16) -> TpmaCc {
        TpmaCc(new_attribute_field(
            index as u32,
            Self::COMMAND_INDEX_MASK,
            Self::COMMAND_INDEX_SHIFT,
        ))
    }
    /// Creates a TpmaCc with the command handles field set to the provided value.
    pub const fn c_handles(count: u32) -> TpmaCc {
        TpmaCc(new_attribute_field(
            count,
            Self::C_HANDLES_MASK,
            Self::C_HANDLES_SHIFT,
        ))
    }

    /// Returns the command being selected.
    pub fn get_command_index(&self) -> u16 {
        get_attribute_field(self.0, Self::COMMAND_INDEX_MASK, Self::COMMAND_INDEX_SHIFT) as u16
    }
    /// Returns the number of handles in the handle area for this command.
    pub fn get_c_handles(&self) -> u32 {
        get_attribute_field(self.0, Self::C_HANDLES_MASK, Self::C_HANDLES_SHIFT)
    }

    /// Sets the command being selected.
    pub fn set_command_index(&mut self, index: u16) {
        self.0 = set_attribute_field(
            self.0,
            index as u32,
            Self::COMMAND_INDEX_MASK,
            Self::COMMAND_INDEX_SHIFT,
        );
    }
    /// Sets the number of handles in the handle area for this command.
    pub fn set_c_handles(&mut self, count: u32) {
        self.0 = set_attribute_field(self.0, count, Self::C_HANDLES_MASK, Self::C_HANDLES_SHIFT);
    }
}

impl Marshal for TpmaCc {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmaCc {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let val: u32 = Unmarshal::unmarshal(src)?;
        if (val & Self::RESERVED_BITS_MASK) != 0 {
            return Err(UnmarshalError::RESERVED_BITS);
        }
        Ok(Self(val))
    }
}

/// `TPMA_MODES` attribute structure defined in TPM 2.0 Part 2: Structures, Section 8.10 (Table 40).
///
/// Reports that the TPM is designed to comply with specific FIPS 140 modes.
/// Returned in response to `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, TPM_PT_MODES)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(transparent)]
pub struct TpmaModes(pub u32);
bitflags! {
    impl TpmaModes : u32 {
        /// Indicates that the TPM is designed to comply with all of the FIPS 140-2 requirements at Level 1 or higher.
        const FIPS_140_2 = 1 << 0;
        /// Indicates that the TPM is designed to comply with all of the FIPS 140-3 requirements at Level 1 or higher.
        const FIPS_140_3 = 1 << 1;
        /// Two-bit field indicating the FIPS 140-3 category of the service provided by the last command.
        const FIPS_140_3_INDICATOR = 3 << 2;
    }
}

impl TpmaModes {
    /// Reserved bits mask for `TPMA_MODES` (TPM 2.0 Part 2, Section 8.10): `0xffff_fff0`.
    pub const RESERVED_BITS_MASK: u32 = 0xffff_fff0;
    /// Shift for the `FIPS_140_3_INDICATOR` field (bits 2..3).
    const FIPS_140_3_INDICATOR_SHIFT: u32 = 2;
    /// Mask for the `FIPS_140_3_INDICATOR` field (bits 2..3).
    const FIPS_140_3_INDICATOR_MASK: u32 = 3 << Self::FIPS_140_3_INDICATOR_SHIFT;

    /// Returns the 2-bit FIPS 140-3 indicator value.
    pub const fn get_fips_140_3_indicator(&self) -> u32 {
        get_attribute_field(
            self.0,
            Self::FIPS_140_3_INDICATOR_MASK,
            Self::FIPS_140_3_INDICATOR_SHIFT,
        )
    }

    /// Sets the 2-bit FIPS 140-3 indicator value.
    pub fn set_fips_140_3_indicator(&mut self, indicator: u32) {
        self.0 = set_attribute_field(
            self.0,
            indicator,
            Self::FIPS_140_3_INDICATOR_MASK,
            Self::FIPS_140_3_INDICATOR_SHIFT,
        );
    }
}

impl Marshal for TpmaModes {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmaModes {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let val: u32 = Unmarshal::unmarshal(src)?;
        if (val & Self::RESERVED_BITS_MASK) != 0 {
            return Err(UnmarshalError::RESERVED_BITS);
        }
        Ok(Self(val))
    }
}

/// `TPMA_X509_KEY_USAGE` attribute structure defined in TPM 2.0 Part 2: Structures, Section 8.11 (Table 41).
///
/// Represents RFC 5280 Key Usage extension bits for validating keys in `TPM2_CertifyX509()`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(transparent)]
pub struct TpmaX509KeyUsage(pub u32);
bitflags! {
    impl TpmaX509KeyUsage : u32 {
        /// Key usage `decipherOnly` (bit 23). Requires `decrypt` set on the subject key.
        const DECIPHER_ONLY = 1 << 23;
        /// Key usage `encipherOnly` (bit 24). Requires `decrypt` set on the subject key.
        const ENCIPHER_ONLY = 1 << 24;
        /// Key usage `cRLSign` (bit 25). Requires `sign` set on the subject key.
        const CRL_SIGN = 1 << 25;
        /// Key usage `keyCertSign` (bit 26). Requires `sign` set on the subject key.
        const KEY_CERT_SIGN = 1 << 26;
        /// Key usage `keyAgreement` (bit 27). Requires `decrypt` set on the subject key.
        const KEY_AGREEMENT = 1 << 27;
        /// Key usage `dataEncipherment` (bit 28). Requires `decrypt` set on the subject key.
        const DATA_ENCIPHERMENT = 1 << 28;
        /// Key usage `keyEncipherment` (bit 29). Requires asymmetric key with `decrypt` and `restricted` set.
        const KEY_ENCIPHERMENT = 1 << 29;
        /// Key usage `nonRepudiation` / `contentCommitment` (bit 30). Requires `fixedTPM` set on the subject key.
        const NON_REPUDIATION = 1 << 30;
        /// Key usage `contentCommitment` (alias for `NON_REPUDIATION`, bit 30).
        const CONTENT_COMMITMENT = 1 << 30;
        /// Key usage `digitalSignature` (bit 31). Requires `sign` set on the subject key.
        const DIGITAL_SIGNATURE = 1 << 31;
    }
}

impl TpmaX509KeyUsage {
    /// Reserved bits mask for `TPMA_X509_KEY_USAGE` (TPM 2.0 Part 2, Section 8.11): `0x007f_ffff`.
    pub const RESERVED_BITS_MASK: u32 = 0x007f_ffff;
}

impl Marshal for TpmaX509KeyUsage {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmaX509KeyUsage {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let val: u32 = Unmarshal::unmarshal(src)?;
        if (val & Self::RESERVED_BITS_MASK) != 0 {
            return Err(UnmarshalError::RESERVED_BITS);
        }
        Ok(Self(val))
    }
}

/// `TPMA_ACT` attribute structure defined in TPM 2.0 Part 2: Structures, Section 8.12 (Table 42).
///
/// Reports the state of an Authenticated Countdown Timer (ACT).
/// Returned in response to `TPM2_GetCapability(TPM_CAP_ACT)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(transparent)]
pub struct TpmaAct(pub u32);
bitflags! {
    impl TpmaAct : u32 {
        /// Whether the ACT has signaled.
        const SIGNALED = 1 << 0;
        /// Preserves the state of `signaled` across power cycles (copied on TPM Resume, cleared on TPM Reset/Restart).
        const PRESERVE_SIGNALED = 1 << 1;
    }
}

impl TpmaAct {
    /// Reserved bits mask for `TPMA_ACT` (TPM 2.0 Part 2, Section 8.12): `0xffff_fffc`.
    pub const RESERVED_BITS_MASK: u32 = 0xffff_fffc;
}

impl Marshal for TpmaAct {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmaAct {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let val: u32 = Unmarshal::unmarshal(src)?;
        if (val & Self::RESERVED_BITS_MASK) != 0 {
            return Err(UnmarshalError::RESERVED_BITS);
        }
        Ok(Self(val))
    }
}

/// `TPMA_ML_PARAMETER_SET` attribute structure defined in TPM 2.0 Part 2: Structures, Section 8.13 (Table 47).
///
/// Reports the supported ML-KEM and ML-DSA parameter sets, as well as support for `allowExternalMu`.
/// Returned in response to `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, TPM_PT_ML_PARAMETER_SETS)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(transparent)]
pub struct TpmaMlParameterSet(pub u32);
bitflags! {
    impl TpmaMlParameterSet : u32 {
        /// Indicates support for `TPM_MLKEM_512` (`mlKem_512`, bit 0).
        const ML_KEM_512 = 1 << 0;
        /// Indicates support for `TPM_MLKEM_768` (`mlKem_768`, bit 1).
        const ML_KEM_768 = 1 << 1;
        /// Indicates support for `TPM_MLKEM_1024` (`mlKem_1024`, bit 2).
        const ML_KEM_1024 = 1 << 2;
        /// Indicates support for `TPM_MLDSA_44` (`mlDsa_44`, bit 3).
        const ML_DSA_44 = 1 << 3;
        /// Indicates support for `TPM_MLDSA_65` (`mlDsa_65`, bit 4).
        const ML_DSA_65 = 1 << 4;
        /// Indicates support for `TPM_MLDSA_87` (`mlDsa_87`, bit 5).
        const ML_DSA_87 = 1 << 5;
        /// Indicates support for `allowExternalMu` for ML-DSA (`extMu`, bit 6).
        const EXT_MU = 1 << 6;
    }
}

impl TpmaMlParameterSet {
    /// Reserved bits mask for `TPMA_ML_PARAMETER_SET` (TPM 2.0 Part 2, Section 8.13, Table 47): bits 31:7 (`0xffff_ff80`).
    pub const RESERVED_BITS_MASK: u32 = 0xffff_ff80;
}

impl Marshal for TpmaMlParameterSet {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmaMlParameterSet {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let val: u32 = Unmarshal::unmarshal(src)?;
        if (val & Self::RESERVED_BITS_MASK) != 0 {
            return Err(UnmarshalError::RESERVED_BITS);
        }
        Ok(Self(val))
    }
}

/// `TPMA_OBJECT` attribute structure defined in TPM 2.0 Part 2: Structures, Section 8.3 (Table 33).
///
/// This bitfield defines the attributes of an object, including its hierarchy/parent binding,
/// authorization requirements, key usage capabilities, and duplication properties.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(transparent)]
pub struct TpmaObject(pub u32);
bitflags! {
    impl TpmaObject : u32 {
        /// Whether the hierarchy of the object may NOT change.
        const FIXED_TPM = 1 << 1;
        /// Whether saved contexts of this object may NOT be loaded after startup(CLEAR).
        const ST_CLEAR = 1 << 2;
        /// Whether the parent of the object may NOT change.
        const FIXED_PARENT = 1 << 4;
        /// Whether the TPM generated all of the sensitive data, other than auth_value, when the object was created.
        const SENSITIVE_DATA_ORIGIN = 1 << 5;
        /// Whether approval of USER role actions with the object may be with an HMAC session or password using the auth_value of the object or a policy session.
        const USER_WITH_AUTH = 1 << 6;
        /// Whether approval of ADMIN role actions with the object may ONLY be done with a policy session.
        const ADMIN_WITH_POLICY = 1 << 7;
        /// Whether the object exists only within a firmware-limited hierarchy.
        const FIRMWARE_LIMITED = 1 << 8;
        /// Whether the object exists only within an SVN-limited hierarchy.
        const SVN_LIMITED = 1 << 9;
        /// Whether the object is NOT subject to dictionary attack protections.
        const NO_DA = 1 << 10;
        /// Whether, if the object is duplicated, symmetric_alg and new_parent_handle shall not be null.
        const ENCRYPTED_DUPLICATION = 1 << 11;
        /// Whether key usage is restricted to manipulate structures of known format.
        const RESTRICTED = 1 << 16;
        /// Whether the private portion of the key may be used to decrypt.
        const DECRYPT = 1 << 17;
        /// Whether the private portion of the key may be used to encrypt (for symmetric cipher objects) or sign.
        const SIGN_ENCRYPT = 1 << 18;
        /// Whether this is an asymmetric key that may not be used to sign with sign().
        const X509_SIGN = 1 << 19;
    }
}

impl TpmaObject {
    /// Reserved bits mask for `TPMA_OBJECT` (TPM 2.0 Part 2, Section 8.3, Table 33): bits 31:20, 15:12, 3, and 0 (`0xfff0_f009`).
    pub const RESERVED_BITS_MASK: u32 = 0xfff0_f009;
}

impl Marshal for TpmaObject {
    const MAX_SIZE: usize = u32::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    #[inline(always)]
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}

impl<'a> Unmarshal<'a> for TpmaObject {
    #[inline(always)]
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let val: u32 = Unmarshal::unmarshal(src)?;
        if (val & Self::RESERVED_BITS_MASK) != 0 {
            return Err(UnmarshalError::RESERVED_BITS);
        }
        Ok(Self(val))
    }
}
