// =============================================================================
// USES
// =============================================================================

use super::{get_attribute_field, new_attribute_field, set_attribute_field};
use crate::types::TPM2NT;
use bitflags::bitflags;
use tpm2_rs_marshal::Marshal;

// =============================================================================
// TYPE
// =============================================================================

/// TpmNv represents the NV index attributes (TPMA_NV).
/// See definition in Part 2: Structures, section 13.4.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Debug, Default, Marshal)]
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

// =============================================================================
// IMPLEMENTATION
// =============================================================================

impl TpmaNv {
    /// Mask for the index type field.
    const NT_MASK: u32 = 0xF0;
    /// Shift of the index type field.
    const NT_SHIFT: u32 = 4;

    /// Returns the attribute for an index type (with all other field clear).
    const fn from_index_type(index_type: TPM2NT) -> TpmaNv {
        TpmaNv(new_attribute_field(
            index_type.0 as u32,
            Self::NT_MASK,
            Self::NT_SHIFT,
        ))
    }

    /// Returns the type of the index.
    pub fn get_index_type(&self) -> TPM2NT {
        TPM2NT(get_attribute_field(self.0, Self::NT_MASK, Self::NT_SHIFT) as u8)
    }
    /// Sets the type of the index.
    pub fn set_type(&mut self, index_type: TPM2NT) {
        self.0 = set_attribute_field(self.0, index_type.0 as u32, Self::NT_MASK, Self::NT_SHIFT);
    }
}

// =============================================================================
// TRAITS
// =============================================================================

impl From<TPM2NT> for TpmaNv {
    fn from(value: TPM2NT) -> Self {
        Self::from_index_type(value)
    }
}
