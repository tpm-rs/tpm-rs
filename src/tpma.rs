//! Bitfield (`TPMA_`) types defined in:
//!   - Part 2, Section 8 "Attribute Structures"
//!   - Part 2, Section 13 "NV Storage Structures"
use crate::marshal::Limits;

/// `TPMA_OBJECT`: a bitfield of object attributes.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct TpmaObject(pub u32);

impl TpmaObject {
    /// The hierarchy of the object, as indicated by its Qualified Name, may not change.
    pub const FIXED_TPM: Self = Self(1 << 1);
    /// Previously saved contexts of this object may not be loaded after Startup(CLEAR).
    pub const ST_CLEAR: Self = Self(1 << 2);
    /// The parent of the object may not change.
    pub const FIXED_PARENT: Self = Self(1 << 4);
    /// Indicates that the TPM generated all of the sensitive data other than the `authValue`.
    pub const SENSITIVE_DATA_ORIGIN: Self = Self(1 << 5);
    /// Approval of USER role actions with this object may be with an HMAC session or with a
    /// password using the `authValue` of the object or a policy session.
    pub const USER_WITH_AUTH: Self = Self(1 << 6);
    /// Approval of ADMIN role actions with this object may only be done with a policy session.
    pub const ADMIN_WITH_POLICY: Self = Self(1 << 7);
    /// The object exists only within a firmware-limited hierarchy.
    pub const FIRMWARE_LIMITED: Self = Self(1 << 8);
    /// The object exists only within an SVN-limited hierarchy.
    pub const SVN_LIMITED: Self = Self(1 << 9);
    /// The object is not subject to dictionary attack protections.
    pub const NO_DA: Self = Self(1 << 10);
    /// If the object is duplicated, then `symmetricAlg` shall not be `TPM_ALG_NULL` and
    /// `newParentHandle` shall not be `TPM_RH_NULL`.
    pub const ENCRYPTED_DUPLICATION: Self = Self(1 << 11);
    /// Key usage is restricted to manipulate structures of known format; the parent of this key
    /// shall have `restricted` SET.
    pub const RESTRICTED: Self = Self(1 << 16);
    /// The private portion of the key may be used to decrypt.
    pub const DECRYPT: Self = Self(1 << 17);
    /// For a symmetric block cipher key, the private portion of the key may be used to encrypt.
    /// For other keys, the private portion of the key may be used to sign.
    pub const SIGN_ENCRYPT: Self = Self(1 << 18);
    /// An asymmetric key that may not be used to sign with `TPM2_Sign()`, `TPM2_SignDigest()`,
    /// or `TPM2_SignSequenceComplete()`.
    pub const X509_SIGN: Self = Self(1 << 19);

    /// Returns true if all the bits in `self` are supported by the [`Limits`].
    pub const fn supported<L: Limits>(self) -> bool {
        L::OBJECT_ATTRIBUTES.contains(self)
    }
}

impl TpmaObject {
    /// Performs a bitwise AND operation.
    pub const fn and(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
    /// Performs a bitwise OR operation.
    pub const fn or(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
    /// Performs a bitwise XOR operation.
    pub const fn xor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
    /// Returns true if `self` contains all of the bits in `other`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    /// Returns true if `self` and `other` share any bits.
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}
