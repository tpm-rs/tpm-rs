use crate::{TpmaObject, TpmiAlgHash, TpmiEccCurve};

/// Allows an implementation to restrict which values it can
/// [`Marshal`][super::Marshal] and [`Unmarshal`][super::Unmarshal].
///
/// This trait enables different implementations to share the same core type
/// definitions while selectively supporting only a subset of variants. This
/// selection can be enforced either at compile time or at runtime.
///
/// This approach is important for two main reasons:
///
/// 1.  **ABI Stability**: It avoids the many compile-time `#define`s found in C
///     implementations. Those defines often alter structure layouts, leading to
///     API and ABI incompatibilities between libraries compiled with different
///     options.
///
/// 2.  **Code Size**: Restricting which algorithms and types the marshaling code
///     must support can significantly reduce the final binary size, which is
///     critical for constrained environments.
pub trait Limits {
    const HASH_ALGS: TpmaHashAlgs;
    const RSA_KEY_SIZES: RsaKeySizes;
    const ECC_CURVES: EccCurves;

    const OBJECT_ATTRIBUTES: TpmaObject = TpmaObject(u32::MAX);
}

/// `TPMA_HASH_ALGS`: a bitfield representing the set of supported hash algorithms.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct TpmaHashAlgs(pub u32);

impl TpmaHashAlgs {
    /// Indicates support for [`TpmiAlgHash::Sha1`].
    pub const SHA1: Self = Self(1 << 0);
    /// Indicates support for [`TpmiAlgHash::Sha256`].
    pub const SHA256: Self = Self(1 << 1);
    /// Indicates support for [`TpmiAlgHash::Sha384`].
    pub const SHA384: Self = Self(1 << 2);
    /// Indicates support for [`TpmiAlgHash::Sha512`].
    pub const SHA512: Self = Self(1 << 3);
    /// Indicates support for [`TpmiAlgHash::Sm3_256`].
    pub const SM3_256: Self = Self(1 << 4);
    /// Indicates support for [`TpmiAlgHash::Sha3_256`].
    pub const SHA3_256: Self = Self(1 << 5);
    /// Indicates support for [`TpmiAlgHash::Sha3_384`].
    pub const SHA3_384: Self = Self(1 << 6);
    /// Indicates support for [`TpmiAlgHash::Sha3_512`].
    pub const SHA3_512: Self = Self(1 << 7);

    const fn from_alg(alg: TpmiAlgHash) -> Self {
        match alg {
            TpmiAlgHash::Sha1 => Self::SHA1,
            TpmiAlgHash::Sha256 => Self::SHA256,
            TpmiAlgHash::Sha384 => Self::SHA384,
            TpmiAlgHash::Sha512 => Self::SHA512,
            TpmiAlgHash::Sm3_256 => Self::SM3_256,
            TpmiAlgHash::Sha3_256 => Self::SHA3_256,
            TpmiAlgHash::Sha3_384 => Self::SHA3_384,
            TpmiAlgHash::Sha3_512 => Self::SHA3_512,
        }
    }
    pub const fn from_alg_list(alg_list: &[TpmiAlgHash]) -> Self {
        let mut tpma = Self(0);
        let mut i = 0;
        while i < alg_list.len() {
            let alg = alg_list[i];
            tpma = tpma.or(Self::from_alg(alg));
            i += 1;
        }
        tpma
    }
    pub const fn supports_alg(self, alg: TpmiAlgHash) -> bool {
        self.contains(Self::from_alg(alg))
    }
    pub const fn max_digest_size(self) -> usize {
        let digest_64 = Self::SHA512.and(Self::SHA3_512);
        let digest_48 = Self::SHA384.and(Self::SHA3_384);
        let digest_32 = Self::SHA256.and(Self::SHA3_256).and(Self::SM3_256);
        let digest_20 = Self::SHA1;

        let all = digest_64.or(digest_48).or(digest_32).or(digest_20);
        if !all.contains(self) {
            panic!("Unsupported TpmiAlgHash set in TpmaHashAlgs");
        }

        if self.intersects(digest_64) {
            64
        } else if self.intersects(digest_48) {
            48
        } else if self.intersects(digest_32) {
            32
        } else if self.intersects(digest_20) {
            20
        } else {
            panic!("At least one TpmiAlgHash must be set in TpmaHashAlgs");
        }
    }
}

impl TpmaHashAlgs {
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

/// A bitfield representing the set of supported RSA key sizes.
///
/// A value of [`RsaKeySizes::NONE`] indicates RSA is not supported.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RsaKeySizes(u64);

impl RsaKeySizes {
    /// RSA is not supported.
    pub const NONE: Self = Self(0);
    /// All RSA key lengths are supported.
    pub const ALL: Self = Self(u64::MAX);

    /// Specific key sizes must be 1024-bit, 2048-bit, etc...
    const BITS_MULTIPLE: u16 = 1024;

    const fn from_key_bits(key_bits: u16) -> Option<Self> {
        if key_bits == 0 || key_bits % Self::BITS_MULTIPLE != 0 {
            None
        } else {
            Some(Self(1 << (key_bits / Self::BITS_MULTIPLE)))
        }
    }
    pub const fn from_key_bits_list(key_bits_list: &[u16]) -> Self {
        let mut sizes = Self::NONE;
        let mut i = 0;
        while i < key_bits_list.len() {
            let key_bits = key_bits_list[i];
            sizes = sizes.or(Self::from_key_bits(key_bits)
                .expect("Provided key sizes must be a positive multiple of 1024 bits"));
            i += 1;
        }
        sizes
    }

    pub const fn is_none(self) -> bool {
        self.0 == Self::NONE.0
    }
    pub const fn is_all(self) -> bool {
        self.0 == Self::ALL.0
    }

    pub const fn supports_key_bits(self, key_bits: u16) -> bool {
        if self.is_all() {
            true
        } else if let Some(sizes) = Self::from_key_bits(key_bits) {
            self.contains(sizes)
        } else {
            false
        }
    }
    pub const fn max_key_bytes(self) -> Option<u16> {
        if self.is_all() {
            return None;
        }
        let max_bits = match self.0.checked_ilog2() {
            Some(x) => (x as u16) * Self::BITS_MULTIPLE,
            None => 0,
        };
        Some(max_bits / 8)
    }
}

impl RsaKeySizes {
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

/// A bitfield representing the set of supported ECC Curves.
///
/// A value of [`EccCurves::NONE`] indicates ECC is not supported.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EccCurves(u128);

impl EccCurves {
    /// ECC is not supported.
    pub const NONE: Self = Self(0);
    /// Any ECC curve is supported.
    pub const ALL: Self = Self(u128::MAX);

    const fn from_curve(curve: TpmiEccCurve) -> Option<Self> {
        // Can't use Option::map in const fns
        match 1u128.checked_shl(curve.0 as u32) {
            Some(x) => Some(Self(x)),
            None => None,
        }
    }

    pub const fn from_curve_list(curve_list: &[TpmiEccCurve]) -> Self {
        let mut s = Self::NONE;
        let mut i = 0;
        while i < curve_list.len() {
            let curve = curve_list[i];
            s = s.or(Self::from_curve(curve)
                .expect("Provided TpmiEccCurve was out of range (>= 0x0080)"));
            i += 1;
        }
        s
    }

    pub const fn is_none(self) -> bool {
        self.0 == Self::NONE.0
    }
    pub const fn is_all(self) -> bool {
        self.0 == Self::ALL.0
    }

    pub const fn supports_curve(self, curve: TpmiEccCurve) -> bool {
        if self.is_all() {
            true
        } else if let Some(curves) = Self::from_curve(curve) {
            self.contains(curves)
        } else {
            false
        }
    }
}

impl EccCurves {
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
