//! Bitfield (`TPMA_`) types defined in:
//!   - Part 2, Section 8 "Attribute Structures"
//!   - Part 2, Section 13 "NV Storage Structures"
use crate::{
    TpmiAlgHash::{self, *},
    marshal::Limits,
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct TpmaHashAlgs(pub u32);

/// TODO: Generate this with macro_rules / proc_macro
impl TpmaHashAlgs {
    pub const SHA1: Self = Self(1 << 0);
    pub const SHA256: Self = Self(1 << 1);
    pub const SHA384: Self = Self(1 << 2);
    pub const SHA512: Self = Self(1 << 3);
    pub const SM3_256: Self = Self(1 << 4);
    pub const SHA3_256: Self = Self(1 << 5);
    pub const SHA3_384: Self = Self(1 << 6);
    pub const SHA3_512: Self = Self(1 << 7);

    pub const fn and(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
    pub const fn or(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
    pub const fn xor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

impl TpmaHashAlgs {
    pub const fn supported<L: Limits>(self) -> bool {
        L::HASH_ALGS.contains(self)
    }
    pub const fn from_alg(alg: TpmiAlgHash) -> Self {
        match alg {
            Sha1 => Self::SHA1,
            Sha256 => Self::SHA256,
            Sha384 => Self::SHA384,
            Sha512 => Self::SHA512,
            Sm3_256 => Self::SM3_256,
            Sha3_256 => Self::SHA3_256,
            Sha3_384 => Self::SHA3_384,
            Sha3_512 => Self::SHA3_512,
        }
    }
    pub const fn from_algs(algs: &[TpmiAlgHash]) -> Self {
        let mut tpma = Self(0);
        let mut i = 0;
        while i < algs.len() {
            let alg = algs[i];
            tpma = tpma.or(Self::from_alg(alg));
            i += 1;
        }
        tpma
    }
    pub const fn contains_alg(self, alg: TpmiAlgHash) -> bool {
        self.contains(Self::from_alg(alg))
    }
    pub const fn max_digest_size(self) -> usize {
        let digest_64 = Self::from_algs(&[Sha512, Sha3_512]);
        let digest_48 = Self::from_algs(&[Sha384, Sha3_384]);
        let digest_32 = Self::from_algs(&[Sha256, Sha3_256, Sm3_256]);
        let digest_20 = Self::from_alg(Sha1);
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
