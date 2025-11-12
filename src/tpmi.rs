//! Interface (`TPMI_`) types defined in:
//!   - Part 2, Section 9 "Interface Types"
use crate::{
    Alg,
    errors::UnmarshalError,
    marshal::{Limits, MarshalFixed, UnmarshalFixed},
};

/// `TPMI_ALG_HASH`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
#[repr(u16)]
pub enum TpmiAlgHash {
    Sha1 = Alg::Sha1.0,
    Sha256 = Alg::Sha256.0,
    Sha384 = Alg::Sha384.0,
    Sha512 = Alg::Sha512.0,
    Sm3_256 = Alg::Sm3_256.0,
    Sha3_256 = Alg::Sha3_256.0,
    Sha3_384 = Alg::Sha3_384.0,
    Sha3_512 = Alg::Sha3_512.0,
}
use TpmiAlgHash::*;

impl TpmiAlgHash {
    pub const fn digest_size(self) -> usize {
        match self {
            Sha1 => 160 / 8,
            Sha256 => 256 / 8,
            Sha384 => 384 / 8,
            Sha512 => 512 / 8,
            Sm3_256 => 256 / 8,
            Sha3_256 => 256 / 8,
            Sha3_384 => 384 / 8,
            Sha3_512 => 512 / 8,
        }
    }
    pub const fn supported<L: Limits>(self) -> bool {
        L::HASH_ALGS.supports_alg(self)
    }
    pub const fn from_alg<L: Limits>(a: Alg) -> Option<Self> {
        match a {
            Alg::Sha1 if const { Sha1.supported::<L>() } => Some(Sha1),
            Alg::Sha256 if const { Sha256.supported::<L>() } => Some(Sha256),
            Alg::Sha384 if const { Sha384.supported::<L>() } => Some(Sha384),
            Alg::Sha512 if const { Sha512.supported::<L>() } => Some(Sha512),
            Alg::Sm3_256 if const { Sm3_256.supported::<L>() } => Some(Sm3_256),
            Alg::Sha3_256 if const { Sha3_256.supported::<L>() } => Some(Sha3_256),
            Alg::Sha3_384 if const { Sha3_384.supported::<L>() } => Some(Sha3_384),
            Alg::Sha3_512 if const { Sha3_512.supported::<L>() } => Some(Sha3_512),
            _ => None,
        }
    }
}

impl From<TpmiAlgHash> for Alg {
    fn from(h: TpmiAlgHash) -> Alg {
        Alg(h as u16)
    }
}
impl From<Option<TpmiAlgHash>> for Alg {
    fn from(value: Option<TpmiAlgHash>) -> Self {
        match value {
            Some(h) => h.into(),
            None => Self::Null,
        }
    }
}

impl MarshalFixed for TpmiAlgHash {
    const SIZE: usize = 2;
    type Array = [u8; 2];
    fn marshal_fixed(&self, arr: &mut [u8; Self::SIZE]) {
        Alg::from(*self).marshal_fixed(arr)
    }
}
impl UnmarshalFixed for TpmiAlgHash {
    fn unmarshal_fixed<L: Limits>(arr: &Self::Array) -> Result<Self, UnmarshalError> {
        Self::from_alg::<L>(Alg::unmarshal_fixed::<L>(arr)?).ok_or(UnmarshalError)
    }
}
impl MarshalFixed for Option<TpmiAlgHash> {
    const SIZE: usize = 2;
    type Array = [u8; 2];
    fn marshal_fixed(&self, arr: &mut [u8; Self::SIZE]) {
        Alg::from(*self).marshal_fixed(arr)
    }
}
impl UnmarshalFixed for Option<TpmiAlgHash> {
    fn unmarshal_fixed<L: Limits>(arr: &Self::Array) -> Result<Self, UnmarshalError> {
        match Alg::unmarshal_fixed::<L>(arr)? {
            Alg::Null => Ok(None),
            a => match TpmiAlgHash::from_alg::<L>(a) {
                Some(h) => Ok(Some(h)),
                None => Err(UnmarshalError),
            },
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
#[repr(u16)]
pub enum TpmiAlgSymMode {
    Ctr = Alg::Ctr.0,
    // TODO add other variants
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
#[repr(u16)]
pub enum TpmiAlgKdf {
    Hkdf = Alg::Hkdf.0,
    // TODO add other variants
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct TpmiRsaKeyBits(pub u16);

impl TpmiRsaKeyBits {
    pub const fn new<L: Limits>(bits: u16) -> Option<Self> {
        if L::RSA_KEY_SIZES.supports_key_bits(bits) {
            Some(Self(bits))
        } else {
            None
        }
    }
}

impl MarshalFixed for TpmiRsaKeyBits {
    const SIZE: usize = 2;
    type Array = [u8; 2];
    fn marshal_fixed(&self, arr: &mut [u8; Self::SIZE]) {
        self.0.marshal_fixed(arr)
    }
}
impl UnmarshalFixed for TpmiRsaKeyBits {
    fn unmarshal_fixed<L: Limits>(arr: &Self::Array) -> Result<Self, UnmarshalError> {
        Self::new::<L>(u16::unmarshal_fixed::<L>(arr)?).ok_or(UnmarshalError)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct TpmiAesKeyBits(pub u16);
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct TpmiSm4KeyBits(pub u16);
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct TpmiCamelliaKeyBits(pub u16);
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct TpmiTdesKeyBits(pub u16);

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct TpmiEccCurve(pub u16);

impl TpmiEccCurve {
    /// NIST P-192.
    pub const NIST_P192: Self = Self(0x0001);
    /// NIST P-224.
    pub const NIST_P224: Self = Self(0x0002);
    /// NIST P-256.
    pub const NIST_P256: Self = Self(0x0003);
    /// NIST P-384.
    pub const NIST_P384: Self = Self(0x0004);
    /// NIST P-521.
    pub const NIST_P521: Self = Self(0x0005);
    /// Barreto-Naehrig P-256.
    pub const BN_P256: Self = Self(0x0010);
    /// Barreto-Naehrig P-638.
    pub const BN_P638: Self = Self(0x0011);
    /// SM2 P-256.
    pub const SM2_P256: Self = Self(0x0020);
    /// Brainpool P-256 R1.
    pub const BP_P256_R1: Self = Self(0x0030);
    /// Brainpool P-384 R1.
    pub const BP_P384_R1: Self = Self(0x0031);
    /// Brainpool P-512 R1.
    pub const BP_P512_R1: Self = Self(0x0032);
    /// Curve25519.
    pub const CURVE_25519: Self = Self(0x0040);
    /// Curve448-Goldilocks.
    pub const CURVE_448: Self = Self(0x0041);
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct TpmiMldsaParms(pub u16);

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct TpmiMlkemParms(pub u16);
