//! Structure (`TPMS_`) types defined in:
//!   - Part 2, Section 10 "Structure Definitions"
//!   - Part 2, Section 11 "Algorithm Parameters and Structures"
//!   - Part 2, Section 12 "Key/Object Complex"
//!   - Part 2, Section 13 "NV Storage Structures"

use crate::{
    Tpm2bEccParameter, TpmiAlgHash, TpmiAlgKdf, TpmiEccCurve, TpmiMldsaParms, TpmiMlkemParms,
    TpmiRsaKeyBits, TpmtEccScheme, TpmtKdfScheme, TpmtKeyedHashScheme, TpmtRsaScheme,
    TpmtSymDefObject,
};

/// TODO: Write docs
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TpmsKeyedHashParms {
    pub scheme: Option<TpmtKeyedHashScheme>,
}

/// TODO: Write docs
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TpmsSymCipherParms {
    pub sym: TpmtSymDefObject,
}

/// `TPMS_RSA_PARMS`: a structure containing the parameters for an RSA key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TpmsRsaParms {
    /// The symmetric encryption scheme for a restricted decryption key.
    pub symmetric: Option<TpmtSymDefObject>,
    /// The signing scheme.
    pub scheme: Option<TpmtRsaScheme>,
    /// The number of bits in the public modulus.
    pub key_bits: TpmiRsaKeyBits,
    /// The public exponent. A value of zero indicates the default of 2^16 + 1.
    pub exponent: u32,
}

/// TODO: Write docs
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TpmsEccParms {
    pub symmetric: Option<TpmtSymDefObject>,
    pub scheme: Option<TpmtEccScheme>,
    pub curve_id: TpmiEccCurve,
    pub kdf: Option<TpmtKdfScheme>,
}

/// TODO: Write docs
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TpmsMldsaParms {
    pub parameter_set: TpmiMldsaParms,
    pub allow_external_mu: bool,
}

/// TODO: Write docs
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TpmsHashMldsaParms {
    pub parameter_set: TpmiMldsaParms,
    pub hash_alg: TpmiAlgHash,
}

/// TODO: Write docs
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TpmsMlkemParms {
    pub symmetric: Option<TpmtSymDefObject>,
    pub parameter_set: TpmiMlkemParms,
}

/// TODO: Write docs
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TpmsSchemeHash {
    pub hash_alg: TpmiAlgHash,
}
/// TODO: Write docs
pub type TpmsSchemeHmac = TpmsSchemeHash;
// TODO: add other variants
pub type TpmsKdfSchemeHkdf = TpmsSchemeHash;

/// TODO: Write docs
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TpmsSchemeEcdaa {
    pub hash_alg: TpmiAlgHash,
    pub count: u16,
}

/// TODO: Write docs
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TpmsSchemeXor {
    pub hash_alg: TpmiAlgHash,
    pub kdf: Option<TpmiAlgKdf>,
}

/// TODO: Write docs
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TpmsEccPoint<'a> {
    pub x: Tpm2bEccParameter<'a>,
    pub y: Tpm2bEccParameter<'a>,
}
