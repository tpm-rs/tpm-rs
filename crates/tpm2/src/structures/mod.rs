//! TPM 2.0 Structures and Specification Types
//!
//! This module groups all data structures, unions, interfaces, lists, buffers,
//! and attribute definitions defined in "Part 2: Structures" of the TPM 2.0 Specification.
//!
//! Internally, the types are partitioned into submodules according to their
//! naming prefixes in the specification:
//!
//! - [`tpm2b`]: Buffer types (`TPM2B_` prefix). Size-prefixed byte arrays which
//!   are either used for fixed-capacity buffers (e.g. [`Tpm2bDigest`]), or to
//!   wrap other types for encryption/decryption (e.g. [`Tpm2bPublic`]).
//! - [`tpma`]: Attribute types (`TPMA_` prefix). Typically represented via the
//!   `bitflags` crate (e.g., [`TpmaLocality`], [`TpmaNv`]).
//! - [`tpmi`]: Interface types (`TPMI_` prefix). Constrained subsets of larger
//!   types (e.g. [`TpmiAlgHash`], [`TpmiAlgKdf`]), which support conversion to
//!   and from the larger type.
//! - [`tpml`]: List types (`TPML_` prefix). Counted arrays containing lists of
//!   handles, digests, algorithms, etc... which have a fixed maximum capacity
//!   (e.g., [`TpmlPcrSelection`], [`TpmlDigest`]).
//! - [`tpms`]: Structure types (`TPMS_` prefix). Plain-old-data structs for
//!   fixed parameter bundles (e.g., [`TpmsClockInfo`], [`TpmsPcrSelection`]).
//! - [`tpmt`]: Template/Tagged Union types (`TPMT_` prefix). Modeled directly
//!   as Rust enums carrying data variants (e.g., [`TpmtPublic`], [`TpmtHa`]).
//! - [`tpmu`]: Union types (`TPMU_` prefix). Unions which need special handling
//!   not done for [`tpmt`], just [`TpmuAttest`] and [`TpmuSensitiveComposite`].
//!
//! We also define the special [`PublicParmsAndId`] type below in this file
//! which has similar handling to [`tpmu`], but contains _two_ unions.
//!
//! The [`headers`] submodule exports [`CommandHeader`] and [`ResponseHeader`].
//!
//! All types are re-exported flatly from this module, making them accessible
//! via `tpm2::*`.

mod headers;
mod tpm2b;
mod tpma;
mod tpmi;
mod tpml;
mod tpms;
mod tpmt;
mod tpmu;

pub use headers::*;
pub use tpm2b::*;
pub use tpma::*;
pub use tpmi::*;
pub use tpml::*;
pub use tpms::*;
pub use tpmt::*;
pub use tpmu::*;

use crate::{
    Alg, Marshal, Unmarshal,
    errors::UnmarshalError,
    marshal::{marshal_helper, max},
};

/// Internal union representing public object parameters and unique identifier.
///
/// We use this custom type in [`TpmtPublic`] to enforce at the type level that
/// the parameters (i.e. `TPMU_PUBLIC_PARMS`) and unique identifier (i.e.
/// `TPMU_PUBLIC_ID`) use the same algorithm.
#[doc(alias = "TPMU_PUBLIC_PARMS")]
#[doc(alias = "TPMU_PUBLIC_ID")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PublicParmsAndId<'a> {
    KeyedHash(Option<TpmtKeyedHashScheme>, Tpm2bDigest<'a>),
    Sym(TpmtSymDefObject, Tpm2bDigest<'a>),
    Rsa(TpmsRsaParms, Tpm2bPublicKeyRsa<'a>),
    Ecc(TpmsEccParms, TpmsEccPoint<'a>),
}

impl PublicParmsAndId<'_> {
    pub const fn parms(self) -> TpmtPublicParms {
        match self {
            Self::KeyedHash(p, _) => TpmtPublicParms::KeyedHash(p),
            Self::Sym(p, _) => TpmtPublicParms::Sym(p),
            Self::Rsa(p, _) => TpmtPublicParms::Rsa(p),
            Self::Ecc(p, _) => TpmtPublicParms::Ecc(p),
        }
    }
}

impl PublicParmsAndId<'_> {
    #[doc(alias = "TPMI_ALG_PUBLIC")]
    pub const fn algorithm(self) -> Alg {
        self.parms().algorithm()
    }
}
impl<'a> PublicParmsAndId<'a> {
    fn unmarshal_variant(selector: Alg, src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(match selector {
            Alg::KEYEDHASH => {
                Self::KeyedHash(Unmarshal::unmarshal(src)?, Unmarshal::unmarshal(src)?)
            }
            Alg::SYMCIPHER => Self::Sym(Unmarshal::unmarshal(src)?, Unmarshal::unmarshal(src)?),
            Alg::RSA => Self::Rsa(Unmarshal::unmarshal(src)?, Unmarshal::unmarshal(src)?),
            Alg::ECC => Self::Ecc(Unmarshal::unmarshal(src)?, Unmarshal::unmarshal(src)?),
            _ => return Err(UnmarshalError),
        })
    }
}

impl Marshal for PublicParmsAndId<'_> {
    const MAX_SIZE: usize = max(&[
        <Option<TpmtKeyedHashScheme>>::MAX_SIZE + Tpm2bDigest::MAX_SIZE,
        TpmtSymDefObject::MAX_SIZE + Tpm2bDigest::MAX_SIZE,
        TpmsRsaParms::MAX_SIZE + Tpm2bPublicKeyRsa::MAX_SIZE,
        TpmsEccParms::MAX_SIZE + TpmsEccPoint::MAX_SIZE,
    ]);
    type MaxBuffer = [u8; PublicParmsAndId::MAX_SIZE];

    fn marshal(&self, dst: &mut [u8; PublicParmsAndId::MAX_SIZE]) -> usize {
        match self {
            Self::KeyedHash(parms, id) => {
                let count = marshal_helper(parms, dst, 0);
                marshal_helper(id, dst, count)
            }
            Self::Sym(parms, id) => {
                let count = marshal_helper(parms, dst, 0);
                marshal_helper(id, dst, count)
            }
            Self::Rsa(parms, id) => {
                let count = marshal_helper(parms, dst, 0);
                marshal_helper(id, dst, count)
            }
            Self::Ecc(parms, point) => {
                let count = marshal_helper(parms, dst, 0);
                marshal_helper(point, dst, count)
            }
        }
    }
}

impl Default for PublicParmsAndId<'_> {
    fn default() -> Self {
        Self::KeyedHash(None, Default::default())
    }
}
