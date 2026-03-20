//! Sized Buffer (`TPM2B_`) types defined in:
//!   - Part 2, Section 10 "Structure Definitions"
//!   - Part 2, Section 11 "Algorithm Parameters and Structures"
//!   - Part 2, Section 12 "Key/Object Complex"
//!   - Part 2, Section 13 "NV Storage Structures"

use crate::marshal::Limits;

/// `TPM2B_DIGEST`: a sized buffer holding a hash digest.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Tpm2bDigest<'a>(&'a [u8]);

impl<'a> Tpm2bDigest<'a> {
    pub const fn new<L: Limits>(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() <= Self::max_length::<L>() {
            Some(Self(bytes))
        } else {
            None
        }
    }
    pub const fn bytes(self) -> &'a [u8] {
        self.0
    }
    pub const fn max_length<L: Limits>() -> usize {
        const { L::HASH_ALGS.max_digest_size() }
    }
}

/// TODO: Write Docs
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Tpm2bPublicKeyRsa<'a>(&'a [u8]);

/// TODO: Write Docs
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Tpm2bEccParameter<'a>(&'a [u8]);

/// TODO: Write Docs
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Tpm2bPublicKeyMldsa<'a>(&'a [u8]);

/// TODO: Write Docs
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Tpm2bPublicKeyMlkem<'a>(&'a [u8]);
