// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2025 Trusted Computing Group and TPM-RS Project Devolopers

//! # Trusted Platform Module 2.0 (TPM2) Structures and Commands
//!
//! This base crate provides:
//!   - Definitions of the TPM2 constants and structures.
//!   - Definitions of the [TPM2 Commands](commands).
//!   - Common traits for [`Marshal`]ing and [`Unmarshal`]ing.
//!
//! ## Design Goals
//!
//! This crate defines a low-level interface to any TPM2. The types and
//! commands in this crate can be used to either communicate with an existing
//! TPM2 (i.e., be used in a client) or to _implement_ a TPM2.
//!
//! Many types in this crate have a direct counterpart in "Part 2: Structures"
//! of the [TPM2 Specification]. Types that map 1:1 to the specification have a
//! `Tpm` prefix. For example:
//!   - The [`TpmtHa`] enum corresponds to the `TPMT_HA` type.
//!   - The [`TpmiAlgHash`] C-like enum corresponds to the `TPMI_ALG_HASH` type.
//!
//! Conversely, types or items that either do not map to a type in the spec
//! (e.g., [`Marshal`] or [`Command`]) or have semantics differing from those in
//! the spec (e.g., [`Alg`]) will not have a `Tpm` prefix.
//!
//! will not have a `Tpm` prefix.
//!
//! [TPM2 Specification]: https://trustedcomputinggroup.org/work-groups/trusted-platform-module/
//!
//! ## Platform Support
//!
//! Unlike some other crates under the TPM-RS project, this crate is intended
//! to work on platforms and in environments which lack the Rust Standard
//! Library or memory allocation. To that end, this crate is `#[no_std]`,
//! and does not use the `std` or `alloc` libraries (only `core` is used).
//!
//! ## Panics
//!
//! Furthermore, we **strive to avoid panics in this library**. While this cannot
//! be statically guaranteed by Rust, we will run tests to ensure that panic code
//! is not emitted, provided sufficient optimizations are enabled.
//!
//! ## Dependencies
//!
//! To allow this crate to be used in constrained environments (like kernels or
//! TPM2 implementations), we disallow any _runtime_ dependencies. Also, we
//! restrict our [build-dependencies] to a subset necessary to create Procedural
//! Macros (`proc_macro`, `syn`, `quote`, etc...). We will have more
//! [dev-dependencies] for running additional tests, but such additional
//! dev-dependencies should be gated by opt-in Cargo features.
//!
//! [build-dependencies]: https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#build-dependencies
//! [dev-dependencies]: https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#development-dependencies
#![no_std]

pub mod commands;
pub use commands::Command;

pub mod errors;
use errors::*;

// We use submodules for code organization, but present a flat API to external users.
mod hash;
pub use hash::*;
mod marshal;
pub use marshal::*;

/// Algorithms defined by either the `TPM_ALG_ID` listing in Part 2 of the
/// [TPM2 Specification] or the `TCG_ALG_ID` list in the
/// [TCG Algorithm Registry](https://trustedcomputinggroup.org/resource/tcg-algorithm-registry/).
#[derive(Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct Alg(pub u16);

// We do this for naming consistnancy with the other algorithm enums.
// TODO: Should this just be an enum?
#[allow(non_upper_case_globals)]
impl Alg {
    pub const Rsa: Self = Self(0x0001);
    pub const Tdes: Self = Self(0x0003);
    pub const Sha1: Self = Self(0x0004);
    pub const Hmac: Self = Self(0x0005);
    pub const Aes: Self = Self(0x0006);
    pub const Mgf1: Self = Self(0x0007);
    pub const KeyedHash: Self = Self(0x0008);
    pub const Null: Self = Self(0x0010);
    pub const Xor: Self = Self(0x000A);
    pub const Sha256: Self = Self(0x000B);
    pub const Sha384: Self = Self(0x000C);
    pub const Sha512: Self = Self(0x000D);
    pub const Sm3_256: Self = Self(0x0012);
    pub const Sm4: Self = Self(0x0013);
    pub const RsaSsa: Self = Self(0x0014);
    pub const RsaEs: Self = Self(0x0015);
    pub const RsaPss: Self = Self(0x0016);
    pub const Oaep: Self = Self(0x0017);
    pub const Ecdsa: Self = Self(0x0018);
    pub const Ecdh: Self = Self(0x0019);
    pub const Ecdaa: Self = Self(0x001A);
    pub const Sm2: Self = Self(0x001B);
    pub const EcSchnorr: Self = Self(0x001C);
    pub const Ecmqv: Self = Self(0x001D);
    pub const Kdf1Sp800_56A: Self = Self(0x0020);
    pub const Kdf2: Self = Self(0x0021);
    pub const Kdf1Sp800_108: Self = Self(0x0022);
    pub const Ecc: Self = Self(0x0023);
    pub const SymCipher: Self = Self(0x0025);
    pub const Camellia: Self = Self(0x0026);
    pub const Sha3_256: Self = Self(0x0027);
    pub const Sha3_384: Self = Self(0x0028);
    pub const Sha3_512: Self = Self(0x0029);
    pub const Ctr: Self = Self(0x0040);
    pub const Ofb: Self = Self(0x0041);
    pub const Cbc: Self = Self(0x0042);
    pub const Cfb: Self = Self(0x0043);
    pub const Ecb: Self = Self(0x0044);
}

impl MarshalFixed for Alg {
    const SIZE: usize = 2;
    type Array = [u8; 2];
    #[inline(always)]
    fn marshal_fixed(&self, arr: &mut [u8; Self::SIZE]) {
        self.0.marshal_fixed(arr)
    }
}
impl UnmarshalFixed for Alg {
    #[inline(always)]
    fn unmarshal_fixed(&mut self, arr: &[u8; Self::SIZE]) -> Result<(), UnmarshalError> {
        self.0.unmarshal_fixed(arr)
    }
}

#[cfg(test)]
mod test {
    use crate::TpmtHa;

    #[test]
    fn size_of_tpmt_ha() {
        assert_eq!(size_of::<TpmtHa>(), 2 * size_of::<usize>());
        assert_eq!(size_of::<Option<TpmtHa>>(), 2 * size_of::<usize>());
    }
}
