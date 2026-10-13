//! # Trusted Platform Module 2.0 (TPM2) Structures and Commands
//!
//! <div class="warning">
//! This code is unstable and there are no guarantees of stability at this time.
//! </div>
//!
//! This base crate provides:
//!   - Definitions of the TPM2 constants and structures.
//!   - Definitions of the [TPM2 Commands](commands).
//!   - Common traits for [`Marshal`]ing and [`Unmarshal`]ing.
//!   - Platform abstraction for crypto, timers, PCRs, and NV Storage.

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
//! Types or items that either do not map to a type in the spec
//! (e.g., [`Marshal`] or [`Command`]) or have semantics differing from those in
//! the spec (e.g., [`Alg`]) will not have a `Tpm` prefix.
//!
//! [TPM2 Specification]: https://trustedcomputinggroup.org/work-groups/trusted-platform-module/
//!
//! ## Algorithm Feature Flags
//!
//! Cargo features control which cryptographic algorithms and modes are enabled
//! in types (like [`TpmiAlgHash`], [`TpmtHa`], [`AlgSym`], [`TpmiAlgSymMode`],
//! and [`TpmiAlgCipherMode`]), size limits (like
//! [`TpmiAlgHash::MAX_DIGEST_BYTES`] and [`AlgSym::MAX_KEY_BYTES`]), and
//! [`crypto`] wrappers. All hash, symmetric cipher, and symmetric mode
//! features are enabled by default, together with RSA-2048 and larger
//! (`rsa2048`, `rsa3072`, `rsa4096`, `rsassa`, `rsapss`, `rsaes`, `oaep`) and
//! NIST P-256 and larger ECC (`ecc_curve_nist_p256`, `ecc_curve_nist_p384`,
//! `ecc_curve_nist_p521`, `nist_p256`, `nist_p384`, `nist_p521`, `ecdsa`,
//! `ecdh`, `ecdaa`). Constrained builds can set `default-features = false` and
//! enable a subset:
//!
//! - **Hash algorithms** (at least one required): `sha1`, `sha256`, `sha384`,
//!   `sha512`, `sm3_256`, `sha3_256`, `sha3_384`, `sha3_512`
//! - **Symmetric ciphers** (at least one required): `aes128`, `aes192`,
//!   `aes256`, `sm4_128`, `camellia128`, `camellia192`, `camellia256`
//! - **Symmetric modes** (`CFB` is always enabled): `cmac`, `ctr`, `ofb`,
//!   `cbc`, `ecb`
//! - **RSA** (each feature implies `rsa`): key sizes `rsa1024`, `rsa2048`,
//!   `rsa3072`, `rsa4096`; schemes `rsassa`, `rsapss`, `rsaes`, `oaep`
//! - **ECC** (each feature implies `ecc`): curves `ecc_curve_nist_p192`,
//!   `ecc_curve_nist_p224`, `ecc_curve_nist_p256`, `ecc_curve_nist_p384`,
//!   `ecc_curve_nist_p521`, `ecc_curve_bn_p256`, `ecc_curve_bn_p638`,
//!   `ecc_curve_sm2_p256`, `ecc_curve_bp_p256_r1`, `ecc_curve_bp_p384_r1`,
//!   `ecc_curve_bp_p512_r1`, `ecc_curve_curve25519`, `ecc_curve_curve448`
//!   (with the shorthands `nist_p224`, `nist_p256`, `nist_p384`, `nist_p521`,
//!   `bn_p256`, `sm2_p256`); schemes `ecdsa`, `ecdh`, `ecdaa`, `sm2`,
//!   `ecschnorr`, `ecmqv`
//!
//! ## Platform Support and Abstraction
//!
//! The core TPM 2.0 library is designed to execute in a wide variety of environments—ranging
//! from resource-constrained embedded firmware (utilizing custom hardware accelerators) to hosted
//! user-space applications running on modern operating systems (e.g., Linux, Windows).
//!
//! The [`platform`] module defines abstract interfaces for functionality the library depends
//! on that implemented by the underlying platform, such as cryptography, random number
//! generation, non-volatile storage, monotonic timers, and PCR registers. These interfaces decouple
//! the core command execution and state engine from a particular platform.
//!
//! This crate is `#[no_std]` and strictly avoids depending on the `std` or `alloc` libraries
//! (only `core` is used) to support bare-metal execution.
//!
//! ## Lifetimes (`'a`) in types
//!
//! Many of the complex structures in this crate (such as [`TpmtPublic<'a>`])
//! have associated lifetimes to allow for components like [`Tpm2bDigest<'a>`]
//! or [`TpmtHa<'a>`] to take byte buffers by reference. This allows our types
//! to remain small, implement [`Copy`], and avoid allocating additional memory
//! on the stack or heap.
//!
//! ```
//! # use tpm2::{TpmtPublic, Unmarshal, errors::UnmarshalError};
//! fn parse<'a>(mut buf: &'a [u8]) -> Result<&'a [u8], UnmarshalError> {
//!     // Parse a structure from a raw byte buffer:
//!     let public: TpmtPublic<'a> = TpmtPublic::unmarshal(&mut buf)?;
//!     // The auth_policy buffer is just a sub-slice of buf. No copying!
//!     Ok(public.auth_policy.as_slice())
//! }
//! ```
//!
//! ## Panics
//!
//! The library seeks to avoid panics. While there currently aren't tools to
//! statically guarantee that this is the case, we will incorporate tests and checks
//! that panic code is not emitted.
//!
//! ## Dependencies
//!
//! To allow this crate to be used in constrained environments (like kernels or
//! TPM2 firmware), it does not allow runtime dependencies.
//!
//! [build-dependencies]: https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#build-dependencies
//! [dev-dependencies]: https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#development-dependencies
//!
//! ## Submodule Organization
//!
//! Internally, we use submodules for code organization, but mostly present a
//! flat API to external users, with the exception of the [`commands`],
//! [`errors`], and [`limits`] submodules.
#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![forbid(unsafe_code)]
#![forbid(unreachable_pub)]
#![allow(clippy::large_enum_variant)]

pub mod commands;
mod constants;
pub mod crypto;
pub mod errors;
pub mod limits;
mod marshal;
pub mod platform;
#[cfg(feature = "std")]
mod std;
mod structures;

pub use commands::{Command, Message, UnmarshalMessage};
pub use constants::*;
pub use marshal::{Marshal, Unmarshal};
pub use structures::*;

/// Common trait for communicating with a TPM.
pub trait Connection {
    /// The type returned if [`Connection::transact`] fails.
    ///
    /// This type does not include `TPM_RC` errors, only errors related to the
    /// connection itself. If the connection can never fail, this can be [`!`].
    type Error: core::error::Error;

    /// Perform a command/response transaction with the TPM.
    ///
    /// Returns a slice of the response containing the bytes that were returned
    /// from the TPM.
    ///
    /// Note that even if the response contains a `TPM_RC` error, this method
    /// still returns `Ok(...)`. `Err` is only returned when we are unable to
    /// get a response at all.
    fn transact<'a>(&mut self, cmd: &[u8], rsp: &'a mut [u8]) -> Result<&'a mut [u8], Self::Error>;
}
