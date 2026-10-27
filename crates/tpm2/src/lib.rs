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
//! [TPM2 Specification]: https://trustedcomputinggroup.org/work-groups/trusted-platform-module/
//!
//! ## Integer Types
//!
//! The TPM specification and C implementation generally do not specify the
//! specific types for integer constants/values. To avoid confusion, we will
//! use [`usize`] for lengths or when specifying a number of _bytes_, and
//! [`u16`] when specifying a number of _bits_. We avoid uses of [`u32`]
//! (even for [`Tpml`] lengths) to avoid `u32 -> usize` conversions, which
//! can be lossy depending on the platform.
//!
//! ## Algorithm Feature Flags
//!
//! Cargo features control which cryptographic algorithms and modes are enabled
//! in types (like [`TpmiAlgHash`], [`TpmtHa`], [`AlgSym`], [`TpmiAlgSymMode`],
//! and [`TpmiAlgCipherMode`]), size limits (like
//! [`TpmiAlgHash::MAX_DIGEST_BYTES`] and [`AlgSym::MAX_KEY_BYTES`]), and
//! [`crypto`] dispatch functions and enums. All algorithm features are enabled
//! by default; constrained builds can set `default-features = false` and enable
//! a subset:
//!
//! - **Hash algorithms** (at least one required): `sha1`, `sha256`, `sha384`,
//!   `sha512`, `sm3_256`, `sha3_256`, `sha3_384`, `sha3_512`
//! - **Symmetric ciphers** (at least one required): `aes128`, `aes192`,
//!   `aes256`, `sm4_128`, `camellia128`, `camellia192`, `camellia256`
//! - **Symmetric modes** (`CFB` is always enabled): `ctr`, `ofb`, `cbc`, `ecb`
//! - **CMAC**: `cmac`
//! - **Asymmetric families**: `rsa`, `ecc`, `mldsa` (pure ML-DSA), `mlkem`.
//!   These are implied by the more specific features below. Each family always
//!   includes its TPM secret sharing primitive: RSA-OAEP, ECDH (including
//!   X25519/X448), or ML-KEM.
//! - **RSA key sizes** (at least one required with `rsa`): `rsa1024`,
//!   `rsa2048`, `rsa3072`, `rsa4096`
//! - **RSA schemes** (`OAEP` is always enabled with `rsa`): `rsassa`,
//!   `rsapss`, `rsaes`
//! - **ECC curves** (at least one required with `ecc`): `nist_p192`,
//!   `nist_p224`, `nist_p256`, `nist_p384`, `nist_p521`, `bn_p256`, `bn_p638`,
//!   `sm2_p256`, `bp_p256_r1`, `bp_p384_r1`, `bp_p512_r1`, `curve25519`,
//!   `curve448`
//! - **ECC schemes** (`ECDH` is always enabled with `ecc`): `ecdsa`, `ecdaa`,
//!   `ecschnorr`, `eddsa`, `hash_eddsa`, `sm2` (signing and key exchange),
//!   `ecmqv`. `eddsa` and `hash_eddsa` require `curve25519` or `curve448`, and
//!   `hash_eddsa` implies `eddsa`.
//! - **ML-DSA** (at least one parameter set required with `mldsa`):
//!   `mldsa_44`, `mldsa_65`, `mldsa_87`, and the `hash_mldsa` scheme (which
//!   implies `mldsa`)
//! - **ML-KEM** (at least one parameter set required with `mlkem`):
//!   `mlkem_512`, `mlkem_768`, `mlkem_1024`
//!
//! These features control which wire-format variants exist (e.g.
//! [`TpmtPublicParms`], [`TpmtSignature`], [`TpmtSigScheme`], and
//! [`TpmEccCurve`]), and therefore which values can be unmarshalled, as well as
//! derived buffer sizes (like [`TpmtPublicParms::MAX_ENCRYPTED_SECRET_BYTES`]
//! and [`TpmtSignature`]'s maximum size).
//!
//! All [`commands`] are always available. If an algorithm family is disabled,
//! the types used by its commands still exist, but their enums have no
//! variants (e.g. [`TpmEccCurve`] or [`TpmiRsaKeyBits`]) and their buffers
//! have a capacity of zero (e.g. [`Tpm2bPublicKeyRsa`] or
//! [`Tpm2bEccParameter`]). Such commands can't be meaningfully constructed or
//! unmarshalled.
//!
//! ## Platform Support
//!
//! Unlike some other crates under the TPM-RS project, this crate is intended
//! to work on platforms and in environments which lack the Rust Standard
//! Library or memory allocation. To that end, this crate is `#[no_std]`,
//! and does not use the `std` or `alloc` libraries (only `core` is used).
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
//! Furthermore, we **strive to avoid panics in this library**. While this cannot
//! be statically guaranteed by Rust, we will run tests to ensure that panic code
//! is not emitted, provided sufficient optimizations are enabled.
//!
//! ## Dependencies
//!
//! To allow this crate to be used in constrained environments (like kernels or
//! TPM2 implementations), we minimize external dependencies and disallow any
//! [build-dependencies] or procedural macros. We will have more
//! [dev-dependencies] for running additional tests, but such additional
//! dev-dependencies should be gated by opt-in Cargo features.
//!
//! [build-dependencies]: https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#build-dependencies
//! [dev-dependencies]: https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#development-dependencies
//!
//! ## Submodule Organization
//!
//! Internally, we use submodules for code organization, but mostly present a
//! flat API to external users, with the exception of the [`commands`],
//! [`errors`], and [`limits`] submodules.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![forbid(unreachable_pub)]
#![allow(clippy::large_enum_variant)]

#[macro_use]
mod macros;

pub mod commands;
mod constants;
pub mod crypto;
pub mod errors;
pub mod limits;
mod marshal;
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

/// Convert a bit count into a byte count
pub(crate) const fn bits_to_bytes(bits: u16) -> usize {
    bits.div_ceil(8) as usize
}

// Algorithm feature checks

#[cfg(not(any(
    feature = "sha1",
    feature = "sha256",
    feature = "sha384",
    feature = "sha512",
    feature = "sm3_256",
    feature = "sha3_256",
    feature = "sha3_384",
    feature = "sha3_512",
)))]
compile_error!("at least one hash algorithm feature must be enabled");

#[cfg(not(any(
    feature = "aes128",
    feature = "aes192",
    feature = "aes256",
    feature = "sm4_128",
    feature = "camellia128",
    feature = "camellia192",
    feature = "camellia256",
)))]
compile_error!("at least one symmetric algorithm feature must be enabled");

#[cfg(all(
    feature = "rsa",
    not(any(
        feature = "rsa1024",
        feature = "rsa2048",
        feature = "rsa3072",
        feature = "rsa4096",
    ))
))]
compile_error!("the `rsa` feature requires at least one RSA key size feature (e.g. `rsa2048`)");

#[cfg(all(
    feature = "ecc",
    not(any(
        feature = "nist_p192",
        feature = "nist_p224",
        feature = "nist_p256",
        feature = "nist_p384",
        feature = "nist_p521",
        feature = "bn_p256",
        feature = "bn_p638",
        feature = "sm2_p256",
        feature = "bp_p256_r1",
        feature = "bp_p384_r1",
        feature = "bp_p512_r1",
        feature = "curve25519",
        feature = "curve448",
    ))
))]
compile_error!("the `ecc` feature requires at least one ECC curve feature (e.g. `nist_p256`)");

#[cfg(all(
    feature = "eddsa",
    not(any(feature = "curve25519", feature = "curve448"))
))]
compile_error!("the `eddsa` feature requires the `curve25519` or `curve448` feature");

#[cfg(all(
    feature = "mldsa",
    not(any(feature = "mldsa_44", feature = "mldsa_65", feature = "mldsa_87"))
))]
compile_error!("the `mldsa` feature requires at least one ML-DSA parameter set feature");

#[cfg(all(
    feature = "mlkem",
    not(any(feature = "mlkem_512", feature = "mlkem_768", feature = "mlkem_1024"))
))]
compile_error!("the `mlkem` feature requires at least one ML-KEM parameter set feature");
