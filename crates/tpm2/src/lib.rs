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
//!
//! ## Submodule Organization
//!
//! Internally, we use submodules for code organization, but mostly present a
//! flat API to external users, with the exception of the [`commands`] and
//! [`errors`] submodules.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![forbid(unreachable_pub)]
#![allow(clippy::large_enum_variant)]

pub mod commands;
mod constants;
pub mod crypto;
pub mod errors;
mod marshal;
#[cfg(feature = "std")]
mod std;
mod structures;

pub use constants::*;
pub use marshal::{Marshal, Unmarshal};
pub use structures::*;

/// Trait for a TPM command transaction.
pub trait Command: Marshal {
    /// The command code.
    const CMD_CODE: TpmCc;
    /// The response parameters type.
    type Response<'a>: Marshal + Unmarshal<'a>;
}

/// Common trait for communicating with a TPM.
pub trait Connection {
    /// The type returned if [`Connection::transact`] fails.
    ///
    /// This type does not include `TPM_RC` errors, only errors related to the
    /// connection itself. If the connection can never fail, this can be
    /// [`Infallible`](core::convert::Infallible).
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
