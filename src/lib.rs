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
//! [`Marshal`]: marshal::Marshal
//! [`Unmarshal`]: marshal::Unmarshal
//! [TPM2 Specification]: https://trustedcomputinggroup.org/work-groups/trusted-platform-module/
//! [build-dependencies]: https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#build-dependencies
//! [dev-dependencies]: https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#development-dependencies
#![no_std]

pub mod commands;
pub use commands::Command;

// Seperate the Errors and Marshaling types/traits from everything else
pub mod errors;
pub mod marshal;

// We use submodules for organizing the TPM Spec types, but expose a flat API.
mod base;
mod constants;
pub use constants::*;
mod tpma;
pub use tpma::*;
mod tpmi;
pub use tpmi::*;
mod tpmt;
pub use tpmt::*;
