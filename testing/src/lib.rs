//! Shared code of the end-to-end tests.
//!
//! The tests themselves live in `testing/tests/`: the Go parity tests in
//! `tests/go/` (test target `go`) and the topic-focused E2E tests in
//! `tests/e2e/` (test target `e2e`). Every test talks to a [`tpm::Tpm`]: a
//! pinned (seeded, virtual-clock) `tpm-rs` simulator that, in a differential
//! build (one `target-*` feature), mirrors every interaction to the C
//! reference TPM of the target (the public or version 185 TCG reference
//! `mstpm20`, or the IBM `ibmswtpm2`) and fails the test on any undocumented
//! difference between `tpm-rs`'s and the reference's responses. The same tests
//! are therefore both the `tpm-rs` E2E tests and the differential tests.
//!
//! The crate provides:
//!
//! * [`tpm`]: the [`tpm::Tpm`] the tests drive, and the virtual-time
//!   [`tpm::sleep`];
//! * [`_common`] (also reachable as [`test_utils`]): reusable helpers of the
//!   E2E tests (command execution with sessions, templates, reference crypto,
//!   constants);
//! * `differential` (in a differential build): the client of the
//!   reference process (`src/bin/reference.rs`) that
//!   host one C reference TPM per `Tpm` and implementation, and the server
//!   logic they run to compare its responses with those of `tpm-rs`.

// The only `unsafe` code is the FFI of the linked C reference TPMs
// (`differential::inproc`, with `differential`), which allows it locally.
#![cfg_attr(feature = "differential", deny(unsafe_code))]
#![cfg_attr(not(feature = "differential"), forbid(unsafe_code))]
#![allow(dead_code)]

pub mod _common;
pub use _common as test_utils;

#[cfg(feature = "differential")]
pub mod differential;
pub mod seed;
pub mod tpm;

pub use tpm::{SimulatorPlatformSignal, Tpm};
