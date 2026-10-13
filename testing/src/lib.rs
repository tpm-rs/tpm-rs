//! Shared code of the end-to-end tests.
//!
//! The tests themselves live in `testing/tests/`: the Go parity tests in
//! `tests/go/` (test target `go`) and the topic-focused E2E tests in
//! `tests/e2e/` (test target `e2e`). Every test talks to a [`tpm::Tpm`]: a
//! pinned (seeded, virtual-clock) `tpm-rs` simulator that, with the
//! `differential` feature, mirrors every interaction to C reference TPMs (the
//! TCG reference `mstpm20` and the IBM `ibmswtpm2`) and fails the test on any
//! undocumented difference between `tpm-rs`'s and a reference's responses. The same tests are therefore both the `tpm-rs`
//! E2E tests and the differential tests.
//!
//! The crate provides:
//!
//! * [`tpm`]: the [`tpm::Tpm`] the tests drive, and the virtual-time
//!   [`tpm::sleep`];
//! * [`_common`] (also reachable as [`test_utils`]): reusable helpers of the
//!   E2E tests (command execution with sessions, templates, reference crypto,
//!   constants);
//! * `differential` (with the `differential` feature): the client of the
//!   reference processes (`src/bin/mstpm20.rs`, `src/bin/ibmswtpm2.rs`) that
//!   host one C reference TPM per `Tpm` and implementation, and the server
//!   logic they run to compare its responses with those of `tpm-rs`.

#![forbid(unsafe_code)]
#![allow(dead_code)]

pub mod _common;
pub use _common as test_utils;

#[cfg(feature = "differential")]
pub mod differential;
pub mod tpm;

pub use tpm::{SimulatorPlatformSignal, Tpm};
