//! Shared code of the end-to-end tests.
//!
//! The tests themselves live in `testing/tests/`: the Go parity tests in
//! `tests/go/` (test target `go`) and the topic-focused E2E tests in
//! `tests/e2e/` (test target `e2e`). Every test talks to an in-process
//! `tpm-rs` simulator created with `tpm2_simulator::create_simulator!()`,
//! only through its command interface.
//!
//! The crate provides [`_common`] (also reachable as [`test_utils`]): reusable
//! helpers of the E2E tests (command execution with sessions, templates,
//! reference crypto, constants).

#![forbid(unsafe_code)]
#![allow(dead_code)]

pub mod _common;
pub use _common as test_utils;
