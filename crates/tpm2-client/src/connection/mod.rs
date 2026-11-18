//! The connection module provides the top level [`Connection`] trait.
//!
//! Implementations of the trait live in their own crates, such as `tpm2-tcp`
//! for the TCP-based TPM simulator.

pub use tpm2::Connection;
