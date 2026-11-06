//! Known-answer test vectors for the `tpm2` crypto backends.
//!
//! The tests live in this crate's `tests/` directory: `tests/common/suite.rs`
//! tests a single backend and `tests/common/interop.rs` tests a pair of
//! backends against each other. Each top-level test target (e.g.
//! `tests/rustcrypto.rs` or `tests/boringssl_rustcrypto.rs`) selects the
//! backend(s) with type aliases and includes one of these files.
//!
//! ## Sources
//!
//! Each vector's documentation names its source. These are published test
//! vectors (FIPS-197, NIST SP 800-38A/B, RFC 4231, RFC 5903, RFC 6979, RFC 7748,
//! RFC 8032, and TPM KATs), or outputs of independent implementations (Python
//! `hashlib`/`hmac`, Python big-integer arithmetic, and pyca/cryptography).
#![no_std]

use tpm2::crypto::CryptoError;
// The backends are only used by the tests.
#[cfg(feature = "boringssl")]
use tpm2_boringssl as _;
#[cfg(feature = "rustcrypto")]
use tpm2_rustcrypto as _;

pub mod vectors;

/// Returns `None` if `result` is `Err(`[`CryptoError::Unsupported`]`)`, i.e.
/// the backend doesn't implement the requested algorithm, curve, parameter
/// set, or scheme, so tests can skip that case.
///
/// # Panics
///
/// Panics on any other error.
#[track_caller]
pub fn supported<T>(result: Result<T, CryptoError>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(CryptoError::Unsupported) => None,
        Err(err) => panic!("unexpected error: {err:?}"),
    }
}
