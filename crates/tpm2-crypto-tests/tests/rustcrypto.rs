//! Runs the shared cryptography test suite against `tpm2_rustcrypto::RustCrypto`.

#![cfg(feature = "rustcrypto")]

tpm2_crypto_tests::backend_tests!(
    rustcrypto,
    tpm2_rustcrypto::RustCrypto,
    tpm2_crypto_tests::backends::RUSTCRYPTO,
);
