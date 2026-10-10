//! Runs the shared cryptography test suite against `tpm2_boringssl::BoringSsl`.

#![cfg(feature = "boringssl")]

tpm2_crypto_tests::backend_tests!(
    boringssl,
    tpm2_boringssl::BoringSsl,
    tpm2_crypto_tests::backends::BORINGSSL,
);
