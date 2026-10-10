//! Runs the shared cryptography test suite against `tpm2_libcrux::Libcrux`.

#![cfg(feature = "libcrux")]

tpm2_crypto_tests::backend_tests!(
    libcrux,
    tpm2_libcrux::Libcrux,
    tpm2_crypto_tests::backends::LIBCRUX,
);
