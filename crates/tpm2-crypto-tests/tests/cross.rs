//! Cross-backend agreement and interoperability tests for every enabled pair
//! of backends.

#[cfg(all(feature = "rustcrypto", feature = "libcrux"))]
tpm2_crypto_tests::cross_backend_tests!(
    rustcrypto_libcrux,
    (
        tpm2_rustcrypto::RustCrypto,
        tpm2_crypto_tests::backends::RUSTCRYPTO
    ),
    (tpm2_libcrux::Libcrux, tpm2_crypto_tests::backends::LIBCRUX),
);

#[cfg(all(feature = "rustcrypto", feature = "boringssl"))]
tpm2_crypto_tests::cross_backend_tests!(
    rustcrypto_boringssl,
    (
        tpm2_rustcrypto::RustCrypto,
        tpm2_crypto_tests::backends::RUSTCRYPTO
    ),
    (
        tpm2_boringssl::BoringSsl,
        tpm2_crypto_tests::backends::BORINGSSL
    ),
);

#[cfg(all(feature = "libcrux", feature = "boringssl"))]
tpm2_crypto_tests::cross_backend_tests!(
    libcrux_boringssl,
    (tpm2_libcrux::Libcrux, tpm2_crypto_tests::backends::LIBCRUX),
    (
        tpm2_boringssl::BoringSsl,
        tpm2_crypto_tests::backends::BORINGSSL
    ),
);
