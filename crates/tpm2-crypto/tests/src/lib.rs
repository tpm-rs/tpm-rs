#![forbid(unsafe_code)]
#![no_std]

#[cfg(not(any(feature = "rust", feature = "crux", feature = "bssl")))]
compile_error!(
    "At least one cryptographic backend feature must be enabled: 'rust', 'crux', or 'bssl'."
);

#[cfg(all(feature = "rust", feature = "crux"))]
compile_error!("Features 'rust' and 'crux' are mutually exclusive.");

#[cfg(all(feature = "rust", feature = "bssl"))]
compile_error!("Features 'rust' and 'bssl' are mutually exclusive.");

#[cfg(all(feature = "crux", feature = "bssl"))]
compile_error!("Features 'crux' and 'bssl' are mutually exclusive.");

#[cfg(feature = "rust")]
pub use tpm2_crypto_rust::RustCryptoProvider as TestProvider;

#[cfg(feature = "crux")]
pub use tpm2_crypto_crux::CruxCryptoProvider as TestProvider;

/// BoringSSL with its own RNG (a type alias, so that the default RNG parameter also applies
/// in expression paths such as `TestProvider::from_entropy()`).
#[cfg(feature = "bssl")]
pub type TestProvider = tpm2_crypto_bssl::BsslCryptoProvider;
