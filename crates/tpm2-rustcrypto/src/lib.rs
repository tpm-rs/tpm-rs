//! # RustCrypto backend for the `tpm2` cryptography interfaces
//!
//! This crate provides [`RustCrypto`], which implements the symmetric and RNG
//! traits in [`tpm2::crypto`] using the [RustCrypto](https://github.com/RustCrypto)
//! crates.
//!
//! ## Supported Algorithms
//!
//! | Trait | Supported | Unsupported |
//! |-------|-----------|-------------|
//! | [`Hash`] | SHA-1, SHA-256, SHA-384, SHA-512 | SM3-256, SHA3-256, SHA3-384, SHA3-512 |
//! | [`Hmac`] | HMAC with SHA-1, SHA-256, SHA-384, SHA-512 | SM3-256, SHA3-256, SHA3-384, SHA3-512 |
//! | [`Symmetric`] | AES-128, AES-192, AES-256 in CTR, OFB, CBC, CFB, and ECB modes | SM4-128, Camellia-128, Camellia-192, Camellia-256 |
//! | [`Random`] | ChaCha20 DRBG ([`ChaChaRng`]), seeded from the OS (via `getrandom`) or from a seed | — |
//! | [`ConstantTimeEq`] | Constant-time comparison (via `ctutils`) | — |
//!
//! ## Example
//!
//! ```
//! # use tpm2::TpmiAlgHash;
//! # use tpm2::crypto::hmac;
//! # use tpm2_rustcrypto::RustCrypto;
//! let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
//! let mac = hmac::<RustCrypto>(TpmiAlgHash::Sha256, b"key", b"data", &mut out).unwrap();
//! assert_eq!(mac.digest().len(), 32);
//! ```
#![forbid(unsafe_code)]
#![no_std]
#![warn(missing_docs)]
use tpm2::crypto::{ConstantTimeEq, Hash, Hmac, Random, Symmetric};

mod hash;
mod rng;
mod symmetric;

pub use {
    hash::{HashWrapper, HmacWrapper},
    rng::ChaChaRng,
    symmetric::AesKey,
};

/// Cryptography backend implemented using the RustCrypto crates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RustCrypto;

impl RustCrypto {
    /// Creates a new [`RustCrypto`] backend.
    pub const fn new() -> Self {
        Self
    }
}

impl ConstantTimeEq for RustCrypto {
    fn eq(a: &[u8], b: &[u8]) -> bool {
        ctutils::CtEq::ct_eq(a, b).into()
    }
}

impl Hash for RustCrypto {
    type Sha1Context = HashWrapper<sha1::Sha1>;
    type Sha256Context = HashWrapper<sha2::Sha256>;
    type Sha384Context = HashWrapper<sha2::Sha384>;
    type Sha512Context = HashWrapper<sha2::Sha512>;
    type Sm3_256Context = !;
    type Sha3_256Context = !;
    type Sha3_384Context = !;
    type Sha3_512Context = !;
}

impl Hmac for RustCrypto {
    type Sha1Context = HmacWrapper<sha1::Sha1>;
    type Sha256Context = HmacWrapper<sha2::Sha256>;
    type Sha384Context = HmacWrapper<sha2::Sha384>;
    type Sha512Context = HmacWrapper<sha2::Sha512>;
    type Sm3_256Context = !;
    type Sha3_256Context = !;
    type Sha3_384Context = !;
    type Sha3_512Context = !;
}

impl Symmetric for RustCrypto {
    type Aes128Key = AesKey<aes::Aes128>;
    type Aes192Key = AesKey<aes::Aes192>;
    type Aes256Key = AesKey<aes::Aes256>;
    type Sm4_128Key = !;
    type Camellia128Key = !;
    type Camellia192Key = !;
    type Camellia256Key = !;
}

impl Random for RustCrypto {
    type RngState = ChaChaRng;
}
