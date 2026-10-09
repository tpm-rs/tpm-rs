//! # RustCrypto backend for the `tpm2` cryptography interfaces
//!
//! This crate provides [`RustCrypto`], which implements the traits in
//! [`tpm2::crypto`] using the [RustCrypto](https://github.com/RustCrypto)
//! crates.
//!
//! ## Supported Algorithms
//!
//! | Trait | Supported | Unsupported |
//! |-------|-----------|-------------|
//! | [`Hash`](tpm2::crypto::Hash) | SHA-1, SHA-256, SHA-384, SHA-512, SM3-256, SHA3-256, SHA3-384, SHA3-512 | — |
//! | [`Hmac`](tpm2::crypto::Hmac) | HMAC with all of the above hash algorithms | — |
//! | [`Cmac`](tpm2::crypto::Cmac) | AES-128, AES-192, AES-256, SM4-128, Camellia-128, Camellia-192, Camellia-256 | — |
//! | [`Symmetric`](tpm2::crypto::Symmetric) | All of the above ciphers in CTR, OFB, CBC, CFB, and ECB modes | — |
//! | [`Random`](tpm2::crypto::Random) | ChaCha20 DRBG ([`ChaChaRng`]), seeded from the OS (via `getrandom`) or from a seed | — |
//! | [`ConstantTimeEq`](tpm2::crypto::ConstantTimeEq) | Constant-time comparison (via `subtle`) | — |
//! | [`Rsa`](tpm2::crypto::Rsa) | 1024, 2048, 3072, and 4096-bit keys with raw (`TPM_ALG_NULL`), RSAES-PKCS1-v1_5, and OAEP encryption | Key generation with an exponent of 1 or an even exponent |
//! | [`Ecc`](tpm2::crypto::Ecc) | NIST P-256, NIST P-384, NIST P-521, and SM2 P-256 keys and ECDH | NIST P-192, NIST P-224, BN P-256, BN P-638, Brainpool P-256/P-384/P-512 R1, Curve25519, Curve448 |
//! | [`Signing`](tpm2::crypto::Signing) | RSASSA-PKCS1-v1_5, RSASSA-PSS, ECDSA, SM2, and ECSchnorr (on all supported curves) | ECDAA |
//! | [`Mlkem`](tpm2::crypto::Mlkem) | ML-KEM-512, ML-KEM-768, and ML-KEM-1024 | — |
//! | [`Mldsa`](tpm2::crypto::Mldsa) | ML-DSA-44, ML-DSA-65, and ML-DSA-87 (hedged signing) with pure, pre-hash (HashML-DSA), and external `µ` messages, and streaming `µ` ([`MuContext`]) | — |
//!
//! ## Side Channels
//!
//! The big integer arithmetic of the [`rsa`](https://docs.rs/rsa/0.9) crate is
//! not constant-time ([RUSTSEC-2023-0071]). All RSA private key operations use
//! blinding, which mitigates (but does not eliminate) this timing side channel.
//!
//! [RUSTSEC-2023-0071]: https://rustsec.org/advisories/RUSTSEC-2023-0071
//!
//! ## Example
//!
//! ```
//! # use tpm2::TpmiAlgHash;
//! # use tpm2::crypto::hmac;
//! # use tpm2_rustcrypto::RustCrypto;
//! let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
//! let mac = hmac(&RustCrypto, TpmiAlgHash::Sha256, b"key", b"data", &mut out).unwrap();
//! assert_eq!(mac.digest().len(), 32);
//! ```
#![forbid(unsafe_code)]
#![no_std]
#![warn(missing_docs)]

// The `rsa` crate stores big integers on the heap, returns its results as
// `Vec<u8>`, and takes the PKCS#1 v1.5 `DigestInfo` prefix as a `Box<[u8]>`.
// The `ml-kem` and `ml-dsa` crates box their large keys, and this crate boxes
// ML-DSA signing keys (up to ~100 KiB).
extern crate alloc;

mod ecc;
mod hash;
mod mldsa;
mod mlkem;
mod rng;
mod rsa;
mod signing;
mod symmetric;

pub use ecc::{EccPrivateKey, EccPublicKey};
pub use hash::{HashContext, MacContext};
pub use mldsa::{MldsaPrivateKey, MldsaPublicKey, MuContext};
pub use mlkem::{MlkemPrivateKey, MlkemPublicKey};
pub use rng::ChaChaRng;
pub use rsa::{RsaPrivateKey, RsaPublicKey};

/// Cryptography backend implemented using the RustCrypto crates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RustCrypto;

impl RustCrypto {
    /// Creates a new [`RustCrypto`] backend.
    pub const fn new() -> Self {
        Self
    }
}

impl tpm2::crypto::ConstantTimeEq for RustCrypto {
    fn constant_time_eq<const N: usize>(&self, a: &[u8; N], b: &[u8; N]) -> bool {
        subtle::ConstantTimeEq::ct_eq(&a[..], &b[..]).into()
    }
}

/// XORs `src` into `dst` (up to the length of the shorter one).
fn xor(dst: &mut [u8], src: &[u8]) {
    dst.iter_mut().zip(src).for_each(|(d, s)| *d ^= s);
}

/// Copies `src` to the start of `out` and returns the copied prefix.
fn copy_prefix<'a>(out: &'a mut [u8], src: &[u8]) -> Result<&'a [u8], tpm2::crypto::CryptoError> {
    let prefix = out
        .get_mut(..src.len())
        .ok_or(tpm2::crypto::CryptoError::Internal)?;
    prefix.copy_from_slice(src);
    Ok(prefix)
}
