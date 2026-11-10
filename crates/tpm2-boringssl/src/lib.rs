//! BoringSSL cryptography backend for [`tpm2::crypto`].
//!
//! This crate is `#![no_std]` (and does not require `alloc`). It uses
//! BoringSSL's public C API through BoringSSL's own `bssl-sys` crate, which
//! links a prebuilt BoringSSL. The `bssl-sys` on crates.io is a placeholder, so
//! users replace it with `[patch.crates-io]`; see `README.md`.
//!
//! This is not a FIPS-validated build of BoringSSL.
//!
//! ## Random Number Generation
//!
//! [`BoringSslRng`] is either BoringSSL's system RNG (`RAND_bytes`, from
//! [`Random::from_entropy`](tpm2::crypto::Random::from_entropy)) or a
//! deterministic `CTR_DRBG` (from
//! [`Random::from_seed`](tpm2::crypto::Random::from_seed)). Randomized
//! operations whose output depends on the randomness (ECDSA, RSASSA-PSS,
//! RSAES-OAEP / RSAES-PKCS1-v1_5 encryption, ML-DSA signing, and ML-KEM
//! encapsulation) use BoringSSL's system RNG directly, so they return
//! `Err(`[`CryptoError::Internal`](tpm2::crypto::CryptoError::Internal)`)` if
//! passed a seeded RNG.
//!
//! ## Supported Algorithms
//!
//! | Family | Algorithms |
//! |--------|------------|
//! | `Hash` | `SHA-1`, `SHA-256`, `SHA-384`, `SHA-512` |
//! | `Hmac` | `HMAC` with the above hashes |
//! | `Cmac` | `AES-128/192/256-CMAC` |
//! | `Symmetric` | `AES-128/192/256` (`CTR`, `OFB`, `CBC`, `CFB`, `ECB`) |
//! | `Random` | System RNG and seeded `CTR_DRBG` |
//! | `Rsa` | `RSA-1024/2048/3072/4096` (raw, `RSAES`, `OAEP`, `RSASSA`, `RSAPSS`) |
//! | `Ecc` | `NIST P-224/P-256/P-384/P-521` (`ECDH`, `ECDSA`) |
//! | `Ecc` | `Ed25519` (`EdDSA`, `HashEdDSA`), `X25519` |
//! | `Mldsa` | `ML-DSA-44/65/87` (pure, external `µ`, `HashML-DSA`) |
//! | `Mlkem` | `ML-KEM-768/1024` |
//!
//! Not supported (bound to `!`): `SM3-256`, `SHA3-*`, `SM4`, `Camellia`,
//! `NIST P-192`, `BN-P256/P638`, `SM2`, `Brainpool`, `Ed448`, `X448`, and
//! `ML-KEM-512`.
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

// docs.rs can't build BoringSSL (or patch `bssl-sys`), so it documents the
// crate against checked-in bindings for just the items rustdoc needs instead
// (see `boringssl.py docs-bindings`).
#[cfg(not(docsrs))]
extern crate bssl_sys;
#[cfg(docsrs)]
#[path = "docsrs_bindings.rs"]
#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code,
    unsafe_op_in_unsafe_fn,
    clippy::all,
    clippy::pedantic
)]
mod bssl_sys;

mod cmac;
mod curve25519;
mod ecc;
mod hash;
mod hmac;
mod mldsa;
mod mlkem;
mod rng;
mod rsa;
mod symmetric;
mod util;

pub use {
    cmac::BoringSslCmacState,
    curve25519::{
        BoringSslEd25519PrivateKey, BoringSslEd25519PublicKey, BoringSslX25519PrivateKey,
        BoringSslX25519PublicKey,
    },
    ecc::{BoringSslEccPrivateKey, BoringSslEccPublicKey},
    hash::BoringSslHashState,
    hmac::BoringSslHmacState,
    mldsa::{
        BoringSslMldsa44PrivateKey, BoringSslMldsa44PublicKey, BoringSslMldsa65PrivateKey,
        BoringSslMldsa65PublicKey, BoringSslMldsa87PrivateKey, BoringSslMldsa87PublicKey,
    },
    mlkem::{
        BoringSslMlkem768PrivateKey, BoringSslMlkem768PublicKey, BoringSslMlkem1024PrivateKey,
        BoringSslMlkem1024PublicKey,
    },
    rng::BoringSslRng,
    rsa::{BoringSslRsaPrivateKey, BoringSslRsaPublicKey},
    symmetric::BoringSslAesKey,
};

use tpm2::crypto::Crypto;

/// BoringSSL cryptography backend implementing [`tpm2::crypto::Crypto`].
#[derive(Debug, Default, Clone, Copy)]
pub struct BoringSsl;

impl Crypto for BoringSsl {
    fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        unsafe { bssl_sys::CRYPTO_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) == 0 }
    }
}
