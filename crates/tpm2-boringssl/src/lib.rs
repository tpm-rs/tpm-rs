//! # TPM2 BoringSSL Cryptography Backend
//!
//! <div class="warning">
//! This code is unstable and there are no guarantees of stability at this time.
//! </div>
//!
//! [`BoringSsl`] implements the [`tpm2::crypto`] traits using Google's
//! [BoringSSL](https://boringssl.googlesource.com/boringssl) (`bssl-crypto`
//! and `bssl-sys`).
//!
//! ## Supported algorithms
//!
//! | Trait | Algorithms | Provider |
//! |-------|------------|----------|
//! | [`Hash`](tpm2::crypto::Hash) | SHA-1, SHA-256, SHA-384, SHA-512 | `bssl-crypto` (`digest`) |
//! | [`Hmac`](tpm2::crypto::Hmac) | HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512; HMAC-SHA-1 | `bssl-crypto` (`hmac`); `bssl-sys` (`HMAC_CTX`) |
//! | [`Cmac`](tpm2::crypto::Cmac) | AES-128, AES-192, AES-256 | `bssl-sys` (`CMAC_CTX`) |
//! | [`Symmetric`](tpm2::crypto::Symmetric) | AES-128, AES-192, AES-256 in CTR, OFB, CBC, CFB, and ECB modes | `bssl-sys` (`AES_KEY`) |
//! | [`Random`](tpm2::crypto::Random) | ChaCha20 DRBG ([`ChaChaRng`]) seeded from `bssl_crypto::rand_bytes` or `SHA-256(seed)` | `bssl-crypto`, `rand_chacha` |
//! | [`ConstantTimeEq`] | Constant-time byte comparison | `bssl-crypto` (`constant_time_compare`) |
//! | [`Rsa`](tpm2::crypto::Rsa), [`Signing`](tpm2::crypto::Signing) | RSA-1024, RSA-2048, RSA-3072, RSA-4096: key generation, raw RSA, RSAES-PKCS1-v1_5, RSAES-OAEP, RSASSA-PKCS1-v1_5, RSASSA-PSS | `bssl-sys` (`RSA`, `EVP_PKEY`, `BIGNUM`) |
//! | [`Ecc`](tpm2::crypto::Ecc), [`Signing`](tpm2::crypto::Signing) | NIST P-256, NIST P-384, NIST P-521: key generation, ECDH, ECDSA | `bssl-sys` (`EC_GROUP`, `EC_POINT`, `ECDSA_sign_p1363`) |
//! | [`Mlkem`](tpm2::crypto::Mlkem) | ML-KEM-768, ML-KEM-1024 | `bssl-sys` (`MLKEM768_*`, `MLKEM1024_*`) |
//! | [`Mldsa`](tpm2::crypto::Mldsa) | ML-DSA-44, ML-DSA-65, ML-DSA-87: pure ML-DSA, external `µ`, and streaming `µ` ([`MuContext`]) | `bssl-sys` (`MLDSA44_*`, `MLDSA65_*`, `MLDSA87_*`) |
//!
//! ## Unsupported algorithms
//!
//! The following return [`CryptoError::Unsupported`]:
//! - [`Hash`](tpm2::crypto::Hash) and [`Hmac`](tpm2::crypto::Hmac): SM3-256, SHA3-256, SHA3-384, and SHA3-512.
//! - [`Cmac`](tpm2::crypto::Cmac) and [`Symmetric`](tpm2::crypto::Symmetric): SM4-128, Camellia-128, Camellia-192, and Camellia-256.
//! - [`Ecc`](tpm2::crypto::Ecc) and [`Signing`](tpm2::crypto::Signing): curves other than NIST P-256, P-384, and P-521; ECDAA, SM2, and EC-Schnorr signatures.
//! - [`Mlkem`](tpm2::crypto::Mlkem): ML-KEM-512.
//! - [`Mldsa`](tpm2::crypto::Mldsa): [`MldsaMessage::PreHash`](tpm2::crypto::MldsaMessage::PreHash) (HashML-DSA).
//!
//! ## Randomness
//!
//! RSA and ECC key generation draw from the `rng` argument, so keys generated
//! from a [seeded](tpm2::crypto::Random::rng_seeded) RNG are reproducible.
//! The RSA prime search differs from other backends, so the same seed gives a
//! different RSA key with each backend.
//!
//! All other randomized operations ignore their `rng` argument and use
//! BoringSSL's internal CSPRNG, as its public API does not accept
//! caller-provided randomness for them: RSAES-PKCS1-v1_5 and RSAES-OAEP
//! padding, RSASSA-PSS salts, ECDSA nonces, ML-KEM encapsulation, and hedged
//! ML-DSA signing.

#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

mod bssl;
mod cmac;
mod ecc;
mod hash;
mod mldsa;
mod mlkem;
mod rng;
mod rsa;
mod signing;
mod symmetric;

pub use self::{
    cmac::{CmacAes128, CmacAes192, CmacAes256},
    ecc::{EccPrivateKey, EccPublicKey},
    hash::{HmacSha1, HmacSha256, HmacSha384, HmacSha512, Sha1, Sha256, Sha384, Sha512},
    mldsa::{MldsaPrivateKey, MldsaPublicKey, MuContext},
    mlkem::{MlkemPrivateKey, MlkemPublicKey},
    rng::ChaChaRng,
    rsa::{RsaPrivateKey, RsaPublicKey},
};

use tpm2::crypto::{ConstantTimeEq, CryptoError};

/// The BoringSSL cryptography backend.
///
/// Implements all of the [`tpm2::crypto`] traits. See the
/// [crate documentation](crate) for the supported algorithms.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct BoringSsl;

impl BoringSsl {
    /// Creates a new [`BoringSsl`] backend instance.
    pub const fn new() -> Self {
        Self
    }
}

impl ConstantTimeEq for BoringSsl {
    fn constant_time_eq<const N: usize>(&self, a: &[u8; N], b: &[u8; N]) -> bool {
        bssl_crypto::constant_time_compare(a, b)
    }
}

/// Copies the big-endian `value` into `out`, left-padded with zeros.
///
/// Returns `None` if `value` is longer than `out`.
fn pad_into(value: &[u8], out: &mut [u8]) -> Option<()> {
    let pad = out.len().checked_sub(value.len())?;
    let (zeros, rest) = out.split_at_mut(pad);
    zeros.fill(0);
    rest.copy_from_slice(value);
    Some(())
}

/// Copies `value` into the start of `out` and returns the copied bytes.
fn write<'a>(value: &[u8], out: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
    let out = out.get_mut(..value.len()).ok_or(CryptoError::Internal)?;
    out.copy_from_slice(value);
    Ok(out)
}
