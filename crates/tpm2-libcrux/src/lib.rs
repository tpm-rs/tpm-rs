//! # TPM2 libcrux Cryptography Backend
//!
//! <div class="warning">
//! This code is unstable and there are no guarantees of stability at this time.
//! </div>
//!
//! [`Libcrux`] implements the [`tpm2::crypto`] traits using the formally
//! verified [libcrux](https://github.com/cryspen/libcrux) primitives where
//! libcrux provides them, and [RustCrypto](https://github.com/RustCrypto)
//! crates for the rest.
//!
//! ## Supported algorithms
//!
//! | Trait | Algorithms | Provider |
//! |-------|------------|----------|
//! | [`Hash`] | SHA-256, SHA-384, SHA-512 | libcrux (`libcrux-sha2`) |
//! | [`Hash`] | SHA-1 | RustCrypto (`sha1`) |
//! | [`Hmac`] | HMAC with SHA-1, SHA-256, SHA-384, SHA-512 | RustCrypto (`hmac`, `sha1`, `sha2`) |
//! | [`Cmac`] | AES-128, AES-192, AES-256 | RustCrypto (`cmac`, `aes`) |
//! | [`Symmetric`] | AES-128, AES-192, AES-256 in CTR, OFB, CBC, CFB and ECB modes | RustCrypto (`aes`); modes implemented in this crate |
//! | [`Random`] | ChaCha20 DRBG seeded from OS entropy or from `SHA-256(seed)` | RustCrypto (`rand_chacha`, `getrandom`); libcrux (`libcrux-sha2`) for SHA-256 |
//! | [`ConstantTimeEq`] | Constant-time byte comparison | RustCrypto (`subtle`) |
//! | [`Rsa`], [`Signing`] | RSA-1024 to RSA-4096: key generation, RSAES-PKCS1-v1_5, RSAES-OAEP and raw RSA, RSASSA-PKCS1-v1_5 and RSASSA-PSS signatures | RustCrypto (`rsa`) |
//! | [`Ecc`], [`Signing`] | NIST P-256: key generation, ECDH, ECDSA | libcrux (`libcrux-p256`) |
//! | [`Ecc`], [`Signing`] | NIST P-384, NIST P-521: key generation, ECDH, ECDSA | RustCrypto (`p384`, `p521`) |
//! | [`Mlkem`] | ML-KEM-512, ML-KEM-768, ML-KEM-1024 | libcrux (`libcrux-ml-kem`) |
//! | [`Mldsa`] | ML-DSA-44, ML-DSA-65, ML-DSA-87: pure ML-DSA and HashML-DSA | libcrux (`libcrux-ml-dsa`) |
//!
//! libcrux has no SHA-1, streaming HMAC, raw AES block cipher or
//! digest-based RSA, so those use RustCrypto crates.
//!
//! ## Unsupported algorithms
//!
//! The following return [`CryptoError::Unsupported`]:
//! - [`Hash`] and [`Hmac`]: SM3-256, SHA3-256, SHA3-384 and SHA3-512
//!   (libcrux has no streaming SHA-3).
//! - [`Symmetric`] and [`Cmac`]: SM4-128, Camellia-128, Camellia-192 and
//!   Camellia-256.
//! - [`Rsa`] and [`Signing`]: hash algorithms other than SHA-1, SHA-256,
//!   SHA-384 and SHA-512; OAEP labels that aren't valid UTF-8 (the `rsa`
//!   crate stores labels as strings); [`Rsa::generate_key`] with an even
//!   public exponent or an exponent of `1`.
//! - [`Ecc`] and [`Signing`]: all curves other than NIST P-256, P-384 and
//!   P-521 (including BN-P256); ECDAA, SM2 and EC-Schnorr signatures.
//! - [`Mldsa`]: [`MldsaMessage::ExternalMu`] and [`Mldsa::mu_start`].
//!
//! ## Behavior notes
//!
//! - [`Rsa::load_public`] returns `Ok(None)` for keys the `rsa` crate
//!   rejects, including keys with an even public exponent or an exponent of
//!   `1`.
//! - RSASSA-PSS signatures use a salt as long as the digest, or as long as
//!   the key allows if that is shorter (like the TPM reference
//!   implementation). Verification accepts any salt length.
//! - ECDSA signatures are hedged: P-256 nonces come from a DRBG keyed with
//!   the caller's RNG output, the private key and the digest, and P-384 and
//!   P-521 use RFC 6979 with added randomness from the caller's RNG.
//! - ECDSA verification ignores leading zeros in `r` and `s`, like the TPM
//!   reference implementation.
//!
//! ## Security notes
//!
//! The `rsa` crate is not constant time ([RUSTSEC-2023-0071]). All RSA private
//! key operations are blinded, which mitigates (but does not eliminate) this
//! timing side channel: signing uses the caller's RNG, and [`Rsa::decrypt`],
//! which takes no RNG, uses a fresh [`Random::rng`].
//!
//! [RUSTSEC-2023-0071]: https://rustsec.org/advisories/RUSTSEC-2023-0071
//!
//! ## `no_std` support
//!
//! This crate is `no_std` but requires [`alloc`]: the libcrux SHA-2 streaming
//! state and the `rsa` crate's big integers are heap allocated.
//! [`Random::rng`] (and so [`Rsa::decrypt`]) gets its entropy from
//! `getrandom`, which needs an operating system or a custom `getrandom`
//! backend.
//!
//! [`Hash`]: tpm2::crypto::Hash
//! [`Hmac`]: tpm2::crypto::Hmac
//! [`Cmac`]: tpm2::crypto::Cmac
//! [`Symmetric`]: tpm2::crypto::Symmetric
//! [`Random`]: tpm2::crypto::Random
//! [`Random::rng`]: tpm2::crypto::Random::rng
//! [`Rsa`]: tpm2::crypto::Rsa
//! [`Rsa::decrypt`]: tpm2::crypto::Rsa::decrypt
//! [`Rsa::generate_key`]: tpm2::crypto::Rsa::generate_key
//! [`Rsa::load_public`]: tpm2::crypto::Rsa::load_public
//! [`Ecc`]: tpm2::crypto::Ecc
//! [`Signing`]: tpm2::crypto::Signing
//! [`Mlkem`]: tpm2::crypto::Mlkem
//! [`Mldsa`]: tpm2::crypto::Mldsa
//! [`Mldsa::mu_start`]: tpm2::crypto::Mldsa::mu_start
//! [`MldsaMessage::ExternalMu`]: tpm2::crypto::MldsaMessage::ExternalMu
//! [`CryptoError::Unsupported`]: tpm2::crypto::CryptoError::Unsupported
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

mod cmac;
mod ecc;
mod hash;
mod hmac;
mod mldsa;
mod mlkem;
mod rng;
mod rsa;
mod signing;
mod symmetric;

pub use self::{
    cmac::{CmacAes128, CmacAes192, CmacAes256},
    ecc::{EccPrivate, EccPublic},
    hash::{Sha1, Sha256, Sha384, Sha512},
    hmac::{HmacSha1, HmacSha256, HmacSha384, HmacSha512},
    mldsa::{MldsaPrivate, MldsaPublic},
    mlkem::{MlkemPrivate, MlkemPublic},
    rng::ChaChaRng,
    rsa::{RsaPrivate, RsaPublic},
};

use tpm2::crypto::{ConstantTimeEq, CryptoError};

/// The libcrux cryptography backend.
///
/// Implements all of the [`tpm2::crypto`] traits. See the
/// [crate documentation](crate) for the supported algorithms.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Libcrux;

impl Libcrux {
    /// Creates the libcrux backend.
    pub const fn new() -> Self {
        Self
    }
}

impl ConstantTimeEq for Libcrux {
    fn constant_time_eq<const N: usize>(&self, a: &[u8; N], b: &[u8; N]) -> bool {
        // libcrux doesn't expose a constant-time comparison, so use `subtle`.
        subtle::ConstantTimeEq::ct_eq(&a[..], &b[..]).into()
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

/// Returns the big-endian `value` left-padded with zeros to `N` bytes.
///
/// Returns `None` if `value` is longer than `N` bytes.
fn left_pad<const N: usize>(value: &[u8]) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    pad_into(value, &mut out)?;
    Some(out)
}

/// Writes the big-endian `value` into the first `len` bytes of `out`,
/// left-padded with zeros, and returns those bytes.
fn write_be<'a>(value: &[u8], len: usize, out: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
    let out = out.get_mut(..len).ok_or(CryptoError::Internal)?;
    pad_into(value, out).ok_or(CryptoError::Internal)?;
    Ok(out)
}

/// Copies `value` into the start of `out` and returns the copied bytes.
fn write<'a>(value: &[u8], out: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
    write_be(value, value.len(), out)
}
