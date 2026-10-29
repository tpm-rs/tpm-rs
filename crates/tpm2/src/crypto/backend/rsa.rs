//! [`Rsa`] and [`RsaKey`].

use super::AsymmetricKey;
use crate::{
    TpmtHa,
    crypto::{CryptoError, Rng, RsaEncryptScheme},
};

/// RSA signature schemes (`RSASSA-PKCS1-v1_5` and `RSASSA-PSS`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RsaSigScheme {
    Rsassa,
    Rsapss,
}

/// RSA asymmetric cryptography, with one associated type per key size.
///
/// Each key size `K` has modulus length `MOD_SIZE = K / 8` bytes and prime
/// factor length `PRIME_SIZE = MOD_SIZE / 2` bytes.
///
/// See the [module documentation](super) for how to implement this trait.
pub trait Rsa {
    type Rsa1024: RsaKey<128, 64>;
    type Rsa2048: RsaKey<256, 128>;
    type Rsa3072: RsaKey<384, 192>;
    type Rsa4096: RsaKey<512, 256>;
}

/// RSA key operations for a single modulus size (`MOD_SIZE` bytes) and prime
/// factor size (`PRIME_SIZE = MOD_SIZE / 2` bytes).
///
/// Backends implement the padding and signature schemes (`TPM_ALG_NULL`,
/// `RSAES-PKCS1-v1_5`, `RSAES-OAEP`, `RSASSA-PKCS1-v1_5`, and `RSASSA-PSS`)
/// directly, including any side-channel protections.
///
/// [`AsymmetricKey`] parameters and encodings:
/// - Params: the public exponent `e`, already normalized (`>= 3` and odd; the
///   dispatch code maps `0` to `65537` and rejects invalid exponents).
///   Backends return `Err(`[`CryptoError::Unsupported`]`)` for exponents they
///   don't support.
/// - Public: the big-endian modulus `n`. Per TPM 2.0 Part 1, a valid modulus
///   has its most significant bit set (`n[0] & 0x80 != 0`) and is odd
///   (`n[MOD_SIZE - 1] & 1 == 1`).
/// - Private: the big-endian first secret prime factor `p`, which must form a
///   valid private key with `public`.
pub trait RsaKey<const MOD_SIZE: usize, const PRIME_SIZE: usize>:
    AsymmetricKey<MOD_SIZE, PRIME_SIZE, u32>
{
    /// Returns the public exponent `e` (`>= 3` and odd).
    fn exponent(public: &Self::Public) -> u32;

    /// Pads and encrypts `plaintext` under `public` using `scheme`, writing the
    /// `MOD_SIZE`-byte ciphertext into `out`.
    ///
    /// For [`RsaEncryptScheme::Raw`] (`TPM_ALG_NULL`), `plaintext` is a
    /// big-endian integer which may be shorter than `MOD_SIZE` or have extra
    /// leading zero bytes (TPM 2.0 Part 3 `CryptRsaEncrypt`), and is
    /// exponentiated directly. For [`RsaEncryptScheme::Oaep`], the OAEP label
    /// `L` is [`scheme.label_bytes()`](RsaEncryptScheme::label_bytes), which
    /// includes the label's terminating zero octet (if there is a label).
    ///
    /// Returns `Ok(None)` if `plaintext` is invalid for the key or `scheme`
    /// (e.g. too long for the padding scheme, or `>= n` for
    /// [`RsaEncryptScheme::Raw`]).
    fn encrypt(
        rng: &mut impl Rng,
        public: &Self::Public,
        scheme: RsaEncryptScheme<'_>,
        plaintext: &[u8],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError>;

    /// Decrypts `ciphertext` under `private` using `scheme`, writing the
    /// recovered plaintext into `out[..len]` and returning `Ok(Some(len))`.
    ///
    /// For [`RsaEncryptScheme::Raw`] (`TPM_ALG_NULL`), the full `MOD_SIZE`-byte
    /// result of the private-key exponentiation is returned. For
    /// [`RsaEncryptScheme::Oaep`], the label is handled as in
    /// [`encrypt`](Self::encrypt). `rng` is provided for side-channel blinding.
    ///
    /// Returns `Ok(None)` if `ciphertext >= n` or the padding is invalid.
    fn decrypt(
        rng: &mut impl Rng,
        private: &Self::Private,
        scheme: RsaEncryptScheme<'_>,
        ciphertext: &[u8; MOD_SIZE],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<usize>, CryptoError>;

    /// Signs `digest` under `private` using `scheme`, writing the
    /// `MOD_SIZE`-byte signature into `out`.
    ///
    /// `RSASSA` uses the `DigestInfo` encoding of `digest.hash_alg()`, and
    /// `RSAPSS` uses `digest.hash_alg()` for `MGF1` with the largest salt length
    /// up to the digest size (TPM 2.0 `PssEncode`).
    fn sign(
        rng: &mut impl Rng,
        private: &Self::Private,
        scheme: RsaSigScheme,
        digest: TpmtHa<'_>,
        out: &mut [u8; MOD_SIZE],
    ) -> Result<(), CryptoError>;

    /// Verifies `sig` over `digest` under `public` using `scheme`.
    ///
    /// `RSAPSS` signatures with any salt length are accepted (TPM 2.0
    /// `PssDecode`). Returns `Ok(true)` if valid, or `Ok(false)` if invalid
    /// (including `sig >= n`).
    fn verify(
        public: &Self::Public,
        scheme: RsaSigScheme,
        digest: TpmtHa<'_>,
        sig: &[u8; MOD_SIZE],
    ) -> Result<bool, CryptoError>;
}

impl<const MOD_SIZE: usize, const PRIME_SIZE: usize> RsaKey<MOD_SIZE, PRIME_SIZE> for ! {
    fn exponent(public: &Self::Public) -> u32 {
        match *public {}
    }
    fn encrypt(
        _: &mut impl Rng,
        public: &Self::Public,
        _: RsaEncryptScheme<'_>,
        _: &[u8],
        _: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        match *public {}
    }
    fn decrypt(
        _: &mut impl Rng,
        private: &Self::Private,
        _: RsaEncryptScheme<'_>,
        _: &[u8; MOD_SIZE],
        _: &mut [u8; MOD_SIZE],
    ) -> Result<Option<usize>, CryptoError> {
        match *private {}
    }
    fn sign(
        _: &mut impl Rng,
        private: &Self::Private,
        _: RsaSigScheme,
        _: TpmtHa<'_>,
        _: &mut [u8; MOD_SIZE],
    ) -> Result<(), CryptoError> {
        match *private {}
    }
    fn verify(
        public: &Self::Public,
        _: RsaSigScheme,
        _: TpmtHa<'_>,
        _: &[u8; MOD_SIZE],
    ) -> Result<bool, CryptoError> {
        match *public {}
    }
}
