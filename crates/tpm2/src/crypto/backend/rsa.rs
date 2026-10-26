//! [`Rsa`] and [`RsaKey`].

use super::PrivateKey;
use crate::{
    TpmiAlgHash, TpmtHa,
    crypto::{CryptoError, Random, Rng},
};

/// RSA asymmetric cryptography, with one associated type per key size.
///
/// Each key size `K` has modulus length `MOD_SIZE = K / 8` bytes and prime
/// factor length `PRIME_SIZE = MOD_SIZE / 2` bytes.
///
/// See the [module documentation](super) for how to implement this trait.
pub trait Rsa: Random {
    type Rsa1024: RsaKey<128, 64, Self::Rng>;
    type Rsa2048: RsaKey<256, 128, Self::Rng>;
    type Rsa3072: RsaKey<384, 192, Self::Rng>;
    type Rsa4096: RsaKey<512, 256, Self::Rng>;
}

/// RSA private key operations for a single modulus size (`MOD_SIZE` bytes) and
/// prime factor size (`PRIME_SIZE = MOD_SIZE / 2` bytes), using RNG `R`.
///
/// Private key operations take `&self`, and public key operations take a
/// [`PublicKey`](PrivateKey::PublicKey).
///
/// Backends implement each padding and signature scheme (`TPM_ALG_NULL`,
/// `RSAES-OAEP`, `RSAES-PKCS1-v1_5`, `RSASSA-PKCS1-v1_5`, and `RSASSA-PSS`)
/// directly, including any side-channel protections. A backend which doesn't
/// support a scheme (e.g. `RSAES-PKCS1-v1_5`) returns
/// `Err(`[`CryptoError::Unsupported`]`)` from its methods.
///
/// [`PrivateKey`] parameters and encodings:
/// - Params: the public exponent `e`, already normalized (`>= 3` and odd; the
///   dispatch code maps `0` to `65537` and rejects invalid exponents).
///   Backends return `Err(`[`CryptoError::Unsupported`]`)` for exponents they
///   don't support.
/// - Public: the big-endian modulus `n`. Per TPM 2.0 Part 1, a valid modulus
///   has its most significant bit set (`n[0] & 0x80 != 0`) and is odd
///   (`n[MOD_SIZE - 1] & 1 == 1`).
/// - Private: the big-endian first secret prime factor `p`, which must form a
///   valid private key with `public`.
pub trait RsaKey<const MOD_SIZE: usize, const PRIME_SIZE: usize, R: Rng>:
    PrivateKey<MOD_SIZE, PRIME_SIZE, R, u32>
{
    /// Returns the public exponent `e` (`>= 3` and odd) of `public`.
    fn exponent(public: &Self::PublicKey) -> u32;

    /// Encrypts `m` under `public` without padding (`TPM_ALG_NULL`, RFC 8017
    /// `RSAEP`), writing the `MOD_SIZE`-byte ciphertext `m^e mod n` into `out`.
    ///
    /// `m` is a big-endian integer, already left-padded to `MOD_SIZE` bytes by
    /// the dispatch code. Returns `Ok(None)` if `m >= n`.
    fn raw_encrypt(
        public: &Self::PublicKey,
        m: &[u8; MOD_SIZE],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError>;

    /// Decrypts `c` under this key without padding (`TPM_ALG_NULL`, RFC 8017
    /// `RSADP`), writing the `MOD_SIZE`-byte result `c^d mod n` into `out`.
    ///
    /// `rng` is provided for side-channel blinding. Returns `Ok(None)` if
    /// `c >= n`.
    fn raw_decrypt(
        &self,
        rng: &mut R,
        c: &[u8; MOD_SIZE],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError>;

    /// Encrypts `m` under `public` using `RSAES-OAEP` (`TPM_ALG_OAEP`, RFC 8017
    /// 7.1) with `hash` for both the label hash and `MGF1`, writing the
    /// `MOD_SIZE`-byte ciphertext into `out`.
    ///
    /// `label` is the OAEP label `L`, which includes the TPM label's
    /// terminating zero octet (empty if there is no label; see
    /// [`RsaEncryptScheme::Oaep`](crate::crypto::RsaEncryptScheme::Oaep)).
    ///
    /// Returns `Ok(None)` if `m` is too long
    /// (`m.len() > MOD_SIZE - 2 * hLen - 2`), or
    /// `Err(`[`CryptoError::Unsupported`]`)` if `hash` is unsupported.
    fn oaep_encrypt(
        public: &Self::PublicKey,
        rng: &mut R,
        hash: TpmiAlgHash,
        label: &[u8],
        m: &[u8],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError>;

    /// Decrypts `c` under this key using `RSAES-OAEP` (`TPM_ALG_OAEP`), with
    /// `hash` and `label` as in [`oaep_encrypt`](Self::oaep_encrypt), writing
    /// the recovered message into `out[..len]` and returning `Ok(Some(len))`.
    ///
    /// `rng` is provided for side-channel blinding. Returns `Ok(None)` if
    /// `c >= n` or the padding is invalid.
    fn oaep_decrypt(
        &self,
        rng: &mut R,
        hash: TpmiAlgHash,
        label: &[u8],
        c: &[u8; MOD_SIZE],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<usize>, CryptoError>;

    /// Encrypts `m` under `public` using `RSAES-PKCS1-v1_5` (`TPM_ALG_RSAES`,
    /// RFC 8017 7.2), writing the `MOD_SIZE`-byte ciphertext into `out`.
    ///
    /// Returns `Ok(None)` if `m` is too long (`m.len() > MOD_SIZE - 11`).
    fn rsaes_encrypt(
        public: &Self::PublicKey,
        rng: &mut R,
        m: &[u8],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError>;

    /// Decrypts `c` under this key using `RSAES-PKCS1-v1_5` (`TPM_ALG_RSAES`),
    /// writing the recovered message into `out[..len]` and returning
    /// `Ok(Some(len))`.
    ///
    /// `rng` is provided for side-channel blinding. Returns `Ok(None)` if
    /// `c >= n` or the padding is invalid.
    ///
    /// A backend that uses implicit rejection instead (returning a synthetic
    /// message for invalid padding) doesn't conform to TPM 2.0 Part 3
    /// (`TPM2_RSA_Decrypt`), which requires `TPM_RC_VALUE` in that case.
    fn rsaes_decrypt(
        &self,
        rng: &mut R,
        c: &[u8; MOD_SIZE],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<usize>, CryptoError>;

    /// Signs `digest` under this key using `RSASSA-PKCS1-v1_5`
    /// (`TPM_ALG_RSASSA`, RFC 8017 8.2) with the `DigestInfo` encoding of
    /// `digest.hash_alg()`, writing the `MOD_SIZE`-byte signature into `out`.
    fn rsassa_sign(
        &self,
        rng: &mut R,
        digest: TpmtHa<'_>,
        out: &mut [u8; MOD_SIZE],
    ) -> Result<(), CryptoError>;

    /// Verifies `RSASSA-PKCS1-v1_5` signature `sig` over `digest` under
    /// `public`.
    ///
    /// Returns `Ok(true)` if valid, or `Ok(false)` if invalid (including
    /// `sig >= n`).
    fn rsassa_verify(
        public: &Self::PublicKey,
        digest: TpmtHa<'_>,
        sig: &[u8; MOD_SIZE],
    ) -> Result<bool, CryptoError>;

    /// Signs `digest` under this key using `RSASSA-PSS` (`TPM_ALG_RSAPSS`, RFC
    /// 8017 8.1) with `digest.hash_alg()` for `MGF1` and the largest salt
    /// length up to the digest size (TPM 2.0 `PssEncode`), writing the
    /// `MOD_SIZE`-byte signature into `out`.
    fn rsapss_sign(
        &self,
        rng: &mut R,
        digest: TpmtHa<'_>,
        out: &mut [u8; MOD_SIZE],
    ) -> Result<(), CryptoError>;

    /// Verifies `RSASSA-PSS` signature `sig` over `digest` under `public`.
    ///
    /// Signatures with any salt length are accepted (TPM 2.0 `PssDecode`).
    /// Returns `Ok(true)` if valid, or `Ok(false)` if invalid (including
    /// `sig >= n`).
    fn rsapss_verify(
        public: &Self::PublicKey,
        digest: TpmtHa<'_>,
        sig: &[u8; MOD_SIZE],
    ) -> Result<bool, CryptoError>;
}

impl<const MOD_SIZE: usize, const PRIME_SIZE: usize, R: Rng> RsaKey<MOD_SIZE, PRIME_SIZE, R> for ! {
    fn exponent(public: &Self::PublicKey) -> u32 {
        match *public {}
    }
    fn raw_encrypt(
        public: &Self::PublicKey,
        _: &[u8; MOD_SIZE],
        _: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        match *public {}
    }
    fn raw_decrypt(
        &self,
        _: &mut R,
        _: &[u8; MOD_SIZE],
        _: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        match *self {}
    }
    fn oaep_encrypt(
        public: &Self::PublicKey,
        _: &mut R,
        _: TpmiAlgHash,
        _: &[u8],
        _: &[u8],
        _: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        match *public {}
    }
    fn oaep_decrypt(
        &self,
        _: &mut R,
        _: TpmiAlgHash,
        _: &[u8],
        _: &[u8; MOD_SIZE],
        _: &mut [u8; MOD_SIZE],
    ) -> Result<Option<usize>, CryptoError> {
        match *self {}
    }
    fn rsaes_encrypt(
        public: &Self::PublicKey,
        _: &mut R,
        _: &[u8],
        _: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        match *public {}
    }
    fn rsaes_decrypt(
        &self,
        _: &mut R,
        _: &[u8; MOD_SIZE],
        _: &mut [u8; MOD_SIZE],
    ) -> Result<Option<usize>, CryptoError> {
        match *self {}
    }
    fn rsassa_sign(
        &self,
        _: &mut R,
        _: TpmtHa<'_>,
        _: &mut [u8; MOD_SIZE],
    ) -> Result<(), CryptoError> {
        match *self {}
    }
    fn rsassa_verify(
        public: &Self::PublicKey,
        _: TpmtHa<'_>,
        _: &[u8; MOD_SIZE],
    ) -> Result<bool, CryptoError> {
        match *public {}
    }
    fn rsapss_sign(
        &self,
        _: &mut R,
        _: TpmtHa<'_>,
        _: &mut [u8; MOD_SIZE],
    ) -> Result<(), CryptoError> {
        match *self {}
    }
    fn rsapss_verify(
        public: &Self::PublicKey,
        _: TpmtHa<'_>,
        _: &[u8; MOD_SIZE],
    ) -> Result<bool, CryptoError> {
        match *public {}
    }
}
