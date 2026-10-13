//! TPM 2.0 Asymmetric Cryptographic Abstractions
//!
//! This module defines the cryptographic traits required for asymmetric operations in TPM 2.0,
//! covering RSA and ECC signing/verification, RSA encryption/decryption, and key pair generation.
//!
//! ### Provider Abstraction
//!
//! Supported algorithms implement the specific trait methods (such as [`AsymmetricSign::rsassa_sign`],
//! [`Asymmetric::ecdsa_verify`], [`Asymmetric::oaep_encrypt`], [`Asymmetric::rsa_generate_key`], etc.),
//! while unimplemented algorithms keep the default body returning
//! `Err(`[`CryptoError::Unsupported`]`)`.
//!
//! ### Error Handling
//!
//! Following the conventions of [`crypto`](super), [`CryptoError`] is only returned for
//! unsupported algorithms, schemes, or key sizes ([`CryptoError::Unsupported`]) and for internal
//! failures ([`CryptoError::Internal`], which puts the TPM into failure mode). Semantic failures
//! caused by the inputs are reported in the `Ok` value:
//!   - Verification returns `Ok(false)` if the signature is invalid, or if the public key cannot
//!     be used to verify it.
//!   - Signing, encryption, decryption, and key import return `Ok(Some(len))` with the number of
//!     bytes written on success, and `Ok(None)` for invalid inputs: an unusable key, a message too
//!     large for the key, a bad ciphertext or padding, inconsistent key components, etc.
//!   - Key generation has no semantic failures; it returns `Ok((public_len, private_len))`.
//!
//! An output buffer too small for the result is a programming error of the caller, reported as
//! [`CryptoError::Internal`].
//!
//! ### Role of `sign_alg` (`scheme`) and `hash_alg`
//!
//! Asymmetric signing/verification (`sign_inner`, `verify_inner`) and encryption/decryption (`encrypt`, `decrypt`)
//! take both a scheme/algorithm identifier (`sign_alg` or `scheme`) and a hash algorithm identifier (`hash_alg`):
//!
//! 1. **`sign_alg` / `scheme` (`Alg`)**: Selects the asymmetric signature padding or encryption scheme:
//!    - **Signing/Verification**:
//!      - [`Alg::RSASSA`]: RSA PKCS#1 v1.5 deterministic signature padding ([`AsymmetricSign::rsassa_sign`], [`Asymmetric::rsassa_verify`]).
//!      - [`Alg::RSAPSS`]: RSA-PSS probabilistic signature padding using an MGF and random salt ([`AsymmetricSign::rsapss_sign`], [`Asymmetric::rsapss_verify`]).
//!      - [`Alg::ECDSA`]: Elliptic curve digital signature over the curve matching the key size ([`AsymmetricSign::ecdsa_sign`], [`Asymmetric::ecdsa_verify`]).
//!      - [`Alg::SM2`], [`Alg::ECSCHNORR`]: Alternative ECC signature schemes ([`AsymmetricSign::sm2_sign`], [`AsymmetricSign::ecschnorr_sign`]).
//!    - **Encryption/Decryption**:
//!      - [`Alg::NULL`]: Raw RSA modular exponentiation without padding ([`Asymmetric::rsa_null_encrypt`], [`Asymmetric::rsa_null_decrypt`]).
//!      - [`Alg::RSAES`]: RSA PKCS#1 v1.5 encryption padding ([`Asymmetric::rsaes_encrypt`], [`Asymmetric::rsaes_decrypt`]).
//!      - [`Alg::OAEP`]: RSA-OAEP padding using an MGF and optional label ([`Asymmetric::oaep_encrypt`], [`Asymmetric::oaep_decrypt`]).
//!
//! 2. **`hash_alg` (`Alg` / `TpmiAlgHash`)**: Even though `sign_inner` and `verify_inner` operate on a pre-computed
//!    `digest` slice, the underlying cryptographic primitives still require the hash algorithm identifier:
//!    - **ASN.1 `DigestInfo` OID Encoding (`Alg::RSASSA`)**: PKCS#1 v1.5 signing wraps the raw digest in an ASN.1
//!      `DigestInfo` structure containing the OID of `hash_alg` followed by the digest bytes.
//!    - **MGF1 & Salt Length Parameterization (`Alg::RSAPSS` & `Alg::OAEP`)**: Specifies the hash function used
//!      internally by the Mask Generation Function (MGF1) and determines the expected digest/salt lengths.
//!    - **Digest Adjustment (`Alg::ECDSA`)**: Pre-hashed digests are truncated or adjusted to the curve's order length per ISO/IEC 14888-3 and TPM 2.0 specifications, allowing cross-hash ECDSA signing and verification.
//!
//! # Example
//!
//! ```
//! # use tpm2::{crypto::{AsymmetricSign, CryptoError}, TpmtHa};
//! # struct MyBackend;
//! impl AsymmetricSign for MyBackend {
//!     fn rsassa_sign(
//!         &self,
//!         _private_key: &[u8],
//!         _digest: TpmtHa<'_>,
//!         signature_out: &mut [u8],
//!     ) -> Result<Option<usize>, CryptoError> {
//!         let Some(signature) = signature_out.get_mut(..32) else {
//!             // The output buffer is too small: a programming error.
//!             return Err(CryptoError::Internal);
//!         };
//!         signature.fill(0xAA);
//!         Ok(Some(32))
//!     }
//!     // All other schemes keep the default `Err(CryptoError::Unsupported)`.
//! }
//! ```

use super::CryptoError;
use crate::{Alg, TpmiAlgHash, TpmtHa, constants::TpmEccCurve};

pub use crate::TpmiRsaKeyBits;

/// Key generation parameters for RSA and ECC keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyParams {
    /// RSA key length in bits (e.g., 1024, 2048, 3072, 4096).
    Rsa(TpmiRsaKeyBits),
    /// ECC curve identifier (e.g., NIST P-256, P-384, P-521, BN P-256).
    Ecc(TpmEccCurve),
}

/// Cryptographic asymmetric signing interfaces for TPM implementations and clients.
///
/// Supported algorithms implement the algorithm-specific methods (such as [`AsymmetricSign::rsassa_sign`],
/// [`AsymmetricSign::rsapss_sign`], [`AsymmetricSign::ecdsa_sign`], etc.).
/// Unimplemented algorithms keep the default body of `Err(`[`CryptoError::Unsupported`]`)`.
///
/// Every signing method writes the signature to the start of `signature_out` and returns:
///   - `Ok(Some(len))` with the signature length on success (for ECC schemes, the signature is
///     `r || s`, each half being the curve's scalar size),
///   - `Ok(None)` if `private_key` is invalid or cannot sign `digest` (e.g. the key is too small
///     for the digest),
///   - `Err(`[`CryptoError::Unsupported`]`)` for an unsupported scheme, hash, or key size, and
///   - `Err(`[`CryptoError::Internal`]`)` for internal failures, including a `signature_out`
///     buffer too small for the signature.
#[allow(unused_variables)]
pub trait AsymmetricSign {
    /// Signs `digest` using RSASSA-PKCS1-v1_5 (`TPM_ALG_RSASSA`) with `private_key`.
    fn rsassa_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Signs `digest` using RSASSA-PSS (`TPM_ALG_RSAPSS`) with `private_key`.
    fn rsapss_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Signs `digest` using ECDSA (`TPM_ALG_ECDSA`) with `private_key`.
    fn ecdsa_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Signs `digest` using SM2 (`TPM_ALG_SM2`) with `private_key`.
    fn sm2_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Signs `digest` using ECSchnorr (`TPM_ALG_ECSCHNORR`) with `private_key`.
    fn ecschnorr_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Signs `digest` using the requested `sign_alg`.
    ///
    /// Dispatches to the algorithm-specific method for each signature scheme
    /// whose crate feature is enabled; any other `sign_alg` returns
    /// `Err(`[`CryptoError::Unsupported`]`)`.
    fn sign_inner(
        &self,
        sign_alg: Alg,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        match sign_alg {
            #[cfg(feature = "rsassa")]
            Alg::RSASSA => self.rsassa_sign(private_key, digest, signature_out),
            #[cfg(feature = "rsapss")]
            Alg::RSAPSS => self.rsapss_sign(private_key, digest, signature_out),
            #[cfg(feature = "ecdsa")]
            Alg::ECDSA => self.ecdsa_sign(private_key, digest, signature_out),
            #[cfg(feature = "sm2")]
            Alg::SM2 => self.sm2_sign(private_key, digest, signature_out),
            #[cfg(feature = "ecschnorr")]
            Alg::ECSCHNORR => self.ecschnorr_sign(private_key, digest, signature_out),
            _ => Err(CryptoError::Unsupported),
        }
    }
}

/// Cryptographic asymmetric verification, encryption/decryption, and key management interfaces for TPM implementations and clients.
///
/// Supported algorithms implement the algorithm-specific methods (such as [`Asymmetric::ecdsa_verify`],
/// [`Asymmetric::oaep_encrypt`], [`Asymmetric::rsa_generate_key`], etc.).
/// Unimplemented algorithms keep the default body of `Err(`[`CryptoError::Unsupported`]`)`.
///
/// Semantic failures are reported in the `Ok` value (see the [module documentation](self)):
///   - verification methods return `Ok(true)` for a valid signature and `Ok(false)` for an invalid
///     signature or an unusable public key,
///   - encryption, decryption, and import methods return `Ok(Some(len))` with the number of bytes
///     written and `Ok(None)` for invalid inputs,
///   - key generation methods return `Ok((public_len, private_len))`.
#[allow(unused_variables)]
pub trait Asymmetric {
    /// Verifies `signature` over `digest` using RSASSA-PKCS1-v1_5 (`TPM_ALG_RSASSA`) with `public_key`.
    fn rsassa_verify(
        &self,
        public_key: &[u8],
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Verifies `signature` over `digest` using RSASSA-PSS (`TPM_ALG_RSAPSS`) with `public_key`.
    fn rsapss_verify(
        &self,
        public_key: &[u8],
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Verifies `signature` over `digest` using ECDSA (`TPM_ALG_ECDSA`) with `public_key`.
    fn ecdsa_verify(
        &self,
        public_key: &[u8],
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Verifies `signature` over `digest` using SM2 (`TPM_ALG_SM2`) with `public_key`.
    fn sm2_verify(
        &self,
        public_key: &[u8],
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Verifies `signature` over `digest` using ECSchnorr (`TPM_ALG_ECSCHNORR`) with `public_key`.
    fn ecschnorr_verify(
        &self,
        public_key: &[u8],
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Encrypts `data` using RSAES-PKCS1-v1_5 (`TPM_ALG_RSAES`) with `public_key`.
    ///
    /// Returns `Ok(None)` if `public_key` is invalid or `data` is too large for it.
    fn rsaes_encrypt(
        &self,
        public_key: &[u8],
        data: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Encrypts `data` using RSAES-OAEP (`TPM_ALG_OAEP`) with `hash_alg`, `public_key`, and `label`.
    ///
    /// Returns `Ok(None)` if `public_key` or `label` is invalid, or `data` is too large for the key.
    fn oaep_encrypt(
        &self,
        hash_alg: TpmiAlgHash,
        public_key: &[u8],
        data: &[u8],
        label: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Encrypts `data` using raw RSA modular exponentiation ($m^e \bmod n$).
    ///
    /// Returns `Ok(None)` if `public_key` is invalid or `data` (as an integer) is not smaller
    /// than the modulus.
    fn rsa_null_encrypt(
        &self,
        public_key: &[u8],
        data: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Decrypts `ciphertext` using RSAES-PKCS1-v1_5 (`TPM_ALG_RSAES`) with `private_key`.
    ///
    /// Returns `Ok(None)` if `private_key` is invalid, or `ciphertext` or its padding is invalid.
    fn rsaes_decrypt(
        &self,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Decrypts `ciphertext` using RSAES-OAEP (`TPM_ALG_OAEP`) with `hash_alg`, `private_key`, and `label`.
    ///
    /// Returns `Ok(None)` if `private_key` or `label` is invalid, or `ciphertext` or its padding
    /// is invalid.
    fn oaep_decrypt(
        &self,
        hash_alg: TpmiAlgHash,
        private_key: &[u8],
        ciphertext: &[u8],
        label: &[u8],
        plaintext: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Decrypts `ciphertext` using raw RSA modular exponentiation ($c^d \bmod n$).
    ///
    /// Returns `Ok(None)` if `private_key` is invalid or `ciphertext` (as an integer) is not
    /// smaller than the modulus.
    fn rsa_null_decrypt(
        &self,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Generates an RSA key pair for `key_bits` using optional deterministic `seed`.
    ///
    /// Writes the public modulus to `public_key` and the private key (in the backend's
    /// internal format) to `private_key`, and returns `(public_len, private_len)`.
    fn rsa_generate_key(
        &self,
        key_bits: TpmiRsaKeyBits,
        public_key: &mut [u8],
        private_key: &mut [u8],
        seed: Option<&[u8]>,
    ) -> Result<(usize, usize), CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Generates an ECC key pair for `curve` using optional deterministic `seed`.
    ///
    /// Writes the public point (`x || y`) to `public_key` and the private scalar to
    /// `private_key`, and returns `(public_len, private_len)`.
    fn ecc_generate_key(
        &self,
        curve: TpmEccCurve,
        public_key: &mut [u8],
        private_key: &mut [u8],
        seed: Option<&[u8]>,
    ) -> Result<(usize, usize), CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Imports an RSA private key by verifying its components and serializing it into the internal format.
    ///
    /// Returns `Ok(Some(len))` with the length of the private key written to
    /// `private_key_out`, or `Ok(None)` if the components do not form a valid key (e.g.
    /// `prime_p` does not divide `modulus`, or `exponent` is invalid).
    fn rsa_import_private_key(
        &self,
        modulus: &[u8],
        prime_p: &[u8],
        exponent: u32,
        private_key_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Extracts prime factor P from a PKCS#8 DER-encoded RSA private key.
    ///
    /// Returns `Ok(Some(len))` with the length of the prime written to `prime_p_out`, or
    /// `Ok(None)` if `private_key` is not a valid private key.
    fn rsa_private_key_to_prime_p(
        &self,
        private_key: &[u8],
        prime_p_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Verifies `signature` over `digest` using the requested `sign_alg`.
    ///
    /// Dispatches to the algorithm-specific method for each signature scheme
    /// whose crate feature is enabled; any other `sign_alg` returns
    /// `Err(`[`CryptoError::Unsupported`]`)`.
    fn verify_inner(
        &self,
        sign_alg: Alg,
        public_key: &[u8],
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        match sign_alg {
            #[cfg(feature = "rsassa")]
            Alg::RSASSA => self.rsassa_verify(public_key, digest, signature),
            #[cfg(feature = "rsapss")]
            Alg::RSAPSS => self.rsapss_verify(public_key, digest, signature),
            #[cfg(feature = "ecdsa")]
            Alg::ECDSA => self.ecdsa_verify(public_key, digest, signature),
            #[cfg(feature = "sm2")]
            Alg::SM2 => self.sm2_verify(public_key, digest, signature),
            #[cfg(feature = "ecschnorr")]
            Alg::ECSCHNORR => self.ecschnorr_verify(public_key, digest, signature),
            _ => Err(CryptoError::Unsupported),
        }
    }

    /// Encrypts `data` using the requested asymmetric `scheme` and `hash_alg`.
    ///
    /// `scheme` is [`Alg::RSAES`], [`Alg::OAEP`] (with `hash_alg` and `label`), or
    /// [`Alg::NULL`] (raw RSA), each available only if the corresponding crate feature is
    /// enabled. Any other `scheme`, or an OAEP `hash_alg` that is not a hash algorithm,
    /// returns `Err(`[`CryptoError::Unsupported`]`)`.
    fn encrypt(
        &self,
        scheme: Alg,
        hash_alg: Alg,
        public_key: &[u8],
        data: &[u8],
        ciphertext: &mut [u8],
        label: &[u8],
    ) -> Result<Option<usize>, CryptoError> {
        match scheme {
            #[cfg(feature = "rsaes")]
            Alg::RSAES => self.rsaes_encrypt(public_key, data, ciphertext),
            #[cfg(feature = "oaep")]
            Alg::OAEP => {
                let hash = Option::<TpmiAlgHash>::try_from(hash_alg)
                    .ok()
                    .flatten()
                    .ok_or(CryptoError::Unsupported)?;
                self.oaep_encrypt(hash, public_key, data, label, ciphertext)
            }
            #[cfg(feature = "rsa")]
            Alg::NULL => self.rsa_null_encrypt(public_key, data, ciphertext),
            _ => Err(CryptoError::Unsupported),
        }
    }

    /// Decrypts `ciphertext` using the requested asymmetric `scheme` and `hash_alg`.
    ///
    /// `scheme` is [`Alg::RSAES`], [`Alg::OAEP`] (with `hash_alg` and `label`), or
    /// [`Alg::NULL`] (raw RSA), each available only if the corresponding crate feature is
    /// enabled. Any other `scheme`, or an OAEP `hash_alg` that is not a hash algorithm,
    /// returns `Err(`[`CryptoError::Unsupported`]`)`.
    fn decrypt(
        &self,
        scheme: Alg,
        hash_alg: Alg,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        label: &[u8],
    ) -> Result<Option<usize>, CryptoError> {
        match scheme {
            #[cfg(feature = "rsaes")]
            Alg::RSAES => self.rsaes_decrypt(private_key, ciphertext, plaintext),
            #[cfg(feature = "oaep")]
            Alg::OAEP => {
                let hash = Option::<TpmiAlgHash>::try_from(hash_alg)
                    .ok()
                    .flatten()
                    .ok_or(CryptoError::Unsupported)?;
                self.oaep_decrypt(hash, private_key, ciphertext, label, plaintext)
            }
            #[cfg(feature = "rsa")]
            Alg::NULL => self.rsa_null_decrypt(private_key, ciphertext, plaintext),
            _ => Err(CryptoError::Unsupported),
        }
    }

    /// Generates an asymmetric key pair for `scheme` and `params`.
    ///
    /// `scheme` is [`Alg::RSA`] (with [`KeyParams::Rsa`], defaulting to 2048 bits) or
    /// [`Alg::ECC`]/[`Alg::ECDH`] (with [`KeyParams::Ecc`], defaulting to NIST P-256), each
    /// available only if the corresponding crate feature is enabled. Any other `scheme`
    /// returns `Err(`[`CryptoError::Unsupported`]`)`.
    fn generate_key(
        &self,
        scheme: Alg,
        params: Option<KeyParams>,
        public_key: &mut [u8],
        private_key: &mut [u8],
        seed: Option<&[u8]>,
    ) -> Result<(usize, usize), CryptoError> {
        match scheme {
            #[cfg(feature = "rsa")]
            Alg::RSA => {
                let bits = match params {
                    Some(KeyParams::Rsa(bits)) => bits,
                    _ => TpmiRsaKeyBits(2048),
                };
                self.rsa_generate_key(bits, public_key, private_key, seed)
            }
            #[cfg(feature = "ecc")]
            Alg::ECC | Alg::ECDH => {
                let curve = match params {
                    Some(KeyParams::Ecc(curve)) => curve,
                    #[cfg(feature = "ecc_curve_nist_p256")]
                    _ => TpmEccCurve::NistP256,
                    #[cfg(not(feature = "ecc_curve_nist_p256"))]
                    _ => return Err(CryptoError::Unsupported),
                };
                self.ecc_generate_key(curve, public_key, private_key, seed)
            }
            _ => Err(CryptoError::Unsupported),
        }
    }
}

/// Signs `digest` using the requested `sign_alg` via backend `a`.
///
/// See [`AsymmetricSign::sign_inner`].
pub fn sign_inner<A: AsymmetricSign>(
    a: &A,
    sign_alg: Alg,
    private_key: &[u8],
    digest: TpmtHa<'_>,
    signature_out: &mut [u8],
) -> Result<Option<usize>, CryptoError> {
    a.sign_inner(sign_alg, private_key, digest, signature_out)
}

/// Verifies `signature` over `digest` using the requested `sign_alg` via backend `a`.
///
/// See [`Asymmetric::verify_inner`].
pub fn verify_inner<A: Asymmetric>(
    a: &A,
    sign_alg: Alg,
    public_key: &[u8],
    digest: TpmtHa<'_>,
    signature: &[u8],
) -> Result<bool, CryptoError> {
    a.verify_inner(sign_alg, public_key, digest, signature)
}

/// Encrypts `data` using the requested asymmetric `scheme` and `hash_alg` via backend `a`.
///
/// See [`Asymmetric::encrypt`].
pub fn rsa_encrypt<A: Asymmetric>(
    a: &A,
    scheme: Alg,
    hash_alg: Alg,
    public_key: &[u8],
    data: &[u8],
    ciphertext: &mut [u8],
    label: &[u8],
) -> Result<Option<usize>, CryptoError> {
    a.encrypt(scheme, hash_alg, public_key, data, ciphertext, label)
}

/// Decrypts `ciphertext` using the requested asymmetric `scheme` and `hash_alg` via backend `a`.
///
/// See [`Asymmetric::decrypt`].
pub fn rsa_decrypt<A: Asymmetric>(
    a: &A,
    scheme: Alg,
    hash_alg: Alg,
    private_key: &[u8],
    ciphertext: &[u8],
    plaintext: &mut [u8],
    label: &[u8],
) -> Result<Option<usize>, CryptoError> {
    a.decrypt(scheme, hash_alg, private_key, ciphertext, plaintext, label)
}

/// Generates an asymmetric key pair for `scheme` and `params` via backend `a`.
///
/// See [`Asymmetric::generate_key`].
pub fn generate_key<A: Asymmetric>(
    a: &A,
    scheme: Alg,
    params: Option<KeyParams>,
    public_key: &mut [u8],
    private_key: &mut [u8],
    seed: Option<&[u8]>,
) -> Result<(usize, usize), CryptoError> {
    a.generate_key(scheme, params, public_key, private_key, seed)
}

/// Imports an RSA private key from modulus, prime P, and exponent via backend `a`.
///
/// See [`Asymmetric::rsa_import_private_key`].
pub fn rsa_import_private_key<A: Asymmetric>(
    a: &A,
    modulus: &[u8],
    prime_p: &[u8],
    exponent: u32,
    private_key_out: &mut [u8],
) -> Result<Option<usize>, CryptoError> {
    a.rsa_import_private_key(modulus, prime_p, exponent, private_key_out)
}

/// Extracts prime factor P from a PKCS#8 DER-encoded RSA private key via backend `a`.
///
/// See [`Asymmetric::rsa_private_key_to_prime_p`].
pub fn rsa_private_key_to_prime_p<A: Asymmetric>(
    a: &A,
    private_key: &[u8],
    prime_p_out: &mut [u8],
) -> Result<Option<usize>, CryptoError> {
    a.rsa_private_key_to_prime_p(private_key, prime_p_out)
}
