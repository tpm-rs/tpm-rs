//! TPM 2.0 Asymmetric Cryptographic Abstractions
//!
//! This module defines the cryptographic traits required for asymmetric operations in TPM 2.0,
//! covering RSA and ECC signing/verification, RSA encryption/decryption, and key pair generation.
//!
//! ### Provider Abstraction
//!
//! Supported algorithms implement the specific trait methods (such as [`AsymmetricSign::rsassa_sign`],
//! [`Asymmetric::ecdsa_verify`], [`Asymmetric::oaep_encrypt`], [`Asymmetric::rsa_generate_key`], etc.),
//! while unimplemented algorithms keep the default body returning [`Err(self.unimplemented(...))`](Base::unimplemented).
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
//! # use tpm2::{crypto::{Base, AsymmetricSign, KeyParams}, Alg, TpmiRsaKeyBits, TpmtHa};
//! # struct MyBackend;
//! # #[derive(Debug, PartialEq)]
//! # struct MyError;
//! # impl Base for MyBackend {
//! #   type Error = MyError;
//! #   fn unimplemented(&self, _: Alg) -> MyError { MyError }
//! # }
//! impl AsymmetricSign for MyBackend {
//!     fn rsassa_sign(
//!         &self,
//!         _private_key: &[u8],
//!         _digest: TpmtHa<'_>,
//!         signature_out: &mut [u8],
//!     ) -> Result<usize, MyError> {
//!         signature_out[..32].fill(0xAA);
//!         Ok(32)
//!     }
//! }
//! ```

use crate::{Alg, TpmiAlgHash, TpmtHa, constants::TpmEccCurve, crypto::Base};

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
/// Unimplemented algorithms keep the default body of [`Err(self.unimplemented(...))`](Base::unimplemented).
pub trait AsymmetricSign: Base {
    /// Signs `digest` using RSASSA-PKCS1-v1_5 (`TPM_ALG_RSASSA`) with `private_key`.
    fn rsassa_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let _ = (private_key, digest, signature_out);
        Err(self.unimplemented(Alg::RSASSA))
    }

    /// Signs `digest` using RSASSA-PSS (`TPM_ALG_RSAPSS`) with `private_key`.
    fn rsapss_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let _ = (private_key, digest, signature_out);
        Err(self.unimplemented(Alg::RSAPSS))
    }

    /// Signs `digest` using ECDSA (`TPM_ALG_ECDSA`) with `private_key`.
    fn ecdsa_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let _ = (private_key, digest, signature_out);
        Err(self.unimplemented(Alg::ECDSA))
    }

    /// Signs `digest` using SM2 (`TPM_ALG_SM2`) with `private_key`.
    fn sm2_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let _ = (private_key, digest, signature_out);
        Err(self.unimplemented(Alg::SM2))
    }

    /// Signs `digest` using ECSchnorr (`TPM_ALG_ECSCHNORR`) with `private_key`.
    fn ecschnorr_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let _ = (private_key, digest, signature_out);
        Err(self.unimplemented(Alg::ECSCHNORR))
    }

    /// Signs `digest` using the requested `sign_alg`.
    fn sign_inner(
        &self,
        sign_alg: Alg,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<usize, Self::Error> {
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
            _ => {
                let _ = (private_key, digest, signature_out);
                Err(self.unimplemented(sign_alg))
            }
        }
    }
}

/// Cryptographic asymmetric verification, encryption/decryption, and key management interfaces for TPM implementations and clients.
///
/// Supported algorithms implement the algorithm-specific methods (such as [`Asymmetric::ecdsa_verify`],
/// [`Asymmetric::oaep_encrypt`], [`Asymmetric::rsa_generate_key`], etc.).
/// Unimplemented algorithms keep the default body of [`Err(self.unimplemented(...))`](Base::unimplemented).
pub trait Asymmetric: Base {
    /// Verifies `signature` over `digest` using RSASSA-PKCS1-v1_5 (`TPM_ALG_RSASSA`) with `public_key`.
    fn rsassa_verify(
        &self,
        public_key: &[u8],
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<(), Self::Error> {
        let _ = (public_key, digest, signature);
        Err(self.unimplemented(Alg::RSASSA))
    }

    /// Verifies `signature` over `digest` using RSASSA-PSS (`TPM_ALG_RSAPSS`) with `public_key`.
    fn rsapss_verify(
        &self,
        public_key: &[u8],
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<(), Self::Error> {
        let _ = (public_key, digest, signature);
        Err(self.unimplemented(Alg::RSAPSS))
    }

    /// Verifies `signature` over `digest` using ECDSA (`TPM_ALG_ECDSA`) with `public_key`.
    fn ecdsa_verify(
        &self,
        public_key: &[u8],
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<(), Self::Error> {
        let _ = (public_key, digest, signature);
        Err(self.unimplemented(Alg::ECDSA))
    }

    /// Verifies `signature` over `digest` using SM2 (`TPM_ALG_SM2`) with `public_key`.
    fn sm2_verify(
        &self,
        public_key: &[u8],
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<(), Self::Error> {
        let _ = (public_key, digest, signature);
        Err(self.unimplemented(Alg::SM2))
    }

    /// Verifies `signature` over `digest` using ECSchnorr (`TPM_ALG_ECSCHNORR`) with `public_key`.
    fn ecschnorr_verify(
        &self,
        public_key: &[u8],
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<(), Self::Error> {
        let _ = (public_key, digest, signature);
        Err(self.unimplemented(Alg::ECSCHNORR))
    }

    /// Encrypts `data` using RSAES-PKCS1-v1_5 (`TPM_ALG_RSAES`) with `public_key`.
    fn rsaes_encrypt(
        &self,
        public_key: &[u8],
        data: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let _ = (public_key, data, ciphertext);
        Err(self.unimplemented(Alg::RSAES))
    }

    /// Encrypts `data` using RSAES-OAEP (`TPM_ALG_OAEP`) with `hash_alg`, `public_key`, and `label`.
    fn oaep_encrypt(
        &self,
        hash_alg: TpmiAlgHash,
        public_key: &[u8],
        data: &[u8],
        label: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let _ = (hash_alg, public_key, data, label, ciphertext);
        Err(self.unimplemented(Alg::OAEP))
    }

    /// Encrypts `data` using raw RSA modular exponentiation ($m^e \bmod n$).
    fn rsa_null_encrypt(
        &self,
        public_key: &[u8],
        data: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let _ = (public_key, data, ciphertext);
        Err(self.unimplemented(Alg::RSA))
    }

    /// Decrypts `ciphertext` using RSAES-PKCS1-v1_5 (`TPM_ALG_RSAES`) with `private_key`.
    fn rsaes_decrypt(
        &self,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let _ = (private_key, ciphertext, plaintext);
        Err(self.unimplemented(Alg::RSAES))
    }

    /// Decrypts `ciphertext` using RSAES-OAEP (`TPM_ALG_OAEP`) with `hash_alg`, `private_key`, and `label`.
    fn oaep_decrypt(
        &self,
        hash_alg: TpmiAlgHash,
        private_key: &[u8],
        ciphertext: &[u8],
        label: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let _ = (hash_alg, private_key, ciphertext, label, plaintext);
        Err(self.unimplemented(Alg::OAEP))
    }

    /// Decrypts `ciphertext` using raw RSA modular exponentiation ($c^d \bmod n$).
    fn rsa_null_decrypt(
        &self,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let _ = (private_key, ciphertext, plaintext);
        Err(self.unimplemented(Alg::RSA))
    }

    /// Generates an RSA key pair for `key_bits` using optional deterministic `seed`.
    fn rsa_generate_key(
        &self,
        key_bits: TpmiRsaKeyBits,
        public_key: &mut [u8],
        private_key: &mut [u8],
        seed: Option<&[u8]>,
    ) -> Result<(usize, usize), Self::Error> {
        let _ = (key_bits, public_key, private_key, seed);
        Err(self.unimplemented(Alg::RSA))
    }

    /// Generates an ECC key pair for `curve` using optional deterministic `seed`.
    fn ecc_generate_key(
        &self,
        curve: TpmEccCurve,
        public_key: &mut [u8],
        private_key: &mut [u8],
        seed: Option<&[u8]>,
    ) -> Result<(usize, usize), Self::Error> {
        let _ = (curve, public_key, private_key, seed);
        Err(self.unimplemented(Alg::ECC))
    }

    /// Imports an RSA private key by verifying its components and serializing it into the internal format.
    fn rsa_import_private_key(
        &self,
        modulus: &[u8],
        prime_p: &[u8],
        exponent: u32,
        private_key_out: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let _ = (modulus, prime_p, exponent, private_key_out);
        Err(self.unimplemented(Alg::RSA))
    }

    /// Extracts prime factor P from a PKCS#8 DER-encoded RSA private key.
    fn rsa_private_key_to_prime_p(
        &self,
        private_key: &[u8],
        prime_p_out: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let _ = (private_key, prime_p_out);
        Err(self.unimplemented(Alg::RSA))
    }

    /// Verifies `signature` over `digest` using the requested `sign_alg`.
    fn verify_inner(
        &self,
        sign_alg: Alg,
        public_key: &[u8],
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<(), Self::Error> {
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
            _ => {
                let _ = (public_key, digest, signature);
                Err(self.unimplemented(sign_alg))
            }
        }
    }

    /// Encrypts `data` using the requested asymmetric `scheme` and `hash_alg`.
    fn encrypt(
        &self,
        scheme: Alg,
        hash_alg: Alg,
        public_key: &[u8],
        data: &[u8],
        ciphertext: &mut [u8],
        label: &[u8],
    ) -> Result<usize, Self::Error> {
        match scheme {
            #[cfg(feature = "rsaes")]
            Alg::RSAES => self.rsaes_encrypt(public_key, data, ciphertext),
            #[cfg(feature = "oaep")]
            Alg::OAEP => {
                let hash = Option::<TpmiAlgHash>::try_from(hash_alg)
                    .ok()
                    .flatten()
                    .ok_or_else(|| self.unimplemented(hash_alg))?;
                self.oaep_encrypt(hash, public_key, data, label, ciphertext)
            }
            #[cfg(feature = "rsa")]
            Alg::NULL => self.rsa_null_encrypt(public_key, data, ciphertext),
            _ => {
                let _ = (hash_alg, public_key, data, ciphertext, label);
                Err(self.unimplemented(scheme))
            }
        }
    }

    /// Decrypts `ciphertext` using the requested asymmetric `scheme` and `hash_alg`.
    fn decrypt(
        &self,
        scheme: Alg,
        hash_alg: Alg,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        label: &[u8],
    ) -> Result<usize, Self::Error> {
        match scheme {
            #[cfg(feature = "rsaes")]
            Alg::RSAES => self.rsaes_decrypt(private_key, ciphertext, plaintext),
            #[cfg(feature = "oaep")]
            Alg::OAEP => {
                let hash = Option::<TpmiAlgHash>::try_from(hash_alg)
                    .ok()
                    .flatten()
                    .ok_or_else(|| self.unimplemented(hash_alg))?;
                self.oaep_decrypt(hash, private_key, ciphertext, label, plaintext)
            }
            #[cfg(feature = "rsa")]
            Alg::NULL => self.rsa_null_decrypt(private_key, ciphertext, plaintext),
            _ => {
                let _ = (hash_alg, private_key, ciphertext, plaintext, label);
                Err(self.unimplemented(scheme))
            }
        }
    }

    /// Generates an asymmetric key pair for `scheme` and `params`.
    fn generate_key(
        &self,
        scheme: Alg,
        params: Option<KeyParams>,
        public_key: &mut [u8],
        private_key: &mut [u8],
        seed: Option<&[u8]>,
    ) -> Result<(usize, usize), Self::Error> {
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
                    _ => return Err(self.unimplemented(scheme)),
                };
                self.ecc_generate_key(curve, public_key, private_key, seed)
            }
            _ => {
                let _ = (params, public_key, private_key, seed);
                Err(self.unimplemented(scheme))
            }
        }
    }
}

/// Signs `digest` using the requested `sign_alg` via backend `a`.
pub fn sign_inner<A: AsymmetricSign>(
    a: &A,
    sign_alg: Alg,
    private_key: &[u8],
    digest: TpmtHa<'_>,
    signature_out: &mut [u8],
) -> Result<usize, A::Error> {
    a.sign_inner(sign_alg, private_key, digest, signature_out)
}

/// Verifies `signature` over `digest` using the requested `sign_alg` via backend `a`.
pub fn verify_inner<A: Asymmetric>(
    a: &A,
    sign_alg: Alg,
    public_key: &[u8],
    digest: TpmtHa<'_>,
    signature: &[u8],
) -> Result<(), A::Error> {
    a.verify_inner(sign_alg, public_key, digest, signature)
}

/// Encrypts `data` using the requested asymmetric `scheme` and `hash_alg` via backend `a`.
pub fn rsa_encrypt<A: Asymmetric>(
    a: &A,
    scheme: Alg,
    hash_alg: Alg,
    public_key: &[u8],
    data: &[u8],
    ciphertext: &mut [u8],
    label: &[u8],
) -> Result<usize, A::Error> {
    a.encrypt(scheme, hash_alg, public_key, data, ciphertext, label)
}

/// Decrypts `ciphertext` using the requested asymmetric `scheme` and `hash_alg` via backend `a`.
pub fn rsa_decrypt<A: Asymmetric>(
    a: &A,
    scheme: Alg,
    hash_alg: Alg,
    private_key: &[u8],
    ciphertext: &[u8],
    plaintext: &mut [u8],
    label: &[u8],
) -> Result<usize, A::Error> {
    a.decrypt(scheme, hash_alg, private_key, ciphertext, plaintext, label)
}

/// Generates an asymmetric key pair for `scheme` and `params` via backend `a`.
pub fn generate_key<A: Asymmetric>(
    a: &A,
    scheme: Alg,
    params: Option<KeyParams>,
    public_key: &mut [u8],
    private_key: &mut [u8],
    seed: Option<&[u8]>,
) -> Result<(usize, usize), A::Error> {
    a.generate_key(scheme, params, public_key, private_key, seed)
}

/// Imports an RSA private key from modulus, prime P, and exponent via backend `a`.
pub fn rsa_import_private_key<A: Asymmetric>(
    a: &A,
    modulus: &[u8],
    prime_p: &[u8],
    exponent: u32,
    private_key_out: &mut [u8],
) -> Result<usize, A::Error> {
    a.rsa_import_private_key(modulus, prime_p, exponent, private_key_out)
}

/// Extracts prime factor P from a PKCS#8 DER-encoded RSA private key via backend `a`.
pub fn rsa_private_key_to_prime_p<A: Asymmetric>(
    a: &A,
    private_key: &[u8],
    prime_p_out: &mut [u8],
) -> Result<usize, A::Error> {
    a.rsa_private_key_to_prime_p(private_key, prime_p_out)
}
