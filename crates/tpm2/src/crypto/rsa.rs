use super::{CryptoError, Random};
use crate::{Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmiAlgHash, TpmiRsaKeyBits};

/// Encryption/decryption schemes for RSA operations (`TPM_ALG_NULL`, `RSAES`, `OAEP`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RsaEncryptScheme<'a> {
    /// Raw modular exponentiation (`TPM_ALG_NULL`).
    Raw,
    /// `RSAES-PKCS1-v1_5` (`TPM_ALG_RSAES`).
    Rsaes,
    /// `RSAES-OAEP` (`TPM_ALG_OAEP`) with digest algorithm and optional label.
    Oaep { hash: TpmiAlgHash, label: &'a [u8] },
}

/// Trait implemented by an opaque RSA public key handle.
pub trait RsaPublicKey {
    /// Returns the modulus size in bits.
    fn bits(&self) -> TpmiRsaKeyBits;

    /// Returns the public exponent `e` (`65537` for a key created with exponent `0`).
    fn exponent(&self) -> u32;

    /// Writes the big-endian public modulus `n` into `out` and returns it as a [`Tpm2bPublicKeyRsa`].
    fn modulus<'a>(
        &self,
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
    ) -> Result<Tpm2bPublicKeyRsa<'a>, CryptoError>;
}

/// Trait implemented by an opaque RSA private key handle.
pub trait RsaPrivateKey {
    type PublicKey: RsaPublicKey;

    /// Returns a reference to the corresponding public key.
    fn public_key(&self) -> &Self::PublicKey;

    /// Writes the secret prime factor `p` into `out` and returns it as a [`Tpm2bPrivateKeyRsa`].
    fn prime_p<'a>(
        &self,
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES],
    ) -> Result<Tpm2bPrivateKeyRsa<'a>, CryptoError>;
}

impl RsaPublicKey for ! {
    fn bits(&self) -> TpmiRsaKeyBits {
        match *self {}
    }

    fn exponent(&self) -> u32 {
        match *self {}
    }

    fn modulus<'a>(
        &self,
        _: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
    ) -> Result<Tpm2bPublicKeyRsa<'a>, CryptoError> {
        match *self {}
    }
}

impl RsaPrivateKey for ! {
    type PublicKey = !;

    fn public_key(&self) -> &! {
        match *self {}
    }

    fn prime_p<'a>(
        &self,
        _: &'a mut [u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES],
    ) -> Result<Tpm2bPrivateKeyRsa<'a>, CryptoError> {
        match *self {}
    }
}

/// Trait implemented by a cryptographic backend to provide RSA key operations.
///
/// Backends without RSA support bind the key types to [`!`] and keep the
/// default method bodies of `Err(`[`CryptoError::Unsupported`]`)`.
#[allow(unused_variables)]
pub trait Rsa: Random {
    type PublicKey: RsaPublicKey;
    type PrivateKey: RsaPrivateKey<PublicKey = Self::PublicKey>;

    /// Validates and loads an RSA public key (`exponent == 0` defaults to `65537`).
    ///
    /// Returns `Ok(None)` if the key parameters or modulus are invalid.
    fn load_public(
        &self,
        bits: TpmiRsaKeyBits,
        exponent: u32,
        modulus: Tpm2bPublicKeyRsa<'_>,
    ) -> Result<Option<Self::PublicKey>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Loads an RSA private key from its public key and first prime factor `p`.
    ///
    /// Returns `Ok(None)` if `prime_p` does not form a valid private key for `public`.
    fn load_private(
        &self,
        public: Self::PublicKey,
        prime_p: Tpm2bPrivateKeyRsa<'_>,
    ) -> Result<Option<Self::PrivateKey>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Generates an RSA keypair from `rng` (`exponent == 0` defaults to `65537`).
    ///
    /// The same `rng` output must give the same key, as `TPM2_CreatePrimary` relies on.
    /// Returns [`CryptoError::Unsupported`] for an exponent the backend cannot use (at least
    /// any even exponent or one below 3).
    fn generate_key(
        &self,
        rng: &mut Self::Rng,
        bits: TpmiRsaKeyBits,
        exponent: u32,
    ) -> Result<Self::PrivateKey, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Encrypts `plaintext` under `key` using `scheme` (`TPM2_RSA_Encrypt`, `MakeCredential`, etc.).
    ///
    /// Returns `Ok(None)` if `plaintext` is invalid for the key/scheme (e.g. too long or `>= modulus`).
    fn encrypt<'a>(
        &self,
        rng: &mut Self::Rng,
        key: &Self::PublicKey,
        scheme: RsaEncryptScheme<'_>,
        plaintext: &[u8],
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
    ) -> Result<Option<Tpm2bPublicKeyRsa<'a>>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Decrypts `ciphertext` under `key` using `scheme` (`TPM2_RSA_Decrypt`, `ActivateCredential`, etc.).
    ///
    /// Returns `Ok(None)` if `ciphertext` or its padding is invalid.
    fn decrypt<'a>(
        &self,
        key: &Self::PrivateKey,
        scheme: RsaEncryptScheme<'_>,
        ciphertext: &[u8],
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
    ) -> Result<Option<Tpm2bPublicKeyRsa<'a>>, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}
