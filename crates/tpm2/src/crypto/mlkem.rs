use super::{CryptoError, Random, Rng};
use crate::{
    Tpm2b, Tpm2bKemCiphertext, Tpm2bPrivateKeyMlkem, Tpm2bPublicKeyMlkem, Tpm2bSharedSecret,
    TpmiMlkemParms,
};

const _: () = assert!(Tpm2bKemCiphertext::CAP >= TpmiMlkemParms::MAX_CT_BYTES);
const _: () = assert!(Tpm2bSharedSecret::CAP >= TpmiMlkemParms::SHARED_SECRET_BYTES);

/// Trait implemented by an opaque ML-KEM encapsulation (public) key handle.
pub trait MlkemPublicKey {
    /// Returns the ML-KEM parameter set.
    fn parameter_set(&self) -> TpmiMlkemParms;

    /// Writes the encoded encapsulation key `ek` into `out` and returns it as a [`Tpm2bPublicKeyMlkem`].
    fn encoded<'a>(
        &self,
        out: &'a mut [u8; TpmiMlkemParms::MAX_PUB_KEY_BYTES],
    ) -> Result<Tpm2bPublicKeyMlkem<'a>, CryptoError>;
}

/// Trait implemented by an opaque ML-KEM decapsulation (private) key handle.
pub trait MlkemPrivateKey {
    type PublicKey: MlkemPublicKey;

    /// Returns a reference to the corresponding public key.
    fn public_key(&self) -> &Self::PublicKey;

    /// Writes the 64-byte seed `(d || z)` into `out` and returns it as a [`Tpm2bPrivateKeyMlkem`].
    fn seed<'a>(&self, out: &'a mut [u8; 64]) -> Result<Tpm2bPrivateKeyMlkem<'a>, CryptoError>;
}

impl MlkemPublicKey for ! {
    fn parameter_set(&self) -> TpmiMlkemParms {
        match *self {}
    }

    fn encoded<'a>(
        &self,
        _: &'a mut [u8; TpmiMlkemParms::MAX_PUB_KEY_BYTES],
    ) -> Result<Tpm2bPublicKeyMlkem<'a>, CryptoError> {
        match *self {}
    }
}

impl MlkemPrivateKey for ! {
    type PublicKey = !;

    fn public_key(&self) -> &! {
        match *self {}
    }

    fn seed<'a>(&self, _: &'a mut [u8; 64]) -> Result<Tpm2bPrivateKeyMlkem<'a>, CryptoError> {
        match *self {}
    }
}

/// Trait implemented by a cryptographic backend to provide ML-KEM ([FIPS 203]) operations.
///
/// The TPM represents an ML-KEM private key as its 64-byte seed `(d || z)`, so
/// backends implement [`Mlkem::derive_key`], and [`Mlkem::generate_key`] and
/// [`Mlkem::load_private`] are provided in terms of it.
///
/// Backends without ML-KEM support bind the key types to [`!`] and keep the
/// default method bodies of `Err(`[`CryptoError::Unsupported`]`)`.
///
/// [FIPS 203]: https://csrc.nist.gov/pubs/fips/203/final
#[allow(unused_variables)]
pub trait Mlkem: Random {
    type PublicKey: MlkemPublicKey;
    type PrivateKey: MlkemPrivateKey<PublicKey = Self::PublicKey>;

    /// Validates and loads an encoded encapsulation key (FIPS 203, Section 7.2 input checking).
    ///
    /// Returns `Ok(None)` if `key` has the wrong length for `parameter_set` or fails the modulus check.
    fn load_public(
        &self,
        parameter_set: TpmiMlkemParms,
        key: Tpm2bPublicKeyMlkem<'_>,
    ) -> Result<Option<Self::PublicKey>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Expands the 64-byte `seed` `(d || z)` into a key pair (`ML-KEM.KeyGen_internal`).
    fn derive_key(
        &self,
        parameter_set: TpmiMlkemParms,
        seed: Tpm2bPrivateKeyMlkem<'_>,
    ) -> Result<Self::PrivateKey, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Generates a key pair from a seed `(d || z)` sampled from `rng` (`ML-KEM.KeyGen`).
    fn generate_key(
        &self,
        rng: &mut Self::Rng,
        parameter_set: TpmiMlkemParms,
    ) -> Result<Self::PrivateKey, CryptoError> {
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed)?;
        self.derive_key(parameter_set, Tpm2b(&seed))
    }

    /// Loads an ML-KEM private key from its public key and seed `(d || z)`.
    ///
    /// Returns `Ok(None)` if `seed` does not derive `public`.
    fn load_private(
        &self,
        public: Self::PublicKey,
        seed: Tpm2bPrivateKeyMlkem<'_>,
    ) -> Result<Option<Self::PrivateKey>, CryptoError> {
        let private = self.derive_key(public.parameter_set(), seed)?;
        let mut expected = [0u8; TpmiMlkemParms::MAX_PUB_KEY_BYTES];
        let mut actual = [0u8; TpmiMlkemParms::MAX_PUB_KEY_BYTES];
        let matches =
            public.encoded(&mut expected)? == private.public_key().encoded(&mut actual)?;
        Ok(matches.then_some(private))
    }

    /// Generates a shared secret and its ciphertext for `key` (`ML-KEM.Encaps`) using randomness from `rng`.
    fn encapsulate<'a>(
        &self,
        rng: &mut Self::Rng,
        key: &Self::PublicKey,
        out_ciphertext: &'a mut [u8; TpmiMlkemParms::MAX_CT_BYTES],
        out_shared_secret: &'a mut [u8; TpmiMlkemParms::SHARED_SECRET_BYTES],
    ) -> Result<(Tpm2bKemCiphertext<'a>, Tpm2bSharedSecret<'a>), CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Recovers the shared secret from `ciphertext` (`ML-KEM.Decaps`).
    ///
    /// Returns `Ok(None)` if `ciphertext` has the wrong length for the key's parameter set.
    fn decapsulate<'a>(
        &self,
        key: &Self::PrivateKey,
        ciphertext: Tpm2bKemCiphertext<'_>,
        out: &'a mut [u8; TpmiMlkemParms::SHARED_SECRET_BYTES],
    ) -> Result<Option<Tpm2bSharedSecret<'a>>, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}
