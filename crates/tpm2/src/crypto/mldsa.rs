use super::{CryptoError, Finalize, Random, Rng, Update};
use crate::{
    Tpm2b, Tpm2bPrivateKeyMldsa, Tpm2bPublicKeyMldsa, Tpm2bSignatureCtx, Tpm2bSignatureMldsa,
    TpmiAlgHash, TpmiMldsaParms, TpmtHa,
};

/// Message representation signed by [`Mldsa::sign`] and verified by [`Mldsa::verify`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MldsaMessage<'a> {
    /// ML-DSA: the full `message` under `context` (FIPS 204, Algorithms 2 and 3).
    Pure {
        context: Tpm2bSignatureCtx<'a>,
        message: &'a [u8],
    },
    /// HashML-DSA: the pre-hash `digest` of the message under `context` (FIPS 204, Algorithms 4 and 5).
    PreHash {
        context: Tpm2bSignatureCtx<'a>,
        digest: TpmtHa<'a>,
    },
    /// The message representative `µ` (FIPS 204, Algorithm 7, line 6), either
    /// supplied externally or computed with [`Mldsa::mu_start`].
    ExternalMu(&'a [u8; TpmiMldsaParms::MU_BYTES]),
}

/// Returns the DER-encoded OID of `hash`, as included in the HashML-DSA message `M'`
/// (FIPS 204, Algorithm 4).
pub const fn pre_hash_oid(hash: TpmiAlgHash) -> &'static [u8] {
    match hash {
        #[cfg(feature = "sha1")]
        TpmiAlgHash::Sha1 => &[0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A],
        #[cfg(feature = "sha256")]
        TpmiAlgHash::Sha256 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ],
        #[cfg(feature = "sha384")]
        TpmiAlgHash::Sha384 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        ],
        #[cfg(feature = "sha512")]
        TpmiAlgHash::Sha512 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        ],
        #[cfg(feature = "sm3_256")]
        TpmiAlgHash::Sm3_256 => &[0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x11],
        #[cfg(feature = "sha3_256")]
        TpmiAlgHash::Sha3_256 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
        ],
        #[cfg(feature = "sha3_384")]
        TpmiAlgHash::Sha3_384 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09,
        ],
        #[cfg(feature = "sha3_512")]
        TpmiAlgHash::Sha3_512 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A,
        ],
    }
}

/// Trait implemented by an opaque ML-DSA public key handle.
pub trait MldsaPublicKey {
    /// Returns the ML-DSA parameter set.
    fn parameter_set(&self) -> TpmiMldsaParms;

    /// Writes the encoded public key `pk` into `out` and returns it as a [`Tpm2bPublicKeyMldsa`].
    fn encoded<'a>(
        &self,
        out: &'a mut [u8; TpmiMldsaParms::MAX_PUB_KEY_BYTES],
    ) -> Result<Tpm2bPublicKeyMldsa<'a>, CryptoError>;
}

/// Trait implemented by an opaque ML-DSA private key handle.
pub trait MldsaPrivateKey {
    type PublicKey: MldsaPublicKey;

    /// Returns a reference to the corresponding public key.
    fn public_key(&self) -> &Self::PublicKey;

    /// Writes the 32-byte seed `ξ` into `out` and returns it as a [`Tpm2bPrivateKeyMldsa`].
    fn seed<'a>(&self, out: &'a mut [u8; 32]) -> Result<Tpm2bPrivateKeyMldsa<'a>, CryptoError>;
}

impl MldsaPublicKey for ! {
    fn parameter_set(&self) -> TpmiMldsaParms {
        match *self {}
    }

    fn encoded<'a>(
        &self,
        _: &'a mut [u8; TpmiMldsaParms::MAX_PUB_KEY_BYTES],
    ) -> Result<Tpm2bPublicKeyMldsa<'a>, CryptoError> {
        match *self {}
    }
}

impl MldsaPrivateKey for ! {
    type PublicKey = !;

    fn public_key(&self) -> &! {
        match *self {}
    }

    fn seed<'a>(&self, _: &'a mut [u8; 32]) -> Result<Tpm2bPrivateKeyMldsa<'a>, CryptoError> {
        match *self {}
    }
}

/// Trait implemented by a cryptographic backend to provide ML-DSA ([FIPS 204]) operations.
///
/// The TPM represents an ML-DSA private key as its 32-byte seed `ξ`, so
/// backends implement [`Mldsa::derive_key`], and [`Mldsa::generate_key`] and
/// [`Mldsa::load_private`] are provided in terms of it.
///
/// Backends implement [`Mldsa::sign`] and [`Mldsa::verify`] for whichever
/// [`MldsaMessage`] variants they support and return
/// [`CryptoError::Unsupported`] for the rest. Backends that cannot compute `µ`
/// incrementally bind [`Mldsa::MuContext`] to [`!`].
///
/// Backends without ML-DSA support bind all associated types to [`!`] and keep
/// the default method bodies of `Err(`[`CryptoError::Unsupported`]`)`.
///
/// [FIPS 204]: https://csrc.nist.gov/pubs/fips/204/final
#[allow(unused_variables)]
pub trait Mldsa: Random {
    type PublicKey: MldsaPublicKey;
    type PrivateKey: MldsaPrivateKey<PublicKey = Self::PublicKey>;
    type MuContext: Update + Finalize<64>;

    /// Loads an encoded public key.
    ///
    /// Returns `Ok(None)` if `key` has the wrong length for `parameter_set`.
    fn load_public(
        &self,
        parameter_set: TpmiMldsaParms,
        key: Tpm2bPublicKeyMldsa<'_>,
    ) -> Result<Option<Self::PublicKey>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Expands the 32-byte `seed` `ξ` into a key pair (`ML-DSA.KeyGen_internal`).
    fn derive_key(
        &self,
        parameter_set: TpmiMldsaParms,
        seed: Tpm2bPrivateKeyMldsa<'_>,
    ) -> Result<Self::PrivateKey, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Generates a key pair from a seed `ξ` sampled from `rng` (`ML-DSA.KeyGen`).
    fn generate_key(
        &self,
        rng: &mut Self::Rng,
        parameter_set: TpmiMldsaParms,
    ) -> Result<Self::PrivateKey, CryptoError> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed)?;
        self.derive_key(parameter_set, Tpm2b(&seed))
    }

    /// Loads an ML-DSA private key from its public key and seed `ξ`.
    ///
    /// Returns `Ok(None)` if `seed` does not derive `public`.
    fn load_private(
        &self,
        public: Self::PublicKey,
        seed: Tpm2bPrivateKeyMldsa<'_>,
    ) -> Result<Option<Self::PrivateKey>, CryptoError> {
        let private = self.derive_key(public.parameter_set(), seed)?;
        let mut expected = [0u8; TpmiMldsaParms::MAX_PUB_KEY_BYTES];
        let mut actual = [0u8; TpmiMldsaParms::MAX_PUB_KEY_BYTES];
        let matches =
            public.encoded(&mut expected)? == private.public_key().encoded(&mut actual)?;
        Ok(matches.then_some(private))
    }

    /// Starts computing `µ` for an ML-DSA message under `context` with `key`
    /// (FIPS 204, Algorithm 7, line 6 with `M' = 0 || |ctx| || ctx || M`).
    ///
    /// The caller feeds the message `M` with [`Update`] and passes the
    /// finalized `µ` as [`MldsaMessage::ExternalMu`]. This is used by the
    /// `TPM2_SignSequence*` and `TPM2_VerifySequence*` commands.
    fn mu_start(
        &self,
        key: &Self::PublicKey,
        context: Tpm2bSignatureCtx<'_>,
    ) -> Result<Self::MuContext, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Signs `message` with `key` (hedged, using randomness from `rng`).
    ///
    /// Returns `Ok(None)` if no signature was produced within the
    /// implementation's rejection-sampling limit (`TPM_RC_NO_RESULT`).
    fn sign<'a>(
        &self,
        rng: &mut Self::Rng,
        key: &Self::PrivateKey,
        message: MldsaMessage<'_>,
        out: &'a mut [u8; TpmiMldsaParms::MAX_SIG_BYTES],
    ) -> Result<Option<Tpm2bSignatureMldsa<'a>>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Verifies `signature` over `message`. Returns `Ok(true)` if valid, `Ok(false)` if invalid.
    fn verify(
        &self,
        key: &Self::PublicKey,
        message: MldsaMessage<'_>,
        signature: Tpm2bSignatureMldsa<'_>,
    ) -> Result<bool, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}
