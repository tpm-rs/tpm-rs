//! [`Mldsa`] and [`MldsaKey`].

use super::AsymmetricKey;
use crate::{
    TpmtHa,
    crypto::{CryptoError, Rng},
};

/// Module-Lattice-Based Digital Signature Algorithm (FIPS 204 ML-DSA), with one
/// associated type per parameter set.
///
/// Each associated type implements [`MldsaKey`] parameterized by its encoded
/// public key size (`PUB_SIZE`) and signature size (`SIG_SIZE`) in bytes.
///
/// See the [module documentation](super) for how to implement this trait.
pub trait Mldsa {
    type Mldsa44: MldsaKey<1312, 2420>;
    type Mldsa65: MldsaKey<1952, 3309>;
    type Mldsa87: MldsaKey<2592, 4627>;
}

/// ML-DSA operations for a single FIPS 204 parameter set, with encoded public
/// keys of `PUB_SIZE` bytes, 32-byte private seeds `ξ`, and signatures of
/// `SIG_SIZE` bytes.
///
/// Per TPM 2.0 Part 2 (`TPMU_SIGNATURE_CTX`) and Part 3 (`TPM2_SignDigest`,
/// `TPM2_VerifyDigestSignature`, `TPM2_SignSequenceStart`,
/// `TPM2_VerifySequenceStart`), pure `ML-DSA` and `HashML-DSA` accept a context
/// string `context` of `0..=255` bytes
/// ([`TpmtSignature::MAX_CTX_BYTES`](crate::TpmtSignature::MAX_CTX_BYTES);
/// checked by the dispatch code before calling the backend), while external-`µ`
/// signing and verification ([`sign_mu`](Self::sign_mu) /
/// [`verify_mu`](Self::verify_mu)) do not take a context string.
///
/// [`AsymmetricKey`] encodings:
/// - Public: the `PUB_SIZE`-byte FIPS 204 encoded public key.
/// - Private: the 32-byte FIPS 204 seed `ξ` (`TPM2B_PRIVATE_KEY_MLDSA`), which
///   must expand to `public`.
pub trait MldsaKey<const PUB_SIZE: usize, const SIG_SIZE: usize>:
    AsymmetricKey<PUB_SIZE, 32>
{
    /// Signs the concatenation of `msg` slices using pure `ML-DSA` (FIPS 204
    /// `ML-DSA.Sign` with context string `context`, `context.len() <= 255`),
    /// writing the signature into `out_sig`.
    fn sign_message(
        rng: &mut impl Rng,
        private: &Self::Private,
        context: &[u8],
        msg: &[&[u8]],
        out_sig: &mut [u8; SIG_SIZE],
    ) -> Result<(), CryptoError>;

    /// Verifies pure `ML-DSA` signature `sig` over the concatenation of `msg`
    /// slices under `public` (FIPS 204 `ML-DSA.Verify` with context string
    /// `context`, `context.len() <= 255`).
    fn verify_message(
        public: &Self::Public,
        context: &[u8],
        msg: &[&[u8]],
        sig: &[u8; SIG_SIZE],
    ) -> Result<bool, CryptoError>;

    /// Signs a 64-byte external message representative `µ` (`TPM2_Sign` /
    /// `TPM2_SignDigest` with `TPM_ALG_MLDSA`) using `ML-DSA.Sign_internal`
    /// directly on `µ`, writing the signature into `out_sig`.
    fn sign_mu(
        rng: &mut impl Rng,
        private: &Self::Private,
        mu: &[u8; 64],
        out_sig: &mut [u8; SIG_SIZE],
    ) -> Result<(), CryptoError>;

    /// Verifies an `ML-DSA` signature `sig` over a 64-byte external message
    /// representative `µ` (`TPM2_VerifySignature` / `TPM2_VerifyDigestSignature`
    /// with `TPM_ALG_MLDSA`) using `ML-DSA.Verify_internal` directly on `µ`.
    fn verify_mu(
        public: &Self::Public,
        mu: &[u8; 64],
        sig: &[u8; SIG_SIZE],
    ) -> Result<bool, CryptoError>;

    /// Signs prehashed `digest` using `HashML-DSA` (FIPS 204 `HashML-DSA.Sign`
    /// with context string `context`, `context.len() <= 255`, and the ASN.1 OID
    /// of `digest.hash_alg()`), writing the signature into `out_sig`.
    ///
    /// Returns `Err(`[`CryptoError::Unsupported`]`)` if `digest.hash_alg()` is
    /// not a supported `HashML-DSA` prehash algorithm.
    fn sign_prehash(
        rng: &mut impl Rng,
        private: &Self::Private,
        context: &[u8],
        digest: TpmtHa<'_>,
        out_sig: &mut [u8; SIG_SIZE],
    ) -> Result<(), CryptoError>;

    /// Verifies `HashML-DSA` signature `sig` over prehashed `digest` under
    /// `public` (FIPS 204 `HashML-DSA.Verify` with context string `context`,
    /// `context.len() <= 255`, and the ASN.1 OID of `digest.hash_alg()`).
    ///
    /// Returns `Err(`[`CryptoError::Unsupported`]`)` if `digest.hash_alg()` is
    /// not a supported `HashML-DSA` prehash algorithm.
    fn verify_prehash(
        public: &Self::Public,
        context: &[u8],
        digest: TpmtHa<'_>,
        sig: &[u8; SIG_SIZE],
    ) -> Result<bool, CryptoError>;
}

impl<const PUB_SIZE: usize, const SIG_SIZE: usize> MldsaKey<PUB_SIZE, SIG_SIZE> for ! {
    fn sign_message(
        _: &mut impl Rng,
        private: &Self::Private,
        _: &[u8],
        _: &[&[u8]],
        _: &mut [u8; SIG_SIZE],
    ) -> Result<(), CryptoError> {
        match *private {}
    }
    fn verify_message(
        public: &Self::Public,
        _: &[u8],
        _: &[&[u8]],
        _: &[u8; SIG_SIZE],
    ) -> Result<bool, CryptoError> {
        match *public {}
    }
    fn sign_mu(
        _: &mut impl Rng,
        private: &Self::Private,
        _: &[u8; 64],
        _: &mut [u8; SIG_SIZE],
    ) -> Result<(), CryptoError> {
        match *private {}
    }
    fn verify_mu(
        public: &Self::Public,
        _: &[u8; 64],
        _: &[u8; SIG_SIZE],
    ) -> Result<bool, CryptoError> {
        match *public {}
    }
    fn sign_prehash(
        _: &mut impl Rng,
        private: &Self::Private,
        _: &[u8],
        _: TpmtHa<'_>,
        _: &mut [u8; SIG_SIZE],
    ) -> Result<(), CryptoError> {
        match *private {}
    }
    fn verify_prehash(
        public: &Self::Public,
        _: &[u8],
        _: TpmtHa<'_>,
        _: &[u8; SIG_SIZE],
    ) -> Result<bool, CryptoError> {
        match *public {}
    }
}
