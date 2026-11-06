#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

use tpm2::crypto::{Crypto, CryptoError, Random, Rng};

/// BoringSSL-based implementation of the `tpm2::crypto` backend interfaces
/// ([`Crypto`] and the [`tpm2::crypto::backend`] family traits).
///
/// Supported algorithms: SHA-1/SHA-256/SHA-384/SHA-512 (hash and HMAC),
/// AES-128/192/256 (CMAC, and the CTR, OFB, CBC, CFB and ECB modes for symmetric
/// encryption), Camellia-128/192/256 (the same; BoringSSL is built without
/// Camellia, `OPENSSL_NO_CAMELLIA`, so these fall back to the RustCrypto
/// implementation of `tpm2-crypto-rust`), RSA 1024-4096
/// (RSASSA, RSAPSS, RSAES, OAEP, raw RSA, key generation and import), the NIST
/// P-224/P-256/P-384/P-521 curves and BN-P256 (ECDSA, ECDH, point operations and
/// key generation), NIST P-192, BN P-638 and SM2 P-256 (the same, and SM2
/// signatures) with the generic constant-time short-Weierstrass arithmetic of
/// `tpm2-crypto-weierstrass` (BoringSSL limits custom curves to 66-byte fields,
/// too small for BN P-638; the same implementation serves the other two curves
/// for uniformity, see `bssl-algorithms.md`), and ML-KEM-768/1024 and
/// ML-DSA-44/65/87 key generation and verification.
/// ML-KEM-512 and ML-DSA signing (with the TPM's signing randomness) fall back
/// to RustCrypto `ml-kem`/`ml-dsa` (`tpm2-crypto-rust`; see [`pqc`]).
/// Everything else is bound to `!` ([`CryptoError::Unsupported`]).
pub struct BsslCryptoProvider;

impl Crypto for BsslCryptoProvider {
    /// Compares `a` and `b` with BoringSSL's `CRYPTO_memcmp`, in time independent
    /// of their contents (slices of different lengths are unequal).
    fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        bssl_crypto::constant_time_compare(a, b)
    }
}

/// The RNG of [`BsslCryptoProvider::from_entropy`] is BoringSSL's `RAND_bytes`, and the
/// deterministic RNG of [`BsslCryptoProvider::from_seed`] is a ChaCha20 RNG seeded with
/// SHA-256 of the seed.
impl Random for BsslCryptoProvider {
    type Rng = BsslRng;

    fn from_entropy() -> Result<BsslRng, CryptoError> {
        Ok(BsslRng(RngSource::System))
    }

    fn from_seed(seed: &[u8]) -> Result<BsslRng, CryptoError> {
        let seed_32 = bssl_crypto::digest::Sha256::hash(seed);
        use rand_chacha::rand_core::SeedableRng as _;
        Ok(BsslRng(RngSource::Seeded(
            rand_chacha::ChaCha20Rng::from_seed(seed_32),
        )))
    }

    fn rand_bytes(out: &mut [u8]) -> Result<(), CryptoError> {
        bssl_crypto::rand_bytes(out);
        Ok(())
    }
}

pub mod bssl;
#[forbid(unsafe_code)]
pub mod cmac;
#[forbid(unsafe_code)]
pub mod ecc;
#[forbid(unsafe_code)]
pub mod hash;
#[forbid(unsafe_code)]
pub mod pqc;
#[forbid(unsafe_code)]
pub mod rsa;
#[forbid(unsafe_code)]
pub mod symmetric;
pub use {bssl::*, cmac::*, ecc::*, hash::*, pqc::*, rsa::*, symmetric::*};

/// Maps the result of a verification or validation binding to the
/// `tpm2::crypto` convention: [`BsslError::InvalidData`] (a bad signature, key,
/// or point) is `Ok(false)`.
pub(crate) fn verified(result: Result<(), BsslError>) -> Result<bool, CryptoError> {
    match result {
        Ok(()) => Ok(true),
        Err(BsslError::InvalidData) => Ok(false),
        Err(err) => Err(err.into()),
    }
}

/// Maps the result of a binding producing output to the `tpm2::crypto`
/// convention: [`BsslError::InvalidData`] (an invalid input) is `Ok(None)`.
pub(crate) fn output<T>(result: Result<T, BsslError>) -> Result<Option<T>, CryptoError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(BsslError::InvalidData) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

/// The random number generator of [`BsslCryptoProvider`] ([`Random::Rng`]).
///
/// It is either BoringSSL's `RAND_bytes` ([`Random::from_entropy`]), or a deterministic
/// ChaCha20 RNG ([`Random::from_seed`]), whose output depends only on the seed and the
/// sequence of calls. It also implements [`rand_core::RngCore`], for the key generation
/// of the curves and parameter sets that take their randomness from it.
pub struct BsslRng(RngSource);

#[allow(clippy::large_enum_variant)]
enum RngSource {
    /// BoringSSL's `RAND_bytes`.
    System,
    /// A ChaCha20 RNG seeded with SHA-256 of the seed (and reseeded by `stir_bytes`).
    Seeded(rand_chacha::ChaCha20Rng),
}

impl BsslRng {
    /// Returns `true` for the deterministic RNG of [`Random::from_seed`].
    pub fn is_seeded(&self) -> bool {
        matches!(self.0, RngSource::Seeded(_))
    }
}

impl Rng for BsslRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        rand_core::RngCore::fill_bytes(self, out);
        Ok(())
    }

    /// For BoringSSL's `RAND_bytes`, does nothing: BoringSSL reseeds itself from the
    /// operating system, and its public API takes no additional input. For the seeded RNG,
    /// reseeds the ChaCha20 RNG with SHA-256 of 32 bytes of its output followed by `data`
    /// (deterministic).
    fn stir_bytes(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if let RngSource::Seeded(rng) = &mut self.0 {
            use rand_chacha::rand_core::SeedableRng as _;
            let mut state = [0u8; 32];
            rand_core::RngCore::fill_bytes(rng, &mut state);
            let mut hash = bssl_crypto::digest::Sha256::new();
            hash.update(&state);
            hash.update(data);
            bssl::cleanse(&mut state);
            *rng = rand_chacha::ChaCha20Rng::from_seed(hash.digest());
        }
        Ok(())
    }
}

impl rand_core::RngCore for BsslRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        rand_core::RngCore::fill_bytes(self, &mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        rand_core::RngCore::fill_bytes(self, &mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        match &mut self.0 {
            RngSource::System => bssl_crypto::rand_bytes(dest),
            RngSource::Seeded(rng) => rng.fill_bytes(dest),
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        rand_core::RngCore::fill_bytes(self, dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for BsslRng {}

/// Draws an `N`-byte array from `rng`.
pub(crate) fn random_array<const N: usize>(rng: &mut BsslRng) -> [u8; N] {
    let mut out = [0u8; N];
    rand_core::RngCore::fill_bytes(rng, &mut out);
    out
}
