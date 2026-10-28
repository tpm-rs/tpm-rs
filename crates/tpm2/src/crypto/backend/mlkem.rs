//! [`Mlkem`] and [`MlkemKey`].

use super::PrivateKey;
use crate::crypto::{CryptoError, Random, Rng};

/// Module-Lattice-Based Key-Encapsulation Mechanism (FIPS 203 ML-KEM), with one
/// associated type per parameter set.
///
/// Each associated type implements [`MlkemKey`] parameterized by its
/// encapsulation key size (`PUB_SIZE`) and ciphertext size (`CT_SIZE`) in
/// bytes.
///
/// See the [module documentation](super) for how to implement this trait.
pub trait Mlkem: Random {
    type Mlkem512: MlkemKey<800, 768, Self::Rng>;
    type Mlkem768: MlkemKey<1184, 1088, Self::Rng>;
    type Mlkem1024: MlkemKey<1568, 1568, Self::Rng>;
}

/// ML-KEM private key operations for a single FIPS 203 parameter set, with
/// encapsulation keys of `PUB_SIZE` bytes, ciphertexts of `CT_SIZE` bytes, and
/// 32-byte shared secrets, using RNG `R`.
///
/// Private key operations take `&self`, and public key operations take a
/// [`PublicKey`](PrivateKey::PublicKey).
///
/// [`PrivateKey`] encodings:
/// - Public: the `PUB_SIZE`-byte FIPS 203 encapsulation key, which must pass
///   the FIPS 203 modulus check (all coefficients `< q = 3329`).
/// - Private: the 64-byte FIPS 203 `(d || z)` seed (`TPM2B_PRIVATE_KEY_MLKEM`),
///   which must expand to `public`.
pub trait MlkemKey<const PUB_SIZE: usize, const CT_SIZE: usize, R: Rng>:
    PrivateKey<PUB_SIZE, 64, R>
{
    /// Encapsulates a fresh 32-byte shared secret to `public` using randomness
    /// from `rng` (`TPM2_Encapsulate`), writing the ciphertext into `out_ct`
    /// and the 32-byte shared secret into `out_ss`.
    fn encapsulate(
        public: &Self::PublicKey,
        rng: &mut R,
        out_ct: &mut [u8; CT_SIZE],
        out_ss: &mut [u8; 32],
    ) -> Result<(), CryptoError>;

    /// Decapsulates `ct` using this key (`TPM2_Decapsulate`), writing the
    /// 32-byte shared secret (with FIPS 203 implicit rejection) into `out_ss`.
    fn decapsulate(&self, ct: &[u8; CT_SIZE], out_ss: &mut [u8; 32]) -> Result<(), CryptoError>;
}

impl<const PUB_SIZE: usize, const CT_SIZE: usize, R: Rng> MlkemKey<PUB_SIZE, CT_SIZE, R> for ! {
    fn encapsulate(
        public: &Self::PublicKey,
        _: &mut R,
        _: &mut [u8; CT_SIZE],
        _: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        match *public {}
    }
    fn decapsulate(&self, _: &[u8; CT_SIZE], _: &mut [u8; 32]) -> Result<(), CryptoError> {
        match *self {}
    }
}
