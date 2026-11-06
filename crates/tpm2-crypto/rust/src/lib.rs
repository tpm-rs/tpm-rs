#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]

extern crate alloc;

use tpm2::crypto::{Crypto, CryptoError, Random};

/// A cryptography backend using RustCrypto crates (such as `aes`, `camellia`, `rsa`, `p256`,
/// `sha2`, `hmac`), implementing [`tpm2::crypto::Crypto`].
///
/// This backend supplies all the necessary cryptographic primitives required by the TPM 2.0
/// stack: SHA-1/256/384/512 (hashes and HMAC), AES-128/192/256 and Camellia-128/192/256 (CMAC,
/// and the CTR, OFB, CBC, CFB and ECB modes for symmetric encryption), RSA-1024/2048/3072/4096
/// (`rsa`; see the [`rsa`] module), the curves NIST P-256/384/521 (`p256`, `p384`, `p521`),
/// ML-KEM-512/768/1024 (`ml-kem`) and ML-DSA-44/65/87 (`ml-dsa`; see the [`pqc`] module).
/// The curves NIST P-192, NIST P-224, BN P-256, BN P-638 and SM2 P-256, which RustCrypto does
/// not offer, use the generic constant-time short-Weierstrass arithmetic of
/// `tpm2-crypto-weierstrass` (which also provides `SM2` signatures on them).
///
/// SM3, SHA-3, SM4, the Brainpool curves, Curve25519 and Curve448 are not supported (`!`).
///
/// Randomness comes from [`RustCryptoRng`]: the operating system's entropy source
/// ([`Random::from_entropy`]) or a deterministic ChaCha20 generator ([`Random::from_seed`]).
pub struct RustCryptoProvider;

impl Random for RustCryptoProvider {
    type Rng = RustCryptoRng;

    fn from_entropy() -> Result<RustCryptoRng, CryptoError> {
        Ok(RustCryptoRng::os())
    }

    fn from_seed(seed: &[u8]) -> Result<RustCryptoRng, CryptoError> {
        Ok(RustCryptoRng::seeded(seed))
    }

    /// Fills `out` from the operating system's entropy source.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Internal` if the OS random number generator fails.
    fn rand_bytes(out: &mut [u8]) -> Result<(), CryptoError> {
        tpm2::crypto::Rng::fill_bytes(&mut RustCryptoRng::os(), out)
    }
}

impl Crypto for RustCryptoProvider {
    /// Compares `a` and `b` in constant time, using the `subtle` crate: the running time does
    /// not depend on the contents of the slices (only on their lengths).
    fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        use subtle::ConstantTimeEq as _;
        a.ct_eq(b).into()
    }
}

pub mod cmac;
pub mod ecc;
pub mod hash;
pub mod pqc;
mod rng;
pub mod rsa;
pub mod symmetric;
pub use rng::{RngAdapter, RustCryptoRng};
pub use symmetric::{BlockCipher, RustCryptoCipher};
pub use {cmac::*, ecc::*, hash::*};
