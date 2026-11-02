//! Post-quantum cryptography interfaces: ML-KEM (FIPS 203) and ML-DSA (FIPS 204).
//!
//! The TPM represents the private keys of both algorithms as seeds (TPM 2.0 Part 1, "ML-KEM Key
//! Representation and Generation" and "ML-DSA Key Representation and Generation"):
//!   - an ML-KEM private key is the 64-byte seed `d || z` of `ML-KEM.KeyGen_internal`
//!     (`TPM2B_PRIVATE_KEY_MLKEM`), and
//!   - an ML-DSA private key is the 32-byte seed `xi` of `ML-DSA.KeyGen_internal`
//!     (`TPM2B_PRIVATE_KEY_MLDSA`).
//!
//! Every operation is deterministic: the randomness a FIPS algorithm draws (the encapsulation
//! message `m` of `ML-KEM.Encaps`, the `rnd` of `ML-DSA.Sign`) is an explicit input, which the TPM
//! draws from its DRBG (as the TCG reference implementation does), so that the results are
//! reproducible.
//!
//! ML-DSA signing and verification work on the message representative `mu` (FIPS 204,
//! Algorithm 7 line 6 and Algorithm 8 line 7): the TPM computes `mu` itself (for pure ML-DSA,
//! HashML-DSA and external-mu signatures alike) and hands it to the provider.
//!
//! Following the conventions of [`crypto`](super), semantic failures are reported in the `Ok`
//! value: an invalid public key (one that fails the FIPS 203 encapsulation key check, or has the
//! wrong size) gives `Ok(None)`/`Ok(false)`, as does a ciphertext or signature of the wrong size.
//! Unimplemented operations keep the default body of `Err(`[`CryptoError::Unsupported`]`)`.
use super::CryptoError;
use crate::{TpmiMldsaParms, TpmiMlkemParms};

/// Size of an ML-KEM private key seed `d || z` (`MLKEM_PRIVATE_KEY_SEED_SIZE`).
pub const MLKEM_SEED_SIZE: usize = 64;
/// Size of the ML-KEM encapsulation randomness `m`.
pub const MLKEM_ENTROPY_SIZE: usize = 32;
/// Size of an ML-KEM shared secret `K` (`MLKEM_SHARED_SECRET_SIZE`).
pub const MLKEM_SHARED_SECRET_SIZE: usize = 32;
/// Size of an ML-DSA private key seed `xi` (`MLDSA_PRIVATE_KEY_SEED_SIZE`).
pub const MLDSA_SEED_SIZE: usize = 32;
/// Size of the ML-DSA message representative `mu` (`MLDSA_MU_SIZE`).
pub const MLDSA_MU_SIZE: usize = 64;
/// Size of the ML-DSA signing randomness `rnd`.
pub const MLDSA_RND_SIZE: usize = 32;

/// ML-KEM (FIPS 203) key encapsulation interfaces (`TPM_ALG_MLKEM`).
#[allow(unused_variables)]
pub trait Mlkem {
    /// Derives the encapsulation (public) key of the ML-KEM key with private seed `seed`
    /// (`d || z`, `ML-KEM.KeyGen_internal(d, z)`, FIPS 203 Algorithm 16) and writes it to the
    /// start of `public_key_out`, returning its length (the `ek` size of `param_set`).
    ///
    /// # Errors
    /// * [`CryptoError::Unsupported`] - `param_set` is not supported.
    /// * [`CryptoError::Internal`] - `public_key_out` is too small, or an internal failure.
    fn mlkem_generate_key(
        &self,
        param_set: TpmiMlkemParms,
        seed: &[u8; MLKEM_SEED_SIZE],
        public_key_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Encapsulates a shared secret to `public_key` with the randomness `entropy`
    /// (`ML-KEM.Encaps_internal(ek, m)`, FIPS 203 Algorithm 17), writing the ciphertext to the
    /// start of `ciphertext_out` and the shared secret to `shared_secret_out`.
    ///
    /// Returns `Ok(Some(ciphertext_len))`, or `Ok(None)` if `public_key` is not a valid
    /// encapsulation key of `param_set` (wrong size, or failing the modulus check of FIPS 203,
    /// Section 7.2).
    ///
    /// # Errors
    /// * [`CryptoError::Unsupported`] - `param_set` is not supported.
    /// * [`CryptoError::Internal`] - `ciphertext_out` is too small, or an internal failure.
    fn mlkem_encapsulate(
        &self,
        param_set: TpmiMlkemParms,
        public_key: &[u8],
        entropy: &[u8; MLKEM_ENTROPY_SIZE],
        ciphertext_out: &mut [u8],
        shared_secret_out: &mut [u8; MLKEM_SHARED_SECRET_SIZE],
    ) -> Result<Option<usize>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Decapsulates `ciphertext` with the ML-KEM key of private seed `seed` (`d || z`;
    /// `ML-KEM.Decaps`, FIPS 203 Algorithm 21, on the key expanded from the seed) and writes the
    /// shared secret to `shared_secret_out`.
    ///
    /// Returns `Ok(true)`, or `Ok(false)` if `ciphertext` does not have the ciphertext size of
    /// `param_set`. (A ciphertext of the right size always decapsulates: ML-KEM rejects invalid
    /// ciphertexts implicitly, with a pseudo-random shared secret.)
    ///
    /// # Errors
    /// * [`CryptoError::Unsupported`] - `param_set` is not supported.
    /// * [`CryptoError::Internal`] - an internal failure.
    fn mlkem_decapsulate(
        &self,
        param_set: TpmiMlkemParms,
        seed: &[u8; MLKEM_SEED_SIZE],
        ciphertext: &[u8],
        shared_secret_out: &mut [u8; MLKEM_SHARED_SECRET_SIZE],
    ) -> Result<bool, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

/// ML-DSA (FIPS 204) signature interfaces (`TPM_ALG_MLDSA` and `TPM_ALG_HASH_MLDSA`).
#[allow(unused_variables)]
pub trait Mldsa {
    /// Derives the verification (public) key of the ML-DSA key with private seed `seed` (`xi`,
    /// `ML-DSA.KeyGen_internal(xi)`, FIPS 204 Algorithm 6) and writes it to the start of
    /// `public_key_out`, returning its length (the `pk` size of `param_set`).
    ///
    /// # Errors
    /// * [`CryptoError::Unsupported`] - `param_set` is not supported.
    /// * [`CryptoError::Internal`] - `public_key_out` is too small, or an internal failure.
    fn mldsa_generate_key(
        &self,
        param_set: TpmiMldsaParms,
        seed: &[u8; MLDSA_SEED_SIZE],
        public_key_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Signs the message representative `mu` with the ML-DSA key of private seed `seed` (`xi`)
    /// and the signing randomness `rnd` (`ML-DSA.Sign_internal` from line 7 on, FIPS 204
    /// Algorithm 7, with `mu` computed by the caller; an all-zero `rnd` gives the deterministic
    /// variant), writing the signature to the start of `signature_out`.
    ///
    /// Returns `Ok(Some(signature_len))` (the signature size of `param_set`), or `Ok(None)` if no
    /// signature was found (the rejection sampling gave up; `TPM_RC_NO_RESULT`).
    ///
    /// # Errors
    /// * [`CryptoError::Unsupported`] - `param_set` is not supported.
    /// * [`CryptoError::Internal`] - `signature_out` is too small, or an internal failure.
    fn mldsa_sign_mu(
        &self,
        param_set: TpmiMldsaParms,
        seed: &[u8; MLDSA_SEED_SIZE],
        mu: &[u8; MLDSA_MU_SIZE],
        rnd: &[u8; MLDSA_RND_SIZE],
        signature_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Verifies `signature` over the message representative `mu` with the verification key
    /// `public_key` (`ML-DSA.Verify_internal` from line 8 on, FIPS 204 Algorithm 8, with `mu`
    /// computed by the caller).
    ///
    /// Returns `Ok(true)` for a valid signature, and `Ok(false)` for an invalid one, or if
    /// `public_key` or `signature` does not have the size of `param_set`.
    ///
    /// # Errors
    /// * [`CryptoError::Unsupported`] - `param_set` is not supported.
    /// * [`CryptoError::Internal`] - an internal failure.
    fn mldsa_verify_mu(
        &self,
        param_set: TpmiMldsaParms,
        public_key: &[u8],
        mu: &[u8; MLDSA_MU_SIZE],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}
