//! ML-KEM (FIPS 203) and ML-DSA (FIPS 204).
//!
//! BoringSSL implements ML-KEM-768/1024 and ML-DSA-44/65/87 ([`crate::bssl`]); the rest falls
//! back to the RustCrypto implementation of [`tpm2_crypto_rust::pqc`] (`ml-kem`, `ml-dsa`):
//!   - ML-KEM-512, which BoringSSL does not implement, and
//!   - ML-DSA signing: BoringSSL's public API draws the signing randomness `rnd` itself (its
//!     derandomized signing is internal to its C++ `BCM_*` module), and the TPM supplies `rnd`
//!     from its DRBG.
use tpm2::crypto::{
    CryptoError, MLDSA_MU_SIZE, MLDSA_RND_SIZE, MLDSA_SEED_SIZE, MLKEM_ENTROPY_SIZE,
    MLKEM_SEED_SIZE, MLKEM_SHARED_SECRET_SIZE,
};
use tpm2::{TpmiMldsaParms, TpmiMlkemParms};

use crate::bssl::{mldsa44, mldsa65, mldsa87, mlkem768, mlkem1024};
use crate::{BsslCryptoProvider, output, verified};

/// Returns the first `N` bytes of `out` as an array, or [`CryptoError::Internal`] if `out` is
/// shorter.
fn output_array<const N: usize>(out: &mut [u8]) -> Result<&mut [u8; N], CryptoError> {
    out.get_mut(..N)
        .and_then(|out| out.try_into().ok())
        .ok_or(CryptoError::Internal)
}

/// ML-KEM-768/1024 with BoringSSL; ML-KEM-512 with RustCrypto `ml-kem`.
impl tpm2::crypto::Mlkem for BsslCryptoProvider {
    fn mlkem_generate_key(
        &self,
        param_set: TpmiMlkemParms,
        seed: &[u8; MLKEM_SEED_SIZE],
        public_key_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        match param_set {
            TpmiMlkemParms::Mlkem512 => {
                return tpm2_crypto_rust::pqc::mlkem_generate_key(param_set, seed, public_key_out);
            }
            TpmiMlkemParms::Mlkem768 => {
                mlkem768::public_key_from_seed(seed, output_array(public_key_out)?)?
            }
            TpmiMlkemParms::Mlkem1024 => {
                mlkem1024::public_key_from_seed(seed, output_array(public_key_out)?)?
            }
        }
        Ok(param_set.public_key_bytes())
    }

    fn mlkem_encapsulate(
        &self,
        param_set: TpmiMlkemParms,
        public_key: &[u8],
        entropy: &[u8; MLKEM_ENTROPY_SIZE],
        ciphertext_out: &mut [u8],
        shared_secret_out: &mut [u8; MLKEM_SHARED_SECRET_SIZE],
    ) -> Result<Option<usize>, CryptoError> {
        let len = param_set.ciphertext_bytes();
        let result = match param_set {
            TpmiMlkemParms::Mlkem512 => {
                return tpm2_crypto_rust::pqc::mlkem_encapsulate(
                    param_set,
                    public_key,
                    entropy,
                    ciphertext_out,
                    shared_secret_out,
                );
            }
            // BoringSSL's key parsing checks the size, but the TPM's size check comes first.
            _ if public_key.len() != param_set.public_key_bytes() => return Ok(None),
            TpmiMlkemParms::Mlkem768 => mlkem768::encapsulate(
                public_key,
                entropy,
                output_array(ciphertext_out)?,
                shared_secret_out,
            ),
            TpmiMlkemParms::Mlkem1024 => mlkem1024::encapsulate(
                public_key,
                entropy,
                output_array(ciphertext_out)?,
                shared_secret_out,
            ),
        };
        Ok(output(result)?.map(|()| len))
    }

    fn mlkem_decapsulate(
        &self,
        param_set: TpmiMlkemParms,
        seed: &[u8; MLKEM_SEED_SIZE],
        ciphertext: &[u8],
        shared_secret_out: &mut [u8; MLKEM_SHARED_SECRET_SIZE],
    ) -> Result<bool, CryptoError> {
        match param_set {
            TpmiMlkemParms::Mlkem512 => {
                return tpm2_crypto_rust::pqc::mlkem_decapsulate(
                    param_set,
                    seed,
                    ciphertext,
                    shared_secret_out,
                );
            }
            TpmiMlkemParms::Mlkem768 => {
                let Ok(ciphertext) = ciphertext.try_into() else {
                    return Ok(false);
                };
                mlkem768::decapsulate(seed, ciphertext, shared_secret_out)?;
            }
            TpmiMlkemParms::Mlkem1024 => {
                let Ok(ciphertext) = ciphertext.try_into() else {
                    return Ok(false);
                };
                mlkem1024::decapsulate(seed, ciphertext, shared_secret_out)?;
            }
        }
        Ok(true)
    }
}

/// ML-DSA-44/65/87: key generation and verification with BoringSSL, signing with RustCrypto
/// `ml-dsa` (with the TPM's `rnd`).
impl tpm2::crypto::Mldsa for BsslCryptoProvider {
    fn mldsa_generate_key(
        &self,
        param_set: TpmiMldsaParms,
        seed: &[u8; MLDSA_SEED_SIZE],
        public_key_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        match param_set {
            TpmiMldsaParms::Mldsa44 => {
                mldsa44::public_key_from_seed(seed, output_array(public_key_out)?)?
            }
            TpmiMldsaParms::Mldsa65 => {
                mldsa65::public_key_from_seed(seed, output_array(public_key_out)?)?
            }
            TpmiMldsaParms::Mldsa87 => {
                mldsa87::public_key_from_seed(seed, output_array(public_key_out)?)?
            }
        }
        Ok(param_set.public_key_bytes())
    }

    /// Falls back to RustCrypto `ml-dsa` ([`tpm2_crypto_rust::pqc::mldsa_sign_mu`]): BoringSSL
    /// has no public signing with a caller-supplied `rnd`.
    fn mldsa_sign_mu(
        &self,
        param_set: TpmiMldsaParms,
        seed: &[u8; MLDSA_SEED_SIZE],
        mu: &[u8; MLDSA_MU_SIZE],
        rnd: &[u8; MLDSA_RND_SIZE],
        signature_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        tpm2_crypto_rust::pqc::mldsa_sign_mu(param_set, seed, mu, rnd, signature_out)
    }

    fn mldsa_verify_mu(
        &self,
        param_set: TpmiMldsaParms,
        public_key: &[u8],
        mu: &[u8; MLDSA_MU_SIZE],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        if public_key.len() != param_set.public_key_bytes()
            || signature.len() != param_set.signature_bytes()
        {
            return Ok(false);
        }
        verified(match param_set {
            TpmiMldsaParms::Mldsa44 => mldsa44::verify_mu(public_key, mu, signature),
            TpmiMldsaParms::Mldsa65 => mldsa65::verify_mu(public_key, mu, signature),
            TpmiMldsaParms::Mldsa87 => mldsa87::verify_mu(public_key, mu, signature),
        })
    }
}
