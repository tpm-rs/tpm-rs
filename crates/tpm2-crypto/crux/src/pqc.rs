//! ML-KEM (FIPS 203) and ML-DSA (FIPS 204).
//!
//! ML-KEM and ML-DSA key generation use the formally verified `libcrux-ml-kem` and
//! `libcrux-ml-dsa`. `libcrux-ml-dsa` signs and verifies messages only (it computes `mu`
//! itself), so signing and verification on an external `mu` fall back to the RustCrypto
//! implementation of [`tpm2_crypto_rust::pqc`] (`ml-dsa`).
use libcrux_ml_kem::{mlkem512, mlkem768, mlkem1024};
use tpm2::crypto::{
    CryptoError, MLDSA_MU_SIZE, MLDSA_RND_SIZE, MLDSA_SEED_SIZE, MLKEM_ENTROPY_SIZE,
    MLKEM_SEED_SIZE, MLKEM_SHARED_SECRET_SIZE,
};
use tpm2::{TpmiMldsaParms, TpmiMlkemParms};

use crate::CruxCryptoProvider;

/// Returns the first `len` bytes of `out`, or [`CryptoError::Internal`] if `out` is shorter.
fn output(out: &mut [u8], len: usize) -> Result<&mut [u8], CryptoError> {
    out.get_mut(..len).ok_or(CryptoError::Internal)
}

/// Runs `$body` with `$m` bound to the `libcrux-ml-kem` module of `$param_set`.
macro_rules! with_mlkem_module {
    ($param_set:expr, $m:ident => $body:expr) => {
        match $param_set {
            TpmiMlkemParms::Mlkem512 => {
                use mlkem512 as $m;
                $body
            }
            TpmiMlkemParms::Mlkem768 => {
                use mlkem768 as $m;
                $body
            }
            TpmiMlkemParms::Mlkem1024 => {
                use mlkem1024 as $m;
                $body
            }
        }
    };
}

/// ML-KEM-512/768/1024 with `libcrux-ml-kem`.
impl tpm2::crypto::Mlkem for CruxCryptoProvider {
    /// `ML-KEM.KeyGen_internal(d, z)` (`generate_key_pair` on the seed `d || z`).
    fn mlkem_generate_key(
        &self,
        param_set: TpmiMlkemParms,
        seed: &[u8; MLKEM_SEED_SIZE],
        public_key_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let len = param_set.public_key_bytes();
        let out = output(public_key_out, len)?;
        with_mlkem_module!(param_set, m => {
            out.copy_from_slice(m::generate_key_pair(*seed).public_key().as_slice());
        });
        Ok(len)
    }

    /// `ML-KEM.Encaps_internal(ek, m)` after the encapsulation key check (`validate_public_key`).
    fn mlkem_encapsulate(
        &self,
        param_set: TpmiMlkemParms,
        public_key: &[u8],
        entropy: &[u8; MLKEM_ENTROPY_SIZE],
        ciphertext_out: &mut [u8],
        shared_secret_out: &mut [u8; MLKEM_SHARED_SECRET_SIZE],
    ) -> Result<Option<usize>, CryptoError> {
        let len = param_set.ciphertext_bytes();
        let out = output(ciphertext_out, len)?;
        with_mlkem_module!(param_set, m => {
            let Ok(ek) = public_key.try_into() else {
                return Ok(None);
            };
            if !m::validate_public_key(&ek) {
                return Ok(None);
            }
            let (ct, k) = m::encapsulate(&ek, *entropy);
            out.copy_from_slice(ct.as_slice());
            *shared_secret_out = k;
        });
        Ok(Some(len))
    }

    /// `ML-KEM.Decaps` on the key pair generated from the seed `d || z`.
    fn mlkem_decapsulate(
        &self,
        param_set: TpmiMlkemParms,
        seed: &[u8; MLKEM_SEED_SIZE],
        ciphertext: &[u8],
        shared_secret_out: &mut [u8; MLKEM_SHARED_SECRET_SIZE],
    ) -> Result<bool, CryptoError> {
        with_mlkem_module!(param_set, m => {
            let Ok(ct) = ciphertext.try_into() else {
                return Ok(false);
            };
            let key_pair = m::generate_key_pair(*seed);
            *shared_secret_out = m::decapsulate(key_pair.private_key(), &ct);
        });
        Ok(true)
    }
}

/// ML-DSA-44/65/87: key generation with `libcrux-ml-dsa`, signing and verification on an
/// external `mu` with RustCrypto `ml-dsa` ([`tpm2_crypto_rust::pqc`]).
impl tpm2::crypto::Mldsa for CruxCryptoProvider {
    /// `ML-DSA.KeyGen_internal(xi)` (`generate_key_pair` on the seed `xi`).
    fn mldsa_generate_key(
        &self,
        param_set: TpmiMldsaParms,
        seed: &[u8; MLDSA_SEED_SIZE],
        public_key_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        use libcrux_ml_dsa::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
        let len = param_set.public_key_bytes();
        let out = output(public_key_out, len)?;
        match param_set {
            TpmiMldsaParms::Mldsa44 => out.copy_from_slice(
                ml_dsa_44::generate_key_pair(*seed)
                    .verification_key
                    .as_slice(),
            ),
            TpmiMldsaParms::Mldsa65 => out.copy_from_slice(
                ml_dsa_65::generate_key_pair(*seed)
                    .verification_key
                    .as_slice(),
            ),
            TpmiMldsaParms::Mldsa87 => out.copy_from_slice(
                ml_dsa_87::generate_key_pair(*seed)
                    .verification_key
                    .as_slice(),
            ),
        }
        Ok(len)
    }

    /// Falls back to RustCrypto `ml-dsa` ([`tpm2_crypto_rust::pqc::mldsa_sign_mu`]):
    /// `libcrux-ml-dsa` has no signing on an external `mu`.
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

    /// Falls back to RustCrypto `ml-dsa` ([`tpm2_crypto_rust::pqc::mldsa_verify_mu`]):
    /// `libcrux-ml-dsa` has no verification on an external `mu`.
    fn mldsa_verify_mu(
        &self,
        param_set: TpmiMldsaParms,
        public_key: &[u8],
        mu: &[u8; MLDSA_MU_SIZE],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        tpm2_crypto_rust::pqc::mldsa_verify_mu(param_set, public_key, mu, signature)
    }
}
