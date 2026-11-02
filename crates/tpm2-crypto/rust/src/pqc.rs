//! ML-KEM (FIPS 203) and ML-DSA (FIPS 204) with the RustCrypto `ml-kem` and `ml-dsa` crates.
//!
//! The functions of this module implement the semantics of [`tpm2::crypto::Mlkem`] and
//! [`tpm2::crypto::Mldsa`] for all three parameter sets of each algorithm; they are public so that
//! the other providers can fall back to them where their own library lacks an operation.
use ml_dsa::common::array::Array;
use ml_dsa::signature::Keypair as _;
use ml_dsa::signature::rand_core::{TryCryptoRng, TryRng};
use ml_dsa::{ExpandedSigningKey, MlDsa44, MlDsa65, MlDsa87, Signature, SigningKey, VerifyingKey};
use ml_kem::{
    Decapsulate as _, DecapsulationKey, EncapsulationKey, KeyExport as _, MlKem512, MlKem768,
    MlKem1024,
};
use tpm2::crypto::{
    CryptoError, MLDSA_MU_SIZE, MLDSA_RND_SIZE, MLDSA_SEED_SIZE, MLKEM_ENTROPY_SIZE,
    MLKEM_SEED_SIZE, MLKEM_SHARED_SECRET_SIZE,
};
use tpm2::{TpmiMldsaParms, TpmiMlkemParms};

use crate::RustCryptoProvider;

/// Returns the first `len` bytes of `out`, or [`CryptoError::Internal`] if `out` is shorter.
fn output(out: &mut [u8], len: usize) -> Result<&mut [u8], CryptoError> {
    out.get_mut(..len).ok_or(CryptoError::Internal)
}

/// Runs `$body` with `$P` bound to the `ml-kem` parameter set type of `$param_set`.
macro_rules! with_mlkem_params {
    ($param_set:expr, $P:ident => $body:expr) => {
        match $param_set {
            TpmiMlkemParms::Mlkem512 => {
                type $P = MlKem512;
                $body
            }
            TpmiMlkemParms::Mlkem768 => {
                type $P = MlKem768;
                $body
            }
            TpmiMlkemParms::Mlkem1024 => {
                type $P = MlKem1024;
                $body
            }
        }
    };
}

/// Runs `$body` with `$P` bound to the `ml-dsa` parameter set type of `$param_set`.
macro_rules! with_mldsa_params {
    ($param_set:expr, $P:ident => $body:expr) => {
        match $param_set {
            TpmiMldsaParms::Mldsa44 => {
                type $P = MlDsa44;
                $body
            }
            TpmiMldsaParms::Mldsa65 => {
                type $P = MlDsa65;
                $body
            }
            TpmiMldsaParms::Mldsa87 => {
                type $P = MlDsa87;
                $body
            }
        }
    };
}

/// [`tpm2::crypto::Mlkem::mlkem_generate_key`]: `ML-KEM.KeyGen_internal(d, z)` with `ml-kem`.
pub fn mlkem_generate_key(
    param_set: TpmiMlkemParms,
    seed: &[u8; MLKEM_SEED_SIZE],
    public_key_out: &mut [u8],
) -> Result<usize, CryptoError> {
    let len = param_set.public_key_bytes();
    let out = output(public_key_out, len)?;
    with_mlkem_params!(param_set, P => {
        let dk = DecapsulationKey::<P>::from_seed(Array::from(*seed));
        out.copy_from_slice(&dk.encapsulation_key().to_bytes());
    });
    Ok(len)
}

/// [`tpm2::crypto::Mlkem::mlkem_encapsulate`]: `ML-KEM.Encaps_internal(ek, m)` with `ml-kem`,
/// after the encapsulation key check of FIPS 203, Section 7.2 (`EncapsulationKey::new`).
pub fn mlkem_encapsulate(
    param_set: TpmiMlkemParms,
    public_key: &[u8],
    entropy: &[u8; MLKEM_ENTROPY_SIZE],
    ciphertext_out: &mut [u8],
    shared_secret_out: &mut [u8; MLKEM_SHARED_SECRET_SIZE],
) -> Result<Option<usize>, CryptoError> {
    let len = param_set.ciphertext_bytes();
    let out = output(ciphertext_out, len)?;
    with_mlkem_params!(param_set, P => {
        let Ok(encoded) = public_key.try_into() else {
            return Ok(None);
        };
        let Ok(ek) = EncapsulationKey::<P>::new(encoded) else {
            return Ok(None);
        };
        let (ct, k) = ek.encapsulate_deterministic(&Array::from(*entropy));
        out.copy_from_slice(&ct);
        shared_secret_out.copy_from_slice(&k);
    });
    Ok(Some(len))
}

/// [`tpm2::crypto::Mlkem::mlkem_decapsulate`]: `ML-KEM.Decaps` with `ml-kem`, on the key expanded
/// from the seed `d || z`.
pub fn mlkem_decapsulate(
    param_set: TpmiMlkemParms,
    seed: &[u8; MLKEM_SEED_SIZE],
    ciphertext: &[u8],
    shared_secret_out: &mut [u8; MLKEM_SHARED_SECRET_SIZE],
) -> Result<bool, CryptoError> {
    with_mlkem_params!(param_set, P => {
        let Ok(ct) = ciphertext.try_into() else {
            return Ok(false);
        };
        let dk = DecapsulationKey::<P>::from_seed(Array::from(*seed));
        shared_secret_out.copy_from_slice(&dk.decapsulate(ct));
    });
    Ok(true)
}

/// [`tpm2::crypto::Mldsa::mldsa_generate_key`]: `ML-DSA.KeyGen_internal(xi)` with `ml-dsa`.
pub fn mldsa_generate_key(
    param_set: TpmiMldsaParms,
    seed: &[u8; MLDSA_SEED_SIZE],
    public_key_out: &mut [u8],
) -> Result<usize, CryptoError> {
    let len = param_set.public_key_bytes();
    let out = output(public_key_out, len)?;
    with_mldsa_params!(param_set, P => {
        let sk = SigningKey::<P>::from_seed(&Array::from(*seed));
        out.copy_from_slice(&sk.verifying_key().encode());
    });
    Ok(len)
}

/// A random number generator that yields the 32-byte signing randomness `rnd` exactly once.
///
/// `ml-dsa` exposes `ML-DSA.Sign_internal` on `mu` only with an RNG
/// ([`ExpandedSigningKey::sign_mu_randomized`]), which draws `rnd` with a single 32-byte
/// `try_fill_bytes`; any other request fails.
struct OneShotRnd<'a>(Option<&'a [u8; MLDSA_RND_SIZE]>);

/// The error of [`OneShotRnd`] for any request other than the single 32-byte fill.
#[derive(Debug)]
struct RndExhausted;

impl core::fmt::Display for RndExhausted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the ML-DSA signing randomness was already used")
    }
}

impl core::error::Error for RndExhausted {}

impl TryRng for OneShotRnd<'_> {
    type Error = RndExhausted;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(RndExhausted)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(RndExhausted)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        match self.0.take() {
            Some(rnd) if dst.len() == rnd.len() => {
                dst.copy_from_slice(rnd);
                Ok(())
            }
            _ => Err(RndExhausted),
        }
    }
}

impl TryCryptoRng for OneShotRnd<'_> {}

/// [`tpm2::crypto::Mldsa::mldsa_sign_mu`]: `ML-DSA.Sign_internal` from line 7 on (external `mu`)
/// with `ml-dsa`, with the signing randomness `rnd`.
pub fn mldsa_sign_mu(
    param_set: TpmiMldsaParms,
    seed: &[u8; MLDSA_SEED_SIZE],
    mu: &[u8; MLDSA_MU_SIZE],
    rnd: &[u8; MLDSA_RND_SIZE],
    signature_out: &mut [u8],
) -> Result<Option<usize>, CryptoError> {
    let len = param_set.signature_bytes();
    let out = output(signature_out, len)?;
    with_mldsa_params!(param_set, P => {
        let sk = ExpandedSigningKey::<P>::from_seed(&Array::from(*seed));
        // `ml-dsa` fails only when its rejection sampling gives up (no signature).
        let Ok(sig) = sk.sign_mu_randomized(&Array::from(*mu), &mut OneShotRnd(Some(rnd))) else {
            return Ok(None);
        };
        out.copy_from_slice(&sig.encode());
    });
    Ok(Some(len))
}

/// [`tpm2::crypto::Mldsa::mldsa_verify_mu`]: `ML-DSA.Verify_internal` from line 8 on (external
/// `mu`) with `ml-dsa`.
pub fn mldsa_verify_mu(
    param_set: TpmiMldsaParms,
    public_key: &[u8],
    mu: &[u8; MLDSA_MU_SIZE],
    signature: &[u8],
) -> Result<bool, CryptoError> {
    with_mldsa_params!(param_set, P => {
        let (Ok(pk), Ok(sig)) = (public_key.try_into(), signature.try_into()) else {
            return Ok(false);
        };
        // `Signature::decode` rejects malformed hints (`sigDecode`, FIPS 204, Algorithm 8
        // lines 2-4) and `z` out of range (line 13).
        let Some(sig) = Signature::<P>::decode(sig) else {
            return Ok(false);
        };
        Ok(VerifyingKey::<P>::decode(pk).verify_mu(&Array::from(*mu), &sig))
    })
}

/// ML-KEM for all three parameter sets (`ml-kem`).
impl tpm2::crypto::Mlkem for RustCryptoProvider {
    fn mlkem_generate_key(
        &self,
        param_set: TpmiMlkemParms,
        seed: &[u8; MLKEM_SEED_SIZE],
        public_key_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        mlkem_generate_key(param_set, seed, public_key_out)
    }

    fn mlkem_encapsulate(
        &self,
        param_set: TpmiMlkemParms,
        public_key: &[u8],
        entropy: &[u8; MLKEM_ENTROPY_SIZE],
        ciphertext_out: &mut [u8],
        shared_secret_out: &mut [u8; MLKEM_SHARED_SECRET_SIZE],
    ) -> Result<Option<usize>, CryptoError> {
        mlkem_encapsulate(
            param_set,
            public_key,
            entropy,
            ciphertext_out,
            shared_secret_out,
        )
    }

    fn mlkem_decapsulate(
        &self,
        param_set: TpmiMlkemParms,
        seed: &[u8; MLKEM_SEED_SIZE],
        ciphertext: &[u8],
        shared_secret_out: &mut [u8; MLKEM_SHARED_SECRET_SIZE],
    ) -> Result<bool, CryptoError> {
        mlkem_decapsulate(param_set, seed, ciphertext, shared_secret_out)
    }
}

/// ML-DSA for all three parameter sets (`ml-dsa`).
impl tpm2::crypto::Mldsa for RustCryptoProvider {
    fn mldsa_generate_key(
        &self,
        param_set: TpmiMldsaParms,
        seed: &[u8; MLDSA_SEED_SIZE],
        public_key_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        mldsa_generate_key(param_set, seed, public_key_out)
    }

    fn mldsa_sign_mu(
        &self,
        param_set: TpmiMldsaParms,
        seed: &[u8; MLDSA_SEED_SIZE],
        mu: &[u8; MLDSA_MU_SIZE],
        rnd: &[u8; MLDSA_RND_SIZE],
        signature_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        mldsa_sign_mu(param_set, seed, mu, rnd, signature_out)
    }

    fn mldsa_verify_mu(
        &self,
        param_set: TpmiMldsaParms,
        public_key: &[u8],
        mu: &[u8; MLDSA_MU_SIZE],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        mldsa_verify_mu(param_set, public_key, mu, signature)
    }
}
