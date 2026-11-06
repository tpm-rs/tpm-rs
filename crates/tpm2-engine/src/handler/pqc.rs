//! ML-KEM (FIPS 203) and ML-DSA (FIPS 204) operations of the command handlers (`mlkem`,
//! `mldsa` and `hash_mldsa` features).
//!
//! The private keys are seeds (TPM 2.0 Part 1, "ML-KEM Key Representation and Generation" and
//! "ML-DSA Key Representation and Generation"); [`TransientObject::private`] holds the seed. The
//! randomness of encapsulation and signing is drawn from the TPM's random number generator, and
//! every operation first runs the algorithm's self test if it still needs one, at the points
//! where the TCG reference implementation (version 185, `CryptoMlkem_*()`/`CryptoMldsa_*()`)
//! calls `TPM_DO_SELF_TEST()` and `CryptoRand_DRBG_Generate()`, so that the values drawn are the
//! same.
//!
//! The ML-KEM Labeled KEM of restricted decryption keys (Part 1, "ML-KEM Labeled KEM") is
//! [`CommandHandler::mlkem_secret_encrypt`] / [`CommandHandler::mlkem_secret_decrypt`].

#![cfg_attr(not(any(feature = "mlkem", feature = "mldsa")), allow(dead_code))]

use crate::Platform;
use tpm2::crypto::{Crypto, CryptoError};
#[cfg(feature = "mldsa")]
use tpm2::crypto::{MldsaPrivateKey, MldsaPublicKey};
#[cfg(feature = "mlkem")]
use tpm2::crypto::{MlkemPrivateKey, MlkemPublicKey};
use tpm2::errors::TpmRc;
use tpm2::{Alg, TpmiMldsaParms, TpmiMlkemParms};

use crate::handler::{CommandHandler, TransientObject};
use crate::owned::OwnedPublicParmsAndId;
use crate::self_test::kdfa_bits;

/// The parameter set and encapsulation key of an ML-KEM key, or `None` for another type.
pub(crate) fn mlkem_key(object: &TransientObject) -> Option<(TpmiMlkemParms, &[u8])> {
    match &object.public.parms_and_id {
        OwnedPublicParmsAndId::Mlkem(parms, unique) => {
            Some((parms.parameter_set, unique.get_buffer()))
        }
        _ => None,
    }
}

/// The parameter set and verification key of an ML-DSA or HashML-DSA key, or `None` for another
/// type.
pub(crate) fn mldsa_key(object: &TransientObject) -> Option<(TpmiMldsaParms, &[u8])> {
    match &object.public.parms_and_id {
        OwnedPublicParmsAndId::Mldsa(parms, unique) => {
            Some((parms.parameter_set, unique.get_buffer()))
        }
        OwnedPublicParmsAndId::HashMldsa(parms, unique) => {
            Some((parms.parameter_set, unique.get_buffer()))
        }
        _ => None,
    }
}

/// The private seed of `object` as an array of the seed size `N`, or `TPM_RC_FAILURE` if the
/// object has no seed of that size (e.g. a public-only object).
fn seed_of<const N: usize>(object: &TransientObject) -> Result<[u8; N], TpmRc> {
    object.private[..object.private_len]
        .try_into()
        .map_err(|_| TpmRc::FAILURE)
}

/// The size of the message representative `mu` of ML-DSA.
const MLDSA_MU_SIZE: usize = TpmiMldsaParms::MU_BYTES;
/// The size of the private seed of an ML-DSA key.
const MLDSA_SEED_SIZE: usize = TpmiMldsaParms::PRIV_KEY_BYTES;
/// The size of the signing randomness `rnd` of ML-DSA.
const MLDSA_RND_SIZE: usize = 32;
/// The size of the private seed of an ML-KEM key.
const MLKEM_SEED_SIZE: usize = TpmiMlkemParms::PRIV_KEY_BYTES;
/// The size of the encapsulation randomness `m` of ML-KEM.
const MLKEM_ENTROPY_SIZE: usize = 32;
/// The size of the shared secret of ML-KEM.
const MLKEM_SHARED_SECRET_SIZE: usize = TpmiMlkemParms::SHARED_SECRET_BYTES;

/// The encapsulation key of the ML-KEM key with parameter set `param_set` and private seed
/// `seed` ([`MlkemPrivateKey::expand`]), written to the start of `out`. Returns its length.
#[cfg(feature = "mlkem")]
fn mlkem_expand_public<C: Crypto>(
    param_set: TpmiMlkemParms,
    seed: &[u8; MLKEM_SEED_SIZE],
    out: &mut [u8],
) -> Result<usize, TpmRc> {
    let key = mlkem_private_key::<C>(param_set, seed)?;
    let mut public = [0u8; TpmiMlkemParms::MAX_PUB_KEY_BYTES];
    let public = key.public(&mut public).map_err(crypto_rc)?;
    copy_out(public.as_slice(), out)
}

/// `ML-KEM.Encaps_internal(ek, m)` ([`MlkemPublicKey::encapsulate_internal`]) to the encapsulation
/// key `public_key` of parameter set `param_set` with the randomness `entropy`. Writes the
/// ciphertext to the start of `ciphertext_out` and returns its length; an invalid encapsulation
/// key is `TPM_RC_PARMS`.
#[cfg(feature = "mlkem")]
fn mlkem_encapsulate_with<C: Crypto>(
    param_set: TpmiMlkemParms,
    public_key: &[u8],
    entropy: &[u8; MLKEM_ENTROPY_SIZE],
    ciphertext_out: &mut [u8],
    shared_secret_out: &mut [u8; MLKEM_SHARED_SECRET_SIZE],
) -> Result<usize, TpmRc> {
    let public_key = tpm2::Tpm2bPublicKeyMlkem::new(public_key).ok_or(TpmRc::PARMS.to_rc())?;
    let public_key = MlkemPublicKey::<C>::load(param_set, public_key)
        .map_err(crypto_rc)?
        .ok_or(TpmRc::PARMS.to_rc())?;
    let (ciphertext, _) = public_key
        .encapsulate_internal(entropy, ciphertext_out, shared_secret_out)
        .map_err(crypto_rc)?;
    Ok(ciphertext.as_slice().len())
}

/// `ML-KEM.Decaps` ([`MlkemPrivateKey::decapsulate`]) of `ciphertext` with the ML-KEM key of
/// parameter set `param_set` and private seed `seed`; a ciphertext of the wrong size is
/// `TPM_RC_PARMS`.
#[cfg(feature = "mlkem")]
fn mlkem_decapsulate_with<C: Crypto>(
    param_set: TpmiMlkemParms,
    seed: &[u8; MLKEM_SEED_SIZE],
    ciphertext: &[u8],
    shared_secret_out: &mut [u8; MLKEM_SHARED_SECRET_SIZE],
) -> Result<(), TpmRc> {
    let ciphertext = tpm2::Tpm2bKemCiphertext::new(ciphertext).ok_or(TpmRc::PARMS.to_rc())?;
    match mlkem_private_key::<C>(param_set, seed)?
        .decapsulate(ciphertext, shared_secret_out)
        .map_err(crypto_rc)?
    {
        Some(_) => Ok(()),
        None => Err(TpmRc::PARMS.to_rc()),
    }
}

/// The ML-KEM key with parameter set `param_set` expanded from the private seed `seed`.
#[cfg(feature = "mlkem")]
fn mlkem_private_key<C: Crypto>(
    param_set: TpmiMlkemParms,
    seed: &[u8; MLKEM_SEED_SIZE],
) -> Result<MlkemPrivateKey<C>, TpmRc> {
    let seed = tpm2::Tpm2bPrivateKeyMlkem::new(seed).ok_or(TpmRc::FAILURE)?;
    MlkemPrivateKey::expand(param_set, seed)
        .map_err(crypto_rc)?
        .ok_or(TpmRc::FAILURE)
}

/// The verification key of the ML-DSA key with parameter set `param_set` and private seed
/// `seed` ([`MldsaPrivateKey::expand`]), written to the start of `out`. Returns its length.
#[cfg(feature = "mldsa")]
fn mldsa_expand_public<C: Crypto>(
    param_set: TpmiMldsaParms,
    seed: &[u8; MLDSA_SEED_SIZE],
    out: &mut [u8],
) -> Result<usize, TpmRc> {
    let key = mldsa_private_key::<C>(param_set, seed)?;
    let mut public = [0u8; TpmiMldsaParms::MAX_PUB_KEY_BYTES];
    let public = key.public(&mut public).map_err(crypto_rc)?;
    copy_out(public.as_slice(), out)
}

/// The ML-DSA signature of the message representative `mu` with the key of parameter set
/// `param_set` and private seed `seed`, and the signing randomness `rnd`
/// ([`MldsaPrivateKey::sign_mu_internal`]). Writes the signature to the start of
/// `signature_out` and returns its length.
#[cfg(feature = "mldsa")]
fn mldsa_sign_mu_with<C: Crypto>(
    param_set: TpmiMldsaParms,
    seed: &[u8; MLDSA_SEED_SIZE],
    mu: &[u8; MLDSA_MU_SIZE],
    rnd: &[u8; MLDSA_RND_SIZE],
    signature_out: &mut [u8],
) -> Result<usize, TpmRc> {
    let mut signature = [0u8; tpm2::crypto::MAX_SIGNATURE_BYTES];
    let signature = mldsa_private_key::<C>(param_set, seed)?
        .sign_mu_internal(rnd, mu, &mut signature)
        .map_err(crypto_rc)?;
    let tpm2::TpmtSignature::Mldsa(signature) = signature else {
        return Err(TpmRc::FAILURE);
    };
    copy_out(signature.as_slice(), signature_out)
}

/// Whether `signature` is an ML-DSA signature of the message representative `mu` with the
/// verification key `public_key` of parameter set `param_set` ([`MldsaPublicKey::verify`]). A
/// verification key or signature of the wrong size does not verify.
#[cfg(feature = "mldsa")]
fn mldsa_verify_mu_with<C: Crypto>(
    param_set: TpmiMldsaParms,
    public_key: &[u8],
    mu: &[u8; MLDSA_MU_SIZE],
    signature: &[u8],
) -> Result<bool, TpmRc> {
    let (Some(public_key), Some(signature)) = (
        tpm2::Tpm2bPublicKeyMldsa::new(public_key),
        tpm2::Tpm2bSignatureMldsa::new(signature),
    ) else {
        return Ok(false);
    };
    match MldsaPublicKey::<C>::load(param_set, public_key).map_err(crypto_rc)? {
        Some(public_key) => public_key
            .verify(&[], mu, tpm2::TpmtSignature::Mldsa(signature))
            .map_err(crypto_rc),
        None => Ok(false),
    }
}

/// The ML-DSA key with parameter set `param_set` expanded from the private seed `seed`.
#[cfg(feature = "mldsa")]
fn mldsa_private_key<C: Crypto>(
    param_set: TpmiMldsaParms,
    seed: &[u8; MLDSA_SEED_SIZE],
) -> Result<MldsaPrivateKey<C>, TpmRc> {
    let seed = tpm2::Tpm2bPrivateKeyMldsa::new(seed).ok_or(TpmRc::FAILURE)?;
    MldsaPrivateKey::expand(param_set, seed)
        .map_err(crypto_rc)?
        .ok_or(TpmRc::FAILURE)
}

/// Without the `mlkem` feature, ML-KEM is not supported by the crypto backend.
#[cfg(not(feature = "mlkem"))]
#[allow(clippy::extra_unused_type_parameters)] // The signature of the `mlkem` version.
fn mlkem_expand_public<C: Crypto>(
    _: TpmiMlkemParms,
    _: &[u8; MLKEM_SEED_SIZE],
    _: &mut [u8],
) -> Result<usize, TpmRc> {
    Err(crypto_rc(CryptoError::Unsupported))
}

/// Without the `mlkem` feature, ML-KEM is not supported by the crypto backend.
#[cfg(not(feature = "mlkem"))]
#[allow(clippy::extra_unused_type_parameters)] // The signature of the `mlkem` version.
fn mlkem_encapsulate_with<C: Crypto>(
    _: TpmiMlkemParms,
    _: &[u8],
    _: &[u8; MLKEM_ENTROPY_SIZE],
    _: &mut [u8],
    _: &mut [u8; MLKEM_SHARED_SECRET_SIZE],
) -> Result<usize, TpmRc> {
    Err(crypto_rc(CryptoError::Unsupported))
}

/// Without the `mlkem` feature, ML-KEM is not supported by the crypto backend.
#[cfg(not(feature = "mlkem"))]
#[allow(clippy::extra_unused_type_parameters)] // The signature of the `mlkem` version.
fn mlkem_decapsulate_with<C: Crypto>(
    _: TpmiMlkemParms,
    _: &[u8; MLKEM_SEED_SIZE],
    _: &[u8],
    _: &mut [u8; MLKEM_SHARED_SECRET_SIZE],
) -> Result<(), TpmRc> {
    Err(crypto_rc(CryptoError::Unsupported))
}

/// Without the `mldsa` feature, ML-DSA is not supported by the crypto backend.
#[cfg(not(feature = "mldsa"))]
#[allow(clippy::extra_unused_type_parameters)] // The signature of the `mldsa` version.
fn mldsa_expand_public<C: Crypto>(
    _: TpmiMldsaParms,
    _: &[u8; MLDSA_SEED_SIZE],
    _: &mut [u8],
) -> Result<usize, TpmRc> {
    Err(crypto_rc(CryptoError::Unsupported))
}

/// Without the `mldsa` feature, ML-DSA is not supported by the crypto backend.
#[cfg(not(feature = "mldsa"))]
#[allow(clippy::extra_unused_type_parameters)] // The signature of the `mldsa` version.
fn mldsa_sign_mu_with<C: Crypto>(
    _: TpmiMldsaParms,
    _: &[u8; MLDSA_SEED_SIZE],
    _: &[u8; MLDSA_MU_SIZE],
    _: &[u8; MLDSA_RND_SIZE],
    _: &mut [u8],
) -> Result<usize, TpmRc> {
    Err(crypto_rc(CryptoError::Unsupported))
}

/// Without the `mldsa` feature, ML-DSA is not supported by the crypto backend.
#[cfg(not(feature = "mldsa"))]
#[allow(clippy::extra_unused_type_parameters)] // The signature of the `mldsa` version.
fn mldsa_verify_mu_with<C: Crypto>(
    _: TpmiMldsaParms,
    _: &[u8],
    _: &[u8; MLDSA_MU_SIZE],
    _: &[u8],
) -> Result<bool, TpmRc> {
    Err(crypto_rc(CryptoError::Unsupported))
}

/// Copies `src` to the start of `out` and returns its length (`TPM_RC_FAILURE` if `out` is too
/// small).
fn copy_out(src: &[u8], out: &mut [u8]) -> Result<usize, TpmRc> {
    out.get_mut(..src.len())
        .ok_or(TpmRc::FAILURE)?
        .copy_from_slice(src);
    Ok(src.len())
}

/// Maps a crypto backend failure of an operation on caller-supplied key material: an
/// unsupported parameter set is `TPM_RC_PARMS` (as the reference's `ERROR_EXIT(TPM_RC_PARMS)`
/// when its crypto library fails), an internal failure `TPM_RC_FAILURE`.
fn crypto_rc(error: CryptoError) -> TpmRc {
    match error {
        CryptoError::Unsupported => TpmRc::PARMS.to_rc(),
        CryptoError::Internal => TpmRc::FAILURE,
    }
}

impl<'b, C: Crypto, P: Platform<Crypto = C>> CommandHandler<'b, P> {
    /// The encapsulation key of the ML-KEM key with private seed `seed`
    /// (`CryptoMlkem_Internal_GenerateKeyFromSeed()`), written to the start of `out`. Returns
    /// its length.
    pub(crate) fn mlkem_public_key(
        &self,
        param_set: TpmiMlkemParms,
        seed: &[u8; MLKEM_SEED_SIZE],
        out: &mut [u8],
    ) -> Result<usize, TpmRc> {
        mlkem_expand_public::<C>(param_set, seed, out)
    }

    /// The verification key of the ML-DSA key with private seed `seed`
    /// (`CryptoMldsa_Internal_GenerateKeyFromSeed()`), written to the start of `out`. Returns
    /// its length.
    pub(crate) fn mldsa_public_key(
        &self,
        param_set: TpmiMldsaParms,
        seed: &[u8; MLDSA_SEED_SIZE],
        out: &mut [u8],
    ) -> Result<usize, TpmRc> {
        mldsa_expand_public::<C>(param_set, seed, out)
    }

    /// `CryptoMlkem_Encapsulate()` with the TPM's DRBG: tests ML-KEM if needed, draws the 32
    /// bytes of randomness, and encapsulates a shared secret to `public_key`. Writes the
    /// ciphertext to the start of `ciphertext_out` and returns its length.
    ///
    /// An encapsulation key that is not valid for `param_set` (wrong size, or failing the
    /// FIPS 203 modulus check) is `TPM_RC_PARMS` without a position, as in the reference (whose
    /// crypto library refuses to import such a key).
    pub(crate) fn mlkem_encapsulate(
        &mut self,
        param_set: TpmiMlkemParms,
        public_key: &[u8],
        ciphertext_out: &mut [u8],
        shared_secret_out: &mut [u8; MLKEM_SHARED_SECRET_SIZE],
    ) -> Result<usize, TpmRc> {
        self.do_self_test(Alg::MLKEM)?;
        let mut entropy = [0u8; MLKEM_ENTROPY_SIZE];
        self.context.random_crypto(&mut entropy)?;
        mlkem_encapsulate_with::<C>(
            param_set,
            public_key,
            &entropy,
            ciphertext_out,
            shared_secret_out,
        )
    }

    /// `CryptoMlkem_Decapsulate()`: tests ML-KEM if needed and decapsulates `ciphertext` with the
    /// ML-KEM key of `key`. A ciphertext that does not have the ciphertext size of the key's
    /// parameter set is `TPM_RC_PARMS` without a position, as in the reference.
    pub(crate) fn mlkem_decapsulate(
        &mut self,
        key: &TransientObject,
        ciphertext: &[u8],
        shared_secret_out: &mut [u8; MLKEM_SHARED_SECRET_SIZE],
    ) -> Result<(), TpmRc> {
        let (param_set, _) = mlkem_key(key).ok_or(TpmRc::TYPE.to_rc())?;
        self.do_self_test(Alg::MLKEM)?;
        let seed: [u8; MLKEM_SEED_SIZE] = seed_of(key)?;
        mlkem_decapsulate_with::<C>(param_set, &seed, ciphertext, shared_secret_out)
    }

    /// The `seed` of the ML-KEM Labeled KEM (TPM 2.0 Part 1, "ML-KEM Labeled KEM"):
    /// `KDFa(nameAlg, K, label, ciphertext, publicKey, digestBits)`, written to the start of
    /// `seed_out`. Returns its length (the `nameAlg` digest size).
    fn mlkem_labeled_seed(
        &self,
        key: &TransientObject,
        label: &[u8],
        shared_secret: &[u8],
        ciphertext: &[u8],
        seed_out: &mut [u8; 64],
    ) -> Result<usize, TpmRc> {
        let name_alg = key.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
        let (_, public_key) = mlkem_key(key).ok_or(TpmRc::TYPE.to_rc())?;
        let digest_size = name_alg.digest_size();
        kdfa_bits(
            &self.crypto(),
            name_alg,
            shared_secret,
            label,
            ciphertext,
            public_key,
            (digest_size * 8) as u32,
            seed_out,
        )
        .map_err(|_| TpmRc::FAILURE)?;
        Ok(digest_size)
    }

    /// The labeled encapsulation of the ML-KEM Labeled KEM (C `CryptoCommon_SecretEncrypt()`
    /// for an ML-KEM key): encapsulates to `key` and derives the seed with `label` (e.g.
    /// `DUPLICATE`, `IDENTITY` or `SECRET`). Writes the seed to `seed_out` and the ciphertext
    /// (the encrypted secret) to `secret_out`, and returns `(seed length, ciphertext length)`.
    pub(crate) fn mlkem_secret_encrypt(
        &mut self,
        key: &TransientObject,
        label: &[u8],
        seed_out: &mut [u8; 64],
        secret_out: &mut [u8],
    ) -> Result<(usize, usize), TpmRc> {
        let (param_set, public_key) = mlkem_key(key).ok_or(TpmRc::TYPE.to_rc())?;
        let mut shared_secret = [0u8; MLKEM_SHARED_SECRET_SIZE];
        let ciphertext_len =
            self.mlkem_encapsulate(param_set, public_key, secret_out, &mut shared_secret)?;
        let seed_len = self.mlkem_labeled_seed(
            key,
            label,
            &shared_secret,
            &secret_out[..ciphertext_len],
            seed_out,
        )?;
        Ok((seed_len, ciphertext_len))
    }

    /// The labeled decapsulation of the ML-KEM Labeled KEM (C `CryptoCommon_SecretDecrypt()`
    /// for an ML-KEM key): decapsulates `secret` with `key` and derives the seed with `label`.
    /// Writes the seed to `seed_out` and returns its length. A `secret` larger than any
    /// ML-KEM ciphertext is `TPM_RC_VALUE`, one of the wrong size for the key `TPM_RC_PARMS`
    /// (both without a position, as in the reference).
    pub(crate) fn mlkem_secret_decrypt(
        &mut self,
        key: &TransientObject,
        label: &[u8],
        secret: &[u8],
        seed_out: &mut [u8; 64],
    ) -> Result<usize, TpmRc> {
        if secret.len() > tpm2::TPM2_MAX_MLKEM_CT_SIZE {
            return Err(TpmRc::VALUE.to_rc());
        }
        let mut shared_secret = [0u8; MLKEM_SHARED_SECRET_SIZE];
        self.mlkem_decapsulate(key, secret, &mut shared_secret)?;
        self.mlkem_labeled_seed(key, label, &shared_secret, secret, seed_out)
    }

    /// `CryptoMldsa_SignMu()`: tests ML-DSA if needed, draws the 32 bytes of signing randomness
    /// from the TPM's DRBG and signs the message representative `mu` with the ML-DSA key of
    /// `key`. Writes the signature to the start of `signature_out` and returns its length.
    pub(crate) fn mldsa_sign_mu(
        &mut self,
        key: &TransientObject,
        mu: &[u8; MLDSA_MU_SIZE],
        signature_out: &mut [u8],
    ) -> Result<usize, TpmRc> {
        let (param_set, _) = mldsa_key(key).ok_or(TpmRc::TYPE.to_rc())?;
        self.do_self_test(Alg::MLDSA)?;
        let seed: [u8; MLDSA_SEED_SIZE] = seed_of(key)?;
        let mut rnd = [0u8; MLDSA_RND_SIZE];
        self.context.random_crypto(&mut rnd)?;
        mldsa_sign_mu_with::<C>(param_set, &seed, mu, &rnd, signature_out)
    }

    /// `CryptoMldsa_VerifyMu()`: tests ML-DSA if needed and verifies `signature` over the
    /// message representative `mu` with the verification key of `key`.
    pub(crate) fn mldsa_verify_mu(
        &mut self,
        key: &TransientObject,
        mu: &[u8; MLDSA_MU_SIZE],
        signature: &[u8],
    ) -> Result<bool, TpmRc> {
        let (param_set, _) = mldsa_key(key).ok_or(TpmRc::TYPE.to_rc())?;
        self.do_self_test(Alg::MLDSA)?;
        let (_, public_key) = mldsa_key(key).ok_or(TpmRc::TYPE.to_rc())?;
        mldsa_verify_mu_with::<C>(param_set, public_key, mu, signature)
    }

    /// A pure ML-DSA signature of the message made of `parts` with an empty context (FIPS 204,
    /// Algorithm 2), as the reference's attestation commands sign an attestation block
    /// (`SignAttestMessageMldsa()`: a signing sequence with an empty context). Writes the
    /// signature to the start of `signature_out` and returns its length.
    #[cfg(feature = "mldsa")]
    pub(crate) fn mldsa_sign_message(
        &mut self,
        key: &TransientObject,
        parts: &[&[u8]],
        signature_out: &mut [u8],
    ) -> Result<usize, TpmRc> {
        let (_, public_key) = mldsa_key(key).ok_or(TpmRc::TYPE.to_rc())?;
        // `CryptoMldsa_SignSequenceStart()` tests ML-DSA before the message is absorbed.
        self.do_self_test(Alg::MLDSA)?;
        let mut shake = crate::mldsa::pure_mu_start(public_key, &[]).ok_or(TpmRc::FAILURE)?;
        for part in parts {
            shake.update(part);
        }
        let mut mu = [0u8; MLDSA_MU_SIZE];
        shake.finalize_into(&mut mu);
        self.mldsa_sign_mu(key, &mu, signature_out)
    }

    /// Verifies a pure ML-DSA `signature` of the message made of `parts` with an empty context
    /// (FIPS 204, Algorithm 3), as the reference's `TPM2_PolicySigned()` verifies an ML-DSA
    /// authorization (a verification sequence with an empty context).
    #[cfg(feature = "mldsa")]
    pub(crate) fn mldsa_verify_message(
        &mut self,
        key: &TransientObject,
        parts: &[&[u8]],
        signature: &[u8],
    ) -> Result<bool, TpmRc> {
        let (_, public_key) = mldsa_key(key).ok_or(TpmRc::TYPE.to_rc())?;
        // `CryptoMldsa_VerifySequenceStart()` tests ML-DSA before the message is absorbed.
        self.do_self_test(Alg::MLDSA)?;
        let mut shake = crate::mldsa::pure_mu_start(public_key, &[]).ok_or(TpmRc::FAILURE)?;
        for part in parts {
            shake.update(part);
        }
        let mut mu = [0u8; MLDSA_MU_SIZE];
        shake.finalize_into(&mut mu);
        self.mldsa_verify_mu(key, &mu, signature)
    }
}

impl<'b, C: Crypto, P: Platform<Crypto = C>> CommandHandler<'b, P> {
    /// The self test of `CryptoMlkem_GenerateKey()`/`CryptoMldsa_GenerateKey()` before the key
    /// of `parms_and_id` is generated (nothing for the other types).
    pub(crate) fn pqc_key_generation_self_test(
        &mut self,
        parms_and_id: &OwnedPublicParmsAndId,
    ) -> Result<(), TpmRc> {
        match parms_and_id {
            OwnedPublicParmsAndId::Mlkem(..) => self.do_self_test(Alg::MLKEM),
            OwnedPublicParmsAndId::Mldsa(..) | OwnedPublicParmsAndId::HashMldsa(..) => {
                self.do_self_test(Alg::MLDSA)
            }
            _ => Ok(()),
        }
    }
}
