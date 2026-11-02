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

use tpm2::crypto::{
    CryptoError, CryptoProvider, MLDSA_MU_SIZE, MLDSA_RND_SIZE, MLDSA_SEED_SIZE,
    MLKEM_ENTROPY_SIZE, MLKEM_SEED_SIZE, MLKEM_SHARED_SECRET_SIZE, Rng,
};
use tpm2::errors::TpmRc;
use tpm2::{Alg, TpmiMldsaParms, TpmiMlkemParms};

use crate::handler::{CommandHandler, TransientObject};
use crate::owned::OwnedPublicParmsAndId;
use crate::self_test::kdfa_bits;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;

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

/// Maps a crypto provider failure of an operation on caller-supplied key material: an
/// unsupported parameter set is `TPM_RC_PARMS` (as the reference's `ERROR_EXIT(TPM_RC_PARMS)`
/// when its crypto library fails), an internal failure `TPM_RC_FAILURE`.
fn crypto_rc(error: CryptoError) -> TpmRc {
    match error {
        CryptoError::Unsupported => TpmRc::PARMS.to_rc(),
        CryptoError::Internal => TpmRc::FAILURE,
    }
}

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// The encapsulation key of the ML-KEM key with private seed `seed`
    /// (`CryptoMlkem_Internal_GenerateKeyFromSeed()`), written to the start of `out`. Returns
    /// its length.
    pub(crate) fn mlkem_public_key(
        &self,
        param_set: TpmiMlkemParms,
        seed: &[u8; MLKEM_SEED_SIZE],
        out: &mut [u8],
    ) -> Result<usize, TpmRc> {
        self.crypto()
            .mlkem_generate_key(param_set, seed, out)
            .map_err(crypto_rc)
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
        self.crypto()
            .mldsa_generate_key(param_set, seed, out)
            .map_err(crypto_rc)
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
        self.crypto()
            .mlkem_encapsulate(
                param_set,
                public_key,
                &entropy,
                ciphertext_out,
                shared_secret_out,
            )
            .map_err(crypto_rc)?
            .ok_or(TpmRc::PARMS.to_rc())
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
        if self
            .crypto()
            .mlkem_decapsulate(param_set, &seed, ciphertext, shared_secret_out)
            .map_err(crypto_rc)?
        {
            Ok(())
        } else {
            Err(TpmRc::PARMS.to_rc())
        }
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
        self.crypto()
            .mldsa_sign_mu(param_set, &seed, mu, &rnd, signature_out)
            .map_err(crypto_rc)?
            // No signature (the rejection sampling gave up): `TPM_RC_NO_RESULT`, as in the
            // reference's `CryptoMldsa_SignMu()`.
            .ok_or(TpmRc::NO_RESULT)
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
        self.crypto()
            .mldsa_verify_mu(param_set, public_key, mu, signature)
            .map_err(crypto_rc)
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

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
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
