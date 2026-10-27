//! ML-DSA (FIPS 204) keys, generic over the `ml-dsa` parameter set.

use ml_dsa::{EncodedVerifyingKey, MlDsaParams, Signature, SigningKey, VerifyingKey};
use shake::{ExtendableOutput, Shake256, Update, XofReader};

use tpm2::TpmtHa;
use tpm2::crypto::{
    CryptoError, Rng,
    backend::{MldsaKey, PrivateKey},
};

use crate::{ChaChaRng, RngWrapper};

fn der_oid_for_hash(alg: tpm2::TpmiAlgHash) -> &'static [u8] {
    match alg {
        tpm2::TpmiAlgHash::Sha1 => &[0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a],
        tpm2::TpmiAlgHash::Sha256 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ],
        tpm2::TpmiAlgHash::Sha384 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        ],
        tpm2::TpmiAlgHash::Sha512 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        ],
        tpm2::TpmiAlgHash::Sm3_256 => &[0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x11],
        tpm2::TpmiAlgHash::Sha3_256 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
        ],
        tpm2::TpmiAlgHash::Sha3_384 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09,
        ],
        tpm2::TpmiAlgHash::Sha3_512 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a,
        ],
    }
}

fn compute_mu(
    public: &[u8],
    domain: u8,
    context: &[u8],
    parts: &[&[u8]],
) -> Result<[u8; 64], CryptoError> {
    let ctx_len = u8::try_from(context.len()).map_err(|_| CryptoError::Internal)?;
    let mut tr = [0u8; 64];
    let mut h_tr = Shake256::default();
    h_tr.update(public);
    h_tr.finalize_xof().read(&mut tr);

    let mut h_mu = Shake256::default();
    h_mu.update(&tr);
    h_mu.update(&[domain, ctx_len]);
    h_mu.update(context);
    for part in parts {
        h_mu.update(part);
    }
    let mut mu = [0u8; 64];
    h_mu.finalize_xof().read(&mut mu);
    Ok(mu)
}

/// ML-DSA private key, storing only the 32-byte seed and the encoded public
/// key. The expanded keys are recomputed (on the stack) for each operation.
pub struct MldsaKeyPair<P: MlDsaParams> {
    seed: [u8; 32],
    public: EncodedVerifyingKey<P>,
}

impl<P: MlDsaParams> MldsaKeyPair<P> {
    #[inline(never)]
    fn derive_public(seed: &[u8; 32]) -> EncodedVerifyingKey<P> {
        let sk = SigningKey::<P>::from_seed(seed.into());
        sk.expanded_key().verifying_key().encode()
    }

    #[inline(never)]
    fn sign_mu_inner(
        rng: &mut ChaChaRng,
        seed: &[u8; 32],
        mu: &[u8; 64],
        out_sig: &mut [u8],
    ) -> Result<(), CryptoError> {
        let sk = SigningKey::<P>::from_seed(seed.into());
        let sig = sk
            .expanded_key()
            .sign_mu_randomized(mu.into(), &mut RngWrapper(rng))
            .map_err(|_| CryptoError::Internal)?;
        out_sig.copy_from_slice(&sig.encode());
        Ok(())
    }

    #[inline(never)]
    fn verify_mu_inner(public: &EncodedVerifyingKey<P>, mu: &[u8; 64], sig: &[u8]) -> bool {
        let Some(sig) = sig.try_into().ok().and_then(Signature::<P>::decode) else {
            return false;
        };
        VerifyingKey::<P>::decode(public).verify_mu(mu.into(), &sig)
    }
}

impl<P, const PUB_SIZE: usize> PrivateKey<PUB_SIZE, 32, ChaChaRng> for MldsaKeyPair<P>
where
    P: MlDsaParams,
    P::VerifyingKeySize: ml_dsa::common::array::ArraySize<ArrayType<u8> = [u8; PUB_SIZE]>,
{
    type PublicKey = EncodedVerifyingKey<P>;

    fn generate(rng: &mut ChaChaRng, _: ()) -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed)?;
        let public = Self::derive_public(&seed);
        Ok(Self { seed, public })
    }

    fn load_public(_: (), public: &[u8; PUB_SIZE]) -> Result<Option<Self::PublicKey>, CryptoError> {
        Ok(Some((*public).into()))
    }

    fn store_public(public: &Self::PublicKey, out: &mut [u8; PUB_SIZE]) -> Result<(), CryptoError> {
        out.copy_from_slice(public);
        Ok(())
    }

    fn load(public: Self::PublicKey, seed: &[u8; 32]) -> Result<Option<Self>, CryptoError> {
        if Self::derive_public(seed) != public {
            return Ok(None);
        }
        Ok(Some(Self {
            seed: *seed,
            public,
        }))
    }

    fn store(&self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        out.copy_from_slice(&self.seed);
        Ok(())
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.public
    }
}

impl<P, const PUB_SIZE: usize, const SIG_SIZE: usize> MldsaKey<PUB_SIZE, SIG_SIZE, ChaChaRng>
    for MldsaKeyPair<P>
where
    P: MlDsaParams,
    P::VerifyingKeySize: ml_dsa::common::array::ArraySize<ArrayType<u8> = [u8; PUB_SIZE]>,
    P::SignatureSize: ml_dsa::common::array::ArraySize<ArrayType<u8> = [u8; SIG_SIZE]>,
{
    fn sign_message(
        &self,
        rng: &mut ChaChaRng,
        context: &[u8],
        msg: &[&[u8]],
        out_sig: &mut [u8; SIG_SIZE],
    ) -> Result<(), CryptoError> {
        let mu = compute_mu(&self.public, 0x00, context, msg)?;
        self.sign_mu(rng, &mu, out_sig)
    }

    fn verify_message(
        public: &Self::PublicKey,
        context: &[u8],
        msg: &[&[u8]],
        sig: &[u8; SIG_SIZE],
    ) -> Result<bool, CryptoError> {
        let mu = compute_mu(public, 0x00, context, msg)?;
        Self::verify_mu(public, &mu, sig)
    }

    fn sign_mu(
        &self,
        rng: &mut ChaChaRng,
        mu: &[u8; 64],
        out_sig: &mut [u8; SIG_SIZE],
    ) -> Result<(), CryptoError> {
        Self::sign_mu_inner(rng, &self.seed, mu, out_sig)
    }

    fn verify_mu(
        public: &Self::PublicKey,
        mu: &[u8; 64],
        sig: &[u8; SIG_SIZE],
    ) -> Result<bool, CryptoError> {
        Ok(Self::verify_mu_inner(public, mu, sig))
    }

    fn sign_prehash(
        &self,
        rng: &mut ChaChaRng,
        context: &[u8],
        digest: TpmtHa<'_>,
        out_sig: &mut [u8; SIG_SIZE],
    ) -> Result<(), CryptoError> {
        let der_oid = der_oid_for_hash(digest.hash_alg());
        let mu = compute_mu(&self.public, 0x01, context, &[der_oid, digest.digest()])?;
        self.sign_mu(rng, &mu, out_sig)
    }

    fn verify_prehash(
        public: &Self::PublicKey,
        context: &[u8],
        digest: TpmtHa<'_>,
        sig: &[u8; SIG_SIZE],
    ) -> Result<bool, CryptoError> {
        let der_oid = der_oid_for_hash(digest.hash_alg());
        let mu = compute_mu(public, 0x01, context, &[der_oid, digest.digest()])?;
        Self::verify_mu(public, &mu, sig)
    }
}
