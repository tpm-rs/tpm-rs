//! ML-KEM (FIPS 203) keys, generic over the `ml-kem` parameter set.

use ml_kem::{
    ArraySize, Decapsulate, Encapsulate, FromSeed, Kem, KeyExport, KeySizeUser, TryKeyInit,
    array::sizes::{U32, U64},
};
use tpm2::crypto::{
    CryptoError, Rng,
    backend::{MlkemKey, PrivateKey},
};

use crate::{ChaChaRng, RngWrapper};

/// ML-KEM private key, storing the 64-byte seed and the expanded keys.
pub struct MlkemKeyPair<K: Kem> {
    private: K::DecapsulationKey,
    public: K::EncapsulationKey,
    seed: [u8; 64],
}

impl<K: FromSeed<SeedSize = U64>> MlkemKeyPair<K> {
    fn expand(seed: &[u8; 64]) -> Self {
        let (private, public) = K::from_seed(&(*seed).into());
        Self {
            private,
            public,
            seed: *seed,
        }
    }
}

impl<K, const PUB_SIZE: usize> PrivateKey<PUB_SIZE, 64, ChaChaRng> for MlkemKeyPair<K>
where
    K: FromSeed<SeedSize = U64>,
    <K::EncapsulationKey as KeySizeUser>::KeySize: ArraySize<ArrayType<u8> = [u8; PUB_SIZE]>,
{
    type PublicKey = K::EncapsulationKey;

    fn generate(rng: &mut ChaChaRng, _: ()) -> Result<Self, CryptoError> {
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed)?;
        Ok(Self::expand(&seed))
    }

    fn load_public(_: (), public: &[u8; PUB_SIZE]) -> Result<Option<Self::PublicKey>, CryptoError> {
        Ok(K::EncapsulationKey::new(public.into()).ok())
    }

    fn store_public(public: &Self::PublicKey, out: &mut [u8; PUB_SIZE]) -> Result<(), CryptoError> {
        out.copy_from_slice(&public.to_bytes());
        Ok(())
    }

    fn load(public: Self::PublicKey, seed: &[u8; 64]) -> Result<Option<Self>, CryptoError> {
        let private = Self::expand(seed);
        Ok((private.public == public).then_some(private))
    }

    fn store(&self, out: &mut [u8; 64]) -> Result<(), CryptoError> {
        out.copy_from_slice(&self.seed);
        Ok(())
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.public
    }
}

impl<K, const PUB_SIZE: usize, const CT_SIZE: usize> MlkemKey<PUB_SIZE, CT_SIZE, ChaChaRng>
    for MlkemKeyPair<K>
where
    K: FromSeed<SeedSize = U64> + Kem<SharedKeySize = U32>,
    K::DecapsulationKey: Decapsulate,
    K::CiphertextSize: ArraySize<ArrayType<u8> = [u8; CT_SIZE]>,
    <K::EncapsulationKey as KeySizeUser>::KeySize: ArraySize<ArrayType<u8> = [u8; PUB_SIZE]>,
{
    fn encapsulate(
        public: &Self::PublicKey,
        rng: &mut ChaChaRng,
        out_ct: &mut [u8; CT_SIZE],
        out_ss: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        let (ct, ss) = public.encapsulate_with_rng(&mut RngWrapper(rng));
        *out_ct = ct.into();
        *out_ss = ss.into();
        Ok(())
    }

    fn decapsulate(&self, ct: &[u8; CT_SIZE], out_ss: &mut [u8; 32]) -> Result<(), CryptoError> {
        *out_ss = self.private.decapsulate(ct.into()).into();
        Ok(())
    }
}
