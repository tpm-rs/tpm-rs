#![allow(missing_docs)]
use crate::{ChaChaRng, RngWrapper};
use ml_kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, KeyExport};
use tpm2::crypto::{
    CryptoError,
    backend::{MlkemKey, PrivateKey},
};

macro_rules! impl_mlkem {
    ($keypair:ident, $mlkem:path, $pub_size:literal, $ct_size:literal) => {
        #[allow(missing_docs)]
        pub struct $keypair {
            pub private: DecapsulationKey<$mlkem>,
            pub public: EncapsulationKey<$mlkem>,
            pub seed: [u8; 64],
        }

        impl $keypair {
            fn expand(seed: &[u8; 64]) -> Self {
                let private = DecapsulationKey::<$mlkem>::from_seed((*seed).into());
                let public = private.encapsulation_key().clone();
                Self {
                    private,
                    public,
                    seed: *seed,
                }
            }
        }

        impl PrivateKey<$pub_size, 64, ChaChaRng> for $keypair {
            type PublicKey = EncapsulationKey<$mlkem>;

            fn generate(rng: &mut ChaChaRng, _: ()) -> Result<Self, CryptoError> {
                let mut wrapper = RngWrapper(rng);
                let mut seed = [0u8; 64];
                rand_core::Rng::fill_bytes(&mut wrapper, &mut seed);
                Ok(Self::expand(&seed))
            }

            fn load_public(
                _: (),
                public: &[u8; $pub_size],
            ) -> Result<Option<Self::PublicKey>, CryptoError> {
                Ok(EncapsulationKey::<$mlkem>::new(public.into()).ok())
            }

            fn store_public(
                public: &Self::PublicKey,
                out: &mut [u8; $pub_size],
            ) -> Result<(), CryptoError> {
                out.copy_from_slice(public.to_bytes().as_ref());
                Ok(())
            }

            fn load(public: Self::PublicKey, seed: &[u8; 64]) -> Result<Option<Self>, CryptoError> {
                let private = Self::expand(seed);
                if private.public.to_bytes() != public.to_bytes() {
                    return Ok(None);
                }
                Ok(Some(private))
            }

            fn store(&self, out: &mut [u8; 64]) -> Result<(), CryptoError> {
                out.copy_from_slice(&self.seed);
                Ok(())
            }

            fn as_public(&self) -> &Self::PublicKey {
                &self.public
            }
        }

        impl MlkemKey<$pub_size, $ct_size, ChaChaRng> for $keypair {
            fn encapsulate(
                public: &Self::PublicKey,
                rng: &mut ChaChaRng,
                out_ct: &mut [u8; $ct_size],
                out_ss: &mut [u8; 32],
            ) -> Result<(), CryptoError> {
                let mut wrapper = RngWrapper(rng);
                let (ct, ss) = public.encapsulate_with_rng(&mut wrapper);
                out_ct.copy_from_slice(ct.as_ref());
                out_ss.copy_from_slice(ss.as_ref());
                Ok(())
            }

            fn decapsulate(
                &self,
                ct: &[u8; $ct_size],
                out_ss: &mut [u8; 32],
            ) -> Result<(), CryptoError> {
                let ss = self.private.decapsulate(ct.into());
                out_ss.copy_from_slice(ss.as_ref());
                Ok(())
            }
        }
    };
}

impl_mlkem!(Mlkem512KeyPair, ml_kem::MlKem512, 800, 768);
impl_mlkem!(Mlkem768KeyPair, ml_kem::MlKem768, 1184, 1088);
impl_mlkem!(Mlkem1024KeyPair, ml_kem::MlKem1024, 1568, 1568);
