#![allow(missing_docs)]
use crate::RngWrapper;
use ml_kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, KeyExport};
use tpm2::crypto::{
    CryptoError, Rng,
    backend::{AsymmetricKey, MlkemKey},
};

macro_rules! impl_mlkem {
    ($name:ident, $keypair:ident, $mlkem:path, $pub_size:literal, $ct_size:literal) => {
        #[allow(missing_docs)]
        pub struct $name;

        #[allow(missing_docs)]
        pub struct $keypair {
            pub private: DecapsulationKey<$mlkem>,
            pub public: EncapsulationKey<$mlkem>,
            pub seed: [u8; 64],
        }

        impl $name {
            fn expand(seed: &[u8; 64]) -> $keypair {
                let private = DecapsulationKey::<$mlkem>::from_seed((*seed).into());
                let public = private.encapsulation_key().clone();
                $keypair {
                    private,
                    public,
                    seed: *seed,
                }
            }
        }

        impl AsymmetricKey<$pub_size, 64> for $name {
            type Public = EncapsulationKey<$mlkem>;
            type Private = $keypair;

            fn generate(rng: &mut impl Rng, _: ()) -> Result<Self::Private, CryptoError> {
                let mut wrapper = RngWrapper(rng);
                let mut seed = [0u8; 64];
                rand_core::Rng::fill_bytes(&mut wrapper, &mut seed);
                Ok(Self::expand(&seed))
            }

            fn load_public(
                _: (),
                public: &[u8; $pub_size],
            ) -> Result<Option<Self::Public>, CryptoError> {
                Ok(EncapsulationKey::<$mlkem>::new(public.into()).ok())
            }

            fn store_public(
                public: &Self::Public,
                out: &mut [u8; $pub_size],
            ) -> Result<(), CryptoError> {
                out.copy_from_slice(public.to_bytes().as_ref());
                Ok(())
            }

            fn load_private(
                public: Self::Public,
                seed: &[u8; 64],
            ) -> Result<Option<Self::Private>, CryptoError> {
                let private = Self::expand(seed);
                if private.public.to_bytes() != public.to_bytes() {
                    return Ok(None);
                }
                Ok(Some(private))
            }

            fn store_private(
                private: &Self::Private,
                out: &mut [u8; 64],
            ) -> Result<(), CryptoError> {
                out.copy_from_slice(&private.seed);
                Ok(())
            }

            fn as_public(private: &Self::Private) -> &Self::Public {
                &private.public
            }
        }

        impl MlkemKey<$pub_size, $ct_size> for $name {
            fn encapsulate(
                rng: &mut impl Rng,
                public: &Self::Public,
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
                private: &Self::Private,
                ct: &[u8; $ct_size],
                out_ss: &mut [u8; 32],
            ) -> Result<(), CryptoError> {
                let ss = private.private.decapsulate(ct.into());
                out_ss.copy_from_slice(ss.as_ref());
                Ok(())
            }
        }
    };
}

impl_mlkem!(Mlkem512Wrapper, Mlkem512KeyPair, ml_kem::MlKem512, 800, 768);
impl_mlkem!(
    Mlkem768Wrapper,
    Mlkem768KeyPair,
    ml_kem::MlKem768,
    1184,
    1088
);
impl_mlkem!(
    Mlkem1024Wrapper,
    Mlkem1024KeyPair,
    ml_kem::MlKem1024,
    1568,
    1568
);
