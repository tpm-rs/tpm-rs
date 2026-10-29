#![allow(missing_docs)]
use crate::RngWrapper;
use tpm2::crypto::{
    CryptoError, Rng,
    backend::{AsymmetricKey, MontgomeryCurve},
};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct X25519Wrapper;

pub struct KeyPair {
    pub private: StaticSecret,
    pub public: PublicKey,
}

impl AsymmetricKey<32, 32> for X25519Wrapper {
    type Public = PublicKey;
    type Private = KeyPair;

    fn generate(rng: &mut impl Rng, _: ()) -> Result<Self::Private, CryptoError> {
        let mut wrapper = RngWrapper(rng);
        let mut secret = [0u8; 32];
        rand_core::Rng::fill_bytes(&mut wrapper, &mut secret);
        let private = StaticSecret::from(secret);
        let public = PublicKey::from(&private);
        Ok(KeyPair { private, public })
    }

    fn load_public(_: (), u: &[u8; 32]) -> Result<Option<Self::Public>, CryptoError> {
        Ok(Some(PublicKey::from(*u)))
    }

    fn store_public(public: &Self::Public, out_u: &mut [u8; 32]) -> Result<(), CryptoError> {
        out_u.copy_from_slice(public.as_bytes());
        Ok(())
    }

    fn load_private(
        public: Self::Public,
        scalar: &[u8; 32],
    ) -> Result<Option<Self::Private>, CryptoError> {
        let private = StaticSecret::from(*scalar);
        if PublicKey::from(&private).as_bytes() != public.as_bytes() {
            return Ok(None);
        }
        Ok(Some(KeyPair { private, public }))
    }

    fn store_private(private: &Self::Private, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        out.copy_from_slice(private.private.to_bytes().as_ref());
        Ok(())
    }

    fn as_public(private: &Self::Private) -> &Self::Public {
        &private.public
    }
}

impl MontgomeryCurve<32> for X25519Wrapper {
    fn ecdh(
        private: &Self::Private,
        peer_public: &Self::Public,
        out_u: &mut [u8; 32],
    ) -> Result<Option<()>, CryptoError> {
        let shared_secret = private.private.diffie_hellman(peer_public);
        if shared_secret.as_bytes().iter().all(|&b| b == 0) {
            return Ok(None);
        }
        out_u.copy_from_slice(shared_secret.as_bytes());
        Ok(Some(()))
    }
}
