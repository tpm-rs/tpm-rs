#![allow(missing_docs)]
use crate::{ChaChaRng, RngWrapper};
use tpm2::crypto::{
    CryptoError,
    backend::{MontgomeryCurve, PrivateKey},
};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct KeyPair {
    pub private: StaticSecret,
    pub public: PublicKey,
}

impl PrivateKey<32, 32, ChaChaRng> for KeyPair {
    type PublicKey = PublicKey;

    fn generate(rng: &mut ChaChaRng, _: ()) -> Result<Self, CryptoError> {
        let mut wrapper = RngWrapper(rng);
        let mut secret = [0u8; 32];
        rand_core::Rng::fill_bytes(&mut wrapper, &mut secret);
        let private = StaticSecret::from(secret);
        let public = PublicKey::from(&private);
        Ok(KeyPair { private, public })
    }

    fn load_public(_: (), u: &[u8; 32]) -> Result<Option<Self::PublicKey>, CryptoError> {
        Ok(Some(PublicKey::from(*u)))
    }

    fn store_public(public: &Self::PublicKey, out_u: &mut [u8; 32]) -> Result<(), CryptoError> {
        out_u.copy_from_slice(public.as_bytes());
        Ok(())
    }

    fn load(public: Self::PublicKey, scalar: &[u8; 32]) -> Result<Option<Self>, CryptoError> {
        let private = StaticSecret::from(*scalar);
        if PublicKey::from(&private).as_bytes() != public.as_bytes() {
            return Ok(None);
        }
        Ok(Some(KeyPair { private, public }))
    }

    fn store(&self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        out.copy_from_slice(self.private.to_bytes().as_ref());
        Ok(())
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.public
    }
}

impl MontgomeryCurve<32, ChaChaRng> for KeyPair {
    fn ecdh(
        &self,
        peer_public: &Self::PublicKey,
        out_u: &mut [u8; 32],
    ) -> Result<Option<()>, CryptoError> {
        let shared_secret = self.private.diffie_hellman(peer_public);
        if shared_secret.as_bytes().iter().all(|&b| b == 0) {
            return Ok(None);
        }
        out_u.copy_from_slice(shared_secret.as_bytes());
        Ok(Some(()))
    }
}
