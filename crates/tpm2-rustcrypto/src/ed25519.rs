#![allow(missing_docs)]
use crate::RngWrapper;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use ml_dsa::signature::{MultipartSigner, MultipartVerifier};
use sha2::digest::typenum::U64;
use sha2::digest::{
    self, FixedOutput, FixedOutputReset, HashMarker, OutputSizeUser, Reset, Update,
};
use tpm2::crypto::{
    CryptoError, Rng,
    backend::{AsymmetricKey, EdwardsCurve},
};

#[derive(Clone, Default)]
struct PrehashDigest(Option<[u8; 64]>);

impl Update for PrehashDigest {
    fn update(&mut self, _data: &[u8]) {}
}
impl OutputSizeUser for PrehashDigest {
    type OutputSize = U64;
}
impl FixedOutput for PrehashDigest {
    fn finalize_into(self, out: &mut digest::Output<Self>) {
        if let Some(h) = self.0 {
            out.copy_from_slice(&h);
        }
    }
}
impl Reset for PrehashDigest {
    fn reset(&mut self) {
        self.0 = None;
    }
}
impl FixedOutputReset for PrehashDigest {
    fn finalize_into_reset(&mut self, out: &mut digest::Output<Self>) {
        if let Some(h) = self.0 {
            out.copy_from_slice(&h);
        }
        self.reset();
    }
}
impl HashMarker for PrehashDigest {}

pub struct Ed25519Wrapper;

pub struct KeyPair {
    pub private: SigningKey,
    pub public: VerifyingKey,
}

impl AsymmetricKey<32, 32> for Ed25519Wrapper {
    type Public = VerifyingKey;
    type Private = KeyPair;

    fn generate(rng: &mut impl Rng, _: ()) -> Result<Self::Private, CryptoError> {
        let mut wrapper = RngWrapper(rng);
        let mut secret = [0u8; 32];
        rand_core::Rng::fill_bytes(&mut wrapper, &mut secret);
        let private = SigningKey::from_bytes(&secret);
        let public = private.verifying_key();
        Ok(KeyPair { private, public })
    }

    fn load_public(_: (), point: &[u8; 32]) -> Result<Option<Self::Public>, CryptoError> {
        Ok(VerifyingKey::from_bytes(point).ok())
    }

    fn store_public(public: &Self::Public, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        out.copy_from_slice(public.as_bytes());
        Ok(())
    }

    fn load_private(
        public: Self::Public,
        secret: &[u8; 32],
    ) -> Result<Option<Self::Private>, CryptoError> {
        let private = SigningKey::from_bytes(secret);
        if private.verifying_key() != public {
            return Ok(None);
        }
        Ok(Some(KeyPair { private, public }))
    }

    fn store_private(private: &Self::Private, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        out.copy_from_slice(private.private.to_bytes().as_slice());
        Ok(())
    }

    fn as_public(private: &Self::Private) -> &Self::Public {
        &private.public
    }
}

impl EdwardsCurve<32> for Ed25519Wrapper {
    fn sign_message(
        private: &Self::Private,
        msg: &[&[u8]],
        out_r: &mut [u8; 32],
        out_s: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        let sig: Signature = private.private.multipart_sign(msg);
        let sig_bytes = sig.to_bytes();
        out_r.copy_from_slice(&sig_bytes[..32]);
        out_s.copy_from_slice(&sig_bytes[32..]);
        Ok(())
    }

    fn sign_prehash(
        private: &Self::Private,
        prehash: &[u8; 64],
        out_r: &mut [u8; 32],
        out_s: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        let h = PrehashDigest(Some(*prehash));
        let sig: Signature = private
            .private
            .sign_prehashed(h, None)
            .map_err(|_| CryptoError::Internal)?;
        let sig_bytes = sig.to_bytes();
        out_r.copy_from_slice(&sig_bytes[..32]);
        out_s.copy_from_slice(&sig_bytes[32..]);
        Ok(())
    }

    fn verify_message(
        public: &Self::Public,
        msg: &[&[u8]],
        sig_r: &[u8; 32],
        sig_s: &[u8; 32],
    ) -> Result<bool, CryptoError> {
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(sig_r);
        sig_bytes[32..].copy_from_slice(sig_s);
        let sig = Signature::from_bytes(&sig_bytes);
        Ok(public.multipart_verify(msg, &sig).is_ok())
    }

    fn verify_prehash(
        public: &Self::Public,
        prehash: &[u8; 64],
        sig_r: &[u8; 32],
        sig_s: &[u8; 32],
    ) -> Result<bool, CryptoError> {
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(sig_r);
        sig_bytes[32..].copy_from_slice(sig_s);
        let sig = Signature::from_bytes(&sig_bytes);
        let h = PrehashDigest(Some(*prehash));
        Ok(public.verify_prehashed(h, None, &sig).is_ok())
    }
}
