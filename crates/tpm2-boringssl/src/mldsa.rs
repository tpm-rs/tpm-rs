//! [`Mldsa`] implementation for ML-DSA-44, ML-DSA-65, and ML-DSA-87 using BoringSSL (`bssl-sys`).

use core::fmt;

use tpm2::crypto::{CryptoError, Finalize, Mldsa, MldsaMessage, Update};
use tpm2::{
    Tpm2b, Tpm2bPrivateKeyMldsa, Tpm2bPublicKeyMldsa, Tpm2bSignatureCtx, Tpm2bSignatureMldsa,
    TpmiMldsaParms,
};

use crate::{BoringSsl, ChaChaRng, bssl};

/// ML-DSA public key handle for [`Mldsa::PublicKey`].
pub struct MldsaPublicKey(Public);

enum Public {
    Mldsa44(bssl::Mldsa44PublicKey),
    Mldsa65(bssl::Mldsa65PublicKey),
    Mldsa87(bssl::Mldsa87PublicKey),
}

/// ML-DSA private key handle for [`Mldsa::PrivateKey`].
pub struct MldsaPrivateKey {
    seed: [u8; 32],
    public: MldsaPublicKey,
    private: Private,
}

enum Private {
    Mldsa44(bssl::Mldsa44PrivateKey),
    Mldsa65(bssl::Mldsa65PrivateKey),
    Mldsa87(bssl::Mldsa87PrivateKey),
}

/// Streaming context computing the 64-byte ML-DSA message representative `µ`,
/// returned by [`Mldsa::mu_start`].
#[derive(Clone)]
pub struct MuContext(Prehash);

#[derive(Clone)]
enum Prehash {
    Mldsa44(bssl::Mldsa44Prehash),
    Mldsa65(bssl::Mldsa65Prehash),
    Mldsa87(bssl::Mldsa87Prehash),
}

impl fmt::Debug for MldsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use tpm2::crypto::MldsaPublicKey as _;
        f.debug_tuple("MldsaPublicKey")
            .field(&self.parameter_set())
            .finish()
    }
}

impl fmt::Debug for MldsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MldsaPrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for MuContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MuContext").finish_non_exhaustive()
    }
}

impl Update for MuContext {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match &mut self.0 {
            Prehash::Mldsa44(state) => state.update(data),
            Prehash::Mldsa65(state) => state.update(data),
            Prehash::Mldsa87(state) => state.update(data),
        }
        Ok(())
    }
}

impl Finalize<{ TpmiMldsaParms::MU_BYTES }> for MuContext {
    fn finalize(self, out: &mut [u8; TpmiMldsaParms::MU_BYTES]) -> Result<(), CryptoError> {
        match self.0 {
            Prehash::Mldsa44(state) => state.finalize(out),
            Prehash::Mldsa65(state) => state.finalize(out),
            Prehash::Mldsa87(state) => state.finalize(out),
        }
        Ok(())
    }
}

impl tpm2::crypto::MldsaPublicKey for MldsaPublicKey {
    fn parameter_set(&self) -> TpmiMldsaParms {
        match self.0 {
            Public::Mldsa44(_) => TpmiMldsaParms::Mldsa44,
            Public::Mldsa65(_) => TpmiMldsaParms::Mldsa65,
            Public::Mldsa87(_) => TpmiMldsaParms::Mldsa87,
        }
    }

    fn encoded<'a>(
        &self,
        out: &'a mut [u8; TpmiMldsaParms::MAX_PUB_KEY_BYTES],
    ) -> Result<Tpm2bPublicKeyMldsa<'a>, CryptoError> {
        let bytes = match &self.0 {
            Public::Mldsa44(key) => key.marshal(out)?,
            Public::Mldsa65(key) => key.marshal(out)?,
            Public::Mldsa87(key) => key.marshal(out)?,
        };
        Tpm2bPublicKeyMldsa::new(bytes).ok_or(CryptoError::Internal)
    }
}

impl tpm2::crypto::MldsaPrivateKey for MldsaPrivateKey {
    type PublicKey = MldsaPublicKey;

    fn public_key(&self) -> &MldsaPublicKey {
        &self.public
    }

    fn seed<'a>(&self, out: &'a mut [u8; 32]) -> Result<Tpm2bPrivateKeyMldsa<'a>, CryptoError> {
        *out = self.seed;
        Ok(Tpm2b(&*out))
    }
}

impl Mldsa for BoringSsl {
    type PublicKey = MldsaPublicKey;
    type PrivateKey = MldsaPrivateKey;
    type MuContext = MuContext;

    fn load_public(
        &self,
        parameter_set: TpmiMldsaParms,
        key: Tpm2bPublicKeyMldsa<'_>,
    ) -> Result<Option<MldsaPublicKey>, CryptoError> {
        let bytes = key.as_slice();
        let public = match parameter_set {
            TpmiMldsaParms::Mldsa44 => bssl::Mldsa44PublicKey::parse(bytes).map(Public::Mldsa44),
            TpmiMldsaParms::Mldsa65 => bssl::Mldsa65PublicKey::parse(bytes).map(Public::Mldsa65),
            TpmiMldsaParms::Mldsa87 => bssl::Mldsa87PublicKey::parse(bytes).map(Public::Mldsa87),
        };
        Ok(public.map(MldsaPublicKey))
    }

    fn derive_key(
        &self,
        parameter_set: TpmiMldsaParms,
        seed: Tpm2bPrivateKeyMldsa<'_>,
    ) -> Result<MldsaPrivateKey, CryptoError> {
        let seed_bytes = *seed.0;
        let (public, private) = match parameter_set {
            TpmiMldsaParms::Mldsa44 => {
                let (pub_key, priv_key) = bssl::Mldsa44PrivateKey::from_seed(&seed_bytes)?;
                (Public::Mldsa44(pub_key), Private::Mldsa44(priv_key))
            }
            TpmiMldsaParms::Mldsa65 => {
                let (pub_key, priv_key) = bssl::Mldsa65PrivateKey::from_seed(&seed_bytes)?;
                (Public::Mldsa65(pub_key), Private::Mldsa65(priv_key))
            }
            TpmiMldsaParms::Mldsa87 => {
                let (pub_key, priv_key) = bssl::Mldsa87PrivateKey::from_seed(&seed_bytes)?;
                (Public::Mldsa87(pub_key), Private::Mldsa87(priv_key))
            }
        };
        Ok(MldsaPrivateKey {
            seed: seed_bytes,
            public: MldsaPublicKey(public),
            private,
        })
    }

    fn mu_start(
        &self,
        key: &MldsaPublicKey,
        context: Tpm2bSignatureCtx<'_>,
    ) -> Result<MuContext, CryptoError> {
        let ctx_bytes = context.as_slice();
        let prehash = match &key.0 {
            Public::Mldsa44(key) => Prehash::Mldsa44(key.prehash_init(ctx_bytes)?),
            Public::Mldsa65(key) => Prehash::Mldsa65(key.prehash_init(ctx_bytes)?),
            Public::Mldsa87(key) => Prehash::Mldsa87(key.prehash_init(ctx_bytes)?),
        };
        Ok(MuContext(prehash))
    }

    fn sign<'a>(
        &self,
        _rng: &mut ChaChaRng,
        key: &MldsaPrivateKey,
        message: MldsaMessage<'_>,
        out: &'a mut [u8; TpmiMldsaParms::MAX_SIG_BYTES],
    ) -> Result<Option<Tpm2bSignatureMldsa<'a>>, CryptoError> {
        let sig_bytes = match (&key.private, message) {
            (Private::Mldsa44(sk), MldsaMessage::Pure { context, message }) => {
                sk.sign(message, context.as_slice(), out)?
            }
            (Private::Mldsa65(sk), MldsaMessage::Pure { context, message }) => {
                sk.sign(message, context.as_slice(), out)?
            }
            (Private::Mldsa87(sk), MldsaMessage::Pure { context, message }) => {
                sk.sign(message, context.as_slice(), out)?
            }
            (Private::Mldsa44(sk), MldsaMessage::ExternalMu(mu)) => sk.sign_mu(mu, out)?,
            (Private::Mldsa65(sk), MldsaMessage::ExternalMu(mu)) => sk.sign_mu(mu, out)?,
            (Private::Mldsa87(sk), MldsaMessage::ExternalMu(mu)) => sk.sign_mu(mu, out)?,
            (_, MldsaMessage::PreHash { .. }) => return Err(CryptoError::Unsupported),
        };
        Ok(Some(
            Tpm2bSignatureMldsa::new(sig_bytes).ok_or(CryptoError::Internal)?,
        ))
    }

    fn verify(
        &self,
        key: &MldsaPublicKey,
        message: MldsaMessage<'_>,
        signature: Tpm2bSignatureMldsa<'_>,
    ) -> Result<bool, CryptoError> {
        let sig = signature.as_slice();
        let valid = match (&key.0, message) {
            (Public::Mldsa44(pk), MldsaMessage::Pure { context, message }) => {
                pk.verify(message, context.as_slice(), sig)
            }
            (Public::Mldsa65(pk), MldsaMessage::Pure { context, message }) => {
                pk.verify(message, context.as_slice(), sig)
            }
            (Public::Mldsa87(pk), MldsaMessage::Pure { context, message }) => {
                pk.verify(message, context.as_slice(), sig)
            }
            (Public::Mldsa44(pk), MldsaMessage::ExternalMu(mu)) => pk.verify_mu(mu, sig),
            (Public::Mldsa65(pk), MldsaMessage::ExternalMu(mu)) => pk.verify_mu(mu, sig),
            (Public::Mldsa87(pk), MldsaMessage::ExternalMu(mu)) => pk.verify_mu(mu, sig),
            (_, MldsaMessage::PreHash { .. }) => return Err(CryptoError::Unsupported),
        };
        Ok(valid)
    }
}
