//! [`Mldsa`] implementation using libcrux-ml-dsa.

use alloc::boxed::Box;
use alloc::vec::Vec;

use libcrux_ml_dsa::{MLDSASignature, SigningError, ml_dsa_44, ml_dsa_65, ml_dsa_87};
use tpm2::crypto::{CryptoError, Mldsa, MldsaMessage, Rng as _, pre_hash_oid};
use tpm2::{Tpm2b, Tpm2bPrivateKeyMldsa, Tpm2bPublicKeyMldsa, Tpm2bSignatureMldsa, TpmiMldsaParms};

use crate::{ChaChaRng, Libcrux, write};

/// ML-DSA public key handle for [`Mldsa::PublicKey`].
pub struct MldsaPublic(Public);

// The keys are boxed as they are up to 4896 bytes long.
enum Public {
    Mldsa44(Box<ml_dsa_44::MLDSA44VerificationKey>),
    Mldsa65(Box<ml_dsa_65::MLDSA65VerificationKey>),
    Mldsa87(Box<ml_dsa_87::MLDSA87VerificationKey>),
}

/// ML-DSA private key handle for [`Mldsa::PrivateKey`].
pub struct MldsaPrivate {
    /// The seed `ξ` the key was derived from.
    seed: [u8; 32],
    public: MldsaPublic,
    private: Private,
}

enum Private {
    Mldsa44(Box<ml_dsa_44::MLDSA44SigningKey>),
    Mldsa65(Box<ml_dsa_65::MLDSA65SigningKey>),
    Mldsa87(Box<ml_dsa_87::MLDSA87SigningKey>),
}

/// A [`MldsaMessage`] in the form libcrux takes it.
enum Message<'a> {
    /// ML-DSA, where libcrux builds `M' = 0 || |ctx| || ctx || M` itself.
    Pure {
        context: &'a [u8],
        message: &'a [u8],
    },
    /// HashML-DSA's `M' = 1 || |ctx| || ctx || OID || PH(M)` (FIPS 204,
    /// Algorithm 4), which is passed to `ML-DSA.Sign_internal` and
    /// `ML-DSA.Verify_internal` directly.
    Internal(Vec<u8>),
}

impl<'a> Message<'a> {
    fn new(message: MldsaMessage<'a>) -> Result<Self, CryptoError> {
        match message {
            MldsaMessage::Pure { context, message } => Ok(Self::Pure {
                context: context.as_slice(),
                message,
            }),
            MldsaMessage::PreHash { context, digest } => {
                let context = context.as_slice();
                // A `Tpm2bSignatureCtx` holds at most 255 bytes.
                let context_len = u8::try_from(context.len()).map_err(|_| CryptoError::Internal)?;
                let oid = pre_hash_oid(digest.hash_alg());
                let digest = digest.digest();
                let mut m = Vec::with_capacity(2 + context.len() + oid.len() + digest.len());
                m.extend_from_slice(&[1, context_len]);
                m.extend_from_slice(context);
                m.extend_from_slice(oid);
                m.extend_from_slice(digest);
                Ok(Self::Internal(m))
            }
            // libcrux can't sign or verify an externally computed `µ`.
            MldsaMessage::ExternalMu(_) => Err(CryptoError::Unsupported),
        }
    }
}

/// Writes a libcrux signing result into `out`.
fn signed<const N: usize>(
    result: Result<MLDSASignature<N>, SigningError>,
    out: &mut [u8; TpmiMldsaParms::MAX_SIG_BYTES],
) -> Result<Option<Tpm2bSignatureMldsa<'_>>, CryptoError> {
    match result {
        Ok(signature) => Ok(Some(
            Tpm2bSignatureMldsa::new(write(signature.as_slice(), out)?)
                .ok_or(CryptoError::Internal)?,
        )),
        // libcrux gives up after a fixed number of rejection-sampling rounds.
        Err(SigningError::RejectionSamplingError) => Ok(None),
        // The context is at most 255 bytes, so this can't happen.
        Err(SigningError::ContextTooLongError) => Err(CryptoError::Internal),
    }
}

impl tpm2::crypto::MldsaPublicKey for MldsaPublic {
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
        let key = match &self.0 {
            Public::Mldsa44(key) => key.as_slice(),
            Public::Mldsa65(key) => key.as_slice(),
            Public::Mldsa87(key) => key.as_slice(),
        };
        Tpm2bPublicKeyMldsa::new(write(key, out)?).ok_or(CryptoError::Internal)
    }
}

impl tpm2::crypto::MldsaPrivateKey for MldsaPrivate {
    type PublicKey = MldsaPublic;

    fn public_key(&self) -> &MldsaPublic {
        &self.public
    }

    fn seed<'a>(&self, out: &'a mut [u8; 32]) -> Result<Tpm2bPrivateKeyMldsa<'a>, CryptoError> {
        *out = self.seed;
        Ok(Tpm2b(&*out))
    }
}

impl Mldsa for Libcrux {
    type PublicKey = MldsaPublic;
    type PrivateKey = MldsaPrivate;
    type MuContext = !;

    fn load_public(
        &self,
        parameter_set: TpmiMldsaParms,
        key: Tpm2bPublicKeyMldsa<'_>,
    ) -> Result<Option<MldsaPublic>, CryptoError> {
        let key = key.as_slice();
        let public =
            match parameter_set {
                TpmiMldsaParms::Mldsa44 => key.try_into().ok().map(|key| {
                    Public::Mldsa44(Box::new(ml_dsa_44::MLDSA44VerificationKey::new(key)))
                }),
                TpmiMldsaParms::Mldsa65 => key.try_into().ok().map(|key| {
                    Public::Mldsa65(Box::new(ml_dsa_65::MLDSA65VerificationKey::new(key)))
                }),
                TpmiMldsaParms::Mldsa87 => key.try_into().ok().map(|key| {
                    Public::Mldsa87(Box::new(ml_dsa_87::MLDSA87VerificationKey::new(key)))
                }),
            };
        Ok(public.map(MldsaPublic))
    }

    fn derive_key(
        &self,
        parameter_set: TpmiMldsaParms,
        seed: Tpm2bPrivateKeyMldsa<'_>,
    ) -> Result<MldsaPrivate, CryptoError> {
        let seed = *seed.0;
        let (public, private) = match parameter_set {
            TpmiMldsaParms::Mldsa44 => {
                let pair = ml_dsa_44::generate_key_pair(seed);
                let public = Public::Mldsa44(Box::new(pair.verification_key));
                (public, Private::Mldsa44(Box::new(pair.signing_key)))
            }
            TpmiMldsaParms::Mldsa65 => {
                let pair = ml_dsa_65::generate_key_pair(seed);
                let public = Public::Mldsa65(Box::new(pair.verification_key));
                (public, Private::Mldsa65(Box::new(pair.signing_key)))
            }
            TpmiMldsaParms::Mldsa87 => {
                let pair = ml_dsa_87::generate_key_pair(seed);
                let public = Public::Mldsa87(Box::new(pair.verification_key));
                (public, Private::Mldsa87(Box::new(pair.signing_key)))
            }
        };
        Ok(MldsaPrivate {
            seed,
            public: MldsaPublic(public),
            private,
        })
    }

    fn sign<'a>(
        &self,
        rng: &mut ChaChaRng,
        key: &MldsaPrivate,
        message: MldsaMessage<'_>,
        out: &'a mut [u8; TpmiMldsaParms::MAX_SIG_BYTES],
    ) -> Result<Option<Tpm2bSignatureMldsa<'a>>, CryptoError> {
        let message = Message::new(message)?;
        let mut rnd = [0u8; 32];
        rng.fill_bytes(&mut rnd)?;
        match (&key.private, &message) {
            (Private::Mldsa44(key), Message::Pure { context, message }) => {
                signed(ml_dsa_44::sign(key, message, context, rnd), out)
            }
            (Private::Mldsa44(key), Message::Internal(m)) => {
                signed(ml_dsa_44::sign_internal(key, m, rnd), out)
            }
            (Private::Mldsa65(key), Message::Pure { context, message }) => {
                signed(ml_dsa_65::sign(key, message, context, rnd), out)
            }
            (Private::Mldsa65(key), Message::Internal(m)) => {
                signed(ml_dsa_65::sign_internal(key, m, rnd), out)
            }
            (Private::Mldsa87(key), Message::Pure { context, message }) => {
                signed(ml_dsa_87::sign(key, message, context, rnd), out)
            }
            (Private::Mldsa87(key), Message::Internal(m)) => {
                signed(ml_dsa_87::sign_internal(key, m, rnd), out)
            }
        }
    }

    fn verify(
        &self,
        key: &MldsaPublic,
        message: MldsaMessage<'_>,
        signature: Tpm2bSignatureMldsa<'_>,
    ) -> Result<bool, CryptoError> {
        let message = Message::new(message)?;
        let signature = signature.as_slice();
        // A signature of the wrong length is invalid.
        let valid = match (&key.0, &message) {
            (Public::Mldsa44(key), message) => signature.try_into().is_ok_and(|signature| {
                let signature = ml_dsa_44::MLDSA44Signature::new(signature);
                match message {
                    Message::Pure { context, message } => {
                        ml_dsa_44::verify(key, message, context, &signature).is_ok()
                    }
                    Message::Internal(m) => ml_dsa_44::verify_internal(key, m, &signature).is_ok(),
                }
            }),
            (Public::Mldsa65(key), message) => signature.try_into().is_ok_and(|signature| {
                let signature = ml_dsa_65::MLDSA65Signature::new(signature);
                match message {
                    Message::Pure { context, message } => {
                        ml_dsa_65::verify(key, message, context, &signature).is_ok()
                    }
                    Message::Internal(m) => ml_dsa_65::verify_internal(key, m, &signature).is_ok(),
                }
            }),
            (Public::Mldsa87(key), message) => signature.try_into().is_ok_and(|signature| {
                let signature = ml_dsa_87::MLDSA87Signature::new(signature);
                match message {
                    Message::Pure { context, message } => {
                        ml_dsa_87::verify(key, message, context, &signature).is_ok()
                    }
                    Message::Internal(m) => ml_dsa_87::verify_internal(key, m, &signature).is_ok(),
                }
            }),
        };
        Ok(valid)
    }
}
