//! [`Mlkem`] implementation using libcrux-ml-kem.

use alloc::boxed::Box;

use libcrux_ml_kem::{mlkem512, mlkem768, mlkem1024};
use tpm2::crypto::{CryptoError, Mlkem, Rng as _};
use tpm2::{
    Tpm2b, Tpm2bKemCiphertext, Tpm2bPrivateKeyMlkem, Tpm2bPublicKeyMlkem, Tpm2bSharedSecret,
    TpmiMlkemParms,
};

use crate::{ChaChaRng, Libcrux, write};

/// ML-KEM encapsulation key handle for [`Mlkem::PublicKey`].
pub struct MlkemPublic(Public);

// The keys are boxed as they are up to 3168 bytes long.
enum Public {
    Mlkem512(Box<mlkem512::MlKem512PublicKey>),
    Mlkem768(Box<mlkem768::MlKem768PublicKey>),
    Mlkem1024(Box<mlkem1024::MlKem1024PublicKey>),
}

/// ML-KEM decapsulation key handle for [`Mlkem::PrivateKey`].
pub struct MlkemPrivate {
    /// The seed `(d || z)` the key was derived from.
    seed: [u8; 64],
    public: MlkemPublic,
    private: Private,
}

enum Private {
    Mlkem512(Box<mlkem512::MlKem512PrivateKey>),
    Mlkem768(Box<mlkem768::MlKem768PrivateKey>),
    Mlkem1024(Box<mlkem1024::MlKem1024PrivateKey>),
}

impl tpm2::crypto::MlkemPublicKey for MlkemPublic {
    fn parameter_set(&self) -> TpmiMlkemParms {
        match self.0 {
            Public::Mlkem512(_) => TpmiMlkemParms::Mlkem512,
            Public::Mlkem768(_) => TpmiMlkemParms::Mlkem768,
            Public::Mlkem1024(_) => TpmiMlkemParms::Mlkem1024,
        }
    }

    fn encoded<'a>(
        &self,
        out: &'a mut [u8; TpmiMlkemParms::MAX_PUB_KEY_BYTES],
    ) -> Result<Tpm2bPublicKeyMlkem<'a>, CryptoError> {
        let key: &[u8] = match &self.0 {
            Public::Mlkem512(key) => key.as_slice(),
            Public::Mlkem768(key) => key.as_slice(),
            Public::Mlkem1024(key) => key.as_slice(),
        };
        Tpm2bPublicKeyMlkem::new(write(key, out)?).ok_or(CryptoError::Internal)
    }
}

impl tpm2::crypto::MlkemPrivateKey for MlkemPrivate {
    type PublicKey = MlkemPublic;

    fn public_key(&self) -> &MlkemPublic {
        &self.public
    }

    fn seed<'a>(&self, out: &'a mut [u8; 64]) -> Result<Tpm2bPrivateKeyMlkem<'a>, CryptoError> {
        *out = self.seed;
        Ok(Tpm2b(&*out))
    }
}

impl Mlkem for Libcrux {
    type PublicKey = MlkemPublic;
    type PrivateKey = MlkemPrivate;

    fn load_public(
        &self,
        parameter_set: TpmiMlkemParms,
        key: Tpm2bPublicKeyMlkem<'_>,
    ) -> Result<Option<MlkemPublic>, CryptoError> {
        let key = key.as_slice();
        // `try_from` checks the length, and `validate_public_key` performs the
        // FIPS 203 modulus check.
        let public = match parameter_set {
            TpmiMlkemParms::Mlkem512 => mlkem512::MlKem512PublicKey::try_from(key)
                .ok()
                .filter(mlkem512::validate_public_key)
                .map(|key| Public::Mlkem512(Box::new(key))),
            TpmiMlkemParms::Mlkem768 => mlkem768::MlKem768PublicKey::try_from(key)
                .ok()
                .filter(mlkem768::validate_public_key)
                .map(|key| Public::Mlkem768(Box::new(key))),
            TpmiMlkemParms::Mlkem1024 => mlkem1024::MlKem1024PublicKey::try_from(key)
                .ok()
                .filter(mlkem1024::validate_public_key)
                .map(|key| Public::Mlkem1024(Box::new(key))),
        };
        Ok(public.map(MlkemPublic))
    }

    fn derive_key(
        &self,
        parameter_set: TpmiMlkemParms,
        seed: Tpm2bPrivateKeyMlkem<'_>,
    ) -> Result<MlkemPrivate, CryptoError> {
        let seed = *seed.0;
        // libcrux takes the key generation randomness as `d || z`.
        let (public, private) = match parameter_set {
            TpmiMlkemParms::Mlkem512 => {
                let (private, public) = mlkem512::generate_key_pair(seed).into_parts();
                let public = Public::Mlkem512(Box::new(public));
                (public, Private::Mlkem512(Box::new(private)))
            }
            TpmiMlkemParms::Mlkem768 => {
                let (private, public) = mlkem768::generate_key_pair(seed).into_parts();
                let public = Public::Mlkem768(Box::new(public));
                (public, Private::Mlkem768(Box::new(private)))
            }
            TpmiMlkemParms::Mlkem1024 => {
                let (private, public) = mlkem1024::generate_key_pair(seed).into_parts();
                let public = Public::Mlkem1024(Box::new(public));
                (public, Private::Mlkem1024(Box::new(private)))
            }
        };
        Ok(MlkemPrivate {
            seed,
            public: MlkemPublic(public),
            private,
        })
    }

    fn encapsulate<'a>(
        &self,
        rng: &mut ChaChaRng,
        key: &MlkemPublic,
        out_ciphertext: &'a mut [u8; TpmiMlkemParms::MAX_CT_BYTES],
        out_shared_secret: &'a mut [u8; TpmiMlkemParms::SHARED_SECRET_BYTES],
    ) -> Result<(Tpm2bKemCiphertext<'a>, Tpm2bSharedSecret<'a>), CryptoError> {
        let mut randomness = [0u8; 32];
        rng.fill_bytes(&mut randomness)?;
        let (ciphertext, shared_secret) = match &key.0 {
            Public::Mlkem512(key) => {
                let (ciphertext, shared_secret) = mlkem512::encapsulate(key, randomness);
                (write(ciphertext.as_slice(), out_ciphertext)?, shared_secret)
            }
            Public::Mlkem768(key) => {
                let (ciphertext, shared_secret) = mlkem768::encapsulate(key, randomness);
                (write(ciphertext.as_slice(), out_ciphertext)?, shared_secret)
            }
            Public::Mlkem1024(key) => {
                let (ciphertext, shared_secret) = mlkem1024::encapsulate(key, randomness);
                (write(ciphertext.as_slice(), out_ciphertext)?, shared_secret)
            }
        };
        *out_shared_secret = shared_secret;
        Ok((
            Tpm2bKemCiphertext::new(ciphertext).ok_or(CryptoError::Internal)?,
            Tpm2bSharedSecret::new(out_shared_secret).ok_or(CryptoError::Internal)?,
        ))
    }

    fn decapsulate<'a>(
        &self,
        key: &MlkemPrivate,
        ciphertext: Tpm2bKemCiphertext<'_>,
        out: &'a mut [u8; TpmiMlkemParms::SHARED_SECRET_BYTES],
    ) -> Result<Option<Tpm2bSharedSecret<'a>>, CryptoError> {
        let ciphertext = ciphertext.as_slice();
        // `try_from` fails if the ciphertext has the wrong length. An invalid
        // ciphertext of the right length gives an implicit-rejection secret.
        let shared_secret = match &key.private {
            Private::Mlkem512(key) => match mlkem512::MlKem512Ciphertext::try_from(ciphertext) {
                Ok(ciphertext) => mlkem512::decapsulate(key, &ciphertext),
                Err(_) => return Ok(None),
            },
            Private::Mlkem768(key) => match mlkem768::MlKem768Ciphertext::try_from(ciphertext) {
                Ok(ciphertext) => mlkem768::decapsulate(key, &ciphertext),
                Err(_) => return Ok(None),
            },
            Private::Mlkem1024(key) => match mlkem1024::MlKem1024Ciphertext::try_from(ciphertext) {
                Ok(ciphertext) => mlkem1024::decapsulate(key, &ciphertext),
                Err(_) => return Ok(None),
            },
        };
        *out = shared_secret;
        Ok(Some(
            Tpm2bSharedSecret::new(out).ok_or(CryptoError::Internal)?,
        ))
    }
}
