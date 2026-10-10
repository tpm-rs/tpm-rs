//! [`Mlkem`] implementation for ML-KEM-768 and ML-KEM-1024 using BoringSSL (`bssl-sys`).

use core::fmt;

use tpm2::crypto::{CryptoError, Mlkem};
use tpm2::{
    Tpm2b, Tpm2bKemCiphertext, Tpm2bPrivateKeyMlkem, Tpm2bPublicKeyMlkem, Tpm2bSharedSecret,
    TpmiMlkemParms,
};

use crate::{BoringSsl, ChaChaRng, bssl};

/// ML-KEM encapsulation key handle for [`Mlkem::PublicKey`].
pub struct MlkemPublicKey(Public);

enum Public {
    Mlkem768(bssl::Mlkem768PublicKey),
    Mlkem1024(bssl::Mlkem1024PublicKey),
}

/// ML-KEM decapsulation key handle for [`Mlkem::PrivateKey`].
pub struct MlkemPrivateKey {
    seed: [u8; 64],
    public: MlkemPublicKey,
    private: Private,
}

enum Private {
    Mlkem768(bssl::Mlkem768PrivateKey),
    Mlkem1024(bssl::Mlkem1024PrivateKey),
}

impl fmt::Debug for MlkemPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use tpm2::crypto::MlkemPublicKey as _;
        f.debug_tuple("MlkemPublicKey")
            .field(&self.parameter_set())
            .finish()
    }
}

impl fmt::Debug for MlkemPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlkemPrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl tpm2::crypto::MlkemPublicKey for MlkemPublicKey {
    fn parameter_set(&self) -> TpmiMlkemParms {
        match self.0 {
            Public::Mlkem768(_) => TpmiMlkemParms::Mlkem768,
            Public::Mlkem1024(_) => TpmiMlkemParms::Mlkem1024,
        }
    }

    fn encoded<'a>(
        &self,
        out: &'a mut [u8; TpmiMlkemParms::MAX_PUB_KEY_BYTES],
    ) -> Result<Tpm2bPublicKeyMlkem<'a>, CryptoError> {
        let bytes = match &self.0 {
            Public::Mlkem768(key) => key.marshal(out)?,
            Public::Mlkem1024(key) => key.marshal(out)?,
        };
        Tpm2bPublicKeyMlkem::new(bytes).ok_or(CryptoError::Internal)
    }
}

impl tpm2::crypto::MlkemPrivateKey for MlkemPrivateKey {
    type PublicKey = MlkemPublicKey;

    fn public_key(&self) -> &MlkemPublicKey {
        &self.public
    }

    fn seed<'a>(&self, out: &'a mut [u8; 64]) -> Result<Tpm2bPrivateKeyMlkem<'a>, CryptoError> {
        *out = self.seed;
        Ok(Tpm2b(&*out))
    }
}

impl Mlkem for BoringSsl {
    type PublicKey = MlkemPublicKey;
    type PrivateKey = MlkemPrivateKey;

    fn load_public(
        &self,
        parameter_set: TpmiMlkemParms,
        key: Tpm2bPublicKeyMlkem<'_>,
    ) -> Result<Option<MlkemPublicKey>, CryptoError> {
        let bytes = key.as_slice();
        let public = match parameter_set {
            TpmiMlkemParms::Mlkem512 => return Err(CryptoError::Unsupported),
            TpmiMlkemParms::Mlkem768 => bssl::Mlkem768PublicKey::parse(bytes).map(Public::Mlkem768),
            TpmiMlkemParms::Mlkem1024 => {
                bssl::Mlkem1024PublicKey::parse(bytes).map(Public::Mlkem1024)
            }
        };
        Ok(public.map(MlkemPublicKey))
    }

    fn derive_key(
        &self,
        parameter_set: TpmiMlkemParms,
        seed: Tpm2bPrivateKeyMlkem<'_>,
    ) -> Result<MlkemPrivateKey, CryptoError> {
        let seed_bytes = *seed.0;
        let (public, private) = match parameter_set {
            TpmiMlkemParms::Mlkem512 => return Err(CryptoError::Unsupported),
            TpmiMlkemParms::Mlkem768 => {
                let (pub_key, priv_key) = bssl::Mlkem768PrivateKey::from_seed(&seed_bytes)?;
                (Public::Mlkem768(pub_key), Private::Mlkem768(priv_key))
            }
            TpmiMlkemParms::Mlkem1024 => {
                let (pub_key, priv_key) = bssl::Mlkem1024PrivateKey::from_seed(&seed_bytes)?;
                (Public::Mlkem1024(pub_key), Private::Mlkem1024(priv_key))
            }
        };
        Ok(MlkemPrivateKey {
            seed: seed_bytes,
            public: MlkemPublicKey(public),
            private,
        })
    }

    fn encapsulate<'a>(
        &self,
        _rng: &mut ChaChaRng,
        key: &MlkemPublicKey,
        out_ciphertext: &'a mut [u8; TpmiMlkemParms::MAX_CT_BYTES],
        out_shared_secret: &'a mut [u8; TpmiMlkemParms::SHARED_SECRET_BYTES],
    ) -> Result<(Tpm2bKemCiphertext<'a>, Tpm2bSharedSecret<'a>), CryptoError> {
        let ct = match &key.0 {
            Public::Mlkem768(key) => key.encapsulate(out_ciphertext, out_shared_secret)?,
            Public::Mlkem1024(key) => key.encapsulate(out_ciphertext, out_shared_secret)?,
        };
        Ok((
            Tpm2bKemCiphertext::new(ct).ok_or(CryptoError::Internal)?,
            Tpm2bSharedSecret::new(out_shared_secret).ok_or(CryptoError::Internal)?,
        ))
    }

    fn decapsulate<'a>(
        &self,
        key: &MlkemPrivateKey,
        ciphertext: Tpm2bKemCiphertext<'_>,
        out: &'a mut [u8; TpmiMlkemParms::SHARED_SECRET_BYTES],
    ) -> Result<Option<Tpm2bSharedSecret<'a>>, CryptoError> {
        let ct = ciphertext.as_slice();
        let ok = match &key.private {
            Private::Mlkem768(key) => key.decapsulate(ct, out),
            Private::Mlkem1024(key) => key.decapsulate(ct, out),
        };
        if !ok {
            return Ok(None);
        }
        Ok(Some(
            Tpm2bSharedSecret::new(out).ok_or(CryptoError::Internal)?,
        ))
    }
}
