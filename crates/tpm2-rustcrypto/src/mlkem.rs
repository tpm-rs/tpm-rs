//! [`Mlkem`]: ML-KEM key encapsulation ([FIPS 203]).
//!
//! [FIPS 203]: https://csrc.nist.gov/pubs/fips/203/final

use core::fmt;

use ml_kem::{
    B32, Decapsulate, DecapsulationKey, EncapsulationKey, KeyExport, MlKem512, MlKem768, MlKem1024,
    Seed, TryKeyInit,
};
use tpm2::{
    Tpm2b, Tpm2bKemCiphertext, Tpm2bPrivateKeyMlkem, Tpm2bPublicKeyMlkem, Tpm2bSharedSecret,
    TpmiMlkemParms,
    crypto::{CryptoError, Mlkem, MlkemPublicKey as _, Rng},
};

use crate::{ChaChaRng, RustCrypto, copy_prefix};

/// Evaluates `$body` with `$var` bound to the parameter-set-specific key
/// inside an [`Ek`] or [`Dk`].
macro_rules! dispatch {
    ($enum:ident, $value:expr, $var:ident => $body:expr) => {
        match $value {
            $enum::Mlkem512($var) => $body,
            $enum::Mlkem768($var) => $body,
            $enum::Mlkem1024($var) => $body,
        }
    };
}

/// ML-KEM encapsulation (public) key.
#[derive(Clone, PartialEq, Eq)]
pub struct MlkemPublicKey(Ek);

#[derive(Clone, PartialEq, Eq)]
enum Ek {
    Mlkem512(EncapsulationKey<MlKem512>),
    Mlkem768(EncapsulationKey<MlKem768>),
    Mlkem1024(EncapsulationKey<MlKem1024>),
}

/// ML-KEM decapsulation (private) key.
#[derive(Clone)]
pub struct MlkemPrivateKey {
    public: MlkemPublicKey,
    secret: Dk,
}

#[derive(Clone)]
enum Dk {
    Mlkem512(DecapsulationKey<MlKem512>),
    Mlkem768(DecapsulationKey<MlKem768>),
    Mlkem1024(DecapsulationKey<MlKem1024>),
}

impl fmt::Debug for MlkemPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
            Ek::Mlkem512(_) => TpmiMlkemParms::Mlkem512,
            Ek::Mlkem768(_) => TpmiMlkemParms::Mlkem768,
            Ek::Mlkem1024(_) => TpmiMlkemParms::Mlkem1024,
        }
    }

    fn encoded<'a>(
        &self,
        out: &'a mut [u8; TpmiMlkemParms::MAX_PUB_KEY_BYTES],
    ) -> Result<Tpm2bPublicKeyMlkem<'a>, CryptoError> {
        let encoded = dispatch!(Ek, &self.0, ek => copy_prefix(out, &ek.to_bytes()))?;
        Tpm2bPublicKeyMlkem::new(encoded).ok_or(CryptoError::Internal)
    }
}

impl tpm2::crypto::MlkemPrivateKey for MlkemPrivateKey {
    type PublicKey = MlkemPublicKey;

    fn public_key(&self) -> &MlkemPublicKey {
        &self.public
    }

    fn seed<'a>(&self, out: &'a mut [u8; 64]) -> Result<Tpm2bPrivateKeyMlkem<'a>, CryptoError> {
        // Keys are only created by `DecapsulationKey::from_seed`, so they
        // always have a seed.
        let seed = dispatch!(Dk, &self.secret, dk => dk.to_seed()).ok_or(CryptoError::Internal)?;
        *out = seed.into();
        Ok(Tpm2b(out))
    }
}

impl Mlkem for RustCrypto {
    type PublicKey = MlkemPublicKey;
    type PrivateKey = MlkemPrivateKey;

    fn load_public(
        &self,
        parameter_set: TpmiMlkemParms,
        key: Tpm2bPublicKeyMlkem<'_>,
    ) -> Result<Option<MlkemPublicKey>, CryptoError> {
        // `new_from_slice` checks the length of `key`, and `EncapsulationKey`
        // performs the modulus check (FIPS 203, Section 7.2).
        let key = key.as_slice();
        let ek = match parameter_set {
            TpmiMlkemParms::Mlkem512 => TryKeyInit::new_from_slice(key).map(Ek::Mlkem512),
            TpmiMlkemParms::Mlkem768 => TryKeyInit::new_from_slice(key).map(Ek::Mlkem768),
            TpmiMlkemParms::Mlkem1024 => TryKeyInit::new_from_slice(key).map(Ek::Mlkem1024),
        };
        Ok(ek.ok().map(MlkemPublicKey))
    }

    fn derive_key(
        &self,
        parameter_set: TpmiMlkemParms,
        seed: Tpm2bPrivateKeyMlkem<'_>,
    ) -> Result<MlkemPrivateKey, CryptoError> {
        let seed = Seed::from(*seed.0);
        let secret = match parameter_set {
            TpmiMlkemParms::Mlkem512 => Dk::Mlkem512(DecapsulationKey::from_seed(seed)),
            TpmiMlkemParms::Mlkem768 => Dk::Mlkem768(DecapsulationKey::from_seed(seed)),
            TpmiMlkemParms::Mlkem1024 => Dk::Mlkem1024(DecapsulationKey::from_seed(seed)),
        };
        let public = MlkemPublicKey(match &secret {
            Dk::Mlkem512(dk) => Ek::Mlkem512(dk.encapsulation_key().clone()),
            Dk::Mlkem768(dk) => Ek::Mlkem768(dk.encapsulation_key().clone()),
            Dk::Mlkem1024(dk) => Ek::Mlkem1024(dk.encapsulation_key().clone()),
        });
        Ok(MlkemPrivateKey { public, secret })
    }

    fn encapsulate<'a>(
        &self,
        rng: &mut ChaChaRng,
        key: &MlkemPublicKey,
        out_ciphertext: &'a mut [u8; TpmiMlkemParms::MAX_CT_BYTES],
        out_shared_secret: &'a mut [u8; TpmiMlkemParms::SHARED_SECRET_BYTES],
    ) -> Result<(Tpm2bKemCiphertext<'a>, Tpm2bSharedSecret<'a>), CryptoError> {
        // ML-KEM.Encaps (FIPS 203, Algorithm 20): sample m, then run
        // ML-KEM.Encaps_internal.
        let mut m = B32::default();
        rng.fill_bytes(&mut m)?;
        let (ciphertext, shared_secret) = dispatch!(Ek, &key.0, ek => {
            let (ciphertext, shared_secret) = ek.encapsulate_deterministic(&m);
            (copy_prefix(out_ciphertext, &ciphertext)?, shared_secret)
        });
        *out_shared_secret = shared_secret.into();
        let out_shared_secret: &'a [u8; TpmiMlkemParms::SHARED_SECRET_BYTES] = out_shared_secret;
        Ok((
            Tpm2bKemCiphertext::new(ciphertext).ok_or(CryptoError::Internal)?,
            Tpm2bSharedSecret::new(out_shared_secret).ok_or(CryptoError::Internal)?,
        ))
    }

    fn decapsulate<'a>(
        &self,
        key: &MlkemPrivateKey,
        ciphertext: Tpm2bKemCiphertext<'_>,
        out: &'a mut [u8; TpmiMlkemParms::SHARED_SECRET_BYTES],
    ) -> Result<Option<Tpm2bSharedSecret<'a>>, CryptoError> {
        // `decapsulate_slice` only fails if `ciphertext` has the wrong length.
        // Invalid ciphertexts of the right length are implicitly rejected
        // (FIPS 203, Algorithm 18), producing a pseudorandom shared secret.
        let ciphertext = ciphertext.as_slice();
        let Ok(shared_secret) = dispatch!(Dk, &key.secret, dk => dk.decapsulate_slice(ciphertext))
        else {
            return Ok(None);
        };
        *out = shared_secret.into();
        let out: &'a [u8; TpmiMlkemParms::SHARED_SECRET_BYTES] = out;
        Tpm2bSharedSecret::new(out)
            .ok_or(CryptoError::Internal)
            .map(Some)
    }
}
