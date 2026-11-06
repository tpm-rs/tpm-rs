//! [`Mlkem`] (FIPS 203) and [`Mldsa`] (FIPS 204) for [`CruxCryptoProvider`].
//!
//! ML-KEM, ML-DSA key generation and pure ML-DSA (signing and verification of
//! messages with a context string) use the formally verified `libcrux-ml-kem`
//! and `libcrux-ml-dsa`. `libcrux-ml-dsa` signs and verifies messages only (it
//! computes `mu` itself), so signing and verification on an external `mu`
//! and HashML-DSA fall back to the RustCrypto implementation of
//! [`tpm2_crypto_rust::pqc`] (`ml-dsa`).
//!
//! The private keys hold their FIPS 203 / FIPS 204 seed and public key, and
//! expand the seed again for each private key operation.

use alloc::vec::Vec;
use libcrux_ml_kem::{mlkem512, mlkem768, mlkem1024};
use tpm2::TpmtHa;
use tpm2::crypto::backend::{Mldsa, MldsaKey, Mlkem, MlkemKey, PrivateKey};
use tpm2::crypto::{Crypto as _, CryptoError, Rng as _};
use tpm2_crypto_rust::pqc::{RustCryptoMldsa44, RustCryptoMldsa65, RustCryptoMldsa87};
use zeroize::Zeroize as _;

use crate::{CruxCryptoProvider, CruxRng};

impl Mlkem for CruxCryptoProvider {
    type Mlkem512 = CruxMlkem512;
    type Mlkem768 = CruxMlkem768;
    type Mlkem1024 = CruxMlkem1024;
}

impl Mldsa for CruxCryptoProvider {
    type Mldsa44 = CruxMldsa44;
    type Mldsa65 = CruxMldsa65;
    type Mldsa87 = CruxMldsa87;
}

/// A validated public key of `SIZE` bytes (an ML-KEM encapsulation key or an
/// ML-DSA verification key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CruxPqcPublicKey<const SIZE: usize>([u8; SIZE]);

/// Defines the ML-KEM private key `$name` of the `libcrux-ml-kem` module `$m`.
macro_rules! mlkem_key {
    ($(#[$doc:meta])* $name:ident, $m:ident, $pub_size:literal, $ct_size:literal) => {
        $(#[$doc])*
        ///
        /// The 64-byte seed `d || z` is zeroized on drop.
        pub struct $name {
            seed: [u8; 64],
            public: CruxPqcPublicKey<$pub_size>,
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.seed.zeroize();
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("public", &self.public)
                    .finish_non_exhaustive()
            }
        }

        impl PrivateKey<$pub_size, 64, CruxRng> for $name {
            type PublicKey = CruxPqcPublicKey<$pub_size>;

            fn generate(rng: &mut CruxRng, _: ()) -> Result<Self, CryptoError> {
                let mut seed = [0u8; 64];
                rng.fill_bytes(&mut seed)?;
                let key = <Self as MlkemKey<$pub_size, $ct_size, CruxRng>>::expand(&seed);
                seed.zeroize();
                key
            }

            fn load(
                public: Self::PublicKey,
                private: &[u8; 64],
            ) -> Result<Option<Self>, CryptoError> {
                let key = <Self as MlkemKey<$pub_size, $ct_size, CruxRng>>::expand(private)?;
                Ok(CruxCryptoProvider::ct_eq(&key.public.0, &public.0).then_some(key))
            }

            fn store(&self, out: &mut [u8; 64]) -> Result<(), CryptoError> {
                *out = self.seed;
                Ok(())
            }

            fn as_public(&self) -> &Self::PublicKey {
                &self.public
            }

            /// `Ok(None)` unless `public` passes the FIPS 203 modulus check.
            fn load_public(
                _: (),
                public: &[u8; $pub_size],
            ) -> Result<Option<Self::PublicKey>, CryptoError> {
                let ek = libcrux_ml_kem::MlKemPublicKey::from(public);
                Ok($m::validate_public_key(&ek).then(|| CruxPqcPublicKey(*public)))
            }

            fn store_public(
                public: &Self::PublicKey,
                out: &mut [u8; $pub_size],
            ) -> Result<(), CryptoError> {
                *out = public.0;
                Ok(())
            }
        }

        impl MlkemKey<$pub_size, $ct_size, CruxRng> for $name {
            fn encapsulate(
                public: &Self::PublicKey,
                rng: &mut CruxRng,
                out_ct: &mut [u8; $ct_size],
                out_ss: &mut [u8; 32],
            ) -> Result<(), CryptoError> {
                let mut m = [0u8; 32];
                rng.fill_bytes(&mut m)?;
                let result = Self::encapsulate_internal(public, &m, out_ct, out_ss);
                m.zeroize();
                result
            }

            /// `ML-KEM.Decaps` on the key pair generated from the seed `d || z`.
            fn decapsulate(
                &self,
                ct: &[u8; $ct_size],
                out_ss: &mut [u8; 32],
            ) -> Result<(), CryptoError> {
                let key_pair = $m::generate_key_pair(self.seed);
                *out_ss = $m::decapsulate(key_pair.private_key(), &libcrux_ml_kem::MlKemCiphertext::from(ct));
                Ok(())
            }

            /// `ML-KEM.KeyGen_internal(d, z)` (`generate_key_pair` on the seed
            /// `d || z`).
            fn expand(seed: &[u8; 64]) -> Result<Self, CryptoError> {
                let key_pair = $m::generate_key_pair(*seed);
                Ok(Self {
                    seed: *seed,
                    public: CruxPqcPublicKey(*key_pair.public_key().as_slice()),
                })
            }

            /// `ML-KEM.Encaps_internal(ek, m)` (`encapsulate`).
            fn encapsulate_internal(
                public: &Self::PublicKey,
                m: &[u8; 32],
                out_ct: &mut [u8; $ct_size],
                out_ss: &mut [u8; 32],
            ) -> Result<(), CryptoError> {
                let (ct, ss) = $m::encapsulate(&libcrux_ml_kem::MlKemPublicKey::from(&public.0), *m);
                out_ct.copy_from_slice(ct.as_slice());
                *out_ss = ss;
                Ok(())
            }
        }
    };
}

mlkem_key!(
    /// An ML-KEM-512 private key (`libcrux-ml-kem`).
    CruxMlkem512,
    mlkem512,
    800,
    768
);
mlkem_key!(
    /// An ML-KEM-768 private key (`libcrux-ml-kem`).
    CruxMlkem768,
    mlkem768,
    1184,
    1088
);
mlkem_key!(
    /// An ML-KEM-1024 private key (`libcrux-ml-kem`).
    CruxMlkem1024,
    mlkem1024,
    1568,
    1568
);

/// The concatenation of the message parts `msg`.
fn concat(msg: &[&[u8]]) -> Vec<u8> {
    msg.concat()
}

/// Defines the ML-DSA private key `$name` of the `libcrux-ml-dsa` module `$m`,
/// with `$rust` the matching key type of [`tpm2_crypto_rust::pqc`].
macro_rules! mldsa_key {
    (
        $(#[$doc:meta])* $name:ident, $m:ident, $rust:ident, $pub_size:literal, $sig_size:literal
    ) => {
        $(#[$doc])*
        ///
        /// The 32-byte seed `ξ` is zeroized on drop.
        pub struct $name {
            seed: [u8; 32],
            public: CruxPqcPublicKey<$pub_size>,
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.seed.zeroize();
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("public", &self.public)
                    .finish_non_exhaustive()
            }
        }

        impl $name {
            /// The RustCrypto `ml-dsa` key of the seed (expanded for each operation, as an
            /// expanded signing key is large).
            fn rust_key(&self) -> Result<$rust, CryptoError> {
                <$rust as MldsaKey<$pub_size, $sig_size, CruxRng>>::expand(&self.seed)
            }

            /// The RustCrypto `ml-dsa` public key of `public`.
            fn rust_public(
                public: &CruxPqcPublicKey<$pub_size>,
            ) -> Result<<$rust as PrivateKey<$pub_size, 32, CruxRng>>::PublicKey, CryptoError> {
                <$rust as PrivateKey<$pub_size, 32, CruxRng>>::load_public((), &public.0)?
                    .ok_or(CryptoError::Internal)
            }
        }

        impl PrivateKey<$pub_size, 32, CruxRng> for $name {
            type PublicKey = CruxPqcPublicKey<$pub_size>;

            fn generate(rng: &mut CruxRng, _: ()) -> Result<Self, CryptoError> {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed)?;
                let key = <Self as MldsaKey<$pub_size, $sig_size, CruxRng>>::expand(&seed);
                seed.zeroize();
                key
            }

            fn load(
                public: Self::PublicKey,
                private: &[u8; 32],
            ) -> Result<Option<Self>, CryptoError> {
                let key = <Self as MldsaKey<$pub_size, $sig_size, CruxRng>>::expand(private)?;
                Ok(CruxCryptoProvider::ct_eq(&key.public.0, &public.0).then_some(key))
            }

            fn store(&self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
                *out = self.seed;
                Ok(())
            }

            fn as_public(&self) -> &Self::PublicKey {
                &self.public
            }

            /// Every `PUB_SIZE`-byte string is a FIPS 204 encoded public key.
            fn load_public(
                _: (),
                public: &[u8; $pub_size],
            ) -> Result<Option<Self::PublicKey>, CryptoError> {
                Ok(Some(CruxPqcPublicKey(*public)))
            }

            fn store_public(
                public: &Self::PublicKey,
                out: &mut [u8; $pub_size],
            ) -> Result<(), CryptoError> {
                *out = public.0;
                Ok(())
            }
        }

        impl MldsaKey<$pub_size, $sig_size, CruxRng> for $name {
            /// Pure ML-DSA with `libcrux-ml-dsa` (`sign`).
            fn sign_message(
                &self,
                rng: &mut CruxRng,
                context: &[u8],
                msg: &[&[u8]],
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                let mut rnd = [0u8; 32];
                rng.fill_bytes(&mut rnd)?;
                let key_pair = libcrux_ml_dsa::$m::generate_key_pair(self.seed);
                let result =
                    libcrux_ml_dsa::$m::sign(&key_pair.signing_key, &concat(msg), context, rnd);
                rnd.zeroize();
                let sig = result.map_err(|_| CryptoError::Internal)?;
                out_sig.copy_from_slice(sig.as_slice());
                Ok(())
            }

            /// Pure ML-DSA with `libcrux-ml-dsa` (`verify`).
            fn verify_message(
                public: &Self::PublicKey,
                context: &[u8],
                msg: &[&[u8]],
                sig: &[u8; $sig_size],
            ) -> Result<bool, CryptoError> {
                let vk = libcrux_ml_dsa::MLDSAVerificationKey::new(public.0);
                let sig = libcrux_ml_dsa::MLDSASignature::new(*sig);
                Ok(libcrux_ml_dsa::$m::verify(&vk, &concat(msg), context, &sig).is_ok())
            }

            fn sign_mu(
                &self,
                rng: &mut CruxRng,
                mu: &[u8; 64],
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                let mut rnd = [0u8; 32];
                rng.fill_bytes(&mut rnd)?;
                let result = self.sign_mu_internal(&rnd, mu, out_sig);
                rnd.zeroize();
                result
            }

            /// Falls back to RustCrypto `ml-dsa` ([`tpm2_crypto_rust::pqc`]):
            /// `libcrux-ml-dsa` has no verification on an external `mu`.
            fn verify_mu(
                public: &Self::PublicKey,
                mu: &[u8; 64],
                sig: &[u8; $sig_size],
            ) -> Result<bool, CryptoError> {
                <$rust as MldsaKey<$pub_size, $sig_size, CruxRng>>::verify_mu(
                    &Self::rust_public(public)?,
                    mu,
                    sig,
                )
            }

            /// Falls back to RustCrypto `ml-dsa` ([`tpm2_crypto_rust::pqc`]):
            /// `libcrux-ml-dsa` only pre-hashes with SHAKE128.
            fn sign_prehash(
                &self,
                rng: &mut CruxRng,
                context: &[u8],
                digest: TpmtHa<'_>,
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                self.rust_key()?.sign_prehash(rng, context, digest, out_sig)
            }

            /// Falls back to RustCrypto `ml-dsa` ([`tpm2_crypto_rust::pqc`]):
            /// `libcrux-ml-dsa` only pre-hashes with SHAKE128.
            fn verify_prehash(
                public: &Self::PublicKey,
                context: &[u8],
                digest: TpmtHa<'_>,
                sig: &[u8; $sig_size],
            ) -> Result<bool, CryptoError> {
                <$rust as MldsaKey<$pub_size, $sig_size, CruxRng>>::verify_prehash(
                    &Self::rust_public(public)?,
                    context,
                    digest,
                    sig,
                )
            }

            /// `ML-DSA.KeyGen_internal(ξ)` (`generate_key_pair` on the seed `ξ`).
            fn expand(seed: &[u8; 32]) -> Result<Self, CryptoError> {
                let key_pair = libcrux_ml_dsa::$m::generate_key_pair(*seed);
                Ok(Self {
                    seed: *seed,
                    public: CruxPqcPublicKey(*key_pair.verification_key.as_ref()),
                })
            }

            /// Falls back to RustCrypto `ml-dsa` ([`tpm2_crypto_rust::pqc`]):
            /// `libcrux-ml-dsa` has no signing on an external `mu`.
            fn sign_mu_internal(
                &self,
                rnd: &[u8; 32],
                mu: &[u8; 64],
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                <$rust as MldsaKey<$pub_size, $sig_size, CruxRng>>::sign_mu_internal(
                    &self.rust_key()?,
                    rnd,
                    mu,
                    out_sig,
                )
            }
        }
    };
}

mldsa_key!(
    /// An ML-DSA-44 private key (`libcrux-ml-dsa`, with RustCrypto `ml-dsa`
    /// for external `mu` and HashML-DSA).
    CruxMldsa44,
    ml_dsa_44,
    RustCryptoMldsa44,
    1312,
    2420
);
mldsa_key!(
    /// An ML-DSA-65 private key (`libcrux-ml-dsa`, with RustCrypto `ml-dsa`
    /// for external `mu` and HashML-DSA).
    CruxMldsa65,
    ml_dsa_65,
    RustCryptoMldsa65,
    1952,
    3309
);
mldsa_key!(
    /// An ML-DSA-87 private key (`libcrux-ml-dsa`, with RustCrypto `ml-dsa`
    /// for external `mu` and HashML-DSA).
    CruxMldsa87,
    ml_dsa_87,
    RustCryptoMldsa87,
    2592,
    4627
);

#[cfg(test)]
mod tests {
    use super::*;
    use tpm2::crypto::Random as _;

    fn rng(seed: &[u8]) -> CruxRng {
        CruxCryptoProvider::from_seed(seed).unwrap()
    }

    fn check_mlkem<K, const PUB: usize, const CT: usize>()
    where
        K: MlkemKey<PUB, CT, CruxRng, PublicKey = CruxPqcPublicKey<PUB>>,
    {
        // Expansion is deterministic, and generation draws the seed from the RNG.
        let key = K::generate(&mut rng(b"mlkem"), ()).unwrap();
        let mut seed = [0u8; 64];
        key.store(&mut seed).unwrap();
        let mut expected_seed = [0u8; 64];
        rng(b"mlkem").fill_bytes(&mut expected_seed).unwrap();
        assert_eq!(seed, expected_seed);
        let expanded = K::expand(&seed).unwrap();
        assert_eq!(expanded.as_public(), key.as_public());
        let mut public = [0u8; PUB];
        K::store_public(key.as_public(), &mut public).unwrap();
        let loaded_public = || K::load_public((), &public).unwrap().unwrap();
        assert!(K::load(loaded_public(), &seed).unwrap().is_some());
        let mut other_seed = seed;
        other_seed[0] ^= 1;
        assert!(K::load(loaded_public(), &other_seed).unwrap().is_none());

        // Encapsulation round trip, deterministic for a given `m`.
        let (mut ct, mut ss, mut ss2) = ([0u8; CT], [0u8; 32], [0u8; 32]);
        K::encapsulate(&loaded_public(), &mut rng(b"m"), &mut ct, &mut ss).unwrap();
        key.decapsulate(&ct, &mut ss2).unwrap();
        assert_eq!(ss, ss2);
        let mut m = [0u8; 32];
        rng(b"m").fill_bytes(&mut m).unwrap();
        let (mut ct3, mut ss3) = ([0u8; CT], [0u8; 32]);
        K::encapsulate_internal(&loaded_public(), &m, &mut ct3, &mut ss3).unwrap();
        assert_eq!((ct3, ss3), (ct, ss));

        // Implicit rejection: a corrupted ciphertext yields another secret.
        ct[0] ^= 1;
        key.decapsulate(&ct, &mut ss2).unwrap();
        assert_ne!(ss, ss2);

        // The FIPS 203 modulus check: a coefficient of 4095 >= q.
        let mut bad = public;
        bad[0] = 0xff;
        bad[1] |= 0x0f;
        assert!(K::load_public((), &bad).unwrap().is_none());
    }

    #[test]
    fn mlkem() {
        check_mlkem::<CruxMlkem512, 800, 768>();
        check_mlkem::<CruxMlkem768, 1184, 1088>();
        check_mlkem::<CruxMlkem1024, 1568, 1568>();
    }

    fn check_mldsa<K, const PUB: usize, const SIG: usize>()
    where
        K: MldsaKey<PUB, SIG, CruxRng, PublicKey = CruxPqcPublicKey<PUB>>,
    {
        let key = K::generate(&mut rng(b"mldsa"), ()).unwrap();
        let mut seed = [0u8; 32];
        key.store(&mut seed).unwrap();
        assert_eq!(K::expand(&seed).unwrap().as_public(), key.as_public());
        let public = key.as_public();
        assert!(K::load(public.clone(), &seed).unwrap().is_some());
        assert!(K::load(public.clone(), &[0; 32]).unwrap().is_none());

        // Pure ML-DSA with a context string.
        let mut sig = [0u8; SIG];
        let mut entropy = CruxCryptoProvider::from_entropy().unwrap();
        key.sign_message(&mut entropy, b"ctx", &[b"hello ", b"world"], &mut sig)
            .unwrap();
        assert_eq!(
            K::verify_message(public, b"ctx", &[b"hello world"], &sig),
            Ok(true)
        );
        assert_eq!(
            K::verify_message(public, b"", &[b"hello world"], &sig),
            Ok(false)
        );
        assert_eq!(
            K::verify_message(public, b"ctx", &[b"hello"], &sig),
            Ok(false)
        );

        // External `mu`: deterministic for a given `rnd`.
        let mu = [0x5au8; 64];
        let rnd = [7u8; 32];
        let mut sig2 = [0u8; SIG];
        key.sign_mu_internal(&rnd, &mu, &mut sig).unwrap();
        key.sign_mu_internal(&rnd, &mu, &mut sig2).unwrap();
        assert_eq!(sig, sig2);
        assert_eq!(K::verify_mu(public, &mu, &sig), Ok(true));
        assert_eq!(K::verify_mu(public, &[0xa5; 64], &sig), Ok(false));
        key.sign_mu(&mut entropy, &mu, &mut sig2).unwrap();
        assert_eq!(K::verify_mu(public, &mu, &sig2), Ok(true));

        // HashML-DSA.
        let digest = [0x11u8; 32];
        key.sign_prehash(&mut entropy, b"ctx", TpmtHa::Sha256(&digest), &mut sig)
            .unwrap();
        assert_eq!(
            K::verify_prehash(public, b"ctx", TpmtHa::Sha256(&digest), &sig),
            Ok(true)
        );
        assert_eq!(
            K::verify_prehash(public, b"", TpmtHa::Sha256(&digest), &sig),
            Ok(false)
        );
        assert_eq!(
            K::verify_prehash(public, b"ctx", TpmtHa::Sha1(&[0x11; 20]), &sig),
            Err(CryptoError::Unsupported)
        );
    }

    /// Pure ML-DSA signatures of `libcrux-ml-dsa` verify with RustCrypto
    /// `ml-dsa`, and vice versa.
    #[test]
    fn mldsa_matches_rust_crypto() {
        type Rust = RustCryptoMldsa65;
        let key = CruxMldsa65::generate(&mut rng(b"cross"), ()).unwrap();
        let mut public = [0u8; 1952];
        CruxMldsa65::store_public(key.as_public(), &mut public).unwrap();
        let rust_public = <Rust as PrivateKey<1952, 32, CruxRng>>::load_public((), &public)
            .unwrap()
            .unwrap();
        let mut sig = [0u8; 3309];
        let mut entropy = CruxCryptoProvider::from_entropy().unwrap();
        key.sign_message(&mut entropy, b"c", &[b"message"], &mut sig)
            .unwrap();
        assert_eq!(
            <Rust as MldsaKey<1952, 3309, CruxRng>>::verify_message(
                &rust_public,
                b"c",
                &[b"message"],
                &sig
            ),
            Ok(true)
        );
        let mut seed = [0u8; 32];
        key.store(&mut seed).unwrap();
        let rust_key = <Rust as MldsaKey<1952, 3309, CruxRng>>::expand(&seed).unwrap();
        rust_key
            .sign_message(&mut entropy, b"c", &[b"mess", b"age"], &mut sig)
            .unwrap();
        assert_eq!(
            CruxMldsa65::verify_message(key.as_public(), b"c", &[b"message"], &sig),
            Ok(true)
        );
    }

    #[test]
    fn mldsa() {
        check_mldsa::<CruxMldsa44, 1312, 2420>();
        check_mldsa::<CruxMldsa65, 1952, 3309>();
        check_mldsa::<CruxMldsa87, 2592, 4627>();
    }
}
