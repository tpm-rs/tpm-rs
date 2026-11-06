//! ML-KEM (FIPS 203) and ML-DSA (FIPS 204).
//!
//! BoringSSL implements ML-KEM-768/1024 and ML-DSA-44/65/87 ([`crate::bssl`]); the rest falls
//! back to the RustCrypto implementation of `tpm2-crypto-rust` (`ml-kem`, `ml-dsa`):
//!   - ML-KEM-512, which BoringSSL does not implement,
//!   - ML-DSA signing: BoringSSL's public API draws the signing randomness `rnd` itself (its
//!     derandomized signing is internal to its C++ `BCM_*` module), and the TPM supplies `rnd`
//!     from its DRBG, and
//!   - HashML-DSA (signing and verification): BoringSSL implements only pure ML-DSA and
//!     external-`mu` operations.
use tpm2::TpmtHa;
use tpm2::crypto::backend::{Mldsa, MldsaKey, Mlkem, MlkemKey, PrivateKey};
use tpm2::crypto::{CryptoError, Random};
use tpm2_crypto_rust::RustCryptoProvider;

use crate::bssl::{cleanse, mldsa44, mldsa65, mldsa87, mlkem768, mlkem1024};
use crate::{BsslCryptoProvider, BsslRng, output, random_array, verified};

/// The RNG of the RustCrypto fallback.
type RustRng = <RustCryptoProvider as Random>::Rng;

/// A validated encoded public key of `PUB` bytes (an ML-KEM encapsulation key or an ML-DSA
/// verification key) of the BoringSSL parameter set `P`.
pub struct BsslPqcPublicKey<P, const PUB: usize> {
    key: [u8; PUB],
    params: core::marker::PhantomData<fn() -> P>,
}

impl<P, const PUB: usize> BsslPqcPublicKey<P, PUB> {
    fn new(key: [u8; PUB]) -> Self {
        Self {
            key,
            params: core::marker::PhantomData,
        }
    }
}

/// Defines the ML-KEM key type `$name` of the BoringSSL binding module `$module`.
macro_rules! bssl_mlkem {
    ($(#[$m:meta])* $name:ident, $public:ident, $module:ident, $pub_size:literal, $ct_size:literal) => {
        $(#[$m])*
        ///
        /// The private key is the 64-byte seed `d || z` (cleansed on drop) with its encapsulation
        /// key.
        pub struct $name {
            seed: [u8; 64],
            public: $public,
        }

        #[doc = concat!("A validated encapsulation key of [`", stringify!($name), "`].")]
        pub type $public = BsslPqcPublicKey<$name, $pub_size>;

        impl Drop for $name {
            fn drop(&mut self) {
                cleanse(&mut self.seed);
            }
        }

        impl PrivateKey<$pub_size, 64, BsslRng> for $name {
            type PublicKey = $public;

            fn generate(rng: &mut BsslRng, _: ()) -> Result<Self, CryptoError> {
                let mut seed = random_array::<64>(rng);
                let key = Self::expand(&seed);
                cleanse(&mut seed);
                key
            }

            fn load(public: $public, private: &[u8; 64]) -> Result<Option<Self>, CryptoError> {
                let key = Self::expand(private)?;
                Ok((key.public.key == public.key).then_some(key))
            }

            fn store(&self, out: &mut [u8; 64]) -> Result<(), CryptoError> {
                *out = self.seed;
                Ok(())
            }

            fn as_public(&self) -> &$public {
                &self.public
            }

            fn load_public(_: (), public: &[u8; $pub_size]) -> Result<Option<$public>, CryptoError> {
                Ok(output($module::check_public_key(public))?.map(|()| BsslPqcPublicKey::new(*public)))
            }

            fn store_public(public: &$public, out: &mut [u8; $pub_size]) -> Result<(), CryptoError> {
                *out = public.key;
                Ok(())
            }
        }

        impl MlkemKey<$pub_size, $ct_size, BsslRng> for $name {
            fn encapsulate(
                public: &$public,
                rng: &mut BsslRng,
                out_ct: &mut [u8; $ct_size],
                out_ss: &mut [u8; 32],
            ) -> Result<(), CryptoError> {
                let mut m = random_array::<32>(rng);
                let result = Self::encapsulate_internal(public, &m, out_ct, out_ss);
                cleanse(&mut m);
                result
            }

            fn decapsulate(&self, ct: &[u8; $ct_size], out_ss: &mut [u8; 32]) -> Result<(), CryptoError> {
                $module::decapsulate(&self.seed, ct, out_ss).map_err(Into::into)
            }

            fn expand(seed: &[u8; 64]) -> Result<Self, CryptoError> {
                let mut public = [0u8; $pub_size];
                $module::public_key_from_seed(seed, &mut public)?;
                Ok(Self {
                    seed: *seed,
                    public: BsslPqcPublicKey::new(public),
                })
            }

            /// Encapsulates with `EVP_KEM_encap_external_entropy_for_testing`, BoringSSL's only
            /// public derandomized encapsulation (the TPM draws `m` from its DRBG, as the TCG
            /// reference does).
            fn encapsulate_internal(
                public: &$public,
                m: &[u8; 32],
                out_ct: &mut [u8; $ct_size],
                out_ss: &mut [u8; 32],
            ) -> Result<(), CryptoError> {
                // The key was validated by `load_public`.
                $module::encapsulate(&public.key, m, out_ct, out_ss).map_err(Into::into)
            }
        }
    };
}

bssl_mlkem!(
    /// ML-KEM-768 keys for `BsslCryptoProvider` (BoringSSL `MLKEM768_*`).
    BsslMlkem768,
    BsslMlkem768PublicKey,
    mlkem768,
    1184,
    1088
);
bssl_mlkem!(
    /// ML-KEM-1024 keys for `BsslCryptoProvider` (BoringSSL `MLKEM1024_*`).
    BsslMlkem1024,
    BsslMlkem1024PublicKey,
    mlkem1024,
    1568,
    1568
);

/// The ML-KEM-512 key of the RustCrypto fallback.
type RustMlkem512 = <RustCryptoProvider as Mlkem>::Mlkem512;

/// ML-KEM-512 keys for `BsslCryptoProvider`, which BoringSSL does not implement: a wrapper of the
/// RustCrypto `ml-kem` key of `tpm2-crypto-rust`, whose randomness (the seed `d || z` of
/// generated keys and `m` of encapsulations) comes from the `BsslCryptoProvider` RNG.
pub struct BsslMlkem512(RustMlkem512);

impl PrivateKey<800, 64, BsslRng> for BsslMlkem512 {
    type PublicKey = <RustMlkem512 as PrivateKey<800, 64, RustRng>>::PublicKey;

    fn generate(rng: &mut BsslRng, _: ()) -> Result<Self, CryptoError> {
        let mut seed = random_array::<64>(rng);
        let key = Self::expand(&seed);
        cleanse(&mut seed);
        key
    }

    fn load(public: Self::PublicKey, private: &[u8; 64]) -> Result<Option<Self>, CryptoError> {
        Ok(<RustMlkem512 as PrivateKey<800, 64, RustRng>>::load(public, private)?.map(Self))
    }

    fn store(&self, out: &mut [u8; 64]) -> Result<(), CryptoError> {
        <RustMlkem512 as PrivateKey<800, 64, RustRng>>::store(&self.0, out)
    }

    fn as_public(&self) -> &Self::PublicKey {
        <RustMlkem512 as PrivateKey<800, 64, RustRng>>::as_public(&self.0)
    }

    fn load_public(_: (), public: &[u8; 800]) -> Result<Option<Self::PublicKey>, CryptoError> {
        <RustMlkem512 as PrivateKey<800, 64, RustRng>>::load_public((), public)
    }

    fn store_public(public: &Self::PublicKey, out: &mut [u8; 800]) -> Result<(), CryptoError> {
        <RustMlkem512 as PrivateKey<800, 64, RustRng>>::store_public(public, out)
    }
}

impl MlkemKey<800, 768, BsslRng> for BsslMlkem512 {
    fn encapsulate(
        public: &Self::PublicKey,
        rng: &mut BsslRng,
        out_ct: &mut [u8; 768],
        out_ss: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        let mut m = random_array::<32>(rng);
        let result = Self::encapsulate_internal(public, &m, out_ct, out_ss);
        cleanse(&mut m);
        result
    }

    fn decapsulate(&self, ct: &[u8; 768], out_ss: &mut [u8; 32]) -> Result<(), CryptoError> {
        <RustMlkem512 as MlkemKey<800, 768, RustRng>>::decapsulate(&self.0, ct, out_ss)
    }

    fn expand(seed: &[u8; 64]) -> Result<Self, CryptoError> {
        <RustMlkem512 as MlkemKey<800, 768, RustRng>>::expand(seed).map(Self)
    }

    fn encapsulate_internal(
        public: &Self::PublicKey,
        m: &[u8; 32],
        out_ct: &mut [u8; 768],
        out_ss: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        <RustMlkem512 as MlkemKey<800, 768, RustRng>>::encapsulate_internal(
            public, m, out_ct, out_ss,
        )
    }
}

/// ML-KEM-768/1024 with BoringSSL; ML-KEM-512 with RustCrypto `ml-kem`.
impl Mlkem for BsslCryptoProvider {
    type Mlkem512 = BsslMlkem512;
    type Mlkem768 = BsslMlkem768;
    type Mlkem1024 = BsslMlkem1024;
}

/// Defines the ML-DSA key type `$name` of the BoringSSL binding module `$module`, with the
/// RustCrypto key `$rust` (of `tpm2-crypto-rust`) for signing and HashML-DSA.
macro_rules! bssl_mldsa {
    (
        $(#[$m:meta])* $name:ident, $public:ident, $module:ident, $rust:ident,
        $pub_size:literal, $sig_size:literal
    ) => {
        $(#[$m])*
        ///
        /// The private key is the 32-byte seed `xi` (cleansed on drop) with its verification key.
        pub struct $name {
            seed: [u8; 32],
            public: $public,
        }

        #[doc = concat!("A validated verification key of [`", stringify!($name), "`].")]
        pub type $public = BsslPqcPublicKey<$name, $pub_size>;

        impl Drop for $name {
            fn drop(&mut self) {
                cleanse(&mut self.seed);
            }
        }

        impl $name {
            /// Expands the RustCrypto key of the seed, for signing.
            fn rust_key(&self) -> Result<<RustCryptoProvider as Mldsa>::$rust, CryptoError> {
                <<RustCryptoProvider as Mldsa>::$rust as MldsaKey<$pub_size, $sig_size, RustRng>>::expand(
                    &self.seed,
                )
            }
        }

        impl PrivateKey<$pub_size, 32, BsslRng> for $name {
            type PublicKey = $public;

            fn generate(rng: &mut BsslRng, _: ()) -> Result<Self, CryptoError> {
                let mut seed = random_array::<32>(rng);
                let key = Self::expand(&seed);
                cleanse(&mut seed);
                key
            }

            fn load(public: $public, private: &[u8; 32]) -> Result<Option<Self>, CryptoError> {
                let key = Self::expand(private)?;
                Ok((key.public.key == public.key).then_some(key))
            }

            fn store(&self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
                *out = self.seed;
                Ok(())
            }

            fn as_public(&self) -> &$public {
                &self.public
            }

            fn load_public(_: (), public: &[u8; $pub_size]) -> Result<Option<$public>, CryptoError> {
                Ok(output($module::check_public_key(public))?.map(|()| BsslPqcPublicKey::new(*public)))
            }

            fn store_public(public: &$public, out: &mut [u8; $pub_size]) -> Result<(), CryptoError> {
                *out = public.key;
                Ok(())
            }
        }

        impl MldsaKey<$pub_size, $sig_size, BsslRng> for $name {
            /// Computes `mu` with BoringSSL and signs it as [`sign_mu`](Self::sign_mu).
            fn sign_message(
                &self,
                rng: &mut BsslRng,
                context: &[u8],
                msg: &[&[u8]],
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                let mut mu = [0u8; 64];
                $module::mu(&self.public.key, context, msg, &mut mu)?;
                self.sign_mu(rng, &mu, out_sig)
            }

            fn verify_message(
                public: &$public,
                context: &[u8],
                msg: &[&[u8]],
                sig: &[u8; $sig_size],
            ) -> Result<bool, CryptoError> {
                let mut mu = [0u8; 64];
                if output($module::mu(&public.key, context, msg, &mut mu))?.is_none() {
                    return Ok(false);
                }
                Self::verify_mu(public, &mu, sig)
            }

            fn sign_mu(
                &self,
                rng: &mut BsslRng,
                mu: &[u8; 64],
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                let mut rnd = random_array::<32>(rng);
                let result = self.sign_mu_internal(&rnd, mu, out_sig);
                cleanse(&mut rnd);
                result
            }

            fn verify_mu(
                public: &$public,
                mu: &[u8; 64],
                sig: &[u8; $sig_size],
            ) -> Result<bool, CryptoError> {
                verified($module::verify_mu(&public.key, mu, sig))
            }

            /// Falls back to RustCrypto `ml-dsa`, with its RNG seeded from `rng`.
            fn sign_prehash(
                &self,
                rng: &mut BsslRng,
                context: &[u8],
                digest: TpmtHa<'_>,
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                let mut seed = random_array::<32>(rng);
                let rust_rng = RustCryptoProvider::from_seed(&seed);
                cleanse(&mut seed);
                <<RustCryptoProvider as Mldsa>::$rust as MldsaKey<$pub_size, $sig_size, RustRng>>::sign_prehash(
                    &self.rust_key()?,
                    &mut rust_rng?,
                    context,
                    digest,
                    out_sig,
                )
            }

            /// Falls back to RustCrypto `ml-dsa`.
            fn verify_prehash(
                public: &$public,
                context: &[u8],
                digest: TpmtHa<'_>,
                sig: &[u8; $sig_size],
            ) -> Result<bool, CryptoError> {
                type Rust = <RustCryptoProvider as Mldsa>::$rust;
                let Some(public) = <Rust as PrivateKey<$pub_size, 32, RustRng>>::load_public((), &public.key)? else {
                    return Ok(false);
                };
                <Rust as MldsaKey<$pub_size, $sig_size, RustRng>>::verify_prehash(&public, context, digest, sig)
            }

            fn expand(seed: &[u8; 32]) -> Result<Self, CryptoError> {
                let mut public = [0u8; $pub_size];
                $module::public_key_from_seed(seed, &mut public)?;
                Ok(Self {
                    seed: *seed,
                    public: BsslPqcPublicKey::new(public),
                })
            }

            /// Falls back to RustCrypto `ml-dsa`: BoringSSL has no public signing with a
            /// caller-supplied `rnd`.
            fn sign_mu_internal(
                &self,
                rnd: &[u8; 32],
                mu: &[u8; 64],
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                <<RustCryptoProvider as Mldsa>::$rust as MldsaKey<$pub_size, $sig_size, RustRng>>::sign_mu_internal(
                    &self.rust_key()?,
                    rnd,
                    mu,
                    out_sig,
                )
            }
        }
    };
}

bssl_mldsa!(
    /// ML-DSA-44 keys for `BsslCryptoProvider` (BoringSSL `MLDSA44_*`; signing with RustCrypto
    /// `ml-dsa`).
    BsslMldsa44,
    BsslMldsa44PublicKey,
    mldsa44,
    Mldsa44,
    1312,
    2420
);
bssl_mldsa!(
    /// ML-DSA-65 keys for `BsslCryptoProvider` (BoringSSL `MLDSA65_*`; signing with RustCrypto
    /// `ml-dsa`).
    BsslMldsa65,
    BsslMldsa65PublicKey,
    mldsa65,
    Mldsa65,
    1952,
    3309
);
bssl_mldsa!(
    /// ML-DSA-87 keys for `BsslCryptoProvider` (BoringSSL `MLDSA87_*`; signing with RustCrypto
    /// `ml-dsa`).
    BsslMldsa87,
    BsslMldsa87PublicKey,
    mldsa87,
    Mldsa87,
    2592,
    4627
);

/// ML-DSA-44/65/87: key generation, `mu` and verification with BoringSSL, signing and
/// HashML-DSA with RustCrypto `ml-dsa` (with the TPM's `rnd`).
impl Mldsa for BsslCryptoProvider {
    type Mldsa44 = BsslMldsa44;
    type Mldsa65 = BsslMldsa65;
    type Mldsa87 = BsslMldsa87;
}
