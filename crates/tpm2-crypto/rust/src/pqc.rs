//! ML-KEM (FIPS 203) and ML-DSA (FIPS 204) with the RustCrypto `ml-kem` and `ml-dsa` crates.
//!
//! The key types of this module implement [`MlkemKey`] and [`MldsaKey`] (with the tpm-rs
//! extensions `expand`, `encapsulate_internal` and `sign_mu_internal`) for all three parameter
//! sets of each algorithm and for any random number generator, so that the other backends can
//! bind their associated types to them where their own library lacks a parameter set or an
//! operation.
//!
//! ML-DSA computes the message representative `µ` itself (FIPS 204, Algorithm 7 line 6, and
//! Algorithms 2 and 4 for pure ML-DSA and HashML-DSA) and signs it with
//! `ExpandedSigningKey::sign_mu_randomized`, with the signing randomness `rnd` drawn from the
//! TPM's random number generator.
use ml_dsa::common::array::Array;
use ml_dsa::signature::Keypair as _;
use ml_dsa::signature::rand_core::{TryCryptoRng, TryRng};
use ml_dsa::{ExpandedSigningKey, MlDsa44, MlDsa65, MlDsa87, Signature, SigningKey, VerifyingKey};
use ml_kem::{Decapsulate as _, DecapsulationKey, EncapsulationKey, KeyExport as _};
use ml_kem::{MlKem512, MlKem768, MlKem1024};
use shake::{ExtendableOutput as _, Shake256, Update as _};
use subtle::ConstantTimeEq as _;
use tpm2::TpmiAlgHash;
use tpm2::TpmtHa;
use tpm2::crypto::backend::{Mldsa, MldsaKey, Mlkem, MlkemKey, PrivateKey};
use tpm2::crypto::{CryptoError, Rng};
use zeroize::Zeroize as _;

use crate::RustCryptoProvider;

/// Copies `src` into `out`, which must have the same length ([`CryptoError::Internal`]
/// otherwise).
fn copy_out(src: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    if src.len() != out.len() {
        return Err(CryptoError::Internal);
    }
    out.copy_from_slice(src);
    Ok(())
}

/// Defines the key types of an ML-KEM parameter set and implements [`MlkemKey`] for them.
macro_rules! mlkem_key {
    ($(#[$m:meta])* $name:ident, $public:ident, $P:ty, $pub_size:literal, $ct_size:literal) => {
        #[doc = concat!("A validated encapsulation key of `", stringify!($P), "`.")]
        #[derive(Clone, Debug, PartialEq)]
        pub struct $public(EncapsulationKey<$P>);

        $(#[$m])*
        ///
        /// It holds the 64-byte seed `d || z` and the expanded decapsulation key; both are
        /// zeroized on drop.
        pub struct $name {
            seed: [u8; 64],
            dk: DecapsulationKey<$P>,
            public: $public,
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.seed.zeroize();
            }
        }

        impl $name {
            /// `ML-KEM.KeyGen_internal(d, z)` of the seed `d || z`.
            fn from_seed(seed: &[u8; 64]) -> Self {
                let dk = DecapsulationKey::<$P>::from_seed(Array::from(*seed));
                let public = $public(dk.encapsulation_key().clone());
                Self {
                    seed: *seed,
                    dk,
                    public,
                }
            }
        }

        impl<R: Rng> PrivateKey<$pub_size, 64, R> for $name {
            type PublicKey = $public;

            fn generate(rng: &mut R, _: ()) -> Result<Self, CryptoError> {
                let mut seed = [0u8; 64];
                rng.fill_bytes(&mut seed)?;
                let key = Self::from_seed(&seed);
                seed.zeroize();
                Ok(key)
            }

            fn load(public: $public, seed: &[u8; 64]) -> Result<Option<Self>, CryptoError> {
                let key = Self::from_seed(seed);
                let matches = key.public.0.to_bytes()[..].ct_eq(&public.0.to_bytes()[..]);
                Ok(bool::from(matches).then_some(key))
            }

            fn store(&self, out: &mut [u8; 64]) -> Result<(), CryptoError> {
                *out = self.seed;
                Ok(())
            }

            fn as_public(&self) -> &$public {
                &self.public
            }

            /// `None` if the encapsulation key fails the modulus check of FIPS 203, Section
            /// 7.2 (`EncapsulationKey::new`).
            fn load_public(_: (), public: &[u8; $pub_size]) -> Result<Option<$public>, CryptoError> {
                let encoded = Array::try_from(&public[..]).map_err(|_| CryptoError::Internal)?;
                Ok(EncapsulationKey::<$P>::new(&encoded).ok().map($public))
            }

            fn store_public(public: &$public, out: &mut [u8; $pub_size]) -> Result<(), CryptoError> {
                copy_out(&public.0.to_bytes(), out)
            }
        }

        impl<R: Rng> MlkemKey<$pub_size, $ct_size, R> for $name {
            fn encapsulate(
                public: &$public,
                rng: &mut R,
                out_ct: &mut [u8; $ct_size],
                out_ss: &mut [u8; 32],
            ) -> Result<(), CryptoError> {
                let mut m = [0u8; 32];
                rng.fill_bytes(&mut m)?;
                let result = <Self as MlkemKey<$pub_size, $ct_size, R>>::encapsulate_internal(
                    public, &m, out_ct, out_ss,
                );
                m.zeroize();
                result
            }

            /// `ML-KEM.Decaps` (with implicit rejection).
            fn decapsulate(
                &self,
                ct: &[u8; $ct_size],
                out_ss: &mut [u8; 32],
            ) -> Result<(), CryptoError> {
                let ct = Array::try_from(&ct[..]).map_err(|_| CryptoError::Internal)?;
                copy_out(&self.dk.decapsulate(&ct), out_ss)
            }

            fn expand(seed: &[u8; 64]) -> Result<Self, CryptoError> {
                Ok(Self::from_seed(seed))
            }

            /// `ML-KEM.Encaps_internal(ek, m)` (`encapsulate_deterministic`).
            fn encapsulate_internal(
                public: &$public,
                m: &[u8; 32],
                out_ct: &mut [u8; $ct_size],
                out_ss: &mut [u8; 32],
            ) -> Result<(), CryptoError> {
                let (ct, ss) = public.0.encapsulate_deterministic(&Array::from(*m));
                copy_out(&ct, out_ct)?;
                copy_out(&ss, out_ss)
            }
        }
    };
}

mlkem_key!(
    /// An ML-KEM-512 key (`ml-kem`).
    RustCryptoMlkem512,
    RustCryptoMlkem512Public,
    MlKem512,
    800,
    768
);
mlkem_key!(
    /// An ML-KEM-768 key (`ml-kem`).
    RustCryptoMlkem768,
    RustCryptoMlkem768Public,
    MlKem768,
    1184,
    1088
);
mlkem_key!(
    /// An ML-KEM-1024 key (`ml-kem`).
    RustCryptoMlkem1024,
    RustCryptoMlkem1024Public,
    MlKem1024,
    1568,
    1568
);

/// A random number generator that yields the 32-byte signing randomness `rnd` exactly once.
///
/// `ml-dsa` exposes `ML-DSA.Sign_internal` on `mu` only with an RNG
/// ([`ExpandedSigningKey::sign_mu_randomized`]), which draws `rnd` with a single 32-byte
/// `try_fill_bytes`; any other request fails.
struct OneShotRnd<'a>(Option<&'a [u8; 32]>);

/// The error of [`OneShotRnd`] for any request other than the single 32-byte fill.
#[derive(Debug)]
struct RndExhausted;

impl core::fmt::Display for RndExhausted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the ML-DSA signing randomness was already used")
    }
}

impl core::error::Error for RndExhausted {}

impl TryRng for OneShotRnd<'_> {
    type Error = RndExhausted;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(RndExhausted)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(RndExhausted)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        match self.0.take() {
            Some(rnd) if dst.len() == rnd.len() => {
                dst.copy_from_slice(rnd);
                Ok(())
            }
            _ => Err(RndExhausted),
        }
    }
}

impl TryCryptoRng for OneShotRnd<'_> {}

/// `SHAKE256` of the concatenation of `parts`, `N` output bytes (FIPS 204 `H`).
fn shake256<const N: usize>(parts: &[&[u8]]) -> [u8; N] {
    let mut h = Shake256::default();
    for part in parts {
        h.update(part);
    }
    let mut out = [0u8; N];
    h.finalize_xof_into(&mut out);
    out
}

/// The DER encoding of the OID of the HashML-DSA prehash algorithm `hash` (FIPS 204,
/// Algorithm 4): SHA-256, SHA-384 or SHA-512 (`Unsupported` for the others).
fn prehash_oid(hash: TpmiAlgHash) -> Result<[u8; 11], CryptoError> {
    let last = match hash {
        TpmiAlgHash::Sha256 => 0x01,
        TpmiAlgHash::Sha384 => 0x02,
        #[cfg(feature = "sha512")]
        TpmiAlgHash::Sha512 => 0x03,
        #[allow(unreachable_patterns)]
        _ => return Err(CryptoError::Unsupported),
    };
    Ok([
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, last,
    ])
}

/// Defines the key types of an ML-DSA parameter set and implements [`MldsaKey`] for them.
macro_rules! mldsa_key {
    ($(#[$m:meta])* $name:ident, $public:ident, $P:ty, $pub_size:literal, $sig_size:literal) => {
        #[doc = concat!("A public key of `", stringify!($P), "`, with its hash `tr`.")]
        #[derive(Clone, Debug, PartialEq)]
        pub struct $public {
            vk: VerifyingKey<$P>,
            tr: [u8; 64],
        }

        impl $public {
            /// Wraps `vk`, computing `tr = H(pk, 64)`.
            fn new(vk: VerifyingKey<$P>) -> Self {
                let tr = shake256(&[&vk.encode()]);
                Self { vk, tr }
            }

            /// `µ = H(tr || M', 64)`, where `M'` is the concatenation of `parts`.
            fn mu(&self, parts: &[&[u8]]) -> [u8; 64] {
                let mut h = Shake256::default();
                h.update(&self.tr);
                for part in parts {
                    h.update(part);
                }
                let mut mu = [0u8; 64];
                h.finalize_xof_into(&mut mu);
                mu
            }

            /// `µ` of the pure ML-DSA message `msg` with context `context` (FIPS 204,
            /// Algorithm 2 line 10): `None` if `context` is longer than 255 bytes.
            fn message_mu(&self, context: &[u8], msg: &[&[u8]]) -> Option<[u8; 64]> {
                let len = u8::try_from(context.len()).ok()?;
                let mut h = Shake256::default();
                h.update(&self.tr);
                h.update(&[0, len]);
                h.update(context);
                for part in msg {
                    h.update(part);
                }
                let mut mu = [0u8; 64];
                h.finalize_xof_into(&mut mu);
                Some(mu)
            }

            /// `µ` of the HashML-DSA prehash `digest` with context `context` (FIPS 204,
            /// Algorithm 4 line 23): `None` if `context` is longer than 255 bytes.
            fn prehash_mu(
                &self,
                context: &[u8],
                digest: TpmtHa<'_>,
            ) -> Result<Option<[u8; 64]>, CryptoError> {
                let oid = prehash_oid(digest.hash_alg())?;
                let Ok(len) = u8::try_from(context.len()) else {
                    return Ok(None);
                };
                Ok(Some(self.mu(&[&[1, len], context, &oid, digest.digest()])))
            }

            /// `ML-DSA.Verify_internal` on `µ`: `false` for a malformed signature.
            fn verify_mu(&self, mu: &[u8; 64], sig: &[u8; $sig_size]) -> Result<bool, CryptoError> {
                let encoded = Array::try_from(&sig[..]).map_err(|_| CryptoError::Internal)?;
                // `Signature::decode` rejects malformed hints (`sigDecode`, FIPS 204, Algorithm 8
                // lines 2-4) and `z` out of range (line 13).
                let Some(sig) = Signature::<$P>::decode(&encoded) else {
                    return Ok(false);
                };
                Ok(self.vk.verify_mu(&Array::from(*mu), &sig))
            }
        }

        $(#[$m])*
        ///
        /// It holds the 32-byte seed `ξ` and the expanded signing key; both are zeroized on drop.
        pub struct $name {
            seed: [u8; 32],
            sk: ExpandedSigningKey<$P>,
            public: $public,
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.seed.zeroize();
            }
        }

        impl $name {
            /// `ML-DSA.KeyGen_internal(ξ)` of the seed `ξ`.
            fn from_seed(seed: &[u8; 32]) -> Self {
                let kp = SigningKey::<$P>::from_seed(&Array::from(*seed));
                let public = $public::new(kp.verifying_key());
                Self {
                    seed: *seed,
                    sk: kp.expanded_key().clone(),
                    public,
                }
            }

            /// Draws the signing randomness `rnd` from `rng` and signs `mu`.
            fn sign_mu_with<R: Rng>(
                &self,
                rng: &mut R,
                mu: &[u8; 64],
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                let mut rnd = [0u8; 32];
                rng.fill_bytes(&mut rnd)?;
                let result = <Self as MldsaKey<$pub_size, $sig_size, R>>::sign_mu_internal(
                    self, &rnd, mu, out_sig,
                );
                rnd.zeroize();
                result
            }
        }

        impl<R: Rng> PrivateKey<$pub_size, 32, R> for $name {
            type PublicKey = $public;

            fn generate(rng: &mut R, _: ()) -> Result<Self, CryptoError> {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed)?;
                let key = Self::from_seed(&seed);
                seed.zeroize();
                Ok(key)
            }

            fn load(public: $public, seed: &[u8; 32]) -> Result<Option<Self>, CryptoError> {
                let key = Self::from_seed(seed);
                let matches = key.public.vk.encode()[..].ct_eq(&public.vk.encode()[..]);
                Ok(bool::from(matches).then_some(key))
            }

            fn store(&self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
                *out = self.seed;
                Ok(())
            }

            fn as_public(&self) -> &$public {
                &self.public
            }

            /// `pkDecode` (FIPS 204, Algorithm 23) accepts every encoding.
            fn load_public(_: (), public: &[u8; $pub_size]) -> Result<Option<$public>, CryptoError> {
                let encoded = Array::try_from(&public[..]).map_err(|_| CryptoError::Internal)?;
                Ok(Some($public::new(VerifyingKey::<$P>::decode(&encoded))))
            }

            fn store_public(public: &$public, out: &mut [u8; $pub_size]) -> Result<(), CryptoError> {
                copy_out(&public.vk.encode(), out)
            }
        }

        impl<R: Rng> MldsaKey<$pub_size, $sig_size, R> for $name {
            fn sign_message(
                &self,
                rng: &mut R,
                context: &[u8],
                msg: &[&[u8]],
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                let mu = self.public.message_mu(context, msg).ok_or(CryptoError::Internal)?;
                self.sign_mu_with(rng, &mu, out_sig)
            }

            fn verify_message(
                public: &$public,
                context: &[u8],
                msg: &[&[u8]],
                sig: &[u8; $sig_size],
            ) -> Result<bool, CryptoError> {
                let Some(mu) = public.message_mu(context, msg) else {
                    return Ok(false);
                };
                public.verify_mu(&mu, sig)
            }

            fn sign_mu(
                &self,
                rng: &mut R,
                mu: &[u8; 64],
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                self.sign_mu_with(rng, mu, out_sig)
            }

            fn verify_mu(
                public: &$public,
                mu: &[u8; 64],
                sig: &[u8; $sig_size],
            ) -> Result<bool, CryptoError> {
                public.verify_mu(mu, sig)
            }

            fn sign_prehash(
                &self,
                rng: &mut R,
                context: &[u8],
                digest: TpmtHa<'_>,
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                let mu = self
                    .public
                    .prehash_mu(context, digest)?
                    .ok_or(CryptoError::Internal)?;
                self.sign_mu_with(rng, &mu, out_sig)
            }

            fn verify_prehash(
                public: &$public,
                context: &[u8],
                digest: TpmtHa<'_>,
                sig: &[u8; $sig_size],
            ) -> Result<bool, CryptoError> {
                let Some(mu) = public.prehash_mu(context, digest)? else {
                    return Ok(false);
                };
                public.verify_mu(&mu, sig)
            }

            fn expand(seed: &[u8; 32]) -> Result<Self, CryptoError> {
                Ok(Self::from_seed(seed))
            }

            /// `ML-DSA.Sign_internal` from line 7 on (external `µ`) with `ml-dsa`, which fails
            /// (`Internal`) only when its rejection sampling gives up.
            fn sign_mu_internal(
                &self,
                rnd: &[u8; 32],
                mu: &[u8; 64],
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                let sig = self
                    .sk
                    .sign_mu_randomized(&Array::from(*mu), &mut OneShotRnd(Some(rnd)))
                    .map_err(|_| CryptoError::Internal)?;
                copy_out(&sig.encode(), out_sig)
            }
        }
    };
}

mldsa_key!(
    /// An ML-DSA-44 key (`ml-dsa`).
    RustCryptoMldsa44,
    RustCryptoMldsa44Public,
    MlDsa44,
    1312,
    2420
);
mldsa_key!(
    /// An ML-DSA-65 key (`ml-dsa`).
    RustCryptoMldsa65,
    RustCryptoMldsa65Public,
    MlDsa65,
    1952,
    3309
);
mldsa_key!(
    /// An ML-DSA-87 key (`ml-dsa`).
    RustCryptoMldsa87,
    RustCryptoMldsa87Public,
    MlDsa87,
    2592,
    4627
);

/// ML-KEM for all three parameter sets (`ml-kem`).
impl Mlkem for RustCryptoProvider {
    type Mlkem512 = RustCryptoMlkem512;
    type Mlkem768 = RustCryptoMlkem768;
    type Mlkem1024 = RustCryptoMlkem1024;
}

/// ML-DSA for all three parameter sets (`ml-dsa`).
impl Mldsa for RustCryptoProvider {
    type Mldsa44 = RustCryptoMldsa44;
    type Mldsa65 = RustCryptoMldsa65;
    type Mldsa87 = RustCryptoMldsa87;
}
