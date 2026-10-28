//! Cryptographic Dispatch Functions
//!
//! This module contains dispatch functions (and enums) used by TPM
//! implementations and clients to call into [`Crypto`] backends. These
//! functions select an algorithm at runtime (e.g. via
//! [`TpmiAlgHash`](crate::TpmiAlgHash)) and dispatch to the corresponding
//! algorithm's implementation.
//!
//! Users should generally use `C: Crypto` bounds for code that is generic
//! over cryptographic backends.
//!
//! ## One-shot functions
//!
//! Most use-cases can use the simple "one-shot" functions for:
//! - Hashing: [`hash`](hash::hash)
//! - HMACs: [`hmac`](hmac::hmac)
//! - KDFs: [`kdfa`], [`kdfa_xor`], [`kdfe`]
//! - Encryption and Decryption: [`SymmetricKey::crypt`]
//! - CMACs: [`SymmetricKey::cmac`]
//! - Random bytes: [`Random::rand_bytes`]
//! - Signing: [`sign`] (digests) and [`sign_message`]
//! - Signature Verification: [`verify`] (digests) and [`verify_message`]
//!
//! ## Stateful `enum`s and RNG
//!
//! When cryptographic context must persist across commands, this module also
//! provides stateful dispatch enums with methods that use/mutate the state:
//! - Hashing: [`HashContext`]
//! - HMACs: [`HmacContext`]
//! - Encryption and Decryption: [`SymmetricContext`]
//! - CMACs: [`CmacContext`]
//! - Random number generation: [`Rng`] (created via [`Random::from_entropy`] or
//!   [`Random::from_seed`])
//! - Signing: [`SigningKey`]
//! - Signature Verification: [`VerifyingKey`]
//! - RSA: [`RsaPublicKey`] (`encrypt`) and [`RsaPrivateKey`] (`decrypt`)
//! - ECC: [`EccPublicKey`] and [`EccPrivateKey`] (`ecdh`)
//! - ML-DSA: [`MldsaPublicKey`] and [`MldsaPrivateKey`]
//! - ML-KEM: [`MlkemPublicKey`] (`encapsulate`) and [`MlkemPrivateKey`]
//!   (`decapsulate`)
//!
//! For stack usage and code size guidance, see the
//! [backend optimization notes](backend#optimization-notes).

#[cfg(feature = "cmac")]
mod cmac;
#[cfg(feature = "ecc")]
mod ecc;
mod hash;
mod hmac;
#[cfg(feature = "mldsa")]
mod mldsa;
#[cfg(feature = "mlkem")]
mod mlkem;
mod rng;
mod rsa;
#[cfg(any(feature = "rsa", feature = "ecc", feature = "mldsa"))]
mod signing;
mod symmetric;

pub mod backend;
#[cfg(feature = "cmac")]
pub use cmac::*;
#[cfg(feature = "ecc")]
pub use ecc::*;
#[cfg(feature = "mldsa")]
pub use mldsa::*;
#[cfg(feature = "mlkem")]
pub use mlkem::*;
#[cfg(any(feature = "rsa", feature = "ecc", feature = "mldsa"))]
pub use signing::*;
pub use {hash::*, hmac::*, rng::*, rsa::*, symmetric::*};

/// Common error type for all cryptographic operations.
///
/// We intentionally don't allow cryptography backends to provide rich error
/// information, as we can't do anything other than enter failure mode when we
/// receive [`CryptoError::Internal`].
///
/// `CryptoError` is not used to reject invalid caller input that a TPM should
/// report with a normal response code. Such checks return an [`Option`] or
/// [`bool`] instead (e.g. [`SymmetricKey::new`], an off-curve ECC point, invalid
/// RSA padding, or a [`verify`] failure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// The requested algorithm, mode, scheme, exponent, or key size is
    /// unsupported.
    Unsupported,
    /// An internal error, which puts the TPM into failure mode.
    Internal,
}

/// A complete cryptography backend.
///
/// Backends implement [`Random`], the [`backend`] family traits, and then this
/// trait. Generic code should use a `C: Crypto` bound rather than naming the
/// backend traits directly.
pub trait Crypto:
    Random
    + backend::Hash
    + backend::Hmac
    + backend::Cmac
    + backend::Symmetric
    + backend::Rsa
    + backend::Ecc
    + backend::Mldsa
    + backend::Mlkem
{
    /// Returns `a == b`, in time independent of the slice contents.
    fn ct_eq(a: &[u8], b: &[u8]) -> bool;
}

// Internal helpers

/// Left-pads a non-empty big-endian integer slice (`1 <= src.len() <= N`) with
/// `0x00` bytes into an `N`-byte array, returning `None` if `src` is empty or
/// longer than `N`.
#[cfg(any(feature = "rsa", feature = "ecc"))]
// Unused if `ecc` is enabled without `rsa` or any Weierstrass curve.
#[cfg_attr(not(feature = "rsa"), allow(dead_code))]
pub(crate) fn left_pad_be<const N: usize>(src: &[u8]) -> Option<[u8; N]> {
    if src.is_empty() || src.len() > N {
        return None;
    }
    let mut out = [0u8; N];
    out[N - src.len()..].copy_from_slice(src);
    Some(out)
}

// Internal helper macros

/// Generates a `match` with one arm per enabled variant of an algorithm enum.
///
/// The first arm is a template: `$Alg` is replaced with each variant name. Its
/// pattern must be a path ending in `$Alg` (optionally followed by `(..)`), and
/// its body must be a `{ .. }` block. Arms after it (following a `,`) are
/// copied unchanged, e.g. for variants outside the algorithm family:
///
/// ```ignore
/// match_ecc_curve!(match self {
///     Self::$Alg(_) => { TpmEccCurve::$Alg },
///     Self::X25519(_) => TpmEccCurve::Curve25519,
/// })
/// ```
///
/// The scrutinee must be a single token tree, e.g. `self` or `(*self)`.
macro_rules! match_variants {
    (
        [$($(#[$m:meta])* $V:ident),* $(,)?]
        match $v:tt {
            $($p:ident ::)+ $d:tt $Alg:ident $(($($f:tt)*))? => $body:tt
            $(, $($extra:tt)*)?
        }
    ) => {{
        // `$d` is the caller's `$`, needed to declare the inner macro's metavariables.
        macro_rules! match_arms {
            ($d($d(#[$d m:meta])* $d $Alg:ident),*) => {
                match $v {
                    $d($d(#[$d m])* $($p ::)+ $d $Alg $(($($f)*))? => $body,)*
                    $($($extra)*)?
                }
            };
        }
        match_arms!($($(#[$m])* $V),*)
    }};
}

/// [`match_variants`] over the [`TpmiAlgHash`](crate::TpmiAlgHash) variants.
macro_rules! match_hash_alg {
    ($($t:tt)*) => {
        $crate::crypto::match_variants!([
            #[cfg(feature = "sha1")] Sha1,
            #[cfg(feature = "sha256")] Sha256,
            #[cfg(feature = "sha384")] Sha384,
            #[cfg(feature = "sha512")] Sha512,
            #[cfg(feature = "sm3_256")] Sm3_256,
            #[cfg(feature = "sha3_256")] Sha3_256,
            #[cfg(feature = "sha3_384")] Sha3_384,
            #[cfg(feature = "sha3_512")] Sha3_512,
        ] $($t)*)
    };
}

/// [`match_variants`] over the [`AlgSym`](crate::AlgSym) variants.
macro_rules! match_sym_alg {
    ($($t:tt)*) => {
        $crate::crypto::match_variants!([
            #[cfg(feature = "aes128")] Aes128,
            #[cfg(feature = "aes192")] Aes192,
            #[cfg(feature = "aes256")] Aes256,
            #[cfg(feature = "sm4_128")] Sm4_128,
            #[cfg(feature = "camellia128")] Camellia128,
            #[cfg(feature = "camellia192")] Camellia192,
            #[cfg(feature = "camellia256")] Camellia256,
        ] $($t)*)
    };
}

/// [`match_variants`] over the [`TpmiRsaKeyBits`](crate::TpmiRsaKeyBits)
/// variants.
#[cfg(feature = "rsa")]
macro_rules! match_rsa_bits {
    ($($t:tt)*) => {
        $crate::crypto::match_variants!([
            #[cfg(feature = "rsa1024")] Rsa1024,
            #[cfg(feature = "rsa2048")] Rsa2048,
            #[cfg(feature = "rsa3072")] Rsa3072,
            #[cfg(feature = "rsa4096")] Rsa4096,
        ] $($t)*)
    };
}
#[cfg(feature = "rsa")]
use match_rsa_bits;

/// [`match_variants`] over the Weierstrass [`TpmEccCurve`](crate::TpmEccCurve)
/// variants.
#[cfg(feature = "ecc")]
macro_rules! match_ecc_curve {
    ($($t:tt)*) => {
        $crate::crypto::match_variants!([
            #[cfg(feature = "nist_p192")] NistP192,
            #[cfg(feature = "nist_p224")] NistP224,
            #[cfg(feature = "nist_p256")] NistP256,
            #[cfg(feature = "nist_p384")] NistP384,
            #[cfg(feature = "nist_p521")] NistP521,
            #[cfg(feature = "bn_p256")] BNP256,
            #[cfg(feature = "bn_p638")] BNP638,
            #[cfg(feature = "sm2_p256")] SM2P256,
            #[cfg(feature = "bp_p256_r1")] BpP256R1,
            #[cfg(feature = "bp_p384_r1")] BpP384R1,
            #[cfg(feature = "bp_p512_r1")] BpP512R1,
        ] $($t)*)
    };
}
#[cfg(feature = "ecc")]
use match_ecc_curve;

/// [`match_variants`] over the [`TpmiMldsaParms`](crate::TpmiMldsaParms)
/// variants.
#[cfg(feature = "mldsa")]
macro_rules! match_mldsa_parms {
    ($($t:tt)*) => {
        $crate::crypto::match_variants!([
            #[cfg(feature = "mldsa_44")] Mldsa44,
            #[cfg(feature = "mldsa_65")] Mldsa65,
            #[cfg(feature = "mldsa_87")] Mldsa87,
        ] $($t)*)
    };
}
#[cfg(feature = "mldsa")]
use match_mldsa_parms;

/// [`match_variants`] over the [`TpmiMlkemParms`](crate::TpmiMlkemParms)
/// variants.
#[cfg(feature = "mlkem")]
macro_rules! match_mlkem_parms {
    ($($t:tt)*) => {
        $crate::crypto::match_variants!([
            #[cfg(feature = "mlkem_512")] Mlkem512,
            #[cfg(feature = "mlkem_768")] Mlkem768,
            #[cfg(feature = "mlkem_1024")] Mlkem1024,
        ] $($t)*)
    };
}
#[cfg(feature = "mlkem")]
use match_mlkem_parms;

use {match_hash_alg, match_sym_alg, match_variants};

#[cfg(test)]
mod tests {
    use super::{
        backend::{
            AsymmetricKey, Cmac, Ecc, EccCurve, EccSigScheme, EdwardsCurve, Hash, HashState, Hmac,
            HmacState, Mldsa, MldsaKey, Mlkem, MlkemKey, MontgomeryCurve, Rsa, RsaKey,
            RsaSigScheme, Symmetric,
        },
        *,
    };
    use crate::{TpmiAlgHash, TpmtHa};

    /// Deterministic xorshift64 RNG for tests.
    struct TestRng(u64);

    impl Rng for TestRng {
        fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
            for b in out.iter_mut() {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                *b = (x & 0xff) as u8;
            }
            Ok(())
        }

        fn stir_bytes(&mut self, data: &[u8]) -> Result<(), CryptoError> {
            for &b in data {
                self.0 = self.0.wrapping_mul(0x100_0000_01b3) ^ u64::from(b);
            }
            if self.0 == 0 {
                self.0 = 1;
            }
            Ok(())
        }
    }

    /// Lightweight deterministic sponge hash for testing dispatch logic across
    /// all digest sizes without external deps.
    struct ToyHash<const N: usize> {
        state: [u8; N],
        pos: usize,
    }

    impl<const N: usize> HashState<N> for ToyHash<N> {
        fn init() -> Result<Self, CryptoError> {
            let mut state = [0u8; N];
            for (i, b) in state.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(37).wrapping_add(0xa5);
            }
            Ok(Self { state, pos: 0 })
        }

        fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
            for &byte in data {
                let idx = self.pos % N;
                let prev = self.state[(idx + N - 1) % N];
                self.state[idx] = self.state[idx]
                    .wrapping_add(byte ^ 0x5c)
                    .rotate_left(3)
                    .wrapping_add(prev);
                self.pos = self.pos.wrapping_add(1);
            }
            Ok(())
        }

        fn finalize(&mut self, out: &mut [u8; N]) -> Result<(), CryptoError> {
            let len_bytes = (self.pos as u64).to_be_bytes();
            self.update(&len_bytes)?;
            for round in 0..4u8 {
                self.update(&[round, 0xff ^ round])?;
            }
            out.copy_from_slice(&self.state);
            Ok(())
        }
    }

    struct ToyHmac<const N: usize>(ToyHash<N>);

    impl<const N: usize> HmacState<N> for ToyHmac<N> {
        fn init(key: &[u8]) -> Result<Self, CryptoError> {
            let mut h = ToyHash::<N>::init()?;
            h.update(&(key.len() as u32).to_be_bytes())?;
            h.update(key)?;
            Ok(Self(h))
        }

        fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
            self.0.update(data)
        }

        fn finalize(&mut self, out: &mut [u8; N]) -> Result<(), CryptoError> {
            self.0.finalize(out)
        }
    }

    /// Toy 1024-bit RSA key implementing an exact bijection on `[0, n)` via
    /// modular addition `(x + secret) mod n` / `(y - secret) mod n`, with toy
    /// padding for every scheme (`Raw`, `RSAES`, `OAEP`, `RSASSA`, `RSAPSS`).
    struct ToyRsa1024;

    #[derive(Clone)]
    struct ToyRsa1024Pub {
        exponent: u32,
        modulus: [u8; 128],
    }

    struct ToyRsa1024Priv {
        public: ToyRsa1024Pub,
        prime_p: [u8; 64],
    }

    fn be_cmp<const N: usize>(a: &[u8; N], b: &[u8; N]) -> core::cmp::Ordering {
        a.cmp(b)
    }

    fn be_add_mod<const N: usize>(x: &[u8; N], delta: &[u8; N], m: &[u8; N]) -> [u8; N] {
        let mut sum = [0u8; N];
        let mut carry = 0u16;
        for i in (0..N).rev() {
            let v = u16::from(x[i]) + u16::from(delta[i]) + carry;
            sum[i] = (v & 0xff) as u8;
            carry = v >> 8;
        }
        if carry != 0 || be_cmp(&sum, m) != core::cmp::Ordering::Less {
            let mut borrow = 0i16;
            for i in (0..N).rev() {
                let v = i16::from(sum[i]) - i16::from(m[i]) - borrow;
                if v < 0 {
                    sum[i] = (v + 256) as u8;
                    borrow = 1;
                } else {
                    sum[i] = v as u8;
                    borrow = 0;
                }
            }
        }
        sum
    }

    fn be_sub_mod<const N: usize>(y: &[u8; N], delta: &[u8; N], m: &[u8; N]) -> [u8; N] {
        let mut diff = [0u8; N];
        let mut borrow = 0i16;
        for i in (0..N).rev() {
            let v = i16::from(y[i]) - i16::from(delta[i]) - borrow;
            if v < 0 {
                diff[i] = (v + 256) as u8;
                borrow = 1;
            } else {
                diff[i] = v as u8;
                borrow = 0;
            }
        }
        if borrow != 0 {
            let mut carry = 0u16;
            for i in (0..N).rev() {
                let v = u16::from(diff[i]) + u16::from(m[i]) + carry;
                diff[i] = (v & 0xff) as u8;
                carry = v >> 8;
            }
        }
        diff
    }

    impl ToyRsa1024 {
        fn secret_delta(pub_key: &ToyRsa1024Pub) -> [u8; 128] {
            let mut d = [0u8; 128];
            // Strictly `< modulus` because `modulus[0] & 0x80 != 0` and `d[0] = 0x13`.
            d[0] = 0x13;
            d[1..5].copy_from_slice(&pub_key.exponent.to_be_bytes());
            for i in 5..128 {
                d[i] = pub_key.modulus[i] ^ 0x3a;
            }
            d
        }

        fn expected_prime(modulus: &[u8; 128]) -> [u8; 64] {
            let mut p = [0u8; 64];
            p.copy_from_slice(&modulus[..64]);
            p[0] |= 0x80;
            p[63] |= 0x01;
            p
        }

        /// Toy public operation `(x + secret) mod n`, or `None` if `x >= n`.
        fn toy_public(public: &ToyRsa1024Pub, x: &[u8; 128]) -> Option<[u8; 128]> {
            if be_cmp(x, &public.modulus) != core::cmp::Ordering::Less {
                return None;
            }
            Some(be_add_mod(x, &Self::secret_delta(public), &public.modulus))
        }

        /// Toy private operation `(y - secret) mod n`, or `None` if `y >= n`.
        fn toy_private(public: &ToyRsa1024Pub, y: &[u8; 128]) -> Option<[u8; 128]> {
            if be_cmp(y, &public.modulus) != core::cmp::Ordering::Less {
                return None;
            }
            Some(be_sub_mod(y, &Self::secret_delta(public), &public.modulus))
        }

        /// Toy encryption padding header `0x00 || tag || len || label_tag`,
        /// followed by the (at most 117-byte) message.
        fn toy_pad_header(scheme: RsaEncryptScheme<'_>) -> Result<[u8; 11], CryptoError> {
            let mut header = [0u8; 11];
            match scheme {
                RsaEncryptScheme::Raw => return Err(CryptoError::Internal),
                RsaEncryptScheme::Rsaes => header[1] = 2,
                RsaEncryptScheme::Oaep { .. } => {
                    header[1] = 3;
                    let mut tag = [0u8; 32];
                    ToyHash::<32>::hash(&[scheme.label_bytes()], &mut tag)?;
                    header[3..].copy_from_slice(&tag[..8]);
                }
            }
            Ok(header)
        }

        /// Toy signature encoding `0x00 || 0x01 || tag || hash_alg || digest`.
        fn toy_sig_encoding(scheme: RsaSigScheme, digest: TpmtHa<'_>) -> [u8; 128] {
            let mut em = [0u8; 128];
            em[1] = 1;
            em[2] = match scheme {
                RsaSigScheme::Rsassa => 1,
                RsaSigScheme::Rsapss => 2,
            };
            em[3..5].copy_from_slice(&(digest.hash_alg() as u16).to_be_bytes());
            em[5..5 + digest.digest().len()].copy_from_slice(digest.digest());
            em
        }
    }

    impl AsymmetricKey<128, 64, u32> for ToyRsa1024 {
        type Public = ToyRsa1024Pub;
        type Private = ToyRsa1024Priv;

        fn generate(rng: &mut impl Rng, exponent: u32) -> Result<Self::Private, CryptoError> {
            let mut modulus = [0u8; 128];
            rng.fill_bytes(&mut modulus)?;
            modulus[0] |= 0x80;
            modulus[127] |= 0x01;
            let prime_p = Self::expected_prime(&modulus);
            Ok(ToyRsa1024Priv {
                public: ToyRsa1024Pub { exponent, modulus },
                prime_p,
            })
        }

        fn load_public(
            exponent: u32,
            modulus: &[u8; 128],
        ) -> Result<Option<Self::Public>, CryptoError> {
            if (modulus[0] & 0x80) == 0 || (modulus[127] & 1) == 0 {
                return Ok(None);
            }
            Ok(Some(ToyRsa1024Pub {
                exponent,
                modulus: *modulus,
            }))
        }

        fn store_public(public: &Self::Public, out: &mut [u8; 128]) -> Result<(), CryptoError> {
            out.copy_from_slice(&public.modulus);
            Ok(())
        }

        fn load_private(
            public: Self::Public,
            prime_p: &[u8; 64],
        ) -> Result<Option<Self::Private>, CryptoError> {
            if *prime_p != Self::expected_prime(&public.modulus) {
                return Ok(None);
            }
            Ok(Some(ToyRsa1024Priv {
                public,
                prime_p: *prime_p,
            }))
        }

        fn store_private(private: &Self::Private, out: &mut [u8; 64]) -> Result<(), CryptoError> {
            out.copy_from_slice(&private.prime_p);
            Ok(())
        }

        fn as_public(private: &Self::Private) -> &Self::Public {
            &private.public
        }
    }

    impl RsaKey<128, 64> for ToyRsa1024 {
        fn exponent(public: &Self::Public) -> u32 {
            public.exponent
        }

        fn encrypt(
            _: &mut impl Rng,
            public: &Self::Public,
            scheme: RsaEncryptScheme<'_>,
            plaintext: &[u8],
            out: &mut [u8; 128],
        ) -> Result<Option<()>, CryptoError> {
            let mut em = [0u8; 128];
            if let RsaEncryptScheme::Raw = scheme {
                let start = plaintext
                    .iter()
                    .position(|&b| b != 0)
                    .unwrap_or(plaintext.len());
                let Some(pad) = 128usize.checked_sub(plaintext.len() - start) else {
                    return Ok(None);
                };
                em[pad..].copy_from_slice(&plaintext[start..]);
            } else {
                if plaintext.len() > 117 {
                    return Ok(None);
                }
                em[..11].copy_from_slice(&Self::toy_pad_header(scheme)?);
                em[2] = plaintext.len() as u8;
                em[11..11 + plaintext.len()].copy_from_slice(plaintext);
            }
            let Some(ct) = Self::toy_public(public, &em) else {
                return Ok(None);
            };
            *out = ct;
            Ok(Some(()))
        }

        fn decrypt(
            rng: &mut impl Rng,
            private: &Self::Private,
            scheme: RsaEncryptScheme<'_>,
            ciphertext: &[u8; 128],
            out: &mut [u8; 128],
        ) -> Result<Option<usize>, CryptoError> {
            // Exercise `rng` blinding path to ensure callers pass a live RNG.
            let mut blind = [0u8; 4];
            rng.fill_bytes(&mut blind)?;
            let Some(em) = Self::toy_private(&private.public, ciphertext) else {
                return Ok(None);
            };
            if let RsaEncryptScheme::Raw = scheme {
                *out = em;
                return Ok(Some(128));
            }
            let mut header = Self::toy_pad_header(scheme)?;
            let len = usize::from(em[2]);
            header[2] = em[2];
            if em[..11] != header || len > 117 {
                return Ok(None);
            }
            out[..len].copy_from_slice(&em[11..11 + len]);
            Ok(Some(len))
        }

        fn sign(
            _: &mut impl Rng,
            private: &Self::Private,
            scheme: RsaSigScheme,
            digest: TpmtHa<'_>,
            out: &mut [u8; 128],
        ) -> Result<(), CryptoError> {
            let em = Self::toy_sig_encoding(scheme, digest);
            *out = Self::toy_private(&private.public, &em).ok_or(CryptoError::Internal)?;
            Ok(())
        }

        fn verify(
            public: &Self::Public,
            scheme: RsaSigScheme,
            digest: TpmtHa<'_>,
            sig: &[u8; 128],
        ) -> Result<bool, CryptoError> {
            let Some(em) = Self::toy_public(public, sig) else {
                return Ok(false);
            };
            Ok(em == Self::toy_sig_encoding(scheme, digest))
        }
    }

    /// Toy 256-bit Weierstrass curve (`y = x ^ 0x55`, non-zero `x < [0xff; 32]`).
    struct ToyP256;

    #[derive(Clone, PartialEq, Eq)]
    struct ToyP256Pub {
        x: [u8; 32],
        y: [u8; 32],
    }

    struct ToyP256Priv {
        public: ToyP256Pub,
        scalar: [u8; 32],
    }

    impl ToyP256 {
        fn point_for_scalar(scalar: &[u8; 32]) -> Option<ToyP256Pub> {
            if scalar.iter().all(|&b| b == 0) || scalar.iter().all(|&b| b == 0xff) {
                return None;
            }
            let x = *scalar;
            let mut y = [0u8; 32];
            for i in 0..32 {
                y[i] = x[i] ^ 0x55;
            }
            Some(ToyP256Pub { x, y })
        }

        fn scheme_tag(scheme: EccSigScheme) -> u8 {
            match scheme {
                EccSigScheme::Ecdsa => 1,
                EccSigScheme::Sm2 => 2,
                EccSigScheme::Ecschnorr => 3,
            }
        }
    }

    impl AsymmetricKey<64, 32> for ToyP256 {
        type Public = ToyP256Pub;
        type Private = ToyP256Priv;

        fn generate(rng: &mut impl Rng, _: ()) -> Result<Self::Private, CryptoError> {
            let mut scalar = [0u8; 32];
            rng.fill_bytes(&mut scalar)?;
            scalar[0] &= 0x7f;
            scalar[31] |= 0x01;
            let public = Self::point_for_scalar(&scalar).ok_or(CryptoError::Internal)?;
            Ok(ToyP256Priv { public, scalar })
        }

        fn load_public(_: (), point: &[u8; 64]) -> Result<Option<Self::Public>, CryptoError> {
            let (x, y) = point.split_first_chunk::<32>().unwrap();
            let Some(expected) = Self::point_for_scalar(x) else {
                return Ok(None);
            };
            if expected.y != *y {
                return Ok(None);
            }
            Ok(Some(expected))
        }

        fn store_public(public: &Self::Public, out: &mut [u8; 64]) -> Result<(), CryptoError> {
            out[..32].copy_from_slice(&public.x);
            out[32..].copy_from_slice(&public.y);
            Ok(())
        }

        fn load_private(
            public: Self::Public,
            scalar: &[u8; 32],
        ) -> Result<Option<Self::Private>, CryptoError> {
            if Self::point_for_scalar(scalar).as_ref() != Some(&public) {
                return Ok(None);
            }
            Ok(Some(ToyP256Priv {
                public,
                scalar: *scalar,
            }))
        }

        fn store_private(private: &Self::Private, out: &mut [u8; 32]) -> Result<(), CryptoError> {
            out.copy_from_slice(&private.scalar);
            Ok(())
        }

        fn as_public(private: &Self::Private) -> &Self::Public {
            &private.public
        }
    }

    impl EccCurve<32, 64> for ToyP256 {
        fn ecdh(
            private: &Self::Private,
            peer_public: &Self::Public,
            out_x: &mut [u8; 32],
            out_y: &mut [u8; 32],
        ) -> Result<Option<()>, CryptoError> {
            // Equal X coordinates simulate `[d]([-d]G) = O` (infinity) when `x[31] == 0xfe`.
            if private.scalar == peer_public.x && peer_public.x[31] == 0xfe {
                return Ok(None);
            }
            for i in 0..32 {
                // Commutative toy shared point: `(d_a ^ d_b)` so `ecdh(a, B) == ecdh(b, A)`.
                out_x[i] = private.scalar[i] ^ peer_public.x[i] ^ 0x11;
                out_y[i] = out_x[i] ^ 0x55;
            }
            Ok(Some(()))
        }

        fn sign<H: Hash>(
            rng: &mut impl Rng,
            private: &Self::Private,
            scheme: EccSigScheme,
            digest: TpmtHa<'_>,
            out_r: &mut [u8; 32],
            out_s: &mut [u8; 32],
        ) -> Result<(), CryptoError> {
            rng.fill_bytes(out_r)?;
            out_r[31] |= 1;
            let tag = [Self::scheme_tag(scheme)];
            ToyHash::<32>::hash(&[&tag, &private.public.x, out_r, digest.digest()], out_s)?;
            out_s[31] |= 1;
            Ok(())
        }

        fn verify<H: Hash>(
            public: &Self::Public,
            scheme: EccSigScheme,
            digest: TpmtHa<'_>,
            sig_r: &[u8; 32],
            sig_s: &[u8; 32],
        ) -> Result<bool, CryptoError> {
            if sig_r.iter().all(|&b| b == 0) || sig_s.iter().all(|&b| b == 0) {
                return Ok(false);
            }
            let tag = [Self::scheme_tag(scheme)];
            let mut expected_s = [0u8; 32];
            ToyHash::<32>::hash(&[&tag, &public.x, sig_r, digest.digest()], &mut expected_s)?;
            expected_s[31] |= 1;
            Ok(*sig_s == expected_s)
        }
    }

    /// Toy twisted Edwards curve (`Ed25519` for `N = 32`, `Ed448` for `N = 57`).
    struct ToyEdwards<const N: usize>;

    #[derive(Clone, PartialEq, Eq)]
    struct ToyEdwardsPub<const N: usize>([u8; N]);

    struct ToyEdwardsPriv<const N: usize> {
        public: ToyEdwardsPub<N>,
        secret: [u8; N],
    }

    impl<const N: usize> ToyEdwards<N> {
        fn derive_point(secret: &[u8; N]) -> [u8; N] {
            let mut pt = [0u8; N];
            for i in 0..N {
                pt[i] = secret[i] ^ 0xa3;
            }
            pt[0] |= 0x01;
            pt
        }
    }

    impl<const N: usize> AsymmetricKey<N, N> for ToyEdwards<N> {
        type Public = ToyEdwardsPub<N>;
        type Private = ToyEdwardsPriv<N>;

        fn generate(rng: &mut impl Rng, _: ()) -> Result<Self::Private, CryptoError> {
            let mut secret = [0u8; N];
            rng.fill_bytes(&mut secret)?;
            secret[0] |= 0x01;
            Ok(ToyEdwardsPriv {
                public: ToyEdwardsPub(Self::derive_point(&secret)),
                secret,
            })
        }

        fn load_public(_: (), point: &[u8; N]) -> Result<Option<Self::Public>, CryptoError> {
            if point.iter().all(|&b| b == 0) || point.iter().all(|&b| b == 0xff) {
                return Ok(None);
            }
            Ok(Some(ToyEdwardsPub(*point)))
        }

        fn store_public(public: &Self::Public, out: &mut [u8; N]) -> Result<(), CryptoError> {
            out.copy_from_slice(&public.0);
            Ok(())
        }

        fn load_private(
            public: Self::Public,
            secret: &[u8; N],
        ) -> Result<Option<Self::Private>, CryptoError> {
            if secret.iter().all(|&b| b == 0) || Self::derive_point(secret) != public.0 {
                return Ok(None);
            }
            Ok(Some(ToyEdwardsPriv {
                public,
                secret: *secret,
            }))
        }

        fn store_private(private: &Self::Private, out: &mut [u8; N]) -> Result<(), CryptoError> {
            out.copy_from_slice(&private.secret);
            Ok(())
        }

        fn as_public(private: &Self::Private) -> &Self::Public {
            &private.public
        }
    }

    impl<const N: usize> EdwardsCurve<N> for ToyEdwards<N> {
        fn sign_message(
            private: &Self::Private,
            msg: &[&[u8]],
            out_r: &mut [u8; N],
            out_s: &mut [u8; N],
        ) -> Result<(), CryptoError> {
            let mut h_r = ToyHash::<N>::init()?;
            h_r.update(b"eddsa-msg-r")?;
            h_r.update(&private.public.0)?;
            for part in msg {
                h_r.update(part)?;
            }
            h_r.finalize(out_r)?;

            let mut h_s = ToyHash::<N>::init()?;
            h_s.update(b"eddsa-msg-s")?;
            h_s.update(&private.public.0)?;
            h_s.update(out_r)?;
            for part in msg {
                h_s.update(part)?;
            }
            h_s.finalize(out_s)?;
            Ok(())
        }

        fn sign_prehash(
            private: &Self::Private,
            prehash: &[u8; 64],
            out_r: &mut [u8; N],
            out_s: &mut [u8; N],
        ) -> Result<(), CryptoError> {
            ToyHash::<N>::hash(&[b"eddsa-ph-r", &private.public.0, prehash], out_r)?;
            ToyHash::<N>::hash(&[b"eddsa-ph-s", &private.public.0, out_r, prehash], out_s)?;
            Ok(())
        }

        fn verify_message(
            public: &Self::Public,
            msg: &[&[u8]],
            sig_r: &[u8; N],
            sig_s: &[u8; N],
        ) -> Result<bool, CryptoError> {
            let mut h_s = ToyHash::<N>::init()?;
            h_s.update(b"eddsa-msg-s")?;
            h_s.update(&public.0)?;
            h_s.update(sig_r)?;
            for part in msg {
                h_s.update(part)?;
            }
            let mut expected_s = [0u8; N];
            h_s.finalize(&mut expected_s)?;
            Ok(*sig_s == expected_s)
        }

        fn verify_prehash(
            public: &Self::Public,
            prehash: &[u8; 64],
            sig_r: &[u8; N],
            sig_s: &[u8; N],
        ) -> Result<bool, CryptoError> {
            let mut expected_s = [0u8; N];
            ToyHash::<N>::hash(&[b"eddsa-ph-s", &public.0, sig_r, prehash], &mut expected_s)?;
            Ok(*sig_s == expected_s)
        }
    }

    /// Toy Montgomery curve (`X25519` for `N = 32`).
    struct ToyMontgomery<const N: usize>;

    #[derive(Clone, PartialEq, Eq)]
    struct ToyMontgomeryPub<const N: usize>([u8; N]);

    struct ToyMontgomeryPriv<const N: usize> {
        public: ToyMontgomeryPub<N>,
        scalar: [u8; N],
    }

    impl<const N: usize> ToyMontgomery<N> {
        fn derive_u(scalar: &[u8; N]) -> [u8; N] {
            let mut u = [0u8; N];
            for i in 0..N {
                u[i] = scalar[i] ^ 0x3c;
            }
            u
        }
    }

    impl<const N: usize> AsymmetricKey<N, N> for ToyMontgomery<N> {
        type Public = ToyMontgomeryPub<N>;
        type Private = ToyMontgomeryPriv<N>;

        fn generate(rng: &mut impl Rng, _: ()) -> Result<Self::Private, CryptoError> {
            let mut scalar = [0u8; N];
            rng.fill_bytes(&mut scalar)?;
            scalar[0] |= 0x01;
            Ok(ToyMontgomeryPriv {
                public: ToyMontgomeryPub(Self::derive_u(&scalar)),
                scalar,
            })
        }

        fn load_public(_: (), u: &[u8; N]) -> Result<Option<Self::Public>, CryptoError> {
            if u.iter().all(|&b| b == 0) {
                return Ok(None);
            }
            Ok(Some(ToyMontgomeryPub(*u)))
        }

        fn store_public(public: &Self::Public, out: &mut [u8; N]) -> Result<(), CryptoError> {
            out.copy_from_slice(&public.0);
            Ok(())
        }

        fn load_private(
            public: Self::Public,
            scalar: &[u8; N],
        ) -> Result<Option<Self::Private>, CryptoError> {
            if scalar.iter().all(|&b| b == 0) || Self::derive_u(scalar) != public.0 {
                return Ok(None);
            }
            Ok(Some(ToyMontgomeryPriv {
                public,
                scalar: *scalar,
            }))
        }

        fn store_private(private: &Self::Private, out: &mut [u8; N]) -> Result<(), CryptoError> {
            out.copy_from_slice(&private.scalar);
            Ok(())
        }

        fn as_public(private: &Self::Private) -> &Self::Public {
            &private.public
        }
    }

    impl<const N: usize> MontgomeryCurve<N> for ToyMontgomery<N> {
        fn ecdh(
            private: &Self::Private,
            peer_public: &Self::Public,
            out_u: &mut [u8; N],
        ) -> Result<Option<()>, CryptoError> {
            if peer_public.0.iter().all(|&b| b == 0xfe) {
                return Ok(None);
            }
            for i in 0..N {
                out_u[i] = private.scalar[i] ^ (peer_public.0[i] ^ 0x3c) ^ 0x77;
            }
            Ok(Some(()))
        }
    }

    /// Toy ML-DSA-44 (`PUB_SIZE = 1312`, `SIG_SIZE = 2420`).
    struct ToyMldsa44;

    #[derive(Clone, PartialEq, Eq)]
    struct ToyMldsa44Pub([u8; 32]);

    struct ToyMldsa44Priv {
        public: ToyMldsa44Pub,
        seed: [u8; 32],
    }

    impl ToyMldsa44 {
        fn expand_public_bytes(tag: &[u8; 32], out: &mut [u8; 1312]) {
            out[..32].copy_from_slice(tag);
            for (i, b) in out[32..].iter_mut().enumerate() {
                *b = tag[i % 32].wrapping_add(i as u8);
            }
        }

        fn public_for_seed(seed: &[u8; 32]) -> Result<ToyMldsa44Pub, CryptoError> {
            let mut tag = [0u8; 32];
            ToyHash::<32>::hash(&[b"mldsa44-pk", seed], &mut tag)?;
            if tag[0] == 0xff && tag[1] == 0xff {
                tag[0] = 0xfe;
            }
            Ok(ToyMldsa44Pub(tag))
        }
    }

    impl AsymmetricKey<1312, 32> for ToyMldsa44 {
        type Public = ToyMldsa44Pub;
        type Private = ToyMldsa44Priv;

        fn generate(rng: &mut impl Rng, _: ()) -> Result<Self::Private, CryptoError> {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed)?;
            seed[0] |= 1;
            Ok(ToyMldsa44Priv {
                public: Self::public_for_seed(&seed)?,
                seed,
            })
        }

        fn load_public(_: (), public: &[u8; 1312]) -> Result<Option<Self::Public>, CryptoError> {
            if public[0] == 0xff && public[1] == 0xff {
                return Ok(None);
            }
            let mut tag = [0u8; 32];
            tag.copy_from_slice(&public[..32]);
            let mut expected = [0u8; 1312];
            Self::expand_public_bytes(&tag, &mut expected);
            if *public != expected {
                return Ok(None);
            }
            Ok(Some(ToyMldsa44Pub(tag)))
        }

        fn store_public(public: &Self::Public, out: &mut [u8; 1312]) -> Result<(), CryptoError> {
            Self::expand_public_bytes(&public.0, out);
            Ok(())
        }

        fn load_private(
            public: Self::Public,
            seed: &[u8; 32],
        ) -> Result<Option<Self::Private>, CryptoError> {
            if seed.iter().all(|&b| b == 0) || Self::public_for_seed(seed)? != public {
                return Ok(None);
            }
            Ok(Some(ToyMldsa44Priv {
                public,
                seed: *seed,
            }))
        }

        fn store_private(private: &Self::Private, out: &mut [u8; 32]) -> Result<(), CryptoError> {
            out.copy_from_slice(&private.seed);
            Ok(())
        }

        fn as_public(private: &Self::Private) -> &Self::Public {
            &private.public
        }
    }

    impl MldsaKey<1312, 2420> for ToyMldsa44 {
        fn sign_message(
            rng: &mut impl Rng,
            private: &Self::Private,
            context: &[u8],
            msg: &[&[u8]],
            out_sig: &mut [u8; 2420],
        ) -> Result<(), CryptoError> {
            let mut rnd = [0u8; 4];
            rng.fill_bytes(&mut rnd)?;
            let ctx_len = u8::try_from(context.len()).map_err(|_| CryptoError::Internal)?;
            let mut h = ToyHash::<32>::init()?;
            h.update(b"mldsa44-msg")?;
            h.update(&private.public.0)?;
            h.update(&[ctx_len])?;
            h.update(context)?;
            for part in msg {
                h.update(part)?;
            }
            let mut tag = [0u8; 32];
            h.finalize(&mut tag)?;
            for (i, b) in out_sig.iter_mut().enumerate() {
                *b = tag[i % 32] ^ (i as u8);
            }
            Ok(())
        }

        fn verify_message(
            public: &Self::Public,
            context: &[u8],
            msg: &[&[u8]],
            sig: &[u8; 2420],
        ) -> Result<bool, CryptoError> {
            let Ok(ctx_len) = u8::try_from(context.len()) else {
                return Ok(false);
            };
            let mut h = ToyHash::<32>::init()?;
            h.update(b"mldsa44-msg")?;
            h.update(&public.0)?;
            h.update(&[ctx_len])?;
            h.update(context)?;
            for part in msg {
                h.update(part)?;
            }
            let mut tag = [0u8; 32];
            h.finalize(&mut tag)?;
            Ok(sig
                .iter()
                .enumerate()
                .all(|(i, &b)| b == (tag[i % 32] ^ (i as u8))))
        }

        fn sign_mu(
            rng: &mut impl Rng,
            private: &Self::Private,
            mu: &[u8; 64],
            out_sig: &mut [u8; 2420],
        ) -> Result<(), CryptoError> {
            let mut rnd = [0u8; 4];
            rng.fill_bytes(&mut rnd)?;
            let mut tag = [0u8; 32];
            ToyHash::<32>::hash(&[b"mldsa44-mu", &private.public.0, mu], &mut tag)?;
            for (i, b) in out_sig.iter_mut().enumerate() {
                *b = tag[i % 32] ^ (i as u8);
            }
            Ok(())
        }

        fn verify_mu(
            public: &Self::Public,
            mu: &[u8; 64],
            sig: &[u8; 2420],
        ) -> Result<bool, CryptoError> {
            let mut tag = [0u8; 32];
            ToyHash::<32>::hash(&[b"mldsa44-mu", &public.0, mu], &mut tag)?;
            Ok(sig
                .iter()
                .enumerate()
                .all(|(i, &b)| b == (tag[i % 32] ^ (i as u8))))
        }

        fn sign_prehash(
            rng: &mut impl Rng,
            private: &Self::Private,
            context: &[u8],
            digest: TpmtHa<'_>,
            out_sig: &mut [u8; 2420],
        ) -> Result<(), CryptoError> {
            let mut rnd = [0u8; 4];
            rng.fill_bytes(&mut rnd)?;
            let ctx_len = u8::try_from(context.len()).map_err(|_| CryptoError::Internal)?;
            let alg_bytes = (digest.hash_alg() as u16).to_be_bytes();
            let mut tag = [0u8; 32];
            ToyHash::<32>::hash(
                &[
                    b"mldsa44-ph",
                    &alg_bytes,
                    &private.public.0,
                    &[ctx_len],
                    context,
                    digest.digest(),
                ],
                &mut tag,
            )?;
            for (i, b) in out_sig.iter_mut().enumerate() {
                *b = tag[i % 32] ^ (i as u8);
            }
            Ok(())
        }

        fn verify_prehash(
            public: &Self::Public,
            context: &[u8],
            digest: TpmtHa<'_>,
            sig: &[u8; 2420],
        ) -> Result<bool, CryptoError> {
            let Ok(ctx_len) = u8::try_from(context.len()) else {
                return Ok(false);
            };
            let alg_bytes = (digest.hash_alg() as u16).to_be_bytes();
            let mut tag = [0u8; 32];
            ToyHash::<32>::hash(
                &[
                    b"mldsa44-ph",
                    &alg_bytes,
                    &public.0,
                    &[ctx_len],
                    context,
                    digest.digest(),
                ],
                &mut tag,
            )?;
            Ok(sig
                .iter()
                .enumerate()
                .all(|(i, &b)| b == (tag[i % 32] ^ (i as u8))))
        }
    }

    /// Toy ML-KEM-768 (`PUB_SIZE = 1184`, `CT_SIZE = 1088`).
    struct ToyMlkem768;

    #[derive(Clone, PartialEq, Eq)]
    struct ToyMlkem768Pub([u8; 32]);

    struct ToyMlkem768Priv {
        public: ToyMlkem768Pub,
        seed: [u8; 64],
    }

    impl ToyMlkem768 {
        fn expand_public_bytes(tag: &[u8; 32], out: &mut [u8; 1184]) {
            out[..32].copy_from_slice(tag);
            for (i, b) in out[32..].iter_mut().enumerate() {
                *b = tag[i % 32].wrapping_add((i as u8).wrapping_mul(3));
            }
        }

        fn public_for_seed(seed: &[u8; 64]) -> Result<ToyMlkem768Pub, CryptoError> {
            let mut tag = [0u8; 32];
            ToyHash::<32>::hash(&[b"mlkem768-ek", seed], &mut tag)?;
            if tag[0] == 0xff && tag[1] == 0xff {
                tag[0] = 0xfe;
            }
            Ok(ToyMlkem768Pub(tag))
        }
    }

    impl AsymmetricKey<1184, 64> for ToyMlkem768 {
        type Public = ToyMlkem768Pub;
        type Private = ToyMlkem768Priv;

        fn generate(rng: &mut impl Rng, _: ()) -> Result<Self::Private, CryptoError> {
            let mut seed = [0u8; 64];
            rng.fill_bytes(&mut seed)?;
            seed[0] |= 1;
            Ok(ToyMlkem768Priv {
                public: Self::public_for_seed(&seed)?,
                seed,
            })
        }

        fn load_public(_: (), public: &[u8; 1184]) -> Result<Option<Self::Public>, CryptoError> {
            if public[0] == 0xff && public[1] == 0xff {
                return Ok(None);
            }
            let mut tag = [0u8; 32];
            tag.copy_from_slice(&public[..32]);
            let mut expected = [0u8; 1184];
            Self::expand_public_bytes(&tag, &mut expected);
            if *public != expected {
                return Ok(None);
            }
            Ok(Some(ToyMlkem768Pub(tag)))
        }

        fn store_public(public: &Self::Public, out: &mut [u8; 1184]) -> Result<(), CryptoError> {
            Self::expand_public_bytes(&public.0, out);
            Ok(())
        }

        fn load_private(
            public: Self::Public,
            seed: &[u8; 64],
        ) -> Result<Option<Self::Private>, CryptoError> {
            if seed.iter().all(|&b| b == 0) || Self::public_for_seed(seed)? != public {
                return Ok(None);
            }
            Ok(Some(ToyMlkem768Priv {
                public,
                seed: *seed,
            }))
        }

        fn store_private(private: &Self::Private, out: &mut [u8; 64]) -> Result<(), CryptoError> {
            out.copy_from_slice(&private.seed);
            Ok(())
        }

        fn as_public(private: &Self::Private) -> &Self::Public {
            &private.public
        }
    }

    impl MlkemKey<1184, 1088> for ToyMlkem768 {
        fn encapsulate(
            rng: &mut impl Rng,
            public: &Self::Public,
            out_ct: &mut [u8; 1088],
            out_ss: &mut [u8; 32],
        ) -> Result<(), CryptoError> {
            let mut m = [0u8; 32];
            rng.fill_bytes(&mut m)?;
            for (i, b) in out_ct.iter_mut().enumerate() {
                *b = if i < 32 {
                    m[i] ^ public.0[i]
                } else {
                    public.0[i % 32] ^ (i as u8)
                };
            }
            ToyHash::<32>::hash(&[b"mlkem768-ss", &public.0, &m], out_ss)?;
            Ok(())
        }

        fn decapsulate(
            private: &Self::Private,
            ct: &[u8; 1088],
            out_ss: &mut [u8; 32],
        ) -> Result<(), CryptoError> {
            let mut m = [0u8; 32];
            for i in 0..32 {
                m[i] = ct[i] ^ private.public.0[i];
            }
            ToyHash::<32>::hash(&[b"mlkem768-ss", &private.public.0, &m], out_ss)?;
            Ok(())
        }
    }

    struct TestBackend;

    impl Hash for TestBackend {
        type Sha1 = ToyHash<20>;
        type Sha256 = ToyHash<32>;
        type Sha384 = ToyHash<48>;
        type Sha512 = ToyHash<64>;
        type Sm3_256 = ToyHash<32>;
        type Sha3_256 = ToyHash<32>;
        type Sha3_384 = ToyHash<48>;
        type Sha3_512 = ToyHash<64>;
    }

    impl Hmac for TestBackend {
        type Sha1 = ToyHmac<20>;
        type Sha256 = ToyHmac<32>;
        type Sha384 = ToyHmac<48>;
        type Sha512 = ToyHmac<64>;
        type Sm3_256 = ToyHmac<32>;
        type Sha3_256 = ToyHmac<32>;
        type Sha3_384 = ToyHmac<48>;
        type Sha3_512 = ToyHmac<64>;
    }

    impl Cmac for TestBackend {
        type Aes128 = !;
        type Aes192 = !;
        type Aes256 = !;
        type Sm4_128 = !;
        type Camellia128 = !;
        type Camellia192 = !;
        type Camellia256 = !;
    }

    impl Symmetric for TestBackend {
        type Aes128 = !;
        type Aes192 = !;
        type Aes256 = !;
        type Sm4_128 = !;
        type Camellia128 = !;
        type Camellia192 = !;
        type Camellia256 = !;
    }

    impl Rsa for TestBackend {
        type Rsa1024 = ToyRsa1024;
        type Rsa2048 = !;
        type Rsa3072 = !;
        type Rsa4096 = !;
    }

    impl Ecc for TestBackend {
        type NistP192 = !;
        type NistP224 = !;
        type NistP256 = ToyP256;
        type NistP384 = !;
        type NistP521 = !;
        type BNP256 = !;
        type BNP638 = !;
        type SM2P256 = !;
        type BpP256R1 = !;
        type BpP384R1 = !;
        type BpP512R1 = !;
        type Ed25519 = ToyEdwards<32>;
        type Ed448 = ToyEdwards<57>;
        type X25519 = ToyMontgomery<32>;
        type X448 = !;
    }

    impl Mldsa for TestBackend {
        type Mldsa44 = ToyMldsa44;
        type Mldsa65 = !;
        type Mldsa87 = !;
    }

    impl Mlkem for TestBackend {
        type Mlkem512 = !;
        type Mlkem768 = ToyMlkem768;
        type Mlkem1024 = !;
    }

    impl Random for TestBackend {
        type Rng = TestRng;

        fn from_entropy() -> Result<TestRng, CryptoError> {
            Self::from_seed(b"entropy")
        }

        fn from_seed(seed: &[u8]) -> Result<TestRng, CryptoError> {
            let mut state = 0x9e37_79b9_7f4a_7c15u64;
            for &b in seed {
                state = state.rotate_left(7) ^ u64::from(b);
            }
            if state == 0 {
                state = 1;
            }
            Ok(TestRng(state))
        }
    }

    impl Crypto for TestBackend {
        fn ct_eq(a: &[u8], b: &[u8]) -> bool {
            // Not constant time, which is fine for tests.
            a == b
        }
    }

    fn first_enabled_hash() -> TpmiAlgHash {
        // At least one hash algorithm is always enabled; prefer SHA-256.
        [
            #[cfg(feature = "sha256")]
            TpmiAlgHash::Sha256,
            #[cfg(feature = "sha1")]
            TpmiAlgHash::Sha1,
            #[cfg(feature = "sha384")]
            TpmiAlgHash::Sha384,
            #[cfg(feature = "sha512")]
            TpmiAlgHash::Sha512,
            #[cfg(feature = "sm3_256")]
            TpmiAlgHash::Sm3_256,
            #[cfg(feature = "sha3_256")]
            TpmiAlgHash::Sha3_256,
            #[cfg(feature = "sha3_384")]
            TpmiAlgHash::Sha3_384,
            #[cfg(feature = "sha3_512")]
            TpmiAlgHash::Sha3_512,
        ][0]
    }

    /// `HMAC` is not a [`sign`] / [`verify`] scheme (use [`hmac`] instead).
    #[cfg(feature = "rsa1024")]
    #[test]
    fn hmac_sign_and_verify_unsupported() {
        use crate::{TpmiRsaKeyBits, TpmtSigScheme, TpmtSignature};

        let alg = first_enabled_hash();
        let mut rng = TestBackend::from_seed(b"hmac-test").unwrap();
        let priv_key =
            RsaPrivateKey::<TestBackend>::generate(&mut rng, TpmiRsaKeyBits::Rsa1024, 0).unwrap();
        let mut mod_buf: RsaModulusBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        let modulus = priv_key.modulus(&mut mod_buf).unwrap();
        let pub_key = RsaPublicKey::<TestBackend>::load(TpmiRsaKeyBits::Rsa1024, 0, modulus)
            .unwrap()
            .unwrap();
        let digest = &[0x42u8; 64][..alg.digest_size()];

        let mut sig_buf: SignatureBuffer = [0u8; MAX_SIGNATURE_BYTES];
        assert_eq!(
            sign(
                &mut rng,
                SigningKey::Rsa(&priv_key),
                TpmtSigScheme::Hmac(alg),
                digest,
                &mut sig_buf,
            ),
            Err(CryptoError::Unsupported)
        );

        let mut tag_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let tag = hmac::<TestBackend>(alg, b"key", &[digest], &mut tag_buf).unwrap();
        assert_eq!(
            verify(
                VerifyingKey::Rsa(&pub_key),
                digest,
                TpmtSignature::Hmac(tag)
            ),
            Err(CryptoError::Unsupported)
        );
    }

    #[test]
    fn hmac_dispatch() {
        let alg = first_enabled_hash();
        let mut buf1 = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let mut buf2 = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let tag = hmac::<TestBackend>(alg, b"key", &[b"hello ", b"hmac"], &mut buf1).unwrap();
        assert_eq!(tag.hash_alg(), alg);
        assert_eq!(tag.digest().len(), alg.digest_size());
        let same = hmac::<TestBackend>(alg, b"key", &[b"hello hmac"], &mut buf2).unwrap();
        assert_eq!(tag, same);
        let mut buf3 = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let other = hmac::<TestBackend>(alg, b"other", &[b"hello hmac"], &mut buf3).unwrap();
        assert_ne!(tag, other);
    }

    #[cfg(feature = "rsa1024")]
    #[test]
    fn rsa_key_roundtrip_and_encrypt_schemes() {
        use core::ffi::CStr;

        use crate::{Tpm2bPrivateKeyRsa, TpmiRsaKeyBits};

        let alg = first_enabled_hash();
        let mut rng = TestBackend::from_seed(b"rsa-seed").unwrap();

        // Exponent 0 normalizes to 65537; invalid exponents fail gracefully.
        let priv_key =
            RsaPrivateKey::<TestBackend>::generate(&mut rng, TpmiRsaKeyBits::Rsa1024, 0).unwrap();
        assert_eq!(priv_key.bits(), TpmiRsaKeyBits::Rsa1024);
        assert_eq!(priv_key.exponent(), 65537);
        assert_eq!(
            RsaPrivateKey::<TestBackend>::generate(&mut rng, TpmiRsaKeyBits::Rsa1024, 2).err(),
            Some(CryptoError::Unsupported)
        );

        let mut mod_buf: RsaModulusBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        let mut p_buf: RsaPrimeBuffer = [0u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES];
        let modulus = priv_key.modulus(&mut mod_buf).unwrap();
        let prime_p = priv_key.prime_p(&mut p_buf).unwrap();

        assert!(
            RsaPublicKey::<TestBackend>::load(TpmiRsaKeyBits::Rsa1024, 4, modulus)
                .unwrap()
                .is_none()
        );
        let pub_key = RsaPublicKey::<TestBackend>::load(TpmiRsaKeyBits::Rsa1024, 0, modulus)
            .unwrap()
            .unwrap();
        assert_eq!(pub_key.exponent(), 65537);

        // Wrong prime_p is rejected with Ok(None) (TPM_RC_BINDING), not failure mode.
        let bad_p = Tpm2bPrivateKeyRsa::new(&[0xffu8; 64]).unwrap();
        assert!(
            RsaPrivateKey::<TestBackend>::load(pub_key, bad_p)
                .unwrap()
                .is_none()
        );

        let pub_key = RsaPublicKey::<TestBackend>::load(TpmiRsaKeyBits::Rsa1024, 0, modulus)
            .unwrap()
            .unwrap();
        let reloaded_priv = RsaPrivateKey::<TestBackend>::load(pub_key, prime_p)
            .unwrap()
            .unwrap();
        let pub_key = RsaPublicKey::<TestBackend>::load(TpmiRsaKeyBits::Rsa1024, 0, modulus)
            .unwrap()
            .unwrap();

        // 1. Raw (`TPM_ALG_NULL`): short input + extra leading zero bytes.
        let mut ct_buf: RsaModulusBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        let mut pt_buf: RsaModulusBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        let mut raw_in = [0u8; 132];
        raw_in[130] = 0xca;
        raw_in[131] = 0xfe;
        let ct = pub_key
            .encrypt(&mut rng, RsaEncryptScheme::Raw, &raw_in, &mut ct_buf)
            .unwrap()
            .unwrap();
        let pt = reloaded_priv
            .decrypt(&mut rng, RsaEncryptScheme::Raw, ct.as_slice(), &mut pt_buf)
            .unwrap()
            .unwrap();
        assert_eq!(pt.as_slice().len(), 128);
        assert_eq!(&pt.as_slice()[126..], &[0xca, 0xfe]);

        // Value >= modulus returns Ok(None).
        assert!(
            pub_key
                .encrypt(&mut rng, RsaEncryptScheme::Raw, &[0xff; 128], &mut ct_buf)
                .unwrap()
                .is_none()
        );

        // 2. RSAES-PKCS1-v1_5 (`TPM_ALG_RSAES`), or Unsupported if disabled.
        #[cfg(feature = "rsaes")]
        {
            let msg = b"hello pkcs1v1.5";
            let ct = pub_key
                .encrypt(&mut rng, RsaEncryptScheme::Rsaes, msg, &mut ct_buf)
                .unwrap()
                .unwrap();
            let pt = reloaded_priv
                .decrypt(
                    &mut rng,
                    RsaEncryptScheme::Rsaes,
                    ct.as_slice(),
                    &mut pt_buf,
                )
                .unwrap()
                .unwrap();
            assert_eq!(pt.as_slice(), msg);

            // Overlong RSAES message (> 128 - 11 = 117) returns Ok(None).
            assert!(
                pub_key
                    .encrypt(&mut rng, RsaEncryptScheme::Rsaes, &[0x11; 118], &mut ct_buf)
                    .unwrap()
                    .is_none()
            );
        }
        #[cfg(not(feature = "rsaes"))]
        {
            assert_eq!(
                pub_key.encrypt(&mut rng, RsaEncryptScheme::Rsaes, b"msg", &mut ct_buf),
                Err(CryptoError::Unsupported)
            );
            assert_eq!(
                reloaded_priv.decrypt(&mut rng, RsaEncryptScheme::Rsaes, &[0u8; 128], &mut pt_buf),
                Err(CryptoError::Unsupported)
            );
        }

        // 3. RSAES-OAEP (`TPM_ALG_OAEP`) with non-UTF-8 label (if hash fits in 128B OAEP: 2*hLen + 2 <= 128, i.e. hLen <= 63).
        if alg.digest_size() <= 48 {
            let label = CStr::from_bytes_with_nul(&[0xff, 0x80, b'D', b'U', b'P', 0x00]).unwrap();
            let scheme = RsaEncryptScheme::Oaep {
                hash: alg,
                label: Some(label),
            };
            assert_eq!(scheme.label_bytes(), label.to_bytes_with_nul());
            let ct = pub_key
                .encrypt(&mut rng, scheme, b"oaep secret", &mut ct_buf)
                .unwrap()
                .unwrap();
            let pt = reloaded_priv
                .decrypt(&mut rng, scheme, ct.as_slice(), &mut pt_buf)
                .unwrap()
                .unwrap();
            assert_eq!(pt.as_slice(), b"oaep secret");

            // Mismatched OAEP label rejects cleanly with Ok(None).
            for label in [Some(c"WRONG"), Some(c""), None] {
                let wrong_label = RsaEncryptScheme::Oaep { hash: alg, label };
                assert!(
                    reloaded_priv
                        .decrypt(&mut rng, wrong_label, ct.as_slice(), &mut pt_buf)
                        .unwrap()
                        .is_none()
                );
            }
        }

        // Unsupported RSA key size (`Rsa2048 = !` on TestBackend) returns CryptoError::Unsupported.
        #[cfg(feature = "rsa2048")]
        {
            let dummy_mod = crate::Tpm2bPublicKeyRsa::new(&[0x81; 128]).unwrap();
            assert_eq!(
                RsaPublicKey::<TestBackend>::load(TpmiRsaKeyBits::Rsa2048, 0, dummy_mod).err(),
                Some(CryptoError::Unsupported)
            );
        }
    }

    #[cfg(all(feature = "rsa1024", any(feature = "rsassa", feature = "rsapss")))]
    #[test]
    fn rsa_sign_and_verify_rsassa_and_rsapss() {
        use crate::{TpmiRsaKeyBits, TpmtSigScheme};

        let alg = first_enabled_hash();
        let mut rng = TestBackend::from_seed(b"rsa-sig").unwrap();
        let priv_key =
            RsaPrivateKey::<TestBackend>::generate(&mut rng, TpmiRsaKeyBits::Rsa1024, 0).unwrap();
        let mut mod_buf: RsaModulusBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        let modulus = priv_key.modulus(&mut mod_buf).unwrap();
        let pub_key = RsaPublicKey::<TestBackend>::load(TpmiRsaKeyBits::Rsa1024, 0, modulus)
            .unwrap()
            .unwrap();

        let digest = &[0x5au8; 64][..alg.digest_size()];
        let mut check = |scheme| {
            let mut sig_buf: SignatureBuffer = [0u8; MAX_SIGNATURE_BYTES];
            let sig = sign(
                &mut rng,
                SigningKey::Rsa(&priv_key),
                scheme,
                digest,
                &mut sig_buf,
            )
            .unwrap();
            assert!(verify(VerifyingKey::Rsa(&pub_key), digest, sig).unwrap());

            let mut bad_digest = [0x5au8; 64];
            bad_digest[0] ^= 0x01;
            assert!(
                !verify(
                    VerifyingKey::Rsa(&pub_key),
                    &bad_digest[..alg.digest_size()],
                    sig
                )
                .unwrap()
            );
        };
        #[cfg(feature = "rsassa")]
        check(TpmtSigScheme::Rsassa(alg));
        #[cfg(feature = "rsapss")]
        check(TpmtSigScheme::Rsapss(alg));
    }

    #[cfg(feature = "nist_p256")]
    #[test]
    fn ecc_padding_and_ecdh() {
        use crate::{Tpm2bEccParameter, TpmEccCurve, TpmsEccPoint};

        let mut rng = TestBackend::from_seed(b"ecc-seed").unwrap();

        let alice =
            EccPrivateKey::<TestBackend>::generate(&mut rng, TpmEccCurve::NistP256, None).unwrap();
        let bob =
            EccPrivateKey::<TestBackend>::generate(&mut rng, TpmEccCurve::NistP256, None).unwrap();
        assert_eq!(alice.curve(), TpmEccCurve::NistP256);
        assert_eq!(alice.key_bytes(), 32);

        let (mut ax, mut ay) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
        let (mut bx, mut by) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
        let alice_pt = alice.point(&mut ax, &mut ay).unwrap();
        let bob_pt = bob.point(&mut bx, &mut by).unwrap();
        let alice_pub = EccPublicKey::<TestBackend>::load(TpmEccCurve::NistP256, None, alice_pt)
            .unwrap()
            .unwrap();
        let bob_pub = EccPublicKey::<TestBackend>::load(TpmEccCurve::NistP256, None, bob_pt)
            .unwrap()
            .unwrap();

        // ECDH symmetry: `[d_a]Q_b == [d_b]Q_a`.
        let (mut zx1, mut zy1) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
        let (mut zx2, mut zy2) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
        let z1 = alice.ecdh(&bob_pub, &mut zx1, &mut zy1).unwrap().unwrap();
        let z2 = bob.ecdh(&alice_pub, &mut zx2, &mut zy2).unwrap().unwrap();
        assert_eq!(z1, z2);

        // Short unpadded big-endian scalar & coordinates normalize cleanly.
        let short_scalar = Tpm2bEccParameter::new(&[0x07]).unwrap();
        let mut short_y = [0x55u8; 32];
        short_y[31] = 0x07 ^ 0x55;
        let unpadded_pt = TpmsEccPoint {
            x: short_scalar,
            y: Tpm2bEccParameter::new(&short_y).unwrap(),
        };
        let short_pub = EccPublicKey::<TestBackend>::load(TpmEccCurve::NistP256, None, unpadded_pt)
            .unwrap()
            .unwrap();
        let (mut sx, mut sy) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
        let short_pt = short_pub.point(&mut sx, &mut sy).unwrap();
        assert_eq!(short_pt.x.as_slice().len(), 32);
        assert_eq!(short_pt.x.as_slice()[31], 0x07);
        assert_eq!(short_pt.y.as_slice(), &short_y);

        // `load_private` validates `[d]G == public`.
        let wrong_d = Tpm2bEccParameter::new(&[0x09]).unwrap();
        assert!(
            EccPrivateKey::<TestBackend>::load(short_pub, wrong_d)
                .unwrap()
                .is_none()
        );
        let short_pub = EccPublicKey::<TestBackend>::load(TpmEccCurve::NistP256, None, unpadded_pt)
            .unwrap()
            .unwrap();
        let short_priv = EccPrivateKey::<TestBackend>::load(short_pub, short_scalar)
            .unwrap()
            .unwrap();
        let mut d_buf = [0u8; MAX_ECC_COORD_BYTES];
        assert_eq!(short_priv.scalar(&mut d_buf).unwrap().as_slice().len(), 32);
        assert_eq!(short_priv.scalar(&mut d_buf).unwrap().as_slice()[31], 0x07);

        // Empty or oversized coordinates return Ok(None).
        let empty_pt = TpmsEccPoint {
            x: Tpm2bEccParameter::new(&[]).unwrap(),
            y: unpadded_pt.y,
        };
        assert!(
            EccPublicKey::<TestBackend>::load(TpmEccCurve::NistP256, None, empty_pt)
                .unwrap()
                .is_none()
        );
        // Only representable if a curve larger than P-256 is enabled.
        if let Some(x) = Tpm2bEccParameter::new(&[0x01; 33]) {
            let long_pt = TpmsEccPoint {
                x,
                y: unpadded_pt.y,
            };
            assert!(
                EccPublicKey::<TestBackend>::load(TpmEccCurve::NistP256, None, long_pt)
                    .unwrap()
                    .is_none()
            );
        }

        // EdDSA scheme on Weierstrass curve and `!`-bound curves return Unsupported.
        #[cfg(feature = "eddsa")]
        assert_eq!(
            EccPublicKey::<TestBackend>::load(
                TpmEccCurve::NistP256,
                Some(crate::TpmtEccScheme::Eddsa),
                unpadded_pt
            )
            .err(),
            Some(CryptoError::Unsupported)
        );
        #[cfg(feature = "nist_p384")]
        assert_eq!(
            EccPublicKey::<TestBackend>::load(TpmEccCurve::NistP384, None, unpadded_pt).err(),
            Some(CryptoError::Unsupported)
        );
    }

    #[cfg(all(
        feature = "nist_p256",
        any(feature = "ecdsa", feature = "sm2", feature = "ecschnorr")
    ))]
    #[test]
    fn ecc_signing() {
        use crate::{TpmEccCurve, TpmtSigScheme};

        let alg = first_enabled_hash();
        let mut rng = TestBackend::from_seed(b"ecc-sig").unwrap();
        let alice =
            EccPrivateKey::<TestBackend>::generate(&mut rng, TpmEccCurve::NistP256, None).unwrap();
        let (mut ax, mut ay) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
        let alice_pub = EccPublicKey::<TestBackend>::load(
            TpmEccCurve::NistP256,
            None,
            alice.point(&mut ax, &mut ay).unwrap(),
        )
        .unwrap()
        .unwrap();
        let digest = &[0x33u8; 64][..alg.digest_size()];

        // ECDSA, SM2, ECSchnorr sign & verify (including short `(r, s)` padding on verify).
        let mut check = |scheme| {
            let mut sig_buf: SignatureBuffer = [0u8; MAX_SIGNATURE_BYTES];
            let sig = sign(
                &mut rng,
                SigningKey::Ecc(&alice),
                scheme,
                digest,
                &mut sig_buf,
            )
            .unwrap();
            assert!(verify(VerifyingKey::Ecc(&alice_pub), digest, sig).unwrap());
        };
        #[cfg(feature = "ecdsa")]
        check(TpmtSigScheme::Ecdsa(alg));
        #[cfg(feature = "sm2")]
        check(TpmtSigScheme::Sm2(alg));
        #[cfg(feature = "ecschnorr")]
        check(TpmtSigScheme::Ecschnorr(alg));
    }

    /// `ECDAA` is not a [`sign`] / [`verify`] scheme.
    #[cfg(all(feature = "nist_p256", feature = "ecdaa"))]
    #[test]
    fn ecdaa_sign_and_verify_unsupported() {
        use crate::{
            Tpm2bEccParameter, TpmEccCurve, TpmsSchemeEcdaa, TpmsSignatureEcc, TpmtSigScheme,
            TpmtSignature,
        };

        let alg = first_enabled_hash();
        let mut rng = TestBackend::from_seed(b"ecdaa").unwrap();
        let key =
            EccPrivateKey::<TestBackend>::generate(&mut rng, TpmEccCurve::NistP256, None).unwrap();
        let (mut x, mut y) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
        let point = key.point(&mut x, &mut y).unwrap();
        let pub_key = EccPublicKey::<TestBackend>::load(TpmEccCurve::NistP256, None, point)
            .unwrap()
            .unwrap();
        let digest = &[0x33u8; 64][..alg.digest_size()];

        let mut sig_buf: SignatureBuffer = [0u8; MAX_SIGNATURE_BYTES];
        let scheme = TpmtSigScheme::Ecdaa(TpmsSchemeEcdaa {
            hash_alg: alg,
            count: 1,
        });
        assert_eq!(
            sign(
                &mut rng,
                SigningKey::Ecc(&key),
                scheme,
                digest,
                &mut sig_buf
            ),
            Err(CryptoError::Unsupported)
        );
        let sig = TpmtSignature::Ecdaa(TpmsSignatureEcc {
            hash: alg,
            signature_r: Tpm2bEccParameter::new(&[1; 32]).unwrap(),
            signature_s: Tpm2bEccParameter::new(&[1; 32]).unwrap(),
        });
        assert_eq!(
            verify(VerifyingKey::Ecc(&pub_key), digest, sig),
            Err(CryptoError::Unsupported)
        );
    }

    #[cfg(feature = "curve25519")]
    #[test]
    fn x25519_key_roundtrip_and_ecdh() {
        use crate::{Tpm2bEccParameter, TpmEccCurve, TpmsEccPoint};

        let mut rng = TestBackend::from_seed(b"x25519-seed").unwrap();
        let alice = EccPrivateKey::<TestBackend>::generate(&mut rng, TpmEccCurve::Curve25519, None)
            .unwrap();
        let bob = EccPrivateKey::<TestBackend>::generate(&mut rng, TpmEccCurve::Curve25519, None)
            .unwrap();
        assert!(matches!(alice, EccPrivateKey::X25519(_)));
        assert_eq!(alice.curve(), TpmEccCurve::Curve25519);
        assert_eq!(alice.key_bytes(), 32);

        let (mut ax, mut ay) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
        let (mut bx, mut by) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
        let alice_pt = alice.point(&mut ax, &mut ay).unwrap();
        assert_eq!(alice_pt.x.as_slice().len(), 32);
        assert!(alice_pt.y.as_slice().is_empty());
        let bob_pt = bob.point(&mut bx, &mut by).unwrap();

        let alice_pub = EccPublicKey::<TestBackend>::load(TpmEccCurve::Curve25519, None, alice_pt)
            .unwrap()
            .unwrap();
        let bob_pub = EccPublicKey::<TestBackend>::load(TpmEccCurve::Curve25519, None, bob_pt)
            .unwrap()
            .unwrap();

        // Non-empty `y` or wrong-length `x` on Curve25519 returns Ok(None).
        let bad_y_pt = TpmsEccPoint {
            x: alice_pt.x,
            y: Tpm2bEccParameter::new(&[1]).unwrap(),
        };
        assert!(
            EccPublicKey::<TestBackend>::load(TpmEccCurve::Curve25519, None, bad_y_pt)
                .unwrap()
                .is_none()
        );
        let short_x_pt = TpmsEccPoint {
            x: Tpm2bEccParameter::new(&[1; 31]).unwrap(),
            y: Tpm2bEccParameter::new(&[]).unwrap(),
        };
        assert!(
            EccPublicKey::<TestBackend>::load(TpmEccCurve::Curve25519, None, short_x_pt)
                .unwrap()
                .is_none()
        );

        // ECDH produces shared `u` in `x` with `y` empty.
        let (mut zx1, mut zy1) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
        let (mut zx2, mut zy2) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
        let z1 = alice.ecdh(&bob_pub, &mut zx1, &mut zy1).unwrap().unwrap();
        let z2 = bob.ecdh(&alice_pub, &mut zx2, &mut zy2).unwrap().unwrap();
        assert_eq!(z1, z2);
        assert_eq!(z1.x.as_slice().len(), 32);
        assert!(z1.y.as_slice().is_empty());

        // Reload private key and verify the `load_private` check.
        let mut s_buf = [0u8; MAX_ECC_COORD_BYTES];
        let scalar = alice.scalar(&mut s_buf).unwrap();
        let wrong_scalar = Tpm2bEccParameter::new(&[0x99; 32]).unwrap();
        assert!(
            EccPrivateKey::<TestBackend>::load(alice_pub, wrong_scalar)
                .unwrap()
                .is_none()
        );
        let alice_pub = EccPublicKey::<TestBackend>::load(TpmEccCurve::Curve25519, None, alice_pt)
            .unwrap()
            .unwrap();
        assert!(
            EccPrivateKey::<TestBackend>::load(alice_pub, scalar)
                .unwrap()
                .is_some()
        );

        // Weierstrass scheme (`Ecdsa`) on Curve25519 returns Unsupported.
        #[cfg(feature = "ecdsa")]
        {
            let alg = first_enabled_hash();
            assert_eq!(
                EccPrivateKey::<TestBackend>::generate(
                    &mut rng,
                    TpmEccCurve::Curve25519,
                    Some(crate::TpmtEccScheme::Ecdsa(alg))
                )
                .err(),
                Some(CryptoError::Unsupported)
            );
        }
    }

    #[cfg(all(feature = "curve25519", feature = "eddsa"))]
    #[test]
    fn ed25519_sign_message_and_hash_eddsa() {
        use crate::{Tpm2bEccParameter, TpmEccCurve, TpmtEccScheme, TpmtSigScheme, TpmtSignature};

        let mut rng = TestBackend::from_seed(b"ed25519-seed").unwrap();
        let priv_key = EccPrivateKey::<TestBackend>::generate(
            &mut rng,
            TpmEccCurve::Curve25519,
            Some(TpmtEccScheme::Eddsa),
        )
        .unwrap();
        assert!(matches!(priv_key, EccPrivateKey::Ed25519(_)));
        assert_eq!(priv_key.curve(), TpmEccCurve::Curve25519);
        assert_eq!(priv_key.key_bytes(), 32);

        let (mut px, mut py) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
        let pt = priv_key.point(&mut px, &mut py).unwrap();
        assert_eq!(pt.x.as_slice().len(), 32);
        assert!(pt.y.as_slice().is_empty());

        let pub_key = EccPublicKey::<TestBackend>::load(
            TpmEccCurve::Curve25519,
            Some(TpmtEccScheme::Eddsa),
            pt,
        )
        .unwrap()
        .unwrap();
        assert!(matches!(pub_key, EccPublicKey::Ed25519(_)));

        // ECDH on an Edwards signing key returns Unsupported.
        let (mut zx, mut zy) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
        assert_eq!(
            priv_key.ecdh(&pub_key, &mut zx, &mut zy),
            Err(CryptoError::Unsupported)
        );

        // Reload private key and verify the `load_private` check.
        let mut s_buf = [0u8; MAX_ECC_COORD_BYTES];
        let secret = priv_key.scalar(&mut s_buf).unwrap();
        let wrong_secret = Tpm2bEccParameter::new(&[0x77; 32]).unwrap();
        assert!(
            EccPrivateKey::<TestBackend>::load(pub_key, wrong_secret)
                .unwrap()
                .is_none()
        );
        let pub_key = EccPublicKey::<TestBackend>::load(
            TpmEccCurve::Curve25519,
            Some(TpmtEccScheme::Eddsa),
            pt,
        )
        .unwrap()
        .unwrap();
        assert!(
            EccPrivateKey::<TestBackend>::load(pub_key, secret)
                .unwrap()
                .is_some()
        );
        let pub_key = EccPublicKey::<TestBackend>::load(
            TpmEccCurve::Curve25519,
            Some(TpmtEccScheme::Eddsa),
            pt,
        )
        .unwrap()
        .unwrap();

        // Pure EdDSA works via `sign_message` / `verify_message` and rejects digest `sign` / `verify`.
        let mut sig_buf: SignatureBuffer = [0u8; MAX_SIGNATURE_BYTES];
        assert_eq!(
            sign(
                &mut rng,
                SigningKey::Ecc(&priv_key),
                TpmtSigScheme::Eddsa,
                &[0x11; 32],
                &mut sig_buf,
            ),
            Err(CryptoError::Unsupported)
        );

        let sig = sign_message(
            &mut rng,
            SigningKey::Ecc(&priv_key),
            TpmtSigScheme::Eddsa,
            &[b"hello ", b"ed25519"],
            &mut sig_buf,
        )
        .unwrap();
        assert!(matches!(sig, TpmtSignature::Eddsa(s) if s.as_slice().len() == 64));
        assert!(verify_message(VerifyingKey::Ecc(&pub_key), &[b"hello ed25519"], sig).unwrap());
        assert!(!verify_message(VerifyingKey::Ecc(&pub_key), &[b"wrong"], sig).unwrap());
        assert_eq!(
            verify(VerifyingKey::Ecc(&pub_key), &[0x11; 32], sig),
            Err(CryptoError::Unsupported)
        );

        // HashEdDSA works via digest `sign` / `verify` with a 64-byte prehash.
        #[cfg(feature = "hash_eddsa")]
        {
            let prehash = [0x42u8; 64];
            let mut ph_buf: SignatureBuffer = [0u8; MAX_SIGNATURE_BYTES];
            assert_eq!(
                sign_message(
                    &mut rng,
                    SigningKey::Ecc(&priv_key),
                    TpmtSigScheme::HashEddsa,
                    &[b"msg"],
                    &mut ph_buf,
                ),
                Err(CryptoError::Unsupported)
            );
            assert_eq!(
                sign(
                    &mut rng,
                    SigningKey::Ecc(&priv_key),
                    TpmtSigScheme::HashEddsa,
                    &prehash[..32],
                    &mut ph_buf,
                ),
                Err(CryptoError::Internal)
            );
            let ph_sig = sign(
                &mut rng,
                SigningKey::Ecc(&priv_key),
                TpmtSigScheme::HashEddsa,
                &prehash,
                &mut ph_buf,
            )
            .unwrap();
            assert!(matches!(ph_sig, TpmtSignature::HashEddsa(s) if s.as_slice().len() == 64));
            assert!(verify(VerifyingKey::Ecc(&pub_key), &prehash, ph_sig).unwrap());
            assert!(!verify(VerifyingKey::Ecc(&pub_key), &[0x00; 64], ph_sig).unwrap());
            assert!(!verify(VerifyingKey::Ecc(&pub_key), &prehash[..32], ph_sig).unwrap());
        }
    }

    #[cfg(all(feature = "curve448", feature = "eddsa"))]
    #[test]
    fn ed448_sizing_and_sign_message() {
        use crate::{TpmEccCurve, TpmtEccScheme, TpmtSigScheme, TpmtSignature};

        // Curve448 is 448 bits (56 bytes for X448), while Ed448 keys are 57 bytes and signatures 114 bytes.
        assert_eq!(TpmEccCurve::Curve448.key_bytes(), 56);
        const {
            assert!(TpmEccCurve::MAX_ECC_KEY_BYTES >= 57);
            assert!(MAX_ECC_COORD_BYTES >= 57);
            assert!(MAX_SIGNATURE_BYTES >= 114);
        }

        let mut rng = TestBackend::from_seed(b"ed448-seed").unwrap();
        let priv_key = EccPrivateKey::<TestBackend>::generate(
            &mut rng,
            TpmEccCurve::Curve448,
            Some(TpmtEccScheme::Eddsa),
        )
        .unwrap();
        assert!(matches!(priv_key, EccPrivateKey::Ed448(_)));
        assert_eq!(priv_key.curve(), TpmEccCurve::Curve448);
        assert_eq!(priv_key.key_bytes(), 57);

        let (mut px, mut py) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
        let pt = priv_key.point(&mut px, &mut py).unwrap();
        assert_eq!(pt.x.as_slice().len(), 57);
        assert!(pt.y.as_slice().is_empty());

        let pub_key = EccPublicKey::<TestBackend>::load(
            TpmEccCurve::Curve448,
            Some(TpmtEccScheme::Eddsa),
            pt,
        )
        .unwrap()
        .unwrap();
        assert_eq!(pub_key.key_bytes(), 57);

        let mut sig_buf: SignatureBuffer = [0u8; MAX_SIGNATURE_BYTES];
        let sig = sign_message(
            &mut rng,
            SigningKey::Ecc(&priv_key),
            TpmtSigScheme::Eddsa,
            &[b"ed448 ", b"message"],
            &mut sig_buf,
        )
        .unwrap();
        assert!(matches!(sig, TpmtSignature::Eddsa(s) if s.as_slice().len() == 114));
        assert!(verify_message(VerifyingKey::Ecc(&pub_key), &[b"ed448 message"], sig).unwrap());
        assert!(!verify_message(VerifyingKey::Ecc(&pub_key), &[b"tampered"], sig).unwrap());

        // `X448 = !` on TestBackend returns Unsupported.
        assert_eq!(
            EccPrivateKey::<TestBackend>::generate(&mut rng, TpmEccCurve::Curve448, None).err(),
            Some(CryptoError::Unsupported)
        );
    }

    #[cfg(feature = "mldsa_44")]
    #[test]
    fn mldsa_message_mu_and_hash_mldsa() {
        use crate::{Tpm2b, Tpm2bPublicKeyMldsa, TpmiMldsaParms, TpmtSigScheme, TpmtSignature};

        let mut rng = TestBackend::from_seed(b"mldsa-seed").unwrap();
        let priv_key =
            MldsaPrivateKey::<TestBackend>::generate(&mut rng, TpmiMldsaParms::Mldsa44).unwrap();
        assert_eq!(priv_key.parms(), TpmiMldsaParms::Mldsa44);

        let mut pk_buf: MldsaPubKeyBuffer = [0u8; TpmiMldsaParms::MAX_PUB_KEY_BYTES];
        let mut seed_buf: MldsaSeedBuffer = [0u8; 32];
        let pk_2b = priv_key.public(&mut pk_buf).unwrap();
        assert_eq!(pk_2b.as_slice().len(), 1312);
        let seed_2b = priv_key.seed(&mut seed_buf).unwrap();

        // Invalid public key length or encoding returns Ok(None).
        let short_pk = Tpm2bPublicKeyMldsa::new(&[0x11; 32]).unwrap();
        assert!(
            MldsaPublicKey::<TestBackend>::load(TpmiMldsaParms::Mldsa44, short_pk)
                .unwrap()
                .is_none()
        );
        let pub_key = MldsaPublicKey::<TestBackend>::load(TpmiMldsaParms::Mldsa44, pk_2b)
            .unwrap()
            .unwrap();
        assert_eq!(pub_key.parms(), TpmiMldsaParms::Mldsa44);

        // Wrong seed rejected with Ok(None) by `load_private`.
        assert!(
            MldsaPrivateKey::<TestBackend>::load(pub_key, Tpm2b(&[0x99u8; 32]))
                .unwrap()
                .is_none()
        );
        let pub_key = MldsaPublicKey::<TestBackend>::load(TpmiMldsaParms::Mldsa44, pk_2b)
            .unwrap()
            .unwrap();
        assert!(
            MldsaPrivateKey::<TestBackend>::load(pub_key, seed_2b)
                .unwrap()
                .is_some()
        );
        let pub_key = MldsaPublicKey::<TestBackend>::load(TpmiMldsaParms::Mldsa44, pk_2b)
            .unwrap()
            .unwrap();

        // 1. Pure ML-DSA message signing (`sign_message` / `verify_message`) with context and >255 rejection.
        let mut sig_buf: SignatureBuffer = [0u8; MAX_SIGNATURE_BYTES];
        let ctx = b"tpm2-mldsa-context";
        let overlong_ctx = [0xaa; TpmtSignature::MAX_CTX_BYTES + 1];
        assert_eq!(
            sign_message(
                &mut rng,
                SigningKey::Mldsa {
                    key: &priv_key,
                    context: &overlong_ctx,
                },
                TpmtSigScheme::Mldsa,
                &[b"pure ", b"mldsa"],
                &mut sig_buf,
            ),
            Err(CryptoError::Internal)
        );
        let msg_sig = sign_message(
            &mut rng,
            SigningKey::Mldsa {
                key: &priv_key,
                context: ctx,
            },
            TpmtSigScheme::Mldsa,
            &[b"pure ", b"mldsa"],
            &mut sig_buf,
        )
        .unwrap();
        assert!(matches!(msg_sig, TpmtSignature::Mldsa(s) if s.as_slice().len() == 2420));
        assert!(
            verify_message(
                VerifyingKey::Mldsa {
                    key: &pub_key,
                    context: ctx,
                },
                &[b"pure mldsa"],
                msg_sig,
            )
            .unwrap()
        );
        assert!(
            !verify_message(
                VerifyingKey::Mldsa {
                    key: &pub_key,
                    context: b"wrong-ctx",
                },
                &[b"pure mldsa"],
                msg_sig,
            )
            .unwrap()
        );
        assert!(
            !verify_message(
                VerifyingKey::Mldsa {
                    key: &pub_key,
                    context: &overlong_ctx,
                },
                &[b"pure mldsa"],
                msg_sig,
            )
            .unwrap()
        );
        assert!(
            !verify_message(
                VerifyingKey::Mldsa {
                    key: &pub_key,
                    context: ctx,
                },
                &[b"wrong"],
                msg_sig,
            )
            .unwrap()
        );

        // 2. External-mu 64-byte digest signing (`sign` / `verify` with `TpmtSigScheme::Mldsa`, empty context required).
        let mu = [0x5au8; TpmiMldsaParms::MU_BYTES];
        let mut mu_buf: SignatureBuffer = [0u8; MAX_SIGNATURE_BYTES];
        assert_eq!(
            sign(
                &mut rng,
                SigningKey::Mldsa {
                    key: &priv_key,
                    context: &[],
                },
                TpmtSigScheme::Mldsa,
                &mu[..32],
                &mut mu_buf,
            ),
            Err(CryptoError::Internal)
        );
        assert_eq!(
            sign(
                &mut rng,
                SigningKey::Mldsa {
                    key: &priv_key,
                    context: b"non-empty",
                },
                TpmtSigScheme::Mldsa,
                &mu,
                &mut mu_buf,
            ),
            Err(CryptoError::Internal)
        );
        let mu_sig = sign(
            &mut rng,
            SigningKey::Mldsa {
                key: &priv_key,
                context: &[],
            },
            TpmtSigScheme::Mldsa,
            &mu,
            &mut mu_buf,
        )
        .unwrap();
        assert!(
            verify(
                VerifyingKey::Mldsa {
                    key: &pub_key,
                    context: &[],
                },
                &mu,
                mu_sig,
            )
            .unwrap()
        );
        assert!(
            !verify(
                VerifyingKey::Mldsa {
                    key: &pub_key,
                    context: b"non-empty",
                },
                &mu,
                mu_sig,
            )
            .unwrap()
        );
        assert!(
            !verify(
                VerifyingKey::Mldsa {
                    key: &pub_key,
                    context: &[],
                },
                &[0u8; 64],
                mu_sig,
            )
            .unwrap()
        );
        assert!(
            !verify(
                VerifyingKey::Mldsa {
                    key: &pub_key,
                    context: &[],
                },
                &mu[..32],
                mu_sig,
            )
            .unwrap()
        );

        // 3. HashML-DSA prehash signing (`sign` / `verify` with `TpmtSigScheme::HashMldsa`).
        #[cfg(feature = "hash_mldsa")]
        {
            let alg = first_enabled_hash();
            let digest = &[0x7bu8; 64][..alg.digest_size()];
            let mut ph_buf: SignatureBuffer = [0u8; MAX_SIGNATURE_BYTES];
            assert_eq!(
                sign(
                    &mut rng,
                    SigningKey::HashMldsa {
                        key: &priv_key,
                        hash: alg,
                        context: &overlong_ctx,
                    },
                    TpmtSigScheme::HashMldsa,
                    digest,
                    &mut ph_buf,
                ),
                Err(CryptoError::Internal)
            );
            let ph_sig = sign(
                &mut rng,
                SigningKey::HashMldsa {
                    key: &priv_key,
                    hash: alg,
                    context: ctx,
                },
                TpmtSigScheme::HashMldsa,
                digest,
                &mut ph_buf,
            )
            .unwrap();
            assert!(
                matches!(ph_sig, TpmtSignature::HashMldsa(s) if s.hash == alg && s.signature.as_slice().len() == 2420)
            );
            assert!(
                verify(
                    VerifyingKey::Mldsa {
                        key: &pub_key,
                        context: ctx,
                    },
                    digest,
                    ph_sig,
                )
                .unwrap()
            );
            assert!(
                !verify(
                    VerifyingKey::Mldsa {
                        key: &pub_key,
                        context: b"wrong-ctx",
                    },
                    digest,
                    ph_sig,
                )
                .unwrap()
            );
            assert!(
                !verify(
                    VerifyingKey::Mldsa {
                        key: &pub_key,
                        context: &overlong_ctx,
                    },
                    digest,
                    ph_sig,
                )
                .unwrap()
            );
            assert!(
                !verify(
                    VerifyingKey::Mldsa {
                        key: &pub_key,
                        context: ctx,
                    },
                    &[0u8; 64][..alg.digest_size()],
                    ph_sig,
                )
                .unwrap()
            );
        }

        // `!`-bound parameter set (`Mldsa65 = !`) returns Unsupported.
        #[cfg(feature = "mldsa_65")]
        assert_eq!(
            MldsaPrivateKey::<TestBackend>::generate(&mut rng, TpmiMldsaParms::Mldsa65).err(),
            Some(CryptoError::Unsupported)
        );
    }

    #[cfg(feature = "mlkem_768")]
    #[test]
    fn mlkem_encapsulate_and_decapsulate() {
        use crate::{Tpm2b, Tpm2bKemCiphertext, Tpm2bPublicKeyMlkem, TpmiMlkemParms};

        let mut rng = TestBackend::from_seed(b"mlkem-seed").unwrap();
        let priv_key =
            MlkemPrivateKey::<TestBackend>::generate(&mut rng, TpmiMlkemParms::Mlkem768).unwrap();
        assert_eq!(priv_key.parms(), TpmiMlkemParms::Mlkem768);

        let mut pk_buf: MlkemPubKeyBuffer = [0u8; TpmiMlkemParms::MAX_PUB_KEY_BYTES];
        let mut seed_buf: MlkemSeedBuffer = [0u8; 64];
        let pk_2b = priv_key.public(&mut pk_buf).unwrap();
        assert_eq!(pk_2b.as_slice().len(), 1184);
        let seed_2b = priv_key.seed(&mut seed_buf).unwrap();

        // Wrong length or failed modulus check returns Ok(None).
        let short_pk = Tpm2bPublicKeyMlkem::new(&[0x22; 32]).unwrap();
        assert!(
            MlkemPublicKey::<TestBackend>::load(TpmiMlkemParms::Mlkem768, short_pk)
                .unwrap()
                .is_none()
        );
        let bad_pk = Tpm2bPublicKeyMlkem::new(&[0xff; 1184]).unwrap();
        assert!(
            MlkemPublicKey::<TestBackend>::load(TpmiMlkemParms::Mlkem768, bad_pk)
                .unwrap()
                .is_none()
        );

        let pub_key = MlkemPublicKey::<TestBackend>::load(TpmiMlkemParms::Mlkem768, pk_2b)
            .unwrap()
            .unwrap();
        assert_eq!(pub_key.parms(), TpmiMlkemParms::Mlkem768);

        // Wrong seed rejected with Ok(None) by `load_private`.
        assert!(
            MlkemPrivateKey::<TestBackend>::load(pub_key, Tpm2b(&[0x55u8; 64]))
                .unwrap()
                .is_none()
        );
        let pub_key = MlkemPublicKey::<TestBackend>::load(TpmiMlkemParms::Mlkem768, pk_2b)
            .unwrap()
            .unwrap();
        let reloaded_priv = MlkemPrivateKey::<TestBackend>::load(pub_key, seed_2b)
            .unwrap()
            .unwrap();
        let pub_key = MlkemPublicKey::<TestBackend>::load(TpmiMlkemParms::Mlkem768, pk_2b)
            .unwrap()
            .unwrap();

        // Encapsulate & decapsulate roundtrip.
        let mut ct_buf: MlkemCiphertextBuffer = [0u8; TpmiMlkemParms::MAX_CT_BYTES];
        let mut ss_enc_buf: MlkemSharedSecretBuffer = [0u8; TpmiMlkemParms::SHARED_SECRET_BYTES];
        let mut ss_dec_buf: MlkemSharedSecretBuffer = [0u8; TpmiMlkemParms::SHARED_SECRET_BYTES];
        let (ct, ss_enc) = pub_key
            .encapsulate(&mut rng, &mut ct_buf, &mut ss_enc_buf)
            .unwrap();
        assert_eq!(ct.as_slice().len(), 1088);
        assert_eq!(ss_enc.as_slice().len(), 32);

        let ss_dec = reloaded_priv
            .decapsulate(ct, &mut ss_dec_buf)
            .unwrap()
            .unwrap();
        assert_eq!(ss_enc, ss_dec);

        // Wrong ciphertext length returns Ok(None).
        let short_ct = Tpm2bKemCiphertext::new(&[0u8; 32]).unwrap();
        assert!(
            reloaded_priv
                .decapsulate(short_ct, &mut ss_dec_buf)
                .unwrap()
                .is_none()
        );

        // `!`-bound parameter set (`Mlkem512 = !`) returns Unsupported.
        #[cfg(feature = "mlkem_512")]
        assert_eq!(
            MlkemPrivateKey::<TestBackend>::generate(&mut rng, TpmiMlkemParms::Mlkem512).err(),
            Some(CryptoError::Unsupported)
        );
    }
}
