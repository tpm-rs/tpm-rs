//! ML-DSA (`ML-DSA-44`, `ML-DSA-65`, and `ML-DSA-87`, FIPS 204) implementations
//! via BoringSSL's `MLDSA44_*`, `MLDSA65_*`, and `MLDSA87_*` functions.
//!
//! All signing and verification goes through the 64-byte message
//! representative `µ` (`MLDSA*_sign_message_representative` and
//! `MLDSA*_verify_message_representative`):
//! - Pure ML-DSA computes `µ` with `MLDSA*_prehash_*`.
//! - External-`µ` signs and verifies `µ` directly.
//! - `HashML-DSA` computes `µ` with `SHAKE256` (`EVP_shake256`), as BoringSSL
//!   has no public `HashML-DSA` API.

use core::{
    mem::MaybeUninit,
    ptr::{self, null_mut},
};

use tpm2::{
    TpmiAlgHash, TpmtHa,
    crypto::{
        CryptoError, Rng,
        backend::{Mldsa, MldsaKey, PrivateKey},
    },
};

use crate::bssl_sys;
use crate::{
    BoringSsl, BoringSslRng,
    util::{self, BsslBox},
};

/// Returns the ASN.1 DER `OBJECT IDENTIFIER` TLV for a FIPS 204 `HashML-DSA`
/// prehash algorithm (`SHA-256/384/512` and `SHA3-256/384/512`), or
/// `Err(CryptoError::Unsupported)` for non-FIPS-204 hashes (`SHA-1`, `SM3-256`).
const fn hash_mldsa_oid(alg: TpmiAlgHash) -> Result<&'static [u8], CryptoError> {
    match alg {
        TpmiAlgHash::Sha256 => Ok(&[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ]),
        TpmiAlgHash::Sha384 => Ok(&[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        ]),
        TpmiAlgHash::Sha512 => Ok(&[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        ]),
        TpmiAlgHash::Sha3_256 => Ok(&[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
        ]),
        TpmiAlgHash::Sha3_384 => Ok(&[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09,
        ]),
        TpmiAlgHash::Sha3_512 => Ok(&[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A,
        ]),
        TpmiAlgHash::Sha1 | TpmiAlgHash::Sm3_256 => Err(CryptoError::Unsupported),
    }
}

/// Returns `SHAKE256(parts[0] || parts[1] || .., 512)`.
fn shake256(parts: &[&[u8]]) -> Result<[u8; 64], CryptoError> {
    let mut out = [0u8; 64];
    let mut ctx = MaybeUninit::<bssl_sys::EVP_MD_CTX>::uninit();
    let ctx = ctx.as_mut_ptr();
    unsafe {
        bssl_sys::EVP_MD_CTX_init(ctx);
        let ok = bssl_sys::EVP_DigestInit_ex(ctx, bssl_sys::EVP_shake256(), null_mut()) == 1
            && parts
                .iter()
                .all(|p| bssl_sys::EVP_DigestUpdate(ctx, p.as_ptr().cast(), p.len()) == 1)
            && bssl_sys::EVP_DigestFinalXOF(ctx, out.as_mut_ptr(), out.len()) == 1;
        bssl_sys::EVP_MD_CTX_cleanup(ctx);
        if !ok {
            return Err(CryptoError::Internal);
        }
    }
    Ok(out)
}

/// Returns the FIPS 204 `HashML-DSA` message representative
/// `µ = SHAKE256(SHAKE256(pk, 512) || 0x01 || |ctx| || ctx || OID || PH_M, 512)`
/// (Algorithms 4 and 5, and Algorithm 7, steps 6 and 7).
fn hash_mldsa_mu(
    encoded_pub: &[u8],
    context: &[u8],
    digest: TpmtHa<'_>,
) -> Result<[u8; 64], CryptoError> {
    let ctx_len = u8::try_from(context.len()).map_err(|_| CryptoError::Internal)?;
    let oid = hash_mldsa_oid(digest.hash_alg())?;
    let tr = shake256(&[encoded_pub])?;
    shake256(&[&tr, &[0x01, ctx_len], context, oid, digest.digest()])
}

macro_rules! impl_mldsa {
    (
        $PubKey:ident,
        $PrivKey:ident,
        $pub_size:literal,
        $sig_size:literal,
        $pub_ty:ident,
        $priv_ty:ident,
        $prehash_ty:ident,
        $from_seed:ident,
        $pub_from_priv:ident,
        $marshal_pub:ident,
        $parse_pub:ident,
        $prehash_init:ident,
        $prehash_update:ident,
        $prehash_finalize:ident,
        $sign_mu:ident,
        $verify_mu:ident
    ) => {
        /// Validated ML-DSA verification (public) key.
        #[derive(Clone)]
        pub struct $PubKey {
            key: BsslBox<bssl_sys::$pub_ty>,
            encoded: [u8; $pub_size],
        }

        // SAFETY: `MLDSA*_public_key` is a plain value struct with no interior
        // mutability or thread-local state.
        unsafe impl Send for $PubKey {}
        unsafe impl Sync for $PubKey {}

        /// Validated ML-DSA signing (private) key.
        #[derive(Clone)]
        pub struct $PrivKey {
            key: BsslBox<bssl_sys::$priv_ty>,
            seed: [u8; 32],
            public: $PubKey,
        }

        // SAFETY: `MLDSA*_private_key` is a plain value struct with no interior
        // mutability or thread-local state.
        unsafe impl Send for $PrivKey {}
        unsafe impl Sync for $PrivKey {}

        impl Drop for $PrivKey {
            fn drop(&mut self) {
                unsafe {
                    bssl_sys::OPENSSL_cleanse(self.seed.as_mut_ptr().cast(), self.seed.len());
                }
            }
        }

        impl $PrivKey {
            /// Expands the private key (and its public key) from `seed`.
            #[inline(never)]
            fn from_seed(seed: &[u8; 32]) -> Result<Self, CryptoError> {
                let key = BsslBox::<bssl_sys::$priv_ty>::try_init(|ptr| {
                    Ok(unsafe { bssl_sys::$from_seed(ptr, seed.as_ptr(), seed.len()) } == 1)
                })?
                .ok_or(CryptoError::Internal)?;
                let pub_key = BsslBox::<bssl_sys::$pub_ty>::try_init(|ptr| {
                    Ok(unsafe { bssl_sys::$pub_from_priv(ptr, key.as_ptr()) } == 1)
                })?
                .ok_or(CryptoError::Internal)?;
                let encoded =
                    util::marshal(|cbb| unsafe { bssl_sys::$marshal_pub(cbb, pub_key.as_ptr()) })?;
                Ok(Self {
                    key,
                    seed: *seed,
                    public: $PubKey {
                        key: pub_key,
                        encoded,
                    },
                })
            }

            /// Returns the pure ML-DSA message representative
            /// `µ = SHAKE256(tr || 0x00 || |ctx| || ctx || M, 512)` of the
            /// multi-slice message `msg`.
            fn compute_mu(
                public: &$PubKey,
                context: &[u8],
                msg: &[&[u8]],
            ) -> Result<[u8; 64], CryptoError> {
                let mut prehash = MaybeUninit::<bssl_sys::$prehash_ty>::uninit();
                let prehash = prehash.as_mut_ptr();
                let ctx_ptr = if context.is_empty() {
                    ptr::null()
                } else {
                    context.as_ptr()
                };
                let mut mu = [0u8; 64];
                unsafe {
                    let ok = bssl_sys::$prehash_init(
                        prehash,
                        public.key.as_ptr(),
                        ctx_ptr,
                        context.len(),
                    );
                    if ok != 1 {
                        return Err(CryptoError::Internal);
                    }
                    for slice in msg {
                        bssl_sys::$prehash_update(prehash, slice.as_ptr(), slice.len());
                    }
                    bssl_sys::$prehash_finalize(mu.as_mut_ptr(), prehash);
                }
                Ok(mu)
            }
        }

        impl PrivateKey<$pub_size, 32, BoringSslRng> for $PrivKey {
            type PublicKey = $PubKey;

            #[inline(never)]
            fn generate(rng: &mut BoringSslRng, _: ()) -> Result<Self, CryptoError> {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed)?;
                let res = Self::from_seed(&seed);
                unsafe {
                    bssl_sys::OPENSSL_cleanse(seed.as_mut_ptr().cast(), seed.len());
                }
                res
            }

            #[inline(never)]
            fn load(public: Self::PublicKey, seed: &[u8; 32]) -> Result<Option<Self>, CryptoError> {
                let private = Self::from_seed(seed)?;
                // The seed must expand to `public`.
                Ok((private.public.encoded == public.encoded).then_some(private))
            }

            fn store(&self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
                *out = self.seed;
                Ok(())
            }

            fn as_public(&self) -> &Self::PublicKey {
                &self.public
            }

            #[inline(never)]
            fn load_public(
                _: (),
                public: &[u8; $pub_size],
            ) -> Result<Option<Self::PublicKey>, CryptoError> {
                let key = BsslBox::<bssl_sys::$pub_ty>::try_init(|ptr| {
                    Ok(util::parse(public, |cbs| unsafe {
                        bssl_sys::$parse_pub(ptr, cbs)
                    }))
                })?;
                Ok(key.map(|key| $PubKey {
                    key,
                    encoded: *public,
                }))
            }

            fn store_public(
                public: &Self::PublicKey,
                out: &mut [u8; $pub_size],
            ) -> Result<(), CryptoError> {
                *out = public.encoded;
                Ok(())
            }
        }

        impl MldsaKey<$pub_size, $sig_size, BoringSslRng> for $PrivKey {
            #[inline(never)]
            fn sign_message(
                &self,
                rng: &mut BoringSslRng,
                context: &[u8],
                msg: &[&[u8]],
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                let mu = Self::compute_mu(&self.public, context, msg)?;
                self.sign_mu(rng, &mu, out_sig)
            }

            #[inline(never)]
            fn verify_message(
                public: &Self::PublicKey,
                context: &[u8],
                msg: &[&[u8]],
                sig: &[u8; $sig_size],
            ) -> Result<bool, CryptoError> {
                let mu = Self::compute_mu(public, context, msg)?;
                Self::verify_mu(public, &mu, sig)
            }

            #[inline(never)]
            fn sign_mu(
                &self,
                rng: &mut BoringSslRng,
                mu: &[u8; 64],
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                rng.check_system()?;
                let ok = unsafe {
                    bssl_sys::$sign_mu(out_sig.as_mut_ptr(), self.key.as_ptr(), mu.as_ptr())
                };
                if ok != 1 {
                    return Err(CryptoError::Internal);
                }
                Ok(())
            }

            #[inline(never)]
            fn verify_mu(
                public: &Self::PublicKey,
                mu: &[u8; 64],
                sig: &[u8; $sig_size],
            ) -> Result<bool, CryptoError> {
                let ok = unsafe {
                    bssl_sys::$verify_mu(public.key.as_ptr(), sig.as_ptr(), sig.len(), mu.as_ptr())
                };
                Ok(ok == 1)
            }

            #[inline(never)]
            fn sign_prehash(
                &self,
                rng: &mut BoringSslRng,
                context: &[u8],
                digest: TpmtHa<'_>,
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                let mu = hash_mldsa_mu(&self.public.encoded, context, digest)?;
                self.sign_mu(rng, &mu, out_sig)
            }

            #[inline(never)]
            fn verify_prehash(
                public: &Self::PublicKey,
                context: &[u8],
                digest: TpmtHa<'_>,
                sig: &[u8; $sig_size],
            ) -> Result<bool, CryptoError> {
                let mu = hash_mldsa_mu(&public.encoded, context, digest)?;
                Self::verify_mu(public, &mu, sig)
            }
        }
    };
}

impl_mldsa!(
    BoringSslMldsa44PublicKey,
    BoringSslMldsa44PrivateKey,
    1312,
    2420,
    MLDSA44_public_key,
    MLDSA44_private_key,
    MLDSA44_prehash,
    MLDSA44_private_key_from_seed,
    MLDSA44_public_from_private,
    MLDSA44_marshal_public_key,
    MLDSA44_parse_public_key,
    MLDSA44_prehash_init,
    MLDSA44_prehash_update,
    MLDSA44_prehash_finalize,
    MLDSA44_sign_message_representative,
    MLDSA44_verify_message_representative
);

impl_mldsa!(
    BoringSslMldsa65PublicKey,
    BoringSslMldsa65PrivateKey,
    1952,
    3309,
    MLDSA65_public_key,
    MLDSA65_private_key,
    MLDSA65_prehash,
    MLDSA65_private_key_from_seed,
    MLDSA65_public_from_private,
    MLDSA65_marshal_public_key,
    MLDSA65_parse_public_key,
    MLDSA65_prehash_init,
    MLDSA65_prehash_update,
    MLDSA65_prehash_finalize,
    MLDSA65_sign_message_representative,
    MLDSA65_verify_message_representative
);

impl_mldsa!(
    BoringSslMldsa87PublicKey,
    BoringSslMldsa87PrivateKey,
    2592,
    4627,
    MLDSA87_public_key,
    MLDSA87_private_key,
    MLDSA87_prehash,
    MLDSA87_private_key_from_seed,
    MLDSA87_public_from_private,
    MLDSA87_marshal_public_key,
    MLDSA87_parse_public_key,
    MLDSA87_prehash_init,
    MLDSA87_prehash_update,
    MLDSA87_prehash_finalize,
    MLDSA87_sign_message_representative,
    MLDSA87_verify_message_representative
);

impl Mldsa for BoringSsl {
    type Mldsa44 = BoringSslMldsa44PrivateKey;
    type Mldsa65 = BoringSslMldsa65PrivateKey;
    type Mldsa87 = BoringSslMldsa87PrivateKey;
}
