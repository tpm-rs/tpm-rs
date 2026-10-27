//! ML-DSA (`ML-DSA-44`, `ML-DSA-65`, and `ML-DSA-87`, FIPS 204) implementations
//! backed by BoringSSL's internal FIPS module (`BCM_mldsa44_*`,
//! `BCM_mldsa65_*`, and `BCM_mldsa87_*`).
//!
//! Supports pure ML-DSA streaming message signing/verification (`sign_message`
//! and `verify_message` via `BCM_mldsa*_prehash_*`), external-`µ` digest
//! signing/verification (`sign_mu` and `verify_mu` via
//! `BCM_mldsa*_sign_mu_internal` and
//! `BCM_mldsa*_verify_message_representative`), and `HashML-DSA` prehash
//! signing/verification (`sign_prehash` and `verify_prehash` via
//! `BCM_mldsa*_sign_internal` and `BCM_mldsa*_verify_internal`).

use core::{mem::MaybeUninit, ptr};

use tpm2::{
    TpmiAlgHash, TpmtHa,
    crypto::{
        CryptoError, Rng,
        backend::{AsymmetricKey, Mldsa, MldsaKey},
    },
};

use crate::{
    BoringSsl,
    bcm::{self, BsslBox},
    bssl_sys,
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

macro_rules! impl_mldsa {
    (
        $Marker:ident,
        $PubKey:ident,
        $PrivKey:ident,
        $pub_size:literal,
        $sig_size:literal,
        $pub_ty:ident,
        $priv_ty:ident,
        $prehash_ty:ident,
        $parse_pub:ident,
        $gen_ext_entropy:ident,
        $pub_from_priv:ident,
        $prehash_init:ident,
        $prehash_update:ident,
        $prehash_finalize:ident,
        $sign_mu_internal:ident,
        $verify_mu:ident,
        $sign_internal:ident,
        $verify_internal:ident
    ) => {
        /// Validated ML-DSA verification (public) key backed by BoringSSL BCM.
        #[derive(Clone)]
        pub struct $PubKey {
            key: BsslBox<bcm::$pub_ty>,
            encoded: [u8; $pub_size],
        }

        // SAFETY: `bcm::MLDSA*_public_key` is a plain value struct with no
        // interior mutability or thread-local state.
        unsafe impl Send for $PubKey {}
        unsafe impl Sync for $PubKey {}

        /// Validated ML-DSA signing (private) key backed by BoringSSL BCM.
        #[derive(Clone)]
        pub struct $PrivKey {
            key: BsslBox<bcm::$priv_ty>,
            seed: [u8; 32],
            public: $PubKey,
        }

        // SAFETY: `bcm::MLDSA*_private_key` is a plain value struct with no
        // interior mutability or thread-local state.
        unsafe impl Send for $PrivKey {}
        unsafe impl Sync for $PrivKey {}

        impl Drop for $PrivKey {
            fn drop(&mut self) {
                unsafe {
                    bssl_sys::OPENSSL_cleanse(self.seed.as_mut_ptr().cast(), self.seed.len());
                }
            }
        }

        /// Marker type implementing [`MldsaKey`].
        pub struct $Marker;

        impl $Marker {
            /// Expands the private key (and its public key) from `seed`.
            #[inline(never)]
            fn from_seed(seed: &[u8; 32]) -> Result<Option<$PrivKey>, CryptoError> {
                let mut pub_encoded = [0u8; $pub_size];
                let priv_key = BsslBox::<bcm::$priv_ty>::try_init(|ptr| {
                    let status = unsafe {
                        bcm::$gen_ext_entropy(pub_encoded.as_mut_ptr(), ptr, seed.as_ptr())
                    };
                    bcm::check_status(status)?;
                    Ok(true)
                })?
                .ok_or(CryptoError::Internal)?;
                let pub_key = BsslBox::<bcm::$pub_ty>::try_init(|ptr| {
                    let status = unsafe { bcm::$pub_from_priv(ptr, priv_key.as_ptr()) };
                    bcm::check_status(status)?;
                    Ok(true)
                })?
                .ok_or(CryptoError::Internal)?;
                let public = $PubKey {
                    key: pub_key,
                    encoded: pub_encoded,
                };
                Ok(Some($PrivKey {
                    key: priv_key,
                    seed: *seed,
                    public,
                }))
            }

            /// Computes the 64-byte FIPS 204 message representative
            /// `µ = SHAKE256(tr || 0x00 || |ctx| || ctx || M, 64)` over
            /// multi-slice `msg` with context string `context` (`<= 255` bytes).
            fn compute_mu(public_key: &bcm::$pub_ty, context: &[u8], msg: &[&[u8]]) -> [u8; 64] {
                let mut prehash = MaybeUninit::<bcm::$prehash_ty>::uninit();
                let ctx_ptr = if context.is_empty() {
                    ptr::null()
                } else {
                    context.as_ptr()
                };
                unsafe {
                    bcm::$prehash_init(prehash.as_mut_ptr(), public_key, ctx_ptr, context.len());
                }
                let mut prehash = unsafe { prehash.assume_init() };
                for slice in msg {
                    if !slice.is_empty() {
                        unsafe {
                            bcm::$prehash_update(&raw mut prehash, slice.as_ptr(), slice.len());
                        }
                    }
                }
                let mut mu = [0u8; 64];
                unsafe {
                    bcm::$prehash_finalize(mu.as_mut_ptr(), &raw mut prehash);
                }
                mu
            }
        }

        impl AsymmetricKey<$pub_size, 32> for $Marker {
            type Public = $PubKey;
            type Private = $PrivKey;

            #[inline(never)]
            fn load_public(
                _: (),
                public: &[u8; $pub_size],
            ) -> Result<Option<Self::Public>, CryptoError> {
                let Some(key) = BsslBox::<bcm::$pub_ty>::try_init(|ptr| {
                    let mut cbs = bssl_sys::CBS {
                        data: public.as_ptr(),
                        len: $pub_size,
                    };
                    let status = unsafe { bcm::$parse_pub(ptr, (&raw mut cbs).cast::<bcm::CBS>()) };
                    Ok(status != bcm::bssl_bcm_status_t_failure && cbs.len == 0)
                })?
                else {
                    return Ok(None);
                };
                Ok(Some($PubKey {
                    key,
                    encoded: *public,
                }))
            }

            fn store_public(
                public: &Self::Public,
                out: &mut [u8; $pub_size],
            ) -> Result<(), CryptoError> {
                *out = public.encoded;
                Ok(())
            }

            #[inline(never)]
            fn load_private(
                public: Self::Public,
                seed: &[u8; 32],
            ) -> Result<Option<Self::Private>, CryptoError> {
                let Some(private) = Self::from_seed(seed)? else {
                    return Ok(None);
                };
                // The seed must expand to `public`.
                if private.public.encoded != public.encoded {
                    return Ok(None);
                }
                Ok(Some(private))
            }

            #[inline(never)]
            fn generate(rng: &mut impl Rng, _: ()) -> Result<Self::Private, CryptoError> {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed)?;
                let res = Self::from_seed(&seed)?.ok_or(CryptoError::Internal);
                unsafe {
                    bssl_sys::OPENSSL_cleanse(seed.as_mut_ptr().cast(), seed.len());
                }
                res
            }

            fn as_public(private: &Self::Private) -> &Self::Public {
                &private.public
            }

            fn store_private(
                private: &Self::Private,
                out: &mut [u8; 32],
            ) -> Result<(), CryptoError> {
                *out = private.seed;
                Ok(())
            }
        }

        impl MldsaKey<$pub_size, $sig_size> for $Marker {
            #[inline(never)]
            fn sign_message(
                rng: &mut impl Rng,
                private: &Self::Private,
                context: &[u8],
                msg: &[&[u8]],
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                if context.len() > 255 {
                    return Err(CryptoError::Internal);
                }
                let mu = Self::compute_mu(&private.public.key, context, msg);
                Self::sign_mu(rng, private, &mu, out_sig)
            }

            #[inline(never)]
            fn verify_message(
                public: &Self::Public,
                context: &[u8],
                msg: &[&[u8]],
                sig: &[u8; $sig_size],
            ) -> Result<bool, CryptoError> {
                if context.len() > 255 {
                    return Err(CryptoError::Internal);
                }
                let mu = Self::compute_mu(&public.key, context, msg);
                Self::verify_mu(public, &mu, sig)
            }

            #[inline(never)]
            fn sign_mu(
                rng: &mut impl Rng,
                private: &Self::Private,
                mu: &[u8; 64],
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                let mut randomizer = [0u8; 32];
                rng.fill_bytes(&mut randomizer)?;
                let status = unsafe {
                    bcm::$sign_mu_internal(
                        out_sig.as_mut_ptr(),
                        private.key.as_ptr(),
                        mu.as_ptr(),
                        randomizer.as_ptr(),
                    )
                };
                unsafe {
                    bssl_sys::OPENSSL_cleanse(randomizer.as_mut_ptr().cast(), randomizer.len());
                }
                bcm::check_status(status)
            }

            #[inline(never)]
            fn verify_mu(
                public: &Self::Public,
                mu: &[u8; 64],
                sig: &[u8; $sig_size],
            ) -> Result<bool, CryptoError> {
                let status =
                    unsafe { bcm::$verify_mu(public.key.as_ptr(), sig.as_ptr(), mu.as_ptr()) };
                Ok(status != bcm::bssl_bcm_status_t_failure)
            }

            #[inline(never)]
            fn sign_prehash(
                rng: &mut impl Rng,
                private: &Self::Private,
                context: &[u8],
                digest: TpmtHa<'_>,
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                let Ok(ctx_len) = u8::try_from(context.len()) else {
                    return Err(CryptoError::Internal);
                };
                let oid = hash_mldsa_oid(digest.hash_alg())?;
                // FIPS 204 Algorithm 4 (`HashML-DSA.Sign`):
                // M' = 0x01 || |ctx| || ctx || OID || PH_M
                let prefix: [u8; 2] = [0x01, ctx_len];
                let bytes = digest.digest();
                let mut oid_and_ph = [0u8; 11 + 64];
                let msg_len = oid.len() + bytes.len();
                oid_and_ph[..oid.len()].copy_from_slice(oid);
                oid_and_ph[oid.len()..msg_len].copy_from_slice(bytes);
                let ctx_ptr = if context.is_empty() {
                    ptr::null()
                } else {
                    context.as_ptr()
                };
                let mut randomizer = [0u8; 32];
                rng.fill_bytes(&mut randomizer)?;
                let status = unsafe {
                    bcm::$sign_internal(
                        out_sig.as_mut_ptr(),
                        private.key.as_ptr(),
                        oid_and_ph.as_ptr(),
                        msg_len,
                        prefix.as_ptr(),
                        prefix.len(),
                        ctx_ptr,
                        context.len(),
                        randomizer.as_ptr(),
                    )
                };
                unsafe {
                    bssl_sys::OPENSSL_cleanse(randomizer.as_mut_ptr().cast(), randomizer.len());
                }
                bcm::check_status(status)
            }

            #[inline(never)]
            fn verify_prehash(
                public: &Self::Public,
                context: &[u8],
                digest: TpmtHa<'_>,
                sig: &[u8; $sig_size],
            ) -> Result<bool, CryptoError> {
                let Ok(ctx_len) = u8::try_from(context.len()) else {
                    return Err(CryptoError::Internal);
                };
                let oid = hash_mldsa_oid(digest.hash_alg())?;
                // FIPS 204 Algorithm 5 (`HashML-DSA.Verify`):
                // M' = 0x01 || |ctx| || ctx || OID || PH_M
                let prefix: [u8; 2] = [0x01, ctx_len];
                let bytes = digest.digest();
                let mut oid_and_ph = [0u8; 11 + 64];
                let msg_len = oid.len() + bytes.len();
                oid_and_ph[..oid.len()].copy_from_slice(oid);
                oid_and_ph[oid.len()..msg_len].copy_from_slice(bytes);
                let ctx_ptr = if context.is_empty() {
                    ptr::null()
                } else {
                    context.as_ptr()
                };
                let status = unsafe {
                    bcm::$verify_internal(
                        public.key.as_ptr(),
                        sig.as_ptr(),
                        oid_and_ph.as_ptr(),
                        msg_len,
                        prefix.as_ptr(),
                        prefix.len(),
                        ctx_ptr,
                        context.len(),
                    )
                };
                Ok(status != bcm::bssl_bcm_status_t_failure)
            }
        }
    };
}

impl_mldsa!(
    BoringSslMldsa44,
    BoringSslMldsa44PublicKey,
    BoringSslMldsa44PrivateKey,
    1312,
    2420,
    MLDSA44_public_key,
    MLDSA44_private_key,
    MLDSA44_prehash,
    bssl_BCM_mldsa44_parse_public_key,
    bssl_BCM_mldsa44_generate_key_external_entropy,
    bssl_BCM_mldsa44_public_from_private,
    bssl_BCM_mldsa44_prehash_init,
    bssl_BCM_mldsa44_prehash_update,
    bssl_BCM_mldsa44_prehash_finalize,
    bssl_BCM_mldsa44_sign_mu_internal,
    bssl_BCM_mldsa44_verify_message_representative,
    bssl_BCM_mldsa44_sign_internal,
    bssl_BCM_mldsa44_verify_internal
);

impl_mldsa!(
    BoringSslMldsa65,
    BoringSslMldsa65PublicKey,
    BoringSslMldsa65PrivateKey,
    1952,
    3309,
    MLDSA65_public_key,
    MLDSA65_private_key,
    MLDSA65_prehash,
    bssl_BCM_mldsa65_parse_public_key,
    bssl_BCM_mldsa65_generate_key_external_entropy,
    bssl_BCM_mldsa65_public_from_private,
    bssl_BCM_mldsa65_prehash_init,
    bssl_BCM_mldsa65_prehash_update,
    bssl_BCM_mldsa65_prehash_finalize,
    bssl_BCM_mldsa65_sign_mu_internal,
    bssl_BCM_mldsa65_verify_message_representative,
    bssl_BCM_mldsa65_sign_internal,
    bssl_BCM_mldsa65_verify_internal
);

impl_mldsa!(
    BoringSslMldsa87,
    BoringSslMldsa87PublicKey,
    BoringSslMldsa87PrivateKey,
    2592,
    4627,
    MLDSA87_public_key,
    MLDSA87_private_key,
    MLDSA87_prehash,
    bssl_BCM_mldsa87_parse_public_key,
    bssl_BCM_mldsa87_generate_key_external_entropy,
    bssl_BCM_mldsa87_public_from_private,
    bssl_BCM_mldsa87_prehash_init,
    bssl_BCM_mldsa87_prehash_update,
    bssl_BCM_mldsa87_prehash_finalize,
    bssl_BCM_mldsa87_sign_mu_internal,
    bssl_BCM_mldsa87_verify_message_representative,
    bssl_BCM_mldsa87_sign_internal,
    bssl_BCM_mldsa87_verify_internal
);

impl Mldsa for BoringSsl {
    type Mldsa44 = BoringSslMldsa44;
    type Mldsa65 = BoringSslMldsa65;
    type Mldsa87 = BoringSslMldsa87;
}
