//! ML-KEM (`ML-KEM-768` and `ML-KEM-1024`, FIPS 203) implementations backed by
//! BoringSSL's internal FIPS module (`BCM_mlkem768_*` and `BCM_mlkem1024_*`).

use tpm2::crypto::{
    CryptoError, Rng,
    backend::{AsymmetricKey, Mlkem, MlkemKey},
};

use crate::{
    BoringSsl,
    bcm::{self, BsslBox},
    bssl_sys,
};

macro_rules! impl_mlkem {
    (
        $Marker:ident,
        $PubKey:ident,
        $PrivKey:ident,
        $pub_size:literal,
        $ct_size:literal,
        $pub_ty:ident,
        $priv_ty:ident,
        $parse_pub:ident,
        $gen_ext_seed:ident,
        $pub_from_priv:ident,
        $encap_ext:ident,
        $decap:ident
    ) => {
        /// Validated ML-KEM encapsulation (public) key backed by BoringSSL BCM.
        #[derive(Clone)]
        pub struct $PubKey {
            key: BsslBox<bcm::$pub_ty>,
            encoded: [u8; $pub_size],
        }

        // SAFETY: `bcm::MLKEM*_public_key` is a plain value struct with no
        // interior mutability or thread-local state.
        unsafe impl Send for $PubKey {}
        unsafe impl Sync for $PubKey {}

        /// Validated ML-KEM decapsulation (private) key backed by BoringSSL BCM.
        #[derive(Clone)]
        pub struct $PrivKey {
            key: BsslBox<bcm::$priv_ty>,
            seed: [u8; 64],
            public: $PubKey,
        }

        // SAFETY: `bcm::MLKEM*_private_key` is a plain value struct with no
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

        /// Marker type implementing [`MlkemKey`].
        pub struct $Marker;

        impl $Marker {
            /// Expands the private key (and its public key) from `seed`.
            #[inline(never)]
            fn from_seed(seed: &[u8; 64]) -> Result<Option<$PrivKey>, CryptoError> {
                let mut pub_encoded = [0u8; $pub_size];
                let priv_key = BsslBox::<bcm::$priv_ty>::try_init(|ptr| {
                    let _ =
                        unsafe { bcm::$gen_ext_seed(pub_encoded.as_mut_ptr(), ptr, seed.as_ptr()) };
                    Ok(true)
                })?
                .ok_or(CryptoError::Internal)?;
                let pub_key = BsslBox::<bcm::$pub_ty>::try_init(|ptr| {
                    let _ = unsafe { bcm::$pub_from_priv(ptr, priv_key.as_ptr()) };
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
        }

        impl AsymmetricKey<$pub_size, 64> for $Marker {
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
                seed: &[u8; 64],
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
                let mut seed = [0u8; 64];
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
                out: &mut [u8; 64],
            ) -> Result<(), CryptoError> {
                *out = private.seed;
                Ok(())
            }
        }

        impl MlkemKey<$pub_size, $ct_size> for $Marker {
            #[inline(never)]
            fn encapsulate(
                rng: &mut impl Rng,
                public: &Self::Public,
                out_ct: &mut [u8; $ct_size],
                out_ss: &mut [u8; 32],
            ) -> Result<(), CryptoError> {
                let mut entropy = [0u8; 32];
                rng.fill_bytes(&mut entropy)?;
                let _ = unsafe {
                    bcm::$encap_ext(
                        out_ct.as_mut_ptr(),
                        out_ss.as_mut_ptr(),
                        public.key.as_ptr(),
                        entropy.as_ptr(),
                    )
                };
                unsafe {
                    bssl_sys::OPENSSL_cleanse(entropy.as_mut_ptr().cast(), entropy.len());
                }
                Ok(())
            }

            #[inline(never)]
            fn decapsulate(
                private: &Self::Private,
                ct: &[u8; $ct_size],
                out_ss: &mut [u8; 32],
            ) -> Result<(), CryptoError> {
                let status = unsafe {
                    bcm::$decap(
                        out_ss.as_mut_ptr(),
                        ct.as_ptr(),
                        $ct_size,
                        private.key.as_ptr(),
                    )
                };
                bcm::check_status(status)
            }
        }
    };
}

impl_mlkem!(
    BoringSslMlkem768,
    BoringSslMlkem768PublicKey,
    BoringSslMlkem768PrivateKey,
    1184,
    1088,
    MLKEM768_public_key,
    MLKEM768_private_key,
    bssl_BCM_mlkem768_parse_public_key,
    bssl_BCM_mlkem768_generate_key_external_seed,
    bssl_BCM_mlkem768_public_from_private,
    bssl_BCM_mlkem768_encap_external_entropy,
    bssl_BCM_mlkem768_decap
);

impl_mlkem!(
    BoringSslMlkem1024,
    BoringSslMlkem1024PublicKey,
    BoringSslMlkem1024PrivateKey,
    1568,
    1568,
    MLKEM1024_public_key,
    MLKEM1024_private_key,
    bssl_BCM_mlkem1024_parse_public_key,
    bssl_BCM_mlkem1024_generate_key_external_seed,
    bssl_BCM_mlkem1024_public_from_private,
    bssl_BCM_mlkem1024_encap_external_entropy,
    bssl_BCM_mlkem1024_decap
);

impl Mlkem for BoringSsl {
    type Mlkem512 = !;
    type Mlkem768 = BoringSslMlkem768;
    type Mlkem1024 = BoringSslMlkem1024;
}
