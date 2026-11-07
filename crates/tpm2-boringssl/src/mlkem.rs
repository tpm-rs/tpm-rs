//! ML-KEM (`ML-KEM-768` and `ML-KEM-1024`, FIPS 203) implementations via
//! BoringSSL's `MLKEM768_*` and `MLKEM1024_*` functions.

use tpm2::crypto::{
    CryptoError, Rng,
    backend::{Mlkem, MlkemKey, PrivateKey},
};

use crate::bssl_sys;
use crate::{
    BoringSsl, BoringSslRng,
    util::{self, BsslBox},
};

macro_rules! impl_mlkem {
    (
        $PubKey:ident,
        $PrivKey:ident,
        $pub_size:literal,
        $ct_size:literal,
        $pub_ty:ident,
        $priv_ty:ident,
        $from_seed:ident,
        $pub_from_priv:ident,
        $marshal_pub:ident,
        $parse_pub:ident,
        $encap:ident,
        $decap:ident
    ) => {
        /// Validated ML-KEM encapsulation (public) key.
        #[derive(Clone)]
        pub struct $PubKey {
            key: BsslBox<bssl_sys::$pub_ty>,
            encoded: [u8; $pub_size],
        }

        // SAFETY: `MLKEM*_public_key` is a plain value struct with no interior
        // mutability or thread-local state.
        unsafe impl Send for $PubKey {}
        unsafe impl Sync for $PubKey {}

        /// Validated ML-KEM decapsulation (private) key.
        #[derive(Clone)]
        pub struct $PrivKey {
            key: BsslBox<bssl_sys::$priv_ty>,
            seed: [u8; 64],
            public: $PubKey,
        }

        // SAFETY: `MLKEM*_private_key` is a plain value struct with no interior
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
            fn from_seed(seed: &[u8; 64]) -> Result<Self, CryptoError> {
                let key = BsslBox::<bssl_sys::$priv_ty>::try_init(|ptr| {
                    Ok(unsafe { bssl_sys::$from_seed(ptr, seed.as_ptr(), seed.len()) } == 1)
                })?
                .ok_or(CryptoError::Internal)?;
                let pub_key = BsslBox::<bssl_sys::$pub_ty>::try_init(|ptr| {
                    unsafe { bssl_sys::$pub_from_priv(ptr, key.as_ptr()) };
                    Ok(true)
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
        }

        impl PrivateKey<$pub_size, 64, BoringSslRng> for $PrivKey {
            type PublicKey = $PubKey;

            #[inline(never)]
            fn generate(rng: &mut BoringSslRng, _: ()) -> Result<Self, CryptoError> {
                let mut seed = [0u8; 64];
                rng.fill_bytes(&mut seed)?;
                let res = Self::from_seed(&seed);
                unsafe {
                    bssl_sys::OPENSSL_cleanse(seed.as_mut_ptr().cast(), seed.len());
                }
                res
            }

            #[inline(never)]
            fn load(public: Self::PublicKey, seed: &[u8; 64]) -> Result<Option<Self>, CryptoError> {
                let private = Self::from_seed(seed)?;
                // The seed must expand to `public`.
                Ok((private.public.encoded == public.encoded).then_some(private))
            }

            fn store(&self, out: &mut [u8; 64]) -> Result<(), CryptoError> {
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

        impl MlkemKey<$pub_size, $ct_size, BoringSslRng> for $PrivKey {
            #[inline(never)]
            fn encapsulate(
                public: &Self::PublicKey,
                rng: &mut BoringSslRng,
                out_ct: &mut [u8; $ct_size],
                out_ss: &mut [u8; 32],
            ) -> Result<(), CryptoError> {
                rng.check_system()?;
                unsafe {
                    bssl_sys::$encap(
                        out_ct.as_mut_ptr(),
                        out_ss.as_mut_ptr(),
                        public.key.as_ptr(),
                    )
                };
                Ok(())
            }

            #[inline(never)]
            fn decapsulate(
                &self,
                ct: &[u8; $ct_size],
                out_ss: &mut [u8; 32],
            ) -> Result<(), CryptoError> {
                let ok = unsafe {
                    bssl_sys::$decap(
                        out_ss.as_mut_ptr(),
                        ct.as_ptr(),
                        ct.len(),
                        self.key.as_ptr(),
                    )
                };
                if ok != 1 {
                    return Err(CryptoError::Internal);
                }
                Ok(())
            }
        }
    };
}

impl_mlkem!(
    BoringSslMlkem768PublicKey,
    BoringSslMlkem768PrivateKey,
    1184,
    1088,
    MLKEM768_public_key,
    MLKEM768_private_key,
    MLKEM768_private_key_from_seed,
    MLKEM768_public_from_private,
    MLKEM768_marshal_public_key,
    MLKEM768_parse_public_key,
    MLKEM768_encap,
    MLKEM768_decap
);

impl_mlkem!(
    BoringSslMlkem1024PublicKey,
    BoringSslMlkem1024PrivateKey,
    1568,
    1568,
    MLKEM1024_public_key,
    MLKEM1024_private_key,
    MLKEM1024_private_key_from_seed,
    MLKEM1024_public_from_private,
    MLKEM1024_marshal_public_key,
    MLKEM1024_parse_public_key,
    MLKEM1024_encap,
    MLKEM1024_decap
);

impl Mlkem for BoringSsl {
    type Mlkem512 = !;
    type Mlkem768 = BoringSslMlkem768PrivateKey;
    type Mlkem1024 = BoringSslMlkem1024PrivateKey;
}
