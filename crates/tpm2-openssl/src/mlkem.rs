use openssl_sys::*;
use std::ffi::CString;
use std::ptr;
use tpm2::crypto::backend::{AsymmetricKey, MlkemKey};
use tpm2::crypto::{CryptoError, Rng};

pub struct EvpPkey(*mut EVP_PKEY);
impl Drop for EvpPkey {
    fn drop(&mut self) {
        unsafe { EVP_PKEY_free(self.0) }
    }
}
impl EvpPkey {
    pub fn as_ptr(&self) -> *mut EVP_PKEY {
        self.0
    }
}

pub struct MlkemImpl<const PUB_SIZE: usize, const CT_SIZE: usize>;

macro_rules! impl_mlkem {
    ($name:ident, $pub_size:expr, $ct_size:expr, $alg_name:expr) => {
        pub struct $name;
        impl $name {
            fn from_seed(seed: &[u8; 64]) -> Result<Option<EvpPkey>, CryptoError> {
                unsafe {
                    let bld = OSSL_PARAM_BLD_new();
                    if bld.is_null() {
                        return Err(CryptoError::Internal);
                    }
                    let key_name = CString::new("seed").unwrap();
                    if OSSL_PARAM_BLD_push_octet_string(
                        bld,
                        key_name.as_ptr(),
                        seed.as_ptr() as *const _,
                        64,
                    ) != 1
                    {
                        OSSL_PARAM_BLD_free(bld);
                        return Err(CryptoError::Internal);
                    }
                    let params = OSSL_PARAM_BLD_to_param(bld);
                    OSSL_PARAM_BLD_free(bld);
                    if params.is_null() {
                        return Err(CryptoError::Internal);
                    }

                    let alg = CString::new($alg_name).unwrap();
                    let pctx =
                        EVP_PKEY_CTX_new_from_name(ptr::null_mut(), alg.as_ptr(), ptr::null_mut());
                    if pctx.is_null() {
                        OSSL_PARAM_free(params);
                        return Err(CryptoError::Internal);
                    }

                    if EVP_PKEY_fromdata_init(pctx) != 1 {
                        EVP_PKEY_CTX_free(pctx);
                        OSSL_PARAM_free(params);
                        return Err(CryptoError::Internal);
                    }

                    let mut pkey_ptr = ptr::null_mut();
                    let res = EVP_PKEY_fromdata(pctx, &mut pkey_ptr, EVP_PKEY_KEYPAIR, params);
                    EVP_PKEY_CTX_free(pctx);
                    OSSL_PARAM_free(params);

                    if res != 1 {
                        return Ok(None);
                    }
                    Ok(Some(EvpPkey(pkey_ptr)))
                }
            }
        }

        impl AsymmetricKey<$pub_size, 64> for $name {
            type Public = EvpPkey;
            type Private = EvpPkey;

            fn load_public(
                _: (),
                encoded: &[u8; $pub_size],
            ) -> Result<Option<Self::Public>, CryptoError> {
                unsafe {
                    let bld = OSSL_PARAM_BLD_new();
                    if bld.is_null() {
                        return Err(CryptoError::Internal);
                    }
                    let key_name = CString::new("pub").unwrap();
                    if OSSL_PARAM_BLD_push_octet_string(
                        bld,
                        key_name.as_ptr(),
                        encoded.as_ptr() as *const _,
                        $pub_size,
                    ) != 1
                    {
                        OSSL_PARAM_BLD_free(bld);
                        return Err(CryptoError::Internal);
                    }
                    let params = OSSL_PARAM_BLD_to_param(bld);
                    OSSL_PARAM_BLD_free(bld);
                    if params.is_null() {
                        return Err(CryptoError::Internal);
                    }

                    let alg = CString::new($alg_name).unwrap();
                    let pctx =
                        EVP_PKEY_CTX_new_from_name(ptr::null_mut(), alg.as_ptr(), ptr::null_mut());
                    if pctx.is_null() {
                        OSSL_PARAM_free(params);
                        return Err(CryptoError::Internal);
                    }

                    if EVP_PKEY_fromdata_init(pctx) != 1 {
                        EVP_PKEY_CTX_free(pctx);
                        OSSL_PARAM_free(params);
                        return Err(CryptoError::Internal);
                    }

                    let mut pkey_ptr = ptr::null_mut();
                    let res = EVP_PKEY_fromdata(pctx, &mut pkey_ptr, EVP_PKEY_PUBLIC_KEY, params);
                    EVP_PKEY_CTX_free(pctx);
                    OSSL_PARAM_free(params);

                    if res != 1 {
                        return Ok(None);
                    }
                    Ok(Some(EvpPkey(pkey_ptr)))
                }
            }

            fn store_public(
                public: &Self::Public,
                out: &mut [u8; $pub_size],
            ) -> Result<(), CryptoError> {
                unsafe {
                    let mut size: usize = 0;
                    if EVP_PKEY_get_octet_string_param(
                        public.as_ptr(),
                        CString::new("pub").unwrap().as_ptr(),
                        std::ptr::null_mut(),
                        0,
                        &mut size,
                    ) != 1
                        || size != $pub_size
                    {
                        return Err(CryptoError::Internal);
                    }
                    if EVP_PKEY_get_octet_string_param(
                        public.as_ptr(),
                        CString::new("pub").unwrap().as_ptr(),
                        out.as_mut_ptr(),
                        $pub_size,
                        &mut size,
                    ) != 1
                    {
                        return Err(CryptoError::Internal);
                    }
                    Ok(())
                }
            }

            fn load_private(
                public: Self::Public,
                seed: &[u8; 64],
            ) -> Result<Option<Self::Private>, CryptoError> {
                let Some(private) = Self::from_seed(seed)? else {
                    return Ok(None);
                };
                // The seed must expand to `public`.
                let mut expected = [0u8; $pub_size];
                let mut actual = [0u8; $pub_size];
                Self::store_public(&public, &mut expected)?;
                Self::store_public(&private, &mut actual)?;
                if expected != actual {
                    return Ok(None);
                }
                Ok(Some(private))
            }

            fn generate(rng: &mut impl Rng, _: ()) -> Result<Self::Private, CryptoError> {
                let mut seed = [0u8; 64];
                rng.fill_bytes(&mut seed)
                    .map_err(|_| CryptoError::Internal)?;
                Self::from_seed(&seed).and_then(|opt| opt.ok_or(CryptoError::Internal))
            }

            fn as_public(private: &Self::Private) -> &Self::Public {
                private
            }

            fn store_private(
                private: &Self::Private,
                out: &mut [u8; 64],
            ) -> Result<(), CryptoError> {
                unsafe {
                    let mut size: usize = 0;
                    if EVP_PKEY_get_octet_string_param(
                        private.as_ptr(),
                        CString::new("seed").unwrap().as_ptr(),
                        std::ptr::null_mut(),
                        0,
                        &mut size,
                    ) != 1
                        || size != 64
                    {
                        return Err(CryptoError::Internal);
                    }
                    if EVP_PKEY_get_octet_string_param(
                        private.as_ptr(),
                        CString::new("seed").unwrap().as_ptr(),
                        out.as_mut_ptr(),
                        64,
                        &mut size,
                    ) != 1
                    {
                        return Err(CryptoError::Internal);
                    }
                    Ok(())
                }
            }
        }

        impl MlkemKey<$pub_size, $ct_size> for $name {
            fn encapsulate(
                _rng: &mut impl Rng,
                public: &Self::Public,
                out_ct: &mut [u8; $ct_size],
                out_ss: &mut [u8; 32],
            ) -> Result<(), CryptoError> {
                unsafe {
                    let pctx = EVP_PKEY_CTX_new(public.as_ptr(), ptr::null_mut());
                    if pctx.is_null() {
                        return Err(CryptoError::Internal);
                    }
                    if EVP_PKEY_encapsulate_init(pctx, ptr::null()) != 1 {
                        EVP_PKEY_CTX_free(pctx);
                        return Err(CryptoError::Internal);
                    }

                    let mut ct_len = out_ct.len();
                    let mut ss_len = out_ss.len();

                    if EVP_PKEY_encapsulate(
                        pctx,
                        out_ct.as_mut_ptr(),
                        &mut ct_len,
                        out_ss.as_mut_ptr(),
                        &mut ss_len,
                    ) != 1
                    {
                        EVP_PKEY_CTX_free(pctx);
                        return Err(CryptoError::Internal);
                    }
                    EVP_PKEY_CTX_free(pctx);
                    if ct_len != $ct_size || ss_len != 32 {
                        return Err(CryptoError::Internal);
                    }
                    Ok(())
                }
            }

            fn decapsulate(
                private: &Self::Private,
                ct: &[u8; $ct_size],
                out_ss: &mut [u8; 32],
            ) -> Result<(), CryptoError> {
                unsafe {
                    let pctx = EVP_PKEY_CTX_new(private.as_ptr(), ptr::null_mut());
                    if pctx.is_null() {
                        return Err(CryptoError::Internal);
                    }
                    if EVP_PKEY_decapsulate_init(pctx, ptr::null()) != 1 {
                        EVP_PKEY_CTX_free(pctx);
                        return Err(CryptoError::Internal);
                    }

                    let mut ss_len = out_ss.len();
                    if EVP_PKEY_decapsulate(
                        pctx,
                        out_ss.as_mut_ptr(),
                        &mut ss_len,
                        ct.as_ptr(),
                        ct.len(),
                    ) != 1
                    {
                        EVP_PKEY_CTX_free(pctx);
                        return Err(CryptoError::Internal);
                    }
                    EVP_PKEY_CTX_free(pctx);
                    if ss_len != 32 {
                        return Err(CryptoError::Internal);
                    }
                    Ok(())
                }
            }
        }
    };
}

impl_mlkem!(Mlkem512, 800, 768, "ML-KEM-512");
impl_mlkem!(Mlkem768, 1184, 1088, "ML-KEM-768");
impl_mlkem!(Mlkem1024, 1568, 1568, "ML-KEM-1024");
