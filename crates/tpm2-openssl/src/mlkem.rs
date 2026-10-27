use openssl_sys::*;
use std::ffi::{CStr, CString};
use std::ptr;
use tpm2::crypto::backend::{MlkemKey, PrivateKey};
use tpm2::crypto::{CryptoError, Rng};

use crate::rng::OpensslRng;

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

/// ML-KEM private key with a `PUB_SIZE`-byte public key and `CT_SIZE`-byte
/// ciphertexts.
pub struct OpensslMlkemKey<const PUB_SIZE: usize, const CT_SIZE: usize>(EvpPkey);

impl<const PUB_SIZE: usize, const CT_SIZE: usize> OpensslMlkemKey<PUB_SIZE, CT_SIZE> {
    /// The OpenSSL algorithm name, which also checks the sizes are valid.
    const ALG: &CStr = match PUB_SIZE {
        800 => c"ML-KEM-512",
        1184 => c"ML-KEM-768",
        1568 => c"ML-KEM-1024",
        _ => panic!("unsupported ML-KEM parameter set"),
    };

    fn from_seed(seed: &[u8; 64]) -> Result<Option<Self>, CryptoError> {
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

            let alg = Self::ALG;
            let pctx = EVP_PKEY_CTX_new_from_name(ptr::null_mut(), alg.as_ptr(), ptr::null_mut());
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
            Ok(Some(Self(EvpPkey(pkey_ptr))))
        }
    }
}

impl<const PUB_SIZE: usize, const CT_SIZE: usize> PrivateKey<PUB_SIZE, 64, OpensslRng>
    for OpensslMlkemKey<PUB_SIZE, CT_SIZE>
{
    type PublicKey = EvpPkey;

    fn load_public(
        _: (),
        encoded: &[u8; PUB_SIZE],
    ) -> Result<Option<Self::PublicKey>, CryptoError> {
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
                PUB_SIZE,
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

            let alg = Self::ALG;
            let pctx = EVP_PKEY_CTX_new_from_name(ptr::null_mut(), alg.as_ptr(), ptr::null_mut());
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

    fn store_public(public: &Self::PublicKey, out: &mut [u8; PUB_SIZE]) -> Result<(), CryptoError> {
        unsafe {
            let mut size: usize = 0;
            if EVP_PKEY_get_octet_string_param(
                public.as_ptr(),
                CString::new("pub").unwrap().as_ptr(),
                std::ptr::null_mut(),
                0,
                &mut size,
            ) != 1
                || size != PUB_SIZE
            {
                return Err(CryptoError::Internal);
            }
            if EVP_PKEY_get_octet_string_param(
                public.as_ptr(),
                CString::new("pub").unwrap().as_ptr(),
                out.as_mut_ptr(),
                PUB_SIZE,
                &mut size,
            ) != 1
            {
                return Err(CryptoError::Internal);
            }
            Ok(())
        }
    }

    fn load(public: Self::PublicKey, seed: &[u8; 64]) -> Result<Option<Self>, CryptoError> {
        let Some(private) = Self::from_seed(seed)? else {
            return Ok(None);
        };
        // The seed must expand to `public`.
        let mut expected = [0u8; PUB_SIZE];
        let mut actual = [0u8; PUB_SIZE];
        Self::store_public(&public, &mut expected)?;
        Self::store_public(&private.0, &mut actual)?;
        if expected != actual {
            return Ok(None);
        }
        Ok(Some(private))
    }

    fn generate(rng: &mut OpensslRng, _: ()) -> Result<Self, CryptoError> {
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed)
            .map_err(|_| CryptoError::Internal)?;
        Self::from_seed(&seed).and_then(|opt| opt.ok_or(CryptoError::Internal))
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.0
    }

    fn store(&self, out: &mut [u8; 64]) -> Result<(), CryptoError> {
        unsafe {
            let mut size: usize = 0;
            if EVP_PKEY_get_octet_string_param(
                self.0.as_ptr(),
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
                self.0.as_ptr(),
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

impl<const PUB_SIZE: usize, const CT_SIZE: usize> MlkemKey<PUB_SIZE, CT_SIZE, OpensslRng>
    for OpensslMlkemKey<PUB_SIZE, CT_SIZE>
{
    fn encapsulate(
        public: &Self::PublicKey,
        _rng: &mut OpensslRng,
        out_ct: &mut [u8; CT_SIZE],
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
            if ct_len != CT_SIZE || ss_len != 32 {
                return Err(CryptoError::Internal);
            }
            Ok(())
        }
    }

    fn decapsulate(&self, ct: &[u8; CT_SIZE], out_ss: &mut [u8; 32]) -> Result<(), CryptoError> {
        unsafe {
            let pctx = EVP_PKEY_CTX_new(self.0.as_ptr(), ptr::null_mut());
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

impl tpm2::crypto::backend::Mlkem for super::OpensslBackend {
    type Mlkem512 = OpensslMlkemKey<800, 768>;
    type Mlkem768 = OpensslMlkemKey<1184, 1088>;
    type Mlkem1024 = OpensslMlkemKey<1568, 1568>;
}
