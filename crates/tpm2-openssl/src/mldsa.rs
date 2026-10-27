use openssl_sys::*;

use crate::sys::{EVP_MD_CTX_get_pkey_ctx, OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING};
use std::ffi::{CStr, CString};
use std::ptr;
use tpm2::TpmtHa;
use tpm2::crypto::backend::{MldsaKey, PrivateKey};
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

/// ML-DSA private key with a `PUB_SIZE`-byte public key and `SIG_SIZE`-byte
/// signatures.
pub struct OpensslMldsaKey<const PUB_SIZE: usize, const SIG_SIZE: usize>(EvpPkey);

impl<const PUB_SIZE: usize, const SIG_SIZE: usize> OpensslMldsaKey<PUB_SIZE, SIG_SIZE> {
    /// The OpenSSL algorithm name, which also checks the sizes are valid.
    const ALG: &CStr = match PUB_SIZE {
        1312 => c"ML-DSA-44",
        1952 => c"ML-DSA-65",
        2592 => c"ML-DSA-87",
        _ => panic!("unsupported ML-DSA parameter set"),
    };

    fn from_seed(seed: &[u8; 32]) -> Result<Option<Self>, CryptoError> {
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
                32,
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

impl<const PUB_SIZE: usize, const SIG_SIZE: usize> PrivateKey<PUB_SIZE, 32, OpensslRng>
    for OpensslMldsaKey<PUB_SIZE, SIG_SIZE>
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

    fn load(public: Self::PublicKey, seed: &[u8; 32]) -> Result<Option<Self>, CryptoError> {
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
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed)
            .map_err(|_| CryptoError::Internal)?;
        Self::from_seed(&seed).and_then(|opt| opt.ok_or(CryptoError::Internal))
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.0
    }

    fn store(&self, out: &mut [u8; 32]) -> Result<(), CryptoError> {
        unsafe {
            let mut size: usize = 0;
            if EVP_PKEY_get_octet_string_param(
                self.0.as_ptr(),
                CString::new("seed").unwrap().as_ptr(),
                std::ptr::null_mut(),
                0,
                &mut size,
            ) != 1
                || size != 32
            {
                return Err(CryptoError::Internal);
            }
            if EVP_PKEY_get_octet_string_param(
                self.0.as_ptr(),
                CString::new("seed").unwrap().as_ptr(),
                out.as_mut_ptr(),
                32,
                &mut size,
            ) != 1
            {
                return Err(CryptoError::Internal);
            }
            Ok(())
        }
    }
}

impl<const PUB_SIZE: usize, const SIG_SIZE: usize> MldsaKey<PUB_SIZE, SIG_SIZE, OpensslRng>
    for OpensslMldsaKey<PUB_SIZE, SIG_SIZE>
{
    fn sign_message(
        &self,
        _rng: &mut OpensslRng,
        context: &[u8],
        msg: &[&[u8]],
        out_sig: &mut [u8; SIG_SIZE],
    ) -> Result<(), CryptoError> {
        if context.len() > 255 {
            return Err(CryptoError::Internal);
        }
        unsafe {
            let mctx = EVP_MD_CTX_new();
            if mctx.is_null() {
                return Err(CryptoError::Internal);
            }

            let key_str = std::ffi::CString::new("context-string").unwrap();
            let mut params = [
                OSSL_PARAM {
                    key: key_str.as_ptr(),
                    data_type: OSSL_PARAM_OCTET_STRING,
                    data: context.as_ptr() as *mut core::ffi::c_void,
                    data_size: context.len(),
                    return_size: 0,
                },
                OSSL_PARAM {
                    key: std::ptr::null(),
                    data_type: 0,
                    data: std::ptr::null_mut(),
                    data_size: 0,
                    return_size: 0,
                },
            ];

            if EVP_DigestSignInit(
                mctx,
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                self.0.as_ptr(),
            ) != 1
            {
                EVP_MD_CTX_free(mctx);
                return Err(CryptoError::Internal);
            }

            let pctx = EVP_MD_CTX_get_pkey_ctx(mctx);
            if pctx.is_null() || EVP_PKEY_CTX_set_params(pctx, params.as_mut_ptr()) != 1 {
                EVP_MD_CTX_free(mctx);
                return Err(CryptoError::Internal);
            }

            let mut full_msg = Vec::new();
            for m in msg {
                full_msg.extend_from_slice(m);
            }
            let mut sig_len = out_sig.len();
            if EVP_DigestSign(
                mctx,
                out_sig.as_mut_ptr(),
                &mut sig_len,
                full_msg.as_ptr(),
                full_msg.len(),
            ) != 1
            {
                EVP_MD_CTX_free(mctx);
                return Err(CryptoError::Internal);
            }
            EVP_MD_CTX_free(mctx);
            if sig_len != SIG_SIZE {
                return Err(CryptoError::Internal);
            }
            Ok(())
        }
    }

    fn verify_message(
        public: &Self::PublicKey,
        context: &[u8],
        msg: &[&[u8]],
        sig: &[u8; SIG_SIZE],
    ) -> Result<bool, CryptoError> {
        if context.len() > 255 {
            return Err(CryptoError::Internal);
        }
        unsafe {
            let mctx = EVP_MD_CTX_new();
            if mctx.is_null() {
                return Err(CryptoError::Internal);
            }

            let key_str = std::ffi::CString::new("context-string").unwrap();
            let mut params = [
                OSSL_PARAM {
                    key: key_str.as_ptr(),
                    data_type: OSSL_PARAM_OCTET_STRING,
                    data: context.as_ptr() as *mut core::ffi::c_void,
                    data_size: context.len(),
                    return_size: 0,
                },
                OSSL_PARAM {
                    key: std::ptr::null(),
                    data_type: 0,
                    data: std::ptr::null_mut(),
                    data_size: 0,
                    return_size: 0,
                },
            ];

            if EVP_DigestVerifyInit(
                mctx,
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                public.as_ptr(),
            ) != 1
            {
                EVP_MD_CTX_free(mctx);
                return Err(CryptoError::Internal);
            }

            let pctx = EVP_MD_CTX_get_pkey_ctx(mctx);
            if pctx.is_null() || EVP_PKEY_CTX_set_params(pctx, params.as_mut_ptr()) != 1 {
                EVP_MD_CTX_free(mctx);
                return Err(CryptoError::Internal);
            }

            let mut full_msg = Vec::new();
            for m in msg {
                full_msg.extend_from_slice(m);
            }
            let res = EVP_DigestVerify(
                mctx,
                sig.as_ptr(),
                sig.len(),
                full_msg.as_ptr(),
                full_msg.len(),
            );
            EVP_MD_CTX_free(mctx);

            match res {
                1 => Ok(true),
                0 => Ok(false),
                _ => Err(CryptoError::Internal),
            }
        }
    }

    fn sign_mu(
        &self,
        _rng: &mut OpensslRng,
        mu: &[u8; 64],
        out_sig: &mut [u8; SIG_SIZE],
    ) -> Result<(), CryptoError> {
        unsafe {
            let mctx = EVP_MD_CTX_new();
            if mctx.is_null() {
                return Err(CryptoError::Internal);
            }

            let key_str = std::ffi::CString::new("mu").unwrap();
            let one: core::ffi::c_int = 1;
            let mut params = [
                OSSL_PARAM {
                    key: key_str.as_ptr(),
                    data_type: OSSL_PARAM_INTEGER,
                    data: &one as *const _ as *mut core::ffi::c_void,
                    data_size: std::mem::size_of::<core::ffi::c_int>(),
                    return_size: 0,
                },
                OSSL_PARAM {
                    key: std::ptr::null(),
                    data_type: 0,
                    data: std::ptr::null_mut(),
                    data_size: 0,
                    return_size: 0,
                },
            ];

            if EVP_DigestSignInit(
                mctx,
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                self.0.as_ptr(),
            ) != 1
            {
                EVP_MD_CTX_free(mctx);
                return Err(CryptoError::Internal);
            }

            let pctx = EVP_MD_CTX_get_pkey_ctx(mctx);
            if pctx.is_null() || EVP_PKEY_CTX_set_params(pctx, params.as_mut_ptr()) != 1 {
                EVP_MD_CTX_free(mctx);
                return Err(CryptoError::Internal);
            }

            let mut sig_len = out_sig.len();
            if EVP_DigestSign(
                mctx,
                out_sig.as_mut_ptr(),
                &mut sig_len,
                mu.as_ptr(),
                mu.len(),
            ) != 1
            {
                EVP_MD_CTX_free(mctx);
                return Err(CryptoError::Internal);
            }
            EVP_MD_CTX_free(mctx);
            if sig_len != SIG_SIZE {
                return Err(CryptoError::Internal);
            }
            Ok(())
        }
    }

    fn verify_mu(
        public: &Self::PublicKey,
        mu: &[u8; 64],
        sig: &[u8; SIG_SIZE],
    ) -> Result<bool, CryptoError> {
        unsafe {
            let mctx = EVP_MD_CTX_new();
            if mctx.is_null() {
                return Err(CryptoError::Internal);
            }

            let key_str = std::ffi::CString::new("mu").unwrap();
            let one: core::ffi::c_int = 1;
            let mut params = [
                OSSL_PARAM {
                    key: key_str.as_ptr(),
                    data_type: OSSL_PARAM_INTEGER,
                    data: &one as *const _ as *mut core::ffi::c_void,
                    data_size: std::mem::size_of::<core::ffi::c_int>(),
                    return_size: 0,
                },
                OSSL_PARAM {
                    key: std::ptr::null(),
                    data_type: 0,
                    data: std::ptr::null_mut(),
                    data_size: 0,
                    return_size: 0,
                },
            ];

            if EVP_DigestVerifyInit(
                mctx,
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                public.as_ptr(),
            ) != 1
            {
                EVP_MD_CTX_free(mctx);
                return Err(CryptoError::Internal);
            }

            let pctx = EVP_MD_CTX_get_pkey_ctx(mctx);
            if pctx.is_null() || EVP_PKEY_CTX_set_params(pctx, params.as_mut_ptr()) != 1 {
                EVP_MD_CTX_free(mctx);
                return Err(CryptoError::Internal);
            }

            let res = EVP_DigestVerify(mctx, sig.as_ptr(), sig.len(), mu.as_ptr(), mu.len());
            EVP_MD_CTX_free(mctx);

            match res {
                1 => Ok(true),
                0 => Ok(false),
                _ => Err(CryptoError::Internal),
            }
        }
    }

    fn sign_prehash(
        &self,
        _rng: &mut OpensslRng,
        context: &[u8],
        digest: TpmtHa<'_>,
        out_sig: &mut [u8; SIG_SIZE],
    ) -> Result<(), CryptoError> {
        if context.len() > 255 {
            return Err(CryptoError::Internal);
        }
        let ctx_len = context.len() as u8;

        #[allow(unreachable_patterns)]
        let der_oid: &[u8] = match digest.hash_alg() {
            _ if false => unreachable!(),
            tpm2::TpmiAlgHash::Sha1 => &[0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a],
            tpm2::TpmiAlgHash::Sha256 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            ],
            tpm2::TpmiAlgHash::Sha384 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
            ],
            tpm2::TpmiAlgHash::Sha512 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
            ],
            tpm2::TpmiAlgHash::Sm3_256 => {
                &[0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x11]
            }
            tpm2::TpmiAlgHash::Sha3_256 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
            ],
            tpm2::TpmiAlgHash::Sha3_384 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09,
            ],
            tpm2::TpmiAlgHash::Sha3_512 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a,
            ],
            _ => return Err(CryptoError::Unsupported),
        };

        let d = digest.digest();

        let mut m_prime = Vec::new();
        m_prime.push(0x01);
        m_prime.push(ctx_len);
        m_prime.extend_from_slice(context);
        m_prime.extend_from_slice(der_oid);
        m_prime.extend_from_slice(d);

        unsafe {
            let mctx = EVP_MD_CTX_new();
            if mctx.is_null() {
                return Err(CryptoError::Internal);
            }

            let key_str = std::ffi::CString::new("message-encoding").unwrap();
            let zero: core::ffi::c_int = 0;
            let mut params = [
                OSSL_PARAM {
                    key: key_str.as_ptr(),
                    data_type: OSSL_PARAM_INTEGER,
                    data: &zero as *const _ as *mut core::ffi::c_void,
                    data_size: std::mem::size_of::<core::ffi::c_int>(),
                    return_size: 0,
                },
                OSSL_PARAM {
                    key: std::ptr::null(),
                    data_type: 0,
                    data: std::ptr::null_mut(),
                    data_size: 0,
                    return_size: 0,
                },
            ];

            if EVP_DigestSignInit(
                mctx,
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                self.0.as_ptr(),
            ) != 1
            {
                EVP_MD_CTX_free(mctx);
                return Err(CryptoError::Internal);
            }

            let pctx = EVP_MD_CTX_get_pkey_ctx(mctx);
            if pctx.is_null() || EVP_PKEY_CTX_set_params(pctx, params.as_mut_ptr()) != 1 {
                EVP_MD_CTX_free(mctx);
                return Err(CryptoError::Internal);
            }

            let mut sig_len = out_sig.len();
            if EVP_DigestSign(
                mctx,
                out_sig.as_mut_ptr(),
                &mut sig_len,
                m_prime.as_ptr(),
                m_prime.len(),
            ) != 1
            {
                EVP_MD_CTX_free(mctx);
                return Err(CryptoError::Internal);
            }
            EVP_MD_CTX_free(mctx);
            if sig_len != SIG_SIZE {
                return Err(CryptoError::Internal);
            }
            Ok(())
        }
    }

    fn verify_prehash(
        public: &Self::PublicKey,
        context: &[u8],
        digest: TpmtHa<'_>,
        sig: &[u8; SIG_SIZE],
    ) -> Result<bool, CryptoError> {
        if context.len() > 255 {
            return Err(CryptoError::Internal);
        }
        let ctx_len = context.len() as u8;

        #[allow(unreachable_patterns)]
        let der_oid: &[u8] = match digest.hash_alg() {
            _ if false => unreachable!(),
            tpm2::TpmiAlgHash::Sha1 => &[0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a],
            tpm2::TpmiAlgHash::Sha256 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            ],
            tpm2::TpmiAlgHash::Sha384 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
            ],
            tpm2::TpmiAlgHash::Sha512 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
            ],
            tpm2::TpmiAlgHash::Sm3_256 => {
                &[0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x11]
            }
            tpm2::TpmiAlgHash::Sha3_256 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
            ],
            tpm2::TpmiAlgHash::Sha3_384 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09,
            ],
            tpm2::TpmiAlgHash::Sha3_512 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a,
            ],
            _ => return Err(CryptoError::Unsupported),
        };

        let d = digest.digest();

        let mut m_prime = Vec::new();
        m_prime.push(0x01);
        m_prime.push(ctx_len);
        m_prime.extend_from_slice(context);
        m_prime.extend_from_slice(der_oid);
        m_prime.extend_from_slice(d);

        unsafe {
            let mctx = EVP_MD_CTX_new();
            if mctx.is_null() {
                return Err(CryptoError::Internal);
            }

            let key_str = std::ffi::CString::new("message-encoding").unwrap();
            let zero: core::ffi::c_int = 0;
            let mut params = [
                OSSL_PARAM {
                    key: key_str.as_ptr(),
                    data_type: OSSL_PARAM_INTEGER,
                    data: &zero as *const _ as *mut core::ffi::c_void,
                    data_size: std::mem::size_of::<core::ffi::c_int>(),
                    return_size: 0,
                },
                OSSL_PARAM {
                    key: std::ptr::null(),
                    data_type: 0,
                    data: std::ptr::null_mut(),
                    data_size: 0,
                    return_size: 0,
                },
            ];

            if EVP_DigestVerifyInit(
                mctx,
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                public.as_ptr(),
            ) != 1
            {
                EVP_MD_CTX_free(mctx);
                return Err(CryptoError::Internal);
            }

            let pctx = EVP_MD_CTX_get_pkey_ctx(mctx);
            if pctx.is_null() || EVP_PKEY_CTX_set_params(pctx, params.as_mut_ptr()) != 1 {
                EVP_MD_CTX_free(mctx);
                return Err(CryptoError::Internal);
            }

            let res = EVP_DigestVerify(
                mctx,
                sig.as_ptr(),
                sig.len(),
                m_prime.as_ptr(),
                m_prime.len(),
            );
            EVP_MD_CTX_free(mctx);

            match res {
                1 => Ok(true),
                0 => Ok(false),
                _ => Err(CryptoError::Internal),
            }
        }
    }
}

impl tpm2::crypto::backend::Mldsa for super::OpensslBackend {
    type Mldsa44 = OpensslMldsaKey<1312, 2420>;
    type Mldsa65 = OpensslMldsaKey<1952, 3309>;
    type Mldsa87 = OpensslMldsaKey<2592, 4627>;
}
