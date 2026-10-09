#![allow(dead_code, unused_imports)]

extern crate alloc;
extern crate std;

use alloc::vec::Vec;
use tpm2::Alg;
use tpm2::crypto::Rng;
use tpm2::crypto::{Asymmetric, AsymmetricSign, Cmac, Symmetric};
use tpm2::crypto::{CryptoError, CryptoProvider};
use tpm2::{Handle, TpmSe};
use tpm2::{Tpm2bNonce, TpmiAlgHash};
use tpm2_impl::handler::SessionState;
use tpm2_impl::storage::{NvStorage, StorageError};
use tpm2_impl::timer::TpmTimer;

#[cfg(not(any(
    feature = "dev_crypto_rust",
    feature = "dev_crypto_crux",
    feature = "dev_crypto_bssl"
)))]
compile_error!(
    "At least one dev crypto backend feature must be enabled: 'dev_crypto_rust', 'dev_crypto_crux', or 'dev_crypto_bssl'."
);

#[cfg(all(feature = "dev_crypto_rust", feature = "dev_crypto_crux"))]
compile_error!("Features 'dev_crypto_rust' and 'dev_crypto_crux' are mutually exclusive.");

#[cfg(all(feature = "dev_crypto_rust", feature = "dev_crypto_bssl"))]
compile_error!("Features 'dev_crypto_rust' and 'dev_crypto_bssl' are mutually exclusive.");

#[cfg(all(feature = "dev_crypto_crux", feature = "dev_crypto_bssl"))]
compile_error!("Features 'dev_crypto_crux' and 'dev_crypto_bssl' are mutually exclusive.");

#[cfg(feature = "dev_crypto_rust")]
pub use tpm2_crypto_rust::RustCryptoProvider as TestCryptoProvider;

#[cfg(feature = "dev_crypto_crux")]
pub use tpm2_crypto_crux::CruxCryptoProvider as TestCryptoProvider;

#[cfg(feature = "dev_crypto_bssl")]
pub use tpm2_crypto_bssl::BsslCryptoProvider as TestCryptoProvider;

#[allow(clippy::too_many_arguments)]
pub fn make_test_session_state(
    session_handle: u32,
    session_type: TpmSe,
    auth_hash: TpmiAlgHash,
    nonce_tpm: Tpm2bNonce,
    nonce_caller: Tpm2bNonce,
    session_key_slice: &[u8],
    symmetric: Option<tpm2::TpmtSymDef>,
    bind_entity: Handle,
) -> SessionState {
    let mut session_key = [0u8; 128];
    session_key[..session_key_slice.len()].copy_from_slice(session_key_slice);
    SessionState {
        session_handle,
        session_type,
        auth_hash,
        nonce_tpm: nonce_tpm.into(),
        nonce_caller: nonce_caller.into(),
        session_key,
        session_key_len: session_key_slice.len(),
        symmetric,
        bind_entity,
        bound_entity: Default::default(),
        audit_digest: None,
        audit_digest_len: 0,
        audit_cp_hash: [0u8; 64],
        audit_cp_hash_len: 0,
        policy_hash: [0u8; 64],
        policy_hash_len: 0,
        is_cp_hash_defined: false,
        is_name_hash_defined: false,
        is_template_hash_defined: false,
        policy_digest: [0u8; 64],
        policy_digest_len: 0,
        command_code: 0,
        start_time: 0,
        timeout: 0,
        epoch: 0,
        is_auth_value_needed: false,
        is_password_needed: false,
        pcr_counter: None,
        check_nv_written: false,
        nv_written_state: false,
        command_locality: 0,
        include_auth: false,
        is_da_bound: false,
        is_lockout_bound: false,
    }
}

pub struct FakeRng {
    counter: std::sync::Mutex<u8>,
}

impl Default for FakeRng {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeRng {
    pub fn new() -> Self {
        Self {
            counter: std::sync::Mutex::new(1),
        }
    }
}

impl Rng for FakeRng {
    fn get_random(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        let mut counter = self.counter.lock().unwrap();
        for b in dest {
            *b = *counter;
            *counter = counter.wrapping_add(1);
        }
        Ok(())
    }
}

pub struct FakeCrypto;

pub struct FakeHashCtx(pub Vec<u8>);

impl tpm2::crypto::Update<CryptoError> for FakeHashCtx {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.extend_from_slice(data);
        Ok(())
    }
}

impl<const N: usize> tpm2::crypto::Finalize<N, CryptoError> for FakeHashCtx {
    fn finalize(self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        *out = [0u8; N];
        if !self.0.is_empty() {
            for (i, &b) in self.0.iter().enumerate() {
                out[i % N] ^= b;
            }
        }
        Ok(())
    }
}

pub struct FakeHmacCtx(pub Vec<u8>);

impl tpm2::crypto::Update<CryptoError> for FakeHmacCtx {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.extend_from_slice(data);
        Ok(())
    }
}

impl<const N: usize> tpm2::crypto::Finalize<N, CryptoError> for FakeHmacCtx {
    fn finalize(self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        *out = [0u8; N];
        if !self.0.is_empty() {
            for (i, &b) in self.0.iter().enumerate() {
                out[i % N] ^= b;
            }
        }
        out[1] ^= self.0.len() as u8;
        Ok(())
    }
}

pub struct FakeSymmetricCtx {
    pub key: Vec<u8>,
    pub iv: [u8; 16],
}

impl tpm2::crypto::UpdateInPlace<CryptoError> for FakeSymmetricCtx {
    fn update(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        if self.key.is_empty() {
            return Ok(());
        }
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= self.key[i % self.key.len()] ^ self.iv[i % 16];
        }
        Ok(())
    }
}

impl tpm2::crypto::Finalize<16, CryptoError> for FakeSymmetricCtx {
    fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
        *out = self.iv;
        Ok(())
    }
}

#[macro_export]
macro_rules! impl_fake_hash {
    ($t:ty) => {
        impl tpm2::crypto::Base for $t {
            type Error = CryptoError;
            fn unimplemented(&self, _: tpm2::Alg) -> Self::Error {
                CryptoError::UnsupportedAlgorithm
            }
        }
        impl tpm2::crypto::Hash for $t {
            type Sha1Ctx = common::FakeHashCtx;
            type Sha256Ctx = common::FakeHashCtx;
            type Sha384Ctx = common::FakeHashCtx;
            type Sha512Ctx = common::FakeHashCtx;
            type Sm3_256Ctx = common::FakeHashCtx;
            type Sha3_256Ctx = common::FakeHashCtx;
            type Sha3_384Ctx = common::FakeHashCtx;
            type Sha3_512Ctx = common::FakeHashCtx;

            fn sha1(&self) -> Result<Self::Sha1Ctx, Self::Error> {
                Ok(common::FakeHashCtx(alloc::vec::Vec::new()))
            }
            fn sha256(&self) -> Result<Self::Sha256Ctx, Self::Error> {
                Ok(common::FakeHashCtx(alloc::vec::Vec::new()))
            }
            fn sha384(&self) -> Result<Self::Sha384Ctx, Self::Error> {
                Ok(common::FakeHashCtx(alloc::vec::Vec::new()))
            }
            fn sha512(&self) -> Result<Self::Sha512Ctx, Self::Error> {
                Ok(common::FakeHashCtx(alloc::vec::Vec::new()))
            }
            fn sm3_256(&self) -> Result<Self::Sm3_256Ctx, Self::Error> {
                Ok(common::FakeHashCtx(alloc::vec::Vec::new()))
            }
            fn sha3_256(&self) -> Result<Self::Sha3_256Ctx, Self::Error> {
                Ok(common::FakeHashCtx(alloc::vec::Vec::new()))
            }
            fn sha3_384(&self) -> Result<Self::Sha3_384Ctx, Self::Error> {
                Ok(common::FakeHashCtx(alloc::vec::Vec::new()))
            }
            fn sha3_512(&self) -> Result<Self::Sha3_512Ctx, Self::Error> {
                Ok(common::FakeHashCtx(alloc::vec::Vec::new()))
            }
        }
        impl tpm2::crypto::Hmac for $t {
            type Sha1Ctx = common::FakeHmacCtx;
            type Sha256Ctx = common::FakeHmacCtx;
            type Sha384Ctx = common::FakeHmacCtx;
            type Sha512Ctx = common::FakeHmacCtx;
            type Sm3_256Ctx = common::FakeHmacCtx;
            type Sha3_256Ctx = common::FakeHmacCtx;
            type Sha3_384Ctx = common::FakeHmacCtx;
            type Sha3_512Ctx = common::FakeHmacCtx;

            fn sha1(&self, key: &[u8]) -> Result<Self::Sha1Ctx, Self::Error> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn sha256(&self, key: &[u8]) -> Result<Self::Sha256Ctx, Self::Error> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn sha384(&self, key: &[u8]) -> Result<Self::Sha384Ctx, Self::Error> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn sha512(&self, key: &[u8]) -> Result<Self::Sha512Ctx, Self::Error> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn sm3_256(&self, key: &[u8]) -> Result<Self::Sm3_256Ctx, Self::Error> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn sha3_256(&self, key: &[u8]) -> Result<Self::Sha3_256Ctx, Self::Error> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn sha3_384(&self, key: &[u8]) -> Result<Self::Sha3_384Ctx, Self::Error> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn sha3_512(&self, key: &[u8]) -> Result<Self::Sha3_512Ctx, Self::Error> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
        }
        impl tpm2::crypto::Cmac for $t {
            fn invalid_key(&self) -> Self::Error {
                CryptoError::InvalidData
            }
            type Aes128Ctx = common::FakeHmacCtx;
            type Aes192Ctx = common::FakeHmacCtx;
            type Aes256Ctx = common::FakeHmacCtx;
            type Sm4_128Ctx = common::FakeHmacCtx;
            type Camellia128Ctx = common::FakeHmacCtx;
            type Camellia192Ctx = common::FakeHmacCtx;
            type Camellia256Ctx = common::FakeHmacCtx;

            fn aes128(&self, key: &[u8; 16]) -> Result<Self::Aes128Ctx, Self::Error> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn aes192(&self, key: &[u8; 24]) -> Result<Self::Aes192Ctx, Self::Error> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn aes256(&self, key: &[u8; 32]) -> Result<Self::Aes256Ctx, Self::Error> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn sm4_128(&self, key: &[u8; 16]) -> Result<Self::Sm4_128Ctx, Self::Error> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn camellia128(&self, key: &[u8; 16]) -> Result<Self::Camellia128Ctx, Self::Error> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn camellia192(&self, key: &[u8; 24]) -> Result<Self::Camellia192Ctx, Self::Error> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn camellia256(&self, key: &[u8; 32]) -> Result<Self::Camellia256Ctx, Self::Error> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
        }
        impl tpm2::crypto::Ecc for $t {
            type NistP192Ctx = !;
            type NistP224Ctx = !;
            type NistP256Ctx = !;
            type NistP384Ctx = !;
            type NistP521Ctx = !;
            type BnP256Ctx = !;
            type BnP638Ctx = !;
            type Sm2P256Ctx = !;
            type BpP256R1Ctx = !;
            type BpP384R1Ctx = !;
            type BpP512R1Ctx = !;
            type Curve25519Ctx = !;
            type Curve448Ctx = !;

            fn validate_point(
                &self,
                _curve: tpm2::TpmEccCurve,
                _public_key: &[u8],
            ) -> Result<(), tpm2::crypto::CryptoError> {
                Ok(())
            }
            fn point_multiply_generator(
                &self,
                _curve: tpm2::TpmEccCurve,
                _scalar: &[u8],
                _public_key_out: &mut [u8],
            ) -> Result<(), tpm2::crypto::CryptoError> {
                Ok(())
            }
            fn point_multiply(
                &self,
                _curve: tpm2::TpmEccCurve,
                _scalar: &[u8],
                _public_point: &[u8],
                _derived_point_out: &mut [u8],
            ) -> Result<(), tpm2::crypto::CryptoError> {
                Ok(())
            }
            fn ecdaa_sign(
                &self,
                _curve: tpm2::TpmEccCurve,
                _commit_r: &[u8],
                _commit_x: &[u8],
                _commit_p1: &[u8],
                _private_key_d: &[u8],
                _digest: &[u8],
                _nonce_k_out: &mut [u8],
                _s_out: &mut [u8],
            ) -> Result<(), tpm2::crypto::CryptoError> {
                Ok(())
            }
        }
        impl tpm2::crypto::Symmetric for $t {
            fn invalid_key(&self) -> Self::Error {
                CryptoError::InvalidData
            }
            fn invalid_iv(&self) -> Self::Error {
                CryptoError::InvalidData
            }
            type Aes128EncryptCtx = common::FakeSymmetricCtx;
            type Aes128DecryptCtx = common::FakeSymmetricCtx;
            type Aes192EncryptCtx = common::FakeSymmetricCtx;
            type Aes192DecryptCtx = common::FakeSymmetricCtx;
            type Aes256EncryptCtx = common::FakeSymmetricCtx;
            type Aes256DecryptCtx = common::FakeSymmetricCtx;
            type Sm4_128EncryptCtx = common::FakeSymmetricCtx;
            type Sm4_128DecryptCtx = common::FakeSymmetricCtx;
            type Camellia128EncryptCtx = common::FakeSymmetricCtx;
            type Camellia128DecryptCtx = common::FakeSymmetricCtx;
            type Camellia192EncryptCtx = common::FakeSymmetricCtx;
            type Camellia192DecryptCtx = common::FakeSymmetricCtx;
            type Camellia256EncryptCtx = common::FakeSymmetricCtx;
            type Camellia256DecryptCtx = common::FakeSymmetricCtx;

            fn aes128_encrypt(
                &self,
                _mode: tpm2::TpmiAlgSymMode,
                key: &[u8; 16],
                iv: &[u8; 16],
            ) -> Result<Self::Aes128EncryptCtx, Self::Error> {
                Ok(common::FakeSymmetricCtx {
                    key: key.to_vec(),
                    iv: *iv,
                })
            }
            fn aes128_decrypt(
                &self,
                _mode: tpm2::TpmiAlgSymMode,
                key: &[u8; 16],
                iv: &[u8; 16],
            ) -> Result<Self::Aes128DecryptCtx, Self::Error> {
                Ok(common::FakeSymmetricCtx {
                    key: key.to_vec(),
                    iv: *iv,
                })
            }
            fn aes192_encrypt(
                &self,
                _mode: tpm2::TpmiAlgSymMode,
                key: &[u8; 24],
                iv: &[u8; 16],
            ) -> Result<Self::Aes192EncryptCtx, Self::Error> {
                Ok(common::FakeSymmetricCtx {
                    key: key.to_vec(),
                    iv: *iv,
                })
            }
            fn aes192_decrypt(
                &self,
                _mode: tpm2::TpmiAlgSymMode,
                key: &[u8; 24],
                iv: &[u8; 16],
            ) -> Result<Self::Aes192DecryptCtx, Self::Error> {
                Ok(common::FakeSymmetricCtx {
                    key: key.to_vec(),
                    iv: *iv,
                })
            }
            fn aes256_encrypt(
                &self,
                _mode: tpm2::TpmiAlgSymMode,
                key: &[u8; 32],
                iv: &[u8; 16],
            ) -> Result<Self::Aes256EncryptCtx, Self::Error> {
                Ok(common::FakeSymmetricCtx {
                    key: key.to_vec(),
                    iv: *iv,
                })
            }
            fn aes256_decrypt(
                &self,
                _mode: tpm2::TpmiAlgSymMode,
                key: &[u8; 32],
                iv: &[u8; 16],
            ) -> Result<Self::Aes256DecryptCtx, Self::Error> {
                Ok(common::FakeSymmetricCtx {
                    key: key.to_vec(),
                    iv: *iv,
                })
            }
        }
    };
}

#[macro_export]
macro_rules! impl_delegate_hash {
    ($t:ty, $field:ident) => {
        impl tpm2::crypto::Base for $t {
            type Error = CryptoError;
            fn unimplemented(&self, _: tpm2::Alg) -> Self::Error {
                CryptoError::UnsupportedAlgorithm
            }
        }
        impl tpm2::crypto::Hash for $t {
            type Sha1Ctx = <$crate::common::TestCryptoProvider as tpm2::crypto::Hash>::Sha1Ctx;
            type Sha256Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hash>::Sha256Ctx;
            type Sha384Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hash>::Sha384Ctx;
            type Sha512Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hash>::Sha512Ctx;
            type Sm3_256Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hash>::Sm3_256Ctx;
            type Sha3_256Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hash>::Sha3_256Ctx;
            type Sha3_384Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hash>::Sha3_384Ctx;
            type Sha3_512Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hash>::Sha3_512Ctx;

            fn sha1(&self) -> Result<Self::Sha1Ctx, Self::Error> {
                tpm2::crypto::Hash::sha1(&self.$field)
            }
            fn sha256(&self) -> Result<Self::Sha256Ctx, Self::Error> {
                tpm2::crypto::Hash::sha256(&self.$field)
            }
            fn sha384(&self) -> Result<Self::Sha384Ctx, Self::Error> {
                tpm2::crypto::Hash::sha384(&self.$field)
            }
            fn sha512(&self) -> Result<Self::Sha512Ctx, Self::Error> {
                tpm2::crypto::Hash::sha512(&self.$field)
            }
            fn sm3_256(&self) -> Result<Self::Sm3_256Ctx, Self::Error> {
                tpm2::crypto::Hash::sm3_256(&self.$field)
            }
            fn sha3_256(&self) -> Result<Self::Sha3_256Ctx, Self::Error> {
                tpm2::crypto::Hash::sha3_256(&self.$field)
            }
            fn sha3_384(&self) -> Result<Self::Sha3_384Ctx, Self::Error> {
                tpm2::crypto::Hash::sha3_384(&self.$field)
            }
            fn sha3_512(&self) -> Result<Self::Sha3_512Ctx, Self::Error> {
                tpm2::crypto::Hash::sha3_512(&self.$field)
            }
        }
        impl tpm2::crypto::Hmac for $t {
            type Sha1Ctx = <$crate::common::TestCryptoProvider as tpm2::crypto::Hmac>::Sha1Ctx;
            type Sha256Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hmac>::Sha256Ctx;
            type Sha384Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hmac>::Sha384Ctx;
            type Sha512Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hmac>::Sha512Ctx;
            type Sm3_256Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hmac>::Sm3_256Ctx;
            type Sha3_256Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hmac>::Sha3_256Ctx;
            type Sha3_384Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hmac>::Sha3_384Ctx;
            type Sha3_512Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hmac>::Sha3_512Ctx;

            fn sha1(&self, key: &[u8]) -> Result<Self::Sha1Ctx, Self::Error> {
                tpm2::crypto::Hmac::sha1(&self.$field, key)
            }
            fn sha256(&self, key: &[u8]) -> Result<Self::Sha256Ctx, Self::Error> {
                tpm2::crypto::Hmac::sha256(&self.$field, key)
            }
            fn sha384(&self, key: &[u8]) -> Result<Self::Sha384Ctx, Self::Error> {
                tpm2::crypto::Hmac::sha384(&self.$field, key)
            }
            fn sha512(&self, key: &[u8]) -> Result<Self::Sha512Ctx, Self::Error> {
                tpm2::crypto::Hmac::sha512(&self.$field, key)
            }
            fn sm3_256(&self, key: &[u8]) -> Result<Self::Sm3_256Ctx, Self::Error> {
                tpm2::crypto::Hmac::sm3_256(&self.$field, key)
            }
            fn sha3_256(&self, key: &[u8]) -> Result<Self::Sha3_256Ctx, Self::Error> {
                tpm2::crypto::Hmac::sha3_256(&self.$field, key)
            }
            fn sha3_384(&self, key: &[u8]) -> Result<Self::Sha3_384Ctx, Self::Error> {
                tpm2::crypto::Hmac::sha3_384(&self.$field, key)
            }
            fn sha3_512(&self, key: &[u8]) -> Result<Self::Sha3_512Ctx, Self::Error> {
                tpm2::crypto::Hmac::sha3_512(&self.$field, key)
            }
        }
        impl tpm2::crypto::Cmac for $t {
            fn invalid_key(&self) -> Self::Error {
                CryptoError::InvalidData
            }
            type Aes128Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Cmac>::Aes128Ctx;
            type Aes192Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Cmac>::Aes192Ctx;
            type Aes256Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Cmac>::Aes256Ctx;
            type Sm4_128Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Cmac>::Sm4_128Ctx;
            type Camellia128Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Cmac>::Camellia128Ctx;
            type Camellia192Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Cmac>::Camellia192Ctx;
            type Camellia256Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Cmac>::Camellia256Ctx;

            fn aes128(&self, key: &[u8; 16]) -> Result<Self::Aes128Ctx, Self::Error> {
                tpm2::crypto::Cmac::aes128(&self.$field, key)
            }
            fn aes192(&self, key: &[u8; 24]) -> Result<Self::Aes192Ctx, Self::Error> {
                tpm2::crypto::Cmac::aes192(&self.$field, key)
            }
            fn aes256(&self, key: &[u8; 32]) -> Result<Self::Aes256Ctx, Self::Error> {
                tpm2::crypto::Cmac::aes256(&self.$field, key)
            }
            fn sm4_128(&self, key: &[u8; 16]) -> Result<Self::Sm4_128Ctx, Self::Error> {
                tpm2::crypto::Cmac::sm4_128(&self.$field, key)
            }
            fn camellia128(&self, key: &[u8; 16]) -> Result<Self::Camellia128Ctx, Self::Error> {
                tpm2::crypto::Cmac::camellia128(&self.$field, key)
            }
            fn camellia192(&self, key: &[u8; 24]) -> Result<Self::Camellia192Ctx, Self::Error> {
                tpm2::crypto::Cmac::camellia192(&self.$field, key)
            }
            fn camellia256(&self, key: &[u8; 32]) -> Result<Self::Camellia256Ctx, Self::Error> {
                tpm2::crypto::Cmac::camellia256(&self.$field, key)
            }
        }
        impl tpm2::crypto::Ecc for $t {
            type NistP192Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::NistP192Ctx;
            type NistP224Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::NistP224Ctx;
            type NistP256Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::NistP256Ctx;
            type NistP384Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::NistP384Ctx;
            type NistP521Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::NistP521Ctx;
            type BnP256Ctx = <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::BnP256Ctx;
            type BnP638Ctx = <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::BnP638Ctx;
            type Sm2P256Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::Sm2P256Ctx;
            type BpP256R1Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::BpP256R1Ctx;
            type BpP384R1Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::BpP384R1Ctx;
            type BpP512R1Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::BpP512R1Ctx;
            type Curve25519Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::Curve25519Ctx;
            type Curve448Ctx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::Curve448Ctx;

            fn nist_p192(&self) -> Result<Self::NistP192Ctx, Self::Error> {
                tpm2::crypto::Ecc::nist_p192(&self.$field)
            }
            fn nist_p224(&self) -> Result<Self::NistP224Ctx, Self::Error> {
                tpm2::crypto::Ecc::nist_p224(&self.$field)
            }
            fn nist_p256(&self) -> Result<Self::NistP256Ctx, Self::Error> {
                tpm2::crypto::Ecc::nist_p256(&self.$field)
            }
            fn nist_p384(&self) -> Result<Self::NistP384Ctx, Self::Error> {
                tpm2::crypto::Ecc::nist_p384(&self.$field)
            }
            fn nist_p521(&self) -> Result<Self::NistP521Ctx, Self::Error> {
                tpm2::crypto::Ecc::nist_p521(&self.$field)
            }
            fn bn_p256(&self) -> Result<Self::BnP256Ctx, Self::Error> {
                tpm2::crypto::Ecc::bn_p256(&self.$field)
            }
            fn bn_p638(&self) -> Result<Self::BnP638Ctx, Self::Error> {
                tpm2::crypto::Ecc::bn_p638(&self.$field)
            }
            fn sm2_p256(&self) -> Result<Self::Sm2P256Ctx, Self::Error> {
                tpm2::crypto::Ecc::sm2_p256(&self.$field)
            }
            fn bp_p256_r1(&self) -> Result<Self::BpP256R1Ctx, Self::Error> {
                tpm2::crypto::Ecc::bp_p256_r1(&self.$field)
            }
            fn bp_p384_r1(&self) -> Result<Self::BpP384R1Ctx, Self::Error> {
                tpm2::crypto::Ecc::bp_p384_r1(&self.$field)
            }
            fn bp_p512_r1(&self) -> Result<Self::BpP512R1Ctx, Self::Error> {
                tpm2::crypto::Ecc::bp_p512_r1(&self.$field)
            }
            fn curve25519(&self) -> Result<Self::Curve25519Ctx, Self::Error> {
                tpm2::crypto::Ecc::curve25519(&self.$field)
            }
            fn curve448(&self) -> Result<Self::Curve448Ctx, Self::Error> {
                tpm2::crypto::Ecc::curve448(&self.$field)
            }
        }
        impl tpm2::crypto::Symmetric for $t {
            fn invalid_key(&self) -> Self::Error {
                CryptoError::InvalidData
            }
            fn invalid_iv(&self) -> Self::Error {
                CryptoError::InvalidData
            }
            type Aes128EncryptCtx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Symmetric>::Aes128EncryptCtx;
            type Aes128DecryptCtx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Symmetric>::Aes128DecryptCtx;
            type Aes192EncryptCtx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Symmetric>::Aes192EncryptCtx;
            type Aes192DecryptCtx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Symmetric>::Aes192DecryptCtx;
            type Aes256EncryptCtx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Symmetric>::Aes256EncryptCtx;
            type Aes256DecryptCtx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Symmetric>::Aes256DecryptCtx;
            type Sm4_128EncryptCtx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Symmetric>::Sm4_128EncryptCtx;
            type Sm4_128DecryptCtx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Symmetric>::Sm4_128DecryptCtx;
            type Camellia128EncryptCtx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Symmetric>::Camellia128EncryptCtx;
            type Camellia128DecryptCtx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Symmetric>::Camellia128DecryptCtx;
            type Camellia192EncryptCtx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Symmetric>::Camellia192EncryptCtx;
            type Camellia192DecryptCtx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Symmetric>::Camellia192DecryptCtx;
            type Camellia256EncryptCtx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Symmetric>::Camellia256EncryptCtx;
            type Camellia256DecryptCtx =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Symmetric>::Camellia256DecryptCtx;

            fn aes128_encrypt(
                &self,
                mode: tpm2::TpmiAlgSymMode,
                key: &[u8; 16],
                iv: &[u8; 16],
            ) -> Result<Self::Aes128EncryptCtx, Self::Error> {
                tpm2::crypto::Symmetric::aes128_encrypt(&self.$field, mode, key, iv)
            }
            fn aes128_decrypt(
                &self,
                mode: tpm2::TpmiAlgSymMode,
                key: &[u8; 16],
                iv: &[u8; 16],
            ) -> Result<Self::Aes128DecryptCtx, Self::Error> {
                tpm2::crypto::Symmetric::aes128_decrypt(&self.$field, mode, key, iv)
            }
            fn aes192_encrypt(
                &self,
                mode: tpm2::TpmiAlgSymMode,
                key: &[u8; 24],
                iv: &[u8; 16],
            ) -> Result<Self::Aes192EncryptCtx, Self::Error> {
                tpm2::crypto::Symmetric::aes192_encrypt(&self.$field, mode, key, iv)
            }
            fn aes192_decrypt(
                &self,
                mode: tpm2::TpmiAlgSymMode,
                key: &[u8; 24],
                iv: &[u8; 16],
            ) -> Result<Self::Aes192DecryptCtx, Self::Error> {
                tpm2::crypto::Symmetric::aes192_decrypt(&self.$field, mode, key, iv)
            }
            fn aes256_encrypt(
                &self,
                mode: tpm2::TpmiAlgSymMode,
                key: &[u8; 32],
                iv: &[u8; 16],
            ) -> Result<Self::Aes256EncryptCtx, Self::Error> {
                tpm2::crypto::Symmetric::aes256_encrypt(&self.$field, mode, key, iv)
            }
            fn aes256_decrypt(
                &self,
                mode: tpm2::TpmiAlgSymMode,
                key: &[u8; 32],
                iv: &[u8; 16],
            ) -> Result<Self::Aes256DecryptCtx, Self::Error> {
                tpm2::crypto::Symmetric::aes256_decrypt(&self.$field, mode, key, iv)
            }
        }
    };
}

impl tpm2::crypto::Base for FakeCrypto {
    type Error = CryptoError;
    fn unimplemented(&self, _: tpm2::Alg) -> Self::Error {
        CryptoError::UnsupportedAlgorithm
    }
}

impl tpm2::crypto::Hash for FakeCrypto {
    type Sha1Ctx = FakeHashCtx;
    type Sha256Ctx = FakeHashCtx;
    type Sha384Ctx = FakeHashCtx;
    type Sha512Ctx = FakeHashCtx;
    type Sm3_256Ctx = FakeHashCtx;
    type Sha3_256Ctx = FakeHashCtx;
    type Sha3_384Ctx = FakeHashCtx;
    type Sha3_512Ctx = FakeHashCtx;

    fn sha1(&self) -> Result<Self::Sha1Ctx, Self::Error> {
        Ok(FakeHashCtx(Vec::new()))
    }
    fn sha256(&self) -> Result<Self::Sha256Ctx, Self::Error> {
        Ok(FakeHashCtx(Vec::new()))
    }
    fn sha384(&self) -> Result<Self::Sha384Ctx, Self::Error> {
        Ok(FakeHashCtx(Vec::new()))
    }
    fn sha512(&self) -> Result<Self::Sha512Ctx, Self::Error> {
        Ok(FakeHashCtx(Vec::new()))
    }
    fn sm3_256(&self) -> Result<Self::Sm3_256Ctx, Self::Error> {
        Ok(FakeHashCtx(Vec::new()))
    }
    fn sha3_256(&self) -> Result<Self::Sha3_256Ctx, Self::Error> {
        Ok(FakeHashCtx(Vec::new()))
    }
    fn sha3_384(&self) -> Result<Self::Sha3_384Ctx, Self::Error> {
        Ok(FakeHashCtx(Vec::new()))
    }
    fn sha3_512(&self) -> Result<Self::Sha3_512Ctx, Self::Error> {
        Ok(FakeHashCtx(Vec::new()))
    }
}

impl tpm2::crypto::Hmac for FakeCrypto {
    type Sha1Ctx = FakeHmacCtx;
    type Sha256Ctx = FakeHmacCtx;
    type Sha384Ctx = FakeHmacCtx;
    type Sha512Ctx = FakeHmacCtx;
    type Sm3_256Ctx = FakeHmacCtx;
    type Sha3_256Ctx = FakeHmacCtx;
    type Sha3_384Ctx = FakeHmacCtx;
    type Sha3_512Ctx = FakeHmacCtx;

    fn sha1(&self, key: &[u8]) -> Result<Self::Sha1Ctx, Self::Error> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn sha256(&self, key: &[u8]) -> Result<Self::Sha256Ctx, Self::Error> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn sha384(&self, key: &[u8]) -> Result<Self::Sha384Ctx, Self::Error> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn sha512(&self, key: &[u8]) -> Result<Self::Sha512Ctx, Self::Error> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn sm3_256(&self, key: &[u8]) -> Result<Self::Sm3_256Ctx, Self::Error> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn sha3_256(&self, key: &[u8]) -> Result<Self::Sha3_256Ctx, Self::Error> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn sha3_384(&self, key: &[u8]) -> Result<Self::Sha3_384Ctx, Self::Error> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn sha3_512(&self, key: &[u8]) -> Result<Self::Sha3_512Ctx, Self::Error> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
}

impl Symmetric for FakeCrypto {
    fn invalid_key(&self) -> Self::Error {
        CryptoError::InvalidData
    }
    fn invalid_iv(&self) -> Self::Error {
        CryptoError::InvalidData
    }
    type Aes128EncryptCtx = FakeSymmetricCtx;
    type Aes128DecryptCtx = FakeSymmetricCtx;
    type Aes192EncryptCtx = FakeSymmetricCtx;
    type Aes192DecryptCtx = FakeSymmetricCtx;
    type Aes256EncryptCtx = FakeSymmetricCtx;
    type Aes256DecryptCtx = FakeSymmetricCtx;
    type Sm4_128EncryptCtx = FakeSymmetricCtx;
    type Sm4_128DecryptCtx = FakeSymmetricCtx;
    type Camellia128EncryptCtx = FakeSymmetricCtx;
    type Camellia128DecryptCtx = FakeSymmetricCtx;
    type Camellia192EncryptCtx = FakeSymmetricCtx;
    type Camellia192DecryptCtx = FakeSymmetricCtx;
    type Camellia256EncryptCtx = FakeSymmetricCtx;
    type Camellia256DecryptCtx = FakeSymmetricCtx;

    fn aes128_encrypt(
        &self,
        _mode: tpm2::TpmiAlgSymMode,
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> Result<Self::Aes128EncryptCtx, Self::Error> {
        Ok(FakeSymmetricCtx {
            key: key.to_vec(),
            iv: *iv,
        })
    }
    fn aes128_decrypt(
        &self,
        _mode: tpm2::TpmiAlgSymMode,
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> Result<Self::Aes128DecryptCtx, Self::Error> {
        Ok(FakeSymmetricCtx {
            key: key.to_vec(),
            iv: *iv,
        })
    }
    fn aes192_encrypt(
        &self,
        _mode: tpm2::TpmiAlgSymMode,
        key: &[u8; 24],
        iv: &[u8; 16],
    ) -> Result<Self::Aes192EncryptCtx, Self::Error> {
        Ok(FakeSymmetricCtx {
            key: key.to_vec(),
            iv: *iv,
        })
    }
    fn aes192_decrypt(
        &self,
        _mode: tpm2::TpmiAlgSymMode,
        key: &[u8; 24],
        iv: &[u8; 16],
    ) -> Result<Self::Aes192DecryptCtx, Self::Error> {
        Ok(FakeSymmetricCtx {
            key: key.to_vec(),
            iv: *iv,
        })
    }
    fn aes256_encrypt(
        &self,
        _mode: tpm2::TpmiAlgSymMode,
        key: &[u8; 32],
        iv: &[u8; 16],
    ) -> Result<Self::Aes256EncryptCtx, Self::Error> {
        Ok(FakeSymmetricCtx {
            key: key.to_vec(),
            iv: *iv,
        })
    }
    fn aes256_decrypt(
        &self,
        _mode: tpm2::TpmiAlgSymMode,
        key: &[u8; 32],
        iv: &[u8; 16],
    ) -> Result<Self::Aes256DecryptCtx, Self::Error> {
        Ok(FakeSymmetricCtx {
            key: key.to_vec(),
            iv: *iv,
        })
    }
}

impl AsymmetricSign for FakeCrypto {
    fn sign_inner(
        &self,
        sign_alg: Alg,
        _private_key: &[u8],
        digest: tpm2::TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let len = match sign_alg {
            Alg::ECDSA => {
                if signature_out.len() < 64 {
                    return Err(CryptoError::BufferTooSmall);
                }
                signature_out[..64].fill(0x5a);
                for (i, &b) in digest.digest().iter().enumerate() {
                    signature_out[i % 64] ^= b;
                }
                64
            }
            _ => {
                let l = std::cmp::min(256, signature_out.len());
                if l < 32 {
                    return Err(CryptoError::BufferTooSmall);
                }
                signature_out[..l].fill(0x5a);
                for (i, &b) in digest.digest().iter().enumerate() {
                    signature_out[i % l] ^= b;
                }
                l
            }
        };
        Ok(len)
    }
}

impl Asymmetric for FakeCrypto {
    fn verify_inner(
        &self,
        sign_alg: Alg,
        _public_key: &[u8],
        digest: tpm2::TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let len = match sign_alg {
            Alg::ECDSA => 64,
            _ => signature.len(),
        };
        if signature.len() != len || len == 0 {
            return Err(CryptoError::InvalidData);
        }
        let mut expected = vec![0x5a; len];
        for (i, &b) in digest.digest().iter().enumerate() {
            expected[i % len] ^= b;
        }
        if signature == expected {
            Ok(())
        } else {
            Err(CryptoError::InvalidData)
        }
    }
    fn encrypt(
        &self,
        _scheme: Alg,
        _hash_alg: Alg,
        _public_key: &[u8],
        _data: &[u8],
        _ciphertext: &mut [u8],
        _label: &[u8],
    ) -> Result<usize, CryptoError> {
        todo!()
    }
    fn decrypt(
        &self,
        _scheme: Alg,
        _hash_alg: Alg,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        _label: &[u8],
    ) -> Result<usize, CryptoError> {
        if private_key.is_empty() {
            return Err(CryptoError::HardwareFailure);
        }
        let len = ciphertext.len();
        if plaintext.len() < len {
            return Err(CryptoError::BufferTooSmall);
        }
        plaintext[..len].copy_from_slice(ciphertext);
        Ok(len)
    }
    fn generate_key(
        &self,
        scheme: Alg,
        _params: Option<tpm2::crypto::asymmetric::KeyParams>,
        public_key: &mut [u8],
        private_key: &mut [u8],
        _seed: Option<&[u8]>,
    ) -> Result<(usize, usize), CryptoError> {
        match scheme {
            Alg::RSA => {
                public_key[..256].fill(0xcc);
                private_key[..256].fill(0xdd);
                Ok((256, 256))
            }
            Alg::ECC => {
                public_key[..64].fill(0xcc);
                private_key[..32].fill(0xdd);
                Ok((64, 32))
            }
            _ => Ok((0, 0)),
        }
    }
}

impl Cmac for FakeCrypto {
    fn invalid_key(&self) -> CryptoError {
        CryptoError::InvalidData
    }
    type Aes128Ctx = FakeHmacCtx;
    type Aes192Ctx = FakeHmacCtx;
    type Aes256Ctx = FakeHmacCtx;
    type Sm4_128Ctx = FakeHmacCtx;
    type Camellia128Ctx = FakeHmacCtx;
    type Camellia192Ctx = FakeHmacCtx;
    type Camellia256Ctx = FakeHmacCtx;

    fn aes128(&self, key: &[u8; 16]) -> Result<Self::Aes128Ctx, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn aes192(&self, key: &[u8; 24]) -> Result<Self::Aes192Ctx, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn aes256(&self, key: &[u8; 32]) -> Result<Self::Aes256Ctx, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn sm4_128(&self, key: &[u8; 16]) -> Result<Self::Sm4_128Ctx, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn camellia128(&self, key: &[u8; 16]) -> Result<Self::Camellia128Ctx, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn camellia192(&self, key: &[u8; 24]) -> Result<Self::Camellia192Ctx, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn camellia256(&self, key: &[u8; 32]) -> Result<Self::Camellia256Ctx, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
}

impl Rng for FakeCrypto {
    fn get_random(&self, _dest: &mut [u8]) -> Result<(), CryptoError> {
        todo!()
    }
}

impl tpm2::crypto::Ecc for FakeCrypto {
    type NistP192Ctx = !;
    type NistP224Ctx = !;
    type NistP256Ctx = !;
    type NistP384Ctx = !;
    type NistP521Ctx = !;
    type BnP256Ctx = !;
    type BnP638Ctx = !;
    type Sm2P256Ctx = !;
    type BpP256R1Ctx = !;
    type BpP384R1Ctx = !;
    type BpP512R1Ctx = !;
    type Curve25519Ctx = !;
    type Curve448Ctx = !;

    fn validate_point(
        &self,
        _curve: tpm2::TpmEccCurve,
        _public_key: &[u8],
    ) -> Result<(), tpm2::crypto::CryptoError> {
        Ok(())
    }
    fn point_multiply_generator(
        &self,
        _curve: tpm2::TpmEccCurve,
        _scalar: &[u8],
        _public_key_out: &mut [u8],
    ) -> Result<(), tpm2::crypto::CryptoError> {
        Ok(())
    }
    fn point_multiply(
        &self,
        _curve: tpm2::TpmEccCurve,
        _scalar: &[u8],
        _public_point: &[u8],
        _derived_point_out: &mut [u8],
    ) -> Result<(), tpm2::crypto::CryptoError> {
        Ok(())
    }
    fn ecdaa_sign(
        &self,
        _curve: tpm2::TpmEccCurve,
        _commit_r: &[u8],
        _commit_x: &[u8],
        _commit_p1: &[u8],
        _private_key_d: &[u8],
        _digest: &[u8],
        _nonce_k_out: &mut [u8],
        _s_out: &mut [u8],
    ) -> Result<(), tpm2::crypto::CryptoError> {
        Ok(())
    }
}

impl CryptoProvider for FakeCrypto {}

pub struct FakeStorage {
    data: std::vec::Vec<u8>,
    pub fail_on_write: bool,
}

impl Default for FakeStorage {
    fn default() -> Self {
        Self {
            data: std::vec![0; 65536],
            fail_on_write: false,
        }
    }
}

impl NvStorage for FakeStorage {
    fn capacity(&self) -> usize {
        self.data.len()
    }
    fn read_nv(&self, offset: usize, buffer: &mut [u8]) -> Result<usize, StorageError> {
        if offset >= self.data.len() {
            return Ok(0);
        }
        let end = std::cmp::min(offset + buffer.len(), self.data.len());
        let len = end - offset;
        buffer[..len].copy_from_slice(&self.data[offset..end]);
        Ok(len)
    }
    fn write_nv(&mut self, offset: usize, buffer: &[u8]) -> Result<usize, StorageError> {
        if self.fail_on_write {
            return Err(StorageError::HardwareError);
        }
        if offset + buffer.len() > self.data.len() {
            self.data.resize(offset + buffer.len(), 0);
        }
        self.data[offset..offset + buffer.len()].copy_from_slice(buffer);
        Ok(buffer.len())
    }
    fn flush(&mut self) -> Result<(), StorageError> {
        Ok(())
    }
}

std::thread_local! {
    static FAKE_TIMER_VAL: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[derive(Default, Clone, Copy)]
pub struct FakeTimer;

impl FakeTimer {
    pub fn new() -> Self {
        Self
    }
    pub fn set_time(&self, val: u64) {
        FAKE_TIMER_VAL.with(|c| c.set(val));
    }
    pub fn advance(&self, delta: u64) {
        FAKE_TIMER_VAL.with(|c| c.set(c.get() + delta));
    }
    pub fn get_time(&self) -> u64 {
        FAKE_TIMER_VAL.with(|c| c.get())
    }
}

impl TpmTimer for FakeTimer {
    fn timer_read(&self) -> u64 {
        FAKE_TIMER_VAL.with(|c| c.get())
    }
}

pub fn marshal_to_slice<M: tpm2::Marshal>(item: &M, buf: &mut [u8]) -> usize
where
    for<'a> &'a mut <M as tpm2::Marshal>::MaxBuffer: TryFrom<&'a mut [u8]>,
{
    let mut tmp = [0u8; 8192];
    let slice: &mut <M as tpm2::Marshal>::MaxBuffer =
        (&mut tmp[..M::MAX_SIZE]).try_into().ok().unwrap();
    let len = item.marshal(slice);
    buf[..len].copy_from_slice(&tmp[..len]);
    len
}

/// A [`tpm2_impl::TpmEngine`] backed by the real test crypto provider and the
/// fake storage/timer/RNG.
pub type RealCryptoEngine<'a> =
    tpm2_impl::TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>;

/// Builds a [`RealCryptoEngine`] plus its [`tpm2_impl::GlobalState`] and runs
/// `TPM2_Startup(TPM_SU_CLEAR)`, so white-box tests can drive real commands
/// while still being able to inspect and modify the internal state.
pub fn setup_real_crypto_tpm<'a>(
    crypto: &'a mut TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a FakeRng,
) -> (RealCryptoEngine<'a>, tpm2_impl::GlobalState) {
    let platform = tpm2_impl::TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = tpm2_impl::TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;
    global_state.g_nv_ok = true;

    let startup = [0x80, 0x01, 0, 0, 0, 0x0c, 0, 0, 0x01, 0x44, 0, 0];
    let mut rsp = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &startup, &mut rsp);
    assert_eq!(&rsp[6..10], &[0, 0, 0, 0], "TPM2_Startup failed");
    (tpm, global_state)
}

/// Marshals `cmd` with `handles` and the given authorization area, executes it
/// on `tpm`, and unmarshals the response (ignoring any response auth area).
///
/// Returns the raw response code on failure.
pub fn execute_command<C: tpm2::commands::Command>(
    tpm: &mut RealCryptoEngine<'_>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &C::Handles,
    cmd: &C,
    auths: &[tpm2::TpmsAuthCommand],
) -> Result<(C::RespHandles, C::Response<'static>), u32>
where
    for<'b> &'b mut <C as tpm2::Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <<C as tpm2::commands::Command>::Handles as tpm2::Marshal>::MaxBuffer:
        TryFrom<&'b mut [u8]>,
    C::Response<'static>: tpm2::Unmarshal<'static>,
{
    use tpm2::Unmarshal;

    let mut req = Vec::new();
    req.extend_from_slice(
        &(if auths.is_empty() {
            0x8001u16
        } else {
            0x8002u16
        })
        .to_be_bytes(),
    );
    req.extend_from_slice(&[0u8; 4]); // commandSize, patched below
    req.extend_from_slice(&C::CMD_CODE.code().to_be_bytes());
    let mut buf = [0u8; 8192];
    let len = marshal_to_slice(handles, &mut buf);
    req.extend_from_slice(&buf[..len]);
    if !auths.is_empty() {
        let mut area = Vec::new();
        for auth in auths {
            let len = marshal_to_slice(auth, &mut buf);
            area.extend_from_slice(&buf[..len]);
        }
        req.extend_from_slice(&(area.len() as u32).to_be_bytes());
        req.extend_from_slice(&area);
    }
    let len = marshal_to_slice(cmd, &mut buf);
    req.extend_from_slice(&buf[..len]);
    let size = req.len() as u32;
    req[2..6].copy_from_slice(&size.to_be_bytes());

    let mut rsp = [0u8; 8192];
    let rsp_len = tpm.execute_command_separate(global_state, &req, &mut rsp);
    let rc = u32::from_be_bytes(rsp[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }
    let body: &'static [u8] = Vec::leak(rsp[10..rsp_len].to_vec());
    let mut slice = body;
    let resp_handles = C::RespHandles::unmarshal(&mut slice).expect("response handles");
    if rsp[0..2] == 0x8002u16.to_be_bytes() {
        let _param_size = u32::unmarshal(&mut slice).expect("parameterSize");
    }
    let resp = <C::Response<'static>>::unmarshal(&mut slice).expect("response parameters");
    Ok((resp_handles, resp))
}

/// A password authorization (`TPM_RS_PW`) carrying `auth`.
pub fn password_auth(auth: &'static [u8]) -> tpm2::TpmsAuthCommand<'static> {
    tpm2::TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: tpm2::TpmaSession(0),
        hmac: tpm2::Tpm2bAuth::from_bytes(auth).unwrap(),
    }
}
