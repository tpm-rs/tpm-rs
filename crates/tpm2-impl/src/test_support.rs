extern crate alloc;
extern crate std;

use crate::handler::SessionState;
use crate::storage::{NvStorage, StorageError};
use crate::timer::TpmTimer;
use alloc::vec::Vec;
use tpm2::Alg;
use tpm2::crypto::Rng;
use tpm2::crypto::{Asymmetric, AsymmetricSign, Cmac, Symmetric};
use tpm2::crypto::{CryptoError, CryptoProvider};
use tpm2::{Handle, TpmSe};
use tpm2::{Tpm2bNonce, TpmiAlgHash, TpmtSymDef};

#[allow(clippy::too_many_arguments)]
pub fn make_test_session_state(
    session_handle: u32,
    session_type: TpmSe,
    auth_hash: TpmiAlgHash,
    nonce_tpm: Tpm2bNonce,
    nonce_caller: Tpm2bNonce,
    session_key_slice: &[u8],
    symmetric: Option<TpmtSymDef>,
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
        bound_entity: tpm2::Tpm2bName::default().into(),
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
        let mut counter = self.counter.lock().expect("lock should not be poisoned");
        for b in dest {
            *b = *counter;
            *counter = counter.wrapping_add(1);
        }
        Ok(())
    }
}

pub struct FakeCrypto;

impl tpm2::crypto::Base for FakeCrypto {
    type Error = CryptoError;
    fn unimplemented(&self, _alg: Alg) -> Self::Error {
        CryptoError::UnsupportedAlgorithm
    }
}

impl tpm2::crypto::Hash for FakeCrypto {
    type Sha1Ctx = !;
    type Sha256Ctx = !;
    type Sha384Ctx = !;
    type Sha512Ctx = !;
    type Sm3_256Ctx = !;
    type Sha3_256Ctx = !;
    type Sha3_384Ctx = !;
    type Sha3_512Ctx = !;
}

pub struct FakeHmacCtx(Vec<u8>);

impl tpm2::crypto::Update<CryptoError> for FakeHmacCtx {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.extend_from_slice(data);
        Ok(())
    }
}

impl<const N: usize> tpm2::crypto::Finalize<N, CryptoError> for FakeHmacCtx {
    fn finalize(self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        out.fill(0);
        if !self.0.is_empty() {
            for (i, &b) in self.0.iter().enumerate() {
                out[i % N] ^= b;
            }
        }
        out[1] ^= self.0.len() as u8;
        Ok(())
    }
}

impl tpm2::crypto::Hmac for FakeCrypto {
    type Sha1Ctx = FakeHmacCtx;
    fn sha1(&self, key: &[u8]) -> Result<Self::Sha1Ctx, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    type Sha256Ctx = FakeHmacCtx;
    fn sha256(&self, key: &[u8]) -> Result<Self::Sha256Ctx, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    type Sha384Ctx = FakeHmacCtx;
    fn sha384(&self, key: &[u8]) -> Result<Self::Sha384Ctx, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    type Sha512Ctx = FakeHmacCtx;
    fn sha512(&self, key: &[u8]) -> Result<Self::Sha512Ctx, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    type Sm3_256Ctx = !;
    type Sha3_256Ctx = !;
    type Sha3_384Ctx = !;
    type Sha3_512Ctx = !;
}

pub struct FakeSymCtx {
    pub key: alloc::vec::Vec<u8>,
    pub iv: [u8; 16],
}

impl tpm2::crypto::UpdateInPlace<CryptoError> for FakeSymCtx {
    fn update(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= self.key[i % self.key.len()] ^ self.iv[i % 16];
        }
        Ok(())
    }
}

impl tpm2::crypto::Finalize<16, CryptoError> for FakeSymCtx {
    fn finalize(self, out: &mut [u8; 16]) -> Result<(), CryptoError> {
        *out = self.iv;
        Ok(())
    }
}

impl Symmetric for FakeCrypto {
    fn invalid_key(&self) -> CryptoError {
        CryptoError::InvalidData
    }

    fn invalid_iv(&self) -> CryptoError {
        CryptoError::InvalidData
    }

    type Aes128EncryptCtx = FakeSymCtx;
    fn aes128_encrypt(
        &self,
        _mode: tpm2::TpmiAlgSymMode,
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> Result<Self::Aes128EncryptCtx, CryptoError> {
        Ok(FakeSymCtx {
            key: key.to_vec(),
            iv: *iv,
        })
    }

    type Aes128DecryptCtx = FakeSymCtx;
    fn aes128_decrypt(
        &self,
        _mode: tpm2::TpmiAlgSymMode,
        key: &[u8; 16],
        iv: &[u8; 16],
    ) -> Result<Self::Aes128DecryptCtx, CryptoError> {
        Ok(FakeSymCtx {
            key: key.to_vec(),
            iv: *iv,
        })
    }

    type Aes192EncryptCtx = FakeSymCtx;
    fn aes192_encrypt(
        &self,
        _mode: tpm2::TpmiAlgSymMode,
        key: &[u8; 24],
        iv: &[u8; 16],
    ) -> Result<Self::Aes192EncryptCtx, CryptoError> {
        Ok(FakeSymCtx {
            key: key.to_vec(),
            iv: *iv,
        })
    }

    type Aes192DecryptCtx = FakeSymCtx;
    fn aes192_decrypt(
        &self,
        _mode: tpm2::TpmiAlgSymMode,
        key: &[u8; 24],
        iv: &[u8; 16],
    ) -> Result<Self::Aes192DecryptCtx, CryptoError> {
        Ok(FakeSymCtx {
            key: key.to_vec(),
            iv: *iv,
        })
    }

    type Aes256EncryptCtx = FakeSymCtx;
    fn aes256_encrypt(
        &self,
        _mode: tpm2::TpmiAlgSymMode,
        key: &[u8; 32],
        iv: &[u8; 16],
    ) -> Result<Self::Aes256EncryptCtx, CryptoError> {
        Ok(FakeSymCtx {
            key: key.to_vec(),
            iv: *iv,
        })
    }

    type Aes256DecryptCtx = FakeSymCtx;
    fn aes256_decrypt(
        &self,
        _mode: tpm2::TpmiAlgSymMode,
        key: &[u8; 32],
        iv: &[u8; 16],
    ) -> Result<Self::Aes256DecryptCtx, CryptoError> {
        Ok(FakeSymCtx {
            key: key.to_vec(),
            iv: *iv,
        })
    }

    type Sm4_128EncryptCtx = !;
    type Sm4_128DecryptCtx = !;
    type Camellia128EncryptCtx = !;
    type Camellia128DecryptCtx = !;
    type Camellia192EncryptCtx = !;
    type Camellia192DecryptCtx = !;
    type Camellia256EncryptCtx = !;
    type Camellia256DecryptCtx = !;
}

impl AsymmetricSign for FakeCrypto {
    fn sign_inner(
        &self,
        _sign_alg: Alg,
        _private_key: &[u8],
        _digest: tpm2::TpmtHa<'_>,
        _signature_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        todo!()
    }
}

impl Asymmetric for FakeCrypto {
    fn verify_inner(
        &self,
        _sign_alg: Alg,
        _public_key: &[u8],
        _digest: tpm2::TpmtHa<'_>,
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        todo!()
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
        _scheme: Alg,
        _params: Option<tpm2::crypto::asymmetric::KeyParams>,
        _public_key: &mut [u8],
        _private_key: &mut [u8],
        _seed: Option<&[u8]>,
    ) -> Result<(usize, usize), CryptoError> {
        todo!()
    }
}

impl Cmac for FakeCrypto {
    fn invalid_key(&self) -> CryptoError {
        CryptoError::InvalidData
    }
    type Aes128Ctx = !;
    type Aes192Ctx = !;
    type Aes256Ctx = !;
    type Sm4_128Ctx = !;
    type Camellia128Ctx = !;
    type Camellia192Ctx = !;
    type Camellia256Ctx = !;
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
            data: std::vec![0; 1024],
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

pub struct FakeTimer;

impl TpmTimer for FakeTimer {
    fn timer_read(&self) -> u64 {
        0
    }
}
