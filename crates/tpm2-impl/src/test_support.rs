extern crate alloc;
extern crate std;

use crate::handler::SessionState;
use crate::storage::{NvStorage, StorageError};
use crate::timer::TpmTimer;
use alloc::vec::Vec;
use tpm2::Alg;
use tpm2::crypto::{Asymmetric, AsymmetricSign, Cmac, ConstantTimeEq, Random, Rng, Symmetric};
use tpm2::crypto::{CryptoError, CryptoProvider, Direction, ModeIv};
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
        is_da_bound: false,
        is_lockout_bound: false,
    }
}

/// A deterministic platform RNG: fills buffers with an incrementing (wrapping) byte counter that
/// starts at 1 and continues across calls.
pub struct FakeRng {
    counter: u8,
}

impl Default for FakeRng {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeRng {
    pub fn new() -> Self {
        Self { counter: 1 }
    }
}

impl Rng for FakeRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), CryptoError> {
        for b in dest {
            *b = self.counter;
            self.counter = self.counter.wrapping_add(1);
        }
        Ok(())
    }

    /// Ignores `data`, like exp's default `Rng::stir_random`.
    fn reseed(&mut self, _data: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

pub struct FakeCrypto;

impl tpm2::crypto::Hash for FakeCrypto {
    type Sha1Context = !;
    type Sha256Context = !;
    type Sha384Context = !;
    type Sha512Context = !;
    type Sm3_256Context = !;
    type Sha3_256Context = !;
    type Sha3_384Context = !;
    type Sha3_512Context = !;
}

/// A fake HMAC: XOR-folds the key and the data into the output and mixes in their total length.
pub struct FakeHmacCtx(Vec<u8>);

impl tpm2::crypto::Update for FakeHmacCtx {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.extend_from_slice(data);
        Ok(())
    }
}

impl<const N: usize> tpm2::crypto::Finalize<N> for FakeHmacCtx {
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
    type Sha1Context = FakeHmacCtx;
    fn sha1(&self, key: &[u8]) -> Result<Self::Sha1Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    type Sha256Context = FakeHmacCtx;
    fn sha256(&self, key: &[u8]) -> Result<Self::Sha256Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    type Sha384Context = FakeHmacCtx;
    fn sha384(&self, key: &[u8]) -> Result<Self::Sha384Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    type Sha512Context = FakeHmacCtx;
    fn sha512(&self, key: &[u8]) -> Result<Self::Sha512Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    type Sm3_256Context = !;
    type Sha3_256Context = !;
    type Sha3_384Context = !;
    type Sha3_512Context = !;
}

/// The fake AES cipher, for both directions and every mode: XORs `data` with the repeated key
/// and the repeated IV (all zeros for ECB). The IV is left unchanged, so the returned `ivOut`
/// equals the IV passed in.
fn fake_sym_xor(key: &[u8], mode: ModeIv<'_>, data: &mut [u8]) -> Result<(), CryptoError> {
    let iv = match mode {
        ModeIv::Ctr(iv) | ModeIv::Ofb(iv) | ModeIv::Cbc(iv) | ModeIv::Cfb(iv) => *iv,
        ModeIv::Ecb => [0u8; 16],
    };
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[i % key.len()] ^ iv[i % 16];
    }
    Ok(())
}

impl Symmetric for FakeCrypto {
    fn aes128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        _dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        fake_sym_xor(key, mode, data)
    }

    fn aes192(
        &self,
        key: &[u8; 24],
        mode: ModeIv<'_>,
        _dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        fake_sym_xor(key, mode, data)
    }

    fn aes256(
        &self,
        key: &[u8; 32],
        mode: ModeIv<'_>,
        _dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        fake_sym_xor(key, mode, data)
    }
}

impl AsymmetricSign for FakeCrypto {
    fn sign_inner(
        &self,
        _sign_alg: Alg,
        _private_key: &[u8],
        _digest: tpm2::TpmtHa<'_>,
        _signature_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        todo!()
    }
}

impl Asymmetric for FakeCrypto {
    fn verify_inner(
        &self,
        _sign_alg: Alg,
        _public_key: &[u8],
        _rsa_exponent: u32,
        _digest: tpm2::TpmtHa<'_>,
        _signature: &[u8],
    ) -> Result<bool, CryptoError> {
        todo!()
    }
    fn encrypt(
        &self,
        _scheme: Alg,
        _hash_alg: Alg,
        _public_key: &[u8],
        _rsa_exponent: u32,
        _data: &[u8],
        _ciphertext: &mut [u8],
        _label: &[u8],
    ) -> Result<Option<usize>, CryptoError> {
        todo!()
    }
    /// Copies `ciphertext` to `plaintext`. An empty private key fails with
    /// [`CryptoError::Internal`] (exp: `HardwareFailure`), and so does a `plaintext` buffer that
    /// is too small (exp: `BufferTooSmall`).
    fn decrypt(
        &self,
        _scheme: Alg,
        _hash_alg: Alg,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        _label: &[u8],
    ) -> Result<Option<usize>, CryptoError> {
        if private_key.is_empty() {
            return Err(CryptoError::Internal);
        }
        let len = ciphertext.len();
        if plaintext.len() < len {
            return Err(CryptoError::Internal);
        }
        plaintext[..len].copy_from_slice(ciphertext);
        Ok(Some(len))
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
    type Aes128Context = !;
    type Aes192Context = !;
    type Aes256Context = !;
    type Sm4_128Context = !;
    type Camellia128Context = !;
    type Camellia192Context = !;
    type Camellia256Context = !;
}

impl ConstantTimeEq for FakeCrypto {
    fn constant_time_eq<const N: usize>(&self, a: &[u8; N], b: &[u8; N]) -> bool {
        a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

impl Random for FakeCrypto {
    type Rng = !;
}

/// The fake ECC operations accept every input and report success without writing any output
/// (exp's `Ok(())`). The output lengths reported are those of the output buffers.
impl tpm2::crypto::Ecc for FakeCrypto {
    type NistP192Context = !;
    type NistP224Context = !;
    type NistP256Context = !;
    type NistP384Context = !;
    type NistP521Context = !;
    type BnP256Context = !;
    type BnP638Context = !;
    type Sm2P256Context = !;
    type BpP256R1Context = !;
    type BpP384R1Context = !;
    type BpP512R1Context = !;
    type Curve25519Context = !;
    type Curve448Context = !;

    fn validate_point(
        &self,
        _curve: tpm2::TpmEccCurve,
        _public_key: &[u8],
    ) -> Result<bool, CryptoError> {
        Ok(true)
    }
    fn point_multiply_generator(
        &self,
        _curve: tpm2::TpmEccCurve,
        _scalar: &[u8],
        public_key_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        Ok(Some(public_key_out.len()))
    }
    fn point_multiply(
        &self,
        _curve: tpm2::TpmEccCurve,
        _scalar: &[u8],
        _public_point: &[u8],
        derived_point_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        Ok(Some(derived_point_out.len()))
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
        s_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        Ok(Some(s_out.len()))
    }
}

impl CryptoProvider for FakeCrypto {
    /// Its algorithms are fakes, which fail the known-answer self tests.
    const KNOWN_ANSWER_TESTS: bool = false;

    fn get_random(&self, _dest: &mut [u8]) -> Result<(), CryptoError> {
        todo!()
    }
}

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
