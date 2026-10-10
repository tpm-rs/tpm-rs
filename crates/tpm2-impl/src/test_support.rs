//! Test doubles for the [`TpmPlatform`](crate::TpmPlatform) dependencies.
//!
//! None of these fakes are cryptographically meaningful. They exist so that unit tests can
//! construct a [`TpmEngine`](crate::TpmEngine) and exercise command processing deterministically
//! without a real cryptographic backend:
//! - [`FakeCrypto`]: a [`Crypto`](crate::Crypto) backend with a fake HMAC (SHA-1/256/384/512) and
//!   a fake XOR "cipher" (AES-128/192/256). Every other algorithm reports
//!   [`CryptoError::Unsupported`].
//! - [`FakeRng`]: a deterministic, counter-based [`Rng`].
//! - [`FakeStorage`]: an in-memory [`NvStorage`].
//! - [`FakeTimer`]: a [`TpmTimer`] that always reads zero.
//!
//! [`with_test_engine`] wires these into a [`TestEngine`], and [`execute`] runs a single
//! no-sessions command through it.

extern crate std;

use crate::handler::SessionState;
use crate::owned::OwnedName;
use crate::storage::{NvStorage, StorageError};
use crate::timer::TpmTimer;
use crate::{GlobalState, TpmEngine, TpmPlatform};
use std::vec::Vec;
use tpm2::crypto::{
    Cmac, ConstantTimeEq, CryptoError, Direction, Ecc, Finalize, Hash, Hmac, Mldsa, Mlkem, ModeIv,
    Random, Rng, Rsa, Signing, Symmetric, Update,
};
use tpm2::{Handle, Tpm2bNonce, TpmCc, TpmSe, TpmiAlgHash, TpmtSymDef};

/// Builds a [`SessionState`] from the given parameters, with every other field cleared.
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
        bound_entity: OwnedName::default(),
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

/// Deterministic, non-cryptographic [`Rng`].
///
/// Produces an incrementing (wrapping) byte counter starting at `1`. [`Rng::reseed`] adds every
/// input byte to the counter, so stirring in data observably shifts the following output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeRng {
    counter: u8,
}

impl Default for FakeRng {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeRng {
    pub const fn new() -> Self {
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

    fn reseed(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.counter = data.iter().fold(self.counter, |c, &b| c.wrapping_add(b));
        Ok(())
    }
}

/// Fake cryptographic backend (see the [module documentation](self)).
pub struct FakeCrypto;

impl Random for FakeCrypto {
    type Rng = FakeRng;

    fn rng(&self) -> Result<FakeRng, CryptoError> {
        Ok(FakeRng::new())
    }

    fn rng_seeded(&self, seed: &[u8]) -> Result<FakeRng, CryptoError> {
        let mut rng = FakeRng::new();
        rng.reseed(seed)?;
        Ok(rng)
    }
}

impl Hash for FakeCrypto {
    type Sha1Context = !;
    type Sha256Context = !;
    type Sha384Context = !;
    type Sha512Context = !;
    type Sm3_256Context = !;
    type Sha3_256Context = !;
    type Sha3_384Context = !;
    type Sha3_512Context = !;
}

/// Fake HMAC context: XOR-folds the key and all input into the output and mixes in the total
/// length. Deterministic, but NOT a MAC.
pub struct FakeHmacCtx(Vec<u8>);

impl Update for FakeHmacCtx {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.extend_from_slice(data);
        Ok(())
    }
}

impl<const N: usize> Finalize<N> for FakeHmacCtx {
    fn finalize(self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        out.fill(0);
        for (i, &b) in self.0.iter().enumerate() {
            out[i % N] ^= b;
        }
        out[1] ^= self.0.len().to_le_bytes()[0];
        Ok(())
    }
}

impl Hmac for FakeCrypto {
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

impl Cmac for FakeCrypto {
    type Aes128Context = !;
    type Aes192Context = !;
    type Aes256Context = !;
    type Sm4_128Context = !;
    type Camellia128Context = !;
    type Camellia192Context = !;
    type Camellia256Context = !;
}

/// Fake XOR "cipher": `data[i] ^= key[i % key.len()] ^ iv[i % 16]` (a zero IV for ECB).
///
/// Encryption and decryption are the same operation, and the IV is NOT updated.
fn fake_xor_cipher(key: &[u8], mode: ModeIv<'_>, data: &mut [u8]) {
    let iv = match mode {
        ModeIv::Ctr(iv) | ModeIv::Ofb(iv) | ModeIv::Cbc(iv) | ModeIv::Cfb(iv) => *iv,
        ModeIv::Ecb => [0; 16],
    };
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[i % key.len()] ^ iv[i % iv.len()];
    }
}

impl Symmetric for FakeCrypto {
    fn aes128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        _dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        fake_xor_cipher(key, mode, data);
        Ok(())
    }

    fn aes192(
        &self,
        key: &[u8; 24],
        mode: ModeIv<'_>,
        _dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        fake_xor_cipher(key, mode, data);
        Ok(())
    }

    fn aes256(
        &self,
        key: &[u8; 32],
        mode: ModeIv<'_>,
        _dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        fake_xor_cipher(key, mode, data);
        Ok(())
    }
}

impl Rsa for FakeCrypto {
    type PublicKey = !;
    type PrivateKey = !;
}

impl Ecc for FakeCrypto {
    type PublicKey = !;
    type PrivateKey = !;
}

impl Signing for FakeCrypto {}

impl Mlkem for FakeCrypto {
    type PublicKey = !;
    type PrivateKey = !;
}

impl Mldsa for FakeCrypto {
    type PublicKey = !;
    type PrivateKey = !;
    type MuContext = !;
}

impl ConstantTimeEq for FakeCrypto {
    fn constant_time_eq<const N: usize>(&self, a: &[u8; N], b: &[u8; N]) -> bool {
        a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

/// In-memory [`NvStorage`] (64 KiB initially, grows on out-of-bounds writes).
///
/// [`StorageManager`](crate::storage::manager::StorageManager) checks [`NvStorage::capacity`]
/// before defining items, so the initial size is what bounds the persistent state.
pub struct FakeStorage {
    data: Vec<u8>,
    /// Makes every [`NvStorage::write_nv`] call fail with [`StorageError::HardwareError`].
    pub fail_on_write: bool,
}

impl Default for FakeStorage {
    fn default() -> Self {
        Self {
            data: std::vec![0; 64 * 1024],
            fail_on_write: false,
        }
    }
}

impl NvStorage for FakeStorage {
    fn capacity(&self) -> usize {
        self.data.len()
    }

    fn read_nv(&self, offset: usize, buffer: &mut [u8]) -> Result<usize, StorageError> {
        let Some(src) = self.data.get(offset..) else {
            return Ok(0);
        };
        let len = buffer.len().min(src.len());
        buffer[..len].copy_from_slice(&src[..len]);
        Ok(len)
    }

    fn write_nv(&mut self, offset: usize, buffer: &[u8]) -> Result<usize, StorageError> {
        if self.fail_on_write {
            return Err(StorageError::HardwareError);
        }
        let end = offset + buffer.len();
        if end > self.data.len() {
            self.data.resize(end, 0);
        }
        self.data[offset..end].copy_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> Result<(), StorageError> {
        Ok(())
    }
}

/// [`TpmTimer`] that always reads zero.
pub struct FakeTimer;

impl TpmTimer for FakeTimer {
    fn timer_read(&self) -> u64 {
        0
    }
}

/// [`TpmEngine`] running on the fakes in this module.
pub type TestEngine<'a> = TpmEngine<'a, FakeCrypto, FakeStorage, FakeTimer>;

/// Runs `f` against a fresh [`TestEngine`] and [`GlobalState`].
///
/// Storage is initialized with [`TpmEngine::init_storage`], NV is available and the locality is
/// 0, but `TPM2_Startup` has NOT been sent yet. The RNG is a fresh [`FakeRng`].
pub fn with_test_engine<R>(f: impl FnOnce(&mut TestEngine<'_>, &mut GlobalState) -> R) -> R {
    let crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let platform = TpmPlatform::new(&crypto, &mut storage, &mut timer, FakeRng::new());
    let mut tpm = TpmEngine::new(platform).expect("TpmEngine::new failed");
    let mut global_state = GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;
    f(&mut tpm, &mut global_state)
}

/// Sends a `TPM_ST_NO_SESSIONS` command with code `cc` and handle/parameter area `body`.
///
/// Returns the raw response code and the response bytes after the 10-byte header.
pub fn execute(
    tpm: &mut TestEngine<'_>,
    global_state: &mut GlobalState,
    cc: TpmCc,
    body: &[u8],
) -> (u32, Vec<u8>) {
    const HEADER_SIZE: usize = 10;
    let size = u32::try_from(HEADER_SIZE + body.len()).expect("command too large");
    let mut request = Vec::with_capacity(HEADER_SIZE + body.len());
    request.extend_from_slice(&0x8001u16.to_be_bytes());
    request.extend_from_slice(&size.to_be_bytes());
    request.extend_from_slice(&cc.code().to_be_bytes());
    request.extend_from_slice(body);

    let mut response = std::vec![0u8; 4096];
    let len = tpm.execute_command_separate(global_state, &request, &mut response);
    assert!(
        len >= HEADER_SIZE,
        "response shorter than a header: {len} bytes"
    );
    let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    (rc, response[HEADER_SIZE..len].to_vec())
}
