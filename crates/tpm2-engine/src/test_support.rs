extern crate alloc;
extern crate std;

use crate::handler::SessionState;
use crate::storage::{NvStorage, StorageError};
use crate::timer::TpmTimer;
use alloc::vec::Vec;
use tpm2::TpmSe;
use tpm2::crypto::backend::{
    Cmac, Ecc, Hash, Hmac, HmacState, Mldsa, Mlkem, Rsa, Symmetric, SymmetricState, default_crypt,
};
use tpm2::crypto::{Block, CipherInput, Crypto, CryptoError, Direction, Random, Rng};
use tpm2::{Tpm2bNonce, TpmiAlgHash, TpmtSymDef};

#[allow(clippy::too_many_arguments)]
pub fn make_test_session_state(
    session_handle: u32,
    session_type: TpmSe,
    auth_hash: TpmiAlgHash,
    nonce_tpm: Tpm2bNonce,
    session_key_slice: &[u8],
    symmetric: Option<TpmtSymDef>,
) -> SessionState {
    let mut session_key = [0u8; 128];
    session_key[..session_key_slice.len()].copy_from_slice(session_key_slice);
    SessionState {
        session_handle,
        session_type,
        auth_hash,
        nonce_tpm: nonce_tpm.into(),
        session_key,
        session_key_len: session_key_slice.len(),
        symmetric,
        bound_entity: tpm2::Tpm2bName::default().into(),
        audit_digest: None,
        audit_digest_len: 0,
        policy_hash: [0u8; 64],
        policy_hash_len: 0,
        is_cp_hash_defined: false,
        is_template_hash_defined: false,
        is_parameters_hash_defined: false,
        is_pp_required: false,
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
        sec_channel: Default::default(),
    }
}

/// A deterministic RNG: fills buffers with an incrementing (wrapping) byte counter that starts at
/// 1 and continues across calls. It is both the fake platform RNG and the RNG of [`FakeCrypto`].
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

    /// Ignores `data`.
    fn stir_bytes(&mut self, _data: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

/// A fake crypto backend: the fake HMAC ([`FakeHmac`]), the fake AES ([`FakeAes`]) and the
/// [`FakeRng`]; every other algorithm is unsupported.
pub struct FakeCrypto;

impl Hash for FakeCrypto {
    type Sha1 = !;
    type Sha256 = !;
    type Sha384 = !;
    type Sha512 = !;
    type Sm3_256 = !;
    type Sha3_256 = !;
    type Sha3_384 = !;
    type Sha3_512 = !;
}

/// A fake HMAC: XOR-folds the key and the data into the output and mixes in their total length.
pub struct FakeHmac(Vec<u8>);

impl<const N: usize> HmacState<N> for FakeHmac {
    fn init(key: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self(key.to_vec()))
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.extend_from_slice(data);
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        out.fill(0);
        for (i, &b) in self.0.iter().enumerate() {
            out[i % N] ^= b;
        }
        out[1] ^= self.0.len() as u8;
        Ok(())
    }
}

impl Hmac for FakeCrypto {
    type Sha1 = FakeHmac;
    type Sha256 = FakeHmac;
    type Sha384 = FakeHmac;
    type Sha512 = FakeHmac;
    type Sm3_256 = !;
    type Sha3_256 = !;
    type Sha3_384 = !;
    type Sha3_512 = !;
}

/// The fake AES cipher, for both directions and every mode: XORs the data with the repeated key
/// and the repeated IV (all zeros for ECB). The IV is left unchanged (also after a partial final
/// CFB block), so the returned `ivOut` equals the IV passed in.
pub struct FakeAes<const K: usize>([u8; K]);

impl<const K: usize> FakeAes<K> {
    fn xor(&self, iv: &Block, data: &mut [u8]) -> Result<(), CryptoError> {
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= self.0[i % K] ^ iv[i % 16];
        }
        Ok(())
    }
}

impl<const K: usize> SymmetricState<K> for FakeAes<K> {
    fn init(key: &[u8; K]) -> Result<Self, CryptoError> {
        Ok(Self(*key))
    }
    fn ctr(&self, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        self.xor(iv, data)
    }
    fn ofb(&self, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        self.xor(iv, data)
    }
    fn cbc(&self, _dir: Direction, iv: &mut Block, data: &mut [Block]) -> Result<(), CryptoError> {
        self.xor(iv, data.as_flattened_mut())
    }
    fn cfb(&self, _dir: Direction, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        self.xor(iv, data)
    }
    fn ecb(&self, _dir: Direction, data: &mut [Block]) -> Result<(), CryptoError> {
        self.xor(&[0; 16], data.as_flattened_mut())
    }
    /// Like [`default_crypt`], but without zeroing the IV after a partial final CFB block.
    fn crypt(&self, dir: Direction, input: CipherInput<'_>) -> Result<(), CryptoError> {
        match input {
            CipherInput::Cfb(iv, data) => self.cfb(dir, iv, data),
            input => default_crypt(self, dir, input),
        }
    }
}

impl Symmetric for FakeCrypto {
    type Aes128 = FakeAes<16>;
    type Aes192 = FakeAes<24>;
    type Aes256 = FakeAes<32>;
    type Sm4_128 = !;
    type Camellia128 = !;
    type Camellia192 = !;
    type Camellia256 = !;
}

impl Cmac for FakeCrypto {
    type Aes128 = !;
    type Aes192 = !;
    type Aes256 = !;
    type Sm4_128 = !;
    type Camellia128 = !;
    type Camellia192 = !;
    type Camellia256 = !;
}

impl Rsa for FakeCrypto {
    type Rsa1024 = !;
    type Rsa2048 = !;
    type Rsa3072 = !;
    type Rsa4096 = !;
}

impl Ecc for FakeCrypto {
    type NistP192 = !;
    type NistP224 = !;
    type NistP256 = !;
    type NistP384 = !;
    type NistP521 = !;
    type BNP256 = !;
    type BNP638 = !;
    type SM2P256 = !;
    type BpP256R1 = !;
    type BpP384R1 = !;
    type BpP512R1 = !;
    type Ed25519 = !;
    type Ed448 = !;
    type X25519 = !;
    type X448 = !;
}

impl Mldsa for FakeCrypto {
    type Mldsa44 = !;
    type Mldsa65 = !;
    type Mldsa87 = !;
}

impl Mlkem for FakeCrypto {
    type Mlkem512 = !;
    type Mlkem768 = !;
    type Mlkem1024 = !;
}

impl Random for FakeCrypto {
    type Rng = FakeRng;

    fn from_entropy() -> Result<FakeRng, CryptoError> {
        Ok(FakeRng::new())
    }

    /// Deterministic: the counter starts at the wrapping sum of the seed octets plus 1.
    fn from_seed(seed: &[u8]) -> Result<FakeRng, CryptoError> {
        let start = seed.iter().fold(1u8, |acc, &b| acc.wrapping_add(b));
        Ok(FakeRng { counter: start })
    }
}

impl Crypto for FakeCrypto {
    /// Its algorithms are fakes, which fail the known-answer self tests.
    const KNOWN_ANSWER_TESTS: bool = false;

    fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
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

/// A [`crate::Platform`] over the fake components whose NV data structure is an owned
/// [`FakeStorage`], for tests of a standalone [`TestState`].
pub type TestPlatform = FakePlatform<'static, FakeCrypto, FakeStorage, FakeTimer, FakeRng>;

/// A standalone TPM state ([`crate::State`]) over [`TestPlatform`]; its
/// [`Default`](crate::State::default) has a fresh [`FakeStorage`].
pub type TestState = crate::State<TestPlatform>;

/// A test platform that borrows its components (every platform crate defines its own
/// platform type; the engine's tests use this one).
///
/// `I` is the [`crate::Platform::IndexState`] of the TPM, which the engine owns
/// ([`crate::TpmEngine::new`]); typically an NV medium or a mutable reference to one.
#[allow(dead_code)]
pub struct FakePlatform<'a, C, I, T, R>
where
    C: Crypto,
    I: IndexState,
    T: TpmTimer,
    R: Rng,
{
    /// Cryptography backend ([`Crypto`]). The backend's interfaces are static (its
    /// algorithms are associated types); the reference only selects and borrows it.
    pub crypto: &'a mut C,
    /// Monotonic timer.
    pub timer: &'a mut T,
    /// Platform random number generator ([`crate::Platform::Rng`]).
    pub rng: &'a mut R,
    /// Firmware identity ([`crate::Platform::firmware`]); `None` by default ([`FakePlatform::new`]).
    pub firmware: Option<&'a (dyn TpmFirmware + Sync)>,
    /// Secure channel information of the TPM's secure transport layer
    /// ([`crate::Platform::secure_channel`]); `None` by default ([`FakePlatform::new`]).
    pub secure_channel: Option<&'a (dyn SecureChannel + Sync)>,
    /// Immutable platform information ([`crate::Platform::info`]); [`crate::Info::DEFAULT`] by default
    /// ([`FakePlatform::new`]).
    pub info: crate::Info,
    /// The type of the TPM's NV data structure ([`crate::Platform::IndexState`]).
    index: PhantomData<fn() -> I>,
}

#[allow(dead_code)]
impl<'a, C, I, T, R> FakePlatform<'a, C, I, T, R>
where
    C: Crypto,
    I: IndexState,
    T: TpmTimer,
    R: Rng,
{
    /// Constructs a new `FakePlatform` from mutable references to hardware providers.
    pub fn new(crypto: &'a mut C, timer: &'a mut T, rng: &'a mut R) -> Self {
        Self {
            crypto,
            timer,
            rng,
            firmware: None,
            secure_channel: None,
            info: crate::Info::DEFAULT,
            index: PhantomData,
        }
    }

    /// Gives the TPM the firmware identity `firmware`, enabling the firmware-limited and
    /// SVN-limited hierarchies (see [`crate::Platform::firmware`]).
    pub fn with_firmware(mut self, firmware: &'a (dyn TpmFirmware + Sync)) -> Self {
        self.firmware = Some(firmware);
        self
    }

    /// Gives the TPM the secure transport layer `secure_channel` (see
    /// [`crate::Platform::secure_channel`]).
    pub fn with_secure_channel(mut self, secure_channel: &'a (dyn SecureChannel + Sync)) -> Self {
        self.secure_channel = Some(secure_channel);
        self
    }

    /// Gives the TPM the platform information `info` (see [`crate::Platform::info`]).
    pub fn with_info(mut self, info: crate::Info) -> Self {
        self.info = info;
        self
    }
}

impl<C, I, T, R> crate::Platform for FakePlatform<'_, C, I, T, R>
where
    C: Crypto,
    I: IndexState,
    T: TpmTimer,
    R: Rng + Sync,
{
    type Crypto = C;
    type Timer = T;
    type Rng = R;
    type IndexState = I;

    fn info(&self) -> &crate::Info {
        &self.info
    }

    fn timer(&self) -> &T {
        self.timer
    }

    fn rng(&mut self) -> &mut R {
        self.rng
    }

    fn firmware(&self) -> Option<&(dyn TpmFirmware + Sync)> {
        self.firmware
    }

    fn secure_channel(&self) -> Option<&(dyn SecureChannel + Sync)> {
        self.secure_channel
    }
}

use crate::storage::IndexState;
use core::marker::PhantomData;
use tpm2::platform::{SecureChannel, TpmFirmware};
