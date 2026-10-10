//! Shared fixtures for the `tpm2-impl` integration tests.
//!
//! None of the fakes are cryptographically meaningful. They let the tests drive a
//! [`TpmEngine`](tpm2_impl::TpmEngine) deterministically:
//! - [`FakeCrypto`]: XOR-fold "hashes", "HMACs" and "CMACs", an XOR "cipher" for AES, and the
//!   counter-based [`FakeRng`]. Every other algorithm reports [`CryptoError::Unsupported`].
//! - [`FakeStorage`]: an in-memory [`NvStorage`] that can be made to fail on write.
//! - [`FakeTimer`]: a [`TpmTimer`] reading a thread-local value.
//!
//! [`TestCryptoProvider`] is the real backend ([`tpm2_rustcrypto::RustCrypto`]).
//!
//! PORTING: exp selected `TestCryptoProvider` from three crypto crates with the
//! `dev_crypto_{rust,crux,bssl}` features. The workspace now has a single backend, so the features
//! and their `compile_error!` guards are gone. The `impl_fake_hash!` and `impl_delegate_hash!`
//! macros were not ported: they implement the old context-based crypto traits and the core tests
//! do not use them. exp's fake asymmetric operations (`AsymmetricSign`, `Asymmetric` and the `Ecc`
//! point arithmetic) have no equivalent in the key-typed `Rsa`/`Ecc`/`Signing` traits, so
//! [`FakeCrypto`] reports them as unsupported.
#![allow(dead_code, unused_imports)]

use std::cell::Cell;
use std::vec::Vec;

use tpm2::crypto::{
    Cmac, ConstantTimeEq, CryptoError, Direction, Ecc, Finalize, Hash, Hmac, Mldsa, Mlkem, ModeIv,
    Random, Rng, Rsa, Signing, Symmetric, Update,
};
use tpm2::{Handle, Tpm2bNonce, TpmSe, TpmiAlgHash, TpmtSymDef};
use tpm2_impl::handler::SessionState;
use tpm2_impl::owned::OwnedName;
use tpm2_impl::storage::{NvStorage, StorageError};
use tpm2_impl::timer::TpmTimer;

pub use tpm2_rustcrypto::RustCrypto as TestCryptoProvider;

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
///
/// PORTING: exp kept the counter in a `Mutex` because the old `Rng::get_random` took `&self`.
/// [`Rng::fill_bytes`] takes `&mut self`, and the engine owns its RNG
/// ([`TpmPlatform::rng`](tpm2_impl::TpmPlatform::rng)).
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

/// Fake hash context: XOR-folds all input into the output. Deterministic, but NOT a hash.
pub struct FakeHashCtx(pub Vec<u8>);

impl Update for FakeHashCtx {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.extend_from_slice(data);
        Ok(())
    }
}

impl<const N: usize> Finalize<N> for FakeHashCtx {
    fn finalize(self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        out.fill(0);
        for (i, &b) in self.0.iter().enumerate() {
            out[i % N] ^= b;
        }
        Ok(())
    }
}

/// Fake HMAC and CMAC context: XOR-folds the key and all input into the output and mixes in the
/// total length. Deterministic, but NOT a MAC.
pub struct FakeHmacCtx(pub Vec<u8>);

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

/// Fake XOR "cipher": `data[i] ^= key[i % key.len()] ^ iv[i % 16]` (a zero IV for ECB).
///
/// Encryption and decryption are the same operation, and the IV is NOT updated.
///
/// PORTING: replaces exp's `FakeSymmetricCtx`; the new [`Symmetric`] trait is one-shot.
fn fake_xor_cipher(key: &[u8], mode: ModeIv<'_>, data: &mut [u8]) {
    let iv = match mode {
        ModeIv::Ctr(iv) | ModeIv::Ofb(iv) | ModeIv::Cbc(iv) | ModeIv::Cfb(iv) => *iv,
        ModeIv::Ecb => [0; 16],
    };
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[i % key.len()] ^ iv[i % iv.len()];
    }
}

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
    type Sha1Context = FakeHashCtx;
    fn sha1(&self) -> Result<Self::Sha1Context, CryptoError> {
        Ok(FakeHashCtx(Vec::new()))
    }
    type Sha256Context = FakeHashCtx;
    fn sha256(&self) -> Result<Self::Sha256Context, CryptoError> {
        Ok(FakeHashCtx(Vec::new()))
    }
    type Sha384Context = FakeHashCtx;
    fn sha384(&self) -> Result<Self::Sha384Context, CryptoError> {
        Ok(FakeHashCtx(Vec::new()))
    }
    type Sha512Context = FakeHashCtx;
    fn sha512(&self) -> Result<Self::Sha512Context, CryptoError> {
        Ok(FakeHashCtx(Vec::new()))
    }
    type Sm3_256Context = FakeHashCtx;
    fn sm3_256(&self) -> Result<Self::Sm3_256Context, CryptoError> {
        Ok(FakeHashCtx(Vec::new()))
    }
    type Sha3_256Context = FakeHashCtx;
    fn sha3_256(&self) -> Result<Self::Sha3_256Context, CryptoError> {
        Ok(FakeHashCtx(Vec::new()))
    }
    type Sha3_384Context = FakeHashCtx;
    fn sha3_384(&self) -> Result<Self::Sha3_384Context, CryptoError> {
        Ok(FakeHashCtx(Vec::new()))
    }
    type Sha3_512Context = FakeHashCtx;
    fn sha3_512(&self) -> Result<Self::Sha3_512Context, CryptoError> {
        Ok(FakeHashCtx(Vec::new()))
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
    type Sm3_256Context = FakeHmacCtx;
    fn sm3_256(&self, key: &[u8]) -> Result<Self::Sm3_256Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    type Sha3_256Context = FakeHmacCtx;
    fn sha3_256(&self, key: &[u8]) -> Result<Self::Sha3_256Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    type Sha3_384Context = FakeHmacCtx;
    fn sha3_384(&self, key: &[u8]) -> Result<Self::Sha3_384Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    type Sha3_512Context = FakeHmacCtx;
    fn sha3_512(&self, key: &[u8]) -> Result<Self::Sha3_512Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
}

impl Cmac for FakeCrypto {
    type Aes128Context = FakeHmacCtx;
    fn aes128(&self, key: &[u8; 16]) -> Result<Self::Aes128Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    type Aes192Context = FakeHmacCtx;
    fn aes192(&self, key: &[u8; 24]) -> Result<Self::Aes192Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    type Aes256Context = FakeHmacCtx;
    fn aes256(&self, key: &[u8; 32]) -> Result<Self::Aes256Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    type Sm4_128Context = FakeHmacCtx;
    fn sm4_128(&self, key: &[u8; 16]) -> Result<Self::Sm4_128Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    type Camellia128Context = FakeHmacCtx;
    fn camellia128(&self, key: &[u8; 16]) -> Result<Self::Camellia128Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    type Camellia192Context = FakeHmacCtx;
    fn camellia192(&self, key: &[u8; 24]) -> Result<Self::Camellia192Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    type Camellia256Context = FakeHmacCtx;
    fn camellia256(&self, key: &[u8; 32]) -> Result<Self::Camellia256Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
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

std::thread_local! {
    static FAKE_TIMER_VAL: Cell<u64> = const { Cell::new(0) };
}

/// [`TpmTimer`] reading a thread-local value, so a test can move time while the engine holds the
/// timer.
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

/// Marshals `item` into the front of `buf` and returns the number of bytes written.
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
