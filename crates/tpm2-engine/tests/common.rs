#![allow(dead_code, unused_imports)]

extern crate alloc;
extern crate std;

use alloc::vec::Vec;
use tpm2::crypto::backend::{
    CmacState, EccCurve, HashState, HmacState, PrivateKey, RsaKey, SymmetricState, default_crypt,
};
use tpm2::crypto::{Block, CipherInput, CryptoError, Direction, Random, Rng};
use tpm2::{Handle, TpmSe};
use tpm2::{Tpm2bNonce, TpmiAlgHash};
use tpm2_engine::handler::SessionState;
use tpm2_engine::storage::{NvStorage, StorageError};
use tpm2_engine::timer::TpmTimer;

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
    session_key_slice: &[u8],
    symmetric: Option<tpm2::TpmtSymDef>,
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
        bound_entity: Default::default(),
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

/// A deterministic platform RNG ([`Rng`]): fills buffers with an incrementing (wrapping) byte
/// counter that starts at 1 and continues across calls.
///
/// [`TpmPlatform`](tpm2_engine::TpmPlatform) borrows its RNG mutably, so pass `&mut rng`. A
/// `FakeRng` that is reused for several engines one after the other keeps counting where the
/// previous engine stopped. It is also the RNG of [`FakeCrypto`] (a separate instance per
/// [`Random::from_entropy`] call).
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

/// An RNG that fills every buffer with the octet `B` (and ignores stirred data).
#[derive(Default)]
pub struct ConstRng<const B: u8>;

impl<const B: u8> Rng for ConstRng<B> {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), CryptoError> {
        dest.fill(B);
        Ok(())
    }

    fn stir_bytes(&mut self, _data: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

/// The fake crypto backend of most white-box tests (see [`impl_fake_crypto!`]), with
/// [`FakeRng`] as its RNG.
pub struct FakeCrypto;

/// A fake hash: XOR-folds the data into the output.
#[derive(Default)]
pub struct FakeHashCtx(pub Vec<u8>);

impl<const N: usize> HashState<N> for FakeHashCtx {
    fn init() -> Result<Self, CryptoError> {
        Ok(Self::default())
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.extend_from_slice(data);
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        *out = [0u8; N];
        for (i, &b) in self.0.iter().enumerate() {
            out[i % N] ^= b;
        }
        Ok(())
    }
}

/// A fake HMAC (also used as the fake CMAC): XOR-folds the key and the data into the output and
/// mixes in their total length.
pub struct FakeHmacCtx(pub Vec<u8>);

impl FakeHmacCtx {
    fn fold<const N: usize>(&self, out: &mut [u8; N]) {
        *out = [0u8; N];
        for (i, &b) in self.0.iter().enumerate() {
            out[i % N] ^= b;
        }
        out[1] ^= self.0.len() as u8;
    }
}

impl<const N: usize> HmacState<N> for FakeHmacCtx {
    fn init(key: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self(key.to_vec()))
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.extend_from_slice(data);
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        self.fold(out);
        Ok(())
    }
}

impl<const K: usize> CmacState<K> for FakeHmacCtx {
    fn init(key: &[u8; K]) -> Result<Self, CryptoError> {
        Ok(Self(key.to_vec()))
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.extend_from_slice(data);
        Ok(())
    }

    fn finalize(&mut self, out: &mut Block) -> Result<(), CryptoError> {
        self.fold(out);
        Ok(())
    }
}

/// The fake symmetric cipher (AES), for both directions and every mode: XORs the data with the
/// repeated key and the repeated IV (all zeros for ECB, which has no IV). The IV is left
/// unchanged (also after a partial final CFB block), so the chaining value returned (`ivOut`)
/// equals the IV passed in.
pub struct FakeSym<const K: usize>([u8; K]);

impl<const K: usize> FakeSym<K> {
    fn xor(&self, iv: &Block, data: &mut [u8]) -> Result<(), CryptoError> {
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= self.0[i % K] ^ iv[i % 16];
        }
        Ok(())
    }
}

impl<const K: usize> SymmetricState<K> for FakeSym<K> {
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

/// The fake signature of `digest` in `out`: `0x5a` octets XORed with the digest folded into
/// `out`.
fn fake_signature(digest: &[u8], out: &mut [u8]) {
    out.fill(0x5a);
    let len = out.len();
    for (i, &b) in digest.iter().enumerate() {
        out[i % len] ^= b;
    }
}

/// A fake RSA public key: the modulus and the exponent, accepted as they are.
#[derive(Clone)]
pub struct FakeRsaPublic<const M: usize> {
    pub n: [u8; M],
    pub e: u32,
}

/// A fake RSA private key: every modulus/prime pair is accepted.
///
/// * Generated keys have the modulus `0xcc..` and the prime `0xdd..`.
/// * `TPM_ALG_NULL` and RSAES encryption copy the message, left-aligned and zero padded to the
///   modulus size; OAEP encryption does the same, and OAEP decryption returns the first
///   32 octets (at most) of the ciphertext, i.e. a message of up to 32 octets (a seed) round
///   trips. The other decryptions copy the whole ciphertext.
/// * Signatures (RSASSA, RSAPSS) are [`fake_signature`]s of the modulus size; verification
///   accepts exactly those.
pub struct FakeRsaKey<const M: usize, const P: usize> {
    public: FakeRsaPublic<M>,
    pub p: [u8; P],
}

fn fake_rsa_pad<const M: usize>(m: &[u8], out: &mut [u8; M]) -> Result<Option<()>, CryptoError> {
    if m.len() > M {
        return Ok(None);
    }
    out.fill(0);
    out[..m.len()].copy_from_slice(m);
    Ok(Some(()))
}

impl<const M: usize, const P: usize, R: Rng> PrivateKey<M, P, R, u32> for FakeRsaKey<M, P> {
    type PublicKey = FakeRsaPublic<M>;

    fn generate(_rng: &mut R, e: u32) -> Result<Self, CryptoError> {
        Ok(Self {
            public: FakeRsaPublic { n: [0xcc; M], e },
            p: [0xdd; P],
        })
    }
    fn load(public: FakeRsaPublic<M>, p: &[u8; P]) -> Result<Option<Self>, CryptoError> {
        Ok(Some(Self { public, p: *p }))
    }
    fn store(&self, out: &mut [u8; P]) -> Result<(), CryptoError> {
        *out = self.p;
        Ok(())
    }
    fn as_public(&self) -> &FakeRsaPublic<M> {
        &self.public
    }
    fn load_public(e: u32, n: &[u8; M]) -> Result<Option<FakeRsaPublic<M>>, CryptoError> {
        Ok(Some(FakeRsaPublic { n: *n, e }))
    }
    fn store_public(public: &FakeRsaPublic<M>, out: &mut [u8; M]) -> Result<(), CryptoError> {
        *out = public.n;
        Ok(())
    }
}

impl<const M: usize, const P: usize, R: Rng> RsaKey<M, P, R> for FakeRsaKey<M, P> {
    fn exponent(public: &FakeRsaPublic<M>) -> u32 {
        public.e
    }
    fn raw_encrypt(
        _public: &FakeRsaPublic<M>,
        m: &[u8; M],
        out: &mut [u8; M],
    ) -> Result<Option<()>, CryptoError> {
        *out = *m;
        Ok(Some(()))
    }
    fn raw_decrypt(
        &self,
        _rng: &mut R,
        c: &[u8; M],
        out: &mut [u8; M],
    ) -> Result<Option<()>, CryptoError> {
        *out = *c;
        Ok(Some(()))
    }
    fn oaep_encrypt(
        _public: &FakeRsaPublic<M>,
        _rng: &mut R,
        _hash: TpmiAlgHash,
        _label: &[u8],
        m: &[u8],
        out: &mut [u8; M],
    ) -> Result<Option<()>, CryptoError> {
        fake_rsa_pad(m, out)
    }
    fn oaep_decrypt(
        &self,
        _rng: &mut R,
        _hash: TpmiAlgHash,
        _label: &[u8],
        c: &[u8; M],
        out: &mut [u8; M],
    ) -> Result<Option<usize>, CryptoError> {
        let len = M.min(32);
        out[..len].copy_from_slice(&c[..len]);
        Ok(Some(len))
    }
    fn rsaes_encrypt(
        _public: &FakeRsaPublic<M>,
        _rng: &mut R,
        m: &[u8],
        out: &mut [u8; M],
    ) -> Result<Option<()>, CryptoError> {
        fake_rsa_pad(m, out)
    }
    fn rsaes_decrypt(
        &self,
        _rng: &mut R,
        c: &[u8; M],
        out: &mut [u8; M],
    ) -> Result<Option<usize>, CryptoError> {
        *out = *c;
        Ok(Some(M))
    }
    fn rsassa_sign(
        &self,
        _rng: &mut R,
        digest: tpm2::TpmtHa<'_>,
        out: &mut [u8; M],
    ) -> Result<(), CryptoError> {
        fake_signature(digest.digest(), out);
        Ok(())
    }
    fn rsassa_verify(
        _public: &FakeRsaPublic<M>,
        digest: tpm2::TpmtHa<'_>,
        sig: &[u8; M],
    ) -> Result<bool, CryptoError> {
        let mut expected = [0u8; M];
        fake_signature(digest.digest(), &mut expected);
        Ok(*sig == expected)
    }
    fn rsapss_sign(
        &self,
        rng: &mut R,
        digest: tpm2::TpmtHa<'_>,
        out: &mut [u8; M],
    ) -> Result<(), CryptoError> {
        <Self as RsaKey<M, P, R>>::rsassa_sign(self, rng, digest, out)
    }
    fn rsapss_verify(
        public: &FakeRsaPublic<M>,
        digest: tpm2::TpmtHa<'_>,
        sig: &[u8; M],
    ) -> Result<bool, CryptoError> {
        <Self as RsaKey<M, P, R>>::rsassa_verify(public, digest, sig)
    }
}

/// A fake ECC public key: the point `x || y`, accepted as it is.
#[derive(Clone)]
pub struct FakeEccPublic<const P: usize>(pub [u8; P]);

/// A fake ECC private key on a short-Weierstrass curve: every point and scalar is accepted.
///
/// * Generated keys have the point `0xcc..` and the scalar `0xdd..`.
/// * ECDH and the point multiplications report success without writing any output.
/// * ECDSA signatures are [`fake_signature`]s of `r || s`; verification accepts exactly those.
pub struct FakeEccKey<const C: usize, const P: usize> {
    public: FakeEccPublic<P>,
    pub d: [u8; C],
}

impl<const C: usize, const P: usize, R: Rng> PrivateKey<P, C, R> for FakeEccKey<C, P> {
    type PublicKey = FakeEccPublic<P>;

    fn generate(_rng: &mut R, _params: ()) -> Result<Self, CryptoError> {
        Ok(Self {
            public: FakeEccPublic([0xcc; P]),
            d: [0xdd; C],
        })
    }
    fn load(public: FakeEccPublic<P>, d: &[u8; C]) -> Result<Option<Self>, CryptoError> {
        Ok(Some(Self { public, d: *d }))
    }
    fn store(&self, out: &mut [u8; C]) -> Result<(), CryptoError> {
        *out = self.d;
        Ok(())
    }
    fn as_public(&self) -> &FakeEccPublic<P> {
        &self.public
    }
    fn load_public(_params: (), point: &[u8; P]) -> Result<Option<FakeEccPublic<P>>, CryptoError> {
        Ok(Some(FakeEccPublic(*point)))
    }
    fn store_public(public: &FakeEccPublic<P>, out: &mut [u8; P]) -> Result<(), CryptoError> {
        *out = public.0;
        Ok(())
    }
}

impl<const C: usize, const P: usize, R: Rng> EccCurve<C, P, R> for FakeEccKey<C, P> {
    fn ecdh(
        &self,
        _peer_public: &FakeEccPublic<P>,
        _out_x: &mut [u8; C],
        _out_y: &mut [u8; C],
    ) -> Result<Option<()>, CryptoError> {
        Ok(Some(()))
    }
    fn sign(
        &self,
        _rng: &mut R,
        digest: &[u8],
        out_r: &mut [u8; C],
        out_s: &mut [u8; C],
    ) -> Result<(), CryptoError> {
        let mut sig = [0u8; P];
        fake_signature(digest, &mut sig);
        out_r.copy_from_slice(&sig[..C]);
        out_s.copy_from_slice(&sig[C..]);
        Ok(())
    }
    fn verify(
        _public: &FakeEccPublic<P>,
        digest: &[u8],
        sig_r: &[u8; C],
        sig_s: &[u8; C],
    ) -> Result<bool, CryptoError> {
        let mut expected = [0u8; P];
        fake_signature(digest, &mut expected);
        Ok(expected[..C] == sig_r[..] && expected[C..] == sig_s[..])
    }
    fn mul_generator(
        _k: &[u8; C],
        _out_x: &mut [u8; C],
        _out_y: &mut [u8; C],
    ) -> Result<Option<()>, CryptoError> {
        Ok(Some(()))
    }
    fn mul_point(
        _point: &FakeEccPublic<P>,
        _k: &[u8; C],
        _out_x: &mut [u8; C],
        _out_y: &mut [u8; C],
    ) -> Result<Option<()>, CryptoError> {
        Ok(Some(()))
    }
}

/// Implements a fake crypto backend for `$t` with the RNG `$rng` (`Default + Rng`; both
/// [`Random::from_entropy`] and [`Random::from_seed`] return `<$rng>::default()`), where `$m`
/// names this module at the invocation site (`common` at a test crate root, `self` here):
/// [`Hash`] ([`FakeHashCtx`]), [`Hmac`] and [`Cmac`] ([`FakeHmacCtx`]), [`Symmetric`] (AES only,
/// [`FakeSym`]), [`Rsa`] ([`FakeRsaKey`]), [`Ecc`] (the short-Weierstrass curves,
/// [`FakeEccKey`]), no ML-DSA/ML-KEM, and [`Crypto`] (`KNOWN_ANSWER_TESTS = false`: the fake
/// algorithms fail the known-answer self tests).
#[macro_export]
macro_rules! impl_fake_crypto {
    ($m:ident, $t:ty, $rng:ty) => {
        impl tpm2::crypto::backend::Hash for $t {
            type Sha1 = $m::FakeHashCtx;
            type Sha256 = $m::FakeHashCtx;
            type Sha384 = $m::FakeHashCtx;
            type Sha512 = $m::FakeHashCtx;
            type Sm3_256 = $m::FakeHashCtx;
            type Sha3_256 = $m::FakeHashCtx;
            type Sha3_384 = $m::FakeHashCtx;
            type Sha3_512 = $m::FakeHashCtx;
        }
        impl tpm2::crypto::backend::Hmac for $t {
            type Sha1 = $m::FakeHmacCtx;
            type Sha256 = $m::FakeHmacCtx;
            type Sha384 = $m::FakeHmacCtx;
            type Sha512 = $m::FakeHmacCtx;
            type Sm3_256 = $m::FakeHmacCtx;
            type Sha3_256 = $m::FakeHmacCtx;
            type Sha3_384 = $m::FakeHmacCtx;
            type Sha3_512 = $m::FakeHmacCtx;
        }
        impl tpm2::crypto::backend::Cmac for $t {
            type Aes128 = $m::FakeHmacCtx;
            type Aes192 = $m::FakeHmacCtx;
            type Aes256 = $m::FakeHmacCtx;
            type Sm4_128 = $m::FakeHmacCtx;
            type Camellia128 = $m::FakeHmacCtx;
            type Camellia192 = $m::FakeHmacCtx;
            type Camellia256 = $m::FakeHmacCtx;
        }
        impl tpm2::crypto::backend::Symmetric for $t {
            type Aes128 = $m::FakeSym<16>;
            type Aes192 = $m::FakeSym<24>;
            type Aes256 = $m::FakeSym<32>;
            type Sm4_128 = !;
            type Camellia128 = !;
            type Camellia192 = !;
            type Camellia256 = !;
        }
        impl tpm2::crypto::backend::Rsa for $t {
            type Rsa1024 = $m::FakeRsaKey<128, 64>;
            type Rsa2048 = $m::FakeRsaKey<256, 128>;
            type Rsa3072 = $m::FakeRsaKey<384, 192>;
            type Rsa4096 = $m::FakeRsaKey<512, 256>;
        }
        impl tpm2::crypto::backend::Ecc for $t {
            type NistP192 = $m::FakeEccKey<24, 48>;
            type NistP224 = $m::FakeEccKey<28, 56>;
            type NistP256 = $m::FakeEccKey<32, 64>;
            type NistP384 = $m::FakeEccKey<48, 96>;
            type NistP521 = $m::FakeEccKey<66, 132>;
            type BNP256 = $m::FakeEccKey<32, 64>;
            type BNP638 = $m::FakeEccKey<80, 160>;
            type SM2P256 = $m::FakeEccKey<32, 64>;
            type BpP256R1 = $m::FakeEccKey<32, 64>;
            type BpP384R1 = $m::FakeEccKey<48, 96>;
            type BpP512R1 = $m::FakeEccKey<64, 128>;
            type Ed25519 = !;
            type Ed448 = !;
            type X25519 = !;
            type X448 = !;
        }
        impl tpm2::crypto::backend::Mldsa for $t {
            type Mldsa44 = !;
            type Mldsa65 = !;
            type Mldsa87 = !;
        }
        impl tpm2::crypto::backend::Mlkem for $t {
            type Mlkem512 = !;
            type Mlkem768 = !;
            type Mlkem1024 = !;
        }
        impl tpm2::crypto::Random for $t {
            type Rng = $rng;

            fn from_entropy() -> Result<$rng, tpm2::crypto::CryptoError> {
                Ok(<$rng>::default())
            }
            fn from_seed(_seed: &[u8]) -> Result<$rng, tpm2::crypto::CryptoError> {
                Ok(<$rng>::default())
            }
        }
        impl tpm2::crypto::Crypto for $t {
            /// Its algorithms are fakes, which fail the known-answer self tests.
            const KNOWN_ANSWER_TESTS: bool = false;

            fn ct_eq(a: &[u8], b: &[u8]) -> bool {
                a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
            }
        }
    };
}

impl_fake_crypto!(self, FakeCrypto, FakeRng);

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

/// A [`tpm2_engine::TpmEngine`] backed by the real test crypto backend and the
/// fake storage/timer/RNG.
pub type RealCryptoEngine<'a> = tpm2_engine::TpmEngine<
    tpm2_engine::TpmPlatform<'a, TestCryptoProvider, &'a mut FakeStorage, FakeTimer, FakeRng>,
>;

/// Builds a [`RealCryptoEngine`] plus its [`tpm2_engine::State`] and runs
/// `TPM2_Startup(TPM_SU_CLEAR)`, so white-box tests can drive real commands
/// while still being able to inspect and modify the internal state.
pub fn setup_real_crypto_tpm<'a>(
    crypto: &'a mut TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a mut FakeRng,
) -> RealCryptoEngine<'a> {
    let platform = tpm2_engine::TpmPlatform::new(crypto, timer, rng);
    let mut tpm = tpm2_engine::TpmEngine::new(platform, storage).unwrap();
    tpm.init_storage();
    tpm.state.nv_available = true;
    tpm.state.locality = 0;
    tpm.state.g_nv_ok = true;

    let startup = [0x80, 0x01, 0, 0, 0, 0x0c, 0, 0, 0x01, 0x44, 0, 0];
    let mut rsp = [0u8; 256];
    tpm.execute_command_separate(&startup, &mut rsp);
    assert_eq!(&rsp[6..10], &[0, 0, 0, 0], "TPM2_Startup failed");
    tpm
}

/// Marshals `auths` back to back (the authorization area, without its size).
///
/// This is a separate, non-generic function so that the generic bounds of
/// [`execute_command`] do not interfere with resolving the bounds of
/// [`marshal_to_slice`] for [`tpm2::TpmsAuthCommand`].
fn marshal_auth_area(auths: &[tpm2::TpmsAuthCommand]) -> Vec<u8> {
    let mut buf = [0u8; 8192];
    let mut area = Vec::new();
    for auth in auths {
        let len = marshal_to_slice(auth, &mut buf);
        area.extend_from_slice(&buf[..len]);
    }
    area
}

/// Marshals `cmd` (its handle area, the given authorization area, then its
/// parameters), executes it on `tpm`, and unmarshals the response (its handle
/// area, then its parameters, ignoring any response auth area).
///
/// The command carries its handles and the returned response carries its
/// response handles (e.g. `rsp.object_handle`).
///
/// Returns the raw response code on failure.
pub fn execute_command<C: tpm2::commands::Command>(
    tpm: &mut RealCryptoEngine<'_>,
    cmd: &C,
    auths: &[tpm2::TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as tpm2::Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    use tpm2::Unmarshal;
    use tpm2::commands::{Message, UnmarshalMessage};

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
    for handle in cmd.handles().as_ref() {
        req.extend_from_slice(&handle.0.to_be_bytes());
    }
    if !auths.is_empty() {
        let area = marshal_auth_area(auths);
        req.extend_from_slice(&(area.len() as u32).to_be_bytes());
        req.extend_from_slice(&area);
    }
    let mut buf = [0u8; 8192];
    let len = marshal_to_slice(cmd, &mut buf);
    req.extend_from_slice(&buf[..len]);
    let size = req.len() as u32;
    req[2..6].copy_from_slice(&size.to_be_bytes());

    let mut rsp = [0u8; 8192];
    let rsp_len = tpm.execute_command_separate(&req, &mut rsp);
    let rc = u32::from_be_bytes(rsp[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }
    let body: &'static [u8] = Vec::leak(rsp[10..rsp_len].to_vec());
    let mut slice = body;
    let mut resp_handles = <C::Response<'static> as Message>::Handles::default();
    for handle in resp_handles.as_mut() {
        *handle = Handle::unmarshal(&mut slice).expect("response handles");
    }
    if rsp[0..2] == 0x8002u16.to_be_bytes() {
        let _param_size = u32::unmarshal(&mut slice).expect("parameterSize");
    }
    let resp = <C::Response<'static>>::unmarshal_with_handles(resp_handles, &mut slice)
        .expect("response parameters");
    Ok(resp)
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

/// The context integrity hash of the engine (`CONTEXT_INTEGRITY_HASH_ALG`): the strongest
/// implemented hash (SHA-512, or SHA-384 without it), or SHA-256 with `context-hash-sha256`.
#[allow(dead_code)]
pub fn context_integrity_hash_alg() -> tpm2::TpmiAlgHash {
    if cfg!(feature = "context-hash-sha256") {
        tpm2::TpmiAlgHash::Sha256
    } else {
        tpm2::TpmiAlgHash::try_from(tpm2::Alg::SHA512).unwrap_or(tpm2::TpmiAlgHash::Sha384)
    }
}

/// A [`tpm2_engine::Platform`] over the fake components whose NV data structure is an owned
/// [`FakeStorage`], for tests of a standalone [`TestState`].
#[allow(dead_code)]
pub type TestPlatform =
    tpm2_engine::TpmPlatform<'static, FakeCrypto, FakeStorage, FakeTimer, FakeRng>;

/// A standalone TPM state ([`tpm2_engine::State`]) over [`TestPlatform`]; its
/// [`Default`](tpm2_engine::State::default) has a fresh [`FakeStorage`].
#[allow(dead_code)]
pub type TestState = tpm2_engine::State<TestPlatform>;
