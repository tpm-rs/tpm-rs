#![allow(dead_code, unused_imports)]

extern crate alloc;
extern crate std;

use alloc::vec::Vec;
use tpm2::Alg;
use tpm2::crypto::{Asymmetric, AsymmetricSign, Cmac, ConstantTimeEq, Random, Rng, Symmetric};
use tpm2::crypto::{CryptoError, CryptoProvider, Direction, ModeIv};
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

/// A deterministic platform RNG ([`Rng`]): fills buffers with an incrementing (wrapping) byte
/// counter that starts at 1 and continues across calls.
///
/// [`TpmPlatform`](tpm2_impl::TpmPlatform) borrows its RNG mutably, so pass `&mut rng`. A
/// `FakeRng` that is reused for several engines one after the other keeps counting where the
/// previous engine stopped.
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

    /// Ignores `data` (like the default `stir_random` of the previous `Rng` trait).
    fn reseed(&mut self, _data: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

pub struct FakeCrypto;

/// A fake hash: XOR-folds the data into the output.
#[derive(Default)]
pub struct FakeHashCtx(pub Vec<u8>);

impl tpm2::crypto::Update for FakeHashCtx {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.extend_from_slice(data);
        Ok(())
    }
}

impl<const N: usize> tpm2::crypto::Finalize<N> for FakeHashCtx {
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

/// A fake HMAC (also used as the fake CMAC): XOR-folds the key and the data into the output and
/// mixes in their total length.
pub struct FakeHmacCtx(pub Vec<u8>);

impl tpm2::crypto::Update for FakeHmacCtx {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.extend_from_slice(data);
        Ok(())
    }
}

impl<const N: usize> tpm2::crypto::Finalize<N> for FakeHmacCtx {
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

/// The fake symmetric cipher, for both directions and every mode: XORs `data` with the repeated
/// key and the repeated IV (all zeros for ECB, which has no IV). The IV is left unchanged, so the
/// chaining value returned (`ivOut`) equals the IV passed in.
pub fn fake_sym_xor(key: &[u8], mode: ModeIv<'_>, data: &mut [u8]) -> Result<(), CryptoError> {
    let iv = match mode {
        ModeIv::Ctr(iv) | ModeIv::Ofb(iv) | ModeIv::Cbc(iv) | ModeIv::Cfb(iv) => *iv,
        ModeIv::Ecb => [0u8; 16],
    };
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[i % key.len()] ^ iv[i % 16];
    }
    Ok(())
}

/// Implements the fake [`Hash`](tpm2::crypto::Hash) ([`FakeHashCtx`]),
/// [`Hmac`](tpm2::crypto::Hmac) and [`Cmac`] ([`FakeHmacCtx`]), [`Symmetric`] (AES only, via
/// [`fake_sym_xor`]), [`Ecc`](tpm2::crypto::Ecc) (accepts every point and reports success
/// without writing any output), [`ConstantTimeEq`] and [`Random`] (no RNG factory) for `$t`.
///
/// The caller still implements [`Asymmetric`], [`AsymmetricSign`] and [`CryptoProvider`] (with
/// its `get_random`). Invoke it at the crate root, after `mod common;`.
#[macro_export]
macro_rules! impl_fake_hash {
    ($t:ty) => {
        impl tpm2::crypto::Hash for $t {
            type Sha1Context = common::FakeHashCtx;
            type Sha256Context = common::FakeHashCtx;
            type Sha384Context = common::FakeHashCtx;
            type Sha512Context = common::FakeHashCtx;
            type Sm3_256Context = common::FakeHashCtx;
            type Sha3_256Context = common::FakeHashCtx;
            type Sha3_384Context = common::FakeHashCtx;
            type Sha3_512Context = common::FakeHashCtx;

            fn sha1(&self) -> Result<Self::Sha1Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHashCtx::default())
            }
            fn sha256(&self) -> Result<Self::Sha256Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHashCtx::default())
            }
            fn sha384(&self) -> Result<Self::Sha384Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHashCtx::default())
            }
            fn sha512(&self) -> Result<Self::Sha512Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHashCtx::default())
            }
            fn sm3_256(&self) -> Result<Self::Sm3_256Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHashCtx::default())
            }
            fn sha3_256(&self) -> Result<Self::Sha3_256Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHashCtx::default())
            }
            fn sha3_384(&self) -> Result<Self::Sha3_384Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHashCtx::default())
            }
            fn sha3_512(&self) -> Result<Self::Sha3_512Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHashCtx::default())
            }
        }
        impl tpm2::crypto::Hmac for $t {
            type Sha1Context = common::FakeHmacCtx;
            type Sha256Context = common::FakeHmacCtx;
            type Sha384Context = common::FakeHmacCtx;
            type Sha512Context = common::FakeHmacCtx;
            type Sm3_256Context = common::FakeHmacCtx;
            type Sha3_256Context = common::FakeHmacCtx;
            type Sha3_384Context = common::FakeHmacCtx;
            type Sha3_512Context = common::FakeHmacCtx;

            fn sha1(&self, key: &[u8]) -> Result<Self::Sha1Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn sha256(&self, key: &[u8]) -> Result<Self::Sha256Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn sha384(&self, key: &[u8]) -> Result<Self::Sha384Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn sha512(&self, key: &[u8]) -> Result<Self::Sha512Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn sm3_256(
                &self,
                key: &[u8],
            ) -> Result<Self::Sm3_256Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn sha3_256(
                &self,
                key: &[u8],
            ) -> Result<Self::Sha3_256Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn sha3_384(
                &self,
                key: &[u8],
            ) -> Result<Self::Sha3_384Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn sha3_512(
                &self,
                key: &[u8],
            ) -> Result<Self::Sha3_512Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
        }
        impl tpm2::crypto::Cmac for $t {
            type Aes128Context = common::FakeHmacCtx;
            type Aes192Context = common::FakeHmacCtx;
            type Aes256Context = common::FakeHmacCtx;
            type Sm4_128Context = common::FakeHmacCtx;
            type Camellia128Context = common::FakeHmacCtx;
            type Camellia192Context = common::FakeHmacCtx;
            type Camellia256Context = common::FakeHmacCtx;

            fn aes128(
                &self,
                key: &[u8; 16],
            ) -> Result<Self::Aes128Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn aes192(
                &self,
                key: &[u8; 24],
            ) -> Result<Self::Aes192Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn aes256(
                &self,
                key: &[u8; 32],
            ) -> Result<Self::Aes256Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn sm4_128(
                &self,
                key: &[u8; 16],
            ) -> Result<Self::Sm4_128Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn camellia128(
                &self,
                key: &[u8; 16],
            ) -> Result<Self::Camellia128Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn camellia192(
                &self,
                key: &[u8; 24],
            ) -> Result<Self::Camellia192Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
            fn camellia256(
                &self,
                key: &[u8; 32],
            ) -> Result<Self::Camellia256Context, tpm2::crypto::CryptoError> {
                Ok(common::FakeHmacCtx(key.to_vec()))
            }
        }
        impl tpm2::crypto::Ecc for $t {
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
            ) -> Result<bool, tpm2::crypto::CryptoError> {
                Ok(true)
            }
            fn point_multiply_generator(
                &self,
                _curve: tpm2::TpmEccCurve,
                _scalar: &[u8],
                public_key_out: &mut [u8],
            ) -> Result<Option<usize>, tpm2::crypto::CryptoError> {
                Ok(Some(public_key_out.len()))
            }
            fn point_multiply(
                &self,
                _curve: tpm2::TpmEccCurve,
                _scalar: &[u8],
                _public_point: &[u8],
                derived_point_out: &mut [u8],
            ) -> Result<Option<usize>, tpm2::crypto::CryptoError> {
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
            ) -> Result<Option<usize>, tpm2::crypto::CryptoError> {
                Ok(Some(s_out.len()))
            }
        }
        impl tpm2::crypto::Symmetric for $t {
            fn aes128(
                &self,
                key: &[u8; 16],
                mode: tpm2::crypto::ModeIv<'_>,
                _dir: tpm2::crypto::Direction,
                data: &mut [u8],
            ) -> Result<(), tpm2::crypto::CryptoError> {
                common::fake_sym_xor(key, mode, data)
            }
            fn aes192(
                &self,
                key: &[u8; 24],
                mode: tpm2::crypto::ModeIv<'_>,
                _dir: tpm2::crypto::Direction,
                data: &mut [u8],
            ) -> Result<(), tpm2::crypto::CryptoError> {
                common::fake_sym_xor(key, mode, data)
            }
            fn aes256(
                &self,
                key: &[u8; 32],
                mode: tpm2::crypto::ModeIv<'_>,
                _dir: tpm2::crypto::Direction,
                data: &mut [u8],
            ) -> Result<(), tpm2::crypto::CryptoError> {
                common::fake_sym_xor(key, mode, data)
            }
        }
        impl tpm2::crypto::ConstantTimeEq for $t {
            fn constant_time_eq<const N: usize>(&self, a: &[u8; N], b: &[u8; N]) -> bool {
                a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
            }
        }
        impl tpm2::crypto::Random for $t {
            type Rng = !;
        }
    };
}

/// Implements [`Hash`](tpm2::crypto::Hash), [`Hmac`](tpm2::crypto::Hmac), [`Cmac`],
/// [`Ecc`](tpm2::crypto::Ecc), [`Symmetric`] (AES only), [`ConstantTimeEq`] and [`Random`] for
/// `$t` by delegating to its [`TestCryptoProvider`] field `$field`.
///
/// The caller still implements [`Asymmetric`], [`AsymmetricSign`] and [`CryptoProvider`] (with
/// its `get_random`). Invoke it at the crate root, after `mod common;`.
#[macro_export]
macro_rules! impl_delegate_hash {
    ($t:ty, $field:ident) => {
        impl tpm2::crypto::Hash for $t {
            type Sha1Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hash>::Sha1Context;
            type Sha256Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hash>::Sha256Context;
            type Sha384Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hash>::Sha384Context;
            type Sha512Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hash>::Sha512Context;
            type Sm3_256Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hash>::Sm3_256Context;
            type Sha3_256Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hash>::Sha3_256Context;
            type Sha3_384Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hash>::Sha3_384Context;
            type Sha3_512Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hash>::Sha3_512Context;

            fn sha1(&self) -> Result<Self::Sha1Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Hash::sha1(&self.$field)
            }
            fn sha256(&self) -> Result<Self::Sha256Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Hash::sha256(&self.$field)
            }
            fn sha384(&self) -> Result<Self::Sha384Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Hash::sha384(&self.$field)
            }
            fn sha512(&self) -> Result<Self::Sha512Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Hash::sha512(&self.$field)
            }
            fn sm3_256(&self) -> Result<Self::Sm3_256Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Hash::sm3_256(&self.$field)
            }
            fn sha3_256(&self) -> Result<Self::Sha3_256Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Hash::sha3_256(&self.$field)
            }
            fn sha3_384(&self) -> Result<Self::Sha3_384Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Hash::sha3_384(&self.$field)
            }
            fn sha3_512(&self) -> Result<Self::Sha3_512Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Hash::sha3_512(&self.$field)
            }
        }
        impl tpm2::crypto::Hmac for $t {
            type Sha1Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hmac>::Sha1Context;
            type Sha256Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hmac>::Sha256Context;
            type Sha384Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hmac>::Sha384Context;
            type Sha512Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hmac>::Sha512Context;
            type Sm3_256Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hmac>::Sm3_256Context;
            type Sha3_256Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hmac>::Sha3_256Context;
            type Sha3_384Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hmac>::Sha3_384Context;
            type Sha3_512Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Hmac>::Sha3_512Context;

            fn sha1(&self, key: &[u8]) -> Result<Self::Sha1Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Hmac::sha1(&self.$field, key)
            }
            fn sha256(&self, key: &[u8]) -> Result<Self::Sha256Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Hmac::sha256(&self.$field, key)
            }
            fn sha384(&self, key: &[u8]) -> Result<Self::Sha384Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Hmac::sha384(&self.$field, key)
            }
            fn sha512(&self, key: &[u8]) -> Result<Self::Sha512Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Hmac::sha512(&self.$field, key)
            }
            fn sm3_256(
                &self,
                key: &[u8],
            ) -> Result<Self::Sm3_256Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Hmac::sm3_256(&self.$field, key)
            }
            fn sha3_256(
                &self,
                key: &[u8],
            ) -> Result<Self::Sha3_256Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Hmac::sha3_256(&self.$field, key)
            }
            fn sha3_384(
                &self,
                key: &[u8],
            ) -> Result<Self::Sha3_384Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Hmac::sha3_384(&self.$field, key)
            }
            fn sha3_512(
                &self,
                key: &[u8],
            ) -> Result<Self::Sha3_512Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Hmac::sha3_512(&self.$field, key)
            }
        }
        impl tpm2::crypto::Cmac for $t {
            type Aes128Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Cmac>::Aes128Context;
            type Aes192Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Cmac>::Aes192Context;
            type Aes256Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Cmac>::Aes256Context;
            type Sm4_128Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Cmac>::Sm4_128Context;
            type Camellia128Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Cmac>::Camellia128Context;
            type Camellia192Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Cmac>::Camellia192Context;
            type Camellia256Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Cmac>::Camellia256Context;

            fn aes128(
                &self,
                key: &[u8; 16],
            ) -> Result<Self::Aes128Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Cmac::aes128(&self.$field, key)
            }
            fn aes192(
                &self,
                key: &[u8; 24],
            ) -> Result<Self::Aes192Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Cmac::aes192(&self.$field, key)
            }
            fn aes256(
                &self,
                key: &[u8; 32],
            ) -> Result<Self::Aes256Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Cmac::aes256(&self.$field, key)
            }
            fn sm4_128(
                &self,
                key: &[u8; 16],
            ) -> Result<Self::Sm4_128Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Cmac::sm4_128(&self.$field, key)
            }
            fn camellia128(
                &self,
                key: &[u8; 16],
            ) -> Result<Self::Camellia128Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Cmac::camellia128(&self.$field, key)
            }
            fn camellia192(
                &self,
                key: &[u8; 24],
            ) -> Result<Self::Camellia192Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Cmac::camellia192(&self.$field, key)
            }
            fn camellia256(
                &self,
                key: &[u8; 32],
            ) -> Result<Self::Camellia256Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Cmac::camellia256(&self.$field, key)
            }
        }
        impl tpm2::crypto::Ecc for $t {
            type NistP192Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::NistP192Context;
            type NistP224Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::NistP224Context;
            type NistP256Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::NistP256Context;
            type NistP384Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::NistP384Context;
            type NistP521Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::NistP521Context;
            type BnP256Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::BnP256Context;
            type BnP638Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::BnP638Context;
            type Sm2P256Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::Sm2P256Context;
            type BpP256R1Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::BpP256R1Context;
            type BpP384R1Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::BpP384R1Context;
            type BpP512R1Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::BpP512R1Context;
            type Curve25519Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::Curve25519Context;
            type Curve448Context =
                <$crate::common::TestCryptoProvider as tpm2::crypto::Ecc>::Curve448Context;

            fn nist_p192(&self) -> Result<Self::NistP192Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Ecc::nist_p192(&self.$field)
            }
            fn nist_p224(&self) -> Result<Self::NistP224Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Ecc::nist_p224(&self.$field)
            }
            fn nist_p256(&self) -> Result<Self::NistP256Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Ecc::nist_p256(&self.$field)
            }
            fn nist_p384(&self) -> Result<Self::NistP384Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Ecc::nist_p384(&self.$field)
            }
            fn nist_p521(&self) -> Result<Self::NistP521Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Ecc::nist_p521(&self.$field)
            }
            fn bn_p256(&self) -> Result<Self::BnP256Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Ecc::bn_p256(&self.$field)
            }
            fn bn_p638(&self) -> Result<Self::BnP638Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Ecc::bn_p638(&self.$field)
            }
            fn sm2_p256(&self) -> Result<Self::Sm2P256Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Ecc::sm2_p256(&self.$field)
            }
            fn bp_p256_r1(&self) -> Result<Self::BpP256R1Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Ecc::bp_p256_r1(&self.$field)
            }
            fn bp_p384_r1(&self) -> Result<Self::BpP384R1Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Ecc::bp_p384_r1(&self.$field)
            }
            fn bp_p512_r1(&self) -> Result<Self::BpP512R1Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Ecc::bp_p512_r1(&self.$field)
            }
            fn curve25519(&self) -> Result<Self::Curve25519Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Ecc::curve25519(&self.$field)
            }
            fn curve448(&self) -> Result<Self::Curve448Context, tpm2::crypto::CryptoError> {
                tpm2::crypto::Ecc::curve448(&self.$field)
            }
        }
        impl tpm2::crypto::Symmetric for $t {
            fn aes128(
                &self,
                key: &[u8; 16],
                mode: tpm2::crypto::ModeIv<'_>,
                dir: tpm2::crypto::Direction,
                data: &mut [u8],
            ) -> Result<(), tpm2::crypto::CryptoError> {
                tpm2::crypto::Symmetric::aes128(&self.$field, key, mode, dir, data)
            }
            fn aes192(
                &self,
                key: &[u8; 24],
                mode: tpm2::crypto::ModeIv<'_>,
                dir: tpm2::crypto::Direction,
                data: &mut [u8],
            ) -> Result<(), tpm2::crypto::CryptoError> {
                tpm2::crypto::Symmetric::aes192(&self.$field, key, mode, dir, data)
            }
            fn aes256(
                &self,
                key: &[u8; 32],
                mode: tpm2::crypto::ModeIv<'_>,
                dir: tpm2::crypto::Direction,
                data: &mut [u8],
            ) -> Result<(), tpm2::crypto::CryptoError> {
                tpm2::crypto::Symmetric::aes256(&self.$field, key, mode, dir, data)
            }
        }
        impl tpm2::crypto::ConstantTimeEq for $t {
            fn constant_time_eq<const N: usize>(&self, a: &[u8; N], b: &[u8; N]) -> bool {
                tpm2::crypto::ConstantTimeEq::constant_time_eq(&self.$field, a, b)
            }
        }
        impl tpm2::crypto::Random for $t {
            type Rng = <$crate::common::TestCryptoProvider as tpm2::crypto::Random>::Rng;

            fn rng(&self) -> Result<Self::Rng, tpm2::crypto::CryptoError> {
                tpm2::crypto::Random::rng(&self.$field)
            }
            fn rng_seeded(&self, seed: &[u8]) -> Result<Self::Rng, tpm2::crypto::CryptoError> {
                tpm2::crypto::Random::rng_seeded(&self.$field, seed)
            }
        }
    };
}

impl tpm2::crypto::Hash for FakeCrypto {
    type Sha1Context = FakeHashCtx;
    type Sha256Context = FakeHashCtx;
    type Sha384Context = FakeHashCtx;
    type Sha512Context = FakeHashCtx;
    type Sm3_256Context = FakeHashCtx;
    type Sha3_256Context = FakeHashCtx;
    type Sha3_384Context = FakeHashCtx;
    type Sha3_512Context = FakeHashCtx;

    fn sha1(&self) -> Result<Self::Sha1Context, CryptoError> {
        Ok(FakeHashCtx(Vec::new()))
    }
    fn sha256(&self) -> Result<Self::Sha256Context, CryptoError> {
        Ok(FakeHashCtx(Vec::new()))
    }
    fn sha384(&self) -> Result<Self::Sha384Context, CryptoError> {
        Ok(FakeHashCtx(Vec::new()))
    }
    fn sha512(&self) -> Result<Self::Sha512Context, CryptoError> {
        Ok(FakeHashCtx(Vec::new()))
    }
    fn sm3_256(&self) -> Result<Self::Sm3_256Context, CryptoError> {
        Ok(FakeHashCtx(Vec::new()))
    }
    fn sha3_256(&self) -> Result<Self::Sha3_256Context, CryptoError> {
        Ok(FakeHashCtx(Vec::new()))
    }
    fn sha3_384(&self) -> Result<Self::Sha3_384Context, CryptoError> {
        Ok(FakeHashCtx(Vec::new()))
    }
    fn sha3_512(&self) -> Result<Self::Sha3_512Context, CryptoError> {
        Ok(FakeHashCtx(Vec::new()))
    }
}

impl tpm2::crypto::Hmac for FakeCrypto {
    type Sha1Context = FakeHmacCtx;
    type Sha256Context = FakeHmacCtx;
    type Sha384Context = FakeHmacCtx;
    type Sha512Context = FakeHmacCtx;
    type Sm3_256Context = FakeHmacCtx;
    type Sha3_256Context = FakeHmacCtx;
    type Sha3_384Context = FakeHmacCtx;
    type Sha3_512Context = FakeHmacCtx;

    fn sha1(&self, key: &[u8]) -> Result<Self::Sha1Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn sha256(&self, key: &[u8]) -> Result<Self::Sha256Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn sha384(&self, key: &[u8]) -> Result<Self::Sha384Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn sha512(&self, key: &[u8]) -> Result<Self::Sha512Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn sm3_256(&self, key: &[u8]) -> Result<Self::Sm3_256Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn sha3_256(&self, key: &[u8]) -> Result<Self::Sha3_256Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn sha3_384(&self, key: &[u8]) -> Result<Self::Sha3_384Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn sha3_512(&self, key: &[u8]) -> Result<Self::Sha3_512Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
}

/// AES only (via [`fake_sym_xor`]); the other ciphers keep the default
/// [`CryptoError::Unsupported`].
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
    /// Writes `0x5a` bytes XORed with the folded digest: 64 bytes for ECDSA, otherwise as many as
    /// fit in `signature_out` (up to 256). A `signature_out` that is too small (fewer than 64
    /// bytes for ECDSA, fewer than 32 otherwise) fails with [`CryptoError::Internal`] (formerly
    /// `BufferTooSmall`).
    fn sign_inner(
        &self,
        sign_alg: Alg,
        _private_key: &[u8],
        digest: tpm2::TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        let len = match sign_alg {
            Alg::ECDSA => {
                if signature_out.len() < 64 {
                    return Err(CryptoError::Internal);
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
                    return Err(CryptoError::Internal);
                }
                signature_out[..l].fill(0x5a);
                for (i, &b) in digest.digest().iter().enumerate() {
                    signature_out[i % l] ^= b;
                }
                l
            }
        };
        Ok(Some(len))
    }
}

impl Asymmetric for FakeCrypto {
    /// Accepts exactly the signatures [`FakeCrypto::sign_inner`] produces for `digest`; anything
    /// else (including an empty or wrongly sized signature) is `Ok(false)` (formerly
    /// `InvalidData`).
    fn verify_inner(
        &self,
        sign_alg: Alg,
        _public_key: &[u8],
        _rsa_exponent: u32,
        digest: tpm2::TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let len = match sign_alg {
            Alg::ECDSA => 64,
            _ => signature.len(),
        };
        if signature.len() != len || len == 0 {
            return Ok(false);
        }
        let mut expected = vec![0x5a; len];
        for (i, &b) in digest.digest().iter().enumerate() {
            expected[i % len] ^= b;
        }
        Ok(signature == expected)
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
    /// [`CryptoError::Internal`] (formerly `HardwareFailure`), and so does a `plaintext` buffer
    /// that is too small (formerly `BufferTooSmall`).
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
    type Aes128Context = FakeHmacCtx;
    type Aes192Context = FakeHmacCtx;
    type Aes256Context = FakeHmacCtx;
    type Sm4_128Context = FakeHmacCtx;
    type Camellia128Context = FakeHmacCtx;
    type Camellia192Context = FakeHmacCtx;
    type Camellia256Context = FakeHmacCtx;

    fn aes128(&self, key: &[u8; 16]) -> Result<Self::Aes128Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn aes192(&self, key: &[u8; 24]) -> Result<Self::Aes192Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn aes256(&self, key: &[u8; 32]) -> Result<Self::Aes256Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn sm4_128(&self, key: &[u8; 16]) -> Result<Self::Sm4_128Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn camellia128(&self, key: &[u8; 16]) -> Result<Self::Camellia128Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn camellia192(&self, key: &[u8; 24]) -> Result<Self::Camellia192Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
    fn camellia256(&self, key: &[u8; 32]) -> Result<Self::Camellia256Context, CryptoError> {
        Ok(FakeHmacCtx(key.to_vec()))
    }
}

impl ConstantTimeEq for FakeCrypto {
    fn constant_time_eq<const N: usize>(&self, a: &[u8; N], b: &[u8; N]) -> bool {
        a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

impl Random for FakeCrypto {
    type Rng = !;
}

/// The fake ECC operations accept every input and report success without writing any output.
/// The output lengths reported are those of the output buffers.
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
    ) -> Result<bool, tpm2::crypto::CryptoError> {
        Ok(true)
    }
    fn point_multiply_generator(
        &self,
        _curve: tpm2::TpmEccCurve,
        _scalar: &[u8],
        public_key_out: &mut [u8],
    ) -> Result<Option<usize>, tpm2::crypto::CryptoError> {
        Ok(Some(public_key_out.len()))
    }
    fn point_multiply(
        &self,
        _curve: tpm2::TpmEccCurve,
        _scalar: &[u8],
        _public_point: &[u8],
        derived_point_out: &mut [u8],
    ) -> Result<Option<usize>, tpm2::crypto::CryptoError> {
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
    ) -> Result<Option<usize>, tpm2::crypto::CryptoError> {
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
    rng: &'a mut FakeRng,
) -> RealCryptoEngine<'a> {
    let platform = tpm2_impl::TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = tpm2_impl::TpmEngine::new(platform).unwrap();
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
