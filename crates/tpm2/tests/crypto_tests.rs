// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Tests of the tpm-rs extensions of `tpm2::crypto` (`kdfa_bits`/`kdfe_bits`,
//! ECC point arithmetic, `digest_eq`) and of the dispatch error handling, with
//! mock backends. The dispatch functions themselves are tested by the in-crate
//! `crypto::tests` module.

// The fake curve is only used with NIST P-256.
#![cfg_attr(not(feature = "nist_p256"), allow(dead_code))]

use tpm2::crypto::backend::{
    Ecc, EccCurve, Hash, HashState, Hmac, HmacState, PrivateKey, Symmetric, SymmetricState,
};
use tpm2::crypto::*;
use tpm2::*;

// --- KDFs ---

/// Mock hash/HMAC state: a FNV-like accumulator, whose output is `0xFF` except
/// for 8 bytes of state (so that the high-order masking of the KDFs is visible
/// in the first byte).
struct MockCtx<const N: usize> {
    state: u64,
}

impl<const N: usize> MockCtx<N> {
    fn absorb(&mut self, data: &[u8]) {
        for &b in data {
            self.state = self
                .state
                .wrapping_mul(1099511628211)
                .wrapping_add(u64::from(b));
        }
    }
}

impl<const N: usize> HashState<N> for MockCtx<N> {
    fn init() -> Result<Self, CryptoError> {
        Ok(Self {
            state: 0xcbf29ce484222325,
        })
    }
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.absorb(data);
        Ok(())
    }
    fn finalize(&mut self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        out.fill(0xFF);
        out[12..20].copy_from_slice(&self.state.to_be_bytes());
        Ok(())
    }
}

impl<const N: usize> HmacState<N> for MockCtx<N> {
    fn init(key: &[u8]) -> Result<Self, CryptoError> {
        let mut ctx = Self {
            state: 0xcbf29ce484222325,
        };
        ctx.absorb(key);
        Ok(ctx)
    }
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.absorb(data);
        Ok(())
    }
    fn finalize(&mut self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        out.fill(0xFF);
        out[12..20].copy_from_slice(&self.state.to_be_bytes());
        Ok(())
    }
}

struct MockProvider;
impl Hash for MockProvider {
    type Sha1 = MockCtx<20>;
    type Sha256 = MockCtx<32>;
    type Sha384 = MockCtx<48>;
    type Sha512 = MockCtx<64>;
    type Sm3_256 = MockCtx<32>;
    type Sha3_256 = MockCtx<32>;
    type Sha3_384 = MockCtx<48>;
    type Sha3_512 = MockCtx<64>;
}
impl Hmac for MockProvider {
    type Sha1 = MockCtx<20>;
    type Sha256 = MockCtx<32>;
    type Sha384 = MockCtx<48>;
    type Sha512 = MockCtx<64>;
    type Sm3_256 = MockCtx<32>;
    type Sha3_256 = MockCtx<32>;
    type Sha3_384 = MockCtx<48>;
    type Sha3_512 = MockCtx<64>;
}

/// A backend without any hash/HMAC algorithm.
struct DummyHmac;
impl Hmac for DummyHmac {
    type Sha1 = !;
    type Sha256 = !;
    type Sha384 = !;
    type Sha512 = !;
    type Sm3_256 = !;
    type Sha3_256 = !;
    type Sha3_384 = !;
    type Sha3_512 = !;
}

const HASH: TpmiAlgHash = TpmiAlgHash::DEFAULT_HASH;

fn kdfa_b(label: &[u8], bits: u32, out: &mut [u8]) -> usize {
    kdfa_bits::<MockProvider>(HASH, b"key", label, (b"u", b"v"), bits, out).unwrap()
}

fn kdfe_b(label: &[u8], bits: u32, out: &mut [u8]) -> usize {
    kdfe_bits::<MockProvider>(HASH, b"z", label, (b"u", b"v"), bits, out).unwrap()
}

#[test]
fn test_kdfa_request_too_large_rejected() {
    let mut out = [0u8; 64];
    // Requesting 1000 bits requires 125 bytes, but our buffer is only 64 bytes:
    // rejected before the (unsupported) HMAC is used.
    let err =
        kdfa_bits::<DummyHmac>(HASH, b"key", b"label", (b"u", b"v"), 1000, &mut out).unwrap_err();
    assert_eq!(err, CryptoError::Internal);
    // With a large enough buffer, the missing algorithm is reported.
    let err =
        kdfa_bits::<DummyHmac>(HASH, b"key", b"label", (b"u", b"v"), 256, &mut out).unwrap_err();
    assert_eq!(err, CryptoError::Unsupported);
}

#[test]
fn test_kdfa_and_kdfe_label_null_termination() {
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    kdfa_b(b"STORAGE", 256, &mut a);
    kdfa_b(b"STORAGE\0", 256, &mut b);
    assert_eq!(a, b);
    // The raw-label variant matches `kdfa` with the same label as a `CStr`.
    let mut c = [0u8; 32];
    kdfa::<MockProvider>(HASH, b"key", c"STORAGE", (b"u", b"v"), &mut c).unwrap();
    assert_eq!(a, c);

    kdfa_b(&[], 256, &mut a);
    kdfa_b(&[0x00], 256, &mut b);
    assert_eq!(a, b);

    kdfa_b(b"STORAGE\0", 256, &mut a);
    kdfa_b(b"STORAGE\0\0", 256, &mut b);
    assert_ne!(a, b);

    kdfe_b(b"IDENTITY", 256, &mut a);
    kdfe_b(b"IDENTITY\0", 256, &mut b);
    assert_eq!(a, b);
    kdfe::<MockProvider>(HASH, b"z", c"IDENTITY", (b"u", b"v"), &mut c).unwrap();
    assert_eq!(a, c);

    kdfe_b(b"IDENTITY\0", 256, &mut a);
    kdfe_b(b"IDENTITY\0\0", 256, &mut b);
    assert_ne!(a, b);

    kdfe_b(&[], 256, &mut a);
    kdfe_b(&[0x00], 256, &mut b);
    assert_eq!(a, b);
}

#[test]
fn test_kdfa_and_kdfe_high_order_bit_masking() {
    // Verify masking for every remainder bits % 8 in 1..=7 (both 1-byte and 2-byte outputs)
    for rem in 1..=7u32 {
        let expected_mask = (1u8 << rem) - 1;

        let mut out = [0u8; 1];
        assert_eq!(kdfa_b(b"STORAGE", rem, &mut out), 1);
        assert_eq!(out[0], expected_mask);
        assert_eq!(kdfe_b(b"SECRET", rem, &mut out), 1);
        assert_eq!(out[0], expected_mask);

        let mut out = [0u8; 2];
        assert_eq!(kdfa_b(b"STORAGE", 8 + rem, &mut out), 2);
        assert_eq!(out, [expected_mask, 0xFF]);
        assert_eq!(kdfe_b(b"SECRET", 8 + rem, &mut out), 2);
        assert_eq!(out, [expected_mask, 0xFF]);
    }

    // 521 bits (e.g. NIST P-521) -> 66 bytes, 521 % 8 = 1 -> mask 0x01
    let mut out = [0u8; 66];
    assert_eq!(kdfa_b(b"STORAGE", 521, &mut out), 66);
    assert_eq!(out[..2], [0x01, 0xFF]);
    assert_eq!(kdfe_b(b"SECRET", 521, &mut out), 66);
    assert_eq!(out[..2], [0x01, 0xFF]);

    // 16 bits -> 2 bytes, 16 % 8 = 0 -> no masking (0xFF)
    let mut out = [0u8; 2];
    assert_eq!(kdfa_b(b"STORAGE", 16, &mut out), 2);
    assert_eq!(out, [0xFF, 0xFF]);
    assert_eq!(kdfe_b(b"SECRET", 16, &mut out), 2);
    assert_eq!(out, [0xFF, 0xFF]);

    // 0 bits -> 0 bytes, `out` untouched
    let mut out = [0xAAu8; 2];
    assert_eq!(kdfa_b(b"STORAGE", 0, &mut out), 0);
    assert_eq!(kdfe_b(b"SECRET", 0, &mut out), 0);
    assert_eq!(out, [0xAA, 0xAA]);

    // Only `ceil(bits / 8)` bytes are written.
    let mut out = [0xAAu8; 4];
    assert_eq!(kdfa_b(b"STORAGE", 12, &mut out), 2);
    assert_eq!(out, [0x0F, 0xFF, 0xAA, 0xAA]);
}

/// A complete backend without any algorithm, only implementing `ct_eq`.
struct CtEqOnly;
impl Random for CtEqOnly {
    type Rng = FakeRng;
    fn from_entropy() -> Result<FakeRng, CryptoError> {
        Ok(FakeRng)
    }
    fn from_seed(_: &[u8]) -> Result<FakeRng, CryptoError> {
        Ok(FakeRng)
    }
}
impl Hash for CtEqOnly {
    type Sha1 = !;
    type Sha256 = !;
    type Sha384 = !;
    type Sha512 = !;
    type Sm3_256 = !;
    type Sha3_256 = !;
    type Sha3_384 = !;
    type Sha3_512 = !;
}
impl Hmac for CtEqOnly {
    type Sha1 = !;
    type Sha256 = !;
    type Sha384 = !;
    type Sha512 = !;
    type Sm3_256 = !;
    type Sha3_256 = !;
    type Sha3_384 = !;
    type Sha3_512 = !;
}
impl backend::Cmac for CtEqOnly {
    type Aes128 = !;
    type Aes192 = !;
    type Aes256 = !;
    type Sm4_128 = !;
    type Camellia128 = !;
    type Camellia192 = !;
    type Camellia256 = !;
}
impl Symmetric for CtEqOnly {
    type Aes128 = !;
    type Aes192 = !;
    type Aes256 = !;
    type Sm4_128 = !;
    type Camellia128 = !;
    type Camellia192 = !;
    type Camellia256 = !;
}
impl backend::Rsa for CtEqOnly {
    type Rsa1024 = !;
    type Rsa2048 = !;
    type Rsa3072 = !;
    type Rsa4096 = !;
}
impl Ecc for CtEqOnly {
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
impl backend::Mldsa for CtEqOnly {
    type Mldsa44 = !;
    type Mldsa65 = !;
    type Mldsa87 = !;
}
impl backend::Mlkem for CtEqOnly {
    type Mlkem512 = !;
    type Mlkem768 = !;
    type Mlkem1024 = !;
}
impl Crypto for CtEqOnly {
    fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        a.len() == b.len() && a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

#[test]
fn test_digest_eq_and_known_answer_tests() {
    let x = [1u8; HASH.digest_size()];
    let y = [2u8; HASH.digest_size()];
    let a = TpmtHa::new(HASH, &x).unwrap();
    let b = TpmtHa::new(HASH, &y).unwrap();
    assert!(digest_eq::<CtEqOnly>(a, a));
    assert!(!digest_eq::<CtEqOnly>(a, b));
    // The known-answer self tests are enabled by default.
    const { assert!(CtEqOnly::KNOWN_ANSWER_TESTS) };
}

// --- Symmetric ---

/// AES-128 "cipher" which XORs the data with the key; only CFB is supported.
struct XorAes;
impl SymmetricState<16> for XorAes {
    fn init(_key: &[u8; 16]) -> Result<Self, CryptoError> {
        Ok(Self)
    }
    fn ctr(&self, _: &mut Block, _: &mut [u8]) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn ofb(&self, _: &mut Block, _: &mut [u8]) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn cbc(&self, _: Direction, _: &mut Block, _: &mut [Block]) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn cfb(&self, _: Direction, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        for b in data.iter_mut() {
            *b ^= 0x5A;
        }
        iv.fill(0x5A);
        Ok(())
    }
    fn ecb(&self, _: Direction, _: &mut [Block]) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

struct DummySymmetric;
impl Symmetric for DummySymmetric {
    type Aes128 = XorAes;
    type Aes192 = !;
    type Aes256 = !;
    type Sm4_128 = !;
    type Camellia128 = !;
    type Camellia192 = !;
    type Camellia256 = !;
}

#[test]
#[cfg(feature = "aes128")]
fn test_symmetric_key_and_iv_sizes() {
    // The key length is checked when the key is built for its algorithm.
    assert!(SymmetricKey::new(AlgSym::Aes128, &[0u8; 15]).is_none());
    // The IV length is checked when the input is built for its mode.
    let mut data = [0u8; 16];
    assert!(CipherInput::new(TpmiAlgCipherMode::Cfb, &mut [0u8; 15], &mut data).is_none());

    // A key and IV of the right length reach the backend.
    let key = SymmetricKey::new(AlgSym::Aes128, &[0x5Au8; 16]).unwrap();
    let mut iv = [0u8; 16];
    let input = CipherInput::new(TpmiAlgCipherMode::Cfb, &mut iv, &mut data).unwrap();
    assert_eq!(
        key.crypt::<DummySymmetric>(Direction::Encrypt, input),
        Ok(())
    );
    assert_eq!(data, [0x5A; 16]);
    assert_eq!(iv, [0x5A; 16]);
}

// --- ECC point arithmetic (tpm-rs extensions) ---

/// A fake P-256 where `[k]G = (k, k)`, `[k]P = (k ^ P.x, k ^ P.y)`, and every
/// point with `x != 0` is on the curve. Private keys are not supported.
struct FakeP256;

#[derive(Clone, Copy)]
struct FakePoint([u8; 64]);

impl PrivateKey<64, 32, FakeRng> for FakeP256 {
    type PublicKey = FakePoint;
    fn generate(_: &mut FakeRng, _: ()) -> Result<Self, CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn load(_: FakePoint, _: &[u8; 32]) -> Result<Option<Self>, CryptoError> {
        Ok(Some(Self))
    }
    fn store(&self, _: &mut [u8; 32]) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn as_public(&self) -> &FakePoint {
        &FakePoint([0; 64])
    }
    fn load_public(_: (), public: &[u8; 64]) -> Result<Option<FakePoint>, CryptoError> {
        Ok((public[..32] != [0; 32]).then_some(FakePoint(*public)))
    }
    fn store_public(public: &FakePoint, out: &mut [u8; 64]) -> Result<(), CryptoError> {
        *out = public.0;
        Ok(())
    }
}

impl EccCurve<32, 64, FakeRng> for FakeP256 {
    fn ecdh(
        &self,
        _: &FakePoint,
        _: &mut [u8; 32],
        _: &mut [u8; 32],
    ) -> Result<Option<()>, CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn sign(
        &self,
        _: &mut FakeRng,
        _: &[u8],
        _: &mut [u8; 32],
        _: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn verify(_: &FakePoint, _: &[u8], _: &[u8; 32], _: &[u8; 32]) -> Result<bool, CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn mul_generator(
        k: &[u8; 32],
        out_x: &mut [u8; 32],
        out_y: &mut [u8; 32],
    ) -> Result<Option<()>, CryptoError> {
        if *k == [0; 32] {
            return Ok(None);
        }
        *out_x = *k;
        *out_y = *k;
        Ok(Some(()))
    }
    fn mul_point(
        point: &FakePoint,
        k: &[u8; 32],
        out_x: &mut [u8; 32],
        out_y: &mut [u8; 32],
    ) -> Result<Option<()>, CryptoError> {
        for i in 0..32 {
            out_x[i] = k[i] ^ point.0[i];
            out_y[i] = k[i] ^ point.0[32 + i];
        }
        Ok(Some(()))
    }
}

struct FakeRng;
impl Rng for FakeRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        out.fill(0x42);
        Ok(())
    }
    fn stir_bytes(&mut self, _: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

struct DummyEcc;
impl Random for DummyEcc {
    type Rng = FakeRng;
    fn from_entropy() -> Result<FakeRng, CryptoError> {
        Ok(FakeRng)
    }
    fn from_seed(_: &[u8]) -> Result<FakeRng, CryptoError> {
        Ok(FakeRng)
    }
}
impl Ecc for DummyEcc {
    type NistP192 = !;
    type NistP224 = !;
    type NistP256 = FakeP256;
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

#[test]
#[cfg(feature = "nist_p256")]
fn test_ecc_point_arithmetic() {
    let curve = TpmEccCurve::NistP256;
    let (mut x, mut y) = ([0u8; 32], [0u8; 32]);

    // [k]G, with a short (left-padded) scalar.
    let q = ecc_mul_generator::<DummyEcc>(curve, &[2], &mut x, &mut y)
        .unwrap()
        .unwrap();
    let mut two = [0u8; 32];
    two[31] = 2;
    assert_eq!((q.x.as_slice(), q.y.as_slice()), (&two[..], &two[..]));
    // Zero and over-long scalars have no result.
    assert!(
        ecc_mul_generator::<DummyEcc>(curve, &[0; 32], &mut x, &mut y)
            .unwrap()
            .is_none()
    );
    assert!(
        ecc_mul_generator::<DummyEcc>(curve, &[1; 33], &mut x, &mut y)
            .unwrap()
            .is_none()
    );
    // Output buffers too small.
    assert_eq!(
        ecc_mul_generator::<DummyEcc>(curve, &[2], &mut [0u8; 31], &mut y),
        Err(CryptoError::Internal)
    );

    // Point validation is `EccPublicKey::load`.
    let px = [1u8; 32];
    let p = TpmsEccPoint {
        x: Tpm2bEccParameter::new(&px).unwrap(),
        y: Tpm2bEccParameter::new(&px).unwrap(),
    };
    let public = EccPublicKey::<DummyEcc>::load(curve, None, p)
        .unwrap()
        .unwrap();
    let off_curve = TpmsEccPoint {
        x: Tpm2bEccParameter::new(&[0u8; 32]).unwrap(),
        y: Tpm2bEccParameter::new(&px).unwrap(),
    };
    assert!(
        EccPublicKey::<DummyEcc>::load(curve, None, off_curve)
            .unwrap()
            .is_none()
    );

    // [k]P
    let r = public.mul_point(&[3], &mut x, &mut y).unwrap().unwrap();
    assert_eq!(r.x.as_slice()[31], 3 ^ 1);
    assert_eq!(r.y.as_slice()[0], 1);

    // A private key from its scalar.
    assert!(
        EccPrivateKey::<DummyEcc>::from_scalar(curve, &[7])
            .unwrap()
            .is_some()
    );
    assert!(
        EccPrivateKey::<DummyEcc>::from_scalar(curve, &[0])
            .unwrap()
            .is_none()
    );
}

#[test]
#[cfg(feature = "nist_p384")]
fn test_ecc_unimplemented_curve() {
    let (mut x, mut y) = ([0u8; 48], [0u8; 48]);
    assert_eq!(
        ecc_mul_generator::<DummyEcc>(TpmEccCurve::NistP384, &[2], &mut x, &mut y),
        Err(CryptoError::Unsupported)
    );
    let p = TpmsEccPoint {
        x: Tpm2bEccParameter::new(&[1u8; 48]).unwrap(),
        y: Tpm2bEccParameter::new(&[1u8; 48]).unwrap(),
    };
    assert!(matches!(
        EccPublicKey::<DummyEcc>::load(TpmEccCurve::NistP384, None, p),
        Err(CryptoError::Unsupported)
    ));
}
