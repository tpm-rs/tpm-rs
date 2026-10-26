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

use tpm2::crypto::*;
use tpm2::*;

// --- From kdf.rs ---

struct DummyHmac;
impl Hmac for DummyHmac {
    type Sha1Context = !;
    type Sha256Context = !;
    type Sha384Context = !;
    type Sha512Context = !;
    type Sm3_256Context = !;
    type Sha3_256Context = !;
    type Sha3_384Context = !;
    type Sha3_512Context = !;
}

struct MockCtx<const N: usize> {
    state: u64,
}

impl<const N: usize> MockCtx<N> {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }
}

impl<const N: usize> Update for MockCtx<N> {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        for &b in data {
            self.state = self
                .state
                .wrapping_mul(1099511628211)
                .wrapping_add(b as u64);
        }
        Ok(())
    }
}

impl<const N: usize> Finalize<N> for MockCtx<N> {
    fn finalize(self, out: &mut [u8; N]) -> Result<(), CryptoError> {
        out.fill(0xFF);
        out[12..20].copy_from_slice(&self.state.to_be_bytes());
        Ok(())
    }
}

struct MockProvider;
impl Hash for MockProvider {
    type Sha1Context = MockCtx<20>;
    type Sha256Context = MockCtx<32>;
    type Sha384Context = MockCtx<48>;
    type Sha512Context = MockCtx<64>;
    type Sm3_256Context = MockCtx<32>;
    type Sha3_256Context = MockCtx<32>;
    type Sha3_384Context = MockCtx<48>;
    type Sha3_512Context = MockCtx<64>;

    fn sha1(&self) -> Result<Self::Sha1Context, CryptoError> {
        Ok(MockCtx::new(0xcbf29ce484222325))
    }
    fn sha256(&self) -> Result<Self::Sha256Context, CryptoError> {
        Ok(MockCtx::new(0xcbf29ce484222325))
    }
    fn sha384(&self) -> Result<Self::Sha384Context, CryptoError> {
        Ok(MockCtx::new(0xcbf29ce484222325))
    }
    fn sha512(&self) -> Result<Self::Sha512Context, CryptoError> {
        Ok(MockCtx::new(0xcbf29ce484222325))
    }
    fn sm3_256(&self) -> Result<Self::Sm3_256Context, CryptoError> {
        Ok(MockCtx::new(0xcbf29ce484222325))
    }
    fn sha3_256(&self) -> Result<Self::Sha3_256Context, CryptoError> {
        Ok(MockCtx::new(0xcbf29ce484222325))
    }
    fn sha3_384(&self) -> Result<Self::Sha3_384Context, CryptoError> {
        Ok(MockCtx::new(0xcbf29ce484222325))
    }
    fn sha3_512(&self) -> Result<Self::Sha3_512Context, CryptoError> {
        Ok(MockCtx::new(0xcbf29ce484222325))
    }
}
impl Hmac for MockProvider {
    type Sha1Context = MockCtx<20>;
    type Sha256Context = MockCtx<32>;
    type Sha384Context = MockCtx<48>;
    type Sha512Context = MockCtx<64>;
    type Sm3_256Context = MockCtx<32>;
    type Sha3_256Context = MockCtx<32>;
    type Sha3_384Context = MockCtx<48>;
    type Sha3_512Context = MockCtx<64>;

    fn sha1(&self, key: &[u8]) -> Result<Self::Sha1Context, CryptoError> {
        let mut ctx = MockCtx::new(0xcbf29ce484222325);
        ctx.update(key)?;
        Ok(ctx)
    }
    fn sha256(&self, key: &[u8]) -> Result<Self::Sha256Context, CryptoError> {
        let mut ctx = MockCtx::new(0xcbf29ce484222325);
        ctx.update(key)?;
        Ok(ctx)
    }
    fn sha384(&self, key: &[u8]) -> Result<Self::Sha384Context, CryptoError> {
        let mut ctx = MockCtx::new(0xcbf29ce484222325);
        ctx.update(key)?;
        Ok(ctx)
    }
    fn sha512(&self, key: &[u8]) -> Result<Self::Sha512Context, CryptoError> {
        let mut ctx = MockCtx::new(0xcbf29ce484222325);
        ctx.update(key)?;
        Ok(ctx)
    }
    fn sm3_256(&self, key: &[u8]) -> Result<Self::Sm3_256Context, CryptoError> {
        let mut ctx = MockCtx::new(0xcbf29ce484222325);
        ctx.update(key)?;
        Ok(ctx)
    }
    fn sha3_256(&self, key: &[u8]) -> Result<Self::Sha3_256Context, CryptoError> {
        let mut ctx = MockCtx::new(0xcbf29ce484222325);
        ctx.update(key)?;
        Ok(ctx)
    }
    fn sha3_384(&self, key: &[u8]) -> Result<Self::Sha3_384Context, CryptoError> {
        let mut ctx = MockCtx::new(0xcbf29ce484222325);
        ctx.update(key)?;
        Ok(ctx)
    }
    fn sha3_512(&self, key: &[u8]) -> Result<Self::Sha3_512Context, CryptoError> {
        let mut ctx = MockCtx::new(0xcbf29ce484222325);
        ctx.update(key)?;
        Ok(ctx)
    }
}

#[test]
fn test_kdfa_request_too_large_rejected() {
    let provider = DummyHmac;
    let mut out = [0u8; 64];
    // Requesting 1000 bits requires 125 bytes, but our buffer is only 64 bytes.
    let err = kdfa_bits(
        &provider,
        TpmiAlgHash::DEFAULT_HASH,
        b"key",
        b"label",
        b"u",
        b"v",
        1000,
        &mut out,
    )
    .unwrap_err();

    assert_eq!(err, CryptoError::Internal);
}

#[test]
fn test_kdfa_and_kdfe_label_null_termination() {
    let provider = MockProvider;
    let hash = TpmiAlgHash::DEFAULT_HASH;

    let mut out_kdfa_no_nul = [0u8; 32];
    let mut out_kdfa_with_nul = [0u8; 32];
    kdfa_bits(
        &provider,
        hash,
        b"key",
        b"STORAGE",
        b"u",
        b"v",
        256,
        &mut out_kdfa_no_nul,
    )
    .unwrap();
    kdfa_bits(
        &provider,
        hash,
        b"key",
        b"STORAGE\0",
        b"u",
        b"v",
        256,
        &mut out_kdfa_with_nul,
    )
    .unwrap();
    assert_eq!(out_kdfa_no_nul, out_kdfa_with_nul);

    let mut out_kdfa_empty = [0u8; 32];
    let mut out_kdfa_zero_byte = [0u8; 32];
    kdfa_bits(
        &provider,
        hash,
        b"key",
        &[],
        b"u",
        b"v",
        256,
        &mut out_kdfa_empty,
    )
    .unwrap();
    kdfa_bits(
        &provider,
        hash,
        b"key",
        &[0x00],
        b"u",
        b"v",
        256,
        &mut out_kdfa_zero_byte,
    )
    .unwrap();
    assert_eq!(out_kdfa_empty, out_kdfa_zero_byte);

    let mut out_kdfa_two_nuls = [0u8; 32];
    kdfa_bits(
        &provider,
        hash,
        b"key",
        b"STORAGE\0\0",
        b"u",
        b"v",
        256,
        &mut out_kdfa_two_nuls,
    )
    .unwrap();
    assert_ne!(out_kdfa_with_nul, out_kdfa_two_nuls);

    let mut out_kdfe_no_nul = [0u8; 32];
    let mut out_kdfe_with_nul = [0u8; 32];
    kdfe_bits(
        &provider,
        hash,
        b"z",
        b"IDENTITY",
        b"u",
        b"v",
        256,
        &mut out_kdfe_no_nul,
    )
    .unwrap();
    kdfe_bits(
        &provider,
        hash,
        b"z",
        b"IDENTITY\0",
        b"u",
        b"v",
        256,
        &mut out_kdfe_with_nul,
    )
    .unwrap();
    assert_eq!(out_kdfe_no_nul, out_kdfe_with_nul);

    let mut out_kdfe_two_nuls = [0u8; 32];
    kdfe_bits(
        &provider,
        hash,
        b"z",
        b"IDENTITY\0\0",
        b"u",
        b"v",
        256,
        &mut out_kdfe_two_nuls,
    )
    .unwrap();
    assert_ne!(out_kdfe_with_nul, out_kdfe_two_nuls);

    let mut out_kdfe_empty = [0u8; 32];
    let mut out_kdfe_zero_byte = [0u8; 32];
    kdfe_bits(
        &provider,
        hash,
        b"z",
        &[],
        b"u",
        b"v",
        256,
        &mut out_kdfe_empty,
    )
    .unwrap();
    kdfe_bits(
        &provider,
        hash,
        b"z",
        &[0x00],
        b"u",
        b"v",
        256,
        &mut out_kdfe_zero_byte,
    )
    .unwrap();
    assert_eq!(out_kdfe_empty, out_kdfe_zero_byte);
}

#[test]
fn test_kdfa_and_kdfe_high_order_bit_masking() {
    let provider = MockProvider;
    let hash = TpmiAlgHash::DEFAULT_HASH;

    // Verify masking for every remainder bits % 8 in 1..=7 (both 1-byte and 2-byte outputs)
    for rem in 1..=7u32 {
        let expected_mask = (1u8 << rem) - 1;

        // 1-byte output (bits = 1..=7)
        let mut out_a1 = [0u8; 1];
        let len_a1 = kdfa_bits(
            &provider,
            hash,
            b"key",
            b"STORAGE",
            b"u",
            b"v",
            rem,
            &mut out_a1,
        )
        .unwrap();
        assert_eq!(len_a1, 1);
        assert_eq!(out_a1[0], expected_mask);

        let mut out_e1 = [0u8; 1];
        let len_e1 = kdfe_bits(
            &provider,
            hash,
            b"z",
            b"SECRET",
            b"u",
            b"v",
            rem,
            &mut out_e1,
        )
        .unwrap();
        assert_eq!(len_e1, 1);
        assert_eq!(out_e1[0], expected_mask);

        // 2-byte output (bits = 9..=15)
        let bits = 8 + rem;
        let mut out_a = [0u8; 2];
        let len_a = kdfa_bits(
            &provider, hash, b"key", b"STORAGE", b"u", b"v", bits, &mut out_a,
        )
        .unwrap();
        assert_eq!(len_a, 2);
        assert_eq!(out_a[0], expected_mask);
        assert_eq!(out_a[1], 0xFF);

        let mut out_e = [0u8; 2];
        let len_e = kdfe_bits(
            &provider, hash, b"z", b"SECRET", b"u", b"v", bits, &mut out_e,
        )
        .unwrap();
        assert_eq!(len_e, 2);
        assert_eq!(out_e[0], expected_mask);
        assert_eq!(out_e[1], 0xFF);
    }

    // 521 bits (e.g. NIST P-521) -> 66 bytes, 521 % 8 = 1 -> mask 0x01
    let mut out_kdfa_521 = [0u8; 66];
    let len = kdfa_bits(
        &provider,
        hash,
        b"key",
        b"STORAGE",
        b"u",
        b"v",
        521,
        &mut out_kdfa_521,
    )
    .unwrap();
    assert_eq!(len, 66);
    assert_eq!(out_kdfa_521[0], 0x01);
    assert_eq!(out_kdfa_521[1], 0xFF);

    // 16 bits -> 2 bytes, 16 % 8 = 0 -> no masking (0xFF)
    let mut out_kdfa_16 = [0u8; 2];
    let len = kdfa_bits(
        &provider,
        hash,
        b"key",
        b"STORAGE",
        b"u",
        b"v",
        16,
        &mut out_kdfa_16,
    )
    .unwrap();
    assert_eq!(len, 2);
    assert_eq!(out_kdfa_16[0], 0xFF);
    assert_eq!(out_kdfa_16[1], 0xFF);

    let mut out_kdfe_16 = [0u8; 2];
    let len = kdfe_bits(
        &provider,
        hash,
        b"z",
        b"SECRET",
        b"u",
        b"v",
        16,
        &mut out_kdfe_16,
    )
    .unwrap();
    assert_eq!(len, 2);
    assert_eq!(out_kdfe_16[0], 0xFF);
    assert_eq!(out_kdfe_16[1], 0xFF);

    // 0 bits -> 0 bytes
    let mut out_kdfa_0 = [0xAAu8; 2];
    let len = kdfa_bits(
        &provider,
        hash,
        b"key",
        b"STORAGE",
        b"u",
        b"v",
        0,
        &mut out_kdfa_0,
    )
    .unwrap();
    assert_eq!(len, 0);
    assert_eq!(out_kdfa_0[0], 0xAA);

    let mut out_kdfe_0 = [0xAAu8; 2];
    let len = kdfe_bits(
        &provider,
        hash,
        b"z",
        b"SECRET",
        b"u",
        b"v",
        0,
        &mut out_kdfe_0,
    )
    .unwrap();
    assert_eq!(len, 0);
    assert_eq!(out_kdfe_0[0], 0xAA);

    // 521 bits -> 66 bytes, 521 % 8 = 1 -> mask 0x01
    let mut out_kdfe_521 = [0u8; 66];
    let len = kdfe_bits(
        &provider,
        hash,
        b"z",
        b"SECRET",
        b"u",
        b"v",
        521,
        &mut out_kdfe_521,
    )
    .unwrap();
    assert_eq!(len, 66);
    assert_eq!(out_kdfe_521[0], 0x01);
    assert_eq!(out_kdfe_521[1], 0xFF);
}

// --- From symmetric.rs ---

/// Test provider whose AES-128 "cipher" XORs the data with the key and sets the
/// chained IV (ivOut) to the key; only CFB is supported.
struct DummyProvider;

impl Symmetric for DummyProvider {
    fn aes128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        _dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        let ModeIv::Cfb(iv_out) = mode else {
            return Err(CryptoError::Unsupported);
        };
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= key[i % 16];
        }
        *iv_out = *key;
        Ok(())
    }
}

#[test]
fn test_symmetric_key_too_small_rejected() {
    let provider = DummyProvider;
    let mut iv = [0u8; 16];
    let bad_key = [0u8; 15]; // Aes128 expects 16
    let mut data = [0u8; 16];

    // The key length is checked when the key is built for its algorithm.
    assert!(SymmetricKey::new(AlgSym::Aes128, &bad_key).is_none());

    // A key of the right length is accepted and reaches the provider.
    let key = [0x5Au8; 16];
    assert_eq!(
        encrypt(
            &provider,
            SymmetricKey::new(AlgSym::Aes128, &key).unwrap(),
            ModeIv::new(TpmiAlgCipherMode::Cfb, &mut iv).unwrap(),
            &mut data,
        ),
        Ok(())
    );
    assert_eq!(data, key);
    assert_eq!(iv, key);
}

#[test]
fn test_symmetric_iv_buffer_too_small_rejected() {
    let provider = DummyProvider;
    let mut bad_iv = [0u8; 15]; // expects 16 bytes
    let key = [0u8; 16];
    let mut data = [0u8; 16];

    // The IV length is checked when the IV is bound to its mode.
    assert!(ModeIv::new(TpmiAlgCipherMode::Cfb, &mut bad_iv).is_none());

    // A 16-byte IV is accepted and reaches the provider.
    let mut iv = [0u8; 16];
    assert_eq!(
        encrypt(
            &provider,
            SymmetricKey::new(AlgSym::Aes128, &key).unwrap(),
            ModeIv::new(TpmiAlgCipherMode::Cfb, &mut iv).unwrap(),
            &mut data,
        ),
        Ok(())
    );
}

// --- From asymmetric.rs ---

struct DummyAsymmetricProvider;

impl AsymmetricSign for DummyAsymmetricProvider {
    fn rsassa_sign(
        &self,
        _private_key: &[u8],
        _digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        signature_out[..4].copy_from_slice(&[1, 2, 3, 4]);
        Ok(Some(4))
    }
}

impl Asymmetric for DummyAsymmetricProvider {}

#[test]
fn test_asymmetric_default_unimplemented() {
    let provider = DummyAsymmetricProvider;
    let mut sig = [0u8; 32];
    let digest = TpmtHa::DEFAULT_HA;
    #[cfg(feature = "rsassa")]
    {
        assert_eq!(
            sign_inner(&provider, Alg::RSASSA, &[], digest, &mut sig),
            Ok(Some(4))
        );
        assert_eq!(sig[..4], [1, 2, 3, 4]);
    }

    assert_eq!(
        sign_inner(&provider, Alg::RSAPSS, &[], digest, &mut sig),
        Err(CryptoError::Unsupported)
    );
    assert_eq!(
        verify_inner(&provider, Alg::ECDSA, &[], 0, digest, &[]),
        Err(CryptoError::Unsupported)
    );
    assert_eq!(
        rsa_encrypt(
            &provider,
            Alg::OAEP,
            Alg::SHA256,
            &[],
            0,
            &[],
            &mut sig,
            &[]
        ),
        Err(CryptoError::Unsupported)
    );
    assert_eq!(
        rsa_decrypt(&provider, Alg::RSAES, Alg::SHA256, &[], &[], &mut sig, &[]),
        Err(CryptoError::Unsupported)
    );
    let mut pub_k = [0u8; 32];
    let mut priv_k = [0u8; 32];
    assert_eq!(
        generate_key(&provider, Alg::RSA, None, &mut pub_k, &mut priv_k, None),
        Err(CryptoError::Unsupported)
    );
    assert_eq!(
        generate_key(&provider, Alg::ECC, None, &mut pub_k, &mut priv_k, None),
        Err(CryptoError::Unsupported)
    );
}

// --- From ecc.rs ---

struct DummyP256;
impl EccCurve<32> for DummyP256 {
    fn validate_point(&self, _x: &[u8; 32], _y: &[u8; 32]) -> Result<bool, CryptoError> {
        Ok(true)
    }
    fn point_multiply_generator(
        &self,
        scalar: &[u8; 32],
        x_out: &mut [u8; 32],
        y_out: &mut [u8; 32],
    ) -> Result<Option<()>, CryptoError> {
        *x_out = *scalar;
        *y_out = *scalar;
        Ok(Some(()))
    }
    fn point_multiply(
        &self,
        scalar: &[u8; 32],
        x_in: &[u8; 32],
        y_in: &[u8; 32],
        x_out: &mut [u8; 32],
        y_out: &mut [u8; 32],
    ) -> Result<Option<()>, CryptoError> {
        for i in 0..32 {
            x_out[i] = scalar[i] ^ x_in[i];
            y_out[i] = scalar[i] ^ y_in[i];
        }
        Ok(Some(()))
    }
    fn ecdaa_sign(
        &self,
        _commit_r: &[u8; 32],
        _commit_x: &[u8],
        _commit_p1: &[u8],
        _private_key_d: &[u8; 32],
        _digest: &[u8],
        nonce_k_out: &mut [u8; 32],
        s_out: &mut [u8; 32],
    ) -> Result<Option<()>, CryptoError> {
        *nonce_k_out = [0xAA; 32];
        *s_out = [0xBB; 32];
        Ok(Some(()))
    }
}

struct DummyBackend;
impl Ecc for DummyBackend {
    type NistP256Context = DummyP256;
    fn nist_p256(&self) -> Result<Self::NistP256Context, CryptoError> {
        Ok(DummyP256)
    }

    type NistP192Context = !;
    type NistP224Context = !;
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
}

#[test]
#[cfg(feature = "ecc_curve_nist_p256")]
fn test_ecc_ctx_and_helpers() {
    let backend = DummyBackend;
    let pt = [1u8; 64];
    assert_eq!(
        validate_point(&backend, TpmEccCurve::NistP256, &pt),
        Ok(true)
    );

    // Invalid point length
    assert_eq!(
        validate_point(&backend, TpmEccCurve::NistP256, &[1u8; 63]),
        Ok(false)
    );

    let scalar = [2u8; 32];
    let mut out = [0u8; 64];
    assert_eq!(
        point_multiply_generator(&backend, TpmEccCurve::NistP256, &scalar, &mut out),
        Ok(Some(64))
    );
    assert_eq!(out[..32], [2u8; 32]);
    assert_eq!(out[32..], [2u8; 32]);

    // Buffer too small
    let mut small_out = [0u8; 63];
    assert_eq!(
        point_multiply_generator(&backend, TpmEccCurve::NistP256, &scalar, &mut small_out),
        Err(CryptoError::Internal)
    );

    // point_multiply
    let mut derived = [0u8; 64];
    assert_eq!(
        point_multiply(&backend, TpmEccCurve::NistP256, &scalar, &pt, &mut derived),
        Ok(Some(64))
    );
    assert_eq!(derived[0], 3);

    // ecdaa_sign
    let mut k_out = [0u8; 32];
    let mut s_out = [0u8; 32];
    assert_eq!(
        ecdaa_sign(
            &backend,
            TpmEccCurve::NistP256,
            &[1u8; 32],
            &[],
            &[],
            &[2u8; 32],
            b"digest",
            &mut k_out,
            &mut s_out,
        ),
        Ok(Some(32))
    );
    assert_eq!(k_out, [0xAA; 32]);
    assert_eq!(s_out, [0xBB; 32]);
}

#[test]
#[cfg(feature = "ecc_curve_nist_p384")]
fn test_ecc_unimplemented_curve() {
    let backend = DummyBackend;
    let pt = [1u8; 96];
    assert_eq!(
        validate_point(&backend, TpmEccCurve::NistP384, &pt),
        Err(CryptoError::Unsupported)
    );
}
