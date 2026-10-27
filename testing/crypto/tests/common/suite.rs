//! Tests for a single crypto backend `C`, defined by the including test target.
//!
//! A case for an algorithm, key size, curve, parameter set, or scheme which `C`
//! doesn't implement is skipped if the operation selecting it returns
//! `Err(CryptoError::Unsupported)` (see [`supported`]). Any other error, or a
//! wrong result, fails the test.

use super::C;
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeyInit, consts::U16};
use core::{ffi::CStr, slice};
use testing_crypto::{supported, vectors};
use tpm2::{
    AlgSym, Tpm2b, Tpm2bEccParameter, Tpm2bKemCiphertext, Tpm2bPrivateKeyRsa, Tpm2bPublicKeyMlkem,
    Tpm2bPublicKeyRsa, TpmEccCurve, TpmiAlgCipherMode, TpmiAlgHash, TpmiMldsaParms, TpmiMlkemParms,
    TpmiRsaKeyBits, TpmsEccPoint, TpmsSignatureEcc, TpmtEccScheme, TpmtHa, TpmtSigScheme,
    TpmtSignature,
    crypto::{
        Block, CipherInput, CmacContext, Crypto, CryptoError, Direction, EccPrivateKey,
        EccPublicKey, HashContext, HmacContext, MAX_ECC_COORD_BYTES, MAX_SIGNATURE_BYTES,
        MldsaPrivateKey, MldsaPublicKey, MlkemPrivateKey, MlkemPublicKey, Random, Rng,
        RsaEncryptScheme, RsaPrivateKey, RsaPublicKey, SymmetricContext, SymmetricKey,
        backend::{
            Ecc, EdwardsCurve, Hash, HashState, Mldsa, MldsaKey, Mlkem, MlkemKey, MontgomeryCurve,
            PrivateKey, Rsa, RsaKey,
        },
        hash, hmac, kdfa, kdfa_xor, kdfe,
    },
};

type CRng = <C as Random>::Rng;
type Rsa1024 = <C as Rsa>::Rsa1024;
type Rsa2048 = <C as Rsa>::Rsa2048;
type Ed25519 = <C as Ecc>::Ed25519;
type Ed448 = <C as Ecc>::Ed448;
type X25519 = <C as Ecc>::X25519;
type Mlkem768 = <C as Mlkem>::Mlkem768;
type Mldsa65 = <C as Mldsa>::Mldsa65;

const WEIERSTRASS_CURVES: [TpmEccCurve; 11] = [
    TpmEccCurve::NistP192,
    TpmEccCurve::NistP224,
    TpmEccCurve::NistP256,
    TpmEccCurve::NistP384,
    TpmEccCurve::NistP521,
    TpmEccCurve::BNP256,
    TpmEccCurve::BNP638,
    TpmEccCurve::SM2P256,
    TpmEccCurve::BpP256R1,
    TpmEccCurve::BpP384R1,
    TpmEccCurve::BpP512R1,
];
const MLKEM_PARMS: [TpmiMlkemParms; 3] = [
    TpmiMlkemParms::Mlkem512,
    TpmiMlkemParms::Mlkem768,
    TpmiMlkemParms::Mlkem1024,
];
const MLDSA_PARMS: [TpmiMldsaParms; 3] = [
    TpmiMldsaParms::Mldsa44,
    TpmiMldsaParms::Mldsa65,
    TpmiMldsaParms::Mldsa87,
];

/// `SHA-256("abc")`.
fn sha256_abc() -> TpmtHa<'static> {
    TpmtHa::new(TpmiAlgHash::Sha256, vectors::hash::SHA256[1].1).unwrap()
}

/// Left-pads big-endian `bytes` with zeros to `len` bytes.
fn left_pad(bytes: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    out[len - bytes.len()..].copy_from_slice(bytes);
    out
}

fn ecc_param(bytes: &[u8]) -> Tpm2bEccParameter<'_> {
    Tpm2bEccParameter::new(bytes).unwrap()
}

/// Loads the public part of `key` as an [`EccPublicKey`].
fn ecc_public(key: &EccPrivateKey<C>, scheme: Option<TpmtEccScheme>) -> EccPublicKey<C> {
    let (mut x, mut y) = ([0; MAX_ECC_COORD_BYTES], [0; MAX_ECC_COORD_BYTES]);
    let point = key.point(&mut x, &mut y).unwrap();
    EccPublicKey::load(key.curve(), scheme, point)
        .unwrap()
        .expect("valid public key")
}

// ---------------------------------------------------------------------------
// Constant-time comparison and random number generation
// ---------------------------------------------------------------------------

#[test]
fn ct_eq() {
    assert!(C::ct_eq(b"", b""));
    assert!(C::ct_eq(b"tpm2-crypto", b"tpm2-crypto"));
    assert!(!C::ct_eq(b"tpm2-crypto", b"tpm2-cryptO"));
    assert!(!C::ct_eq(b"short", b"longer"));
}

#[test]
fn rng_from_seed_is_deterministic() {
    let mut a = C::from_seed(b"seed").unwrap();
    let mut b = C::from_seed(b"seed").unwrap();
    let mut c = C::from_seed(b"other seed").unwrap();
    let (mut out_a, mut out_b, mut out_c) = ([0; 128], [0; 128], [0; 128]);
    a.fill_bytes(&mut out_a).unwrap();
    b.fill_bytes(&mut out_b).unwrap();
    c.fill_bytes(&mut out_c).unwrap();
    assert_eq!(out_a, out_b);
    assert_ne!(out_a, out_c);

    // Successive outputs differ.
    a.fill_bytes(&mut out_c).unwrap();
    assert_ne!(out_a, out_c);
}

#[test]
fn rng_stir_is_deterministic() {
    let mut a = C::from_seed(b"seed").unwrap();
    let mut b = C::from_seed(b"seed").unwrap();
    let mut c = C::from_seed(b"seed").unwrap();
    let (mut out_a, mut out_b, mut out_c) = ([0; 64], [0; 64], [0; 64]);
    a.fill_bytes(&mut out_a).unwrap();
    b.fill_bytes(&mut out_b).unwrap();
    c.fill_bytes(&mut out_c).unwrap();

    // Stirring the same data gives the same output, which differs from the
    // unstirred output.
    a.stir_bytes(b"data").unwrap();
    b.stir_bytes(b"data").unwrap();
    a.fill_bytes(&mut out_a).unwrap();
    b.fill_bytes(&mut out_b).unwrap();
    c.fill_bytes(&mut out_c).unwrap();
    assert_eq!(out_a, out_b);
    assert_ne!(out_a, out_c);
}

#[test]
fn rng_from_entropy_is_random() {
    let (mut out_a, mut out_b) = ([0; 64], [0; 64]);
    let mut a = C::from_entropy().unwrap();
    let mut b = C::from_entropy().unwrap();
    a.fill_bytes(&mut out_a).unwrap();
    b.fill_bytes(&mut out_b).unwrap();
    assert_ne!(out_a, out_b);

    // Successive outputs differ.
    a.fill_bytes(&mut out_b).unwrap();
    assert_ne!(out_a, out_b);

    C::rand_bytes(&mut out_a).unwrap();
    C::rand_bytes(&mut out_b).unwrap();
    assert_ne!(out_a, out_b);
}

// ---------------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------------

#[test]
fn hash_one_shot() {
    let mut out = [0; 32];
    let digest = hash::<C>(TpmiAlgHash::Sha256, &[b"abc"], &mut out).unwrap();
    assert_eq!(digest, sha256_abc());
}

/// The parts are hashed as if they were concatenated.
#[test]
fn hash_one_shot_parts() {
    let mut out = [0; 32];
    let digest = hash::<C>(TpmiAlgHash::Sha256, &[b"a", b"", b"bc"], &mut out).unwrap();
    assert_eq!(digest, sha256_abc());

    let digest = hash::<C>(TpmiAlgHash::Sha256, &[], &mut out).unwrap();
    assert_eq!(digest.digest(), vectors::hash::SHA256[0].1);
}

#[test]
fn hash_streaming() {
    let mut ctx = HashContext::<C>::new(TpmiAlgHash::Sha256).unwrap();
    assert_eq!(ctx.alg(), TpmiAlgHash::Sha256);
    ctx.update(b"ab").unwrap();
    ctx.update(b"c").unwrap();
    let mut out = [0; 32];
    assert_eq!(ctx.finalize(&mut out).unwrap(), sha256_abc());
}

#[test]
fn hash_wrong_output_size() {
    let mut out = [0; 31];
    let err = hash::<C>(TpmiAlgHash::Sha256, &[b"abc"], &mut out).unwrap_err();
    assert_eq!(err, CryptoError::Internal);

    let ctx = HashContext::<C>::new(TpmiAlgHash::Sha256).unwrap();
    assert_eq!(ctx.finalize(&mut out).err(), Some(CryptoError::Internal));
}

/// The digest is written to the start of a longer output buffer.
#[test]
fn hash_longer_output_buffer() {
    let mut out = [0xFF; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = hash::<C>(TpmiAlgHash::Sha256, &[b"abc"], &mut out).unwrap();
    assert_eq!(digest, sha256_abc());
    assert!(out[32..].iter().all(|&b| b == 0xFF));
}

/// The dispatch functions use a backend's specialized one-shot methods (like
/// [`HashState::hash`]).
#[test]
fn hash_uses_specialized_one_shot() {
    struct CustomBackend;
    struct CustomSha256;

    impl HashState<32> for CustomSha256 {
        fn init() -> Result<Self, CryptoError> {
            Err(CryptoError::Unsupported)
        }
        fn update(&mut self, _: &[u8]) -> Result<(), CryptoError> {
            unreachable!()
        }
        fn finalize(&mut self, _: &mut [u8; 32]) -> Result<(), CryptoError> {
            unreachable!()
        }
        fn hash(_data: &[&[u8]], out: &mut [u8; 32]) -> Result<(), CryptoError> {
            *out = [0xAA; 32];
            Ok(())
        }
    }

    impl Hash for CustomBackend {
        type Sha1 = !;
        type Sha256 = CustomSha256;
        type Sha384 = !;
        type Sha512 = !;
        type Sm3_256 = !;
        type Sha3_256 = !;
        type Sha3_384 = !;
        type Sha3_512 = !;
    }

    let mut out = [0; 32];
    let digest = hash::<CustomBackend>(TpmiAlgHash::Sha256, &[b"abc"], &mut out).unwrap();
    assert_eq!(digest.digest(), &[0xAA; 32]);
}

#[test]
fn hash_vectors() {
    use vectors::hash::*;
    // (algorithm, (message, digest) pairs, digest of one million 'a' bytes)
    type Case = (
        TpmiAlgHash,
        &'static [(&'static [u8], &'static [u8])],
        &'static [u8],
    );
    let cases: [Case; 8] = [
        (TpmiAlgHash::Sha1, SHA1, &SHA1_MILLION_A),
        (TpmiAlgHash::Sha256, SHA256, &SHA256_MILLION_A),
        (TpmiAlgHash::Sha384, SHA384, &SHA384_MILLION_A),
        (TpmiAlgHash::Sha512, SHA512, &SHA512_MILLION_A),
        (TpmiAlgHash::Sm3_256, SM3_256, &SM3_256_MILLION_A),
        (TpmiAlgHash::Sha3_256, SHA3_256, &SHA3_256_MILLION_A),
        (TpmiAlgHash::Sha3_384, SHA3_384, &SHA3_384_MILLION_A),
        (TpmiAlgHash::Sha3_512, SHA3_512, &SHA3_512_MILLION_A),
    ];
    let mut out = [0; TpmiAlgHash::MAX_DIGEST_BYTES];
    for (alg, kats, million_a) in cases {
        let Some(mut ctx) = supported(HashContext::<C>::new(alg)) else {
            continue;
        };
        for _ in 0..1000 {
            ctx.update(&[b'a'; 1000]).unwrap();
        }
        assert_eq!(
            ctx.finalize(&mut out).unwrap().digest(),
            million_a,
            "{alg:?}"
        );

        for &(msg, digest) in kats {
            let d = hash::<C>(alg, &[msg], &mut out).unwrap();
            assert_eq!(d.digest(), digest, "{alg:?} one-shot");

            let mut ctx = HashContext::<C>::new(alg).unwrap();
            ctx.update(msg).unwrap();
            assert_eq!(ctx.finalize(&mut out).unwrap().digest(), digest, "{alg:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// HMAC and KDFs
// ---------------------------------------------------------------------------

#[test]
fn hmac_one_shot() {
    use vectors::hmac::*;
    let (key, data) = CASES[1];
    let mut out = [0; 32];
    let mac = hmac::<C>(TpmiAlgHash::Sha256, key, &[data], &mut out).unwrap();
    assert_eq!(mac.digest(), SHA256[1]);

    // The parts are MACed as if they were concatenated.
    let (a, b) = data.split_at(7);
    let mut out = [0; 64];
    let mac = hmac::<C>(TpmiAlgHash::Sha512, key, &[a, b], &mut out).unwrap();
    assert_eq!(mac.digest(), SHA512[1]);

    // RFC 4231, test case 6 (131-byte key > 128-byte SHA-512 block size).
    let (key, data) = CASES[4];
    let mac = hmac::<C>(TpmiAlgHash::Sha512, key, &[data], &mut out).unwrap();
    assert_eq!(mac.digest(), SHA512[4]);
}

#[test]
fn hmac_streaming() {
    use vectors::hmac::*;
    let (key, data) = CASES[1];
    let (a, b) = data.split_at(7);
    let mut out = [0; TpmiAlgHash::MAX_DIGEST_BYTES];
    for (alg, mac) in [
        (TpmiAlgHash::Sha256, SHA256[1]),
        (TpmiAlgHash::Sha512, SHA512[1]),
    ] {
        let mut ctx = HmacContext::<C>::new(alg, key).unwrap();
        assert_eq!(ctx.alg(), alg);
        ctx.update(a).unwrap();
        ctx.update(b).unwrap();
        assert_eq!(ctx.finalize(&mut out).unwrap().digest(), mac, "{alg:?}");
    }

    // Empty key.
    let mut ctx = HmacContext::<C>::new(TpmiAlgHash::Sha256, b"").unwrap();
    ctx.update(b"part1").unwrap();
    ctx.update(b"part2").unwrap();
    let mut expected = [0; 32];
    hmac::<C>(TpmiAlgHash::Sha256, b"", &[b"part1part2"], &mut expected).unwrap();
    assert_eq!(ctx.finalize(&mut out).unwrap().digest(), expected);
}

#[test]
fn hmac_vectors() {
    use vectors::hmac::*;
    let cases: [(TpmiAlgHash, &[&[u8]]); 8] = [
        (TpmiAlgHash::Sha1, SHA1),
        (TpmiAlgHash::Sha256, SHA256),
        (TpmiAlgHash::Sha384, SHA384),
        (TpmiAlgHash::Sha512, SHA512),
        (TpmiAlgHash::Sm3_256, SM3_256),
        (TpmiAlgHash::Sha3_256, SHA3_256),
        (TpmiAlgHash::Sha3_384, SHA3_384),
        (TpmiAlgHash::Sha3_512, SHA3_512),
    ];
    let mut out = [0; TpmiAlgHash::MAX_DIGEST_BYTES];
    for (alg, macs) in cases {
        for (&(key, data), &mac) in CASES.iter().zip(macs) {
            let Some(mut ctx) = supported(HmacContext::<C>::new(alg, key)) else {
                break;
            };
            ctx.update(data).unwrap();
            assert_eq!(ctx.finalize(&mut out).unwrap().digest(), mac, "{alg:?}");

            let m = hmac::<C>(alg, key, &[data], &mut out).unwrap();
            assert_eq!(m.digest(), mac, "{alg:?} one-shot");
        }
    }
}

/// A single-block KDFa is `HMAC(key, [1]_32 || label || 0 || u || v || [bits]_32)`.
#[test]
fn kdfa_single_block_matches_hmac() {
    let (key, label, u, v): (&[u8], &CStr, &[u8], &[u8]) = (b"secret", c"ATH", b"uu", b"vvv");
    let mut derived = [0; 32];
    kdfa::<C>(TpmiAlgHash::Sha256, key, label, (u, v), &mut derived).unwrap();

    let msg = [
        &1u32.to_be_bytes()[..],
        label.to_bytes_with_nul(),
        u,
        v,
        &256u32.to_be_bytes(),
    ];
    let mut expected = [0; 32];
    hmac::<C>(TpmiAlgHash::Sha256, key, &msg, &mut expected).unwrap();
    assert_eq!(derived, expected);
}

/// `kdfa_xor` XORs the `kdfa` output (with `[L]_2` set from `data.len()`) into
/// `data`, including a partial final block, and is its own inverse.
#[test]
fn kdfa_xor_matches_kdfa() {
    let (key, label, u, v): (&[u8], &CStr, &[u8], &[u8]) = (b"secret", c"XOR", b"uu", b"vvv");
    let plain: [u8; 70] = core::array::from_fn(|i| i as u8);
    let mut mask = [0; 70];
    kdfa::<C>(TpmiAlgHash::Sha256, key, label, (u, v), &mut mask).unwrap();

    let mut data = plain;
    kdfa_xor::<C>(TpmiAlgHash::Sha256, key, label, (u, v), &mut data).unwrap();
    let expected: [u8; 70] = core::array::from_fn(|i| plain[i] ^ mask[i]);
    assert_eq!(data, expected);

    kdfa_xor::<C>(TpmiAlgHash::Sha256, key, label, (u, v), &mut data).unwrap();
    assert_eq!(data, plain);
}

/// A single-block KDFe is `H([1]_32 || z || label || 0 || u || v)`.
#[test]
fn kdfe_single_block_matches_hash() {
    let (z, label, u, v): (&[u8], &CStr, &[u8], &[u8]) = (b"shared_z", c"ECDH", b"uu", b"vvv");
    let mut derived = [0; 32];
    kdfe::<C>(TpmiAlgHash::Sha256, z, label, (u, v), &mut derived).unwrap();

    let msg = [&1u32.to_be_bytes()[..], z, label.to_bytes_with_nul(), u, v];
    let mut expected = [0; 32];
    hash::<C>(TpmiAlgHash::Sha256, &msg, &mut expected).unwrap();
    assert_eq!(derived, expected);
}

#[test]
fn kdf_vectors() {
    use vectors::kdf::*;
    let cases: [(TpmiAlgHash, &[KdfKat], &[KdfKat]); 8] = [
        (TpmiAlgHash::Sha1, &KDFA_SHA1, &KDFE_SHA1),
        (TpmiAlgHash::Sha256, &KDFA_SHA256, &KDFE_SHA256),
        (TpmiAlgHash::Sha384, &KDFA_SHA384, &KDFE_SHA384),
        (TpmiAlgHash::Sha512, &KDFA_SHA512, &KDFE_SHA512),
        (TpmiAlgHash::Sm3_256, &KDFA_SM3_256, &KDFE_SM3_256),
        (TpmiAlgHash::Sha3_256, &KDFA_SHA3_256, &KDFE_SHA3_256),
        (TpmiAlgHash::Sha3_384, &KDFA_SHA3_384, &KDFE_SHA3_384),
        (TpmiAlgHash::Sha3_512, &KDFA_SHA3_512, &KDFE_SHA3_512),
    ];
    let mut buf = [0; 1024];
    for (alg, kdfa_kats, kdfe_kats) in cases {
        for kat in kdfa_kats {
            let out = &mut buf[..kat.out.len()];
            let context = (kat.context_u, kat.context_v);
            if supported(kdfa::<C>(alg, kat.key, kat.label, context, out)).is_some() {
                assert_eq!(out, kat.out, "KDFa {alg:?}");
            }
        }
        for kat in kdfe_kats {
            let out = &mut buf[..kat.out.len()];
            let context = (kat.context_u, kat.context_v);
            if supported(kdfe::<C>(alg, kat.key, kat.label, context, out)).is_some() {
                assert_eq!(out, kat.out, "KDFe {alg:?}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Symmetric ciphers and CMAC
// ---------------------------------------------------------------------------

/// The initial IV of `mode` for the NIST SP 800-38A vectors.
fn sp800_38a_iv(mode: TpmiAlgCipherMode) -> Block {
    use vectors::cipher::*;
    match mode {
        TpmiAlgCipherMode::Ctr => CTR_IV,
        TpmiAlgCipherMode::Ecb => [0; 16],
        _ => IV,
    }
}

/// Encrypts or decrypts `data` in place with a one-shot `key.crypt`, updating
/// `iv` (which is ignored for ECB).
fn crypt_once(
    key: SymmetricKey<'_>,
    mode: TpmiAlgCipherMode,
    dir: Direction,
    iv: &mut Block,
    data: &mut [u8],
) -> Result<(), CryptoError> {
    let iv: &mut [u8] = if mode == TpmiAlgCipherMode::Ecb {
        &mut []
    } else {
        iv
    };
    key.crypt::<C>(dir, CipherInput::new(mode, iv, data).unwrap())
}

/// Like [`crypt_once`], but with a [`SymmetricContext`].
fn crypt_context(
    ctx: &SymmetricContext<C>,
    mode: TpmiAlgCipherMode,
    dir: Direction,
    iv: &mut Block,
    data: &mut [u8],
) -> Result<(), CryptoError> {
    let iv: &mut [u8] = if mode == TpmiAlgCipherMode::Ecb {
        &mut []
    } else {
        iv
    };
    ctx.crypt(dir, CipherInput::new(mode, iv, data).unwrap())
}

#[test]
fn fips197_ecb() {
    use vectors::cipher::*;
    for (alg, key, ct) in FIPS197 {
        let key = SymmetricKey::new(alg, key).unwrap();
        let ctx = SymmetricContext::<C>::new(key).unwrap();
        assert_eq!(ctx.alg(), alg);

        let mut block = FIPS197_PLAINTEXT;
        let input = CipherInput::Ecb(slice::from_mut(&mut block));
        ctx.crypt(Direction::Encrypt, input).unwrap();
        assert_eq!(block, ct, "{alg:?}");
        let input = CipherInput::Ecb(slice::from_mut(&mut block));
        key.crypt::<C>(Direction::Decrypt, input).unwrap();
        assert_eq!(block, FIPS197_PLAINTEXT, "{alg:?}");
    }
}

/// NIST SP 800-38A (AES) and equivalent (SM4, Camellia) vectors for every
/// mode, including the chaining value (`ivOut`).
#[test]
fn cipher_vectors() {
    use vectors::cipher::*;
    // (algorithm, key, (ciphertext, ivOut) per mode)
    type Case = (AlgSym, &'static [u8], &'static [([u8; 64], Block); 5]);
    let cases: [Case; 7] = [
        (AlgSym::Aes128, &KEY128, &MODES_AES128),
        (AlgSym::Aes192, &KEY192, &MODES_AES192),
        (AlgSym::Aes256, &KEY256, &MODES_AES256),
        (AlgSym::Sm4_128, &KEY128, &MODES_SM4_128),
        (AlgSym::Camellia128, &KEY128, &MODES_CAMELLIA128),
        (AlgSym::Camellia192, &KEY192, &MODES_CAMELLIA192),
        (AlgSym::Camellia256, &KEY256, &MODES_CAMELLIA256),
    ];
    for (alg, key, table) in cases {
        let key = SymmetricKey::new(alg, key).unwrap();
        let Some(ctx) = supported(SymmetricContext::<C>::new(key)) else {
            continue;
        };
        for (mode, (ct, iv_out)) in MODES.into_iter().zip(table) {
            let (mut data, mut iv) = (PLAINTEXT, sp800_38a_iv(mode));
            crypt_once(key, mode, Direction::Encrypt, &mut iv, &mut data).unwrap();
            assert_eq!((&data, &iv), (ct, iv_out), "{alg:?} {mode:?} encrypt");

            let mut iv = sp800_38a_iv(mode);
            crypt_context(&ctx, mode, Direction::Decrypt, &mut iv, &mut data).unwrap();
            assert_eq!(
                (&data, &iv),
                (&PLAINTEXT, iv_out),
                "{alg:?} {mode:?} decrypt"
            );
        }
    }
}

/// Encrypting in two chained calls (passing `ivOut` along) matches a single
/// call, for block-aligned splits.
#[test]
fn cipher_chaining_matches_single_call() {
    use vectors::cipher::*;
    let key = SymmetricKey::Aes128(&KEY128);
    for (mode, (ct, _)) in MODES.into_iter().zip(&MODES_AES128) {
        let (mut data, mut iv) = (PLAINTEXT, sp800_38a_iv(mode));
        let (a, b) = data.split_at_mut(32);
        crypt_once(key, mode, Direction::Encrypt, &mut iv, a).unwrap();
        crypt_once(key, mode, Direction::Encrypt, &mut iv, b).unwrap();
        assert_eq!(&data, ct, "{mode:?}");
    }
}

/// A direct port of `CryptSymmetricEncrypt` and `CryptSymmetricDecrypt` from
/// the TPM reference implementation (`CryptSym.c`).
fn reference_crypt<B>(
    cipher: &B,
    mode: TpmiAlgCipherMode,
    dir: Direction,
    iv: &mut Block,
    data: &mut [u8],
) where
    B: BlockCipherEncrypt + BlockCipherDecrypt + BlockSizeUser<BlockSize = U16>,
{
    let enc = |b: &mut Block| cipher.encrypt_block(b.into());
    let dec = |b: &mut Block| cipher.decrypt_block(b.into());
    for chunk in data.chunks_mut(16) {
        let n = chunk.len();
        match (mode, dir) {
            (TpmiAlgCipherMode::Ctr, _) => {
                let mut tmp = *iv;
                enc(&mut tmp);
                for i in (0..16).rev() {
                    iv[i] = iv[i].wrapping_add(1);
                    if iv[i] != 0 {
                        break;
                    }
                }
                (0..n).for_each(|i| chunk[i] ^= tmp[i]);
            }
            (TpmiAlgCipherMode::Ofb, _) => {
                enc(iv);
                (0..n).for_each(|i| chunk[i] ^= iv[i]);
            }
            (TpmiAlgCipherMode::Cbc, Direction::Encrypt) => {
                (0..16).for_each(|i| iv[i] ^= chunk[i]);
                enc(iv);
                chunk.copy_from_slice(iv);
            }
            (TpmiAlgCipherMode::Cbc, Direction::Decrypt) => {
                let tmp: Block = (&*chunk).try_into().unwrap();
                let mut out = tmp;
                dec(&mut out);
                (0..16).for_each(|i| chunk[i] = out[i] ^ iv[i]);
                *iv = tmp;
            }
            (TpmiAlgCipherMode::Cfb, Direction::Encrypt) => {
                enc(iv);
                (0..n).for_each(|i| {
                    iv[i] ^= chunk[i];
                    chunk[i] = iv[i];
                });
                iv[n..].fill(0);
            }
            (TpmiAlgCipherMode::Cfb, Direction::Decrypt) => {
                let mut tmp = *iv;
                enc(&mut tmp);
                (0..n).for_each(|i| {
                    iv[i] = chunk[i];
                    chunk[i] ^= tmp[i];
                });
                iv[n..].fill(0);
            }
            (TpmiAlgCipherMode::Ecb, Direction::Encrypt) => enc(chunk.try_into().unwrap()),
            (TpmiAlgCipherMode::Ecb, Direction::Decrypt) => dec(chunk.try_into().unwrap()),
        }
    }
}

/// Every mode, direction, and (partial) data length produces the same data
/// and chaining value (`ivOut`) as the reference implementation, including
/// CTR counter carries and wraparound and CFB/OFB partial final blocks.
#[test]
fn cipher_matches_reference_implementation() {
    use vectors::cipher::*;
    let aes128 = aes::Aes128::new(&KEY128.into());
    let aes256 = aes::Aes256::new(&KEY256.into());
    let ctx128 = SymmetricContext::<C>::new(SymmetricKey::Aes128(&KEY128)).unwrap();
    let ctx256 = SymmetricContext::<C>::new(SymmetricKey::Aes256(&KEY256)).unwrap();
    let ivs = [
        IV,
        [0xff; 16],
        hex_literal::hex!("0102030405060708090a0b0cfffffffe"),
    ];
    let msg: Vec<u8> = (0..=255).collect();

    for mode in MODES {
        let block_mode = matches!(mode, TpmiAlgCipherMode::Cbc | TpmiAlgCipherMode::Ecb);
        for len in (0..=70).filter(|len| !block_mode || len % 16 == 0) {
            for iv0 in ivs {
                for dir in [Direction::Encrypt, Direction::Decrypt] {
                    let case = format!("{mode:?} {dir:?} len={len} iv={iv0:02x?}");

                    let (mut want, mut want_iv) = (msg[..len].to_vec(), iv0);
                    reference_crypt(&aes128, mode, dir, &mut want_iv, &mut want);
                    let (mut got, mut got_iv) = (msg[..len].to_vec(), iv0);
                    crypt_context(&ctx128, mode, dir, &mut got_iv, &mut got).unwrap();
                    assert_eq!((&got, got_iv), (&want, want_iv), "AES-128 {case}");

                    let (mut want, mut want_iv) = (msg[..len].to_vec(), iv0);
                    reference_crypt(&aes256, mode, dir, &mut want_iv, &mut want);
                    let (mut got, mut got_iv) = (msg[..len].to_vec(), iv0);
                    let key = SymmetricKey::Aes256(&KEY256);
                    crypt_once(key, mode, dir, &mut got_iv, &mut got).unwrap();
                    assert_eq!((&got, got_iv), (&want, want_iv), "AES-256 one-shot {case}");

                    let (mut got, mut got_iv) = (msg[..len].to_vec(), iv0);
                    crypt_context(&ctx256, mode, dir, &mut got_iv, &mut got).unwrap();
                    assert_eq!((&got, got_iv), (&want, want_iv), "AES-256 context {case}");
                }
            }
        }
    }
}

#[test]
fn cipher_input_validation() {
    let mut iv = [0; 16];
    let mut short_iv = [0; 15];
    let mut data = [0; 17];

    // Stream modes accept any data length, but need a full block IV.
    for mode in [
        TpmiAlgCipherMode::Ctr,
        TpmiAlgCipherMode::Ofb,
        TpmiAlgCipherMode::Cfb,
    ] {
        let input = CipherInput::new(mode, &mut iv, &mut data).unwrap();
        assert_eq!(input.mode(), mode);
        assert!(CipherInput::new(mode, &mut short_iv, &mut data).is_none());
        assert!(CipherInput::new(mode, &mut [], &mut data).is_none());
    }

    // Block modes need block-aligned data.
    let mode = TpmiAlgCipherMode::Cbc;
    assert!(CipherInput::new(mode, &mut iv, &mut data).is_none());
    assert!(CipherInput::new(mode, &mut short_iv, &mut data[..16]).is_none());
    let input = CipherInput::new(mode, &mut iv, &mut data[..16]).unwrap();
    assert_eq!(input.mode(), mode);

    // ECB needs an empty IV.
    let mode = TpmiAlgCipherMode::Ecb;
    assert!(CipherInput::new(mode, &mut iv, &mut data[..16]).is_none());
    assert!(CipherInput::new(mode, &mut [], &mut data).is_none());
    let input = CipherInput::new(mode, &mut [], &mut data[..16]).unwrap();
    assert_eq!(input.mode(), mode);
}

#[test]
fn symmetric_key_validation() {
    use vectors::cipher::*;
    assert!(SymmetricKey::new(AlgSym::Aes256, &KEY128).is_none());
    assert!(SymmetricKey::new(AlgSym::Aes128, &KEY256).is_none());

    let key = SymmetricKey::new(AlgSym::Aes256, &KEY256).unwrap();
    assert_eq!(key.alg(), AlgSym::Aes256);
    assert_eq!(key.bytes(), KEY256);
}

/// NIST SP 800-38B (AES) and equivalent (SM4, Camellia) vectors, both
/// one-shot and streaming, with the message split in two parts.
#[test]
fn cmac_vectors() {
    use vectors::cipher::*;
    // (algorithm, key, MAC per message length)
    type Case = (AlgSym, &'static [u8], &'static [[u8; 16]; 4]);
    let cases: [Case; 7] = [
        (AlgSym::Aes128, &KEY128, &CMAC_AES128),
        (AlgSym::Aes192, &KEY192, &CMAC_AES192),
        (AlgSym::Aes256, &KEY256, &CMAC_AES256),
        (AlgSym::Sm4_128, &KEY128, &CMAC_SM4_128),
        (AlgSym::Camellia128, &KEY128, &CMAC_CAMELLIA128),
        (AlgSym::Camellia192, &KEY192, &CMAC_CAMELLIA192),
        (AlgSym::Camellia256, &KEY256, &CMAC_CAMELLIA256),
    ];
    for (alg, key, macs) in cases {
        let key = SymmetricKey::new(alg, key).unwrap();
        for (&len, mac) in CMAC_LENS.iter().zip(macs) {
            let Some(mut ctx) = supported(CmacContext::<C>::new(key)) else {
                break;
            };
            assert_eq!(ctx.alg(), alg);
            let (a, b) = PLAINTEXT[..len].split_at(len / 2);
            let mut out = [0; 16];
            ctx.update(a).unwrap();
            ctx.update(b).unwrap();
            ctx.finalize(&mut out).unwrap();
            assert_eq!(&out, mac, "{alg:?} len={len}");

            key.cmac::<C>(&[a, b], &mut out).unwrap();
            assert_eq!(&out, mac, "{alg:?} one-shot len={len}");
        }
    }
}

// ---------------------------------------------------------------------------
// RSA
// ---------------------------------------------------------------------------

/// Verifies the RSASSA (SHA-256) signature `sig` of `SHA-256("abc")` under
/// modulus `n`.
fn check_rsassa_vector<K, const MOD: usize, const PRIME: usize>(n: &[u8; MOD], sig: &[u8; MOD])
where
    K: RsaKey<MOD, PRIME, CRng>,
{
    let Some(public) = supported(K::load_public(65537, n)) else {
        return;
    };
    let public = public.expect("valid modulus");
    assert!(
        K::rsassa_verify(&public, sha256_abc(), sig).unwrap(),
        "RSA-{}",
        MOD * 8
    );
}

#[test]
fn rsa_signature_vectors() {
    use vectors::rsa::*;
    check_rsassa_vector::<Rsa1024, 128, 64>(&N1024, &RSASSA_SHA256_1024);
    check_rsassa_vector::<Rsa2048, 256, 128>(&N2048, &RSASSA_SHA256_2048);
    check_rsassa_vector::<<C as Rsa>::Rsa3072, 384, 192>(&N3072, &RSASSA_SHA256_3072);
    check_rsassa_vector::<<C as Rsa>::Rsa4096, 512, 256>(&N4096, &RSASSA_SHA256_4096);

    let Some(public) = supported(Rsa2048::load_public(65537, &N2048)) else {
        return;
    };
    let public = public.expect("valid modulus");
    assert!(Rsa2048::rsapss_verify(&public, sha256_abc(), &RSAPSS_SHA256_2048).unwrap());
}

#[test]
fn rsa_decryption_vectors() {
    use vectors::rsa::*;
    let mut rng = C::from_seed(b"rsa_decryption_vectors").unwrap();
    let Some(public) = supported(Rsa2048::load_public(65537, &N2048)) else {
        return;
    };
    let key = Rsa2048::load(public.expect("valid modulus"), &P2048)
        .unwrap()
        .expect("valid prime");
    let mut out = [0; 256];

    assert_eq!(
        key.raw_decrypt(&mut rng, &RAW_C2048, &mut out),
        Ok(Some(()))
    );
    assert_eq!(out, RAW_M2048);

    let len = key.rsaes_decrypt(&mut rng, &RSAES_C2048, &mut out);
    assert_eq!(&out[..len.unwrap().unwrap()], MESSAGE, "RSAES");

    let len = key.oaep_decrypt(&mut rng, TpmiAlgHash::Sha1, b"", &OAEP_SHA1_C2048, &mut out);
    assert_eq!(&out[..len.unwrap().unwrap()], MESSAGE, "OAEP SHA-1");

    let label = c"DUPLICATE".to_bytes_with_nul();
    let len = key.oaep_decrypt(
        &mut rng,
        TpmiAlgHash::Sha256,
        label,
        &OAEP_SHA256_C2048,
        &mut out,
    );
    assert_eq!(&out[..len.unwrap().unwrap()], MESSAGE, "OAEP SHA-256");
}

/// Generates an RSA-1024 key, returning it with its modulus and prime `p`.
fn generate_rsa1024(rng: &mut CRng) -> Option<(Rsa1024, [u8; 128], [u8; 64])> {
    let key = supported(Rsa1024::generate(rng, 65537))?;
    let (mut n, mut p) = ([0; 128], [0; 64]);
    Rsa1024::store_public(key.as_public(), &mut n).unwrap();
    key.store(&mut p).unwrap();
    Some((key, n, p))
}

#[test]
fn rsa_generate_is_deterministic() {
    let mut rng1 = C::from_seed(b"rsa_generate_is_deterministic").unwrap();
    let mut rng2 = C::from_seed(b"rsa_generate_is_deterministic").unwrap();
    let Some((key, n1, p1)) = generate_rsa1024(&mut rng1) else {
        return;
    };
    let (_, n2, p2) = generate_rsa1024(&mut rng2).unwrap();
    assert_eq!((n1, p1), (n2, p2));
    assert_eq!(Rsa1024::exponent(key.as_public()), 65537);
}

#[test]
fn rsa_load_validates_keys() {
    let mut rng = C::from_seed(b"rsa_load_validates_keys").unwrap();
    let Some((_, n, p)) = generate_rsa1024(&mut rng) else {
        return;
    };
    let (_, _, other_p) = generate_rsa1024(&mut rng).unwrap();
    let load_public = || Rsa1024::load_public(65537, &n).unwrap().unwrap();

    let key = Rsa1024::load(load_public(), &p).unwrap().unwrap();
    let mut stored = [0; 64];
    key.store(&mut stored).unwrap();
    assert_eq!(stored, p);

    // Modulus with the top bit clear.
    let mut bad_n = n;
    bad_n[0] &= 0x7f;
    assert!(Rsa1024::load_public(65537, &bad_n).unwrap().is_none());

    // Even prime, and another key's prime.
    let mut bad_p = p;
    bad_p[63] &= 0xfe;
    assert!(Rsa1024::load(load_public(), &bad_p).unwrap().is_none());
    assert!(Rsa1024::load(load_public(), &other_p).unwrap().is_none());
}

/// Raw RSA (`TPM_ALG_NULL`) encryption.
#[test]
fn rsa_raw_encryption() {
    let mut rng = C::from_seed(b"rsa_raw_encryption").unwrap();
    let Some((key, n, _)) = generate_rsa1024(&mut rng) else {
        return;
    };
    let mut input = [0; 128];
    input[1] = 0x42;
    input[127] = 0x99;
    let (mut ct, mut pt) = ([0; 128], [0; 128]);
    let public = key.as_public();
    assert_eq!(Rsa1024::raw_encrypt(public, &input, &mut ct), Ok(Some(())));
    assert_ne!(ct, input);
    assert_eq!(key.raw_decrypt(&mut rng, &ct, &mut pt), Ok(Some(())));
    assert_eq!(pt, input);

    // Plaintext or ciphertext `>= n`.
    for big in [&n, &[0xff; 128]] {
        assert_eq!(Rsa1024::raw_encrypt(public, big, &mut [0; 128]), Ok(None));
    }
    assert_eq!(key.raw_decrypt(&mut rng, &n, &mut pt), Ok(None));

    // Dispatch: short inputs and extra leading zeros are the same integer, and
    // inputs longer than the modulus are rejected.
    let modulus = Tpm2bPublicKeyRsa::new(&n).unwrap();
    let public = RsaPublicKey::<C>::load(TpmiRsaKeyBits::Rsa1024, 0, modulus)
        .unwrap()
        .unwrap();
    let mut out = [0; 512];
    let mut long_input = [0; 130];
    long_input[2..].copy_from_slice(&input);
    for input in [&input[..], &input[1..], &long_input[..]] {
        let got = public.encrypt(&mut rng, RsaEncryptScheme::Raw, input, &mut out);
        assert_eq!(got.unwrap().unwrap().as_slice(), ct);
    }
    let mut too_long = [0; 129];
    too_long[0] = 1;
    let got = public.encrypt(&mut rng, RsaEncryptScheme::Raw, &too_long, &mut out);
    assert!(got.unwrap().is_none());
}

/// RSAES and OAEP encryption round trips, and tampered ciphertexts are rejected
/// (RSAES may instead use implicit rejection; see [`RsaKey::rsaes_decrypt`]).
#[test]
fn rsa_encryption_round_trip() {
    let mut rng = C::from_entropy().unwrap();
    let Some((key, n, p)) = generate_rsa1024(&mut rng) else {
        return;
    };
    let public = key.as_public();
    let msg = b"secret message";
    for scheme in [
        RsaEncryptScheme::Rsaes,
        RsaEncryptScheme::Oaep {
            hash: TpmiAlgHash::Sha1,
            label: Some(c"DUPLICATE"),
        },
        RsaEncryptScheme::Oaep {
            hash: TpmiAlgHash::Sha256,
            label: Some(c"DUPLICATE"),
        },
        RsaEncryptScheme::Oaep {
            hash: TpmiAlgHash::Sha384,
            label: None,
        },
    ] {
        let label = scheme.label_bytes();
        let mut ct = [0; 128];
        match scheme {
            RsaEncryptScheme::Oaep { hash, .. } => {
                Rsa1024::oaep_encrypt(public, &mut rng, hash, label, msg, &mut ct)
            }
            _ => Rsa1024::rsaes_encrypt(public, &mut rng, msg, &mut ct),
        }
        .unwrap()
        .unwrap();

        let mut decrypt = |ct: &[u8; 128], pt: &mut [u8; 128]| match scheme {
            RsaEncryptScheme::Oaep { hash, .. } => key.oaep_decrypt(&mut rng, hash, label, ct, pt),
            _ => key.rsaes_decrypt(&mut rng, ct, pt),
        };
        let mut pt = [0; 128];
        let len = decrypt(&ct, &mut pt).unwrap().unwrap();
        assert_eq!(&pt[..len], msg, "{scheme:?}");

        ct[127] ^= 1;
        match (scheme, decrypt(&ct, &mut pt).unwrap()) {
            (_, None) => {}
            // Implicit rejection: a synthetic message, never the original.
            (RsaEncryptScheme::Rsaes, Some(len)) => assert_ne!(&pt[..len], msg),
            (_, Some(_)) => panic!("{scheme:?} accepted a tampered ciphertext"),
        }
    }

    // Dispatch.
    let modulus = Tpm2bPublicKeyRsa::new(&n).unwrap();
    let public = RsaPublicKey::<C>::load(TpmiRsaKeyBits::Rsa1024, 0, modulus)
        .unwrap()
        .unwrap();
    let mut ct = [0; 512];
    let len = public
        .encrypt(&mut rng, RsaEncryptScheme::Rsaes, b"hello", &mut ct)
        .unwrap()
        .unwrap()
        .as_slice()
        .len();
    let prime = Tpm2bPrivateKeyRsa::new(&p).unwrap();
    let key = RsaPrivateKey::<C>::load(public, prime).unwrap().unwrap();
    let mut pt = [0; 512];
    let got = key.decrypt(&mut rng, RsaEncryptScheme::Rsaes, &ct[..len], &mut pt);
    assert_eq!(got.unwrap().unwrap().as_slice(), b"hello");
}

/// RSASSA and RSAPSS (the SHA-512 RSAPSS salt is truncated to 62 bytes on
/// RSA-1024) sign/verify round trips, and invalid signatures are rejected.
#[test]
fn rsa_signature_round_trip() {
    let mut rng = C::from_entropy().unwrap();
    let Some((key, n, _)) = generate_rsa1024(&mut rng) else {
        return;
    };
    let public = key.as_public();
    let digest_bytes = [0x5a; 64];
    for (pss, alg) in [
        (false, TpmiAlgHash::Sha256),
        (true, TpmiAlgHash::Sha256),
        (false, TpmiAlgHash::Sha512),
        (true, TpmiAlgHash::Sha512),
    ] {
        let digest = TpmtHa::new(alg, &digest_bytes[..alg.digest_size()]).unwrap();
        let verify = |sig: &[u8; 128]| {
            if pss {
                Rsa1024::rsapss_verify(public, digest, sig)
            } else {
                Rsa1024::rsassa_verify(public, digest, sig)
            }
        };
        let mut sig = [0; 128];
        if pss {
            key.rsapss_sign(&mut rng, digest, &mut sig).unwrap();
        } else {
            key.rsassa_sign(&mut rng, digest, &mut sig).unwrap();
        }
        assert!(verify(&sig).unwrap(), "pss={pss} {alg:?}");

        let mut bad_sig = sig;
        bad_sig[127] ^= 1;
        assert!(!verify(&bad_sig).unwrap(), "pss={pss} {alg:?}");
        // Signature `>= n`.
        assert!(!verify(&n).unwrap(), "pss={pss} {alg:?}");
    }
}

// ---------------------------------------------------------------------------
// ECC: Weierstrass curves
// ---------------------------------------------------------------------------

#[test]
fn ecdsa_vectors() {
    for kat in vectors::ecc::ECDSA {
        assert_eq!(kat.digest.len(), kat.hash.digest_size());
        let point = TpmsEccPoint {
            x: ecc_param(kat.q.0),
            y: ecc_param(kat.q.1),
        };
        let Some(public) = supported(EccPublicKey::<C>::load(kat.curve, None, point)) else {
            continue;
        };
        let public = public.expect("valid public key");
        let sig = TpmsSignatureEcc {
            hash: kat.hash,
            signature_r: ecc_param(kat.sig.0),
            signature_s: ecc_param(kat.sig.1),
        };
        let sig = if kat.curve == TpmEccCurve::SM2P256 {
            TpmtSignature::Sm2(sig)
        } else {
            TpmtSignature::Ecdsa(sig)
        };
        let valid = public.verify(kat.digest, sig);
        assert!(valid.unwrap(), "{:?}", kat.curve);
    }
}

#[test]
fn ecdh_vectors() {
    for kat in vectors::ecc::ECDH {
        let point = TpmsEccPoint {
            x: ecc_param(kat.q.0),
            y: ecc_param(kat.q.1),
        };
        let Some(public) = supported(EccPublicKey::<C>::load(kat.curve, None, point)) else {
            continue;
        };
        let key = EccPrivateKey::load(public.expect("valid public key"), ecc_param(kat.d))
            .unwrap()
            .expect("valid private key");
        let len = key.key_bytes();

        let (mut x, mut y) = ([0; MAX_ECC_COORD_BYTES], [0; MAX_ECC_COORD_BYTES]);
        let q = key.point(&mut x, &mut y).unwrap();
        assert_eq!(q.x.as_slice(), left_pad(kat.q.0, len), "{:?}", kat.curve);
        assert_eq!(q.y.as_slice(), left_pad(kat.q.1, len), "{:?}", kat.curve);

        let point = TpmsEccPoint {
            x: ecc_param(kat.peer.0),
            y: ecc_param(kat.peer.1),
        };
        let peer = EccPublicKey::<C>::load(kat.curve, None, point)
            .unwrap()
            .expect("valid peer key");
        let (mut x, mut y) = ([0; MAX_ECC_COORD_BYTES], [0; MAX_ECC_COORD_BYTES]);
        let z = key.ecdh(&peer, &mut x, &mut y).unwrap().unwrap();
        assert_eq!(z.x.as_slice(), left_pad(kat.z.0, len), "{:?}", kat.curve);
        assert_eq!(z.y.as_slice(), left_pad(kat.z.1, len), "{:?}", kat.curve);
    }
}

/// Generated keys round trip through their encodings, and invalid points and
/// scalars are rejected.
#[test]
fn ecc_key_round_trip() {
    let mut rng = C::from_seed(b"ecc_key_round_trip").unwrap();
    for curve in WEIERSTRASS_CURVES {
        let Some(key) = supported(EccPrivateKey::<C>::generate(&mut rng, curve, None)) else {
            continue;
        };
        let other = EccPrivateKey::<C>::generate(&mut rng, curve, None).unwrap();
        let len = key.key_bytes();

        // Point not on the curve.
        let point = TpmsEccPoint {
            x: ecc_param(&[1]),
            y: ecc_param(&[1]),
        };
        let loaded = EccPublicKey::<C>::load(curve, None, point).unwrap();
        assert!(loaded.is_none(), "{curve:?}");

        let (mut x, mut y) = ([0; MAX_ECC_COORD_BYTES], [0; MAX_ECC_COORD_BYTES]);
        let point = key.point(&mut x, &mut y).unwrap();
        let load_public = || {
            EccPublicKey::<C>::load(curve, None, point)
                .unwrap()
                .unwrap()
        };
        let (mut x2, mut y2) = ([0; MAX_ECC_COORD_BYTES], [0; MAX_ECC_COORD_BYTES]);
        assert_eq!(
            load_public().point(&mut x2, &mut y2).unwrap(),
            point,
            "{curve:?}"
        );

        // Scalars `0`, `>= n`, and another key's scalar.
        let mut other_d = [0; MAX_ECC_COORD_BYTES];
        let other_d = other.scalar(&mut other_d).unwrap();
        let too_big = [0xff; MAX_ECC_COORD_BYTES];
        for bad in [&[0][..], &too_big[..len], other_d.as_slice()] {
            let loaded = EccPrivateKey::load(load_public(), ecc_param(bad)).unwrap();
            assert!(loaded.is_none(), "{curve:?}");
        }

        let mut d = [0; MAX_ECC_COORD_BYTES];
        let d = key.scalar(&mut d).unwrap();
        let reloaded = EccPrivateKey::load(load_public(), d).unwrap().unwrap();
        let mut d2 = [0; MAX_ECC_COORD_BYTES];
        assert_eq!(reloaded.scalar(&mut d2).unwrap(), d, "{curve:?}");
    }
}

#[test]
fn ecc_generate_is_deterministic() {
    for curve in WEIERSTRASS_CURVES {
        let mut rng1 = C::from_seed(b"ecc_generate_is_deterministic").unwrap();
        let mut rng2 = C::from_seed(b"ecc_generate_is_deterministic").unwrap();
        let Some(key1) = supported(EccPrivateKey::<C>::generate(&mut rng1, curve, None)) else {
            continue;
        };
        let key2 = EccPrivateKey::<C>::generate(&mut rng2, curve, None).unwrap();
        let (mut d1, mut d2) = ([0; MAX_ECC_COORD_BYTES], [0; MAX_ECC_COORD_BYTES]);
        let d1 = key1.scalar(&mut d1).unwrap();
        assert_eq!(key2.scalar(&mut d2).unwrap(), d1, "{curve:?}");
    }
}

/// ECDH between generated keys agrees, on every Weierstrass and Montgomery
/// (X25519, X448) curve.
#[test]
fn ecdh_agreement() {
    let mut rng = C::from_seed(b"ecdh_agreement").unwrap();
    let curves = WEIERSTRASS_CURVES
        .into_iter()
        .chain([TpmEccCurve::Curve25519, TpmEccCurve::Curve448]);
    for curve in curves {
        let Some(a) = supported(EccPrivateKey::<C>::generate(&mut rng, curve, None)) else {
            continue;
        };
        let b = EccPrivateKey::<C>::generate(&mut rng, curve, None).unwrap();
        let (mut ax, mut ay) = ([0; MAX_ECC_COORD_BYTES], [0; MAX_ECC_COORD_BYTES]);
        let (mut bx, mut by) = ([0; MAX_ECC_COORD_BYTES], [0; MAX_ECC_COORD_BYTES]);
        let za = a.ecdh(&ecc_public(&b, None), &mut ax, &mut ay).unwrap();
        let zb = b.ecdh(&ecc_public(&a, None), &mut bx, &mut by).unwrap();
        assert_eq!(za.unwrap(), zb.unwrap(), "{curve:?}");
    }
}

#[test]
fn ecdsa_sign_verify() {
    let mut rng = C::from_entropy().unwrap();
    let digest = [0x33; 32];
    for curve in WEIERSTRASS_CURVES {
        let Some(key) = supported(EccPrivateKey::<C>::generate(&mut rng, curve, None)) else {
            continue;
        };
        let public = ecc_public(&key, None);
        let mut buf = [0; MAX_SIGNATURE_BYTES];
        let scheme = TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256);
        let Some(sig) = supported(key.sign(&mut rng, scheme, &digest, &mut buf)) else {
            continue;
        };
        let verify = |digest: &[u8], sig| public.verify(digest, sig);
        assert!(verify(&digest, sig).unwrap(), "{curve:?}");
        assert!(!verify(&[0x34; 32], sig).unwrap(), "{curve:?}");

        let TpmtSignature::Ecdsa(s) = sig else {
            panic!("{sig:?}");
        };
        let mut bad_s = s.signature_s.as_slice().to_vec();
        *bad_s.last_mut().unwrap() ^= 1;
        let bad_sig = TpmtSignature::Ecdsa(TpmsSignatureEcc {
            signature_s: ecc_param(&bad_s),
            ..s
        });
        assert!(!verify(&digest, bad_sig).unwrap(), "{curve:?}");
    }
}

#[test]
fn sm2_sign_verify() {
    let mut rng = C::from_entropy().unwrap();
    let curve = TpmEccCurve::SM2P256;
    let Some(key) = supported(EccPrivateKey::<C>::generate(&mut rng, curve, None)) else {
        return;
    };
    let public = ecc_public(&key, None);
    let mut digest = [0; 32];
    hash::<C>(TpmiAlgHash::Sm3_256, &[b"hello sm2"], &mut digest).unwrap();
    let mut buf = [0; MAX_SIGNATURE_BYTES];
    let scheme = TpmtSigScheme::Sm2(TpmiAlgHash::Sm3_256);
    let Some(sig) = supported(key.sign(&mut rng, scheme, &digest, &mut buf)) else {
        return;
    };
    let verify = |digest: &[u8]| public.verify(digest, sig);
    assert!(verify(&digest).unwrap());
    digest[0] ^= 1;
    assert!(!verify(&digest).unwrap());
}

// ---------------------------------------------------------------------------
// ECC: Edwards (Ed25519, Ed448) and Montgomery (X25519) curves
// ---------------------------------------------------------------------------

/// Checks an RFC 8032 pure EdDSA vector (secret seed `sk`, public key `pk`,
/// and signature `sig` of `msg`), key validation, and multi-part messages.
fn check_eddsa_vector<K, const N: usize>(sk: &[u8; N], pk: &[u8; N], msg: &[u8], sig: &[u8])
where
    K: EdwardsCurve<N, CRng>,
{
    let Some(public) = supported(K::load_public((), pk)) else {
        return;
    };
    let public = public.expect("valid public key");
    let load_public = || K::load_public((), pk).unwrap().unwrap();

    // A secret seed which doesn't derive the public key.
    let mut bad_sk = *sk;
    bad_sk[0] ^= 1;
    assert!(K::load(load_public(), &bad_sk).unwrap().is_none());

    let key = K::load(public, sk).unwrap().expect("valid secret key");
    let (mut out_pk, mut out_sk) = ([0; N], [0; N]);
    K::store_public(key.as_public(), &mut out_pk).unwrap();
    key.store(&mut out_sk).unwrap();
    assert_eq!((&out_pk, &out_sk), (pk, sk));

    let (mut r, mut s) = ([0; N], [0; N]);
    key.sign_message(&[msg], &mut r, &mut s).unwrap();
    assert_eq!((&r[..], &s[..]), sig.split_at(N));
    assert!(K::verify_message(key.as_public(), &[msg], &r, &s).unwrap());
    let mut bad_s = s;
    bad_s[0] ^= 1;
    assert!(!K::verify_message(key.as_public(), &[msg], &r, &bad_s).unwrap());

    // Multi-part messages are signed as if they were concatenated.
    let (a, b) = ([0x41; 2000], [0x42; 2000]);
    let whole = [a, b].concat();
    let (mut r2, mut s2) = ([0; N], [0; N]);
    key.sign_message(&[&a, &b], &mut r, &mut s).unwrap();
    key.sign_message(&[&whole], &mut r2, &mut s2).unwrap();
    assert_eq!((r, s), (r2, s2));
    assert!(K::verify_message(key.as_public(), &[&a, &b], &r, &s).unwrap());
    let mut bad_s = s;
    bad_s[0] ^= 1;
    assert!(!K::verify_message(key.as_public(), &[&a, &b], &r, &bad_s).unwrap());
}

/// Checks an RFC 8032 HashEdDSA vector (secret seed `sk`, public key `pk`, and
/// signature `sig` of `prehash`), and that the signature doesn't verify for
/// another prehash or as a pure EdDSA signature of `prehash`.
///
/// `other_context_sig` is a signature of `prehash` with a non-empty context,
/// which must not verify (as the context is always empty).
fn check_hash_eddsa_vector<K, const N: usize>(
    sk: &[u8; N],
    pk: &[u8; N],
    prehash: &[u8; 64],
    sig: &[u8],
    other_context_sig: Option<&[u8]>,
) where
    K: EdwardsCurve<N, CRng>,
{
    let Some(public) = supported(K::load_public((), pk)) else {
        return;
    };
    let key = K::load(public.expect("valid public key"), sk)
        .unwrap()
        .expect("valid secret key");
    let (mut r, mut s) = ([0; N], [0; N]);
    let Some(()) = supported(key.sign_prehash(prehash, &mut r, &mut s)) else {
        return;
    };
    assert_eq!((&r[..], &s[..]), sig.split_at(N));

    let public = key.as_public();
    assert!(K::verify_prehash(public, prehash, &r, &s).unwrap());
    assert!(!K::verify_prehash(public, &[0; 64], &r, &s).unwrap());
    assert!(!K::verify_message(public, &[prehash], &r, &s).unwrap());

    if let Some(sig) = other_context_sig {
        let (r, s) = sig.split_at(N);
        let (r, s) = (r.try_into().unwrap(), s.try_into().unwrap());
        assert!(!K::verify_prehash(public, prehash, r, s).unwrap());
    }
}

#[test]
fn ed25519_vectors() {
    use vectors::asym::*;
    check_eddsa_vector::<Ed25519, 32>(&ED25519_SK, &ED25519_PK, ED25519_MSG, &ED25519_SIG);
}

/// Checks that the non-canonical RFC 8032 public key encoding `pk` is rejected.
fn check_rejects_public_key<K: EdwardsCurve<N, CRng>, const N: usize>(pk: &[u8; N]) {
    if let Some(public) = supported(K::load_public((), pk)) {
        assert!(public.is_none());
    }
}

#[test]
fn eddsa_rejects_non_canonical_public_keys() {
    use vectors::asym::*;
    check_rejects_public_key::<Ed25519, 32>(&ED25519_NON_CANONICAL_PK);
    check_rejects_public_key::<Ed448, 57>(&ED448_NON_CANONICAL_PK);
}

#[test]
fn eddsa_rejects_invalid_public_keys() {
    use vectors::asym::*;
    for pk in &ED25519_INVALID_PKS {
        check_rejects_public_key::<Ed25519, 32>(pk);
    }
    for pk in &ED448_INVALID_PKS {
        check_rejects_public_key::<Ed448, 57>(pk);
    }
}

#[test]
fn ed25519ph_vectors() {
    use vectors::asym::*;
    check_hash_eddsa_vector::<Ed25519, 32>(
        &ED25519PH_SK,
        &ED25519PH_PK,
        &ED25519PH_PREHASH,
        &ED25519PH_SIG,
        None,
    );
}

#[test]
fn ed448_vectors() {
    use vectors::asym::*;
    check_eddsa_vector::<Ed448, 57>(&ED448_SK, &ED448_PK, ED448_MSG, &ED448_SIG);
}

#[test]
fn ed448ph_vectors() {
    use vectors::asym::*;
    check_hash_eddsa_vector::<Ed448, 57>(
        &ED448PH_SK,
        &ED448PH_PK,
        &ED448PH_PREHASH,
        &ED448PH_SIG,
        Some(&ED448PH_SIG_CTX_FOO),
    );
}

/// EdDSA and HashEdDSA through the dispatch functions.
#[test]
fn eddsa_sign_verify() {
    let mut rng = C::from_seed(b"eddsa_sign_verify").unwrap();
    let prehash = [0x5a; 64];
    for curve in [TpmEccCurve::Curve25519, TpmEccCurve::Curve448] {
        let scheme = Some(TpmtEccScheme::Eddsa);
        let Some(key) = supported(EccPrivateKey::<C>::generate(&mut rng, curve, scheme)) else {
            continue;
        };
        let public = ecc_public(&key, scheme);
        let mut buf = [0; MAX_SIGNATURE_BYTES];
        let msg: [&[u8]; 2] = [b"hello ", b"eddsa"];
        let sig = key.sign_message(&msg, &mut buf).unwrap();
        let valid = public.verify_message(&[b"hello eddsa"], sig);
        assert!(valid.unwrap(), "{curve:?}");
        let valid = public.verify_message(&[b"hello"], sig);
        assert!(!valid.unwrap(), "{curve:?}");

        let mut buf = [0; MAX_SIGNATURE_BYTES];
        let scheme = TpmtSigScheme::HashEddsa;
        let Some(sig) = supported(key.sign(&mut rng, scheme, &prehash, &mut buf)) else {
            continue;
        };
        let valid = public.verify(&prehash, sig);
        assert!(valid.unwrap(), "{curve:?}");
        let valid = public.verify(&[0x5b; 64], sig);
        assert!(!valid.unwrap(), "{curve:?}");
    }
}

#[test]
fn x25519_vectors() {
    check_x25519_vectors::<X25519>();
}

/// Checks the RFC 7748 (Section 6.1) X25519 vectors, key validation, and the
/// low-order point.
fn check_x25519_vectors<K: MontgomeryCurve<32, CRng>>() {
    use vectors::asym::*;
    let Some(a_public) = supported(K::load_public((), &X25519_A_PK)) else {
        return;
    };
    let a_public = a_public.expect("valid public key");
    let load_public = |pk| K::load_public((), pk).unwrap().unwrap();

    // A scalar which doesn't derive the public key.
    assert!(
        K::load(load_public(&X25519_A_PK), &X25519_B_SK)
            .unwrap()
            .is_none()
    );

    let a = K::load(a_public, &X25519_A_SK).unwrap().unwrap();
    let b = K::load(load_public(&X25519_B_PK), &X25519_B_SK)
        .unwrap()
        .unwrap();
    let (mut a_pk, mut b_pk, mut a_sk) = ([0; 32], [0; 32], [0; 32]);
    K::store_public(a.as_public(), &mut a_pk).unwrap();
    K::store_public(b.as_public(), &mut b_pk).unwrap();
    a.store(&mut a_sk).unwrap();
    assert_eq!((a_pk, b_pk, a_sk), (X25519_A_PK, X25519_B_PK, X25519_A_SK));

    let (mut ss_ab, mut ss_ba) = ([0; 32], [0; 32]);
    assert_eq!(a.ecdh(b.as_public(), &mut ss_ab), Ok(Some(())));
    assert_eq!(b.ecdh(a.as_public(), &mut ss_ba), Ok(Some(())));
    assert_eq!((ss_ab, ss_ba), (X25519_SS, X25519_SS));

    // The low-order point `u = 0` gives the all-zero shared secret.
    let zero = load_public(&[0; 32]);
    assert_eq!(a.ecdh(&zero, &mut ss_ab), Ok(None));
}

// ---------------------------------------------------------------------------
// ML-KEM
// ---------------------------------------------------------------------------

#[test]
fn mlkem768_vectors() {
    use vectors::asym::*;
    let Some(public) = supported(Mlkem768::load_public((), &MLKEM768_PK)) else {
        return;
    };
    let key = Mlkem768::load(public.expect("valid public key"), &MLKEM768_SEED)
        .unwrap()
        .expect("valid seed");
    let mut pk = [0; 1184];
    Mlkem768::store_public(key.as_public(), &mut pk).unwrap();
    assert_eq!(pk, MLKEM768_PK);

    let public = Mlkem768::load_public((), &MLKEM768_KAT_PK)
        .unwrap()
        .unwrap();
    let key = Mlkem768::load(public, &MLKEM768_KAT_SEED).unwrap().unwrap();
    let mut ss = [0; 32];
    key.decapsulate(&MLKEM768_KAT_CT, &mut ss).unwrap();
    assert_eq!(ss, MLKEM768_KAT_SS);
}

/// Key generation, encoding, and validation, and encapsulation round trips.
#[test]
fn mlkem_key_lifecycle() {
    let mut rng = C::from_entropy().unwrap();
    for parms in MLKEM_PARMS {
        let Some(key) = supported(MlkemPrivateKey::<C>::generate(&mut rng, parms)) else {
            continue;
        };
        let mut seed = [0; 64];
        key.seed(&mut seed).unwrap();
        let mut pk = [0; TpmiMlkemParms::MAX_PUB_KEY_BYTES];
        let pk = key.public(&mut pk).unwrap();
        let load_public = || MlkemPublicKey::<C>::load(parms, pk).unwrap().unwrap();

        let loaded = MlkemPrivateKey::load(load_public(), Tpm2b(&seed))
            .unwrap()
            .unwrap();
        let mut pk2 = [0; TpmiMlkemParms::MAX_PUB_KEY_BYTES];
        assert_eq!(loaded.public(&mut pk2).unwrap(), pk, "{parms:?}");

        // A seed which doesn't derive the public key.
        let mut bad_seed = seed;
        bad_seed[0] ^= 1;
        let bad = MlkemPrivateKey::load(load_public(), Tpm2b(&bad_seed)).unwrap();
        assert!(bad.is_none(), "{parms:?}");

        // A coefficient which isn't reduced mod q (0xfff >= 3329, FIPS 203).
        let mut bad_pk = pk.as_slice().to_vec();
        bad_pk[..2].fill(0xff);
        let bad_pk = Tpm2bPublicKeyMlkem::new(&bad_pk).unwrap();
        assert!(
            MlkemPublicKey::<C>::load(parms, bad_pk).unwrap().is_none(),
            "{parms:?}"
        );

        let (mut ct, mut ss) = ([0; TpmiMlkemParms::MAX_CT_BYTES], [0; 32]);
        let (ct, ss) = load_public()
            .encapsulate(&mut rng, &mut ct, &mut ss)
            .unwrap();
        let mut ss2 = [0; 32];
        let ss2 = loaded.decapsulate(ct, &mut ss2).unwrap().unwrap();
        assert_eq!(ss2, ss, "{parms:?}");

        // Implicit rejection of a modified ciphertext.
        let mut bad_ct = ct.as_slice().to_vec();
        bad_ct[0] ^= 1;
        let mut ss3 = [0; 32];
        let bad_ct = Tpm2bKemCiphertext::new(&bad_ct).unwrap();
        let ss3 = loaded.decapsulate(bad_ct, &mut ss3).unwrap().unwrap();
        assert_ne!(ss3, ss, "{parms:?}");
    }
}

// ---------------------------------------------------------------------------
// ML-DSA
// ---------------------------------------------------------------------------

#[test]
fn mldsa65_vectors() {
    use vectors::asym::*;
    let mut rng = C::from_entropy().unwrap();
    let Some(public) = supported(Mldsa65::load_public((), &MLDSA65_PK)) else {
        return;
    };
    let key = Mldsa65::load(public.expect("valid public key"), &MLDSA65_SEED)
        .unwrap()
        .expect("valid seed");
    let mut pk = [0; 1952];
    Mldsa65::store_public(key.as_public(), &mut pk).unwrap();
    assert_eq!(pk, MLDSA65_PK);

    assert!(Mldsa65::verify_mu(key.as_public(), &MLDSA65_KAT_MU, &MLDSA65_KAT_SIG).unwrap());
    let mut sig = [0; 3309];
    key.sign_mu(&mut rng, &MLDSA65_KAT_MU, &mut sig).unwrap();
    assert!(Mldsa65::verify_mu(key.as_public(), &MLDSA65_KAT_MU, &sig).unwrap());
}

/// Key generation, encoding, and validation.
#[test]
fn mldsa_key_lifecycle() {
    let mut rng = C::from_seed(b"mldsa_key_lifecycle").unwrap();
    for parms in MLDSA_PARMS {
        let Some(key) = supported(MldsaPrivateKey::<C>::generate(&mut rng, parms)) else {
            continue;
        };
        let mut seed = [0; 32];
        key.seed(&mut seed).unwrap();
        let mut pk = [0; TpmiMldsaParms::MAX_PUB_KEY_BYTES];
        let pk = key.public(&mut pk).unwrap();
        let load_public = || MldsaPublicKey::<C>::load(parms, pk).unwrap().unwrap();

        let loaded = MldsaPrivateKey::load(load_public(), Tpm2b(&seed))
            .unwrap()
            .unwrap();
        let mut pk2 = [0; TpmiMldsaParms::MAX_PUB_KEY_BYTES];
        assert_eq!(loaded.public(&mut pk2).unwrap(), pk, "{parms:?}");

        // A seed which doesn't derive the public key.
        let mut bad_seed = seed;
        bad_seed[0] ^= 1;
        let bad = MldsaPrivateKey::load(load_public(), Tpm2b(&bad_seed)).unwrap();
        assert!(bad.is_none(), "{parms:?}");
    }
}

/// Pure ML-DSA (with and without a context), external-µ ML-DSA, and
/// HashML-DSA sign/verify round trips, and invalid signatures are rejected.
#[test]
fn mldsa_sign_verify() {
    let mut rng = C::from_entropy().unwrap();
    for parms in MLDSA_PARMS {
        let Some(key) = supported(MldsaPrivateKey::<C>::generate(&mut rng, parms)) else {
            continue;
        };
        let mut pk = [0; TpmiMldsaParms::MAX_PUB_KEY_BYTES];
        let pk = key.public(&mut pk).unwrap();
        let public = MldsaPublicKey::<C>::load(parms, pk).unwrap().unwrap();
        let mut buf = [0; MAX_SIGNATURE_BYTES];

        // Pure ML-DSA, with a multi-part message.
        for ctx in [&b""[..], b"mldsa-ctx"] {
            let msg: [&[u8]; 3] = [b"multi-", b"part ", b"message"];
            let sig = key.sign_message(&mut rng, ctx, &msg, &mut buf).unwrap();
            let verify = |ctx, msg: &[u8]| public.verify_message(ctx, &[msg], sig);
            assert!(verify(ctx, b"multi-part message").unwrap(), "{parms:?}");
            assert!(!verify(ctx, b"wrong message").unwrap(), "{parms:?}");
            assert!(
                !verify(b"other-ctx", b"multi-part message").unwrap(),
                "{parms:?}"
            );
        }

        // External µ (with an empty context).
        let mu = [0x5a; 64];
        let sig = key.sign_mu(&mut rng, &mu, &mut buf).unwrap();
        assert!(public.verify(b"", &mu, sig).unwrap(), "{parms:?}");
        assert!(!public.verify(b"", &[0x5b; 64], sig).unwrap(), "{parms:?}");

        // HashML-DSA.
        for hash in [
            TpmiAlgHash::Sha256,
            TpmiAlgHash::Sha384,
            TpmiAlgHash::Sha512,
            TpmiAlgHash::Sha3_256,
            TpmiAlgHash::Sha3_384,
            TpmiAlgHash::Sha3_512,
        ] {
            let digest = &[0x42; 64][..hash.digest_size()];
            let wrong_digest = &[0x43; 64][..hash.digest_size()];
            for ctx in [&b""[..], b"hash-mldsa-ctx"] {
                let Some(sig) = supported(key.sign_prehash(&mut rng, hash, ctx, digest, &mut buf))
                else {
                    break;
                };
                let verify = |ctx, digest| public.verify(ctx, digest, sig);
                assert!(verify(ctx, digest).unwrap(), "{parms:?} {hash:?}");
                assert!(!verify(ctx, wrong_digest).unwrap(), "{parms:?} {hash:?}");
                assert!(!verify(b"wrong-ctx", digest).unwrap(), "{parms:?} {hash:?}");
            }
        }
    }
}
