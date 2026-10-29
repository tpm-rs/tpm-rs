#![no_std]
extern crate alloc;

pub mod vectors;

use alloc::format;
use alloc::vec::Vec;
use core::ffi::CStr;
use core::slice;
use hex_literal::hex;
use tpm2::{
    AlgSym, TpmiAlgCipherMode, TpmiAlgHash, TpmtHa,
    crypto::{
        Block, CipherInput, Crypto, CryptoError, Direction, HashContext, HmacContext,
        SymmetricContext, SymmetricKey,
        backend::{Hash, HashState},
        hash, hmac, kdfa, kdfa_xor, kdfe,
    },
};

// RFC 4231, test case 2.

pub fn hash_one_shot<C: Crypto>() {
    let _sha256_abc: [u8; 32] = crate::vectors::hash::SHA256[1].1.try_into().unwrap();
    let mut out = [0; 32];
    let d = hash::<C>(TpmiAlgHash::Sha256, &[b"abc"], &mut out).unwrap();
    assert_eq!(
        d,
        TpmtHa::Sha256(&crate::vectors::hash::SHA256[1].1.try_into().unwrap())
    );
}

/// The parts are hashed as if they were concatenated.
pub fn hash_one_shot_parts<C: Crypto>() {
    let sha256_abc: [u8; 32] = crate::vectors::hash::SHA256[1].1.try_into().unwrap();
    let sha256_empty: [u8; 32] = crate::vectors::hash::SHA256[0].1.try_into().unwrap();
    let mut out = [0; 32];
    let d = hash::<C>(TpmiAlgHash::Sha256, &[b"a", b"", b"bc"], &mut out).unwrap();
    assert_eq!(d.digest(), sha256_abc);

    let d = hash::<C>(TpmiAlgHash::Sha256, &[], &mut out).unwrap();
    assert_eq!(d.digest(), sha256_empty);
}

pub fn hash_streaming<C: Crypto>() {
    let sha256_abc: [u8; 32] = crate::vectors::hash::SHA256[1].1.try_into().unwrap();
    let mut ctx = HashContext::<C>::new(TpmiAlgHash::Sha256).unwrap();
    assert_eq!(ctx.alg(), TpmiAlgHash::Sha256);
    ctx.update(b"ab").unwrap();
    ctx.update(b"c").unwrap();
    let mut out = [0; 32];
    assert_eq!(ctx.finalize(&mut out).unwrap().digest(), sha256_abc);
}

pub fn hash_wrong_output_size<C: Crypto>() {
    let mut out = [0; 31];
    let err = hash::<C>(TpmiAlgHash::Sha256, &[b"abc"], &mut out).unwrap_err();
    assert_eq!(err, CryptoError::Internal);

    let ctx = HashContext::<C>::new(TpmiAlgHash::Sha256).unwrap();
    assert_eq!(ctx.finalize(&mut out).err(), Some(CryptoError::Internal));
}

/// The digest is written to the start of a longer output buffer.
pub fn hash_longer_output_buffer<C: Crypto>() {
    let _sha256_abc: [u8; 32] = crate::vectors::hash::SHA256[1].1.try_into().unwrap();
    let mut out = [0xFF; TpmiAlgHash::MAX_DIGEST_BYTES];
    let d = hash::<C>(TpmiAlgHash::Sha256, &[b"abc"], &mut out).unwrap();
    assert_eq!(
        d,
        TpmtHa::Sha256(&crate::vectors::hash::SHA256[1].1.try_into().unwrap())
    );
    assert!(out[32..].iter().all(|&b| b == 0xFF));
}

pub fn hmac_one_shot<C: Crypto>() {
    let hmac_key = crate::vectors::hmac::CASES[1].0;
    let hmac_data = crate::vectors::hmac::CASES[1].1;
    let hmac_sha256: [u8; 32] = crate::vectors::hmac::SHA256[1].try_into().unwrap();
    let hmac_sha512: [u8; 64] = crate::vectors::hmac::SHA512[1].try_into().unwrap();
    let mut out = [0; 32];
    let mac = hmac::<C>(TpmiAlgHash::Sha256, hmac_key, &[hmac_data], &mut out).unwrap();
    assert_eq!(mac.digest(), hmac_sha256);

    // The parts are MACed as if they were concatenated.
    let (a, b) = hmac_data.split_at(7);
    let mut out = [0; 64];
    let mac = hmac::<C>(TpmiAlgHash::Sha512, hmac_key, &[a, b], &mut out).unwrap();
    assert_eq!(mac.digest(), hmac_sha512);

    // RFC 4231, test case 6 (131-byte key > 128-byte SHA-512 block size).
    let long_key = [0xaa; 131];
    let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
    let mac = hmac::<C>(TpmiAlgHash::Sha512, &long_key, &[data], &mut out).unwrap();
    assert_eq!(
        mac.digest(),
        hex!(
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
            "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
        )
    );
}

pub fn hmac_streaming<C: Crypto>() {
    let hmac_key = crate::vectors::hmac::CASES[1].0;
    let hmac_data = crate::vectors::hmac::CASES[1].1;
    let hmac_sha512: [u8; 64] = crate::vectors::hmac::SHA512[1].try_into().unwrap();
    let (a, b) = hmac_data.split_at(7);
    let mut ctx = HmacContext::<C>::new(TpmiAlgHash::Sha512, hmac_key).unwrap();
    assert_eq!(ctx.alg(), TpmiAlgHash::Sha512);
    ctx.update(a).unwrap();
    ctx.update(b).unwrap();
    let mut out = [0; 64];
    assert_eq!(ctx.finalize(&mut out).unwrap().digest(), hmac_sha512);
}

/// A single-block KDFa is `HMAC(key, [1]_32 || label || 0 || u || v || [bits]_32)`.
pub fn kdfa_single_block_matches_hmac<C: Crypto>() {
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
pub fn kdfa_xor_matches_kdfa<C: Crypto>() {
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
pub fn kdfe_single_block_matches_hash<C: Crypto>() {
    let (z, label, u, v): (&[u8], &CStr, &[u8], &[u8]) = (b"shared_z", c"ECDH", b"uu", b"vvv");
    let mut derived = [0; 32];
    kdfe::<C>(TpmiAlgHash::Sha256, z, label, (u, v), &mut derived).unwrap();

    let msg = [&1u32.to_be_bytes()[..], z, label.to_bytes_with_nul(), u, v];
    let mut expected = [0; 32];
    hash::<C>(TpmiAlgHash::Sha256, &msg, &mut expected).unwrap();
    assert_eq!(derived, expected);
}

/// Backends can specialize one-shot methods (like [`HashState::hash`]) directly.
pub fn specialized_one_shot_override<C: Crypto>() {
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

/// `RustCrypto` is a complete backend.
pub fn implements_crypto<C: Crypto>() {
    fn assert_crypto<C: Crypto>() {}
    assert_crypto::<C>();
}

/// [`Random`](tpm2::crypto::Random) and [`Rng`]: seeded RNGs are
/// deterministic, and entropy-seeded RNGs and `rand_bytes` produce output.
pub fn random_tests<C: Crypto>() {
    let mut a = C::from_seed(b"seed").unwrap();
    let mut b = C::from_seed(b"seed").unwrap();
    let mut c = C::from_seed(b"other seed").unwrap();
    let (mut out_a, mut out_b, mut out_c) = ([0u8; 64], [0u8; 64], [0u8; 64]);
    a.fill_bytes(&mut out_a).unwrap();
    b.fill_bytes(&mut out_b).unwrap();
    c.fill_bytes(&mut out_c).unwrap();
    assert_eq!(out_a, out_b);
    assert_ne!(out_a, out_c);

    // Stirring is deterministic, and changes the output.
    a.stir_bytes(b"data").unwrap();
    b.stir_bytes(b"data").unwrap();
    c = C::from_seed(b"seed").unwrap();
    c.fill_bytes(&mut out_c).unwrap();
    a.fill_bytes(&mut out_a).unwrap();
    b.fill_bytes(&mut out_b).unwrap();
    c.fill_bytes(&mut out_c).unwrap();
    assert_eq!(out_a, out_b);
    assert_ne!(out_a, out_c);

    // Entropy-seeded RNGs differ from each other.
    let mut e1 = C::from_entropy().unwrap();
    let mut e2 = C::from_entropy().unwrap();
    e1.fill_bytes(&mut out_a).unwrap();
    e2.fill_bytes(&mut out_b).unwrap();
    assert_ne!(out_a, out_b);

    C::rand_bytes(&mut out_a).unwrap();
    C::rand_bytes(&mut out_b).unwrap();
    assert_ne!(out_a, out_b);
}

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeyInit, consts::U16};

const ALL_MODES: [TpmiAlgCipherMode; 5] = [
    TpmiAlgCipherMode::Ctr,
    TpmiAlgCipherMode::Ofb,
    TpmiAlgCipherMode::Cbc,
    TpmiAlgCipherMode::Cfb,
    TpmiAlgCipherMode::Ecb,
];

// FIPS-197, Appendix C.
const FIPS_PT: Block = hex!("00112233445566778899aabbccddeeff");
const FIPS_VECTORS: [(AlgSym, &[u8], Block); 3] = [
    (
        AlgSym::Aes128,
        &hex!("000102030405060708090a0b0c0d0e0f"),
        hex!("69c4e0d86a7b0430d8cdb78070b4c55a"),
    ),
    (
        AlgSym::Aes192,
        &hex!("000102030405060708090a0b0c0d0e0f1011121314151617"),
        hex!("dda97ca4864cdfe06eaf70a0ec0d7191"),
    ),
    (
        AlgSym::Aes256,
        &hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        hex!("8ea2b7ca516745bfeafc49904b496089"),
    ),
];

// NIST SP 800-38A, Appendix F (AES-128).
const KEY_128: [u8; 16] = hex!("2b7e151628aed2a6abf7158809cf4f3c");
const KEY_256: [u8; 32] = hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
const PT: [u8; 64] = hex!(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
);
const IV: Block = hex!("000102030405060708090a0b0c0d0e0f");
const CTR_IV: Block = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

fn sp800_38a(mode: TpmiAlgCipherMode) -> (Block, [u8; 64]) {
    match mode {
        TpmiAlgCipherMode::Ecb => (
            [0; 16],
            hex!(
                "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
                "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4"
            ),
        ),
        TpmiAlgCipherMode::Cbc => (
            IV,
            hex!(
                "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
                "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"
            ),
        ),
        TpmiAlgCipherMode::Cfb => (
            IV,
            hex!(
                "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b"
                "26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6"
            ),
        ),
        TpmiAlgCipherMode::Ofb => (
            IV,
            hex!(
                "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825"
                "9740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e"
            ),
        ),
        TpmiAlgCipherMode::Ctr => (
            CTR_IV,
            hex!(
                "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
                "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"
            ),
        ),
    }
}

/// Encrypts or decrypts `data` in place with a raw `key`, updating `iv`.
fn crypt_once<C: Crypto>(
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

pub fn fips197_ecb<C: Crypto>() {
    for (alg, key, ct) in FIPS_VECTORS {
        let key = SymmetricKey::new(alg, key).unwrap();
        let ctx = SymmetricContext::<C>::new(key).unwrap();
        assert_eq!(ctx.alg(), alg);

        let mut block = FIPS_PT;
        ctx.crypt(
            Direction::Encrypt,
            CipherInput::Ecb(slice::from_mut(&mut block)),
        )
        .unwrap();
        assert_eq!(block, ct);
        key.crypt::<C>(
            Direction::Decrypt,
            CipherInput::Ecb(slice::from_mut(&mut block)),
        )
        .unwrap();
        assert_eq!(block, FIPS_PT);
    }
}

pub fn sp800_38a_modes<C: Crypto>() {
    let key = SymmetricKey::Aes128(&KEY_128);
    for mode in ALL_MODES {
        let (iv, ct) = sp800_38a(mode);

        let (mut data, mut enc_iv) = (PT, iv);
        crypt_once::<C>(key, mode, Direction::Encrypt, &mut enc_iv, &mut data).unwrap();
        assert_eq!(data, ct, "{mode:?}");

        let mut dec_iv = iv;
        crypt_once::<C>(key, mode, Direction::Decrypt, &mut dec_iv, &mut data).unwrap();
        assert_eq!(data, PT, "{mode:?}");
        assert_eq!(enc_iv, dec_iv, "{mode:?}");
    }
}

/// Encrypting in two chained calls (passing `ivOut` along) matches a single
/// call, for block-aligned splits.
pub fn chaining_matches_single_call<C: Crypto>() {
    let key = SymmetricKey::Aes128(&KEY_128);
    for mode in ALL_MODES {
        let (iv, ct) = sp800_38a(mode);
        let (mut data, mut iv) = (PT, iv);
        let (a, b) = data.split_at_mut(32);
        crypt_once::<C>(key, mode, Direction::Encrypt, &mut iv, a).unwrap();
        crypt_once::<C>(key, mode, Direction::Encrypt, &mut iv, b).unwrap();
        assert_eq!(data, ct, "{mode:?}");
    }
}

/// A direct port of `CryptSymmetricEncrypt` and `CryptSymmetricDecrypt` from
/// the TPM reference implementation (`CryptSym.c`).
fn reference_crypt<C>(
    cipher: &C,
    mode: TpmiAlgCipherMode,
    dir: Direction,
    iv: &mut Block,
    data: &mut [u8],
) where
    C: BlockCipherEncrypt + BlockCipherDecrypt + BlockSizeUser<BlockSize = U16>,
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
/// CTR counter carries and CFB's zero-padded partial blocks.
pub fn matches_reference_implementation<C: Crypto>() {
    let aes128 = aes::Aes128::new(&KEY_128.into());
    let aes256 = aes::Aes256::new(&KEY_256.into());
    let ctx128 = SymmetricContext::<C>::new(SymmetricKey::Aes128(&KEY_128)).unwrap();
    let ctx256 = SymmetricContext::<C>::new(SymmetricKey::Aes256(&KEY_256)).unwrap();
    let ivs = [IV, [0xff; 16], hex!("0102030405060708090a0b0cfffffffe")];
    let msg: Vec<u8> = (0..=255).collect();

    for mode in ALL_MODES {
        let block_mode = matches!(mode, TpmiAlgCipherMode::Cbc | TpmiAlgCipherMode::Ecb);
        for len in (0..=70).filter(|len| !block_mode || len % 16 == 0) {
            for iv0 in ivs {
                for dir in [Direction::Encrypt, Direction::Decrypt] {
                    let ctx = format!("{mode:?} {dir:?} len={len} iv={iv0:02x?}");

                    let (mut want, mut want_iv) = (msg[..len].to_vec(), iv0);
                    reference_crypt(&aes128, mode, dir, &mut want_iv, &mut want);
                    let (mut got, mut got_iv) = (msg[..len].to_vec(), iv0);
                    let iv: &mut [u8] = if mode == TpmiAlgCipherMode::Ecb {
                        &mut []
                    } else {
                        &mut got_iv
                    };
                    let input = CipherInput::new(mode, iv, &mut got).unwrap();
                    ctx128.crypt(dir, input).unwrap();
                    assert_eq!((&got, got_iv), (&want, want_iv), "AES-128 {ctx}");

                    let (mut want, mut want_iv) = (msg[..len].to_vec(), iv0);
                    reference_crypt(&aes256, mode, dir, &mut want_iv, &mut want);
                    let (mut got, mut got_iv) = (msg[..len].to_vec(), iv0);
                    let key = SymmetricKey::Aes256(&KEY_256);
                    crypt_once::<C>(key, mode, dir, &mut got_iv, &mut got).unwrap();
                    assert_eq!((&got, got_iv), (&want, want_iv), "AES-256 one-shot {ctx}");

                    let (mut got, mut got_iv) = (msg[..len].to_vec(), iv0);
                    let iv: &mut [u8] = if mode == TpmiAlgCipherMode::Ecb {
                        &mut []
                    } else {
                        &mut got_iv
                    };
                    ctx256
                        .crypt(dir, CipherInput::new(mode, iv, &mut got).unwrap())
                        .unwrap();
                    assert_eq!((&got, got_iv), (&want, want_iv), "AES-256 context {ctx}");
                }
            }
        }
    }
}

pub fn cipher_input_validation<C: Crypto>() {
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
    assert_eq!(
        CipherInput::new(mode, &mut iv, &mut data[..16])
            .unwrap()
            .mode(),
        mode
    );

    // ECB needs an empty IV.
    let mode = TpmiAlgCipherMode::Ecb;
    assert!(CipherInput::new(mode, &mut iv, &mut data[..16]).is_none());
    assert!(CipherInput::new(mode, &mut [], &mut data).is_none());
    assert_eq!(
        CipherInput::new(mode, &mut [], &mut data[..16])
            .unwrap()
            .mode(),
        mode
    );
}

pub fn symmetric_key<C: Crypto>() {
    assert!(SymmetricKey::new(AlgSym::Aes256, &KEY_128).is_none());
    assert!(SymmetricKey::new(AlgSym::Aes128, &KEY_256).is_none());

    let key = SymmetricKey::new(AlgSym::Aes256, &KEY_256).unwrap();
    assert_eq!(key.alg(), AlgSym::Aes256);
    assert_eq!(key.bytes(), KEY_256);
}

pub fn unsupported<C: Crypto>() {}
use crate::vectors::cipher::*;
use crate::vectors::ecc::*;
use crate::vectors::rsa::*;
use tpm2::TpmEccCurve;
use tpm2::crypto::backend::{
    AsymmetricKey, Cmac, CmacState, Ecc, EccCurve, EccSigScheme, EdwardsCurve, Mldsa, MldsaKey,
    Mlkem, MlkemKey, MontgomeryCurve, Rsa, RsaKey, RsaSigScheme,
};
use tpm2::crypto::{Rng, RsaEncryptScheme};

/// Packs big-endian coordinates `x` and `y` (each left-padded to `P / 2` bytes)
/// into an `x || y` public point encoding.
fn ecc_point<const P: usize>(x: &[u8], y: &[u8]) -> [u8; P] {
    let mut out = [0u8; P];
    out[P / 2 - x.len()..P / 2].copy_from_slice(x);
    out[P - y.len()..].copy_from_slice(y);
    out
}

pub fn cmac_vectors<C: Crypto>() {
    fn test_cmac_kat<S: CmacState<KEY_SIZE>, const KEY_SIZE: usize>(
        key: &[u8],
        expected: &[[u8; 16]; 4],
    ) {
        if let Ok(_state) = S::init(key.try_into().unwrap()) {
            for (len, expected_mac) in CMAC_LENS.iter().zip(expected) {
                let mut state = S::init(key.try_into().unwrap()).unwrap();
                state.update(&PLAINTEXT[..*len]).unwrap();
                let mut out = [0u8; 16];
                state.finalize(&mut out).unwrap();
                assert_eq!(&out, expected_mac, "len={}", len);
            }
        }
    }
    test_cmac_kat::<<C as Cmac>::Aes128, 16>(&KEY128, &CMAC_AES128);
    test_cmac_kat::<<C as Cmac>::Aes192, 24>(&KEY192, &CMAC_AES192);
    test_cmac_kat::<<C as Cmac>::Aes256, 32>(&KEY256, &CMAC_AES256);
    test_cmac_kat::<<C as Cmac>::Sm4_128, 16>(&KEY128, &CMAC_SM4_128);
    test_cmac_kat::<<C as Cmac>::Camellia128, 16>(&KEY128, &CMAC_CAMELLIA128);
    test_cmac_kat::<<C as Cmac>::Camellia192, 24>(&KEY192, &CMAC_CAMELLIA192);
    test_cmac_kat::<<C as Cmac>::Camellia256, 32>(&KEY256, &CMAC_CAMELLIA256);
}

pub fn rsa_vectors<C: Crypto>(rng: &mut impl Rng) {
    let digest: [u8; 32] = crate::vectors::hash::SHA256[1].1.try_into().unwrap();

    fn test_rsa_sig<
        K: RsaKey<MOD_SIZE, PRIME_SIZE>,
        const MOD_SIZE: usize,
        const PRIME_SIZE: usize,
    >(
        n: &[u8; MOD_SIZE],
        _p: &[u8; PRIME_SIZE],
        sig: &[u8; MOD_SIZE],
        scheme: RsaSigScheme,
        digest: &[u8],
    ) {
        if let Ok(Some(pub_key)) = K::load_public(65537, n) {
            assert!(
                K::verify(
                    &pub_key,
                    scheme,
                    tpm2::TpmtHa::Sha256(digest.try_into().unwrap()),
                    sig
                )
                .unwrap()
            );
        }
    }

    test_rsa_sig::<<C as Rsa>::Rsa1024, 128, 64>(
        &N1024,
        &P1024,
        &RSASSA_SHA256_1024,
        RsaSigScheme::Rsassa,
        &digest,
    );
    test_rsa_sig::<<C as Rsa>::Rsa2048, 256, 128>(
        &N2048,
        &P2048,
        &RSASSA_SHA256_2048,
        RsaSigScheme::Rsassa,
        &digest,
    );
    test_rsa_sig::<<C as Rsa>::Rsa3072, 384, 192>(
        &N3072,
        &P3072,
        &RSASSA_SHA256_3072,
        RsaSigScheme::Rsassa,
        &digest,
    );
    test_rsa_sig::<<C as Rsa>::Rsa4096, 512, 256>(
        &N4096,
        &P4096,
        &RSASSA_SHA256_4096,
        RsaSigScheme::Rsassa,
        &digest,
    );

    if let Ok(Some(pub_key)) = <C as Rsa>::Rsa2048::load_public(65537, &N2048) {
        assert!(
            <C as Rsa>::Rsa2048::verify(
                &pub_key,
                RsaSigScheme::Rsapss,
                tpm2::TpmtHa::Sha256(&digest),
                &RSAPSS_SHA256_2048
            )
            .unwrap()
        );
    }

    fn test_rsa_enc<
        K: RsaKey<MOD_SIZE, PRIME_SIZE>,
        const MOD_SIZE: usize,
        const PRIME_SIZE: usize,
    >(
        rng: &mut impl Rng,
        n: &[u8; MOD_SIZE],
        p: &[u8; PRIME_SIZE],
        msg: &[u8],
        expected_enc: &[u8; MOD_SIZE],
        scheme: RsaEncryptScheme<'_>,
    ) {
        if let Ok(Some(pub_key)) = K::load_public(65537, n)
            && let Ok(Some(priv_key)) = K::load_private(pub_key, p)
        {
            let mut out = [0u8; MOD_SIZE];
            let len = match K::decrypt(rng, &priv_key, scheme, expected_enc, &mut out).unwrap() {
                Some(l) => l,
                None => panic!("RSA decrypt returned None for scheme: {:?}", scheme),
            };
            assert_eq!(&out[..len], msg);
        }
    }

    test_rsa_enc::<<C as Rsa>::Rsa2048, 256, 128>(
        rng,
        &N2048,
        &P2048,
        &RAW_M2048,
        &RAW_C2048,
        RsaEncryptScheme::Raw,
    );
    test_rsa_enc::<<C as Rsa>::Rsa2048, 256, 128>(
        rng,
        &N2048,
        &P2048,
        MESSAGE,
        &RSAES_C2048,
        RsaEncryptScheme::Rsaes,
    );
    test_rsa_enc::<<C as Rsa>::Rsa2048, 256, 128>(
        rng,
        &N2048,
        &P2048,
        MESSAGE,
        &OAEP_SHA1_C2048,
        RsaEncryptScheme::Oaep {
            hash: tpm2::TpmiAlgHash::Sha1,
            label: None,
        },
    );
    test_rsa_enc::<<C as Rsa>::Rsa2048, 256, 128>(
        rng,
        &N2048,
        &P2048,
        MESSAGE,
        &OAEP_SHA256_C2048,
        RsaEncryptScheme::Oaep {
            hash: tpm2::TpmiAlgHash::Sha256,
            label: Some(c"DUPLICATE"),
        },
    );
}

pub fn ecc_vectors<C: Crypto>(_rng: &mut impl Rng) {
    for kat in ECDSA {
        let digest_alg = kat.hash;

        macro_rules! test_verify {
            ($curve:ty, $size:expr) => {{
                let q: [u8; 2 * $size] = ecc_point(kat.q.0, kat.q.1);
                if let Ok(Some(pub_key)) = <$curve>::load_public((), &q) {
                    let mut digest_buf = [0u8; 64];
                    digest_buf[..kat.digest.len()].copy_from_slice(kat.digest);
                    let tpmt_ha = match digest_alg {
                        TpmiAlgHash::Sha1 => TpmtHa::Sha1((&digest_buf[..20]).try_into().unwrap()),
                        TpmiAlgHash::Sha256 => {
                            TpmtHa::Sha256((&digest_buf[..32]).try_into().unwrap())
                        }
                        TpmiAlgHash::Sha384 => {
                            TpmtHa::Sha384((&digest_buf[..48]).try_into().unwrap())
                        }
                        TpmiAlgHash::Sha512 => {
                            TpmtHa::Sha512((&digest_buf[..64]).try_into().unwrap())
                        }
                        TpmiAlgHash::Sm3_256 => {
                            TpmtHa::Sm3_256((&digest_buf[..32]).try_into().unwrap())
                        }
                        _ => panic!("unsupported hash in kat"),
                    };

                    let mut rx = [0u8; $size];
                    let mut ry = [0u8; $size];
                    let (rxl, kxl) = (rx.len(), kat.sig.0.len());
                    rx[rxl - kxl..].copy_from_slice(kat.sig.0);
                    let (ryl, kyl) = (ry.len(), kat.sig.1.len());
                    ry[ryl - kyl..].copy_from_slice(kat.sig.1);

                    let scheme = if kat.curve == TpmEccCurve::SM2P256 {
                        EccSigScheme::Sm2
                    } else {
                        EccSigScheme::Ecdsa
                    };

                    match <$curve>::verify::<C>(&pub_key, scheme, tpmt_ha, &rx, &ry) {
                        Ok(true) => (),
                        Ok(false) => panic!("ecdsa verify failed"),
                        Err(tpm2::crypto::CryptoError::Unsupported) => (),
                        Err(e) => panic!("ecdsa verify error: {:?}", e),
                    }
                }
            }};
        }

        match kat.curve {
            TpmEccCurve::NistP192 => test_verify!(<C as Ecc>::NistP192, 24),
            TpmEccCurve::NistP224 => test_verify!(<C as Ecc>::NistP224, 28),
            TpmEccCurve::NistP256 => test_verify!(<C as Ecc>::NistP256, 32),
            TpmEccCurve::NistP384 => test_verify!(<C as Ecc>::NistP384, 48),
            TpmEccCurve::NistP521 => test_verify!(<C as Ecc>::NistP521, 66),
            TpmEccCurve::SM2P256 => test_verify!(<C as Ecc>::SM2P256, 32),
            _ => continue,
        }
    }

    for kat in crate::vectors::ecc::ECDH {
        macro_rules! test_ecdh {
            ($curve:ty, $size:expr) => {{
                let mut d = [0u8; $size];
                let (dl, kl) = (d.len(), kat.d.len());
                d[dl - kl..].copy_from_slice(kat.d);
                let q: [u8; 2 * $size] = ecc_point(kat.q.0, kat.q.1);
                if let Ok(Some(q_pub)) = <$curve>::load_public((), &q)
                    && let Ok(Some(private)) = <$curve>::load_private(q_pub, &d)
                {
                    let peer: [u8; 2 * $size] = ecc_point(kat.peer.0, kat.peer.1);
                    if let Ok(Some(peer_pub)) = <$curve>::load_public((), &peer) {
                        let mut zx = [0u8; $size];
                        let mut zy = [0u8; $size];
                        if <$curve>::ecdh(&private, &peer_pub, &mut zx, &mut zy).is_ok() {
                            let (zxl, kl) = (zx.len(), kat.z.0.len());
                            assert_eq!(&zx[zxl - kl..], kat.z.0);
                            let (zyl, kl) = (zy.len(), kat.z.1.len());
                            assert_eq!(&zy[zyl - kl..], kat.z.1);
                        }

                        let q_pub = <$curve>::as_public(&private);
                        let mut out_q = [0u8; 2 * $size];
                        <$curve>::store_public(q_pub, &mut out_q).unwrap();
                        let (out_qx, out_qy) = out_q.split_at($size);
                        let (qxl, kl) = (out_qx.len(), kat.q.0.len());
                        assert_eq!(&out_qx[qxl - kl..], kat.q.0);
                        let (qyl, kl) = (out_qy.len(), kat.q.1.len());
                        assert_eq!(&out_qy[qyl - kl..], kat.q.1);
                    }
                }
            }};
        }

        match kat.curve {
            tpm2::TpmEccCurve::NistP192 => test_ecdh!(<C as Ecc>::NistP192, 24),
            tpm2::TpmEccCurve::NistP224 => test_ecdh!(<C as Ecc>::NistP224, 28),
            tpm2::TpmEccCurve::NistP256 => test_ecdh!(<C as Ecc>::NistP256, 32),
            tpm2::TpmEccCurve::NistP384 => test_ecdh!(<C as Ecc>::NistP384, 48),
            tpm2::TpmEccCurve::NistP521 => test_ecdh!(<C as Ecc>::NistP521, 66),
            tpm2::TpmEccCurve::BNP256 => test_ecdh!(<C as Ecc>::BNP256, 32),
            tpm2::TpmEccCurve::BNP638 => test_ecdh!(<C as Ecc>::BNP638, 80),
            tpm2::TpmEccCurve::SM2P256 => test_ecdh!(<C as Ecc>::SM2P256, 32),
            tpm2::TpmEccCurve::BpP256R1 => test_ecdh!(<C as Ecc>::BpP256R1, 32),
            tpm2::TpmEccCurve::BpP384R1 => test_ecdh!(<C as Ecc>::BpP384R1, 48),
            tpm2::TpmEccCurve::BpP512R1 => test_ecdh!(<C as Ecc>::BpP512R1, 64),
            _ => {}
        }
    }
}

pub fn interop_rsa_sign_verify<Signer: Crypto, Verifier: Crypto>(rng: &mut impl Rng) {
    let digest: [u8; 32] = crate::vectors::hash::SHA256[1].1.try_into().unwrap();
    if let Ok(signer_priv) = <Signer as Rsa>::Rsa2048::generate(rng, 65537) {
        let pub_key = <Signer as Rsa>::Rsa2048::as_public(&signer_priv);
        let mut out = [0u8; 256];
        <Signer as Rsa>::Rsa2048::sign(
            rng,
            &signer_priv,
            RsaSigScheme::Rsassa,
            tpm2::TpmtHa::Sha256(&digest),
            &mut out,
        )
        .unwrap();

        let mut n = [0u8; 256];
        <Signer as Rsa>::Rsa2048::store_public(pub_key, &mut n).unwrap();
        let e = <Signer as Rsa>::Rsa2048::exponent(pub_key);

        if let Ok(Some(verifier_pub)) = <Verifier as Rsa>::Rsa2048::load_public(e, &n) {
            assert!(
                <Verifier as Rsa>::Rsa2048::verify(
                    &verifier_pub,
                    RsaSigScheme::Rsassa,
                    tpm2::TpmtHa::Sha256(&digest),
                    &out
                )
                .unwrap()
            );
        }
    }
}

pub fn interop_rsa_encrypt_decrypt<Encrypter: Crypto, Decrypter: Crypto>(rng: &mut impl Rng) {
    if let Ok(decrypter_priv) = <Decrypter as Rsa>::Rsa2048::generate(rng, 65537) {
        let pub_key = <Decrypter as Rsa>::Rsa2048::as_public(&decrypter_priv);
        let mut n = [0u8; 256];
        <Decrypter as Rsa>::Rsa2048::store_public(pub_key, &mut n).unwrap();
        let e = <Decrypter as Rsa>::Rsa2048::exponent(pub_key);

        if let Ok(Some(encrypter_pub)) = <Encrypter as Rsa>::Rsa2048::load_public(e, &n) {
            let mut out = [0u8; 256];
            <Encrypter as Rsa>::Rsa2048::encrypt(
                rng,
                &encrypter_pub,
                RsaEncryptScheme::Rsaes,
                MESSAGE,
                &mut out,
            )
            .unwrap();
            let mut pt = [0u8; 256];
            let len = <Decrypter as Rsa>::Rsa2048::decrypt(
                rng,
                &decrypter_priv,
                RsaEncryptScheme::Rsaes,
                &out,
                &mut pt,
            )
            .unwrap()
            .unwrap();
            assert_eq!(&pt[..len], MESSAGE);
        }
    }
}

pub fn interop_ecdsa_sign_verify<Signer: Crypto, Verifier: Crypto>(rng: &mut impl Rng) {
    let digest = tpm2::TpmtHa::Sha256(&crate::vectors::hash::SHA256[1].1.try_into().unwrap());
    macro_rules! test_curve {
        ($Curve:ident, $COORD:expr) => {
            if let Ok(priv_key) = <Signer as Ecc>::$Curve::generate(rng, ()) {
                let pub_key = <Signer as Ecc>::$Curve::as_public(&priv_key);
                let mut q = [0u8; 2 * $COORD];
                <Signer as Ecc>::$Curve::store_public(pub_key, &mut q).unwrap();
                let mut r = [0u8; $COORD];
                let mut s = [0u8; $COORD];
                if let Ok(()) = <Signer as Ecc>::$Curve::sign::<Signer>(
                    rng,
                    &priv_key,
                    EccSigScheme::Ecdsa,
                    digest,
                    &mut r,
                    &mut s,
                ) {
                    if let Ok(Some(ver_pub)) = <Verifier as Ecc>::$Curve::load_public((), &q) {
                        assert!(
                            <Verifier as Ecc>::$Curve::verify::<Verifier>(
                                &ver_pub,
                                EccSigScheme::Ecdsa,
                                digest,
                                &r,
                                &s
                            )
                            .unwrap_or(false)
                        );
                    }
                }
            }
        };
    }
    test_curve!(NistP256, 32);
    test_curve!(NistP384, 48);
}

pub fn interop_ecdh<A: Crypto, B: Crypto>(rng: &mut impl Rng) {
    macro_rules! test_curve {
        ($Curve:ident, $COORD:expr) => {
            if let Ok(a_priv) = <A as Ecc>::$Curve::generate(rng, ()) {
                let a_pub = <A as Ecc>::$Curve::as_public(&a_priv);
                let mut a = [0u8; 2 * $COORD];
                <A as Ecc>::$Curve::store_public(a_pub, &mut a).unwrap();

                if let Ok(b_priv) = <B as Ecc>::$Curve::generate(rng, ()) {
                    let b_pub = <B as Ecc>::$Curve::as_public(&b_priv);
                    let mut b = [0u8; 2 * $COORD];
                    <B as Ecc>::$Curve::store_public(b_pub, &mut b).unwrap();

                    if let Ok(Some(b_a_pub)) = <B as Ecc>::$Curve::load_public((), &a) {
                        if let Ok(Some(a_b_pub)) = <A as Ecc>::$Curve::load_public((), &b) {
                            let mut a_shared_x = [0u8; $COORD];
                            let mut a_shared_y = [0u8; $COORD];
                            let mut b_shared_x = [0u8; $COORD];
                            let mut b_shared_y = [0u8; $COORD];

                            if let (Ok(Some(())), Ok(Some(()))) = (
                                <A as Ecc>::$Curve::ecdh(
                                    &a_priv,
                                    &a_b_pub,
                                    &mut a_shared_x,
                                    &mut a_shared_y,
                                ),
                                <B as Ecc>::$Curve::ecdh(
                                    &b_priv,
                                    &b_a_pub,
                                    &mut b_shared_x,
                                    &mut b_shared_y,
                                ),
                            ) {
                                assert_eq!(a_shared_x, b_shared_x);
                                assert_eq!(a_shared_y, b_shared_y);
                            }
                        }
                    }
                }
            }
        };
    }
    test_curve!(NistP256, 32);
    test_curve!(NistP384, 48);
}

pub fn asym_vectors<C: Crypto>(rng: &mut impl Rng) {
    use crate::vectors::asym::*;

    // Ed25519
    if let Ok(Some(public)) =
        <<C as Ecc>::Ed25519 as AsymmetricKey<32, 32>>::load_public((), &ED25519_PK)
        && let Ok(Some(private)) =
            <<C as Ecc>::Ed25519 as AsymmetricKey<32, 32>>::load_private(public, &ED25519_SK)
    {
        let public = <<C as Ecc>::Ed25519 as AsymmetricKey<32, 32>>::as_public(&private);
        let mut out_pk = [0u8; 32];
        <<C as Ecc>::Ed25519 as AsymmetricKey<32, 32>>::store_public(public, &mut out_pk).unwrap();
        assert_eq!(out_pk, ED25519_PK);

        let mut out_r = [0u8; 32];
        let mut out_s = [0u8; 32];
        <<C as Ecc>::Ed25519 as EdwardsCurve<32>>::sign_message(
            &private,
            &[ED25519_MSG],
            &mut out_r,
            &mut out_s,
        )
        .unwrap();
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&out_r);
        sig[32..].copy_from_slice(&out_s);
        assert_eq!(sig, ED25519_SIG);

        let mut r = [0u8; 32];
        r.copy_from_slice(&ED25519_SIG[..32]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&ED25519_SIG[32..]);
        assert!(
            <<C as Ecc>::Ed25519 as EdwardsCurve<32>>::verify_message(
                public,
                &[ED25519_MSG],
                &r,
                &s
            )
            .unwrap()
        );
    }

    // Ed25519ph (RFC 8032 §7.3)
    if let Ok(Some(public)) =
        <<C as Ecc>::Ed25519 as AsymmetricKey<32, 32>>::load_public((), &ED25519PH_PK)
        && let Ok(Some(private)) =
            <<C as Ecc>::Ed25519 as AsymmetricKey<32, 32>>::load_private(public, &ED25519PH_SK)
    {
        let public = <<C as Ecc>::Ed25519 as AsymmetricKey<32, 32>>::as_public(&private);
        let mut out_pk = [0u8; 32];
        <<C as Ecc>::Ed25519 as AsymmetricKey<32, 32>>::store_public(public, &mut out_pk).unwrap();
        assert_eq!(out_pk, ED25519PH_PK);

        let mut out_r = [0u8; 32];
        let mut out_s = [0u8; 32];
        <<C as Ecc>::Ed25519 as EdwardsCurve<32>>::sign_prehash(
            &private,
            &ED25519PH_PREHASH,
            &mut out_r,
            &mut out_s,
        )
        .unwrap();
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&out_r);
        sig[32..].copy_from_slice(&out_s);
        assert_eq!(sig, ED25519PH_SIG);

        let mut r = [0u8; 32];
        r.copy_from_slice(&ED25519PH_SIG[..32]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&ED25519PH_SIG[32..]);
        assert!(
            <<C as Ecc>::Ed25519 as EdwardsCurve<32>>::verify_prehash(
                public,
                &ED25519PH_PREHASH,
                &r,
                &s
            )
            .unwrap()
        );
        assert!(
            !<<C as Ecc>::Ed25519 as EdwardsCurve<32>>::verify_prehash(public, &[0u8; 64], &r, &s)
                .unwrap()
        );
        assert!(
            !<<C as Ecc>::Ed25519 as EdwardsCurve<32>>::verify_message(
                public,
                &[&ED25519PH_PREHASH],
                &r,
                &s
            )
            .unwrap()
        );
    }

    // Ed448 (RFC 8032 §7.4) & Ed448ph (RFC 8032 §7.5)
    if let Ok(Some(public)) =
        <<C as Ecc>::Ed448 as AsymmetricKey<57, 57>>::load_public((), &ED448_PK)
        && let Ok(Some(private)) =
            <<C as Ecc>::Ed448 as AsymmetricKey<57, 57>>::load_private(public, &ED448_SK)
    {
        let public = <<C as Ecc>::Ed448 as AsymmetricKey<57, 57>>::as_public(&private);
        let mut out_pk = [0u8; 57];
        <<C as Ecc>::Ed448 as AsymmetricKey<57, 57>>::store_public(public, &mut out_pk).unwrap();
        assert_eq!(out_pk, ED448_PK);

        let mut out_r = [0u8; 57];
        let mut out_s = [0u8; 57];
        <<C as Ecc>::Ed448 as EdwardsCurve<57>>::sign_message(
            &private,
            &[ED448_MSG],
            &mut out_r,
            &mut out_s,
        )
        .unwrap();
        let mut sig = [0u8; 114];
        sig[..57].copy_from_slice(&out_r);
        sig[57..].copy_from_slice(&out_s);
        assert_eq!(sig, ED448_SIG);

        let mut r = [0u8; 57];
        r.copy_from_slice(&ED448_SIG[..57]);
        let mut s = [0u8; 57];
        s.copy_from_slice(&ED448_SIG[57..]);
        assert!(
            <<C as Ecc>::Ed448 as EdwardsCurve<57>>::verify_message(public, &[ED448_MSG], &r, &s)
                .unwrap()
        );
    }
    if let Ok(Some(public)) =
        <<C as Ecc>::Ed448 as AsymmetricKey<57, 57>>::load_public((), &ED448PH_PK)
        && let Ok(Some(private)) =
            <<C as Ecc>::Ed448 as AsymmetricKey<57, 57>>::load_private(public, &ED448PH_SK)
    {
        let public = <<C as Ecc>::Ed448 as AsymmetricKey<57, 57>>::as_public(&private);
        let mut out_pk = [0u8; 57];
        <<C as Ecc>::Ed448 as AsymmetricKey<57, 57>>::store_public(public, &mut out_pk).unwrap();
        assert_eq!(out_pk, ED448PH_PK);

        let mut out_r = [0u8; 57];
        let mut out_s = [0u8; 57];
        if <<C as Ecc>::Ed448 as EdwardsCurve<57>>::sign_prehash(
            &private,
            &ED448PH_PREHASH,
            &mut out_r,
            &mut out_s,
        )
        .is_ok()
        {
            let mut sig = [0u8; 114];
            sig[..57].copy_from_slice(&out_r);
            sig[57..].copy_from_slice(&out_s);
            assert_eq!(sig, ED448PH_SIG);

            let mut r = [0u8; 57];
            r.copy_from_slice(&ED448PH_SIG[..57]);
            let mut s = [0u8; 57];
            s.copy_from_slice(&ED448PH_SIG[57..]);
            assert!(
                <<C as Ecc>::Ed448 as EdwardsCurve<57>>::verify_prehash(
                    public,
                    &ED448PH_PREHASH,
                    &r,
                    &s
                )
                .unwrap()
            );

            // Context "foo" signature must be rejected by empty-context verify_prehash.
            let mut r_foo = [0u8; 57];
            r_foo.copy_from_slice(&ED448PH_SIG_CTX_FOO[..57]);
            let mut s_foo = [0u8; 57];
            s_foo.copy_from_slice(&ED448PH_SIG_CTX_FOO[57..]);
            assert!(
                !<<C as Ecc>::Ed448 as EdwardsCurve<57>>::verify_prehash(
                    public,
                    &ED448PH_PREHASH,
                    &r_foo,
                    &s_foo
                )
                .unwrap()
            );

            // Domain separation: Ed448ph signature must be rejected by pure Ed448 verify_message.
            assert!(
                !<<C as Ecc>::Ed448 as EdwardsCurve<57>>::verify_message(
                    public,
                    &[&ED448PH_PREHASH],
                    &r,
                    &s
                )
                .unwrap()
            );
        }
    }

    // X25519
    if let Ok(Some(public)) =
        <<C as Ecc>::X25519 as AsymmetricKey<32, 32>>::load_public((), &X25519_A_PK)
        && let Ok(Some(private)) =
            <<C as Ecc>::X25519 as AsymmetricKey<32, 32>>::load_private(public, &X25519_A_SK)
    {
        let public = <<C as Ecc>::X25519 as AsymmetricKey<32, 32>>::as_public(&private);
        let mut out_pk = [0u8; 32];
        <<C as Ecc>::X25519 as AsymmetricKey<32, 32>>::store_public(public, &mut out_pk).unwrap();
        assert_eq!(out_pk, X25519_A_PK);

        let b_pub = <<C as Ecc>::X25519 as AsymmetricKey<32, 32>>::load_public((), &X25519_B_PK)
            .unwrap()
            .unwrap();
        let mut out_ss = [0u8; 32];
        <<C as Ecc>::X25519 as MontgomeryCurve<32>>::ecdh(&private, &b_pub, &mut out_ss).unwrap();
        assert_eq!(out_ss, X25519_SS);
    }

    // ML-KEM-768
    if let Ok(Some(public)) =
        <<C as Mlkem>::Mlkem768 as AsymmetricKey<1184, 64>>::load_public((), &MLKEM768_PK)
        && let Ok(Some(private)) = <<C as Mlkem>::Mlkem768 as AsymmetricKey<1184, 64>>::load_private(
            public,
            &MLKEM768_SEED,
        )
    {
        let public = <<C as Mlkem>::Mlkem768 as AsymmetricKey<1184, 64>>::as_public(&private);
        let mut out_pk = [0u8; 1184];
        <<C as Mlkem>::Mlkem768 as AsymmetricKey<1184, 64>>::store_public(public, &mut out_pk)
            .unwrap();
        assert_eq!(out_pk.as_slice(), MLKEM768_PK);
    }
    if let Ok(Some(public)) =
        <<C as Mlkem>::Mlkem768 as AsymmetricKey<1184, 64>>::load_public((), &MLKEM768_KAT_PK)
        && let Ok(Some(private)) = <<C as Mlkem>::Mlkem768 as AsymmetricKey<1184, 64>>::load_private(
            public,
            &MLKEM768_KAT_SEED,
        )
    {
        let mut out_ss = [0u8; 32];
        let mut ct = [0u8; 1088];
        ct.copy_from_slice(&MLKEM768_KAT_CT);
        <<C as Mlkem>::Mlkem768 as MlkemKey<1184, 1088>>::decapsulate(&private, &ct, &mut out_ss)
            .unwrap();
        assert_eq!(out_ss.as_slice(), MLKEM768_KAT_SS);
    }

    // ML-DSA-65
    if let Ok(Some(public)) =
        <<C as Mldsa>::Mldsa65 as AsymmetricKey<1952, 32>>::load_public((), &MLDSA65_PK)
        && let Ok(Some(private)) =
            <<C as Mldsa>::Mldsa65 as AsymmetricKey<1952, 32>>::load_private(public, &MLDSA65_SEED)
    {
        let public = <<C as Mldsa>::Mldsa65 as AsymmetricKey<1952, 32>>::as_public(&private);
        let mut out_pk = [0u8; 1952];
        <<C as Mldsa>::Mldsa65 as AsymmetricKey<1952, 32>>::store_public(public, &mut out_pk)
            .unwrap();
        assert_eq!(out_pk.as_slice(), MLDSA65_PK);

        let mut sig = [0u8; 3309];
        <<C as Mldsa>::Mldsa65 as MldsaKey<1952, 3309>>::sign_mu(
            rng,
            &private,
            &MLDSA65_KAT_MU,
            &mut sig,
        )
        .unwrap();

        assert!(
            <<C as Mldsa>::Mldsa65 as MldsaKey<1952, 3309>>::verify_mu(
                public,
                &MLDSA65_KAT_MU,
                &MLDSA65_KAT_SIG,
            )
            .unwrap()
        );

        assert!(
            <<C as Mldsa>::Mldsa65 as MldsaKey<1952, 3309>>::verify_mu(
                public,
                &MLDSA65_KAT_MU,
                &sig,
            )
            .unwrap()
        );
    }
}

pub fn interop_ed25519<A: Crypto, B: Crypto>(rng: &mut impl Rng) {
    use crate::vectors::asym::*;
    if let Ok(a_priv) = <<A as Ecc>::Ed25519 as AsymmetricKey<32, 32>>::generate(rng, ())
        && let Ok(_b_priv) = <<B as Ecc>::Ed25519 as AsymmetricKey<32, 32>>::generate(rng, ())
    {
        let mut out_r = [0u8; 32];
        let mut out_s = [0u8; 32];
        <<A as Ecc>::Ed25519 as EdwardsCurve<32>>::sign_message(
            &a_priv,
            &[ED25519_MSG],
            &mut out_r,
            &mut out_s,
        )
        .unwrap();
        let a_pub = <<A as Ecc>::Ed25519 as AsymmetricKey<32, 32>>::as_public(&a_priv);
        let mut out_pk = [0u8; 32];
        <<A as Ecc>::Ed25519 as AsymmetricKey<32, 32>>::store_public(a_pub, &mut out_pk).unwrap();
        let b_a_pub = <<B as Ecc>::Ed25519 as AsymmetricKey<32, 32>>::load_public((), &out_pk)
            .unwrap()
            .unwrap();
        assert!(
            <<B as Ecc>::Ed25519 as EdwardsCurve<32>>::verify_message(
                &b_a_pub,
                &[ED25519_MSG],
                &out_r,
                &out_s,
            )
            .unwrap()
        );
        assert!(
            !<<B as Ecc>::Ed25519 as EdwardsCurve<32>>::verify_message(
                &b_a_pub,
                &[b"wrong"],
                &out_r,
                &out_s,
            )
            .unwrap()
        );

        let prehash = [0x5a; 64];
        if <<A as Ecc>::Ed25519 as EdwardsCurve<32>>::sign_prehash(
            &a_priv, &prehash, &mut out_r, &mut out_s,
        )
        .is_ok()
            && let Ok(valid) = <<B as Ecc>::Ed25519 as EdwardsCurve<32>>::verify_prehash(
                &b_a_pub, &prehash, &out_r, &out_s,
            )
        {
            assert!(valid);
            assert!(
                !<<B as Ecc>::Ed25519 as EdwardsCurve<32>>::verify_prehash(
                    &b_a_pub,
                    &[0x5b; 64],
                    &out_r,
                    &out_s,
                )
                .unwrap()
            );
            assert!(
                !<<B as Ecc>::Ed25519 as EdwardsCurve<32>>::verify_message(
                    &b_a_pub,
                    &[&prehash],
                    &out_r,
                    &out_s,
                )
                .unwrap()
            );
        }
    }
}

pub fn interop_ed448<A: Crypto, B: Crypto>(rng: &mut impl Rng) {
    use crate::vectors::asym::*;
    if let Ok(a_priv) = <<A as Ecc>::Ed448 as AsymmetricKey<57, 57>>::generate(rng, ())
        && let Ok(_b_priv) = <<B as Ecc>::Ed448 as AsymmetricKey<57, 57>>::generate(rng, ())
    {
        let mut out_r = [0u8; 57];
        let mut out_s = [0u8; 57];
        <<A as Ecc>::Ed448 as EdwardsCurve<57>>::sign_message(
            &a_priv,
            &[ED448_MSG],
            &mut out_r,
            &mut out_s,
        )
        .unwrap();
        let a_pub = <<A as Ecc>::Ed448 as AsymmetricKey<57, 57>>::as_public(&a_priv);
        let mut out_pk = [0u8; 57];
        <<A as Ecc>::Ed448 as AsymmetricKey<57, 57>>::store_public(a_pub, &mut out_pk).unwrap();
        let b_a_pub = <<B as Ecc>::Ed448 as AsymmetricKey<57, 57>>::load_public((), &out_pk)
            .unwrap()
            .unwrap();
        assert!(
            <<B as Ecc>::Ed448 as EdwardsCurve<57>>::verify_message(
                &b_a_pub,
                &[ED448_MSG],
                &out_r,
                &out_s,
            )
            .unwrap()
        );
        assert!(
            !<<B as Ecc>::Ed448 as EdwardsCurve<57>>::verify_message(
                &b_a_pub,
                &[b"wrong"],
                &out_r,
                &out_s,
            )
            .unwrap()
        );

        let prehash = [0x6c; 64];
        if <<A as Ecc>::Ed448 as EdwardsCurve<57>>::sign_prehash(
            &a_priv, &prehash, &mut out_r, &mut out_s,
        )
        .is_ok()
            && let Ok(valid) = <<B as Ecc>::Ed448 as EdwardsCurve<57>>::verify_prehash(
                &b_a_pub, &prehash, &out_r, &out_s,
            )
        {
            assert!(valid);
            assert!(
                !<<B as Ecc>::Ed448 as EdwardsCurve<57>>::verify_prehash(
                    &b_a_pub,
                    &[0x6d; 64],
                    &out_r,
                    &out_s,
                )
                .unwrap()
            );
            assert!(
                !<<B as Ecc>::Ed448 as EdwardsCurve<57>>::verify_message(
                    &b_a_pub,
                    &[&prehash],
                    &out_r,
                    &out_s,
                )
                .unwrap()
            );
        }
    }
}

pub fn interop_mlkem<A: Crypto, B: Crypto>(rng: &mut impl Rng) {
    if let Ok(a_priv) = <<A as Mlkem>::Mlkem768 as AsymmetricKey<1184, 64>>::generate(rng, ())
        && let Ok(_b_priv) = <<B as Mlkem>::Mlkem768 as AsymmetricKey<1184, 64>>::generate(rng, ())
    {
        let a_pub = <<A as Mlkem>::Mlkem768 as AsymmetricKey<1184, 64>>::as_public(&a_priv);
        let mut out_pk = [0u8; 1184];
        <<A as Mlkem>::Mlkem768 as AsymmetricKey<1184, 64>>::store_public(a_pub, &mut out_pk)
            .unwrap();

        let b_a_pub = <<B as Mlkem>::Mlkem768 as AsymmetricKey<1184, 64>>::load_public((), &out_pk)
            .unwrap()
            .unwrap();

        let mut ct = [0u8; 1088];
        let mut ss_b = [0u8; 32];
        <<B as Mlkem>::Mlkem768 as MlkemKey<1184, 1088>>::encapsulate(
            rng, &b_a_pub, &mut ct, &mut ss_b,
        )
        .unwrap();

        let mut ss_a = [0u8; 32];
        <<A as Mlkem>::Mlkem768 as MlkemKey<1184, 1088>>::decapsulate(&a_priv, &ct, &mut ss_a)
            .unwrap();

        assert_eq!(ss_a, ss_b);
    }
}

pub fn interop_mldsa<A: Crypto, B: Crypto>(rng: &mut impl Rng) {
    macro_rules! test_mldsa {
        ($param:ident, $pk_size:literal, $sig_size:literal) => {
            {
                #[inline(never)]
                fn inner<A: Crypto, B: Crypto>(rng: &mut impl Rng) {
                    if let Ok(a_priv) =
                        <<A as Mldsa>::$param as AsymmetricKey<$pk_size, 32>>::generate(rng, ())
                    {
                        let a_pub =
                            <<A as Mldsa>::$param as AsymmetricKey<$pk_size, 32>>::as_public(&a_priv);
                        let mut out_pk = [0u8; $pk_size];
                        <<A as Mldsa>::$param as AsymmetricKey<$pk_size, 32>>::store_public(a_pub, &mut out_pk)
                            .unwrap();
                        let b_a_pub =
                            <<B as Mldsa>::$param as AsymmetricKey<$pk_size, 32>>::load_public((), &out_pk)
                                .unwrap()
                                .unwrap();

                        // sign_mu
                        let mut sig = [0u8; $sig_size];
                        let mu = [0x42; 64];
                        <<A as Mldsa>::$param as MldsaKey<$pk_size, $sig_size>>::sign_mu(
                            rng, &a_priv, &mu, &mut sig,
                        )
                        .unwrap();
                        assert!(
                            <<B as Mldsa>::$param as MldsaKey<$pk_size, $sig_size>>::verify_mu(
                                &b_a_pub, &mu, &sig
                            )
                            .unwrap()
                        );
                        assert!(
                            !<<B as Mldsa>::$param as MldsaKey<$pk_size, $sig_size>>::verify_mu(
                                &b_a_pub,
                                &[0x43; 64],
                                &sig
                            )
                            .unwrap()
                        );

                        // sign_message
                        for ctx in [b"" as &[u8], b"tpm2 test context"] {
                            <<A as Mldsa>::$param as MldsaKey<$pk_size, $sig_size>>::sign_message(
                                rng,
                                &a_priv,
                                ctx,
                                &[b"hello", b"world"],
                                &mut sig,
                            )
                            .unwrap();
                            assert!(
                                <<B as Mldsa>::$param as MldsaKey<$pk_size, $sig_size>>::verify_message(
                                    &b_a_pub,
                                    ctx,
                                    &[b"hello", b"world"],
                                    &sig
                                )
                                .unwrap()
                            );
                            assert!(
                                !<<B as Mldsa>::$param as MldsaKey<$pk_size, $sig_size>>::verify_message(
                                    &b_a_pub,
                                    b"wrong ctx",
                                    &[b"hello", b"world"],
                                    &sig
                                )
                                .unwrap()
                            );
                            assert!(
                                !<<B as Mldsa>::$param as MldsaKey<$pk_size, $sig_size>>::verify_message(
                                    &b_a_pub,
                                    ctx,
                                    &[b"wrong", b"msg"],
                                    &sig
                                )
                                .unwrap()
                            );
                        }

                        // sign_prehash
                        let digest = TpmtHa::Sha256(&[0xaa; 32].try_into().unwrap());
                        let wrong_digest = TpmtHa::Sha256(&[0xab; 32].try_into().unwrap());
                        for ctx in [b"" as &[u8], b"tpm2 test context"] {
                            <<A as Mldsa>::$param as MldsaKey<$pk_size, $sig_size>>::sign_prehash(
                                rng, &a_priv, ctx, digest, &mut sig,
                            )
                            .unwrap();
                            assert!(
                                <<B as Mldsa>::$param as MldsaKey<$pk_size, $sig_size>>::verify_prehash(
                                    &b_a_pub, ctx, digest, &sig
                                )
                                .unwrap()
                            );
                            assert!(
                                !<<B as Mldsa>::$param as MldsaKey<$pk_size, $sig_size>>::verify_prehash(
                                    &b_a_pub,
                                    b"wrong ctx",
                                    digest,
                                    &sig
                                )
                                .unwrap()
                            );
                            assert!(
                                !<<B as Mldsa>::$param as MldsaKey<$pk_size, $sig_size>>::verify_prehash(
                                    &b_a_pub,
                                    ctx,
                                    wrong_digest,
                                    &sig
                                )
                                .unwrap()
                            );

                            let der_oid = match digest.hash_alg() {
                                tpm2::TpmiAlgHash::Sha256 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
                                _ => &[][..],
                            };
                            let mut full_msg = alloc::vec::Vec::new();
                            full_msg.extend_from_slice(der_oid);
                            full_msg.extend_from_slice(digest.digest());
                            assert!(
                                !<<B as Mldsa>::$param as MldsaKey<$pk_size, $sig_size>>::verify_message(
                                    &b_a_pub,
                                    ctx,
                                    &[&full_msg],
                                    &sig
                                )
                                .unwrap()
                            );
                        }
                    }
                }
                inner::<A, B>(rng);
            }
        };
    }

    test_mldsa!(Mldsa44, 1312, 2420);
    test_mldsa!(Mldsa65, 1952, 3309);
    test_mldsa!(Mldsa87, 2592, 4627);
}

pub fn interop_x25519<A: Crypto, B: Crypto>(rng: &mut impl Rng) {
    if let Ok(a_priv) = <<A as Ecc>::X25519 as AsymmetricKey<32, 32>>::generate(rng, ())
        && let Ok(b_priv) = <<B as Ecc>::X25519 as AsymmetricKey<32, 32>>::generate(rng, ())
    {
        let a_pub = <<A as Ecc>::X25519 as AsymmetricKey<32, 32>>::as_public(&a_priv);
        let b_pub = <<B as Ecc>::X25519 as AsymmetricKey<32, 32>>::as_public(&b_priv);

        let mut out_pk_a = [0u8; 32];
        <<A as Ecc>::X25519 as AsymmetricKey<32, 32>>::store_public(a_pub, &mut out_pk_a).unwrap();
        let b_a_pub = <<B as Ecc>::X25519 as AsymmetricKey<32, 32>>::load_public((), &out_pk_a)
            .unwrap()
            .unwrap();

        let mut out_pk_b = [0u8; 32];
        <<B as Ecc>::X25519 as AsymmetricKey<32, 32>>::store_public(b_pub, &mut out_pk_b).unwrap();
        let a_b_pub = <<A as Ecc>::X25519 as AsymmetricKey<32, 32>>::load_public((), &out_pk_b)
            .unwrap()
            .unwrap();

        let mut ss_a = [0u8; 32];
        <<A as Ecc>::X25519 as MontgomeryCurve<32>>::ecdh(&a_priv, &a_b_pub, &mut ss_a).unwrap();

        let mut ss_b = [0u8; 32];
        <<B as Ecc>::X25519 as MontgomeryCurve<32>>::ecdh(&b_priv, &b_a_pub, &mut ss_b).unwrap();

        assert_eq!(ss_a, ss_b);
    }
}

macro_rules! test_hash {
    ($alg:ident, $arr:expr, $len:expr) => {
        for &(msg, expected) in $arr {
            if let Ok(mut ctx) = HashContext::<C>::new(TpmiAlgHash::$alg) {
                ctx.update(msg).unwrap();
                let mut out = [0u8; $len];
                ctx.finalize(&mut out).unwrap();
                assert_eq!(out, expected);
            }
        }
    };
    (million $alg:ident, $expected:expr, $len:expr) => {
        if let Ok(mut ctx) = HashContext::<C>::new(TpmiAlgHash::$alg) {
            let msg = &[b'a'; 1000];
            for _ in 0..1000 {
                ctx.update(msg).unwrap();
            }
            let mut out = [0u8; $len];
            ctx.finalize(&mut out).unwrap();
            assert_eq!(out, $expected);
        }
    };
}
pub fn hash_vectors<C: Crypto>() {
    test_hash!(Sha1, crate::vectors::hash::SHA1, 20);
    test_hash!(Sha256, crate::vectors::hash::SHA256, 32);
    test_hash!(Sha384, crate::vectors::hash::SHA384, 48);
    test_hash!(Sha512, crate::vectors::hash::SHA512, 64);
    test_hash!(Sm3_256, crate::vectors::hash::SM3_256, 32);
    test_hash!(Sha3_256, crate::vectors::hash::SHA3_256, 32);
    test_hash!(Sha3_384, crate::vectors::hash::SHA3_384, 48);
    test_hash!(Sha3_512, crate::vectors::hash::SHA3_512, 64);
    test_hash!(million Sha1, crate::vectors::hash::SHA1_MILLION_A, 20);
    test_hash!(million Sha256, crate::vectors::hash::SHA256_MILLION_A, 32);
    test_hash!(million Sha384, crate::vectors::hash::SHA384_MILLION_A, 48);
    test_hash!(million Sha512, crate::vectors::hash::SHA512_MILLION_A, 64);
    test_hash!(million Sm3_256, crate::vectors::hash::SM3_256_MILLION_A, 32);
    test_hash!(million Sha3_256, crate::vectors::hash::SHA3_256_MILLION_A, 32);
    test_hash!(million Sha3_384, crate::vectors::hash::SHA3_384_MILLION_A, 48);
    test_hash!(million Sha3_512, crate::vectors::hash::SHA3_512_MILLION_A, 64);
}

macro_rules! test_hmac {
    ($alg:ident, $arr:expr, $len:expr) => {
        for (i, &(key, data)) in crate::vectors::hmac::CASES.iter().enumerate() {
            if let Ok(mut ctx) = HmacContext::<C>::new(TpmiAlgHash::$alg, key) {
                ctx.update(data).unwrap();
                let mut out = [0u8; $len];
                ctx.finalize(&mut out).unwrap();
                assert_eq!(out, $arr[i]);
            }
        }
    };
}
pub fn hmac_vectors<C: Crypto>() {
    test_hmac!(Sha1, crate::vectors::hmac::SHA1, 20);
    test_hmac!(Sha256, crate::vectors::hmac::SHA256, 32);
    test_hmac!(Sha384, crate::vectors::hmac::SHA384, 48);
    test_hmac!(Sha512, crate::vectors::hmac::SHA512, 64);
    test_hmac!(Sm3_256, crate::vectors::hmac::SM3_256, 32);
    test_hmac!(Sha3_256, crate::vectors::hmac::SHA3_256, 32);
    test_hmac!(Sha3_384, crate::vectors::hmac::SHA3_384, 48);
    test_hmac!(Sha3_512, crate::vectors::hmac::SHA3_512, 64);
}

macro_rules! test_kdfa {
    ($alg:ident, $arr:expr) => {
        for kat in $arr {
            let mut out = [0u8; 1024];
            if kdfa::<C>(
                TpmiAlgHash::$alg,
                kat.key,
                kat.label,
                (kat.context_u, kat.context_v),
                &mut out[..kat.out.len()],
            )
            .is_ok()
            {
                assert_eq!(&out[..kat.out.len()], kat.out);
            }
        }
    };
}
macro_rules! test_kdfe {
    ($alg:ident, $arr:expr) => {
        for kat in $arr {
            let mut out = [0u8; 1024];
            if kdfe::<C>(
                TpmiAlgHash::$alg,
                kat.key,
                kat.label,
                (kat.context_u, kat.context_v),
                &mut out[..kat.out.len()],
            )
            .is_ok()
            {
                assert_eq!(&out[..kat.out.len()], kat.out);
            }
        }
    };
}
pub fn kdf_vectors<C: Crypto>() {
    test_kdfa!(Sha1, crate::vectors::kdf::KDFA_SHA1);
    test_kdfa!(Sha256, crate::vectors::kdf::KDFA_SHA256);
    test_kdfa!(Sha384, crate::vectors::kdf::KDFA_SHA384);
    test_kdfa!(Sha512, crate::vectors::kdf::KDFA_SHA512);
    test_kdfa!(Sm3_256, crate::vectors::kdf::KDFA_SM3_256);
    test_kdfa!(Sha3_256, crate::vectors::kdf::KDFA_SHA3_256);
    test_kdfa!(Sha3_384, crate::vectors::kdf::KDFA_SHA3_384);
    test_kdfa!(Sha3_512, crate::vectors::kdf::KDFA_SHA3_512);

    test_kdfe!(Sha1, crate::vectors::kdf::KDFE_SHA1);
    test_kdfe!(Sha256, crate::vectors::kdf::KDFE_SHA256);
    test_kdfe!(Sha384, crate::vectors::kdf::KDFE_SHA384);
    test_kdfe!(Sha512, crate::vectors::kdf::KDFE_SHA512);
    test_kdfe!(Sm3_256, crate::vectors::kdf::KDFE_SM3_256);
    test_kdfe!(Sha3_256, crate::vectors::kdf::KDFE_SHA3_256);
    test_kdfe!(Sha3_384, crate::vectors::kdf::KDFE_SHA3_384);
    test_kdfe!(Sha3_512, crate::vectors::kdf::KDFE_SHA3_512);
}

pub fn cipher_vectors<C: Crypto>() {
    use crate::vectors::cipher::*;
    macro_rules! test_modes {
        ($modes:expr, $key_alg:ident, $key_val:expr) => {
            let key = SymmetricKey::$key_alg($key_val);
            for (idx, mode) in ALL_MODES.iter().enumerate() {
                let (expected_ct, _expected_iv) = $modes[idx];
                let iv0 = if *mode == TpmiAlgCipherMode::Ctr {
                    CTR_IV
                } else {
                    IV
                };
                let iv0 = if *mode == TpmiAlgCipherMode::Ecb {
                    [0; 16]
                } else {
                    iv0
                };

                let (mut data, mut enc_iv) = (PLAINTEXT, iv0);
                if crypt_once::<C>(key, *mode, Direction::Encrypt, &mut enc_iv, &mut data).is_err()
                {
                    continue; // Skip unsupported
                }
                assert_eq!(data, expected_ct, "{mode:?}");

                let mut dec_iv = iv0;
                crypt_once::<C>(key, *mode, Direction::Decrypt, &mut dec_iv, &mut data).unwrap();
                assert_eq!(data, PLAINTEXT, "{mode:?}");
            }
        };
    }

    test_modes!(MODES_AES128, Aes128, &KEY128);
    test_modes!(MODES_AES192, Aes192, &KEY192);
    test_modes!(MODES_AES256, Aes256, &KEY256);
    test_modes!(MODES_SM4_128, Sm4_128, &KEY128);
    test_modes!(MODES_CAMELLIA128, Camellia128, &KEY128);
    test_modes!(MODES_CAMELLIA192, Camellia192, &KEY192);
    test_modes!(MODES_CAMELLIA256, Camellia256, &KEY256);
}
