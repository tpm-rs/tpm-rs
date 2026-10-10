//! Tests for [`Symmetric`] (via [`encrypt`], [`decrypt`], and
//! [`encrypt_decrypt`]).
//!
//! The chaining value (`ivOut`) written back to the IV buffer is checked
//! against the TPM reference implementation (`CryptSym.c`):
//!
//! - CBC and CFB: the last ciphertext block. For a partial final CFB block,
//!   its ciphertext bytes followed by zeros.
//! - OFB: the last encrypted IV (keystream block).
//! - CTR: the initial counter plus the number of (partial) blocks, as a
//!   128-bit big-endian integer.

use tpm2::{
    AlgSym, TpmiAlgCipherMode,
    crypto::{Direction, ModeIv, Symmetric, SymmetricKey, decrypt, encrypt, encrypt_decrypt},
};

use crate::{
    Caps, Check, expect_support,
    util::{CIPHERS, MODES, assert_bytes},
    vectors::cipher as kat,
};

/// Block size of every cipher.
const BLOCK: usize = AlgSym::BLOCK_SIZE;

/// Returns the test key for `alg`.
pub(crate) fn key(alg: AlgSym) -> SymmetricKey<'static> {
    let bytes: &'static [u8] = match alg.key_bytes() {
        16 => &kat::KEY128,
        24 => &kat::KEY192,
        _ => &kat::KEY256,
    };
    SymmetricKey::new(alg, bytes).expect("test key has the wrong size")
}

/// Returns the `(ciphertext, iv_out)` vectors of `alg`, in [`MODES`] order.
fn vectors(alg: AlgSym) -> &'static [([u8; 64], [u8; 16]); 5] {
    match alg {
        AlgSym::Aes128 => &kat::MODES_AES128,
        AlgSym::Aes192 => &kat::MODES_AES192,
        AlgSym::Aes256 => &kat::MODES_AES256,
        AlgSym::Sm4_128 => &kat::MODES_SM4_128,
        AlgSym::Camellia128 => &kat::MODES_CAMELLIA128,
        AlgSym::Camellia192 => &kat::MODES_CAMELLIA192,
        AlgSym::Camellia256 => &kat::MODES_CAMELLIA256,
    }
}

/// Returns the vectors of `alg` in `mode`.
fn vector(alg: AlgSym, mode: TpmiAlgCipherMode) -> &'static ([u8; 64], [u8; 16]) {
    let index = MODES.iter().position(|&m| m == mode).expect("unknown mode");
    &vectors(alg)[index]
}

/// Returns the initial IV of `mode` in the test vectors.
fn initial_iv(mode: TpmiAlgCipherMode) -> [u8; BLOCK] {
    match mode {
        TpmiAlgCipherMode::Ctr => kat::CTR_IV,
        _ => kat::IV,
    }
}

/// Wraps `iv` for `mode`.
fn mode_iv(mode: TpmiAlgCipherMode, iv: &mut [u8; BLOCK]) -> ModeIv<'_> {
    match mode {
        TpmiAlgCipherMode::Ctr => ModeIv::Ctr(iv),
        TpmiAlgCipherMode::Ofb => ModeIv::Ofb(iv),
        TpmiAlgCipherMode::Cbc => ModeIv::Cbc(iv),
        TpmiAlgCipherMode::Cfb => ModeIv::Cfb(iv),
        TpmiAlgCipherMode::Ecb => ModeIv::Ecb,
    }
}

/// Encrypts or decrypts `data` with a copy of `iv`, returning the updated IV.
fn crypt<C: Symmetric>(
    c: &C,
    alg: AlgSym,
    mode: TpmiAlgCipherMode,
    dir: Direction,
    iv: [u8; BLOCK],
    data: &mut [u8],
) -> [u8; BLOCK] {
    let mut iv = iv;
    encrypt_decrypt(c, key(alg), mode_iv(mode, &mut iv), dir, data)
        .check(format!("{alg:?}-{mode:?} {dir:?}"));
    iv
}

/// Returns `true` if `alg` in `mode` is supported (checking that it correctly
/// fails otherwise).
fn supported<C: Symmetric>(c: &C, caps: &Caps, alg: AlgSym, mode: TpmiAlgCipherMode) -> bool {
    let expected = caps.symmetric.contains(&alg) && caps.modes.contains(&mode);
    let mut iv = initial_iv(mode);
    let mut data = [0u8; BLOCK];
    let result = encrypt(c, key(alg), mode_iv(mode, &mut iv), &mut data);
    expect_support(expected, format!("Symmetric {alg:?}-{mode:?}"), result).is_some()
}

fn kat<C: Symmetric>(c: &C, caps: &Caps, alg: AlgSym) {
    for &mode in MODES {
        if !supported(c, caps, alg, mode) {
            continue;
        }
        let (ciphertext, iv_out) = vector(alg, mode);
        let what = format!("{alg:?}-{mode:?}");

        let mut data = kat::PLAINTEXT;
        let mut iv = initial_iv(mode);
        encrypt(c, key(alg), mode_iv(mode, &mut iv), &mut data).check(&what);
        assert_bytes(&data, ciphertext, format!("{what} ciphertext"));
        if mode != TpmiAlgCipherMode::Ecb {
            assert_bytes(&iv, iv_out, format!("{what} encryption ivOut"));
        }

        let mut iv = initial_iv(mode);
        decrypt(c, key(alg), mode_iv(mode, &mut iv), &mut data).check(&what);
        assert_bytes(&data, &kat::PLAINTEXT, format!("{what} plaintext"));
        if mode != TpmiAlgCipherMode::Ecb {
            assert_bytes(&iv, iv_out, format!("{what} decryption ivOut"));
        }
    }
}

macro_rules! kat_fns {
    ($($name:ident => $alg:ident),* $(,)?) => {$(
        #[doc = concat!("Known answers for ", stringify!($alg), " in every mode (NIST SP 800-38A data), including `ivOut`.")]
        pub fn $name<C: Symmetric>(c: &C, caps: &Caps) {
            kat(c, caps, AlgSym::$alg);
        }
    )*};
}

kat_fns! {
    aes128_kat => Aes128,
    aes192_kat => Aes192,
    aes256_kat => Aes256,
    sm4_128_kat => Sm4_128,
    camellia128_kat => Camellia128,
    camellia192_kat => Camellia192,
    camellia256_kat => Camellia256,
}

/// Processing data in two calls (passing `ivOut` as the next IV) gives the
/// same result as one call, in both directions.
pub fn symmetric_chaining<C: Symmetric>(c: &C, caps: &Caps) {
    for &alg in CIPHERS {
        for &mode in MODES {
            if !supported(c, caps, alg, mode) {
                continue;
            }
            for dir in [Direction::Encrypt, Direction::Decrypt] {
                let mut whole = kat::PLAINTEXT;
                let iv_whole = crypt(c, alg, mode, dir, initial_iv(mode), &mut whole);
                for split in [BLOCK, 2 * BLOCK, 3 * BLOCK] {
                    let mut parts = kat::PLAINTEXT;
                    let (first, second) = parts.split_at_mut(split);
                    let iv = crypt(c, alg, mode, dir, initial_iv(mode), first);
                    let iv = crypt(c, alg, mode, dir, iv, second);
                    let what = format!("{alg:?}-{mode:?} {dir:?} split at {split}");
                    assert_bytes(&parts, &whole, &what);
                    assert_bytes(&iv, &iv_whole, format!("{what} ivOut"));
                }
            }
        }
    }
}

/// The stream modes (CTR, OFB, and CFB) handle data that isn't a multiple of
/// the block size, including the chaining value.
pub fn symmetric_partial_blocks<C: Symmetric>(c: &C, caps: &Caps) {
    let stream_modes = [
        TpmiAlgCipherMode::Ctr,
        TpmiAlgCipherMode::Ofb,
        TpmiAlgCipherMode::Cfb,
    ];
    for &alg in CIPHERS {
        for mode in stream_modes {
            if !supported(c, caps, alg, mode) {
                continue;
            }
            let (ciphertext, _) = vector(alg, mode);
            for len in [1, 7, 15, 17, 31, 33, 47, 63] {
                let what = format!("{alg:?}-{mode:?} of {len} bytes");
                let mut data = kat::PLAINTEXT[..len].to_vec();
                let iv = crypt(
                    c,
                    alg,
                    mode,
                    Direction::Encrypt,
                    initial_iv(mode),
                    &mut data,
                );
                assert_bytes(&data, &ciphertext[..len], &what);
                let expected_iv = partial_iv_out(alg, mode, len);
                assert_bytes(&iv, &expected_iv, format!("{what} encryption ivOut"));

                let iv = crypt(
                    c,
                    alg,
                    mode,
                    Direction::Decrypt,
                    initial_iv(mode),
                    &mut data,
                );
                assert_bytes(&data, &kat::PLAINTEXT[..len], &what);
                assert_bytes(&iv, &expected_iv, format!("{what} decryption ivOut"));
            }
        }
    }
}

/// Returns the TPM reference implementation's `ivOut` after `len` bytes of
/// the test vector plaintext.
fn partial_iv_out(alg: AlgSym, mode: TpmiAlgCipherMode, len: usize) -> [u8; BLOCK] {
    let (ciphertext, _) = vector(alg, mode);
    let blocks = len.div_ceil(BLOCK);
    let last = (blocks - 1) * BLOCK..blocks * BLOCK;
    let mut iv = [0u8; BLOCK];
    match mode {
        TpmiAlgCipherMode::Ctr => {
            let counter = u128::from_be_bytes(initial_iv(mode));
            let blocks = u128::try_from(blocks).expect("block count overflow");
            iv = counter.wrapping_add(blocks).to_be_bytes();
        }
        TpmiAlgCipherMode::Ofb => {
            // The keystream block is the ciphertext XOR the plaintext.
            let pairs = ciphertext[last.clone()].iter().zip(&kat::PLAINTEXT[last]);
            for (v, (c, p)) in iv.iter_mut().zip(pairs) {
                *v = c ^ p;
            }
        }
        TpmiAlgCipherMode::Cfb => {
            let used = len - last.start;
            iv[..used].copy_from_slice(&ciphertext[last.start..len]);
        }
        TpmiAlgCipherMode::Cbc | TpmiAlgCipherMode::Ecb => unreachable!("not a stream mode"),
    }
    iv
}

/// Empty data succeeds in every mode and leaves the IV unchanged.
pub fn symmetric_empty_data<C: Symmetric>(c: &C, caps: &Caps) {
    for &alg in CIPHERS {
        for &mode in MODES {
            if !supported(c, caps, alg, mode) {
                continue;
            }
            for dir in [Direction::Encrypt, Direction::Decrypt] {
                let iv = crypt(c, alg, mode, dir, initial_iv(mode), &mut []);
                assert_bytes(
                    &iv,
                    &initial_iv(mode),
                    format!("{alg:?}-{mode:?} {dir:?} ivOut"),
                );
            }
        }
    }
}
