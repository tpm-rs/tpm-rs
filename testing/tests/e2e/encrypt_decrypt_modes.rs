//! `TPM2_EncryptDecrypt` and `TPM2_EncryptDecrypt2` in every implemented block cipher mode (CTR,
//! OFB, CBC, CFB and ECB) with every implemented block cipher and key size (AES-128/256 and, with
//! the `camellia*` features, Camellia): the ciphertext against a client-side model of the mode
//! built on the single-block cipher, the output chaining value `ivOut` (TPM 2.0 Part 3: "chaining
//! value to use for IV in next round"; CTR: the next counter block, OFB: the last keystream
//! block, CBC: the last ciphertext block, CFB: the last ciphertext block zero-padded after a
//! partial block, ECB: empty), chaining across calls, the mode taken from the key or from the
//! command, and decryption back to the plaintext.
#![allow(deprecated)] // TPM2_EncryptDecrypt is deprecated upstream but still implemented.

use crate::_common::{
    ClientCrypto, execute_with_password_sessions, get_bound_unique, leak_bytes, load_with_private,
};
use testing::tpm::Tpm;
use tpm2::commands::{EncryptDecrypt, EncryptDecrypt2};
use tpm2::crypto::{CipherInput, Direction, SymmetricKey};
use tpm2::{
    AlgSym, Handle, PublicParmsAndId, Tpm2bDigest, Tpm2bIv, Tpm2bMaxBuffer, Tpm2bSymKey,
    TpmaObject, TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode, TpmtPublic, TpmtSymDefObject,
    TpmuSensitiveComposite,
};

/// The block size of the block ciphers.
const BLOCK: usize = 16;

/// Every implemented mode.
const MODES: [TpmiAlgCipherMode; 5] = [
    TpmiAlgCipherMode::Ctr,
    TpmiAlgCipherMode::Ofb,
    TpmiAlgCipherMode::Cbc,
    TpmiAlgCipherMode::Cfb,
    TpmiAlgCipherMode::Ecb,
];

/// Every implemented block cipher and key size.
fn block_ciphers() -> Vec<AlgSym> {
    #[allow(unused_mut)]
    let mut algs = vec![AlgSym::Aes128, AlgSym::Aes256];
    #[cfg(feature = "camellia128")]
    algs.push(AlgSym::Camellia128);
    #[cfg(feature = "camellia192")]
    algs.push(AlgSym::Camellia192);
    #[cfg(feature = "camellia256")]
    algs.push(AlgSym::Camellia256);
    algs
}

/// Whether `mode` needs a whole number of blocks (CBC, ECB).
fn is_block_mode(mode: TpmiAlgCipherMode) -> bool {
    matches!(mode, TpmiAlgCipherMode::Cbc | TpmiAlgCipherMode::Ecb)
}

/// The message lengths tested in `mode`: around the block size, and only whole blocks for CBC
/// and ECB.
fn lengths(mode: TpmiAlgCipherMode) -> &'static [usize] {
    if is_block_mode(mode) {
        &[0, 16, 48]
    } else {
        &[0, 1, 15, 16, 17, 33, 64]
    }
}

/// `E_K(block)` with the client's crypto provider: CFB encryption of one zero block with the IV
/// `block` yields the encrypted block (independent of the mode implementations under test).
fn encrypt_block(alg: AlgSym, key: &[u8], block: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut iv = *block;
    let mut out = [0u8; BLOCK];
    let input = CipherInput::new(TpmiAlgCipherMode::Cfb, &mut iv, &mut out).unwrap();
    SymmetricKey::new(alg, key)
        .unwrap()
        .crypt::<ClientCrypto>(Direction::Encrypt, input)
        .unwrap();
    out
}

/// The client-side model of encryption in `mode` (the TCG reference's
/// `CryptSymmetricEncrypt()`): the ciphertext of `data` and `ivOut`.
fn model_encrypt(
    alg: AlgSym,
    key: &[u8],
    mode: TpmiAlgCipherMode,
    iv_in: &[u8; BLOCK],
    data: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut iv = *iv_in;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(BLOCK) {
        match mode {
            TpmiAlgCipherMode::Ctr => {
                let keystream = encrypt_block(alg, key, &iv);
                for byte in iv.iter_mut().rev() {
                    *byte = byte.wrapping_add(1);
                    if *byte != 0 {
                        break;
                    }
                }
                out.extend(chunk.iter().zip(keystream).map(|(d, k)| d ^ k));
            }
            TpmiAlgCipherMode::Ofb => {
                iv = encrypt_block(alg, key, &iv);
                out.extend(chunk.iter().zip(iv).map(|(d, k)| d ^ k));
            }
            TpmiAlgCipherMode::Cbc => {
                for (v, d) in iv.iter_mut().zip(chunk) {
                    *v ^= d;
                }
                iv = encrypt_block(alg, key, &iv);
                out.extend_from_slice(&iv);
            }
            TpmiAlgCipherMode::Cfb => {
                let keystream = encrypt_block(alg, key, &iv);
                let mut next = [0u8; BLOCK];
                for (i, d) in chunk.iter().enumerate() {
                    next[i] = d ^ keystream[i];
                }
                out.extend_from_slice(&next[..chunk.len()]);
                iv = next;
            }
            TpmiAlgCipherMode::Ecb => {
                out.extend_from_slice(&encrypt_block(alg, key, chunk.try_into().unwrap()));
            }
        }
    }
    let iv_out = if mode == TpmiAlgCipherMode::Ecb {
        Vec::new()
    } else {
        iv.to_vec()
    };
    (out, iv_out)
}

/// Loads (`TPM2_LoadExternal`, NULL hierarchy) an encryption/decryption SYMCIPHER key `key` of
/// `alg` with the mode `mode`.
fn load_key(sim: &mut Tpm, alg: AlgSym, mode: Option<TpmiAlgCipherMode>, key: &[u8]) -> Handle {
    let key: &'static [u8] = leak_bytes(key);
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject {
                alg,
                mode: mode.map(TpmiAlgSymMode::Cipher),
            },
            get_bound_unique(key),
        ),
    };
    load_with_private(
        sim,
        public,
        TpmuSensitiveComposite::Sym(Tpm2bSymKey::from_bytes(key).unwrap()),
        &[0x02; 32],
    )
}

/// The IV of a command in `mode`: empty for ECB, `iv` otherwise.
fn iv_for(mode: TpmiAlgCipherMode, iv: &[u8]) -> Tpm2bIv<'static> {
    let iv: &[u8] = if mode == TpmiAlgCipherMode::Ecb {
        &[]
    } else {
        iv
    };
    Tpm2bIv::from_bytes(leak_bytes(iv)).unwrap()
}

/// `TPM2_EncryptDecrypt` (or `TPM2_EncryptDecrypt2` with `second_form`) with the command mode
/// `mode` (`None` = the key's) and an IV for `iv_mode`: (outData, ivOut).
#[allow(clippy::too_many_arguments)]
fn encrypt_decrypt(
    sim: &mut Tpm,
    key: Handle,
    second_form: bool,
    decrypt: bool,
    mode: Option<TpmiAlgCipherMode>,
    iv_mode: TpmiAlgCipherMode,
    iv: &[u8],
    data: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let iv_in = iv_for(iv_mode, iv);
    let in_data = Tpm2bMaxBuffer::from_bytes(leak_bytes(data)).unwrap();
    let (out, iv_out) = if second_form {
        let rsp = execute_with_password_sessions(
            sim,
            &EncryptDecrypt2 {
                key_handle: key,
                in_data,
                decrypt,
                mode,
                iv_in,
            },
            1,
            &[],
        )
        .expect("TPM2_EncryptDecrypt2");
        (rsp.out_data, rsp.iv_out)
    } else {
        let rsp = execute_with_password_sessions(
            sim,
            &EncryptDecrypt {
                key_handle: key,
                decrypt,
                mode,
                iv_in,
                in_data,
            },
            1,
            &[],
        )
        .expect("TPM2_EncryptDecrypt");
        (rsp.out_data, rsp.iv_out)
    };
    (out.get_buffer().to_vec(), iv_out.get_buffer().to_vec())
}

/// A test message of `len` octets.
fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 37 + 11) as u8).collect()
}

/// For every block cipher, mode and message length, `TPM2_EncryptDecrypt` (mode in the command,
/// key mode NULL) and `TPM2_EncryptDecrypt2` (mode in the key, command mode NULL) produce the
/// modeled ciphertext and `ivOut`, and decrypting the ciphertext with the same IV returns the
/// plaintext and the same `ivOut`.
#[test]
fn every_mode_matches_the_model_and_decrypts() {
    let iv = [0xa5u8; BLOCK];
    for alg in block_ciphers() {
        let key_bytes: Vec<u8> = (0..alg.key_bytes()).map(|i| i as u8 ^ 0x3c).collect();
        for mode in MODES {
            let mut sim = Tpm::new();
            let null_key = load_key(&mut sim, alg, None, &key_bytes);
            let mode_key = load_key(&mut sim, alg, Some(mode), &key_bytes);
            for &len in lengths(mode) {
                let plain = message(len);
                let (cipher, iv_out) = model_encrypt(alg, &key_bytes, mode, &iv, &plain);
                for (key, second_form, cmd_mode) in
                    [(null_key, false, Some(mode)), (mode_key, true, None)]
                {
                    let ctx = format!("{alg:?} {mode:?} len {len} second form {second_form}");
                    let got = encrypt_decrypt(
                        &mut sim,
                        key,
                        second_form,
                        false,
                        cmd_mode,
                        mode,
                        &iv,
                        &plain,
                    );
                    assert_eq!(got, (cipher.clone(), iv_out.clone()), "encrypt {ctx}");
                    let back = encrypt_decrypt(
                        &mut sim,
                        key,
                        second_form,
                        true,
                        cmd_mode,
                        mode,
                        &iv,
                        &cipher,
                    );
                    assert_eq!(back.0, plain, "decrypt {ctx}");
                    // Decryption advances the chaining value like encryption, except that the
                    // CBC and CFB values are taken from the (same) ciphertext.
                    assert_eq!(back.1, iv_out, "decrypt ivOut {ctx}");
                }
            }
        }
    }
}

/// Encrypting a message in two calls (split at a block boundary), the second with the first
/// call's `ivOut`, gives the ciphertext and `ivOut` of one call over the whole message.
#[test]
fn iv_out_chains_across_calls() {
    let iv = [0x0fu8; BLOCK];
    for alg in block_ciphers() {
        let key_bytes: Vec<u8> = (0..alg.key_bytes()).map(|i| (i * 7) as u8).collect();
        for mode in MODES {
            let mut sim = Tpm::new();
            let key = load_key(&mut sim, alg, None, &key_bytes);
            let plain = message(64);
            let (whole, whole_iv) = model_encrypt(alg, &key_bytes, mode, &iv, &plain);
            let (first, first_iv) = encrypt_decrypt(
                &mut sim,
                key,
                false,
                false,
                Some(mode),
                mode,
                &iv,
                &plain[..32],
            );
            let (second, second_iv) = encrypt_decrypt(
                &mut sim,
                key,
                false,
                false,
                Some(mode),
                mode,
                &first_iv,
                &plain[32..],
            );
            assert_eq!([first, second].concat(), whole, "{alg:?} {mode:?}");
            assert_eq!(second_iv, whole_iv, "{alg:?} {mode:?} ivOut");
        }
    }
}

/// The CTR counter is a 128-bit big-endian integer that wraps: an IV of all-ones continues with
/// the all-zero counter block, and `ivOut` after a partial block is the next counter.
#[test]
fn ctr_counter_wraps_and_counts_partial_blocks() {
    let iv = [0xffu8; BLOCK];
    for alg in block_ciphers() {
        let key_bytes = vec![0x42u8; alg.key_bytes()];
        let mut sim = Tpm::new();
        let key = load_key(&mut sim, alg, Some(TpmiAlgCipherMode::Ctr), &key_bytes);
        let plain = message(21);
        let expected = model_encrypt(alg, &key_bytes, TpmiAlgCipherMode::Ctr, &iv, &plain);
        let mut next = [0u8; BLOCK];
        next[BLOCK - 1] = 1;
        assert_eq!(expected.1, next);
        assert_eq!(
            encrypt_decrypt(
                &mut sim,
                key,
                false,
                false,
                None,
                TpmiAlgCipherMode::Ctr,
                &iv,
                &plain
            ),
            expected,
            "{alg:?}"
        );
    }
}
