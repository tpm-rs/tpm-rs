use crate::CruxCryptoProvider;
use tpm2::crypto::{CryptoError, Direction, ModeIv, Symmetric};
// The mode loops (and their IV chaining) are shared with the Rust backend.
use tpm2_crypto_rust::rust_crypto_mode;

/// AES-128, AES-192, AES-256 and Camellia-128, Camellia-192, Camellia-256 in the CTR, OFB, CBC,
/// CFB and ECB modes (see [`tpm2_crypto_rust::run_mode`] for the IV chaining).
///
/// The other block cipher (SM4) is not supported and returns `Err(CryptoError::Unsupported)`.
///
/// libcrux has no AES-CBC/CTR/OFB/ECB or Camellia, so the block ciphers are the RustCrypto
/// `aes` and `camellia` crates.
impl Symmetric for CruxCryptoProvider {
    fn aes128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        rust_crypto_mode::<aes::Aes128>(key, mode, dir, data)
    }

    fn aes192(
        &self,
        key: &[u8; 24],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        rust_crypto_mode::<aes::Aes192>(key, mode, dir, data)
    }

    fn aes256(
        &self,
        key: &[u8; 32],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        rust_crypto_mode::<aes::Aes256>(key, mode, dir, data)
    }

    fn camellia128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        rust_crypto_mode::<camellia::Camellia128>(key, mode, dir, data)
    }

    fn camellia192(
        &self,
        key: &[u8; 24],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        rust_crypto_mode::<camellia::Camellia192>(key, mode, dir, data)
    }

    fn camellia256(
        &self,
        key: &[u8; 32],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        rust_crypto_mode::<camellia::Camellia256>(key, mode, dir, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// NIST SP 800-38A, F.3.13 (CFB128-AES128.Encrypt): key.
    const KEY_128: [u8; 16] = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    /// NIST SP 800-38A, F.3.15 (CFB128-AES192.Encrypt): key.
    const KEY_192: [u8; 24] = hex!("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    /// NIST SP 800-38A, F.3.17 (CFB128-AES256.Encrypt): key.
    const KEY_256: [u8; 32] =
        hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    /// NIST SP 800-38A, F.3: IV shared by the CFB128 vectors.
    const IV: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");
    /// NIST SP 800-38A, F.3: plaintext shared by the CFB128 vectors.
    const PLAINTEXT: [u8; 64] = hex!(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    );
    const CIPHERTEXT_128: [u8; 64] = hex!(
        "3b3fd92eb72dad20333449f8e83cfb4a"
        "c8a64537a0b3a93fcde3cdad9f1ce58b"
        "26751f67a3cbb140b1808cf187a4f4df"
        "c04b05357c5d1c0eeac4c66f9ff7f2e6"
    );
    const CIPHERTEXT_192: [u8; 64] = hex!(
        "cdc80d6fddf18cab34c25909c99a4174"
        "67ce7f7f81173621961a2b70171d3d7a"
        "2e1e8a1dd59b88b1c8e60fed1efac4c9"
        "c05f9f9ca9834fa042ae8fba584b09ff"
    );
    const CIPHERTEXT_256: [u8; 64] = hex!(
        "dc7e84bfda79164b7ecd8486985d3860"
        "39ffed143b28b1c832113c6331e5407b"
        "df10132415e54b92a13ed0a8267ae2f9"
        "75a385741ab9cef82031623d55b1e471"
    );

    /// Encrypts and decrypts with `op` and checks the NIST vectors, including
    /// the final chaining value (the last ciphertext block).
    fn check_known_answer(
        op: impl Fn(ModeIv<'_>, Direction, &mut [u8]) -> Result<(), CryptoError>,
        ciphertext: &[u8; 64],
    ) {
        let mut iv = IV;
        let mut data = PLAINTEXT;
        op(ModeIv::Cfb(&mut iv), Direction::Encrypt, &mut data).unwrap();
        assert_eq!(data, *ciphertext);
        assert_eq!(iv, ciphertext[48..]);

        let mut iv = IV;
        op(ModeIv::Cfb(&mut iv), Direction::Decrypt, &mut data).unwrap();
        assert_eq!(data, PLAINTEXT);
        assert_eq!(iv, ciphertext[48..]);
    }

    #[test]
    fn aes128_cfb_known_answer() {
        let c = CruxCryptoProvider;
        check_known_answer(|m, d, data| c.aes128(&KEY_128, m, d, data), &CIPHERTEXT_128);
    }

    #[test]
    fn aes192_cfb_known_answer() {
        let c = CruxCryptoProvider;
        check_known_answer(|m, d, data| c.aes192(&KEY_192, m, d, data), &CIPHERTEXT_192);
    }

    #[test]
    fn aes256_cfb_known_answer() {
        let c = CruxCryptoProvider;
        check_known_answer(|m, d, data| c.aes256(&KEY_256, m, d, data), &CIPHERTEXT_256);
    }

    #[test]
    fn cfb_matches_cfb_mode_crate_for_every_length() {
        use aes::cipher::{AsyncStreamCipher as _, KeyIvInit as _};
        let c = CruxCryptoProvider;
        for len in 0..=PLAINTEXT.len() {
            let mut expected = PLAINTEXT;
            cfb_mode::Encryptor::<aes::Aes256>::new(&KEY_256.into(), &IV.into())
                .encrypt(&mut expected[..len]);

            let mut iv = IV;
            let mut data = PLAINTEXT;
            c.aes256(
                &KEY_256,
                ModeIv::Cfb(&mut iv),
                Direction::Encrypt,
                &mut data[..len],
            )
            .unwrap();
            assert_eq!(data[..len], expected[..len], "len {len}");
            assert_eq!(data[len..], PLAINTEXT[len..], "len {len}");

            let mut iv = IV;
            c.aes256(
                &KEY_256,
                ModeIv::Cfb(&mut iv),
                Direction::Decrypt,
                &mut data[..len],
            )
            .unwrap();
            assert_eq!(data, PLAINTEXT, "len {len}");
        }
    }

    #[test]
    fn cfb_iv_chains_across_whole_block_calls() {
        let c = CruxCryptoProvider;
        let mut iv = IV;
        let mut data = PLAINTEXT;
        let (first, second) = data.split_at_mut(32);
        c.aes128(&KEY_128, ModeIv::Cfb(&mut iv), Direction::Encrypt, first)
            .unwrap();
        assert_eq!(iv, CIPHERTEXT_128[16..32]);
        c.aes128(&KEY_128, ModeIv::Cfb(&mut iv), Direction::Encrypt, second)
            .unwrap();
        assert_eq!(data, CIPHERTEXT_128);
        assert_eq!(iv, CIPHERTEXT_128[48..]);
    }

    #[test]
    fn cfb_partial_block_iv_keeps_previous_chaining_bytes() {
        let c = CruxCryptoProvider;
        for dir in [Direction::Encrypt, Direction::Decrypt] {
            let mut iv = IV;
            let mut data = match dir {
                Direction::Encrypt => PLAINTEXT,
                Direction::Decrypt => CIPHERTEXT_128,
            };
            c.aes128(&KEY_128, ModeIv::Cfb(&mut iv), dir, &mut data[..21])
                .unwrap();
            // After one whole block and 5 bytes of the second one: the 5 new
            // ciphertext bytes, then bytes 5.. of the first ciphertext block.
            let mut expected_iv = [0u8; 16];
            expected_iv[..5].copy_from_slice(&CIPHERTEXT_128[16..21]);
            expected_iv[5..].copy_from_slice(&CIPHERTEXT_128[5..16]);
            assert_eq!(iv, expected_iv);
        }
    }

    #[test]
    fn cfb_empty_data_leaves_iv_unchanged() {
        let c = CruxCryptoProvider;
        let mut iv = IV;
        c.aes192(&KEY_192, ModeIv::Cfb(&mut iv), Direction::Encrypt, &mut [])
            .unwrap();
        assert_eq!(iv, IV);
    }

    /// The AES-128 modes other than CFB match the first block of NIST SP 800-38A F.1.1 (ECB),
    /// F.2.1 (CBC), F.4.1 (OFB) and F.5.1 (CTR), with the TCG reference's `ivOut`; SM4 is
    /// unsupported.
    #[test]
    fn other_modes_match_sp800_38a() {
        let c = CruxCryptoProvider;
        let pt: [u8; 16] = PLAINTEXT[..16].try_into().unwrap();
        let mut data = pt;
        c.aes128(&KEY_128, ModeIv::Ecb, Direction::Encrypt, &mut data)
            .unwrap();
        assert_eq!(data, hex!("3ad77bb40d7a3660a89ecaf32466ef97"));
        let mut iv = IV;
        c.aes128(
            &KEY_128,
            ModeIv::Cbc(&mut iv),
            Direction::Decrypt,
            &mut data,
        )
        .unwrap();
        assert_eq!(iv, hex!("3ad77bb40d7a3660a89ecaf32466ef97"));
        let mut data = pt;
        let mut iv = IV;
        c.aes128(
            &KEY_128,
            ModeIv::Cbc(&mut iv),
            Direction::Encrypt,
            &mut data,
        )
        .unwrap();
        assert_eq!(data, hex!("7649abac8119b246cee98e9b12e9197d"));
        assert_eq!(iv, data);
        let mut data = pt;
        let mut iv = IV;
        c.aes128(
            &KEY_128,
            ModeIv::Ofb(&mut iv),
            Direction::Encrypt,
            &mut data,
        )
        .unwrap();
        assert_eq!(data, hex!("3b3fd92eb72dad20333449f8e83cfb4a"));
        assert_eq!(iv, hex!("50fe67cc996d32b6da0937e99bafec60"));
        let mut data = pt;
        let mut iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        c.aes128(
            &KEY_128,
            ModeIv::Ctr(&mut iv),
            Direction::Encrypt,
            &mut data,
        )
        .unwrap();
        assert_eq!(data, hex!("874d6191b620e3261bef6864990db6ce"));
        assert_eq!(iv, hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdff00"));
        let mut iv = IV;
        assert_eq!(
            c.sm4_128(
                &KEY_128,
                ModeIv::Cfb(&mut iv),
                Direction::Encrypt,
                &mut data
            ),
            Err(CryptoError::Unsupported)
        );
        assert_eq!(iv, IV);
    }

    #[test]
    fn encrypt_decrypt_dispatches_through_symmetric_key() {
        use tpm2::{AlgSym, TpmiAlgCipherMode, crypto};
        let c = CruxCryptoProvider;
        let key = crypto::SymmetricKey::new(AlgSym::Aes128, &KEY_128).unwrap();
        let mut iv = IV;
        let mut data = PLAINTEXT;
        let mode = ModeIv::new(TpmiAlgCipherMode::Cfb, &mut iv).unwrap();
        crypto::encrypt(&c, key, mode, &mut data).unwrap();
        assert_eq!(data, CIPHERTEXT_128);
        assert_eq!(iv, CIPHERTEXT_128[48..]);
    }
}
