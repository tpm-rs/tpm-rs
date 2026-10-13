use hex_literal::hex;
use tpm2::crypto::CryptoProvider;
use tpm2::crypto::{
    Asymmetric, AsymmetricSign, CmacStream, ConstantTimeEq, CryptoError, Direction, Ecc, ModeIv,
    Random, SymmetricKey, TpmiRsaKeyBits, cmac, digest_eq, encrypt_decrypt, symmetric,
};
use tpm2::crypto::{Finalize, Hash, Hmac, Update};
use tpm2::{AlgSym, TpmEccCurve, TpmiAlgCipherMode, TpmiAlgHash, TpmtHa};
use tpm2_crypto_rust::RustCryptoProvider;

#[test]
fn test_rust_crypto_provider_get_random() {
    let provider = RustCryptoProvider;
    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];
    provider.get_random(&mut buf1).expect("get_random failed");
    provider.get_random(&mut buf2).expect("get_random failed");
    assert_ne!(buf1, buf2, "get_random produced identical buffers");
}

#[test]
fn test_rust_crypto_provider_hash_sha256() {
    let provider = RustCryptoProvider;
    let data = b"hello world";
    let mut ctx = Hash::sha256(&provider).expect("sha256 failed");
    ctx.update(data).expect("update failed");
    let mut digest = [0u8; 32];
    ctx.finalize(&mut digest).expect("finalize failed");
    let expected = hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    assert_eq!(digest, expected);
}

#[test]
fn test_rust_crypto_provider_hmac_sha256() {
    let provider = RustCryptoProvider;
    let key = b"key";
    let data = b"The quick brown fox jumps over the lazy dog";
    let mut ctx = Hmac::sha256(&provider, key).expect("hmac sha256 failed");
    ctx.update(data).expect("update failed");
    let mut digest = [0u8; 32];
    ctx.finalize(&mut digest).expect("finalize failed");
    let expected = hex!("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
    assert_eq!(digest, expected);
}

#[test]
fn test_rust_crypto_provider_concurrency() {
    use std::thread;
    let provider = std::sync::Arc::new(RustCryptoProvider);

    let mut handles = vec![];
    for i in 0..10 {
        let p = provider.clone();
        handles.push(thread::spawn(move || {
            let data = format!("hello world {}", i);
            let mut ctx = Hash::sha256(&*p).expect("sha256 failed");
            ctx.update(data.as_bytes()).expect("update failed");
            let mut digest = [0u8; 32];
            ctx.finalize(&mut digest).expect("finalize failed");
            assert_eq!(digest.len(), 32);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}

// ==========================================
// Symmetric (AES-CFB), CMAC, ConstantTimeEq, Random
// ==========================================

/// NIST SP 800-38A, Appendix F.3: the four-block plaintext of the CFB128 examples.
const NIST_PLAINTEXT: [u8; 64] = hex!(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
);

/// NIST SP 800-38A, Appendix F.3: the IV of the CFB128 examples.
const NIST_IV: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");

/// NIST SP 800-38A / SP 800-38B example keys.
const AES128_KEY: [u8; 16] = hex!("2b7e151628aed2a6abf7158809cf4f3c");
const AES192_KEY: [u8; 24] = hex!("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
const AES256_KEY: [u8; 32] =
    hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");

/// NIST SP 800-38A, F.3.13 (CFB128-AES128.Encrypt).
const AES128_CFB_CIPHERTEXT: [u8; 64] = hex!(
    "3b3fd92eb72dad20333449f8e83cfb4a"
    "c8a64537a0b3a93fcde3cdad9f1ce58b"
    "26751f67a3cbb140b1808cf187a4f4df"
    "c04b05357c5d1c0eeac4c66f9ff7f2e6"
);

/// NIST SP 800-38A, F.3.15 (CFB128-AES192.Encrypt).
const AES192_CFB_CIPHERTEXT: [u8; 64] = hex!(
    "cdc80d6fddf18cab34c25909c99a4174"
    "67ce7f7f81173621961a2b70171d3d7a"
    "2e1e8a1dd59b88b1c8e60fed1efac4c9"
    "c05f9f9ca9834fa042ae8fba584b09ff"
);

/// NIST SP 800-38A, F.3.17 (CFB128-AES256.Encrypt).
const AES256_CFB_CIPHERTEXT: [u8; 64] = hex!(
    "dc7e84bfda79164b7ecd8486985d3860"
    "39ffed143b28b1c832113c6331e5407b"
    "df10132415e54b92a13ed0a8267ae2f9"
    "75a385741ab9cef82031623d55b1e471"
);

/// Encrypts or decrypts `data` in place with `alg` in CFB mode, updating `iv`.
fn aes_cfb(
    provider: &RustCryptoProvider,
    alg: AlgSym,
    key: &[u8],
    iv: &mut [u8],
    dir: Direction,
    data: &mut [u8],
) -> Result<(), CryptoError> {
    let key = SymmetricKey::new(alg, key).expect("key length matches the algorithm");
    let mode = ModeIv::new(TpmiAlgCipherMode::Cfb, iv).expect("IV length is valid for CFB");
    encrypt_decrypt(provider, key, mode, dir, data)
}

#[test]
fn test_rust_crypto_provider_aes_cfb_known_answer() {
    let provider = RustCryptoProvider;
    let vectors: [(AlgSym, &[u8], &[u8; 64]); 3] = [
        (AlgSym::Aes128, &AES128_KEY, &AES128_CFB_CIPHERTEXT),
        (AlgSym::Aes192, &AES192_KEY, &AES192_CFB_CIPHERTEXT),
        (AlgSym::Aes256, &AES256_KEY, &AES256_CFB_CIPHERTEXT),
    ];
    for (alg, key, ciphertext) in vectors {
        // Encryption: the output IV is the last ciphertext block.
        let mut iv = NIST_IV;
        let mut data = NIST_PLAINTEXT;
        aes_cfb(&provider, alg, key, &mut iv, Direction::Encrypt, &mut data).unwrap();
        assert_eq!(&data, ciphertext, "{alg:?} encryption");
        assert_eq!(iv[..], ciphertext[48..], "{alg:?} encryption IV out");

        // Decryption: the output IV is also the last ciphertext block.
        let mut iv = NIST_IV;
        let mut data = *ciphertext;
        aes_cfb(&provider, alg, key, &mut iv, Direction::Decrypt, &mut data).unwrap();
        assert_eq!(data, NIST_PLAINTEXT, "{alg:?} decryption");
        assert_eq!(iv[..], ciphertext[48..], "{alg:?} decryption IV out");
    }
}

#[test]
fn test_rust_crypto_provider_aes_cfb_encrypt_decrypt_wrappers() {
    let provider = RustCryptoProvider;
    let key = SymmetricKey::new(AlgSym::Aes128, &AES128_KEY).unwrap();

    let mut iv = NIST_IV;
    let mut data = NIST_PLAINTEXT;
    let mode = ModeIv::new(TpmiAlgCipherMode::Cfb, &mut iv).unwrap();
    symmetric::encrypt(&provider, key, mode, &mut data).unwrap();
    assert_eq!(data, AES128_CFB_CIPHERTEXT);

    let mut iv = NIST_IV;
    let mode = ModeIv::new(TpmiAlgCipherMode::Cfb, &mut iv).unwrap();
    symmetric::decrypt(&provider, key, mode, &mut data).unwrap();
    assert_eq!(data, NIST_PLAINTEXT);
}

#[test]
fn test_rust_crypto_provider_aes_cfb_iv_chaining() {
    let provider = RustCryptoProvider;

    // Encrypting block-aligned chunks while chaining the output IV gives the
    // same ciphertext as a single call.
    let mut iv = NIST_IV;
    let mut data = NIST_PLAINTEXT;
    let (first, second) = data.split_at_mut(32);
    aes_cfb(
        &provider,
        AlgSym::Aes128,
        &AES128_KEY,
        &mut iv,
        Direction::Encrypt,
        first,
    )
    .unwrap();
    assert_eq!(iv[..], AES128_CFB_CIPHERTEXT[16..32]);
    aes_cfb(
        &provider,
        AlgSym::Aes128,
        &AES128_KEY,
        &mut iv,
        Direction::Encrypt,
        second,
    )
    .unwrap();
    assert_eq!(data, AES128_CFB_CIPHERTEXT);
    assert_eq!(iv[..], AES128_CFB_CIPHERTEXT[48..]);

    // The same holds for decryption.
    let mut iv = NIST_IV;
    let (first, second) = data.split_at_mut(16);
    aes_cfb(
        &provider,
        AlgSym::Aes128,
        &AES128_KEY,
        &mut iv,
        Direction::Decrypt,
        first,
    )
    .unwrap();
    aes_cfb(
        &provider,
        AlgSym::Aes128,
        &AES128_KEY,
        &mut iv,
        Direction::Decrypt,
        second,
    )
    .unwrap();
    assert_eq!(data, NIST_PLAINTEXT);
    assert_eq!(iv[..], AES128_CFB_CIPHERTEXT[48..]);
}

#[test]
fn test_rust_crypto_provider_aes_cfb_partial_block_iv() {
    let provider = RustCryptoProvider;
    // After a final partial block of `n` bytes, the output IV is those `n`
    // ciphertext bytes followed by the rest of the previous chaining value
    // (here the first ciphertext block).
    let mut expected_iv = [0u8; 16];
    expected_iv[..4].copy_from_slice(&AES128_CFB_CIPHERTEXT[16..20]);
    expected_iv[4..].copy_from_slice(&AES128_CFB_CIPHERTEXT[4..16]);
    assert_eq!(expected_iv, hex!("c8a64537b72dad20333449f8e83cfb4a"));

    let mut iv = NIST_IV;
    let mut data: [u8; 20] = NIST_PLAINTEXT[..20].try_into().unwrap();
    aes_cfb(
        &provider,
        AlgSym::Aes128,
        &AES128_KEY,
        &mut iv,
        Direction::Encrypt,
        &mut data,
    )
    .unwrap();
    assert_eq!(data[..], AES128_CFB_CIPHERTEXT[..20]);
    assert_eq!(iv, expected_iv);

    let mut iv = NIST_IV;
    aes_cfb(
        &provider,
        AlgSym::Aes128,
        &AES128_KEY,
        &mut iv,
        Direction::Decrypt,
        &mut data,
    )
    .unwrap();
    assert_eq!(data[..], NIST_PLAINTEXT[..20]);
    assert_eq!(iv, expected_iv);

    // A partial first block keeps the tail of the input IV.
    let mut iv = NIST_IV;
    let mut data: [u8; 3] = NIST_PLAINTEXT[..3].try_into().unwrap();
    aes_cfb(
        &provider,
        AlgSym::Aes128,
        &AES128_KEY,
        &mut iv,
        Direction::Encrypt,
        &mut data,
    )
    .unwrap();
    assert_eq!(data[..], AES128_CFB_CIPHERTEXT[..3]);
    assert_eq!(iv[..3], AES128_CFB_CIPHERTEXT[..3]);
    assert_eq!(iv[3..], NIST_IV[3..]);

    // Empty data leaves the IV unchanged.
    let mut iv = NIST_IV;
    aes_cfb(
        &provider,
        AlgSym::Aes128,
        &AES128_KEY,
        &mut iv,
        Direction::Encrypt,
        &mut [],
    )
    .unwrap();
    assert_eq!(iv, NIST_IV);
}

#[test]
fn test_rust_crypto_provider_symmetric_unsupported() {
    let provider = RustCryptoProvider;
    let key = SymmetricKey::new(AlgSym::Aes256, &AES256_KEY).unwrap();

    // Only CFB is implemented: the other modes are rejected before touching
    // the data or the IV.
    for dir in [Direction::Encrypt, Direction::Decrypt] {
        let mut data = NIST_PLAINTEXT;
        let res = encrypt_decrypt(&provider, key, ModeIv::Ecb, dir, &mut data);
        assert_eq!(res, Err(CryptoError::Unsupported));
        assert_eq!(data, NIST_PLAINTEXT);

        for mode in 0..3 {
            let mut iv = NIST_IV;
            let mode_iv = match mode {
                0 => ModeIv::Cbc(&mut iv),
                1 => ModeIv::Ctr(&mut iv),
                _ => ModeIv::Ofb(&mut iv),
            };
            let res = encrypt_decrypt(&provider, key, mode_iv, dir, &mut data);
            assert_eq!(res, Err(CryptoError::Unsupported));
            assert_eq!(data, NIST_PLAINTEXT);
            assert_eq!(iv, NIST_IV);
        }
    }

    // SM4 and Camellia are not implemented.
    let key16 = [0x11u8; 16];
    let key24 = [0x22u8; 24];
    let key32 = [0x33u8; 32];
    let keys = [
        SymmetricKey::new(AlgSym::Sm4_128, &key16).unwrap(),
        SymmetricKey::new(AlgSym::Camellia128, &key16).unwrap(),
        SymmetricKey::new(AlgSym::Camellia192, &key24).unwrap(),
        SymmetricKey::new(AlgSym::Camellia256, &key32).unwrap(),
    ];
    for key in keys {
        let mut iv = NIST_IV;
        let mut data = NIST_PLAINTEXT;
        let res = encrypt_decrypt(
            &provider,
            key,
            ModeIv::Cfb(&mut iv),
            Direction::Encrypt,
            &mut data,
        );
        assert_eq!(res, Err(CryptoError::Unsupported), "{:?}", key.alg());
        assert_eq!(data, NIST_PLAINTEXT);
    }
}

/// A CMAC test vector: the cipher, its key, and the MACs of the first 0, 16,
/// 40 and 64 bytes of [`NIST_PLAINTEXT`].
type CmacVector = (AlgSym, &'static [u8], [[u8; 16]; 4]);

#[test]
fn test_rust_crypto_provider_cmac_known_answer() {
    let provider = RustCryptoProvider;
    // NIST SP 800-38B, Appendix D.1-D.3 (messages of 0, 16, 40 and 64 bytes).
    let vectors: [CmacVector; 3] = [
        (
            AlgSym::Aes128,
            &AES128_KEY,
            [
                hex!("bb1d6929e95937287fa37d129b756746"),
                hex!("070a16b46b4d4144f79bdd9dd04a287c"),
                hex!("dfa66747de9ae63030ca32611497c827"),
                hex!("51f0bebf7e3b9d92fc49741779363cfe"),
            ],
        ),
        (
            AlgSym::Aes192,
            &AES192_KEY,
            [
                hex!("d17ddf46adaacde531cac483de7a9367"),
                hex!("9e99a7bf31e710900662f65e617c5184"),
                hex!("8a1de5be2eb31aad089a82e6ee908b0e"),
                hex!("a1d5df0eed790f794d77589659f39a11"),
            ],
        ),
        (
            AlgSym::Aes256,
            &AES256_KEY,
            [
                hex!("028962f61b7bf89efc6b551f4667d983"),
                hex!("28a7023f452e8f82bd4bf28d8c37c35c"),
                hex!("aaf3d8f1de5640c232f5b169b9c911e6"),
                hex!("e1992190549f6ed5696a2c056c315410"),
            ],
        ),
    ];
    for (alg, key, macs) in vectors {
        let key = SymmetricKey::new(alg, key).unwrap();
        for (len, expected) in [0, 16, 40, 64].into_iter().zip(macs) {
            let message = &NIST_PLAINTEXT[..len];

            // One-shot.
            let mut mac = [0u8; 16];
            cmac(&provider, key, message, &mut mac).unwrap();
            assert_eq!(mac, expected, "{alg:?} CMAC of {len} bytes");

            // Streaming, in uneven pieces.
            let mut stream = CmacStream::new(&provider, key).unwrap();
            for piece in message.chunks(7) {
                stream.update(piece).unwrap();
            }
            let mut mac = [0u8; 16];
            stream.finalize(&mut mac).unwrap();
            assert_eq!(mac, expected, "{alg:?} streaming CMAC of {len} bytes");
        }
    }
}

#[test]
fn test_rust_crypto_provider_cmac_unsupported() {
    let provider = RustCryptoProvider;
    let key16 = [0x11u8; 16];
    let key24 = [0x22u8; 24];
    let key32 = [0x33u8; 32];
    let keys = [
        SymmetricKey::new(AlgSym::Sm4_128, &key16).unwrap(),
        SymmetricKey::new(AlgSym::Camellia128, &key16).unwrap(),
        SymmetricKey::new(AlgSym::Camellia192, &key24).unwrap(),
        SymmetricKey::new(AlgSym::Camellia256, &key32).unwrap(),
    ];
    for key in keys {
        let mut mac = [0u8; 16];
        let res = cmac(&provider, key, b"data", &mut mac);
        assert_eq!(res, Err(CryptoError::Unsupported), "{:?}", key.alg());
    }
}

#[test]
fn test_rust_crypto_provider_hash_hmac_unsupported() {
    let provider = RustCryptoProvider;
    assert!(matches!(
        Hash::sm3_256(&provider),
        Err(CryptoError::Unsupported)
    ));
    assert!(matches!(
        Hash::sha3_256(&provider),
        Err(CryptoError::Unsupported)
    ));
    assert!(matches!(
        Hash::sha3_384(&provider),
        Err(CryptoError::Unsupported)
    ));
    assert!(matches!(
        Hash::sha3_512(&provider),
        Err(CryptoError::Unsupported)
    ));
    assert!(matches!(
        Hmac::sm3_256(&provider, b"key"),
        Err(CryptoError::Unsupported)
    ));
    assert!(matches!(
        Hmac::sha3_256(&provider, b"key"),
        Err(CryptoError::Unsupported)
    ));
    assert!(matches!(
        Hmac::sha3_384(&provider, b"key"),
        Err(CryptoError::Unsupported)
    ));
    assert!(matches!(
        Hmac::sha3_512(&provider, b"key"),
        Err(CryptoError::Unsupported)
    ));
}

#[test]
fn test_rust_crypto_provider_constant_time_eq() {
    let provider = RustCryptoProvider;
    assert!(provider.constant_time_eq(&[], &[]));

    let a = [0x5Au8; 32];
    assert!(provider.constant_time_eq(&a, &a.clone()));
    for i in [0, 15, 31] {
        let mut b = a;
        b[i] ^= 0x01;
        assert!(!provider.constant_time_eq(&a, &b), "difference at byte {i}");
    }

    let b = [0x5Au8; 32];
    assert!(digest_eq(&provider, TpmtHa::Sha256(&a), TpmtHa::Sha256(&b)));
    let mut c = b;
    c[7] = 0;
    assert!(!digest_eq(
        &provider,
        TpmtHa::Sha256(&a),
        TpmtHa::Sha256(&c)
    ));
    // Digests of different algorithms never compare equal.
    assert!(!digest_eq(
        &provider,
        TpmtHa::Sha256(&a),
        TpmtHa::Sm3_256(&b)
    ));
}

#[test]
fn test_rust_crypto_provider_random_defaults() {
    let provider = RustCryptoProvider;
    // There is no RNG factory: the engine uses `CryptoProvider::get_random`.
    assert!(matches!(provider.rng(), Err(CryptoError::Unsupported)));
    assert!(matches!(
        provider.rng_seeded(b"seed"),
        Err(CryptoError::Unsupported)
    ));
    // The OS entropy source cannot be stirred: the data is ignored.
    assert_eq!(provider.stir_random(b"additional entropy"), Ok(()));
    let mut buf = [0u8; 0];
    assert_eq!(provider.get_random(&mut buf), Ok(()));
}

// ==========================================
// ECC
// ==========================================

/// `2 * G` on each curve implemented with its own arithmetic or a RustCrypto
/// crate, with the curve's coordinate size and the expected `x || y`.
fn ecc_double_generator_vectors() -> [(TpmEccCurve, usize, Vec<u8>); 5] {
    [
        (
            TpmEccCurve::NistP224,
            28,
            hex!(
                "706a46dc76dcb76798e60e6d89474788d16dc18032d268fd1a704fa6"
                "1c2b76a7bc25e7702a704fa986892849fca629487acf3709d2e4e8bb"
            )
            .to_vec(),
        ),
        (
            TpmEccCurve::NistP256,
            32,
            hex!(
                "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
                "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"
            )
            .to_vec(),
        ),
        (
            TpmEccCurve::NistP384,
            48,
            hex!(
                "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e"
                "4fe0e86ebe0e64f85b96a9c75295df61"
                "8e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab425"
                "5ffd43e94d39e22d61501e700a940e80"
            )
            .to_vec(),
        ),
        (
            TpmEccCurve::NistP521,
            66,
            hex!(
                "00433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769"
                "be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d"
                "783d"
                "00f4bb8cc7f86db26700a7f3eceeeed3f0b5c6b5107c4da97740ab21a29906c4"
                "2dbbb3e377de9f251f6b93937fa99a3248f4eafcbe95edc0f4f71be356d661f4"
                "1b02"
            )
            .to_vec(),
        ),
        (
            TpmEccCurve::BNP256,
            32,
            hex!(
                "cffffffffffd83a6c99ad4ed21bc55c13a7312dbff1b888a4b9175427e0b970e"
                "a3fffffffffe0a43816b4f44d0c0cd75e43d3154d7e966bbcf466160bbff4acc"
            )
            .to_vec(),
        ),
    ]
}

#[test]
fn test_rust_crypto_provider_ecc_known_answer() {
    let provider = RustCryptoProvider;
    for (curve, n, expected) in ecc_double_generator_vectors() {
        // 2 * G from the generator.
        let mut out = [0u8; 132];
        let len = provider
            .point_multiply_generator(curve, &[2], &mut out)
            .unwrap();
        assert_eq!(len, Some(2 * n), "{curve:?}");
        assert_eq!(out[..2 * n], expected[..], "{curve:?}");
        assert_eq!(provider.validate_point(curve, &expected), Ok(true));

        // 2 * G as 2 * (1 * G).
        let mut g = [0u8; 132];
        provider
            .point_multiply_generator(curve, &[1], &mut g)
            .unwrap()
            .unwrap();
        let mut out = [0u8; 132];
        let len = provider
            .point_multiply(curve, &[2], &g[..2 * n], &mut out)
            .unwrap();
        assert_eq!(len, Some(2 * n), "{curve:?}");
        assert_eq!(out[..2 * n], expected[..], "{curve:?}");
    }
}

#[test]
fn test_rust_crypto_provider_ecc_result_conventions() {
    let provider = RustCryptoProvider;
    for (curve, n, two_g) in ecc_double_generator_vectors() {
        let mut out = [0u8; 132];
        // A zero scalar has no valid result.
        assert_eq!(
            provider.point_multiply_generator(curve, &[0], &mut out),
            Ok(None),
            "{curve:?}"
        );
        assert_eq!(
            provider.point_multiply(curve, &[0], &two_g, &mut out),
            Ok(None),
            "{curve:?}"
        );
        // A point that is not on the curve is invalid.
        let mut off_curve = two_g.clone();
        off_curve[2 * n - 1] ^= 0x01;
        assert_eq!(
            provider.validate_point(curve, &off_curve),
            Ok(false),
            "{curve:?}"
        );
        assert_eq!(
            provider.point_multiply(curve, &[3], &off_curve, &mut out),
            Ok(None),
            "{curve:?}"
        );
        // A point of the wrong length is invalid.
        assert_eq!(
            provider.validate_point(curve, &two_g[1..]),
            Ok(false),
            "{curve:?}"
        );
        // An output buffer that is too small is an internal error.
        assert_eq!(
            provider.point_multiply_generator(curve, &[2], &mut out[..2 * n - 1]),
            Err(CryptoError::Internal),
            "{curve:?}"
        );
    }

    // ECDAA is only implemented on NIST P-256.
    let mut k = [0u8; 48];
    let mut s = [0u8; 48];
    let res = provider.ecdaa_sign(
        TpmEccCurve::NistP384,
        &[1],
        &[],
        &[],
        &[2],
        &[0u8; 48],
        &mut k,
        &mut s,
    );
    assert_eq!(res, Err(CryptoError::Unsupported));

    // Curves without an implementation are unsupported.
    let mut out = [0u8; 64];
    assert_eq!(
        provider.point_multiply_generator(TpmEccCurve::NistP192, &[2], &mut out),
        Err(CryptoError::Unsupported)
    );
    assert_eq!(
        provider.validate_point(TpmEccCurve::Curve25519, &[0u8; 64]),
        Err(CryptoError::Unsupported)
    );
}

#[test]
fn test_rust_crypto_provider_ecdaa_sign_p256() {
    let provider = RustCryptoProvider;
    let digest = [0xA5u8; 32];
    let mut k = [0u8; 32];
    let mut s = [0u8; 32];
    let res = provider.ecdaa_sign(
        TpmEccCurve::NistP256,
        &[7],
        &[],
        &[],
        &[9],
        &digest,
        &mut k,
        &mut s,
    );
    assert_eq!(res, Ok(Some(32)));
    // The nonce output is SHA-256(digest).
    let mut expected_k = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let expected_k =
        tpm2::crypto::hash(&provider, TpmiAlgHash::Sha256, &digest, &mut expected_k).unwrap();
    assert_eq!(&k[..], expected_k.digest());
    assert_ne!(s, [0u8; 32]);

    // An invalid (zero) commit or private scalar has no valid result.
    let res = provider.ecdaa_sign(
        TpmEccCurve::NistP256,
        &[0],
        &[],
        &[],
        &[9],
        &digest,
        &mut k,
        &mut s,
    );
    assert_eq!(res, Ok(None));
    let res = provider.ecdaa_sign(
        TpmEccCurve::NistP256,
        &[7],
        &[],
        &[],
        &[0],
        &digest,
        &mut k,
        &mut s,
    );
    assert_eq!(res, Ok(None));
}

#[test]
fn test_rust_crypto_provider_ecdsa_result_conventions() {
    let provider = RustCryptoProvider;
    let digest = [0x42u8; 32];
    for (curve, n) in [
        (TpmEccCurve::NistP256, 32),
        (TpmEccCurve::NistP384, 48),
        (TpmEccCurve::NistP521, 66),
    ] {
        let mut public_key = [0u8; 132];
        let mut private_key = [0u8; 66];
        let (pub_len, priv_len) = provider
            .ecc_generate_key(curve, &mut public_key, &mut private_key, Some(b"seed"))
            .unwrap();
        assert_eq!((pub_len, priv_len), (2 * n, n), "{curve:?}");

        let mut signature = [0u8; 132];
        let sig_len = provider
            .ecdsa_sign(
                &private_key[..priv_len],
                TpmtHa::Sha256(&digest),
                &mut signature,
            )
            .unwrap();
        assert_eq!(sig_len, Some(2 * n), "{curve:?}");
        let signature = &mut signature[..2 * n];
        assert_eq!(
            provider.ecdsa_verify(&public_key[..pub_len], TpmtHa::Sha256(&digest), signature),
            Ok(true),
            "{curve:?}"
        );

        // A corrupted signature or a mismatched digest does not verify.
        assert_eq!(
            provider.ecdsa_verify(
                &public_key[..pub_len],
                TpmtHa::Sha256(&[0x43u8; 32]),
                signature
            ),
            Ok(false),
            "{curve:?}"
        );
        signature[n] ^= 0x01;
        assert_eq!(
            provider.ecdsa_verify(&public_key[..pub_len], TpmtHa::Sha256(&digest), signature),
            Ok(false),
            "{curve:?}"
        );

        // A signature buffer that is too small is an internal error.
        let mut small = [0u8; 132];
        assert_eq!(
            provider.ecdsa_sign(
                &private_key[..priv_len],
                TpmtHa::Sha256(&digest),
                &mut small[..2 * n - 1]
            ),
            Err(CryptoError::Internal),
            "{curve:?}"
        );
        // A zero private key is invalid.
        assert_eq!(
            provider.ecdsa_sign(&[0u8; 66][..n], TpmtHa::Sha256(&digest), &mut small),
            Ok(None),
            "{curve:?}"
        );
    }
    // Keys of an unsupported size cannot sign.
    let mut signature = [0u8; 132];
    assert_eq!(
        provider.ecdsa_sign(&[], TpmtHa::Sha256(&digest), &mut signature),
        Ok(None)
    );
    assert_eq!(
        provider.ecdsa_sign(&[1u8; 67], TpmtHa::Sha256(&digest), &mut signature),
        Ok(None)
    );
}

// ==========================================
// RSA
// ==========================================

#[test]
fn test_rust_crypto_provider_rsa_result_conventions() {
    let provider = RustCryptoProvider;
    let mut public_key = [0u8; 512];
    let mut private_key = [0u8; 2048];
    let (pub_len, priv_len) = provider
        .rsa_generate_key(
            TpmiRsaKeyBits(1024),
            &mut public_key,
            &mut private_key,
            Some(b"rsa seed"),
        )
        .unwrap();
    assert_eq!(pub_len, 128);
    let public_key = &public_key[..pub_len];
    let private_key = &private_key[..priv_len];

    // RSAES-PKCS1-v1_5 round trip; a message too large for the key is
    // rejected.
    let mut ciphertext = [0u8; 128];
    let len = provider
        .rsaes_encrypt(public_key, b"secret", &mut ciphertext)
        .unwrap();
    assert_eq!(len, Some(128));
    let mut plaintext = [0u8; 128];
    let len = provider
        .rsaes_decrypt(private_key, &ciphertext, &mut plaintext)
        .unwrap();
    assert_eq!(len, Some(6));
    assert_eq!(&plaintext[..6], b"secret");
    assert_eq!(
        provider.rsaes_encrypt(public_key, &[0x01; 118], &mut ciphertext),
        Ok(None)
    );
    let mut corrupted = ciphertext;
    corrupted[5] ^= 0x01;
    assert_eq!(
        provider.rsaes_decrypt(private_key, &corrupted, &mut plaintext),
        Ok(None)
    );

    // OAEP round trip with a label; a wrong label, an empty label, a corrupted
    // ciphertext, a non-UTF-8 label, or a message too large for the key are
    // rejected.
    let label = b"LABEL\0";
    let len = provider
        .oaep_encrypt(
            TpmiAlgHash::Sha256,
            public_key,
            b"secret",
            label,
            &mut ciphertext,
        )
        .unwrap();
    assert_eq!(len, Some(128));
    let len = provider
        .oaep_decrypt(
            TpmiAlgHash::Sha256,
            private_key,
            &ciphertext,
            label,
            &mut plaintext,
        )
        .unwrap();
    assert_eq!(len, Some(6));
    assert_eq!(&plaintext[..6], b"secret");
    for bad_label in [&b"OTHER\0"[..], &[][..]] {
        assert_eq!(
            provider.oaep_decrypt(
                TpmiAlgHash::Sha256,
                private_key,
                &ciphertext,
                bad_label,
                &mut plaintext
            ),
            Ok(None)
        );
    }
    let mut corrupted = ciphertext;
    corrupted[10] ^= 0xFF;
    assert_eq!(
        provider.oaep_decrypt(
            TpmiAlgHash::Sha256,
            private_key,
            &corrupted,
            label,
            &mut plaintext
        ),
        Ok(None)
    );
    assert_eq!(
        provider.oaep_decrypt(
            TpmiAlgHash::Sha256,
            private_key,
            &ciphertext,
            &[0xFF, 0xFE],
            &mut plaintext
        ),
        Ok(None)
    );
    assert_eq!(
        provider.oaep_encrypt(
            TpmiAlgHash::Sha256,
            public_key,
            &[0x01; 63],
            &[],
            &mut ciphertext
        ),
        Ok(None)
    );
    assert_eq!(
        provider.oaep_encrypt(
            TpmiAlgHash::Sm3_256,
            public_key,
            b"secret",
            &[],
            &mut ciphertext
        ),
        Err(CryptoError::Unsupported)
    );

    // Raw RSA round trip; an input that is not smaller than the modulus is
    // rejected.
    let len = provider
        .rsa_null_encrypt(public_key, b"raw", &mut ciphertext)
        .unwrap();
    assert_eq!(len, Some(128));
    let len = provider
        .rsa_null_decrypt(private_key, &ciphertext, &mut plaintext)
        .unwrap();
    assert_eq!(len, Some(128));
    assert_eq!(&plaintext[125..128], b"raw");
    assert_eq!(
        provider.rsa_null_encrypt(public_key, public_key, &mut ciphertext),
        Ok(None)
    );
    assert_eq!(
        provider.rsa_null_encrypt(public_key, b"raw", &mut ciphertext[..127]),
        Err(CryptoError::Internal)
    );

    // RSASSA and RSAPSS sign and verify; a corrupted signature does not
    // verify, and a key too small for the digest and its padding cannot sign.
    let digest = [0x5Au8; 32];
    let mut signature = [0u8; 128];
    for pss in [false, true] {
        let sig_len = if pss {
            provider.rsapss_sign(private_key, TpmtHa::Sha256(&digest), &mut signature)
        } else {
            provider.rsassa_sign(private_key, TpmtHa::Sha256(&digest), &mut signature)
        }
        .unwrap();
        assert_eq!(sig_len, Some(128));
        let verify = |signature: &[u8]| {
            if pss {
                provider.rsapss_verify(public_key, TpmtHa::Sha256(&digest), signature)
            } else {
                provider.rsassa_verify(public_key, TpmtHa::Sha256(&digest), signature)
            }
        };
        assert_eq!(verify(&signature), Ok(true));
        let mut corrupted = signature;
        corrupted[0] ^= 0x01;
        assert_eq!(verify(&corrupted), Ok(false));
        assert_eq!(verify(&signature[..127]), Ok(false));
    }
    assert_eq!(
        provider.rsapss_sign(private_key, TpmtHa::Sha512(&[0x5A; 64]), &mut signature),
        Ok(None)
    );
    assert_eq!(
        provider.rsassa_sign(private_key, TpmtHa::Sha256(&digest), &mut signature[..127]),
        Err(CryptoError::Internal)
    );
    assert_eq!(
        provider.rsassa_sign(private_key, TpmtHa::Sm3_256(&digest), &mut signature),
        Err(CryptoError::Unsupported)
    );
    assert_eq!(
        provider.rsassa_sign(b"not a key", TpmtHa::Sha256(&digest), &mut signature),
        Ok(None)
    );
    assert_eq!(
        provider.rsassa_verify(&[], TpmtHa::Sha256(&digest), &signature),
        Ok(false)
    );

    // Key import round trip through prime P; inconsistent components are
    // rejected.
    let mut prime_p = [0u8; 64];
    let p_len = provider
        .rsa_private_key_to_prime_p(private_key, &mut prime_p)
        .unwrap()
        .unwrap();
    let mut imported = [0u8; 2048];
    let imported_len = provider
        .rsa_import_private_key(public_key, &prime_p[..p_len], 65537, &mut imported)
        .unwrap()
        .unwrap();
    let imported = &imported[..imported_len];
    let mut imported_p = [0u8; 64];
    assert_eq!(
        provider.rsa_private_key_to_prime_p(imported, &mut imported_p),
        Ok(Some(p_len))
    );
    assert_eq!(imported_p[..p_len], prime_p[..p_len]);
    // RSASSA is deterministic, so the imported key gives the same signature.
    let mut expected = [0u8; 128];
    provider
        .rsassa_sign(private_key, TpmtHa::Sha256(&digest), &mut expected)
        .unwrap();
    assert_eq!(
        provider.rsassa_sign(imported, TpmtHa::Sha256(&digest), &mut signature),
        Ok(Some(128))
    );
    assert_eq!(signature, expected);
    let mut imported = [0u8; 2048];
    assert_eq!(
        provider.rsa_import_private_key(public_key, &prime_p[..p_len], 0, &mut imported),
        Ok(None)
    );
    assert_eq!(
        provider.rsa_import_private_key(public_key, &[1], 65537, &mut imported),
        Ok(None)
    );
    assert_eq!(
        provider.rsa_import_private_key(public_key, &prime_p[..p_len], 65537, &mut imported[..1]),
        Err(CryptoError::Internal)
    );
    assert_eq!(
        provider.rsa_private_key_to_prime_p(b"not a key", &mut prime_p),
        Ok(None)
    );
}
