//! Known-answer tests for the hash, MAC, symmetric cipher and RNG
//! implementations. The vectors are from FIPS 180, RFC 2202, RFC 4231 and
//! NIST SP 800-38A/B.

use hex_literal::hex;
use tpm2::crypto::{
    ConstantTimeEq, CryptoError, HashStream, ModeIv, Random, Rng, SymmetricKey, cmac, decrypt,
    encrypt, hash, hmac,
};
use tpm2::{TpmiAlgCipherMode, TpmiAlgHash};
use tpm2_libcrux::Libcrux;

const C: Libcrux = Libcrux::new();

const K128: [u8; 16] = hex!("2b7e151628aed2a6abf7158809cf4f3c");
const K192: [u8; 24] = hex!("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
const K256: [u8; 32] = hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
const IV: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");
const COUNTER: [u8; 16] = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
const PLAINTEXT: [u8; 64] = hex!(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
);

#[test]
fn hash_known_answers() {
    let cases: [(TpmiAlgHash, &[u8]); 4] = [
        (
            TpmiAlgHash::Sha1,
            &hex!("a9993e364706816aba3e25717850c26c9cd0d89d"),
        ),
        (
            TpmiAlgHash::Sha256,
            &hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ),
        (
            TpmiAlgHash::Sha384,
            &hex!(
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
                "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
            ),
        ),
        (
            TpmiAlgHash::Sha512,
            &hex!(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            ),
        ),
    ];
    for (alg, expected) in cases {
        let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let digest = hash(&C, alg, b"abc", &mut out).unwrap();
        assert_eq!(digest.hash_alg(), alg);
        assert_eq!(digest.digest(), expected, "{alg:?}");

        // Streaming the input in pieces gives the same digest.
        let mut stream = HashStream::new(&C, alg).unwrap();
        for piece in [&b""[..], b"a", b"bc"] {
            stream.update(piece).unwrap();
        }
        let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        assert_eq!(stream.finalize(&mut out).unwrap().digest(), expected);
    }
}

#[test]
fn hmac_known_answers() {
    // RFC 2202 and RFC 4231, test case 2.
    let cases: [(TpmiAlgHash, &[u8]); 4] = [
        (
            TpmiAlgHash::Sha1,
            &hex!("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"),
        ),
        (
            TpmiAlgHash::Sha256,
            &hex!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        ),
        (
            TpmiAlgHash::Sha384,
            &hex!(
                "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47"
                "e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"
            ),
        ),
        (
            TpmiAlgHash::Sha512,
            &hex!(
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
            ),
        ),
    ];
    for (alg, expected) in cases {
        let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let mac = hmac(&C, alg, b"Jefe", b"what do ya want for nothing?", &mut out).unwrap();
        assert_eq!(mac.digest(), expected, "{alg:?}");
    }
}

#[test]
fn unsupported_hashes() {
    for alg in [
        TpmiAlgHash::Sm3_256,
        TpmiAlgHash::Sha3_256,
        TpmiAlgHash::Sha3_384,
        TpmiAlgHash::Sha3_512,
    ] {
        let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        assert_eq!(
            hash(&C, alg, b"abc", &mut out),
            Err(CryptoError::Unsupported)
        );
        let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        assert_eq!(
            hmac(&C, alg, b"key", b"abc", &mut out),
            Err(CryptoError::Unsupported)
        );
    }
}

#[test]
fn cmac_known_answers() {
    // NIST SP 800-38B, Appendix D.
    let cases = [
        (
            SymmetricKey::Aes128(&K128),
            0,
            hex!("bb1d6929e95937287fa37d129b756746"),
        ),
        (
            SymmetricKey::Aes128(&K128),
            16,
            hex!("070a16b46b4d4144f79bdd9dd04a287c"),
        ),
        (
            SymmetricKey::Aes128(&K128),
            40,
            hex!("dfa66747de9ae63030ca32611497c827"),
        ),
        (
            SymmetricKey::Aes256(&K256),
            64,
            hex!("e1992190549f6ed5696a2c056c315410"),
        ),
    ];
    for (key, len, expected) in cases {
        let mut out = [0u8; 16];
        cmac(&C, key, &PLAINTEXT[..len], &mut out).unwrap();
        assert_eq!(out, expected, "{key:?} {len}");
    }

    let mut out = [0u8; 16];
    for key in [
        SymmetricKey::Sm4_128(&K128),
        SymmetricKey::Camellia192(&K192),
    ] {
        assert_eq!(cmac(&C, key, b"", &mut out), Err(CryptoError::Unsupported));
    }
}

/// Checks that encrypting [`PLAINTEXT`] with `key` in `mode` starting from
/// `iv` gives `expected` and leaves `iv_out` as the chaining value, in one
/// call or in two chained calls, and that decryption reverses it.
fn check_mode(
    key: SymmetricKey<'_>,
    mode: TpmiAlgCipherMode,
    iv: &[u8],
    expected: &[u8; 64],
    iv_out: &[u8],
) {
    let mut data = PLAINTEXT;
    let mut chain = iv.to_vec();
    encrypt(&C, key, ModeIv::new(mode, &mut chain).unwrap(), &mut data).unwrap();
    assert_eq!(&data, expected, "{key:?} {mode:?}");
    assert_eq!(chain, iv_out, "{key:?} {mode:?}");

    let mut data = PLAINTEXT;
    let mut chain = iv.to_vec();
    let (first, second) = data.split_at_mut(16);
    encrypt(&C, key, ModeIv::new(mode, &mut chain).unwrap(), first).unwrap();
    encrypt(&C, key, ModeIv::new(mode, &mut chain).unwrap(), second).unwrap();
    assert_eq!(&data, expected, "{key:?} {mode:?}");

    let mut chain = iv.to_vec();
    decrypt(&C, key, ModeIv::new(mode, &mut chain).unwrap(), &mut data).unwrap();
    assert_eq!(data, PLAINTEXT, "{key:?} {mode:?}");
    assert_eq!(chain, iv_out, "{key:?} {mode:?}");
}

#[test]
fn aes_known_answers() {
    // NIST SP 800-38A, Appendix F.
    check_mode(
        SymmetricKey::Aes128(&K128),
        TpmiAlgCipherMode::Ecb,
        &[],
        &hex!(
            "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
            "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4"
        ),
        &[],
    );
    check_mode(
        SymmetricKey::Aes192(&K192),
        TpmiAlgCipherMode::Ecb,
        &[],
        &hex!(
            "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eef"
            "ef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e"
        ),
        &[],
    );
    check_mode(
        SymmetricKey::Aes128(&K128),
        TpmiAlgCipherMode::Cbc,
        &IV,
        &hex!(
            "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"
        ),
        &hex!("3ff1caa1681fac09120eca307586e1a7"),
    );
    check_mode(
        SymmetricKey::Aes256(&K256),
        TpmiAlgCipherMode::Cbc,
        &IV,
        &hex!(
            "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d"
            "39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b"
        ),
        &hex!("b2eb05e2c39be9fcda6c19078c6a9d1b"),
    );
    check_mode(
        SymmetricKey::Aes128(&K128),
        TpmiAlgCipherMode::Cfb,
        &IV,
        &hex!(
            "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b"
            "26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6"
        ),
        &hex!("c04b05357c5d1c0eeac4c66f9ff7f2e6"),
    );
    check_mode(
        SymmetricKey::Aes128(&K128),
        TpmiAlgCipherMode::Ofb,
        &IV,
        &hex!(
            "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825"
            "9740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e"
        ),
        &hex!("c6d3416d29165c6fcb8e51a227ba994e"),
    );
    check_mode(
        SymmetricKey::Aes128(&K128),
        TpmiAlgCipherMode::Ctr,
        &COUNTER,
        &hex!(
            "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
            "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"
        ),
        &hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdff03"),
    );
}

#[test]
fn aes_partial_blocks() {
    let key = SymmetricKey::Aes128(&K128);

    // Like the TPM reference implementation, CFB leaves the partial
    // ciphertext block followed by zeros in the IV.
    let mut data = PLAINTEXT;
    let mut iv = IV;
    encrypt(&C, key, ModeIv::Cfb(&mut iv), &mut data[..20]).unwrap();
    assert_eq!(data[..20], hex!("3b3fd92eb72dad20333449f8e83cfb4ac8a64537"));
    assert_eq!(iv, hex!("c8a64537000000000000000000000000"));
    let mut iv = IV;
    decrypt(&C, key, ModeIv::Cfb(&mut iv), &mut data[..20]).unwrap();
    assert_eq!(data, PLAINTEXT);
    assert_eq!(iv, hex!("c8a64537000000000000000000000000"));

    // CTR increments the counter after a partial block.
    let mut counter = COUNTER;
    encrypt(&C, key, ModeIv::Ctr(&mut counter), &mut data[..20]).unwrap();
    assert_eq!(data[..20], hex!("874d6191b620e3261bef6864990db6ce9806f66b"));
    assert_eq!(counter, hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdff01"));
}

#[test]
fn symmetric_errors() {
    // Block modes need whole blocks.
    let mut data = [0u8; 15];
    let mut iv = IV;
    let key = SymmetricKey::Aes128(&K128);
    assert_eq!(
        encrypt(&C, key, ModeIv::Ecb, &mut data),
        Err(CryptoError::Internal)
    );
    assert_eq!(
        decrypt(&C, key, ModeIv::Cbc(&mut iv), &mut data),
        Err(CryptoError::Internal)
    );

    let mut data = [0u8; 16];
    for key in [
        SymmetricKey::Sm4_128(&K128),
        SymmetricKey::Camellia128(&K128),
        SymmetricKey::Camellia256(&K256),
    ] {
        assert_eq!(
            encrypt(&C, key, ModeIv::Ecb, &mut data),
            Err(CryptoError::Unsupported)
        );
    }
}

#[test]
fn rng() {
    let output = |seed: &[u8], reseed: Option<&[u8]>| {
        let mut rng = C.rng_seeded(seed).unwrap();
        if let Some(data) = reseed {
            rng.reseed(data).unwrap();
        }
        let mut out = [0u8; 64];
        Rng::fill_bytes(&mut rng, &mut out).unwrap();
        out
    };
    assert_eq!(output(b"seed", None), output(b"seed", None));
    assert_ne!(output(b"seed", None), output(b"other seed", None));
    assert_eq!(
        output(b"seed", Some(b"data")),
        output(b"seed", Some(b"data"))
    );
    assert_ne!(output(b"seed", Some(b"data")), output(b"seed", None));
    assert_ne!(
        output(b"seed", Some(b"data")),
        output(b"seed", Some(b"other data"))
    );

    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    Rng::fill_bytes(&mut C.rng().unwrap(), &mut a).unwrap();
    Rng::fill_bytes(&mut C.rng().unwrap(), &mut b).unwrap();
    assert_ne!(a, b);
}

#[test]
fn constant_time_eq() {
    assert!(C.constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
    assert!(!C.constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
    assert!(C.constant_time_eq::<0>(&[], &[]));
}
