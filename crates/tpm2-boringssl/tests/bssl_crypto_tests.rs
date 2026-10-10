//! Integration and known-answer tests for `tpm2-boringssl`.

#![forbid(unsafe_code)]

use hex_literal::hex;
use tpm2::crypto::{
    ConstantTimeEq, CryptoError, Ecc, EccPrivateKey as _, EccPublicKey as _, Finalize, HashStream,
    Mldsa, MldsaMessage, MldsaPrivateKey as _, MldsaPublicKey as _, Mlkem, MlkemPrivateKey as _,
    MlkemPublicKey as _, ModeIv, Random, Rng, Rsa, RsaEncryptScheme, RsaPrivateKey as _,
    RsaPublicKey as _, SignatureBuffer, SigningKey, SymmetricKey, Update, VerifyingKey, cmac,
    decrypt, encrypt, hash, hmac, sign, verify,
};
use tpm2::{
    Tpm2b, Tpm2bEccParameter, Tpm2bKemCiphertext, Tpm2bPrivateKeyRsa, Tpm2bPublicKeyMldsa,
    Tpm2bPublicKeyMlkem, Tpm2bPublicKeyRsa, Tpm2bSignatureCtx, Tpm2bSignatureMldsa, TpmEccCurve,
    TpmiAlgCipherMode, TpmiAlgHash, TpmiMldsaParms, TpmiMlkemParms, TpmiRsaKeyBits, TpmsEccPoint,
    TpmsSchemeEcdaa, TpmsSignatureEcc, TpmsSignatureRsa, TpmtHa, TpmtSigScheme, TpmtSignature,
};
use tpm2_boringssl::{BoringSsl, EccPublicKey, RsaPrivateKey, RsaPublicKey};

const C: BoringSsl = BoringSsl::new();
/// Message used by the fixed RSA and ECDSA vectors below, which are shared
/// with the tpm2-libcrux tests (crates/tpm2-libcrux/tests/{rsa,ecc}.rs).
const MESSAGE: &[u8] = b"tpm2-libcrux";

// =========================================================================
// Trait-level Hash, HMAC, CMAC, Symmetric, Random, and ConstantTimeEq tests
// =========================================================================

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
fn hash_hmac_cmac_known_answers() {
    let hash_cases: [(TpmiAlgHash, &[u8]); 4] = [
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
    for (alg, expected) in hash_cases {
        let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let digest = hash(&C, alg, b"abc", &mut out).unwrap();
        assert_eq!(digest.hash_alg(), alg);
        assert_eq!(digest.digest(), expected);

        let mut stream = HashStream::new(&C, alg).unwrap();
        for piece in [&b""[..], b"a", b"bc"] {
            stream.update(piece).unwrap();
        }
        let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        assert_eq!(stream.finalize(&mut out).unwrap().digest(), expected);
    }

    let hmac_cases: [(TpmiAlgHash, &[u8]); 4] = [
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
    for (alg, expected) in hmac_cases {
        let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let mac = hmac(&C, alg, b"Jefe", b"what do ya want for nothing?", &mut out).unwrap();
        assert_eq!(mac.digest(), expected);
    }

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
        assert_eq!(
            hmac(&C, alg, b"key", b"abc", &mut out),
            Err(CryptoError::Unsupported)
        );
    }

    let cmac_cases = [
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
    for (key, len, expected) in cmac_cases {
        let mut out = [0u8; 16];
        cmac(&C, key, &PLAINTEXT[..len], &mut out).unwrap();
        assert_eq!(out, expected);
    }
    let mut out = [0u8; 16];
    for key in [
        SymmetricKey::Sm4_128(&K128),
        SymmetricKey::Camellia192(&K192),
    ] {
        assert_eq!(cmac(&C, key, b"", &mut out), Err(CryptoError::Unsupported));
    }
}

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
    assert_eq!(&data, expected);
    assert_eq!(chain, iv_out);

    let mut data = PLAINTEXT;
    let mut chain = iv.to_vec();
    let (first, second) = data.split_at_mut(16);
    encrypt(&C, key, ModeIv::new(mode, &mut chain).unwrap(), first).unwrap();
    encrypt(&C, key, ModeIv::new(mode, &mut chain).unwrap(), second).unwrap();
    assert_eq!(&data, expected);

    let mut chain = iv.to_vec();
    decrypt(&C, key, ModeIv::new(mode, &mut chain).unwrap(), &mut data).unwrap();
    assert_eq!(data, PLAINTEXT);
    assert_eq!(chain, iv_out);
}

#[test]
fn symmetric_and_rng_and_constant_time_eq() {
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

    let key = SymmetricKey::Aes128(&K128);
    let mut data = PLAINTEXT;
    let mut iv = IV;
    encrypt(&C, key, ModeIv::Cfb(&mut iv), &mut data[..20]).unwrap();
    assert_eq!(data[..20], hex!("3b3fd92eb72dad20333449f8e83cfb4ac8a64537"));
    assert_eq!(iv, hex!("c8a64537000000000000000000000000"));
    let mut iv = IV;
    decrypt(&C, key, ModeIv::Cfb(&mut iv), &mut data[..20]).unwrap();
    assert_eq!(data, PLAINTEXT);
    assert_eq!(iv, hex!("c8a64537000000000000000000000000"));

    let mut counter = COUNTER;
    encrypt(&C, key, ModeIv::Ctr(&mut counter), &mut data[..20]).unwrap();
    assert_eq!(data[..20], hex!("874d6191b620e3261bef6864990db6ce9806f66b"));
    assert_eq!(counter, hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdff01"));

    let mut unaligned = [0u8; 15];
    assert_eq!(
        encrypt(&C, key, ModeIv::Ecb, &mut unaligned),
        Err(CryptoError::Internal)
    );
    assert_eq!(
        decrypt(&C, key, ModeIv::Cbc(&mut iv), &mut unaligned),
        Err(CryptoError::Internal)
    );

    let mut block = [0u8; 16];
    for unsupported in [
        SymmetricKey::Sm4_128(&K128),
        SymmetricKey::Camellia128(&K128),
        SymmetricKey::Camellia256(&K256),
    ] {
        assert_eq!(
            encrypt(&C, unsupported, ModeIv::Ecb, &mut block),
            Err(CryptoError::Unsupported)
        );
    }

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

    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    Rng::fill_bytes(&mut C.rng().unwrap(), &mut a).unwrap();
    Rng::fill_bytes(&mut C.rng().unwrap(), &mut b).unwrap();
    assert_ne!(a, b);

    assert!(C.constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
    assert!(!C.constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
    assert!(C.constant_time_eq::<0>(&[], &[]));
}

// =========================================================================
// Trait-level RSA and Signing tests
// =========================================================================

const N: [u8; 128] = hex!(
    "f865cea666ddabbed9ebe26f75312e11a9d9662dca2bec439dfa3b419b0311ea"
    "21a5e63ed2669e6cd0b06aeedcfec1d02bfdef405bf4b40f616678383d7c739d"
    "c2a6cf2b9964ff7fbe7c453a07842f2f924cf4afc2ad4c3287bdee2eb0aa26f9"
    "6d4c47c06d58cc301401bfff9014210c61118362c53e326e926cb3ac5e19a3f9"
);
const P: [u8; 64] = hex!(
    "ff1fd080fb97268899ce34e33a50aa657840c9270e66d2c9a766a9aae72f762d"
    "c2a713d1a5d7cf02c2721d71dffa308ae3332d01af276264304917e5712689bb"
);
const RSASSA_SHA256: [u8; 128] = hex!(
    "c1214e1a18f1f1fe358c1a502fc228dce63be82b5af6a58d4726ea4537d615b3"
    "2c6fb26d0e259651e48a181ac99e5da58412fe1154be73ce4c8dedd5c5f0f20e"
    "394a6fef12a123f7a0c7435d4aa44de042014b181e2fbf1fb3ad06ba246c88c9"
    "04814a110ba7f36512cb55484d20ecc00a8303e555c93f9561e885c6e309de8c"
);
const RSAPSS_SHA512: [u8; 128] = hex!(
    "83faece9a8e00fcada13874fb97ce065531fdf4cd740f3868213ba2ef7a99c11"
    "2515be4f42b830f0d80c54fdb3a8fdbaabdc7e8c5cc61796a66b3a471f1c50b3"
    "b8909c9cfc64d4588cf2c95f1dc5426f2ae44f1c69ae8b055f0d2b684f175756"
    "0f7071fa7d299ffa792534f7cd13af6adb0a686b6ab73a955b78d5e06cf0301b"
);
const OAEP_SHA256: [u8; 128] = hex!(
    "a2af4d5faeb9be5a3a05bf1574664524ac60d8b615d0314ad7431e83f6d1fc5a"
    "85e37591e4d94f80ee2632f398623aa6765f24eda86f8c973fa1406d24c71469"
    "0083a37aff56b22f588d8d5066aae2c1ec2cb6fffe42f0d8e1e058ebe70c140f"
    "1b088ffcaaa72cc6d69175d607c0bd1c36e5dc2d4009baddece404a24ac61196"
);

fn load_rsa_public() -> RsaPublicKey {
    let modulus = Tpm2bPublicKeyRsa::new(&N).unwrap();
    Rsa::load_public(&C, TpmiRsaKeyBits::Rsa1024, 0, modulus)
        .unwrap()
        .unwrap()
}

fn load_rsa_private() -> RsaPrivateKey {
    let prime = Tpm2bPrivateKeyRsa::new(&P).unwrap();
    Rsa::load_private(&C, load_rsa_public(), prime)
        .unwrap()
        .unwrap()
}

fn digest<'a>(alg: TpmiAlgHash, message: &[u8], out: &'a mut [u8; 64]) -> &'a [u8] {
    hash(&C, alg, message, out).unwrap().digest()
}

fn rsa_signature(scheme: TpmtSigScheme, sig: &[u8]) -> TpmtSignature<'_> {
    let sig = Tpm2bPublicKeyRsa::new(sig).unwrap();
    match scheme {
        TpmtSigScheme::Rsassa(hash) => TpmtSignature::Rsassa(TpmsSignatureRsa { hash, sig }),
        TpmtSigScheme::Rsapss(hash) => TpmtSignature::Rsapss(TpmsSignatureRsa { hash, sig }),
        _ => unreachable!(),
    }
}

#[test]
fn rsa_trait_tests() {
    let private = load_rsa_private();
    let public = private.public_key();
    assert_eq!(public.bits(), TpmiRsaKeyBits::Rsa1024);
    assert_eq!(public.exponent(), 65537);

    for (scheme, sig) in [
        (TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256), &RSASSA_SHA256),
        (TpmtSigScheme::Rsapss(TpmiAlgHash::Sha512), &RSAPSS_SHA512),
    ] {
        let (TpmtSigScheme::Rsassa(alg) | TpmtSigScheme::Rsapss(alg)) = scheme else {
            unreachable!()
        };
        let mut d = [0u8; 64];
        let digest = digest(alg, MESSAGE, &mut d);
        let key = VerifyingKey::Rsa(public);
        assert_eq!(
            verify(&C, key, digest, rsa_signature(scheme, sig)),
            Ok(true)
        );

        let mut tampered = *sig;
        tampered[64] ^= 1;
        let key = VerifyingKey::Rsa(public);
        assert_eq!(
            verify(&C, key, digest, rsa_signature(scheme, &tampered)),
            Ok(false)
        );
    }

    // Signatures must be as long as the modulus and strictly less than n.
    let mut d = [0u8; 64];
    let sha256_digest = digest(TpmiAlgHash::Sha256, MESSAGE, &mut d);
    let scheme = TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256);
    for bad_sig in [&RSASSA_SHA256[1..], &N[..]] {
        assert_eq!(
            verify(
                &C,
                VerifyingKey::Rsa(public),
                sha256_digest,
                rsa_signature(scheme, bad_sig)
            ),
            Ok(false)
        );
    }

    let oaep_scheme = RsaEncryptScheme::Oaep {
        hash: TpmiAlgHash::Sha256,
        label: b"DUPLICATE\0",
    };
    let mut out = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let plaintext = C.decrypt(&private, oaep_scheme, &OAEP_SHA256, &mut out);
    assert_eq!(plaintext.unwrap().unwrap().as_slice(), MESSAGE);

    // Key generation, reload from prime_p, and signing round-trip.
    let mut rng = C.rng_seeded(b"rsa").unwrap();
    let gen_priv = Rsa::generate_key(&C, &mut rng, TpmiRsaKeyBits::Rsa1024, 0).unwrap();
    assert_eq!(gen_priv.public_key().exponent(), 65537);

    let mut n_buf = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let mut p_buf = [0u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES];
    let n = gen_priv.public_key().modulus(&mut n_buf).unwrap();
    let p = gen_priv.prime_p(&mut p_buf).unwrap();
    let loaded_pub = Rsa::load_public(&C, TpmiRsaKeyBits::Rsa1024, 65537, n)
        .unwrap()
        .unwrap();
    let loaded_priv = Rsa::load_private(&C, loaded_pub, p).unwrap().unwrap();

    for scheme in [
        TpmtSigScheme::Rsassa(TpmiAlgHash::Sha1),
        TpmtSigScheme::Rsassa(TpmiAlgHash::Sha384),
        TpmtSigScheme::Rsapss(TpmiAlgHash::Sha256),
        TpmtSigScheme::Rsapss(TpmiAlgHash::Sha512),
    ] {
        let (TpmtSigScheme::Rsassa(alg) | TpmtSigScheme::Rsapss(alg)) = scheme else {
            unreachable!()
        };
        let mut d = [0u8; 64];
        let digest = digest(alg, MESSAGE, &mut d);
        let mut sig_out: SignatureBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        let sig = sign(
            &C,
            &mut rng,
            SigningKey::Rsa(&gen_priv),
            scheme,
            digest,
            &mut sig_out,
        )
        .unwrap();
        assert_eq!(
            verify(&C, VerifyingKey::Rsa(loaded_priv.public_key()), digest, sig),
            Ok(true)
        );
    }

    // Encrypt / decrypt schemes and invalid inputs.
    let mut ct = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let mut pt = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    for scheme in [
        RsaEncryptScheme::Rsaes,
        RsaEncryptScheme::Oaep {
            hash: TpmiAlgHash::Sha1,
            label: b"",
        },
        RsaEncryptScheme::Oaep {
            hash: TpmiAlgHash::Sha256,
            label: &[0xff],
        },
    ] {
        let ciphertext = C.encrypt(&mut rng, public, scheme, MESSAGE, &mut ct);
        let mut ciphertext: [u8; 128] = ciphertext.unwrap().unwrap().as_slice().try_into().unwrap();
        let plaintext = C.decrypt(&private, scheme, &ciphertext, &mut pt);
        assert_eq!(plaintext.unwrap().unwrap().as_slice(), MESSAGE);

        ciphertext[64] ^= 1;
        assert_eq!(C.decrypt(&private, scheme, &ciphertext, &mut pt), Ok(None));
        assert_eq!(
            C.decrypt(&private, scheme, &ciphertext[1..], &mut pt),
            Ok(None)
        );
    }

    let mut block = [0u8; 128];
    block[128 - MESSAGE.len()..].copy_from_slice(MESSAGE);
    let raw_ct = C
        .encrypt(&mut rng, public, RsaEncryptScheme::Raw, MESSAGE, &mut ct)
        .unwrap()
        .unwrap();
    let raw_pt = C
        .decrypt(&private, RsaEncryptScheme::Raw, raw_ct.as_slice(), &mut pt)
        .unwrap()
        .unwrap();
    assert_eq!(raw_pt.as_slice(), block);

    let too_long = [1u8; 128 - 10];
    for (scheme, input) in [
        (RsaEncryptScheme::Raw, &N[..]),
        (RsaEncryptScheme::Rsaes, &too_long[..]),
        (
            RsaEncryptScheme::Oaep {
                hash: TpmiAlgHash::Sha512,
                label: b"",
            },
            MESSAGE,
        ),
    ] {
        assert_eq!(
            C.encrypt(&mut rng, public, scheme, input, &mut ct),
            Ok(None)
        );
    }
    assert_eq!(
        C.decrypt(&private, RsaEncryptScheme::Raw, &N, &mut pt),
        Ok(None)
    );

    // Invalid keys and unsupported parameters.
    let modulus = Tpm2bPublicKeyRsa::new(&N).unwrap();
    let mut even = N;
    even[127] &= !1;
    let mut short = N;
    short[0] = 0;
    for (bits, exp, m) in [
        (TpmiRsaKeyBits::Rsa2048, 0, modulus),
        (TpmiRsaKeyBits::Rsa1024, 1, modulus),
        (TpmiRsaKeyBits::Rsa1024, 65536, modulus),
        (
            TpmiRsaKeyBits::Rsa1024,
            0,
            Tpm2bPublicKeyRsa::new(&even).unwrap(),
        ),
        (
            TpmiRsaKeyBits::Rsa1024,
            0,
            Tpm2bPublicKeyRsa::new(&short).unwrap(),
        ),
        (
            TpmiRsaKeyBits::Rsa1024,
            0,
            Tpm2bPublicKeyRsa::new(&N[1..]).unwrap(),
        ),
    ] {
        assert!(Rsa::load_public(&C, bits, exp, m).unwrap().is_none());
    }

    let mut wrong_p = P;
    wrong_p[63] ^= 2;
    for bad_p in [&wrong_p[..], &[1u8], &N[..]] {
        let p = Tpm2bPrivateKeyRsa::new(bad_p).unwrap();
        assert!(
            Rsa::load_private(&C, load_rsa_public(), p)
                .unwrap()
                .is_none()
        );
    }
    assert!(matches!(
        Rsa::generate_key(&C, &mut rng, TpmiRsaKeyBits::Rsa1024, 4),
        Err(CryptoError::Unsupported)
    ));
}

// =========================================================================
// Trait-level ECC and ECDSA tests
// =========================================================================

const MAX_ECC: usize = TpmEccCurve::MAX_ECC_KEY_BYTES;

fn ecc_param(value: &[u8]) -> Tpm2bEccParameter<'_> {
    Tpm2bEccParameter::new(value).unwrap()
}

fn ecc_point<'a>(x: &'a [u8], y: &'a [u8]) -> TpmsEccPoint<'a> {
    TpmsEccPoint {
        x: ecc_param(x),
        y: ecc_param(y),
    }
}

fn load_ecc_public(curve: TpmEccCurve, x: &[u8], y: &[u8]) -> Option<EccPublicKey> {
    Ecc::load_public(&C, curve, ecc_point(x, y)).unwrap()
}

fn ecdsa_sig<'a>(hash: TpmiAlgHash, r: &'a [u8], s: &'a [u8]) -> TpmtSignature<'a> {
    TpmtSignature::Ecdsa(TpmsSignatureEcc {
        hash,
        signature_r: ecc_param(r),
        signature_s: ecc_param(s),
    })
}

#[test]
fn ecc_and_ecdsa_trait_tests() {
    let d_p256 = hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    let x_p256 = hex!("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");
    let y_p256 = hex!("7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299");
    let r_sha1 = hex!("2182d640c8c57942489eae54ffb2f76570fe80264384e31262e4f0dc6f113773");
    let s_sha1 = hex!("fa84ad234d69bb70c9da75edfb59d8c9a1fe849ce852af0e4bc9f4a51b4d28f1");

    let public = load_ecc_public(TpmEccCurve::NistP256, &x_p256, &y_p256).unwrap();
    assert_eq!(public.curve(), TpmEccCurve::NistP256);
    let private = Ecc::load_private(&C, public, ecc_param(&d_p256))
        .unwrap()
        .unwrap();

    let mut d_buf = [0u8; 64];
    let sha1_digest = digest(TpmiAlgHash::Sha1, MESSAGE, &mut d_buf);
    assert_eq!(
        verify(
            &C,
            VerifyingKey::Ecc(private.public_key()),
            sha1_digest,
            ecdsa_sig(TpmiAlgHash::Sha1, &r_sha1, &s_sha1)
        ),
        Ok(true)
    );
    assert_eq!(
        verify(
            &C,
            VerifyingKey::Ecc(private.public_key()),
            sha1_digest,
            ecdsa_sig(TpmiAlgHash::Sha1, &s_sha1, &r_sha1)
        ),
        Ok(false)
    );

    // Leading zeros in r/s are ignored; out-of-range values are rejected.
    let mut padded_r = [0u8; 40];
    padded_r[8..].copy_from_slice(&r_sha1);
    assert_eq!(
        verify(
            &C,
            VerifyingKey::Ecc(private.public_key()),
            sha1_digest,
            ecdsa_sig(TpmiAlgHash::Sha1, &padded_r, &s_sha1)
        ),
        Ok(true)
    );
    let order = hex!("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let mut long_r = padded_r;
    long_r[7] = 1;
    for (bad_r, bad_s) in [
        (&[0u8; 0][..], &s_sha1[..]),
        (&[0u8][..], &s_sha1[..]),
        (&r_sha1[..], &order[..]),
        (&long_r[..], &s_sha1[..]),
    ] {
        assert_eq!(
            verify(
                &C,
                VerifyingKey::Ecc(private.public_key()),
                sha1_digest,
                ecdsa_sig(TpmiAlgHash::Sha1, bad_r, bad_s)
            ),
            Ok(false)
        );
    }

    // Cross-hash ECDSA and ECDH round-trip across P-256, P-384, and P-521.
    let mut rng = C.rng_seeded(b"ecc").unwrap();
    for curve in [
        TpmEccCurve::NistP256,
        TpmEccCurve::NistP384,
        TpmEccCurve::NistP521,
    ] {
        let a = Ecc::generate_key(&C, &mut rng, curve).unwrap();
        let b = Ecc::generate_key(&C, &mut rng, curve).unwrap();

        let (mut x1, mut y1) = ([0u8; MAX_ECC], [0u8; MAX_ECC]);
        let (mut x2, mut y2) = ([0u8; MAX_ECC], [0u8; MAX_ECC]);
        let z1 = C.ecdh(&a, b.public_key(), &mut x1, &mut y1).unwrap();
        let z2 = C.ecdh(&b, a.public_key(), &mut x2, &mut y2).unwrap();
        assert_eq!(z1, z2);

        for alg in [
            TpmiAlgHash::Sha1,
            TpmiAlgHash::Sha256,
            TpmiAlgHash::Sha384,
            TpmiAlgHash::Sha512,
        ] {
            let mut d = [0u8; 64];
            let digest = digest(alg, MESSAGE, &mut d);
            let mut out: SignatureBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
            let sig = sign(
                &C,
                &mut rng,
                SigningKey::Ecc(&a),
                TpmtSigScheme::Ecdsa(alg),
                digest,
                &mut out,
            )
            .unwrap();
            assert_eq!(
                verify(&C, VerifyingKey::Ecc(a.public_key()), digest, sig),
                Ok(true)
            );
            assert_eq!(
                verify(&C, VerifyingKey::Ecc(b.public_key()), digest, sig),
                Ok(false)
            );
        }
    }

    // Invalid points and scalars.
    let mut bad_y = y_p256;
    bad_y[31] ^= 1;
    let ff = [0xffu8; 32];
    let mut long_x = [0u8; 33];
    long_x[0] = 1;
    long_x[1..].copy_from_slice(&x_p256);
    for (x, y) in [
        (&x_p256[..], &bad_y[..]),
        (&ff[..], &y_p256[..]),
        (&long_x[..], &y_p256[..]),
    ] {
        assert!(load_ecc_public(TpmEccCurve::NistP256, x, y).is_none());
    }
    for bad_d in [&[0u8][..], &[1u8], &ff[..]] {
        let pub_key = load_ecc_public(TpmEccCurve::NistP256, &x_p256, &y_p256).unwrap();
        assert!(
            Ecc::load_private(&C, pub_key, ecc_param(bad_d))
                .unwrap()
                .is_none()
        );
    }

    // Unsupported curves and signature schemes.
    for curve in [
        TpmEccCurve::NistP192,
        TpmEccCurve::NistP224,
        TpmEccCurve::BNP256,
        TpmEccCurve::SM2P256,
        TpmEccCurve::Curve25519,
    ] {
        assert!(matches!(
            Ecc::generate_key(&C, &mut rng, curve),
            Err(CryptoError::Unsupported)
        ));
        assert!(matches!(
            Ecc::load_public(&C, curve, ecc_point(&[1; 32], &[1; 32])),
            Err(CryptoError::Unsupported)
        ));
    }

    let p256_key = Ecc::generate_key(&C, &mut rng, TpmEccCurve::NistP256).unwrap();
    let p384_key = Ecc::generate_key(&C, &mut rng, TpmEccCurve::NistP384).unwrap();
    let (mut x, mut y) = ([0u8; MAX_ECC], [0u8; MAX_ECC]);
    assert_eq!(
        C.ecdh(&p256_key, p384_key.public_key(), &mut x, &mut y),
        Err(CryptoError::Unsupported)
    );

    let ecdaa = TpmsSchemeEcdaa {
        hash_alg: TpmiAlgHash::Sha256,
        count: 0,
    };
    for scheme in [
        TpmtSigScheme::Ecdaa(ecdaa),
        TpmtSigScheme::Sm2(TpmiAlgHash::Sha256),
        TpmtSigScheme::Ecschnorr(TpmiAlgHash::Sha256),
    ] {
        let mut out: SignatureBuffer = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        assert_eq!(
            sign(
                &C,
                &mut rng,
                SigningKey::Ecc(&p256_key),
                scheme,
                sha1_digest,
                &mut out
            ),
            Err(CryptoError::Unsupported)
        );
    }
}

// =========================================================================
// ML-KEM and ML-DSA tests
// =========================================================================

fn counting<const N: usize>() -> [u8; N] {
    core::array::from_fn(|i| u8::try_from(i).unwrap())
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 64];
    let digest = hash(&C, TpmiAlgHash::Sha256, data, &mut out).unwrap();
    digest.digest().try_into().unwrap()
}

#[test]
fn mlkem_tests() {
    let mut rng = C.rng_seeded(b"mlkem").unwrap();

    // ML-KEM-512 is unsupported by BoringSSL.
    let seed = counting::<64>();
    assert!(matches!(
        Mlkem::derive_key(&C, TpmiMlkemParms::Mlkem512, Tpm2b(&seed)),
        Err(CryptoError::Unsupported)
    ));
    assert!(matches!(
        Mlkem::load_public(
            &C,
            TpmiMlkemParms::Mlkem512,
            Tpm2bPublicKeyMlkem::new(&[0u8; 800]).unwrap()
        ),
        Err(CryptoError::Unsupported)
    ));

    // Known-answer public key hashes for ML-KEM-768 and ML-KEM-1024.
    let kats = [
        (
            TpmiMlkemParms::Mlkem768,
            hex!("0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9"),
        ),
        (
            TpmiMlkemParms::Mlkem1024,
            hex!("c7b8fa0aa471d5ae18922d6ccad5b31e1d84f92ae723abfd13747018740a8530"),
        ),
    ];

    for (set, expected_hash) in kats {
        let private = Mlkem::derive_key(&C, set, Tpm2b(&seed)).unwrap();
        assert_eq!(private.public_key().parameter_set(), set);
        let mut out = [0u8; TpmiMlkemParms::MAX_PUB_KEY_BYTES];
        let encoded = private.public_key().encoded(&mut out).unwrap();
        assert_eq!(encoded.as_slice().len(), set.pub_key_bytes());
        assert_eq!(sha256(encoded.as_slice()), expected_hash);

        let mut seed_out = [0u8; 64];
        assert_eq!(*private.seed(&mut seed_out).unwrap().0, seed);

        // Reload public and private keys, and check mismatched seed -> Ok(None).
        let load = || Mlkem::load_public(&C, set, encoded).unwrap().unwrap();
        let reloaded = Mlkem::load_private(&C, load(), Tpm2b(&seed))
            .unwrap()
            .unwrap();
        let mut wrong_seed = seed;
        wrong_seed[0] ^= 1;
        assert!(
            Mlkem::load_private(&C, load(), Tpm2b(&wrong_seed))
                .unwrap()
                .is_none()
        );

        // Encapsulate and decapsulate round-trip.
        let mut ct_buf = [0u8; TpmiMlkemParms::MAX_CT_BYTES];
        let mut ss_buf = [0u8; TpmiMlkemParms::SHARED_SECRET_BYTES];
        let (ciphertext, secret) =
            Mlkem::encapsulate(&C, &mut rng, &load(), &mut ct_buf, &mut ss_buf).unwrap();
        assert_eq!(ciphertext.as_slice().len(), set.ct_bytes());

        for key in [&private, &reloaded] {
            let mut dec_out = [0u8; TpmiMlkemParms::SHARED_SECRET_BYTES];
            assert_eq!(
                Mlkem::decapsulate(&C, key, ciphertext, &mut dec_out),
                Ok(Some(secret))
            );
        }

        // Tampered ciphertext -> implicit rejection secret; wrong length -> Ok(None).
        let mut tampered = ciphertext.as_slice().to_vec();
        tampered[0] ^= 1;
        let mut dec_out = [0u8; TpmiMlkemParms::SHARED_SECRET_BYTES];
        let rejected = Mlkem::decapsulate(
            &C,
            &private,
            Tpm2bKemCiphertext::new(&tampered).unwrap(),
            &mut dec_out,
        )
        .unwrap();
        assert!(rejected.is_some_and(|r| r != secret));

        assert_eq!(
            Mlkem::decapsulate(
                &C,
                &private,
                Tpm2bKemCiphertext::new(&tampered[1..]).unwrap(),
                &mut dec_out
            ),
            Ok(None)
        );

        // Wrong-length or unreduced public key -> Ok(None).
        let ff = vec![0xff; set.pub_key_bytes()];
        for bad_pub in [&encoded.as_slice()[1..], &ff[..]] {
            let bad_pub = Tpm2bPublicKeyMlkem::new(bad_pub).unwrap();
            assert!(Mlkem::load_public(&C, set, bad_pub).unwrap().is_none());
        }
    }
}

#[test]
fn mldsa_tests() {
    let mut rng = C.rng_seeded(b"mldsa").unwrap();
    let seed = counting::<32>();
    let context = Tpm2bSignatureCtx::new(b"context").unwrap();
    let other_ctx = Tpm2bSignatureCtx::new(b"other").unwrap();

    // Known-answer public key hashes for ML-DSA-44, ML-DSA-65, and ML-DSA-87.
    let kats = [
        (
            TpmiMldsaParms::Mldsa44,
            hex!("9f107644c1084526af3bc8098680b05499a2325a644e388fb4f970e058d19d46"),
        ),
        (
            TpmiMldsaParms::Mldsa65,
            hex!("d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9"),
        ),
        (
            TpmiMldsaParms::Mldsa87,
            hex!("91dc389cfaa01470b7f66eee45a4ae9026d154817c754dfe22298b3fa241ffcd"),
        ),
    ];

    for (set, expected_hash) in kats {
        let private = Mldsa::derive_key(&C, set, Tpm2b(&seed)).unwrap();
        assert_eq!(private.public_key().parameter_set(), set);
        let mut out = [0u8; TpmiMldsaParms::MAX_PUB_KEY_BYTES];
        let encoded = private.public_key().encoded(&mut out).unwrap();
        assert_eq!(encoded.as_slice().len(), set.pub_key_bytes());
        assert_eq!(sha256(encoded.as_slice()), expected_hash);

        let mut seed_out = [0u8; 32];
        assert_eq!(*private.seed(&mut seed_out).unwrap().0, seed);

        // Reload public and private keys, and check mismatched seed -> Ok(None).
        let load = || Mldsa::load_public(&C, set, encoded).unwrap().unwrap();
        let public = load();
        assert!(
            Mldsa::load_private(&C, load(), Tpm2b(&seed))
                .unwrap()
                .is_some()
        );
        let mut wrong_seed = seed;
        wrong_seed[0] ^= 1;
        assert!(
            Mldsa::load_private(&C, load(), Tpm2b(&wrong_seed))
                .unwrap()
                .is_none()
        );
        let short_pub = Tpm2bPublicKeyMldsa::new(&encoded.as_slice()[1..]).unwrap();
        assert!(Mldsa::load_public(&C, set, short_pub).unwrap().is_none());

        // Pure sign and verify round-trip.
        let pure = MldsaMessage::Pure {
            context,
            message: MESSAGE,
        };
        let mut sig_buf = [0u8; TpmiMldsaParms::MAX_SIG_BYTES];
        let sig = Mldsa::sign(&C, &mut rng, &private, pure, &mut sig_buf)
            .unwrap()
            .unwrap();
        assert_eq!(sig.as_slice().len(), set.sig_bytes());
        assert_eq!(Mldsa::verify(&C, &public, pure, sig), Ok(true));
        assert_eq!(
            Mldsa::verify(
                &C,
                &public,
                MldsaMessage::Pure {
                    context: other_ctx,
                    message: MESSAGE
                },
                sig
            ),
            Ok(false)
        );
        assert_eq!(
            Mldsa::verify(
                &C,
                &public,
                MldsaMessage::Pure {
                    context,
                    message: b"other"
                },
                sig
            ),
            Ok(false)
        );
        let short_sig = Tpm2bSignatureMldsa::new(&sig.as_slice()[1..]).unwrap();
        assert_eq!(Mldsa::verify(&C, &public, pure, short_sig), Ok(false));

        // Streaming `mu_start` matches `Pure` and `ExternalMu`.
        let mut mu_ctx = Mldsa::mu_start(&C, &public, context).unwrap();
        mu_ctx.update(&MESSAGE[..4]).unwrap();
        mu_ctx.update(&MESSAGE[4..]).unwrap();
        let mut mu = [0u8; TpmiMldsaParms::MU_BYTES];
        mu_ctx.finalize(&mut mu).unwrap();

        let ext_mu = MldsaMessage::ExternalMu(&mu);
        assert_eq!(Mldsa::verify(&C, &public, ext_mu, sig), Ok(true));

        let mut mu_sig_buf = [0u8; TpmiMldsaParms::MAX_SIG_BYTES];
        let mu_sig = Mldsa::sign(&C, &mut rng, &private, ext_mu, &mut mu_sig_buf)
            .unwrap()
            .unwrap();
        assert_eq!(Mldsa::verify(&C, &public, pure, mu_sig), Ok(true));
        assert_eq!(Mldsa::verify(&C, &public, ext_mu, mu_sig), Ok(true));

        // PreHash (HashML-DSA) -> Err(CryptoError::Unsupported).
        let digest_bytes = [0u8; 32];
        let pre_hash = MldsaMessage::PreHash {
            context,
            digest: TpmtHa::Sha256(&digest_bytes),
        };
        let mut ph_sig_buf = [0u8; TpmiMldsaParms::MAX_SIG_BYTES];
        assert_eq!(
            Mldsa::sign(&C, &mut rng, &private, pre_hash, &mut ph_sig_buf),
            Err(CryptoError::Unsupported)
        );
        assert_eq!(
            Mldsa::verify(&C, &public, pre_hash, sig),
            Err(CryptoError::Unsupported)
        );
    }
}
