//! Tests of `RustCryptoProvider`, through the dispatch functions of `tpm2::crypto` where the
//! algorithms are enabled in `tpm2` (the TPM profile of the workspace), and through the backend
//! traits otherwise.

use hex_literal::hex;
use tpm2::crypto::backend::{
    CmacState, EccCurve, MldsaKey, MlkemKey, PrivateKey, RsaKey, SymmetricState,
};
use tpm2::crypto::{
    CipherInput, Crypto, CryptoError, Direction, EccPrivateKey, EccPublicKey, HashContext,
    HmacContext, Random, Rng, SignatureBuffer, SymmetricKey, digest_eq, ecc_mul_generator, hash,
    hmac,
};
use tpm2::{
    AlgSym, Tpm2bEccParameter, TpmEccCurve, TpmiAlgCipherMode, TpmiAlgHash, TpmsEccPoint, TpmtHa,
    TpmtSigScheme,
};
use tpm2_crypto_rust::pqc::{RustCryptoMldsa65, RustCryptoMlkem768};
use tpm2_crypto_rust::rsa::{RustCryptoRsa1024, RustCryptoRsa2048};
use tpm2_crypto_rust::{RustCryptoCipher, RustCryptoProvider as C, RustCryptoRng};

/// The random number generator of the backend.
type R = RustCryptoRng;

// ==========================================
// Random, hashes, HMAC, constant time
// ==========================================

#[test]
fn random() {
    let mut rng = C::from_entropy().unwrap();
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    rng.fill_bytes(&mut a).unwrap();
    rng.fill_bytes(&mut b).unwrap();
    assert_ne!(a, b);
    // The OS entropy source cannot be stirred: the data is ignored.
    assert_eq!(rng.stir_bytes(b"additional entropy"), Ok(()));
    C::rand_bytes(&mut a).unwrap();
    C::rand_bytes(&mut b).unwrap();
    assert_ne!(a, b);
    assert_eq!(C::rand_bytes(&mut []), Ok(()));

    // A seeded generator is deterministic, also after stirring, and depends on the seed and the
    // stirred data.
    let output = |seed: &[u8], stir: Option<&[u8]>| {
        let mut rng = C::from_seed(seed).unwrap();
        let mut out = [0u8; 64];
        rng.fill_bytes(&mut out[..10]).unwrap();
        if let Some(data) = stir {
            rng.stir_bytes(data).unwrap();
        }
        rng.fill_bytes(&mut out[10..]).unwrap();
        out
    };
    assert_eq!(output(b"seed", None), output(b"seed", None));
    assert_ne!(output(b"seed", None), output(b"other", None));
    assert_eq!(output(b"seed", Some(b"x")), output(b"seed", Some(b"x")));
    assert_ne!(output(b"seed", Some(b"x")), output(b"seed", Some(b"y")));
    assert_ne!(output(b"seed", Some(b"x")), output(b"seed", None));
    assert_eq!(
        output(b"seed", Some(b"x"))[..10],
        output(b"seed", None)[..10]
    );
}

#[test]
fn hash_and_hmac() {
    let mut buf = [0u8; 64];
    let digest = hash::<C>(TpmiAlgHash::Sha256, &[b"hello ", b"world"], &mut buf).unwrap();
    let expected = hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    assert_eq!(digest, TpmtHa::Sha256(&expected));

    let mut ctx = HashContext::<C>::new(TpmiAlgHash::Sha256).unwrap();
    ctx.update(b"hello").unwrap();
    ctx.update(b" world").unwrap();
    assert_eq!(ctx.finalize(&mut buf).unwrap(), TpmtHa::Sha256(&expected));

    let digest = hash::<C>(TpmiAlgHash::Sha1, &[b"abc"], &mut buf).unwrap();
    assert_eq!(
        digest,
        TpmtHa::Sha1(&hex!("a9993e364706816aba3e25717850c26c9cd0d89d"))
    );
    let digest = hash::<C>(TpmiAlgHash::Sha384, &[b"abc"], &mut buf).unwrap();
    assert_eq!(
        digest.digest(),
        hex!(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
            "8086072ba1e7cc2358baeca134c825a7"
        )
    );
    #[cfg(feature = "sha512")]
    assert_eq!(
        hash::<C>(TpmiAlgHash::Sha512, &[b"abc"], &mut buf)
            .unwrap()
            .digest(),
        hex!(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
    );

    let key = b"key";
    let data = b"The quick brown fox jumps over the lazy dog";
    let expected = hex!("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
    let mac = hmac::<C>(
        TpmiAlgHash::Sha256,
        key,
        &[&data[..10], &data[10..]],
        &mut buf,
    )
    .unwrap();
    assert_eq!(mac, TpmtHa::Sha256(&expected));
    let mut ctx = HmacContext::<C>::new(TpmiAlgHash::Sha256, key).unwrap();
    ctx.update(data).unwrap();
    assert_eq!(ctx.finalize(&mut buf).unwrap(), TpmtHa::Sha256(&expected));
}

#[test]
fn unsupported_algorithms() {
    use tpm2::crypto::backend::{Hash, HashState, Hmac, HmacState};
    assert!(matches!(
        <<C as Hash>::Sm3_256 as HashState<32>>::init(),
        Err(CryptoError::Unsupported)
    ));
    assert!(matches!(
        <<C as Hmac>::Sha3_256 as HmacState<32>>::init(b"key"),
        Err(CryptoError::Unsupported)
    ));
    assert!(matches!(
        <<C as tpm2::crypto::backend::Symmetric>::Sm4_128 as SymmetricState<16>>::init(&[0; 16]),
        Err(CryptoError::Unsupported)
    ));
    assert!(matches!(
        <<C as tpm2::crypto::backend::Cmac>::Sm4_128 as CmacState<16>>::init(&[0; 16]),
        Err(CryptoError::Unsupported)
    ));
}

#[test]
fn concurrency() {
    let handles: Vec<_> = (0..10)
        .map(|i| {
            std::thread::spawn(move || {
                let data = format!("hello world {i}");
                let mut buf = [0u8; 32];
                let digest = hash::<C>(TpmiAlgHash::Sha256, &[data.as_bytes()], &mut buf).unwrap();
                assert_eq!(digest.digest().len(), 32);
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn constant_time_eq() {
    assert!(C::ct_eq(&[], &[]));
    let a = [0x5Au8; 32];
    assert!(C::ct_eq(&a, &a.clone()));
    for i in [0, 15, 31] {
        let mut b = a;
        b[i] ^= 0x01;
        assert!(!C::ct_eq(&a, &b), "difference at byte {i}");
    }
    assert!(!C::ct_eq(&a, &a[..31]));

    let b = [0x5Au8; 32];
    assert!(digest_eq::<C>(TpmtHa::Sha256(&a), TpmtHa::Sha256(&b)));
    let mut c = b;
    c[7] = 0;
    assert!(!digest_eq::<C>(TpmtHa::Sha256(&a), TpmtHa::Sha256(&c)));
    // Digests of different algorithms never compare equal.
    assert!(!digest_eq::<C>(
        TpmtHa::Sha256(&a),
        TpmtHa::Sha384(&[0x5Au8; 48])
    ));
}

// ==========================================
// Symmetric ciphers and CMAC
// ==========================================

/// NIST SP 800-38A, Appendix F: the four-block plaintext of the examples.
const NIST_PLAINTEXT: [u8; 64] = hex!(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
);

/// NIST SP 800-38A, Appendix F: the IV of the examples.
const NIST_IV: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");

/// NIST SP 800-38A / SP 800-38B example keys.
const AES128_KEY: [u8; 16] = hex!("2b7e151628aed2a6abf7158809cf4f3c");
const AES256_KEY: [u8; 32] =
    hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");

/// NIST SP 800-38A, F.3.13 (CFB128-AES128.Encrypt).
const AES128_CFB_CIPHERTEXT: [u8; 64] = hex!(
    "3b3fd92eb72dad20333449f8e83cfb4a"
    "c8a64537a0b3a93fcde3cdad9f1ce58b"
    "26751f67a3cbb140b1808cf187a4f4df"
    "c04b05357c5d1c0eeac4c66f9ff7f2e6"
);

/// NIST SP 800-38A, F.3.17 (CFB128-AES256.Encrypt).
const AES256_CFB_CIPHERTEXT: [u8; 64] = hex!(
    "dc7e84bfda79164b7ecd8486985d3860"
    "39ffed143b28b1c832113c6331e5407b"
    "df10132415e54b92a13ed0a8267ae2f9"
    "75a385741ab9cef82031623d55b1e471"
);

/// Encrypts or decrypts `data` in place with `alg` and `mode`, updating `iv`.
fn crypt(
    alg: AlgSym,
    key: &[u8],
    mode: TpmiAlgCipherMode,
    iv: &mut [u8],
    dir: Direction,
    data: &mut [u8],
) -> Result<(), CryptoError> {
    let key = SymmetricKey::new(alg, key).expect("key length matches the algorithm");
    let input = CipherInput::new(mode, iv, data).expect("valid IV and data lengths");
    key.crypt::<C>(dir, input)
}

#[test]
fn aes_cfb_known_answer() {
    let vectors: [(AlgSym, &[u8], &[u8; 64]); 2] = [
        (AlgSym::Aes128, &AES128_KEY, &AES128_CFB_CIPHERTEXT),
        (AlgSym::Aes256, &AES256_KEY, &AES256_CFB_CIPHERTEXT),
    ];
    let cfb = TpmiAlgCipherMode::Cfb;
    for (alg, key, ciphertext) in vectors {
        // Encryption: the output IV is the last ciphertext block.
        let mut iv = NIST_IV;
        let mut data = NIST_PLAINTEXT;
        crypt(alg, key, cfb, &mut iv, Direction::Encrypt, &mut data).unwrap();
        assert_eq!(&data, ciphertext, "{alg:?} encryption");
        assert_eq!(iv[..], ciphertext[48..], "{alg:?} encryption IV out");

        // Decryption: the output IV is also the last ciphertext block.
        let mut iv = NIST_IV;
        let mut data = *ciphertext;
        crypt(alg, key, cfb, &mut iv, Direction::Decrypt, &mut data).unwrap();
        assert_eq!(data, NIST_PLAINTEXT, "{alg:?} decryption");
        assert_eq!(iv[..], ciphertext[48..], "{alg:?} decryption IV out");
    }
}

#[test]
fn aes_cfb_iv_chaining() {
    let (alg, cfb) = (AlgSym::Aes128, TpmiAlgCipherMode::Cfb);
    // Encrypting block-aligned chunks while chaining the output IV gives the same ciphertext as
    // a single call.
    let mut iv = NIST_IV;
    let mut data = NIST_PLAINTEXT;
    let (first, second) = data.split_at_mut(32);
    crypt(alg, &AES128_KEY, cfb, &mut iv, Direction::Encrypt, first).unwrap();
    assert_eq!(iv[..], AES128_CFB_CIPHERTEXT[16..32]);
    crypt(alg, &AES128_KEY, cfb, &mut iv, Direction::Encrypt, second).unwrap();
    assert_eq!(data, AES128_CFB_CIPHERTEXT);
    assert_eq!(iv[..], AES128_CFB_CIPHERTEXT[48..]);

    // The same holds for decryption.
    let mut iv = NIST_IV;
    let (first, second) = data.split_at_mut(16);
    crypt(alg, &AES128_KEY, cfb, &mut iv, Direction::Decrypt, first).unwrap();
    crypt(alg, &AES128_KEY, cfb, &mut iv, Direction::Decrypt, second).unwrap();
    assert_eq!(data, NIST_PLAINTEXT);
    assert_eq!(iv[..], AES128_CFB_CIPHERTEXT[48..]);
}

#[test]
fn aes_cfb_partial_block_iv() {
    let (alg, cfb) = (AlgSym::Aes128, TpmiAlgCipherMode::Cfb);
    // After a final partial block of `n` bytes, the output IV is those `n` ciphertext bytes
    // padded with zeros (TPM 2.0).
    let mut expected_iv = [0u8; 16];
    expected_iv[..4].copy_from_slice(&AES128_CFB_CIPHERTEXT[16..20]);

    let mut iv = NIST_IV;
    let mut data: [u8; 20] = NIST_PLAINTEXT[..20].try_into().unwrap();
    crypt(
        alg,
        &AES128_KEY,
        cfb,
        &mut iv,
        Direction::Encrypt,
        &mut data,
    )
    .unwrap();
    assert_eq!(data[..], AES128_CFB_CIPHERTEXT[..20]);
    assert_eq!(iv, expected_iv);

    let mut iv = NIST_IV;
    crypt(
        alg,
        &AES128_KEY,
        cfb,
        &mut iv,
        Direction::Decrypt,
        &mut data,
    )
    .unwrap();
    assert_eq!(data[..], NIST_PLAINTEXT[..20]);
    assert_eq!(iv, expected_iv);

    // The mode function itself leaves the rest of the previous chaining value.
    let cipher = <RustCryptoCipher<aes::Aes128> as SymmetricState<16>>::init(&AES128_KEY).unwrap();
    let mut iv = NIST_IV;
    let mut data: [u8; 3] = NIST_PLAINTEXT[..3].try_into().unwrap();
    SymmetricState::<16>::cfb(&cipher, Direction::Encrypt, &mut iv, &mut data).unwrap();
    assert_eq!(data[..], AES128_CFB_CIPHERTEXT[..3]);
    assert_eq!(iv[..3], AES128_CFB_CIPHERTEXT[..3]);
    assert_eq!(iv[3..], NIST_IV[3..]);

    // Empty data leaves the IV unchanged.
    let mut iv = NIST_IV;
    crypt(alg, &AES128_KEY, cfb, &mut iv, Direction::Encrypt, &mut []).unwrap();
    assert_eq!(iv, NIST_IV);
}

/// The AES-256 modes other than CFB match the first block of NIST SP 800-38A F.1.5 (ECB), F.2.5
/// (CBC), F.4.5 (OFB) and F.5.5 (CTR), with the TCG reference's `ivOut`.
#[test]
fn aes_modes() {
    let alg = AlgSym::Aes256;
    let pt: [u8; 16] = NIST_PLAINTEXT[..16].try_into().unwrap();

    let mut data = pt;
    let ecb = TpmiAlgCipherMode::Ecb;
    crypt(
        alg,
        &AES256_KEY,
        ecb,
        &mut [],
        Direction::Encrypt,
        &mut data,
    )
    .unwrap();
    assert_eq!(data, hex!("f3eed1bdb5d2a03c064b5a7e3db181f8"));
    crypt(
        alg,
        &AES256_KEY,
        ecb,
        &mut [],
        Direction::Decrypt,
        &mut data,
    )
    .unwrap();
    assert_eq!(data, pt);

    let cbc = TpmiAlgCipherMode::Cbc;
    let mut iv = NIST_IV;
    crypt(
        alg,
        &AES256_KEY,
        cbc,
        &mut iv,
        Direction::Encrypt,
        &mut data,
    )
    .unwrap();
    assert_eq!(data, hex!("f58c4c04d6e5f1ba779eabfb5f7bfbd6"));
    assert_eq!(iv, data);
    let mut iv = NIST_IV;
    crypt(
        alg,
        &AES256_KEY,
        cbc,
        &mut iv,
        Direction::Decrypt,
        &mut data,
    )
    .unwrap();
    assert_eq!(data, pt);

    let mut iv = NIST_IV;
    let ofb = TpmiAlgCipherMode::Ofb;
    crypt(
        alg,
        &AES256_KEY,
        ofb,
        &mut iv,
        Direction::Encrypt,
        &mut data,
    )
    .unwrap();
    assert_eq!(data, hex!("dc7e84bfda79164b7ecd8486985d3860"));
    // ivOut is the keystream block.
    assert_eq!(iv, hex!("b7bf3a5df43989dd97f0fa97ebce2f4a"));

    let mut data = pt;
    let mut iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let ctr = TpmiAlgCipherMode::Ctr;
    crypt(
        alg,
        &AES256_KEY,
        ctr,
        &mut iv,
        Direction::Encrypt,
        &mut data,
    )
    .unwrap();
    assert_eq!(data, hex!("601ec313775789a5b7a7f504bbf3d228"));
    // ivOut is the next counter block.
    assert_eq!(iv, hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdff00"));
}

/// Camellia-128/192/256: the known answers of RFC 3713, Appendix A.
#[test]
fn camellia_known_answer() {
    let pt = hex!("0123456789abcdeffedcba9876543210");
    let key = hex!("0123456789abcdeffedcba98765432100011223344556677" "8899aabbccddeeff");
    let ecb = |state: &dyn Fn(&mut [[u8; 16]], Direction), expected: [u8; 16]| {
        let mut blocks = [pt];
        state(&mut blocks, Direction::Encrypt);
        assert_eq!(blocks[0], expected);
        state(&mut blocks, Direction::Decrypt);
        assert_eq!(blocks[0], pt);
    };
    let c128 = <RustCryptoCipher<camellia::Camellia128> as SymmetricState<16>>::init(&pt).unwrap();
    ecb(
        &|b, dir| SymmetricState::<16>::ecb(&c128, dir, b).unwrap(),
        hex!("67673138549669730857065648eabe43"),
    );
    let c192 = <RustCryptoCipher<camellia::Camellia192> as SymmetricState<24>>::init(
        key[..24].try_into().unwrap(),
    )
    .unwrap();
    ecb(
        &|b, dir| SymmetricState::<24>::ecb(&c192, dir, b).unwrap(),
        hex!("b4993401b3e996f84ee5cee7d79b09b9"),
    );
    let c256 = <RustCryptoCipher<camellia::Camellia256> as SymmetricState<32>>::init(&key).unwrap();
    ecb(
        &|b, dir| SymmetricState::<32>::ecb(&c256, dir, b).unwrap(),
        hex!("9acc237dff16d76c20ef7c919e3a7509"),
    );
}

#[test]
fn cmac_known_answer() {
    use tpm2_crypto_rust::{RustCryptoCmacAes128, RustCryptoCmacAes256};
    // NIST SP 800-38B, Appendix D.1-D.3 (messages of 0, 16, 40 and 64 bytes).
    let aes128 = [
        hex!("bb1d6929e95937287fa37d129b756746"),
        hex!("070a16b46b4d4144f79bdd9dd04a287c"),
        hex!("dfa66747de9ae63030ca32611497c827"),
        hex!("51f0bebf7e3b9d92fc49741779363cfe"),
    ];
    let aes256 = [
        hex!("028962f61b7bf89efc6b551f4667d983"),
        hex!("28a7023f452e8f82bd4bf28d8c37c35c"),
        hex!("aaf3d8f1de5640c232f5b169b9c911e6"),
        hex!("e1992190549f6ed5696a2c056c315410"),
    ];
    for (len, (mac128, mac256)) in [0, 16, 40, 64]
        .into_iter()
        .zip(aes128.into_iter().zip(aes256))
    {
        let message = &NIST_PLAINTEXT[..len];
        // One-shot.
        let mut mac = [0u8; 16];
        RustCryptoCmacAes128::cmac(&AES128_KEY, &[message], &mut mac).unwrap();
        assert_eq!(mac, mac128, "AES-128 CMAC of {len} bytes");
        RustCryptoCmacAes256::cmac(&AES256_KEY, &[message], &mut mac).unwrap();
        assert_eq!(mac, mac256, "AES-256 CMAC of {len} bytes");

        // Streaming, in uneven pieces.
        let mut state = <RustCryptoCmacAes128 as CmacState<16>>::init(&AES128_KEY).unwrap();
        for piece in message.chunks(7) {
            CmacState::<16>::update(&mut state, piece).unwrap();
        }
        CmacState::<16>::finalize(&mut state, &mut mac).unwrap();
        assert_eq!(mac, mac128, "AES-128 streaming CMAC of {len} bytes");
    }
}

// ==========================================
// ECC
// ==========================================

/// `2 * G` on each curve of the TPM profile, with the curve's coordinate size and the expected
/// `x || y`.
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

/// The point `x || y` as a `TPMS_ECC_POINT`.
fn ecc_point(xy: &[u8], n: usize) -> TpmsEccPoint<'_> {
    TpmsEccPoint {
        x: Tpm2bEccParameter::new(&xy[..n]).unwrap(),
        y: Tpm2bEccParameter::new(&xy[n..2 * n]).unwrap(),
    }
}

#[test]
fn ecc_point_multiplication() {
    for (curve, n, two_g) in ecc_double_generator_vectors() {
        let (mut x, mut y) = ([0u8; 66], [0u8; 66]);
        // 2 * G from the generator.
        let q = ecc_mul_generator::<C>(curve, &[2], &mut x, &mut y)
            .unwrap()
            .unwrap();
        assert_eq!(
            (q.x.as_slice(), q.y.as_slice()),
            (&two_g[..n], &two_g[n..]),
            "{curve:?}"
        );
        // 2 * G as 2 * (1 * G); 0 * G and 0 * P have no result.
        let (mut gx, mut gy) = ([0u8; 66], [0u8; 66]);
        let g = ecc_mul_generator::<C>(curve, &[1], &mut gx, &mut gy)
            .unwrap()
            .unwrap();
        let g = EccPublicKey::<C>::load(curve, None, g).unwrap().unwrap();
        let q = g.mul_point(&[2], &mut x, &mut y).unwrap().unwrap();
        assert_eq!(q.x.as_slice(), &two_g[..n], "{curve:?}");
        assert!(
            ecc_mul_generator::<C>(curve, &[0], &mut x, &mut y)
                .unwrap()
                .is_none()
        );
        assert!(g.mul_point(&[0], &mut x, &mut y).unwrap().is_none());
        // A point that is not on the curve is invalid.
        let mut off_curve = two_g.clone();
        off_curve[2 * n - 1] ^= 0x01;
        assert!(
            EccPublicKey::<C>::load(curve, None, ecc_point(&off_curve, n))
                .unwrap()
                .is_none(),
            "{curve:?}"
        );
    }
}

/// ECDSA signatures and ECDH, through the dispatch enums.
#[test]
fn ecc_keys() {
    let mut rng = C::from_seed(b"ecc seed").unwrap();
    let digest = [0x42u8; 32];
    for (curve, n, _) in ecc_double_generator_vectors() {
        let key = EccPrivateKey::<C>::generate(&mut rng, curve, None).unwrap();
        let (mut x, mut y) = ([0u8; 66], [0u8; 66]);
        let q = key.point(&mut x, &mut y).unwrap();
        assert_eq!(q.x.as_slice().len(), n);
        let public = EccPublicKey::<C>::load(curve, None, q).unwrap().unwrap();

        let mut buf: SignatureBuffer = [0; _];
        let scheme = TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256);
        let signature = key.sign(&mut rng, scheme, &digest, &mut buf).unwrap();
        assert_eq!(public.verify(&digest, signature), Ok(true), "{curve:?}");
        assert_eq!(
            public.verify(&[0x43; 32], signature),
            Ok(false),
            "{curve:?}"
        );

        // ECDH is symmetric.
        let other = EccPrivateKey::<C>::generate(&mut rng, curve, None).unwrap();
        let (mut ox, mut oy) = ([0u8; 66], [0u8; 66]);
        let other_public =
            EccPublicKey::<C>::load(curve, None, other.point(&mut ox, &mut oy).unwrap())
                .unwrap()
                .unwrap();
        let (mut z1x, mut z1y, mut z2x, mut z2y) = ([0u8; 66], [0u8; 66], [0u8; 66], [0u8; 66]);
        let z1 = key
            .ecdh(&other_public, &mut z1x, &mut z1y)
            .unwrap()
            .unwrap();
        let z2 = other.ecdh(&public, &mut z2x, &mut z2y).unwrap().unwrap();
        assert_eq!(z1, z2, "{curve:?}");
    }
}

/// Key generation, loading and storing, ECDSA, ECDH and the point multiplications of the
/// backend key type `K` of a curve with `COORD`-byte coordinates.
fn check_ecc_key_type<K, const COORD: usize, const POINT: usize>()
where
    K: EccCurve<COORD, POINT, R>,
{
    let mut rng = C::from_seed(b"ecc key type").unwrap();
    let key = K::generate(&mut rng, ()).unwrap();
    let (mut d, mut q) = ([0u8; COORD], [0u8; POINT]);
    key.store(&mut d).unwrap();
    K::store_public(key.as_public(), &mut q).unwrap();
    let (mut x, mut y) = ([0u8; COORD], [0u8; COORD]);
    K::mul_generator(&d, &mut x, &mut y).unwrap().unwrap();
    assert_eq!((&x[..], &y[..]), (&q[..COORD], &q[COORD..]));
    let public = K::load_public((), &q).unwrap().unwrap();
    let loaded = K::load(public, &d).unwrap().unwrap();
    let public = K::load_public((), &q).unwrap().unwrap();
    assert!(K::load(public, &[0; COORD]).unwrap().is_none());

    let digest = [0x5a; 48];
    let (mut r, mut s) = ([0u8; COORD], [0u8; COORD]);
    loaded.sign(&mut rng, &digest, &mut r, &mut s).unwrap();
    assert!(K::verify(key.as_public(), &digest, &r, &s).unwrap());
    assert!(!K::verify(key.as_public(), &[0x5b; 48], &r, &s).unwrap());
    let (mut zx, mut zy) = ([0u8; COORD], [0u8; COORD]);
    key.ecdh(loaded.as_public(), &mut zx, &mut zy)
        .unwrap()
        .unwrap();
    K::mul_point(key.as_public(), &d, &mut x, &mut y)
        .unwrap()
        .unwrap();
    assert_eq!((zx, zy), (x, y));
}

/// The backend key types of all supported Weierstrass curves.
#[test]
fn ecc_key_types() {
    use tpm2::crypto::backend::Ecc;
    check_ecc_key_type::<<C as Ecc>::NistP192, 24, 48>();
    check_ecc_key_type::<<C as Ecc>::NistP224, 28, 56>();
    check_ecc_key_type::<<C as Ecc>::NistP256, 32, 64>();
    check_ecc_key_type::<<C as Ecc>::NistP384, 48, 96>();
    check_ecc_key_type::<<C as Ecc>::NistP521, 66, 132>();
    check_ecc_key_type::<<C as Ecc>::BNP256, 32, 64>();
    check_ecc_key_type::<<C as Ecc>::BNP638, 80, 160>();
    check_ecc_key_type::<<C as Ecc>::SM2P256, 32, 64>();
}

/// The generic ECDSA of `tpm2-crypto-weierstrass` (on NIST P-256) and the `p256` crate verify
/// each other's signatures.
#[test]
fn weierstrass_ecdsa_matches_p256() {
    use p256::ecdsa::signature::hazmat::{PrehashSigner as _, PrehashVerifier as _};

    /// NIST P-256 for the generic arithmetic.
    struct P256Id;
    impl tpm2_crypto_weierstrass::CurveId for P256Id {
        fn params() -> &'static tpm2::crypto::EccCurveParams {
            &tpm2::crypto::NIST_P256
        }
    }
    const LIMBS: usize = 32 / core::mem::size_of::<usize>();
    type Generic = tpm2_crypto_weierstrass::EcPrivateKey<P256Id, LIMBS, 32>;

    let mut rng = C::from_seed(b"cross check").unwrap();
    let key = <Generic as PrivateKey<64, 32, R>>::generate(&mut rng, ()).unwrap();
    let (mut d, mut q) = ([0u8; 32], [0u8; 64]);
    PrivateKey::<64, 32, R>::store(&key, &mut d).unwrap();
    <Generic as PrivateKey<64, 32, R>>::store_public(
        PrivateKey::<64, 32, R>::as_public(&key),
        &mut q,
    )
    .unwrap();
    let signing_key = p256::ecdsa::SigningKey::from_slice(&d).unwrap();
    let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
    let mut sec1 = [0x04; 65];
    sec1[1..].copy_from_slice(&q);
    assert_eq!(
        verifying_key,
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap()
    );

    let digest = [0x17u8; 32];
    let (mut r, mut s) = ([0u8; 32], [0u8; 32]);
    EccCurve::<32, 64, R>::sign(&key, &mut rng, &digest, &mut r, &mut s).unwrap();
    let signature = p256::ecdsa::Signature::from_scalars(r, s).unwrap();
    assert!(verifying_key.verify_prehash(&digest, &signature).is_ok());

    let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&digest).unwrap();
    let (r, s) = signature.split_bytes();
    assert!(
        <Generic as EccCurve<32, 64, R>>::verify(
            PrivateKey::<64, 32, R>::as_public(&key),
            &digest,
            &r.into(),
            &s.into()
        )
        .unwrap()
    );
}

// ==========================================
// RSA
// ==========================================

type Rsa1024 = RustCryptoRsa1024;

/// Generates a deterministic RSA-1024 key and returns it with its modulus.
fn rsa1024_key() -> (Rsa1024, [u8; 128]) {
    let key = <Rsa1024 as PrivateKey<128, 64, R, u32>>::generate(
        &mut C::from_seed(b"rsa seed").unwrap(),
        65537,
    )
    .unwrap();
    let mut n = [0u8; 128];
    <Rsa1024 as PrivateKey<128, 64, R, u32>>::store_public(
        PrivateKey::<128, 64, R, u32>::as_public(&key),
        &mut n,
    )
    .unwrap();
    (key, n)
}

#[test]
fn rsa_keys() {
    let (key, n) = rsa1024_key();
    assert_eq!(rsa1024_key().1, n);
    assert!(n[0] & 0x80 != 0 && n[127] & 1 == 1);
    let public = <Rsa1024 as PrivateKey<128, 64, R, u32>>::load_public(65537, &n)
        .unwrap()
        .unwrap();
    assert_eq!(<Rsa1024 as RsaKey<128, 64, R>>::exponent(&public), 65537);

    // The CRT form: p > q, p * q = n, dP, dQ and qInv.
    let mut crt = [[0u8; 64]; 5];
    RsaKey::<128, 64, R>::store_crt(&key, &mut crt).unwrap();
    let [p, q, dp, dq, qinv] = crt.map(|v| rsa::BigUint::from_bytes_be(&v));
    let one = rsa::BigUint::from(1u32);
    let e = rsa::BigUint::from(65537u32);
    assert!(p > q);
    assert_eq!(&p * &q, rsa::BigUint::from_bytes_be(&n));
    assert_eq!((&dp * &e) % (&p - &one), one);
    assert_eq!((&dq * &e) % (&q - &one), one);
    assert_eq!((&qinv * &q) % &p, one);

    // Loading either prime gives the same key, which stores the prime it was loaded with.
    let mut stored = [0u8; 64];
    for prime in [crt[0], crt[1]] {
        let public = <Rsa1024 as PrivateKey<128, 64, R, u32>>::load_public(65537, &n)
            .unwrap()
            .unwrap();
        let loaded = <Rsa1024 as PrivateKey<128, 64, R, u32>>::load(public, &prime)
            .unwrap()
            .unwrap();
        PrivateKey::<128, 64, R, u32>::store(&loaded, &mut stored).unwrap();
        assert_eq!(stored, prime);
        let mut loaded_crt = [[0u8; 64]; 5];
        RsaKey::<128, 64, R>::store_crt(&loaded, &mut loaded_crt).unwrap();
        assert_eq!(loaded_crt, crt);
    }
    // Primes that do not factor the modulus are rejected.
    for bad in [[0u8; 64], [0xff; 64], {
        let mut one = [0u8; 64];
        one[63] = 1;
        one
    }] {
        let public = <Rsa1024 as PrivateKey<128, 64, R, u32>>::load_public(65537, &n)
            .unwrap()
            .unwrap();
        assert!(
            <Rsa1024 as PrivateKey<128, 64, R, u32>>::load(public, &bad)
                .unwrap()
                .is_none()
        );
    }
    // An even modulus or one without its top bit set is invalid.
    let mut even = n;
    even[127] ^= 1;
    assert!(
        <Rsa1024 as PrivateKey<128, 64, R, u32>>::load_public(65537, &even)
            .unwrap()
            .is_none()
    );
    let mut short = n;
    short[0] = 0x7f;
    assert!(
        <Rsa1024 as PrivateKey<128, 64, R, u32>>::load_public(65537, &short)
            .unwrap()
            .is_none()
    );
}

#[test]
fn rsa_encryption() {
    let (key, n) = rsa1024_key();
    let mut rng = C::from_entropy().unwrap();
    let public = PrivateKey::<128, 64, R, u32>::as_public(&key);
    let rsa_key = key.key();
    let (mut ct, mut pt) = ([0u8; 128], [0u8; 128]);

    // Raw RSA round trip; an input that is not smaller than the modulus is rejected.
    let mut m = [0u8; 128];
    m[125..].copy_from_slice(b"raw");
    assert_eq!(
        <Rsa1024 as RsaKey<128, 64, R>>::raw_encrypt(public, &m, &mut ct),
        Ok(Some(()))
    );
    assert_eq!(key.raw_decrypt(&mut rng, &ct, &mut pt), Ok(Some(())));
    assert_eq!(pt, m);
    assert_eq!(
        <Rsa1024 as RsaKey<128, 64, R>>::raw_encrypt(public, &n, &mut ct),
        Ok(None)
    );
    assert_eq!(key.raw_decrypt(&mut rng, &[0xff; 128], &mut pt), Ok(None));

    // RSAES-PKCS1-v1_5 round trip, also with the `rsa` crate; a message too large for the key
    // and a corrupted ciphertext are rejected.
    assert_eq!(
        <Rsa1024 as RsaKey<128, 64, R>>::rsaes_encrypt(public, &mut rng, b"secret", &mut ct),
        Ok(Some(()))
    );
    assert_eq!(key.rsaes_decrypt(&mut rng, &ct, &mut pt), Ok(Some(6)));
    assert_eq!(&pt[..6], b"secret");
    assert_eq!(
        rsa_key.decrypt(rsa::Pkcs1v15Encrypt, &ct).unwrap(),
        b"secret"
    );
    assert_eq!(
        <Rsa1024 as RsaKey<128, 64, R>>::rsaes_encrypt(public, &mut rng, &[1; 118], &mut ct),
        Ok(None)
    );
    let mut corrupted = ct;
    corrupted[5] ^= 0x01;
    assert_eq!(key.rsaes_decrypt(&mut rng, &corrupted, &mut pt), Ok(None));

    // OAEP round trip with a label (with its terminating zero), compatible with the `rsa` crate;
    // a wrong or empty label and a corrupted ciphertext are rejected, and labels need not be
    // UTF-8.
    let label = b"LABEL\0";
    let sha256 = TpmiAlgHash::Sha256;
    assert_eq!(
        <Rsa1024 as RsaKey<128, 64, R>>::oaep_encrypt(
            public, &mut rng, sha256, label, b"secret", &mut ct
        ),
        Ok(Some(()))
    );
    assert_eq!(
        key.oaep_decrypt(&mut rng, sha256, label, &ct, &mut pt),
        Ok(Some(6))
    );
    assert_eq!(&pt[..6], b"secret");
    let oaep = || rsa::Oaep::new_with_label::<sha2::Sha256, _>("LABEL\0");
    assert_eq!(rsa_key.decrypt(oaep(), &ct).unwrap(), b"secret");
    let theirs = rsa_key
        .to_public_key()
        .encrypt(&mut rand_core::OsRng, oaep(), b"theirs")
        .unwrap();
    assert_eq!(
        key.oaep_decrypt(
            &mut rng,
            sha256,
            label,
            theirs.as_slice().try_into().unwrap(),
            &mut pt
        ),
        Ok(Some(6))
    );
    assert_eq!(&pt[..6], b"theirs");
    for bad_label in [&b"OTHER\0"[..], &[][..]] {
        assert_eq!(
            key.oaep_decrypt(&mut rng, sha256, bad_label, &ct, &mut pt),
            Ok(None)
        );
    }
    let mut corrupted = ct;
    corrupted[10] ^= 0xff;
    assert_eq!(
        key.oaep_decrypt(&mut rng, sha256, label, &corrupted, &mut pt),
        Ok(None)
    );
    let binary = [0xff, 0xfe, 0x00];
    assert_eq!(
        <Rsa1024 as RsaKey<128, 64, R>>::oaep_encrypt(
            public, &mut rng, sha256, &binary, b"bin", &mut ct
        ),
        Ok(Some(()))
    );
    assert_eq!(
        key.oaep_decrypt(&mut rng, sha256, &binary, &ct, &mut pt),
        Ok(Some(3))
    );
    assert_eq!(
        <Rsa1024 as RsaKey<128, 64, R>>::oaep_encrypt(
            public,
            &mut rng,
            sha256,
            &[],
            &[1; 63],
            &mut ct
        ),
        Ok(None)
    );
    assert_eq!(
        <Rsa1024 as RsaKey<128, 64, R>>::oaep_encrypt(
            public,
            &mut rng,
            sha256,
            &[],
            &[1; 62],
            &mut ct
        ),
        Ok(Some(()))
    );
    assert_eq!(
        key.oaep_decrypt(&mut rng, sha256, &[], &ct, &mut pt),
        Ok(Some(62))
    );
    // SHA-1 OAEP works as well.
    assert_eq!(
        <Rsa1024 as RsaKey<128, 64, R>>::oaep_encrypt(
            public,
            &mut rng,
            TpmiAlgHash::Sha1,
            &[],
            b"sha1",
            &mut ct
        ),
        Ok(Some(()))
    );
    assert_eq!(
        rsa_key
            .decrypt(rsa::Oaep::new::<sha1::Sha1>(), &ct)
            .unwrap(),
        b"sha1"
    );
}

#[test]
fn rsa_signatures() {
    let (key, _) = rsa1024_key();
    let mut rng = C::from_entropy().unwrap();
    let public = PrivateKey::<128, 64, R, u32>::as_public(&key);
    let rsa_public = public.key();
    let digest = [0x5Au8; 32];
    let mut sig = [0u8; 128];

    // RSASSA: deterministic, compatible with the `rsa` crate.
    key.rsassa_sign(&mut rng, TpmtHa::Sha256(&digest), &mut sig)
        .unwrap();
    assert_eq!(
        <Rsa1024 as RsaKey<128, 64, R>>::rsassa_verify(public, TpmtHa::Sha256(&digest), &sig),
        Ok(true)
    );
    assert_eq!(
        sig.to_vec(),
        key.key()
            .sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &digest)
            .unwrap()
    );
    let mut corrupted = sig;
    corrupted[0] ^= 0x01;
    assert_eq!(
        <Rsa1024 as RsaKey<128, 64, R>>::rsassa_verify(public, TpmtHa::Sha256(&digest), &corrupted),
        Ok(false)
    );
    assert_eq!(
        <Rsa1024 as RsaKey<128, 64, R>>::rsassa_verify(public, TpmtHa::Sha256(&[0; 32]), &sig),
        Ok(false)
    );

    // RSAPSS with the digest size as salt length, compatible with the `rsa` crate; signatures
    // with any salt length verify.
    key.rsapss_sign(&mut rng, TpmtHa::Sha256(&digest), &mut sig)
        .unwrap();
    assert_eq!(
        <Rsa1024 as RsaKey<128, 64, R>>::rsapss_verify(public, TpmtHa::Sha256(&digest), &sig),
        Ok(true)
    );
    assert!(
        rsa_public
            .verify(rsa::Pss::new::<sha2::Sha256>(), &digest, &sig)
            .is_ok()
    );
    for salt in [0, 1, 20, 94] {
        let theirs = key
            .key()
            .sign_with_rng(
                &mut rand_core::OsRng,
                rsa::Pss::new_with_salt::<sha2::Sha256>(salt),
                &digest,
            )
            .unwrap();
        let theirs: [u8; 128] = theirs.try_into().unwrap();
        assert_eq!(
            <Rsa1024 as RsaKey<128, 64, R>>::rsapss_verify(
                public,
                TpmtHa::Sha256(&digest),
                &theirs
            ),
            Ok(true),
            "salt {salt}"
        );
    }
    let mut corrupted = sig;
    corrupted[127] ^= 0x01;
    assert_eq!(
        <Rsa1024 as RsaKey<128, 64, R>>::rsapss_verify(public, TpmtHa::Sha256(&digest), &corrupted),
        Ok(false)
    );
    assert_eq!(
        <Rsa1024 as RsaKey<128, 64, R>>::rsapss_verify(
            public,
            TpmtHa::Sha256(&digest),
            &[0xff; 128]
        ),
        Ok(false)
    );

    // RSA-1024 with SHA-512 PSS: the salt is shortened to 62 bytes.
    #[cfg(feature = "sha512")]
    {
        let digest = [0x5Au8; 64];
        key.rsapss_sign(&mut rng, TpmtHa::Sha512(&digest), &mut sig)
            .unwrap();
        assert_eq!(
            <Rsa1024 as RsaKey<128, 64, R>>::rsapss_verify(public, TpmtHa::Sha512(&digest), &sig),
            Ok(true)
        );
        assert!(
            rsa_public
                .verify(rsa::Pss::new_with_salt::<sha2::Sha512>(62), &digest, &sig)
                .is_ok()
        );
    }
}

/// RSA public-key operations use the key's public exponent (here 3).
#[test]
fn rsa_public_exponent() {
    use rsa::traits::PublicKeyParts as _;
    let key =
        <Rsa1024 as PrivateKey<128, 64, R, u32>>::generate(&mut C::from_seed(b"e3").unwrap(), 3)
            .unwrap();
    let public = PrivateKey::<128, 64, R, u32>::as_public(&key);
    assert_eq!(<Rsa1024 as RsaKey<128, 64, R>>::exponent(public), 3);
    let mut m = [0u8; 128];
    m[100..].fill(0x33);
    let mut ct = [0u8; 128];
    <Rsa1024 as RsaKey<128, 64, R>>::raw_encrypt(public, &m, &mut ct)
        .unwrap()
        .unwrap();
    let expected =
        rsa::BigUint::from_bytes_be(&m).modpow(&rsa::BigUint::from(3u32), public.key().n());
    assert_eq!(rsa::BigUint::from_bytes_be(&ct), expected);
}

/// RSA-2048 through the dispatch enums.
#[test]
fn rsa_dispatch() {
    use tpm2::crypto::{RsaEncryptScheme, RsaPrivateKey, RsaPublicKey};
    let _: Option<RustCryptoRsa2048> = None;
    let mut rng = C::from_seed(b"rsa 2048").unwrap();
    let key = RsaPrivateKey::<C>::generate(&mut rng, tpm2::TpmiRsaKeyBits::Rsa2048, 0).unwrap();
    assert_eq!(key.exponent(), 65537);
    let mut n_buf = [0u8; 512];
    let n = key.modulus(&mut n_buf).unwrap();
    let public = RsaPublicKey::<C>::load(tpm2::TpmiRsaKeyBits::Rsa2048, 0, n)
        .unwrap()
        .unwrap();
    let scheme = RsaEncryptScheme::Oaep {
        hash: TpmiAlgHash::Sha256,
        label: Some(c"DUPLICATE"),
    };
    let mut ct_buf = [0u8; 512];
    let ct = public
        .encrypt(&mut rng, scheme, b"seed", &mut ct_buf)
        .unwrap()
        .unwrap();
    let mut pt_buf = [0u8; 512];
    let pt = key
        .decrypt(&mut rng, scheme, ct.as_slice(), &mut pt_buf)
        .unwrap()
        .unwrap();
    assert_eq!(pt.as_slice(), b"seed");

    let mut buf: SignatureBuffer = [0; _];
    let digest = [7u8; 32];
    let signature = key
        .sign(
            &mut rng,
            TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256),
            &digest,
            &mut buf,
        )
        .unwrap();
    assert_eq!(public.verify(&digest, signature), Ok(true));
    let mut prime_buf = [0u8; 256];
    let p = key.prime_p(&mut prime_buf).unwrap();
    let mut n_buf2 = [0u8; 512];
    let reloaded = RsaPrivateKey::<C>::load(
        RsaPublicKey::<C>::load(
            tpm2::TpmiRsaKeyBits::Rsa2048,
            0,
            key.modulus(&mut n_buf2).unwrap(),
        )
        .unwrap()
        .unwrap(),
        p,
    )
    .unwrap()
    .unwrap();
    let mut crt_buf = [0u8; 1280];
    let mut crt_buf2 = [0u8; 1280];
    assert_eq!(
        key.crt(&mut crt_buf).unwrap().as_slice(),
        reloaded.crt(&mut crt_buf2).unwrap().as_slice()
    );
}

// ==========================================
// ML-KEM and ML-DSA
// ==========================================

#[test]
fn mlkem() {
    type K = RustCryptoMlkem768;
    let seed = [0x11u8; 64];
    let key = <K as MlkemKey<1184, 1088, R>>::expand(&seed).unwrap();
    let mut ek = [0u8; 1184];
    <K as PrivateKey<1184, 64, R>>::store_public(
        PrivateKey::<1184, 64, R>::as_public(&key),
        &mut ek,
    )
    .unwrap();
    let mut stored = [0u8; 64];
    PrivateKey::<1184, 64, R>::store(&key, &mut stored).unwrap();
    assert_eq!(stored, seed);

    // Encapsulation with explicit randomness is deterministic and decapsulates.
    let public = <K as PrivateKey<1184, 64, R>>::load_public((), &ek)
        .unwrap()
        .unwrap();
    let (mut ct, mut ss, mut ss2) = ([0u8; 1088], [0u8; 32], [0u8; 32]);
    <K as MlkemKey<1184, 1088, R>>::encapsulate_internal(&public, &[0x22; 32], &mut ct, &mut ss)
        .unwrap();
    let (mut ct2, mut ss3) = ([0u8; 1088], [0u8; 32]);
    <K as MlkemKey<1184, 1088, R>>::encapsulate_internal(&public, &[0x22; 32], &mut ct2, &mut ss3)
        .unwrap();
    assert_eq!((ct, ss), (ct2, ss3));
    MlkemKey::<1184, 1088, R>::decapsulate(&key, &ct, &mut ss2).unwrap();
    assert_eq!(ss, ss2);
    // Implicit rejection: a corrupted ciphertext gives another secret.
    ct[0] ^= 1;
    MlkemKey::<1184, 1088, R>::decapsulate(&key, &ct, &mut ss2).unwrap();
    assert_ne!(ss, ss2);

    // Randomized encapsulation and key generation.
    let mut rng = C::from_entropy().unwrap();
    <K as MlkemKey<1184, 1088, R>>::encapsulate(&public, &mut rng, &mut ct, &mut ss).unwrap();
    MlkemKey::<1184, 1088, R>::decapsulate(&key, &ct, &mut ss2).unwrap();
    assert_eq!(ss, ss2);
    let generated = <K as PrivateKey<1184, 64, R>>::generate(&mut rng, ()).unwrap();
    let mut ek2 = [0u8; 1184];
    <K as PrivateKey<1184, 64, R>>::store_public(
        PrivateKey::<1184, 64, R>::as_public(&generated),
        &mut ek2,
    )
    .unwrap();
    assert_ne!(ek, ek2);

    // The seed must match the public key.
    assert!(
        <K as PrivateKey<1184, 64, R>>::load(
            <K as PrivateKey<1184, 64, R>>::load_public((), &ek)
                .unwrap()
                .unwrap(),
            &seed
        )
        .unwrap()
        .is_some()
    );
    assert!(
        <K as PrivateKey<1184, 64, R>>::load(
            <K as PrivateKey<1184, 64, R>>::load_public((), &ek)
                .unwrap()
                .unwrap(),
            &[0; 64]
        )
        .unwrap()
        .is_none()
    );
    // An encapsulation key with coefficients `>= q` fails the modulus check.
    assert!(
        <K as PrivateKey<1184, 64, R>>::load_public((), &[0xff; 1184])
            .unwrap()
            .is_none()
    );
}

#[test]
fn mldsa() {
    type K = RustCryptoMldsa65;
    type Vk = ml_dsa::VerifyingKey<ml_dsa::MlDsa65>;
    let seed = [0x33u8; 32];
    let key = <K as MldsaKey<1952, 3309, R>>::expand(&seed).unwrap();
    let mut pk = [0u8; 1952];
    <K as PrivateKey<1952, 32, R>>::store_public(
        PrivateKey::<1952, 32, R>::as_public(&key),
        &mut pk,
    )
    .unwrap();
    let public = <K as PrivateKey<1952, 32, R>>::load_public((), &pk)
        .unwrap()
        .unwrap();
    let vk = Vk::decode(&pk.as_slice().try_into().unwrap());
    let decode = |sig: &[u8; 3309]| {
        ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(&sig.as_slice().try_into().unwrap()).unwrap()
    };
    let mut rng = C::from_entropy().unwrap();
    let mut sig = [0u8; 3309];

    // Pure ML-DSA with a context, compatible with `ml-dsa`.
    let msg: [&[u8]; 2] = [b"hello ", b"world"];
    key.sign_message(&mut rng, b"ctx", &msg, &mut sig).unwrap();
    assert!(<K as MldsaKey<1952, 3309, R>>::verify_message(&public, b"ctx", &msg, &sig).unwrap());
    assert!(vk.verify_with_context(b"hello world", b"ctx", &decode(&sig)));
    assert!(
        !<K as MldsaKey<1952, 3309, R>>::verify_message(&public, b"other", &msg, &sig).unwrap()
    );
    assert!(
        !<K as MldsaKey<1952, 3309, R>>::verify_message(&public, &[0; 256], &msg, &sig).unwrap()
    );
    let theirs = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa65>::from_seed(&seed.into())
        .sign_deterministic(b"hello world", b"")
        .unwrap();
    assert!(
        <K as MldsaKey<1952, 3309, R>>::verify_message(
            &public,
            b"",
            &[b"hello world"],
            &theirs.encode().into()
        )
        .unwrap()
    );

    // External mu: deterministic with explicit randomness.
    let mu = [0x44u8; 64];
    MldsaKey::<1952, 3309, R>::sign_mu_internal(&key, &[0; 32], &mu, &mut sig).unwrap();
    assert!(<K as MldsaKey<1952, 3309, R>>::verify_mu(&public, &mu, &sig).unwrap());
    assert!(vk.verify_mu(&mu.into(), &decode(&sig)));
    let mut sig2 = [0u8; 3309];
    MldsaKey::<1952, 3309, R>::sign_mu_internal(&key, &[0; 32], &mu, &mut sig2).unwrap();
    assert_eq!(sig, sig2);
    key.sign_mu(&mut rng, &mu, &mut sig2).unwrap();
    assert!(<K as MldsaKey<1952, 3309, R>>::verify_mu(&public, &mu, &sig2).unwrap());
    assert!(!<K as MldsaKey<1952, 3309, R>>::verify_mu(&public, &[0; 64], &sig2).unwrap());
    // A malformed signature does not verify.
    assert!(!<K as MldsaKey<1952, 3309, R>>::verify_mu(&public, &mu, &[0xff; 3309]).unwrap());

    // HashML-DSA, domain-separated from pure ML-DSA.
    let digest = [0x55u8; 32];
    key.sign_prehash(&mut rng, b"", TpmtHa::Sha256(&digest), &mut sig)
        .unwrap();
    assert!(
        <K as MldsaKey<1952, 3309, R>>::verify_prehash(&public, b"", TpmtHa::Sha256(&digest), &sig)
            .unwrap()
    );
    assert!(
        !<K as MldsaKey<1952, 3309, R>>::verify_prehash(
            &public,
            b"",
            TpmtHa::Sha256(&[0; 32]),
            &sig
        )
        .unwrap()
    );
    assert!(
        !<K as MldsaKey<1952, 3309, R>>::verify_message(&public, b"", &[&digest], &sig).unwrap()
    );
    assert_eq!(
        key.sign_prehash(&mut rng, b"", TpmtHa::Sha1(&[0; 20]), &mut sig),
        Err(CryptoError::Unsupported)
    );

    // The seed must match the public key.
    assert!(
        <K as PrivateKey<1952, 32, R>>::load(
            <K as PrivateKey<1952, 32, R>>::load_public((), &pk)
                .unwrap()
                .unwrap(),
            &seed
        )
        .unwrap()
        .is_some()
    );
    assert!(
        <K as PrivateKey<1952, 32, R>>::load(
            <K as PrivateKey<1952, 32, R>>::load_public((), &pk)
                .unwrap()
                .unwrap(),
            &[0; 32]
        )
        .unwrap()
        .is_none()
    );
    let mut stored = [0u8; 32];
    PrivateKey::<1952, 32, R>::store(&key, &mut stored).unwrap();
    assert_eq!(stored, seed);
}
