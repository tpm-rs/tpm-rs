//! Smoke tests for the [`RustCrypto`] backend.
//!
//! The known-answer tests check that each algorithm is wired up correctly, and
//! the asymmetric tests check that operations round-trip (with the RSA padding
//! schemes also cross-checked against the `rsa` crate).

use std::sync::OnceLock;

use hex_literal::hex;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use rsa::{BigUint, Oaep, Pss};
use sha2::Sha256;
use tpm2::{
    AlgSym, Tpm2bEccParameter, Tpm2bPrivateKeyRsa, TpmEccCurve, TpmiAlgCipherMode, TpmiAlgHash,
    TpmiRsaKeyBits, TpmsEccPoint, TpmtHa,
    crypto::{
        ConstantTimeEq as _, CryptoError, Direction, Ecc, EccPrivateKey as _, EccPublicKey as _,
        EccSigScheme, ModeIv, Random, Rng, Rsa, RsaEncryptScheme, RsaPrivateKey as _,
        RsaPublicKey as _, RsaSigScheme, Signing, SymmetricKey, cmac, encrypt_decrypt, hash, hmac,
    },
};
use tpm2_rustcrypto::{ChaChaRng, EccPrivateKey, RsaPrivateKey, RsaPublicKey, RustCrypto};

const MAX_RSA: usize = TpmiRsaKeyBits::MAX_PUB_KEY_BYTES;
const MAX_ECC: usize = TpmEccCurve::MAX_ECC_KEY_BYTES;

#[test]
fn hash_kats() {
    let cases: [(TpmiAlgHash, &[u8]); 8] = [
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
        (
            TpmiAlgHash::Sm3_256,
            &hex!("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
        ),
        (
            TpmiAlgHash::Sha3_256,
            &hex!("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        ),
        (
            TpmiAlgHash::Sha3_384,
            &hex!(
                "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c25"
                "96da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
            ),
        ),
        (
            TpmiAlgHash::Sha3_512,
            &hex!(
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
                "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
            ),
        ),
    ];
    for (alg, expected) in cases {
        let mut out = [0; TpmiAlgHash::MAX_DIGEST_BYTES];
        let digest = hash(&RustCrypto, alg, b"abc", &mut out).unwrap();
        assert_eq!(digest.hash_alg(), alg);
        assert_eq!(digest.digest(), expected, "{alg:?}");
    }
}

#[test]
fn hmac_kats() {
    // RFC 2202 and RFC 4231, Test Case 2 (with the same inputs for SM3 and SHA-3).
    let cases: [(TpmiAlgHash, &[u8]); 8] = [
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
        (
            TpmiAlgHash::Sm3_256,
            &hex!("2e87f1d16862e6d964b50a5200bf2b10b764faa9680a296a2405f24bec39f882"),
        ),
        (
            TpmiAlgHash::Sha3_256,
            &hex!("c7d4072e788877ae3596bbb0da73b887c9171f93095b294ae857fbe2645e1ba5"),
        ),
        (
            TpmiAlgHash::Sha3_384,
            &hex!(
                "f1101f8cbf9766fd6764d2ed61903f21ca9b18f57cf3e1a2"
                "3ca13508a93243ce48c045dc007f26a21b3f5e0e9df4c20a"
            ),
        ),
        (
            TpmiAlgHash::Sha3_512,
            &hex!(
                "5a4bfeab6166427c7a3647b747292b8384537cdb89afb3bf5665e4c5e709350b"
                "287baec921fd7ca0ee7a0c31d022a95e1fc92ba9d77df883960275beb4e62024"
            ),
        ),
    ];
    for (alg, expected) in cases {
        let mut out = [0; TpmiAlgHash::MAX_DIGEST_BYTES];
        let mac = hmac(
            &RustCrypto,
            alg,
            b"Jefe",
            b"what do ya want for nothing?",
            &mut out,
        );
        assert_eq!(mac.unwrap().digest(), expected, "{alg:?}");
    }
}

fn check_cmac(alg: AlgSym, key: &[u8], data: &[u8], expected: [u8; 16]) {
    let mut out = [0; 16];
    let key = SymmetricKey::new(alg, key).unwrap();
    cmac(&RustCrypto, key, data, &mut out).unwrap();
    assert_eq!(out, expected, "{alg:?}");
}

#[test]
fn cmac_kats() {
    // NIST SP 800-38B, Appendix D
    let aes128_key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    check_cmac(
        AlgSym::Aes128,
        &aes128_key,
        b"",
        hex!("bb1d6929e95937287fa37d129b756746"),
    );
    check_cmac(
        AlgSym::Aes128,
        &aes128_key,
        &PLAINTEXT[..16],
        hex!("070a16b46b4d4144f79bdd9dd04a287c"),
    );
    check_cmac(
        AlgSym::Aes192,
        &hex!("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
        b"",
        hex!("d17ddf46adaacde531cac483de7a9367"),
    );
    check_cmac(
        AlgSym::Aes256,
        &hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
        b"",
        hex!("028962f61b7bf89efc6b551f4667d983"),
    );
}

#[test]
fn constant_time_eq() {
    assert!(RustCrypto.constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
    assert!(!RustCrypto.constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
}

/// Checks that `alg` encrypts the single block `plaintext` to `ciphertext`,
/// and decrypts it back.
fn check_block_cipher(alg: AlgSym, key: &[u8], plaintext: [u8; 16], ciphertext: [u8; 16]) {
    let key = SymmetricKey::new(alg, key).unwrap();
    let mut data = plaintext;
    encrypt_decrypt(&RustCrypto, key, ModeIv::Ecb, Direction::Encrypt, &mut data).unwrap();
    assert_eq!(data, ciphertext, "{alg:?}");
    encrypt_decrypt(&RustCrypto, key, ModeIv::Ecb, Direction::Decrypt, &mut data).unwrap();
    assert_eq!(data, plaintext, "{alg:?}");
}

#[test]
fn block_cipher_kats() {
    // FIPS 197, Appendix C
    let pt = hex!("00112233445566778899aabbccddeeff");
    check_block_cipher(
        AlgSym::Aes128,
        &hex!("000102030405060708090a0b0c0d0e0f"),
        pt,
        hex!("69c4e0d86a7b0430d8cdb78070b4c55a"),
    );
    check_block_cipher(
        AlgSym::Aes192,
        &hex!("000102030405060708090a0b0c0d0e0f1011121314151617"),
        pt,
        hex!("dda97ca4864cdfe06eaf70a0ec0d7191"),
    );
    check_block_cipher(
        AlgSym::Aes256,
        &hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        pt,
        hex!("8ea2b7ca516745bfeafc49904b496089"),
    );
    // GB/T 32907-2016, Appendix A.1
    let pt = hex!("0123456789abcdeffedcba9876543210");
    check_block_cipher(
        AlgSym::Sm4_128,
        &hex!("0123456789abcdeffedcba9876543210"),
        pt,
        hex!("681edf34d206965e86b3e94f536e4246"),
    );
    // RFC 3713, Appendix A
    check_block_cipher(
        AlgSym::Camellia128,
        &hex!("0123456789abcdeffedcba9876543210"),
        pt,
        hex!("67673138549669730857065648eabe43"),
    );
    check_block_cipher(
        AlgSym::Camellia192,
        &hex!("0123456789abcdeffedcba98765432100011223344556677"),
        pt,
        hex!("b4993401b3e996f84ee5cee7d79b09b9"),
    );
    check_block_cipher(
        AlgSym::Camellia256,
        &hex!("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff"),
        pt,
        hex!("9acc237dff16d76c20ef7c919e3a7509"),
    );
}

/// AES-128 key from NIST SP 800-38A, Appendix F.
const AES128_KEY: [u8; 16] = hex!("2b7e151628aed2a6abf7158809cf4f3c");
/// Plaintext from NIST SP 800-38A, Appendix F.
const PLAINTEXT: [u8; 32] =
    hex!("6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51");
/// IV from NIST SP 800-38A, Appendix F (for all modes except CTR).
const IV: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");

/// Encrypts the start of [`PLAINTEXT`] with AES-128 in `mode`, checks that it
/// matches `ciphertext`, and decrypts it again. Returns the output IV.
fn aes128_mode(mode: TpmiAlgCipherMode, iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let key = SymmetricKey::new(AlgSym::Aes128, &AES128_KEY).unwrap();
    let plaintext = &PLAINTEXT[..ciphertext.len()];
    let mut data = plaintext.to_vec();
    let mut iv_enc = iv.to_vec();
    let mode_iv = ModeIv::new(mode, &mut iv_enc).unwrap();
    encrypt_decrypt(&RustCrypto, key, mode_iv, Direction::Encrypt, &mut data).unwrap();
    assert_eq!(data, ciphertext);
    let mut iv_dec = iv.to_vec();
    let mode_iv = ModeIv::new(mode, &mut iv_dec).unwrap();
    encrypt_decrypt(&RustCrypto, key, mode_iv, Direction::Decrypt, &mut data).unwrap();
    assert_eq!(data, plaintext);
    // Both directions produce the same output IV.
    assert_eq!(iv_enc, iv_dec);
    iv_enc
}

#[test]
fn symmetric_modes() {
    // NIST SP 800-38A, Appendix F.1.1
    let ct = hex!("3ad77bb40d7a3660a89ecaf32466ef97" "f5d3d58503b9699de785895a96fdbaaf");
    aes128_mode(TpmiAlgCipherMode::Ecb, &[], &ct);

    // Appendix F.2.1: the output IV is the last ciphertext block.
    let ct = hex!("7649abac8119b246cee98e9b12e9197d" "5086cb9b507219ee95db113a917678b2");
    assert_eq!(aes128_mode(TpmiAlgCipherMode::Cbc, &IV, &ct), ct[16..]);

    // Appendix F.3.13: the output IV is the last ciphertext block, padded
    // with zeros if it is partial.
    let ct = hex!("3b3fd92eb72dad20333449f8e83cfb4a" "c8a64537a0b3a93fcde3cdad9f1ce58b");
    assert_eq!(aes128_mode(TpmiAlgCipherMode::Cfb, &IV, &ct), ct[16..]);
    let iv_out = aes128_mode(TpmiAlgCipherMode::Cfb, &IV, &ct[..21]);
    assert_eq!(iv_out, [&ct[16..21], &[0; 11]].concat());

    // Appendix F.4.1
    let ct = hex!("3b3fd92eb72dad20333449f8e83cfb4a" "7789508d16918f03f53c52dac54ed825");
    aes128_mode(TpmiAlgCipherMode::Ofb, &IV, &ct);
    aes128_mode(TpmiAlgCipherMode::Ofb, &IV, &ct[..21]);

    // Appendix F.5.1: the output IV is the next counter value.
    let ctr = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let ctr_out = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdff01");
    let ct = hex!("874d6191b620e3261bef6864990db6ce" "9806f66b7970fdff8617187bb9fffdff");
    assert_eq!(aes128_mode(TpmiAlgCipherMode::Ctr, &ctr, &ct), ctr_out);
    assert_eq!(
        aes128_mode(TpmiAlgCipherMode::Ctr, &ctr, &ct[..21]),
        ctr_out
    );

    // Block modes require block-aligned data.
    let key = SymmetricKey::new(AlgSym::Aes128, &AES128_KEY).unwrap();
    let result = encrypt_decrypt(
        &RustCrypto,
        key,
        ModeIv::Ecb,
        Direction::Encrypt,
        &mut [0; 15],
    );
    assert_eq!(result, Err(CryptoError::Internal));
}

fn random_bytes(rng: &mut ChaChaRng) -> [u8; 32] {
    let mut out = [0; 32];
    rng.fill_bytes(&mut out).unwrap();
    out
}

/// Returns the first output of an RNG seeded with `seed`, and then reseeded
/// with each of `reseeds`.
fn seeded_output(seed: &[u8], reseeds: &[&[u8]]) -> [u8; 32] {
    let mut rng = RustCrypto.rng_seeded(seed).unwrap();
    for data in reseeds {
        rng.reseed(data).unwrap();
    }
    random_bytes(&mut rng)
}

#[test]
fn rng() {
    // Seeded RNGs are deterministic, including after reseeding.
    let output = seeded_output(b"seed", &[]);
    assert_eq!(seeded_output(b"seed", &[]), output);
    assert_ne!(seeded_output(b"other seed", &[]), output);
    let reseeded = seeded_output(b"seed", &[b"data"]);
    assert_eq!(seeded_output(b"seed", &[b"data"]), reseeded);
    assert_ne!(reseeded, output);
    assert_ne!(seeded_output(b"seed", &[b"other data"]), reseeded);

    // RNGs seeded from the OS are independent.
    let mut a = RustCrypto.rng().unwrap();
    let mut b = RustCrypto.rng().unwrap();
    assert_ne!(random_bytes(&mut a), random_bytes(&mut b));
}

/// Seed for the RSA key shared by all tests (as key generation is slow).
const RSA_SEED: &[u8] = b"tpm2-rustcrypto RSA key";

fn generate_rsa_key(seed: &[u8]) -> RsaPrivateKey {
    let mut rng = RustCrypto.rng_seeded(seed).unwrap();
    Rsa::generate_key(&RustCrypto, &mut rng, TpmiRsaKeyBits::Rsa1024, 0).unwrap()
}

fn rsa_key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| generate_rsa_key(RSA_SEED))
}

fn rsa_encrypt(
    rng: &mut ChaChaRng,
    key: &RsaPublicKey,
    scheme: RsaEncryptScheme<'_>,
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    let mut out = [0; MAX_RSA];
    let ciphertext = Rsa::encrypt(&RustCrypto, rng, key, scheme, plaintext, &mut out).unwrap();
    ciphertext.map(|c| c.as_slice().to_vec())
}

fn rsa_decrypt(
    key: &RsaPrivateKey,
    scheme: RsaEncryptScheme<'_>,
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    let mut out = [0; MAX_RSA];
    let plaintext = Rsa::decrypt(&RustCrypto, key, scheme, ciphertext, &mut out).unwrap();
    plaintext.map(|p| p.as_slice().to_vec())
}

fn oaep(label: &[u8]) -> RsaEncryptScheme<'_> {
    RsaEncryptScheme::Oaep {
        hash: TpmiAlgHash::Sha256,
        label,
    }
}

/// Converts `key` into an `rsa` crate public key.
fn rsa_crate_key(key: &RsaPublicKey) -> rsa::RsaPublicKey {
    let mut n = [0; MAX_RSA];
    let n = BigUint::from_bytes_be(key.modulus(&mut n).unwrap().as_slice());
    rsa::RsaPublicKey::new(n, BigUint::from(key.exponent())).unwrap()
}

#[test]
fn rsa_generate_key() {
    let key = rsa_key();
    assert_eq!(key.public_key().bits(), TpmiRsaKeyBits::Rsa1024);
    assert_eq!(key.public_key().exponent(), 65537);
    // Key generation is deterministic.
    assert_eq!(generate_rsa_key(RSA_SEED).public_key(), key.public_key());
    // Even exponents are unsupported.
    let mut rng = RustCrypto.rng_seeded(RSA_SEED).unwrap();
    let result = Rsa::generate_key(&RustCrypto, &mut rng, TpmiRsaKeyBits::Rsa1024, 4);
    assert_eq!(result.unwrap_err(), CryptoError::Unsupported);
}

#[test]
fn rsa_load() {
    let key = rsa_key();
    let public = key.public_key();
    let mut n = [0; MAX_RSA];
    let modulus = public.modulus(&mut n).unwrap();
    assert_eq!(modulus.as_slice().len(), 128);
    let loaded = Rsa::load_public(&RustCrypto, TpmiRsaKeyBits::Rsa1024, 0, modulus);
    let loaded = loaded.unwrap().unwrap();
    assert_eq!(&loaded, public);

    let mut p = [0; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES];
    let prime_p = key.prime_p(&mut p).unwrap();
    assert_eq!(prime_p.as_slice().len(), 64);
    let private = Rsa::load_private(&RustCrypto, loaded.clone(), prime_p);
    let private = private.unwrap().unwrap();
    assert_eq!(private.public_key(), public);
    let mut rng = RustCrypto.rng_seeded(b"rsa load").unwrap();
    let ciphertext = rsa_encrypt(&mut rng, public, oaep(b""), b"message").unwrap();
    assert_eq!(
        rsa_decrypt(&private, oaep(b""), &ciphertext).unwrap(),
        b"message"
    );

    // A modulus of the wrong size, or an even exponent, is rejected.
    let result = Rsa::load_public(&RustCrypto, TpmiRsaKeyBits::Rsa2048, 0, modulus);
    assert_eq!(result.unwrap(), None);
    let result = Rsa::load_public(&RustCrypto, TpmiRsaKeyBits::Rsa1024, 4, modulus);
    assert_eq!(result.unwrap(), None);
    // A prime that isn't a factor of the modulus is rejected.
    let mut bad_p = prime_p.as_slice().to_vec();
    bad_p[63] ^= 2;
    let bad_p = Tpm2bPrivateKeyRsa::new(&bad_p).unwrap();
    let result = Rsa::load_private(&RustCrypto, loaded, bad_p);
    assert!(result.unwrap().is_none());
}

#[test]
fn rsa_encrypt_decrypt() {
    let key = rsa_key();
    let mut rng = RustCrypto.rng_seeded(b"rsa encrypt").unwrap();
    for scheme in [
        RsaEncryptScheme::Raw,
        RsaEncryptScheme::Rsaes,
        oaep(b"label\0"),
    ] {
        let ciphertext = rsa_encrypt(&mut rng, key.public_key(), scheme, b"message").unwrap();
        assert_eq!(ciphertext.len(), 128);
        let plaintext = rsa_decrypt(key, scheme, &ciphertext).unwrap();
        // Raw decryption returns the message left-padded to the modulus size.
        let plaintext = match scheme {
            RsaEncryptScheme::Raw => plaintext.strip_prefix(&[0; 121]).unwrap(),
            _ => plaintext.as_slice(),
        };
        assert_eq!(plaintext, b"message", "{scheme:?}");
        // Ciphertexts must be the size of the modulus.
        assert_eq!(rsa_decrypt(key, scheme, &ciphertext[1..]), None);
    }
}

#[test]
fn rsa_oaep() {
    let key = rsa_key();
    // Decrypt a ciphertext from the rsa crate (TPM labels include the NUL).
    let mut crate_rng = ChaCha20Rng::from_seed([0; 32]);
    let padding = Oaep::new_with_label::<Sha256, _>("label\0");
    let ciphertext = rsa_crate_key(key.public_key())
        .encrypt(&mut crate_rng, padding, b"message")
        .unwrap();
    assert_eq!(
        rsa_decrypt(key, oaep(b"label\0"), &ciphertext).unwrap(),
        b"message"
    );

    // The wrong label, or a modified ciphertext, is rejected.
    assert_eq!(rsa_decrypt(key, oaep(b"other\0"), &ciphertext), None);
    let mut modified = ciphertext.clone();
    modified[64] ^= 1;
    assert_eq!(rsa_decrypt(key, oaep(b"label\0"), &modified), None);

    // Messages can be at most k - 2 * hLen - 2 bytes long.
    let mut rng = RustCrypto.rng_seeded(b"rsa oaep").unwrap();
    assert!(rsa_encrypt(&mut rng, key.public_key(), oaep(b""), &[1; 62]).is_some());
    assert_eq!(
        rsa_encrypt(&mut rng, key.public_key(), oaep(b""), &[1; 63]),
        None
    );
}

#[test]
fn rsa_sign_verify() {
    let key = rsa_key();
    let public = key.public_key();
    let mut rng = RustCrypto.rng_seeded(b"rsa sign").unwrap();
    let digest = TpmtHa::new(TpmiAlgHash::Sha256, &[0x5a; 32]).unwrap();
    let other = TpmtHa::new(TpmiAlgHash::Sha256, &[0xa5; 32]).unwrap();
    for scheme in [RsaSigScheme::Rsassa, RsaSigScheme::Rsapss] {
        let mut out = [0; MAX_RSA];
        let sig = RustCrypto.rsa_sign(&mut rng, key, scheme, digest, &mut out);
        let sig = sig.unwrap().as_slice();
        assert_eq!(sig.len(), 128);
        assert!(RustCrypto.rsa_verify(public, scheme, digest, sig).unwrap());
        assert!(!RustCrypto.rsa_verify(public, scheme, other, sig).unwrap());
        let mut modified = sig.to_vec();
        modified[64] ^= 1;
        assert!(
            !RustCrypto
                .rsa_verify(public, scheme, digest, &modified)
                .unwrap()
        );
        assert!(
            !RustCrypto
                .rsa_verify(public, scheme, digest, &sig[1..])
                .unwrap()
        );
    }
}

#[test]
fn rsa_signature_encoding() {
    let key = rsa_key();
    let public = key.public_key();
    let mut rng = RustCrypto.rng_seeded(b"rsa signature encoding").unwrap();
    let digest_bytes = [0x5a; 32];
    let digest = TpmtHa::new(TpmiAlgHash::Sha256, &digest_bytes).unwrap();

    // RSASSA-PKCS1-v1_5: a raw public key operation recovers
    // EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo
    let mut out = [0; MAX_RSA];
    let sig = RustCrypto.rsa_sign(&mut rng, key, RsaSigScheme::Rsassa, digest, &mut out);
    let em = rsa_encrypt(
        &mut rng,
        public,
        RsaEncryptScheme::Raw,
        sig.unwrap().as_slice(),
    );
    let digest_info = hex!("3031300d060960864801650304020105000420");
    let mut expected = vec![0x00, 0x01];
    expected.resize(128 - digest_info.len() - digest_bytes.len() - 1, 0xff);
    expected.push(0x00);
    expected.extend_from_slice(&digest_info);
    expected.extend_from_slice(&digest_bytes);
    assert_eq!(em.unwrap(), expected);

    // RSASSA-PSS: the rsa crate verifies the signature (with the salt as long
    // as the digest).
    let mut out = [0; MAX_RSA];
    let sig = RustCrypto.rsa_sign(&mut rng, key, RsaSigScheme::Rsapss, digest, &mut out);
    let pss = Pss::new_with_salt::<Sha256>(32);
    let result = rsa_crate_key(public).verify(pss, &digest_bytes, sig.unwrap().as_slice());
    assert_eq!(result, Ok(()));
}

const CURVES: [TpmEccCurve; 4] = [
    TpmEccCurve::NistP256,
    TpmEccCurve::NistP384,
    TpmEccCurve::NistP521,
    TpmEccCurve::SM2P256,
];

/// Returns the size of the field of `curve` in bytes.
fn field_bytes(curve: TpmEccCurve) -> usize {
    match curve {
        TpmEccCurve::NistP384 => 48,
        TpmEccCurve::NistP521 => 66,
        _ => 32,
    }
}

fn ecc_key(rng: &mut ChaChaRng, curve: TpmEccCurve) -> EccPrivateKey {
    Ecc::generate_key(&RustCrypto, rng, curve).unwrap()
}

#[test]
fn ecc_load() {
    let mut rng = RustCrypto.rng_seeded(b"ecc load").unwrap();
    for curve in CURVES {
        let key = ecc_key(&mut rng, curve);
        assert_eq!(key.public_key().curve(), curve);
        let (mut x, mut y, mut d) = ([0; MAX_ECC], [0; MAX_ECC], [0; MAX_ECC]);
        let point = key.public_key().point(&mut x, &mut y).unwrap();
        assert_eq!(point.x.as_slice().len(), field_bytes(curve));
        assert_eq!(point.y.as_slice().len(), field_bytes(curve));
        let public = Ecc::load_public(&RustCrypto, curve, point)
            .unwrap()
            .unwrap();
        assert_eq!(&public, key.public_key());
        let scalar = key.scalar(&mut d).unwrap();
        assert_eq!(scalar.as_slice().len(), field_bytes(curve));
        let private = Ecc::load_private(&RustCrypto, public.clone(), scalar);
        assert_eq!(private.unwrap().unwrap().public_key(), key.public_key());

        // A point that isn't on the curve is rejected.
        let mut bad_y = point.y.as_slice().to_vec();
        *bad_y.last_mut().unwrap() ^= 1;
        let y = Tpm2bEccParameter::new(&bad_y).unwrap();
        let result = Ecc::load_public(&RustCrypto, curve, TpmsEccPoint { x: point.x, y });
        assert_eq!(result.unwrap(), None);
        // The scalar of a different key is rejected.
        let mut d = [0; MAX_ECC];
        let other = ecc_key(&mut rng, curve);
        let result = Ecc::load_private(&RustCrypto, public, other.scalar(&mut d).unwrap());
        assert!(result.unwrap().is_none());
    }
    let result = Ecc::generate_key(&RustCrypto, &mut rng, TpmEccCurve::BNP256);
    assert_eq!(result.unwrap_err(), CryptoError::Unsupported);
}

#[test]
fn ecc_sign_verify() {
    let mut rng = RustCrypto.rng_seeded(b"ecc sign").unwrap();
    let (bytes, other_bytes) = ([0x5a; 64], [0xa5; 64]);
    let schemes = [
        EccSigScheme::Ecdsa,
        EccSigScheme::Sm2,
        EccSigScheme::Ecschnorr,
    ];
    for curve in CURVES {
        let key = ecc_key(&mut rng, curve);
        for scheme in schemes {
            // Digests both shorter and longer than the curve order.
            for alg in [TpmiAlgHash::Sha1, TpmiAlgHash::Sha512] {
                let digest = TpmtHa::new(alg, &bytes[..alg.digest_size()]).unwrap();
                let other = TpmtHa::new(alg, &other_bytes[..alg.digest_size()]).unwrap();
                let (mut r, mut s) = ([0; MAX_ECC], [0; MAX_ECC]);
                let sig = RustCrypto.ecc_sign(&mut rng, &key, scheme, digest, &mut r, &mut s);
                let (r, s) = sig.unwrap();
                let (r, s) = (r.as_slice(), s.as_slice());
                assert_eq!(r.len(), field_bytes(curve));
                assert_eq!(s.len(), field_bytes(curve));
                let verify = |digest, r: &[u8], s: &[u8]| {
                    let result = RustCrypto.ecc_verify(key.public_key(), scheme, digest, r, s);
                    result.unwrap()
                };
                assert!(verify(digest, r, s), "{curve:?} {scheme:?} {alg:?}");
                assert!(!verify(other, r, s));
                let mut modified = s.to_vec();
                *modified.last_mut().unwrap() ^= 1;
                assert!(!verify(digest, r, &modified));
                assert!(!verify(digest, &[0], s));
            }
        }
        let digest = TpmtHa::new(TpmiAlgHash::Sha256, &bytes[..32]).unwrap();
        let (mut r, mut s) = ([0; MAX_ECC], [0; MAX_ECC]);
        let scheme = EccSigScheme::Ecdaa(0);
        let result = RustCrypto.ecc_sign(&mut rng, &key, scheme, digest, &mut r, &mut s);
        assert_eq!(result.unwrap_err(), CryptoError::Unsupported);
    }
}

#[test]
fn ecdh_agreement() {
    let mut rng = RustCrypto.rng_seeded(b"ecdh").unwrap();
    for curve in CURVES {
        let (a, b) = (ecc_key(&mut rng, curve), ecc_key(&mut rng, curve));
        let (mut x1, mut y1) = ([0; MAX_ECC], [0; MAX_ECC]);
        let (mut x2, mut y2) = ([0; MAX_ECC], [0; MAX_ECC]);
        let z1 = RustCrypto
            .ecdh(&a, b.public_key(), &mut x1, &mut y1)
            .unwrap();
        let z2 = RustCrypto
            .ecdh(&b, a.public_key(), &mut x2, &mut y2)
            .unwrap();
        assert_eq!(z1, z2);
        assert_eq!(z1.unwrap().x.as_slice().len(), field_bytes(curve));
    }
    // The keys must be on the same curve.
    let a = ecc_key(&mut rng, TpmEccCurve::NistP256);
    let b = ecc_key(&mut rng, TpmEccCurve::SM2P256);
    let (mut x, mut y) = ([0; MAX_ECC], [0; MAX_ECC]);
    let result = RustCrypto.ecdh(&a, b.public_key(), &mut x, &mut y);
    assert_eq!(result.unwrap_err(), CryptoError::Unsupported);
}
