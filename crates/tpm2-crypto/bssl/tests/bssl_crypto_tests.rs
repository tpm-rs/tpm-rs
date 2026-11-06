#![forbid(unsafe_code)]

use hex_literal::hex;
use tpm2::crypto::backend::{Cmac, Ecc, Hash, Hmac, Mldsa, Mlkem, Rsa, Symmetric};
use tpm2::crypto::backend::{
    CmacState, EccCurve, HashState, HmacState, MldsaKey, MlkemKey, PrivateKey, RsaKey,
    SymmetricState,
};
use tpm2::crypto::{Crypto, CryptoError, Direction, Random, Rng};
use tpm2::{Alg, TpmiAlgHash, TpmtHa};
use tpm2_crypto_bssl::*;

type C = BsslCryptoProvider;
type R = BsslRng;

// =========================================================================
// Random numbers and constant-time comparison
// =========================================================================

#[test]
fn test_random_and_constant_time_eq() {
    let mut rng = C::from_entropy().unwrap();
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    rng.fill_bytes(&mut a).unwrap();
    rng.fill_bytes(&mut b).unwrap();
    assert_ne!(a, [0u8; 32]);
    assert_ne!(a, b);
    assert_eq!(rng.stir_bytes(b"additional entropy"), Ok(()));
    assert!(!rng.is_seeded());
    C::rand_bytes(&mut b).unwrap();
    assert_ne!(a, b);

    assert!(C::ct_eq(&a, &a));
    let mut c = a;
    c[31] ^= 0x80;
    assert!(!C::ct_eq(&a, &c));
    assert!(!C::ct_eq(&a, &a[..31]));
    assert!(C::ct_eq(&[], &[]));
    const { assert!(C::KNOWN_ANSWER_TESTS) };
}

/// The RNG of `from_seed` depends only on the seed and the sequence of calls, including
/// `stir_bytes`.
#[test]
fn test_seeded_rng_is_deterministic() {
    let draw = |seed: &[u8], stir: Option<&[u8]>| {
        let mut rng = C::from_seed(seed).unwrap();
        assert!(rng.is_seeded());
        let mut out = [0u8; 64];
        rng.fill_bytes(&mut out[..32]).unwrap();
        if let Some(data) = stir {
            rng.stir_bytes(data).unwrap();
        }
        rng.fill_bytes(&mut out[32..]).unwrap();
        out
    };
    assert_eq!(draw(b"seed", None), draw(b"seed", None));
    assert_ne!(draw(b"seed", None), draw(b"other", None));
    assert_eq!(draw(b"seed", Some(b"x")), draw(b"seed", Some(b"x")));
    assert_ne!(draw(b"seed", Some(b"x")), draw(b"seed", Some(b"y")));
    assert_eq!(draw(b"seed", Some(b"x"))[..32], draw(b"seed", None)[..32]);
    assert_ne!(draw(b"seed", Some(b"x"))[32..], draw(b"seed", None)[32..]);
}

// =========================================================================
// Hashes, HMAC and CMAC
// =========================================================================

#[test]
fn test_hash_and_hmac_vectors() {
    // FIPS 180-2 SHA-256("abc"), one shot and streaming.
    let expected = hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    let mut out = [0u8; 32];
    <<C as Hash>::Sha256 as HashState<32>>::hash(&[b"a", b"bc"], &mut out).unwrap();
    assert_eq!(out, expected);
    let mut buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = tpm2::crypto::hash::<C>(TpmiAlgHash::Sha256, &[b"abc"], &mut buf).unwrap();
    assert_eq!(digest.digest(), expected);

    let mut sha1 = [0u8; 20];
    <<C as Hash>::Sha1 as HashState<20>>::hash(&[b"abc"], &mut sha1).unwrap();
    assert_eq!(sha1, hex!("a9993e364706816aba3e25717850c26c9cd0d89d"));
    let mut sha384 = [0u8; 48];
    <<C as Hash>::Sha384 as HashState<48>>::hash(&[b"abc"], &mut sha384).unwrap();
    assert_eq!(
        sha384,
        hex!(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
            "8086072ba1e7cc2358baeca134c825a7"
        )
    );
    let mut sha512 = [0u8; 64];
    <<C as Hash>::Sha512 as HashState<64>>::hash(&[b"abc"], &mut sha512).unwrap();
    assert_eq!(
        sha512,
        hex!(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
    );

    // RFC 4231 test case 1 (HMAC-SHA-256) and RFC 2202 test case 1 (HMAC-SHA-1).
    let key = [0x0bu8; 20];
    let mut mac = [0u8; 32];
    <<C as Hmac>::Sha256 as HmacState<32>>::hmac(&key, &[b"Hi ", b"There"], &mut mac).unwrap();
    assert_eq!(
        mac,
        hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );
    let mac = tpm2::crypto::hmac::<C>(TpmiAlgHash::Sha1, &key, &[b"Hi There"], &mut buf).unwrap();
    assert_eq!(
        mac.digest(),
        hex!("b617318655057264e28bc0b6fb378c8ef146be00")
    );

    // SM3 and SHA-3 are not implemented by this backend.
    assert!(matches!(
        <<C as Hash>::Sm3_256 as HashState<32>>::init(),
        Err(CryptoError::Unsupported)
    ));
    assert!(matches!(
        <<C as Hmac>::Sha3_256 as HmacState<32>>::init(&key),
        Err(CryptoError::Unsupported)
    ));
}

#[test]
fn test_hmac_binding_empty_key_and_clone() {
    let mut ctx = tpm2_crypto_bssl::bssl::Hmac::<20>::new_from_slice(&[]).unwrap();
    ctx.update(&[]).unwrap();
    let mut out = [0u8; 20];
    ctx.finalize(&mut out).unwrap();
    assert_eq!(out, hex!("fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"));

    // RFC 2202 Test Case 1, with a clone taken mid-stream.
    let mut ctx = tpm2_crypto_bssl::bssl::Hmac::<20>::new_from_slice(&[0x0b; 20]).unwrap();
    ctx.update(b"Hi ").unwrap();
    let mut clone = ctx.clone();
    ctx.update(b"There").unwrap();
    clone.update(b"There").unwrap();
    let mut out2 = [0u8; 20];
    ctx.finalize(&mut out).unwrap();
    clone.finalize(&mut out2).unwrap();
    assert_eq!(out, hex!("b617318655057264e28bc0b6fb378c8ef146be00"));
    assert_eq!(out2, out);

    assert!(matches!(
        tpm2_crypto_bssl::bssl::Hmac::<16>::new_from_slice(&[]),
        Err(BsslError::Unsupported)
    ));
}

#[test]
fn test_cmac_vectors() {
    // NIST SP 800-38B AES-128-CMAC (empty message), AES-192 and AES-256 (16-byte message).
    let msg = hex!("6bc1bee22e409f96e93d7e117393172a");
    let mut tag = [0u8; 16];
    <<C as Cmac>::Aes128 as CmacState<16>>::cmac(
        &hex!("2b7e151628aed2a6abf7158809cf4f3c"),
        &[],
        &mut tag,
    )
    .unwrap();
    assert_eq!(tag, hex!("bb1d6929e95937287fa37d129b756746"));

    let mut ctx = <<C as Cmac>::Aes192 as CmacState<24>>::init(&hex!(
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    ))
    .unwrap();
    ctx.update(&msg[..5]).unwrap();
    ctx.update(&msg[5..]).unwrap();
    ctx.finalize(&mut tag).unwrap();
    assert_eq!(tag, hex!("9e99a7bf31e710900662f65e617c5184"));

    <<C as Cmac>::Aes256 as CmacState<32>>::cmac(
        &hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914df1a"),
        &[&msg],
        &mut tag,
    )
    .unwrap();
    assert_eq!(tag, hex!("22c2ef5b01082373365b34de01a7de91"));

    // Camellia-CMAC (RustCrypto fallback): streaming equals one shot; SM4 is unsupported.
    let key = [0x42u8; 16];
    let mut one_shot = [0u8; 16];
    <<C as Cmac>::Camellia128 as CmacState<16>>::cmac(&key, &[&msg], &mut one_shot).unwrap();
    type CamelliaCmac = <C as Cmac>::Camellia128;
    let mut ctx = <CamelliaCmac as CmacState<16>>::init(&key).unwrap();
    <CamelliaCmac as CmacState<16>>::update(&mut ctx, &msg[..7]).unwrap();
    <CamelliaCmac as CmacState<16>>::update(&mut ctx, &msg[7..]).unwrap();
    <CamelliaCmac as CmacState<16>>::finalize(&mut ctx, &mut tag).unwrap();
    assert_eq!(tag, one_shot);
    assert_ne!(tag, [0u8; 16]);
    assert!(matches!(
        <<C as Cmac>::Sm4_128 as CmacState<16>>::init(&key),
        Err(CryptoError::Unsupported)
    ));
}

// =========================================================================
// Symmetric ciphers
// =========================================================================

const KEY128: [u8; 16] = hex!("2b7e151628aed2a6abf7158809cf4f3c");
const IV0: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");
const PT: [u8; 32] = hex!(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
);

/// The AES modes match NIST SP 800-38A F.1.1 (ECB), F.2.1 (CBC), F.3.13 (CFB128), F.4.1
/// (OFB) and F.5.1 (CTR), with the TCG reference's chaining values.
#[test]
fn test_aes_modes_nist_vectors_and_chaining_values() {
    let aes = <<C as Symmetric>::Aes128 as SymmetricState<16>>::init(&KEY128).unwrap();

    let mut blocks = [[0u8; 16]; 2];
    blocks.as_flattened_mut().copy_from_slice(&PT);
    aes.ecb(Direction::Encrypt, &mut blocks).unwrap();
    assert_eq!(blocks[0], hex!("3ad77bb40d7a3660a89ecaf32466ef97"));
    assert_eq!(blocks[1], hex!("f5d3d58503b9699de785895a96fdbaaf"));
    aes.ecb(Direction::Decrypt, &mut blocks).unwrap();
    assert_eq!(blocks.as_flattened(), PT);

    let mut iv = IV0;
    aes.cbc(Direction::Encrypt, &mut iv, &mut blocks).unwrap();
    assert_eq!(blocks[0], hex!("7649abac8119b246cee98e9b12e9197d"));
    assert_eq!(blocks[1], hex!("5086cb9b507219ee95db113a917678b2"));
    assert_eq!(iv, blocks[1]);
    let mut iv = IV0;
    aes.cbc(Direction::Decrypt, &mut iv, &mut blocks).unwrap();
    assert_eq!(blocks.as_flattened(), PT);
    assert_eq!(iv, hex!("5086cb9b507219ee95db113a917678b2"));

    let cfb_ct = hex!(
        "3b3fd92eb72dad20333449f8e83cfb4a"
        "c8a64537a0b3a93fcde3cdad9f1ce58b"
    );
    let mut data = PT;
    let mut iv = IV0;
    aes.cfb(Direction::Encrypt, &mut iv, &mut data).unwrap();
    assert_eq!(data, cfb_ct);
    assert_eq!(iv, cfb_ct[16..]);
    let mut iv = IV0;
    aes.cfb(Direction::Decrypt, &mut iv, &mut data).unwrap();
    assert_eq!(data, PT);
    assert_eq!(iv, cfb_ct[16..]);
    // Chaining two calls through the updated IV equals one call.
    let mut iv = IV0;
    let (first, second) = data.split_at_mut(16);
    aes.cfb(Direction::Encrypt, &mut iv, first).unwrap();
    aes.cfb(Direction::Encrypt, &mut iv, second).unwrap();
    assert_eq!(data, cfb_ct);

    let mut data = PT;
    let mut iv = IV0;
    aes.ofb(&mut iv, &mut data).unwrap();
    assert_eq!(
        data,
        hex!(
            "3b3fd92eb72dad20333449f8e83cfb4a"
            "7789508d16918f03f53c52dac54ed825"
        )
    );
    // The chaining value is the last keystream block.
    assert_eq!(iv, hex!("d9a4dada0892239f6b8b3d7680e15674"));

    let mut data = PT;
    let mut iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    aes.ctr(&mut iv, &mut data).unwrap();
    assert_eq!(
        data,
        hex!(
            "874d6191b620e3261bef6864990db6ce"
            "9806f66b7970fdff8617187bb9fffdff"
        )
    );
    // The chaining value is the next counter block.
    assert_eq!(iv, hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdff01"));

    // SM4 is unsupported.
    assert!(matches!(
        <<C as Symmetric>::Sm4_128 as SymmetricState<16>>::init(&KEY128),
        Err(CryptoError::Unsupported)
    ));
}

/// CFB with a partial final block through the dispatch code (`SymmetricKey::crypt`): the
/// chaining value is the partial ciphertext block zero padded, as in the TCG reference.
#[test]
fn test_aes_cfb_partial_block_dispatch() {
    use tpm2::crypto::{CipherInput, SymmetricKey};
    use tpm2::{AlgSym, TpmiAlgCipherMode};

    let key = SymmetricKey::new(AlgSym::Aes128, &KEY128).unwrap();
    let mut data = [0x42u8; 21];
    let mut iv = IV0;
    key.crypt::<C>(
        Direction::Encrypt,
        CipherInput::new(TpmiAlgCipherMode::Cfb, &mut iv, &mut data).unwrap(),
    )
    .unwrap();
    let mut expected_iv = [0u8; 16];
    expected_iv[..5].copy_from_slice(&data[16..]);
    assert_eq!(iv, expected_iv);

    let ct = data;
    let mut iv = IV0;
    key.crypt::<C>(
        Direction::Decrypt,
        CipherInput::new(TpmiAlgCipherMode::Cfb, &mut iv, &mut data).unwrap(),
    )
    .unwrap();
    assert_eq!(data, [0x42u8; 21]);
    assert_eq!(iv, expected_iv);

    // One block at a time gives the same ciphertext.
    let aes = <<C as Symmetric>::Aes128 as SymmetricState<16>>::init(&KEY128).unwrap();
    let mut chunks = [0x42u8; 21];
    let mut iv = IV0;
    let (first, second) = chunks.split_at_mut(16);
    aes.cfb(Direction::Encrypt, &mut iv, first).unwrap();
    aes.cfb(Direction::Encrypt, &mut iv, second).unwrap();
    assert_eq!(chunks, ct);
}

#[test]
fn test_aes192_aes256_and_camellia() {
    // NIST SP 800-38A F.3.15 / F.3.17 (CFB128-AES192/256, first block).
    let mut block = hex!("6bc1bee22e409f96e93d7e117393172a");
    let mut iv = IV0;
    <<C as Symmetric>::Aes192 as SymmetricState<24>>::init(&hex!(
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    ))
    .unwrap()
    .cfb(Direction::Encrypt, &mut iv, &mut block)
    .unwrap();
    assert_eq!(block, hex!("cdc80d6fddf18cab34c25909c99a4174"));
    let mut block = hex!("6bc1bee22e409f96e93d7e117393172a");
    let mut iv = IV0;
    <<C as Symmetric>::Aes256 as SymmetricState<32>>::init(&hex!(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914df1a"
    ))
    .unwrap()
    .cfb(Direction::Encrypt, &mut iv, &mut block)
    .unwrap();
    assert_eq!(block, hex!("b5a8a1747ed889ebce581f4ea2a5646e"));

    // Camellia-128 (RustCrypto fallback), RFC 3713 test vector, and a CBC round trip.
    type Camellia = <C as Symmetric>::Camellia128;
    let camellia =
        <Camellia as SymmetricState<16>>::init(&hex!("0123456789abcdeffedcba9876543210")).unwrap();
    let mut blocks = [hex!("0123456789abcdeffedcba9876543210")];
    <Camellia as SymmetricState<16>>::ecb(&camellia, Direction::Encrypt, &mut blocks).unwrap();
    assert_eq!(blocks[0], hex!("67673138549669730857065648eabe43"));
    let mut iv = IV0;
    <Camellia as SymmetricState<16>>::cbc(&camellia, Direction::Encrypt, &mut iv, &mut blocks)
        .unwrap();
    let mut iv = IV0;
    <Camellia as SymmetricState<16>>::cbc(&camellia, Direction::Decrypt, &mut iv, &mut blocks)
        .unwrap();
    assert_eq!(blocks[0], hex!("67673138549669730857065648eabe43"));
}

// =========================================================================
// RSA
// =========================================================================

type Rsa1024 = <C as Rsa>::Rsa1024;
type Rsa1024Public = <Rsa1024 as PrivateKey<128, 64, R, u32>>::PublicKey;

fn sha256(digest: &[u8; 32]) -> TpmtHa<'_> {
    TpmtHa::new(TpmiAlgHash::Sha256, digest).unwrap()
}

fn load_public_1024(key: &Rsa1024, exponent: u32) -> Rsa1024Public {
    let mut n = [0u8; 128];
    Rsa1024::store_public(key.as_public(), &mut n).unwrap();
    Rsa1024::load_public(exponent, &n).unwrap().unwrap()
}

#[test]
fn test_rsa_schemes_round_trip() {
    let mut rng = C::from_entropy().unwrap();
    let key = Rsa1024::generate(&mut rng, 65537).unwrap();
    let public = key.as_public();
    assert_eq!(Rsa1024::exponent(public), 65537);
    let digest = [0x11u8; 32];
    let mut sig = [0u8; 128];

    // RSASSA-PKCS1-v1_5
    key.rsassa_sign(&mut rng, sha256(&digest), &mut sig)
        .unwrap();
    assert_eq!(
        Rsa1024::rsassa_verify(public, sha256(&digest), &sig),
        Ok(true)
    );
    assert_eq!(
        Rsa1024::rsassa_verify(public, sha256(&[0x12; 32]), &sig),
        Ok(false)
    );

    // RSASSA-PSS, also with SHA-512 on a 1024-bit key (salt shortened to 62 bytes).
    key.rsapss_sign(&mut rng, sha256(&digest), &mut sig)
        .unwrap();
    assert_eq!(
        Rsa1024::rsapss_verify(public, sha256(&digest), &sig),
        Ok(true)
    );
    sig[0] ^= 0x01;
    assert_eq!(
        Rsa1024::rsapss_verify(public, sha256(&digest), &sig),
        Ok(false)
    );
    if let Ok(sha512) = TpmiAlgHash::try_from(Alg::SHA512) {
        let digest = [0x22u8; 64];
        let digest = TpmtHa::new(sha512, &digest).unwrap();
        key.rsapss_sign(&mut rng, digest, &mut sig).unwrap();
        assert_eq!(Rsa1024::rsapss_verify(public, digest, &sig), Ok(true));
    }

    // RSAES-PKCS1-v1_5
    let msg = b"Hello RSAES!";
    let mut ct = [0u8; 128];
    let mut pt = [0u8; 128];
    Rsa1024::rsaes_encrypt(public, &mut rng, msg, &mut ct)
        .unwrap()
        .unwrap();
    let len = key.rsaes_decrypt(&mut rng, &ct, &mut pt).unwrap().unwrap();
    assert_eq!(&pt[..len], msg);
    assert_eq!(
        Rsa1024::rsaes_encrypt(public, &mut rng, &[0x42; 118], &mut ct),
        Ok(None)
    );

    // RSAES-OAEP with a label (including its terminating zero), a wrong label and a
    // corrupted ciphertext.
    Rsa1024::oaep_encrypt(
        public,
        &mut rng,
        TpmiAlgHash::Sha256,
        b"DUPLICATE\0",
        msg,
        &mut ct,
    )
    .unwrap()
    .unwrap();
    let len = key
        .oaep_decrypt(&mut rng, TpmiAlgHash::Sha256, b"DUPLICATE\0", &ct, &mut pt)
        .unwrap()
        .unwrap();
    assert_eq!(&pt[..len], msg);
    assert_eq!(
        key.oaep_decrypt(&mut rng, TpmiAlgHash::Sha256, b"OTHER\0", &ct, &mut pt),
        Ok(None)
    );
    let mut bad_ct = ct;
    bad_ct[5] ^= 0x01;
    assert_eq!(
        key.oaep_decrypt(
            &mut rng,
            TpmiAlgHash::Sha256,
            b"DUPLICATE\0",
            &bad_ct,
            &mut pt
        ),
        Ok(None)
    );
    assert_eq!(
        Rsa1024::oaep_encrypt(
            public,
            &mut rng,
            TpmiAlgHash::Sha256,
            &[],
            &[0x42; 63],
            &mut ct
        ),
        Ok(None)
    );

    // Raw RSA (`TPM_ALG_NULL`), which requires `m < n` and `c < n`.
    let mut m = [0u8; 128];
    m[96..].fill(0x01);
    Rsa1024::raw_encrypt(public, &m, &mut ct).unwrap().unwrap();
    key.raw_decrypt(&mut rng, &ct, &mut pt).unwrap().unwrap();
    assert_eq!(pt, m);
    assert_eq!(
        Rsa1024::raw_encrypt(public, &[0xFF; 128], &mut ct),
        Ok(None)
    );
    assert_eq!(key.raw_decrypt(&mut rng, &[0xFF; 128], &mut pt), Ok(None));
}

/// A key loads back from either prime, its CRT form matches the key, and invalid primes and
/// moduli are rejected with `Ok(None)`.
#[test]
fn test_rsa_load_store_and_crt() {
    let mut rng = C::from_entropy().unwrap();
    let key = Rsa1024::generate(&mut rng, 65537).unwrap();
    let mut prime = [0u8; 64];
    key.store(&mut prime).unwrap();
    let mut crt = [[0u8; 64]; 5];
    key.store_crt(&mut crt).unwrap();
    assert!(crt[0] > crt[1], "p is the larger prime");
    assert!(prime == crt[0] || prime == crt[1]);

    let digest = [0x33u8; 32];
    let mut sig = [0u8; 128];
    for p in [crt[0], crt[1]] {
        let loaded = Rsa1024::load(load_public_1024(&key, 65537), &p)
            .unwrap()
            .unwrap();
        let mut stored = [0u8; 64];
        loaded.store(&mut stored).unwrap();
        assert_eq!(stored, p);
        let mut loaded_crt = [[0u8; 64]; 5];
        loaded.store_crt(&mut loaded_crt).unwrap();
        assert_eq!(loaded_crt, crt);
        loaded
            .rsassa_sign(&mut rng, sha256(&digest), &mut sig)
            .unwrap();
        assert_eq!(
            Rsa1024::rsassa_verify(key.as_public(), sha256(&digest), &sig),
            Ok(true)
        );
    }

    let mut not_a_factor = crt[0];
    not_a_factor[63] ^= 0x02;
    assert!(matches!(
        Rsa1024::load(load_public_1024(&key, 65537), &not_a_factor),
        Ok(None)
    ));
    let mut tiny = [0u8; 64];
    tiny[63] = 3;
    assert!(matches!(
        Rsa1024::load(load_public_1024(&key, 65537), &tiny),
        Ok(None)
    ));

    // Moduli without the top bit or odd parity are invalid (TPM 2.0 Part 1).
    let mut n = [0u8; 128];
    Rsa1024::store_public(key.as_public(), &mut n).unwrap();
    let mut even = n;
    even[127] &= 0xFE;
    assert!(matches!(Rsa1024::load_public(65537, &even), Ok(None)));
    let mut short = n;
    short[0] &= 0x7F;
    assert!(matches!(Rsa1024::load_public(65537, &short), Ok(None)));
}

/// Keys from the RNG of `from_seed` are deterministic; other exponents work.
#[test]
fn test_rsa_seeded_generation_and_exponents() {
    let generate = |seed: &[u8], exponent: u32| {
        let mut rng = C::from_seed(seed).unwrap();
        let key = Rsa1024::generate(&mut rng, exponent).unwrap();
        let mut n = [0u8; 128];
        Rsa1024::store_public(key.as_public(), &mut n).unwrap();
        let mut p = [0u8; 64];
        key.store(&mut p).unwrap();
        (n, p)
    };
    let (n, p) = generate(b"test_seed", 65537);
    assert_eq!(generate(b"test_seed", 65537), (n, p));
    assert_ne!(generate(b"other_seed", 65537).0, n);
    assert_ne!(generate(b"test_seed", 3).0, n);

    // Raw RSA under exponent 3 of `m` with `m^3 < n` is exactly `m^3`.
    let mut rng = C::from_seed(b"e3").unwrap();
    let key = Rsa1024::generate(&mut rng, 3).unwrap();
    assert_eq!(Rsa1024::exponent(key.as_public()), 3);
    let mut m = [0u8; 128];
    m[126] = 0x01; // 2^8
    let mut ct = [0u8; 128];
    Rsa1024::raw_encrypt(key.as_public(), &m, &mut ct)
        .unwrap()
        .unwrap();
    let mut cubed = [0u8; 128];
    cubed[124] = 0x01; // 2^24
    assert_eq!(ct, cubed);

    // Even exponents and exponents below 3 are unsupported for generation.
    assert!(matches!(
        Rsa1024::generate(&mut rng, 4),
        Err(CryptoError::Unsupported)
    ));
}

#[test]
fn test_rsa_2048_and_dispatch() {
    use tpm2::crypto::{RsaEncryptScheme, RsaPrivateKey};
    use tpm2::{TpmiRsaKeyBits, TpmtSigScheme};

    let mut rng = C::from_entropy().unwrap();
    let key = RsaPrivateKey::<C>::generate(&mut rng, TpmiRsaKeyBits::Rsa2048, 0).unwrap();
    assert_eq!(key.exponent(), 65537);
    let digest = [0x44u8; 32];
    let mut sig_buf = [0u8; size_of::<tpm2::crypto::SignatureBuffer>()];
    let sig = key
        .sign(
            &mut rng,
            TpmtSigScheme::Rsapss(TpmiAlgHash::Sha256),
            &digest,
            &mut sig_buf,
        )
        .unwrap();
    let mut modulus = [0u8; 256];
    let n = key.modulus(&mut modulus).unwrap();
    let public = tpm2::crypto::RsaPublicKey::<C>::load(TpmiRsaKeyBits::Rsa2048, 0, n)
        .unwrap()
        .unwrap();
    assert_eq!(public.verify(&digest, sig), Ok(true));

    let mut ct_buf = [0u8; 256];
    let ct = public
        .encrypt(&mut rng, RsaEncryptScheme::Rsaes, b"secret", &mut ct_buf)
        .unwrap()
        .unwrap();
    let mut pt_buf = [0u8; 256];
    let pt = key
        .decrypt(&mut rng, RsaEncryptScheme::Rsaes, ct.as_ref(), &mut pt_buf)
        .unwrap()
        .unwrap();
    assert_eq!(pt.as_ref(), b"secret");
}

#[test]
fn test_rsa_3072_4096_generation() {
    let mut rng = C::from_entropy().unwrap();
    let digest = [0x55u8; 32];
    let key = <C as Rsa>::Rsa3072::generate(&mut rng, 65537).unwrap();
    let mut sig = [0u8; 384];
    key.rsassa_sign(&mut rng, sha256(&digest), &mut sig)
        .unwrap();
    assert_eq!(
        <C as Rsa>::Rsa3072::rsassa_verify(key.as_public(), sha256(&digest), &sig),
        Ok(true)
    );
    let mut crt = [[0u8; 192]; 5];
    key.store_crt(&mut crt).unwrap();

    let key = <C as Rsa>::Rsa4096::generate(&mut rng, 65537).unwrap();
    let mut sig = [0u8; 512];
    key.rsapss_sign(&mut rng, sha256(&digest), &mut sig)
        .unwrap();
    assert_eq!(
        <C as Rsa>::Rsa4096::rsapss_verify(key.as_public(), sha256(&digest), &sig),
        Ok(true)
    );
}

// =========================================================================
// ECC
// =========================================================================

/// Key generation, loading, point multiplications, ECDH and ECDSA on a curve.
fn check_curve<K, const COORD: usize, const POINT: usize>(ecdsa: bool)
where
    K: EccCurve<COORD, POINT, R>,
{
    let mut rng = C::from_entropy().unwrap();
    let alice = K::generate(&mut rng, ()).unwrap();
    let bob = K::generate(&mut rng, ()).unwrap();

    // The public key is [d]G and loads back.
    let mut d = [0u8; COORD];
    alice.store(&mut d).unwrap();
    let mut point = [0u8; POINT];
    K::store_public(alice.as_public(), &mut point).unwrap();
    let (mut x, mut y) = ([0u8; COORD], [0u8; COORD]);
    assert_eq!(K::mul_generator(&d, &mut x, &mut y), Ok(Some(())));
    assert_eq!((&x[..], &y[..]), (&point[..COORD], &point[COORD..]));
    let public = K::load_public((), &point).unwrap().unwrap();
    let alice2 = K::load(public, &d).unwrap().unwrap();

    // A scalar that does not match the public key, an off-curve point, and invalid scalars.
    let mut other_d = [0u8; COORD];
    bob.store(&mut other_d).unwrap();
    let public = K::load_public((), &point).unwrap().unwrap();
    assert!(matches!(K::load(public, &other_d), Ok(None)));
    let mut off_curve = point;
    off_curve[POINT - 1] ^= 0x01;
    assert!(matches!(K::load_public((), &off_curve), Ok(None)));
    assert!(matches!(K::load_public((), &[0u8; POINT]), Ok(None)));
    assert_eq!(K::mul_generator(&[0u8; COORD], &mut x, &mut y), Ok(None));
    assert_eq!(K::mul_generator(&[0xFFu8; COORD], &mut x, &mut y), Ok(None));

    // [1]P = P and [2]G = [2]P for P = G.
    let mut one = [0u8; COORD];
    one[COORD - 1] = 1;
    assert_eq!(
        K::mul_point(alice.as_public(), &one, &mut x, &mut y),
        Ok(Some(()))
    );
    assert_eq!((&x[..], &y[..]), (&point[..COORD], &point[COORD..]));
    let (mut gx, mut gy) = ([0u8; COORD], [0u8; COORD]);
    K::mul_generator(&one, &mut gx, &mut gy).unwrap().unwrap();
    let mut g = [0u8; POINT];
    g[..COORD].copy_from_slice(&gx);
    g[COORD..].copy_from_slice(&gy);
    let g = K::load_public((), &g).unwrap().unwrap();
    let mut two = [0u8; COORD];
    two[COORD - 1] = 2;
    let (mut ax, mut ay) = ([0u8; COORD], [0u8; COORD]);
    K::mul_generator(&two, &mut ax, &mut ay).unwrap().unwrap();
    K::mul_point(&g, &two, &mut x, &mut y).unwrap().unwrap();
    assert_eq!((x, y), (ax, ay));

    // ECDH is symmetric.
    let (mut zx1, mut zy1) = ([0u8; COORD], [0u8; COORD]);
    let (mut zx2, mut zy2) = ([0u8; COORD], [0u8; COORD]);
    alice2
        .ecdh(bob.as_public(), &mut zx1, &mut zy1)
        .unwrap()
        .unwrap();
    bob.ecdh(alice.as_public(), &mut zx2, &mut zy2)
        .unwrap()
        .unwrap();
    assert_eq!((zx1, zy1), (zx2, zy2));

    // ECDSA with digests shorter and longer than the scalars.
    if ecdsa {
        for digest in [&[0x5Au8; 20][..], &[0x6B; 32], &[0x7C; 64]] {
            let (mut r, mut s) = ([0u8; COORD], [0u8; COORD]);
            alice.sign(&mut rng, digest, &mut r, &mut s).unwrap();
            assert_eq!(K::verify(alice.as_public(), digest, &r, &s), Ok(true));
            assert_eq!(K::verify(bob.as_public(), digest, &r, &s), Ok(false));
            let mut bad_s = s;
            bad_s[COORD - 1] ^= 0x01;
            assert_eq!(K::verify(alice.as_public(), digest, &r, &bad_s), Ok(false));
            assert_eq!(
                K::verify(alice.as_public(), digest, &[0u8; COORD], &s),
                Ok(false)
            );
        }
    }

    // Keys from the RNG of `from_seed` are deterministic.
    let seeded = |seed: &[u8]| {
        let key = K::generate(&mut C::from_seed(seed).unwrap(), ()).unwrap();
        let mut point = [0u8; POINT];
        K::store_public(key.as_public(), &mut point).unwrap();
        point
    };
    assert_eq!(seeded(b"seed"), seeded(b"seed"));
    assert_ne!(seeded(b"seed"), seeded(b"other"));
}

#[test]
fn test_ecc_bssl_curves() {
    check_curve::<<C as Ecc>::NistP224, 28, 56>(true);
    check_curve::<<C as Ecc>::NistP256, 32, 64>(true);
    check_curve::<<C as Ecc>::NistP384, 48, 96>(true);
    check_curve::<<C as Ecc>::NistP521, 66, 132>(true);
    check_curve::<<C as Ecc>::BNP256, 32, 64>(true);
}

#[test]
fn test_ecc_weierstrass_curves() {
    check_curve::<<C as Ecc>::NistP192, 24, 48>(true);
    check_curve::<<C as Ecc>::BNP638, 80, 160>(true);
    check_curve::<<C as Ecc>::SM2P256, 32, 64>(true);
}

#[test]
fn test_ecc_unsupported_curves() {
    let mut rng = C::from_entropy().unwrap();
    assert!(matches!(
        <<C as Ecc>::BpP256R1 as PrivateKey<64, 32, R>>::generate(&mut rng, ()),
        Err(CryptoError::Unsupported)
    ));
    assert!(matches!(
        <<C as Ecc>::Ed25519 as PrivateKey<32, 32, R>>::load_public((), &[0; 32]),
        Err(CryptoError::Unsupported)
    ));
}

#[test]
fn test_ecc_dispatch() {
    use tpm2::TpmEccCurve;
    use tpm2::crypto::{EccPrivateKey, ecc_mul_generator};

    let (mut x, mut y) = ([0u8; 66], [0u8; 66]);
    let g = ecc_mul_generator::<C>(TpmEccCurve::NistP256, &[1], &mut x, &mut y)
        .unwrap()
        .unwrap();
    assert_eq!(g.x.as_ref().len(), 32);
    let key = EccPrivateKey::<C>::from_scalar(TpmEccCurve::NistP256, &[1])
        .unwrap()
        .unwrap();
    let (mut px, mut py) = ([0u8; 66], [0u8; 66]);
    let point = key.point(&mut px, &mut py).unwrap();
    assert_eq!(point.x, g.x);
    assert_eq!(point.y, g.y);
}

// =========================================================================
// ML-KEM and ML-DSA
// =========================================================================

fn check_mlkem<K, const PUB: usize, const CT: usize>()
where
    K: MlkemKey<PUB, CT, R>,
{
    let mut rng = C::from_entropy().unwrap();
    let key = K::generate(&mut rng, ()).unwrap();
    let mut public = [0u8; PUB];
    K::store_public(key.as_public(), &mut public).unwrap();

    // Encapsulation (random and derandomized) and decapsulation agree.
    let (mut ct, mut ss, mut ss2) = ([0u8; CT], [0u8; 32], [0u8; 32]);
    K::encapsulate(key.as_public(), &mut rng, &mut ct, &mut ss).unwrap();
    key.decapsulate(&ct, &mut ss2).unwrap();
    assert_eq!(ss, ss2);
    let mut ct2 = [0u8; CT];
    K::encapsulate_internal(key.as_public(), &[7; 32], &mut ct, &mut ss).unwrap();
    K::encapsulate_internal(key.as_public(), &[7; 32], &mut ct2, &mut ss2).unwrap();
    assert_eq!((ct, ss), (ct2, ss2));
    key.decapsulate(&ct, &mut ss2).unwrap();
    assert_eq!(ss, ss2);
    // Implicit rejection: a corrupted ciphertext gives another shared secret.
    ct[0] ^= 0x01;
    key.decapsulate(&ct, &mut ss2).unwrap();
    assert_ne!(ss, ss2);

    // The seed expands to the same key, which loads with its public key only.
    let mut seed = [0u8; 64];
    key.store(&mut seed).unwrap();
    let expanded = K::expand(&seed).unwrap();
    let mut public2 = [0u8; PUB];
    K::store_public(expanded.as_public(), &mut public2).unwrap();
    assert_eq!(public, public2);
    let loaded = K::load(K::load_public((), &public).unwrap().unwrap(), &seed).unwrap();
    assert!(loaded.is_some());
    let other = K::generate(&mut rng, ()).unwrap();
    let mut other_seed = [0u8; 64];
    other.store(&mut other_seed).unwrap();
    assert!(matches!(
        K::load(K::load_public((), &public).unwrap().unwrap(), &other_seed),
        Ok(None)
    ));

    // The FIPS 203 modulus check: a coefficient of 0xFFF >= q is rejected.
    let mut bad = public;
    bad[0] = 0xFF;
    bad[1] |= 0x0F;
    assert!(matches!(K::load_public((), &bad), Ok(None)));
}

#[test]
fn test_mlkem() {
    check_mlkem::<<C as Mlkem>::Mlkem512, 800, 768>();
    check_mlkem::<<C as Mlkem>::Mlkem768, 1184, 1088>();
    check_mlkem::<<C as Mlkem>::Mlkem1024, 1568, 1568>();
}

fn check_mldsa<K, const PUB: usize, const SIG: usize>()
where
    K: MldsaKey<PUB, SIG, R>,
{
    let mut rng = C::from_entropy().unwrap();
    let key = K::generate(&mut rng, ()).unwrap();
    let other = K::generate(&mut rng, ()).unwrap();
    let mut sig = [0u8; SIG];

    // External mu, with explicit and random signing randomness.
    let mu = [0x42u8; 64];
    key.sign_mu_internal(&[1; 32], &mu, &mut sig).unwrap();
    let mut sig2 = [0u8; SIG];
    key.sign_mu_internal(&[1; 32], &mu, &mut sig2).unwrap();
    assert_eq!(sig, sig2);
    assert_eq!(K::verify_mu(key.as_public(), &mu, &sig), Ok(true));
    assert_eq!(K::verify_mu(other.as_public(), &mu, &sig), Ok(false));
    key.sign_mu(&mut rng, &mu, &mut sig).unwrap();
    assert_eq!(K::verify_mu(key.as_public(), &mu, &sig), Ok(true));
    assert_eq!(K::verify_mu(key.as_public(), &[0x43; 64], &sig), Ok(false));

    // Pure ML-DSA with a context string.
    key.sign_message(&mut rng, b"ctx", &[b"hello ", b"world"], &mut sig)
        .unwrap();
    assert_eq!(
        K::verify_message(key.as_public(), b"ctx", &[b"hello world"], &sig),
        Ok(true)
    );
    assert_eq!(
        K::verify_message(key.as_public(), b"", &[b"hello world"], &sig),
        Ok(false)
    );

    // HashML-DSA (RustCrypto fallback).
    let digest = [0x24u8; 32];
    key.sign_prehash(&mut rng, b"", sha256(&digest), &mut sig)
        .unwrap();
    assert_eq!(
        K::verify_prehash(key.as_public(), b"", sha256(&digest), &sig),
        Ok(true)
    );
    assert_eq!(
        K::verify_prehash(key.as_public(), b"", sha256(&[0x25; 32]), &sig),
        Ok(false)
    );

    // The seed expands to the same key, which loads with its public key only.
    let mut seed = [0u8; 32];
    key.store(&mut seed).unwrap();
    let mut public = [0u8; PUB];
    K::store_public(key.as_public(), &mut public).unwrap();
    let mut public2 = [0u8; PUB];
    K::store_public(K::expand(&seed).unwrap().as_public(), &mut public2).unwrap();
    assert_eq!(public, public2);
    assert!(
        K::load(K::load_public((), &public).unwrap().unwrap(), &seed)
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        K::load(K::load_public((), &public).unwrap().unwrap(), &[0; 32]),
        Ok(None)
    ));
}

#[test]
fn test_mldsa() {
    check_mldsa::<<C as Mldsa>::Mldsa44, 1312, 2420>();
    check_mldsa::<<C as Mldsa>::Mldsa65, 1952, 3309>();
    check_mldsa::<<C as Mldsa>::Mldsa87, 2592, 4627>();
}
