use hex_literal::hex;
use tpm2::crypto::backend::{Cmac, CmacState};
use tpm2::crypto::{
    CipherInput, Crypto, CryptoError, Direction, EccPrivateKey, EccPublicKey, HashContext,
    HmacContext, MAX_ECC_COORD_BYTES, MAX_SIGNATURE_BYTES, Random, Rng, RsaEncryptScheme,
    RsaPrivateKey, RsaPublicKey, SymmetricKey,
};
use tpm2::{
    AlgSym, Tpm2bEccParameter, Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmEccCurve,
    TpmiAlgCipherMode, TpmiAlgHash, TpmiRsaKeyBits, TpmsEccPoint, TpmsSignatureEcc,
    TpmsSignatureRsa, TpmtHa, TpmtSigScheme, TpmtSignature,
};
use tpm2_crypto_tests::TestProvider;

type C = TestProvider;

/// Every hash algorithm of the TPM profile (SHA-512 only with the `sha512` feature).
const PROFILE_HASHES: &[TpmiAlgHash] = &[
    TpmiAlgHash::Sha1,
    TpmiAlgHash::Sha256,
    TpmiAlgHash::Sha384,
    #[cfg(feature = "sha512")]
    TpmiAlgHash::Sha512,
];

/// Returns a fresh RNG of the backend, seeded from its entropy source.
fn entropy_rng() -> <C as Random>::Rng {
    C::from_entropy().unwrap()
}

/// Generates an RSA key of `bits` with the default exponent (65537).
fn rsa_generate(bits: TpmiRsaKeyBits) -> RsaPrivateKey<C> {
    RsaPrivateKey::<C>::generate(&mut entropy_rng(), bits, 0).unwrap()
}

/// Returns the big-endian modulus of `key`.
fn rsa_modulus(key: &RsaPrivateKey<C>) -> Vec<u8> {
    let mut buf = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    key.modulus(&mut buf).unwrap().as_slice().to_vec()
}

/// Returns the (validated) public key of `key`.
fn rsa_public(key: &RsaPrivateKey<C>) -> RsaPublicKey<C> {
    let modulus = rsa_modulus(key);
    RsaPublicKey::<C>::load(
        key.bits(),
        key.exponent(),
        Tpm2bPublicKeyRsa::new(&modulus).unwrap(),
    )
    .unwrap()
    .unwrap()
}

/// Returns the public key of `key` as an `rsa` crate key, for independent checks.
fn rsa_crate_public(key: &RsaPrivateKey<C>) -> rsa::RsaPublicKey {
    rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&rsa_modulus(key)),
        rsa::BigUint::from(key.exponent()),
    )
    .unwrap()
}

/// Returns the secret prime `p` that `key` stores.
fn rsa_prime(key: &RsaPrivateKey<C>) -> Vec<u8> {
    let mut buf = [0u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES];
    key.prime_p(&mut buf).unwrap().as_slice().to_vec()
}

/// Loads the RSA private key with modulus `modulus`, exponent `exponent` and prime `prime`:
/// `None` if the modulus is not a valid public key or `prime` does not factor it.
fn rsa_load(
    bits: TpmiRsaKeyBits,
    modulus: &[u8],
    prime: &[u8],
    exponent: u32,
) -> Option<RsaPrivateKey<C>> {
    let public = RsaPublicKey::<C>::load(bits, exponent, Tpm2bPublicKeyRsa::new(modulus).unwrap())
        .unwrap()?;
    RsaPrivateKey::<C>::load(public, Tpm2bPrivateKeyRsa::new(prime).unwrap()).unwrap()
}

/// Returns `m^e mod n` as a big-endian integer left-padded to the modulus size.
fn rsa_raw_encrypt(key: &RsaPrivateKey<C>, m: u32) -> Vec<u8> {
    let n = rsa::BigUint::from_bytes_be(&rsa_modulus(key));
    let c = rsa::BigUint::from(m)
        .modpow(&rsa::BigUint::from(key.exponent()), &n)
        .to_bytes_be();
    let mut out = vec![0u8; usize::from(key.bits().as_u16() / 8)];
    let start = out.len() - c.len();
    out[start..].copy_from_slice(&c);
    out
}

/// Generates a NIST P-256 key.
fn p256_generate() -> EccPrivateKey<C> {
    EccPrivateKey::<C>::generate(&mut entropy_rng(), TpmEccCurve::NistP256, None).unwrap()
}

/// Returns the (validated) public key of `key`.
fn ecc_public(key: &EccPrivateKey<C>) -> EccPublicKey<C> {
    let (mut x, mut y) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    let point = key.point(&mut x, &mut y).unwrap();
    EccPublicKey::<C>::load(key.curve(), None, point)
        .unwrap()
        .unwrap()
}

/// Returns the secret scalar of `key`.
fn ecc_scalar(key: &EccPrivateKey<C>) -> Vec<u8> {
    let mut buf = [0u8; MAX_ECC_COORD_BYTES];
    key.scalar(&mut buf).unwrap().as_slice().to_vec()
}

/// Returns `x || y` of `[k]P` for the public key `p` (`k` the scalar of `key`), asserting that
/// it is not the point at infinity.
fn ecc_mul_point(p: &EccPublicKey<C>, key: &EccPrivateKey<C>) -> Vec<u8> {
    let (mut x, mut y) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    let q = p
        .mul_point(&ecc_scalar(key), &mut x, &mut y)
        .unwrap()
        .unwrap();
    assert_eq!(q.x.as_slice().len(), 32);
    assert_eq!(q.y.as_slice().len(), 32);
    [q.x.as_slice(), q.y.as_slice()].concat()
}

/// Encrypts or decrypts `data` in place with `key` in CFB mode, updating `iv`.
fn cfb(key: SymmetricKey<'_>, dir: Direction, iv: &mut [u8; 16], data: &mut [u8]) {
    key.crypt::<C>(dir, CipherInput::Cfb(iv, data)).unwrap();
}

/// Returns the one-shot digest of `data` with `alg`.
fn hash_of(alg: TpmiAlgHash, data: &[u8]) -> Vec<u8> {
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    tpm2::crypto::hash::<C>(alg, &[data], &mut out)
        .unwrap()
        .digest()
        .to_vec()
}

/// Returns the one-shot HMAC of `data` with `alg` and `key`.
fn hmac_of(alg: TpmiAlgHash, key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    tpm2::crypto::hmac::<C>(alg, key, &[data], &mut out)
        .unwrap()
        .digest()
        .to_vec()
}

// ==========================================
// FEATURE 1: Hash (SHA-1, SHA-256, SHA-384, SHA-512)
// ==========================================

#[test]
fn test_sha1_kat() {
    // Empty input
    assert_eq!(
        hash_of(TpmiAlgHash::Sha1, b""),
        hex!("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    );

    // Standard vector "abc"
    assert_eq!(
        hash_of(TpmiAlgHash::Sha1, b"abc"),
        hex!("a9993e364706816aba3e25717850c26c9cd0d89d")
    );
}

#[test]
fn test_sha256_kat() {
    // Empty input
    assert_eq!(
        hash_of(TpmiAlgHash::Sha256, b""),
        hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );

    // Standard vector "abc"
    assert_eq!(
        hash_of(TpmiAlgHash::Sha256, b"abc"),
        hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[test]
fn test_sha384_kat() {
    // Empty input
    assert_eq!(
        hash_of(TpmiAlgHash::Sha384, b""),
        hex!(
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        )
    );

    // Standard vector "abc"
    assert_eq!(
        hash_of(TpmiAlgHash::Sha384, b"abc"),
        hex!(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        )
    );
}

#[cfg(feature = "sha512")]
#[test]
fn test_sha512_kat() {
    // Empty input
    assert_eq!(
        hash_of(TpmiAlgHash::Sha512, b""),
        hex!(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        )
    );

    // Standard vector "abc"
    assert_eq!(
        hash_of(TpmiAlgHash::Sha512, b"abc"),
        hex!(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
    );
}

#[test]
fn test_hash_incremental() {
    // Incremental hashing of "abcdefghijklmnopqrstuvwxyz"
    let mut state = HashContext::<C>::new(TpmiAlgHash::Sha256).unwrap();
    state.update(b"abcdefg").unwrap();
    state.update(b"hijklmnop").unwrap();
    state.update(b"qrstuvwxyz").unwrap();
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = state.finalize(&mut out).unwrap();

    let expected = hash_of(TpmiAlgHash::Sha256, b"abcdefghijklmnopqrstuvwxyz");
    assert_eq!(digest.digest(), &expected[..]);

    // The one-shot function hashes the concatenation of its inputs.
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = tpm2::crypto::hash::<C>(
        TpmiAlgHash::Sha256,
        &[b"abcdefg", b"", b"hijklmnop", b"qrstuvwxyz"],
        &mut out,
    )
    .unwrap();
    assert_eq!(digest.digest(), &expected[..]);
}

#[test]
fn test_hash_large_buffer() {
    let mut large_buf = [0u8; 64 * 1024];
    // Fill with dummy deterministic pattern
    for (i, val) in large_buf.iter_mut().enumerate() {
        *val = (i % 251) as u8;
    }

    let digest = hash_of(TpmiAlgHash::Sha256, &large_buf);

    // Verify against standard implementation
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(large_buf);
    let expected_hash = hasher.finalize();
    assert_eq!(digest, &expected_hash[..]);
}

/// The output buffer must hold the digest (exp: `HashStream::finalize` into a fixed-size array).
#[test]
fn test_hash_output_buffer_too_small() {
    let mut out = [0u8; 31];
    assert_eq!(
        tpm2::crypto::hash::<C>(TpmiAlgHash::Sha256, &[b"abc"], &mut out),
        Err(CryptoError::Internal)
    );
    let ctx = HashContext::<C>::new(TpmiAlgHash::Sha256).unwrap();
    assert_eq!(ctx.finalize(&mut out), Err(CryptoError::Internal));
}

// ==========================================
// FEATURE 2: Hmac (HMAC-SHA1, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512)
// ==========================================

#[test]
fn test_hmac_sha1_kat() {
    // RFC 2202 Case 1
    let key = [0x0b; 20];
    let data = b"Hi There";
    let expected = hex!("b617318655057264e28bc0b6fb378c8ef146be00");

    assert_eq!(hmac_of(TpmiAlgHash::Sha1, &key, data), expected);
}

#[test]
fn test_hmac_sha256_kat() {
    // RFC 4231 Case 1
    let key = [0x0b; 20];
    let data = b"Hi There";
    let expected = hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    assert_eq!(hmac_of(TpmiAlgHash::Sha256, &key, data), expected);
}

#[test]
fn test_hmac_sha384_kat() {
    // RFC 4231 Case 1
    let key = [0x0b; 20];
    let data = b"Hi There";
    let expected = hex!(
        "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"
    );

    assert_eq!(hmac_of(TpmiAlgHash::Sha384, &key, data), expected);
}

#[cfg(feature = "sha512")]
#[test]
fn test_hmac_sha512_kat() {
    // RFC 4231 Case 1
    let key = [0x0b; 20];
    let data = b"Hi There";
    let expected = hex!(
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
    );

    assert_eq!(hmac_of(TpmiAlgHash::Sha512, &key, data), expected);
}

#[test]
fn test_hmac_key_longer_than_block() {
    // RFC 4231 Case 3
    let key = [0xaa; 131];
    let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
    let expected = hex!("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

    assert_eq!(hmac_of(TpmiAlgHash::Sha256, &key, data), expected);
}

#[test]
fn test_hmac_incremental() {
    let key = b"secret_key_data";
    let mut ctx = HmacContext::<C>::new(TpmiAlgHash::Sha256, key).unwrap();
    ctx.update(b"hello ").unwrap();
    ctx.update(b"world!").unwrap();
    let mut out1 = [0u8; 64];
    let mac = ctx.finalize(&mut out1).unwrap();

    let expected = hmac_of(TpmiAlgHash::Sha256, key, b"hello world!");
    assert_eq!(mac.digest(), &expected[..]);
}

#[test]
fn test_hmac_empty_key() {
    let key = [];
    let data = b"some data";
    let mut out = [0u8; 64];
    let mac = tpm2::crypto::hmac::<C>(TpmiAlgHash::Sha256, &key, &[data], &mut out);
    assert!(mac.is_ok());
}

#[test]
fn test_hmac_empty_data() {
    let key = b"mykey";
    let mut out = [0u8; 64];
    let mac = tpm2::crypto::hmac::<C>(TpmiAlgHash::Sha256, key, &[&[]], &mut out);
    assert!(mac.is_ok());
    // No input slices at all is the same empty message.
    let mut out2 = [0u8; 64];
    let mac2 = tpm2::crypto::hmac::<C>(TpmiAlgHash::Sha256, key, &[], &mut out2);
    assert_eq!(mac, mac2);
}

#[test]
fn test_hmac_large_data() {
    let key = b"key";
    let mut data = [0u8; 32 * 1024];
    for (i, val) in data.iter_mut().enumerate() {
        *val = (i % 251) as u8;
    }
    let mut out = [0u8; 64];
    let mac = tpm2::crypto::hmac::<C>(TpmiAlgHash::Sha256, key, &[&data], &mut out);
    assert!(mac.is_ok());
}

/// The output buffer must hold the MAC (exp: `HmacStream::finalize` into a fixed-size array).
#[test]
fn test_hmac_output_buffer_too_small() {
    let mut out = [0u8; 47];
    assert_eq!(
        tpm2::crypto::hmac::<C>(TpmiAlgHash::Sha384, b"key", &[b"data"], &mut out),
        Err(CryptoError::Internal)
    );
    let ctx = HmacContext::<C>::new(TpmiAlgHash::Sha384, b"key").unwrap();
    assert_eq!(ctx.finalize(&mut out), Err(CryptoError::Internal));
}

// ==========================================
// FEATURE 3: Symmetric (AES-128, AES-256 in CFB mode)
// ==========================================

#[test]
fn test_aes128_cfb_encrypt_decrypt() {
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    let mut data = *b"plaintext_16byte";

    // Encrypt
    cfb(
        SymmetricKey::Aes128(&key),
        Direction::Encrypt,
        &mut iv,
        &mut data,
    );
    let ciphertext = data;

    // Reset IV
    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    // Decrypt
    cfb(
        SymmetricKey::Aes128(&key),
        Direction::Decrypt,
        &mut iv,
        &mut data,
    );
    assert_eq!(&data[..], b"plaintext_16byte");
    assert_ne!(ciphertext, data);
}

#[test]
fn test_aes128_cfb_multi_block() {
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    let mut data = [0xAAu8; 48];
    let original = data;

    cfb(
        SymmetricKey::Aes128(&key),
        Direction::Encrypt,
        &mut iv,
        &mut data,
    );
    let ciphertext = data;

    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    cfb(
        SymmetricKey::Aes128(&key),
        Direction::Decrypt,
        &mut iv,
        &mut data,
    );
    assert_eq!(data, original);
    assert_ne!(ciphertext, original);
}

#[test]
fn test_aes256_cfb_encrypt_decrypt() {
    let key = hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914df1a");
    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    let mut data = *b"plaintext_16byte";

    cfb(
        SymmetricKey::Aes256(&key),
        Direction::Encrypt,
        &mut iv,
        &mut data,
    );
    let ciphertext = data;

    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    cfb(
        SymmetricKey::Aes256(&key),
        Direction::Decrypt,
        &mut iv,
        &mut data,
    );
    assert_eq!(&data[..], b"plaintext_16byte");
    assert_ne!(ciphertext, data);
}

#[test]
fn test_aes256_cfb_multi_block() {
    let key = hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914df1a");
    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    let mut data = [0x55u8; 80];
    let original = data;

    cfb(
        SymmetricKey::Aes256(&key),
        Direction::Encrypt,
        &mut iv,
        &mut data,
    );
    let ciphertext = data;

    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    cfb(
        SymmetricKey::Aes256(&key),
        Direction::Decrypt,
        &mut iv,
        &mut data,
    );
    assert_eq!(data, original);
    assert_ne!(ciphertext, original);
}

#[test]
fn test_aes_cfb_non_zero_iv() {
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let mut iv1 = hex!("000102030405060708090a0b0c0d0e0f");
    let mut iv2 = hex!("ffeeddccbbaa99887766554433221100");
    let mut data1 = *b"plaintext_16byte";
    let mut data2 = *b"plaintext_16byte";

    cfb(
        SymmetricKey::Aes128(&key),
        Direction::Encrypt,
        &mut iv1,
        &mut data1,
    );
    cfb(
        SymmetricKey::Aes128(&key),
        Direction::Encrypt,
        &mut iv2,
        &mut data2,
    );

    // Verify dependency on IV (outputs must be different)
    assert_ne!(data1, data2);
}

#[test]
fn test_aes_empty_data() {
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    let mut data = [];

    let res = SymmetricKey::Aes128(&key).crypt::<C>(
        Direction::Encrypt,
        CipherInput::new(TpmiAlgCipherMode::Cfb, &mut iv, &mut data).unwrap(),
    );
    assert!(res.is_ok());
    // An empty message leaves the IV unchanged.
    assert_eq!(iv, hex!("000102030405060708090a0b0c0d0e0f"));
}

#[test]
fn test_aes_key_too_small() {
    let key = [0u8; 10]; // too small

    // The key length is validated when the `SymmetricKey` is built, before any backend call
    // (exp: `encrypt` returned `CryptoError::InvalidData`).
    assert!(SymmetricKey::new(AlgSym::Aes128, &key).is_none());
}

#[test]
fn test_aes_iv_too_small() {
    let mut iv = [0u8; 10]; // too small
    let mut data = [0u8; 16];

    // The IV length is validated when the `CipherInput` is built, before any backend call
    // (exp: `encrypt` returned `CryptoError::InvalidData`).
    assert!(CipherInput::new(TpmiAlgCipherMode::Cfb, &mut iv, &mut data).is_none());
}

#[test]
fn test_aes_corrupted_ciphertext() {
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    let mut data = *b"plaintext_16byte";

    cfb(
        SymmetricKey::Aes128(&key),
        Direction::Encrypt,
        &mut iv,
        &mut data,
    );
    // Corrupt ciphertext
    data[5] ^= 0xFF;

    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    cfb(
        SymmetricKey::Aes128(&key),
        Direction::Decrypt,
        &mut iv,
        &mut data,
    );
    // Verify it decrypts to garbage (not matching original plaintext)
    assert_ne!(&data[..], b"plaintext_16byte");
}

/// Plaintext of the NIST SP 800-38A, Appendix F.3 (CFB128) example vectors.
const SP800_38A_PLAINTEXT: [u8; 64] = hex!(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
);

/// Initialization vector of the NIST SP 800-38A, Appendix F.3 (CFB128) example vectors.
const SP800_38A_IV: [u8; 16] = hex!("000102030405060708090a0b0c0d0e0f");

/// Encrypts and then decrypts [`SP800_38A_PLAINTEXT`] in CFB mode with `key` in one call each,
/// checking the output against `ciphertext` and the IV written back by each call (`ivOut`),
/// which is the last ciphertext block for block-aligned data.
fn check_aes_cfb_sp800_38a(key: SymmetricKey<'_>, ciphertext: &[u8; 64]) {
    let mut data = SP800_38A_PLAINTEXT;
    let mut iv = SP800_38A_IV;
    cfb(key, Direction::Encrypt, &mut iv, &mut data);
    assert_eq!(&data, ciphertext, "{:?} encryption", key.alg());
    assert_eq!(
        &iv[..],
        &ciphertext[48..],
        "{:?} encryption ivOut",
        key.alg()
    );

    let mut iv = SP800_38A_IV;
    cfb(key, Direction::Decrypt, &mut iv, &mut data);
    assert_eq!(data, SP800_38A_PLAINTEXT, "{:?} decryption", key.alg());
    assert_eq!(
        &iv[..],
        &ciphertext[48..],
        "{:?} decryption ivOut",
        key.alg()
    );
}

#[test]
fn test_aes_cfb_sp800_38a_kat() {
    // F.3.13 / F.3.14: CFB128-AES128.Encrypt / Decrypt
    check_aes_cfb_sp800_38a(
        SymmetricKey::Aes128(&hex!("2b7e151628aed2a6abf7158809cf4f3c")),
        &hex!(
            "3b3fd92eb72dad20333449f8e83cfb4a"
            "c8a64537a0b3a93fcde3cdad9f1ce58b"
            "26751f67a3cbb140b1808cf187a4f4df"
            "c04b05357c5d1c0eeac4c66f9ff7f2e6"
        ),
    );

    // F.3.17 / F.3.18: CFB128-AES256.Encrypt / Decrypt
    check_aes_cfb_sp800_38a(
        SymmetricKey::Aes256(&hex!(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
        )),
        &hex!(
            "dc7e84bfda79164b7ecd8486985d3860"
            "39ffed143b28b1c832113c6331e5407b"
            "df10132415e54b92a13ed0a8267ae2f9"
            "75a385741ab9cef82031623d55b1e471"
        ),
    );
}

#[test]
fn test_aes_cfb_iv_chaining() {
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let key = SymmetricKey::Aes128(&key);

    // One call over the whole message.
    let mut whole = SP800_38A_PLAINTEXT;
    let mut iv = SP800_38A_IV;
    cfb(key, Direction::Encrypt, &mut iv, &mut whole);

    // The IV written back by a call continues the stream: two block-aligned calls give the
    // same ciphertext as one call.
    let mut parts = SP800_38A_PLAINTEXT;
    let mut iv = SP800_38A_IV;
    let (first, second) = parts.split_at_mut(32);
    cfb(key, Direction::Encrypt, &mut iv, first);
    cfb(key, Direction::Encrypt, &mut iv, second);
    assert_eq!(parts, whole);

    // The same holds for decryption, with a different split.
    let mut iv = SP800_38A_IV;
    let (first, second) = parts.split_at_mut(16);
    cfb(key, Direction::Decrypt, &mut iv, first);
    cfb(key, Direction::Decrypt, &mut iv, second);
    assert_eq!(parts, SP800_38A_PLAINTEXT);
}

// ==========================================
// FEATURE 4: Cmac (AES-128-CMAC, AES-256-CMAC)
//
// CMAC is not an algorithm of the TPM profile (`tpm2` feature `cmac`), so these tests use the
// backend's `CmacState` directly.
// ==========================================

type CmacAes128 = <C as Cmac>::Aes128;
type CmacAes256 = <C as Cmac>::Aes256;

#[test]
fn test_cmac_aes128_empty() {
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let mut mac = [0u8; 16];
    <CmacAes128 as CmacState<16>>::cmac(&key, &[b""], &mut mac).unwrap();
    assert_eq!(&mac[..], &hex!("bb1d6929e95937287fa37d129b756746")[..]);
}

#[test]
fn test_cmac_aes128_16bytes() {
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let data = hex!("6bc1bee22e409f96e93d7e117393172a");
    let mut mac = [0u8; 16];
    <CmacAes128 as CmacState<16>>::cmac(&key, &[&data], &mut mac).unwrap();
    assert_eq!(&mac[..], &hex!("070a16b46b4d4144f79bdd9dd04a287c")[..]);
}

#[test]
fn test_cmac_aes128_40bytes() {
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let data =
        hex!("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");
    let mut mac = [0u8; 16];
    <CmacAes128 as CmacState<16>>::cmac(&key, &[&data], &mut mac).unwrap();
    assert_eq!(&mac[..], &hex!("dfa66747de9ae63030ca32611497c827")[..]);

    // Streaming over uneven parts gives the same tag.
    let mut ctx = <CmacAes128 as CmacState<16>>::init(&key).unwrap();
    // (The rust backend's CMAC states are generic over the key size, hence the qualified paths.)
    <CmacAes128 as CmacState<16>>::update(&mut ctx, &data[..7]).unwrap();
    <CmacAes128 as CmacState<16>>::update(&mut ctx, &data[7..23]).unwrap();
    <CmacAes128 as CmacState<16>>::update(&mut ctx, &data[23..]).unwrap();
    let mut streamed = [0u8; 16];
    <CmacAes128 as CmacState<16>>::finalize(&mut ctx, &mut streamed).unwrap();
    assert_eq!(streamed, mac);
}

#[test]
fn test_cmac_aes256_empty() {
    let key = hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914df1a");
    let mut mac = [0u8; 16];
    <CmacAes256 as CmacState<32>>::cmac(&key, &[b""], &mut mac).unwrap();
    assert_eq!(&mac[..], &hex!("5f6844eb8d79e76cd244c07ad1003bce")[..]);
}

#[test]
fn test_cmac_aes256_16bytes() {
    let key = hex!("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914df1a");
    let data = hex!("6bc1bee22e409f96e93d7e117393172a");
    let mut mac = [0u8; 16];
    <CmacAes256 as CmacState<32>>::cmac(&key, &[&data], &mut mac).unwrap();
    assert_eq!(&mac[..], &hex!("22c2ef5b01082373365b34de01a7de91")[..]);
}

#[test]
fn test_cmac_key_too_small() {
    let key = [0u8; 10]; // too small

    // The key length is validated when the `SymmetricKey` is built, before any backend call
    // (exp: `cmac` returned `CryptoError::InvalidData`); the backend's `CmacState::init` takes
    // a key of exactly the algorithm's size.
    assert!(SymmetricKey::new(AlgSym::Aes128, &key).is_none());
    assert!(<&[u8; 16]>::try_from(&key[..]).is_err());
}

#[test]
fn test_cmac_large_message() {
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let mut data = [0u8; 16 * 1024];
    for (i, val) in data.iter_mut().enumerate() {
        *val = (i % 251) as u8;
    }
    let mut mac = [0u8; 16];
    let res = <CmacAes128 as CmacState<16>>::cmac(&key, &[&data], &mut mac);
    assert!(res.is_ok());
}

// ==========================================
// FEATURE 5: Asymmetric (RSA)
// ==========================================

#[test]
fn test_rsa_keygen_1024() {
    let key = rsa_generate(TpmiRsaKeyBits::Rsa1024);

    assert!(matches!(key.bits(), TpmiRsaKeyBits::Rsa1024));
    assert_eq!(key.exponent(), 65537);
    // The modulus has its top bit set, and the stored prime is half its size.
    let modulus = rsa_modulus(&key);
    assert_eq!(modulus.len(), 128);
    assert!(modulus[0] & 0x80 != 0);
    assert_eq!(rsa_prime(&key).len(), 64);
}

#[test]
fn test_rsa_keygen_2048() {
    let key = rsa_generate(TpmiRsaKeyBits::Rsa2048);

    assert!(matches!(key.bits(), TpmiRsaKeyBits::Rsa2048));
    assert_eq!(key.exponent(), 65537);
    let modulus = rsa_modulus(&key);
    assert_eq!(modulus.len(), 256);
    assert!(modulus[0] & 0x80 != 0);
    assert_eq!(rsa_prime(&key).len(), 128);
}

#[test]
fn test_rsa_oaep_encrypt_decrypt() {
    let key = rsa_generate(TpmiRsaKeyBits::Rsa2048);
    let public = rsa_public(&key);
    let mut rng = entropy_rng();
    let scheme = RsaEncryptScheme::Oaep {
        hash: TpmiAlgHash::Sha256,
        label: None,
    };

    let plaintext = b"hello world";
    let mut ciphertext = [0u8; 256];

    // Let's encrypt using the provider
    let ct = public
        .encrypt(&mut rng, scheme, plaintext, &mut ciphertext)
        .unwrap()
        .unwrap();
    assert_eq!(ct.as_slice().len(), 256);

    // Decrypt using provider
    let mut decrypted = [0u8; 256];
    let pt = key
        .decrypt(&mut rng, scheme, ct.as_slice(), &mut decrypted)
        .unwrap()
        .unwrap();

    assert_eq!(pt.as_slice(), plaintext);
}

#[test]
fn test_rsa_pss_sign_verify() {
    let key = rsa_generate(TpmiRsaKeyBits::Rsa2048);
    let mut rng = entropy_rng();

    let digest = [0xAAu8; 32];
    let mut signature = [0u8; MAX_SIGNATURE_BYTES];

    // Sign
    let sig = key
        .sign(
            &mut rng,
            TpmtSigScheme::Rsapss(TpmiAlgHash::Sha256),
            &digest,
            &mut signature,
        )
        .unwrap();
    let TpmtSignature::Rsapss(TpmsSignatureRsa {
        hash,
        sig: sig_bytes,
    }) = sig
    else {
        panic!("unexpected signature {sig:?}");
    };
    assert_eq!(hash, TpmiAlgHash::Sha256);
    assert_eq!(sig_bytes.as_slice().len(), 256);

    // The provider's verification should succeed
    assert_eq!(rsa_public(&key).verify(&digest, sig), Ok(true));

    // Verify using rsa crate directly
    rsa_crate_public(&key)
        .verify(
            rsa::pss::Pss::new::<sha2::Sha256>(),
            &digest,
            sig_bytes.as_slice(),
        )
        .unwrap();
}

#[test]
fn test_rsa_pkcs1v15_sign_verify() {
    let key = rsa_generate(TpmiRsaKeyBits::Rsa2048);
    let mut rng = entropy_rng();

    let digest = [0x55u8; 32];
    let mut signature = [0u8; MAX_SIGNATURE_BYTES];

    // Sign
    let sig = key
        .sign(
            &mut rng,
            TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256),
            &digest,
            &mut signature,
        )
        .unwrap();
    let TpmtSignature::Rsassa(TpmsSignatureRsa {
        hash,
        sig: sig_bytes,
    }) = sig
    else {
        panic!("unexpected signature {sig:?}");
    };
    assert_eq!(hash, TpmiAlgHash::Sha256);
    assert_eq!(sig_bytes.as_slice().len(), 256);

    // The provider's verification should succeed
    assert_eq!(rsa_public(&key).verify(&digest, sig), Ok(true));

    // Verify using rsa crate directly
    rsa_crate_public(&key)
        .verify(
            rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha256>(),
            &digest,
            sig_bytes.as_slice(),
        )
        .unwrap();
}

#[test]
fn test_rsa_import_and_raw_decrypt() {
    // First generate key to get standard modulus, primes, etc.
    let key = rsa_generate(TpmiRsaKeyBits::Rsa2048);
    let modulus = rsa_modulus(&key);
    let prime_p = rsa_prime(&key);
    let exponent = 65537u32;

    let imported = rsa_load(TpmiRsaKeyBits::Rsa2048, &modulus, &prime_p, exponent).unwrap();

    // Raw decrypt using imported private key
    let ciphertext = rsa_raw_encrypt(&key, 42);

    let mut plaintext = [0u8; 256];
    let decrypted = imported
        .decrypt(
            &mut entropy_rng(),
            RsaEncryptScheme::Raw,
            &ciphertext,
            &mut plaintext,
        )
        .unwrap()
        .unwrap();

    assert_eq!(decrypted.as_slice().len(), 256);
    let mut expected_plaintext = [0u8; 256];
    expected_plaintext[255] = 42;
    assert_eq!(decrypted.as_slice(), &expected_plaintext[..]);
}

#[test]
fn test_rsa_import_p_zero() {
    let modulus = [0u8; 128];
    let prime_p = [0u8; 64];

    assert!(rsa_load(TpmiRsaKeyBits::Rsa1024, &modulus, &prime_p, 65537).is_none());

    // A zero prime does not factor a valid modulus either.
    let key = rsa_generate(TpmiRsaKeyBits::Rsa1024);
    assert!(rsa_load(TpmiRsaKeyBits::Rsa1024, &rsa_modulus(&key), &prime_p, 65537).is_none());
}

#[test]
fn test_rsa_import_modulus_zero_p_nonzero() {
    let modulus = [0u8; 128];
    let prime_p = [2u8; 64];

    // An all-zero modulus is not a valid public key.
    assert!(matches!(
        RsaPublicKey::<C>::load(
            TpmiRsaKeyBits::Rsa1024,
            65537,
            Tpm2bPublicKeyRsa::new(&modulus).unwrap()
        ),
        Ok(None)
    ));
    assert!(rsa_load(TpmiRsaKeyBits::Rsa1024, &modulus, &prime_p, 65537).is_none());
}

#[test]
fn test_rsa_import_invalid_primes() {
    let modulus = [0x0f; 128];
    let prime_p = [0x02; 64]; // modulus is odd, prime_p is even.

    assert!(rsa_load(TpmiRsaKeyBits::Rsa1024, &modulus, &prime_p, 65537).is_none());

    // An even prime (or any non-factor) does not load for a valid modulus either.
    let key = rsa_generate(TpmiRsaKeyBits::Rsa1024);
    assert!(rsa_load(TpmiRsaKeyBits::Rsa1024, &rsa_modulus(&key), &prime_p, 65537).is_none());
}

#[test]
fn test_rsa_oaep_decrypt_corrupted() {
    let key = rsa_generate(TpmiRsaKeyBits::Rsa2048);

    // Encrypt
    let pub_key = rsa_crate_public(&key);
    let mut rng_thread = rsa::rand_core::OsRng;
    let oaep = rsa::Oaep::new::<sha2::Sha256>();
    let mut c = pub_key.encrypt(&mut rng_thread, oaep, b"secret").unwrap();

    let scheme = RsaEncryptScheme::Oaep {
        hash: TpmiAlgHash::Sha256,
        label: None,
    };
    // The uncorrupted ciphertext decrypts.
    let mut decrypted = [0u8; 256];
    let res = key.decrypt(&mut entropy_rng(), scheme, &c, &mut decrypted);
    assert_eq!(res.unwrap().unwrap().as_slice(), b"secret");

    // Corrupt ciphertext
    c[10] ^= 0xFF;

    let mut decrypted = [0u8; 256];
    let res = key.decrypt(&mut entropy_rng(), scheme, &c, &mut decrypted);
    // A bad OAEP padding is an invalid ciphertext: `Ok(None)` (exp: `HardwareFailure`).
    assert_eq!(res, Ok(None));
}

#[test]
fn test_rsa_pss_verify_corrupted() {
    // exp verified an all-zero signature with an all-zero public key, which the new API rejects
    // when the public key is loaded (see `test_rsa_import_modulus_zero_p_nonzero`): verify an
    // all-zero signature with a valid key instead, which must be `Ok(false)`.
    let key = rsa_generate(TpmiRsaKeyBits::Rsa2048);
    let public = rsa_public(&key);
    let digest = [0u8; 32];
    let signature = [0u8; 256];

    let sig = TpmtSignature::Rsapss(TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: Tpm2bPublicKeyRsa::new(&signature).unwrap(),
    });
    assert_eq!(public.verify(&digest, sig), Ok(false));

    // A signature of the wrong size or a digest of the wrong size is `Ok(false)` too.
    let short = TpmtSignature::Rsapss(TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: Tpm2bPublicKeyRsa::new(&signature[..255]).unwrap(),
    });
    assert_eq!(public.verify(&digest, short), Ok(false));
    assert_eq!(public.verify(&digest[..31], sig), Ok(false));
}

#[test]
fn test_rsa_decrypt_buffer_too_small() {
    let key = rsa_generate(TpmiRsaKeyBits::Rsa2048);

    let pub_key = rsa_crate_public(&key);
    let mut rng_thread = rsa::rand_core::OsRng;
    let oaep = rsa::Oaep::new::<sha2::Sha256>();
    let c = pub_key.encrypt(&mut rng_thread, oaep, b"secret").unwrap();

    // Output buffer too small (plaintext is 6 bytes, let's pass a 5-byte buffer); the output
    // buffer must hold a modulus-sized block.
    let scheme = RsaEncryptScheme::Oaep {
        hash: TpmiAlgHash::Sha256,
        label: None,
    };
    let mut decrypted = [0u8; 5];
    let res = key.decrypt(&mut entropy_rng(), scheme, &c, &mut decrypted);
    assert_eq!(res.unwrap_err(), CryptoError::Internal);
    let mut decrypted = [0u8; 255];
    let res = key.decrypt(&mut entropy_rng(), scheme, &c, &mut decrypted);
    assert_eq!(res.unwrap_err(), CryptoError::Internal);
}

// ==========================================
// FEATURE 6: Ecc (ECDSA P256, ECDH P256)
// ==========================================

#[test]
fn test_ecc_keygen_p256() {
    let key = p256_generate();

    assert_eq!(key.curve(), TpmEccCurve::NistP256);
    let (mut x, mut y) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    let point = key.point(&mut x, &mut y).unwrap();
    assert_eq!(point.x.as_slice().len(), 32);
    assert_eq!(point.y.as_slice().len(), 32);
    assert_eq!(ecc_scalar(&key).len(), 32);
}

/// Signs `digest` with `key` using ECDSA with SHA-256, writing the signature into `buf`.
fn ecdsa_sign<'a>(
    key: &EccPrivateKey<C>,
    digest: &[u8],
    buf: &'a mut [u8; MAX_SIGNATURE_BYTES],
) -> TpmsSignatureEcc<'a> {
    let sig = key
        .sign(
            &mut entropy_rng(),
            TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256),
            digest,
            buf,
        )
        .unwrap();
    let TpmtSignature::Ecdsa(sig) = sig else {
        panic!("unexpected signature {sig:?}");
    };
    sig
}

#[test]
fn test_ecdsa_sign_verify() {
    let key = p256_generate();

    let digest = [0u8; 32];
    let mut signature = [0u8; MAX_SIGNATURE_BYTES];

    let sig = ecdsa_sign(&key, &digest, &mut signature);
    assert_eq!(sig.hash, TpmiAlgHash::Sha256);
    assert_eq!(sig.signature_r.as_slice().len(), 32);
    assert_eq!(sig.signature_s.as_slice().len(), 32);

    assert_eq!(
        ecc_public(&key).verify(&digest, TpmtSignature::Ecdsa(sig)),
        Ok(true)
    );
}

#[test]
fn test_ecc_validate_point() {
    let key = p256_generate();

    // Validate generated key
    let (mut x, mut y) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    let point = key.point(&mut x, &mut y).unwrap();
    assert!(
        EccPublicKey::<C>::load(TpmEccCurve::NistP256, None, point)
            .unwrap()
            .is_some()
    );

    // Uncompressed generator point (X and Y coordinates, 64 bytes)
    let generator_uncompressed = hex!(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    );
    let (gx, gy) = generator_uncompressed.split_at(32);
    let generator = TpmsEccPoint {
        x: Tpm2bEccParameter::new(gx).unwrap(),
        y: Tpm2bEccParameter::new(gy).unwrap(),
    };
    assert!(
        EccPublicKey::<C>::load(TpmEccCurve::NistP256, None, generator)
            .unwrap()
            .is_some()
    );

    // [1]G is the generator.
    let (mut x, mut y) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    let g = tpm2::crypto::ecc_mul_generator::<C>(TpmEccCurve::NistP256, &[1], &mut x, &mut y)
        .unwrap()
        .unwrap();
    assert_eq!(g, generator);
}

#[test]
fn test_ecdh_shared_secret() {
    let priv_a = p256_generate();
    let pub_a = ecc_public(&priv_a);
    let priv_b = p256_generate();
    let pub_b = ecc_public(&priv_b);

    // [a]B == [b]A
    let secret_a = ecc_mul_point(&pub_b, &priv_a);
    let secret_b = ecc_mul_point(&pub_a, &priv_b);
    assert_eq!(secret_a, secret_b);

    // ECDH gives the same point.
    let (mut x, mut y) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    let z = priv_a.ecdh(&pub_b, &mut x, &mut y).unwrap().unwrap();
    assert_eq!([z.x.as_slice(), z.y.as_slice()].concat(), secret_a);
}

#[test]
fn test_ecdsa_verify_corrupted_signature() {
    let key = p256_generate();

    let digest = [0u8; 32];
    let mut signature = [0u8; MAX_SIGNATURE_BYTES];

    let sig = ecdsa_sign(&key, &digest, &mut signature);

    // Corrupt signature
    let mut r = [0u8; 32];
    r.copy_from_slice(sig.signature_r.as_slice());
    r[0] ^= 1;
    let corrupted = TpmsSignatureEcc {
        signature_r: Tpm2bEccParameter::new(&r).unwrap(),
        ..sig
    };

    let res = ecc_public(&key).verify(&digest, TpmtSignature::Ecdsa(corrupted));
    assert_eq!(res, Ok(false));
}

#[test]
fn test_ecdsa_verify_mismatched_key() {
    let key_a = p256_generate();
    let key_b = p256_generate();

    let digest = [0u8; 32];
    let mut signature = [0u8; MAX_SIGNATURE_BYTES];

    let sig = ecdsa_sign(&key_a, &digest, &mut signature);

    let res = ecc_public(&key_b).verify(&digest, TpmtSignature::Ecdsa(sig));
    assert_eq!(res, Ok(false));
}

#[test]
fn test_ecc_validate_invalid_point() {
    // All zeros
    let pt = [0u8; 32];
    let point = TpmsEccPoint {
        x: Tpm2bEccParameter::new(&pt).unwrap(),
        y: Tpm2bEccParameter::new(&pt).unwrap(),
    };
    let res = EccPublicKey::<C>::load(TpmEccCurve::NistP256, None, point);
    assert!(matches!(res, Ok(None)));
}

#[test]
fn test_ecdh_output_buffer_too_small() {
    let priv_a = p256_generate();
    let priv_b = p256_generate();
    let pub_b = ecc_public(&priv_b);

    // The output coordinates must each hold the curve size.
    let (mut small_x, mut small_y) = ([0u8; 16], [0u8; 16]);
    let res = pub_b.mul_point(&ecc_scalar(&priv_a), &mut small_x, &mut small_y);
    assert_eq!(res.unwrap_err(), CryptoError::Internal);
    let res = priv_a.ecdh(&pub_b, &mut small_x, &mut small_y);
    assert_eq!(res.unwrap_err(), CryptoError::Internal);
    let (mut x, mut small_y) = ([0u8; 32], [0u8; 31]);
    let res = priv_a.ecdh(&pub_b, &mut x, &mut small_y);
    assert_eq!(res.unwrap_err(), CryptoError::Internal);
}

// ==========================================
// FEATURE 7: Rng
// ==========================================

#[test]
fn test_rng_get_random() {
    let mut rng = entropy_rng();

    let mut buf1 = [0u8; 16];
    let mut buf2 = [0u8; 16];
    rng.fill_bytes(&mut buf1).unwrap();
    rng.fill_bytes(&mut buf2).unwrap();
    assert_ne!(buf1, buf2);

    // The stateless one-shot function draws fresh output too.
    let mut buf3 = [0u8; 16];
    C::rand_bytes(&mut buf3).unwrap();
    assert_ne!(buf3, buf1);
    assert_ne!(buf3, buf2);
}

#[test]
fn test_rng_large_request() {
    let mut buf = [0u8; 1024];
    entropy_rng().fill_bytes(&mut buf).unwrap();
    C::rand_bytes(&mut buf).unwrap();
}

#[test]
fn test_rng_non_zero() {
    let mut buf = [0u8; 64];
    entropy_rng().fill_bytes(&mut buf).unwrap();

    let is_all_zero = buf.iter().all(|&x| x == 0);
    assert!(!is_all_zero);
}

#[test]
fn test_rng_zero_bytes() {
    let mut buf = [];
    let res = entropy_rng().fill_bytes(&mut buf);
    assert!(res.is_ok());
    assert!(C::rand_bytes(&mut buf).is_ok());
}

#[test]
fn test_rng_multiple_requests() {
    let mut rng = entropy_rng();

    let mut bufs = [[0u8; 8]; 10];
    for buf in &mut bufs {
        rng.fill_bytes(buf).unwrap();
    }

    for i in 0..10 {
        for j in i + 1..10 {
            assert_ne!(bufs[i], bufs[j]);
        }
    }
}

#[test]
fn test_rng_stir_random() {
    let mut rng = entropy_rng();

    // `TPM2_StirRandom` input (including an empty one) is accepted, and the generator keeps
    // producing output afterwards.
    rng.stir_bytes(b"additional input").unwrap();
    rng.stir_bytes(&[]).unwrap();

    let mut buf1 = [0u8; 64];
    let mut buf2 = [0u8; 64];
    rng.fill_bytes(&mut buf1).unwrap();
    rng.fill_bytes(&mut buf2).unwrap();
    assert!(!buf1.iter().all(|&x| x == 0));
    assert_ne!(buf1, buf2);
}

// ==========================================
// TIER 3: Cross-Feature Combinations
// ==========================================

#[test]
fn test_combo_rsa_keygen_sign_verify() {
    // 1. Generate RSA key
    let key = rsa_generate(TpmiRsaKeyBits::Rsa2048);

    // 2. Hash message
    let message = b"combo test message for RSA";
    let mut ctx = HashContext::<C>::new(TpmiAlgHash::Sha256).unwrap();
    ctx.update(message).unwrap();
    let mut digest_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = ctx.finalize(&mut digest_buf).unwrap();

    // 3. Sign digest
    let mut signature = [0u8; MAX_SIGNATURE_BYTES];
    let sig = key
        .sign(
            &mut entropy_rng(),
            TpmtSigScheme::Rsapss(digest.hash_alg()),
            digest.digest(),
            &mut signature,
        )
        .unwrap();
    let TpmtSignature::Rsapss(TpmsSignatureRsa { sig: sig_bytes, .. }) = sig else {
        panic!("unexpected signature {sig:?}");
    };

    // 4. Verify signature using rsa crate directly
    rsa_crate_public(&key)
        .verify(
            rsa::pss::Pss::new::<sha2::Sha256>(),
            digest.digest(),
            sig_bytes.as_slice(),
        )
        .unwrap();
}

#[test]
fn test_combo_ecc_keygen_sign_verify() {
    // 1. Generate ECC key
    let key = p256_generate();

    // 2. Hash message
    let message = b"combo test message for ECC";
    let mut ctx = HashContext::<C>::new(TpmiAlgHash::Sha256).unwrap();
    ctx.update(message).unwrap();
    let mut digest_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = ctx.finalize(&mut digest_buf).unwrap();

    // 3. Sign digest
    let mut signature = [0u8; MAX_SIGNATURE_BYTES];
    let sig = ecdsa_sign(&key, digest.digest(), &mut signature);

    // 4. Verify signature
    assert_eq!(
        ecc_public(&key).verify(digest.digest(), TpmtSignature::Ecdsa(sig)),
        Ok(true)
    );
}

#[test]
fn test_combo_ecdh_exchange_aes_cfb() {
    // 1. Perform ECDH exchange
    let priv_a = p256_generate();
    let pub_a = ecc_public(&priv_a);
    let priv_b = p256_generate();
    let pub_b = ecc_public(&priv_b);

    let secret_a = ecc_mul_point(&pub_b, &priv_a);
    let secret_b = ecc_mul_point(&pub_a, &priv_b);
    assert_eq!(secret_a, secret_b);

    // 2. Derive AES key from shared secret (using first 32 bytes)
    let aes_key = &secret_a[..32];

    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    let mut data = *b"super_secret_payload_from_ecdh_kdf_etc.";
    let original = data;
    let key = SymmetricKey::new(AlgSym::Aes256, aes_key).unwrap();

    cfb(key, Direction::Encrypt, &mut iv, &mut data);
    let ciphertext = data;

    let mut iv = hex!("000102030405060708090a0b0c0d0e0f");
    cfb(key, Direction::Decrypt, &mut iv, &mut data);

    assert_eq!(data, original);
    assert_ne!(ciphertext, original);
}

#[test]
fn test_combo_keygen_save_load() {
    // Generate keys
    let key = rsa_generate(TpmiRsaKeyBits::Rsa2048);

    // Save/Serialize: the private key is stored as its prime p (with the public modulus).
    let saved_modulus = rsa_modulus(&key);
    let saved_prime = rsa_prime(&key);

    // Import/Load key
    let imported = rsa_load(TpmiRsaKeyBits::Rsa2048, &saved_modulus, &saved_prime, 65537).unwrap();
    assert_eq!(rsa_modulus(&imported), saved_modulus);
    assert_eq!(rsa_prime(&imported), saved_prime);

    // Perform decrypt with loaded key
    let ciphertext = rsa_raw_encrypt(&key, 123456);

    let mut plaintext = [0u8; 256];
    let decrypted = imported
        .decrypt(
            &mut entropy_rng(),
            RsaEncryptScheme::Raw,
            &ciphertext,
            &mut plaintext,
        )
        .unwrap()
        .unwrap();

    assert_eq!(decrypted.as_slice().len(), 256);
    let mut expected_plaintext = [0u8; 256];
    expected_plaintext[255] = (123456u32 % 256u32) as u8;
    expected_plaintext[254] = ((123456u32 / 256u32) % 256u32) as u8;
    expected_plaintext[253] = (123456u32 / 65536u32) as u8;
    assert_eq!(decrypted.as_slice(), &expected_plaintext[..]);
}

// ==========================================
// FEATURE 8: Differential/Stress Testing of TestProvider
// ==========================================

fn generate_deterministic_data(size: usize, seed: u8) -> Vec<u8> {
    let mut data = vec![0u8; size];
    for (i, val) in data.iter_mut().enumerate() {
        *val = ((i ^ (seed as usize)).wrapping_mul(17).wrapping_add(3)) as u8;
    }
    data
}

fn oracle_hash(alg: TpmiAlgHash, data: &[u8]) -> Vec<u8> {
    match alg {
        TpmiAlgHash::Sha1 => {
            use sha1::Digest as _;
            let mut hasher = sha1::Sha1::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        TpmiAlgHash::Sha256 => {
            use sha2::Digest as _;
            let mut hasher = sha2::Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        TpmiAlgHash::Sha384 => {
            use sha2::Digest as _;
            let mut hasher = sha2::Sha384::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        #[cfg(feature = "sha512")]
        TpmiAlgHash::Sha512 => {
            use sha2::Digest as _;
            let mut hasher = sha2::Sha512::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        #[allow(unreachable_patterns)]
        _ => panic!("unsupported hash alg"),
    }
}

fn oracle_hmac(alg: TpmiAlgHash, key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::Mac as _;
    match alg {
        TpmiAlgHash::Sha1 => {
            let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        TpmiAlgHash::Sha256 => {
            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        TpmiAlgHash::Sha384 => {
            let mut mac = hmac::Hmac::<sha2::Sha384>::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        #[cfg(feature = "sha512")]
        TpmiAlgHash::Sha512 => {
            let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        #[allow(unreachable_patterns)]
        _ => panic!("unsupported hmac alg"),
    }
}

#[test]
fn test_rust_crypto_provider_hash_differential() {
    let sizes = [0, 1, 2, 10, 63, 64, 65, 127, 128, 129, 1024, 4096, 10000];

    // SHA-1, SHA-256, SHA-384 (and SHA-512), each with its own data pattern.
    for (&alg, seed) in PROFILE_HASHES.iter().zip([0x11, 0x22, 0x33, 0x44]) {
        for &size in &sizes {
            let data = generate_deterministic_data(size, seed);
            let digest = hash_of(alg, &data);
            let expected = oracle_hash(alg, &data);
            assert_eq!(digest, expected, "{alg:?} mismatch at size {size}");

            // Incremental test
            let mut state = HashContext::<C>::new(alg).unwrap();
            if size > 0 {
                let half = size / 2;
                state.update(&data[..half]).unwrap();
                state.update(&data[half..]).unwrap();
            }
            let mut digest_inc = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
            let digest_inc = state.finalize(&mut digest_inc).unwrap();
            assert_eq!(digest_inc.hash_alg(), alg);
            assert_eq!(
                digest_inc.digest(),
                &expected[..],
                "{alg:?} incremental mismatch at size {size}"
            );
        }
    }
}

#[test]
fn test_rust_crypto_provider_hmac_differential() {
    let key_sizes = [0, 1, 10, 63, 64, 65, 127, 128, 129, 256];
    let data_sizes = [0, 1, 100, 1024, 10000];

    for &key_size in &key_sizes {
        for &data_size in &data_sizes {
            let key = generate_deterministic_data(key_size, 0x55);
            let data = generate_deterministic_data(data_size, 0x66);

            // HMAC-SHA1, HMAC-SHA256, HMAC-SHA384 (and HMAC-SHA512)
            for &alg in PROFILE_HASHES {
                let mac = hmac_of(alg, &key, &data);
                let expected = oracle_hmac(alg, &key, &data);
                assert_eq!(
                    mac, expected,
                    "HMAC-{alg:?} mismatch: key_size={key_size}, data_size={data_size}"
                );

                // Incremental
                let mut ctx = HmacContext::<C>::new(alg, &key).unwrap();
                if data_size > 0 {
                    let half = data_size / 2;
                    ctx.update(&data[..half]).unwrap();
                    ctx.update(&data[half..]).unwrap();
                }
                let mut out_inc = [0u8; 64];
                let mac_inc = ctx.finalize(&mut out_inc).unwrap();
                assert_eq!(
                    mac_inc.digest(),
                    &expected[..],
                    "HMAC-{alg:?} incremental mismatch: key_size={key_size}, data_size={data_size}"
                );
            }
        }
    }
}

#[test]
fn test_rust_crypto_provider_rng_properties() {
    let mut rng = entropy_rng();

    // 1. Edge Case: 0-length request
    let mut empty_buf = [];
    assert!(rng.fill_bytes(&mut empty_buf).is_ok());

    // 2. Edge Case: varying lengths
    for size in [1, 2, 5, 10, 64, 100, 1024, 10000] {
        let mut buf = vec![0u8; size];
        rng.fill_bytes(&mut buf).unwrap();
        if size >= 10 {
            assert!(
                !buf.iter().all(|&x| x == 0),
                "RNG returned all zeros for size {}",
                size
            );
        }
    }

    // 3. Statistical test: Uniformity
    let total_bytes = 100_000;
    let mut buf = vec![0u8; total_bytes];
    rng.fill_bytes(&mut buf).unwrap();

    let mut counts = [0usize; 256];
    for &byte in &buf {
        counts[byte as usize] += 1;
    }

    for (val, &count) in counts.iter().enumerate() {
        assert!(
            (250..=530).contains(&count),
            "Byte value {} count {} is out of expected uniform range [250, 530]",
            val,
            count
        );
    }
}

// ==========================================
// FEATURE 10: KDFa and KDFe Stress & Boundary Tests
// ==========================================

#[test]
fn test_kdfa_boundary_conditions() {
    use tpm2::crypto::kdfa_bits;

    let key = b"my_secret_kdf_key_that_is_long";
    let label = b"LABEL";
    let context = (&b"context_u"[..], &b"context_v"[..]);

    // 1. Verify buffer too small triggers error
    let mut out_small = [0u8; 10];
    let err = kdfa_bits::<C>(
        TpmiAlgHash::Sha256,
        key,
        label,
        context,
        128,
        &mut out_small,
    )
    .unwrap_err();
    assert_eq!(err, CryptoError::Internal);

    // 2. Exact buffer size works
    let mut out_exact = [0u8; 16];
    let len = kdfa_bits::<C>(
        TpmiAlgHash::Sha256,
        key,
        label,
        context,
        128,
        &mut out_exact,
    )
    .unwrap();
    assert_eq!(len, 16);

    // 3. Larger buffer size works, only populates required bytes
    let mut out_large = [0u8; 32];
    let len = kdfa_bits::<C>(
        TpmiAlgHash::Sha256,
        key,
        label,
        context,
        128,
        &mut out_large,
    )
    .unwrap();
    assert_eq!(len, 16);
    assert_eq!(out_large[16..], [0u8; 16]);

    // 4. Test bits not divisible by 8 (e.g., 13 bits) -> div_ceil(13, 8) = 2 bytes
    let mut out_non_div = [0u8; 5];
    let len = kdfa_bits::<C>(
        TpmiAlgHash::Sha256,
        key,
        label,
        context,
        13,
        &mut out_non_div,
    )
    .unwrap();
    assert_eq!(len, 2);
    assert_eq!(out_non_div[0] & 0xE0, 0);
    // Verify against raw HMAC digest with bits=13 that upper 3 bits are masked and lower bits preserved
    let mut raw_ctx = HmacContext::<C>::new(TpmiAlgHash::Sha256, key).unwrap();
    raw_ctx.update(&1u32.to_be_bytes()).unwrap();
    raw_ctx.update(label).unwrap();
    raw_ctx.update(&[0x00]).unwrap();
    raw_ctx.update(context.0).unwrap();
    raw_ctx.update(context.1).unwrap();
    raw_ctx.update(&13u32.to_be_bytes()).unwrap();
    let mut raw_mac_buf = [0u8; 64];
    let raw_mac = raw_ctx.finalize(&mut raw_mac_buf).unwrap();
    assert_eq!(out_non_div[0], raw_mac.digest()[0] & 0x1F);
    assert_eq!(out_non_div[1], raw_mac.digest()[1]);

    // 4b. Verify label with trailing NUL byte produces identical output
    let mut out_nul_label = [0u8; 16];
    let len_nul = kdfa_bits::<C>(
        TpmiAlgHash::Sha256,
        key,
        b"LABEL\0",
        context,
        128,
        &mut out_nul_label,
    )
    .unwrap();
    assert_eq!(len_nul, 16);
    assert_eq!(out_exact, out_nul_label);

    // 4c. The `CStr` label variant matches for labels without interior zero octets.
    let mut out_cstr = [0u8; 16];
    tpm2::crypto::kdfa::<C>(TpmiAlgHash::Sha256, key, c"LABEL", context, &mut out_cstr).unwrap();
    assert_eq!(out_exact, out_cstr);

    // 5. Test different hash algorithms (Sha1, Sha256, Sha384, Sha512)
    let mut out_sha1 = [0u8; 20];
    let len1 = kdfa_bits::<C>(TpmiAlgHash::Sha1, key, label, context, 160, &mut out_sha1).unwrap();
    assert_eq!(len1, 20);

    let mut out_sha384 = [0u8; 48];
    let len3 = kdfa_bits::<C>(
        TpmiAlgHash::Sha384,
        key,
        label,
        context,
        384,
        &mut out_sha384,
    )
    .unwrap();
    assert_eq!(len3, 48);

    #[cfg(feature = "sha512")]
    {
        let mut out_sha512 = [0u8; 64];
        let len5 = kdfa_bits::<C>(
            TpmiAlgHash::Sha512,
            key,
            label,
            context,
            512,
            &mut out_sha512,
        )
        .unwrap();
        assert_eq!(len5, 64);
    }

    // 6. Test very large bit generation (multiple iterations of KDF loop)
    let mut out_huge = [0u8; 512];
    let len_huge = kdfa_bits::<C>(
        TpmiAlgHash::Sha256,
        key,
        label,
        context,
        4096,
        &mut out_huge,
    )
    .unwrap();
    assert_eq!(len_huge, 512);

    // 7. Empty inputs
    let mut out_empty = [0u8; 32];
    let len_empty = kdfa_bits::<C>(
        TpmiAlgHash::Sha256,
        &[],
        &[],
        (&[], &[]),
        256,
        &mut out_empty,
    )
    .unwrap();
    assert_eq!(len_empty, 32);
}

#[test]
fn test_kdfe_boundary_conditions() {
    use tpm2::crypto::kdfe_bits;

    let z = b"shared_secret_z_value_for_kdfe";
    let label = b"LABEL";
    let party = (&b"party_u"[..], &b"party_v"[..]);

    // 1. Verify buffer too small triggers error
    let mut out_small = [0u8; 10];
    let err =
        kdfe_bits::<C>(TpmiAlgHash::Sha256, z, label, party, 128, &mut out_small).unwrap_err();
    assert_eq!(err, CryptoError::Internal);

    // 2. Exact buffer size works
    let mut out_exact = [0u8; 16];
    let len = kdfe_bits::<C>(TpmiAlgHash::Sha256, z, label, party, 128, &mut out_exact).unwrap();
    assert_eq!(len, 16);

    // 3. Larger buffer size works, only populates required bytes
    let mut out_large = [0u8; 32];
    let len = kdfe_bits::<C>(TpmiAlgHash::Sha256, z, label, party, 128, &mut out_large).unwrap();
    assert_eq!(len, 16);
    assert_eq!(out_large[16..], [0u8; 16]);

    // 4. Test bits not divisible by 8 (e.g., 13 bits) -> div_ceil(13, 8) = 2 bytes
    let mut out_non_div = [0u8; 5];
    let len = kdfe_bits::<C>(TpmiAlgHash::Sha256, z, label, party, 13, &mut out_non_div).unwrap();
    assert_eq!(len, 2);
    assert_eq!(out_non_div[0] & 0xE0, 0);
    assert_eq!(out_non_div[0], out_exact[0] & 0x1F);
    assert_eq!(out_non_div[1], out_exact[1]);

    // 4b. Verify label with trailing NUL byte produces identical output
    let mut out_nul_label = [0u8; 16];
    let len_nul = kdfe_bits::<C>(
        TpmiAlgHash::Sha256,
        z,
        b"LABEL\0",
        party,
        128,
        &mut out_nul_label,
    )
    .unwrap();
    assert_eq!(len_nul, 16);
    assert_eq!(out_exact, out_nul_label);

    // 4c. The `CStr` label variant matches for labels without interior zero octets.
    let mut out_cstr = [0u8; 16];
    tpm2::crypto::kdfe::<C>(TpmiAlgHash::Sha256, z, c"LABEL", party, &mut out_cstr).unwrap();
    assert_eq!(out_exact, out_cstr);

    // 5. Test different hash algorithms (Sha1, Sha256, Sha384, Sha512)
    let mut out_sha1 = [0u8; 20];
    let len1 = kdfe_bits::<C>(TpmiAlgHash::Sha1, z, label, party, 160, &mut out_sha1).unwrap();
    assert_eq!(len1, 20);

    let mut out_sha384 = [0u8; 48];
    let len3 = kdfe_bits::<C>(TpmiAlgHash::Sha384, z, label, party, 384, &mut out_sha384).unwrap();
    assert_eq!(len3, 48);

    #[cfg(feature = "sha512")]
    {
        let mut out_sha512 = [0u8; 64];
        let len5 =
            kdfe_bits::<C>(TpmiAlgHash::Sha512, z, label, party, 512, &mut out_sha512).unwrap();
        assert_eq!(len5, 64);
    }

    // 6. Test very large bit generation (multiple iterations of KDFe loop)
    let mut out_huge = [0u8; 512];
    let len_huge =
        kdfe_bits::<C>(TpmiAlgHash::Sha256, z, label, party, 4096, &mut out_huge).unwrap();
    assert_eq!(len_huge, 512);

    // 7. Empty inputs
    let mut out_empty = [0u8; 32];
    let len_empty = kdfe_bits::<C>(
        TpmiAlgHash::Sha256,
        &[],
        &[],
        (&[], &[]),
        256,
        &mut out_empty,
    )
    .unwrap();
    assert_eq!(len_empty, 32);
}

// ==========================================
// FEATURE 11: Constant-time comparison
// ==========================================

#[test]
fn test_constant_time_eq() {
    let a = [0x5Au8; 32];
    assert!(C::ct_eq(&a, &a));
    assert!(C::ct_eq(&[], &[]));

    // A difference in the first or in the last byte is detected.
    let mut first = a;
    first[0] ^= 0x01;
    assert!(!C::ct_eq(&a, &first));
    let mut last = a;
    last[31] ^= 0x80;
    assert!(!C::ct_eq(&a, &last));
    // Slices of different lengths are different.
    assert!(!C::ct_eq(&a, &a[..31]));

    // `digest_eq` compares tagged digests: both the algorithm and the digest must match.
    assert!(tpm2::crypto::digest_eq::<C>(
        TpmtHa::Sha256(&a),
        TpmtHa::Sha256(&a)
    ));
    assert!(!tpm2::crypto::digest_eq::<C>(
        TpmtHa::Sha256(&a),
        TpmtHa::Sha256(&last)
    ));
}

/// `RsaPrivateKey::crt` writes `p | q | dP | dQ | qInv` with `p` the larger prime, each
/// padded to the size of `p`, whichever prime the private key was loaded with; a prime that
/// does not factor the modulus does not load (`Ok(None)`; exp: an invalid key blob) and a short
/// buffer is an error.
#[test]
fn test_rsa_private_key_to_crt() {
    use rsa::BigUint;
    let key = rsa_generate(TpmiRsaKeyBits::Rsa1024);
    let modulus = rsa_modulus(&key);
    let n = BigUint::from_bytes_be(&modulus);
    let prime = BigUint::from_bytes_be(&rsa_prime(&key));
    let other = &n / &prime;
    assert_eq!(&prime * &other, n);
    let one = BigUint::from(1u32);
    // Import the key with each prime first.
    for prime in [&prime, &other] {
        let imported = rsa_load(
            TpmiRsaKeyBits::Rsa1024,
            &modulus,
            &prime.to_bytes_be(),
            65537,
        )
        .unwrap();
        let mut crt = [0u8; tpm2::limits::RSA_PRIVATE_SIZE];
        let len = imported.crt(&mut crt).unwrap().as_slice().len();
        assert_eq!(len, 5 * 64);
        let v: Vec<BigUint> = crt[..len].chunks(64).map(BigUint::from_bytes_be).collect();
        let (p, q) = (&v[0], &v[1]);
        assert!(p > q, "the larger prime comes first");
        assert_eq!(p * q, n);
        let e = BigUint::from(65537u32);
        assert_eq!((&e * &v[2]) % (p - &one), one, "dP");
        assert_eq!((&e * &v[3]) % (q - &one), one, "dQ");
        assert_eq!((q * &v[4]) % p, one, "qInv");
        assert!(imported.crt(&mut crt[..5 * 64 - 1]).is_err());
        // The first component is a prime factor, which loads back.
        assert!(rsa_load(TpmiRsaKeyBits::Rsa1024, &modulus, &crt[..64], 65537).is_some());
    }
    let not_a_factor = (&prime + BigUint::from(2u32)).to_bytes_be();
    assert!(rsa_load(TpmiRsaKeyBits::Rsa1024, &modulus, &not_a_factor, 65537).is_none());
}
