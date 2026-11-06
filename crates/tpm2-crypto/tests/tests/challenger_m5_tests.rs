use hex_literal::hex;
use tpm2::crypto::{
    CryptoError, EccPrivateKey, EccPublicKey, MAX_ECC_COORD_BYTES, Random, Rng, RsaEncryptScheme,
    RsaModulusBuffer, RsaPrimeBuffer, RsaPrivateKey, RsaPublicKey, ecc_mul_generator,
};
use tpm2::{
    Tpm2bEccParameter, Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmEccCurve, TpmiRsaKeyBits,
    TpmsEccPoint,
};
use tpm2_crypto_tests::TestProvider;

type C = TestProvider;

const MAX_PUB_KEY_BYTES: usize = TpmiRsaKeyBits::MAX_PUB_KEY_BYTES;

fn rng() -> <C as Random>::Rng {
    C::from_entropy().unwrap()
}

/// Loads an RSA public key of `bits` from a big-endian `modulus`.
fn rsa_public(bits: TpmiRsaKeyBits, exponent: u32, modulus: &[u8]) -> Option<RsaPublicKey<C>> {
    RsaPublicKey::<C>::load(bits, exponent, Tpm2bPublicKeyRsa::new(modulus).unwrap()).unwrap()
}

/// Loads an RSA private key from `(modulus, exponent)` and the prime `prime`.
fn rsa_import(
    bits: TpmiRsaKeyBits,
    exponent: u32,
    modulus: &[u8],
    prime: &[u8],
) -> Result<Option<RsaPrivateKey<C>>, CryptoError> {
    let Some(public) = rsa_public(bits, exponent, modulus) else {
        return Ok(None);
    };
    RsaPrivateKey::<C>::load(public, Tpm2bPrivateKeyRsa::new(prime).unwrap())
}

/// Generates an RSA-1024 key and returns it with its modulus and prime.
fn rsa1024() -> (RsaPrivateKey<C>, RsaModulusBuffer, RsaPrimeBuffer) {
    let key = RsaPrivateKey::<C>::generate(&mut rng(), TpmiRsaKeyBits::Rsa1024, 65537).unwrap();
    let mut modulus = [0u8; _];
    let mut prime = [0u8; _];
    assert_eq!(key.modulus(&mut modulus).unwrap().as_slice().len(), 128);
    assert_eq!(key.prime_p(&mut prime).unwrap().as_slice().len(), 64);
    (key, modulus, prime)
}

fn point<'a>(x: &'a [u8], y: &'a [u8]) -> TpmsEccPoint<'a> {
    TpmsEccPoint {
        x: Tpm2bEccParameter::new(x).unwrap(),
        y: Tpm2bEccParameter::new(y).unwrap(),
    }
}

#[test]
fn test_rsa_import_modulus_zero() {
    let modulus = [0u8; 128];
    let prime_p = [0u8; 64];

    // Modulus and p are zero: the zero modulus is already rejected as a public key.
    assert!(rsa_public(TpmiRsaKeyBits::Rsa1024, 65537, &modulus).is_none());
    let res = rsa_import(TpmiRsaKeyBits::Rsa1024, 65537, &modulus, &prime_p);
    assert!(matches!(res, Ok(None)));

    // A zero prime of a valid modulus is rejected too.
    let (_, modulus, _) = rsa1024();
    let res = rsa_import(TpmiRsaKeyBits::Rsa1024, 65537, &modulus[..128], &prime_p);
    assert!(matches!(res, Ok(None)));
}

#[test]
fn test_rsa_import_p_equals_n() {
    // Let's use 35 as n, 35 as p (n % p == 0, n / p == 1). Both are not prime, but we want to see if p == n works/fails.
    // A modulus that small is not a valid 1024-bit modulus.
    let res = rsa_import(TpmiRsaKeyBits::Rsa1024, 65537, &[35], &[35]);
    assert!(matches!(res, Ok(None)), "Importing p == n should fail");

    // p == n with a real modulus: n does not fit the prime size of the key.
    let (_, modulus, _) = rsa1024();
    let res = rsa_import(
        TpmiRsaKeyBits::Rsa1024,
        65537,
        &modulus[..128],
        &modulus[..128],
    );
    assert!(matches!(res, Ok(None)), "Importing p == n should fail");
}

#[test]
fn test_rsa_import_p_equals_one() {
    let res = rsa_import(TpmiRsaKeyBits::Rsa1024, 65537, &[35], &[1]);
    assert!(matches!(res, Ok(None)), "Importing p == 1 should fail");

    // p == 1 for a real modulus (n / p == n).
    let (_, modulus, _) = rsa1024();
    let res = rsa_import(TpmiRsaKeyBits::Rsa1024, 65537, &modulus[..128], &[1]);
    assert!(matches!(res, Ok(None)), "Importing p == 1 should fail");
}

#[test]
fn test_rsa_import_composite_non_primes() {
    // n = 32, p = 4. q = 8. (4 * 8 == 32, 32 % 4 == 0). Neither is prime.
    let res = rsa_import(TpmiRsaKeyBits::Rsa1024, 65537, &[32], &[4]);
    assert!(
        matches!(res, Ok(None)),
        "Importing composite numbers should fail"
    );

    // Composite candidates for a real modulus: 4, and the key's prime turned
    // into an even (composite) number. Neither divides n.
    let (_, modulus, prime) = rsa1024();
    let res = rsa_import(TpmiRsaKeyBits::Rsa1024, 65537, &modulus[..128], &[4]);
    assert!(
        matches!(res, Ok(None)),
        "Importing composite numbers should fail"
    );
    let mut even = prime;
    even[63] ^= 1;
    let res = rsa_import(TpmiRsaKeyBits::Rsa1024, 65537, &modulus[..128], &even[..64]);
    assert!(
        matches!(res, Ok(None)),
        "Importing composite numbers should fail"
    );
}

#[test]
fn test_rsa_import_exponent_invalid() {
    // First generate key to get standard modulus, primes, etc.
    let (_, modulus, prime_p) = rsa1024();
    let (modulus, prime_p) = (&modulus[..128], &prime_p[..64]);

    // Exponent 0 is the TPM's default exponent (65537) in the new API, so it
    // loads the key generated with 65537.
    let key = rsa_import(TpmiRsaKeyBits::Rsa1024, 0, modulus, prime_p)
        .unwrap()
        .expect("exponent 0 means 65537");
    assert_eq!(key.exponent(), 65537);

    // Try with invalid exponent = 1
    let res = rsa_import(TpmiRsaKeyBits::Rsa1024, 1, modulus, prime_p);
    assert!(
        matches!(res, Ok(None)),
        "Importing exponent = 1 should fail"
    );

    // Try with invalid exponent = 2 (even)
    let res = rsa_import(TpmiRsaKeyBits::Rsa1024, 2, modulus, prime_p);
    assert!(
        matches!(res, Ok(None)),
        "Importing exponent = 2 should fail"
    );
}

#[test]
fn test_ecc_scalar_zero() {
    let scalar = [0u8; 32];
    let (mut x, mut y) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);

    // 0 is not a valid private scalar
    let res = ecc_mul_generator::<C>(TpmEccCurve::NistP256, &scalar, &mut x, &mut y);
    assert_eq!(res, Ok(None));
    assert!(matches!(
        EccPrivateKey::<C>::from_scalar(TpmEccCurve::NistP256, &scalar),
        Ok(None)
    ));

    let pt = hex!(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    );
    let public = EccPublicKey::<C>::load(TpmEccCurve::NistP256, None, point(&pt[..32], &pt[32..]))
        .unwrap()
        .unwrap();
    let res_mult = public.mul_point(&scalar, &mut x, &mut y);
    assert_eq!(res_mult, Ok(None));
}

#[test]
fn test_ecc_scalar_too_large() {
    // Order of P-256 is ~ 1.1579208921035624876269744694940757353008090692179611295775678292847764947233e77
    // Order n = FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FA14 86200347 52C2DEC8 0249236D
    // Let's use FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
    let scalar = [0xFFu8; 32];
    let (mut x, mut y) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);

    let res = ecc_mul_generator::<C>(TpmEccCurve::NistP256, &scalar, &mut x, &mut y);
    assert_eq!(res, Ok(None));
}

#[test]
fn test_ecc_scalar_empty() {
    let scalar = [];
    let (mut x, mut y) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);

    let res = ecc_mul_generator::<C>(TpmEccCurve::NistP256, &scalar, &mut x, &mut y);
    // An empty scalar is not a valid scalar, it should fail
    assert_eq!(res, Ok(None));
}

#[test]
fn test_ecc_point_multiply_small_buffer() {
    // The output coordinates of P-256 are 32 bytes each; the y buffer is 1
    // byte short (63 bytes in total).
    let (mut x_buf, mut small_buf) = ([0u8; 32], [0u8; 31]);

    let priv_a = EccPrivateKey::<C>::generate(&mut rng(), TpmEccCurve::NistP256, None).unwrap();
    let (mut ax, mut ay) = ([0u8; MAX_ECC_COORD_BYTES], [0u8; MAX_ECC_COORD_BYTES]);
    let mut d = [0u8; MAX_ECC_COORD_BYTES];
    let pub_a = priv_a.point(&mut ax, &mut ay).unwrap();
    let pub_a = EccPublicKey::<C>::load(TpmEccCurve::NistP256, None, pub_a)
        .unwrap()
        .unwrap();
    let d = priv_a.scalar(&mut d).unwrap();

    // Check ecc_mul_generator handles small buffer without panicking
    let res_gen = ecc_mul_generator::<C>(
        TpmEccCurve::NistP256,
        d.as_slice(),
        &mut x_buf,
        &mut small_buf,
    );
    assert_eq!(res_gen.unwrap_err(), CryptoError::Internal);

    // Let's check mul_point behavior
    let res = pub_a.mul_point(d.as_slice(), &mut x_buf, &mut small_buf);
    assert_eq!(res.unwrap_err(), CryptoError::Internal);

    // And the point export of the key.
    let res = priv_a.point(&mut x_buf, &mut small_buf);
    assert_eq!(res.unwrap_err(), CryptoError::Internal);
}

#[test]
fn test_rsa_decrypt_null_large_ciphertext() {
    let (key, _, _) = rsa1024();

    // Ciphertext is larger than modulus (e.g. 128 bytes of 0xFF)
    let ciphertext = [0xFFu8; 128];
    let mut plaintext = [0u8; MAX_PUB_KEY_BYTES];

    let res = key.decrypt(
        &mut rng(),
        RsaEncryptScheme::Raw,
        &ciphertext,
        &mut plaintext,
    );
    assert_eq!(res, Ok(None));
}

#[test]
fn test_rsa_decrypt_null_empty_ciphertext() {
    let (key, _, _) = rsa1024();
    let mut plaintext = [0u8; MAX_PUB_KEY_BYTES];

    // The ciphertext must have the size of the modulus: an empty one is
    // rejected (the old API zero-extended it).
    let res = key.decrypt(&mut rng(), RsaEncryptScheme::Raw, &[], &mut plaintext);
    assert_eq!(res, Ok(None));

    // The zero ciphertext of the modulus size decrypts to zero (0^d = 0).
    let ciphertext = [0u8; 128];
    let dec = key
        .decrypt(
            &mut rng(),
            RsaEncryptScheme::Raw,
            &ciphertext,
            &mut plaintext,
        )
        .unwrap()
        .unwrap();
    assert_eq!(dec.as_slice().len(), 128);
    assert!(dec.as_slice().iter().all(|&x| x == 0));
}

#[test]
fn test_rsa_decrypt_oaep_non_utf8_label() {
    let (key, modulus, _) = rsa1024();

    // Label with non-UTF-8 bytes
    let invalid_label = c"\xFF\xFE\xFD";
    let scheme = RsaEncryptScheme::Oaep {
        hash: tpm2::TpmiAlgHash::Sha256,
        label: Some(invalid_label),
    };
    let ciphertext = [0u8; 128];
    let mut plaintext = [0u8; MAX_PUB_KEY_BYTES];

    // An invalid (all-zero) ciphertext fails whatever the label.
    let res = key.decrypt(&mut rng(), scheme, &ciphertext, &mut plaintext);
    assert_eq!(res, Ok(None));

    // A real ciphertext with this label: the `rust` and `bssl` backends accept
    // any label bytes, while `crux` (whose `rsa` crate takes UTF-8 labels)
    // rejects non-UTF-8 labels with `Ok(None)`.
    let public = rsa_public(TpmiRsaKeyBits::Rsa1024, 65537, &modulus[..128]).unwrap();
    let mut ct = [0u8; MAX_PUB_KEY_BYTES];
    let ct = public
        .encrypt(&mut rng(), scheme, b"secret", &mut ct)
        .unwrap();
    #[cfg(feature = "crux")]
    assert_eq!(ct, None);
    #[cfg(not(feature = "crux"))]
    {
        let ct = ct.unwrap();
        let dec = key
            .decrypt(&mut rng(), scheme, ct.as_slice(), &mut plaintext)
            .unwrap()
            .unwrap();
        assert_eq!(dec.as_slice(), b"secret");
    }
}

#[test]
fn test_rsa_sign_mismatched_digest_size() {
    // Digest size is 10 bytes instead of 32 (for SHA-256). TpmtHa rejects it at construction.
    let digest = [0u8; 10];
    assert!(tpm2::TpmtHa::new(tpm2::TpmiAlgHash::Sha256, &digest).is_none());

    // And the RSA signing dispatch rejects it.
    let (key, _, _) = rsa1024();
    let mut sig = [0u8; _];
    let res = key.sign(
        &mut rng(),
        tpm2::TpmtSigScheme::Rsassa(tpm2::TpmiAlgHash::Sha256),
        &digest,
        &mut sig,
    );
    assert_eq!(res.unwrap_err(), CryptoError::Internal);
}

#[test]
fn test_rsa_keygen_small_buffers() {
    // Key generation no longer writes into caller buffers; the key's
    // encodings are exported into buffers that must be large enough.
    let (key, _, _) = rsa1024();
    let mut small = [0u8; 1];

    assert_eq!(key.modulus(&mut small).unwrap_err(), CryptoError::Internal);
    assert_eq!(key.prime_p(&mut small).unwrap_err(), CryptoError::Internal);
    assert_eq!(key.crt(&mut small).unwrap_err(), CryptoError::Internal);
    // One byte short of the sizes of RSA-1024.
    assert_eq!(
        key.modulus(&mut [0u8; 127]).unwrap_err(),
        CryptoError::Internal
    );
    assert_eq!(
        key.prime_p(&mut [0u8; 63]).unwrap_err(),
        CryptoError::Internal
    );
    assert_eq!(
        key.crt(&mut [0u8; 5 * 64 - 1]).unwrap_err(),
        CryptoError::Internal
    );
    // The exact sizes succeed.
    assert!(key.crt(&mut [0u8; 5 * 64]).is_ok());
}

#[test]
fn test_rng_limits() {
    let mut buf = vec![0u8; 1024 * 1024]; // 1MB buffer
    let res = rng().fill_bytes(&mut buf);
    assert!(res.is_ok());
    let res = C::rand_bytes(&mut buf);
    assert!(res.is_ok());
}
