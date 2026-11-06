use rsa::traits::PublicKeyParts as _;
use tpm2::crypto::backend::{Rsa, RsaKey};
use tpm2::crypto::{
    CryptoError, EccPrivateKey, EccPublicKey, MAX_ECC_COORD_BYTES, Random, RsaEncryptScheme,
    RsaPrivateKey, RsaPublicKey, ecc_mul_generator,
};
use tpm2::{
    Tpm2bEccParameter, Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmEccCurve, TpmiAlgHash,
    TpmiRsaKeyBits, TpmsEccPoint, TpmsSchemeEcdaa, TpmsSignatureEcc, TpmsSignatureRsa,
    TpmtSigScheme, TpmtSignature,
};
use tpm2_crypto_tests::TestProvider;

type C = TestProvider;
type Coord = [u8; MAX_ECC_COORD_BYTES];

const MAX_PUB_KEY_BYTES: usize = TpmiRsaKeyBits::MAX_PUB_KEY_BYTES;

fn rng() -> <C as Random>::Rng {
    C::from_entropy().unwrap()
}

fn coord() -> Coord {
    [0u8; MAX_ECC_COORD_BYTES]
}

/// Loads an RSA public key of `bits` from a big-endian `modulus`.
fn rsa_public(bits: TpmiRsaKeyBits, exponent: u32, modulus: &[u8]) -> Option<RsaPublicKey<C>> {
    RsaPublicKey::<C>::load(bits, exponent, Tpm2bPublicKeyRsa::new(modulus).unwrap()).unwrap()
}

/// Loads an RSA private key from `(modulus, exponent)` and the prime `prime`
/// (`Ok(None)` if the public key is already invalid).
fn rsa_import(
    bits: TpmiRsaKeyBits,
    exponent: u32,
    modulus: &[u8],
    prime: &[u8],
) -> Result<Option<RsaPrivateKey<C>>, CryptoError> {
    let Some(public) = rsa_public(bits, exponent, modulus) else {
        return Ok(None);
    };
    match Tpm2bPrivateKeyRsa::new(prime) {
        Some(prime) => RsaPrivateKey::<C>::load(public, prime),
        None => Ok(None),
    }
}

/// Returns the modulus and the prime of `key`.
fn rsa_parts(key: &RsaPrivateKey<C>) -> (Vec<u8>, Vec<u8>) {
    let mut modulus = [0u8; MAX_PUB_KEY_BYTES];
    let mut prime = [0u8; MAX_PUB_KEY_BYTES];
    (
        key.modulus(&mut modulus).unwrap().as_slice().to_vec(),
        key.prime_p(&mut prime).unwrap().as_slice().to_vec(),
    )
}

/// The public key of `key`.
fn rsa_public_of(key: &RsaPrivateKey<C>) -> RsaPublicKey<C> {
    let (modulus, _) = rsa_parts(key);
    rsa_public(key.bits(), key.exponent(), &modulus).unwrap()
}

fn point<'a>(x: &'a [u8], y: &'a [u8]) -> TpmsEccPoint<'a> {
    TpmsEccPoint {
        x: Tpm2bEccParameter::new(x).unwrap(),
        y: Tpm2bEccParameter::new(y).unwrap(),
    }
}

/// Validates the point `x || y` (two equal halves) on `curve`.
fn load_point(curve: TpmEccCurve, xy: &[u8]) -> Option<EccPublicKey<C>> {
    let (x, y) = xy.split_at(xy.len() / 2);
    EccPublicKey::<C>::load(curve, None, point(x, y)).unwrap()
}

/// Asserts that `x || y` is not a valid point of `curve`. The old API's
/// `point_multiply` with such a point returned `Ok(None)`; the new API
/// multiplies only validated points, so the rejection happens at load.
fn assert_invalid_point(curve: TpmEccCurve, xy: &[u8]) {
    assert!(load_point(curve, xy).is_none());
}

/// Returns the public point `x || y` and the scalar of `key`.
fn ecc_parts(key: &EccPrivateKey<C>) -> (Vec<u8>, Vec<u8>) {
    let (mut x, mut y, mut d) = (coord(), coord(), coord());
    let q = key.point(&mut x, &mut y).unwrap();
    let mut xy = q.x.as_slice().to_vec();
    xy.extend_from_slice(q.y.as_slice());
    (xy, key.scalar(&mut d).unwrap().as_slice().to_vec())
}

fn rsa_sig(hash: TpmiAlgHash, sig: &[u8]) -> TpmsSignatureRsa<'_> {
    TpmsSignatureRsa {
        hash,
        sig: Tpm2bPublicKeyRsa::new(sig).unwrap(),
    }
}

fn rsassa(hash: TpmiAlgHash, sig: &[u8]) -> TpmtSignature<'_> {
    TpmtSignature::Rsassa(rsa_sig(hash, sig))
}

fn ecdsa<'a>(hash: TpmiAlgHash, r: &'a [u8], s: &'a [u8]) -> TpmtSignature<'a> {
    TpmtSignature::Ecdsa(ecc_sig(hash, r, s))
}

fn ecc_sig<'a>(hash: TpmiAlgHash, r: &'a [u8], s: &'a [u8]) -> TpmsSignatureEcc<'a> {
    TpmsSignatureEcc {
        hash,
        signature_r: Tpm2bEccParameter::new(r).unwrap(),
        signature_s: Tpm2bEccParameter::new(s).unwrap(),
    }
}

#[test]
fn test_rsa_import_private_key_bounds() {
    let bits = TpmiRsaKeyBits::Rsa1024;

    // 1. Zero modulus, zero p
    let res = rsa_import(bits, 65537, &[0], &[0]);
    assert!(matches!(res, Ok(None)));

    // 2. Zero p, non-zero modulus
    let res = rsa_import(bits, 65537, &[15], &[0]);
    assert!(matches!(res, Ok(None)));

    // 3. p = 1
    let res = rsa_import(bits, 65537, &[15], &[1]);
    assert!(matches!(res, Ok(None)));

    // 4. p > n (so q = 0)
    let res = rsa_import(bits, 65537, &[15], &[16]);
    assert!(matches!(res, Ok(None)));

    // 5. p = n (so q = 1)
    let res = rsa_import(bits, 65537, &[15], &[15]);
    assert!(matches!(res, Ok(None)));

    // 6. n not divisible by p
    let res = rsa_import(bits, 65537, &[15], &[4]);
    assert!(matches!(res, Ok(None)));

    // Moduli that small are no valid 1024-bit moduli, so the cases above
    // fail at the public key; repeat them with a real modulus.
    let key = RsaPrivateKey::<C>::generate(&mut rng(), bits, 65537).unwrap();
    let (modulus, prime_p) = rsa_parts(&key);
    assert!(matches!(rsa_import(bits, 65537, &modulus, &[0]), Ok(None)));
    assert!(matches!(rsa_import(bits, 65537, &modulus, &[1]), Ok(None)));
    // p > n and p = n: too long for the prime of the key.
    let mut greater = vec![1u8];
    greater.extend_from_slice(&modulus);
    assert!(matches!(
        rsa_import(bits, 65537, &modulus, &greater),
        Ok(None)
    ));
    assert!(matches!(
        rsa_import(bits, 65537, &modulus, &modulus),
        Ok(None)
    ));
    // n not divisible by p.
    assert!(matches!(rsa_import(bits, 65537, &modulus, &[4]), Ok(None)));
    let mut not_divisor = prime_p.clone();
    *not_divisor.last_mut().unwrap() ^= 2;
    assert!(matches!(
        rsa_import(bits, 65537, &modulus, &not_divisor),
        Ok(None)
    ));
    // The real prime loads.
    assert!(matches!(
        rsa_import(bits, 65537, &modulus, &prime_p),
        Ok(Some(_))
    ));

    // 7. Invalid exponents (1, 2); 0 is the default exponent 65537.
    let res = rsa_import(bits, 0, &modulus, &prime_p).unwrap().unwrap();
    assert_eq!(res.exponent(), 65537);

    // Exponent 1
    let res = rsa_import(bits, 1, &modulus, &prime_p);
    assert!(matches!(res, Ok(None)));

    // Exponent 2 (even exponent should fail for RSA)
    let res = rsa_import(bits, 2, &modulus, &prime_p);
    assert!(matches!(res, Ok(None)));

    // 8. Extreme/garbage values
    let res = rsa_import(bits, 65537, b"garbage modulus", b"garbage p");
    assert!(matches!(res, Ok(None)));
    let res = rsa_import(bits, 65537, &modulus, b"garbage p");
    assert!(matches!(res, Ok(None)));
}

#[test]
fn test_ecc_point_multiply_buffer_sizes() {
    let curve = TpmEccCurve::NistP256;
    let priv_a = EccPrivateKey::<C>::generate(&mut rng(), curve, None).unwrap();
    let (pub_a, d) = ecc_parts(&priv_a);
    let pub_a = load_point(curve, &pub_a).unwrap();

    // 1. Output buffer sizes for mul_point: each coordinate needs 32 bytes.
    for size in [0, 1, 10, 31] {
        let (mut short, mut full) = (vec![0u8; size], [0u8; 32]);
        let res = pub_a.mul_point(&d, &mut short, &mut full);
        assert_eq!(res.unwrap_err(), CryptoError::Internal);
        let res = pub_a.mul_point(&d, &mut full, &mut short);
        assert_eq!(res.unwrap_err(), CryptoError::Internal);
    }

    // Output buffer size 32 + 32 (succeeds)
    let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
    let q = pub_a.mul_point(&d, &mut x, &mut y).unwrap().unwrap();
    assert_eq!((q.x.as_slice().len(), q.y.as_slice().len()), (32, 32));

    // Output buffer size 50 + 50 (succeeds)
    let (mut x, mut y) = ([0u8; 50], [0u8; 50]);
    let q = pub_a.mul_point(&d, &mut x, &mut y).unwrap().unwrap();
    assert_eq!((q.x.as_slice().len(), q.y.as_slice().len()), (32, 32));
    // Verification that only 32 bytes of each were written
    assert_ne!(x[..32], [0u8; 32]);
    assert_eq!(x[32..], [0u8; 18]);
    assert_ne!(y[..32], [0u8; 32]);
    assert_eq!(y[32..], [0u8; 18]);

    // 2. Output buffer sizes for ecc_mul_generator
    for size in [0, 1, 10, 31] {
        let (mut short, mut full) = (vec![0u8; size], [0u8; 32]);
        let res = ecc_mul_generator::<C>(curve, &d, &mut short, &mut full);
        assert_eq!(res.unwrap_err(), CryptoError::Internal);
        let res = ecc_mul_generator::<C>(curve, &d, &mut full, &mut short);
        assert_eq!(res.unwrap_err(), CryptoError::Internal);
    }

    let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
    let q = ecc_mul_generator::<C>(curve, &d, &mut x, &mut y)
        .unwrap()
        .unwrap();
    assert_eq!((q.x.as_slice().len(), q.y.as_slice().len()), (32, 32));

    let (mut x, mut y) = ([0u8; 50], [0u8; 50]);
    let q = ecc_mul_generator::<C>(curve, &d, &mut x, &mut y)
        .unwrap()
        .unwrap();
    assert_eq!((q.x.as_slice().len(), q.y.as_slice().len()), (32, 32));
    assert_ne!(x[..32], [0u8; 32]);
    assert_eq!(x[32..], [0u8; 18]);
    assert_ne!(y[..32], [0u8; 32]);
    assert_eq!(y[32..], [0u8; 18]);
}

#[test]
fn test_bn_p256_fallback() {
    let curve = TpmEccCurve::BNP256;

    // BN_P256 curve point: (1, 2)
    // Coordinates must be 32 bytes each
    let mut bn_point = [0u8; 64];
    bn_point[31] = 1; // X = 1
    bn_point[63] = 2; // Y = 2

    // 1. Validate point (1, 2) on BN_P256
    let public = load_point(curve, &bn_point).expect("(1, 2) is on BN P-256");

    // 2. Validate point (1, 3) is NOT on BN_P256
    let mut invalid_bn_point = [0u8; 64];
    invalid_bn_point[31] = 1; // X = 1
    invalid_bn_point[63] = 3; // Y = 3
    assert_invalid_point(curve, &invalid_bn_point);

    // 3. Point multiplication with scalar = 1 (should return same point)
    let mut scalar_1 = [0u8; 32];
    scalar_1[31] = 1;
    let (mut x, mut y) = (coord(), coord());
    let q = public
        .mul_point(&scalar_1, &mut x, &mut y)
        .unwrap()
        .unwrap();
    assert_eq!(q.x.as_slice(), &bn_point[..32]);
    assert_eq!(q.y.as_slice(), &bn_point[32..]);

    // 4. Point multiplication with scalar = 2 (should return a valid point on the curve)
    let mut scalar_2 = [0u8; 32];
    scalar_2[31] = 2;
    let (mut x, mut y) = (coord(), coord());
    let q = public
        .mul_point(&scalar_2, &mut x, &mut y)
        .unwrap()
        .unwrap();
    // Output point must be on the curve
    assert!(EccPublicKey::<C>::load(curve, None, q).unwrap().is_some());

    // 5. Point multiplication with scalar = 0 (should fail)
    let scalar_0 = [0u8; 32];
    let (mut x, mut y) = (coord(), coord());
    let res = public.mul_point(&scalar_0, &mut x, &mut y);
    assert_eq!(res, Ok(None));

    // 6. Point multiplication with large scalar
    let mut scalar_large = [0u8; 32];
    scalar_large[0] = 0x01; // some arbitrary non-zero scalar
    let (mut x, mut y) = (coord(), coord());
    let q = public
        .mul_point(&scalar_large, &mut x, &mut y)
        .unwrap()
        .unwrap();
    assert!(EccPublicKey::<C>::load(curve, None, q).unwrap().is_some());
}

#[test]
fn test_bn_p256_coordinate_range_validation() {
    // p = fffffffffffcf0cd46e5f25eee71a49f0cdc65fb12980a82d3292ddbaed33013
    // Let's create X = p + 1, Y = 2
    let bn_point = hex_literal::hex!(
        "fffffffffffcf0cd46e5f25eee71a49f0cdc65fb12980a82d3292ddbaed33014" // X = p + 1
        "0000000000000000000000000000000000000000000000000000000000000002" // Y = 2
    );

    // If coordinates >= p are strictly rejected, this should fail with Ok(None)
    assert_invalid_point(TpmEccCurve::BNP256, &bn_point);
}

#[test]
fn test_ecc_curve_isolation_and_boundaries() {
    let nist = TpmEccCurve::NistP256;
    let bn = TpmEccCurve::BNP256;

    // NIST P-256 prime: p = ffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    let nist_p_bytes =
        hex_literal::hex!("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");

    // 1. NIST P-256: Coordinate X = p, Y = 1
    let mut nist_p_equal_x = [0u8; 64];
    nist_p_equal_x[..32].copy_from_slice(&nist_p_bytes);
    nist_p_equal_x[63] = 1;
    assert_invalid_point(nist, &nist_p_equal_x);

    // 2. NIST P-256: Coordinate X = p + 1, Y = 1
    let mut nist_p_greater_x = [0u8; 64];
    // p + 1 = ffffffff00000001000000000000000000000001000000000000000000000000
    let nist_p_plus_1_bytes =
        hex_literal::hex!("ffffffff00000001000000000000000000000001000000000000000000000000");
    nist_p_greater_x[..32].copy_from_slice(&nist_p_plus_1_bytes);
    nist_p_greater_x[63] = 1;
    assert_invalid_point(nist, &nist_p_greater_x);

    // 3. NIST P-256: Coordinate X = 1, Y = p
    let mut nist_p_equal_y = [0u8; 64];
    nist_p_equal_y[31] = 1;
    nist_p_equal_y[32..].copy_from_slice(&nist_p_bytes);
    assert_invalid_point(nist, &nist_p_equal_y);

    // 4. BN_P256: Coordinate X = p, Y = 1
    let bn_p_bytes =
        hex_literal::hex!("fffffffffffcf0cd46e5f25eee71a49f0cdc65fb12980a82d3292ddbaed33013");
    let mut bn_p_equal_x = [0u8; 64];
    bn_p_equal_x[..32].copy_from_slice(&bn_p_bytes);
    bn_p_equal_x[63] = 1;
    assert_invalid_point(bn, &bn_p_equal_x);

    // 5. BN_P256: Coordinate X = 1, Y = p
    let mut bn_p_equal_y = [0u8; 64];
    bn_p_equal_y[31] = 1;
    bn_p_equal_y[32..].copy_from_slice(&bn_p_bytes);
    assert_invalid_point(bn, &bn_p_equal_y);

    // 6. Curve Isolation: Valid BN_P256 point (1, 2) validated/multiplied on NIST P-256
    let mut bn_valid_point = [0u8; 64];
    bn_valid_point[31] = 1;
    bn_valid_point[63] = 2;
    // Verify it is indeed valid on BN_P256
    assert!(load_point(bn, &bn_valid_point).is_some());
    // Validate (and so multiply) on NIST P-256 should fail
    assert_invalid_point(nist, &bn_valid_point);

    // 7. Curve Isolation: Valid NIST P-256 point validated/multiplied on BN_P256
    let nist_priv = EccPrivateKey::<C>::generate(&mut rng(), nist, None).unwrap();
    let (nist_pub, _) = ecc_parts(&nist_priv);
    // Verify it is indeed valid on NIST P-256
    assert!(load_point(nist, &nist_pub).is_some());
    // Validate (and so multiply) on BN_P256 should fail
    assert_invalid_point(bn, &nist_pub);

    // 8. NIST P-256: Coordinate X = 1, Y = p + 1
    let mut nist_p_plus_1_y = [0u8; 64];
    nist_p_plus_1_y[31] = 1;
    nist_p_plus_1_y[32..].copy_from_slice(&nist_p_plus_1_bytes);
    assert_invalid_point(nist, &nist_p_plus_1_y);

    // 9. BN_P256: Coordinate X = p + 1, Y = 2
    let mut bn_p_plus_1_x = [0u8; 64];
    let mut bn_p_plus_1_bytes = bn_p_bytes;
    bn_p_plus_1_bytes[31] = 0x14;
    bn_p_plus_1_x[..32].copy_from_slice(&bn_p_plus_1_bytes);
    bn_p_plus_1_x[63] = 2;
    assert_invalid_point(bn, &bn_p_plus_1_x);

    // 10. BN_P256: Coordinate X = 1, Y = p + 1
    let mut bn_p_plus_1_y = [0u8; 64];
    bn_p_plus_1_y[31] = 1;
    bn_p_plus_1_y[32..].copy_from_slice(&bn_p_plus_1_bytes);
    assert_invalid_point(bn, &bn_p_plus_1_y);

    // 11. Point with all 0xFF coordinates
    let all_ff = [0xffu8; 64];
    assert_invalid_point(nist, &all_ff);
    assert_invalid_point(bn, &all_ff);

    // 12. Point with all 0x00 coordinates (0, 0)
    let all_zero = [0u8; 64];
    assert_invalid_point(nist, &all_zero);
    assert_invalid_point(bn, &all_zero);
}

#[test]
fn adv_test_rsa_keygen_with_seed() {
    let seed1 = b"deterministic seed 1";
    let seed2 = b"deterministic seed 2";
    let bits = TpmiRsaKeyBits::Rsa1024;

    let key1 = RsaPrivateKey::<C>::generate(&mut C::from_seed(seed1).unwrap(), bits, 0).unwrap();

    // Generate again with same seed, must be identical
    let key1_bis =
        RsaPrivateKey::<C>::generate(&mut C::from_seed(seed1).unwrap(), bits, 0).unwrap();
    assert_eq!(rsa_parts(&key1), rsa_parts(&key1_bis));

    // Generate with different seed, must be different
    let key2 = RsaPrivateKey::<C>::generate(&mut C::from_seed(seed2).unwrap(), bits, 0).unwrap();
    assert_ne!(rsa_parts(&key1).1, rsa_parts(&key2).1);
    assert_ne!(rsa_parts(&key1).0, rsa_parts(&key2).0);
}

#[test]
fn adv_test_ecc_keygen_with_seed() {
    let seed1 = b"deterministic ecc seed 1";
    let seed2 = b"deterministic ecc seed 2";
    let curve = TpmEccCurve::NistP256;

    let gen_key = |seed: &[u8]| {
        EccPrivateKey::<C>::generate(&mut C::from_seed(seed).unwrap(), curve, None).unwrap()
    };
    let (pub1, priv1) = ecc_parts(&gen_key(seed1));
    let (pub1_bis, priv1_bis) = ecc_parts(&gen_key(seed1));

    assert_eq!(pub1, pub1_bis);
    assert_eq!(priv1, priv1_bis);

    let (_, priv2) = ecc_parts(&gen_key(seed2));
    assert_ne!(priv1, priv2);
}

#[test]
fn adv_test_rsa_signatures_all_hashes() {
    let key = RsaPrivateKey::<C>::generate(&mut rng(), TpmiRsaKeyBits::Rsa2048, 65537).unwrap();
    let (modulus, _) = rsa_parts(&key);

    let test_cases = vec![
        (false, TpmiAlgHash::Sha1, 20),
        (false, TpmiAlgHash::Sha256, 32),
        (false, TpmiAlgHash::Sha384, 48),
        #[cfg(feature = "sha512")]
        (false, TpmiAlgHash::Sha512, 64),
        (true, TpmiAlgHash::Sha1, 20),
        (true, TpmiAlgHash::Sha256, 32),
        (true, TpmiAlgHash::Sha384, 48),
        #[cfg(feature = "sha512")]
        (true, TpmiAlgHash::Sha512, 64),
    ];

    // Verify using rsa crate directly
    let pub_key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&modulus),
        rsa::BigUint::from(65537u32),
    )
    .unwrap();

    for (pss, hash_alg, digest_len) in test_cases {
        let digest = vec![0xABu8; digest_len];
        let mut signature = [0u8; _];

        // Sign
        let scheme = if pss {
            TpmtSigScheme::Rsapss(hash_alg)
        } else {
            TpmtSigScheme::Rsassa(hash_alg)
        };
        let sig = match key
            .sign(&mut rng(), scheme, &digest, &mut signature)
            .unwrap()
        {
            TpmtSignature::Rsassa(s) if !pss => s,
            TpmtSignature::Rsapss(s) if pss => s,
            other => panic!("unexpected signature {other:?}"),
        };
        assert_eq!(sig.hash, hash_alg);
        let sig = sig.sig.as_slice();
        assert_eq!(sig.len(), 256);

        match (pss, hash_alg) {
            (false, TpmiAlgHash::Sha1) => pub_key
                .verify(
                    rsa::pkcs1v15::Pkcs1v15Sign::new::<sha1::Sha1>(),
                    &digest,
                    sig,
                )
                .unwrap(),
            (false, TpmiAlgHash::Sha256) => pub_key
                .verify(
                    rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha256>(),
                    &digest,
                    sig,
                )
                .unwrap(),
            (false, TpmiAlgHash::Sha384) => pub_key
                .verify(
                    rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha384>(),
                    &digest,
                    sig,
                )
                .unwrap(),
            #[cfg(feature = "sha512")]
            (false, TpmiAlgHash::Sha512) => pub_key
                .verify(
                    rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha512>(),
                    &digest,
                    sig,
                )
                .unwrap(),
            (true, TpmiAlgHash::Sha1) => pub_key
                .verify(rsa::pss::Pss::new::<sha1::Sha1>(), &digest, sig)
                .unwrap(),
            (true, TpmiAlgHash::Sha256) => pub_key
                .verify(rsa::pss::Pss::new::<sha2::Sha256>(), &digest, sig)
                .unwrap(),
            (true, TpmiAlgHash::Sha384) => pub_key
                .verify(rsa::pss::Pss::new::<sha2::Sha384>(), &digest, sig)
                .unwrap(),
            #[cfg(feature = "sha512")]
            (true, TpmiAlgHash::Sha512) => pub_key
                .verify(rsa::pss::Pss::new::<sha2::Sha512>(), &digest, sig)
                .unwrap(),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }
}

#[test]
fn adv_test_rsa_oaep_decrypt_all_hashes() {
    let key = RsaPrivateKey::<C>::generate(&mut rng(), TpmiRsaKeyBits::Rsa2048, 65537).unwrap();
    let (modulus, _) = rsa_parts(&key);

    let pub_key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&modulus),
        rsa::BigUint::from(65537u32),
    )
    .unwrap();
    let mut rng_thread = rsa::rand_core::OsRng;
    let plaintext = b"hello world hashes";

    let hash_cases = vec![
        (TpmiAlgHash::Sha1, rsa::Oaep::new::<sha1::Sha1>()),
        (TpmiAlgHash::Sha256, rsa::Oaep::new::<sha2::Sha256>()),
        (TpmiAlgHash::Sha384, rsa::Oaep::new::<sha2::Sha384>()),
        #[cfg(feature = "sha512")]
        (TpmiAlgHash::Sha512, rsa::Oaep::new::<sha2::Sha512>()),
    ];

    for (hash_alg, oaep) in hash_cases {
        let c = pub_key.encrypt(&mut rng_thread, oaep, plaintext).unwrap();

        let mut decrypted = [0u8; MAX_PUB_KEY_BYTES];
        let scheme = RsaEncryptScheme::Oaep {
            hash: hash_alg,
            label: None,
        };
        let dec = key
            .decrypt(&mut rng(), scheme, &c, &mut decrypted)
            .unwrap()
            .unwrap();

        assert_eq!(dec.as_slice(), plaintext);
    }
}

/// Generates a key of the backend RSA key type `K` (with modulus size `MOD`)
/// and checks its encodings: a full-size modulus and prime, which load back.
fn check_rsa_keygen<const MOD: usize, const PRIME: usize, K>()
where
    K: RsaKey<MOD, PRIME, <C as Random>::Rng>,
{
    let key = K::generate(&mut rng(), 65537).unwrap();

    let mut public_key = [0u8; MOD];
    let mut private_key = [0u8; PRIME];
    K::store_public(key.as_public(), &mut public_key).unwrap();
    key.store(&mut private_key).unwrap();

    // A full-size modulus and a full-size prime.
    assert!(public_key[0] & 0x80 != 0);
    assert!(private_key[0] & 0x80 != 0);
    // They load back.
    let public = K::load_public(65537, &public_key).unwrap().unwrap();
    assert!(K::load(public, &private_key).unwrap().is_some());
}

/// RSA-3072 is not in the engine profile, so it is tested through the
/// backend trait.
#[test]
fn adv_test_rsa_keygen_3072() {
    check_rsa_keygen::<384, 192, <C as Rsa>::Rsa3072>();
}

/// RSA-4096 is not in the engine profile, so it is tested through the
/// backend trait.
#[test]
fn adv_test_rsa_keygen_4096() {
    check_rsa_keygen::<512, 256, <C as Rsa>::Rsa4096>();
}

#[test]
fn adv_test_ecc_bn_p256_keygen_and_multiply_generator() {
    let curve = TpmEccCurve::BNP256;
    let key = EccPrivateKey::<C>::generate(&mut rng(), curve, None).unwrap();
    let (public_key, private_key) = ecc_parts(&key);

    assert_eq!(public_key.len(), 64);
    assert_eq!(private_key.len(), 32);

    // Validate the generated point on BN_P256
    assert!(load_point(curve, &public_key).is_some());

    // Multiply the generator with the private scalar using ecc_mul_generator
    let (mut x, mut y) = (coord(), coord());
    let q = ecc_mul_generator::<C>(curve, &private_key, &mut x, &mut y)
        .unwrap()
        .unwrap();

    // Verify it yields the same public key
    assert_eq!(q.x.as_slice(), &public_key[..32]);
    assert_eq!(q.y.as_slice(), &public_key[32..]);
}

#[test]
fn adv_test_ecc_validate_point_invalid_lengths() {
    for curve in [TpmEccCurve::NistP256, TpmEccCurve::BNP256] {
        // Encodings `x || y` of the old API's lengths, split into halves:
        // empty coordinates, coordinates longer than 32 bytes, and short
        // (left-padded) coordinates of the point (0, 0).
        for len in [0, 1, 32, 63, 65, 100] {
            let invalid_point = vec![0u8; len];
            let (x, y) = invalid_point.split_at(len / 2);
            let res = EccPublicKey::<C>::load(curve, None, point(x, y)).unwrap();
            assert!(res.is_none());
        }

        // A valid point with a coordinate longer than 32 bytes (even with a
        // leading zero) is rejected too.
        let key = EccPrivateKey::<C>::generate(&mut rng(), curve, None).unwrap();
        let (xy, _) = ecc_parts(&key);
        let mut long_x = vec![0u8];
        long_x.extend_from_slice(&xy[..32]);
        let res = EccPublicKey::<C>::load(curve, None, point(&long_x, &xy[32..])).unwrap();
        assert!(res.is_none());
        assert!(load_point(curve, &xy).is_some());
    }
}

#[test]
fn adv_test_ecc_bn_p256_keygen_with_seed() {
    let seed1 = b"bn256 deterministic seed 1";
    let seed2 = b"bn256 deterministic seed 2";
    let curve = TpmEccCurve::BNP256;

    let gen_key = |seed: &[u8]| {
        EccPrivateKey::<C>::generate(&mut C::from_seed(seed).unwrap(), curve, None).unwrap()
    };
    let (pub1, priv1) = ecc_parts(&gen_key(seed1));

    assert_eq!(pub1.len(), 64);
    assert_eq!(priv1.len(), 32);

    // Verify it is on the curve
    assert!(load_point(curve, &pub1).is_some());

    // Re-generate with the same seed, must be identical
    let (pub1_bis, priv1_bis) = ecc_parts(&gen_key(seed1));
    assert_eq!(pub1, pub1_bis);
    assert_eq!(priv1, priv1_bis);

    // Generate with a different seed, must be different
    let (_, priv2) = ecc_parts(&gen_key(seed2));
    assert_ne!(priv1, priv2);
}

#[test]
fn adv_test_keygen_empty_seed() {
    let bits = TpmiRsaKeyBits::Rsa1024;

    // RSA with empty seed
    let key1 = RsaPrivateKey::<C>::generate(&mut C::from_seed(&[]).unwrap(), bits, 0).unwrap();

    // Re-generate with empty seed, must be identical
    let key1_bis = RsaPrivateKey::<C>::generate(&mut C::from_seed(&[]).unwrap(), bits, 0).unwrap();

    assert_eq!(rsa_parts(&key1), rsa_parts(&key1_bis));
}

#[test]
fn adv_test_rsa_keygen_fallback_params() {
    // The old API fell back to 2048 bits without key parameters; the key size
    // is now always explicit, and the exponent 0 falls back to 65537.

    // 1. Exponent 0 -> 65537, and a valid 2048-bit key
    let key = RsaPrivateKey::<C>::generate(&mut rng(), TpmiRsaKeyBits::Rsa2048, 0).unwrap();
    assert_eq!(key.exponent(), 65537);
    assert_eq!(key.bits(), TpmiRsaKeyBits::Rsa2048);

    // Verify it is a valid 2048-bit key
    let (modulus, _) = rsa_parts(&key);
    let rsa_key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&modulus),
        rsa::BigUint::from(65537u32),
    )
    .unwrap();
    assert_eq!(rsa_key.n().bits(), 2048);

    // 2. Invalid exponents (1, even) are unsupported for key generation.
    for exponent in [1, 2, 65536] {
        let res = RsaPrivateKey::<C>::generate(&mut rng(), TpmiRsaKeyBits::Rsa2048, exponent);
        assert!(matches!(res, Err(CryptoError::Unsupported)));
    }
}

#[test]
fn adv_test_rsa_oaep_decrypt_with_label() {
    let key = RsaPrivateKey::<C>::generate(&mut rng(), TpmiRsaKeyBits::Rsa2048, 65537).unwrap();
    let (modulus, _) = rsa_parts(&key);

    let pub_key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&modulus),
        rsa::BigUint::from(65537u32),
    )
    .unwrap();
    let mut rng_thread = rsa::rand_core::OsRng;
    let plaintext = b"secure message with label";
    // The TPM's label includes its terminating zero octet.
    let label = c"my_secure_label";
    let oaep_scheme = |label| RsaEncryptScheme::Oaep {
        hash: TpmiAlgHash::Sha256,
        label,
    };

    // Encrypt with label
    let oaep = rsa::Oaep::new_with_label::<sha2::Sha256, _>("my_secure_label\0");
    let c = pub_key.encrypt(&mut rng_thread, oaep, plaintext).unwrap();

    // Decrypt with correct label
    let mut decrypted = [0u8; MAX_PUB_KEY_BYTES];
    let dec = key
        .decrypt(&mut rng(), oaep_scheme(Some(label)), &c, &mut decrypted)
        .unwrap()
        .unwrap();
    assert_eq!(dec.as_slice(), plaintext);

    // Decrypt with incorrect label -> should fail (Ok(None); exp: HardwareFailure)
    let bad_label = c"wrong_label";
    let mut decrypted_bad = [0u8; MAX_PUB_KEY_BYTES];
    let res = key.decrypt(
        &mut rng(),
        oaep_scheme(Some(bad_label)),
        &c,
        &mut decrypted_bad,
    );
    assert_eq!(res, Ok(None));

    // Decrypt with empty label -> should fail
    let res_empty = key.decrypt(&mut rng(), oaep_scheme(None), &c, &mut decrypted_bad);
    assert_eq!(res_empty, Ok(None));

    // A label without the terminating zero is a different label.
    let oaep = rsa::Oaep::new_with_label::<sha2::Sha256, _>("my_secure_label");
    let c = pub_key.encrypt(&mut rng_thread, oaep, plaintext).unwrap();
    let res = key.decrypt(&mut rng(), oaep_scheme(Some(label)), &c, &mut decrypted_bad);
    assert_eq!(res, Ok(None));
}

#[test]
fn adv_test_ecc_invalid_scalar_len() {
    let curve = TpmEccCurve::NistP256;
    let scalar_too_large = [1u8; 33];
    let (mut x, mut y) = (coord(), coord());

    // NIST P-256
    let res1 = ecc_mul_generator::<C>(curve, &scalar_too_large, &mut x, &mut y);
    assert_eq!(res1, Ok(None));

    // The old test multiplied the invalid point (0, 0); the new API multiplies
    // only validated points, so use the generator.
    let g = hex_literal::hex!(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    );
    let pt = load_point(curve, &g).unwrap();
    let res2 = pt.mul_point(&scalar_too_large, &mut x, &mut y);
    assert_eq!(res2, Ok(None));
    assert!(matches!(
        EccPrivateKey::<C>::from_scalar(curve, &scalar_too_large),
        Ok(None)
    ));
}

#[test]
fn adv_test_rsa_sign_buffer_too_small() {
    // Signatures are written into a `SignatureBuffer`, which always fits; the
    // buffer checks of the new API are on the key exports, and a digest that
    // doesn't match the scheme's hash is rejected.
    let key = RsaPrivateKey::<C>::generate(&mut rng(), TpmiRsaKeyBits::Rsa1024, 65537).unwrap();

    // The modulus of a 1024-bit RSA key is 128 bytes. Let's pass 127 bytes buffer.
    let mut short = [0u8; 127];
    let res = key.modulus(&mut short);
    assert_eq!(res.unwrap_err(), CryptoError::Internal);
    let res = rsa_public_of(&key).modulus(&mut short);
    assert_eq!(res.unwrap_err(), CryptoError::Internal);

    // A 32-byte digest for an RSAPSS-SHA384 signature.
    let digest = [0xAAu8; 32];
    let mut signature = [0u8; _];
    let res = key.sign(
        &mut rng(),
        TpmtSigScheme::Rsapss(TpmiAlgHash::Sha384),
        &digest,
        &mut signature,
    );
    assert_eq!(res.unwrap_err(), CryptoError::Internal);
}

#[test]
fn adv_test_signature_verification_edge_cases() {
    // 1. RSA setup
    let rsa_priv1 =
        RsaPrivateKey::<C>::generate(&mut rng(), TpmiRsaKeyBits::Rsa2048, 65537).unwrap();
    let rsa_pub1 = rsa_public_of(&rsa_priv1);
    let rsa_priv2 =
        RsaPrivateKey::<C>::generate(&mut rng(), TpmiRsaKeyBits::Rsa2048, 65537).unwrap();
    let rsa_pub2 = rsa_public_of(&rsa_priv2);

    let digest = [0xBCu8; 32];
    let mut sig_buf = [0u8; _];

    // Sign with RSASSA SHA256
    let TpmtSignature::Rsassa(sig) = rsa_priv1
        .sign(
            &mut rng(),
            TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256),
            &digest,
            &mut sig_buf,
        )
        .unwrap()
    else {
        panic!("expected an RSASSA signature");
    };
    let signature = sig.sig.as_slice().to_vec();
    let sig_len = signature.len();

    // Verify successfully
    assert_eq!(
        rsa_pub1.verify(&digest, rsassa(TpmiAlgHash::Sha256, &signature)),
        Ok(true)
    );

    // Challenge 1: Corrupted RSA signature
    {
        let mut corrupted_sig = signature.clone();
        corrupted_sig[sig_len / 2] ^= 0xFF;
        let res = rsa_pub1.verify(&digest, rsassa(TpmiAlgHash::Sha256, &corrupted_sig));
        assert_eq!(res, Ok(false));
    }

    // Challenge 2: Wrong hash algorithm for RSA signature verification
    {
        let digest_sha384 = [0xBCu8; 48];
        let res = rsa_pub1.verify(&digest_sha384, rsassa(TpmiAlgHash::Sha384, &signature));
        assert_eq!(res, Ok(false));
        // A digest that doesn't match the signature's hash algorithm.
        let res = rsa_pub1.verify(&digest_sha384, rsassa(TpmiAlgHash::Sha256, &signature));
        assert_eq!(res, Ok(false));
    }

    // Challenge 3: Mismatched keys (verify using public key 2)
    {
        let res = rsa_pub2.verify(&digest, rsassa(TpmiAlgHash::Sha256, &signature));
        assert_eq!(res, Ok(false));
    }

    // Challenge 4: Unsupported scheme (verify an ECDSA signature with an RSA
    // public key). The old API returned `Ok(false)` (its sizes did not match);
    // the new dispatch rejects a scheme of another key type as unsupported.
    {
        let res = rsa_pub1.verify(
            &digest,
            TpmtSignature::Ecdsa(ecc_sig(
                TpmiAlgHash::Sha256,
                &signature[..32],
                &signature[32..64],
            )),
        );
        assert_eq!(res, Err(CryptoError::Unsupported));
    }

    // RSA signature of the wrong size.
    {
        let res = rsa_pub1.verify(&digest, rsassa(TpmiAlgHash::Sha256, &signature[1..]));
        assert_eq!(res, Ok(false));
    }

    // 2. ECC setup
    let curve = TpmEccCurve::NistP256;
    let ecc_priv1 = EccPrivateKey::<C>::generate(&mut rng(), curve, None).unwrap();
    let (ecc_pub1_bytes, _) = ecc_parts(&ecc_priv1);
    let ecc_pub1 = load_point(curve, &ecc_pub1_bytes).unwrap();
    let ecc_priv2 = EccPrivateKey::<C>::generate(&mut rng(), curve, None).unwrap();
    let (ecc_pub2_bytes, _) = ecc_parts(&ecc_priv2);
    let ecc_pub2 = load_point(curve, &ecc_pub2_bytes).unwrap();

    let ecc_digest = [0xDEu8; 32];
    let mut ecc_sig_buf = [0u8; _];

    // Sign with ECDSA SHA256
    let TpmtSignature::Ecdsa(sig) = ecc_priv1
        .sign(
            &mut rng(),
            TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256),
            &ecc_digest,
            &mut ecc_sig_buf,
        )
        .unwrap()
    else {
        panic!("expected an ECDSA signature");
    };
    let (r, s) = (
        sig.signature_r.as_slice().to_vec(),
        sig.signature_s.as_slice().to_vec(),
    );
    assert_eq!((r.len(), s.len()), (32, 32));

    // Verify successfully
    assert_eq!(
        ecc_pub1.verify(&ecc_digest, ecdsa(TpmiAlgHash::Sha256, &r, &s)),
        Ok(true)
    );

    // Challenge 5: Corrupted ECC signature
    {
        let mut corrupted_r = r.clone();
        corrupted_r[16] ^= 0xFF;
        let res = ecc_pub1.verify(&ecc_digest, ecdsa(TpmiAlgHash::Sha256, &corrupted_r, &s));
        assert_eq!(res, Ok(false));
        let mut corrupted_s = s.clone();
        corrupted_s[0] ^= 0xFF;
        let res = ecc_pub1.verify(&ecc_digest, ecdsa(TpmiAlgHash::Sha256, &r, &corrupted_s));
        assert_eq!(res, Ok(false));
    }

    // Challenge 6: Wrong digest / hash algorithm for ECC signature verification
    {
        let ecc_digest_sha384 = [0xBCu8; 48];
        let res = ecc_pub1.verify(&ecc_digest_sha384, ecdsa(TpmiAlgHash::Sha384, &r, &s));
        assert_eq!(res, Ok(false));
        // A digest that doesn't match the signature's hash algorithm.
        let res = ecc_pub1.verify(&ecc_digest_sha384, ecdsa(TpmiAlgHash::Sha256, &r, &s));
        assert_eq!(res, Ok(false));
    }

    // Challenge 7: Mismatched ECC keys
    {
        let res = ecc_pub2.verify(&ecc_digest, ecdsa(TpmiAlgHash::Sha256, &r, &s));
        assert_eq!(res, Ok(false));
    }

    // Challenge 8: Invalid ECC buffer sizes
    {
        // A public key one byte short (x of 31 bytes, left-padded) is not on
        // the curve.
        let res = EccPublicKey::<C>::load(
            curve,
            None,
            point(&ecc_pub1_bytes[..31], &ecc_pub1_bytes[32..]),
        )
        .unwrap();
        assert!(res.is_none());

        // A signature one byte short (s of 31 bytes, left-padded).
        let res2 = ecc_pub1.verify(&ecc_digest, ecdsa(TpmiAlgHash::Sha256, &r, &s[..31]));
        assert_eq!(res2, Ok(false));

        // A component longer than the curve size.
        let mut long_r = vec![0u8];
        long_r.extend_from_slice(&r);
        let res3 = ecc_pub1.verify(&ecc_digest, ecdsa(TpmiAlgHash::Sha256, &long_r, &s));
        assert_eq!(res3, Ok(false));
    }

    // Challenge 9: Completely unsupported algorithms (schemes of another key
    // type, HMAC, and ECDAA, which the dispatch does not implement)
    {
        let res = ecc_pub1.verify(&ecc_digest, rsassa(TpmiAlgHash::Sha256, &signature));
        assert_eq!(res.unwrap_err(), CryptoError::Unsupported);
        let hmac = TpmtSignature::Hmac(tpm2::TpmtHa::Sha256(&ecc_digest));
        assert_eq!(
            ecc_pub1.verify(&ecc_digest, hmac).unwrap_err(),
            CryptoError::Unsupported
        );
        assert_eq!(
            rsa_pub1.verify(&digest, hmac).unwrap_err(),
            CryptoError::Unsupported
        );

        let mut out = [0u8; _];
        // With an ECC key, an RSA or HMAC scheme -> Unsupported
        for scheme in [
            TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256),
            TpmtSigScheme::Hmac(TpmiAlgHash::Sha256),
            TpmtSigScheme::Ecdaa(TpmsSchemeEcdaa {
                hash_alg: TpmiAlgHash::Sha256,
                count: 0,
            }),
        ] {
            let res2 = ecc_priv1.sign(&mut rng(), scheme, &ecc_digest, &mut out);
            assert_eq!(res2.unwrap_err(), CryptoError::Unsupported);
        }

        // With an RSA key, an ECC or HMAC scheme -> Unsupported
        for scheme in [
            TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256),
            TpmtSigScheme::Hmac(TpmiAlgHash::Sha256),
        ] {
            let res3 = rsa_priv1.sign(&mut rng(), scheme, &digest, &mut out);
            assert_eq!(res3.unwrap_err(), CryptoError::Unsupported);
        }
    }
}
