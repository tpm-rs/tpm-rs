use super::*;
use hex_literal::hex;
use tpm2::crypto::Random as _;
use tpm2::crypto::ecc_params::{
    BN_P256, BN_P638, EccCurveParams, NIST_P192, NIST_P224, NIST_P256, NIST_P384, NIST_P521,
    SM2_P256,
};

type P256 = <CruxCryptoProvider as Ecc>::NistP256;
type P384 = <CruxCryptoProvider as Ecc>::NistP384;
type P521 = <CruxCryptoProvider as Ecc>::NistP521;

fn rng(seed: &[u8]) -> CruxRng {
    CruxCryptoProvider::from_seed(seed).unwrap()
}

/// Left-pads the big-endian integer `bytes` to `N` bytes.
fn pad<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out[N - bytes.len()..].copy_from_slice(bytes);
    out
}

/// The generator `x || y` and order `n` of `params`.
fn generator<const C: usize, const P: usize>(params: &EccCurveParams) -> ([u8; P], [u8; C]) {
    let mut g = [0u8; P];
    g[..C].copy_from_slice(&pad::<C>(params.gx));
    g[C..].copy_from_slice(&pad::<C>(params.gy));
    (g, pad::<C>(params.n))
}

/// Checks the point arithmetic, point validation, key management, ECDH and
/// ECDSA of the curve `K` with the domain parameters `params`.
fn check_curve<K, const C: usize, const P: usize>(params: &EccCurveParams)
where
    K: EccCurve<C, P, CruxRng>,
{
    let name = params.curve_id;
    let (g, n) = generator::<C, P>(params);
    let (mut x, mut y) = ([0u8; C], [0u8; C]);
    let xy = |x: &[u8; C], y: &[u8; C]| {
        let mut p = [0u8; P];
        p[..C].copy_from_slice(x);
        p[C..].copy_from_slice(y);
        p
    };

    // 1 * G, 2 * G, 6 * G and 3 * (2 * G).
    assert_eq!(
        K::mul_generator(&pad(&[1]), &mut x, &mut y),
        Ok(Some(())),
        "{name}"
    );
    assert_eq!(xy(&x, &y), g, "{name}");
    let g_key = K::load_public((), &g).unwrap().unwrap();
    assert_eq!(
        K::mul_point(&g_key, &pad(&[1]), &mut x, &mut y),
        Ok(Some(()))
    );
    assert_eq!(xy(&x, &y), g, "{name}");
    K::mul_generator(&pad(&[2]), &mut x, &mut y)
        .unwrap()
        .unwrap();
    let two_g = K::load_public((), &xy(&x, &y)).unwrap().unwrap();
    K::mul_generator(&pad(&[6]), &mut x, &mut y)
        .unwrap()
        .unwrap();
    let six_g = xy(&x, &y);
    K::mul_point(&two_g, &pad(&[3]), &mut x, &mut y)
        .unwrap()
        .unwrap();
    assert_eq!(xy(&x, &y), six_g, "{name}");

    // Invalid scalars and points.
    for k in [[0u8; C], n] {
        assert_eq!(K::mul_generator(&k, &mut x, &mut y), Ok(None), "{name}");
        assert_eq!(K::mul_point(&g_key, &k, &mut x, &mut y), Ok(None), "{name}");
    }
    let mut off_curve = g;
    off_curve[P - 1] ^= 1;
    assert!(K::load_public((), &off_curve).unwrap().is_none(), "{name}");
    assert!(K::load_public((), &[0xff; P]).unwrap().is_none(), "{name}");
    assert!(K::load_public((), &[0; P]).unwrap().is_none(), "{name}");

    // Key generation: deterministic for a seeded RNG, with `[d]G` as public key.
    let key = K::generate(&mut rng(b"ecc"), ()).unwrap();
    let (mut d, mut q) = ([0u8; C], [0u8; P]);
    key.store(&mut d).unwrap();
    K::store_public(key.as_public(), &mut q).unwrap();
    let mut d2 = [0u8; C];
    K::generate(&mut rng(b"ecc"), ())
        .unwrap()
        .store(&mut d2)
        .unwrap();
    assert_eq!(d, d2, "{name}");
    K::generate(&mut rng(b"other"), ())
        .unwrap()
        .store(&mut d2)
        .unwrap();
    assert_ne!(d, d2, "{name}");
    K::mul_generator(&d, &mut x, &mut y).unwrap().unwrap();
    assert_eq!(xy(&x, &y), q, "{name}");
    let public = || K::load_public((), &q).unwrap().unwrap();
    assert!(K::load(public(), &d).unwrap().is_some(), "{name}");
    assert!(K::load(public(), &d2).unwrap().is_none(), "{name}");
    assert!(K::load(public(), &[0; C]).unwrap().is_none(), "{name}");

    // ECDH: [d1]Q2 == [d2]Q1.
    let other = K::generate(&mut rng(b"peer"), ()).unwrap();
    let (mut x2, mut y2) = ([0u8; C], [0u8; C]);
    assert_eq!(key.ecdh(other.as_public(), &mut x, &mut y), Ok(Some(())));
    assert_eq!(other.ecdh(key.as_public(), &mut x2, &mut y2), Ok(Some(())));
    assert_eq!((x, y), (x2, y2), "{name}");

    // ECDSA with digests shorter than, as long as, and longer than the order.
    let mut entropy = CruxCryptoProvider::from_entropy().unwrap();
    for len in [20, 32, 48, 64] {
        let digest: Vec<u8> = (0..len).map(|i| (i * 7 + 1) as u8).collect();
        let (mut r, mut s) = ([0u8; C], [0u8; C]);
        key.sign(&mut entropy, &digest, &mut r, &mut s).unwrap();
        assert_eq!(
            K::verify(&public(), &digest, &r, &s),
            Ok(true),
            "{name} {len}"
        );
        let mut other_digest = digest.clone();
        other_digest[0] ^= 1;
        assert_eq!(
            K::verify(&public(), &other_digest, &r, &s),
            Ok(false),
            "{name} {len}"
        );
        let mut bad_s = s;
        bad_s[C - 1] ^= 1;
        assert_eq!(
            K::verify(&public(), &digest, &r, &bad_s),
            Ok(false),
            "{name} {len}"
        );
        assert_eq!(
            K::verify(&public(), &digest, &[0; C], &s),
            Ok(false),
            "{name} {len}"
        );
        assert_eq!(
            K::verify(&public(), &digest, &r, &n),
            Ok(false),
            "{name} {len}"
        );
    }
}

#[test]
fn nist_p256() {
    check_curve::<P256, 32, 64>(&NIST_P256);
}

#[test]
fn nist_p384() {
    check_curve::<P384, 48, 96>(&NIST_P384);
}

#[test]
fn nist_p521() {
    check_curve::<P521, 66, 132>(&NIST_P521);
}

#[test]
fn weierstrass_curves() {
    check_curve::<<CruxCryptoProvider as Ecc>::NistP192, 24, 48>(&NIST_P192);
    check_curve::<<CruxCryptoProvider as Ecc>::NistP224, 28, 56>(&NIST_P224);
    check_curve::<<CruxCryptoProvider as Ecc>::BNP256, 32, 64>(&BN_P256);
    check_curve::<<CruxCryptoProvider as Ecc>::SM2P256, 32, 64>(&SM2_P256);
    check_curve::<<CruxCryptoProvider as Ecc>::BNP638, 80, 160>(&BN_P638);
}

/// Longer digests are truncated to their leftmost bytes, shorter ones are
/// zero-padded on the left, and equal-length digests are copied verbatim.
#[test]
fn ecdsa_prehash_truncates_and_pads() {
    let long: [u8; 48] = core::array::from_fn(|i| i as u8);
    assert_eq!(ecdsa_prehash::<32>(&long)[..], long[..32]);

    let short = [0xAAu8; 20];
    let padded = ecdsa_prehash::<32>(&short);
    assert_eq!(padded[..12], [0u8; 12]);
    assert_eq!(padded[12..], short);

    let exact = [0x55u8; 48];
    assert_eq!(ecdsa_prehash::<48>(&exact), exact);

    let sha512 = [0x77u8; 64];
    let p521 = ecdsa_prehash::<66>(&sha512);
    assert_eq!(p521[..2], [0u8; 2]);
    assert_eq!(p521[2..], sha512);
}

/// A P-256 signature over a truncated SHA-384 digest verifies against the
/// truncated digest, and the bytes beyond the order are ignored.
#[test]
fn ecdsa_p256_truncates_long_digests() {
    let key = P256::generate(&mut rng(b"p256"), ()).unwrap();
    let mut entropy = CruxCryptoProvider::from_entropy().unwrap();
    let d384: [u8; 48] = core::array::from_fn(|i| (i * 7) as u8);
    let (mut r, mut s) = ([0u8; 32], [0u8; 32]);
    key.sign(&mut entropy, &d384, &mut r, &mut s).unwrap();
    assert_eq!(P256::verify(key.as_public(), &d384[..32], &r, &s), Ok(true));
    let mut tail_changed = d384;
    tail_changed[47] ^= 1;
    assert_eq!(
        P256::verify(key.as_public(), &tail_changed, &r, &s),
        Ok(true)
    );
}

/// P-384 signatures over a SHA-512 digest are cross-checked with the `p384`
/// crate's own FIPS 186 handling of the full, untruncated digest.
#[test]
fn ecdsa_p384_matches_p384_crate() {
    let key = P384::generate(&mut rng(b"p384"), ()).unwrap();
    let d512: [u8; 64] = core::array::from_fn(|i| (255 - i) as u8);
    let (mut r, mut s) = ([0u8; 48], [0u8; 48]);
    key.sign(&mut rng(b"nonce"), &d512, &mut r, &mut s).unwrap();
    let mut q = [0u8; 96];
    P384::store_public(key.as_public(), &mut q).unwrap();
    let mut sec1 = [0u8; 97];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(&q);
    let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let sig = p384::ecdsa::Signature::from_scalars(r, s).unwrap();
    use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
    vk.verify_prehash(&d512, &sig).unwrap();
}

/// RFC 5903 section 8.1 (ECDH with NIST P-256).
#[test]
fn p256_ecdh_known_answer() {
    let i = hex!("c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433");
    let gr = hex!(
        "d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf63"
        "56fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab"
    );
    let gir = hex!(
        "d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de"
        "522bde0af0d8585b8def9c183b5ae38f50235206a8674ecb5d98edb20eb153a2"
    );
    let public = P256::load_public((), &gr).unwrap().unwrap();
    let mut q = [0u8; 64];
    P256::store_public(&public, &mut q).unwrap();
    assert_eq!(q, gr);
    let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
    assert_eq!(P256::mul_point(&public, &i, &mut x, &mut y), Ok(Some(())));
    assert_eq!((&x[..], &y[..]), (&gir[..32], &gir[32..]));
}

/// The dispatch layer (`EccPrivateKey`/`EccPublicKey`/`ecc_mul_generator`)
/// drives this backend.
#[test]
fn dispatch() {
    use tpm2::crypto::{
        EccCoordBuffer, EccPrivateKey, EccPublicKey, SignatureBuffer, ecc_mul_generator,
    };
    use tpm2::{TpmEccCurve, TpmiAlgHash, TpmtSigScheme};
    let mut r = rng(b"dispatch");
    for curve in [
        TpmEccCurve::NistP224,
        TpmEccCurve::NistP256,
        TpmEccCurve::NistP384,
        TpmEccCurve::NistP521,
        TpmEccCurve::BNP256,
    ] {
        let private = EccPrivateKey::<CruxCryptoProvider>::generate(&mut r, curve, None).unwrap();
        let digest = [3u8; 32];
        let mut sig_buf: SignatureBuffer = [0; _];
        let sig = private
            .sign(
                &mut r,
                TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256),
                &digest,
                &mut sig_buf,
            )
            .unwrap();
        let (mut x, mut y): (EccCoordBuffer, EccCoordBuffer) = ([0; _], [0; _]);
        let point = private.point(&mut x, &mut y).unwrap();
        let public = EccPublicKey::<CruxCryptoProvider>::load(curve, None, point)
            .unwrap()
            .unwrap();
        assert_eq!(public.verify(&digest, sig), Ok(true), "{curve:?}");
        let (mut x, mut y): (EccCoordBuffer, EccCoordBuffer) = ([0; _], [0; _]);
        assert!(
            ecc_mul_generator::<CruxCryptoProvider>(curve, &[1], &mut x, &mut y)
                .unwrap()
                .is_some(),
            "{curve:?}"
        );
    }
}
