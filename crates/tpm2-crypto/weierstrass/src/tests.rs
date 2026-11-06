//! Unit tests of the generic curve arithmetic, with known answers computed independently
//! (Python integer arithmetic, and OpenSSL for NIST P-192 and SM2 P-256).

use super::*;
use hex_literal::hex;

/// `2 * G` and `k * G` of each curve.
struct Kat<const N: usize> {
    g2: ([u8; N], [u8; N]),
    k: [u8; N],
    kg: ([u8; N], [u8; N]),
}

const P192: Kat<24> = Kat {
    g2: (
        hex!("dafebf5828783f2ad35534631588a3f629a70fb16982a888"),
        hex!("dd6bda0d993da0fa46b27bbc141b868f59331afa5c7e93ab"),
    ),
    k: hex!("e3071a87264d1d8487b5e77eb323b71be02a265d661cbc99"),
    kg: (
        hex!("94803c11f78947183d8b75df4c5976a47ed801d117dc1510"),
        hex!("b080b8a8d7c3920239dad8f1933ea6d8a1950f02a3ba4fd8"),
    ),
};

const SM2: Kat<32> = Kat {
    g2: (
        hex!("56cefd60d7c87c000d58ef57fa73ba4d9c0dfa08c08a7331495c2e1da3f2bd52"),
        hex!("31b7e7e6cc8189f668535ce0f8eaf1bd6de84c182f6c8e716f780d3a970a23c3"),
    ),
    // The example key pair of GB/T 32918.5-2017 (the SM2 signature example).
    k: hex!("3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"),
    kg: (
        hex!("09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020"),
        hex!("ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13"),
    ),
};

const BN638: Kat<80> = Kat {
    g2: (
        hex!(
            "1178fffee87000068d5fffdd0e0000e324fffcbaad740adb3e8fcbd685c067788bfef0a0b8044de91e7041314c907391e6fffab8c7fa9f4ce00000252120a8527b7ffffffffff6b7b800000000000034"
        ),
        hex!(
            "087ca7ff783580032ebeffef06b0006e5487fe694a3d2545f42266a9db76324232df7c2feec2173a43259faa70dbfdac3257fd6fad3d634ccb00001208e551c2346bfffffffffb7dc6c0000000000008"
        ),
    ),
    k: hex!(
        "1bec5ef6f4b8272e6b96c076b099455590e31171e26f00382fbadecfdfebf0257652d1dc80baf987c2e081ad7401a5ce5b33346e7ddc2c14e1202911699e728d08de735f5ee9b201fcedfb9918354857"
    ),
    kg: (
        hex!(
            "204d1c2a365f201ab3fb46dad5e33e6a3e8d6e2971a0925acaf75bfd4371e19fbca6910a7c5403e760535e3f64c96c9c9ee4b081b3771b5ccbe846a63b7a2eab217a3991fed1e04e6731e7ed0e2e8bb7"
        ),
        hex!(
            "1b07d7cf4ada162239fe32422e4ef71d2edfa1787d2ca82c3bf3ed3d9e212e4a95071be6762287cf1718fa70b21b0241eb9caac78d4a1923b29b96fa3a3aa209ddd6a544abecdf0bdd895054f99c65ff"
        ),
    ),
};

/// The affine coordinates of `p`, or `None` for the point at infinity.
fn affine<const LIMBS: usize>(c: &Curve<LIMBS>, p: &Point<LIMBS>) -> Option<(Vec<u8>, Vec<u8>)> {
    let (mut x, mut y) = (vec![0; c.size()], vec![0; c.size()]);
    c.write_affine(p, &mut x, &mut y).unwrap().map(|()| (x, y))
}

/// The scalar `n - delta` as an integer.
fn n_minus<const LIMBS: usize>(c: &Curve<LIMBS>, delta: u64) -> Uint<LIMBS> {
    c.n.wrapping_sub(&Uint::from_u64(delta))
}

/// Checks the arithmetic identities and known answers of one curve.
fn check_curve<const LIMBS: usize, const N: usize>(c: &Curve<LIMBS>, kat: &Kat<N>) {
    assert_eq!(c.size(), N);
    let g = c.g;
    let params = c.params();
    assert_eq!(c.validate_point(params.gx, params.gy), Ok(true));

    // 2G by the complete formulas, by the ladder and as known answer.
    let g2 = affine(c, &c.add(&g, &g)).unwrap();
    assert_eq!(g2, (kat.g2.0.to_vec(), kat.g2.1.to_vec()));
    assert_eq!(affine(c, &c.multiply(&Uint::from_u64(2), &g)).unwrap(), g2);
    // G + 2G = 3G, by addition of distinct points and by the ladder.
    let g2_point = c.multiply(&Uint::from_u64(2), &g);
    let g3 = affine(c, &c.add(&g, &g2_point)).unwrap();
    assert_eq!(affine(c, &c.multiply(&Uint::from_u64(3), &g)).unwrap(), g3);
    assert_eq!(c.validate_point(&g3.0, &g3.1), Ok(true));

    // The point at infinity: n * G, G + (n - 1) * G, and the identity as an operand.
    assert_eq!(affine(c, &c.multiply(&c.n, &g)), None);
    let minus_g = c.multiply(&n_minus(c, 1), &g);
    let (mx, my) = affine(c, &minus_g).unwrap();
    assert_eq!(mx, params.gx);
    let neg_gy = c.p.wrapping_sub(&decode(params.gy).unwrap());
    let mut neg_gy_bytes = vec![0; N];
    encode(&neg_gy, &mut neg_gy_bytes).unwrap();
    assert_eq!(my, neg_gy_bytes);
    assert_eq!(affine(c, &c.add(&g, &minus_g)), None);
    assert_eq!(
        affine(c, &c.add(&c.identity(), &g)).unwrap(),
        (params.gx.to_vec(), params.gy.to_vec())
    );
    assert_eq!(affine(c, &c.add(&c.identity(), &c.identity())), None);

    // Known answer k * G, and k * G through the public point multiplication.
    let (mut x, mut y) = ([0u8; N], [0u8; N]);
    assert_eq!(
        c.point_multiply_generator(&kat.k, &mut x, &mut y),
        Ok(Some(()))
    );
    assert_eq!((x, y), kat.kg);
    let (mut x2, mut y2) = ([0u8; N], [0u8; N]);
    assert_eq!(
        c.point_multiply(&kat.k, params.gx, params.gy, &mut x2, &mut y2),
        Ok(Some(()))
    );
    assert_eq!((x2, y2), kat.kg);

    // Invalid scalars: 0, n and all-ones.
    let mut n_bytes = [0u8; N];
    encode(&c.n, &mut n_bytes).unwrap();
    for bad in [[0u8; N], n_bytes, [0xff; N]] {
        assert_eq!(c.point_multiply_generator(&bad, &mut x, &mut y), Ok(None));
        assert_eq!(
            c.point_multiply(&bad, &kat.kg.0, &kat.kg.1, &mut x, &mut y),
            Ok(None)
        );
    }
    // n - 1 is the largest valid scalar.
    let mut nm1 = [0u8; N];
    encode(&n_minus(c, 1), &mut nm1).unwrap();
    assert_eq!(
        c.point_multiply_generator(&nm1, &mut x, &mut y),
        Ok(Some(()))
    );
    assert_eq!((x.to_vec(), y.to_vec()), (mx, my));

    // Invalid points: off the curve, and coordinates not smaller than p (also p + gx, which
    // reduces to a point on the curve).
    let mut off = kat.kg.1;
    off[N - 1] ^= 1;
    assert_eq!(c.validate_point(&kat.kg.0, &off), Ok(false));
    assert_eq!(
        c.point_multiply(&kat.k, &kat.kg.0, &off, &mut x, &mut y),
        Ok(None)
    );
    assert_eq!(c.validate_point(params.p, params.gy), Ok(false));
    assert_eq!(c.validate_point(params.gx, params.p), Ok(false));
    let (gx_plus_p, overflow) = decode::<LIMBS>(params.gx).unwrap().adc(&c.p, Limb::ZERO);
    if overflow == Limb::ZERO {
        let mut bytes = [0u8; N];
        encode(&gx_plus_p, &mut bytes).unwrap();
        assert_eq!(c.validate_point(&bytes, params.gy), Ok(false));
        assert_eq!(
            c.point_multiply(&kat.k, &bytes, params.gy, &mut x, &mut y),
            Ok(None)
        );
    }
    assert_eq!(c.validate_point(&[0xff; N], &[0xff; N]), Ok(false));
    // Wrong buffer sizes are internal errors.
    assert_eq!(
        c.validate_point(&kat.kg.0[1..], &kat.kg.1[1..]),
        Err(CryptoError::Internal)
    );
    assert_eq!(
        c.point_multiply_generator(&kat.k, &mut x[1..], &mut y),
        Err(CryptoError::Internal)
    );
}

/// NIST P-192: arithmetic identities, known answers and input validation.
#[test]
fn nist_p192_arithmetic() {
    check_curve(&Curve::<{ U192::LIMBS }>::new(&NIST_P192).unwrap(), &P192);
}

/// SM2 P-256: arithmetic identities, known answers and input validation.
#[test]
fn sm2_p256_arithmetic() {
    check_curve(&Curve::<{ U256::LIMBS }>::new(&SM2_P256).unwrap(), &SM2);
}

/// BN P-638: arithmetic identities, known answers and input validation.
#[test]
fn bn_p638_arithmetic() {
    check_curve(&Curve::<{ U640::LIMBS }>::new(&BN_P638).unwrap(), &BN638);
}

/// A curve whose size does not match the instantiation is rejected.
#[test]
fn mismatched_curve_is_rejected() {
    assert!(Curve::<{ U192::LIMBS }>::new(&BN_P638).is_err());
    assert!(Curve::<{ U192::LIMBS }>::new(&NIST_P224).is_err());
    // A larger instantiation is accepted (NIST P-224 has 28-byte coordinates).
    assert_eq!(
        Curve::<{ U256::LIMBS }>::new(&NIST_P192).unwrap().size(),
        24
    );
    assert_eq!(
        Curve::<{ U256::LIMBS }>::new(&NIST_P224).unwrap().size(),
        28
    );
}

/// A deterministic random number generator: SplitMix64 from a seed.
struct TestRng(u64);

impl Rng for TestRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        for byte in out {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            *byte = (z ^ (z >> 31)) as u8;
        }
        Ok(())
    }

    fn stir_bytes(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        for &byte in data {
            self.0 = self.0.rotate_left(8) ^ u64::from(byte);
        }
        Ok(())
    }
}

/// A random number generator that only yields zeros.
struct Zeros;

impl Rng for Zeros {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        out.fill(0);
        Ok(())
    }

    fn stir_bytes(&mut self, _: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

/// A random number generator that fails.
struct Failing;

impl Rng for Failing {
    fn fill_bytes(&mut self, _: &mut [u8]) -> Result<(), CryptoError> {
        Err(CryptoError::Internal)
    }

    fn stir_bytes(&mut self, _: &[u8]) -> Result<(), CryptoError> {
        Err(CryptoError::Internal)
    }
}

/// Key generation, loading and storing, ECDSA, SM2, ECDH and the point multiplications of the
/// key type `K` (the backend traits).
fn check_key_type<K, const COORD: usize, const POINT: usize>(n: &[u8])
where
    K: EccCurve<COORD, POINT, TestRng>
        + EccCurve<COORD, POINT, Zeros>
        + EccCurve<COORD, POINT, Failing>
        + PrivateKey<
            POINT,
            COORD,
            TestRng,
            PublicKey = <K as PrivateKey<POINT, COORD, Zeros>>::PublicKey,
        > + PrivateKey<
            POINT,
            COORD,
            Failing,
            PublicKey = <K as PrivateKey<POINT, COORD, Zeros>>::PublicKey,
        >,
    <K as PrivateKey<POINT, COORD, Zeros>>::PublicKey: Clone + PartialEq + core::fmt::Debug,
{
    type Pub<K, const C: usize, const P: usize> = <K as PrivateKey<P, C, Zeros>>::PublicKey;
    let store = |k: &K| {
        let (mut d, mut q) = ([0u8; COORD], [0u8; POINT]);
        PrivateKey::<POINT, COORD, TestRng>::store(k, &mut d).unwrap();
        let public = PrivateKey::<POINT, COORD, TestRng>::as_public(k);
        <K as PrivateKey<POINT, COORD, TestRng>>::store_public(public, &mut q).unwrap();
        (d, q)
    };
    // Deterministic in the random bytes, with a private scalar in `[1, n - 1]`.
    let key = <K as PrivateKey<POINT, COORD, TestRng>>::generate(&mut TestRng(1), ()).unwrap();
    let (d, q) = store(&key);
    assert_eq!(
        store(&<K as PrivateKey<POINT, COORD, TestRng>>::generate(&mut TestRng(1), ()).unwrap()),
        (d, q)
    );
    assert_ne!(
        store(&<K as PrivateKey<POINT, COORD, TestRng>>::generate(&mut TestRng(2), ()).unwrap()).1,
        q
    );
    assert!(d[COORD - n.len()..] < *n && d.iter().any(|&b| b != 0));
    // Random number generators that never yield a valid scalar, or fail.
    assert!(matches!(
        <K as PrivateKey<POINT, COORD, Zeros>>::generate(&mut Zeros, ()),
        Err(CryptoError::Internal)
    ));
    assert!(matches!(
        <K as PrivateKey<POINT, COORD, Failing>>::generate(&mut Failing, ()),
        Err(CryptoError::Internal)
    ));

    // The public key is `[d]G`, and loads back; a scalar of another key does not.
    let (mut x, mut y) = ([0u8; COORD], [0u8; COORD]);
    assert_eq!(
        <K as EccCurve<COORD, POINT, TestRng>>::mul_generator(&d, &mut x, &mut y),
        Ok(Some(()))
    );
    assert_eq!((&x[..], &y[..]), (&q[..COORD], &q[COORD..]));
    let public: Pub<K, COORD, POINT> =
        <K as PrivateKey<POINT, COORD, TestRng>>::load_public((), &q)
            .unwrap()
            .unwrap();
    let loaded = <K as PrivateKey<POINT, COORD, TestRng>>::load(public.clone(), &d)
        .unwrap()
        .unwrap();
    assert_eq!(store(&loaded), (d, q));
    let other = <K as PrivateKey<POINT, COORD, TestRng>>::generate(&mut TestRng(3), ()).unwrap();
    let (d2, q2) = store(&other);
    assert!(
        <K as PrivateKey<POINT, COORD, TestRng>>::load(public.clone(), &d2)
            .unwrap()
            .is_none()
    );
    assert!(
        <K as PrivateKey<POINT, COORD, TestRng>>::load(public.clone(), &[0; COORD])
            .unwrap()
            .is_none()
    );
    let mut off = q;
    off[POINT - 1] ^= 1;
    assert!(
        <K as PrivateKey<POINT, COORD, TestRng>>::load_public((), &off)
            .unwrap()
            .is_none()
    );

    // ECDH is symmetric, and `mul_point` computes the same point.
    let public2 = <K as PrivateKey<POINT, COORD, TestRng>>::load_public((), &q2)
        .unwrap()
        .unwrap();
    let (mut zx, mut zy) = ([0u8; COORD], [0u8; COORD]);
    let (mut zx2, mut zy2) = ([0u8; COORD], [0u8; COORD]);
    assert_eq!(
        <K as EccCurve<COORD, POINT, TestRng>>::ecdh(&key, &public2, &mut zx, &mut zy),
        Ok(Some(()))
    );
    assert_eq!(
        <K as EccCurve<COORD, POINT, TestRng>>::ecdh(&other, &public, &mut zx2, &mut zy2),
        Ok(Some(()))
    );
    assert_eq!((zx, zy), (zx2, zy2));
    assert_eq!(
        <K as EccCurve<COORD, POINT, TestRng>>::mul_point(&public2, &d, &mut zx2, &mut zy2),
        Ok(Some(()))
    );
    assert_eq!((zx, zy), (zx2, zy2));
    assert_eq!(
        <K as EccCurve<COORD, POINT, TestRng>>::mul_point(
            &public2,
            &[0; COORD],
            &mut zx2,
            &mut zy2
        ),
        Ok(None)
    );

    // ECDSA and SM2 signatures verify, and fail for another digest, key or signature.
    for digest in [&[0x5a; 20][..], &[0xa5; 32], &[0x3c; 48], &[0xc3; 64]] {
        let (mut r, mut s) = ([0u8; COORD], [0u8; COORD]);
        <K as EccCurve<COORD, POINT, TestRng>>::sign(&key, &mut TestRng(4), digest, &mut r, &mut s)
            .unwrap();
        let verify = |p: &Pub<K, COORD, POINT>, digest: &[u8], r: &[u8; COORD], s: &[u8; COORD]| {
            <K as EccCurve<COORD, POINT, TestRng>>::verify(p, digest, r, s).unwrap()
        };
        assert!(verify(&public, digest, &r, &s));
        assert!(!verify(&public2, digest, &r, &s));
        assert!(!verify(&public, &[0x11; 32], &r, &s));
        assert!(!verify(&public, digest, &s, &r));
        assert!(!verify(&public, digest, &[0; COORD], &s));
        assert!(!verify(&public, digest, &r, &[0xff; COORD]));

        <K as EccCurve<COORD, POINT, TestRng>>::sm2_sign(
            &key,
            &mut TestRng(5),
            digest,
            &mut r,
            &mut s,
        )
        .unwrap();
        let sm2_verify =
            |p: &Pub<K, COORD, POINT>, digest: &[u8], r: &[u8; COORD], s: &[u8; COORD]| {
                <K as EccCurve<COORD, POINT, TestRng>>::sm2_verify(p, digest, r, s).unwrap()
            };
        assert!(sm2_verify(&public, digest, &r, &s));
        assert!(!sm2_verify(&public2, digest, &r, &s));
        assert!(!sm2_verify(&public, &[0x11; 32], &r, &s));
        assert!(!sm2_verify(&public, digest, &[0; COORD], &s));
    }
}

/// The key types of all curves of this crate.
#[test]
fn key_types() {
    check_key_type::<NistP192, 24, 48>(NIST_P192.n);
    check_key_type::<NistP224, 28, 56>(NIST_P224.n);
    check_key_type::<BnP256, 32, 64>(BN_P256.n);
    check_key_type::<BnP638, 80, 160>(BN_P638.n);
    check_key_type::<Sm2P256, 32, 64>(SM2_P256.n);
}

/// Yields `k` (once) as the per-message secret of a signature.
struct FixedK<'a>(&'a [u8]);

impl Rng for FixedK<'_> {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        out.copy_from_slice(self.0);
        Ok(())
    }

    fn stir_bytes(&mut self, _: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

/// `SHA-256("sample")`, the message of the examples of RFC 6979.
const SHA256_SAMPLE: [u8; 32] =
    hex!("af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf");

/// Signs `digest` with the secret scalar `d` and the per-message secret `k`, and checks `(r, s)`.
fn check_ecdsa<K, const COORD: usize, const POINT: usize>(
    d: [u8; COORD],
    digest: &[u8],
    k: [u8; COORD],
    rs: ([u8; COORD], [u8; COORD]),
    sm2: bool,
) where
    K: for<'a> EccCurve<COORD, POINT, FixedK<'a>>,
{
    let key = <K as PrivateKey<POINT, COORD, FixedK<'_>>>::load(
        {
            let (mut q, mut x, mut y) = ([0u8; POINT], [0u8; COORD], [0u8; COORD]);
            <K as EccCurve<COORD, POINT, FixedK<'_>>>::mul_generator(&d, &mut x, &mut y)
                .unwrap()
                .unwrap();
            q[..COORD].copy_from_slice(&x);
            q[COORD..].copy_from_slice(&y);
            <K as PrivateKey<POINT, COORD, FixedK<'_>>>::load_public((), &q)
                .unwrap()
                .unwrap()
        },
        &d,
    )
    .unwrap()
    .unwrap();
    let (mut r, mut s) = ([0u8; COORD], [0u8; COORD]);
    if sm2 {
        key.sm2_sign(&mut FixedK(&k), digest, &mut r, &mut s)
            .unwrap();
    } else {
        key.sign(&mut FixedK(&k), digest, &mut r, &mut s).unwrap();
    }
    assert_eq!((r, s), rs);
}

/// ECDSA known answers: the NIST P-192 and P-224 examples of RFC 6979 (A.2.3 and A.2.4, SHA-256,
/// "sample"; P-224 also truncates the digest), and the SM2 signature example of GM/T 0003.5-2012.
#[test]
fn signature_known_answers() {
    check_ecdsa::<NistP192, 24, 48>(
        hex!("6fab034934e4c0fc9ae67f5b5659a9d7d1fefd187ee09fd4"),
        &SHA256_SAMPLE,
        hex!("32b1b6d7d42a05cb449065727a84804fb1a3e34d8f261496"),
        (
            hex!("4b0b8ce98a92866a2820e20aa6b75b56382e0f9bfd5ecb55"),
            hex!("ccdb006926ea9565cbadc840829d8c384e06de1f1e381b85"),
        ),
        false,
    );
    check_ecdsa::<NistP224, 28, 56>(
        hex!("f220266e1105bfe3083e03ec7a3a654651f45e37167e88600bf257c1"),
        &SHA256_SAMPLE,
        hex!("ad3029e0278f80643de33917ce6908c70a8ff50a411f06e41dedfcdc"),
        (
            hex!("61aa3da010e8e8406c656bc477a7a7189895e7e840cdfe8ff42307ba"),
            hex!("bc814050dab5d23770879494f9e0a680dc1af7161991bde692b10101"),
        ),
        false,
    );
    check_ecdsa::<Sm2P256, 32, 64>(
        SM2.k,
        &hex!("f0b43e94ba45accaace692ed534382eb17e6ab5a19ce7b31f4486fdfc0d28640"),
        hex!("59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21"),
        (
            hex!("f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3"),
            hex!("b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa"),
        ),
        true,
    );
}
