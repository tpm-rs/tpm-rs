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
    let (mut x, mut y) = (
        vec![0; Curve::<LIMBS>::BYTES],
        vec![0; Curve::<LIMBS>::BYTES],
    );
    c.write_affine(p, &mut x, &mut y).unwrap().map(|()| (x, y))
}

/// The scalar `n - delta` as an integer.
fn n_minus<const LIMBS: usize>(c: &Curve<LIMBS>, delta: u64) -> Uint<LIMBS> {
    c.n.wrapping_sub(&Uint::from_u64(delta))
}

/// Checks the arithmetic identities and known answers of one curve.
fn check_curve<const LIMBS: usize, const N: usize>(c: &Curve<LIMBS>, kat: &Kat<N>) {
    assert_eq!(Curve::<LIMBS>::BYTES, N);
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
    check_curve(&nist_p192().unwrap(), &P192);
}

/// SM2 P-256: arithmetic identities, known answers and input validation.
#[test]
fn sm2_p256_arithmetic() {
    check_curve(&sm2_p256().unwrap(), &SM2);
}

/// BN P-638: arithmetic identities, known answers and input validation.
#[test]
fn bn_p638_arithmetic() {
    check_curve(&bn_p638().unwrap(), &BN638);
}

/// A curve whose size does not match the instantiation is rejected.
#[test]
fn mismatched_curve_is_rejected() {
    assert!(Curve::<{ U256::LIMBS }>::new(&NIST_P192).is_err());
    assert!(Curve::<{ U192::LIMBS }>::new(&BN_P638).is_err());
}

/// A deterministic byte source: SplitMix64 from `seed`.
fn source(seed: u64) -> impl FnMut(&mut [u8]) -> Result<(), CryptoError> {
    let mut state = seed;
    move |buf: &mut [u8]| {
        for byte in buf {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            *byte = (z ^ (z >> 31)) as u8;
        }
        Ok(())
    }
}

/// Key generation: deterministic in the random bytes, a private scalar in `[1, n - 1]` and a
/// matching public point on the curve.
#[test]
fn key_generation() {
    for (id, size) in [(0x0001u16, 24usize), (0x0020, 32), (0x0011, 80)] {
        let gen_key = |seed: u64| {
            let (mut public, mut private) = ([0u8; 160], [0u8; 80]);
            let lens = generate_key(id, &mut source(seed), &mut public, &mut private)
                .unwrap()
                .unwrap();
            (lens, public, private)
        };
        let (lens, public, private) = gen_key(1);
        assert_eq!(lens, (2 * size, size));
        assert_eq!(gen_key(1), (lens, public, private));
        assert_ne!(gen_key(2).1, public);
        assert!(public[2 * size..].iter().all(|&b| b == 0));
        assert!(private[size..].iter().all(|&b| b == 0));
        let n = match id {
            0x0001 => NIST_P192.n,
            0x0020 => SM2_P256.n,
            _ => BN_P638.n,
        };
        assert!(private[..size] < *n && private[..size].iter().any(|&b| b != 0));
        let (mut x, mut y) = ([0u8; 80], [0u8; 80]);
        let ok = match id {
            0x0001 => nist_p192().unwrap().point_multiply_generator(
                &private[..size],
                &mut x[..size],
                &mut y[..size],
            ),
            0x0020 => sm2_p256().unwrap().point_multiply_generator(
                &private[..size],
                &mut x[..size],
                &mut y[..size],
            ),
            _ => bn_p638().unwrap().point_multiply_generator(
                &private[..size],
                &mut x[..size],
                &mut y[..size],
            ),
        };
        assert_eq!(ok, Ok(Some(())));
        assert_eq!(
            (&x[..size], &y[..size]),
            (&public[..size], &public[size..2 * size])
        );

        // Output buffers that are too small, and byte sources that never yield a valid scalar.
        let (mut public, mut private) = ([0u8; 160], [0u8; 80]);
        assert_eq!(
            generate_key(
                id,
                &mut source(1),
                &mut public[..2 * size - 1],
                &mut private
            ),
            Some(Err(CryptoError::Internal))
        );
        assert_eq!(
            generate_key(id, &mut source(1), &mut public, &mut private[..size - 1]),
            Some(Err(CryptoError::Internal))
        );
        let mut zeros = |buf: &mut [u8]| {
            buf.fill(0);
            Ok(())
        };
        assert_eq!(
            generate_key(id, &mut zeros, &mut public, &mut private),
            Some(Err(CryptoError::Internal))
        );
        let mut failing = |_: &mut [u8]| Err(CryptoError::Internal);
        assert_eq!(
            generate_key(id, &mut failing, &mut public, &mut private),
            Some(Err(CryptoError::Internal))
        );
    }
    // Other curves are not handled by this crate.
    assert_eq!(
        generate_key(0x0003, &mut source(1), &mut [0; 64], &mut [0; 32]),
        None
    );
}
