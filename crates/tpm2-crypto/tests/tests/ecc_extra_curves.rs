//! NIST P-192, SM2 P-256 and BN P-638 through the `Ecc` contexts of the backend under test:
//! known-answer scalar multiplications, `k * G` against `point_multiply(k, G)`, point
//! validation, invalid scalars and the point at infinity.
//!
//! The curves are called through the trait methods (`nist_p192()`, `sm2_p256()`,
//! `bn_p638()`), not through `TpmEccCurve`, whose variants for these curves exist only with
//! the `tpm2` curve features, which this crate does not enable (they would widen the TPM).
//!
//! The known answers were computed independently of the backends: with Python integer
//! arithmetic (affine double-and-add), cross-checked against OpenSSL (`openssl ec` on SEC1
//! private keys) for NIST P-192 and SM2 P-256; the SM2 P-256 key pair is the example of
//! GB/T 32918.5-2017.

use hex_literal::hex;
use tpm2::crypto::ecc_params::{BN_P638, EccCurveParams, NIST_P192, SM2_P256};
use tpm2::crypto::{CryptoError, Ecc, EccCurve};
use tpm2_crypto_tests::TestProvider;

/// Known answers on one curve: `k1 * G`, `k2 * (k1 * G)` and `2 * G`.
struct Vectors<const N: usize> {
    params: &'static EccCurveParams,
    k1: [u8; N],
    k1_g: ([u8; N], [u8; N]),
    k2: [u8; N],
    k2_k1_g: ([u8; N], [u8; N]),
    g2: ([u8; N], [u8; N]),
}

const P192: Vectors<24> = Vectors {
    params: &NIST_P192,
    k1: hex!("e3071a87264d1d8487b5e77eb323b71be02a265d661cbc99"),
    k1_g: (
        hex!("94803c11f78947183d8b75df4c5976a47ed801d117dc1510"),
        hex!("b080b8a8d7c3920239dad8f1933ea6d8a1950f02a3ba4fd8"),
    ),
    k2: hex!("6a6b3067c942f4f928634eb74142119acd516005164c9710"),
    k2_k1_g: (
        hex!("f1921f4ba37866c28e4a10632dbcc096e7cc252645a84b0d"),
        hex!("469af3da9d45b2eb2f877138ef96f62b73275f051dcdd6e3"),
    ),
    g2: (
        hex!("dafebf5828783f2ad35534631588a3f629a70fb16982a888"),
        hex!("dd6bda0d993da0fa46b27bbc141b868f59331afa5c7e93ab"),
    ),
};

const SM2: Vectors<32> = Vectors {
    params: &SM2_P256,
    k1: hex!("9fdeccb1ec6e6db183eaeccb69a09ec0a4388a509cc025d6b28d141d0746e1f2"),
    k1_g: (
        hex!("1d722ea97e0f688dbb39ba30e45fce4c2acc0e9757d8d8f88a535d528babaef8"),
        hex!("6d30f9f5758fb4918f2cadc673e7fb49cf42b8b8da47038f2afac5184de86a43"),
    ),
    k2: hex!("3b491a7f5f62730ad32e3993dab6e8b23d42bfd0bc11725039dec5645cabb458"),
    k2_k1_g: (
        hex!("598641a2c1e27d8020914d35fb32ba3177f469b6b0ea32b92042eb894b4f8464"),
        hex!("678e334ccda18069ec0a9ff5b043981eac11b63e71e3eacacae2086b288faec9"),
    ),
    g2: (
        hex!("56cefd60d7c87c000d58ef57fa73ba4d9c0dfa08c08a7331495c2e1da3f2bd52"),
        hex!("31b7e7e6cc8189f668535ce0f8eaf1bd6de84c182f6c8e716f780d3a970a23c3"),
    ),
};

/// The example key pair of GB/T 32918.5-2017 (SM2 signature example): `d` and `d * G`.
const SM2_EXAMPLE_KEY: ([u8; 32], [u8; 32], [u8; 32]) = (
    hex!("3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"),
    hex!("09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020"),
    hex!("ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13"),
);

const BN638: Vectors<80> = Vectors {
    params: &BN_P638,
    k1: hex!(
        "1bec5ef6f4b8272e6b96c076b099455590e31171e26f00382fbadecfdfebf0257652d1dc80baf987c2e081ad7401a5ce5b33346e7ddc2c14e1202911699e728d08de735f5ee9b201fcedfb9918354857"
    ),
    k1_g: (
        hex!(
            "204d1c2a365f201ab3fb46dad5e33e6a3e8d6e2971a0925acaf75bfd4371e19fbca6910a7c5403e760535e3f64c96c9c9ee4b081b3771b5ccbe846a63b7a2eab217a3991fed1e04e6731e7ed0e2e8bb7"
        ),
        hex!(
            "1b07d7cf4ada162239fe32422e4ef71d2edfa1787d2ca82c3bf3ed3d9e212e4a95071be6762287cf1718fa70b21b0241eb9caac78d4a1923b29b96fa3a3aa209ddd6a544abecdf0bdd895054f99c65ff"
        ),
    ),
    k2: hex!(
        "05f0288c6357a96d8a209d6fc88e6cf3992e1a41613f4251a6da6df3c505a8afe521b195f8bccf33b06b573b5c902784a2cf00a2b4932d8ef5a75ea8be9a010427305fae8f5179b62d407b84b2fee6fb"
    ),
    k2_k1_g: (
        hex!(
            "0cf433ffafb95697145804790f3218a43c922ffad5da1902fe931b8c94b608f1a9eda0470ff617bfd32b042f2cd7f3df0ff1db13a326397a9794b9aec4a4ed784f7937d81f1cfcf58e3cb66a48c52661"
        ),
        hex!(
            "042064d1a55480ea775a984ee9c94b661b09a11790c93deaea16fdcf8f0d30f1ea5e178f3aa179999f9d1c1f13dd2ec88a7f916f9e90e554769a6990987b24173bb4897b77d886c3c12162e271810b5e"
        ),
    ),
    g2: (
        hex!(
            "1178fffee87000068d5fffdd0e0000e324fffcbaad740adb3e8fcbd685c067788bfef0a0b8044de91e7041314c907391e6fffab8c7fa9f4ce00000252120a8527b7ffffffffff6b7b800000000000034"
        ),
        hex!(
            "087ca7ff783580032ebeffef06b0006e5487fe694a3d2545f42266a9db76324232df7c2feec2173a43259faa70dbfdac3257fd6fad3d634ccb00001208e551c2346bfffffffffb7dc6c0000000000008"
        ),
    ),
};

/// `value - delta` for a big-endian `value >= delta`.
fn sub_small<const N: usize>(value: &[u8], delta: u8) -> [u8; N] {
    let mut out: [u8; N] = value.try_into().unwrap();
    let mut borrow = delta;
    for byte in out.iter_mut().rev() {
        let (d, b) = byte.overflowing_sub(borrow);
        *byte = d;
        borrow = u8::from(b);
        if borrow == 0 {
            break;
        }
    }
    out
}

/// `p - value` (the negation of a field element) for big-endian `value < p`.
fn negate<const N: usize>(p: &[u8], value: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut borrow = 0i16;
    for i in (0..N).rev() {
        let d = i16::from(p[i]) - i16::from(value[i]) - borrow;
        out[i] = d.rem_euclid(256) as u8;
        borrow = i16::from(d < 0);
    }
    out
}

/// Runs every check on one curve context.
fn check_curve<const N: usize>(c: &impl EccCurve<N>, v: &Vectors<N>) {
    let params = v.params;
    let gx: [u8; N] = params.gx.try_into().unwrap();
    let gy: [u8; N] = params.gy.try_into().unwrap();
    let p: [u8; N] = params.p.try_into().unwrap();
    let n: [u8; N] = params.n.try_into().unwrap();
    let mut two = [0u8; N];
    two[N - 1] = 2;
    let (mut x, mut y) = ([0u8; N], [0u8; N]);

    // Known answers: k1 * G, 2 * G, and k2 * (k1 * G) both ways.
    assert_eq!(
        c.point_multiply_generator(&v.k1, &mut x, &mut y),
        Ok(Some(()))
    );
    assert_eq!((x, y), v.k1_g);
    assert_eq!(
        c.point_multiply_generator(&two, &mut x, &mut y),
        Ok(Some(()))
    );
    assert_eq!((x, y), v.g2);
    assert_eq!(
        c.point_multiply(&v.k2, &v.k1_g.0, &v.k1_g.1, &mut x, &mut y),
        Ok(Some(()))
    );
    assert_eq!((x, y), v.k2_k1_g);
    assert_eq!(
        c.point_multiply(&v.k1, &gx, &gy, &mut x, &mut y),
        Ok(Some(()))
    );
    assert_eq!((x, y), v.k1_g);
    assert_eq!(
        c.point_multiply(&two, &gx, &gy, &mut x, &mut y),
        Ok(Some(()))
    );
    assert_eq!((x, y), v.g2);

    // (n - 1) * G = -G, the largest valid scalar.
    let n_minus_1 = sub_small::<N>(&n, 1);
    assert_eq!(
        c.point_multiply_generator(&n_minus_1, &mut x, &mut y),
        Ok(Some(()))
    );
    assert_eq!((x, y), (gx, negate(&p, &gy)));
    assert_eq!(
        c.point_multiply(&n_minus_1, &gx, &gy, &mut x, &mut y),
        Ok(Some(()))
    );
    assert_eq!((x, y), (gx, negate(&p, &gy)));

    // Point validation.
    for (px, py) in [(gx, gy), v.k1_g, v.k2_k1_g, v.g2, (gx, negate(&p, &gy))] {
        assert_eq!(c.validate_point(&px, &py), Ok(true));
    }
    let mut off_curve = v.k1_g.1;
    off_curve[N - 1] ^= 1;
    assert_eq!(c.validate_point(&v.k1_g.0, &off_curve), Ok(false));
    assert_eq!(c.validate_point(&[0; N], &[0; N]), Ok(false));
    assert_eq!(c.validate_point(&p, &gy), Ok(false));
    assert_eq!(c.validate_point(&gx, &p), Ok(false));
    assert_eq!(c.validate_point(&[0xff; N], &gy), Ok(false));

    // Invalid input points give no result.
    for (px, py) in [(v.k1_g.0, off_curve), (p, gy), (gx, p), ([0; N], [0; N])] {
        assert_eq!(c.point_multiply(&v.k1, &px, &py, &mut x, &mut y), Ok(None));
    }

    // Invalid scalars (0, n, n + 1 for the larger curves, all ones) give no result; n * P
    // would be the point at infinity.
    let mut bad_scalars = vec![[0u8; N], n, [0xff; N]];
    if n[N - 1] < 0xff {
        let mut n_plus_1 = n;
        n_plus_1[N - 1] += 1;
        bad_scalars.push(n_plus_1);
    }
    for k in &bad_scalars {
        assert_eq!(c.point_multiply_generator(k, &mut x, &mut y), Ok(None));
        assert_eq!(c.point_multiply(k, &gx, &gy, &mut x, &mut y), Ok(None));
        assert_eq!(
            c.point_multiply(k, &v.k1_g.0, &v.k1_g.1, &mut x, &mut y),
            Ok(None)
        );
    }

    // k * G = point_multiply(k, G) for a range of scalars.
    let mut k = v.k2;
    for i in 0..8u8 {
        k[0] = k[0].wrapping_add(i) & (n[0] >> 1);
        k[N - 1] ^= i;
        let (mut x1, mut y1, mut x2, mut y2) = ([0u8; N], [0u8; N], [0u8; N], [0u8; N]);
        assert_eq!(
            c.point_multiply_generator(&k, &mut x1, &mut y1),
            Ok(Some(()))
        );
        assert_eq!(
            c.point_multiply(&k, &gx, &gy, &mut x2, &mut y2),
            Ok(Some(()))
        );
        assert_eq!((x1, y1), (x2, y2));
        assert_eq!(c.validate_point(&x1, &y1), Ok(true));
    }

    // ECDAA signing is computed by the engine.
    assert_eq!(
        c.ecdaa_sign(&v.k1, &[], &[], &v.k2, &[0; 32], &mut x, &mut y),
        Err(CryptoError::Unsupported)
    );
}

/// NIST P-192: known answers, validation, invalid scalars and points.
#[test]
fn nist_p192_point_operations() {
    check_curve(&TestProvider.nist_p192().unwrap(), &P192);
}

/// SM2 P-256: known answers (including the GB/T 32918.5 example key pair), validation,
/// invalid scalars and points.
#[test]
fn sm2_p256_point_operations() {
    let c = TestProvider.sm2_p256().unwrap();
    check_curve(&c, &SM2);
    let (d, qx, qy) = SM2_EXAMPLE_KEY;
    let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
    assert_eq!(c.point_multiply_generator(&d, &mut x, &mut y), Ok(Some(())));
    assert_eq!((x, y), (qx, qy));
}

/// BN P-638: known answers, validation, invalid scalars and points.
#[test]
fn bn_p638_point_operations() {
    check_curve(&TestProvider.bn_p638().unwrap(), &BN638);
}
