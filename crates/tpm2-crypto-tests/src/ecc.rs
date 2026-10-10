//! Tests for [`Ecc`] keys and ECDH.

use tpm2::{
    Tpm2bEccParameter, TpmEccCurve, TpmsEccPoint,
    crypto::{Ecc, EccPrivateKey, EccPublicKey},
};

use crate::{
    Caps, Check, expect_support,
    util::{add_be, assert_bytes, seeded_rng},
    vectors::ecc as kat,
};

/// The curves tested by this crate: every short Weierstrass curve.
///
/// Curve25519 and Curve448 are only used by EdDSA, which the [`Ecc`] trait
/// doesn't cover.
pub const CURVES: &[TpmEccCurve] = &[
    TpmEccCurve::NistP192,
    TpmEccCurve::NistP224,
    TpmEccCurve::NistP256,
    TpmEccCurve::NistP384,
    TpmEccCurve::NistP521,
    TpmEccCurve::BNP256,
    TpmEccCurve::BNP638,
    TpmEccCurve::SM2P256,
    TpmEccCurve::BpP256R1,
    TpmEccCurve::BpP384R1,
    TpmEccCurve::BpP512R1,
];

/// Builds a [`TpmsEccPoint`] from its coordinates.
fn tpms_point<'a>(x: &'a [u8], y: &'a [u8]) -> TpmsEccPoint<'a> {
    TpmsEccPoint {
        x: Tpm2bEccParameter::new(x).expect("x coordinate too long"),
        y: Tpm2bEccParameter::new(y).expect("y coordinate too long"),
    }
}

/// Returns the coordinates of `key`.
pub(crate) fn point<K: EccPublicKey>(key: &K) -> (Vec<u8>, Vec<u8>) {
    let (mut x, mut y) = (
        [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
        [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    );
    let point = key.point(&mut x, &mut y).check("EccPublicKey::point");
    (point.x.as_slice().to_vec(), point.y.as_slice().to_vec())
}

/// Returns the secret scalar of `key`.
pub(crate) fn scalar<K: EccPrivateKey>(key: &K) -> Vec<u8> {
    let mut out = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    key.scalar(&mut out)
        .check("EccPrivateKey::scalar")
        .as_slice()
        .to_vec()
}

/// Loads a public key on a supported curve, returning `None` if it is rejected.
pub(crate) fn load_point<C: Ecc>(
    c: &C,
    curve: TpmEccCurve,
    x: &[u8],
    y: &[u8],
) -> Option<C::PublicKey> {
    Ecc::load_public(c, curve, tpms_point(x, y)).check(format!("Ecc::load_public {curve:?}"))
}

/// Loads a private key, returning `None` if it is rejected.
pub(crate) fn load_private<C: Ecc>(c: &C, public: C::PublicKey, d: &[u8]) -> Option<C::PrivateKey> {
    let d = Tpm2bEccParameter::new(d).expect("scalar too long");
    Ecc::load_private(c, public, d).check("Ecc::load_private")
}

/// Generates a key on `curve`, or returns `None` if the curve is (correctly)
/// unsupported.
pub(crate) fn generate<C: Ecc>(
    c: &C,
    caps: &Caps,
    rng: &mut C::Rng,
    curve: TpmEccCurve,
) -> Option<C::PrivateKey> {
    let result = Ecc::generate_key(c, rng, curve);
    expect_support(caps.curves.contains(&curve), format!("{curve:?}"), result)
}

/// Computes the ECDH shared point.
pub(crate) fn ecdh<C: Ecc>(
    c: &C,
    private: &C::PrivateKey,
    peer: &C::PublicKey,
) -> (Vec<u8>, Vec<u8>) {
    let (mut x, mut y) = (
        [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
        [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    );
    let z = Ecc::ecdh(c, private, peer, &mut x, &mut y).check("Ecc::ecdh");
    let z = z.expect("ECDH produced the point at infinity");
    (z.x.as_slice().to_vec(), z.y.as_slice().to_vec())
}

/// Generated keys are on the requested curve, have full-size coordinates and
/// scalars, and round-trip through [`Ecc::load_public`] and
/// [`Ecc::load_private`]. Unsupported curves fail to load and generate.
pub fn ecc_generate_and_load<C: Ecc>(c: &C, caps: &Caps) {
    let mut rng = seeded_rng(c, "ecc_generate_and_load");
    for &curve in CURVES {
        let Some(key) = generate(c, caps, &mut rng, curve) else {
            let result = Ecc::load_public(c, curve, tpms_point(&[1], &[2]));
            expect_support(false, format!("Ecc::load_public {curve:?}"), result);
            continue;
        };
        let size = curve.key_bytes();
        assert_eq!(key.public_key().curve(), curve);
        let (x, y) = point(key.public_key());
        assert_eq!(
            (x.len(), y.len()),
            (size, size),
            "{curve:?}: coordinate sizes"
        );
        let d = scalar(&key);
        assert_eq!(d.len(), size, "{curve:?}: scalar size");

        let public = load_point(c, curve, &x, &y).expect("generated point rejected");
        assert_eq!(public.curve(), curve);
        assert_eq!(
            point(&public),
            (x.clone(), y.clone()),
            "{curve:?}: loaded point"
        );
        let private = load_private(c, public, &d).expect("generated scalar rejected");
        assert_bytes(&scalar(&private), &d, format!("{curve:?} loaded scalar"));
        assert_eq!(
            point(private.public_key()),
            (x, y),
            "{curve:?}: loaded private key"
        );
    }
}

/// Invalid points (off the curve, coordinates not less than the field prime,
/// points on other curves) and scalars (zero, too large, or not matching the
/// public key) are rejected with `Ok(None)`.
pub fn ecc_load_rejects_invalid<C: Ecc>(c: &C, caps: &Caps) {
    let mut rng = seeded_rng(c, "ecc_load_rejects_invalid");
    for &curve in CURVES {
        let Some(key) = generate(c, caps, &mut rng, curve) else {
            continue;
        };
        let other = generate(c, caps, &mut rng, curve).expect("second key");
        let size = curve.key_bytes();
        let (x, y) = point(key.public_key());
        let (zeros, ones) = (vec![0u8; size], vec![0xFFu8; size]);
        let y_plus_one = add_be(&y, 1);
        let mut bad_points: Vec<(&[u8], &[u8], &str)> = vec![
            (&zeros, &zeros, "(0, 0)"),
            (&[], &[], "empty coordinates"),
            (&x, &y_plus_one, "off the curve"),
            (&ones, &y, "x >= p"),
            (&x, &ones, "y >= p"),
        ];
        let long_x = [&[0x01][..], &x].concat();
        if long_x.len() <= Tpm2bEccParameter::CAP {
            bad_points.push((&long_x, &y, "oversized x"));
        }
        for (bx, by, why) in bad_points {
            assert!(
                load_point(c, curve, bx, by).is_none(),
                "{curve:?}: point accepted ({why})"
            );
        }
        // Points on other curves with the same coordinate size.
        for &curve2 in caps.curves {
            if curve2 != curve && curve2.key_bytes() == size {
                assert!(
                    load_point(c, curve2, &x, &y).is_none(),
                    "{curve:?} point accepted on {curve2:?}"
                );
            }
        }

        let other_d = scalar(&other);
        let bad_scalars: [(&[u8], &str); 4] = [
            (&zeros, "zero"),
            (&[], "empty"),
            (&ones, "larger than the order"),
            (&other_d, "another key's scalar"),
        ];
        for (d, why) in bad_scalars {
            let public = load_point(c, curve, &x, &y).expect("valid point rejected");
            assert!(
                load_private(c, public, d).is_none(),
                "{curve:?}: scalar accepted ({why})"
            );
        }
    }
}

/// Both parties of an ECDH exchange compute the same point, which is on the
/// curve.
pub fn ecdh_agreement<C: Ecc>(c: &C, caps: &Caps) {
    let mut rng = seeded_rng(c, "ecdh_agreement");
    for &curve in CURVES {
        let Some(a) = generate(c, caps, &mut rng, curve) else {
            continue;
        };
        let b = generate(c, caps, &mut rng, curve).expect("second key");
        let z_ab = ecdh(c, &a, b.public_key());
        let z_ba = ecdh(c, &b, a.public_key());
        assert_eq!(z_ab, z_ba, "{curve:?}: ECDH disagreement");
        assert!(
            load_point(c, curve, &z_ab.0, &z_ab.1).is_some(),
            "{curve:?}: Z is not on the curve"
        );
        assert_ne!(z_ab, point(a.public_key()), "{curve:?}: Z is a public key");
    }
}

/// ECDH known answers (RFC 5903 for P-256).
pub fn ecdh_kat<C: Ecc>(c: &C, caps: &Caps) {
    for v in kat::ECDH {
        let curve = v.curve;
        let result = Ecc::load_public(c, curve, tpms_point(v.q.0, v.q.1));
        let Some(public) =
            expect_support(caps.curves.contains(&curve), format!("{curve:?}"), result)
        else {
            continue;
        };
        let public = public.expect("valid point rejected");
        let private = load_private(c, public, v.d).expect("valid scalar rejected");
        let peer = load_point(c, curve, v.peer.0, v.peer.1).expect("valid peer point rejected");
        let (x, y) = ecdh(c, &private, &peer);
        assert_bytes(&x, v.z.0, format!("{curve:?} ECDH x"));
        assert_bytes(&y, v.z.1, format!("{curve:?} ECDH y"));
    }
}

/// Key generation from a seeded RNG is deterministic (as required for
/// `TPM2_CreatePrimary`), and depends on the seed.
pub fn ecc_generate_key_deterministic<C: Ecc>(c: &C, caps: &Caps) {
    for &curve in CURVES {
        let generate = |seed: &str| {
            let mut rng = c.rng_seeded(seed.as_bytes()).check("Random::rng_seeded");
            let key = generate(c, caps, &mut rng, curve)?;
            Some((point(key.public_key()), scalar(&key)))
        };
        let Some(first) = generate("ecc seed 1") else {
            continue;
        };
        assert_eq!(
            Some(&first),
            generate("ecc seed 1").as_ref(),
            "{curve:?}: same seed, different key"
        );
        assert_ne!(
            Some(&first),
            generate("ecc seed 2").as_ref(),
            "{curve:?}: different seeds, same key"
        );
    }
}
