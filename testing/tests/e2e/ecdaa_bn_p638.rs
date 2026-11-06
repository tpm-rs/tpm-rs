//! ECDAA on BN P-638 (`bn_p638`): TPM2_Commit with an ECDAA key on BN P-638 returns
//! commitment points of the curve (`E = [r]G` without inputs, `E = [r]P1` with `P1`), the
//! TPM2_Sign ECDAA signature with the committed counter verifies client-side
//! (`[s]G = E + [T]Q` with `T = H(k || digest) mod n`), and a counter signs only once.

use crate::_common::{
    base_attrs, client_curve, compute_hash, create_primary_returning_public, ecc_curve_template,
    ecc_signature_parts, ecdaa_scheme, leak_bytes, rc_bare, rc_p, run, sha256, sign,
};
use testing::tpm::Tpm;
use tpm2::commands::Commit;
use tpm2::errors::TpmRc;
use tpm2::{
    Handle, Tpm2b, Tpm2bEccParameter, Tpm2bEccPoint, Tpm2bSensitiveData, TpmEccCurve, TpmaObject,
    TpmiAlgHash, TpmsEccPoint, TpmsSchemeEcdaa, TpmtEccScheme, TpmtSignature,
};

/// A BN P-638 ECDAA-SHA256 signing key; returns its handle and public point.
fn ecdaa_key(sim: &mut Tpm) -> (Handle, (rsa::BigUint, rsa::BigUint)) {
    let template = ecc_curve_template(
        TpmEccCurve::BNP638,
        base_attrs() | TpmaObject::SIGN_ENCRYPT,
        Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
            hash_alg: TpmiAlgHash::Sha256,
            count: 0,
        })),
    );
    let (key, public) = create_primary_returning_public(sim, template, b"");
    (
        key,
        client_curve(TpmEccCurve::BNP638 as u16).public_point(&public),
    )
}

/// `TPM2_Commit(key, P1)` without `s2`/`y2`.
fn commit(
    sim: &mut Tpm,
    key: Handle,
    p1: Option<TpmsEccPoint<'static>>,
) -> Result<tpm2::commands::responses::Commit<'static>, u32> {
    run(
        sim,
        &Commit {
            sign_handle: key,
            p1: p1.map(Tpm2b).unwrap_or_default(),
            s2: Tpm2bSensitiveData::default(),
            y2: Tpm2bEccParameter::default(),
        },
        1,
    )
}

/// The affine point of `point` (coordinates of the BN P-638 size).
fn affine(point: &Tpm2bEccPoint<'_>) -> (rsa::BigUint, rsa::BigUint) {
    assert_eq!(point.0.x.get_buffer().len(), 80, "size of x");
    assert_eq!(point.0.y.get_buffer().len(), 80, "size of y");
    (
        rsa::BigUint::from_bytes_be(point.0.x.get_buffer()),
        rsa::BigUint::from_bytes_be(point.0.y.get_buffer()),
    )
}

/// TPM2_Commit without inputs returns `E` on BN P-638 (and empty `K` and `L`); the ECDAA
/// signature with its counter has `s` of the order size and satisfies `[s]G = E + [T]Q` with
/// `T = SHA-256(k || digest) mod n`; signing again with the same counter, or with a counter
/// that was never committed, fails with `TPM_RC_VALUE`, and the next commit counter signs.
#[test]
#[allow(deprecated)] // TPM2_Sign is deprecated upstream, but the TPM implements it.
fn commit_counter_signs_once_with_a_verifiable_signature() {
    let mut sim = Tpm::new();
    let c = client_curve(TpmEccCurve::BNP638 as u16);
    let (key, q) = ecdaa_key(&mut sim);
    let rsp = commit(&mut sim, key, None).expect("Commit");
    assert_eq!(rsp.k.0.x.get_buffer().len(), 0, "K is empty");
    assert_eq!(rsp.l.0.x.get_buffer().len(), 0, "L is empty");
    let e = affine(&rsp.e);
    assert!(c.contains(&e.0, &e.1), "E is on BN P-638");

    let digest = leak_bytes(&sha256(&[b"ECDAA on BN P-638"]));
    let signature = sign(&mut sim, key, b"", digest, ecdaa_scheme(rsp.counter)).expect("Sign");
    assert!(
        matches!(signature, TpmtSignature::Ecdaa(_)),
        "{signature:?}"
    );
    let (hash, k, s) = ecc_signature_parts(&signature);
    assert_eq!(hash, TpmiAlgHash::Sha256);
    assert_eq!(s.len(), 80, "size of s");
    let t = rsa::BigUint::from_bytes_be(&compute_hash(TpmiAlgHash::Sha256, &[&k, digest])) % &c.n;
    let lhs = c.mul(&rsa::BigUint::from_bytes_be(&s), &c.g());
    let rhs = c.add(&Some(e), &c.mul(&t, &Some(q)));
    assert_eq!(lhs, rhs, "[s]G = E + [T]Q");

    assert_eq!(
        sign(&mut sim, key, b"", digest, ecdaa_scheme(rsp.counter)).err(),
        Some(rc_bare(TpmRc::VALUE)),
        "reused counter"
    );
    assert_eq!(
        sign(
            &mut sim,
            key,
            b"",
            digest,
            ecdaa_scheme(rsp.counter.wrapping_add(1))
        )
        .err(),
        Some(rc_bare(TpmRc::VALUE)),
        "uncommitted counter"
    );
    let next = commit(&mut sim, key, None).expect("Commit");
    assert_eq!(next.counter, rsp.counter.wrapping_add(1));
    sign(&mut sim, key, b"", digest, ecdaa_scheme(next.counter)).expect("fresh counter signs");
}

/// TPM2_Commit with a point `P1` of BN P-638 returns `E = [r]P1` on the curve; a `P1` that is not
/// on the curve, or whose x coordinate is not below `p`, fails with `TPM_RC_ECC_POINT + RC_P1`.
#[test]
fn commit_with_p1_returns_a_point_on_the_curve() {
    let mut sim = Tpm::new();
    let c = client_curve(TpmEccCurve::BNP638 as u16);
    let (key, _) = ecdaa_key(&mut sim);
    let (_, p1) = c.key_pair();
    let point = |x: &rsa::BigUint, y: &rsa::BigUint| TpmsEccPoint {
        x: Tpm2bEccParameter::from_bytes(leak_bytes(&c.coordinate(x))).unwrap(),
        y: Tpm2bEccParameter::from_bytes(leak_bytes(&c.coordinate(y))).unwrap(),
    };
    let rsp = commit(&mut sim, key, Some(point(&p1.0, &p1.1))).expect("Commit with P1");
    let e = affine(&rsp.e);
    assert!(c.contains(&e.0, &e.1), "E is on BN P-638");
    assert_ne!(e, p1);

    let off = (&p1.1 + 1u32) % &c.p;
    assert_eq!(
        commit(&mut sim, key, Some(point(&p1.0, &off))).err(),
        Some(rc_p(TpmRc::ECC_POINT, 1))
    );
    // x + p has the same residue as x but is not a field element.
    assert_eq!(
        commit(&mut sim, key, Some(point(&(&p1.0 + &c.p), &p1.1))).err(),
        Some(rc_p(TpmRc::ECC_POINT, 1))
    );
}
