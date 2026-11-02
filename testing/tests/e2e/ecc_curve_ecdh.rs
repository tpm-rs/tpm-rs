//! ECDH on the optional ECC curves NIST P-192, BN P-638 and SM2 P-256: TPM2_ECDH_KeyGen and
//! TPM2_ECDH_ZGen agree on the shared point, match the client-side scalar multiplications of
//! `_common::ClientCurve`, and TPM2_ECDH_ZGen rejects points that are not on the curve.

use crate::_common::{
    OPTIONAL_ECC_CURVES, base_attrs, client_curve, create_primary_returning_public,
    ecc_curve_public, ecc_curve_template, leak_bytes, load_external_ecc, rc_p, run,
};
use testing::tpm::Tpm;
use tpm2::commands::{ECDHKeyGen, ECDHZGen};
use tpm2::errors::TpmRc;
use tpm2::{Handle, Tpm2b, Tpm2bEccParameter, TpmaObject, TpmsEccPoint};

/// `TPMS_ECC_POINT` with the coordinates `x` and `y`.
fn point(x: &[u8], y: &[u8]) -> TpmsEccPoint<'static> {
    TpmsEccPoint {
        x: Tpm2bEccParameter::from_bytes(leak_bytes(x)).unwrap(),
        y: Tpm2bEccParameter::from_bytes(leak_bytes(y)).unwrap(),
    }
}

/// `TPM2_ECDH_ZGen(key, in_point)`.
fn zgen(
    sim: &mut Tpm,
    key: Handle,
    in_point: TpmsEccPoint<'static>,
) -> Result<TpmsEccPoint<'static>, u32> {
    run(
        sim,
        &ECDHZGen {
            key_handle: key,
            in_point: Tpm2b(in_point),
        },
        1,
    )
    .map(|rsp| rsp.out_point.0)
}

/// On every optional curve, TPM2_ECDH_KeyGen with a TPM-generated decryption key returns an
/// ephemeral point on the curve, and TPM2_ECDH_ZGen of that point with the same key returns the
/// same shared point (`[d_e]Q_s = [d_s]Q_e`), with coordinates of the curve's size.
#[test]
fn key_gen_and_zgen_agree() {
    let mut sim = Tpm::new();
    for &curve in OPTIONAL_ECC_CURVES {
        let c = client_curve(curve as u16);
        let template = ecc_curve_template(curve, base_attrs() | TpmaObject::DECRYPT, None);
        let (key, _) = create_primary_returning_public(&mut sim, template, b"");
        let rsp = sim
            .execute(ECDHKeyGen { key_handle: key })
            .unwrap_or_else(|rc| panic!("ECDH_KeyGen on {curve:?}: {rc:?}"));
        let (z, q_e) = (rsp.z_point.0, rsp.pub_point.0);
        for p in [&z, &q_e] {
            assert_eq!(p.x.get_buffer().len(), c.size, "size of x on {curve:?}");
            assert_eq!(p.y.get_buffer().len(), c.size, "size of y on {curve:?}");
            assert!(c.contains(
                &rsa::BigUint::from_bytes_be(p.x.get_buffer()),
                &rsa::BigUint::from_bytes_be(p.y.get_buffer())
            ));
        }
        let shared = zgen(&mut sim, key, q_e).expect("ECDH_ZGen");
        assert_eq!(shared, z, "shared point on {curve:?}");
        sim.execute(tpm2::commands::FlushContext { flush_handle: key })
            .unwrap();
    }
}

/// With a client-generated key `d` loaded by TPM2_LoadExternal, TPM2_ECDH_ZGen of a client point
/// `P` is the client's `[d]P`, and the shared point of TPM2_ECDH_KeyGen with the public key `Q`
/// is `[d]Q_e` for the returned ephemeral point `Q_e`.
#[test]
fn shared_points_match_client_scalar_multiplication() {
    let mut sim = Tpm::new();
    for &curve in OPTIONAL_ECC_CURVES {
        let c = client_curve(curve as u16);
        let (d, q) = c.key_pair();
        let public = ecc_curve_public(
            curve,
            TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
            None,
            &c.coordinate(&q.0),
            &c.coordinate(&q.1),
        );
        let key = load_external_ecc(&mut sim, public, Some(&c.coordinate(&d)))
            .unwrap_or_else(|rc| panic!("LoadExternal on {curve:?}: {rc:#x}"));

        let (_, p) = c.key_pair();
        let shared = zgen(
            &mut sim,
            key,
            point(&c.coordinate(&p.0), &c.coordinate(&p.1)),
        )
        .expect("ECDH_ZGen");
        let (zx, zy) = c.mul(&d, &Some(p)).unwrap();
        assert_eq!(
            shared,
            point(&c.coordinate(&zx), &c.coordinate(&zy)),
            "[d]P on {curve:?}"
        );

        let rsp = sim
            .execute(ECDHKeyGen { key_handle: key })
            .expect("ECDH_KeyGen");
        let q_e = (
            rsa::BigUint::from_bytes_be(rsp.pub_point.0.x.get_buffer()),
            rsa::BigUint::from_bytes_be(rsp.pub_point.0.y.get_buffer()),
        );
        let (zx, zy) = c.mul(&d, &Some(q_e)).unwrap();
        assert_eq!(
            rsp.z_point.0,
            point(&c.coordinate(&zx), &c.coordinate(&zy)),
            "[d]Q_e on {curve:?}"
        );
        sim.execute(tpm2::commands::FlushContext { flush_handle: key })
            .unwrap();
    }
}

/// TPM2_ECDH_ZGen of a point that is not on the curve, or whose coordinate is not below the
/// field prime, fails with `TPM_RC_ECC_POINT + RC_P1`.
#[test]
fn zgen_rejects_points_off_the_curve() {
    let mut sim = Tpm::new();
    for &curve in OPTIONAL_ECC_CURVES {
        let c = client_curve(curve as u16);
        let template = ecc_curve_template(curve, base_attrs() | TpmaObject::DECRYPT, None);
        let (key, _) = create_primary_returning_public(&mut sim, template, b"");
        let (_, p) = c.key_pair();
        let x = c.coordinate(&p.0);
        let off = c.coordinate(&((&p.1 + 1u32) % &c.p));
        assert_eq!(
            zgen(&mut sim, key, point(&x, &off)).err(),
            Some(rc_p(TpmRc::ECC_POINT, 1)),
            "point off {curve:?}"
        );
        assert_eq!(
            zgen(&mut sim, key, point(&x, &c.coordinate(&c.p))).err(),
            Some(rc_p(TpmRc::ECC_POINT, 1)),
            "y = p on {curve:?}"
        );
        // x + p and y + p: the same residues, but not field elements (fit on BN P-638).
        let y = c.coordinate(&p.1);
        if let Some(x_plus_p) = c.plus_p(&p.0) {
            assert_eq!(
                zgen(&mut sim, key, point(&x_plus_p, &y)).err(),
                Some(rc_p(TpmRc::ECC_POINT, 1)),
                "x + p on {curve:?}"
            );
        }
        if let Some(y_plus_p) = c.plus_p(&p.1) {
            assert_eq!(
                zgen(&mut sim, key, point(&x, &y_plus_p)).err(),
                Some(rc_p(TpmRc::ECC_POINT, 1)),
                "y + p on {curve:?}"
            );
        }
        zgen(&mut sim, key, point(&x, &y)).expect("ECDH_ZGen of the valid point");
        sim.execute(tpm2::commands::FlushContext { flush_handle: key })
            .unwrap();
    }
}
