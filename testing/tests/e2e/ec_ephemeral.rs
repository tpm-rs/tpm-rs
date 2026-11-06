//! TPM2_EC_Ephemeral: the ephemeral public key `Q := [r]G` of the commit mechanism, the commit
//! counter it returns (shared with TPM2_Commit) and the validation of `curveID`.

use crate::_common::{
    client_ecc_public, create_primary_returning_public, ecc_point_bytes, ecc_public, rc_at,
    sdo_user,
};
use testing::tpm::Tpm;
use tpm2::commands::{Commit, ECEphemeral};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Tpm2b, Tpm2bEccPoint, Tpm2bSensitiveData, TpmEccCurve, TpmaObject, TpmiAlgHash, TpmsEccPoint,
    TpmsSchemeEcdaa, TpmtEccScheme,
};

/// The curves of the default profile, with their coordinate sizes.
const CURVES: [(TpmEccCurve, usize); 5] = [
    (TpmEccCurve::NistP224, 28),
    (TpmEccCurve::NistP256, 32),
    (TpmEccCurve::NistP384, 48),
    (TpmEccCurve::NistP521, 66),
    (TpmEccCurve::BNP256, 32),
];

/// TPM2_EC_Ephemeral returns a point on the requested curve with full-size coordinates.
#[test]
fn returns_point_on_each_curve() {
    let mut sim = Tpm::new();
    for (curve, size) in CURVES {
        let rsp = sim
            .execute(ECEphemeral { curve_id: curve })
            .unwrap_or_else(|e| panic!("TPM2_EC_Ephemeral({curve:?}) failed: {e:?}"));
        let q = ecc_point_bytes(&rsp.q.0);
        assert_eq!(q.len(), 2 * size, "{curve:?}");
        assert!(client_ecc_public(curve, &q).is_some(), "{curve:?}");
    }
}

/// Each TPM2_EC_Ephemeral commits the current commit counter value and returns it, so the
/// counter increases by one per command and every call returns a different point.
#[test]
fn counter_increments_and_points_differ() {
    let mut sim = Tpm::new();
    let first = sim
        .execute(ECEphemeral {
            curve_id: TpmEccCurve::NistP256,
        })
        .unwrap();
    let second = sim
        .execute(ECEphemeral {
            curve_id: TpmEccCurve::NistP256,
        })
        .unwrap();
    assert_eq!(second.counter, first.counter.wrapping_add(1));
    assert_ne!(ecc_point_bytes(&first.q.0), ecc_point_bytes(&second.q.0));
}

/// TPM2_EC_Ephemeral and TPM2_Commit share the commit counter: a TPM2_Commit after a
/// TPM2_EC_Ephemeral returns the next counter value, and vice versa.
#[test]
fn shares_counter_with_commit() {
    let mut sim = Tpm::new();
    let (key, _) = create_primary_returning_public(
        &mut sim,
        ecc_public(
            TpmaObject::SIGN_ENCRYPT | sdo_user(),
            None,
            Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
                hash_alg: TpmiAlgHash::Sha256,
                count: 0,
            })),
        ),
        &[],
    );
    let ephemeral = sim
        .execute(ECEphemeral {
            curve_id: TpmEccCurve::NistP256,
        })
        .unwrap();
    let commit = sim
        .execute(Commit {
            sign_handle: key,
            p1: Tpm2b(TpmsEccPoint::default()),
            s2: Tpm2bSensitiveData::default(),
            y2: Default::default(),
        })
        .unwrap();
    assert_eq!(commit.counter, ephemeral.counter.wrapping_add(1));
    let next = sim
        .execute(ECEphemeral {
            curve_id: TpmEccCurve::NistP256,
        })
        .unwrap();
    assert_eq!(next.counter, commit.counter.wrapping_add(1));
}

/// TPM2_EC_Ephemeral with a curve this TPM does not implement fails with TPM_RC_CURVE + P1 and
/// does not advance the commit counter.
#[test]
fn rejects_unimplemented_curve() {
    let mut sim = Tpm::new();
    let before = sim
        .execute(ECEphemeral {
            curve_id: TpmEccCurve::NistP256,
        })
        .unwrap();
    // TPM_ECC_NONE, and TPM_ECC_SM2_P256 + 1 (unassigned).
    for curve in [0x0000u16, 0x0021] {
        let rc = crate::_common::execute_with_corrupted_bytes(
            &mut sim,
            &ECEphemeral {
                curve_id: TpmEccCurve::NistP256,
            },
            0,
            &[],
            |params| params[..2].copy_from_slice(&curve.to_be_bytes()),
        )
        .unwrap_err();
        assert_eq!(
            rc,
            rc_at(TpmRc::CURVE, Position::parameter(1)),
            "{curve:#x}"
        );
    }
    let after = sim
        .execute(ECEphemeral {
            curve_id: TpmEccCurve::NistP256,
        })
        .unwrap();
    assert_eq!(after.counter, before.counter.wrapping_add(1));
}

/// An ephemeral point is accepted as an ECC point by other commands (TPM2_ECDH_ZGen with a key
/// on the same curve), i.e. it is a valid `TPM2B_ECC_POINT`.
#[test]
fn ephemeral_point_is_usable_as_input_point() {
    let mut sim = Tpm::new();
    let (key, _) = create_primary_returning_public(
        &mut sim,
        ecc_public(TpmaObject::DECRYPT | sdo_user(), None, None),
        &[],
    );
    let rsp = sim
        .execute(ECEphemeral {
            curve_id: TpmEccCurve::NistP256,
        })
        .unwrap();
    let in_point: Tpm2bEccPoint<'_> = rsp.q;
    let z = sim
        .execute(tpm2::commands::ECDHZGen {
            key_handle: key,
            in_point,
        })
        .expect("TPM2_ECDH_ZGen with an ephemeral point");
    assert_eq!(ecc_point_bytes(&z.out_point.0).len(), 64);
}
