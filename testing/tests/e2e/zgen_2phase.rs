//! TPM2_ZGen_2Phase: the two-phase key exchanges `TPM_ALG_ECDH` (Full Unified Model),
//! `TPM_ALG_ECMQV` (Full MQV) and `TPM_ALG_SM2` with the ephemeral key of TPM2_EC_Ephemeral
//! (checked against client-side computations and between two parties in the TPM), the retiring
//! of the commitment, and the validation of the key, scheme, points and counter.

use crate::_common::{
    AES128_CFB, client_ecc_key, client_ecc_mul_point, create_primary_returning_public,
    ecc_point_bytes, ecc_point_from_bytes, ecc_public, execute_with_corrupted_bytes,
    execute_with_password_sessions, flush_handle, load_external_ecc_key_on, rc_at,
    rsa_public_with_symmetric, sdo_user,
};
use testing::tpm::Tpm;
use tpm2::Alg;
use tpm2::commands::{ECEphemeral, ZGen2Phase};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bEccPoint, TpmEccCurve, TpmaObject, TpmiAlgHash,
    TpmiEccKeyExchange, TpmtEccScheme, TpmtPublic,
};

/// The curves of the default profile.
const CURVES: [TpmEccCurve; 5] = [
    TpmEccCurve::NistP224,
    TpmEccCurve::NistP256,
    TpmEccCurve::NistP384,
    TpmEccCurve::NistP521,
    TpmEccCurve::BNP256,
];

/// An unrestricted ECC decryption key template on `curve` with `scheme`.
fn decrypt_key_template(curve: TpmEccCurve, scheme: Option<TpmtEccScheme>) -> TpmtPublic<'static> {
    let mut public = ecc_public(TpmaObject::DECRYPT | sdo_user(), None, scheme);
    if let PublicParmsAndId::Ecc(parms, _) = &mut public.parms_and_id {
        parms.curve_id = curve;
    }
    public
}

/// Creates an unrestricted ECC decryption primary key on `curve`; returns its handle and its
/// public point.
fn create_party(sim: &mut Tpm, curve: TpmEccCurve) -> (Handle, Tpm2bEccPoint<'static>) {
    let (handle, public) =
        create_primary_returning_public(sim, decrypt_key_template(curve, None), &[]);
    let PublicParmsAndId::Ecc(_, point) = public.parms_and_id else {
        unreachable!()
    };
    (handle, tpm2::Tpm2b(point))
}

/// A client-side key pair on `curve`: (private scalar, public point `x || y`).
fn client_key(curve: TpmEccCurve) -> (Vec<u8>, Vec<u8>) {
    client_ecc_key(curve)
}

/// Runs TPM2_ZGen_2Phase with `keyA`, `inQsB`, `inQeB`, `inScheme` and `counter`.
fn zgen(
    sim: &mut Tpm,
    key_a: Handle,
    qs_b: Tpm2bEccPoint<'static>,
    qe_b: Tpm2bEccPoint<'static>,
    scheme: TpmiEccKeyExchange,
    counter: u16,
) -> Result<ZValues, u32> {
    let rsp = execute_with_password_sessions(
        sim,
        &ZGen2Phase {
            key_a,
            in_qs_b: qs_b,
            in_qe_b: qe_b,
            in_scheme: scheme,
            counter,
        },
        1,
        &[],
    )?;
    Ok((
        ecc_point_bytes(&rsp.out_z1.0),
        ecc_point_bytes(&rsp.out_z2.0),
    ))
}

/// TPM2_EC_Ephemeral on `curve`: (Q, counter).
fn ephemeral(sim: &mut Tpm, curve: TpmEccCurve) -> (Tpm2bEccPoint<'static>, u16) {
    let rsp = execute_with_password_sessions(sim, &ECEphemeral { curve_id: curve }, 0, &[])
        .expect("TPM2_EC_Ephemeral");
    (rsp.q, rsp.counter)
}

/// The (outZ1, outZ2) of a TPM2_ZGen_2Phase.
type ZValues = (Vec<u8>, Vec<u8>);

/// Both parties of a key exchange in the TPM: each party's ZGen_2Phase with the other party's
/// static and ephemeral public keys; returns party A's and party B's (outZ1, outZ2).
fn exchange_in_tpm(
    sim: &mut Tpm,
    curve: TpmEccCurve,
    scheme: TpmiEccKeyExchange,
) -> (ZValues, ZValues) {
    let (a, qs_a) = create_party(sim, curve);
    let (b, qs_b) = create_party(sim, curve);
    let (qe_a, counter_a) = ephemeral(sim, curve);
    let (qe_b, counter_b) = ephemeral(sim, curve);
    let za = zgen(sim, a, qs_b, qe_b, scheme, counter_a).expect("party A");
    let zb = zgen(sim, b, qs_a, qe_a, scheme, counter_b).expect("party B");
    flush_handle(sim, a);
    flush_handle(sim, b);
    (za, zb)
}

/// With `TPM_ALG_ECDH`, both parties in the TPM compute the same Zs (outZ1) and Ze (outZ2) on
/// every curve.
#[test]
fn ecdh_parties_agree_on_each_curve() {
    let mut sim = Tpm::new();
    for curve in CURVES {
        let (za, zb) = exchange_in_tpm(&mut sim, curve, TpmiEccKeyExchange::Ecdh);
        assert!(!za.0.is_empty() && !za.1.is_empty(), "{curve:?}");
        assert_eq!(za, zb, "{curve:?}");
    }
}

/// With `TPM_ALG_ECDH`, outZ1 is `[d_s,A]Q_s,B` and outZ2 is `[d_e,A]Q_e,B`, i.e. what party B
/// computes with its own private keys: `[d_s,B]Q_s,A` and `[d_e,B]Q_e,A`.
#[test]
fn ecdh_matches_client_computation() {
    let mut sim = Tpm::new();
    let curve = TpmEccCurve::NistP256;
    let (a, qs_a) = create_party(&mut sim, curve);
    let (qe_a, counter) = ephemeral(&mut sim, curve);
    let (ds_b, qs_b) = client_key(curve);
    let (de_b, qe_b) = client_key(curve);
    let (z1, z2) = zgen(
        &mut sim,
        a,
        ecc_point_from_bytes(&qs_b),
        ecc_point_from_bytes(&qe_b),
        TpmiEccKeyExchange::Ecdh,
        counter,
    )
    .unwrap();
    let expected = client_ecc_mul_point(curve, &ds_b, &ecc_point_bytes(&qs_a.0)).unwrap();
    assert_eq!(z1, expected);
    let expected = client_ecc_mul_point(curve, &de_b, &ecc_point_bytes(&qe_a.0)).unwrap();
    assert_eq!(z2, expected);
}

/// A key whose scheme is `TPM_ALG_ECDH` can be used with `inScheme` `TPM_ALG_ECDH`.
#[test]
fn ecdh_key_scheme_matches_in_scheme() {
    let mut sim = Tpm::new();
    let (key, _) = create_primary_returning_public(
        &mut sim,
        decrypt_key_template(
            TpmEccCurve::NistP256,
            Some(TpmtEccScheme::Ecdh(TpmiAlgHash::Sha256)),
        ),
        &[],
    );
    let (qs_b, _) = ephemeral(&mut sim, TpmEccCurve::NistP256);
    let (qe_b, counter) = ephemeral(&mut sim, TpmEccCurve::NistP256);
    zgen(&mut sim, key, qs_b, qe_b, TpmiEccKeyExchange::Ecdh, counter).unwrap();
}

/// A successful TPM2_ZGen_2Phase retires the commitment: the same counter fails with
/// TPM_RC_VALUE + P4 the second time.
#[test]
fn successful_exchange_retires_counter() {
    let mut sim = Tpm::new();
    let (a, _) = create_party(&mut sim, TpmEccCurve::NistP256);
    let (qs_b, _) = ephemeral(&mut sim, TpmEccCurve::NistP256);
    let (qe_b, counter) = ephemeral(&mut sim, TpmEccCurve::NistP256);
    zgen(&mut sim, a, qs_b, qe_b, TpmiEccKeyExchange::Ecdh, counter).unwrap();
    assert_eq!(
        zgen(&mut sim, a, qs_b, qe_b, TpmiEccKeyExchange::Ecdh, counter),
        Err(rc_at(TpmRc::VALUE, Position::parameter(4)))
    );
}

/// A failing TPM2_ZGen_2Phase (a point that is not on the curve) does not retire the
/// commitment: the counter still works afterwards.
#[test]
fn failed_exchange_keeps_counter() {
    let mut sim = Tpm::new();
    let (a, qs_a) = create_party(&mut sim, TpmEccCurve::NistP256);
    let (qe_b, counter) = ephemeral(&mut sim, TpmEccCurve::NistP256);
    let mut bad = ecc_point_bytes(&qs_a.0);
    bad[63] ^= 1;
    assert_eq!(
        zgen(
            &mut sim,
            a,
            ecc_point_from_bytes(&bad),
            qe_b,
            TpmiEccKeyExchange::Ecdh,
            counter
        ),
        Err(rc_at(TpmRc::ECC_POINT, Position::parameter(1)))
    );
    zgen(&mut sim, a, qs_a, qe_b, TpmiEccKeyExchange::Ecdh, counter).unwrap();
}

/// A counter that was never committed fails with TPM_RC_VALUE + P4.
#[test]
fn rejects_uncommitted_counter() {
    let mut sim = Tpm::new();
    let (a, qs_a) = create_party(&mut sim, TpmEccCurve::NistP256);
    let (qe_b, counter) = ephemeral(&mut sim, TpmEccCurve::NistP256);
    for unused in [counter.wrapping_add(1), counter.wrapping_add(5)] {
        assert_eq!(
            zgen(&mut sim, a, qs_a, qe_b, TpmiEccKeyExchange::Ecdh, unused),
            Err(rc_at(TpmRc::VALUE, Position::parameter(4))),
            "{unused}"
        );
    }
}

/// A counter outside the window of the commit array (128 values) fails with TPM_RC_VALUE + P4
/// although its array bit is set again by a later commitment.
#[test]
fn rejects_counter_outside_window() {
    let mut sim = Tpm::new();
    let (a, qs_a) = create_party(&mut sim, TpmEccCurve::NistP256);
    let (qe_b, counter) = ephemeral(&mut sim, TpmEccCurve::NistP256);
    for _ in 0..128 {
        ephemeral(&mut sim, TpmEccCurve::NistP256);
    }
    assert_eq!(
        zgen(&mut sim, a, qs_a, qe_b, TpmiEccKeyExchange::Ecdh, counter),
        Err(rc_at(TpmRc::VALUE, Position::parameter(4)))
    );
    // The counter 128 values later (same array bit) is still usable.
    zgen(
        &mut sim,
        a,
        qs_a,
        qe_b,
        TpmiEccKeyExchange::Ecdh,
        counter.wrapping_add(128),
    )
    .unwrap();
}

/// `inQsB` is checked before `inQeB`: points that are not on the curve of `keyA` fail with
/// TPM_RC_ECC_POINT + P1 and + P2.
#[test]
fn rejects_points_not_on_curve() {
    let mut sim = Tpm::new();
    let (a, qs_a) = create_party(&mut sim, TpmEccCurve::NistP256);
    let (_, counter) = ephemeral(&mut sim, TpmEccCurve::NistP256);
    let mut bad = ecc_point_bytes(&qs_a.0);
    bad[0] ^= 0x80;
    let bad = ecc_point_from_bytes(&bad);
    assert_eq!(
        zgen(&mut sim, a, bad, bad, TpmiEccKeyExchange::Ecdh, counter),
        Err(rc_at(TpmRc::ECC_POINT, Position::parameter(1)))
    );
    assert_eq!(
        zgen(&mut sim, a, qs_a, bad, TpmiEccKeyExchange::Ecdh, counter),
        Err(rc_at(TpmRc::ECC_POINT, Position::parameter(2)))
    );
    // A point of another curve (P-384) is not on P-256.
    let (q384, _) = ephemeral(&mut sim, TpmEccCurve::NistP384);
    assert_eq!(
        zgen(&mut sim, a, qs_a, q384, TpmiEccKeyExchange::Ecdh, counter),
        Err(rc_at(TpmRc::ECC_POINT, Position::parameter(2)))
    );
}

/// Coordinates with leading zero bytes are integers like any other: a point whose coordinates
/// are padded beyond the coordinate size is accepted.
#[test]
fn accepts_zero_padded_coordinates() {
    let mut sim = Tpm::new();
    let (a, qs_a) = create_party(&mut sim, TpmEccCurve::NistP256);
    let (qe_b, counter) = ephemeral(&mut sim, TpmEccCurve::NistP256);
    let xy = ecc_point_bytes(&qs_a.0);
    let padded = [&[0u8][..], &xy[..32], &[0u8], &xy[32..]].concat();
    let padded = ecc_point_from_bytes(&padded);
    let (z1, _) = zgen(&mut sim, a, padded, qe_b, TpmiEccKeyExchange::Ecdh, counter).unwrap();
    assert_eq!(z1.len(), 64);
}

/// `keyA` must be an ECC key (TPM_RC_KEY + H1) with `restricted` CLEAR and `decrypt` SET
/// (TPM_RC_ATTRIBUTES + H1).
#[test]
fn rejects_unsuitable_keys() {
    let mut sim = Tpm::new();
    let (party, qs) = create_party(&mut sim, TpmEccCurve::NistP256);
    flush_handle(&mut sim, party);
    let (qe, counter) = ephemeral(&mut sim, TpmEccCurve::NistP256);
    let (rsa, _) = create_primary_returning_public(
        &mut sim,
        rsa_public_with_symmetric(TpmaObject::DECRYPT | sdo_user(), None),
        &[],
    );
    let (restricted, _) = create_primary_returning_public(
        &mut sim,
        ecc_public(
            TpmaObject::DECRYPT | TpmaObject::RESTRICTED | sdo_user(),
            Some(AES128_CFB),
            None,
        ),
        &[],
    );
    let (signing, _) = create_primary_returning_public(
        &mut sim,
        ecc_public(TpmaObject::SIGN_ENCRYPT | sdo_user(), None, None),
        &[],
    );
    for (key, rc) in [
        (rsa, TpmRc::KEY),
        (restricted, TpmRc::ATTRIBUTES),
        (signing, TpmRc::ATTRIBUTES),
    ] {
        assert_eq!(
            zgen(&mut sim, key, qs, qe, TpmiEccKeyExchange::Ecdh, counter),
            Err(rc_at(rc, Position::handle(1)))
        );
    }
}

/// An `inScheme` that is not a key-exchange scheme of this TPM, or `TPM_ALG_NULL`, fails while
/// it is unmarshaled with TPM_RC_SCHEME + P3.
#[test]
fn rejects_unimplemented_in_scheme() {
    let mut sim = Tpm::new();
    let (a, qs_a) = create_party(&mut sim, TpmEccCurve::NistP256);
    let (qe_b, counter) = ephemeral(&mut sim, TpmEccCurve::NistP256);
    let mut schemes = vec![Alg::NULL, Alg::ECDSA, Alg::RSAES];
    if cfg!(not(feature = "ecmqv")) {
        schemes.push(Alg::ECMQV);
    }
    for scheme in schemes {
        let cmd = ZGen2Phase {
            key_a: a,
            in_qs_b: qs_a,
            in_qe_b: qe_b,
            in_scheme: TpmiEccKeyExchange::Ecdh,
            counter,
        };
        let rc = execute_with_corrupted_bytes(&mut sim, &cmd, 1, &[], |params| {
            let at = params.len() - 4;
            params[at..at + 2].copy_from_slice(&scheme.id().to_be_bytes());
        })
        .unwrap_err();
        assert_eq!(
            rc,
            rc_at(TpmRc::SCHEME, Position::parameter(3)),
            "{scheme:?}"
        );
    }
}

/// A key-exchange scheme of `keyA` other than `TPM_ALG_NULL` must be `inScheme`
/// (TPM_RC_SCHEME + P3).
#[cfg(feature = "ecmqv")]
#[test]
fn rejects_in_scheme_other_than_key_scheme() {
    let mut sim = Tpm::new();
    let (ecdh_key, qs) = {
        let (h, public) = create_primary_returning_public(
            &mut sim,
            decrypt_key_template(
                TpmEccCurve::NistP256,
                Some(TpmtEccScheme::Ecdh(TpmiAlgHash::Sha256)),
            ),
            &[],
        );
        let PublicParmsAndId::Ecc(_, point) = public.parms_and_id else {
            unreachable!()
        };
        (h, tpm2::Tpm2b(point))
    };
    let (mqv_key, _) = create_primary_returning_public(
        &mut sim,
        decrypt_key_template(
            TpmEccCurve::NistP256,
            Some(TpmtEccScheme::Ecmqv(TpmiAlgHash::Sha256)),
        ),
        &[],
    );
    let (qe, counter) = ephemeral(&mut sim, TpmEccCurve::NistP256);
    assert_eq!(
        zgen(
            &mut sim,
            ecdh_key,
            qs,
            qe,
            TpmiEccKeyExchange::Ecmqv,
            counter
        ),
        Err(rc_at(TpmRc::SCHEME, Position::parameter(3)))
    );
    assert_eq!(
        zgen(&mut sim, mqv_key, qs, qe, TpmiEccKeyExchange::Ecdh, counter),
        Err(rc_at(TpmRc::SCHEME, Position::parameter(3)))
    );
    // The matching scheme works.
    let (z1, z2) = zgen(
        &mut sim,
        mqv_key,
        qs,
        qe,
        TpmiEccKeyExchange::Ecmqv,
        counter,
    )
    .unwrap();
    assert_eq!((z1.len(), z2.len()), (64, 0));
}

/// With `TPM_ALG_ECMQV`, both parties in the TPM compute the same Z (outZ1) on every curve, and
/// outZ2 is the Empty Point.
#[cfg(feature = "ecmqv")]
#[test]
fn mqv_parties_agree_on_each_curve() {
    let mut sim = Tpm::new();
    for curve in CURVES {
        let (za, zb) = exchange_in_tpm(&mut sim, curve, TpmiEccKeyExchange::Ecmqv);
        assert!(!za.0.is_empty(), "{curve:?}");
        assert!(za.1.is_empty() && zb.1.is_empty(), "{curve:?}");
        assert_eq!(za.0, zb.0, "{curve:?}");
    }
}

/// With `TPM_ALG_ECMQV`, outZ1 is Part 1's Full MQV value: party B (the client) computes the
/// same Z as `[t_B](Q_e,A + [avf(Q_e,A)]Q_s,A)` with `t_B := (d_e,B + d_s,B · avf(Q_e,B)) mod n`.
#[cfg(feature = "ecmqv")]
#[test]
fn mqv_matches_client_computation() {
    let mut sim = Tpm::new();
    let curve = TpmEccCurve::NistP256;
    for _ in 0..4 {
        let (a, qs_a) = create_party(&mut sim, curve);
        let (qe_a, counter) = ephemeral(&mut sim, curve);
        let (ds_b, qs_b) = client_key(curve);
        let (de_b, qe_b) = client_key(curve);
        let (z1, z2) = zgen(
            &mut sim,
            a,
            ecc_point_from_bytes(&qs_b),
            ecc_point_from_bytes(&qe_b),
            TpmiEccKeyExchange::Ecmqv,
            counter,
        )
        .unwrap();
        let expected = crate::_common::p256_mqv_reference(
            &ds_b,
            &de_b,
            &ecc_point_bytes(&qs_a.0),
            &ecc_point_bytes(&qe_a.0),
        )
        .unwrap();
        assert_eq!(z1, expected);
        assert!(z2.is_empty());
        flush_handle(&mut sim, a);
    }
}

/// With `TPM_ALG_ECMQV`, a Z that is the point at infinity (`Q_e,B + [avf(Q_e,B)]Q_s,B = O`, for
/// `Q_s,B := -[avf(Q_e,B)^-1]Q_e,B`) is returned as the Empty Point (Part 3: "If a computation
/// of either Z produces the point at infinity, then the corresponding Z value will be an Empty
/// Point"), and the command succeeds and retires the counter.
#[cfg(feature = "ecmqv")]
#[test]
fn mqv_point_at_infinity_is_empty_point() {
    use crate::_common::{p256_associated_value, p256_point, p256_point_bytes};
    let mut sim = Tpm::new();
    let curve = TpmEccCurve::NistP256;
    let (a, _) = create_party(&mut sim, curve);
    let (_, counter) = ephemeral(&mut sim, curve);
    let (_, qe_b) = client_key(curve);
    let avf_inv = Option::<p256::Scalar>::from(p256_associated_value(&qe_b, 128).invert()).unwrap();
    let qs_b = p256_point_bytes(-(p256_point(&qe_b) * avf_inv)).unwrap();
    let (z1, z2) = zgen(
        &mut sim,
        a,
        ecc_point_from_bytes(&qs_b),
        ecc_point_from_bytes(&qe_b),
        TpmiEccKeyExchange::Ecmqv,
        counter,
    )
    .unwrap();
    assert!(z1.is_empty() && z2.is_empty());
    assert_eq!(
        zgen(
            &mut sim,
            a,
            ecc_point_from_bytes(&qs_b),
            ecc_point_from_bytes(&qe_b),
            TpmiEccKeyExchange::Ecmqv,
            counter
        ),
        Err(rc_at(TpmRc::VALUE, Position::parameter(4)))
    );
}

/// With `TPM_ALG_ECMQV`, `Q_e,B = [avf(Q_e,B)]Q_s,B` makes the sum a point doubling; the result
/// is still the Full MQV value.
#[cfg(feature = "ecmqv")]
#[test]
fn mqv_with_doubling_matches_client_computation() {
    use crate::_common::{p256_associated_value, p256_point, p256_point_bytes};
    let mut sim = Tpm::new();
    let curve = TpmEccCurve::NistP256;
    let (a, qs_a) = create_party(&mut sim, curve);
    let (qe_a, counter) = ephemeral(&mut sim, curve);
    // Q_e,B := [de_B]G and Q_s,B := [avf(Q_e,B)^-1]Q_e,B, so d_s,B = de_B · avf^-1.
    let (de_b, qe_b) = client_key(curve);
    let avf_inv = Option::<p256::Scalar>::from(p256_associated_value(&qe_b, 128).invert()).unwrap();
    let qs_b = p256_point_bytes(p256_point(&qe_b) * avf_inv).unwrap();
    let ds_b = (crate::_common::p256_scalar(&de_b) * avf_inv).to_bytes();
    let (z1, _) = zgen(
        &mut sim,
        a,
        ecc_point_from_bytes(&qs_b),
        ecc_point_from_bytes(&qe_b),
        TpmiEccKeyExchange::Ecmqv,
        counter,
    )
    .unwrap();
    let expected = crate::_common::p256_mqv_reference(
        &ds_b,
        &de_b,
        &ecc_point_bytes(&qs_a.0),
        &ecc_point_bytes(&qe_a.0),
    );
    assert_eq!(Some(z1), expected);
}

/// With `TPM_ALG_SM2`, outZ1 is Part 1's SM2 key-exchange value: party B (the client) computes
/// the same Z as `[t_B](Q_s,A + [avfSM2(Q_e,A)]Q_e,A)` with
/// `t_B := (d_s,B + d_e,B · avfSM2(Q_e,B)) mod n`; both parties in the TPM agree.
#[cfg(feature = "sm2")]
#[test]
fn sm2_matches_client_computation() {
    let mut sim = Tpm::new();
    let curve = TpmEccCurve::NistP256;
    let (a, qs_a) = create_party(&mut sim, curve);
    let (qe_a, counter) = ephemeral(&mut sim, curve);
    let (ds_b, qs_b) = client_key(curve);
    let (de_b, qe_b) = client_key(curve);
    let (z1, z2) = zgen(
        &mut sim,
        a,
        ecc_point_from_bytes(&qs_b),
        ecc_point_from_bytes(&qe_b),
        TpmiEccKeyExchange::Sm2,
        counter,
    )
    .unwrap();
    let expected = crate::_common::p256_sm2_key_exchange_reference(
        &ds_b,
        &de_b,
        &ecc_point_bytes(&qs_a.0),
        &ecc_point_bytes(&qe_a.0),
    )
    .unwrap();
    assert_eq!(z1, expected);
    assert!(z2.is_empty());
    let (za, zb) = exchange_in_tpm(&mut sim, curve, TpmiEccKeyExchange::Sm2);
    assert_eq!(za, zb);
}

/// A loaded external key works as `keyA` like a created one (its private scalar is the static
/// key): ECDH outZ1 is `[d_s,A]Q_s,B`.
#[test]
fn external_key_as_key_a() {
    let mut sim = Tpm::new();
    let curve = TpmEccCurve::NistP384;
    let (a, ds_a, _) = load_external_ecc_key_on(
        &mut sim,
        curve,
        TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
        None,
    );
    let (qe_b, counter) = ephemeral(&mut sim, curve);
    let (_, qs_b) = client_key(curve);
    let (z1, _) = zgen(
        &mut sim,
        a,
        ecc_point_from_bytes(&qs_b),
        qe_b,
        TpmiEccKeyExchange::Ecdh,
        counter,
    )
    .unwrap();
    let expected = client_ecc_mul_point(curve, &ds_a, &qs_b).unwrap();
    assert_eq!(z1, expected);
}

/// With `TPM_ALG_SM2`, a Z that is the point at infinity (`Q_s,B + [avfSM2(Q_e,B)]Q_e,B = O`, for
/// `Q_s,B := -[avfSM2(Q_e,B)]Q_e,B`) is returned as the Empty Point (Part 3's rule for every
/// scheme of the command), and the command succeeds and retires the counter.
#[cfg(feature = "sm2")]
#[test]
fn sm2_point_at_infinity_is_empty_point() {
    use crate::_common::{p256_associated_value, p256_point, p256_point_bytes};
    let mut sim = Tpm::new();
    let curve = TpmEccCurve::NistP256;
    let (a, _) = create_party(&mut sim, curve);
    let (_, counter) = ephemeral(&mut sim, curve);
    let (_, qe_b) = client_key(curve);
    let qs_b = p256_point_bytes(-(p256_point(&qe_b) * p256_associated_value(&qe_b, 127))).unwrap();
    let zgen_sm2 = |sim: &mut Tpm| {
        zgen(
            sim,
            a,
            ecc_point_from_bytes(&qs_b),
            ecc_point_from_bytes(&qe_b),
            TpmiEccKeyExchange::Sm2,
            counter,
        )
    };
    let (z1, z2) = zgen_sm2(&mut sim).unwrap();
    assert!(z1.is_empty() && z2.is_empty());
    assert_eq!(
        zgen_sm2(&mut sim),
        Err(rc_at(TpmRc::VALUE, Position::parameter(4)))
    );
}
