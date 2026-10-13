//! TPM2_ECDH_KeyGen and TPM2_ECDH_ZGen: key type/attribute checks, validation order and shared
//! point computation.

use crate::_common::{
    AES128_CFB, CC_ECDH_ZGEN, CLIENT_CRYPTO, base_attrs, create_primary_returning_public,
    create_primary_with_auth_in, ecc_point_param, ecc_public, ecc_storage_template_derived,
    ecc_template, execute_with_password_sessions, fixed_zgen_point, hmac_template,
    load_external_ecc_key, rc_at, rc_bare, rsa_public_with_symmetric, sdo_user, send_key_command,
    send_with_trailing,
};
use testing::tpm::Tpm;
use tpm2::commands::{ECDHKeyGen, ECDHZGen, HMAC};
use tpm2::crypto::Ecc;
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2b, Tpm2bEccParameter, Tpm2bMaxBuffer, TpmEccCurve, TpmaObject, TpmiAlgHash,
    TpmsEccPoint, TpmtEccScheme, TpmtKeyedHashScheme,
};

/// TPM2_ECDH_ZGen with a restricted decryption key fails with TPM_RC_ATTRIBUTES
#[test]
fn ecdh_zgen_rejects_restricted_key() {
    let mut sim = Tpm::new();
    // Key with RESTRICTED attribute set (invalid for ECDH_ZGen); a restricted decryption key
    // needs a symmetric algorithm to be creatable.
    let (key, _) = create_primary_returning_public(
        &mut sim,
        ecc_public(
            TpmaObject::DECRYPT | TpmaObject::RESTRICTED | sdo_user(),
            Some(AES128_CFB),
            None,
        ),
        &[],
    );

    let error_code = send_key_command(&mut sim, CC_ECDH_ZGEN, key, true, &fixed_zgen_point());
    assert_eq!(
        error_code,
        0x00000182, // TPM_RC_ATTRIBUTES | Position::Handle | Position::handle(1)
        "Expected TPM_RC_ATTRIBUTES + Handle + Pos1 (0x182), got error_code = 0x{:08X}",
        error_code
    );
}

/// TPM2_ECDH_ZGen with an RSA key fails with TPM_RC_KEY
#[test]
fn ecdh_zgen_rejects_rsa_key() {
    let mut sim = Tpm::new();
    // RSA key instead of ECC key
    let (key, _) = create_primary_returning_public(
        &mut sim,
        rsa_public_with_symmetric(TpmaObject::DECRYPT | sdo_user(), None),
        &[],
    );

    let error_code = send_key_command(&mut sim, CC_ECDH_ZGEN, key, true, &fixed_zgen_point());
    assert_eq!(
        error_code,
        0x0000019C, // TPM_RC_KEY | Position::Handle | Position::handle(1)
        "Expected TPM_RC_KEY + Handle + Pos1 (0x19C), got error_code = 0x{:08X}",
        error_code
    );
}

/// TPM2_ECDH_ZGen with the key own public point succeeds
#[test]
fn ecdh_zgen_with_own_public_point() {
    let mut sim = Tpm::new();
    let (key, public) = create_primary_returning_public(
        &mut sim,
        ecc_public(TpmaObject::DECRYPT | sdo_user(), None, None),
        &[],
    );

    // Use the key's own public point as a valid point on the curve.
    let error_code = send_key_command(&mut sim, CC_ECDH_ZGEN, key, true, &ecc_point_param(&public));
    assert_eq!(
        error_code, 0,
        "ECDH_ZGen failed! error_code = 0x{:08X}",
        error_code
    );
}

/// ECDH_KeyGen returns an ephemeral point on the curve and zPoint = [d_s] Q_e
///
/// `TPM2_ECDH_KeyGen` returns an ephemeral public point on the key's curve and
/// `zPoint = [d_s] Q_e`, where `d_s` is the private scalar of the loaded key.
#[test]
fn key_gen_shared_point() {
    let mut sim = Tpm::new();

    let (key_handle, priv_bytes) =
        load_external_ecc_key(&mut sim, TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH);

    let rsp = sim
        .execute(ECDHKeyGen { key_handle })
        .expect("TPM2_ECDH_KeyGen should return TPM_RC_SUCCESS");

    let pub_tpms = rsp.pub_point.0;
    let mut pub_raw = [0u8; 64];
    pub_raw[..32].copy_from_slice(pub_tpms.x.get_buffer());
    pub_raw[32..64].copy_from_slice(pub_tpms.y.get_buffer());
    assert!(
        CLIENT_CRYPTO.validate_point(TpmEccCurve::NistP256, &pub_raw) == Ok(true),
        "pubPoint must lie on NIST P-256 curve"
    );

    // Check zPoint coordinates match expected ECDH scalar multiplication: Z = [d_s] Q_e
    let mut expected_z_raw = [0u8; 64];
    CLIENT_CRYPTO
        .point_multiply(
            TpmEccCurve::NistP256,
            &priv_bytes,
            &pub_raw,
            &mut expected_z_raw,
        )
        .expect("Scalar multiplication [d_s] Q_e should succeed")
        .expect("Scalar multiplication [d_s] Q_e should succeed");

    let z_tpms = rsp.z_point.0;
    let mut z_raw = [0u8; 64];
    z_raw[..32].copy_from_slice(z_tpms.x.get_buffer());
    z_raw[32..64].copy_from_slice(z_tpms.y.get_buffer());

    assert_eq!(
        z_raw, expected_z_raw,
        "zPoint coordinates must match expected ECDH scalar multiplication [d_s] Q_e"
    );
}

/// ECDH_KeyGen accepts any loaded ECC key (signing/restricted) and rejects non-ECC keys with KEY + H1.
///
/// ECDH_KeyGen only needs a loaded ECC key: signing / restricted keys are accepted and a
/// non-ECC key is `TPM_RC_KEY + RC_H1`.
#[test]
fn keygen_accepts_signing_and_restricted_keys() {
    let mut sim = Tpm::new();
    let sign_key = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        ecc_template(
            base_attrs() | TpmaObject::SIGN_ENCRYPT,
            Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        ),
        b"",
    );
    sim.execute(ECDHKeyGen {
        key_handle: sign_key,
    })
    .expect("ECDH_KeyGen must accept an ECC signing key");

    let storage = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        ecc_storage_template_derived(),
        b"",
    );
    sim.execute(ECDHKeyGen {
        key_handle: storage,
    })
    .expect("ECDH_KeyGen must accept a restricted ECC key");
}

/// ECDH_KeyGen on a non-ECC key without decrypt fails with KEY + H1 (type checked first).
///
/// A non-ECC key without `decrypt` is `TPM_RC_KEY + RC_H1` (type checked first).
#[test]
fn keygen_checks_key_type_first() {
    let mut sim = Tpm::new();
    let hmac_key = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        hmac_template(
            base_attrs() | TpmaObject::SIGN_ENCRYPT,
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
        ),
        b"",
    );
    let err = sim
        .execute(ECDHKeyGen {
            key_handle: hmac_key,
        })
        .unwrap_err();
    assert_eq!(err.get(), rc_at(TpmRc::KEY, Position::handle(1)));
}

/// ECDH_ZGen checks key type before attributes; TPM2_HMAC checks restricted before hash selection.
///
/// ECDH_ZGen checks the key type before its attributes and rejects trailing bytes.
#[test]
fn zgen_and_hmac_validation_order() {
    let mut sim = Tpm::new();

    // A restricted keyed-hash key: type (KEY) is checked before restricted/decrypt.
    let hmac_key = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        hmac_template(
            base_attrs() | TpmaObject::SIGN_ENCRYPT | TpmaObject::RESTRICTED,
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
        ),
        b"",
    );
    let zgen = ECDHZGen {
        key_handle: hmac_key,
        in_point: Tpm2b(TpmsEccPoint {
            x: Tpm2bEccParameter::from_bytes(&[1]).unwrap(),
            y: Tpm2bEccParameter::from_bytes(&[2]).unwrap(),
        }),
    };
    assert_eq!(
        execute_with_password_sessions(&mut sim, &zgen, 1, &[]).unwrap_err(),
        rc_at(TpmRc::KEY, Position::handle(1))
    );

    // TPM2_HMAC: restricted is checked before the hash algorithm selection.
    let hmac = HMAC {
        handle: hmac_key,
        buffer: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha1),
    };
    assert_eq!(
        execute_with_password_sessions(&mut sim, &hmac, 1, &[]).unwrap_err(),
        rc_at(TpmRc::ATTRIBUTES, Position::handle(1))
    );
}

/// ECDH_ZGen rejects trailing parameter bytes with TPM_RC_SIZE.
///
/// ECDH_ZGen rejects trailing parameter bytes with `TPM_RC_SIZE`, and checks the type of a
/// restricted RSA key before its attributes.
#[test]
fn zgen_trailing_bytes_return_size() {
    let mut sim = Tpm::new();
    let storage = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        ecc_storage_template_derived(),
        b"",
    );
    let zgen = ECDHZGen {
        key_handle: storage,
        in_point: Tpm2b(TpmsEccPoint {
            x: Tpm2bEccParameter::from_bytes(&[1]).unwrap(),
            y: Tpm2bEccParameter::from_bytes(&[2]).unwrap(),
        }),
    };
    assert_eq!(
        send_with_trailing(&mut sim, &zgen, 1, &[], &[0]),
        rc_bare(TpmRc::SIZE)
    );
}
