//! Public-only objects cannot be authorized (authValue or authPolicy) or used for private
//! operations.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bDigest, TpmCc, TpmSe, TpmaObject, TpmiAlgHash,
    TpmtKeyedHashScheme, TpmtPublic,
};

/// TPM2_EncryptDecrypt2 with a public-only symmetric key fails without panicking
///
/// `TPM2_EncryptDecrypt2` with a public-only symmetric key.
#[test]
fn encrypt_decrypt2_public_only_sym_key_fails() {
    let mut sim = Tpm::new();
    let key = public_only_sym_key(&mut sim);
    let mut params = tpm2b_params(&[0x22; 16]); // inData
    params.push(0); // decrypt = NO
    params.extend_from_slice(&0x0043u16.to_be_bytes()); // CFB
    put_tpm2b(&mut params, &[0; 16]); // ivIn
    let code = send_rc_with_auth_entries(
        &mut sim,
        TpmCc::EncryptDecrypt2,
        &[key],
        &[AuthEntry::pw(&[])],
        &params,
    );
    assert_eq!(code, RC_AUTH_UNAVAILABLE);
}

/// TPM2_EncryptDecrypt with a public-only symmetric key fails
///
/// `TPM2_EncryptDecrypt` with a public-only symmetric key.
#[test]
fn encrypt_decrypt_public_only_sym_key_fails() {
    let mut sim = Tpm::new();
    let key = public_only_sym_key(&mut sim);
    let mut params = Vec::new();
    params.push(0); // decrypt = NO
    params.extend_from_slice(&0x0043u16.to_be_bytes()); // CFB
    put_tpm2b(&mut params, &[0; 16]); // ivIn
    put_tpm2b(&mut params, &[0x22; 16]); // inData
    let code = send_rc_with_auth_entries(
        &mut sim,
        TpmCc::EncryptDecrypt,
        &[key],
        &[AuthEntry::pw(&[])],
        &params,
    );
    assert_eq!(code, RC_AUTH_UNAVAILABLE);
}

/// Public-only objects cannot be authorized by authValue nor by authPolicy
///
/// Public-only objects (loaded without a private area) cannot be authorized at all: neither
/// their authValue nor their authPolicy is available (C `IsAuthValueAvailable()` /
/// `IsAuthPolicyAvailable()` require `publicOnly == CLEAR`).
#[test]
fn public_only_object_cannot_be_authorized() {
    let mut sim = Tpm::new();
    let public = sealed_template_with_policy(
        TpmaObject::USER_WITH_AUTH | TpmaObject::NO_DA,
        &EMPTY_POLICY,
    );
    let item = load_public_only(&mut sim, &public);
    assert_eq!(
        unseal_with_auth_entry(&mut sim, item, AuthEntry::pw(&[])),
        RC_AUTH_UNAVAILABLE
    );
    let policy = start_session_of_type(&mut sim, TpmSe::Policy);
    assert_eq!(
        unseal_with_auth_entry(&mut sim, item, raw_entry(&policy, 0, &[])),
        RC_AUTH_UNAVAILABLE
    );
}

/// TPM2_Sign with a public-only HMAC key fails
///
/// `TPM2_Sign` with a public-only HMAC key.
#[test]
fn sign_public_only_hmac_key_fails() {
    let mut sim = Tpm::new();
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            Tpm2bDigest::from_bytes(leak_bytes(&[7; 32])).unwrap(),
        ),
    };
    let key = load_public_only(&mut sim, &public);
    let mut params = tpm2b_params(&[0x11; 32]);
    params.extend_from_slice(&0x0010u16.to_be_bytes()); // inScheme: TPM_ALG_NULL
    params.extend_from_slice(&0x8024u16.to_be_bytes()); // TPM_ST_HASHCHECK
    params.extend_from_slice(&Handle::RH_NULL.0.to_be_bytes());
    put_tpm2b(&mut params, &[]);
    let code = send_rc_with_auth_entries(
        &mut sim,
        TpmCc::Sign,
        &[key],
        &[AuthEntry::pw(&[])],
        &params,
    );
    assert_eq!(code, RC_AUTH_UNAVAILABLE);
}

/// TPM2_Unseal of a public-only sealed-data object fails
///
/// `TPM2_Unseal` of a public-only sealed-data object.
#[test]
fn unseal_public_only_sealed_object_fails() {
    let mut sim = Tpm::new();
    let public = sealed_template_with_policy(TpmaObject::USER_WITH_AUTH | TpmaObject::NO_DA, &[]);
    let item = load_public_only(&mut sim, &public);
    assert_eq!(
        unseal_with_auth_entry(&mut sim, item, AuthEntry::pw(&[])),
        RC_AUTH_UNAVAILABLE
    );
}

/// An HMAC session bound to another entity cannot authorize a public-only object: its
/// sensitive area is not loaded, so the TPM returns `TPM_RC_AUTH_UNAVAILABLE` (TPM 2.0 Part 3,
/// "Authorization Checks": "Authorization checks must be performed in this order. 1. The public
/// and sensitive portions of the object shall be present on the TPM
/// (`TPM_RC_AUTH_UNAVAILABLE`)."), before the check whether the session is bound to the object
/// (which needs the object's authValue). Found by differential fuzzing (the references entered
/// failure mode in `EntityGetAuthValue()`).
#[test]
fn bound_hmac_session_cannot_authorize_public_only_object() {
    let mut tpm = Tpm::new();
    // TPM2_NV_DefineSpace(TPM_RH_OWNER, auth "a-auth", index 0x01500031).
    let rsp = tpm.send_command(
        0,
        &[
            0x80, 0x02, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x01, 0x2a, 0x40, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x06, 0x61, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x00, 0x0e, 0x01, 0x50, 0x00, 0x31, 0x00,
            0x0b, 0x02, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        ],
    );
    assert_eq!(rc_of(&rsp), 0);
    // TPM2_StartAuthSession(tpmKey = TPM_RH_NULL, bind = 0x01500031, HMAC, SHA-256).
    let rsp = tpm.send_command(
        0,
        &[
            0x80, 0x01, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x00, 0x01, 0x76, 0x40, 0x00, 0x00, 0x07,
            0x01, 0x50, 0x00, 0x31, 0x00, 0x10, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x0b,
        ],
    );
    assert_eq!(rc_of(&rsp), 0);
    let session = u32::from_be_bytes(rsp[10..14].try_into().unwrap());
    // TPM2_LoadExternal(public-only keyedhash object, TPM_RH_NULL).
    let rsp = tpm.send_command(
        0,
        &[
            0x80, 0x01, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x01, 0x67, 0x00, 0x00, 0x00, 0x30,
            0x00, 0x08, 0x00, 0x0b, 0x00, 0x04, 0x00, 0x40, 0x00, 0x00, 0x00, 0x05, 0x00, 0x0b,
            0x00, 0x20, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0xbe, 0xb9, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x40, 0x00, 0x00, 0x07,
        ],
    );
    assert_eq!(rc_of(&rsp), 0);
    let object = u32::from_be_bytes(rsp[10..14].try_into().unwrap());
    // TPM2_Create(parentHandle = the public-only object) authorized by the bound session.
    let mut cmd = vec![0x80, 0x02, 0x00, 0x00, 0x00, 0x5d, 0x00, 0x00, 0x01, 0x53];
    cmd.extend_from_slice(&object.to_be_bytes());
    cmd.extend_from_slice(&[0x00, 0x00, 0x00, 0x49]);
    cmd.extend_from_slice(&session.to_be_bytes());
    cmd.extend_from_slice(&[0x00, 0x20]);
    cmd.extend_from_slice(&[0xb1; 32]); // nonceCaller
    cmd.extend_from_slice(&[0x00, 0x00, 0x20]); // attributes, hmac size
    cmd.extend_from_slice(&[0xb0; 32]); // hmac
    cmd.extend_from_slice(&[0x00, 0x00]); // inSensitive (truncated parameters)
    assert_eq!(cmd.len(), 0x5d);
    assert_eq!(rc_of(&tpm.send_command(0, &cmd)), RC_AUTH_UNAVAILABLE);
}
