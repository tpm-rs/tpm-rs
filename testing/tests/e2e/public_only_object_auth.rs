//! Public-only objects cannot be authorized (authValue or authPolicy) or used for private
//! operations.

use crate::_common::*;
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bDigest, TpmCc, TpmSe, TpmaObject, TpmiAlgHash,
    TpmtKeyedHashScheme, TpmtPublic,
};
use tpm2_simulator::create_simulator;

/// TPM2_EncryptDecrypt2 with a public-only symmetric key fails without panicking
///
/// `TPM2_EncryptDecrypt2` with a public-only symmetric key.
#[test]
fn encrypt_decrypt2_public_only_sym_key_fails() {
    let mut sim = create_simulator!();
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
    let mut sim = create_simulator!();
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
    let mut sim = create_simulator!();
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
    let mut sim = create_simulator!();
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
    let mut sim = create_simulator!();
    let public = sealed_template_with_policy(TpmaObject::USER_WITH_AUTH | TpmaObject::NO_DA, &[]);
    let item = load_public_only(&mut sim, &public);
    assert_eq!(
        unseal_with_auth_entry(&mut sim, item, AuthEntry::pw(&[])),
        RC_AUTH_UNAVAILABLE
    );
}
