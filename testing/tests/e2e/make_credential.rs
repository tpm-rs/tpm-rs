//! TPM2_MakeCredential: protector handle and credential size validation.

use crate::_common::{hex_checked as hex, *};
use testing::tpm::Tpm;
use tpm2::commands::{CreatePrimary, MakeCredential};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, Tpm2bAuth, Tpm2bDigest, Tpm2bSensitiveData, TpmsSensitiveCreate};

/// MakeCredential with a credential larger than the protector nameAlg digest fails with TPM_RC_SIZE.
#[test]
fn credential_larger_than_digest_rejected() {
    let mut sim = Tpm::new();

    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });

    // 1. Create ECC EK (name_alg is SHA256, digest size is 32 bytes)
    let ek_pub = get_ecc_ek_template();
    let in_public_ek = tpm2::Tpm2b(ek_pub);
    let create_primary_ek = CreatePrimary {
        primary_handle: Handle::RH_ENDORSEMENT,
        in_sensitive,
        in_public: in_public_ek,
        ..Default::default()
    };
    let ek_resp_handles = execute_with_password_sessions(&mut sim, &create_primary_ek, 1, &[])
        .expect("could not generate EK");

    // 2. Create target SRK
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = tpm2::Tpm2b(srk_pub);
    let create_primary_srk = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public: in_public_srk,
        ..Default::default()
    };
    let srk_resp = execute_with_password_sessions(&mut sim, &create_primary_srk, 1, &[])
        .expect("could not generate SRK");

    // 3. Credential size of 33 bytes exceeds SHA256 digest size of 32 bytes.
    let secret = Tpm2bDigest::from_bytes(&[0u8; 33]).unwrap();
    let mc = MakeCredential {
        handle: ek_resp_handles.object_handle,
        credential: secret,
        object_name: srk_resp.name,
    };
    let res = execute_with_password_sessions(&mut sim, &mc, 0, &[]);
    assert_eq!(
        res.err().unwrap(),
        TpmRc::SIZE.with(Position::parameter(1)).get()
    );
}

/// MakeCredential treats its first handle as an object handle when parsing the request.
///
/// Verifies that TPM2_MakeCredential correctly recognizes its first handle as an object handle during request parsing.
#[test]
fn handle_parsed_as_object() {
    let mut sim = Tpm::new();

    let make_cred_req = hex(concat!(
        "8001",          // tag: NO_SESSIONS
        "0000001a",      // size: 26 bytes
        "00000168",      // command code: TPM_CC_MakeCredential (0x0168)
        "80000000",      // handle 0: unloaded object handle
        "0004 01020304", // credential (TPM2B_DIGEST)
        "0004 00010203", // objectName (TPM2B_NAME)
    ));
    let rc = raw_rc(&mut sim, &make_cred_req);
    // `handle` is a TPMI_DH_OBJECT: an unloaded transient handle is TPM_RC_REFERENCE_H0.
    assert_eq!(
        rc,
        TpmRc::REFERENCE_H0.get(),
        "Command targeting unmapped handle 0x80000000 must fail with TPM_RC_REFERENCE_H0"
    );
}

/// MakeCredential with a non-existent protector handle fails with TPM_RC_REFERENCE_H0.
#[test]
fn missing_protector_handle_rejected() {
    let mut sim = Tpm::new();

    let srk_pub = get_ecc_srk_template();
    let in_public_srk = tpm2::Tpm2b(srk_pub);
    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });
    let create_primary_srk = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public: in_public_srk,
        ..Default::default()
    };
    let srk_resp = execute_with_password_sessions(&mut sim, &create_primary_srk, 1, &[])
        .expect("could not generate SRK");

    let secret = Tpm2bDigest::from_bytes(b"Secrets!!!").unwrap();
    let mc = MakeCredential {
        handle: Handle(0x8000000E),
        credential: secret,
        object_name: srk_resp.name,
    };
    // Non-existent transient handle
    let res = execute_with_password_sessions(&mut sim, &mc, 0, &[]);
    assert_eq!(res.err().unwrap(), TpmRc::REFERENCE_H0.get());
}

/// MakeCredential with a restricted sign-only protector fails with TPM_RC_TYPE.
#[test]
fn sign_only_protector_rejected() {
    let mut sim = Tpm::new();

    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });

    // 1. Create a protector key that is restricted sign-only
    let protector_template = get_ecc_sign_restricted_template();
    let in_public_p = tpm2::Tpm2b(protector_template);
    let create_primary_p = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public: in_public_p,
        ..Default::default()
    };
    let p_resp_handles = execute_with_password_sessions(&mut sim, &create_primary_p, 1, &[])
        .expect("could not generate protector key");

    // 2. Create target SRK
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = tpm2::Tpm2b(srk_pub);
    let create_primary_srk = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public: in_public_srk,
        ..Default::default()
    };
    let srk_resp = execute_with_password_sessions(&mut sim, &create_primary_srk, 1, &[])
        .expect("could not generate SRK");

    // 3. MakeCredential should fail because protector key does not have DECRYPT attribute
    let secret = Tpm2bDigest::from_bytes(b"Secrets!!!").unwrap();
    let mc = MakeCredential {
        handle: p_resp_handles.object_handle,
        credential: secret,
        object_name: srk_resp.name,
    };
    let res = execute_with_password_sessions(&mut sim, &mc, 0, &[]);
    assert_eq!(
        res.err().unwrap(),
        TpmRc::TYPE.with(Position::handle(1)).get()
    );
}

/// MakeCredential with an unrestricted decryption protector fails with TPM_RC_TYPE.
#[test]
fn unrestricted_protector_rejected() {
    let mut sim = Tpm::new();

    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });

    // 1. Create a protector key that is decrypt but not restricted
    let protector_template = get_ecc_decrypt_unrestricted_template();
    let in_public_p = tpm2::Tpm2b(protector_template);
    let create_primary_p = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public: in_public_p,
        ..Default::default()
    };
    let p_resp_handles = execute_with_password_sessions(&mut sim, &create_primary_p, 1, &[])
        .expect("could not generate protector key");

    // 2. Create target SRK
    let srk_pub = get_ecc_srk_template();
    let in_public_srk = tpm2::Tpm2b(srk_pub);
    let create_primary_srk = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public: in_public_srk,
        ..Default::default()
    };
    let srk_resp = execute_with_password_sessions(&mut sim, &create_primary_srk, 1, &[])
        .expect("could not generate SRK");

    // 3. MakeCredential should fail because protector key does not have RESTRICTED attribute
    let secret = Tpm2bDigest::from_bytes(b"Secrets!!!").unwrap();
    let mc = MakeCredential {
        handle: p_resp_handles.object_handle,
        credential: secret,
        object_name: srk_resp.name,
    };
    let res = execute_with_password_sessions(&mut sim, &mc, 0, &[]);
    assert_eq!(
        res.err().unwrap(),
        TpmRc::TYPE.with(Position::handle(1)).get()
    );
}
