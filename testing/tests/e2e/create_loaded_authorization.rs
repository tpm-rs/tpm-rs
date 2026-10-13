//! TPM2_CreateLoaded parent authorization: wrong passwords, userWithAuth and missing sessions.

use crate::_common::{AES128_CFB, execute_with_password_sessions, make_template};
use testing::tpm::Tpm;
#[allow(deprecated)]
use tpm2::commands::{CreateLoaded, CreatePrimary};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmEccCurve, TpmaObject, TpmiAlgHash, TpmiRsaKeyBits,
    TpmlPcrSelection, TpmsEccParms, TpmsEccPoint, TpmsRsaParms, TpmsSchemeEcdaa,
    TpmsSensitiveCreate, TpmtEccScheme, TpmtPublic,
};

/// CreateLoaded under a parent without userWithAuth rejects password authorization.
#[test]
#[allow(deprecated)]
fn parent_without_user_with_auth_rejects_password() {
    let mut sim = Tpm::new();

    let password = b"parent_secret";

    // 1. Create a parent object WITHOUT USER_WITH_AUTH
    let parent_in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(password).unwrap(),
        data: Tpm2bSensitiveData::default(),
    });

    // MISSING USER_WITH_AUTH
    let parent_pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: Some(AES128_CFB),
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };

    let create_parent = CreateLoaded {
        parent_handle: Handle(tpm2::Handle::RH_OWNER.0),
        in_sensitive: parent_in_sensitive,
        in_public: make_template(&parent_pub_area),
    };

    let rsp_handles = execute_with_password_sessions(&mut sim, &create_parent, 1, &[]).unwrap();
    let parent_handle = rsp_handles.object_handle;

    // 2. Try to create a child under this parent
    let child_in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });

    let child_pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
                    hash_alg: TpmiAlgHash::Sha256,
                    count: 0,
                })),
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };

    let create_child = CreateLoaded {
        parent_handle,
        in_sensitive: child_in_sensitive,
        in_public: make_template(&child_pub_area),
    };

    let result = execute_with_password_sessions(&mut sim, &create_child, 1, password);
    if result.is_ok() {
        panic!(
            "VULNERABILITY: CreateLoaded allowed password authorization for parent even though parent's USER_WITH_AUTH was 0!"
        );
    }
}

/// CreateLoaded under a password-protected parent with the wrong password fails.
#[test]
#[allow(deprecated)]
fn wrong_parent_password_rejected() {
    let mut sim = Tpm::new();

    // 1. Create a primary key WITH A PASSWORD
    let parent_password = b"secret_parent_pass";
    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(parent_password).unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let cp_cmd = CreatePrimary {
        primary_handle: Handle(0x40000001),
        in_sensitive: tpm2::Tpm2b(tpmt_sensitive),
        in_public: tpm2::Tpm2b(pub_area),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let cp_resp_handles = execute_with_password_sessions(&mut sim, &cp_cmd, 1, &[]).unwrap();

    // 2. Try to CreateLoaded under this parent WITH WRONG PASSWORD
    let cl_cmd = CreateLoaded {
        parent_handle: cp_resp_handles.object_handle,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: make_template(&pub_area),
    };

    let wrong_password = b"wrong_pass";
    let res = execute_with_password_sessions(&mut sim, &cl_cmd, 1, wrong_password);

    assert!(
        res.is_err(),
        "BUG: CreateLoaded succeeded with incorrect parent password! Missing auth check."
    );
}

/// CreateLoaded under a parent without USER_WITH_AUTH and with zero sessions fails.
#[test]
#[allow(deprecated)]
fn zero_sessions_rejected() {
    let mut sim = Tpm::new();

    let password = b"parent_secret";

    // 1. Create a parent object WITHOUT USER_WITH_AUTH
    let parent_in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(password).unwrap(),
        data: Tpm2bSensitiveData::default(),
    });

    // MISSING USER_WITH_AUTH
    let parent_pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: Some(AES128_CFB),
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };

    let create_parent = CreateLoaded {
        parent_handle: Handle(tpm2::Handle::RH_OWNER.0),
        in_sensitive: parent_in_sensitive,
        in_public: make_template(&parent_pub_area),
    };

    let rsp_handles = execute_with_password_sessions(&mut sim, &create_parent, 1, &[]).unwrap();
    let parent_handle = rsp_handles.object_handle;

    // 2. Try to create a child under this parent, with num_sessions = 0
    let child_in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });

    let child_pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
                    hash_alg: TpmiAlgHash::Sha256,
                    count: 0,
                })),
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };

    let create_child = CreateLoaded {
        parent_handle,
        in_sensitive: child_in_sensitive,
        in_public: make_template(&child_pub_area),
    };

    let result = execute_with_password_sessions(&mut sim, &create_child, 0, &[]);
    if result.is_ok() {
        panic!(
            "VULNERABILITY: CreateLoaded allowed 0 sessions when USER_WITH_AUTH was 0! Bypass achieved."
        );
    }
}
