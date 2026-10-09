use crate::test_utils::*;
use tpm2::commands::{Commit, CommitHandles, CreateLoaded, CreateLoadedHandles};
use tpm2::errors::{Position, TpmRc};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_simulator::create_simulator;

#[test]
fn test_commit_auth_bypass() {
    let mut sim = create_simulator!();
    let password = b"correct_password";

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(password).unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::SIGN_ENCRYPT,
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
    let in_public = crate::test_utils::make_template(&pub_area);
    let create = CreateLoaded {
        in_sensitive,
        in_public,
    };
    let create_handles = CreateLoadedHandles {
        parent_handle: Handle(0x40000001),
    };
    let (_rsp_cp, rsp_handles) =
        execute_with_password_sessions(&mut sim, &create, create_handles, 1, &[]).unwrap();

    let commit = Commit {
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };
    let commit_handles = CommitHandles {
        sign_handle: rsp_handles.object_handle,
    };

    // THIS SHOULD FAIL because the password is wrong!
    let wrong_password = b"wrong_password";
    let res = execute_with_password_sessions(
        &mut sim,
        &commit,
        commit_handles.clone(),
        1,
        wrong_password,
    );

    // If it succeeds, it's a bug!
    assert!(
        res.is_err(),
        "BUG: Commit succeeded with wrong password! The handler is missing auth checks."
    );
}

#[test]
fn test_commit_invalid_handle() {
    let mut sim = create_simulator!();
    let commit = Commit {
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };
    // Use an arbitrary uninitialized handle
    let commit_handles = CommitHandles {
        sign_handle: Handle(0x80000099),
    };

    let res = execute_with_password_sessions(&mut sim, &commit, commit_handles, 1, b"");
    assert!(
        res.is_err(),
        "BUG: Commit succeeded with an invalid uninitialized handle! The handler is missing handle existence checks."
    );
}

#[test]
fn test_commit_decrypt_attr() {
    let mut sim = create_simulator!();
    let password = b"password";

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(password).unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::DECRYPT, // DECRYPT IS SET! THIS SHOULD FAIL IN COMMIT!
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
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
    let in_public = crate::test_utils::make_template(&pub_area);
    let create = CreateLoaded {
        in_sensitive,
        in_public,
    };
    let create_handles = CreateLoadedHandles {
        parent_handle: Handle(0x40000001),
    };
    let (_rsp_cp, rsp_handles) =
        execute_with_password_sessions(&mut sim, &create, create_handles, 1, &[]).unwrap();

    let commit = Commit {
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };
    let commit_handles = CommitHandles {
        sign_handle: rsp_handles.object_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &commit, commit_handles, 1, password);

    assert!(
        res.is_err(),
        "BUG: Commit succeeded with DECRYPT attribute set! The handler should reject this."
    );
    // Error code should be attributes_for(Position::Handle, Pos1).
    // Specifically RC is FormatZero(0x0a2) or similar but testing `is_err()` is sufficient.
}

#[test]
fn test_commit_missing_sign_encrypt_attr() {
    let mut sim = create_simulator!();
    let password = b"password";

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(password).unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SENSITIVE_DATA_ORIGIN,
        // SIGN_ENCRYPT IS MISSING!
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
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
    let in_public = crate::test_utils::make_template(&pub_area);
    let create = CreateLoaded {
        in_sensitive,
        in_public,
    };
    let create_handles = CreateLoadedHandles {
        parent_handle: Handle(0x40000001),
    };
    let create_res = execute_with_password_sessions(&mut sim, &create, create_handles, 1, &[]);
    if let Err(e) = create_res {
        assert_eq!(e, TpmRc::ATTRIBUTES.with(Position::parameter(2)).get());
        return;
    }
    let (_rsp_cp, rsp_handles) = create_res.unwrap();

    let commit = Commit {
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };
    let commit_handles = CommitHandles {
        sign_handle: rsp_handles.object_handle,
    };

    let res = execute_with_password_sessions(&mut sim, &commit, commit_handles, 1, password);

    assert!(
        res.is_err(),
        "BUG: Commit succeeded without SIGN_ENCRYPT attribute set! The handler should reject this."
    );
}
