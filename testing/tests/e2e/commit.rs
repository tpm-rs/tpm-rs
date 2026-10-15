//! TPM2_Commit (ECDAA): key type/scheme/attribute requirements, point and size validation,
//! authorization and counter consumption.

use crate::_common::{
    AES128_CFB, base_attrs, commit, create_primary_with_auth_in, ecc_template, ecdaa_scheme,
    ecdaa_template, execute_with_hmac_sessions, execute_with_password_sessions,
    execute_with_password_sessions_status, leak_bytes, make_template, marshal_to_slice, rc_at,
    rc_bare, sign, start_auth_session,
};
use testing::tpm::Tpm;
#[allow(deprecated)]
use tpm2::commands::{Command, Commit, CreateLoaded, CreatePrimary, EvictControl, Message};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Marshal, PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter,
    Tpm2bEccPoint, Tpm2bPublicKeyRsa, Tpm2bSensitiveData, Tpm2bTemplate, TpmCc, TpmEccCurve, TpmSe,
    TpmaObject, TpmiAlgHash, TpmiRsaKeyBits, TpmsEccParms, TpmsEccPoint, TpmsRsaParms,
    TpmsSchemeEcdaa, TpmsSensitiveCreate, TpmtEccScheme, TpmtPublic, TpmtSignature,
};

/// A TPM2_Commit counter signs exactly once; reuse or an uncommitted counter fails with TPM_RC_VALUE.
///
/// The counter returned by TPM2_Commit signs exactly once; reusing it fails with
/// `TPM_RC_VALUE` (no ECDAA nonce reuse).
#[test]
fn commit_counter_signs_once() {
    let mut sim = Tpm::new();
    let key = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        ecdaa_template(base_attrs() | TpmaObject::SIGN_ENCRYPT),
        b"pw",
    );
    let count = commit(&mut sim, key, b"pw").expect("commit failed");

    let d1: &'static [u8] = leak_bytes(&[0x55; 32]);
    let d2: &'static [u8] = leak_bytes(&[0x66; 32]);
    let sig = sign(&mut sim, key, b"pw", d1, ecdaa_scheme(count))
        .expect("signing with the committed counter must succeed");
    assert!(matches!(sig, TpmtSignature::Ecdaa(_)));

    // Second signature with the same commitment (same r) must be refused.
    assert_eq!(
        sign(&mut sim, key, b"pw", d2, ecdaa_scheme(count)).unwrap_err(),
        rc_bare(TpmRc::VALUE)
    );
    // A counter that was never committed is refused as well.
    assert_eq!(
        sign(
            &mut sim,
            key,
            b"pw",
            d2,
            ecdaa_scheme(count.wrapping_add(1))
        )
        .unwrap_err(),
        rc_bare(TpmRc::VALUE)
    );

    // A new commitment can be used once.
    let count2 = commit(&mut sim, key, b"pw").unwrap();
    assert_eq!(count2, count.wrapping_add(1));
    sign(&mut sim, key, b"pw", d2, ecdaa_scheme(count2)).expect("fresh commit must sign");
}

/// Commit accepts persistent and policy-only ECDAA keys and rejects non-anonymous schemes with SCHEME + H1.
///
/// TPM2_Commit accepts persistent keys, policy-authorized keys with `userWithAuth` clear, and
/// requires an anonymous (ECDAA) scheme (`TPM_RC_SCHEME + RC_H1`).
#[test]
fn commit_key_and_scheme_requirements() {
    let mut sim = Tpm::new();

    // Persistent ECDAA key.
    let key = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        ecdaa_template(base_attrs() | TpmaObject::SIGN_ENCRYPT),
        b"pw",
    );
    let persistent = Handle(0x8100_0A01);
    execute_with_password_sessions(
        &mut sim,
        &EvictControl {
            auth: Handle::RH_OWNER,
            object_handle: key,
            persistent_handle: persistent,
        },
        1,
        &[],
    )
    .expect("EvictControl failed");
    commit(&mut sim, persistent, b"pw").expect("Commit must accept a persistent ECDAA key");

    // ECDSA key: not an anonymous scheme.
    let ecdsa_key = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        ecc_template(
            base_attrs() | TpmaObject::SIGN_ENCRYPT,
            Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        ),
        b"",
    );
    assert_eq!(
        commit(&mut sim, ecdsa_key, b"").unwrap_err(),
        rc_at(TpmRc::SCHEME, Position::handle(1))
    );

    // Policy-only ECDAA key (userWithAuth clear) authorized with a policy session whose
    // (initial, all-zero) digest matches the key's authPolicy.
    let mut template = ecdaa_template(
        TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::SIGN_ENCRYPT,
    );
    template.auth_policy = Tpm2bDigest::from_bytes(&[0u8; 32]).unwrap();
    let policy_key = create_primary_with_auth_in(&mut sim, Handle::RH_OWNER, template, b"");
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let cmd = Commit {
        sign_handle: policy_key,
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };
    execute_with_hmac_sessions(&mut sim, &cmd, &[], &mut [session], &[b""])
        .expect("Commit must accept a policy-authorized key with userWithAuth clear");
}

/// TPM2_Commit with an ECC restricted decryption key (NULL scheme) fails with TPM_RC_SCHEME + H1
#[test]
#[allow(deprecated)]
fn commit_rejects_ecc_storage_key() {
    let mut sim = Tpm::new();

    let password = b"hello";

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
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT, // Not SIGN_ENCRYPT
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                // A restricted decryption (storage) key needs a symmetric algorithm, otherwise
                // creation fails with TPM_RC_SYMMETRIC (C PublicAttributesValidation).
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

    let in_public = make_template(&pub_area);

    let create = CreateLoaded {
        parent_handle: Handle(0x40000001), // TPMRH_OWNER
        in_sensitive,
        in_public,
    };

    let rsp_handles = execute_with_password_sessions(&mut sim, &create, 1, &[]).unwrap();

    let commit = Commit {
        sign_handle: rsp_handles.object_handle,
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };

    let res = execute_with_password_sessions(&mut sim, &commit, 1, password);
    assert!(
        res.is_err(),
        "Commit on ECC key without SIGN attribute should fail"
    );
    // Commit.c: a storage key has a NULL scheme, which is not anonymous ->
    // TPM_RCS_SCHEME + RC_Commit_signHandle.
    assert_eq!(res.err(), Some(0x192));
}

/// TPM2_Commit with y2 present but P1 empty fails with TPM_RC_SIZE
#[test]
#[allow(deprecated)]
fn commit_rejects_y2_without_p1() {
    let mut sim = Tpm::new();

    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(b"password").unwrap(),
        data: Tpm2bSensitiveData::default(),
    });

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
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

    let create = CreateLoaded {
        parent_handle: tpm2::Handle(0x40000001),
        in_sensitive,
        in_public: make_template(&pub_area),
    };

    let rsp_handles = execute_with_password_sessions(&mut sim, &create, 1, &[]).unwrap();
    let key_handle = rsp_handles.object_handle;

    // Test with y2 provided but P1 empty
    let y2_bytes = [0xCC; 32];
    let y2 = Tpm2bEccParameter::from_bytes(&y2_bytes).unwrap();
    let commit = Commit {
        sign_handle: key_handle,
        p1: Tpm2bEccPoint::default(), // Empty!
        s2: Tpm2bSensitiveData::default(),
        y2,
    };

    let res = execute_with_password_sessions(&mut sim, &commit, 1, b"password");
    match res {
        Err(e) => {
            // Should be TPM_RC_SIZE (0x095) per TPM 2.0 Spec (when s2 is empty and y2 is present).
            assert_eq!(
                e & 0x0BF,
                0x095,
                "Expected error when y2 is provided without s2/p1"
            );
        }
        Ok(_) => {
            panic!("Expected Commit to fail when y2 is provided without p1, but it succeeded!")
        }
    }
}

/// Commit on an ECDAA key that requires USER auth fails without a session.
#[test]
#[allow(deprecated)]
fn commit_without_session_rejected() {
    let mut sim = Tpm::new();

    let password = b"hello";

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

    let in_public = make_template(&pub_area);

    let create = CreateLoaded {
        parent_handle: Handle(0x40000001), // TPMRH_OWNER
        in_sensitive,
        in_public,
    };

    let rsp_handles = execute_with_password_sessions(&mut sim, &create, 1, &[]).unwrap();

    let commit = Commit {
        sign_handle: rsp_handles.object_handle,
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };

    if execute_with_password_sessions(&mut sim, &commit, 0, &[]).is_ok() {
        panic!("Should fail with 0 sessions, but succeeded!");
    }
}

/// Commit with a key that has DECRYPT set fails.
#[test]
#[allow(deprecated)]
fn decrypt_key_rejected() {
    let mut sim = Tpm::new();
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
    let in_public = make_template(&pub_area);
    let create = CreateLoaded {
        parent_handle: Handle(0x40000001),
        in_sensitive,
        in_public,
    };
    let rsp_handles = execute_with_password_sessions(&mut sim, &create, 1, &[]).unwrap();

    let commit = Commit {
        sign_handle: rsp_handles.object_handle,
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };

    let res = execute_with_password_sessions(&mut sim, &commit, 1, password);

    assert!(
        res.is_err(),
        "BUG: Commit succeeded with DECRYPT attribute set! The handler should reject this."
    );
    // Error code should be attributes_for(Position::Handle, Pos1).
    // Specifically RC is FormatZero(0x0a2) or similar but testing `is_err()` is sufficient.
}

/// Commit with an ECDAA P-256 key rejects a wrong password and increments the counter on each success.
///
/// Previous (non-faithful) version of the `TestCommit` port: uses an ECDAA key
/// on NIST P-256 with an empty P1, and additionally checks that TPM2_Commit
/// fails when the signing key is authorized with a wrong password.
#[test]
#[allow(deprecated)]
fn ecdaa_counter_increments_and_wrong_password_rejected() {
    let mut sim = Tpm::new();

    let password = b"hello";

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
                scheme: Some(TpmtEccScheme::Ecdaa(tpm2::TpmsSchemeEcdaa {
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

    let in_public = make_template(&pub_area);

    let create = CreateLoaded {
        parent_handle: Handle(0x40000001), // TPMRH_OWNER
        in_sensitive,
        in_public,
    };

    let rsp_handles = execute_with_password_sessions(&mut sim, &create, 1, &[]).unwrap();

    let commit = Commit {
        sign_handle: rsp_handles.object_handle,
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };

    let password_wrong = b"wrong";
    let res = execute_with_password_sessions(&mut sim, &commit, 1, password_wrong);
    assert!(res.is_err(), "Wrong password should fail");

    let resp1 = execute_with_password_sessions(&mut sim, &commit, 1, password).unwrap();
    let first_counter = resp1.counter;

    let resp2 = execute_with_password_sessions(&mut sim, &commit, 1, password).unwrap();
    let second_counter = resp2.counter;

    assert_eq!(
        first_counter + 1,
        second_counter,
        "counter did not increment"
    );
}

/// TPM2_Commit with empty s2 but non-empty y2 fails.
#[test]
#[allow(deprecated)]
fn empty_s2_with_y2_rejected() {
    let mut sim = Tpm::new();
    let auth = b"secret";

    let ecc_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject(
            TpmaObject::USER_WITH_AUTH.0
                | TpmaObject::SIGN_ENCRYPT.0
                | TpmaObject::SENSITIVE_DATA_ORIGIN.0,
        ),
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
                    hash_alg: TpmiAlgHash::Sha256,
                    count: 0,
                })),
                // SM2P256 is close enough or use NIST_P256 if available?
                // Let's use SM2P256 or another valid curve from constants
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };

    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&ecc_pub, &mut pub_buf);

    let in_sens = tpm2::TpmsSensitiveCreate {
        user_auth: tpm2::Tpm2bDigest::from_bytes(auth).unwrap(),
        data: tpm2::Tpm2bSensitiveData::default(),
    };

    let mut in_sens_buf = [0u8; 1024];
    let _in_sens_len = marshal_to_slice(&in_sens, &mut in_sens_buf);

    let create_cmd = CreateLoaded {
        parent_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(in_sens),
        in_public: Tpm2bTemplate::from_bytes(&pub_buf[..pub_len]).unwrap(),
    };

    let resp_handles =
        execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).expect("CreateLoaded failed");

    let key_handle = resp_handles.object_handle;

    let mut commit_cmd = Commit::default();

    let mut p1_buf = [0u8; 1024];
    let p1_len = marshal_to_slice(
        &(TpmsEccPoint {
            x: Tpm2bEccParameter::from_bytes(&[1u8; 32]).unwrap(),
            y: Tpm2bEccParameter::from_bytes(&[2u8; 32]).unwrap(),
        }),
        &mut p1_buf,
    );
    commit_cmd.p1 = Tpm2bEccPoint::from_bytes(&p1_buf[..p1_len]).unwrap();

    commit_cmd.s2 = tpm2::Tpm2bSensitiveData::default(); // Empty
    commit_cmd.y2 = Tpm2bEccParameter::from_bytes(&[3u8; 32]).unwrap(); // Not empty
    commit_cmd.sign_handle = key_handle;

    let res = execute_with_password_sessions(&mut sim, &commit_cmd, 1, &[]);

    assert!(
        res.is_err(),
        "Expected Commit to fail when s2 is empty but y2 is not empty"
    );
}

/// Commit with a key lacking SIGN_ENCRYPT fails (or the key cannot be created).
#[test]
#[allow(deprecated)]
fn key_without_sign_encrypt_rejected() {
    let mut sim = Tpm::new();
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
    let in_public = make_template(&pub_area);
    let create = CreateLoaded {
        parent_handle: Handle(0x40000001),
        in_sensitive,
        in_public,
    };
    let create_res = execute_with_password_sessions(&mut sim, &create, 1, &[]);
    if let Err(e) = create_res {
        assert_eq!(e, TpmRc::ATTRIBUTES.with(Position::parameter(2)).get());
        return;
    }
    let rsp_handles = create_res.unwrap();

    let commit = Commit {
        sign_handle: rsp_handles.object_handle,
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };

    let res = execute_with_password_sessions(&mut sim, &commit, 1, password);

    assert!(
        res.is_err(),
        "BUG: Commit succeeded without SIGN_ENCRYPT attribute set! The handler should reject this."
    );
}

/// TPM2_Commit with a 40-byte s2 fails with TPM_RC_SIZE.
#[test]
#[allow(deprecated)]
fn oversized_s2_rejected() {
    let mut sim = Tpm::new();

    // Clear and get Owner auth
    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(b"password").unwrap(),
        data: Tpm2bSensitiveData::default(),
    });

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
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

    let create = CreateLoaded {
        parent_handle: tpm2::Handle(0x40000001),
        in_sensitive,
        in_public: make_template(&pub_area),
    };

    let rsp_handles = execute_with_password_sessions(&mut sim, &create, 1, &[]).unwrap();
    let key_handle = rsp_handles.object_handle;

    // Test with s2 = 40 bytes (max allowed is 32 for SHA256)
    let s2_bytes = [0xBB; 40];
    let s2 = Tpm2bSensitiveData::from_bytes(&s2_bytes).unwrap();
    let commit = Commit {
        sign_handle: key_handle,
        p1: Tpm2bEccPoint::default(),
        s2,
        y2: Tpm2bEccParameter::default(),
    };

    let res = execute_with_password_sessions(&mut sim, &commit, 1, b"password");
    match res {
        Err(e) => {
            // TPM_RC_SIZE (0x095) with possible parameter info
            assert_eq!(
                e & 0x0BF,
                0x095,
                "Expected TPM_RC_SIZE for invalid s2 length, got 0x{:X}",
                e
            );
        }
        Ok(_) => panic!("Expected Commit to fail with TPM_RC_SIZE but it succeeded!"),
    }
}

/// TPM2_Commit with a valid P1 point followed by trailing garbage inside the TPM2B is rejected.
#[test]
#[allow(deprecated)]
fn p1_with_trailing_bytes_rejected() {
    let mut sim = Tpm::new();
    let password = b"hello";
    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(password).unwrap(),
        data: Tpm2bSensitiveData::default(),
    });
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
    let in_public = make_template(&pub_area);
    let create = CreateLoaded {
        parent_handle: Handle(0x40000001),
        in_sensitive,
        in_public,
    };
    let rsp_handles = execute_with_password_sessions(&mut sim, &create, 1, &[]).unwrap();

    let commit1 = Commit {
        sign_handle: rsp_handles.object_handle,
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };
    let commit1_rsp = execute_with_password_sessions(&mut sim, &commit1, 1, password).unwrap();

    let valid_point = commit1_rsp.e.0;

    let mut valid_point_buf = [0u8; 100];
    let valid_len = marshal_to_slice(&valid_point, &mut valid_point_buf);
    let bad_p1_buf = valid_point_buf[..valid_len + 5].to_vec();

    struct BadCommit<'a> {
        sign_handle: Handle,
        p1_buf: &'a [u8],
        s2: Tpm2bSensitiveData<'a>,
        y2: Tpm2bEccParameter<'a>,
    }
    impl Marshal for BadCommit<'_> {
        const MAX_SIZE: usize = 1024;
        type MaxBuffer = [u8; 1024];
        fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
            let mut off = (self.p1_buf.len() as u16).marshal((&mut dst[0..2]).try_into().unwrap());
            dst[off..off + self.p1_buf.len()].copy_from_slice(self.p1_buf);
            off += self.p1_buf.len();
            off += self.s2.marshal(
                (&mut dst[off..off + Tpm2bSensitiveData::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
            off += self.y2.marshal(
                (&mut dst[off..off + Tpm2bEccParameter::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
            off
        }
    }
    impl Message for BadCommit<'_> {
        type Handles = [Handle; 1];
        fn handles(&self) -> Self::Handles {
            [self.sign_handle]
        }
    }
    impl Command for BadCommit<'_> {
        const CMD_CODE: TpmCc = TpmCc::Commit;
        type Response<'a> = ();
    }

    let commit2 = BadCommit {
        sign_handle: rsp_handles.object_handle,
        p1_buf: &bad_p1_buf,
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };

    let result = execute_with_password_sessions_status(&mut sim, &commit2, 1, password);
    match result {
        Ok(_) => panic!("VULNERABILITY: Trailing garbage in valid p1 ignored!"),
        Err(e) => println!("Error code: 0x{:x}", e),
    }
}

/// Commit on a key without userWithAuth rejects password authorization.
#[test]
#[allow(deprecated)]
fn password_rejected_without_user_with_auth() {
    let mut sim = Tpm::new();

    let password = b"secret";

    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(password).unwrap(),
        data: Tpm2bSensitiveData::default(),
    });

    // NOTICE: We omit TpmaObject::USER_WITH_AUTH
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
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

    let in_public = make_template(&pub_area);

    let create = CreateLoaded {
        parent_handle: Handle(tpm2::Handle::RH_OWNER.0),
        in_sensitive,
        in_public,
    };

    let rsp_handles = execute_with_password_sessions(&mut sim, &create, 1, &[]).unwrap();

    let commit = Commit {
        sign_handle: rsp_handles.object_handle,
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };

    // Attempt to authorize using the password
    let result = execute_with_password_sessions(&mut sim, &commit, 1, password);
    if result.is_ok() {
        panic!(
            "VULNERABILITY: Commit allowed password authorization even though USER_WITH_AUTH was 0!"
        );
    }
}

/// Commit with an RSA signing key fails
#[test]
#[allow(deprecated)]
fn rsa_key_rejected() {
    let mut sim = Tpm::new();

    let password = b"hello";

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

    let in_public = make_template(&pub_area);

    let create = CreateLoaded {
        parent_handle: Handle(0x40000001), // TPMRH_OWNER
        in_sensitive,
        in_public,
    };

    let rsp_handles = execute_with_password_sessions(&mut sim, &create, 1, &[]).unwrap();

    let commit = Commit {
        sign_handle: rsp_handles.object_handle,
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };

    let res = execute_with_password_sessions(&mut sim, &commit, 1, password);
    assert!(res.is_err(), "Commit on RSA key should fail");
}

/// Commit with a sign+decrypt ECC key fails with TPM_RC_SCHEME + RC_H1 (anonymous scheme check first)
#[test]
fn sign_decrypt_key_rejected_by_scheme() {
    let mut sim = Tpm::new();

    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: None,
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };

    let public_primary = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject(
            TpmaObject::FIXED_TPM.0
                | TpmaObject::FIXED_PARENT.0
                | TpmaObject::SENSITIVE_DATA_ORIGIN.0
                | TpmaObject::USER_WITH_AUTH.0
                | TpmaObject::SIGN_ENCRYPT.0
                | TpmaObject::DECRYPT.0, // DECRYPT SET!
        ),
        auth_policy: Default::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            ecc_parms,
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };

    let cmd1 = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(tpm2::TpmsSensitiveCreate {
            user_auth: Default::default(),
            data: Default::default(),
        }),
        in_public: tpm2::Tpm2b(public_primary),
        outside_info: Tpm2bData::default(),
        creation_pcr: Default::default(),
    };
    let resp_handles1 = execute_with_password_sessions(&mut sim, &cmd1, 1, &[]).unwrap();

    let sign_handle = resp_handles1.object_handle;

    let cmd2 = Commit {
        sign_handle,
        p1: tpm2::Tpm2bEccPoint::default(),
        s2: tpm2::Tpm2bSensitiveData::default(),
        y2: tpm2::Tpm2bEccParameter::default(),
    };

    let res = execute_with_password_sessions(&mut sim, &cmd2, 1, &[]);
    assert!(
        res.is_err(),
        "Expected TPM2_Commit to fail on handle WITH decrypt attr"
    );
    let err = res.err().unwrap();
    // Commit.c checks CryptIsSchemeAnonymous before anything attribute related: a sign+decrypt
    // ECC key must have a NULL scheme, so it fails with TPM_RCS_SCHEME + RC_Commit_signHandle.
    assert_eq!(err, 0x192, "Expected Scheme error (0x192), got {}", err);
}

/// Commit with trailing garbage inside the P1 TPM2B is rejected.
#[test]
#[allow(deprecated)]
fn trailing_bytes_in_p1_rejected() {
    let mut sim = Tpm::new();

    let password = b"hello";

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

    let in_public = make_template(&pub_area);

    let create = CreateLoaded {
        parent_handle: Handle(0x40000001), // TPMRH_OWNER
        in_sensitive,
        in_public,
    };

    let rsp_handles = execute_with_password_sessions(&mut sim, &create, 1, &[]).unwrap();

    // Create a p1 that is a valid empty point but has trailing garbage
    let valid_point = TpmsEccPoint {
        x: Tpm2bEccParameter::default(),
        y: Tpm2bEccParameter::default(),
    };
    let mut valid_point_buf = [0u8; 100];
    let valid_len = marshal_to_slice(&valid_point, &mut valid_point_buf);
    let bad_p1_buf = valid_point_buf[..valid_len + 10].to_vec();
    assert!(
        Tpm2bEccPoint::from_bytes(&bad_p1_buf).is_err(),
        "Client unmarshaler should reject trailing garbage in p1"
    );

    struct BadCommit<'a> {
        sign_handle: Handle,
        p1_buf: &'a [u8],
        s2: Tpm2bSensitiveData<'a>,
        y2: Tpm2bEccParameter<'a>,
    }
    impl Marshal for BadCommit<'_> {
        const MAX_SIZE: usize = 1024;
        type MaxBuffer = [u8; 1024];
        fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
            let mut off = (self.p1_buf.len() as u16).marshal((&mut dst[0..2]).try_into().unwrap());
            dst[off..off + self.p1_buf.len()].copy_from_slice(self.p1_buf);
            off += self.p1_buf.len();
            off += self.s2.marshal(
                (&mut dst[off..off + Tpm2bSensitiveData::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
            off += self.y2.marshal(
                (&mut dst[off..off + Tpm2bEccParameter::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
            off
        }
    }
    impl Message for BadCommit<'_> {
        type Handles = [Handle; 1];
        fn handles(&self) -> Self::Handles {
            [self.sign_handle]
        }
    }
    impl Command for BadCommit<'_> {
        const CMD_CODE: TpmCc = TpmCc::Commit;
        type Response<'a> = ();
    }

    let commit = BadCommit {
        sign_handle: rsp_handles.object_handle,
        p1_buf: &bad_p1_buf,
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };

    let result = execute_with_password_sessions_status(&mut sim, &commit, 1, password);
    println!("Is Ok: {}", result.is_ok());
    if result.is_ok() {
        panic!("VULNERABILITY: Trailing garbage in p1 ignored!");
    }
}

/// A key whose authValue is all zero bytes authorizes Commit with an empty password (trailing zeros stripped).
#[test]
#[allow(deprecated)]
fn trailing_zero_auth_value_matches_empty() {
    let mut sim = Tpm::new();

    let password = b"\x00\x00\x00\x00";

    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(password).unwrap(),
        data: Tpm2bSensitiveData::default(),
    });

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
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

    let in_public = make_template(&pub_area);

    let create = CreateLoaded {
        parent_handle: Handle(tpm2::Handle::RH_OWNER.0),
        in_sensitive,
        in_public,
    };

    let rsp_handles = execute_with_password_sessions(&mut sim, &create, 1, &[]).unwrap();

    let commit = Commit {
        sign_handle: rsp_handles.object_handle,
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };

    let result = execute_with_password_sessions(&mut sim, &commit, 1, &[]);
    assert!(
        result.is_ok(),
        "Expected authorization to succeed because trailing zeros in authValue are ignored"
    );
}

/// A key auth with trailing zeros authorizes Commit with the trimmed (empty) password.
#[test]
#[allow(deprecated)]
fn trailing_zero_key_auth_ignored() {
    let mut sim = Tpm::new();

    let password = b"\x00\x00\x00";

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

    let in_public = make_template(&pub_area);

    let create = CreateLoaded {
        parent_handle: Handle(0x40000001), // TPMRH_OWNER
        in_sensitive,
        in_public,
    };

    let rsp_handles = execute_with_password_sessions(&mut sim, &create, 1, &[]).unwrap();

    let commit = Commit {
        sign_handle: rsp_handles.object_handle,
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };

    let result = execute_with_password_sessions(&mut sim, &commit, 1, b"");
    assert!(
        result.is_ok(),
        "Expected authorization to succeed because trailing zeros in authValue are ignored"
    );
}

/// Commit with an unloaded transient sign handle fails.
#[test]
fn unloaded_sign_handle_rejected() {
    let mut sim = Tpm::new();
    let commit = Commit {
        sign_handle: Handle::TRANSIENT_LAST,
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };
    // Use an arbitrary uninitialized handle

    let res = execute_with_password_sessions(&mut sim, &commit, 1, b"");
    assert!(
        res.is_err(),
        "BUG: Commit succeeded with an invalid uninitialized handle! The handler is missing handle existence checks."
    );
}

/// Commit with an unloaded transient signHandle fails with TPM_RC_REFERENCE_H0.
///
/// An unloaded transient `signHandle` is reported as `TPM_RC_REFERENCE_H0`.
#[test]
fn unloaded_sign_handle_returns_reference_h0() {
    let mut sim = Tpm::new();
    assert_eq!(
        commit(&mut sim, Handle::TRANSIENT_LAST, b"").unwrap_err(),
        TpmRc::REFERENCE_H0.get()
    );
}

/// Commit with a wrong signing-key password must fail.
#[test]
#[allow(deprecated)]
fn wrong_password_rejected() {
    let mut sim = Tpm::new();
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
    let in_public = make_template(&pub_area);
    let create = CreateLoaded {
        parent_handle: Handle(0x40000001),
        in_sensitive,
        in_public,
    };
    let rsp_handles = execute_with_password_sessions(&mut sim, &create, 1, &[]).unwrap();

    let commit = Commit {
        sign_handle: rsp_handles.object_handle,
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };

    // THIS SHOULD FAIL because the password is wrong!
    let wrong_password = b"wrong_password";
    let res = execute_with_password_sessions(&mut sim, &commit, 1, wrong_password);

    // If it succeeds, it's a bug!
    assert!(
        res.is_err(),
        "BUG: Commit succeeded with wrong password! The handler is missing auth checks."
    );
}
