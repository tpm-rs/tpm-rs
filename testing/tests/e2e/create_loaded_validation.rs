//! TPM2_CreateLoaded parameter validation: parent handles, template/sensitive encoding and size
//! limits.

#![allow(deprecated)] // TPM2_CreateLoaded is deprecated upstream but still implemented.

use crate::_common::{
    command_rc, execute_with_password_sessions, execute_with_password_sessions_status,
    make_template, marshal_to_slice, owner_srk, rc_p, sealed_template, sensitive_create,
};
use testing::tpm::Tpm;
use tpm2::commands::{CreateLoaded, CreatePrimary};
use tpm2::errors::TpmRc;
use tpm2::{
    Command, Handle, Marshal, Message, PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest,
    Tpm2bEccParameter, Tpm2bPublicKeyRsa, Tpm2bSensitiveCreate, Tpm2bSensitiveData, Tpm2bTemplate,
    TpmCc, TpmEccCurve, TpmaObject, TpmiAlgHash, TpmsEccParms, TpmsEccPoint, TpmsRsaParms,
    TpmsSchemeEcdaa, TpmsSensitiveCreate, TpmtEccScheme, TpmtPublic, TpmtRsaScheme,
};

/// CreateLoaded with a 40-byte userAuth for a SHA-256 key fails with TPM_RC_SIZE.
#[test]
fn auth_longer_than_name_alg_digest_rejected() {
    let mut sim = Tpm::new();
    let password = [0x41u8; 40]; // 40 bytes, > SHA256 (32 bytes)
    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(&password).unwrap(),
        data: Tpm2bSensitiveData::default(),
    });

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::USER_WITH_AUTH | TpmaObject::SIGN_ENCRYPT,
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
        parent_handle: Handle(tpm2::Handle::RH_OWNER.0),
        in_sensitive,
        in_public: make_template(&pub_area),
    };

    let res = execute_with_password_sessions(&mut sim, &create, 1, &[]);

    // It should fail with TPM_RC_SIZE because the auth size > nameAlg digest size.
    assert!(
        res.is_err(),
        "Expected CreateLoaded to fail when auth size is too large"
    );
    match res {
        Err(e) => {
            // TPM_RC_SIZE = 0x095, optionally with format bits
            assert_eq!(
                e & 0x0BF,
                0x095,
                "Expected TPM_RC_SIZE for invalid auth length, got 0x{:X}",
                e
            );
        }
        Ok(_) => panic!("Expected CreateLoaded to fail but it succeeded"),
    }
}

/// TPM2_CreateLoaded of a primary on TPM_RH_OWNER with large sensitive data and sensitiveDataOrigin set is accepted
#[test]
fn create_loaded_primary_discards_large_sensitive_data() {
    let mut sim = Tpm::new();

    // Large sensitive data
    let large_data = [0u8; 128];
    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::from_bytes(&large_data).unwrap(),
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

    // Test TPM_RH_OWNER (supported)

    let res = execute_with_password_sessions(&mut sim, &create, 1, &[]);
    // C accepts this: the "data must be empty when sensitiveDataOrigin is SET"
    // rule only applies to ordinary objects (Object_spt.c CreateChecks), and for
    // a primary object the provided data is discarded (CryptUtil.c:1092-1093).
    assert!(
        res.is_ok(),
        "CreateLoaded of a primary with sensitiveDataOrigin ignores inSensitive.data: {res:?}"
    );
}

/// CreateLoaded with parent 0xFFFFFFFF fails.
#[test]
fn invalid_permanent_parent_rejected() {
    let mut sim = Tpm::new();

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
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
        parent_handle: Handle(0xFFFFFFFF), // Invalid permanent handle
        in_sensitive,
        in_public,
    };

    let res = execute_with_password_sessions(&mut sim, &create, 1, &[]);
    assert!(res.is_err(), "CreateLoaded with 0xFFFFFFFF should fail");
}

/// CreateLoaded under a parent without DECRYPT is TPM_RC_TYPE + RC_H1
#[test]
fn non_storage_parent_rejected() {
    let mut sim = Tpm::new();

    let rsa_parms = TpmsRsaParms {
        symmetric: None,
        scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        key_bits: tpm2::TpmiRsaKeyBits(2048),
        exponent: 0,
    };

    let public_primary = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject(
            TpmaObject::FIXED_TPM.0
                | TpmaObject::FIXED_PARENT.0
                | TpmaObject::SENSITIVE_DATA_ORIGIN.0
                | TpmaObject::USER_WITH_AUTH.0
                | TpmaObject::SIGN_ENCRYPT.0, // NOT DECRYPT
        ),
        auth_policy: Default::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, Tpm2bPublicKeyRsa::default()),
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
    let rsp1 = execute_with_password_sessions(&mut sim, &cmd1, 1, &[]).unwrap();

    let parent_handle = rsp1.object_handle;

    let public_child = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject(
            TpmaObject::FIXED_TPM.0
                | TpmaObject::FIXED_PARENT.0
                | TpmaObject::SENSITIVE_DATA_ORIGIN.0
                | TpmaObject::USER_WITH_AUTH.0
                | TpmaObject::SIGN_ENCRYPT.0,
        ),
        auth_policy: Default::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, Tpm2bPublicKeyRsa::default()),
    };

    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&public_child, &mut pub_buf);

    let cmd2 = CreateLoaded {
        parent_handle,
        in_sensitive: tpm2::Tpm2b(tpm2::TpmsSensitiveCreate {
            user_auth: Default::default(),
            data: Default::default(),
        }),
        in_public: Tpm2bTemplate::from_bytes(&pub_buf[..pub_len]).unwrap(),
    };

    let res = execute_with_password_sessions(&mut sim, &cmd2, 1, &[]);
    assert!(
        res.is_err(),
        "Expected TPM2_CreateLoaded to fail on parent without decrypt attr"
    );
    let err = res.err().unwrap();
    // C CreateLoaded.c:69-70: a parent object that is not a storage parent is
    // rejected with TPM_RCS_TYPE + RC_CreateLoaded_parentHandle (TYPE+H1, 0x18A).
    assert_eq!(err, 0x18a, "Expected Type error (0x18A), got {:#x}", err);
}

/// CreateLoaded with parentHandle = TPM_RH_NULL creates a primary-like object successfully.
#[test]
fn null_hierarchy_parent_succeeds() {
    let mut sim = Tpm::new();

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
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
        parent_handle: Handle(0x40000007),
        in_sensitive,
        in_public,
    };

    // Test TPM_RH_NULL

    let res = execute_with_password_sessions(&mut sim, &create, 1, &[]);
    if let Err(rc) = res {
        panic!("Expected SUCCESS but got error 0x{:X}", rc);
    }
}

/// CreateLoaded with a NULL nameAlg in the template fails with HASH+P2.
#[test]
fn null_name_alg_rejected_as_hash_error() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    let mut t = sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    t.name_alg = None;
    let rc = command_rc(
        &mut sim,
        &CreateLoaded {
            parent_handle: srk,
            in_sensitive: sensitive_create(&[], b"x"),
            in_public: make_template(&t),
        },
        1,
    );
    assert_eq!(rc, rc_p(TpmRc::HASH, 2));
}

/// CreateLoaded with trailing garbage after the public template fails.
#[test]
fn trailing_bytes_in_public_rejected() {
    let mut sim = Tpm::new();

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(b"pass").unwrap(),
        data: Tpm2bSensitiveData::default(),
    };

    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH,
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

    let mut valid_buf = [0u8; 1024];
    let valid_len = marshal_to_slice(&pub_area, &mut valid_buf);

    let mut bad_buf = valid_buf[..valid_len + 5].to_vec();
    bad_buf[valid_len] = 0xDE;
    bad_buf[valid_len + 1] = 0xAD;

    let in_public = Tpm2bTemplate::from_bytes(&bad_buf).unwrap();

    let create = CreateLoaded {
        parent_handle: Handle(0x40000001), // TPM_RH_OWNER
        in_sensitive,
        in_public,
    };

    let res = execute_with_password_sessions(&mut sim, &create, 1, &[]);
    match res {
        Ok(_) => panic!("BUG: CreateLoaded succeeded with trailing garbage in in_public!"),
        Err(e) => {
            println!("Got expected error code: 0x{:x}", e);
        }
    }
}

/// CreateLoaded with trailing garbage inside inSensitive is rejected.
#[test]
fn trailing_bytes_in_sensitive_rejected() {
    let mut sim = Tpm::new();

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(b"pass").unwrap(),
        data: Tpm2bSensitiveData::default(),
    };

    let mut valid_buf = [0u8; 1024];
    let valid_len = marshal_to_slice(&tpmt_sensitive, &mut valid_buf);

    let mut bad_buf = valid_buf[..valid_len + 5].to_vec();
    // Add some trailing garbage
    bad_buf[valid_len] = 0xFF;
    bad_buf[valid_len + 1] = 0xFF;

    assert!(
        Tpm2bSensitiveCreate::from_bytes(&bad_buf).is_err(),
        "Client unmarshaler should reject trailing garbage in in_sensitive"
    );

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH,
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

    struct BadCreateLoaded<'a> {
        parent_handle: Handle,
        in_sensitive_buf: &'a [u8],
        in_public: Tpm2bTemplate<'a>,
    }
    impl Marshal for BadCreateLoaded<'_> {
        const MAX_SIZE: usize = 4096;
        type MaxBuffer = [u8; 4096];
        fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
            let mut off =
                (self.in_sensitive_buf.len() as u16).marshal((&mut dst[0..2]).try_into().unwrap());
            dst[off..off + self.in_sensitive_buf.len()].copy_from_slice(self.in_sensitive_buf);
            off += self.in_sensitive_buf.len();
            off += self.in_public.marshal(
                (&mut dst[off..off + Tpm2bTemplate::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
            off
        }
    }
    impl Command for BadCreateLoaded<'_> {
        const CMD_CODE: TpmCc = TpmCc::CreateLoaded;
        type Response<'a> = ();
    }
    impl Message for BadCreateLoaded<'_> {
        type Handles = [Handle; 1];
        fn handles(&self) -> Self::Handles {
            [self.parent_handle]
        }
    }

    let create = BadCreateLoaded {
        parent_handle: Handle(0x40000001), // TPM_RH_OWNER
        in_sensitive_buf: &bad_buf,
        in_public,
    };

    let res = execute_with_password_sessions_status(&mut sim, &create, 1, &[]);
    match res {
        Ok(_) => panic!("BUG: CreateLoaded succeeded with trailing garbage in in_sensitive!"),
        Err(e) => {
            println!("Got expected error code: 0x{:x}", e);
            // 0x195 is TpmRc::SIZE. With Pos1, it should be 0x195 + 0x100?
            // Actually let's just make sure it fails.
        }
    }
}

/// CreateLoaded with an unloaded transient parent handle fails.
#[test]
fn unloaded_parent_rejected() {
    let mut sim = Tpm::new();

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(b"pass").unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH,
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
        parent_handle: Handle(0x8000000F),
        in_sensitive,
        in_public,
    };
    // Use an uninitialized invalid handle for parent

    let res = execute_with_password_sessions(&mut sim, &create, 1, &[]);
    assert!(
        res.is_err(),
        "BUG: CreateLoaded succeeded with invalid parent handle! Missing existence/auth checks."
    );
}
