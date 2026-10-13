#![forbid(unsafe_code)]
use crate::test_utils::*;
use tpm2::Handle;
use tpm2::commands::{Create, CreatePrimary, Load, ObjectChangeAuth, Unseal};
use tpm2::*;
use tpm2_simulator::create_simulator;

/// Data we are sealing.
const DATA: &[u8] = b"secrets";
/// Original auth for the key.
const AUTH: &[u8] = b"oldauth";
/// New auth we are changing to.
const NEWAUTH: &[u8] = b"newauth";

/// TPM_RC_BAD_AUTH reported on session 1 (TPM_RC_S | TPM_RC_1 | TPM_RC_BAD_AUTH).
const TPM_RC_BAD_AUTH_SESSION_1: u32 = 0x9A2;

/// go-tpm's `ECCSRKTemplate`.
fn get_ecc_srk_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: Some(TpmtSymDefObject {
                    alg: AlgSym::Aes128,
                    mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
                }),
                scheme: None,
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(&[0u8; 32]).unwrap(),
                y: Tpm2bEccParameter::from_bytes(&[0u8; 32]).unwrap(),
            },
        ),
    }
}

/// The Go `TestObjectChangeAuth` runs its subtests sequentially against one
/// TPM, each depending on the state left by the previous ones. Each Rust test
/// replays the Go flow up to and including its own subtest; this enum names
/// the subtests in Go order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Subtest {
    Create,
    WithPassword,
    ObjectChangeAuth,
    WithOldPassword,
    WithNewPassword,
}

/// Runs `TestObjectChangeAuth` up to and including subtest `last`, including
/// the setup between subtests and the deferred cleanup at the end.
fn run_object_change_auth(last: Subtest) {
    let mut sim = create_simulator!();

    // Create the SRK
    let create_srk_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(get_ecc_srk_template()),
        ..Default::default()
    };
    let srk_resp = execute_with_password_sessions(&mut sim, &create_srk_cmd, 1, &[])
        .expect("could not generate SRK");
    let srk_handle = srk_resp.object_handle;

    // Create a sealed blob under the SRK
    let create_blob_cmd = Create {
        parent_handle: srk_handle,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(AUTH).unwrap(),
            data: Tpm2bSensitiveData::from_bytes(DATA).unwrap(),
        }),
        in_public: tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::NO_DA,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };

    // Subtest "Create"
    let create_blob_rsp =
        execute_with_password_sessions(&mut sim, &create_blob_cmd, 1, &[]).expect("Create failed");
    if last == Subtest::Create {
        flush_context(&mut sim, srk_handle).unwrap();
        return;
    }

    let load_blob_cmd = Load {
        parent_handle: srk_handle,
        in_private: create_blob_rsp.out_private,
        in_public: create_blob_rsp.out_public,
    };
    let load_resp =
        execute_with_password_sessions(&mut sim, &load_blob_cmd, 1, &[]).expect("Load failed");
    let mut blob_handle = load_resp.object_handle;

    // Subtest "WithPassword": unseal the blob with a password session.
    // Each subtest builds its own Unseal command, because `blob_handle`
    // changes when the blob is reloaded after ObjectChangeAuth.
    let unseal_cmd = Unseal {
        item_handle: blob_handle,
    };
    let unseal_rsp = execute_with_password_sessions(&mut sim, &unseal_cmd, 1, AUTH)
        .expect("unseal with old auth failed");
    assert_eq!(unseal_rsp.out_data.get_buffer(), DATA);

    // Subtest "ObjectChangeAuth": change the auth of the object.
    if last >= Subtest::ObjectChangeAuth {
        let oca_cmd = ObjectChangeAuth {
            object_handle: blob_handle,
            parent_handle: srk_handle,
            new_auth: Tpm2bAuth::from_bytes(NEWAUTH).unwrap(),
        };
        let oca_rsp = execute_with_password_sessions(&mut sim, &oca_cmd, 1, AUTH)
            .expect("failed objectchangeauthrequest");

        // Flush the old handle
        flush_context(&mut sim, blob_handle).unwrap();

        // Load the new private blob, and the old public blob
        let load_new_cmd = Load {
            parent_handle: srk_handle,
            in_private: oca_rsp.out_private,
            in_public: create_blob_rsp.out_public,
        };
        let load_new_resp = execute_with_password_sessions(&mut sim, &load_new_cmd, 1, &[])
            .expect("Load of new private blob failed");
        blob_handle = load_new_resp.object_handle;
    }

    // Subtest "WithOldPassword": unsealing with the old password must fail
    // with TPM_RC_BAD_AUTH on session 1.
    if last >= Subtest::WithOldPassword {
        let unseal_cmd = Unseal {
            item_handle: blob_handle,
        };
        let unseal_err =
            execute_with_password_sessions(&mut sim, &unseal_cmd, 1, AUTH).unwrap_err();
        assert_eq!(
            unseal_err, TPM_RC_BAD_AUTH_SESSION_1,
            "want TPM_RC_BAD_AUTH on session 1, got {unseal_err:#x}"
        );
    }

    // Subtest "WithNewPassword": unsealing with the new password succeeds.
    if last >= Subtest::WithNewPassword {
        let unseal_cmd = Unseal {
            item_handle: blob_handle,
        };
        let unseal_rsp = execute_with_password_sessions(&mut sim, &unseal_cmd, 1, NEWAUTH)
            .expect("unseal with new auth failed");
        assert_eq!(unseal_rsp.out_data.get_buffer(), DATA);
    }

    // Deferred cleanup: flush the blob, then the SRK.
    flush_context(&mut sim, blob_handle).unwrap();
    flush_context(&mut sim, srk_handle).unwrap();
}

// Original Go test: object_change_auth_test.go - TestObjectChangeAuth/Create
#[test]
fn test_object_change_auth_create() {
    run_object_change_auth(Subtest::Create);
}

// Original Go test: object_change_auth_test.go - TestObjectChangeAuth/WithPassword
#[test]
fn test_object_change_auth_with_password() {
    run_object_change_auth(Subtest::WithPassword);
}

// Original Go test: object_change_auth_test.go - TestObjectChangeAuth/ObjectChangeAuth
#[test]
fn test_object_change_auth_object_change_auth() {
    run_object_change_auth(Subtest::ObjectChangeAuth);
}

// Original Go test: object_change_auth_test.go - TestObjectChangeAuth/WithOldPassword
#[test]
fn test_object_change_auth_with_old_password() {
    run_object_change_auth(Subtest::WithOldPassword);
}

// Original Go test: object_change_auth_test.go - TestObjectChangeAuth/WithNewPassword
#[test]
fn test_object_change_auth_with_new_password() {
    run_object_change_auth(Subtest::WithNewPassword);
}
