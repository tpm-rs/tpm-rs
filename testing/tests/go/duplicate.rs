#![forbid(unsafe_code)]
use crate::test_utils::*;
use testing::tpm::Tpm;
#[allow(deprecated)] // TPM2_CreateLoaded is deprecated upstream, but the TPM implements it.
use tpm2::commands::CreateLoaded;
use tpm2::commands::{CreatePrimary, Duplicate, Import, Load, PolicyCommandCode, PolicyGetDigest};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve, TpmSe};

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
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(&[0u8; 32]).unwrap(),
                y: Tpm2bEccParameter::from_bytes(&[0u8; 32]).unwrap(),
            },
        ),
    }
}

/// Creates a primary key from `ECCSRKTemplate` under `hierarchy` using an
/// empty password session, returning its handle.
fn create_ecc_srk(sim: &mut Tpm, hierarchy: Handle) -> Handle {
    let create_cmd = CreatePrimary {
        primary_handle: hierarchy,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(get_ecc_srk_template()),
        ..Default::default()
    };
    let resp =
        execute_with_password_sessions(sim, &create_cmd, 1, &[]).expect("could not generate SRK");
    resp.object_handle
}

/// Port of Go's `dupPolicyDigest`: computes the PolicyCommandCode(Duplicate)
/// digest with a trial policy session.
fn dup_policy_digest(sim: &mut Tpm) -> Tpm2bDigest<'static> {
    let trial_sess = start_auth_session(
        sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Trial,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let policy_cc_cmd = PolicyCommandCode {
        policy_session: trial_sess.session_handle,
        code: tpm2::TpmCc::Duplicate,
    };
    execute_with_password_sessions(sim, &policy_cc_cmd, 0, &[]).unwrap();

    let get_digest_cmd = PolicyGetDigest {
        policy_session: trial_sess.session_handle,
    };
    let get_digest_resp = execute_with_password_sessions(sim, &get_digest_cmd, 0, &[]).unwrap();

    flush_context(sim, trial_sess.session_handle).unwrap();
    // The deferred `cleanup()` in Go flushes the session a second time and
    // ignores the resulting error.
    let _ = flush_context(sim, trial_sess.session_handle);

    get_digest_resp.policy_digest
}

// Original Go test: duplicate_test.go - TestDuplicate
#[test]
#[allow(deprecated)] // TPM2_CreateLoaded is deprecated upstream, but the TPM implements it.
fn test_duplicate() {
    let mut sim = Tpm::new();

    // ### Create Owner SRK
    let srk_handle = create_ecc_srk(&mut sim, Handle::RH_OWNER);

    let policy_digest = dup_policy_digest(&mut sim);

    let key_pass = b"foo";

    // ### Create Object to be duplicated
    let obj_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: policy_digest,
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(&[0u8; 32]).unwrap(),
                y: Tpm2bEccParameter::from_bytes(&[0u8; 32]).unwrap(),
            },
        ),
    };
    let create_obj_cmd = CreateLoaded {
        parent_handle: srk_handle,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(key_pass).unwrap(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: crate::test_utils::make_template(&obj_pub),
    };
    let obj_resp = execute_with_password_sessions(&mut sim, &create_obj_cmd, 1, &[])
        .expect("TPM2_CreateLoaded");
    let obj_handle = obj_resp.object_handle;

    // We don't need the owner SRK handle anymore.
    let _ = flush_context(&mut sim, srk_handle);

    // ### Create Endorsement SRK (New Parent)
    let new_parent_handle = create_ecc_srk(&mut sim, Handle::RH_ENDORSEMENT);

    // ### Duplicate Object
    // Policy(TPMAlgSHA256, 16, PolicyCallback(PolicyCommandCode(Duplicate))):
    // a one-off policy session started when the command is executed.
    let policy_sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let policy_cc_cmd = PolicyCommandCode {
        policy_session: policy_sess.session_handle,
        code: tpm2::TpmCc::Duplicate,
    };
    execute_with_password_sessions(&mut sim, &policy_cc_cmd, 0, &[]).unwrap();

    let dup_cmd = Duplicate {
        object_handle: obj_handle,
        new_parent_handle,
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let dup_resp = execute_with_hmac_sessions(&mut sim, &dup_cmd, &[], &mut [policy_sess], &[&[]])
        .expect("TPM2_Duplicate");

    // We don't need the original object handle anymore.
    let _ = flush_context(&mut sim, obj_handle);

    // ### Import Object
    let import_cmd = Import {
        parent_handle: new_parent_handle,
        encryption_key: Tpm2bData::default(),
        object_public: obj_resp.out_public,
        duplicate: dup_resp.duplicate,
        in_sym_seed: dup_resp.out_sym_seed,
        symmetric_alg: None,
    };
    let import_resp =
        execute_with_password_sessions(&mut sim, &import_cmd, 1, &[]).expect("TPM2_Import");

    // ### Load Imported Object
    let load_cmd = Load {
        parent_handle: new_parent_handle,
        in_private: import_resp.out_private,
        in_public: obj_resp.out_public,
    };
    let load_resp = execute_with_password_sessions(&mut sim, &load_cmd, 1, &[]).expect("TPM2_Load");

    // Deferred cleanup (LIFO order, errors ignored like in Go).
    let _ = flush_context(&mut sim, load_resp.object_handle);
    let _ = flush_context(&mut sim, new_parent_handle);
}
