#![forbid(unsafe_code)]
use crate::test_utils::*;
use tpm2::commands::{
    CreateLoaded, CreateLoadedHandles, CreatePrimary, CreatePrimaryHandles, Duplicate,
    DuplicateHandles, Import, ImportHandles, Load, LoadHandles, PolicyCommandCode,
    PolicyCommandCodeHandles, PolicyGetDigest, PolicyGetDigestHandles,
};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve, TpmSe};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

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
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
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
fn create_ecc_srk(sim: &mut Simulator<'_>, hierarchy: Handle) -> Handle {
    let create_cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(get_ecc_srk_template()),
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: hierarchy,
    };
    let (_, resp_handles) =
        execute_with_password_sessions(sim, &create_cmd, create_handles, 1, &[])
            .expect("could not generate SRK");
    resp_handles.object_handle
}

/// Port of Go's `dupPolicyDigest`: computes the PolicyCommandCode(Duplicate)
/// digest with a trial policy session.
fn dup_policy_digest(sim: &mut Simulator<'_>) -> Tpm2bDigest<'static> {
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
        code: tpm2::TpmCc::Duplicate,
    };
    let policy_cc_handles = PolicyCommandCodeHandles {
        policy_session: trial_sess.session_handle,
    };
    execute_with_password_sessions(sim, &policy_cc_cmd, policy_cc_handles, 0, &[]).unwrap();

    let get_digest_cmd = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: trial_sess.session_handle,
    };
    let (get_digest_resp, _) =
        execute_with_password_sessions(sim, &get_digest_cmd, get_digest_handles, 0, &[]).unwrap();

    flush_context(sim, trial_sess.session_handle).unwrap();
    // The deferred `cleanup()` in Go flushes the session a second time and
    // ignores the resulting error.
    let _ = flush_context(sim, trial_sess.session_handle);

    get_digest_resp.policy_digest
}

// Original Go test: duplicate_test.go - TestDuplicate
#[test]
fn test_duplicate() {
    let mut sim = create_simulator!();

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
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(key_pass).unwrap(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: crate::test_utils::make_template(&obj_pub),
    };
    let create_obj_handles = CreateLoadedHandles {
        parent_handle: srk_handle,
    };
    let (obj_resp, obj_resp_handles) =
        execute_with_password_sessions(&mut sim, &create_obj_cmd, create_obj_handles, 1, &[])
            .expect("TPM2_CreateLoaded");
    let obj_handle = obj_resp_handles.object_handle;

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
        code: tpm2::TpmCc::Duplicate,
    };
    let policy_cc_handles = PolicyCommandCodeHandles {
        policy_session: policy_sess.session_handle,
    };
    execute_with_password_sessions(&mut sim, &policy_cc_cmd, policy_cc_handles, 0, &[]).unwrap();

    let dup_cmd = Duplicate {
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let dup_handles = DuplicateHandles {
        object_handle: obj_handle,
        new_parent_handle,
    };
    let (dup_resp, _) = execute_with_hmac_sessions(
        &mut sim,
        &dup_cmd,
        dup_handles,
        &[],
        &mut [policy_sess],
        &[&[]],
    )
    .expect("TPM2_Duplicate");

    // We don't need the original object handle anymore.
    let _ = flush_context(&mut sim, obj_handle);

    // ### Import Object
    let import_cmd = Import {
        encryption_key: Tpm2bData::default(),
        object_public: obj_resp.out_public,
        duplicate: dup_resp.duplicate,
        in_sym_seed: dup_resp.out_sym_seed,
        symmetric_alg: None,
    };
    let import_handles = ImportHandles {
        parent_handle: new_parent_handle,
    };
    let (import_resp, _) =
        execute_with_password_sessions(&mut sim, &import_cmd, import_handles, 1, &[])
            .expect("TPM2_Import");

    // ### Load Imported Object
    let load_cmd = Load {
        in_private: import_resp.out_private,
        in_public: obj_resp.out_public,
    };
    let load_handles = LoadHandles {
        parent_handle: new_parent_handle,
    };
    let (_load_resp, load_resp_handles) =
        execute_with_password_sessions(&mut sim, &load_cmd, load_handles, 1, &[])
            .expect("TPM2_Load");

    // Deferred cleanup (LIFO order, errors ignored like in Go).
    let _ = flush_context(&mut sim, load_resp_handles.object_handle);
    let _ = flush_context(&mut sim, new_parent_handle);
}
