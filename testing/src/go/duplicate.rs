#![forbid(unsafe_code)]
use crate::test_utils::*;
use tpm2::commands::{
    CreateLoaded, CreateLoadedHandles, Duplicate, DuplicateHandles, Import, ImportHandles, Load,
    LoadHandles, PolicyCommandCode, PolicyCommandCodeHandles, PolicyGetDigest,
    PolicyGetDigestHandles,
};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve, TpmSe};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

fn get_ecc_srk_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
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
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    }
}

// Original Go test: duplicate_test.go - TestDuplicate
#[test]
fn test_duplicate_and_import() {
    let mut sim = create_simulator!();

    // 1. Create Owner SRK (ECC)
    let srk_pub = get_ecc_srk_template();
    let in_public = crate::test_utils::make_template(&srk_pub);
    let create_srk_cmd = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public,
    };
    let create_srk_handles = CreateLoadedHandles {
        parent_handle: Handle(0x40000001), // TPMRH_OWNER
    };
    let (_, srk_resp_handles) =
        execute_with_password_sessions(&mut sim, &create_srk_cmd, create_srk_handles, 1, &[])
            .unwrap();
    let srk_handle = srk_resp_handles.object_handle;

    // 2. Get duplication policy digest by running a trial policy session
    let trial_sess = start_auth_session(
        &mut sim,
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
    let _ = execute_with_password_sessions(&mut sim, &policy_cc_cmd, policy_cc_handles, 0, &[])
        .unwrap();

    let get_digest_cmd = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: trial_sess.session_handle,
    };
    let (get_digest_resp, _) =
        execute_with_password_sessions(&mut sim, &get_digest_cmd, get_digest_handles, 0, &[])
            .unwrap();
    let policy_digest = get_digest_resp.policy_digest;

    // Flush trial session
    flush_context(&mut sim, trial_sess.session_handle).unwrap();

    // 3. Create the object to be duplicated (ECC key authorized by the policy)
    let obj_auth = b"foo";
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
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let obj_in_public = crate::test_utils::make_template(&obj_pub);
    let create_obj_cmd = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(obj_auth).unwrap(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: obj_in_public,
    };
    let create_obj_handles = CreateLoadedHandles {
        parent_handle: srk_handle,
    };
    let (obj_resp, obj_resp_handles) =
        execute_with_password_sessions(&mut sim, &create_obj_cmd, create_obj_handles, 1, &[])
            .unwrap();
    let obj_handle = obj_resp_handles.object_handle;

    // Flush owner SRK handle
    flush_context(&mut sim, srk_handle).unwrap();

    // 4. Create new parent (Endorsement SRK) - ECC
    let ecc_srk_pub = get_ecc_srk_template();
    let ecc_in_public = crate::test_utils::make_template(&ecc_srk_pub);
    let create_ecc_srk_cmd = CreateLoaded {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: ecc_in_public,
    };
    let create_ecc_srk_handles = CreateLoadedHandles {
        parent_handle: Handle(0x4000000B), // TPMRH_ENDORSEMENT
    };
    let (_, ecc_srk_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_ecc_srk_cmd,
        create_ecc_srk_handles,
        1,
        &[],
    )
    .unwrap();
    let new_parent_handle = ecc_srk_resp_handles.object_handle;

    // 5. Start policy session for duplication authorization
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

    // Execute PolicyCommandCode(Duplicate)
    let policy_cc_handles = PolicyCommandCodeHandles {
        policy_session: policy_sess.session_handle,
    };
    let _ = execute_with_password_sessions(&mut sim, &policy_cc_cmd, policy_cc_handles, 0, &[])
        .unwrap();

    // 6. Duplicate the object to the new parent
    let dup_cmd = Duplicate {
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let dup_handles = DuplicateHandles {
        object_handle: obj_handle,
        new_parent_handle,
    };

    let mut sessions = [policy_sess];
    println!(
        "DEBUG: obj_handle={:#x}, new_parent_handle={:#x}",
        obj_handle.0, new_parent_handle.0
    );
    if let Some(obj) = sim.global_state.find_transient_object(obj_handle.0) {
        println!(
            "DEBUG: obj public attributes={:?}",
            obj.public.object_attributes
        );
        println!(
            "DEBUG: obj auth policy={:?}",
            obj.public.auth_policy.get_buffer()
        );
        println!("DEBUG: obj auth value={:?}", obj.auth.get_buffer());
    } else {
        println!("DEBUG: obj not found!");
    }
    println!("DEBUG: session handle={:#x}", sessions[0].session_handle.0);
    if let Some(sess) = sim.global_state.session(sessions[0].session_handle.0) {
        println!(
            "DEBUG: session policy_digest={:?}",
            &sess.policy_digest[..sess.policy_digest_len]
        );
        println!("DEBUG: session type={:?}", sess.session_type);
    } else {
        println!("DEBUG: session not found in context!");
    }

    let (dup_resp, _) =
        execute_with_hmac_sessions(&mut sim, &dup_cmd, dup_handles, &[], &mut sessions, &[&[]])
            .unwrap();

    // Flush duplicated object handle
    flush_context(&mut sim, obj_handle).unwrap();

    // 7. Import under new parent (Endorsement SRK)
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
        execute_with_password_sessions(&mut sim, &import_cmd, import_handles, 1, &[]).unwrap();

    // 8. Load the imported object
    let load_cmd = Load {
        in_private: import_resp.out_private,
        in_public: obj_resp.out_public,
    };
    let load_handles = LoadHandles {
        parent_handle: new_parent_handle,
    };
    let (_load_resp, load_resp_handles) =
        execute_with_password_sessions(&mut sim, &load_cmd, load_handles, 1, &[]).unwrap();

    // Cleanup
    flush_context(&mut sim, load_resp_handles.object_handle).unwrap();
    flush_context(&mut sim, new_parent_handle).unwrap();
}
