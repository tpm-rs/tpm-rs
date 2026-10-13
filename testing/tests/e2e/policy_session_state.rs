//! Policy session state after failed and successful commands (digest resets, continueSession).

use crate::_common::*;
use tpm2::commands::{
    Create, CreatePrimary, NVWrite, PolicyGetDigest, PolicyRestart, PolicySecret, StartAuthSession,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bNonce,
    Tpm2bSensitiveData, TpmSe, TpmaNv, TpmaObject, TpmiAlgHash, TpmsSensitiveCreate, TpmtPublic,
};
use tpm2_simulator::create_simulator;

/// EK policy session digest is not reset when the authorized command fails with a format-1 error
#[test]
fn digest_kept_after_failed_command() {
    let mut sim = create_simulator!();
    let ek_template = rsa_ek_template();

    let in_public = tpm2::Tpm2b(ek_template);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);
    let create_primary_cmd = CreatePrimary {
        primary_handle: Handle::RH_ENDORSEMENT,
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };
    let create_primary_resp =
        execute_with_password_sessions(&mut sim, &create_primary_cmd, 1, &[]).unwrap();

    let ek_handle = create_primary_resp.object_handle;
    let ek_name = create_primary_resp.name;

    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    session.attributes = tpm2::TpmaSession::from_bits_retain(1); // CONTINUE_SESSION

    let policy_secret_cmd = PolicySecret {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: session.session_handle,
        nonce_tpm: session.nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: 0,
    };
    let _ = execute_with_password_sessions(&mut sim, &policy_secret_cmd, 1, &[]).unwrap();

    // Policy digest after PolicySecret, before the failing command.
    let digest_before = execute_with_password_sessions(
        &mut sim,
        &PolicyGetDigest {
            policy_session: session.session_handle,
        },
        0,
        &[],
    )
    .unwrap();

    // Create an invalid command that will fail validation in the handler (Format 1 error: TPM_RC_ATTRIBUTES)
    let create_cmd = Create {
        parent_handle: ek_handle,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        }),
        in_public: tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::DECRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };

    let mut sessions = [session.clone()];
    let res = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        &[ek_name.get_buffer()],
        &mut sessions,
        &[&[]],
    );
    // Command must fail in the handler (after authorization): the template's object attributes
    // are inconsistent, TPM_RC_ATTRIBUTES + RC_P2 (inPublic).
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::parameter(2)).get())
    );

    let updated_session = &sessions[0];

    // Query policy digest again - it must have been reset to zero!
    let get_digest_cmd = PolicyGetDigest {
        policy_session: updated_session.session_handle,
    };
    let get_digest_rsp2 =
        execute_with_password_sessions(&mut sim, &get_digest_cmd, 0, &[]).unwrap();

    // C only resets policy data when the nonce rolls in a successful response
    // (SessionProcess.c UpdateInternalSession, called from BuildResponseSession);
    // a failed command leaves the policy session untouched.
    assert_eq!(
        get_digest_rsp2.policy_digest.get_buffer(),
        digest_before.policy_digest.get_buffer(),
        "Policy digest must be unchanged after a Format-1 command failure"
    );

    flush_context(&mut sim, ek_handle).unwrap();
    flush_context(&mut sim, updated_session.session_handle).unwrap();
}

/// EK policy session (PolicySecret endorsement) with continueSession has its digest reset after a successful authorization
#[test]
fn digest_reset_after_successful_use() {
    let mut sim = create_simulator!();
    let ek_template = rsa_ek_template();

    let in_public = tpm2::Tpm2b(ek_template);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);
    let create_primary_cmd = CreatePrimary {
        primary_handle: Handle::RH_ENDORSEMENT,
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };
    let create_primary_resp =
        execute_with_password_sessions(&mut sim, &create_primary_cmd, 1, &[]).unwrap();

    let ek_handle = create_primary_resp.object_handle;
    let ek_name = create_primary_resp.name;

    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    session.attributes = tpm2::TpmaSession::from_bits_retain(1);

    let policy_secret_cmd = PolicySecret {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: session.session_handle,
        nonce_tpm: session.nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: 0,
    };
    let _ = execute_with_password_sessions(&mut sim, &policy_secret_cmd, 1, &[]).unwrap();

    let get_digest_cmd = PolicyGetDigest {
        policy_session: session.session_handle,
    };
    let get_digest_rsp = execute_with_password_sessions(&mut sim, &get_digest_cmd, 0, &[]).unwrap();
    assert_eq!(
        get_digest_rsp.policy_digest.get_buffer(),
        ek_template.auth_policy.get_buffer()
    );

    let create_cmd = Create {
        parent_handle: ek_handle,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
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
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };

    let mut sessions = [session.clone()];
    let _ = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        &[ek_name.get_buffer()],
        &mut sessions,
        &[&[]],
    )
    .unwrap();

    let updated_session = &sessions[0];

    let get_digest_rsp2 = execute_with_password_sessions(
        &mut sim,
        &PolicyGetDigest {
            policy_session: updated_session.session_handle,
        },
        0,
        &[],
    )
    .unwrap();

    let zero_digest = vec![0u8; 32];
    assert_eq!(
        get_digest_rsp2.policy_digest.get_buffer(),
        zero_digest.as_slice()
    );

    flush_context(&mut sim, ek_handle).unwrap();
    flush_context(&mut sim, updated_session.session_handle).unwrap();
}

/// Failed commands leave policy sessions and audit exclusivity untouched; success resets continued policy sessions.
///
/// policy-session-zeroed-on-command-error-and-premature-exclusive-audit-clear
#[test]
fn failed_command_keeps_policy_and_audit_state() {
    let mut sim = new_sim();

    // 1. A failing command leaves the policy sessions it used untouched.
    let mut p = start_session(&mut sim, TpmSe::Policy, true);
    assert_eq!(
        policy_command_code_raw(&mut sim, p.handle, CC_GET_RANDOM),
        0
    );
    let digest = policy_get_digest_raw(&mut sim, p.handle);
    assert_ne!(digest, vec![0u8; 32]);
    // TPM2_LoadExternal with a malformed inPrivate fails inside the command handler.
    let mut params = vec![0x00, 0x02, 0xFF, 0xFF, 0x00, 0x00];
    params.extend_from_slice(&RH_NULL.to_be_bytes());
    let rc = exec(
        &mut sim,
        CC_LOAD_EXTERNAL,
        &[],
        &mut [SessUse::hmac(&mut p, ATTR_CONT | ATTR_ENCRYPT, &[])],
        &params,
        1,
    )
    .rc;
    assert_ne!(rc, 0);
    assert_eq!(policy_get_digest_raw(&mut sim, p.handle), digest);

    // 2. A failing TPM_ST_NO_SESSIONS command does not end audit exclusivity.
    let mut a = start_session(&mut sim, TpmSe::HMAC, false);
    let get_random = 8u16.to_be_bytes();
    let rc = exec(
        &mut sim,
        CC_GET_RANDOM,
        &[],
        &mut [SessUse::hmac(&mut a, ATTR_CONT | ATTR_AUDIT, &[])],
        &get_random,
        0,
    )
    .rc;
    assert_eq!(rc, 0);
    let rc = rc_of(&transact(
        &mut sim,
        &build(ST_NO_SESSIONS, CC_READ_PUBLIC, &[0x80FF_FFFF], None, &[]),
    ));
    assert_ne!(rc, 0);
    let rc = exec(
        &mut sim,
        CC_GET_RANDOM,
        &[],
        &mut [SessUse::hmac(
            &mut a,
            ATTR_CONT | ATTR_AUDIT | ATTR_AUDIT_EXCLUSIVE,
            &[],
        )],
        &get_random,
        0,
    )
    .rc;
    assert_eq!(rc, 0, "audit session should still be exclusive");

    // 3. A successful command resets every continued policy session in the session area, even
    //    one that only encrypts.
    let mut p = start_session(&mut sim, TpmSe::Policy, true);
    assert_eq!(
        policy_command_code_raw(&mut sim, p.handle, CC_GET_RANDOM),
        0
    );
    let rc = exec(
        &mut sim,
        CC_GET_RANDOM,
        &[],
        &mut [SessUse::hmac(&mut p, ATTR_CONT | ATTR_ENCRYPT, &[])],
        &get_random,
        0,
    )
    .rc;
    assert_eq!(rc, 0);
    assert_eq!(policy_get_digest_raw(&mut sim, p.handle), vec![0u8; 32]);
}

/// PolicyGetDigest on an HMAC session fails with TPM_RC_VALUE on the session handle.
///
/// `TPM2_PolicyGetDigest` on an HMAC session fails with `TPM_RC_VALUE` on the
/// session handle.
#[test]
fn policy_get_digest_on_hmac_session_rejected() {
    let mut sim = create_simulator!();

    let start_rsp = exec_command(
        &mut sim,
        &StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::from_bytes(&[1; 32]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::HMAC,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        },
        &[],
    )
    .unwrap();

    let res = exec_command(
        &mut sim,
        &PolicyGetDigest {
            policy_session: start_rsp.session_handle,
        },
        &[],
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::handle(1)).get())
    );
}

/// PolicyRestart clears the cpHash union and the PolicySecret timeout so the restarted session does not expire.
#[test]
fn policy_restart_clears_cphash_and_timeout() {
    let mut sim = create_simulator!();

    // 1. PolicyRestart clears the cpHash union (`u1.cpHash.b.size = 0`).
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256);
    policy_cp_hash(&mut sim, s.session_handle, &[0x11; 32]).unwrap();
    run_command(
        &mut sim,
        PolicyRestart {
            session_handle: s.session_handle,
        },
    )
    .unwrap();
    policy_secret(&mut sim, Handle::RH_OWNER, &s, &[0x22; 32], 0)
        .expect("cpHashA after PolicyRestart");
    run_command(
        &mut sim,
        PolicyRestart {
            session_handle: s.session_handle,
        },
    )
    .unwrap();
    policy_duplication_select(&mut sim, s.session_handle, &[], &[1, 2, 3, 4], false)
        .expect("PolicyDuplicationSelect after PolicyRestart");

    // 2. PolicyRestart clears the timeout: a 1 s PolicySecret expiration must not expire the
    //    restarted session.
    let index = 0x0150_0013;
    let mut s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256);
    define_nv_with_policy(
        &mut sim,
        index,
        TpmaNv::POLICYWRITE | TpmaNv::AUTHREAD,
        8,
        &[0; 32],
    );
    policy_secret(&mut sim, Handle::RH_OWNER, &s, &[], 1).unwrap();
    sleep(std::time::Duration::from_millis(1500));
    run_command(
        &mut sim,
        PolicyRestart {
            session_handle: s.session_handle,
        },
    )
    .unwrap();
    s.attributes.insert(tpm2::TpmaSession::CONTINUE_SESSION);
    execute_with_hmac_sessions(
        &mut sim,
        &NVWrite {
            auth_handle: Handle(index),
            nv_index: Handle(index),
            data: tpm2::Tpm2bMaxNvBuffer::from_bytes(&[1; 8]).unwrap(),
            offset: 0,
        },
        &[],
        &mut [s],
        &[&[]],
    )
    .expect("restarted policy session must not be expired");
}

/// A policy session stays loaded across PolicyCommandCode / PolicyGetDigest / PolicyRestart and PolicyRestart zeroes the digest.
#[test]
fn policy_restart_resets_digest() {
    let mut sim = create_simulator!();

    // Start active policy session
    let pol_handle = start_session_u32(&mut sim, TpmSe::Policy);
    assert!(is_loaded(&mut sim, pol_handle));

    // Step 1: PolicyCommandCode (0x016c) on pol_handle
    let rsp = policy_raw(&mut sim, 0x016c, pol_handle, &0x0000_0181u32.to_be_bytes());
    assert_eq!(rsp.len(), 10);
    assert_eq!(rc_of(&rsp), 0);
    assert!(is_loaded(&mut sim, pol_handle));

    // Step 2: PolicyGetDigest (0x0189) on pol_handle
    let rsp = policy_raw(&mut sim, 0x0189, pol_handle, &[]);
    assert!(rsp.len() >= 10);
    assert_eq!(rc_of(&rsp), 0);
    assert!(is_loaded(&mut sim, pol_handle));

    // Step 3: PolicyRestart (0x0180) on pol_handle
    let rsp = policy_raw(&mut sim, 0x0180, pol_handle, &[]);
    assert_eq!(rsp.len(), 10);
    assert_eq!(rc_of(&rsp), 0);
    assert!(is_loaded(&mut sim, pol_handle));

    // Verify session state was reset to initial state by PolicyRestart:
    // the policy digest is all zeros again ...
    let rsp = policy_raw(&mut sim, 0x0189, pol_handle, &[]);
    assert_eq!(rc_of(&rsp), 0);
    assert_eq!(&rsp[10..12], &32u16.to_be_bytes());
    assert_eq!(&rsp[12..44], &[0u8; 32]);
    // ... and the command code is cleared, so a different PolicyCommandCode is accepted.
    let rsp = policy_raw(&mut sim, 0x016c, pol_handle, &0x0000_0182u32.to_be_bytes());
    assert_eq!(rc_of(&rsp), 0);
}
