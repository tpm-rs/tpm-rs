//! Session audit digest accumulation, auditReset and attestation via GetSessionAuditDigest.

use crate::_common::{
    ATTR_AUDIT, ATTR_AUDIT_EXCLUSIVE, ATTR_AUDIT_RESET, ATTR_CONT, RC_ATTRIBUTES, RC_KEY_H2,
    RC_SCHEME_P2, RC_TYPE_H3, audited_get_cap, audited_get_capability, cp_hash, create_primary_in,
    create_primary_with_auth, create_signing_key_ecc, exec_pws, execute_get_session_audit_digest,
    execute_with_hmac_sessions_raw, execute_with_password_sessions,
    execute_with_password_sessions_status, extend_audit, extend_audit_digest_local, flush_context,
    get_cap_with, get_session_audit_digest, get_time, hmac_session, marshal_to_slice,
    marshal_to_vec, new_sim, rc_s1, rsa_decrypt_template, rsa_sign_template,
    rsassa_signer_template, session_audit_digest, sha256, start_auth_session, start_hmac_session,
    start_session,
};
use testing::tpm::Tpm;
use tpm2::commands::{Command, GetCapability, GetSessionAuditDigest};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bData, TpmCap, TpmCc, TpmPt, TpmSe, TpmaSession, TpmiAlgHash, TpmtRsaScheme,
    TpmtSigScheme, TpmtSignature, TpmuAttest,
};

/// The session audit digest accumulates across audited commands after an auditReset.
///
/// Case 3: Audit Digest Accumulation / Multi-Command Auditing
#[test]
fn accumulates_across_commands() {
    let mut sim = new_sim();
    let mut sess = start_session(&mut sim, TpmSe::HMAC, false);

    // Command 1: GetCapability, session with AUDIT_RESET and AUDIT (attributes 0x85)
    let r = audited_get_cap(
        &mut sim,
        &mut sess,
        ATTR_AUDIT | ATTR_AUDIT_RESET | ATTR_CONT,
    );
    assert_eq!(r.rc, 0, "First command failed");
    let digest_1 = get_session_audit_digest(&mut sim, Handle::RH_ENDORSEMENT, sess.handle)
        .expect("GetSessionAuditDigest failed");

    // Command 2: GetCapability, session with AUDIT but NO AUDIT_RESET (attributes 0x81)
    let r = audited_get_cap(&mut sim, &mut sess, ATTR_AUDIT | ATTR_CONT);
    assert_eq!(r.rc, 0, "Second command failed");
    let digest_2 = get_session_audit_digest(&mut sim, Handle::RH_ENDORSEMENT, sess.handle)
        .expect("GetSessionAuditDigest failed");

    // Verify it is not the same as digest_1 (since it should have accumulated)
    assert_ne!(digest_2, digest_1);
}

/// Case 2: GetSessionAuditDigest Response Field Verification: the attested
/// session digest equals `H(0^32 || cpHash || rpHash)` of the single audited
/// command after an audit reset, and the session holds exclusivity.
#[test]
fn attested_digest_matches_cp_rp_hash() {
    let mut sim = Tpm::new();

    let mut session = start_hmac_session(&mut sim);

    // Command 1: GetCapability, session with AUDIT_RESET and AUDIT (0x85) to initialize and
    // extend the audit digest
    let (resp_params, _) = audited_get_capability(&mut sim, &mut session, 0x85);

    // Expected audit digest: H(zero digest || cpHash || rpHash)
    let params = marshal_to_vec(&GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    });
    let cp = cp_hash(TpmCc::GetCapability, &[], &params);
    let rp = sha256(&[
        &0u32.to_be_bytes(),
        &TpmCc::GetCapability.code().to_be_bytes(),
        &resp_params,
    ]);
    let expected_digest = sha256(&[&[0u8; 32], &cp, &rp]);

    // Execute GetSessionAuditDigest on this session
    let get_audit_cmd = GetSessionAuditDigest {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: Handle::RH_NULL,
        session_handle: session.session_handle,
        qualifying_data: Tpm2bData::from_bytes(&[9, 9, 9]).unwrap(),
        in_scheme: None,
    };
    // signHandle (TPM_RH_NULL) also has the USER auth role, so C needs a second session
    // (SessionProcess.c:1641-1651, otherwise TPM_RC_AUTH_MISSING).
    let resp = execute_with_password_sessions(&mut sim, &get_audit_cmd, 2, &[]).unwrap();

    // Parse audit_info: Tpm2bAttest into TpmsAttest
    let attest = resp.audit_info.0;
    assert_eq!(attest.extra_data.get_buffer(), &[9, 9, 9]);

    match attest.attested {
        TpmuAttest::SessionAudit(info) => {
            // exclusive_session is YES because the session currently holds the exclusivity lock
            assert!(info.exclusive_session);
            assert_eq!(info.session_digest.get_buffer(), &expected_digest[..]);
        }
        _ => panic!("Expected attested to be SessionAudit"),
    }
}

/// auditReset restarts the session audit digest while plain audit extends it; invalid privacyAdminHandle is TPM_RC_VALUE + RC_H1.
#[test]
fn audit_reset_and_privacy_handle_errors() {
    let mut sim = Tpm::new();

    // 1. Verify AUDIT_RESET behavior
    let mut audit_session = hmac_session(&mut sim);

    // First audited command: initializes the (non-zero) audit digest.
    let r1 = get_cap_with(&mut sim, &mut audit_session, ATTR_CONT | ATTR_AUDIT);
    assert_eq!(r1.rc, 0, "Command failed");
    let digest_1 = extend_audit(&[0u8; 32], &r1.params);
    assert_eq!(
        session_audit_digest(&mut sim, audit_session.handle),
        digest_1
    );

    // Send GetCapability with continueSession | audit but NO auditReset (0x04)
    let r2 = get_cap_with(&mut sim, &mut audit_session, ATTR_CONT | ATTR_AUDIT);
    assert_eq!(r2.rc, 0, "Command failed");

    // Verify audit digest is NOT reset (the previous digest is extended)
    let digest_2 = extend_audit(&digest_1, &r2.params);
    assert_eq!(
        session_audit_digest(&mut sim, audit_session.handle),
        digest_2
    );

    // Send GetCapability with continueSession | audit | auditReset
    let r3 = get_cap_with(
        &mut sim,
        &mut audit_session,
        ATTR_CONT | ATTR_AUDIT | ATTR_AUDIT_RESET,
    );
    assert_eq!(r3.rc, 0, "Command failed");

    // Verify audit digest IS reset to all zeros and then extended
    let digest_3 = session_audit_digest(&mut sim, audit_session.handle);
    assert_eq!(digest_3, extend_audit(&[0u8; 32], &r3.params));
    assert_eq!(digest_3.len(), 32);

    // Verify other format 1 errors:
    // Handle 1 invalid: privacy_admin_handle = 0 (invalid admin handle)
    let get_audit_cmd = GetSessionAuditDigest {
        privacy_admin_handle: Handle(0), // Invalid admin handle
        sign_handle: Handle(0x40000007),
        session_handle: Handle(audit_session.handle),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let res = exec_pws(&mut sim, &get_audit_cmd, &[&[]]);
    assert_eq!(
        res.as_ref().err(),
        Some(&TpmRc::VALUE.with(Position::handle(1)).get())
    );
    assert_eq!(res.err(), Some(0x184));
}

/// auditExclusive or auditReset without audit fails attribute validation.
///
/// Case 4: Attribute validation error: AUDIT_EXCLUSIVE or AUDIT_RESET without AUDIT
#[test]
fn exclusive_or_reset_without_audit_rejected() {
    let mut sim = new_sim();
    let mut sess = start_session(&mut sim, TpmSe::HMAC, false);

    // Case 4A: session_attributes = 0x02 (AUDIT_EXCLUSIVE, but no AUDIT 0x80)
    let r = audited_get_cap(&mut sim, &mut sess, ATTR_AUDIT_EXCLUSIVE);
    assert_eq!(r.rc, rc_s1(RC_ATTRIBUTES)); // 0x982

    // Case 4B: session_attributes = 0x04 (AUDIT_RESET, but no AUDIT 0x80)
    let r = audited_get_cap(&mut sim, &mut sess, ATTR_AUDIT_RESET);
    assert_eq!(r.rc, rc_s1(RC_ATTRIBUTES)); // 0x982
}

/// GetSessionAuditDigest: missing session (REFERENCE_H2), missing key (REFERENCE_H1), non-audit session (TPM_RC_TYPE + RC_H3).
#[test]
fn handle_and_session_type_errors() {
    let mut sim = Tpm::new();

    // Signer object with fixed scheme RSASSA SHA256
    let signer_handle = create_primary_with_auth(&mut sim, rsassa_signer_template(), &[]);

    // An audit session (initialized by its first audited command)
    let mut audit_session = hmac_session(&mut sim);
    assert_eq!(
        get_cap_with(&mut sim, &mut audit_session, ATTR_CONT | ATTR_AUDIT).rc,
        0
    );

    let cmd = GetSessionAuditDigest {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        ..Default::default()
    };

    // 1. Session handle invalid -> should fail with TpmRc::REFERENCE_H2
    let missing_session = Handle(0x02000009);
    assert_ne!(missing_session.0, audit_session.handle);
    let cmd = GetSessionAuditDigest {
        privacy_admin_handle: Handle(0x4000000B), // TPM_RH_ENDORSEMENT
        sign_handle: signer_handle,
        session_handle: missing_session, // Non-existent session
        ..cmd
    };
    let res = exec_pws(&mut sim, &cmd, &[&[], &[]]);
    // An unloaded session in the handle area is TPM_RC_REFERENCE_H0 + index (here H2) per C
    // EntityGetLoadStatus (Entity.c), reported before any authorization processing.
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H2.get()));

    // 2. Sign handle invalid -> should fail with TpmRc::REFERENCE_H1
    let missing_key = Handle::TRANSIENT_LAST;
    assert_ne!(missing_key, signer_handle);
    let cmd = GetSessionAuditDigest {
        privacy_admin_handle: Handle(0x4000000B), // TPM_RH_ENDORSEMENT
        sign_handle: missing_key,                 // Non-existent key
        session_handle: Handle(audit_session.handle),
        ..cmd
    };
    let res = exec_pws(&mut sim, &cmd, &[&[], &[]]);
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H1.get()));

    // 3. Valid params -> Success
    let cmd = GetSessionAuditDigest {
        privacy_admin_handle: Handle(0x4000000B), // TPM_RH_ENDORSEMENT
        sign_handle: signer_handle,
        session_handle: Handle(audit_session.handle),
        ..cmd
    };
    let resp = exec_pws(&mut sim, &cmd, &[&[], &[]]).expect("GetSessionAuditDigest failed");
    assert!(matches!(resp.signature, Some(TpmtSignature::Rsassa(..))));

    // 4. Session exists but is not an audit session (no audit digest) -> type_for(Handle, Pos3) (0x38A)
    let non_audit_session = hmac_session(&mut sim);
    let cmd = GetSessionAuditDigest {
        privacy_admin_handle: Handle(0x4000000B), // TPM_RH_ENDORSEMENT
        sign_handle: signer_handle,
        session_handle: Handle(non_audit_session.handle),
        ..cmd
    };
    let res = exec_pws(&mut sim, &cmd, &[&[], &[]]);
    assert_eq!(res.err(), Some(TpmRc::TYPE.with(Position::handle(3)).get()));
}

/// GetSessionAuditDigest on a session never used for audit fails.
#[test]
fn never_audited_session_rejected() {
    let mut sim = new_sim();
    // A session that has never been used for auditing: NOT an audit session!
    let sess = start_session(&mut sim, TpmSe::HMAC, false);

    let res = get_session_audit_digest(&mut sim, Handle::RH_ENDORSEMENT, sess.handle);
    assert!(res.is_err());
}

/// GetSessionAuditDigest with privacyAdminHandle = platform fails; endorsement succeeds.
///
/// Case 5: GetSessionAuditDigest Command Errors
#[test]
fn platform_privacy_admin_rejected() {
    let mut sim = new_sim();
    let mut sess = start_session(&mut sim, TpmSe::HMAC, false);
    let r = audited_get_cap(&mut sim, &mut sess, ATTR_AUDIT | ATTR_CONT);
    assert_eq!(r.rc, 0);

    // 5A: privacy_admin_handle is RHPlatform instead of RHEndorsement
    let res = get_session_audit_digest(&mut sim, Handle::RH_PLATFORM, sess.handle);
    assert!(res.is_err());

    // Control: the same request with the endorsement hierarchy succeeds.
    assert!(get_session_audit_digest(&mut sim, Handle::RH_ENDORSEMENT, sess.handle).is_ok());
}

/// GetSessionAuditDigest checks the signing key before the session's audit attribute.
#[test]
fn session_audit_digest_key_checked_before_audit() {
    let mut sim = Tpm::new();
    let decrypt_key = create_primary_in(&mut sim, Handle::RH_ENDORSEMENT, rsa_decrypt_template());
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("StartAuthSession failed");

    let gsad = |sim: &mut Tpm, sign_handle: Handle| {
        let cmd = GetSessionAuditDigest {
            privacy_admin_handle: Handle::RH_ENDORSEMENT,
            sign_handle,
            session_handle: session.session_handle,
            qualifying_data: Tpm2bData::default(),
            in_scheme: None,
        };
        // Every handle with an authorization role needs a session, even TPM_RH_NULL (C
        // ParseSessionBuffer); TPM_RH_NULL has an empty authValue.
        let sessions = 2;
        execute_with_password_sessions_status(sim, &cmd, sessions, &[]).err()
    };

    // Not an audit session, but the key error comes first.
    assert_eq!(gsad(&mut sim, decrypt_key), Some(RC_KEY_H2));
    // With an acceptable signer the audit attribute is reported.
    assert_eq!(gsad(&mut sim, Handle::RH_NULL), Some(RC_TYPE_H3));

    // GetTime reports the same positions (H2 / P2).
    assert_eq!(
        get_time(&mut sim, Handle::RH_ENDORSEMENT, decrypt_key, None, 2).err(),
        Some(RC_KEY_H2)
    );
    let rsa_key = create_primary_in(
        &mut sim,
        Handle::RH_ENDORSEMENT,
        rsa_sign_template(Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256))),
    );
    assert_eq!(
        get_time(
            &mut sim,
            Handle::RH_ENDORSEMENT,
            rsa_key,
            Some(TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256)),
            2
        )
        .err(),
        Some(RC_SCHEME_P2)
    );
}

/// An audit session extends its digest per command and auditReset restarts it, matching a locally computed digest.
#[test]
fn session_audit_reset_attribute_restarts_digest() {
    let mut sim = Tpm::new();

    // Create the AK for audit signing
    let (ak_handle, _ak_name) = create_signing_key_ecc(&mut sim, &[]);

    // 1. Start audit session
    let mut sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // Set AUDIT attribute
    sess.attributes = TpmaSession::AUDIT | TpmaSession::CONTINUE_SESSION;

    // 2. Run a command with audit session (should initialize and extend audit digest)
    let get_cmd_1 = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    };
    let mut sessions = [sess.clone()];
    let (_get_rsp_1, _) =
        execute_with_hmac_sessions_raw(&mut sim, &get_cmd_1, &[], &mut sessions, &[&[]]).unwrap();
    sess = sessions[0].clone();

    // Verify audit digest is non-zero
    let get_audit_cmd = GetSessionAuditDigest {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: ak_handle,
        session_handle: sess.session_handle,
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let mut resp_buffer_1 = [0u8; 4096];
    let get_audit_rsp_1 =
        execute_get_session_audit_digest(&mut sim, &get_audit_cmd, 2, &[], &mut resp_buffer_1)
            .unwrap();
    let attest_1 = get_audit_rsp_1.audit_info.0;
    let aud_info_1 = match attest_1.attested {
        tpm2::TpmuAttest::SessionAudit(info) => info,
        _ => panic!("Expected SessionAudit"),
    };
    let digest_1 = aud_info_1.session_digest.get_buffer().to_vec();
    assert_ne!(digest_1, vec![0u8; 32]);

    // 3. Run a second command with audit session, but WITHOUT AUDIT_RESET attribute.
    // It should extend the digest further.
    let get_cmd_2 = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::LEVEL),
        property_count: 1,
    };
    let mut sessions = [sess.clone()];
    let (_get_rsp_2, _) =
        execute_with_hmac_sessions_raw(&mut sim, &get_cmd_2, &[], &mut sessions, &[&[]]).unwrap();
    sess = sessions[0].clone();

    let mut resp_buffer_2 = [0u8; 4096];
    let get_audit_rsp_2 =
        execute_get_session_audit_digest(&mut sim, &get_audit_cmd, 2, &[], &mut resp_buffer_2)
            .unwrap();
    let attest_2 = get_audit_rsp_2.audit_info.0;
    let aud_info_2 = match attest_2.attested {
        tpm2::TpmuAttest::SessionAudit(info) => info,
        _ => panic!("Expected SessionAudit"),
    };
    let digest_2 = aud_info_2.session_digest.get_buffer().to_vec();
    assert_ne!(digest_2, vec![0u8; 32]);
    assert_ne!(digest_2, digest_1);

    // 4. Run a third command WITH AUDIT_RESET attribute (0x04) set in attributes.
    // The TPM should reset the session's audit digest to zero, then extend it with only the third command.
    sess.attributes = TpmaSession::AUDIT | TpmaSession::AUDIT_RESET | TpmaSession::CONTINUE_SESSION;
    let mut sessions = [sess.clone()];
    let (get_rsp_3_bytes, _) =
        execute_with_hmac_sessions_raw(&mut sim, &get_cmd_2, &[], &mut sessions, &[&[]]).unwrap();
    sess = sessions[0].clone();

    let mut resp_buffer_3 = [0u8; 4096];
    let get_audit_rsp_3 =
        execute_get_session_audit_digest(&mut sim, &get_audit_cmd, 2, &[], &mut resp_buffer_3)
            .unwrap();
    let attest_3 = get_audit_rsp_3.audit_info.0;
    let aud_info_3 = match attest_3.attested {
        tpm2::TpmuAttest::SessionAudit(info) => info,
        _ => panic!("Expected SessionAudit"),
    };
    let digest_3 = aud_info_3.session_digest.get_buffer().to_vec();
    assert_ne!(digest_3, vec![0u8; 32]);

    // The digest should be different from digest_2 because of the reset.
    assert_ne!(digest_3, digest_2);

    // Let's manually compute what digest_3 should be.
    // Since it was reset, digest_3 should be equal to the extension of a zero digest with command 3.
    let mut expected_digest_3 = [0u8; 32];

    let mut cmd_buf = [0u8; 512];
    let cmd_len = marshal_to_slice(&get_cmd_2, &mut cmd_buf);

    extend_audit_digest_local(
        &mut expected_digest_3,
        GetCapability::CMD_CODE,
        &[],
        &cmd_buf[..cmd_len],
        &get_rsp_3_bytes,
    );

    assert_eq!(digest_3.as_slice(), expected_digest_3.as_slice());

    // 5. Run a fourth command WITHOUT AUDIT_RESET attribute (0x04) set in attributes.
    // The TPM should extend expected_digest_3.
    sess.attributes = TpmaSession::AUDIT | TpmaSession::CONTINUE_SESSION;
    let mut sessions = [sess.clone()];
    let (get_rsp_4_bytes, _) =
        execute_with_hmac_sessions_raw(&mut sim, &get_cmd_2, &[], &mut sessions, &[&[]]).unwrap();
    let _final_sess = sessions[0].clone();

    let mut resp_buffer_4 = [0u8; 4096];
    let get_audit_rsp_4 =
        execute_get_session_audit_digest(&mut sim, &get_audit_cmd, 2, &[], &mut resp_buffer_4)
            .unwrap();
    let attest_4 = get_audit_rsp_4.audit_info.0;
    let aud_info_4 = match attest_4.attested {
        tpm2::TpmuAttest::SessionAudit(info) => info,
        _ => panic!("Expected SessionAudit"),
    };
    let digest_4 = aud_info_4.session_digest.get_buffer().to_vec();
    assert_ne!(digest_4, vec![0u8; 32]);
    assert_ne!(digest_4, digest_3);

    // Compute expected digest 4:
    let mut expected_digest_4 = expected_digest_3;
    let mut cmd_buf_4 = [0u8; 512];
    let cmd_len_4 = marshal_to_slice(&get_cmd_2, &mut cmd_buf_4);

    extend_audit_digest_local(
        &mut expected_digest_4,
        GetCapability::CMD_CODE,
        &[],
        &cmd_buf_4[..cmd_len_4],
        &get_rsp_4_bytes,
    );

    assert_eq!(digest_4.as_slice(), expected_digest_4.as_slice());

    flush_context(&mut sim, ak_handle).unwrap();
}
