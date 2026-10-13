//! Verification, creation, hashcheck and auth tickets: which hierarchies produce accepted tickets
//! and forged ticket rejection.

use crate::_common::{
    create_ecc_signing_key, create_signing_key_name_bytes, execute_sign,
    execute_with_password_sessions, execute_with_password_sessions_status, flush_session,
    leak_bytes, null_secret_ticket, policy_cp_hash, policy_signed_digest, policy_signed_with_nonce,
    policy_ticket, run_command, sign_pss, start_policy, start_session_with_hash,
};
use sha2::{Digest, Sha256};
use testing::tpm::{SimulatorPlatformSignal, Tpm};
use tpm2::commands::{
    CertifyCreation, CreatePrimary, Hash, PolicyAuthorize, PolicyGetDigest, PolicySecret,
    PolicyTicket, StartAuthSession, Startup,
};
#[allow(deprecated)]
use tpm2::commands::{Sign, VerifySignature};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bName,
    Tpm2bNonce, Tpm2bSensitiveData, TpmEccCurve, TpmSe, TpmSt, TpmSu, TpmaObject, TpmiAlgHash,
    TpmsEccParms, TpmsSensitiveCreate, TpmtPublic, TpmtSigScheme, TpmtTkHashcheck, TpmtTkVerified,
    *,
};

/// PolicySigned/PolicySecret auth tickets: NULL tickets rejected, owner/NULL-hierarchy tickets accepted or rejected by PolicyTicket as specified.
#[test]
fn auth_ticket_policy_ticket() {
    let mut sim = Tpm::new();

    // Case 2A: NULL Ticket on non-negative expiration (expiration >= 0)
    let start_auth = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_rsp = execute_with_password_sessions(&mut sim, &start_auth, 0, &[]).unwrap();

    let policy_secret_zero_exp = PolicySecret {
        auth_handle: Handle::RH_OWNER,
        policy_session: start_rsp.session_handle,
        nonce_tpm: Tpm2bNonce::default(),
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: 0,
    };
    let sec_zero_rsp =
        execute_with_password_sessions(&mut sim, &policy_secret_zero_exp, 1, &[]).unwrap();

    assert_eq!(sec_zero_rsp.policy_ticket.hierarchy(), Handle::RH_NULL);
    assert_eq!(sec_zero_rsp.policy_ticket.tag(), TpmSt::AUTH_SECRET.id());
    assert!(
        sec_zero_rsp.policy_ticket.digest().get_buffer().is_empty(),
        "expiration=0 must produce a NULL ticket"
    );
    assert!(sec_zero_rsp.timeout.get_buffer().is_empty());

    // PolicyTicket must REJECT NULL ticket (parameter 5 is ticket)
    let bad_policy_ticket_cmd = PolicyTicket {
        policy_session: start_rsp.session_handle,
        timeout: sec_zero_rsp.timeout,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        auth_name: Tpm2bName::from_bytes(leak_bytes(&Handle::RH_OWNER.0.to_be_bytes())).unwrap(),
        ticket: sec_zero_rsp.policy_ticket,
    };
    let err = execute_with_password_sessions(&mut sim, &bad_policy_ticket_cmd, 0, &[])
        .expect_err("PolicyTicket must reject NULL ticket");
    // The NULL ticket comes with an empty timeout, and C checks the timeout size
    // first: TPM_RCS_SIZE + RC_PolicyTicket_timeout (SIZE+P1, PolicyTicket.c:48-49).
    assert_eq!(err, TpmRc::SIZE.with(Position::parameter(1)).get());
    flush_session(&mut sim, start_rsp.session_handle);

    // Case 2B: Non-NULL Ticket under regular hierarchy (TPM_RH_OWNER) with expiration < 0
    let session1 = execute_with_password_sessions(&mut sim, &start_auth, 0, &[]).unwrap();

    let policy_secret_neg = PolicySecret {
        auth_handle: Handle::RH_OWNER,
        policy_session: session1.session_handle,
        nonce_tpm: Tpm2bNonce::default(),
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: -1,
    };
    let sec_owner_rsp =
        execute_with_password_sessions(&mut sim, &policy_secret_neg, 1, &[]).unwrap();

    assert_eq!(sec_owner_rsp.policy_ticket.hierarchy(), Handle::RH_OWNER);
    assert_eq!(sec_owner_rsp.policy_ticket.tag(), TpmSt::AUTH_SECRET.id());
    assert!(!sec_owner_rsp.policy_ticket.digest().get_buffer().is_empty());
    assert!(!sec_owner_rsp.timeout.get_buffer().is_empty());

    let digest1 = execute_with_password_sessions(
        &mut sim,
        &PolicyGetDigest {
            policy_session: session1.session_handle,
        },
        0,
        &[],
    )
    .unwrap();

    // Use ticket in session 2
    let session2 = execute_with_password_sessions(&mut sim, &start_auth, 0, &[]).unwrap();

    let policy_ticket_cmd = PolicyTicket {
        policy_session: session2.session_handle,
        timeout: sec_owner_rsp.timeout,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        auth_name: Tpm2bName::from_bytes(leak_bytes(&Handle::RH_OWNER.0.to_be_bytes())).unwrap(),
        ticket: sec_owner_rsp.policy_ticket,
    };
    execute_with_password_sessions(&mut sim, &policy_ticket_cmd, 0, &[])
        .expect("PolicyTicket with valid owner ticket must succeed");

    let digest2 = execute_with_password_sessions(
        &mut sim,
        &PolicyGetDigest {
            policy_session: session2.session_handle,
        },
        0,
        &[],
    )
    .unwrap();
    assert_eq!(digest1.policy_digest, digest2.policy_digest);

    flush_session(&mut sim, session1.session_handle);
    flush_session(&mut sim, session2.session_handle);

    // Case 2C: Non-NULL Ticket under TPM_RH_NULL hierarchy with expiration < 0 (computed with nullProof)
    let session3 = execute_with_password_sessions(&mut sim, &start_auth, 0, &[]).unwrap();

    // Direct Handle::RH_NULL as auth_handle must be rejected during handle unmarshalling (TPMI_DH_ENTITY without +)
    let null_auth_err = execute_with_password_sessions(
        &mut sim,
        &PolicySecret {
            auth_handle: Handle::RH_NULL,
            policy_session: session3.session_handle,
            ..policy_secret_neg
        },
        1,
        &[],
    )
    .expect_err("PolicySecret with auth_handle = TPM_RH_NULL must fail with TPM_RC_VALUE + H1");
    assert_eq!(null_auth_err, TpmRc::VALUE.with(Position::handle(1)).get());

    let (null_obj_handle, null_obj_name) = create_ecc_signing_key(&mut sim, Handle::RH_NULL, false);

    let sec_null_rsp = execute_with_password_sessions(
        &mut sim,
        &PolicySecret {
            auth_handle: null_obj_handle,
            policy_session: session3.session_handle,
            ..policy_secret_neg
        },
        1,
        &[],
    )
    .unwrap();

    assert_eq!(sec_null_rsp.policy_ticket.hierarchy(), Handle::RH_NULL);
    assert_eq!(sec_null_rsp.policy_ticket.tag(), TpmSt::AUTH_SECRET.id());
    assert!(
        !sec_null_rsp.policy_ticket.digest().get_buffer().is_empty(),
        "RHNull ticket with expiration < 0 must have non-empty HMAC"
    );
    assert!(!sec_null_rsp.timeout.get_buffer().is_empty());

    let digest3 = execute_with_password_sessions(
        &mut sim,
        &PolicyGetDigest {
            policy_session: session3.session_handle,
        },
        0,
        &[],
    )
    .unwrap();

    // Use RHNull ticket in session 4
    let session4 = execute_with_password_sessions(&mut sim, &start_auth, 0, &[]).unwrap();

    let policy_null_ticket_cmd = PolicyTicket {
        policy_session: session4.session_handle,
        timeout: sec_null_rsp.timeout,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        auth_name: null_obj_name,
        ticket: sec_null_rsp.policy_ticket,
    };
    execute_with_password_sessions(&mut sim, &policy_null_ticket_cmd, 0, &[])
        .expect("PolicyTicket with valid RHNull ticket must succeed");

    let digest4 = execute_with_password_sessions(
        &mut sim,
        &PolicyGetDigest {
            policy_session: session4.session_handle,
        },
        0,
        &[],
    )
    .unwrap();
    assert_eq!(digest3.policy_digest, digest4.policy_digest);

    flush_session(&mut sim, null_obj_handle);
    flush_session(&mut sim, session3.session_handle);
    flush_session(&mut sim, session4.session_handle);
}

/// Creation tickets from owner and NULL hierarchies are accepted by CertifyCreation; forged/mismatched ones fail with TPM_RC_TICKET.
#[test]
fn creation_ticket_hierarchies() {
    let mut sim = Tpm::new();
    let (signer_handle, _) = create_ecc_signing_key(&mut sim, Handle::RH_OWNER, false);
    let in_scheme = Some(TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256));

    // Case 1A: Non-NULL Ticket in regular hierarchy (TPM_RH_OWNER)
    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: None,
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };
    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(ecc_parms, TpmsEccPoint::default()),
    };
    let in_public = tpm2::Tpm2b(public_area);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let owner_rsp = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();

    // Verify Owner creation ticket properties
    assert_eq!(owner_rsp.creation_ticket.hierarchy(), Handle::RH_OWNER);
    assert_eq!(owner_rsp.creation_ticket.tag(), TpmSt::CREATION.id());
    assert!(!owner_rsp.creation_ticket.digest().get_buffer().is_empty());

    // CertifyCreation should succeed with valid ticket
    let certify_cmd = CertifyCreation {
        sign_handle: signer_handle,
        object_handle: owner_rsp.object_handle,
        qualifying_data: Tpm2bData::default(),
        creation_hash: owner_rsp.creation_hash,
        in_scheme,
        creation_ticket: owner_rsp.creation_ticket,
    };
    assert!(execute_with_password_sessions_status(&mut sim, &certify_cmd, 1, &[]).is_ok());

    // Case 1B: Non-NULL Ticket in TPM_RH_NULL hierarchy (computed with nullProof)
    let null_rsp = execute_with_password_sessions(
        &mut sim,
        &CreatePrimary {
            primary_handle: Handle::RH_NULL,
            ..create_cmd
        },
        1,
        &[],
    )
    .unwrap();

    // Verify NULL hierarchy creation ticket properties
    assert_eq!(null_rsp.creation_ticket.hierarchy(), Handle::RH_NULL);
    assert_eq!(null_rsp.creation_ticket.tag(), TpmSt::CREATION.id());
    assert!(
        !null_rsp.creation_ticket.digest().get_buffer().is_empty(),
        "RHNull ticket with valid nameAlg must have non-empty HMAC"
    );

    // CertifyCreation on RHNull object should succeed with this ticket
    let certify_null_cmd = CertifyCreation {
        sign_handle: signer_handle,
        object_handle: null_rsp.object_handle,
        qualifying_data: Tpm2bData::default(),
        creation_hash: null_rsp.creation_hash,
        in_scheme,
        creation_ticket: null_rsp.creation_ticket,
    };
    assert!(execute_with_password_sessions_status(&mut sim, &certify_null_cmd, 1, &[]).is_ok());

    // Case 1C: NULL Ticket usage (empty digest) must be rejected by CertifyCreation
    let null_creation_ticket = TpmtTkCreation::Creation(Handle::RH_NULL, Tpm2bDigest::default());
    let certify_null_ticket_cmd = CertifyCreation {
        sign_handle: signer_handle,
        object_handle: owner_rsp.object_handle,
        qualifying_data: Tpm2bData::default(),
        creation_hash: owner_rsp.creation_hash,
        in_scheme,
        creation_ticket: null_creation_ticket,
    };
    let err = execute_with_password_sessions_status(&mut sim, &certify_null_ticket_cmd, 1, &[])
        .expect_err("CertifyCreation must reject NULL ticket");
    // TPM_RC_TICKET + RC_CertifyCreation_creationTicket (P4).
    assert_eq!(err, 0x4E0);

    // Case 1D: Corrupted creation ticket must fail
    let mut bad_digest = owner_rsp.creation_ticket.digest().get_buffer().to_vec();
    bad_digest[0] ^= 0xff;
    let bad_ticket = TpmtTkCreation::Creation(
        owner_rsp.creation_ticket.hierarchy(),
        Tpm2bDigest::from_bytes(&bad_digest).unwrap(),
    );
    let certify_bad_cmd = CertifyCreation {
        sign_handle: signer_handle,
        object_handle: owner_rsp.object_handle,
        qualifying_data: Tpm2bData::default(),
        creation_hash: owner_rsp.creation_hash,
        in_scheme,
        creation_ticket: bad_ticket,
    };
    let err = execute_with_password_sessions_status(&mut sim, &certify_bad_cmd, 1, &[])
        .expect_err("CertifyCreation must reject modified digest");
    // TPM_RC_TICKET + RC_CertifyCreation_creationTicket (P4).
    assert_eq!(err, 0x4E0);
}

/// Hashcheck tickets for Sign: NULL ticket ok for unrestricted keys, rejected for restricted keys and TPM_GENERATED data; real tickets accepted.
#[test]
#[allow(deprecated)]
fn hashcheck_ticket_sign() {
    let mut sim = Tpm::new();
    let (unrestricted_key, _) = create_ecc_signing_key(&mut sim, Handle::RH_OWNER, false);
    let (restricted_key, _) = create_ecc_signing_key(&mut sim, Handle::RH_OWNER, true);

    let safe_data = b"Arbitrary safe test buffer";

    // Case 3A: NULL Ticket on TPM_RH_NULL
    let hash_null_cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(safe_data).unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle::RH_NULL,
    };
    let hash_null_rsp = sim.execute(hash_null_cmd).unwrap();
    assert_eq!(hash_null_rsp.validation.hierarchy(), Handle::RH_NULL);
    assert_eq!(hash_null_rsp.validation.tag(), TpmSt::HASHCHECK.id());
    assert!(
        hash_null_rsp.validation.digest().get_buffer().is_empty(),
        "Hash with RHNull must return empty validation digest"
    );

    // NULL ticket works with UNRESTRICTED signing key
    let sign_unrestricted_cmd = Sign {
        key_handle: unrestricted_key,
        digest: hash_null_rsp.out_hash,
        in_scheme: None,
        validation: hash_null_rsp.validation,
    };
    let mut resp_buf = [0u8; 4096];
    assert!(
        execute_sign(
            &mut sim,
            &sign_unrestricted_cmd,
            1, // Sign keyHandle needs a session (USER role)
            &[],
            &mut resp_buf,
        )
        .is_ok(),
        "Unrestricted signing key must accept NULL ticket"
    );

    // NULL ticket FAILS with RESTRICTED signing key
    let sign_restricted_cmd = Sign {
        key_handle: restricted_key,
        digest: hash_null_rsp.out_hash,
        in_scheme: None,
        validation: hash_null_rsp.validation,
    };
    let err = execute_sign(
        &mut sim,
        &sign_restricted_cmd,
        1, // Sign keyHandle needs a session (USER role)
        &[],
        &mut resp_buf,
    )
    .expect_err("Restricted signing key must reject NULL ticket");
    assert_eq!(err, TpmRc::TICKET.with(Position::parameter(3)).get());

    // Case 3B: NULL Ticket on Unsafe Data (starts with TPM_GENERATED_VALUE = 0xff544347)
    let mut unsafe_data = vec![0xff, 0x54, 0x43, 0x47];
    unsafe_data.extend_from_slice(b"Some extra payload");
    let hash_unsafe_cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(&unsafe_data).unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle::RH_OWNER,
    };
    let hash_unsafe_rsp = sim.execute(hash_unsafe_cmd).unwrap();
    assert_eq!(hash_unsafe_rsp.validation.hierarchy(), Handle::RH_NULL);
    assert!(
        hash_unsafe_rsp.validation.digest().get_buffer().is_empty(),
        "Unsafe data must force NULL ticket even under RHOwner"
    );

    // Case 3C: Non-NULL Ticket under regular hierarchy (TPM_RH_OWNER)
    let hash_owner_cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(safe_data).unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle::RH_OWNER,
    };
    let hash_owner_rsp = sim.execute(hash_owner_cmd).unwrap();
    assert_eq!(hash_owner_rsp.validation.hierarchy(), Handle::RH_OWNER);
    assert_eq!(hash_owner_rsp.validation.tag(), TpmSt::HASHCHECK.id());
    assert!(!hash_owner_rsp.validation.digest().get_buffer().is_empty());

    // Non-NULL ticket works with RESTRICTED signing key
    let sign_restricted_valid = Sign {
        key_handle: restricted_key,
        digest: hash_owner_rsp.out_hash,
        in_scheme: None,
        validation: hash_owner_rsp.validation,
    };
    assert!(
        execute_sign(
            &mut sim,
            &sign_restricted_valid,
            1, // Sign keyHandle needs a session (USER role)
            &[],
            &mut resp_buf,
        )
        .is_ok(),
        "Restricted signing key must accept valid non-NULL ticket"
    );

    // Case 3D: Corrupted ticket fails on restricted signing key
    let mut bad_digest = hash_owner_rsp.validation.digest().get_buffer().to_vec();
    bad_digest[0] ^= 0x55;
    let corrupted_ticket = TpmtTkHashcheck::Hashcheck(
        hash_owner_rsp.validation.hierarchy(),
        Tpm2bDigest::from_bytes(&bad_digest).unwrap(),
    );
    let sign_restricted_corrupt = Sign {
        key_handle: restricted_key,
        digest: hash_owner_rsp.out_hash,
        in_scheme: None,
        validation: corrupted_ticket,
    };
    let err = execute_sign(
        &mut sim,
        &sign_restricted_corrupt,
        1, // Sign keyHandle needs a session (USER role)
        &[],
        &mut resp_buf,
    )
    .expect_err("Restricted signing key must reject corrupted ticket");
    assert_eq!(err, TpmRc::TICKET.with(Position::parameter(3)).get());
}

/// A PolicySigned auth ticket from before a TPM Reset fails TPM2_PolicyTicket with TPM_RC_TICKET.
#[test]
fn policy_ticket_rejects_ticket_from_before_reset() {
    let mut sim = Tpm::new();
    let (key, auth_name) = create_signing_key_name_bytes(&mut sim);

    // 1. Start a policy session
    let (session, nonce_tpm) = start_policy(&mut sim, TpmSe::Policy);

    // 2. Generate a ticket with PolicySigned (expiration = -10 so it outputs a ticket)
    let expiration: i32 = -10;
    let digest = policy_signed_digest(nonce_tpm.get_buffer(), expiration);
    let auth = sign_pss(&mut sim, key, &digest);
    let ps_rsp =
        policy_signed_with_nonce(&mut sim, key, session, nonce_tpm, expiration, auth).unwrap();

    // We get our auth ticket (TPMT_TK_AUTH) bound to the current time epoch
    let ticket = ps_rsp.policy_ticket;
    let timeout = ps_rsp.timeout;

    // 3. TPM Reset (power cycle + Startup(CLEAR)) -> epoch changes
    sim.signal_platform(SimulatorPlatformSignal::PowerOff)
        .unwrap();
    sim.signal_platform(SimulatorPlatformSignal::PowerOn)
        .unwrap();
    sim.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();
    sim.execute(Startup {
        startup_type: TpmSu::Clear,
    })
    .unwrap();

    // 4. Start a NEW policy session (because the old one died on reboot)
    let (session2, _) = start_policy(&mut sim, TpmSe::Policy);

    // 5. Try to use PolicyTicket with the expired ticket from the old epoch
    let pt_res = run_command(
        &mut sim,
        PolicyTicket {
            policy_session: session2,
            timeout,
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: Tpm2bNonce::default(),
            auth_name: Tpm2bName::from_bytes(leak_bytes(&auth_name)).unwrap(),
            ticket,
        },
    );

    // It should fail with TPM_RC_TICKET because the ticket's HMAC won't match the new epoch
    assert_eq!(
        pt_res.err(),
        Some(TpmRc::TICKET.with(Position::parameter(5)).get())
    );
}

/// PolicyTicket rejects trial sessions, non-8-byte timeouts, cpHash conflicts before validating the ticket (TICKET+P5).
#[test]
fn trial_timeout_and_cphash_checked_before_ticket() {
    let mut sim = Tpm::new();
    let owner_name = Handle::RH_OWNER.0.to_be_bytes();

    // 1. Trial sessions are rejected (TPM_RCS_ATTRIBUTES + RC_PolicyTicket_policySession).
    let s = start_session_with_hash(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_ticket(&mut sim, s, &[0; 8], &[], &owner_name, null_secret_ticket()),
        Err(TpmRc::ATTRIBUTES.with(Position::handle(1)).get())
    );

    // 2. The timeout must be exactly 8 bytes (TPM_RCS_SIZE + RC_PolicyTicket_timeout).
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_ticket(&mut sim, s, &[], &[], &owner_name, null_secret_ticket()),
        Err(TpmRc::SIZE.with(Position::parameter(1)).get())
    );
    assert_eq!(
        policy_ticket(&mut sim, s, &[0; 4], &[], &owner_name, null_secret_ticket()),
        Err(TpmRc::SIZE.with(Position::parameter(1)).get())
    );

    // 3. PolicyParameterChecks (cpHashA size) run before the ticket is validated.
    assert_eq!(
        policy_ticket(
            &mut sim,
            s,
            &[0; 8],
            &[0xAA; 5],
            &owner_name,
            null_secret_ticket()
        ),
        Err(TpmRc::SIZE.with(Position::parameter(2)).get())
    );
    // ... and a cpHashA conflicting with the session's cpHash is TPM_RC_CPHASH, not TICKET.
    policy_cp_hash(&mut sim, s, &[0x11; 32]).unwrap();
    assert_eq!(
        policy_ticket(
            &mut sim,
            s,
            &[0; 8],
            &[0x22; 32],
            &owner_name,
            null_secret_ticket()
        ),
        Err(TpmRc::CPHASH.get())
    );
    // A bad ticket with otherwise valid parameters is still TPM_RC_TICKET + RC_P5.
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_ticket(&mut sim, s, &[0; 8], &[], &owner_name, null_secret_ticket()),
        Err(TpmRc::TICKET.with(Position::parameter(5)).get())
    );
}

/// Verified tickets for PolicyAuthorize: NULL ticket accepted only in trial sessions; owner-hierarchy tickets validated.
#[test]
#[allow(deprecated)]
fn verified_ticket_policy_authorize() {
    let mut sim = Tpm::new();

    // Setup authority signing keys
    let (null_signer, null_signer_name) = create_ecc_signing_key(&mut sim, Handle::RH_NULL, false);
    let (owner_signer, owner_signer_name) =
        create_ecc_signing_key(&mut sim, Handle::RH_OWNER, false);

    let digest_to_sign = Tpm2bDigest::from_bytes(&[0x42; 32]).unwrap();

    // Case 4A: NULL Ticket produced when verifying key is in TPM_RH_NULL
    let sign_null_cmd = Sign {
        key_handle: null_signer,
        digest: digest_to_sign,
        in_scheme: None,
        validation: TpmtTkHashcheck::default(),
    };
    let mut resp_buf = [0u8; 4096];
    let sign_null_rsp = execute_sign(
        &mut sim,
        &sign_null_cmd,
        1, // Sign keyHandle needs a session (USER role)
        &[],
        &mut resp_buf,
    )
    .unwrap();

    let verify_null_cmd = VerifySignature {
        key_handle: null_signer,
        digest: digest_to_sign,
        signature: sign_null_rsp.signature,
    };
    let verify_null_rsp =
        execute_with_password_sessions(&mut sim, &verify_null_cmd, 0, &[]).unwrap();

    assert_eq!(verify_null_rsp.validation.hierarchy(), Handle::RH_NULL);
    assert_eq!(verify_null_rsp.validation.tag(), TpmSt::VERIFIED.id());
    assert!(
        verify_null_rsp.validation.digest().get_buffer().is_empty(),
        "Verifying key in RHNull must yield NULL ticket"
    );

    // NULL ticket in TRIAL session is ACCEPTED
    let start_trial = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let trial_session = execute_with_password_sessions(&mut sim, &start_trial, 0, &[]).unwrap();

    let policy_auth_null_ticket = PolicyAuthorize {
        policy_session: trial_session.session_handle,
        approved_policy: Tpm2bDigest::from_bytes(&[0u8; 32]).unwrap(),
        policy_ref: Tpm2bNonce::default(),
        key_sign: null_signer_name,
        check_ticket: verify_null_rsp.validation,
    };
    assert!(
        execute_with_password_sessions(&mut sim, &policy_auth_null_ticket, 0, &[]).is_ok(),
        "Trial policy session must accept NULL ticket"
    );
    flush_session(&mut sim, trial_session.session_handle);

    // NULL ticket in REGULAR policy session is REJECTED
    let start_policy = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let regular_session = execute_with_password_sessions(&mut sim, &start_policy, 0, &[]).unwrap();

    let err = execute_with_password_sessions(
        &mut sim,
        &PolicyAuthorize {
            policy_session: regular_session.session_handle,
            ..policy_auth_null_ticket
        },
        0,
        &[],
    )
    .expect_err("Regular policy session must reject NULL ticket");
    assert_eq!(err, TpmRc::VALUE.with(Position::parameter(4)).get());
    flush_session(&mut sim, regular_session.session_handle);

    // Case 4B: Non-NULL Ticket in regular hierarchy (TPM_RH_OWNER)
    // Compute aHash = SHA256(approvedPolicy || policyRef)
    let approved_policy = Tpm2bDigest::from_bytes(&[0u8; 32]).unwrap();
    let policy_ref = Tpm2bNonce::default();
    let mut hasher = Sha256::new();
    hasher.update(approved_policy.get_buffer());
    hasher.update(policy_ref.get_buffer());
    let a_hash = Tpm2bDigest::from_bytes(leak_bytes(&hasher.finalize())).unwrap();

    let sign_auth_cmd = Sign {
        key_handle: owner_signer,
        digest: a_hash,
        in_scheme: None,
        validation: TpmtTkHashcheck::default(),
    };
    let mut resp_buf_auth = [0u8; 4096];
    let sign_auth_rsp = execute_sign(
        &mut sim,
        &sign_auth_cmd,
        1, // Sign keyHandle needs a session (USER role)
        &[],
        &mut resp_buf_auth,
    )
    .unwrap();

    let verify_owner_cmd = VerifySignature {
        key_handle: owner_signer,
        digest: a_hash,
        signature: sign_auth_rsp.signature,
    };
    let verify_owner_rsp =
        execute_with_password_sessions(&mut sim, &verify_owner_cmd, 0, &[]).unwrap();

    assert_eq!(verify_owner_rsp.validation.hierarchy(), Handle::RH_OWNER);
    assert_eq!(verify_owner_rsp.validation.tag(), TpmSt::VERIFIED.id());
    assert!(!verify_owner_rsp.validation.digest().get_buffer().is_empty());

    // Non-NULL ticket in regular policy session is ACCEPTED
    let regular_session2 = execute_with_password_sessions(&mut sim, &start_policy, 0, &[]).unwrap();

    let policy_auth_valid = PolicyAuthorize {
        policy_session: regular_session2.session_handle,
        approved_policy,
        policy_ref,
        key_sign: owner_signer_name,
        check_ticket: verify_owner_rsp.validation,
    };
    assert!(
        execute_with_password_sessions(&mut sim, &policy_auth_valid, 0, &[]).is_ok(),
        "Regular policy session must accept valid non-NULL ticket"
    );
    flush_session(&mut sim, regular_session2.session_handle);

    // Case 4C: Corrupted verified ticket is REJECTED
    let regular_session3 = execute_with_password_sessions(&mut sim, &start_policy, 0, &[]).unwrap();

    let mut bad_digest = verify_owner_rsp.validation.digest().get_buffer().to_vec();
    bad_digest[0] ^= 0xaa;
    let bad_verified_ticket = TpmtTkVerified::Verified(
        verify_owner_rsp.validation.hierarchy(),
        Tpm2bDigest::from_bytes(&bad_digest).unwrap(),
    );

    let policy_auth_corrupt = PolicyAuthorize {
        policy_session: regular_session3.session_handle,
        approved_policy,
        policy_ref,
        key_sign: owner_signer_name,
        check_ticket: bad_verified_ticket,
    };
    let err = execute_with_password_sessions(&mut sim, &policy_auth_corrupt, 0, &[])
        .expect_err("Regular policy session must reject corrupted ticket");
    assert_eq!(err, TpmRc::VALUE.with(Position::parameter(4)).get());
    flush_session(&mut sim, regular_session3.session_handle);
}
