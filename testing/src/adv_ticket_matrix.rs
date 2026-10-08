#![forbid(unsafe_code)]

use crate::test_utils::*;
use sha2::{Digest, Sha256};
use tpm2::commands::{
    CertifyCreation, CertifyCreationHandles, CreatePrimary, CreatePrimaryHandles, FlushContext,
    Hash, PolicyAuthorize, PolicyAuthorizeHandles, PolicyGetDigest, PolicyGetDigestHandles,
    PolicySecret, PolicySecretHandles, PolicyTicket, PolicyTicketHandles, Sign, SignHandles,
    StartAuthSession, StartAuthSessionHandles, VerifySignature, VerifySignatureHandles,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve, TpmSe, TpmSt};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

fn flush_session(sim: &mut Simulator<'_>, handle: Handle) {
    let _ = execute_with_password_sessions(
        sim,
        &FlushContext {
            flush_handle: handle,
        },
        (),
        0,
        &[],
    );
}

fn create_ecc_signing_key(
    sim: &mut Simulator<'_>,
    hierarchy: Handle,
    restricted: bool,
) -> (Handle, Tpm2bName<'static>) {
    let mut object_attributes = TpmaObject::FIXED_TPM
        | TpmaObject::FIXED_PARENT
        | TpmaObject::SENSITIVE_DATA_ORIGIN
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::SIGN_ENCRYPT;
    if restricted {
        object_attributes |= TpmaObject::RESTRICTED;
    }

    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };

    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(ecc_parms, TpmsEccPoint::default()),
    };
    let in_public = tpm2::Tpm2b(public_area);

    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_primary = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: hierarchy,
    };

    let (rsp, rsp_handles) =
        execute_with_password_sessions(sim, &create_primary, create_handles, 0, &[])
            .expect("could not create ECC primary key");
    (rsp_handles.object_handle, rsp.name)
}

// -----------------------------------------------------------------------------
// 1. TPMT_TK_CREATION Tests
// -----------------------------------------------------------------------------

#[test]
fn test_ticket_creation_matrix() {
    let mut sim = create_simulator!();
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
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let (owner_rsp, owner_handles) = execute_with_password_sessions(
        &mut sim,
        &create_cmd,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        },
        0,
        &[],
    )
    .unwrap();

    // Verify Owner creation ticket properties
    assert_eq!(owner_rsp.creation_ticket.hierarchy(), Handle::RH_OWNER);
    assert_eq!(owner_rsp.creation_ticket.tag(), TpmSt::CREATION.id());
    assert!(!owner_rsp.creation_ticket.digest().get_buffer().is_empty());

    // CertifyCreation should succeed with valid ticket
    let certify_cmd = CertifyCreation {
        qualifying_data: Tpm2bData::default(),
        creation_hash: owner_rsp.creation_hash,
        in_scheme,
        creation_ticket: owner_rsp.creation_ticket,
    };
    let certify_handles = CertifyCreationHandles {
        sign_handle: signer_handle,
        object_handle: owner_handles.object_handle,
    };
    assert!(
        execute_with_password_sessions_status(&mut sim, &certify_cmd, certify_handles, 1, &[])
            .is_ok()
    );

    // Case 1B: Non-NULL Ticket in TPM_RH_NULL hierarchy (computed with nullProof)
    let (null_rsp, null_handles) = execute_with_password_sessions(
        &mut sim,
        &create_cmd,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_NULL,
        },
        0,
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
        qualifying_data: Tpm2bData::default(),
        creation_hash: null_rsp.creation_hash,
        in_scheme,
        creation_ticket: null_rsp.creation_ticket,
    };
    let certify_null_handles = CertifyCreationHandles {
        sign_handle: signer_handle,
        object_handle: null_handles.object_handle,
    };
    assert!(
        execute_with_password_sessions_status(
            &mut sim,
            &certify_null_cmd,
            certify_null_handles,
            1,
            &[]
        )
        .is_ok()
    );

    // Case 1C: NULL Ticket usage (empty digest) must be rejected by CertifyCreation
    let null_creation_ticket = TpmtTkCreation::Creation(Handle::RH_NULL, Tpm2bDigest::default());
    let certify_null_ticket_cmd = CertifyCreation {
        qualifying_data: Tpm2bData::default(),
        creation_hash: owner_rsp.creation_hash,
        in_scheme,
        creation_ticket: null_creation_ticket,
    };
    let certify_null_ticket_handles = CertifyCreationHandles {
        sign_handle: signer_handle,
        object_handle: owner_handles.object_handle,
    };
    let err = execute_with_password_sessions_status(
        &mut sim,
        &certify_null_ticket_cmd,
        certify_null_ticket_handles,
        1,
        &[],
    )
    .expect_err("CertifyCreation must reject NULL ticket");
    assert_eq!(err, TpmRc::TICKET.get());

    // Case 1D: Corrupted creation ticket must fail
    let mut bad_digest = owner_rsp.creation_ticket.digest().get_buffer().to_vec();
    bad_digest[0] ^= 0xff;
    let bad_ticket = TpmtTkCreation::Creation(
        owner_rsp.creation_ticket.hierarchy(),
        Tpm2bDigest::from_bytes(&bad_digest).unwrap(),
    );
    let certify_bad_cmd = CertifyCreation {
        qualifying_data: Tpm2bData::default(),
        creation_hash: owner_rsp.creation_hash,
        in_scheme,
        creation_ticket: bad_ticket,
    };
    let err =
        execute_with_password_sessions_status(&mut sim, &certify_bad_cmd, certify_handles, 1, &[])
            .expect_err("CertifyCreation must reject modified digest");
    assert_eq!(err, TpmRc::TICKET.get());
}

// -----------------------------------------------------------------------------
// 2. TPMT_TK_AUTH Tests
// -----------------------------------------------------------------------------

#[test]
fn test_ticket_auth_matrix() {
    let mut sim = create_simulator!();

    // Case 2A: NULL Ticket on non-negative expiration (expiration >= 0)
    let start_auth = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (_, start_rsp) = execute_with_password_sessions(
        &mut sim,
        &start_auth,
        StartAuthSessionHandles {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
        },
        0,
        &[],
    )
    .unwrap();

    let policy_secret_zero_exp = PolicySecret {
        nonce_tpm: Tpm2bNonce::default(),
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: 0,
    };
    let (sec_zero_rsp, _) = execute_with_password_sessions(
        &mut sim,
        &policy_secret_zero_exp,
        PolicySecretHandles {
            auth_handle: Handle::RH_OWNER,
            policy_session: start_rsp.session_handle,
        },
        1,
        &[],
    )
    .unwrap();

    assert_eq!(sec_zero_rsp.policy_ticket.hierarchy(), Handle::RH_NULL);
    assert_eq!(sec_zero_rsp.policy_ticket.tag(), TpmSt::AUTH_SECRET.id());
    assert!(
        sec_zero_rsp.policy_ticket.digest().get_buffer().is_empty(),
        "expiration=0 must produce a NULL ticket"
    );
    assert!(sec_zero_rsp.timeout.get_buffer().is_empty());

    // PolicyTicket must REJECT NULL ticket (parameter 5 is ticket)
    let bad_policy_ticket_cmd = PolicyTicket {
        timeout: sec_zero_rsp.timeout,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        auth_name: Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
            &Handle::RH_OWNER.0.to_be_bytes(),
        ))
        .unwrap(),
        ticket: sec_zero_rsp.policy_ticket,
    };
    let err = execute_with_password_sessions(
        &mut sim,
        &bad_policy_ticket_cmd,
        PolicyTicketHandles {
            policy_session: start_rsp.session_handle,
        },
        0,
        &[],
    )
    .expect_err("PolicyTicket must reject NULL ticket");
    assert_eq!(err, TpmRc::TICKET.with(Position::parameter(5)).get());
    flush_session(&mut sim, start_rsp.session_handle);

    // Case 2B: Non-NULL Ticket under regular hierarchy (TPM_RH_OWNER) with expiration < 0
    let (_, session1) = execute_with_password_sessions(
        &mut sim,
        &start_auth,
        StartAuthSessionHandles {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
        },
        0,
        &[],
    )
    .unwrap();

    let policy_secret_neg = PolicySecret {
        nonce_tpm: Tpm2bNonce::default(),
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: -1,
    };
    let (sec_owner_rsp, _) = execute_with_password_sessions(
        &mut sim,
        &policy_secret_neg,
        PolicySecretHandles {
            auth_handle: Handle::RH_OWNER,
            policy_session: session1.session_handle,
        },
        1,
        &[],
    )
    .unwrap();

    assert_eq!(sec_owner_rsp.policy_ticket.hierarchy(), Handle::RH_OWNER);
    assert_eq!(sec_owner_rsp.policy_ticket.tag(), TpmSt::AUTH_SECRET.id());
    assert!(!sec_owner_rsp.policy_ticket.digest().get_buffer().is_empty());
    assert!(!sec_owner_rsp.timeout.get_buffer().is_empty());

    let (digest1, _) = execute_with_password_sessions(
        &mut sim,
        &PolicyGetDigest {},
        PolicyGetDigestHandles {
            policy_session: session1.session_handle,
        },
        0,
        &[],
    )
    .unwrap();

    // Use ticket in session 2
    let (_, session2) = execute_with_password_sessions(
        &mut sim,
        &start_auth,
        StartAuthSessionHandles {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
        },
        0,
        &[],
    )
    .unwrap();

    let policy_ticket_cmd = PolicyTicket {
        timeout: sec_owner_rsp.timeout,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        auth_name: Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
            &Handle::RH_OWNER.0.to_be_bytes(),
        ))
        .unwrap(),
        ticket: sec_owner_rsp.policy_ticket,
    };
    execute_with_password_sessions(
        &mut sim,
        &policy_ticket_cmd,
        PolicyTicketHandles {
            policy_session: session2.session_handle,
        },
        0,
        &[],
    )
    .expect("PolicyTicket with valid owner ticket must succeed");

    let (digest2, _) = execute_with_password_sessions(
        &mut sim,
        &PolicyGetDigest {},
        PolicyGetDigestHandles {
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
    let (_, session3) = execute_with_password_sessions(
        &mut sim,
        &start_auth,
        StartAuthSessionHandles {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
        },
        0,
        &[],
    )
    .unwrap();

    // Direct Handle::RH_NULL as auth_handle must be rejected during handle unmarshalling (TPMI_DH_ENTITY without +)
    let null_auth_err = execute_with_password_sessions(
        &mut sim,
        &policy_secret_neg,
        PolicySecretHandles {
            auth_handle: Handle::RH_NULL,
            policy_session: session3.session_handle,
        },
        1,
        &[],
    )
    .expect_err("PolicySecret with auth_handle = TPM_RH_NULL must fail with TPM_RC_VALUE + H1");
    assert_eq!(null_auth_err, TpmRc::VALUE.with(Position::handle(1)).get());

    let (null_obj_handle, null_obj_name) = create_ecc_signing_key(&mut sim, Handle::RH_NULL, false);

    let (sec_null_rsp, _) = execute_with_password_sessions(
        &mut sim,
        &policy_secret_neg,
        PolicySecretHandles {
            auth_handle: null_obj_handle,
            policy_session: session3.session_handle,
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

    let (digest3, _) = execute_with_password_sessions(
        &mut sim,
        &PolicyGetDigest {},
        PolicyGetDigestHandles {
            policy_session: session3.session_handle,
        },
        0,
        &[],
    )
    .unwrap();

    // Use RHNull ticket in session 4
    let (_, session4) = execute_with_password_sessions(
        &mut sim,
        &start_auth,
        StartAuthSessionHandles {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
        },
        0,
        &[],
    )
    .unwrap();

    let policy_null_ticket_cmd = PolicyTicket {
        timeout: sec_null_rsp.timeout,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        auth_name: null_obj_name,
        ticket: sec_null_rsp.policy_ticket,
    };
    execute_with_password_sessions(
        &mut sim,
        &policy_null_ticket_cmd,
        PolicyTicketHandles {
            policy_session: session4.session_handle,
        },
        0,
        &[],
    )
    .expect("PolicyTicket with valid RHNull ticket must succeed");

    let (digest4, _) = execute_with_password_sessions(
        &mut sim,
        &PolicyGetDigest {},
        PolicyGetDigestHandles {
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

// -----------------------------------------------------------------------------
// 3. TPMT_TK_HASHCHECK Tests
// -----------------------------------------------------------------------------

#[test]
fn test_ticket_hashcheck_matrix() {
    let mut sim = create_simulator!();
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
        digest: hash_null_rsp.out_hash,
        in_scheme: None,
        validation: hash_null_rsp.validation,
    };
    let mut resp_buf = [0u8; 4096];
    assert!(
        execute_sign(
            &mut sim,
            &sign_unrestricted_cmd,
            SignHandles {
                key_handle: unrestricted_key
            },
            0,
            &[],
            &mut resp_buf,
        )
        .is_ok(),
        "Unrestricted signing key must accept NULL ticket"
    );

    // NULL ticket FAILS with RESTRICTED signing key
    let sign_restricted_cmd = Sign {
        digest: hash_null_rsp.out_hash,
        in_scheme: None,
        validation: hash_null_rsp.validation,
    };
    let err = execute_sign(
        &mut sim,
        &sign_restricted_cmd,
        SignHandles {
            key_handle: restricted_key,
        },
        0,
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
        digest: hash_owner_rsp.out_hash,
        in_scheme: None,
        validation: hash_owner_rsp.validation,
    };
    assert!(
        execute_sign(
            &mut sim,
            &sign_restricted_valid,
            SignHandles {
                key_handle: restricted_key
            },
            0,
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
        digest: hash_owner_rsp.out_hash,
        in_scheme: None,
        validation: corrupted_ticket,
    };
    let err = execute_sign(
        &mut sim,
        &sign_restricted_corrupt,
        SignHandles {
            key_handle: restricted_key,
        },
        0,
        &[],
        &mut resp_buf,
    )
    .expect_err("Restricted signing key must reject corrupted ticket");
    assert_eq!(err, TpmRc::TICKET.with(Position::parameter(3)).get());
}

// -----------------------------------------------------------------------------
// 4. TPMT_TK_VERIFIED Tests
// -----------------------------------------------------------------------------

#[test]
fn test_ticket_verified_matrix() {
    let mut sim = create_simulator!();

    // Setup authority signing keys
    let (null_signer, null_signer_name) = create_ecc_signing_key(&mut sim, Handle::RH_NULL, false);
    let (owner_signer, owner_signer_name) =
        create_ecc_signing_key(&mut sim, Handle::RH_OWNER, false);

    let digest_to_sign = Tpm2bDigest::from_bytes(&[0x42; 32]).unwrap();

    // Case 4A: NULL Ticket produced when verifying key is in TPM_RH_NULL
    let sign_null_cmd = Sign {
        digest: digest_to_sign,
        in_scheme: None,
        validation: TpmtTkHashcheck::default(),
    };
    let mut resp_buf = [0u8; 4096];
    let (sign_null_rsp, _) = execute_sign(
        &mut sim,
        &sign_null_cmd,
        SignHandles {
            key_handle: null_signer,
        },
        0,
        &[],
        &mut resp_buf,
    )
    .unwrap();

    let verify_null_cmd = VerifySignature {
        digest: digest_to_sign,
        signature: sign_null_rsp.signature,
    };
    let (verify_null_rsp, _) = execute_with_password_sessions(
        &mut sim,
        &verify_null_cmd,
        VerifySignatureHandles {
            key_handle: null_signer,
        },
        0,
        &[],
    )
    .unwrap();

    assert_eq!(verify_null_rsp.validation.hierarchy(), Handle::RH_NULL);
    assert_eq!(verify_null_rsp.validation.tag(), TpmSt::VERIFIED.id());
    assert!(
        verify_null_rsp.validation.digest().get_buffer().is_empty(),
        "Verifying key in RHNull must yield NULL ticket"
    );

    // NULL ticket in TRIAL session is ACCEPTED
    let start_trial = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (_, trial_session) = execute_with_password_sessions(
        &mut sim,
        &start_trial,
        StartAuthSessionHandles {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
        },
        0,
        &[],
    )
    .unwrap();

    let policy_auth_null_ticket = PolicyAuthorize {
        approved_policy: Tpm2bDigest::from_bytes(&[0u8; 32]).unwrap(),
        policy_ref: Tpm2bNonce::default(),
        key_sign: null_signer_name,
        check_ticket: verify_null_rsp.validation,
    };
    assert!(
        execute_with_password_sessions(
            &mut sim,
            &policy_auth_null_ticket,
            PolicyAuthorizeHandles {
                policy_session: trial_session.session_handle
            },
            0,
            &[]
        )
        .is_ok(),
        "Trial policy session must accept NULL ticket"
    );
    flush_session(&mut sim, trial_session.session_handle);

    // NULL ticket in REGULAR policy session is REJECTED
    let start_policy = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[0; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (_, regular_session) = execute_with_password_sessions(
        &mut sim,
        &start_policy,
        StartAuthSessionHandles {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
        },
        0,
        &[],
    )
    .unwrap();

    let err = execute_with_password_sessions(
        &mut sim,
        &policy_auth_null_ticket,
        PolicyAuthorizeHandles {
            policy_session: regular_session.session_handle,
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
    let a_hash =
        Tpm2bDigest::from_bytes(crate::test_utils::leak_bytes(&hasher.finalize())).unwrap();

    let sign_auth_cmd = Sign {
        digest: a_hash,
        in_scheme: None,
        validation: TpmtTkHashcheck::default(),
    };
    let mut resp_buf_auth = [0u8; 4096];
    let (sign_auth_rsp, _) = execute_sign(
        &mut sim,
        &sign_auth_cmd,
        SignHandles {
            key_handle: owner_signer,
        },
        0,
        &[],
        &mut resp_buf_auth,
    )
    .unwrap();

    let verify_owner_cmd = VerifySignature {
        digest: a_hash,
        signature: sign_auth_rsp.signature,
    };
    let (verify_owner_rsp, _) = execute_with_password_sessions(
        &mut sim,
        &verify_owner_cmd,
        VerifySignatureHandles {
            key_handle: owner_signer,
        },
        0,
        &[],
    )
    .unwrap();

    assert_eq!(verify_owner_rsp.validation.hierarchy(), Handle::RH_OWNER);
    assert_eq!(verify_owner_rsp.validation.tag(), TpmSt::VERIFIED.id());
    assert!(!verify_owner_rsp.validation.digest().get_buffer().is_empty());

    // Non-NULL ticket in regular policy session is ACCEPTED
    let (_, regular_session2) = execute_with_password_sessions(
        &mut sim,
        &start_policy,
        StartAuthSessionHandles {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
        },
        0,
        &[],
    )
    .unwrap();

    let policy_auth_valid = PolicyAuthorize {
        approved_policy,
        policy_ref,
        key_sign: owner_signer_name,
        check_ticket: verify_owner_rsp.validation,
    };
    assert!(
        execute_with_password_sessions(
            &mut sim,
            &policy_auth_valid,
            PolicyAuthorizeHandles {
                policy_session: regular_session2.session_handle
            },
            0,
            &[]
        )
        .is_ok(),
        "Regular policy session must accept valid non-NULL ticket"
    );
    flush_session(&mut sim, regular_session2.session_handle);

    // Case 4C: Corrupted verified ticket is REJECTED
    let (_, regular_session3) = execute_with_password_sessions(
        &mut sim,
        &start_policy,
        StartAuthSessionHandles {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
        },
        0,
        &[],
    )
    .unwrap();

    let mut bad_digest = verify_owner_rsp.validation.digest().get_buffer().to_vec();
    bad_digest[0] ^= 0xaa;
    let bad_verified_ticket = TpmtTkVerified::Verified(
        verify_owner_rsp.validation.hierarchy(),
        Tpm2bDigest::from_bytes(&bad_digest).unwrap(),
    );

    let policy_auth_corrupt = PolicyAuthorize {
        approved_policy,
        policy_ref,
        key_sign: owner_signer_name,
        check_ticket: bad_verified_ticket,
    };
    let err = execute_with_password_sessions(
        &mut sim,
        &policy_auth_corrupt,
        PolicyAuthorizeHandles {
            policy_session: regular_session3.session_handle,
        },
        0,
        &[],
    )
    .expect_err("Regular policy session must reject corrupted ticket");
    assert_eq!(err, TpmRc::VALUE.with(Position::parameter(4)).get());
    flush_session(&mut sim, regular_session3.session_handle);
}
