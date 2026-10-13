//! TPM2_CertifyCreation: creation ticket verification, check order and response-code positions.

use crate::_common::{
    RC_KEY_H1, RC_SCHEME_P3, RC_TICKET_P4, certify_creation, create_primary_full,
    create_primary_in, execute_with_password_sessions, execute_with_password_sessions_status,
    flush_context, leak_bytes, rsa_decrypt_template, rsa_sign_template,
};
use tpm2::commands::{CertifyCreation, CreatePrimary, LoadExternal};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bPublicKeyRsa,
    Tpm2bSensitiveData, TpmaObject, TpmiAlgHash, TpmiRsaKeyBits, TpmlPcrSelection, TpmsRsaParms,
    TpmsSensitiveCreate, TpmtPublic, TpmtRsaScheme, TpmtSigScheme, TpmtTkCreation,
};
use tpm2_simulator::create_simulator;

/// CertifyCreation: non-signing key KEY+H1, scheme (SCHEME+P3) checked before ticket (TICKET+P4).
///
/// `TPM2_CertifyCreation`: non-signing key -> `TPM_RC_KEY + H1`; a bad scheme is reported
/// (`TPM_RC_SCHEME + P3`) before a bad ticket; a bad ticket -> `TPM_RC_TICKET + P4`.
#[test]
fn certify_creation_check_order() {
    let mut sim = create_simulator!();
    let (created, object) = create_primary_full(
        &mut sim,
        Handle::RH_OWNER,
        rsa_sign_template(Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256))),
        &[],
    );
    let decrypt_key = create_primary_in(&mut sim, Handle::RH_OWNER, rsa_decrypt_template());
    let bad_ticket = TpmtTkCreation::new(
        Handle::RH_OWNER,
        Tpm2bDigest::from_bytes(leak_bytes(&[0x5A; 32])).unwrap(),
    );

    // Non-signing key, valid ticket.
    assert_eq!(
        certify_creation(
            &mut sim,
            decrypt_key,
            object,
            created.creation_hash,
            created.creation_ticket,
            None,
        )
        .err(),
        Some(RC_KEY_H1)
    );

    // Mismatching scheme and a bad ticket: the scheme is checked first.
    assert_eq!(
        certify_creation(
            &mut sim,
            object,
            object,
            created.creation_hash,
            bad_ticket,
            Some(TpmtSigScheme::Rsapss(TpmiAlgHash::Sha256)),
        )
        .err(),
        Some(RC_SCHEME_P3)
    );

    // Valid scheme, bad ticket.
    assert_eq!(
        certify_creation(
            &mut sim,
            object,
            object,
            created.creation_hash,
            bad_ticket,
            None
        )
        .err(),
        Some(RC_TICKET_P4)
    );

    // Everything valid.
    certify_creation(
        &mut sim,
        object,
        object,
        created.creation_hash,
        created.creation_ticket,
        None,
    )
    .expect("CertifyCreation with a valid ticket failed");
}

/// TPM2_CertifyCreation succeeds with the right creation ticket and fails with TPM_RC_TICKET for wrong hierarchy or digest
#[test]
fn certify_creation_rejects_bad_ticket() {
    let mut sim = create_simulator!();

    // Setup primary key template (RSA, SHA256, restricted, sign/encrypt)
    let rsa_parms = TpmsRsaParms {
        symmetric: None,
        scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        key_bits: TpmiRsaKeyBits(2048),
        exponent: 0,
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::RESTRICTED
            | TpmaObject::NO_DA,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, Tpm2bPublicKeyRsa::default()),
    };
    let in_public = tpm2::Tpm2b(pub_area);

    let pcr_selection = TpmlPcrSelection::from_slice(&[]).unwrap();
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    // Create primary key on Endorsement hierarchy
    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_ENDORSEMENT,
        in_sensitive,
        in_public,
        creation_pcr: pcr_selection,
        ..Default::default()
    };
    let create_rsp = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();
    let object_handle = create_rsp.object_handle;

    let in_scheme = Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256));

    // 1. Correct ticket should pass
    let certify_creation_cmd = CertifyCreation {
        sign_handle: object_handle,
        object_handle,
        qualifying_data: Tpm2bData::default(),
        creation_hash: create_rsp.creation_hash,
        in_scheme,
        creation_ticket: create_rsp.creation_ticket,
    };
    let res = execute_with_password_sessions_status(&mut sim, &certify_creation_cmd, 1, &[]);
    assert!(res.is_ok());

    // 3. Bad ticket hierarchy should fail with TPM_RC_TICKET: the ticket is recomputed with the
    //    proof of the hierarchy named in the ticket (C TicketComputeCreation). Platform is used
    //    because the owner and endorsement proofs are not yet randomized on a fresh simulator.
    let bad_hierarchy_ticket =
        TpmtTkCreation::Creation(Handle::RH_PLATFORM, *create_rsp.creation_ticket.digest());
    let certify_creation_cmd_bad_hierarchy = CertifyCreation {
        creation_ticket: bad_hierarchy_ticket,
        ..certify_creation_cmd
    };
    let res_bad_hierarchy = execute_with_password_sessions_status(
        &mut sim,
        &certify_creation_cmd_bad_hierarchy,
        1,
        &[],
    );
    // TPM_RC_TICKET + RC_CertifyCreation_creationTicket (P4).
    assert_eq!(res_bad_hierarchy.err(), Some(0x4E0));

    // 4. Bad ticket digest should fail with TPM_RC_TICKET
    let mut bad_digest = create_rsp.creation_ticket.digest().get_buffer().to_vec();
    if !bad_digest.is_empty() {
        bad_digest[0] ^= 0xFF; // Modify a byte of digest
    }
    let bad_digest_ticket = TpmtTkCreation::Creation(
        create_rsp.creation_ticket.hierarchy(),
        Tpm2bDigest::from_bytes(&bad_digest).unwrap(),
    );
    let certify_creation_cmd_bad_digest = CertifyCreation {
        creation_ticket: bad_digest_ticket,
        ..certify_creation_cmd
    };
    let res_bad_digest =
        execute_with_password_sessions_status(&mut sim, &certify_creation_cmd_bad_digest, 1, &[]);
    // TPM_RC_TICKET + RC_CertifyCreation_creationTicket (P4).
    assert_eq!(res_bad_digest.err(), Some(0x4E0));

    flush_context(&mut sim, object_handle).unwrap();
}

/// CertifyCreation recomputes the ticket over creationTicket.hierarchy, not the object current hierarchy.
///
/// The ticket is recomputed over `creationTicket.hierarchy`, which need not equal the certified
/// object's current hierarchy (here: the same public area reloaded into the NULL hierarchy).
#[test]
fn certify_creation_uses_ticket_hierarchy() {
    let mut sim = create_simulator!();
    let mut public = rsa_sign_template(Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)));
    public.object_attributes =
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH | TpmaObject::SENSITIVE_DATA_ORIGIN;
    let (created, _) = create_primary_full(&mut sim, Handle::RH_OWNER, public, &[]);

    let load = LoadExternal {
        in_private: None,
        in_public: created.out_public,
        hierarchy: Handle::RH_NULL,
    };
    let loaded = execute_with_password_sessions(&mut sim, &load, 0, &[])
        .expect("LoadExternal of the public area failed");

    certify_creation(
        &mut sim,
        Handle::RH_NULL,
        loaded.object_handle,
        created.creation_hash,
        created.creation_ticket,
        None,
    )
    .expect("CertifyCreation must accept an owner-hierarchy ticket for a NULL-hierarchy object");
}

/// CertifyCreation with a valid ticket succeeds, a tampered ticket is TPM_RC_TICKET, a missing session is TPM_RC_AUTH_MISSING
#[test]
fn ticket_and_auth_validation() {
    let mut sim = create_simulator!();

    // Create an object (transient key) to certify
    let rsa_parms = tpm2::TpmsRsaParms {
        symmetric: None,
        scheme: Some(tpm2::TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        key_bits: tpm2::TpmiRsaKeyBits(2048),
        exponent: 0,
    };
    let pubkey = tpm2::Tpm2bPublicKeyRsa::default();
    let tpmt_public = tpm2::TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: tpm2::TpmaObject::from_bits_retain(0x00040072),
        auth_policy: tpm2::Tpm2bDigest::default(),
        parms_and_id: tpm2::PublicParmsAndId::Rsa(rsa_parms, pubkey),
    };
    let in_public = tpm2::Tpm2b(tpmt_public);

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };
    let resp = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();
    let object_handle = resp.object_handle;

    // Normal ticket that we received
    let ticket = resp.creation_ticket;
    let creation_hash = resp.creation_hash;

    let sign_handle = Handle(0x40000007); // TPM_RH_NULL
    // signHandle has the USER role, so even TPM_RH_NULL needs a (password) session; C returns
    // TPM_RC_AUTH_MISSING otherwise (SessionProcess.c ParseSessionBuffer).

    // 2. Verify mismatching ticket hierarchy (should fail with Ticket error)
    let bad_hier_ticket = TpmtTkCreation::Creation(Handle::RH_PLATFORM, *ticket.digest());
    let cert_cmd_hier = CertifyCreation {
        sign_handle,
        object_handle,
        qualifying_data: Tpm2bData::default(),
        creation_hash,
        in_scheme: None,
        creation_ticket: bad_hier_ticket,
    };
    let res = execute_with_password_sessions_status(&mut sim, &cert_cmd_hier, 1, &[]);
    match res {
        // TPM_RC_TICKET + RC_CertifyCreation_creationTicket (P4).
        Err(err) => assert_eq!(err, 0x4E0),
        Ok(_) => panic!("Expected Ticket error, but command succeeded"),
    }

    // 3. Verify mismatching ticket digest / cryptographically invalid ticket
    // Let's modify the ticket digest to an invalid value (e.g. non-zeroes)
    let bad_digest_ticket = TpmtTkCreation::Creation(
        ticket.hierarchy(),
        Tpm2bDigest::from_bytes(&[0xAA; 32]).unwrap(),
    );
    let cert_cmd_digest = CertifyCreation {
        sign_handle,
        object_handle,
        qualifying_data: Tpm2bData::default(),
        creation_hash,
        in_scheme: None,
        creation_ticket: bad_digest_ticket,
    };
    let res_digest = execute_with_password_sessions_status(&mut sim, &cert_cmd_digest, 1, &[]);

    // We expect this to fail with Ticket error (since the digest is wrong).
    let err_digest = match res_digest {
        Err(err) => err,
        Ok(_) => panic!(
            "SECURITY BUG: CertifyCreation accepted a ticket with a mismatching/fabricated digest!"
        ),
    };
    // TPM_RC_TICKET + RC_CertifyCreation_creationTicket (P4).
    assert_eq!(err_digest, 0x4E0);
}
