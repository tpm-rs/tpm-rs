//! TPM2_Sign: schemes, hash validation, tickets, ECDAA and HMAC signing keys.

use crate::_common::Connection;
use crate::_common::{
    CC_SIGN, ECC_D, ECC_X, ECC_Y, base_attributes, base_attrs, create_primary_handle,
    create_primary_returning_public, create_primary_with_auth_in, create_primary_with_data_handle,
    ecc_storage_template_derived, ecc_template, ecdaa_template, execute_sign,
    execute_with_password_sessions, execute_with_password_sessions_status, flush_context, hex,
    hmac_key_template_with_policy, hmac_template, leak_bytes, load_rsa_with_private,
    make_ecc_public_area, rc_at, rsa_public_with_symmetric, rsa_signing_template_with, sdo_user,
    send_key_command, send_raw_rc, sign, sign_params, start_auth_session, sym_template,
    with_unique,
};
use sha2::{Digest as _, Sha256};
use testing::tpm::Tpm;
use tpm2::commands::{
    CreatePrimary, LoadExternal, PolicyCommandCode, PolicyGetDigest, PolicyPassword,
};
#[allow(deprecated)]
use tpm2::commands::{Sign, VerifySignature};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2b, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmCc, TpmEccCurve, TpmSe, TpmaObject, TpmiAlgHash,
    TpmiRsaKeyBits, TpmlPcrSelection, TpmsEccParms, TpmsEccPoint, TpmsRsaParms,
    TpmsSensitiveCreate, TpmtKeyedHashScheme, TpmtPublic, TpmtRsaScheme, TpmtSensitive,
    TpmtSigScheme, TpmtSignature, TpmtTkHashcheck, TpmuSensitiveComposite,
};

/// Sign with ECDAA and an unused commit counter is TPM_RC_VALUE.
#[test]
fn ecdaa_without_commit_rejected() {
    let mut sim = Tpm::new();
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: base_attributes() | TpmaObject::SIGN_ENCRYPT | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint::default(),
        ),
    };
    let key_handle = create_primary_handle(&mut sim, public).0;

    // Send Sign with ECDAA, hashAlg = SHA1, count = 0
    let mut sign_req = Vec::new();
    sign_req.extend_from_slice(&hex("8002")); // tag: TPM_ST_SESSIONS
    sign_req.extend_from_slice(&[0, 0, 0, 0]); // placeholder for size
    sign_req.extend_from_slice(&hex("0000015d")); // TPM_CC_Sign
    sign_req.extend_from_slice(&key_handle.to_be_bytes());
    // auth
    sign_req.extend_from_slice(&hex("00000009 40000009 0000 01 0000"));
    // digest (20 bytes of 0x11)
    sign_req.extend_from_slice(&hex("0014"));
    sign_req.extend_from_slice(&[0x11u8; 20]);
    // inScheme: ECDAA with SHA1, count 0
    // ECDAA tag = 0x001a, SHA1 = 0x0004, count = 0x0000
    sign_req.extend_from_slice(&hex("001a 0004 0000"));
    // validation ticket: tag 8024, hierarchy RH_NULL, empty digest
    sign_req.extend_from_slice(&hex("8024 40000007 0000"));

    let rc = send_raw_rc(&mut sim, sign_req);
    assert_eq!(
        rc,
        // C TPM2_Sign returns CryptSign()'s bare TPM_RC_VALUE (TpmEcc_SignEcdaa/CryptGenerateR).
        TpmRc::VALUE.get(),
        "Expected TPM_RC_VALUE for ECDAA sign with invalid commit status, got {:08x}",
        rc
    );
}

/// Sign with an HMAC KEYEDHASH key (password session required) and VerifySignature of the result succeed.
#[test]
#[allow(deprecated)]
fn hmac_sign_and_verify() {
    let mut sim = Tpm::new();

    // An HMAC-SHA256 KeyedHash signing key with a fixed HMAC key.
    let key_handle = create_primary_with_data_handle(
        &mut sim,
        TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(
                Some(tpm2::TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
                Tpm2bDigest::default(),
            ),
        },
        &[0x42u8; 32],
    );

    // Call Sign. keyHandle has the USER role, so an (empty) password session is required (C
    // returns TPM_RC_AUTH_MISSING without one).
    let digest = Tpm2bDigest::from_bytes(&[2u8; 32]).unwrap();
    let sign_rsp = execute_with_password_sessions(
        &mut sim,
        &Sign {
            key_handle,
            digest,
            in_scheme: Some(tpm2::TpmtSigScheme::Hmac(TpmiAlgHash::Sha256)),
            validation: tpm2::TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
        },
        1,
        &[],
    )
    .expect("Sign command should succeed");

    // Now call VerifySignature with the produced signature.
    let res = execute_with_password_sessions(
        &mut sim,
        &VerifySignature {
            key_handle,
            digest,
            signature: sign_rsp.signature,
        },
        0,
        &[],
    );
    assert!(
        res.is_ok(),
        "VerifySignature on signed HMAC should return 0 (TPM_SUCCESS), got {:?}",
        res.err()
    );
}

/// Sign with a non-hash algorithm in the scheme is TPM_RC_HASH + RC_P2.
#[test]
fn invalid_scheme_hash_rejected() {
    let mut sim = Tpm::new();
    let key_handle =
        create_primary_handle(&mut sim, rsa_signing_template_with(TpmaObject::default())).0;

    // Call TPM2_Sign with an invalid hash algorithm in inScheme (e.g., SYMCIPHER 0x0025 inside RSASSA 0x0014)
    let mut sign_req = Vec::new();
    sign_req.extend_from_slice(&hex("8002")); // tag: TPM_ST_SESSIONS
    sign_req.extend_from_slice(&[0, 0, 0, 0]); // size placeholder
    sign_req.extend_from_slice(&hex("0000015d")); // TPM_CC_Sign
    sign_req.extend_from_slice(&key_handle.to_be_bytes());
    // auth
    sign_req.extend_from_slice(&hex("00000009 40000009 0000 01 0000"));
    // digest (32 bytes of 0x11)
    sign_req.extend_from_slice(&hex("0020"));
    sign_req.extend_from_slice(&[0x11u8; 32]);
    // inScheme: RSASSA (0x0014) with invalid hash alg (0x0025)
    sign_req.extend_from_slice(&hex("0014 0025"));
    // validation ticket: tag 8024, hierarchy RH_NULL, empty digest
    sign_req.extend_from_slice(&hex("8024 40000007 0000"));

    let rc = send_raw_rc(&mut sim, sign_req);
    let expected_rc = TpmRc::HASH.with(Position::parameter(2)).get();
    assert_eq!(
        rc, expected_rc,
        "Expected TPM_RC_HASH + TPM_RC_P + TPM_RC_2 ({:08x}) when signing with invalid scheme hash alg, got {:08x}",
        expected_rc, rc
    );
}

/// Sign with a public-only HMAC key must not produce an HMAC under an empty key.
#[test]
fn public_only_hmac_key_returns_auth_unavailable() {
    let mut sim = Tpm::new();
    let cmd = LoadExternal {
        in_private: None,
        in_public: Tpm2b(with_unique(hmac_template(
            TpmaObject::USER_WITH_AUTH | TpmaObject::SIGN_ENCRYPT,
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
        ))),
        hierarchy: Handle::RH_NULL,
    };
    let rsp = sim.execute(cmd).unwrap();
    let digest: &'static [u8] = leak_bytes(&[0x88; 32]);
    assert_eq!(
        sign(&mut sim, rsp.object_handle, b"", digest, None).unwrap_err(),
        TpmRc::AUTH_UNAVAILABLE.get()
    );
}

/// Sign with a restricted key and an empty hashcheck ticket fails with TPM_RC_TICKET.
#[test]
fn restricted_key_without_ticket_rejected() {
    let mut sim = Tpm::new();
    let key_handle =
        create_primary_handle(&mut sim, rsa_signing_template_with(TpmaObject::RESTRICTED)).0;

    // Now call TPM2_Sign with an empty/invalid ticket on this restricted key
    // Sign request structure:
    // keyHandle (4), auth area, digest (2 + 32), inScheme (2 + 2), validation (2 + 4 + 2 + 0)
    let mut sign_req = Vec::new();
    sign_req.extend_from_slice(&hex("8002")); // tag: TPM_ST_SESSIONS
    sign_req.extend_from_slice(&[0, 0, 0, 0]); // placeholder for size
    sign_req.extend_from_slice(&hex("0000015d")); // TPM_CC_Sign
    sign_req.extend_from_slice(&key_handle.to_be_bytes());
    // auth
    sign_req.extend_from_slice(&hex("00000009 40000009 0000 01 0000"));
    // digest (32 bytes of 0x11)
    sign_req.extend_from_slice(&hex("0020"));
    sign_req.extend_from_slice(&[0x11u8; 32]);
    // inScheme: RSASSA with SHA256
    sign_req.extend_from_slice(&hex("0014 000b"));
    // validation ticket: tag 8024, hierarchy RH_NULL, empty digest
    sign_req.extend_from_slice(&hex("8024 40000007 0000"));

    let rc = send_raw_rc(&mut sim, sign_req);
    let expected_rc = TpmRc::TICKET.with(Position::parameter(3)).get();
    assert_eq!(
        rc, expected_rc,
        "Expected TPM_RC_TICKET ({:08x}) when signing restricted without valid ticket, got {:08x}",
        expected_rc, rc
    );
}

/// ECDAA default scheme with a NULL `inScheme`, invalid hashes and scheme mismatches are
/// `TPM_RC_SCHEME + RC_P2`; non-signing (symmetric) keys are `TPM_RC_KEY + RC_H1`.
#[test]
fn scheme_and_signing_key_validation() {
    let mut sim = Tpm::new();
    let ecdaa_key = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        ecdaa_template(base_attrs() | TpmaObject::SIGN_ENCRYPT),
        b"",
    );
    let digest: &'static [u8] = leak_bytes(&[0x77; 32]);
    let scheme_p2 = rc_at(TpmRc::SCHEME, Position::parameter(2));

    // Split-signing default scheme requires an explicit inScheme.
    assert_eq!(
        sign(&mut sim, ecdaa_key, b"", digest, None).unwrap_err(),
        scheme_p2
    );
    // Mismatching scheme.
    assert_eq!(
        sign(
            &mut sim,
            ecdaa_key,
            b"",
            digest,
            Some(TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256))
        )
        .unwrap_err(),
        scheme_p2
    );

    // Scheme-less ECC key with an RSA scheme -> SCHEME + P2.
    let ecc_key = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        ecc_template(base_attrs() | TpmaObject::SIGN_ENCRYPT, None),
        b"",
    );
    assert_eq!(
        sign(
            &mut sim,
            ecc_key,
            b"",
            digest,
            Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256))
        )
        .unwrap_err(),
        scheme_p2
    );

    // Symmetric cipher key with `sign` set is not a signing object.
    let sym_key = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        sym_template(base_attrs() | TpmaObject::SIGN_ENCRYPT | TpmaObject::DECRYPT),
        b"",
    );
    assert_eq!(
        sign(
            &mut sim,
            sym_key,
            b"",
            digest,
            Some(TpmtSigScheme::Hmac(TpmiAlgHash::Sha256))
        )
        .unwrap_err(),
        rc_at(TpmRc::KEY, Position::handle(1))
    );

    // A decrypt-only key is not a signing object either.
    let storage = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        ecc_storage_template_derived(),
        b"",
    );
    assert_eq!(
        sign(&mut sim, storage, b"", digest, None).unwrap_err(),
        rc_at(TpmRc::KEY, Position::handle(1))
    );
}

/// Repeated raw Sign commands with a password session all succeed.
#[test]
fn sequential_signs_with_password_session() {
    let mut sim = Tpm::new();
    let key_handle = create_primary_handle(
        &mut sim,
        hmac_key_template_with_policy(Tpm2bDigest::default()),
    )
    .0;

    // Run sequential sign operations using password session (0x40000009) to authorize key_handle
    for _ in 0..3 {
        let mut sign_req = Vec::new();
        sign_req.extend_from_slice(&hex("8002")); // tag: TPM_ST_SESSIONS
        sign_req.extend_from_slice(&[0, 0, 0, 0]); // size placeholder
        sign_req.extend_from_slice(&hex("0000015d")); // TPM_CC_Sign
        sign_req.extend_from_slice(&key_handle.to_be_bytes());
        // auth area: handle 0x40000009, nonce empty (0000), attributes (01), hmac empty (0000) -> 9 bytes
        sign_req.extend_from_slice(&hex("00000009 40000009 0000 01 0000"));
        // digest (32 bytes of 0x22)
        sign_req.extend_from_slice(&hex("0020"));
        sign_req.extend_from_slice(&[0x22u8; 32]);
        // inScheme: HMAC with SHA256
        sign_req.extend_from_slice(&hex("0005 000b"));
        // validation ticket: tag 8024, hierarchy RH_NULL, empty digest
        sign_req.extend_from_slice(&hex("8024 40000007 0000"));

        let rc = send_raw_rc(&mut sim, sign_req);
        assert_eq!(
            rc, 0,
            "Expected sequential TPM2_Sign to succeed under auth session, got {:08x}",
            rc
        );
    }
}

/// The white-box original installed the policy digest into the key's authPolicy after the
/// first policy round; here the key is created with the same policy
/// (`PolicyPassword` + `PolicyCommandCode(TPM_CC_Sign)`), computed with a trial session.
#[test]
fn sequential_signs_with_policy_session() {
    let mut sim = Tpm::new();

    // Runs PolicyPassword + PolicyCommandCode(TPM_CC_Sign) on `session`.
    let run_policy = |sim: &mut Tpm, session: Handle, step: usize| {
        let pp_cmd = PolicyPassword {
            policy_session: session,
        };
        execute_with_password_sessions(sim, &pp_cmd, 0, &[])
            .unwrap_or_else(|rc| panic!("PolicyPassword step {step} failed: {rc:08x}"));
        let pc_cmd = PolicyCommandCode {
            policy_session: session,
            code: TpmCc::Sign,
        };
        execute_with_password_sessions(sim, &pc_cmd, 0, &[])
            .unwrap_or_else(|rc| panic!("PolicyCommandCode step {step} failed: {rc:08x}"));
    };

    // Compute the policy digest with a trial session.
    let trial = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Trial,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    run_policy(&mut sim, trial.session_handle, 0);
    let gd_cmd = PolicyGetDigest {
        policy_session: trial.session_handle,
    };
    let gd_rsp = execute_with_password_sessions(&mut sim, &gd_cmd, 0, &[]).unwrap();
    flush_context(&mut sim, trial.session_handle).unwrap();

    let key_handle = create_primary_handle(
        &mut sim,
        hmac_key_template_with_policy(gd_rsp.policy_digest),
    )
    .0;

    // Start a Policy session (StartAuthSession: unbound, unseeded, sessionType = Policy)
    let mut start_req = Vec::new();
    start_req.extend_from_slice(&hex("8001")); // tag: TPM_ST_NO_SESSIONS
    start_req.extend_from_slice(&[0, 0, 0, 0]); // size placeholder
    start_req.extend_from_slice(&hex("00000176")); // TPM_CC_StartAuthSession
    start_req.extend_from_slice(&hex("40000007 40000007")); // tpmKey = RH_NULL, bind = RH_NULL
    start_req.extend_from_slice(&hex("0020")); // nonceCaller (32 bytes of 0x01)
    start_req.extend_from_slice(&[0x01u8; 32]);
    start_req.extend_from_slice(&hex("0000")); // encryptedSalt
    start_req.extend_from_slice(&hex("01")); // sessionType = Policy
    start_req.extend_from_slice(&hex("0010 000b")); // symmetric = Null, authHash = SHA256
    let len = start_req.len() as u32;
    start_req[2..6].copy_from_slice(&len.to_be_bytes());
    let mut response = [0u8; 1024];
    let response = sim.transact(&start_req, &mut response).unwrap();
    let start_rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    assert_eq!(start_rc, 0, "StartAuthSession failed: {:08x}", start_rc);
    let session_handle = u32::from_be_bytes(response[10..14].try_into().unwrap());

    // Run sequential sign operations using this Policy session_handle across multiple steps
    for step in 0..3 {
        // Step A: PolicyPassword; Step B: PolicyCommandCode for TPM_CC_Sign (0x015d)
        run_policy(&mut sim, Handle(session_handle), step);

        let mut sign_req = Vec::new();
        sign_req.extend_from_slice(&hex("8002")); // tag: TPM_ST_SESSIONS
        sign_req.extend_from_slice(&[0, 0, 0, 0]); // size placeholder
        sign_req.extend_from_slice(&hex("0000015d")); // TPM_CC_Sign
        sign_req.extend_from_slice(&key_handle.to_be_bytes());
        // auth area size (4) + session_handle (4), nonce empty (0000), attributes continueSession (01), hmac empty (0000)
        sign_req.extend_from_slice(&9u32.to_be_bytes());
        sign_req.extend_from_slice(&session_handle.to_be_bytes());
        sign_req.extend_from_slice(&hex("0000 01 0000"));
        // digest (32 bytes of 0x22)
        sign_req.extend_from_slice(&hex("0020"));
        sign_req.extend_from_slice(&[0x22u8; 32]);
        // inScheme: HMAC with SHA256
        sign_req.extend_from_slice(&hex("0005 000b"));
        // validation ticket: tag 8024, hierarchy RH_NULL, empty digest
        sign_req.extend_from_slice(&hex("8024 40000007 0000"));

        let rc = send_raw_rc(&mut sim, sign_req);
        assert_eq!(
            rc, 0,
            "Expected sequential TPM2_Sign step {} to succeed under Policy session, got {:08x}",
            step, rc
        );
    }
}

/// TPM2_Sign rejects a mismatching scheme hash, signs successfully, and VerifySignature accepts it but rejects a modified digest or signature.
#[test]
#[allow(deprecated)]
fn sign_and_verify_signature_round_trip_and_tampering() {
    let mut sim = Tpm::new();

    let in_public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };

    let create_primary_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(in_public),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };

    let create_primary_resp = execute_with_password_sessions(
        &mut sim,
        &create_primary_cmd,
        1, // CreatePrimary needs authorization of the hierarchy (C: AUTH_MISSING otherwise)
        &[],
    )
    .expect("CreatePrimary failed");

    let object_handle = create_primary_resp.object_handle;

    let data_to_sign = b"migrationpains";
    let digest = Sha256::digest(data_to_sign);

    // 1. Test signing with mismatched/invalid scheme hash algorithm
    let sign_cmd_mismatched = Sign {
        key_handle: object_handle,
        digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha1)), // Mismatched hash algorithm
        validation: TpmtTkHashcheck::default(),
    };

    let res_mismatched =
        execute_with_password_sessions_status(&mut sim, &sign_cmd_mismatched, 1, &[]);
    assert!(
        res_mismatched.is_err(),
        "Expected sign with mismatched scheme to fail"
    );

    // 2. Test successful sign
    let sign_cmd = Sign {
        key_handle: object_handle,
        digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
        validation: TpmtTkHashcheck::default(),
    };
    let mut resp_buffer = [0u8; 4096];
    let sign_resp =
        execute_sign(&mut sim, &sign_cmd, 1, &[], &mut resp_buffer).expect("Sign failed");

    // 3. Test VerifySignature command (Success)
    let verify_cmd = VerifySignature {
        key_handle: object_handle,
        digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
        signature: sign_resp.signature,
    };
    let verify_resp = execute_with_password_sessions(&mut sim, &verify_cmd, 0, &[])
        .expect("VerifySignature failed");
    // Verify that the ticket is returned indicating success
    assert_eq!(verify_resp.validation.tag(), (tpm2::TpmSt::VERIFIED.id()));

    // 4. Test VerifySignature with modified digest
    let mut modified_digest = digest;
    modified_digest[0] ^= 1;
    let verify_cmd_mod_digest = VerifySignature {
        key_handle: object_handle,
        digest: Tpm2bDigest::from_bytes(&modified_digest).unwrap(),
        signature: sign_resp.signature,
    };
    let res_mod_digest = execute_with_password_sessions(&mut sim, &verify_cmd_mod_digest, 0, &[]);
    assert!(
        res_mod_digest.is_err(),
        "VerifySignature should fail when digest is modified"
    );

    // 5. Test VerifySignature with modified signature
    let mut modified_sig = sign_resp.signature;
    match &mut modified_sig {
        TpmtSignature::Rsassa(rsassa) => {
            let mut sig_bytes = rsassa.sig.get_buffer().to_vec();
            sig_bytes[0] ^= 1;
            rsassa.sig = Tpm2bPublicKeyRsa::from_bytes(leak_bytes(&sig_bytes)).unwrap();
        }
        _ => panic!("Expected RSASSA signature"),
    }
    let verify_cmd_mod_sig = VerifySignature {
        key_handle: object_handle,
        digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
        signature: modified_sig,
    };
    let res_mod_sig = execute_with_password_sessions(&mut sim, &verify_cmd_mod_sig, 0, &[]);
    assert!(
        res_mod_sig.is_err(),
        "VerifySignature should fail when signature is modified"
    );

    // Cleanup key
    flush_context(&mut sim, object_handle).unwrap();
}

/// TPM2_Sign with a TPM-created decrypt-only key fails with TPM_RC_KEY.
#[test]
#[allow(deprecated)]
fn sign_rejects_decrypt_only_key() {
    let mut sim = Tpm::new();

    // Create a key with DECRYPT attribute only (no SIGN_ENCRYPT)
    let in_public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT
            | TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };

    let create_primary_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(in_public),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };

    let create_primary_resp = execute_with_password_sessions(
        &mut sim,
        &create_primary_cmd,
        1, // CreatePrimary needs authorization of the hierarchy (C: AUTH_MISSING otherwise)
        &[],
    )
    .expect("CreatePrimary failed");

    let object_handle = create_primary_resp.object_handle;

    let data_to_sign = b"migrationpains";
    let digest = Sha256::digest(data_to_sign);

    let sign_cmd = Sign {
        key_handle: object_handle,
        digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
        validation: TpmtTkHashcheck::default(),
    };

    let res = execute_with_password_sessions_status(&mut sim, &sign_cmd, 1, &[]);
    assert!(
        res.is_err(),
        "Sign should fail when using a key without SIGN attribute"
    );
    let err = res.err().unwrap();
    // Sign.c: TPM_RCS_KEY + RC_Sign_keyHandle.
    assert_eq!(err, TpmRc::KEY.with(Position::handle(1)).get());

    // Cleanup key
    flush_context(&mut sim, object_handle).unwrap();
}

/// Raw TPM2_Sign with a decrypt-only RSA primary fails with TPM_RC_KEY.
#[test]
fn sign_rejects_decrypt_only_key_raw() {
    let mut sim = Tpm::new();
    let (key, _) = create_primary_returning_public(
        &mut sim,
        rsa_public_with_symmetric(TpmaObject::DECRYPT | sdo_user(), None),
        &[],
    );

    let error_code = send_key_command(&mut sim, CC_SIGN, key, true, &sign_params());
    assert_eq!(
        error_code,
        0x0000019C, // TPM_RC_KEY + RC_Sign_keyHandle (Sign.c)
        "Expected TPM_RC_KEY + H1 (0x19C), got error_code = 0x{:08X}",
        error_code
    );
}

/// Test Sign fails with TPM_RC_KEY if key lacks SIGN_ENCRYPT attribute.
#[test]
#[allow(deprecated)]
fn sign_rejects_key_without_sign() {
    let mut sim = Tpm::new();

    let object_handle = load_rsa_with_private(&mut sim, TpmaObject::DECRYPT, None);

    let sign_cmd = Sign {
        key_handle: object_handle,
        digest: Tpm2bDigest::from_bytes(&[0x01; 32]).unwrap(),
        in_scheme: None,
        validation: TpmtTkHashcheck::default(),
    };
    let res = execute_with_password_sessions_status(&mut sim, &sign_cmd, 1, &[]);
    // Sign.c: !IsSigningObject -> TPM_RCS_KEY + RC_Sign_keyHandle.
    assert_eq!(res.err(), Some(TpmRc::KEY.with(Position::handle(1)).get()));

    flush_context(&mut sim, object_handle).unwrap();
}

/// 11. Test Sign with an invalid handle.
///
/// Expected: TPM_RC_HANDLE.
#[test]
#[allow(deprecated)]
fn sign_rejects_unloaded_key_handle() {
    let mut sim = Tpm::new();
    let sign_cmd = Sign {
        key_handle: Handle(0x8000000E),
        digest: Tpm2bDigest::default(),
        in_scheme: None,
        validation: TpmtTkHashcheck::default(),
    };
    let res = execute_with_password_sessions_status(&mut sim, &sign_cmd, 1, &[]);
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H0.get()));
}

/// 12. Test Sign with unsupported scheme (non-Null).
///
/// Expected: TPM_RC_SCHEME.
#[test]
#[allow(deprecated)]
fn sign_rejects_unsupported_sm2_scheme() {
    let mut sim = Tpm::new();

    // Load ECC key
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&[0x02; 32]).unwrap(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_ecc_public_area(ECC_X, ECC_Y, TpmaObject::SIGN_ENCRYPT));
    let load_cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let load_rsp = sim.execute(load_cmd).unwrap();

    let sign_cmd = Sign {
        key_handle: load_rsp.object_handle,
        digest: Tpm2bDigest::from_bytes(&[0x01; 32]).unwrap(),
        in_scheme: Some(TpmtSigScheme::Sm2(TpmiAlgHash::Sha256)),
        validation: TpmtTkHashcheck::default(),
    };
    let res = execute_with_password_sessions_status(&mut sim, &sign_cmd, 1, &[]);
    // Sign.c: TPM_RCS_SCHEME + RC_Sign_inScheme (SM2 is not implemented).
    assert_eq!(
        res.err(),
        Some(TpmRc::SCHEME.with(Position::parameter(2)).get())
    );

    flush_context(&mut sim, load_rsp.object_handle).unwrap();
}

/// VerifySignature with an unloaded key handle is TPM_RC_REFERENCE_H0.
#[test]
fn verify_signature_unloaded_key_rejected() {
    let mut sim = Tpm::new();

    // Send VerifySignature with an unloaded transient handle 0x80000002
    let mut verify_req = Vec::new();
    verify_req.extend_from_slice(&hex("8001")); // tag: TPM_ST_NO_SESSIONS
    verify_req.extend_from_slice(&[0, 0, 0, 0]); // size placeholder
    verify_req.extend_from_slice(&hex("00000177")); // TPM_CC_VerifySignature
    verify_req.extend_from_slice(&0x80000002u32.to_be_bytes()); // unloaded handle
    // digest (32 bytes)
    verify_req.extend_from_slice(&hex("0020"));
    verify_req.extend_from_slice(&[0x11u8; 32]);
    // signature (RSASSA with SHA256)
    verify_req.extend_from_slice(&hex("0014 000b 0100"));
    verify_req.extend_from_slice(&[0xccu8; 256]);

    let rc = send_raw_rc(&mut sim, verify_req);
    assert_eq!(
        rc,
        TpmRc::REFERENCE_H0.get(),
        "Expected TPM_RC_REFERENCE_H0 ({:08x}) for unloaded transient handle in VerifySignature, got {:08x}",
        TpmRc::REFERENCE_H0.get(),
        rc
    );
}
