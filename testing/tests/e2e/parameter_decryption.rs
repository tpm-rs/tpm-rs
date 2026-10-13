//! Command parameter decryption with DECRYPT sessions (AES-CFB): key derivation, sizes and errors.

use crate::_common::{
    AES128_CFB, AES256_CFB, ATTR_CONT, ATTR_DECRYPT, CC_HIERARCHY_CHANGE_AUTH, KEYED_HASH_SEED,
    RC_BAD_AUTH, RC_INSUFFICIENT, RC_SIZE, RH_OWNER, SessUse,
    create_ecc_key_with_auth as create_ecc_key, create_primary_key, exec, execute_sign,
    execute_with_hmac_sessions, execute_with_hmac_sessions_custom, execute_with_password_sessions,
    flush_context, get_create_primary_cmd_and_handles, make_keyed_hash_public_area_local,
    marshal_to_slice, new_sim, rc_s1, start_auth_session, start_session,
};
#[allow(deprecated)]
use tpm2::commands::{CreatePrimary, LoadExternal, ReadPublic, VerifySignature};
use tpm2::{
    Handle, Marshal, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter,
    Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmEccCurve, TpmSe, TpmaObject, TpmaSession,
    TpmiAlgHash, TpmiStCommandTag, TpmsAuthCommand, TpmsEccParms, TpmsEccPoint,
    TpmsSensitiveCreate, TpmtEccScheme, TpmtPublic, TpmtSensitive, TpmuSensitiveComposite,
    Unmarshal,
};
use tpm2_simulator::create_simulator;

/// CreatePrimary with an AES-128-CFB decrypt session succeeds.
#[test]
fn aes128_cfb_create_primary() {
    let mut sim = create_simulator!();
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(AES128_CFB),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::DECRYPT);
    let create_cmd = get_create_primary_cmd_and_handles();
    let resp_handles =
        execute_with_hmac_sessions(&mut sim, &create_cmd, &[], &mut [session], &[&[]]).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// CreatePrimary with an AES-256-CFB decrypt session succeeds.
#[test]
fn aes256_cfb_create_primary() {
    let mut sim = create_simulator!();
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(AES256_CFB),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::DECRYPT);
    let create_cmd = get_create_primary_cmd_and_handles();
    let resp_handles =
        execute_with_hmac_sessions(&mut sim, &create_cmd, &[], &mut [session], &[&[]]).unwrap();
    flush_context(&mut sim, resp_handles.object_handle).unwrap();
}

/// ReadPublic (no TPM2B parameter) with DECRYPT on the second session fails with ATTRIBUTES+S2.
#[test]
fn decrypt_on_read_public_rejected() {
    let mut sim = create_simulator!();
    let object_handle = create_primary_key(&mut sim);
    let session1 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let mut session2 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // Set decrypt on the second session (index 1), which is invalid
    session2.attributes.insert(TpmaSession::DECRYPT);

    let read_cmd = ReadPublic { object_handle };
    let err = match execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        &[],
        &mut [session1, session2],
        &[&[], &[]],
    ) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    // Expected error code: attributes_for(Session, Pos2) -> 2690
    assert_eq!(err, 2690);
}

/// An encrypted parameter size larger than the remaining buffer fails with SIZE+S1.
#[test]
fn decrypt_size_exceeds_buffer() {
    let mut sim = create_simulator!();
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(AES128_CFB),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::DECRYPT);

    // Build the request:
    let mut cmd_buf = [0u8; 4096];
    use crate::test_utils::CmdHeader;
    let mut header = CmdHeader {
        tag: TpmiStCommandTag::Sessions,
        size: 0,
        code: tpm2::TpmCc::CreatePrimary,
    };
    let mut written = header.marshal((&mut cmd_buf[0..10]).try_into().unwrap());
    written += marshal_to_slice(&(Handle::RH_OWNER.0), &mut cmd_buf[written..]);

    let session_size_pos = written;
    written += 4; // Reserve space for sessionSize

    let mock_auth = TpmsAuthCommand {
        session_handle: Handle(session.session_handle.0),
        nonce: session.nonce_caller,
        session_attributes: session.attributes,
        hmac: Tpm2bAuth::default(),
    };
    let mut auth_bytes = [0u8; 256];
    let auth_len = marshal_to_slice(&mock_auth, &mut auth_bytes);

    marshal_to_slice(
        &(auth_len as u32),
        &mut cmd_buf[session_size_pos..session_size_pos + 4],
    );
    cmd_buf[written..written + auth_len].copy_from_slice(&auth_bytes[..auth_len]);
    written += auth_len;

    // Parameters area: we specify a size of 0x0005 (5 bytes), but only provide 3 bytes of parameters (making total size 2 + 3 = 5 bytes, which is < 2 + 5 = 7)
    cmd_buf[written..written + 2].copy_from_slice(&5u16.to_be_bytes());
    cmd_buf[written + 2] = 0xAA;
    cmd_buf[written + 3] = 0xBB;
    cmd_buf[written + 4] = 0xCC;
    written += 5;

    // Fill total size in header
    header.size = written as u32;
    let mut header_buf = [0u8; 10];
    header.marshal(&mut header_buf);
    cmd_buf[..10].copy_from_slice(&header_buf[..10]);

    let mut resp_buf = [0u8; 4096];
    sim.transact(&cmd_buf[..written], &mut resp_buf).unwrap();

    let mut unmarsh = &resp_buf[..];
    use crate::test_utils::RespHeader;
    let resp_header = RespHeader::unmarshal(&mut unmarsh).unwrap();

    // C CryptParameterDecryption (CryptUtil.c:966-970): ciphertext larger than
    // the remaining buffer is TPM_RC_SIZE, plus the decrypt session index
    // (SessionProcess.c:1760-1762): SIZE+S1 (0x995).
    assert_eq!(resp_header.rc, 0x995);
}

/// A 1-byte encrypted parameter area fails with INSUFFICIENT+S1.
#[test]
fn decrypt_size_field_truncated() {
    let mut sim = create_simulator!();
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(AES128_CFB),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::DECRYPT);

    // Build the request:
    let mut cmd_buf = [0u8; 4096];
    use crate::test_utils::CmdHeader;
    let mut header = CmdHeader {
        tag: TpmiStCommandTag::Sessions,
        size: 0,
        code: tpm2::TpmCc::CreatePrimary,
    };
    let mut written = header.marshal((&mut cmd_buf[0..10]).try_into().unwrap());
    written += marshal_to_slice(&(Handle::RH_OWNER.0), &mut cmd_buf[written..]);

    let session_size_pos = written;
    written += 4; // Reserve space for sessionSize

    let mock_auth = TpmsAuthCommand {
        session_handle: Handle(session.session_handle.0),
        nonce: session.nonce_caller,
        session_attributes: session.attributes,
        hmac: Tpm2bAuth::default(),
    };
    let mut auth_bytes = [0u8; 256];
    let auth_len = marshal_to_slice(&mock_auth, &mut auth_bytes);

    marshal_to_slice(
        &(auth_len as u32),
        &mut cmd_buf[session_size_pos..session_size_pos + 4],
    );
    cmd_buf[written..written + auth_len].copy_from_slice(&auth_bytes[..auth_len]);
    written += auth_len;

    // Parameters area: we will write exactly 1 byte to parameters (making it smaller than 2 bytes size header)
    cmd_buf[written] = 0x01;
    written += 1;

    // Fill total size in header
    header.size = written as u32;
    let mut header_buf = [0u8; 10];
    header.marshal(&mut header_buf);
    cmd_buf[..10].copy_from_slice(&header_buf[..10]);

    let mut resp_buf = [0u8; 4096];
    sim.transact(&cmd_buf[..written], &mut resp_buf).unwrap();

    let mut unmarsh = &resp_buf[..];
    use crate::test_utils::RespHeader;
    let resp_header = RespHeader::unmarshal(&mut unmarsh).unwrap();

    // C CryptParameterDecryption (CryptUtil.c:961-964): fewer than 2 bytes for
    // the size field is TPM_RC_INSUFFICIENT, plus the decrypt session index
    // (SessionProcess.c:1760-1762): INSUFFICIENT+S1 (0x99A). The empty HMAC is
    // accepted because the HMAC key is empty (SessionProcess.c:937-941).
    assert_eq!(resp_header.rc, 0x99a);
}

/// DECRYPT on a session with NULL symmetric fails with SYMMETRIC+S1.
#[test]
fn decrypt_with_null_symmetric_rejected() {
    let mut sim = create_simulator!();
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // Set decrypt on a Null symmetric session, which is invalid
    session.attributes.insert(TpmaSession::DECRYPT);

    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            ecc_parms,
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);
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

    let err = match execute_with_hmac_sessions(&mut sim, &create_cmd, &[], &mut [session], &[&[]]) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    // Expected error code: symmetric_for(Session, Pos1) -> 2454
    assert_eq!(err, 2454);
}

/// LoadExternal (no handles) with a DECRYPT session derives the key with an empty auth value.
#[test]
fn decrypt_without_auth_handles_uses_empty_auth() {
    let mut sim = create_simulator!();

    // Start an HMAC session with AES-128-CFB
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(AES128_CFB),
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let mut sessions = [session];
    sessions[0].attributes = TpmaSession::DECRYPT | TpmaSession::CONTINUE_SESSION;

    // Prepare LoadExternal which has NO handles
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&KEYED_HASH_SEED).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(Tpm2bSensitiveData::default()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area_local(
        &[0x11; 32],
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };

    // Execute command with DECRYPT attribute session.
    // KDFa key derivation should correctly use Empty Auth because there are no handles.
    let result = execute_with_hmac_sessions_custom(&mut sim, &cmd, &mut sessions, &[&[]]);

    assert!(
        result.is_ok(),
        "LoadExternal failed with DECRYPT session: {:?}",
        result.err()
    );
}

/// HierarchyChangeAuth with a DECRYPT HMAC session sets the owner auth (restored afterwards with a password session).
#[test]
fn hierarchy_change_auth_new_auth_decrypted() {
    let mut sim = create_simulator!();
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(AES128_CFB),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::DECRYPT);

    use tpm2::commands::HierarchyChangeAuth;
    let cmd = HierarchyChangeAuth {
        auth_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::from_bytes(b"new_auth_password").unwrap(),
    };

    execute_with_hmac_sessions(&mut sim, &cmd, &[], &mut [session], &[&[]]).unwrap();

    let cmd_back = HierarchyChangeAuth {
        auth_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::default(),
    };
    execute_with_password_sessions(&mut sim, &cmd_back, 1, b"new_auth_password").unwrap();
}

// parameter-decryption-executed-before-session-hmac-verification
/// A wrong HMAC is reported (BAD_AUTH) before malformed encrypted parameters; with a correct HMAC decrypt errors carry S1.
#[test]
fn hmac_verified_before_decryption() {
    let mut sim = new_sim();
    let mut s = start_session(&mut sim, TpmSe::HMAC, true);

    // A malformed (1-byte) encrypted first parameter together with a wrong HMAC: the
    // authorization failure must be reported, not the decryption error.
    let rc = exec(
        &mut sim,
        CC_HIERARCHY_CHANGE_AUTH,
        &[RH_OWNER],
        &mut [SessUse::hmac(&mut s, ATTR_CONT | ATTR_DECRYPT, &[]).bad_hmac()],
        &[0x00],
        0,
    )
    .rc;
    // TPM_RH_OWNER is DA-exempt, so the HMAC failure is TPM_RC_BAD_AUTH (C IncrementLockout).
    assert_eq!(rc, rc_s1(RC_BAD_AUTH));

    // With a correct HMAC the decryption errors carry the session position and use the C codes.
    let rc = exec(
        &mut sim,
        CC_HIERARCHY_CHANGE_AUTH,
        &[RH_OWNER],
        &mut [SessUse::hmac(&mut s, ATTR_CONT | ATTR_DECRYPT, &[])],
        &[0x00],
        0,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_INSUFFICIENT));
    let rc = exec(
        &mut sim,
        CC_HIERARCHY_CHANGE_AUTH,
        &[RH_OWNER],
        &mut [SessUse::hmac(&mut s, ATTR_CONT | ATTR_DECRYPT, &[])],
        &[0x00, 0x05, 0x01],
        0,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_SIZE));
}

/// CreatePrimary whose decrypted inSensitive size overstates its content fails with TPM_RC_SIZE + P1.
#[test]
fn oversized_sensitive_size_returns_size_p1() {
    let mut sim = create_simulator!();
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(AES128_CFB),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::DECRYPT);

    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            ecc_parms,
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);

    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(b"123").unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let mut sensitive_buf = [0u8; 256];
    let len = marshal_to_slice(&sensitive_create, &mut sensitive_buf);

    let mut corrupted_bytes = vec![0u8; len + 12];
    corrupted_bytes[0..2].copy_from_slice(&((len + 10) as u16).to_be_bytes());
    corrupted_bytes[2..len + 2].copy_from_slice(&sensitive_buf[..len]);

    assert!(
        Tpm2bSensitiveCreate::from_bytes(&corrupted_bytes).is_err(),
        "Client unmarshaler should reject corrupted Tpm2bSensitiveCreate buffer"
    );

    struct BadCreatePrimary<'a> {
        primary_handle: Handle,
        in_sensitive_buf: &'a [u8],
        in_public: tpm2::Tpm2bPublic<'a>,
        outside_info: tpm2::Tpm2bData<'a>,
        creation_pcr: tpm2::TpmlPcrSelection,
    }
    impl tpm2::Marshal for BadCreatePrimary<'_> {
        const MAX_SIZE: usize = 4096;
        type MaxBuffer = [u8; 4096];
        fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
            let mut off =
                (self.in_sensitive_buf.len() as u16).marshal((&mut dst[0..2]).try_into().unwrap());
            dst[off..off + self.in_sensitive_buf.len()].copy_from_slice(self.in_sensitive_buf);
            off += self.in_sensitive_buf.len();
            off += self.in_public.marshal(
                (&mut dst[off..off + tpm2::Tpm2bPublic::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
            off += self.outside_info.marshal(
                (&mut dst[off..off + tpm2::Tpm2bData::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
            off += self.creation_pcr.marshal(
                (&mut dst[off..off + tpm2::TpmlPcrSelection::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
            off
        }
    }
    impl tpm2::Command for BadCreatePrimary<'_> {
        const CMD_CODE: tpm2::TpmCc = tpm2::TpmCc::CreatePrimary;
        type Response<'a> = tpm2::commands::responses::CreatePrimary<'a>;
    }
    impl tpm2::Message for BadCreatePrimary<'_> {
        type Handles = [Handle; 1];
        fn handles(&self) -> Self::Handles {
            [self.primary_handle]
        }
    }

    let create_cmd = BadCreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive_buf: &corrupted_bytes,
        in_public,
        outside_info: tpm2::Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };

    let err = match execute_with_hmac_sessions(&mut sim, &create_cmd, &[], &mut [session], &[&[]]) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    assert_eq!(
        err,
        tpm2::errors::TpmRc::SIZE
            .with(tpm2::errors::Position::parameter(1))
            .get()
    ); // TPM_RC_SIZE + P1
}

/// LoadExternal with DECRYPT set on two sessions fails with an ATTRIBUTES error.
#[test]
fn two_decrypt_sessions_rejected() {
    let mut sim = create_simulator!();

    let sess1 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(AES128_CFB),
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let sess2 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(AES128_CFB),
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let mut sessions = [sess1, sess2];
    // Set DECRYPT on BOTH sessions (which is invalid, only the first session can have DECRYPT)
    sessions[0].attributes = TpmaSession::DECRYPT | TpmaSession::CONTINUE_SESSION;
    sessions[1].attributes = TpmaSession::DECRYPT | TpmaSession::CONTINUE_SESSION;

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&KEYED_HASH_SEED).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(Tpm2bSensitiveData::default()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area_local(
        &[0x11; 32],
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public,
        hierarchy: Handle::RH_NULL,
    };
    let result = execute_with_hmac_sessions_custom(&mut sim, &cmd, &mut sessions, &[&[], &[]]);

    assert!(result.is_err());
    let err = result.err().unwrap();
    assert_eq!(err & 0xFF, 0x82, "Expected Attributes error, got {:X}", err);
    assert_eq!(
        (err >> 8) & 0xF,
        10,
        "Expected error on session 2 (PosA/10), got {:X}",
        err
    );
}

/// CreatePrimary with decrypted userAuth of 7/16/17/32/33 bytes succeeds across AES-CFB block boundaries.
#[test]
fn user_auth_sizes_across_cfb_blocks() {
    let mut sim = create_simulator!();
    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha384),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            ecc_parms,
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);

    for auth_size in &[7, 16, 17, 32, 33] {
        let mut session = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::HMAC,
            Some(AES128_CFB),
            TpmiAlgHash::Sha256,
        )
        .unwrap();
        session.attributes.insert(TpmaSession::DECRYPT);

        let sensitive_create = TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(crate::test_utils::leak_bytes(&vec![
                0x41u8;
                *auth_size
            ]))
            .unwrap(),
            data: Tpm2bSensitiveData::default(),
        };
        let in_sensitive = tpm2::Tpm2b(sensitive_create);

        let create_cmd = CreatePrimary {
            primary_handle: Handle::RH_OWNER,
            in_sensitive,
            in_public,
            ..Default::default()
        };

        let create_rsp_handles =
            execute_with_hmac_sessions(&mut sim, &create_cmd, &[], &mut [session], &[&[]]).unwrap();

        flush_context(&mut sim, create_rsp_handles.object_handle).unwrap();
    }
}

/// A decrypt session on VerifySignature (no auth handle) derives its key with empty auth, not the key's auth.
#[allow(deprecated)]
#[test]
fn verify_signature_decrypt_uses_empty_auth() {
    let mut sim = create_simulator!();

    // Create an ECC key with non-empty auth
    let key_auth = b"key_secret_auth";
    let key_handle = create_ecc_key(&mut sim, key_auth);

    // Start decryption session
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(AES128_CFB),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::DECRYPT);

    let digest = Tpm2bDigest::from_bytes(&[0xBB; 32]).unwrap();
    let sign_cmd = tpm2::commands::Sign {
        key_handle,
        digest,
        in_scheme: None,
        validation: tpm2::TpmtTkHashcheck::default(),
    };
    let mut resp_buffer = [0u8; 4096];
    let sign_rsp = execute_sign(&mut sim, &sign_cmd, 1, key_auth, &mut resp_buffer)
        .expect("could not sign digest");

    // VerifySignature parameter: digest (to be decrypted)
    let verify_cmd = VerifySignature {
        key_handle,
        digest,
        signature: sign_rsp.signature,
    };

    // Case A: Client uses Empty Auth (&[]). This must SUCCEED.
    let session_a = session.clone();
    let result_a = execute_with_hmac_sessions(
        &mut sim,
        &verify_cmd,
        &[],
        &mut [session_a],
        &[&[]], // Empty Auth
    );
    assert!(
        result_a.is_ok(),
        "VerifySignature decryption should succeed with Empty Auth, got {:?}",
        result_a.err()
    );

    // Case B: Client uses the key's auth value. This must FAIL because TPM uses Empty Auth, resulting in key mismatch.
    let session_b = session.clone();
    let result_b = execute_with_hmac_sessions(
        &mut sim,
        &verify_cmd,
        &[],
        &mut [session_b.clone()],
        &[key_auth], // Wrong Auth (for this decrypt-only session KDFa key derivation)
    );
    assert!(
        result_b.is_err(),
        "VerifySignature decryption should fail when client uses key's auth value"
    );

    flush_context(&mut sim, key_handle).unwrap();
}

/// A decrypt session with a corrupted session key fails CreatePrimary with TPM_RC_BAD_AUTH + S1 (owner is DA-exempt).
#[test]
fn wrong_session_key_returns_bad_auth() {
    let mut sim = create_simulator!();
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(AES128_CFB),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::DECRYPT);
    session.session_key = vec![1u8; 32]; // wrong key

    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            ecc_parms,
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(b"key_auth_password").unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let err = match execute_with_hmac_sessions(&mut sim, &create_cmd, &[], &mut [session], &[&[]]) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    // Owner hierarchy is DA-exempt, so a bad HMAC yields BAD_AUTH+S1 (0x9A2)
    // rather than AUTH_FAIL (C SessionProcess.c IncrementLockout).
    assert_eq!(err, 0x9a2);
}
