use crate::test_utils::marshal_to_slice;
use crate::test_utils::{
    execute_with_hmac_sessions, execute_with_password_sessions, start_auth_session,
};
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles, ReadPublic, ReadPublicHandles};
use tpm2::{Handle, TpmEccCurve, TpmSe};
use tpm2::{Marshal, Unmarshal};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bSensitiveData, TpmaObject,
    TpmaSession, TpmiAlgHash, TpmiAlgSymMode, TpmiStCommandTag, TpmsAuthCommand, TpmsEccParms,
    TpmsEccPoint, TpmsSensitiveCreate, TpmtEccScheme, TpmtPublic, TpmtSymDefObject,
};
use tpm2_simulator::{Simulator, create_simulator};

fn create_primary_key(sim: &mut Simulator) -> Handle {
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
    use tpm2::Tpm2bEccParameter;
    let in_public = tpm2::Tpm2b(pub_area);
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
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (_, create_rsp_handles) =
        execute_with_password_sessions(sim, &create_cmd, create_handles, 0, &[]).unwrap();
    create_rsp_handles.object_handle
}

#[test]
fn test_decrypt_second_session_fails() {
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

    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles { object_handle };
    let err = match execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        read_handles,
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

#[test]
fn test_encrypt_multiple_sessions_fails() {
    let mut sim = create_simulator!();
    let object_handle = create_primary_key(&mut sim);
    let mut session1 = start_auth_session(
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

    // Set encrypt on both sessions
    session1.attributes.insert(TpmaSession::ENCRYPT);
    session2.attributes.insert(TpmaSession::ENCRYPT);

    let read_cmd = ReadPublic {};
    let read_handles = ReadPublicHandles { object_handle };
    let err = match execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        read_handles,
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

#[test]
fn test_param_decrypt_symmetric_null_fails() {
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
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let err = match execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[],
        &mut [session],
        &[&[]],
    ) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    // Expected error code: symmetric_for(Session, Pos1) -> 2454
    assert_eq!(err, 2454);
}

/// Parameter encryption/decryption only supports CFB mode (TPM 2.0 Part 1,
/// 21.3). A black-box client cannot force a non-CFB mode into a live session,
/// so verify that the TPM refuses to create such a session in the first place:
/// `TPM2_StartAuthSession` must reject every symmetric mode other than CFB.
#[test]
fn test_start_auth_session_rejects_non_cfb_symmetric_mode() {
    let mut sim = create_simulator!();
    for mode in [
        TpmiAlgSymMode::CTR,
        TpmiAlgSymMode::OFB,
        TpmiAlgSymMode::CBC,
        TpmiAlgSymMode::ECB,
    ] {
        let res = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::HMAC,
            Some(TpmtSymDefObject::Aes128(Some(mode))),
            TpmiAlgHash::Sha256,
        );
        let err = res.expect_err("StartAuthSession accepted a non-CFB symmetric mode");
        // Strip the format-1 parameter number (bits 6 and 8..11).
        assert_eq!(
            err & 0xBF,
            tpm2::errors::TpmRc::MODE.get(),
            "mode {mode:?}: unexpected error {err:#x}"
        );
    }

    // CFB is accepted.
    start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .expect("StartAuthSession with AES-128-CFB failed");
}

#[test]
fn test_param_decrypt_size_too_small() {
    let mut sim = create_simulator!();
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
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

    // Expected error code: TPM_RC_SIZE (149 or 0x095)
    assert_eq!(resp_header.rc, 149);
}

#[test]
fn test_param_decrypt_size_mismatch() {
    let mut sim = create_simulator!();
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
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

    // Expected error code: TPM_RC_SIZE (149 or 0x095)
    assert_eq!(resp_header.rc, 149);
}
