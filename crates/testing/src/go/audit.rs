use crate::test_utils::marshal_to_slice;

use crate::test_utils::{
    CmdHeader, RespHeader, execute_get_session_audit_digest, execute_with_hmac_sessions_raw,
    execute_with_password_sessions, flush_context, start_auth_session,
};
use sha2::{Digest as _, Sha256};
use tpm2::Marshal;
use tpm2::Unmarshal;
use tpm2::commands::{
    Certify, CertifyHandles, Command, CreatePrimary, CreatePrimaryHandles, GetCapability,
    GetSessionAuditDigest, GetSessionAuditDigestHandles,
};
use tpm2::{Handle, TpmCap, TpmCc, TpmEccCurve, TpmPt, TpmSe, TpmSt};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter, Tpm2bNonce,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmaObject, TpmaSession, TpmiAlgHash, TpmiRsaKeyBits,
    TpmiStCommandTag, TpmsAuthCommand, TpmsEccParms, TpmsEccPoint, TpmsRsaParms,
    TpmsSensitiveCreate, TpmtEccScheme, TpmtPublic, TpmtSigScheme,
};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

// Stubs removed, imported from tpm2::commands instead.

// =========================================================================
// Helper Functions
// =========================================================================

pub fn execute_with_password_sessions_diff_raw<CmdT: Command>(
    tpm: &mut Simulator<'_>,
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    auth_values: &[&[u8]],
    resp_buffer: &mut [u8; 4096],
) -> Result<(usize, usize, CmdT::RespHandles), u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut cmd_buffer = [0u8; 4096];
    let mut cmd_header = CmdHeader {
        tag: if !auth_values.is_empty() {
            TpmiStCommandTag::Sessions
        } else {
            TpmiStCommandTag::NoSessions
        },
        size: 0,
        code: CmdT::CMD_CODE,
    };
    let mut written = cmd_header.marshal((&mut cmd_buffer[0..10]).try_into().unwrap());
    written += marshal_to_slice(&(cmd_handles), &mut cmd_buffer[written..]);

    let mut auth_buffer = [0u8; 1024];
    let mut auth_written = 0;
    for auth_value in auth_values {
        let mut auth_val = Tpm2bAuth::default();
        if !auth_value.is_empty() {
            auth_val = Tpm2bAuth::from_bytes(auth_value).unwrap();
        }
        let auth_cmd = TpmsAuthCommand {
            session_handle: Handle::RS_PW,
            nonce: Tpm2bNonce::default(),
            session_attributes: TpmaSession(1),
            hmac: auth_val,
        };
        auth_written += marshal_to_slice(&(auth_cmd), &mut auth_buffer[auth_written..]);
    }

    if !auth_values.is_empty() {
        written += marshal_to_slice(&(auth_written as u32), &mut cmd_buffer[written..]);
        cmd_buffer[written..written + auth_written].copy_from_slice(&auth_buffer[..auth_written]);
        written += auth_written;
    }

    written += marshal_to_slice(cmd, &mut cmd_buffer[written..]);

    let mut header_buf = [0u8; 10];
    cmd_header.size = written as u32;
    cmd_header.marshal(&mut header_buf);
    cmd_buffer[..10].copy_from_slice(&header_buf[..10]);

    tpm.transact(&cmd_buffer[..written], resp_buffer).unwrap();

    let mut slice = &resp_buffer[..];
    let resp_header = RespHeader::unmarshal(&mut slice).unwrap();
    if resp_header.rc != 0 {
        return Err(resp_header.rc);
    }

    let orig_handles_len = slice.len();
    let resp_handles = CmdT::RespHandles::unmarshal(&mut slice).unwrap();
    let handles_consumed = orig_handles_len - slice.len();
    let mut param_start = 10 + handles_consumed;
    if resp_header.tag == TpmSt::SESSIONS {
        let _param_size = u32::unmarshal(&mut slice).unwrap();
        param_start += 4;
    }

    let resp_size = resp_header.size as usize;
    Ok((param_start, resp_size, resp_handles))
}

pub fn execute_with_password_sessions_diff<CmdT: Command>(
    tpm: &mut Simulator<'_>,
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    auth_values: &[&[u8]],
) -> Result<(CmdT::Response<'static>, CmdT::RespHandles), u32>
where
    CmdT::Response<'static>: Unmarshal<'static>,
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut resp_buffer = [0u8; 4096];
    let (param_start, resp_size, resp_handles) = execute_with_password_sessions_diff_raw(
        tpm,
        cmd,
        cmd_handles,
        auth_values,
        &mut resp_buffer,
    )?;
    let mut slice: &'static [u8] =
        crate::test_utils::leak_bytes(&resp_buffer[param_start..resp_size]);
    let resp = <CmdT::Response<'static>>::unmarshal(&mut slice).unwrap();
    Ok((resp, resp_handles))
}

pub fn execute_get_session_audit_digest_diff(
    tpm: &mut Simulator<'_>,
    cmd: &GetSessionAuditDigest,
    cmd_handles: GetSessionAuditDigestHandles,
    auth_values: &[&[u8]],
    resp_buffer: &mut [u8; 4096],
) -> Result<
    (
        <GetSessionAuditDigest<'static> as Command>::Response<'static>,
        (),
    ),
    u32,
> {
    let (param_start, resp_size, handles) =
        execute_with_password_sessions_diff_raw(tpm, cmd, cmd_handles, auth_values, resp_buffer)?;
    let mut slice: &'static [u8] =
        crate::test_utils::leak_bytes(&resp_buffer[param_start..resp_size]);
    let resp = Unmarshal::unmarshal(&mut slice).unwrap();
    Ok((resp, handles))
}

fn create_ak_ecc(sim: &mut Simulator<'_>, auth: &[u8]) -> (Handle, tpm2::Tpm2bName<'static>) {
    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::RESTRICTED
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let in_public = tpm2::Tpm2b(public_area);

    let mut user_auth = Tpm2bAuth::default();
    if !auth.is_empty() {
        user_auth = Tpm2bAuth::from_bytes(auth).unwrap();
    }

    let sensitive_create = TpmsSensitiveCreate {
        user_auth,
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
    let (rsp, rsp_handles) =
        execute_with_password_sessions(sim, &create_cmd, create_handles, 1, &[])
            .expect("could not generate AK ECC key");

    (rsp_handles.object_handle, rsp.name)
}

fn create_certifiable_key_rsa(sim: &mut Simulator<'_>) -> (Handle, tpm2::Tpm2bName<'static>) {
    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
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

    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (rsp, rsp_handles) =
        execute_with_password_sessions(sim, &create_cmd, create_handles, 1, &[])
            .expect("could not generate RSA key to certify");

    (rsp_handles.object_handle, rsp.name)
}

fn extend_audit_digest(
    current_digest: &mut [u8; 32],
    cmd_code: TpmCc,
    handle_names: &[&[u8]],
    cmd_params: &[u8],
    resp_params: &[u8],
) {
    // cpHash
    let mut cp_hasher = Sha256::new();
    cp_hasher.update(cmd_code.code().to_be_bytes());
    for name in handle_names {
        cp_hasher.update(name);
    }
    cp_hasher.update(cmd_params);
    let cp_hash = cp_hasher.finalize();

    // rpHash
    let mut rp_hasher = Sha256::new();
    rp_hasher.update(0u32.to_be_bytes()); // responseCode = TPM_RC_SUCCESS (0)
    rp_hasher.update(cmd_code.code().to_be_bytes());
    rp_hasher.update(resp_params);
    let rp_hash = rp_hasher.finalize();

    // extend digest: digest = SHA256(digest || cpHash || rpHash)
    let mut extend_hasher = Sha256::new();
    extend_hasher.update(current_digest.as_slice());
    extend_hasher.update(cp_hash.as_slice());
    extend_hasher.update(rp_hash.as_slice());
    current_digest.copy_from_slice(&extend_hasher.finalize());
}

// =========================================================================
// Tests
// =========================================================================

// Original Go test: audit_test.go - TestAuditSession
#[test]
fn test_audit_session() {
    let mut sim = create_simulator!();

    // Create the audit session
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
    sess.attributes = TpmaSession::AUDIT | TpmaSession::CONTINUE_SESSION;

    // Create the AK for audit signing
    let (ak_handle, _ak_name) = create_ak_ecc(&mut sim, &[]);

    let mut accumulated_digest = [0u8; 32];
    let mut audit_replay_digest = [0u8; 32];

    let props = [
        TpmPt::FAMILY_INDICATOR,
        TpmPt::LEVEL,
        TpmPt::REVISION,
        TpmPt::DAY_OF_YEAR,
        TpmPt::YEAR,
        TpmPt::MANUFACTURER,
    ];

    for prop in props {
        let get_cmd = GetCapability {
            capability: TpmCap::TPMProperties,
            property: u32::from(prop),
            property_count: 1,
        };

        // Execute GetCapability command with the audit session
        let mut sessions = [sess.clone()];
        let (get_rsp_bytes, _) =
            execute_with_hmac_sessions_raw(&mut sim, &get_cmd, (), &[], &mut sessions, &[&[]])
                .unwrap();
        // Update session state (nonces)
        sess = sessions[0].clone();

        // Calculate audit digest locally
        let mut cmd_buf = [0u8; 512];
        let cmd_len = marshal_to_slice(&get_cmd, &mut cmd_buf);

        extend_audit_digest(
            &mut accumulated_digest,
            GetCapability::CMD_CODE,
            &[],
            &cmd_buf[..cmd_len],
            &get_rsp_bytes,
        );

        // Get the audit digest signed by the AK
        let get_audit_cmd = GetSessionAuditDigest {
            qualifying_data: Tpm2bData::from_bytes(b"foobar").unwrap(),
            in_scheme: None,
        };
        let get_audit_handles = GetSessionAuditDigestHandles {
            privacy_admin_handle: Handle::RH_ENDORSEMENT,
            sign_handle: ak_handle,
            session_handle: sess.session_handle,
        };

        let mut resp_buffer = [0u8; 4096];
        let (get_audit_rsp, _) = execute_get_session_audit_digest(
            &mut sim,
            &get_audit_cmd,
            get_audit_handles,
            2,
            &[],
            &mut resp_buffer,
        )
        .unwrap();

        // Check that the TPM's audit digest matches our accumulated digest
        let attest = get_audit_rsp
            .audit_info
            .to_struct()
            .expect("failed to unmarshal audit_info");

        let aud_info = match attest.attested {
            tpm2::TpmuAttest::SessionAudit(info) => info,
            _ => panic!("Expected SessionAudit attestation type"),
        };

        assert_eq!(
            accumulated_digest.as_slice(),
            aud_info.session_digest.get_buffer(),
            "unexpected audit value"
        );

        // Demonstrate that audit value can be replayed from marshaled command/response
        let mut unmarsh_cmd = &cmd_buf[..cmd_len];
        let replayed_cmd = GetCapability::unmarshal(&mut unmarsh_cmd).unwrap();

        let mut unmarsh_resp = &get_rsp_bytes[..];
        let replayed_rsp =
            <GetCapability as Command>::Response::unmarshal(&mut unmarsh_resp).unwrap();

        let mut rep_cmd_buf = [0u8; 512];
        let rep_cmd_len = marshal_to_slice(&replayed_cmd, &mut rep_cmd_buf);
        let mut rep_resp_buf = [0u8; 512];
        let rep_resp_len = marshal_to_slice(&replayed_rsp, &mut rep_resp_buf);

        extend_audit_digest(
            &mut audit_replay_digest,
            GetCapability::CMD_CODE,
            &[],
            &rep_cmd_buf[..rep_cmd_len],
            &rep_resp_buf[..rep_resp_len],
        );

        assert_eq!(
            accumulated_digest, audit_replay_digest,
            "unexpected audit value from replay"
        );
    }

    flush_context(&mut sim, ak_handle).unwrap();
}

// Original Go test: audit_test.go - TestAuditSessionWithCertify
#[test]
fn test_audit_session_with_certify() {
    let mut sim = create_simulator!();

    // Create the audit session
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
    sess.attributes = TpmaSession::AUDIT | TpmaSession::CONTINUE_SESSION;

    let auth_value = b"password";

    // Create the AK for audit signing
    let (ak_handle, ak_name) = create_ak_ecc(&mut sim, auth_value);

    // Create a key to certify
    let (key_to_certify_handle, key_to_certify_name) = create_certifiable_key_rsa(&mut sim);

    let certify_cmd = Certify {
        qualifying_data: Tpm2bData::from_bytes(b"test").unwrap(),
        in_scheme: Some(TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256)),
    };
    let certify_handles = CertifyHandles {
        object_handle: key_to_certify_handle,
        sign_handle: ak_handle,
    };

    // We authorize the object_handle with password auth (empty) and sign_handle with password auth (auth_value)
    // plus we pass the audit session as a third session.
    let key_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let ak_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // Session order:
    // 1. Session for ObjectHandle (key_session)
    // 2. Session for SignHandle (ak_session)
    // 3. Audit Session (sess)
    let mut sessions = [key_session, ak_session, sess.clone()];
    let (certify_resp_bytes, _) = execute_with_hmac_sessions_raw(
        &mut sim,
        &certify_cmd,
        certify_handles,
        &[],
        &mut sessions,
        &[&[] as &[u8], auth_value, &[]],
    )
    .unwrap();

    // Update audit session state
    sess = sessions[2].clone();

    // Calculate audit digest locally
    let mut cmd_buf = [0u8; 1024];
    let cmd_len = marshal_to_slice(&certify_cmd, &mut cmd_buf);

    let mut accumulated_digest = [0u8; 32];
    extend_audit_digest(
        &mut accumulated_digest,
        Certify::CMD_CODE,
        &[key_to_certify_name.get_buffer(), ak_name.get_buffer()],
        &cmd_buf[..cmd_len],
        &certify_resp_bytes,
    );

    // Get the audit digest signed by the AK
    let get_audit_cmd = GetSessionAuditDigest {
        qualifying_data: Tpm2bData::from_bytes(b"foobar").unwrap(),
        in_scheme: None,
    };
    let get_audit_handles = GetSessionAuditDigestHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: ak_handle,
        session_handle: sess.session_handle,
    };

    // Use password auth for sign_handle to get the audit digest
    let mut resp_buffer = [0u8; 4096];
    let (get_audit_rsp, _) = execute_get_session_audit_digest_diff(
        &mut sim,
        &get_audit_cmd,
        get_audit_handles,
        &[&[], auth_value],
        &mut resp_buffer,
    )
    .unwrap();

    // Verify the TPM's audit digest matches our calculated digest
    let attest = get_audit_rsp
        .audit_info
        .to_struct()
        .expect("failed to unmarshal audit_info");

    let aud_info = match attest.attested {
        tpm2::TpmuAttest::SessionAudit(info) => info,
        _ => panic!("Expected SessionAudit attestation type"),
    };

    assert_eq!(
        accumulated_digest.as_slice(),
        aud_info.session_digest.get_buffer(),
        "TPM audit digest doesn't match calculated digest"
    );

    // Verify unmarshaling works and matches
    let mut unmarsh_cmd = &cmd_buf[..cmd_len];
    let replayed_cmd = Certify::unmarshal(&mut unmarsh_cmd).unwrap();

    let mut unmarsh_resp = &certify_resp_bytes[..];
    let replayed_rsp = <Certify as Command>::Response::unmarshal(&mut unmarsh_resp).unwrap();

    let mut rep_cmd_buf = [0u8; 1024];
    let rep_cmd_len = marshal_to_slice(&replayed_cmd, &mut rep_cmd_buf);
    let mut rep_resp_buf = [0u8; 1024];
    let rep_resp_len = marshal_to_slice(&replayed_rsp, &mut rep_resp_buf);

    let mut audit_replay_digest = [0u8; 32];
    extend_audit_digest(
        &mut audit_replay_digest,
        Certify::CMD_CODE,
        &[key_to_certify_name.get_buffer(), ak_name.get_buffer()],
        &rep_cmd_buf[..rep_cmd_len],
        &rep_resp_buf[..rep_resp_len],
    );

    assert_eq!(
        accumulated_digest, audit_replay_digest,
        "unmarshalled audit digest doesn't match original"
    );

    flush_context(&mut sim, key_to_certify_handle).unwrap();
    flush_context(&mut sim, ak_handle).unwrap();
}
