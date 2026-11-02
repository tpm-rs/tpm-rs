//! TPM2_Policy_AC_SendSelect (deprecated in version 184): the policy digest update with and
//! without the Object Name, the cpHash/nameHash and commandCode checks, and that the session
//! is then bound to TPM2_AC_Send (which no reference implements).
#![allow(deprecated)]

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::{
    ClockRateAdjust, PolicyACSendSelect, PolicyCommandCode, PolicyCpHash, PolicyNameHash,
    SetPrimaryPolicy,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bNonce, TpmCc, TpmClockAdjust, TpmSe,
    TpmaSession, TpmiAlgHash, TpmsAuthCommand,
};

const OBJECT_NAME: [u8; 34] = [0x0B; 34];
const AUTH_HANDLE_NAME: [u8; 4] = [0x40, 0x00, 0x00, 0x01];
const AC_NAME: [u8; 4] = [0x90, 0x00, 0x00, 0x01];

/// `TPM2_Policy_AC_SendSelect(session, OBJECT_NAME, AUTH_HANDLE_NAME, AC_NAME, include_object)`.
fn ac_send_select(tpm: &mut Tpm, session: Handle, include_object: bool) -> Result<(), u32> {
    execute_with_password_sessions(
        tpm,
        &PolicyACSendSelect {
            policy_session: session,
            object_name: Tpm2bName::from_bytes(&OBJECT_NAME).unwrap(),
            auth_object_name: Tpm2bName::from_bytes(&AUTH_HANDLE_NAME).unwrap(),
            ac_name: Tpm2bName::from_bytes(&AC_NAME).unwrap(),
            include_object,
        },
        0,
        &[],
    )
    .map(|_| ())
}

/// The expected policy digest after TPM2_Policy_AC_SendSelect in a fresh SHA-256 session.
fn expected_digest(include_object: bool) -> Vec<u8> {
    let object: &[u8] = if include_object { &OBJECT_NAME } else { &[] };
    sha256(&[
        &[0u8; 32],
        &TpmCc::PolicyACSendSelect.code().to_be_bytes(),
        object,
        &AUTH_HANDLE_NAME,
        &AC_NAME,
        &[u8::from(include_object)],
    ])
}

/// The digest includes objectName only if includeObject is SET, and the includeObject octet.
#[test]
fn extends_policy_digest() {
    let mut tpm = Tpm::new();
    for include_object in [false, true] {
        for session_type in [TpmSe::Trial, TpmSe::Policy] {
            let session =
                start_session_with_nonce(&mut tpm, session_type, TpmiAlgHash::Sha256, &[1; 32]);
            assert_eq!(ac_send_select(&mut tpm, session, include_object), Ok(()));
            assert_eq!(
                policy_get_digest_checked(&mut tpm, session),
                expected_digest(include_object)
            );
            flush_context(&mut tpm, session).unwrap();
        }
    }
}

/// includeObject is a `TPMI_YES_NO`: any value but 0 and 1 is `TPM_RC_VALUE` (parameter 4).
#[test]
fn rejects_invalid_include_object() {
    let mut tpm = Tpm::new();
    let session = start_session_with_nonce(&mut tpm, TpmSe::Policy, TpmiAlgHash::Sha256, &[1; 32]);
    let mut params = Vec::new();
    push_2b(&mut params, &OBJECT_NAME);
    push_2b(&mut params, &AUTH_HANDLE_NAME);
    push_2b(&mut params, &AC_NAME);
    params.push(2);
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        TpmCc::PolicyACSendSelect.code(),
        &[session.0],
        None,
        &params,
    );
    assert_eq!(
        send_rc(&mut tpm, &cmd),
        TpmRc::VALUE.with(Position::parameter(4)).get()
    );
}

/// A session whose cpHash is set is `TPM_RC_CPHASH`; one whose commandCode is set is
/// `TPM_RC_COMMAND_CODE`; a second TPM2_Policy_AC_SendSelect is `TPM_RC_CPHASH`.
#[test]
fn rejects_occupied_cp_hash_and_command_code() {
    let mut tpm = Tpm::new();

    let session = start_session_with_nonce(&mut tpm, TpmSe::Policy, TpmiAlgHash::Sha256, &[1; 32]);
    execute_with_password_sessions(
        &mut tpm,
        &PolicyCpHash {
            policy_session: session,
            cp_hash_a: Tpm2bDigest::from_bytes(&[3u8; 32]).unwrap(),
        },
        0,
        &[],
    )
    .unwrap();
    assert_eq!(
        ac_send_select(&mut tpm, session, false),
        Err(TpmRc::CPHASH.get())
    );

    let session = start_session_with_nonce(&mut tpm, TpmSe::Policy, TpmiAlgHash::Sha256, &[2; 32]);
    execute_with_password_sessions(
        &mut tpm,
        &PolicyCommandCode {
            policy_session: session,
            code: TpmCc::GetRandom,
        },
        0,
        &[],
    )
    .unwrap();
    assert_eq!(
        ac_send_select(&mut tpm, session, false),
        Err(TpmRc::COMMAND_CODE.get())
    );

    let session = start_session_with_nonce(&mut tpm, TpmSe::Policy, TpmiAlgHash::Sha256, &[3; 32]);
    ac_send_select(&mut tpm, session, true).unwrap();
    assert_eq!(
        ac_send_select(&mut tpm, session, true),
        Err(TpmRc::CPHASH.get())
    );
}

/// TPM2_Policy_AC_SendSelect sets nameHash: a later TPM2_PolicyNameHash or TPM2_PolicyCpHash is
/// `TPM_RC_CPHASH`.
#[test]
fn sets_name_hash() {
    let mut tpm = Tpm::new();
    let session = start_session_with_nonce(&mut tpm, TpmSe::Policy, TpmiAlgHash::Sha256, &[1; 32]);
    ac_send_select(&mut tpm, session, false).unwrap();
    let digest = Tpm2bDigest::from_bytes(&[9u8; 32]).unwrap();
    assert_eq!(
        execute_with_password_sessions(
            &mut tpm,
            &PolicyNameHash {
                policy_session: session,
                name_hash: digest,
            },
            0,
            &[],
        )
        .map(|_| ()),
        Err(TpmRc::CPHASH.get())
    );
    assert_eq!(
        execute_with_password_sessions(
            &mut tpm,
            &PolicyCpHash {
                policy_session: session,
                cp_hash_a: digest,
            },
            0,
            &[],
        )
        .map(|_| ()),
        Err(TpmRc::CPHASH.get())
    );
}

/// The session's commandCode is TPM_CC_AC_Send: authorizing any other command fails with
/// `TPM_RC_POLICY_CC` (session 1).
#[test]
fn binds_session_to_ac_send() {
    let mut tpm = Tpm::new();
    execute_with_password_sessions(
        &mut tpm,
        &SetPrimaryPolicy {
            auth_handle: Handle::RH_OWNER,
            auth_policy: Tpm2bDigest::from_bytes(leak_bytes(&expected_digest(false))).unwrap(),
            hash_alg: Some(TpmiAlgHash::Sha256),
        },
        1,
        &[],
    )
    .unwrap();
    let session = start_session_with_nonce(&mut tpm, TpmSe::Policy, TpmiAlgHash::Sha256, &[1; 32]);
    ac_send_select(&mut tpm, session, false).unwrap();
    let auth = TpmsAuthCommand {
        session_handle: session,
        nonce: Tpm2bNonce::from_bytes(&[0x55; 16]).unwrap(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bAuth::default(),
    };
    let cmd = ClockRateAdjust {
        auth: Handle::RH_OWNER,
        rate_adjust: TpmClockAdjust::NoChange,
    };
    assert_eq!(
        exec_command(&mut tpm, &cmd, &[auth]).map(|_| ()),
        Err(TpmRc::POLICY_CC.with(Position::session(1)).get())
    );
}
