//! TPM2_PolicyNV and TPM2_PolicyNvWritten: operand/offset checks, read access and written-state
//! assertions.

use crate::_common::*;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmSe, TpmaNv, TpmiAlgHash};
use tpm2_simulator::create_simulator;

/// PolicyNvWritten with writtenSet = 3 fails with TPM_RC_VALUE + P1 (TC2_1_25_20_05).
///
/// Regression test for CPCTPM_TC2_1_25_20_05:
/// TPM2_PolicyNvWritten with an invalid writtenSet value (3)
/// must return TPM_RC_VALUE (Parameter 1, 0x0103).
#[test]
fn invalid_written_set_rejected() {
    let mut sim = create_simulator!();

    // Start a trial policy session
    let session_handle = start_trial_session(&mut sim);

    let mut pnw_req = hex_checked(concat!(
        "8001",     // NO_SESSIONS
        "0000000f", // size: 15 bytes
        "0000018f", // TPM_CC_PolicyNvWritten
        "03000000", // sessionHandle
        "03",       // writtenSet = 3 (invalid bool)
    ));
    pnw_req[10..14].copy_from_slice(&session_handle.0.to_be_bytes());

    let rc = raw_rc(&mut sim, &pnw_req);
    assert_eq!(
        rc,
        TpmRc::VALUE.with(Position::parameter(1)).get(),
        "Expected TPM_RC_VALUE (0x0103) for PolicyNvWritten with invalid writtenSet"
    );
}

/// PolicyNvWritten on a non-NV entity fails at the session position; PolicyGetDigest allows an encrypt session.
///
/// verify-session-hmacs-check-nv-written-missing-rc-s-and-encrypt-decrypt-command-table
#[test]
fn nv_written_on_non_nv_entity_and_get_digest_encrypt() {
    let mut sim = new_sim();
    check_nv_written_on_non_nv_entity(&mut sim);

    // The command tables: TPM2_PolicyGetDigest allows an encrypt session.
    let mut s = start_session(&mut sim, TpmSe::HMAC, true);
    let p = start_session(&mut sim, TpmSe::Policy, false);
    let r = exec(
        &mut sim,
        CC_POLICY_GET_DIGEST,
        &[p.handle],
        &mut [SessUse::hmac(&mut s, ATTR_CONT | ATTR_ENCRYPT, &[])],
        &[],
        0,
    );
    assert_eq!(r.rc, 0);
}

/// A PolicyNvWritten session authorizing a non-NV entity fails with an S1-positioned error.
///
/// verify-session-hmacs-check-nv-written-omits-session-position (handed over by fix-auth)
#[test]
fn nv_written_on_non_nv_entity_position() {
    let mut sim = new_sim();
    check_nv_written_on_non_nv_entity(&mut sim);
}

/// PolicyNV operand/offset size checks, owner read access, trial undefined index; PolicyAuthorizeNV SHA-1 TPMT_HA is HASH.
#[test]
fn operand_offset_and_read_access_checks() {
    let mut sim = create_simulator!();
    let readable = 0x0150_0020;
    define_nv_empty_policy(&mut sim, readable, nv_attrs(TpmaNv::OWNERREAD), 32);
    write_nv_owner(&mut sim, readable, &[0x11; 32]);

    // operandB is not limited to the session's digest size (SHA-1 = 20 bytes).
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha1).session_handle;
    policy_nv(&mut sim, Handle::RH_OWNER, readable, s, &[0x11; 24], 0)
        .expect("24-byte operandB with a SHA-1 session");

    // offset > dataSize: TPM_RCS_VALUE + RC_PolicyNV_offset (parameter 2).
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_nv(&mut sim, Handle::RH_OWNER, readable, s, &[0x11; 1], 33),
        Err(TpmRc::VALUE.with(Position::parameter(2)).get())
    );
    // dataSize - offset < operandB size: TPM_RCS_SIZE + RC_PolicyNV_operandB.
    assert_eq!(
        policy_nv(&mut sim, Handle::RH_OWNER, readable, s, &[0x11; 4], 30),
        Err(TpmRc::SIZE.with(Position::parameter(1)).get())
    );

    // authHandle = TPM_RH_OWNER without TPMA_NV_OWNERREAD: TPM_RC_NV_AUTHORIZATION.
    let no_owner_read = 0x0150_0021;
    define_nv_empty_policy(&mut sim, no_owner_read, nv_attrs(TpmaNv::empty()), 32);
    write_nv_owner(&mut sim, no_owner_read, &[0x11; 32]);
    assert_eq!(
        policy_nv(&mut sim, Handle::RH_OWNER, no_owner_read, s, &[0x11; 4], 0),
        Err(TpmRc::NV_AUTHORIZATION.get())
    );

    // Trial session: an undefined nvIndex is rejected against handle 2.
    let t = start_session_with_hash(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_nv(&mut sim, Handle::RH_OWNER, 0x0150_0099, t, &[0x11; 4], 0),
        Err(TpmRc::HANDLE.with(Position::handle(2)).get())
    );

    // PolicyAuthorizeNV: a SHA-1 TPMT_HA in the index with a SHA-256 session is TPM_RC_HASH.
    let policy_index = 0x0150_0022;
    define_nv_empty_policy(&mut sim, policy_index, nv_attrs(TpmaNv::OWNERREAD), 22);
    let mut tpmt_ha = vec![0x00, 0x04];
    tpmt_ha.extend_from_slice(&[0; 20]);
    write_nv_owner(&mut sim, policy_index, &tpmt_ha);
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_authorize_nv(&mut sim, Handle::RH_OWNER, policy_index, s),
        Err(TpmRc::HASH.get())
    );

    // PolicyAuthorizeNV accepts a POLICYREAD index authorized by a policy session.
    let policy_read = 0x0150_0028;
    define_policy_read_authorize_index(&mut sim, policy_read);
    let target =
        start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    policy_authorize_nv_with_policy_auth(&mut sim, policy_read, target).unwrap();
}
