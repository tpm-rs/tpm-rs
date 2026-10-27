//! TPM2_Vendor_TCG_Test (TPM 2.0 Part 3, "Vendor Specific"): the vendor command (`CC_VEND`,
//! `0x20000000`) every TPM implements to test the dispatch of vendor-specific commands. It
//! returns its `inputData` as `outputData`; its `TPM2B_DATA` parameters allow parameter
//! encryption in both directions, it works with audit sessions, can be command-audited and
//! named by `TPM2_PolicyCommandCode`, and it is dispatched like any other command (header,
//! size and startup checks).

use crate::_common::{
    AES128_CFB, RC_INSUFFICIENT, RC_SIZE, ST_NO_SESSIONS, STRONGEST_HASH_ALG, audit_commands,
    build_raw_cmd, command_audit_report, execute_with_hmac_sessions, hash_parts, send_raw,
    set_command_code_audit_status, start_auth_session,
};
use testing::tpm::Tpm;
use tpm2::commands::VendorTcgTest;
use tpm2::{Handle, Marshal, Tpm2bData, TpmSe, TpmaSession, TpmiAlgHash};

/// `TPM_CC_Vendor_TCG_Test`.
const CC_VENDOR_TCG_TEST: u32 = 0x2000_0000;
/// `TPM_CC_SetCommandCodeAuditStatus`.
const CC_SET_COMMAND_CODE_AUDIT_STATUS: u32 = 0x140;
/// `TPM_CC_PolicyCommandCode`.
const CC_POLICY_COMMAND_CODE: u32 = 0x16C;
/// `TPM_ALG_NULL`.
const ALG_NULL: u16 = 0x0010;
/// `TPM_RC_P + TPM_RC_1`.
const P1: u32 = 0x140;
/// `TPM_RC_POLICY_CC`.
const RC_POLICY_CC: u32 = 0x0A4;
/// `TPM_RC_INITIALIZE`.
const RC_INITIALIZE: u32 = 0x100;
/// `TPM_RC_COMMAND_CODE`.
const RC_COMMAND_CODE: u32 = 0x143;

/// The capacity of a `TPM2B_DATA` (`sizeof(TPMT_HA)`).
fn data_capacity() -> usize {
    Tpm2bData::MAX_SIZE - 2
}

/// `TPM2B_DATA` wire bytes of `data`.
fn tpm2b(data: &[u8]) -> Vec<u8> {
    let mut out = (data.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(data);
    out
}

/// Sends `TPM2_Vendor_TCG_Test` without sessions with the raw parameter area `params` and
/// returns the response.
fn vendor_tcg_test_raw(sim: &mut Tpm, params: &[u8]) -> Vec<u8> {
    send_raw(
        sim,
        &build_raw_cmd(ST_NO_SESSIONS, CC_VENDOR_TCG_TEST, &[], None, params),
    )
}

/// The response code of a response.
fn rc(rsp: &[u8]) -> u32 {
    u32::from_be_bytes(rsp[6..10].try_into().unwrap())
}

/// The command returns its inputData as outputData
///
/// For an empty, a short and a maximum-size `inputData`, the response (`TPM_ST_NO_SESSIONS`)
/// carries exactly the same `TPM2B_DATA` as `outputData`.
#[test]
fn echoes_input_data() {
    let mut sim = Tpm::new();
    let max: Vec<u8> = (0..data_capacity()).map(|i| i as u8).collect();
    for data in [&[][..], b"vendor", &max] {
        let rsp = vendor_tcg_test_raw(&mut sim, &tpm2b(data));
        assert_eq!(rc(&rsp), 0, "len {}", data.len());
        assert_eq!(&rsp[0..2], &ST_NO_SESSIONS.to_be_bytes());
        assert_eq!(&rsp[10..], &tpm2b(data)[..], "len {}", data.len());
    }
}

/// The typed command round-trips through the tpm2 command and response types
///
/// `Connection::execute` with `tpm2::commands::VendorTcgTest` returns the `inputData` in
/// `responses::VendorTcgTest::output_data`.
#[test]
fn typed_command_echoes_input_data() {
    let mut sim = Tpm::new();
    let cmd = VendorTcgTest {
        input_data: Tpm2bData::from_bytes(b"typed").unwrap(),
    };
    let rsp = sim.execute(cmd).unwrap();
    assert_eq!(rsp.output_data.get_buffer(), b"typed");
}

/// Malformed parameter areas fail like for any other command
///
/// An `inputData` larger than a `TPM2B_DATA` is `TPM_RC_SIZE + P1`, a truncated one is
/// `TPM_RC_INSUFFICIENT + P1` (also with no parameter at all), and trailing bytes after it
/// are `TPM_RC_SIZE`.
#[test]
fn malformed_parameters_are_rejected() {
    let mut sim = Tpm::new();
    let too_big = vec![0x5A; data_capacity() + 1];
    assert_eq!(
        rc(&vendor_tcg_test_raw(&mut sim, &tpm2b(&too_big))),
        RC_SIZE + P1
    );
    assert_eq!(
        rc(&vendor_tcg_test_raw(&mut sim, &[0, 4, 1, 2])),
        RC_INSUFFICIENT + P1
    );
    assert_eq!(
        rc(&vendor_tcg_test_raw(&mut sim, &[])),
        RC_INSUFFICIENT + P1
    );
    assert_eq!(rc(&vendor_tcg_test_raw(&mut sim, &[0, 1, 7, 0])), RC_SIZE);
}

/// The command is rejected with TPM_RC_INITIALIZE before TPM2_Startup
///
/// Like every command but `TPM2_Startup`, `TPM2_Vendor_TCG_Test` fails with
/// `TPM_RC_INITIALIZE` after `_TPM_Init` until the TPM is started.
#[test]
fn rejected_before_startup() {
    let mut sim = Tpm::new();
    crate::_common::power_cycle(&mut sim);
    assert_eq!(
        rc(&vendor_tcg_test_raw(&mut sim, &tpm2b(b"x"))),
        RC_INITIALIZE
    );
}

/// Neighbouring vendor command codes are not implemented
///
/// Only the implemented vendor command codes are dispatched: `CC_VEND + 0x100`, a command
/// code with a reserved bit next to `V` and `CC_VEND` with a nonzero upper index fail with
/// `TPM_RC_COMMAND_CODE`.
#[test]
fn unimplemented_vendor_codes_are_rejected() {
    let mut sim = Tpm::new();
    for cc in [0x2000_0100u32, 0x6000_0000, 0x2001_0000, 0x1000_0000] {
        let rsp = send_raw(
            &mut sim,
            &build_raw_cmd(ST_NO_SESSIONS, cc, &[], None, &tpm2b(b"x")),
        );
        assert_eq!(rc(&rsp), RC_COMMAND_CODE, "cc {cc:#x}");
    }
}

/// Parameter encryption works in both directions with an HMAC session
///
/// An unbound, unsalted HMAC session with AES-128-CFB and both `decrypt` and `encrypt` SET
/// encrypts `inputData` in the command and `outputData` in the response (the client helper
/// encrypts and decrypts them and verifies the response HMAC).
#[test]
fn parameter_encryption_in_both_directions() {
    let mut sim = Tpm::new();
    for attributes in [
        TpmaSession::DECRYPT,
        TpmaSession::ENCRYPT,
        TpmaSession::DECRYPT | TpmaSession::ENCRYPT,
    ] {
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
        session.attributes = attributes;
        let cmd = VendorTcgTest {
            input_data: Tpm2bData::from_bytes(b"secret vendor data").unwrap(),
        };
        let rsp = execute_with_hmac_sessions(&mut sim, &cmd, &[], &mut [session], &[&[]]).unwrap();
        assert_eq!(rsp.output_data.get_buffer(), b"secret vendor data");
    }
}

/// The command can be executed in an audit session
///
/// An HMAC session with `audit` SET (and no handle to authorize) is accepted; the response
/// carries the audit session's HMAC, which the client helper verifies.
#[test]
fn audit_session_is_accepted() {
    let mut sim = Tpm::new();
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
    session.attributes = TpmaSession::AUDIT | TpmaSession::CONTINUE_SESSION;
    let cmd = VendorTcgTest {
        input_data: Tpm2bData::from_bytes(b"audited").unwrap(),
    };
    let rsp = execute_with_hmac_sessions(&mut sim, &cmd, &[], &mut [session], &[&[]]).unwrap();
    assert_eq!(rsp.output_data.get_buffer(), b"audited");
}

/// Command audit of the vendor command extends the audit digest with its vendor command code
///
/// `TPM2_SetCommandCodeAuditStatus` adds `TPM_CC_Vendor_TCG_Test` to the audit list
/// (`TPM_CAP_AUDIT_COMMANDS` lists it after the library commands). Executing it then extends
/// the audit digest with `cpHash = H(0x20000000 || inputData)` and
/// `rpHash = H(TPM_RC_SUCCESS || 0x20000000 || outputData)`, and the command digest of
/// `TPM2_GetCommandAuditDigest` covers `0x00000140 || 0x20000000`. Removing it again
/// restores the default list.
#[test]
fn command_audit_covers_vendor_command() {
    let mut sim = Tpm::new();
    assert_eq!(
        set_command_code_audit_status(
            &mut sim,
            Handle::RH_OWNER.0,
            ALG_NULL,
            &[CC_VENDOR_TCG_TEST],
            &[]
        ),
        0
    );
    assert_eq!(
        audit_commands(&mut sim, 0, 254),
        (
            false,
            vec![CC_SET_COMMAND_CODE_AUDIT_STATUS, CC_VENDOR_TCG_TEST]
        )
    );
    let start = command_audit_report(&mut sim);

    let params = tpm2b(b"audit me");
    let rsp = vendor_tcg_test_raw(&mut sim, &params);
    assert_eq!(rc(&rsp), 0);

    let alg: TpmiAlgHash = STRONGEST_HASH_ALG;
    let cc = CC_VENDOR_TCG_TEST.to_be_bytes();
    let cp_hash = hash_parts(alg, &[&cc, &params]);
    let rp_hash = hash_parts(alg, &[&0u32.to_be_bytes(), &cc, &rsp[10..]]);
    let report = command_audit_report(&mut sim);
    assert_eq!(report.audit_counter, start.audit_counter);
    assert_eq!(
        report.audit_digest,
        hash_parts(alg, &[&start.audit_digest, &cp_hash, &rp_hash])
    );
    assert_eq!(
        report.command_digest,
        hash_parts(alg, &[&CC_SET_COMMAND_CODE_AUDIT_STATUS.to_be_bytes(), &cc])
    );

    assert_eq!(
        set_command_code_audit_status(
            &mut sim,
            Handle::RH_OWNER.0,
            ALG_NULL,
            &[],
            &[CC_VENDOR_TCG_TEST]
        ),
        0
    );
    assert_eq!(
        audit_commands(&mut sim, 0, 254),
        (false, vec![CC_SET_COMMAND_CODE_AUDIT_STATUS])
    );
}

/// TPM2_PolicyCommandCode accepts the vendor command code
///
/// `TPM_CC_Vendor_TCG_Test` is an implemented command, so a policy session can be bound to
/// it; an unimplemented vendor code (`CC_VEND + 0x100`) fails with `TPM_RC_POLICY_CC + P1`.
#[test]
fn policy_command_code_accepts_vendor_command() {
    let mut sim = Tpm::new();
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let handle = session.session_handle.0;
    for (code, expected) in [(0x2000_0100u32, RC_POLICY_CC + P1), (CC_VENDOR_TCG_TEST, 0)] {
        let rsp = send_raw(
            &mut sim,
            &build_raw_cmd(
                ST_NO_SESSIONS,
                CC_POLICY_COMMAND_CODE,
                &[handle],
                None,
                &code.to_be_bytes(),
            ),
        );
        assert_eq!(rc(&rsp), expected, "code {code:#x}");
    }
}
