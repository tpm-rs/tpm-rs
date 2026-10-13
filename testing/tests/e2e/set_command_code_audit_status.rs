//! TPM2_SetCommandCodeAuditStatus and command audit: the manufacture-default audit list,
//! adding and removing commands (`setList`/`clearList`), changing the audit hash algorithm,
//! the authorization and NV requirements, `TPM2_GetCapability(TPM_CAP_AUDIT_COMMANDS)` and
//! `TPM_CAP_COMMANDS`, and the command audit digest reported by `TPM2_GetCommandAuditDigest`
//! after audited commands run (with and without parameter encryption), across `TPM2_Clear`,
//! signed audit reports and power cycles.

use crate::_common::{
    ALG_SHA1, CLIENT_CRYPTO, RC_AUTH_MISSING, RC_BAD_AUTH_S1, RC_NV_UNAVAILABLE, RC_VALUE_H1,
    RC_VALUE_P1, ST_NO_SESSIONS, ST_SESSIONS, aes_cfb, audit_commands, build_pw_cmd, build_raw_cmd,
    command_audit_report, create_primary, get_ecc_signing_key_template, hash_parts, hmac_sha256,
    kdfa_by_alg, nv_off, nv_on, parse_command_audit_report, power_cycle, power_cycle_with,
    send_raw, send_rc, set_command_code_audit_status, start_auth_session,
};
use testing::tpm::Tpm;
use tpm2::{Handle, TpmSe, TpmiAlgHash, TpmtSymDefObject};

const CC_SET_COMMAND_CODE_AUDIT_STATUS: u32 = 0x140;
const CC_GET_RANDOM: u32 = 0x17B;
const CC_PCR_READ: u32 = 0x17E;
const CC_PCR_EVENT: u32 = 0x13C;
const CC_STARTUP: u32 = 0x144;
const CC_SHUTDOWN: u32 = 0x145;
const CC_SET_ALGORITHM_SET: u32 = 0x13F;
const CC_CLEAR: u32 = 0x126;
const CC_GET_COMMAND_AUDIT_DIGEST: u32 = 0x133;
const CC_HASH: u32 = 0x17D;
/// `TPM_RC_HASH + TPM_RC_P + TPM_RC_1`.
const RC_HASH_P1: u32 = 0x1C3;
/// `TPM2_GetCommandAuditDigest` parameters: empty `qualifyingData`, `inScheme` =
/// ECDSA/SHA-256.
const ECDSA_SHA256_AUDIT_PARAMS: [u8; 6] = [0, 0, 0, 0x18, 0, 0x0B];
const ALG_SHA256: u16 = 0x000B;
const ALG_SHA512: u16 = 0x000D;
const ALG_NULL: u16 = 0x0010;
const TPM_SU_CLEAR: u16 = 0x0000;
const TPM_SU_STATE: u16 = 0x0001;
const OWNER: u32 = Handle::RH_OWNER.0;
const PLATFORM: u32 = Handle::RH_PLATFORM.0;

/// The digest of a list of audited commands (`commandDigest`): the hash of their big-endian
/// command codes in ascending order.
fn command_list_digest(alg: TpmiAlgHash, commands: &[u32]) -> Vec<u8> {
    let codes: Vec<[u8; 4]> = commands.iter().map(|cc| cc.to_be_bytes()).collect();
    let parts: Vec<&[u8]> = codes.iter().map(|c| &c[..]).collect();
    hash_parts(alg, &parts)
}

/// Extends `digest` by one audited command: `H(digest || cpHash || rpHash)` with
/// `cpHash = H(cc || names || parameters)` and `rpHash = H(TPM_RC_SUCCESS || cc || parameters)`.
fn extend_audit_digest(
    alg: TpmiAlgHash,
    digest: &[u8],
    cc: u32,
    names: &[&[u8]],
    cp_params: &[u8],
    rp_params: &[u8],
) -> Vec<u8> {
    let cc_bytes = cc.to_be_bytes();
    let mut cp_parts: Vec<&[u8]> = vec![&cc_bytes];
    cp_parts.extend_from_slice(names);
    cp_parts.push(cp_params);
    let cp_hash = hash_parts(alg, &cp_parts);
    let rp_hash = hash_parts(alg, &[&0u32.to_be_bytes(), &cc_bytes, rp_params]);
    hash_parts(alg, &[digest, &cp_hash, &rp_hash])
}

/// Executes `TPM2_GetRandom(8)` without sessions and returns `(command parameters, response
/// parameters)`.
fn get_random(sim: &mut Tpm) -> (Vec<u8>, Vec<u8>) {
    let params = 8u16.to_be_bytes().to_vec();
    let rsp = send_raw(
        sim,
        &build_raw_cmd(ST_NO_SESSIONS, CC_GET_RANDOM, &[], None, &params),
    );
    assert_eq!(&rsp[6..10], &[0, 0, 0, 0], "GetRandom failed");
    (params, rsp[10..].to_vec())
}

/// `TPM2_SetCommandCodeAuditStatus(TPM_RH_OWNER, TPM_ALG_NULL, setList, clearList)`
/// parameters (to compute the expected audit cpHash).
fn audit_status_params(audit_alg: u16, set_list: &[u32], clear_list: &[u32]) -> Vec<u8> {
    let mut params = audit_alg.to_be_bytes().to_vec();
    for list in [set_list, clear_list] {
        params.extend_from_slice(&(list.len() as u32).to_be_bytes());
        for cc in list {
            params.extend_from_slice(&cc.to_be_bytes());
        }
    }
    params
}

/// A fresh TPM audits only TPM2_SetCommandCodeAuditStatus, with SHA-512, no audit log
///
/// At manufacture only `TPM2_SetCommandCodeAuditStatus` is audited
/// (`TPM_CAP_AUDIT_COMMANDS` lists exactly `0x140`), the audit hash algorithm is SHA-512, the
/// audit counter is zero and the audit digest is empty; `commandDigest` is the SHA-512 of
/// `0x00000140`.
#[test]
fn manufacture_default_audits_only_set_command_code_audit_status() {
    let mut sim = Tpm::new();
    assert_eq!(
        audit_commands(&mut sim, 0, 254),
        (false, vec![CC_SET_COMMAND_CODE_AUDIT_STATUS])
    );
    let report = command_audit_report(&mut sim);
    assert_eq!(report.digest_alg, ALG_SHA512);
    assert_eq!(report.audit_counter, 0);
    assert!(report.audit_digest.is_empty());
    assert_eq!(
        report.command_digest,
        command_list_digest(TpmiAlgHash::Sha512, &[CC_SET_COMMAND_CODE_AUDIT_STATUS])
    );
}

/// setList adds commands, clearList removes them, 0x140 can never be removed
///
/// Commands in `setList` are added to the audit list and commands in `clearList` are removed;
/// `TPM_CC_SetCommandCodeAuditStatus` in `clearList` is ignored. `commandDigest` follows the
/// list.
#[test]
fn set_list_adds_and_clear_list_removes_commands() {
    let mut sim = Tpm::new();
    assert_eq!(
        set_command_code_audit_status(
            &mut sim,
            OWNER,
            ALG_NULL,
            &[CC_PCR_READ, CC_GET_RANDOM],
            &[]
        ),
        0
    );
    assert_eq!(
        audit_commands(&mut sim, 0, 254).1,
        [CC_SET_COMMAND_CODE_AUDIT_STATUS, CC_GET_RANDOM, CC_PCR_READ]
    );

    assert_eq!(
        set_command_code_audit_status(
            &mut sim,
            OWNER,
            ALG_NULL,
            &[],
            &[CC_GET_RANDOM, CC_SET_COMMAND_CODE_AUDIT_STATUS]
        ),
        0
    );
    let expected = [CC_SET_COMMAND_CODE_AUDIT_STATUS, CC_PCR_READ];
    assert_eq!(audit_commands(&mut sim, 0, 254).1, expected);
    assert_eq!(
        command_audit_report(&mut sim).command_digest,
        command_list_digest(TpmiAlgHash::Sha512, &expected)
    );
}

/// A command in both setList and clearList ends up not audited
///
/// `setList` is processed before `clearList`, so a command named in both lists is not
/// audited afterwards.
#[test]
fn command_in_both_lists_is_not_audited() {
    let mut sim = Tpm::new();
    assert_eq!(
        set_command_code_audit_status(
            &mut sim,
            OWNER,
            ALG_NULL,
            &[CC_GET_RANDOM],
            &[CC_GET_RANDOM]
        ),
        0
    );
    assert_eq!(
        audit_commands(&mut sim, 0, 254).1,
        [CC_SET_COMMAND_CODE_AUDIT_STATUS]
    );
}

/// TPM2_Shutdown and unimplemented command codes are ignored without error
///
/// It is not an error to name `TPM2_Shutdown` (which cannot be audited) or unimplemented
/// command codes in `setList` or `clearList`; they never appear in the audit list.
#[test]
fn shutdown_and_unimplemented_commands_are_ignored() {
    let mut sim = Tpm::new();
    let ignored = [CC_SHUTDOWN, CC_SET_ALGORITHM_SET, 0x1FF, 0x2000_0000];
    assert_eq!(
        set_command_code_audit_status(&mut sim, OWNER, ALG_NULL, &ignored, &ignored),
        0
    );
    assert_eq!(
        set_command_code_audit_status(&mut sim, OWNER, ALG_NULL, &ignored, &[]),
        0
    );
    assert_eq!(
        audit_commands(&mut sim, 0, 254).1,
        [CC_SET_COMMAND_CODE_AUDIT_STATUS]
    );
}

/// Changing auditAlg together with a non-empty list fails with TPM_RC_VALUE on auditAlg
///
/// The algorithm and the command list cannot change in the same command: a new `auditAlg`
/// with a non-empty `setList` or `clearList` fails with `TPM_RC_VALUE + TPM_RC_P + TPM_RC_1`
/// and changes nothing.
#[test]
fn audit_alg_change_with_command_list_is_rejected() {
    let mut sim = Tpm::new();
    assert_eq!(
        set_command_code_audit_status(&mut sim, OWNER, ALG_SHA256, &[CC_GET_RANDOM], &[]),
        RC_VALUE_P1
    );
    assert_eq!(
        set_command_code_audit_status(&mut sim, OWNER, ALG_SHA256, &[], &[CC_PCR_READ]),
        RC_VALUE_P1
    );
    assert_eq!(
        audit_commands(&mut sim, 0, 254).1,
        [CC_SET_COMMAND_CODE_AUDIT_STATUS]
    );
    assert_eq!(command_audit_report(&mut sim).digest_alg, ALG_SHA512);
}

/// auditAlg equal to the current algorithm processes the command lists
///
/// When `auditAlg` names the current audit hash algorithm the algorithm is unchanged and the
/// lists are processed as with `TPM_ALG_NULL`.
#[test]
fn current_audit_alg_processes_command_lists() {
    let mut sim = Tpm::new();
    assert_eq!(
        set_command_code_audit_status(&mut sim, OWNER, ALG_SHA512, &[CC_GET_RANDOM], &[]),
        0
    );
    assert_eq!(
        audit_commands(&mut sim, 0, 254).1,
        [CC_SET_COMMAND_CODE_AUDIT_STATUS, CC_GET_RANDOM]
    );
    let report = command_audit_report(&mut sim);
    assert_eq!(report.digest_alg, ALG_SHA512);
    assert_eq!(report.audit_counter, 1, "the list change was audited");
}

/// Changing auditAlg clears the audit digest and is not audited; the next audit starts a log
///
/// A new `auditAlg` with empty lists changes the algorithm and clears the audit digest
/// without auditing that command (the counter is unchanged). The next audited command starts
/// a new audit log with the new algorithm and increments the audit counter.
#[test]
fn audit_alg_change_clears_digest_without_auditing() {
    let mut sim = Tpm::new();
    // Start an audit log (counter 1) by changing the list.
    assert_eq!(
        set_command_code_audit_status(&mut sim, OWNER, ALG_NULL, &[CC_GET_RANDOM], &[]),
        0
    );
    let report = command_audit_report(&mut sim);
    assert_eq!(report.audit_counter, 1);
    assert_eq!(report.audit_digest.len(), 64);

    assert_eq!(
        set_command_code_audit_status(&mut sim, OWNER, ALG_SHA256, &[], &[]),
        0
    );
    let report = command_audit_report(&mut sim);
    assert_eq!(report.digest_alg, ALG_SHA256);
    assert_eq!(report.audit_counter, 1);
    assert!(report.audit_digest.is_empty());
    assert_eq!(
        report.command_digest,
        command_list_digest(
            TpmiAlgHash::Sha256,
            &[CC_SET_COMMAND_CODE_AUDIT_STATUS, CC_GET_RANDOM]
        )
    );

    // The next audited command starts a SHA-256 audit log.
    let (cp, rp) = get_random(&mut sim);
    let report = command_audit_report(&mut sim);
    assert_eq!(report.audit_counter, 2);
    assert_eq!(
        report.audit_digest,
        extend_audit_digest(TpmiAlgHash::Sha256, &[0; 32], CC_GET_RANDOM, &[], &cp, &rp)
    );
}

/// Audited commands extend the audit digest with their cpHash and rpHash
///
/// The audit digest starts as zeros when the first audited command (the
/// `TPM2_SetCommandCodeAuditStatus` that adds `TPM2_GetRandom`) completes and is then extended
/// as `H(digest || cpHash || rpHash)` by each audited command; commands that are not audited
/// (`TPM2_PCR_Read`, `TPM2_GetCommandAuditDigest`) leave it unchanged.
#[test]
fn audited_commands_extend_audit_digest() {
    let mut sim = Tpm::new();
    let alg = TpmiAlgHash::Sha512;
    let set_params = audit_status_params(ALG_NULL, &[CC_GET_RANDOM], &[]);
    let rsp = send_raw(
        &mut sim,
        &build_pw_cmd(CC_SET_COMMAND_CODE_AUDIT_STATUS, &[OWNER], 1, &set_params),
    );
    assert_eq!(&rsp[6..10], &[0, 0, 0, 0]);
    let owner_name = OWNER.to_be_bytes();
    let mut expected = extend_audit_digest(
        alg,
        &[0; 64],
        CC_SET_COMMAND_CODE_AUDIT_STATUS,
        &[&owner_name],
        &set_params,
        &[],
    );
    assert_eq!(command_audit_report(&mut sim).audit_digest, expected);

    // An unaudited command does not change the digest.
    let pcr_read = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_PCR_READ,
        &[],
        None,
        &[0, 0, 0, 1, 0, 0x0B, 3, 1, 0, 0],
    );
    assert_eq!(send_rc(&mut sim, &pcr_read), 0);
    assert_eq!(command_audit_report(&mut sim).audit_digest, expected);

    for _ in 0..2 {
        let (cp, rp) = get_random(&mut sim);
        expected = extend_audit_digest(alg, &expected, CC_GET_RANDOM, &[], &cp, &rp);
    }
    let report = command_audit_report(&mut sim);
    assert_eq!(report.audit_counter, 1, "one audit log");
    assert_eq!(report.audit_digest, expected);
}

/// An audited command with a session hashes handle Names and only the parameter areas
///
/// For an audited command sent with a session (`TPM2_PCR_Event` on PCR 16) the `cpHash`
/// covers the command code, the Name of the PCR handle and the parameters, and the `rpHash`
/// covers only the response parameter area (not `parameterSize` or the authorization area).
#[test]
fn audited_session_command_hashes_names_and_parameter_areas() {
    let mut sim = Tpm::new();
    let alg = TpmiAlgHash::Sha512;
    assert_eq!(
        set_command_code_audit_status(&mut sim, OWNER, ALG_NULL, &[CC_PCR_EVENT], &[]),
        0
    );
    let before = command_audit_report(&mut sim).audit_digest;

    let pcr: u32 = 16;
    let params = [0, 3, b'a', b'b', b'c'];
    let rsp = send_raw(&mut sim, &build_pw_cmd(CC_PCR_EVENT, &[pcr], 1, &params));
    assert_eq!(&rsp[6..10], &[0, 0, 0, 0]);
    let param_size = u32::from_be_bytes(rsp[10..14].try_into().unwrap()) as usize;
    let rp = &rsp[14..14 + param_size];
    assert_eq!(
        command_audit_report(&mut sim).audit_digest,
        extend_audit_digest(
            alg,
            &before,
            CC_PCR_EVENT,
            &[&pcr.to_be_bytes()],
            &params,
            rp
        )
    );
}

/// Platform authorization is accepted; endorsement and lockout handles are TPM_RC_VALUE
///
/// `auth` is a `TPMI_RH_PROVISION`: `TPM_RH_PLATFORM` works like `TPM_RH_OWNER`, while
/// `TPM_RH_ENDORSEMENT` and `TPM_RH_LOCKOUT` fail with `TPM_RC_VALUE + TPM_RC_H + TPM_RC_1`.
#[test]
fn platform_or_owner_authorization_is_required() {
    let mut sim = Tpm::new();
    assert_eq!(
        set_command_code_audit_status(&mut sim, PLATFORM, ALG_NULL, &[CC_PCR_READ], &[]),
        0
    );
    for handle in [Handle::RH_ENDORSEMENT.0, Handle::RH_LOCKOUT.0] {
        assert_eq!(
            set_command_code_audit_status(&mut sim, handle, ALG_NULL, &[CC_GET_RANDOM], &[]),
            RC_VALUE_H1,
            "auth {handle:#x}"
        );
    }
    assert_eq!(
        audit_commands(&mut sim, 0, 254).1,
        [CC_SET_COMMAND_CODE_AUDIT_STATUS, CC_PCR_READ]
    );
}

/// Missing or wrong authorization fails and leaves the audit list unchanged
///
/// Without a session the command fails with `TPM_RC_AUTH_MISSING`; with a wrong owner
/// password it fails with `TPM_RC_BAD_AUTH` on session 1. Neither changes the audit list or
/// the audit digest.
#[test]
fn missing_or_wrong_authorization_is_rejected() {
    let mut sim = Tpm::new();
    let params = audit_status_params(ALG_NULL, &[CC_GET_RANDOM], &[]);
    let no_session = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_SET_COMMAND_CODE_AUDIT_STATUS,
        &[OWNER],
        None,
        &params,
    );
    assert_eq!(send_rc(&mut sim, &no_session), RC_AUTH_MISSING);

    // TPM_RS_PW, empty nonce, continueSession, password "x".
    let wrong_password = [0x40, 0, 0, 9, 0, 0, 1, 0, 1, b'x'];
    let bad_auth = build_raw_cmd(
        ST_SESSIONS,
        CC_SET_COMMAND_CODE_AUDIT_STATUS,
        &[OWNER],
        Some(&wrong_password),
        &params,
    );
    assert_eq!(send_rc(&mut sim, &bad_auth), RC_BAD_AUTH_S1);

    assert_eq!(
        audit_commands(&mut sim, 0, 254).1,
        [CC_SET_COMMAND_CODE_AUDIT_STATUS]
    );
    assert!(command_audit_report(&mut sim).audit_digest.is_empty());
}

/// Audited commands need NV while a new audit log would start
///
/// While NV is unavailable `TPM2_SetCommandCodeAuditStatus` fails with
/// `TPM_RC_NV_UNAVAILABLE`, and so does an audited command when the audit digest is empty
/// (its audit would increment the persistent audit counter). Once an audit log is in
/// progress, audited commands that do not write NV succeed without NV.
#[test]
fn audited_commands_require_nv_to_start_an_audit_log() {
    let mut sim = Tpm::new();
    nv_off(&mut sim);
    assert_eq!(
        set_command_code_audit_status(&mut sim, OWNER, ALG_NULL, &[CC_GET_RANDOM], &[]),
        RC_NV_UNAVAILABLE
    );
    nv_on(&mut sim);
    assert_eq!(
        set_command_code_audit_status(&mut sim, PLATFORM, ALG_SHA256, &[], &[]),
        0
    );
    assert_eq!(
        set_command_code_audit_status(&mut sim, OWNER, ALG_NULL, &[CC_GET_RANDOM], &[]),
        0
    );
    // Clear the digest again by changing the algorithm back.
    assert_eq!(
        set_command_code_audit_status(&mut sim, OWNER, ALG_SHA512, &[], &[]),
        0
    );

    let get_random = build_raw_cmd(ST_NO_SESSIONS, CC_GET_RANDOM, &[], None, &[0, 8]);
    nv_off(&mut sim);
    assert_eq!(send_rc(&mut sim, &get_random), RC_NV_UNAVAILABLE);
    nv_on(&mut sim);
    assert_eq!(send_rc(&mut sim, &get_random), 0);
    nv_off(&mut sim);
    assert_eq!(send_rc(&mut sim, &get_random), 0);
    nv_on(&mut sim);
    let report = command_audit_report(&mut sim);
    assert_eq!(report.audit_counter, 2);
}

/// TPM_CAP_AUDIT_COMMANDS starts at property and honours propertyCount and moreData
///
/// `TPM2_GetCapability(TPM_CAP_AUDIT_COMMANDS)` lists the audited commands with a command
/// code of at least `property` in ascending order, at most `propertyCount` of them, and
/// reports `moreData` when further audited commands follow.
#[test]
fn capability_audit_commands_pagination() {
    let mut sim = Tpm::new();
    assert_eq!(
        set_command_code_audit_status(
            &mut sim,
            OWNER,
            ALG_NULL,
            &[CC_PCR_READ, CC_STARTUP, CC_GET_RANDOM],
            &[]
        ),
        0
    );
    assert_eq!(
        audit_commands(&mut sim, 0, 2),
        (true, vec![CC_SET_COMMAND_CODE_AUDIT_STATUS, CC_STARTUP])
    );
    assert_eq!(audit_commands(&mut sim, 0x141, 1), (true, vec![CC_STARTUP]));
    assert_eq!(
        audit_commands(&mut sim, 0x17C, 10),
        (false, vec![CC_PCR_READ])
    );
    assert_eq!(audit_commands(&mut sim, 0, 0), (true, vec![]));
    assert_eq!(audit_commands(&mut sim, 0x17F, 10), (false, vec![]));
    assert_eq!(audit_commands(&mut sim, 0x2000_0000, 10), (false, vec![]));
}

/// TPM_CAP_COMMANDS lists TPM2_SetCommandCodeAuditStatus with its attributes
///
/// The command is implemented: `TPM_CAP_COMMANDS` reports its `TPMA_CC` (`commandIndex`
/// 0x140, `nv`, one handle) and the implemented-command counts include it.
#[test]
fn capability_commands_lists_set_command_code_audit_status() {
    let mut sim = Tpm::new();
    let mut params = 2u32.to_be_bytes().to_vec();
    params.extend_from_slice(&CC_SET_COMMAND_CODE_AUDIT_STATUS.to_be_bytes());
    params.extend_from_slice(&1u32.to_be_bytes());
    let rsp = send_raw(
        &mut sim,
        &build_raw_cmd(ST_NO_SESSIONS, 0x17A, &[], None, &params),
    );
    assert_eq!(&rsp[6..10], &[0, 0, 0, 0]);
    // moreData, capability, count, TPMA_CC.
    assert_eq!(&rsp[11..19], &[0, 0, 0, 2, 0, 0, 0, 1]);
    assert_eq!(
        u32::from_be_bytes(rsp[19..23].try_into().unwrap()),
        0x0240_0140
    );
}

/// The audit digest survives TPM Restart and is cleared by TPM Reset
///
/// `TPM2_Shutdown(TPM_SU_STATE)` saves the audit digest, so it is unchanged after a TPM
/// Restart; a TPM Reset clears it. The audit list and counter are persistent.
#[test]
fn audit_digest_survives_restart_and_clears_on_reset() {
    let mut sim = Tpm::new();
    assert_eq!(
        set_command_code_audit_status(&mut sim, OWNER, ALG_NULL, &[CC_GET_RANDOM], &[]),
        0
    );
    get_random(&mut sim);
    let before = command_audit_report(&mut sim);
    assert_eq!(before.audit_counter, 1);

    assert_eq!(
        power_cycle_with(&mut sim, Some(TPM_SU_STATE), TPM_SU_CLEAR),
        0
    );
    assert_eq!(command_audit_report(&mut sim), before, "TPM Restart");

    assert_eq!(
        power_cycle_with(&mut sim, Some(TPM_SU_CLEAR), TPM_SU_CLEAR),
        0
    );
    let after = command_audit_report(&mut sim);
    assert!(after.audit_digest.is_empty(), "TPM Reset");
    assert_eq!(after.audit_counter, 1);
    assert_eq!(after.command_digest, before.command_digest);
}

/// The audit list, algorithm and counter persist across an unorderly power cycle
///
/// `gp.auditCommands`, `gp.auditHashAlg` and `gp.auditCounter` are persistent: they survive a
/// power loss followed by a TPM Reset.
#[test]
fn audit_configuration_persists_across_power_loss() {
    let mut sim = Tpm::new();
    assert_eq!(
        set_command_code_audit_status(&mut sim, OWNER, ALG_NULL, &[CC_PCR_READ], &[]),
        0
    );
    assert_eq!(
        set_command_code_audit_status(&mut sim, OWNER, ALG_SHA1, &[], &[]),
        0
    );
    assert_eq!(
        set_command_code_audit_status(&mut sim, OWNER, ALG_NULL, &[CC_GET_RANDOM], &[]),
        0
    );

    power_cycle(&mut sim);
    assert_eq!(
        crate::_common::startup(&mut sim, TPM_SU_CLEAR),
        0,
        "TPM2_Startup failed"
    );
    assert_eq!(
        audit_commands(&mut sim, 0, 254).1,
        [CC_SET_COMMAND_CODE_AUDIT_STATUS, CC_GET_RANDOM, CC_PCR_READ]
    );
    let report = command_audit_report(&mut sim);
    assert_eq!(report.digest_alg, ALG_SHA1);
    assert_eq!(report.audit_counter, 2, "two audit logs were started");
    assert!(report.audit_digest.is_empty());
}

/// TPM2_Clear resets the audit counter but keeps the audit list and algorithm
///
/// The audit counter is reset to zero by `TPM2_Clear` while `gp.auditCommands` and
/// `gp.auditHashAlg` are unchanged; the next audit log then starts at counter 1.
#[test]
fn clear_resets_audit_counter_only() {
    let mut sim = Tpm::new();
    assert_eq!(
        set_command_code_audit_status(&mut sim, OWNER, ALG_NULL, &[CC_GET_RANDOM], &[]),
        0
    );
    // Clear the digest so that the next audited command starts a new log.
    assert_eq!(
        set_command_code_audit_status(&mut sim, OWNER, ALG_SHA256, &[], &[]),
        0
    );
    assert_eq!(command_audit_report(&mut sim).audit_counter, 1);

    assert_eq!(
        send_rc(&mut sim, &build_pw_cmd(CC_CLEAR, &[PLATFORM], 1, &[])),
        0
    );
    let report = command_audit_report(&mut sim);
    assert_eq!(report.audit_counter, 0);
    assert_eq!(report.digest_alg, ALG_SHA256);
    assert!(report.audit_digest.is_empty());
    assert_eq!(
        audit_commands(&mut sim, 0, 254).1,
        [CC_SET_COMMAND_CODE_AUDIT_STATUS, CC_GET_RANDOM]
    );

    get_random(&mut sim);
    assert_eq!(command_audit_report(&mut sim).audit_counter, 1);
}

/// A signed TPM2_GetCommandAuditDigest ends the audit log
///
/// `TPM2_GetCommandAuditDigest` with a signing key (not `TPM_RH_NULL`) reports the current
/// digest and then clears it, so the next audited command starts a new audit log from a
/// zero digest and increments the audit counter.
#[test]
fn signed_get_command_audit_digest_ends_audit_log() {
    let mut sim = Tpm::new();
    let (key, _) = create_primary(&mut sim, get_ecc_signing_key_template());
    assert_eq!(
        set_command_code_audit_status(&mut sim, OWNER, ALG_NULL, &[CC_GET_RANDOM], &[]),
        0
    );
    get_random(&mut sim);
    let before = command_audit_report(&mut sim);
    assert_eq!(before.audit_counter, 1);

    let rsp = send_raw(
        &mut sim,
        &build_pw_cmd(
            CC_GET_COMMAND_AUDIT_DIGEST,
            &[Handle::RH_ENDORSEMENT.0, key.0],
            2,
            &ECDSA_SHA256_AUDIT_PARAMS,
        ),
    );
    assert_eq!(
        &rsp[6..10],
        &[0, 0, 0, 0],
        "signed GetCommandAuditDigest failed"
    );
    assert_eq!(parse_command_audit_report(&rsp), before);
    assert!(command_audit_report(&mut sim).audit_digest.is_empty());

    let (cp, rp) = get_random(&mut sim);
    let report = command_audit_report(&mut sim);
    assert_eq!(report.audit_counter, 2);
    assert_eq!(
        report.audit_digest,
        extend_audit_digest(TpmiAlgHash::Sha512, &[0; 64], CC_GET_RANDOM, &[], &cp, &rp)
    );
}

/// An audited TPM2_GetCommandAuditDigest needs NV and audits itself after its reset
///
/// When `TPM2_GetCommandAuditDigest` is audited it fails with `TPM_RC_NV_UNAVAILABLE` while
/// NV is unavailable even if an audit log is in progress. Each execution reports the digest
/// before its own audit; an unsigned one then extends the digest, and a signed one clears the
/// digest first, so its own audit starts a new log.
#[test]
fn audited_get_command_audit_digest_needs_nv_and_audits_itself() {
    let mut sim = Tpm::new();
    let alg = TpmiAlgHash::Sha512;
    let (key, key_name) = create_primary(&mut sim, get_ecc_signing_key_template());
    assert_eq!(
        set_command_code_audit_status(
            &mut sim,
            OWNER,
            ALG_NULL,
            &[CC_GET_COMMAND_AUDIT_DIGEST],
            &[]
        ),
        0
    );
    let endorsement = Handle::RH_ENDORSEMENT.0.to_be_bytes();
    let null = Handle::RH_NULL.0.to_be_bytes();
    let unsigned_params = [0, 0, 0, 0x10];
    let unsigned = build_pw_cmd(
        CC_GET_COMMAND_AUDIT_DIGEST,
        &[Handle::RH_ENDORSEMENT.0, Handle::RH_NULL.0],
        2,
        &unsigned_params,
    );

    // Unsigned: reports d1, then extends it with its own execution.
    let rsp = send_raw(&mut sim, &unsigned);
    assert_eq!(&rsp[6..10], &[0, 0, 0, 0]);
    let d1 = parse_command_audit_report(&rsp);
    assert_eq!(d1.audit_counter, 1);
    let param_size = u32::from_be_bytes(rsp[10..14].try_into().unwrap()) as usize;
    let d2 = extend_audit_digest(
        alg,
        &d1.audit_digest,
        CC_GET_COMMAND_AUDIT_DIGEST,
        &[&endorsement, &null],
        &unsigned_params,
        &rsp[14..14 + param_size],
    );

    // NV is needed although an audit log is in progress.
    nv_off(&mut sim);
    assert_eq!(send_rc(&mut sim, &unsigned), RC_NV_UNAVAILABLE);
    nv_on(&mut sim);

    // Signed: reports d2, clears the digest, and its own audit starts log 2.
    let rsp = send_raw(
        &mut sim,
        &build_pw_cmd(
            CC_GET_COMMAND_AUDIT_DIGEST,
            &[Handle::RH_ENDORSEMENT.0, key.0],
            2,
            &ECDSA_SHA256_AUDIT_PARAMS,
        ),
    );
    assert_eq!(&rsp[6..10], &[0, 0, 0, 0]);
    let report = parse_command_audit_report(&rsp);
    assert_eq!(report.audit_digest, d2);
    assert_eq!(report.audit_counter, 1);
    let param_size = u32::from_be_bytes(rsp[10..14].try_into().unwrap()) as usize;
    let d3 = extend_audit_digest(
        alg,
        &[0; 64],
        CC_GET_COMMAND_AUDIT_DIGEST,
        &[&endorsement, &key_name],
        &ECDSA_SHA256_AUDIT_PARAMS,
        &rsp[14..14 + param_size],
    );

    let rsp = send_raw(&mut sim, &unsigned);
    assert_eq!(&rsp[6..10], &[0, 0, 0, 0]);
    let report = parse_command_audit_report(&rsp);
    assert_eq!(report.audit_counter, 2);
    assert_eq!(report.audit_digest, d3);
}

/// An audited command with parameter encryption hashes the parameters as sent
///
/// For an audited `TPM2_Hash` with a decrypt+encrypt session, the audit `cpHash` covers the
/// encrypted `data` parameter and the `rpHash` covers the encrypted `outHash`, i.e. both
/// parameter areas exactly as they appear on the wire.
#[test]
fn audited_command_with_parameter_encryption_hashes_ciphertext() {
    let mut sim = Tpm::new();
    assert_eq!(
        set_command_code_audit_status(&mut sim, OWNER, ALG_NULL, &[CC_HASH], &[]),
        0
    );
    let before = command_audit_report(&mut sim).audit_digest;

    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::aes_cfb(128).unwrap()),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let nonce_tpm = session.nonce_tpm.get_buffer().to_vec();
    let nonce_caller = [0x5Au8; 16];
    // Unbound, unsalted: no session key; the session authorizes no handle.
    let cfb_key = |newer: &[u8], older: &[u8]| {
        let mut k = [0u8; 32];
        kdfa_by_alg(
            CLIENT_CRYPTO,
            TpmiAlgHash::Sha256,
            &session.session_key,
            b"CFB",
            newer,
            older,
            256,
            &mut k,
        );
        k
    };

    let plaintext = b"audited parameter encryption";
    let mut data = plaintext.to_vec();
    let k = cfb_key(&nonce_caller, &nonce_tpm);
    aes_cfb(&k[..16], k[16..].try_into().unwrap(), &mut data, true);
    let mut params = (data.len() as u16).to_be_bytes().to_vec();
    params.extend_from_slice(&data);
    params.extend_from_slice(&ALG_SHA256.to_be_bytes());
    params.extend_from_slice(&Handle::RH_NULL.0.to_be_bytes());

    // continueSession | decrypt | encrypt
    let attrs = 0x61u8;
    let cp_hash = hash_parts(TpmiAlgHash::Sha256, &[&CC_HASH.to_be_bytes(), &params]);
    let hmac = hmac_sha256(
        &session.session_key,
        &[&cp_hash, &nonce_caller, &nonce_tpm, &[attrs]],
    );
    let mut area = session.session_handle.0.to_be_bytes().to_vec();
    area.extend_from_slice(&(nonce_caller.len() as u16).to_be_bytes());
    area.extend_from_slice(&nonce_caller);
    area.push(attrs);
    area.extend_from_slice(&(hmac.len() as u16).to_be_bytes());
    area.extend_from_slice(&hmac);

    let rsp = send_raw(
        &mut sim,
        &build_raw_cmd(ST_SESSIONS, CC_HASH, &[], Some(&area), &params),
    );
    assert_eq!(&rsp[6..10], &[0, 0, 0, 0], "TPM2_Hash failed");
    let param_size = u32::from_be_bytes(rsp[10..14].try_into().unwrap()) as usize;
    let rp = &rsp[14..14 + param_size];
    let at = 14 + param_size;
    let nonce_len = u16::from_be_bytes(rsp[at..at + 2].try_into().unwrap()) as usize;
    let new_nonce_tpm = &rsp[at + 2..at + 2 + nonce_len];

    // The response outHash is encrypted and decrypts to the digest of the plaintext.
    let mut out_hash = rp[2..34].to_vec();
    let k = cfb_key(new_nonce_tpm, &nonce_caller);
    aes_cfb(&k[..16], k[16..].try_into().unwrap(), &mut out_hash, false);
    assert_eq!(out_hash, hash_parts(TpmiAlgHash::Sha256, &[plaintext]));
    assert_ne!(&rp[2..34], &out_hash[..]);

    assert_eq!(
        command_audit_report(&mut sim).audit_digest,
        extend_audit_digest(TpmiAlgHash::Sha512, &before, CC_HASH, &[], &params, rp)
    );
}

/// An unsupported or unimplemented auditAlg is TPM_RC_HASH on auditAlg
///
/// `auditAlg` is a `TPMI_ALG_HASH+`: a non-hash algorithm (`TPM_ALG_RSA`) or a hash this TPM
/// does not implement (`TPM_ALG_SM3_256`) fails with `TPM_RC_HASH + TPM_RC_P + TPM_RC_1` and
/// changes nothing.
#[test]
fn unsupported_audit_alg_is_hash_error() {
    let mut sim = Tpm::new();
    for alg in [0x0001, 0x0012] {
        assert_eq!(
            set_command_code_audit_status(&mut sim, OWNER, alg, &[], &[]),
            RC_HASH_P1,
            "auditAlg {alg:#06x}"
        );
        assert_eq!(
            set_command_code_audit_status(&mut sim, OWNER, alg, &[CC_GET_RANDOM], &[]),
            RC_HASH_P1,
            "auditAlg {alg:#06x} with setList"
        );
    }
    let report = command_audit_report(&mut sim);
    assert_eq!(report.digest_alg, ALG_SHA512);
    assert_eq!(report.audit_counter, 0);
    assert!(report.audit_digest.is_empty());
    assert_eq!(
        audit_commands(&mut sim, 0, 254).1,
        [CC_SET_COMMAND_CODE_AUDIT_STATUS]
    );
}
