//! TPM2_SelfTest, TPM2_IncrementalSelfTest and TPM2_GetTestResult.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::responses::{
    GetTestResult as GetTestResultRsp, IncrementalSelfTest as IncrementalSelfTestRsp,
};
use tpm2::commands::*;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Unmarshal, *};

/// IncrementalSelfTest, SelfTest and GetTestResult succeed; a reserved alg fails with VALUE + P1 or SIZE with trailing bytes.
#[test]
fn all_commands_execute() {
    let mut sim = Tpm::new();

    // 1. IncrementalSelfTest
    let inc_cmd = IncrementalSelfTest {
        to_test: TpmlAlg::from_slice(&[Alg::RSA]).unwrap(),
    };
    let (rsp_hdr, params) = send_no_sessions(&mut sim, &inc_cmd);
    assert_eq!(rsp_hdr.rc, Ok(()));
    let mut slice = &params[..];
    let inc_rsp = IncrementalSelfTestRsp::unmarshal_with_handles([], &mut slice).unwrap();
    assert!(slice.is_empty());
    assert!(inc_rsp.to_do_list.count() <= 32);

    // 2. SelfTest
    let st_cmd = SelfTest { full_test: true };
    let (rsp_hdr, params) = send_no_sessions(&mut sim, &st_cmd);
    assert_eq!(rsp_hdr.rc, Ok(()));
    assert!(params.is_empty());

    // 3. GetTestResult
    let gtr_cmd = GetTestResult {};
    let (rsp_hdr, params) = send_no_sessions(&mut sim, &gtr_cmd);
    assert_eq!(rsp_hdr.rc, Ok(()));
    let mut slice = &params[..];
    let gtr_rsp = GetTestResultRsp::unmarshal_with_handles([], &mut slice).unwrap();
    assert!(slice.is_empty());
    assert_eq!(gtr_rsp.test_result, Ok(()));

    // 4. IncrementalSelfTest with reserved Alg ID (0x0000):
    // - Exact buffer -> fails during command execution with VALUE | P | 1
    // - Trailing bytes -> fails during dispatch with SIZE (not VALUE)
    // - Truncated buffer after reserved alg[0] -> fails during unmarshal with INSUFFICIENT
    //   (not VALUE)
    let resp = send(&mut sim, &hex("8001 00000010 00000142 00000001 0000"));
    let rsp_hdr = ResponseHeader::unmarshal(&mut &resp[..]).unwrap();
    assert_eq!(rsp_hdr.rc, Err(TpmRc::VALUE.with(Position::parameter(1))));

    let resp = send(&mut sim, &hex("8001 00000011 00000142 00000001 0000 FF"));
    let rsp_hdr = ResponseHeader::unmarshal(&mut &resp[..]).unwrap();
    assert_eq!(rsp_hdr.rc, Err(TpmRc::SIZE.to_rc()));

    let resp = send(&mut sim, &hex("8001 00000011 00000142 00000002 0000 00"));
    let rsp_hdr = ResponseHeader::unmarshal(&mut &resp[..]).unwrap();
    assert_eq!(
        rsp_hdr.rc,
        Err(TpmRc::INSUFFICIENT.with(Position::parameter(1)))
    );
}

/// IncrementalSelfTest with ALG_NULL fails with VALUE+P1 and does not mutate the to-do list.
#[test]
fn failed_incremental_run_keeps_todo_list() {
    let mut sim = Tpm::new();
    let todo = incremental_self_test(&mut sim, &[]).unwrap();
    assert!(todo.contains(&Alg::RSA));
    assert_eq!(
        incremental_self_test(&mut sim, &[Alg::RSA, Alg::NULL]),
        Err(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
    let todo_after = incremental_self_test(&mut sim, &[]).unwrap();
    assert_eq!(
        todo, todo_after,
        "failed IncrementalSelfTest mutated the to-do list"
    );
}

/// IncrementalSelfTest with TPM_ALG_ERROR fails with TPM_RC_VALUE + P1 (TC2_0_12_03_02).
///
/// Regression test for CPCTPM_TC2_0_12_03_02:
/// TPM2_IncrementalSelfTest with an invalid algorithm ID (TPM_ALG_ERROR = 0x0000)
/// must return TPM_RC_VALUE (Parameter 1, 0x0103).
#[test]
fn incremental_alg_error_rejected() {
    let mut sim = Tpm::new();

    let inc_test_req = hex_checked(concat!(
        "8001",     // NO_SESSIONS
        "00000010", // size: 16 bytes
        "00000142", // TPM_CC_IncrementalSelfTest
        "00000001", // count: 1
        "0000",     // alg: TPM_ALG_ERROR (0x0000)
    ));
    let rc = raw_rc(&mut sim, &inc_test_req);
    assert_eq!(
        rc,
        TpmRc::VALUE.with(Position::parameter(1)).get(),
        "Expected TPM_RC_VALUE (0x0103) for IncrementalSelfTest with invalid algorithm ID"
    );
}

/// IncrementalSelfTest unmarshals TPML_ALG per element: trailing bytes -> SIZE, truncation -> INSUFFICIENT, even after reserved IDs.
///
/// Regression test verifying that `TPM2_IncrementalSelfTest` unmarshals `TPML_ALG`
/// (`TPM_ALG_ID` Constants) infallibly per element, returning `TPM_RC_SIZE` on trailing
/// bytes and `TPM_RC_INSUFFICIENT` on truncated buffers even when earlier elements are
/// reserved `TPM_ALG_ID` values (`0x0000`, `0x00C1..=0x00C6`, `0x8000..=0xFFFF`).
#[test]
fn incremental_alg_list_framing() {
    let mut sim = Tpm::new();

    // 1. Trailing bytes after a reserved algorithm ID must return TPM_RC_SIZE (not TPM_RC_VALUE)
    for reserved_hex in ["0000", "00C4", "8001", "FFFF"] {
        let mut req = [0u8; 17];
        req[0..2].copy_from_slice(&0x8001u16.to_be_bytes()); // NO_SESSIONS
        req[2..6].copy_from_slice(&17u32.to_be_bytes()); // size = 17 (1 trailing byte)
        req[6..10].copy_from_slice(&0x00000142u32.to_be_bytes()); // TPM_CC_IncrementalSelfTest
        req[10..14].copy_from_slice(&1u32.to_be_bytes()); // count = 1
        let alg_bytes = u16::from_str_radix(reserved_hex, 16).unwrap().to_be_bytes();
        req[14..16].copy_from_slice(&alg_bytes);
        req[16] = 0xAA; // trailing byte

        let rc = raw_rc(&mut sim, &req);
        assert_eq!(
            rc,
            TpmRc::SIZE.to_rc().get(),
            "Expected TPM_RC_SIZE on trailing bytes with reserved alg 0x{}",
            reserved_hex
        );
    }

    // 2. Truncated buffer after a reserved algorithm ID must return TPM_RC_INSUFFICIENT (not TPM_RC_VALUE)
    let truncated_req = hex_checked(concat!(
        "8001",     // NO_SESSIONS
        "00000011", // size: 17 bytes (truncated: count=2 requires 18 bytes)
        "00000142", // TPM_CC_IncrementalSelfTest
        "00000002", // count: 2
        "0000",     // alg[0]: 0x0000 (reserved)
        "00",       // alg[1]: truncated (only 1 byte)
    ));
    let rc = raw_rc(&mut sim, &truncated_req);
    assert_eq!(
        rc,
        TpmRc::INSUFFICIENT.with(Position::parameter(1)).get(),
        "Expected TPM_RC_INSUFFICIENT (Parameter 1) on truncated buffer with reserved alg[0]"
    );
}

/// IncrementalSelfTest rejects ALG_NULL and unimplemented SM2 without partially testing AES.
#[test]
fn incremental_rejects_null_and_sm2_algs() {
    let mut sim = Tpm::new();
    assert_eq!(
        incremental_self_test(&mut sim, &[Alg::NULL]),
        Err(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
    assert_eq!(
        incremental_self_test(&mut sim, &[Alg::AES, Alg::SM2]),
        Err(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
    assert!(
        incremental_self_test(&mut sim, &[])
            .unwrap()
            .contains(&Alg::AES)
    );
}

/// IncrementalSelfTest with a reserved algorithm: trailing bytes -> SIZE, truncation -> INSUFFICIENT, exact buffer -> VALUE + P1.
#[test]
fn incremental_reserved_alg_errors() {
    let mut sim = Tpm::new();

    for reserved_id in [0x0000u16, 0x00C1, 0x8000, 0xFFFF] {
        let alg_bytes = reserved_id.to_be_bytes();

        // 1. Trailing bytes after toTest containing reserved algorithm ID -> TPM_RC_SIZE
        // Header: tag = 0x8001, size = 17 (0x11), cmd = 0x00000142 (IncrementalSelfTest)
        // toTest: count = 1 (0x00000001), algorithms[0] = reserved_id
        // Trailing byte: 0xAA
        let mut req_trailing = hex("8001 00000011 00000142 00000001");
        req_trailing.extend_from_slice(&alg_bytes);
        req_trailing.push(0xAA);
        assert_eq!(
            transact_rc_of(&mut sim, &req_trailing),
            TpmRc::SIZE.get(),
            "IncrementalSelfTest with reserved alg {reserved_id:#06x} and trailing byte must return TPM_RC_SIZE"
        );

        // 2. Truncated buffer after reserved algorithm ID (count = 2, only 1 byte of 2nd alg) -> TPM_RC_INSUFFICIENT + P1
        let mut req_truncated = hex("8001 00000011 00000142 00000002");
        req_truncated.extend_from_slice(&alg_bytes);
        req_truncated.push(0x00);
        assert_eq!(
            transact_rc_of(&mut sim, &req_truncated),
            TpmRc::INSUFFICIENT.with(Position::parameter(1)).get(),
            "IncrementalSelfTest with reserved alg {reserved_id:#06x} and truncated 2nd alg must return TPM_RC_INSUFFICIENT + P1"
        );

        // 3. Exact buffer with reserved algorithm ID -> TPM_RC_VALUE + P1 during execution
        let mut req_exact = hex("8001 00000010 00000142 00000001");
        req_exact.extend_from_slice(&alg_bytes);
        assert_eq!(
            transact_rc_of(&mut sim, &req_exact),
            TpmRc::VALUE.with(Position::parameter(1)).get(),
            "IncrementalSelfTest with reserved alg {reserved_id:#06x} must return TPM_RC_VALUE + P1 during execution"
        );
    }
}

/// IncrementalSelfTest with a reserved TPM_ALG_ID: trailing bytes TPM_RC_SIZE, exact TPM_RC_VALUE + RC_P1, truncated TPM_RC_INSUFFICIENT
#[test]
fn reserved_algorithm_error_codes() {
    use testing::tpm::Tpm;
    use tpm2::errors::{Position, TpmRc};

    let mut sim = Tpm::new();

    let expected_size = TpmRc::SIZE.get();
    let expected_val_p1 = TpmRc::VALUE.with(Position::parameter(1)).get();
    let expected_insufficient = TpmRc::INSUFFICIENT.with(Position::parameter(1)).get();

    for reserved_id in [0x0000u16, 0x00C1, 0x00C4, 0x00C6, 0x8000, 0x8021, 0xFFFF] {
        // 1. Trailing bytes after reserved TPM_ALG_ID -> must return TPM_RC_SIZE (0x00000095)
        // Header: tag = TPM_ST_NO_SESSIONS (0x8001), size = 17, cc = TPM_CC_IncrementalSelfTest (0x00000142)
        // Payload: count = 1 (0x00000001), alg[0] = reserved_id, trailing byte = 0xFF
        let mut cmd_trailing = Vec::new();
        cmd_trailing.extend_from_slice(&0x8001u16.to_be_bytes());
        cmd_trailing.extend_from_slice(&17u32.to_be_bytes());
        cmd_trailing.extend_from_slice(&0x00000142u32.to_be_bytes());
        cmd_trailing.extend_from_slice(&1u32.to_be_bytes());
        cmd_trailing.extend_from_slice(&reserved_id.to_be_bytes());
        cmd_trailing.push(0xFF);

        let mut rsp = [0u8; 64];
        let out = sim.transact(&cmd_trailing, &mut rsp).unwrap();
        let rc = u32::from_be_bytes(out[6..10].try_into().unwrap());
        assert_eq!(
            rc, expected_size,
            "Expected TPM_RC_SIZE (0x{:08X}) on trailing bytes with reserved alg 0x{:04X}, got 0x{:08X}",
            expected_size, reserved_id, rc
        );

        // 2. Exact buffer with reserved TPM_ALG_ID -> must return TPM_RC_VALUE | TPM_RC_P | TPM_RC_1 (0x000001C4)
        let mut cmd_exact = Vec::new();
        cmd_exact.extend_from_slice(&0x8001u16.to_be_bytes());
        cmd_exact.extend_from_slice(&16u32.to_be_bytes());
        cmd_exact.extend_from_slice(&0x00000142u32.to_be_bytes());
        cmd_exact.extend_from_slice(&1u32.to_be_bytes());
        cmd_exact.extend_from_slice(&reserved_id.to_be_bytes());

        let out_exact = sim.transact(&cmd_exact, &mut rsp).unwrap();
        let rc_exact = u32::from_be_bytes(out_exact[6..10].try_into().unwrap());
        assert_eq!(
            rc_exact, expected_val_p1,
            "Expected TPM_RC_VALUE | TPM_RC_P | TPM_RC_1 (0x{:08X}) for reserved alg 0x{:04X}, got 0x{:08X}",
            expected_val_p1, reserved_id, rc_exact
        );

        // 3. Truncated buffer after reserved TPM_ALG_ID (count = 2, only 1 byte of 2nd alg) -> TPM_RC_INSUFFICIENT (0x0000009A)
        let mut cmd_trunc = Vec::new();
        cmd_trunc.extend_from_slice(&0x8001u16.to_be_bytes());
        cmd_trunc.extend_from_slice(&17u32.to_be_bytes());
        cmd_trunc.extend_from_slice(&0x00000142u32.to_be_bytes());
        cmd_trunc.extend_from_slice(&2u32.to_be_bytes());
        cmd_trunc.extend_from_slice(&reserved_id.to_be_bytes());
        cmd_trunc.push(0x00);

        let out_trunc = sim.transact(&cmd_trunc, &mut rsp).unwrap();
        let rc_trunc = u32::from_be_bytes(out_trunc[6..10].try_into().unwrap());
        assert_eq!(
            rc_trunc, expected_insufficient,
            "Expected TPM_RC_INSUFFICIENT (0x{:08X}) on truncated buffer after reserved alg 0x{:04X}, got 0x{:08X}",
            expected_insufficient, reserved_id, rc_trunc
        );
    }
}

/// IncrementalSelfTest with an algorithm this TPM does not implement (TPM_ALG_ECSCHNORR, absent
/// from `TPM_CAP_ALGS`) in `toTest` fails with `TPM_RC_VALUE + RC_P1`, even though the rest of the
/// list is implemented (found by differential fuzzing). TPM 2.0 Part 3 TPM2_IncrementalSelfTest is
/// silent on unimplemented algorithms; the TCG reference checks `g_implementedAlgorithms`.
#[test]
fn unimplemented_algorithm_in_to_test_rejected() {
    let mut sim = Tpm::new();
    let cmd = IncrementalSelfTest {
        to_test: TpmlAlg::from_slice(&[Alg::SHA256, Alg::ECSCHNORR, Alg::AES]).unwrap(),
    };
    assert_eq!(
        sim.execute(cmd).err().map(rc_of_error),
        Some(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
}
