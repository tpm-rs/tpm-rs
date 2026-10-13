//! TPM2_PCR_Extend: bank updates, TPM_RH_NULL, hash validation and the PCR update counter.

use crate::_common::{
    ALG_SHA1, ALG_SHA256, ALG_SHA384, ALG_SHA512, CC_PCR_EXTEND, PW_SESSION, ST_SESSIONS,
    build_raw_cmd as build_cmd, compute_expected_extend, exec_command as exec,
    execute_tpm_command_at_locality0 as execute_tpm_command, execute_with_password_sessions,
    expected_extend_sha1, expected_extend_sha256, hex_checked as hex,
    pcr_extend_at_no_continue as pcr_extend_at, pcr_read_selection as pcr_read, pw, raw_rc,
    read_pcr, read_pcr_by_alg_id, send_with_rc as send, update_counter,
};
use testing::tpm::Tpm;
use tpm2::commands::{PCREvent, PCRExtend, PCRRead, PCRReset};
use tpm2::errors::{Position, TpmRc};
use tpm2::*;

// 1. Correctness of PCR_Extend (matching SHA-1, SHA-256, SHA-384 mathematical output)
/// PCR_Extend updates allocated SHA-1/SHA-256 banks correctly, skips unallocated SHA-384 and bumps the update counter.
#[test]
fn extend_matches_reference_digests() {
    let mut sim = Tpm::new();

    let pcr_idx = 5usize;
    let initial_sha1 = read_pcr_by_alg_id(&mut sim, ALG_SHA1, pcr_idx).unwrap();
    let initial_sha256 = read_pcr_by_alg_id(&mut sim, ALG_SHA256, pcr_idx).unwrap();
    // The default PCR allocation is SHA1+SHA256 only.
    assert_eq!(read_pcr_by_alg_id(&mut sim, ALG_SHA384, pcr_idx), None);
    let initial_counter = update_counter(&mut sim);

    let extend_val_sha1 = vec![0x11u8; 20];
    let extend_val_sha256 = vec![0x22u8; 32];
    let extend_val_sha384 = vec![0x33u8; 48];

    // Execute PCR_Extend
    let rc = pcr_extend_at(
        &mut sim,
        0,
        pcr_idx as u32,
        &[
            (ALG_SHA1, extend_val_sha1.clone()),
            (ALG_SHA256, extend_val_sha256.clone()),
            (ALG_SHA384, extend_val_sha384),
        ],
    );
    assert_eq!(rc, 0, "PCR_Extend failed: {rc:#x}");

    // Verify digests extended correctly
    let expected_sha1 = compute_expected_extend(TpmiAlgHash::Sha1, &initial_sha1, &extend_val_sha1);
    let expected_sha256 =
        compute_expected_extend(TpmiAlgHash::Sha256, &initial_sha256, &extend_val_sha256);

    assert_eq!(
        read_pcr_by_alg_id(&mut sim, ALG_SHA1, pcr_idx).unwrap(),
        expected_sha1
    );
    assert_eq!(
        read_pcr_by_alg_id(&mut sim, ALG_SHA256, pcr_idx).unwrap(),
        expected_sha256
    );
    // Like C PCRExtend (PCR.c), banks that are not allocated (SHA384) are not extended (and
    // still are not readable).
    assert_eq!(read_pcr_by_alg_id(&mut sim, ALG_SHA384, pcr_idx), None);

    // Verify update_counter incremented: C PCRExtend calls PCRChanged() once per allocated
    // bank that is extended (PCR.c:751), i.e. twice here (SHA1 and SHA256).
    assert_eq!(update_counter(&mut sim), initial_counter + 2);
}

/// PCR_Extend with TPM_RH_NULL succeeds without changing any PCR.
#[test]
fn extend_rh_null_is_noop() {
    let mut sim = Tpm::new();

    // Keep track of some baseline PCR values (e.g. PCR 5)
    let pcr_idx = 5usize;
    let baseline_sha256 = read_pcr(&mut sim, TpmiAlgHash::Sha256, pcr_idx).unwrap();

    let extend_val_sha256 = [0x22u8; 32];
    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha256(&extend_val_sha256)).unwrap();

    // Call PCR_Extend with TPM_RH_NULL
    let extend_cmd = PCRExtend {
        pcr_handle: Handle::RH_NULL,
        digests,
    };
    execute_tpm_command(&mut sim, &extend_cmd, &[pw()]).unwrap();

    // Verify that the PCR 5 value did not change
    assert_eq!(
        read_pcr(&mut sim, TpmiAlgHash::Sha256, pcr_idx).unwrap(),
        baseline_sha256
    );
}

/// PCR_Extend with an unsupported hash algorithm in digests fails with TPM_RC_HASH + P1 (TC2_2_24_02_05).
///
/// Regression test for CPCTPM_TC2_2_24_02_05:
/// TPM2_PCR_Extend specifying an unsupported hash algorithm (TPM_ALG_AES = 0x0006) in digests
/// must return TPM_RC_HASH (Parameter 1, 0x01C3).
#[test]
fn invalid_digest_hash_rejected() {
    let mut sim = Tpm::new();

    let mut pcr_extend_req = hex(concat!(
        "8002",                             // SESSIONS
        "0000002b",                         // size: 43 bytes
        "00000182",                         // TPM_CC_PCR_Extend
        "00000000",                         // pcrHandle: PCR 0
        "00000009",                         // authSize: 9
        "40000009",                         // session: RS_PW
        "0000",                             // nonce
        "01",                               // continueSession
        "0000",                             // hmac
        "00000001",                         // digests count: 1
        "0006",                             // hashAlg: TPM_ALG_AES (invalid)
        "000102030405060708090a0b0c0d0e0f", // digest: 16 bytes
    ));
    let len = pcr_extend_req.len() as u32;
    pcr_extend_req[2..6].copy_from_slice(&len.to_be_bytes());
    let rc = raw_rc(&mut sim, &pcr_extend_req);
    assert_eq!(
        rc,
        TpmRc::HASH.with(Position::parameter(1)).get(),
        "Expected TPM_RC_HASH (0x01C3) for PCR_Extend with invalid hash algorithm in digests"
    );
}

// 9. Stress/Adversarial tests for PCRExtend invalid banks
/// PCR_Extend with hash algorithm 0xFFFF fails with HASH (after auth checks).
#[test]
fn invalid_hash_alg_rejected() {
    let mut sim = Tpm::new();

    // Send invalid hash algorithm ID 0xFFFF
    // C checks authorization (CheckAuthNoSession -> AUTH_MISSING) before unmarshaling the
    // parameters, so send an empty password session for pcrHandle.
    let req_invalid_hash = build_cmd(
        ST_SESSIONS,
        CC_PCR_EXTEND,
        &[5],
        Some(&PW_SESSION),
        &[0x00, 0x00, 0x00, 0x01, 0xff, 0xff, 0x00],
    );
    assert_eq!(req_invalid_hash.len(), 0x22);
    let (rc, _) = send(&mut sim, &req_invalid_hash);
    assert_eq!(rc, TpmRc::HASH.with(Position::parameter(1)).get());
}

/// PCR_Extend, PCR_Event and PCR_Reset reject PCR handles beyond PCR 23 with TPM_RC_VALUE
///
/// PCR_Extend / PCR_Event / PCR_Reset reject PCR handles beyond PCR 23 with
/// `TPM_RC_VALUE` on the PCR handle.
#[test]
fn pcr_extend_event_reset_reject_pcr_above_23() {
    let mut sim = Tpm::new();

    // 1. PCR_Extend beyond 23
    let res = exec(
        &mut sim,
        &PCRExtend {
            pcr_handle: Handle(24),
            digests: TpmlDigestValues::default(),
        },
        &[pw()],
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::handle(1)).get())
    );

    // 2. PCR_Event beyond 23
    let res = exec(
        &mut sim,
        &PCREvent {
            pcr_handle: Handle(25),
            event_data: Tpm2bEvent::from_bytes(&[1, 2, 3]).unwrap(),
        },
        &[pw()],
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::handle(1)).get())
    );

    // 3. PCR_Reset beyond 23 -> Value error
    let res = exec(
        &mut sim,
        &PCRReset {
            pcr_handle: Handle(24),
        },
        &[pw()],
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::handle(1)).get())
    );
}

/// PCR_Extend of PCR 16 with a SHA-256 digest succeeds
#[test]
fn pcr_extend_sha256_bank() {
    let mut sim = Tpm::new();
    let auth_handle = Handle(16);
    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha256(&[0xaa; 32])).unwrap();
    let cmd = PCRExtend {
        pcr_handle: auth_handle,
        digests,
    };
    execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();
}

/// PCR_Extend extends every allocated bank (SHA-1, SHA-256) correctly; the unallocated SHA-384 bank is ignored
///
/// PCR_Extend extends every allocated bank with the matching digest; the
/// unallocated SHA-384 bank is neither extended nor read back.
#[test]
fn pcr_extend_updates_allocated_banks() {
    let mut sim = Tpm::new();

    let sha1_init = [0u8; 20];
    let sha256_init = [0u8; 32];

    let sha1_ext = [0x11; 20];
    let sha256_ext = [0x22; 32];
    let sha384_ext = [0x33; 48];

    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha1(&sha1_ext)).unwrap();
    digests.add(&TpmtHa::Sha256(&sha256_ext)).unwrap();
    digests.add(&TpmtHa::Sha384(&sha384_ext)).unwrap();
    exec(
        &mut sim,
        &PCRExtend {
            pcr_handle: Handle(0),
            digests,
        },
        &[pw()],
    )
    .unwrap();

    let mut selection = TpmlPcrSelection::default();
    for alg in [TpmiAlgHash::Sha1, TpmiAlgHash::Sha256, TpmiAlgHash::Sha384] {
        selection
            .add(&TpmsPcrSelection::new(alg, &[1, 0, 0]).unwrap())
            .unwrap();
    }
    let read_resp = pcr_read(&mut sim, selection).unwrap();

    // The default PCR allocation is SHA1+SHA256; like C (PCRExtend only extends allocated
    // banks, PCRRead/FilterPcr drops unallocated ones, PCR.c), SHA384 is neither extended
    // nor read back.
    assert_eq!(read_resp.pcr_values.count(), 2);

    let expected_sha1 = expected_extend_sha1(&sha1_init, &sha1_ext);
    let expected_sha256 = expected_extend_sha256(&sha256_init, &sha256_ext);
    assert_eq!(
        read_resp.pcr_values.digests()[0].get_buffer(),
        &expected_sha1
    );
    assert_eq!(
        read_resp.pcr_values.digests()[1].get_buffer(),
        &expected_sha256
    );
}

// 6. PCRExtend unsupported banks are ignored and command succeeds
/// PCR_Extend with an unallocated SHA-512 digest succeeds and still extends SHA-256.
#[test]
fn unallocated_bank_ignored() {
    let mut sim = Tpm::new();

    let pcr_idx = 5usize;
    let initial_sha256 = read_pcr_by_alg_id(&mut sim, ALG_SHA256, pcr_idx).unwrap();

    let extend_val_sha256 = vec![0x22u8; 32];
    let extend_val_sha512 = vec![0x55u8; 64]; // unsupported bank

    // Execute PCR_Extend: should succeed and NOT return TpmRc::HASH (or any other error)
    let rc = pcr_extend_at(
        &mut sim,
        0,
        pcr_idx as u32,
        &[
            (ALG_SHA256, extend_val_sha256.clone()),
            (ALG_SHA512, extend_val_sha512), // Add unsupported bank digest
        ],
    );
    assert_eq!(rc, 0, "PCR_Extend failed: {rc:#x}");

    // Verify SHA-256 extended correctly
    let expected_sha256 =
        compute_expected_extend(TpmiAlgHash::Sha256, &initial_sha256, &extend_val_sha256);
    assert_eq!(
        read_pcr_by_alg_id(&mut sim, ALG_SHA256, pcr_idx).unwrap(),
        expected_sha256
    );
}

/// pcrUpdateCounter increments on PCR_Extend and PCR_Reset.
#[test]
fn update_counter_tracks_extend_and_reset() {
    let mut sim = Tpm::new();

    // Read baseline update counter
    let read_cmd = PCRRead {
        pcr_selection_in: TpmlPcrSelection::default(),
    };
    let resp = execute_tpm_command(&mut sim, &read_cmd, &[]).unwrap();
    let initial_counter = resp.pcr_update_counter;

    // 1. Extend PCR 16
    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha1(&[0xdd; 20])).unwrap();
    let extend_cmd = PCRExtend {
        pcr_handle: Handle(16),
        digests,
    };
    execute_tpm_command(&mut sim, &extend_cmd, &[pw()]).unwrap();

    // Read counter again
    let resp = execute_tpm_command(&mut sim, &read_cmd, &[]).unwrap();
    let after_extend_counter = resp.pcr_update_counter;
    assert_eq!(after_extend_counter, initial_counter + 1);

    // 2. Reset PCR 16
    let reset_cmd = PCRReset {
        pcr_handle: Handle(16),
    };
    execute_tpm_command(&mut sim, &reset_cmd, &[pw()]).unwrap();

    // Read counter again
    let resp = execute_tpm_command(&mut sim, &read_cmd, &[]).unwrap();
    let after_reset_counter = resp.pcr_update_counter;
    assert_eq!(after_reset_counter, after_extend_counter + 1);
}
