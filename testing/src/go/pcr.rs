//! Rust port of the Go E2E test file `pcr_test.go`.

use crate::test_utils::{execute_with_password_sessions, execute_with_password_sessions_status};
use tpm2::commands::{
    PCREvent, PCREventHandles, PCRExtend, PCRExtendHandles, PCRRead, PCRReset, PCRResetHandles,
};
use tpm2::{
    Handle, Tpm2bEvent, TpmiAlgHash, TpmlDigestValues, TpmlPcrSelection, TpmsPcrSelection, TpmtHa,
};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

/// The TPM requires all PCR selections to be at least big enough to select all
/// the PCRs in the minimum PC Client PCR allocation.
const PC_CLIENT_MINIMUM_PCR_COUNT: u32 = 24;

/// Port of go-tpm's `PCClientCompatible.PCRs(pcrs...)`.
///
/// Returns the PC Client PTP-compatible PCR selection bitmask for the given
/// PCR indices. The bitmask is byte-wise little-endian and bit-wise
/// big-endian, and is at least `PC_CLIENT_MINIMUM_PCR_COUNT / 8` bytes long.
fn pc_client_compatible_pcrs(pcrs: &[u32]) -> Vec<u8> {
    // Find the biggest PCR we selected.
    let max_pcr = pcrs.iter().copied().max().unwrap_or(0);
    // Enforce the minimum PCR selection size.
    let selection_size = (max_pcr / 8 + 1).max(PC_CLIENT_MINIMUM_PCR_COUNT / 8);
    let mut selection = vec![0u8; selection_size as usize];
    for &pcr in pcrs {
        selection[(pcr / 8) as usize] |= 1 << (pcr % 8);
    }
    selection
}

/// Builds a `TPML_PCR_SELECTION` with a single PC Client-compatible selection
/// of `pcrs` in the `hash` bank.
fn pcr_selections(hash: TpmiAlgHash, pcrs: &[u32]) -> TpmlPcrSelection {
    let selection = TpmsPcrSelection::new(hash, &pc_client_compatible_pcrs(pcrs)).unwrap();
    TpmlPcrSelection::from_slice(&[selection]).unwrap()
}

/// Shared body of the `TestPCRs` table-driven subtests.
fn pcrs_case(pcrs: &[u32], want_select: &[u8]) {
    let selection = pc_client_compatible_pcrs(pcrs);
    assert_eq!(
        selection, want_select,
        "PCRs() = {selection:02x?}, want {want_select:02x?}"
    );
}

// Original Go test: pcr_test.go - TestPCRs/0
#[test]
fn test_pcrs_0() {
    pcrs_case(&[], &[0x00, 0x00, 0x00]);
}

// Original Go test: pcr_test.go - TestPCRs/1
#[test]
fn test_pcrs_1() {
    pcrs_case(&[0], &[0x01, 0x00, 0x00]);
}

// Original Go test: pcr_test.go - TestPCRs/2
#[test]
fn test_pcrs_2() {
    pcrs_case(&[0, 1, 2], &[0x07, 0x00, 0x00]);
}

// Original Go test: pcr_test.go - TestPCRs/3
#[test]
fn test_pcrs_3() {
    pcrs_case(&[0, 7], &[0x81, 0x00, 0x00]);
}

// Original Go test: pcr_test.go - TestPCRs/4
#[test]
fn test_pcrs_4() {
    pcrs_case(&[8], &[0x00, 0x01, 0x00]);
}

// Original Go test: pcr_test.go - TestPCRs/5
#[test]
fn test_pcrs_5() {
    pcrs_case(&[1, 8, 9], &[0x02, 0x03, 0x00]);
}

// Original Go test: pcr_test.go - TestPCRs/6
#[test]
fn test_pcrs_6() {
    pcrs_case(
        &[
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        ],
        &[0xff, 0xff, 0xff],
    );
}

// Original Go test: pcr_test.go - TestPCRs/7
#[test]
fn test_pcrs_7() {
    let mut want_select = [0x00u8; 32];
    want_select[31] = 0x80;
    pcrs_case(&[255], &want_select);
}

/// Returns the three digests (all-0x00, all-0x01, all-0x02) that `TestPCRReset`
/// extends into the debug PCR for the given bank (`extendstpm2` in Go).
fn extends_tpm2(hash: TpmiAlgHash) -> [TpmtHa<'static>; 3] {
    const SHA1: [[u8; 20]; 3] = [[0x00; 20], [0x01; 20], [0x02; 20]];
    const SHA256: [[u8; 32]; 3] = [[0x00; 32], [0x01; 32], [0x02; 32]];
    const SHA384: [[u8; 48]; 3] = [[0x00; 48], [0x01; 48], [0x02; 48]];
    match hash {
        TpmiAlgHash::Sha1 => SHA1.each_ref().map(TpmtHa::Sha1),
        TpmiAlgHash::Sha256 => SHA256.each_ref().map(TpmtHa::Sha256),
        TpmiAlgHash::Sha384 => SHA384.each_ref().map(TpmtHa::Sha384),
        _ => panic!("unsupported hash {hash:?}"),
    }
}

/// Shared body of the `TestPCRReset` subtests: extends the debug PCR (16) in
/// the `hash` bank three times, checks it is non-zero, resets it and checks it
/// is all zero again.
fn pcr_reset_case(hash: TpmiAlgHash) {
    let mut sim = create_simulator!();
    let debug_pcr: u32 = 16;
    let auth_handle = Handle(debug_pcr);

    let pcr_read = PCRRead {
        pcr_selection_in: pcr_selections(hash, &[debug_pcr]),
    };

    // Extending PCR 16
    for digest in extends_tpm2(hash) {
        let mut digests = TpmlDigestValues::default();
        digests.add(&digest).unwrap();
        let extend_cmd = PCRExtend { digests };
        let extend_handles = PCRExtendHandles {
            pcr_handle: auth_handle,
        };
        execute_with_password_sessions(&mut sim, &extend_cmd, extend_handles, 1, &[])
            .expect("failed to extend pcr for test");
    }

    let read_resp = sim.execute(pcr_read).expect("failed to read PCRs");
    if read_resp.pcr_values.count() == 0 {
        eprintln!("PCR bank {hash:?} not allocated/supported, skipping");
        return;
    }
    let post_extend_pcr16 = read_resp.pcr_values.digests()[0];
    assert!(
        !post_extend_pcr16.as_ref().iter().all(|&b| b == 0),
        "postExtendPCR16 not expected to be all Zero: {:?}",
        post_extend_pcr16.as_ref()
    );

    // Resetting PCR 16
    let reset_cmd = PCRReset {};
    let reset_handles = PCRResetHandles {
        pcr_handle: auth_handle,
    };
    execute_with_password_sessions(&mut sim, &reset_cmd, reset_handles, 1, &[])
        .expect("pcrReset failed");
    let read_resp = sim.execute(pcr_read).expect("failed to read PCRs");
    let post_reset_pcr16 = read_resp.pcr_values.digests()[0];
    assert!(
        post_reset_pcr16.as_ref().iter().all(|&b| b == 0),
        "postResetPCR16 expected to be all Zero: {:?}",
        post_reset_pcr16.as_ref()
    );
}

// Original Go test: pcr_test.go - TestPCRReset/SHA1
#[test]
fn test_pcr_reset_sha1() {
    pcr_reset_case(TpmiAlgHash::Sha1);
}

// Original Go test: pcr_test.go - TestPCRReset/SHA256
#[test]
fn test_pcr_reset_sha256() {
    pcr_reset_case(TpmiAlgHash::Sha256);
}

// Original Go test: pcr_test.go - TestPCRReset/SHA384
#[test]
fn test_pcr_reset_sha384() {
    pcr_reset_case(TpmiAlgHash::Sha384);
}

/// Shared body of the `TestPCREvent/<bank>/PCRxx` subtests: extends PCR
/// `pcr` with TPM2_PCR_Event("hello") and then (as the Go test does) reads
/// PCR 20 in the `hash` bank, checking that it is not all zero.
fn pcr_event_case(hash: TpmiAlgHash, pcr: u32) {
    let mut sim = create_simulator!();

    let pcr_read = PCRRead {
        pcr_selection_in: pcr_selections(hash, &[20]),
    };

    let event_cmd = PCREvent {
        event_data: Tpm2bEvent::from_bytes(b"hello").unwrap(),
    };
    let event_handles = PCREventHandles {
        pcr_handle: Handle(pcr),
    };
    execute_with_password_sessions_status(&mut sim, &event_cmd, event_handles, 1, &[])
        .expect("failed to extend pcr for test");

    let read_resp = sim.execute(pcr_read).expect("failed to read PCRs");
    if read_resp.pcr_values.count() == 0 {
        eprintln!("PCR bank {hash:?} not allocated/supported, skipping");
        return;
    }
    let post_extend_pcr16 = read_resp.pcr_values.digests()[0];
    assert!(
        !post_extend_pcr16.as_ref().iter().all(|&b| b == 0),
        "postExtendPCR16 not expected to be all Zero: {:?}",
        post_extend_pcr16.as_ref()
    );
}

// Original Go test: pcr_test.go - TestPCREvent/SHA1/PCR00
#[test]
fn test_pcr_event_sha1_pcr00() {
    pcr_event_case(TpmiAlgHash::Sha1, 0);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA1/PCR01
#[test]
fn test_pcr_event_sha1_pcr01() {
    pcr_event_case(TpmiAlgHash::Sha1, 1);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA1/PCR02
#[test]
fn test_pcr_event_sha1_pcr02() {
    pcr_event_case(TpmiAlgHash::Sha1, 2);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA1/PCR03
#[test]
fn test_pcr_event_sha1_pcr03() {
    pcr_event_case(TpmiAlgHash::Sha1, 3);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA1/PCR04
#[test]
fn test_pcr_event_sha1_pcr04() {
    pcr_event_case(TpmiAlgHash::Sha1, 4);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA1/PCR05
#[test]
fn test_pcr_event_sha1_pcr05() {
    pcr_event_case(TpmiAlgHash::Sha1, 5);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA1/PCR06
#[test]
fn test_pcr_event_sha1_pcr06() {
    pcr_event_case(TpmiAlgHash::Sha1, 6);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA1/PCR07
#[test]
fn test_pcr_event_sha1_pcr07() {
    pcr_event_case(TpmiAlgHash::Sha1, 7);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA1/PCR08
#[test]
fn test_pcr_event_sha1_pcr08() {
    pcr_event_case(TpmiAlgHash::Sha1, 8);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA1/PCR09
#[test]
fn test_pcr_event_sha1_pcr09() {
    pcr_event_case(TpmiAlgHash::Sha1, 9);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA1/PCR10
#[test]
fn test_pcr_event_sha1_pcr10() {
    pcr_event_case(TpmiAlgHash::Sha1, 10);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA1/PCR11
#[test]
fn test_pcr_event_sha1_pcr11() {
    pcr_event_case(TpmiAlgHash::Sha1, 11);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA1/PCR12
#[test]
fn test_pcr_event_sha1_pcr12() {
    pcr_event_case(TpmiAlgHash::Sha1, 12);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA1/PCR13
#[test]
fn test_pcr_event_sha1_pcr13() {
    pcr_event_case(TpmiAlgHash::Sha1, 13);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA1/PCR14
#[test]
fn test_pcr_event_sha1_pcr14() {
    pcr_event_case(TpmiAlgHash::Sha1, 14);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA1/PCR15
#[test]
fn test_pcr_event_sha1_pcr15() {
    pcr_event_case(TpmiAlgHash::Sha1, 15);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA1/PCR16
#[test]
fn test_pcr_event_sha1_pcr16() {
    pcr_event_case(TpmiAlgHash::Sha1, 16);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA256/PCR00
#[test]
fn test_pcr_event_sha256_pcr00() {
    pcr_event_case(TpmiAlgHash::Sha256, 0);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA256/PCR01
#[test]
fn test_pcr_event_sha256_pcr01() {
    pcr_event_case(TpmiAlgHash::Sha256, 1);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA256/PCR02
#[test]
fn test_pcr_event_sha256_pcr02() {
    pcr_event_case(TpmiAlgHash::Sha256, 2);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA256/PCR03
#[test]
fn test_pcr_event_sha256_pcr03() {
    pcr_event_case(TpmiAlgHash::Sha256, 3);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA256/PCR04
#[test]
fn test_pcr_event_sha256_pcr04() {
    pcr_event_case(TpmiAlgHash::Sha256, 4);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA256/PCR05
#[test]
fn test_pcr_event_sha256_pcr05() {
    pcr_event_case(TpmiAlgHash::Sha256, 5);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA256/PCR06
#[test]
fn test_pcr_event_sha256_pcr06() {
    pcr_event_case(TpmiAlgHash::Sha256, 6);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA256/PCR07
#[test]
fn test_pcr_event_sha256_pcr07() {
    pcr_event_case(TpmiAlgHash::Sha256, 7);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA256/PCR08
#[test]
fn test_pcr_event_sha256_pcr08() {
    pcr_event_case(TpmiAlgHash::Sha256, 8);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA256/PCR09
#[test]
fn test_pcr_event_sha256_pcr09() {
    pcr_event_case(TpmiAlgHash::Sha256, 9);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA256/PCR10
#[test]
fn test_pcr_event_sha256_pcr10() {
    pcr_event_case(TpmiAlgHash::Sha256, 10);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA256/PCR11
#[test]
fn test_pcr_event_sha256_pcr11() {
    pcr_event_case(TpmiAlgHash::Sha256, 11);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA256/PCR12
#[test]
fn test_pcr_event_sha256_pcr12() {
    pcr_event_case(TpmiAlgHash::Sha256, 12);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA256/PCR13
#[test]
fn test_pcr_event_sha256_pcr13() {
    pcr_event_case(TpmiAlgHash::Sha256, 13);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA256/PCR14
#[test]
fn test_pcr_event_sha256_pcr14() {
    pcr_event_case(TpmiAlgHash::Sha256, 14);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA256/PCR15
#[test]
fn test_pcr_event_sha256_pcr15() {
    pcr_event_case(TpmiAlgHash::Sha256, 15);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA256/PCR16
#[test]
fn test_pcr_event_sha256_pcr16() {
    pcr_event_case(TpmiAlgHash::Sha256, 16);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA384/PCR00
#[test]
fn test_pcr_event_sha384_pcr00() {
    pcr_event_case(TpmiAlgHash::Sha384, 0);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA384/PCR01
#[test]
fn test_pcr_event_sha384_pcr01() {
    pcr_event_case(TpmiAlgHash::Sha384, 1);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA384/PCR02
#[test]
fn test_pcr_event_sha384_pcr02() {
    pcr_event_case(TpmiAlgHash::Sha384, 2);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA384/PCR03
#[test]
fn test_pcr_event_sha384_pcr03() {
    pcr_event_case(TpmiAlgHash::Sha384, 3);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA384/PCR04
#[test]
fn test_pcr_event_sha384_pcr04() {
    pcr_event_case(TpmiAlgHash::Sha384, 4);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA384/PCR05
#[test]
fn test_pcr_event_sha384_pcr05() {
    pcr_event_case(TpmiAlgHash::Sha384, 5);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA384/PCR06
#[test]
fn test_pcr_event_sha384_pcr06() {
    pcr_event_case(TpmiAlgHash::Sha384, 6);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA384/PCR07
#[test]
fn test_pcr_event_sha384_pcr07() {
    pcr_event_case(TpmiAlgHash::Sha384, 7);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA384/PCR08
#[test]
fn test_pcr_event_sha384_pcr08() {
    pcr_event_case(TpmiAlgHash::Sha384, 8);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA384/PCR09
#[test]
fn test_pcr_event_sha384_pcr09() {
    pcr_event_case(TpmiAlgHash::Sha384, 9);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA384/PCR10
#[test]
fn test_pcr_event_sha384_pcr10() {
    pcr_event_case(TpmiAlgHash::Sha384, 10);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA384/PCR11
#[test]
fn test_pcr_event_sha384_pcr11() {
    pcr_event_case(TpmiAlgHash::Sha384, 11);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA384/PCR12
#[test]
fn test_pcr_event_sha384_pcr12() {
    pcr_event_case(TpmiAlgHash::Sha384, 12);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA384/PCR13
#[test]
fn test_pcr_event_sha384_pcr13() {
    pcr_event_case(TpmiAlgHash::Sha384, 13);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA384/PCR14
#[test]
fn test_pcr_event_sha384_pcr14() {
    pcr_event_case(TpmiAlgHash::Sha384, 14);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA384/PCR15
#[test]
fn test_pcr_event_sha384_pcr15() {
    pcr_event_case(TpmiAlgHash::Sha384, 15);
}

// Original Go test: pcr_test.go - TestPCREvent/SHA384/PCR16
#[test]
fn test_pcr_event_sha384_pcr16() {
    pcr_event_case(TpmiAlgHash::Sha384, 16);
}
