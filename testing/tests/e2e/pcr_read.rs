//! TPM2_PCR_Read: selections, bank limits and digest count caps.

use crate::_common::{
    ALG_SHA1, ALG_SHA256, CC_PCR_READ, ST_NO_SESSIONS, build_raw_cmd as build_cmd,
    execute_tpm_command_at_locality0 as execute_tpm_command, pcr_read, pcr_read_selection,
    pcr_selection, send_with_rc as send,
};
use testing::tpm::Tpm;
use tpm2::commands::PCRRead;
use tpm2::errors::{Position, TpmRc};
use tpm2::*;

// 5. PCR_Read constraints
/// PCR_Read with empty selection, PCR 0 zeros after startup, and >8 PCRs truncated to 8 digests with updated mask.
#[test]
fn empty_small_and_truncated_selections() {
    let mut sim = Tpm::new();

    // A. Read empty selection (no banks selected)
    let resp_empty = pcr_read(&mut sim, &[]);
    assert_eq!(resp_empty.selection_out.len(), 0);
    assert_eq!(resp_empty.values.len(), 0);

    // B. Read small selection (e.g. SHA-256 bank PCR 0)
    let resp_small = pcr_read(&mut sim, &[(ALG_SHA256, [0x01, 0x00, 0x00])]);
    assert_eq!(resp_small.selection_out.len(), 1);
    assert_eq!(resp_small.values.len(), 1);
    // PCR 0 of a freshly started TPM (no H-CRTM, startup at locality 0) is all zeros.
    assert_eq!(resp_small.values[0], vec![0u8; 32]);

    // C. Limit of returned digests:
    // If we request 9 PCRs (e.g. PCR 0..8), the implementation returns success but truncates
    // the returned digests to 8, updating the selection out mask to match.
    let resp_nine = pcr_read(&mut sim, &[(ALG_SHA256, [0xff, 0x01, 0x00])]);
    assert_eq!(resp_nine.values.len(), 8);
    assert_eq!(resp_nine.selection_out.len(), 1);
    // bit for PCR 8 is cleared!
    assert_eq!(resp_nine.selection_out[0].1, vec![0xff, 0x00, 0x00]);

    // D. Read all selections: what happens if we select all SHA-256 PCRs (24 PCRs)?
    let resp_all = pcr_read(&mut sim, &[(ALG_SHA256, [0xff, 0xff, 0xff])]);
    assert_eq!(resp_all.values.len(), 8);
    assert_eq!(resp_all.selection_out.len(), 1);
    // bit for PCR 8..23 are cleared!
    assert_eq!(resp_all.selection_out[0].1, vec![0xff, 0x00, 0x00]);
}

// 8. Stress/Adversarial tests for PCRRead
/// PCR_Read rejects >HASH_COUNT banks and sizeofSelect > 4, and caps digests at 8 across banks.
#[test]
fn oversized_bank_count_and_select_size() {
    let mut sim = Tpm::new();

    let size_p1 = TpmRc::SIZE.with(Position::parameter(1)).get();

    // A. Count exceeding TPM2_NUM_PCR_BANKS (HASH_COUNT = 8, so count = 9 and count = 17)
    let banks_9 = vec![(ALG_SHA256, [0x01, 0x00, 0x00]); 9];
    let req_count_9 = build_cmd(
        ST_NO_SESSIONS,
        CC_PCR_READ,
        &[],
        None,
        &pcr_selection(&banks_9),
    );
    assert_eq!(req_count_9.len(), 0x44);
    let (rc, resp) = send(&mut sim, &req_count_9);
    assert_eq!(resp.len(), 10);
    assert_eq!(rc, size_p1);

    let banks_17 = vec![(ALG_SHA256, [0x01, 0x00, 0x00]); 17];
    let req_count_17 = build_cmd(
        ST_NO_SESSIONS,
        CC_PCR_READ,
        &[],
        None,
        &pcr_selection(&banks_17),
    );
    assert_eq!(req_count_17.len(), 0x74);
    let (rc, _) = send(&mut sim, &req_count_17);
    assert_eq!(rc, size_p1);

    // B. sizeof_select = 5 (greater than TPM2_PCR_SELECT_MAX = 4)
    let req_sizeof_5 = build_cmd(
        ST_NO_SESSIONS,
        CC_PCR_READ,
        &[],
        None,
        &[0, 0, 0, 1, 0x00, 0x0b, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00],
    );
    let (rc, _) = send(&mut sim, &req_sizeof_5);
    assert_eq!(rc, TpmRc::VALUE.with(Position::parameter(1)).get());

    // C. Requesting more digests than max limit (8) across multiple banks.
    // Bank 1 (SHA-256): select 6 PCRs (0..5)
    // Bank 2 (SHA-1): select 6 PCRs (0..5)
    // Total requested: 12. Only 8 should be returned.
    // (Bank 2 uses SHA-1 because the default allocation is SHA1+SHA256 and, like C
    // PCRRead/FilterPcr, unallocated banks such as SHA-384 return no digests.)
    // The response should have the first 8 digests (Bank 1 PCR 0..5, Bank 2 PCR 0..1),
    // and the selection out should reflect exactly which PCRs were read.
    let resp_multi = pcr_read(
        &mut sim,
        &[
            (ALG_SHA256, [0x3f, 0x00, 0x00]),
            (ALG_SHA1, [0x3f, 0x00, 0x00]),
        ],
    );
    // Verify total digests returned is exactly 8
    assert_eq!(resp_multi.values.len(), 8);
    // Selection out count should be 2 (both banks had some PCRs read)
    assert_eq!(resp_multi.selection_out.len(), 2);
    // Bank 1 (SHA-256) selection out should have all 6 PCRs read
    assert_eq!(resp_multi.selection_out[0].0, ALG_SHA256);
    assert_eq!(resp_multi.selection_out[0].1, vec![0x3f, 0x00, 0x00]);
    // Bank 2 (SHA-1) selection out should have only 2 PCRs read (PCR 0 and 1)
    assert_eq!(resp_multi.selection_out[1].0, ALG_SHA1);
    assert_eq!(resp_multi.selection_out[1].1, vec![0x03, 0x00, 0x00]);
}

/// PCR_Read with an empty selection returns no digests
#[test]
fn pcr_read_empty_selection() {
    let mut sim = Tpm::new();
    let cmd = PCRRead {
        pcr_selection_in: TpmlPcrSelection::default(),
    };
    let resp = sim.execute(cmd).unwrap();
    assert_eq!(resp.pcr_values.count(), 0);
}

/// PCR_Read of an empty selection returns nothing; at most 8 digests per call with an updated output selection
///
/// PCR_Read of an empty selection returns no digests; at most 8 digests are
/// returned per call, and the output selection reflects what was read.
#[test]
fn pcr_read_selection_limits() {
    let mut sim = Tpm::new();

    // 1. Reading empty selection
    let mut empty_selection = TpmlPcrSelection::default();
    empty_selection
        .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0, 0, 0]).unwrap())
        .unwrap();
    let resp_empty = pcr_read_selection(&mut sim, empty_selection).unwrap();
    assert_eq!(resp_empty.pcr_values.count(), 0);
    assert_eq!(resp_empty.pcr_selection_out.count(), 1);
    assert_eq!(
        resp_empty
            .pcr_selection_out
            .pcr_selections()
            .next()
            .unwrap()
            .pcr_select(),
        &[0, 0, 0]
    );

    // 2. Reading exactly 8 PCRs
    let mut selection_8 = TpmlPcrSelection::default();
    selection_8
        .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0xff, 0, 0]).unwrap())
        .unwrap(); // PCR 0..7
    let resp_8 = pcr_read_selection(&mut sim, selection_8).unwrap();
    assert_eq!(resp_8.pcr_values.count(), 8);

    // 3. Reading 9 PCRs
    let mut selection_9 = TpmlPcrSelection::default();
    selection_9
        .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0xff, 0x01, 0]).unwrap())
        .unwrap(); // PCR 0..8
    match pcr_read_selection(&mut sim, selection_9) {
        Ok(resp) => {
            assert_eq!(resp.pcr_values.count(), 8);
            assert_eq!(
                resp.pcr_selection_out
                    .pcr_selections()
                    .next()
                    .unwrap()
                    .pcr_select(),
                &[0xff, 0x00, 0x00]
            );
        }
        Err(rc) => {
            assert_eq!(rc, TpmRc::SIZE.get());
        }
    }
}

/// PCR_Read walks selections in caller order (SHA-256 before SHA-1) and caps at 8 digests.
#[test]
fn selections_returned_in_caller_order() {
    let mut sim = Tpm::new();

    // Build selection: SHA256 first, then SHA1.
    // Select PCR 0..6 (6 PCRs) for each.
    let mut pcr_selection_in = TpmlPcrSelection::default();
    // Add SHA256 bank first
    pcr_selection_in
        .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0x3F, 0x00, 0x00]).unwrap())
        .unwrap();
    // Add SHA1 bank second
    pcr_selection_in
        .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha1, &[0x3F, 0x00, 0x00]).unwrap())
        .unwrap();

    let read_cmd = PCRRead { pcr_selection_in };
    let resp = execute_tpm_command(&mut sim, &read_cmd, &[]).unwrap();

    // Total returned digests must be exactly 8 (the limit)
    assert_eq!(resp.pcr_values.count(), 8);

    // C PCRRead (PCR.c:827) walks the selections in the caller's order without sorting, so
    // the first 6 digests are SHA256 (size 32) and the remaining 2 are SHA1 (size 20).
    let digests = resp.pcr_values.digests();
    for (i, digest) in digests.iter().enumerate().take(6) {
        assert_eq!(digest.get_size(), 32, "Digest {} should be SHA256", i);
    }
    for (i, digest) in digests.iter().enumerate().take(8).skip(6) {
        assert_eq!(digest.get_size(), 20, "Digest {} should be SHA1", i);
    }
}

/// PCR_Read of the unallocated SHA-512 bank returns a cleared selection and no digests.
#[test]
fn unallocated_bank_returns_no_digests() {
    let mut sim = Tpm::new();

    // Create selection containing unsupported SHA-512 bank
    let mut pcr_selection_in = TpmlPcrSelection::default();
    // Select PCR 1, 2, 3 in SHA-512 bank
    pcr_selection_in
        .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha512, &[0x0E, 0x00, 0x00]).unwrap())
        .unwrap();

    let read_cmd = PCRRead { pcr_selection_in };
    let resp = execute_tpm_command(&mut sim, &read_cmd, &[]).unwrap();

    // The output selection count should match (contains the bank we requested)
    assert_eq!(resp.pcr_selection_out.count(), 1);
    let out_sel = resp.pcr_selection_out.pcr_selections().next().unwrap();
    assert_eq!(out_sel.hash(), TpmiAlgHash::Sha512);
    // But since the bank is unsupported, all bits in selection out should be cleared (0)
    for &b in out_sel.pcr_select() {
        assert_eq!(b, 0);
    }
    // No digests should be returned in values list
    assert_eq!(resp.pcr_values.count(), 0);
}
