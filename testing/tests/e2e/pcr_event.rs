//! TPM2_PCR_Event: returned digests and extension of allocated banks.

use crate::_common::{
    ALG_SHA1, ALG_SHA256, ALG_SHA384, RH_NULL, compute_expected_extend,
    compute_hash_single as compute_hash, exec_command as exec,
    execute_tpm_command_at_locality0 as execute_tpm_command, execute_with_password_sessions_status,
    expected_extend_sha1, expected_extend_sha256, hash, hash_array as hash_bytes,
    pcr_event_at_digests as pcr_event_at, pcr_read_selection as pcr_read, pw, read_pcr,
    read_pcr_by_alg_id,
};
use testing::tpm::Tpm;
use tpm2::commands::PCREvent;
use tpm2::*;

// 2. Correctness of PCR_Event (calculating event digest and extending it)
/// PCR_Event returns digests for every implemented hash and extends allocated banks with them.
#[test]
fn event_digests_and_extension() {
    let mut sim = Tpm::new();

    let pcr_idx = 10usize;
    let initial_sha1 = read_pcr_by_alg_id(&mut sim, ALG_SHA1, pcr_idx).unwrap();
    let initial_sha256 = read_pcr_by_alg_id(&mut sim, ALG_SHA256, pcr_idx).unwrap();

    let event_bytes = b"Event message data";

    // Execute PCR_Event
    let (rc, digests) = pcr_event_at(&mut sim, 0, pcr_idx as u32, event_bytes);
    assert_eq!(rc, 0, "PCR_Event failed: {rc:#x}");
    let digests = digests.unwrap();

    // Verify event digests computed by PCR_Event
    let computed_sha1 = compute_hash(TpmiAlgHash::Sha1, event_bytes);
    let computed_sha256 = compute_hash(TpmiAlgHash::Sha256, event_bytes);
    let computed_sha384 = compute_hash(TpmiAlgHash::Sha384, event_bytes);

    let mut found_sha1 = false;
    let mut found_sha256 = false;
    let mut found_sha384 = false;

    for digest in digests.digests() {
        match *digest {
            TpmtHa::Sha1(val) => {
                assert_eq!(val, &computed_sha1[..]);
                found_sha1 = true;
            }
            TpmtHa::Sha256(val) => {
                assert_eq!(val, &computed_sha256[..]);
                found_sha256 = true;
            }
            TpmtHa::Sha384(val) => {
                assert_eq!(val, &computed_sha384[..]);
                found_sha384 = true;
            }
            // C PCR_Event returns a digest for every implemented hash (HASH_COUNT),
            // PCR_Event.c, which includes SHA512.
            TpmtHa::Sha512(val) => assert_eq!(val.len(), 64),
            _ => panic!("Unexpected digest algorithm in event response"),
        }
    }
    assert!(found_sha1 && found_sha256 && found_sha384);

    // Verify PCR extended correctly with computed event digests
    let expected_sha1 = compute_expected_extend(TpmiAlgHash::Sha1, &initial_sha1, &computed_sha1);
    let expected_sha256 =
        compute_expected_extend(TpmiAlgHash::Sha256, &initial_sha256, &computed_sha256);

    assert_eq!(
        read_pcr_by_alg_id(&mut sim, ALG_SHA1, pcr_idx).unwrap(),
        expected_sha1
    );
    assert_eq!(
        read_pcr_by_alg_id(&mut sim, ALG_SHA256, pcr_idx).unwrap(),
        expected_sha256
    );
    // The default PCR allocation is SHA1+SHA256 only; like C PCRExtend (PCR.c), banks that
    // are not allocated (SHA384) are not extended.
    assert_eq!(read_pcr_by_alg_id(&mut sim, ALG_SHA384, pcr_idx), None);

    // Test with RHNull handle: shouldn't extend PCR but should return digests
    let initial_pcr_null_sha1 = read_pcr_by_alg_id(&mut sim, ALG_SHA1, pcr_idx).unwrap();
    let (rc, digests_null) = pcr_event_at(&mut sim, 0, RH_NULL, event_bytes);
    assert_eq!(rc, 0, "PCR_Event(TPM_RH_NULL) failed: {rc:#x}");
    // Digests are still returned (one per implemented hash: SHA1/256/384/512)
    assert_eq!(digests_null.unwrap().count(), 4);
    // But PCR state did not change
    assert_eq!(
        read_pcr_by_alg_id(&mut sim, ALG_SHA1, pcr_idx).unwrap(),
        initial_pcr_null_sha1
    );
}

/// PCR_Event with empty data returns empty-data digests and extends allocated banks with them.
#[test]
fn event_with_empty_data() {
    let mut sim = Tpm::new();

    let pcr_idx = 5usize;
    let initial_sha1 = read_pcr(&mut sim, TpmiAlgHash::Sha1, pcr_idx).unwrap();
    let initial_sha256 = read_pcr(&mut sim, TpmiAlgHash::Sha256, pcr_idx).unwrap();

    // Empty event data
    let event_data = Tpm2bEvent::from_bytes(&[]).unwrap();
    let event_cmd = PCREvent {
        pcr_handle: Handle(pcr_idx as u32),
        event_data,
    };
    // pcrHandle has the USER auth role, so C requires a session even for an empty authValue.
    let resp = execute_tpm_command(&mut sim, &event_cmd, &[pw()]).unwrap();

    // Calculate empty data hashes
    let empty_hash_sha1 = hash(TpmiAlgHash::Sha1, &[]);
    let empty_hash_sha256 = hash(TpmiAlgHash::Sha256, &[]);
    let empty_hash_sha384 = hash(TpmiAlgHash::Sha384, &[]);

    // Verify digests returned match hashes of empty data
    let mut found_sha1 = false;
    let mut found_sha256 = false;
    let mut found_sha384 = false;

    for digest_val in resp.digests.digests() {
        match *digest_val {
            TpmtHa::Sha1(val) => {
                assert_eq!(val, &empty_hash_sha1[..]);
                found_sha1 = true;
            }
            TpmtHa::Sha256(val) => {
                assert_eq!(val, &empty_hash_sha256[..]);
                found_sha256 = true;
            }
            TpmtHa::Sha384(val) => {
                assert_eq!(val, &empty_hash_sha384[..]);
                found_sha384 = true;
            }
            _ => {}
        }
    }

    assert!(found_sha1);
    assert!(found_sha256);
    assert!(found_sha384);

    // Verify PCRs are extended by the empty data digests
    let expected_sha1 = compute_expected_extend(TpmiAlgHash::Sha1, &initial_sha1, &empty_hash_sha1);
    let expected_sha256 =
        compute_expected_extend(TpmiAlgHash::Sha256, &initial_sha256, &empty_hash_sha256);

    assert_eq!(
        read_pcr(&mut sim, TpmiAlgHash::Sha1, pcr_idx).unwrap(),
        expected_sha1
    );
    assert_eq!(
        read_pcr(&mut sim, TpmiAlgHash::Sha256, pcr_idx).unwrap(),
        expected_sha256
    );
    // The default PCR allocation is SHA1+SHA256 only; like C PCRExtend (PCR.c), the
    // unallocated SHA384 bank is not extended (and PCR_Read returns no value for it).
    assert_eq!(read_pcr(&mut sim, TpmiAlgHash::Sha384, pcr_idx), None);
}

/// PCR_Event returns a digest per implemented hash and extends allocated banks; on TPM_RH_NULL nothing is extended
///
/// PCR_Event returns the event digest for every implemented hash and extends
/// the allocated banks; PCR_Event on `TPM_RH_NULL` returns digests without
/// extending anything.
#[test]
fn pcr_event_returns_digests_and_extends_banks() {
    let mut sim = Tpm::new();

    let event_data = b"my test event data";
    let evt_cmd = PCREvent {
        pcr_handle: Handle(1),
        event_data: Tpm2bEvent::from_bytes(event_data).unwrap(),
    };

    // 1. PCR_Event with PCR 1
    let evt_resp = exec(&mut sim, &evt_cmd, &[pw()]).unwrap();

    let expected_sha1_hash = hash_bytes::<20>(TpmiAlgHash::Sha1, event_data);
    let expected_sha256_hash = hash_bytes::<32>(TpmiAlgHash::Sha256, event_data);
    let expected_sha384_hash = hash_bytes::<48>(TpmiAlgHash::Sha384, event_data);

    // C PCR_Event returns one digest per implemented hash (SHA1/256/384/512), PCR_Event.c.
    assert_eq!(evt_resp.digests.count(), 4);
    assert_eq!(
        evt_resp.digests.digests().next().unwrap().digest(),
        &expected_sha1_hash[..]
    );
    assert_eq!(
        evt_resp.digests.digests().nth(1).unwrap().digest(),
        &expected_sha256_hash[..]
    );
    assert_eq!(
        evt_resp.digests.digests().nth(2).unwrap().digest(),
        &expected_sha384_hash[..]
    );

    // Verify PCR 1 was extended
    let mut selection = TpmlPcrSelection::default();
    for alg in [TpmiAlgHash::Sha1, TpmiAlgHash::Sha256, TpmiAlgHash::Sha384] {
        selection
            .add(&TpmsPcrSelection::new(alg, &[2, 0, 0]).unwrap())
            .unwrap(); // PCR 1
    }
    let read_resp = pcr_read(&mut sim, selection).unwrap();

    let expected_sha1_val = expected_extend_sha1(&[0u8; 20], &expected_sha1_hash);
    let expected_sha256_val = expected_extend_sha256(&[0u8; 32], &expected_sha256_hash);
    // The default PCR allocation is SHA1+SHA256; like C (PCRExtend only extends allocated
    // banks, PCRRead/FilterPcr drops unallocated ones, PCR.c), SHA384 is neither extended
    // nor read back.
    assert_eq!(read_resp.pcr_values.count(), 2);
    assert_eq!(
        read_resp.pcr_values.digests()[0].get_buffer(),
        &expected_sha1_val
    );
    assert_eq!(
        read_resp.pcr_values.digests()[1].get_buffer(),
        &expected_sha256_val
    );

    // 2. PCR_Event with RHNull
    let null_resp = exec(
        &mut sim,
        &PCREvent {
            pcr_handle: Handle::RH_NULL,
            ..evt_cmd
        },
        &[pw()],
    )
    .unwrap();
    assert_eq!(null_resp.digests.count(), 4);
    assert_eq!(
        null_resp.digests.digests().next().unwrap().digest(),
        &expected_sha1_hash[..]
    );

    // Verify PCR 1's values have not changed
    let read_resp2 = pcr_read(&mut sim, selection).unwrap();
    assert_eq!(
        read_resp2.pcr_values.digests()[0].get_buffer(),
        &expected_sha1_val
    );
}

/// PCR_Event measurements into PCRs 0,1,2,4,5 (SRTM boot sequence) succeed
#[test]
fn pcr_event_srtm_boot_measurements() {
    let mut sim = Tpm::new();
    for &pcr in &[0, 1, 2, 4, 5] {
        let auth_handle = Handle(pcr);
        let cmd = PCREvent {
            pcr_handle: auth_handle,
            event_data: Tpm2bEvent::from_bytes(b"measurement").unwrap(),
        };
        execute_with_password_sessions_status(&mut sim, &cmd, 1, &[]).unwrap();
    }
}
