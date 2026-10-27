//! Event digests of every implemented hash: `TPM2_EventSequenceComplete` returns one digest per
//! implemented hash algorithm (SHA-1, SHA-256, SHA-384 and, with the `sha512` feature, SHA-512;
//! TPM 2.0 Part 3, TPM2_EventSequenceComplete: "the TPM will return a list of digests, one for
//! each implemented hash algorithm"), and an event or DRTM sequence extends each allocated bank
//! exactly once with the digest of its own algorithm. Regressions: a DRTM sequence neither reset
//! nor extended the SHA-512 bank (nor counted that extension in `pcrUpdateCounter`); and without
//! SHA-512, where an event sequence has one hash state fewer, its unused state was used as a
//! second SHA-1 state (`TPM2_EventSequenceComplete` failed with `TPM_RC_SIZE` and the SHA-1 bank
//! was extended twice).

use crate::_common::{
    IMPLEMENTED_HASH_ALGS, client_hash, execute_tpm_command_via_send, hash_data, hash_end,
    hash_start, pcr_allocate, power_cycle, pw, read_pcr_value, start_sequence, startup_raw,
    tpm_reset,
};
use testing::tpm::Tpm;
use tpm2::commands::{EventSequenceComplete, SequenceUpdate};
use tpm2::{Alg, Handle, Tpm2bMaxBuffer, TpmiAlgHash};

/// Allocates every PCR of every implemented bank (effective after the TPM Reset it performs).
fn allocate_all_implemented_banks(sim: &mut Tpm) {
    let banks: Vec<(u16, [u8; 3])> = IMPLEMENTED_HASH_ALGS
        .iter()
        .map(|&alg| (Alg::from(alg).id(), [0xFF, 0xFF, 0xFF]))
        .collect();
    let (rc, rsp) = pcr_allocate(sim, &banks);
    assert_eq!(rc, 0, "TPM2_PCR_Allocate");
    assert_eq!(
        rsp.map(|(success, ..)| success),
        Some(1),
        "allocationSuccess"
    );
    tpm_reset(sim);
}

/// `H(0^n || H(data))`: a PCR of `alg` that was zero, extended once with the digest of `data`.
fn extended_once(alg: TpmiAlgHash, data: &[u8]) -> Vec<u8> {
    let digest = client_hash(alg, data);
    let mut input = vec![0u8; digest.len()];
    input.extend_from_slice(&digest);
    client_hash(alg, &input)
}

/// `TPM2_EventSequenceComplete` returns exactly one digest per implemented hash algorithm, in
/// `TPM_ALG_ID` order, each the digest of the whole event data with that algorithm.
#[test]
fn event_sequence_complete_reports_one_digest_per_implemented_hash() {
    let mut sim = Tpm::new();
    let sequence = start_sequence(&mut sim, None);
    let first = b"event ";
    let last = b"data";
    let update = SequenceUpdate {
        sequence_handle: sequence,
        buffer: Tpm2bMaxBuffer::from_bytes(first).unwrap(),
    };
    execute_tpm_command_via_send(&mut sim, &update, &[pw()]).unwrap();
    let complete = EventSequenceComplete {
        pcr_handle: Handle::RH_NULL,
        sequence_handle: sequence,
        buffer: Tpm2bMaxBuffer::from_bytes(last).unwrap(),
    };
    let rsp = execute_tpm_command_via_send(&mut sim, &complete, &[pw(), pw()]).unwrap();

    let data = [&first[..], &last[..]].concat();
    let digests: Vec<(TpmiAlgHash, Vec<u8>)> = rsp
        .results
        .digests()
        .map(|ha| (ha.hash_alg(), ha.digest().to_vec()))
        .collect();
    let expected: Vec<(TpmiAlgHash, Vec<u8>)> = IMPLEMENTED_HASH_ALGS
        .iter()
        .map(|&alg| (alg, client_hash(alg, &data)))
        .collect();
    assert_eq!(digests, expected);
}

/// With every implemented bank allocated, `TPM2_EventSequenceComplete` extends each bank of the
/// PCR exactly once with the event digest of its algorithm.
#[test]
fn event_sequence_complete_extends_each_allocated_bank_once() {
    let mut sim = Tpm::new();
    allocate_all_implemented_banks(&mut sim);
    let data = b"measured event";
    let sequence = start_sequence(&mut sim, None);
    let complete = EventSequenceComplete {
        pcr_handle: Handle(16),
        sequence_handle: sequence,
        buffer: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
    };
    execute_tpm_command_via_send(&mut sim, &complete, &[pw(), pw()]).unwrap();
    for &alg in IMPLEMENTED_HASH_ALGS {
        assert_eq!(
            read_pcr_value(&mut sim, alg, 16),
            extended_once(alg, data),
            "PCR 16 of {alg:?}"
        );
    }
}

/// With every implemented bank allocated, a DRTM sequence (`_TPM_Hash_Start/Data/End` after
/// `TPM2_Startup`) resets PCR 17 and extends each of its banks exactly once with the digest of
/// the hashed data.
#[test]
fn drtm_sequence_extends_each_allocated_bank_once() {
    let mut sim = Tpm::new();
    allocate_all_implemented_banks(&mut sim);
    let payload = b"DRTM payload";
    hash_start(&mut sim);
    hash_data(&mut sim, payload);
    hash_end(&mut sim);
    for &alg in IMPLEMENTED_HASH_ALGS {
        assert_eq!(
            read_pcr_value(&mut sim, alg, 17),
            extended_once(alg, payload),
            "PCR 17 of {alg:?}"
        );
    }
}

/// With every implemented bank allocated, an H-CRTM sequence before `TPM2_Startup` sets PCR 0 of
/// each bank to its locality-4 initial value (4 in the last octet) and extends it exactly once
/// with the digest of the hashed data.
#[test]
fn hcrtm_sequence_extends_each_allocated_bank_once() {
    let mut sim = Tpm::new();
    allocate_all_implemented_banks(&mut sim);
    power_cycle(&mut sim);
    let payload = b"H-CRTM payload";
    hash_start(&mut sim);
    hash_data(&mut sim, payload);
    hash_end(&mut sim);
    assert_eq!(
        startup_raw(&mut sim, 0, 0x0000),
        0,
        "TPM2_Startup(TPM_SU_CLEAR)"
    );
    for &alg in IMPLEMENTED_HASH_ALGS {
        let digest = client_hash(alg, payload);
        let mut input = vec![0u8; digest.len()];
        *input.last_mut().unwrap() = 4;
        input.extend_from_slice(&digest);
        assert_eq!(
            read_pcr_value(&mut sim, alg, 0),
            client_hash(alg, &input),
            "PCR 0 of {alg:?}"
        );
    }
}
