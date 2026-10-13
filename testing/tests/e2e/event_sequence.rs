//! TPM2_EventSequenceComplete: PCR extension with per-bank event digests and sequence handle
//! checks.

use crate::_common::{
    allocated_banks_for_pcr, compute_sha256, event_sequence_complete, execute_tpm_command_via_send,
    pcr_update_counter, pw, rc_at, start_hash_sequence, start_sequence,
};
use tpm2::commands::{EventSequenceComplete, PCRRead, SequenceUpdate};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, Tpm2bMaxBuffer, TpmiAlgHash, TpmlPcrSelection, TpmsPcrSelection, TpmtHa};
use tpm2_simulator::create_simulator;

/// EventSequenceComplete extends the PCR with the event digest and returns one digest per implemented hash.
#[test]
fn extends_pcr_with_all_bank_digests() {
    let mut sim = create_simulator!();

    // 1. HashSequenceStart with Null hash algorithm (Event sequence)
    let seq_handle = start_sequence(&mut sim, None);

    // 2. SequenceUpdate with partial data
    let partial_data = b"partial data ";
    let update_cmd = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(partial_data).unwrap(),
    };
    execute_tpm_command_via_send(&mut sim, &update_cmd, &[pw()]).unwrap();

    // 3. EventSequenceComplete with pcrHandle=0, buffer=final_data
    let final_data = b"final data";
    let complete_cmd = EventSequenceComplete {
        pcr_handle: Handle(0),
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(final_data).unwrap(),
    };
    // Both pcrHandle and sequenceHandle need an authorization session in C.
    let complete_resp =
        execute_tpm_command_via_send(&mut sim, &complete_cmd, &[pw(), pw()]).unwrap();

    // Assert PCR 0 equals SHA256(00..00 || SHA256(partial_data || final_data))
    let mut combined = Vec::new();
    combined.extend_from_slice(partial_data);
    combined.extend_from_slice(final_data);
    let event_digest = compute_sha256(&combined);

    let mut extend_input = [0u8; 64];
    extend_input[32..64].copy_from_slice(&event_digest);
    let expected_pcr0 = compute_sha256(&extend_input);

    let mut pcr_selection_in = TpmlPcrSelection::default();
    pcr_selection_in
        .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0x01, 0x00, 0x00]).unwrap())
        .unwrap();
    let pcr_read =
        execute_tpm_command_via_send(&mut sim, &PCRRead { pcr_selection_in }, &[]).unwrap();
    assert_eq!(
        pcr_read.pcr_values.digests()[0].get_buffer(),
        &expected_pcr0
    );

    // C returns one digest per implemented hash (HASH_COUNT = 4: SHA1/256/384/512),
    // EventSequenceComplete.c:52.
    assert_eq!(complete_resp.results.count(), 4);
    assert_eq!(
        *complete_resp.results.digests().nth(1).unwrap(),
        TpmtHa::Sha256(&event_digest)
    );

    // Verify the sequence handle is flushed (`ReferenceH0` on subsequent use as handle 0)
    let bad_update_cmd = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(b"more").unwrap(),
    };
    let err = execute_tpm_command_via_send(&mut sim, &bad_update_cmd, &[]);
    assert_eq!(err.unwrap_err(), TpmRc::REFERENCE_H0.get());

    // Also verify that subsequent use in EventSequenceComplete (handle 1) gives `ReferenceH1`
    let bad_complete_cmd = EventSequenceComplete {
        pcr_handle: Handle(0),
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(b"more").unwrap(),
    };
    let err2 = execute_tpm_command_via_send(&mut sim, &bad_complete_cmd, &[]);
    assert_eq!(err2.unwrap_err(), TpmRc::REFERENCE_H1.get());
}

/// EventSequenceComplete on a hash (non-event) sequence fails with TPM_RC_MODE + H2.
#[test]
fn hash_sequence_handle_returns_mode() {
    let mut sim = create_simulator!();

    // 1. HashSequenceStart with SHA256 (Hash sequence instead of Event sequence)
    let seq_handle = start_sequence(&mut sim, Some(TpmiAlgHash::Sha256));

    // 2. EventSequenceComplete must return TPM_RC_MODE when called on a Hash sequence
    let complete_cmd = EventSequenceComplete {
        pcr_handle: Handle(0),
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(b"final data").unwrap(),
    };
    let res = execute_tpm_command_via_send(&mut sim, &complete_cmd, &[pw(), pw()]);
    // C: TPM_RCS_MODE + RC_EventSequenceComplete_sequenceHandle (0x289),
    // EventSequenceComplete.c:28.
    assert_eq!(
        res.unwrap_err(),
        TpmRc::MODE.with(Position::handle(2)).get()
    );
}

/// EventSequenceComplete validates `sequenceHandle` (Handle 2) first, extends only allocated
/// banks and counts like PCR_Event.
#[test]
fn validates_handle_and_extends_allocated_banks() {
    let mut sim = create_simulator!();

    // A hash (non-event) sequence -> TPM_RC_MODE + RC_H2.
    let seq = start_hash_sequence(&mut sim, Some(TpmiAlgHash::Sha256));
    assert_eq!(
        event_sequence_complete(&mut sim, Handle(16), seq, b"").unwrap_err(),
        rc_at(TpmRc::MODE, Position::handle(2))
    );

    // PCRExtend() changes (and counts) every *allocated* bank of PCR 16 once.
    let allocated_banks = allocated_banks_for_pcr(&mut sim, 16);
    assert!(
        allocated_banks >= 2,
        "default allocation has SHA-1 and SHA-256"
    );

    let ev = start_hash_sequence(&mut sim, None);
    let before = pcr_update_counter(&mut sim);
    event_sequence_complete(&mut sim, Handle(16), ev, b"event").unwrap();
    assert_eq!(pcr_update_counter(&mut sim) - before, allocated_banks);
}
