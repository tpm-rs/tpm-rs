//! Hash sequences (HashSequenceStart / SequenceUpdate / SequenceComplete) producing correct digests
//! and tickets for all inputs.

use crate::_common::{
    BUF_1000_AA, BUF_1000_BB, BUF_1000_CC, BUF_1024_55, BUF_A, CONTEXT_INTEGRITY_DIGEST_SIZE, Lcg,
    STRONGEST_HASH_ALG, compute_hash_single, compute_sha256, execute_tpm_command_auto_pw_unwrap,
    execute_tpm_command_via_send, is_null_hashcheck, pw, rc_at, run_differential_case,
    run_hash_sequence, sequence_complete, sequence_update, sha256_sequence, start_hash_sequence,
    start_sequence, start_sequence_alg,
};
use testing::tpm::Tpm;
use tpm2::commands::{ContextLoad, ContextSave, FlushContext, SequenceComplete, SequenceUpdate};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, Tpm2bMaxBuffer, TpmiAlgHash};

/// Hash sequences over empty/single/many/large chunk sets match a reference digest.
#[test]
fn chunked_inputs_match_reference() {
    let mut sim = Tpm::new();

    let algs = [
        TpmiAlgHash::Sha1,
        TpmiAlgHash::Sha256,
        TpmiAlgHash::Sha384,
        #[cfg(feature = "sha512")]
        TpmiAlgHash::Sha512,
    ];

    // Let's generate a list of chunk sets of various sizes
    let chunk_scenarios: &[&[&[u8]]] = &[
        // Scenario 1: Empty input
        &[],
        // Scenario 2: Single chunk
        &[b"hello"],
        // Scenario 3: Multiple small chunks
        &[b"hello", b" ", b"world", b"!"],
        // Scenario 4: Many small chunks
        &[&BUF_A[..]; 100],
        // Scenario 5: Large chunks (exactly matching block size boundaries or arbitrary)
        &[&BUF_1000_AA[..], &BUF_1000_BB[..], &BUF_1000_CC[..]],
        // Scenario 6: Mixed empty and non-empty chunks
        &[b"", b"data", b"", b"more data", b""],
        // Scenario 7: Exactly 4096 bytes accumulated
        &[&BUF_1024_55[..]; 4],
    ];

    let final_chunks: &[&[u8]] = &[
        b"",
        b"final",
        &[0x99; 100],
        &[0xFF; 1024], // Max final chunk size
    ];

    for &alg in &algs {
        for &chunks in chunk_scenarios {
            for &final_chunk in final_chunks {
                run_differential_case(&mut sim, alg, chunks, final_chunk);
            }
        }
    }
}

/// TPM2_SequenceComplete with a maximum-size final buffer produces the correct digest
#[test]
fn complete_with_max_buffer() {
    let mut sim = Tpm::new();

    let handle = start_sequence_alg(&mut sim, TpmiAlgHash::Sha256);

    let chunk = [0xAAu8; 1024];
    for _ in 0..4 {
        let update_cmd = SequenceUpdate {
            sequence_handle: handle,
            buffer: Tpm2bMaxBuffer::from_bytes(&chunk).unwrap(),
        };
        execute_tpm_command_auto_pw_unwrap(&mut sim, &update_cmd).unwrap();
    }

    let complete_cmd = SequenceComplete {
        sequence_handle: handle,
        buffer: Tpm2bMaxBuffer::from_bytes(&chunk).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_resp = execute_tpm_command_auto_pw_unwrap(&mut sim, &complete_cmd).unwrap();

    let mut concatenated = Vec::new();
    for _ in 0..5 {
        concatenated.extend_from_slice(&chunk);
    }
    let expected_digest = compute_hash_single(TpmiAlgHash::Sha256, &concatenated);
    assert_eq!(complete_resp.result.get_buffer(), &expected_digest[..]);
}

/// Completing a sequence with no data returns the digest of the empty string.
#[test]
fn complete_without_update_digest() {
    let mut sim = Tpm::new();

    let seq_handle = start_sequence(&mut sim, Some(TpmiAlgHash::Sha256));

    let complete_cmd = SequenceComplete {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_resp = execute_tpm_command_via_send(&mut sim, &complete_cmd, &[pw()]).unwrap();

    let digest = compute_sha256(b"");
    assert_eq!(complete_resp.result.get_buffer(), &digest);
}

/// A hash sequence saved, flushed and reloaded mid-stream completes with the correct digest.
#[test]
fn context_save_load_preserves_state() {
    let mut sim = Tpm::new();

    // 1. Start a SHA-256 hash sequence
    let seq_handle = start_sequence(&mut sim, Some(TpmiAlgHash::Sha256));

    // 2. Feed > 1 block (100 bytes) of data via SequenceUpdate
    let part1 = [0x42u8; 100];
    let update_cmd = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(&part1).unwrap(),
    };
    execute_tpm_command_via_send(&mut sim, &update_cmd, &[pw()]).unwrap();

    // 3. ContextSave the in-flight sequence (which serializes the live hash state)
    let save_rsp = execute_tpm_command_via_send(
        &mut sim,
        &ContextSave {
            save_handle: seq_handle,
        },
        &[],
    )
    .unwrap();

    // 4. Flush the sequence handle from active memory
    let flush_cmd = FlushContext {
        flush_handle: seq_handle,
    };
    execute_tpm_command_via_send(&mut sim, &flush_cmd, &[]).unwrap();

    // 5. ContextLoad the saved sequence context blob
    let load_cmd = ContextLoad {
        context: save_rsp.context,
    };
    let load_resp_handles = execute_tpm_command_via_send(&mut sim, &load_cmd, &[]).unwrap();
    let restored_handle = load_resp_handles.loaded_handle;

    // 6. Complete the sequence with part2 (50 bytes)
    let part2 = [0x99u8; 50];
    let complete_cmd = SequenceComplete {
        sequence_handle: restored_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(&part2).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_rsp = execute_tpm_command_via_send(&mut sim, &complete_cmd, &[pw()]).unwrap();

    // 7. Verify the digest matches hashing (part1 || part2) in a single pass
    let mut combined = [0u8; 150];
    combined[..100].copy_from_slice(&part1);
    combined[100..].copy_from_slice(&part2);
    let expected = compute_sha256(&combined);
    assert_eq!(complete_rsp.result.get_buffer(), &expected);
}

/// A hash sequence accepts more than 4096 bytes and still completes.
#[test]
fn data_beyond_4096_bytes_accepted() {
    let mut sim = Tpm::new();

    // Feed 4096 bytes into a sequence.
    let seq_handle = start_sequence(&mut sim, Some(TpmiAlgHash::Sha256));

    let chunk = [0u8; 1024];
    let update_cmd = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(&chunk).unwrap(),
    };

    // Update 4 times -> 4096 bytes
    for _ in 0..4 {
        execute_tpm_command_via_send(&mut sim, &update_cmd, &[pw()]).unwrap();
    }

    // Update 1 more byte. C streams sequence data into the hash state and has no
    // buffer limit (SequenceUpdate.c returns only MODE/auth errors), so this succeeds.
    let update_cmd_small = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(&[1]).unwrap(),
    };
    let update_res = execute_tpm_command_via_send(&mut sim, &update_cmd_small, &[pw()]);
    assert!(update_res.is_ok());

    // Verify we can still complete the sequence
    let complete_cmd = SequenceComplete {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_res = execute_tpm_command_via_send(&mut sim, &complete_cmd, &[pw()]);
    assert!(complete_res.is_ok());
}

/// Hash sequences produce correct digests for every supported hash alg
#[test]
fn digest_for_every_hash_alg() {
    let mut sim = Tpm::new();

    let test_data =
        b"Verify multiple hash algorithms supported by TPM (2 as u16) sequence hashing.";

    for alg in [
        TpmiAlgHash::Sha1,
        TpmiAlgHash::Sha256,
        TpmiAlgHash::Sha384,
        #[cfg(feature = "sha512")]
        TpmiAlgHash::Sha512,
    ] {
        let handle = start_sequence_alg(&mut sim, alg);

        let complete_cmd = SequenceComplete {
            sequence_handle: handle,
            buffer: Tpm2bMaxBuffer::from_bytes(test_data).unwrap(),
            hierarchy: Handle::RH_NULL,
        };
        let complete_resp = execute_tpm_command_auto_pw_unwrap(&mut sim, &complete_cmd).unwrap();

        let expected_digest = compute_hash_single(alg, test_data);
        assert_eq!(complete_resp.result.get_buffer(), &expected_digest[..]);
    }
}

/// A hash sequence with empty update and complete buffers yields the hash of the empty string
#[test]
fn empty_update_and_complete_digest() {
    let mut sim = Tpm::new();

    // 1. Start sequence
    let handle = start_sequence_alg(&mut sim, TpmiAlgHash::Sha256);

    // 2. Update with 0 bytes
    let update_cmd = SequenceUpdate {
        sequence_handle: handle,
        buffer: Tpm2bMaxBuffer::from_bytes(&[]).unwrap(),
    };
    execute_tpm_command_auto_pw_unwrap(&mut sim, &update_cmd).unwrap();

    // 3. Complete with 0 bytes
    let complete_cmd = SequenceComplete {
        sequence_handle: handle,
        buffer: Tpm2bMaxBuffer::from_bytes(&[]).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_resp = execute_tpm_command_auto_pw_unwrap(&mut sim, &complete_cmd).unwrap();

    // Expect hash of empty slice
    let expected_digest = compute_hash_single(TpmiAlgHash::Sha256, &[]);
    assert_eq!(complete_resp.result.get_buffer(), &expected_digest[..]);
}

/// Interleaved SHA-256 and SHA-512 sequences produce independent correct digests
#[test]
fn interleaved_sequences() {
    let mut sim = Tpm::new();

    // Start Sequence A (SHA256)
    let handle_a = start_sequence_alg(&mut sim, TpmiAlgHash::Sha256);

    // Start Sequence B (SHA512; SHA384 without the `sha512` feature)
    let handle_b = start_sequence_alg(&mut sim, STRONGEST_HASH_ALG);

    // Update Sequence A
    let update_cmd_a1 = SequenceUpdate {
        sequence_handle: handle_a,
        buffer: Tpm2bMaxBuffer::from_bytes(b"Sequence A: Part 1. ").unwrap(),
    };
    execute_tpm_command_auto_pw_unwrap(&mut sim, &update_cmd_a1).unwrap();

    // Update Sequence B
    let update_cmd_b1 = SequenceUpdate {
        sequence_handle: handle_b,
        buffer: Tpm2bMaxBuffer::from_bytes(b"Sequence B: Part 1. ").unwrap(),
    };
    execute_tpm_command_auto_pw_unwrap(&mut sim, &update_cmd_b1).unwrap();

    // Update Sequence A again
    let update_cmd_a2 = SequenceUpdate {
        sequence_handle: handle_a,
        buffer: Tpm2bMaxBuffer::from_bytes(b"Sequence A: Part 2.").unwrap(),
    };
    execute_tpm_command_auto_pw_unwrap(&mut sim, &update_cmd_a2).unwrap();

    // Complete Sequence B
    let complete_cmd_b = SequenceComplete {
        sequence_handle: handle_b,
        buffer: Tpm2bMaxBuffer::from_bytes(b"Sequence B: Final.").unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_resp_b = execute_tpm_command_auto_pw_unwrap(&mut sim, &complete_cmd_b).unwrap();

    // Complete Sequence A
    let complete_cmd_a = SequenceComplete {
        sequence_handle: handle_a,
        buffer: Tpm2bMaxBuffer::from_bytes(b"Sequence A: Final.").unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_resp_a = execute_tpm_command_auto_pw_unwrap(&mut sim, &complete_cmd_a).unwrap();

    // Verify digests
    let expected_a = compute_hash_single(
        TpmiAlgHash::Sha256,
        b"Sequence A: Part 1. Sequence A: Part 2.Sequence A: Final.",
    );
    assert_eq!(complete_resp_a.result.get_buffer(), &expected_a[..]);

    let expected_b = compute_hash_single(
        STRONGEST_HASH_ALG,
        b"Sequence B: Part 1. Sequence B: Final.",
    );
    assert_eq!(complete_resp_b.result.get_buffer(), &expected_b[..]);
}

/// Randomized chunk counts/sizes (incl. oversized) match the reference or are rejected like C.
#[test]
fn random_chunks_match_reference() {
    let mut sim = Tpm::new();

    let algs = [
        TpmiAlgHash::Sha1,
        TpmiAlgHash::Sha256,
        TpmiAlgHash::Sha384,
        #[cfg(feature = "sha512")]
        TpmiAlgHash::Sha512,
    ];

    let mut lcg = Lcg { seed: 42 };

    for &alg in &algs {
        for _ in 0..50 {
            // Generate a random number of chunks (0 to 15)
            let num_chunks = lcg.next_range(0, 15);
            let mut chunks_vec = Vec::new();
            let mut chunks_data = Vec::new();
            let mut accumulated = 0;

            for _ in 0..num_chunks {
                // Size of each chunk between 0 and 1024 bytes (or keeping under the limit)
                let chunk_size = lcg.next_range(0, 1024);
                // Keep it under limit mostly, but allow some to exceed to test rejection
                if accumulated + chunk_size > 8300 {
                    break;
                }
                let mut chunk = vec![0u8; chunk_size];
                for b in &mut chunk {
                    *b = lcg.next_byte();
                }
                accumulated += chunk_size;
                chunks_data.push(chunk);
            }

            for c in &chunks_data {
                chunks_vec.push(c.as_slice());
            }

            // Generate a random final chunk
            let final_chunk_size = lcg.next_range(0, 1024);
            let mut final_chunk = vec![0u8; final_chunk_size];
            for b in &mut final_chunk {
                *b = lcg.next_byte();
            }

            run_differential_case(&mut sim, alg, &chunks_vec, &final_chunk);
        }
    }
}

/// Seeded random payloads split randomly across updates and complete match a local reference hash
#[test]
fn random_splits_match_reference() {
    let mut sim = Tpm::new();

    let algs = [
        (TpmiAlgHash::Sha1, 20),
        (TpmiAlgHash::Sha256, 32),
        (TpmiAlgHash::Sha384, 48),
        #[cfg(feature = "sha512")]
        (TpmiAlgHash::Sha512, 64),
    ];

    // Seeded pseudo-random generation for deterministic differential fuzzing
    let mut seed_val = 0x12345678u32;
    let mut pseudo_rng = || {
        seed_val = seed_val.wrapping_mul(1103515245).wrapping_add(12345);
        (seed_val / 65536) % 32768
    };

    for (alg, digest_size) in algs {
        for iteration in 0..50 {
            // Generate a random payload up to 5KB (so it fits in 4096 updates + 1024 completion)
            let total_size = (pseudo_rng() as usize) % 5000 + 1;
            let mut payload = vec![0u8; total_size];
            for byte in payload.iter_mut() {
                *byte = pseudo_rng() as u8;
            }

            // Decide how to split the payload. The accumulated update buffer must not exceed
            // 4096 bytes. Split into updates of up to 1024 bytes.
            let mut offset = 0;
            let mut update_data = Vec::new();
            while offset < payload.len() {
                // If remaining is small or we already have accumulated 4096, we must stop updates.
                if update_data.len() >= 4096 || payload.len() - offset <= 1024 {
                    break;
                }
                let chunk_size = std::cmp::min(1024, 4096 - update_data.len());
                if chunk_size == 0 {
                    break;
                }
                update_data.extend_from_slice(&payload[offset..offset + chunk_size]);
                offset += chunk_size;
            }

            // Start sequence
            let handle = start_sequence_alg(&mut sim, alg);

            // Run updates
            let mut update_offset = 0;
            while update_offset < update_data.len() {
                let chunk_size = std::cmp::min(1024, update_data.len() - update_offset);
                let update_cmd = SequenceUpdate {
                    sequence_handle: handle,
                    buffer: Tpm2bMaxBuffer::from_bytes(
                        &update_data[update_offset..update_offset + chunk_size],
                    )
                    .unwrap(),
                };
                execute_tpm_command_auto_pw_unwrap(&mut sim, &update_cmd).unwrap();
                update_offset += chunk_size;
            }

            // The rest goes to the final chunk in SequenceComplete (up to 1024 bytes)
            let final_chunk = &payload[offset..];
            assert!(
                final_chunk.len() <= 1024,
                "Iteration {} failed partition logic: final chunk size is {}",
                iteration,
                final_chunk.len()
            );

            let complete_cmd = SequenceComplete {
                sequence_handle: handle,
                buffer: Tpm2bMaxBuffer::from_bytes(final_chunk).unwrap(),
                hierarchy: Handle::RH_NULL,
            };
            let complete_resp =
                execute_tpm_command_auto_pw_unwrap(&mut sim, &complete_cmd).unwrap();

            // Oracle reference hash computation (client-side crypto)
            let expected_digest = compute_hash_single(alg, &payload);
            assert_eq!(expected_digest.len(), digest_size);
            assert_eq!(complete_resp.result.get_buffer(), &expected_digest[..]);
        }
    }
}

/// Hash sequences with SHA-1/SHA-384/SHA-512 in the Null and Owner
/// hierarchies. The Go tests only cover SHA-256.
#[test]
fn sha1_sha384_sha512_sequences() {
    let mut sim = Tpm::new();
    let password = "password";
    let buffer_sizes = [512, 1024, 2048, 4096];
    let hash_algs = [
        TpmiAlgHash::Sha1,
        TpmiAlgHash::Sha384,
        #[cfg(feature = "sha512")]
        TpmiAlgHash::Sha512,
    ];

    for &size in &buffer_sizes {
        for &alg in &hash_algs {
            run_hash_sequence(&mut sim, size, password, Handle::RH_NULL, alg);
            run_hash_sequence(&mut sim, size, password, Handle::RH_OWNER, alg);
        }
    }
}

/// HashSequenceStart/SequenceUpdate/SequenceComplete with SHA-256 produces the correct digest
#[test]
fn sha256_digest() {
    let mut sim = Tpm::new();

    // 1. Start sequence
    let handle = start_sequence_alg(&mut sim, TpmiAlgHash::Sha256);

    // 2. Update sequence
    let chunk1 = b"Hello, ";
    let update1_cmd = SequenceUpdate {
        sequence_handle: handle,
        buffer: Tpm2bMaxBuffer::from_bytes(chunk1).unwrap(),
    };
    execute_tpm_command_auto_pw_unwrap(&mut sim, &update1_cmd).unwrap();

    let chunk2 = b"world!";
    let update2_cmd = SequenceUpdate {
        sequence_handle: handle,
        buffer: Tpm2bMaxBuffer::from_bytes(chunk2).unwrap(),
    };
    execute_tpm_command_auto_pw_unwrap(&mut sim, &update2_cmd).unwrap();

    // 3. Complete sequence
    let final_chunk = b" Sequence Hashing Test.";
    let complete_cmd = SequenceComplete {
        sequence_handle: handle,
        buffer: Tpm2bMaxBuffer::from_bytes(final_chunk).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_resp = execute_tpm_command_auto_pw_unwrap(&mut sim, &complete_cmd).unwrap();

    // Verify hash digest correctness
    let mut concatenated = Vec::new();
    concatenated.extend_from_slice(chunk1);
    concatenated.extend_from_slice(chunk2);
    concatenated.extend_from_slice(final_chunk);

    let expected_digest = compute_hash_single(TpmiAlgHash::Sha256, &concatenated);
    assert_eq!(complete_resp.result.get_buffer(), &expected_digest[..]);
}

/// HashSequenceStart/SequenceUpdate/SequenceComplete produce the SHA-256 digest of the data.
#[test]
fn sha256_digest_matches() {
    let mut sim = Tpm::new();

    // 1. HashSequenceStart
    let seq_handle = start_sequence(&mut sim, Some(TpmiAlgHash::Sha256));

    // 2. SequenceUpdate
    let data1 = b"Hello, ";
    let update_cmd = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(data1).unwrap(),
    };
    execute_tpm_command_via_send(&mut sim, &update_cmd, &[pw()]).unwrap();

    // 3. SequenceComplete
    let data2 = b"World!";
    let complete_cmd = SequenceComplete {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(data2).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_resp = execute_tpm_command_via_send(&mut sim, &complete_cmd, &[pw()]).unwrap();

    // Verify hash output
    let digest = compute_sha256(b"Hello, World!");
    assert_eq!(complete_resp.result.get_buffer(), &digest);
}

/// `TicketIsSafe` is applied to the first data block only: a short first block (or a short
/// total) yields the NULL ticket; a safe first block yields a real ticket.
#[test]
fn ticket_safety_from_first_block() {
    let mut sim = Tpm::new();

    // First block shorter than 4 bytes.
    let seq = start_hash_sequence(&mut sim, Some(TpmiAlgHash::Sha256));
    sequence_update(&mut sim, seq, b"ab").unwrap();
    let ticket = sequence_complete(&mut sim, seq, b"cdefgh", Handle::RH_OWNER).unwrap();
    assert!(
        is_null_hashcheck(&ticket),
        "short first block must not get a ticket"
    );

    // Total data shorter than 4 bytes, no SequenceUpdate.
    let seq = start_hash_sequence(&mut sim, Some(TpmiAlgHash::Sha256));
    let ticket = sequence_complete(&mut sim, seq, b"abc", Handle::RH_OWNER).unwrap();
    assert!(is_null_hashcheck(&ticket));

    // Empty first block.
    let seq = start_hash_sequence(&mut sim, Some(TpmiAlgHash::Sha256));
    sequence_update(&mut sim, seq, b"").unwrap();
    let ticket = sequence_complete(&mut sim, seq, b"abcdefgh", Handle::RH_OWNER).unwrap();
    assert!(is_null_hashcheck(&ticket));

    // Safe first block -> real ticket.
    let seq = start_hash_sequence(&mut sim, Some(TpmiAlgHash::Sha256));
    sequence_update(&mut sim, seq, b"abcd").unwrap();
    let ticket = sequence_complete(&mut sim, seq, b"\xffTCG", Handle::RH_OWNER).unwrap();
    assert_eq!(ticket.hierarchy(), Handle::RH_OWNER);
    assert_eq!(
        ticket.digest().get_size() as usize,
        CONTEXT_INTEGRITY_DIGEST_SIZE
    );

    // SequenceComplete on an event sequence -> TPM_RC_MODE + RC_H1.
    let ev = start_hash_sequence(&mut sim, None);
    assert_eq!(
        sequence_complete(&mut sim, ev, b"", Handle::RH_NULL).unwrap_err(),
        rc_at(TpmRc::MODE, Position::handle(1))
    );
}

/// SequenceUpdate data beyond 4096 accumulated bytes is accepted (no TPM_RC_MEMORY limit)
#[test]
fn update_beyond_4096_bytes() {
    let mut sim = Tpm::new();

    let handle = start_sequence_alg(&mut sim, TpmiAlgHash::Sha256);

    let chunk = [0xAAu8; 1024];
    for _ in 0..4 {
        let update_cmd = SequenceUpdate {
            sequence_handle: handle,
            buffer: Tpm2bMaxBuffer::from_bytes(&chunk).unwrap(),
        };
        execute_tpm_command_auto_pw_unwrap(&mut sim, &update_cmd).unwrap();
    }

    // Update one more byte -> total 4097. C streams sequence data into the hash state and has
    // no length limit (SequenceUpdate.c has no TPM_RC_MEMORY path), so this succeeds.
    let update_cmd = SequenceUpdate {
        sequence_handle: handle,
        buffer: Tpm2bMaxBuffer::from_bytes(&[0xBB]).unwrap(),
    };
    let res = execute_tpm_command_auto_pw_unwrap(&mut sim, &update_cmd);
    assert_eq!(res.err(), None);
}

/// Splitting 5000 bytes between SequenceUpdate and SequenceComplete yields the same SHA-256 digest.
#[test]
fn update_complete_split_equivalence() {
    let mut sim = Tpm::new();

    // Verify that passing data in updates vs passing data in complete behaves identically.
    // Case A: 4KB updated, 1KB completed.
    // Case B: 0KB updated, 5KB completed.
    // Both should yield the same hash output if total data is identical.

    let total_data = vec![0x33u8; 5000];

    // Setup Case A: Update first 4000 bytes (in 4 chunks of 1000 bytes), then complete with remaining 1000 bytes.
    let thousands: Vec<(usize, usize)> = (0..4).map(|i| (i * 1000, (i + 1) * 1000)).collect();
    let complete_resp_a = sha256_sequence(&mut sim, &total_data, &thousands, 4000);

    // Verify different chunk combinations of total 5000 bytes:
    // Partition A: [1000, 1000, 1000, 1000] updates, [1000] complete.
    // Partition B: [1024, 1024, 1024, 1024] updates, [904] complete.

    let data_5000 = total_data;

    // Partition A:
    let resp_1 = sha256_sequence(&mut sim, &data_5000, &thousands, 4000);

    // Partition B:
    let kibs: Vec<(usize, usize)> = (0..4).map(|i| (i * 1024, (i + 1) * 1024)).collect();
    let resp_2 = sha256_sequence(&mut sim, &data_5000, &kibs, 4096);

    assert_eq!(resp_1, resp_2);
    assert_eq!(resp_1, complete_resp_a);
}
