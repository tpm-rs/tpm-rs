use common::marshal_to_slice;
use tpm2::errors::TpmRc;
use tpm2::{Marshal, Message, TpmiAlgHash, Unmarshal, UnmarshalMessage};
mod common;

use common::{FakeStorage, FakeTimer, TestCryptoProvider};
use hex_literal::hex;
use tpm2::Handle;
use tpm2::commands::{Command, HashSequenceStart, SequenceComplete, SequenceUpdate};
use tpm2::crypto::Random;
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

fn compute_hash(alg: TpmiAlgHash, data: &[u8]) -> Vec<u8> {
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    tpm2::crypto::hash(&TestCryptoProvider, alg, data, &mut out)
        .unwrap()
        .digest()
        .to_vec()
}

fn setup_tpm_with_crypto<'a>(
    crypto: &'a TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer>,
    tpm2_impl::GlobalState,
) {
    let rng = crypto.rng_seeded(b"challenger_seq").unwrap();
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state).unwrap();
    global_state.nv_available = true;
    global_state.locality = 0;

    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    (tpm, global_state)
}

fn execute_tpm_command<C, S, T, Cmd>(
    tpm: &mut TpmEngine<C, S, T>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &Cmd,
) -> Result<Cmd::Response<'static>, u32>
where
    C: tpm2_impl::Crypto,
    S: tpm2_impl::storage::NvStorage,
    T: tpm2_impl::timer::TpmTimer,
    Cmd: Command,
    for<'b> &'b mut <Cmd as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    Cmd::Response<'static>: UnmarshalMessage<'static>,
{
    let mut req_buf = [0u8; 20000];
    let tag = 0x8001u16;
    let cc = Cmd::CMD_CODE.code();

    req_buf[0..2].copy_from_slice(&tag.to_be_bytes());
    req_buf[6..10].copy_from_slice(&cc.to_be_bytes());

    let mut offset = 10;
    for h in cmd.handles().as_ref() {
        req_buf[offset..offset + 4].copy_from_slice(&h.0.to_be_bytes());
        offset += 4;
    }
    offset += marshal_to_slice(cmd, &mut req_buf[offset..]);

    let total_len = u32::try_from(offset).unwrap();
    req_buf[2..6].copy_from_slice(&total_len.to_be_bytes());

    let mut resp_buf = [0u8; 20000];
    let resp_size =
        tpm.execute_command_separate(global_state, &req_buf[..offset], &mut resp_buf[..]);

    let rc = u32::from_be_bytes(resp_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut cursor: &'static [u8] = std::vec::Vec::leak(resp_buf[10..resp_size].to_vec());

    let mut resp_handles = <Cmd::Response<'static> as Message>::Handles::default();
    for h in resp_handles.as_mut() {
        *h = Handle::unmarshal(&mut cursor).map_err(|_| 0xFFFFFFFFu32)?;
    }
    let resp_t = <Cmd::Response<'static>>::unmarshal_with_handles(resp_handles, &mut cursor)
        .map_err(|_| 0xFFFFFFFFu32)?;

    Ok(resp_t)
}

#[test]
fn test_sequence_hash_sha256() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm_with_crypto(&crypto, &mut storage, &mut timer);

    // 1. Start sequence
    let start_cmd = HashSequenceStart {
        auth: Default::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_resp = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd).unwrap();
    let handle = start_resp.sequence_handle;

    // 2. Update sequence
    let chunk1 = b"Hello, ";
    let update1_cmd = SequenceUpdate {
        sequence_handle: handle,
        buffer: tpm2::Tpm2bMaxBuffer::new(chunk1).unwrap(),
    };
    execute_tpm_command(&mut tpm, &mut global_state, &update1_cmd).unwrap();

    let chunk2 = b"world!";
    let update2_cmd = SequenceUpdate {
        sequence_handle: handle,
        buffer: tpm2::Tpm2bMaxBuffer::new(chunk2).unwrap(),
    };
    execute_tpm_command(&mut tpm, &mut global_state, &update2_cmd).unwrap();

    // 3. Complete sequence
    let final_chunk = b" Sequence Hashing Test.";
    let complete_cmd = SequenceComplete {
        sequence_handle: handle,
        buffer: tpm2::Tpm2bMaxBuffer::new(final_chunk).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_resp = execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd).unwrap();

    // Verify hash digest correctness
    let mut concatenated = Vec::new();
    concatenated.extend_from_slice(chunk1);
    concatenated.extend_from_slice(chunk2);
    concatenated.extend_from_slice(final_chunk);

    let expected_digest = compute_hash(TpmiAlgHash::Sha256, &concatenated);
    assert_eq!(complete_resp.result.as_slice(), &expected_digest[..]);
}

#[test]
fn test_sequence_hash_algorithms() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm_with_crypto(&crypto, &mut storage, &mut timer);

    let test_data = b"Verify multiple hash algorithms supported by TPM 2.0 sequence hashing.";

    // SHA-1
    {
        let start_cmd = HashSequenceStart {
            auth: Default::default(),
            hash_alg: Some(TpmiAlgHash::Sha1),
        };
        let start_resp = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd).unwrap();
        let handle = start_resp.sequence_handle;

        let complete_cmd = SequenceComplete {
            sequence_handle: handle,
            buffer: tpm2::Tpm2bMaxBuffer::new(test_data).unwrap(),
            hierarchy: Handle::RH_NULL,
        };
        let complete_resp =
            execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd).unwrap();

        let expected_digest = compute_hash(TpmiAlgHash::Sha1, test_data);
        assert_eq!(complete_resp.result.as_slice(), &expected_digest[..]);
    }

    // SHA-256
    {
        let start_cmd = HashSequenceStart {
            auth: Default::default(),
            hash_alg: Some(TpmiAlgHash::Sha256),
        };
        let start_resp = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd).unwrap();
        let handle = start_resp.sequence_handle;

        let complete_cmd = SequenceComplete {
            sequence_handle: handle,
            buffer: tpm2::Tpm2bMaxBuffer::new(test_data).unwrap(),
            hierarchy: Handle::RH_NULL,
        };
        let complete_resp =
            execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd).unwrap();

        let expected_digest = compute_hash(TpmiAlgHash::Sha256, test_data);
        assert_eq!(complete_resp.result.as_slice(), &expected_digest[..]);
    }

    // SHA-384
    {
        let start_cmd = HashSequenceStart {
            auth: Default::default(),
            hash_alg: Some(TpmiAlgHash::Sha384),
        };
        let start_resp = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd).unwrap();
        let handle = start_resp.sequence_handle;

        let complete_cmd = SequenceComplete {
            sequence_handle: handle,
            buffer: tpm2::Tpm2bMaxBuffer::new(test_data).unwrap(),
            hierarchy: Handle::RH_NULL,
        };
        let complete_resp =
            execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd).unwrap();

        let expected_digest = compute_hash(TpmiAlgHash::Sha384, test_data);
        assert_eq!(complete_resp.result.as_slice(), &expected_digest[..]);
    }

    // SHA-512
    {
        let start_cmd = HashSequenceStart {
            auth: Default::default(),
            hash_alg: Some(TpmiAlgHash::Sha512),
        };
        let start_resp = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd).unwrap();
        let handle = start_resp.sequence_handle;

        let complete_cmd = SequenceComplete {
            sequence_handle: handle,
            buffer: tpm2::Tpm2bMaxBuffer::new(test_data).unwrap(),
            hierarchy: Handle::RH_NULL,
        };
        let complete_resp =
            execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd).unwrap();

        let expected_digest = compute_hash(TpmiAlgHash::Sha512, test_data);
        assert_eq!(complete_resp.result.as_slice(), &expected_digest[..]);
    }
}

#[test]
fn test_sequence_invalid_algorithm() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm_with_crypto(&crypto, &mut storage, &mut timer);

    // Unsupported algorithm: Sm3_256
    let start_cmd = HashSequenceStart {
        auth: Default::default(),
        hash_alg: Some(TpmiAlgHash::Sm3_256),
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd);
    assert_eq!(
        res.err().map(|rc| rc & 0xFF),
        Some(TpmRc::HASH.to_rc().get() & 0xFF)
    );
}

#[test]
fn test_sequence_invalid_handle() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm_with_crypto(&crypto, &mut storage, &mut timer);

    let invalid_handle = Handle(0x800000FF);

    // Update with invalid handle
    let update_cmd = SequenceUpdate {
        sequence_handle: invalid_handle,
        buffer: tpm2::Tpm2bMaxBuffer::new(b"data").unwrap(),
    };
    let res_update = execute_tpm_command(&mut tpm, &mut global_state, &update_cmd);
    assert_eq!(res_update.err(), Some(TpmRc::REFERENCE_H0.get()));

    // Complete with invalid handle
    let complete_cmd = SequenceComplete {
        sequence_handle: invalid_handle,
        buffer: tpm2::Tpm2bMaxBuffer::new(b"data").unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let res_complete = execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd);
    assert_eq!(res_complete.err(), Some(TpmRc::REFERENCE_H0.get()));
}

#[test]
fn test_sequence_empty_inputs() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm_with_crypto(&crypto, &mut storage, &mut timer);

    // 1. Start sequence
    let start_cmd = HashSequenceStart {
        auth: Default::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_resp = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd).unwrap();
    let handle = start_resp.sequence_handle;

    // 2. Update with 0 bytes
    let update_cmd = SequenceUpdate {
        sequence_handle: handle,
        buffer: tpm2::Tpm2bMaxBuffer::new(&[]).unwrap(),
    };
    execute_tpm_command(&mut tpm, &mut global_state, &update_cmd).unwrap();

    // 3. Complete with 0 bytes
    let complete_cmd = SequenceComplete {
        sequence_handle: handle,
        buffer: tpm2::Tpm2bMaxBuffer::new(&[]).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_resp = execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd).unwrap();

    // Expect hash of empty slice
    let expected_digest = compute_hash(TpmiAlgHash::Sha256, &[]);
    assert_eq!(complete_resp.result.as_slice(), &expected_digest[..]);
}

#[test]
fn test_sequence_complete_invalid_hierarchy() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm_with_crypto(&crypto, &mut storage, &mut timer);

    // 1. Start sequence
    let start_cmd = HashSequenceStart {
        auth: Default::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_resp = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd).unwrap();
    let handle = start_resp.sequence_handle;

    // 2. Complete sequence with invalid hierarchy (e.g. 0x00000000 is not a valid hierarchy)
    let complete_cmd = SequenceComplete {
        sequence_handle: handle,
        buffer: tpm2::Tpm2bMaxBuffer::new(&[]).unwrap(),
        hierarchy: Handle(0x00000000),
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd);
    assert!(res.is_err());
}

#[test]
fn test_sequence_boundary_buffer_size() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm_with_crypto(&crypto, &mut storage, &mut timer);

    let start_cmd = HashSequenceStart {
        auth: Default::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_resp = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd).unwrap();
    let handle = start_resp.sequence_handle;

    let chunk = [0xAAu8; 1024];
    for _ in 0..4 {
        let update_cmd = SequenceUpdate {
            sequence_handle: handle,
            buffer: tpm2::Tpm2bMaxBuffer::new(&chunk).unwrap(),
        };
        execute_tpm_command(&mut tpm, &mut global_state, &update_cmd).unwrap();
    }

    // Try to update one more byte -> total 4097. Expect TpmRc::MEMORY.
    let update_cmd = SequenceUpdate {
        sequence_handle: handle,
        buffer: tpm2::Tpm2bMaxBuffer::new(&[0xBB]).unwrap(),
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &update_cmd);
    assert_eq!(res.err(), Some(TpmRc::MEMORY.get()));
}

#[test]
fn test_sequence_complete_boundary_size() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm_with_crypto(&crypto, &mut storage, &mut timer);

    let start_cmd = HashSequenceStart {
        auth: Default::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_resp = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd).unwrap();
    let handle = start_resp.sequence_handle;

    let chunk = [0xAAu8; 1024];
    for _ in 0..4 {
        let update_cmd = SequenceUpdate {
            sequence_handle: handle,
            buffer: tpm2::Tpm2bMaxBuffer::new(&chunk).unwrap(),
        };
        execute_tpm_command(&mut tpm, &mut global_state, &update_cmd).unwrap();
    }

    let complete_cmd = SequenceComplete {
        sequence_handle: handle,
        buffer: tpm2::Tpm2bMaxBuffer::new(&chunk).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_resp = execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd).unwrap();

    let mut concatenated = Vec::new();
    for _ in 0..5 {
        concatenated.extend_from_slice(&chunk);
    }
    let expected_digest = compute_hash(TpmiAlgHash::Sha256, &concatenated);
    assert_eq!(complete_resp.result.as_slice(), &expected_digest[..]);
}

#[test]
fn test_multiple_sequences_limit() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm_with_crypto(&crypto, &mut storage, &mut timer);

    // Active sequences limit is MAX_ACTIVE_SEQUENCES.
    let mut handles = Vec::new();
    for _ in 0..tpm2_impl::MAX_ACTIVE_SEQUENCES {
        let start_cmd = HashSequenceStart {
            auth: Default::default(),
            hash_alg: Some(TpmiAlgHash::Sha256),
        };
        let start_resp = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd).unwrap();
        handles.push(start_resp.sequence_handle);
    }

    // Try starting one more sequence. Should fail with TpmRc::OBJECT_MEMORY.
    let start_cmd = HashSequenceStart {
        auth: Default::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd);
    assert_eq!(res.err(), Some(TpmRc::OBJECT_MEMORY.get()));

    // Complete one sequence to free up a slot.
    let handle_to_complete = handles.pop().unwrap();
    let complete_cmd = SequenceComplete {
        sequence_handle: handle_to_complete,
        buffer: tpm2::Tpm2bMaxBuffer::new(&[]).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd).unwrap();

    // Now starting a new sequence should succeed.
    let start_resp = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd).unwrap();
    let new_handle = start_resp.sequence_handle;
    assert_ne!(new_handle.0, 0);
}

#[test]
fn test_sequence_update_already_completed() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm_with_crypto(&crypto, &mut storage, &mut timer);

    let start_cmd = HashSequenceStart {
        auth: Default::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_resp = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd).unwrap();
    let handle = start_resp.sequence_handle;

    let complete_cmd = SequenceComplete {
        sequence_handle: handle,
        buffer: tpm2::Tpm2bMaxBuffer::new(b"data").unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd).unwrap();

    // Now try to update it again. Should fail with TpmRc::REFERENCE_H0.
    let update_cmd = SequenceUpdate {
        sequence_handle: handle,
        buffer: tpm2::Tpm2bMaxBuffer::new(b"more data").unwrap(),
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &update_cmd);
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H0.get()));

    // Now try to complete it again. Should fail with TpmRc::REFERENCE_H0.
    let res_complete = execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd);
    assert_eq!(res_complete.err(), Some(TpmRc::REFERENCE_H0.get()));
}

#[test]
fn test_interleaved_sequences() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm_with_crypto(&crypto, &mut storage, &mut timer);

    // Start Sequence A (SHA256)
    let start_cmd_a = HashSequenceStart {
        auth: Default::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_resp_a = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd_a).unwrap();
    let handle_a = start_resp_a.sequence_handle;

    // Start Sequence B (SHA512)
    let start_cmd_b = HashSequenceStart {
        auth: Default::default(),
        hash_alg: Some(TpmiAlgHash::Sha512),
    };
    let start_resp_b = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd_b).unwrap();
    let handle_b = start_resp_b.sequence_handle;

    // Update Sequence A
    let update_cmd_a1 = SequenceUpdate {
        sequence_handle: handle_a,
        buffer: tpm2::Tpm2bMaxBuffer::new(b"Sequence A: Part 1. ").unwrap(),
    };
    execute_tpm_command(&mut tpm, &mut global_state, &update_cmd_a1).unwrap();

    // Update Sequence B
    let update_cmd_b1 = SequenceUpdate {
        sequence_handle: handle_b,
        buffer: tpm2::Tpm2bMaxBuffer::new(b"Sequence B: Part 1. ").unwrap(),
    };
    execute_tpm_command(&mut tpm, &mut global_state, &update_cmd_b1).unwrap();

    // Update Sequence A again
    let update_cmd_a2 = SequenceUpdate {
        sequence_handle: handle_a,
        buffer: tpm2::Tpm2bMaxBuffer::new(b"Sequence A: Part 2.").unwrap(),
    };
    execute_tpm_command(&mut tpm, &mut global_state, &update_cmd_a2).unwrap();

    // Complete Sequence B
    let complete_cmd_b = SequenceComplete {
        sequence_handle: handle_b,
        buffer: tpm2::Tpm2bMaxBuffer::new(b"Sequence B: Final.").unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_resp_b =
        execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd_b).unwrap();

    // Complete Sequence A
    let complete_cmd_a = SequenceComplete {
        sequence_handle: handle_a,
        buffer: tpm2::Tpm2bMaxBuffer::new(b"Sequence A: Final.").unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_resp_a =
        execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd_a).unwrap();

    // Verify digests
    let expected_a = compute_hash(
        TpmiAlgHash::Sha256,
        b"Sequence A: Part 1. Sequence A: Part 2.Sequence A: Final.",
    );
    assert_eq!(complete_resp_a.result.as_slice(), &expected_a[..]);

    let expected_b = compute_hash(
        TpmiAlgHash::Sha512,
        b"Sequence B: Part 1. Sequence B: Final.",
    );
    assert_eq!(complete_resp_b.result.as_slice(), &expected_b[..]);
}

#[test]
fn test_sequence_hashing_differential_fuzzing() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm_with_crypto(&crypto, &mut storage, &mut timer);

    let algs = [
        (TpmiAlgHash::Sha1, 20),
        (TpmiAlgHash::Sha256, 32),
        (TpmiAlgHash::Sha384, 48),
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
            let total_size = usize::try_from(pseudo_rng() % 5000 + 1).unwrap();
            let mut payload = vec![0u8; total_size];
            for byte in payload.iter_mut() {
                *byte = u8::try_from(pseudo_rng() & 0xFF).unwrap();
            }

            // Decide how to split the payload. The accumulated update buffer must not exceed 4096 bytes.
            // Let's split into updates of up to 1024 bytes.
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
            let start_cmd = HashSequenceStart {
                auth: Default::default(),
                hash_alg: Some(alg),
            };
            let start_resp = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd).unwrap();
            let handle = start_resp.sequence_handle;

            // Run updates
            let mut update_offset = 0;
            while update_offset < update_data.len() {
                let chunk_size = std::cmp::min(1024, update_data.len() - update_offset);
                let update_cmd = SequenceUpdate {
                    sequence_handle: handle,
                    buffer: tpm2::Tpm2bMaxBuffer::new(
                        &update_data[update_offset..update_offset + chunk_size],
                    )
                    .unwrap(),
                };
                execute_tpm_command(&mut tpm, &mut global_state, &update_cmd).unwrap();
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
                buffer: tpm2::Tpm2bMaxBuffer::new(final_chunk).unwrap(),
                hierarchy: Handle::RH_NULL,
            };
            let complete_resp =
                execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd).unwrap();

            // Oracle reference hash computation (using TestCryptoProvider)
            let expected_digest = compute_hash(alg, &payload);
            assert_eq!(expected_digest.len(), digest_size);
            assert_eq!(complete_resp.result.as_slice(), &expected_digest[..]);
        }
    }
}
