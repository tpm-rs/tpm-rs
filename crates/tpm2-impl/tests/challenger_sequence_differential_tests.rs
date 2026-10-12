use common::marshal_to_slice;
use tpm2::errors::TpmRc;
use tpm2::{Marshal, Message, TpmiAlgHash, Unmarshal, UnmarshalMessage};
mod common;

use common::TestCryptoProvider;
use common::{FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::Handle;
use tpm2::commands::{Command, HashSequenceStart, SequenceComplete, SequenceUpdate};
use tpm2::crypto::Random;
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

fn setup_tpm_with_crypto<'a>(
    crypto: &'a TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer>,
    tpm2_impl::GlobalState,
) {
    let rng = crypto.rng_seeded(b"challenger_seq_diff").unwrap();
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
    let mut req_buf = [0u8; 32768];
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

    let mut resp_buf = [0u8; 32768];
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

fn run_differential_case(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    alg: TpmiAlgHash,
    chunks: &[&[u8]],
    final_chunk: &[u8],
) {
    // 1. Start sequence
    let start_cmd = HashSequenceStart {
        auth: Default::default(),
        hash_alg: Some(alg),
    };
    let start_resp = execute_tpm_command(tpm, global_state, &start_cmd).unwrap();
    let handle = start_resp.sequence_handle;

    // 2. Perform updates
    let mut total_accumulated = 0;
    let mut hit_limit = false;
    for chunk in chunks {
        let update_cmd = SequenceUpdate {
            sequence_handle: handle,
            buffer: tpm2::Tpm2bMaxBuffer::new(chunk).unwrap(),
        };

        let res = execute_tpm_command(tpm, global_state, &update_cmd);
        total_accumulated += chunk.len();
        if total_accumulated > 4096 {
            assert!(res.is_err());
            assert_eq!(res.unwrap_err() & 0xFF, TpmRc::MEMORY.get() & 0xFF);
            hit_limit = true;
            break;
        } else {
            res.unwrap();
        }
    }

    if hit_limit {
        // Cleanup by completing with empty buffer (even if it's over limit, the TPM allows completion)
        let complete_cmd = SequenceComplete {
            sequence_handle: handle,
            buffer: tpm2::Tpm2bMaxBuffer::default(),
            hierarchy: Handle::RH_NULL,
        };
        let _ = execute_tpm_command(tpm, global_state, &complete_cmd);
        return;
    }

    // 3. Complete sequence
    let complete_cmd = SequenceComplete {
        sequence_handle: handle,
        buffer: tpm2::Tpm2bMaxBuffer::new(final_chunk).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_resp = execute_tpm_command(tpm, global_state, &complete_cmd).unwrap();

    // Verify against direct hashing
    let mut concatenated = Vec::new();
    for chunk in chunks {
        concatenated.extend_from_slice(chunk);
    }
    concatenated.extend_from_slice(final_chunk);

    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let expected_digest_bytes =
        tpm2::crypto::hash(tpm.platform.crypto, alg, &concatenated, &mut out)
            .unwrap()
            .digest()
            .to_vec();

    assert_eq!(complete_resp.result.as_slice(), &expected_digest_bytes[..]);
}

static BUF_A: [u8; 1] = *b"a";
static BUF_1000_AA: [u8; 1000] = [0xAA; 1000];
static BUF_1000_BB: [u8; 1000] = [0xBB; 1000];
static BUF_1000_CC: [u8; 1000] = [0xCC; 1000];
static BUF_1024_55: [u8; 1024] = [0x55; 1024];

#[test]
fn test_sequence_hash_differential_exhaustive() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm_with_crypto(&crypto, &mut storage, &mut timer);

    let algs = [
        TpmiAlgHash::Sha1,
        TpmiAlgHash::Sha256,
        TpmiAlgHash::Sha384,
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
                run_differential_case(&mut tpm, &mut global_state, alg, chunks, final_chunk);
            }
        }
    }
}

struct Lcg {
    seed: u64,
}
impl Lcg {
    fn next_byte(&mut self) -> u8 {
        self.seed = self.seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        u8::try_from((self.seed >> 24) & 0xFF).unwrap()
    }
    fn next_range(&mut self, min: usize, max: usize) -> usize {
        let span = max - min + 1;
        let r = (usize::from(self.next_byte()) << 8) | usize::from(self.next_byte());
        min + (r % span)
    }
}

#[test]
fn test_sequence_hash_differential_random_fuzz() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm_with_crypto(&crypto, &mut storage, &mut timer);

    let algs = [
        TpmiAlgHash::Sha1,
        TpmiAlgHash::Sha256,
        TpmiAlgHash::Sha384,
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

            run_differential_case(&mut tpm, &mut global_state, alg, &chunks_vec, &final_chunk);
        }
    }
}

#[test]
fn test_sequence_complete_slice_passing_correctness() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm_with_crypto(&crypto, &mut storage, &mut timer);

    let total_data = vec![0x33u8; 5000];

    // Setup Case A: Update first 4000 bytes (in 4 chunks of 1000 bytes), then complete with remaining 1000 bytes.
    let start_cmd_a = HashSequenceStart {
        auth: Default::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_resp_a = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd_a).unwrap();
    let handle_a = start_resp_a.sequence_handle;

    for i in 0..4 {
        let update_cmd_a = SequenceUpdate {
            sequence_handle: handle_a,
            buffer: tpm2::Tpm2bMaxBuffer::new(&total_data[i * 1000..(i + 1) * 1000]).unwrap(),
        };
        execute_tpm_command(&mut tpm, &mut global_state, &update_cmd_a).unwrap();
    }

    let complete_cmd_a = SequenceComplete {
        sequence_handle: handle_a,
        buffer: tpm2::Tpm2bMaxBuffer::new(&total_data[4000..]).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_resp_a =
        execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd_a).unwrap();

    // Verify different chunk combinations of total 5000 bytes:
    // Partition A: [1000, 1000, 1000, 1000] updates, [1000] complete.
    // Partition B: [1024, 1024, 1024, 1024] updates, [904] complete.

    let data_5000 = total_data;

    // Partition A:
    let start_cmd_1 = HashSequenceStart {
        auth: Default::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let resp_start_1 = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd_1).unwrap();
    let h1 = resp_start_1.sequence_handle;

    for i in 0..4 {
        let update_cmd = SequenceUpdate {
            sequence_handle: h1,
            buffer: tpm2::Tpm2bMaxBuffer::new(&data_5000[i * 1000..(i + 1) * 1000]).unwrap(),
        };
        execute_tpm_command(&mut tpm, &mut global_state, &update_cmd).unwrap();
    }
    let complete_cmd_1 = SequenceComplete {
        sequence_handle: h1,
        buffer: tpm2::Tpm2bMaxBuffer::new(&data_5000[4000..5000]).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let resp_1 = execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd_1).unwrap();

    // Partition B:
    let start_cmd_2 = HashSequenceStart {
        auth: Default::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let resp_start_2 = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd_2).unwrap();
    let h2 = resp_start_2.sequence_handle;

    for i in 0..4 {
        let update_cmd = SequenceUpdate {
            sequence_handle: h2,
            buffer: tpm2::Tpm2bMaxBuffer::new(&data_5000[i * 1024..(i + 1) * 1024]).unwrap(),
        };
        execute_tpm_command(&mut tpm, &mut global_state, &update_cmd).unwrap();
    }
    let complete_cmd_2 = SequenceComplete {
        sequence_handle: h2,
        buffer: tpm2::Tpm2bMaxBuffer::new(&data_5000[4096..5000]).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let resp_2 = execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd_2).unwrap();

    assert_eq!(resp_1.result.as_slice(), resp_2.result.as_slice());
    assert_eq!(resp_1.result.as_slice(), complete_resp_a.result.as_slice());
}
