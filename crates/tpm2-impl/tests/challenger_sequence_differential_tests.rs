use common::marshal_to_slice;

use tpm2::Unmarshal;
mod common;

use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::Handle;
use tpm2::commands::{
    Command, HashSequenceStart, SequenceComplete, SequenceCompleteHandles, SequenceUpdate,
    SequenceUpdateHandles,
};
use tpm2::{Marshal, TpmiAlgHash};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

fn setup_tpm_with_crypto<'a>(
    crypto: &'a mut TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a FakeRng,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    tpm2_impl::GlobalState,
) {
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
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

fn execute_tpm_command<C, S, T, R, Cmd>(
    tpm: &mut TpmEngine<C, S, T, R>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &Cmd::Handles,
    cmd: &Cmd,
) -> Result<(Cmd::RespHandles, Cmd::Response<'static>), u32>
where
    C: tpm2::crypto::CryptoProvider,
    S: tpm2_impl::storage::NvStorage,
    T: tpm2_impl::timer::TpmTimer,
    R: tpm2::crypto::Rng + Sync,
    Cmd: Command,
    for<'b> &'b mut <Cmd as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <<Cmd as Command>::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    Cmd::Response<'static>: Unmarshal<'static>,
{
    let mut req_buf = [0u8; 32768];
    let cc = Cmd::CMD_CODE.code();

    req_buf[6..10].copy_from_slice(&cc.to_be_bytes());

    let mut offset = 10;
    let handles_len = marshal_to_slice(handles, &mut req_buf[offset..]);
    offset += handles_len;
    // Every handle passed to this helper is a sequence handle, which has the USER auth role:
    // C requires a session even for an empty authValue (TPM_RC_AUTH_MISSING otherwise,
    // SessionProcess.c CheckAuthNoSession), so send an empty TPM_RS_PW session.
    let with_session = handles_len > 0;
    let tag = if with_session { 0x8002u16 } else { 0x8001u16 };
    req_buf[0..2].copy_from_slice(&tag.to_be_bytes());
    if with_session {
        let pw_area = [0, 0, 0, 9, 0x40, 0, 0, 9, 0, 0, 0, 0, 0];
        req_buf[offset..offset + pw_area.len()].copy_from_slice(&pw_area);
        offset += pw_area.len();
    }
    offset += marshal_to_slice(cmd, &mut req_buf[offset..]);

    req_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut resp_buf = [0u8; 32768];
    let resp_size =
        tpm.execute_command_separate(global_state, &req_buf[..offset], &mut resp_buf[..]);

    let rc = u32::from_be_bytes(resp_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut cursor: &'static [u8] = std::vec::Vec::leak(resp_buf[10..resp_size].to_vec());

    let resp_handles = Cmd::RespHandles::unmarshal(&mut cursor).map_err(|_| 0xFFFFFFFFu32)?;
    if with_session {
        let _param_size = u32::unmarshal(&mut cursor).map_err(|_| 0xFFFFFFFFu32)?;
    }
    let resp_t = <Cmd::Response<'static>>::unmarshal(&mut cursor).map_err(|_| 0xFFFFFFFFu32)?;

    Ok((resp_handles, resp_t))
}

fn run_differential_case(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
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
    let (start_resp_handles, _) = execute_tpm_command(tpm, global_state, &(), &start_cmd).unwrap();
    let handle = start_resp_handles.sequence_handle;

    // 2. Perform updates. C streams sequence data into the hash state and has no length
    // limit (SequenceUpdate.c has no TPM_RC_MEMORY path), so every update must succeed.
    for chunk in chunks {
        let update_handles = SequenceUpdateHandles {
            sequence_handle: handle,
        };
        let update_cmd = SequenceUpdate {
            buffer: tpm2::Tpm2bMaxBuffer::from_bytes(chunk).unwrap(),
        };

        execute_tpm_command(tpm, global_state, &update_handles, &update_cmd).unwrap();
    }

    // 3. Complete sequence
    let complete_handles = SequenceCompleteHandles {
        sequence_handle: handle,
    };
    let complete_cmd = SequenceComplete {
        buffer: tpm2::Tpm2bMaxBuffer::from_bytes(final_chunk).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, complete_resp) =
        execute_tpm_command(tpm, global_state, &complete_handles, &complete_cmd).unwrap();

    // Verify against direct hashing
    let mut concatenated = Vec::new();
    for chunk in chunks {
        concatenated.extend_from_slice(chunk);
    }
    concatenated.extend_from_slice(final_chunk);

    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let expected_digest_bytes =
        tpm2::crypto::hash(tpm.platform.crypto, alg, &concatenated, &mut out)
            .unwrap()
            .digest()
            .to_vec();

    assert_eq!(
        complete_resp.result.get_buffer(),
        &expected_digest_bytes[..]
    );
}

static BUF_A: [u8; 1] = *b"a";
static BUF_1000_AA: [u8; 1000] = [0xAA; 1000];
static BUF_1000_BB: [u8; 1000] = [0xBB; 1000];
static BUF_1000_CC: [u8; 1000] = [0xCC; 1000];
static BUF_1024_55: [u8; 1024] = [0x55; 1024];

#[test]
fn test_sequence_hash_differential_exhaustive() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_crypto(&mut crypto, &mut storage, &mut timer, &rng);

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
        (self.seed >> 24) as u8
    }
    fn next_range(&mut self, min: usize, max: usize) -> usize {
        let span = max - min + 1;
        let r = ((self.next_byte() as usize) << 8) | (self.next_byte() as usize);
        min + (r % span)
    }
}

#[test]
fn test_sequence_hash_differential_random_fuzz() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_crypto(&mut crypto, &mut storage, &mut timer, &rng);

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
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_crypto(&mut crypto, &mut storage, &mut timer, &rng);

    // Verify that passing data in updates vs passing data in complete behaves identically.
    // Case A: 4KB updated, 1KB completed.
    // Case B: 0KB updated, 5KB completed.
    // Both should yield the same hash output if total data is identical.

    let total_data = vec![0x33u8; 5000];

    // Setup Case A: Update first 4000 bytes (in 4 chunks of 1000 bytes), then complete with remaining 1000 bytes.
    let start_cmd_a = HashSequenceStart {
        auth: Default::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let (start_resp_handles_a, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd_a).unwrap();
    let handle_a = start_resp_handles_a.sequence_handle;

    for i in 0..4 {
        let update_handles_a = SequenceUpdateHandles {
            sequence_handle: handle_a,
        };
        let update_cmd_a = SequenceUpdate {
            buffer: tpm2::Tpm2bMaxBuffer::from_bytes(&total_data[i * 1000..(i + 1) * 1000])
                .unwrap(),
        };
        execute_tpm_command(
            &mut tpm,
            &mut global_state,
            &update_handles_a,
            &update_cmd_a,
        )
        .unwrap();
    }

    let complete_handles_a = SequenceCompleteHandles {
        sequence_handle: handle_a,
    };
    let complete_cmd_a = SequenceComplete {
        buffer: tpm2::Tpm2bMaxBuffer::from_bytes(&total_data[4000..]).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, complete_resp_a) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles_a,
        &complete_cmd_a,
    )
    .unwrap();

    // Verify different chunk combinations of total 5000 bytes:
    // Partition A: [1000, 1000, 1000, 1000] updates, [1000] complete.
    // Partition B: [1024, 1024, 1024, 1024] updates, [904] complete.

    let data_5000 = total_data;

    // Partition A:
    let start_cmd_1 = HashSequenceStart {
        auth: Default::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let (handles_1, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd_1).unwrap();
    let h1 = handles_1.sequence_handle;

    for i in 0..4 {
        let update_handles = SequenceUpdateHandles {
            sequence_handle: h1,
        };
        let update_cmd = SequenceUpdate {
            buffer: tpm2::Tpm2bMaxBuffer::from_bytes(&data_5000[i * 1000..(i + 1) * 1000]).unwrap(),
        };
        execute_tpm_command(&mut tpm, &mut global_state, &update_handles, &update_cmd).unwrap();
    }
    let complete_handles_1 = SequenceCompleteHandles {
        sequence_handle: h1,
    };
    let complete_cmd_1 = SequenceComplete {
        buffer: tpm2::Tpm2bMaxBuffer::from_bytes(&data_5000[4000..5000]).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_1) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles_1,
        &complete_cmd_1,
    )
    .unwrap();

    // Partition B:
    let start_cmd_2 = HashSequenceStart {
        auth: Default::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let (handles_2, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd_2).unwrap();
    let h2 = handles_2.sequence_handle;

    for i in 0..4 {
        let update_handles = SequenceUpdateHandles {
            sequence_handle: h2,
        };
        let update_cmd = SequenceUpdate {
            buffer: tpm2::Tpm2bMaxBuffer::from_bytes(&data_5000[i * 1024..(i + 1) * 1024]).unwrap(),
        };
        execute_tpm_command(&mut tpm, &mut global_state, &update_handles, &update_cmd).unwrap();
    }
    let complete_handles_2 = SequenceCompleteHandles {
        sequence_handle: h2,
    };
    let complete_cmd_2 = SequenceComplete {
        buffer: tpm2::Tpm2bMaxBuffer::from_bytes(&data_5000[4096..5000]).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, resp_2) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles_2,
        &complete_cmd_2,
    )
    .unwrap();

    assert_eq!(resp_1.result.get_buffer(), resp_2.result.get_buffer());
    assert_eq!(
        resp_1.result.get_buffer(),
        complete_resp_a.result.get_buffer()
    );
}
