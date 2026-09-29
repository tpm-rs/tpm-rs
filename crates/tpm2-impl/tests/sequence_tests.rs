use common::marshal_to_slice;
use tpm2::errors::{Position, TpmRc};

use tpm2::{Marshal, Unmarshal};
mod common;

use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::Handle;
use tpm2::commands::{
    Command, EventSequenceComplete, EventSequenceCompleteHandles, FlushContext, Hash,
    HashSequenceStart, SequenceComplete, SequenceCompleteHandles, SequenceUpdate,
    SequenceUpdateHandles,
};

use common::TestCryptoProvider;
use tpm2::{Tpm2bAuth, Tpm2bMaxBuffer, TpmaSession, TpmiAlgHash, TpmsAuthCommand};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

fn compute_sha256(crypto: &TestCryptoProvider, data: &[u8]) -> [u8; 32] {
    use tpm2::crypto::{Finalize as _, Hash as _, Update as _};
    let mut ctx = crypto.sha256().unwrap();
    ctx.update(data).unwrap();
    let mut digest = [0u8; 32];
    ctx.finalize(&mut digest).unwrap();
    digest
}

fn setup_tpm<'a>(
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

    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    (tpm, global_state)
}

fn execute_tpm_command<C: Command>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &C::Handles,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<(C::RespHandles, C::Response<'static>), u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <<C as Command>::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: Unmarshal<'static>,
{
    let mut request_buf = [0u8; 32768];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    let handles_slice: &mut <C::Handles as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C::Handles as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let handles_len = handles.marshal(handles_slice);
    offset += handles_len;

    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4;
        let auth_start = offset;
        for auth in auths {
            let auth_slice: &mut [u8; TpmsAuthCommand::MAX_SIZE] = (&mut request_buf
                [offset..offset + TpmsAuthCommand::MAX_SIZE])
                .try_into()
                .map_err(|_| ())
                .unwrap();
            let auth_len = auth.marshal(auth_slice);
            offset += auth_len;
        }
        let auth_len = (offset - auth_start) as u32;
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    let cmd_slice: &mut <C as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let cmd_len = cmd.marshal(cmd_slice);
    offset += cmd_len;
    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut response_buf = [0u8; 32768];
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut resp_offset = 10;
    let mut handles_slice = &response_buf[resp_offset..resp_size];
    let orig_handles_len = handles_slice.len();
    let resp_handles =
        C::RespHandles::unmarshal(&mut handles_slice).map_err(|_| TpmRc::FAILURE.get())?;

    let handles_len = orig_handles_len - handles_slice.len();
    resp_offset += handles_len;

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        resp_offset += 4; // Skip parameter size
    }

    let mut params_slice: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
    let resp_params =
        <C::Response<'static>>::unmarshal(&mut params_slice).map_err(|_| TpmRc::FAILURE.get())?;

    Ok((resp_handles, resp_params))
}

fn execute_tpm_event_sequence_complete<'a>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &EventSequenceCompleteHandles,
    cmd: &EventSequenceComplete,
    auths: &[TpmsAuthCommand],
    response_buf: &'a mut [u8; 32768],
) -> Result<<EventSequenceComplete<'static> as Command>::Response<'a>, u32> {
    let mut request_buf = [0u8; 32768];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(EventSequenceComplete::CMD_CODE.code()).to_be_bytes());

    let mut handles_buf = [0u8; EventSequenceCompleteHandles::MAX_SIZE];
    let handles_len = handles.marshal(&mut handles_buf);
    request_buf[offset..offset + handles_len].copy_from_slice(&handles_buf.as_ref()[..handles_len]);
    offset += handles_len;

    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4;
        let auth_start = offset;
        for auth in auths {
            let auth_slice: &mut [u8; TpmsAuthCommand::MAX_SIZE] = (&mut request_buf
                [offset..offset + TpmsAuthCommand::MAX_SIZE])
                .try_into()
                .map_err(|_| ())
                .unwrap();
            let auth_len = auth.marshal(auth_slice);
            offset += auth_len;
        }
        let auth_len = (offset - auth_start) as u32;
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    let mut cmd_buf = [0u8; EventSequenceComplete::MAX_SIZE];
    let cmd_len = cmd.marshal(&mut cmd_buf);
    request_buf[offset..offset + cmd_len].copy_from_slice(&cmd_buf.as_ref()[..cmd_len]);
    offset += cmd_len;
    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut resp_offset = 10;
    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        resp_offset += 4; // Skip parameter size
    }

    let mut params_slice = &response_buf[resp_offset..resp_size];
    Unmarshal::unmarshal(&mut params_slice).map_err(|_| TpmRc::FAILURE.get())
}

fn execute_tpm_command_with_corrupted_bytes<C: Command>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &C::Handles,
    cmd: &C,
    auths: &[TpmsAuthCommand],
    corrupt_fn: impl FnOnce(&mut [u8]),
) -> Result<(C::RespHandles, C::Response<'static>), u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <<C as Command>::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: Unmarshal<'static>,
{
    let mut request_buf = [0u8; 32768];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    offset += marshal_to_slice(handles, &mut request_buf[offset..]);

    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4;
        let auth_start = offset;
        for auth in auths {
            let auth_slice: &mut [u8; TpmsAuthCommand::MAX_SIZE] = (&mut request_buf
                [offset..offset + TpmsAuthCommand::MAX_SIZE])
                .try_into()
                .map_err(|_| ())
                .unwrap();
            let auth_len = auth.marshal(auth_slice);
            offset += auth_len;
        }
        let auth_len = (offset - auth_start) as u32;
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    let payload_start = offset;
    offset += marshal_to_slice(cmd, &mut request_buf[offset..]);

    corrupt_fn(&mut request_buf[payload_start..offset]);

    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut response_buf = [0u8; 32768];
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut resp_offset = 10;
    let mut handles_slice = &response_buf[resp_offset..resp_size];
    let orig_handles_len = handles_slice.len();
    let resp_handles =
        C::RespHandles::unmarshal(&mut handles_slice).map_err(|_| TpmRc::FAILURE.get())?;

    let handles_len = orig_handles_len - handles_slice.len();
    resp_offset += handles_len;

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        resp_offset += 4;
    }

    let mut params_slice: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
    let resp_params =
        <C::Response<'static>>::unmarshal(&mut params_slice).map_err(|_| TpmRc::FAILURE.get())?;

    Ok((resp_handles, resp_params))
}

#[test]
fn test_sequence_hashing_basic_sha256() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. HashSequenceStart
    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let (start_resp_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]).unwrap();
    let seq_handle = start_resp_handles.sequence_handle;

    // 2. SequenceUpdate
    let data1 = b"Hello, ";
    let update_handles = SequenceUpdateHandles {
        sequence_handle: seq_handle,
    };
    let update_cmd = SequenceUpdate {
        buffer: Tpm2bMaxBuffer::from_bytes(data1).unwrap(),
    };
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &update_handles,
        &update_cmd,
        &[],
    )
    .unwrap();

    // 3. SequenceComplete
    let data2 = b"World!";
    let complete_handles = SequenceCompleteHandles {
        sequence_handle: seq_handle,
    };
    let complete_cmd = SequenceComplete {
        buffer: Tpm2bMaxBuffer::from_bytes(data2).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, complete_resp) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles,
        &complete_cmd,
        &[],
    )
    .unwrap();

    // Verify hash output
    let digest = compute_sha256(&crypto, b"Hello, World!");
    assert_eq!(complete_resp.result.get_buffer(), &digest);
}

#[test]
fn test_sequence_hashing_algorithms() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let test_cases = [
        (TpmiAlgHash::Sha1, 20),
        (TpmiAlgHash::Sha256, 32),
        (TpmiAlgHash::Sha384, 48),
        (TpmiAlgHash::Sha512, 64),
    ];

    for (alg, expected_len) in test_cases {
        let start_cmd = HashSequenceStart {
            auth: Tpm2bAuth::default(),
            hash_alg: Some(alg),
        };
        let (start_resp_handles, _) =
            execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]).unwrap();
        let seq_handle = start_resp_handles.sequence_handle;

        let complete_handles = SequenceCompleteHandles {
            sequence_handle: seq_handle,
        };
        let complete_cmd = SequenceComplete {
            buffer: Tpm2bMaxBuffer::from_bytes(b"test").unwrap(),
            hierarchy: Handle::RH_NULL,
        };
        let (_, complete_resp) = execute_tpm_command(
            &mut tpm,
            &mut global_state,
            &complete_handles,
            &complete_cmd,
            &[],
        )
        .unwrap();
        assert_eq!(complete_resp.result.get_size() as usize, expected_len);
    }

    // Invalid hash algorithm
    let invalid_start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_res = execute_tpm_command_with_corrupted_bytes::<HashSequenceStart>(
        &mut tpm,
        &mut global_state,
        &(),
        &invalid_start_cmd,
        &[],
        |buf| {
            buf[2..4].copy_from_slice(&0u16.to_be_bytes());
        },
    );
    assert_eq!(
        start_res.unwrap_err(),
        TpmRc::HASH.with(tpm2::errors::Position::parameter(2)).get()
    );
}

#[test]
fn test_sequence_hashing_empty_input() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let (start_resp_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]).unwrap();
    let seq_handle = start_resp_handles.sequence_handle;

    let complete_handles = SequenceCompleteHandles {
        sequence_handle: seq_handle,
    };
    let complete_cmd = SequenceComplete {
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, complete_resp) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles,
        &complete_cmd,
        &[],
    )
    .unwrap();

    let digest = compute_sha256(&crypto, b"");
    assert_eq!(complete_resp.result.get_buffer(), &digest);
}

#[test]
fn test_sequence_hashing_limits() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // ActiveSequence buffer is 4096 bytes.
    // Let's fill it to 4096 bytes.
    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let (start_resp_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]).unwrap();
    let seq_handle = start_resp_handles.sequence_handle;

    let chunk = [0u8; 1024];
    let update_handles = SequenceUpdateHandles {
        sequence_handle: seq_handle,
    };
    let update_cmd = SequenceUpdate {
        buffer: Tpm2bMaxBuffer::from_bytes(&chunk).unwrap(),
    };

    // Update 4 times -> 4096 bytes
    for _ in 0..4 {
        execute_tpm_command(
            &mut tpm,
            &mut global_state,
            &update_handles,
            &update_cmd,
            &[],
        )
        .unwrap();
    }

    // Try to update 1 more byte -> should fail with memory error
    let update_cmd_small = SequenceUpdate {
        buffer: Tpm2bMaxBuffer::from_bytes(&[1]).unwrap(),
    };
    let update_res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &update_handles,
        &update_cmd_small,
        &[],
    );
    assert!(update_res.is_err());
    let rc = update_res.unwrap_err();
    assert_eq!(rc & 0xFF, 0x04); // TPM_RC_MEMORY is warning code 0x904 (so lower byte is 0x04)

    // Verify we can still complete the sequence
    let complete_handles = SequenceCompleteHandles {
        sequence_handle: seq_handle,
    };
    let complete_cmd = SequenceComplete {
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles,
        &complete_cmd,
        &[],
    );
    assert!(complete_res.is_ok());
}

#[test]
fn test_sequence_hashing_concurrent_slots() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };

    let mut handles = Vec::new();
    // Start up to MAX_ACTIVE_SEQUENCES sequences
    for _ in 0..tpm2_impl::MAX_ACTIVE_SEQUENCES {
        let (start_resp_handles, _) =
            execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]).unwrap();
        handles.push(start_resp_handles.sequence_handle);
    }

    // Attempting one more should fail with TPM_RC_OBJECT_MEMORY (0x902)
    let start_res = execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]);
    assert!(start_res.is_err());
    let rc = start_res.unwrap_err();
    assert_eq!(rc & 0xFF, 0x02); // TPM_RC_OBJECT_MEMORY is 0x902 (lower byte is 0x02)

    // Complete one sequence
    let complete_handles = SequenceCompleteHandles {
        sequence_handle: handles[0],
    };
    let complete_cmd = SequenceComplete {
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles,
        &complete_cmd,
        &[],
    )
    .unwrap();

    // Now starting a 5th sequence should succeed!
    let start_res_ok = execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]);
    assert!(start_res_ok.is_ok());
}

#[test]
fn test_sequence_hashing_authorization() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. HashSequenceStart with a non-empty authorization value.
    let sequence_auth = b"SecretAuthPassword123";
    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::from_bytes(sequence_auth).unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let (start_resp_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]).unwrap();
    let seq_handle = start_resp_handles.sequence_handle;

    // 2. SequenceUpdate with a session containing the WRONG password.
    // The implementation MUST reject this with TPM_RC_BAD_AUTH for session 1 (0x9A2).
    let wrong_auth_session = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(b"WrongPassword123").unwrap(),
    };

    let update_handles = SequenceUpdateHandles {
        sequence_handle: seq_handle,
    };
    let update_cmd = SequenceUpdate {
        buffer: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
    };
    let update_res_wrong = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &update_handles,
        &update_cmd,
        &[wrong_auth_session],
    );
    assert_eq!(update_res_wrong, Err(0x9A2));

    // 3. SequenceUpdate with the CORRECT password -> should succeed.
    let correct_auth_session = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(sequence_auth).unwrap(),
    };
    let update_res_correct = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &update_handles,
        &update_cmd,
        &[correct_auth_session],
    );
    assert!(update_res_correct.is_ok());

    // 4. SequenceComplete with a session containing the WRONG password -> should fail.
    let complete_handles = SequenceCompleteHandles {
        sequence_handle: seq_handle,
    };
    let complete_cmd = SequenceComplete {
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let wrong_auth_session_2 = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(b"WrongPassword123").unwrap(),
    };
    let complete_res_wrong = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles,
        &complete_cmd,
        &[wrong_auth_session_2],
    );
    assert_eq!(complete_res_wrong, Err(0x9A2));

    // 5. SequenceComplete with the CORRECT password -> should succeed.
    let complete_res_correct = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles,
        &complete_cmd,
        &[correct_auth_session],
    );
    assert!(complete_res_correct.is_ok());
}

fn execute_tpm_command_with_trailing<C: Command>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &C::Handles,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<(), u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <<C as Command>::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut request_buf = [0u8; 32768];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    let handles_slice: &mut <C::Handles as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C::Handles as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let handles_len = handles.marshal(handles_slice);
    offset += handles_len;

    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4;
        let auth_start = offset;
        for auth in auths {
            let auth_slice: &mut [u8; TpmsAuthCommand::MAX_SIZE] = (&mut request_buf
                [offset..offset + TpmsAuthCommand::MAX_SIZE])
                .try_into()
                .map_err(|_| ())
                .unwrap();
            let auth_len = auth.marshal(auth_slice);
            offset += auth_len;
        }
        let auth_len = (offset - auth_start) as u32;
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    let cmd_slice: &mut <C as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let cmd_len = cmd.marshal(cmd_slice);
    offset += cmd_len;

    // Add trailing byte
    request_buf[offset] = 0xFF;
    offset += 1;

    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut response_buf = [0u8; 32768];
    tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    Ok(())
}

#[test]
fn adv_hash_command_exhaustive() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let test_cases = [
        (TpmiAlgHash::Sha1, 20),
        (TpmiAlgHash::Sha256, 32),
        (TpmiAlgHash::Sha384, 48),
        (TpmiAlgHash::Sha512, 64),
    ];

    let hierarchies = [
        Handle::RH_OWNER,
        Handle::RH_ENDORSEMENT,
        Handle::RH_PLATFORM,
        Handle::RH_NULL,
    ];

    let data_inputs: &[&[u8]] = &[
        b"",
        b"Hello, World!",
        &[0u8; 1024], // Max buffer size representation
    ];

    // Test happy paths
    for &(alg, expected_len) in &test_cases {
        for &hierarchy in &hierarchies {
            for &data in data_inputs {
                let hash_cmd = Hash {
                    data: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
                    hash_alg: alg,
                    hierarchy,
                };
                let (_, resp) =
                    execute_tpm_command(&mut tpm, &mut global_state, &(), &hash_cmd, &[]).unwrap();
                assert_eq!(resp.out_hash.get_size() as usize, expected_len);
                assert_eq!(resp.validation.tag(), 0x8024);
                assert_eq!(resp.validation.hierarchy(), hierarchy);
                if hierarchy == Handle::RH_NULL {
                    assert_eq!(resp.validation.digest().get_size() as usize, 0);
                    assert_eq!(resp.validation.digest().get_buffer(), &[] as &[u8]);
                } else {
                    assert_eq!(resp.validation.digest().get_size() as usize, 32);
                }
            }
        }
    }

    // Test error: unsupported hash algorithm
    let invalid_hash_cmd = Hash {
        data: Tpm2bMaxBuffer::default(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_tpm_command_with_corrupted_bytes::<Hash>(
        &mut tpm,
        &mut global_state,
        &(),
        &invalid_hash_cmd,
        &[],
        |buf| {
            buf[2..4].copy_from_slice(&0u16.to_be_bytes());
        },
    );
    assert_eq!(
        res.unwrap_err(),
        TpmRc::HASH.with(Position::parameter(2)).get()
    );

    // Test error: invalid hierarchy
    let invalid_hier_cmd = Hash {
        data: Tpm2bMaxBuffer::default(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle(1), // Invalid hierarchy handle (e.g. PCR1)
    };
    let res2 = execute_tpm_command(&mut tpm, &mut global_state, &(), &invalid_hier_cmd, &[]);
    assert!(res2.is_err());
    let rc2 = res2.unwrap_err();
    assert_eq!(rc2, TpmRc::VALUE.with(Position::parameter(3)).get());
}

#[test]
fn adv_sequence_handle_validation() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Start a valid sequence to have a reference handle
    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let (start_resp_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]).unwrap();
    let seq_handle = start_resp_handles.sequence_handle;

    // 1. SequenceUpdate with invalid sequence handle
    let invalid_handle = Handle(seq_handle.0 + 1);
    let update_handles = SequenceUpdateHandles {
        sequence_handle: invalid_handle,
    };
    let update_cmd = SequenceUpdate {
        buffer: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
    };
    let update_res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &update_handles,
        &update_cmd,
        &[],
    );
    assert_eq!(update_res, Err(TpmRc::REFERENCE_H0.get()));

    // 2. SequenceComplete with invalid sequence handle
    let complete_handles = SequenceCompleteHandles {
        sequence_handle: invalid_handle,
    };
    let complete_cmd = SequenceComplete {
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles,
        &complete_cmd,
        &[],
    );
    assert_eq!(complete_res, Err(TpmRc::REFERENCE_H0.get()));

    // 3. SequenceComplete with invalid hierarchy (hierarchy is first parameter of cmd)
    let complete_handles_valid = SequenceCompleteHandles {
        sequence_handle: seq_handle,
    };
    let complete_cmd_invalid_hier = SequenceComplete {
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle(0), // Invalid hierarchy
    };
    let complete_res2 = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles_valid,
        &complete_cmd_invalid_hier,
        &[],
    );
    assert_eq!(
        complete_res2,
        Err(TpmRc::VALUE
            .with(tpm2::errors::Position::parameter(2))
            .get())
    );

    // 4. Complete sequence successfully
    let complete_cmd_valid = SequenceComplete {
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_res_ok = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles_valid,
        &complete_cmd_valid,
        &[],
    );
    assert!(complete_res_ok.is_ok());

    // 5. SequenceUpdate reuse
    let update_handles_valid = SequenceUpdateHandles {
        sequence_handle: seq_handle,
    };
    let update_res2 = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &update_handles_valid,
        &update_cmd,
        &[],
    );
    assert_eq!(update_res2, Err(TpmRc::REFERENCE_H0.get()));

    // 6. SequenceComplete reuse
    let complete_res_reuse = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles_valid,
        &complete_cmd_valid,
        &[],
    );
    assert_eq!(complete_res_reuse, Err(TpmRc::REFERENCE_H0.get()));
}

#[test]
fn adv_sequence_abort_flush() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Start a sequence, then abort it via FlushContext
    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let (start_resp_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]).unwrap();
    let seq_handle = start_resp_handles.sequence_handle;

    let flush_cmd = FlushContext {
        flush_handle: seq_handle,
    };
    execute_tpm_command(&mut tpm, &mut global_state, &(), &flush_cmd, &[]).unwrap();

    // Verify it is aborted (SequenceUpdate returns ReferenceH0)
    let update_handles = SequenceUpdateHandles {
        sequence_handle: seq_handle,
    };
    let update_cmd = SequenceUpdate {
        buffer: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
    };
    let update_res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &update_handles,
        &update_cmd,
        &[],
    );
    assert_eq!(update_res, Err(TpmRc::REFERENCE_H0.get()));

    // Double flush should fail with ReferenceH0
    let flush_res_double = execute_tpm_command(&mut tpm, &mut global_state, &(), &flush_cmd, &[]);
    assert_eq!(flush_res_double, Err(TpmRc::HANDLE.get()));

    // 2. Slot recycling verification
    let mut handles = Vec::new();
    // Fill all available slots
    for _ in 0..tpm2_impl::MAX_ACTIVE_SEQUENCES {
        let (resp_h, _) =
            execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]).unwrap();
        handles.push(resp_h.sequence_handle);
    }

    // Attempting one more fails with ObjectMemory (0x902)
    let start_res_fail = execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]);
    assert_eq!(start_res_fail.unwrap_err() & 0xFF, 0x02);

    // Flush one sequence
    let flush_cmd_recycle = FlushContext {
        flush_handle: handles[2],
    };
    execute_tpm_command(&mut tpm, &mut global_state, &(), &flush_cmd_recycle, &[]).unwrap();

    // 17th start should now succeed
    let start_res_retry = execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]);
    assert!(start_res_retry.is_ok());
}

#[test]
fn adv_sequence_trailing_bytes() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Hash command with trailing bytes
    let hash_cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(b"Helloooo").unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle::RH_NULL,
    };
    let res = execute_tpm_command_with_trailing(&mut tpm, &mut global_state, &(), &hash_cmd, &[]);
    assert_eq!(res, Err(TpmRc::SIZE.get()));

    // 2. HashSequenceStart command with trailing bytes
    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let res2 = execute_tpm_command_with_trailing(&mut tpm, &mut global_state, &(), &start_cmd, &[]);
    assert_eq!(res2, Err(TpmRc::SIZE.get()));

    // 3. SequenceUpdate command with trailing bytes
    let (start_resp_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]).unwrap();
    let seq_handle = start_resp_handles.sequence_handle;

    let update_handles = SequenceUpdateHandles {
        sequence_handle: seq_handle,
    };
    let update_cmd = SequenceUpdate {
        buffer: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
    };
    let res3 = execute_tpm_command_with_trailing(
        &mut tpm,
        &mut global_state,
        &update_handles,
        &update_cmd,
        &[],
    );
    assert_eq!(res3, Err(TpmRc::SIZE.get()));

    // 4. SequenceComplete command with trailing bytes
    let complete_handles = SequenceCompleteHandles {
        sequence_handle: seq_handle,
    };
    let complete_cmd = SequenceComplete {
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let res4 = execute_tpm_command_with_trailing(
        &mut tpm,
        &mut global_state,
        &complete_handles,
        &complete_cmd,
        &[],
    );
    assert_eq!(res4, Err(TpmRc::SIZE.get()));

    // 5. EventSequenceComplete command with trailing bytes
    let start_event_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: None,
    };
    let (start_event_resp_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &start_event_cmd, &[]).unwrap();
    let event_seq_handle = start_event_resp_handles.sequence_handle;

    let event_complete_handles = EventSequenceCompleteHandles {
        pcr_handle: Handle::RH_NULL,
        sequence_handle: event_seq_handle,
    };
    let event_complete_cmd = EventSequenceComplete {
        buffer: Tpm2bMaxBuffer::default(),
    };
    let res5 = execute_tpm_command_with_trailing(
        &mut tpm,
        &mut global_state,
        &event_complete_handles,
        &event_complete_cmd,
        &[],
    );
    assert_eq!(res5, Err(TpmRc::SIZE.get()));
}

#[test]
fn test_event_sequence_complete_pcr_extend() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. HashSequenceStart with Null hash algorithm (Event sequence)
    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: None,
    };
    let (start_resp_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]).unwrap();
    let seq_handle = start_resp_handles.sequence_handle;

    // 2. SequenceUpdate with partial data
    let partial_data = b"partial data ";
    let update_handles = SequenceUpdateHandles {
        sequence_handle: seq_handle,
    };
    let update_cmd = SequenceUpdate {
        buffer: Tpm2bMaxBuffer::from_bytes(partial_data).unwrap(),
    };
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &update_handles,
        &update_cmd,
        &[],
    )
    .unwrap();

    // 3. EventSequenceComplete with pcrHandle=0, buffer=final_data
    let final_data = b"final data";
    let complete_handles = EventSequenceCompleteHandles {
        pcr_handle: Handle(0),
        sequence_handle: seq_handle,
    };
    let complete_cmd = EventSequenceComplete {
        buffer: Tpm2bMaxBuffer::from_bytes(final_data).unwrap(),
    };
    let mut complete_response_buf = [0u8; 32768];
    let mut request_buf = [0u8; 32768];
    request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    request_buf[6..10].copy_from_slice(&(EventSequenceComplete::CMD_CODE.code()).to_be_bytes());
    let mut offset = 10;
    let mut handles_buf = [0u8; EventSequenceCompleteHandles::MAX_SIZE];
    let handles_len = complete_handles.marshal(&mut handles_buf);
    request_buf[offset..offset + handles_len].copy_from_slice(&handles_buf.as_ref()[..handles_len]);
    offset += handles_len;
    let mut cmd_buf = [0u8; EventSequenceComplete::MAX_SIZE];
    let cmd_len = complete_cmd.marshal(&mut cmd_buf);
    request_buf[offset..offset + cmd_len].copy_from_slice(&cmd_buf.as_ref()[..cmd_len]);
    offset += cmd_len;
    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    tpm.execute_command_separate(
        &mut global_state,
        &request_buf[..offset],
        &mut complete_response_buf[..],
    );
    let mut param_slice = &complete_response_buf[10..];
    let complete_resp =
        <EventSequenceComplete<'static> as Command>::Response::unmarshal(&mut param_slice).unwrap();

    // Assert PCR 0 equals SHA256(00..00 || SHA256(partial_data || final_data))
    let mut combined = Vec::new();
    combined.extend_from_slice(partial_data);
    combined.extend_from_slice(final_data);
    let event_digest = compute_sha256(&TestCryptoProvider, &combined);

    let mut extend_input = [0u8; 64];
    extend_input[0..32].copy_from_slice(&[0u8; 32]);
    extend_input[32..64].copy_from_slice(&event_digest);
    let expected_pcr0 = compute_sha256(&TestCryptoProvider, &extend_input);

    assert_eq!(global_state.pcrs.sha256[0], expected_pcr0);
    assert_eq!(complete_resp.results.count(), 3);
    assert_eq!(
        *complete_resp.results.digests().nth(1).unwrap(),
        tpm2::TpmtHa::Sha256(&event_digest)
    );

    // Verify the sequence handle is flushed (`ReferenceH0` on subsequent use as handle 0)
    let bad_update_handles = SequenceUpdateHandles {
        sequence_handle: seq_handle,
    };
    let bad_update_cmd = SequenceUpdate {
        buffer: Tpm2bMaxBuffer::from_bytes(b"more").unwrap(),
    };
    let err = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &bad_update_handles,
        &bad_update_cmd,
        &[],
    );
    assert_eq!(err, Err(TpmRc::REFERENCE_H0.get()));

    // Also verify that subsequent use in EventSequenceComplete (handle 1) gives `ReferenceH1`
    let bad_complete_handles = EventSequenceCompleteHandles {
        pcr_handle: Handle(0),
        sequence_handle: seq_handle,
    };
    let bad_complete_cmd = EventSequenceComplete {
        buffer: Tpm2bMaxBuffer::from_bytes(b"more").unwrap(),
    };
    let mut response_buf = [0u8; 32768];
    let err2 = execute_tpm_event_sequence_complete(
        &mut tpm,
        &mut global_state,
        &bad_complete_handles,
        &bad_complete_cmd,
        &[],
        &mut response_buf,
    );
    assert_eq!(err2, Err(TpmRc::REFERENCE_H1.get()));
}

#[test]
fn test_event_sequence_complete_mode_error() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. HashSequenceStart with SHA256 (Hash sequence instead of Event sequence)
    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let (start_resp_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]).unwrap();
    let seq_handle = start_resp_handles.sequence_handle;

    // 2. EventSequenceComplete must return TPM_RC_MODE when called on a Hash sequence
    let complete_handles = EventSequenceCompleteHandles {
        pcr_handle: Handle(0),
        sequence_handle: seq_handle,
    };
    let complete_cmd = EventSequenceComplete {
        buffer: Tpm2bMaxBuffer::from_bytes(b"final data").unwrap(),
    };
    let mut response_buf = [0u8; 32768];
    let res = execute_tpm_event_sequence_complete(
        &mut tpm,
        &mut global_state,
        &complete_handles,
        &complete_cmd,
        &[],
        &mut response_buf,
    );
    assert_eq!(res, Err(TpmRc::MODE.get()));
}

#[test]
fn test_sequence_context_save_load_mid_flight_streaming_state() {
    use tpm2::commands::{ContextLoad, ContextSave, ContextSaveHandles, FlushContext};

    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Start a SHA-256 hash sequence
    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let (start_resp_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]).unwrap();
    let seq_handle = start_resp_handles.sequence_handle;

    // 2. Feed > 1 block (100 bytes) of data via SequenceUpdate
    let part1 = [0x42u8; 100];
    let update_handles = SequenceUpdateHandles {
        sequence_handle: seq_handle,
    };
    let update_cmd = SequenceUpdate {
        buffer: Tpm2bMaxBuffer::from_bytes(&part1).unwrap(),
    };
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &update_handles,
        &update_cmd,
        &[],
    )
    .unwrap();

    // 3. ContextSave the in-flight sequence (which serializes the live StreamingHashState registers)
    let save_handles = ContextSaveHandles {
        save_handle: seq_handle,
    };
    let save_cmd = ContextSave {};
    let (_, save_rsp): ((), tpm2::commands::responses::ContextSave) =
        execute_tpm_command(&mut tpm, &mut global_state, &save_handles, &save_cmd, &[]).unwrap();

    // 4. Flush the sequence handle from active memory
    let flush_cmd = FlushContext {
        flush_handle: seq_handle,
    };
    execute_tpm_command(&mut tpm, &mut global_state, &(), &flush_cmd, &[]).unwrap();

    // 5. ContextLoad the saved sequence context blob
    let load_cmd = ContextLoad {
        context: save_rsp.context,
    };
    let (load_resp_handles, _): (tpm2::commands::ContextLoadRespHandles, ()) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &load_cmd, &[]).unwrap();
    let restored_handle = load_resp_handles.loaded_handle;

    // 6. Complete the sequence with part2 (50 bytes)
    let part2 = [0x99u8; 50];
    let complete_handles = SequenceCompleteHandles {
        sequence_handle: restored_handle,
    };
    let complete_cmd = SequenceComplete {
        buffer: Tpm2bMaxBuffer::from_bytes(&part2).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, complete_rsp): ((), tpm2::commands::responses::SequenceComplete) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles,
        &complete_cmd,
        &[],
    )
    .unwrap();

    // 7. Verify the digest matches hashing (part1 || part2) in a single pass
    let mut combined = [0u8; 150];
    combined[..100].copy_from_slice(&part1);
    combined[100..].copy_from_slice(&part2);
    let expected = compute_sha256(tpm.platform.crypto, &combined);
    assert_eq!(complete_rsp.result.get_buffer(), &expected);
}

#[test]
fn test_sequence_transient_shared_handle_namespace_parity() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Start 3 sequences -> handles should be strictly 0x80000000, 0x80000001, 0x80000002
    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let mut handles = [0u32; 3];
    for h in &mut handles {
        let (resp, _) =
            execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]).unwrap();
        *h = resp.sequence_handle.0;
    }
    assert_eq!(handles, [0x80000000, 0x80000001, 0x80000002]);

    // Attempting a 4th sequence should fail with OBJECT_MEMORY because s_objects capacity (3) is full
    let fourth_res = execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]);
    assert!(fourth_res.is_err());
}
