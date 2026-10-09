use tpm2::{Marshal, Unmarshal};
mod common;

use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::Handle;
use tpm2::commands::{
    Command, Hash, HashSequenceStart, SequenceComplete, SequenceCompleteHandles, SequenceUpdate,
    SequenceUpdateHandles,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2bAuth, Tpm2bMaxBuffer, TpmiAlgHash, TpmsAuthCommand, TpmtHa};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

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

/// An empty-password `TPM_RS_PW` session. In C every handle with an authorization role
/// needs a session even if its authValue is empty; with no session C returns
/// TPM_RC_AUTH_MISSING (SessionProcess.c CheckAuthNoSession).
fn pw() -> tpm2::TpmsAuthCommand<'static> {
    tpm2::TpmsAuthCommand {
        session_handle: tpm2::Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: tpm2::TpmaSession(0),
        hmac: tpm2::Tpm2bAuth::default(),
    }
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

fn execute_tpm_command_with_extra_bytes<C: Command>(
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
    // Append 4 dummy extra bytes
    request_buf[offset..offset + 4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    offset += 4;
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

#[test]
fn adv_hash_happy_path_sha256() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let test_data = b"Hello Adversary Hash!";
    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(test_data).unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle::RH_NULL,
    };

    let (_, resp) = execute_tpm_command(&mut tpm, &mut global_state, &(), &cmd, &[]).unwrap();
    let mut out = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    let expected_digest = tpm2::crypto::hash(
        &TestCryptoProvider,
        TpmiAlgHash::Sha256,
        test_data,
        &mut out,
    )
    .unwrap()
    .digest();
    assert_eq!(resp.out_hash.get_buffer(), expected_digest);

    // Verify ticket
    assert_eq!(resp.validation.tag(), 0x8024);
    assert_eq!(resp.validation.hierarchy(), Handle::RH_NULL);
    assert_eq!(resp.validation.digest().get_buffer(), &[] as &[u8]);
}

#[test]
fn adv_hash_happy_path_all_algorithms_and_hierarchies() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let test_data = b"Multialg data check";

    let scenarios = [
        (TpmiAlgHash::Sha1, Handle::RH_OWNER),
        (TpmiAlgHash::Sha256, Handle::RH_ENDORSEMENT),
        (TpmiAlgHash::Sha384, Handle::RH_PLATFORM),
        (TpmiAlgHash::Sha512, Handle::RH_NULL),
    ];

    for (alg, hierarchy) in scenarios {
        let cmd = Hash {
            data: Tpm2bMaxBuffer::from_bytes(test_data).unwrap(),
            hash_alg: alg,
            hierarchy,
        };

        let (_, resp) = execute_tpm_command(&mut tpm, &mut global_state, &(), &cmd, &[]).unwrap();
        let mut out = [0u8; TpmtHa::MAX_DIGEST_SIZE];
        let expected_digest = tpm2::crypto::hash(&TestCryptoProvider, alg, test_data, &mut out)
            .unwrap()
            .digest();

        assert_eq!(resp.out_hash.get_buffer(), expected_digest);
        assert_eq!(resp.validation.hierarchy(), hierarchy);
        if hierarchy == Handle::RH_NULL {
            assert_eq!(resp.validation.digest().get_buffer(), &[] as &[u8]);
        } else {
            assert_eq!(resp.validation.digest().get_size() as usize, 32);
        }
    }
}

#[test]
fn adv_hash_invalid_alg() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
        hash_alg: TpmiAlgHash::Sm3_256, // invalid/unsupported alg for Hash command
        hierarchy: Handle::RH_NULL,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &(), &cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::HASH.with(Position::parameter(2)).get())
    );
}

#[test]
fn adv_hash_invalid_hierarchy() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle(0x80000000), // invalid hierarchy handle
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &(), &cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::parameter(3)).get())
    );
}

#[test]
fn adv_hash_trailing_bytes() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle::RH_NULL,
    };

    let res = execute_tpm_command_with_extra_bytes(&mut tpm, &mut global_state, &(), &cmd, &[]);
    assert_eq!(res.err(), Some(TpmRc::SIZE.get()));
}

#[test]
fn adv_sequence_start_trailing_bytes() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };

    let res = execute_tpm_command_with_extra_bytes(&mut tpm, &mut global_state, &(), &cmd, &[]);
    assert_eq!(res.err(), Some(TpmRc::SIZE.get()));
}

#[test]
fn adv_sequence_update_trailing_bytes() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let (start_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]).unwrap();

    let update_handles = SequenceUpdateHandles {
        sequence_handle: start_handles.sequence_handle,
    };
    let update_cmd = SequenceUpdate {
        buffer: Tpm2bMaxBuffer::from_bytes(b"data").unwrap(),
    };

    let res = execute_tpm_command_with_extra_bytes(
        &mut tpm,
        &mut global_state,
        &update_handles,
        &update_cmd,
        &[pw()],
    );
    assert_eq!(res.err(), Some(TpmRc::SIZE.get()));
}

#[test]
fn adv_sequence_complete_trailing_bytes() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let (start_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]).unwrap();

    let complete_handles = SequenceCompleteHandles {
        sequence_handle: start_handles.sequence_handle,
    };
    let complete_cmd = SequenceComplete {
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };

    let res = execute_tpm_command_with_extra_bytes(
        &mut tpm,
        &mut global_state,
        &complete_handles,
        &complete_cmd,
        &[pw()],
    );
    assert_eq!(res.err(), Some(TpmRc::SIZE.get()));
}

#[test]
fn adv_sequence_complete_invalid_hierarchy_detailed() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let (start_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &start_cmd, &[]).unwrap();

    let complete_handles = SequenceCompleteHandles {
        sequence_handle: start_handles.sequence_handle,
    };
    let complete_cmd = SequenceComplete {
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle(0x80000000), // invalid hierarchy handle
    };

    let res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles,
        &complete_cmd,
        &[pw()],
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::parameter(2)).get())
    );
}
