use common::marshal_to_slice;
use tpm2::{Marshal, Message, Ticket, Unmarshal, UnmarshalMessage};
mod common;

use common::TestCryptoProvider;
use common::{FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::Handle;
use tpm2::commands::{Command, Hash, HashSequenceStart, SequenceComplete, SequenceUpdate};
use tpm2::crypto::Random;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Tpm2bAuth, Tpm2bMaxBuffer, TpmSt, TpmiAlgHash, TpmsAuthCommand};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

fn setup_tpm<'a>(
    crypto: &'a TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer>,
    tpm2_impl::GlobalState,
) {
    let rng = crypto.rng_seeded(b"adv_sequence_gaps").unwrap();
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

fn execute_tpm_command<C: Command>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: UnmarshalMessage<'static>,
{
    let mut request_buf = [0u8; 32768];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    for h in cmd.handles().as_ref() {
        request_buf[offset..offset + 4].copy_from_slice(&h.0.to_be_bytes());
        offset += 4;
    }

    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4;
        let auth_start = offset;
        for auth in auths {
            let mut auth_buf = [0u8; TpmsAuthCommand::MAX_SIZE];
            let auth_len = auth.marshal(&mut auth_buf);
            request_buf[offset..offset + auth_len].copy_from_slice(&auth_buf[..auth_len]);
            offset += auth_len;
        }
        let auth_len = u32::try_from(offset - auth_start).unwrap();
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    offset += marshal_to_slice(cmd, &mut request_buf[offset..]);
    let total_len = u32::try_from(offset).unwrap();
    request_buf[2..6].copy_from_slice(&total_len.to_be_bytes());

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
    let mut resp_handles = <C::Response<'static> as Message>::Handles::default();
    for h in resp_handles.as_mut() {
        *h = Handle::unmarshal(&mut handles_slice).map_err(|_| TpmRc::FAILURE.get())?;
    }

    let handles_len = orig_handles_len - handles_slice.len();
    resp_offset += handles_len;

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        resp_offset += 4; // Skip parameter size
    }

    let mut params_slice: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
    let resp_params =
        <C::Response<'static>>::unmarshal_with_handles(resp_handles, &mut params_slice)
            .map_err(|_| TpmRc::FAILURE.get())?;

    Ok(resp_params)
}

fn execute_tpm_command_with_extra_bytes<C: Command>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: UnmarshalMessage<'static>,
{
    let mut request_buf = [0u8; 32768];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    for h in cmd.handles().as_ref() {
        request_buf[offset..offset + 4].copy_from_slice(&h.0.to_be_bytes());
        offset += 4;
    }

    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4;
        let auth_start = offset;
        for auth in auths {
            let mut auth_buf = [0u8; TpmsAuthCommand::MAX_SIZE];
            let auth_len = auth.marshal(&mut auth_buf);
            request_buf[offset..offset + auth_len].copy_from_slice(&auth_buf[..auth_len]);
            offset += auth_len;
        }
        let auth_len = u32::try_from(offset - auth_start).unwrap();
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    offset += marshal_to_slice(cmd, &mut request_buf[offset..]);
    // Append 4 dummy extra bytes
    request_buf[offset..offset + 4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    offset += 4;
    let total_len = u32::try_from(offset).unwrap();
    request_buf[2..6].copy_from_slice(&total_len.to_be_bytes());

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
    let mut resp_handles = <C::Response<'static> as Message>::Handles::default();
    for h in resp_handles.as_mut() {
        *h = Handle::unmarshal(&mut handles_slice).map_err(|_| TpmRc::FAILURE.get())?;
    }

    let handles_len = orig_handles_len - handles_slice.len();
    resp_offset += handles_len;

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        resp_offset += 4; // Skip parameter size
    }

    let mut params_slice: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
    let resp_params =
        <C::Response<'static>>::unmarshal_with_handles(resp_handles, &mut params_slice)
            .map_err(|_| TpmRc::FAILURE.get())?;

    Ok(resp_params)
}

#[test]
fn adv_hash_happy_path_sha256() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let test_data = b"Hello Adversary Hash!";
    let cmd = Hash {
        data: Tpm2bMaxBuffer::new(test_data).unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle::RH_NULL,
    };

    let resp = execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]).unwrap();
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let expected_digest = tpm2::crypto::hash(
        &TestCryptoProvider,
        TpmiAlgHash::Sha256,
        test_data,
        &mut out,
    )
    .unwrap()
    .digest();
    assert_eq!(resp.out_hash.as_slice(), expected_digest);

    // Verify ticket
    assert_eq!(resp.validation.tag(), TpmSt::HASHCHECK);
    assert_eq!(resp.validation.hierarchy(), Handle::RH_NULL);
    assert_eq!(resp.validation.digest().as_slice(), &[] as &[u8]);
}

#[test]
fn adv_hash_happy_path_all_algorithms_and_hierarchies() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let test_data = b"Multialg data check";

    let scenarios = [
        (TpmiAlgHash::Sha1, Handle::RH_OWNER),
        (TpmiAlgHash::Sha256, Handle::RH_ENDORSEMENT),
        (TpmiAlgHash::Sha384, Handle::RH_PLATFORM),
        (TpmiAlgHash::Sha512, Handle::RH_NULL),
    ];

    for (alg, hierarchy) in scenarios {
        let cmd = Hash {
            data: Tpm2bMaxBuffer::new(test_data).unwrap(),
            hash_alg: alg,
            hierarchy,
        };

        let resp = execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]).unwrap();
        let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let expected_digest = tpm2::crypto::hash(&TestCryptoProvider, alg, test_data, &mut out)
            .unwrap()
            .digest();

        assert_eq!(resp.out_hash.as_slice(), expected_digest);
        assert_eq!(resp.validation.hierarchy(), hierarchy);
        if hierarchy == Handle::RH_NULL {
            assert_eq!(resp.validation.digest().as_slice(), &[] as &[u8]);
        } else {
            assert_eq!(resp.validation.digest().as_slice().len(), 32);
        }
    }
}

#[test]
fn adv_hash_invalid_alg() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let cmd = Hash {
        data: Tpm2bMaxBuffer::new(b"data").unwrap(),
        hash_alg: TpmiAlgHash::Sm3_256, // invalid/unsupported alg for Hash command
        hierarchy: Handle::RH_NULL,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::HASH.with(Position::parameter(2)).get())
    );
}

#[test]
fn adv_hash_invalid_hierarchy() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let cmd = Hash {
        data: Tpm2bMaxBuffer::new(b"data").unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle(0x80000000), // invalid hierarchy handle
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::parameter(3)).get())
    );
}

#[test]
fn adv_hash_trailing_bytes() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let cmd = Hash {
        data: Tpm2bMaxBuffer::new(b"data").unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle::RH_NULL,
    };

    let res = execute_tpm_command_with_extra_bytes(&mut tpm, &mut global_state, &cmd, &[]);
    assert_eq!(res.err(), Some(TpmRc::SIZE.to_rc().get()));
}

#[test]
fn adv_sequence_start_trailing_bytes() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };

    let res = execute_tpm_command_with_extra_bytes(&mut tpm, &mut global_state, &cmd, &[]);
    assert_eq!(res.err(), Some(TpmRc::SIZE.to_rc().get()));
}

#[test]
fn adv_sequence_update_trailing_bytes() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_resp = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd, &[]).unwrap();

    let update_cmd = SequenceUpdate {
        sequence_handle: start_resp.sequence_handle,
        buffer: Tpm2bMaxBuffer::new(b"data").unwrap(),
    };

    let res = execute_tpm_command_with_extra_bytes(&mut tpm, &mut global_state, &update_cmd, &[]);
    assert_eq!(res.err(), Some(TpmRc::SIZE.to_rc().get()));
}

#[test]
fn adv_sequence_complete_trailing_bytes() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_resp = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd, &[]).unwrap();

    let complete_cmd = SequenceComplete {
        sequence_handle: start_resp.sequence_handle,
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };

    let res = execute_tpm_command_with_extra_bytes(&mut tpm, &mut global_state, &complete_cmd, &[]);
    assert_eq!(res.err(), Some(TpmRc::SIZE.to_rc().get()));
}

#[test]
fn adv_sequence_complete_invalid_hierarchy_detailed() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_resp = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd, &[]).unwrap();

    let complete_cmd = SequenceComplete {
        sequence_handle: start_resp.sequence_handle,
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle(0x80000000), // invalid hierarchy handle
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::parameter(2)).get())
    );
}
