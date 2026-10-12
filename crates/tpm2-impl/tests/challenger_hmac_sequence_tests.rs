#![allow(deprecated)]
use common::marshal_to_slice;
use tpm2::{Marshal, Message, Unmarshal, UnmarshalMessage};

mod common;

use common::TestCryptoProvider;
use common::{FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::Handle;
use tpm2::commands::{
    Command, EvictControl, HMAC, HMACStart, ReadPublic, SequenceComplete, SequenceUpdate, Sign,
};
use tpm2::crypto::Random;
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bNonce, TpmaObject, TpmaSession,
    TpmiAlgHash, TpmsAuthCommand, TpmtPublic, TpmtSigScheme, TpmtTkHashcheck,
};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::owned::{OwnedSensitiveComposite, OwnedSensitiveData};

fn setup_tpm_with_crypto<'a>(
    crypto: &'a TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer>,
    tpm2_impl::GlobalState,
) {
    let rng = crypto.rng_seeded(b"challenger_hmac_seq").unwrap();
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

fn execute_tpm_sign<'a>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &Sign,
    auths: &[TpmsAuthCommand],
    response_buf: &'a mut [u8; 32768],
) -> Result<<Sign<'static> as Command>::Response<'a>, u32> {
    let mut request_buf = [0u8; 32768];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(Sign::CMD_CODE.code()).to_be_bytes());

    for h in cmd.handles().as_ref() {
        offset += marshal_to_slice(h, &mut request_buf[offset..]);
    }

    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4;
        let auth_start = offset;
        for auth in auths {
            offset += marshal_to_slice(auth, &mut request_buf[offset..]);
        }
        let auth_len = u32::try_from(offset - auth_start).unwrap();
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    offset += marshal_to_slice(cmd, &mut request_buf[offset..]);
    let total_len = u32::try_from(offset).unwrap();
    request_buf[2..6].copy_from_slice(&total_len.to_be_bytes());

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
    UnmarshalMessage::unmarshal_with_handles([], &mut params_slice)
        .map_err(|_| TpmRc::FAILURE.get())
}

fn insert_keyed_hash_key(
    global_state: &mut tpm2_impl::GlobalState,
    handle: u32,
    auth: &[u8],
    secret_key: &[u8],
    attributes: TpmaObject,
) {
    let name_str = hex!("000b 23791a27e7f7bb196e8d2e4d9c72e2762283ea01");
    let name = tpm2::Tpm2bName::new(&name_str).unwrap();

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attributes | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, tpm2::Tpm2bDigest::default()),
    };

    let obj = tpm2_impl::handler::TransientObject {
        handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: name.into(),
        auth: (Tpm2bAuth::new(auth).unwrap()).into(),
        public: public.into(),
        sensitive: OwnedSensitiveComposite::KeyedHash(OwnedSensitiveData::new(secret_key).unwrap()),
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: Handle::RH_OWNER.0,
        st_clear: false,
    };

    let slot = global_state
        .transient_objects
        .iter_mut()
        .find(|s| s.is_none())
        .expect("no empty transient slot");
    *slot = Some(obj);
}

#[test]
fn test_multiple_concurrent_hmac_sequences() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm_with_crypto(&crypto, &mut storage, &mut timer);

    let key_handle = 0x80000005u32;
    insert_keyed_hash_key(
        &mut global_state,
        key_handle,
        b"keyauth",
        b"my_secret_key_bytes_12345",
        TpmaObject::SIGN_ENCRYPT,
    );

    let auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::new(b"keyauth").unwrap(),
    }];

    let mut seq_handles = Vec::new();
    for _ in 0..tpm2_impl::MAX_ACTIVE_SEQUENCES {
        let start_cmd = HMACStart {
            handle: Handle(key_handle),
            auth: Tpm2bAuth::new(b"seqauth").unwrap(),
            hash_alg: Some(TpmiAlgHash::Sha256),
        };
        let resp = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd, &auths).unwrap();
        seq_handles.push(resp.sequence_handle);
    }

    let start_cmd = HMACStart {
        handle: Handle(key_handle),
        auth: Tpm2bAuth::new(b"seqauth").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd, &auths);
    assert!(res.is_err());
    assert_eq!(res.err().unwrap(), TpmRc::OBJECT_MEMORY.get());

    let complete_cmd = SequenceComplete {
        sequence_handle: seq_handles[0],
        buffer: tpm2::Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::new(b"seqauth").unwrap(),
    }];
    execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd, &complete_auths).unwrap();

    let resp = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd, &auths).unwrap();
    let new_seq_handle = resp.sequence_handle;
    assert_eq!(new_seq_handle.0, seq_handles[0].0);
}

#[test]
fn test_hmac_sequence_correctness_and_split_chunks() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm_with_crypto(&crypto, &mut storage, &mut timer);

    let key_handle = 0x80000005u32;
    let key_bytes = b"another_secret_key_bytes_56789";
    insert_keyed_hash_key(
        &mut global_state,
        key_handle,
        b"keyauth",
        key_bytes,
        TpmaObject::SIGN_ENCRYPT,
    );

    let auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::new(b"keyauth").unwrap(),
    }];

    let start_cmd = HMACStart {
        handle: Handle(key_handle),
        auth: Tpm2bAuth::new(b"seqauth").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let resp = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd, &auths).unwrap();
    let seq_handle = resp.sequence_handle;

    let seq_auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::new(b"seqauth").unwrap(),
    }];

    let chunk1 = b"Hello, ";
    let chunk2 = b"this is a stress test for ";
    let chunk3 = b"HMAC sequence updates!";

    let update_cmd1 = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: tpm2::Tpm2bMaxBuffer::new(chunk1).unwrap(),
    };
    execute_tpm_command(&mut tpm, &mut global_state, &update_cmd1, &seq_auths).unwrap();

    let update_cmd2 = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: tpm2::Tpm2bMaxBuffer::new(chunk2).unwrap(),
    };
    execute_tpm_command(&mut tpm, &mut global_state, &update_cmd2, &seq_auths).unwrap();

    let update_cmd3 = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: tpm2::Tpm2bMaxBuffer::new(chunk3).unwrap(),
    };
    execute_tpm_command(&mut tpm, &mut global_state, &update_cmd3, &seq_auths).unwrap();

    let final_chunk = b" End of sequence.";
    let complete_cmd = SequenceComplete {
        sequence_handle: seq_handle,
        buffer: tpm2::Tpm2bMaxBuffer::new(final_chunk).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_resp =
        execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd, &seq_auths).unwrap();

    let mut full_data = Vec::new();
    full_data.extend_from_slice(chunk1);
    full_data.extend_from_slice(chunk2);
    full_data.extend_from_slice(chunk3);
    full_data.extend_from_slice(final_chunk);

    let mut expected_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let expected_digest = tpm2::crypto::hmac(
        &TestCryptoProvider,
        TpmiAlgHash::Sha256,
        key_bytes,
        &full_data,
        &mut expected_buf,
    )
    .unwrap();

    assert_eq!(complete_resp.result.as_slice(), expected_digest.digest());
}

#[test]
fn test_hmac_sequence_memory_limit() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm_with_crypto(&crypto, &mut storage, &mut timer);

    let key_handle = 0x80000005u32;
    insert_keyed_hash_key(
        &mut global_state,
        key_handle,
        b"keyauth",
        b"key",
        TpmaObject::SIGN_ENCRYPT,
    );

    let auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::new(b"keyauth").unwrap(),
    }];

    let start_cmd = HMACStart {
        handle: Handle(key_handle),
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let resp = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd, &auths).unwrap();
    let seq_handle = resp.sequence_handle;

    // Send 4 chunks of 1024 bytes (total 4096 bytes)
    let chunk_1024 = vec![0u8; 1024];
    let update_cmd = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: tpm2::Tpm2bMaxBuffer::new(&chunk_1024).unwrap(),
    };
    for _ in 0..4 {
        execute_tpm_command(&mut tpm, &mut global_state, &update_cmd, &[]).unwrap();
    }

    // Now try to update 1 more byte - should fail with Memory
    let update_cmd_err = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: tpm2::Tpm2bMaxBuffer::new(&[0]).unwrap(),
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &update_cmd_err, &[]);
    assert!(res.is_err());
    assert_eq!(res.err().unwrap(), TpmRc::MEMORY.get());

    let complete_cmd = SequenceComplete {
        sequence_handle: seq_handle,
        buffer: tpm2::Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd, &[]).unwrap();
}

#[test]
fn test_hmac_sequence_auth_and_unauthorized_commands() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm_with_crypto(&crypto, &mut storage, &mut timer);

    let key_handle = 0x80000005u32;
    insert_keyed_hash_key(
        &mut global_state,
        key_handle,
        b"keyauth",
        b"key",
        TpmaObject::SIGN_ENCRYPT,
    );

    let auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::new(b"keyauth").unwrap(),
    }];

    let start_cmd = HMACStart {
        handle: Handle(key_handle),
        auth: Tpm2bAuth::new(b"seqauth").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let resp = execute_tpm_command(&mut tpm, &mut global_state, &start_cmd, &auths).unwrap();
    let seq_handle = resp.sequence_handle;

    let update_cmd = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: tpm2::Tpm2bMaxBuffer::new(b"hello").unwrap(),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &update_cmd, &[]);
    assert!(res.is_err());
    assert_eq!(res.err().unwrap(), TpmRc::AUTH_MISSING.get());

    let wrong_auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::new(b"wrongauth").unwrap(),
    }];
    let res = execute_tpm_command(&mut tpm, &mut global_state, &update_cmd, &wrong_auths);
    assert!(res.is_err());
    assert_eq!(
        res.err().unwrap(),
        TpmRc::BAD_AUTH.with(Position::session(1)).get()
    );

    let rp_cmd = ReadPublic {
        object_handle: seq_handle,
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &rp_cmd, &[]);
    assert!(res.is_err());
    assert_eq!(res.err().unwrap(), TpmRc::REFERENCE_H0.get());

    let mac_cmd = HMAC {
        handle: seq_handle,
        buffer: tpm2::Tpm2bMaxBuffer::new(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &mac_cmd, &[]);
    assert!(res.is_err());
    assert_eq!(res.err().unwrap(), TpmRc::AUTH_MISSING.get());

    let bad_update_cmd = SequenceUpdate {
        sequence_handle: Handle(key_handle),
        buffer: tpm2::Tpm2bMaxBuffer::new(b"hello").unwrap(),
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &bad_update_cmd, &auths);
    assert!(res.is_err());
    assert_eq!(
        res.err().unwrap(),
        TpmRc::MODE.with(Position::handle(1)).get()
    );

    let complete_cmd = SequenceComplete {
        sequence_handle: seq_handle,
        buffer: tpm2::Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let correct_auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::new(b"seqauth").unwrap(),
    }];
    execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd, &correct_auths).unwrap();
}

#[test]
fn test_persistent_handle_resolution() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm_with_crypto(&crypto, &mut storage, &mut timer);

    let transient_handle = 0x80000007u32;
    let persistent_handle = 0x81000003u32;
    let key_bytes = b"persistent_key_bytes_secret_12";

    insert_keyed_hash_key(
        &mut global_state,
        transient_handle,
        b"keyauth",
        key_bytes,
        TpmaObject::SIGN_ENCRYPT,
    );

    let evict_cmd = EvictControl {
        auth: Handle::RH_OWNER,
        object_handle: Handle(transient_handle),
        persistent_handle: Handle(persistent_handle),
    };

    let evict_auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    }];

    execute_tpm_command(&mut tpm, &mut global_state, &evict_cmd, &evict_auths).unwrap();

    global_state
        .remove_transient_object(transient_handle)
        .unwrap();

    let rp_cmd = ReadPublic {
        object_handle: Handle(transient_handle),
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &rp_cmd, &[]);
    assert!(res.is_err());
    assert_eq!(res.err().unwrap(), TpmRc::REFERENCE_H0.get());

    let rp_cmd_p = ReadPublic {
        object_handle: Handle(persistent_handle),
    };
    let rp_resp = execute_tpm_command(&mut tpm, &mut global_state, &rp_cmd_p, &[]).unwrap();
    assert!(!rp_resp.name.as_slice().is_empty());

    let mac_cmd = HMAC {
        handle: Handle(persistent_handle),
        buffer: tpm2::Tpm2bMaxBuffer::new(b"hello world").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let key_auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::new(b"keyauth").unwrap(),
    }];
    let mac_resp = execute_tpm_command(&mut tpm, &mut global_state, &mac_cmd, &key_auths).unwrap();

    let mut expected_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let expected_mac = tpm2::crypto::hmac(
        &TestCryptoProvider,
        TpmiAlgHash::Sha256,
        key_bytes,
        b"hello world",
        &mut expected_buf,
    )
    .unwrap();
    assert_eq!(mac_resp.out_hmac.as_slice(), expected_mac.digest());

    let hmac_start_cmd = HMACStart {
        handle: Handle(persistent_handle),
        auth: Tpm2bAuth::new(b"seqauth").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let hmac_start_resp =
        execute_tpm_command(&mut tpm, &mut global_state, &hmac_start_cmd, &key_auths).unwrap();
    let seq_handle = hmac_start_resp.sequence_handle;

    let seq_auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::new(b"seqauth").unwrap(),
    }];
    let complete_cmd = SequenceComplete {
        sequence_handle: seq_handle,
        buffer: tpm2::Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    execute_tpm_command(&mut tpm, &mut global_state, &complete_cmd, &seq_auths).unwrap();

    let sign_cmd = Sign {
        key_handle: Handle(persistent_handle),
        digest: Tpm2bDigest::new(&[0; 32]).unwrap(),
        in_scheme: Some(TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256)),
        validation: TpmtTkHashcheck::default(),
    };
    let mut response_buf = [0u8; 32768];
    let res = execute_tpm_sign(
        &mut tpm,
        &mut global_state,
        &sign_cmd,
        &key_auths,
        &mut response_buf,
    );
    assert!(res.is_err());
    assert_eq!(res.err().unwrap() & 0xFF, TpmRc::VALUE.to_rc().get() & 0xFF);

    let evict_cmd_p = EvictControl {
        auth: Handle::RH_OWNER,
        object_handle: Handle(persistent_handle),
        persistent_handle: Handle(persistent_handle),
    };
    execute_tpm_command(&mut tpm, &mut global_state, &evict_cmd_p, &evict_auths).unwrap();
}
