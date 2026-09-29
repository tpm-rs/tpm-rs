use tpm2::{Marshal, Unmarshal};

mod common;

use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::commands::{
    Command, EvictControl, EvictControlHandles, ReadPublic, ReadPublicHandles, SequenceComplete,
    SequenceCompleteHandles, SequenceUpdate, SequenceUpdateHandles, Sign, SignHandles,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmCc};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bNonce, TpmaObject, TpmaSession,
    TpmiAlgHash, TpmsAuthCommand, TpmtPublic, TpmtSigScheme, TpmtTkHashcheck,
};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

// Local structures for commands not fully exported by tpm2 or tpm2-impl.
#[derive(Clone, PartialEq, Default, Debug)]
pub struct LocalHmacStartCmd<'a> {
    pub auth: Tpm2bAuth<'a>,
    pub hash_alg: Option<TpmiAlgHash>,
}
impl tpm2::Marshal for LocalHmacStartCmd<'_> {
    const MAX_SIZE: usize = Tpm2bAuth::MAX_SIZE + <Option<TpmiAlgHash>>::MAX_SIZE;
    type MaxBuffer = [u8; Tpm2bAuth::MAX_SIZE + <Option<TpmiAlgHash>>::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let mut offset = self
            .auth
            .marshal((&mut dst[0..Tpm2bAuth::MAX_SIZE]).try_into().unwrap());
        offset += self.hash_alg.marshal(
            (&mut dst[offset..offset + <Option<TpmiAlgHash>>::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset
    }
}
impl<'a> tpm2::Unmarshal<'a> for LocalHmacStartCmd<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, tpm2::errors::UnmarshalError> {
        let auth = Tpm2bAuth::unmarshal(src)?;
        let hash_alg = <Option<TpmiAlgHash>>::unmarshal(src)?;
        Ok(Self { auth, hash_alg })
    }
}

#[derive(Clone, Copy, PartialEq, Default, Debug)]
pub struct LocalHmacStartHandles {
    pub handle: Handle,
}
impl tpm2::Marshal for LocalHmacStartHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.handle.marshal(dst)
    }
}
impl<'a> tpm2::Unmarshal<'a> for LocalHmacStartHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, tpm2::errors::UnmarshalError> {
        let handle = Handle::unmarshal(src)?;
        Ok(Self { handle })
    }
}

#[derive(Clone, Copy, PartialEq, Default, Debug)]
pub struct LocalHmacStartRespHandles {
    pub sequence_handle: Handle,
}
impl tpm2::Marshal for LocalHmacStartRespHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.sequence_handle.marshal(dst)
    }
}
impl<'a> tpm2::Unmarshal<'a> for LocalHmacStartRespHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, tpm2::errors::UnmarshalError> {
        let sequence_handle = Handle::unmarshal(src)?;
        Ok(Self { sequence_handle })
    }
}

impl Command for LocalHmacStartCmd<'_> {
    const CMD_CODE: TpmCc = TpmCc::HmacStart;
    type Handles = LocalHmacStartHandles;
    type Response<'a> = ();
    type RespHandles = LocalHmacStartRespHandles;
}

#[derive(Clone, PartialEq, Default, Debug)]
pub struct LocalMacCmd<'a> {
    pub in_buffer: tpm2::Tpm2bMaxBuffer<'a>,
    pub hash_alg: Option<TpmiAlgHash>,
}
impl tpm2::Marshal for LocalMacCmd<'_> {
    const MAX_SIZE: usize = tpm2::Tpm2bMaxBuffer::MAX_SIZE + <Option<TpmiAlgHash>>::MAX_SIZE;
    type MaxBuffer = [u8; tpm2::Tpm2bMaxBuffer::MAX_SIZE + <Option<TpmiAlgHash>>::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let mut offset = self.in_buffer.marshal(
            (&mut dst[0..tpm2::Tpm2bMaxBuffer::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset += self.hash_alg.marshal(
            (&mut dst[offset..offset + <Option<TpmiAlgHash>>::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset
    }
}
impl<'a> tpm2::Unmarshal<'a> for LocalMacCmd<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, tpm2::errors::UnmarshalError> {
        let in_buffer = tpm2::Tpm2bMaxBuffer::unmarshal(src)?;
        let hash_alg = <Option<TpmiAlgHash>>::unmarshal(src)?;
        Ok(Self {
            in_buffer,
            hash_alg,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Default, Debug)]
pub struct LocalMacHandles {
    pub handle: Handle,
}
impl tpm2::Marshal for LocalMacHandles {
    const MAX_SIZE: usize = Handle::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.handle.marshal(dst)
    }
}
impl<'a> tpm2::Unmarshal<'a> for LocalMacHandles {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, tpm2::errors::UnmarshalError> {
        let handle = Handle::unmarshal(src)?;
        Ok(Self { handle })
    }
}

#[derive(Clone, PartialEq, Default, Debug)]
pub struct LocalMacRsp<'a> {
    pub out_hmac: Tpm2bDigest<'a>,
}
impl tpm2::Marshal for LocalMacRsp<'_> {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; Tpm2bDigest::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.out_hmac.marshal(dst)
    }
}
impl<'a> tpm2::Unmarshal<'a> for LocalMacRsp<'a> {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, tpm2::errors::UnmarshalError> {
        let out_hmac = Tpm2bDigest::unmarshal(src)?;
        Ok(Self { out_hmac })
    }
}

impl Command for LocalMacCmd<'_> {
    const CMD_CODE: TpmCc = TpmCc::MAC;
    type Handles = LocalMacHandles;
    type Response<'a> = LocalMacRsp<'a>;
    type RespHandles = ();
}

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

fn execute_tpm_sign<'a>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &SignHandles,
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

    let mut handles_buf = [0u8; SignHandles::MAX_SIZE];
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

    let mut cmd_buf = [0u8; Sign::MAX_SIZE];
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

fn insert_keyed_hash_key(
    global_state: &mut tpm2_impl::GlobalState,
    handle: u32,
    auth: &[u8],
    secret_key: &[u8],
    attributes: TpmaObject,
) {
    let mut private = [0u8; 1536];
    private[..secret_key.len()].copy_from_slice(secret_key);

    let name_str = hex!("000b 23791a27e7f7bb196e8d2e4d9c72e2762283ea01");
    let name = tpm2::Tpm2bName::from_bytes(&name_str).unwrap();

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attributes | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, tpm2::Tpm2bDigest::default()),
    };

    let obj = tpm2_impl::handler::TransientObject {
        handle,
        seed: [0u8; 32],
        name: name.into(),
        auth: (Tpm2bAuth::from_bytes(auth).unwrap()).into(),
        public: public.into(),
        private,
        private_len: secret_key.len(),
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
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_crypto(&mut crypto, &mut storage, &mut timer, &rng);

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
        hmac: Tpm2bAuth::from_bytes(b"keyauth").unwrap(),
    }];

    let mut seq_handles = Vec::new();
    for _ in 0..tpm2_impl::MAX_ACTIVE_SEQUENCES {
        let start_cmd = LocalHmacStartCmd {
            auth: Tpm2bAuth::from_bytes(b"seqauth").unwrap(),
            hash_alg: Some(TpmiAlgHash::Sha256),
        };
        let start_handles = LocalHmacStartHandles {
            handle: Handle(key_handle),
        };
        let (resp_handles, _) = execute_tpm_command(
            &mut tpm,
            &mut global_state,
            &start_handles,
            &start_cmd,
            &auths,
        )
        .unwrap();
        seq_handles.push(resp_handles.sequence_handle);
    }

    let start_cmd = LocalHmacStartCmd {
        auth: Tpm2bAuth::from_bytes(b"seqauth").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_handles = LocalHmacStartHandles {
        handle: Handle(key_handle),
    };
    let res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &start_handles,
        &start_cmd,
        &auths,
    );
    assert!(res.is_err());
    assert_eq!(res.err().unwrap(), TpmRc::OBJECT_MEMORY.get());

    let complete_handles = SequenceCompleteHandles {
        sequence_handle: seq_handles[0],
    };
    let complete_cmd = SequenceComplete {
        buffer: tpm2::Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(b"seqauth").unwrap(),
    }];
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles,
        &complete_cmd,
        &complete_auths,
    )
    .unwrap();

    let (resp_handles, _) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &start_handles,
        &start_cmd,
        &auths,
    )
    .unwrap();
    let new_seq_handle = resp_handles.sequence_handle;
    assert_eq!(new_seq_handle.0, seq_handles[0].0);
}

#[test]
fn test_hmac_sequence_correctness_and_split_chunks() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_crypto(&mut crypto, &mut storage, &mut timer, &rng);

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
        hmac: Tpm2bAuth::from_bytes(b"keyauth").unwrap(),
    }];

    let start_cmd = LocalHmacStartCmd {
        auth: Tpm2bAuth::from_bytes(b"seqauth").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_handles = LocalHmacStartHandles {
        handle: Handle(key_handle),
    };
    let (resp_handles, _) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &start_handles,
        &start_cmd,
        &auths,
    )
    .unwrap();
    let seq_handle = resp_handles.sequence_handle;

    let seq_auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(b"seqauth").unwrap(),
    }];

    let chunk1 = b"Hello, ";
    let chunk2 = b"this is a stress test for ";
    let chunk3 = b"HMAC sequence updates!";

    let update_handles = SequenceUpdateHandles {
        sequence_handle: seq_handle,
    };

    let update_cmd1 = SequenceUpdate {
        buffer: tpm2::Tpm2bMaxBuffer::from_bytes(chunk1).unwrap(),
    };
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &update_handles,
        &update_cmd1,
        &seq_auths,
    )
    .unwrap();

    let update_cmd2 = SequenceUpdate {
        buffer: tpm2::Tpm2bMaxBuffer::from_bytes(chunk2).unwrap(),
    };
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &update_handles,
        &update_cmd2,
        &seq_auths,
    )
    .unwrap();

    let update_cmd3 = SequenceUpdate {
        buffer: tpm2::Tpm2bMaxBuffer::from_bytes(chunk3).unwrap(),
    };
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &update_handles,
        &update_cmd3,
        &seq_auths,
    )
    .unwrap();

    let final_chunk = b" End of sequence.";
    let complete_handles = SequenceCompleteHandles {
        sequence_handle: seq_handle,
    };
    let complete_cmd = SequenceComplete {
        buffer: tpm2::Tpm2bMaxBuffer::from_bytes(final_chunk).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let (_, complete_resp) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles,
        &complete_cmd,
        &seq_auths,
    )
    .unwrap();

    let mut full_data = Vec::new();
    full_data.extend_from_slice(chunk1);
    full_data.extend_from_slice(chunk2);
    full_data.extend_from_slice(chunk3);
    full_data.extend_from_slice(final_chunk);

    let mut expected_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let expected_digest = tpm2::crypto::hmac(
        &TestCryptoProvider,
        TpmiAlgHash::Sha256,
        key_bytes,
        &full_data,
        &mut expected_buf,
    )
    .unwrap();

    assert_eq!(complete_resp.result.get_buffer(), expected_digest.digest());
}

#[test]
fn test_hmac_sequence_memory_limit() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_crypto(&mut crypto, &mut storage, &mut timer, &rng);

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
        hmac: Tpm2bAuth::from_bytes(b"keyauth").unwrap(),
    }];

    let start_cmd = LocalHmacStartCmd {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_handles = LocalHmacStartHandles {
        handle: Handle(key_handle),
    };
    let (resp_handles, _) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &start_handles,
        &start_cmd,
        &auths,
    )
    .unwrap();
    let seq_handle = resp_handles.sequence_handle;

    // Send 4 chunks of 1024 bytes (total 4096 bytes)
    let chunk_1024 = vec![0u8; 1024];
    let update_handles = SequenceUpdateHandles {
        sequence_handle: seq_handle,
    };
    let update_cmd = SequenceUpdate {
        buffer: tpm2::Tpm2bMaxBuffer::from_bytes(&chunk_1024).unwrap(),
    };
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

    // Now try to update 1 more byte - should fail with Memory (0x903)
    let update_cmd_err = SequenceUpdate {
        buffer: tpm2::Tpm2bMaxBuffer::from_bytes(&[0]).unwrap(),
    };
    let res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &update_handles,
        &update_cmd_err,
        &[],
    );
    assert!(res.is_err());
    assert_eq!(res.err().unwrap(), TpmRc::MEMORY.get());

    let complete_handles = SequenceCompleteHandles {
        sequence_handle: seq_handle,
    };
    let complete_cmd = SequenceComplete {
        buffer: tpm2::Tpm2bMaxBuffer::default(),
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
}

#[test]
fn test_hmac_sequence_auth_and_unauthorized_commands() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_crypto(&mut crypto, &mut storage, &mut timer, &rng);

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
        hmac: Tpm2bAuth::from_bytes(b"keyauth").unwrap(),
    }];

    let start_cmd = LocalHmacStartCmd {
        auth: Tpm2bAuth::from_bytes(b"seqauth").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_handles = LocalHmacStartHandles {
        handle: Handle(key_handle),
    };
    let (resp_handles, _) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &start_handles,
        &start_cmd,
        &auths,
    )
    .unwrap();
    let seq_handle = resp_handles.sequence_handle;

    let update_handles = SequenceUpdateHandles {
        sequence_handle: seq_handle,
    };
    let update_cmd = SequenceUpdate {
        buffer: tpm2::Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
    };

    let res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &update_handles,
        &update_cmd,
        &[],
    );
    assert!(res.is_err());
    assert_eq!(res.err().unwrap(), TpmRc::AUTH_MISSING.get());

    let wrong_auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(b"wrongauth").unwrap(),
    }];
    let res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &update_handles,
        &update_cmd,
        &wrong_auths,
    );
    assert!(res.is_err());
    assert_eq!(
        res.err().unwrap(),
        TpmRc::BAD_AUTH.with(Position::session(1)).get()
    );

    let rp_handles = ReadPublicHandles {
        object_handle: seq_handle,
    };
    let rp_cmd = ReadPublic {};
    let res = execute_tpm_command(&mut tpm, &mut global_state, &rp_handles, &rp_cmd, &[]);
    assert!(res.is_err());
    assert_eq!(res.err().unwrap(), TpmRc::REFERENCE_H0.get());

    let mac_handles = LocalMacHandles { handle: seq_handle };
    let mac_cmd = LocalMacCmd {
        in_buffer: tpm2::Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &mac_handles, &mac_cmd, &[]);
    assert!(res.is_err());
    assert_eq!(res.err().unwrap(), TpmRc::AUTH_MISSING.get());

    let bad_update_handles = SequenceUpdateHandles {
        sequence_handle: Handle(key_handle),
    };
    let res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &bad_update_handles,
        &update_cmd,
        &auths,
    );
    assert!(res.is_err());
    assert_eq!(
        res.err().unwrap(),
        TpmRc::MODE.with(Position::handle(1)).get()
    );

    let complete_handles = SequenceCompleteHandles {
        sequence_handle: seq_handle,
    };
    let complete_cmd = SequenceComplete {
        buffer: tpm2::Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let correct_auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(b"seqauth").unwrap(),
    }];
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles,
        &complete_cmd,
        &correct_auths,
    )
    .unwrap();
}

#[test]
fn test_persistent_handle_resolution() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_tpm_with_crypto(&mut crypto, &mut storage, &mut timer, &rng);

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

    let evict_handles = EvictControlHandles {
        auth: Handle::RH_OWNER,
        object_handle: Handle(transient_handle),
    };
    let evict_cmd = EvictControl {
        persistent_handle: Handle(persistent_handle),
    };

    let evict_auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    }];

    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &evict_handles,
        &evict_cmd,
        &evict_auths,
    )
    .unwrap();

    global_state
        .remove_transient_object(transient_handle)
        .unwrap();

    let rp_handles = ReadPublicHandles {
        object_handle: Handle(transient_handle),
    };
    let rp_cmd = ReadPublic {};
    let res = execute_tpm_command(&mut tpm, &mut global_state, &rp_handles, &rp_cmd, &[]);
    assert!(res.is_err());
    assert_eq!(res.err().unwrap(), TpmRc::REFERENCE_H0.get());

    let rp_handles_p = ReadPublicHandles {
        object_handle: Handle(persistent_handle),
    };
    let (_, rp_resp) =
        execute_tpm_command(&mut tpm, &mut global_state, &rp_handles_p, &rp_cmd, &[]).unwrap();
    assert!(!rp_resp.name.get_buffer().is_empty());

    let mac_handles = LocalMacHandles {
        handle: Handle(persistent_handle),
    };
    let mac_cmd = LocalMacCmd {
        in_buffer: tpm2::Tpm2bMaxBuffer::from_bytes(b"hello world").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let key_auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(b"keyauth").unwrap(),
    }];
    let (_, mac_resp) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &mac_handles,
        &mac_cmd,
        &key_auths,
    )
    .unwrap();

    let mut expected_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let expected_mac = tpm2::crypto::hmac(
        &TestCryptoProvider,
        TpmiAlgHash::Sha256,
        key_bytes,
        b"hello world",
        &mut expected_buf,
    )
    .unwrap();
    assert_eq!(mac_resp.out_hmac.get_buffer(), expected_mac.digest());

    let hmac_start_cmd = LocalHmacStartCmd {
        auth: Tpm2bAuth::from_bytes(b"seqauth").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let hmac_start_handles = LocalHmacStartHandles {
        handle: Handle(persistent_handle),
    };
    let (hmac_start_resp_handles, _) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &hmac_start_handles,
        &hmac_start_cmd,
        &key_auths,
    )
    .unwrap();
    let seq_handle = hmac_start_resp_handles.sequence_handle;

    let seq_auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(b"seqauth").unwrap(),
    }];
    let complete_handles = SequenceCompleteHandles {
        sequence_handle: seq_handle,
    };
    let complete_cmd = SequenceComplete {
        buffer: tpm2::Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles,
        &complete_cmd,
        &seq_auths,
    )
    .unwrap();

    let sign_handles = SignHandles {
        key_handle: Handle(persistent_handle),
    };
    let sign_cmd = Sign {
        digest: Tpm2bDigest::from_bytes(&[0; 32]).unwrap(),
        in_scheme: Some(TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256)),
        validation: TpmtTkHashcheck::default(),
    };
    let mut response_buf = [0u8; 32768];
    let res = execute_tpm_sign(
        &mut tpm,
        &mut global_state,
        &sign_handles,
        &sign_cmd,
        &key_auths,
        &mut response_buf,
    );
    assert!(res.is_err());
    assert_eq!(res.err().unwrap(), TpmRc::VALUE.get());

    let evict_handles_p = EvictControlHandles {
        auth: Handle::RH_OWNER,
        object_handle: Handle(persistent_handle),
    };
    let evict_cmd_p = EvictControl {
        persistent_handle: Handle(persistent_handle),
    };
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &evict_handles_p,
        &evict_cmd_p,
        &evict_auths,
    )
    .unwrap();
}
