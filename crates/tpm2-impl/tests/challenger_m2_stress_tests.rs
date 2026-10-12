#![allow(clippy::unwrap_used, clippy::expect_used)]

extern crate alloc;

mod common;

use alloc::vec::Vec;
use common::{FakeRng, FakeStorage, FakeTimer, TestCryptoProvider, marshal_to_slice};
use hex_literal::hex;
use tpm2::commands::{
    Certify, Command, EvictControl, HMACStart, Message, ReadPublic, SequenceComplete,
    SequenceUpdate, UnmarshalMessage,
};
use tpm2::crypto::{Random, Rsa, RsaPrivateKey, RsaPublicKey};
use tpm2::errors::TpmRc;
use tpm2::{
    Handle, Marshal, PublicParmsAndId, ResponseHeader, Tpm2bAuth, Tpm2bData, Tpm2bDigest,
    Tpm2bMaxBuffer, Tpm2bName, Tpm2bNonce, TpmaObject, TpmaSession, TpmiAlgHash, TpmiRsaKeyBits,
    TpmiStCommandTag, TpmsAuthCommand, TpmsRsaParms, TpmtPublic, TpmtRsaScheme, TpmtSignature,
    Unmarshal,
};
use tpm2_impl::handler::TransientObject;
use tpm2_impl::owned::{OwnedPrivateKeyRsa, OwnedSensitiveComposite, OwnedSensitiveData};
use tpm2_impl::{TpmEngine, TpmPlatform};

struct CertifyHandles {
    pub object_handle: Handle,
    pub sign_handle: Handle,
}

struct HmacStartHandles {
    pub handle: Handle,
}

struct SequenceCompleteHandles {
    pub sequence_handle: Handle,
}

struct SequenceUpdateHandles {
    pub sequence_handle: Handle,
}

struct EvictControlHandles {
    pub auth: Handle,
    pub object_handle: Handle,
}

struct ReadPublicHandles {
    pub object_handle: Handle,
}

trait TestHandles {
    fn to_vec(&self) -> Vec<Handle>;
}

impl TestHandles for CertifyHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.object_handle, self.sign_handle]
    }
}
impl TestHandles for HmacStartHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.handle]
    }
}
impl TestHandles for SequenceCompleteHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.sequence_handle]
    }
}
impl TestHandles for SequenceUpdateHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.sequence_handle]
    }
}
impl TestHandles for EvictControlHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.auth, self.object_handle]
    }
}
impl TestHandles for ReadPublicHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.object_handle]
    }
}

fn setup_tpm<'a>(
    crypto: &'a TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    _rng: &FakeRng,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer>,
    tpm2_impl::GlobalState,
) {
    let rng = crypto.rng_seeded(&[0u8; 32]).unwrap();
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state).unwrap();
    global_state.g_nv_ok = true;
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

fn execute_tpm_command<C: Command, H: TestHandles>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &H,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<(C::Response<'static>, C::Response<'static>), u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: UnmarshalMessage<'static> + Copy,
{
    let mut request_buf = [0u8; 32768];
    let mut offset = 10;

    let tag: u16 = if auths.is_empty() { 0x8001 } else { 0x8002 };
    request_buf[0..2].copy_from_slice(&tag.to_be_bytes());
    request_buf[6..10].copy_from_slice(&C::CMD_CODE.code().to_be_bytes());

    for h in handles.to_vec() {
        request_buf[offset..offset + 4].copy_from_slice(&h.0.to_be_bytes());
        offset += 4;
    }

    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4;
        let auth_start = offset;
        for auth in auths {
            let mut auth_slice = [0u8; TpmsAuthCommand::MAX_SIZE];
            let auth_len = auth.marshal(&mut auth_slice);
            request_buf[offset..offset + auth_len].copy_from_slice(&auth_slice[..auth_len]);
            offset += auth_len;
        }
        let auth_len = u32::try_from(offset - auth_start).unwrap();
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    let cmd_len = marshal_to_slice(cmd, &mut request_buf[offset..]);
    offset += cmd_len;
    let total_size = u32::try_from(offset).unwrap();
    request_buf[2..6].copy_from_slice(&total_size.to_be_bytes());

    let mut response_buf = [0u8; 32768];
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);
    assert!(resp_size >= ResponseHeader::MAX_SIZE);

    let mut resp_slice: &'static [u8] = std::vec::Vec::leak(response_buf[..resp_size].to_vec());
    let resp_header = ResponseHeader::unmarshal(&mut resp_slice).unwrap();
    if let Err(rc) = resp_header.rc {
        return Err(rc.get());
    }

    let mut resp_handles = <C::Response<'static> as Message>::Handles::default();
    for h in resp_handles.as_mut() {
        *h = Handle::unmarshal(&mut resp_slice).map_err(|_| TpmRc::FAILURE.get())?;
    }

    if resp_header.tag == TpmiStCommandTag::Sessions {
        let param_size = usize::try_from(u32::unmarshal(&mut resp_slice).unwrap()).unwrap();
        let mut param_slice = &resp_slice[..param_size];
        let resp_params = C::Response::unmarshal_with_handles(resp_handles, &mut param_slice)
            .map_err(|_| TpmRc::FAILURE.get())?;
        Ok((resp_params, resp_params))
    } else {
        let resp_params = C::Response::unmarshal_with_handles(resp_handles, &mut resp_slice)
            .map_err(|_| TpmRc::FAILURE.get())?;
        Ok((resp_params, resp_params))
    }
}

fn execute_tpm_certify<'a>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &CertifyHandles,
    cmd: &Certify,
    auths: &[TpmsAuthCommand],
    response_buf: &'a mut [u8; 32768],
) -> Result<<Certify<'static> as Command>::Response<'a>, u32> {
    let mut request_buf = [0u8; 32768];
    let mut offset = 10;

    let tag: u16 = if auths.is_empty() { 0x8001 } else { 0x8002 };
    request_buf[0..2].copy_from_slice(&tag.to_be_bytes());
    request_buf[6..10].copy_from_slice(&Certify::CMD_CODE.code().to_be_bytes());

    for h in handles.to_vec() {
        request_buf[offset..offset + 4].copy_from_slice(&h.0.to_be_bytes());
        offset += 4;
    }

    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4;
        let auth_start = offset;
        for auth in auths {
            let mut auth_slice = [0u8; TpmsAuthCommand::MAX_SIZE];
            let auth_len = auth.marshal(&mut auth_slice);
            request_buf[offset..offset + auth_len].copy_from_slice(&auth_slice[..auth_len]);
            offset += auth_len;
        }
        let auth_len = u32::try_from(offset - auth_start).unwrap();
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    let mut cmd_buf = [0u8; Certify::MAX_SIZE];
    let cmd_len = cmd.marshal(&mut cmd_buf);
    request_buf[offset..offset + cmd_len].copy_from_slice(&cmd_buf.as_ref()[..cmd_len]);
    offset += cmd_len;
    let total_size = u32::try_from(offset).unwrap();
    request_buf[2..6].copy_from_slice(&total_size.to_be_bytes());

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
    <<Certify<'static> as Command>::Response<'a> as UnmarshalMessage<'a>>::unmarshal_with_handles(
        [],
        &mut params_slice,
    )
    .map_err(|_| TpmRc::FAILURE.get())
}

fn make_keyed_hash_key(handle: u32, key_bytes: &[u8]) -> TransientObject {
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, tpm2::Tpm2bDigest::default()),
    };
    TransientObject {
        handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: Tpm2bName::new(&[1, 2, 3]).unwrap().into(),
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        sensitive: OwnedSensitiveComposite::KeyedHash(
            OwnedSensitiveData::from_bytes(key_bytes).unwrap(),
        ),
        qualified_name: Tpm2bName::new(&[1, 2, 3]).unwrap().into(),
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

// 1. Starting multiple concurrent HMAC sequences.
#[test]
fn test_concurrent_hmac_sequences() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let key_handle = 0x80000001;
    let key = make_keyed_hash_key(key_handle, b"hmac_key_bytes");
    global_state.transient_objects[0] = Some(key);

    let start_cmd = HMACStart {
        handle: Handle(key_handle),
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_handles = HmacStartHandles {
        handle: Handle(key_handle),
    };

    let mut handles = Vec::new();
    // Start up to MAX_ACTIVE_SEQUENCES concurrent HMAC sequences
    for _ in 0..tpm2_impl::MAX_ACTIVE_SEQUENCES {
        let (resp_h, _) =
            execute_tpm_command(&mut tpm, &mut global_state, &start_handles, &start_cmd, &[])
                .unwrap();
        handles.push(resp_h.sequence_handle);
    }

    // Try starting one more, should fail with TPM_RC_OBJECT_MEMORY (0x902)
    let start_res =
        execute_tpm_command(&mut tpm, &mut global_state, &start_handles, &start_cmd, &[]);
    assert!(start_res.is_err());
    let rc = start_res.unwrap_err();
    assert_eq!(rc & 0xFF, 0x02);

    // Complete one sequence
    let complete_handles = SequenceCompleteHandles {
        sequence_handle: handles[0],
    };
    let complete_cmd = SequenceComplete {
        sequence_handle: handles[0],
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

    // Now starting another should succeed
    let start_res_ok =
        execute_tpm_command(&mut tpm, &mut global_state, &start_handles, &start_cmd, &[]);
    assert!(start_res_ok.is_ok());
}

// 2. Using invalid session attributes or unauthorized commands.
#[test]
fn test_hmac_sequence_auth_failures() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let key_handle = 0x80000001;
    let key = make_keyed_hash_key(key_handle, b"hmac_key_bytes");
    global_state.transient_objects[0] = Some(key);

    let seq_auth = b"SeqPassword123";
    let start_cmd = HMACStart {
        handle: Handle(key_handle),
        auth: Tpm2bAuth::new(seq_auth).unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_handles = HmacStartHandles {
        handle: Handle(key_handle),
    };
    let (start_resp_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &start_handles, &start_cmd, &[]).unwrap();
    let seq_handle = start_resp_handles.sequence_handle;

    // Try updating sequence with WRONG password session
    let wrong_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::new(b"WrongPassword123").unwrap(),
    };
    let update_handles = SequenceUpdateHandles {
        sequence_handle: seq_handle,
    };
    let update_cmd = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::new(b"data").unwrap(),
    };
    let update_res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &update_handles,
        &update_cmd,
        &[wrong_auth],
    );
    assert_eq!(update_res, Err(0x9A2)); // TPM_RC_BAD_AUTH for session 1

    // Update with CORRECT password session
    let correct_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::new(seq_auth).unwrap(),
    };
    let update_res_ok = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &update_handles,
        &update_cmd,
        &[correct_auth],
    );
    assert!(update_res_ok.is_ok());

    // Try completing sequence with WRONG password session
    let complete_handles = SequenceCompleteHandles {
        sequence_handle: seq_handle,
    };
    let complete_cmd = SequenceComplete {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles,
        &complete_cmd,
        &[wrong_auth],
    );
    assert_eq!(complete_res, Err(0x9A2));

    // Complete with CORRECT password session
    let complete_res_ok = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles,
        &complete_cmd,
        &[correct_auth],
    );
    assert!(complete_res_ok.is_ok());
}

// 3. Performing HMAC update with very large data buffers or split chunks.
#[test]
fn test_hmac_sequence_large_split_chunks() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let key_handle = 0x80000001;
    let key_bytes = b"hmac_key_bytes";
    let key = make_keyed_hash_key(key_handle, key_bytes);
    global_state.transient_objects[0] = Some(key);

    let start_cmd = HMACStart {
        handle: Handle(key_handle),
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_handles = HmacStartHandles {
        handle: Handle(key_handle),
    };
    let (start_resp_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &start_handles, &start_cmd, &[]).unwrap();
    let seq_handle = start_resp_handles.sequence_handle;

    let update_handles = SequenceUpdateHandles {
        sequence_handle: seq_handle,
    };

    // Update with 10 split chunks of 100 bytes each
    let chunk = [0x55u8; 100];
    let update_cmd = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::new(&chunk).unwrap(),
    };
    for _ in 0..10 {
        execute_tpm_command(
            &mut tpm,
            &mut global_state,
            &update_handles,
            &update_cmd,
            &[],
        )
        .unwrap();
    }

    // Complete sequence
    let complete_handles = SequenceCompleteHandles {
        sequence_handle: seq_handle,
    };
    let complete_cmd = SequenceComplete {
        sequence_handle: seq_handle,
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

    // Verify HMAC output using TestCryptoProvider's hmac function accessed via tpm context
    let combined_data = vec![0x55u8; 1000];
    let mut expected_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let expected_digest = tpm2::crypto::hmac(
        tpm.platform.crypto,
        TpmiAlgHash::Sha256,
        key_bytes,
        &combined_data,
        &mut expected_buf,
    )
    .unwrap();
    assert_eq!(complete_resp.result.as_slice(), expected_digest.digest());

    // Test streaming past 4096 bytes succeeds with streaming hash state
    let (start_resp_handles_2, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &start_handles, &start_cmd, &[]).unwrap();
    let seq_handle_2 = start_resp_handles_2.sequence_handle;
    let update_handles_2 = SequenceUpdateHandles {
        sequence_handle: seq_handle_2,
    };

    let large_chunk = [0xaa; 1024];
    let update_cmd_large = SequenceUpdate {
        sequence_handle: seq_handle_2,
        buffer: Tpm2bMaxBuffer::new(&large_chunk).unwrap(),
    };
    for _ in 0..4 {
        execute_tpm_command(
            &mut tpm,
            &mut global_state,
            &update_handles_2,
            &update_cmd_large,
            &[],
        )
        .unwrap();
    }

    // Clean up sequence 2
    let complete_handles_2 = SequenceCompleteHandles {
        sequence_handle: seq_handle_2,
    };
    let complete_cmd_2 = SequenceComplete {
        sequence_handle: seq_handle_2,
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles_2,
        &complete_cmd_2,
        &[],
    )
    .unwrap();
}

// 4. Testing persistent handle resolution under different commands (read_public, hmac_start, certify).
#[test]
fn test_persistent_handle_resolution_all() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let transient_key_handle = 0x80000001;
    let persistent_key_handle = 0x81000002;

    let rsa_priv = Rsa::generate_key(
        tpm.platform.crypto,
        &mut tpm.platform.rng,
        TpmiRsaKeyBits::Rsa2048,
        0,
    )
    .unwrap();
    let mut mod_buf = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let modulus = rsa_priv.public_key().modulus(&mut mod_buf).unwrap();
    let mut prime_buf = [0u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES];
    let prime_p = rsa_priv.prime_p(&mut prime_buf).unwrap();

    // Load transient key
    let name = Tpm2bName::new(&[1, 2, 3, 4, 5]).unwrap();
    let transient_key = TransientObject {
        handle: transient_key_handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: name.into(),
        auth: (Tpm2bAuth::new(&[0x11, 0x22]).unwrap()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                    key_bits: TpmiRsaKeyBits::Rsa2048,
                    exponent: 0,
                },
                modulus,
            ),
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::from(prime_p)),
        qualified_name: name.into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(transient_key);

    // Evict key to persistent handle
    let evict_handles = EvictControlHandles {
        auth: Handle::RH_OWNER,
        object_handle: Handle(transient_key_handle),
    };
    let evict_cmd = EvictControl {
        auth: Handle::RH_OWNER,
        object_handle: Handle(transient_key_handle),
        persistent_handle: Handle(persistent_key_handle),
    };
    let owner_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &evict_handles,
        &evict_cmd,
        &[owner_auth],
    )
    .unwrap();

    // Flush/remove transient key
    global_state.transient_objects[0] = None;

    // A. Verify ReadPublic resolves persistent key
    let read_handles = ReadPublicHandles {
        object_handle: Handle(persistent_key_handle),
    };
    let read_cmd = ReadPublic {
        object_handle: Handle(persistent_key_handle),
    };
    let (_, read_resp) =
        execute_tpm_command(&mut tpm, &mut global_state, &read_handles, &read_cmd, &[]).unwrap();
    assert_eq!(read_resp.name, name);

    // B. Verify Certify resolves persistent key as sign_handle
    let certified_handle = 0x80000002;
    let certified_key = make_keyed_hash_key(certified_handle, b"cert_key_bytes");
    global_state.transient_objects[0] = Some(certified_key);

    let certify_handles = CertifyHandles {
        object_handle: Handle(certified_handle),
        sign_handle: Handle(persistent_key_handle),
    };
    let certify_cmd = Certify {
        object_handle: Handle(certified_handle),
        sign_handle: Handle(persistent_key_handle),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    let certified_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };
    let persistent_key_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::new(&[0x11, 0x22]).unwrap(),
    };

    let mut response_buf = [0u8; 32768];
    let certify_resp = execute_tpm_certify(
        &mut tpm,
        &mut global_state,
        &certify_handles,
        &certify_cmd,
        &[certified_auth, persistent_key_auth],
        &mut response_buf,
    )
    .unwrap();
    assert!(matches!(
        certify_resp.signature,
        Some(TpmtSignature::Rsassa(..))
    ));

    // C. Verify HmacStart resolves persistent key as key handle
    let transient_hmac_handle = 0x80000003;
    let hmac_key_bytes = b"pers_hmac_bytes";
    let transient_hmac = make_keyed_hash_key(transient_hmac_handle, hmac_key_bytes);
    global_state.transient_objects[1] = Some(transient_hmac);

    let persistent_hmac_handle = 0x81000003;
    let evict_handles_hmac = EvictControlHandles {
        auth: Handle::RH_OWNER,
        object_handle: Handle(transient_hmac_handle),
    };
    let evict_cmd_hmac = EvictControl {
        auth: Handle::RH_OWNER,
        object_handle: Handle(transient_hmac_handle),
        persistent_handle: Handle(persistent_hmac_handle),
    };
    let owner_auth_hmac = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &evict_handles_hmac,
        &evict_cmd_hmac,
        &[owner_auth_hmac],
    )
    .unwrap();

    // Flush/remove transient key
    global_state.transient_objects[1] = None;

    let hmac_start_cmd = HMACStart {
        handle: Handle(persistent_hmac_handle),
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let hmac_start_handles = HmacStartHandles {
        handle: Handle(persistent_hmac_handle),
    };
    let (hmac_start_resp_handles, _) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &hmac_start_handles,
        &hmac_start_cmd,
        &[],
    )
    .unwrap();
    let seq_handle = hmac_start_resp_handles.sequence_handle;

    // Perform update and complete on the hmac sequence
    let update_handles = SequenceUpdateHandles {
        sequence_handle: seq_handle,
    };
    let update_cmd = SequenceUpdate {
        sequence_handle: seq_handle,
        buffer: Tpm2bMaxBuffer::new(b"hello").unwrap(),
    };
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &update_handles,
        &update_cmd,
        &[],
    )
    .unwrap();

    let complete_handles = SequenceCompleteHandles {
        sequence_handle: seq_handle,
    };
    let complete_cmd = SequenceComplete {
        sequence_handle: seq_handle,
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

    // Verify correct HMAC computed from persistent key using crypto accessed via tpm context
    let mut expected_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let expected_digest = tpm2::crypto::hmac(
        tpm.platform.crypto,
        TpmiAlgHash::Sha256,
        hmac_key_bytes,
        b"hello",
        &mut expected_buf,
    )
    .unwrap();
    assert_eq!(complete_resp.result.as_slice(), expected_digest.digest());
}
