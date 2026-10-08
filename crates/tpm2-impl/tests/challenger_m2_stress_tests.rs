use tpm2::errors::TpmRc;
use tpm2::{Marshal, Unmarshal};
extern crate alloc;

mod common;

use alloc::vec::Vec;
use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::Alg;
use tpm2::Handle;
use tpm2::commands::{
    Certify, CertifyHandles, Command, EvictControl, EvictControlHandles, HmacStart,
    HmacStartHandles, ReadPublic, ReadPublicHandles, SequenceComplete, SequenceCompleteHandles,
    SequenceUpdate, SequenceUpdateHandles,
};
use tpm2::crypto::Rng;
use tpm2::crypto::{Asymmetric, AsymmetricSign};
use tpm2::crypto::{CryptoError, CryptoProvider};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bMaxBuffer, Tpm2bName, Tpm2bNonce,
    Tpm2bPublicKeyRsa, TpmaObject, TpmaSession, TpmiAlgHash, TpmsAuthCommand, TpmtPublic,
    TpmtRsaScheme, TpmtSignature,
};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::TransientObject;

struct ChallengerCrypto {
    crypto: TestCryptoProvider,
}

impl_delegate_hash!(ChallengerCrypto, crypto);

impl AsymmetricSign for ChallengerCrypto {
    fn sign_inner(
        &self,
        _sign_alg: Alg,
        _private_key: &[u8],
        _digest: tpm2::TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let len = 256;
        if signature_out.len() < len {
            return Err(CryptoError::BufferTooSmall);
        }
        signature_out[..len].fill(0xbb);
        Ok(len)
    }
}

impl Asymmetric for ChallengerCrypto {
    fn verify_inner(
        &self,
        sign_alg: Alg,
        public_key: &[u8],
        digest: tpm2::TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.crypto
            .verify_inner(sign_alg, public_key, digest, signature)
    }
    fn encrypt(
        &self,
        scheme: Alg,
        hash_alg: Alg,
        public_key: &[u8],
        data: &[u8],
        ciphertext: &mut [u8],
        label: &[u8],
    ) -> Result<usize, CryptoError> {
        self.crypto
            .encrypt(scheme, hash_alg, public_key, data, ciphertext, label)
    }
    fn decrypt(
        &self,
        scheme: Alg,
        hash_alg: Alg,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        label: &[u8],
    ) -> Result<usize, CryptoError> {
        if private_key.iter().all(|&b| b == 0) {
            let len = ciphertext.len();
            plaintext[..len].copy_from_slice(ciphertext);
            Ok(len)
        } else {
            self.crypto
                .decrypt(scheme, hash_alg, private_key, ciphertext, plaintext, label)
        }
    }
    fn generate_key(
        &self,
        scheme: Alg,
        params: Option<tpm2::crypto::asymmetric::KeyParams>,
        public_key: &mut [u8],
        private_key: &mut [u8],
        seed: Option<&[u8]>,
    ) -> Result<(usize, usize), CryptoError> {
        self.crypto
            .generate_key(scheme, params, public_key, private_key, seed)
    }
}

impl Rng for ChallengerCrypto {
    fn get_random(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        self.crypto.get_random(dest)
    }
}

impl CryptoProvider for ChallengerCrypto {}

fn setup_tpm<'a>(
    crypto: &'a mut ChallengerCrypto,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a FakeRng,
) -> (
    TpmEngine<'a, ChallengerCrypto, FakeStorage, FakeTimer, FakeRng>,
    tpm2_impl::GlobalState,
) {
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
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

fn execute_tpm_command<C: Command>(
    tpm: &mut TpmEngine<'_, ChallengerCrypto, FakeStorage, FakeTimer, FakeRng>,
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

fn execute_tpm_certify<'a>(
    tpm: &mut TpmEngine<'_, ChallengerCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &CertifyHandles,
    cmd: &Certify,
    auths: &[TpmsAuthCommand],
    response_buf: &'a mut [u8; 32768],
) -> Result<<Certify<'static> as Command>::Response<'a>, u32> {
    let mut request_buf = [0u8; 32768];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(Certify::CMD_CODE.code()).to_be_bytes());

    let mut handles_buf = [0u8; CertifyHandles::MAX_SIZE];
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

    let mut cmd_buf = [0u8; Certify::MAX_SIZE];
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

fn make_keyed_hash_key(handle: u32, key_bytes: &[u8]) -> TransientObject {
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, tpm2::Tpm2bDigest::default()),
    };
    let mut private = [0u8; 1536];
    private[..key_bytes.len()].copy_from_slice(key_bytes);
    TransientObject {
        handle,
        seed: [0u8; 32],
        name: Tpm2bName::from_bytes(&[1, 2, 3]).unwrap().into(),
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        private,
        private_len: key_bytes.len(),
        qualified_name: Tpm2bName::from_bytes(&[1, 2, 3]).unwrap().into(),
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

// 1. Starting multiple concurrent HMAC sequences.
#[test]
fn test_concurrent_hmac_sequences() {
    let mut crypto = ChallengerCrypto {
        crypto: TestCryptoProvider,
    };
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let key_handle = 0x80000001;
    let key = make_keyed_hash_key(key_handle, b"hmac_key_bytes");
    global_state.transient_objects[0] = Some(key);

    let start_cmd = HmacStart {
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

    // Now starting a 5th should succeed
    let start_res_ok =
        execute_tpm_command(&mut tpm, &mut global_state, &start_handles, &start_cmd, &[]);
    assert!(start_res_ok.is_ok());
}

// 2. Using invalid session attributes or unauthorized commands.
#[test]
fn test_hmac_sequence_auth_failures() {
    let mut crypto = ChallengerCrypto {
        crypto: TestCryptoProvider,
    };
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let key_handle = 0x80000001;
    let key = make_keyed_hash_key(key_handle, b"hmac_key_bytes");
    global_state.transient_objects[0] = Some(key);

    let seq_auth = b"SeqPassword123";
    let start_cmd = HmacStart {
        auth: Tpm2bAuth::from_bytes(seq_auth).unwrap(),
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
        hmac: Tpm2bAuth::from_bytes(b"WrongPassword123").unwrap(),
    };
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
        &[wrong_auth],
    );
    assert_eq!(update_res, Err(0x9A2)); // TPM_RC_BAD_AUTH for session 1

    // Update with CORRECT password session
    let correct_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(seq_auth).unwrap(),
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
    let mut crypto = ChallengerCrypto {
        crypto: TestCryptoProvider,
    };
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let key_handle = 0x80000001;
    let key_bytes = b"hmac_key_bytes";
    let key = make_keyed_hash_key(key_handle, key_bytes);
    global_state.transient_objects[0] = Some(key);

    let start_cmd = HmacStart {
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
        buffer: Tpm2bMaxBuffer::from_bytes(&chunk).unwrap(),
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
    let mut expected_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let expected_digest = tpm2::crypto::hmac(
        &*tpm.platform.crypto,
        TpmiAlgHash::Sha256,
        key_bytes,
        &combined_data,
        &mut expected_buf,
    )
    .unwrap();
    assert_eq!(complete_resp.result.get_buffer(), expected_digest.digest());

    // Test buffer limits: ActiveSequence buffer is 4096 bytes.
    let (start_resp_handles_2, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &start_handles, &start_cmd, &[]).unwrap();
    let seq_handle_2 = start_resp_handles_2.sequence_handle;
    let update_handles_2 = SequenceUpdateHandles {
        sequence_handle: seq_handle_2,
    };

    // Fill to 4096 bytes
    let large_chunk = [0xaa; 1024];
    let update_cmd_large = SequenceUpdate {
        buffer: Tpm2bMaxBuffer::from_bytes(&large_chunk).unwrap(),
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

    // Try updating 1 more byte -> should fail with TPM_RC_MEMORY (0x904)
    let update_cmd_one = SequenceUpdate {
        buffer: Tpm2bMaxBuffer::from_bytes(&[1]).unwrap(),
    };
    let update_res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &update_handles_2,
        &update_cmd_one,
        &[],
    );
    assert!(update_res.is_err());
    let rc = update_res.unwrap_err();
    assert_eq!(rc & 0xFF, 0x04);

    // Clean up sequence 2 to avoid memory leaks
    let complete_handles_2 = SequenceCompleteHandles {
        sequence_handle: seq_handle_2,
    };
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &complete_handles_2,
        &complete_cmd,
        &[],
    )
    .unwrap();
}

// 4. Testing persistent handle resolution under different commands (read_public, hmac_start, certify).
#[test]
fn test_persistent_handle_resolution_all() {
    let mut crypto = ChallengerCrypto {
        crypto: TestCryptoProvider,
    };
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let transient_key_handle = 0x80000001;
    let persistent_key_handle = 0x81000002;

    // Load transient key
    let name = Tpm2bName::from_bytes(&[1, 2, 3, 4, 5]).unwrap();
    let transient_key = TransientObject {
        handle: transient_key_handle,
        seed: [0u8; 32],
        name: name.into(),
        auth: (Tpm2bAuth::from_bytes(&[0x11, 0x22]).unwrap()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                tpm2::TpmsRsaParms {
                    symmetric: None,
                    scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                    key_bits: tpm2::TpmiRsaKeyBits(2048),
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::default(),
            ),
        })
        .into(),
        private: [0u8; 1536],
        private_len: 256,
        qualified_name: (name).into(),
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
    let read_cmd = ReadPublic {};
    let (_, read_resp) =
        execute_tpm_command(&mut tpm, &mut global_state, &read_handles, &read_cmd, &[]).unwrap();
    assert_eq!(read_resp.name, name);

    // B. Verify Certify resolves persistent key as sign_handle
    // Load a certified object (could be any key, let's load a simple one)
    let certified_handle = 0x80000002;
    let certified_key = make_keyed_hash_key(certified_handle, b"cert_key_bytes");
    global_state.transient_objects[0] = Some(certified_key);

    let certify_handles = CertifyHandles {
        object_handle: Handle(certified_handle),
        sign_handle: Handle(persistent_key_handle),
    };
    let certify_cmd = Certify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    // Use password auth for both the certified key (empty auth) and the persistent key (password [0x11, 0x22])
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
        hmac: Tpm2bAuth::from_bytes(&[0x11, 0x22]).unwrap(),
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
    // Evict an HMAC key to a persistent handle
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

    let hmac_start_cmd = HmacStart {
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
        buffer: Tpm2bMaxBuffer::from_bytes(b"hello").unwrap(),
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
    let mut expected_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let expected_digest = tpm2::crypto::hmac(
        &*tpm.platform.crypto,
        TpmiAlgHash::Sha256,
        hmac_key_bytes,
        b"hello",
        &mut expected_buf,
    )
    .unwrap();
    assert_eq!(complete_resp.result.get_buffer(), expected_digest.digest());
}
