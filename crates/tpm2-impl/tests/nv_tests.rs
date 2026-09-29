extern crate alloc;
use common::marshal_to_slice;
use tpm2::Alg;
use tpm2::errors::TpmRc;
use tpm2::{Marshal, TpmNt, Unmarshal};

mod common;

use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::commands::{
    Command, NVChangeAuth, NVChangeAuthHandles, NVDefineSpace, NVDefineSpaceHandles, NVExtend,
    NVExtendHandles, NVRead, NVReadHandles, NVSetBits, NVSetBitsHandles, NVWrite, NVWriteHandles,
    NVWriteLock, NVWriteLockHandles,
};

use common::TestCryptoProvider;
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bDigest, Tpm2bMaxNvBuffer, Tpm2bNonce, TpmaNv, TpmaSession, TpmiAlgHash,
    TpmsAuthCommand, TpmsNvPublic,
};
use tpm2_impl::{TpmEngine, TpmPlatform};

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    tpm2::crypto::hash(&TestCryptoProvider, TpmiAlgHash::Sha256, data, &mut out)
        .unwrap()
        .digest()
        .try_into()
        .unwrap()
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
    global_state.nv_available = true;
    global_state.locality = 0;
    global_state.g_nv_ok = true;

    // Startup(CLEAR)
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    (tpm, global_state)
}

fn make_auth_session(hmac: &[u8]) -> TpmsAuthCommand<'_> {
    TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(hmac).unwrap(),
    }
}

fn execute_tpm_command_with_auths<C: Command>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &C::Handles,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <<C as Command>::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: Unmarshal<'static>,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    // Tag
    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    // Command code
    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    let handles_slice: &mut <C::Handles as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C::Handles as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let handles_len = handles.marshal(handles_slice);
    offset += handles_len;

    // Marshal auth area if tag is 0x8002
    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4; // place holder for auth size
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

    // Fill in total Size
    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut response_buf = [0u8; 16384];
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let mut unmarshal_buf: &'static [u8] = std::vec::Vec::leak(response_buf[..resp_size].to_vec());
    let tag = u16::unmarshal(&mut unmarshal_buf).map_err(|_| TpmRc::FAILURE.get())?;
    let _size = u32::unmarshal(&mut unmarshal_buf).map_err(|_| TpmRc::FAILURE.get())?;
    let rc = u32::unmarshal(&mut unmarshal_buf).map_err(|_| TpmRc::FAILURE.get())?;

    if rc != 0 {
        return Err(rc);
    }

    if tag == 0x8002 {
        let _parameter_size =
            u32::unmarshal(&mut unmarshal_buf).map_err(|_| TpmRc::FAILURE.get())?;
    }

    let resp =
        <C::Response<'static>>::unmarshal(&mut unmarshal_buf).map_err(|_| TpmRc::FAILURE.get())?;
    Ok(resp)
}

#[test]
fn test_nv_extend_success() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let auth_session = make_auth_session(&[]);

    // 1. Define Extend NV index with TPMA_NV_EXTEND | TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD, size=32 (SHA256 digest size)
    let nv_extend_idx = Handle(0x01000010);
    let mut attributes = TpmaNv::from(TpmNt::Extend);
    attributes.insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::PLATFORMCREATE);
    let public_info = tpm2::Tpm2b(TpmsNvPublic {
        nv_index: nv_extend_idx,
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 32,
    });

    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
    };
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define Extend NV space");

    // 2. Call TPM2_NV_Extend with 32 bytes of input data
    let mut input_data = [0u8; 32];
    for (i, byte) in input_data.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(7);
    }

    let extend_handles = NVExtendHandles {
        auth_handle: nv_extend_idx,
        nv_index: nv_extend_idx,
    };
    let extend_cmd = NVExtend {
        data: Tpm2bMaxNvBuffer::from_bytes(&input_data).unwrap(),
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &extend_handles,
        &extend_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to extend NV index");

    // 3. Verify using NV_Read that the stored index equals SHA256(zeros || input)
    let read_handles = NVReadHandles {
        auth_handle: nv_extend_idx,
        nv_index: nv_extend_idx,
    };
    let read_cmd = NVRead {
        size: 32,
        offset: 0,
    };
    let read_resp = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &read_handles,
        &read_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to read NV index after extend");

    // Compute expected SHA256(zeros || input)
    let mut expected_buf = [0u8; 64];
    expected_buf[..32].copy_from_slice(&[0u8; 32]);
    expected_buf[32..64].copy_from_slice(&input_data);
    let expected_hash = sha256_bytes(&expected_buf[..]);

    assert_eq!(read_resp.data.get_buffer(), expected_hash.as_ref());
}

#[test]
fn test_nv_extend_missing_attribute_fails() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let auth_session = make_auth_session(&[]);

    // 1. Define Ordinary NV index without TPMA_NV_EXTEND (TpmNt::Ordinary)
    let nv_ord_idx = Handle(0x01000011);
    let mut attributes = TpmaNv::from(TpmNt::Ordinary);
    attributes.insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::PLATFORMCREATE);
    let public_info = tpm2::Tpm2b(TpmsNvPublic {
        nv_index: nv_ord_idx,
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 32,
    });

    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
    };
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define Ordinary NV space");

    // 2. Call NV_Extend on the Ordinary index and verify it fails with TPM_RC_ATTRIBUTES
    let extend_handles = NVExtendHandles {
        auth_handle: nv_ord_idx,
        nv_index: nv_ord_idx,
    };
    let extend_cmd = NVExtend {
        data: Tpm2bMaxNvBuffer::from_bytes(&[1u8; 32]).unwrap(),
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &extend_handles,
        &extend_cmd,
        core::slice::from_ref(&auth_session),
    );
    assert_eq!(res.err(), Some(TpmRc::ATTRIBUTES.get()));
}

#[test]
fn test_nv_set_bits_bitwise_or() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let auth_session = make_auth_session(&[]);

    // Define a 64-bit (8-byte) NV index with TPMA_NV_BITFIELD | TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD
    let nv_bits_idx = Handle(0x01000020);
    let mut attributes = TpmaNv::from(TpmNt::Bits);
    attributes.insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::PLATFORMCREATE);
    let public_info = tpm2::Tpm2b(TpmsNvPublic {
        nv_index: nv_bits_idx,
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 8,
    });

    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
    };
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define Bits NV space");

    // Call NV_SetBits(0x0F0F)
    let set_handles = NVSetBitsHandles {
        auth_handle: nv_bits_idx,
        nv_index: nv_bits_idx,
    };
    let set_cmd_1 = NVSetBits { bits: 0x0F0F };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &set_handles,
        &set_cmd_1,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed first NV_SetBits");

    // Verify value is 0x0F0F via NV_Read
    let read_handles = NVReadHandles {
        auth_handle: nv_bits_idx,
        nv_index: nv_bits_idx,
    };
    let read_cmd = NVRead { size: 8, offset: 0 };
    let read_resp_1 = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &read_handles,
        &read_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to read NV bits after first set");
    let val_1 = u64::from_be_bytes(read_resp_1.data.get_buffer().try_into().unwrap());
    assert_eq!(val_1, 0x0F0F);

    // Call NV_SetBits(0xF0F0)
    let set_cmd_2 = NVSetBits { bits: 0xF0F0 };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &set_handles,
        &set_cmd_2,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed second NV_SetBits");

    // Verify value becomes 0xFFFF
    let read_resp_2 = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &read_handles,
        &read_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to read NV bits after second set");
    let val_2 = u64::from_be_bytes(read_resp_2.data.get_buffer().try_into().unwrap());
    assert_eq!(val_2, 0xFFFF);
}

#[test]
fn test_nv_change_auth_password_session_rejected() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Define an NV index with authValue="old_pass" and TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE
    let nv_idx = Handle(0x01000030);
    let mut attributes = TpmaNv::from(TpmNt::Ordinary);
    attributes.insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::PLATFORMCREATE);
    let public_info = tpm2::Tpm2b(TpmsNvPublic {
        nv_index: nv_idx,
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 32,
    });

    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
    };
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::from_bytes(b"old_pass").unwrap(),
        public_info,
    };
    let platform_session = make_auth_session(&[]);
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_cmd,
        core::slice::from_ref(&platform_session),
    )
    .expect("Failed to define NV space with old_pass");

    // Call TPM2_NV_ChangeAuth("new_pass") authorized with password session "old_pass"
    // Per TCG spec Section 31.15.2 and CPCTPM_TC2_3_33_15_03, password sessions must be rejected with TPM_RC_AUTH_TYPE
    let change_handles = NVChangeAuthHandles { nv_index: nv_idx };
    let change_cmd = NVChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(b"new_pass").unwrap(),
    };
    let old_auth_session = make_auth_session(b"old_pass");
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &change_handles,
        &change_cmd,
        core::slice::from_ref(&old_auth_session),
    );
    assert_eq!(res.err(), Some(TpmRc::AUTH_TYPE.get()));
}

fn execute_tpm_command_full<'a, C: Command>(
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
    let mut request_buf = [0u8; 16384];
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

    offset += marshal_to_slice(cmd, &mut request_buf[offset..]);

    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut response_buf = [0u8; 16384];
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let mut resp_offset = 0;
    let mut unmarshal_buf: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
    let orig_header_len = unmarshal_buf.len();
    let tag = u16::unmarshal(&mut unmarshal_buf).map_err(|_| TpmRc::FAILURE.get())?;
    let _size = u32::unmarshal(&mut unmarshal_buf).map_err(|_| TpmRc::FAILURE.get())?;
    let rc = u32::unmarshal(&mut unmarshal_buf).map_err(|_| TpmRc::FAILURE.get())?;

    if rc != 0 {
        return Err(rc);
    }

    let header_consumed = orig_header_len - unmarshal_buf.len();
    resp_offset += header_consumed;

    let mut handles_slice = &response_buf[resp_offset..resp_size];
    let orig_handles_len = handles_slice.len();
    let resp_handles =
        C::RespHandles::unmarshal(&mut handles_slice).map_err(|_| TpmRc::FAILURE.get())?;

    let handles_len = orig_handles_len - handles_slice.len();
    resp_offset += handles_len;

    if tag == 0x8002 {
        resp_offset += 4; // Skip parameter size
    }

    let mut params_slice: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
    let resp_params =
        <C::Response<'static>>::unmarshal(&mut params_slice).map_err(|_| TpmRc::FAILURE.get())?;

    Ok((resp_handles, resp_params))
}

#[test]
fn test_nv_undefine_space_special_enforcement() {
    use tpm2::TpmSe;

    use tpm2::commands::{
        NVUndefineSpaceSpecial, NVUndefineSpaceSpecialHandles, PolicyCommandCode,
        PolicyCommandCodeHandles, PolicyGetDigest, PolicyGetDigestHandles, StartAuthSession,
        StartAuthSessionHandles,
    };

    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Run a Trial session with PolicyCommandCode(NVUndefineSpaceSpecial) to compute required policy digest
    let session_handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let trial_cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[1; 32]).unwrap(),
        encrypted_salt: tpm2::Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (trial_session_handles, _) = execute_tpm_command_full(
        &mut tpm,
        &mut global_state,
        &session_handles,
        &trial_cmd,
        &[],
    )
    .unwrap();
    let trial_session = trial_session_handles.session_handle;

    let policy_cc_handles = PolicyCommandCodeHandles {
        policy_session: trial_session,
    };
    let policy_cc_cmd = PolicyCommandCode {
        code: tpm2::TpmCc::NVUndefineSpaceSpecial,
    };
    execute_tpm_command_full(
        &mut tpm,
        &mut global_state,
        &policy_cc_handles,
        &policy_cc_cmd,
        &[],
    )
    .unwrap();

    let digest_handles = PolicyGetDigestHandles {
        policy_session: trial_session,
    };
    let digest_cmd = PolicyGetDigest {};
    let (_, digest_resp) = execute_tpm_command_full(
        &mut tpm,
        &mut global_state,
        &digest_handles,
        &digest_cmd,
        &[],
    )
    .unwrap();
    let policy_digest = digest_resp.policy_digest;

    // 2. Define an NV index with POLICY_DELETE bound to policy_digest
    let nv_idx = Handle(0x01000022);
    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
    };
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::from_bytes(b"idx_pass").unwrap(),
        public_info: tpm2::Tpm2b(TpmsNvPublic {
            nv_index: nv_idx,
            name_alg: TpmiAlgHash::Sha256,
            attributes: TpmaNv::POLICY_DELETE
                | TpmaNv::PLATFORMCREATE
                | TpmaNv::AUTHWRITE
                | TpmaNv::AUTHREAD,
            auth_policy: policy_digest,
            data_size: 32,
        }),
    };
    let platform_auth_session = make_auth_session(b"");
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_cmd,
        core::slice::from_ref(&platform_auth_session),
    )
    .expect("Failed to define NV index with POLICY_DELETE");

    // 3. Start a real Policy session and execute PolicyCommandCode(NVUndefineSpaceSpecial)
    let real_cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[2; 32]).unwrap(),
        encrypted_salt: tpm2::Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (real_session_handles, real_session_resp) = execute_tpm_command_full(
        &mut tpm,
        &mut global_state,
        &session_handles,
        &real_cmd,
        &[],
    )
    .unwrap();
    let real_session = real_session_handles.session_handle;

    let real_policy_handles = PolicyCommandCodeHandles {
        policy_session: real_session,
    };
    execute_tpm_command_full(
        &mut tpm,
        &mut global_state,
        &real_policy_handles,
        &policy_cc_cmd,
        &[],
    )
    .unwrap();

    // 4. Call NV_UndefineSpaceSpecial under Platform auth and satisfied policy session
    let undefine_handles = NVUndefineSpaceSpecialHandles {
        nv_index: nv_idx,
        platform: Handle::RH_PLATFORM,
    };
    let undefine_cmd = NVUndefineSpaceSpecial {};

    // Compute command HMAC for policy session (HMAC with session_key = &[])
    let test_crypto = TestCryptoProvider;
    let mut nv_pub_buf = [0u8; TpmsNvPublic::MAX_SIZE];
    let nv_pub_len = define_cmd.public_info.0.marshal(&mut nv_pub_buf);
    let nv_pub_bytes = &nv_pub_buf[..nv_pub_len];
    let nv_pub_digest = sha256_bytes(nv_pub_bytes);
    let mut nv_name_bytes = [0u8; 34];
    nv_name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    nv_name_bytes[2..34].copy_from_slice(&nv_pub_digest);

    let mut cp_data = alloc::vec::Vec::new();
    cp_data.extend_from_slice(&(tpm2::TpmCc::NVUndefineSpaceSpecial.code()).to_be_bytes());
    cp_data.extend_from_slice(&nv_name_bytes);
    cp_data.extend_from_slice(&0x4000000cu32.to_be_bytes());
    let cp_hash = sha256_bytes(&cp_data);

    let mut hmac_state =
        tpm2::crypto::HmacCtx::new(&test_crypto, TpmiAlgHash::Sha256, &[]).unwrap();
    let caller_nonce = [5u8; 32];
    hmac_state.update(&cp_hash).unwrap();
    hmac_state.update(&caller_nonce).unwrap();
    hmac_state
        .update(real_session_resp.nonce_tpm.get_buffer())
        .unwrap();
    hmac_state.update(&[1u8]).unwrap();
    let mut hmac_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let policy_hmac = hmac_state.finalize(&mut hmac_buf).unwrap();

    let policy_auth_command = TpmsAuthCommand {
        session_handle: Handle(real_session.0),
        nonce: Tpm2bNonce::from_bytes(&caller_nonce).unwrap(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(policy_hmac.digest()).unwrap(),
    };
    let auths = [policy_auth_command, platform_auth_session];
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &undefine_handles,
        &undefine_cmd,
        &auths,
    )
    .expect("Failed to undefine NV index with NV_UndefineSpaceSpecial");

    // 5. Verify index is undefined (read fails)
    let read_handles = NVReadHandles {
        auth_handle: nv_idx,
        nv_index: nv_idx,
    };
    let read_cmd = NVRead {
        size: 32,
        offset: 0,
    };
    let read_res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &read_handles,
        &read_cmd,
        core::slice::from_ref(&platform_auth_session),
    );
    assert!(read_res.is_err());
}

#[test]
fn test_nv_write_range_error_precedence_over_locks() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);
    let auth_session = make_auth_session(&[]);

    let nv_idx = Handle(0x01000050);
    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
    };
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info: tpm2::Tpm2b(TpmsNvPublic {
            nv_index: nv_idx,
            name_alg: TpmiAlgHash::Sha256,
            attributes: TpmaNv::AUTHWRITE
                | TpmaNv::AUTHREAD
                | TpmaNv::WRITEDEFINE
                | TpmaNv::PLATFORMCREATE,
            auth_policy: Tpm2bDigest::default(),
            data_size: 16,
        }),
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define NV index");

    // Lock index with NV_WriteLock
    let lock_handles = NVWriteLockHandles {
        auth_handle: nv_idx,
        nv_index: nv_idx,
    };
    let lock_cmd = NVWriteLock {};
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &lock_handles,
        &lock_cmd,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to lock NV index");

    // Attempt NV_Write with offset + size > 16 on write-locked index
    let write_handles = NVWriteHandles {
        auth_handle: nv_idx,
        nv_index: nv_idx,
    };
    let write_cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0x11; 10]).unwrap(),
        offset: 10,
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &write_handles,
        &write_cmd,
        core::slice::from_ref(&auth_session),
    );

    // WRITELOCKED must take precedence over range errors per compliance test CPCTPM_TC2_3_33_07_10
    assert_eq!(res.unwrap_err() & 0xfff, TpmRc::NV_LOCKED.get());
}

#[test]
fn test_nv_extend_and_setbits_locked_error_precedence() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);
    let auth_session = make_auth_session(&[]);

    // 1. Test NV_Extend error precedence
    let nv_idx_ext = Handle(0x01000051);
    let define_handles_ext = NVDefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
    };
    let mut attr_ext = TpmaNv::from(TpmNt::Extend);
    attr_ext.insert(
        TpmaNv::AUTHWRITE | TpmaNv::AUTHREAD | TpmaNv::WRITEDEFINE | TpmaNv::PLATFORMCREATE,
    );
    let define_cmd_ext = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info: tpm2::Tpm2b(TpmsNvPublic {
            nv_index: nv_idx_ext,
            name_alg: TpmiAlgHash::Sha256,
            attributes: attr_ext,
            auth_policy: Tpm2bDigest::default(),
            data_size: 32,
        }),
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles_ext,
        &define_cmd_ext,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define extend NV index");

    let lock_handles_ext = NVWriteLockHandles {
        auth_handle: nv_idx_ext,
        nv_index: nv_idx_ext,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &lock_handles_ext,
        &NVWriteLock {},
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to lock extend NV index");

    // Call NV_Extend using RHOwner (where OWNERWRITE = 0) on locked index
    let ext_handles = NVExtendHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: nv_idx_ext,
    };
    let ext_cmd = NVExtend {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xaa; 32]).unwrap(),
    };
    let res_ext = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &ext_handles,
        &ext_cmd,
        core::slice::from_ref(&auth_session),
    );
    assert_eq!(res_ext.unwrap_err() & 0xfff, TpmRc::AUTH_UNAVAILABLE.get());

    // 2. Test NV_SetBits error precedence
    let nv_idx_bits = Handle(0x01000052);
    let define_handles_bits = NVDefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
    };
    let mut attr_bits = TpmaNv::from(TpmNt::Bits);
    attr_bits.insert(
        TpmaNv::AUTHWRITE | TpmaNv::AUTHREAD | TpmaNv::WRITEDEFINE | TpmaNv::PLATFORMCREATE,
    );
    let define_cmd_bits = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info: tpm2::Tpm2b(TpmsNvPublic {
            nv_index: nv_idx_bits,
            name_alg: TpmiAlgHash::Sha256,
            attributes: attr_bits,
            auth_policy: Tpm2bDigest::default(),
            data_size: 8,
        }),
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles_bits,
        &define_cmd_bits,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define bits NV index");

    let lock_handles_bits = NVWriteLockHandles {
        auth_handle: nv_idx_bits,
        nv_index: nv_idx_bits,
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &lock_handles_bits,
        &NVWriteLock {},
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to lock bits NV index");

    // Call NV_SetBits using RHOwner (where OWNERWRITE = 0) on locked index
    let bits_handles = NVSetBitsHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: nv_idx_bits,
    };
    let bits_cmd = NVSetBits { bits: 0x01 };
    let res_bits = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &bits_handles,
        &bits_cmd,
        core::slice::from_ref(&auth_session),
    );
    assert_eq!(res_bits.unwrap_err() & 0xfff, TpmRc::AUTH_UNAVAILABLE.get());
}

#[test]
fn test_nv_undefine_space_and_special_return_code_precedence() {
    use tpm2::errors::{Position, TpmRc};

    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Helper to construct a raw wire buffer with session (tag 0x8002, empty password session)
    let make_request = |cc: u32, h0: u32, h1: u32| -> [u8; 31] {
        let mut buf = [0u8; 31];
        buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes()); // tag
        buf[2..6].copy_from_slice(&31u32.to_be_bytes()); // size
        buf[6..10].copy_from_slice(&cc.to_be_bytes()); // cc
        buf[10..14].copy_from_slice(&h0.to_be_bytes()); // handle 0
        buf[14..18].copy_from_slice(&h1.to_be_bytes()); // handle 1
        buf[18..22].copy_from_slice(&9u32.to_be_bytes()); // authSize
        buf[22..26].copy_from_slice(&Handle::RS_PW.0.to_be_bytes()); // session handle
        buf[26..28].copy_from_slice(&0u16.to_be_bytes()); // nonce
        buf[28] = 0; // session attributes
        buf[29..31].copy_from_slice(&0u16.to_be_bytes()); // hmac
        buf
    };

    let mut resp = [0u8; 256];

    // 1. CPCTPM_TC2_3_33_04_05 Step 1: NV_UndefineSpace(TPM_RH_OWNER, 0x02400000)
    let req1 = make_request(0x0122, Handle::RH_OWNER.0, 0x02400000);
    tpm.execute_command_separate(&mut global_state, &req1, &mut resp);
    let rc1 = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
    assert_eq!(
        rc1,
        TpmRc::VALUE.with(Position::handle(2)).get(),
        "NV_UndefineSpace with 0x02400000 should return TPM_RC_VALUE at Pos2"
    );

    // 2. CPCTPM_TC2_3_33_04_05 Step 2: NV_UndefineSpace(TPM_RH_PLATFORM, 0x00400000)
    let req2 = make_request(0x0122, Handle::RH_PLATFORM.0, 0x00400000);
    tpm.execute_command_separate(&mut global_state, &req2, &mut resp);
    let rc2 = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
    assert_eq!(
        rc2,
        TpmRc::VALUE.with(Position::handle(2)).get(),
        "NV_UndefineSpace with 0x00400000 should return TPM_RC_VALUE at Pos2"
    );

    // 3. CPCTPM_TC2_4_33_05_03 Step 1: NV_UndefineSpaceSpecial(0x02400000, TPM_RH_PLATFORM)
    let req3 = make_request(0x011F, 0x02400000, Handle::RH_PLATFORM.0);
    tpm.execute_command_separate(&mut global_state, &req3, &mut resp);
    let rc3 = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
    assert_eq!(
        rc3,
        TpmRc::VALUE.with(Position::handle(1)).get(),
        "NV_UndefineSpaceSpecial with 0x02400000 should return TPM_RC_VALUE at Pos1"
    );

    // 4. CPCTPM_TC2_4_33_05_03 Step 2: NV_UndefineSpaceSpecial(0x00400000, TPM_RH_PLATFORM)
    let req4 = make_request(0x011F, 0x00400000, Handle::RH_PLATFORM.0);
    tpm.execute_command_separate(&mut global_state, &req4, &mut resp);
    let rc4 = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
    assert_eq!(
        rc4,
        TpmRc::VALUE.with(Position::handle(1)).get(),
        "NV_UndefineSpaceSpecial with 0x00400000 should return TPM_RC_VALUE at Pos1"
    );
}

#[test]
fn test_nv_monotonic_counter_anti_rollback_and_persistence() {
    use tpm2::commands::{
        NVIncrement, NVIncrementHandles, NVUndefineSpace, NVUndefineSpaceHandles,
    };

    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();

    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let nv_index = Handle(0x01000010);
    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    let mut attrs = TpmaNv::from(TpmNt::Counter);
    attrs.insert(TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD);
    let public_info = TpmsNvPublic {
        nv_index,
        name_alg: TpmiAlgHash::Sha256,
        attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        data_size: 8,
    };
    let define_cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info: tpm2::Tpm2b(public_info),
    };
    let auths = [make_auth_session(&[])];

    // 1. Define counter index 0x01000010 and increment it 3 times (values: 1, 2, 3)
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_cmd,
        &auths,
    )
    .unwrap();

    let inc_handles = NVIncrementHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index,
    };
    let inc_cmd = NVIncrement {};
    for expected in 1..=3u64 {
        execute_tpm_command_with_auths(&mut tpm, &mut global_state, &inc_handles, &inc_cmd, &auths)
            .unwrap();
        let read_handles = NVReadHandles {
            auth_handle: Handle::RH_OWNER,
            nv_index,
        };
        let read_cmd = NVRead { size: 8, offset: 0 };
        let resp = execute_tpm_command_with_auths(
            &mut tpm,
            &mut global_state,
            &read_handles,
            &read_cmd,
            &auths,
        )
        .unwrap();
        let val = u64::from_be_bytes(resp.data.get_buffer().try_into().unwrap());
        assert_eq!(val, expected);
    }
    assert_eq!(global_state.max_counter, 3);

    // 2. Delete the counter index and recreate it
    let undef_handles = NVUndefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index,
    };
    let undef_cmd = NVUndefineSpace {};
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &undef_handles,
        &undef_cmd,
        &auths,
    )
    .unwrap();
    assert_eq!(global_state.max_counter, 3);

    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &define_handles,
        &define_cmd,
        &auths,
    )
    .unwrap();

    // 3. First increment of the recreated counter must initialize to max_counter + 1 (4), not 1
    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &inc_handles, &inc_cmd, &auths)
        .unwrap();
    let read_handles = NVReadHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index,
    };
    let read_cmd = NVRead { size: 8, offset: 0 };
    let resp = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &read_handles,
        &read_cmd,
        &auths,
    )
    .unwrap();
    let val = u64::from_be_bytes(resp.data.get_buffer().try_into().unwrap());
    assert_eq!(val, 4);
    assert_eq!(global_state.max_counter, 4);

    // 4. Delete again, simulate cold reboot (new GlobalState::default() + Startup(CLEAR)), and verify persistence
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &undef_handles,
        &undef_cmd,
        &auths,
    )
    .unwrap();

    let mut fresh_state = tpm2_impl::GlobalState::default();
    fresh_state.nv_available = true;
    fresh_state.locality = 0;
    fresh_state.g_nv_ok = true;
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut fresh_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    assert_eq!(
        fresh_state.max_counter, 4,
        "max_counter must be loaded from NV storage on startup"
    );

    execute_tpm_command_with_auths(
        &mut tpm,
        &mut fresh_state,
        &define_handles,
        &define_cmd,
        &auths,
    )
    .unwrap();
    execute_tpm_command_with_auths(&mut tpm, &mut fresh_state, &inc_handles, &inc_cmd, &auths)
        .unwrap();
    let resp_after_reboot = execute_tpm_command_with_auths(
        &mut tpm,
        &mut fresh_state,
        &read_handles,
        &read_cmd,
        &auths,
    )
    .unwrap();
    let val_after_reboot =
        u64::from_be_bytes(resp_after_reboot.data.get_buffer().try_into().unwrap());
    assert_eq!(
        val_after_reboot, 5,
        "Counter after cold reboot must continue from persisted max_counter + 1"
    );
}
