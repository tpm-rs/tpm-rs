use tpm2::{Marshal, Unmarshal};
extern crate alloc;

mod common;

use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::commands::{
    Command, Message, PolicyGetDigest, PolicyTemplate, StartAuthSession, UnmarshalMessage,
};
use tpm2::crypto::{Finalize as _, Hash as _, Update as _};
use tpm2::{Handle, TpmCc, TpmSe};
use tpm2::{Tpm2bDigest, Tpm2bNonce, TpmiAlgHash, TpmsAuthCommand};
use tpm2_impl::{TpmEngine, TpmPlatform};

fn setup_tpm<'a>(
    crypto: &'a mut TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a mut FakeRng,
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

fn execute_tpm_command<C: Command>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    for handle in cmd.handles().as_ref() {
        let handle_slice: &mut [u8; Handle::MAX_SIZE] = (&mut request_buf
            [offset..offset + Handle::MAX_SIZE])
            .try_into()
            .map_err(|_| ())
            .unwrap();
        let handle_len = handle.marshal(handle_slice);
        offset += handle_len;
    }

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

    let mut response_buf = [0u8; 16384];
    tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut resp_offset = 10;
    let mut handles_slice = &response_buf[resp_offset..];
    let before_handles = handles_slice.len();
    let mut resp_handles = <C::Response<'static> as Message>::Handles::default();
    for handle in resp_handles.as_mut() {
        *handle = Handle::unmarshal(&mut handles_slice).unwrap();
    }
    resp_offset += before_handles - handles_slice.len();

    if !auths.is_empty() {
        let param_size = u32::from_be_bytes(
            response_buf[resp_offset..resp_offset + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        resp_offset += 4;
        let mut param_slice: &'static [u8] =
            std::vec::Vec::leak(response_buf[resp_offset..resp_offset + param_size].to_vec());
        let resp =
            <C::Response<'static>>::unmarshal_with_handles(resp_handles, &mut param_slice).unwrap();
        Ok(resp)
    } else {
        let mut param_slice: &'static [u8] =
            std::vec::Vec::leak(response_buf[resp_offset..].to_vec());
        let resp =
            <C::Response<'static>>::unmarshal_with_handles(resp_handles, &mut param_slice).unwrap();
        Ok(resp)
    }
}

#[test]
fn test_policy_template_digest() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let mut rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &mut rng);

    // 1. Start a trial/policy session
    let start_session_cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[1u8; 32]).unwrap(),
        encrypted_salt: Default::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_session_rsp = execute_tpm_command::<StartAuthSession>(
        &mut tpm,
        &mut global_state,
        &start_session_cmd,
        &[],
    )
    .expect("StartAuthSession failed");

    let session_handle = start_session_rsp.session_handle;

    // 2. Define a template hash
    let template_hash = [0x5au8; 32];
    let policy_template_cmd = PolicyTemplate {
        policy_session: session_handle,
        template_hash: Tpm2bDigest::from_bytes(&template_hash).unwrap(),
    };
    execute_tpm_command::<PolicyTemplate>(&mut tpm, &mut global_state, &policy_template_cmd, &[])
        .expect("PolicyTemplate command failed");

    // 3. Compute expected policy digest: Sha256(0[32] || TPM_CC_PolicyTemplate (0x00000190) || template_hash)
    let mut hasher = TestCryptoProvider.sha256().unwrap();
    hasher.update(&[0u8; 32]).unwrap();
    hasher
        .update(&(TpmCc::PolicyTemplate.code()).to_be_bytes())
        .unwrap();
    hasher.update(&template_hash).unwrap();
    let mut expected_digest = [0u8; 32];
    hasher.finalize(&mut expected_digest).unwrap();

    // 4. Query policy digest with PolicyGetDigest
    let get_digest_cmd = PolicyGetDigest {
        policy_session: session_handle,
    };
    let digest_resp =
        execute_tpm_command::<PolicyGetDigest>(&mut tpm, &mut global_state, &get_digest_cmd, &[])
            .expect("PolicyGetDigest failed");

    assert_eq!(
        digest_resp.policy_digest.get_buffer(),
        expected_digest.as_ref()
    );
}
