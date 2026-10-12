#![forbid(unsafe_code)]

use tpm2::Marshal;
extern crate alloc;

mod common;

use alloc::vec::Vec;
use common::TestCryptoProvider;
use common::{FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::commands::{
    Command, Message, PolicyLocality, PolicyPassword, SetPrimaryPolicy, StartAuthSession,
    UnmarshalMessage,
};
use tpm2::crypto::Random;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmCc, TpmSe};
use tpm2::{
    Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bNonce, TpmaLocality, TpmaSession, TpmiAlgHash,
    TpmsAuthCommand,
};
use tpm2_impl::{TpmEngine, TpmPlatform};

fn setup_tpm<'a>(
    crypto: &'a mut TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer>,
    tpm2_impl::GlobalState,
) {
    let rng = crypto.rng_seeded(b"policy_hierarchy_tests").unwrap();
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state).unwrap();
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
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: UnmarshalMessage<'static>,
{
    let mut request_buf = [0u8; 16384];
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
            let auth_slice: &mut [u8; TpmsAuthCommand::MAX_SIZE] = (&mut request_buf
                [offset..offset + TpmsAuthCommand::MAX_SIZE])
                .try_into()
                .map_err(|_| ())
                .unwrap();
            let auth_len = auth.marshal(auth_slice);
            offset += auth_len;
        }
        let auth_len = u32::try_from(offset - auth_start).unwrap();
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    let cmd_slice: &mut <C as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let cmd_len = cmd.marshal(cmd_slice);
    offset += cmd_len;
    let total_len = u32::try_from(offset).unwrap();
    request_buf[2..6].copy_from_slice(&total_len.to_be_bytes());

    let mut response_buf = [0u8; 16384];
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut resp_offset = 10;
    let mut resp_handles = <<C::Response<'static> as Message>::Handles>::default();
    for h in resp_handles.as_mut() {
        *h = Handle(u32::from_be_bytes(
            response_buf[resp_offset..resp_offset + 4]
                .try_into()
                .unwrap(),
        ));
        resp_offset += 4;
    }

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    let params_end = if resp_tag == 0x8002 {
        let param_size = usize::try_from(u32::from_be_bytes(
            response_buf[resp_offset..resp_offset + 4]
                .try_into()
                .unwrap(),
        ))
        .unwrap();
        resp_offset += 4;
        resp_offset + param_size
    } else {
        resp_size
    };

    let mut params_slice: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..params_end].to_vec());
    <C::Response<'static>>::unmarshal_with_handles(resp_handles, &mut params_slice)
        .map_err(|_| TpmRc::FAILURE.get())
}

#[test]
fn test_policy_locality_and_password_digest_accumulation() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer);

    // Start a trial policy session
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let session_resp = execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]).unwrap();
    let policy_session = session_resp.session_handle;

    // 1. Run PolicyLocality(LOC_ONE | LOC_TWO)
    let loc_cmd = PolicyLocality {
        policy_session,
        locality: TpmaLocality(3), // Bit 0 and Bit 1 set (LOC_ZERO | LOC_ONE)
    };
    execute_tpm_command(&mut tpm, &mut global_state, &loc_cmd, &[]).unwrap();

    let session_state = global_state.session(policy_session.0).unwrap();
    assert_eq!(session_state.command_locality, 3);

    // Compute expected policy digest after PolicyLocality:
    // SHA256(32 zero bytes || TPM_CC_PolicyLocality || locality)
    let mut to_hash = Vec::new();
    to_hash.extend_from_slice(&[0u8; 32]);
    to_hash.extend_from_slice(&(TpmCc::PolicyLocality.code()).to_be_bytes());
    to_hash.push(3);
    let crypto_hash = TestCryptoProvider;
    let mut out_loc = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest_after_loc =
        tpm2::crypto::hash(&crypto_hash, TpmiAlgHash::Sha256, &to_hash, &mut out_loc)
            .expect("Sha256 hash calculation")
            .digest();
    assert_eq!(session_state.policy_digest[..32], digest_after_loc[..]);

    // 2. Run PolicyPassword
    let pw_cmd = PolicyPassword { policy_session };
    execute_tpm_command(&mut tpm, &mut global_state, &pw_cmd, &[]).unwrap();

    let session_state = global_state.session(policy_session.0).unwrap();
    assert!(session_state.is_password_needed);

    // Compute expected policy digest after PolicyPassword:
    // SHA256(digest_after_loc || TPM_CC_PolicyAuthValue)
    let mut to_hash_pw = Vec::new();
    to_hash_pw.extend_from_slice(digest_after_loc);
    to_hash_pw.extend_from_slice(&(TpmCc::PolicyAuthValue.code()).to_be_bytes());
    let mut out_pw = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest_after_pw =
        tpm2::crypto::hash(&crypto_hash, TpmiAlgHash::Sha256, &to_hash_pw, &mut out_pw)
            .expect("Sha256 hash calculation")
            .digest();
    assert_eq!(session_state.policy_digest[..32], digest_after_pw[..]);
}

#[test]
fn test_set_primary_policy_hierarchy_enforcement() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer);

    let policy_digest = Tpm2bDigest::new(&[0x42; 32]).unwrap();
    let cmd = SetPrimaryPolicy {
        auth_handle: Handle::RH_OWNER,
        auth_policy: policy_digest,
        hash_alg: Some(TpmiAlgHash::Sha256),
    };

    // 1. Authorize with default empty owner auth via password session
    let auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::default(),
        hmac: tpm2::Tpm2bDigest::default(),
    };
    assert!(execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[auth]).is_ok());
    assert_eq!(global_state.owner_policy.get_buffer(), &[0x42; 32]);

    // 2. Test disabling sh_enable fails any operation requiring RHOwner
    global_state.sh_enable = false;
    let res = execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[auth]);
    assert_eq!(
        res.err(),
        Some(TpmRc::HIERARCHY.with(Position::handle(1)).get())
    );
}
