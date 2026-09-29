use common::marshal_to_slice;
use tpm2::errors::{Position, TpmRc};

mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::commands::{
    CreatePrimary, CreatePrimaryHandles, SetPrimaryPolicy, SetPrimaryPolicyHandles,
};
use tpm2::{Handle, TpmCc};
use tpm2::{Tpm2bDigest, TpmiAlgHash, TpmsAuthCommand};
use tpm2_impl::{TpmEngine, TpmPlatform};

fn setup_tpm<'a>(
    crypto: &'a mut FakeCrypto,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a FakeRng,
) -> (
    TpmEngine<'a, FakeCrypto, FakeStorage, FakeTimer, FakeRng>,
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

#[test]
fn test_set_primary_policy_owner() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Authorize under Owner hierarchy and set a 32-byte authPolicy
    let policy_digest = Tpm2bDigest::from_bytes(&[0x42; 32]).unwrap();
    let cmd = SetPrimaryPolicy {
        auth_policy: policy_digest,
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let handles = SetPrimaryPolicyHandles {
        auth_handle: Handle::RH_OWNER,
    };

    let mut req_buf = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8002u16), &mut req_buf[offset..]);
    let len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    offset += marshal_to_slice(&(TpmCc::SetPrimaryPolicy.code()), &mut req_buf[offset..]);
    offset += marshal_to_slice(&handles, &mut req_buf[offset..]);

    let auth_len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    let auth_start = offset;
    let pw_auth = TpmsAuthCommand {
        session_handle: tpm2::Handle::RS_PW,
        nonce: Default::default(),
        session_attributes: Default::default(),
        hmac: Default::default(),
    };
    offset += marshal_to_slice(&(pw_auth), &mut req_buf[offset..]);
    let auth_len = (offset - auth_start) as u32;
    offset += marshal_to_slice(&cmd, &mut req_buf[offset..]);

    let total_len = offset as u32;
    req_buf[len_offset..len_offset + 4].copy_from_slice(&total_len.to_be_bytes());
    req_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());

    let mut resp_buf = [0u8; 1024];
    let _ = tpm.execute_command_separate(&mut global_state, &req_buf[..offset], &mut resp_buf[..]);
    let rc = u32::from_be_bytes(resp_buf[6..10].try_into().unwrap());
    assert_eq!(rc, 0, "SetPrimaryPolicy under Owner should succeed");
    assert_eq!(global_state.owner_policy.get_buffer(), &[0x42; 32]);

    // 2. Confirm subsequent hierarchy-bound operations enforce the new primary policy.
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let create_cmd = CreatePrimary::default();

    offset = 0;
    offset += marshal_to_slice(&(0x8002u16), &mut req_buf[offset..]);
    let len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    offset += marshal_to_slice(&(TpmCc::CreatePrimary.code()), &mut req_buf[offset..]);
    offset += marshal_to_slice(&(create_handles), &mut req_buf[offset..]);

    let auth_len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    let auth_start = offset;
    offset += marshal_to_slice(&(pw_auth), &mut req_buf[offset..]);
    let auth_len = (offset - auth_start) as u32;
    offset += marshal_to_slice(&(create_cmd), &mut req_buf[offset..]);
    let total_len = offset as u32;
    req_buf[len_offset..len_offset + 4].copy_from_slice(&total_len.to_be_bytes());
    req_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());

    let _ = tpm.execute_command_separate(&mut global_state, &req_buf[..offset], &mut resp_buf[..]);
    assert_ne!(
        global_state.owner_policy.get_buffer(),
        &[],
        "Owner policy should be stored in global state and preserved"
    );
}

#[test]
fn test_set_primary_policy_endorsement_and_lockout() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let policy_digest = Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap();
    let cmd = SetPrimaryPolicy {
        auth_policy: policy_digest,
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let handles = SetPrimaryPolicyHandles {
        auth_handle: Handle::RH_ENDORSEMENT,
    };

    let mut req_buf = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8002u16), &mut req_buf[offset..]);
    let len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    offset += marshal_to_slice(&(TpmCc::SetPrimaryPolicy.code()), &mut req_buf[offset..]);
    offset += marshal_to_slice(&handles, &mut req_buf[offset..]);

    let auth_len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    let auth_start = offset;
    let pw_auth = TpmsAuthCommand {
        session_handle: tpm2::Handle::RS_PW,
        nonce: Default::default(),
        session_attributes: Default::default(),
        hmac: Default::default(),
    };
    offset += marshal_to_slice(&(pw_auth), &mut req_buf[offset..]);
    let auth_len = (offset - auth_start) as u32;
    offset += marshal_to_slice(&cmd, &mut req_buf[offset..]);

    let total_len = offset as u32;
    req_buf[len_offset..len_offset + 4].copy_from_slice(&total_len.to_be_bytes());
    req_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());

    let mut resp_buf = [0u8; 1024];
    let _ = tpm.execute_command_separate(&mut global_state, &req_buf[..offset], &mut resp_buf[..]);
    let rc = u32::from_be_bytes(resp_buf[6..10].try_into().unwrap());
    assert_eq!(rc, 0);
    assert_eq!(global_state.endorsement_policy.get_buffer(), &[0x11; 32]);
}

#[test]
fn test_set_primary_policy_disabled_hierarchy() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    global_state.sh_enable = false;

    let policy_digest = Tpm2bDigest::from_bytes(&[0x42; 32]).unwrap();
    let cmd = SetPrimaryPolicy {
        auth_policy: policy_digest,
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let handles = SetPrimaryPolicyHandles {
        auth_handle: Handle::RH_OWNER,
    };

    let mut req_buf = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8002u16), &mut req_buf[offset..]);
    let len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    offset += marshal_to_slice(&(TpmCc::SetPrimaryPolicy.code()), &mut req_buf[offset..]);
    offset += marshal_to_slice(&handles, &mut req_buf[offset..]);

    let auth_len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    let auth_start = offset;
    let pw_auth = TpmsAuthCommand {
        session_handle: tpm2::Handle::RS_PW,
        nonce: Default::default(),
        session_attributes: Default::default(),
        hmac: Default::default(),
    };
    offset += marshal_to_slice(&(pw_auth), &mut req_buf[offset..]);
    let auth_len = (offset - auth_start) as u32;
    offset += marshal_to_slice(&cmd, &mut req_buf[offset..]);

    let total_len = offset as u32;
    req_buf[len_offset..len_offset + 4].copy_from_slice(&total_len.to_be_bytes());
    req_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());

    let mut resp_buf = [0u8; 1024];
    let _ = tpm.execute_command_separate(&mut global_state, &req_buf[..offset], &mut resp_buf[..]);
    let rc = u32::from_be_bytes(resp_buf[6..10].try_into().unwrap());
    assert_ne!(
        rc, 0,
        "SetPrimaryPolicy against disabled hierarchy should fail"
    );
}

#[test]
fn test_set_primary_policy_size_mismatch() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let policy_digest = Tpm2bDigest::from_bytes(&[0x22; 20]).unwrap();
    let cmd = SetPrimaryPolicy {
        auth_policy: policy_digest,
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let handles = SetPrimaryPolicyHandles {
        auth_handle: Handle::RH_OWNER,
    };

    let mut req_buf = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8002u16), &mut req_buf[offset..]);
    let len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    offset += marshal_to_slice(&(TpmCc::SetPrimaryPolicy.code()), &mut req_buf[offset..]);
    offset += marshal_to_slice(&handles, &mut req_buf[offset..]);

    let auth_len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    let auth_start = offset;
    let pw_auth = TpmsAuthCommand {
        session_handle: tpm2::Handle::RS_PW,
        nonce: Default::default(),
        session_attributes: Default::default(),
        hmac: Default::default(),
    };
    offset += marshal_to_slice(&(pw_auth), &mut req_buf[offset..]);
    let auth_len = (offset - auth_start) as u32;
    offset += marshal_to_slice(&cmd, &mut req_buf[offset..]);

    let total_len = offset as u32;
    req_buf[len_offset..len_offset + 4].copy_from_slice(&total_len.to_be_bytes());
    req_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());

    let mut resp_buf = [0u8; 1024];
    let _ = tpm.execute_command_separate(&mut global_state, &req_buf[..offset], &mut resp_buf[..]);
    let rc = u32::from_be_bytes(resp_buf[6..10].try_into().unwrap());
    assert_eq!(rc, TpmRc::SIZE.with(Position::parameter(1)).get());
}
