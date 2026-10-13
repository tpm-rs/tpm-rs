mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use tpm2::errors::TpmRc;
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

#[test]
fn test_adv_total_reset_count_overflow() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &mut rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;
    global_state.total_reset_count = u64::MAX;

    let request = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x0c, // size (12 bytes)
        0x00, 0x00, 0x01, 0x44, // TPM_CC_Startup
        0x00, 0x00, // TpmSu::Clear
    ];
    let mut response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    assert_eq!(rc, TpmRc::FAILURE.get());
}

#[test]
fn test_adv_nv_storage_failure() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    storage.fail_on_write = true;
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &mut rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;

    let request = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x0c, // size (12 bytes)
        0x00, 0x00, 0x01, 0x44, // TPM_CC_Startup
        0x00, 0x00, // TpmSu::Clear
    ];
    let mut response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    assert_eq!(rc, TpmRc::FAILURE.get());
}

#[test]
fn test_startup_preserves_custom_platform_unique_details_and_allows_policy_secret() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &mut rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;

    let custom_secret = b"custom_vendor_permanent_secret_0123456789abcdef";
    global_state.platform_unique_details =
        tpm2::Tpm2bAuth::from_bytes(custom_secret).unwrap().into();

    // Startup(CLEAR) should preserve custom platform_unique_details
    let startup_clear = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
    ];
    let mut response = [0u8; 512];
    tpm.execute_command_separate(&mut global_state, &startup_clear, &mut response);
    assert_eq!(u32::from_be_bytes(response[6..10].try_into().unwrap()), 0);
    assert_eq!(
        global_state.platform_unique_details.get_buffer(),
        custom_secret
    );

    // Start a Trial Policy Session (TPM2_StartAuthSession)
    let start_session = [
        0x80, 0x01, // TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x3b, // size: 59 bytes
        0x00, 0x00, 0x01, 0x76, // TPM_CC_StartAuthSession
        0x40, 0x00, 0x00, 0x07, // tpmKey: TPM_RH_NULL
        0x40, 0x00, 0x00, 0x07, // bind: TPM_RH_NULL
        0x00, 0x20, // nonceCaller size: 32
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0x00, 0x00, // encryptedSalt size: 0
        0x03, // sessionType: TPM_SE_TRIAL (0x03)
        0x00, 0x10, // symmetric: TPM_ALG_NULL
        0x00, 0x0b, // authHash: TPM_ALG_SHA256
    ];
    tpm.execute_command_separate(&mut global_state, &start_session, &mut response);
    assert_eq!(u32::from_be_bytes(response[6..10].try_into().unwrap()), 0);
    let session_handle = u32::from_be_bytes(response[10..14].try_into().unwrap());

    // Execute TPM2_PolicySecret with authHandle = TPM_RH_AUTH_00 (0x40000010) and password auth = custom_secret
    let mut policy_secret_cmd = Vec::new();
    policy_secret_cmd.extend_from_slice(&[0x80, 0x02]); // TPM_ST_SESSIONS
    policy_secret_cmd.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // size placeholder
    policy_secret_cmd.extend_from_slice(&[0x00, 0x00, 0x01, 0x51]); // TPM_CC_PolicySecret
    policy_secret_cmd.extend_from_slice(&tpm2::Handle::RH_AUTH_00.0.to_be_bytes()); // authHandle: 0x40000010
    policy_secret_cmd.extend_from_slice(&session_handle.to_be_bytes()); // policySession

    // Auth area: RS_PW with hmac = custom_secret
    let auth_area_size = 4 + 2 + 1 + 2 + custom_secret.len() as u32;
    policy_secret_cmd.extend_from_slice(&auth_area_size.to_be_bytes());
    policy_secret_cmd.extend_from_slice(&[0x40, 0x00, 0x00, 0x09]); // TPM_RS_PW
    policy_secret_cmd.extend_from_slice(&[0x00, 0x00]); // nonce size: 0
    policy_secret_cmd.push(0x01); // sessionAttributes: continueSession
    policy_secret_cmd.extend_from_slice(&(custom_secret.len() as u16).to_be_bytes());
    policy_secret_cmd.extend_from_slice(custom_secret);

    // Parameters: nonceTPM (0), cpHashA (0), policyRef (0), expiration (0)
    policy_secret_cmd.extend_from_slice(&[0x00, 0x00]); // nonceTPM
    policy_secret_cmd.extend_from_slice(&[0x00, 0x00]); // cpHashA
    policy_secret_cmd.extend_from_slice(&[0x00, 0x00]); // policyRef
    policy_secret_cmd.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // expiration

    let total_size = policy_secret_cmd.len() as u32;
    policy_secret_cmd[2..6].copy_from_slice(&total_size.to_be_bytes());

    tpm.execute_command_separate(&mut global_state, &policy_secret_cmd, &mut response);
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    assert_eq!(rc, 0, "TPM2_PolicySecret with TPM_RH_AUTH_00 must succeed");
}
