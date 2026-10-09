use common::marshal_to_slice;

mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::commands::{
    CreatePrimary, CreatePrimaryHandles, EvictControl, EvictControlHandles, HierarchyControl,
    HierarchyControlHandles,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmCc};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bSensitiveData, TpmaObject, TpmiAlgHash,
    TpmlPcrSelection, TpmsAuthCommand, TpmsSensitiveCreate, TpmtPublic,
};
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

fn get_test_template(st_clear: bool) -> TpmtPublic<'static> {
    let mut attrs = TpmaObject::FIXED_TPM
        | TpmaObject::FIXED_PARENT
        | TpmaObject::SENSITIVE_DATA_ORIGIN
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::RESTRICTED
        | TpmaObject::DECRYPT;
    if st_clear {
        attrs |= TpmaObject::ST_CLEAR;
    }
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Default::default(),
        // A restricted decrypt KEYEDHASH object would need an XOR scheme (C `SchemeChecks()`);
        // use a symmetric storage key instead.
        parms_and_id: PublicParmsAndId::Sym(
            tpm2::TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB)),
            tpm2::Tpm2bDigest::default(),
        ),
    }
}

fn create_primary(
    tpm: &mut TpmEngine<'_, FakeCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    hierarchy: Handle,
    st_clear: bool,
) -> (u32, u32) {
    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);
    let in_public = tpm2::Tpm2b(get_test_template(st_clear));
    let outside_info = Tpm2bData::default();
    let creation_pcr = TpmlPcrSelection::default();

    let handles = CreatePrimaryHandles {
        primary_handle: hierarchy,
    };
    let cmd = CreatePrimary {
        in_sensitive,
        in_public,
        outside_info,
        creation_pcr,
    };

    let mut req_buf = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8002u16), &mut req_buf[offset..]);
    let len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    offset += marshal_to_slice(&(TpmCc::CreatePrimary.code()), &mut req_buf[offset..]);
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
    let _ = tpm.execute_command_separate(global_state, &req_buf[..offset], &mut resp_buf[..]);
    let rc = u32::from_be_bytes(resp_buf[6..10].try_into().unwrap());
    let object_handle = u32::from_be_bytes(resp_buf[10..14].try_into().unwrap());
    (rc, object_handle)
}

fn evict_control(
    tpm: &mut TpmEngine<'_, FakeCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    auth: Handle,
    object_handle: u32,
    persistent_handle: u32,
) -> u32 {
    let handles = EvictControlHandles {
        auth,
        object_handle: Handle(object_handle),
    };
    let cmd = EvictControl {
        persistent_handle: Handle(persistent_handle),
    };

    let mut req_buf = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8002u16), &mut req_buf[offset..]);
    let len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    offset += marshal_to_slice(&(TpmCc::EvictControl.code()), &mut req_buf[offset..]);
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
    let _ = tpm.execute_command_separate(global_state, &req_buf[..offset], &mut resp_buf[..]);
    u32::from_be_bytes(resp_buf[6..10].try_into().unwrap())
}

fn hierarchy_control(
    tpm: &mut TpmEngine<'_, FakeCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    auth: Handle,
    enable: Handle,
    state: bool,
) -> u32 {
    let handles = HierarchyControlHandles { auth_handle: auth };
    let cmd = HierarchyControl { enable, state };

    let mut req_buf = [0u8; 1024];
    let mut offset = 0;
    offset += marshal_to_slice(&(0x8002u16), &mut req_buf[offset..]);
    let len_offset = offset;
    offset += marshal_to_slice(&(0u32), &mut req_buf[offset..]);
    offset += marshal_to_slice(&(TpmCc::HierarchyControl.code()), &mut req_buf[offset..]);
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
    let _ = tpm.execute_command_separate(global_state, &req_buf[..offset], &mut resp_buf[..]);
    u32::from_be_bytes(resp_buf[6..10].try_into().unwrap())
}

#[test]
fn test_evict_control_stclear_primary_fails() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Create a primary object with stClear = true
    let (rc, primary_handle) = create_primary(&mut tpm, &mut global_state, Handle::RH_OWNER, true);
    assert_eq!(rc, 0, "CreatePrimary with stClear = true must succeed");

    // 2. Call EvictControl(auth=TPM_RH_OWNER, objectHandle=primary, persistentHandle=0x81000001)
    let evict_rc = evict_control(
        &mut tpm,
        &mut global_state,
        Handle::RH_OWNER,
        primary_handle,
        0x81000001,
    );

    // 3. Assert TPM_RC_ATTRIBUTES per TCG Part 3 Section 30.5
    assert_eq!(
        evict_rc,
        TpmRc::ATTRIBUTES.with(Position::handle(2)).get(),
        "EvictControl against a primary key with stClear = true must return TPM_RC_ATTRIBUTES"
    );
}

#[test]
fn test_evict_control_persistency_constraints() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Create a primary object without stClear
    let (rc, primary_handle) = create_primary(&mut tpm, &mut global_state, Handle::RH_OWNER, false);
    assert_eq!(rc, 0);

    // Evict to NV (0x81000001) - first time must succeed (TPM_SUCCESS)
    let evict_rc = evict_control(
        &mut tpm,
        &mut global_state,
        Handle::RH_OWNER,
        primary_handle,
        0x81000001,
    );
    assert_eq!(evict_rc, 0);

    // Attempting to evict another primary object to the same persistent handle 0x81000001 must return TPM_RC_NV_DEFINED
    let (rc2, primary_handle2) =
        create_primary(&mut tpm, &mut global_state, Handle::RH_OWNER, false);
    assert_eq!(rc2, 0);

    let evict_rc2 = evict_control(
        &mut tpm,
        &mut global_state,
        Handle::RH_OWNER,
        primary_handle2,
        0x81000001,
    );
    assert_eq!(
        evict_rc2,
        TpmRc::NV_DEFINED.get(),
        "EvictControl to an already defined persistent handle must return TPM_RC_NV_DEFINED"
    );
}

#[test]
fn test_evict_control_hierarchy_disabled() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Create and persist an Owner hierarchy object without stClear
    let (rc, primary_handle) = create_primary(&mut tpm, &mut global_state, Handle::RH_OWNER, false);
    assert_eq!(rc, 0);
    let persistent_handle = 0x81000001;
    let evict_rc = evict_control(
        &mut tpm,
        &mut global_state,
        Handle::RH_OWNER,
        primary_handle,
        persistent_handle,
    );
    assert_eq!(evict_rc, 0);

    // 2. Disable Storage Hierarchy using HierarchyControl
    let hc_rc = hierarchy_control(
        &mut tpm,
        &mut global_state,
        Handle::RH_OWNER,
        Handle::RH_OWNER,
        false,
    );
    assert_eq!(hc_rc, 0);

    // 3. Attempting to access the persistent handle directly via load_persistent_object should fail while disabled
    assert!(
        tpm.load_persistent_object(&global_state, persistent_handle)
            .is_err(),
        "Persistent object access must return error when its hierarchy is disabled"
    );

    // 4. Re-enable Storage Hierarchy using HierarchyControl (requires Platform auth)
    let hc_rc2 = hierarchy_control(
        &mut tpm,
        &mut global_state,
        Handle::RH_PLATFORM,
        Handle::RH_OWNER,
        true,
    );
    assert_eq!(hc_rc2, 0);

    // 5. Verifying persistent object access succeeds without handle reference exceptions on subsequent operations
    assert!(
        tpm.load_persistent_object(&global_state, persistent_handle)
            .is_ok(),
        "Persistent object access must succeed when its hierarchy is re-enabled"
    );

    // 6. Evict (remove) persistent handle
    let evict_rc2 = evict_control(
        &mut tpm,
        &mut global_state,
        Handle::RH_OWNER,
        persistent_handle,
        persistent_handle,
    );
    assert_eq!(
        evict_rc2, 0,
        "Evicting persistent object from NV storage must succeed"
    );
    assert!(
        tpm.load_persistent_object(&global_state, persistent_handle)
            .is_err(),
        "Persistent object should be removed from NV after eviction"
    );
}
