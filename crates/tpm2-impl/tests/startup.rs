use tpm2::Unmarshal;
mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use tpm2::errors::{Position, TpmRc};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::TransientObject;

#[test]
fn test_startup_clear_twice_fails() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
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
    let mut response1 = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &request[..], &mut response1[..]);
    assert_eq!(&response1[6..10], &[0, 0, 0, 0]); // Success

    let mut response2 = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &request[..], &mut response2[..]);
    assert_eq!(
        u32::from_be_bytes(response2[6..10].try_into().unwrap()),
        TpmRc::INITIALIZE.get()
    );
    assert_eq!(global_state.reset_count, 1);
}

#[test]
fn test_startup_too_many_bytes() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;

    let request = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x0d, // size (13 bytes = 10 + 3)
        0x00, 0x00, 0x01, 0x44, // TPM_CC_Startup
        0x00, 0x00, // TpmSu::Clear
        0xFF, // Trailing byte
    ];
    let mut response = [0u8; 256];
    let _size = tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);

    assert_eq!(&response[6..10], &TpmRc::SIZE.get().to_be_bytes());
}

#[test]
fn stress_startup_parameter_bounds() {
    for su_val in 0..=u16::MAX {
        let mut crypto = FakeCrypto;
        let mut storage = FakeStorage::default();
        let mut timer = FakeTimer;
        let rng = FakeRng::new();
        let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
        let mut tpm = TpmEngine::new(platform).unwrap();
        let mut global_state = tpm2_impl::GlobalState::default();
        tpm.init_storage(&mut global_state);
        global_state.nv_available = true;
        global_state.locality = 0;
        global_state.orderly_state = 0x0001;
        global_state.g_nv_ok = true;

        let request = [
            0x80,
            0x01, // tag
            0x00,
            0x00,
            0x00,
            0x0c, // size (12 bytes)
            0x00,
            0x00,
            0x01,
            0x44, // TPM_CC_Startup
            (su_val >> 8) as u8,
            (su_val & 0xff) as u8,
        ];
        let mut response = [0u8; 256];
        tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
        let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());

        if su_val == 0 || su_val == 1 {
            assert_eq!(rc, 0, "Failed for valid su_val {}", su_val);
        } else {
            assert_eq!(
                rc,
                TpmRc::VALUE.with(Position::parameter(1)).get(),
                "Failed for invalid su_val {}",
                su_val
            );
        }
    }
}

#[test]
fn test_startup_clear() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
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
    assert_eq!(&response[6..10], &[0, 0, 0, 0]);
    assert_eq!(global_state.reset_count, 1);
    assert_eq!(global_state.restart_count, 0);
    assert_eq!(global_state.clear_count, 0);
    assert!(global_state.initialized);
}

#[test]
fn test_startup_invalid_su() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;

    let request = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x0c, // size (12 bytes)
        0x00, 0x00, 0x01, 0x44, // TPM_CC_Startup
        0x00, 0x02, // Invalid TpmSu
    ];
    let mut response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    assert_eq!(rc, TpmRc::VALUE.with(Position::parameter(1)).get());
}

#[test]
fn test_startup_command_size_error() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;

    let request = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x0b, // size (11 bytes)
        0x00, 0x00, 0x01, 0x44, // TPM_CC_Startup
        0x00, // Too short payload (1 byte)
    ];
    let mut response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    assert_eq!(
        rc,
        TpmRc::INSUFFICIENT
            .with(tpm2::errors::Position::parameter(1))
            .get()
    );
}

#[test]
fn test_startup_state() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;
    global_state.orderly_state = 0x0001;
    global_state.g_nv_ok = true;

    let request = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x0c, // size (12 bytes)
        0x00, 0x00, 0x01, 0x44, // TPM_CC_Startup
        0x00, 0x01, // TpmSu::State
    ];
    let mut response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    assert_eq!(&response[6..10], &[0, 0, 0, 0]);
    assert_eq!(global_state.reset_count, 0);
    assert_eq!(global_state.restart_count, 1);
    assert_eq!(global_state.clear_count, 0);
    assert!(global_state.initialized);
}

#[test]
fn test_startup_called_twice() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
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
    assert_eq!(&response[6..10], &[0, 0, 0, 0]);

    let request2 = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x0c, // size (12 bytes)
        0x00, 0x00, 0x01, 0x44, // TPM_CC_Startup
        0x00, 0x01, // TpmSu::State
    ];
    let mut response2 = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &request2[..], &mut response2[..]);
    let rc = u32::from_be_bytes(response2[6..10].try_into().unwrap());
    assert_eq!(rc, TpmRc::INITIALIZE.get());
}

#[test]
fn test_adv_startup_missing_state() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;

    let request = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x0c, // size (12 bytes)
        0x00, 0x00, 0x01, 0x44, // TPM_CC_Startup
        0x00, 0x01, // TpmSu::State
    ];
    let mut response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    assert_eq!(rc, TpmRc::VALUE.with(Position::parameter(1)).get());
}

#[test]
fn test_adv_total_reset_count_overflow() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
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
fn test_adv_nv_uninitialized_check() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = false;
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
    // C `TPM2_Startup` uses RETURN_IF_NV_IS_NOT_AVAILABLE -> TPM_RC_NV_UNAVAILABLE.
    assert_eq!(rc, TpmRc::NV_UNAVAILABLE.get());
}

#[test]
fn test_adv_startup_locality_4_drtm() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.drtm_pre_startup = true;
    global_state.locality = 4;

    let request = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x0c, // size (12 bytes)
        0x00, 0x00, 0x01, 0x44, // TPM_CC_Startup
        0x00, 0x00, // TpmSu::Clear
    ];
    let mut response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    // C `TPM2_Startup` checks `locality != 0 && locality != 3` before the H-CRTM override
    // (`Startup.c`), so a Startup at locality 4 is rejected even after an H-CRTM sequence.
    assert_eq!(rc, TpmRc::LOCALITY.get());
}

#[test]
fn test_orderly_clear() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;
    global_state.orderly_state = 0x0000; // TPM_SU_CLEAR
    global_state.g_nv_ok = true;

    let request = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x0c, // size (12 bytes)
        0x00, 0x00, 0x01, 0x44, // TPM_CC_Startup
        0x00, 0x00, // TpmSu::Clear
    ];
    let mut response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    assert_eq!(rc, 0);
    // Shutdown(CLEAR) + Startup(CLEAR) is a TPM Reset (`Startup.c`), not a TPM Restart.
    assert_eq!(global_state.clear_count, 0);
    assert_eq!(global_state.restart_count, 0);
    assert_eq!(global_state.reset_count, 1);
}

#[test]
fn test_adv_nv_storage_failure() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    storage.fail_on_write = true;
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
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
fn test_startup_state_clears_transient_objects_and_sequences() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;

    let mut tpmt_public_buf = [0u8; 1024];
    tpmt_public_buf[0] = 0x00;
    tpmt_public_buf[1] = 0x08; // KeyedHash
    tpmt_public_buf[2] = 0x00;
    tpmt_public_buf[3] = 0x0B; // Sha256
    tpmt_public_buf[10] = 0x00;
    tpmt_public_buf[11] = 0x10; // Null scheme

    // Populate transient RAM state from an earlier session before Startup(SU_STATE)
    global_state.transient_objects[0] = Some(TransientObject {
        handle: 0x80000000,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (tpm2::Tpm2bName::default()).into(),
        auth: (tpm2::Tpm2bAuth::default()).into(),
        public: (tpm2::TpmtPublic::unmarshal(&mut (&tpmt_public_buf[..])).unwrap()).into(),
        private: [0u8; 1536],
        private_len: 0,
        qualified_name: (tpm2::Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    });
    global_state.active_sequences[0] = Some(tpm2_impl::ActiveSequence::new(
        0x80000010,
        tpm2::Tpm2bAuth::default(),
        tpm2_impl::SequenceType::Hash {
            alg: tpm2::TpmiAlgHash::Sha256,
        },
    ));
    global_state.saved_sessions[0] = Some(0x02000001); // Saved session must survive SU_STATE
    global_state.initialized = false;
    global_state.orderly_state = 0x0001; // TPM_SU_STATE from prior shutdown
    global_state.g_nv_ok = true;

    let request = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x0c, // size (12 bytes)
        0x00, 0x00, 0x01, 0x44, // TPM_CC_Startup
        0x00, 0x01, // TpmSu::State
    ];
    let mut response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &request[..], &mut response[..]);
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    assert_eq!(rc, 0);

    // Assert transient objects and active sequences are cleared on SU_STATE (spec Part 1 Sec 12.2.3)
    assert!(
        global_state
            .transient_objects
            .iter()
            .all(|obj| obj.is_none())
    );
    assert!(
        global_state
            .active_sequences
            .iter()
            .all(|seq| seq.is_none())
    );
    // Assert saved sessions survive SU_STATE
    assert_eq!(global_state.saved_sessions[0], Some(0x02000001));
}

#[test]
fn test_shutdown_state_invalidated_by_pcr_extend() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;

    // 1. Startup(CLEAR)
    let startup_clear = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
    ];
    let mut response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &startup_clear, &mut response);
    assert_eq!(u32::from_be_bytes(response[6..10].try_into().unwrap()), 0);

    // 2. Shutdown(STATE)
    let shutdown_state = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x45, 0x00, 0x01,
    ];
    tpm.execute_command_separate(&mut global_state, &shutdown_state, &mut response);
    assert_eq!(u32::from_be_bytes(response[6..10].try_into().unwrap()), 0);
    assert_eq!(global_state.orderly_state, 0x0001);
    assert!(global_state.state_saved);

    // 3. Execute PCR_Extend on PCR 0 (state-saved PCR) after Shutdown(STATE)
    let pcr_extend = [
        0x80, 0x02, // TPM_ST_SESSIONS
        0x00, 0x00, 0x00, 0x41, // size: 65 bytes
        0x00, 0x00, 0x01, 0x82, // TPM_CC_PCR_Extend
        0x00, 0x00, 0x00, 0x00, // pcrHandle: PCR 0
        0x00, 0x00, 0x00, 0x09, // authSize: 9 bytes
        0x40, 0x00, 0x00, 0x09, // TPM_RS_PW
        0x00, 0x00, // nonce size 0
        0x01, // sessionAttributes: continueSession
        0x00, 0x00, // hmac size 0
        0x00, 0x00, 0x00, 0x01, // count: 1 digest
        0x00, 0x0b, // hashAlg: SHA256
        // 32-byte digest
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa,
    ];
    tpm.execute_command_separate(&mut global_state, &pcr_extend, &mut response);
    assert_eq!(u32::from_be_bytes(response[6..10].try_into().unwrap()), 0);

    // Verify orderly_state is invalidated to SU_NONE_VALUE (0xFFFF) in memory and NV storage
    assert_eq!(global_state.orderly_state, 0xFFFF);
    assert!(!global_state.state_saved);

    // 4. Simulate reboot and attempt Startup(STATE) -> must fail with TPM_RC_VALUE
    global_state.initialized = false;
    global_state.g_nv_ok = true;
    let startup_state = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x01,
    ];
    tpm.execute_command_separate(&mut global_state, &startup_state, &mut response);
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    assert_eq!(rc, TpmRc::VALUE.with(Position::parameter(1)).get());
}

#[test]
fn test_shutdown_state_invalidated_by_hierarchy_change_auth_platform() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;

    // 1. Startup(CLEAR)
    let startup_clear = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
    ];
    let mut response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &startup_clear, &mut response);
    assert_eq!(u32::from_be_bytes(response[6..10].try_into().unwrap()), 0);

    // 2. Shutdown(STATE)
    let shutdown_state = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x45, 0x00, 0x01,
    ];
    tpm.execute_command_separate(&mut global_state, &shutdown_state, &mut response);
    assert_eq!(u32::from_be_bytes(response[6..10].try_into().unwrap()), 0);
    assert_eq!(global_state.orderly_state, 0x0001);

    // 3. Execute HierarchyChangeAuth on TPM_RH_PLATFORM after Shutdown(STATE)
    let change_auth = [
        0x80, 0x02, // TPM_ST_SESSIONS
        0x00, 0x00, 0x00, 0x21, // size: 33 bytes
        0x00, 0x00, 0x01, 0x29, // TPM_CC_HierarchyChangeAuth
        0x40, 0x00, 0x00, 0x0c, // authHandle: TPM_RH_PLATFORM
        0x00, 0x00, 0x00, 0x09, // authSize: 9 bytes
        0x40, 0x00, 0x00, 0x09, // TPM_RS_PW
        0x00, 0x00, // nonce size 0
        0x01, // sessionAttributes: continueSession
        0x00, 0x00, // hmac size 0
        0x00, 0x04, // newAuth size: 4 bytes
        0x01, 0x02, 0x03, 0x04, // newAuth
    ];
    tpm.execute_command_separate(&mut global_state, &change_auth, &mut response);
    assert_eq!(u32::from_be_bytes(response[6..10].try_into().unwrap()), 0);

    // Verify orderly_state is invalidated to 0xFFFF (not 0x0000!)
    assert_eq!(global_state.orderly_state, 0xFFFF);
}

#[test]
fn test_startup_populates_platform_unique_details_and_get_capability_returns_rh_auth_00() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;

    // Startup(CLEAR)
    let startup_clear = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
    ];
    let mut response = [0u8; 512];
    tpm.execute_command_separate(&mut global_state, &startup_clear, &mut response);
    assert_eq!(u32::from_be_bytes(response[6..10].try_into().unwrap()), 0);

    // Verify platform_unique_details matches ibmswtpm2 _plat__GetUnique(1, 48, ...)
    assert_eq!(global_state.platform_unique_details.get_size(), 48);
    assert_eq!(
        global_state.platform_unique_details.get_buffer(),
        b"euqinu laer A .eulav euqinu a yllaer ton si sihT"
    );

    // Query TPM2_GetCapability(TPM_CAP_HANDLES, property = 0x40000000, count = 32)
    let get_cap = [
        0x80, 0x01, // TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x16, // size: 22 bytes
        0x00, 0x00, 0x01, 0x7a, // TPM_CC_GetCapability
        0x00, 0x00, 0x00, 0x01, // capability: TPM_CAP_HANDLES
        0x40, 0x00, 0x00, 0x00, // property: permanent handles (0x40000000)
        0x00, 0x00, 0x00, 0x20, // propertyCount: 32
    ];
    let resp_len = tpm.execute_command_separate(&mut global_state, &get_cap, &mut response);
    assert_eq!(u32::from_be_bytes(response[6..10].try_into().unwrap()), 0);

    // Response structure: header (10) + moreData (1) + capability (4) + count (4) + handles (4 * count)
    assert!(resp_len >= 19);
    let count = u32::from_be_bytes(response[15..19].try_into().unwrap()) as usize;
    let mut found_rh_auth_00 = false;
    for i in 0..count {
        let offset = 19 + i * 4;
        let handle = u32::from_be_bytes(response[offset..offset + 4].try_into().unwrap());
        if handle == tpm2::Handle::RH_AUTH_00.0 {
            found_rh_auth_00 = true;
        }
    }
    assert!(
        found_rh_auth_00,
        "TPM_RH_AUTH_00 (0x40000010) must be present in permanent handles"
    );
}

#[test]
fn test_startup_preserves_custom_platform_unique_details_and_allows_policy_secret() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);
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
