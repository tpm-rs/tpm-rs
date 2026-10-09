use tpm2::errors::TpmRc;
use tpm2::{Marshal, Unmarshal};
extern crate alloc;

mod common;

use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::Handle;
use tpm2::commands::{Command, GetCommandAuditDigest, GetCommandAuditDigestHandles};
use tpm2::{Tpm2bAuth, Tpm2bData, Tpm2bNonce, TpmaSession, TpmsAuthCommand};
use tpm2_impl::{TpmEngine, TpmPlatform};

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

fn execute_tpm_get_command_audit_digest<'a>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &GetCommandAuditDigestHandles,
    cmd: &GetCommandAuditDigest,
    auths: &[TpmsAuthCommand],
    response_buf: &'a mut [u8],
) -> Result<<GetCommandAuditDigest<'static> as Command>::Response<'a>, u32> {
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(GetCommandAuditDigest::CMD_CODE.code()).to_be_bytes());

    let mut handles_buf = [0u8; GetCommandAuditDigestHandles::MAX_SIZE];
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

    let mut cmd_buf = [0u8; GetCommandAuditDigest::MAX_SIZE];
    let cmd_len = cmd.marshal(&mut cmd_buf);
    request_buf[offset..offset + cmd_len].copy_from_slice(&cmd_buf.as_ref()[..cmd_len]);
    offset += cmd_len;
    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut resp_offset = 10;
    if !auths.is_empty() {
        let param_size = u32::from_be_bytes(
            response_buf[resp_offset..resp_offset + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        resp_offset += 4;
        let mut param_slice: &'static [u8] =
            std::vec::Vec::leak(response_buf[resp_offset..resp_offset + param_size].to_vec());
        Unmarshal::unmarshal(&mut param_slice).map_err(|_| TpmRc::FAILURE.get())
    } else {
        let mut param_slice: &'static [u8] =
            std::vec::Vec::leak(response_buf[resp_offset..].to_vec());
        Unmarshal::unmarshal(&mut param_slice).map_err(|_| TpmRc::FAILURE.get())
    }
}

#[test]
fn test_get_command_audit_digest() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Call GetCommandAuditDigest with sign_handle: RHNull
    let audit_handles = GetCommandAuditDigestHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: Handle::RH_NULL,
    };
    let audit_cmd = GetCommandAuditDigest {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    // Both privacyAdminHandle and signHandle (TPM_RH_NULL) have the USER auth role, so C
    // needs two sessions (SessionProcess.c:1641-1651, otherwise TPM_RC_AUTH_MISSING).
    let pw = TpmsAuthCommand {
        session_handle: Handle(0x40000009),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::default(),
        hmac: Tpm2bAuth::default(),
    };
    let auths = [pw, pw];

    let mut response_buf = [0u8; 16384];
    let resp = execute_tpm_get_command_audit_digest(
        &mut tpm,
        &mut global_state,
        &audit_handles,
        &audit_cmd,
        &auths,
        &mut response_buf,
    )
    .expect("GetCommandAuditDigest failed");

    assert!(resp.audit_info.get_size() > 0);
}

#[test]
fn test_get_command_audit_digest_with_rsa_signing_key() {
    use common::FakeCrypto;
    use tpm2::{
        PublicParmsAndId, Tpm2bDigest, Tpm2bName, Tpm2bPublicKeyRsa, TpmaObject, TpmiAlgHash,
        TpmsRsaParms, TpmtPublic,
    };
    use tpm2_impl::handler::TransientObject;

    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut response = [0u8; 1024];
    tpm.execute_command_separate(&mut global_state, &startup_request[..], &mut response[..]);

    let key_handle = 0x80000001;
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::RESTRICTED
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let obj = TransientObject {
        handle: key_handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0xcc; 1536],
        private_len: 256,
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    // GetCommandAuditDigest request:
    // tag: 8002
    // cc: 00000133
    // handles: privacyAdmin (4000000B), signHandle (80000001)
    // auth area: 2 password sessions
    // qualifyingData: 0003 'aaa'
    // inScheme: 0014 (RSASSA) 0004 (SHA1)
    let mut req = Vec::new();
    req.extend_from_slice(&hex!("8002"));
    req.extend_from_slice(&[0, 0, 0, 0]); // size placeholder
    req.extend_from_slice(&hex!("00000133")); // TPM_CC_GetCommandAuditDigest
    req.extend_from_slice(&0x4000000Bu32.to_be_bytes()); // RH_ENDORSEMENT
    req.extend_from_slice(&key_handle.to_be_bytes()); // signHandle
    // Auth size + 2 auth sessions (each: handle=40000009, nonce=0, attr=01, hmac=0)
    req.extend_from_slice(&hex!(
        "00000012 40000009 0000 01 0000 40000009 0000 01 0000"
    ));
    // qualifyingData
    req.extend_from_slice(&hex!("0003 616161"));
    // inScheme: RSASSA (0x0014) SHA1 (0x0004)
    req.extend_from_slice(&hex!("0014 0004"));

    let req_len = req.len() as u32;
    req[2..6].copy_from_slice(&req_len.to_be_bytes());

    let mut response_buf = [0u8; 16384];
    tpm.execute_command_separate(&mut global_state, &req[..], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(rc, 0, "GetCommandAuditDigest failed with rc: 0x{:08x}", rc);
}

#[test]
fn test_get_command_audit_digest_with_zeroed_audit_hash_alg() {
    use common::FakeCrypto;
    use tpm2::{
        PublicParmsAndId, Tpm2bDigest, Tpm2bName, Tpm2bPublicKeyRsa, TpmaObject, TpmiAlgHash,
        TpmsRsaParms, TpmtPublic,
    };
    use tpm2_impl::handler::TransientObject;

    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    global_state.init_zeroed();
    // Intentionally test with audit_hash_alg = 0
    global_state.audit_hash_alg = 0;
    tpm.init_storage(&mut global_state);

    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut response = [0u8; 1024];
    tpm.execute_command_separate(&mut global_state, &startup_request[..], &mut response[..]);

    let key_handle = 0x80000001;
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::RESTRICTED
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let obj = TransientObject {
        handle: key_handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0xcc; 1536],
        private_len: 256,
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    let mut req = Vec::new();
    req.extend_from_slice(&hex!("8002"));
    req.extend_from_slice(&[0, 0, 0, 0]); // size placeholder
    req.extend_from_slice(&hex!("00000133")); // TPM_CC_GetCommandAuditDigest
    req.extend_from_slice(&0x4000000Bu32.to_be_bytes()); // RH_ENDORSEMENT
    req.extend_from_slice(&key_handle.to_be_bytes()); // signHandle
    req.extend_from_slice(&hex!(
        "00000012 40000009 0000 01 0000 40000009 0000 01 0000"
    ));
    req.extend_from_slice(&hex!("0003 616161"));
    req.extend_from_slice(&hex!("0014 0004"));

    let req_len = req.len() as u32;
    req[2..6].copy_from_slice(&req_len.to_be_bytes());

    let mut response_buf = [0u8; 16384];
    tpm.execute_command_separate(&mut global_state, &req[..], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc, 0,
        "GetCommandAuditDigest should succeed without panic even if audit_hash_alg was 0, got rc: 0x{:08x}",
        rc
    );
}
