use tpm2::{Marshal, Unmarshal};
mod common;

use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::Handle;
use tpm2::commands::{Command, HMACStart, Message, UnmarshalMessage};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bNonce, TpmaObject, TpmaSession, TpmiAlgHash,
    TpmsAuthCommand,
};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

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

    // Startup
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
        offset += handle.marshal(handle_slice);
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
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut resp_offset = 10;
    let mut handles_slice = &response_buf[resp_offset..resp_size];
    let orig_handles_len = handles_slice.len();
    let mut resp_handles = <C::Response<'static> as Message>::Handles::default();
    for handle in resp_handles.as_mut() {
        *handle = Handle::unmarshal(&mut handles_slice).map_err(|_| TpmRc::FAILURE.get())?;
    }

    let handles_len = orig_handles_len - handles_slice.len();
    resp_offset += handles_len;

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        resp_offset += 4; // Skip parameter size
    }

    let mut params_slice: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
    let resp = <C::Response<'static>>::unmarshal_with_handles(resp_handles, &mut params_slice)
        .map_err(|_| TpmRc::FAILURE.get())?;

    Ok(resp)
}

#[test]
fn test_mac_start_dispatch_without_sessions() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &mut rng);

    let cmd = HMACStart {
        handle: Handle(0x80000001),
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]);

    // We expect the command to fail with the specific error returned by hmac_start.
    // If hmac_start is returning CommandCode, we expect CommandCode.
    // We will verify this explicitly.
    assert!(res.is_err());
    let err_code = res.err().unwrap();
    println!(
        "test_mac_start_dispatch_without_sessions error code: 0x{:X}",
        err_code
    );
    assert_eq!(err_code, TpmRc::REFERENCE_H0.get());
}

#[test]
fn test_mac_start_dispatch_with_sessions() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &mut rng);

    // Setup a transient object so that it exists in the TPM and we can authenticate it
    let key_handle = 0x80000001;
    let transient_obj = tpm2_impl::handler::TransientObject {
        handle: key_handle,
        seed: {
            let mut s = [0u8; 64];
            s[..32].copy_from_slice(&[1u8; 32]);
            s
        },
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::from_bytes(&[1, 2, 3]).unwrap()).into(),
        auth: (Tpm2bAuth::from_bytes(b"password").unwrap()).into(),
        public: (tpm2::TpmtPublic {
            object_attributes: TpmaObject::USER_WITH_AUTH,
            ..Default::default()
        })
        .into(),
        private: [0u8; 1536],
        private_len: 0,
        qualified_name: (Tpm2bName::from_bytes(&[1, 2, 3]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(transient_obj);

    // We use a password session (Handle::RS_PW) for simplicity.
    // Let's construct a TpmsAuthCommand.
    let auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::default(),
        hmac: Tpm2bDigest::from_bytes(b"password").unwrap(),
    }];

    let cmd = HMACStart {
        handle: Handle(key_handle),
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &cmd, &auths);

    assert!(res.is_err());
    let err_code = res.err().unwrap();
    println!(
        "test_mac_start_dispatch_with_sessions error code: 0x{:X}",
        err_code
    );
    assert_eq!(err_code, TpmRc::KEY.with(Position::handle(1)).get());
}
