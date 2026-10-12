#![allow(clippy::unwrap_used, clippy::expect_used)]

extern crate alloc;

mod common;

use common::{FakeRng, FakeStorage, FakeTimer, TestCryptoProvider, marshal_to_slice};
use hex_literal::hex;
use tpm2::commands::{Command, HMACStart, Message, UnmarshalMessage};
use tpm2::crypto::Random;
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, Marshal, Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bNonce, TpmaObject, TpmaSession,
    TpmiAlgHash, TpmsAuthCommand, Unmarshal,
};
use tpm2_impl::owned::{OwnedPrivateKeyRsa, OwnedSensitiveComposite};
use tpm2_impl::{TpmEngine, TpmPlatform};

fn setup_tpm<'a>(
    crypto: &'a TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    _rng: FakeRng,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer>,
    tpm2_impl::GlobalState,
) {
    let rng = crypto.rng_seeded(&[0u8; 32]).unwrap();
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state).unwrap();
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
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &C,
    auths: &[TpmsAuthCommand<'_>],
) -> Result<(C::Response<'static>, C::Response<'static>), u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: Copy,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&u32::from(C::CMD_CODE).to_be_bytes());

    for h in cmd.handles().as_ref() {
        request_buf[offset..offset + 4].copy_from_slice(&h.0.to_be_bytes());
        offset += 4;
    }

    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4;
        let auth_start = offset;
        for auth in auths {
            let mut auth_buf = [0u8; TpmsAuthCommand::MAX_SIZE];
            let auth_len = auth.marshal(&mut auth_buf);
            request_buf[offset..offset + auth_len].copy_from_slice(&auth_buf[..auth_len]);
            offset += auth_len;
        }
        let auth_len = u32::try_from(offset - auth_start).unwrap();
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    offset += marshal_to_slice(cmd, &mut request_buf[offset..]);
    request_buf[2..6].copy_from_slice(&u32::try_from(offset).unwrap().to_be_bytes());

    let response_buf = alloc::vec![0u8; 16384].leak();
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut resp_slice: &'static [u8] = &response_buf[10..resp_size];
    let mut resp_handles = <C::Response<'static> as Message>::Handles::default();
    for h in resp_handles.as_mut() {
        *h = Handle::unmarshal(&mut resp_slice).map_err(|_| TpmRc::FAILURE.get())?;
    }

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        let param_size = u32::unmarshal(&mut resp_slice).map_err(|_| TpmRc::FAILURE.get())?;
        let param_len = usize::try_from(param_size).unwrap();
        resp_slice = &resp_slice[..param_len];
    }

    let resp_params = C::Response::unmarshal_with_handles(resp_handles, &mut resp_slice)
        .map_err(|_| TpmRc::FAILURE.get())?;

    Ok((resp_params, resp_params))
}

#[test]
fn test_mac_start_dispatch_without_sessions() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let cmd = HMACStart {
        handle: Handle(0x80000001),
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]);

    assert!(res.is_err());
    let err_code = res.err().unwrap();
    assert_eq!(err_code, TpmRc::REFERENCE_H0.get());
}

#[test]
fn test_mac_start_dispatch_with_sessions() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // Setup a transient object so that it exists in the TPM and we can authenticate it
    let key_handle = 0x80000001;
    let transient_obj = tpm2_impl::handler::TransientObject {
        handle: key_handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[1u8; 32]).unwrap(),
        name: (Tpm2bName::new(&[1, 2, 3]).unwrap()).into(),
        auth: (Tpm2bAuth::new(b"password").unwrap()).into(),
        public: (tpm2::TpmtPublic {
            object_attributes: TpmaObject::USER_WITH_AUTH,
            ..Default::default()
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::default()),
        qualified_name: (Tpm2bName::new(&[1, 2, 3]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(transient_obj);

    let auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::default(),
        hmac: Tpm2bDigest::new(b"password").unwrap(),
    }];

    let cmd = HMACStart {
        handle: Handle(key_handle),
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &cmd, &auths);

    assert!(res.is_err());
    let err_code = res.err().unwrap();
    assert_eq!(err_code, TpmRc::KEY.with(Position::handle(1)).get());
}
