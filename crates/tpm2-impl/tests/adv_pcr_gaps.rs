use tpm2::errors::TpmRc;
use tpm2::{Marshal, Unmarshal};
mod common;

use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::Handle;
use tpm2::commands::{Command, Message, PCRExtend, PCRRead, UnmarshalMessage};
use tpm2::{TpmlDigestValues, TpmlPcrSelection, TpmsAuthCommand, TpmtHa};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

fn setup_tpm<'a>(
    crypto: &'a mut TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a mut FakeRng,
) -> TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng> {
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    tpm.init_storage();
    tpm.state.nv_available = true;
    tpm.state.locality = 0;
    tpm.state.g_nv_ok = true;

    // Startup
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(&startup_request[..], &mut startup_response[..]);
    tpm
}

/// An empty-password `TPM_RS_PW` session. In C every handle with an authorization role
/// needs a session even if its authValue is empty; with no session C returns
/// TPM_RC_AUTH_MISSING (SessionProcess.c CheckAuthNoSession).
fn pw() -> tpm2::TpmsAuthCommand<'static> {
    tpm2::TpmsAuthCommand {
        session_handle: tpm2::Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: tpm2::TpmaSession(0),
        hmac: tpm2::Tpm2bAuth::default(),
    }
}

fn execute_tpm_command<C: Command>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
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
        let handle_slice: &mut <tpm2::Handle as Marshal>::MaxBuffer = (&mut request_buf
            [offset..offset + tpm2::Handle::MAX_SIZE])
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
    let resp_size = tpm.execute_command_separate(&request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut resp_offset = 10;
    let mut handles_slice = &response_buf[resp_offset..resp_size];
    let orig_handles_len = handles_slice.len();
    let mut resp_handles = <C::Response<'static> as Message>::Handles::default();
    for handle in resp_handles.as_mut() {
        *handle = tpm2::Handle::unmarshal(&mut handles_slice).map_err(|_| TpmRc::FAILURE.get())?;
    }

    let handles_len = orig_handles_len - handles_slice.len();
    resp_offset += handles_len;

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        resp_offset += 4; // Skip parameter size
    }

    let mut params_slice: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
    let resp_params = <C::Response<'static> as UnmarshalMessage>::unmarshal_with_handles(
        resp_handles,
        &mut params_slice,
    )
    .map_err(|_| TpmRc::FAILURE.get())?;

    Ok(resp_params)
}

#[test]
fn test_pcr_update_counter_wrap_around() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let mut tpm = setup_tpm(&mut crypto, &mut storage, &mut timer, &mut rng);

    tpm.state.pcrs.update_counter = u32::MAX; // set to maximum value AFTER startup

    // Read counter
    let read_cmd = PCRRead {
        pcr_selection_in: TpmlPcrSelection::default(),
    };
    let resp = execute_tpm_command(&mut tpm, &read_cmd, &[]).unwrap();
    assert_eq!(resp.pcr_update_counter, u32::MAX);

    // Extend PCR 16 to trigger update_counter increment
    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha256(&[0xdd; 32])).unwrap();
    let extend_cmd = PCRExtend {
        pcr_handle: Handle(16),
        digests,
    };
    execute_tpm_command(&mut tpm, &extend_cmd, &[pw()]).unwrap();

    // Read counter again
    let resp = execute_tpm_command(&mut tpm, &read_cmd, &[]).unwrap();
    assert_eq!(resp.pcr_update_counter, 0);
}
