use tpm2::{Marshal, Unmarshal};
extern crate alloc;

mod common;

use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::Handle;
use tpm2::commands::{Command, Rewrap, RewrapHandles};
use tpm2::{Tpm2bEncryptedSecret, Tpm2bName, Tpm2bPrivate, TpmsAuthCommand};
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

fn execute_tpm_command<C: Command>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &C::Handles,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<(C::RespHandles, C::Response<'static>), u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <<C as Command>::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: Unmarshal<'static>,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    let handles_slice: &mut <C::Handles as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C::Handles as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let handles_len = handles.marshal(handles_slice);
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
    let resp_handles = C::RespHandles::unmarshal(&mut handles_slice).unwrap();
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
        let resp = <C::Response<'static>>::unmarshal(&mut param_slice).unwrap();
        Ok((resp_handles, resp))
    } else {
        let mut param_slice: &'static [u8] =
            std::vec::Vec::leak(response_buf[resp_offset..].to_vec());
        let resp = <C::Response<'static>>::unmarshal(&mut param_slice).unwrap();
        Ok((resp_handles, resp))
    }
}

#[test]
fn test_rewrap_null_parents() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let handles = RewrapHandles {
        old_parent: Handle::RH_NULL,
        new_parent: Handle::RH_NULL,
    };
    let test_blob = [1, 2, 3, 4, 5, 6, 7, 8];
    let cmd = Rewrap {
        in_duplicate: Tpm2bPrivate::from_bytes(&test_blob).unwrap(),
        name: Tpm2bName::default(),
        in_sym_seed: Tpm2bEncryptedSecret::default(),
    };

    let (_, resp) = execute_tpm_command::<Rewrap>(&mut tpm, &mut global_state, &handles, &cmd, &[])
        .expect("Rewrap with null parents failed");

    assert_eq!(resp.out_duplicate.get_buffer(), &test_blob);
    assert_eq!(resp.out_sym_seed.get_size(), 0);
}

#[test]
fn test_rewrap_seed_handle_mismatch() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Non-empty in_sym_seed with RHNull old_parent must return handle error
    let handles = RewrapHandles {
        old_parent: Handle::RH_NULL,
        new_parent: Handle::RH_NULL,
    };
    let cmd = Rewrap {
        in_duplicate: Tpm2bPrivate::default(),
        name: Tpm2bName::default(),
        in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&[1u8; 16]).unwrap(),
    };

    let err = execute_tpm_command::<Rewrap>(&mut tpm, &mut global_state, &handles, &cmd, &[])
        .expect_err("Rewrap should fail when in_sym_seed is non-empty for null old_parent");

    assert_ne!(err, 0);
}
