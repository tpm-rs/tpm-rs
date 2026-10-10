mod common;

use common::{FakeRng, FakeStorage, FakeTimer, TestCryptoProvider};
use hex_literal::hex;
use tpm2::commands::{Command, Message, Rewrap, UnmarshalMessage};
use tpm2::{
    Handle, Marshal, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bPrivate, TpmsAuthCommand, Unmarshal,
};
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
    let rng = tpm2::crypto::Random::rng_seeded(crypto, &[0u8; 32]).unwrap();
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
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
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
        request_buf[offset..offset + 4].copy_from_slice(&handle.0.to_be_bytes());
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
    let mut handles_slice = &response_buf[resp_offset..resp_size];
    let orig_handles_len = handles_slice.len();
    let mut resp_handles = <<C::Response<'static> as Message>::Handles as Default>::default();
    for h in resp_handles.as_mut() {
        *h = Handle::unmarshal(&mut handles_slice).unwrap();
    }
    resp_offset += orig_handles_len - handles_slice.len();

    if !auths.is_empty() {
        let param_size = usize::try_from(u32::from_be_bytes(
            response_buf[resp_offset..resp_offset + 4]
                .try_into()
                .unwrap(),
        ))
        .unwrap();
        resp_offset += 4;
        let mut param_slice: &'static [u8] =
            std::vec::Vec::leak(response_buf[resp_offset..resp_offset + param_size].to_vec());
        let resp =
            <C::Response<'static>>::unmarshal_with_handles(resp_handles, &mut param_slice).unwrap();
        Ok(resp)
    } else {
        let mut param_slice: &'static [u8] =
            std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
        let resp =
            <C::Response<'static>>::unmarshal_with_handles(resp_handles, &mut param_slice).unwrap();
        Ok(resp)
    }
}

#[test]
fn test_rewrap_null_parents() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let test_blob = [1, 2, 3, 4, 5, 6, 7, 8];
    let cmd = Rewrap {
        old_parent: Handle::RH_NULL,
        new_parent: Handle::RH_NULL,
        in_duplicate: Tpm2bPrivate::new(&test_blob).unwrap(),
        name: Tpm2bName::default(),
        in_sym_seed: Tpm2bEncryptedSecret::default(),
    };

    let resp = execute_tpm_command::<Rewrap>(&mut tpm, &mut global_state, &cmd, &[])
        .expect("Rewrap with null parents failed");

    assert_eq!(resp.out_duplicate.as_slice(), &test_blob);
    assert_eq!(resp.out_sym_seed.as_slice().len(), 0);
}

#[test]
fn test_rewrap_seed_handle_mismatch() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // Non-empty in_sym_seed with RHNull old_parent must return handle error
    let cmd = Rewrap {
        old_parent: Handle::RH_NULL,
        new_parent: Handle::RH_NULL,
        in_duplicate: Tpm2bPrivate::default(),
        name: Tpm2bName::default(),
        in_sym_seed: Tpm2bEncryptedSecret::new(&[1u8; 16]).unwrap(),
    };

    let err = execute_tpm_command::<Rewrap>(&mut tpm, &mut global_state, &cmd, &[])
        .expect_err("Rewrap should fail when in_sym_seed is non-empty for null old_parent");

    assert_ne!(err, 0);
}
