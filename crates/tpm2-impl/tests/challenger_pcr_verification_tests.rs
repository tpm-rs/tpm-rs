use common::marshal_to_slice;
use tpm2::errors::TpmRc;

use tpm2::Unmarshal;
mod common;

use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::Handle;
use tpm2::commands::{
    Command, PCREvent, PCREventHandles, PCRExtend, PCRExtendHandles, PCRRead, PCRReset,
    PCRResetHandles,
};
use tpm2::{
    Marshal, Tpm2bEvent, TpmiAlgHash, TpmlDigestValues, TpmlPcrSelection, TpmsPcrSelection, TpmtHa,
};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

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
    handles: &C::Handles,
    cmd: &C,
) -> Result<(C::RespHandles, C::Response<'static>), u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <<C as Command>::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: Unmarshal<'static>,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    offset += marshal_to_slice(handles, &mut request_buf[offset..]);
    offset += marshal_to_slice(cmd, &mut request_buf[offset..]);
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
    let resp_handles =
        C::RespHandles::unmarshal(&mut handles_slice).map_err(|_| TpmRc::FAILURE.get())?;

    let handles_len = orig_handles_len - handles_slice.len();
    resp_offset += handles_len;

    let mut params_slice: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
    let resp_params =
        <C::Response<'static>>::unmarshal(&mut params_slice).map_err(|_| TpmRc::FAILURE.get())?;

    Ok((resp_handles, resp_params))
}

fn execute_tpm_event<'a>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &PCREventHandles,
    cmd: &PCREvent,
    response_buf: &'a mut [u8],
) -> Result<<PCREvent<'static> as Command>::Response<'a>, u32> {
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    request_buf[6..10].copy_from_slice(&(PCREvent::CMD_CODE.code()).to_be_bytes());

    offset += marshal_to_slice(handles, &mut request_buf[offset..]);
    offset += marshal_to_slice(cmd, &mut request_buf[offset..]);
    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut params_slice = &response_buf[10..];
    Unmarshal::unmarshal(&mut params_slice).map_err(|_| TpmRc::FAILURE.get())
}

fn hash_bytes<const N: usize>(alg: TpmiAlgHash, data: &[u8]) -> [u8; N] {
    let mut out = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    let d = tpm2::crypto::hash(&TestCryptoProvider, alg, data, &mut out)
        .unwrap()
        .digest();
    d.try_into().unwrap()
}

fn expected_extend_sha1(old: &[u8; 20], val: &[u8; 20]) -> [u8; 20] {
    let mut data = [0u8; 40];
    data[..20].copy_from_slice(old);
    data[20..40].copy_from_slice(val);
    hash_bytes::<20>(TpmiAlgHash::Sha1, &data)
}

fn expected_extend_sha256(old: &[u8; 32], val: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(old);
    data[32..64].copy_from_slice(val);
    hash_bytes::<32>(TpmiAlgHash::Sha256, &data)
}

fn expected_extend_sha384(old: &[u8; 48], val: &[u8; 48]) -> [u8; 48] {
    let mut data = [0u8; 96];
    data[..48].copy_from_slice(old);
    data[48..96].copy_from_slice(val);
    hash_bytes::<48>(TpmiAlgHash::Sha384, &data)
}

fn get_digest_bytes<'a>(ha: &'a TpmtHa<'a>) -> &'a [u8] {
    ha.digest()
}

#[test]
fn test_pcr_bounds_validation() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. PCR_Extend beyond 23
    let ext_handles = PCRExtendHandles {
        pcr_handle: Handle(24),
    };
    let ext_cmd = PCRExtend {
        digests: TpmlDigestValues::default(),
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &ext_handles, &ext_cmd);
    assert_eq!(
        res,
        Err(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)).get())
    );

    // 2. PCR_Event beyond 23
    let evt_handles = PCREventHandles {
        pcr_handle: Handle(25),
    };
    let evt_cmd = PCREvent {
        event_data: Tpm2bEvent::from_bytes(&[1, 2, 3]).unwrap(),
    };
    let mut response_buf = [0u8; 16384];
    let res = execute_tpm_event(
        &mut tpm,
        &mut global_state,
        &evt_handles,
        &evt_cmd,
        &mut response_buf,
    );
    assert_eq!(
        res,
        Err(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)).get())
    );

    // 3. PCR_Reset beyond 23 -> Value error
    let rst_handles = PCRResetHandles {
        pcr_handle: Handle(24),
    };
    let rst_cmd = PCRReset {};
    let res = execute_tpm_command(&mut tpm, &mut global_state, &rst_handles, &rst_cmd);
    assert_eq!(
        res,
        Err(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)).get())
    );
}

#[test]
fn test_pcr_reset() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Reset PCR 16 (valid reset-able PCR)
    let ext_handles_16 = PCRExtendHandles {
        pcr_handle: Handle(16),
    };
    let mut digests_16 = TpmlDigestValues::default();
    digests_16.add(&TpmtHa::Sha256(&[0xaa; 32])).unwrap();
    let ext_cmd_16 = PCRExtend {
        digests: digests_16,
    };
    execute_tpm_command(&mut tpm, &mut global_state, &ext_handles_16, &ext_cmd_16).unwrap();

    // Verify PCR 16 has changed
    let mut selection_16 = TpmlPcrSelection::default();
    selection_16
        .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0, 0, 1]).unwrap())
        .unwrap();
    let read_cmd_16 = PCRRead {
        pcr_selection_in: selection_16,
    };
    let (_, read_resp_16) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &read_cmd_16).unwrap();
    assert_ne!(
        read_resp_16.pcr_values.digests()[0].get_buffer(),
        &[0u8; 32]
    );

    // Reset PCR 16
    let rst_handles_16 = PCRResetHandles {
        pcr_handle: Handle(16),
    };
    execute_tpm_command(&mut tpm, &mut global_state, &rst_handles_16, &PCRReset {}).unwrap();

    // Verify PCR 16 has reset to 0
    let (_, read_resp_16_post) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &read_cmd_16).unwrap();
    assert_eq!(
        read_resp_16_post.pcr_values.digests()[0].get_buffer(),
        &[0u8; 32]
    );

    // 2. Reset PCR 23 (valid reset-able PCR)
    let ext_handles_23 = PCRExtendHandles {
        pcr_handle: Handle(23),
    };
    let mut digests_23 = TpmlDigestValues::default();
    digests_23.add(&TpmtHa::Sha256(&[0xbb; 32])).unwrap();
    let ext_cmd_23 = PCRExtend {
        digests: digests_23,
    };
    execute_tpm_command(&mut tpm, &mut global_state, &ext_handles_23, &ext_cmd_23).unwrap();

    // Verify PCR 23 has changed
    let mut selection_23 = TpmlPcrSelection::default();
    selection_23
        .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0, 0, 128]).unwrap())
        .unwrap();
    let read_cmd_23 = PCRRead {
        pcr_selection_in: selection_23,
    };
    let (_, read_resp_23) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &read_cmd_23).unwrap();
    assert_ne!(
        read_resp_23.pcr_values.digests()[0].get_buffer(),
        &[0u8; 32]
    );

    // Reset PCR 23
    let rst_handles_23 = PCRResetHandles {
        pcr_handle: Handle(23),
    };
    execute_tpm_command(&mut tpm, &mut global_state, &rst_handles_23, &PCRReset {}).unwrap();

    // Verify PCR 23 has reset to 0
    let (_, read_resp_23_post) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &read_cmd_23).unwrap();
    assert_eq!(
        read_resp_23_post.pcr_values.digests()[0].get_buffer(),
        &[0u8; 32]
    );

    // 3. Reset PCR 0 (should fail with Locality)
    let rst_handles_0 = PCRResetHandles {
        pcr_handle: Handle(0),
    };
    let res_0 = execute_tpm_command(&mut tpm, &mut global_state, &rst_handles_0, &PCRReset {});
    assert_eq!(res_0, Err(TpmRc::LOCALITY.get()));
}

#[test]
fn test_pcr_extend_correctness() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let sha1_init = [0u8; 20];
    let sha256_init = [0u8; 32];
    let sha384_init = [0u8; 48];

    let sha1_ext = [0x11; 20];
    let sha256_ext = [0x22; 32];
    let sha384_ext = [0x33; 48];

    let ext_handles = PCRExtendHandles {
        pcr_handle: Handle(0),
    };
    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha1(&sha1_ext)).unwrap();
    digests.add(&TpmtHa::Sha256(&sha256_ext)).unwrap();
    digests.add(&TpmtHa::Sha384(&sha384_ext)).unwrap();

    let ext_cmd = PCRExtend { digests };
    execute_tpm_command(&mut tpm, &mut global_state, &ext_handles, &ext_cmd).unwrap();

    let mut selection = TpmlPcrSelection::default();
    selection
        .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha1, &[1, 0, 0]).unwrap())
        .unwrap();
    selection
        .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[1, 0, 0]).unwrap())
        .unwrap();
    selection
        .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha384, &[1, 0, 0]).unwrap())
        .unwrap();

    let read_cmd = PCRRead {
        pcr_selection_in: selection,
    };
    let (_, read_resp) = execute_tpm_command(&mut tpm, &mut global_state, &(), &read_cmd).unwrap();

    assert_eq!(read_resp.pcr_values.count(), 3);

    let expected_sha1 = expected_extend_sha1(&sha1_init, &sha1_ext);
    let expected_sha256 = expected_extend_sha256(&sha256_init, &sha256_ext);
    let expected_sha384 = expected_extend_sha384(&sha384_init, &sha384_ext);

    assert_eq!(
        read_resp.pcr_values.digests()[0].get_buffer(),
        &expected_sha1
    );
    assert_eq!(
        read_resp.pcr_values.digests()[1].get_buffer(),
        &expected_sha256
    );
    assert_eq!(
        read_resp.pcr_values.digests()[2].get_buffer(),
        &expected_sha384
    );
}

#[test]
fn test_pcr_event_correctness() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let event_data = b"my test event data";
    let tpm_event = Tpm2bEvent::from_bytes(event_data).unwrap();

    // 1. PCR_Event with PCR 1
    let evt_handles = PCREventHandles {
        pcr_handle: Handle(1),
    };
    let evt_cmd = PCREvent {
        event_data: tpm_event,
    };
    let mut response_buf1 = [0u8; 2048];
    let evt_resp = execute_tpm_event(
        &mut tpm,
        &mut global_state,
        &evt_handles,
        &evt_cmd,
        &mut response_buf1,
    )
    .unwrap();

    let expected_sha1_hash = hash_bytes::<20>(TpmiAlgHash::Sha1, event_data);
    let expected_sha256_hash = hash_bytes::<32>(TpmiAlgHash::Sha256, event_data);
    let expected_sha384_hash = hash_bytes::<48>(TpmiAlgHash::Sha384, event_data);

    assert_eq!(evt_resp.digests.count(), 3);
    assert_eq!(
        get_digest_bytes(evt_resp.digests.digests().next().unwrap()),
        &expected_sha1_hash[..]
    );
    assert_eq!(
        get_digest_bytes(evt_resp.digests.digests().nth(1).unwrap()),
        &expected_sha256_hash[..]
    );
    assert_eq!(
        get_digest_bytes(evt_resp.digests.digests().nth(2).unwrap()),
        &expected_sha384_hash[..]
    );

    // Verify PCR 1 was extended
    let mut selection = TpmlPcrSelection::default();
    selection
        .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha1, &[2, 0, 0]).unwrap())
        .unwrap(); // PCR 1
    selection
        .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[2, 0, 0]).unwrap())
        .unwrap();
    selection
        .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha384, &[2, 0, 0]).unwrap())
        .unwrap();

    let read_cmd = PCRRead {
        pcr_selection_in: selection,
    };
    let (_, read_resp) = execute_tpm_command(&mut tpm, &mut global_state, &(), &read_cmd).unwrap();

    let expected_sha1_val = expected_extend_sha1(&[0u8; 20], &expected_sha1_hash);
    let expected_sha256_val = expected_extend_sha256(&[0u8; 32], &expected_sha256_hash);
    let expected_sha384_val = expected_extend_sha384(&[0u8; 48], &expected_sha384_hash);

    assert_eq!(
        read_resp.pcr_values.digests()[0].get_buffer(),
        &expected_sha1_val
    );
    assert_eq!(
        read_resp.pcr_values.digests()[1].get_buffer(),
        &expected_sha256_val
    );
    assert_eq!(
        read_resp.pcr_values.digests()[2].get_buffer(),
        &expected_sha384_val
    );

    // 2. PCR_Event with RHNull
    let null_handles = PCREventHandles {
        pcr_handle: Handle::RH_NULL,
    };
    let mut response_buf2 = [0u8; 2048];
    let null_resp = execute_tpm_event(
        &mut tpm,
        &mut global_state,
        &null_handles,
        &evt_cmd,
        &mut response_buf2,
    )
    .unwrap();

    assert_eq!(null_resp.digests.count(), 3);
    assert_eq!(
        get_digest_bytes(null_resp.digests.digests().next().unwrap()),
        &expected_sha1_hash[..]
    );

    // Verify PCR 1's values have not changed
    let (_, read_resp2) = execute_tpm_command(&mut tpm, &mut global_state, &(), &read_cmd).unwrap();
    assert_eq!(
        read_resp2.pcr_values.digests()[0].get_buffer(),
        &expected_sha1_val
    );
}

#[test]
fn test_pcr_read_constraints() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Reading empty selection
    let mut empty_selection = TpmlPcrSelection::default();
    empty_selection
        .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0, 0, 0]).unwrap())
        .unwrap();
    let read_cmd_empty = PCRRead {
        pcr_selection_in: empty_selection,
    };
    let (_, resp_empty) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &read_cmd_empty).unwrap();
    assert_eq!(resp_empty.pcr_values.count(), 0);
    assert_eq!(resp_empty.pcr_selection_out.count(), 1);
    assert_eq!(
        resp_empty
            .pcr_selection_out
            .pcr_selections()
            .next()
            .unwrap()
            .pcr_select(),
        &[0, 0, 0]
    );

    // 2. Reading exactly 8 PCRs
    let mut selection_8 = TpmlPcrSelection::default();
    selection_8
        .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0xff, 0, 0]).unwrap())
        .unwrap(); // PCR 0..7
    let read_cmd_8 = PCRRead {
        pcr_selection_in: selection_8,
    };
    let (_, resp_8) = execute_tpm_command(&mut tpm, &mut global_state, &(), &read_cmd_8).unwrap();
    assert_eq!(resp_8.pcr_values.count(), 8);

    // 3. Reading 9 PCRs
    let mut selection_9 = TpmlPcrSelection::default();
    selection_9
        .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0xff, 0x01, 0]).unwrap())
        .unwrap(); // PCR 0..8
    let read_cmd_9 = PCRRead {
        pcr_selection_in: selection_9,
    };
    let res_9 = execute_tpm_command(&mut tpm, &mut global_state, &(), &read_cmd_9);

    match res_9 {
        Ok((_, resp)) => {
            println!(
                "PCR_Read with 9 PCRs succeeded! Count: {}",
                resp.pcr_values.count()
            );
            assert_eq!(resp.pcr_values.count(), 8);
            assert_eq!(
                resp.pcr_selection_out
                    .pcr_selections()
                    .next()
                    .unwrap()
                    .pcr_select(),
                &[0xff, 0x00, 0x00]
            );
        }
        Err(rc) => {
            println!("PCR_Read with 9 PCRs failed with RC: 0x{:X}", rc);
            assert_eq!(rc, TpmRc::SIZE.get());
        }
    }
}
