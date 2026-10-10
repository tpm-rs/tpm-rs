mod common;

use common::marshal_to_slice;
use common::{FakeRng, FakeStorage, FakeTimer, TestCryptoProvider};
use hex_literal::hex;
use tpm2::commands::{Command, Message, PCREvent, PCRExtend, PCRRead, PCRReset, UnmarshalMessage};
use tpm2::errors::TpmRc;
use tpm2::{
    Handle, Marshal, Tpm2bEvent, TpmiAlgHash, TpmlDigestValues, TpmlPcrSelection, TpmsPcrSelect,
    TpmsPcrSelection, TpmtHa, Unmarshal,
};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

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
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    for handle in cmd.handles().as_ref() {
        request_buf[offset..offset + 4].copy_from_slice(&handle.0.to_be_bytes());
        offset += 4;
    }
    offset += marshal_to_slice(cmd, &mut request_buf[offset..]);
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
        *h = Handle::unmarshal(&mut handles_slice).map_err(|_| TpmRc::FAILURE.get())?;
    }

    let handles_len = orig_handles_len - handles_slice.len();
    resp_offset += handles_len;

    let mut params_slice: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
    let resp_params =
        <C::Response<'static>>::unmarshal_with_handles(resp_handles, &mut params_slice)
            .map_err(|_| TpmRc::FAILURE.get())?;

    Ok(resp_params)
}

fn execute_tpm_event<'a>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &PCREvent,
    response_buf: &'a mut [u8],
) -> Result<<PCREvent<'static> as Command>::Response<'a>, u32> {
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    request_buf[6..10].copy_from_slice(&(PCREvent::CMD_CODE.code()).to_be_bytes());

    for handle in cmd.handles().as_ref() {
        request_buf[offset..offset + 4].copy_from_slice(&handle.0.to_be_bytes());
        offset += 4;
    }
    offset += marshal_to_slice(cmd, &mut request_buf[offset..]);
    let total_len = u32::try_from(offset).unwrap();
    request_buf[2..6].copy_from_slice(&total_len.to_be_bytes());

    tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut params_slice = &response_buf[10..];
    UnmarshalMessage::unmarshal_with_handles([], &mut params_slice)
        .map_err(|_| TpmRc::FAILURE.get())
}

fn hash_bytes<const N: usize>(alg: TpmiAlgHash, data: &[u8]) -> [u8; N] {
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
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
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // 1. PCR_Extend beyond 23
    let ext_cmd = PCRExtend {
        pcr_handle: Handle(24),
        digests: TpmlDigestValues::default(),
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &ext_cmd);
    assert_eq!(
        res,
        Err(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)).get())
    );

    // 2. PCR_Event beyond 23
    let evt_cmd = PCREvent {
        pcr_handle: Handle(25),
        event_data: Tpm2bEvent::new(&[1, 2, 3]).unwrap(),
    };
    let mut response_buf = [0u8; 16384];
    let res = execute_tpm_event(&mut tpm, &mut global_state, &evt_cmd, &mut response_buf);
    assert_eq!(
        res,
        Err(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)).get())
    );

    // 3. PCR_Reset beyond 23 -> Value error
    let rst_cmd = PCRReset {
        pcr_handle: Handle(24),
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &rst_cmd);
    assert_eq!(
        res,
        Err(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)).get())
    );
}

#[test]
fn test_pcr_reset() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // 1. Reset PCR 16 (valid reset-able PCR)
    let digests_16 = TpmlDigestValues::new(&[TpmtHa::Sha256(&[0xaa; 32])]).unwrap();
    let ext_cmd_16 = PCRExtend {
        pcr_handle: Handle(16),
        digests: digests_16,
    };
    execute_tpm_command(&mut tpm, &mut global_state, &ext_cmd_16).unwrap();

    // Verify PCR 16 has changed
    let selection_16 = TpmlPcrSelection::new(&[TpmsPcrSelection {
        hash: TpmiAlgHash::Sha256,
        selection: TpmsPcrSelect::new(&[0, 0, 1]).unwrap(),
    }])
    .unwrap();
    let read_cmd_16 = PCRRead {
        pcr_selection_in: selection_16,
    };
    let read_resp_16 = execute_tpm_command(&mut tpm, &mut global_state, &read_cmd_16).unwrap();
    assert_ne!(read_resp_16.pcr_values.as_slice()[0].as_slice(), &[0u8; 32]);

    // Reset PCR 16
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &PCRReset {
            pcr_handle: Handle(16),
        },
    )
    .unwrap();

    // Verify PCR 16 has reset to 0
    let read_resp_16_post = execute_tpm_command(&mut tpm, &mut global_state, &read_cmd_16).unwrap();
    assert_eq!(
        read_resp_16_post.pcr_values.as_slice()[0].as_slice(),
        &[0u8; 32]
    );

    // 2. Reset PCR 23 (valid reset-able PCR)
    let digests_23 = TpmlDigestValues::new(&[TpmtHa::Sha256(&[0xbb; 32])]).unwrap();
    let ext_cmd_23 = PCRExtend {
        pcr_handle: Handle(23),
        digests: digests_23,
    };
    execute_tpm_command(&mut tpm, &mut global_state, &ext_cmd_23).unwrap();

    // Verify PCR 23 has changed
    let selection_23 = TpmlPcrSelection::new(&[TpmsPcrSelection {
        hash: TpmiAlgHash::Sha256,
        selection: TpmsPcrSelect::new(&[0, 0, 128]).unwrap(),
    }])
    .unwrap();
    let read_cmd_23 = PCRRead {
        pcr_selection_in: selection_23,
    };
    let read_resp_23 = execute_tpm_command(&mut tpm, &mut global_state, &read_cmd_23).unwrap();
    assert_ne!(read_resp_23.pcr_values.as_slice()[0].as_slice(), &[0u8; 32]);

    // Reset PCR 23
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &PCRReset {
            pcr_handle: Handle(23),
        },
    )
    .unwrap();

    // Verify PCR 23 has reset to 0
    let read_resp_23_post = execute_tpm_command(&mut tpm, &mut global_state, &read_cmd_23).unwrap();
    assert_eq!(
        read_resp_23_post.pcr_values.as_slice()[0].as_slice(),
        &[0u8; 32]
    );

    // 3. Reset PCR 0 (should fail with Locality)
    let res_0 = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &PCRReset {
            pcr_handle: Handle(0),
        },
    );
    assert_eq!(res_0, Err(TpmRc::LOCALITY.get()));
}

#[test]
fn test_pcr_extend_correctness() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let sha1_init = [0u8; 20];
    let sha256_init = [0u8; 32];
    let sha384_init = [0u8; 48];

    let sha1_ext = [0x11; 20];
    let sha256_ext = [0x22; 32];
    let sha384_ext = [0x33; 48];

    let digests = TpmlDigestValues::new(&[
        TpmtHa::Sha1(&sha1_ext),
        TpmtHa::Sha256(&sha256_ext),
        TpmtHa::Sha384(&sha384_ext),
    ])
    .unwrap();

    let ext_cmd = PCRExtend {
        pcr_handle: Handle(0),
        digests,
    };
    execute_tpm_command(&mut tpm, &mut global_state, &ext_cmd).unwrap();

    let selection = TpmlPcrSelection::new(&[
        TpmsPcrSelection {
            hash: TpmiAlgHash::Sha1,
            selection: TpmsPcrSelect::new(&[1, 0, 0]).unwrap(),
        },
        TpmsPcrSelection {
            hash: TpmiAlgHash::Sha256,
            selection: TpmsPcrSelect::new(&[1, 0, 0]).unwrap(),
        },
        TpmsPcrSelection {
            hash: TpmiAlgHash::Sha384,
            selection: TpmsPcrSelect::new(&[1, 0, 0]).unwrap(),
        },
    ])
    .unwrap();

    let read_cmd = PCRRead {
        pcr_selection_in: selection,
    };
    let read_resp = execute_tpm_command(&mut tpm, &mut global_state, &read_cmd).unwrap();

    assert_eq!(read_resp.pcr_values.as_slice().len(), 3);

    let expected_sha1 = expected_extend_sha1(&sha1_init, &sha1_ext);
    let expected_sha256 = expected_extend_sha256(&sha256_init, &sha256_ext);
    let expected_sha384 = expected_extend_sha384(&sha384_init, &sha384_ext);

    assert_eq!(
        read_resp.pcr_values.as_slice()[0].as_slice(),
        &expected_sha1
    );
    assert_eq!(
        read_resp.pcr_values.as_slice()[1].as_slice(),
        &expected_sha256
    );
    assert_eq!(
        read_resp.pcr_values.as_slice()[2].as_slice(),
        &expected_sha384
    );
}

#[test]
fn test_pcr_event_correctness() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let event_data = b"my test event data";
    let tpm_event = Tpm2bEvent::new(event_data).unwrap();

    // 1. PCR_Event with PCR 1
    let evt_cmd = PCREvent {
        pcr_handle: Handle(1),
        event_data: tpm_event,
    };
    let mut response_buf1 = [0u8; 2048];
    let evt_resp =
        execute_tpm_event(&mut tpm, &mut global_state, &evt_cmd, &mut response_buf1).unwrap();

    let expected_sha1_hash = hash_bytes::<20>(TpmiAlgHash::Sha1, event_data);
    let expected_sha256_hash = hash_bytes::<32>(TpmiAlgHash::Sha256, event_data);
    let expected_sha384_hash = hash_bytes::<48>(TpmiAlgHash::Sha384, event_data);

    assert_eq!(evt_resp.digests.as_slice().len(), 3);
    assert_eq!(
        get_digest_bytes(&evt_resp.digests.as_slice()[0]),
        &expected_sha1_hash[..]
    );
    assert_eq!(
        get_digest_bytes(&evt_resp.digests.as_slice()[1]),
        &expected_sha256_hash[..]
    );
    assert_eq!(
        get_digest_bytes(&evt_resp.digests.as_slice()[2]),
        &expected_sha384_hash[..]
    );

    // Verify PCR 1 was extended
    let selection = TpmlPcrSelection::new(&[
        TpmsPcrSelection {
            hash: TpmiAlgHash::Sha1,
            selection: TpmsPcrSelect::new(&[2, 0, 0]).unwrap(),
        }, // PCR 1
        TpmsPcrSelection {
            hash: TpmiAlgHash::Sha256,
            selection: TpmsPcrSelect::new(&[2, 0, 0]).unwrap(),
        },
        TpmsPcrSelection {
            hash: TpmiAlgHash::Sha384,
            selection: TpmsPcrSelect::new(&[2, 0, 0]).unwrap(),
        },
    ])
    .unwrap();

    let read_cmd = PCRRead {
        pcr_selection_in: selection,
    };
    let read_resp = execute_tpm_command(&mut tpm, &mut global_state, &read_cmd).unwrap();

    let expected_sha1_val = expected_extend_sha1(&[0u8; 20], &expected_sha1_hash);
    let expected_sha256_val = expected_extend_sha256(&[0u8; 32], &expected_sha256_hash);
    let expected_sha384_val = expected_extend_sha384(&[0u8; 48], &expected_sha384_hash);

    assert_eq!(
        read_resp.pcr_values.as_slice()[0].as_slice(),
        &expected_sha1_val
    );
    assert_eq!(
        read_resp.pcr_values.as_slice()[1].as_slice(),
        &expected_sha256_val
    );
    assert_eq!(
        read_resp.pcr_values.as_slice()[2].as_slice(),
        &expected_sha384_val
    );

    // 2. PCR_Event with RHNull
    let null_cmd = PCREvent {
        pcr_handle: Handle::RH_NULL,
        event_data: tpm_event,
    };
    let mut response_buf2 = [0u8; 2048];
    let null_resp =
        execute_tpm_event(&mut tpm, &mut global_state, &null_cmd, &mut response_buf2).unwrap();

    assert_eq!(null_resp.digests.as_slice().len(), 3);
    assert_eq!(
        get_digest_bytes(&null_resp.digests.as_slice()[0]),
        &expected_sha1_hash[..]
    );

    // Verify PCR 1's values have not changed
    let read_resp2 = execute_tpm_command(&mut tpm, &mut global_state, &read_cmd).unwrap();
    assert_eq!(
        read_resp2.pcr_values.as_slice()[0].as_slice(),
        &expected_sha1_val
    );
}

#[test]
fn test_pcr_read_constraints() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // 1. Reading empty selection
    let empty_selection = TpmlPcrSelection::new(&[TpmsPcrSelection {
        hash: TpmiAlgHash::Sha256,
        selection: TpmsPcrSelect::new(&[0, 0, 0]).unwrap(),
    }])
    .unwrap();
    let read_cmd_empty = PCRRead {
        pcr_selection_in: empty_selection,
    };
    let resp_empty = execute_tpm_command(&mut tpm, &mut global_state, &read_cmd_empty).unwrap();
    assert_eq!(resp_empty.pcr_values.as_slice().len(), 0);
    assert_eq!(resp_empty.pcr_selection_out.as_slice().len(), 1);
    assert_eq!(
        resp_empty.pcr_selection_out.as_slice()[0].selection.pcrs(),
        &[0, 0, 0]
    );

    // 2. Reading exactly 8 PCRs
    let selection_8 = TpmlPcrSelection::new(&[TpmsPcrSelection {
        hash: TpmiAlgHash::Sha256,
        selection: TpmsPcrSelect::new(&[0xff, 0, 0]).unwrap(),
    }])
    .unwrap(); // PCR 0..7
    let read_cmd_8 = PCRRead {
        pcr_selection_in: selection_8,
    };
    let resp_8 = execute_tpm_command(&mut tpm, &mut global_state, &read_cmd_8).unwrap();
    assert_eq!(resp_8.pcr_values.as_slice().len(), 8);

    // 3. Reading 9 PCRs
    let selection_9 = TpmlPcrSelection::new(&[TpmsPcrSelection {
        hash: TpmiAlgHash::Sha256,
        selection: TpmsPcrSelect::new(&[0xff, 0x01, 0]).unwrap(),
    }])
    .unwrap(); // PCR 0..8
    let read_cmd_9 = PCRRead {
        pcr_selection_in: selection_9,
    };
    let res_9 = execute_tpm_command(&mut tpm, &mut global_state, &read_cmd_9);

    match res_9 {
        Ok(resp) => {
            println!(
                "PCR_Read with 9 PCRs succeeded! Count: {}",
                resp.pcr_values.as_slice().len()
            );
            assert_eq!(resp.pcr_values.as_slice().len(), 8);
            assert_eq!(
                resp.pcr_selection_out.as_slice()[0].selection.pcrs(),
                &[0xff, 0x00, 0x00]
            );
        }
        Err(rc) => {
            println!("PCR_Read with 9 PCRs failed with RC: 0x{:X}", rc);
            assert_eq!(rc, TpmRc::SIZE.get());
        }
    }
}
