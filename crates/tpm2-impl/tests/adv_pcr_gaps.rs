mod common;

use common::{FakeRng, FakeStorage, FakeTimer, TestCryptoProvider};
use hex_literal::hex;
use tpm2::commands::{Command, Message, PCREvent, PCRExtend, PCRRead, PCRReset, UnmarshalMessage};
use tpm2::crypto::HashStream;
use tpm2::errors::TpmRc;
use tpm2::{
    Handle, Marshal, Tpm2bEvent, TpmiAlgHash, TpmlDigestValues, TpmlPcrSelection, TpmsAuthCommand,
    TpmsPcrSelect, TpmsPcrSelection, TpmtHa, Unmarshal,
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
        *h = Handle::unmarshal(&mut handles_slice).map_err(|_| TpmRc::FAILURE.get())?;
    }

    let handles_len = orig_handles_len - handles_slice.len();
    resp_offset += handles_len;

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        resp_offset += 4; // Skip parameter size
    }

    let mut params_slice: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
    let resp_params =
        <C::Response<'static>>::unmarshal_with_handles(resp_handles, &mut params_slice)
            .map_err(|_| TpmRc::FAILURE.get())?;

    Ok(resp_params)
}

fn compute_expected_extend(
    crypto: &TestCryptoProvider,
    alg: TpmiAlgHash,
    old: &[u8],
    new: &[u8],
) -> [u8; 64] {
    let mut ctx = HashStream::new(crypto, alg).unwrap();
    ctx.update(old).unwrap();
    ctx.update(new).unwrap();
    let mut out = [0u8; 64];
    ctx.finalize(&mut out).unwrap();
    out
}

#[test]
fn adv_pcr_read_unsupported_bank() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // Create selection containing unsupported SHA-512 bank
    let pcr_selection_in = TpmlPcrSelection::new(&[TpmsPcrSelection {
        hash: TpmiAlgHash::Sha512,
        selection: TpmsPcrSelect::new(&[0x0E, 0x00, 0x00]).unwrap(),
    }])
    .unwrap();

    let read_cmd = PCRRead { pcr_selection_in };
    let resp = execute_tpm_command(&mut tpm, &mut global_state, &read_cmd, &[]).unwrap();

    // The output selection count should match (contains the bank we requested)
    assert_eq!(resp.pcr_selection_out.as_slice().len(), 1);
    let out_sel = &resp.pcr_selection_out.as_slice()[0];
    assert_eq!(out_sel.hash, TpmiAlgHash::Sha512);
    // But since the bank is unsupported, all bits in selection out should be cleared (0)
    for &b in out_sel.selection.pcrs() {
        assert_eq!(b, 0);
    }
    // No digests should be returned in values list
    assert_eq!(resp.pcr_values.as_slice().len(), 0);
}

#[test]
fn adv_pcr_extend_rh_null() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // Keep track of some baseline PCR values (e.g. PCR 5)
    let pcr_idx = 5usize;
    let baseline_sha256 = global_state.pcrs.sha256[pcr_idx];

    let extend_val_sha256 = [0x22u8; 32];
    let digests = TpmlDigestValues::new(&[TpmtHa::Sha256(&extend_val_sha256)]).unwrap();

    // Call PCR_Extend with TPM_RH_NULL
    let extend_cmd = PCRExtend {
        pcr_handle: Handle::RH_NULL,
        digests,
    };
    execute_tpm_command(&mut tpm, &mut global_state, &extend_cmd, &[]).unwrap();

    // Verify that the PCR 5 value did not change
    assert_eq!(global_state.pcrs.sha256[pcr_idx], baseline_sha256);
}

fn execute_tpm_event<'a>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &PCREvent,
    response_buf: &'a mut [u8],
) -> Result<<PCREvent<'static> as Command>::Response<'a>, u32> {
    let mut request_buf = [0u8; 16384];
    request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    request_buf[6..10].copy_from_slice(&(PCREvent::CMD_CODE.code()).to_be_bytes());

    let mut offset = 10;
    for handle in cmd.handles().as_ref() {
        request_buf[offset..offset + 4].copy_from_slice(&handle.0.to_be_bytes());
        offset += 4;
    }

    let mut cmd_buf = [0u8; PCREvent::MAX_SIZE];
    let cmd_len = cmd.marshal(&mut cmd_buf);
    request_buf[offset..offset + cmd_len].copy_from_slice(&cmd_buf.as_ref()[..cmd_len]);
    offset += cmd_len;

    let total_len = u32::try_from(offset).unwrap();
    request_buf[2..6].copy_from_slice(&total_len.to_be_bytes());
    tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut param_slice: &'static [u8] = std::vec::Vec::leak(response_buf[10..].to_vec());
    UnmarshalMessage::unmarshal_with_handles([], &mut param_slice).map_err(|_| TpmRc::FAILURE.get())
}

#[test]
fn adv_pcr_event_empty_data() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let pcr_idx = 5usize;
    let initial_sha1 = global_state.pcrs.sha1[pcr_idx];
    let initial_sha256 = global_state.pcrs.sha256[pcr_idx];
    let initial_sha384 = global_state.pcrs.sha384[pcr_idx];

    // Empty event data
    let event_data = Tpm2bEvent::new(&[]).unwrap();
    let event_cmd = PCREvent {
        pcr_handle: Handle(u32::try_from(pcr_idx).unwrap()),
        event_data,
    };
    let mut response_buf = [0u8; 16384];
    let resp =
        execute_tpm_event(&mut tpm, &mut global_state, &event_cmd, &mut response_buf).unwrap();

    // Calculate empty data hashes
    let mut out1 = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let empty_hash_sha1 =
        tpm2::crypto::hash(tpm.platform.crypto, TpmiAlgHash::Sha1, &[], &mut out1)
            .unwrap()
            .digest();
    let mut out2 = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let empty_hash_sha256 =
        tpm2::crypto::hash(tpm.platform.crypto, TpmiAlgHash::Sha256, &[], &mut out2)
            .unwrap()
            .digest();
    let mut out3 = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let empty_hash_sha384 =
        tpm2::crypto::hash(tpm.platform.crypto, TpmiAlgHash::Sha384, &[], &mut out3)
            .unwrap()
            .digest();

    // Verify digests returned match hashes of empty data
    let mut found_sha1 = false;
    let mut found_sha256 = false;
    let mut found_sha384 = false;

    for digest_val in resp.digests.as_slice() {
        match *digest_val {
            TpmtHa::Sha1(val) => {
                assert_eq!(val, empty_hash_sha1);
                found_sha1 = true;
            }
            TpmtHa::Sha256(val) => {
                assert_eq!(val, empty_hash_sha256);
                found_sha256 = true;
            }
            TpmtHa::Sha384(val) => {
                assert_eq!(val, empty_hash_sha384);
                found_sha384 = true;
            }
            _ => {}
        }
    }

    assert!(found_sha1);
    assert!(found_sha256);
    assert!(found_sha384);

    // Verify PCRs are extended by the empty data digests
    let expected_sha1 = compute_expected_extend(
        tpm.platform.crypto,
        TpmiAlgHash::Sha1,
        &initial_sha1,
        empty_hash_sha1,
    );
    let expected_sha256 = compute_expected_extend(
        tpm.platform.crypto,
        TpmiAlgHash::Sha256,
        &initial_sha256,
        empty_hash_sha256,
    );
    let expected_sha384 = compute_expected_extend(
        tpm.platform.crypto,
        TpmiAlgHash::Sha384,
        &initial_sha384,
        empty_hash_sha384,
    );

    assert_eq!(global_state.pcrs.sha1[pcr_idx], expected_sha1[..20]);
    assert_eq!(global_state.pcrs.sha256[pcr_idx], expected_sha256[..32]);
    assert_eq!(global_state.pcrs.sha384[pcr_idx], expected_sha384[..48]);
}

#[test]
fn adv_pcr_reset_rh_null() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let reset_cmd = PCRReset {
        pcr_handle: Handle::RH_NULL,
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &reset_cmd, &[]);
    assert_eq!(
        res,
        Err(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)).get())
    );
}

#[test]
fn test_pcr_locality_enforcement() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // 1. Extend PCR 17 at locality 0 (should fail, 17 expects 2, 3, 4)
    global_state.locality = 0;
    let digests = TpmlDigestValues::new(&[TpmtHa::Sha1(&[0xbb; 20])]).unwrap();
    let extend_cmd = PCRExtend {
        pcr_handle: Handle(17),
        digests,
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &extend_cmd, &[]);
    assert_eq!(res, Err(TpmRc::LOCALITY.get()));

    // 2. Extend PCR 17 at locality 3 (should succeed)
    global_state.locality = 3;
    let res = execute_tpm_command(&mut tpm, &mut global_state, &extend_cmd, &[]);
    assert!(res.is_ok());

    // 3. Reset PCR 16 at locality 4 (should fail, 16 expects 0, 1, 2, 3)
    global_state.locality = 4;
    let reset_cmd = PCRReset {
        pcr_handle: Handle(16),
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &reset_cmd, &[]);
    assert_eq!(res, Err(TpmRc::LOCALITY.get()));

    // 4. Reset PCR 16 at locality 0 (should succeed)
    global_state.locality = 0;
    let res = execute_tpm_command(&mut tpm, &mut global_state, &reset_cmd, &[]);
    assert!(res.is_ok());
}

#[test]
fn test_pcr_invalid_handles() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // 1. Extend on PCR 24
    let digests = TpmlDigestValues::new(&[TpmtHa::Sha1(&[0xcc; 20])]).unwrap();
    let extend_cmd = PCRExtend {
        pcr_handle: Handle(24),
        digests,
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &extend_cmd, &[]);
    assert_eq!(
        res,
        Err(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)).get())
    );

    // 2. Event on PCR 24
    let event_cmd = PCREvent {
        pcr_handle: Handle(24),
        event_data: Tpm2bEvent::new(b"test").unwrap(),
    };
    let mut response_buf = [0u8; 16384];
    let res = execute_tpm_event(&mut tpm, &mut global_state, &event_cmd, &mut response_buf);
    assert_eq!(
        res,
        Err(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)).get())
    );

    // 3. Reset on PCR 24
    let reset_cmd = PCRReset {
        pcr_handle: Handle(24),
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &reset_cmd, &[]);
    assert_eq!(
        res,
        Err(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)).get())
    );
}

#[test]
fn test_pcr_update_counter() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // Read baseline update counter
    let read_cmd = PCRRead {
        pcr_selection_in: TpmlPcrSelection::default(),
    };
    let resp = execute_tpm_command(&mut tpm, &mut global_state, &read_cmd, &[]).unwrap();
    let initial_counter = resp.pcr_update_counter;

    // 1. Extend PCR 16
    let digests = TpmlDigestValues::new(&[TpmtHa::Sha1(&[0xdd; 20])]).unwrap();
    let extend_cmd = PCRExtend {
        pcr_handle: Handle(16),
        digests,
    };
    execute_tpm_command(&mut tpm, &mut global_state, &extend_cmd, &[]).unwrap();

    // Read counter again
    let resp = execute_tpm_command(&mut tpm, &mut global_state, &read_cmd, &[]).unwrap();
    let after_extend_counter = resp.pcr_update_counter;
    assert_eq!(after_extend_counter, initial_counter + 1);

    // 2. Reset PCR 16
    let reset_cmd = PCRReset {
        pcr_handle: Handle(16),
    };
    execute_tpm_command(&mut tpm, &mut global_state, &reset_cmd, &[]).unwrap();

    // Read counter again
    let resp = execute_tpm_command(&mut tpm, &mut global_state, &read_cmd, &[]).unwrap();
    let after_reset_counter = resp.pcr_update_counter;
    assert_eq!(after_reset_counter, after_extend_counter + 1);
}

#[test]
fn test_pcr_update_counter_wrap_around() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    global_state.pcrs.update_counter = u32::MAX; // set to maximum value AFTER startup

    // Read counter
    let read_cmd = PCRRead {
        pcr_selection_in: TpmlPcrSelection::default(),
    };
    let resp = execute_tpm_command(&mut tpm, &mut global_state, &read_cmd, &[]).unwrap();
    assert_eq!(resp.pcr_update_counter, u32::MAX);

    // Extend PCR 16 to trigger update_counter increment
    let digests = TpmlDigestValues::new(&[TpmtHa::Sha1(&[0xdd; 20])]).unwrap();
    let extend_cmd = PCRExtend {
        pcr_handle: Handle(16),
        digests,
    };
    execute_tpm_command(&mut tpm, &mut global_state, &extend_cmd, &[]).unwrap();

    // Read counter again
    let resp = execute_tpm_command(&mut tpm, &mut global_state, &read_cmd, &[]).unwrap();
    assert_eq!(resp.pcr_update_counter, 0);
}

#[test]
fn test_pcr_read_sort_order() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // Build selection: SHA256 first, then SHA1.
    // Select PCR 0..6 (6 PCRs) for each.
    let pcr_selection_in = TpmlPcrSelection::new(&[
        TpmsPcrSelection {
            hash: TpmiAlgHash::Sha256,
            selection: TpmsPcrSelect::new(&[0x3F, 0x00, 0x00]).unwrap(),
        },
        TpmsPcrSelection {
            hash: TpmiAlgHash::Sha1,
            selection: TpmsPcrSelect::new(&[0x3F, 0x00, 0x00]).unwrap(),
        },
    ])
    .unwrap();

    let read_cmd = PCRRead { pcr_selection_in };
    let resp = execute_tpm_command(&mut tpm, &mut global_state, &read_cmd, &[]).unwrap();

    // Total returned digests must be exactly 8 (the limit)
    assert_eq!(resp.pcr_values.as_slice().len(), 8);

    // Since SHA1 (alg 0x0004) has lower ID than SHA256 (0x000B), it must be sorted first.
    // Therefore, the first 6 digests should be SHA1 (size 20), and the remaining 2 should be SHA256 (size 32).
    let digests = resp.pcr_values.as_slice();
    for (i, digest) in digests.iter().enumerate().take(6) {
        assert_eq!(digest.as_slice().len(), 20, "Digest {} should be SHA1", i);
    }
    for (i, digest) in digests.iter().enumerate().take(8).skip(6) {
        assert_eq!(digest.as_slice().len(), 32, "Digest {} should be SHA256", i);
    }
}
