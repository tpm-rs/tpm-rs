use tpm2::errors::TpmRc;
use tpm2::{Marshal, Unmarshal};
mod common;

use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::Handle;
use tpm2::commands::{
    Command, PCREvent, PCREventHandles, PCRExtend, PCRExtendHandles, PCRRead, PCRReset,
    PCRResetHandles,
};
use tpm2::crypto::HashCtx;
use tpm2::{
    Tpm2bEvent, TpmiAlgHash, TpmlDigestValues, TpmlPcrSelection, TpmsAuthCommand, TpmsPcrSelection,
    TpmtHa,
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

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        resp_offset += 4; // Skip parameter size
    }

    let mut params_slice: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
    let resp_params =
        <C::Response<'static>>::unmarshal(&mut params_slice).map_err(|_| TpmRc::FAILURE.get())?;

    Ok((resp_handles, resp_params))
}

fn compute_expected_extend(
    crypto: &TestCryptoProvider,
    alg: TpmiAlgHash,
    old: &[u8],
    new: &[u8],
) -> [u8; 64] {
    let mut ctx = HashCtx::new(crypto, alg).unwrap();
    ctx.update(old).unwrap();
    ctx.update(new).unwrap();
    let mut out = [0u8; 64];
    ctx.finalize(&mut out).unwrap();
    out
}

#[test]
fn adv_pcr_read_unsupported_bank() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Create selection containing unsupported SHA-512 bank
    let mut pcr_selection_in = TpmlPcrSelection::default();
    // Select PCR 1, 2, 3 in SHA-512 bank
    pcr_selection_in
        .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha512, &[0x0E, 0x00, 0x00]).unwrap())
        .unwrap();

    let read_cmd = PCRRead { pcr_selection_in };
    let (_, resp) = execute_tpm_command(&mut tpm, &mut global_state, &(), &read_cmd, &[]).unwrap();

    // The output selection count should match (contains the bank we requested)
    assert_eq!(resp.pcr_selection_out.count(), 1);
    let out_sel = resp.pcr_selection_out.pcr_selections().next().unwrap();
    assert_eq!(out_sel.hash(), TpmiAlgHash::Sha512);
    // But since the bank is unsupported, all bits in selection out should be cleared (0)
    for &b in out_sel.pcr_select() {
        assert_eq!(b, 0);
    }
    // No digests should be returned in values list
    assert_eq!(resp.pcr_values.count(), 0);
}

#[test]
fn adv_pcr_extend_rh_null() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Keep track of some baseline PCR values (e.g. PCR 5)
    let pcr_idx = 5usize;
    let baseline_sha256 = global_state.pcrs.sha256[pcr_idx];

    let extend_val_sha256 = [0x22u8; 32];
    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha256(&extend_val_sha256)).unwrap();

    // Call PCR_Extend with TPM_RH_NULL
    let extend_handles = PCRExtendHandles {
        pcr_handle: Handle::RH_NULL,
    };
    let extend_cmd = PCRExtend { digests };
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &extend_handles,
        &extend_cmd,
        &[],
    )
    .unwrap();

    // Verify that the PCR 5 value did not change
    assert_eq!(global_state.pcrs.sha256[pcr_idx], baseline_sha256);
}

fn execute_tpm_event<'a>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &PCREventHandles,
    cmd: &PCREvent,
    response_buf: &'a mut [u8],
) -> Result<<PCREvent<'static> as Command>::Response<'a>, u32> {
    let mut request_buf = [0u8; 16384];
    request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    request_buf[6..10].copy_from_slice(&(PCREvent::CMD_CODE.code()).to_be_bytes());

    let mut offset = 10;
    let mut handles_buf = [0u8; PCREventHandles::MAX_SIZE];
    let handles_len = handles.marshal(&mut handles_buf);
    request_buf[offset..offset + handles_len].copy_from_slice(&handles_buf.as_ref()[..handles_len]);
    offset += handles_len;

    let mut cmd_buf = [0u8; PCREvent::MAX_SIZE];
    let cmd_len = cmd.marshal(&mut cmd_buf);
    request_buf[offset..offset + cmd_len].copy_from_slice(&cmd_buf.as_ref()[..cmd_len]);
    offset += cmd_len;

    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());
    tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut param_slice: &'static [u8] = std::vec::Vec::leak(response_buf[10..].to_vec());
    Unmarshal::unmarshal(&mut param_slice).map_err(|_| TpmRc::FAILURE.get())
}

#[test]
fn adv_pcr_event_empty_data() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let pcr_idx = 5usize;
    let initial_sha1 = global_state.pcrs.sha1[pcr_idx];
    let initial_sha256 = global_state.pcrs.sha256[pcr_idx];
    let initial_sha384 = global_state.pcrs.sha384[pcr_idx];

    // Empty event data
    let event_data = Tpm2bEvent::from_bytes(&[]).unwrap();
    let event_handles = PCREventHandles {
        pcr_handle: Handle(pcr_idx as u32),
    };
    let event_cmd = PCREvent { event_data };
    let mut response_buf = [0u8; 16384];
    let resp = execute_tpm_event(
        &mut tpm,
        &mut global_state,
        &event_handles,
        &event_cmd,
        &mut response_buf,
    )
    .unwrap();

    // Calculate empty data hashes
    let mut out1 = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    let empty_hash_sha1 =
        tpm2::crypto::hash(tpm.platform.crypto, TpmiAlgHash::Sha1, &[], &mut out1)
            .unwrap()
            .digest();
    let mut out2 = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    let empty_hash_sha256 =
        tpm2::crypto::hash(tpm.platform.crypto, TpmiAlgHash::Sha256, &[], &mut out2)
            .unwrap()
            .digest();
    let mut out3 = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    let empty_hash_sha384 =
        tpm2::crypto::hash(tpm.platform.crypto, TpmiAlgHash::Sha384, &[], &mut out3)
            .unwrap()
            .digest();

    // Verify digests returned match hashes of empty data
    let mut found_sha1 = false;
    let mut found_sha256 = false;
    let mut found_sha384 = false;

    for digest_val in resp.digests.digests() {
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
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let reset_handles = PCRResetHandles {
        pcr_handle: Handle::RH_NULL,
    };
    let reset_cmd = PCRReset {};
    let res = execute_tpm_command(&mut tpm, &mut global_state, &reset_handles, &reset_cmd, &[]);
    assert_eq!(
        res,
        Err(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)).get())
    );
}

#[test]
fn test_pcr_locality_enforcement() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Extend PCR 17 at locality 0 (should fail, 17 expects 2, 3, 4)
    global_state.locality = 0;
    let extend_handles = PCRExtendHandles {
        pcr_handle: Handle(17),
    };
    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha1(&[0xbb; 20])).unwrap();
    let extend_cmd = PCRExtend { digests };
    let res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &extend_handles,
        &extend_cmd,
        &[],
    );
    assert_eq!(res, Err(TpmRc::LOCALITY.get()));

    // 2. Extend PCR 17 at locality 3 (should succeed)
    global_state.locality = 3;
    let res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &extend_handles,
        &extend_cmd,
        &[],
    );
    assert!(res.is_ok());

    // 3. Reset PCR 16 at locality 4 (should fail, 16 expects 0, 1, 2, 3)
    global_state.locality = 4;
    let reset_handles = PCRResetHandles {
        pcr_handle: Handle(16),
    };
    let reset_cmd = PCRReset {};
    let res = execute_tpm_command(&mut tpm, &mut global_state, &reset_handles, &reset_cmd, &[]);
    assert_eq!(res, Err(TpmRc::LOCALITY.get()));

    // 4. Reset PCR 16 at locality 0 (should succeed)
    global_state.locality = 0;
    let res = execute_tpm_command(&mut tpm, &mut global_state, &reset_handles, &reset_cmd, &[]);
    assert!(res.is_ok());
}

#[test]
fn test_pcr_invalid_handles() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Extend on PCR 24
    let extend_handles = PCRExtendHandles {
        pcr_handle: Handle(24),
    };
    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha1(&[0xcc; 20])).unwrap();
    let extend_cmd = PCRExtend { digests };
    let res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &extend_handles,
        &extend_cmd,
        &[],
    );
    assert_eq!(
        res,
        Err(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)).get())
    );

    // 2. Event on PCR 24
    let event_handles = PCREventHandles {
        pcr_handle: Handle(24),
    };
    let event_cmd = PCREvent {
        event_data: Tpm2bEvent::from_bytes(b"test").unwrap(),
    };
    let mut response_buf = [0u8; 16384];
    let res = execute_tpm_event(
        &mut tpm,
        &mut global_state,
        &event_handles,
        &event_cmd,
        &mut response_buf,
    );
    assert_eq!(
        res,
        Err(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)).get())
    );

    // 3. Reset on PCR 24
    let reset_handles = PCRResetHandles {
        pcr_handle: Handle(24),
    };
    let reset_cmd = PCRReset {};
    let res = execute_tpm_command(&mut tpm, &mut global_state, &reset_handles, &reset_cmd, &[]);
    assert_eq!(
        res,
        Err(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)).get())
    );
}

#[test]
fn test_pcr_update_counter() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Read baseline update counter
    let read_cmd = PCRRead {
        pcr_selection_in: TpmlPcrSelection::default(),
    };
    let (_, resp) = execute_tpm_command(&mut tpm, &mut global_state, &(), &read_cmd, &[]).unwrap();
    let initial_counter = resp.pcr_update_counter;

    // 1. Extend PCR 16
    let extend_handles = PCRExtendHandles {
        pcr_handle: Handle(16),
    };
    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha1(&[0xdd; 20])).unwrap();
    let extend_cmd = PCRExtend { digests };
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &extend_handles,
        &extend_cmd,
        &[],
    )
    .unwrap();

    // Read counter again
    let (_, resp) = execute_tpm_command(&mut tpm, &mut global_state, &(), &read_cmd, &[]).unwrap();
    let after_extend_counter = resp.pcr_update_counter;
    assert_eq!(after_extend_counter, initial_counter + 1);

    // 2. Reset PCR 16
    let reset_handles = PCRResetHandles {
        pcr_handle: Handle(16),
    };
    let reset_cmd = PCRReset {};
    execute_tpm_command(&mut tpm, &mut global_state, &reset_handles, &reset_cmd, &[]).unwrap();

    // Read counter again
    let (_, resp) = execute_tpm_command(&mut tpm, &mut global_state, &(), &read_cmd, &[]).unwrap();
    let after_reset_counter = resp.pcr_update_counter;
    assert_eq!(after_reset_counter, after_extend_counter + 1);
}

#[test]
fn test_pcr_update_counter_wrap_around() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    global_state.pcrs.update_counter = u32::MAX; // set to maximum value AFTER startup

    // Read counter
    let read_cmd = PCRRead {
        pcr_selection_in: TpmlPcrSelection::default(),
    };
    let (_, resp) = execute_tpm_command(&mut tpm, &mut global_state, &(), &read_cmd, &[]).unwrap();
    assert_eq!(resp.pcr_update_counter, u32::MAX);

    // Extend PCR 16 to trigger update_counter increment
    let extend_handles = PCRExtendHandles {
        pcr_handle: Handle(16),
    };
    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha1(&[0xdd; 20])).unwrap();
    let extend_cmd = PCRExtend { digests };
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &extend_handles,
        &extend_cmd,
        &[],
    )
    .unwrap();

    // Read counter again
    let (_, resp) = execute_tpm_command(&mut tpm, &mut global_state, &(), &read_cmd, &[]).unwrap();
    assert_eq!(resp.pcr_update_counter, 0);
}

#[test]
fn test_pcr_read_sort_order() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Build selection: SHA256 first, then SHA1.
    // Select PCR 0..6 (6 PCRs) for each.
    let mut pcr_selection_in = TpmlPcrSelection::default();
    // Add SHA256 bank first
    pcr_selection_in
        .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0x3F, 0x00, 0x00]).unwrap())
        .unwrap();
    // Add SHA1 bank second
    pcr_selection_in
        .add(&TpmsPcrSelection::new(TpmiAlgHash::Sha1, &[0x3F, 0x00, 0x00]).unwrap())
        .unwrap();

    let read_cmd = PCRRead { pcr_selection_in };
    let (_, resp) = execute_tpm_command(&mut tpm, &mut global_state, &(), &read_cmd, &[]).unwrap();

    // Total returned digests must be exactly 8 (the limit)
    assert_eq!(resp.pcr_values.count(), 8);

    // Since SHA1 (alg 0x0004) has lower ID than SHA256 (0x000B), it must be sorted first.
    // Therefore, the first 6 digests should be SHA1 (size 20), and the remaining 2 should be SHA256 (size 32).
    let digests = resp.pcr_values.digests();
    for (i, digest) in digests.iter().enumerate().take(6) {
        assert_eq!(digest.get_size(), 20, "Digest {} should be SHA1", i);
    }
    for (i, digest) in digests.iter().enumerate().take(8).skip(6) {
        assert_eq!(digest.get_size(), 32, "Digest {} should be SHA256", i);
    }
}
