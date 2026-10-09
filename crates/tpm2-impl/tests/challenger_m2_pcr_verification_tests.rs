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
use tpm2::errors::{Position, TpmRc};
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

fn execute_tpm_event<'a>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &PCREventHandles,
    cmd: &PCREvent,
    response_buf: &'a mut [u8],
) -> Result<<PCREvent<'static> as Command>::Response<'a>, u32> {
    let mut request_buf = [0u8; 16384];
    request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    request_buf[6..10].copy_from_slice(&(PCREvent::CMD_CODE.code()).to_be_bytes());

    let mut offset = 10;
    let mut handles_buf = [0u8; PCREventHandles::MAX_SIZE];
    let handles_len = handles.marshal(&mut handles_buf);
    request_buf[offset..offset + handles_len].copy_from_slice(&handles_buf.as_ref()[..handles_len]);
    offset += handles_len;

    // pcrHandle has the USER auth role, so C requires a session even for an empty authValue
    // (TPM_RC_AUTH_MISSING otherwise, SessionProcess.c CheckAuthNoSession). authSize = 9,
    // then an empty TPM_RS_PW session.
    let pw_area = hex!("00000009 40000009 0000 00 0000");
    request_buf[offset..offset + pw_area.len()].copy_from_slice(&pw_area);
    offset += pw_area.len();

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

    // Skip the parameterSize field of the TPM_ST_SESSIONS response.
    let mut param_slice: &'static [u8] = std::vec::Vec::leak(response_buf[14..].to_vec());
    Unmarshal::unmarshal(&mut param_slice).map_err(|_| TpmRc::FAILURE.get())
}

// Helper to compute HASH(old || new) using TestCryptoProvider
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

// 1. Correctness of PCR_Extend (matching SHA-1, SHA-256, SHA-384 mathematical output)
#[test]
fn test_pcr_extend_correctness() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let pcr_idx = 5usize;
    let initial_sha1 = global_state.pcrs.sha1[pcr_idx];
    let initial_sha256 = global_state.pcrs.sha256[pcr_idx];
    let initial_sha384 = global_state.pcrs.sha384[pcr_idx];

    let extend_val_sha1 = [0x11u8; 20];
    let extend_val_sha256 = [0x22u8; 32];
    let extend_val_sha384 = [0x33u8; 48];

    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha1(&extend_val_sha1)).unwrap();
    digests.add(&TpmtHa::Sha256(&extend_val_sha256)).unwrap();
    digests.add(&TpmtHa::Sha384(&extend_val_sha384)).unwrap();

    let handles = PCRExtendHandles {
        pcr_handle: Handle(pcr_idx as u32),
    };
    let cmd = PCRExtend { digests };

    // Execute PCR_Extend
    execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[pw()]).unwrap();

    // Verify digests extended correctly
    let expected_sha1 = compute_expected_extend(
        tpm.platform.crypto,
        TpmiAlgHash::Sha1,
        &initial_sha1,
        &extend_val_sha1,
    );
    let expected_sha256 = compute_expected_extend(
        tpm.platform.crypto,
        TpmiAlgHash::Sha256,
        &initial_sha256,
        &extend_val_sha256,
    );
    let expected_sha384 = compute_expected_extend(
        tpm.platform.crypto,
        TpmiAlgHash::Sha384,
        &initial_sha384,
        &extend_val_sha384,
    );

    assert_eq!(global_state.pcrs.sha1[pcr_idx], expected_sha1[..20]);
    assert_eq!(global_state.pcrs.sha256[pcr_idx], expected_sha256[..32]);
    // The default PCR allocation is SHA1+SHA256 only; like C PCRExtend (PCR.c), banks that
    // are not allocated (SHA384) are not extended.
    let _ = expected_sha384;
    assert_eq!(global_state.pcrs.sha384[pcr_idx], initial_sha384);

    // Verify update_counter incremented: C PCRExtend calls PCRChanged() once per allocated
    // bank that is extended (PCR.c:751), i.e. twice here (SHA1 and SHA256).
    assert_eq!(global_state.pcrs.update_counter, 2);
}

// 2. Correctness of PCR_Event (calculating event digest and extending it)
#[test]
fn test_pcr_event_correctness() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let pcr_idx = 10usize;
    let initial_sha1 = global_state.pcrs.sha1[pcr_idx];
    let initial_sha256 = global_state.pcrs.sha256[pcr_idx];
    let initial_sha384 = global_state.pcrs.sha384[pcr_idx];

    let event_bytes = b"Event message data";
    let event_data = Tpm2bEvent::from_bytes(event_bytes).unwrap();

    let handles = PCREventHandles {
        pcr_handle: Handle(pcr_idx as u32),
    };
    let cmd = PCREvent { event_data };

    // Execute PCR_Event
    let mut response_buf = [0u8; 16384];
    let resp = execute_tpm_event(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &mut response_buf,
    )
    .unwrap();

    // Verify event digests computed by PCR_Event
    let mut out1 = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    let computed_sha1 = tpm2::crypto::hash(
        tpm.platform.crypto,
        TpmiAlgHash::Sha1,
        event_bytes,
        &mut out1,
    )
    .unwrap()
    .digest();
    let mut out2 = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    let computed_sha256 = tpm2::crypto::hash(
        tpm.platform.crypto,
        TpmiAlgHash::Sha256,
        event_bytes,
        &mut out2,
    )
    .unwrap()
    .digest();
    let mut out3 = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    let computed_sha384 = tpm2::crypto::hash(
        tpm.platform.crypto,
        TpmiAlgHash::Sha384,
        event_bytes,
        &mut out3,
    )
    .unwrap()
    .digest();

    let mut found_sha1 = false;
    let mut found_sha256 = false;
    let mut found_sha384 = false;

    for digest in resp.digests.digests() {
        match *digest {
            TpmtHa::Sha1(val) => {
                assert_eq!(val, computed_sha1);
                found_sha1 = true;
            }
            TpmtHa::Sha256(val) => {
                assert_eq!(val, computed_sha256);
                found_sha256 = true;
            }
            TpmtHa::Sha384(val) => {
                assert_eq!(val, computed_sha384);
                found_sha384 = true;
            }
            // C PCR_Event returns a digest for every implemented hash (HASH_COUNT),
            // PCR_Event.c, which includes SHA512.
            TpmtHa::Sha512(val) => assert_eq!(val.len(), 64),
            _ => panic!("Unexpected digest algorithm in event response"),
        }
    }
    assert!(found_sha1 && found_sha256 && found_sha384);

    // Verify PCR extended correctly with computed event digests
    let expected_sha1 = compute_expected_extend(
        tpm.platform.crypto,
        TpmiAlgHash::Sha1,
        &initial_sha1,
        computed_sha1,
    );
    let expected_sha256 = compute_expected_extend(
        tpm.platform.crypto,
        TpmiAlgHash::Sha256,
        &initial_sha256,
        computed_sha256,
    );
    let expected_sha384 = compute_expected_extend(
        tpm.platform.crypto,
        TpmiAlgHash::Sha384,
        &initial_sha384,
        computed_sha384,
    );

    assert_eq!(global_state.pcrs.sha1[pcr_idx], expected_sha1[..20]);
    assert_eq!(global_state.pcrs.sha256[pcr_idx], expected_sha256[..32]);
    // The default PCR allocation is SHA1+SHA256 only; like C PCRExtend (PCR.c), banks that
    // are not allocated (SHA384) are not extended.
    let _ = expected_sha384;
    assert_eq!(global_state.pcrs.sha384[pcr_idx], initial_sha384);

    // Test with RHNull handle: shouldn't extend PCR but should return digests
    let null_handles = PCREventHandles {
        pcr_handle: Handle::RH_NULL,
    };
    let initial_pcr_null_sha1 = global_state.pcrs.sha1[pcr_idx];
    let mut response_buf_null = [0u8; 4096];
    let resp_null = execute_tpm_event(
        &mut tpm,
        &mut global_state,
        &null_handles,
        &cmd,
        &mut response_buf_null,
    )
    .unwrap();
    // Digests are still returned (one per implemented hash: SHA1/256/384/512)
    assert_eq!(resp_null.digests.count(), 4);
    // But PCR state did not change
    assert_eq!(global_state.pcrs.sha1[pcr_idx], initial_pcr_null_sha1);
}

// 3. Correctness of PCR_Reset
#[test]
fn test_pcr_reset_correctness() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Extend non-zero values into PCR 16 and PCR 23
    let extend_val_sha1 = [0x55u8; 20];
    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha1(&extend_val_sha1)).unwrap();

    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &PCRExtendHandles {
            pcr_handle: Handle(16),
        },
        &PCRExtend { digests },
        &[pw()],
    )
    .unwrap();
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &PCRExtendHandles {
            pcr_handle: Handle(23),
        },
        &PCRExtend { digests },
        &[pw()],
    )
    .unwrap();

    assert_ne!(global_state.pcrs.sha1[16], [0u8; 20]);
    assert_ne!(global_state.pcrs.sha1[23], [0u8; 20]);

    // Reset PCR 16
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &PCRResetHandles {
            pcr_handle: Handle(16),
        },
        &PCRReset {},
        &[pw()],
    )
    .unwrap();
    assert_eq!(global_state.pcrs.sha1[16], [0u8; 20]);
    assert_eq!(global_state.pcrs.sha256[16], [0u8; 32]);
    assert_eq!(global_state.pcrs.sha384[16], [0u8; 48]);

    // Reset PCR 23
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &PCRResetHandles {
            pcr_handle: Handle(23),
        },
        &PCRReset {},
        &[pw()],
    )
    .unwrap();
    assert_eq!(global_state.pcrs.sha1[23], [0u8; 20]);
    assert_eq!(global_state.pcrs.sha256[23], [0u8; 32]);
    assert_eq!(global_state.pcrs.sha384[23], [0u8; 48]);

    // PCR 0 cannot be reset -> should fail with TpmRc::LOCALITY (0x907)
    let res_pcr0 = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &PCRResetHandles {
            pcr_handle: Handle(0),
        },
        &PCRReset {},
        &[pw()],
    );
    assert_eq!(res_pcr0.err(), Some(TpmRc::LOCALITY.get()));

    // PCR 17 (DRTM) cannot be reset via PCR_Reset -> should fail with TpmRc::LOCALITY (0x907)
    let res_pcr17 = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &PCRResetHandles {
            pcr_handle: Handle(17),
        },
        &PCRReset {},
        &[pw()],
    );
    assert_eq!(res_pcr17.err(), Some(TpmRc::LOCALITY.get()));
}

// 4. Bounds validation for PCR handles
#[test]
fn test_pcr_bounds_validation() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let invalid_pcr_handle = Handle(24);

    // PCR_Extend on handle 24 -> Value error (0x84)
    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha1(&[0xaa; 20])).unwrap();
    let res_extend = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &PCRExtendHandles {
            pcr_handle: invalid_pcr_handle,
        },
        &PCRExtend { digests },
        &[],
    );
    assert_eq!(
        res_extend.err(),
        Some(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)).get())
    );

    // PCR_Event on handle 24 -> Value error (0x184)
    let event_data = Tpm2bEvent::from_bytes(b"event").unwrap();
    let mut response_buf = [0u8; 16384];
    let res_event = execute_tpm_event(
        &mut tpm,
        &mut global_state,
        &PCREventHandles {
            pcr_handle: invalid_pcr_handle,
        },
        &PCREvent { event_data },
        &mut response_buf,
    );
    assert_eq!(
        res_event.err(),
        Some(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)).get())
    );

    // PCR_Reset on handle 24 -> Value error (0x184) since handle is out of bounds
    let res_reset = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &PCRResetHandles {
            pcr_handle: invalid_pcr_handle,
        },
        &PCRReset {},
        &[],
    );
    assert_eq!(
        res_reset.err(),
        Some(TpmRc::VALUE.with(tpm2::errors::Position::handle(1)).get())
    );
}

// 5. PCR_Read constraints
#[test]
fn test_pcr_read_constraints() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // A. Read empty selection (no banks selected)
    let read_empty = PCRRead {
        pcr_selection_in: TpmlPcrSelection::from_slice(&[]).unwrap(),
    };
    let (_, resp_empty) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &read_empty, &[]).unwrap();
    assert_eq!(resp_empty.pcr_selection_out.count(), 0);
    assert_eq!(resp_empty.pcr_values.count(), 0);

    // B. Read small selection (e.g. SHA-256 bank PCR 0)
    let read_small = PCRRead {
        pcr_selection_in: TpmlPcrSelection::from_slice(&[
            TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0x01, 0x00, 0x00]).unwrap(), // PCR 0
        ])
        .unwrap(),
    };
    let (_, resp_small) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &read_small, &[]).unwrap();
    assert_eq!(resp_small.pcr_selection_out.count(), 1);
    assert_eq!(resp_small.pcr_values.count(), 1);
    assert_eq!(
        resp_small.pcr_values.digests()[0].get_buffer(),
        &global_state.pcrs.sha256[0]
    );

    // C. Limit of returned digests:
    // If we request 9 PCRs (e.g. PCR 0..8), the implementation returns success but truncates
    // the returned digests to 8, updating the selection out mask to match.
    let read_nine = PCRRead {
        pcr_selection_in: TpmlPcrSelection::from_slice(&[
            TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0xff, 0x01, 0x00]).unwrap(), // PCR 0..8 (9 PCRs)
        ])
        .unwrap(),
    };
    let (_, resp_nine) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &read_nine, &[]).unwrap();
    assert_eq!(resp_nine.pcr_values.count(), 8);
    assert_eq!(resp_nine.pcr_selection_out.count(), 1);
    assert_eq!(
        resp_nine
            .pcr_selection_out
            .pcr_selections()
            .next()
            .unwrap()
            .pcr_select(),
        &[0xff, 0x00, 0x00] // bit for PCR 8 is cleared!
    );

    // D. Read all selections: what happens if we select all SHA-256 PCRs (24 PCRs)?
    let read_all = PCRRead {
        pcr_selection_in: TpmlPcrSelection::from_slice(&[
            TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0xff, 0xff, 0xff]).unwrap(), // All 24 PCRs
        ])
        .unwrap(),
    };
    let (_, resp_all) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &read_all, &[]).unwrap();
    assert_eq!(resp_all.pcr_values.count(), 8);
    assert_eq!(resp_all.pcr_selection_out.count(), 1);
    assert_eq!(
        resp_all
            .pcr_selection_out
            .pcr_selections()
            .next()
            .unwrap()
            .pcr_select(),
        &[0xff, 0x00, 0x00] // bit for PCR 8..23 are cleared!
    );
}

// 6. PCRExtend unsupported banks are ignored and command succeeds
#[test]
fn test_pcr_extend_unsupported_bank() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let pcr_idx = 5usize;
    let initial_sha256 = global_state.pcrs.sha256[pcr_idx];

    let extend_val_sha256 = [0x22u8; 32];
    let extend_val_sha512 = [0x55u8; 64]; // unsupported bank

    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha256(&extend_val_sha256)).unwrap();
    digests.add(&TpmtHa::Sha512(&extend_val_sha512)).unwrap(); // Add unsupported bank digest

    let handles = PCRExtendHandles {
        pcr_handle: Handle(pcr_idx as u32),
    };
    let cmd = PCRExtend { digests };

    // Execute PCR_Extend: should succeed and NOT return TpmRc::HASH (or any other error)
    execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[pw()]).unwrap();

    // Verify SHA-256 extended correctly
    let expected_sha256 = compute_expected_extend(
        tpm.platform.crypto,
        TpmiAlgHash::Sha256,
        &initial_sha256,
        &extend_val_sha256,
    );
    assert_eq!(global_state.pcrs.sha256[pcr_idx], expected_sha256[..32]);
}

// 7. PCR locality validation for extend, event, and reset
#[test]
fn test_pcr_locality_enforcement() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Test 1: PCRExtend on PCR 21 (extend locality is 2 only)
    let extend_val_sha256 = [0x22u8; 32];
    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha256(&extend_val_sha256)).unwrap();
    let extend_cmd = PCRExtend { digests };
    let extend_handles = PCRExtendHandles {
        pcr_handle: Handle(21),
    };

    // At locality 0: should fail with TpmRc::LOCALITY (0x907)
    global_state.locality = 0;
    let res_extend_loc0 = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &extend_handles,
        &extend_cmd,
        &[pw()],
    );
    assert_eq!(res_extend_loc0.err(), Some(TpmRc::LOCALITY.get()));

    // At locality 2: should succeed
    global_state.locality = 2;
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &extend_handles,
        &extend_cmd,
        &[pw()],
    )
    .unwrap();

    // Test 2: PCREvent on PCR 21 (extend locality is 2 only)
    let event_data = Tpm2bEvent::from_bytes(b"event").unwrap();
    let event_cmd = PCREvent { event_data };
    let event_handles = PCREventHandles {
        pcr_handle: Handle(21),
    };

    // At locality 0: should fail with TpmRc::LOCALITY
    global_state.locality = 0;
    let mut response_buf = [0u8; 16384];
    let res_event_loc0 = execute_tpm_event(
        &mut tpm,
        &mut global_state,
        &event_handles,
        &event_cmd,
        &mut response_buf,
    );
    assert_eq!(res_event_loc0.err(), Some(TpmRc::LOCALITY.get()));

    // At locality 2: should succeed
    global_state.locality = 2;
    let mut response_buf = [0u8; 16384];
    execute_tpm_event(
        &mut tpm,
        &mut global_state,
        &event_handles,
        &event_cmd,
        &mut response_buf,
    )
    .unwrap();

    // Test 3: PCRReset on PCR 16 (reset locality is 0..3)
    let reset_cmd = PCRReset {};
    let reset_handles_16 = PCRResetHandles {
        pcr_handle: Handle(16),
    };

    // At locality 4: should fail with TpmRc::LOCALITY
    global_state.locality = 4;
    let res_reset_loc4 = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &reset_handles_16,
        &reset_cmd,
        &[pw()],
    );
    assert_eq!(res_reset_loc4.err(), Some(TpmRc::LOCALITY.get()));

    // At locality 0: should succeed
    global_state.locality = 0;
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &reset_handles_16,
        &reset_cmd,
        &[pw()],
    )
    .unwrap();
}

// 8. Stress/Adversarial tests for PCRRead
#[test]
fn test_pcr_read_extreme_banks() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // A. Count exceeding TPM2_NUM_PCR_BANKS (HASH_COUNT = 8, so count = 9 and count = 17)
    let req_count_9 = hex!(
        "8001 00000044 0000017e 00000009 000b03010000 000b03010000 000b03010000 000b03010000 000b03010000 000b03010000 000b03010000 000b03010000 000b03010000"
    );
    let mut resp = [0u8; 256];
    let size = tpm.execute_command_separate(&mut global_state, &req_count_9[..], &mut resp[..]);
    assert_eq!(size, 10);
    let rc = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    assert_eq!(
        rc,
        TpmRc::SIZE.with(tpm2::errors::Position::parameter(1)).get()
    );

    let req_count_17 = hex!(
        "8001 00000074 0000017e 00000011 000b03010000 000b03010000 000b03010000 000b03010000 000b03010000 000b03010000 000b03010000 000b03010000 000b03010000 000b03010000 000b03010000 000b03010000 000b03010000 000b03010000 000b03010000 000b03010000 000b03010000"
    );
    let mut resp = [0u8; 256];
    let size = tpm.execute_command_separate(&mut global_state, &req_count_17[..], &mut resp[..]);
    println!("req_count_17 size = {}, resp = {:?}", size, &resp[..size]);
    let rc = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    assert_eq!(
        rc,
        TpmRc::SIZE.with(tpm2::errors::Position::parameter(1)).get()
    );

    // B. sizeof_select = 5 (greater than TPM2_PCR_SELECT_MAX = 4)
    let req_sizeof_5 = hex!("8001 00000016 0000017e 00000001 000b 05 0100000000");
    let mut resp = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &req_sizeof_5[..], &mut resp[..]);
    let rc = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    assert_eq!(
        rc,
        TpmRc::VALUE
            .with(tpm2::errors::Position::parameter(1))
            .get()
    );

    // C. Requesting more digests than max limit (8) across multiple banks.
    // Bank 1 (SHA-256): select 6 PCRs (0..5)
    // Bank 2 (SHA-1): select 6 PCRs (0..5)
    // Total requested: 12. Only 8 should be returned.
    // (Bank 2 uses SHA-1 because the default allocation is SHA1+SHA256 and, like C
    // PCRRead/FilterPcr, unallocated banks such as SHA-384 return no digests.)
    // The response should have the first 8 digests (Bank 1 PCR 0..5, Bank 2 PCR 0..1),
    // and the selection out should reflect exactly which PCRs were read.
    let read_multi = PCRRead {
        pcr_selection_in: TpmlPcrSelection::from_slice(&[
            TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0x3f, 0x00, 0x00]).unwrap(), // 6 PCRs
            TpmsPcrSelection::new(TpmiAlgHash::Sha1, &[0x3f, 0x00, 0x00]).unwrap(),   // 6 PCRs
        ])
        .unwrap(),
    };
    let (_, resp_multi) =
        execute_tpm_command(&mut tpm, &mut global_state, &(), &read_multi, &[]).unwrap();
    // Verify total digests returned is exactly 8
    assert_eq!(resp_multi.pcr_values.count(), 8);
    // Selection out count should be 2 (both banks had some PCRs read)
    assert_eq!(resp_multi.pcr_selection_out.count(), 2);
    // Bank 1 (SHA-256) selection out should have all 6 PCRs read
    assert_eq!(
        resp_multi
            .pcr_selection_out
            .pcr_selections()
            .next()
            .unwrap()
            .hash(),
        TpmiAlgHash::Sha256
    );
    assert_eq!(
        resp_multi
            .pcr_selection_out
            .pcr_selections()
            .next()
            .unwrap()
            .pcr_select(),
        &[0x3f, 0x00, 0x00]
    );
    // Bank 2 (SHA-1) selection out should have only 2 PCRs read (PCR 0 and 1)
    assert_eq!(
        resp_multi
            .pcr_selection_out
            .pcr_selections()
            .nth(1)
            .unwrap()
            .hash(),
        TpmiAlgHash::Sha1
    );
    assert_eq!(
        resp_multi
            .pcr_selection_out
            .pcr_selections()
            .nth(1)
            .unwrap()
            .pcr_select(),
        &[0x03, 0x00, 0x00]
    );
}

// 9. Stress/Adversarial tests for PCRExtend invalid banks
#[test]
fn test_pcr_extend_invalid_banks() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Send invalid hash algorithm ID 0xFFFF
    // C checks authorization (CheckAuthNoSession -> AUTH_MISSING) before unmarshaling the
    // parameters, so send an empty password session for pcrHandle.
    let req_invalid_hash =
        hex!("8002 00000022 00000182 00000005 00000009 40000009 0000 00 0000 00000001 ffff 00");
    let mut resp = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &req_invalid_hash[..], &mut resp[..]);
    let rc = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    assert_eq!(rc, TpmRc::HASH.with(Position::parameter(1)).get());
}

// 10. Stress/Adversarial tests for locality enforcement
#[test]
fn test_pcr_locality_unauthorized() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // PCR 16 Reset: reset mask allows 0..3, so locality 4 is unauthorized.
    // Locality 5 (unauthorized as locality > 4)
    let reset_cmd = PCRReset {};
    let reset_handles_16 = PCRResetHandles {
        pcr_handle: Handle(16),
    };

    global_state.locality = 5;
    let res_reset_loc5 = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &reset_handles_16,
        &reset_cmd,
        &[pw()],
    );
    assert_eq!(res_reset_loc5.err(), Some(TpmRc::LOCALITY.get()));

    // PCR 21 Extend: extend mask allows 2 only. Locality 3 is unauthorized.
    let extend_val_sha256 = [0x22u8; 32];
    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha256(&extend_val_sha256)).unwrap();
    let extend_cmd = PCRExtend { digests };
    let extend_handles_21 = PCRExtendHandles {
        pcr_handle: Handle(21),
    };

    global_state.locality = 3;
    let res_extend_loc3 = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &extend_handles_21,
        &extend_cmd,
        &[pw()],
    );
    assert_eq!(res_extend_loc3.err(), Some(TpmRc::LOCALITY.get()));

    global_state.locality = 5;
    let res_extend_loc5 = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &extend_handles_21,
        &extend_cmd,
        &[pw()],
    );
    assert_eq!(res_extend_loc5.err(), Some(TpmRc::LOCALITY.get()));
}
