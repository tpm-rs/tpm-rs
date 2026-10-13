//! PCR commands with PCR handles beyond PCR_LAST.

use crate::_common::{
    ALG_SHA1, CC_PCR_EXTEND, CC_PCR_RESET, ST_NO_SESSIONS, build_raw_cmd as build_cmd,
    digest_values, execute_tpm_command_at_locality0 as execute_tpm_command,
    pcr_event_at_digests as pcr_event_at, pw, send_with_rc as send,
};
use testing::tpm::Tpm;
use tpm2::commands::*;
use tpm2::errors::{Position, TpmRc};
use tpm2::*;

// 4. Bounds validation for PCR handles
/// PCR_Extend/Event/Reset on handle 24 fail with VALUE+H1.
#[test]
fn pcr_24_rejected_by_extend_event_reset() {
    let mut sim = Tpm::new();

    let invalid_pcr_handle = 24u32;
    let value_h1 = TpmRc::VALUE.with(Position::handle(1)).get();

    // PCR_Extend on handle 24 (no sessions) -> Value error (0x184)
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_PCR_EXTEND,
        &[invalid_pcr_handle],
        None,
        &digest_values(&[(ALG_SHA1, vec![0xaa; 20])]),
    );
    assert_eq!(send(&mut sim, &cmd).0, value_h1);

    // PCR_Event on handle 24 -> Value error (0x184)
    let (rc, _) = pcr_event_at(&mut sim, 0, invalid_pcr_handle, b"event");
    assert_eq!(rc, value_h1);

    // PCR_Reset on handle 24 (no sessions) -> Value error (0x184) since handle is out of bounds
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_PCR_RESET,
        &[invalid_pcr_handle],
        None,
        &[],
    );
    assert_eq!(send(&mut sim, &cmd).0, value_h1);
}

/// PCR_Extend/Event/Reset on PCR 24 with password sessions fail with VALUE+H1.
#[test]
fn pcr_24_rejected_with_sessions() {
    let mut sim = Tpm::new();

    // 1. Extend on PCR 24
    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha1(&[0xcc; 20])).unwrap();
    let extend_cmd = PCRExtend {
        pcr_handle: Handle(24),
        digests,
    };
    let res = execute_tpm_command(&mut sim, &extend_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::handle(1)).get())
    );

    // 2. Event on PCR 24
    let event_cmd = PCREvent {
        pcr_handle: Handle(24),
        event_data: Tpm2bEvent::from_bytes(b"test").unwrap(),
    };
    let res = execute_tpm_command(&mut sim, &event_cmd, &[pw()]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::handle(1)).get())
    );

    // 3. Reset on PCR 24
    let reset_cmd = PCRReset {
        pcr_handle: Handle(24),
    };
    let res = execute_tpm_command(&mut sim, &reset_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::handle(1)).get())
    );
}
