//! Locality restrictions of PCR extend and reset.

use crate::_common::{
    ALG_SHA256, execute_at, pcr_event_at_digests as pcr_event_at,
    pcr_extend_at_no_continue as pcr_extend_at, pcr_reset_at_no_continue as pcr_reset_at, pw,
};
use tpm2::commands::*;
use tpm2::errors::TpmRc;
use tpm2::*;
use tpm2_simulator::create_simulator;

/// PCR 17 extend only at localities 2-4; PCR 16 reset fails at locality 4 and works at 0.
#[test]
fn drtm_extend_and_resettable_reset_localities() {
    let mut sim = create_simulator!();

    // 1. Extend PCR 17 at locality 0 (should fail, 17 expects 2, 3, 4)
    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha1(&[0xbb; 20])).unwrap();
    let extend_cmd = PCRExtend {
        pcr_handle: Handle(17),
        digests,
    };
    let res = execute_at(&mut sim, 0, &extend_cmd, &[pw()]);
    assert_eq!(res.err(), Some(TpmRc::LOCALITY.get()));

    // 2. Extend PCR 17 at locality 3 (should succeed)
    let res = execute_at(&mut sim, 3, &extend_cmd, &[pw()]);
    assert!(res.is_ok());

    // 3. Reset PCR 16 at locality 4 (should fail, 16 expects 0, 1, 2, 3)
    let reset_cmd = PCRReset {
        pcr_handle: Handle(16),
    };
    let res = execute_at(&mut sim, 4, &reset_cmd, &[pw()]);
    assert_eq!(res.err(), Some(TpmRc::LOCALITY.get()));

    // 4. Reset PCR 16 at locality 0 (should succeed)
    let res = execute_at(&mut sim, 0, &reset_cmd, &[pw()]);
    assert!(res.is_ok());
}

// 7. PCR locality validation for extend, event, and reset
/// PCR 21 extend/event only at locality 2 and reset locality checks.
#[test]
fn extend_event_reset_locality_masks() {
    let mut sim = create_simulator!();

    // Test 1: PCRExtend on PCR 21 (extend locality is 2 only)
    let digests = [(ALG_SHA256, vec![0x22u8; 32])];

    // At locality 0: should fail with TpmRc::LOCALITY (0x907)
    assert_eq!(
        pcr_extend_at(&mut sim, 0, 21, &digests),
        TpmRc::LOCALITY.get()
    );

    // At locality 2: should succeed
    assert_eq!(pcr_extend_at(&mut sim, 2, 21, &digests), 0);

    // Test 2: PCREvent on PCR 21 (extend locality is 2 only)
    // At locality 0: should fail with TpmRc::LOCALITY
    let (rc, _) = pcr_event_at(&mut sim, 0, 21, b"event");
    assert_eq!(rc, TpmRc::LOCALITY.get());

    // At locality 2: should succeed
    let (rc, _) = pcr_event_at(&mut sim, 2, 21, b"event");
    assert_eq!(rc, 0);

    // Test 3: PCRReset on PCR 16 (reset locality is 0..3)
    // At locality 4: should fail with TpmRc::LOCALITY
    assert_eq!(pcr_reset_at(&mut sim, 4, 16), TpmRc::LOCALITY.get());

    // At locality 0: should succeed
    assert_eq!(pcr_reset_at(&mut sim, 0, 16), 0);
}

// 10. Stress/Adversarial tests for locality enforcement
/// PCR 16 reset at locality 4/5 and PCR 21 extend at locality 3 fail with LOCALITY.
#[test]
fn reset_and_extend_from_unauthorized_locality() {
    let mut sim = create_simulator!();

    // PCR 16 Reset: reset mask allows 0..3, so locality 4 is unauthorized.
    // Locality 5 (unauthorized as locality > 4)
    assert_eq!(pcr_reset_at(&mut sim, 5, 16), TpmRc::LOCALITY.get());

    // PCR 21 Extend: extend mask allows 2 only. Locality 3 is unauthorized.
    let digests = [(ALG_SHA256, vec![0x22u8; 32])];
    assert_eq!(
        pcr_extend_at(&mut sim, 3, 21, &digests),
        TpmRc::LOCALITY.get()
    );
    assert_eq!(
        pcr_extend_at(&mut sim, 5, 21, &digests),
        TpmRc::LOCALITY.get()
    );
}
