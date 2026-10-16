//! `Tpm::reset` (the per-input reset of the differential fuzzer): a reset
//! TPM gives byte-identical responses to a new TPM with the same seed, for
//! `TPM2_GetRandom`, `TPM2_CreatePrimary` (ECC NIST P-256 and RSA 2048, whose
//! primary seeds and proofs come from the random number generator at
//! manufacture) and `TPM2_ReadClock`. With the `differential` feature, the C
//! references are re-initialized in place (`Request::Reinit`) and every
//! response is compared with theirs, so this also checks that no reference
//! keeps state (random number generation, clock, NV, loaded objects) across
//! a re-initialization.

use std::time::Duration;

use crate::_common::{build_cmd, build_pw_cmd, get_ecc_srk_template, get_rsa_srk_template, pw};
use testing::seed::ReferenceSeed;
use testing::tpm::{Tpm, sleep};
use tpm2::commands::CreatePrimary;
use tpm2::{Handle, Tpm2b, Tpm2bAuth, Tpm2bSensitiveData, TpmsSensitiveCreate, TpmtPublic};

/// `TPM2_GetRandom(32)`.
const GET_RANDOM_32: [u8; 12] = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x7B, 0, 32];

/// `TPM2_ReadClock`.
const READ_CLOCK: [u8; 10] = [0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x81];

/// `TPM_CC_HierarchyChangeAuth`.
const TPM_CC_HIERARCHY_CHANGE_AUTH: u32 = 0x0000_0129;

/// A raw `TPM2_CreatePrimary` of `public` under `hierarchy` with empty
/// authorization values.
fn create_primary(hierarchy: Handle, public: TpmtPublic<'static>) -> Vec<u8> {
    let cmd = CreatePrimary {
        primary_handle: hierarchy,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(public),
        ..Default::default()
    };
    build_cmd(&cmd, &[pw()])
}

/// Sends `command` and checks that it succeeded; returns the response.
fn send_ok(tpm: &mut Tpm, command: &[u8]) -> Vec<u8> {
    let rsp = tpm.send_command(0, command);
    assert_eq!(
        rsp.get(6..10),
        Some(&[0, 0, 0, 0][..]),
        "failed: {rsp:02x?}"
    );
    rsp
}

/// The commands whose responses must repeat after a reset, and their
/// responses: random bytes, an ECC P-256 and an RSA 2048 primary key, more
/// random bytes and the clock.
fn conversation(tpm: &mut Tpm) -> Vec<Vec<u8>> {
    [
        GET_RANDOM_32.to_vec(),
        create_primary(Handle::RH_OWNER, get_ecc_srk_template()),
        create_primary(Handle::RH_ENDORSEMENT, get_rsa_srk_template()),
        GET_RANDOM_32.to_vec(),
        READ_CLOCK.to_vec(),
    ]
    .iter()
    .map(|command| send_ok(tpm, command))
    .collect()
}

/// Changes the TPM's state beyond what [`conversation`] does: moves the
/// clock, draws random bytes, loads another primary key and sets an owner
/// authorization value (after which [`conversation`]'s empty owner
/// authorization would fail).
fn change_state(tpm: &mut Tpm) {
    sleep(Duration::from_millis(2500));
    send_ok(tpm, &GET_RANDOM_32);
    send_ok(
        tpm,
        &create_primary(Handle::RH_OWNER, get_ecc_srk_template()),
    );
    let new_auth = [0, 4, b'a', b'u', b't', b'h'];
    send_ok(
        tpm,
        &build_pw_cmd(
            TPM_CC_HIERARCHY_CHANGE_AUTH,
            &[Handle::RH_OWNER.0],
            1,
            &new_auth,
        ),
    );
}

/// After a reset, a TPM repeats the responses of a new TPM with the same
/// seed, however its state was changed before the reset.
#[test]
fn reset_tpm_repeats_the_responses_of_a_new_tpm() {
    let seed = ReferenceSeed::choose();
    let fresh = conversation(&mut Tpm::with_seed(seed));

    let mut tpm = Tpm::with_seed(seed);
    assert_eq!(tpm.seed(), seed);
    assert_eq!(conversation(&mut tpm), fresh, "the same seed repeats");
    change_state(&mut tpm);
    tpm.reset();
    assert_eq!(conversation(&mut tpm), fresh, "after the first reset");
}

/// Repeated resets keep repeating the same responses, including resets of a
/// TPM that was not used since its last reset.
#[test]
fn repeated_resets_repeat_the_same_responses() {
    let seed = ReferenceSeed::choose();
    let mut tpm = Tpm::with_seed(seed);
    let first = conversation(&mut tpm);
    for round in 0..3 {
        change_state(&mut tpm);
        tpm.reset();
        tpm.reset();
        assert_eq!(conversation(&mut tpm), first, "after reset round {round}");
    }
}

/// `try_exchange` returns the `tpm-rs` response of a command every TPM
/// agrees on, exactly like `send_command`.
#[test]
fn try_exchange_returns_the_response() {
    let seed = ReferenceSeed::choose();
    let mut a = Tpm::with_seed(seed);
    let mut b = Tpm::with_seed(seed);
    let rsp = a.try_exchange(0, &GET_RANDOM_32).unwrap();
    assert_eq!(rsp, b.send_command(0, &GET_RANDOM_32));
    assert_eq!(rsp.len(), 12 + 32);
}

/// A `Tpm` mirrored to the in-process C references (`fuzz-inproc`) repeats
/// the responses of one mirrored to reference processes, before and after
/// resets. The only test creating an in-process-mirrored `Tpm` (at most one
/// may be alive per process).
#[cfg(feature = "fuzz-inproc")]
#[test]
fn in_process_mirror_repeats_the_responses_of_reference_processes() {
    let seed = ReferenceSeed::choose();
    let fresh = conversation(&mut Tpm::with_seed(seed));
    let mut tpm = Tpm::with_seed_in_process(seed);
    assert_eq!(conversation(&mut tpm), fresh);
    for round in 0..2 {
        change_state(&mut tpm);
        tpm.reset();
        assert_eq!(conversation(&mut tpm), fresh, "after reset round {round}");
    }
}
