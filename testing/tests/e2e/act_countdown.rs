//! Authenticated Countdown Timers (TPM 2.0 Part 1, "Authenticated Countdown Timer (ACT)"): the
//! once-per-second countdown on the virtual clock, the `signaled` attribute (the four cases of
//! TPM2_ACT_SetTimeout and `startTimeout` `0xFFFFFFFF`), and what TPM2_Shutdown(TPM_SU_STATE),
//! TPM Reset, TPM Restart and TPM Resume do to the timeouts, `signaled` and `preserveSignaled`.

use crate::_common::{
    SimulatorPlatformSignal, TPM_SU_CLEAR, TPM_SU_STATE, act_set_timeout, act_state,
    implemented_act_handles, nv_on, power_cycle_with, rc_p, shutdown_raw, sleep, startup_raw,
};
use std::time::Duration;
use testing::tpm::Tpm;
use tpm2::errors::TpmRc;

/// `TPM_RH_ACT_0`.
const ACT_0: u32 = 0x4000_0110;
/// `TPMA_ACT.signaled`.
const SIGNALED: u32 = 1;
/// `TPMA_ACT.preserveSignaled`.
const PRESERVE_SIGNALED: u32 = 2;

/// Advances the virtual clock by `seconds` ACT ticks.
fn ticks(seconds: u64) {
    sleep(Duration::from_secs(seconds));
}

/// A TPM Resume: TPM2_Shutdown(TPM_SU_STATE), power cycle, TPM2_Startup(TPM_SU_STATE).
fn resume(sim: &mut Tpm) {
    assert_eq!(power_cycle_with(sim, Some(TPM_SU_STATE), TPM_SU_STATE), 0);
}

/// A TPM Restart: TPM2_Shutdown(TPM_SU_STATE), power cycle, TPM2_Startup(TPM_SU_CLEAR).
fn restart(sim: &mut Tpm) {
    assert_eq!(power_cycle_with(sim, Some(TPM_SU_STATE), TPM_SU_CLEAR), 0);
}

/// After TPM2_Startup every implemented ACT is zero and has not signaled.
#[test]
fn acts_start_zero_and_unsignaled() {
    let mut sim = Tpm::new();
    for act in implemented_act_handles() {
        assert_eq!(act_state(&mut sim, act), (0, 0), "ACT {act:#x}");
    }
    // Ticks do not change a zero timeout.
    ticks(5);
    assert_eq!(act_state(&mut sim, ACT_0), (0, 0));
}

/// The new timeout is pending (and reported) until the next tick, which applies it and counts it
/// down in the same tick; the ACT then counts down once per second and SETs `signaled` when it
/// reaches zero, and stays there.
#[test]
fn timeout_counts_down_once_per_second_and_signals_at_zero() {
    let mut sim = Tpm::new();
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 3), 0);
    assert_eq!(act_state(&mut sim, ACT_0), (3, 0));
    sleep(Duration::from_millis(999));
    assert_eq!(act_state(&mut sim, ACT_0), (3, 0));
    sleep(Duration::from_millis(1));
    assert_eq!(act_state(&mut sim, ACT_0), (2, 0));
    ticks(1);
    assert_eq!(act_state(&mut sim, ACT_0), (1, 0));
    ticks(1);
    assert_eq!(act_state(&mut sim, ACT_0), (0, SIGNALED));
    ticks(10);
    assert_eq!(act_state(&mut sim, ACT_0), (0, SIGNALED));
}

/// Several ticks between two commands are all processed, and a long countdown expires after
/// exactly its timeout.
#[test]
fn elapsed_ticks_are_caught_up() {
    let mut sim = Tpm::new();
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 3600), 0);
    sleep(Duration::from_millis(1500));
    assert_eq!(act_state(&mut sim, ACT_0), (3599, 0));
    ticks(3598);
    assert_eq!(act_state(&mut sim, ACT_0), (1, 0));
    sleep(Duration::from_millis(500));
    assert_eq!(act_state(&mut sim, ACT_0), (0, SIGNALED));
}

/// A `startTimeout` of 1 is applied and counted down to zero by the first tick: the ACT signals
/// one second after the command.
#[test]
fn start_timeout_one_signals_at_the_first_tick() {
    let mut sim = Tpm::new();
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 1), 0);
    assert_eq!(act_state(&mut sim, ACT_0), (1, 0));
    ticks(1);
    assert_eq!(act_state(&mut sim, ACT_0), (0, SIGNALED));
}

/// Part 3, TPM2_ACT_SetTimeout, the four cases: ACT Timeout zero or non-zero, `startTimeout` zero
/// or non-zero.
#[test]
fn signaled_follows_the_four_set_timeout_cases() {
    let mut sim = Tpm::new();
    // Make the ACT signal: timeout zero, signaled SET.
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 1), 0);
    ticks(1);
    assert_eq!(act_state(&mut sim, ACT_0), (0, SIGNALED));

    // 3) ACT Timeout zero, startTimeout zero: signaled unchanged.
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 0), 0);
    ticks(1);
    assert_eq!(act_state(&mut sim, ACT_0), (0, SIGNALED));

    // 1) ACT Timeout zero, startTimeout non-zero: signaled CLEAR.
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 10), 0);
    ticks(1);
    assert_eq!(act_state(&mut sim, ACT_0), (9, 0));

    // 2) ACT Timeout non-zero, startTimeout non-zero: signaled CLEAR.
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 20), 0);
    ticks(1);
    assert_eq!(act_state(&mut sim, ACT_0), (19, 0));

    // 4) ACT Timeout non-zero, startTimeout zero: signaled SET at the tick (the transition from
    // non-zero to zero).
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 0), 0);
    assert_eq!(act_state(&mut sim, ACT_0), (0, 0));
    ticks(1);
    assert_eq!(act_state(&mut sim, ACT_0), (0, SIGNALED));

    // 3) with signaled CLEAR stays CLEAR.
    let mut sim = Tpm::new();
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 0), 0);
    ticks(1);
    assert_eq!(act_state(&mut sim, ACT_0), (0, 0));
}

/// "When ACT Timeout is zero and the *signaled* attribute is SET, writing a *startTimeout* of
/// FF FF FF FF₁₆ will clear *signaled* and stop the counting": the timeout then stays
/// `0xFFFFFFFF`; a later non-zero `startTimeout` restarts the countdown, zero signals.
#[test]
fn max_start_timeout_clears_signaled_and_stops_counting() {
    let mut sim = Tpm::new();
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 1), 0);
    ticks(1);
    assert_eq!(act_state(&mut sim, ACT_0), (0, SIGNALED));
    assert_eq!(act_set_timeout(&mut sim, ACT_0, u32::MAX), 0);
    ticks(1);
    assert_eq!(act_state(&mut sim, ACT_0), (u32::MAX, 0));
    ticks(100);
    assert_eq!(act_state(&mut sim, ACT_0), (u32::MAX, 0));
    // A stopped ACT is not signaling, so 0xFFFFFFFF is rejected now.
    assert_eq!(
        act_set_timeout(&mut sim, ACT_0, u32::MAX),
        rc_p(TpmRc::VALUE, 1)
    );
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 0), 0);
    ticks(1);
    assert_eq!(act_state(&mut sim, ACT_0), (0, SIGNALED));
}

/// Each implemented ACT counts independently.
#[test]
fn implemented_acts_count_independently() {
    let mut sim = Tpm::new();
    let acts = implemented_act_handles();
    for (i, &act) in acts.iter().enumerate() {
        assert_eq!(act_set_timeout(&mut sim, act, 2 + i as u32), 0);
    }
    ticks(2);
    for (i, &act) in acts.iter().enumerate() {
        let expected = if i == 0 { (0, SIGNALED) } else { (i as u32, 0) };
        assert_eq!(act_state(&mut sim, act), expected, "ACT {act:#x}");
    }
}

/// The ticks are the whole seconds of the platform clock since the last power on: a power on at
/// a fractional second moves them.
#[test]
fn ticks_are_anchored_at_power_on() {
    let mut sim = Tpm::new();
    sleep(Duration::from_millis(400));
    sim.signal_platform(SimulatorPlatformSignal::PowerOff)
        .unwrap();
    sleep(Duration::from_millis(300));
    sim.signal_platform(SimulatorPlatformSignal::PowerOn)
        .unwrap();
    nv_on(&mut sim);
    assert_eq!(startup_raw(&mut sim, 0, TPM_SU_CLEAR), 0);
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 5), 0);
    // 999 ms after the power on: no tick yet (a tick anchored at the creation of the TPM would
    // have happened 300 ms after the power on).
    sleep(Duration::from_millis(999));
    assert_eq!(act_state(&mut sim, ACT_0), (5, 0));
    sleep(Duration::from_millis(1));
    assert_eq!(act_state(&mut sim, ACT_0), (4, 0));
}

/// Ticks are not processed between `_TPM_Init` and TPM2_Startup: an ACT saved by
/// TPM2_Shutdown(TPM_SU_STATE) and restored by TPM Resume does not count down while the TPM
/// waits for TPM2_Startup, and a `_TPM_Init` without power loss (the Reset signal) keeps the
/// tick phase.
#[test]
fn acts_do_not_count_before_startup() {
    let mut sim = Tpm::new();
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 20), 0);
    ticks(1);
    assert_eq!(act_state(&mut sim, ACT_0), (19, 0));
    assert_eq!(shutdown_raw(&mut sim, TPM_SU_STATE), 0);
    sim.signal_platform(SimulatorPlatformSignal::Reset).unwrap();
    ticks(5);
    assert_eq!(startup_raw(&mut sim, 0, TPM_SU_STATE), 0);
    // Restored as pending (written since the previous startup, so not halved).
    assert_eq!(act_state(&mut sim, ACT_0), (19, 0));
    sleep(Duration::from_millis(999));
    assert_eq!(act_state(&mut sim, ACT_0), (19, 0));
    sleep(Duration::from_millis(1));
    assert_eq!(act_state(&mut sim, ACT_0), (18, 0));
}

/// TPM2_Shutdown(TPM_SU_STATE) saves the current timeout of an ACT written by
/// TPM2_ACT_SetTimeout since TPM2_Startup and half the timeout of any other ACT (rounded down;
/// a timeout of 1 and the stopped `0xFFFFFFFF` are kept, as in the TCG reference).
#[test]
fn shutdown_state_halves_timeouts_not_written_since_startup() {
    let mut sim = Tpm::new();
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 101), 0);
    ticks(1);
    // Written since TPM2_Startup: saved as is.
    resume(&mut sim);
    assert_eq!(act_state(&mut sim, ACT_0), (100, 0));
    ticks(1);
    assert_eq!(act_state(&mut sim, ACT_0), (99, 0));
    // Not written since this TPM2_Startup: halved.
    resume(&mut sim);
    assert_eq!(act_state(&mut sim, ACT_0), (49, 0));
    ticks(1);
    resume(&mut sim);
    assert_eq!(act_state(&mut sim, ACT_0), (24, 0));
    // A pending value counts as the current timeout.
    resume(&mut sim);
    assert_eq!(act_state(&mut sim, ACT_0), (12, 0));

    // 1 is not halved to zero.
    let mut sim = Tpm::new();
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 3), 0);
    ticks(2);
    resume(&mut sim);
    assert_eq!(act_state(&mut sim, ACT_0), (1, 0));
    resume(&mut sim);
    assert_eq!(act_state(&mut sim, ACT_0), (1, 0));
    ticks(1);
    assert_eq!(act_state(&mut sim, ACT_0), (0, SIGNALED));

    // The stopped 0xFFFFFFFF is not halved.
    assert_eq!(act_set_timeout(&mut sim, ACT_0, u32::MAX), 0);
    ticks(1);
    resume(&mut sim);
    ticks(1);
    resume(&mut sim);
    ticks(1);
    assert_eq!(act_state(&mut sim, ACT_0), (u32::MAX, 0));
}

/// TPM Resume restores `signaled` and copies it to `preserveSignaled` (Part 2, TPMA_ACT); a
/// successful TPM2_ACT_SetTimeout CLEARs `preserveSignaled` at once, also with `startTimeout`
/// zero.
#[test]
fn resume_copies_signaled_to_preserve_signaled() {
    let mut sim = Tpm::new();
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 1), 0);
    ticks(1);
    assert_eq!(act_state(&mut sim, ACT_0), (0, SIGNALED));
    resume(&mut sim);
    assert_eq!(
        act_state(&mut sim, ACT_0),
        (0, SIGNALED | PRESERVE_SIGNALED)
    );
    // Another TPM Resume copies signaled again (still SET).
    resume(&mut sim);
    assert_eq!(
        act_state(&mut sim, ACT_0),
        (0, SIGNALED | PRESERVE_SIGNALED)
    );
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 0), 0);
    assert_eq!(act_state(&mut sim, ACT_0), (0, SIGNALED));
    ticks(1);
    assert_eq!(act_state(&mut sim, ACT_0), (0, SIGNALED));
}

/// `preserveSignaled` is per ACT: TPM Resume copies each ACT's `signaled`, and stopping one ACT
/// with `0xFFFFFFFF` CLEARs its `signaled` and `preserveSignaled` only, also across the next TPM
/// Resume.
#[test]
fn preserve_signaled_is_tracked_per_act() {
    let mut sim = Tpm::new();
    let acts = implemented_act_handles();
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 1), 0);
    ticks(1);
    resume(&mut sim);
    assert_eq!(
        act_state(&mut sim, ACT_0),
        (0, SIGNALED | PRESERVE_SIGNALED)
    );
    if let Some(&other) = acts.get(1) {
        assert_eq!(act_state(&mut sim, other), (0, 0));
        assert_eq!(act_set_timeout(&mut sim, other, 1), 0);
        ticks(1);
        resume(&mut sim);
        assert_eq!(
            act_state(&mut sim, other),
            (0, SIGNALED | PRESERVE_SIGNALED)
        );
    }
    assert_eq!(act_set_timeout(&mut sim, ACT_0, u32::MAX), 0);
    ticks(1);
    resume(&mut sim);
    assert_eq!(act_state(&mut sim, ACT_0), (u32::MAX, 0));
    if let Some(&other) = acts.get(1) {
        assert_eq!(
            act_state(&mut sim, other),
            (0, SIGNALED | PRESERVE_SIGNALED)
        );
    }
}

/// TPM Restart zeroes every ACT and CLEARs `signaled` and `preserveSignaled` (Part 3,
/// TPM2_Startup; Part 2, TPMA_ACT), even after TPM2_Shutdown(TPM_SU_STATE) saved a signaled ACT.
#[test]
fn restart_zeroes_acts_and_clears_preserve_signaled() {
    let mut sim = Tpm::new();
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 1), 0);
    ticks(1);
    resume(&mut sim);
    assert_eq!(
        act_state(&mut sim, ACT_0),
        (0, SIGNALED | PRESERVE_SIGNALED)
    );
    restart(&mut sim);
    assert_eq!(act_state(&mut sim, ACT_0), (0, 0));

    // A counting ACT is stopped too.
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 50), 0);
    ticks(1);
    restart(&mut sim);
    assert_eq!(act_state(&mut sim, ACT_0), (0, 0));
    ticks(60);
    assert_eq!(act_state(&mut sim, ACT_0), (0, 0));
}

/// TPM Reset after a `_TPM_Init` without power loss (the Reset signal) zeroes every ACT and
/// CLEARs `preserveSignaled`.
#[test]
fn reset_without_power_loss_clears_preserve_signaled() {
    let mut sim = Tpm::new();
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 1), 0);
    ticks(1);
    resume(&mut sim);
    assert_eq!(
        act_state(&mut sim, ACT_0),
        (0, SIGNALED | PRESERVE_SIGNALED)
    );
    // TPM2_Shutdown(TPM_SU_STATE) then _TPM_Init and TPM2_Startup(TPM_SU_CLEAR): TPM Restart.
    assert_eq!(shutdown_raw(&mut sim, TPM_SU_STATE), 0);
    sim.signal_platform(SimulatorPlatformSignal::Reset).unwrap();
    assert_eq!(startup_raw(&mut sim, 0, TPM_SU_CLEAR), 0);
    assert_eq!(act_state(&mut sim, ACT_0), (0, 0));

    // Signal again, then TPM Reset without a shutdown and without power loss.
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 1), 0);
    ticks(1);
    resume(&mut sim);
    sim.signal_platform(SimulatorPlatformSignal::Reset).unwrap();
    assert_eq!(startup_raw(&mut sim, 0, TPM_SU_CLEAR), 0);
    assert_eq!(act_state(&mut sim, ACT_0), (0, 0));
}

/// TPM Resume after a power loss restores a signaled ACT with `preserveSignaled` SET (the TCG
/// reference cleared it after a power loss, see `bug-fix-act-preserve-signaled.patch`).
#[test]
fn resume_after_power_loss_preserves_signaled() {
    let mut sim = Tpm::new();
    assert_eq!(act_set_timeout(&mut sim, ACT_0, 1), 0);
    ticks(1);
    // power_cycle_with: PowerOff + PowerOn (a power loss).
    resume(&mut sim);
    assert_eq!(
        act_state(&mut sim, ACT_0),
        (0, SIGNALED | PRESERVE_SIGNALED)
    );
}
