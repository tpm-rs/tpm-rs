//! TPM2_ReadClock, TPM2_ClockSet and TPM2_ClockRateAdjust: clock/time semantics, authorization, NV
//! requirements and the safe flag.

use crate::_common::{
    RC_VALUE_P1, STEP_MS, SU_CLEAR, advance, clear, execute_with_password_sessions,
    hierarchy_change_auth, nv_off, nv_on, nv_unavailable, power_cycle, power_cycle_with,
    read_clock, send_clock_rate_adjust, send_clock_set, shutdown_with_type, sleep,
    startup_with_type,
};
use testing::tpm::Tpm;
use tpm2::commands::{ClockRateAdjust, ClockSet};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmClockAdjust};

/// clockInfo.safe is NO after unorderly power cycle and while NV is unavailable; Clear makes it safe again.
///
/// `clockInfo.safe` is NO after an unorderly power cycle and while NV is unavailable.
#[test]
fn clock_info_safe_flag() {
    let mut sim = Tpm::new();
    assert!(read_clock(&mut sim).clock_info.safe);

    // NV unavailable -> clock not safe (`TimeFillInfo`).
    nv_off(&mut sim);
    assert!(!read_clock(&mut sim).clock_info.safe);
    nv_on(&mut sim);
    assert!(read_clock(&mut sim).clock_info.safe);

    // Unorderly shutdown (no TPM2_Shutdown) -> not safe after the next startup (`TimeStartup`).
    assert_eq!(power_cycle_with(&mut sim, None, SU_CLEAR), 0);
    assert!(!read_clock(&mut sim).clock_info.safe);

    // An orderly shutdown keeps the previous value; TPM2_Clear makes it safe again.
    clear(&mut sim, Handle::RH_PLATFORM).unwrap();
    assert!(read_clock(&mut sim).clock_info.safe);
    assert_eq!(power_cycle_with(&mut sim, Some(SU_CLEAR), SU_CLEAR), 0);
    assert!(read_clock(&mut sim).clock_info.safe);
}

/// ClockRateAdjust accepts valid adjust values and rejects invalid ones with TPM_RC_VALUE + RC_P1
#[test]
fn clock_rate_adjust_values() {
    let mut sim = Tpm::new();

    for mode in -3..=3i8 {
        let rc = send_clock_rate_adjust(&mut sim, 0x40000001, mode, 0x8002);
        assert_eq!(rc, 0, "Failed on valid adjustment mode {mode}");
    }

    let out_of_bounds = [-4i8, 4i8, 127i8];
    for mode in out_of_bounds {
        let rc = send_clock_rate_adjust(&mut sim, 0x40000001, mode, 0x8002);
        assert_eq!(
            rc, RC_VALUE_P1,
            "Did not return TPM_RC_VALUE for out of bounds mode {mode}"
        );
    }
}

/// ClockSet/ClockRateAdjust without an authorization session fail with AUTH_MISSING even with empty ownerAuth.
#[test]
fn clock_set_and_rate_adjust_require_session() {
    let mut sim = Tpm::new();
    let now = read_clock(&mut sim).clock_info.clock;
    let rc = execute_with_password_sessions(
        &mut sim,
        &ClockSet {
            auth: Handle::RH_OWNER,
            new_time: now + 10,
        },
        0,
        &[],
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::AUTH_MISSING.get());
    let rc = execute_with_password_sessions(
        &mut sim,
        &ClockRateAdjust {
            auth: Handle::RH_PLATFORM,
            rate_adjust: TpmClockAdjust::FineFaster,
        },
        0,
        &[],
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::AUTH_MISSING.get());
}

/// ClockSet to an earlier value is TPM_RC_VALUE + RC_P1
#[test]
fn clock_set_backward_rejected() {
    let mut sim = Tpm::new();

    // Move the clock to (at least) 1000 ms first.
    assert_eq!(send_clock_set(&mut sim, 0x40000001, 1000, 0x8002), 0);

    let rc = send_clock_set(&mut sim, 0x40000001, 500, 0x8002);
    assert_eq!(rc, RC_VALUE_P1); // TPM_RC_VALUE | TPM_RC_P | TPM_RC_1
}

/// ClockSet to a later value updates the clock
#[test]
fn clock_set_forward() {
    let mut sim = Tpm::new();

    advance();
    let current = read_clock(&mut sim).clock_info.clock;

    let rc = send_clock_set(&mut sim, 0x40000001, current + 1000, 0x8002);
    assert_eq!(rc, 0);

    let rsp = read_clock(&mut sim);
    assert!(rsp.clock_info.clock >= current + 1000);
}

/// ClockSet to >= 2^63 does not wrap; the largest permitted value is represented exactly.
///
/// `TPM2_ClockSet` to a value >= 2^63 must not wrap the clock to 0.
#[test]
fn clock_set_large_value_does_not_wrap() {
    let mut sim = Tpm::new();
    let new_time = 0x8000_0000_0000_0000u64;
    execute_with_password_sessions(
        &mut sim,
        &ClockSet {
            auth: Handle::RH_OWNER,
            new_time,
        },
        1,
        &[],
    )
    .unwrap();
    let clock = read_clock(&mut sim).clock_info.clock;
    assert!(clock >= new_time, "clock wrapped to {clock:#x}");

    // The largest permitted value is also represented exactly.
    let max_time = 0xFFFF_0000_0000_0000u64;
    execute_with_password_sessions(
        &mut sim,
        &ClockSet {
            auth: Handle::RH_OWNER,
            new_time: max_time,
        },
        1,
        &[],
    )
    .unwrap();
    let clock = read_clock(&mut sim).clock_info.clock;
    assert!(clock >= max_time, "clock wrapped to {clock:#x}");
}

/// ClockSet returns NV_UNAVAILABLE while NV is unavailable and leaves the clock unchanged.
///
/// `TPM2_ClockSet` returns `TPM_RC_NV_UNAVAILABLE` while NV is unavailable.
#[test]
fn clock_set_requires_nv() {
    let mut sim = Tpm::new();
    let before = read_clock(&mut sim).clock_info.clock;
    nv_off(&mut sim);
    let rc = execute_with_password_sessions(
        &mut sim,
        &ClockSet {
            auth: Handle::RH_OWNER,
            new_time: before + 1_000_000,
        },
        1,
        &[],
    )
    .unwrap_err();
    assert_eq!(rc, nv_unavailable());
    nv_on(&mut sim);
    assert!(read_clock(&mut sim).clock_info.clock < before + 1_000_000);
}

/// ClockSet with a wrong owner password fails with BAD_AUTH+S1 (owner is DA-exempt).
///
/// A wrong owner password for ClockSet fails with BAD_AUTH + S1 (owner is DA-exempt), and a
/// no-session ClockSet fails with AUTH_MISSING even with an empty ownerAuth.
#[test]
fn clock_set_wrong_owner_password() {
    let mut sim = Tpm::new();
    hierarchy_change_auth(&mut sim, Handle::RH_OWNER, &[], b"abc").unwrap();
    let now = read_clock(&mut sim).clock_info.clock;
    let rc = execute_with_password_sessions(
        &mut sim,
        &ClockSet {
            auth: Handle::RH_OWNER,
            new_time: now + 10,
        },
        1,
        b"ab",
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::BAD_AUTH.with(Position::session(1)).get());
}

/// ClockRateAdjust (saturated slower) actually slows the advance of Time/Clock.
///
/// `TPM2_ClockRateAdjust` actually slows down the advance of Time/Clock.
#[test]
fn rate_adjust_slows_clock() {
    let mut sim = Tpm::new();
    // 17 coarse steps exceed CLOCK_ADJUST_LIMIT: the divisor saturates at 35000 / 30000.
    for _ in 0..17 {
        execute_with_password_sessions(
            &mut sim,
            &ClockRateAdjust {
                auth: Handle::RH_PLATFORM,
                rate_adjust: TpmClockAdjust::CoarseSlower,
            },
            1,
            &[],
        )
        .unwrap();
    }
    let t0 = read_clock(&mut sim).time;
    // `sleep` advances the platform timer by exactly this much.
    let platform_ms = 1500;
    sleep(std::time::Duration::from_millis(platform_ms));
    let t1 = read_clock(&mut sim).time;
    let tpm_ms = t1 - t0;
    // Nominal would be `platform_ms`; the adjusted rate is 30000/35000 ~= 0.857.
    assert!(
        tpm_ms * 100 <= platform_ms * 92,
        "TPM time advanced {tpm_ms} ms in {platform_ms} ms of platform time"
    );
    assert!(
        tpm_ms * 100 >= platform_ms * 70,
        "TPM time advanced too slowly"
    );
}

/// ReadClock reports a safe clock and time/clock follow the platform timer
///
/// `TPM2_ReadClock` succeeds, reports a safe clock and both `time` and `clock` follow the
/// platform timer (originally: timer set to 42 ms).
#[test]
fn read_clock_follows_timer() {
    let mut sim = Tpm::new();

    advance();

    let rsp = read_clock(&mut sim);
    assert!(rsp.clock_info.safe);
    assert!(rsp.clock_info.clock >= STEP_MS);
    assert!(rsp.time >= STEP_MS);
}

/// ClockSet changes only clock; time restarts after Shutdown(STATE)/Startup(STATE) while clock is preserved
///
/// `TpmsTimeInfo.time` (`g_time`) and `clock` (`go.clock`) are separate: `TPM2_ClockSet` only
/// changes `clock`, both advance with the timer, and across `Shutdown(STATE)` + power cycle +
/// `Startup(STATE)` `time` restarts for the new power period while `clock` is preserved.
#[test]
fn time_and_clock_are_separate() {
    let mut sim = Tpm::new();

    // 1. Advance the timer. Both g_time (time) and go.clock (clock) advance.
    advance();
    let rsp1 = read_clock(&mut sim);
    assert!(rsp1.time >= STEP_MS, "g_time should have advanced");
    assert!(
        rsp1.clock_info.clock >= STEP_MS,
        "go.clock should have advanced"
    );

    // 2. Execute TPM2_ClockSet to set go.clock to 10_000 ms.
    // g_time (TpmsTimeInfo.time) MUST remain unmodified by ClockSet, while go.clock becomes 10_000 ms.
    let rc = send_clock_set(&mut sim, 0x40000001, 10_000, 0x8002);
    assert_eq!(rc, 0);

    let rsp2 = read_clock(&mut sim);
    assert!(rsp2.time >= rsp1.time);
    assert!(
        rsp2.time < 10_000,
        "g_time must never be modified by TPM2_ClockSet"
    );
    let elapsed = rsp2.time - rsp1.time;
    assert!(
        rsp2.clock_info.clock >= 10_000 && rsp2.clock_info.clock <= 10_000 + elapsed,
        "go.clock must reflect new ClockSet value"
    );

    // 3. Advance the timer again. Both g_time and go.clock advance.
    advance();
    let rsp3 = read_clock(&mut sim);
    assert!(rsp3.time >= rsp2.time + STEP_MS);
    assert!(rsp3.clock_info.clock >= rsp2.clock_info.clock + STEP_MS);

    // 4. Simulate live migration / power cycle: Shutdown(STATE) -> Startup(STATE).
    // g_time resets for the new power period, while go.clock preserves its orderly value.
    assert_eq!(shutdown_with_type(&mut sim, 1), 0);
    power_cycle(&mut sim);
    assert_eq!(startup_with_type(&mut sim, 1), 0);

    let rsp4 = read_clock(&mut sim);
    assert!(rsp4.time < rsp3.time, "g_time resets on power cycle");
    assert!(
        rsp4.clock_info.clock >= rsp3.clock_info.clock,
        "go.clock preserves orderly clock value across power cycle"
    );
}

/// Shutdown(CLEAR)+Startup(CLEAR) preserves clock, increments resetCount and clears restartCount
///
/// `TPM2_Shutdown(CLEAR)` + `TPM2_Startup(CLEAR)` is a TPM Reset: the orderly-saved clock is
/// preserved, `resetCount` increments and `restartCount` is cleared.
#[test]
fn tpm_reset_preserves_clock() {
    let mut sim = Tpm::new();

    // Check initial ReadClock
    advance();
    let rsp1 = read_clock(&mut sim);
    let initial_reset = rsp1.clock_info.reset_count;

    // Advance clock and simulate Shutdown(CLEAR) + reset/restart + Startup(CLEAR)
    advance();
    assert_eq!(shutdown_with_type(&mut sim, 0), 0);

    // Simulate power/initialization reset before next startup
    power_cycle(&mut sim);
    assert_eq!(startup_with_type(&mut sim, 0), 0);

    // ReadClock after restart
    let rsp2 = read_clock(&mut sim);

    assert!(rsp2.clock_info.clock >= rsp1.clock_info.clock + STEP_MS);
    // Shutdown(CLEAR) + Startup(CLEAR) is a TPM Reset (`Startup.c`): resetCount increments and
    // restartCount is cleared.
    assert_eq!(rsp2.clock_info.reset_count, initial_reset + 1);
    assert_eq!(rsp2.clock_info.restart_count, 0);
}

/// After TPM2_ClockRateAdjust, elapsed platform time is converted to TPM time as the TCG
/// reference platform does (`_plat__TimerRead()`: `timeDiff * CLOCK_NOMINAL / adjustRate`,
/// consuming only the platform time that maps back), so the times TPM2_ReadClock reports after
/// long sleeps are byte-identical to the references (checked in differential mode). TPM 2.0
/// Part 3, TPM2_ClockRateAdjust: "This command adjusts the rate of advance of *Clock* and *Time*
/// to provide a better approximation to real time.", with the step size left to the platform.
/// Found by differential fuzzing.
#[test]
fn clock_rate_adjustment_rounds_like_the_platform() {
    let response_code = |rsp: &[u8]| u32::from_be_bytes(rsp[6..10].try_into().unwrap());
    let mut tpm = testing::tpm::Tpm::with_seed(testing::seed::ReferenceSeed {
        pid: 4242,
        realtime_ms: 1000000,
    });

    // Round 0: TPM2_ClockRateAdjust.
    let rsp = tpm.send_command(
        0,
        &[
            0x80, 0x02, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x01, 0x30, 0x40, 0x00, 0x00, 0x0c,
            0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00, 0xfd,
        ],
    );
    assert_eq!(response_code(&rsp), 0x0);

    // Round 1: 268435549 ms pass.
    testing::tpm::sleep(std::time::Duration::from_millis(268435549));

    // Round 2: TPM2_ReadClock.
    let rsp = tpm.send_command(
        0,
        &[0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x81],
    );
    assert_eq!(response_code(&rsp), 0x0);

    // Round 3: 4244635741 ms pass.
    testing::tpm::sleep(std::time::Duration::from_millis(4244635741));

    // Round 4: TPM2_ReadClock.
    let rsp = tpm.send_command(
        0,
        &[0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x81],
    );
    assert_eq!(response_code(&rsp), 0x0);
}

/// Every command, even one with an unimplemented command code, first brings Clock up to date
/// and writes it to NV when it crosses an `NV_CLOCK_UPDATE_INTERVAL` boundary (TCG reference
/// `ExecuteCommand()`: `TimeUpdateToCurrent()` runs before the command header is parsed), so the
/// Clock survives the following power cycle. TPM 2.0 Part 1, "Clock": "A non-volatile value
/// (*NV Clock*) is updated periodically from *Clock*." Found by differential fuzzing.
#[test]
fn rejected_command_updates_clock_in_nv() {
    let mut tpm = Tpm::new();
    testing::tpm::sleep(std::time::Duration::from_millis(1 << 22));
    // An unimplemented command code (TPM2_VerifyDigestSignature).
    let rsp = tpm.send_command(0, &[0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0xa5]);
    assert_eq!(crate::_common::rc_of(&rsp), 0x143);
    tpm.signal_platform(testing::tpm::SimulatorPlatformSignal::PowerOff)
        .unwrap();
    tpm.signal_platform(testing::tpm::SimulatorPlatformSignal::PowerOn)
        .unwrap();
    let rsp = tpm.send_command(0, &[0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x44, 0, 0]);
    assert_eq!(crate::_common::rc_of(&rsp), 0);
    // TPM2_ReadClock: currentTime.clockInfo.clock.
    let rsp = tpm.send_command(0, &[0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x81]);
    assert_eq!(crate::_common::rc_of(&rsp), 0);
    assert!(u64::from_be_bytes(rsp[18..26].try_into().unwrap()) >= 1 << 22);
}

/// `Time` counts how long "the circuit providing *Time* has been powered" (TPM 2.0 Part 1,
/// "Time"), so a `_TPM_Init` without a power loss (the platform `Reset` signal) followed by
/// `TPM2_Startup` keeps it running, while a power cycle restarts it.
#[test]
fn time_continues_across_reset_without_power_loss() {
    let mut sim = Tpm::new();
    sleep(std::time::Duration::from_millis(5_000));
    let before = read_clock(&mut sim).time;
    assert!(before >= 5_000);
    for startup in [SU_CLEAR as u8, 1] {
        assert_eq!(shutdown_with_type(&mut sim, startup), 0);
        sim.signal_platform(testing::tpm::SimulatorPlatformSignal::Reset)
            .unwrap();
        assert_eq!(startup_with_type(&mut sim, startup), 0);
        assert!(read_clock(&mut sim).time >= before);
    }
    power_cycle(&mut sim);
    assert_eq!(startup_with_type(&mut sim, SU_CLEAR as u8), 0);
    assert!(read_clock(&mut sim).time < before);
}
