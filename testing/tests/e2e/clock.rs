//! TPM2_ReadClock, TPM2_ClockSet and TPM2_ClockRateAdjust: clock/time semantics, authorization, NV
//! requirements and the safe flag.

use crate::_common::{
    RC_VALUE_P1, STEP_MS, SU_CLEAR, advance, clear, execute_with_password_sessions,
    hierarchy_change_auth, nv_off, nv_on, nv_unavailable, power_cycle, power_cycle_with,
    read_clock, send_clock_rate_adjust, send_clock_set, shutdown_with_type, sleep,
    startup_with_type,
};
use tpm2::commands::{ClockRateAdjust, ClockSet};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmClockAdjust};
use tpm2_simulator::create_simulator;

/// clockInfo.safe is NO after unorderly power cycle and while NV is unavailable; Clear makes it safe again.
///
/// `clockInfo.safe` is NO after an unorderly power cycle and while NV is unavailable.
#[test]
fn clock_info_safe_flag() {
    let mut sim = create_simulator!();
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
    let mut sim = create_simulator!();

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
    let mut sim = create_simulator!();
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
    let mut sim = create_simulator!();

    // Move the clock to (at least) 1000 ms first.
    assert_eq!(send_clock_set(&mut sim, 0x40000001, 1000, 0x8002), 0);

    let rc = send_clock_set(&mut sim, 0x40000001, 500, 0x8002);
    assert_eq!(rc, RC_VALUE_P1); // TPM_RC_VALUE | TPM_RC_P | TPM_RC_1
}

/// ClockSet to a later value updates the clock
#[test]
fn clock_set_forward() {
    let mut sim = create_simulator!();

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
    let mut sim = create_simulator!();
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
    let mut sim = create_simulator!();
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
    let mut sim = create_simulator!();
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
    let mut sim = create_simulator!();
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
    let mut sim = create_simulator!();

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
    let mut sim = create_simulator!();

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
    let mut sim = create_simulator!();

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
