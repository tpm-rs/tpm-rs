//! Authenticated Countdown Timers (ACT).
//!
//! TPM 2.0 Part 1, "Authenticated Countdown Timer (ACT)": "An ACT is a 32-bit counter that, when
//! not already zero, will decrement by one each second that the TPM is powered." Each ACT has a
//! handle `TPM_RH_ACT_x` (Part 2, `TPMI_RH_ACT`), a timeout set by `TPM2_ACT_SetTimeout()`, a
//! `signaled` attribute (Part 2, `TPMA_ACT`) that is SET when the timeout counts down to zero,
//! and an ACT-specific `authPolicy` set by `TPM2_SetPrimaryPolicy()` (its authValue is
//! `platformAuth`).
//!
//! # Which ACTs exist
//!
//! The implemented ACTs are a profile setting: `TPM_RH_ACT_0` always (as in the TCG reference
//! implementation version 185), and `TPM_RH_ACT_A` too with the `act-a` feature (the public TCG
//! reference implementation and `ibmswtpm2`). See [`IMPLEMENTED_ACTS`].
//!
//! # Countdown
//!
//! The counters are modelled on the reference platform (`PlatformACT.c`): a
//! `TPM2_ACT_SetTimeout()` posts a *pending* value (a second update while one is pending is
//! `TPM_RC_RETRY`), which the next once-per-second tick applies and decrements in the same tick
//! (Part 3, TPM2_ACT_SetTimeout: "It may take up to one second until ACT Timeout will be set and
//! *signaled* will be CLEAR or SET by TPM2_ACT_SetTimeout() or TPM2_Startup(TPM_SU_STATE). This
//! allows the counting and signaling to take place synchronously with the hardware clock
//! tick."). The ticks are the whole seconds of the platform timer since the last power on
//! ([`ActState::power_on`]); they are processed only from `TPM2_Startup()` (the reference's
//! `ActStartup()`) until the next `_TPM_Init` or power loss (`_plat__ACT_EnableTicks()`), and
//! they are applied lazily: the engine catches up on the ticks that elapsed before each command
//! ([`ActState::catch_up`]), which nothing can observe except a command.
//!
//! # TPM Reset, Restart and Resume
//!
//! `TPM2_Shutdown(TPM_SU_STATE)` saves each timeout ([`ActState::shutdown_state`]), halved unless
//! the ACT was written since `TPM2_Startup()`, and the `signaled` attributes; with the ACT
//! policies they are restored by the next TPM Resume ([`ActState::startup`]). TPM Reset and TPM
//! Restart zero every ACT and set its `authPolicy` to the Empty Policy.

use crate::owned::OwnedDigest;
use tpm2::{Handle, TpmaAct, TpmiAlgHash, TpmsActData};

/// The numbers (`x` of `TPM_RH_ACT_x`) of the implemented ACTs, in ascending order: `ACT_0`, and
/// `ACT_A` with the `act-a` feature (TCG reference profile `RH_ACT_0`/`RH_ACT_A`).
pub const IMPLEMENTED_ACTS: &[u8] = &[
    0x0,
    #[cfg(feature = "act-a")]
    0xA,
];

/// The number of implemented ACTs.
pub const ACT_COUNT: usize = IMPLEMENTED_ACTS.len();

/// The handle `TPM_RH_ACT_x` of ACT number `act`.
pub const fn act_handle(act: u8) -> Handle {
    Handle(Handle::RH_ACT_0.0 + act as u32)
}

/// The index into [`IMPLEMENTED_ACTS`] (and the arrays of [`ActState`]) of the ACT with handle
/// `handle`, or `None` if `handle` is not an implemented ACT.
pub fn act_index(handle: u32) -> Option<usize> {
    IMPLEMENTED_ACTS
        .iter()
        .position(|&act| act_handle(act).0 == handle)
}

/// Whether `handle` is the handle of an implemented ACT.
pub fn is_implemented_act(handle: u32) -> bool {
    act_index(handle).is_some()
}

/// The `go.signaledACT`/`go.preservedSignaled`/`s_ActUpdated` bit of the ACT at `index`.
const fn act_bit(index: usize) -> u16 {
    1 << IMPLEMENTED_ACTS[index]
}

/// The hardware counter of one ACT (`ACT_DATA` of the reference platform `PlatformACT.c`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActCounter {
    /// The current timeout in seconds (`remaining`); `u32::MAX` does not count down.
    pub remaining: u32,
    /// The value posted by the last update (`newValue`), applied at the next tick.
    pub new_value: u32,
    /// Whether an update is waiting for the next tick (`pending`).
    pub pending: bool,
    /// The `TPMA_ACT.signaled` attribute.
    pub signaled: bool,
}

impl ActCounter {
    /// The timeout reported by `TPM_CAP_ACT` and saved by `TPM2_Shutdown(TPM_SU_STATE)`: the
    /// pending value if an update is pending (`_plat__ACT_GetRemaining()`).
    pub fn timeout(&self) -> u32 {
        if self.pending {
            self.new_value
        } else {
            self.remaining
        }
    }

    /// Posts `new_value` for the next tick (`_plat__ACT_UpdateCounter()`). Returns `false`, and
    /// changes nothing, if an update is already pending.
    pub fn update(&mut self, new_value: u32) -> bool {
        if self.pending {
            return false;
        }
        self.new_value = new_value;
        self.pending = true;
        true
    }

    /// Processes one tick (`ActDecrement()`): a pending update is applied first (an update from
    /// a non-zero timeout to zero becomes 1, so that it expires in this tick); then a timeout
    /// other than 0 and `u32::MAX` is decremented, SETting `signaled` when it reaches zero; a
    /// non-zero timeout CLEARs `signaled`.
    ///
    /// These are the four cases of Part 3, TPM2_ACT_SetTimeout: a non-zero `startTimeout`
    /// CLEARs `signaled` (it SETs it again in the same tick if `startTimeout` is 1, the ACT
    /// then expiring at once); `startTimeout` zero leaves `signaled` unchanged if the timeout
    /// was zero and SETs it ("The ACT signals on a transition from non-zero to zero") if it was
    /// not; `0xFFFFFFFF` CLEARs `signaled` and stops the counting.
    pub fn tick(&mut self) {
        if self.pending {
            if self.new_value == 0 && self.remaining != 0 {
                self.new_value = 1;
            }
            self.remaining = self.new_value;
            self.pending = false;
        }
        if self.remaining != 0 && self.remaining != u32::MAX {
            self.remaining -= 1;
            if self.remaining == 0 {
                self.signaled = true;
            }
        }
        if self.signaled && self.remaining > 0 {
            self.signaled = false;
        }
    }

    /// Processes `ticks` ticks, as many calls of [`Self::tick`] would.
    pub fn tick_n(&mut self, ticks: u64) {
        if ticks == 0 {
            return;
        }
        self.tick();
        // After the first tick no update is pending: a counting timeout just counts down.
        let rest = ticks - 1;
        if rest != 0 && self.remaining != 0 && self.remaining != u32::MAX {
            let decrement = rest.min(u64::from(self.remaining)) as u32;
            self.remaining -= decrement;
            if self.remaining == 0 {
                self.signaled = true;
            }
        }
    }
}

/// The ACT-specific authorization policy (`go.ACT_x.hashAlg`/`go.ACT_x.authPolicy`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActPolicy {
    /// The policy hash algorithm (`TPM_ALG_NULL`: `None`).
    pub hash_alg: Option<TpmiAlgHash>,
    /// The policy digest (the Empty Buffer if no policy is set).
    pub auth_policy: OwnedDigest,
}

/// The kind of a `TPM2_Startup()`, as far as the ACTs are concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActStartupKind {
    /// TPM Reset or TPM Restart.
    ResetOrRestart,
    /// TPM Resume.
    Resume,
}

/// The state of all implemented ACTs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActState {
    /// The counter of each implemented ACT (in [`IMPLEMENTED_ACTS`] order).
    pub counters: [ActCounter; ACT_COUNT],
    /// The `authPolicy` of each implemented ACT.
    pub policies: [ActPolicy; ACT_COUNT],
    /// The timeouts saved by the last `TPM2_Shutdown(TPM_SU_STATE)` (`go.ACT_x.remaining`).
    pub saved_timeouts: [u32; ACT_COUNT],
    /// The `signaled` attributes saved by the last `TPM2_Shutdown(TPM_SU_STATE)`
    /// (`go.signaledACT`, one bit per ACT number).
    pub saved_signaled: u16,
    /// The `TPMA_ACT.preserveSignaled` attributes (`go.preservedSignaled`, one bit per ACT
    /// number).
    pub preserved_signaled: u16,
    /// The ACTs written by `TPM2_ACT_SetTimeout()` since the last `TPM2_Startup()`
    /// (`s_ActUpdated`, one bit per ACT number), whose timeouts `TPM2_Shutdown(TPM_SU_STATE)`
    /// saves unhalved.
    pub updated: u16,
    /// Whether ticks are processed (`actTicksAllowed`): from `TPM2_Startup()` until the next
    /// `_TPM_Init` or power loss.
    pub ticks_allowed: bool,
    /// The platform timer (ms) at the last power on: the ticks are its whole seconds since.
    pub tick_anchor_ms: u64,
    /// The number of ticks since the last power on that have been processed (or dropped).
    pub ticks_seen: u64,
}

impl Default for ActState {
    fn default() -> Self {
        Self {
            counters: [ActCounter::default(); ACT_COUNT],
            policies: [ActPolicy::default(); ACT_COUNT],
            saved_timeouts: [0; ACT_COUNT],
            saved_signaled: 0,
            preserved_signaled: 0,
            updated: 0,
            ticks_allowed: false,
            tick_anchor_ms: 0,
            ticks_seen: 0,
        }
    }
}

impl ActState {
    /// A power on at platform time `now_ms` (`_plat__TimerReset()`): the ticks restart at the
    /// whole seconds after it.
    pub fn power_on(&mut self, now_ms: u64) {
        self.tick_anchor_ms = now_ms;
        self.ticks_seen = 0;
    }

    /// Processes the ticks that elapsed up to platform time `now_ms`. Ticks that elapse while
    /// ticks are not allowed are dropped.
    pub fn catch_up(&mut self, now_ms: u64) {
        let elapsed = now_ms.saturating_sub(self.tick_anchor_ms) / 1000;
        let ticks = elapsed.saturating_sub(self.ticks_seen);
        self.ticks_seen = self.ticks_seen.max(elapsed);
        if self.ticks_allowed {
            for counter in self.counters.iter_mut() {
                counter.tick_n(ticks);
            }
        }
    }

    /// `_TPM_Init` (or a power loss): ticks are not processed until the next `TPM2_Startup()`
    /// (`_plat__ACT_EnableTicks(FALSE)`).
    pub fn disable_ticks(&mut self) {
        self.ticks_allowed = false;
    }

    /// `TPM2_Startup()` (the reference's `ActStartup()`): every counter is zeroed, and
    ///
    /// * on TPM Reset and TPM Restart, every `authPolicy` is set to the Empty Policy and every
    ///   `preserveSignaled` is CLEAR (Part 3, TPM2_Startup: "For each ACT the timeout is reset to
    ///   zero, the *signaled* attribute is set to CLEAR, its *authPolicy* is set to the Empty
    ///   Buffer, and its hashAlg is set to TPM_ALG_NULL"; Part 2, `TPMA_ACT`: "On a TPM Reset or
    ///   Restart, preservedSignaled is CLEAR for all ACT");
    /// * on TPM Resume, the timeouts and `signaled` attributes saved by
    ///   `TPM2_Shutdown(TPM_SU_STATE)` are restored (a non-zero timeout as a pending update,
    ///   applied by the next tick) and each `signaled` is copied to `preserveSignaled` (Part 2,
    ///   `TPMA_ACT`: "On a TPM Resume, the state of each ACT signaled is copied to the
    ///   corresponding preservedSignaled"); the policies are kept.
    ///
    /// Then no ACT has been written since this startup, and ticks are processed.
    pub fn startup(&mut self, kind: ActStartupKind) {
        self.counters = [ActCounter::default(); ACT_COUNT];
        match kind {
            ActStartupKind::ResetOrRestart => {
                self.preserved_signaled = 0;
                self.saved_signaled = 0;
                self.policies = [ActPolicy::default(); ACT_COUNT];
            }
            ActStartupKind::Resume => {
                let mut preserved = 0;
                for (index, counter) in self.counters.iter_mut().enumerate() {
                    let signaled = self.saved_signaled & act_bit(index) != 0;
                    if signaled {
                        preserved |= act_bit(index);
                    }
                    if self.saved_timeouts[index] > 0 {
                        counter.update(self.saved_timeouts[index]);
                    } else if signaled {
                        counter.signaled = true;
                    }
                }
                self.preserved_signaled = preserved;
            }
        }
        self.updated = 0;
        self.ticks_allowed = true;
    }

    /// `TPM2_Shutdown(TPM_SU_STATE)` (the reference's `ActShutdown()`): saves the timeout and the
    /// `signaled` attribute of every ACT.
    ///
    /// Part 1, "Authenticated Countdown Timer (ACT)": "If an ACT *startTimeout* has been written
    /// (TPM2_ACT_SetTimeout()) since the last TPM2_Startup(), then the current timeout of the ACT
    /// is saved by TPM2_Shutdown(TPM_SU_STATE); otherwise, the saved value is one half of the
    /// current ACT timeout." The specification is silent on rounding and on the timeout
    /// `0xFFFFFFFF`, which does not count down; as the TCG reference, a timeout of 1 (whose half
    /// would never signal) and `0xFFFFFFFF` (whose half would start a countdown) are saved
    /// unhalved, and other odd timeouts are rounded down.
    pub fn shutdown_state(&mut self) {
        self.saved_signaled = 0;
        for (index, counter) in self.counters.iter().enumerate() {
            let mut timeout = counter.timeout();
            if self.updated & act_bit(index) == 0 && timeout != u32::MAX && timeout > 1 {
                timeout /= 2;
            }
            self.saved_timeouts[index] = timeout;
            if counter.signaled {
                self.saved_signaled |= act_bit(index);
            }
        }
    }

    /// Records a successful `TPM2_ACT_SetTimeout()` of the ACT at `index`: it was written since
    /// `TPM2_Startup()`, and its `preserveSignaled` is CLEAR (Part 3, TPM2_ACT_SetTimeout: "When
    /// this command is successful, *preserveSignaled* will be CLEAR.").
    pub fn record_set_timeout(&mut self, index: usize) {
        self.updated |= act_bit(index);
        self.preserved_signaled &= !act_bit(index);
    }

    /// The `TPMS_ACT_DATA` of the ACT at `index` (`TPM_CAP_ACT`).
    pub fn act_data(&self, index: usize) -> TpmsActData {
        let counter = &self.counters[index];
        let mut attributes = TpmaAct::empty();
        if counter.signaled {
            attributes |= TpmaAct::SIGNALED;
        }
        if self.preserved_signaled & act_bit(index) != 0 {
            attributes |= TpmaAct::PRESERVE_SIGNALED;
        }
        TpmsActData {
            handle: act_handle(IMPLEMENTED_ACTS[index]),
            timeout: counter.timeout(),
            attributes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counter(remaining: u32, signaled: bool) -> ActCounter {
        ActCounter {
            remaining,
            signaled,
            ..ActCounter::default()
        }
    }

    #[test]
    fn act_0_is_always_implemented() {
        assert_eq!(IMPLEMENTED_ACTS[0], 0);
        assert_eq!(act_index(Handle::RH_ACT_0.0), Some(0));
        assert!(is_implemented_act(0x4000_0110));
        assert!(!is_implemented_act(0x4000_0111));
        assert!(!is_implemented_act(Handle::RH_PLATFORM.0));
        assert_eq!(act_handle(0xF), Handle::RH_ACT_F);
    }

    #[test]
    fn act_a_follows_the_profile() {
        assert_eq!(
            is_implemented_act(Handle::RH_ACT_A.0),
            cfg!(feature = "act-a")
        );
        assert_eq!(ACT_COUNT, if cfg!(feature = "act-a") { 2 } else { 1 });
    }

    #[test]
    fn update_is_pending_until_the_next_tick() {
        let mut c = ActCounter::default();
        assert!(c.update(5));
        assert_eq!(c.timeout(), 5);
        assert_eq!(c.remaining, 0);
        // A second update while one is pending is rejected (TPM_RC_RETRY).
        assert!(!c.update(7));
        assert_eq!(c.timeout(), 5);
        // The tick applies the update and counts it down at once.
        c.tick();
        assert_eq!((c.remaining, c.pending, c.signaled), (4, false, false));
        assert!(c.update(7));
    }

    #[test]
    fn countdown_signals_at_zero() {
        let mut c = counter(2, false);
        c.tick();
        assert_eq!((c.remaining, c.signaled), (1, false));
        c.tick();
        assert_eq!((c.remaining, c.signaled), (0, true));
        // Zero stays zero and signaled.
        c.tick();
        assert_eq!((c.remaining, c.signaled), (0, true));
    }

    #[test]
    fn the_four_set_timeout_cases() {
        // 1) timeout zero, startTimeout non-zero: signaled CLEAR.
        let mut c = counter(0, true);
        c.update(10);
        c.tick();
        assert_eq!((c.remaining, c.signaled), (9, false));
        // 2) timeout non-zero, startTimeout non-zero: signaled CLEAR.
        let mut c = counter(5, false);
        c.update(10);
        c.tick();
        assert_eq!((c.remaining, c.signaled), (9, false));
        // 3) timeout zero, startTimeout zero: signaled unchanged.
        for signaled in [false, true] {
            let mut c = counter(0, signaled);
            c.update(0);
            c.tick();
            assert_eq!((c.remaining, c.signaled), (0, signaled));
        }
        // 4) timeout non-zero, startTimeout zero: signaled SET.
        let mut c = counter(5, false);
        c.update(0);
        c.tick();
        assert_eq!((c.remaining, c.signaled), (0, true));
        let mut c = counter(u32::MAX, false);
        c.update(0);
        c.tick();
        assert_eq!((c.remaining, c.signaled), (0, true));
    }

    #[test]
    fn start_timeout_one_expires_in_the_first_tick() {
        let mut c = counter(0, false);
        c.update(1);
        c.tick();
        assert_eq!((c.remaining, c.signaled), (0, true));
    }

    #[test]
    fn max_timeout_clears_signaled_and_stops() {
        let mut c = counter(0, true);
        c.update(u32::MAX);
        c.tick();
        assert_eq!((c.remaining, c.signaled), (u32::MAX, false));
        c.tick_n(1_000_000);
        assert_eq!((c.remaining, c.signaled), (u32::MAX, false));
    }

    #[test]
    fn tick_n_matches_repeated_ticks() {
        let starts = [
            counter(0, false),
            counter(0, true),
            counter(3, false),
            counter(10, false),
            counter(u32::MAX, false),
        ];
        let updates = [None, Some(0), Some(1), Some(4), Some(u32::MAX)];
        for start in starts {
            for update in updates {
                for n in 0..15u64 {
                    let mut a = start;
                    let mut b = start;
                    if let Some(v) = update {
                        a.update(v);
                        b.update(v);
                    }
                    a.tick_n(n);
                    for _ in 0..n {
                        b.tick();
                    }
                    assert_eq!(a, b, "start {start:?}, update {update:?}, {n} ticks");
                }
            }
        }
    }

    #[test]
    fn ticks_are_whole_seconds_since_power_on() {
        let mut s = ActState::default();
        s.power_on(10_500);
        s.startup(ActStartupKind::ResetOrRestart);
        s.counters[0].update(10);
        s.catch_up(11_499);
        assert_eq!(s.counters[0].timeout(), 10);
        s.catch_up(11_500);
        assert_eq!(s.counters[0].remaining, 9);
        s.catch_up(11_900);
        assert_eq!(s.counters[0].remaining, 9);
        s.catch_up(14_500);
        assert_eq!(s.counters[0].remaining, 6);
        // A timer that does not advance (or a stale read) adds no tick.
        s.catch_up(13_000);
        assert_eq!(s.counters[0].remaining, 6);
    }

    #[test]
    fn ticks_are_dropped_until_startup() {
        let mut s = ActState::default();
        s.power_on(0);
        s.startup(ActStartupKind::ResetOrRestart);
        s.counters[0].update(10);
        s.catch_up(1_000);
        assert_eq!(s.counters[0].remaining, 9);
        s.disable_ticks();
        s.catch_up(5_000);
        assert_eq!(s.counters[0].remaining, 9);
        s.startup(ActStartupKind::ResetOrRestart);
        assert_eq!(s.counters[0], ActCounter::default());
        s.counters[0].update(10);
        // The dropped ticks are not processed later.
        s.catch_up(5_999);
        assert_eq!(s.counters[0].timeout(), 10);
        s.catch_up(6_000);
        assert_eq!(s.counters[0].remaining, 9);
        // A power on restarts the seconds.
        s.power_on(6_300);
        s.catch_up(7_299);
        assert_eq!(s.counters[0].remaining, 9);
        s.catch_up(7_300);
        assert_eq!(s.counters[0].remaining, 8);
    }

    #[test]
    fn shutdown_state_halves_timeouts_not_written_since_startup() {
        let mut s = ActState::default();
        s.startup(ActStartupKind::ResetOrRestart);
        for (timeout, saved) in [(0, 0), (1, 1), (2, 1), (7, 3), (u32::MAX, u32::MAX)] {
            s.counters[0] = counter(timeout, false);
            s.shutdown_state();
            assert_eq!(s.saved_timeouts[0], saved, "timeout {timeout}");
        }
        // Written since TPM2_Startup: saved unhalved (a pending value counts).
        s.counters[0] = counter(7, false);
        s.counters[0].update(9);
        s.record_set_timeout(0);
        s.shutdown_state();
        assert_eq!(s.saved_timeouts[0], 9);
        assert_eq!(s.saved_signaled, 0);
        s.counters[0] = counter(0, true);
        s.shutdown_state();
        assert_eq!((s.saved_timeouts[0], s.saved_signaled), (0, 1));
    }

    #[test]
    fn resume_restores_the_saved_state_and_preserves_signaled() {
        let mut s = ActState::default();
        s.startup(ActStartupKind::ResetOrRestart);
        s.policies[0].hash_alg = Some(TpmiAlgHash::Sha256);
        s.counters[0] = counter(0, true);
        s.shutdown_state();
        s.disable_ticks();
        s.startup(ActStartupKind::Resume);
        assert!(s.ticks_allowed);
        assert_eq!(s.counters[0], counter(0, true));
        let data = s.act_data(0);
        assert_eq!(data.handle, Handle::RH_ACT_0);
        assert_eq!(data.timeout, 0);
        assert_eq!(
            data.attributes,
            TpmaAct::SIGNALED | TpmaAct::PRESERVE_SIGNALED
        );
        assert_eq!(s.policies[0].hash_alg, Some(TpmiAlgHash::Sha256));
        // TPM2_ACT_SetTimeout clears preserveSignaled.
        s.record_set_timeout(0);
        assert_eq!(s.act_data(0).attributes, TpmaAct::SIGNALED);

        // A non-zero saved timeout is a pending update after Resume.
        s.counters[0] = counter(8, false);
        s.updated = 0;
        s.shutdown_state();
        s.startup(ActStartupKind::Resume);
        assert_eq!(s.counters[0].timeout(), 4);
        assert!(s.counters[0].pending);
        assert_eq!(s.act_data(0).attributes, TpmaAct::empty());
    }

    #[test]
    fn reset_or_restart_clears_everything() {
        let mut s = ActState::default();
        s.startup(ActStartupKind::ResetOrRestart);
        s.policies[0].hash_alg = Some(TpmiAlgHash::Sha256);
        s.counters[0] = counter(0, true);
        s.shutdown_state();
        s.startup(ActStartupKind::Resume);
        assert_ne!(s.preserved_signaled, 0);
        s.startup(ActStartupKind::ResetOrRestart);
        assert_eq!(s.counters[0], ActCounter::default());
        assert_eq!(s.policies[0], ActPolicy::default());
        assert_eq!(s.preserved_signaled, 0);
        assert_eq!(s.act_data(0).attributes, TpmaAct::empty());
    }
}
