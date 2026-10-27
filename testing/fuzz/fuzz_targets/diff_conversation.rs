//! Fuzz target `diff_conversation`: one input is a multi-round conversation
//! ([`tpm2_fuzz::model::Conversation`]) with a fresh, started TPM, compared
//! differentially with the C reference TPMs at every round.
//!
//! One [`Tpm`] (seeded with [`FIXED_SEED`], so every input is deterministic)
//! is reused across inputs and reset with [`Tpm::reset`] before each input
//! except the first, so no reference process is spawned per input. Each step
//! runs through [`Driver::round`]; a finding panics with its signatures (see
//! [`tpm2_fuzz::driver`]) unless `known_divergences.txt` suppresses it, in
//! which case the conversation ends quietly.
//!
//! By default the C reference (of the fuzz crate's `target-*` feature) runs in
//! child processes (set `REFERENCE_BIN`); with the `inproc` feature it is
//! linked into the fuzz binary and driven in-process ([`Tpm::with_seed_in_process`]).
//!
//! Every [`Tpm::reset`] leaks the simulator's small `'static` platform
//! components, so run with `-detect_leaks=0`.
//!
//! With `TPM_FUZZ_STATS=<n>`, aggregated driver and session counters are
//! printed to stderr every `n` inputs.

#![no_main]
#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use testing::tpm::Tpm;
use tpm2_fuzz::driver::{Driver, FIXED_SEED, KnownDivergences, Stats};
use tpm2_fuzz::model::Conversation;
use tpm2_fuzz::session::HmacStats;

/// The suppressed finding signatures.
static KNOWN: LazyLock<KnownDivergences> = LazyLock::new(KnownDivergences::load);

/// How often to print the counters (`TPM_FUZZ_STATS`; 0 = never).
static STATS_EVERY: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("TPM_FUZZ_STATS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
});

/// Counters aggregated over the inputs of this process.
#[derive(Default)]
struct Totals {
    inputs: u64,
    suppressed: u64,
    driver: Stats,
    sessions: HmacStats,
}

thread_local! {
    /// The TPM reused across inputs.
    static TPM: RefCell<Option<Tpm>> = const { RefCell::new(None) };
    /// The aggregated counters.
    static TOTALS: RefCell<Totals> = RefCell::new(Totals::default());
}

/// Runs `conv` on `tpm`; whether it ended at a suppressed finding.
fn run(tpm: &mut Tpm, conv: &Conversation) -> (Driver, bool) {
    let mut driver = Driver::default();
    for step in &conv.steps {
        if let Err(finding) = driver.round(tpm, step) {
            if KNOWN.suppresses(&finding) {
                return (driver, true);
            }
            panic!("{}", finding.report());
        }
    }
    (driver, false)
}

/// Adds `driver`'s counters to the totals and prints them periodically.
fn account(driver: &Driver, suppressed: bool) {
    TOTALS.with_borrow_mut(|t| {
        t.inputs += 1;
        t.suppressed += u64::from(suppressed);
        t.driver.add(&driver.stats);
        t.sessions.add(&driver.sessions.hmac_stats());
        if *STATS_EVERY > 0 && t.inputs % *STATS_EVERY == 0 {
            eprintln!(
                "tpm2-fuzz stats: inputs={} suppressed={} {:?} {:?}",
                t.inputs, t.suppressed, t.driver, t.sessions
            );
        }
    });
}

fuzz_target!(|conv: Conversation| {
    TPM.with_borrow_mut(|slot| {
        let tpm = match slot {
            Some(tpm) => {
                tpm.reset();
                tpm
            }
            None => {
                #[cfg(feature = "inproc")]
                let tpm = Tpm::with_seed_in_process(FIXED_SEED);
                #[cfg(not(feature = "inproc"))]
                let tpm = Tpm::with_seed(FIXED_SEED);
                slot.insert(tpm)
            }
        };
        let (driver, suppressed) = run(tpm, &conv);
        account(&driver, suppressed);
    });
});
