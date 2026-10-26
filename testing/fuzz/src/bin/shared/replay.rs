//! Replays a [`Conversation`] through the fuzz driver on a TPM, the way the
//! `diff_conversation` fuzz target does, and keeps every round's resolved
//! command and `tpm-rs` response. Shared by `trace2conv` (to check that a
//! converted conversation reproduces its trace) and `to_test` (to print a
//! finding as an E2E test).

use std::panic::{AssertUnwindSafe, catch_unwind};

use testing::tpm::Tpm;
use tpm2_fuzz::driver::{Driver, Finding, RoundOutcome};
use tpm2_fuzz::model::{Conversation, Step};

/// What one replayed round did.
#[derive(Debug)]
pub enum Outcome {
    /// Executed, with the `tpm-rs` response code (see
    /// [`RoundOutcome::Executed`]).
    Executed(u32),
    /// Rejected at the transport level, or sent while the TPM was powered
    /// off (not executed, not mirrored).
    Skipped,
    /// An event step (platform signal, `_TPM_Hash_*`, sleep, locality).
    Event,
    /// The round ended the conversation with a driver finding.
    Finding(Finding),
    /// The round panicked (e.g. a session engine finding such as
    /// `BAD_RESPONSE_HMAC[...]`), with the panic message. The `Tpm` must be
    /// reset (or dropped) afterwards.
    Panic(String),
}

/// One replayed round.
#[derive(Debug)]
pub struct Replayed {
    /// The step of the round.
    pub step: Step,
    /// The locality the command was sent at (for an event step: the
    /// locality after it).
    pub locality: u8,
    /// The resolved command bytes that were sent.
    pub command: Vec<u8>,
    /// The `tpm-rs` response (empty if the round was skipped or panicked
    /// before the response).
    pub response: Vec<u8>,
    /// What happened.
    pub outcome: Outcome,
}

impl Replayed {
    /// Whether the conversation ended at this round.
    pub fn is_final(&self) -> bool {
        matches!(self.outcome, Outcome::Finding(_) | Outcome::Panic(_))
    }
}

/// The message of a caught panic payload.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_else(|| "non-string panic payload".into())
}

/// Replays `conv` on `tpm` (which must be fresh and started, e.g.
/// `Tpm::with_seed(FIXED_SEED)` or after `Tpm::reset()`), stopping after the
/// first round that ends the conversation (a finding or a panic, which is
/// caught).
pub fn replay(tpm: &mut Tpm, conv: &Conversation) -> Vec<Replayed> {
    let mut driver = Driver::default();
    let mut out = Vec::with_capacity(conv.steps.len());
    for step in &conv.steps {
        let result = catch_unwind(AssertUnwindSafe(|| driver.round(tpm, step)));
        let outcome = match result {
            Ok(Ok(RoundOutcome::Executed(rc))) => Outcome::Executed(rc),
            Ok(Ok(RoundOutcome::Skipped)) => Outcome::Skipped,
            Ok(Ok(RoundOutcome::Event)) => Outcome::Event,
            Ok(Err(finding)) => Outcome::Finding(finding),
            Err(payload) => Outcome::Panic(panic_message(payload.as_ref())),
        };
        let replayed = Replayed {
            step: step.clone(),
            locality: driver.locality(),
            command: driver.last_command().to_vec(),
            response: driver.last_response().to_vec(),
            outcome,
        };
        let done = replayed.is_final();
        out.push(replayed);
        if done {
            break;
        }
    }
    out
}
