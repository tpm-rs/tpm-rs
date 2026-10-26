//! Splits the command/response traces that `testing::tpm::Tpm` records with
//! `TPM_FUZZ_RECORD_DIR` (format and parser: `testing::tpm::trace`) into the
//! conversations the `diff_conversation` fuzz target can replay.
//!
//! A fuzz conversation always starts on a fresh TPM that is powered on, has NV
//! available and has received `TPM2_Startup(CLEAR)`, with commands sent at
//! locality 0. A trace starts in that state (and returns to it after every
//! `Z` reset), so a conversation is the run of events from such a starting
//! point up to the first event the fuzzer cannot express (a platform signal
//! outside [`PLATFORM_SIGNALS`]). Commands become command rounds; platform
//! signals, `_TPM_Hash_*` indications and clock advances become event rounds
//! ([`Step::Platform`], [`Step::Sleep`]), and a command at another locality
//! than the previous one is preceded by a [`Step::Locality`] event round.

use testing::tpm::trace::{Event, Trace};
use tpm2_fuzz::model::{PLATFORM_SIGNALS, PlatformOp, Step};

/// One round of a conversation: a command and the `tpm-rs` response
/// recorded for it, or an event step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Round {
    /// The command bytes (empty for an event round).
    pub command: Vec<u8>,
    /// The `tpm-rs` response bytes (empty for an event round).
    pub response: Vec<u8>,
    /// The step of an event round.
    pub event: Option<Step>,
}

impl Round {
    /// A command round.
    pub fn command(command: Vec<u8>, response: Vec<u8>) -> Self {
        Self {
            command,
            response,
            event: None,
        }
    }

    /// An event round.
    pub fn event(step: Step) -> Self {
        Self {
            command: Vec::new(),
            response: Vec::new(),
            event: Some(step),
        }
    }
}

/// The transport-level signals that leave the TPM untouched
/// (`testing::differential::server`); conversations skip them.
const NO_OP_SIGNALS: [&str; 6] = [
    "KeyCacheOn",
    "KeyCacheOff",
    "SessionEnd",
    "Stop",
    "GetCommandResponseSizes",
    "ActGetSignaled",
];

/// The event step of a recorded event, `None` if the fuzzer cannot express
/// it.
fn event_step(event: &Event) -> Option<Step> {
    Some(match event {
        Event::Signal(name) => {
            let signal = PLATFORM_SIGNALS
                .iter()
                .find(|s| format!("{s:?}") == *name)?;
            Step::Platform(PlatformOp::signal(*signal)?)
        }
        Event::HashStart => Step::Platform(PlatformOp::HashStart),
        Event::HashData(data) => Step::Platform(PlatformOp::HashData(data.clone())),
        Event::HashEnd => Step::Platform(PlatformOp::HashEnd),
        Event::AdvanceClock(ms) => Step::Sleep(u32::try_from(*ms).ok()?),
        Event::Command { .. } | Event::Rejected { .. } | Event::Reset => return None,
    })
}

/// Splits `trace` into replayable conversations (see the module docs).
/// Commands rejected at transport level are dropped, because they were not
/// executed (the driver skips them too). Empty conversations are omitted.
pub fn conversations(trace: &Trace) -> Vec<Vec<Round>> {
    let mut out = Vec::new();
    let mut current = Vec::new();
    let mut open = true;
    let mut current_locality = 0;
    for event in &trace.events {
        match event {
            Event::Reset => {
                out.push(std::mem::take(&mut current));
                open = true;
                current_locality = 0;
            }
            _ if !open => {}
            Event::Rejected { .. } => {}
            Event::Command {
                locality,
                command,
                response,
            } => {
                if *locality != current_locality {
                    current.push(Round::event(Step::Locality(*locality)));
                    current_locality = *locality;
                }
                current.push(Round::command(command.clone(), response.clone()));
            }
            Event::Signal(name) if NO_OP_SIGNALS.contains(&name.as_str()) => {}
            event => match event_step(event) {
                Some(step) => current.push(Round::event(step)),
                None => open = false,
            },
        }
    }
    out.push(current);
    out.retain(|c| c.iter().any(|r| r.event.is_none()));
    out
}

/// Encodes bytes as lowercase hexadecimal.
pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use testing::tpm::trace::parse;

    const HEADER: &str = "# tpm-rs-trace v1 seed=1234:5678 test=e2e::nv::define";

    /// Conversations start fresh, turn events into event rounds (with a
    /// locality round before a command at a new locality), skip rejected
    /// commands, stop at events the fuzzer cannot express and restart after
    /// a reset.
    #[test]
    fn splits_conversations() {
        let text = format!(
            "{HEADER}\nC 0 01\nR 11\nX 0 99\nC 0 02\nR 12\nC 3 03\nR 13\nC 0 04\nR 14\nZ\n\
             C 0 05\nR 15\nT 10\nC 0 06\nR 16\nZ\nZ\nC 0 07\nR 17\nH start\nH data 0a0b\n\
             S PowerOff\nS Restart\nC 0 08\nR 18\n"
        );
        let convs = conversations(&parse(&text).unwrap());
        let steps: Vec<Vec<Result<Vec<u8>, Step>>> = convs
            .iter()
            .map(|c| {
                c.iter()
                    .map(|r| r.event.clone().map_or(Ok(r.command.clone()), Err))
                    .collect()
            })
            .collect();
        assert_eq!(
            steps,
            vec![
                vec![
                    Ok(vec![1]),
                    Ok(vec![2]),
                    Err(Step::Locality(3)),
                    Ok(vec![3]),
                    Err(Step::Locality(0)),
                    Ok(vec![4]),
                ],
                vec![Ok(vec![5]), Err(Step::Sleep(10)), Ok(vec![6])],
                vec![
                    Ok(vec![7]),
                    Err(Step::Platform(PlatformOp::HashStart)),
                    Err(Step::Platform(PlatformOp::HashData(vec![0x0a, 0x0b]))),
                    Err(Step::Platform(PlatformOp::Signal(0))),
                ],
            ]
        );
        assert_eq!(convs[0][1].response, vec![0x12]);
    }

    /// A conversation of events only (no command) is omitted.
    #[test]
    fn event_only_conversation_yields_nothing() {
        let text = format!("{HEADER}\nS PowerOff\nS Restart\nC 0 01\nR 11\n");
        assert!(conversations(&parse(&text).unwrap()).is_empty());
    }

    /// Hex encoding is lowercase and two digits per byte.
    #[test]
    fn hex_encoding() {
        assert_eq!(encode_hex(&[0x00, 0x01, 0xab, 0xff]), "0001abff");
        assert_eq!(encode_hex(&[]), "");
    }
}
