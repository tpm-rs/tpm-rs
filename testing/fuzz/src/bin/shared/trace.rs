//! Splits the command/response traces that `testing::tpm::Tpm` records with
//! `TPM_FUZZ_RECORD_DIR` (format and parser: `testing::tpm::trace`) into the
//! conversations the `diff_conversation` fuzz target can replay.
//!
//! A fuzz conversation always starts on a fresh TPM that is powered on, has NV
//! available and has received `TPM2_Startup(CLEAR)`, and holds only commands
//! at locality 0. A trace starts in that state (and returns to it after every
//! `Z` reset), so a conversation is the run of locality-0 commands from such a
//! starting point up to the first event the fuzzer cannot express: a platform
//! signal, a `_TPM_Hash_*` indication, a clock advance, or a command at
//! another locality.

use testing::tpm::trace::{Event, Trace};

/// One command round of a conversation: the command and the `tpm-rs`
/// response recorded for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Round {
    /// The command bytes.
    pub command: Vec<u8>,
    /// The `tpm-rs` response bytes.
    pub response: Vec<u8>,
}

/// Splits `trace` into replayable conversations (see the module docs).
/// Commands rejected at transport level are dropped, because they were not
/// executed (the driver skips them too). Empty conversations are omitted.
pub fn conversations(trace: &Trace) -> Vec<Vec<Round>> {
    let mut out = Vec::new();
    let mut current = Vec::new();
    let mut open = true;
    for event in &trace.events {
        match event {
            Event::Command {
                locality: 0,
                command,
                response,
            } if open => current.push(Round {
                command: command.clone(),
                response: response.clone(),
            }),
            Event::Rejected { .. } => {}
            Event::Reset => {
                out.push(std::mem::take(&mut current));
                open = true;
            }
            Event::Command { .. }
            | Event::Signal(_)
            | Event::HashStart
            | Event::HashData(_)
            | Event::HashEnd
            | Event::AdvanceClock(_) => open = false,
        }
    }
    out.push(current);
    out.retain(|c| !c.is_empty());
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

    /// Conversations start fresh, stop at out-of-scope events, skip
    /// rejected commands and restart after a reset.
    #[test]
    fn splits_conversations() {
        let text = format!(
            "{HEADER}\nC 0 01\nR 11\nX 0 99\nC 0 02\nR 12\nC 3 03\nR 13\nC 0 04\nR 14\nZ\n\
             C 0 05\nR 15\nT 10\nC 0 06\nR 16\nZ\nZ\nC 0 07\nR 17\nH start\nC 0 08\nR 18\n"
        );
        let convs = conversations(&parse(&text).unwrap());
        let commands: Vec<Vec<Vec<u8>>> = convs
            .iter()
            .map(|c| c.iter().map(|r| r.command.clone()).collect())
            .collect();
        assert_eq!(
            commands,
            vec![vec![vec![1], vec![2]], vec![vec![5]], vec![vec![7]]]
        );
        assert_eq!(convs[0][1].response, vec![0x12]);
    }

    /// A signal before the first command yields no conversation at all.
    #[test]
    fn leading_signal_yields_nothing() {
        let text = format!("{HEADER}\nS PowerOff\nC 0 01\nR 11\n");
        assert!(conversations(&parse(&text).unwrap()).is_empty());
    }

    /// Hex encoding is lowercase and two digits per byte.
    #[test]
    fn hex_encoding() {
        assert_eq!(encode_hex(&[0x00, 0x01, 0xab, 0xff]), "0001abff");
        assert_eq!(encode_hex(&[]), "");
    }
}
