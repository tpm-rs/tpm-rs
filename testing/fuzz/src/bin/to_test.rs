//! Turns a `diff_conversation` fuzzer input (typically a minimized crash)
//! into a ready-to-paste Rust E2E test for `testing/tests/e2e/<topic>.rs`.
//!
//! The input is decoded as a [`Conversation`] and replayed through the fuzz
//! driver on `Tpm::with_seed(FIXED_SEED)`, exactly as the fuzz target runs
//! it. Every round's resolved command bytes are then printed as a
//! `tpm.send_command(0, &[...])` call on a `Tpm` with the same fixed seed, so
//! the test sends the same bytes and gets the same responses (all random
//! values are deterministic under the seed). The rounds before the finding
//! assert the `tpm-rs` response code; the finding's round is annotated with
//! the diverging references' response codes and a `TODO` for the triager to
//! assert the correct behavior. The replay stops at the first finding, so
//! later rounds are not printed.
//!
//! The replay needs the reference binaries (`MSTPM20_BIN`, `IBMSWTPM2_BIN`),
//! because the fuzz crate's `Tpm` is differential.
//!
//! Usage:
//!
//! ```sh
//! cargo run --release --manifest-path testing/fuzz/Cargo.toml --bin to_test -- \
//!     [--name <test fn name>] <crash file>
//! ```
//!
//! Follow the GEMINI.md rules when pasting: pick a test name that describes
//! the behavior under test (`--name`), and complete the `///` doc.
#![forbid(unsafe_code)]

#[path = "shared/constants.rs"]
mod constants;
#[path = "shared/replay.rs"]
mod replay;

use std::fmt::Write as _;
use std::path::Path;
use std::process::ExitCode;

use testing::tpm::Tpm;
use tpm2_fuzz::driver::{FIXED_SEED, Finding};
use tpm2_fuzz::model::Conversation;

use crate::constants::command_name;
use crate::replay::{Outcome, Replayed};

/// Bytes per line in the printed command arrays.
const BYTES_PER_LINE: usize = 12;

/// The response code of a response buffer, if it has a header.
fn response_code(response: &[u8]) -> Option<u32> {
    response
        .get(6..10)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// The command code of a command buffer, if it has a header.
fn command_code(command: &[u8]) -> Option<u32> {
    response_code(command)
}

/// A human-readable command label, e.g. `TPM2_CreatePrimary` or
/// `command code 0x12345678`.
fn command_label(command: &[u8]) -> String {
    match command_code(command) {
        Some(code) => command_name(code).map_or_else(
            || format!("command code {code:#010x}"),
            |name| format!("TPM2_{name}"),
        ),
        None => "a command without a complete header".into(),
    }
}

/// `CreatePrimary` → `create_primary`, `NV_Write` → `nv_write`.
fn snake_case(name: &str) -> String {
    let mut out = String::new();
    let mut prev_lower = false;
    for c in name.chars() {
        if c == '_' {
            if !out.ends_with('_') {
                out.push('_');
            }
            prev_lower = false;
        } else if c.is_ascii_uppercase() {
            if prev_lower && !out.ends_with('_') {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
            prev_lower = false;
        } else {
            out.push(c);
            prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        }
    }
    out
}

/// The default test name: the snake-case name of the finding's command and
/// `matches_reference` (to be renamed after triage).
fn default_name(rounds: &[Replayed]) -> String {
    let base = rounds
        .last()
        .and_then(|r| command_code(&r.command))
        .and_then(command_name)
        .map_or_else(|| "command".into(), |n| snake_case(&n));
    format!("{base}_matches_reference")
}

/// Formats `bytes` as the lines of a Rust slice literal body, indented by
/// `indent` spaces.
fn byte_lines(bytes: &[u8], indent: usize) -> String {
    let pad = " ".repeat(indent);
    let mut out = String::new();
    for chunk in bytes.chunks(BYTES_PER_LINE) {
        let items: Vec<String> = chunk.iter().map(|b| format!("{b:#04x}")).collect();
        let _ = writeln!(out, "{pad}{},", items.join(", "));
    }
    out
}

/// A one-line description of how a round ended the conversation.
fn finding_summary(outcome: &Outcome) -> Option<String> {
    match outcome {
        Outcome::Finding(f) => Some(f.signatures().join(", ")),
        Outcome::Panic(message) => Some(format!(
            "panic: {}",
            message.lines().next().unwrap_or_default()
        )),
        Outcome::Executed(_) | Outcome::Skipped => None,
    }
}

/// The comment and assertion lines for the finding round.
fn finding_lines(r: &Replayed) -> String {
    let mut out = String::new();
    let rs_rc = response_code(&r.response);
    match &r.outcome {
        Outcome::Finding(Finding::Divergence { divergences, .. }) => {
            let rs = rs_rc.map_or("no response".into(), |rc| format!("{rc:#x}"));
            let _ = writeln!(out, "    // tpm-rs answered {rs}; the references disagree:");
            let mut expected = None;
            for d in divergences {
                let ref_rc = d.reference_response.as_deref().and_then(response_code);
                expected = expected.or(ref_rc);
                let rc = ref_rc.map_or("no response".into(), |rc| format!("{rc:#x}"));
                let _ = writeln!(out, "    // - {} answered {rc}.", d.implementation.name());
            }
            let _ = writeln!(
                out,
                "    // TODO(triage): assert the specified behavior (fix tpm-rs, patch the reference,\n    \
                 // or add a documented exception), e.g. the reference's response code:"
            );
            if let Some(rc) = expected {
                let _ = writeln!(out, "    assert_eq!(response_code(&rsp), {rc:#x});");
            }
        }
        Outcome::Finding(Finding::Malformed { reason, .. })
        | Outcome::Finding(Finding::Unparseable { reason, .. }) => {
            let _ = writeln!(out, "    // The tpm-rs response is wrong: {reason}");
            let _ = writeln!(
                out,
                "    // TODO(triage): assert the specified response (it must be well formed and parse)."
            );
        }
        Outcome::Panic(message) => {
            let _ = writeln!(
                out,
                "    // The fuzz driver panicked here: {}",
                message.lines().next().unwrap_or_default()
            );
            let _ = writeln!(out, "    // TODO(triage): assert the specified response.");
        }
        Outcome::Executed(_) | Outcome::Skipped => {}
    }
    out
}

/// Renders the replayed rounds as an E2E test named `name`; `source` names
/// the fuzzer input in the doc comment.
fn render_test(name: &str, source: &str, rounds: &[Replayed]) -> String {
    let finding = rounds.last().and_then(|r| finding_summary(&r.outcome));
    let mut out = String::new();
    let _ = writeln!(
        out,
        "/// TODO: describe the behavior under test (GEMINI.md naming and doc rules)."
    );
    let _ = writeln!(out, "///");
    let _ = writeln!(
        out,
        "/// Found by the `diff_conversation` fuzzer (input `{source}`, {} round(s){}).",
        rounds.len(),
        finding
            .as_deref()
            .map(|f| format!(", `{f}`"))
            .unwrap_or_default()
    );
    let _ = writeln!(
        out,
        "/// The command bytes are resolved under the fuzzer's fixed reference seed, so the\n\
         /// responses (including every random value) are reproducible."
    );
    let _ = writeln!(out, "#[test]");
    let _ = writeln!(out, "fn {name}() {{");
    let _ = writeln!(
        out,
        "    let response_code = |rsp: &[u8]| u32::from_be_bytes(rsp[6..10].try_into().unwrap());"
    );
    let _ = writeln!(
        out,
        "    let mut tpm = testing::tpm::Tpm::with_seed(testing::seed::ReferenceSeed {{\n        \
         pid: {},\n        realtime_ms: {},\n    }});",
        FIXED_SEED.pid, FIXED_SEED.realtime_ms
    );
    for (i, r) in rounds.iter().enumerate() {
        let label = command_label(&r.command);
        let _ = writeln!(out);
        match &r.outcome {
            Outcome::Skipped => {
                let _ = writeln!(
                    out,
                    "    // Round {i}: {label}, rejected at the transport level."
                );
                let _ = write!(
                    out,
                    "    assert!(tpm\n        .try_send_command(\n            0,\n            &[\n"
                );
                let _ = write!(out, "{}", byte_lines(&r.command, 16));
                let _ = writeln!(out, "            ],\n        )\n        .is_err());");
            }
            Outcome::Executed(rc) => {
                let _ = writeln!(out, "    // Round {i}: {label}.");
                let _ = write!(
                    out,
                    "    let rsp = tpm.send_command(\n        0,\n        &[\n"
                );
                let _ = write!(out, "{}", byte_lines(&r.command, 12));
                let _ = writeln!(out, "        ],\n    );");
                let _ = writeln!(out, "    assert_eq!(response_code(&rsp), {rc:#x});");
            }
            Outcome::Finding(_) | Outcome::Panic(_) => {
                let _ = writeln!(out, "    // Round {i}: {label}: the finding.");
                let _ = write!(
                    out,
                    "    let rsp = tpm.send_command(\n        0,\n        &[\n"
                );
                let _ = write!(out, "{}", byte_lines(&r.command, 12));
                let _ = writeln!(out, "        ],\n    );");
                let _ = write!(out, "{}", finding_lines(r));
            }
        }
    }
    let _ = writeln!(out, "}}");
    out
}

/// The command line options.
struct Options {
    /// The test name (`--name`), if given.
    name: Option<String>,
    /// The fuzzer input.
    input: String,
}

/// Parses the command line.
fn parse_args(args: &[String]) -> Result<Options, String> {
    let usage = "usage: to_test [--name <test fn name>] <crash file>";
    let mut name = None;
    let mut input = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--name" => name = Some(it.next().ok_or(usage)?.clone()),
            _ if input.is_none() => input = Some(arg.clone()),
            _ => return Err(usage.into()),
        }
    }
    Ok(Options {
        name,
        input: input.ok_or(usage)?,
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opts = match parse_args(&args) {
        Ok(opts) => opts,
        Err(e) => {
            eprintln!("to_test: {e}");
            return ExitCode::FAILURE;
        }
    };
    let data = match std::fs::read(&opts.input) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("to_test: {}: {e}", opts.input);
            return ExitCode::FAILURE;
        }
    };
    let conv = Conversation::from_bytes(&data);
    let mut tpm = Tpm::with_seed(FIXED_SEED);
    let rounds = replay::replay(&mut tpm, &conv);
    let source = Path::new(&opts.input)
        .file_name()
        .map_or(opts.input.clone(), |n| n.to_string_lossy().into_owned());
    let name = opts.name.unwrap_or_else(|| default_name(&rounds));
    print!("{}", render_test(&name, &source, &rounds));
    if rounds.last().is_none_or(|r| !r.is_final()) {
        eprintln!("to_test: note: the input replayed without a finding");
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpm2_fuzz::model::{Cmd, Segment, Step};

    /// Snake case handles camel case, acronyms and underscores.
    #[test]
    fn snake_case_names() {
        assert_eq!(snake_case("CreatePrimary"), "create_primary");
        assert_eq!(snake_case("NV_Write"), "nv_write");
        assert_eq!(snake_case("PCR_Extend"), "pcr_extend");
        assert_eq!(snake_case("HMAC_Start"), "hmac_start");
        assert_eq!(snake_case("ECC_Parameters"), "ecc_parameters");
    }

    /// Commands are labeled by their specification names.
    #[test]
    fn command_labels() {
        let get_random = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x7B, 0, 16];
        assert_eq!(command_label(&get_random), "TPM2_GetRandom");
        assert_eq!(
            command_label(&[0x80]),
            "a command without a complete header"
        );
        let unknown = [0x80, 0x01, 0, 0, 0, 10, 0x12, 0x34, 0x56, 0x78];
        assert_eq!(command_label(&unknown), "command code 0x12345678");
    }

    /// Byte arrays are printed twelve per line with the given indentation.
    #[test]
    fn byte_formatting() {
        let text = byte_lines(&(0..13).collect::<Vec<u8>>(), 4);
        assert_eq!(
            text,
            "    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,\n    0x0c,\n"
        );
    }

    /// The command line takes an optional name and one input.
    #[test]
    fn argument_parsing() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(parse_args(&args(&[])).is_err());
        assert!(parse_args(&args(&["a", "b"])).is_err());
        let opts = parse_args(&args(&["--name", "x", "crash"])).unwrap();
        assert_eq!(opts.name.as_deref(), Some("x"));
        assert_eq!(opts.input, "crash");
    }

    /// A replayed conversation renders as a test that sends the resolved
    /// bytes and asserts the response codes, and replaying the rendered
    /// rounds' bytes directly gives the same responses.
    #[test]
    fn renders_a_replayed_conversation() {
        let mut get_random = Cmd::new(0x17B);
        get_random.params = vec![Segment::Bytes(vec![0, 8])];
        let conv = Conversation {
            steps: vec![
                Step::Cmd(get_random),
                Step::Raw(vec![0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x7B]),
            ],
        };
        let mut tpm = Tpm::with_seed(FIXED_SEED);
        let rounds = replay::replay(&mut tpm, &conv);
        assert_eq!(rounds.len(), 2);
        let text = render_test("get_random_sizes", "crash-1", &rounds);
        assert!(text.contains("fn get_random_sizes() {"), "{text}");
        assert!(text.contains("// Round 0: TPM2_GetRandom."), "{text}");
        assert!(
            text.contains("assert_eq!(response_code(&rsp), 0x0);"),
            "{text}"
        );
        assert!(text.contains("pid: 4242,"), "{text}");
        assert!(
            text.contains(
                "0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x7b, 0x00, 0x08,"
            )
        );
        assert_eq!(default_name(&rounds), "get_random_matches_reference");
        // The printed bytes are the resolved commands: sending them to a
        // fresh TPM with the same seed reproduces the responses.
        let mut fresh = Tpm::with_seed(FIXED_SEED);
        for r in &rounds {
            assert_eq!(fresh.send_command(0, &r.command), r.response);
        }
    }
}
