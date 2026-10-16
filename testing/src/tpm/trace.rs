//! The opt-in trace recorder of [`super::Tpm`] (`TPM_FUZZ_RECORD_DIR`).
//!
//! With [`RECORD_DIR_ENV`] set to a directory, every `Tpm` writes everything
//! it is asked to do, together with every `tpm-rs` response, to its own file
//! in that directory. The traces of the E2E and Go parity suites seed the
//! corpus of the differential fuzzer (`testing/fuzz/`), whose converter reads
//! them with [`parse`].
//!
//! # Format (`v1`)
//!
//! One UTF-8 text file per `Tpm`, named
//! `<test>-<pid>-<n>.trace`: `<test>` is the name of the thread that created
//! the `Tpm` (the test name) with every character outside `[A-Za-z0-9_.-]`
//! replaced by `_`, `<pid>` the ID of the test process and `<n>` a counter of
//! the process's `Tpm`s. Every line ends with `\n`; fields are separated by
//! single spaces and byte strings are lowercase hex (an empty byte string is
//! an empty field, i.e. the line ends with the separating space).
//!
//! The first line is the header
//! `# tpm-rs-trace v1 seed=<pid>:<realtime_ms> test=<thread name>` (the seed
//! of the `Tpm`, see [`crate::seed`]; the test name extends to the end of the
//! line). The `Tpm` starts powered on, with NV available and
//! `TPM2_Startup(TPM_SU_CLEAR)` done. Every following line is one event, in
//! order:
//!
//! * `C <locality> <command>` followed by the line `R <response>`: a command
//!   (sent raw, typed or through `tpm2::Connection`) and the `tpm-rs`
//!   response to it (empty while the TPM is powered off). The pair is
//!   written before the command is mirrored to the references, so the trace
//!   of a diverging test ends with the diverging command;
//! * `X <locality> <command>`: a command the simulator rejected at the
//!   transport level (not executed, not mirrored);
//! * `S <signal>`: a platform signal (the `SimulatorPlatformSignal` variant
//!   name, e.g. `PowerOff`);
//! * `H start`, `H data <bytes>`, `H end`: the `_TPM_Hash_*` indications;
//! * `T <ms>`: the virtual clocks advanced by `<ms>` milliseconds (written
//!   when the advance is applied, i.e. right before the event it precedes);
//! * `Z`: the `Tpm` was reset ([`super::Tpm::reset`]): it is again fresh and
//!   started, with the same seed.
//!
//! Every event is written with one `write` call as it happens, so the trace
//! of a test that panics is complete up to the panic.

use std::fmt::Write as _;
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::seed::ReferenceSeed;

/// Environment variable naming the directory every `Tpm` records its trace
/// in (see the module docs); unset or empty: no traces are recorded.
pub const RECORD_DIR_ENV: &str = "TPM_FUZZ_RECORD_DIR";

/// The first word after `#` in the header line, with the format version.
const MAGIC: &str = "tpm-rs-trace v1";

/// One recorded event (see the module docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A command and the `tpm-rs` response (`C` + `R` lines).
    Command {
        /// The locality the command was sent at.
        locality: u8,
        /// The command bytes.
        command: Vec<u8>,
        /// The `tpm-rs` response bytes.
        response: Vec<u8>,
    },
    /// A command rejected at the transport level (`X`).
    Rejected {
        /// The locality the command was sent at.
        locality: u8,
        /// The command bytes.
        command: Vec<u8>,
    },
    /// A platform signal, by `SimulatorPlatformSignal` variant name (`S`).
    Signal(String),
    /// `_TPM_Hash_Start` (`H start`).
    HashStart,
    /// `_TPM_Hash_Data` (`H data`).
    HashData(Vec<u8>),
    /// `_TPM_Hash_End` (`H end`).
    HashEnd,
    /// A virtual clock advance in milliseconds (`T`).
    AdvanceClock(u64),
    /// A [`super::Tpm::reset`] (`Z`).
    Reset,
}

/// A parsed trace file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trace {
    /// The seed of the recorded `Tpm`.
    pub seed: ReferenceSeed,
    /// The test (thread) name of the header.
    pub test: String,
    /// The events, in order.
    pub events: Vec<Event>,
}

/// Lowercase hex encoding.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 * bytes.len());
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decodes lowercase or uppercase hex.
fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("odd-length hex `{s}`"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            s.get(i..i + 2)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| format!("invalid hex `{s}`"))
        })
        .collect()
}

/// The text of `event` (one or two lines, each ending with `\n`).
pub fn format_event(event: &Event) -> String {
    match event {
        Event::Command {
            locality,
            command,
            response,
        } => format!("C {locality} {}\nR {}\n", hex(command), hex(response)),
        Event::Rejected { locality, command } => format!("X {locality} {}\n", hex(command)),
        Event::Signal(name) => format!("S {name}\n"),
        Event::HashStart => "H start\n".into(),
        Event::HashData(data) => format!("H data {}\n", hex(data)),
        Event::HashEnd => "H end\n".into(),
        Event::AdvanceClock(ms) => format!("T {ms}\n"),
        Event::Reset => "Z\n".into(),
    }
}

/// The header line of a trace (ending with `\n`).
pub fn format_header(seed: ReferenceSeed, test: &str) -> String {
    format!("# {MAGIC} seed={seed} test={test}\n")
}

/// `name` with every character outside `[A-Za-z0-9_.-]` replaced by `_`.
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Parses a trace (see the module docs).
pub fn parse(text: &str) -> Result<Trace, String> {
    let mut lines = text.lines().enumerate();
    let (_, header) = lines.next().ok_or("empty trace")?;
    let rest = header
        .strip_prefix("# ")
        .and_then(|h| h.strip_prefix(MAGIC))
        .and_then(|h| h.strip_prefix(" seed="))
        .ok_or_else(|| format!("not a `{MAGIC}` header: `{header}`"))?;
    let (seed, test) = rest
        .split_once(" test=")
        .ok_or_else(|| format!("header without `test=`: `{header}`"))?;
    let seed = ReferenceSeed::parse(seed)?;
    let mut events = Vec::new();
    while let Some((n, line)) = lines.next() {
        let err = |e: String| format!("line {}: {e}: `{line}`", n + 1);
        let (kind, args) = line.split_once(' ').unwrap_or((line, ""));
        let locality_and_command = || -> Result<(u8, Vec<u8>), String> {
            let (locality, command) = args.split_once(' ').unwrap_or((args, ""));
            let locality = locality
                .parse()
                .map_err(|_| format!("invalid locality `{locality}`"))?;
            Ok((locality, unhex(command)?))
        };
        let event = match kind {
            "C" => {
                let (locality, command) = locality_and_command().map_err(err)?;
                let (_, response_line) = lines
                    .next()
                    .ok_or_else(|| err("command without an `R` line".into()))?;
                let response = response_line
                    .strip_prefix("R ")
                    .or_else(|| (response_line == "R").then_some(""))
                    .ok_or_else(|| err(format!("expected an `R` line, got `{response_line}`")))?;
                Event::Command {
                    locality,
                    command,
                    response: unhex(response).map_err(err)?,
                }
            }
            "X" => {
                let (locality, command) = locality_and_command().map_err(err)?;
                Event::Rejected { locality, command }
            }
            "S" if !args.is_empty() => Event::Signal(args.to_owned()),
            "H" => match args.split_once(' ').unwrap_or((args, "")) {
                ("start", "") => Event::HashStart,
                ("data", data) => Event::HashData(unhex(data).map_err(err)?),
                ("end", "") => Event::HashEnd,
                _ => return Err(err("invalid `H` event".into())),
            },
            "T" => Event::AdvanceClock(
                args.parse()
                    .map_err(|_| err("invalid milliseconds".into()))?,
            ),
            "Z" if args.is_empty() => Event::Reset,
            _ => return Err(err("unknown event".into())),
        };
        events.push(event);
    }
    Ok(Trace {
        seed,
        test: test.to_owned(),
        events,
    })
}

/// Reads and parses the trace file at `path`.
pub fn read(path: &Path) -> Result<Trace, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// The trace file of one `Tpm`.
pub struct Recorder {
    file: File,
    path: PathBuf,
}

impl Recorder {
    /// A recorder for a new `Tpm` with `seed` if [`RECORD_DIR_ENV`] is set
    /// (creating the directory if needed); `None` otherwise.
    ///
    /// # Panics
    /// If the directory or the file cannot be created.
    pub fn from_env(seed: ReferenceSeed) -> Option<Self> {
        let dir = std::env::var_os(RECORD_DIR_ENV).filter(|d| !d.is_empty())?;
        Some(Self::create(Path::new(&dir), seed))
    }

    /// Creates a new trace file for a `Tpm` with `seed` in `dir` (see the
    /// module docs for its name) and writes the header.
    ///
    /// # Panics
    /// If the directory or the file cannot be created or written.
    pub fn create(dir: &Path, seed: ReferenceSeed) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let test = std::thread::current()
            .name()
            .unwrap_or("<unnamed>")
            .to_owned();
        std::fs::create_dir_all(dir)
            .unwrap_or_else(|e| panic!("{RECORD_DIR_ENV}: cannot create {}: {e}", dir.display()));
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!(
            "{}-{}-{n}.trace",
            sanitize(&test),
            std::process::id()
        ));
        let file = File::create(&path)
            .unwrap_or_else(|e| panic!("{RECORD_DIR_ENV}: cannot create {}: {e}", path.display()));
        let mut recorder = Self { file, path };
        recorder.write(&format_header(seed, &test));
        recorder
    }

    /// The path of the trace file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends `event`.
    ///
    /// # Panics
    /// If the file cannot be written.
    pub fn record(&mut self, event: &Event) {
        self.write(&format_event(event));
    }

    fn write(&mut self, text: &str) {
        self.file
            .write_all(text.as_bytes())
            .unwrap_or_else(|e| panic!("cannot write {}: {e}", self.path.display()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_events() -> Vec<Event> {
        vec![
            Event::Command {
                locality: 0,
                command: vec![0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x7B, 0, 16],
                response: vec![0x80, 0x01, 0, 0, 0, 10, 0, 0, 0, 0],
            },
            Event::Command {
                locality: 3,
                command: vec![0xAB],
                response: vec![],
            },
            Event::Rejected {
                locality: 4,
                command: vec![1, 2, 3],
            },
            Event::Rejected {
                locality: 0,
                command: vec![],
            },
            Event::Signal("PowerOff".into()),
            Event::HashStart,
            Event::HashData(vec![0xde, 0xad]),
            Event::HashData(vec![]),
            Event::HashEnd,
            Event::AdvanceClock(1500),
            Event::Reset,
        ]
    }

    #[test]
    fn events_round_trip_through_the_text_format() {
        let seed = ReferenceSeed {
            pid: 4242,
            realtime_ms: 1_000_000,
        };
        let mut text = format_header(seed, "e2e::topic::name with space");
        for event in all_events() {
            text.push_str(&format_event(&event));
        }
        let trace = parse(&text).unwrap();
        assert_eq!(trace.seed, seed);
        assert_eq!(trace.test, "e2e::topic::name with space");
        assert_eq!(trace.events, all_events());
    }

    #[test]
    fn the_format_is_the_documented_one() {
        let text: String = all_events()[..3].iter().map(format_event).collect();
        assert_eq!(
            text,
            "C 0 80010000000c0000017b0010\nR 80010000000a00000000\nC 3 ab\nR \nX 4 010203\n"
        );
        assert_eq!(
            format_header(
                ReferenceSeed {
                    pid: 1,
                    realtime_ms: 2
                },
                "t"
            ),
            "# tpm-rs-trace v1 seed=1:2 test=t\n"
        );
    }

    #[test]
    fn malformed_traces_are_rejected() {
        let header = "# tpm-rs-trace v1 seed=1:2 test=t\n";
        assert!(parse("").is_err());
        assert!(parse("# tpm-rs-trace v2 seed=1:2 test=t\n").is_err());
        assert!(parse("# tpm-rs-trace v1 seed=1:2\n").is_err());
        for body in [
            "C 0 0102\n",
            "C 0 0102\nX 0 01\n",
            "C 0 012\nR \n",
            "C x 01\nR \n",
            "H middle\n",
            "T -1\n",
            "Q\n",
            "Z now\n",
            "S\n",
        ] {
            assert!(parse(&format!("{header}{body}")).is_err(), "{body:?}");
        }
    }

    #[test]
    fn file_names_are_sanitized() {
        assert_eq!(sanitize("e2e::a b/c-d.e_f"), "e2e__a_b_c-d.e_f");
    }

    #[test]
    fn a_recorder_writes_a_parsable_file() {
        let dir = tempfile_dir();
        let seed = ReferenceSeed {
            pid: 7,
            realtime_ms: 8,
        };
        let mut recorder = Recorder::create(&dir, seed);
        for event in all_events() {
            recorder.record(&event);
        }
        let trace = read(recorder.path()).unwrap();
        assert_eq!(trace.seed, seed);
        assert_eq!(trace.events, all_events());
        let name = recorder.path().file_name().unwrap().to_str().unwrap();
        assert!(name.ends_with(".trace"), "{name}");
        assert!(
            name.contains(&format!("-{}-", std::process::id())),
            "{name}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A fresh directory under the system temporary directory.
    fn tempfile_dir() -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        std::env::temp_dir().join(format!(
            "tpm-rs-trace-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ))
    }
}
