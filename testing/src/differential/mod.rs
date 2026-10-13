//! Differential testing against C reference TPMs (`differential` feature).
//!
//! Every [`crate::tpm::Tpm`] owns one [`Reference`] per enabled
//! [`Implementation`]: a child process (the `mstpm20` or `ibmswtpm2` binary
//! of this crate, `src/bin/`) that hosts its own instance of a patched C
//! reference TPM:
//!
//! * [`Implementation::Mstpm20`]: the TCG reference implementation
//!   (`https://github.com/TrustedComputingGroup/TPM`, the Microsoft
//!   `ms-tpm-20-ref` code base), patched by `testing/mstpm20.patch`;
//! * [`Implementation::Ibmswtpm2`]: the IBM software TPM
//!   (`https://github.com/kgoldman/ibmswtpm2`), patched by
//!   `testing/ibmswtpm2.patch`.
//!
//! Both keep their state in globals, so one process per TPM is what lets
//! tests run in parallel and a single test use several TPMs.
//!
//! The `Tpm` mirrors every interaction to its references over the children's
//! stdin/stdout pipes ([`protocol`]): commands together with the response
//! `tpm-rs` gave (the child executes the command on its C reference and
//! compares the responses, see [`server`] and `differential.md`), platform
//! signals, `_TPM_Hash_*` indications and virtual-clock advances. Every
//! request is answered; an error reply (an undocumented difference, or an
//! interaction the C reference does not support) panics in the test at the
//! diverging interaction.
//!
//! The references to run are selected with the `DIFFERENTIAL_REFERENCES`
//! environment variable (a comma-separated list of `mstpm20`/`ibmswtpm2`;
//! default: both). A reference binary is located through its environment
//! variable (`MSTPM20_BIN`, `IBMSWTPM2_BIN`) or, by default, next to the
//! running test executable (in it or in one of its ancestor directories,
//! e.g. `target/release/mstpm20`); `cargo test -p testing --features
//! differential` builds both automatically.

use std::fmt;
use std::io::{BufReader, BufWriter, Write as _};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::OnceLock;

use tpm2_simulator::SimulatorPlatformSignal;

use self::protocol::Request;

pub mod protocol;
pub mod server;

/// A C reference TPM implementation that `tpm-rs` is compared with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Implementation {
    /// The TCG (Microsoft) reference implementation, binary `mstpm20`.
    Mstpm20,
    /// The IBM software TPM, binary `ibmswtpm2`.
    Ibmswtpm2,
}

impl Implementation {
    /// Every implementation, in the order `tpm-rs` responses are compared.
    pub const ALL: [Self; 2] = [Self::Mstpm20, Self::Ibmswtpm2];

    /// The name of the implementation, which is also the name of its
    /// reference binary.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mstpm20 => "mstpm20",
            Self::Ibmswtpm2 => "ibmswtpm2",
        }
    }

    /// The environment variable that overrides the path of the reference
    /// binary.
    pub const fn binary_env(self) -> &'static str {
        match self {
            Self::Mstpm20 => "MSTPM20_BIN",
            Self::Ibmswtpm2 => "IBMSWTPM2_BIN",
        }
    }

    /// Parses an implementation name (see [`Self::name`]).
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|i| i.name() == name)
    }

    /// The implementations selected by `DIFFERENTIAL_REFERENCES` (see the
    /// module docs).
    ///
    /// # Panics
    /// If the variable names an unknown implementation or none at all.
    pub fn enabled() -> &'static [Self] {
        static ENABLED: OnceLock<Vec<Implementation>> = OnceLock::new();
        ENABLED.get_or_init(|| match std::env::var(REFERENCES_ENV) {
            Err(_) => Self::ALL.to_vec(),
            Ok(list) => {
                let mut enabled = Vec::new();
                for name in list.split(',').map(str::trim).filter(|n| !n.is_empty()) {
                    let implementation = Self::from_name(name).unwrap_or_else(|| {
                        panic!(
                            "{REFERENCES_ENV}: unknown reference `{name}` (expected a \
                             comma-separated list of mstpm20, ibmswtpm2)"
                        )
                    });
                    if !enabled.contains(&implementation) {
                        enabled.push(implementation);
                    }
                }
                assert!(!enabled.is_empty(), "{REFERENCES_ENV} selects no reference");
                enabled
            }
        })
    }
}

impl fmt::Display for Implementation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.name())
    }
}

/// Environment variable selecting the references (see the module docs).
pub const REFERENCES_ENV: &str = "DIFFERENTIAL_REFERENCES";

/// Locates the binary of `implementation` (see the module docs).
fn locate_binary(implementation: Implementation) -> PathBuf {
    let env = implementation.binary_env();
    if let Some(path) = std::env::var_os(env) {
        return PathBuf::from(path);
    }
    let name = implementation.name();
    let exe = std::env::current_exe().expect("cannot locate the test executable");
    exe.ancestors()
        .skip(1)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| {
            panic!(
                "cannot find the `{name}` binary near {}; build it with `cargo build \
                 --release -p testing --features differential --bin {name}` or set {env}",
                exe.display()
            )
        })
}

/// The path of the binary of `implementation`, located once.
fn reference_binary(implementation: Implementation) -> &'static PathBuf {
    static BINARIES: [OnceLock<PathBuf>; Implementation::ALL.len()] =
        [const { OnceLock::new() }; Implementation::ALL.len()];
    BINARIES[implementation as usize].get_or_init(|| locate_binary(implementation))
}

/// A reference child process hosting a C reference TPM that mirrors one
/// [`crate::tpm::Tpm`] (see the module docs).
pub struct Reference {
    /// The implementation the process hosts.
    implementation: Implementation,
    child: Child,
    /// The child's stdin; `None` once closed (on drop).
    requests: Option<BufWriter<ChildStdin>>,
    replies: BufReader<ChildStdout>,
    /// Name of the owning test (thread), for diagnostics.
    test: String,
}

impl Reference {
    /// The implementation this process hosts.
    pub fn implementation(&self) -> Implementation {
        self.implementation
    }

    /// Launches a reference process of `implementation`, whose C reference
    /// TPM is initialized like a new `Tpm` (powered on, NV on,
    /// `TPM2_Startup(TPM_SU_CLEAR)` done).
    ///
    /// # Panics
    /// If the process cannot be started or the C reference fails to
    /// initialize.
    pub fn launch(implementation: Implementation) -> Self {
        let mut reference = Self::spawn(implementation);
        reference.finish("start-up");
        reference
    }

    /// Starts a reference process without waiting for its start-up reply.
    fn spawn(implementation: Implementation) -> Self {
        let test = std::thread::current()
            .name()
            .unwrap_or("<unnamed>")
            .to_owned();
        let binary = reference_binary(implementation);
        let mut child = Command::new(binary)
            .arg(&test)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap_or_else(|e| panic!("cannot start {}: {e}", binary.display()));
        let requests = child.stdin.take().map(BufWriter::new);
        let replies = BufReader::new(child.stdout.take().expect("piped stdout"));
        Self {
            implementation,
            child,
            requests,
            replies,
            test,
        }
    }

    /// Reads the reply to the last request.
    ///
    /// # Panics
    /// On an error reply, or if the process died.
    fn finish(&mut self, what: &str) {
        if let Err(message) = self.try_finish(what) {
            panic!("{message}");
        }
    }

    /// Reads the reply to the last request; the error message of an error
    /// reply or of a dead process.
    fn try_finish(&mut self, what: &str) -> Result<(), String> {
        match protocol::read_reply(&mut self.replies) {
            Ok(result) => result,
            Err(e) => Err(format!(
                "test `{}`: the {} reference TPM process failed during {what} ({e}; {})",
                self.test,
                self.implementation,
                match self.child.try_wait() {
                    Ok(Some(status)) => format!("exited with {status}"),
                    _ => "still running".into(),
                }
            )),
        }
    }

    /// Sends `request` without waiting for its reply.
    ///
    /// # Panics
    /// If the process cannot be written to.
    fn send(&mut self, request: &Request) {
        let requests = self
            .requests
            .as_mut()
            .expect("reference process stdin is open");
        if let Err(e) = protocol::write_request(requests, request).and_then(|()| requests.flush()) {
            panic!(
                "test `{}`: cannot send {request:?} to the {} reference TPM process: {e}",
                self.test, self.implementation
            );
        }
    }
}

impl Drop for Reference {
    fn drop(&mut self) {
        // Closing stdin ends the process.
        drop(self.requests.take());
        let _ = self.child.wait();
    }
}

/// What a request is, for diagnostics.
fn describe(request: &Request) -> &'static str {
    match request {
        Request::Exchange { .. } => "a command",
        Request::AdvanceClock(_) => "a clock advance",
        Request::Signal(_) => "a platform signal",
        Request::HashStart | Request::HashData(_) | Request::HashEnd => "a _TPM_Hash indication",
    }
}

/// The reference processes mirroring one [`crate::tpm::Tpm`], one per
/// enabled [`Implementation`].
///
/// Every interaction is sent to all references before any reply is awaited,
/// so the references work concurrently.
pub struct References(Vec<Reference>);

impl References {
    /// Launches one reference process per enabled implementation (see
    /// [`Implementation::enabled`] and [`Reference::launch`]).
    ///
    /// # Panics
    /// If a process cannot be started or its C reference fails to
    /// initialize.
    pub fn launch() -> Self {
        let mut references: Vec<Reference> = Implementation::enabled()
            .iter()
            .map(|&i| Reference::spawn(i))
            .collect();
        let errors: Vec<String> = references
            .iter_mut()
            .filter_map(|reference| reference.try_finish("start-up").err())
            .collect();
        if !errors.is_empty() {
            panic!("{}", errors.join("\n\n"));
        }
        Self(references)
    }

    /// The reference processes.
    pub fn iter(&self) -> impl Iterator<Item = &Reference> {
        self.0.iter()
    }

    /// Sends `request` to every reference and waits for all replies.
    ///
    /// # Panics
    /// On any error reply (reporting every reference's error), or if a
    /// process died.
    fn call(&mut self, request: Request) {
        for reference in &mut self.0 {
            reference.send(&request);
        }
        let what = describe(&request);
        let errors: Vec<String> = self
            .0
            .iter_mut()
            .filter_map(|reference| reference.try_finish(what).err())
            .collect();
        if !errors.is_empty() {
            panic!("{}", errors.join("\n\n"));
        }
    }

    /// Advances the references' virtual clocks by `ms` milliseconds.
    pub fn advance_clock(&mut self, ms: u64) {
        self.call(Request::AdvanceClock(ms));
    }

    /// Delivers a platform signal to the references.
    ///
    /// # Panics
    /// For signals the reference harness does not support (`Restart`,
    /// `TestFailureMode`, `SetFirmwareHash`, `SetFirmwareSvn`).
    pub fn signal(&mut self, signal: SimulatorPlatformSignal) {
        self.call(Request::Signal(signal as u32));
    }

    /// Sends `_TPM_Hash_Start` to the references.
    pub fn hash_start(&mut self) {
        self.call(Request::HashStart);
    }

    /// Sends `_TPM_Hash_Data(data)` to the references.
    pub fn hash_data(&mut self, data: &[u8]) {
        self.call(Request::HashData(data.to_vec()));
    }

    /// Sends `_TPM_Hash_End` to the references.
    pub fn hash_end(&mut self) {
        self.call(Request::HashEnd);
    }

    /// Executes `command` (which `tpm-rs` answered with `expected`) on every
    /// reference at `locality`; each reference compares its response with
    /// `expected`.
    ///
    /// # Panics
    /// If a reference's response differs other than as documented.
    pub fn exchange(&mut self, locality: u8, command: &[u8], expected: &[u8]) {
        self.call(Request::Exchange {
            locality,
            command: command.to_vec(),
            expected: expected.to_vec(),
        });
    }
}
