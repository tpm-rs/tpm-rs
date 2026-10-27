//! Differential testing against C reference TPMs (`differential` feature).
//!
//! Every [`crate::tpm::Tpm`] owns one [`Reference`]: a child process (the
//! `mstpm20` or `ibmswtpm2` binary of this crate, `src/bin/`) that hosts its
//! own instance of a patched C reference TPM:
//!
//! * [`Implementation::Mstpm20`]: the TCG reference implementation
//!   (the Microsoft `ms-tpm-20-ref` code base): version 185 of the
//!   TCG-internal `https://github.com/TrustedComputingGroup/TPM-Internal`,
//!   patched by `testing/patches/mstpm20-185-feature/`, when the user's `git` may
//!   clone it, and otherwise `https://github.com/TrustedComputingGroup/TPM`,
//!   patched by `testing/patches/mstpm20/` (see `testing/build.rs`);
//! * [`Implementation::Ibmswtpm2`]: the IBM software TPM
//!   (`https://github.com/kgoldman/ibmswtpm2`), patched by
//!   `testing/patches/ibmswtpm2/`.
//!
//! Both keep their state in globals, so one process per TPM is what lets
//! tests run in parallel and a single test use several TPMs.
//!
//! The C references run their own, unmodified random number generation:
//! glibc `rand()` seeded from their real-time clock and their process ID,
//! feeding their DRBG. Right after start-up, the reference process reports
//! its process ID and initial real time ([`protocol::Handshake`]), and the
//! `Tpm` builds its `tpm-rs` simulator to reproduce exactly that randomness
//! (`tpm2_simulator::create_reference_simulator!`). Since the randomness
//! depends on the process ID, a `Tpm` can be compared with only one
//! reference. Setting `TPM_REFERENCE_SEED=<pid>:<realtime_ms>` (see
//! [`crate::seed`]) fixes both values for the reference process (its
//! `getpid()` is redirected to `difftest_getpid` at link time by
//! `build.rs`) and for `tpm-rs`, which reproduces a run.
//!
//! The `Tpm` mirrors every interaction to its reference over the child's
//! stdin/stdout pipes ([`protocol`]): commands together with the response
//! `tpm-rs` gave (the child executes the command on its C reference and
//! compares the responses, see [`server`] and `differential.md`), platform
//! signals, `_TPM_Hash_*` indications and virtual-clock advances. Every
//! request is answered; an error reply (an undocumented difference, or an
//! interaction the C reference does not support) panics in the test at the
//! diverging interaction. [`References::try_exchange`] reports a diverging
//! command as [`Divergence`]s instead (with each reference's response), and
//! [`References::reinit`] re-initializes the existing processes like new
//! ones with the same seed (`Reinit`), which is much cheaper than launching
//! new processes (e.g. once per fuzz input).
//!
//! The references are selected with the `DIFFERENTIAL_REFERENCES`
//! environment variable (a comma-separated list of implementation names);
//! unset, every `Tpm` is mirrored to `mstpm20` and `ibmswtpm2`. A reference
//! binary is located through its environment variable (`MSTPM20_BIN`,
//! `IBMSWTPM2_BIN`) or, by default, next to the running test executable (in
//! it or in one of its ancestor directories, e.g. `target/release/mstpm20`);
//! `cargo test -p testing --features differential` builds them
//! automatically.

use std::fmt;
use std::io::{BufReader, BufWriter, Write as _};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::OnceLock;

use tpm2_simulator::SimulatorPlatformSignal;

use self::protocol::{Failure, Request};
use crate::seed::{ReferenceSeed, SEED_ENV};

pub mod inproc;
pub mod protocol;
pub mod server;

/// A reference TPM whose response to a command differs from the `tpm-rs`
/// response other than as documented, or that failed to execute it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Divergence {
    /// The diverging reference.
    pub implementation: Implementation,
    /// The reference's response; `None` if it has none (the process died or
    /// the failure was not a response difference).
    pub reference_response: Option<Vec<u8>>,
    /// The diagnostic message (with both responses for a difference).
    pub message: String,
}

impl fmt::Display for Divergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// A C reference TPM implementation that `tpm-rs` is compared with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Implementation {
    /// The TCG (Microsoft) reference implementation, binary `mstpm20`.
    Mstpm20,
    /// The IBM software TPM, binary `ibmswtpm2`.
    Ibmswtpm2,
}

impl Implementation {
    /// Every implementation.
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
}

/// The references every `Tpm` is mirrored to, selected by
/// `DIFFERENTIAL_REFERENCES` (see the module docs): every implementation by
/// default.
///
/// # Panics
/// If the variable names an unknown implementation.
pub fn selected() -> &'static [Implementation] {
    static SELECTED: OnceLock<Vec<Implementation>> = OnceLock::new();
    SELECTED.get_or_init(|| {
        let value = std::env::var(REFERENCES_ENV).unwrap_or_default();
        parse_selection(&value).unwrap_or_else(|e| panic!("{e}"))
    })
}

/// Parses a `DIFFERENTIAL_REFERENCES` value: a comma-separated list of
/// implementation names (surrounding whitespace and duplicates are ignored;
/// an empty value means every implementation).
pub fn parse_selection(value: &str) -> Result<Vec<Implementation>, String> {
    let mut selected = Vec::new();
    for name in value.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        let implementation = Implementation::from_name(name).ok_or_else(|| {
            format!(
                "{REFERENCES_ENV}: unknown reference `{name}` (expected mstpm20 and/or ibmswtpm2)"
            )
        })?;
        if !selected.contains(&implementation) {
            selected.push(implementation);
        }
    }
    if selected.is_empty() {
        selected = Implementation::ALL.to_vec();
    }
    Ok(selected)
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

    /// Launches a reference process of `implementation` seeded with `seed`,
    /// whose C reference TPM is initialized like a new `Tpm` (powered on, NV
    /// on, `TPM2_Startup(TPM_SU_CLEAR)` done).
    ///
    /// # Panics
    /// If the process cannot be started, its handshake is invalid or the C
    /// reference fails to initialize.
    pub fn launch(implementation: Implementation, seed: ReferenceSeed) -> Self {
        let mut reference = Self::spawn(implementation, seed);
        reference.finish("start-up");
        reference
    }

    /// Starts a reference process seeded with `seed` (passed as
    /// [`SEED_ENV`] in its environment) and checks its handshake, without
    /// waiting for its start-up reply.
    fn spawn(implementation: Implementation, seed: ReferenceSeed) -> Self {
        let test = std::thread::current()
            .name()
            .unwrap_or("<unnamed>")
            .to_owned();
        let binary = reference_binary(implementation);
        let mut child = Command::new(binary)
            .arg(&test)
            .env(SEED_ENV, seed.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap_or_else(|e| panic!("cannot start {}: {e}", binary.display()));
        let requests = child.stdin.take().map(BufWriter::new);
        let mut replies = BufReader::new(child.stdout.take().expect("piped stdout"));
        let handshake = protocol::read_handshake(&mut replies).unwrap_or_else(|e| {
            panic!(
                "test `{test}`: cannot read the handshake of the {implementation} reference TPM \
                 process: {e} ({})",
                match child.try_wait() {
                    Ok(Some(status)) => format!("exited with {status}"),
                    _ => "still running".into(),
                }
            )
        });
        assert_eq!(
            (handshake.pid, handshake.realtime_ms),
            (seed.pid, seed.realtime_ms),
            "test `{test}`: the {implementation} reference TPM process did not adopt the seed \
             {SEED_ENV}={seed} (process ID, initial real time)"
        );
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
        if let Err(failure) = self.try_finish(what) {
            panic!("{}", failure.message);
        }
    }

    /// Reads the reply to the last request; the failure of an error reply
    /// or of a dead process.
    fn try_finish(&mut self, what: &str) -> Result<(), Failure> {
        match protocol::read_reply(&mut self.replies) {
            Ok(result) => result,
            Err(e) => Err(Failure::new(format!(
                "test `{}`: the {} reference TPM process failed during {what} ({e}; {})",
                self.test,
                self.implementation,
                match self.child.try_wait() {
                    Ok(Some(status)) => format!("exited with {status}"),
                    _ => "still running".into(),
                }
            ))),
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
        Request::Reinit => "a re-initialization",
    }
}

/// The C reference TPMs mirroring one [`crate::tpm::Tpm`]: one
/// [`Reference`] process per selected implementation, all seeded with the
/// `Tpm`'s seed.
///
/// Every interaction is sent to all references before any reply is awaited,
/// so the references work in parallel; each compares its response with the
/// `tpm-rs` response, so they are also compared with each other.
pub struct References(Vec<Reference>);

impl References {
    /// Launches one reference process per `implementation`, each seeded with
    /// `seed`, in parallel (see [`Reference::launch`]).
    ///
    /// # Panics
    /// If a process cannot be started, its handshake is invalid or its C
    /// reference fails to initialize.
    pub fn launch(implementations: &[Implementation], seed: ReferenceSeed) -> Self {
        let mut references = Self(
            implementations
                .iter()
                .map(|&implementation| Reference::spawn(implementation, seed))
                .collect(),
        );
        references.finish_all("start-up");
        references
    }

    /// The implementations of the references.
    pub fn implementations(&self) -> impl Iterator<Item = Implementation> + '_ {
        self.0.iter().map(Reference::implementation)
    }

    /// Reads every reference's reply to the last request (always all of
    /// them, so every channel stays in sync); the failing references.
    fn try_finish_all(&mut self, what: &str) -> Result<(), Vec<Divergence>> {
        let divergences: Vec<Divergence> = self
            .0
            .iter_mut()
            .filter_map(|reference| {
                let failure = reference.try_finish(what).err()?;
                Some(Divergence {
                    implementation: reference.implementation,
                    reference_response: failure.reference_response,
                    message: failure.message,
                })
            })
            .collect();
        if divergences.is_empty() {
            Ok(())
        } else {
            Err(divergences)
        }
    }

    /// Reads every reference's reply to the last request.
    ///
    /// # Panics
    /// If any reply is an error or a process died (with the messages of all
    /// failing references).
    fn finish_all(&mut self, what: &str) {
        if let Err(divergences) = self.try_finish_all(what) {
            panic!("{}", join_messages(&divergences));
        }
    }

    /// Sends `request` to every reference, then waits for all replies; the
    /// failing references.
    fn try_call(&mut self, request: Request) -> Result<(), Vec<Divergence>> {
        for reference in &mut self.0 {
            reference.send(&request);
        }
        self.try_finish_all(describe(&request))
    }

    /// Sends `request` to every reference, then waits for all replies.
    ///
    /// # Panics
    /// See [`Self::finish_all`].
    fn call(&mut self, request: Request) {
        if let Err(divergences) = self.try_call(request) {
            panic!("{}", join_messages(&divergences));
        }
    }

    /// Re-initializes every reference process like a new one with the same
    /// seed (`Request::Reinit`, see [`server::Server::reinit`]): virtual clock
    /// back at the seed's real time, manufactured, powered on, NV on,
    /// `TPM2_Startup(TPM_SU_CLEAR)` done, and comparison state cleared. No
    /// process is launched.
    ///
    /// # Panics
    /// If a reference fails to re-initialize or a process died.
    pub fn reinit(&mut self) {
        self.call(Request::Reinit);
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
        if let Err(divergences) = self.try_exchange(locality, command, expected) {
            panic!("{}", join_messages(&divergences));
        }
    }

    /// Like [`Self::exchange`], but returns the references whose responses
    /// differ (or that failed) instead of panicking. Every reference has
    /// executed the command either way, so the `References` stay usable
    /// (unless a process died).
    pub fn try_exchange(
        &mut self,
        locality: u8,
        command: &[u8],
        expected: &[u8],
    ) -> Result<(), Vec<Divergence>> {
        self.try_call(Request::Exchange {
            locality,
            command: command.to_vec(),
            expected: expected.to_vec(),
        })
    }
}

/// The messages of `divergences`, separated by blank lines.
pub fn join_messages(divergences: &[Divergence]) -> String {
    divergences
        .iter()
        .map(|d| d.message.as_str())
        .collect::<Vec<_>>()
        .join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_are_selected_by_name() {
        use Implementation::{Ibmswtpm2, Mstpm20};
        assert_eq!(parse_selection(""), Ok(vec![Mstpm20, Ibmswtpm2]));
        assert_eq!(
            parse_selection("ibmswtpm2, mstpm20"),
            Ok(vec![Ibmswtpm2, Mstpm20])
        );
        assert_eq!(parse_selection(" ibmswtpm2 "), Ok(vec![Ibmswtpm2]));
        assert_eq!(parse_selection("mstpm20,mstpm20"), Ok(vec![Mstpm20]));
        assert!(parse_selection("mstpm2").is_err());
    }
}
