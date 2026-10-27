//! The TPM the E2E tests talk to.
//!
//! Every test drives a [`Tpm`]: a `tpm-rs` simulator on a virtual clock
//! (see `tpm2_simulator::create_reference_simulator!`), reachable only
//! through its command interface (typed commands, raw command buffers at any
//! locality, platform signals and `_TPM_Hash_*` indications), exactly like a
//! real TPM.
//!
//! In a differential build (a `target-*` feature), every interaction is
//! additionally mirrored to the patched C reference TPM of the target (the
//! public or version 185 TCG reference `mstpm20`, or the IBM `ibmswtpm2`),
//! running in a child process of its own (see `crate::differential`): each
//! command is first executed by `tpm-rs`, then by the reference, and the
//! reference's response must be identical to the `tpm-rs` response except for
//! the documented, implementation-defined differences. A mismatch panics at the command that diverged, so the same test suite
//! serves as both the `tpm-rs` E2E tests and the differential tests. The test
//! always continues with the `tpm-rs` response.
//!
//! The C references seed their random number generation from their process
//! ID and their real-time clock. The `Tpm` chooses both values
//! ([`crate::seed::ReferenceSeed::choose`]: the test process's ID and its
//! current monotonic time), builds its simulator, which reproduces the
//! references' random number generation, from them, and hands them to every
//! reference process, which adopts them (its `getpid()` and its initial
//! clock). Afterwards all clocks only move together, through [`sleep`] (no
//! wall-clock time passes), so `tpm-rs` and every reference draw the same
//! random values.
//!
//! Every `Tpm` prints its seed (`TPM_REFERENCE_SEED=<pid>:<realtime_ms>`, see
//! [`crate::seed`]) on stderr, which the test harness shows for failing
//! tests. Setting that environment variable makes every `Tpm` use that seed
//! instead, so the TPM's random values repeat exactly. The variable holds one
//! seed, so a test that creates several `Tpm`s gives all of them the same
//! seed when reproduced.
//!
//! Client-side randomness (nonces, salts and client keys, see
//! [`crate::_common::client_random`]) comes from the OS, so the commands a
//! test sends may differ between runs, unless `TPM_REFERENCE_SEED` is set, in
//! which case it is derived from the seed and the test name; the references
//! always receive exactly the commands `tpm-rs` received.
//!
//! For fuzzing, [`Tpm::with_seed`] fixes the seed explicitly,
//! [`Tpm::try_exchange`] reports a diverging command as an error instead of
//! panicking, and [`Tpm::reset`] returns the `Tpm` (and its reference
//! processes, without launching new ones) to the state of a new `Tpm` with
//! the same seed. With `TPM_FUZZ_RECORD_DIR` set, every `Tpm` records its
//! commands and responses (see [`trace`]).

use std::cell::Cell;
use std::io::Cursor;
use std::time::Duration;

use tpm2::Connection;
use tpm2::commands::Command;
use tpm2_simulator::{NO_STREAM, PlatformConnection, Simulator, create_reference_simulator};

pub use tpm2_simulator::{ExecuteError, SimulatorPlatformSignal};

use self::trace::{Event, Recorder};
use crate::seed::{ReferenceSeed, SEED_ENV};

pub mod trace;

/// Why [`Tpm::try_exchange`] failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SendError {
    /// The simulator rejected the command at the transport level (e.g. an
    /// oversized buffer); it was neither executed nor mirrored.
    Transport(String),
    /// `tpm-rs` executed the command, but the responses of these references
    /// differ from its response other than as documented (or a reference
    /// failed). Every reference executed the command; continue with
    /// [`Tpm::reset`] (or drop the `Tpm`).
    #[cfg(feature = "differential")]
    Divergence {
        /// The `tpm-rs` response.
        response: Vec<u8>,
        /// The diverging references.
        divergences: Vec<crate::differential::Divergence>,
    },
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "TPM transport error: {e}"),
            #[cfg(feature = "differential")]
            Self::Divergence { divergences, .. } => {
                f.write_str(&crate::differential::join_messages(divergences))
            }
        }
    }
}

impl std::error::Error for SendError {}

/// MSSIM `TPM_SIGNAL_HASH_START`.
const TPM_SIGNAL_HASH_START: u32 = 5;
/// MSSIM `TPM_SIGNAL_HASH_DATA`.
const TPM_SIGNAL_HASH_DATA: u32 = 6;
/// MSSIM `TPM_SIGNAL_HASH_END`.
const TPM_SIGNAL_HASH_END: u32 = 7;
/// MSSIM `TPM_SEND_COMMAND`.
const TPM_SEND_COMMAND: u32 = 8;

thread_local! {
    /// Milliseconds this thread let pass via [`sleep`].
    static THREAD_CLOCK_MS: Cell<u64> = const { Cell::new(0) };
}

/// Lets `duration` pass for every [`Tpm`] of the calling thread.
///
/// No wall-clock time passes: the TPMs run on virtual clocks, which are
/// advanced by `duration` before their next interaction. Tests must use this
/// instead of `std::thread::sleep`.
pub fn sleep(duration: Duration) {
    let ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
    THREAD_CLOCK_MS.with(|c| c.set(c.get().saturating_add(ms)));
}

/// The TPM under test (see the module docs).
///
/// A `Tpm` must be driven from the thread that created it (its [`sleep`]
/// clock is per thread).
pub struct Tpm {
    /// The `tpm-rs` simulator, whose responses the tests see.
    sim: Simulator<'static>,
    /// The seed `sim` and the references were built from.
    seed: ReferenceSeed,
    /// The value of this thread's [`sleep`] clock last applied to the TPMs.
    clock_ms: u64,
    /// The C reference TPMs mirroring `sim`.
    #[cfg(feature = "differential")]
    references: Mirror,
    /// The trace file, with `TPM_FUZZ_RECORD_DIR` (see [`trace`]).
    recorder: Option<Recorder>,
}

/// The C reference TPMs mirroring a [`Tpm`]: reference processes, or (with
/// `fuzz-inproc`) the C references linked into this process.
#[cfg(feature = "differential")]
enum Mirror {
    /// One child process per reference ([`crate::differential::References`]).
    Processes(crate::differential::References),
    /// The in-process references
    /// ([`crate::differential::inproc::InProcReferences`]).
    #[cfg(feature = "fuzz-inproc")]
    InProcess(crate::differential::inproc::InProcReferences),
}

/// Forwards a method call to the references of a [`Mirror`].
#[cfg(feature = "differential")]
macro_rules! dispatch {
    ($mirror:expr, $r:ident => $call:expr) => {
        match $mirror {
            Mirror::Processes($r) => $call,
            #[cfg(feature = "fuzz-inproc")]
            Mirror::InProcess($r) => $call,
        }
    };
}

#[cfg(feature = "differential")]
impl Mirror {
    /// The names of the references, comma-separated.
    fn names(&self) -> String {
        let names: Vec<&str> =
            dispatch!(self, r => r.implementations().map(|i| i.name()).collect());
        names.join(", ")
    }

    fn reinit(&mut self) {
        dispatch!(self, r => r.reinit())
    }

    fn advance_clock(&mut self, ms: u64) {
        dispatch!(self, r => r.advance_clock(ms))
    }

    fn signal(&mut self, signal: SimulatorPlatformSignal) {
        dispatch!(self, r => r.signal(signal))
    }

    fn set_firmware(&mut self, setting: crate::differential::protocol::FirmwareSetting) {
        dispatch!(self, r => r.set_firmware(setting))
    }

    fn hash_start(&mut self) {
        dispatch!(self, r => r.hash_start())
    }

    fn hash_data(&mut self, data: &[u8]) {
        dispatch!(self, r => r.hash_data(data))
    }

    fn hash_end(&mut self) {
        dispatch!(self, r => r.hash_end())
    }

    fn try_exchange(
        &mut self,
        locality: u8,
        command: &[u8],
        expected: &[u8],
    ) -> Result<(), Vec<crate::differential::Divergence>> {
        dispatch!(self, r => r.try_exchange(locality, command, expected))
    }
}

impl Default for Tpm {
    fn default() -> Self {
        Self::new()
    }
}

impl Tpm {
    /// Creates a fresh TPM that has been powered on, had NV enabled and
    /// received `TPM2_Startup(TPM_SU_CLEAR)`.
    ///
    /// With the `differential` feature, the TPM is mirrored to every selected
    /// C reference TPM, each in a child process of its own seeded with this
    /// TPM's seed, so `Tpm`s are fully independent (across threads and
    /// within one test).
    pub fn new() -> Self {
        Self::with_seed(ReferenceSeed::choose())
    }

    /// Like [`Self::new`], but with the given seed of the TPM's random number
    /// generation (instead of [`ReferenceSeed::choose`], so `TPM_REFERENCE_SEED`
    /// is not consulted).
    ///
    /// Two `Tpm`s with the same seed that receive the same interactions give
    /// byte-identical responses (`tpm-rs` and every C reference alike), which
    /// is what makes a fuzz input reproducible: a fuzzer uses one fixed seed
    /// for every input.
    pub fn with_seed(seed: ReferenceSeed) -> Self {
        #[cfg(feature = "differential")]
        let references = Mirror::Processes(crate::differential::References::launch(
            crate::differential::selected(),
            seed,
        ));
        Self::from_parts(
            seed,
            #[cfg(feature = "differential")]
            references,
        )
    }

    /// Like [`Self::with_seed`], but mirrored to the C references linked
    /// into this process ([`crate::differential::inproc::InProcReferences`])
    /// instead of reference processes, which saves the pipe round trips of
    /// every interaction (for single-threaded fuzzing).
    ///
    /// # Panics
    /// If another in-process-mirrored `Tpm` is alive in this process (the C
    /// references keep their state in globals).
    #[cfg(feature = "fuzz-inproc")]
    pub fn with_seed_in_process(seed: ReferenceSeed) -> Self {
        let references = Mirror::InProcess(crate::differential::inproc::InProcReferences::launch(
            crate::differential::selected(),
            seed,
        ));
        Self::from_parts(seed, references)
    }

    /// A new `Tpm` with `seed` mirrored to `references`, which are already
    /// seeded with it.
    fn from_parts(
        seed: ReferenceSeed,
        #[cfg(feature = "differential")] references: Mirror,
    ) -> Self {
        // Shown with the output of a failing test: setting the variable
        // reproduces this TPM's random values.
        #[cfg(feature = "differential")]
        eprintln!(
            "tpm-rs: {SEED_ENV}={seed} (compared with {})",
            references.names()
        );
        #[cfg(not(feature = "differential"))]
        eprintln!("tpm-rs: {SEED_ENV}={seed}");
        Self {
            sim: create_reference_simulator!(seed.pid, seed.realtime_ms),
            seed,
            clock_ms: THREAD_CLOCK_MS.with(Cell::get),
            #[cfg(feature = "differential")]
            references,
            recorder: Recorder::from_env(seed),
        }
    }

    /// The seed of this TPM's random number generation.
    pub fn seed(&self) -> ReferenceSeed {
        self.seed
    }

    /// Returns the TPM to the state of a new `Tpm` with the same seed
    /// ([`Self::with_seed`]`(self.seed())`): powered on, NV available,
    /// `TPM2_Startup(TPM_SU_CLEAR)` done, virtual clock at the seed's real
    /// time, and the same random values ahead.
    ///
    /// The `tpm-rs` simulator is reset in place
    /// (`Simulator::reset_reference`, which reuses its allocations, so
    /// resetting leaks nothing); with `differential`, the existing references
    /// are re-initialized in place (no process is launched) and their
    /// comparison state is cleared. Time this thread let pass via [`sleep`]
    /// before the reset does not apply to the reset TPM.
    ///
    /// # Panics
    /// With `differential`, if a reference fails to re-initialize or its
    /// process died.
    pub fn reset(&mut self) {
        self.record(&Event::Reset);
        self.sim
            .reset_reference(self.seed.pid, self.seed.realtime_ms);
        self.clock_ms = THREAD_CLOCK_MS.with(Cell::get);
        #[cfg(feature = "differential")]
        self.references.reinit();
    }

    /// Appends `event` to the trace, if one is recorded.
    fn record(&mut self, event: &Event) {
        if let Some(recorder) = &mut self.recorder {
            recorder.record(event);
        }
    }

    /// Applies the time this thread let pass since the last interaction (see
    /// [`sleep`]) to the TPMs' virtual clocks.
    fn sync_clock(&mut self) {
        let now = THREAD_CLOCK_MS.with(Cell::get);
        let ms = now.saturating_sub(self.clock_ms);
        if ms == 0 {
            return;
        }
        self.clock_ms = now;
        self.record(&Event::AdvanceClock(ms));
        assert!(
            self.sim.advance_clock(ms),
            "the simulator has no virtual clock"
        );
        #[cfg(feature = "differential")]
        self.references.advance_clock(ms);
    }

    /// Sends `command` at `locality` to `tpm-rs` (MSSIM `TPM_SEND_COMMAND`)
    /// and, with `differential`, to every C reference, comparing the
    /// responses.
    ///
    /// Returns the `tpm-rs` response (empty while the TPM is powered off), or
    /// [`SendError::Transport`] if the simulator rejected the command at the
    /// transport level (e.g. an oversized buffer), in which case it is not
    /// mirrored, or `SendError::Divergence` (in a differential build) if a reference's response
    /// differs other than as documented. Unlike [`Self::send_command`] it
    /// never panics on a divergence, so a fuzzer can classify it.
    pub fn try_exchange(&mut self, locality: u8, command: &[u8]) -> Result<Vec<u8>, SendError> {
        self.sync_clock();
        let response = match self.run_on_simulator(locality, command) {
            Ok(response) => response,
            Err(e) => {
                self.record(&Event::Rejected {
                    locality,
                    command: command.to_vec(),
                });
                return Err(SendError::Transport(e));
            }
        };
        self.record(&Event::Command {
            locality,
            command: command.to_vec(),
            response: response.clone(),
        });
        #[cfg(feature = "differential")]
        if let Err(divergences) = self.references.try_exchange(locality, command, &response) {
            return Err(SendError::Divergence {
                response,
                divergences,
            });
        }
        Ok(response)
    }

    /// Executes `command` at `locality` on the `tpm-rs` simulator only; its
    /// response, or the simulator's transport-level rejection.
    fn run_on_simulator(&mut self, locality: u8, command: &[u8]) -> Result<Vec<u8>, String> {
        let mut input = vec![locality];
        input.extend_from_slice(&(command.len() as u32).to_be_bytes());
        input.extend_from_slice(command);
        let input_len = input.len();
        let mut stream = Cursor::new(input);
        self.sim
            .transact_platform(TPM_SEND_COMMAND, &mut stream)
            .map_err(|e| e.to_string())?;
        let output = stream.into_inner();
        let out = &output[input_len..];
        let len = out
            .get(..4)
            .map(|l| u32::from_be_bytes([l[0], l[1], l[2], l[3]]) as usize)
            .ok_or("simulator wrote no response length")?;
        Ok(out
            .get(4..4 + len)
            .ok_or("truncated simulator response")?
            .to_vec())
    }

    /// Like [`Self::try_exchange`], but only transport-level rejections are
    /// returned (as an error message, the command was neither executed nor
    /// mirrored); the `tpm-rs` response otherwise.
    ///
    /// # Panics
    /// With `differential`, if a reference's response differs other than as
    /// documented.
    pub fn try_send_command(&mut self, locality: u8, command: &[u8]) -> Result<Vec<u8>, String> {
        match self.try_exchange(locality, command) {
            Ok(response) => Ok(response),
            Err(SendError::Transport(e)) => Err(e),
            #[cfg(feature = "differential")]
            Err(e @ SendError::Divergence { .. }) => panic!("{e}"),
        }
    }

    /// Sends the raw command buffer `command` at `locality` and returns the
    /// raw response (empty while the TPM is powered off).
    ///
    /// # Panics
    /// If the simulator rejects the command at the transport level.
    pub fn send_command(&mut self, locality: u8, command: &[u8]) -> Vec<u8> {
        self.try_send_command(locality, command)
            .unwrap_or_else(|e| panic!("TPM transport error: {e}"))
    }

    /// Executes the typed command `cmd`: its handles (carried in the command)
    /// go to the handle area, with an empty password session for every handle
    /// that needs authorization. The response carries the response handles.
    pub fn execute<Cmd: Command>(
        &mut self,
        cmd: Cmd,
    ) -> Result<Cmd::Response<'static>, ExecuteError>
    where
        for<'d> &'d mut Cmd::MaxBuffer: TryFrom<&'d mut [u8]>,
    {
        tpm2_simulator::execute::run_command(&cmd, self)
    }

    /// Delivers the platform signal `signal`.
    ///
    /// # Panics
    /// With `differential`, if a C reference TPM does not support `signal`.
    pub fn signal_platform(&mut self, signal: SimulatorPlatformSignal) -> Result<(), String> {
        self.sync_clock();
        self.record(&Event::Signal(format!("{signal:?}")));
        self.sim
            .signal_platform(signal, NO_STREAM)
            .map_err(|e| e.to_string())?;
        #[cfg(feature = "differential")]
        self.references.signal(signal);
        Ok(())
    }

    /// Installs a firmware image with the hash `hash` (the MSSIM platform signal
    /// `TPM_SET_FW_HASH`, `_plat__SetTpmFirmwareHash`): the Firmware Secret of the
    /// firmware-limited hierarchies changes.
    ///
    /// # Panics
    /// If the simulator rejects the signal.
    pub fn set_firmware_hash(&mut self, hash: u32) {
        self.firmware_signal(SimulatorPlatformSignal::SetFirmwareHash, hash);
        #[cfg(feature = "differential")]
        self.references
            .set_firmware(crate::differential::protocol::FirmwareSetting::Hash(hash));
    }

    /// Installs a firmware image with the SVN `svn` (the MSSIM platform signal
    /// `TPM_SET_FW_SVN`, `_plat__SetTpmFirmwareSvn`, which caps it at the maximum SVN):
    /// the SVN-limited hierarchies of larger SVNs become unavailable.
    ///
    /// # Panics
    /// If the simulator rejects the signal.
    pub fn set_firmware_svn(&mut self, svn: u16) {
        self.firmware_signal(SimulatorPlatformSignal::SetFirmwareSvn, u32::from(svn));
        #[cfg(feature = "differential")]
        self.references
            .set_firmware(crate::differential::protocol::FirmwareSetting::Svn(svn));
    }

    /// Delivers the firmware platform signal `signal` with its 32-bit `value` to `tpm-rs`.
    fn firmware_signal(&mut self, signal: SimulatorPlatformSignal, value: u32) {
        self.sync_clock();
        self.record(&Event::Signal(format!("{signal:?}={value:#x}")));
        let mut stream = Cursor::new(value.to_be_bytes().to_vec());
        self.sim
            .signal_platform(signal, Some(&mut stream))
            .unwrap_or_else(|e| panic!("TPM transport error: {e}"));
        let reply = stream.into_inner();
        assert_eq!(reply[4..], 0u32.to_be_bytes(), "{signal:?} failed");
    }

    /// Sends a `_TPM_Hash_*` indication (MSSIM command `code` with `payload`,
    /// recorded as `event`) to `tpm-rs`.
    fn hash_indication(&mut self, code: u32, payload: Vec<u8>, event: Event) {
        self.sync_clock();
        self.record(&event);
        self.sim
            .transact_platform(code, &mut Cursor::new(payload))
            .unwrap_or_else(|e| panic!("TPM transport error: {e}"));
    }

    /// Sends the `_TPM_Hash_Start` indication.
    pub fn hash_start(&mut self) {
        self.hash_indication(TPM_SIGNAL_HASH_START, Vec::new(), Event::HashStart);
        #[cfg(feature = "differential")]
        self.references.hash_start();
    }

    /// Sends the `_TPM_Hash_Data` indication with `data`.
    pub fn hash_data(&mut self, data: &[u8]) {
        let mut payload = (data.len() as u32).to_be_bytes().to_vec();
        payload.extend_from_slice(data);
        self.hash_indication(
            TPM_SIGNAL_HASH_DATA,
            payload,
            Event::HashData(data.to_vec()),
        );
        #[cfg(feature = "differential")]
        self.references.hash_data(data);
    }

    /// Sends the `_TPM_Hash_End` indication.
    pub fn hash_end(&mut self) {
        self.hash_indication(TPM_SIGNAL_HASH_END, Vec::new(), Event::HashEnd);
        #[cfg(feature = "differential")]
        self.references.hash_end();
    }

    /// Whether every interaction with this TPM is mirrored to (and compared
    /// with) a C reference TPM.
    pub fn is_differential(&self) -> bool {
        cfg!(feature = "differential")
    }
}

/// Sends raw command buffers at locality 0 (see [`Tpm::send_command`]).
impl Connection for Tpm {
    type Error = ExecuteError;

    /// Sends the raw command `cmd` at locality 0 and copies the response into
    /// the front of `rsp`, returning the part of `rsp` it occupies (empty
    /// while the TPM is powered off).
    fn transact<'b>(
        &mut self,
        cmd: &[u8],
        rsp: &'b mut [u8],
    ) -> Result<&'b mut [u8], ExecuteError> {
        let response = self
            .try_send_command(0, cmd)
            .map_err(|_| ExecuteError::Unexpected)?;
        let out = rsp
            .get_mut(..response.len())
            .ok_or(ExecuteError::ResponseTooLarge)?;
        out.copy_from_slice(&response);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `TPM2_ReadClock` (no sessions).
    const READ_CLOCK: [u8; 10] = [0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x81];

    /// `TPMS_TIME_INFO.time` of a `TPM2_ReadClock` response.
    fn time_ms(tpm: &mut Tpm) -> u64 {
        let rsp = tpm.send_command(0, &READ_CLOCK);
        assert_eq!(&rsp[6..10], &[0, 0, 0, 0], "ReadClock failed: {rsp:02x?}");
        u64::from_be_bytes(rsp[10..18].try_into().unwrap())
    }

    #[test]
    fn sleep_advances_only_the_virtual_clock() {
        let mut tpm = Tpm::new();
        let start = time_ms(&mut tpm);
        let wall = std::time::Instant::now();
        sleep(Duration::from_secs(3600));
        assert_eq!(time_ms(&mut tpm) - start, 3_600_000);
        assert!(wall.elapsed() < Duration::from_secs(60));
    }

    /// `TPM2_GetRandom(16)`.
    const GET_RANDOM_16: [u8; 12] = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x7B, 0, 16];

    #[test]
    fn get_random_draws_fresh_values() {
        let mut tpm = Tpm::new();
        let first = tpm.send_command(0, &GET_RANDOM_16);
        assert_eq!(
            &first[6..10],
            &[0, 0, 0, 0],
            "GetRandom failed: {first:02x?}"
        );
        assert_eq!(first.len(), 12 + 16);
        sleep(Duration::from_millis(1500));
        let second = tpm.send_command(0, &GET_RANDOM_16);
        assert_eq!(second.len(), first.len());
        assert_ne!(first, second, "the DRBG advances");
    }

    #[test]
    fn tpms_of_one_test_are_independent() {
        let mut a = Tpm::new();
        let mut b = Tpm::new();
        sleep(Duration::from_millis(250));
        let (ta, tb) = (time_ms(&mut a), time_ms(&mut b));
        assert_eq!(ta, tb);
        // Powering one TPM off leaves the other running.
        a.signal_platform(SimulatorPlatformSignal::PowerOff)
            .unwrap();
        assert!(a.send_command(0, &READ_CLOCK).is_empty());
        assert!(time_ms(&mut b) >= tb);
        assert_eq!(a.is_differential(), cfg!(feature = "differential"));
    }

    #[test]
    fn powered_off_tpm_returns_empty_responses() {
        let mut tpm = Tpm::new();
        tpm.signal_platform(SimulatorPlatformSignal::PowerOff)
            .unwrap();
        assert!(tpm.send_command(0, &READ_CLOCK).is_empty());
        crate::_common::power_on_start_up(&mut tpm);
        time_ms(&mut tpm);
    }
}
