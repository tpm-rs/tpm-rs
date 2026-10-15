//! The TPM the E2E tests talk to.
//!
//! Every test drives a [`Tpm`]: a `tpm-rs` simulator on a virtual clock
//! (see `tpm2_simulator::create_reference_simulator!`), reachable only
//! through its command interface (typed commands, raw command buffers at any
//! locality, platform signals and `_TPM_Hash_*` indications), exactly like a
//! real TPM.
//!
//! With the `differential` feature, every interaction is additionally mirrored
//! to the patched C reference TPMs selected by `DIFFERENTIAL_REFERENCES`
//! (default: both the TCG reference `mstpm20` and the IBM `ibmswtpm2`), each
//! running in a child process of its own (see [`crate::differential`]): each
//! command is first executed by `tpm-rs`, then by every reference (in
//! parallel), and each reference's response must be identical to the
//! `tpm-rs` response except for the documented, implementation-defined
//! differences, so the references are also compared with each other. A
//! mismatch panics at the command that diverged, so the same test suite
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

use std::cell::Cell;
use std::io::Cursor;
use std::time::Duration;

use tpm2::Connection;
use tpm2::commands::Command;
use tpm2_simulator::{NO_STREAM, PlatformConnection, Simulator, create_reference_simulator};

pub use tpm2_simulator::{ExecuteError, SimulatorPlatformSignal};

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
    /// The value of this thread's [`sleep`] clock last applied to the TPMs.
    clock_ms: u64,
    /// The C reference TPMs mirroring `sim`.
    #[cfg(feature = "differential")]
    references: crate::differential::References,
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
        use crate::seed::{ReferenceSeed, SEED_ENV};
        let seed = ReferenceSeed::choose();
        #[cfg(feature = "differential")]
        let references =
            crate::differential::References::launch(crate::differential::selected(), seed);
        // Shown with the output of a failing test: setting the variable
        // reproduces this TPM's random values.
        #[cfg(feature = "differential")]
        eprintln!(
            "tpm-rs: {SEED_ENV}={seed} (compared with {})",
            references
                .implementations()
                .map(|i| i.name())
                .collect::<Vec<_>>()
                .join(", ")
        );
        #[cfg(not(feature = "differential"))]
        eprintln!("tpm-rs: {SEED_ENV}={seed}");
        Self {
            sim: create_reference_simulator!(seed.pid, seed.realtime_ms),
            clock_ms: THREAD_CLOCK_MS.with(Cell::get),
            #[cfg(feature = "differential")]
            references,
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
        assert!(
            self.sim.advance_clock(ms),
            "the simulator has no virtual clock"
        );
        #[cfg(feature = "differential")]
        self.references.advance_clock(ms);
    }

    /// Sends `command` at `locality` to `tpm-rs` (MSSIM `TPM_SEND_COMMAND`)
    /// and, with `differential`, to the C reference, comparing the
    /// responses.
    /// Returns the `tpm-rs` response (empty while the TPM is powered off), or
    /// an error if the simulator rejected the command at the transport level
    /// (e.g. an oversized buffer), in which case it is not mirrored.
    fn try_send_command(&mut self, locality: u8, command: &[u8]) -> Result<Vec<u8>, String> {
        self.sync_clock();
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
        let response = out
            .get(4..4 + len)
            .ok_or("truncated simulator response")?
            .to_vec();
        #[cfg(feature = "differential")]
        self.references.exchange(locality, command, &response);
        Ok(response)
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
        self.sim
            .signal_platform(signal, NO_STREAM)
            .map_err(|e| e.to_string())?;
        #[cfg(feature = "differential")]
        self.references.signal(signal);
        Ok(())
    }

    /// Sends a `_TPM_Hash_*` indication (MSSIM command `code` with `payload`)
    /// to `tpm-rs`.
    fn hash_indication(&mut self, code: u32, payload: Vec<u8>) {
        self.sync_clock();
        self.sim
            .transact_platform(code, &mut Cursor::new(payload))
            .unwrap_or_else(|e| panic!("TPM transport error: {e}"));
    }

    /// Sends the `_TPM_Hash_Start` indication.
    pub fn hash_start(&mut self) {
        self.hash_indication(TPM_SIGNAL_HASH_START, Vec::new());
        #[cfg(feature = "differential")]
        self.references.hash_start();
    }

    /// Sends the `_TPM_Hash_Data` indication with `data`.
    pub fn hash_data(&mut self, data: &[u8]) {
        let mut payload = (data.len() as u32).to_be_bytes().to_vec();
        payload.extend_from_slice(data);
        self.hash_indication(TPM_SIGNAL_HASH_DATA, payload);
        #[cfg(feature = "differential")]
        self.references.hash_data(data);
    }

    /// Sends the `_TPM_Hash_End` indication.
    pub fn hash_end(&mut self) {
        self.hash_indication(TPM_SIGNAL_HASH_END, Vec::new());
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
