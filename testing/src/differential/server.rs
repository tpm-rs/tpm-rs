//! The server side of differential testing: hosts one C reference TPM in a
//! reference process (`mstpm20` or `ibmswtpm2`, see `src/bin/`) and compares
//! its responses with those of `tpm-rs`.
//!
//! A reference binary links its patched C reference TPM (built by
//! `testing/build.rs`), implements [`Backend`] over the C entry points
//! (`difftest_*`, the only `unsafe` FFI of this crate, in
//! `src/differential/inproc.rs`) and calls [`serve`]. The only callback the
//! patches add is the virtual clock (`_plat__RealTime()` returns
//! `difftest_virtual_ms()`, i.e. [`virtual_ms`]); the C references otherwise
//! run their unmodified algorithms, including their random number generation
//! (glibc `rand()` seeded from the real time and the process ID, feeding
//! their DRBG), which the `tpm-rs` simulator reproduces (`reference-rng`).
//!
//! On startup the server sends the [`Handshake`] (the process ID and initial
//! real time the C reference uses, i.e. the seed the parent chose),
//! then initializes the C reference like a new `Tpm` (manufactured, powered
//! on, NV on, `TPM2_Startup(TPM_SU_CLEAR)` done) and answers with a reply; it
//! then serves the requests of [`super::protocol`] read from stdin, one reply
//! each, until stdin is closed.
//!
//! Each `Exchange` request carries a command and the response `tpm-rs` gave
//! to it. The command is executed by the C reference (after translating the
//! implementation-defined `contextBlob`s a test may pass back (exception 1),
//! see [`DiffState::to_ref_command`]), and its response must be byte-identical
//! to the `tpm-rs` response, except for the narrowly-scoped, documented
//! rules in `compare_differential_response` (each keyed to a command code, a
//! response code pair and a checked condition, and listed in
//! `differential.md`) and the `TPM_RC_RETRY` re-issue rule. Any other
//! difference is replied as an error carrying the C reference's response
//! (see [`protocol::Failure`]), which fails the test.
//!
//! A `Reinit` request re-initializes the C reference exactly like a new
//! process with the same seed ([`Server::reinit`]), so one process can serve
//! many independent conversations (e.g. one per fuzz input).

use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicU64, Ordering};

use tpm2_simulator::SimulatorPlatformSignal;

use super::Implementation;
use super::protocol::{self, Failure, Handshake, Request};

/// Environment variable that makes reference processes log every applied
/// documented exception and `TPM_RC_RETRY` re-issue on stderr.
pub const LOG_EXCEPTIONS_ENV: &str = "DIFFERENTIAL_LOG_EXCEPTIONS";

/// The virtual clock of this reference process: the current
/// `_plat__RealTime()` in milliseconds. It starts at the process's
/// `CLOCK_MONOTONIC` time (set by [`serve`]) and only moves on
/// `AdvanceClock` requests.
static VIRTUAL_MS: AtomicU64 = AtomicU64::new(0);

/// The current value of the virtual clock (`_plat__RealTime()` of the C
/// reference TPM, returned by the `difftest_virtual_ms` callback).
pub fn virtual_ms() -> u64 {
    VIRTUAL_MS.load(Ordering::Relaxed)
}

/// Sets the virtual clock (see [`virtual_ms`]) to `ms` milliseconds.
///
/// The clock is global to the process: [`serve`] starts it at the seed's
/// real time and the [`Server`] moves it on `AdvanceClock` and `Reinit`
/// requests. Hosts that drive several [`Server`]s in one process (which then
/// share the clock) use this to set it before each one handles a request.
pub fn set_virtual_ms(ms: u64) {
    VIRTUAL_MS.store(ms, Ordering::Relaxed);
}

/// Serializes the unit tests of this crate that use the process-global virtual clock
/// ([`virtual_ms`], [`set_virtual_ms`]): every such test holds this lock while it runs, since
/// the test harness runs tests in parallel threads of one process.
#[cfg(test)]
pub(crate) static VIRTUAL_CLOCK_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A platform signal delivered to a C reference TPM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    /// Power on (`_rpc__Signal_PowerOn(false)`).
    PowerOn,
    /// Power off.
    PowerOff,
    /// Power cycle (`_rpc__Signal_PowerOn(true)`).
    Reset,
    /// NV available.
    NvOn,
    /// NV unavailable.
    NvOff,
    /// Physical presence asserted.
    PhysicalPresenceOn,
    /// Physical presence deasserted.
    PhysicalPresenceOff,
    /// Cancel asserted.
    CancelOn,
    /// Cancel deasserted.
    CancelOff,
}

/// The entry points of a patched C reference TPM (`difftest_*` in the
/// reference patches).
pub trait Backend {
    /// Manufactures the TPM (fresh RAM-backed NV), powers it on and makes NV
    /// available. This seeds the C reference's random number generator from
    /// the current real time ([`virtual_ms`]) and the process ID.
    fn init(&mut self);
    /// Advances the C reference's own clock by `ms` milliseconds (the
    /// virtual clock the patches read is advanced by the server).
    fn advance_clock(&mut self, ms: u64);
    /// Delivers a platform signal.
    fn signal(&mut self, signal: Signal);
    /// `_TPM_Hash_Start`.
    fn hash_start(&mut self);
    /// `_TPM_Hash_Data(data)`.
    fn hash_data(&mut self, data: &[u8]);
    /// `_TPM_Hash_End`.
    fn hash_end(&mut self);
    /// Executes `command` at `locality` and returns the response.
    fn run_command(&mut self, locality: u8, command: &[u8]) -> Vec<u8>;
}

/// Runs a reference process: starts the virtual clock at `seed.realtime_ms`
/// (the value the parent chose, see [`crate::seed`]), sends the
/// [`Handshake`] with `seed` (`seed.pid` is what `getpid()` returns to the C
/// reference), initializes `backend`, then answers the requests read from
/// `input` on `output` until `input` ends (see the module docs).
/// `test` names the test the process serves, for diagnostics.
///
/// # Panics
/// If the protocol channel fails.
pub fn serve<B: Backend>(
    implementation: Implementation,
    backend: B,
    test: String,
    seed: crate::seed::ReferenceSeed,
    mut input: impl BufRead,
    mut output: impl Write,
) {
    VIRTUAL_MS.store(seed.realtime_ms, Ordering::Relaxed);
    let handshake = Handshake {
        pid: seed.pid,
        realtime_ms: seed.realtime_ms,
    };
    // The handshake goes out before the C reference is initialized (which
    // seeds its RNG from the clock and the process ID); the clock does not
    // move in between.
    protocol::write_handshake(&mut output, &handshake)
        .and_then(|()| output.flush())
        .unwrap_or_else(|e| panic!("{implementation}: cannot write handshake: {e}"));
    let mut reply = |result: &Result<(), Failure>| {
        protocol::write_reply(&mut output, result)
            .and_then(|()| output.flush())
            .unwrap_or_else(|e| panic!("{implementation}: cannot write reply: {e}"));
    };
    let mut server = match Server::new(implementation, backend, test) {
        Ok(server) => {
            reply(&Ok(()));
            server
        }
        Err(e) => {
            reply(&Err(Failure::new(e)));
            std::process::exit(1);
        }
    };
    loop {
        match protocol::read_request(&mut input) {
            Ok(Some(request)) => {
                let result = server.handle(request);
                reply(&result);
            }
            Ok(None) => return,
            Err(e) => panic!("{implementation}: cannot read request: {e}"),
        }
    }
}

/// The state the comparison keeps across commands: the translations of
/// implementation-defined values and what the documented exceptions need.
#[derive(Debug, Default)]
pub struct DiffState {
    /// `(tpm-rs contextBlob, C contextBlob)` of every successful
    /// `TPM2_ContextSave` (exception 1).
    pub context_blobs: Vec<(Vec<u8>, Vec<u8>)>,
}

impl DiffState {
    /// The command to send to C: the command itself, except that the
    /// `contextBlob` of a `TPM2_ContextLoad` is replaced by the C blob (see
    /// [`DiffState::translate_context_load`]), or, for a blob that cannot be
    /// translated, its integrity value is made invalid (see
    /// [`DiffState::untranslated_context_load`]).
    pub fn to_ref_command(&self, command: &[u8]) -> Vec<u8> {
        let Some((_, code)) = header(command) else {
            return command.to_vec();
        };
        if code == cc::CONTEXT_LOAD {
            return self
                .translate_context_load(command)
                .unwrap_or_else(|| Self::untranslated_context_load(command));
        }
        command.to_vec()
    }

    /// Translates the `contextBlob` of a `TPM2_ContextLoad` command to the
    /// C reference's blob for the same saved context; `None` to send the
    /// command unchanged.
    ///
    /// The `contextBlob` layout is implementation-defined, so a blob produced
    /// by `tpm-rs`'s `TPM2_ContextSave` can never be loaded by C. Only a blob
    /// that is byte-for-byte identical to one `tpm-rs` returned earlier on
    /// this TPM is translated (to the blob C returned for the same
    /// `TPM2_ContextSave`; the `TPM2B` size and the `commandSize` are
    /// adjusted). Every other blob (tampered, truncated, foreign) is passed
    /// to C unchanged, so neither implementation's rejection of a modified
    /// blob is fabricated by the harness. A command whose `commandSize` is not
    /// its length is also passed unchanged: recomputing the size would hide
    /// the `TPM_RC_COMMAND_SIZE` error from C (and the blob is never read).
    pub fn translate_context_load(&self, command: &[u8]) -> Option<Vec<u8>> {
        if be32(command, 2)? as usize != command.len() {
            return None;
        }
        let (_, params) = command_parts(command, 0)?;
        // TPMS_CONTEXT: sequence (8), savedHandle (4), hierarchy (4),
        // contextBlob (TPM2B).
        let size_at = command.len() - params.len() + 16;
        let blob_len = be16(command, size_at)? as usize;
        let blob_at = size_at + 2;
        let blob = command.get(blob_at..blob_at + blob_len)?;
        // Bytes after the context fail the command with `TPM_RC_SIZE` whatever the blob is
        // (parameter unmarshaling precedes the blob's integrity check), and a larger C blob
        // could push the command beyond `MAX_COMMAND_SIZE` (`TPM_RC_COMMAND_SIZE` in C only):
        // such a command is sent unchanged.
        if blob_at + blob_len != command.len() {
            return None;
        }
        let (_, ref_blob) = self
            .context_blobs
            .iter()
            .rev()
            .find(|(rs_blob, _)| rs_blob.as_slice() == blob)?;
        let ref_len = u16::try_from(ref_blob.len()).ok()?;
        let mut out = Vec::with_capacity(command.len() - blob_len + ref_blob.len());
        out.extend_from_slice(&command[..size_at]);
        out.extend_from_slice(&ref_len.to_be_bytes());
        out.extend_from_slice(ref_blob);
        out.extend_from_slice(&command[blob_at + blob_len..]);
        let total = u32::try_from(out.len()).ok()?;
        out[2..6].copy_from_slice(&total.to_be_bytes());
        Some(out)
    }

    /// A `TPM2_ContextLoad` whose blob cannot be translated (not one `tpm-rs`
    /// saved on this TPM: tampered, truncated, or from another run), with its
    /// integrity value zeroed (never a valid HMAC; unlike a reversible change,
    /// it cannot turn a tampered integrity value back into the authentic one).
    ///
    /// All implementations share the hierarchy proofs (one seed) and the
    /// integrity HMAC of TPM 2.0 Part 1, "Context Integrity Protection"
    /// (`HMAC(hProof, resetValue || sequence || handle || encContext)`), so an
    /// authentic `tpm-rs` blob from another run (e.g. a fuzzing seed) would
    /// also pass the integrity check of a C reference, which would then
    /// interpret `tpm-rs`'s implementation-defined contents as its own
    /// (`ibmswtpm2` loads garbage, `mstpm20` enters failure mode on the
    /// fingerprint). On a real TPM no other implementation can authenticate a
    /// blob, so C must reject it as unauthentic (`TPM_RC_INTEGRITY`, or a size
    /// error the integrity check never reaches; exception 9). Commands without
    /// a complete blob or a non-empty integrity value are sent unchanged.
    pub fn untranslated_context_load(command: &[u8]) -> Vec<u8> {
        let mut out = command.to_vec();
        let Some((_, params)) = command_parts(command, 0) else {
            return out;
        };
        let size_at = command.len() - params.len() + 16;
        let (Some(blob_len), Some(integrity_len)) =
            (be16(command, size_at), be16(command, size_at + 2))
        else {
            return out;
        };
        let integrity_at = size_at + 4;
        let integrity_end = integrity_at + integrity_len as usize;
        if 2 + integrity_len as usize <= blob_len as usize && integrity_end <= command.len() {
            out[integrity_at..integrity_end].fill(0);
        }
        out
    }

    /// Records the `contextBlob` pair of a successful `TPM2_ContextSave`
    /// (`expected` from `tpm-rs`, `actual` from C) after a command
    /// completes.
    pub fn post_command(&mut self, command: &[u8], expected: &[u8], actual: &[u8]) {
        if header(command).map(|(_, code)| code) != Some(cc::CONTEXT_SAVE) {
            return;
        }
        fn blob(rsp: &[u8]) -> Option<&[u8]> {
            split_response(rsp, cc::CONTEXT_SAVE).and_then(|r| context_blob(r.params))
        }
        if let (Some(rs_blob), Some(ref_blob)) = (blob(expected), blob(actual)) {
            self.context_blobs
                .push((rs_blob.to_vec(), ref_blob.to_vec()));
        }
    }
}

/// `TPM_RC_RETRY` (a warning).
const TPM_RC_RETRY: u32 = 0x0000_0922;

/// The response code of a response, if it has a complete header.
fn response_code(rsp: &[u8]) -> Option<u32> {
    header(rsp).map(|(_, rc)| rc)
}

/// Hex encoding of `bytes`, for diagnostics.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether `DIFFERENTIAL_LOG_EXCEPTIONS` asks for logs of the applied rules.
fn logging() -> bool {
    std::env::var_os(LOG_EXCEPTIONS_ENV).is_some()
}

/// The C reference TPM of this process and the test it serves.
pub struct Server<B: Backend> {
    /// Which reference implementation `backend` is.
    implementation: Implementation,
    /// The C reference TPM.
    backend: B,
    /// Name of the test, for diagnostics.
    test: String,
    /// Number of commands exchanged so far, for diagnostics.
    commands: usize,
    /// Number of commands re-issued under the `TPM_RC_RETRY` rule.
    retries: usize,
    /// The comparison state.
    state: DiffState,
    /// The virtual clock ([`virtual_ms`]) when the server was created, i.e.
    /// the seed's real time; `Reinit` resets the clock to it.
    initial_ms: u64,
}

impl<B: Backend> Server<B> {
    /// Initializes the C reference TPM like a new `Tpm`: manufactured,
    /// powered on, NV on and `TPM2_Startup(TPM_SU_CLEAR)` done.
    ///
    /// The current virtual clock ([`virtual_ms`]) must be the seed's real
    /// time (as [`serve`] sets it): the C reference seeds its random number
    /// generation from it, and [`Self::reinit`] returns the clock to it.
    pub fn new(
        implementation: Implementation,
        mut backend: B,
        test: String,
    ) -> Result<Self, String> {
        Self::start_up(implementation, &mut backend, &test)?;
        Ok(Self {
            implementation,
            backend,
            test,
            commands: 0,
            retries: 0,
            state: DiffState::default(),
            initial_ms: virtual_ms(),
        })
    }

    /// Manufactures, powers on and enables NV of `backend` ([`Backend::init`])
    /// and sends it `TPM2_Startup(TPM_SU_CLEAR)`.
    fn start_up(implementation: Implementation, backend: &mut B, test: &str) -> Result<(), String> {
        backend.init();
        let startup_clear = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ];
        let startup_rsp = backend.run_command(0, &startup_clear);
        if response_code(&startup_rsp) != Some(0) {
            return Err(format!(
                "test `{test}`: initial {implementation} TPM2_Startup(CLEAR) failed: {}",
                hex(&startup_rsp)
            ));
        }
        Ok(())
    }

    /// Re-initializes the C reference TPM like a new reference process with
    /// the same seed (the `Reinit` request): resets the virtual clock to its
    /// value when the server was created (the seed's real time), then
    /// manufactures, powers on, enables NV and sends
    /// `TPM2_Startup(TPM_SU_CLEAR)` as [`Self::new`] does, and forgets the
    /// comparison state ([`DiffState`]) and the command counters.
    ///
    /// The C reference reseeds its random number generation from the clock
    /// and the process ID when it is manufactured, so the TPM then produces
    /// the same responses as a new process.
    pub fn reinit(&mut self) -> Result<(), Failure> {
        set_virtual_ms(self.initial_ms);
        self.state = DiffState::default();
        self.commands = 0;
        self.retries = 0;
        Self::start_up(self.implementation, &mut self.backend, &self.test).map_err(Failure::new)
    }

    /// Handles one protocol request.
    pub fn handle(&mut self, request: Request) -> Result<(), Failure> {
        match request {
            Request::Exchange {
                locality,
                command,
                expected,
            } => {
                let index = self.commands;
                self.commands += 1;
                self.exchange(index, locality, &command, &expected)
            }
            Request::AdvanceClock(ms) => {
                VIRTUAL_MS.fetch_add(ms, Ordering::Relaxed);
                self.backend.advance_clock(ms);
                Ok(())
            }
            Request::Signal(code) => match SimulatorPlatformSignal::try_from(code) {
                Ok(signal) => self.signal(signal).map_err(Failure::new),
                Err(()) => Err(Failure::new(format!(
                    "test `{}`: unknown signal {code}",
                    self.test
                ))),
            },
            Request::HashStart => {
                self.backend.hash_start();
                Ok(())
            }
            Request::HashData(data) => {
                self.backend.hash_data(&data);
                Ok(())
            }
            Request::HashEnd => {
                self.backend.hash_end();
                Ok(())
            }
            Request::Reinit => self.reinit(),
        }
    }

    /// Delivers a platform signal to the C reference.
    fn signal(&mut self, signal: SimulatorPlatformSignal) -> Result<(), String> {
        use SimulatorPlatformSignal as S;
        match signal {
            S::PowerOn => self.backend.signal(Signal::PowerOn),
            S::PowerOff => self.backend.signal(Signal::PowerOff),
            S::Reset => self.backend.signal(Signal::Reset),
            S::NvOn => self.backend.signal(Signal::NvOn),
            S::NvOff => self.backend.signal(Signal::NvOff),
            S::PhysicalPresenceOn => self.backend.signal(Signal::PhysicalPresenceOn),
            S::PhysicalPresenceOff => self.backend.signal(Signal::PhysicalPresenceOff),
            S::CancelOn => self.backend.signal(Signal::CancelOn),
            S::CancelOff => self.backend.signal(Signal::CancelOff),
            // Transport-level signals that leave the TPM untouched.
            S::KeyCacheOn
            | S::KeyCacheOff
            | S::SessionEnd
            | S::Stop
            | S::GetCommandResponseSizes
            | S::ActGetSignaled => {}
            // `Restart` is not a TPM Reset (the C simulator maps it to a
            // clock restart, tpm-rs ignores it): fail loudly rather than
            // mis-map it.
            S::Restart | S::TestFailureMode | S::SetFirmwareHash | S::SetFirmwareSvn => {
                return Err(format!(
                    "test `{}`: signal {signal:?} is not supported by {}",
                    self.test, self.implementation
                ));
            }
        }
        Ok(())
    }

    /// Executes `command` (which `tpm-rs` answered with `expected`) on
    /// the C reference at `locality` and compares the responses; a failure
    /// carries the C reference's response.
    fn exchange(
        &mut self,
        index: usize,
        locality: u8,
        command: &[u8],
        expected: &[u8],
    ) -> Result<(), Failure> {
        let test = self.test.as_str();
        let implementation = self.implementation;
        let ref_command = self.state.to_ref_command(command);
        let mut actual = self.backend.run_command(locality, &ref_command);
        // TPM_RC_RETRY rule: the C reference (upstream `CheckLockedOut`)
        // answers the first DA-protected authorization after a boot with
        // the TPM_RC_RETRY warning while it records `daUsed` in NV;
        // tpm-rs records it inline. Both are spec-compliant. Like a TSS,
        // re-issue the identical command once; its response is then
        // compared byte for byte (a second RETRY fails the comparison).
        if response_code(&actual) == Some(TPM_RC_RETRY)
            && response_code(expected) != Some(TPM_RC_RETRY)
        {
            self.retries += 1;
            if logging() {
                eprintln!(
                    "differential: test `{test}`, command {index}: {implementation} returned \
                     TPM_RC_RETRY; re-issuing once ({} retries so far)",
                    self.retries
                );
            }
            actual = self.backend.run_command(locality, &ref_command);
        }
        let st = &mut self.state;
        st.post_command(command, expected, &actual);
        let result = compare_differential_response(
            st,
            implementation,
            test,
            index,
            locality,
            command,
            expected,
            &actual,
        );
        result.map_err(|message| Failure {
            message,
            reference_response: Some(actual),
        })
    }
}

/// Command codes referenced by the documented exceptions.
mod cc {
    pub const PCR_RESET: u32 = 0x0000_013D;
    pub const INCREMENTAL_SELF_TEST: u32 = 0x0000_0142;
    pub const ECC_PARAMETERS: u32 = 0x0000_0178;
    pub const STARTUP: u32 = 0x0000_0144;
    pub const CONTEXT_LOAD: u32 = 0x0000_0161;
    pub const CONTEXT_SAVE: u32 = 0x0000_0162;
    pub const GET_CAPABILITY: u32 = 0x0000_017A;
}

/// `(command handles, response handles)` of every command code (TPM 2.0
/// Library Part 3), or `None` for an unknown command code.
pub fn handle_counts(code: u32) -> Option<(usize, usize)> {
    Some(match code {
        0x11F => (2, 0), // NV_UndefineSpaceSpecial
        0x120 => (2, 0), // EvictControl
        0x121 => (1, 0), // HierarchyControl
        0x122 => (2, 0), // NV_UndefineSpace
        0x124 => (1, 0), // ChangeEPS
        0x125 => (1, 0), // ChangePPS
        0x126 => (1, 0), // Clear
        0x127 => (1, 0), // ClearControl
        0x128 => (1, 0), // ClockSet
        0x129 => (1, 0), // HierarchyChangeAuth
        0x12A => (1, 0), // NV_DefineSpace
        0x12B => (1, 0), // PCR_Allocate
        0x12C => (1, 0), // PCR_SetAuthPolicy
        0x12D => (1, 0), // PP_Commands
        0x12E => (1, 0), // SetPrimaryPolicy
        0x12F => (2, 0), // FieldUpgradeStart
        0x130 => (1, 0), // ClockRateAdjust
        0x131 => (1, 1), // CreatePrimary
        0x132 => (1, 0), // NV_GlobalWriteLock
        0x133 => (2, 0), // GetCommandAuditDigest
        0x134 => (2, 0), // NV_Increment
        0x135 => (2, 0), // NV_SetBits
        0x136 => (2, 0), // NV_Extend
        0x137 => (2, 0), // NV_Write
        0x138 => (2, 0), // NV_WriteLock
        0x139 => (1, 0), // DictionaryAttackLockReset
        0x13A => (1, 0), // DictionaryAttackParameters
        0x13B => (1, 0), // NV_ChangeAuth
        0x13C => (1, 0), // PCR_Event
        0x13D => (1, 0), // PCR_Reset
        0x13E => (1, 0), // SequenceComplete
        0x13F => (1, 0), // SetAlgorithmSet
        0x140 => (1, 0), // SetCommandCodeAuditStatus
        0x141 => (0, 0), // FieldUpgradeData
        0x142 => (0, 0), // IncrementalSelfTest
        0x143 => (0, 0), // SelfTest
        0x144 => (0, 0), // Startup
        0x145 => (0, 0), // Shutdown
        0x146 => (0, 0), // StirRandom
        0x147 => (2, 0), // ActivateCredential
        0x148 => (2, 0), // Certify
        0x149 => (3, 0), // PolicyNV
        0x14A => (2, 0), // CertifyCreation
        0x14B => (2, 0), // Duplicate
        0x14C => (2, 0), // GetTime
        0x14D => (3, 0), // GetSessionAuditDigest
        0x14E => (2, 0), // NV_Read
        0x14F => (2, 0), // NV_ReadLock
        0x150 => (2, 0), // ObjectChangeAuth
        0x151 => (2, 0), // PolicySecret
        0x152 => (2, 0), // Rewrap
        0x153 => (1, 0), // Create
        0x154 => (1, 0), // ECDH_ZGen
        0x155 => (1, 0), // MAC
        0x156 => (1, 0), // Import
        0x157 => (1, 1), // Load
        0x158 => (1, 0), // Quote
        0x159 => (1, 0), // RSA_Decrypt
        0x15B => (1, 1), // MAC_Start
        0x15C => (1, 0), // SequenceUpdate
        0x15D => (1, 0), // Sign
        0x15E => (1, 0), // Unseal
        0x160 => (2, 0), // PolicySigned
        0x161 => (0, 1), // ContextLoad
        0x162 => (1, 0), // ContextSave
        0x163 => (1, 0), // ECDH_KeyGen
        0x164 => (1, 0), // EncryptDecrypt
        0x165 => (0, 0), // FlushContext
        0x167 => (0, 1), // LoadExternal
        0x168 => (1, 0), // MakeCredential
        0x169 => (1, 0), // NV_ReadPublic
        0x16A => (1, 0), // PolicyAuthorize
        0x16B => (1, 0), // PolicyAuthValue
        0x16C => (1, 0), // PolicyCommandCode
        0x16D => (1, 0), // PolicyCounterTimer
        0x16E => (1, 0), // PolicyCpHash
        0x16F => (1, 0), // PolicyLocality
        0x170 => (1, 0), // PolicyNameHash
        0x171 => (1, 0), // PolicyOR
        0x172 => (1, 0), // PolicyTicket
        0x173 => (1, 0), // ReadPublic
        0x174 => (1, 0), // RSA_Encrypt
        0x176 => (2, 1), // StartAuthSession
        0x177 => (1, 0), // VerifySignature
        0x178 => (0, 0), // ECC_Parameters
        0x179 => (0, 0), // FirmwareRead
        0x17A => (0, 0), // GetCapability
        0x17B => (0, 0), // GetRandom
        0x17C => (0, 0), // GetTestResult
        0x17D => (0, 0), // Hash
        0x17E => (0, 0), // PCR_Read
        0x17F => (1, 0), // PolicyPCR
        0x180 => (1, 0), // PolicyRestart
        0x181 => (0, 0), // ReadClock
        0x182 => (1, 0), // PCR_Extend
        0x183 => (1, 0), // PCR_SetAuthValue
        0x184 => (3, 0), // NV_Certify
        0x185 => (2, 0), // EventSequenceComplete
        0x186 => (0, 1), // HashSequenceStart
        0x187 => (1, 0), // PolicyPhysicalPresence
        0x188 => (1, 0), // PolicyDuplicationSelect
        0x189 => (1, 0), // PolicyGetDigest
        0x18A => (0, 0), // TestParms
        0x18B => (1, 0), // Commit
        0x18C => (1, 0), // PolicyPassword
        0x18D => (1, 0), // ZGen_2Phase
        0x18E => (0, 0), // EC_Ephemeral
        0x18F => (1, 0), // PolicyNvWritten
        0x190 => (1, 0), // PolicyTemplate
        0x191 => (1, 1), // CreateLoaded
        0x192 => (3, 0), // PolicyAuthorizeNV
        0x193 => (1, 0), // EncryptDecrypt2
        0x194 => (1, 0), // AC_GetCapability
        0x195 => (3, 0), // AC_Send
        0x196 => (1, 0), // Policy_AC_SendSelect
        0x197 => (2, 0), // CertifyX509
        0x198 => (1, 0), // ACT_SetTimeout
        0x199 => (1, 0), // ECC_Encrypt
        0x19A => (1, 0), // ECC_Decrypt
        0x19B => (1, 0), // PolicyCapability
        0x19C => (1, 0), // PolicyParameters
        0x19D => (1, 0), // NV_DefineSpace2
        0x19E => (1, 0), // NV_ReadPublic2
        0x19F => (1, 0), // SetCapability
        0x1A0 => (1, 0), // ReadOnlyControl
        0x1A1 => (1, 0), // PolicyTransportSPDM
        0x1A3 => (2, 0), // VerifySequenceComplete
        0x1A4 => (2, 0), // SignSequenceComplete
        0x1A5 => (1, 0), // VerifyDigestSignature
        0x1A6 => (1, 0), // SignDigest
        0x1A7 => (1, 0), // Encapsulate
        0x1A8 => (1, 0), // Decapsulate
        0x1A9 => (1, 1), // VerifySequenceStart
        0x1AA => (1, 1), // SignSequenceStart
        _ => return None,
    })
}

/// A cursor over marshaled TPM data.
#[derive(Clone, Copy)]
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    /// The next `n` bytes.
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    /// The next `TPM2B` in wire form (size field and buffer).
    fn tpm2b(&mut self) -> Option<&'a [u8]> {
        let size = be16(self.0, 0)? as usize;
        self.take(2 + size)
    }

    /// The buffer of the next `TPM2B`.
    fn tpm2b_body(&mut self) -> Option<&'a [u8]> {
        self.tpm2b().map(|b| &b[2..])
    }
}

/// The areas of a well-formed, successful response.
struct ResponseParts<'a> {
    /// The parameter area.
    params: &'a [u8],
    /// The authorization area (empty for a `TPM_ST_NO_SESSIONS` response).
    auth: &'a [u8],
}

/// Splits a successful response to command `code` into its areas;
/// `None` for an error response, an unknown command code or a malformed
/// envelope.
fn split_response(rsp: &[u8], code: u32) -> Option<ResponseParts<'_>> {
    let (tag, rc) = header(rsp)?;
    if rc != 0 || be32(rsp, 2)? as usize != rsp.len() {
        return None;
    }
    let at = 10 + 4 * handle_counts(code)?.1;
    match tag {
        0x8001 => Some(ResponseParts {
            params: rsp.get(at..)?,
            auth: &[],
        }),
        0x8002 => {
            let size = be32(rsp, at)? as usize;
            Some(ResponseParts {
                params: rsp.get(at + 4..at + 4 + size)?,
                auth: rsp.get(at + 4 + size..)?,
            })
        }
        _ => None,
    }
}

/// The `contextBlob` buffer of a `TPM2_ContextSave` parameter area (a
/// `TPMS_CONTEXT`: sequence, savedHandle, hierarchy, contextBlob).
fn context_blob(params: &[u8]) -> Option<&[u8]> {
    let mut r = Reader(params);
    r.take(16)?;
    let blob = r.tpm2b_body()?;
    r.0.is_empty().then_some(blob)
}

/// Splits a `TPM2_ECC_Parameters` parameter area
/// (`TPMS_ALGORITHM_DETAIL_ECC`) into its scalar head (`curveID`,
/// `keySize`, `kdf`, `sign`) and the buffers of `p`, `a`, `b`, `gX`, `gY`,
/// `n` and `h`.
fn ecc_parameters(params: &[u8]) -> Option<(&[u8], Vec<&[u8]>)> {
    const TPM_ALG_NULL: u16 = 0x0010;
    const TPM_ALG_ECDAA: u16 = 0x001A;
    let mut r = Reader(params);
    r.take(4)?;
    // TPMT_KDF_SCHEME: every scheme but NULL carries a hash algorithm.
    if r.u16()? != TPM_ALG_NULL {
        r.u16()?;
    }
    // TPMT_ECC_SCHEME: a hash algorithm, plus `count` for ECDAA.
    match r.u16()? {
        TPM_ALG_NULL => {}
        TPM_ALG_ECDAA => {
            r.take(4)?;
        }
        _ => {
            r.u16()?;
        }
    }
    let head = &params[..params.len() - r.0.len()];
    let fields = (0..7).map(|_| r.tpm2b_body()).collect::<Option<Vec<_>>>()?;
    r.0.is_empty().then_some((head, fields))
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// `(tag, code)` of a command or response header (`code` is the command
/// code or the response code).
fn header(b: &[u8]) -> Option<(u16, u32)> {
    Some((be16(b, 0)?, be32(b, 6)?))
}

/// Splits a command into its `n_handles` handles and its parameter area
/// (skipping the authorization area of a `TPM_ST_SESSIONS` command).
fn command_parts(cmd: &[u8], n_handles: usize) -> Option<(Vec<u32>, &[u8])> {
    let (tag, _) = header(cmd)?;
    let mut at = 10;
    let mut handles = Vec::with_capacity(n_handles);
    for _ in 0..n_handles {
        handles.push(be32(cmd, at)?);
        at += 4;
    }
    if tag == 0x8002 {
        at += 4 + be32(cmd, at)? as usize;
    }
    Some((handles, cmd.get(at..)?))
}

/// The offset and contents of the parameter area of a successful response
/// with `n_handles` handles (without the trailing authorization area).
fn response_params_at(rsp: &[u8], n_handles: usize) -> Option<(usize, &[u8])> {
    let (tag, _) = header(rsp)?;
    let at = 10 + 4 * n_handles;
    if tag == 0x8002 {
        let size = be32(rsp, at)? as usize;
        Some((at + 4, rsp.get(at + 4..at + 4 + size)?))
    } else {
        Some((at, rsp.get(at..)?))
    }
}

/// The parameter area of a successful response with `n_handles` handles
/// (without the trailing authorization area).
fn response_params(rsp: &[u8], n_handles: usize) -> Option<&[u8]> {
    response_params_at(rsp, n_handles).map(|(_, p)| p)
}

/// Parses a `TPMS_CAPABILITY_DATA` list of a `TPM2_GetCapability`
/// response: `(moreData, capability, entries)`, each entry being its raw
/// bytes. `None` for capabilities without a known entry layout or trailing
/// bytes.
fn capability_list(rsp: &[u8]) -> Option<(u8, u32, Vec<&[u8]>)> {
    let p = response_params(rsp, 0)?;
    let more = *p.first()?;
    let cap = be32(p, 1)?;
    let count = be32(p, 5)? as usize;
    let mut at = 9;
    let mut entries = Vec::new();
    for _ in 0..count {
        let len = match cap {
            // TPM_CAP_ALGS: TPMS_ALG_PROPERTY.
            0 => 6,
            // TPM_CAP_HANDLES, TPM_CAP_COMMANDS, TPM_CAP_PP_COMMANDS,
            // TPM_CAP_AUDIT_COMMANDS: 32-bit values.
            1..=4 => 4,
            // TPM_CAP_PCRS: TPMS_PCR_SELECTION.
            5 => 3 + *p.get(at + 2)? as usize,
            // TPM_CAP_TPM_PROPERTIES: TPMS_TAGGED_PROPERTY.
            6 => 8,
            // TPM_CAP_PCR_PROPERTIES: TPMS_TAGGED_PCR_SELECT.
            7 => 5 + *p.get(at + 4)? as usize,
            // TPM_CAP_ECC_CURVES: TPM_ECC_CURVE.
            8 => 2,
            // TPM_CAP_AUTH_POLICIES: TPMS_TAGGED_POLICY (handle + TPMT_HA).
            9 => {
                6 + match be16(p, at + 4)? {
                    0x0004 => 20,
                    0x000B => 32,
                    0x000C => 48,
                    0x000D => 64,
                    0x0010 => 0,
                    _ => return None,
                }
            }
            _ => return None,
        };
        entries.push(p.get(at..at + len)?);
        at += len;
    }
    (at == p.len()).then_some((more, cap, entries))
}

/// Exception 2 (`TPM2_GetCapability`): the capability lists may differ
/// only by the documented implementation-specific entries; every other
/// entry, the entry order, `moreData` and the selector must be identical.
fn capability_difference_is_documented(expected: &[u8], actual: &[u8]) -> bool {
    let (Some((e_more, e_cap, e)), Some((a_more, a_cap, a))) =
        (capability_list(expected), capability_list(actual))
    else {
        return false;
    };
    if e_cap != a_cap {
        return false;
    }
    let keep = |list: &[&[u8]], drop: &dyn Fn(&[u8]) -> bool| -> Vec<Vec<u8>> {
        list.iter()
            .filter(|x| !drop(x))
            .map(|x| x.to_vec())
            .collect()
    };
    let none = |_: &[u8]| false;
    match e_cap {
        // TPM_CAP_TPM_PROPERTIES: values of implementation-specific
        // properties may differ; C additionally reports
        // TPM_PT_FIRMWARE_SVN/TPM_PT_FIRMWARE_MAX_SVN (0x12F/0x130, spec
        // 1.83+) and, from version 185 on, TPM_PT_ML_PARAMETER_SETS (0x131)
        // with no ML-KEM/ML-DSA parameter set implemented (value 0). All
        // other properties must match exactly.
        6 => {
            const IMPLEMENTATION_SPECIFIC: &[u32] = &[
                0x10F, // TPM_PT_HR_PERSISTENT_MIN
                0x116, // TPM_PT_NV_COUNTERS_MAX
                0x118, // TPM_PT_MEMORY
                0x119, // TPM_PT_CLOCK_UPDATE
                0x11C, // TPM_PT_CONTEXT_SYM_SIZE
                0x11F, // TPM_PT_MAX_RESPONSE_SIZE
                // TPM_PT_MAX_OBJECT_CONTEXT/TPM_PT_MAX_SESSION_CONTEXT: the bounds of each
                // implementation's own context format (exception 1); C reports
                // SIZE_OF_CONTEXT_OVERHEAD + sizeof(OBJECT)/sizeof(SESSION), tpm-rs the bounds
                // of its serialization (context_save.rs).
                0x121, // TPM_PT_MAX_OBJECT_CONTEXT
                0x122, // TPM_PT_MAX_SESSION_CONTEXT
                0x12D, // TPM_PT_MODES (vendor certification modes)
            ];
            let prop = |x: &[u8]| be32(x, 0).unwrap_or(0);
            let ref_only = |x: &[u8]| {
                matches!(prop(x), 0x12F | 0x130) || (prop(x) == 0x131 && be32(x, 4) == Some(0))
            };
            let mask = |list: Vec<Vec<u8>>| -> Vec<Vec<u8>> {
                list.into_iter()
                    .map(|mut x| {
                        if IMPLEMENTATION_SPECIFIC.contains(&prop(&x)) {
                            x[4..].fill(0);
                        }
                        x
                    })
                    .collect()
            };
            // C's `moreData` may be YES where tpm-rs's is NO: tpm-rs returned every property
            // it has from the requested one on, and C's list (equal up to the C-only entries)
            // was cut by `propertyCount` before or within its C-only tail
            // (0x12F/0x130/0x131), the only properties C has beyond tpm-rs's last.
            let more_matches = e_more == a_more || (e_more == 0 && a_more == 1);
            more_matches && mask(keep(&e, &none)) == mask(keep(&a, &ref_only))
        }
        _ => false,
    }
}

/// With `DIFFERENTIAL_LOG_EXCEPTIONS` set, logs every applied documented exception
/// (one `DIFFEXC` line with the command and both responses in base64), so
/// the exceptions' hit counts can be audited.
fn log_exception(
    test: &str,
    index: usize,
    code: u32,
    command: &[u8],
    expected: &[u8],
    actual: &[u8],
) {
    if logging() {
        eprintln!(
            "DIFFEXC test={test} command={index} cc={code:#010x} cmd={} rs={} ref={}",
            hex(command),
            hex(expected),
            hex(actual),
        );
    }
}

/// Compares the C reference response (`actual`) with the recorded tpm-rs
/// response (`expected`): they must be byte-identical, except for the
/// narrowly-scoped, documented divergences below (each also listed in
/// `differential.md`). Every exception requires the same command code and
/// checks every response field it does not explicitly exempt.
#[allow(clippy::too_many_arguments)]
fn compare_differential_response(
    st: &DiffState,
    implementation: Implementation,
    test: &str,
    index: usize,
    locality: u8,
    command: &[u8],
    expected: &[u8],
    actual: &[u8],
) -> Result<(), String> {
    if expected == actual {
        return Ok(());
    }
    let code = header(command).map(|(_, c)| c).unwrap_or(0);
    let exp_rc = header(expected).map(|(_, rc)| rc);
    let act_rc = header(actual).map(|(_, rc)| rc);
    let same_tag = header(expected).map(|(t, _)| t) == header(actual).map(|(t, _)| t);

    let documented = match (code, exp_rc, act_rc) {
        // 1. TPM2_ContextSave: the `contextBlob` (encrypted OBJECT/SESSION
        //    image) is implementation-defined; `sequence`, `savedHandle` and
        //    `hierarchy` must match, and the blob is checked indirectly: a
        //    later TPM2_ContextLoad of it must behave identically.
        (cc::CONTEXT_SAVE, Some(0), Some(0)) => {
            same_tag
                && match (split_response(expected, code), split_response(actual, code)) {
                    (Some(e), Some(a)) => {
                        context_blob(e.params).is_some()
                            && context_blob(a.params).is_some()
                            && e.params[..16] == a.params[..16]
                            && e.auth == a.auth
                    }
                    _ => false,
                }
        }
        // 2. TPM2_GetCapability: see `capability_difference_is_documented`.
        (cc::GET_CAPABILITY, Some(0), Some(0)) => {
            header(expected).is_some_and(|(tag, _)| tag == 0x8001)
                && same_tag
                && capability_difference_is_documented(expected, actual)
        }
        // 3. TPM2_ECC_Parameters: tpm-rs pads every curve parameter to the
        //    curve's byte width; C's `CryptEccData.c` constants omit leading
        //    zero bytes (e.g. `a = 0` on BN_P256, `b` on NIST_P521). All
        //    fields must match up to leading zero bytes.
        (cc::ECC_PARAMETERS, Some(0), Some(0)) => {
            fn trim_zeros(mut s: &[u8]) -> &[u8] {
                while let Some((&0, rest)) = s.split_first() {
                    s = rest;
                }
                s
            }
            same_tag
                && match (split_response(expected, code), split_response(actual, code)) {
                    (Some(e), Some(a)) => {
                        e.auth == a.auth
                            && match (ecc_parameters(e.params), ecc_parameters(a.params)) {
                                (Some((e_head, e_fields)), Some((a_head, a_fields))) => {
                                    e_head == a_head
                                        && e_fields
                                            .iter()
                                            .zip(&a_fields)
                                            .all(|(e, a)| trim_zeros(e) == trim_zeros(a))
                                }
                                _ => false,
                            }
                    }
                    _ => false,
                }
        }
        // 4. TPM2_IncrementalSelfTest: `toDoList` is TPM-dependent (Part 3
        //    §10.3: the list of algorithms that still need testing); the C
        //    reference is built with ENABLE_SELF_TESTS = NO and a different
        //    algorithm set, so the lists differ in content and order. Both
        //    must be well-formed TPML_ALG responses with identical headers
        //    and no other content.
        (cc::INCREMENTAL_SELF_TEST, Some(0), Some(0)) => {
            let well_formed = |r: &[u8]| {
                header(r).is_some_and(|(tag, _)| tag == 0x8001)
                    && response_params(r, 0)
                        .is_some_and(|p| be32(p, 0).is_some_and(|n| p.len() == 4 + 2 * n as usize))
            };
            well_formed(expected) && well_formed(actual)
        }
        // 8. Retired: tpm-rs selects locality 0 for a reserved locality (5..=31)
        //    like the C simulator's platform layer (`_plat__LocalitySet`).
        // 9. TPM2_ContextLoad of a `contextBlob` that is not byte-identical
        //    to one tpm-rs returned (truncated or modified by the test): the
        //    blob layout is implementation-defined, so both must reject it
        //    as a malformed blob, but whether the size or the integrity
        //    check fires first depends on the layout (TPM_RC_SIZE + P1 vs
        //    TPM_RC_INTEGRITY + P1).
        //    tpm-rs may also answer `TPM_RC_FAILURE`: a blob from another run
        //    can be authentic (all implementations share the proofs under one
        //    seed) and then fail tpm-rs's decrypted fingerprint check, for which
        //    the specification requires failure mode (TPM 2.0 Part 3,
        //    TPM2_ContextLoad: "The TPM shall perform a check on the decrypted
        //    context [...] and enter failure mode if the check fails."); C gets
        //    the blob with a zeroed integrity value
        //    (`DiffState::untranslated_context_load`) and rejects it.
        (cc::CONTEXT_LOAD, Some(e @ (0x1D5 | 0x1DF | 0x101)), Some(a @ (0x1D5 | 0x1DF))) => {
            e != a
                && command_parts(command, 0).is_some_and(|(_, p)| {
                    // TPMS_CONTEXT: sequence (8), savedHandle (4),
                    // hierarchy (4), contextBlob (TPM2B).
                    be16(p, 16).is_some_and(|len| {
                        p.get(18..18 + len as usize).is_some_and(|blob| {
                            !st.context_blobs.iter().any(|(rs, _)| rs.as_slice() == blob)
                        })
                    })
                })
        }
        _ => false,
    };
    if documented {
        log_exception(test, index, code, command, expected, actual);
        return Ok(());
    }

    Err(format!(
        "differential mismatch with {implementation} in test `{test}`, command {index} \
         (cc={code:#010x}, locality {locality}):\n\
         command:              {}\n\
         tpm-rs    (rc={exp_rc:#x?}): {}\n\
         {implementation:<9} (rc={act_rc:#x?}): {}",
        hex(command),
        hex(expected),
        hex(actual),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `TPM2_ContextLoad` command (no sessions) loading `blob`.
    fn context_load(blob: &[u8]) -> Vec<u8> {
        let mut cmd = vec![0x80, 0x01, 0, 0, 0, 0, 0x00, 0x00, 0x01, 0x61];
        cmd.extend_from_slice(&7u64.to_be_bytes()); // sequence
        cmd.extend_from_slice(&0x8000_0001u32.to_be_bytes()); // savedHandle
        cmd.extend_from_slice(&0x4000_0001u32.to_be_bytes()); // hierarchy
        cmd.extend_from_slice(&(blob.len() as u16).to_be_bytes());
        cmd.extend_from_slice(blob);
        let len = cmd.len() as u32;
        cmd[2..6].copy_from_slice(&len.to_be_bytes());
        cmd
    }

    #[test]
    fn context_load_of_a_recorded_blob_is_translated() {
        let state = DiffState {
            context_blobs: vec![(vec![1; 40], vec![2; 64]), (vec![3; 10], vec![4; 5])],
        };
        assert_eq!(
            state.to_ref_command(&context_load(&[1; 40])),
            context_load(&[2; 64])
        );
        assert_eq!(
            state.to_ref_command(&context_load(&[3; 10])),
            context_load(&[4; 5])
        );
    }

    #[test]
    fn context_load_of_another_blob_is_unchanged() {
        let state = DiffState {
            context_blobs: vec![(vec![1; 40], vec![2; 64])],
        };
        for blob in [&[1u8; 39][..], &[1; 41], &[9; 40], &[]] {
            let cmd = context_load(blob);
            assert_eq!(state.to_ref_command(&cmd), cmd);
        }
        // A truncated command is passed through as well.
        let cmd = context_load(&[1; 40]);
        let truncated = &cmd[..cmd.len() - 1];
        assert_eq!(state.to_ref_command(truncated), truncated);
    }

    #[test]
    fn the_latest_context_save_wins() {
        let state = DiffState {
            context_blobs: vec![(vec![1; 8], vec![2; 8]), (vec![1; 8], vec![5; 9])],
        };
        assert_eq!(
            state.to_ref_command(&context_load(&[1; 8])),
            context_load(&[5; 9])
        );
    }

    /// A backend that records what it is asked to do and answers every
    /// command with a fixed response.
    #[derive(Default)]
    struct MockBackend {
        /// The virtual clock at every `init`.
        inits: Vec<u64>,
        /// Every command executed.
        commands: Vec<Vec<u8>>,
        /// The response to every command but `TPM2_Startup`.
        response: Vec<u8>,
    }

    impl Backend for MockBackend {
        fn init(&mut self) {
            self.inits.push(virtual_ms());
        }
        fn advance_clock(&mut self, _ms: u64) {}
        fn signal(&mut self, _signal: Signal) {}
        fn hash_start(&mut self) {}
        fn hash_data(&mut self, _data: &[u8]) {}
        fn hash_end(&mut self) {}
        fn run_command(&mut self, _locality: u8, command: &[u8]) -> Vec<u8> {
            self.commands.push(command.to_vec());
            if header(command).map(|(_, code)| code) == Some(cc::STARTUP) {
                vec![0x80, 0x01, 0, 0, 0, 10, 0, 0, 0, 0]
            } else {
                self.response.clone()
            }
        }
    }

    /// `TPM2_GetRandom(8)`.
    const GET_RANDOM_8: [u8; 12] = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x7B, 0, 8];

    /// Holds [`VIRTUAL_CLOCK_TEST_LOCK`]: the test sets the process-global virtual clock.
    #[test]
    fn reinit_restarts_the_reference_like_a_new_process() {
        let _clock = VIRTUAL_CLOCK_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        set_virtual_ms(5_000);
        let backend = MockBackend {
            response: vec![0x80, 0x01, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0],
            ..MockBackend::default()
        };
        let mut server = Server::new(Implementation::Mstpm20, backend, "reinit".into()).unwrap();
        assert_eq!(server.backend.inits, [5_000]);
        server.handle(Request::AdvanceClock(250)).unwrap();
        assert_eq!(virtual_ms(), 5_250);
        server.state.context_blobs.push((vec![1], vec![2]));
        // A diverging command fails with the reference's response.
        let failure = server
            .handle(Request::Exchange {
                locality: 0,
                command: GET_RANDOM_8.to_vec(),
                expected: vec![0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x01],
            })
            .unwrap_err();
        assert_eq!(
            failure.reference_response,
            Some(server.backend.response.clone())
        );
        assert_eq!(server.commands, 1);

        server.handle(Request::Reinit).unwrap();
        assert_eq!(virtual_ms(), 5_000, "the clock returns to the seed time");
        assert_eq!(server.backend.inits, [5_000, 5_000]);
        assert_eq!(server.commands, 0);
        assert!(server.state.context_blobs.is_empty());
        let codes: Vec<u32> = server
            .backend
            .commands
            .iter()
            .filter_map(|c| header(c).map(|(_, code)| code))
            .collect();
        assert_eq!(codes, [cc::STARTUP, 0x17B, cc::STARTUP]);
        // A matching command succeeds after the re-initialization.
        let expected = server.backend.response.clone();
        server
            .handle(Request::Exchange {
                locality: 0,
                command: GET_RANDOM_8.to_vec(),
                expected,
            })
            .unwrap();
        reinit_reports_a_failed_startup();
    }

    /// A failed `TPM2_Startup` fails the re-initialization (part of
    /// [`reinit_restarts_the_reference_like_a_new_process`], which holds the
    /// virtual clock lock).
    fn reinit_reports_a_failed_startup() {
        struct FailingStartup(bool);
        impl Backend for FailingStartup {
            fn init(&mut self) {}
            fn advance_clock(&mut self, _ms: u64) {}
            fn signal(&mut self, _signal: Signal) {}
            fn hash_start(&mut self) {}
            fn hash_data(&mut self, _data: &[u8]) {}
            fn hash_end(&mut self) {}
            fn run_command(&mut self, _locality: u8, _command: &[u8]) -> Vec<u8> {
                let rc = if self.0 { 0x100u32 } else { 0 };
                let mut rsp = vec![0x80, 0x01, 0, 0, 0, 10];
                rsp.extend_from_slice(&rc.to_be_bytes());
                rsp
            }
        }
        let mut server =
            Server::new(Implementation::Ibmswtpm2, FailingStartup(false), "t".into()).unwrap();
        server.backend.0 = true;
        let failure = server.reinit().unwrap_err();
        assert!(failure.message.contains("TPM2_Startup"), "{failure:?}");
        assert_eq!(failure.reference_response, None);
    }

    /// A `TPM2_ContextLoad` whose `commandSize` is not its length is sent
    /// unchanged, even if its blob is a known tpm-rs blob, so C sees the
    /// same malformed size.
    #[test]
    fn context_load_with_wrong_command_size_is_not_translated() {
        let state = DiffState {
            context_blobs: vec![(vec![0xAA], vec![0xBB, 0xCC])],
        };
        // TPM2_ContextLoad: sequence, savedHandle, hierarchy, blob {0xAA}.
        let mut cmd = vec![0x80, 0x01, 0, 0, 0, 0, 0, 0, 0x01, 0x61];
        cmd.extend_from_slice(&[0; 16]);
        cmd.extend_from_slice(&[0, 1, 0xAA]);
        let len = cmd.len() as u32;
        cmd[2..6].copy_from_slice(&len.to_be_bytes());
        let translated = state.to_ref_command(&cmd);
        assert_eq!(translated[translated.len() - 4..], [0, 2, 0xBB, 0xCC]);
        assert_eq!(be32(&translated, 2), Some(len + 1));
        cmd[2..6].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(state.to_ref_command(&cmd), cmd);
        // Bytes after the context: sent unchanged too.
        cmd.push(0);
        let len = cmd.len() as u32;
        cmd[2..6].copy_from_slice(&len.to_be_bytes());
        assert_eq!(state.to_ref_command(&cmd), cmd);
    }

    /// A `TPM2_ContextLoad` blob that is not one tpm-rs saved reaches C with
    /// a zeroed integrity value, so C cannot authenticate tpm-rs's contents.
    #[test]
    fn untranslated_context_blob_is_unauthentic_for_the_reference() {
        let state = DiffState::default();
        // TPM2_ContextLoad: sequence, savedHandle, hierarchy, blob {integrity {0x11, 0x22}, 0x33}.
        let mut cmd = vec![0x80, 0x01, 0, 0, 0, 0, 0, 0, 0x01, 0x61];
        cmd.extend_from_slice(&[0; 16]);
        cmd.extend_from_slice(&[0, 5, 0, 2, 0x11, 0x22, 0x33]);
        let len = cmd.len() as u32;
        cmd[2..6].copy_from_slice(&len.to_be_bytes());
        let out = state.to_ref_command(&cmd);
        assert_eq!(out[..cmd.len() - 3], cmd[..cmd.len() - 3]);
        assert_eq!(out[cmd.len() - 3..], [0, 0, 0x33]);
        // A tampered integrity value is not turned back into the authentic one.
        let n = cmd.len();
        cmd[n - 3] ^= 0xFF;
        assert_eq!(state.to_ref_command(&cmd)[n - 3..], [0, 0, 0x33]);
    }
}
