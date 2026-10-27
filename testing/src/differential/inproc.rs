//! The C reference TPM linked into this process: the FFI of the patched C
//! reference of the build's target ([`Implementation::TARGET`]) and the hosts
//! built on it.
//!
//! `testing/build.rs` compiles the target into a symbol-isolated static
//! archive whose only global symbols are its entry points, prefixed with its
//! name (`difftest_mstpm20_*` or `difftest_ibmswtpm2_*`), and links the
//! archive into this crate. The archives call back into the harness through
//! symbols this module defines:
//!
//! * `difftest_getpid()`: the reference's `getpid()` (redirected at link
//!   time), the process ID of the seed (see [`set_reference_pid`]);
//! * `difftest_virtual_ms()`: the virtual clock the patched `_plat__RealTime()`
//!   reads ([`server::virtual_ms`]);
//! * `difftest_<name>_rand()`/`difftest_<name>_srand()`: the reference's
//!   `rand()`/`srand()` (redirected at link time), a port of glibc's
//!   generator ([`GlibcRand`]) per reference. In a process of its own, a
//!   reference would own the C library's generator; here two references may
//!   share the process, and each still has a generator of its own.
//!
//! On top of the FFI ([`CReference`], a [`Backend`]), this module provides
//! the two ways to host the references:
//!
//! * [`serve_process`]: the reference processes (`src/bin/reference.rs`)
//!   that [`super::References`] launches, one per `Tpm`;
//! * `InProcReferences` (with the `fuzz-inproc` feature): the reference in
//!   the calling process, with the same interface as
//!   [`super::References`] but without processes and pipes.
//!
//! The C references keep their state in globals, so each can be hosted at
//! most once per process at a time ([`CReference::acquire`] enforces this).
//! Different references share no C state (every global but the entry points
//! is local to its archive, including its copy of OpenSSL), and the shared
//! callbacks are thread-safe, so two different references may run
//! concurrently on different threads.
//!
//! # Unsafe code
//! This is the only module of the crate with `unsafe` code (the crate root
//! denies it elsewhere): the calls of the C entry points, the exported
//! callbacks and the stdout takeover of [`serve_process`]. Every `unsafe`
//! block states why it is sound.

#![allow(unsafe_code)]

use std::io::BufReader;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use tpm2_platform_linux::GlibcRand;

use super::Implementation;
use super::protocol::FirmwareSetting;
use super::server::{self, Backend, Signal};
use crate::seed::ReferenceSeed;
use tpm2::platform::SimulatedFirmware;

/// The entry points of one linked C reference (see the reference patches
/// `harness-difftest-entry-points.patch`).
struct EntryPoints {
    /// Manufactures the TPM, powers it on and makes NV available.
    init: unsafe extern "C" fn(),
    /// Advances the reference's own clock (a no-op in both references).
    advance_clock: unsafe extern "C" fn(ms: u64),
    signal_power_on: unsafe extern "C" fn(),
    signal_power_off: unsafe extern "C" fn(),
    signal_reset: unsafe extern "C" fn(),
    signal_nv_on: unsafe extern "C" fn(),
    signal_nv_off: unsafe extern "C" fn(),
    signal_physical_presence_on: unsafe extern "C" fn(),
    signal_physical_presence_off: unsafe extern "C" fn(),
    signal_cancel_on: unsafe extern "C" fn(),
    signal_cancel_off: unsafe extern "C" fn(),
    signal_hash_start: unsafe extern "C" fn(),
    signal_hash_data: unsafe extern "C" fn(data: *const u8, size: u32),
    signal_hash_end: unsafe extern "C" fn(),
    /// Installs a firmware image with another hash (`_plat__SetTpmFirmwareHash`,
    /// `harness-difftest-firmware.patch`).
    set_firmware_hash: unsafe extern "C" fn(hash: u32),
    /// Installs a firmware image with another SVN (`_plat__SetTpmFirmwareSvn`).
    set_firmware_svn: unsafe extern "C" fn(svn: u16),
    /// Executes `in_buf[..in_size]` at `locality`, writes the response to
    /// `out_buf[..out_cap]` and returns its length.
    run_command: unsafe extern "C" fn(
        locality: u8,
        in_buf: *const u8,
        in_size: u32,
        out_buf: *mut u8,
        out_cap: u32,
    ) -> u32,
}

/// Declares the entry points of the reference whose archive exports them
/// with `$prefix` (`difftest_<name>_`) in module `$module`, as an
/// [`EntryPoints`] table `$module::ENTRY_POINTS`.
macro_rules! entry_points {
    ($module:ident, $prefix:literal) => {
        mod $module {
            unsafe extern "C" {
                #[link_name = concat!($prefix, "init")]
                fn init();
                #[link_name = concat!($prefix, "advance_clock")]
                fn advance_clock(ms: u64);
                #[link_name = concat!($prefix, "signal_power_on")]
                fn signal_power_on();
                #[link_name = concat!($prefix, "signal_power_off")]
                fn signal_power_off();
                #[link_name = concat!($prefix, "signal_reset")]
                fn signal_reset();
                #[link_name = concat!($prefix, "signal_nv_on")]
                fn signal_nv_on();
                #[link_name = concat!($prefix, "signal_nv_off")]
                fn signal_nv_off();
                #[link_name = concat!($prefix, "signal_physical_presence_on")]
                fn signal_physical_presence_on();
                #[link_name = concat!($prefix, "signal_physical_presence_off")]
                fn signal_physical_presence_off();
                #[link_name = concat!($prefix, "signal_cancel_on")]
                fn signal_cancel_on();
                #[link_name = concat!($prefix, "signal_cancel_off")]
                fn signal_cancel_off();
                #[link_name = concat!($prefix, "signal_hash_start")]
                fn signal_hash_start();
                #[link_name = concat!($prefix, "signal_hash_data")]
                fn signal_hash_data(data: *const u8, size: u32);
                #[link_name = concat!($prefix, "signal_hash_end")]
                fn signal_hash_end();
                #[link_name = concat!($prefix, "set_firmware_hash")]
                fn set_firmware_hash(hash: u32);
                #[link_name = concat!($prefix, "set_firmware_svn")]
                fn set_firmware_svn(svn: u16);
                #[link_name = concat!($prefix, "run_command")]
                fn run_command(
                    locality: u8,
                    in_buf: *const u8,
                    in_size: u32,
                    out_buf: *mut u8,
                    out_cap: u32,
                ) -> u32;
            }

            pub(super) const ENTRY_POINTS: super::EntryPoints = super::EntryPoints {
                init,
                advance_clock,
                signal_power_on,
                signal_power_off,
                signal_reset,
                signal_nv_on,
                signal_nv_off,
                signal_physical_presence_on,
                signal_physical_presence_off,
                signal_cancel_on,
                signal_cancel_off,
                signal_hash_start,
                signal_hash_data,
                signal_hash_end,
                set_firmware_hash,
                set_firmware_svn,
                run_command,
            };
        }
    };
}

// Only the archive of the target is linked (see `testing/build.rs`).
#[cfg(any(feature = "target-mstpm20", feature = "target-mstpm20-v185"))]
entry_points!(mstpm20, "difftest_mstpm20_");
#[cfg(feature = "target-ibmswtpm2")]
entry_points!(ibmswtpm2, "difftest_ibmswtpm2_");

/// The entry points of `implementation`.
///
/// # Panics
/// Unless `implementation` is the target of this build ([`Implementation::TARGET`]), the only
/// implementation linked into it.
fn entry_points(implementation: Implementation) -> &'static EntryPoints {
    assert_eq!(
        implementation,
        Implementation::TARGET,
        "only the target's C reference is linked into this build"
    );
    #[cfg(feature = "target-ibmswtpm2")]
    return &ibmswtpm2::ENTRY_POINTS;
    #[cfg(not(feature = "target-ibmswtpm2"))]
    return &mstpm20::ENTRY_POINTS;
}

/// The process ID the C references see; `0` until [`set_reference_pid`]
/// (then the real one).
static REFERENCE_PID: AtomicU32 = AtomicU32::new(0);

/// Sets the process ID the C references' `getpid()` returns (the `pid` of
/// the seed, which with the clock seeds their random number generation).
pub fn set_reference_pid(pid: u32) {
    REFERENCE_PID.store(pid, Ordering::Relaxed);
}

/// `getpid()` as seen by the C references: `testing/build.rs` redirects
/// their `getpid` calls here. Returns the process ID set by
/// [`set_reference_pid`], or else the real one.
#[unsafe(no_mangle)]
pub extern "C" fn difftest_getpid() -> i32 {
    match REFERENCE_PID.load(Ordering::Relaxed) {
        0 => std::process::id() as i32,
        pid => pid as i32,
    }
}

/// The virtual clock the patched C references read as `_plat__RealTime()`
/// (milliseconds; see [`server::virtual_ms`]).
#[unsafe(no_mangle)]
pub extern "C" fn difftest_virtual_ms() -> u64 {
    server::virtual_ms()
}

/// The `rand()` generator of each reference (indexed by
/// [`Implementation`]); `None` until its first `srand()`, which glibc treats
/// as `srand(1)`.
static GENERATORS: [Mutex<Option<GlibcRand>>; Implementation::ALL.len()] =
    [const { Mutex::new(None) }; Implementation::ALL.len()];

/// `rand()` of `implementation` (glibc's, on the reference's own state).
fn rand(implementation: Implementation) -> i32 {
    let mut generator = GENERATORS[implementation as usize]
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    generator.get_or_insert_with(|| GlibcRand::new(1)).next() as i32
}

/// `srand(seed)` of `implementation`.
fn srand(implementation: Implementation, seed: u32) {
    *GENERATORS[implementation as usize]
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(GlibcRand::new(seed));
}

/// Returns the `rand()` generator of `implementation` to the state of a new
/// process (never seeded, i.e. `srand(1)` on first use).
fn reset_rand(implementation: Implementation) {
    *GENERATORS[implementation as usize]
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = None;
}

/// `rand()` of `mstpm20` (redirected by `testing/build.rs`).
#[unsafe(no_mangle)]
pub extern "C" fn difftest_mstpm20_rand() -> i32 {
    rand(Implementation::Mstpm20)
}

/// `srand()` of `mstpm20` (redirected by `testing/build.rs`).
#[unsafe(no_mangle)]
pub extern "C" fn difftest_mstpm20_srand(seed: u32) {
    srand(Implementation::Mstpm20, seed);
}

/// `rand()` of `ibmswtpm2` (redirected by `testing/build.rs`).
#[unsafe(no_mangle)]
pub extern "C" fn difftest_ibmswtpm2_rand() -> i32 {
    rand(Implementation::Ibmswtpm2)
}

/// `srand()` of `ibmswtpm2` (redirected by `testing/build.rs`).
#[unsafe(no_mangle)]
pub extern "C" fn difftest_ibmswtpm2_srand(seed: u32) {
    srand(Implementation::Ibmswtpm2, seed);
}

/// Whether each reference (indexed by [`Implementation`]) is hosted by a
/// [`CReference`].
static IN_USE: [AtomicBool; Implementation::ALL.len()] =
    [const { AtomicBool::new(false) }; Implementation::ALL.len()];

/// Capacity of the response buffer of [`CReference::run_command`] (larger
/// than any response of either reference).
const RESPONSE_CAPACITY: usize = 8192;

/// Exclusive access to the linked C reference of one implementation.
///
/// The C code keeps its state in globals and is not thread-safe, so at most
/// one `CReference` per implementation exists at a time, and its `&mut self`
/// methods serialize every call into that C reference. It may move between
/// threads (the C code has no thread affinity), and `CReference`s of
/// different implementations may be used concurrently.
pub struct CReference {
    implementation: Implementation,
    entry_points: &'static EntryPoints,
}

impl CReference {
    /// Takes the C reference of `implementation`; `None` while another
    /// `CReference` holds it.
    pub fn acquire(implementation: Implementation) -> Option<Self> {
        IN_USE[implementation as usize]
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        Some(Self {
            implementation,
            entry_points: entry_points(implementation),
        })
    }

    /// The implementation this is.
    pub fn implementation(&self) -> Implementation {
        self.implementation
    }
}

impl Drop for CReference {
    fn drop(&mut self) {
        IN_USE[self.implementation as usize].store(false, Ordering::Release);
    }
}

impl Backend for CReference {
    fn init(&mut self) {
        // Like a new process, the reference starts with an unseeded
        // `rand()`, so a re-init (`Server::reinit`) never keeps the previous
        // conversation's generator state and draws the same random values as
        // a new process, even if the reference draws from `rand()` before
        // seeding it.
        reset_rand(self.implementation);
        // SAFETY (this and the other entry-point calls below): the entry
        // points take no pointers or only the given valid buffers, and
        // `self` is the only handle to this C reference (see `acquire`), so
        // no other call into it runs concurrently.
        unsafe { (self.entry_points.init)() };
        // The firmware of a new reference process (the platform's statics
        // `currentHash`/`currentSvn` survive `init`).
        self.set_firmware(FirmwareSetting::Hash(SimulatedFirmware::DEFAULT_HASH));
        self.set_firmware(FirmwareSetting::Svn(SimulatedFirmware::DEFAULT_SVN));
    }

    fn set_firmware(&mut self, setting: FirmwareSetting) {
        // SAFETY: see `init`.
        match setting {
            FirmwareSetting::Hash(hash) => unsafe { (self.entry_points.set_firmware_hash)(hash) },
            FirmwareSetting::Svn(svn) => unsafe { (self.entry_points.set_firmware_svn)(svn) },
        }
    }

    fn advance_clock(&mut self, ms: u64) {
        // SAFETY: see `init`.
        unsafe { (self.entry_points.advance_clock)(ms) };
    }

    fn signal(&mut self, signal: Signal) {
        let ep = self.entry_points;
        let entry = match signal {
            Signal::PowerOn => ep.signal_power_on,
            Signal::PowerOff => ep.signal_power_off,
            Signal::Reset => ep.signal_reset,
            Signal::NvOn => ep.signal_nv_on,
            Signal::NvOff => ep.signal_nv_off,
            Signal::PhysicalPresenceOn => ep.signal_physical_presence_on,
            Signal::PhysicalPresenceOff => ep.signal_physical_presence_off,
            Signal::CancelOn => ep.signal_cancel_on,
            Signal::CancelOff => ep.signal_cancel_off,
        };
        // SAFETY: see `init`.
        unsafe { entry() };
    }

    fn hash_start(&mut self) {
        // SAFETY: see `init`.
        unsafe { (self.entry_points.signal_hash_start)() };
    }

    fn hash_data(&mut self, data: &[u8]) {
        let size = u32::try_from(data.len()).expect("_TPM_Hash_Data larger than 4 GiB");
        // SAFETY: `data` is valid for `size` bytes; see also `init`.
        unsafe { (self.entry_points.signal_hash_data)(data.as_ptr(), size) };
    }

    fn hash_end(&mut self) {
        // SAFETY: see `init`.
        unsafe { (self.entry_points.signal_hash_end)() };
    }

    fn run_command(&mut self, locality: u8, command: &[u8]) -> Vec<u8> {
        let size = u32::try_from(command.len()).expect("command larger than 4 GiB");
        let mut out = vec![0u8; RESPONSE_CAPACITY];
        // SAFETY: `command` is valid for `size` bytes and `out` is writable
        // for its length; see also `init`.
        let len = unsafe {
            (self.entry_points.run_command)(
                locality,
                command.as_ptr(),
                size,
                out.as_mut_ptr(),
                out.len() as u32,
            )
        };
        out.truncate(len as usize);
        out
    }
}

unsafe extern "C" {
    fn dup(fd: i32) -> i32;
    fn dup2(old_fd: i32, new_fd: i32) -> i32;
    fn clock_gettime(clock_id: i32, tp: *mut Timespec) -> i32;
}

/// `struct timespec` on 64-bit Linux.
#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

/// `CLOCK_MONOTONIC` on Linux.
const CLOCK_MONOTONIC: i32 = 1;

/// The current `CLOCK_MONOTONIC` time in milliseconds, computed exactly like
/// the C references' `_plat__RealTime()` (`tv_sec * 1000 + tv_nsec /
/// 1000000`), at which a reference process run by hand starts its virtual
/// clock.
fn monotonic_ms() -> u64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable `struct timespec`.
    let rc = unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime(CLOCK_MONOTONIC) failed");
    (ts.tv_sec as u64)
        .wrapping_mul(1000)
        .wrapping_add((ts.tv_nsec / 1_000_000) as u64)
}

/// Takes over stdout as the protocol channel: returns a file for the
/// original stdout and points file descriptor 1 at stderr, so output of the
/// C code cannot corrupt the protocol.
fn take_stdout() -> std::fs::File {
    use std::os::fd::FromRawFd as _;
    // SAFETY: `dup` has no memory-safety preconditions.
    let fd = unsafe { dup(1) };
    assert!(fd >= 0, "dup(stdout) failed");
    // SAFETY: `dup2` has no memory-safety preconditions; nothing in this
    // process owns file descriptor 1 as a Rust object.
    assert!(unsafe { dup2(2, 1) } >= 0, "dup2(stderr, stdout) failed");
    // SAFETY: `fd` is a freshly duplicated descriptor owned by nobody else.
    unsafe { std::fs::File::from_raw_fd(fd) }
}

/// Runs the reference process of `implementation` (the `main` of
/// `src/bin/reference.rs`, see [`server::serve`]);
/// the first command-line argument names the test.
///
/// The seed chosen by the parent (`TPM_REFERENCE_SEED`, always set by
/// [`super::Reference`]) gives the process ID `getpid()` returns to the C
/// reference and the start of its virtual clock, which only moves when the
/// harness advances it. Run by hand without it, the process uses its own
/// process ID and its `CLOCK_MONOTONIC` time at start-up.
///
/// # Panics
/// If the C reference is already hosted in this process, or the protocol
/// channel fails.
pub fn serve_process(implementation: Implementation) {
    let realtime_ms = monotonic_ms();
    let fixed = ReferenceSeed::from_env();
    if let Some(seed) = fixed {
        set_reference_pid(seed.pid);
    }
    let seed = ReferenceSeed {
        pid: difftest_getpid() as u32,
        realtime_ms: fixed.map_or(realtime_ms, |s| s.realtime_ms),
    };
    let test = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "<unknown>".into());
    let backend = CReference::acquire(implementation)
        .unwrap_or_else(|| panic!("the {implementation} C reference is already in use"));
    let output = std::io::BufWriter::new(take_stdout());
    let input = BufReader::new(std::io::stdin().lock());
    server::serve(implementation, backend, test, seed, input, output);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes the tests that host C references (each may be hosted once
    /// per process at a time) or use the process-global virtual clock: the
    /// server tests' lock, so they do not race with those either.
    pub(super) use super::super::server::VIRTUAL_CLOCK_TEST_LOCK as HOSTING;

    /// A C reference can be acquired only once at a time.
    #[test]
    fn c_reference_is_exclusive() {
        let _hosting = HOSTING.lock().unwrap_or_else(|e| e.into_inner());
        let first = CReference::acquire(Implementation::TARGET).expect("free");
        assert_eq!(first.implementation(), Implementation::TARGET);
        assert!(CReference::acquire(Implementation::TARGET).is_none());
        drop(first);
        assert!(CReference::acquire(Implementation::TARGET).is_some());
    }

    /// Every reference's `rand()` is glibc's generator on state of its own:
    /// seeding or drawing from one leaves the other's sequence unchanged.
    #[test]
    fn references_have_separate_rand_generators() {
        // Hosting a reference (re)seeds and resets its generator.
        let _hosting = HOSTING.lock().unwrap_or_else(|e| e.into_inner());
        difftest_mstpm20_srand(1234);
        difftest_ibmswtpm2_srand(1234);
        let mut expected = GlibcRand::new(1234);
        let first = expected.next() as i32;
        assert_eq!(difftest_mstpm20_rand(), first);
        difftest_ibmswtpm2_srand(99);
        for _ in 0..5 {
            difftest_ibmswtpm2_rand();
        }
        assert_eq!(difftest_mstpm20_rand(), expected.next() as i32);
        difftest_ibmswtpm2_srand(1234);
        assert_eq!(difftest_ibmswtpm2_rand(), first);
    }

    /// Initializing a reference returns its `rand()` to the state of a new
    /// process (glibc's implicit `srand(1)`), whatever it drew before, so a
    /// re-initialized reference draws the same values as a new process.
    #[test]
    fn init_resets_the_rand_generator() {
        let _hosting = HOSTING.lock().unwrap_or_else(|e| e.into_inner());
        difftest_ibmswtpm2_srand(99);
        difftest_ibmswtpm2_rand();
        reset_rand(Implementation::Ibmswtpm2);
        assert_eq!(difftest_ibmswtpm2_rand(), GlibcRand::new(1).next() as i32);
    }

    /// `getpid()` of the references returns the seed's process ID once set.
    #[test]
    fn getpid_returns_the_reference_pid() {
        let _hosting = HOSTING.lock().unwrap_or_else(|e| e.into_inner());
        set_reference_pid(4242);
        assert_eq!(difftest_getpid(), 4242);
    }
}

#[cfg(feature = "fuzz-inproc")]
pub use self::references::InProcReferences;

/// Both C references in the calling process (`fuzz-inproc`).
#[cfg(feature = "fuzz-inproc")]
mod references {
    use tpm2_simulator::SimulatorPlatformSignal;

    use super::super::protocol::{Failure, FirmwareSetting, Request};
    use super::super::server::{self, Server};
    use super::super::{Divergence, Implementation, join_messages};
    use super::{CReference, set_reference_pid};
    use crate::seed::ReferenceSeed;

    /// The commands that generate keys or use private keys, which take the C
    /// references milliseconds (RSA key generation dominates) and therefore
    /// run on all references concurrently (see [`InProcReferences`]).
    const EXPENSIVE_COMMANDS: [u32; 21] = [
        0x0000_0131, // TPM2_CreatePrimary
        0x0000_0153, // TPM2_Create
        0x0000_0191, // TPM2_CreateLoaded
        0x0000_0159, // TPM2_RSA_Decrypt
        0x0000_015D, // TPM2_Sign
        0x0000_0156, // TPM2_Import
        0x0000_014B, // TPM2_Duplicate
        0x0000_0152, // TPM2_Rewrap
        0x0000_0147, // TPM2_ActivateCredential
        0x0000_0176, // TPM2_StartAuthSession (salt decryption)
        0x0000_0158, // TPM2_Quote
        0x0000_0148, // TPM2_Certify
        0x0000_014A, // TPM2_CertifyCreation
        0x0000_014C, // TPM2_GetTime
        0x0000_0184, // TPM2_NV_Certify
        0x0000_014D, // TPM2_GetSessionAuditDigest
        0x0000_0133, // TPM2_GetCommandAuditDigest
        0x0000_0154, // TPM2_ECDH_ZGen
        0x0000_0163, // TPM2_ECDH_KeyGen
        0x0000_018D, // TPM2_ZGen_2Phase
        0x0000_018B, // TPM2_Commit
    ];

    /// Whether `command` is worth running on the references concurrently:
    /// one of [`EXPENSIVE_COMMANDS`] (by its header's command code).
    fn runs_in_parallel(command: &[u8]) -> bool {
        command
            .get(6..10)
            .map(|code| u32::from_be_bytes([code[0], code[1], code[2], code[3]]))
            .is_some_and(|code| EXPENSIVE_COMMANDS.contains(&code))
    }

    /// The C reference TPMs mirroring one `tpm-rs` TPM, hosted in the calling
    /// process: one [`Server`] over a [`CReference`] per implementation, all
    /// seeded with the same seed.
    ///
    /// It has the interface of [`super::super::References`], but every
    /// request runs in this process, without reference processes or pipes,
    /// which makes it much faster for short, numerous conversations such as
    /// fuzz inputs: cheap requests run on the calling thread, one reference
    /// after the other, and expensive commands ([`EXPENSIVE_COMMANDS`]) on
    /// all references concurrently (one scoped thread each; the references
    /// share no C state). Since the C references keep their state in
    /// globals, at most one `InProcReferences` exists per process at a time
    /// ([`Self::launch`] panics otherwise), so tests using it must not run in
    /// parallel within one process.
    ///
    /// The servers share the process's virtual clock
    /// ([`server::virtual_ms`]): before each server handles a request, the
    /// clock is set to its value before the request, so every reference sees
    /// the same time.
    pub struct InProcReferences {
        /// The server of every reference, with its implementation.
        servers: Vec<(Implementation, Server<CReference>)>,
    }

    impl InProcReferences {
        /// Hosts the C reference of every `implementation` in this process,
        /// seeded with `seed` (`getpid()` returns `seed.pid`, the virtual clock
        /// starts at `seed.realtime_ms`) and initialized like a new `Tpm`
        /// (manufactured, powered on, NV on, `TPM2_Startup(TPM_SU_CLEAR)`
        /// done).
        ///
        /// # Panics
        /// If a C reference is already hosted in this process (by another
        /// `InProcReferences`), or fails to initialize.
        pub fn launch(implementations: &[Implementation], seed: ReferenceSeed) -> Self {
            let test = std::thread::current()
                .name()
                .unwrap_or("<unnamed>")
                .to_owned();
            set_reference_pid(seed.pid);
            let mut servers = Vec::with_capacity(implementations.len());
            for &implementation in implementations {
                // Every reference starts at the seed's real time.
                server::set_virtual_ms(seed.realtime_ms);
                let backend = CReference::acquire(implementation).unwrap_or_else(|| {
                    panic!(
                        "test `{test}`: the {implementation} C reference is already hosted in \
                         this process (one InProcReferences per process at a time)"
                    )
                });
                let server = Server::new(implementation, backend, test.clone())
                    .unwrap_or_else(|e| panic!("{e}"));
                servers.push((implementation, server));
            }
            server::set_virtual_ms(seed.realtime_ms);
            Self { servers }
        }

        /// The implementations of the references.
        pub fn implementations(&self) -> impl Iterator<Item = Implementation> + '_ {
            self.servers
                .iter()
                .map(|(implementation, _)| *implementation)
        }

        /// Lets every server handle `request` (each with the virtual clock at
        /// its value before the request); the failing references.
        ///
        /// An expensive command (see [`runs_in_parallel`]) runs on all
        /// references concurrently, one thread each, like the reference
        /// processes do; everything else runs on the calling thread, one
        /// reference after the other, which is cheaper than a thread handoff.
        fn try_call(&mut self, request: Request) -> Result<(), Vec<Divergence>> {
            let before = server::virtual_ms();
            let parallel = self.servers.len() > 1
                && matches!(&request, Request::Exchange { command, .. } if runs_in_parallel(command));
            let results: Vec<(Implementation, Result<(), Failure>)> = if parallel {
                // An exchange leaves the virtual clock alone, so the
                // references can share it while they run.
                server::set_virtual_ms(before);
                std::thread::scope(|scope| {
                    let workers: Vec<_> = self
                        .servers
                        .iter_mut()
                        .map(|(implementation, server)| {
                            let request = request.clone();
                            (*implementation, scope.spawn(move || server.handle(request)))
                        })
                        .collect();
                    workers
                        .into_iter()
                        .map(|(implementation, worker)| {
                            let result = worker
                                .join()
                                .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
                            (implementation, result)
                        })
                        .collect()
                })
            } else {
                self.servers
                    .iter_mut()
                    .map(|(implementation, server)| {
                        server::set_virtual_ms(before);
                        (*implementation, server.handle(request.clone()))
                    })
                    .collect()
            };
            let divergences: Vec<Divergence> = results
                .into_iter()
                .filter_map(|(implementation, result)| {
                    let Failure {
                        message,
                        reference_response,
                    } = result.err()?;
                    Some(Divergence {
                        implementation,
                        reference_response,
                        message,
                    })
                })
                .collect();
            if divergences.is_empty() {
                Ok(())
            } else {
                Err(divergences)
            }
        }

        /// Lets every server handle `request`.
        ///
        /// # Panics
        /// If any reference fails (with the messages of all failing
        /// references).
        fn call(&mut self, request: Request) {
            if let Err(divergences) = self.try_call(request) {
                panic!("{}", join_messages(&divergences));
            }
        }

        /// Re-initializes every reference like a new one with the same seed
        /// (see [`Server::reinit`]): virtual clock back at the seed's real
        /// time, manufactured, powered on, NV on, `TPM2_Startup(TPM_SU_CLEAR)`
        /// done, and comparison state cleared.
        ///
        /// # Panics
        /// If a reference fails to re-initialize.
        pub fn reinit(&mut self) {
            self.call(Request::Reinit);
        }

        /// Advances the references' virtual clock by `ms` milliseconds.
        pub fn advance_clock(&mut self, ms: u64) {
            self.call(Request::AdvanceClock(ms));
        }

        /// Delivers a platform signal to the references.
        ///
        /// # Panics
        /// For signals the reference harness does not support (`Restart`,
        /// `TestFailureMode`, and `SetFirmwareHash`/`SetFirmwareSvn`, which
        /// carry a value: see [`Self::set_firmware`]).
        pub fn signal(&mut self, signal: SimulatorPlatformSignal) {
            self.call(Request::Signal(signal as u32));
        }

        /// Installs a firmware image with another hash or SVN on the
        /// references (the `SetFirmwareHash`/`SetFirmwareSvn` platform
        /// signals).
        pub fn set_firmware(&mut self, setting: FirmwareSetting) {
            self.call(Request::SetFirmware(setting));
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

        /// Executes `command` (which `tpm-rs` answered with `expected`) on
        /// every reference at `locality`; each reference compares its
        /// response with `expected`.
        ///
        /// # Panics
        /// If a reference's response differs other than as documented.
        pub fn exchange(&mut self, locality: u8, command: &[u8], expected: &[u8]) {
            if let Err(divergences) = self.try_exchange(locality, command, expected) {
                panic!("{}", join_messages(&divergences));
            }
        }

        /// Like [`Self::exchange`], but returns the references whose
        /// responses differ (or that failed) instead of panicking. Every
        /// reference has executed the command either way, so the
        /// `InProcReferences` stay usable.
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

    #[cfg(test)]
    mod tests {
        use tpm2::Connection as _;
        use tpm2_simulator::{Simulator, create_reference_simulator};

        use super::*;

        /// `TPM2_GetRandom(32)`.
        const GET_RANDOM_32: [u8; 12] = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x7B, 0, 32];

        /// `TPM2_ReadClock`.
        const READ_CLOCK: [u8; 10] = [0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x81];

        /// A `TPM2_CreatePrimary` of an ECC NIST P-256 storage key under the
        /// owner hierarchy (an expensive command, run on the references
        /// concurrently).
        fn create_primary_ecc() -> Vec<u8> {
            use crate::_common::{build_cmd, get_ecc_srk_template, pw};
            use tpm2::commands::CreatePrimary;
            use tpm2::{Handle, Tpm2b};
            let cmd = CreatePrimary {
                primary_handle: Handle::RH_OWNER,
                in_public: Tpm2b(get_ecc_srk_template()),
                ..Default::default()
            };
            build_cmd(&cmd, &[pw()])
        }

        /// The `tpm-rs` response to `command`.
        fn tpm_rs(sim: &mut Simulator<'static>, command: &[u8]) -> Vec<u8> {
            let mut rsp = vec![0u8; 8192];
            sim.transact(command, &mut rsp).expect("transact").to_vec()
        }

        /// Sends `command` to `sim` and mirrors it to `references` (which
        /// panics on a divergence); the `tpm-rs` response.
        fn mirrored(
            sim: &mut Simulator<'static>,
            references: &mut InProcReferences,
            command: &[u8],
        ) -> Vec<u8> {
            let rsp = tpm_rs(sim, command);
            references.exchange(0, command, &rsp);
            rsp
        }

        /// Both in-process references agree with `tpm-rs` on random bytes, a
        /// primary key (run concurrently) and the clock, and repeat them after
        /// a re-initialization (also after the clock moved) and after being
        /// hosted anew.
        #[test]
        fn in_process_references_repeat_after_reinit() {
            let _hosting = super::super::tests::HOSTING
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let seed = ReferenceSeed {
                pid: 4242,
                realtime_ms: 1_000_000,
            };
            let conversation = |references: &mut InProcReferences| {
                let mut sim = create_reference_simulator!(seed.pid, seed.realtime_ms);
                let create_primary = create_primary_ecc();
                assert!(runs_in_parallel(&create_primary));
                [
                    GET_RANDOM_32.as_slice(),
                    &create_primary,
                    &GET_RANDOM_32,
                    &READ_CLOCK,
                ]
                .iter()
                .map(|command| mirrored(&mut sim, references, command))
                .collect::<Vec<_>>()
            };
            let mut references = InProcReferences::launch(&[Implementation::TARGET], seed);
            assert_eq!(
                references.implementations().collect::<Vec<_>>(),
                [Implementation::TARGET]
            );
            let first = conversation(&mut references);
            references.advance_clock(1500);
            references.reinit();
            assert_eq!(conversation(&mut references), first, "after reinit");
            drop(references);
            let mut references = InProcReferences::launch(&[Implementation::TARGET], seed);
            assert_eq!(conversation(&mut references), first, "hosted anew");
        }

        /// A response that differs is reported with the reference's response,
        /// and the references stay usable.
        #[test]
        fn divergence_carries_the_reference_response() {
            let _hosting = super::super::tests::HOSTING
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let seed = ReferenceSeed {
                pid: 77,
                realtime_ms: 5_000,
            };
            let mut sim = create_reference_simulator!(seed.pid, seed.realtime_ms);
            let mut references = InProcReferences::launch(&[Implementation::TARGET], seed);
            let mut wrong = tpm_rs(&mut sim, &GET_RANDOM_32);
            let last = wrong.len() - 1;
            wrong[last] ^= 1;
            let divergences = references
                .try_exchange(0, &GET_RANDOM_32, &wrong)
                .unwrap_err();
            assert_eq!(divergences.len(), 1);
            assert_eq!(divergences[0].implementation, Implementation::TARGET);
            let reference = divergences[0]
                .reference_response
                .as_ref()
                .expect("response");
            assert_eq!(reference.len(), wrong.len());
            assert_ne!(reference, &wrong);
            mirrored(&mut sim, &mut references, &READ_CLOCK);
        }

        /// A second `InProcReferences` cannot host a reference that is
        /// already hosted.
        #[test]
        fn second_host_of_a_reference_panics() {
            let _hosting = super::super::tests::HOSTING
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let seed = ReferenceSeed {
                pid: 1,
                realtime_ms: 1,
            };
            let _first = InProcReferences::launch(&[Implementation::TARGET], seed);
            let second = std::panic::catch_unwind(|| {
                InProcReferences::launch(&[Implementation::TARGET], seed);
            });
            assert!(second.is_err());
        }
    }
}
