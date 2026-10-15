//! The FFI shell shared by the reference binaries (`mstpm20`, `ibmswtpm2`):
//! the entry points of the linked, patched C reference TPM (`difftest_*`,
//! exported by the symbol-isolated static library `testing/build.rs` links
//! into exactly one binary), the virtual-clock callback the patches call
//! back into (`difftest_virtual_ms`), the start-up clock reading and the
//! stdout takeover. This is the only `unsafe` code of the crate; all
//! logic lives in the safe [`testing::differential::server`].

#![allow(unsafe_code)]

use std::io::BufReader;

use testing::differential::Implementation;
use testing::differential::server::{self, Backend, Signal};
use testing::seed::ReferenceSeed;

unsafe extern "C" {
    fn difftest_init();
    fn difftest_advance_clock(ms: u64);
    fn difftest_signal_power_on();
    fn difftest_signal_power_off();
    fn difftest_signal_reset();
    fn difftest_signal_nv_on();
    fn difftest_signal_nv_off();
    fn difftest_signal_physical_presence_on();
    fn difftest_signal_physical_presence_off();
    fn difftest_signal_cancel_on();
    fn difftest_signal_cancel_off();
    fn difftest_signal_hash_start();
    fn difftest_signal_hash_data(data: *const u8, size: u32);
    fn difftest_signal_hash_end();
    fn difftest_run_command(
        locality: u8,
        in_buf: *const u8,
        in_size: u32,
        out_buf: *mut u8,
        out_cap: u32,
    ) -> u32;
}

unsafe extern "C" {
    fn dup(fd: i32) -> i32;
    fn dup2(old_fd: i32, new_fd: i32) -> i32;
    fn clock_gettime(clock_id: i32, tp: *mut Timespec) -> i32;
    fn getpid() -> i32;
}

/// The process ID the C reference sees, if fixed by `TPM_REFERENCE_SEED`.
static FIXED_PID: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();

/// `getpid()` as seen by the C reference: `testing/build.rs` redirects the
/// reference's `getpid` calls here. Returns the process ID fixed by
/// `TPM_REFERENCE_SEED`, or the real one.
#[unsafe(no_mangle)]
pub extern "C" fn difftest_getpid() -> i32 {
    match FIXED_PID.get().copied().flatten() {
        Some(pid) => pid as i32,
        // SAFETY: `getpid` has no preconditions.
        None => unsafe { getpid() },
    }
}

/// Takes over stdout as the protocol channel: returns a file for the
/// original stdout and points file descriptor 1 at stderr, so output of
/// the C code cannot corrupt the protocol.
pub fn take_stdout() -> std::fs::File {
    use std::os::fd::FromRawFd as _;
    let fd = unsafe { dup(1) };
    assert!(fd >= 0, "dup(stdout) failed");
    assert!(unsafe { dup2(2, 1) } >= 0, "dup2(stderr, stdout) failed");
    unsafe { std::fs::File::from_raw_fd(fd) }
}

/// The virtual clock the patched C reference reads as `_plat__RealTime()`
/// (milliseconds; see [`server::virtual_ms`]).
#[unsafe(no_mangle)]
pub extern "C" fn difftest_virtual_ms() -> u64 {
    server::virtual_ms()
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
/// 1000000`), whose value the virtual clock starts at.
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

/// The linked C reference TPM.
struct CReference;

impl Backend for CReference {
    fn init(&mut self) {
        unsafe { difftest_init() };
    }

    fn advance_clock(&mut self, ms: u64) {
        unsafe { difftest_advance_clock(ms) };
    }

    fn signal(&mut self, signal: Signal) {
        unsafe {
            match signal {
                Signal::PowerOn => difftest_signal_power_on(),
                Signal::PowerOff => difftest_signal_power_off(),
                Signal::Reset => difftest_signal_reset(),
                Signal::NvOn => difftest_signal_nv_on(),
                Signal::NvOff => difftest_signal_nv_off(),
                Signal::PhysicalPresenceOn => difftest_signal_physical_presence_on(),
                Signal::PhysicalPresenceOff => difftest_signal_physical_presence_off(),
                Signal::CancelOn => difftest_signal_cancel_on(),
                Signal::CancelOff => difftest_signal_cancel_off(),
            }
        }
    }

    fn hash_start(&mut self) {
        unsafe { difftest_signal_hash_start() };
    }

    fn hash_data(&mut self, data: &[u8]) {
        unsafe { difftest_signal_hash_data(data.as_ptr(), data.len() as u32) };
    }

    fn hash_end(&mut self) {
        unsafe { difftest_signal_hash_end() };
    }

    fn run_command(&mut self, locality: u8, command: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 8192];
        let len = unsafe {
            difftest_run_command(
                locality,
                command.as_ptr(),
                command.len() as u32,
                out.as_mut_ptr(),
                out.len() as u32,
            )
        };
        out.truncate(len as usize);
        out
    }
}

/// Runs the reference process of `implementation` (see
/// [`testing::differential::server`]); the first argument names the test.
pub fn main(implementation: Implementation) {
    // The seed chosen by the parent (`TPM_REFERENCE_SEED`, always set by
    // `differential::Reference`): the process ID `getpid()` returns to the C
    // reference and the start of its virtual clock, which only moves when the
    // harness advances it. Run by hand without it, the process uses its own
    // process ID and its `CLOCK_MONOTONIC` time at start-up.
    let realtime_ms = monotonic_ms();
    let fixed = ReferenceSeed::from_env();
    FIXED_PID.get_or_init(|| fixed.map(|s| s.pid));
    let seed = ReferenceSeed {
        pid: difftest_getpid() as u32,
        realtime_ms: fixed.map_or(realtime_ms, |s| s.realtime_ms),
    };
    let test = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "<unknown>".into());
    let output = std::io::BufWriter::new(take_stdout());
    let input = BufReader::new(std::io::stdin().lock());
    server::serve(implementation, CReference, test, seed, input, output);
}
