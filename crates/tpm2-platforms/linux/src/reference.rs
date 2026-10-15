//! The simulator-platform entropy source and clock of the C reference TPMs
//! (`reference-rng` feature).
//!
//! The TCG reference implementation (`mstpm20`) and the IBM software TPM
//! (`ibmswtpm2`) share the platform code of `Entropy.c`: their
//! `_plat__GetEntropy()` seeds the C library's `rand()` with
//! `(unsigned)_plat__RealTime() ^ getpid()` when the TPM is initialized and
//! then returns 32 bits at a time, built from two `rand()` outputs and XORed
//! with the current real time. [`ReferenceEntropy`] reproduces this exactly
//! (with a port of glibc's `rand()`, [`GlibcRand`]), given the process ID of
//! the reference process and the same clock ([`VirtualClock`]).
//!
//! Together with the references' DRBG, which `tpm2-impl`'s `reference-rng` links,
//! this makes `tpm-rs` draw exactly the random values a C reference TPM draws.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tpm2::crypto::CryptoError;

/// A clock that only moves when advanced, shared by a [`crate::LinuxTimer`]
/// and a [`ReferenceEntropy`].
///
/// It models the C references' simulator clock: the real time
/// (`_plat__RealTime()`, milliseconds) starts at the value the reference
/// process reported (its `CLOCK_MONOTONIC` time when it started) and advances
/// in lockstep with the TPM timer, which counts from 0.
#[derive(Clone, Debug)]
pub struct VirtualClock {
    /// `_plat__RealTime()` when the clock was created.
    realtime_base_ms: u64,
    /// Milliseconds the clock has been advanced by.
    elapsed_ms: Arc<AtomicU64>,
}

impl VirtualClock {
    /// Creates a clock whose real time starts at `realtime_base_ms`.
    pub fn new(realtime_base_ms: u64) -> Self {
        Self {
            realtime_base_ms,
            elapsed_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Advances the clock (every handle of it) by `ms` milliseconds.
    pub fn advance(&self, ms: u64) {
        self.elapsed_ms.fetch_add(ms, Ordering::Relaxed);
    }

    /// Milliseconds the clock has been advanced by (the TPM timer).
    pub fn elapsed_ms(&self) -> u64 {
        self.elapsed_ms.load(Ordering::Relaxed)
    }

    /// The current real time (`_plat__RealTime()`).
    pub fn realtime_ms(&self) -> u64 {
        self.realtime_base_ms.wrapping_add(self.elapsed_ms())
    }
}

/// Degree of glibc's default `TYPE_3` additive feedback generator.
const DEG: usize = 31;
/// Separation of the two taps of the generator.
const SEP: usize = 3;

/// A port of glibc's `rand()`/`srand()` (`random_r.c`, the default `TYPE_3`
/// additive feedback generator with a 31-word state), which the C reference
/// TPMs' simulator platform uses as its entropy source.
#[derive(Clone, Debug)]
pub struct GlibcRand {
    state: [i32; DEG],
    /// Index of the front tap (`fptr`).
    front: usize,
    /// Index of the rear tap (`rptr`).
    rear: usize,
}

impl GlibcRand {
    /// The generator as after `srand(seed)` (`__srandom_r()`).
    pub fn new(seed: u32) -> Self {
        let seed = if seed == 0 { 1 } else { seed };
        let mut state = [0i32; DEG];
        state[0] = seed as i32;
        let mut word = seed as i32;
        for s in state.iter_mut().skip(1) {
            // state[i] = (16807 * state[i - 1]) % 2147483647 without overflow.
            let hi = i64::from(word) / 127_773;
            let lo = i64::from(word) % 127_773;
            let mut w = 16_807 * lo - 2_836 * hi;
            if w < 0 {
                w += 2_147_483_647;
            }
            word = w as i32;
            *s = word;
        }
        let mut rand = Self {
            state,
            front: SEP,
            rear: 0,
        };
        for _ in 0..DEG * 10 {
            rand.next();
        }
        rand
    }

    /// The next `rand()` output, in `[0, RAND_MAX]` with `RAND_MAX = 2^31 - 1`
    /// (`__random_r()`).
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> u32 {
        let val = (self.state[self.front] as u32).wrapping_add(self.state[self.rear] as u32);
        self.state[self.front] = val as i32;
        self.front += 1;
        if self.front >= DEG {
            self.front = 0;
            self.rear += 1;
        } else {
            self.rear += 1;
            if self.rear >= DEG {
                self.rear = 0;
            }
        }
        val >> 1
    }
}

/// The C reference TPMs' simulator-platform entropy source (`Entropy.c`).
pub struct ReferenceEntropy {
    /// The process ID of the reference process (`getpid()`).
    pid: u32,
    /// The clock of `_plat__RealTime()`.
    clock: VirtualClock,
    /// The C library generator; `srand()` was never called before the first
    /// [`ReferenceEntropy::init`], which is equivalent to `srand(1)`.
    rand: GlibcRand,
    /// The last 32-bit value produced (`lastEntropy`), for the FIPS 140-2
    /// continuous test.
    last_entropy: u32,
}

impl ReferenceEntropy {
    /// Creates the entropy source of the reference process with process ID
    /// `pid` and real-time clock `clock`.
    pub fn new(pid: u32, clock: VirtualClock) -> Self {
        Self {
            pid,
            clock,
            rand: GlibcRand::new(1),
            last_entropy: 0,
        }
    }

    /// `rand32()`: two `rand()` outputs combined into 32 bits
    /// (`RAND_MAX == INT32_MAX`).
    fn rand32(&mut self) -> u32 {
        let first = self.rand.next();
        (first << 1) ^ self.rand.next()
    }

    /// `_plat__GetEntropy(NULL, 0)`: seeds the generator with
    /// `(unsigned)_plat__RealTime() ^ getpid()` and primes the continuous test.
    pub fn init(&mut self) {
        self.rand = GlibcRand::new((self.clock.realtime_ms() as u32) ^ self.pid);
        self.last_entropy = self.rand32();
    }

    /// `_plat__GetEntropy(entropy, amount)` for `amount = out.len() > 0`:
    /// writes up to 4 bytes and returns their number, or `None` if the
    /// continuous test failed (two equal consecutive values).
    pub fn get_entropy(&mut self, out: &mut [u8]) -> Option<usize> {
        let rnd = self.rand32();
        if rnd == self.last_entropy {
            return None;
        }
        self.last_entropy = rnd;
        let rnd = rnd ^ (self.clock.realtime_ms() as u32);
        let n = out.len().min(4);
        // memcpy() of the native-endian (x86-64: little-endian) value.
        out[..n].copy_from_slice(&rnd.to_le_bytes()[..n]);
        Some(n)
    }

    /// The entropy collection loop of `DRBG_GetEntropy()`: fills `out`
    /// completely from [`ReferenceEntropy::get_entropy`].
    pub fn fill(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        let mut obtained = 0;
        while obtained < out.len() {
            obtained += self
                .get_entropy(&mut out[obtained..])
                .ok_or(CryptoError::Internal)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Values of glibc's `rand()` after `srand(seed)`, printed by a C program.
    #[test]
    fn glibc_rand_matches_glibc() {
        let mut r = GlibcRand::new(12345);
        let got: Vec<u32> = (0..5).map(|_| r.next()).collect();
        assert_eq!(got, [383100999, 858300821, 357768173, 455528251, 133005921]);
        let mut r = GlibcRand::new(0x8765_4321);
        let first = r.next();
        assert_eq!([first, r.next()], [1611021024, 1022764121]);
        // srand(1) and srand(0) are the default sequence.
        assert_eq!(GlibcRand::new(1).next(), 1804289383);
        assert_eq!(GlibcRand::new(0).next(), 1804289383);
    }

    /// `DRBG_Instantiate()` and `DRBG_Generate()` of the same C process on top
    /// of this entropy source, through the C DRBG linked by `tpm2-impl`.
    #[test]
    fn reference_drbg_on_reference_entropy_matches_c() {
        use tpm2_impl::reference_rng::{RefRng, drbg};
        let clock = VirtualClock::new(123_456_789);
        let mut rng = crate::LinuxRng::reference(ReferenceEntropy::new(814_633, clock.clone()));
        tpm2::crypto::Rng::init(&mut rng).unwrap();
        clock.advance(5);
        let mut state = tpm2_impl::DrbgState::default();
        let mut ref_rng = RefRng {
            drbg: Some(&mut state),
            entropy: Some(&mut rng),
        };
        drbg::instantiate(&mut ref_rng).unwrap();
        let mut out = [0u8; 40];
        drbg::fill(&mut ref_rng, None, &mut out).unwrap();
        assert_eq!(
            out,
            [
                0xee, 0xe5, 0xc5, 0xe2, 0x19, 0x94, 0x79, 0xbe, 0x3a, 0x7d, 0x62, 0x3f, 0x9d, 0xbb,
                0x8d, 0xdc, 0xea, 0x16, 0xb3, 0x6d, 0xa3, 0x22, 0x67, 0x87, 0xe0, 0x29, 0xb8, 0xf5,
                0xde, 0xa9, 0x79, 0x72, 0x76, 0x66, 0xfe, 0x21, 0xd3, 0x37, 0x5f, 0x90
            ]
        );
    }

    /// The entropy a C reference process (pid 814633) produced at real time
    /// 123456789 (seeding) and 123456794 (drawing), printed by a C program
    /// calling `_plat__GetEntropy()`, after 48 bytes were drawn by
    /// `DRBG_Instantiate()`.
    #[test]
    fn entropy_matches_reference_platform() {
        let clock = VirtualClock::new(123_456_789);
        let mut e = ReferenceEntropy::new(814_633, clock.clone());
        e.init();
        clock.advance(5);
        let mut skipped = [0u8; 48];
        e.fill(&mut skipped).unwrap();
        let mut out = [0u8; 12];
        e.fill(&mut out).unwrap();
        assert_eq!(
            out,
            [
                0x62, 0xdf, 0xee, 0x61, 0x1b, 0x0a, 0x80, 0xe8, 0xba, 0x01, 0x14, 0x9a
            ]
        );
    }
}
