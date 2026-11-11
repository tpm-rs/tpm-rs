//! Freestanding binary-size harness for the `tpm2-impl` server crate.
//!
//! Instantiates [`TpmContext`] over minimal `#![no_std]` entropy and DRBG stubs
//! and executes both separate-buffer and in-place command dispatch so every new
//! handler wired into `TpmContext` is automatically measured in CI.

#![no_std]
#![no_main]
#![deny(unsafe_code)]
#![forbid(unreachable_pub)]

use core::hint::black_box;
use core::panic::PanicInfo;

use tpm2_impl::TpmContext;
use tpm2_impl::platform::TpmContextDeps;
use tpm2_impl::platform::crypto::drbg_helpers::{next_u32_via_fill, next_u64_via_fill};
use tpm2_impl::platform::crypto::{Drbg, DrbgError, EntropySource};

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

struct StubEntropy;

impl EntropySource for StubEntropy {
    #[inline(never)]
    fn fill_entropy(&mut self, dest: &mut [u8]) {
        if let Some(first) = dest.first_mut() {
            *first = black_box(0x5a);
        }
        black_box(dest);
    }

    fn instantiate() -> Self {
        Self
    }
}

struct StubDrbg(u8);

impl Drbg for StubDrbg {
    type Entropy = [u8; 32];
    type Nonce = [u8; 16];

    fn instantiate(
        entropy_input: &Self::Entropy,
        nonce: &Self::Nonce,
        personalization: &[u8],
    ) -> Result<Self, DrbgError> {
        let seed = entropy_input[0] ^ nonce[0] ^ personalization.first().copied().unwrap_or(0);
        Ok(Self(black_box(seed)))
    }

    fn reseed(
        &mut self,
        entropy_input: &Self::Entropy,
        additional_input: &[u8],
    ) -> Result<(), DrbgError> {
        self.0 ^= black_box(entropy_input[0] ^ additional_input.first().copied().unwrap_or(0));
        Ok(())
    }

    #[inline(never)]
    fn fill_bytes(&mut self, additional_input: &[u8], buffer: &mut [u8]) -> Result<(), DrbgError> {
        let _ = black_box(additional_input);
        for byte in buffer.iter_mut() {
            self.0 = self.0.wrapping_add(1);
            *byte = black_box(self.0);
        }
        Ok(())
    }

    fn next_u32(&mut self, additional_input: &[u8]) -> Result<u32, DrbgError> {
        next_u32_via_fill(self, additional_input)
    }

    fn next_u64(&mut self, additional_input: &[u8]) -> Result<u64, DrbgError> {
        next_u64_via_fill(self, additional_input)
    }

    fn requires_reseeding(&mut self) -> bool {
        black_box(false)
    }
}

struct StubDeps;

impl TpmContextDeps for StubDeps {
    type Drbg = StubDrbg;
    type EntropySource = StubEntropy;
    type Request = [u8];
    type Response = [u8];
}

#[expect(unsafe_code, reason = "freestanding ELF entry point symbol")]
#[unsafe(no_mangle)]
extern "C" fn _start() -> ! {
    let _ = black_box(measure_server());
    loop {
        core::hint::spin_loop();
    }
}

#[inline(never)]
fn measure_server() -> usize {
    let Ok(mut ctx) = TpmContext::<StubDeps>::new() else {
        return 0;
    };
    let req = black_box([0u8; 64]);
    let mut resp = [0u8; 256];
    let n1 = ctx.execute_command_separate(&req, &mut resp);
    let _ = black_box(&resp[..n1.min(resp.len())]);

    let req_len = black_box(12usize);
    let n2 = ctx.execute_command_in_place(&mut resp, req_len);
    let _ = black_box(&resp[..n2.min(resp.len())]);
    n1.wrapping_add(n2)
}
