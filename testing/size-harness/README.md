# `tpm2-size-harness`

Freestanding `#![no_std]` / `#![no_main]` measurement binaries used by
`cargo xtask size` and CI to track the Flash (`.text` + `.rodata`) and RAM
(`.data` + `.bss`) footprint of the `tpm-rs` workspace crates without `std`
runtime overhead.

This package is intentionally excluded from the root Cargo workspace so its
bare-metal `#![no_main]` and `#[panic_handler]` definitions do not collide with
host `cargo test` or Miri runs.

## Binaries

- `size-tpm2`: Exercises representative TPM 2.0 structure and command
  `Marshal`/`Unmarshal` paths alongside the `tpm2::crypto` runtime dispatch
  layer backed by a minimal `core::hint::black_box` stub backend.
- `size-client` (`--features client`): Exercises `tpm2_client::run_command` and
  `run_command_with_sessions` (`PasswordSession`) over a `#![no_std]` stub
  `Connection` (`tpm2-client` built with `default-features = false`).
- `size-server` (`--features server`): Exercises `tpm2_impl::TpmContext`
  (`execute_command_separate` and `execute_command_in_place`) with minimal stub
  entropy and DRBG implementations.

## Specification Profiles

- `v184`: Classical pre-Rev 1.85 TPM 2.0 algorithms (SHA-1/2/3, SM3, AES, SM4,
  Camellia, CMAC, RSA-1024..4096, and Weierstrass ECC curves/schemes).
- `v185` (default): Full TPM 2.0 Rev 1.85 algorithm set (`v184` plus
  Curve25519/Curve448, EdDSA/HashEdDSA, ML-DSA, and ML-KEM).

## Usage

From the repository root (requires only the bare-metal `rustup` targets):

```bash
rustup target add riscv32imac-unknown-none-elf thumbv7em-none-eabihf x86_64-unknown-none
cargo xtask size --base HEAD^1 --head HEAD
```
