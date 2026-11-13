# `xtask`

Developer and CI automation tasks for the `tpm-rs` workspace (`publish = false`,
`#![forbid(unsafe_code)]`).

## `cargo xtask size`

Builds the freestanding `#![no_std]` binaries in `testing/size-harness` across
three bare-metal targets (`riscv32imac-unknown-none-elf`,
`thumbv7em-none-eabihf`, and `x86_64-unknown-none`) and compares Flash
(`.text` + `.rodata`) and RAM (`.data` + `.bss`) usage between two revisions
by parsing the compiled ELF32/ELF64 section headers and `.symtab` symbol tables
directly in Rust (`rustc-demangle`).

### Prerequisites

```bash
# Bare-metal target standard libraries (no external C cross-compiler or profiler needed)
rustup target add riscv32imac-unknown-none-elf thumbv7em-none-eabihf x86_64-unknown-none
```

### Usage

```bash
# Compare current HEAD against its first parent (default in CI)
cargo xtask size --base HEAD^1 --head HEAD

# Compare local uncommitted working tree edits against HEAD
cargo xtask size --base HEAD --head WORKDIR

# Fail with exit code 1 if any row grows by more than 4096 bytes
cargo xtask size --base main --head HEAD --fail-on-bytes 4096
```

When `GITHUB_STEP_SUMMARY` is set in the environment, `cargo xtask size`
appends the rendered Markdown report directly to the GitHub Actions job
summary. Rows growing by more than `4 KiB` or `5%` are highlighted with `⚠️`
and automatically expand their per-symbol breakdown; missing or incompatible
`base` rows degrade gracefully to `Base: N/A (new)`.
