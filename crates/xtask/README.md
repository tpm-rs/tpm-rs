# `xtask`

Developer and CI automation tasks for the `tpm-rs` workspace (`publish = false`,
`#![forbid(unsafe_code)]`).

## `cargo xtask size`

Builds the freestanding `#![no_std]` binaries in `testing/size-harness` across
three bare-metal targets (`riscv32imac-unknown-none-elf`,
`thumbv7em-none-eabihf`, and `x86_64-unknown-none`) and compares Flash
(`.text` + `.rodata` + `.data`) and RAM (`.data` + `.bss`) usage between two
revisions by parsing the compiled ELF32/ELF64 section headers and `.symtab`
symbol tables directly in Rust (`rustc-demangle`).

### ELF Section Accounting

`testing/size-harness` links via `rust-lld` without a custom linker script, so
`cargo xtask size` sums `sh_size` across allocatable (`SHF_ALLOC`) ELF sections
matching standard ELF and RISC-V psABI prefixes (including `.<suffix>`
subsections emitted by `-ffunction-sections` / `-fdata-sections`, such as
`.text.foo` or `.rodata.cst4`):

| Accepted ELF Section Prefixes | Canonical Group | Counted Toward | Purpose |
| :--- | :--- | :--- | :--- |
| `.text`, `.text.*` | `.text` | Flash | Executable instructions (plus inline literal pools on ARM Cortex-M) |
| `.rodata`, `.rodata.*`, `.srodata`, `.srodata.*` | `.rodata` | Flash | Read-only constants and RISC-V `gp`-relative small read-only data |
| `.data.rel.ro`, `.data.rel.ro.*` | `.data.rel.ro` | Flash | Read-only-after-relocation tables (such as vtables on `x86_64`) |
| `.data`, `.data.*`, `.sdata`, `.sdata.*` | `.data` | Flash + RAM | Non-zero initialized mutable statics (initializers in Flash, runtime state in RAM) |
| `.bss`, `.bss.*`, `.sbss`, `.sbss.*` | `.bss` | RAM | Zero-initialized mutable statics (`SHT_NOBITS`) |

Non-allocatable sections (`.symtab`, `.strtab`, `.shstrtab`, `.comment`,
`*.attributes`, and debug sections) as well as unwind and loader metadata
(`.eh_frame`, `.ARM.exidx`, `.got`, and `.relro_padding`) are excluded from
Flash and RAM totals. Custom linker scripts with non-standard output section
names are not used by `testing/size-harness` and would require updating this
mapping.

Note that on some architectures (particularly ARM Cortex-M /
`thumbv7em-none-eabihf`), LLVM embeds PC-relative constant pools (such as jump
tables or panic strings) directly inside `.text` after functions. Aggregate
`Flash` totals remain exact, though `.text` in per-symbol breakdowns can
include inline constant data alongside executable instructions.

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
