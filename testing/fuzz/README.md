# Differential fuzzing of tpm-rs (`testing/fuzz`)

This crate fuzzes `tpm-rs` against the C reference TPMs (`mstpm20` and
`ibmswtpm2`) with [`cargo fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html)
(libFuzzer). One fuzz input is a **conversation**: up to 32 rounds with a
fresh TPM that is powered on, has NV available and has received
`TPM2_Startup(CLEAR)`. A round is a TPM command (at locality 0 unless a
locality round changed it) or an event: a platform signal (`PowerOff`,
`PowerOn`, `NvOn`, `NvOff`, `Reset`), a `_TPM_Hash_Start`/`Data`/`End`
indication, a virtual clock advance, or a locality change. Later commands can
reuse values from earlier responses (handles, names, public/private blobs,
nonces, context blobs, tickets, NV indices), so the fuzzer reaches stateful
behavior such as keys loaded under parents, authorized sessions, policy
chains, context management and NV lifecycles, and the events reach power
cycles with `TPM2_Startup`/`TPM2_Shutdown` (reset, restart, resume), NV
unavailability, D-RTM sequences, timeouts and locality checks.

Every command goes to `tpm-rs` and to every C reference through
`testing::tpm::Tpm`, which compares the responses round by round. A finding
is:

- `DIVERGENCE[<impl>:round<i>:<cc>:<rs_rc>:<ref_rc>]`: a reference's response
  differs from the `tpm-rs` response at round `i`, and no documented exception
  in `testing/src/differential/server.rs` (and `differential.md`) covers it;
- `MALFORMED_RESPONSE[round<i>:<cc>]`: the `tpm-rs` response size or tag is
  inconsistent;
- `UNPARSEABLE_RESPONSE[round<i>:<cc>]`: a successful `tpm-rs` response that
  the typed `tpm2` response cannot unmarshal;
- `BAD_RESPONSE_HMAC[...]`, `BAD_RESPONSE_AUTH[...]`,
  `ACCEPTED_CORRUPT_HMAC[...]`: session engine findings;
- a panic, hang or out-of-memory in `tpm-rs`, or a crash of a C reference.

The input model, driver and session engine live in `src/` (see the docs of
`src/lib.rs`); the target is `fuzz_targets/diff_conversation.rs`.

## Layout

| Path | What |
|---|---|
| `fuzz_targets/diff_conversation.rs` | The fuzz target |
| `src/` | The library `tpm2_fuzz`: input model, value pool, builder, driver, session engine |
| `src/bin/gen_dict.rs` | Generates `tpm2.dict` from the `tpm2` constants |
| `src/bin/trace2conv.rs` | Converts recorded E2E traces into seed inputs |
| `src/bin/to_test.rs` | Prints a fuzzer input as a ready-to-paste E2E test |
| `src/bin/shared/` | Code shared by the tools (and the test traces in `testdata/`) |
| `tpm2.dict` | The libFuzzer dictionary (generated, do not edit) |
| `corpus/diff_conversation/` | The seed corpus, generated locally and gitignored (see [The seed corpus](#the-seed-corpus)) |
| `known_divergences.txt` | Finding signatures the target suppresses |

## The seed

Every fuzzed TPM uses the fixed reference seed `4242:1000000`
(`tpm2_fuzz::driver::FIXED_SEED`, the same as
`TPM_REFERENCE_SEED=4242:1000000`). With `reference-rng`, `tpm-rs` and both
references draw identical random values from it, and between inputs the
target only resets the TPM (`Tpm::reset()`), so every conversation is
deterministic: an input always produces the same responses, crashes
reproduce, and the literal HMACs and nonces in the seed corpus stay valid.
Changing the seed invalidates the corpus (regenerate it, see below).

## Build

All commands run from the repository root. The nightly toolchain of
`rust-toolchain.toml` satisfies `cargo fuzz`.

**Recommended:** the references linked into the fuzzer and driven in-process
(the `inproc` feature), without a sanitizer. The C references are not
sanitizer-instrumented anyway and Rust panics are the oracle, so ASan only
slows the comparison code down; this mode is about 28% faster than process
mode and needs no reference binaries:

```sh
cargo fuzz build --fuzz-dir testing/fuzz -O -s none --features inproc diff_conversation
```

For debugging, the default (process) mode runs the references as child
processes, so build them first and point the fuzzer at them (the tools in
`src/bin/` always use this mode):

```sh
cargo build --release -p testing --features differential --bins
export MSTPM20_BIN=$PWD/target/release/mstpm20 IBMSWTPM2_BIN=$PWD/target/release/ibmswtpm2
cargo fuzz build --fuzz-dir testing/fuzz
```

`DIFFERENTIAL_REFERENCES=mstpm20` (or `ibmswtpm2`) restricts the comparison to
one reference. Pass the same build options (`-O -s none --features inproc`)
to every later `cargo fuzz run`/`tmin`/`cmin`, or it rebuilds the target in
another mode.

## Run

Fuzz with a scratch working corpus first, so new inputs do not land in the
seed corpus (libFuzzer writes new inputs to the first directory):

```sh
mkdir -p /tmp/diff_conversation
cargo fuzz run --fuzz-dir testing/fuzz -O -s none --features inproc diff_conversation \
    /tmp/diff_conversation testing/fuzz/corpus/diff_conversation -- \
    -dict=testing/fuzz/tpm2.dict -detect_leaks=0 -timeout=10 -rss_limit_mb=4096
```

- `-detect_leaks=0` is required for now: each `Tpm::reset()` leaks a few
  `'static` simulator components.
- Long campaigns: add `-fork=8 -ignore_crashes=1` (each fork has its own
  references; with `inproc` one in-process TPM per fork process) and
  `-max_total_time=<s>`.
- `TPM_FUZZ_STATS=<n>` prints driver and session counters (rounds, successes,
  HMAC success rate) every `n` inputs.
- Crashes go to `testing/fuzz/artifacts/diff_conversation/`.

## Triage

1. **Reproduce** a crash:
   `cargo fuzz run --fuzz-dir testing/fuzz -O -s none --features inproc diff_conversation <crash>`. The
   panic message carries the finding signature and, for a divergence, both
   responses.
2. **Minimize** it (removes rounds and shrinks operands; the references
   between rounds keep the rest consistent):

   ```sh
   cargo fuzz tmin --fuzz-dir testing/fuzz -O -s none --features inproc diff_conversation <crash> -- \
       -detect_leaks=0
   ```

3. **Turn it into a test**: `to_test` replays the input exactly like the
   target and prints an E2E test that sends the resolved command bytes with
   `tpm.send_command(0, ...)` on a `Tpm` with the fixed seed, asserts the
   response codes of the rounds before the finding, and marks the finding's
   round with the references' response codes and a `TODO(triage)`:

   ```sh
   cargo run --release --manifest-path testing/fuzz/Cargo.toml --bin to_test -- \
       --name nv_define_space_validates_handles_before_sessions <minimized crash>
   ```

   Paste it into `testing/tests/e2e/<topic>.rs`, give it a name that describes
   the behavior under test and complete its `///` doc (GEMINI.md rules), and
   replace the `TODO` with the specified behavior. Run it with
   `cargo test --release -p testing --features differential <name>`.
4. **Classify** it (as in `differential.md`):
   - `tpm-rs` bug: fix it in `crates/tpm2-impl` and keep the test;
   - reference bug: add `testing/patches/<impl>/bug-fix-<fix>.patch` and a
     doc section;
   - implementation-defined: add a narrow exception in
     `testing/src/differential/server.rs` and a doc entry.
5. **Suppress** it until it is fixed, so long campaigns keep finding new
   issues: add its signature pattern to `known_divergences.txt`.

## `known_divergences.txt`

One pattern per line, `#` starts a comment, `*` matches any run of
characters, e.g. `DIVERGENCE[ibmswtpm2:*:0x17a:*:*]` (leave the round as `*`).
A finding whose signatures all match a pattern ends the conversation quietly
instead of crashing. Every entry must name the triage issue or doc section
that explains it, and must be removed together with the fix.
`TPM_FUZZ_KNOWN_DIVERGENCES=<file>` selects another file.

## The seed corpus

`corpus/diff_conversation/` holds conversations taken from the E2E and Go
parity suites plus hand-written session seeds, so the fuzzer starts from
realistic, deep, multi-round conversations (keys, HMAC/salted/policy sessions,
NV, context management). The corpus is **not checked in** (it is gitignored):
generate it locally before the first run, and regenerate it after changing the
input encoding, the value pool, the seed, or `tpm-rs` behavior that the
recorded conversations depend on (literal HMACs and nonces only replay while
the responses stay the same):

```sh
# 1. Record a trace of every Tpm of both suites (`testing::tpm::trace`, format v1),
#    with the fuzzer's fixed seed so literal values replay.
rm -rf /tmp/traces && mkdir /tmp/traces
TPM_FUZZ_RECORD_DIR=/tmp/traces TPM_REFERENCE_SEED=4242:1000000 \
    cargo test --release -p testing

# 2. Convert the traces into fuzzer inputs; --verify replays every conversation
#    through the driver and cuts it before the first round that does not
#    reproduce the recorded response; --ecc-variants adds cheaper variants of
#    the conversations with RSA key templates (see below). Needs the reference
#    binaries (MSTPM20_BIN/IBMSWTPM2_BIN, see Build).
rm -rf /tmp/converted
cargo run --release --manifest-path testing/fuzz/Cargo.toml --bin trace2conv -- \
    --verify --ecc-variants /tmp/converted /tmp/traces

# 3. Add the session engine's seeds (HMAC, salted and policy sessions, built by
#    its live tests).
(cd testing/fuzz && TPM_FUZZ_SESSION_SEEDS=/tmp/converted \
    cargo test --release --lib session::tests::driver_conversations)

# 4. Minimize into the corpus directory (keep it under about 5 MB).
rm -rf testing/fuzz/corpus/diff_conversation && mkdir -p testing/fuzz/corpus/diff_conversation
cp /tmp/converted/* testing/fuzz/corpus/diff_conversation/
cargo fuzz cmin --fuzz-dir testing/fuzz -O -s none --features inproc diff_conversation \
    testing/fuzz/corpus/diff_conversation -- -detect_leaks=0  # minimizes in place
```

Optionally, grow it from a campaign's working corpus without exceeding the
size budget: an edge-preserving set-cover merge keeps every edge with few
inputs (`<work>` is the first corpus directory of a `cargo fuzz run`):

```sh
mkdir /tmp/grown
testing/fuzz/target/x86_64-unknown-linux-gnu/release/diff_conversation -set_cover_merge=1 \
    -use_counters=0 -detect_leaks=0 /tmp/grown testing/fuzz/corpus/diff_conversation <work>
cp -n /tmp/grown/* testing/fuzz/corpus/diff_conversation/
```

A trace is split into conversations at the start and after every
`Tpm::reset()`, each ending at the first event a conversation cannot express
(a platform signal other than `PowerOff`, `PowerOn`, `NvOn`, `NvOff` and
`Reset`; transport-level signals such as `KeyCacheOn` are skipped), and
truncated to 32 rounds. Platform signals, `_TPM_Hash_*` indications and clock
advances become event rounds, and a command at another locality than the
previous one is preceded by a locality round. `trace2conv` turns every command handle that equals
an earlier response handle or NV index into a `HandleOperand::Response`/`Nv`
reference, every parameter byte range that equals an extracted response field
into a `Segment::Value` reference, and password sessions into
`SessionSel::Password`; other sessions stay literal. Commands that the
structured form cannot rebuild byte for byte (e.g. a deliberately wrong
`commandSize`) stay `Step::Raw`.

RSA key generation dominates the cost of a round, so `--ecc-variants` also
emits, for every conversation with an RSA template in `TPM2_CreatePrimary`,
`Create` or `CreateLoaded`, a variant with the templates rewritten into ECC
NIST P-256 templates (same attributes, symmetric algorithm and signing hash;
file suffix `-ecc`) and, for templates above 2048 bits, one with `keyBits`
capped at 2048 (`-rsa2048`). The variant's later rounds refer to the new
keys' outputs through the converted references. A variant is replayed and cut
before the first round whose response code differs from the recording, and
dropped if that leaves no rewritten round; `cmin` keeps whichever inputs add
coverage.

## The dictionary

`tpm2.dict` holds the `TPM_CC_*`, `TPM_ALG_*`, `TPM_RH_*`, `TPM_RS_PW`,
`TPM_ST_*`, `TPM_ECC_*`, `TPM_SU_*`, `TPM_SE_*` and `TPM_CAP_*` constants and
the `TPMA_OBJECT`, `TPMA_NV` and `TPMA_SESSION` attributes of the `tpm2` crate
in big-endian wire form (the input encoding is big-endian too). Regenerate it
after changing the constants:

```sh
cargo run --manifest-path testing/fuzz/Cargo.toml --bin gen_dict > testing/fuzz/tpm2.dict
```

## Testing the tools

```sh
cd testing/fuzz
cargo test --release --bin gen_dict --bin trace2conv --bin to_test
cargo clippy --all-targets -- -D warnings
```

The `trace2conv` and `to_test` tests replay conversations on a differential
`Tpm`, so they need `MSTPM20_BIN`/`IBMSWTPM2_BIN` (see Build). The trace
fixtures in `src/bin/shared/testdata/` are E2E traces recorded with the fixed
seed; if a `tpm-rs` change alters their responses, re-record them (step 1
above) and copy the traces of the same tests.
