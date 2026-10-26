---
name: fuzz
description: Run differential fuzzing campaigns of tpm-rs against the C reference TPMs (mstpm20, ibmswtpm2), triage and fix the findings. Only run fuzzing when the user explicitly asks for it.
---

# Differential fuzzing of tpm-rs and fixing its findings

> [!IMPORTANT]
> **Do not run fuzzing unless the user explicitly asks for it.** This covers
> `cargo fuzz run/tmin/cmin`, the scripts in `scripts/` (campaigns, triage
> replays, coverage, `final_check.sh`) and corpus regeneration. They take a long
> time and use every core. Without such a request, use this skill only as
> reference, e.g. to classify or fix a divergence the user gives you, and verify
> fixes with the normal tests.

Use this skill to fuzz `tpm-rs` against the C references, to triage crash
artifacts, or to fix a divergence that a fuzzer (or a differential E2E test)
found. It is distilled from the first fuzzing effort (a five-worker swarm).
That effort ran five 30-minute campaigns, which found 23,538 → 346 → 27 → 10 → 0
crash artifacts, and fixed 46 `tpm-rs` bugs.

Read these first; this skill does not repeat them:
- [`testing/fuzz/README.md`](../../../testing/fuzz/README.md): the build, run,
  triage, corpus and dictionary commands (the reference manual).
- [`testing/fuzz/report.md`](../../../testing/fuzz/report.md): every bug found
  so far, with root cause, fix and spec quote. Check it for a known bug class
  before you dig in.
- [`differential.md`](../../../differential.md): the comparison method, the
  reference patches (Parts II, VI, VII), the profile settings (Part III) and
  the active harness exceptions (Part IV).
- The `tpm2-spec` skill: the spec is the ground truth for every decision below.

## Ground rules

1. **Spec first.** For every discrepancy, look up the TPM 2.0 spec: Part 2
   unmarshal tables (the `#TPM_RC_*` rows) and Part 3 (the command's
   "Detailed Actions", "Command Header/Handle Area/Session Area Validation",
   "Response Code Details"). `tpm-rs` follows the spec. It follows `mstpm20` only
   where the spec is silent or ambiguous. `ibmswtpm2` never decides.
   - Part 3 "Command Validation" says the order of the checks is not normative
     unless stated otherwise. For pure check-order differences, follow the
     `mstpm20` order and quote that sentence.
   - Derive limits (TPM2B sizes, list bounds) from the Part 2 definitions. Never
     derive them by probing what a reference accepts.
2. **Quote the spec verbatim.** Citing a section number is not enough.
   - A `tpm-rs` fix gets a comment at the fixed check with the quote and its
     source, e.g. `// TPM 2.0 Part 3, 12.1 TPM2_Create: "..."`.
   - A reference patch quotes the spec in its header.
   - Where the spec is silent, quote the closest text and say plainly that the
     spec does not cover the point and that you followed `mstpm20`.
3. **Commands only `tpm-rs` supports:** ignore the discrepancy. Add a narrow
   `server.rs` exception for that command and `Implementation`, plus a
   `differential.md` entry. Do not change `tpm-rs`.
4. **Commands only a reference supports:** turn them off in that reference
   with a `profile-*` patch, so both sides answer `TPM_RC_COMMAND_CODE`. Today
   `profile-command-list.patch` (one per reference directory) does this.
   Extend it when `tpm-rs` drops a command or a reference gains one.
5. **Bad input must never produce `TPM_RC_FAILURE`** in `tpm-rs`. The only
   allowed `FAILURE` is the one the spec requires: the `TPM2_ContextLoad`
   fingerprint check. Every `0x101` the fuzzer found was a real bug.
6. **Prefer real alignment over exceptions.** Five exceptions (5, 6, 7, 10 and
   11) were retired once `tpm-rs` matched. Never fake a value to make the
   comparison pass. For example, `TPM_PT_MAX_*_CONTEXT` reports the true value
   and keeps a documented exception.
7. **Follow the repo rules.**
   - Git and `jj` are read-only unless the user says otherwise.
   - Keep campaign directories, crash copies, logs and scratch scripts outside
     the repo (e.g. `/tmp/tpm-rs-fuzz/`). `testing/fuzz/{artifacts,corpus,coverage,target}`
     are gitignored, and the user does not want the corpus committed.
   - Tests in `testing` are strictly black-box: use the `Tpm` command interface
     only.
   - Follow the `GEMINI.md` naming and doc rules.

## Scripts

Portable versions of the swarm's tools are in `scripts/` (they find the repo
root themselves):

| Script | What it does |
|---|---|
| [`campaign.sh`](scripts/campaign.sh) `<dir> [secs=1800] [forks]` | Builds the in-process target into its own target dir and freezes the binary in `<dir>`. Fuzzes a scratch copy of the seed corpus and writes artifacts to `<dir>/art`. Records the tree state in `<dir>/tree.txt`. |
| [`triage.py`](scripts/triage.py) `group <dir> [--top N]` | Computes signatures (cached), groups them into families, minimizes the top N representatives and renders them with `to_test` into `<dir>/families.md`, with `us-only`/`them-only`/`spec` tags. |
| [`triage.py`](scripts/triage.py) `replay <old dir> [binary]` | Replays an old campaign's artifacts on a new build and lists, per family, what still reproduces. |
| [`coverage.sh`](scripts/coverage.sh) `[corpus] [out]` | Source-based coverage (`cargo fuzz coverage` + `llvm-cov`), including the `tpm2-impl` handler table. |
| [`final_check.sh`](scripts/final_check.sh) | The 19-step verification list plus a check that `known_divergences.txt` has no active entries. |

## Workflow

### 0. Prerequisites

```sh
# Reference binaries (process mode: to_test, trace2conv, rendering in triage.py)
cargo build --release -p testing --features differential --bins
export MSTPM20_BIN=$PWD/target/release/mstpm20 IBMSWTPM2_BIN=$PWD/target/release/ibmswtpm2
```

The seed corpus `testing/fuzz/corpus/diff_conversation/` is generated
locally and is not checked in. If it is missing or stale, regenerate it with
README "The seed corpus" (record traces → `trace2conv --verify
--ecc-variants` → session seeds → `cmin`). It is stale after any change to
the input encoding, the value pool, the seed `4242:1000000`, or `tpm-rs`
responses the recorded conversations depend on (literal HMACs and nonces only
replay while the responses stay byte-identical).

### 1. Build and smoke-run

```sh
cargo fuzz build --fuzz-dir testing/fuzz -O -s none --features inproc diff_conversation
```

- **The target name `diff_conversation` is required.** Without it, cargo also
  builds the `src/bin` tools with sancov but no sanitizer runtime, and the
  link fails with undefined `__sanitizer_cov_*`.
- Pass the same mode flags (`-O -s none --features inproc`) to every later
  `cargo fuzz run/tmin/cmin`. Otherwise cargo silently rebuilds the target in
  another mode.
- Always use `-detect_leaks=0`. Without it, LSan writes an empty
  `crash-da39a3ee…` artifact at exit (that name is the SHA-1 of empty input).
- Before a long campaign, do a short smoke run (e.g. `campaign.sh /tmp/tpm-rs-fuzz/smoke 120 8`).
  Early runs mostly find harness and driver problems.

### 2. Run a campaign

```sh
_agents/skills/fuzz/scripts/campaign.sh /tmp/tpm-rs-fuzz/campaign1 1800 72
```

- The script freezes a copy of the binary. Triage and replay must use the
  same binary even if the tree changes meanwhile. Note which fixes were in
  the tree when it was built (`tree.txt`).
- Use a separate `--target-dir` (the script does) so campaign builds do not
  block on the cargo build lock of other work.
- Throughput: about 130–160 exec/s per fork on the real corpus, dominated
  by `tpm-rs` RSA key generation, and about 5,500 exec/s per fork on an empty
  corpus. `TPM_FUZZ_STATS=<n>` prints driver and session counters, such as
  the HMAC success rate.
- `FUZZ_C_COVERAGE=1` (clang, separate target dir) also counts the C
  references' edges. It is slower, so use it only for occasional runs that
  look for reference paths.

### 3. Group the artifacts

```sh
_agents/skills/fuzz/scripts/triage.py group /tmp/tpm-rs-fuzz/campaign1 --top 40
```

Thousands of artifacts collapse into a few families. In the first campaign,
23,538 artifacts became 625 signatures and then 213 families. Work through
`families.md` from the largest family down.

- `[us-only]` and `[them-only]` families are handled by rules 3 and 4.
- Everything else is `[spec]`.
- `NO_REPRO` means the artifact does not fail on its own binary. This is
  usually a flaky driver or harness state; investigate it if it is frequent.

Manual tools for a single input:

```sh
cargo fuzz run --fuzz-dir testing/fuzz -O -s none --features inproc diff_conversation <crash>   # both responses
cargo fuzz tmin --fuzz-dir testing/fuzz -O -s none --features inproc diff_conversation <crash> -- -detect_leaks=0
cargo run --release --manifest-path testing/fuzz/Cargo.toml --bin to_test -- --name <behavior> <crash>
```

After `tmin`, check that the minimized input still has the **same
signature**. Otherwise keep the original. If `to_test` prints "without a
finding" on stderr, the input no longer reproduces on the current source.

### 4. Classify each family

Before you blame `tpm-rs`, rule out the harness. Several divergences in the
first run were bugs in the test harness, not in `tpm-rs`:
- `server.rs` handle translation aliasing after a flush;
- `translate_context_load` recomputing a fuzzed `commandSize`;
- the value pool recording ciphertext as auth values;
- a driver round off-by-one;
- stale corpus literals containing context blobs from an older `tpm-rs`
  build.

Read both responses round by round. Ask whether the earlier rounds agree and
whether the conversation is plausible.

Then decide with the spec:

| Finding | Action |
|---|---|
| `tpm-rs` deviates from the spec, or from `mstpm20` where the spec is silent | Fix `crates/tpm2*` with a verbatim spec-quote comment and add an E2E regression test (step 5). |
| A reference deviates from the spec (also when the references disagree with each other) | `testing/patches/<impl>/bug-fix-<topic>.patch` in every affected reference directory, plus a `differential.md` item (step 6). |
| A command or algorithm one side does not implement | Rules 3 and 4 (`server.rs` exception, or a `profile-*` patch). |
| Implementation-defined (blob layouts, capability values the spec leaves to the vendor) | A narrow `server.rs` exception plus a `differential.md` Part IV row (step 7). |
| Harness, driver or session-engine bug | Fix `testing/src/differential/*` or `testing/fuzz/src/*`, with a unit test. |

Only add a pattern to `testing/fuzz/known_divergences.txt` to keep a long
campaign productive while the fix is pending. Each entry needs a comment
explaining why, and you must remove it together with the fix. At the end of a
series, the file must have no active entries.

### 5. Fix `tpm-rs` and add the regression test

- Put the fix in `crates/tpm2-impl` (or in `crates/tpm2` for unmarshal and
  profile limits), with a comment that quotes the spec at the fixed check.
- Generate the test with `to_test --name <behavior> <crash.min>`.
  - Paste it into `testing/tests/e2e/<topic>.rs`: an existing topic file, or a
    new one with a `//!` doc, linked from `tests/e2e/mod.rs`.
  - Name the test after the behavior, e.g.
    `invalid_handle_is_reported_before_missing_authorization_size`. Do not
    use `test_`, `findings` or `probe` names.
  - Write a `///` doc that quotes the spec.
  - Replace the `TODO(triage)` with the specified response code.
- Run the test against both `mstpm20` versions:
  `cargo test --release -p testing --features differential <name>`, then the
  same with `MSTPM20_VERSION=public`.
- Update any `tpm2-impl` unit test that encoded the old behavior.
- Delete temporary probe tests and examples before you hand off. In the first
  run, they broke `fmt`, `clippy` and the differential suite.

Recurring `tpm-rs` bug classes (details and spec quotes are in `report.md`
§2):
- **Validation order:**
  - Validate the whole handle area first, each handle against its Part 3
    interface type in order, before load status, `authSize` or sessions
    (`engine.rs` `validate_command_handles`, `handle_checks::command_handle_types`).
  - A truncated handle area gives per-handle `INSUFFICIENT`/`VALUE` errors.
  - Each session is checked as it is unmarshaled.
- **Hand-written "error refinement" fallbacks** were repeatedly wrong (in
  `TestParms`, `PolicyPCR`, `Create` `inPublic` and capabilities). Replace
  them with the plain profile-aware unmarshal, where the first bad field in
  wire order wins.
- **Profile limits:** `tpm2::profile` defines the algorithms, curves, RSA
  bits, TPM2B capacities (`TPM2B_TEMPLATE` 350, `TPM2B_ECC_PARAMETER` 66) and
  `HASH_COUNT` lists. `MAX_COMMAND_SIZE` follows the profile.
- **Object, load and import check order:**
  - `Import` recovers the seed before it validates `objectPublic`.
  - A zero-padded ECC private key is valid.
  - In `LoadExternal`, the binding check decides when a private area is
    present.
  - `Create`/`CreatePrimary` check the attributes before the `userAuth` size.
- **Any `TPM_RC_FAILURE`** on malformed input: `ContextLoad` contents,
  `MakeCredential` with a CTR protector. Credentials always use CFB.
- **State on error:** a failing command leaves the TPM unchanged (Part 3
  "Response Codes").
- **Matching reference-defined layout:**
  - Transient handle numbering skips the per-command copies of persistent
    objects.
  - Unwritten bytes of a non-orderly NV index read as `0xFF`, of an orderly
    one as `0x00`.
  - NV capacity follows the `storage::nv_capacity` ledger.

### 6. Write a reference patch

- File: `testing/patches/{mstpm20,mstpm20-185-feature,ibmswtpm2}/bug-fix-<topic>.patch`.
  Use the same name in every directory that needs it, and check each version
  separately. For example, v185 already persisted public-only objects
  correctly. Patches apply in file-name order.
- The header comes before the first `diff --git`. Copy the format of an
  existing patch, e.g. `bug-fix-sequence-complete-ticket-error-state.patch`:
  ```
  <topic>: <one-line summary>

  Classification: spec-deviation bug fix.

  Specification (TPM 2.0 Part 3, "<section>"): "<verbatim quote>"

  <What the C code does wrong and what the patch changes, "as in tpm-rs".
  Found by differential fuzzing.>
  ```
- In the C code, mark the change with
  `// tpm-rs differential testing -- C-ref spec deviation fix (NOT determinism): ...`.
- No patch may change how a reference draws random numbers. Keep patches
  narrow: an over-broad `ibmswtpm2` patch once also accepted handles where
  `TPMI_RH_BASE_HIERARCHY` forbids them.
- Verify the patch:
  - `cargo build --release -p testing --features differential` rebuilds v185
    and `ibmswtpm2` when the patches change.
  - `MSTPM20_VERSION=public cargo test --release -p testing --features differential`
    builds and tests the public `mstpm20`. Afterwards, rebuild v185 by
    running a differential test without the variable.
  - Do not use `git init`/`git apply` to check a patch, even in `/tmp`; use
    `patch -p1 --dry-run`.
- Add a `differential.md` item: Part II for `mstpm20`, Part VI for
  `ibmswtpm2`, Part VII for spec 185. Also add a summary-table row, and keep
  the numbering consistent.

### 7. Add a harness exception (last resort)

- Put it in `testing/src/differential/server.rs` (`compare_differential_response`,
  `capability_difference_is_documented`).
- Key it on the command code, the `Implementation`, and exact field or
  response-code conditions.
- Give it a doc comment with the spec basis ("implementation-defined" plus
  a quote), a unit test, and a `differential.md` Part IV row.
- Call out deliberate masks explicitly, such as rule 9's zeroed integrity
  bytes.
- After changing context translation, rerun the full `context_*` E2E suite.
  An earlier "invert one integrity byte" mask turned a tampered test blob back
  into an authentic one and crashed the `mstpm20` process.
- `DIFFERENTIAL_LOG_EXCEPTIONS=1` logs every applied exception.

### 8. Recheck, loop and finish

1. Replay the old artifacts on the fixed tree:
   `triage.py replay /tmp/tpm-rs-fuzz/campaign1`. Every fixed family should
   drop to 0. Whatever still reproduces goes back to step 4.
2. Regenerate the seed corpus if the fixes changed responses that recorded
   conversations depend on. Optionally grow it from the campaign's
   `<dir>/work` with the README's `-set_cover_merge=1` command (keep it under
   about 5 MB).
3. Run the next campaign (step 2) on the new tree.
4. **Done criterion** (agreed with the user): a full 30-minute campaign
   finds nothing apart from documented exceptions, `known_divergences.txt`
   has no active entries, and `scripts/final_check.sh` passes. Run
   `final_check.sh` once as a dry run before the last campaign; it caught a
   broken documented build command.
5. If the user asks for a report, update `testing/fuzz/report.md` and keep
   its structure:
   1. Coverage: a per-campaign table plus `coverage.sh` handler coverage.
   2. Every `tpm-rs` bug: campaign and family, root cause, fix with a
      line-anchored relative link, verbatim spec quote, regression test. Leave
      reference bugs out.
   3. The remaining ignored discrepancies, re-derived from the current
      `server.rs`.

   Check that every link and line anchor resolves, and do not mention
   swarm-internal identifiers.
6. Keep the docs in sync with behavior changes: `differential.md`,
   `testing/fuzz/README.md`, and the `GEMINI.md` architecture notes
   (`GEMINI.md` is gitignored; do not force-add it).

## Working as a swarm

Parallel triage works well. Split the families by area, such as handles and
sessions, objects and import, context management, NV, and capabilities. Rules
that avoided collisions:
- Give each worker its own working copy (`workspace: share`), or at least
  its own `--target-dir`.
- Announce file claims before you edit. Never edit the same handler
  (`engine.rs`, `create_loaded.rs`, `load_external.rs`) at the same time as
  another worker. Re-read a file before you write it.
- Run `rustfmt` on your own files only, not `cargo fmt` over a crate other
  workers are editing.
- Tests that touch the virtual clock or `CReference` take
  `server::VIRTUAL_CLOCK_TEST_LOCK`.
- Workers run only read-only git. Only the coordinator commits, and only
  when the user asks.
