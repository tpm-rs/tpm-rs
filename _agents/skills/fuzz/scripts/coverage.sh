#!/bin/bash
# Source-based coverage of the `diff_conversation` target over a corpus: builds
# the coverage-instrumented target, runs it once per corpus file (one process
# per file, so a failing input does not stop the run), merges the profiles and
# reports coverage, in particular of crates/tpm2-impl/src/handler/.
#
# Usage: coverage.sh [corpus dir] [output dir]
# Defaults: testing/fuzz/corpus/diff_conversation, /tmp/tpm-rs-fuzz/coverage.
# Needs the llvm-tools component of the repo's toolchain
# (`rustup component add llvm-tools-preview`).
set -uo pipefail
R=$(cd "$(dirname "$0")/../../../.." && pwd)
CORPUS=$(realpath "${1:-$R/testing/fuzz/corpus/diff_conversation}")
OUT=$(realpath -m "${2:-/tmp/tpm-rs-fuzz/coverage}")
TARGET_DIR=${FUZZ_COV_TARGET_DIR:-$(dirname "$OUT")/covtarget}
CARGO=${CARGO:-$HOME/.cargo/bin/cargo}
cd "$R"
TOOLS=$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin
EMPTY=$(mktemp -d)
"$CARGO" fuzz coverage --fuzz-dir testing/fuzz --features inproc --target-dir "$TARGET_DIR" \
    diff_conversation "$EMPTY" -- -runs=0 > /dev/null 2>&1
BIN=$TARGET_DIR/x86_64-unknown-linux-gnu/release/diff_conversation
[ -x "$BIN" ] || { echo "error: coverage binary $BIN not built" >&2; exit 1; }
rm -rf "$OUT"; mkdir -p "$OUT/raw"
ls "$CORPUS" | xargs -P "$(nproc)" -I{} env ASAN_OPTIONS=detect_leaks=0 \
    LLVM_PROFILE_FILE="$OUT/raw/%p-%m.profraw" "$BIN" -detect_leaks=0 "$CORPUS/{}" \
    > "$OUT/run.log" 2>&1
"$TOOLS/llvm-profdata" merge -sparse "$OUT"/raw/*.profraw -o "$OUT/merged.profdata"
"$TOOLS/llvm-cov" report "$BIN" -instr-profile="$OUT/merged.profdata" \
    --ignore-filename-regex='(\.cargo|rustc|/rust/)' > "$OUT/report_all.txt"
"$TOOLS/llvm-cov" report "$BIN" -instr-profile="$OUT/merged.profdata" \
    "$R/crates/tpm2-impl/src/handler" > "$OUT/report_handlers.txt"
echo "per-line details: $TOOLS/llvm-cov show $BIN -instr-profile=$OUT/merged.profdata <file>"
echo "reports: $OUT/report_all.txt $OUT/report_handlers.txt"
tail -1 "$OUT/report_handlers.txt"
