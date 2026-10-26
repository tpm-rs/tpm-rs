#!/bin/bash
# Runs one differential fuzzing campaign of the `diff_conversation` target:
# builds it (in-process references, no sanitizer, own target dir), freezes a
# copy of the binary in the campaign directory, copies the seed corpus into a
# scratch work corpus (the seed corpus is never written to) and fuzzes.
#
# Usage: campaign.sh <campaign dir> [seconds=1800] [forks=$(nproc)/2]
#
# Writes <dir>/diff_conversation (frozen binary), <dir>/work (grown corpus),
# <dir>/art (crash artifacts), <dir>/build.log, <dir>/fuzz.log and
# <dir>/tree.txt (the git revision and dirty files the binary was built from).
# Keep <dir> outside the repository (e.g. /tmp/tpm-rs-fuzz/campaign1).
set -euo pipefail
R=$(cd "$(dirname "$0")/../../../.." && pwd)
D=$(realpath -m "$1")
SECS=${2:-1800}
FORKS=${3:-$(($(nproc) / 2))}
TARGET_DIR=${FUZZ_TARGET_DIR:-$(dirname "$D")/fuzztarget}
CARGO=${CARGO:-$HOME/.cargo/bin/cargo}

if [ ! -d "$R/testing/fuzz/corpus/diff_conversation" ] || \
   [ -z "$(ls -A "$R/testing/fuzz/corpus/diff_conversation")" ]; then
    echo "error: no seed corpus; generate it (testing/fuzz/README.md, 'The seed corpus')" >&2
    exit 1
fi

rm -rf "$D"; mkdir -p "$D/work" "$D/art"
cd "$R"
{ git rev-parse HEAD; git status --short; } > "$D/tree.txt"
# The target name is required: without it the -s none build also builds the
# src/bin tools and fails to link (undefined __sanitizer_cov_*).
"$CARGO" fuzz build --fuzz-dir testing/fuzz -O -s none --features inproc \
    --target-dir "$TARGET_DIR" diff_conversation > "$D/build.log" 2>&1
cp "$TARGET_DIR/x86_64-unknown-linux-gnu/release/diff_conversation" "$D/diff_conversation"
cp testing/fuzz/corpus/diff_conversation/* "$D/work/"
cp testing/fuzz/known_divergences.txt "$D/known_divergences.txt"
echo "campaign $D: ${SECS}s, $FORKS forks, $(ls "$D/work" | wc -l) seed inputs"
"$D/diff_conversation" "$D/work" -dict=testing/fuzz/tpm2.dict -detect_leaks=0 -timeout=10 \
    -rss_limit_mb=4096 -max_total_time="$SECS" -fork="$FORKS" -ignore_crashes=1 \
    -artifact_prefix="$D/art/" > "$D/fuzz.log" 2>&1 || true
grep -E "^#[0-9]+: cov" "$D/fuzz.log" | tail -1 || true
echo "artifacts: $(ls "$D/art" | wc -l)"
