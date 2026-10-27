#!/bin/bash
# The full verification list run before declaring a fuzzing/triage round done
# (all steps passed at the end of the first campaign series). Prints one
# PASS/FAIL line per step; logs go to $LOG (default /tmp/tpm-rs-final-check).
#
# Usage: final_check.sh
# The differential steps run one target (C reference) each.
cd "$(dirname "$0")/../../../.." || exit 1
C=${CARGO:-$HOME/.cargo/bin/cargo}
export PATH=$HOME/.cargo/bin:$PATH
LOG=${LOG:-/tmp/tpm-rs-final-check}
mkdir -p "$LOG"
export REFERENCE_BIN=$PWD/target/release/reference
n=0; failed=0
step() {
  n=$((n+1)); local name="$1"; shift
  local t0; t0=$(date +%s)
  if (eval "$@") > "$LOG/$n.log" 2>&1; then r=PASS; else r=FAIL; failed=$((failed+1)); fi
  echo "$r [$n] $name ($(( $(date +%s)-t0 ))s) log=$LOG/$n.log"
}
step "check" "$C check"
step "fmt" "$C fmt --check"
step "clippy" "$C clippy --all-targets -- -D warnings"
for t in mstpm20 mstpm20-v185 ibmswtpm2; do
  step "clippy target-$t" "$C clippy --all-targets -p testing --features target-$t -- -D warnings"
done
step "clippy fuzz-inproc" "$C clippy --all-targets -p testing --features target-mstpm20,fuzz-inproc -- -D warnings"
step "clippy reference-rng" "$C clippy --all-targets -p tpm2-impl --features reference-rng -- -D warnings"
step "test" "$C test --release"
step "test reference-rng" "$C test --release -p tpm2-impl --features reference-rng"
for t in mstpm20 mstpm20-v185 ibmswtpm2; do
  step "differential (target-$t)" "$C test --release -p testing --features target-$t"
done
step "fuzz-inproc lib" "$C test --release -p testing --features target-mstpm20,fuzz-inproc --lib inproc"
step "fuzz-inproc reset_determinism" "$C test --release -p testing --features target-mstpm20,fuzz-inproc --test e2e reset_determinism"
# The fuzz crate's default target; restores REFERENCE_BIN for the fuzz crate tests.
step "reference binary (target-mstpm20)" "$C build --release -p testing --features target-mstpm20 --bin reference"
step "fuzz crate tests" "cd testing/fuzz && $C test --release --lib && $C test --release --bin gen_dict --bin trace2conv --bin to_test"
step "fuzz crate clippy" "cd testing/fuzz && $C clippy --all-targets -- -D warnings && $C clippy --all-targets --features inproc -- -D warnings"
step "fuzz crate fmt" "cd testing/fuzz && $C fmt --check"
step "cargo fuzz build (process mode)" "$C fuzz build --fuzz-dir testing/fuzz"
step "cargo fuzz build (inproc)" "$C fuzz build --fuzz-dir testing/fuzz -O -s none --features inproc diff_conversation"
step "go tests" "./_agents/skills/go-tests/run-go-tests.sh --release"
step "no active suppressions" "! grep -v '^\s*\(#\|$\)' testing/fuzz/known_divergences.txt"
echo "DONE: $failed failed"
[ "$failed" = 0 ]
