#!/usr/bin/env bash
#
# Script to build tpm2-simulator and run the Go E2E integration test suite.
#
# Usage:
#   # Run all Go E2E tests:
#   ./_agents/skills/go-tests/run-go-tests.sh
#
#   # Run all Go E2E tests with release build:
#   ./_agents/skills/go-tests/run-go-tests.sh --release
#
#   # Run a specific test:
#   ./_agents/skills/go-tests/run-go-tests.sh -run TestActivateTPMCredential
#
#   # Run tests in a specific file:
#   ./_agents/skills/go-tests/run-go-tests.sh nv_test.go
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

RELEASE=false
GO_TEST_ARGS=()

for arg in "$@"; do
  case "$arg" in
    --release)
      RELEASE=true
      ;;
    *)
      GO_TEST_ARGS+=("$arg")
      ;;
  esac
done

CARGO_BUILD_ARGS=(--manifest-path "${REPO_ROOT}/Cargo.toml" -p tpm2-simulator)
if [ "$RELEASE" = true ]; then
  PROFILE_DIR="release"
  CARGO_BUILD_ARGS+=(--release)
else
  PROFILE_DIR="debug"
fi

SIMULATOR_PATH="${REPO_ROOT}/target/${PROFILE_DIR}/tpm2-simulator"

echo "Building tpm2-simulator (${PROFILE_DIR})..."
cargo build "${CARGO_BUILD_ARGS[@]}"

echo "Running Go E2E tests..."
cd "${SCRIPT_DIR}/tests"

GO_TEST_CMD=(go test -v)
if [ ${#GO_TEST_ARGS[@]} -gt 0 ]; then
  GO_TEST_CMD+=("${GO_TEST_ARGS[@]}")
fi
GO_TEST_CMD+=(-args --tpm-sim-path "${SIMULATOR_PATH}")

"${GO_TEST_CMD[@]}"
