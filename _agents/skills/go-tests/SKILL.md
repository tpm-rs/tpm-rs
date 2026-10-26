---
name: go-tests
description: Instructions and documentation for running Go E2E integration tests under go-tests/tests. Only run them when the user explicitly asks for it.
---

# Go E2E Integration Tests

> [!IMPORTANT]
> **Do not run the Go tests unless the user explicitly asks for it.** For
> regular verification, use the Rust ports of these tests instead:
> `cargo test --release -p testing --test go`.

This document describes how to run the Go end-to-end (E2E) integration test suite located under `go-tests/tests`.

## Overview

The tests under `go-tests/tests/` exercise the Rust TPM 2.0 simulator (`tpm2-simulator`) against an external Go client library over network/IPC sockets. This verifies that the Rust simulator behaves correctly when called by external clients.

These tests are copied from https://github.com/google/go-tpm/tree/main/tpm2/test (commit `e05fb8b`), and `go.mod` pins the `go-tpm` library at the same commit.

To update them, clone `go-tpm` to `/tmp/` (or your artifact folder), and do the following:
1. Replace the `*_test.go` files here with those of `tpm2/test/`, deleting the ones upstream removed. Keep `go.mod`, `go.sum` and `.gitignore`.
2. Bump the library with `go get github.com/google/go-tpm@<commit> && go mod tidy`.
3. Update the Rust ports in `testing/tests/go/` so every Go test function has a port marked `// Original Go test: <file>_test.go - <TestName>`.

> [!NOTE]
> These Go E2E integration tests are also ported to native Rust integration tests under *testing/src/go* to ensure behavioral parity and allow fast testing within standard Cargo workflows.

## Running the Tests

> [!IMPORTANT]
> **Build Profile Guideline**: Always use `--release` for overall testing (e.g., `./_agents/skills/go-tests/run-go-tests.sh --release` or `cargo build --release -p tpm2-simulator`) to avoid slow execution. Use debug builds **only** for per-test debugging.

### Convenience Script (Recommended)

Use `run-go-tests.sh` to automatically compile `tpm2-simulator` and execute the Go tests:

```bash
# Run all Go E2E tests (always use --release for overall testing)
./_agents/skills/go-tests/run-go-tests.sh --release

# Run a specific test function by regex (debug build for per-test debugging)
./_agents/skills/go-tests/run-go-tests.sh -run ^TestGetTime$

# Run all tests in a specific file (debug build for per-test debugging)
./_agents/skills/go-tests/run-go-tests.sh get_time_test.go

# Run a specific test with release build
./_agents/skills/go-tests/run-go-tests.sh --release -run ^TestGetTime$
```

### Manual Execution

1. Compile the `tpm2-simulator` binary (use `--release` for overall testing):

```bash
cargo build --release -p tpm2-simulator
```

To test against a specific cryptographic backend (e.g., `bssl` or `crux`), pass the corresponding features when building:

```bash
cargo build --release -p tpm2-simulator --no-default-features --features bssl
```

*(Note: For per-test debugging, you may omit `--release` to build in debug mode).*

2. Change into the `go-tests/tests` directory and run `go test`, pointing `--tpm-sim-path` to your compiled `tpm2-simulator` binary:

```bash
cd _agents/skills/go-tests/tests
go test -v -args --tpm-sim-path ../../../../target/release/tpm2-simulator
```

#### Running Specific Tests Manually

For per-test debugging, you can use the debug binary or release binary:

```bash
cd _agents/skills/go-tests/tests

# Run all tests in a specific file
go test -v get_time_test.go -args --tpm-sim-path ../../../../target/debug/tpm2-simulator

# Run a specific test function by regex
go test -v -run ^TestGetTime$ -args --tpm-sim-path ../../../../target/debug/tpm2-simulator
```

## Notice

> [!CAUTION]
> **DO NOT MODIFY GO TESTS**: Never modify, edit, or delete any of the Go test files or dependencies under `go-tests/tests/`. These tests represent external client verification suites and must remain unmodified. The only exception is syncing them verbatim from upstream `go-tpm` when the user asks for it.