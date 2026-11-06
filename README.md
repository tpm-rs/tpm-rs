# tpm-rs

[![Build Status]][GitHub Actions]
[![Crate]][crates.io]
[![Documentation]][docs.rs]
[![Dependency Status]][deps.rs]

## About

TPM 2.0 Implementation in Rust, consisting of:
- [`tpm2`](./crates/tpm2/): our core crate consisting of:
  - the [v185] TPM types
  - marshalling and unmarshalling code
  - cryptographic interfaces
- [`tpm2-client`](./crates/tpm2-client/): client-side code for running TPM commands
  - Includes bindings to the TCP-based simulator.
- [`tpm2-engine`](./crates/tpm2-engine/): engine code implementing the TPM's core logic
- [`tpm2-crypto`](./crates/tpm2-crypto/): cryptographic backends (`rust`, `crux`, `bssl`)
  implementing the `tpm2` cryptographic interfaces
- [`tpm2-platforms/linux`](./crates/tpm2-platforms/linux/) and
  [`tpm2-simulator`](./crates/tpm2-simulator/): a Linux platform and an MSSIM TPM simulator

## Status

While `tpm2` is mostly stable, both `tpm2-client` and `tpm2-engine` are expected
to undergo significant changes, perhaps on a daily basis. This crate follows
[SemVer], so any `v0.y.z` code may experience breaking changes.

## Building & Testing

Building and testing `tpm-rs` requires selecting a cryptographic backend. The workspace supports three backends:
- `rust`: Pure-Rust implementations.
- `crux`: Cryspen `libcrux` verification-oriented cryptography.
- `bssl` (default): BoringSSL integration.

To check compilation:
```bash
# Check with Rust
cargo check -p tpm2-simulator --no-default-features --features rust,sha512

# Check with Crux
cargo check -p tpm2-simulator --no-default-features --features crux,sha512

# Check with BoringSSL (BORINGSSL_BUILD_DIR defaults to <project-dir>/boringssl-build)
cargo check -p tpm2-simulator --no-default-features --features bssl,sha512
```

### Running Unit and Integration Tests

Run the test suite for the selected cryptographic backend:
```bash
# BoringSSL (default; BORINGSSL_BUILD_DIR defaults to <project-dir>/boringssl-build)
cargo test --release

# `tpm2` alone (its default features are every algorithm, so it is not a default member of the
# workspace)
cargo test --release -p tpm2

# Rust and Crux (the crates that support other backends; see AGENTS.md and `make test-backends`)
cargo test --release -p tpm2-crypto-tests --no-default-features --features rust,sha512
cargo test --release -p tpm2-engine --no-default-features --features dev_crypto_crux,sha512

# Build the simulator, and run only the simulator tests
cd crates/tpm2-client && docker compose run --rm simulator_tests
```

## Contributing

- You can read our detailed [coding style] and [contribution guide].
- Please file suggestions, issues, or designs to the [issues page].
- If you wish to work on an issue but have not seen much activity on it, just
  comment on the issue to see what would be needed to get started.
- You can see [good first issues] for a list of issues aimed towards beginners.

### Test-Driven PRs

Good test coverage is key to code velocity and reliability. The easiest way to
maintain good test coverage is to require it from the beginning. Since we are
starting from a green field, we treat test coverage as a first-class feature
that underpins all others.

Hence, any PR for code needs meaningful tests, and those tests need to be
integrated into our CI pipeline.

[GitHub Actions]: https://github.com/tpm-rs/tpm-rs/actions?query=branch:main
[Build Status]: https://github.com/tpm-rs/tpm-rs/actions/workflows/ci.yml/badge.svg?branch=main
[crates.io]: https://crates.io/crates/tpm2
[Crate]: https://img.shields.io/crates/v/tpm2
[docs.rs]: https://docs.rs/tpm2
[Documentation]: https://docs.rs/tpm2/badge.svg
[deps.rs]: https://deps.rs/repo/github/tpm-rs/tpm-rs
[Dependency Status]: https://deps.rs/repo/github/tpm-rs/tpm-rs/status.svg

[v185]: https://www.trustedcomputinggroup.org/resources/documents/tpm-library-specification
[semver]: https://semver.org/spec/v2.0.0.html
[coding style]: ./docs/coding-style.md
[contribution guide]: ./CONTRIBUTING.md
[issues page]: https://github.com/tpm-rs/tpm-rs/issues
[good first issues]: https://github.com/tpm-rs/tpm-rs/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22
