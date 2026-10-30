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
- [`tpm2-impl`](./crates/tpm2-impl/): engine code implementing the TPM's core logic
  - Currently _quite_ incomplete.

## Status

While `tpm2` is mostly stable, both `tpm2-client` and `tpm2-impl` are expected
to undergo significant changes, perhaps on a daily basis. This crate follows
[SemVer], so any `v0.y.z` code may experience breaking changes.

## Building & Testing

Building and testing tpm-rs is the same as other Cargo projects:

```
# Just build the project
cargo build

# Run most of the tests (excluding simulator tests)
cargo test
```

### Simulator Tests

Simulator tests use the TPM simulator provided by TCG to test the TPM client
against a running simulation. This depends on having the TPM simulator built.

There is a Dockerfile that can build this for you, making the process easier:

```
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
