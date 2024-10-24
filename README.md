# tpm-rs

## About
TPM 2.0 Implementation in Rust

## Status
This is an early development environment and is currently very unstable -
Everything is subject to change, perhaps on a daily basis.

## What needs to be done

See the [issues](https://github.com/tpm-rs/tpm-rs/issues) for a list of tasks
to do. Feel free to contribute PRs to achieve those, or to add goals to the
Project list. If you are unsure, have a look at the [good first
issues](https://github.com/tpm-rs/tpm-rs/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)

## Test-Driven Principle for PRs.

Good test coverage is key to code velocity and reliability. The easiest way to
maintain good test coverage is to require it from the beginning. Since we are
starting from a green field, we treat test coverage as a first-class feature
that underpins all others.

Hence, any PR for code needs meaningful tests, and those tests need to be
integrated into our CI pipeline.
