#!/bin/sh
set -ex

cargo build
cargo testsudo
cargo fmt -- --check
cargo clippy -- --deny=warnings