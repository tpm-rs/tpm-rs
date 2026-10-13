//! `ibmswtpm2`: the patched IBM software TPM as a child process of the
//! differential tests (`differential` feature of `testing`).
//!
//! `testing/build.rs` clones `https://github.com/kgoldman/ibmswtpm2` at a
//! pinned commit, applies `testing/ibmswtpm2.patch`, compiles it into a
//! symbol-isolated static library (`libibmswtpm2.a`, exporting only
//! `difftest_*`) and links it into this binary. The IBM TPM keeps its state in
//! globals, so every `testing::tpm::Tpm` launches its own `ibmswtpm2` process
//! (see `testing::differential::Reference`), which lets tests run in parallel
//! and a single test use several TPMs.
//!
//! The process serves `testing::differential::protocol` on stdin/stdout (see
//! `testing::differential::server`); anything the C code prints goes to
//! stderr instead of the protocol channel.

#![deny(unsafe_code)]

#[path = "shared/ffi.rs"]
mod ffi;

fn main() {
    ffi::main(testing::differential::Implementation::Ibmswtpm2);
}
