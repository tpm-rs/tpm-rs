//! `ibmswtpm2`: the patched IBM software TPM as a child process of the
//! differential tests (`differential` feature of `testing`).
//!
//! `testing/build.rs` clones `https://github.com/kgoldman/ibmswtpm2` at a
//! pinned commit, applies `testing/patches/ibmswtpm2/*.patch`, compiles it into a
//! symbol-isolated static library (`libibmswtpm2.a`, exporting only
//! `difftest_ibmswtpm2_*`) and links it into the `testing` library, whose
//! `testing::differential::inproc` hosts it in this process. The IBM TPM keeps
//! its state in globals, so every `testing::tpm::Tpm` launches its own
//! `ibmswtpm2` process (see `testing::differential::Reference`), which lets
//! tests run in parallel and a single test use several TPMs.
//!
//! Its C reference runs its own random number generator, seeded from the
//! process ID and its (virtual) clock, which the matching `tpm-rs` simulator
//! reproduces; one process can therefore only be compared with the one
//! simulator built for it.
//!
//! The process serves `testing::differential::protocol` on stdin/stdout (see
//! `testing::differential::server`); anything the C code prints goes to
//! stderr instead of the protocol channel.

#![forbid(unsafe_code)]

fn main() {
    testing::differential::inproc::serve_process(testing::differential::Implementation::Ibmswtpm2);
}
