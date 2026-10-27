//! `reference`: the patched C reference TPM of a differential build of
//! `testing` (its `target-*` feature) as a child process of the differential
//! tests.
//!
//! `testing/build.rs` clones the target's C code (the public TCG reference
//! implementation, the TCG reference implementation version 185 or the IBM
//! software TPM), patches it with `testing/patches/<target>/*.patch`, compiles
//! it into a symbol-isolated static library (exporting only
//! `difftest_<name>_*`) and links it into the `testing` library, whose
//! `testing::differential::inproc` hosts it in this process. The C reference
//! keeps its state in globals, so every `testing::tpm::Tpm` launches its own
//! `reference` process (see `testing::differential::Reference`), which lets
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
    testing::differential::inproc::serve_process(testing::differential::Implementation::TARGET);
}
