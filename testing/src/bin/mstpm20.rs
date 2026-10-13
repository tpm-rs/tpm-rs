//! `mstpm20`: the patched TCG reference TPM (the Microsoft `ms-tpm-20-ref`
//! code base) as a child process of the differential tests (`differential`
//! feature of `testing`).
//!
//! `testing/build.rs` clones `https://github.com/TrustedComputingGroup/TPM` at
//! commit `3b1f0e623f244abe2015df9e3ba86de5c9118524`, applies
//! `testing/mstpm20.patch`, compiles it into a symbol-isolated static library
//! (`libmstpm20.a`, exporting only `difftest_*`) and links it into this
//! binary. The C reference keeps its state in globals, so every
//! `testing::tpm::Tpm` launches its own `mstpm20` process (see
//! `testing::differential::Reference`), which lets tests run in parallel and a
//! single test use several TPMs.
//!
//! The process serves `testing::differential::protocol` on stdin/stdout (see
//! `testing::differential::server`); anything the C code prints goes to
//! stderr instead of the protocol channel.

#![deny(unsafe_code)]

#[path = "shared/ffi.rs"]
mod ffi;

fn main() {
    ffi::main(testing::differential::Implementation::Mstpm20);
}
