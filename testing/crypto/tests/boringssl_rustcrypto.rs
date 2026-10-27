//! Interoperability tests between the BoringSSL and RustCrypto backends.

type A = tpm2_boringssl::BoringSsl;
type B = tpm2_rustcrypto::RustCrypto;

#[path = "common/interop.rs"]
mod interop;
