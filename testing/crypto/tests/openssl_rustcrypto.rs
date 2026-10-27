//! Interoperability tests between the OpenSSL and RustCrypto backends.

type A = tpm2_openssl::OpensslBackend;
type B = tpm2_rustcrypto::RustCrypto;

#[path = "common/interop.rs"]
mod interop;
