//! Interoperability tests between the BoringSSL and OpenSSL backends.

type A = tpm2_boringssl::BoringSsl;
type B = tpm2_openssl::OpensslBackend;

#[path = "common/interop.rs"]
mod interop;
