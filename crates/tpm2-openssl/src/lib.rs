//! OpenSSL cryptography backend for `tpm2`.
//!
//! Note on `no_std` support: The `openssl` crate requires `std` (e.g. for `Error`,
//! `io::Read`/`Write`, and memory allocation APIs). While `openssl-sys` does not
//! strictly require `std`, writing complete safe wrappers for the entire EVP API,
//! RSA, and ECC in `#![no_std]` is beyond a reasonable effort. Thus, this crate
//! requires `std`.
//!
//! # Supported Algorithms
//!
//! | Algorithm | Supported? | Notes |
//! |---|---|---|
//! | SHA-1, SHA-2 | Yes | |
//! | SHA-3, SM3 | Yes | |
//! | HMAC | Yes | |
//! | CMAC | Yes | |
//! | AES (CTR, OFB, CBC, CFB, ECB) | Yes | |
//! | SM4 (CTR, OFB, CBC, CFB, ECB) | Yes | |
//! | Camellia (CTR, OFB, CBC, CFB, ECB) | Yes | |
//! | RSA (1024-4096) | Yes | |
//! | ECC (NIST P-192..P-521, Brainpool, SM2) | Yes | BN curves are not supported |
//! | ECDSA, ECDH, SM2 | Yes | SM2 signatures only on the SM2 curve |
//! | Ed25519/Ed448 | Yes | Pure and HashEdDSA supported |
//! | X25519/X448 | Yes | |
//! | ML-DSA, ML-KEM | Yes | |
#![cfg_attr(docsrs, feature(doc_cfg))]

/// OpenSSL 3 declarations missing from `openssl-sys`, which declares
/// everything else this crate uses.
mod sys {
    use core::ffi::{c_int, c_uint};
    use openssl_sys::{EVP_MD_CTX, EVP_PKEY_CTX, EVP_SIGNATURE, OSSL_PARAM};

    /// `OSSL_PARAM` data type of a native signed integer (`core_names.h`).
    pub(crate) const OSSL_PARAM_INTEGER: c_uint = 1;
    /// `OSSL_PARAM` data type of a byte string (`core_names.h`).
    pub(crate) const OSSL_PARAM_OCTET_STRING: c_uint = 5;

    /// `RSAES-PKCS1-v1_5` decryption padding mode which reports invalid
    /// padding as an error, rather than OpenSSL's default implicit rejection
    /// (returning a synthetic plaintext).
    pub(crate) const RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING: c_int = 8;
    /// PSS salt length which recovers the salt length from the signature when
    /// verifying.
    pub(crate) const RSA_PSS_SALTLEN_AUTO: c_int = -2;

    unsafe extern "C" {
        /// Initializes `ctx` to sign with an explicitly fetched `signature`
        /// algorithm (e.g. `Ed25519ph`, rather than the key's default).
        pub(crate) fn EVP_PKEY_sign_init_ex2(
            ctx: *mut EVP_PKEY_CTX,
            signature: *mut EVP_SIGNATURE,
            params: *const OSSL_PARAM,
        ) -> c_int;
        /// Like [`EVP_PKEY_sign_init_ex2`], but to verify.
        pub(crate) fn EVP_PKEY_verify_init_ex2(
            ctx: *mut EVP_PKEY_CTX,
            signature: *mut EVP_SIGNATURE,
            params: *const OSSL_PARAM,
        ) -> c_int;
        /// Returns the `EVP_PKEY_CTX` of `ctx` (`EVP_MD_CTX_pkey_ctx` before
        /// OpenSSL 3).
        pub(crate) fn EVP_MD_CTX_get_pkey_ctx(ctx: *const EVP_MD_CTX) -> *mut EVP_PKEY_CTX;
    }
}

pub mod cmac;
pub mod ecc;
pub mod hash;
pub mod hmac;
pub mod mldsa;
pub mod mlkem;
pub mod rng;
pub mod rsa;
pub mod symmetric;

/// OpenSSL cryptography backend implementing [`tpm2::crypto::Crypto`].
pub struct OpensslBackend;

impl tpm2::crypto::Crypto for OpensslBackend {
    fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        // `memcmp::eq` panics if the lengths differ.
        a.len() == b.len() && openssl::memcmp::eq(a, b)
    }
}
