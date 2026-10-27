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
//! | ECDSA, ECDH, SM2 | Yes | |
//! | ECSchnorr | Yes | |
//! | Ed25519/Ed448 | Yes | Pure and HashEdDSA supported |
//! | X25519/X448 | Yes | |
//! | ML-DSA, ML-KEM | Yes | |

pub mod cmac;
pub mod ecc;
pub mod hash;
pub mod hmac;
pub mod rng;
pub mod rsa;
pub mod symmetric;

use tpm2::crypto::Crypto;

pub struct OpensslBackend;

impl Crypto for OpensslBackend {
    fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        // Use CRYPTO_memcmp which is bound in openssl-sys
        unsafe {
            openssl_sys::CRYPTO_memcmp(
                a.as_ptr() as *const libc::c_void,
                b.as_ptr() as *const libc::c_void,
                a.len(),
            ) == 0
        }
    }
}

impl tpm2::crypto::backend::Mlkem for OpensslBackend {
    type Mlkem512 = mlkem::Mlkem512;
    type Mlkem768 = mlkem::Mlkem768;
    type Mlkem1024 = mlkem::Mlkem1024;
}
pub mod mldsa;
impl tpm2::crypto::backend::Mldsa for OpensslBackend {
    type Mldsa44 = mldsa::Mldsa44;
    type Mldsa65 = mldsa::Mldsa65;
    type Mldsa87 = mldsa::Mldsa87;
}
pub mod mlkem;
