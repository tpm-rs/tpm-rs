//! RustCrypto backend implementation
//!
//! ## Supported Algorithms
//!
//! | Algorithm Family | Supported | Details |
//! | --- | --- | --- |
//! | Hashes | Yes | SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, SM3_256 |
//! | HMAC | Yes | Supported for all available hashes |
//! | CMAC | Yes | AES |
//! | Symmetric | Yes | AES (128, 192, 256) in CTR, OFB, CBC, CFB, ECB modes. SM4/Camellia supported. |
//! | RSA | Yes (Opt-in) | RSA 1024, 2048, 3072, 4096 (requires `rsa` feature). |
//! | ECC Curves | Yes | NIST P-192, P-224, P-256, P-384, P-521, SM2. |
//! | ECC Schemes | Partial | ECDSA, ECDH. SM2 and ECSchnorr are currently unsupported. |
//! | BN Curves | No | Bound to `!` (Not available in RustCrypto) |
//! | Brainpool | No | Bound to `!` (Not available in RustCrypto) |
//! | EdDSA | Partial | Ed25519 (`EdDSA` and `HashEdDSA`). Ed448 bound to `!`. |
//! | Montgomery | Partial | X25519 (`ECDH`). X448 bound to `!`. |
//! | ML-DSA | Yes | ML-DSA-44, ML-DSA-65, ML-DSA-87 (pure `ML-DSA`, external `µ`, `HashML-DSA`). |
//! | ML-KEM | Yes | ML-KEM-512, ML-KEM-768, ML-KEM-1024. |
//! | RNG | Yes | ChaCha20 RNG, seeded from the OS via `getrandom` |
//! | Constant Time Eq| Yes | Using `ct_eq` from `ctutils` |
//!
//! ## Note on `#![no_std]` and ML-DSA Stack Usage
//! This crate is `#![no_std]` compatible. The `rsa` module requires the `alloc` crate,
//! which is enabled via the optional `rsa` feature.
//!
//! To keep resident key handles small in `#![no_std]` environments, ML-DSA `Public` keys store
//! only the encoded public key bytes (`[u8; PUB_SIZE]`) and `Private` keys store only the
//! 32-byte seed plus the encoded public key (`1,344` B for ML-DSA-44, `1,984` B for ML-DSA-65,
//! `2,624` B for ML-DSA-87). Because `ml-dsa` runs without `alloc`, `load_private`, `generate`,
//! `sign_*`, and `verify_*` expand the NTT matrix $\hat{A}$ and polynomial vectors on the stack
//! inside `#[inline(never)]` helpers for the duration of the call:
//!
//! | Parameter Set | KeyPair Size (`Private`) | Transient Signing / Keygen Stack (`SigningKey`) | Transient Verification Stack (`VerifyingKey`) |
//! | --- | --- | --- | --- |
//! | ML-DSA-44 | 1,344 B | ~43 KB | ~26 KB |
//! | ML-DSA-65 | 1,984 B | ~72 KB | ~45 KB |
//! | ML-DSA-87 | 2,624 B | ~103 KB | ~75 KB |
#![forbid(unsafe_code)]
#![no_std]
#![warn(missing_docs)]

#[cfg(feature = "rsa")]
extern crate alloc;

use tpm2::crypto::{
    Crypto,
    backend::{Cmac, Ecc, Hash, Hmac, Rsa, Symmetric},
};

mod cmac;
mod ecc;
mod hash;
mod rng;
#[cfg(feature = "rsa")]
mod rsa;
mod symmetric;

pub mod ed25519;
pub mod mldsa;
pub mod mlkem;
pub mod x25519;

pub use {
    cmac::CmacWrapper,
    hash::{HashWrapper, HmacWrapper},
    rng::ChaChaRng,
    symmetric::AesKey,
};

#[cfg(feature = "rsa")]
pub use rsa::RsaKeyWrapper;

pub use ecc::EccCurveWrapper;

/// Cryptography backend implemented using the RustCrypto crates.
pub struct RustCrypto;

impl Hash for RustCrypto {
    type Sha1 = HashWrapper<sha1::Sha1>;
    type Sha256 = HashWrapper<sha2::Sha256>;
    type Sha384 = HashWrapper<sha2::Sha384>;
    type Sha512 = HashWrapper<sha2::Sha512>;
    type Sm3_256 = HashWrapper<sm3::Sm3>;
    type Sha3_256 = HashWrapper<sha3::Sha3_256>;
    type Sha3_384 = HashWrapper<sha3::Sha3_384>;
    type Sha3_512 = HashWrapper<sha3::Sha3_512>;
}

impl Hmac for RustCrypto {
    type Sha1 = HmacWrapper<sha1::Sha1>;
    type Sha256 = HmacWrapper<sha2::Sha256>;
    type Sha384 = HmacWrapper<sha2::Sha384>;
    type Sha512 = HmacWrapper<sha2::Sha512>;
    type Sm3_256 = HmacWrapper<sm3::Sm3>;
    type Sha3_256 = HmacWrapper<sha3::Sha3_256>;
    type Sha3_384 = HmacWrapper<sha3::Sha3_384>;
    type Sha3_512 = HmacWrapper<sha3::Sha3_512>;
}

impl Symmetric for RustCrypto {
    type Aes128 = AesKey<aes::Aes128>;
    type Aes192 = AesKey<aes::Aes192>;
    type Aes256 = AesKey<aes::Aes256>;
    type Sm4_128 = AesKey<sm4::Sm4>;
    type Camellia128 = AesKey<camellia::Camellia128>;
    type Camellia192 = AesKey<camellia::Camellia192>;
    type Camellia256 = AesKey<camellia::Camellia256>;
}

impl Cmac for RustCrypto {
    type Aes128 = CmacWrapper<aes::Aes128>;
    type Aes192 = CmacWrapper<aes::Aes192>;
    type Aes256 = CmacWrapper<aes::Aes256>;
    type Sm4_128 = CmacWrapper<sm4::Sm4>;
    type Camellia128 = CmacWrapper<camellia::Camellia128>;
    type Camellia192 = CmacWrapper<camellia::Camellia192>;
    type Camellia256 = CmacWrapper<camellia::Camellia256>;
}

#[cfg(feature = "rsa")]
impl Rsa for RustCrypto {
    type Rsa1024 = RsaKeyWrapper<128, 64>;
    type Rsa2048 = RsaKeyWrapper<256, 128>;
    type Rsa3072 = RsaKeyWrapper<384, 192>;
    type Rsa4096 = RsaKeyWrapper<512, 256>;
}

#[cfg(not(feature = "rsa"))]
impl Rsa for RustCrypto {
    type Rsa1024 = !;
    type Rsa2048 = !;
    type Rsa3072 = !;
    type Rsa4096 = !;
}

impl Ecc for RustCrypto {
    type NistP192 = EccCurveWrapper<p192::NistP192, 24>;
    type NistP224 = EccCurveWrapper<p224::NistP224, 28>;
    type NistP256 = EccCurveWrapper<p256::NistP256, 32>;
    type NistP384 = EccCurveWrapper<p384::NistP384, 48>;
    type NistP521 = EccCurveWrapper<p521::NistP521, 66>;
    type BNP256 = !;
    type BNP638 = !;
    type SM2P256 = EccCurveWrapper<sm2::Sm2, 32>;
    type BpP256R1 = !;
    type BpP384R1 = !;
    type BpP512R1 = !;
    type Ed25519 = ed25519::Ed25519Wrapper;
    type Ed448 = !;
    type X25519 = x25519::X25519Wrapper;
    type X448 = !;
}

impl tpm2::crypto::backend::Mldsa for RustCrypto {
    type Mldsa44 = mldsa::Mldsa44Wrapper;
    type Mldsa65 = mldsa::Mldsa65Wrapper;
    type Mldsa87 = mldsa::Mldsa87Wrapper;
}

impl tpm2::crypto::backend::Mlkem for RustCrypto {
    type Mlkem512 = mlkem::Mlkem512Wrapper;
    type Mlkem768 = mlkem::Mlkem768Wrapper;
    type Mlkem1024 = mlkem::Mlkem1024Wrapper;
}

impl Crypto for RustCrypto {
    fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        ctutils::CtEq::ct_eq(a, b).into()
    }
}

pub(crate) struct RngWrapper<'a, R: tpm2::crypto::Rng>(pub &'a mut R);

impl<'a, R: tpm2::crypto::Rng> rand_core::TryRng for RngWrapper<'a, R> {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.try_fill_bytes(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.try_fill_bytes(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let _ = self.0.fill_bytes(dst);
        Ok(())
    }
}

impl<'a, R: tpm2::crypto::Rng> rand_core::TryCryptoRng for RngWrapper<'a, R> {}
