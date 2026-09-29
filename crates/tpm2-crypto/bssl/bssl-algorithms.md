# Cryptographic Algorithm Audit: `tpm2-crypto-bssl` vs `bssl-crypto` / `bssl.rs` vs BoringSSL C

## 1. Executive Summary

This document audits the cryptographic implementations in [`crates/tpm2-crypto/bssl`](.), comparing:
1. **BoringSSL C Library (`bssl` / `bssl-sys`)**: The underlying C library and its raw FFI bindings.
2. **`bssl-crypto` & `bssl.rs` (Safe Rust Wrappers)**: Google safe Rust wrapper crate (`rust/bssl-crypto`) and local safe FFI bindings over `bssl-sys` (`src/bssl.rs`).
3. **`tpm2-crypto-bssl` (Current Crate)**: The TPM 2.0 cryptographic provider implementation in this repository.

### Key Takeaways
- **BoringSSL C supports almost all required TPM 2.0 primitives natively**, including native AES-CFB-128 (`AES_cfb128_encrypt`), AES-192, CMAC (`<openssl/cmac.h>`), HMAC-SHA1, NIST P-256/P-384/P-521 (`EC_group_p256()`, `EC_group_p384()`, `EC_group_p521()`), pre-hashed IEEE P1363 ECDSA signing/verifying (`ECDSA_sign_p1363` / `ECDSA_verify_p1363`), arbitrary EC point multiplication (`EC_POINT_mul`), and full RSA padding/encryption/signing/modpow operations.
- **`bssl-crypto` (the safe Rust wrapper) is very opinionated and intentionally restricted**: It omits CMAC, HMAC-SHA1, AES-192, AES-CFB, P-521, arbitrary EC point multiplication, RSA encryption/decryption, and only provides high-level message signing (hashing the message internally rather than accepting pre-hashed digests).
- **Safe FFI bindings in `src/bssl.rs`**: To use BoringSSL C primitives where `bssl-crypto` lacks APIs, `tpm2-crypto-bssl` enforces `#![deny(unsafe_code)]` at the crate root and `#![forbid(unsafe_code)]` on all modules except `src/bssl.rs`, which encapsulates safe RAII wrappers over `bssl-sys` for HMAC-SHA1, AES-128/192/256-CMAC, AES-128/192/256-CFB, RSASSA, RSAPSS, RSAES, RSA-OAEP, RSA-NULL, RSA Keygen, RSA Import/Export, and NIST P-256/P-384/P-521 + BN-P256 curve operations and ECDSA.
- **Completed Migrations**: SHA-1, SHA-256/384/512, HMAC-SHA1, AES-128/192/256-CMAC, AES-128/192/256-CFB, RSASSA, RSAPSS, RSAES, RSA-OAEP, RSA-NULL, RSA Keygen, RSA Import/Export, NIST P-256/P-384/P-521, and BN-P256 now all use BoringSSL (`bssl-crypto` or `bssl-sys` via `src/bssl.rs`), completely eliminating the RustCrypto `sha1`, `sha2`, `hmac`, `cmac`, `aes`, `digest`, `p256`, `p384`, `p521`, `rsa`, and `rand` dependencies from `Cargo.toml`. Only `rand_chacha` (`ChaCha20Rng`) is used for deterministic seed expansion in RSA/ECC key derivation where BoringSSL lacks a deterministic seeded PRNG API.

---

## 2. Algorithm-by-Algorithm Audit Table

| Algorithm / Feature | TPM 2.0 Spec Requirement | BoringSSL C (`bssl` / `bssl-sys`) | `bssl-crypto` / `bssl.rs` (Safe Rust Wrappers) | Current Implementation in `tpm2-crypto-bssl` | Reason RustCrypto / Fallback is Used |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **RNG (Random)** | Generate cryptographically secure random bytes | ✅ **Supported** (`RAND_bytes`) | ✅ **Supported** (`rand_bytes`) | ✅ `bssl_crypto::rand_bytes` | N/A — `bssl-crypto` **is** used in `src/lib.rs`. |
| **SHA-1** | Incremental digest (`Update`, `Finalize`) | ✅ **Supported** (`SHA1_Init`, `SHA1_Update`, `SHA1_Final`, `EVP_sha1()`) | ✅ **Supported** (`digest::InsecureSha1`) | ✅ `bssl_crypto::digest::InsecureSha1` | N/A — `bssl-crypto` **is** used in `hash.rs`. |
| **SHA-256** | Incremental digest | ✅ **Supported** (`SHA256_*`, `EVP_sha256()`) | ✅ **Supported** (`digest::Sha256`) | ✅ `bssl_crypto::digest::Sha256` | N/A — `bssl-crypto` **is** used in `hash.rs` and seed hashing in `asymmetric.rs`. |
| **SHA-384** | Incremental digest | ✅ **Supported** (`SHA384_*`, `EVP_sha384()`) | ✅ **Supported** (`digest::Sha384`) | ✅ `bssl_crypto::digest::Sha384` | N/A — `bssl-crypto` **is** used in `hash.rs`. |
| **SHA-512** | Incremental digest | ✅ **Supported** (`SHA512_*`, `EVP_sha512()`) | ✅ **Supported** (`digest::Sha512`) | ✅ `bssl_crypto::digest::Sha512` | N/A — `bssl-crypto` **is** used in `hash.rs`. |
| **SM3-256** | Incremental digest | ❌ **Not Supported** (`OPENSSL_NO_SM3`) | ❌ **Not Supported** | ❌ Unimplemented (`!`) | Disabled in BoringSSL; not supported in crate. |
| **SHA3-{256,384,512}** | Keccak/SHA-3 digest | ❌ **Not Supported** | ❌ **Not Supported** | ❌ Unimplemented (`!`) | BoringSSL does not implement standard SHA-3 hash functions. |
| **HMAC-SHA1** | Keyed MAC with SHA-1 | ✅ **Supported** (`HMAC_Init_ex` with `EVP_sha1()`) | ✅ **Supported** (`bssl::HmacSha1` in `bssl.rs`; omitted in `bssl-crypto`) | ✅ `bssl::HmacSha1` (`bssl-sys`) | N/A — `bssl-sys` **is** used via safe wrapper in `src/bssl.rs`. |
| **HMAC-SHA256** | Keyed MAC with SHA-256 | ✅ **Supported** (`HMAC_Init_ex` with `EVP_sha256()`) | ✅ **Supported** (`hmac::HmacSha256`) | ✅ `bssl_crypto::hmac::HmacSha256` | N/A — `bssl-crypto` **is** used. |
| **HMAC-SHA384** | Keyed MAC with SHA-384 | ✅ **Supported** (`HMAC_Init_ex` with `EVP_sha384()`) | ✅ **Supported** (`hmac::HmacSha384`) | ✅ `bssl_crypto::hmac::HmacSha384` | N/A — `bssl-crypto` **is** used. |
| **HMAC-SHA512** | Keyed MAC with SHA-512 | ✅ **Supported** (`HMAC_Init_ex` with `EVP_sha512()`) | ✅ **Supported** (`hmac::HmacSha512`) | ✅ `bssl_crypto::hmac::HmacSha512` | N/A — `bssl-crypto` **is** used. |
| **HMAC-SM3 / SHA3** | Keyed MAC with SM3 or SHA3 | ❌ **Not Supported** | ❌ **Not Supported** | ❌ Unimplemented (`!`) | Underlying hash algorithms unavailable in BoringSSL. |
| **AES-128-CMAC** | Block cipher MAC | ✅ **Supported** (`<openssl/cmac.h>`: `CMAC_*` / `AES_CMAC`) | ✅ **Supported** (`bssl::CmacAes128` in `bssl.rs`; omitted in `bssl-crypto`) | ✅ `bssl::CmacAes128` (`bssl-sys`) | N/A — `bssl-sys` **is** used via safe wrapper in `src/bssl.rs`. |
| **AES-192-CMAC** | Block cipher MAC | ✅ **Supported** (`CMAC_Init` with `EVP_aes_192_cbc()`) | ✅ **Supported** (`bssl::CmacAes192` in `bssl.rs`; omitted in `bssl-crypto`) | ✅ `bssl::CmacAes192` (`bssl-sys`) | N/A — `bssl-sys` **is** used via safe wrapper in `src/bssl.rs`. |
| **AES-256-CMAC** | Block cipher MAC | ✅ **Supported** (`CMAC_Init` with `EVP_aes_256_cbc()`) | ✅ **Supported** (`bssl::CmacAes256` in `bssl.rs`; omitted in `bssl-crypto`) | ✅ `bssl::CmacAes256` (`bssl-sys`) | N/A — `bssl-sys` **is** used via safe wrapper in `src/bssl.rs`. |
| **SM4 / Camellia CMAC**| Block cipher MAC | ❌ **Not Supported** (`OPENSSL_NO_SM4`, `OPENSSL_NO_CAMELLIA`) | ❌ **Not Supported** | ❌ Unimplemented (`!`) | Disabled in BoringSSL; context types set to `!`. |
| **AES-128-CFB** | 128-bit streaming CFB mode | ✅ **Supported** (`AES_cfb128_encrypt` in `<openssl/aes.h>`) | ✅ **Supported** (`bssl::Aes128Cfb` in `bssl.rs`; omitted in `bssl-crypto`) | ✅ `bssl::Aes128Cfb` (`bssl-sys`) | N/A — `bssl-sys` **is** used via safe wrapper in `src/bssl.rs`. |
| **AES-192-CFB** | 128-bit streaming CFB mode | ✅ **Supported** (`AES_cfb128_encrypt` with 192-bit key) | ✅ **Supported** (`bssl::Aes192Cfb` in `bssl.rs`; omitted in `bssl-crypto`) | ✅ `bssl::Aes192Cfb` (`bssl-sys`) | N/A — `bssl-sys` **is** used via safe wrapper in `src/bssl.rs`. |
| **AES-256-CFB** | 128-bit streaming CFB mode | ✅ **Supported** (`AES_cfb128_encrypt` with 256-bit key) | ✅ **Supported** (`bssl::Aes256Cfb` in `bssl.rs`; omitted in `bssl-crypto`) | ✅ `bssl::Aes256Cfb` (`bssl-sys`) | N/A — `bssl-sys` **is** used via safe wrapper in `src/bssl.rs`. |
| **SM4 / Camellia Sym** | Block cipher symmetric encryption/decryption | ❌ **Not Supported** (`OPENSSL_NO_SM4`, `OPENSSL_NO_CAMELLIA`) | ❌ **Not Supported** | ❌ Unimplemented (`!`) | Disabled in BoringSSL; context types set to `!`. |
| **RSASSA (PKCS#1 v1.5)** | Sign/verify pre-hashed digest | ✅ **Supported** (`RSA_sign`, `RSA_verify` taking pre-hashed digest and hash NID) | ✅ **Supported** (`bssl::rsa_sign_pkcs1v15`, `bssl::rsa_verify_pkcs1v15` in `bssl.rs`) | ✅ `bssl::rsa_*_pkcs1v15` (`bssl-sys`) | N/A — `bssl-sys` **is** used via safe wrapper in `src/bssl.rs`. |
| **RSAPSS** | Sign/verify pre-hashed digest with configurable salt | ✅ **Supported** (`RSA_sign_pss_mgf1`, `RSA_verify_pss_mgf1` with `RSA_PSS_SALTLEN_DIGEST` / `RSA_PSS_SALTLEN_AUTO`) | ✅ **Supported** (`bssl::rsa_sign_pss`, `bssl::rsa_verify_pss` in `bssl.rs`) | ✅ `bssl::rsa_*_pss` (`bssl-sys`) | N/A — `bssl-sys` **is** used via safe wrapper in `src/bssl.rs`. |
| **RSAES (PKCS#1 v1.5)** | Asymmetric encryption/decryption | ✅ **Supported** (`RSA_encrypt`, `RSA_decrypt` with `RSA_PKCS1_PADDING`) | ✅ **Supported** (`bssl::rsa_encrypt_pkcs1v15`, `bssl::rsa_decrypt_pkcs1v15` in `bssl.rs`) | ✅ `bssl::rsa_*_pkcs1v15` (`bssl-sys`) | N/A — `bssl-sys` **is** used via safe wrapper in `src/bssl.rs`. |
| **RSA-OAEP** | Asymmetric encryption/decryption with label and custom hash | ✅ **Supported** (`EVP_PKEY_encrypt`/`decrypt` with OAEP MD, MGF1 MD, and label) | ✅ **Supported** (`bssl::rsa_encrypt_oaep`, `bssl::rsa_decrypt_oaep` in `bssl.rs`) | ✅ `bssl::rsa_*_oaep` (`bssl-sys`) | N/A — `bssl-sys` **is** used via safe wrapper in `src/bssl.rs`. |
| **RSA-NULL** | Raw modular exponentiation ($c = m^e \pmod n$) | ✅ **Supported** (`RSA_encrypt` / `RSA_decrypt` with `RSA_NO_PADDING`) | ✅ **Supported** (`bssl::rsa_encrypt_null`, `bssl::rsa_decrypt_null` in `bssl.rs`) | ✅ `bssl::rsa_*_null` (`bssl-sys`) | N/A — `bssl-sys` **is** used via safe wrapper in `src/bssl.rs`. |
| **RSA Keygen** | 1024/2048/3072/4096-bit, deterministic from seed | ⚠️ **Partial** (`RSA_generate_key_ex` supports any bits with random RNG, but lacks deterministic seed PRNG) | ⚠️ **Partial** (`bssl-crypto` only supports random 2048–4096; `bssl.rs` uses `RSA_generate_key_ex` + `BN_primality_test` with `rand_chacha`) | ⚠️ `bssl::rsa_generate_key` (`bssl-sys` + `rand_chacha`) | BoringSSL C lacks deterministic seeded PRNG API; `rand_chacha::ChaCha20Rng` expands the seed while `bssl-sys` (`BN_primality_test`, `RSA_new_private_key`) performs prime search and key construction. |
| **RSA Import / Export** | Import from $(n, p, e)$, export prime $p$ | ✅ **Supported** (`RSA_new_private_key`, `RSA_get0_p`, `BN_div`, `BN_primality_test`, `BN_mod_inverse`) | ✅ **Supported** (`bssl::rsa_import_private_key`, `bssl::rsa_private_key_to_prime_p` in `bssl.rs`) | ✅ `bssl::rsa_import_private_key`, `bssl::rsa_private_key_to_prime_p` (`bssl-sys`) | N/A — `bssl-sys` **is** used via safe wrapper in `src/bssl.rs`. |
| **NIST P-256 Validation** | Validate point lies on curve | ✅ **Supported** (`EC_POINT_set_affine_coordinates_GFp` + `EC_POINT_is_on_curve`) | ✅ **Supported** (`bssl::ec_validate_point` in `bssl.rs`) | ✅ `bssl::ec_validate_point` (`bssl-sys`) | N/A — `bssl-sys` **is** used via safe wrapper in `src/bssl.rs`. |
| **NIST P-256 Point Mult (Generator)** | $P = d \cdot G$ | ✅ **Supported** (`EC_POINT_mul`) | ✅ **Supported** (`bssl::ec_point_multiply_generator` in `bssl.rs`) | ✅ `bssl::ec_point_multiply_generator` (`bssl-sys`) | N/A — `bssl-sys` **is** used via safe wrapper in `src/bssl.rs`. |
| **NIST P-256 Point Mult (Arbitrary)** | $R = d \cdot Q$, returns $(x, y)$ | ✅ **Supported** (`EC_POINT_mul` + `EC_POINT_get_affine_coordinates_GFp`) | ✅ **Supported** (`bssl::ec_point_multiply` in `bssl.rs`) | ✅ `bssl::ec_point_multiply` (`bssl-sys`) | N/A — `bssl-sys` **is** used via safe wrapper in `src/bssl.rs`. |
| **NIST P-256 ECDSA** | Sign/verify pre-hashed digest, raw IEEE P1363 $(r, s)$ | ✅ **Supported** (`ECDSA_sign_p1363`, `ECDSA_verify_p1363` take pre-hashed digest) | ✅ **Supported** (`bssl::ecdsa_sign`, `bssl::ecdsa_verify` in `bssl.rs`) | ✅ `bssl::ecdsa_*` (`bssl-sys`) | N/A — `bssl-sys` **is** used via safe wrapper in `src/bssl.rs`. |
| **NIST P-256 Keygen** | Generate key deterministically from seed | ⚠️ **Partial** (`EC_KEY_generate_key` uses internal RNG; lacks deterministic seed PRNG) | ⚠️ **Partial** (`bssl-crypto` only supports random keygen; `bssl.rs` uses `EC_POINT_mul` with `rand_chacha`) | ⚠️ `bssl::ec_generate_key` (`bssl-sys` + `rand_chacha`) | BoringSSL C lacks deterministic seeded keygen API; `rand_chacha::ChaCha20Rng` generates candidate scalars while `bssl-sys` (`EC_POINT_mul`) computes the public key. |
| **NIST P-384** | All curve operations (validation, mult, ECDSA, keygen) | ⚠️ **Partial** (`EC_group_p384()`, `EC_POINT_*`, `ECDSA_*` supported; keygen lacks seeded PRNG) | ⚠️ **Partial** (`EcGroup::P384` in `bssl.rs` + `rand_chacha` for seeded keygen) | ⚠️ `bssl::*` with `EcGroup::P384` (`bssl-sys` + `rand_chacha` for seeded keygen) | `bssl-sys` is used for all curve/ECDSA operations; `rand_chacha` is used for deterministic seeded keygen. |
| **NIST P-521** | All curve operations (validation, mult, ECDSA, keygen) | ⚠️ **Partial** (`EC_group_p521()`, `EC_POINT_*`, `ECDSA_*` supported; keygen lacks seeded PRNG) | ⚠️ **Partial** (`EcGroup::P521` in `bssl.rs` + `rand_chacha` for seeded keygen) | ⚠️ `bssl::*` with `EcGroup::P521` (`bssl-sys` + `rand_chacha` for seeded keygen) | `bssl-sys` is used for all curve/ECDSA operations; `rand_chacha` is used for deterministic seeded keygen. |
| **BN-P256** | Barreto-Naehrig curve ($y^2 = x^3 + 3 \pmod p$) | ⚠️ **Partial** (No built-in BN-P256 curve group/NID; requires custom group via `EC_GROUP_new_curve_GFp` + `EC_GROUP_set_generator`) | ⚠️ **Partial** (Omitted in `bssl-crypto`; `bssl.rs` constructs custom `EcGroup::BnP256` + `rand_chacha` for seeded keygen) | ⚠️ `bssl::*` with `EcGroup::BnP256` (`bssl-sys` + `rand_chacha` for seeded keygen) | BoringSSL C has no built-in BN-P256 constant group or seeded PRNG; `src/bssl.rs` constructs a custom `EC_GROUP` and uses `rand_chacha` for seeded keygen. |

---

## 3. Detailed Component Analysis

### 3.1 Random Number Generation (`src/lib.rs`)
- **Current State**: Implements `tpm2::crypto::Rng` on `BsslCryptoProvider` using `bssl_crypto::rand_bytes(dest)`.
- **C BoringSSL vs `bssl-crypto`**:
  - BoringSSL C provides `RAND_bytes` in `<openssl/rand.h>`.
  - `bssl-crypto` safely exposes this as `bssl_crypto::rand_bytes`.
  - Used directly with zero RustCrypto fallback.

### 3.2 Hash & HMAC (`src/hash.rs`, `src/bssl.rs`)
- **Current State**:
  - `BsslSha1`, `BsslSha256`, `BsslSha384`, `BsslSha512` use `bssl_crypto::digest` (`InsecureSha1`, `Sha256`, `Sha384`, `Sha512`).
  - `BsslHmacSha256`, `BsslHmacSha384`, `BsslHmacSha512` use `bssl_crypto::hmac`.
  - `BsslHmacSha1` uses `crate::bssl::HmacSha1`, a safe wrapper in `src/bssl.rs` over `bssl_sys::HMAC_CTX` and `bssl_sys::EVP_sha1()`.
  - Unsupported hash algorithms (SM3-256, SHA3-256, SHA3-384, SHA3-512) bind their context types to `!`.

### 3.3 CMAC (`src/cmac.rs`, `src/bssl.rs`)
- **Current State**: Uses safe wrappers `crate::bssl::{CmacAes128, CmacAes192, CmacAes256}` over BoringSSL's `bssl_sys::CMAC_CTX` (`<openssl/cmac.h>`) with `EVP_aes_128_cbc()`, `EVP_aes_192_cbc()`, and `EVP_aes_256_cbc()`. Context types for SM4 and Camellia are bound to `!`.

### 3.4 Symmetric Ciphers & CFB Mode (`src/symmetric.rs`, `src/bssl.rs`)
- **Current State**:
  - Uses safe wrappers `crate::bssl::{Aes128Cfb, Aes192Cfb, Aes256Cfb}` over BoringSSL's `bssl_sys::AES_set_encrypt_key` and `bssl_sys::AES_cfb128_encrypt`.
  - Supports streaming in-place CFB-128 encryption/decryption and reconstructs exact TPM 2.0 feedback output IVs (`iv_out`) for both block-aligned and partial-block inputs.
  - Unsupported symmetric ciphers (SM4, Camellia) bind their context types to `!`.

### 3.5 Asymmetric RSA (`src/asymmetric.rs`, `src/bssl.rs`)
- **Current State**:
  - **RSASSA (PKCS#1 v1.5)**: Implemented via safe wrapper `rsa_sign_pkcs1v15` / `rsa_verify_pkcs1v15` in `src/bssl.rs` using `RSA_sign` and `RSA_verify`.
  - **RSAPSS**: Implemented via safe wrapper `rsa_sign_pss` / `rsa_verify_pss` in `src/bssl.rs` using `RSA_sign_pss_mgf1` (`RSA_PSS_SALTLEN_DIGEST`) and `RSA_verify_pss_mgf1` (`RSA_PSS_SALTLEN_DIGEST` with fallback to `RSA_PSS_SALTLEN_AUTO` for maximal salt compatibility).
  - **RSAES (PKCS#1 v1.5)**: Implemented via safe wrapper `rsa_encrypt_pkcs1v15` / `rsa_decrypt_pkcs1v15` in `src/bssl.rs` using `RSA_encrypt` and `RSA_decrypt` with `RSA_PKCS1_PADDING`.
  - **RSA-OAEP**: Implemented via safe wrapper `rsa_encrypt_oaep` / `rsa_decrypt_oaep` in `src/bssl.rs` using `EVP_PKEY_encrypt` / `EVP_PKEY_decrypt` with `RSA_PKCS1_OAEP_PADDING`, OAEP MD, MGF1 MD, and label ownership via `EVP_PKEY_CTX_set0_rsa_oaep_label`.
  - **RSA-NULL**: Implemented via safe wrapper `rsa_encrypt_null` / `rsa_decrypt_null` in `src/bssl.rs` using `RSA_encrypt` / `RSA_decrypt` with `RSA_NO_PADDING` after validating $m < n$ via `BIGNUM`.
  - **RSA Import / Export**: Implemented via `rsa_import_private_key` (which computes $q = n/p$, checks primality of $p$ and $q$ via `BN_primality_test`, derives CRT parameters via `BN_*` arithmetic, constructs `RSA_new_private_key`, and serializes to PKCS#8 DER via `CBB` + `EVP_marshal_private_key`) and `rsa_private_key_to_prime_p` (`RSA_get0_p`).
  - **RSA Key Generation (`rsa_generate_key`)**: Implemented in `src/bssl.rs`:
    - **Random keygen (`seed: None`)**: Uses BoringSSL's `bssl_sys::RSA_generate_key_ex` directly for 1024, 2048, 3072, and 4096-bit keys.
    - **Deterministic seeded keygen (`seed: Some(...)`)**: Uses `bssl_crypto::digest::Sha256` and `rand_chacha::ChaCha20Rng` to expand the seed into a deterministic byte stream, and uses `bssl-sys` (`Bignum`, `BN_mod_word`, `BN_primality_test` with trial division, `RSA_new_private_key`, and `EVP_marshal_private_key`) to generate primes $p$ and $q$, compute CRT parameters ($d, dmp1, dmq1, iqmp$), and export the PKCS#8 DER key.

### 3.6 ECC Curves: NIST P-256, P-384, P-521, BN-P256 (`src/ecc.rs`, `src/asymmetric.rs`, `src/bssl.rs`)
- **Current State**:
  - **NIST P-256, P-384, P-521**: All operations (point validation `ec_validate_point`, generator multiplication `ec_point_multiply_generator`, arbitrary point multiplication `ec_point_multiply`, pre-hashed IEEE P1363 ECDSA signing/verification `ecdsa_sign`/`ecdsa_verify`, and deterministic/random key generation `ec_generate_key`) are implemented in `src/bssl.rs` using BoringSSL's `EC_group_p256()`, `EC_group_p384()`, `EC_group_p521()`, `EC_POINT_mul`, `EC_POINT_get_affine_coordinates_GFp`, `ECDSA_sign_p1363`, and `ECDSA_verify_p1363`.
  - **BN-P256**: Implemented 100% via BoringSSL's custom curve APIs (`EC_GROUP_new_curve_GFp` and `EC_GROUP_set_generator`) backed by `EC_GFp_mont_method()` in `src/bssl.rs` (`EcGroup::BnP256` with scoped RAII `EcGroupHandle`). Supports point validation, generator multiplication, arbitrary point multiplication, ECDSA signing/verification, and key generation.

---

## 4. Action Items & Completed Migrations

1. **Migrate SHA-1 and SHA-256/384/512 to `bssl-crypto`** *(Completed)*:
   - Replaced `sha1` and `sha2` with `bssl_crypto::digest` (`InsecureSha1`, `Sha256`, `Sha384`, `Sha512`).
2. **Migrate HMAC-SHA1, AES-CMAC, and AES-CFB to `bssl-sys` Safe Bindings** *(Completed)*:
   - Added safe RAII wrappers in `src/bssl.rs` over `bssl-sys`: `HmacSha1`, `CmacAes128`, `CmacAes192`, `CmacAes256`, `Aes128Cfb`, `Aes192Cfb`, and `Aes256Cfb`.
3. **Migrate RSASSA, RSAPSS, RSAES, RSA-OAEP, RSA-NULL, and RSA Import/Export to `bssl-sys` Safe Bindings** *(Completed)*:
   - Added safe RAII wrappers (`RsaKey`, `EvpPkey`, `EvpPkeyCtx`, `Bignum`, `BnCtx`, `ScopedBsslBuffer`) and functions (`rsa_sign_pkcs1v15`, `rsa_verify_pkcs1v15`, `rsa_sign_pss`, `rsa_verify_pss`, `rsa_encrypt_pkcs1v15`, `rsa_decrypt_pkcs1v15`, `rsa_encrypt_oaep`, `rsa_decrypt_oaep`, `rsa_encrypt_null`, `rsa_decrypt_null`, `rsa_import_private_key`, `rsa_private_key_to_prime_p`) in `src/bssl.rs`.
4. **Migrate NIST P-256, P-384, and P-521 (Curve Operations, Point Mult, ECDSA, Keygen) to `bssl-sys` Safe Bindings** *(Completed)*:
   - Added safe RAII wrappers (`EcGroup`, `EcPoint`, `EcKey`) and functions (`ec_validate_point`, `ec_point_multiply_generator`, `ec_point_multiply`, `ecdsa_sign`, `ecdsa_verify`, `ec_generate_key`) in `src/bssl.rs`.
   - Removed `p256`, `p384`, `p521`, `digest`, and `rand` dependencies from `Cargo.toml`.
5. **Migrate RSA Keygen and BN-P256 to `bssl-sys` Safe Bindings** *(Completed)*:
   - Implemented `rsa_generate_key` in `src/bssl.rs` using `RSA_generate_key_ex` for random keys and `ChaCha20Rng` + `BN_primality_test` + `RSA_new_private_key` for deterministic seeded keys.
   - Implemented `EcGroup::BnP256` in `src/bssl.rs` using `EC_GROUP_new_curve_GFp` and `EC_GROUP_set_generator` with scoped RAII `EcGroupHandle`.
   - Completely removed `rsa` dependency from `Cargo.toml`.
