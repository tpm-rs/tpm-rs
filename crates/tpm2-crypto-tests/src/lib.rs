//! # Shared test suite for `tpm2::crypto` backends
//!
//! This crate holds backend-agnostic tests for the cryptography traits in
//! [`tpm2::crypto`]. Every test is a generic function (like
//! [`hash::sha256_kat`]) taking a backend and the backend's [`Caps`], and the
//! [`backend_tests!`] macro instantiates one `#[test]` per function for a
//! concrete backend. Tests checking that two backends agree with each other
//! live in [`cross`] and are instantiated with [`cross_backend_tests!`].
//!
//! ## Running
//!
//! Each backend is enabled with a (non-exclusive) Cargo feature:
//!
//! | Feature | Backend | Tests |
//! |---------|---------|-------|
//! | `rustcrypto` (default) | `tpm2_rustcrypto::RustCrypto` | `tests/rustcrypto.rs` |
//! | `libcrux` (default) | `tpm2_libcrux::Libcrux` | `tests/libcrux.rs` |
//! | `boringssl` (default) | `tpm2_boringssl::BoringSsl` | `tests/boringssl.rs` |
//!
//! Every pair of enabled backends is also checked for agreement in
//! `tests/cross.rs`:
//!
//! ```text
//! cargo test -p tpm2-crypto-tests --features rustcrypto,libcrux,boringssl
//! ```
//!
//! ## Unsupported algorithms
//!
//! Backends return [`CryptoError::Unsupported`] for algorithms, modes, key
//! sizes, and parameter sets they don't implement. So that a test can never
//! pass just because a backend supports nothing, each backend declares what
//! it supports in a [`Caps`] (see [`backends`]), and every test checks each
//! algorithm (or parameter set, ...) against it:
//!
//! - If the [`Caps`] says the algorithm is supported, the operation must
//!   succeed and produce the right result.
//! - Otherwise, the operation must fail with exactly
//!   [`CryptoError::Unsupported`], and the rest of the test is skipped for
//!   that algorithm. An operation that unexpectedly *succeeds* also fails the
//!   test, which keeps every [`Caps`] accurate.
//!
//! ## Test vectors
//!
//! Known answers come from published sources where possible. All vectors were
//! also checked against independent implementations (Python `hashlib`/`hmac`,
//! OpenSSL, and pyca/cryptography) when they were added:
//!
//! - Hash: FIPS 180-2, GB/T 32905 (SM3), and FIPS 202 examples (`""`,
//!   `"abc"`, the 448-bit message, and one million `'a'`).
//! - HMAC: the RFC 4231 test cases (and RFC 2202 for SHA-1), applied to every
//!   hash algorithm.
//! - CMAC and block cipher modes: NIST SP 800-38B and SP 800-38A for AES (the
//!   same keys and data are used for SM4 and Camellia). `ivOut` follows the
//!   TPM reference implementation (`CryptSym.c`).
//! - KDFa/KDFe: computed from TPM 2.0 Part 1, Section 11.4.10.
//! - RSA: fixed keys generated with pyca/cryptography; PKCS#1 v1.5 and PSS
//!   signatures computed with Python big-integer arithmetic (and verified with
//!   pyca/cryptography), and OAEP/RSAES ciphertexts produced by
//!   pyca/cryptography.
//! - ECC: RFC 5903 (ECDH) and RFC 6979 (ECDSA) for NIST P-256; vectors for
//!   the other curves were computed with Python big-integer arithmetic (and
//!   checked against OpenSSL).
//! - ML-KEM and ML-DSA: the NIST ACVP FIPS 203/204 vectors from
//!   `AcvpKatData.cs` (generated from ACVP-Server commit `ad33b3d9`). Each
//!   vector records its ACVP test group (`tgId`) and test case (`tcId`).
//!
//! The ML-DSA tests additionally compute `µ` with an independent SHAKE256
//! (the [`sha3`] crate) to check [`Mldsa::mu_start`], external-`µ` signing,
//! and the HashML-DSA encoding (via [`pre_hash_oid`]).
//!
//! [`Mldsa::mu_start`]: tpm2::crypto::Mldsa::mu_start
//! [`pre_hash_oid`]: tpm2::crypto::pre_hash_oid
//!
//! ## Adding a backend
//!
//! 1. Add an optional dependency and a feature for it in `Cargo.toml`.
//! 2. Describe what it supports with a [`Caps`] constant in [`backends`].
//! 3. Add `tests/<backend>.rs` invoking [`backend_tests!`], and add the new
//!    pairs to `tests/cross.rs`.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use core::fmt;

use tpm2::{
    AlgSym, TpmEccCurve, TpmiAlgCipherMode, TpmiAlgHash, TpmiMldsaParms, TpmiMlkemParms,
    TpmiRsaKeyBits, crypto::CryptoError,
};

pub mod cmac;
pub mod constant_time;
pub mod cross;
pub mod ecc;
pub mod hash;
pub mod hmac;
pub mod kdf;
pub mod mldsa;
pub mod mlkem;
pub mod rng;
pub mod rsa;
pub mod signing;
pub mod symmetric;
mod util;
mod vectors;

/// The algorithms, modes, key sizes, and parameter sets a backend supports.
///
/// Anything not listed must make the backend return
/// [`CryptoError::Unsupported`] (see the [crate docs](crate#unsupported-algorithms)).
/// Start from [`Caps::ALL`] and remove what a backend doesn't support.
#[derive(Clone, Copy, Debug)]
pub struct Caps {
    /// Hash algorithms of [`Hash`](tpm2::crypto::Hash) (also used by KDFe).
    pub hash: &'static [TpmiAlgHash],
    /// Hash algorithms of [`Hmac`](tpm2::crypto::Hmac) (also used by KDFa and
    /// HMAC signatures).
    pub hmac: &'static [TpmiAlgHash],
    /// Block ciphers of [`Cmac`](tpm2::crypto::Cmac).
    pub cmac: &'static [AlgSym],
    /// Block ciphers of [`Symmetric`](tpm2::crypto::Symmetric).
    pub symmetric: &'static [AlgSym],
    /// Modes of [`Symmetric`](tpm2::crypto::Symmetric), for every cipher in
    /// [`Caps::symmetric`].
    pub modes: &'static [TpmiAlgCipherMode],
    /// RSA key sizes of [`Rsa`](tpm2::crypto::Rsa).
    pub rsa: &'static [TpmiRsaKeyBits],
    /// Raw RSA encryption ([`RsaEncryptScheme::Raw`](tpm2::crypto::RsaEncryptScheme::Raw)).
    pub rsa_raw: bool,
    /// RSAES-PKCS1-v1_5 encryption.
    pub rsaes: bool,
    /// Hash algorithms of RSAES-OAEP encryption.
    pub oaep: &'static [TpmiAlgHash],
    /// Hash algorithms of RSASSA-PKCS1-v1_5 signatures.
    pub rsassa: &'static [TpmiAlgHash],
    /// Hash algorithms of RSASSA-PSS signatures.
    pub rsapss: &'static [TpmiAlgHash],
    /// ECC curves of [`Ecc`](tpm2::crypto::Ecc). Only short Weierstrass
    /// curves are tested; see [`ecc::CURVES`].
    pub curves: &'static [TpmEccCurve],
    /// Hash algorithms (digest sizes) of ECDSA signatures on every curve.
    pub ecdsa: &'static [TpmiAlgHash],
    /// SM2 signatures on every curve.
    pub sm2: bool,
    /// EC-Schnorr signatures on every curve.
    pub ecschnorr: bool,
    /// ML-KEM parameter sets of [`Mlkem`](tpm2::crypto::Mlkem).
    pub mlkem: &'static [TpmiMlkemParms],
    /// ML-DSA parameter sets of [`Mldsa`](tpm2::crypto::Mldsa) (with
    /// [`MldsaMessage::Pure`](tpm2::crypto::MldsaMessage::Pure)).
    pub mldsa: &'static [TpmiMldsaParms],
    /// Hash algorithms of HashML-DSA
    /// ([`MldsaMessage::PreHash`](tpm2::crypto::MldsaMessage::PreHash)).
    pub mldsa_pre_hash: &'static [TpmiAlgHash],
    /// Signing and verifying an external `µ`
    /// ([`MldsaMessage::ExternalMu`](tpm2::crypto::MldsaMessage::ExternalMu)).
    pub mldsa_external_mu: bool,
    /// Computing `µ` with [`Mldsa::mu_start`](tpm2::crypto::Mldsa::mu_start).
    pub mldsa_mu_start: bool,
}

impl Caps {
    /// Every algorithm tested by this crate.
    pub const ALL: Self = Self {
        hash: util::HASHES,
        hmac: util::HASHES,
        cmac: util::CIPHERS,
        symmetric: util::CIPHERS,
        modes: util::MODES,
        rsa: util::RSA_KEY_BITS,
        rsa_raw: true,
        rsaes: true,
        oaep: util::HASHES,
        rsassa: util::HASHES,
        rsapss: util::HASHES,
        curves: ecc::CURVES,
        ecdsa: util::HASHES,
        sm2: true,
        ecschnorr: true,
        mlkem: util::MLKEM,
        mldsa: util::MLDSA,
        mldsa_pre_hash: util::HASHES,
        mldsa_external_mu: true,
        mldsa_mu_start: true,
    };
}

/// Checks `result` against whether `what` is expected to be `supported`,
/// returning the value only if it is.
///
/// Panics if a supported operation fails, or if an unsupported operation does
/// anything other than fail with [`CryptoError::Unsupported`].
#[track_caller]
pub(crate) fn expect_support<T>(
    supported: bool,
    what: impl fmt::Display,
    result: Result<T, CryptoError>,
) -> Option<T> {
    match (supported, result) {
        (true, Ok(value)) => Some(value),
        (true, Err(err)) => panic!("{what}: expected to be supported, got Err({err:?})"),
        (false, Err(CryptoError::Unsupported)) => None,
        (false, Err(err)) => panic!("{what}: expected Err(Unsupported), got Err({err:?})"),
        (false, Ok(_)) => {
            panic!(
                "{what}: expected Err(Unsupported), but it succeeded (update the backend's Caps)"
            )
        }
    }
}

/// Unwraps the result of an operation that must succeed.
pub(crate) trait Check<T> {
    /// Returns the value, or panics with `what` and the error.
    fn check(self, what: impl fmt::Display) -> T;
}

impl<T> Check<T> for Result<T, CryptoError> {
    #[track_caller]
    fn check(self, what: impl fmt::Display) -> T {
        match self {
            Ok(value) => value,
            Err(err) => panic!("{what}: unexpected Err({err:?})"),
        }
    }
}

/// The expected [`Caps`] of each backend.
pub mod backends {
    #[cfg(any(feature = "rustcrypto", feature = "libcrux", feature = "boringssl"))]
    use super::Caps;
    #[cfg(feature = "boringssl")]
    use tpm2::TpmiMlkemParms;
    #[cfg(any(feature = "libcrux", feature = "boringssl"))]
    use tpm2::{AlgSym, TpmEccCurve, TpmiAlgHash};

    /// [`Caps`] of `tpm2_rustcrypto::RustCrypto`: everything except the NIST
    /// P-192/P-224, BN, and Brainpool curves.
    #[cfg(feature = "rustcrypto")]
    pub const RUSTCRYPTO: Caps = Caps {
        curves: &[
            tpm2::TpmEccCurve::NistP256,
            tpm2::TpmEccCurve::NistP384,
            tpm2::TpmEccCurve::NistP521,
            tpm2::TpmEccCurve::SM2P256,
        ],
        ..Caps::ALL
    };

    /// [`Caps`] of `tpm2_libcrux::Libcrux`: SHA-1/2, AES, RSA (with SHA-1/2),
    /// NIST P-256/P-384/P-521 (with ECDSA), ML-KEM, and pure/pre-hash ML-DSA.
    #[cfg(feature = "libcrux")]
    pub const LIBCRUX: Caps = {
        const SHA1_SHA2: &[TpmiAlgHash] = &[
            TpmiAlgHash::Sha1,
            TpmiAlgHash::Sha256,
            TpmiAlgHash::Sha384,
            TpmiAlgHash::Sha512,
        ];
        const AES: &[AlgSym] = &[AlgSym::Aes128, AlgSym::Aes192, AlgSym::Aes256];
        Caps {
            hash: SHA1_SHA2,
            hmac: SHA1_SHA2,
            cmac: AES,
            symmetric: AES,
            oaep: SHA1_SHA2,
            rsassa: SHA1_SHA2,
            rsapss: SHA1_SHA2,
            curves: &[
                TpmEccCurve::NistP256,
                TpmEccCurve::NistP384,
                TpmEccCurve::NistP521,
            ],
            sm2: false,
            ecschnorr: false,
            mldsa_external_mu: false,
            mldsa_mu_start: false,
            ..Caps::ALL
        }
    };

    /// [`Caps`] of `tpm2_boringssl::BoringSsl`: SHA-1/2, AES, RSA (with
    /// SHA-1/2), NIST P-256/P-384/P-521 (with ECDSA), ML-KEM-768/1024, and
    /// pure, external-`µ` and streaming-`µ` ML-DSA.
    #[cfg(feature = "boringssl")]
    pub const BORINGSSL: Caps = {
        const SHA1_SHA2: &[TpmiAlgHash] = &[
            TpmiAlgHash::Sha1,
            TpmiAlgHash::Sha256,
            TpmiAlgHash::Sha384,
            TpmiAlgHash::Sha512,
        ];
        const AES: &[AlgSym] = &[AlgSym::Aes128, AlgSym::Aes192, AlgSym::Aes256];
        Caps {
            hash: SHA1_SHA2,
            hmac: SHA1_SHA2,
            cmac: AES,
            symmetric: AES,
            oaep: SHA1_SHA2,
            rsassa: SHA1_SHA2,
            rsapss: SHA1_SHA2,
            curves: &[
                TpmEccCurve::NistP256,
                TpmEccCurve::NistP384,
                TpmEccCurve::NistP521,
            ],
            sm2: false,
            ecschnorr: false,
            mlkem: &[TpmiMlkemParms::Mlkem768, TpmiMlkemParms::Mlkem1024],
            mldsa_pre_hash: &[],
            ..Caps::ALL
        }
    };
}

/// Instantiates one `#[test]` per test function in this crate for a backend.
///
/// `$name` is the name of the generated module, `$backend` an expression
/// creating the backend, and `$caps` its [`Caps`]. The expressions are
/// evaluated inside nested modules, so they should use absolute paths (or
/// items imported into the invoking module).
///
/// ```ignore
/// tpm2_crypto_tests::backend_tests!(
///     rustcrypto,
///     tpm2_rustcrypto::RustCrypto,
///     tpm2_crypto_tests::backends::RUSTCRYPTO,
/// );
/// ```
#[macro_export]
macro_rules! backend_tests {
    ($name:ident, $backend:expr, $caps:expr $(,)?) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            $crate::__module_tests!(
                $backend,
                $caps,
                hash,
                [
                    sha1_kat,
                    sha256_kat,
                    sha384_kat,
                    sha512_kat,
                    sm3_256_kat,
                    sha3_256_kat,
                    sha3_384_kat,
                    sha3_512_kat,
                    hash_streaming,
                ]
            );
            $crate::__module_tests!(
                $backend,
                $caps,
                hmac,
                [
                    hmac_sha1_kat,
                    hmac_sha256_kat,
                    hmac_sha384_kat,
                    hmac_sha512_kat,
                    hmac_sm3_256_kat,
                    hmac_sha3_256_kat,
                    hmac_sha3_384_kat,
                    hmac_sha3_512_kat,
                    hmac_streaming,
                    hmac_key_handling,
                ]
            );
            $crate::__module_tests!(
                $backend,
                $caps,
                cmac,
                [
                    cmac_aes128_kat,
                    cmac_aes192_kat,
                    cmac_aes256_kat,
                    cmac_sm4_128_kat,
                    cmac_camellia128_kat,
                    cmac_camellia192_kat,
                    cmac_camellia256_kat,
                    cmac_streaming,
                ]
            );
            $crate::__module_tests!(
                $backend,
                $caps,
                symmetric,
                [
                    aes128_kat,
                    aes192_kat,
                    aes256_kat,
                    sm4_128_kat,
                    camellia128_kat,
                    camellia192_kat,
                    camellia256_kat,
                    symmetric_chaining,
                    symmetric_partial_blocks,
                    symmetric_empty_data,
                ]
            );
            $crate::__module_tests!($backend, $caps, kdf, [kdfa_kat, kdfe_kat]);
            $crate::__module_tests!(
                $backend,
                $caps,
                rng,
                [
                    rng_system,
                    rng_seeded_deterministic,
                    rng_seeded_seed_sensitivity,
                    rng_reseed,
                    rng_byte_distribution,
                ]
            );
            $crate::__module_tests!(
                $backend,
                $caps,
                constant_time,
                [constant_time_eq, digest_eq,]
            );
            $crate::__module_tests!(
                $backend,
                $caps,
                rsa,
                [
                    rsa_load_fixed_keys,
                    rsa_load_rejects_invalid,
                    rsa_raw_kat,
                    rsa_decrypt_kat,
                    rsa_encrypt_decrypt,
                    rsa_encrypt_rejects_invalid,
                    rsa_decrypt_rejects_invalid,
                    rsa_generate_key,
                    rsa_generate_key_deterministic,
                ]
            );
            $crate::__module_tests!(
                $backend,
                $caps,
                ecc,
                [
                    ecc_generate_and_load,
                    ecc_load_rejects_invalid,
                    ecdh_agreement,
                    ecdh_kat,
                    ecc_generate_key_deterministic,
                ]
            );
            $crate::__module_tests!(
                $backend,
                $caps,
                signing,
                [
                    rsassa_kat,
                    rsapss_verify_kat,
                    rsa_sign_verify,
                    rsa_sign_verify_all_sizes,
                    ecdsa_verify_kat,
                    ecdsa_sign_verify,
                    sm2_sign_verify,
                    ecschnorr_sign_verify,
                    hmac_sign_verify,
                ]
            );
            $crate::__module_tests!(
                $backend,
                $caps,
                mlkem,
                [
                    mlkem_keygen_kat,
                    mlkem_roundtrip,
                    mlkem_decapsulate_rejects,
                    mlkem_load_public_rejects,
                    mlkem_load_private,
                ]
            );
            $crate::__module_tests!(
                $backend,
                $caps,
                mldsa,
                [
                    mldsa_keygen_kat,
                    mldsa_sigver_kat,
                    mldsa_pure_roundtrip,
                    mldsa_pre_hash_roundtrip,
                    mldsa_external_mu_matches_pure,
                    mldsa_mu_start_matches_reference,
                    mldsa_load_public_rejects,
                    mldsa_load_private,
                ]
            );
        }
    };
}

/// Implementation detail of [`backend_tests!`].
#[doc(hidden)]
#[macro_export]
macro_rules! __module_tests {
    ($backend:expr, $caps:expr, $module:ident, [$($test:ident),* $(,)?]) => {
        mod $module {
            #[allow(unused_imports)]
            use super::*;

            $(
                #[test]
                fn $test() {
                    $crate::$module::$test(&$backend, &$caps);
                }
            )*
        }
    };
}

/// Instantiates one `#[test]` per function in [`cross`] for a pair of
/// backends `(backend, caps)`. Each test checks both directions.
///
/// ```ignore
/// tpm2_crypto_tests::cross_backend_tests!(
///     rustcrypto_libcrux,
///     (tpm2_rustcrypto::RustCrypto, tpm2_crypto_tests::backends::RUSTCRYPTO),
///     (tpm2_libcrux::Libcrux, tpm2_crypto_tests::backends::LIBCRUX),
/// );
/// ```
#[macro_export]
macro_rules! cross_backend_tests {
    ($name:ident, ($a:expr, $a_caps:expr), ($b:expr, $b_caps:expr) $(,)?) => {
        $crate::__cross_tests!(
            $name,
            ($a, $a_caps),
            ($b, $b_caps),
            [
                mlkem_keys_agree,
                mlkem_ciphertext_interop,
                mldsa_keys_agree,
                mldsa_signature_interop,
                ecdh_interop,
                ecdsa_interop,
                rsa_signature_interop,
                rsa_encryption_interop,
            ]
        );
    };
}

/// Implementation detail of [`cross_backend_tests!`].
#[doc(hidden)]
#[macro_export]
macro_rules! __cross_tests {
    ($name:ident, ($a:expr, $a_caps:expr), ($b:expr, $b_caps:expr), [$($test:ident),* $(,)?]) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            $(
                #[test]
                fn $test() {
                    $crate::cross::$test(&$a, &$a_caps, &$b, &$b_caps);
                }
            )*
        }
    };
}
