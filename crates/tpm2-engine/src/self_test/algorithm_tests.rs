//! The algorithm self tests: a port of the TCG reference implementation's `TestAlgorithm()` and
//! the tests it dispatches to (`AlgorithmTests.c`), and of `CryptSelfTest()`,
//! `CryptIncrementalSelfTest()` and `CryptRunSelfTests()` (`CryptSelfTest.c`).
//!
//! The tests are known-answer tests ([`super::vectors`]) on the crypto provider. Their algorithm
//! bookkeeping, including its idiosyncrasies (e.g. which tests also mark other algorithms as
//! tested, and that the RSA and ECC signature tests clear `TPM_ALG_NULL`/`TPM_ALG_ECDH` without
//! testing them), is that of the reference, because it is visible in the `toDoList` of
//! `TPM2_IncrementalSelfTest`. The tests that draw random values draw exactly the values the
//! reference draws: with the `reference-rng` feature, the RSAES/OAEP/PSS encodings and the ECDSA
//! signature are computed by the reference's own code on the TPM's DRBG.
//!
//! A vector is either `g_toTest` itself ([`Vector::Global`], a test of an algorithm on its first
//! use) or a local copy of the algorithms a command asked to test ([`Vector::Local`]); the
//! reference's `CLEAR_BOTH`/`SET_BOTH`/`TEST_BOTH` macros update/test both.

use tpm2::crypto::{CryptoError, CryptoProvider, Direction, HmacStream, ModeIv, SymmetricKey};
use tpm2::errors::TpmRc;
use tpm2::{Alg, AlgSym, TpmEccCurve, TpmiAlgCipherMode, TpmiAlgHash, TpmtHa};

#[cfg(feature = "reference-rng")]
use crate::reference_rng::{RefRng, ecc, rsa};

use super::vectors::*;
use super::{ALG_FIRST, ALG_LAST, AlgorithmVector, SelfTestState, Tested, default_test_hash};

/// `SYM_MODE_FIRST`/`SYM_MODE_LAST`: the block cipher modes `TPM_ALG_CTR..=TPM_ALG_ECB`.
const SYM_MODES: core::ops::RangeInclusive<u16> = 0x0040..=0x0044;

/// The size of the test RSA key (`RSA_TEST_KEY_SIZE`).
const RSA_TEST_KEY_SIZE: usize = 256;
/// The public exponent of the test RSA key (the default exponent, `RsaKeyInitialize()`).
const RSA_TEST_EXPONENT: u32 = 65537;
/// The OAEP label of the RSA tests (`OAEP_TEST_STRING`, a `TPM2B_STRING` including the NUL).
const OAEP_TEST_LABEL: &[u8] = b"OAEP Test Value\0";
/// The curve of the ECC tests (`c_testCurve`).
const TEST_CURVE: TpmEccCurve = TpmEccCurve::NistP256;

/// An algorithm ID.
const fn id(alg: Alg) -> u16 {
    alg.id()
}

/// A symmetric test vector (`SYMMETRIC_TEST_VECTOR` of `c_symTestValues`).
struct SymTestVector {
    alg: u16,
    key_alg: AlgSym,
    key: &'static [u8],
    data_in: &'static [u8; 32],
    /// The ciphertexts in mode order `CTR, OFB, CBC, CFB, ECB`.
    data_out: [&'static [u8; 32]; 5],
}

/// `c_symTestValues`: AES-128 and AES-256, the AES key sizes of the TCG reference profile (a
/// vector is skipped if [`SymmetricKey::new`] fails, i.e. the key size is not implemented).
const SYM_TEST_VALUES: [SymTestVector; 2] = [
    SymTestVector {
        alg: id(Alg::AES),
        key_alg: AlgSym::Aes128,
        key: &AES128_KEY,
        data_in: &AES128_DATA_IN,
        data_out: [
            &AES128_CTR_OUT,
            &AES128_OFB_OUT,
            &AES128_CBC_OUT,
            &AES128_CFB_OUT,
            &AES128_ECB_OUT,
        ],
    },
    SymTestVector {
        alg: id(Alg::AES),
        key_alg: AlgSym::Aes256,
        key: &AES256_KEY,
        data_in: &AES256_DATA_IN,
        data_out: [
            &AES256_CTR_OUT,
            &AES256_OFB_OUT,
            &AES256_CBC_OUT,
            &AES256_CFB_OUT,
            &AES256_ECB_OUT,
        ],
    },
];

/// The vector a test operates on (the reference's `toTest` argument).
pub(crate) enum Vector<'v> {
    /// `toTest == &g_toTest` (or `NULL`): a test on first use, or the initialization.
    Global,
    /// A command's local list of algorithms to test.
    Local(&'v mut AlgorithmVector),
}

impl Vector<'_> {
    fn reborrow(&mut self) -> Vector<'_> {
        match self {
            Vector::Global => Vector::Global,
            Vector::Local(v) => Vector::Local(v),
        }
    }

    fn is_global(&self) -> bool {
        matches!(self, Vector::Global)
    }
}

/// `CLEAR_BIT(alg, g_toTest)` for every algorithm without a test: `TestAlgorithm(TPM_ALG_ERROR,
/// &g_toTest)` of `CryptInitializeToTest()`.
pub(crate) fn clear_untestable(state: &SelfTestState) {
    let mut v = Vector::Global;
    for alg in ALG_FIRST..=ALG_LAST {
        if !super::is_implemented(alg) {
            clear_both(state, &mut v, alg);
            continue;
        }
        match classify(alg) {
            // The block ciphers and CFB are tested; the other modes need no separate test (all
            // modes are tested with the block cipher by `TPM2_SelfTest(fullTest = YES)`).
            Class::BlockCipher | Class::Cfb | Class::Hash => {}
            Class::OtherMode => state.update(alg, false),
            // HMAC is tested with the default test hash.
            Class::Hmac => {
                clear_both(state, &mut v, alg);
                set_both(state, &mut v, id_hash(default_test_hash()));
            }
            // RSA is tested with raw RSA (`TPM_ALG_NULL`, which is not implemented and so is
            // cleared again when the loop reaches it).
            Class::Rsa => {
                clear_both(state, &mut v, alg);
                set_both(state, &mut v, id(Alg::NULL));
            }
            Class::RsaScheme | Class::Kdf | Class::EccScheme => {}
            // ECC is tested with ECDH.
            Class::Ecc => {
                clear_both(state, &mut v, alg);
                set_both(state, &mut v, id(Alg::ECDH));
            }
            Class::Untestable => clear_both(state, &mut v, alg),
        }
    }
}

/// The algorithm classes of `TestAlgorithm()`'s dispatch.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    /// `TPM_ALG_AES` (SM4 and Camellia have no test vectors in the reference).
    BlockCipher,
    /// `TPM_ALG_CFB`.
    Cfb,
    /// `TPM_ALG_CTR`, `TPM_ALG_OFB`, `TPM_ALG_CBC`, `TPM_ALG_ECB`.
    OtherMode,
    /// `TPM_ALG_HMAC`.
    Hmac,
    /// An implemented hash algorithm (`FOR_EACH_HASH`).
    Hash,
    /// `TPM_ALG_RSA`.
    Rsa,
    /// `TPM_ALG_RSASSA`, `TPM_ALG_RSAES`, `TPM_ALG_RSAPSS`, `TPM_ALG_OAEP`, `TPM_ALG_NULL`.
    RsaScheme,
    /// `TPM_ALG_KDF1_SP800_108`.
    Kdf,
    /// `TPM_ALG_ECC`.
    Ecc,
    /// `TPM_ALG_ECDSA`, `TPM_ALG_ECDH`, `TPM_ALG_ECSCHNORR`.
    EccScheme,
    /// Every other algorithm: it has no test (e.g. KEYEDHASH, XOR, MGF1, ECDAA, SYMCIPHER, the
    /// other KDFs, SM4, Camellia, CMAC, SM2, ECMQV, and the post-quantum algorithms).
    Untestable,
}

fn classify(alg: u16) -> Class {
    match alg {
        a if a == id(Alg::AES) => Class::BlockCipher,
        a if a == id(Alg::CFB) => Class::Cfb,
        a if a == id(Alg::CTR) || a == id(Alg::OFB) || a == id(Alg::CBC) || a == id(Alg::ECB) => {
            Class::OtherMode
        }
        a if a == id(Alg::HMAC) => Class::Hmac,
        a if TpmiAlgHash::try_from(Alg::new(a)).is_ok() => Class::Hash,
        a if a == id(Alg::RSA) => Class::Rsa,
        a if a == id(Alg::RSASSA)
            || a == id(Alg::RSAES)
            || a == id(Alg::RSAPSS)
            || a == id(Alg::OAEP)
            || a == id(Alg::NULL) =>
        {
            Class::RsaScheme
        }
        a if a == id(Alg::KDF1_SP800_108) => Class::Kdf,
        a if a == id(Alg::ECC) => Class::Ecc,
        a if a == id(Alg::ECDSA) || a == id(Alg::ECDH) || a == id(Alg::ECSCHNORR) => {
            Class::EccScheme
        }
        _ => Class::Untestable,
    }
}

fn id_hash(hash: TpmiAlgHash) -> u16 {
    Alg::from(hash).id()
}

/// `CLEAR_BOTH(alg)`.
fn clear_both(state: &SelfTestState, v: &mut Vector<'_>, alg: u16) {
    if let Vector::Local(local) = v {
        local.clear(alg);
    }
    state.update(alg, false);
}

/// `SET_BOTH(alg)`.
fn set_both(state: &SelfTestState, v: &mut Vector<'_>, alg: u16) {
    if let Vector::Local(local) = v {
        local.set(alg);
    }
    state.update(alg, true);
}

/// `TEST_BOTH(alg)`.
fn test_both(state: &SelfTestState, v: &Vector<'_>, alg: u16) -> bool {
    match v {
        Vector::Local(local) => local.test(alg) || state.needs_test(alg),
        Vector::Global => state.needs_test(alg),
    }
}

/// `TEST_BIT(alg, *toTest)`.
fn test_bit(state: &SelfTestState, v: &Vector<'_>, alg: u16) -> bool {
    match v {
        Vector::Local(local) => local.test(alg),
        Vector::Global => state.needs_test(alg),
    }
}

/// Runs the algorithm self tests: the crypto provider (hooked, so that the algorithms the tests
/// use are tested first, as the reference's nested `TPM_DO_SELF_TEST()` calls do) and, with the
/// `reference-rng` feature, the TPM's DRBG for the tests that draw random values.
pub(crate) struct SelfTester<'a, C: CryptoProvider> {
    pub(crate) crypto: Tested<'a, C>,
    /// The TPM's DRBG, or `None` in the hooked crypto provider, which only runs tests that draw
    /// no random values.
    #[cfg(feature = "reference-rng")]
    pub(crate) rng: Option<RefRng<'a>>,
}

type TestResult = Result<(), TpmRc>;

impl<'a, C: CryptoProvider> SelfTester<'a, C> {
    fn state(&self) -> &'a SelfTestState {
        self.crypto.state
    }

    /// `SELF_TEST_FAILURE`: the TPM enters Failure mode and the command fails.
    fn failure(&self) -> TpmRc {
        self.state().fail();
        TpmRc::FAILURE
    }

    /// Fails the test unless `ok` (or the provider is a test double whose results are not
    /// compared, [`CryptoProvider::KNOWN_ANSWER_TESTS`]).
    fn check(&self, ok: bool) -> TestResult {
        if ok || !C::KNOWN_ANSWER_TESTS {
            Ok(())
        } else {
            Err(self.failure())
        }
    }

    /// Checks the result of a crypto provider operation: `ok` decides on a successful result; an
    /// operation the provider does not implement ([`CryptoError::Unsupported`]) cannot produce a
    /// value that depends on it (Part 3, "Testing": "The TPM may perform operations using
    /// testable functions before those functions have been tested as long as the TPM returns no
    /// value that depends on the correctness of the testable function"), so it passes.
    fn check_crypto<T>(
        &self,
        result: &Result<T, CryptoError>,
        ok: impl FnOnce(&T) -> bool,
    ) -> TestResult {
        match result {
            Ok(value) => self.check(ok(value)),
            Err(CryptoError::Unsupported) => Ok(()),
            Err(_) => self.check(false),
        }
    }

    /// The value of a test step that must succeed: `Some` value, or (if [`Self::check`] lets a
    /// failure pass) the default.
    fn require<T: Default>(&self, value: Option<T>) -> Result<T, TpmRc> {
        match value {
            Some(value) => Ok(value),
            None => self.check(false).map(|()| T::default()),
        }
    }

    /// `TPM_DO_SELF_TEST(alg)`: tests `alg` if it still needs a test.
    pub(crate) fn do_self_test(&mut self, alg: u16) -> TestResult {
        if self.state().needs_test(alg) {
            self.test_algorithm(alg, Vector::Global)?;
        }
        Ok(())
    }

    /// `TestAlgorithm(alg, toTest)` for a single algorithm.
    pub(crate) fn test_algorithm(&mut self, alg: u16, mut v: Vector<'_>) -> TestResult {
        let state = self.state();
        if !super::is_implemented(alg) {
            clear_both(state, &mut v, alg);
            return Ok(());
        }
        match classify(alg) {
            Class::BlockCipher | Class::Cfb | Class::OtherMode => self.test_symmetric(alg, v),
            Class::Hmac => {
                clear_both(state, &mut v, alg);
                // The reference ignores the result (a failure has entered Failure mode).
                self.test_hash(default_test_hash(), v)
            }
            Class::Hash => {
                let hash = TpmiAlgHash::try_from(Alg::new(alg)).map_err(|_| self.failure())?;
                self.test_hash(hash, v)
            }
            Class::Rsa => {
                clear_both(state, &mut v, alg);
                self.test_rsa(id(Alg::NULL), v)
            }
            Class::RsaScheme => self.test_rsa(alg, v),
            Class::Kdf => self.test_kdfa(v),
            Class::Ecc => {
                clear_both(state, &mut v, alg);
                self.test_ecc(id(Alg::ECDH), v)
            }
            Class::EccScheme => self.test_ecc(alg, v),
            Class::Untestable => {
                clear_both(state, &mut v, alg);
                Ok(())
            }
        }
    }

    /// `CryptRunSelfTests()`: tests every algorithm of `v`, in ascending order.
    pub(crate) fn run_self_tests(&mut self, v: &mut AlgorithmVector) -> TestResult {
        for alg in ALG_FIRST..=ALG_LAST {
            if v.test(alg) {
                self.test_algorithm(alg, Vector::Local(v))?;
            }
        }
        Ok(())
    }

    /// `CryptSelfTest()` (TPM2_SelfTest): with `full_test`, every implemented algorithm needs a
    /// test again; then every algorithm that needs a test is tested.
    pub(crate) fn self_test(&mut self, full_test: bool) -> TestResult {
        if full_test {
            self.state().store(&AlgorithmVector::implemented());
        }
        let mut v = self.state().load();
        self.run_self_tests(&mut v)
    }

    // ---------------------------------------------------------------------------------------
    // Hash and HMAC.
    // ---------------------------------------------------------------------------------------

    /// `TestHash()`: a known-value HMAC with `hash`.
    fn test_hash(&mut self, hash: TpmiAlgHash, mut v: Vector<'_>) -> TestResult {
        clear_both(self.state(), &mut v, id_hash(hash));
        let kvt: &[u8] = match Alg::from(hash) {
            a if a == Alg::SHA1 => &SHA1_HMAC_KVT,
            a if a == Alg::SHA256 => &SHA256_HMAC_KVT,
            a if a == Alg::SHA384 => &SHA384_HMAC_KVT,
            a if a == Alg::SHA512 => &SHA512_HMAC_KVT,
            // A hash without test vectors (SM3, SHA-3) is assumed to be correct.
            _ => return Ok(()),
        };
        let digest_size = hash.digest_size();
        let block_size = usize::from(hash.block_size());
        let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let computed = (|| {
            let mut mac = HmacStream::new(&self.crypto, hash, &HASH_TEST_KEY[..2 * digest_size])?;
            mac.update(&HASH_TEST_DATA[..2 * block_size])?;
            let digest = mac.finalize(&mut out)?;
            Ok::<bool, CryptoError>(digest.digest() == kvt)
        })();
        self.check_crypto(&computed, |ok| *ok)
    }

    /// `TEST_DEFAULT_TEST_HASH(toTest)`: tests the default test hash if it needs a test.
    fn test_default_hash(&mut self, v: Vector<'_>) -> TestResult {
        let hash = default_test_hash();
        if self.state().needs_test(id_hash(hash)) {
            self.test_hash(hash, v)?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------------------------------
    // Symmetric.
    // ---------------------------------------------------------------------------------------

    /// `TestSymmetricAlgorithm()`: encrypts and decrypts the test data with `test`'s key in
    /// `mode`.
    fn test_symmetric_algorithm(&mut self, test: &SymTestVector, mode: u16) -> TestResult {
        let Some(key) = SymmetricKey::new(test.key_alg, test.key) else {
            return Ok(());
        };
        let cipher_mode =
            TpmiAlgCipherMode::try_from(Alg::new(mode)).map_err(|_| self.failure())?;
        let expected = test.data_out[usize::from(mode - SYM_MODES.start())];
        let mut data = *test.data_in;
        let mut iv = [0u8; 16];
        let iv_len = make_iv(mode, &mut iv);
        let mode_iv = ModeIv::new(cipher_mode, &mut iv[..iv_len]).ok_or_else(|| self.failure())?;
        let encrypted = tpm2::crypto::encrypt_decrypt(
            &self.crypto,
            key,
            mode_iv,
            Direction::Encrypt,
            &mut data,
        );
        if encrypted == Err(CryptoError::Unsupported) {
            // A crypto provider that does not implement the mode (e.g. the BoringSSL provider,
            // which implements only CFB) cannot return any value that depends on it (Part 3,
            // "Testing": "The TPM may perform operations using testable functions before those
            // functions have been tested as long as the TPM returns no value that depends on the
            // correctness of the testable function"), so there is nothing to test.
            return Ok(());
        }
        self.check_crypto(&encrypted, |_| &data == expected)?;
        let iv_len = make_iv(mode, &mut iv);
        let mode_iv = ModeIv::new(cipher_mode, &mut iv[..iv_len]).ok_or_else(|| self.failure())?;
        let decrypted = tpm2::crypto::encrypt_decrypt(
            &self.crypto,
            key,
            mode_iv,
            Direction::Decrypt,
            &mut data,
        );
        self.check_crypto(&decrypted, |_| &data == test.data_in)
    }

    /// `AllSymsAreDone()`.
    fn all_syms_are_done(&self, v: &Vector<'_>) -> bool {
        !test_both(self.state(), v, id(Alg::AES)) && !test_both(self.state(), v, id(Alg::SM4))
    }

    /// `AllModesAreDone()`.
    fn all_modes_are_done(&self, v: &Vector<'_>) -> bool {
        SYM_MODES
            .clone()
            .all(|mode| !test_both(self.state(), v, mode))
    }

    /// `TestSymmetric()`: a block cipher is tested in all the modes to test; a mode is tested
    /// with all the block ciphers to test.
    fn test_symmetric(&mut self, alg: u16, mut v: Vector<'_>) -> TestResult {
        let state = self.state();
        if !test_bit(state, &v, alg) {
            return Ok(());
        }
        if alg == id(Alg::AES) || alg == id(Alg::SM4) || alg == id(Alg::CAMELLIA) {
            clear_both(state, &mut v, alg);
            for test in SYM_TEST_VALUES.iter().filter(|t| t.alg == alg) {
                for mode in SYM_MODES {
                    if test_bit(state, &v, mode) {
                        self.test_symmetric_algorithm(test, mode)?;
                    }
                }
            }
            if self.all_syms_are_done(&v) {
                for mode in SYM_MODES {
                    clear_both(state, &mut v, mode);
                }
            }
        } else if SYM_MODES.contains(&alg) {
            // The reference's loop over the test vectors runs once (its inner loop reuses the
            // index).
            if !test_bit(state, &v, id(Alg::AES)) && !test_bit(state, &v, id(Alg::SM4)) {
                clear_both(state, &mut v, alg);
            } else {
                for test in SYM_TEST_VALUES.iter() {
                    if test_bit(state, &v, test.alg) {
                        self.test_symmetric_algorithm(test, alg)?;
                    }
                }
                clear_both(state, &mut v, alg);
            }
            if self.all_modes_are_done(&v) {
                clear_both(state, &mut v, id(Alg::AES));
                clear_both(state, &mut v, id(Alg::SM4));
            }
        } else {
            return Err(self.failure());
        }
        Ok(())
    }

    // ---------------------------------------------------------------------------------------
    // RSA.
    // ---------------------------------------------------------------------------------------

    /// The private key of the test RSA key (`RsaKeyInitialize()`: the public modulus, the first
    /// prime and the default exponent), in the crypto provider's format.
    fn rsa_test_key(&self, out: &mut [u8]) -> Result<Option<usize>, TpmRc> {
        let imported = self.crypto.inner.rsa_import_private_key(
            &RSA_TEST_MODULUS,
            &RSA_TEST_PRIME,
            RSA_TEST_EXPONENT,
            out,
        );
        match imported {
            // No RSA private keys, so nothing that depends on them.
            Err(CryptoError::Unsupported) => Ok(None),
            imported => self.require(imported.ok().flatten()).map(Some),
        }
    }

    /// The RSAES or OAEP (`hash` `Some`) encryption of `message` with the test key, drawing the
    /// padding from the TPM's DRBG as the reference's `CryptRsaEncrypt()` does.
    fn rsa_encrypt(
        &mut self,
        hash: Option<TpmiAlgHash>,
        message: &[u8],
        out: &mut [u8; RSA_TEST_KEY_SIZE],
    ) -> TestResult {
        #[cfg(feature = "reference-rng")]
        {
            let Some(rng) = self.rng.as_mut() else {
                // Only the engine's self tester has the DRBG these tests draw from.
                self.crypto.state.fail();
                return Err(TpmRc::FAILURE);
            };
            let mut padded = [0u8; RSA_TEST_KEY_SIZE];
            let encoded = match hash {
                Some(hash) => rsa::oaep_encode(rng, hash, OAEP_TEST_LABEL, message, &mut padded),
                None => rsa::rsaes_pkcs1v15_encode(rng, message, &mut padded),
            };
            self.check(encoded.is_ok())?;
            let encrypted = self.crypto.inner.rsa_null_encrypt(
                &RSA_TEST_MODULUS,
                RSA_TEST_EXPONENT,
                &padded,
                &mut out[..],
            );
            self.check_crypto(&encrypted, |len| *len == Some(RSA_TEST_KEY_SIZE))
        }
        #[cfg(not(feature = "reference-rng"))]
        {
            let (scheme, hash_alg) = match hash {
                Some(hash) => (Alg::OAEP, Alg::from(hash)),
                None => (Alg::RSAES, Alg::NULL),
            };
            let encrypted = self.crypto.inner.encrypt(
                scheme,
                hash_alg,
                &RSA_TEST_MODULUS,
                RSA_TEST_EXPONENT,
                message,
                &mut out[..],
                OAEP_TEST_LABEL,
            );
            self.check_crypto(&encrypted, |len| *len == Some(RSA_TEST_KEY_SIZE))
        }
    }

    /// `TestRsaEncryptDecrypt()`: raw RSA (`TPM_ALG_NULL`) with known values, or RSAES/OAEP
    /// encryption (random) followed by the decryption of the result and of a known value.
    fn test_rsa_encrypt_decrypt(&mut self, scheme: u16, mut v: Vector<'_>) -> TestResult {
        let state = self.state();
        clear_both(state, &mut v, scheme);
        clear_both(state, &mut v, id(Alg::NULL));
        let mut private_key = [0u8; 2048];
        let Some(key_len) = self.rsa_test_key(&mut private_key)? else {
            return Ok(());
        };
        let private_key = &private_key[..key_len];
        let crypto = self.crypto.inner;
        let mut output = [0u8; RSA_TEST_KEY_SIZE];
        if scheme == id(Alg::NULL) {
            let encrypted = crypto.rsa_null_encrypt(
                &RSA_TEST_MODULUS,
                RSA_TEST_EXPONENT,
                &RSA_TEST_VALUE,
                &mut output,
            );
            self.check_crypto(&encrypted, |len| {
                *len == Some(RSA_TEST_KEY_SIZE) && output == RSAEP_KVT
            })?;
            let mut decrypted = [0u8; RSA_TEST_KEY_SIZE];
            let len = crypto.rsa_null_decrypt(private_key, &output, &mut decrypted);
            return self.check_crypto(&len, |len| {
                *len == Some(RSA_TEST_KEY_SIZE) && decrypted == RSA_TEST_VALUE
            });
        }
        let hash = default_test_hash();
        let (oaep, kvt) = if scheme == id(Alg::OAEP) {
            self.test_default_hash(v.reborrow())?;
            (true, oaep_kvt(hash))
        } else if scheme == id(Alg::RSAES) {
            (false, rsaes_kvt(hash))
        } else {
            return Err(self.failure());
        };
        let (scheme_alg, hash_alg) = if oaep {
            (Alg::OAEP, Alg::from(hash))
        } else {
            (Alg::RSAES, Alg::NULL)
        };
        let message = &RSA_TEST_VALUE[..hash.digest_size()];
        self.rsa_encrypt(oaep.then_some(hash), message, &mut output)?;
        let mut decrypted = [0u8; RSA_TEST_KEY_SIZE];
        for ciphertext in [&output, kvt] {
            let len = crypto.decrypt(
                scheme_alg,
                hash_alg,
                private_key,
                ciphertext,
                &mut decrypted,
                OAEP_TEST_LABEL,
            );
            self.check_crypto(&len, |len| {
                *len == Some(message.len()) && &decrypted[..message.len()] == message
            })?;
        }
        Ok(())
    }

    /// `TestRsaSignAndVerify()`: signs a known digest (RSASSA: compared with a known
    /// signature; RSASSA-PSS: random salt), verifies the signature and, for RSASSA-PSS, a known
    /// signature.
    fn test_rsa_sign_and_verify(&mut self, scheme: u16, mut v: Vector<'_>) -> TestResult {
        let state = self.state();
        clear_both(state, &mut v, scheme);
        clear_both(state, &mut v, id(Alg::NULL));
        clear_both(state, &mut v, id(Alg::RSA));
        let mut private_key = [0u8; 2048];
        let Some(key_len) = self.rsa_test_key(&mut private_key)? else {
            return Ok(());
        };
        let private_key = &private_key[..key_len];
        let hash = default_test_hash();
        let digest = &RSA_TEST_VALUE[..hash.digest_size()];
        let ha = TpmtHa::new(hash, digest).ok_or_else(|| self.failure())?;
        let mut signature = [0u8; RSA_TEST_KEY_SIZE];
        if scheme == id(Alg::RSASSA) {
            let signed = self
                .crypto
                .inner
                .rsassa_sign(private_key, ha, &mut signature);
            self.check_crypto(&signed, |len| {
                *len == Some(RSA_TEST_KEY_SIZE) && signature == rsassa_kvt(hash)
            })?;
            let verified = self.crypto.inner.rsassa_verify(
                &RSA_TEST_MODULUS,
                RSA_TEST_EXPONENT,
                ha,
                &signature,
            );
            return self.check_crypto(&verified, |ok| *ok);
        }
        if scheme != id(Alg::RSAPSS) {
            return Err(self.failure());
        }
        // `PssEncode()` starts a hash with the default test hash.
        self.do_self_test(id_hash(hash))?;
        self.rsa_pss_sign(private_key, hash, digest, &mut signature)?;
        for sig in [&signature, rsapss_kvt(hash)] {
            let verified =
                self.crypto
                    .inner
                    .rsapss_verify(&RSA_TEST_MODULUS, RSA_TEST_EXPONENT, ha, sig);
            self.check_crypto(&verified, |ok| *ok)?;
        }
        Ok(())
    }

    /// An RSASSA-PSS signature of `digest` with the test key, drawing the salt from the TPM's
    /// DRBG as the reference's `CryptRsaSign()` does.
    fn rsa_pss_sign(
        &mut self,
        private_key: &[u8],
        hash: TpmiAlgHash,
        digest: &[u8],
        out: &mut [u8; RSA_TEST_KEY_SIZE],
    ) -> TestResult {
        #[cfg(feature = "reference-rng")]
        {
            let Some(rng) = self.rng.as_mut() else {
                // Only the engine's self tester has the DRBG these tests draw from.
                self.crypto.state.fail();
                return Err(TpmRc::FAILURE);
            };
            let mut encoded = [0u8; RSA_TEST_KEY_SIZE];
            let pss = rsa::pss_encode(rng, hash, digest, &mut encoded);
            self.check(pss.is_ok())?;
            let signed = self
                .crypto
                .inner
                .rsa_null_decrypt(private_key, &encoded, &mut out[..]);
            self.check_crypto(&signed, |len| *len == Some(RSA_TEST_KEY_SIZE))
        }
        #[cfg(not(feature = "reference-rng"))]
        {
            let ha = TpmtHa::new(hash, digest).ok_or_else(|| self.failure())?;
            let signed = self.crypto.inner.rsapss_sign(private_key, ha, &mut out[..]);
            self.check_crypto(&signed, |len| *len == Some(RSA_TEST_KEY_SIZE))
        }
    }

    /// `TestRsa()`.
    fn test_rsa(&mut self, alg: u16, v: Vector<'_>) -> TestResult {
        if alg == id(Alg::NULL) {
            // Raw RSA is tested by every other RSA test; it is tested by itself only on first
            // use or when no other RSA test is requested.
            let run = match &v {
                Vector::Global => true,
                Vector::Local(local) => {
                    !local.test(id(Alg::RSASSA))
                        && !local.test(id(Alg::RSAES))
                        && !local.test(id(Alg::RSAPSS))
                        && !local.test(id(Alg::OAEP))
                }
            };
            if run {
                self.test_rsa_encrypt_decrypt(alg, v)?;
            }
            Ok(())
        } else if alg == id(Alg::OAEP) || alg == id(Alg::RSAES) {
            self.test_rsa_encrypt_decrypt(alg, v)
        } else if alg == id(Alg::RSAPSS) || alg == id(Alg::RSASSA) {
            self.test_rsa_sign_and_verify(alg, v)
        } else {
            Err(self.failure())
        }
    }

    // ---------------------------------------------------------------------------------------
    // ECC.
    // ---------------------------------------------------------------------------------------

    /// `TestECDH()`: a known-value point multiplication.
    fn test_ecdh(&mut self, mut v: Vector<'_>) -> TestResult {
        clear_both(self.state(), &mut v, id(Alg::ECDH));
        let mut qe = [0u8; 64];
        qe[..32].copy_from_slice(&EC_TEST_KEY_QE_X);
        qe[32..].copy_from_slice(&EC_TEST_KEY_QE_Y);
        let mut z = [0u8; 64];
        let multiplied = self
            .crypto
            .point_multiply(TEST_CURVE, &EC_TEST_KEY_DS, &qe, &mut z);
        self.check_crypto(&multiplied, |len| {
            *len == Some(64) && z[..32] == EC_TEST_ECDH_X && z[32..] == EC_TEST_ECDH_Y
        })
    }

    /// `TestEccSignAndVerify()`: verifies a known ECDSA signature, then signs (random nonce) and
    /// verifies the signature.
    fn test_ecc_sign_and_verify(&mut self, scheme: u16, mut v: Vector<'_>) -> TestResult {
        let state = self.state();
        clear_both(state, &mut v, scheme);
        clear_both(state, &mut v, id(Alg::ECDH));
        if scheme != id(Alg::ECDSA) {
            // The reference has no test for SM2; this TPM has no EC-Schnorr test vectors (and
            // the C references do not implement EC-Schnorr in the profiles tpm-rs is compared
            // with).
            return Ok(());
        }
        self.test_default_hash(v.reborrow())?;
        let hash = default_test_hash();
        let digest = &EC_TEST_VALUE[..hash.digest_size()];
        let ha = TpmtHa::new(hash, digest).ok_or_else(|| self.failure())?;
        let mut qs = [0u8; 64];
        qs[..32].copy_from_slice(&EC_TEST_KEY_QS_X);
        qs[32..].copy_from_slice(&EC_TEST_KEY_QS_Y);
        let (kvt_r, kvt_s) = ecdsa_kvt(hash);
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(kvt_r);
        signature[32..].copy_from_slice(kvt_s);
        let verified = self.crypto.inner.ecdsa_verify(&qs, ha, &signature);
        self.check_crypto(&verified, |ok| *ok)?;
        self.ecdsa_sign(digest, &mut signature)?;
        let verified = self.crypto.inner.ecdsa_verify(&qs, ha, &signature);
        self.check_crypto(&verified, |ok| *ok)
    }

    /// An ECDSA signature (`r || s`) of `digest` with the test key, drawing the nonce from the
    /// TPM's DRBG as the reference's `CryptEccSign()` does.
    fn ecdsa_sign(&mut self, digest: &[u8], out: &mut [u8; 64]) -> TestResult {
        #[cfg(feature = "reference-rng")]
        {
            let Some(rng) = self.rng.as_mut() else {
                // Only the engine's self tester has the DRBG these tests draw from.
                self.crypto.state.fail();
                return Err(TpmRc::FAILURE);
            };
            let (r, s) = out.split_at_mut(32);
            let signed = ecc::sign_ecdsa(rng, None, TEST_CURVE, &EC_TEST_KEY_DS, digest, r, s);
            self.check(signed == Ok(32))
        }
        #[cfg(not(feature = "reference-rng"))]
        {
            let ha = TpmtHa::new(default_test_hash(), digest).ok_or_else(|| self.failure())?;
            let signed = self
                .crypto
                .inner
                .ecdsa_sign(&EC_TEST_KEY_DS, ha, &mut out[..]);
            self.check_crypto(&signed, |len| *len == Some(64))
        }
    }

    /// `TestEcc()`.
    fn test_ecc(&mut self, alg: u16, v: Vector<'_>) -> TestResult {
        if alg == id(Alg::ECC) || alg == id(Alg::ECDH) {
            // ECDH is tested by the signature tests; it is tested by itself only on first use
            // or when no signature test is requested.
            let run = match &v {
                Vector::Global => true,
                Vector::Local(local) => {
                    !(local.test(id(Alg::ECDSA))
                        || (super::is_implemented(id(Alg::ECSCHNORR))
                            && local.test(id(Alg::ECSCHNORR)))
                        || (super::is_implemented(id(Alg::SM2)) && local.test(id(Alg::SM2))))
                }
            };
            if run {
                self.test_ecdh(v)?;
            }
            Ok(())
        } else if alg == id(Alg::ECDSA) || alg == id(Alg::ECSCHNORR) || alg == id(Alg::SM2) {
            self.test_ecc_sign_and_verify(alg, v)
        } else {
            Err(self.failure())
        }
    }

    // ---------------------------------------------------------------------------------------
    // KDF.
    // ---------------------------------------------------------------------------------------

    /// `TestKDFa()`: a known-value KDFa with the default test hash (`KDF_TEST_ALG`).
    fn test_kdfa(&mut self, mut v: Vector<'_>) -> TestResult {
        clear_both(self.state(), &mut v, id(Alg::KDF1_SP800_108));
        let hash = default_test_hash();
        let mut out = [0u8; 20];
        let derived = tpm2::crypto::kdfa_bits(
            &self.crypto,
            hash,
            &KDF_TEST_KEY_IN,
            &KDF_TEST_LABEL,
            &KDF_TEST_CONTEXT_U,
            &KDF_TEST_CONTEXT_V,
            160,
            &mut out,
        );
        let expected = if super::super::handler::capability::is_sha512(hash) {
            &KDF_TEST_KEY_OUT_SHA512
        } else {
            &KDF_TEST_KEY_OUT_SHA384
        };
        self.check_crypto(&derived, |len| *len == 20 && &out == expected)
    }
}

/// `MakeIv()`: the IV of the symmetric tests (none for ECB; for CTR the block size bytes ending
/// in `0xff`; otherwise `0, 1, 2, ...`). Returns its length.
fn make_iv(mode: u16, iv: &mut [u8; 16]) -> usize {
    if mode == id(Alg::ECB) {
        return 0;
    }
    for (i, b) in iv.iter_mut().enumerate() {
        *b = if mode == id(Alg::CTR) {
            0xf0 + i as u8
        } else {
            i as u8
        };
    }
    16
}

/// The known-answer vectors that depend on the default test hash.
fn by_hash<T>(hash: TpmiAlgHash, sha512: T, sha384: T) -> T {
    if super::super::handler::capability::is_sha512(hash) {
        sha512
    } else {
        sha384
    }
}

fn oaep_kvt(hash: TpmiAlgHash) -> &'static [u8; RSA_TEST_KEY_SIZE] {
    by_hash(hash, &OAEP_KVT_SHA512, &OAEP_KVT_SHA384)
}

fn rsaes_kvt(hash: TpmiAlgHash) -> &'static [u8; RSA_TEST_KEY_SIZE] {
    by_hash(hash, &RSAES_KVT_SHA512, &RSAES_KVT_SHA384)
}

fn rsassa_kvt(hash: TpmiAlgHash) -> [u8; RSA_TEST_KEY_SIZE] {
    *by_hash(hash, &RSASSA_KVT_SHA512, &RSASSA_KVT_SHA384)
}

fn rsapss_kvt(hash: TpmiAlgHash) -> &'static [u8; RSA_TEST_KEY_SIZE] {
    by_hash(hash, &RSAPSS_KVT_SHA512, &RSAPSS_KVT_SHA384)
}

fn ecdsa_kvt(hash: TpmiAlgHash) -> (&'static [u8; 32], &'static [u8; 32]) {
    by_hash(
        hash,
        (&EC_TEST_ECDSA_R_SHA512, &EC_TEST_ECDSA_S_SHA512),
        (&EC_TEST_ECDSA_R_SHA384, &EC_TEST_ECDSA_S_SHA384),
    )
}
