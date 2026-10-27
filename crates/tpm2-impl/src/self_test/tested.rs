//! The crypto provider of the engine with the reference's on-demand self tests
//! (`TPM_DO_SELF_TEST()`): [`Tested`].

use core::ops::Deref;

use tpm2::crypto::{
    CryptoError, CryptoProvider, Direction, Hash, HashStream, Hmac, HmacStream, ModeIv, Symmetric,
};
use tpm2::{Alg, TpmEccCurve, TpmiAlgHash};

use super::{SelfTestState, SelfTester};

/// The engine's crypto provider together with its self-test state: before a hash or HMAC
/// computation, a symmetric encryption or decryption, or an ECC point multiplication, it tests the
/// algorithm if it still needs a test, as the reference's `CryptHashStart()`,
/// `CryptSymmetricEncrypt()`/`CryptSymmetricDecrypt()` and `TpmEcc_PointMult()` do. (KDFa is
/// tested by [`kdfa_bits`].) Every other operation is the provider's ([`Deref`]).
///
/// A failed test fails the operation with [`CryptoError::Internal`] and puts the TPM into Failure
/// mode.
pub struct Tested<'a, C> {
    /// The crypto provider.
    pub inner: &'a C,
    /// The TPM's self-test state.
    pub state: &'a SelfTestState,
}

impl<C> Clone for Tested<'_, C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for Tested<'_, C> {}

impl<C> Deref for Tested<'_, C> {
    type Target = C;

    fn deref(&self) -> &C {
        self.inner
    }
}

impl<'a, C: CryptoProvider> Tested<'a, C> {
    /// The hooked `inner`, with self-test state `state`.
    pub fn new(inner: &'a C, state: &'a SelfTestState) -> Self {
        Self { inner, state }
    }

    /// `TPM_DO_SELF_TEST(alg)`: tests `alg` if it still needs a test. The tests run here draw no
    /// random values (hash, HMAC, symmetric, KDFa and ECDH tests).
    pub(crate) fn do_self_test(&self, alg: Alg) -> Result<(), CryptoError> {
        if !self.state.needs_test(alg.id()) {
            return Ok(());
        }
        let mut tester = SelfTester {
            crypto: *self,
            #[cfg(feature = "reference-rng")]
            rng: None,
        };
        tester
            .do_self_test(alg.id())
            .map_err(|_| CryptoError::Internal)
    }

    /// [`tpm2::crypto::Ecc::point_multiply_generator`], after the ECDH test (`TpmEcc_PointMult()`).
    pub fn point_multiply_generator(
        &self,
        curve: TpmEccCurve,
        scalar: &[u8],
        public_key_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        self.do_self_test(Alg::ECDH)?;
        tpm2::crypto::Ecc::point_multiply_generator(self.inner, curve, scalar, public_key_out)
    }

    /// [`tpm2::crypto::Ecc::point_multiply`], after the ECDH test (`TpmEcc_PointMult()`).
    pub fn point_multiply(
        &self,
        curve: TpmEccCurve,
        scalar: &[u8],
        public_point: &[u8],
        derived_point_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        self.do_self_test(Alg::ECDH)?;
        tpm2::crypto::Ecc::point_multiply(
            self.inner,
            curve,
            scalar,
            public_point,
            derived_point_out,
        )
    }

    /// [`tpm2::crypto::Ecc::ecdaa_sign`], after the ECDH test (`TpmEcc_SignEcdaa()` multiplies
    /// points).
    #[allow(clippy::too_many_arguments)]
    pub fn ecdaa_sign(
        &self,
        curve: TpmEccCurve,
        commit_r: &[u8],
        commit_x: &[u8],
        commit_p1: &[u8],
        private_key_d: &[u8],
        digest: &[u8],
        nonce_k_out: &mut [u8],
        s_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        self.do_self_test(Alg::ECDH)?;
        tpm2::crypto::Ecc::ecdaa_sign(
            self.inner,
            curve,
            commit_r,
            commit_x,
            commit_p1,
            private_key_d,
            digest,
            nonce_k_out,
            s_out,
        )
    }
}

impl<C: CryptoProvider> Tested<'_, C> {
    /// A hash computation with `alg` (`CryptHashStart()`): tests `alg` if it needs a test, then
    /// starts the hash with the provider (the stream does not borrow the engine).
    pub fn hash_stream(&self, alg: TpmiAlgHash) -> Result<HashStream<C>, CryptoError> {
        self.do_self_test(Alg::from(alg))?;
        HashStream::new(self.inner, alg)
    }

    /// An HMAC computation with `alg` and `key` (`CryptHmacStart()`): tests `alg` if it needs a
    /// test, then starts the HMAC with the provider (the stream does not borrow the engine).
    pub fn hmac_stream(&self, alg: TpmiAlgHash, key: &[u8]) -> Result<HmacStream<C>, CryptoError> {
        self.do_self_test(Alg::from(alg))?;
        HmacStream::new(self.inner, alg, key)
    }
}

/// `CryptKDFa()`: [`tpm2::crypto::kdfa_bits`] after the KDFa test
/// (`TPM_DO_SELF_TEST(TPM_ALG_KDF1_SP800_108)`); its HMACs test `alg`.
#[allow(clippy::too_many_arguments)]
pub fn kdfa_bits<C: CryptoProvider>(
    h: &Tested<'_, C>,
    alg: TpmiAlgHash,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    bits: u32,
    out: &mut [u8],
) -> Result<usize, CryptoError> {
    h.do_self_test(Alg::KDF1_SP800_108)?;
    tpm2::crypto::kdfa_bits(h, alg, key, label, context_u, context_v, bits, out)
}

impl<C: CryptoProvider> Hash for Tested<'_, C> {
    type Sha1Context = <C as Hash>::Sha1Context;
    fn sha1(&self) -> Result<Self::Sha1Context, CryptoError> {
        self.do_self_test(Alg::SHA1)?;
        Hash::sha1(self.inner)
    }

    type Sha256Context = <C as Hash>::Sha256Context;
    fn sha256(&self) -> Result<Self::Sha256Context, CryptoError> {
        self.do_self_test(Alg::SHA256)?;
        Hash::sha256(self.inner)
    }

    type Sha384Context = <C as Hash>::Sha384Context;
    fn sha384(&self) -> Result<Self::Sha384Context, CryptoError> {
        self.do_self_test(Alg::SHA384)?;
        Hash::sha384(self.inner)
    }

    type Sha512Context = <C as Hash>::Sha512Context;
    fn sha512(&self) -> Result<Self::Sha512Context, CryptoError> {
        self.do_self_test(Alg::SHA512)?;
        Hash::sha512(self.inner)
    }

    type Sm3_256Context = <C as Hash>::Sm3_256Context;
    fn sm3_256(&self) -> Result<Self::Sm3_256Context, CryptoError> {
        self.do_self_test(Alg::SM3_256)?;
        Hash::sm3_256(self.inner)
    }

    type Sha3_256Context = <C as Hash>::Sha3_256Context;
    fn sha3_256(&self) -> Result<Self::Sha3_256Context, CryptoError> {
        self.do_self_test(Alg::SHA3_256)?;
        Hash::sha3_256(self.inner)
    }

    type Sha3_384Context = <C as Hash>::Sha3_384Context;
    fn sha3_384(&self) -> Result<Self::Sha3_384Context, CryptoError> {
        self.do_self_test(Alg::SHA3_384)?;
        Hash::sha3_384(self.inner)
    }

    type Sha3_512Context = <C as Hash>::Sha3_512Context;
    fn sha3_512(&self) -> Result<Self::Sha3_512Context, CryptoError> {
        self.do_self_test(Alg::SHA3_512)?;
        Hash::sha3_512(self.inner)
    }
}

impl<C: CryptoProvider> Hmac for Tested<'_, C> {
    type Sha1Context = <C as Hmac>::Sha1Context;
    fn sha1(&self, key: &[u8]) -> Result<Self::Sha1Context, CryptoError> {
        self.do_self_test(Alg::SHA1)?;
        Hmac::sha1(self.inner, key)
    }

    type Sha256Context = <C as Hmac>::Sha256Context;
    fn sha256(&self, key: &[u8]) -> Result<Self::Sha256Context, CryptoError> {
        self.do_self_test(Alg::SHA256)?;
        Hmac::sha256(self.inner, key)
    }

    type Sha384Context = <C as Hmac>::Sha384Context;
    fn sha384(&self, key: &[u8]) -> Result<Self::Sha384Context, CryptoError> {
        self.do_self_test(Alg::SHA384)?;
        Hmac::sha384(self.inner, key)
    }

    type Sha512Context = <C as Hmac>::Sha512Context;
    fn sha512(&self, key: &[u8]) -> Result<Self::Sha512Context, CryptoError> {
        self.do_self_test(Alg::SHA512)?;
        Hmac::sha512(self.inner, key)
    }

    type Sm3_256Context = <C as Hmac>::Sm3_256Context;
    fn sm3_256(&self, key: &[u8]) -> Result<Self::Sm3_256Context, CryptoError> {
        self.do_self_test(Alg::SM3_256)?;
        Hmac::sm3_256(self.inner, key)
    }

    type Sha3_256Context = <C as Hmac>::Sha3_256Context;
    fn sha3_256(&self, key: &[u8]) -> Result<Self::Sha3_256Context, CryptoError> {
        self.do_self_test(Alg::SHA3_256)?;
        Hmac::sha3_256(self.inner, key)
    }

    type Sha3_384Context = <C as Hmac>::Sha3_384Context;
    fn sha3_384(&self, key: &[u8]) -> Result<Self::Sha3_384Context, CryptoError> {
        self.do_self_test(Alg::SHA3_384)?;
        Hmac::sha3_384(self.inner, key)
    }

    type Sha3_512Context = <C as Hmac>::Sha3_512Context;
    fn sha3_512(&self, key: &[u8]) -> Result<Self::Sha3_512Context, CryptoError> {
        self.do_self_test(Alg::SHA3_512)?;
        Hmac::sha3_512(self.inner, key)
    }
}

impl<C: CryptoProvider> Symmetric for Tested<'_, C> {
    fn aes128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.do_self_test(Alg::AES)?;
        Symmetric::aes128(self.inner, key, mode, dir, data)
    }

    fn aes192(
        &self,
        key: &[u8; 24],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.do_self_test(Alg::AES)?;
        Symmetric::aes192(self.inner, key, mode, dir, data)
    }

    fn aes256(
        &self,
        key: &[u8; 32],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.do_self_test(Alg::AES)?;
        Symmetric::aes256(self.inner, key, mode, dir, data)
    }

    fn sm4_128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.do_self_test(Alg::SM4)?;
        Symmetric::sm4_128(self.inner, key, mode, dir, data)
    }

    fn camellia128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.do_self_test(Alg::CAMELLIA)?;
        Symmetric::camellia128(self.inner, key, mode, dir, data)
    }

    fn camellia192(
        &self,
        key: &[u8; 24],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.do_self_test(Alg::CAMELLIA)?;
        Symmetric::camellia192(self.inner, key, mode, dir, data)
    }

    fn camellia256(
        &self,
        key: &[u8; 32],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.do_self_test(Alg::CAMELLIA)?;
        Symmetric::camellia256(self.inner, key, mode, dir, data)
    }
}
