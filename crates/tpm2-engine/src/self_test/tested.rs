//! The crypto backend of the engine with the reference's on-demand self tests
//! (`TPM_DO_SELF_TEST()`): [`Tested`].

use core::ffi::CStr;
use core::marker::PhantomData;

use tpm2::crypto::EccPublicKey;
use tpm2::crypto::{
    CipherInput, Crypto, CryptoError, Direction, HashContext, HmacContext, SymmetricKey,
};
use tpm2::{Alg, TpmEccCurve, TpmiAlgHash, TpmsEccPoint, TpmtHa};

use super::{SelfTestState, SelfTester};

/// The engine's crypto backend `C` together with its self-test state: before a hash or HMAC
/// computation, a KDF, a symmetric encryption or decryption, or an ECC point multiplication, it
/// tests the algorithm if it still needs a test, as the reference's `CryptHashStart()`,
/// `CryptSymmetricEncrypt()`/`CryptSymmetricDecrypt()` and `TpmEcc_PointMult()` do. (KDFa is
/// tested by [`kdfa_bits`].) Every other operation uses the dispatch functions of
/// [`tpm2::crypto`] with `C` directly (the backend is static: `C` only selects it).
///
/// A failed test fails the operation with [`CryptoError::Internal`] and puts the TPM into Failure
/// mode.
pub struct Tested<'a, C> {
    /// The TPM's self-test state.
    pub state: &'a SelfTestState,
    crypto: PhantomData<fn() -> C>,
}

impl<C> Clone for Tested<'_, C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C> Copy for Tested<'_, C> {}

impl<'a, C: Crypto> Tested<'a, C> {
    /// The backend `C`, with self-test state `state`.
    pub fn new(state: &'a SelfTestState) -> Self {
        Self {
            state,
            crypto: PhantomData,
        }
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

    /// A hash computation with `alg` (`CryptHashStart()`): tests `alg` if it needs a test, then
    /// starts the hash with the backend (the context does not borrow the engine).
    pub fn hash_stream(&self, alg: TpmiAlgHash) -> Result<HashContext<C>, CryptoError> {
        self.do_self_test(Alg::from(alg))?;
        HashContext::new(alg)
    }

    /// An HMAC computation with `alg` and `key` (`CryptHmacStart()`): tests `alg` if it needs a
    /// test, then starts the HMAC with the backend (the context does not borrow the engine).
    pub fn hmac_stream(&self, alg: TpmiAlgHash, key: &[u8]) -> Result<HmacContext<C>, CryptoError> {
        self.do_self_test(Alg::from(alg))?;
        HmacContext::new(alg, key)
    }

    /// The `alg` digest of the concatenation of `data` ([`tpm2::crypto::hash`]), after the test of
    /// `alg`. `out` must hold the digest.
    pub fn hash<'o>(
        &self,
        alg: TpmiAlgHash,
        data: &[&[u8]],
        out: &'o mut [u8],
    ) -> Result<TpmtHa<'o>, CryptoError> {
        self.do_self_test(Alg::from(alg))?;
        tpm2::crypto::hash::<C>(alg, data, out)
    }

    /// The `alg` HMAC with `key` of the concatenation of `data` ([`tpm2::crypto::hmac`]), after
    /// the test of `alg`. `out` must hold the digest.
    pub fn hmac<'o>(
        &self,
        alg: TpmiAlgHash,
        key: &[u8],
        data: &[&[u8]],
        out: &'o mut [u8],
    ) -> Result<TpmtHa<'o>, CryptoError> {
        self.do_self_test(Alg::from(alg))?;
        tpm2::crypto::hmac::<C>(alg, key, data, out)
    }

    /// [`tpm2::crypto::kdfa`] (whose HMACs test `alg`, as the reference's `CryptKDFa()` HMACs
    /// do, but not KDFa itself: see [`kdfa_bits`]).
    pub fn kdfa(
        &self,
        alg: TpmiAlgHash,
        key: &[u8],
        label: &CStr,
        context: (&[u8], &[u8]),
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        if !out.is_empty() {
            self.do_self_test(Alg::from(alg))?;
        }
        tpm2::crypto::kdfa::<C>(alg, key, label, context, out)
    }

    /// `CryptKDFe()`: [`tpm2::crypto::kdfe_bits`], whose hashes test `alg`.
    pub fn kdfe_bits(
        &self,
        alg: TpmiAlgHash,
        z: &[u8],
        label: &[u8],
        party_info: (&[u8], &[u8]),
        bits: u32,
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if bits > 0 && out.len() >= bits.div_ceil(8) as usize {
            self.do_self_test(Alg::from(alg))?;
        }
        tpm2::crypto::kdfe_bits::<C>(alg, z, label, party_info, bits, out)
    }

    /// Encrypts or decrypts `input` with `key` ([`SymmetricKey::crypt`],
    /// `CryptSymmetricEncrypt()`/`CryptSymmetricDecrypt()`), after the test of its block cipher.
    pub fn crypt(
        &self,
        key: SymmetricKey<'_>,
        dir: Direction,
        input: CipherInput<'_>,
    ) -> Result<(), CryptoError> {
        self.do_self_test(key.alg().algorithm())?;
        key.crypt::<C>(dir, input)
    }

    /// [`tpm2::crypto::ecc_mul_generator`] (`[k]G`), after the ECDH test (`TpmEcc_PointMult()`).
    pub fn mul_generator<'o>(
        &self,
        curve: TpmEccCurve,
        scalar: &[u8],
        out_x: &'o mut [u8],
        out_y: &'o mut [u8],
    ) -> Result<Option<TpmsEccPoint<'o>>, CryptoError> {
        self.do_self_test(Alg::ECDH)?;
        tpm2::crypto::ecc_mul_generator::<C>(curve, scalar, out_x, out_y)
    }

    /// `[k]G` on `curve` as a `x || y` octet string: [`Self::mul_generator`] (after the ECDH
    /// test), writing both coordinates, each padded to the curve size, to `out`. Returns their
    /// total length, or `Ok(None)` if `scalar` is not in `[1, n - 1]`.
    pub fn point_multiply_generator(
        &self,
        curve: TpmEccCurve,
        scalar: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        let size = curve.key_bytes();
        let (mut x, mut y) = ([0u8; MAX_COORD], [0u8; MAX_COORD]);
        let Some(q) = self.mul_generator(curve, scalar, &mut x, &mut y)? else {
            return Ok(None);
        };
        write_xy(q, size, out).map(Some)
    }

    /// `[k]P` on `curve` for the point `point` (`x || y`, each coordinate the curve size) as a
    /// `x || y` octet string: [`Self::mul_point`] (after the ECDH test), writing both
    /// coordinates, each padded to the curve size, to `out`. Returns their total length, or
    /// `Ok(None)` if `point` is not a point of `curve` (or not `2 * size` octets long), `scalar`
    /// is not in `[1, n - 1]`, or the product is the point at infinity.
    pub fn point_multiply(
        &self,
        curve: TpmEccCurve,
        scalar: &[u8],
        point: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        self.do_self_test(Alg::ECDH)?;
        let size = curve.key_bytes();
        let Some(public) = crate::ecc_curves::load_point::<C>(curve, point)? else {
            return Ok(None);
        };
        let (mut x, mut y) = ([0u8; MAX_COORD], [0u8; MAX_COORD]);
        let Some(q) = public.mul_point(scalar, &mut x, &mut y)? else {
            return Ok(None);
        };
        write_xy(q, size, out).map(Some)
    }

    /// [`EccPublicKey::mul_point`] (`[k]P`), after the ECDH test (`TpmEcc_PointMult()`).
    pub fn mul_point<'o>(
        &self,
        point: &EccPublicKey<C>,
        scalar: &[u8],
        out_x: &'o mut [u8],
        out_y: &'o mut [u8],
    ) -> Result<Option<TpmsEccPoint<'o>>, CryptoError> {
        self.do_self_test(Alg::ECDH)?;
        point.mul_point(scalar, out_x, out_y)
    }
}

/// The size of the largest coordinate of the curves of the profile.
const MAX_COORD: usize = TpmEccCurve::MAX_ECC_KEY_BYTES;

/// Writes `q` as `x || y`, each coordinate left-padded to `size` octets, to `out`.
fn write_xy(q: TpmsEccPoint<'_>, size: usize, out: &mut [u8]) -> Result<usize, CryptoError> {
    let out = out.get_mut(..2 * size).ok_or(CryptoError::Internal)?;
    out.fill(0);
    for (half, coord) in out.chunks_mut(size).zip([q.x.as_slice(), q.y.as_slice()]) {
        let offset = size.checked_sub(coord.len()).ok_or(CryptoError::Internal)?;
        half[offset..].copy_from_slice(coord);
    }
    Ok(2 * size)
}

/// `CryptKDFa()`: [`tpm2::crypto::kdfa_bits`] after the KDFa test
/// (`TPM_DO_SELF_TEST(TPM_ALG_KDF1_SP800_108)`); its HMACs test `alg`.
#[allow(clippy::too_many_arguments)]
pub fn kdfa_bits<C: Crypto>(
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
    if bits > 0 && out.len() >= bits.div_ceil(8) as usize {
        h.do_self_test(Alg::from(alg))?;
    }
    tpm2::crypto::kdfa_bits::<C>(alg, key, label, (context_u, context_v), bits, out)
}
