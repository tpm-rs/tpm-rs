#![cfg_attr(not(any(test, feature = "reproducible")), no_std)]
#![deny(unsafe_code)]

use tpm2::crypto::{ConstantTimeEq, CryptoError, CryptoProvider, Random};

/// BoringSSL-based implementation of the `tpm2::crypto` interfaces
/// ([`CryptoProvider`] and its super-traits).
///
/// Supported algorithms: SHA-1/SHA-256/SHA-384/SHA-512 (hash and HMAC),
/// AES-128/192/256 (CMAC, and CFB for symmetric encryption), RSA 1024-4096
/// (RSASSA, RSAPSS, RSAES, OAEP, raw RSA, key generation and import), the NIST
/// P-224/P-256/P-384/P-521 curves (ECDSA, point operations and key generation),
/// and BN-P256 (point operations and key generation).
/// Everything else returns [`CryptoError::Unsupported`].
pub struct BsslCryptoProvider;

impl CryptoProvider for BsslCryptoProvider {
    fn get_random(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        rand_bytes(dest);
        Ok(())
    }
}

impl ConstantTimeEq for BsslCryptoProvider {
    /// Compares `a` and `b` with BoringSSL's `CRYPTO_memcmp`, in time independent
    /// of their contents.
    fn constant_time_eq<const N: usize>(&self, a: &[u8; N], b: &[u8; N]) -> bool {
        bssl_crypto::constant_time_compare(a, b)
    }
}

/// The provider does not create [`tpm2::crypto::Rng`] instances: its CSPRNG is
/// [`CryptoProvider::get_random`], and deterministic key generation takes a seed
/// directly ([`tpm2::crypto::Asymmetric::generate_key`]).
impl Random for BsslCryptoProvider {
    type Rng = !;
}

/// Fills `dest` with random bytes: from the thread's replay generator if one
/// is installed (`reproducible` feature), otherwise from BoringSSL's `RAND_bytes`.
pub(crate) fn rand_bytes(dest: &mut [u8]) {
    #[cfg(feature = "reproducible")]
    if replay::fill(dest) {
        return;
    }
    bssl_crypto::rand_bytes(dest);
}

/// Deterministic randomness for reproducible (and differential) test runs.
///
/// A [`replay::ReplayRng`] is a seeded ChaCha20 stream owned by the caller
/// (e.g. one per simulator). While [`replay::ReplayRng::scope`] runs, every
/// random value this provider produces on the current thread comes from that
/// stream: `get_random`, key generation, ECDSA nonces, RSA-PSS salts and
/// RSA-OAEP / PKCS#1 v1.5 encryption padding. Outside a scope (and without the
/// `reproducible` feature) BoringSSL's RNG is used as usual, so other users of the
/// provider on the same thread (e.g. a test's client-side crypto) neither
/// consume nor perturb the stream. Operations that use randomness only
/// internally without affecting their output (e.g. RSA blinding) always use
/// BoringSSL's RNG. **Not for production use.**
#[cfg(feature = "reproducible")]
#[forbid(unsafe_code)]
pub mod replay {
    use core::cell::RefCell;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore as _, SeedableRng as _};

    std::thread_local! {
        static ACTIVE: RefCell<Option<ChaCha20Rng>> = const { RefCell::new(None) };
        /// Stream used on this thread when no [`ReplayRng::scope`] is active.
        static THREAD_DEFAULT: RefCell<Option<ChaCha20Rng>> = const { RefCell::new(None) };
    }

    /// Sets (or, with `None`, clears) a seeded stream that this thread uses for
    /// the provider's randomness whenever no [`ReplayRng::scope`] is active.
    ///
    /// This pins randomness drawn *outside* a simulator, e.g. by a test's
    /// client-side crypto (nonces, salts, client key generation), so that a
    /// test sends the same commands on every run. Scoped streams
    /// still take precedence, so a simulator's own stream is unaffected.
    pub fn set_thread_default_seed(seed: Option<u64>) {
        THREAD_DEFAULT.with(|d| *d.borrow_mut() = seed.map(ChaCha20Rng::seed_from_u64));
    }

    /// A seeded random stream that can be made the provider's randomness
    /// source for the duration of a closure.
    pub struct ReplayRng {
        /// `None` only while the stream is installed by [`ReplayRng::scope`].
        rng: Option<ChaCha20Rng>,
    }

    impl ReplayRng {
        /// A stream fully determined by `seed`.
        pub fn new(seed: u64) -> Self {
            Self {
                rng: Some(ChaCha20Rng::seed_from_u64(seed)),
            }
        }

        /// Runs `f` with this stream as the provider's randomness source on the
        /// current thread, then takes the (advanced) stream back. Scopes nest:
        /// the previously active stream, if any, is restored afterwards, also
        /// when `f` panics.
        pub fn scope<R>(&mut self, f: impl FnOnce() -> R) -> R {
            struct Restore<'a> {
                owner: &'a mut ReplayRng,
                previous: Option<ChaCha20Rng>,
            }
            impl Drop for Restore<'_> {
                fn drop(&mut self) {
                    let previous = self.previous.take();
                    self.owner.rng = ACTIVE.with(|a| a.replace(previous));
                }
            }
            let mine = self.rng.take();
            let previous = ACTIVE.with(|a| a.replace(mine));
            let _restore = Restore {
                owner: self,
                previous,
            };
            f()
        }
    }

    /// Whether a seeded stream (a [`ReplayRng`] scope or the thread default)
    /// is active on the current thread.
    pub fn is_active() -> bool {
        ACTIVE.with(|a| a.borrow().is_some()) || THREAD_DEFAULT.with(|d| d.borrow().is_some())
    }

    /// Fills `dest` from the active scope's stream, else from the thread
    /// default; returns `false` if neither is set.
    pub(crate) fn fill(dest: &mut [u8]) -> bool {
        let fill_from = |cell: &RefCell<Option<ChaCha20Rng>>| match cell.borrow_mut().as_mut() {
            Some(rng) => {
                rng.fill_bytes(dest);
                true
            }
            None => false,
        };
        if ACTIVE.with(|a| a.borrow().is_some()) {
            return ACTIVE.with(fill_from);
        }
        THREAD_DEFAULT.with(fill_from)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn draw() -> [u8; 16] {
            let mut b = [0u8; 16];
            crate::rand_bytes(&mut b);
            b
        }

        #[test]
        fn scoped_stream_is_deterministic_and_resumes() {
            assert!(!is_active());
            let (mut a, mut b) = (ReplayRng::new(7), ReplayRng::new(7));
            let a1 = a.scope(draw);
            // Draws outside a scope do not consume the stream.
            let _ = draw();
            let a2 = a.scope(draw);
            let b_all = b.scope(|| (draw(), draw()));
            assert_eq!((a1, a2), b_all);
            assert_ne!(a1, a2);
            assert!(!is_active());
        }

        #[test]
        fn thread_default_applies_outside_scopes_only() {
            set_thread_default_seed(Some(5));
            assert!(is_active());
            let mut scoped = ReplayRng::new(9);
            let (d1, s1, d2) = (draw(), scoped.scope(draw), draw());
            set_thread_default_seed(Some(5));
            let (e1, e2) = (draw(), draw());
            assert_eq!(
                (d1, d2),
                (e1, e2),
                "scopes do not consume the default stream"
            );
            assert_eq!(s1, ReplayRng::new(9).scope(draw));
            set_thread_default_seed(None);
            assert!(!is_active());
        }

        #[test]
        fn scopes_nest_and_restore_on_panic() {
            let (mut outer, mut inner) = (ReplayRng::new(1), ReplayRng::new(2));
            let mut reference = ReplayRng::new(1);
            let (x, y) = outer.scope(|| {
                let x = draw();
                inner.scope(draw);
                (x, draw())
            });
            assert_eq!((x, y), reference.scope(|| (draw(), draw())));
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                inner.scope(|| panic!("boom"))
            }));
            assert!(r.is_err());
            assert!(!is_active());
            assert!(inner.rng.is_some(), "the stream is returned after a panic");
        }
    }
}

#[forbid(unsafe_code)]
pub mod asymmetric;
pub mod bssl;
#[forbid(unsafe_code)]
pub mod cmac;
#[forbid(unsafe_code)]
pub mod ecc;
#[forbid(unsafe_code)]
pub mod hash;
#[forbid(unsafe_code)]
pub mod symmetric;
pub use {bssl::*, cmac::*, ecc::*, hash::*};

/// Maps the result of a verification or validation binding to the
/// `tpm2::crypto` convention: [`BsslError::InvalidData`] (a bad signature, key,
/// or point) is `Ok(false)`.
pub(crate) fn verified(result: Result<(), BsslError>) -> Result<bool, CryptoError> {
    match result {
        Ok(()) => Ok(true),
        Err(BsslError::InvalidData) => Ok(false),
        Err(err) => Err(err.into()),
    }
}

/// Maps the result of a binding producing output to the `tpm2::crypto`
/// convention: [`BsslError::InvalidData`] (an invalid input) is `Ok(None)`.
pub(crate) fn output<T>(result: Result<T, BsslError>) -> Result<Option<T>, CryptoError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(BsslError::InvalidData) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

/// Random number generator backed by BoringSSL's `RAND_bytes` (or the
/// thread's replay generator, see `replay`).
pub struct BsslRng;

impl rand_core::RngCore for BsslRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        rand_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        rand_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_bytes(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        rand_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for BsslRng {}

#[allow(clippy::large_enum_variant)]
pub(crate) enum RngWrapper {
    ChaCha(rand_chacha::ChaCha20Rng),
    Bssl(BsslRng),
}

impl rand_core::RngCore for RngWrapper {
    fn next_u32(&mut self) -> u32 {
        match self {
            Self::ChaCha(rng) => rng.next_u32(),
            Self::Bssl(rng) => rng.next_u32(),
        }
    }
    fn next_u64(&mut self) -> u64 {
        match self {
            Self::ChaCha(rng) => rng.next_u64(),
            Self::Bssl(rng) => rng.next_u64(),
        }
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        match self {
            Self::ChaCha(rng) => rng.fill_bytes(dest),
            Self::Bssl(rng) => rng.fill_bytes(dest),
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        match self {
            Self::ChaCha(rng) => rng.try_fill_bytes(dest),
            Self::Bssl(rng) => rng.try_fill_bytes(dest),
        }
    }
}

impl rand_core::CryptoRng for RngWrapper {}
