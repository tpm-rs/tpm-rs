//! [`Hmac`] and [`HmacState`].

use core::ffi::CStr;

use super::{default_kdfa, default_kdfa_xor};
use crate::crypto::CryptoError;

/// HMAC, with one associated type per hash algorithm.
///
/// This is identical to [`Hash`](super::Hash), except that the states are
/// initialized with a key. See the [module documentation](super) for how to
/// implement this trait.
pub trait Hmac {
    type Sha1: HmacState<20>;
    type Sha256: HmacState<32>;
    type Sha384: HmacState<48>;
    type Sha512: HmacState<64>;
    type Sm3_256: HmacState<32>;
    type Sha3_256: HmacState<32>;
    type Sha3_384: HmacState<48>;
    type Sha3_512: HmacState<64>;
}

/// Streaming HMAC state for a single hash algorithm, with a MAC of
/// `DIGEST_SIZE` bytes.
pub trait HmacState<const DIGEST_SIZE: usize>: Sized {
    /// Initializes a new HMAC state from `key` (of any length).
    fn init(key: &[u8]) -> Result<Self, CryptoError>;

    /// Feeds `data` into the HMAC state.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError>;

    /// Writes the final MAC into `out`. The state is then spent.
    fn finalize(&mut self, out: &mut [u8; DIGEST_SIZE]) -> Result<(), CryptoError>;

    /// Computes the MAC of the concatenation of `data` under `key` in one shot.
    #[inline(never)]
    fn hmac(key: &[u8], data: &[&[u8]], out: &mut [u8; DIGEST_SIZE]) -> Result<(), CryptoError> {
        // Use the state inside the `Result`: moving it out would copy it.
        match &mut Self::init(key) {
            Ok(ctx) => {
                for part in data {
                    ctx.update(part)?;
                }
                ctx.finalize(out)
            }
            Err(e) => Err(*e),
        }
    }

    /// NIST SP 800-108 KDF in Counter Mode (`KDFa`), as described by
    /// [`kdfa`](crate::crypto::kdfa).
    ///
    /// Defaults to [`default_kdfa`].
    fn kdfa(
        key: &[u8],
        label: &CStr,
        context: (&[u8], &[u8]),
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        default_kdfa::<Self, DIGEST_SIZE>(key, label, context, out)
    }

    /// XORs the output of `KDFa` into `data`, as described by
    /// [`kdfa_xor`](crate::crypto::kdfa_xor).
    ///
    /// Defaults to [`default_kdfa_xor`].
    fn kdfa_xor(
        key: &[u8],
        label: &CStr,
        context: (&[u8], &[u8]),
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        default_kdfa_xor::<Self, DIGEST_SIZE>(key, label, context, data)
    }
}

impl<const DIGEST_SIZE: usize> HmacState<DIGEST_SIZE> for ! {
    fn init(_: &[u8]) -> Result<Self, CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn update(&mut self, _: &[u8]) -> Result<(), CryptoError> {
        match *self {}
    }
    fn finalize(&mut self, _: &mut [u8; DIGEST_SIZE]) -> Result<(), CryptoError> {
        match *self {}
    }
}
