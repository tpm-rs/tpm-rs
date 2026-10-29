//! [`Hash`] and [`HashState`].

use core::ffi::CStr;

use super::default_kdfe;
use crate::crypto::CryptoError;

/// Cryptographic hash functions, with one associated type per hash algorithm.
///
/// See the [module documentation](super) for how to implement this trait.
pub trait Hash {
    type Sha1: HashState<20>;
    type Sha256: HashState<32>;
    type Sha384: HashState<48>;
    type Sha512: HashState<64>;
    type Sm3_256: HashState<32>;
    type Sha3_256: HashState<32>;
    type Sha3_384: HashState<48>;
    type Sha3_512: HashState<64>;
}

/// Streaming hash state for a single hash algorithm, with a digest of
/// `DIGEST_SIZE` bytes.
pub trait HashState<const DIGEST_SIZE: usize>: Sized {
    /// Initializes a new hash state.
    fn init() -> Result<Self, CryptoError>;

    /// Feeds `data` into the hash state.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError>;

    /// Writes the final digest into `out`. The state is then spent.
    fn finalize(&mut self, out: &mut [u8; DIGEST_SIZE]) -> Result<(), CryptoError>;

    /// Computes the digest of the concatenation of `data` in one shot.
    #[inline(never)]
    fn hash(data: &[&[u8]], out: &mut [u8; DIGEST_SIZE]) -> Result<(), CryptoError> {
        // Use the state inside the `Result`: moving it out would copy it.
        match &mut Self::init() {
            Ok(ctx) => {
                for part in data {
                    ctx.update(part)?;
                }
                ctx.finalize(out)
            }
            Err(e) => Err(*e),
        }
    }

    /// NIST SP 800-56A/C One-Step Key Derivation Function (`KDFe`), as
    /// described by [`kdfe`](crate::crypto::kdfe).
    ///
    /// Defaults to [`default_kdfe`].
    fn kdfe(
        z: &[u8],
        label: &CStr,
        party_info: (&[u8], &[u8]),
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        default_kdfe::<Self, DIGEST_SIZE>(z, label, party_info, out)
    }
}

impl<const DIGEST_SIZE: usize> HashState<DIGEST_SIZE> for ! {
    fn init() -> Result<Self, CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn update(&mut self, _: &[u8]) -> Result<(), CryptoError> {
        match *self {}
    }
    fn finalize(&mut self, _: &mut [u8; DIGEST_SIZE]) -> Result<(), CryptoError> {
        match *self {}
    }
}
