//! [`Cmac`] and [`CmacState`].

use crate::crypto::{Block, CryptoError};

/// CMAC, with one associated type per symmetric cipher algorithm.
///
/// This is similar to [`Hmac`](super::Hmac), except that the states are
/// initialized from a fixed-size key and always produce a 16-byte MAC. See the
/// [module documentation](super) for how to implement this trait.
pub trait Cmac {
    type Aes128: CmacState<16>;
    type Aes192: CmacState<24>;
    type Aes256: CmacState<32>;
    type Sm4_128: CmacState<16>;
    type Camellia128: CmacState<16>;
    type Camellia192: CmacState<24>;
    type Camellia256: CmacState<32>;
}

/// Streaming CMAC state for a single cipher algorithm, with a key of
/// `KEY_SIZE` bytes.
pub trait CmacState<const KEY_SIZE: usize>: Sized {
    /// Initializes a new CMAC state from `key`.
    fn init(key: &[u8; KEY_SIZE]) -> Result<Self, CryptoError>;

    /// Feeds `data` into the CMAC state.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError>;

    /// Writes the final MAC into `out`. The state is then spent.
    fn finalize(&mut self, out: &mut Block) -> Result<(), CryptoError>;

    /// Computes the CMAC of the concatenation of `data` under `key` in one shot.
    #[inline(never)]
    fn cmac(key: &[u8; KEY_SIZE], data: &[&[u8]], out: &mut Block) -> Result<(), CryptoError> {
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
}

impl<const KEY_SIZE: usize> CmacState<KEY_SIZE> for ! {
    fn init(_: &[u8; KEY_SIZE]) -> Result<Self, CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn update(&mut self, _: &[u8]) -> Result<(), CryptoError> {
        match *self {}
    }
    fn finalize(&mut self, _: &mut Block) -> Result<(), CryptoError> {
        match *self {}
    }
}
