//! [`Hash`] implementation.
//!
//! SHA-256, SHA-384 and SHA-512 use libcrux-sha2. libcrux has no SHA-1, so
//! SHA-1 uses the RustCrypto `sha1` crate.

use libcrux_sha2::Digest as _;
use tpm2::crypto::{CryptoError, Finalize, Hash, Update};

use crate::Libcrux;

/// Largest input passed to a single libcrux-sha2 update, which panics on
/// inputs longer than `u32::MAX` bytes.
const MAX_UPDATE_BYTES: usize = 1 << 30;

/// SHA-1 context for [`Hash::sha1`] (RustCrypto `sha1`).
pub struct Sha1(sha1::Sha1);

impl Update for Sha1 {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        sha1::Digest::update(&mut self.0, data);
        Ok(())
    }
}

impl Finalize<20> for Sha1 {
    fn finalize(self, out: &mut [u8; 20]) -> Result<(), CryptoError> {
        out.copy_from_slice(&sha1::Digest::finalize(self.0));
        Ok(())
    }
}

/// Defines a streaming hash context wrapping a libcrux-sha2 state.
macro_rules! libcrux_hash {
    ($(#[$doc:meta])* $name:ident, $state:ty, $len:literal) => {
        $(#[$doc])*
        pub struct $name($state);

        impl Update for $name {
            fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
                for chunk in data.chunks(MAX_UPDATE_BYTES) {
                    self.0.update(chunk);
                }
                Ok(())
            }
        }

        impl Finalize<$len> for $name {
            fn finalize(self, out: &mut [u8; $len]) -> Result<(), CryptoError> {
                self.0.finish(out);
                Ok(())
            }
        }
    };
}

libcrux_hash!(
    /// SHA-256 context for [`Hash::sha256`] (libcrux).
    Sha256,
    libcrux_sha2::Sha256,
    32
);
libcrux_hash!(
    /// SHA-384 context for [`Hash::sha384`] (libcrux).
    Sha384,
    libcrux_sha2::Sha384,
    48
);
libcrux_hash!(
    /// SHA-512 context for [`Hash::sha512`] (libcrux).
    Sha512,
    libcrux_sha2::Sha512,
    64
);

/// Computes `SHA-256(parts[0] || parts[1] || ...)`.
pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut state = libcrux_sha2::Sha256::new();
    for chunk in parts.iter().flat_map(|part| part.chunks(MAX_UPDATE_BYTES)) {
        state.update(chunk);
    }
    let mut digest = [0u8; 32];
    state.finish(&mut digest);
    digest
}

impl Hash for Libcrux {
    type Sha1Context = Sha1;
    fn sha1(&self) -> Result<Sha1, CryptoError> {
        Ok(Sha1(sha1::Digest::new()))
    }

    type Sha256Context = Sha256;
    fn sha256(&self) -> Result<Sha256, CryptoError> {
        Ok(Sha256(libcrux_sha2::Sha256::new()))
    }

    type Sha384Context = Sha384;
    fn sha384(&self) -> Result<Sha384, CryptoError> {
        Ok(Sha384(libcrux_sha2::Sha384::new()))
    }

    type Sha512Context = Sha512;
    fn sha512(&self) -> Result<Sha512, CryptoError> {
        Ok(Sha512(libcrux_sha2::Sha512::new()))
    }

    type Sm3_256Context = !;
    type Sha3_256Context = !;
    type Sha3_384Context = !;
    type Sha3_512Context = !;
}
