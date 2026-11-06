//! [`Hash`] and [`Hmac`] for [`CruxCryptoProvider`].

use crate::CruxCryptoProvider;
use libcrux_sha2::Digest as _;
use tpm2::crypto::CryptoError;
use tpm2::crypto::backend::{Hash, HashState, Hmac, HmacState};

/// SHA-1 hash state for `CruxCryptoProvider` (RustCrypto `sha1`).
pub struct CruxSha1(sha1::Sha1);

impl HashState<20> for CruxSha1 {
    fn init() -> Result<Self, CryptoError> {
        use sha1::Digest as _;
        Ok(Self(sha1::Sha1::new()))
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        use sha1::Digest as _;
        self.0.update(data);
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8; 20]) -> Result<(), CryptoError> {
        use sha1::Digest as _;
        out.copy_from_slice(&self.0.finalize_reset());
        Ok(())
    }
}

/// Defines a `libcrux-sha2` hash state.
macro_rules! libcrux_hash {
    ($(#[$doc:meta])* $name:ident, $inner:ty, $size:literal) => {
        $(#[$doc])*
        pub struct $name($inner);

        impl HashState<$size> for $name {
            fn init() -> Result<Self, CryptoError> {
                Ok(Self(<$inner>::new()))
            }

            fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
                self.0.update(data);
                Ok(())
            }

            fn finalize(&mut self, out: &mut [u8; $size]) -> Result<(), CryptoError> {
                self.0.finish(out);
                Ok(())
            }
        }
    };
}

libcrux_hash!(
    /// SHA-256 hash state for `CruxCryptoProvider` (`libcrux-sha2`).
    CruxSha256,
    libcrux_sha2::Sha256,
    32
);
libcrux_hash!(
    /// SHA-384 hash state for `CruxCryptoProvider` (`libcrux-sha2`).
    CruxSha384,
    libcrux_sha2::Sha384,
    48
);
libcrux_hash!(
    /// SHA-512 hash state for `CruxCryptoProvider` (`libcrux-sha2`).
    CruxSha512,
    libcrux_sha2::Sha512,
    64
);

impl Hash for CruxCryptoProvider {
    type Sha1 = CruxSha1;
    type Sha256 = CruxSha256;
    type Sha384 = CruxSha384;
    type Sha512 = CruxSha512;
    type Sm3_256 = !;
    type Sha3_256 = !;
    type Sha3_384 = !;
    type Sha3_512 = !;
}

/// Defines a RustCrypto `hmac` state.
///
/// HMAC accepts keys of any length, so [`HmacState::init`] only fails
/// ([`CryptoError::Internal`]) if the `hmac` crate rejects the key, which it
/// never does.
macro_rules! rust_crypto_hmac {
    ($(#[$doc:meta])* $name:ident, $digest:ty, $size:literal) => {
        $(#[$doc])*
        pub struct $name(hmac::Hmac<$digest>);

        impl HmacState<$size> for $name {
            fn init(key: &[u8]) -> Result<Self, CryptoError> {
                use hmac::Mac as _;
                hmac::Hmac::<$digest>::new_from_slice(key)
                    .map(Self)
                    .map_err(|_| CryptoError::Internal)
            }

            fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
                use hmac::Mac as _;
                self.0.update(data);
                Ok(())
            }

            fn finalize(&mut self, out: &mut [u8; $size]) -> Result<(), CryptoError> {
                use hmac::Mac as _;
                out.copy_from_slice(&self.0.finalize_reset().into_bytes());
                Ok(())
            }
        }
    };
}

rust_crypto_hmac!(
    /// HMAC-SHA-1 state for `CruxCryptoProvider` (RustCrypto `hmac`).
    CruxHmacSha1,
    sha1::Sha1,
    20
);
rust_crypto_hmac!(
    /// HMAC-SHA-256 state for `CruxCryptoProvider` (RustCrypto `hmac`).
    CruxHmacSha256,
    sha2::Sha256,
    32
);
rust_crypto_hmac!(
    /// HMAC-SHA-384 state for `CruxCryptoProvider` (RustCrypto `hmac`).
    CruxHmacSha384,
    sha2::Sha384,
    48
);
rust_crypto_hmac!(
    /// HMAC-SHA-512 state for `CruxCryptoProvider` (RustCrypto `hmac`).
    CruxHmacSha512,
    sha2::Sha512,
    64
);

impl Hmac for CruxCryptoProvider {
    type Sha1 = CruxHmacSha1;
    type Sha256 = CruxHmacSha256;
    type Sha384 = CruxHmacSha384;
    type Sha512 = CruxHmacSha512;
    type Sm3_256 = !;
    type Sha3_256 = !;
    type Sha3_384 = !;
    type Sha3_512 = !;
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// FIPS 180 "abc" vectors, in one shot and split across updates.
    #[test]
    fn hash_known_answers() {
        fn check<H: HashState<N>, const N: usize>(expected: [u8; N]) {
            let mut out = [0u8; N];
            H::hash(&[b"abc"], &mut out).unwrap();
            assert_eq!(out, expected);
            let mut state = H::init().unwrap();
            state.update(b"a").unwrap();
            state.update(b"").unwrap();
            state.update(b"bc").unwrap();
            state.finalize(&mut out).unwrap();
            assert_eq!(out, expected);
        }
        check::<CruxSha1, 20>(hex!("a9993e364706816aba3e25717850c26c9cd0d89d"));
        check::<CruxSha256, 32>(hex!(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        ));
        check::<CruxSha384, 48>(hex!(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
            "8086072ba1e7cc2358baeca134c825a7"
        ));
        check::<CruxSha512, 64>(hex!(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        ));
    }

    /// RFC 4231 test case 2 (and RFC 2202 test case 2 for SHA-1).
    #[test]
    fn hmac_known_answers() {
        fn check<H: HmacState<N>, const N: usize>(expected: [u8; N]) {
            let mut out = [0u8; N];
            H::hmac(b"Jefe", &[b"what do ya want ", b"for nothing?"], &mut out).unwrap();
            assert_eq!(out, expected);
        }
        check::<CruxHmacSha1, 20>(hex!("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"));
        check::<CruxHmacSha256, 32>(hex!(
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        ));
        check::<CruxHmacSha384, 48>(hex!(
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e"
            "8e2240ca5e69e2c78b3239ecfab21649"
        ));
        check::<CruxHmacSha512, 64>(hex!(
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
            "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        ));
    }

    #[test]
    fn hash_dispatch_and_unsupported_algorithms() {
        use tpm2::TpmiAlgHash;
        let mut buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let digest =
            tpm2::crypto::hash::<CruxCryptoProvider>(TpmiAlgHash::Sha256, &[b"abc"], &mut buf)
                .unwrap();
        assert_eq!(
            digest.digest(),
            hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert!(matches!(
            <<CruxCryptoProvider as Hash>::Sm3_256 as HashState<32>>::init(),
            Err(CryptoError::Unsupported)
        ));
        assert!(matches!(
            <<CruxCryptoProvider as Hmac>::Sha3_512 as HmacState<64>>::init(b"key"),
            Err(CryptoError::Unsupported)
        ));
    }
}
