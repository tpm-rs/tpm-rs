//! The RSA private key in a sensitive area (`TPMU_SENSITIVE_COMPOSITE.rsa`, a
//! `TPM2B_PRIVATE_KEY_RSA`).
//!
//! TPM 2.0 Part 2, TPM2B_PRIVATE_KEY_RSA: "`RSA_PRIVATE_SIZE` is a vendor specific value that
//! can be (`MAX_RSA_KEY_BYTES` / 2) or ((`MAX_RSA_KEY_BYTES` \* 5) / 2). The larger size would
//! only apply to keys that have *fixedTPM* parents." This TPM, like the TCG reference
//! (`CRT_FORMAT_RSA = YES`, `MarshalSensitive()` in `Object_spt.c`), uses the larger size:
//!
//! - A private area protected by a *fixedTPM* parent (`TPM2_Create`, `TPM2_CreateLoaded`,
//!   `TPM2_Import` and `TPM2_ObjectChangeAuth` under such a parent) holds the CRT form of the key:
//!   five values of the size of a prime, in the reference's packed layout
//!   (`TpmRsaUtil_PackExponent()`): `P | Q | dP | dQ | qInv`, where `P` is the prime that the
//!   prime-only form holds and `Q = N / P` the other one, while `dP`, `dQ` and `qInv` are computed
//!   with the *larger* of the two primes as "p" (`TpmRsaUtil_MakePgreaterThanQ()` swaps only
//!   the prime pointers, not their storage): `dP = e^-1 mod (max(P, Q) - 1)`,
//!   `dQ = e^-1 mod (min(P, Q) - 1)` and `qInv = min(P, Q)^-1 mod max(P, Q)`. Such a blob can
//!   only have been produced by this TPM (only it knows the parent's seed).
//! - Every other sensitive area (any other parent, `TPM2_Duplicate`, and the sensitive areas
//!   that `TPM2_LoadExternal` and `TPM2_Import` take) holds only the prime `P`.
//!
//! `TPM2_Load` under a *fixedTPM* parent accepts both forms; under any other parent (and
//! `TPM2_LoadExternal`) only the prime (`CryptoCommon_ValidateKeys()`: otherwise
//! `TPM_RC_KEY_SIZE`).
//!
//! With the `rsa-sensitive-prime-only` feature, the private areas under a *fixedTPM* parent
//! hold the prime as well (the smaller `RSA_PRIVATE_SIZE`, like Google's production
//! `ibmswtpm2`), see [`WRITES_CRT_FORM`]; `TPM2_Load` still accepts both forms.

use crate::Platform;
use tpm2::crypto::{CryptoError, RsaPrivateKey};
use tpm2::errors::TpmRc;
use tpm2::{Tpm2bPrivateKeyRsa, TpmsRsaParms};

use crate::handler::CommandHandler;

/// The number of prime-sized values in the CRT form (`P`, `Q`, `dP`, `dQ`, `qInv`).
pub(crate) const CRT_VALUES: usize = 5;

/// The largest RSA sensitive value (`RSA_PRIVATE_SIZE`, the capacity of `TPM2B_PRIVATE_KEY_RSA`).
pub(crate) const RSA_PRIVATE_SIZE: usize = Tpm2bPrivateKeyRsa::CAP;

/// Whether the private areas this TPM writes under a *fixedTPM* parent hold the CRT form of an
/// RSA key (otherwise the prime, with the `rsa-sensitive-prime-only` feature).
pub(crate) const WRITES_CRT_FORM: bool = !cfg!(feature = "rsa-sensitive-prime-only");

/// Returns `bytes` without its leading zero octets (the number it represents).
fn significant(bytes: &[u8]) -> &[u8] {
    &bytes[bytes.iter().take_while(|&&b| b == 0).count()..]
}

/// Rearranges the CRT form `crt` (`p | q | dP | dQ | qInv` with `p` the larger prime, see
/// [`RsaPrivateKey::crt`]) into the reference's layout for a key
/// whose prime-only form is `prime`: if `prime` is the smaller prime, the two primes are
/// swapped, the other values keep their places.
///
/// Returns `false` if `crt` is not five equal values or `prime` is neither of its primes.
pub(crate) fn order_crt_for_prime(prime: &[u8], crt: &mut [u8]) -> bool {
    if crt.is_empty() || !crt.len().is_multiple_of(CRT_VALUES) {
        return false;
    }
    let size = crt.len() / CRT_VALUES;
    let (first, rest) = crt.split_at_mut(size);
    let second = &mut rest[..size];
    let prime = significant(prime);
    if prime == significant(first) {
        true
    } else if prime == significant(second) {
        first.swap_with_slice(second);
        true
    } else {
        false
    }
}

/// Splits an RSA sensitive value that is loaded under a *fixedTPM* parent into the prime and
/// whether the value is the CRT form, for a modulus of `modulus_len` bytes.
///
/// The prime-only form is half the modulus size; the CRT form is five values of half the
/// modulus size each (`CryptoRsa_LoadPrivateExponent()`). Returns `None` (`TPM_RC_BINDING`)
/// for any other size.
pub(crate) fn split_sensitive_value(value: &[u8], modulus_len: usize) -> Option<(&[u8], bool)> {
    if value.len() * 2 == modulus_len {
        Some((value, false))
    } else if value.len().is_multiple_of(CRT_VALUES)
        && (value.len() / CRT_VALUES) * 2 == modulus_len
    {
        Some((&value[..value.len() / CRT_VALUES], true))
    } else {
        None
    }
}

/// The largest prime of a key that passes the size checks: one byte more than half the largest
/// modulus (`Q = N / P` with `P` of half the modulus size can have one bit more than `P`).
const MAX_PRIME_BYTES: usize = RSA_PRIVATE_SIZE / CRT_VALUES + 1;

/// Returns the number of significant bits of the big-endian number `x`.
fn bit_length(x: &[u8]) -> usize {
    let x = significant(x);
    x.first()
        .map_or(0, |&top| 8 * x.len() - top.leading_zeros() as usize)
}

/// Returns the number of significant bits of `x * x` for a big-endian `x` of at most
/// [`MAX_PRIME_BYTES`] significant bytes (schoolbook squaring).
fn square_bit_length(x: &[u8]) -> usize {
    let x = significant(x);
    let mut product = [0u64; 2 * MAX_PRIME_BYTES];
    // Little-endian byte columns; every column sum stays far below 2^64.
    for (i, &a) in x.iter().rev().enumerate() {
        for (j, &b) in x.iter().rev().enumerate() {
            product[i + j] += u64::from(a) * u64::from(b);
        }
    }
    let mut bytes = [0u8; 2 * MAX_PRIME_BYTES];
    let mut carry = 0u64;
    for (k, column) in product.iter().enumerate() {
        let sum = column + carry;
        bytes[bytes.len() - 1 - k] = sum as u8;
        carry = sum >> 8;
    }
    bit_length(&bytes)
}

impl<'b, P: Platform> CommandHandler<'b, P> {
    /// Writes the sensitive value (`TPMU_SENSITIVE_COMPOSITE.rsa`) of the RSA key with the
    /// parameters `parms`, the modulus `modulus` and the prime `prime` (the private value of the
    /// object, [`TransientObject::private`](crate::handler::TransientObject::private)) to `out`
    /// and returns its length: the CRT form if `crt` (a *fixedTPM* parent protects the private
    /// area), otherwise the prime as it is (see the [module documentation](self)).
    ///
    /// Returns `None` if the CRT form is requested and `prime` is not a prime of a valid RSA
    /// key with that public key, or if `prime` does not fit `out`.
    pub(crate) fn rsa_sensitive_value(
        &self,
        parms: &TpmsRsaParms,
        modulus: &[u8],
        prime: &[u8],
        crt: bool,
        out: &mut [u8; RSA_PRIVATE_SIZE],
    ) -> Result<Option<usize>, TpmRc> {
        if !crt {
            let Some(out) = out.get_mut(..prime.len()) else {
                return Ok(None);
            };
            out.copy_from_slice(prime);
            return Ok(Some(prime.len()));
        }
        let key = match crate::handler::rsa_private_key::<P::Crypto>(parms, modulus, prime) {
            Ok(Some(key)) => key,
            Ok(None) | Err(_) => return Ok(None),
        };
        self.rsa_crt_value(&key, prime, out).map(Some)
    }

    /// Writes the CRT form of the RSA key `key`, whose prime-only form is `prime`, in the
    /// reference's layout ([`order_crt_for_prime`]) to `out` and returns its length.
    pub(crate) fn rsa_crt_value(
        &self,
        key: &RsaPrivateKey<P::Crypto>,
        prime: &[u8],
        out: &mut [u8; RSA_PRIVATE_SIZE],
    ) -> Result<usize, TpmRc> {
        let crt_len = key.crt(out).map_err(|_| TpmRc::FAILURE)?.as_slice().len();
        if !order_crt_for_prime(prime, &mut out[..crt_len]) {
            return Err(TpmRc::FAILURE);
        }
        Ok(crt_len)
    }

    /// Returns whether both primes of the RSA key `key` are in the acceptable range for the
    /// modulus `modulus`.
    ///
    /// TPM 2.0 Part 1, "RSA", "Introduction": "The TPM will also validate that the provided and
    /// computed prime factors are in an acceptable range. To be acceptable, the square of the
    /// prime is required to have the same number of significant bits as the public modulus."
    /// The references check only the most significant bit of the provided prime, and the
    /// computed one not at all (`bug-fix-rsa-prime-range.patch`).
    ///
    /// A crypto backend without [`RsaPrivateKey::crt`] (`CryptoError::Unsupported`) cannot
    /// check the range; the key is then accepted (such a backend cannot produce the CRT form
    /// either).
    pub(crate) fn rsa_primes_in_range(
        &self,
        key: &RsaPrivateKey<P::Crypto>,
        modulus: &[u8],
    ) -> bool {
        let mut crt = [0u8; RSA_PRIVATE_SIZE];
        let len = match key.crt(&mut crt) {
            Ok(crt) => crt.as_slice().len(),
            Err(CryptoError::Unsupported) => return true,
            Err(_) => return false,
        };
        let size = len / CRT_VALUES;
        let modulus_bits = bit_length(modulus);
        square_bit_length(&crt[..size]) == modulus_bits
            && square_bit_length(&crt[size..2 * size]) == modulus_bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use tpm2::crypto::{RsaCrtBuffer, RsaPrivateKey, RsaPublicKey};
    use tpm2::{Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmiAlgHash, TpmiRsaKeyBits};
    #[cfg(feature = "dev_crypto_bssl")]
    type Crypto = tpm2_crypto_bssl::BsslCryptoProvider;
    #[cfg(feature = "dev_crypto_crux")]
    use tpm2_crypto_crux::CruxCryptoProvider as Crypto;
    #[cfg(feature = "dev_crypto_rust")]
    use tpm2_crypto_rust::RustCryptoProvider as Crypto;

    /// Keys generated by the C reference's `CryptRsaGenerateKey()` (`n`, the prime it stores
    /// first `p`, and SHA-256 of `n || p ||` its packed CRT sensitive area), from
    /// `tpm2_platform_linux`'s `reference_rng::rsa` tests (`CRT_DIGESTS`, which pins the C
    /// outputs): of both sizes, with the larger and with the smaller prime first.
    const REFERENCE_KEYS: [(&[u8], &[u8], [u8; 32]); 4] = [
        // Key 0 (1024 bits, the smaller prime first).
        (
            &hex!(
                "eadebda8df73fc9108dbccb34ef8fe529e17d33395d2606fce9e9920b3cfe620"
                "a176f55bffba9de6cffe1d2f0c349cf0d401dfeed133a2146d1e01127be5a7b1"
                "b03c8cf1bafc013c564a041a3c22f61957e70d6657f85bdd087a77d9ae1effb2"
                "37bc9c3ce11e09470f517dd298677aa9f0a022fda2f47429fa3215c4a36f6cab"
            ),
            &hex!(
                "ec44944aedfcfefa72bcc8000bc493b8401487882d8674c4ed1eb69f58b224b4"
                "f491e884c57b706494eae0bf0d29508c10435cac557ba3a9213886f0c4fc2867"
            ),
            hex!("877d5068669f74d3424dc2d7f4597e513d5c77d65f60d00ac8dac3b0340561ea"),
        ),
        // Key 1 (2048 bits, the smaller prime first).
        (
            &hex!(
                "a27054b164db01fde5c250a0530cfeadcdbf83855e2b68e97e36a2e0efddbb52"
                "9092a31e869a6504a377f5c9359829d0027aa88afa85c15cf1f09b9b72bab5f2"
                "e847451b7e02c84ffb61b7664af341c5d90d6ceff2a8f1908922be495c732ad3"
                "c93ad01d32ddd3b3e4e9081cfda336869c471f44f134725afe4724ddf597beab"
                "2ff5363657de4e9c1a02b975b9ddd49f9794a037e2305db76cc0a7a1c41bbce0"
                "f5293f45b0800123936a34b34447c8b27d0de52c772930286362b437f4293fcb"
                "f26dad869144e81896bdfaffbfb2104d60fcc89a9ad657d0c63fa5c54df31fbf"
                "8d8a04237677ade87e5113575bc471c8409508505c84fedfce7b437508373ebf"
            ),
            &hex!(
                "bf5991fca14ef20ebcffdd932c37f99cd5033c8c499f8684c74e8b280613a778"
                "da7983fd19217c77ff76f94f1dfc3fa181ad17ccd9093ba56d51c9204d5751a4"
                "7e805a60968328b84f0c12f92e8f731631efd4f37f1dfc01e88d705dcce9d1be"
                "54f44b8ac2e5854301e5db89227e4b1cd88c6f148e30fcafcf842f6e9de8c823"
            ),
            hex!("8b89d34ac7a9f754ee6ac536d777b8897c28619542040f93b3978835cdbfed91"),
        ),
        // Key 2 (1024 bits, the larger prime first).
        (
            &hex!(
                "e5084436594bf3abb9e4b0e2df458a4c54be4b0c885e56aba8a2594175ea11cf"
                "1e6c4f27054685671040efb809d0e69d3b6e1997495a4f742a6986e2b9bbf366"
                "3111bde476c368e489a13afc69fac2c8dc39ec82f29f28e17584a3e9f02c5f46"
                "144551ed4756ed191090f4e733024c9825623424e9af6d7da7efb190675fcfc1"
            ),
            &hex!(
                "feb373610710d5e9a2287dd62b6be577ce598312cf1bd1fb881a41e8ab4bf68f"
                "b5af164236599e2a9f82751228aef27f74f7a3f1ec84b8a34c65f1e49750d175"
            ),
            hex!("2bb6a03c43cd1c452424272b51b87ae9e52c34cf3dcc199d5ce4850e38f036c9"),
        ),
        // Key 7 (2048 bits, the larger prime first).
        (
            &hex!(
                "9293e42d289b157ef2a4e873ed12eada773c63b39a796ad3810349da4054d3e4"
                "be3d02cec4eac71b4359b15cf77f99b4ae9ec84491a7f12fdd9330b26a5bcb47"
                "ad0a3bff5158c6f91f02326427b66d735c8a7fc3f42cbf039c1fcc13dcf0a0dd"
                "71616db20b0646d6a304103f8fb6e6e58813c2ce6efa14eaa8fa31b5b239742c"
                "e6562c00cfd58208306f9c8f6ab100cb749e73fb664a33b4e967b1f92d4941fb"
                "a7cf33d41c485dea1da56dd6514da41e16ba2511e050f412b88b54ea12a8c0a5"
                "a9512097417c41211b2c5b108c973dffe38a3a37667e9ebcf02edfb6e6a900af"
                "c36678e8c2b1ba9420b561828466774e02304d005880f7b66060c1814b286d6f"
            ),
            &hex!(
                "cba30d1ad72691aafbd95cc9b2452d86d2b1f9f6387b389b789b09f764f5a553"
                "78aac107ef7f4fa7c96418182fdb84f0f06eda142419e1f58d60ca7b975d8d2d"
                "90b100316627020d6adc497fa1e04d64c007531ee7a48f90cf55d16f61effeee"
                "74e65e667fca6431d048d273eccca69fc01cc76d18cd3315c56d92e3e3c56525"
            ),
            hex!("32f777e1398ef7dbc1140ad4f339c90f44a7b1b668b1d02ce39acd398b3f5c7c"),
        ),
    ];

    /// The CRT form that tpm-rs stores under fixedTPM parents (the backend's CRT values
    /// rearranged around the prime-only form) is byte for byte the packed sensitive area of the
    /// C reference's `CryptRsaGenerateKey()` ([`REFERENCE_KEYS`]), both when the reference's first
    /// prime is the larger and when it is the smaller one.
    #[test]
    fn crt_form_matches_the_reference_packed_sensitive_area() {
        for (i, (n, p, digest)) in REFERENCE_KEYS.into_iter().enumerate() {
            let bits = TpmiRsaKeyBits::new(u16::try_from(n.len() * 8).unwrap()).unwrap();
            let modulus = Tpm2bPublicKeyRsa::new(n).unwrap();
            let public = RsaPublicKey::<Crypto>::load(bits, 65537, modulus)
                .unwrap()
                .unwrap();
            let key = RsaPrivateKey::load(public, Tpm2bPrivateKeyRsa::new(p).unwrap())
                .unwrap()
                .unwrap();
            let mut buf: RsaCrtBuffer = [0u8; core::mem::size_of::<RsaCrtBuffer>()];
            let crt_len = key.crt(&mut buf).unwrap().as_slice().len();
            let mut crt = [0u8; core::mem::size_of::<RsaCrtBuffer>()];
            crt[..crt_len].copy_from_slice(&buf[..crt_len]);
            assert!(order_crt_for_prime(p, &mut crt[..crt_len]));
            let mut sha = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
            let sha = tpm2::crypto::hash::<Crypto>(
                TpmiAlgHash::Sha256,
                &[n, p, &crt[..crt_len]],
                &mut sha,
            )
            .unwrap();
            assert_eq!(sha.digest(), digest, "key {i}");
        }
    }

    /// The primes swap places only if the prime-only form is the smaller prime.
    #[test]
    fn order_crt_for_prime_keeps_or_swaps_the_primes() {
        let crt = [9u8, 9, 3, 3, 1, 1, 2, 2, 4, 4];
        let mut kept = crt;
        assert!(order_crt_for_prime(&[9, 9], &mut kept));
        assert_eq!(kept, crt);
        let mut swapped = crt;
        assert!(order_crt_for_prime(&[0, 3, 3], &mut swapped));
        assert_eq!(swapped, [3, 3, 9, 9, 1, 1, 2, 2, 4, 4]);
        assert!(!order_crt_for_prime(&[5, 5], &mut kept.clone()));
        assert!(!order_crt_for_prime(&[9, 9], &mut [9, 9, 3, 3]));
        assert!(!order_crt_for_prime(&[], &mut []));
    }

    /// `square_bit_length` squares exactly, also at the boundaries of the bit length.
    #[test]
    fn square_bit_length_is_exact() {
        assert_eq!(square_bit_length(&[]), 0);
        assert_eq!(square_bit_length(&[0, 1]), 1);
        assert_eq!(square_bit_length(&[0xff]), 16);
        assert_eq!(square_bit_length(&[0x80]), 15);
        // 0xb504 = floor(sqrt(2) * 2^15): its square has 31 bits, the next one's 32.
        assert_eq!(square_bit_length(&[0xb5, 0x04]), 31);
        assert_eq!(square_bit_length(&[0xb5, 0x05]), 32);
        assert_eq!(
            square_bit_length(&[0xff; MAX_PRIME_BYTES]),
            16 * MAX_PRIME_BYTES
        );
        assert_eq!(bit_length(&[0, 0, 0x10, 0]), 13);
    }

    /// A sensitive value under a fixedTPM parent is the prime (half the modulus) or the CRT form
    /// (five halves); every other size is rejected.
    #[test]
    fn split_sensitive_value_accepts_prime_and_crt_sizes() {
        let value = [7u8; 640];
        assert_eq!(
            split_sensitive_value(&value[..128], 256),
            Some((&value[..128], false))
        );
        assert_eq!(
            split_sensitive_value(&value, 256),
            Some((&value[..128], true))
        );
        assert_eq!(
            split_sensitive_value(&value[..320], 128),
            Some((&value[..64], true))
        );
        for len in [0, 127, 129, 256, 321, 324, 639] {
            assert_eq!(
                split_sensitive_value(&value[..len], 256),
                None,
                "length {len}"
            );
        }
        // (size / 5) * 2 matches, but the size is not a multiple of five.
        assert_eq!(split_sensitive_value(&value[..322], 128), None);
    }
}
