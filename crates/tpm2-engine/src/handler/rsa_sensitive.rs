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
use tpm2::crypto::{Crypto, CryptoError, RsaPrivateKey};
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

impl<'b, C: Crypto, P: Platform<Crypto = C>> CommandHandler<'b, P> {
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
        let key = match crate::handler::rsa_private_key::<C>(parms, modulus, prime) {
            Ok(Some(key)) => key,
            Ok(None) | Err(_) => return Ok(None),
        };
        self.rsa_crt_value(&key, prime, out).map(Some)
    }

    /// Writes the CRT form of the RSA key `key`, whose prime-only form is `prime`, in the
    /// reference's layout ([`order_crt_for_prime`]) to `out` and returns its length.
    pub(crate) fn rsa_crt_value(
        &self,
        key: &RsaPrivateKey<C>,
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
    pub(crate) fn rsa_primes_in_range(&self, key: &RsaPrivateKey<C>, modulus: &[u8]) -> bool {
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
