//! Helpers shared by the test modules.

use core::fmt;

use tpm2::{
    AlgSym, TpmiAlgCipherMode, TpmiAlgHash, TpmiMldsaParms, TpmiMlkemParms, TpmiRsaKeyBits, TpmtHa,
    crypto::{Random, Rng},
};

use crate::Check;

/// Every hash algorithm.
pub(crate) const HASHES: &[TpmiAlgHash] = &[
    TpmiAlgHash::Sha1,
    TpmiAlgHash::Sha256,
    TpmiAlgHash::Sha384,
    TpmiAlgHash::Sha512,
    TpmiAlgHash::Sm3_256,
    TpmiAlgHash::Sha3_256,
    TpmiAlgHash::Sha3_384,
    TpmiAlgHash::Sha3_512,
];

/// Every block cipher.
pub(crate) const CIPHERS: &[AlgSym] = &[
    AlgSym::Aes128,
    AlgSym::Aes192,
    AlgSym::Aes256,
    AlgSym::Sm4_128,
    AlgSym::Camellia128,
    AlgSym::Camellia192,
    AlgSym::Camellia256,
];

/// Every block cipher mode, in the order of the mode vectors.
pub(crate) const MODES: &[TpmiAlgCipherMode] = &[
    TpmiAlgCipherMode::Ctr,
    TpmiAlgCipherMode::Ofb,
    TpmiAlgCipherMode::Cbc,
    TpmiAlgCipherMode::Cfb,
    TpmiAlgCipherMode::Ecb,
];

/// Every RSA key size.
pub(crate) const RSA_KEY_BITS: &[TpmiRsaKeyBits] = &[
    TpmiRsaKeyBits::Rsa1024,
    TpmiRsaKeyBits::Rsa2048,
    TpmiRsaKeyBits::Rsa3072,
    TpmiRsaKeyBits::Rsa4096,
];

/// Every ML-KEM parameter set.
pub(crate) const MLKEM: &[TpmiMlkemParms] = &[
    TpmiMlkemParms::Mlkem512,
    TpmiMlkemParms::Mlkem768,
    TpmiMlkemParms::Mlkem1024,
];

/// Every ML-DSA parameter set.
pub(crate) const MLDSA: &[TpmiMldsaParms] = &[
    TpmiMldsaParms::Mldsa44,
    TpmiMldsaParms::Mldsa65,
    TpmiMldsaParms::Mldsa87,
];

/// Returns `len` bytes of deterministic, non-repeating test data.
pub(crate) fn pattern(len: usize, seed: u8) -> Vec<u8> {
    let mut state = 0x9E37_79B9_u32 ^ u32::from(seed);
    (0..len)
        .map(|_| {
            // xorshift32
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let [byte, ..] = state.to_be_bytes();
            byte
        })
        .collect()
}

/// Returns a deterministic RNG of the backend, seeded with `label`, so that
/// test failures are reproducible.
pub(crate) fn seeded_rng<C: Random>(c: &C, label: &str) -> C::Rng {
    c.rng_seeded(label.as_bytes()).check("Random::rng_seeded")
}

/// Fills a new buffer of `len` bytes from `rng`.
pub(crate) fn fill<R: Rng>(rng: &mut R, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rng.fill_bytes(&mut out).check("Rng::fill_bytes");
    out
}

/// Creates a [`TpmtHa`] from a digest of the right size.
pub(crate) fn tpmt_ha(alg: TpmiAlgHash, digest: &[u8]) -> TpmtHa<'_> {
    TpmtHa::new(alg, digest).expect("digest has the wrong size")
}

/// Returns a hash algorithm with the same digest size as `alg`, if any.
pub(crate) fn same_size_hash(alg: TpmiAlgHash) -> Option<TpmiAlgHash> {
    HASHES
        .iter()
        .copied()
        .find(|&other| other != alg && other.digest_size() == alg.digest_size())
}

/// Returns a copy of `data` with one bit of byte `index` flipped.
pub(crate) fn flip(data: &[u8], index: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    out[index] ^= 0x01;
    out
}

/// Adds `n` to the big-endian integer `data` (modulo `256^len`).
pub(crate) fn add_be(data: &[u8], n: u8) -> Vec<u8> {
    let mut out = data.to_vec();
    let mut carry = n;
    for byte in out.iter_mut().rev() {
        let (sum, overflow) = byte.overflowing_add(carry);
        *byte = sum;
        carry = u8::from(overflow);
        if carry == 0 {
            break;
        }
    }
    out
}

/// Formats bytes as (possibly truncated) hex.
pub(crate) struct Hex<'a>(pub &'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const MAX: usize = 48;
        for byte in self.0.iter().take(MAX) {
            write!(f, "{byte:02x}")?;
        }
        if self.0.len() > MAX {
            write!(f, "... ({} bytes)", self.0.len())?;
        }
        Ok(())
    }
}

impl fmt::Debug for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Asserts that `actual == expected`, printing (truncated) hex on failure.
#[track_caller]
pub(crate) fn assert_bytes(actual: &[u8], expected: &[u8], what: impl fmt::Display) {
    assert!(
        actual == expected,
        "{what}: mismatch\n  actual:   {}\n  expected: {}",
        Hex(actual),
        Hex(expected),
    );
}
