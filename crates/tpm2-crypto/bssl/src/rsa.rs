//! RSA 1024-4096 with BoringSSL: key generation and import, RSASSA-PKCS1-v1_5, RSASSA-PSS,
//! RSAES-PKCS1-v1_5, RSAES-OAEP and raw RSA (`TPM_ALG_NULL`).

use crate::bssl::{BsslError, RsaPrivate, RsaPublic};
use crate::{BsslCryptoProvider, BsslRng, output, verified};
use tpm2::TpmiAlgHash;
use tpm2::TpmtHa;
use tpm2::crypto::CryptoError;
use tpm2::crypto::backend::{PrivateKey, Rsa, RsaKey};

/// A validated RSA public key with a `MOD`-byte modulus for `BsslCryptoProvider`.
pub struct BsslRsaPublicKey<const MOD: usize>(RsaPublic);

/// A validated RSA private key with a `MOD`-byte modulus and `PRIME`-byte prime factors for
/// `BsslCryptoProvider` (a BoringSSL `RSA` with all its CRT components).
pub struct BsslRsa<const MOD: usize, const PRIME: usize> {
    public: BsslRsaPublicKey<MOD>,
    private: RsaPrivate,
}

impl<const MOD: usize, const PRIME: usize> BsslRsa<MOD, PRIME> {
    fn new(private: RsaPrivate) -> Result<Self, CryptoError> {
        Ok(Self {
            public: BsslRsaPublicKey(private.public()?),
            private,
        })
    }
}

/// Maps an error of an operation without semantic failures: [`BsslError::InvalidData`] (e.g. a
/// key too small for the signature encoding, which the dispatch code rules out) is
/// [`CryptoError::Internal`].
fn internal(err: BsslError) -> CryptoError {
    err.into()
}

impl<const MOD: usize, const PRIME: usize> PrivateKey<MOD, PRIME, BsslRng, u32>
    for BsslRsa<MOD, PRIME>
{
    type PublicKey = BsslRsaPublicKey<MOD>;

    /// With the RNG of `from_entropy`, generates the key with BoringSSL's
    /// `RSA_generate_key_ex`; with the deterministic RNG of `from_seed`, draws the prime
    /// candidates from it, so that the key is deterministic.
    fn generate(rng: &mut BsslRng, exponent: u32) -> Result<Self, CryptoError> {
        let private = if rng.is_seeded() {
            RsaPrivate::generate_from_rng(MOD * 8, exponent, rng)
        } else {
            RsaPrivate::generate(MOD * 8, exponent)
        }?;
        Self::new(private)
    }

    fn load(public: Self::PublicKey, private: &[u8; PRIME]) -> Result<Option<Self>, CryptoError> {
        let mut modulus = [0u8; MOD];
        public.0.modulus(&mut modulus)?;
        let Some(private) = output(RsaPrivate::from_prime(
            &modulus,
            private,
            public.0.exponent(),
        ))?
        else {
            return Ok(None);
        };
        Ok(Some(Self { public, private }))
    }

    fn store(&self, out: &mut [u8; PRIME]) -> Result<(), CryptoError> {
        self.private.prime(out).map_err(internal)
    }

    fn as_public(&self) -> &Self::PublicKey {
        &self.public
    }

    fn load_public(
        exponent: u32,
        public: &[u8; MOD],
    ) -> Result<Option<Self::PublicKey>, CryptoError> {
        // TPM 2.0 Part 1: the modulus has its most significant bit set and is odd.
        if public[0] & 0x80 == 0 || public[MOD - 1] & 1 == 0 {
            return Ok(None);
        }
        Ok(output(RsaPublic::new(public, exponent))?.map(BsslRsaPublicKey))
    }

    fn store_public(public: &Self::PublicKey, out: &mut [u8; MOD]) -> Result<(), CryptoError> {
        public.0.modulus(out).map_err(internal)
    }
}

/// The largest `RSASSA-PSS` salt length up to the digest size `digest_len` for a `mod_len`-byte
/// modulus (TPM 2.0 `PssEncode`; `emLen = mod_len`, as the modulus has its top bit set).
fn pss_salt_len(mod_len: usize, digest_len: usize) -> usize {
    digest_len.min(mod_len.saturating_sub(digest_len + 2))
}

/// RSA with BoringSSL. The `rng` arguments are unused: BoringSSL blinds private key operations
/// and draws padding randomness from its own RNG.
impl<const MOD: usize, const PRIME: usize> RsaKey<MOD, PRIME, BsslRng> for BsslRsa<MOD, PRIME> {
    fn exponent(public: &Self::PublicKey) -> u32 {
        public.0.exponent()
    }

    fn raw_encrypt(
        public: &Self::PublicKey,
        m: &[u8; MOD],
        out: &mut [u8; MOD],
    ) -> Result<Option<()>, CryptoError> {
        output(public.0.encrypt_raw(m, out))
    }

    fn raw_decrypt(
        &self,
        _rng: &mut BsslRng,
        c: &[u8; MOD],
        out: &mut [u8; MOD],
    ) -> Result<Option<()>, CryptoError> {
        output(self.private.decrypt_raw(c, out))
    }

    fn oaep_encrypt(
        public: &Self::PublicKey,
        _rng: &mut BsslRng,
        hash: TpmiAlgHash,
        label: &[u8],
        m: &[u8],
        out: &mut [u8; MOD],
    ) -> Result<Option<()>, CryptoError> {
        output(public.0.encrypt_oaep(hash, label, m, out))
    }

    fn oaep_decrypt(
        &self,
        _rng: &mut BsslRng,
        hash: TpmiAlgHash,
        label: &[u8],
        c: &[u8; MOD],
        out: &mut [u8; MOD],
    ) -> Result<Option<usize>, CryptoError> {
        output(self.private.decrypt_oaep(hash, label, c, out))
    }

    fn rsaes_encrypt(
        public: &Self::PublicKey,
        _rng: &mut BsslRng,
        m: &[u8],
        out: &mut [u8; MOD],
    ) -> Result<Option<()>, CryptoError> {
        output(public.0.encrypt_pkcs1(m, out))
    }

    fn rsaes_decrypt(
        &self,
        _rng: &mut BsslRng,
        c: &[u8; MOD],
        out: &mut [u8; MOD],
    ) -> Result<Option<usize>, CryptoError> {
        output(self.private.decrypt_pkcs1(c, out))
    }

    fn rsassa_sign(
        &self,
        _rng: &mut BsslRng,
        digest: TpmtHa<'_>,
        out: &mut [u8; MOD],
    ) -> Result<(), CryptoError> {
        self.private
            .sign_pkcs1(digest.hash_alg(), digest.digest(), out)
            .map_err(internal)
    }

    fn rsassa_verify(
        public: &Self::PublicKey,
        digest: TpmtHa<'_>,
        sig: &[u8; MOD],
    ) -> Result<bool, CryptoError> {
        verified(
            public
                .0
                .verify_pkcs1(digest.hash_alg(), digest.digest(), sig),
        )
    }

    fn rsapss_sign(
        &self,
        _rng: &mut BsslRng,
        digest: TpmtHa<'_>,
        out: &mut [u8; MOD],
    ) -> Result<(), CryptoError> {
        let salt_len = pss_salt_len(MOD, digest.digest().len());
        self.private
            .sign_pss(digest.hash_alg(), digest.digest(), salt_len, out)
            .map_err(internal)
    }

    fn rsapss_verify(
        public: &Self::PublicKey,
        digest: TpmtHa<'_>,
        sig: &[u8; MOD],
    ) -> Result<bool, CryptoError> {
        verified(public.0.verify_pss(digest.hash_alg(), digest.digest(), sig))
    }

    fn store_crt(&self, out: &mut [[u8; PRIME]; 5]) -> Result<(), CryptoError> {
        self.private.crt(out).map_err(internal)
    }
}

/// RSA-1024 key for `BsslCryptoProvider`.
pub type BsslRsa1024 = BsslRsa<128, 64>;
/// RSA-2048 key for `BsslCryptoProvider`.
pub type BsslRsa2048 = BsslRsa<256, 128>;
/// RSA-3072 key for `BsslCryptoProvider`.
pub type BsslRsa3072 = BsslRsa<384, 192>;
/// RSA-4096 key for `BsslCryptoProvider`.
pub type BsslRsa4096 = BsslRsa<512, 256>;

impl Rsa for BsslCryptoProvider {
    type Rsa1024 = BsslRsa1024;
    type Rsa2048 = BsslRsa2048;
    type Rsa3072 = BsslRsa3072;
    type Rsa4096 = BsslRsa4096;
}
