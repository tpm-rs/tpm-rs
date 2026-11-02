use crate::bssl::{
    EcGroup, ec_generate_key, ecdsa_sign, ecdsa_verify, rsa_decrypt_null, rsa_decrypt_oaep,
    rsa_decrypt_pkcs1v15, rsa_encrypt_null, rsa_encrypt_oaep, rsa_encrypt_pkcs1v15,
    rsa_generate_key, rsa_import_private_key, rsa_private_key_to_crt, rsa_private_key_to_prime_p,
    rsa_sign_pkcs1v15, rsa_sign_pss, rsa_verify_pkcs1v15, rsa_verify_pss,
};
use crate::{BsslCryptoProvider, RngWrapper, output, verified};
use tpm2::crypto::{Asymmetric, AsymmetricSign, CryptoError, TpmiRsaKeyBits};
use tpm2::{TpmEccCurve, TpmiAlgHash, TpmtHa};

impl AsymmetricSign for BsslCryptoProvider {
    fn rsassa_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        output(rsa_sign_pkcs1v15(
            private_key,
            digest.hash_alg(),
            digest.digest(),
            signature_out,
        ))
    }

    fn rsapss_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        output(rsa_sign_pss(
            private_key,
            digest.hash_alg(),
            digest.digest(),
            signature_out,
        ))
    }

    fn ecdsa_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        let group = match private_key.len() {
            28 => EcGroup::P224,
            32 => EcGroup::P256,
            48 => EcGroup::P384,
            66 => EcGroup::P521,
            // A private scalar of any other length is not a key of a supported curve.
            _ => return Ok(None),
        };
        output(ecdsa_sign(
            group,
            private_key,
            digest.digest(),
            signature_out,
        ))
    }
}

impl Asymmetric for BsslCryptoProvider {
    fn rsassa_verify(
        &self,
        public_key: &[u8],
        exponent: u32,
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        verified(rsa_verify_pkcs1v15(
            public_key,
            exponent,
            digest.hash_alg(),
            digest.digest(),
            signature,
        ))
    }

    fn rsapss_verify(
        &self,
        public_key: &[u8],
        exponent: u32,
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        verified(rsa_verify_pss(
            public_key,
            exponent,
            digest.hash_alg(),
            digest.digest(),
            signature,
        ))
    }

    fn ecdsa_verify(
        &self,
        public_key: &[u8],
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let group = match public_key.len() {
            56 => EcGroup::P224,
            64 => EcGroup::P256,
            96 => EcGroup::P384,
            132 => EcGroup::P521,
            // A public point of any other length is not a key of a supported curve.
            _ => return Ok(false),
        };
        verified(ecdsa_verify(group, public_key, digest.digest(), signature))
    }

    fn rsaes_encrypt(
        &self,
        public_key: &[u8],
        exponent: u32,
        data: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        output(rsa_encrypt_pkcs1v15(public_key, exponent, data, ciphertext))
    }

    fn oaep_encrypt(
        &self,
        hash_alg: TpmiAlgHash,
        public_key: &[u8],
        exponent: u32,
        data: &[u8],
        label: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        output(rsa_encrypt_oaep(
            hash_alg, public_key, exponent, data, label, ciphertext,
        ))
    }

    fn rsa_null_encrypt(
        &self,
        public_key: &[u8],
        exponent: u32,
        data: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        output(rsa_encrypt_null(public_key, exponent, data, ciphertext))
    }

    fn rsaes_decrypt(
        &self,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        output(rsa_decrypt_pkcs1v15(private_key, ciphertext, plaintext))
    }

    fn oaep_decrypt(
        &self,
        hash_alg: TpmiAlgHash,
        private_key: &[u8],
        ciphertext: &[u8],
        label: &[u8],
        plaintext: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        output(rsa_decrypt_oaep(
            hash_alg,
            private_key,
            ciphertext,
            label,
            plaintext,
        ))
    }

    fn rsa_null_decrypt(
        &self,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        output(rsa_decrypt_null(private_key, ciphertext, plaintext))
    }

    fn rsa_generate_key(
        &self,
        key_bits: TpmiRsaKeyBits,
        public_key: &mut [u8],
        private_key: &mut [u8],
        seed: Option<&[u8]>,
    ) -> Result<(usize, usize), CryptoError> {
        let bit_size = usize::from(u16::from(key_bits));
        rsa_generate_key(bit_size, public_key, private_key, seed).map_err(Into::into)
    }

    fn ecc_generate_key(
        &self,
        curve: TpmEccCurve,
        public_key: &mut [u8],
        private_key: &mut [u8],
        seed: Option<&[u8]>,
    ) -> Result<(usize, usize), CryptoError> {
        let mut rng = ecc_rng(seed);

        let group = match curve {
            TpmEccCurve::NistP224 => EcGroup::P224,
            TpmEccCurve::NistP256 => EcGroup::P256,
            TpmEccCurve::NistP384 => EcGroup::P384,
            TpmEccCurve::NistP521 => EcGroup::P521,
            TpmEccCurve::BNP256 => EcGroup::BnP256,
            // NIST P-192, BN P-638 and SM2 P-256 use the generic arithmetic of
            // `tpm2-crypto-weierstrass` (matched on the identifier, as their variants exist only
            // with the corresponding `tpm2` curve features).
            _ => {
                return weierstrass_generate_key(curve as u16, &mut rng, public_key, private_key);
            }
        };
        ec_generate_key(group, &mut rng, public_key, private_key).map_err(Into::into)
    }

    fn rsa_import_private_key(
        &self,
        modulus: &[u8],
        prime_p: &[u8],
        exponent: u32,
        private_key_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        output(rsa_import_private_key(
            modulus,
            prime_p,
            exponent,
            private_key_out,
        ))
    }

    fn rsa_private_key_to_prime_p(
        &self,
        private_key: &[u8],
        prime_p_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        output(rsa_private_key_to_prime_p(private_key, prime_p_out))
    }

    fn rsa_private_key_to_crt(
        &self,
        private_key: &[u8],
        crt_out: &mut [u8],
    ) -> Result<Option<usize>, CryptoError> {
        output(rsa_private_key_to_crt(private_key, crt_out))
    }
}

/// The random source of ECC key generation: a ChaCha20 RNG seeded with SHA-256(`seed`) for a
/// deterministic key, or BoringSSL's RNG without a seed.
fn ecc_rng(seed: Option<&[u8]>) -> RngWrapper {
    match seed {
        Some(seed_bytes) => {
            let seed_32 = bssl_crypto::digest::Sha256::hash(seed_bytes);
            use rand_chacha::rand_core::SeedableRng as _;
            RngWrapper::ChaCha(rand_chacha::ChaCha20Rng::from_seed(seed_32))
        }
        None => RngWrapper::Bssl(crate::BsslRng),
    }
}

/// Generates a key pair on NIST P-192, BN P-638 or SM2 P-256 (by `TPM_ECC_CURVE` identifier)
/// with the generic arithmetic of `tpm2-crypto-weierstrass`, drawing the private scalar from
/// `rng`; [`CryptoError::Unsupported`] for any other curve.
fn weierstrass_generate_key(
    curve_id: u16,
    rng: &mut RngWrapper,
    public_key: &mut [u8],
    private_key: &mut [u8],
) -> Result<(usize, usize), CryptoError> {
    use rand_core::RngCore as _;
    tpm2_crypto_weierstrass::generate_key(
        curve_id,
        &mut |buf: &mut [u8]| {
            rng.fill_bytes(buf);
            Ok(())
        },
        public_key,
        private_key,
    )
    .unwrap_or(Err(CryptoError::Unsupported))
}

#[cfg(test)]
mod weierstrass_key_tests {
    use super::*;
    use tpm2::crypto::ecc_params::{BN_P638, NIST_P192, SM2_P256};
    use tpm2::crypto::{Ecc as _, EccCurve};

    /// Checks that `public` (`x || y`) is `private * G` on `curve` and lies on the curve.
    fn check_key<const N: usize>(curve: impl EccCurve<N>, private: &[u8], public: &[u8]) {
        let d: [u8; N] = private[..N].try_into().unwrap();
        let (mut x, mut y) = ([0u8; N], [0u8; N]);
        assert_eq!(
            curve.point_multiply_generator(&d, &mut x, &mut y),
            Ok(Some(()))
        );
        assert_eq!((&x[..], &y[..]), (&public[..N], &public[N..2 * N]));
        assert_eq!(curve.validate_point(&x, &y), Ok(true));
    }

    /// Key generation on NIST P-192, BN P-638 and SM2 P-256: deterministic for a seed,
    /// random without one, with a private scalar in `[1, n - 1]` and the matching public
    /// point; other curves are not handled.
    #[test]
    fn weierstrass_key_generation() {
        let c = BsslCryptoProvider;
        for (id, size, n) in [
            (0x0001u16, 24usize, NIST_P192.n),
            (0x0011, 80, BN_P638.n),
            (0x0020, 32, SM2_P256.n),
        ] {
            let gen_key = |seed: Option<&[u8]>| {
                let (mut public, mut private) = ([0u8; 160], [0u8; 80]);
                let lens =
                    weierstrass_generate_key(id, &mut ecc_rng(seed), &mut public, &mut private)
                        .unwrap();
                (lens, public, private)
            };
            let (lens, public, private) = gen_key(Some(b"seed"));
            assert_eq!(lens, (2 * size, size), "{id:#x}");
            assert_eq!(gen_key(Some(b"seed")), (lens, public, private), "{id:#x}");
            assert_ne!(gen_key(Some(b"other")).1, public, "{id:#x}");
            assert_ne!(gen_key(None).1, gen_key(None).1, "{id:#x}");
            assert!(private[..size] < *n && private[..size].iter().any(|&b| b != 0));
            match id {
                0x0001 => check_key(c.nist_p192().unwrap(), &private, &public),
                0x0011 => check_key(c.bn_p638().unwrap(), &private, &public),
                _ => check_key(c.sm2_p256().unwrap(), &private, &public),
            }
            assert_eq!(
                weierstrass_generate_key(
                    id,
                    &mut ecc_rng(None),
                    &mut [0; 160][..2 * size - 1],
                    &mut [0; 80]
                ),
                Err(CryptoError::Internal)
            );
        }
        assert_eq!(
            weierstrass_generate_key(0x0003, &mut ecc_rng(None), &mut [0; 64], &mut [0; 32]),
            Err(CryptoError::Unsupported)
        );
    }
}
