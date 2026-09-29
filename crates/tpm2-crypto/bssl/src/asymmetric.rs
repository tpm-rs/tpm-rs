use crate::bssl::{
    EcGroup, ec_generate_key, ecdsa_sign, ecdsa_verify, rsa_decrypt_null, rsa_decrypt_oaep,
    rsa_decrypt_pkcs1v15, rsa_encrypt_null, rsa_encrypt_oaep, rsa_encrypt_pkcs1v15,
    rsa_generate_key, rsa_import_private_key, rsa_private_key_to_prime_p, rsa_sign_pkcs1v15,
    rsa_sign_pss, rsa_verify_pkcs1v15, rsa_verify_pss,
};
use crate::{BsslCryptoProvider, RngWrapper};
use tpm2::crypto::{Asymmetric, AsymmetricSign, CryptoError, TpmiRsaKeyBits};
use tpm2::{TpmEccCurve, TpmiAlgHash, TpmtHa};

impl AsymmetricSign for BsslCryptoProvider {
    fn rsassa_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        rsa_sign_pkcs1v15(
            private_key,
            digest.hash_alg(),
            digest.digest(),
            signature_out,
        )
    }

    fn rsapss_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        rsa_sign_pss(
            private_key,
            digest.hash_alg(),
            digest.digest(),
            signature_out,
        )
    }

    fn ecdsa_sign(
        &self,
        private_key: &[u8],
        digest: TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        match private_key.len() {
            28 => ecdsa_sign(EcGroup::P224, private_key, digest.digest(), signature_out),
            32 => ecdsa_sign(EcGroup::P256, private_key, digest.digest(), signature_out),
            48 => ecdsa_sign(EcGroup::P384, private_key, digest.digest(), signature_out),
            66 => ecdsa_sign(EcGroup::P521, private_key, digest.digest(), signature_out),
            _ => Err(CryptoError::InvalidData),
        }
    }
}

impl Asymmetric for BsslCryptoProvider {
    fn rsassa_verify(
        &self,
        public_key: &[u8],
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        rsa_verify_pkcs1v15(public_key, digest.hash_alg(), digest.digest(), signature)
    }

    fn rsapss_verify(
        &self,
        public_key: &[u8],
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        rsa_verify_pss(public_key, digest.hash_alg(), digest.digest(), signature)
    }

    fn ecdsa_verify(
        &self,
        public_key: &[u8],
        digest: TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        match public_key.len() {
            56 => ecdsa_verify(EcGroup::P224, public_key, digest.digest(), signature),
            64 => ecdsa_verify(EcGroup::P256, public_key, digest.digest(), signature),
            96 => ecdsa_verify(EcGroup::P384, public_key, digest.digest(), signature),
            132 => ecdsa_verify(EcGroup::P521, public_key, digest.digest(), signature),
            _ => Err(CryptoError::InvalidData),
        }
    }

    fn rsaes_encrypt(
        &self,
        public_key: &[u8],
        data: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, CryptoError> {
        rsa_encrypt_pkcs1v15(public_key, data, ciphertext)
    }

    fn oaep_encrypt(
        &self,
        hash_alg: TpmiAlgHash,
        public_key: &[u8],
        data: &[u8],
        label: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, CryptoError> {
        rsa_encrypt_oaep(hash_alg, public_key, data, label, ciphertext)
    }

    fn rsa_null_encrypt(
        &self,
        public_key: &[u8],
        data: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, CryptoError> {
        rsa_encrypt_null(public_key, data, ciphertext)
    }

    fn rsaes_decrypt(
        &self,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, CryptoError> {
        rsa_decrypt_pkcs1v15(private_key, ciphertext, plaintext)
    }

    fn oaep_decrypt(
        &self,
        hash_alg: TpmiAlgHash,
        private_key: &[u8],
        ciphertext: &[u8],
        label: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, CryptoError> {
        rsa_decrypt_oaep(hash_alg, private_key, ciphertext, label, plaintext)
    }

    fn rsa_null_decrypt(
        &self,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, CryptoError> {
        rsa_decrypt_null(private_key, ciphertext, plaintext)
    }

    fn rsa_generate_key(
        &self,
        key_bits: TpmiRsaKeyBits,
        public_key: &mut [u8],
        private_key: &mut [u8],
        seed: Option<&[u8]>,
    ) -> Result<(usize, usize), CryptoError> {
        let bit_size = usize::from(u16::from(key_bits));
        rsa_generate_key(bit_size, public_key, private_key, seed)
    }

    fn ecc_generate_key(
        &self,
        curve: TpmEccCurve,
        public_key: &mut [u8],
        private_key: &mut [u8],
        seed: Option<&[u8]>,
    ) -> Result<(usize, usize), CryptoError> {
        let mut rng = match seed {
            Some(seed_bytes) => {
                let seed_32 = bssl_crypto::digest::Sha256::hash(seed_bytes);
                use rand_chacha::rand_core::SeedableRng as _;
                RngWrapper::ChaCha(rand_chacha::ChaCha20Rng::from_seed(seed_32))
            }
            None => RngWrapper::Bssl(crate::BsslRng),
        };

        match curve {
            TpmEccCurve::NistP224 => {
                ec_generate_key(EcGroup::P224, &mut rng, public_key, private_key)
            }
            TpmEccCurve::NistP256 => {
                ec_generate_key(EcGroup::P256, &mut rng, public_key, private_key)
            }
            TpmEccCurve::NistP384 => {
                ec_generate_key(EcGroup::P384, &mut rng, public_key, private_key)
            }
            TpmEccCurve::NistP521 => {
                ec_generate_key(EcGroup::P521, &mut rng, public_key, private_key)
            }
            TpmEccCurve::BNP256 => {
                ec_generate_key(EcGroup::BnP256, &mut rng, public_key, private_key)
            }
            _ => Err(CryptoError::UnsupportedAlgorithm),
        }
    }

    fn rsa_import_private_key(
        &self,
        modulus: &[u8],
        prime_p: &[u8],
        exponent: u32,
        private_key_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        rsa_import_private_key(modulus, prime_p, exponent, private_key_out)
    }

    fn rsa_private_key_to_prime_p(
        &self,
        private_key: &[u8],
        prime_p_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        rsa_private_key_to_prime_p(private_key, prime_p_out)
    }
}
