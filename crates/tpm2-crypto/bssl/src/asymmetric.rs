use crate::bssl::{
    EcGroup, ec_generate_key, ecdsa_sign, ecdsa_verify, rsa_decrypt_null, rsa_decrypt_oaep,
    rsa_decrypt_pkcs1v15, rsa_encrypt_null, rsa_encrypt_oaep, rsa_encrypt_pkcs1v15,
    rsa_generate_key, rsa_import_private_key, rsa_private_key_to_prime_p, rsa_sign_pkcs1v15,
    rsa_sign_pss, rsa_verify_pkcs1v15, rsa_verify_pss,
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
        let mut rng = match seed {
            Some(seed_bytes) => {
                let seed_32 = bssl_crypto::digest::Sha256::hash(seed_bytes);
                use rand_chacha::rand_core::SeedableRng as _;
                RngWrapper::ChaCha(rand_chacha::ChaCha20Rng::from_seed(seed_32))
            }
            None => RngWrapper::Bssl(crate::BsslRng),
        };

        let group = match curve {
            TpmEccCurve::NistP224 => EcGroup::P224,
            TpmEccCurve::NistP256 => EcGroup::P256,
            TpmEccCurve::NistP384 => EcGroup::P384,
            TpmEccCurve::NistP521 => EcGroup::P521,
            TpmEccCurve::BNP256 => EcGroup::BnP256,
            _ => return Err(CryptoError::Unsupported),
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
}
