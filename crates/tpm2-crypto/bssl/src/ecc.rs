use crate::BsslCryptoProvider;
use crate::bssl::{
    EcGroup, ec_point_multiply, ec_point_multiply_generator, ec_validate_point, p256_ecdaa_sign,
};
use tpm2::crypto::{CryptoError, Ecc, EccCurve};

/// NIST P-224 context for `BsslCryptoProvider`.
pub struct BsslEccNistP224;

impl EccCurve<28, CryptoError> for BsslEccNistP224 {
    fn invalid_data(&self) -> CryptoError {
        CryptoError::InvalidData
    }

    fn buffer_too_small(&self) -> CryptoError {
        CryptoError::BufferTooSmall
    }

    fn validate_point(&self, x: &[u8; 28], y: &[u8; 28]) -> Result<(), CryptoError> {
        ec_validate_point(EcGroup::P224, x, y)
    }

    fn point_multiply_generator(
        &self,
        scalar: &[u8; 28],
        x_out: &mut [u8; 28],
        y_out: &mut [u8; 28],
    ) -> Result<(), CryptoError> {
        ec_point_multiply_generator(EcGroup::P224, scalar, x_out, y_out)
    }

    fn point_multiply(
        &self,
        scalar: &[u8; 28],
        x_in: &[u8; 28],
        y_in: &[u8; 28],
        x_out: &mut [u8; 28],
        y_out: &mut [u8; 28],
    ) -> Result<(), CryptoError> {
        ec_point_multiply(EcGroup::P224, scalar, x_in, y_in, x_out, y_out)
    }

    fn ecdaa_sign(
        &self,
        _commit_r: &[u8; 28],
        _commit_x: &[u8],
        _commit_p1: &[u8],
        _private_key_d: &[u8; 28],
        _digest: &[u8],
        _nonce_k_out: &mut [u8; 28],
        _s_out: &mut [u8; 28],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm)
    }
}

/// NIST P-256 context for `BsslCryptoProvider`.
pub struct BsslEccNistP256;

impl EccCurve<32, CryptoError> for BsslEccNistP256 {
    fn invalid_data(&self) -> CryptoError {
        CryptoError::InvalidData
    }

    fn buffer_too_small(&self) -> CryptoError {
        CryptoError::BufferTooSmall
    }

    fn validate_point(&self, x: &[u8; 32], y: &[u8; 32]) -> Result<(), CryptoError> {
        ec_validate_point(EcGroup::P256, x, y)
    }

    fn point_multiply_generator(
        &self,
        scalar: &[u8; 32],
        x_out: &mut [u8; 32],
        y_out: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        ec_point_multiply_generator(EcGroup::P256, scalar, x_out, y_out)
    }

    fn point_multiply(
        &self,
        scalar: &[u8; 32],
        x_in: &[u8; 32],
        y_in: &[u8; 32],
        x_out: &mut [u8; 32],
        y_out: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        ec_point_multiply(EcGroup::P256, scalar, x_in, y_in, x_out, y_out)
    }

    fn ecdaa_sign(
        &self,
        commit_r: &[u8; 32],
        commit_x: &[u8],
        commit_p1: &[u8],
        private_key_d: &[u8; 32],
        digest: &[u8],
        nonce_k_out: &mut [u8; 32],
        s_out: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        p256_ecdaa_sign(
            commit_r,
            commit_x,
            commit_p1,
            private_key_d,
            digest,
            nonce_k_out,
            s_out,
        )
    }
}

/// NIST P-384 context for `BsslCryptoProvider`.
pub struct BsslEccNistP384;

impl EccCurve<48, CryptoError> for BsslEccNistP384 {
    fn invalid_data(&self) -> CryptoError {
        CryptoError::InvalidData
    }

    fn buffer_too_small(&self) -> CryptoError {
        CryptoError::BufferTooSmall
    }

    fn validate_point(&self, x: &[u8; 48], y: &[u8; 48]) -> Result<(), CryptoError> {
        ec_validate_point(EcGroup::P384, x, y)
    }

    fn point_multiply_generator(
        &self,
        scalar: &[u8; 48],
        x_out: &mut [u8; 48],
        y_out: &mut [u8; 48],
    ) -> Result<(), CryptoError> {
        ec_point_multiply_generator(EcGroup::P384, scalar, x_out, y_out)
    }

    fn point_multiply(
        &self,
        scalar: &[u8; 48],
        x_in: &[u8; 48],
        y_in: &[u8; 48],
        x_out: &mut [u8; 48],
        y_out: &mut [u8; 48],
    ) -> Result<(), CryptoError> {
        ec_point_multiply(EcGroup::P384, scalar, x_in, y_in, x_out, y_out)
    }

    fn ecdaa_sign(
        &self,
        _commit_r: &[u8; 48],
        _commit_x: &[u8],
        _commit_p1: &[u8],
        _private_key_d: &[u8; 48],
        _digest: &[u8],
        _nonce_k_out: &mut [u8; 48],
        _s_out: &mut [u8; 48],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm)
    }
}

/// NIST P-521 context for `BsslCryptoProvider`.
pub struct BsslEccNistP521;

impl EccCurve<66, CryptoError> for BsslEccNistP521 {
    fn invalid_data(&self) -> CryptoError {
        CryptoError::InvalidData
    }

    fn buffer_too_small(&self) -> CryptoError {
        CryptoError::BufferTooSmall
    }

    fn validate_point(&self, x: &[u8; 66], y: &[u8; 66]) -> Result<(), CryptoError> {
        ec_validate_point(EcGroup::P521, x, y)
    }

    fn point_multiply_generator(
        &self,
        scalar: &[u8; 66],
        x_out: &mut [u8; 66],
        y_out: &mut [u8; 66],
    ) -> Result<(), CryptoError> {
        ec_point_multiply_generator(EcGroup::P521, scalar, x_out, y_out)
    }

    fn point_multiply(
        &self,
        scalar: &[u8; 66],
        x_in: &[u8; 66],
        y_in: &[u8; 66],
        x_out: &mut [u8; 66],
        y_out: &mut [u8; 66],
    ) -> Result<(), CryptoError> {
        ec_point_multiply(EcGroup::P521, scalar, x_in, y_in, x_out, y_out)
    }

    fn ecdaa_sign(
        &self,
        _commit_r: &[u8; 66],
        _commit_x: &[u8],
        _commit_p1: &[u8],
        _private_key_d: &[u8; 66],
        _digest: &[u8],
        _nonce_k_out: &mut [u8; 66],
        _s_out: &mut [u8; 66],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm)
    }
}

/// BN-P256 context for `BsslCryptoProvider`.
pub struct BsslEccBnP256;

impl EccCurve<32, CryptoError> for BsslEccBnP256 {
    fn invalid_data(&self) -> CryptoError {
        CryptoError::InvalidData
    }

    fn buffer_too_small(&self) -> CryptoError {
        CryptoError::BufferTooSmall
    }

    fn validate_point(&self, x: &[u8; 32], y: &[u8; 32]) -> Result<(), CryptoError> {
        ec_validate_point(EcGroup::BnP256, x, y)
    }

    fn point_multiply_generator(
        &self,
        scalar: &[u8; 32],
        x_out: &mut [u8; 32],
        y_out: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        ec_point_multiply_generator(EcGroup::BnP256, scalar, x_out, y_out)
    }

    fn point_multiply(
        &self,
        scalar: &[u8; 32],
        x_in: &[u8; 32],
        y_in: &[u8; 32],
        x_out: &mut [u8; 32],
        y_out: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        ec_point_multiply(EcGroup::BnP256, scalar, x_in, y_in, x_out, y_out)
    }

    fn ecdaa_sign(
        &self,
        _commit_r: &[u8; 32],
        _commit_x: &[u8],
        _commit_p1: &[u8],
        _private_key_d: &[u8; 32],
        _digest: &[u8],
        _nonce_k_out: &mut [u8; 32],
        _s_out: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm)
    }
}

impl Ecc for BsslCryptoProvider {
    type NistP256Ctx = BsslEccNistP256;
    fn nist_p256(&self) -> Result<Self::NistP256Ctx, CryptoError> {
        Ok(BsslEccNistP256)
    }

    type NistP384Ctx = BsslEccNistP384;
    fn nist_p384(&self) -> Result<Self::NistP384Ctx, CryptoError> {
        Ok(BsslEccNistP384)
    }

    type NistP521Ctx = BsslEccNistP521;
    fn nist_p521(&self) -> Result<Self::NistP521Ctx, CryptoError> {
        Ok(BsslEccNistP521)
    }

    type BnP256Ctx = BsslEccBnP256;
    fn bn_p256(&self) -> Result<Self::BnP256Ctx, CryptoError> {
        Ok(BsslEccBnP256)
    }

    type NistP224Ctx = BsslEccNistP224;
    fn nist_p224(&self) -> Result<Self::NistP224Ctx, CryptoError> {
        Ok(BsslEccNistP224)
    }

    type NistP192Ctx = !;
    type BnP638Ctx = !;
    type Sm2P256Ctx = !;
    type BpP256R1Ctx = !;
    type BpP384R1Ctx = !;
    type BpP512R1Ctx = !;
    type Curve25519Ctx = !;
    type Curve448Ctx = !;
}
