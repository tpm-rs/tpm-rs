use crate::bssl::{EcGroup, ec_point_multiply, ec_point_multiply_generator, ec_validate_point};
use crate::{BsslCryptoProvider, output, verified};
use tpm2::crypto::{CryptoError, Ecc, EccCurve};

/// NIST P-224 context for `BsslCryptoProvider`.
pub struct BsslEccNistP224;

impl EccCurve<28> for BsslEccNistP224 {
    fn validate_point(&self, x: &[u8; 28], y: &[u8; 28]) -> Result<bool, CryptoError> {
        verified(ec_validate_point(EcGroup::P224, x, y))
    }

    fn point_multiply_generator(
        &self,
        scalar: &[u8; 28],
        x_out: &mut [u8; 28],
        y_out: &mut [u8; 28],
    ) -> Result<Option<()>, CryptoError> {
        output(ec_point_multiply_generator(
            EcGroup::P224,
            scalar,
            x_out,
            y_out,
        ))
    }

    fn point_multiply(
        &self,
        scalar: &[u8; 28],
        x_in: &[u8; 28],
        y_in: &[u8; 28],
        x_out: &mut [u8; 28],
        y_out: &mut [u8; 28],
    ) -> Result<Option<()>, CryptoError> {
        output(ec_point_multiply(
            EcGroup::P224,
            scalar,
            x_in,
            y_in,
            x_out,
            y_out,
        ))
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
    ) -> Result<Option<()>, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

/// NIST P-256 context for `BsslCryptoProvider`.
pub struct BsslEccNistP256;

impl EccCurve<32> for BsslEccNistP256 {
    fn validate_point(&self, x: &[u8; 32], y: &[u8; 32]) -> Result<bool, CryptoError> {
        verified(ec_validate_point(EcGroup::P256, x, y))
    }

    fn point_multiply_generator(
        &self,
        scalar: &[u8; 32],
        x_out: &mut [u8; 32],
        y_out: &mut [u8; 32],
    ) -> Result<Option<()>, CryptoError> {
        output(ec_point_multiply_generator(
            EcGroup::P256,
            scalar,
            x_out,
            y_out,
        ))
    }

    fn point_multiply(
        &self,
        scalar: &[u8; 32],
        x_in: &[u8; 32],
        y_in: &[u8; 32],
        x_out: &mut [u8; 32],
        y_out: &mut [u8; 32],
    ) -> Result<Option<()>, CryptoError> {
        output(ec_point_multiply(
            EcGroup::P256,
            scalar,
            x_in,
            y_in,
            x_out,
            y_out,
        ))
    }

    /// Not provided: ECDAA signing (TPM 2.0 Part 1, "ECDAA Sign Operation") needs the
    /// signing scheme's hash, which this interface does not carry, so `tpm2-impl` computes it
    /// itself from the generic primitives. The previous implementation did not follow the
    /// spec (it derived the nonce from the digest and special-cased fixed test points).
    fn ecdaa_sign(
        &self,
        _commit_r: &[u8; 32],
        _commit_x: &[u8],
        _commit_p1: &[u8],
        _private_key_d: &[u8; 32],
        _digest: &[u8],
        _nonce_k_out: &mut [u8; 32],
        _s_out: &mut [u8; 32],
    ) -> Result<Option<()>, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

/// NIST P-384 context for `BsslCryptoProvider`.
pub struct BsslEccNistP384;

impl EccCurve<48> for BsslEccNistP384 {
    fn validate_point(&self, x: &[u8; 48], y: &[u8; 48]) -> Result<bool, CryptoError> {
        verified(ec_validate_point(EcGroup::P384, x, y))
    }

    fn point_multiply_generator(
        &self,
        scalar: &[u8; 48],
        x_out: &mut [u8; 48],
        y_out: &mut [u8; 48],
    ) -> Result<Option<()>, CryptoError> {
        output(ec_point_multiply_generator(
            EcGroup::P384,
            scalar,
            x_out,
            y_out,
        ))
    }

    fn point_multiply(
        &self,
        scalar: &[u8; 48],
        x_in: &[u8; 48],
        y_in: &[u8; 48],
        x_out: &mut [u8; 48],
        y_out: &mut [u8; 48],
    ) -> Result<Option<()>, CryptoError> {
        output(ec_point_multiply(
            EcGroup::P384,
            scalar,
            x_in,
            y_in,
            x_out,
            y_out,
        ))
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
    ) -> Result<Option<()>, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

/// NIST P-521 context for `BsslCryptoProvider`.
pub struct BsslEccNistP521;

impl EccCurve<66> for BsslEccNistP521 {
    fn validate_point(&self, x: &[u8; 66], y: &[u8; 66]) -> Result<bool, CryptoError> {
        verified(ec_validate_point(EcGroup::P521, x, y))
    }

    fn point_multiply_generator(
        &self,
        scalar: &[u8; 66],
        x_out: &mut [u8; 66],
        y_out: &mut [u8; 66],
    ) -> Result<Option<()>, CryptoError> {
        output(ec_point_multiply_generator(
            EcGroup::P521,
            scalar,
            x_out,
            y_out,
        ))
    }

    fn point_multiply(
        &self,
        scalar: &[u8; 66],
        x_in: &[u8; 66],
        y_in: &[u8; 66],
        x_out: &mut [u8; 66],
        y_out: &mut [u8; 66],
    ) -> Result<Option<()>, CryptoError> {
        output(ec_point_multiply(
            EcGroup::P521,
            scalar,
            x_in,
            y_in,
            x_out,
            y_out,
        ))
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
    ) -> Result<Option<()>, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

/// BN-P256 context for `BsslCryptoProvider`.
pub struct BsslEccBnP256;

impl EccCurve<32> for BsslEccBnP256 {
    fn validate_point(&self, x: &[u8; 32], y: &[u8; 32]) -> Result<bool, CryptoError> {
        verified(ec_validate_point(EcGroup::BnP256, x, y))
    }

    fn point_multiply_generator(
        &self,
        scalar: &[u8; 32],
        x_out: &mut [u8; 32],
        y_out: &mut [u8; 32],
    ) -> Result<Option<()>, CryptoError> {
        output(ec_point_multiply_generator(
            EcGroup::BnP256,
            scalar,
            x_out,
            y_out,
        ))
    }

    fn point_multiply(
        &self,
        scalar: &[u8; 32],
        x_in: &[u8; 32],
        y_in: &[u8; 32],
        x_out: &mut [u8; 32],
        y_out: &mut [u8; 32],
    ) -> Result<Option<()>, CryptoError> {
        output(ec_point_multiply(
            EcGroup::BnP256,
            scalar,
            x_in,
            y_in,
            x_out,
            y_out,
        ))
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
    ) -> Result<Option<()>, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

impl Ecc for BsslCryptoProvider {
    type NistP256Context = BsslEccNistP256;
    fn nist_p256(&self) -> Result<Self::NistP256Context, CryptoError> {
        Ok(BsslEccNistP256)
    }

    type NistP384Context = BsslEccNistP384;
    fn nist_p384(&self) -> Result<Self::NistP384Context, CryptoError> {
        Ok(BsslEccNistP384)
    }

    type NistP521Context = BsslEccNistP521;
    fn nist_p521(&self) -> Result<Self::NistP521Context, CryptoError> {
        Ok(BsslEccNistP521)
    }

    type BnP256Context = BsslEccBnP256;
    fn bn_p256(&self) -> Result<Self::BnP256Context, CryptoError> {
        Ok(BsslEccBnP256)
    }

    type NistP224Context = BsslEccNistP224;
    fn nist_p224(&self) -> Result<Self::NistP224Context, CryptoError> {
        Ok(BsslEccNistP224)
    }

    type NistP192Context = !;
    type BnP638Context = !;
    type Sm2P256Context = !;
    type BpP256R1Context = !;
    type BpP384R1Context = !;
    type BpP512R1Context = !;
    type Curve25519Context = !;
    type Curve448Context = !;
}
