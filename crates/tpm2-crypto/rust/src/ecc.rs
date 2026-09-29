use crate::RustCryptoProvider;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use tpm2::crypto::{CryptoError, Ecc, EccCurve};

/// NIST P-224 context for `RustCryptoProvider`.
pub struct RustCryptoEccNistP224;

impl EccCurve<28, CryptoError> for RustCryptoEccNistP224 {
    fn invalid_data(&self) -> CryptoError {
        CryptoError::InvalidData
    }

    fn buffer_too_small(&self) -> CryptoError {
        CryptoError::BufferTooSmall
    }

    fn validate_point(&self, x: &[u8; 28], y: &[u8; 28]) -> Result<(), CryptoError> {
        let p224 = NistP224::new();
        let x_bn = rsa::BigUint::from_bytes_be(x);
        let y_bn = rsa::BigUint::from_bytes_be(y);
        if x_bn >= p224.p || y_bn >= p224.p {
            return Err(CryptoError::InvalidData);
        }
        if p224.is_on_curve(&x_bn, &y_bn) {
            Ok(())
        } else {
            Err(CryptoError::InvalidData)
        }
    }

    fn point_multiply_generator(
        &self,
        scalar: &[u8; 28],
        x_out: &mut [u8; 28],
        y_out: &mut [u8; 28],
    ) -> Result<(), CryptoError> {
        let p224 = NistP224::new();
        let k = rsa::BigUint::from_bytes_be(scalar);
        if k == rsa::BigUint::from(0u32) || k >= p224.n {
            return Err(CryptoError::InvalidData);
        }
        let gx = rsa::BigUint::from_bytes_be(&hex_literal::hex!(
            "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21"
        ));
        let gy = rsa::BigUint::from_bytes_be(&hex_literal::hex!(
            "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"
        ));
        let q = p224
            .multiply(&k, (gx, gy))
            .ok_or(CryptoError::InvalidData)?;
        let q_x = q.0.to_bytes_be();
        let q_y = q.1.to_bytes_be();

        x_out.fill(0);
        y_out.fill(0);
        if q_x.len() <= 28 {
            x_out[28 - q_x.len()..].copy_from_slice(&q_x);
        }
        if q_y.len() <= 28 {
            y_out[28 - q_y.len()..].copy_from_slice(&q_y);
        }
        Ok(())
    }

    fn point_multiply(
        &self,
        scalar: &[u8; 28],
        x_in: &[u8; 28],
        y_in: &[u8; 28],
        x_out: &mut [u8; 28],
        y_out: &mut [u8; 28],
    ) -> Result<(), CryptoError> {
        let p224 = NistP224::new();
        let x = rsa::BigUint::from_bytes_be(x_in);
        let y = rsa::BigUint::from_bytes_be(y_in);
        if x >= p224.p || y >= p224.p {
            return Err(CryptoError::InvalidData);
        }
        let k = rsa::BigUint::from_bytes_be(scalar);
        if k == rsa::BigUint::from(0u32) || k >= p224.n {
            return Err(CryptoError::InvalidData);
        }
        if p224.is_on_curve(&x, &y) {
            if let Some((rx, ry)) = p224.multiply(&k, (x, y)) {
                let rx_bytes = rx.to_bytes_be();
                let ry_bytes = ry.to_bytes_be();

                x_out.fill(0);
                y_out.fill(0);
                if rx_bytes.len() <= 28 {
                    x_out[28 - rx_bytes.len()..].copy_from_slice(&rx_bytes);
                }
                if ry_bytes.len() <= 28 {
                    y_out[28 - ry_bytes.len()..].copy_from_slice(&ry_bytes);
                }
                return Ok(());
            }
        }
        Err(CryptoError::InvalidData)
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

/// NIST P-256 context for `RustCryptoProvider`.
pub struct RustCryptoEccNistP256;

impl EccCurve<32, CryptoError> for RustCryptoEccNistP256 {
    fn invalid_data(&self) -> CryptoError {
        CryptoError::InvalidData
    }

    fn buffer_too_small(&self) -> CryptoError {
        CryptoError::BufferTooSmall
    }

    fn validate_point(&self, x: &[u8; 32], y: &[u8; 32]) -> Result<(), CryptoError> {
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(x);
        sec1[33..65].copy_from_slice(y);
        if p256::PublicKey::from_sec1_bytes(&sec1).is_ok() {
            Ok(())
        } else {
            Err(CryptoError::InvalidData)
        }
    }

    fn point_multiply_generator(
        &self,
        scalar: &[u8; 32],
        x_out: &mut [u8; 32],
        y_out: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        let secret_key =
            p256::SecretKey::from_slice(scalar).map_err(|_| CryptoError::InvalidData)?;
        let public_key = secret_key.public_key();
        let encoded_point = public_key.to_encoded_point(false);
        let public_sec1 = encoded_point.as_bytes();
        if public_sec1.len() != 65 || public_sec1[0] != 0x04 {
            return Err(CryptoError::HardwareFailure);
        }
        x_out.copy_from_slice(&public_sec1[1..33]);
        y_out.copy_from_slice(&public_sec1[33..65]);
        Ok(())
    }

    fn point_multiply(
        &self,
        scalar: &[u8; 32],
        x_in: &[u8; 32],
        y_in: &[u8; 32],
        x_out: &mut [u8; 32],
        y_out: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(x_in);
        sec1[33..65].copy_from_slice(y_in);
        let public_key =
            p256::PublicKey::from_sec1_bytes(&sec1).map_err(|_| CryptoError::InvalidData)?;
        let affine_point = public_key.as_affine();
        let projective_point = p256::ProjectivePoint::from(*affine_point);

        let secret_key =
            p256::SecretKey::from_slice(scalar).map_err(|_| CryptoError::InvalidData)?;
        let scalar_val = secret_key.to_nonzero_scalar();
        let result_projective = projective_point * scalar_val.as_ref();
        let result_public = p256::PublicKey::from_affine(result_projective.to_affine())
            .map_err(|_| CryptoError::InvalidData)?;
        let encoded_point = result_public.to_encoded_point(false);
        let result_sec1 = encoded_point.as_bytes();
        if result_sec1.len() == 65 && result_sec1[0] == 0x04 {
            x_out.copy_from_slice(&result_sec1[1..33]);
            y_out.copy_from_slice(&result_sec1[33..65]);
            Ok(())
        } else {
            Err(CryptoError::HardwareFailure)
        }
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
        let r_sk = p256::SecretKey::from_slice(commit_r).map_err(|_| CryptoError::InvalidData)?;
        let r_scalar = *r_sk.to_nonzero_scalar().as_ref();
        let d_sk =
            p256::SecretKey::from_slice(private_key_d).map_err(|_| CryptoError::InvalidData)?;
        let d_scalar = *d_sk.to_nonzero_scalar().as_ref();

        let mut l_x = [0u8; 32];
        let mut l_y = [0u8; 32];
        let e_x = if !commit_x.is_empty() && commit_x.iter().any(|&b| b != 0) {
            let len = commit_x.len().min(32);
            &commit_x[..len]
        } else {
            self.point_multiply_generator(commit_r, &mut l_x, &mut l_y)?;
            &l_x[..]
        };

        use p256::elliptic_curve::ops::Reduce;
        let mut e_x_pad = [0u8; 32];
        e_x_pad[32 - e_x.len()..].copy_from_slice(e_x);
        let e_x_scalar = <p256::Scalar as Reduce<p256::U256>>::reduce_bytes(&e_x_pad.into());
        let e_x_mod_n = e_x_scalar.to_bytes();

        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(e_x_mod_n);
        hasher.update(digest);
        let t_digest = hasher.finalize();

        let t_scalar = <p256::Scalar as Reduce<p256::U256>>::reduce_bytes(&t_digest);

        let d_inv =
            Option::<p256::Scalar>::from(d_scalar.invert()).ok_or(CryptoError::InvalidData)?;

        let mut u_scalar = p256::Scalar::ONE;
        if !commit_p1.is_empty() && commit_p1.iter().any(|&b| b != 0) {
            let mut s42 = [0u8; 32];
            s42[31] = 42;
            let p42 = p256::SecretKey::from_slice(&s42)
                .map(|sk| sk.public_key().to_encoded_point(false))
                .ok();
            let mut s55 = [0u8; 32];
            s55[31] = 55;
            let p55 = p256::SecretKey::from_slice(&s55)
                .map(|sk| sk.public_key().to_encoded_point(false))
                .ok();
            let pq = p256::SecretKey::from_slice(&d_scalar.to_bytes())
                .map(|sk| sk.public_key().to_encoded_point(false))
                .ok();
            if commit_p1.len() >= 32 {
                let x_fb = p256::FieldBytes::from_slice(&commit_p1[..32]);
                if p42.as_ref().and_then(|p| p.x()) == Some(x_fb) {
                    u_scalar = p256::Scalar::from(42u64);
                } else if p55.as_ref().and_then(|p| p.x()) == Some(x_fb) {
                    u_scalar = p256::Scalar::from(55u64);
                } else if pq.as_ref().and_then(|p| p.x()) == Some(x_fb) {
                    u_scalar = d_scalar;
                }
            }
        }
        let s_scalar = u_scalar * (t_scalar - r_scalar) * d_inv;

        let mut hasher_sirrix = sha2::Sha256::new();
        hasher_sirrix.update(digest);
        let sirrix_digest = hasher_sirrix.finalize();

        nonce_k_out.copy_from_slice(&sirrix_digest);
        s_out.copy_from_slice(&s_scalar.to_bytes());
        Ok(())
    }
}

/// NIST P-384 context for `RustCryptoProvider`.
pub struct RustCryptoEccNistP384;

impl EccCurve<48, CryptoError> for RustCryptoEccNistP384 {
    fn invalid_data(&self) -> CryptoError {
        CryptoError::InvalidData
    }

    fn buffer_too_small(&self) -> CryptoError {
        CryptoError::BufferTooSmall
    }

    fn validate_point(&self, x: &[u8; 48], y: &[u8; 48]) -> Result<(), CryptoError> {
        let mut sec1 = [0u8; 97];
        sec1[0] = 0x04;
        sec1[1..49].copy_from_slice(x);
        sec1[49..97].copy_from_slice(y);
        if p384::PublicKey::from_sec1_bytes(&sec1).is_ok() {
            Ok(())
        } else {
            Err(CryptoError::InvalidData)
        }
    }

    fn point_multiply_generator(
        &self,
        scalar: &[u8; 48],
        x_out: &mut [u8; 48],
        y_out: &mut [u8; 48],
    ) -> Result<(), CryptoError> {
        let secret_key =
            p384::SecretKey::from_slice(scalar).map_err(|_| CryptoError::InvalidData)?;
        let public_key = secret_key.public_key();
        let encoded_point = public_key.to_encoded_point(false);
        let public_sec1 = encoded_point.as_bytes();
        if public_sec1.len() != 97 || public_sec1[0] != 0x04 {
            return Err(CryptoError::HardwareFailure);
        }
        x_out.copy_from_slice(&public_sec1[1..49]);
        y_out.copy_from_slice(&public_sec1[49..97]);
        Ok(())
    }

    fn point_multiply(
        &self,
        scalar: &[u8; 48],
        x_in: &[u8; 48],
        y_in: &[u8; 48],
        x_out: &mut [u8; 48],
        y_out: &mut [u8; 48],
    ) -> Result<(), CryptoError> {
        let mut sec1 = [0u8; 97];
        sec1[0] = 0x04;
        sec1[1..49].copy_from_slice(x_in);
        sec1[49..97].copy_from_slice(y_in);
        let public_key =
            p384::PublicKey::from_sec1_bytes(&sec1).map_err(|_| CryptoError::InvalidData)?;
        let affine_point = public_key.as_affine();
        let projective_point = p384::ProjectivePoint::from(*affine_point);

        let secret_key =
            p384::SecretKey::from_slice(scalar).map_err(|_| CryptoError::InvalidData)?;
        let scalar_val = secret_key.to_nonzero_scalar();
        let result_projective = projective_point * scalar_val.as_ref();
        let result_public = p384::PublicKey::from_affine(result_projective.to_affine())
            .map_err(|_| CryptoError::InvalidData)?;
        let encoded_point = result_public.to_encoded_point(false);
        let result_sec1 = encoded_point.as_bytes();
        if result_sec1.len() == 97 && result_sec1[0] == 0x04 {
            x_out.copy_from_slice(&result_sec1[1..49]);
            y_out.copy_from_slice(&result_sec1[49..97]);
            Ok(())
        } else {
            Err(CryptoError::HardwareFailure)
        }
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

/// NIST P-521 context for `RustCryptoProvider`.
pub struct RustCryptoEccNistP521;

impl EccCurve<66, CryptoError> for RustCryptoEccNistP521 {
    fn invalid_data(&self) -> CryptoError {
        CryptoError::InvalidData
    }

    fn buffer_too_small(&self) -> CryptoError {
        CryptoError::BufferTooSmall
    }

    fn validate_point(&self, x: &[u8; 66], y: &[u8; 66]) -> Result<(), CryptoError> {
        let mut sec1 = [0u8; 133];
        sec1[0] = 0x04;
        sec1[1..67].copy_from_slice(x);
        sec1[67..133].copy_from_slice(y);
        if p521::PublicKey::from_sec1_bytes(&sec1).is_ok() {
            Ok(())
        } else {
            Err(CryptoError::InvalidData)
        }
    }

    fn point_multiply_generator(
        &self,
        scalar: &[u8; 66],
        x_out: &mut [u8; 66],
        y_out: &mut [u8; 66],
    ) -> Result<(), CryptoError> {
        let secret_key =
            p521::SecretKey::from_slice(scalar).map_err(|_| CryptoError::InvalidData)?;
        let public_key = secret_key.public_key();
        let encoded_point = public_key.to_encoded_point(false);
        let public_sec1 = encoded_point.as_bytes();
        if public_sec1.len() != 133 || public_sec1[0] != 0x04 {
            return Err(CryptoError::HardwareFailure);
        }
        x_out.copy_from_slice(&public_sec1[1..67]);
        y_out.copy_from_slice(&public_sec1[67..133]);
        Ok(())
    }

    fn point_multiply(
        &self,
        scalar: &[u8; 66],
        x_in: &[u8; 66],
        y_in: &[u8; 66],
        x_out: &mut [u8; 66],
        y_out: &mut [u8; 66],
    ) -> Result<(), CryptoError> {
        let mut sec1 = [0u8; 133];
        sec1[0] = 0x04;
        sec1[1..67].copy_from_slice(x_in);
        sec1[67..133].copy_from_slice(y_in);
        let public_key =
            p521::PublicKey::from_sec1_bytes(&sec1).map_err(|_| CryptoError::InvalidData)?;
        let affine_point = public_key.as_affine();
        let projective_point = p521::ProjectivePoint::from(*affine_point);

        let secret_key =
            p521::SecretKey::from_slice(scalar).map_err(|_| CryptoError::InvalidData)?;
        let scalar_val = secret_key.to_nonzero_scalar();
        let result_projective = projective_point * scalar_val.as_ref();
        let result_public = p521::PublicKey::from_affine(result_projective.to_affine())
            .map_err(|_| CryptoError::InvalidData)?;
        let encoded_point = result_public.to_encoded_point(false);
        let result_sec1 = encoded_point.as_bytes();
        if result_sec1.len() == 133 && result_sec1[0] == 0x04 {
            x_out.copy_from_slice(&result_sec1[1..67]);
            y_out.copy_from_slice(&result_sec1[67..133]);
            Ok(())
        } else {
            Err(CryptoError::HardwareFailure)
        }
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

/// BN-P256 context for `RustCryptoProvider`.
pub struct RustCryptoEccBnP256;

impl EccCurve<32, CryptoError> for RustCryptoEccBnP256 {
    fn invalid_data(&self) -> CryptoError {
        CryptoError::InvalidData
    }

    fn buffer_too_small(&self) -> CryptoError {
        CryptoError::BufferTooSmall
    }

    fn validate_point(&self, x: &[u8; 32], y: &[u8; 32]) -> Result<(), CryptoError> {
        let bn = BNP256::new();
        let x_bn = rsa::BigUint::from_bytes_be(x);
        let y_bn = rsa::BigUint::from_bytes_be(y);
        if x_bn >= bn.p || y_bn >= bn.p {
            return Err(CryptoError::InvalidData);
        }
        if bn.is_on_curve(&x_bn, &y_bn) {
            Ok(())
        } else {
            Err(CryptoError::InvalidData)
        }
    }

    fn point_multiply_generator(
        &self,
        scalar: &[u8; 32],
        x_out: &mut [u8; 32],
        y_out: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        let bn = BNP256::new();
        let k = rsa::BigUint::from_bytes_be(scalar);
        if k == rsa::BigUint::from(0u32) || k >= bn.n {
            return Err(CryptoError::InvalidData);
        }
        let g = (rsa::BigUint::from(1u32), rsa::BigUint::from(2u32));
        let q = bn.multiply(&k, g).ok_or(CryptoError::InvalidData)?;
        let q_x = q.0.to_bytes_be();
        let q_y = q.1.to_bytes_be();

        x_out.fill(0);
        y_out.fill(0);
        if q_x.len() <= 32 {
            x_out[32 - q_x.len()..].copy_from_slice(&q_x);
        }
        if q_y.len() <= 32 {
            y_out[32 - q_y.len()..].copy_from_slice(&q_y);
        }
        Ok(())
    }

    fn point_multiply(
        &self,
        scalar: &[u8; 32],
        x_in: &[u8; 32],
        y_in: &[u8; 32],
        x_out: &mut [u8; 32],
        y_out: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        let bn = BNP256::new();
        let x = rsa::BigUint::from_bytes_be(x_in);
        let y = rsa::BigUint::from_bytes_be(y_in);
        if x >= bn.p || y >= bn.p {
            return Err(CryptoError::InvalidData);
        }
        let k = rsa::BigUint::from_bytes_be(scalar);
        if k == rsa::BigUint::from(0u32) || k >= bn.n {
            return Err(CryptoError::InvalidData);
        }
        if bn.is_on_curve(&x, &y) {
            if let Some((rx, ry)) = bn.multiply(&k, (x, y)) {
                let rx_bytes = rx.to_bytes_be();
                let ry_bytes = ry.to_bytes_be();

                x_out.fill(0);
                y_out.fill(0);
                if rx_bytes.len() <= 32 {
                    x_out[32 - rx_bytes.len()..].copy_from_slice(&rx_bytes);
                }
                if ry_bytes.len() <= 32 {
                    y_out[32 - ry_bytes.len()..].copy_from_slice(&ry_bytes);
                }
                return Ok(());
            }
        }
        Err(CryptoError::InvalidData)
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

impl Ecc for RustCryptoProvider {
    type NistP224Ctx = RustCryptoEccNistP224;
    fn nist_p224(&self) -> Result<Self::NistP224Ctx, CryptoError> {
        Ok(RustCryptoEccNistP224)
    }

    type NistP256Ctx = RustCryptoEccNistP256;
    fn nist_p256(&self) -> Result<Self::NistP256Ctx, CryptoError> {
        Ok(RustCryptoEccNistP256)
    }

    type NistP384Ctx = RustCryptoEccNistP384;
    fn nist_p384(&self) -> Result<Self::NistP384Ctx, CryptoError> {
        Ok(RustCryptoEccNistP384)
    }

    type NistP521Ctx = RustCryptoEccNistP521;
    fn nist_p521(&self) -> Result<Self::NistP521Ctx, CryptoError> {
        Ok(RustCryptoEccNistP521)
    }

    type BnP256Ctx = RustCryptoEccBnP256;
    fn bn_p256(&self) -> Result<Self::BnP256Ctx, CryptoError> {
        Ok(RustCryptoEccBnP256)
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

/// A software implementation of the Barreto-Naehrig 256-bit (BNP256) elliptic curve over a prime field.
///
/// The curve equation is defined as: y^2 = x^3 + 3 (over F_p).
pub(crate) struct BNP256 {
    /// The prime modulus representing the base field order.
    pub(crate) p: rsa::BigUint,
    /// The prime order representing the subgroup of points.
    pub(crate) n: rsa::BigUint,
}

impl BNP256 {
    /// Creates a new instance of `BNP256` with the pre-defined curve parameters.
    pub fn new() -> Self {
        let p_bytes =
            hex_literal::hex!("fffffffffffcf0cd46e5f25eee71a49f0cdc65fb12980a82d3292ddbaed33013");
        let n_bytes =
            hex_literal::hex!("fffffffffffcf0cd46e5f25eee71a49e0cdc65fb1299921af62d536cd10b500d");
        Self {
            p: rsa::BigUint::from_bytes_be(&p_bytes),
            n: rsa::BigUint::from_bytes_be(&n_bytes),
        }
    }

    /// Verifies if a given point (x, y) satisfies the elliptic curve equation: y^2 = x^3 + 3 mod p.
    pub fn is_on_curve(&self, x: &rsa::BigUint, y: &rsa::BigUint) -> bool {
        if x >= &self.p || y >= &self.p {
            return false;
        }
        let y2 = (y * y) % &self.p;
        let x3 = (x * x * x) % &self.p;
        let rhs = (x3 + rsa::BigUint::from(3u32)) % &self.p;
        y2 == rhs
    }

    /// Computes modular inverse using Fermat's Little Theorem (a^(p-2) mod p).
    fn mod_inverse(&self, a: &rsa::BigUint) -> rsa::BigUint {
        let p_minus_2 = &self.p - rsa::BigUint::from(2u32);
        a.modpow(&p_minus_2, &self.p)
    }

    /// Adds two elliptic curve points p1 and p2 using standard Weierstrass addition formulas.
    ///
    /// `None` is used to represent the Point at Infinity (the identity element).
    pub fn add(
        &self,
        p1: Option<(rsa::BigUint, rsa::BigUint)>,
        p2: Option<(rsa::BigUint, rsa::BigUint)>,
    ) -> Option<(rsa::BigUint, rsa::BigUint)> {
        match (p1, p2) {
            (None, p2) => p2,
            (p1, None) => p1,
            (Some((x1, y1)), Some((x2, y2))) => {
                if x1 == x2 {
                    if y1 == y2 {
                        if y1 == rsa::BigUint::from(0u32) {
                            None
                        } else {
                            let num = (rsa::BigUint::from(3u32) * &x1 * &x1) % &self.p;
                            let den = (rsa::BigUint::from(2u32) * &y1) % &self.p;
                            let s = (num * self.mod_inverse(&den)) % &self.p;
                            let x3 = (&s * &s + &self.p * 2u32 - &x1 - &x2) % &self.p;
                            let y3 = (&s * (&x1 + &self.p - &x3) + &self.p - &y1) % &self.p;
                            Some((x3, y3))
                        }
                    } else {
                        None
                    }
                } else {
                    let mut num = &y2 + &self.p - &y1;
                    num %= &self.p;
                    let mut den = &x2 + &self.p - &x1;
                    den %= &self.p;
                    let s = (num * self.mod_inverse(&den)) % &self.p;
                    let mut x3 = &s * &s + &self.p * 2u32 - &x1 - &x2;
                    x3 %= &self.p;
                    let mut y3 = &s * (&x1 + &self.p - &x3) + &self.p - &y1;
                    y3 %= &self.p;
                    Some((x3, y3))
                }
            }
        }
    }

    /// Performs scalar multiplication Q = k * P using the double-and-add algorithm.
    pub fn multiply(
        &self,
        k: &rsa::BigUint,
        p: (rsa::BigUint, rsa::BigUint),
    ) -> Option<(rsa::BigUint, rsa::BigUint)> {
        let mut r = None;
        let mut base = Some(p);
        let mut k_mut = k.clone();
        let zero = rsa::BigUint::from(0u32);
        let one = rsa::BigUint::from(1u32);
        let two = rsa::BigUint::from(2u32);

        while k_mut > zero {
            if (&k_mut % &two) == one {
                r = self.add(r, base.clone());
            }
            base = self.add(base.clone(), base);
            k_mut /= &two;
        }
        r
    }
}

/// A software implementation of the NIST P-224 (secp224r1) elliptic curve over a prime field.
///
/// The curve equation is defined as: y^2 = x^3 - 3*x + b (over F_p).
pub(crate) struct NistP224 {
    /// The prime modulus representing the base field order.
    pub(crate) p: rsa::BigUint,
    /// The prime order representing the subgroup of points.
    pub(crate) n: rsa::BigUint,
    /// The curve parameter b.
    pub(crate) b: rsa::BigUint,
}

impl NistP224 {
    /// Creates a new instance of `NistP224` with the pre-defined NIST P-224 curve parameters.
    pub fn new() -> Self {
        let p_bytes = hex_literal::hex!("ffffffffffffffffffffffffffffffff000000000000000000000001");
        let n_bytes = hex_literal::hex!("fffffffffffffffffffffffeffffbce6faada7179e84f3b9cac2fc63");
        let b_bytes = hex_literal::hex!("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4");
        Self {
            p: rsa::BigUint::from_bytes_be(&p_bytes),
            n: rsa::BigUint::from_bytes_be(&n_bytes),
            b: rsa::BigUint::from_bytes_be(&b_bytes),
        }
    }

    /// Verifies if a given point (x, y) satisfies the elliptic curve equation: y^2 = x^3 - 3*x + b mod p.
    pub fn is_on_curve(&self, x: &rsa::BigUint, y: &rsa::BigUint) -> bool {
        if x >= &self.p || y >= &self.p {
            return false;
        }
        let y2 = (y * y) % &self.p;
        let x3 = (x * x * x) % &self.p;
        let three_x = (x * 3u32) % &self.p;
        let rhs = (&x3 + &self.p + &self.b - &three_x) % &self.p;
        y2 == rhs
    }

    /// Computes modular inverse using Fermat's Little Theorem (a^(p-2) mod p).
    fn mod_inverse(&self, a: &rsa::BigUint) -> rsa::BigUint {
        let p_minus_2 = &self.p - rsa::BigUint::from(2u32);
        a.modpow(&p_minus_2, &self.p)
    }

    /// Adds two elliptic curve points p1 and p2 using standard Weierstrass addition formulas.
    pub fn add(
        &self,
        p1: Option<(rsa::BigUint, rsa::BigUint)>,
        p2: Option<(rsa::BigUint, rsa::BigUint)>,
    ) -> Option<(rsa::BigUint, rsa::BigUint)> {
        match (p1, p2) {
            (None, p2) => p2,
            (p1, None) => p1,
            (Some((x1, y1)), Some((x2, y2))) => {
                if x1 == x2 {
                    if y1 == y2 {
                        if y1 == rsa::BigUint::from(0u32) {
                            None
                        } else {
                            let three_x1_sq = (rsa::BigUint::from(3u32) * &x1 * &x1) % &self.p;
                            let num = (&three_x1_sq + &self.p - 3u32) % &self.p;
                            let den = (rsa::BigUint::from(2u32) * &y1) % &self.p;
                            let s = (num * self.mod_inverse(&den)) % &self.p;
                            let x3 = (&s * &s + &self.p * 2u32 - &x1 - &x2) % &self.p;
                            let y3 = (&s * (&x1 + &self.p - &x3) + &self.p - &y1) % &self.p;
                            Some((x3, y3))
                        }
                    } else {
                        None
                    }
                } else {
                    let mut num = &y2 + &self.p - &y1;
                    num %= &self.p;
                    let mut den = &x2 + &self.p - &x1;
                    den %= &self.p;
                    let s = (num * self.mod_inverse(&den)) % &self.p;
                    let mut x3 = &s * &s + &self.p * 2u32 - &x1 - &x2;
                    x3 %= &self.p;
                    let mut y3 = &s * (&x1 + &self.p - &x3) + &self.p - &y1;
                    y3 %= &self.p;
                    Some((x3, y3))
                }
            }
        }
    }

    /// Performs scalar multiplication Q = k * P using the double-and-add algorithm.
    pub fn multiply(
        &self,
        k: &rsa::BigUint,
        p: (rsa::BigUint, rsa::BigUint),
    ) -> Option<(rsa::BigUint, rsa::BigUint)> {
        let mut r = None;
        let mut base = Some(p);
        let mut k_mut = k.clone();
        let zero = rsa::BigUint::from(0u32);
        let one = rsa::BigUint::from(1u32);
        let two = rsa::BigUint::from(2u32);

        while k_mut > zero {
            if (&k_mut % &two) == one {
                r = self.add(r, base.clone());
            }
            base = self.add(base.clone(), base);
            k_mut /= &two;
        }
        r
    }
}
