use crate::CruxCryptoProvider;
use tpm2::crypto::{CryptoError, Ecc, EccCurve};

/// NIST P-256 context for `CruxCryptoProvider`.
pub struct CruxEccNistP256;

impl EccCurve<32, CryptoError> for CruxEccNistP256 {
    fn invalid_data(&self) -> CryptoError {
        CryptoError::InvalidData
    }

    fn buffer_too_small(&self) -> CryptoError {
        CryptoError::BufferTooSmall
    }

    fn validate_point(&self, x: &[u8; 32], y: &[u8; 32]) -> Result<(), CryptoError> {
        let mut pub_key = [0u8; 64];
        pub_key[..32].copy_from_slice(x);
        pub_key[32..].copy_from_slice(y);
        if libcrux_p256::validate_public_key(&pub_key) {
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
        let mut pub_64 = [0u8; 64];
        if libcrux_p256::dh_initiator(&mut pub_64, scalar) {
            x_out.copy_from_slice(&pub_64[..32]);
            y_out.copy_from_slice(&pub_64[32..]);
            Ok(())
        } else {
            Err(CryptoError::InvalidData)
        }
    }

    fn point_multiply(
        &self,
        scalar: &[u8; 32],
        x_in: &[u8; 32],
        y_in: &[u8; 32],
        x_out: &mut [u8; 32],
        y_out: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        let mut public_point = [0u8; 64];
        public_point[..32].copy_from_slice(x_in);
        public_point[32..].copy_from_slice(y_in);
        let mut derived_64 = [0u8; 64];
        if libcrux_p256::dh_responder(&mut derived_64, &public_point, scalar) {
            x_out.copy_from_slice(&derived_64[..32]);
            y_out.copy_from_slice(&derived_64[32..]);
            Ok(())
        } else {
            Err(CryptoError::InvalidData)
        }
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

/// NIST P-384 context for `CruxCryptoProvider`.
pub struct CruxEccNistP384;

impl EccCurve<48, CryptoError> for CruxEccNistP384 {
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
        use p384::elliptic_curve::sec1::ToEncodedPoint as _;
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
        use p384::elliptic_curve::sec1::ToEncodedPoint as _;
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

/// NIST P-521 context for `CruxCryptoProvider`.
pub struct CruxEccNistP521;

impl EccCurve<66, CryptoError> for CruxEccNistP521 {
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
        use p521::elliptic_curve::sec1::ToEncodedPoint as _;
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
        use p521::elliptic_curve::sec1::ToEncodedPoint as _;
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

/// BN-P256 context for `CruxCryptoProvider`.
pub struct CruxEccBnP256;

impl EccCurve<32, CryptoError> for CruxEccBnP256 {
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
        if bn.is_on_curve(&x, &y)
            && let Some((rx, ry)) = bn.multiply(&k, (x, y))
        {
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

impl Ecc for CruxCryptoProvider {
    type NistP256Ctx = CruxEccNistP256;
    fn nist_p256(&self) -> Result<Self::NistP256Ctx, CryptoError> {
        Ok(CruxEccNistP256)
    }

    type NistP384Ctx = CruxEccNistP384;
    fn nist_p384(&self) -> Result<Self::NistP384Ctx, CryptoError> {
        Ok(CruxEccNistP384)
    }

    type NistP521Ctx = CruxEccNistP521;
    fn nist_p521(&self) -> Result<Self::NistP521Ctx, CryptoError> {
        Ok(CruxEccNistP521)
    }

    type BnP256Ctx = CruxEccBnP256;
    fn bn_p256(&self) -> Result<Self::BnP256Ctx, CryptoError> {
        Ok(CruxEccBnP256)
    }

    type NistP192Ctx = !;
    type NistP224Ctx = !;
    type BnP638Ctx = !;
    type Sm2P256Ctx = !;
    type BpP256R1Ctx = !;
    type BpP384R1Ctx = !;
    type BpP512R1Ctx = !;
    type Curve25519Ctx = !;
    type Curve448Ctx = !;
}

pub(crate) struct BNP256 {
    pub(crate) p: rsa::BigUint,
    pub(crate) n: rsa::BigUint,
}

impl BNP256 {
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

    pub fn is_on_curve(&self, x: &rsa::BigUint, y: &rsa::BigUint) -> bool {
        if x >= &self.p || y >= &self.p {
            return false;
        }
        let y2 = (y * y) % &self.p;
        let x3 = (x * x * x) % &self.p;
        let rhs = (x3 + rsa::BigUint::from(3u32)) % &self.p;
        y2 == rhs
    }

    fn mod_inverse(&self, a: &rsa::BigUint) -> rsa::BigUint {
        let p_minus_2 = &self.p - rsa::BigUint::from(2u32);
        a.modpow(&p_minus_2, &self.p)
    }

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
