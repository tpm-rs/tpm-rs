use crate::CruxCryptoProvider;
use tpm2::crypto::{CryptoError, Ecc, EccCurve};

/// NIST P-256 context for `CruxCryptoProvider` (`libcrux-p256`).
pub struct CruxEccNistP256;

impl EccCurve<32> for CruxEccNistP256 {
    fn validate_point(&self, x: &[u8; 32], y: &[u8; 32]) -> Result<bool, CryptoError> {
        let mut pub_key = [0u8; 64];
        pub_key[..32].copy_from_slice(x);
        pub_key[32..].copy_from_slice(y);
        Ok(libcrux_p256::validate_public_key(&pub_key))
    }

    fn point_multiply_generator(
        &self,
        scalar: &[u8; 32],
        x_out: &mut [u8; 32],
        y_out: &mut [u8; 32],
    ) -> Result<Option<()>, CryptoError> {
        let mut pub_64 = [0u8; 64];
        if libcrux_p256::dh_initiator(&mut pub_64, scalar) {
            x_out.copy_from_slice(&pub_64[..32]);
            y_out.copy_from_slice(&pub_64[32..]);
            Ok(Some(()))
        } else {
            Ok(None)
        }
    }

    fn point_multiply(
        &self,
        scalar: &[u8; 32],
        x_in: &[u8; 32],
        y_in: &[u8; 32],
        x_out: &mut [u8; 32],
        y_out: &mut [u8; 32],
    ) -> Result<Option<()>, CryptoError> {
        let mut public_point = [0u8; 64];
        public_point[..32].copy_from_slice(x_in);
        public_point[32..].copy_from_slice(y_in);
        let mut derived_64 = [0u8; 64];
        if libcrux_p256::dh_responder(&mut derived_64, &public_point, scalar) {
            x_out.copy_from_slice(&derived_64[..32]);
            y_out.copy_from_slice(&derived_64[32..]);
            Ok(Some(()))
        } else {
            Ok(None)
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
    ) -> Result<Option<()>, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

/// NIST P-384 context for `CruxCryptoProvider` (RustCrypto `p384`).
pub struct CruxEccNistP384;

impl EccCurve<48> for CruxEccNistP384 {
    fn validate_point(&self, x: &[u8; 48], y: &[u8; 48]) -> Result<bool, CryptoError> {
        let mut sec1 = [0u8; 97];
        sec1[0] = 0x04;
        sec1[1..49].copy_from_slice(x);
        sec1[49..97].copy_from_slice(y);
        Ok(p384::PublicKey::from_sec1_bytes(&sec1).is_ok())
    }

    fn point_multiply_generator(
        &self,
        scalar: &[u8; 48],
        x_out: &mut [u8; 48],
        y_out: &mut [u8; 48],
    ) -> Result<Option<()>, CryptoError> {
        let Ok(secret_key) = p384::SecretKey::from_slice(scalar) else {
            return Ok(None);
        };
        let public_key = secret_key.public_key();
        use p384::elliptic_curve::sec1::ToEncodedPoint as _;
        let encoded_point = public_key.to_encoded_point(false);
        let public_sec1 = encoded_point.as_bytes();
        if public_sec1.len() != 97 || public_sec1[0] != 0x04 {
            return Err(CryptoError::Internal);
        }
        x_out.copy_from_slice(&public_sec1[1..49]);
        y_out.copy_from_slice(&public_sec1[49..97]);
        Ok(Some(()))
    }

    fn point_multiply(
        &self,
        scalar: &[u8; 48],
        x_in: &[u8; 48],
        y_in: &[u8; 48],
        x_out: &mut [u8; 48],
        y_out: &mut [u8; 48],
    ) -> Result<Option<()>, CryptoError> {
        let mut sec1 = [0u8; 97];
        sec1[0] = 0x04;
        sec1[1..49].copy_from_slice(x_in);
        sec1[49..97].copy_from_slice(y_in);
        let Ok(public_key) = p384::PublicKey::from_sec1_bytes(&sec1) else {
            return Ok(None);
        };
        let affine_point = public_key.as_affine();
        let projective_point = p384::ProjectivePoint::from(*affine_point);

        let Ok(secret_key) = p384::SecretKey::from_slice(scalar) else {
            return Ok(None);
        };
        let scalar_val = secret_key.to_nonzero_scalar();
        let result_projective = projective_point * scalar_val.as_ref();
        // The product is the point at infinity.
        let Ok(result_public) = p384::PublicKey::from_affine(result_projective.to_affine()) else {
            return Ok(None);
        };
        use p384::elliptic_curve::sec1::ToEncodedPoint as _;
        let encoded_point = result_public.to_encoded_point(false);
        let result_sec1 = encoded_point.as_bytes();
        if result_sec1.len() == 97 && result_sec1[0] == 0x04 {
            x_out.copy_from_slice(&result_sec1[1..49]);
            y_out.copy_from_slice(&result_sec1[49..97]);
            Ok(Some(()))
        } else {
            Err(CryptoError::Internal)
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
    ) -> Result<Option<()>, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

/// NIST P-521 context for `CruxCryptoProvider` (RustCrypto `p521`).
pub struct CruxEccNistP521;

impl EccCurve<66> for CruxEccNistP521 {
    fn validate_point(&self, x: &[u8; 66], y: &[u8; 66]) -> Result<bool, CryptoError> {
        let mut sec1 = [0u8; 133];
        sec1[0] = 0x04;
        sec1[1..67].copy_from_slice(x);
        sec1[67..133].copy_from_slice(y);
        Ok(p521::PublicKey::from_sec1_bytes(&sec1).is_ok())
    }

    fn point_multiply_generator(
        &self,
        scalar: &[u8; 66],
        x_out: &mut [u8; 66],
        y_out: &mut [u8; 66],
    ) -> Result<Option<()>, CryptoError> {
        let Ok(secret_key) = p521::SecretKey::from_slice(scalar) else {
            return Ok(None);
        };
        let public_key = secret_key.public_key();
        use p521::elliptic_curve::sec1::ToEncodedPoint as _;
        let encoded_point = public_key.to_encoded_point(false);
        let public_sec1 = encoded_point.as_bytes();
        if public_sec1.len() != 133 || public_sec1[0] != 0x04 {
            return Err(CryptoError::Internal);
        }
        x_out.copy_from_slice(&public_sec1[1..67]);
        y_out.copy_from_slice(&public_sec1[67..133]);
        Ok(Some(()))
    }

    fn point_multiply(
        &self,
        scalar: &[u8; 66],
        x_in: &[u8; 66],
        y_in: &[u8; 66],
        x_out: &mut [u8; 66],
        y_out: &mut [u8; 66],
    ) -> Result<Option<()>, CryptoError> {
        let mut sec1 = [0u8; 133];
        sec1[0] = 0x04;
        sec1[1..67].copy_from_slice(x_in);
        sec1[67..133].copy_from_slice(y_in);
        let Ok(public_key) = p521::PublicKey::from_sec1_bytes(&sec1) else {
            return Ok(None);
        };
        let affine_point = public_key.as_affine();
        let projective_point = p521::ProjectivePoint::from(*affine_point);

        let Ok(secret_key) = p521::SecretKey::from_slice(scalar) else {
            return Ok(None);
        };
        let scalar_val = secret_key.to_nonzero_scalar();
        let result_projective = projective_point * scalar_val.as_ref();
        // The product is the point at infinity.
        let Ok(result_public) = p521::PublicKey::from_affine(result_projective.to_affine()) else {
            return Ok(None);
        };
        use p521::elliptic_curve::sec1::ToEncodedPoint as _;
        let encoded_point = result_public.to_encoded_point(false);
        let result_sec1 = encoded_point.as_bytes();
        if result_sec1.len() == 133 && result_sec1[0] == 0x04 {
            x_out.copy_from_slice(&result_sec1[1..67]);
            y_out.copy_from_slice(&result_sec1[67..133]);
            Ok(Some(()))
        } else {
            Err(CryptoError::Internal)
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
    ) -> Result<Option<()>, CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

/// BN-P256 context for `CruxCryptoProvider` (affine big-integer arithmetic).
pub struct CruxEccBnP256;

impl EccCurve<32> for CruxEccBnP256 {
    fn validate_point(&self, x: &[u8; 32], y: &[u8; 32]) -> Result<bool, CryptoError> {
        let bn = BNP256::new();
        let x_bn = rsa::BigUint::from_bytes_be(x);
        let y_bn = rsa::BigUint::from_bytes_be(y);
        if x_bn >= bn.p || y_bn >= bn.p {
            return Ok(false);
        }
        Ok(bn.is_on_curve(&x_bn, &y_bn))
    }

    fn point_multiply_generator(
        &self,
        scalar: &[u8; 32],
        x_out: &mut [u8; 32],
        y_out: &mut [u8; 32],
    ) -> Result<Option<()>, CryptoError> {
        let bn = BNP256::new();
        let k = rsa::BigUint::from_bytes_be(scalar);
        if k == rsa::BigUint::from(0u32) || k >= bn.n {
            return Ok(None);
        }
        let g = (rsa::BigUint::from(1u32), rsa::BigUint::from(2u32));
        let Some(q) = bn.multiply(&k, g) else {
            return Ok(None);
        };
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
        Ok(Some(()))
    }

    fn point_multiply(
        &self,
        scalar: &[u8; 32],
        x_in: &[u8; 32],
        y_in: &[u8; 32],
        x_out: &mut [u8; 32],
        y_out: &mut [u8; 32],
    ) -> Result<Option<()>, CryptoError> {
        let bn = BNP256::new();
        let x = rsa::BigUint::from_bytes_be(x_in);
        let y = rsa::BigUint::from_bytes_be(y_in);
        if x >= bn.p || y >= bn.p {
            return Ok(None);
        }
        let k = rsa::BigUint::from_bytes_be(scalar);
        if k == rsa::BigUint::from(0u32) || k >= bn.n {
            return Ok(None);
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
            return Ok(Some(()));
        }
        // The point is not on the curve, or the product is the point at infinity.
        Ok(None)
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

impl Ecc for CruxCryptoProvider {
    type NistP256Context = CruxEccNistP256;
    fn nist_p256(&self) -> Result<Self::NistP256Context, CryptoError> {
        Ok(CruxEccNistP256)
    }

    type NistP384Context = CruxEccNistP384;
    fn nist_p384(&self) -> Result<Self::NistP384Context, CryptoError> {
        Ok(CruxEccNistP384)
    }

    type NistP521Context = CruxEccNistP521;
    fn nist_p521(&self) -> Result<Self::NistP521Context, CryptoError> {
        Ok(CruxEccNistP521)
    }

    type BnP256Context = CruxEccBnP256;
    fn bn_p256(&self) -> Result<Self::BnP256Context, CryptoError> {
        Ok(CruxEccBnP256)
    }

    type NistP192Context = !;
    type NistP224Context = !;
    type BnP638Context = !;
    type Sm2P256Context = !;
    type BpP256R1Context = !;
    type BpP384R1Context = !;
    type BpP512R1Context = !;
    type Curve25519Context = !;
    type Curve448Context = !;
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

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use tpm2::TpmEccCurve;

    /// The generator `x || y` of each implemented curve, with its order `n`.
    fn generator_and_order(curve: TpmEccCurve) -> (Vec<u8>, Vec<u8>) {
        match curve {
            TpmEccCurve::NistP256 => (
                hex!(
                    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
                )
                .to_vec(),
                hex!("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551").to_vec(),
            ),
            TpmEccCurve::NistP384 => (
                hex!(
                    "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
                    "5502f25dbf55296c3a545e3872760ab7"
                    "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
                    "0a60b1ce1d7e819d7a431d7c90ea0e5f"
                )
                .to_vec(),
                hex!(
                    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
                    "581a0db248b0a77aecec196accc52973"
                )
                .to_vec(),
            ),
            TpmEccCurve::NistP521 => (
                hex!(
                    "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d"
                    "3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5"
                    "bd66"
                    "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e"
                    "662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd1"
                    "6650"
                )
                .to_vec(),
                hex!(
                    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    "fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138"
                    "6409"
                )
                .to_vec(),
            ),
            TpmEccCurve::BNP256 => {
                let mut g = [0u8; 64];
                g[31] = 1;
                g[63] = 2;
                (g.to_vec(), BNP256::new().n.to_bytes_be())
            }
            _ => unreachable!(),
        }
    }

    const CURVES: [TpmEccCurve; 4] = [
        TpmEccCurve::NistP256,
        TpmEccCurve::NistP384,
        TpmEccCurve::NistP521,
        TpmEccCurve::BNP256,
    ];

    #[test]
    fn generator_times_one_is_the_generator() {
        let c = CruxCryptoProvider;
        for curve in CURVES {
            let (g, _) = generator_and_order(curve);
            let mut out = vec![0u8; g.len()];
            assert_eq!(
                Ecc::point_multiply_generator(&c, curve, &[1], &mut out),
                Ok(Some(g.len())),
                "{curve:?}"
            );
            assert_eq!(out, g, "{curve:?}");
            assert_eq!(Ecc::validate_point(&c, curve, &g), Ok(true), "{curve:?}");

            // 1 * G through the generic point multiplication.
            let mut out2 = vec![0u8; g.len()];
            assert_eq!(
                Ecc::point_multiply(&c, curve, &[1], &g, &mut out2),
                Ok(Some(g.len())),
                "{curve:?}"
            );
            assert_eq!(out2, g, "{curve:?}");
        }
    }

    #[test]
    fn point_multiply_agrees_with_generator_multiplication() {
        let c = CruxCryptoProvider;
        for curve in CURVES {
            let (g, _) = generator_and_order(curve);
            let mut two_g = vec![0u8; g.len()];
            Ecc::point_multiply_generator(&c, curve, &[2], &mut two_g)
                .unwrap()
                .unwrap();
            let mut six_g = vec![0u8; g.len()];
            Ecc::point_multiply_generator(&c, curve, &[6], &mut six_g)
                .unwrap()
                .unwrap();
            // 3 * (2 * G) == 6 * G
            let mut out = vec![0u8; g.len()];
            assert_eq!(
                Ecc::point_multiply(&c, curve, &[3], &two_g, &mut out),
                Ok(Some(g.len())),
                "{curve:?}"
            );
            assert_eq!(out, six_g, "{curve:?}");
        }
    }

    #[test]
    fn invalid_points_and_scalars_are_reported_in_the_ok_value() {
        let c = CruxCryptoProvider;
        for curve in CURVES {
            let (g, n) = generator_and_order(curve);
            let mut off_curve = g.clone();
            *off_curve.last_mut().unwrap() ^= 1;
            assert_eq!(
                Ecc::validate_point(&c, curve, &off_curve),
                Ok(false),
                "{curve:?}"
            );
            assert_eq!(
                Ecc::validate_point(&c, curve, &g[1..]),
                Ok(false),
                "{curve:?}"
            );
            assert_eq!(
                Ecc::validate_point(&c, curve, &vec![0xff; g.len()]),
                Ok(false),
                "{curve:?}"
            );

            let mut out = vec![0u8; g.len()];
            for scalar in [&[0u8][..], &n] {
                assert_eq!(
                    Ecc::point_multiply_generator(&c, curve, scalar, &mut out),
                    Ok(None),
                    "{curve:?}"
                );
                assert_eq!(
                    Ecc::point_multiply(&c, curve, scalar, &g, &mut out),
                    Ok(None),
                    "{curve:?}"
                );
            }
            assert_eq!(
                Ecc::point_multiply(&c, curve, &[2], &off_curve, &mut out),
                Ok(None),
                "{curve:?}"
            );
            // A scalar longer than the curve size, and an output buffer too small.
            let long_scalar = vec![1u8; g.len() / 2 + 1];
            assert_eq!(
                Ecc::point_multiply_generator(&c, curve, &long_scalar, &mut out),
                Ok(None),
                "{curve:?}"
            );
            assert_eq!(
                Ecc::point_multiply_generator(&c, curve, &[1], &mut out[1..]),
                Err(CryptoError::Internal),
                "{curve:?}"
            );
            assert_eq!(
                Ecc::point_multiply(&c, curve, &[1], &g, &mut out[1..]),
                Err(CryptoError::Internal),
                "{curve:?}"
            );
        }
    }

    #[test]
    fn ecdaa_and_unimplemented_curves_are_unsupported() {
        let c = CruxCryptoProvider;
        for curve in CURVES {
            let (g, _) = generator_and_order(curve);
            let len = g.len() / 2;
            let (mut k, mut s) = (vec![0u8; len], vec![0u8; len]);
            assert_eq!(
                Ecc::ecdaa_sign(&c, curve, &[1], &g, &g, &[1], &[0; 32], &mut k, &mut s),
                Err(CryptoError::Unsupported),
                "{curve:?}"
            );
        }
        let mut out = [0u8; 160];
        for curve in [TpmEccCurve::None, TpmEccCurve::NistP224] {
            assert_eq!(
                Ecc::point_multiply_generator(&c, curve, &[1], &mut out),
                Err(CryptoError::Unsupported),
                "{curve:?}"
            );
        }
    }
}
