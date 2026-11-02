//! Domain parameters of the TCG-registered ECC curves (`TPMS_ALGORITHM_DETAIL_ECC`).
//!
//! The parameters are those of TPM 2.0 Part 4 / the TCG Algorithm Registry (and of the
//! reference implementation's `EccConstantData.inl`): every curve is a short Weierstrass curve
//! `y^2 = x^3 + a*x + b` over the prime field `GF(p)` with base point `G = (gx, gy)` of prime
//! order `n` and cofactor `h`.
//!
//! The parameters of every curve are always available as statics (e.g. [`NIST_P192`]), so that
//! crypto backends can implement curves generically without enabling `tpm2` features (which
//! would widen the TPM built with them); [`ecc_curve_params`] returns a curve only if the
//! corresponding `ecc_curve_*` [crate feature](crate#algorithm-feature-flags) is enabled. The
//! table is shared by the TPM (`TPM2_ECC_Parameters`, scalar ranges, point arithmetic the crypto
//! provider does not offer) and by the crypto backends.

use crate::constants::TpmEccCurve;

/// The domain parameters of one ECC curve.
///
/// All values are unsigned big-endian byte strings. `p`, `a`, `b`, `gx` and `gy` are padded with
/// leading zeros to the coordinate size of the curve ([`TpmEccCurve::parameter_size`]); `n` is
/// the order without leading zero bytes (its size is the scalar size of the curve, equal to the
/// coordinate size for every registered curve) and `h` is the minimal encoding of the cofactor.
#[derive(Debug, PartialEq, Eq)]
pub struct EccCurveParams {
    /// The curve identifier (`TPM_ECC_CURVE`).
    pub curve_id: u16,
    /// The size of the curve in bits (`TPMS_ALGORITHM_DETAIL_ECC.keySize`).
    pub key_bits: u16,
    /// The field prime `p`.
    pub p: &'static [u8],
    /// The coefficient `a` of the curve equation.
    pub a: &'static [u8],
    /// The coefficient `b` of the curve equation.
    pub b: &'static [u8],
    /// The x coordinate of the base point `G`.
    pub gx: &'static [u8],
    /// The y coordinate of the base point `G`.
    pub gy: &'static [u8],
    /// The order `n` of the base point `G`.
    pub n: &'static [u8],
    /// The cofactor `h`.
    pub h: &'static [u8],
}

impl EccCurveParams {
    /// The coordinate size of the curve in bytes (the size of `p`).
    pub const fn coordinate_size(&self) -> usize {
        self.p.len()
    }

    /// The scalar size of the curve in bytes (the size of `n`).
    pub const fn scalar_size(&self) -> usize {
        self.n.len()
    }
}

/// Decodes the hexadecimal string `s` (exactly `2 * N` hex digits) into `N` bytes at compile time.
const fn hex<const N: usize>(s: &str) -> [u8; N] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("invalid hex digit"),
        }
    }
    let s = s.as_bytes();
    assert!(s.len() == 2 * N, "hex string of the wrong length");
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (nibble(s[2 * i]) << 4) | nibble(s[2 * i + 1]);
        i += 1;
    }
    out
}

/// A cofactor of one.
const ONE: [u8; 1] = [1];

/// NIST P-192 (FIPS 186-4, D.1.2.1).
pub static NIST_P192: EccCurveParams = EccCurveParams {
    curve_id: 0x0001,
    key_bits: 192,
    p: &hex::<24>("fffffffffffffffffffffffffffffffeffffffffffffffff"),
    a: &hex::<24>("fffffffffffffffffffffffffffffffefffffffffffffffc"),
    b: &hex::<24>("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1"),
    gx: &hex::<24>("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012"),
    gy: &hex::<24>("07192b95ffc8da78631011ed6b24cdd573f977a11e794811"),
    n: &hex::<24>("ffffffffffffffffffffffff99def836146bc9b1b4d22831"),
    h: &ONE,
};

/// NIST P-224 (FIPS 186-4, D.1.2.2).
pub static NIST_P224: EccCurveParams = EccCurveParams {
    curve_id: 0x0002,
    key_bits: 224,
    p: &hex::<28>("ffffffffffffffffffffffffffffffff000000000000000000000001"),
    a: &hex::<28>("fffffffffffffffffffffffffffffffefffffffffffffffffffffffe"),
    b: &hex::<28>("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4"),
    gx: &hex::<28>("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21"),
    gy: &hex::<28>("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"),
    n: &hex::<28>("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d"),
    h: &ONE,
};

/// NIST P-256 (FIPS 186-4, D.1.2.3).
pub static NIST_P256: EccCurveParams = EccCurveParams {
    curve_id: 0x0003,
    key_bits: 256,
    p: &hex::<32>("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
    a: &hex::<32>("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
    b: &hex::<32>("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
    gx: &hex::<32>("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
    gy: &hex::<32>("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
    n: &hex::<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
    h: &ONE,
};

/// NIST P-384 (FIPS 186-4, D.1.2.4).
pub static NIST_P384: EccCurveParams = EccCurveParams {
    curve_id: 0x0004,
    key_bits: 384,
    p: &hex::<48>(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    ),
    a: &hex::<48>(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
    ),
    b: &hex::<48>(
        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    ),
    gx: &hex::<48>(
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    ),
    gy: &hex::<48>(
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
    ),
    n: &hex::<48>(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    ),
    h: &ONE,
};

/// NIST P-521 (FIPS 186-4, D.1.2.5).
pub static NIST_P521: EccCurveParams = EccCurveParams {
    curve_id: 0x0005,
    key_bits: 521,
    p: &hex::<66>(
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ),
    a: &hex::<66>(
        "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
    ),
    b: &hex::<66>(
        "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
    ),
    gx: &hex::<66>(
        "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
    ),
    gy: &hex::<66>(
        "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
    ),
    n: &hex::<66>(
        "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
    ),
    h: &ONE,
};

/// BN P-256 (ISO/IEC 15946-5, the Barreto-Naehrig curve with `b = 3` and `G = (1, 2)`).
pub static BN_P256: EccCurveParams = EccCurveParams {
    curve_id: 0x0010,
    key_bits: 256,
    p: &hex::<32>("fffffffffffcf0cd46e5f25eee71a49f0cdc65fb12980a82d3292ddbaed33013"),
    a: &[0; 32],
    b: &hex::<32>("0000000000000000000000000000000000000000000000000000000000000003"),
    gx: &hex::<32>("0000000000000000000000000000000000000000000000000000000000000001"),
    gy: &hex::<32>("0000000000000000000000000000000000000000000000000000000000000002"),
    n: &hex::<32>("fffffffffffcf0cd46e5f25eee71a49e0cdc65fb1299921af62d536cd10b500d"),
    h: &ONE,
};

/// BN P-638 (ISO/IEC 15946-5, the Barreto-Naehrig curve with `b = 257` and `G = (-1, 16)`).
pub static BN_P638: EccCurveParams = EccCurveParams {
    curve_id: 0x0011,
    key_bits: 638,
    p: &hex::<80>(
        "23fffffdc000000d7fffffb8000001d3fffff942d000165e3fff94870000d52ffffdd0e00008de55c00086520021e55bfffff51ffff4eb800000004c80015acdffffffffffffece00000000000000067",
    ),
    a: &[0; 80],
    b: &hex::<80>(
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101",
    ),
    gx: &hex::<80>(
        "23fffffdc000000d7fffffb8000001d3fffff942d000165e3fff94870000d52ffffdd0e00008de55c00086520021e55bfffff51ffff4eb800000004c80015acdffffffffffffece00000000000000066",
    ),
    gy: &hex::<80>(
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010",
    ),
    n: &hex::<80>(
        "23fffffdc000000d7fffffb8000001d3fffff942d000165e3fff94870000d52ffffdd0e00008de55600086550021e555fffff54ffff4eac000000049800154d9ffffffffffffeda00000000000000061",
    ),
    h: &ONE,
};

/// SM2 P-256 (GB/T 32918.5-2017, the recommended curve of the SM2 algorithms).
pub static SM2_P256: EccCurveParams = EccCurveParams {
    curve_id: 0x0020,
    key_bits: 256,
    p: &hex::<32>("fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff"),
    a: &hex::<32>("fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc"),
    b: &hex::<32>("28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93"),
    gx: &hex::<32>("32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"),
    gy: &hex::<32>("bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"),
    n: &hex::<32>("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123"),
    h: &ONE,
};

/// Returns the domain parameters of `curve`, or `None` for [`TpmEccCurve::None`] and for curves
/// without parameters in this table (Brainpool, Curve25519 and Curve448).
pub fn ecc_curve_params(curve: TpmEccCurve) -> Option<&'static EccCurveParams> {
    match curve {
        #[cfg(feature = "ecc_curve_nist_p192")]
        TpmEccCurve::NistP192 => Some(&NIST_P192),
        #[cfg(feature = "ecc_curve_nist_p224")]
        TpmEccCurve::NistP224 => Some(&NIST_P224),
        #[cfg(feature = "ecc_curve_nist_p256")]
        TpmEccCurve::NistP256 => Some(&NIST_P256),
        #[cfg(feature = "ecc_curve_nist_p384")]
        TpmEccCurve::NistP384 => Some(&NIST_P384),
        #[cfg(feature = "ecc_curve_nist_p521")]
        TpmEccCurve::NistP521 => Some(&NIST_P521),
        #[cfg(feature = "ecc_curve_bn_p256")]
        TpmEccCurve::BNP256 => Some(&BN_P256),
        #[cfg(feature = "ecc_curve_bn_p638")]
        TpmEccCurve::BNP638 => Some(&BN_P638),
        #[cfg(feature = "ecc_curve_sm2_p256")]
        TpmEccCurve::SM2P256 => Some(&SM2_P256),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every curve's parameters are consistent: sizes match the key size, `n` has no leading
    /// zero byte, and `G` satisfies the curve equation (checked with a schoolbook big-integer
    /// evaluation).
    #[test]
    fn parameters_are_consistent() {
        for c in [
            &NIST_P192, &NIST_P224, &NIST_P256, &NIST_P384, &NIST_P521, &BN_P256, &BN_P638,
            &SM2_P256,
        ] {
            let size = usize::from(c.key_bits).div_ceil(8);
            assert_eq!(c.coordinate_size(), size);
            assert_eq!(c.scalar_size(), size);
            for v in [c.a, c.b, c.gx, c.gy] {
                assert_eq!(v.len(), size);
                assert!(v < c.p);
            }
            assert_ne!(c.n[0], 0);
            assert_eq!(c.h, &[1]);
            // y^2 == x^3 + a*x + b (mod p)
            let lhs = mod_mul(c.gy, c.gy, c.p);
            let x3 = mod_mul(&mod_mul(c.gx, c.gx, c.p), c.gx, c.p);
            let ax = mod_mul(c.a, c.gx, c.p);
            let rhs = mod_add(&mod_add(&x3, &ax, c.p), c.b, c.p);
            assert_eq!(lhs, rhs, "curve {:#06x}: G is not on the curve", c.curve_id);
        }
    }

    /// [`ecc_curve_params`] returns exactly the curves of the build, with matching sizes.
    #[test]
    fn lookup_follows_the_features() {
        assert!(ecc_curve_params(TpmEccCurve::None).is_none());
        for curve in [
            #[cfg(feature = "ecc_curve_nist_p192")]
            TpmEccCurve::NistP192,
            #[cfg(feature = "ecc_curve_nist_p224")]
            TpmEccCurve::NistP224,
            #[cfg(feature = "ecc_curve_nist_p256")]
            TpmEccCurve::NistP256,
            #[cfg(feature = "ecc_curve_nist_p384")]
            TpmEccCurve::NistP384,
            #[cfg(feature = "ecc_curve_nist_p521")]
            TpmEccCurve::NistP521,
            #[cfg(feature = "ecc_curve_bn_p256")]
            TpmEccCurve::BNP256,
            #[cfg(feature = "ecc_curve_bn_p638")]
            TpmEccCurve::BNP638,
            #[cfg(feature = "ecc_curve_sm2_p256")]
            TpmEccCurve::SM2P256,
        ] {
            let c = ecc_curve_params(curve).unwrap();
            assert_eq!(c.curve_id, curve as u16);
            assert_eq!(c.coordinate_size(), curve.parameter_size());
        }
    }

    /// `(a * b) mod m` by shift-and-add, for test purposes only.
    fn mod_mul(a: &[u8], b: &[u8], m: &[u8]) -> [u8; 80] {
        let mut acc = [0u8; 80];
        let n = m.len();
        for &byte in a {
            for bit in (0..8).rev() {
                let doubled = acc;
                acc = mod_add(&doubled[80 - n..], &doubled[80 - n..], m);
                if (byte >> bit) & 1 == 1 {
                    acc = mod_add(&acc[80 - n..], b, m);
                }
            }
        }
        acc
    }

    /// `(a + b) mod m` for `a, b < m`, for test purposes only; the result is right-aligned.
    fn mod_add(a: &[u8], b: &[u8], m: &[u8]) -> [u8; 80] {
        let n = m.len();
        let mut sum = [0u8; 81];
        let mut carry = 0u16;
        for i in (0..n).rev() {
            let s = u16::from(a[a.len() - n + i]) + u16::from(b[b.len() - n + i]) + carry;
            sum[81 - n + i] = s as u8;
            carry = s >> 8;
        }
        sum[80 - n] = carry as u8;
        let mut m_ext = [0u8; 81];
        m_ext[81 - n..].copy_from_slice(m);
        if sum[80 - n..] >= m_ext[80 - n..] {
            let mut borrow = 0i16;
            for i in (80 - n..81).rev() {
                let d = i16::from(sum[i]) - i16::from(m_ext[i]) - borrow;
                sum[i] = d.rem_euclid(256) as u8;
                borrow = i16::from(d < 0);
            }
        }
        let mut out = [0u8; 80];
        out.copy_from_slice(&sum[1..]);
        out
    }
}
