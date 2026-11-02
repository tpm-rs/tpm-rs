//! The optional ECC curves NIST P-192, BN P-638 and SM2 P-256 (`ecc_curve_*` features):
//! `TPM_CAP_ECC_CURVES` lists exactly the implemented curves, `TPM2_ECC_Parameters` reports their
//! domain parameters (checked against the published constants of `_common::client_curve`) and
//! KDF, and `TPM2_TestParms` accepts ECC parameters on them.

use crate::_common::{ClientCurve, OPTIONAL_ECC_CURVES, client_curve, get_cap};
use testing::tpm::Tpm;
use tpm2::commands::{ECCParameters, TestParms};
use tpm2::{TpmEccCurve, TpmiAlgHash, TpmsEccParms, TpmtEccScheme, TpmtKdfScheme, TpmtPublicParms};

/// `TPM_CAP_ECC_CURVES`.
const CAP_ECC_CURVES: u32 = 8;

/// The curves every build implements: NIST P-224, P-256, P-384, P-521 and BN P-256.
const DEFAULT_CURVES: [u16; 5] = [0x0002, 0x0003, 0x0004, 0x0005, 0x0010];

/// `TPM2_ECC_Parameters(curve)` reports `key_size` bits, `kdf`, no signing scheme, the domain
/// parameters of [`client_curve`] with every field element padded to the coordinate size, and
/// the cofactor 1.
fn check_domain_parameters(curve: TpmEccCurve, key_size: u16, kdf: Option<TpmtKdfScheme>) {
    let mut sim = Tpm::new();
    let c = client_curve(curve as u16);
    let rsp = sim
        .execute(ECCParameters { curve_id: curve })
        .expect("TPM2_ECC_Parameters");
    let params = rsp.parameters;
    assert_eq!(params.curve_id, curve);
    assert_eq!(params.key_size, key_size);
    assert_eq!(params.kdf, kdf, "kdf");
    assert_eq!(params.sign, None, "sign");
    let field = |v: &rsa::BigUint| ClientCurve::pad(v, c.size);
    assert_eq!(params.curve_p.get_buffer(), field(&c.p), "p");
    assert_eq!(params.curve_a.get_buffer(), field(&c.a), "a");
    assert_eq!(params.curve_b.get_buffer(), field(&c.b), "b");
    assert_eq!(params.g_x.get_buffer(), field(&c.gx), "gX");
    assert_eq!(params.g_y.get_buffer(), field(&c.gy), "gY");
    assert_eq!(params.n.get_buffer(), field(&c.n), "n");
    assert_eq!(params.h.get_buffer(), &[0x01], "h");
    // The client-side constants describe a curve whose base point is on it and has order n.
    assert!(c.contains(&c.gx, &c.gy));
    assert_eq!(c.mul(&c.n, &c.g()), None, "[n]G is the point at infinity");
}

/// `TPM_CAP_ECC_CURVES` lists exactly the default curves and the optional curves of this build,
/// in ascending order.
#[test]
fn ecc_curves_capability_lists_exactly_the_implemented_curves() {
    let mut sim = Tpm::new();
    let (more, data) = get_cap(&mut sim, CAP_ECC_CURVES, 0, 64).unwrap();
    assert!(!more);
    let count = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
    assert_eq!(data.len(), 4 + 2 * count);
    let listed: Vec<u16> = (0..count)
        .map(|i| u16::from_be_bytes([data[4 + 2 * i], data[5 + 2 * i]]))
        .collect();
    let mut expected: Vec<u16> = DEFAULT_CURVES.to_vec();
    expected.extend(OPTIONAL_ECC_CURVES.iter().map(|&c| c as u16));
    expected.sort_unstable();
    assert_eq!(listed, expected);
}

/// `TPM2_ECC_Parameters(TPM_ECC_NIST_P192)` reports the FIPS 186-4 domain parameters and
/// `KDF1_SP800_56A` with SHA-256 (`TPM_ALG_NULL` with the `ecc-parameters-null-kdf` profile).
#[cfg(feature = "ecc_curve_nist_p192")]
#[test]
fn nist_p192_domain_parameters() {
    check_domain_parameters(
        TpmEccCurve::NistP192,
        192,
        tpm2_engine::ECC_PARAMETERS_REPORT_KDF
            .then_some(TpmtKdfScheme::Kdf1Sp800_56a(TpmiAlgHash::Sha256)),
    );
}

/// `TPM2_ECC_Parameters(TPM_ECC_BN_P638)` reports the TCG Algorithm Registry domain parameters
/// (a 638-bit prime in 80-byte field elements, `a = 0`, `b = 257`, `G = (p - 1, 16)`) and no KDF.
#[cfg(feature = "ecc_curve_bn_p638")]
#[test]
fn bn_p638_domain_parameters() {
    check_domain_parameters(TpmEccCurve::BNP638, 638, None);
}

/// `TPM2_ECC_Parameters(TPM_ECC_SM2_P256)` reports the GM/T 0003.5 domain parameters and no
/// KDF: the curve's KDF hash would be SM3-256, which is not implemented, so the reported KDF is
/// `TPM_ALG_NULL`.
#[cfg(feature = "ecc_curve_sm2_p256")]
#[test]
fn sm2_p256_domain_parameters() {
    check_domain_parameters(TpmEccCurve::SM2P256, 256, None);
}

/// `TPM2_TestParms` accepts ECDSA signing parameters and unrestricted decryption parameters
/// (with and without an ECDH scheme) on every optional curve.
#[test]
fn test_parms_accepts_the_optional_curves() {
    let mut sim = Tpm::new();
    for &curve in OPTIONAL_ECC_CURVES {
        for scheme in [
            Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
            Some(TpmtEccScheme::Ecdh(TpmiAlgHash::Sha256)),
            None,
        ] {
            let parameters = TpmtPublicParms::Ecc(TpmsEccParms {
                symmetric: None,
                scheme,
                curve_id: curve,
                kdf: None,
            });
            sim.execute(TestParms { parameters })
                .unwrap_or_else(|rc| panic!("TestParms({curve:?}, {scheme:?}): {rc:?}"));
        }
    }
}
