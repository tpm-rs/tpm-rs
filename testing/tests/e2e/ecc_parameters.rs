//! TPM2_ECC_Parameters: curve constants for implemented curves and rejection of unknown curves.

use crate::_common::{
    CC_ECC_PARAMETERS, ST_NO_SESSIONS, build_raw_cmd, rc_of, run_raw, send_with_rc,
};
use testing::tpm::Tpm;
use tpm2::commands::ECCParameters;
use tpm2::errors::{Position, TpmRc};
use tpm2::{TpmEccCurve, TpmiAlgHash, TpmtKdfScheme};

/// ECC_Parameters(TPM_ECC_BN_P256) returns the exact TCG curve constants.
#[test]
fn bn_p256_curve_constants() {
    let mut sim = Tpm::new();

    // Call TPM2_ECC_Parameters(TPM_ECC_BN_P256)
    let rsp = sim
        .execute(ECCParameters {
            curve_id: TpmEccCurve::BNP256,
        })
        .expect("TPM2_ECC_Parameters(BNP256) should succeed");
    assert_eq!(rsp.parameters.key_size, 256);
    assert_eq!(rsp.parameters.curve_id, TpmEccCurve::BNP256);

    // Check exact coordinate P value string per TCG Part 4 Table 8
    let expected_p = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0xf0, 0xcd, 0x46, 0xe5, 0xf2, 0x5e, 0xee, 0x71, 0xa4,
        0x9f, 0x0c, 0xdc, 0x65, 0xfb, 0x12, 0x98, 0x0a, 0x82, 0xd3, 0x29, 0x2d, 0xdb, 0xae, 0xd3,
        0x30, 0x13,
    ];
    assert_eq!(rsp.parameters.curve_p.get_buffer(), &expected_p);

    // Check n, a, b, g_x, g_y, h
    let expected_n = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0xf0, 0xcd, 0x46, 0xe5, 0xf2, 0x5e, 0xee, 0x71, 0xa4,
        0x9e, 0x0c, 0xdc, 0x65, 0xfb, 0x12, 0x99, 0x92, 0x1a, 0xf6, 0x2d, 0x53, 0x6c, 0xd1, 0x0b,
        0x50, 0x0d,
    ];
    assert_eq!(rsp.parameters.n.get_buffer(), &expected_n);
    assert_eq!(rsp.parameters.curve_a.get_buffer(), &[0; 32]);
    let mut expected_b = [0u8; 32];
    expected_b[31] = 3;
    assert_eq!(rsp.parameters.curve_b.get_buffer(), &expected_b);
    let mut expected_gx = [0u8; 32];
    expected_gx[31] = 1;
    assert_eq!(rsp.parameters.g_x.get_buffer(), &expected_gx);
    let mut expected_gy = [0u8; 32];
    expected_gy[31] = 2;
    assert_eq!(rsp.parameters.g_y.get_buffer(), &expected_gy);
    assert_eq!(rsp.parameters.h.get_buffer(), &[0x01]);
}

/// Raw ECC_Parameters with TPM_ECC_NONE and unknown curves is TPM_RC_CURVE; implemented curves succeed
#[test]
fn invalid_curve_ids_rejected() {
    let mut sim = Tpm::new();

    // 1. Test TPM_ECC_NONE (0x0000) -> TPM_RC_CURVE (0x1A6)
    let req_none = [
        0x80, 0x01, // tag: TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x0C, // size: 12 bytes
        0x00, 0x00, 0x01, 0x78, // cc: TPM_CC_ECC_Parameters (0x178)
        0x00, 0x00, // curveID: TPM_ECC_NONE
    ];
    let response = run_raw(&mut sim, &req_none);
    assert_eq!(
        rc_of(&response),
        TpmRc::CURVE.with(Position::parameter(1)).get(),
        "Expected TPM_RC_CURVE at Pos1 (0x1A6) for TPM_ECC_NONE"
    );

    // 2. Test unsupported curve 0x0022 -> TPM_RC_CURVE (0x1A6)
    let req_unsupported = [
        0x80, 0x01, // tag: TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x0C, // size: 12 bytes
        0x00, 0x00, 0x01, 0x78, // cc: TPM_CC_ECC_Parameters (0x178)
        0x00, 0x22, // curveID: 0x0022
    ];
    let response = run_raw(&mut sim, &req_unsupported);
    assert_eq!(
        rc_of(&response),
        TpmRc::CURVE.with(Position::parameter(1)).get(),
        "Expected TPM_RC_CURVE at Pos1 (0x1A6) for curve 0x0022"
    );

    // 3. Test valid curve NIST_P256 (0x0003) -> TPM_RC_SUCCESS (0x000)
    let req_valid = [
        0x80, 0x01, // tag: TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x0C, // size: 12 bytes
        0x00, 0x00, 0x01, 0x78, // cc: TPM_CC_ECC_Parameters (0x178)
        0x00, 0x03, // curveID: NIST_P256
    ];
    let response = run_raw(&mut sim, &req_valid);
    assert_eq!(rc_of(&response), 0, "Expected TPM_RC_SUCCESS for NIST_P256");
}

/// ECC_Parameters(NIST P-224) returns the FIPS 186-4 domain parameters and KDF1_SP800_56A/SHA-256
///
/// `TPM2_ECC_Parameters(TPM_ECC_NIST_P224)` returns the FIPS 186-4 domain parameters and the
/// curve's KDF (`KDF1_SP800_56A` with SHA-256), as `CryptEccData.c`.
#[test]
fn nist_p224_domain_parameters() {
    let mut sim = Tpm::new();
    let expected_kdf: [(u16, u16); 4] = [
        (0x0002, 0x000B),
        (0x0003, 0x000B),
        (0x0004, 0x000C),
        (0x0005, 0x000D),
    ];
    for (curve, kdf_hash) in expected_kdf {
        let cmd = build_raw_cmd(
            ST_NO_SESSIONS,
            CC_ECC_PARAMETERS,
            &[],
            None,
            &curve.to_be_bytes(),
        );
        let (rc, resp) = send_with_rc(&mut sim, &cmd);
        assert_eq!(rc, 0);
        let p = &resp[10..];
        assert_eq!(u16::from_be_bytes(p[0..2].try_into().unwrap()), curve);
        if !tpm2_impl::ECC_PARAMETERS_REPORT_KDF {
            // `ecc-parameters-null-kdf`: the KDF is `TPM_ALG_NULL` (no details).
            assert_eq!(
                u16::from_be_bytes(p[4..6].try_into().unwrap()),
                0x0010,
                "kdf scheme"
            );
            continue;
        }
        assert_eq!(
            u16::from_be_bytes(p[4..6].try_into().unwrap()),
            0x0020,
            "kdf scheme"
        );
        assert_eq!(
            u16::from_be_bytes(p[6..8].try_into().unwrap()),
            kdf_hash,
            "kdf hash"
        );
        if curve != 0x0002 {
            continue;
        }
        // sign scheme (NULL), then p, a, b, gX, gY, n, h.
        assert_eq!(u16::from_be_bytes(p[8..10].try_into().unwrap()), 0x0010);
        let mut off = 10;
        let mut fields = Vec::new();
        for _ in 0..7 {
            let size = u16::from_be_bytes(p[off..off + 2].try_into().unwrap()) as usize;
            fields.push(p[off + 2..off + 2 + size].to_vec());
            off += 2 + size;
        }
        let hex = |s: &str| {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect::<Vec<u8>>()
        };
        assert_eq!(
            fields[1],
            hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE"),
            "a"
        );
        assert_eq!(
            fields[5],
            hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D"),
            "n"
        );
        assert_eq!(fields[6], vec![1], "h");
    }
}

/// ECC_Parameters reports the parameters of BN P-256 and NIST P-256
///
/// `TPM2_ECC_Parameters` reports the parameters of BN P-256 and NIST P-256.
#[test]
fn p256_curves_parameters() {
    let mut sim = Tpm::new();

    let rsp = sim
        .execute(ECCParameters {
            curve_id: TpmEccCurve::BNP256,
        })
        .expect("TPM2_ECC_Parameters(BNP256) should succeed");
    assert_eq!(rsp.parameters.key_size, 256);
    assert_eq!(rsp.parameters.kdf, None);
    assert_eq!(rsp.parameters.sign, None);
    assert_eq!(rsp.parameters.curve_id, TpmEccCurve::BNP256);

    let rsp = sim
        .execute(ECCParameters {
            curve_id: TpmEccCurve::NistP256,
        })
        .expect("TPM2_ECC_Parameters(NistP256) should succeed");
    assert_eq!(rsp.parameters.key_size, 256);
    // C CryptEccData.c: NIST P-256 carries {TPM_ALG_KDF1_SP800_56A, SHA256} as its KDF (none
    // with the `ecc-parameters-null-kdf` profile).
    assert_eq!(
        rsp.parameters.kdf,
        tpm2_impl::ECC_PARAMETERS_REPORT_KDF
            .then_some(TpmtKdfScheme::Kdf1Sp800_56a(TpmiAlgHash::Sha256))
    );
    assert_eq!(rsp.parameters.sign, None);
    assert_eq!(rsp.parameters.curve_id, TpmEccCurve::NistP256);
}
