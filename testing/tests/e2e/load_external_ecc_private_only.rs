//! An ECC key loaded by TPM2_LoadExternal with nameAlg `TPM_ALG_NULL`, its private key and no
//! public point: TPM2_Sign uses only the private key; TPM2_VerifySignature against the empty
//! public point reports the signature as not genuine.

use crate::_common::{ST_NO_SESSIONS, ST_SESSIONS, build_raw_cmd, hex, rc_p, response_rc, send};
use testing::tpm::Tpm;
use tpm2::errors::TpmRc;

const CC_LOAD_EXTERNAL: u32 = 0x167;
const CC_SIGN: u32 = 0x15D;
const CC_VERIFY_SIGNATURE: u32 = 0x177;

/// TPM2_LoadExternal of an ECDSA (SHA-256) NIST P-256 signing key with nameAlg `TPM_ALG_NULL` in
/// the NULL hierarchy whose sensitive area holds the private key `0x0101..01` and whose public
/// area has an empty `unique` point; TPM2_Sign of a SHA-256 digest with it succeeds, and
/// TPM2_VerifySignature of that signature with the same key fails with `TPM_RC_SIGNATURE`.
///
/// TPM 2.0 Part 3, TPM2_LoadExternal: "If the nameAlg is `TPM_ALG_NULL`, the TPM cannot, and thus
/// shall not verify the integrity HMAC on the sensitive area." Signing needs only the private key
/// (as in the TCG reference's `CryptEccSign()`); TPM2_VerifySignature: "`TPM_RC_SIGNATURE` | the
/// signature is not genuine".
#[test]
fn ecc_key_without_public_point_signs_with_private_key() {
    let mut tpm = Tpm::new();
    let load = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_LOAD_EXTERNAL,
        &[],
        None,
        &hex(concat!(
            // inPrivate: ECC, empty authValue and seedValue, 32-byte private key 0x0101..01.
            "0028 0023 0000 0000 0020",
            "0101010101010101010101010101010101010101010101010101010101010101",
            // inPublic: ECC, nameAlg NULL, userWithAuth|sign, no authPolicy, symmetric NULL,
            // ECDSA SHA-256, NIST P-256, KDF NULL, empty unique.x and unique.y.
            "0018 0023 0010 00040040 0000 0010 0018 000b 0003 0010 0000 0000",
            // hierarchy: TPM_RH_NULL.
            "40000007",
        )),
    );
    let rsp = send(&mut tpm, &load);
    assert_eq!(response_rc(&rsp), 0, "LoadExternal");
    let key = u32::from_be_bytes(rsp[10..14].try_into().unwrap());

    let digest = [0x66u8; 32];
    let mut sign_params = vec![0x00, 0x20];
    sign_params.extend_from_slice(&digest);
    // inScheme NULL (the key's ECDSA scheme), validation: a NULL hashcheck ticket.
    sign_params.extend_from_slice(&hex("0010 8024 40000007 0000"));
    let pw_session = hex("40000009 0000 01 0000");
    let sign = build_raw_cmd(
        ST_SESSIONS,
        CC_SIGN,
        &[key],
        Some(&pw_session),
        &sign_params,
    );
    let rsp = send(&mut tpm, &sign);
    assert_eq!(response_rc(&rsp), 0, "Sign");
    // Response: header (10), parameterSize (4), then the TPMT_SIGNATURE.
    let signature = &rsp[14..rsp.len() - 5];
    assert_eq!(&signature[..4], &hex("0018 000b")[..], "ECDSA with SHA-256");

    let mut verify_params = vec![0x00, 0x20];
    verify_params.extend_from_slice(&digest);
    verify_params.extend_from_slice(signature);
    let verify = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_VERIFY_SIGNATURE,
        &[key],
        None,
        &verify_params,
    );
    assert_eq!(
        response_rc(&send(&mut tpm, &verify)),
        rc_p(TpmRc::SIGNATURE, 2)
    );
}
