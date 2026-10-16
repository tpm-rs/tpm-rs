//! TPM2_RSA_Decrypt: a ciphertext whose value is not below the modulus is
//! rejected as `TPM_RC_SIZE` (without a position), before any padding is
//! examined.

use crate::_common::{build_pw_cmd, rc_of};
use testing::tpm::Tpm;

/// `TPM_RC_SIZE` (format one, no position).
const TPM_RC_SIZE: u32 = 0x0000_0095;

/// `TPM2_CreatePrimary` of an unrestricted RSA 2048 decryption key (OAEP
/// SHA256 scheme) under the owner hierarchy.
const CREATE_PRIMARY_RSA_DECRYPT: [u8; 65] = [
    0x80, 0x02, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x01, 0x31, 0x40, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x18, 0x00, 0x01, 0x00, 0x0b, 0x00, 0x02, 0x00, 0x72, 0x00, 0x00, 0x00, 0x10, 0x00,
    0x17, 0x00, 0x0b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00,
];

/// A modulus-sized ciphertext of all `0xFF` bytes is larger than the modulus:
/// `TPM_RC_SIZE` (RFC 8017 RSADP: "ciphertext representative out of range";
/// TPM 2.0 Part 3, TPM2_RSA_Decrypt, gives `TPM_RC_VALUE` only for padding
/// failures, so the reference's code is used).
#[test]
fn ciphertext_not_below_modulus_is_size_error() {
    let mut tpm = Tpm::new();
    let rsp = tpm.send_command(0, &CREATE_PRIMARY_RSA_DECRYPT);
    assert_eq!(rc_of(&rsp), 0, "CreatePrimary: {rsp:02x?}");
    let key = u32::from_be_bytes(rsp[10..14].try_into().unwrap());
    let mut params = vec![0x01, 0x00];
    params.extend_from_slice(&[0xff; 256]);
    params.extend_from_slice(&[0x00, 0x10]); // inScheme: TPM_ALG_NULL
    params.extend_from_slice(&[0x00, 0x00]); // label
    let cmd = build_pw_cmd(0x0000_0159, &[key], 1, &params);
    assert_eq!(rc_of(&tpm.send_command(0, &cmd)), TPM_RC_SIZE);
}
