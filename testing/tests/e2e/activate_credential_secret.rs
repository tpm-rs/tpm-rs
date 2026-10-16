//! TPM2_ActivateCredential: the protector key checks, which come before the
//! activated object is used, and the response codes of the `secret`
//! decryption (`CryptSecretDecrypt`) for malformed encrypted seeds, for RSA
//! and ECC protector keys.
//!
//! TPM 2.0 Part 1, "RSAES_OAEP": "This encryption scheme is defined in RFC
//! 8017 [@{rfc8017}]. It is the only scheme used with an RSA-restricted
//! decryption key." The specification does not assign response codes to the
//! failures of RFC 8017 decryption (a ciphertext that is not as long as the
//! modulus, a ciphertext representative out of range, a decoding error), nor
//! does it say whether bytes after the `TPMS_ECC_POINT` of an ECC secret are
//! an error, so tpm-rs follows the TCG reference (`CryptoRsa_Decrypt()`,
//! `CryptoCommon_SecretDecrypt()`).

use crate::_common::{
    build_pw_cmd, get_ecc_srk_template, owner_srk, rc_h, rc_of, rc_p, try_create_owner_primary,
};
use testing::tpm::Tpm;
use tpm2::Handle;
use tpm2::errors::TpmRc;

/// `TPM_CC_ActivateCredential`.
const TPM_CC_ACTIVATE_CREDENTIAL: u32 = 0x0000_0147;

/// The size of the modulus of `owner_srk`'s RSA 2048 key.
const RSA_2048_MODULUS_BYTES: usize = 256;

/// A raw `TPM2_ActivateCredential(activate_handle, key_handle, credentialBlob
/// = empty, secret)` with password sessions; its response code.
fn activate_credential_rc(tpm: &mut Tpm, activate: Handle, key: Handle, secret: &[u8]) -> u32 {
    let mut params = vec![0, 0];
    params.extend_from_slice(&(secret.len() as u16).to_be_bytes());
    params.extend_from_slice(secret);
    let cmd = build_pw_cmd(TPM_CC_ACTIVATE_CREDENTIAL, &[activate.0, key.0], 2, &params);
    rc_of(&tpm.send_command(0, &cmd))
}

/// The expected response code `rc` for the `secret` parameter (P2).
fn secret_rc(rc: tpm2::errors::Fmt1) -> u32 {
    rc_p(rc, 2)
}

/// An RSA secret that is not exactly as long as the modulus is rejected with
/// `TPM_RC_SIZE` (C: "Size is checked to make sure that the encrypted value
/// is the right size"), including an empty secret.
#[test]
fn rsa_secret_not_modulus_sized_is_size_error() {
    let mut tpm = Tpm::new();
    let srk = owner_srk(&mut tpm);
    for len in [0, 1, RSA_2048_MODULUS_BYTES - 1, RSA_2048_MODULUS_BYTES + 1] {
        let secret = vec![0x5a; len];
        assert_eq!(
            activate_credential_rc(&mut tpm, srk, srk, &secret),
            secret_rc(TpmRc::SIZE),
            "secret of {len} bytes"
        );
    }
}

/// An RSA secret whose numeric value is not below the modulus is rejected
/// with `TPM_RC_SIZE` (RFC 8017 RSADP: "ciphertext representative out of
/// range"; C `RSADP()`).
#[test]
fn rsa_secret_not_below_modulus_is_size_error() {
    let mut tpm = Tpm::new();
    let srk = owner_srk(&mut tpm);
    let secret = vec![0xff; RSA_2048_MODULUS_BYTES];
    assert_eq!(
        activate_credential_rc(&mut tpm, srk, srk, &secret),
        secret_rc(TpmRc::SIZE)
    );
}

/// A modulus-sized RSA secret that is not a valid OAEP encoding is rejected
/// with `TPM_RC_VALUE`.
#[test]
fn rsa_secret_with_bad_padding_is_value_error() {
    let mut tpm = Tpm::new();
    let srk = owner_srk(&mut tpm);
    let mut secret = vec![0x5a; RSA_2048_MODULUS_BYTES];
    secret[0] = 0;
    assert_eq!(
        activate_credential_rc(&mut tpm, srk, srk, &secret),
        secret_rc(TpmRc::VALUE)
    );
}

/// The `TPMS_ECC_POINT` of an ECC secret with coordinates shorter than the
/// curve's parameters is padded and then rejected as a point that is not on
/// the curve (`TPM_RC_ECC_POINT`), not as a size error.
#[test]
fn ecc_secret_with_short_coordinates_is_ecc_point_error() {
    let mut tpm = Tpm::new();
    let (srk, _) = try_create_owner_primary(&mut tpm, get_ecc_srk_template()).expect("ECC SRK");
    // A P-256 key; 16-byte coordinates that are not a point on the curve.
    let mut secret = vec![0, 16];
    secret.extend_from_slice(&[0x11; 16]);
    secret.extend_from_slice(&[0, 16]);
    secret.extend_from_slice(&[0x22; 16]);
    assert_eq!(
        activate_credential_rc(&mut tpm, srk, srk, &secret),
        secret_rc(TpmRc::ECC_POINT)
    );
}

/// Bytes after the `TPMS_ECC_POINT` of an ECC secret are ignored: the point
/// itself decides the result (here `TPM_RC_ECC_POINT` for a point that is
/// not on the curve).
#[test]
fn ecc_secret_trailing_bytes_are_ignored() {
    let mut tpm = Tpm::new();
    let (srk, _) = try_create_owner_primary(&mut tpm, get_ecc_srk_template()).expect("ECC SRK");
    let mut secret = vec![0, 32];
    secret.extend_from_slice(&[0x11; 32]);
    secret.extend_from_slice(&[0, 32]);
    secret.extend_from_slice(&[0x22; 32]);
    secret.extend_from_slice(&[0xee; 5]);
    assert_eq!(
        activate_credential_rc(&mut tpm, srk, srk, &secret),
        secret_rc(TpmRc::ECC_POINT)
    );
}

/// `TPM2_HashSequenceStart(auth = empty, hashAlg = SHA256)`.
const HASH_SEQUENCE_START: [u8; 14] = [0x80, 0x01, 0, 0, 0, 14, 0, 0, 0x01, 0x86, 0, 0, 0x00, 0x0b];

/// A sequence object as the protector key (`keyHandle`) is not an asymmetric
/// restricted decryption key: `TPM_RC_TYPE` on `keyHandle`, checked before
/// the activated object (here the same sequence object) is used.
#[test]
fn sequence_object_protector_is_type_error() {
    let mut tpm = Tpm::new();
    let rsp = tpm.send_command(0, &HASH_SEQUENCE_START);
    assert_eq!(rc_of(&rsp), 0, "HashSequenceStart: {rsp:02x?}");
    let sequence = Handle(u32::from_be_bytes(rsp[10..14].try_into().unwrap()));
    assert_eq!(
        activate_credential_rc(&mut tpm, sequence, sequence, &[0x5a; 4]),
        rc_h(TpmRc::TYPE, 2)
    );
}
