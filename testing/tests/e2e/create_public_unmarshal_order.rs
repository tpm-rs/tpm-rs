//! TPM2_Create: errors in `inPublic` are reported in the unmarshaling order of
//! `TPMT_PUBLIC` (`type`, `nameAlg`, `objectAttributes`, `authPolicy`,
//! `parameters`, `unique`), so the first invalid field decides the response.

use crate::_common::{build_pw_cmd, owner_srk, rc_of, rc_p};
use testing::tpm::Tpm;
use tpm2::errors::TpmRc;

/// `TPM_CC_Create`.
const TPM_CC_CREATE: u32 = 0x0000_0153;

/// Reserved bits in `objectAttributes` are reported (`TPM_RC_RESERVED_BITS`)
/// before an invalid hash in the keyedHash scheme that follows them. TPM 2.0
/// Part 2, "Attribute Structures": "When any reserved bit in an attribute is
/// SET, the TPM shall return `TPM_RC_RESERVED_BITS`."; Part 3, "Unmarshaling
/// Errors": "When an error is encountered while unmarshaling a command
/// parameter, an error response code is returned, and no command processing
/// occurs."
#[test]
fn reserved_attribute_bits_precede_scheme_errors() {
    let mut tpm = Tpm::new();
    let srk = owner_srk(&mut tpm);
    // inSensitive: empty userAuth, one byte of data.
    let mut params = vec![0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x78];
    // inPublic: KEYEDHASH, SHA256, objectAttributes with reserved bits SET,
    // empty authPolicy, scheme HMAC with hash 0x0000 (not a hash).
    let public: [u8; 16] = [
        0x00, 0x08, 0x00, 0x0b, 0x00, 0xff, 0xfa, 0x40, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x0b,
    ];
    params.extend_from_slice(&(public.len() as u16).to_be_bytes());
    params.extend_from_slice(&public);
    params.extend_from_slice(&[0x00, 0x00]); // outsideInfo
    params.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // creationPCR
    let cmd = build_pw_cmd(TPM_CC_CREATE, &[srk.0], 1, &params);
    assert_eq!(
        rc_of(&tpm.send_command(0, &cmd)),
        rc_p(TpmRc::RESERVED_BITS, 2)
    );
}
