//! Command dispatch: unimplemented/unmapped command codes and malformed handle areas before command
//! execution.

use crate::_common::Connection;
use crate::_common::{
    CC_MAC, CC_RSA_DECRYPT, CC_SIGN, CC_VERIFY_SIGNATURE, digest12, hx, leak_bytes, mac_params,
    rc_of, rsa_decrypt_params, send_key_command, send_raw, sign_params,
};
use testing::tpm::Tpm;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, Unmarshal};

/// Raw HMAC, VerifySignature, Sign and RSA_Decrypt commands without their key handle are rejected
#[test]
fn crypto_commands_reject_missing_handle() {
    let mut sim = Tpm::new();
    let missing_handle = Handle(0x8000000F); // Unloaded transient key handle (TRANSIENT_LAST).

    // 1. MAC Command
    let error_code = send_key_command(&mut sim, CC_MAC, missing_handle, false, &mac_params(0x000b));
    assert_eq!(
        error_code, 0x00000910,
        "Expected ReferenceH0 (0x910) for missing handle in MAC"
    );

    // 2. VerifySignature Command
    let mut verify_params = digest12();
    verify_params.extend_from_slice(&[0x00, 0x10]);
    let error_code = send_key_command(
        &mut sim,
        CC_VERIFY_SIGNATURE,
        missing_handle,
        false,
        &verify_params,
    );
    assert_eq!(
        error_code, 0x00000910,
        "Expected ReferenceH0 (0x910) for missing handle in VerifySignature"
    );

    // 3. Sign Command
    let error_code = send_key_command(&mut sim, CC_SIGN, missing_handle, false, &sign_params());
    assert_eq!(
        error_code, 0x00000910,
        "Expected ReferenceH0 (0x910) for missing handle in Sign"
    );

    // 4. RSADecrypt Command
    let error_code = send_key_command(
        &mut sim,
        CC_RSA_DECRYPT,
        missing_handle,
        false,
        &rsa_decrypt_params(),
    );
    assert_eq!(
        error_code, 0x00000910,
        "Expected ReferenceH0 (0x910) for missing handle in RSADecrypt"
    );
}

/// TPM2_HMAC_Start on TPM_RH_NULL with a non-existent session still fails with TPM_RC_VALUE + H1
///
/// Handle validation runs before session validation: a `TPM2_HMAC_Start` on `TPM_RH_NULL`
/// with a non-existent session still fails with `TPM_RC_VALUE + TPM_RC_H + TPM_RC_1`.
#[test]
fn hmac_start_checks_handle_before_session() {
    let mut sim = Tpm::new();

    // HmacStart command with sessions: tag = 8002, size = 27, cc = 0000015b
    // Handle: 00000007 (RHNull)
    // Auth Session area size: 9
    // Auth Session:
    //   session handle: 02000000 (invalid/non-existent)
    //   nonce: 0000 (0 length)
    //   attributes: 00
    //   hmac: 0000 (0 length)
    let request = [
        0x80, 0x02, // tag
        0x00, 0x00, 0x00, 0x1b, // size = 27
        0x00, 0x00, 0x01, 0x5b, // cc = HmacStart
        0x00, 0x00, 0x00, 0x07, // handle
        0x00, 0x00, 0x00, 0x09, // auth session area size = 9
        0x02, 0x00, 0x00, 0x00, // session handle
        0x00, 0x00, // nonce (0 len)
        0x00, // attributes
        0x00, 0x00, // hmac (0 len)
    ];
    let resp = send_raw(&mut sim, &request);
    assert_eq!(resp.len(), 10);
    // Should return TpmRc::VALUE.with(Position::handle(1)) which is 0x184 (since handle
    // validation runs first)
    assert_eq!(rc_of(&resp), 0x184, "Should return a Value error (0x184)");
}

/// A 10-byte TPM2_HMAC_Start without its handle gets a 10-byte TPM_RC_INSUFFICIENT + H1 response
///
/// A `TPM2_HMAC_Start` without its handle (commandSize = 10) fails while unmarshaling the
/// `TPMI_DH_OBJECT` handle: the input buffer does not contain enough octets, which is
/// `TPM_RC_INSUFFICIENT` (TPM 2.0 Part 2, "Unmarshaling Errors") at handle 1, as in C
/// `ParseHandleBuffer`.
#[test]
fn hmac_start_rejects_missing_handle() {
    let mut sim = Tpm::new();

    // HmacStart command: tag = 8001, size = 10, cc = 0000015b
    // Since HmacStart takes 1 handle, a request size of 10 is missing the handle.
    let request = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x0a, // size = 10
        0x00, 0x00, 0x01, 0x5b, // cc = HmacStart
    ];
    let resp = send_raw(&mut sim, &request);
    assert_eq!(resp.len(), 10);
    assert_eq!(
        rc_of(&resp),
        TpmRc::INSUFFICIENT.with(Position::handle(1)).get()
    );
}

/// A truncated handle area fails with TPM_RC_INSUFFICIENT at the first incomplete handle
///
/// Covers a partial handle (2 of 4 octets) and a two-handle command that carries only its first
/// handle (`TPM_RC_INSUFFICIENT + H2`), with and without an authorization area tag.
#[test]
fn truncated_handle_area_is_insufficient_at_first_incomplete_handle() {
    let mut sim = Tpm::new();

    // TPM2_HMAC_Start (NO_SESSIONS) with half of its handle.
    let partial = [
        0x80, 0x01, // tag: TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x0c, // size = 12
        0x00, 0x00, 0x01, 0x5b, // cc = HmacStart
        0x80, 0x00, // first two octets of the handle
    ];
    assert_eq!(
        rc_of(&send_raw(&mut sim, &partial)),
        TpmRc::INSUFFICIENT.with(Position::handle(1)).get()
    );

    // TPM2_ActivateCredential (TPM_ST_SESSIONS, two handles) with only activateHandle.
    let one_of_two = [
        0x80, 0x02, // tag: TPM_ST_SESSIONS
        0x00, 0x00, 0x00, 0x0e, // size = 14
        0x00, 0x00, 0x01, 0x47, // cc = ActivateCredential
        0x80, 0x00, 0x00, 0x00, // activateHandle
    ];
    assert_eq!(
        rc_of(&send_raw(&mut sim, &one_of_two)),
        TpmRc::INSUFFICIENT.with(Position::handle(2)).get()
    );
}

/// TPM2_HMAC_Start on TPM_RH_NULL fails the handle check with TPM_RC_VALUE + H1
///
/// A `TPM2_HMAC_Start` on `TPM_RH_NULL` (not a loaded HMAC key) fails the handle check with
/// `TPM_RC_VALUE + TPM_RC_H + TPM_RC_1`.
#[test]
fn hmac_start_rejects_null_key_handle() {
    let mut sim = Tpm::new();

    // HmacStart command: tag = 8001, size = 18, cc = 0000015b, handle = 00000007 (RHNull)
    // Auth size = 0 (0000), Hash Alg = SHA256 (000b)
    let request = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x12, // size = 18
        0x00, 0x00, 0x01, 0x5b, // cc = HmacStart
        0x00, 0x00, 0x00, 0x07, // handle
        0x00, 0x00, // auth size = 0
        0x00, 0x0b, // hash alg = SHA256
    ];
    let resp = send_raw(&mut sim, &request);
    assert_eq!(resp.len(), 10);
    // Should return Value error for handle 1 (0x184)
    assert_eq!(rc_of(&resp), 0x184);
}

/// An unmapped command code (0x999) fails with TPM_RC_COMMAND_CODE.
#[test]
fn unmapped_command_code_rejected() {
    let mut sim = Tpm::new();

    // Send an unmapped command code (0x00000999)
    // tag: 8001
    // size: 0000000c
    // cc: 00000999 (unmapped)
    // params: 0000
    let request = hx(concat!("8001", "0000000c", "00000999", "0000",));
    let mut response = [0u8; 256];
    let response = sim.transact(&request, &mut response).unwrap();
    assert_eq!(response.len(), 10);
    // Should return CommandCode error (0x143)
    assert_eq!(&response[6..10], &0x143u32.to_be_bytes());
}

/// Unimplemented command codes (PP_Commands, FieldUpgrade*, ...) return TPM_RC_COMMAND_CODE
#[test]
fn unsupported_command_codes_rejected() {
    let mut sim = Tpm::new();

    // Pick multiple other unimplemented command codes and check they return TPM_RC_COMMAND_CODE (0x143)
    let unimplemented_codes: [u32; 3] = [
        0x0000012D, // TPM_CC_PPCommands
        0x0000012F, // TPM_CC_FieldUpgradeStart
        0x00000141, // TPM_CC_FieldUpgradeData
    ];

    for &code in &unimplemented_codes {
        // Construct raw request buffer for each code
        let mut req = Vec::new();
        // tag: NoSessions (0x8001)
        req.extend_from_slice(&0x8001u16.to_be_bytes());
        // size: 10 bytes
        req.extend_from_slice(&10u32.to_be_bytes());
        // command code
        req.extend_from_slice(&code.to_be_bytes());

        let mut resp = [0u8; 1024];
        let resp_bytes = sim.transact(&req, &mut resp).unwrap();
        assert_eq!(resp_bytes.len(), 10);

        let mut unmarsh: &'static [u8] = leak_bytes(resp_bytes);
        let header = crate::test_utils::RespHeader::unmarshal(&mut unmarsh).unwrap();
        assert_eq!(
            header.rc, 0x143,
            "Expected TPM_RC_COMMAND_CODE (0x143) for command 0x{:X}, got 0x{:X}",
            code, header.rc
        );
    }
}
