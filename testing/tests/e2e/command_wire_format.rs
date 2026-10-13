//! Raw command wire format: hand-marshalled commands and trailing parameter bytes.

use crate::_common::Connection;
use crate::_common::{
    CmdHeader, RespHeader, base_attrs, create_primary_with_auth_in, ecc_template, marshal_to_slice,
    rc_bare, send_with_trailing,
};
use testing::tpm::Tpm;
#[allow(deprecated)]
use tpm2::commands::{CreatePrimary, RSADecrypt, RSAEncrypt, Sign, VerifySignature};
use tpm2::errors::TpmRc;
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter, Tpm2bNonce,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmCc, TpmaObject, TpmaSession, TpmiAlgHash,
    TpmiRsaKeyBits, TpmiStCommandTag, TpmlPcrSelection, TpmsAuthCommand, TpmsRsaParms,
    TpmsSensitiveCreate, TpmsSignatureEcc, TpmtEccScheme, TpmtPublic, TpmtRsaScheme, TpmtSignature,
    TpmtTkHashcheck, Unmarshal,
};

/// Trailing parameter bytes on VerifySignature/Sign/RSA_Encrypt/RSA_Decrypt return TPM_RC_SIZE before execution errors.
///
/// Trailing parameter bytes are a `TPM_RC_SIZE` error that wins over execution errors.
#[test]
#[allow(deprecated)]
fn crypto_command_trailing_byte_precedes_execution_errors() {
    let mut sim = Tpm::new();
    let key = create_primary_with_auth_in(
        &mut sim,
        Handle::RH_OWNER,
        ecc_template(
            base_attrs() | TpmaObject::SIGN_ENCRYPT,
            Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        ),
        b"",
    );
    let size = rc_bare(TpmRc::SIZE);

    // VerifySignature with an invalid signature + 1 trailing byte.
    let verify = VerifySignature {
        key_handle: key,
        digest: Tpm2bDigest::from_bytes(&[0x44; 32]).unwrap(),
        signature: TpmtSignature::Ecdsa(TpmsSignatureEcc {
            hash: TpmiAlgHash::Sha256,
            signature_r: Tpm2bEccParameter::from_bytes(&[1]).unwrap(),
            signature_s: Tpm2bEccParameter::from_bytes(&[1]).unwrap(),
        }),
    };
    assert_eq!(send_with_trailing(&mut sim, &verify, 0, &[], &[0]), size);

    // Sign with a wrong digest size + trailing byte.
    let sign_cmd = Sign {
        key_handle: key,
        digest: Tpm2bDigest::from_bytes(&[0x44; 7]).unwrap(),
        in_scheme: None,
        validation: TpmtTkHashcheck::new(Handle::RH_NULL, Tpm2bDigest::default()),
    };
    assert_eq!(send_with_trailing(&mut sim, &sign_cmd, 1, &[], &[0]), size);

    // RSA_Encrypt / RSA_Decrypt on an ECC key (TPM_RC_KEY) + trailing byte.
    let enc = RSAEncrypt {
        key_handle: key,
        message: Tpm2bPublicKeyRsa::from_bytes(b"msg").unwrap(),
        in_scheme: None,
        label: Tpm2bData::default(),
    };
    assert_eq!(send_with_trailing(&mut sim, &enc, 0, &[], &[0]), size);
    let dec = RSADecrypt {
        key_handle: key,
        cipher_text: Tpm2bPublicKeyRsa::from_bytes(b"msg").unwrap(),
        in_scheme: None,
        label: Tpm2bData::default(),
    };
    assert_eq!(send_with_trailing(&mut sim, &dec, 1, &[], &[0]), size);
}

/// Hand-marshalled password-authorized CreatePrimary has the expected auth-area layout and executes
///
/// Hand-marshals a password-authorized `TPM2_CreatePrimary` command, checks
/// the auth-area layout, and executes it on the simulator.
#[test]
fn hand_marshaled_create_primary() {
    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);

    let rsa_parms = TpmsRsaParms {
        symmetric: None,
        scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        key_bits: TpmiRsaKeyBits(2048),
        exponent: 0,
    };

    let tpmt_public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, Tpm2bPublicKeyRsa::default()),
    };
    let in_public = tpm2::Tpm2b(tpmt_public);

    let mut pcr_buf = [0u8; 100];
    let mut written = 0;
    written += marshal_to_slice(&(1u32), &mut pcr_buf[written..]);
    written += marshal_to_slice(&(TpmiAlgHash::Sha1), &mut pcr_buf[written..]);
    written += marshal_to_slice(&(3u8), &mut pcr_buf[written..]);
    pcr_buf[written] = 0x80;
    written += 3;
    let mut unmarsh = &pcr_buf[..written];
    let creation_pcr = TpmlPcrSelection::unmarshal(&mut unmarsh).unwrap();

    let cp_cmd = CreatePrimary {
        primary_handle: Handle(0x40000001),
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr,
    };

    let _num_sessions = 1;
    let mut cmd_buffer = [0u8; 4096];
    let cmd_header = CmdHeader {
        tag: TpmiStCommandTag::Sessions,
        size: 0,
        code: TpmCc::CreatePrimary,
    };
    let mut written = marshal_to_slice(&cmd_header, &mut cmd_buffer);
    written += marshal_to_slice(&(cp_cmd.primary_handle), &mut cmd_buffer[written..]);

    let auth_cmd = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };

    let mut auth_buffer = [0u8; 1024];
    let auth_written = marshal_to_slice(&auth_cmd, &mut auth_buffer);

    written += marshal_to_slice(&(auth_written as u32), &mut cmd_buffer[written..]);
    cmd_buffer[written..written + auth_written].copy_from_slice(&auth_buffer[..auth_written]);
    let end_of_auth = written + auth_written;
    written += auth_written;

    written += marshal_to_slice(&cp_cmd, &mut cmd_buffer[written..]);

    assert_eq!(end_of_auth - auth_written, 10 + 4 + 4);

    // Patch commandSize and send the hand-marshaled command to the simulator.
    let size = written as u32;
    cmd_buffer[2..6].copy_from_slice(&size.to_be_bytes());
    let mut sim = Tpm::new();
    let mut resp_buffer = [0u8; 4096];
    let resp = sim
        .transact(&cmd_buffer[..written], &mut resp_buffer)
        .expect("transact failed");
    let mut resp_slice: &[u8] = resp;
    let resp_header = RespHeader::unmarshal(&mut resp_slice).unwrap();
    assert_eq!(
        resp_header.rc, 0,
        "hand-marshaled CreatePrimary failed with {:#x}",
        resp_header.rc
    );
    assert_eq!(resp_header.size as usize, resp.len());
}
