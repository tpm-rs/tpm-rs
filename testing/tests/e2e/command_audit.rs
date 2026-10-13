//! TPM2_GetCommandAuditDigest: unsigned and signed command audit attestations.

use crate::_common::Connection;
use crate::_common::execute_with_password_sessions;
use testing::tpm::Tpm;
use tpm2::commands::{CreatePrimary, GetCommandAuditDigest};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2b, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bPublicKeyRsa,
    Tpm2bSensitiveData, TpmaObject, TpmiAlgHash, TpmiRsaKeyBits, TpmlPcrSelection, TpmsRsaParms,
    TpmsSensitiveCreate, TpmtPublic, TpmtRsaScheme,
};

/// Raw TPM2_GetCommandAuditDigest signed with a restricted RSASSA/SHA-1 key succeeds
///
/// `TPM2_GetCommandAuditDigest` signed with a restricted RSA signing key
/// (RSASSA/SHA-1 scheme) succeeds.
#[test]
fn get_command_audit_digest_signed_with_rsa_key() {
    let mut sim = Tpm::new();

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::RESTRICTED
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha1)),
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let create = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(public),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_handles =
        execute_with_password_sessions(&mut sim, &create, 1, &[]).expect("CreatePrimary failed");
    let key_handle = create_handles.object_handle.0;

    // GetCommandAuditDigest request:
    // tag: 8002
    // cc: 00000133
    // handles: privacyAdmin (4000000B), signHandle (key)
    // auth area: 2 password sessions
    // qualifyingData: 0003 'aaa'
    // inScheme: 0014 (RSASSA) 0004 (SHA1)
    let mut req = Vec::new();
    req.extend_from_slice(&0x8002u16.to_be_bytes());
    req.extend_from_slice(&[0, 0, 0, 0]); // size placeholder
    req.extend_from_slice(&0x0000_0133u32.to_be_bytes()); // TPM_CC_GetCommandAuditDigest
    req.extend_from_slice(&0x4000000Bu32.to_be_bytes()); // RH_ENDORSEMENT
    req.extend_from_slice(&key_handle.to_be_bytes()); // signHandle
    // Auth size + 2 auth sessions (each: handle=40000009, nonce=0, attr=01, hmac=0)
    req.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x12, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00,
        0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00,
    ]);
    // qualifyingData
    req.extend_from_slice(&[0x00, 0x03, 0x61, 0x61, 0x61]);
    // inScheme: RSASSA (0x0014) SHA1 (0x0004)
    req.extend_from_slice(&[0x00, 0x14, 0x00, 0x04]);

    let req_len = req.len() as u32;
    req[2..6].copy_from_slice(&req_len.to_be_bytes());

    let mut response_buf = [0u8; 4096];
    let rsp = sim.transact(&req, &mut response_buf).unwrap();

    let rc = u32::from_be_bytes(rsp[6..10].try_into().unwrap());
    assert_eq!(rc, 0, "GetCommandAuditDigest failed with rc: 0x{:08x}", rc);
}

/// TPM2_GetCommandAuditDigest with signHandle=TPM_RH_NULL and two sessions returns a non-empty unsigned attestation
///
/// `TPM2_GetCommandAuditDigest` with `signHandle = TPM_RH_NULL` returns a
/// non-empty (unsigned) attestation.
#[test]
fn get_command_audit_digest_unsigned() {
    let mut sim = Tpm::new();

    let audit_cmd = GetCommandAuditDigest {
        privacy_handle: Handle::RH_ENDORSEMENT,
        sign_handle: Handle::RH_NULL,
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    // Both privacyAdminHandle and signHandle (TPM_RH_NULL) have the USER auth role, so C
    // needs two sessions (SessionProcess.c:1641-1651, otherwise TPM_RC_AUTH_MISSING).
    let resp = execute_with_password_sessions(&mut sim, &audit_cmd, 2, &[])
        .expect("GetCommandAuditDigest failed");

    assert!(resp.audit_info.get_size() > 0);
}
