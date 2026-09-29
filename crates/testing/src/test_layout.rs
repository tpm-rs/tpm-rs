use crate::test_utils::marshal_to_slice;
use crate::test_utils::*;
use tpm2::TpmiStCommandTag;
use tpm2::Unmarshal;
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles};
use tpm2::*;
use tpm2::{Handle, TpmCc};

#[test]
fn test_dump() {
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
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr,
    };
    let cp_handles = CreatePrimaryHandles {
        primary_handle: Handle(0x40000001),
    };

    let _num_sessions = 1;
    let mut cmd_buffer = [0u8; 4096];
    let cmd_header = CmdHeader {
        tag: TpmiStCommandTag::Sessions,
        size: 0,
        code: TpmCc::CreatePrimary,
    };
    let mut written = marshal_to_slice(&cmd_header, &mut cmd_buffer);
    written += marshal_to_slice(&(cp_handles), &mut cmd_buffer[written..]);

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

    println!("Total written: {}", written);
    println!("Auth Size value: {}", auth_written);
    println!("Auth Area starts at: {}", end_of_auth - auth_written);
    println!("Cmd Parameters start at: {}", end_of_auth);
}
