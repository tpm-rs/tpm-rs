use crate::test_utils::marshal_to_slice;
use crate::test_utils::*;
use tpm2::Handle;
use tpm2::Unmarshal;
use tpm2::commands::{
    ContextLoad, ContextSave, ContextSaveHandles, CreatePrimary, CreatePrimaryHandles,
};
use tpm2::*;
use tpm2_simulator::create_simulator;

#[test]
fn test_stress_combined_context() {
    let mut sim = create_simulator!();

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
    pcr_buf[written + 1] = 0;
    pcr_buf[written + 2] = 0;
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

    let (_cp_resp, cp_resp_handles) =
        execute_with_password_sessions(&mut sim, &cp_cmd, cp_handles, 1, &[]).unwrap();
    let cp_handle = cp_resp_handles.object_handle;

    let cp_name = read_public_name(&mut sim, cp_handle);

    // Save Context
    let save_cmd = ContextSave::default();
    let save_handles = ContextSaveHandles {
        save_handle: cp_handle,
    };
    let (save_resp, _) =
        execute_with_password_sessions(&mut sim, &save_cmd, save_handles, 0, &[]).unwrap();

    // Flush it before load
    let _ = flush_context(&mut sim, cp_handle);

    // Load it back
    let load_cmd = ContextLoad {
        context: save_resp.context,
    };
    let (_, load_resp_handles) =
        execute_with_password_sessions(&mut sim, &load_cmd, (), 0, &[]).unwrap();
    let cl_handle = load_resp_handles.loaded_handle;

    let cl_name = read_public_name(&mut sim, cl_handle);

    assert_eq!(
        cp_name.get_size(),
        cl_name.get_size(),
        "Mismatch in name size"
    );
    assert_eq!(
        cp_name.get_buffer()[..cp_name.get_size() as usize],
        cl_name.get_buffer()[..cl_name.get_size() as usize],
        "Mismatch in name contents"
    );

    // Load it again, should work and give a different handle
    let (_, load_resp_handles2) =
        execute_with_password_sessions(&mut sim, &load_cmd, (), 0, &[]).unwrap();
    let cl_handle2 = load_resp_handles2.loaded_handle;
    assert_ne!(
        cl_handle.0, cl_handle2.0,
        "Should get a different transient handle"
    );

    let _ = flush_context(&mut sim, cl_handle);
    let _ = flush_context(&mut sim, cl_handle2);
}
