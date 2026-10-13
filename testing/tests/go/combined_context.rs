use crate::test_utils::marshal_to_slice;
use tpm2::Handle;
use tpm2::Unmarshal;
use tpm2::commands::{ContextLoad, ContextSave, CreatePrimary};
use tpm2::*;
#[rustfmt::skip]
use testing::tpm::Tpm;
use crate::test_utils::*;

/// Builds the `CreatePrimary` command used by `TestCombinedContext`: an
/// RSA-2048 RSASSA-SHA256 signing key under the owner hierarchy, with an empty
/// sensitive area and a creation PCR selection of SHA-1 PCR 7 (PC-client
/// compatible, 3-byte select).
pub(crate) fn combined_context_create_primary() -> CreatePrimary<'static> {
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

    // TPML_PCR_SELECTION { count = 1, { SHA1, sizeofSelect = 3, [0x80, 0, 0] } }
    let mut pcr_buf = [0u8; 100];
    let mut written = 0;
    written += marshal_to_slice(&(1u32), &mut pcr_buf[written..]);
    written += marshal_to_slice(&(TpmiAlgHash::Sha1), &mut pcr_buf[written..]);
    written += marshal_to_slice(&(3u8), &mut pcr_buf[written..]);
    pcr_buf[written] = 0x80;
    pcr_buf[written + 1] = 0;
    pcr_buf[written + 2] = 0;
    written += 3;
    let mut unmarsh: &'static [u8] = leak_bytes(&pcr_buf[..written]);
    let creation_pcr = TpmlPcrSelection::unmarshal(&mut unmarsh).unwrap();

    CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr,
    }
}

// Original Go test: combined_context_test.go - TestCombinedContext
#[test]
fn test_combined_context() {
    let mut sim = Tpm::new();

    let cp_cmd = combined_context_create_primary();

    let cp_resp =
        execute_with_password_sessions(&mut sim, &cp_cmd, 1, &[]).expect("could not create key");
    let cp_handle = cp_resp.object_handle;

    let save_cmd = ContextSave {
        save_handle: cp_handle,
    };
    let save_resp =
        execute_with_password_sessions(&mut sim, &save_cmd, 0, &[]).expect("ContextSave failed");

    let load_cmd = ContextLoad {
        context: save_resp.context,
    };
    let load_resp =
        execute_with_password_sessions(&mut sim, &load_cmd, 0, &[]).expect("ContextLoad failed");
    let cl_handle = load_resp.loaded_handle;

    let cl_name = read_public_name(&mut sim, cl_handle);
    let cp_name = read_public_name(&mut sim, cp_handle);

    assert_eq!(
        cl_name.get_buffer()[..cl_name.get_size() as usize],
        cp_name.get_buffer()[..cp_name.get_size() as usize],
        "Mismatch between public returned from ContextLoad & CreateLoaded"
    );

    // Mirrors the deferred FlushContext calls in the Go test (LIFO order).
    let _ = flush_context(&mut sim, cl_handle);
    let _ = flush_context(&mut sim, cp_handle);
}
