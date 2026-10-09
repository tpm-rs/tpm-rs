#![forbid(unsafe_code)]
use crate::test_utils::marshal_to_slice;

use crate::test_utils::{execute_with_password_sessions, flush_context, read_public_name};
use hmac::{Hmac as RustHmac, Mac};
use rand::{RngCore, thread_rng};
use sha2::{Digest as ShaDigest, Sha256};
use tpm2::Handle;
use tpm2::commands::{
    CreatePrimary, CreatePrimaryHandles, EvictControl, EvictControlHandles, Hmac, HmacHandles,
    Import, ImportHandles,
};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bPrivate, Tpm2bPublicKeyRsa, Tpm2bSensitiveData,
    TpmaObject, TpmiAlgHash, TpmiAlgSymMode, TpmiRsaKeyBits, TpmsRsaParms, TpmsSensitiveCreate,
    TpmtKeyedHashScheme, TpmtPublic, TpmtSensitive, TpmtSymDefObject, TpmuSensitiveComposite,
};
use tpm2_simulator::create_simulator;

/// Port of go-tpm's `RSASRKTemplate` (TCG reference RSA-2048 SRK template).
fn get_rsa_srk_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(&[0u8; 256]).unwrap(),
        ),
    }
}

/// Builds a `TPM2_CreatePrimary` command with an empty sensitive area and the
/// given public template.
fn create_primary_cmd(pub_area: TpmtPublic<'static>) -> CreatePrimary<'static> {
    CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(pub_area),
        ..Default::default()
    }
}

// Original Go test: hmac_test.go - TestHMAC
#[test]
fn test_hmac() {
    let mut sim = create_simulator!();

    // create HMAC key
    let hmac_scheme = Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256));
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(hmac_scheme, Tpm2bDigest::default()),
    };
    let create_cmd = create_primary_cmd(pub_area);
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let (_, create_rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[])
            .expect("CreatePrimary HMAC key failed");
    let hmac_key_handle = create_rsp_handles.object_handle;

    let hmac_cmd = Hmac {
        buffer: tpm2::Tpm2bMaxBuffer::from_bytes(b"test").unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let hmac_handles = HmacHandles {
        handle: hmac_key_handle,
    };

    // HMAC Key is not exportable and cannot be known.
    // Calculate HMAC twice and confirm they are the same.
    let (hmac1, _) = execute_with_password_sessions(&mut sim, &hmac_cmd, hmac_handles, 1, &[])
        .expect("TPM2_HMAC failed");
    let (hmac2, _) = execute_with_password_sessions(&mut sim, &hmac_cmd, hmac_handles, 1, &[])
        .expect("TPM2_HMAC failed");
    assert_eq!(
        hmac1.out_hmac.as_ref(),
        hmac2.out_hmac.as_ref(),
        "TPM2_HMAC failed: hmacs are different"
    );

    let _ = flush_context(&mut sim, hmac_key_handle);
}

// Original Go test: hmac_test.go - TestImportedHMACKey
#[test]
fn test_imported_hmac_key() {
    // configurable values
    let data = b"input data";
    let key_sensitive = b"the hmac key";
    let persistent_handle = Handle(0x81000000);

    let mut sim = create_simulator!();

    // create primary key
    let create_srk_cmd = create_primary_cmd(get_rsa_srk_template());
    let create_srk_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (_, srk_resp_handles) =
        execute_with_password_sessions(&mut sim, &create_srk_cmd, create_srk_handles, 1, &[])
            .expect("could not generate SRK");
    let srk_handle = srk_resp_handles.object_handle;

    // hmac template
    let mut sv = [0u8; 32];
    thread_rng().fill_bytes(&mut sv);

    let mut hasher = Sha256::new();
    hasher.update(sv);
    hasher.update(key_sensitive);
    let unique_digest = hasher.finalize().to_vec();

    let hmac_scheme = Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256));
    let hmac_template = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::USER_WITH_AUTH | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            hmac_scheme,
            Tpm2bDigest::from_bytes(crate::test_utils::leak_bytes(&unique_digest)).unwrap(),
        ),
    };
    let object_public = tpm2::Tpm2b(hmac_template);

    // sensitive data
    let sensitive = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(&sv).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(key_sensitive).unwrap(),
        ),
    };
    let mut sens_buf = vec![0u8; 1024];
    let sens_len = marshal_to_slice(&sensitive, &mut sens_buf);
    sens_buf.truncate(sens_len);

    // l := Marshal(TPM2BPrivate{Buffer: sens2B})
    let mut dup_buf = vec![0u8; 2 + sens_len];
    dup_buf[0..2].copy_from_slice(&(sens_len as u16).to_be_bytes());
    dup_buf[2..].copy_from_slice(&sens_buf);
    let duplicate = Tpm2bPrivate::from_bytes(&dup_buf).unwrap();

    // import hmac key
    let import_cmd = Import {
        encryption_key: tpm2::Tpm2bData::default(),
        object_public,
        duplicate,
        in_sym_seed: tpm2::Tpm2bEncryptedSecret::default(),
        symmetric_alg: None,
    };
    let import_handles = ImportHandles {
        parent_handle: srk_handle,
    };
    let import_resp = execute_with_password_sessions(&mut sim, &import_cmd, import_handles, 1, &[])
        .expect("could not import hmac key");

    // load hmac key
    let load_cmd = tpm2::commands::Load {
        in_private: import_resp.0.out_private,
        in_public: object_public,
    };
    let load_handles = tpm2::commands::LoadHandles {
        parent_handle: srk_handle,
    };
    let (_, load_resp_handles) =
        execute_with_password_sessions(&mut sim, &load_cmd, load_handles, 1, &[])
            .expect("could not load hmac key");
    let hmac_key_handle = load_resp_handles.object_handle;

    let _ = flush_context(&mut sim, srk_handle);

    // persist hmac key
    let evict_cmd = EvictControl { persistent_handle };
    let evict_handles = EvictControlHandles {
        auth: Handle::RH_OWNER,
        object_handle: hmac_key_handle,
    };
    execute_with_password_sessions(&mut sim, &evict_cmd, evict_handles, 1, &[])
        .expect("could not persist hmac key");

    let _ = flush_context(&mut sim, hmac_key_handle);

    // calculate hmac using TPM
    // Go resolves the name via ReadPublicName (TPM2_ReadPublic) before HMAC.
    let _name = read_public_name(&mut sim, persistent_handle);
    let hmac_cmd = Hmac {
        buffer: tpm2::Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let hmac_handles = HmacHandles {
        handle: persistent_handle,
    };

    let (resp, _) = execute_with_password_sessions(&mut sim, &hmac_cmd, hmac_handles, 1, &[])
        .expect("TPM2_HMAC failed");

    // calculate hmac in usual way
    type HmacSha256 = RustHmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key_sensitive).unwrap();
    mac.update(data);
    let expected_result = mac.finalize().into_bytes();

    // compare hmac results
    assert_eq!(expected_result.as_slice(), resp.out_hmac.as_ref());
}
