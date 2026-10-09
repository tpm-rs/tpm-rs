use crate::test_utils::*;
use tpm2::Unmarshal;
use tpm2::commands::{
    ContextLoad, ContextSave, ContextSaveHandles, CreateLoaded, CreateLoadedHandles, ReadPublic,
    ReadPublicHandles,
};
use tpm2::errors::TpmRc;
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_simulator::create_simulator;

#[test]
fn test_context_load_rejects_tampered_blob() {
    let mut sim = create_simulator!();

    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(b"pass").unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(tpmt_sensitive);

    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
                    hash_alg: TpmiAlgHash::Sha256,
                    count: 0,
                })),
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let in_public = crate::test_utils::make_template(&pub_area);
    let create = CreateLoaded {
        in_sensitive,
        in_public,
    };
    let create_handles = CreateLoadedHandles {
        parent_handle: Handle(0x40000001),
    };

    let (_create_resp, create_resp_handles) =
        execute_with_password_sessions(&mut sim, &create, create_handles, 1, &[]).unwrap();
    let object_handle = create_resp_handles.object_handle;

    let save = ContextSave {};
    let save_handles = ContextSaveHandles {
        save_handle: object_handle,
    };
    let (save_resp, _) =
        execute_with_password_sessions(&mut sim, &save, save_handles, 0, &[]).unwrap();

    // The context integrity HMAC is keyed with a TPM-internal proof value, so
    // it cannot be recomputed by a black-box client. Instead, verify that the
    // TPM accepts the untouched blob and rejects any tampering with either the
    // integrity digest or the encrypted payload that the HMAC covers.
    let context = save_resp.context;
    let blob = context.context_blob.get_buffer().to_vec();
    let mut unmarshal_blob = &blob[..];
    let context_data = tpm2::TpmsContextData::unmarshal(&mut unmarshal_blob).unwrap();
    assert_eq!(
        context_data.integrity.get_buffer().len(),
        32,
        "ContextSave integrity must be a SHA-256 HMAC"
    );
    assert!(!context_data.encrypted.get_buffer().is_empty());

    flush_context(&mut sim, object_handle).unwrap();

    // Byte offsets inside the marshaled TPMS_CONTEXT_DATA blob:
    // [integrity.size (2) | integrity (32) | encrypted.size (2) | encrypted ...].
    let integrity_offset = 2;
    let size_offset = 2 + context_data.integrity.get_buffer().len();
    let encrypted_offset = size_offset + 2;
    let flip = |offset: usize| {
        let mut b = blob.clone();
        b[offset] ^= 0x01;
        b
    };
    let mut appended = blob.clone();
    appended.push(0xEE);
    let mut truncated = blob.clone();
    truncated.pop();
    for (what, tampered) in [
        ("integrity", flip(integrity_offset)),
        ("encrypted size (+256)", flip(size_offset)),
        ("encrypted size (low bit)", flip(size_offset + 1)),
        ("encrypted (first byte)", flip(encrypted_offset)),
        ("encrypted (last byte)", flip(blob.len() - 1)),
        ("appended byte", appended),
        ("truncated blob", truncated),
    ] {
        let mut tampered_context = context;
        tampered_context.context_blob =
            Tpm2bContextData::from_bytes(leak_bytes(&tampered)).unwrap();
        let res = execute_with_password_sessions(
            &mut sim,
            &ContextLoad {
                context: tampered_context,
            },
            (),
            0,
            &[],
        );
        let err = res.expect_err(&format!(
            "ContextLoad accepted a context with tampered {what}"
        ));
        // Strip the format-1 parameter/handle/session number (bits 6 and 8..11).
        assert_eq!(
            err & 0xBF,
            TpmRc::INTEGRITY.get(),
            "tampered {what}: unexpected error {err:#x}"
        );
    }

    // The untouched context must still load and yield a usable object.
    let (_, load_handles) =
        execute_with_password_sessions(&mut sim, &ContextLoad { context }, (), 0, &[])
            .expect("ContextLoad of untouched context failed");
    let (read_pub, _) = execute_with_password_sessions(
        &mut sim,
        &ReadPublic {},
        ReadPublicHandles {
            object_handle: load_handles.loaded_handle,
        },
        0,
        &[],
    )
    .unwrap();
    assert!(!read_pub.name.get_buffer().is_empty());
}
