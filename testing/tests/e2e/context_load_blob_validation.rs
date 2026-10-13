//! TPM2_ContextLoad of modified context blobs: size fields, truncation, trailing bytes and
//! integrity failures.

use crate::_common::{
    CONTEXT_INTEGRITY_DIGEST_SIZE, ENC_SIZE_OFFSET, FINGERPRINT_SIZE, assert_load_rejected,
    execute_with_password_sessions, flush_context, integrity_rc, leak_bytes, load_context,
    make_template, save_object_context, size_rc, start_auth_session,
};
use testing::tpm::Tpm;
#[allow(deprecated)]
use tpm2::commands::{ContextLoad, ContextSave, CreateLoaded, ReadPublic};
use tpm2::errors::TpmRc;
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bContextData, Tpm2bDigest, Tpm2bEccParameter,
    Tpm2bSensitiveData, TpmEccCurve, TpmSe, TpmaObject, TpmiAlgHash, TpmsEccParms, TpmsEccPoint,
    TpmsSchemeEcdaa, TpmsSensitiveCreate, TpmtEccScheme, TpmtPublic, Unmarshal,
};

/// A context blob whose encrypted size is increased fails with TPM_RC_INTEGRITY.
#[test]
fn enlarged_encrypted_size_returns_integrity() {
    let mut sim = Tpm::new();
    let context = save_object_context(&mut sim);
    let mut blob = context.context_blob.get_buffer().to_vec();
    blob[ENC_SIZE_OFFSET] ^= 0x01; // +256: larger than the remaining data
    assert_load_rejected(&mut sim, context, blob, integrity_rc(), "size+256");
}

/// Blobs too short for the integrity TPM2B give INSUFFICIENT; later size checks give SIZE + P1.
#[test]
fn short_blobs_return_size() {
    let mut sim = Tpm::new();
    let context = save_object_context(&mut sim);
    let blob = context.context_blob.get_buffer().to_vec();
    // C starts with TPM2B_DIGEST_Unmarshal(&integrity, blob) and returns its result unmodified
    // (ContextLoad.c:49-51), so a blob too short for the integrity TPM2B gives bare
    // TPM_RC_INSUFFICIENT; the later size checks return TPM_RCS_SIZE + RC_ContextLoad_context.
    let insufficient = TpmRc::INSUFFICIENT.get();
    for (what, len, rc) in [
        ("empty blob", 0, insufficient),
        ("1 byte", 1, insufficient),
        ("partial integrity", 10, insufficient),
        ("integrity only", ENC_SIZE_OFFSET, size_rc()),
        ("integrity + size only", ENC_SIZE_OFFSET + 2, size_rc()),
        (
            "no room for fingerprint",
            ENC_SIZE_OFFSET + 2 + FINGERPRINT_SIZE - 1,
            size_rc(),
        ),
    ] {
        assert_load_rejected(&mut sim, context, blob[..len].to_vec(), rc, what);
    }
}

/// A context blob whose encrypted size is decreased fails with TPM_RC_INTEGRITY.
#[test]
fn shrunken_encrypted_size_returns_integrity() {
    let mut sim = Tpm::new();
    let context = save_object_context(&mut sim);
    let mut blob = context.context_blob.get_buffer().to_vec();
    let size = u16::from_be_bytes([blob[ENC_SIZE_OFFSET], blob[ENC_SIZE_OFFSET + 1]]);
    blob[ENC_SIZE_OFFSET..ENC_SIZE_OFFSET + 2].copy_from_slice(&(size - 1).to_be_bytes());
    assert_load_rejected(&mut sim, context, blob, integrity_rc(), "size-1");
}

/// Tampering with the integrity digest or encrypted payload fails with TPM_RC_INTEGRITY.
#[test]
fn tampered_integrity_or_payload_returns_integrity() {
    let mut sim = Tpm::new();
    let context = save_object_context(&mut sim);
    let blob = context.context_blob.get_buffer().to_vec();
    for (what, offset) in [
        ("integrity", 2),
        ("encrypted first byte", ENC_SIZE_OFFSET + 2),
        ("encrypted last byte", blob.len() - 1),
    ] {
        let mut tampered = blob.clone();
        tampered[offset] ^= 0x01;
        assert_load_rejected(&mut sim, context, tampered, integrity_rc(), what);
    }
}

/// An untouched saved object context loads; tampering with integrity or encrypted bytes fails with TPM_RC_INTEGRITY.
#[test]
#[allow(deprecated)]
fn tampered_object_blob_returns_integrity() {
    let mut sim = Tpm::new();

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
    let in_public = make_template(&pub_area);
    let create = CreateLoaded {
        parent_handle: Handle(0x40000001),
        in_sensitive,
        in_public,
    };

    let create_resp_handles = execute_with_password_sessions(&mut sim, &create, 1, &[]).unwrap();
    let object_handle = create_resp_handles.object_handle;

    let save = ContextSave {
        save_handle: object_handle,
    };
    let save_resp = execute_with_password_sessions(&mut sim, &save, 0, &[]).unwrap();

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
        CONTEXT_INTEGRITY_DIGEST_SIZE,
        "ContextSave integrity must be a SHA-512 HMAC (strongest implemented hash)"
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
    let load_handles = execute_with_password_sessions(&mut sim, &ContextLoad { context }, 0, &[])
        .expect("ContextLoad of untouched context failed");
    let read_pub = execute_with_password_sessions(
        &mut sim,
        &ReadPublic {
            object_handle: load_handles.loaded_handle,
        },
        0,
        &[],
    )
    .unwrap();
    assert!(!read_pub.name.get_buffer().is_empty());
}

/// A context blob with trailing bytes fails with TPM_RC_INTEGRITY.
#[test]
fn trailing_bytes_return_integrity() {
    let mut sim = Tpm::new();
    let context = save_object_context(&mut sim);
    let mut blob = context.context_blob.get_buffer().to_vec();
    blob.push(0xEE);
    assert_load_rejected(&mut sim, context, blob, integrity_rc(), "trailing byte");
}

/// A context blob with truncated encrypted data fails with TPM_RC_INTEGRITY.
#[test]
fn truncated_encrypted_data_returns_integrity() {
    let mut sim = Tpm::new();
    let context = save_object_context(&mut sim);
    let mut blob = context.context_blob.get_buffer().to_vec();
    blob.pop();
    assert_load_rejected(&mut sim, context, blob, integrity_rc(), "truncated");
}

/// An unmodified object context blob loads back.
#[test]
fn untouched_object_context_round_trips() {
    let mut sim = Tpm::new();
    let context = save_object_context(&mut sim);
    let handle = load_context(&mut sim, context).expect("ContextLoad failed");
    sim.execute(ReadPublic {
        object_handle: handle,
    })
    .expect("loaded object must be usable");
}

/// An unmodified session context blob loads back.
#[test]
fn untouched_session_context_round_trips() {
    let mut sim = Tpm::new();
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("StartAuthSession failed");
    let save = sim
        .execute(ContextSave {
            save_handle: session.session_handle,
        })
        .expect("ContextSave of session failed");
    assert_eq!(
        load_context(&mut sim, save.context),
        Ok(session.session_handle)
    );
}

/// A context blob whose integrity is re-encoded as a 20-byte digest fails with TPM_RC_SIZE.
#[test]
fn wrong_integrity_size_returns_size() {
    let mut sim = Tpm::new();
    let context = save_object_context(&mut sim);
    let blob = context.context_blob.get_buffer().to_vec();
    // Re-encode the integrity value as a 20-byte digest.
    let mut tampered = Vec::new();
    tampered.extend_from_slice(&20u16.to_be_bytes());
    tampered.extend_from_slice(&blob[2..22]);
    tampered.extend_from_slice(&blob[ENC_SIZE_OFFSET..]);
    assert_load_rejected(&mut sim, context, tampered, size_rc(), "20-byte integrity");
}
