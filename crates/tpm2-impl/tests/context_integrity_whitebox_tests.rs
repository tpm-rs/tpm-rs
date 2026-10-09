//! White-box test for the `TPM2_ContextSave` integrity HMAC.
//!
//! Moved from the black-box `testing` crate: recomputing the HMAC requires the
//! TPM-internal hierarchy proof and `totalResetCount`, which are only reachable
//! through [`tpm2_impl::GlobalState`].

mod common;

use common::{
    FakeRng, FakeStorage, FakeTimer, TestCryptoProvider, execute_command, password_auth,
    setup_real_crypto_tpm,
};
use tpm2::commands::{ContextSave, ContextSaveHandles, CreatePrimary, CreatePrimaryHandles};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bSensitiveData,
    TpmEccCurve, TpmaObject, TpmiAlgHash, TpmsEccParms, TpmsEccPoint, TpmsSchemeEcdaa,
    TpmsSensitiveCreate, TpmtEccScheme, TpmtPublic, Unmarshal,
};

/// The integrity value of a saved context must be
/// `HMAC_SHA256(hProof, totalResetCount || sequence || savedHandle || encContext)`,
/// where `encContext` is the marshaled `TPM2B_CONTEXT_SENSITIVE` (size included)
/// (TPM 2.0 Part 1, "Context Integrity Protection"), keyed with the proof of
/// the hierarchy the object belongs to (here: the owner/storage hierarchy).
#[test]
fn test_context_save_kdfa_bug() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) =
        setup_real_crypto_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(b"pass").unwrap(),
        data: Tpm2bSensitiveData::default(),
    });
    let in_public = tpm2::Tpm2b(TpmtPublic {
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
    });
    let create = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let (create_handles, _) = execute_command(
        &mut tpm,
        &mut global_state,
        &CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        },
        &create,
        &[password_auth(b"")],
    )
    .expect("CreatePrimary failed");

    let (_, save_resp) = execute_command(
        &mut tpm,
        &mut global_state,
        &ContextSaveHandles {
            save_handle: create_handles.object_handle,
        },
        &ContextSave {},
        &[],
    )
    .expect("ContextSave failed");
    let context = save_resp.context;
    assert_eq!(context.hierarchy, Handle::RH_OWNER);

    let blob = context.context_blob.get_buffer();
    let mut unmarshal_blob = blob;
    let context_data = tpm2::TpmsContextData::unmarshal(&mut unmarshal_blob).unwrap();
    assert!(unmarshal_blob.is_empty());
    // encContext: every byte after the integrity value, i.e. the marshaled
    // TPM2B_CONTEXT_SENSITIVE including its size field.
    let enc_context = &blob[2 + context_data.integrity.get_buffer().len()..];
    assert_eq!(
        &enc_context[2..],
        context_data.encrypted.get_buffer(),
        "encContext must be size || encrypted"
    );

    let proof = &global_state.sh_proof[..global_state.sh_proof_size as usize];
    let mut hmac = tpm2::crypto::HmacCtx::new(&crypto, TpmiAlgHash::Sha256, proof).unwrap();
    hmac.update(&global_state.total_reset_count.to_be_bytes())
        .unwrap();
    hmac.update(&context.sequence.to_be_bytes()).unwrap();
    hmac.update(&context.saved_handle.0.to_be_bytes()).unwrap();
    hmac.update(enc_context).unwrap();
    let mut mac_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let mac = hmac.finalize(&mut mac_buf).unwrap();

    assert_eq!(
        mac.digest(),
        context_data.integrity.get_buffer(),
        "ContextSave HMAC must match TCG spec (proof key + totalResetCount + sequence + savedHandle + encContext)"
    );
}
