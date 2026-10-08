use crate::test_utils::*;
use tpm2::Unmarshal;
use tpm2::commands::{ContextSave, ContextSaveHandles, CreateLoaded, CreateLoadedHandles};
use tpm2::*;
use tpm2::{Handle, TpmEccCurve};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

#[test]
fn test_context_save_kdfa_bug() {
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

    let sequence_bytes = save_resp.context.sequence.to_be_bytes();
    let proof = &sim.global_state.sh_proof[0..sim.global_state.sh_proof_size as usize];

    let mut unmarshal_blob = save_resp.context.context_blob.get_buffer();
    let context_data = tpm2::TpmsContextData::unmarshal(&mut unmarshal_blob).unwrap();

    let mut hash_state =
        tpm2::crypto::HmacCtx::new(&*sim.context.platform.crypto, TpmiAlgHash::Sha256, proof)
            .unwrap();
    hash_state
        .update(&sim.global_state.total_reset_count.to_be_bytes())
        .unwrap();
    hash_state.update(&sequence_bytes).unwrap();
    hash_state
        .update(&save_resp.context.saved_handle.0.to_be_bytes())
        .unwrap();
    hash_state
        .update(context_data.encrypted.get_buffer())
        .unwrap();
    let mut mac_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let mac = hash_state.finalize(&mut mac_buf).unwrap();

    assert_eq!(
        mac.digest(),
        context_data.integrity.get_buffer(),
        "ContextSave HMAC must match TCG spec (proof key + totalResetCount + sequence + savedHandle + encrypted)"
    );
}
