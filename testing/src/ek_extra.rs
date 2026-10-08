//! Extra (non-Go-parity) tests for ek, moved out of src/go.

use crate::test_utils::*;
use tpm2::commands::{
    Create, CreateHandles, CreatePrimary, CreatePrimaryHandles, PolicyGetDigest,
    PolicyGetDigestHandles, PolicySecret, PolicySecretHandles, ReadPublic, ReadPublicHandles,
};
use tpm2::{Handle, TpmSe};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bNonce, Tpm2bSensitiveData,
    TpmaObject, TpmiAlgHash, TpmsSensitiveCreate, TpmtPublic,
};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

/// Creates an EK from `ek_template`, checks that its auth policy (via
/// ReadPublic) and the TPM-computed PolicySecret(RH_ENDORSEMENT) digest
/// (via PolicyGetDigest) match the template, then creates a sealed blob under
/// the EK using that policy session.
///
/// (Formerly an unused helper in `go/ek.rs`; it has no Go counterpart.)
fn test_ek_policy_with_template(ek_template: TpmtPublic) {
    let mut sim = create_simulator!();

    let in_public = tpm2::Tpm2b(ek_template);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);
    let create_primary_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };
    let create_primary_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_ENDORSEMENT,
    };
    let (create_primary_resp, create_primary_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_primary_cmd,
        create_primary_handles,
        1,
        &[],
    )
    .unwrap();

    let ek_handle = create_primary_resp_handles.object_handle;
    let ek_name = create_primary_resp.name;

    let read_pub_cmd = ReadPublic {};
    let read_pub_handles = ReadPublicHandles {
        object_handle: ek_handle,
    };
    let (read_pub_resp, _) =
        execute_with_password_sessions(&mut sim, &read_pub_cmd, read_pub_handles, 0, &[]).unwrap();
    assert_eq!(
        read_pub_resp.out_public.0.auth_policy,
        ek_template.auth_policy
    );

    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let policy_secret_cmd = PolicySecret {
        nonce_tpm: session.nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: 0,
    };
    let policy_secret_handles = PolicySecretHandles {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: session.session_handle,
    };
    let _ =
        execute_with_password_sessions(&mut sim, &policy_secret_cmd, policy_secret_handles, 1, &[])
            .unwrap();

    let get_digest_cmd = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: session.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest_cmd, get_digest_handles, 0, &[])
            .unwrap();
    assert_eq!(
        get_digest_rsp.policy_digest.get_buffer(),
        ek_template.auth_policy.get_buffer()
    );

    let create_cmd = Create {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        }),
        in_public: tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::NO_DA,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };
    let create_handles = CreateHandles {
        parent_handle: ek_handle,
    };

    let mut sessions = [session];
    let _ = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[ek_name.get_buffer()],
        &mut sessions,
        &[&[]],
    )
    .unwrap();

    flush_context(&mut sim, ek_handle).unwrap();
}

#[test]
fn test_ek_policy_digest_and_create_rsa() {
    test_ek_policy_with_template(rsa_ek_template());
}

#[test]
fn test_ek_policy_digest_and_create_ecc() {
    test_ek_policy_with_template(ecc_ek_template());
}
