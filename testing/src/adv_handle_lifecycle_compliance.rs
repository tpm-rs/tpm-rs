#![forbid(unsafe_code)]
use tpm2::commands::{
    CreatePrimary, CreatePrimaryHandles, EvictControl, EvictControlHandles, FlushContext,
    PolicySecret, PolicySecretHandles, StartAuthSession, StartAuthSessionHandles,
};
use tpm2::*;
use tpm2::{Handle, TpmSe};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

use crate::test_utils::*;

fn get_rsa_srk_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
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
            Tpm2bPublicKeyRsa::default(),
        ),
    }
}

#[test]
fn test_compliance_multi_step_session_eviction_parity() {
    let mut sim = create_simulator!();

    // 1. CreatePrimary under Owner hierarchy
    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);
    let in_public = tpm2::Tpm2b(get_rsa_srk_template());
    let create_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (_, create_rsp) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, &[]).unwrap();
    let transient_handle = create_rsp.object_handle;

    // 2. Persist the primary object using EvictControl
    let persistent_handle = Handle(0x81000005);
    let evict_handles = EvictControlHandles {
        auth: Handle::RH_OWNER,
        object_handle: transient_handle,
    };
    let evict_cmd = EvictControl { persistent_handle };
    execute_with_password_sessions(&mut sim, &evict_cmd, evict_handles, 1, &[]).unwrap();

    // 3. StartAuthSession bound to the persistent object
    let start_handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: persistent_handle,
    };
    let start_cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[1u8; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (_, start_rsp) =
        execute_with_password_sessions(&mut sim, &start_cmd, start_handles, 0, &[]).unwrap();
    let session_handle = start_rsp.session_handle;

    // Verify session handle transitions cleanly and is valid
    assert_ne!(session_handle, Handle::RH_NULL);

    // 4. PolicySecret authorization loop against the session
    let policy_handles = PolicySecretHandles {
        auth_handle: Handle::RH_OWNER,
        policy_session: session_handle,
    };
    let policy_cmd = PolicySecret {
        nonce_tpm: Tpm2bNonce::default(),
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: 0,
    };
    execute_with_password_sessions(&mut sim, &policy_cmd, policy_handles, 1, &[]).unwrap();

    // 5. Evict the persistent object back to transient/unloaded state
    let evict_handles2 = EvictControlHandles {
        auth: Handle::RH_OWNER,
        object_handle: persistent_handle,
    };
    let evict_cmd2 = EvictControl { persistent_handle };
    execute_with_password_sessions(&mut sim, &evict_cmd2, evict_handles2, 1, &[]).unwrap();

    // 6. FlushContext on the policy session
    let flush_cmd = FlushContext {
        flush_handle: session_handle,
    };
    let flush_res = execute_with_password_sessions(&mut sim, &flush_cmd, (), 0, &[]);
    assert!(
        flush_res.is_ok(),
        "FlushContext on active policy session failed unexpectedly: {:?}",
        flush_res
    );
}
