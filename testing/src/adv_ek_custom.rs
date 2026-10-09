#![allow(unused_imports, dead_code)]
use crate::test_utils::*;
use tpm2::commands::{
    Create, CreateHandles, CreatePrimary, CreatePrimaryHandles, PolicyGetDigest,
    PolicyGetDigestHandles, PolicySecret, PolicySecretHandles, ReadPublic, ReadPublicHandles,
};
use tpm2::{Handle, TpmSe};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bName, Tpm2bNonce,
    Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmaNv, TpmaObject, TpmiAlgHash, TpmsNvPublic,
    TpmsSensitiveCreate, TpmtPublic, TpmtSymDefObject,
};
use tpm2_simulator::{Simulator, create_simulator};

fn hex_decode(s: &str) -> Vec<u8> {
    let mut res = Vec::with_capacity(s.len() / 2);
    let mut iter = s.chars().filter(|c| !c.is_whitespace());
    while let (Some(c1), Some(c2)) = (iter.next(), iter.next()) {
        let hex_str = format!("{}{}", c1, c2);
        res.push(u8::from_str_radix(&hex_str, 16).unwrap());
    }
    res
}

fn compute_hash(alg: TpmiAlgHash, data: &[&[u8]]) -> Vec<u8> {
    use sha1::Sha1;
    use sha2::{Digest, Sha256, Sha384, Sha512};
    match alg {
        TpmiAlgHash::Sha1 => {
            let mut hasher = Sha1::new();
            for d in data {
                hasher.update(d);
            }
            hasher.finalize().to_vec()
        }
        TpmiAlgHash::Sha256 => {
            let mut hasher = Sha256::new();
            for d in data {
                hasher.update(d);
            }
            hasher.finalize().to_vec()
        }
        TpmiAlgHash::Sha384 => {
            let mut hasher = Sha384::new();
            for d in data {
                hasher.update(d);
            }
            hasher.finalize().to_vec()
        }
        TpmiAlgHash::Sha512 => {
            let mut hasher = Sha512::new();
            for d in data {
                hasher.update(d);
            }
            hasher.finalize().to_vec()
        }
        _ => panic!("Unsupported hash"),
    }
}

fn policy_or_go(alg: TpmiAlgHash, digests: &[&[u8]]) -> Vec<u8> {
    let digest_size = match alg {
        TpmiAlgHash::Sha1 => 20,
        TpmiAlgHash::Sha256 => 32,
        TpmiAlgHash::Sha384 => 48,
        TpmiAlgHash::Sha512 => 64,
        _ => panic!("Unsupported hash"),
    };
    let zero_digest = vec![0u8; digest_size];
    let cc_bytes = (tpm2::TpmCc::PolicyOR.code()).to_be_bytes();
    let mut updates = vec![zero_digest.as_slice(), &cc_bytes];
    for d in digests {
        updates.push(*d);
    }
    compute_hash(alg, &updates)
}

#[test]
fn test_policy_digest_reset_on_continue() {
    let mut sim = create_simulator!();
    let ek_template = rsa_ek_template();

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

    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    session.attributes = tpm2::TpmaSession::from_bits_retain(1);

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

    let mut sessions = [session.clone()];
    let _ = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[ek_name.get_buffer()],
        &mut sessions,
        &[&[]],
    )
    .unwrap();

    let updated_session = &sessions[0];

    let (get_digest_rsp2, _) = execute_with_password_sessions(
        &mut sim,
        &get_digest_cmd,
        PolicyGetDigestHandles {
            policy_session: updated_session.session_handle,
        },
        0,
        &[],
    )
    .unwrap();

    let zero_digest = vec![0u8; 32];
    assert_eq!(
        get_digest_rsp2.policy_digest.get_buffer(),
        zero_digest.as_slice()
    );

    flush_context(&mut sim, ek_handle).unwrap();
    flush_context(&mut sim, updated_session.session_handle).unwrap();
}

#[test]
fn test_policy_digest_reset_on_format1_failure() {
    let mut sim = create_simulator!();
    let ek_template = rsa_ek_template();

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

    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    session.attributes = tpm2::TpmaSession::from_bits_retain(1); // CONTINUE_SESSION

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

    // Create an invalid command that will fail validation in the handler (Format 1 error: TPM_RC_ATTRIBUTES)
    let create_cmd = Create {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
        }),
        in_public: tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sm3_256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::DECRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };
    let create_handles = CreateHandles {
        parent_handle: ek_handle,
    };

    let mut sessions = [session.clone()];
    let res = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[ek_name.get_buffer()],
        &mut sessions,
        &[&[]],
    );
    // Command must fail!
    assert!(res.is_err());

    let updated_session = &sessions[0];

    // Query policy digest again - it must have been reset to zero!
    let get_digest_cmd = PolicyGetDigest {};
    let (get_digest_rsp2, _) = execute_with_password_sessions(
        &mut sim,
        &get_digest_cmd,
        PolicyGetDigestHandles {
            policy_session: updated_session.session_handle,
        },
        0,
        &[],
    )
    .unwrap();

    let zero_digest = vec![0u8; 32];
    assert_eq!(
        get_digest_rsp2.policy_digest.get_buffer(),
        zero_digest.as_slice(),
        "Policy digest should be reset to zero on Format-1 command failure"
    );

    flush_context(&mut sim, ek_handle).unwrap();
    flush_context(&mut sim, updated_session.session_handle).unwrap();
}

#[test]
fn test_policy_secret_with_nv_index() {
    let mut sim = create_simulator!();

    // 1. Define NV index
    let nv_index_val = 0x01600008;
    let nv_pub = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE,
        auth_policy: Tpm2bDigest::default(),
        data_size: 32,
    };
    let public_info = tpm2::Tpm2b(nv_pub);
    let nv_auth = Tpm2bAuth::default();

    let define_cmd = tpm2::commands::NVDefineSpace {
        public_info,
        auth: nv_auth,
    };
    let define_handles = tpm2::commands::NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &define_cmd, define_handles, 1, &[]).unwrap();

    // 2. Start policy session
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

    // 3. Execute PolicySecret using NV Index as auth_handle
    let policy_secret_cmd = PolicySecret {
        nonce_tpm: session.nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: 0,
    };
    let policy_secret_handles = PolicySecretHandles {
        auth_handle: Handle(nv_index_val),
        policy_session: session.session_handle,
    };

    // Auth session 1 is for the NV Index (password session with empty auth)
    let res =
        execute_with_password_sessions(&mut sim, &policy_secret_cmd, policy_secret_handles, 1, &[]);
    assert!(res.is_ok(), "PolicySecret failed: {:?}", res.err());

    // 4. Get policy digest
    let get_digest_cmd = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: session.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest_cmd, get_digest_handles, 0, &[])
            .unwrap();

    // 5. Compute expected digest
    // expected_digest = H( H(0_size || TPM_CC_PolicySecret || nv_name) || policyRef )
    let nv_name = nv_name(&nv_pub);

    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_secret(nv_name.get_buffer(), &[]);

    assert_eq!(
        get_digest_rsp.policy_digest.get_buffer(),
        pol.policy_digest.as_slice(),
        "PolicySecret digest should match the expected digest computed with NV Index Name"
    );
}
