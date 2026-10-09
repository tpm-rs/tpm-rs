#![forbid(unsafe_code)]

use crate::test_utils::*;
use tpm2::commands::{
    CreatePrimary, CreatePrimaryHandles, NVDefineSpace, NVDefineSpaceHandles, PolicyGetDigest,
    PolicyGetDigestHandles, PolicyOR, PolicyORHandles, PolicySecret, PolicySecretHandles,
};
use tpm2::*;
use tpm2::{Handle, TpmSe};
use tpm2_simulator::create_simulator;

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

fn policy_or_expected(alg: TpmiAlgHash, digests: &[&[u8]]) -> Vec<u8> {
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
fn test_milestone3_integration_and_stress() {
    let mut sim = create_simulator!();

    // -------------------------------------------------------------
    // Step 1: Create ECC Endorsement Key (used for ECC KDFe salting)
    // -------------------------------------------------------------
    let ecc_ek = ecc_ek_template();
    let in_public = tpm2::Tpm2b(ecc_ek);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);
    let create_primary_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_primary_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_ENDORSEMENT,
    };
    let (cp_resp, cp_resp_handles) = execute_with_password_sessions(
        &mut sim,
        &create_primary_cmd,
        create_primary_handles,
        1,
        &[],
    )
    .unwrap();

    let ek_handle = cp_resp_handles.object_handle;
    let _ek_public_struct = cp_resp.out_public.0;

    // -------------------------------------------------------------
    // Step 2: Define an NV Index (used for PolicySecret name resolution)
    // -------------------------------------------------------------
    let nv_index_val = 0x01600099;
    let nv_pub = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE,
        auth_policy: Tpm2bDigest::default(),
        data_size: 32,
    };
    let public_info = tpm2::Tpm2b(nv_pub);
    let define_cmd = NVDefineSpace {
        public_info,
        auth: Tpm2bAuth::default(),
    };
    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &define_cmd, define_handles, 1, &[]).unwrap();

    // -------------------------------------------------------------
    // Step 3: Start a salted policy session using the ECC EK (ECC KDFe Salting)
    // -------------------------------------------------------------
    let mut rng = rand::rngs::OsRng;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    // Generate ephemeral key pair
    let eph_private = p256::SecretKey::random(&mut rng);
    let eph_public = eph_private.public_key();
    let eph_encoded = eph_public.to_encoded_point(false);
    let eph_xy = eph_encoded.as_bytes(); // starts with 0x04, length 65
    assert_eq!(eph_xy[0], 0x04);

    let eph_point = tpm2::TpmsEccPoint {
        x: tpm2::Tpm2bEccParameter::from_bytes(&eph_xy[1..33]).unwrap(),
        y: tpm2::Tpm2bEccParameter::from_bytes(&eph_xy[33..65]).unwrap(),
    };
    let mut enc_salt_bytes = [0u8; 1024];
    let len = marshal_to_slice(&eph_point, &mut enc_salt_bytes);
    let encrypted_salt = tpm2::Tpm2bEncryptedSecret::from_bytes(crate::test_utils::leak_bytes(
        &enc_salt_bytes[..len],
    ))
    .unwrap();

    // Start auth session command
    let nonce_caller = Tpm2bNonce::from_bytes(&[5u8; 32]).unwrap();
    let start_sess_cmd = tpm2::commands::StartAuthSession {
        nonce_caller,
        encrypted_salt,
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_sess_handles = tpm2::commands::StartAuthSessionHandles {
        tpm_key: ek_handle,
        bind: Handle::RH_NULL,
    };
    let (start_sess_resp, start_sess_resp_handles) =
        execute_with_password_sessions(&mut sim, &start_sess_cmd, start_sess_handles, 0, &[])
            .unwrap();

    let policy_session_handle = start_sess_resp_handles.session_handle;

    // -------------------------------------------------------------
    // Step 4: Execute PolicySecret with NV Index handle as auth_handle
    // -------------------------------------------------------------
    let policy_secret_cmd = PolicySecret {
        nonce_tpm: start_sess_resp.nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: 0,
    };
    let policy_secret_handles = PolicySecretHandles {
        auth_handle: Handle(nv_index_val),
        policy_session: policy_session_handle,
    };
    execute_with_password_sessions(&mut sim, &policy_secret_cmd, policy_secret_handles, 1, &[])
        .unwrap();

    // Get current policy digest after PolicySecret
    let get_digest_cmd = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: policy_session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest_cmd, get_digest_handles, 0, &[])
            .unwrap();

    // Calculate expected digest after PolicySecret
    let nv_name = nv_name(&nv_pub);
    let mut pol = PolicyCalculator::new(TpmiAlgHash::Sha256);
    pol.policy_secret(nv_name.get_buffer(), &[]);

    assert_eq!(
        get_digest_rsp.policy_digest.get_buffer(),
        pol.policy_digest.as_slice(),
        "PolicySecret digest should match after NV Index Name resolution"
    );

    // -------------------------------------------------------------
    // Step 5: Execute PolicyOR with concatenated hash updates
    // -------------------------------------------------------------
    let current_digest = get_digest_rsp.policy_digest;
    let dummy_digest = Tpm2bDigest::from_bytes(&[8u8; 32]).unwrap();

    let p_hash_list = TpmlDigest::from_slice(&[current_digest, dummy_digest]).unwrap();
    let policy_or_cmd = PolicyOR { p_hash_list };
    let policy_or_handles = PolicyORHandles {
        policy_session: policy_session_handle,
    };
    execute_with_password_sessions(&mut sim, &policy_or_cmd, policy_or_handles, 0, &[]).unwrap();

    // Get policy digest after PolicyOR
    let get_digest_handles_2 = PolicyGetDigestHandles {
        policy_session: policy_session_handle,
    };
    let (get_digest_rsp_2, _) =
        execute_with_password_sessions(&mut sim, &get_digest_cmd, get_digest_handles_2, 0, &[])
            .unwrap();

    let expected_or = policy_or_expected(
        TpmiAlgHash::Sha256,
        &[current_digest.get_buffer(), dummy_digest.get_buffer()],
    );

    assert_eq!(
        get_digest_rsp_2.policy_digest.get_buffer(),
        expected_or.as_slice(),
        "PolicyOR digest should match after concatenated hash updates"
    );
}

#[test]
fn test_milestone3_trial_session_bypass() {
    let mut sim = create_simulator!();

    // Start a Trial session
    let trial_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Trial,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // For a Trial session, PolicyOR should bypass size and matching checks.
    let digest1 = Tpm2bDigest::from_bytes(&[10u8; 32]).unwrap();
    let digest2 = Tpm2bDigest::from_bytes(&[20u8; 32]).unwrap();

    let p_hash_list = TpmlDigest::from_slice(&[digest1, digest2]).unwrap();
    let policy_or_cmd = PolicyOR { p_hash_list };
    let policy_or_handles = PolicyORHandles {
        policy_session: trial_session.session_handle,
    };
    // This should succeed even though the current policy digest is NOT in the list!
    let res = execute_with_password_sessions(&mut sim, &policy_or_cmd, policy_or_handles, 0, &[]);
    assert!(
        res.is_ok(),
        "PolicyOR on Trial session should bypass checks and succeed, got: {:?}",
        res.err()
    );

    // Get policy digest after PolicyOR
    let get_digest_cmd = PolicyGetDigest {};
    let get_digest_handles = PolicyGetDigestHandles {
        policy_session: trial_session.session_handle,
    };
    let (get_digest_rsp, _) =
        execute_with_password_sessions(&mut sim, &get_digest_cmd, get_digest_handles, 0, &[])
            .unwrap();

    let expected_or = policy_or_expected(
        TpmiAlgHash::Sha256,
        &[digest1.get_buffer(), digest2.get_buffer()],
    );

    assert_eq!(
        get_digest_rsp.policy_digest.get_buffer(),
        expected_or.as_slice(),
        "Trial session policy digest should be updated correctly"
    );
}
