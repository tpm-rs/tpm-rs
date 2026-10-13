//! TPM2_PolicyPassword: password-in-HMAC authorization, response HMACs and check order.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::{Create, CreatePrimary, Load, PolicyPassword};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2b, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bPublicKeyRsa,
    Tpm2bSensitiveData, TpmCc, TpmSe, TpmaObject, TpmiAlgHash, TpmiRsaKeyBits, TpmlPcrSelection,
    TpmsRsaParms, TpmsSensitiveCreate, TpmtPublic,
};

/// With PolicyCpHash + PolicyPassword, the cpHash mismatch is reported before the password check.
///
/// verify-session-hmacs-strips-trailing-zeros-on-hmac-and-checks-auth-before-cphash (part 2) and
/// policy-password-non-empty-response-hmac-and-policy-check-order (part 2), handed over by
/// fix-auth: cpHash is checked before the password.
#[test]
fn cphash_checked_before_password() {
    let mut sim = new_sim();
    let cp_hash = [0x33u8; 32];
    let mut cp_hash_param = vec![0x00, 0x20];
    cp_hash_param.extend_from_slice(&cp_hash);
    let digest = trial_digest(&mut sim, |sim, t| {
        assert_eq!(policy_cmd(sim, CC_POLICY_CP_HASH, t, &cp_hash_param), 0);
        assert_eq!(policy_cmd(sim, CC_POLICY_PASSWORD, t, &[]), 0);
    });
    set_owner_policy(&mut sim, &digest, &[]);
    let mut p = start_session(&mut sim, TpmSe::Policy, false);
    assert_eq!(
        policy_cmd(&mut sim, CC_POLICY_CP_HASH, p.handle, &cp_hash_param),
        0
    );
    assert_eq!(policy_cmd(&mut sim, CC_POLICY_PASSWORD, p.handle, &[]), 0);
    let rc = exec(
        &mut sim,
        CC_CREATE_PRIMARY,
        &[RH_OWNER],
        &mut [SessUse::policy_password(&mut p, b"wrong")],
        &create_primary_params(),
        1,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_POLICY_FAIL));
}

/// Sealed object with a PolicyPassword policy: unseal needs the cleartext authValue in the HMAC field (TPM_RC_BAD_AUTH otherwise)
#[test]
fn password_required_for_sealed_object() {
    // Compute expected policy digest after PolicyPassword:
    // SHA256(32 zero bytes || TPM_CC_PolicyAuthValue)
    let mut to_hash = Vec::new();
    to_hash.extend_from_slice(&[0u8; 32]);
    to_hash.extend_from_slice(&(TpmCc::PolicyAuthValue.code()).to_be_bytes());
    let expected_policy = hash_bytes(TpmiAlgHash::Sha256, &to_hash);

    let mut sim = Tpm::new();

    // 1. Create a primary storage parent under Owner hierarchy
    let parent_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM
            | TpmaObject::SENSITIVE_DATA_ORIGIN,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: Some(AES128_CFB),
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let cp_resp = execute_with_password_sessions(
        &mut sim,
        &CreatePrimary {
            primary_handle: Handle::RH_OWNER,
            in_sensitive: Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::default(),
                data: Tpm2bSensitiveData::default(),
            }),
            in_public: Tpm2b(parent_pub),
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        },
        1,
        &[],
    )
    .unwrap();
    let parent_handle = cp_resp.object_handle;

    // 2. Create a KeyedHash sealed data object under parent_handle
    let secret_data = b"secret_unsealed_data";
    let user_auth = b"secret_password";
    let item_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM,
        auth_policy: Tpm2bDigest::from_bytes(&expected_policy).unwrap(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
    };
    let create_resp = execute_with_password_sessions(
        &mut sim,
        &Create {
            parent_handle,
            in_sensitive: Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::from_bytes(user_auth).unwrap(),
                data: Tpm2bSensitiveData::from_bytes(secret_data).unwrap(),
            }),
            in_public: Tpm2b(item_pub),
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        },
        1,
        &[],
    )
    .unwrap();

    // 3. Load the sealed data object
    let load_resp = execute_with_password_sessions(
        &mut sim,
        &Load {
            parent_handle,
            in_private: create_resp.out_private,
            in_public: create_resp.out_public,
        },
        1,
        &[],
    )
    .unwrap();
    let item_handle = load_resp.object_handle;

    // Start a policy session
    let policy_session_handle =
        start_session_with_nonce(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256, &[1; 32]);

    // Execute PolicyPassword
    execute_with_password_sessions(
        &mut sim,
        &PolicyPassword {
            policy_session: policy_session_handle,
        },
        0,
        &[],
    )
    .unwrap();

    // Verify PolicyGetDigest matches expected_policy
    assert_eq!(
        policy_get_digest_checked(&mut sim, policy_session_handle),
        expected_policy
    );

    // Attempt unsealing using this policy session, but without satisfying
    // is_password_needed (empty password in the hmac field).
    let mut sess = Sess {
        handle: policy_session_handle.0,
        nonce_tpm: Vec::new(),
        session_key: Vec::new(),
    };
    const CC_UNSEAL: u32 = 0x15E;
    let res = exec(
        &mut sim,
        CC_UNSEAL,
        &[item_handle.0],
        &mut [SessUse::policy_password(&mut sess, b"").with_attrs(0)],
        &[],
        0,
    );
    // The sealed object is NO_DA (DA-exempt), so C IncrementLockout returns
    // TPM_RC_BAD_AUTH + S1 rather than AUTH_FAIL (SessionProcess.c:105-118).
    assert_eq!(res.rc, TpmRc::BAD_AUTH.with(Position::session(1)).get());

    // Now provide valid password auth along with policy session and verify success
    let res = exec(
        &mut sim,
        CC_UNSEAL,
        &[item_handle.0],
        &mut [SessUse::policy_password(&mut sess, user_auth).with_attrs(0)],
        &[],
        0,
    );
    assert_eq!(res.rc, 0);
    // outData is a TPM2B_SENSITIVE_DATA.
    assert_eq!(&res.params[2..], secret_data);
}

/// PolicyPassword sessions return an empty response HMAC even when the owner has a non-empty authValue.
///
/// policy-password-non-empty-response-hmac-and-policy-check-order (part 1)
#[test]
fn policy_password_response_hmac() {
    let mut sim = new_sim();
    // Give the owner a non-empty authValue so a response HMAC would have a non-empty key.
    let mut new_auth = vec![0x00, 0x02];
    new_auth.extend_from_slice(b"pw");
    let rc = exec(
        &mut sim,
        CC_HIERARCHY_CHANGE_AUTH,
        &[RH_OWNER],
        &mut [SessUse::pw(&[])],
        &new_auth,
        0,
    )
    .rc;
    assert_eq!(rc, 0);

    let digest = trial_digest(&mut sim, |sim, t| {
        assert_eq!(policy_cmd(sim, CC_POLICY_PASSWORD, t, &[]), 0);
    });
    set_owner_policy(&mut sim, &digest, b"pw");
    let mut p = start_session(&mut sim, TpmSe::Policy, false);
    assert_eq!(policy_cmd(&mut sim, CC_POLICY_PASSWORD, p.handle, &[]), 0);
    let r = exec(
        &mut sim,
        CC_SET_PRIMARY_POLICY,
        &[RH_OWNER],
        &mut [SessUse::policy_password(&mut p, b"pw")],
        &set_primary_policy_params(&digest),
        0,
    );
    assert_eq!(r.rc, 0);
    assert_eq!(r.session_hmacs, vec![Vec::<u8>::new()]);
}
