//! Password authorization: empty passwords, prefixes and trailing zeros in authValues.

use crate::_common::{send_rc_with_auth_entries as rc, unseal_with_auth_entry as unseal, *};
use tpm2::commands::CreatePrimary;
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bSensitiveData, TpmCc,
    TpmEccCurve, TpmaObject, TpmiAlgHash, TpmsEccParms, TpmsEccPoint, TpmsSensitiveCreate,
    TpmtEccScheme, TpmtPublic,
};
use tpm2_simulator::create_simulator;

/// CreatePrimary under the owner hierarchy succeeds with an empty password session.
#[test]
fn create_primary_with_empty_owner_password() {
    let mut sim = create_simulator!();
    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            ecc_parms,
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_rsp = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();
    flush_context(&mut sim, create_rsp.object_handle).unwrap();
}

/// Password authorization needs the full authValue: a prefix fails (BAD_AUTH / AUTH_FAIL), trailing zeros are ignored
///
/// Password authorization requires the complete authValue: a prefix of it must fail
/// (C `CheckPWAuthSession()` compares with `MemoryEqual2B`, i.e. equal length and contents).
#[test]
fn password_auth_rejects_auth_value_prefix() {
    let mut sim = create_simulator!();
    let item = create_sealed(&mut sim, TpmaObject::USER_WITH_AUTH, b"secret", &[]);
    set_owner_auth(&mut sim, b"secret");

    // ownerAuth is DA-exempt: TPM_RC_BAD_AUTH + RC_S1.
    for prefix in [&b"s"[..], b"secre"] {
        let code = rc(
            &mut sim,
            TpmCc::HierarchyChangeAuth,
            &[Handle::RH_OWNER.0],
            &[AuthEntry::pw(prefix)],
            &tpm2b_params(b"other"),
        );
        assert_eq!(code, RC_BAD_AUTH_S1, "prefix {prefix:?} must be rejected");
    }

    // A DA-protected object: TPM_RC_AUTH_FAIL + RC_S1.
    assert_eq!(
        unseal(&mut sim, item, AuthEntry::pw(b"sec")),
        RC_AUTH_FAIL_S1
    );

    // Trailing zeros are still ignored, and the full value works.
    assert_eq!(
        unseal(&mut sim, item, AuthEntry::pw(b"secret\0\0")),
        RC_SUCCESS
    );
    let code = rc(
        &mut sim,
        TpmCc::HierarchyChangeAuth,
        &[Handle::RH_OWNER.0],
        &[AuthEntry::pw(b"secret")],
        &tpm2b_params(b""),
    );
    assert_eq!(code, RC_SUCCESS);
}

// 13. Password trailing zero input succeeds authorization
/// An owner auth set with trailing zeros authorizes with the trimmed password.
#[test]
fn trailing_zero_owner_auth_matches_trimmed() {
    use tpm2::commands::HierarchyChangeAuth;

    let mut sim = create_simulator!();

    // 1. Change Owner Auth from empty to "hello" (with trailing zeros, e.g. "hello\0\0")
    let cmd1 = HierarchyChangeAuth {
        auth_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::from_bytes(b"hello\0\0").unwrap(),
    };
    let res1 = execute_with_password_sessions(&mut sim, &cmd1, 1, &[]);
    assert!(
        res1.is_ok(),
        "Setting owner auth to hello\\0\\0 should succeed: {:?}",
        res1
    );

    // 2. Perform another auth check using "hello" (without trailing zeros)
    // We change the owner auth back to empty
    let cmd2 = HierarchyChangeAuth {
        auth_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::default(),
    };
    let res2 = execute_with_password_sessions(&mut sim, &cmd2, 1, b"hello");
    assert!(
        res2.is_ok(),
        "Authorizing hello\\0\\0 auth using hello should succeed: {:?}",
        res2
    );
}
