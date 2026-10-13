//! HMAC session authorization: one session per handle, nonces and HMAC computation.

use crate::_common::{
    AES128_CFB, ATTR_CONTINUE, ATTR_ENCRYPT, EMPTY_POLICY, RC_BAD_AUTH_S1, RC_SUCCESS,
    certify_cmd_and_handles, create_primary_key, create_sealed, execute_with_hmac_sessions,
    execute_with_hmac_sessions_mismatch_nonce, handle_name, hmac_entry, raw_entry,
    send_rc_with_auth_entries, set_owner_auth, sign_cmd_and_handles, start_auth_session,
    start_session_of_type, tpm2b_params, unseal_with_auth_entry,
};
use testing::tpm::Tpm;
use tpm2::{Handle, Tpm2bNonce, TpmCc, TpmSe, TpmaObject, TpmiAlgHash};

/// TPM2_Certify is authorized with one HMAC session per authorization handle.
#[test]
fn certify_authorized_by_object_and_sign_sessions() {
    let mut sim = Tpm::new();
    let object_handle = create_primary_key(&mut sim);
    let sess1 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let sess2 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    // ReadPublic has no auth handle, and C requires such sessions to be
    // audit/encrypt/decrypt (SessionProcess.c:1709-1712), so authorize the key
    // instead to keep the HMAC session an authorization session.
    let auth_cmd = certify_cmd_and_handles(object_handle);
    let mut sessions = [sess1, sess2];
    execute_with_hmac_sessions(&mut sim, &auth_cmd, &[], &mut sessions, &[&[], &[]]).unwrap();
}

/// An HMAC computed over a different caller nonce than sent fails with TPM_RC_BAD_AUTH + S1.
#[test]
fn mismatched_nonce_caller_returns_bad_auth() {
    let mut sim = Tpm::new();
    let object_handle = create_primary_key(&mut sim);
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    // ReadPublic has no auth handle, and C requires such sessions to be
    // audit/encrypt/decrypt (SessionProcess.c:1709-1712), so authorize the key
    // instead to keep the HMAC session an authorization session.
    let auth_cmd = sign_cmd_and_handles(object_handle);
    let res =
        execute_with_hmac_sessions_mismatch_nonce(&mut sim, &auth_cmd, &[], &mut [session], &[&[]]);
    assert_eq!(res, Err(2446));
}

/// HMAC tags are compared exactly: neither trailing zero padding nor an all-zero tag with an
/// empty HMAC key is accepted (C `CheckSessionHMAC()` uses `MemoryEqual2B`).
#[test]
fn session_hmac_compared_exactly() {
    let mut sim = Tpm::new();
    let item = create_sealed(
        &mut sim,
        TpmaObject::USER_WITH_AUTH | TpmaObject::NO_DA,
        b"",
        &EMPTY_POLICY,
    );
    set_owner_auth(&mut sim, b"owner");
    let names = [handle_name(Handle::RH_OWNER.0)];
    let params = tpm2b_params(b"owner");

    // A valid HMAC padded with a zero byte.
    let session = start_session_of_type(&mut sim, TpmSe::HMAC);
    let mut auth = hmac_entry(
        &session,
        TpmCc::HierarchyChangeAuth,
        &names,
        &params,
        b"owner",
        ATTR_CONTINUE,
    );
    auth.hmac.push(0);
    let code = send_rc_with_auth_entries(
        &mut sim,
        TpmCc::HierarchyChangeAuth,
        &[Handle::RH_OWNER.0],
        &[auth],
        &params,
    );
    assert_eq!(code, RC_BAD_AUTH_S1);

    // The same HMAC without padding is accepted (the session is still usable: a failed
    // authorization does not consume the nonce).
    let auth = hmac_entry(
        &session,
        TpmCc::HierarchyChangeAuth,
        &names,
        &params,
        b"owner",
        ATTR_CONTINUE,
    );
    let code = send_rc_with_auth_entries(
        &mut sim,
        TpmCc::HierarchyChangeAuth,
        &[Handle::RH_OWNER.0],
        &[auth],
        &params,
    );
    assert_eq!(code, RC_SUCCESS);

    // Empty HMAC key (policy session without PolicyAuthValue): a non-empty all-zero authHMAC
    // is not an empty one.
    let policy = start_session_of_type(&mut sim, TpmSe::Policy);
    assert_eq!(
        unseal_with_auth_entry(&mut sim, item, raw_entry(&policy, ATTR_CONTINUE, &[0])),
        RC_BAD_AUTH_S1
    );
    assert_eq!(
        unseal_with_auth_entry(&mut sim, item, raw_entry(&policy, ATTR_CONTINUE, &[])),
        RC_SUCCESS
    );
}

/// An empty authHMAC is accepted for any session type when the HMAC key is empty (C
/// `ComputeCommandHMAC()`), and a `TPM2_PolicyPassword` session that authorizes no handle is
/// verified by its HMAC, not as a password.
#[test]
fn session_hmac_empty_accepted_with_empty_key() {
    let mut sim = Tpm::new();

    // Unbound, unsalted HMAC session authorizing an entity with an empty authValue.
    let session = start_session_of_type(&mut sim, TpmSe::HMAC);
    let code = send_rc_with_auth_entries(
        &mut sim,
        TpmCc::HierarchyChangeAuth,
        &[Handle::RH_OWNER.0],
        &[raw_entry(&session, ATTR_CONTINUE, &[])],
        &tpm2b_params(b""),
    );
    assert_eq!(code, RC_SUCCESS);

    // A PolicyPassword policy session used only for response encryption.
    let policy = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        Some(AES128_CFB),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let code = send_rc_with_auth_entries(
        &mut sim,
        TpmCc::PolicyPassword,
        &[policy.session_handle.0],
        &[],
        &[],
    );
    assert_eq!(code, RC_SUCCESS);
    let params = 8u16.to_be_bytes();
    let auth = hmac_entry(
        &policy,
        TpmCc::GetRandom,
        &[],
        &params,
        &[],
        ATTR_CONTINUE | ATTR_ENCRYPT,
    );
    assert_eq!(
        send_rc_with_auth_entries(&mut sim, TpmCc::GetRandom, &[], &[auth], &params),
        RC_SUCCESS
    );
}

/// An HMAC keyed with a wrong entity auth value fails with TPM_RC_BAD_AUTH + S1.
#[test]
fn wrong_auth_value_returns_bad_auth() {
    let mut sim = Tpm::new();
    let object_handle = create_primary_key(&mut sim);
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    // ReadPublic has no auth handle, and C requires such sessions to be
    // audit/encrypt/decrypt (SessionProcess.c:1709-1712), so authorize the key
    // instead to keep the HMAC session an authorization session.
    let auth_cmd = sign_cmd_and_handles(object_handle);
    let err = match execute_with_hmac_sessions(
        &mut sim,
        &auth_cmd,
        &[],
        &mut [session],
        &[b"wrong_auth_val"],
    ) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    assert_eq!(err, 2446);
}

/// An HMAC whose cpHash uses a wrong handle name fails with TPM_RC_BAD_AUTH + S1.
#[test]
fn wrong_handle_name_in_cphash_returns_bad_auth() {
    let mut sim = Tpm::new();
    let object_handle = create_primary_key(&mut sim);
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    // ReadPublic has no auth handle, and C requires such sessions to be
    // audit/encrypt/decrypt (SessionProcess.c:1709-1712), so authorize the key
    // instead to keep the HMAC session an authorization session.
    let auth_cmd = sign_cmd_and_handles(object_handle);
    let err = match execute_with_hmac_sessions(
        &mut sim,
        &auth_cmd,
        &[b"bad_handle_name"],
        &mut [session],
        &[&[]],
    ) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    assert_eq!(err, 2446);
}

/// An HMAC computed with an empty TPM nonce fails with TPM_RC_BAD_AUTH + S1.
#[test]
fn wrong_nonce_tpm_returns_bad_auth() {
    let mut sim = Tpm::new();
    let object_handle = create_primary_key(&mut sim);
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.nonce_tpm = Tpm2bNonce::default(); // mismatch
    // ReadPublic has no auth handle, and C requires such sessions to be
    // audit/encrypt/decrypt (SessionProcess.c:1709-1712), so authorize the key
    // instead to keep the HMAC session an authorization session.
    let auth_cmd = sign_cmd_and_handles(object_handle);
    let err = match execute_with_hmac_sessions(&mut sim, &auth_cmd, &[], &mut [session], &[&[]]) {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    assert_eq!(err, 2446);
}

/// An HMAC computed with a corrupted session key fails with TPM_RC_BAD_AUTH + S1.
#[test]
fn wrong_session_key_returns_bad_auth() {
    let mut sim = Tpm::new();
    let object_handle = create_primary_key(&mut sim);
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.session_key = vec![1u8; 32]; // corrupt session key
    // ReadPublic has no auth handle, and C requires such sessions to be
    // audit/encrypt/decrypt (SessionProcess.c:1709-1712), so authorize the key
    // instead to keep the HMAC session an authorization session.
    let auth_cmd = sign_cmd_and_handles(object_handle);
    let res = execute_with_hmac_sessions(&mut sim, &auth_cmd, &[], &mut [session], &[&[]]);
    assert_eq!(res, Err(2446));
}
