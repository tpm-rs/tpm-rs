//! Bound sessions: bind entity recognition, SHA-512 names and evicting a bound entity.

use crate::_common::{
    ATTR_CONTINUE, AuthEntry, RC_SUCCESS, create_primary, create_primary_obj, create_sealed,
    ecc_signing_template, execute_with_hmac_sessions, execute_with_password_sessions,
    get_rsa_srk_template, hmac_entry, object_name, sealed_template_with_policy,
    send_rc_with_auth_entries, start_auth_session, start_bound, start_salted,
    unseal_with_auth_entry,
};
use testing::tpm::Tpm;
use tpm2::commands::{
    CreatePrimary, EvictControl, FlushContext, HierarchyChangeAuth, PolicySecret, StartAuthSession,
};
use tpm2::{
    Handle, Tpm2bAuth, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bNonce, Tpm2bSensitiveData, TpmCc,
    TpmSe, TpmaObject, TpmiAlgHash, TpmlPcrSelection, TpmsSensitiveCreate, *,
};

/// A bound HMAC session recognizes its bind entity by its bind value, whatever handle the
/// entity is referenced by, and SHA-512 Names are supported (C `IsSessionBindEntity()`).
#[test]
fn bound_session_matches_entity_by_bind_value() {
    // SHA-512 Name.
    {
        let mut sim = Tpm::new();
        let mut public =
            sealed_template_with_policy(TpmaObject::USER_WITH_AUTH | TpmaObject::NO_DA, &[]);
        public.name_alg = Some(TpmiAlgHash::Sha512);
        let item = create_primary_obj(&mut sim, public, b"key", b"data");
        let session = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle(item),
            b"key",
            TpmSe::HMAC,
            None,
            TpmiAlgHash::Sha256,
        )
        .unwrap();
        let names = [object_name(&mut sim, item)];
        // Bound to the entity: the authValue is not part of the HMAC key.
        let auth = hmac_entry(&session, TpmCc::Unseal, &names, &[], &[], ATTR_CONTINUE);
        assert_eq!(unseal_with_auth_entry(&mut sim, item, auth), RC_SUCCESS);
    }

    // Same entity under another handle (persistent copy of the bind object).
    {
        let mut sim = Tpm::new();
        let item = create_sealed(
            &mut sim,
            TpmaObject::USER_WITH_AUTH | TpmaObject::NO_DA,
            b"key",
            &[],
        );
        let session = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle(item),
            b"key",
            TpmSe::HMAC,
            None,
            TpmiAlgHash::Sha256,
        )
        .unwrap();
        let persistent: u32 = 0x8100_0100;
        let code = send_rc_with_auth_entries(
            &mut sim,
            TpmCc::EvictControl,
            &[Handle::RH_OWNER.0, item],
            &[AuthEntry::pw(&[])],
            &persistent.to_be_bytes(),
        );
        assert_eq!(code, RC_SUCCESS, "EvictControl");
        let names = [object_name(&mut sim, persistent)];
        let auth = hmac_entry(&session, TpmCc::Unseal, &names, &[], &[], ATTR_CONTINUE);
        assert_eq!(
            unseal_with_auth_entry(&mut sim, persistent, auth),
            RC_SUCCESS
        );
    }
}

/// Persist a primary, bind a policy session to it, PolicySecret, evict it and flush the session.
#[test]
fn persist_bind_policy_session_and_evict() {
    let mut sim = Tpm::new();

    // 1. CreatePrimary under Owner hierarchy
    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);
    let in_public = tpm2::Tpm2b(get_rsa_srk_template());
    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_rsp = execute_with_password_sessions(&mut sim, &create_cmd, 1, &[]).unwrap();
    let transient_handle = create_rsp.object_handle;

    // 2. Persist the primary object using EvictControl
    let persistent_handle = Handle(0x81000005);
    let evict_cmd = EvictControl {
        auth: Handle::RH_OWNER,
        object_handle: transient_handle,
        persistent_handle,
    };
    execute_with_password_sessions(&mut sim, &evict_cmd, 1, &[]).unwrap();

    // 3. StartAuthSession bound to the persistent object
    let start_cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: persistent_handle,
        nonce_caller: Tpm2bNonce::from_bytes(&[1u8; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_rsp = execute_with_password_sessions(&mut sim, &start_cmd, 0, &[]).unwrap();
    let session_handle = start_rsp.session_handle;

    // Verify session handle transitions cleanly and is valid
    assert_ne!(session_handle, Handle::RH_NULL);

    // 4. PolicySecret authorization loop against the session
    let policy_cmd = PolicySecret {
        auth_handle: Handle::RH_OWNER,
        policy_session: session_handle,
        nonce_tpm: Tpm2bNonce::default(),
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: 0,
    };
    execute_with_password_sessions(&mut sim, &policy_cmd, 1, &[]).unwrap();

    // 5. Evict the persistent object back to transient/unloaded state
    let evict_cmd2 = EvictControl {
        auth: Handle::RH_OWNER,
        object_handle: persistent_handle,
        persistent_handle,
    };
    execute_with_password_sessions(&mut sim, &evict_cmd2, 1, &[]).unwrap();

    // 6. FlushContext on the policy session
    let flush_cmd = FlushContext {
        flush_handle: session_handle,
    };
    let flush_res = execute_with_password_sessions(&mut sim, &flush_cmd, 0, &[]);
    assert!(
        flush_res.is_ok(),
        "FlushContext on active policy session failed unexpectedly: {:?}",
        flush_res
    );
}

/// A salted session bound to a SHA-512-named entity starts without panicking.
#[test]
fn salted_session_bound_to_sha512_entity() {
    // StartAuthSession side of the SHA-512 bind panic (the engine side is fix-auth's).
    let mut sim = Tpm::new();
    let (key, _) = create_primary(&mut sim, ecc_signing_template(TpmiAlgHash::Sha512));
    start_salted(&mut sim, Handle::RH_NULL, key, &[]).expect("bind to a SHA-512 object");
}

/// Binding to an entity with a SHA-512 Name does not panic and the session authorizes unrelated entities.
#[test]
fn sha512_named_bind_entity() {
    // Part 1 (StartAuthSession side): binding to an entity with a 66-byte SHA-512 Name must not
    // panic. Parts 2-3 are engine-side (fix-auth / fix-sessions).
    let mut sim = Tpm::new();
    let (key, name) = create_primary(&mut sim, ecc_signing_template(TpmiAlgHash::Sha512));
    assert_eq!(name.len(), 66);
    let mut session = start_bound(&mut sim, key, &[], TpmSe::HMAC);
    session
        .attributes
        .insert(tpm2::TpmaSession::CONTINUE_SESSION);
    // The session works for an unrelated (unbound) entity.
    execute_with_hmac_sessions(
        &mut sim,
        &HierarchyChangeAuth {
            auth_handle: Handle::RH_OWNER,
            new_auth: Tpm2bAuth::default(),
        },
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
}
