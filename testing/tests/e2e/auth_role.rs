//! Authorization roles (USER, ADMIN, DUP): which session types may authorize each role and how
//! userWithAuth/adminWithPolicy apply.

use crate::_common::{
    ATTR_CONTINUE, AuthEntry, EMPTY_POLICY, NV_AUTHREAD, NV_AUTHWRITE, NV_NO_DA, RC_AUTH_TYPE,
    RC_AUTH_UNAVAILABLE, RC_SUCCESS, create_sealed, define_nv_raw, hmac_entry, nv_read_public_name,
    object_name, raw_entry, send_rc_with_auth_entries, set_owner_auth, start_session_of_type,
    tpm2b_params, unseal_with_auth_entry,
};
use tpm2::{Handle, TpmCc, TpmSe, TpmaObject};
use tpm2_simulator::create_simulator;

/// DUP role, ADMIN role on non-objects and PCRs with an authPolicy require a policy session (TPM_RC_AUTH_TYPE otherwise)
///
/// `IsPolicySessionRequired()`: the DUP role, the ADMIN role on non-objects, and PCRs with an
/// authPolicy require a policy session (`TPM_RC_AUTH_TYPE` otherwise).
#[test]
fn dup_admin_and_pcr_policy_roles_require_policy_session() {
    let mut sim = create_simulator!();

    // TPM2_Duplicate (DUP role) with a password session.
    let item = create_sealed(
        &mut sim,
        TpmaObject::USER_WITH_AUTH | TpmaObject::NO_DA,
        b"",
        &EMPTY_POLICY,
    );
    let mut dup_params = tpm2b_params(&[]);
    dup_params.extend_from_slice(&0x0010u16.to_be_bytes());
    let code = send_rc_with_auth_entries(
        &mut sim,
        TpmCc::Duplicate,
        &[item, Handle::RH_NULL.0],
        &[AuthEntry::pw(&[])],
        &dup_params,
    );
    assert_eq!(code, RC_AUTH_TYPE);

    // TPM2_NV_ChangeAuth (ADMIN role on an NV Index) with an HMAC session.
    let index = 0x0150_0020;
    define_nv_raw(
        &mut sim,
        index,
        NV_AUTHWRITE | NV_AUTHREAD | NV_NO_DA,
        b"nv",
        &EMPTY_POLICY,
        8,
    );
    let session = start_session_of_type(&mut sim, TpmSe::HMAC);
    let names = [nv_read_public_name(&mut sim, index)];
    let params = tpm2b_params(b"new");
    let auth = hmac_entry(
        &session,
        TpmCc::NVChangeAuth,
        &names,
        &params,
        b"nv",
        ATTR_CONTINUE,
    );
    assert_eq!(
        send_rc_with_auth_entries(&mut sim, TpmCc::NVChangeAuth, &[index], &[auth], &params),
        RC_AUTH_TYPE
    );

    // A PCR with an authPolicy.
    let mut set_policy = tpm2b_params(&EMPTY_POLICY);
    set_policy.extend_from_slice(&0x000Bu16.to_be_bytes());
    set_policy.extend_from_slice(&20u32.to_be_bytes());
    let code = send_rc_with_auth_entries(
        &mut sim,
        TpmCc::PCRSetAuthPolicy,
        &[Handle::RH_PLATFORM.0],
        &[AuthEntry::pw(&[])],
        &set_policy,
    );
    assert_eq!(code, RC_SUCCESS);
    let mut extend = Vec::new();
    extend.extend_from_slice(&1u32.to_be_bytes());
    extend.extend_from_slice(&0x000Bu16.to_be_bytes());
    extend.extend_from_slice(&[0xAB; 32]);
    let code = send_rc_with_auth_entries(
        &mut sim,
        TpmCc::PCRExtend,
        &[20],
        &[AuthEntry::pw(&[])],
        &extend,
    );
    assert_eq!(code, RC_AUTH_TYPE);
    // A PCR outside the policy group is unaffected.
    let code = send_rc_with_auth_entries(
        &mut sim,
        TpmCc::PCRExtend,
        &[16],
        &[AuthEntry::pw(&[])],
        &extend,
    );
    assert_eq!(code, RC_SUCCESS);

    // TPM2_HierarchyChangeAuth is a USER role command: a password session is fine.
    set_owner_auth(&mut sim, b"x");
}

/// USER-role password/HMAC auth of an object with userWithAuth clear fails with TPM_RC_AUTH_UNAVAILABLE; its policy still works
///
/// USER role authorization of an object with `userWithAuth` clear by a password or HMAC
/// session: `TPM_RC_AUTH_UNAVAILABLE` (C `IsAuthValueAvailable()`), not `TPM_RC_AUTH_TYPE`.
#[test]
fn user_role_without_user_with_auth_is_auth_unavailable() {
    let mut sim = create_simulator!();
    let item = create_sealed(&mut sim, TpmaObject::NO_DA, b"a", &EMPTY_POLICY);
    assert_eq!(
        unseal_with_auth_entry(&mut sim, item, AuthEntry::pw(b"a")),
        RC_AUTH_UNAVAILABLE
    );

    let session = start_session_of_type(&mut sim, TpmSe::HMAC);
    let names = [object_name(&mut sim, item)];
    let auth = hmac_entry(&session, TpmCc::Unseal, &names, &[], b"a", ATTR_CONTINUE);
    assert_eq!(
        unseal_with_auth_entry(&mut sim, item, auth),
        RC_AUTH_UNAVAILABLE
    );

    // The policy is still usable.
    let policy = start_session_of_type(&mut sim, TpmSe::Policy);
    assert_eq!(
        unseal_with_auth_entry(&mut sim, item, raw_entry(&policy, 0, &[])),
        RC_SUCCESS
    );
}
