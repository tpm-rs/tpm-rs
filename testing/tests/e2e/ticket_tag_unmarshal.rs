//! Unmarshaling of the `tag` of the `TPMT_TK_AUTH` ticket of TPM2_PolicyTicket (for the
//! `TPMT_TK_VERIFIED` of TPM2_PolicyAuthorize see `policy_authorize.rs`): a structure tag of
//! another ticket type is `TPM_RC_TAG`.

use crate::_common::{ST_NO_SESSIONS, build_raw_cmd, rc_p, start_policy, transact_rc_of};
use testing::tpm::Tpm;
use tpm2::errors::TpmRc;
use tpm2::{Handle, TpmSe};

const CC_POLICY_TICKET: u32 = 0x172;

/// Sends a TPM2_PolicyTicket for the policy session `session` with empty `timeout`, `cpHashA`
/// and `policyRef`, the Name of `TPM_RH_OWNER` as `authName` and a ticket with the structure tag
/// `tag`, hierarchy `TPM_RH_NULL` and an empty digest; returns the response code.
fn policy_ticket_with_ticket_tag(tpm: &mut Tpm, session: Handle, tag: u16) -> u32 {
    let mut params = vec![0, 0, 0, 0, 0, 0, 0, 4];
    params.extend_from_slice(&Handle::RH_OWNER.0.to_be_bytes());
    params.extend_from_slice(&tag.to_be_bytes());
    params.extend_from_slice(&Handle::RH_NULL.0.to_be_bytes());
    params.extend_from_slice(&[0, 0]);
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_POLICY_TICKET,
        &[session.0],
        None,
        &params,
    );
    transact_rc_of(tpm, &cmd)
}

/// A `TPMT_TK_AUTH` with the tag of a verification ticket (`TPM_ST_VERIFIED`) is
/// `TPM_RC_TAG` on the ticket parameter.
///
/// TPM 2.0 Part 2, `TPMT_TK_AUTH`: "tag | `TPM_ST_AUTH_SIGNED`, `TPM_ST_AUTH_SECRET` | ticket
/// structure tag | `#TPM_RC_TAG`".
#[test]
fn auth_ticket_with_verified_tag_is_tag_error() {
    let mut tpm = Tpm::new();
    let (session, _) = start_policy(&mut tpm, TpmSe::Policy);
    assert_eq!(
        policy_ticket_with_ticket_tag(&mut tpm, session, 0x8022),
        rc_p(TpmRc::TAG, 5)
    );
}
