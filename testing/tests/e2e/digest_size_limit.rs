//! Size limit of `TPM2B_DIGEST` and its aliases (`TPM2B_NONCE`, `TPM2B_AUTH`): a size larger
//! than the largest digest of the TPM's hash algorithms is `TPM_RC_SIZE` before the buffer is
//! read.

use crate::_common::{
    ST_NO_SESSIONS, ST_SESSIONS, build_raw_cmd, rc_p, rc_s, start_policy, transact_rc_of,
};
use testing::tpm::Tpm;
use tpm2::errors::TpmRc;
use tpm2::{Handle, TpmSe};

/// The largest digest of the TPM's hash algorithms (`sizeof(TPMU_HA)`): SHA-512.
const LARGEST_DIGEST: usize = 64;

const CC_POLICY_TICKET: u32 = 0x172;
const CC_PCR_RESET: u32 = 0x13D;

/// A `TPM2B_NONCE` parameter one byte larger than the largest digest is `TPM_RC_SIZE` on that
/// parameter, even though the command has fewer bytes left than the size announces; a size equal
/// to the largest digest is read and fails with `TPM_RC_INSUFFICIENT`.
///
/// TPM 2.0 Part 2, `TPM2B_DIGEST`: "size | size in octets of the buffer field; may be 0" and
/// "buffer[size]{:sizeof(TPMU_HA)} | the buffer area that can be no larger than a digest", with
/// `#TPM_RC_SIZE` for a size outside the bound, checked before the buffer is unmarshaled.
#[test]
fn nonce_parameter_larger_than_largest_digest_is_size_error() {
    let mut tpm = Tpm::new();
    for (size, expected) in [
        (LARGEST_DIGEST + 1, rc_p(TpmRc::SIZE, 3)),
        (LARGEST_DIGEST, rc_p(TpmRc::INSUFFICIENT, 3)),
    ] {
        let (session, _) = start_policy(&mut tpm, TpmSe::Policy);
        // TPM2_PolicyTicket: empty timeout and cpHashA, then policyRef announcing `size` bytes
        // followed by only 10.
        let mut params = vec![0, 0, 0, 0];
        params.extend_from_slice(&(size as u16).to_be_bytes());
        params.extend_from_slice(&[0; 10]);
        let cmd = build_raw_cmd(
            ST_NO_SESSIONS,
            CC_POLICY_TICKET,
            &[session.0],
            None,
            &params,
        );
        assert_eq!(
            transact_rc_of(&mut tpm, &cmd),
            expected,
            "policyRef size {size}"
        );
    }
}

/// The `hmac` (`TPM2B_AUTH`) of a password session one byte larger than the largest digest is
/// `TPM_RC_SIZE` on that session.
///
/// TPM 2.0 Part 2, `TPMS_AUTH_COMMAND`: "hmac | `TPM2B_AUTH` | either an HMAC, a password, or an
/// EmptyAuth", and `TPM2B_AUTH` is a `TPM2B_DIGEST`, whose buffer "can be no larger than a
/// digest" (`#TPM_RC_SIZE`).
#[test]
fn session_hmac_larger_than_largest_digest_is_size_error() {
    let mut tpm = Tpm::new();
    let mut session = Vec::new();
    session.extend_from_slice(&Handle::RS_PW.0.to_be_bytes());
    session.extend_from_slice(&[0, 0, 0x01]);
    session.extend_from_slice(&((LARGEST_DIGEST + 1) as u16).to_be_bytes());
    session.extend_from_slice(&[0x5A; LARGEST_DIGEST + 1]);
    // TPM2_PCR_Reset of PCR 16.
    let cmd = build_raw_cmd(ST_SESSIONS, CC_PCR_RESET, &[16], Some(&session), &[]);
    assert_eq!(transact_rc_of(&mut tpm, &cmd), rc_s(TpmRc::SIZE, 1));
}
