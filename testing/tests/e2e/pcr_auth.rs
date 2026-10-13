//! TPM2_PCR_SetAuthPolicy and TPM2_PCR_SetAuthValue: PCR groups and authorization of PCR changes.

use crate::_common::{mssim_rc_of as rc_of, rc_at_locality as rc_at, *};
use tpm2::errors::TpmRc;
use tpm2::*;
use tpm2_simulator::create_simulator;

/// PCR_SetAuthPolicy parameter checks; the PCR policy authorizes PCR 20 extends until ChangePPS clears it.
///
/// `TPM2_PCR_SetAuthPolicy` parameter checks, and `TPM2_ChangePPS` clearing
/// the PCR policy.
///
/// The PCR policy is observed through authorization: the policy is set to the
/// digest of `TPM2_PolicyPassword`, so a policy session that ran
/// `TPM2_PolicyPassword` can authorize `TPM2_PCR_Extend` of PCR 20 until
/// `TPM2_ChangePPS` clears the policy.
#[test]
fn set_auth_policy_cleared_by_change_pps() {
    let mut sim = create_simulator!();

    // 1. Attempt TPM2_PCR_SetAuthPolicy with mismatched digest size -> should fail with TPM_RC_SIZE (P1)
    let set_policy_bad_size = hx(concat!(
        "8002",         // TPM_ST_SESSIONS
        "00000027",     // size (39 bytes)
        "0000012c",     // TPM2_PCR_SetAuthPolicy
        "4000000c",     // authHandle: TPM_RH_PLATFORM
        "00000009",     // authSize: 9 bytes
        "40000009",     // TPM_RS_PW
        "0000",         // nonce: empty
        "01",           // attributes: continueSession
        "0000",         // hmac: empty
        "000411223344", // authPolicy: 4 bytes (invalid for SHA256)
        "000b",         // hashAlg: SHA256 (requires 32 bytes)
        "00000014",     // pcrNum: PCR 20
    ));
    assert_eq!(
        rc_at(&mut sim, 0, &set_policy_bad_size),
        0x000001D5,
        "Expected TPM_RC_SIZE + P1 for invalid policy digest size"
    );

    // 2. Attempt TPM2_PCR_SetAuthPolicy on PCR 0 (not in policy group 20-22) -> should fail with TPM_RC_VALUE (P3)
    let set_policy_pcr0 = hx(concat!(
        "8002",     // TPM_ST_SESSIONS
        "00000043", // size (67 bytes)
        "0000012c", // TPM2_PCR_SetAuthPolicy
        "4000000c", // authHandle: TPM_RH_PLATFORM
        "00000009", // authSize: 9 bytes
        "40000009", // TPM_RS_PW
        "0000",     // nonce: empty
        "01",       // attributes: continueSession
        "0000",     // hmac: empty
        "0020",     // authPolicy size: 32 bytes
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "000b",     // hashAlg: SHA256
        "00000000", // pcrNum: PCR 0
    ));
    assert_eq!(
        rc_at(&mut sim, 0, &set_policy_pcr0),
        0x000003C4,
        "Expected TPM_RC_VALUE + P3 for PCR 0"
    );

    // Before any policy is set, PCR 20 cannot be authorized with a policy session.
    let session = policy_password_session(&mut sim);
    assert_ne!(
        rc_at(&mut sim, 2, &pcr20_extend_with_policy_session(session)),
        0,
        "PCR 20 has no policy yet"
    );
    flush_context(&mut sim, session).unwrap();

    // 3. Execute valid TPM2_PCR_SetAuthPolicy on PCR 20 -> should succeed
    // authPolicy = SHA256(0^32 || TPM_CC_PolicyAuthValue), the PolicyPassword digest.
    let mut state = tpm2::crypto::HashStream::new(CLIENT_CRYPTO, TpmiAlgHash::Sha256).unwrap();
    state.update(&[0u8; 32]).unwrap();
    state
        .update(&TpmCc::PolicyAuthValue.code().to_be_bytes())
        .unwrap();
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let policy = state.finalize(&mut out).unwrap().digest().to_vec();
    let mut set_policy_ok = hx(concat!(
        "8002",     // TPM_ST_SESSIONS
        "00000043", // size (67 bytes)
        "0000012c", // TPM2_PCR_SetAuthPolicy
        "4000000c", // authHandle: TPM_RH_PLATFORM
        "00000009", // authSize: 9 bytes
        "40000009", // TPM_RS_PW
        "0000",     // nonce: empty
        "01",       // attributes: continueSession
        "0000",     // hmac: empty
        "0020",     // authPolicy size: 32 bytes
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "000b",     // hashAlg: SHA256
        "00000014", // pcrNum: PCR 20
    ));
    set_policy_ok[29..61].copy_from_slice(&policy);
    assert_eq!(rc_at(&mut sim, 0, &set_policy_ok), 0);

    // The PCR policy is now in effect.
    let session = policy_password_session(&mut sim);
    assert_eq!(
        rc_at(&mut sim, 2, &pcr20_extend_with_policy_session(session)),
        0,
        "PCR 20 extend authorized by its policy should succeed"
    );
    flush_context(&mut sim, session).unwrap();

    // 4. Execute TPM2_ChangePPS -> should clear the PCR policy
    let change_pps = hx(concat!(
        "8002",     // TPM_ST_SESSIONS
        "0000001b", // size (27 bytes)
        "00000125", // TPM2_ChangePPS
        "4000000c", // authHandle: TPM_RH_PLATFORM
        "00000009", // authSize: 9 bytes
        "40000009", // TPM_RS_PW
        "0000",     // nonce: empty
        "01",       // attributes: continueSession
        "0000",     // hmac: empty
    ));
    assert_eq!(rc_at(&mut sim, 0, &change_pps), 0);

    let session = policy_password_session(&mut sim);
    assert_ne!(
        rc_at(&mut sim, 2, &pcr20_extend_with_policy_session(session)),
        0,
        "ChangePPS must clear the PCR policy"
    );
}

/// PCR_SetAuthPolicy checks NV availability; PCR_SetAuthValue rejects PCRs above PCR_LAST with VALUE + H1.
///
/// `TPM2_PCR_SetAuthPolicy` checks NV availability; `TPM2_PCR_SetAuthValue` rejects a PCR handle
/// above `PCR_LAST` with `TPM_RC_VALUE + RC_H1`.
#[test]
fn set_auth_policy_nv_and_set_auth_value_range() {
    let mut sim = create_simulator!();

    let mut params = 32u16.to_be_bytes().to_vec();
    params.extend_from_slice(&[0x33; 32]);
    params.extend_from_slice(&ALG_SHA256.to_be_bytes());
    params.extend_from_slice(&21u32.to_be_bytes());
    let cmd = build_pw_cmd(CC_PCR_SET_AUTH_POLICY, &[Handle::RH_PLATFORM.0], 1, &params);
    nv_off(&mut sim);
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::NV_UNAVAILABLE.get());
    nv_on(&mut sim);
    assert_eq!(rc_of(&mut sim, &cmd), 0);

    let auth = [0u8, 0u8]; // empty TPM2B_DIGEST
    let cmd = build_pw_cmd(CC_PCR_SET_AUTH_VALUE, &[24], 1, &auth);
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 1));
    let cmd = build_pw_cmd(CC_PCR_SET_AUTH_VALUE, &[Handle::RH_NULL.0], 1, &auth);
    assert_eq!(rc_of(&mut sim, &cmd), rc_h(TpmRc::VALUE, 1));
    // In-range PCR outside the auth group: bare TPM_RC_VALUE (as in the C reference).
    let cmd = build_pw_cmd(CC_PCR_SET_AUTH_VALUE, &[5], 1, &auth);
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::VALUE.get());
}

/// PCR_SetAuthValue only works on auth-group PCRs and the new auth then controls PCR_Extend.
#[test]
fn set_auth_value_controls_extend() {
    let mut sim = create_simulator!();

    // 1. Attempt TPM2_PCR_SetAuthValue on PCR 0 (not in auth group 20-22) -> should fail with TPM_RC_VALUE
    let set_auth_pcr0 = hx(concat!(
        "8002",         // TPM_ST_SESSIONS
        "00000021",     // size (33 bytes)
        "00000183",     // TPM2_PCR_SetAuthValue
        "00000000",     // pcrHandle: PCR 0
        "00000009",     // authSize: 9 bytes
        "40000009",     // TPM_RS_PW
        "0000",         // nonce: empty
        "01",           // attributes: continueSession
        "0000",         // hmac: empty
        "000411223344", // auth: 4 bytes [0x11, 0x22, 0x33, 0x44]
    ));
    let rc_pcr0 = rc_at(&mut sim, 0, &set_auth_pcr0);
    assert_ne!(rc_pcr0, 0, "PCR 0 is not in an auth group and should fail");

    // 2. Execute TPM2_PCR_SetAuthValue on PCR 20 (in auth group 20-22) -> should succeed
    let set_auth_pcr20 = hx(concat!(
        "8002",         // TPM_ST_SESSIONS
        "00000021",     // size (33 bytes)
        "00000183",     // TPM2_PCR_SetAuthValue
        "00000014",     // pcrHandle: PCR 20 (0x14)
        "00000009",     // authSize: 9 bytes
        "40000009",     // TPM_RS_PW
        "0000",         // nonce: empty
        "01",           // attributes: continueSession
        "0000",         // hmac: empty
        "000411223344", // auth: 4 bytes [0x11, 0x22, 0x33, 0x44]
    ));
    assert_eq!(rc_at(&mut sim, 0, &set_auth_pcr20), 0);

    // 3. Attempt TPM2_PCR_Extend on PCR 20 without session -> should fail with TPM_RC_AUTH_MISSING
    // (PCR 20 requires locality 1, 2, or 3 to extend, so the extends are sent at locality 2.)
    let extend_no_session = hx(concat!(
        "8001",     // TPM_ST_NO_SESSIONS
        "00000028", // size (40 bytes)
        "00000182", // TPM2_PCR_Extend
        "00000014", // pcrHandle: PCR 20
        "00000001", // count: 1 digest
        "0004",     // SHA1
        "0102030405060708090a0b0c0d0e0f1011121314",
    ));
    assert_eq!(
        rc_at(&mut sim, 2, &extend_no_session),
        0x00000125,
        "Expected TPM_RC_AUTH_MISSING when extending PCR 20 without session"
    );

    // 4. Attempt TPM2_PCR_Extend on PCR 20 with wrong password -> should fail with TPM_RC_BAD_AUTH
    let extend_bad_auth = hx(concat!(
        "8002",         // TPM_ST_SESSIONS
        "00000039",     // size (57 bytes)
        "00000182",     // TPM2_PCR_Extend
        "00000014",     // pcrHandle: PCR 20
        "0000000d",     // authSize: 13 bytes
        "40000009",     // TPM_RS_PW
        "0000",         // nonce: empty
        "01",           // attributes: continueSession
        "000499999999", // hmac: wrong password
        "00000001",     // count: 1 digest
        "0004",         // SHA1
        "0102030405060708090a0b0c0d0e0f1011121314",
    ));
    assert_eq!(
        rc_at(&mut sim, 2, &extend_bad_auth),
        0x000009A2,
        "Expected TPM_RC_BAD_AUTH (session 1) for wrong password"
    );

    // 5. Execute TPM2_PCR_Extend on PCR 20 with correct password -> should succeed
    // (this also shows that step 2 set the PCR authValue to [0x11, 0x22, 0x33, 0x44]).
    let extend_ok = hx(concat!(
        "8002",         // TPM_ST_SESSIONS
        "00000039",     // size (57 bytes)
        "00000182",     // TPM2_PCR_Extend
        "00000014",     // pcrHandle: PCR 20
        "0000000d",     // authSize: 13 bytes
        "40000009",     // TPM_RS_PW
        "0000",         // nonce: empty
        "01",           // attributes: continueSession
        "000411223344", // hmac: correct password [0x11, 0x22, 0x33, 0x44]
        "00000001",     // count: 1 digest
        "0004",         // SHA1
        "0102030405060708090a0b0c0d0e0f1011121314",
    ));
    assert_eq!(rc_at(&mut sim, 2, &extend_ok), 0);
}
