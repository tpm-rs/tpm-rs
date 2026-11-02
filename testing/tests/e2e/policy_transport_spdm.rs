//! TPM2_PolicyTransportSPDM (secure channel support, `tpm2-engine`'s `sec-channel`): the policy
//! digest with and without the requester/TPM key Names, the validation of the Names, the repeated
//! assertion, its reset by TPM2_PolicyRestart and its survival across a session context save, and
//! the deferred checks when the session authorizes a command (`TPM_RC_CHANNEL_KEY`).
//!
//! The simulator's platform, like the TCG reference, has a dummy secure transport layer that
//! protects every command with an SPDM session (requester key Name `TPM_ALG_SHA384 || 0x11 * 48`,
//! TPM key `TPM_PUB_KEY_TPM_SPDM_00`), so a policy without key Names (or with the Names of that
//! session) always authorizes; a session without secure channel (`TPM_RC_CHANNEL`) cannot be
//! produced through the command interface. Without secure channel support the command is not
//! implemented.

#![cfg_attr(not(feature = "sec-channel"), allow(unused_imports))]

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::{GetCapability, PolicyRestart, PolicyTransportSPDM};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, Tpm2bName, TpmCap, TpmCc, TpmSe, TpmiAlgHash, TpmsCapabilityData};

/// `TPM_CC_PolicyTransportSPDM`.
const CC_POLICY_TRANSPORT_SPDM: u32 = 0x1A1;
/// `TPM_RC_COMMAND_CODE`.
const RC_COMMAND_CODE: u32 = 0x143;

/// The parameters of TPM2_PolicyTransportSPDM: `reqKeyName` and `tpmKeyName` as `TPM2B_NAME`s.
fn params(req_key_name: &[u8], tpm_key_name: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    for name in [req_key_name, tpm_key_name] {
        p.extend_from_slice(&(name.len() as u16).to_be_bytes());
        p.extend_from_slice(name);
    }
    p
}

/// A Name with SHA-256 as its algorithm and `fill` as every digest octet.
fn sha256_name(fill: u8) -> Vec<u8> {
    let mut name = 0x000Bu16.to_be_bytes().to_vec();
    name.extend_from_slice(&[fill; 32]);
    name
}

/// TPM2_PolicyTransportSPDM(`req_key_name`, `tpm_key_name`) on `session`.
fn policy_transport_spdm(
    sim: &mut Tpm,
    session: Handle,
    req_key_name: &[u8],
    tpm_key_name: &[u8],
) -> Result<(), u32> {
    sim.execute(PolicyTransportSPDM {
        policy_session: session,
        req_key_name: Tpm2bName::from_bytes(req_key_name).unwrap(),
        tpm_key_name: Tpm2bName::from_bytes(tpm_key_name).unwrap(),
    })
    .map_err(rc_of_error)
}

/// The SHA-256 policy digest after TPM2_PolicyTransportSPDM from the initial (all-zero) digest:
/// `H(0^32 || TPM_CC_PolicyTransportSPDM || scKeyNameHash)`, where `scKeyNameHash` is
/// `H(reqKeyName.size || reqKeyName.name || tpmKeyName.size || tpmKeyName.name)`, or absent
/// if both Names are Empty Buffers.
fn expected_digest(req_key_name: &[u8], tpm_key_name: &[u8]) -> Vec<u8> {
    let sc_key_name_hash = if req_key_name.is_empty() && tpm_key_name.is_empty() {
        Vec::new()
    } else {
        sha256(&[&params(req_key_name, tpm_key_name)])
    };
    sha256(&[
        &[0u8; 32],
        &TpmCc::PolicyTransportSPDM.code().to_be_bytes(),
        &sc_key_name_hash,
    ])
}

/// The requester and TPM key Names of the SPDM session protecting the command, read with
/// TPM2_GetCapability(TPM_CAP_SPDM_SESSION_INFO).
fn spdm_session_names(sim: &mut Tpm) -> (Vec<u8>, Vec<u8>) {
    let rsp = sim
        .execute(GetCapability {
            capability: TpmCap::SpdmSessionInfo,
            property: 0,
            property_count: 1,
        })
        .expect("TPM2_GetCapability(TPM_CAP_SPDM_SESSION_INFO) failed");
    let TpmsCapabilityData::SpdmSessionInfo(list) = rsp.capability_data else {
        panic!("unexpected capability data");
    };
    let [info] = list.spdm_session_info() else {
        panic!("expected one SPDM session");
    };
    (
        info.req_key_name.get_buffer().to_vec(),
        info.tpm_key_name.get_buffer().to_vec(),
    )
}

/// Sets the owner policy to the digest of TPM2_PolicyTransportSPDM(`policy_req`, `policy_tpm`)
/// and authorizes TPM2_CreatePrimary(TPM_RH_OWNER) with a policy session that asserted
/// TPM2_PolicyTransportSPDM(`session_req`, `session_tpm`); returns the response code.
fn create_primary_with_policy(
    sim: &mut Tpm,
    (policy_req, policy_tpm): (&[u8], &[u8]),
    (session_req, session_tpm): (&[u8], &[u8]),
) -> u32 {
    let digest = trial_digest(sim, |sim, t| {
        assert_eq!(
            policy_cmd(
                sim,
                CC_POLICY_TRANSPORT_SPDM,
                t,
                &params(policy_req, policy_tpm)
            ),
            0
        );
    });
    set_owner_policy(sim, &digest, &[]);
    let mut p = start_session(sim, TpmSe::Policy, false);
    assert_eq!(
        policy_cmd(
            sim,
            CC_POLICY_TRANSPORT_SPDM,
            p.handle,
            &params(session_req, session_tpm)
        ),
        0
    );
    let rc = exec(
        sim,
        CC_CREATE_PRIMARY,
        &[RH_OWNER],
        &mut [SessUse::hmac(&mut p, ATTR_CONT, &[])],
        &create_primary_params(),
        1,
    )
    .rc;
    flush(sim, p.handle);
    rc
}

/// Without secure channel support TPM2_PolicyTransportSPDM is not implemented
///
/// Outside the `sec-channel` profile the command code fails with `TPM_RC_COMMAND_CODE` (the
/// profile is covered by the other tests of this file).
#[cfg(not(feature = "sec-channel"))]
#[test]
fn command_is_unimplemented_without_secure_channel_support() {
    let mut sim = Tpm::new();
    let s = start_session_handle(&mut sim, TpmSe::Trial);
    assert_eq!(
        policy_cmd(&mut sim, CC_POLICY_TRANSPORT_SPDM, s.0, &params(&[], &[])),
        RC_COMMAND_CODE
    );
}

/// Without key Names the policy digest extends TPM_CC_PolicyTransportSPDM only
///
/// `policyDigest_new = H(policyDigest_old || TPM_CC_PolicyTransportSPDM)` when both
/// `reqKeyName` and `tpmKeyName` are Empty Buffers (no `scKeyNameHash`).
#[cfg(feature = "sec-channel")]
#[test]
fn digest_without_key_names() {
    let mut sim = Tpm::new();
    let s = start_session_handle(&mut sim, TpmSe::Trial);
    policy_transport_spdm(&mut sim, s, &[], &[]).unwrap();
    assert_eq!(policy_digest(&mut sim, s), expected_digest(&[], &[]));
}

/// Key Names enter the policy digest through scKeyNameHash, with their sizes
///
/// With a requester key Name, a TPM key Name, or both, the digest includes
/// `scKeyNameHash = H(reqKeyName.size || reqKeyName.name || tpmKeyName.size ||
/// tpmKeyName.name)`, so the same Name as requester key or as TPM key gives different digests.
#[cfg(feature = "sec-channel")]
#[test]
fn digest_binds_key_names_with_their_sizes() {
    let mut sim = Tpm::new();
    let name = sha256_name(0x22);
    let mut digests = Vec::new();
    for (req, tpm) in [
        (&name[..], &[][..]),
        (&[][..], &name[..]),
        (&name[..], &sha256_name(0x33)[..]),
    ] {
        let s = start_session_handle(&mut sim, TpmSe::Trial);
        policy_transport_spdm(&mut sim, s, req, tpm).unwrap();
        let digest = policy_digest(&mut sim, s);
        assert_eq!(digest, expected_digest(req, tpm));
        digests.push(digest);
        flush_session(&mut sim, s);
    }
    assert_ne!(digests[0], digests[1]);
}

/// A second TPM2_PolicyTransportSPDM on the same session is TPM_RC_VALUE
///
/// "If policySession→checkSecureChannel is SET (i.e., TPM2_PolicyTransportSPDM() has been
/// previously executed), the TPM shall return TPM_RC_VALUE", whatever the Names; the digest is
/// unchanged.
#[cfg(feature = "sec-channel")]
#[test]
fn repeated_assertion_is_value_error() {
    let mut sim = Tpm::new();
    let s = start_session_handle(&mut sim, TpmSe::Policy);
    policy_transport_spdm(&mut sim, s, &[], &[]).unwrap();
    for (req, tpm) in [(&[][..], &[][..]), (&sha256_name(1)[..], &[][..])] {
        assert_eq!(
            policy_transport_spdm(&mut sim, s, req, tpm),
            Err(TpmRc::VALUE.get())
        );
    }
    assert_eq!(policy_digest(&mut sim, s), expected_digest(&[], &[]));
}

/// Key Names must be valid object Names: TPM_RC_HASH for the algorithm, TPM_RC_SIZE for the size
///
/// A Name whose first two octets are not an implemented hash algorithm (including
/// `TPM_ALG_NULL`) is `TPM_RC_HASH`, one whose remainder is not the digest size of its algorithm
/// (or that is too short to hold an algorithm) is `TPM_RC_SIZE`, each with the position of the
/// parameter; `reqKeyName` is checked first.
#[cfg(feature = "sec-channel")]
#[test]
fn invalid_key_names_rejected() {
    let mut sim = Tpm::new();
    let s = start_session_handle(&mut sim, TpmSe::Trial);
    let good = sha256_name(0x44);
    let mut short_digest = good.clone();
    short_digest.pop();
    let null_alg = [0x00, 0x10, 0xAA, 0xBB];
    let unknown_alg = [0x12, 0x34, 0xAA, 0xBB];
    let cases: [(&[u8], &[u8], TpmRc); 7] = [
        (&[0x00], &[], TpmRc::SIZE.with(Position::parameter(1))),
        (&short_digest, &[], TpmRc::SIZE.with(Position::parameter(1))),
        (&null_alg, &[], TpmRc::HASH.with(Position::parameter(1))),
        (&unknown_alg, &[], TpmRc::HASH.with(Position::parameter(1))),
        (&[], &short_digest, TpmRc::SIZE.with(Position::parameter(2))),
        (
            &good,
            &unknown_alg,
            TpmRc::HASH.with(Position::parameter(2)),
        ),
        (
            &unknown_alg,
            &short_digest,
            TpmRc::HASH.with(Position::parameter(1)),
        ),
    ];
    for (req, tpm, rc) in cases {
        assert_eq!(
            policy_transport_spdm(&mut sim, s, req, tpm),
            Err(rc.get()),
            "reqKeyName {req:02x?}, tpmKeyName {tpm:02x?}"
        );
    }
    // The failed assertions left the session unchanged.
    assert_eq!(policy_digest(&mut sim, s), vec![0u8; 32]);
    policy_transport_spdm(&mut sim, s, &good, &[]).unwrap();
}

/// TPM2_PolicyRestart clears the assertion, so it can be asserted again
///
/// `checkSecureChannel` is part of the policy session state that TPM2_PolicyRestart resets.
#[cfg(feature = "sec-channel")]
#[test]
fn policy_restart_clears_assertion() {
    let mut sim = Tpm::new();
    let s = start_session_handle(&mut sim, TpmSe::Policy);
    policy_transport_spdm(&mut sim, s, &sha256_name(5), &[]).unwrap();
    sim.execute(PolicyRestart { session_handle: s })
        .expect("TPM2_PolicyRestart failed");
    policy_transport_spdm(&mut sim, s, &[], &[]).unwrap();
    assert_eq!(policy_digest(&mut sim, s), expected_digest(&[], &[]));
}

/// The assertion survives a context save and load of the policy session
///
/// A session saved after TPM2_PolicyTransportSPDM and loaded again still has
/// `checkSecureChannel` SET (a second assertion is TPM_RC_VALUE) and its digest.
#[cfg(feature = "sec-channel")]
#[test]
fn assertion_survives_context_save_and_load() {
    let mut sim = Tpm::new();
    let s = start_session_handle(&mut sim, TpmSe::Policy);
    policy_transport_spdm(&mut sim, s, &sha256_name(6), &[]).unwrap();
    let context = context_save(&mut sim, s);
    let s = context_load(&mut sim, context).expect("TPM2_ContextLoad failed");
    assert_eq!(
        policy_transport_spdm(&mut sim, s, &[], &[]),
        Err(TpmRc::VALUE.get())
    );
    assert_eq!(
        policy_digest(&mut sim, s),
        expected_digest(&sha256_name(6), &[])
    );
}

/// A policy without key Names authorizes a command protected by an SPDM session
///
/// The simulator protects every command with an SPDM session, so the deferred
/// `checkSecureChannel` check passes and the owner policy authorizes TPM2_CreatePrimary.
#[cfg(feature = "sec-channel")]
#[test]
fn policy_without_key_names_authorizes() {
    let mut sim = Tpm::new();
    assert_eq!(
        create_primary_with_policy(&mut sim, (&[], &[]), (&[], &[])),
        0
    );
}

/// Policies bound to the Names of the session's keys authorize
///
/// With the requester key Name and/or the TPM key Name reported by
/// TPM2_GetCapability(TPM_CAP_SPDM_SESSION_INFO), the recomputed `scKeyNameHash` (with an Empty
/// Buffer for a key that is not checked) matches and the policy authorizes.
#[cfg(feature = "sec-channel")]
#[test]
fn policy_with_session_key_names_authorizes() {
    let mut sim = Tpm::new();
    let (req, tpm) = spdm_session_names(&mut sim);
    for names in [
        (&req[..], &[][..]),
        (&[][..], &tpm[..]),
        (&req[..], &tpm[..]),
    ] {
        assert_eq!(create_primary_with_policy(&mut sim, names, names), 0);
    }
}

/// A policy bound to another key Name fails with TPM_RC_CHANNEL_KEY
///
/// "If the scKeyNameHash values do not match, the TPM shall return TPM_RC_CHANNEL_KEY" (with
/// the position of the session) when the requester or TPM key of the SPDM session is not the
/// one in the policy.
#[cfg(feature = "sec-channel")]
#[test]
fn policy_with_other_key_name_is_channel_key_error() {
    let mut sim = Tpm::new();
    let (req, tpm) = spdm_session_names(&mut sim);
    let other = sha256_name(0x77);
    let expected = TpmRc::CHANNEL_KEY.with(Position::session(1)).get();
    for names in [
        (&other[..], &[][..]),
        (&[][..], &other[..]),
        (&req[..], &other[..]),
        (&other[..], &tpm[..]),
        // The TPM key Name given as requester key Name.
        (&tpm[..], &[][..]),
    ] {
        assert_eq!(
            create_primary_with_policy(&mut sim, names, names),
            expected,
            "policy Names {names:02x?}"
        );
    }
}

/// The TPM key Name is the Name of the TPM SPDM public key of TPM_CAP_PUB_KEYS
///
/// The `tpmKeyName` of the SPDM session is `nameAlg || H_nameAlg(publicArea)` of the key
/// TPM2_GetCapability(TPM_CAP_PUB_KEYS, TPM_PUB_KEY_TPM_SPDM_00) returns, so a policy can be
/// bound to the TPM key read from the capability.
#[cfg(feature = "sec-channel")]
#[test]
fn tpm_key_name_is_name_of_reported_public_key() {
    let mut sim = Tpm::new();
    let rsp = sim
        .execute(GetCapability {
            capability: TpmCap::PubKeys,
            property: 0,
            property_count: 1,
        })
        .expect("TPM2_GetCapability(TPM_CAP_PUB_KEYS) failed");
    let TpmsCapabilityData::PubKeys(keys) = rsp.capability_data else {
        panic!("unexpected capability data");
    };
    let public = keys.pub_keys()[0].0;
    let name_alg = public.name_alg.expect("nameAlg");
    let mut name = u16::from(tpm2::Alg::from(name_alg)).to_be_bytes().to_vec();
    name.extend_from_slice(&hash_bytes(name_alg, &marshal_to_vec(&public)));
    assert_eq!(spdm_session_names(&mut sim).1, name);
    assert_eq!(name_alg, TpmiAlgHash::Sha384);
    assert_eq!(
        create_primary_with_policy(&mut sim, (&[], &name), (&[], &name)),
        0
    );
}
