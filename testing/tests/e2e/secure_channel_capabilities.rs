//! TPM2_GetCapability(TPM_CAP_PUB_KEYS) and TPM2_GetCapability(TPM_CAP_SPDM_SESSION_INFO), the
//! capabilities of secure channel support (`tpm2-engine`'s `sec-channel`): the TPM SPDM
//! authentication public keys, the key Names of the SPDM session protecting the command, their
//! property checks and `propertyCount`. Without secure channel support both capabilities are
//! unknown.
//!
//! The simulator's platform, like the TCG reference, has a dummy secure transport layer: a single
//! TPM SPDM key (`TPM_PUB_KEY_TPM_SPDM_00`, an ECC NIST P-384 signing key with all-zero
//! coordinates) and an SPDM session with that key and the requester key Name
//! `TPM_ALG_SHA384 || 0x11 * 48` that protects every command.

#![cfg_attr(not(feature = "sec-channel"), allow(unused_imports))]

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::GetCapability;
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    PublicParmsAndId, TpmCap, TpmEccCurve, TpmaObject, TpmiAlgHash, TpmsCapabilityData,
    TpmtEccScheme,
};

/// `TPM_CAP_PUB_KEYS`.
const CAP_PUB_KEYS: u32 = 0xB;
/// `TPM_CAP_SPDM_SESSION_INFO`.
const CAP_SPDM_SESSION_INFO: u32 = 0xC;

/// The requester key Name of the simulator's dummy SPDM session.
fn dummy_req_key_name() -> Vec<u8> {
    let mut name = vec![0x00, 0x0C];
    name.extend_from_slice(&[0x11; 48]);
    name
}

/// TPM2_GetCapability(`capability`, `property`, `count`): `moreData` and the capability data.
fn capability(
    sim: &mut Tpm,
    capability: TpmCap,
    property: u32,
    count: u32,
) -> (bool, TpmsCapabilityData<'static>) {
    let rsp = sim
        .execute(GetCapability {
            capability,
            property,
            property_count: count,
        })
        .expect("TPM2_GetCapability failed");
    (rsp.more_data, rsp.capability_data)
}

/// Without secure channel support both capabilities are TPM_RC_VALUE on the capability
///
/// The `TPM_CAP` unmarshaler of a TPM without secure channel support rejects
/// `TPM_CAP_PUB_KEYS` and `TPM_CAP_SPDM_SESSION_INFO` (the profile is covered by the other tests
/// of this file).
#[cfg(not(feature = "sec-channel"))]
#[test]
fn capabilities_are_unknown_without_secure_channel_support() {
    let mut sim = Tpm::new();
    for cap in [CAP_PUB_KEYS, CAP_SPDM_SESSION_INFO] {
        assert_eq!(
            get_cap(&mut sim, cap, 0, 1).map(|_| ()),
            Err(rc_p(TpmRc::VALUE, 1)),
            "capability {cap:#x}"
        );
    }
}

/// TPM_CAP_PUB_KEYS returns the TPM SPDM public key of TPM_PUB_KEY_TPM_SPDM_00
///
/// The list holds the single TPM SPDM authentication key of the platform as a `TPM2B_PUBLIC`
/// (an ECC NIST P-384 restricted signing key with ECDSA/SHA-384 and nameAlg SHA-384), and
/// `moreData` is NO.
#[cfg(feature = "sec-channel")]
#[test]
fn pub_keys_returns_tpm_spdm_key() {
    let mut sim = Tpm::new();
    for count in [1, 2, u32::MAX] {
        let (more, data) = capability(&mut sim, TpmCap::PubKeys, 0, count);
        assert!(!more);
        let TpmsCapabilityData::PubKeys(keys) = data else {
            panic!("unexpected capability data");
        };
        let [key] = keys.pub_keys() else {
            panic!("expected one key");
        };
        let public = key.0;
        assert_eq!(public.name_alg, Some(TpmiAlgHash::Sha384));
        assert_eq!(
            public.object_attributes,
            TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::RESTRICTED
                | TpmaObject::SIGN_ENCRYPT
        );
        assert_eq!(public.auth_policy.get_size(), 0);
        let PublicParmsAndId::Ecc(parms, point) = public.parms_and_id else {
            panic!("expected an ECC key");
        };
        assert_eq!(parms.symmetric, None);
        assert_eq!(
            parms.scheme,
            Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha384))
        );
        assert_eq!(parms.curve_id, TpmEccCurve::NistP384);
        assert_eq!(parms.kdf, None);
        assert_eq!(point.x.get_buffer(), &[0u8; 48]);
        assert_eq!(point.y.get_buffer(), &[0u8; 48]);
    }
}

/// TPM_CAP_PUB_KEYS rejects a property that is not a TPM SPDM key with TPM_RC_VALUE
///
/// Part 2, TPM_PUB_KEY: "TPM_RC_VALUE is returned for not supported property values": the
/// unused `TPM_PUB_KEY_TPM_SPDM_01`..`TPM_PUB_KEY_TPM_SPDM_FF` and values outside the range,
/// with the position of `property`.
#[cfg(feature = "sec-channel")]
#[test]
fn pub_keys_rejects_unsupported_property() {
    let mut sim = Tpm::new();
    for property in [1, 0xFF, 0x100, 0x8000_0000] {
        assert_eq!(
            get_cap(&mut sim, CAP_PUB_KEYS, property, 1).map(|_| ()),
            Err(TpmRc::VALUE.with(Position::parameter(2)).get()),
            "property {property:#x}"
        );
    }
}

/// TPM_CAP_PUB_KEYS with propertyCount 0 returns no key and moreData YES
///
/// Part 3, TPM2_GetCapability: "The TPM will return no more than the number of requested values
/// (propertyCount)", and moreData is YES "if there are more values of the requested type that
/// were not returned".
#[cfg(feature = "sec-channel")]
#[test]
fn pub_keys_with_zero_count_returns_no_key() {
    let mut sim = Tpm::new();
    let (more, data) = capability(&mut sim, TpmCap::PubKeys, 0, 0);
    assert!(more);
    let TpmsCapabilityData::PubKeys(keys) = data else {
        panic!("unexpected capability data");
    };
    assert!(keys.pub_keys().is_empty());
}

/// TPM_CAP_SPDM_SESSION_INFO returns the key Names of the SPDM session protecting the command
///
/// The single entry holds the requester key Name of the session and the TPM key Name, which is
/// `TPM_ALG_SHA384 || SHA-384(publicArea)` of the TPM SPDM key; `moreData` is NO.
#[cfg(feature = "sec-channel")]
#[test]
fn spdm_session_info_reports_session_key_names() {
    let mut sim = Tpm::new();
    let (_, keys) = capability(&mut sim, TpmCap::PubKeys, 0, 1);
    let TpmsCapabilityData::PubKeys(keys) = keys else {
        panic!("unexpected capability data");
    };
    let mut tpm_key_name = vec![0x00, 0x0C];
    tpm_key_name.extend_from_slice(&hash_bytes(
        TpmiAlgHash::Sha384,
        &marshal_to_vec(&keys.pub_keys()[0].0),
    ));
    for count in [1, 5, u32::MAX] {
        let (more, data) = capability(&mut sim, TpmCap::SpdmSessionInfo, 0, count);
        assert!(!more);
        let TpmsCapabilityData::SpdmSessionInfo(list) = data else {
            panic!("unexpected capability data");
        };
        let [info] = list.spdm_session_info() else {
            panic!("expected one SPDM session");
        };
        assert_eq!(info.req_key_name.get_buffer(), &dummy_req_key_name()[..]);
        assert_eq!(info.tpm_key_name.get_buffer(), &tpm_key_name[..]);
    }
}

/// TPM_CAP_SPDM_SESSION_INFO requires the reserved property 0 (TPM_RC_VALUE otherwise)
///
/// The property of `TPM_CAP_SPDM_SESSION_INFO` is reserved; any other value is `TPM_RC_VALUE`
/// with the position of `property`.
#[cfg(feature = "sec-channel")]
#[test]
fn spdm_session_info_rejects_nonzero_property() {
    let mut sim = Tpm::new();
    for property in [1, 0x100, u32::MAX] {
        assert_eq!(
            get_cap(&mut sim, CAP_SPDM_SESSION_INFO, property, 1).map(|_| ()),
            Err(TpmRc::VALUE.with(Position::parameter(2)).get()),
            "property {property:#x}"
        );
    }
}

/// TPM_CAP_SPDM_SESSION_INFO with propertyCount 0 returns no entry and moreData YES
///
/// "The TPM will return no more than the number of requested values (propertyCount)": the
/// session's entry is left out and reported by moreData.
#[cfg(feature = "sec-channel")]
#[test]
fn spdm_session_info_with_zero_count_returns_no_entry() {
    let mut sim = Tpm::new();
    let (more, data) = capability(&mut sim, TpmCap::SpdmSessionInfo, 0, 0);
    assert!(more);
    let TpmsCapabilityData::SpdmSessionInfo(list) = data else {
        panic!("unexpected capability data");
    };
    assert!(list.spdm_session_info().is_empty());
}
