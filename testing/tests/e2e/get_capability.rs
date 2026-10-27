//! TPM2_GetCapability: algorithms, commands, handles, PCRs, properties and policies reported by
//! each capability.

use crate::_common::Connection;
use crate::_common::{
    CAP_ACT, CAP_ALGS, CAP_PCRS, CmdHeader, STRONGEST_HASH_ALG, TPMA_CC_EXTENSIVE, TPMA_CC_FLUSHED,
    TPMA_CC_NV, cap_handles, cap_pcr_properties, command_attributes, context_save_raw,
    create_primary, create_storage_primary_in, da_parameters_unwrap, execute_get_capability,
    execute_raw_transact, execute_with_corrupted_bytes_status, get_cap, get_tpm_property,
    hash_sequence_start, marshal_to_slice, no_session_command, power_cycle_orderly, rc_of, rc_p,
    rsa_ek_template, run_raw, start_auth_session, start_session_raw,
};
use testing::tpm::Tpm;
use tpm2::commands::GetCapability;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, Marshal, TpmCap, TpmCc, TpmPt, TpmSe, TpmiStCommandTag, Unmarshal};

/// `TPM_CAP_ACT` reports `TPM_RC_VALUE + RC_P2`, not `RC_P1`.
#[test]
fn act_capability_rejected_on_property() {
    let mut sim = Tpm::new();
    for property in [0x4000_0110, 0x4000_011F, 0x0000_0000] {
        assert_eq!(
            get_cap(&mut sim, CAP_ACT, property, 1).map(|_| ()),
            Err(rc_p(TpmRc::VALUE, 2)),
            "property {property:#x}"
        );
    }
}

/// `TPM_CAP_ALGS` and `TPM_CAP_ECC_CURVES` take only the low 16 bits of `property` as the first
/// `TPM_ALG_ID`/`TPM_ECC_CURVE` (the reference casts it), so set upper bits do not empty the
/// list (found by differential fuzzing). Part 3 `TPM2_GetCapability` only says the ID "is cast to a
/// UINT32" and is silent on set upper bits, so `tpm-rs` follows `mstpm20`.
#[test]
fn algorithm_and_curve_properties_ignore_upper_bits() {
    /// `TPM_CAP_ECC_CURVES`.
    const CAP_ECC_CURVES: u32 = 8;
    let mut sim = Tpm::new();
    for capability in [CAP_ALGS, CAP_ECC_CURVES] {
        let plain = get_cap(&mut sim, capability, 0x0003, 64).unwrap();
        let masked = get_cap(&mut sim, capability, 0x00A2_0003, 64).unwrap();
        assert_eq!(masked, plain, "capability {capability}");
        let count = u32::from_be_bytes(plain.1[0..4].try_into().unwrap());
        assert!(count > 0, "capability {capability}");
    }
}

/// `TPM_CAP_TPM_PROPERTIES` returns only properties of the group of `property`: a start beyond
/// the last fixed property returns an empty list (not the variable group), and a start at
/// `PT_FIXED` stops at `PT_VAR` (found by differential fuzzing). TPM 2.0 Part 3,
/// TPM2_GetCapability: "The TPM will only return values in the same group as the *property*
/// parameter in the command."
#[test]
fn tpm_properties_stay_within_the_requested_group() {
    /// `TPM_CAP_TPM_PROPERTIES`.
    const CAP_TPM_PROPERTIES: u32 = 6;
    let mut sim = Tpm::new();
    let (more, data) = get_cap(&mut sim, CAP_TPM_PROPERTIES, 0x154, 4).unwrap();
    assert!(!more);
    assert_eq!(data, [0, 0, 0, 0], "empty TPML_TAGGED_TPM_PROPERTY");
    let (more, data) = get_cap(&mut sim, CAP_TPM_PROPERTIES, 0x100, 127).unwrap();
    assert!(!more);
    let n = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
    assert!(n > 0);
    for i in 0..n {
        let tag = u32::from_be_bytes(data[4 + 8 * i..8 + 8 * i].try_into().unwrap());
        assert!((0x100..0x200).contains(&tag), "property {tag:#x}");
    }
}

/// A capability this TPM does not implement (`TPM_CAP_PUB_KEYS`, `TPM_CAP_SPDM_SESSION_INFO`) is
/// `TPM_RC_VALUE + RC_P1` while it is unmarshaled, so it wins over
/// trailing bytes (`TPM_RC_SIZE`) and over missing later parameters (found by differential
/// fuzzing). TPM 2.0 Part 2, "Definition of (UINT32) TPM_CAP Constants": "#TPM_RC_VALUE".
#[test]
fn unimplemented_capability_rejected_while_unmarshaling() {
    let mut sim = Tpm::new();
    for capability in [0x0Bu32, 0x0C] {
        let mut params = capability.to_be_bytes().to_vec();
        params.extend_from_slice(&[0, 0, 0, 0x0A, 0, 0, 0, 0, 0, 0, 1, 0]); // + 4 trailing bytes
        for len in [params.len(), 4] {
            let mut cmd = vec![0x80, 0x01, 0, 0, 0, 0, 0, 0, 0x01, 0x7A];
            cmd.extend_from_slice(&params[..len]);
            let size = cmd.len() as u32;
            cmd[2..6].copy_from_slice(&size.to_be_bytes());
            assert_eq!(
                rc_of(&run_raw(&mut sim, &cmd)),
                rc_p(TpmRc::VALUE, 1),
                "capability {capability:#x}, {len} parameter bytes"
            );
        }
    }
}

/// `TPM_PT_LOADED_CURVES` is the number of implemented (always loaded) ECC curves, i.e. the length
/// of the `TPM_CAP_ECC_CURVES` list (found by differential fuzzing). TPM 2.0 Part 2, TPM_PT:
/// "TPM_PT_LOADED_CURVES | PT_VAR + 13 | the number of loaded ECC curves".
#[test]
fn loaded_curves_counts_every_implemented_curve() {
    /// `TPM_CAP_ECC_CURVES`.
    const CAP_ECC_CURVES: u32 = 8;
    /// `TPM_PT_LOADED_CURVES`.
    const PT_LOADED_CURVES: u32 = 0x20D;
    let mut sim = Tpm::new();
    let (_, curves) = get_cap(&mut sim, CAP_ECC_CURVES, 0, 64).unwrap();
    let n_curves = u32::from_be_bytes(curves[0..4].try_into().unwrap());
    let (_, props) = get_cap(&mut sim, 6, PT_LOADED_CURVES, 1).unwrap();
    assert_eq!(
        &props[0..8],
        [&1u32.to_be_bytes()[..], &PT_LOADED_CURVES.to_be_bytes()].concat()
    );
    assert_eq!(
        u32::from_be_bytes(props[8..12].try_into().unwrap()),
        n_curves
    );
}

/// `TPM_CAP_ECC_CURVES` lists the curves in ascending order from `property`, so reading the list
/// one curve at a time, continuing after the last returned curve, yields the whole list: TPM 2.0
/// Part 3, TPM2_GetCapability: "The *property* parameter selects the first value of the selected
/// category to be returned. If there is no property that corresponds to the value of
/// *property*, the next higher value is returned, if it exists."
#[test]
fn ecc_curves_are_listed_in_ascending_order() {
    /// `TPM_CAP_ECC_CURVES`.
    const CAP_ECC_CURVES: u32 = 8;
    let curves_of = |data: &[u8]| -> Vec<u16> {
        let count = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
        assert_eq!(data.len(), 4 + 2 * count);
        (0..count)
            .map(|i| u16::from_be_bytes([data[4 + 2 * i], data[5 + 2 * i]]))
            .collect()
    };
    let mut sim = Tpm::new();
    let (more, data) = get_cap(&mut sim, CAP_ECC_CURVES, 0, 64).unwrap();
    assert!(!more);
    let all = curves_of(&data);
    assert!(all.len() > 1, "{all:x?}");
    assert!(all.windows(2).all(|w| w[0] < w[1]), "{all:x?}");
    let mut paged = Vec::new();
    let mut property = 0;
    loop {
        let (more, data) = get_cap(&mut sim, CAP_ECC_CURVES, property, 1).unwrap();
        let curves = curves_of(&data);
        assert_eq!(curves.len(), 1, "property {property:#x}");
        paged.push(curves[0]);
        if !more {
            break;
        }
        property = u32::from(curves[0]) + 1;
    }
    assert_eq!(paged, all);
}

/// `TPM_CAP_ALGS` reports MGF1 and the KDFs, and the full `KEYEDHASH` attributes.
#[test]
fn algorithms_list_complete_and_sorted() {
    let mut sim = Tpm::new();
    let (_, data) = get_cap(&mut sim, CAP_ALGS, 0, 64).unwrap();
    let n = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
    let algs: Vec<(u16, u32)> = (0..n)
        .map(|i| {
            let o = 4 + 6 * i;
            (
                u16::from_be_bytes(data[o..o + 2].try_into().unwrap()),
                u32::from_be_bytes(data[o + 2..o + 6].try_into().unwrap()),
            )
        })
        .collect();
    let attr = |alg: u16| {
        algs.iter()
            .find(|(a, _)| *a == alg)
            .map(|(_, attr)| *attr)
            .unwrap_or_else(|| panic!("algorithm {alg:#x} not reported"))
    };
    // TPMA_ALGORITHM: asymmetric 0, symmetric 1, hash 2, object 3, signing 8, encrypting 9,
    // method 10.
    let hash_method = (1 << 2) | (1 << 10);
    assert_eq!(attr(0x0007), hash_method, "MGF1");
    assert_eq!(attr(0x0020), hash_method, "KDF1_SP800_56A");
    assert_eq!(attr(0x0021), hash_method, "KDF2");
    assert_eq!(attr(0x0022), hash_method, "KDF1_SP800_108");
    assert_eq!(
        attr(0x0008),
        (1 << 2) | (1 << 3) | (1 << 8) | (1 << 9),
        "KEYEDHASH"
    );
    // The list is sorted by algorithm ID.
    assert!(algs.windows(2).all(|w| w[0].0 < w[1].0));
}

/// TPM_CAP_AUTH_POLICIES reports TPM_ALG_NULL for unset policies and the digest after SetPrimaryPolicy
#[test]
fn auth_policies_after_set_primary_policy() {
    use tpm2::commands::SetPrimaryPolicy;
    use tpm2::{Handle, Tpm2bDigest, TpmiAlgHash, TpmsAuthCommand, TpmtHa};

    let mut sim = Tpm::new();

    // 1. Query TPM2_GetCapability(TPM_CAP_AUTH_POLICIES, 0x40000001, 4)
    // Initially, all permanent handles have no policy set.
    let cmd = GetCapability {
        capability: TpmCap::AuthPolicies,
        property: 0x40000001,
        property_count: 4,
    };
    let request = no_session_command(TpmCc::GetCapability, &cmd);
    let response = run_raw(&mut sim, &request);
    assert_eq!(rc_of(&response), 0);
    let res_len = response.len();

    let mut unmarsh = &response[10..res_len];
    let more_data = bool::unmarshal(&mut unmarsh).unwrap();
    assert!(!more_data);
    let cap_data = tpm2::TpmsCapabilityData::unmarshal(&mut unmarsh).unwrap();
    assert!(unmarsh.is_empty());

    if let tpm2::TpmsCapabilityData::AuthPolicies(tagged_policies) = cap_data {
        assert_eq!(tagged_policies.count(), 4);
        let policies = tagged_policies.as_slice();

        let expected_handles = [
            Handle::RH_OWNER,
            Handle::RH_LOCKOUT,
            Handle::RH_ENDORSEMENT,
            Handle::RH_PLATFORM,
        ];

        for (i, &expected_handle) in expected_handles.iter().enumerate() {
            assert_eq!(policies[i].handle, expected_handle);
            // All unassigned policies MUST report policy_hash == None (TPM_ALG_NULL)
            assert_eq!(policies[i].policy_hash, None);
        }

        // Verify wire format: 4 policies of 6 bytes each (4 handle + 2 TPM_ALG_NULL)
        // capability (4) + count (4) + 4 * 6 = 32 bytes capability data
        // header (10) + more_data (1) + 32 = 43 bytes total
        assert_eq!(res_len, 10 + 1 + 4 + 4 + 4 * 6);
    } else {
        panic!("Expected AuthPolicies capability data");
    }

    // 2. Set an authPolicy on RH_OWNER via TPM2_SetPrimaryPolicy
    let dummy_policy = [0x42u8; 32];
    let policy_digest = Tpm2bDigest::from_bytes(&dummy_policy).unwrap();
    let set_cmd = SetPrimaryPolicy {
        auth_handle: Handle::RH_OWNER,
        auth_policy: policy_digest,
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let mut set_req = [0u8; 1024];
    let mut s_off = 0;
    s_off += marshal_to_slice(&(0x8002u16), &mut set_req[s_off..]);
    let len_offset = s_off;
    s_off += marshal_to_slice(&(0u32), &mut set_req[s_off..]);
    s_off += marshal_to_slice(&(TpmCc::SetPrimaryPolicy.code()), &mut set_req[s_off..]);
    s_off += marshal_to_slice(&set_cmd.auth_handle, &mut set_req[s_off..]);
    let auth_len_offset = s_off;
    s_off += marshal_to_slice(&(0u32), &mut set_req[s_off..]);
    let auth_start = s_off;
    let pw_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Default::default(),
        session_attributes: Default::default(),
        hmac: Default::default(),
    };
    s_off += marshal_to_slice(&pw_auth, &mut set_req[s_off..]);
    let auth_len = (s_off - auth_start) as u32;
    s_off += marshal_to_slice(&set_cmd, &mut set_req[s_off..]);
    let total_len = s_off as u32;
    set_req[len_offset..len_offset + 4].copy_from_slice(&total_len.to_be_bytes());
    set_req[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());

    let set_resp = run_raw(&mut sim, &set_req[..s_off]);
    assert_eq!(rc_of(&set_resp), 0);

    // 3. Query TPM2_GetCapability(TPM_CAP_AUTH_POLICIES) again
    let response = run_raw(&mut sim, &request);
    assert_eq!(rc_of(&response), 0);
    let mut unmarsh2 = &response[10..];
    let _more_data2 = bool::unmarshal(&mut unmarsh2).unwrap();
    let cap_data2 = tpm2::TpmsCapabilityData::unmarshal(&mut unmarsh2).unwrap();
    if let tpm2::TpmsCapabilityData::AuthPolicies(tagged_policies) = cap_data2 {
        assert_eq!(tagged_policies.count(), 4);
        let policies = tagged_policies.as_slice();

        // RH_OWNER must now have Some(Sha256) policy
        assert_eq!(policies[0].handle, Handle::RH_OWNER);
        assert_eq!(policies[0].policy_hash, Some(TpmtHa::Sha256(&dummy_policy)));

        // Others must still be None
        assert_eq!(policies[1].handle, Handle::RH_LOCKOUT);
        assert_eq!(policies[1].policy_hash, None);
        assert_eq!(policies[2].handle, Handle::RH_ENDORSEMENT);
        assert_eq!(policies[2].policy_hash, None);
        assert_eq!(policies[3].handle, Handle::RH_PLATFORM);
        assert_eq!(policies[3].policy_hash, None);
    } else {
        panic!("Expected AuthPolicies capability data");
    }
}

/// `TPM_CAP_COMMANDS`: `ChangeEPS`/`ChangePPS` are `nv` + `extensive`, and the
/// `NV_UndefineSpace*` commands are not `flushed` (`CommandAttributeData.h`).
#[test]
fn command_attributes_match_reference() {
    let mut sim = Tpm::new();
    for cc in [0x124, 0x125] {
        let attr = command_attributes(&mut sim, cc);
        assert_eq!(
            attr & (TPMA_CC_NV | TPMA_CC_EXTENSIVE),
            TPMA_CC_NV | TPMA_CC_EXTENSIVE
        );
        assert_eq!(attr & TPMA_CC_FLUSHED, 0);
    }
    for cc in [0x11F, 0x122] {
        let attr = command_attributes(&mut sim, cc);
        assert_eq!(attr & TPMA_CC_FLUSHED, 0, "cc {cc:#x}");
        assert_ne!(attr & TPMA_CC_NV, 0, "cc {cc:#x}");
    }
    // SequenceComplete / EventSequenceComplete remain flushed.
    for cc in [0x13E, 0x185] {
        assert_ne!(command_attributes(&mut sim, cc) & TPMA_CC_FLUSHED, 0);
    }
}

/// GetCapability(TPM_CAP_COMMANDS) starting at TPM_CC_Startup succeeds with data
#[test]
fn commands_from_startup() {
    let mut sim = Tpm::new();

    let cmd = GetCapability {
        capability: TpmCap::Commands,
        property: TpmCc::Startup.code(),
        property_count: 5,
    };
    let response = run_raw(&mut sim, &no_session_command(TpmCc::GetCapability, &cmd));
    assert!(response.len() > 10);
    assert_eq!(rc_of(&response), 0);
}

/// TPM_PROPERTIES starting at FAMILY_INDICATOR report family, level, revision, errata and year
#[test]
fn family_level_revision_properties() {
    let mut sim = Tpm::new();

    let cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(tpm2::TpmPt::FAMILY_INDICATOR),
        property_count: 5,
    };
    let response = run_raw(&mut sim, &no_session_command(TpmCc::GetCapability, &cmd));
    assert_eq!(rc_of(&response), 0);
    let mut unmarsh = &response[10..];
    let _more_data = u8::unmarshal(&mut unmarsh).unwrap();
    let cap_data = tpm2::TpmsCapabilityData::unmarshal(&mut unmarsh).unwrap();
    if let tpm2::TpmsCapabilityData::TpmProperties(props) = cap_data {
        assert_eq!(props.count(), 5);
        assert_eq!(
            props.tpm_property()[0].property,
            tpm2::TpmPt::FAMILY_INDICATOR
        );
        assert_eq!(props.tpm_property()[0].value, tpm2::TPM_SPEC_FAMILY);
        assert_eq!(props.tpm_property()[1].property, tpm2::TpmPt::LEVEL);
        assert_eq!(props.tpm_property()[1].value, tpm2::TPM_SPEC_LEVEL);
        assert_eq!(props.tpm_property()[2].property, tpm2::TpmPt::REVISION);
        assert_eq!(props.tpm_property()[2].value, tpm2::TPM_SPEC_VERSION);
        assert_eq!(props.tpm_property()[3].property, tpm2::TpmPt::ERRATA);
        assert_eq!(props.tpm_property()[3].value, tpm2::TPM_SPEC_ERRATA);
        assert_eq!(props.tpm_property()[4].property, tpm2::TpmPt::YEAR);
        assert_eq!(props.tpm_property()[4].value, tpm2::TPM_SPEC_YEAR);
    } else {
        panic!("Expected TpmProperties capability data");
    }
}

/// TPM2_GetCapability with a huge propertyCount returns properties without panicking
#[test]
fn get_capability_property_count_huge() {
    let mut sim = Tpm::new();

    let get_cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: u32::MAX,
    };

    let mut resp_buffer = [0u8; 4096];
    let rsp = execute_get_capability(&mut sim, &get_cmd, 0, &[], &mut resp_buffer)
        .expect("Should handle property_count = u32::MAX gracefully");
    // It should have returned properties without panicking
    assert!(!rsp.more_data);
}

/// TPM2_GetCapability with propertyCount=0 succeeds
#[test]
fn get_capability_property_count_zero() {
    let mut sim = Tpm::new();

    let get_cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 0,
    };

    let mut resp_buffer = [0u8; 4096];
    let get_resp = execute_get_capability(&mut sim, &get_cmd, 0, &[], &mut resp_buffer)
        .expect("property_count = 0 should succeed and return more_data = YES per TPM 2.0 Spec");
    assert!(get_resp.more_data);
}

/// TPM2_GetCapability with one extra trailing byte fails with TPM_RC_SIZE
#[test]
fn get_capability_rejects_trailing_bytes() {
    let mut sim = Tpm::new();

    // Marshal GetCapability
    let get_cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    };

    let mut cmd_bytes = [0u8; 100];
    let header = CmdHeader {
        tag: TpmiStCommandTag::NoSessions,
        size: 0,
        code: TpmCc::GetCapability,
    };

    let mut written = header.marshal((&mut cmd_bytes[0..10]).try_into().unwrap());
    written += marshal_to_slice(&(get_cmd), &mut cmd_bytes[written..]);

    // Add 1 extra byte of garbage
    cmd_bytes[written] = 0xAA;
    written += 1;

    // Update size in header
    let mut size_bytes = [0u8; 4];
    size_bytes.copy_from_slice(&(written as u32).to_be_bytes());
    cmd_bytes[2..6].copy_from_slice(&size_bytes);

    let resp = execute_raw_transact(&mut sim, &cmd_bytes[..written]);
    // Expect TPM_RC_SIZE (0x95)
    assert_eq!(resp.err(), Some(0x95));
}

/// TPM2_GetCapability with an undefined capability (0x9999) fails with TPM_RC_VALUE + P1
#[test]
fn get_capability_rejects_unknown_capability() {
    let mut sim = Tpm::new();

    // Use an unsupported capability tag (e.g. 0x9999)
    let get_cmd = GetCapability {
        capability: TpmCap::Algs,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    };

    let resp = execute_with_corrupted_bytes_status(&mut sim, &get_cmd, 0, &[], |buf| {
        buf[0..4].copy_from_slice(&0x9999u32.to_be_bytes());
    });
    // Invalid capability fails unmarshalling with TPM_RC_VALUE + TPM_RC_P + TPM_RC_1
    assert_eq!(
        resp.err(),
        Some(
            TpmRc::VALUE
                .with(tpm2::errors::Position::parameter(1))
                .get()
        )
    );
}

/// `TPM_CAP_HANDLES` / `TPM_CAP_PCRS` / `TPM_CAP_PCR_PROPERTIES` / `TPM_CAP_ACT` edge cases.
#[test]
fn handles_pcrs_and_pcr_properties_edge_cases() {
    let mut sim = Tpm::new();

    assert_eq!(
        cap_handles(&mut sim, 0x0400_0000, 8),
        Err(rc_p(TpmRc::HANDLE, 2))
    );
    assert_eq!(cap_handles(&mut sim, 30, 8), Ok((vec![], false)));

    // propertyCount == 0: empty allocation with moreData = YES.
    let (more, data) = get_cap(&mut sim, CAP_PCRS, 0, 0).unwrap();
    assert!(more);
    assert_eq!(data, 0u32.to_be_bytes().to_vec());

    // Properties past TPM_PT_PCR_LAST: empty, no error.
    let (props, more) = cap_pcr_properties(&mut sim, 21, 8);
    assert!(props.is_empty());
    assert!(!more);
    // POLICY / AUTH include PCRs 20-22.
    let (props, _) = cap_pcr_properties(&mut sim, 0x13, 2);
    assert_eq!(
        props,
        vec![(0x13, vec![0, 0, 0x70]), (0x14, vec![0, 0, 0x70])]
    );
    // When the list fills up while more property values remain, moreData is YES.
    let (props, more) = cap_pcr_properties(&mut sim, 0, 1);
    assert_eq!(props.len(), 1);
    assert!(more);

    // ACT is not implemented: TPM_RC_VALUE + RC_P2 for every property.
    assert_eq!(
        get_cap(&mut sim, CAP_ACT, 0x4000_0110, 1).map(|_| ()),
        Err(rc_p(TpmRc::VALUE, 2))
    );
}

/// `TPM_CAP_TPM_PROPERTIES` reports live DA values, the number of loaded sessions, the real
/// `orderly` flag and `tpmGeneratedEPS`; `TPM_CAP_HANDLES` rejects unsupported handle types with
/// `TPM_RC_HANDLE + RC_P2` and returns an empty list past `PCR_LAST`; `TPM_CAP_COMMANDS` matches
/// `CommandAttributeData.h`.
#[test]
fn live_properties_handles_and_commands() {
    let mut sim = Tpm::new();

    da_parameters_unwrap(&mut sim, 7, 11, 13);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::LOCKOUT_COUNTER), 0);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::MAX_AUTH_FAIL), 7);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::LOCKOUT_INTERVAL), 11);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::LOCKOUT_RECOVERY), 13);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::AUDIT_COUNTER_0), 0);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::AUDIT_COUNTER_1), 0);

    // HR_LOADED counts loaded sessions, not transient objects.
    let transient_avail = get_tpm_property(&mut sim, TpmPt::HR_TRANSIENT_AVAIL);
    let _primary = create_storage_primary_in(&mut sim, Handle::RH_OWNER);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::HR_LOADED), 0);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::HR_LOADED_AVAIL), 3);
    let _session = start_session_raw(&mut sim, 0);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::HR_LOADED), 1);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::HR_LOADED_AVAIL), 2);
    // One object slot is now taken by the primary key (sessions do not use object slots).
    assert_eq!(
        get_tpm_property(&mut sim, TpmPt::HR_TRANSIENT_AVAIL),
        transient_avail - 1
    );

    // tpmGeneratedEPS is always set.
    let permanent = get_tpm_property(&mut sim, TpmPt::PERMANENT);
    assert_ne!(permanent & (1 << 10), 0, "tpmGeneratedEPS");

    // orderly reflects the previous shutdown.
    power_cycle_orderly(&mut sim, false);
    let startup_clear = get_tpm_property(&mut sim, TpmPt::STARTUP_CLEAR);
    assert_eq!(
        startup_clear & (1 << 31),
        0,
        "orderly after an unorderly shutdown"
    );
    power_cycle_orderly(&mut sim, true);
    let startup_clear = get_tpm_property(&mut sim, TpmPt::STARTUP_CLEAR);
    assert_ne!(
        startup_clear & (1 << 31),
        0,
        "orderly after an orderly shutdown"
    );

    // Unsupported handle type.
    assert_eq!(
        cap_handles(&mut sim, 0x0500_0000, 8),
        Err(rc_p(TpmRc::HANDLE, 2))
    );
    // PCR handles past PCR_LAST: empty list, no error.
    assert_eq!(cap_handles(&mut sim, 24, 8), Ok((vec![], false)));

    // TPMA_CC of ChangeEPS / NV_UndefineSpace.
    let eps = command_attributes(&mut sim, 0x124);
    assert_ne!(eps & TPMA_CC_NV, 0);
    assert_ne!(eps & TPMA_CC_EXTENSIVE, 0);
    let undef = command_attributes(&mut sim, 0x122);
    assert_eq!(undef & TPMA_CC_FLUSHED, 0);
}

/// GetCapability lists HMAC/policy sessions as loaded, then as saved after ContextSave
#[test]
fn loaded_and_saved_session_handles() {
    let mut sim = Tpm::new();

    // Start 1 HMAC session and 1 Policy session
    let start_hmac = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x2B, 0x00, 0x00, 0x01, 0x76, 0x40, 0x00, 0x00, 0x07, 0x40,
        0x00, 0x00, 0x07, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0B,
    ];
    let response = run_raw(&mut sim, &start_hmac);
    assert_eq!(rc_of(&response), 0);
    let handle_hmac = u32::from_be_bytes([response[10], response[11], response[12], response[13]]);

    let start_policy = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x2B, 0x00, 0x00, 0x01, 0x76, 0x40, 0x00, 0x00, 0x07, 0x40,
        0x00, 0x00, 0x07, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x0B,
    ];
    let response = run_raw(&mut sim, &start_policy);
    assert_eq!(rc_of(&response), 0);
    let handle_policy =
        u32::from_be_bytes([response[10], response[11], response[12], response[13]]);

    // Query loaded sessions (TPM_HT_LOADED_SESSION = 0x02)
    let cmd = GetCapability {
        capability: TpmCap::Handles,
        property: 0x02000000,
        property_count: 10,
    };
    let response = run_raw(&mut sim, &no_session_command(TpmCc::GetCapability, &cmd));
    assert_eq!(rc_of(&response), 0);
    let mut unmarsh = &response[10..];
    let _more_data = u8::unmarshal(&mut unmarsh).unwrap();
    let cap_data = tpm2::TpmsCapabilityData::unmarshal(&mut unmarsh).unwrap();
    if let tpm2::TpmsCapabilityData::Handles(handles) = cap_data {
        assert_eq!(handles.count(), 2);
        assert!(handles.handle().iter().any(|h| h.0 == handle_hmac));
        assert!(handles.handle().iter().any(|h| h.0 == handle_policy));
    } else {
        panic!("Expected Handles capability data");
    }

    // Save both sessions using ContextSave (0x0162)
    for handle in [handle_hmac, handle_policy] {
        let mut cs_req = [0u8; 1024];
        let mut cs_off = 0;
        cs_off += marshal_to_slice(&(0x8001u16), &mut cs_req[cs_off..]);
        cs_off += marshal_to_slice(&(0u32), &mut cs_req[cs_off..]);
        cs_off += marshal_to_slice(&(TpmCc::ContextSave.code()), &mut cs_req[cs_off..]);
        cs_off += marshal_to_slice(&(handle), &mut cs_req[cs_off..]);
        let total_cs = cs_off as u32;
        marshal_to_slice(&(total_cs), &mut cs_req[2..6]);
        let response = run_raw(&mut sim, &cs_req[..cs_off]);
        assert_eq!(rc_of(&response), 0);
    }

    // Query saved sessions (TPM_HT_SAVED_SESSION = 0x03)
    let cmd_saved = GetCapability {
        capability: TpmCap::Handles,
        property: 0x03000000,
        property_count: 10,
    };
    let response = run_raw(
        &mut sim,
        &no_session_command(TpmCc::GetCapability, &cmd_saved),
    );
    assert_eq!(rc_of(&response), 0);
    let mut unmarsh = &response[10..];
    let _more_data = u8::unmarshal(&mut unmarsh).unwrap();
    let cap_data = tpm2::TpmsCapabilityData::unmarshal(&mut unmarsh).unwrap();
    if let tpm2::TpmsCapabilityData::Handles(handles) = cap_data {
        assert_eq!(handles.count(), 2);
        // All returned saved session handles must have MSO 0x02 per spec Part 3
        for h in handles.handle().iter().take(handles.count()) {
            assert_eq!(h.0 >> 24, 0x02);
        }
    } else {
        panic!("Expected Handles capability data for saved sessions");
    }
}

/// Loaded sessions are listed in slot order regardless of their HMAC/policy type, so
/// pagination does not skip a policy session in a lower slot.
#[test]
fn loaded_sessions_paginate_in_slot_order() {
    let mut sim = Tpm::new();
    let policy = start_session_raw(&mut sim, 1);
    let hmac = start_session_raw(&mut sim, 0);
    assert_eq!(policy & 0x00FF_FFFF, 0);
    assert_eq!(hmac & 0x00FF_FFFF, 1);
    assert_eq!(policy >> 24, 0x03);
    assert_eq!(hmac >> 24, 0x02);

    let (handles, more) = cap_handles(&mut sim, 0x0200_0000, 8).unwrap();
    assert_eq!(handles, vec![policy, hmac]);
    assert!(!more);

    // Paginate one handle at a time, resuming at last + 1.
    let (page1, more) = cap_handles(&mut sim, 0x0200_0000, 1).unwrap();
    assert_eq!(page1, vec![policy]);
    assert!(more);
    let next = 0x0200_0000 | ((page1[0] & 0x00FF_FFFF) + 1);
    let (page2, more) = cap_handles(&mut sim, next, 1).unwrap();
    assert_eq!(page2, vec![hmac]);
    assert!(!more);
}

/// GetCapability(PCR_PROPERTIES) reports the EXTEND_L2 PCR set
#[test]
fn pcr_extend_l2_property() {
    let mut sim = Tpm::new();

    let cmd = GetCapability {
        capability: TpmCap::PCRProperties,
        property: u32::from(tpm2::TpmPtPcr::EXTEND_L2),
        property_count: 1,
    };
    let response = run_raw(&mut sim, &no_session_command(TpmCc::GetCapability, &cmd));
    let rc = rc_of(&response);
    let res_len = response.len();
    assert_eq!(
        rc, 0,
        "GetCapability failed with rc=0x{:08x}, res_len={}",
        rc, res_len
    );
    assert!(res_len > 10, "res_len <= 10 despite rc=0");
    // Unmarshal response data and verify PCR properties for EXTEND_L2
    let mut unmarsh = &response[10..res_len];
    let more_data = u8::unmarshal(&mut unmarsh).unwrap();
    assert_eq!(more_data, 1);
    let cap_data = tpm2::TpmsCapabilityData::unmarshal(&mut unmarsh).unwrap();
    if let tpm2::TpmsCapabilityData::PcrProperties(props) = cap_data {
        assert_eq!(props.count(), 1);
        assert_eq!(props.pcr_property()[0].tag, tpm2::TpmPtPcr::EXTEND_L2);
        assert_eq!(props.pcr_property()[0].pcr_select[..3], [0xff, 0xff, 0xff]);
    } else {
        panic!("Expected PcrProperties capability data");
    }
}

/// GetCapability(PCR_PROPERTIES) reports the RESET_L2 PCR set
#[test]
fn pcr_reset_l2_property() {
    let mut sim = Tpm::new();

    let cmd = GetCapability {
        capability: TpmCap::PCRProperties,
        property: u32::from(tpm2::TpmPtPcr::RESET_L2),
        property_count: 1,
    };
    let response = run_raw(&mut sim, &no_session_command(TpmCc::GetCapability, &cmd));
    assert_eq!(rc_of(&response), 0);
    let mut unmarsh = &response[10..];
    let _more_data = u8::unmarshal(&mut unmarsh).unwrap();
    let cap_data = tpm2::TpmsCapabilityData::unmarshal(&mut unmarsh).unwrap();
    if let tpm2::TpmsCapabilityData::PcrProperties(props) = cap_data {
        assert_eq!(props.count(), 1);
        assert_eq!(props.pcr_property()[0].tag, tpm2::TpmPtPcr::RESET_L2);
        assert_eq!(props.pcr_property()[0].pcr_select[..3], [0x00, 0x00, 0xf1]);
    } else {
        panic!("Expected PcrProperties capability data");
    }
}

/// GetCapability with propertyCount 0 and u32::MAX succeeds; an invalid capability is TPM_RC_VALUE + RC_P1
#[test]
fn property_count_bounds() {
    let mut sim = Tpm::new();

    // 1. property_count = 0 (should succeed with 0 items per TPM (2 as u16) Spec Section 30.1)
    let cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 0,
    };
    assert!(sim.execute(cmd).is_ok());

    // 2. property_count = u32::MAX (should succeed, bounds to max properties)
    let cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: u32::MAX,
    };
    let resp = sim
        .execute(cmd)
        .expect("GetCapability with property_count=MAX failed");
    if let tpm2::TpmsCapabilityData::TpmProperties(ref props) = resp.capability_data {
        assert!(props.count() > 0);
        assert!(props.count() <= tpm2::TPM2_MAX_TPM_PROPERTIES);
    } else {
        panic!("Expected TpmProperties");
    }

    // 3. Invalid capability (e.g. 0x9999) -> should return TPM_RC_VALUE (132 / 0x84)
    let mut params = 0x9999u32.to_be_bytes().to_vec();
    params.extend_from_slice(&u32::from(TpmPt::FAMILY_INDICATOR).to_be_bytes());
    params.extend_from_slice(&5u32.to_be_bytes());
    let mut req = vec![0x80, 0x01, 0, 0, 0, 0, 0x00, 0x00, 0x01, 0x7a];
    req.extend_from_slice(&params);
    let len = req.len() as u32;
    req[2..6].copy_from_slice(&len.to_be_bytes());
    let mut buf = [0u8; 4096];
    let resp = sim.transact(&req, &mut buf).unwrap();
    let rc = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    assert_eq!(rc, TpmRc::VALUE.with(Position::parameter(1)).get());
}

/// TPM_PT_VENDOR_STRING_* properties spell "TPM-RUST"
#[test]
fn vendor_string_properties() {
    let mut sim = Tpm::new();

    let cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(tpm2::TpmPt::VENDOR_STRING_1),
        property_count: 4,
    };
    let response = run_raw(&mut sim, &no_session_command(TpmCc::GetCapability, &cmd));
    assert_eq!(rc_of(&response), 0);
    let mut unmarsh = &response[10..];
    let _more_data = u8::unmarshal(&mut unmarsh).unwrap();
    let cap_data = tpm2::TpmsCapabilityData::unmarshal(&mut unmarsh).unwrap();
    if let tpm2::TpmsCapabilityData::TpmProperties(props) = cap_data {
        assert_eq!(props.count(), 4);
        assert_eq!(
            props.tpm_property()[0].property,
            tpm2::TpmPt::VENDOR_STRING_1
        );
        assert_eq!(props.tpm_property()[0].value, 0x54504D2D); // "TPM-"
        assert_eq!(
            props.tpm_property()[1].property,
            tpm2::TpmPt::VENDOR_STRING_2
        );
        assert_eq!(props.tpm_property()[1].value, 0x52555354); // "RUST"
        assert_eq!(
            props.tpm_property()[2].property,
            tpm2::TpmPt::VENDOR_STRING_3
        );
        assert_eq!(props.tpm_property()[2].value, 0);
        assert_eq!(
            props.tpm_property()[3].property,
            tpm2::TpmPt::VENDOR_STRING_4
        );
        assert_eq!(props.tpm_property()[3].value, 0);
    } else {
        panic!("Expected TpmProperties capability data");
    }
}

/// `TPM_PT_MAX_OBJECT_CONTEXT` and `TPM_PT_MAX_SESSION_CONTEXT` bound the contexts that
/// TPM2_ContextSave actually returns (an RSA-2048 key, a hash sequence object and a SHA-512 policy
/// session). Before, `tpm-rs` reported a fixed 3072/512 regardless of its context format. TPM 2.0
/// Part 2, TPM_PT: "TPM_PT_MAX_OBJECT_CONTEXT | PT_FIXED + 33 | the maximum size of an object
/// context that will be returned by TPM2_ContextSave()" and "TPM_PT_MAX_SESSION_CONTEXT |
/// PT_FIXED + 34 | the maximum size of a session context that will be returned by
/// TPM2_ContextSave()".
#[test]
fn max_context_sizes_bound_saved_contexts() {
    let mut sim = Tpm::new();
    let max_object = get_tpm_property(&mut sim, TpmPt::MAX_OBJECT_CONTEXT) as usize;
    let max_session = get_tpm_property(&mut sim, TpmPt::MAX_SESSION_CONTEXT) as usize;

    let (key, _) = create_primary(&mut sim, rsa_ek_template());
    let key_context = context_save_raw(&mut sim, key.0).unwrap();
    assert!(
        key_context.len() <= max_object,
        "{} > {max_object}",
        key_context.len()
    );

    let sequence = hash_sequence_start(&mut sim);
    let sequence_context = context_save_raw(&mut sim, sequence.0).unwrap();
    assert!(
        sequence_context.len() <= max_object,
        "{} > {max_object}",
        sequence_context.len()
    );

    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        // The largest implemented digest (SHA-512 with the `sha512` feature).
        STRONGEST_HASH_ALG,
    )
    .unwrap();
    let session_context = context_save_raw(&mut sim, session.session_handle.0).unwrap();
    assert!(
        session_context.len() <= max_session,
        "{} > {max_session}",
        session_context.len()
    );
}

/// TPM_CAP_TPM_PROPERTIES from `TPM_PT_NV_INDEX_MAX` (0x10C) with a `propertyCount` that reaches
/// past the last fixed property this TPM reports: the response lists every implemented property
/// of the group from 0x10C on, in order, and `moreData` is NO, as no value remains (TPM 2.0
/// Part 3, TPM2_GetCapability: "The *moreData* parameter will have a value of YES if there are
/// more values of the requested type that were not returned."). The C references also report the
/// firmware-SVN properties, so their list is cut there (`differential.md` rule 2).
#[test]
fn fixed_properties_to_the_end_of_the_group() {
    let mut tpm = Tpm::new();
    let cmd = [
        0x80, 0x01, 0, 0, 0, 0x16, 0, 0, 0x01, 0x7A, 0, 0, 0, 6, 0, 0, 0x01, 0x0C, 0, 0, 0, 0x24,
    ];
    let rsp = tpm.send_command(0, &cmd);
    assert_eq!(rc_of(&rsp), 0);
    assert_eq!(rsp[10], 0, "moreData");
}

/// TPM_CAP_TPM_PROPERTIES of the last fixed property this TPM reports
/// (`TPM_PT_MAX_CAP_BUFFER`, 0x12E) with `propertyCount` 1: that property, and `moreData` NO, as
/// no further value of this TPM remains (TPM 2.0 Part 3, TPM2_GetCapability: "The *moreData* parameter will have a value of
/// YES if there are more values of the requested type that were not returned."). The C
/// references have their firmware-SVN properties after it (`differential.md` rule 2).
#[test]
fn last_fixed_property_has_no_more_data() {
    let mut tpm = Tpm::new();
    let cmd = [
        0x80, 0x01, 0, 0, 0, 0x16, 0, 0, 0x01, 0x7A, 0, 0, 0, 6, 0, 0, 0x01, 0x2E, 0, 0, 0, 0x01,
    ];
    let rsp = tpm.send_command(0, &cmd);
    assert_eq!(rc_of(&rsp), 0);
    assert_eq!(rsp[10], 0, "moreData");
}
