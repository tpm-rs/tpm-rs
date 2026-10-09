//! Regression tests for the `TPM2_GetCapability`, `TPM2_TestParms` and `TPM2_ECC_Parameters`
//! findings.

use super::*;

const CC_GET_CAPABILITY: u32 = 0x17A;
const CC_TEST_PARMS: u32 = 0x18A;
const CC_ECC_PARAMETERS: u32 = 0x178;
const CC_DA_PARAMETERS: u32 = 0x13A;

const CAP_ALGS: u32 = 0;
const CAP_HANDLES: u32 = 1;
const CAP_COMMANDS: u32 = 2;
const CAP_PCRS: u32 = 5;
const CAP_PCR_PROPERTIES: u32 = 7;
const CAP_ACT: u32 = 0xA;

/// Sends `TPM2_GetCapability(capability, property, count)`. On success returns `moreData` and
/// the capability data that follows the `capability` selector.
pub(crate) fn get_cap(
    sim: &mut Simulator<'_>,
    capability: u32,
    property: u32,
    count: u32,
) -> Result<(bool, Vec<u8>), u32> {
    let mut params = Vec::new();
    params.extend_from_slice(&capability.to_be_bytes());
    params.extend_from_slice(&property.to_be_bytes());
    params.extend_from_slice(&count.to_be_bytes());
    let cmd = build_cmd(ST_NO_SESSIONS, CC_GET_CAPABILITY, &[], None, &params);
    let (rc, resp) = send(sim, &cmd);
    if rc != 0 {
        return Err(rc);
    }
    let more = resp[10] != 0;
    assert_eq!(
        u32::from_be_bytes(resp[11..15].try_into().unwrap()),
        capability
    );
    Ok((more, resp[15..].to_vec()))
}

/// Returns the list of `(tag, pcrSelect)` from `TPM_CAP_PCR_PROPERTIES` and `moreData`.
pub(crate) fn cap_pcr_properties(
    sim: &mut Simulator<'_>,
    property: u32,
    count: u32,
) -> (Vec<(u32, Vec<u8>)>, bool) {
    let (more, data) = get_cap(sim, CAP_PCR_PROPERTIES, property, count)
        .unwrap_or_else(|rc| panic!("GetCapability(PCR_PROPERTIES) failed: {rc:#x}"));
    let n = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
    let mut off = 4;
    let mut out = Vec::new();
    for _ in 0..n {
        let tag = u32::from_be_bytes(data[off..off + 4].try_into().unwrap());
        let size = data[off + 4] as usize;
        out.push((tag, data[off + 5..off + 5 + size].to_vec()));
        off += 5 + size;
    }
    (out, more)
}

/// Returns the list of handles from `TPM_CAP_HANDLES` and `moreData`.
fn cap_handles(
    sim: &mut Simulator<'_>,
    property: u32,
    count: u32,
) -> Result<(Vec<u32>, bool), u32> {
    let (more, data) = get_cap(sim, CAP_HANDLES, property, count)?;
    let n = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
    let handles = (0..n)
        .map(|i| u32::from_be_bytes(data[4 + 4 * i..8 + 4 * i].try_into().unwrap()))
        .collect();
    Ok((handles, more))
}

/// Returns the `TPMA_CC` of command `cc` from `TPM_CAP_COMMANDS`.
fn command_attributes(sim: &mut Simulator<'_>, cc: u32) -> u32 {
    let (_, data) = get_cap(sim, CAP_COMMANDS, cc, 1).unwrap();
    assert_eq!(u32::from_be_bytes(data[0..4].try_into().unwrap()), 1);
    let attr = u32::from_be_bytes(data[4..8].try_into().unwrap());
    assert_eq!(attr & 0xFFFF, cc, "command not implemented");
    attr
}

const TPMA_CC_NV: u32 = 1 << 22;
const TPMA_CC_EXTENSIVE: u32 = 1 << 23;
const TPMA_CC_FLUSHED: u32 = 1 << 24;

/// Sets the dictionary-attack parameters with lockout authorization (empty password).
fn da_parameters(sim: &mut Simulator<'_>, max_tries: u32, recovery: u32, lockout_recovery: u32) {
    let mut params = max_tries.to_be_bytes().to_vec();
    params.extend_from_slice(&recovery.to_be_bytes());
    params.extend_from_slice(&lockout_recovery.to_be_bytes());
    let cmd = build_pw_cmd(CC_DA_PARAMETERS, &[Handle::RH_LOCKOUT.0], 1, &params);
    assert_eq!(rc_of(sim, &cmd), 0, "DictionaryAttackParameters failed");
}

/// Power cycles the TPM, optionally after an orderly `TPM2_Shutdown(TPM_SU_CLEAR)`.
fn power_cycle(sim: &mut Simulator<'_>, orderly: bool) {
    if orderly {
        let shutdown = build_cmd(ST_NO_SESSIONS, 0x145, &[], None, &0u16.to_be_bytes());
        assert_eq!(rc_of(sim, &shutdown), 0);
    }
    sim.signal_platform(SimulatorPlatformSignal::PowerOff)
        .unwrap();
    sim.power_on_start_up();
}

/// `TPM_CAP_TPM_PROPERTIES` reports live DA values, the number of loaded sessions, the real
/// `orderly` flag and `tpmGeneratedEPS`; `TPM_CAP_HANDLES` rejects unsupported handle types with
/// `TPM_RC_HANDLE + RC_P2` and returns an empty list past `PCR_LAST`; `TPM_CAP_COMMANDS` matches
/// `CommandAttributeData.h`.
#[test]
fn tpm2_getcapability_auth_policies_panic_and_property_bugs() {
    let mut sim = create_simulator!();

    da_parameters(&mut sim, 7, 11, 13);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::LOCKOUT_COUNTER), 0);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::MAX_AUTH_FAIL), 7);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::LOCKOUT_INTERVAL), 11);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::LOCKOUT_RECOVERY), 13);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::AUDIT_COUNTER_0), 0);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::AUDIT_COUNTER_1), 0);

    // HR_LOADED counts loaded sessions, not transient objects.
    let transient_avail = get_tpm_property(&mut sim, TpmPt::HR_TRANSIENT_AVAIL);
    let _primary = create_primary(&mut sim, Handle::RH_OWNER);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::HR_LOADED), 0);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::HR_LOADED_AVAIL), 3);
    let _session = start_session(&mut sim, 0);
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
    power_cycle(&mut sim, false);
    let startup_clear = get_tpm_property(&mut sim, TpmPt::STARTUP_CLEAR);
    assert_eq!(
        startup_clear & (1 << 31),
        0,
        "orderly after an unorderly shutdown"
    );
    power_cycle(&mut sim, true);
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

/// `newMaxTries == 0` puts the TPM in lockout: `TPM_PT_PERMANENT.inLockout` is reported.
#[test]
fn tpm2_dictionaryattackparameters_maxtries_zero_disables_lockout_and_omits_nv_sync() {
    let mut sim = create_simulator!();
    let permanent = get_tpm_property(&mut sim, TpmPt::PERMANENT);
    assert_eq!(permanent & (1 << 9), 0, "inLockout before");
    da_parameters(&mut sim, 0, 1000, 1000);
    let permanent = get_tpm_property(&mut sim, TpmPt::PERMANENT);
    assert_ne!(permanent & (1 << 9), 0, "inLockout with maxTries == 0");
}

/// `TPM_CAP_COMMANDS`: `ChangeEPS`/`ChangePPS` are `nv` + `extensive`, and the
/// `NV_UndefineSpace*` commands are not `flushed` (`CommandAttributeData.h`).
#[test]
fn get_command_attribute_tpma_cc_divergences() {
    let mut sim = create_simulator!();
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

/// Loaded sessions are listed in slot order regardless of their HMAC/policy type, so
/// pagination does not skip a policy session in a lower slot.
#[test]
fn getcapability_handles_loaded_session_sort_order_and_pagination_bug() {
    let mut sim = create_simulator!();
    let policy = start_session(&mut sim, 1);
    let hmac = start_session(&mut sim, 0);
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

/// `TPM_CAP_ALGS` reports MGF1 and the KDFs, and the full `KEYEDHASH` attributes.
#[test]
fn getcapability_algs_ecccurves_and_auditcommands_omissions() {
    let mut sim = create_simulator!();
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

/// `TPM_CAP_HANDLES` / `TPM_CAP_PCRS` / `TPM_CAP_PCR_PROPERTIES` / `TPM_CAP_ACT` edge cases.
#[test]
fn tpm2_getcapability_handles_pcrs_and_pcrproperties_discrepancies() {
    let mut sim = create_simulator!();

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

/// `TPM_CAP_ACT` reports `TPM_RC_VALUE + RC_P2`, not `RC_P1`.
#[test]
fn getcapability_unmarshal_error_loss_and_act_ppcommands_bugs() {
    let mut sim = create_simulator!();
    for property in [0x4000_0110, 0x4000_011F, 0x0000_0000] {
        assert_eq!(
            get_cap(&mut sim, CAP_ACT, property, 1).map(|_| ()),
            Err(rc_p(TpmRc::VALUE, 2)),
            "property {property:#x}"
        );
    }
}

/// Sends `TPM2_TestParms` with the raw `TPMT_PUBLIC_PARMS` bytes.
fn test_parms(sim: &mut Simulator<'_>, parms: &[u8]) -> u32 {
    let cmd = build_cmd(ST_NO_SESSIONS, CC_TEST_PARMS, &[], None, parms);
    rc_of(sim, &cmd)
}

/// `TPMT_PUBLIC_PARMS` of a SYMCIPHER AES-128 key with `mode`.
fn symcipher_parms(mode: u16) -> Vec<u8> {
    let mut v = 0x0025u16.to_be_bytes().to_vec();
    v.extend_from_slice(&0x0006u16.to_be_bytes());
    v.extend_from_slice(&128u16.to_be_bytes());
    v.extend_from_slice(&mode.to_be_bytes());
    v
}

/// `TPMT_PUBLIC_PARMS` of an RSA key without symmetric/scheme and `key_bits`.
fn rsa_parms(symmetric: &[u8], key_bits: u16) -> Vec<u8> {
    let mut v = 0x0001u16.to_be_bytes().to_vec();
    v.extend_from_slice(symmetric);
    v.extend_from_slice(&0x0010u16.to_be_bytes()); // scheme NULL
    v.extend_from_slice(&key_bits.to_be_bytes());
    v.extend_from_slice(&0u32.to_be_bytes());
    v
}

/// `TPM2_TestParms` accepts every implemented block-cipher mode (also as the symmetric
/// definition of an RSA key). RSA-3072/4096 stay unsupported (see the log: go-tpm parity).
#[test]
fn tpm2_testparms_rejects_non_cfb_symmetric_modes_and_rsa_3072_4096() {
    let mut sim = create_simulator!();
    for mode in [0x0040u16, 0x0041, 0x0042, 0x0043, 0x0044, 0x0010] {
        assert_eq!(
            test_parms(&mut sim, &symcipher_parms(mode)),
            0,
            "mode {mode:#x}"
        );
    }
    assert_eq!(
        test_parms(&mut sim, &rsa_parms(&0x0010u16.to_be_bytes(), 2048)),
        0
    );
    // RSA with an AES-128-CTR symmetric definition.
    let mut sym = 0x0006u16.to_be_bytes().to_vec();
    sym.extend_from_slice(&128u16.to_be_bytes());
    sym.extend_from_slice(&0x0040u16.to_be_bytes());
    assert_eq!(test_parms(&mut sim, &rsa_parms(&sym, 2048)), 0);
}

/// `TPM2_TestParms` accepts a NULL KDF in `TPMS_SCHEME_XOR` and reports trailing bytes as
/// `TPM_RC_SIZE`.
#[test]
fn test_parms_null_scheme_hash_xor_kdf_and_trailing_bytes() {
    let mut sim = create_simulator!();
    let mut xor = 0x0008u16.to_be_bytes().to_vec();
    xor.extend_from_slice(&0x000Au16.to_be_bytes()); // XOR
    xor.extend_from_slice(&0x000Bu16.to_be_bytes()); // SHA256
    xor.extend_from_slice(&0x0010u16.to_be_bytes()); // kdf NULL
    assert_eq!(test_parms(&mut sim, &xor), 0);

    let mut trailing = symcipher_parms(0x0043);
    trailing.push(0);
    assert_eq!(test_parms(&mut sim, &trailing), TpmRc::SIZE.get());
}

/// Truncated `TPM2_TestParms` input reports the unmarshal error; `TPM2_ECC_Parameters` rejects an
/// unimplemented curve before checking for trailing bytes.
#[test]
fn test_parms_and_ecc_parameters_unmarshal_underflow_and_trailing_bytes_error_bugs() {
    let mut sim = create_simulator!();
    let mut trailing = symcipher_parms(0x0043);
    trailing.push(0xAA);
    assert_eq!(test_parms(&mut sim, &trailing), TpmRc::SIZE.get());

    // SYMCIPHER / AES without keyBits and mode.
    let mut truncated = 0x0025u16.to_be_bytes().to_vec();
    truncated.extend_from_slice(&0x0006u16.to_be_bytes());
    assert_eq!(
        test_parms(&mut sim, &truncated),
        rc_p(TpmRc::INSUFFICIENT, 1)
    );

    // NIST P-192 unmarshals as a curve ID but is not implemented.
    let mut params = 0x0001u16.to_be_bytes().to_vec();
    params.push(0);
    let cmd = build_cmd(ST_NO_SESSIONS, CC_ECC_PARAMETERS, &[], None, &params);
    assert_eq!(rc_of(&mut sim, &cmd), rc_p(TpmRc::CURVE, 1));
    // An implemented curve with trailing bytes is a size error.
    let mut params = 0x0003u16.to_be_bytes().to_vec();
    params.push(0);
    let cmd = build_cmd(ST_NO_SESSIONS, CC_ECC_PARAMETERS, &[], None, &params);
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::SIZE.get());
}

/// `TPM2_ECC_Parameters(TPM_ECC_NIST_P224)` returns the FIPS 186-4 domain parameters and the
/// curve's KDF (`KDF1_SP800_56A` with SHA-256), as `CryptEccData.c`.
#[test]
fn tpm2_ecc_parameters_nistp224_corrupted_order_and_error_bugs() {
    let mut sim = create_simulator!();
    let expected_kdf: [(u16, u16); 4] = [
        (0x0002, 0x000B),
        (0x0003, 0x000B),
        (0x0004, 0x000C),
        (0x0005, 0x000D),
    ];
    for (curve, kdf_hash) in expected_kdf {
        let cmd = build_cmd(
            ST_NO_SESSIONS,
            CC_ECC_PARAMETERS,
            &[],
            None,
            &curve.to_be_bytes(),
        );
        let (rc, resp) = send(&mut sim, &cmd);
        assert_eq!(rc, 0);
        let p = &resp[10..];
        assert_eq!(u16::from_be_bytes(p[0..2].try_into().unwrap()), curve);
        assert_eq!(
            u16::from_be_bytes(p[4..6].try_into().unwrap()),
            0x0020,
            "kdf scheme"
        );
        assert_eq!(
            u16::from_be_bytes(p[6..8].try_into().unwrap()),
            kdf_hash,
            "kdf hash"
        );
        if curve != 0x0002 {
            continue;
        }
        // sign scheme (NULL), then p, a, b, gX, gY, n, h.
        assert_eq!(u16::from_be_bytes(p[8..10].try_into().unwrap()), 0x0010);
        let mut off = 10;
        let mut fields = Vec::new();
        for _ in 0..7 {
            let size = u16::from_be_bytes(p[off..off + 2].try_into().unwrap()) as usize;
            fields.push(p[off + 2..off + 2 + size].to_vec());
            off += 2 + size;
        }
        let hex = |s: &str| {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect::<Vec<u8>>()
        };
        assert_eq!(
            fields[1],
            hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE"),
            "a"
        );
        assert_eq!(
            fields[5],
            hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D"),
            "n"
        );
        assert_eq!(fields[6], vec![1], "h");
    }
}
