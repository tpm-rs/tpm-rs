//! Regression tests for the `TPM2_PCR_*` findings.

use super::*;

const CC_PCR_READ: u32 = 0x17E;
const CC_PCR_EXTEND: u32 = 0x182;
const CC_PCR_EVENT: u32 = 0x13C;
const CC_PCR_RESET: u32 = 0x13D;
const CC_PCR_ALLOCATE: u32 = 0x12B;
const CC_PCR_SET_AUTH_POLICY: u32 = 0x12C;
const CC_PCR_SET_AUTH_VALUE: u32 = 0x183;

const ALG_SHA1: u16 = 0x0004;
const ALG_SHA256: u16 = 0x000B;
const ALG_SHA384: u16 = 0x000C;
const ALG_SHA512: u16 = 0x000D;

/// Marshals a `TPML_PCR_SELECTION` from `(hashAlg, pcrSelect)` pairs.
fn pcr_selection(banks: &[(u16, [u8; 3])]) -> Vec<u8> {
    let mut v = (banks.len() as u32).to_be_bytes().to_vec();
    for (alg, bits) in banks {
        v.extend_from_slice(&alg.to_be_bytes());
        v.push(3);
        v.extend_from_slice(bits);
    }
    v
}

/// Selection bits for a single PCR.
fn bit(pcr: usize) -> [u8; 3] {
    let mut b = [0u8; 3];
    b[pcr / 8] |= 1 << (pcr % 8);
    b
}

/// Parsed `TPM2_PCR_Read` response.
struct PcrReadRsp {
    update_counter: u32,
    selection_out: Vec<(u16, Vec<u8>)>,
    values: Vec<Vec<u8>>,
}

/// Sends `TPM2_PCR_Read` for `banks` and parses the response.
fn pcr_read(sim: &mut Simulator<'_>, banks: &[(u16, [u8; 3])]) -> PcrReadRsp {
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        CC_PCR_READ,
        &[],
        None,
        &pcr_selection(banks),
    );
    let (rc, resp) = send(sim, &cmd);
    assert_eq!(rc, 0, "PCR_Read failed: {rc:#x}");
    let p = &resp[10..];
    let update_counter = u32::from_be_bytes(p[0..4].try_into().unwrap());
    let count = u32::from_be_bytes(p[4..8].try_into().unwrap()) as usize;
    let mut off = 8;
    let mut selection_out = Vec::new();
    for _ in 0..count {
        let alg = u16::from_be_bytes(p[off..off + 2].try_into().unwrap());
        let size = p[off + 2] as usize;
        selection_out.push((alg, p[off + 3..off + 3 + size].to_vec()));
        off += 3 + size;
    }
    let n = u32::from_be_bytes(p[off..off + 4].try_into().unwrap()) as usize;
    off += 4;
    let mut values = Vec::new();
    for _ in 0..n {
        let size = u16::from_be_bytes(p[off..off + 2].try_into().unwrap()) as usize;
        values.push(p[off + 2..off + 2 + size].to_vec());
        off += 2 + size;
    }
    PcrReadRsp {
        update_counter,
        selection_out,
        values,
    }
}

fn update_counter(sim: &mut Simulator<'_>) -> u32 {
    pcr_read(sim, &[(ALG_SHA256, [0, 0, 0])]).update_counter
}

/// Marshals a `TPML_DIGEST_VALUES` from `(hashAlg, digest)` pairs.
fn digest_values(digests: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut v = (digests.len() as u32).to_be_bytes().to_vec();
    for (alg, d) in digests {
        v.extend_from_slice(&alg.to_be_bytes());
        v.extend_from_slice(d);
    }
    v
}

/// `TPM2_PCR_Extend(pcr)` at `locality`, authorized with an empty password.
fn pcr_extend_at(
    sim: &mut Simulator<'_>,
    locality: u8,
    pcr: u32,
    digests: &[(u16, Vec<u8>)],
) -> u32 {
    let cmd = build_pw_cmd(CC_PCR_EXTEND, &[pcr], 1, &digest_values(digests));
    send_at(sim, locality, &cmd).0
}

/// `TPM2_PCR_Event(pcr)` at `locality`; returns the response code and the response.
fn pcr_event_at(sim: &mut Simulator<'_>, locality: u8, pcr: u32, data: &[u8]) -> (u32, Vec<u8>) {
    let mut params = (data.len() as u16).to_be_bytes().to_vec();
    params.extend_from_slice(data);
    let cmd = build_pw_cmd(CC_PCR_EVENT, &[pcr], 1, &params);
    send_at(sim, locality, &cmd)
}

/// `TPM2_PCR_Reset(pcr)` at `locality`.
fn pcr_reset_at(sim: &mut Simulator<'_>, locality: u8, pcr: u32) -> u32 {
    let cmd = build_pw_cmd(CC_PCR_RESET, &[pcr], 1, &[]);
    send_at(sim, locality, &cmd).0
}

/// `TPM2_PCR_Allocate` with platform authorization; returns the response code and the
/// response parameters (`allocationSuccess`, `maxPCR`, `sizeNeeded`, `sizeAvailable`).
fn pcr_allocate(
    sim: &mut Simulator<'_>,
    banks: &[(u16, [u8; 3])],
) -> (u32, Option<(u8, u32, u32, u32)>) {
    let cmd = build_pw_cmd(
        CC_PCR_ALLOCATE,
        &[Handle::RH_PLATFORM.0],
        1,
        &pcr_selection(banks),
    );
    let (rc, resp) = send(sim, &cmd);
    if rc != 0 {
        return (rc, None);
    }
    let p = session_rsp_params(&resp, 0);
    let be = |o: usize| u32::from_be_bytes(p[o..o + 4].try_into().unwrap());
    (rc, Some((p[0], be(1), be(5), be(9))))
}

/// Returns the active allocation reported by `TPM2_GetCapability(TPM_CAP_PCRS)`.
fn cap_pcrs(sim: &mut Simulator<'_>) -> Vec<(u16, Vec<u8>)> {
    let mut params = Vec::new();
    params.extend_from_slice(&5u32.to_be_bytes()); // TPM_CAP_PCRS
    params.extend_from_slice(&0u32.to_be_bytes());
    params.extend_from_slice(&1u32.to_be_bytes());
    let cmd = build_cmd(ST_NO_SESSIONS, 0x17A, &[], None, &params);
    let (rc, resp) = send(sim, &cmd);
    assert_eq!(rc, 0, "GetCapability(PCRS) failed: {rc:#x}");
    let p = &resp[10 + 1 + 4..];
    let count = u32::from_be_bytes(p[0..4].try_into().unwrap()) as usize;
    let mut off = 4;
    let mut out = Vec::new();
    for _ in 0..count {
        let alg = u16::from_be_bytes(p[off..off + 2].try_into().unwrap());
        let size = p[off + 2] as usize;
        out.push((alg, p[off + 3..off + 3 + size].to_vec()));
        off += 3 + size;
    }
    out
}

/// Computes `alg(data)` on the client side.
fn client_hash(alg: TpmiAlgHash, data: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    tpm2::crypto::hash(CLIENT_CRYPTO, alg, data, &mut buf)
        .unwrap()
        .digest()
        .to_vec()
}

/// `TPM2_PCR_Read` keeps the caller's bank order and filters unallocated banks; extends skip
/// unallocated banks; resets follow the PC Client reset localities; TCB PCRs (20-22) do not
/// bump the update counter; `TPM2_PCR_Event` reports every implemented hash (incl. SHA-512).
#[test]
fn tpm2_pcr_commands_ignore_bank_allocation_reorder_selections_and_mishandle_reset_localities() {
    let mut sim = create_simulator!();

    // 1. Input order is preserved (SHA-256 before SHA-1).
    let rsp = pcr_read(&mut sim, &[(ALG_SHA256, bit(0)), (ALG_SHA1, bit(0))]);
    let algs: Vec<u16> = rsp.selection_out.iter().map(|(a, _)| *a).collect();
    assert_eq!(algs, vec![ALG_SHA256, ALG_SHA1]);
    assert_eq!(rsp.values.len(), 2);
    assert_eq!(rsp.values[0].len(), 32);
    assert_eq!(rsp.values[1].len(), 20);

    // 2. The SHA-384 bank is not allocated by default: no values, bits cleared (FilterPcr).
    let rsp = pcr_read(&mut sim, &[(ALG_SHA384, bit(1))]);
    assert_eq!(rsp.selection_out, vec![(ALG_SHA384, vec![0, 0, 0])]);
    assert!(rsp.values.is_empty());

    // 3. Extending only an unallocated bank changes nothing (no update counter increment).
    let before = update_counter(&mut sim);
    assert_eq!(
        pcr_extend_at(&mut sim, 0, 1, &[(ALG_SHA384, vec![0xAB; 48])]),
        0
    );
    assert_eq!(update_counter(&mut sim), before);
    // Extending two allocated banks counts one change per bank (PCRChanged per PCRExtend).
    assert_eq!(
        pcr_extend_at(
            &mut sim,
            0,
            1,
            &[(ALG_SHA1, vec![1; 20]), (ALG_SHA256, vec![2; 32])]
        ),
        0
    );
    assert_eq!(update_counter(&mut sim), before + 2);

    // 4. PCR 20 can be reset from locality 2 (resetLocality 0x14) but not from locality 0.
    assert_eq!(pcr_reset_at(&mut sim, 0, 20), TpmRc::LOCALITY.get());
    let before = update_counter(&mut sim);
    assert_eq!(pcr_reset_at(&mut sim, 2, 20), 0);
    // ...and as a TCB PCR its reset does not bump the update counter.
    assert_eq!(update_counter(&mut sim), before);
    let rsp = pcr_read(&mut sim, &[(ALG_SHA256, bit(20))]);
    assert_eq!(rsp.values[0], vec![0u8; 32]);
    // PCR 17 is reset only by locality 4, which TPM2_PCR_Reset never accepts (DRTM).
    assert_eq!(pcr_reset_at(&mut sim, 2, 17), TpmRc::LOCALITY.get());
    assert_eq!(pcr_reset_at(&mut sim, 4, 17), TpmRc::LOCALITY.get());

    // 5. PCR_Event reports SHA-1, SHA-256, SHA-384 and SHA-512 digests.
    let (rc, resp) = pcr_event_at(&mut sim, 0, Handle::RH_NULL.0, b"event");
    assert_eq!(rc, 0);
    let p = session_rsp_params(&resp, 0);
    let count = u32::from_be_bytes(p[0..4].try_into().unwrap());
    let mut algs = Vec::new();
    let mut off = 4;
    for _ in 0..count {
        let alg = u16::from_be_bytes(p[off..off + 2].try_into().unwrap());
        let size = match alg {
            ALG_SHA1 => 20,
            ALG_SHA256 => 32,
            ALG_SHA384 => 48,
            ALG_SHA512 => 64,
            other => panic!("unexpected alg {other:#x}"),
        };
        algs.push(alg);
        off += 2 + size;
    }
    assert_eq!(algs, vec![ALG_SHA1, ALG_SHA256, ALG_SHA384, ALG_SHA512]);
}

/// Extending, event-extending or resetting a TCB PCR (20-22) does not increment the PCR update
/// counter; `TPM2_PCR_SetAuthPolicy` requires NV; the PCR properties match `PlatformPcr.c`.
#[test]
fn pcr_tcb_counter_increment_and_pcr_properties_capability_bugs() {
    let mut sim = create_simulator!();

    // PCR 21/22 are extendable only from locality 2.
    let before = update_counter(&mut sim);
    assert_eq!(
        pcr_extend_at(&mut sim, 2, 21, &[(ALG_SHA256, vec![7; 32])]),
        0
    );
    assert_eq!(pcr_event_at(&mut sim, 2, 22, b"tcb").0, 0);
    assert_eq!(pcr_reset_at(&mut sim, 2, 21), 0);
    assert_eq!(update_counter(&mut sim), before);
    // A non-TCB PCR still counts.
    assert_eq!(
        pcr_extend_at(&mut sim, 0, 16, &[(ALG_SHA256, vec![7; 32])]),
        0
    );
    assert_eq!(update_counter(&mut sim), before + 1);

    // TPM2_PCR_SetAuthPolicy: RETURN_IF_NV_IS_NOT_AVAILABLE.
    let mut params = 0u16.to_be_bytes().to_vec(); // authPolicy (empty)
    params.extend_from_slice(&0x0010u16.to_be_bytes()); // hashAlg = NULL
    params.extend_from_slice(&20u32.to_be_bytes()); // pcrNum
    let cmd = build_pw_cmd(CC_PCR_SET_AUTH_POLICY, &[Handle::RH_PLATFORM.0], 1, &params);
    nv_off(&mut sim);
    assert_eq!(rc_of(&mut sim, &cmd), TpmRc::NV_UNAVAILABLE.get());
    nv_on(&mut sim);
    assert_eq!(rc_of(&mut sim, &cmd), 0);

    // PCR properties (TPM_CAP_PCR_PROPERTIES) for the whole range.
    let props = super::capability::cap_pcr_properties(&mut sim, 0, 64);
    let get = |tag: u32| {
        props
            .0
            .iter()
            .find(|(t, _)| *t == tag)
            .map(|(_, b)| b.clone())
            .unwrap_or_else(|| panic!("missing property {tag:#x}"))
    };
    assert_eq!(get(0x08), vec![0x00, 0x00, 0x81], "RESET_L3");
    assert_eq!(get(0x11), vec![0x00, 0x00, 0x70], "NO_INCREMENT");
    assert_eq!(get(0x13), vec![0x00, 0x00, 0x70], "POLICY");
    assert_eq!(get(0x14), vec![0x00, 0x00, 0x70], "AUTH");
    // A start property beyond TPM_PT_PCR_LAST yields an empty list, not an error.
    let (list, more) = super::capability::cap_pcr_properties(&mut sim, 0x15, 8);
    assert!(list.is_empty());
    assert!(!more);
}

/// `TPM2_PCR_Read` preserves the bank order, reads the SHA-512 bank once it is allocated, and
/// ignores unallocated PCRs.
#[test]
fn pcr_read_and_compute_pcr_digest_sha512_and_bank_order_bugs() {
    let mut sim = create_simulator!();
    let rsp = pcr_read(&mut sim, &[(ALG_SHA256, bit(3)), (ALG_SHA1, bit(3))]);
    assert_eq!(rsp.selection_out[0].0, ALG_SHA256);
    assert_eq!(rsp.selection_out[1].0, ALG_SHA1);

    // Allocate the SHA-512 bank (all PCRs) and reset the TPM so it becomes active.
    let (rc, _) = pcr_allocate(&mut sim, &[(ALG_SHA512, [0xFF, 0xFF, 0xFF])]);
    assert_eq!(rc, 0);
    tpm_reset(&mut sim);
    let rsp = pcr_read(&mut sim, &[(ALG_SHA512, bit(0))]);
    assert_eq!(rsp.selection_out, vec![(ALG_SHA512, bit(0).to_vec())]);
    assert_eq!(rsp.values, vec![vec![0u8; 64]]);

    // Extending the SHA-512 bank works and is visible through PCR_Read.
    assert_eq!(
        pcr_extend_at(&mut sim, 0, 0, &[(ALG_SHA512, vec![5; 64])]),
        0
    );
    let rsp = pcr_read(&mut sim, &[(ALG_SHA512, bit(0))]);
    let mut data = vec![0u8; 64];
    data.extend_from_slice(&[5u8; 64]);
    assert_eq!(rsp.values[0], client_hash(TpmiAlgHash::Sha512, &data));
}

/// `TPM2_PCR_Allocate` only changes the NV copy of the allocation (active after the next TPM
/// Reset, and kept across it); `TPM2_PCR_SetAuthPolicy` requires NV.
#[test]
fn pcr_allocate_setauthvalue_setauthpolicy_persistence_and_error_bugs() {
    let mut sim = create_simulator!();
    let before = cap_pcrs(&mut sim);
    let sha1_before = before
        .iter()
        .find(|(a, _)| *a == ALG_SHA1)
        .unwrap()
        .1
        .clone();
    assert_eq!(sha1_before, vec![0xFF, 0xFF, 0xFF]);

    // Deallocate the SHA-1 bank.
    let (rc, rsp) = pcr_allocate(&mut sim, &[(ALG_SHA1, [0, 0, 0])]);
    assert_eq!(rc, 0);
    assert_eq!(rsp.unwrap().0, 1, "allocationSuccess");
    // The active allocation is unchanged until the next TPM Reset.
    assert_eq!(cap_pcrs(&mut sim), before);
    let rsp = pcr_read(&mut sim, &[(ALG_SHA1, bit(0))]);
    assert_eq!(rsp.values.len(), 1);

    tpm_reset(&mut sim);
    let after = cap_pcrs(&mut sim);
    assert_eq!(
        after.iter().find(|(a, _)| *a == ALG_SHA1).unwrap().1,
        vec![0, 0, 0]
    );
    let rsp = pcr_read(&mut sim, &[(ALG_SHA1, bit(0))]);
    assert!(rsp.values.is_empty());

    // The allocation survives another reset.
    tpm_reset(&mut sim);
    assert_eq!(cap_pcrs(&mut sim), after);
}

/// `TPM2_PCR_Allocate` requires the DRTM PCR (17) itself, computes `sizeNeeded` /
/// `sizeAvailable`, and checks NV availability unconditionally.
#[test]
fn pcr_allocate_drtm_mask_and_size_needed_reporting() {
    let mut sim = create_simulator!();

    // Removing PCR 17 from every bank while keeping PCR 18 is rejected.
    let no17 = [0xFF, 0xFF, 0xFD];
    let (rc, _) = pcr_allocate(
        &mut sim,
        &[
            (ALG_SHA1, no17),
            (ALG_SHA256, no17),
            (ALG_SHA384, [0, 0, 0]),
            (ALG_SHA512, [0, 0, 0]),
        ],
    );
    assert_eq!(rc, TpmRc::PCR.get());

    // sizeNeeded = sum over the new allocation of popcount * digest size.
    let (rc, rsp) = pcr_allocate(&mut sim, &[(ALG_SHA384, [0x01, 0x00, 0x02])]);
    assert_eq!(rc, 0);
    let (success, max_pcr, size_needed, size_available) = rsp.unwrap();
    assert_eq!(success, 1);
    assert_eq!(max_pcr, 24);
    assert_eq!(size_needed, 24 * 20 + 24 * 32 + 2 * 48);
    assert_eq!(size_available, 24 * (20 + 32 + 48 + 64));

    // NV unavailable -> TPM_RC_NV_UNAVAILABLE, even though the TPM is not orderly.
    nv_off(&mut sim);
    let (rc, _) = pcr_allocate(&mut sim, &[(ALG_SHA384, [0, 0, 0])]);
    assert_eq!(rc, TpmRc::NV_UNAVAILABLE.get());
    nv_on(&mut sim);
}

/// `TPM2_PCR_SetAuthPolicy` checks NV availability; `TPM2_PCR_SetAuthValue` rejects a PCR handle
/// above `PCR_LAST` with `TPM_RC_VALUE + RC_H1`.
#[test]
fn pcr_set_auth_policy_and_pcr_set_auth_value_nv_auth_and_unmarshal_bugs() {
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
