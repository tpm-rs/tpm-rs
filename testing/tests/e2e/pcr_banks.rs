//! PCR bank handling: bank ordering, unallocated banks and newly allocated banks.

use crate::_common::{mssim_rc_of as rc_of, *};
use testing::tpm::Tpm;
use tpm2::errors::TpmRc;
use tpm2::*;

/// PCR_Read keeps bank order and filters unallocated banks; extends skip them; resets follow PC Client localities.
///
/// `TPM2_PCR_Read` keeps the caller's bank order and filters unallocated banks; extends skip
/// unallocated banks; resets follow the PC Client reset localities; TCB PCRs (20-22) do not
/// bump the update counter; `TPM2_PCR_Event` reports every implemented hash (incl. SHA-512).
#[test]
fn read_order_unallocated_banks_and_reset_localities() {
    let mut sim = Tpm::new();

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

/// After allocating SHA-512 and resetting, its bank can be extended and read in the requested order.
///
/// `TPM2_PCR_Read` preserves the bank order, reads the SHA-512 bank once it is allocated, and
/// ignores unallocated PCRs.
#[test]
fn sha512_bank_readable_after_allocation() {
    let mut sim = Tpm::new();
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

/// Extending/resetting TCB PCRs 20-22 does not bump the update counter; PCR_SetAuthPolicy needs NV.
///
/// Extending, event-extending or resetting a TCB PCR (20-22) does not increment the PCR update
/// counter; `TPM2_PCR_SetAuthPolicy` requires NV; the PCR properties match `PlatformPcr.c`.
#[test]
fn tcb_pcrs_do_not_bump_update_counter() {
    let mut sim = Tpm::new();

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
    let props = cap_pcr_properties(&mut sim, 0, 64);
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
    let (list, more) = cap_pcr_properties(&mut sim, 0x15, 8);
    assert!(list.is_empty());
    assert!(!more);
}
