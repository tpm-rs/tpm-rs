//! TPM2_PCR_Allocate: allocation rules, required PCRs, NV requirements and activation on reset.

use crate::_common::{send_raw_at as send_at, *};
use testing::tpm::{SimulatorPlatformSignal, Tpm};
use tpm2::commands::responses;
use tpm2::errors::{Position, TpmRc};
use tpm2::*;

/// PCR_Allocate changes only the NV allocation, active after the next TPM Reset and kept across resets.
///
/// `TPM2_PCR_Allocate` only changes the NV copy of the allocation (active after the next TPM
/// Reset, and kept across it); `TPM2_PCR_SetAuthPolicy` requires NV.
#[test]
fn allocation_takes_effect_after_reset() {
    let mut sim = Tpm::new();
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

/// PCR_Allocate leaving neither H-CRTM nor DRTM PCR allocated fails with PCR.
///
/// `TPM2_PCR_Allocate` that leaves neither the H-CRTM nor the DRTM PCR
/// allocated in any bank fails with `TPM_RC_PCR`.
#[test]
fn allocation_without_crtm_or_drtm_rejected() {
    let mut sim = Tpm::new();

    let sha1_sel = TpmsPcrSelection::new(TpmiAlgHash::Sha1, &[0x00, 0x00, 0x00]).unwrap();
    let sha256_sel = TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0x00, 0x00, 0x00]).unwrap();
    let sha384_sel = TpmsPcrSelection::new(TpmiAlgHash::Sha384, &[0x00, 0x00, 0x00]).unwrap();
    let rsp = send_at(
        &mut sim,
        0,
        &pcr_allocate_cmd(Handle::RH_PLATFORM, &[sha1_sel, sha256_sel, sha384_sel]),
    );
    assert_eq!(
        rc_of(&rsp),
        TpmRc::PCR.get(),
        "TPM2_PCR_Allocate missing HCRTM or DRTM PCR should return TPM_RC_PCR"
    );
}

/// PCR_Allocate requires DRTM PCR 17, reports sizeNeeded/sizeAvailable and needs NV.
///
/// `TPM2_PCR_Allocate` requires the DRTM PCR (17) itself, computes `sizeNeeded` /
/// `sizeAvailable`, and checks NV availability unconditionally.
#[test]
fn drtm_pcr_required_and_size_reporting() {
    let mut sim = Tpm::new();

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

/// PCR_Allocate under the owner hierarchy fails.
///
/// `TPM2_PCR_Allocate` under the owner hierarchy fails.
#[test]
fn owner_allocate_rejected() {
    let mut sim = Tpm::new();

    let sha256_sel = TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0xFF, 0xFF, 0xFF]).unwrap();
    let rsp = send_at(
        &mut sim,
        0,
        &pcr_allocate_cmd(Handle::RH_OWNER, &[sha256_sel]),
    );
    assert_ne!(
        rc_of(&rsp),
        0,
        "TPM2_PCR_Allocate under Owner hierarchy should fail"
    );
}

/// After PCR_Allocate, Shutdown(STATE) fails with TYPE+P1 while Shutdown(CLEAR) succeeds.
///
/// After a successful `TPM2_PCR_Allocate`, `TPM2_Shutdown(STATE)` is rejected
/// with `TPM_RC_TYPE` while `TPM2_Shutdown(CLEAR)` succeeds.
#[test]
fn pending_allocation_blocks_shutdown_state() {
    let mut sim = Tpm::new();

    // 1. Reallocate PCRs
    let sha256_sel = TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0xFF, 0xFF, 0xFF]).unwrap();
    let rsp = send_at(
        &mut sim,
        0,
        &pcr_allocate_cmd(Handle::RH_PLATFORM, &[sha256_sel]),
    );
    assert_eq!(rc_of(&rsp), 0);

    // 2. Try TPM2_Shutdown(STATE) -> should fail with TpmRc::TYPE for parameter 1
    let rsp = send_at(&mut sim, 0, &SHUTDOWN_STATE);
    assert_eq!(
        rc_of(&rsp),
        TpmRc::TYPE.with(Position::parameter(1)).get(),
        "TPM2_Shutdown(STATE) should fail if PCR reconfig is pending"
    );

    // 3. Try TPM2_Shutdown(CLEAR) -> should succeed
    let rsp = send_at(&mut sim, 0, &SHUTDOWN_CLEAR);
    assert_eq!(
        rc_of(&rsp),
        0,
        "TPM2_Shutdown(CLEAR) should succeed even with PCR reconfig pending"
    );
}

/// PCR_Allocate under platform auth succeeds and reports C maxPCR, sizeNeeded and sizeAvailable.
///
/// `TPM2_PCR_Allocate` under the platform hierarchy succeeds and reports the
/// C reference's `maxPCR`, `sizeNeeded` and `sizeAvailable`.
#[test]
fn platform_allocate_reports_sizes() {
    let mut sim = Tpm::new();

    let sha256_sel = TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0xFF, 0xFF, 0xFF]).unwrap();
    let rsp = send_at(
        &mut sim,
        0,
        &pcr_allocate_cmd(Handle::RH_PLATFORM, &[sha256_sel]),
    );
    assert_eq!(
        rc_of(&rsp),
        0,
        "TPM2_PCR_Allocate under Platform hierarchy should succeed"
    );

    let mut resp_slice = &rsp[14..]; // skip the response parameterSize
    let rsp = responses::PCRAllocate::unmarshal_with_handles([], &mut resp_slice)
        .expect("unmarshal PCRAllocateRsp");
    assert!(rsp.allocation_success);
    assert_eq!(rsp.max_pcr, 24);
    // C PCRAllocate sums the digest sizes of every PCR in the resulting allocation
    // (PCR.c:939-972): existing SHA1 bank 24 * 20 + new SHA256 bank 24 * 32 = 1248.
    assert_eq!(rsp.size_needed, 1248);
    // C reports sizeof(s_pcrs), i.e. room for every implemented bank (PCR.c:981):
    // 24 * (20 + 32 + 48 + 64) = 3936.
    assert_eq!(rsp.size_available, 3936);
}

/// A new PCR allocation is inactive until Shutdown(CLEAR) + _TPM_Init + Startup(CLEAR) allocates SHA-384.
///
/// A `TPM2_PCR_Allocate` only takes effect at the next TPM Reset: the active
/// allocation is unchanged until then, and after Shutdown(CLEAR), `_TPM_Init`
/// and Startup(CLEAR) the new SHA-384 bank is allocated.
#[test]
fn sha384_bank_active_after_startup_clear() {
    let mut sim = Tpm::new();

    // 1. Allocate PCRs: enable sha256 and sha384 with [0xFF, 0xFF, 0xFF]
    let sha256_sel = TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0xFF, 0xFF, 0xFF]).unwrap();
    let sha384_sel = TpmsPcrSelection::new(TpmiAlgHash::Sha384, &[0xFF, 0xFF, 0xFF]).unwrap();
    let rsp = send_at(
        &mut sim,
        0,
        &pcr_allocate_cmd(Handle::RH_PLATFORM, &[sha256_sel, sha384_sel]),
    );
    assert_eq!(rc_of(&rsp), 0, "TPM2_PCR_Allocate should succeed");

    // Like C (PCRAllocate only writes the new allocation to NV, PCR.c:983-987), the active
    // allocation is unchanged until the next TPM Reset, so Sha384 is still unallocated.
    assert_eq!(
        allocated_pcrs(&mut sim, TpmiAlgHash::Sha384),
        vec![0x00, 0x00, 0x00]
    );

    // 2. Shutdown(CLEAR)
    assert_eq!(rc_of(&send_at(&mut sim, 0, &SHUTDOWN_CLEAR)), 0);

    // 3. Power cycle (_TPM_Init) followed by Startup(CLEAR). C reloads gp.pcrAllocated from NV
    // at _TPM_Init.
    sim.signal_platform(SimulatorPlatformSignal::PowerOff)
        .unwrap();
    sim.signal_platform(SimulatorPlatformSignal::PowerOn)
        .unwrap();
    sim.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();
    assert_eq!(rc_of(&send_at(&mut sim, 0, &STARTUP_CLEAR)), 0);

    // 4. Verify that the configured PCR allocation took effect at the TPM Reset
    assert_eq!(
        allocated_pcrs(&mut sim, TpmiAlgHash::Sha384),
        vec![0xFF, 0xFF, 0xFF]
    );
}
