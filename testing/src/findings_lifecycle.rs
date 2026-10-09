//! End-to-end regression tests for the `lifecycle` findings in command-handlers.toml.
//!
//! Owned by the `fix-lifecycle` worker; add submodules under `findings_lifecycle/` if this grows.
//!
//! Every test drives the simulator exclusively through its command interface and platform
//! signals (`PowerOn`/`PowerOff`/`NvOn`/`NvOff`), and is named after the finding it covers.

#![allow(unused_imports)]

use crate::test_utils::*;
use tpm2::commands::*;
use tpm2::errors::{Position, TpmRc};
use tpm2::*;
use tpm2_simulator::{Simulator, SimulatorPlatformSignal, create_simulator};

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// `TPM_RC_NV_UNAVAILABLE` as returned by `RETURN_IF_NV_IS_NOT_AVAILABLE`.
fn nv_unavailable() -> u32 {
    TpmRc::NV_UNAVAILABLE.get()
}

/// Makes NV unavailable to the TPM (`_plat__ClearNvAvail`).
fn nv_off(sim: &mut Simulator<'_>) {
    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
}

/// Makes NV available to the TPM again (`_plat__SetNvAvail`).
fn nv_on(sim: &mut Simulator<'_>) {
    sim.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();
}

/// Sends a raw command at `locality` and returns the response code.
fn raw_rc(sim: &mut Simulator<'_>, locality: u8, cmd: &[u8]) -> u32 {
    let mut input = vec![locality];
    input.extend_from_slice(&(cmd.len() as u32).to_be_bytes());
    input.extend_from_slice(cmd);
    let mut stream = std::io::Cursor::new(input);
    // TPM_SEND_COMMAND
    sim.handle_regular_command_raw(8, &mut stream).unwrap();
    let out = stream.into_inner();
    let start = 1 + 4 + cmd.len();
    let resp_len = u32::from_be_bytes(out[start..start + 4].try_into().unwrap()) as usize;
    assert!(resp_len >= 10, "short response");
    u32::from_be_bytes(out[start + 4 + 6..start + 4 + 10].try_into().unwrap())
}

/// Builds a `TPM_ST_NO_SESSIONS` command with a single `UINT16` parameter.
fn u16_param_command(cc: u32, param: u16) -> Vec<u8> {
    let mut cmd = Vec::new();
    cmd.extend_from_slice(&0x8001u16.to_be_bytes());
    cmd.extend_from_slice(&12u32.to_be_bytes());
    cmd.extend_from_slice(&cc.to_be_bytes());
    cmd.extend_from_slice(&param.to_be_bytes());
    cmd
}

/// Raw `TPM2_Startup(startup_type)` at `locality`.
fn startup_raw(sim: &mut Simulator<'_>, locality: u8, startup_type: u16) -> u32 {
    raw_rc(sim, locality, &u16_param_command(0x144, startup_type))
}

/// Raw `TPM2_Shutdown(shutdown_type)`.
fn shutdown_raw(sim: &mut Simulator<'_>, shutdown_type: u16) -> u32 {
    raw_rc(sim, 0, &u16_param_command(0x145, shutdown_type))
}

const SU_CLEAR: u16 = 0x0000;
const SU_STATE: u16 = 0x0001;

/// Optionally sends `TPM2_Shutdown(shutdown)`, power-cycles the TPM (`_TPM_Init`), enables NV
/// and sends `TPM2_Startup(startup)`. Returns the Startup response code.
fn power_cycle(sim: &mut Simulator<'_>, shutdown: Option<u16>, startup: u16) -> u32 {
    if let Some(su) = shutdown {
        assert_eq!(shutdown_raw(sim, su), 0, "TPM2_Shutdown failed");
    }
    sim.signal_platform(SimulatorPlatformSignal::PowerOff)
        .unwrap();
    sim.signal_platform(SimulatorPlatformSignal::PowerOn)
        .unwrap();
    nv_on(sim);
    startup_raw(sim, 0, startup)
}

fn read_clock(sim: &mut Simulator<'_>) -> TpmsTimeInfo {
    sim.execute(ReadClock {}).unwrap().current_time
}

/// Small, fast-to-generate ECC storage key template.
fn ecc_primary_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    }
}

/// Creates an ECC primary key under `hierarchy` and returns its handle and Name.
fn create_primary(sim: &mut Simulator<'_>, hierarchy: Handle, auth: &[u8]) -> (Handle, Vec<u8>) {
    let cmd = CreatePrimary {
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(ecc_primary_template()),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let handles = CreatePrimaryHandles {
        primary_handle: hierarchy,
    };
    let (rsp, rsp_handles) = execute_with_password_sessions(sim, &cmd, handles, 1, auth)
        .unwrap_or_else(|rc| panic!("CreatePrimary({hierarchy:?}) failed: {rc:#x}"));
    (rsp_handles.object_handle, rsp.name.get_buffer().to_vec())
}

/// Makes `object` persistent at `persistent` using `auth` (owner or platform).
fn evict(sim: &mut Simulator<'_>, auth: Handle, object: Handle, persistent: u32) {
    let cmd = EvictControl {
        persistent_handle: Handle(persistent),
    };
    let handles = EvictControlHandles {
        auth,
        object_handle: object,
    };
    execute_with_password_sessions(sim, &cmd, handles, 1, &[])
        .unwrap_or_else(|rc| panic!("EvictControl({persistent:#x}) failed: {rc:#x}"));
}

/// Returns whether a persistent/transient object handle is present (`TPM2_ReadPublic`).
fn object_exists(sim: &mut Simulator<'_>, handle: u32) -> bool {
    sim.execute_with_handles(
        ReadPublic {},
        ReadPublicHandles {
            object_handle: Handle(handle),
        },
    )
    .is_ok()
}

fn clear(sim: &mut Simulator<'_>, auth: Handle) -> Result<(), u32> {
    execute_with_password_sessions(sim, &Clear {}, ClearHandles { auth_handle: auth }, 1, &[])
        .map(|_| ())
}

fn clear_control(sim: &mut Simulator<'_>, auth: Handle, disable: bool) -> Result<(), u32> {
    execute_with_password_sessions(
        sim,
        &ClearControl { disable },
        ClearControlHandles { auth },
        1,
        &[],
    )
    .map(|_| ())
}

fn hierarchy_control(
    sim: &mut Simulator<'_>,
    auth: Handle,
    enable: Handle,
    state: bool,
) -> Result<(), u32> {
    execute_with_password_sessions(
        sim,
        &HierarchyControl { enable, state },
        HierarchyControlHandles { auth_handle: auth },
        1,
        &[],
    )
    .map(|_| ())
}

fn hierarchy_change_auth(
    sim: &mut Simulator<'_>,
    hierarchy: Handle,
    current: &[u8],
    new_auth: &[u8],
) -> Result<(), u32> {
    execute_with_password_sessions(
        sim,
        &HierarchyChangeAuth {
            new_auth: Tpm2bAuth::from_bytes(new_auth).unwrap(),
        },
        HierarchyChangeAuthHandles {
            auth_handle: hierarchy,
        },
        1,
        current,
    )
    .map(|_| ())
}

fn pcr_update_counter(sim: &mut Simulator<'_>) -> u32 {
    sim.execute(PCRRead {
        pcr_selection_in: TpmlPcrSelection::default(),
    })
    .unwrap()
    .pcr_update_counter
}

fn incremental_self_test(sim: &mut Simulator<'_>, algs: &[Alg]) -> Result<Vec<Alg>, u32> {
    let cmd = IncrementalSelfTest {
        to_test: TpmlAlg::from_slice(algs).unwrap(),
    };
    sim.execute(cmd)
        .map(|rsp| rsp.to_do_list.algorithms().to_vec())
        .map_err(|e| e.get())
}

fn define_nv(sim: &mut Simulator<'_>, index: u32, attributes: TpmaNv, size: u16) {
    let cmd = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info: Tpm2b(TpmsNvPublic {
            nv_index: Handle(index),
            name_alg: TpmiAlgHash::Sha256,
            attributes,
            auth_policy: Tpm2bDigest::default(),
            data_size: size,
        }),
    };
    execute_with_password_sessions(
        sim,
        &cmd,
        NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        },
        1,
        &[],
    )
    .unwrap_or_else(|rc| panic!("NV_DefineSpace({index:#x}) failed: {rc:#x}"));
}

fn nv_write(sim: &mut Simulator<'_>, index: u32, data: &[u8]) -> Result<(), u32> {
    execute_with_password_sessions(
        sim,
        &NVWrite {
            data: Tpm2bMaxNvBuffer::from_bytes(data).unwrap(),
            offset: 0,
        },
        NVWriteHandles {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(index),
        },
        1,
        &[],
    )
    .map(|_| ())
}

fn nv_read(sim: &mut Simulator<'_>, index: u32, size: u16) -> Result<(), u32> {
    execute_with_password_sessions(
        sim,
        &NVRead { size, offset: 0 },
        NVReadHandles {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(index),
        },
        1,
        &[],
    )
    .map(|_| ())
}

const NV_RW: TpmaNv = TpmaNv::OWNERWRITE.union(TpmaNv::OWNERREAD);

// ---------------------------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------------------------

/// `TPM2_ClockSet` to a value >= 2^63 must not wrap the clock to 0.
#[test]
fn tpm2_clockset_i64_overflow_and_hardcoded_clock_safe_flag() {
    let mut sim = create_simulator!();
    let new_time = 0x8000_0000_0000_0000u64;
    execute_with_password_sessions(
        &mut sim,
        &ClockSet { new_time },
        ClockSetHandles {
            auth: Handle::RH_OWNER,
        },
        1,
        &[],
    )
    .unwrap();
    let clock = read_clock(&mut sim).clock_info.clock;
    assert!(clock >= new_time, "clock wrapped to {clock:#x}");

    // The largest permitted value is also represented exactly.
    let max_time = 0xFFFF_0000_0000_0000u64;
    execute_with_password_sessions(
        &mut sim,
        &ClockSet { new_time: max_time },
        ClockSetHandles {
            auth: Handle::RH_OWNER,
        },
        1,
        &[],
    )
    .unwrap();
    let clock = read_clock(&mut sim).clock_info.clock;
    assert!(clock >= max_time, "clock wrapped to {clock:#x}");
}

/// `clockInfo.safe` is NO after an unorderly power cycle and while NV is unavailable.
#[test]
fn clock_set_clock_rate_adjust_and_get_clock_info_nv_and_safe_flag_bugs() {
    let mut sim = create_simulator!();
    assert!(read_clock(&mut sim).clock_info.safe);

    // NV unavailable -> clock not safe (`TimeFillInfo`).
    nv_off(&mut sim);
    assert!(!read_clock(&mut sim).clock_info.safe);
    nv_on(&mut sim);
    assert!(read_clock(&mut sim).clock_info.safe);

    // Unorderly shutdown (no TPM2_Shutdown) -> not safe after the next startup (`TimeStartup`).
    assert_eq!(power_cycle(&mut sim, None, SU_CLEAR), 0);
    assert!(!read_clock(&mut sim).clock_info.safe);

    // An orderly shutdown keeps the previous value; TPM2_Clear makes it safe again.
    clear(&mut sim, Handle::RH_PLATFORM).unwrap();
    assert!(read_clock(&mut sim).clock_info.safe);
    assert_eq!(power_cycle(&mut sim, Some(SU_CLEAR), SU_CLEAR), 0);
    assert!(read_clock(&mut sim).clock_info.safe);
}

/// `TPM2_ClockSet` returns `TPM_RC_NV_UNAVAILABLE` while NV is unavailable.
#[test]
fn clock_set_rate_adjust_and_clock_safe_nv_bugs() {
    let mut sim = create_simulator!();
    let before = read_clock(&mut sim).clock_info.clock;
    nv_off(&mut sim);
    let rc = execute_with_password_sessions(
        &mut sim,
        &ClockSet {
            new_time: before + 1_000_000,
        },
        ClockSetHandles {
            auth: Handle::RH_OWNER,
        },
        1,
        &[],
    )
    .unwrap_err();
    assert_eq!(rc, nv_unavailable());
    nv_on(&mut sim);
    assert!(read_clock(&mut sim).clock_info.clock < before + 1_000_000);
}

/// `TPM2_ClockRateAdjust` actually slows down the advance of Time/Clock.
#[test]
fn clock_set_clock_rate_adjust_slows_time() {
    let mut sim = create_simulator!();
    // 17 coarse steps exceed CLOCK_ADJUST_LIMIT: the divisor saturates at 35000 / 30000.
    for _ in 0..17 {
        execute_with_password_sessions(
            &mut sim,
            &ClockRateAdjust {
                rate_adjust: TpmClockAdjust::CoarseSlower,
            },
            ClockRateAdjustHandles {
                auth: Handle::RH_PLATFORM,
            },
            1,
            &[],
        )
        .unwrap();
    }
    let t0 = read_clock(&mut sim).time;
    let wall = std::time::Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let t1 = read_clock(&mut sim).time;
    let wall_ms = wall.elapsed().as_millis() as u64;
    let tpm_ms = t1 - t0;
    // Nominal would be ~wall_ms; the adjusted rate is 30000/35000 ~= 0.857.
    assert!(
        tpm_ms * 100 <= wall_ms * 92,
        "TPM time advanced {tpm_ms} ms in {wall_ms} ms of wall time"
    );
    assert!(tpm_ms * 100 >= wall_ms * 70, "TPM time advanced too slowly");
}

// ---------------------------------------------------------------------------------------------
// TPM2_Clear / ChangeEPS / ChangePPS / HierarchyControl
// ---------------------------------------------------------------------------------------------

/// Clear keeps platform persistent objects, bumps the PCR update counter, resets clearCount,
/// and persists the zeroed resetCount.
#[test]
fn tpm2_clear_deletes_platform_persistent_objects_and_corrupts_counters() {
    let mut sim = create_simulator!();
    let (owner_key, _) = create_primary(&mut sim, Handle::RH_OWNER, &[]);
    evict(&mut sim, Handle::RH_OWNER, owner_key, 0x8100_0001);
    let (platform_key, _) = create_primary(&mut sim, Handle::RH_PLATFORM, &[]);
    evict(&mut sim, Handle::RH_PLATFORM, platform_key, 0x8180_0001);

    // A saved platform-object context must remain loadable: clearCount is reset to 0
    // (it was already 0 after the TPM Reset), not incremented.
    let saved = sim
        .execute_with_handles(
            ContextSave {},
            ContextSaveHandles {
                save_handle: platform_key,
            },
        )
        .unwrap()
        .0
        .context;

    let counter_before = pcr_update_counter(&mut sim);
    clear(&mut sim, Handle::RH_PLATFORM).unwrap();

    assert!(
        !object_exists(&mut sim, 0x8100_0001),
        "owner object survived"
    );
    assert!(
        object_exists(&mut sim, 0x8180_0001),
        "platform object deleted"
    );
    assert_eq!(pcr_update_counter(&mut sim), counter_before + 1);

    flush_context(&mut sim, platform_key).unwrap();
    sim.execute(ContextLoad { context: saved })
        .expect("platform context no longer loadable after Clear");

    // resetCount was zeroed and written to NV: the next TPM Reset makes it 1.
    assert_eq!(read_clock(&mut sim).clock_info.reset_count, 0);
    assert_eq!(power_cycle(&mut sim, None, SU_CLEAR), 0);
    assert_eq!(read_clock(&mut sim).clock_info.reset_count, 1);
}

/// Same evict-object behavior through the generic hierarchy finding.
#[test]
fn tpm2_hierarchy_commands_clear_changeeps_changepps_and_hierarchycontrol_bugs() {
    let mut sim = create_simulator!();
    // Owner may "enable" the already enabled storage hierarchy (no-op success).
    hierarchy_control(&mut sim, Handle::RH_OWNER, Handle::RH_OWNER, true).unwrap();
    hierarchy_control(
        &mut sim,
        Handle::RH_ENDORSEMENT,
        Handle::RH_ENDORSEMENT,
        true,
    )
    .unwrap();
    // ...but not re-enable it once disabled: ownerAuth is unusable while shEnable is CLEAR
    // (`EntityGetLoadStatus` -> TPM_RC_HIERARCHY + H1); only platform auth can re-enable it.
    hierarchy_control(&mut sim, Handle::RH_OWNER, Handle::RH_OWNER, false).unwrap();
    assert_eq!(
        hierarchy_control(&mut sim, Handle::RH_OWNER, Handle::RH_OWNER, true),
        Err(TpmRc::HIERARCHY.with(Position::handle(1)).get())
    );
    assert_eq!(
        hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_OWNER, true),
        Ok(())
    );

    // ChangePPS flushes platform evict objects but keeps owner ones.
    let (owner_key, _) = create_primary(&mut sim, Handle::RH_OWNER, &[]);
    evict(&mut sim, Handle::RH_OWNER, owner_key, 0x8100_0002);
    let (platform_key, _) = create_primary(&mut sim, Handle::RH_PLATFORM, &[]);
    evict(&mut sim, Handle::RH_PLATFORM, platform_key, 0x8180_0002);
    execute_with_password_sessions(
        &mut sim,
        &ChangePPS {},
        ChangePPSHandles {
            auth_handle: Handle::RH_PLATFORM,
        },
        1,
        &[],
    )
    .unwrap();
    assert!(!object_exists(&mut sim, 0x8180_0002));
    assert!(object_exists(&mut sim, 0x8100_0002));
}

/// ChangeEPS flushes endorsement evict objects (but not storage ones) and resets endorsementAlg.
#[test]
fn tpm2_changeeps_and_changepps_omit_nv_evict_flushing_and_endorsement_alg() {
    let mut sim = create_simulator!();
    let (ek, _) = create_primary(&mut sim, Handle::RH_ENDORSEMENT, &[]);
    evict(&mut sim, Handle::RH_OWNER, ek, 0x8101_0001);
    let (srk, _) = create_primary(&mut sim, Handle::RH_OWNER, &[]);
    evict(&mut sim, Handle::RH_OWNER, srk, 0x8100_0003);
    execute_with_password_sessions(
        &mut sim,
        &SetPrimaryPolicy {
            auth_policy: Tpm2bDigest::from_bytes(&[0x11; 32]).unwrap(),
            hash_alg: Some(TpmiAlgHash::Sha256),
        },
        SetPrimaryPolicyHandles {
            auth_handle: Handle::RH_ENDORSEMENT,
        },
        1,
        &[],
    )
    .unwrap();

    // The storage hierarchy being disabled must not protect endorsement evict objects stored in
    // the owner persistent range: NvFlushHierarchy only looks at the stored hierarchy.
    hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_OWNER, false).unwrap();
    execute_with_password_sessions(
        &mut sim,
        &ChangeEPS {},
        ChangeEPSHandles {
            auth_handle: Handle::RH_PLATFORM,
        },
        1,
        &[],
    )
    .unwrap();
    hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_OWNER, true).unwrap();
    assert!(
        !object_exists(&mut sim, 0x8101_0001),
        "EK survived ChangeEPS"
    );
    assert!(
        object_exists(&mut sim, 0x8100_0003),
        "SRK deleted by ChangeEPS"
    );

    // TPM_CAP_AUTH_POLICIES reports TPM_ALG_NULL for the endorsement hierarchy again.
    let (rsp, _) = sim
        .execute_with_handles(
            GetCapability {
                capability: TpmCap::AuthPolicies,
                property: Handle::RH_ENDORSEMENT.0,
                property_count: 1,
            },
            (),
        )
        .unwrap();
    match rsp.capability_data {
        TpmsCapabilityData::AuthPolicies(policies) => {
            let entry = policies
                .as_ref()
                .iter()
                .find(|p| p.handle == Handle::RH_ENDORSEMENT)
                .expect("endorsement policy missing");
            assert!(
                entry.policy_hash.is_none(),
                "endorsementAlg not reset: {entry:?}"
            );
        }
        other => panic!("unexpected capability data {other:?}"),
    }
}

/// `TPM2_Clear`: NV availability is checked before `disableClear`.
#[test]
fn tpm2_clear_clearcount_auditcounter_and_nv_toc_cap_bugs() {
    let mut sim = create_simulator!();
    clear_control(&mut sim, Handle::RH_PLATFORM, true).unwrap();
    nv_off(&mut sim);
    assert_eq!(clear(&mut sim, Handle::RH_LOCKOUT), Err(nv_unavailable()));
    nv_on(&mut sim);
    assert_eq!(
        clear(&mut sim, Handle::RH_LOCKOUT),
        Err(TpmRc::DISABLED.get())
    );
}

/// ChangeEPS / ChangePPS / Clear check NV availability unconditionally.
#[test]
fn change_eps_change_pps_and_clear_ph_enable_nv_available_and_clear_count_bugs() {
    let mut sim = create_simulator!();
    nv_off(&mut sim);
    let rc = execute_with_password_sessions(
        &mut sim,
        &ChangeEPS {},
        ChangeEPSHandles {
            auth_handle: Handle::RH_PLATFORM,
        },
        1,
        &[],
    )
    .unwrap_err();
    assert_eq!(rc, nv_unavailable());
    let rc = execute_with_password_sessions(
        &mut sim,
        &ChangePPS {},
        ChangePPSHandles {
            auth_handle: Handle::RH_PLATFORM,
        },
        1,
        &[],
    )
    .unwrap_err();
    assert_eq!(rc, nv_unavailable());
    assert_eq!(clear(&mut sim, Handle::RH_PLATFORM), Err(nv_unavailable()));
}

/// The persistent NV-mutating hierarchy commands use RETURN_IF_NV_IS_NOT_AVAILABLE, which
/// fails even after the orderly state has already been cleared.
#[test]
fn nv_clear_orderly_bypasses_nv_available_when_orderly_state_cleared() {
    let mut sim = create_simulator!();
    // The orderly state is SU_NONE after Startup, so RETURN_IF_ORDERLY alone never fails here.
    nv_off(&mut sim);
    assert_eq!(
        hierarchy_change_auth(&mut sim, Handle::RH_PLATFORM, &[], b"pp"),
        Err(nv_unavailable())
    );
    let rc = execute_with_password_sessions(
        &mut sim,
        &SetPrimaryPolicy {
            auth_policy: Tpm2bDigest::from_bytes(&[0x22; 32]).unwrap(),
            hash_alg: Some(TpmiAlgHash::Sha256),
        },
        SetPrimaryPolicyHandles {
            auth_handle: Handle::RH_PLATFORM,
        },
        1,
        &[],
    )
    .unwrap_err();
    assert_eq!(rc, nv_unavailable());
}

/// HierarchyChangeAuth / ClearControl check NV availability for every hierarchy, and
/// disableClear persists across TPM Reset.
#[test]
fn tpm2_hierarchychangeauth_and_clearcontrol_size_and_nv_persistence_bugs() {
    let mut sim = create_simulator!();
    nv_off(&mut sim);
    for h in [Handle::RH_OWNER, Handle::RH_ENDORSEMENT, Handle::RH_LOCKOUT] {
        assert_eq!(
            hierarchy_change_auth(&mut sim, h, &[], b"new"),
            Err(nv_unavailable()),
            "{h:?}"
        );
    }
    assert_eq!(
        clear_control(&mut sim, Handle::RH_LOCKOUT, true),
        Err(nv_unavailable())
    );
    nv_on(&mut sim);
    // The failed attempt must not have changed the owner auth.
    hierarchy_change_auth(&mut sim, Handle::RH_OWNER, &[], b"o").unwrap();

    clear_control(&mut sim, Handle::RH_LOCKOUT, true).unwrap();
    assert_eq!(power_cycle(&mut sim, Some(SU_CLEAR), SU_CLEAR), 0);
    assert_eq!(
        clear(&mut sim, Handle::RH_LOCKOUT),
        Err(TpmRc::DISABLED.get()),
        "disableClear lost across TPM Reset"
    );
    clear_control(&mut sim, Handle::RH_PLATFORM, false).unwrap();
    clear(&mut sim, Handle::RH_LOCKOUT).unwrap();
}

/// Same persistence / NV checks for ClearControl.
#[test]
fn tpm2_clearcontrol_missing_nv_persistence_and_orderly_clear() {
    let mut sim = create_simulator!();
    clear_control(&mut sim, Handle::RH_PLATFORM, true).unwrap();
    // Unorderly power loss must not lose disableClear either.
    assert_eq!(power_cycle(&mut sim, None, SU_CLEAR), 0);
    assert_eq!(
        clear(&mut sim, Handle::RH_PLATFORM),
        Err(TpmRc::DISABLED.get())
    );
    nv_off(&mut sim);
    assert_eq!(
        clear_control(&mut sim, Handle::RH_PLATFORM, false),
        Err(nv_unavailable())
    );
}

/// HierarchyControl: phEnableNV can be SET again, and owner may no-op enable.
#[test]
fn tpm2_hierarchycontrol_and_clearcontrol_validation_and_persistence_bugs() {
    let mut sim = create_simulator!();
    hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_PLATFORM_NV, false).unwrap();
    hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_PLATFORM_NV, true)
        .expect("phEnableNV could not be re-enabled");
    hierarchy_control(&mut sim, Handle::RH_OWNER, Handle::RH_OWNER, true).unwrap();
    hierarchy_control(&mut sim, Handle::RH_OWNER, Handle::RH_OWNER, false).unwrap();
    assert_eq!(
        hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_ENDORSEMENT, true),
        Ok(())
    );
}

/// HierarchyControl runs RETURN_IF_ORDERLY before changing state, and a no-op call needs no NV.
#[test]
fn hierarchy_control_pre_nv_mutation_and_noop_orderly_clear_bugs() {
    let mut sim = create_simulator!();
    // Make the TPM orderly again so that RETURN_IF_ORDERLY needs NV.
    assert_eq!(shutdown_raw(&mut sim, SU_CLEAR), 0);
    nv_off(&mut sim);
    // No-op: the storage hierarchy is already enabled.
    hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_OWNER, true)
        .expect("no-op HierarchyControl needed NV");
    // A real change fails without modifying the state.
    assert_eq!(
        hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_OWNER, false),
        Err(nv_unavailable())
    );
    nv_on(&mut sim);
    create_primary(&mut sim, Handle::RH_OWNER, &[]);
}

/// Same ordering through the engine path (owner re-enable no-op is not AUTH_TYPE).
#[test]
fn hierarchy_control_pre_auth_validation_and_state_mutation_before_orderly_check() {
    let mut sim = create_simulator!();
    assert_eq!(
        hierarchy_control(
            &mut sim,
            Handle::RH_ENDORSEMENT,
            Handle::RH_ENDORSEMENT,
            true
        ),
        Ok(())
    );
    assert_eq!(shutdown_raw(&mut sim, SU_CLEAR), 0);
    nv_off(&mut sim);
    assert_eq!(
        hierarchy_control(
            &mut sim,
            Handle::RH_ENDORSEMENT,
            Handle::RH_ENDORSEMENT,
            false
        ),
        Err(nv_unavailable())
    );
    nv_on(&mut sim);
    // The endorsement hierarchy is still enabled.
    create_primary(&mut sim, Handle::RH_ENDORSEMENT, &[]);
}

// ---------------------------------------------------------------------------------------------
// SetPrimaryPolicy
// ---------------------------------------------------------------------------------------------

fn set_primary_policy_nv_off_check(sim: &mut Simulator<'_>, hierarchy: Handle) {
    let rc = execute_with_password_sessions(
        sim,
        &SetPrimaryPolicy {
            auth_policy: Tpm2bDigest::from_bytes(&[0x33; 32]).unwrap(),
            hash_alg: Some(TpmiAlgHash::Sha256),
        },
        SetPrimaryPolicyHandles {
            auth_handle: hierarchy,
        },
        1,
        &[],
    )
    .unwrap_err();
    assert_eq!(rc, nv_unavailable(), "{hierarchy:?}");
}

#[test]
fn tpm2_setprimarypolicy_omits_nv_availability_check_and_act_handles() {
    let mut sim = create_simulator!();
    nv_off(&mut sim);
    set_primary_policy_nv_off_check(&mut sim, Handle::RH_OWNER);
}

#[test]
fn setprimarypolicy_nv_availability_and_selftest_algorithm_bugs() {
    let mut sim = create_simulator!();
    nv_off(&mut sim);
    set_primary_policy_nv_off_check(&mut sim, Handle::RH_ENDORSEMENT);
    nv_on(&mut sim);
    // IncrementalSelfTest: TPM_ALG_NULL is not implemented, TPM_ALG_XOR is.
    assert_eq!(
        incremental_self_test(&mut sim, &[Alg::NULL]),
        Err(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
    incremental_self_test(&mut sim, &[Alg::XOR]).expect("XOR rejected");
}

#[test]
fn set_primary_policy_missing_nv_available_check_and_unmarshal_error_codes() {
    let mut sim = create_simulator!();
    nv_off(&mut sim);
    set_primary_policy_nv_off_check(&mut sim, Handle::RH_LOCKOUT);
}

// ---------------------------------------------------------------------------------------------
// Self test
// ---------------------------------------------------------------------------------------------

#[test]
fn tpm2_incrementalselftest_accepts_tpm_alg_null_and_mutates_state_on_error() {
    let mut sim = create_simulator!();
    let todo = incremental_self_test(&mut sim, &[]).unwrap();
    assert!(todo.contains(&Alg::RSA));
    assert_eq!(
        incremental_self_test(&mut sim, &[Alg::RSA, Alg::NULL]),
        Err(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
    let todo_after = incremental_self_test(&mut sim, &[]).unwrap();
    assert_eq!(
        todo, todo_after,
        "failed IncrementalSelfTest mutated the to-do list"
    );
}

#[test]
fn tpm2_incrementalselftest_and_selftest_alg_null_partial_mutation_and_unmarshal_bugs() {
    let mut sim = create_simulator!();
    assert_eq!(
        incremental_self_test(&mut sim, &[Alg::NULL]),
        Err(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
    assert_eq!(
        incremental_self_test(&mut sim, &[Alg::AES, Alg::SM2]),
        Err(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
    assert!(
        incremental_self_test(&mut sim, &[])
            .unwrap()
            .contains(&Alg::AES)
    );
}

// ---------------------------------------------------------------------------------------------
// Dictionary attack
// ---------------------------------------------------------------------------------------------

fn da_lock_reset(sim: &mut Simulator<'_>) -> Result<(), u32> {
    execute_with_password_sessions(
        sim,
        &DictionaryAttackLockReset {},
        DictionaryAttackLockResetHandles {
            lock_handle: Handle::RH_LOCKOUT,
        },
        1,
        &[],
    )
    .map(|_| ())
}

fn da_parameters(
    sim: &mut Simulator<'_>,
    max: u32,
    recovery: u32,
    lockout: u32,
) -> Result<(), u32> {
    execute_with_password_sessions(
        sim,
        &DictionaryAttackParameters {
            new_max_tries: max,
            new_recovery_time: recovery,
            lockout_recovery: lockout,
        },
        DictionaryAttackParametersHandles {
            lock_handle: Handle::RH_LOCKOUT,
        },
        1,
        &[],
    )
    .map(|_| ())
}

#[test]
fn tpm2_dictionaryattackparameters_omits_nv_persistence_and_resets_failedtries() {
    let mut sim = create_simulator!();
    nv_off(&mut sim);
    assert_eq!(da_parameters(&mut sim, 5, 10, 10), Err(nv_unavailable()));
    nv_on(&mut sim);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::MAX_AUTH_FAIL), 3);
    da_parameters(&mut sim, 5, 10, 10).unwrap();
    assert_eq!(power_cycle(&mut sim, Some(SU_CLEAR), SU_CLEAR), 0);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::MAX_AUTH_FAIL), 5);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::LOCKOUT_INTERVAL), 10);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::LOCKOUT_RECOVERY), 10);
}

#[test]
fn dictionary_attack_lock_reset_clearcontrol_and_daselfheal_nv_bugs() {
    let mut sim = create_simulator!();
    nv_off(&mut sim);
    assert_eq!(da_lock_reset(&mut sim), Err(nv_unavailable()));
    assert_eq!(
        clear_control(&mut sim, Handle::RH_LOCKOUT, true),
        Err(nv_unavailable())
    );
    nv_on(&mut sim);

    // DASelfHeal must not run while NV is unavailable (`TimeUpdateToCurrent`).
    da_parameters(&mut sim, 3, 1, 1000).unwrap();
    hierarchy_change_auth(&mut sim, Handle::RH_OWNER, &[], b"owner").unwrap();
    let (key, _) = create_primary(&mut sim, Handle::RH_OWNER, b"owner");
    // A wrong password for the (DA-protected) key counts as a DA failure.
    let rc = execute_with_password_sessions(
        &mut sim,
        &Create {
            in_sensitive: Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::default(),
                data: Tpm2bSensitiveData::default(),
            }),
            in_public: Tpm2b(ecc_primary_template()),
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        },
        CreateHandles { parent_handle: key },
        1,
        b"wrong",
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::AUTH_FAIL.with(Position::session(1)).get());
    assert_eq!(get_tpm_property(&mut sim, TpmPt::LOCKOUT_COUNTER), 1);
    nv_off(&mut sim);
    std::thread::sleep(std::time::Duration::from_millis(1300));
    assert_eq!(
        get_tpm_property(&mut sim, TpmPt::LOCKOUT_COUNTER),
        1,
        "DASelfHeal ran while NV was unavailable"
    );
    nv_on(&mut sim);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::LOCKOUT_COUNTER), 0);
}

#[test]
fn validate_lockout_auth_and_da_handlers_execution_order_and_nv_pending_bugs() {
    let mut sim = create_simulator!();
    nv_off(&mut sim);
    assert_eq!(da_lock_reset(&mut sim), Err(nv_unavailable()));
    assert_eq!(da_parameters(&mut sim, 1, 1, 1), Err(nv_unavailable()));
    nv_on(&mut sim);
    assert_eq!(get_tpm_property(&mut sim, TpmPt::MAX_AUTH_FAIL), 3);
}

// ---------------------------------------------------------------------------------------------
// Startup / Shutdown
// ---------------------------------------------------------------------------------------------

/// Shutdown(CLEAR) + Startup(CLEAR) is a TPM Reset; Shutdown(STATE) + Startup(STATE) resumes
/// and preserves platformAuth and the hierarchy enables.
#[test]
fn tpm2_startup_state_transition_and_null_seed_bugs() {
    let mut sim = create_simulator!();
    let info = read_clock(&mut sim).clock_info;
    assert_eq!(power_cycle(&mut sim, Some(SU_CLEAR), SU_CLEAR), 0);
    let after = read_clock(&mut sim).clock_info;
    assert_eq!(after.reset_count, info.reset_count + 1, "not a TPM Reset");
    assert_eq!(after.restart_count, 0);

    // TPM Resume keeps platformAuth and shEnable.
    hierarchy_change_auth(&mut sim, Handle::RH_PLATFORM, &[], b"plat").unwrap();
    hierarchy_control(&mut sim, Handle::RH_OWNER, Handle::RH_OWNER, false).unwrap();
    assert_eq!(power_cycle(&mut sim, Some(SU_STATE), SU_STATE), 0);
    let resumed = read_clock(&mut sim).clock_info;
    assert_eq!(resumed.reset_count, after.reset_count);
    assert_eq!(resumed.restart_count, 1);
    // The empty password no longer works for the platform hierarchy...
    assert!(hierarchy_control(&mut sim, Handle::RH_PLATFORM, Handle::RH_OWNER, true).is_err());
    // ...the saved one does, and the storage hierarchy is still disabled until re-enabled.
    let cmd = CreatePrimary {
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(ecc_primary_template()),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    assert!(
        execute_with_password_sessions(
            &mut sim,
            &cmd,
            CreatePrimaryHandles {
                primary_handle: Handle::RH_OWNER,
            },
            1,
            &[],
        )
        .is_err(),
        "shEnable was re-enabled by TPM Resume"
    );
    execute_with_password_sessions(
        &mut sim,
        &HierarchyControl {
            enable: Handle::RH_OWNER,
            state: true,
        },
        HierarchyControlHandles {
            auth_handle: Handle::RH_PLATFORM,
        },
        1,
        b"plat",
    )
    .expect("platformAuth lost on TPM Resume");

    // TPM Restart keeps the null seed; TPM Reset replaces it.
    let (_, null_name) = create_primary(&mut sim, Handle::RH_NULL, &[]);
    assert_eq!(power_cycle(&mut sim, Some(SU_STATE), SU_CLEAR), 0);
    let restarted = read_clock(&mut sim).clock_info;
    assert_eq!(restarted.restart_count, 2);
    let (_, null_name_restart) = create_primary(&mut sim, Handle::RH_NULL, &[]);
    assert_eq!(
        null_name, null_name_restart,
        "null seed changed on TPM Restart"
    );
    assert_eq!(power_cycle(&mut sim, Some(SU_CLEAR), SU_CLEAR), 0);
    let (_, null_name_reset) = create_primary(&mut sim, Handle::RH_NULL, &[]);
    assert_ne!(null_name, null_name_reset, "null seed kept on TPM Reset");
}

/// resetCount/orderlyState are loaded from NV at _TPM_Init.
#[test]
fn tpm2_startup_missing_nv_loads_for_orderly_counters_and_lockout() {
    let mut sim = create_simulator!();
    let base = read_clock(&mut sim).clock_info.reset_count;
    for i in 1..=3 {
        assert_eq!(power_cycle(&mut sim, Some(SU_CLEAR), SU_CLEAR), 0);
        assert_eq!(read_clock(&mut sim).clock_info.reset_count, base + i);
    }
    // Startup(STATE) after Shutdown(STATE) is possible after a power cycle.
    assert_eq!(power_cycle(&mut sim, Some(SU_STATE), SU_STATE), 0);
    // Startup(STATE) after an unorderly shutdown is rejected.
    assert_eq!(
        power_cycle(&mut sim, None, SU_STATE),
        TpmRc::VALUE.with(Position::parameter(1)).get()
    );
    assert_eq!(startup_raw(&mut sim, 0, SU_CLEAR), 0);
}

/// Shutdown: NV_UNAVAILABLE (not NV_UNINITIALIZED), checked after parameter unmarshaling.
#[test]
fn tpm2_getrandom_stirrandom_and_shutdown_omit_session_parsing_and_response_formatting() {
    let mut sim = create_simulator!();
    nv_off(&mut sim);
    assert_eq!(shutdown_raw(&mut sim, SU_CLEAR), nv_unavailable());
}

#[test]
fn tpm2_shutdown_session_omission_and_nv_uninitialized_bugs() {
    let mut sim = create_simulator!();
    nv_off(&mut sim);
    assert_eq!(
        shutdown_raw(&mut sim, 0x0002),
        TpmRc::VALUE.with(Position::parameter(1)).get()
    );
    // Trailing bytes are reported before the NV error.
    let mut cmd = u16_param_command(0x145, SU_CLEAR);
    cmd.push(0);
    cmd[2..6].copy_from_slice(&13u32.to_be_bytes());
    assert_eq!(raw_rc(&mut sim, 0, &cmd), TpmRc::SIZE.get());
    assert_eq!(shutdown_raw(&mut sim, SU_STATE), nv_unavailable());
}

#[test]
fn tpm2_shutdown_nv_uninitialized_error_order_and_missing_state_persistence() {
    let mut sim = create_simulator!();
    // The context counter (STATE_RESET_DATA) survives Shutdown(STATE): a session context saved
    // before the shutdown is still loadable after TPM Resume.
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let saved = sim
        .execute_with_handles(
            ContextSave {},
            ContextSaveHandles {
                save_handle: session.session_handle,
            },
        )
        .unwrap()
        .0
        .context;
    assert_eq!(power_cycle(&mut sim, Some(SU_STATE), SU_STATE), 0);
    sim.execute(ContextLoad { context: saved })
        .expect("saved session context lost on TPM Resume");
    nv_off(&mut sim);
    assert_eq!(shutdown_raw(&mut sim, SU_STATE), nv_unavailable());
}

#[test]
fn tpm2_shutdown_state_persistence_and_nv_orderly_index_flush_bugs() {
    let mut sim = create_simulator!();
    // Null proof/seed survive Shutdown(STATE) + Startup(STATE).
    let (_, before) = create_primary(&mut sim, Handle::RH_NULL, &[]);
    assert_eq!(power_cycle(&mut sim, Some(SU_STATE), SU_STATE), 0);
    let (_, after) = create_primary(&mut sim, Handle::RH_NULL, &[]);
    assert_eq!(before, after);
    nv_off(&mut sim);
    assert_eq!(shutdown_raw(&mut sim, SU_CLEAR), nv_unavailable());
}

/// Startup: startupType is validated (VALUE+P1) before NV availability; NV_UNAVAILABLE when NV
/// is off; LOCALITY when a Resume happens at a different startup locality.
#[test]
fn crypt_ops_and_startup_unmarshal_trailing_bytes_startup_order() {
    let mut sim = create_simulator!();
    sim.signal_platform(SimulatorPlatformSignal::PowerOff)
        .unwrap();
    sim.signal_platform(SimulatorPlatformSignal::PowerOn)
        .unwrap();
    nv_off(&mut sim);
    assert_eq!(
        startup_raw(&mut sim, 0, 0x0002),
        TpmRc::VALUE.with(Position::parameter(1)).get()
    );
    assert_eq!(startup_raw(&mut sim, 0, SU_CLEAR), nv_unavailable());
    nv_on(&mut sim);
    assert_eq!(startup_raw(&mut sim, 3, SU_CLEAR), 0);
    // Shutdown(STATE) after a locality-3 startup; resuming at locality 0 is a LOCALITY error.
    assert_eq!(shutdown_raw(&mut sim, SU_STATE), 0);
    sim.signal_platform(SimulatorPlatformSignal::PowerOff)
        .unwrap();
    sim.signal_platform(SimulatorPlatformSignal::PowerOn)
        .unwrap();
    nv_on(&mut sim);
    assert_eq!(startup_raw(&mut sim, 0, SU_STATE), TpmRc::LOCALITY.get());
    assert_eq!(startup_raw(&mut sim, 3, SU_STATE), 0);
}

/// NvEntityStartup: READLOCKED and WRITE_STCLEAR locks are cleared, CLEAR_STCLEAR indices
/// become unwritten on TPM Reset / Restart, but nothing changes on TPM Resume.
#[test]
fn tpm2_startup_omits_nv_entity_startup_lock_reset_clear_stclear_and_orderly_counter_advance() {
    let mut sim = create_simulator!();
    let read_locked = 0x0150_0010;
    let write_locked = 0x0150_0011;
    let clear_stclear = 0x0150_0012;
    define_nv(&mut sim, read_locked, NV_RW | TpmaNv::READ_STCLEAR, 8);
    define_nv(&mut sim, write_locked, NV_RW | TpmaNv::WRITE_STCLEAR, 8);
    define_nv(&mut sim, clear_stclear, NV_RW | TpmaNv::CLEAR_STCLEAR, 8);
    for idx in [read_locked, write_locked, clear_stclear] {
        nv_write(&mut sim, idx, &[1; 8]).unwrap();
    }
    execute_with_password_sessions(
        &mut sim,
        &NVReadLock {},
        NVReadLockHandles {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(read_locked),
        },
        1,
        &[],
    )
    .unwrap();
    execute_with_password_sessions(
        &mut sim,
        &NVWriteLock {},
        NVWriteLockHandles {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(write_locked),
        },
        1,
        &[],
    )
    .unwrap();
    assert!(nv_read(&mut sim, read_locked, 8).is_err());
    assert!(nv_write(&mut sim, write_locked, &[2; 8]).is_err());

    // TPM Resume keeps the locks.
    assert_eq!(power_cycle(&mut sim, Some(SU_STATE), SU_STATE), 0);
    assert!(nv_read(&mut sim, read_locked, 8).is_err());
    assert!(nv_write(&mut sim, write_locked, &[2; 8]).is_err());
    nv_read(&mut sim, clear_stclear, 8).unwrap();

    // TPM Reset clears them.
    assert_eq!(power_cycle(&mut sim, Some(SU_CLEAR), SU_CLEAR), 0);
    nv_read(&mut sim, read_locked, 8).expect("READLOCKED survived TPM Reset");
    nv_write(&mut sim, write_locked, &[2; 8]).expect("WRITELOCKED survived TPM Reset");
    assert_eq!(
        nv_read(&mut sim, clear_stclear, 8),
        Err(TpmRc::NV_UNINITIALIZED.get()),
        "CLEAR_STCLEAR index still written after TPM Reset"
    );
}

// ---------------------------------------------------------------------------------------------
// Provision / platform authorization helpers
// ---------------------------------------------------------------------------------------------

/// A wrong owner password for ClockSet fails with BAD_AUTH + S1 (owner is DA-exempt), and a
/// no-session ClockSet fails with AUTH_MISSING even with an empty ownerAuth.
#[test]
fn validate_provision_and_platform_auth_hierarchy_enable_bad_auth_and_order_bugs() {
    let mut sim = create_simulator!();
    hierarchy_change_auth(&mut sim, Handle::RH_OWNER, &[], b"abc").unwrap();
    let now = read_clock(&mut sim).clock_info.clock;
    let rc = execute_with_password_sessions(
        &mut sim,
        &ClockSet { new_time: now + 10 },
        ClockSetHandles {
            auth: Handle::RH_OWNER,
        },
        1,
        b"ab",
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::BAD_AUTH.with(Position::session(1)).get());
}

#[test]
fn clock_set_and_clock_rate_adjust_provision_auth_and_unmarshal_bugs() {
    let mut sim = create_simulator!();
    let now = read_clock(&mut sim).clock_info.clock;
    let rc = execute_with_password_sessions(
        &mut sim,
        &ClockSet { new_time: now + 10 },
        ClockSetHandles {
            auth: Handle::RH_OWNER,
        },
        0,
        &[],
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::AUTH_MISSING.get());
    let rc = execute_with_password_sessions(
        &mut sim,
        &ClockRateAdjust {
            rate_adjust: TpmClockAdjust::FineFaster,
        },
        ClockRateAdjustHandles {
            auth: Handle::RH_PLATFORM,
        },
        0,
        &[],
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::AUTH_MISSING.get());
}

/// DictionaryAttackLockReset / Parameters without a session -> AUTH_MISSING even with an empty
/// lockoutAuth.
#[test]
fn da_lockout_auth_validation_order_orderly_state_and_auth_missing_bugs() {
    let mut sim = create_simulator!();
    let rc = execute_with_password_sessions(
        &mut sim,
        &DictionaryAttackLockReset {},
        DictionaryAttackLockResetHandles {
            lock_handle: Handle::RH_LOCKOUT,
        },
        0,
        &[],
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::AUTH_MISSING.get());
}

/// A `lockoutPolicy` policy session (without PolicyAuthValue/PolicyPassword) keeps working
/// while direct use of `lockoutAuth` is disabled (`IsAuthValueAvailable` / `CheckLockedOut`
/// only when the authValue is used).
#[test]
fn lockout_policy_and_bound_session_rejected_when_lockout_auth_disabled() {
    use sha2::{Digest, Sha256};
    let mut sim = create_simulator!();

    // lockoutPolicy = PolicyCommandCode(TPM_CC_DictionaryAttackLockReset).
    let mut hasher = Sha256::new();
    hasher.update([0u8; 32]);
    hasher.update(0x16Cu32.to_be_bytes()); // TPM_CC_PolicyCommandCode
    hasher.update(0x139u32.to_be_bytes()); // TPM_CC_DictionaryAttackLockReset
    let policy = hasher.finalize().to_vec();
    execute_with_password_sessions(
        &mut sim,
        &SetPrimaryPolicy {
            auth_policy: Tpm2bDigest::from_bytes(leak_bytes(&policy)).unwrap(),
            hash_alg: Some(TpmiAlgHash::Sha256),
        },
        SetPrimaryPolicyHandles {
            auth_handle: Handle::RH_LOCKOUT,
        },
        1,
        &[],
    )
    .unwrap();

    // A wrong lockoutAuth disables direct use of lockoutAuth.
    hierarchy_change_auth(&mut sim, Handle::RH_LOCKOUT, &[], b"lock").unwrap();
    let lock_reset = |sim: &mut Simulator<'_>, auth: &[u8]| {
        execute_with_password_sessions(
            sim,
            &DictionaryAttackLockReset {},
            DictionaryAttackLockResetHandles {
                lock_handle: Handle::RH_LOCKOUT,
            },
            1,
            auth,
        )
        .map(|_| ())
    };
    assert!(lock_reset(&mut sim, b"bad").is_err());
    assert_eq!(lock_reset(&mut sim, b"lock"), Err(TpmRc::LOCKOUT.get()));

    // The lockout policy still authorizes DictionaryAttackLockReset.
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes = TpmaSession::CONTINUE_SESSION;
    sim.execute_with_handles(
        PolicyCommandCode {
            code: TpmCc::DictionaryAttackLockReset,
        },
        PolicyCommandCodeHandles {
            policy_session: session.session_handle,
        },
    )
    .unwrap();
    let lockout_name = Handle::RH_LOCKOUT.0.to_be_bytes();
    execute_with_hmac_sessions_status(
        &mut sim,
        &DictionaryAttackLockReset {},
        DictionaryAttackLockResetHandles {
            lock_handle: Handle::RH_LOCKOUT,
        },
        &[&lockout_name],
        core::slice::from_mut(&mut session),
        &[b"lock"],
    )
    .expect("lockoutPolicy rejected while lockoutAuth is disabled");
}
