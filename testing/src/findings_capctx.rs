//! End-to-end regression tests for the `capctx` findings in command-handlers.toml.
//!
//! Owned by the `fix-capctx` worker; add submodules under `findings_capctx/` if this grows.
//!
//! Every test drives the simulator exclusively through its command interface and platform
//! signals, and is named after the finding it covers. The submodules group the tests by area:
//! - [`pcr`]: `TPM2_PCR_*` commands.
//! - [`capability`]: `TPM2_GetCapability`, `TPM2_TestParms`, `TPM2_ECC_Parameters`.
//! - [`context`]: `TPM2_ContextSave`, `TPM2_ContextLoad`, `TPM2_FlushContext`.
//! - [`handles`]: command dispatch (handle validation, `NO_SESSIONS`, persistent objects).

#![allow(unused_imports)]

mod capability;
mod context;
mod handles;
mod pcr;

use crate::test_utils::*;
use tpm2::commands::*;
use tpm2::errors::{Fmt1, Position, TpmRc};
use tpm2::*;
use tpm2_simulator::{Simulator, SimulatorPlatformSignal, create_simulator};

/// `TPM_ST_NO_SESSIONS`.
pub(crate) const ST_NO_SESSIONS: u16 = 0x8001;
/// `TPM_ST_SESSIONS`.
pub(crate) const ST_SESSIONS: u16 = 0x8002;

/// A password authorization (`TPM_RS_PW`) with an empty password and `continueSession` set.
pub(crate) const PW_SESSION: [u8; 9] = [0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00];

/// Builds a raw command with the given tag, command code, handle area, optional session area
/// (the concatenated `TPMS_AUTH_COMMAND`s, without the `authorizationSize` prefix) and
/// parameter area.
pub(crate) fn build_cmd(
    tag: u16,
    cc: u32,
    handles: &[u32],
    sessions: Option<&[u8]>,
    params: &[u8],
) -> Vec<u8> {
    let mut cmd = Vec::new();
    cmd.extend_from_slice(&tag.to_be_bytes());
    cmd.extend_from_slice(&0u32.to_be_bytes());
    cmd.extend_from_slice(&cc.to_be_bytes());
    for h in handles {
        cmd.extend_from_slice(&h.to_be_bytes());
    }
    if let Some(s) = sessions {
        cmd.extend_from_slice(&(s.len() as u32).to_be_bytes());
        cmd.extend_from_slice(s);
    }
    cmd.extend_from_slice(params);
    let len = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&len.to_be_bytes());
    cmd
}

/// Builds a raw command authorized with one empty-password session per entry of `handles`
/// that is listed in `auth_count` (the first `auth_count` handles).
pub(crate) fn build_pw_cmd(cc: u32, handles: &[u32], auth_count: usize, params: &[u8]) -> Vec<u8> {
    let sessions: Vec<u8> = PW_SESSION.repeat(auth_count);
    build_cmd(ST_SESSIONS, cc, handles, Some(&sessions), params)
}

/// Sends a raw command at `locality` and returns the response code and the full response.
pub(crate) fn send_at(sim: &mut Simulator<'_>, locality: u8, cmd: &[u8]) -> (u32, Vec<u8>) {
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
    let resp = out[start + 4..start + 4 + resp_len].to_vec();
    let rc = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    (rc, resp)
}

/// Sends a raw command at locality 0 and returns the response code and the full response.
pub(crate) fn send(sim: &mut Simulator<'_>, cmd: &[u8]) -> (u32, Vec<u8>) {
    send_at(sim, 0, cmd)
}

/// Sends a raw command at locality 0 and returns only the response code.
pub(crate) fn rc_of(sim: &mut Simulator<'_>, cmd: &[u8]) -> u32 {
    send(sim, cmd).0
}

/// Returns the parameter area of a successful response to a command sent with
/// `TPM_ST_SESSIONS` (skipping `resp_handles` response handles and `parameterSize`).
pub(crate) fn session_rsp_params(resp: &[u8], resp_handles: usize) -> &[u8] {
    let start = 10 + 4 * resp_handles;
    let size = u32::from_be_bytes(resp[start..start + 4].try_into().unwrap()) as usize;
    &resp[start + 4..start + 4 + size]
}

/// Makes NV unavailable to the TPM.
pub(crate) fn nv_off(sim: &mut Simulator<'_>) {
    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
}

/// Makes NV available to the TPM again.
pub(crate) fn nv_on(sim: &mut Simulator<'_>) {
    sim.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();
}

/// Performs `TPM2_Shutdown(TPM_SU_CLEAR)`, a power cycle and `TPM2_Startup(TPM_SU_CLEAR)`
/// (a TPM Reset).
pub(crate) fn tpm_reset(sim: &mut Simulator<'_>) {
    let shutdown = build_cmd(ST_NO_SESSIONS, 0x145, &[], None, &0u16.to_be_bytes());
    assert_eq!(rc_of(sim, &shutdown), 0, "TPM2_Shutdown failed");
    sim.signal_platform(SimulatorPlatformSignal::PowerOff)
        .unwrap();
    sim.power_on_start_up();
}

/// Expected response code `rc` with a handle position.
pub(crate) fn rc_h(rc: Fmt1, h: u8) -> u32 {
    rc.with(Position::handle(h)).get()
}

/// Expected response code `rc` with a parameter position.
pub(crate) fn rc_p(rc: Fmt1, p: u8) -> u32 {
    rc.with(Position::parameter(p)).get()
}

/// Expected response code `rc` with a session position.
pub(crate) fn rc_s(rc: Fmt1, s: u8) -> u32 {
    rc.with(Position::session(s)).get()
}

/// Small, fast-to-generate ECC restricted storage key template.
pub(crate) fn ecc_storage_template() -> TpmtPublic<'static> {
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

/// Creates an ECC primary storage key under `hierarchy` (empty hierarchy password) and returns
/// its handle.
pub(crate) fn create_primary(sim: &mut Simulator<'_>, hierarchy: Handle) -> Handle {
    let cmd = CreatePrimary {
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(ecc_storage_template()),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let handles = CreatePrimaryHandles {
        primary_handle: hierarchy,
    };
    let (_, rsp_handles) = execute_with_password_sessions(sim, &cmd, handles, 1, &[])
        .unwrap_or_else(|rc| panic!("CreatePrimary({hierarchy:?}) failed: {rc:#x}"));
    rsp_handles.object_handle
}

/// Makes `object` persistent at `persistent`, authorized by `auth` (empty password).
pub(crate) fn evict(sim: &mut Simulator<'_>, auth: Handle, object: Handle, persistent: u32) {
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

/// Starts an unbound, unsalted session of `session_type` (`0x00` HMAC, `0x01` policy) with
/// SHA-256 and returns its handle.
pub(crate) fn start_session(sim: &mut Simulator<'_>, session_type: u8) -> u32 {
    let mut params = Vec::new();
    params.extend_from_slice(&32u16.to_be_bytes());
    params.extend_from_slice(&[0x11; 32]); // nonceCaller
    params.extend_from_slice(&0u16.to_be_bytes()); // encryptedSalt
    params.push(session_type);
    params.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric = TPM_ALG_NULL
    params.extend_from_slice(&0x000Bu16.to_be_bytes()); // authHash = SHA256
    let cmd = build_cmd(
        ST_NO_SESSIONS,
        0x176,
        &[Handle::RH_NULL.0, Handle::RH_NULL.0],
        None,
        &params,
    );
    let (rc, resp) = send(sim, &cmd);
    assert_eq!(rc, 0, "StartAuthSession failed: {rc:#x}");
    u32::from_be_bytes(resp[10..14].try_into().unwrap())
}
