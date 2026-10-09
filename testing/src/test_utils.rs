use tpm2::commands::{
    Certify, CertifyCreation, Command, FlushContext, GetCapability, GetSessionAuditDigest, GetTime,
    NVCertify, PCREvent, ReadPublic, ReadPublicHandles, Sign, StartAuthSession,
    StartAuthSessionHandles,
};
use tpm2::{Handle, TpmCc, TpmEccCurve, TpmSe, TpmSt};
use tpm2::{Marshal, Unmarshal};

use tpm2::crypto::Rng;
use tpm2::crypto::kdf::kdfa;

use tpm2::Tpm2b;
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bNonce,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveCreate, Tpm2bSensitiveData, Tpm2bTemplate, TpmaObject,
    TpmaSession, TpmiAlgHash, TpmiAlgSymMode, TpmiRsaKeyBits, TpmiStCommandTag, TpmsAuthCommand,
    TpmsAuthResponse, TpmsEccParms, TpmsNvPublic, TpmsRsaParms, TpmsSensitiveCreate, TpmtPublic,
    TpmtRsaScheme, TpmtSymDefObject,
};

pub fn leak_bytes(bytes: &[u8]) -> &'static [u8] {
    Vec::leak(bytes.to_vec())
}

pub fn marshal_to_vec<M: Marshal>(item: &M) -> Vec<u8>
where
    for<'a> &'a mut M::MaxBuffer: TryFrom<&'a mut [u8]>,
{
    let mut tmp = vec![0u8; M::MAX_SIZE];
    let len = item.marshal((&mut tmp[..M::MAX_SIZE]).try_into().ok().unwrap());
    tmp.truncate(len);
    tmp
}

pub fn make_template<M: Marshal>(item: &M) -> Tpm2bTemplate<'static>
where
    for<'a> &'a mut M::MaxBuffer: TryFrom<&'a mut [u8]>,
{
    Tpm2bTemplate::from_bytes(leak_bytes(&marshal_to_vec(item))).unwrap()
}

pub fn make_derive_template(
    pub_area: &TpmtPublic<'_>,
    derive: &tpm2::TpmsDerive<'_>,
) -> Tpm2bTemplate<'static> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&marshal_to_vec(&pub_area.parms_and_id.algorithm()));
    bytes.extend_from_slice(&marshal_to_vec(&pub_area.name_alg));
    bytes.extend_from_slice(&marshal_to_vec(&pub_area.object_attributes));
    bytes.extend_from_slice(&marshal_to_vec(&pub_area.auth_policy));
    match &pub_area.parms_and_id {
        PublicParmsAndId::KeyedHash(parms, _) => bytes.extend_from_slice(&marshal_to_vec(parms)),
        PublicParmsAndId::Sym(parms, _) => bytes.extend_from_slice(&marshal_to_vec(parms)),
        PublicParmsAndId::Rsa(parms, _) => bytes.extend_from_slice(&marshal_to_vec(parms)),
        PublicParmsAndId::Ecc(parms, _) => bytes.extend_from_slice(&marshal_to_vec(parms)),
        PublicParmsAndId::Mldsa(parms, _) => bytes.extend_from_slice(&marshal_to_vec(parms)),
        PublicParmsAndId::HashMldsa(parms, _) => bytes.extend_from_slice(&marshal_to_vec(parms)),
        PublicParmsAndId::Mlkem(parms, _) => bytes.extend_from_slice(&marshal_to_vec(parms)),
    }
    bytes.extend_from_slice(&marshal_to_vec(derive));
    Tpm2bTemplate::from_bytes(leak_bytes(&bytes)).unwrap()
}
use tpm2_platform_linux::PlatformCryptoProvider;
use tpm2_simulator::Simulator;
pub use tpm2_simulator::execute::{CmdHeader, RespHeader};

/// Crypto provider used by the *client* side of the tests (HMAC/KDF/nonce
/// generation, parameter encryption, expected-value computation, ...).
///
/// Tests treat the simulator as a black box, so they never borrow the TPM's
/// own crypto provider; instead they use this independent instance.
pub const CLIENT_CRYPTO: &PlatformCryptoProvider = &PlatformCryptoProvider;

pub fn marshal_to_slice<M: Marshal>(item: &M, buf: &mut [u8]) -> usize
where
    for<'a> &'a mut M::MaxBuffer: TryFrom<&'a mut [u8]>,
{
    if buf.len() >= M::MAX_SIZE {
        item.marshal((&mut buf[..M::MAX_SIZE]).try_into().ok().unwrap())
    } else {
        let mut tmp = vec![0u8; M::MAX_SIZE];
        let len = item.marshal((&mut tmp[..M::MAX_SIZE]).try_into().ok().unwrap());
        buf[..len].copy_from_slice(&tmp[..len]);
        len
    }
}

pub fn execute_with_password_sessions_raw<CmdT: Command>(
    tpm: &mut Simulator<'_>,
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    num_sessions: usize,
    auth_value: &[u8],
    resp_buffer: &mut [u8],
) -> Result<(usize, usize, CmdT::RespHandles), u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut cmd_buffer = [0u8; 16384];
    let mut cmd_header = CmdHeader {
        tag: if num_sessions > 0 {
            TpmiStCommandTag::Sessions
        } else {
            TpmiStCommandTag::NoSessions
        },
        size: 0,
        code: CmdT::CMD_CODE,
    };
    let mut written = cmd_header.marshal((&mut cmd_buffer[0..10]).try_into().unwrap());
    let handles_len = marshal_to_slice(&cmd_handles, &mut cmd_buffer[written..]);
    written += handles_len;

    let mut auth_val = Tpm2bAuth::default();
    if !auth_value.is_empty() {
        auth_val = Tpm2bAuth::from_bytes(auth_value).unwrap();
    }

    let auth_cmd = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: auth_val,
    };

    let mut auth_buffer = [0u8; 1024];
    let mut auth_written = 0;
    for _ in 0..num_sessions {
        auth_written += marshal_to_slice(&auth_cmd, &mut auth_buffer[auth_written..]);
    }

    if num_sessions > 0 {
        written += (auth_written as u32)
            .marshal((&mut cmd_buffer[written..written + 4]).try_into().unwrap());
        cmd_buffer[written..written + auth_written].copy_from_slice(&auth_buffer[..auth_written]);
        written += auth_written;
    }

    let cmd_len = marshal_to_slice(cmd, &mut cmd_buffer[written..]);
    written += cmd_len;

    let mut header_buf = [0u8; 10];
    cmd_header.size = written as u32;
    cmd_header.marshal((&mut header_buf[0..10]).try_into().unwrap());
    cmd_buffer[..10].copy_from_slice(&header_buf[..10]);

    tpm.transact(&cmd_buffer[..written], resp_buffer).unwrap();

    let mut slice = &resp_buffer[..];
    let resp_header = RespHeader::unmarshal(&mut slice).unwrap();
    if resp_header.rc != 0 {
        return Err(resp_header.rc);
    }

    let orig_handles_len = slice.len();
    let resp_handles = CmdT::RespHandles::unmarshal(&mut slice).unwrap();
    let handles_consumed = orig_handles_len - slice.len();
    let mut param_start = 10 + handles_consumed;
    if resp_header.tag == TpmSt::SESSIONS {
        let _param_size = u32::unmarshal(&mut slice).unwrap();
        param_start += 4;
    }

    let resp_size = resp_header.size as usize;
    Ok((param_start, resp_size, resp_handles))
}

pub fn execute_with_password_sessions_status<CmdT: Command>(
    tpm: &mut Simulator<'_>,
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    num_sessions: usize,
    auth_value: &[u8],
) -> Result<CmdT::RespHandles, u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut resp_buffer = [0u8; 16384];
    execute_with_password_sessions_raw(
        tpm,
        cmd,
        cmd_handles,
        num_sessions,
        auth_value,
        &mut resp_buffer,
    )
    .map(|(_, _, handles)| handles)
}

pub fn execute_with_password_sessions<CmdT: Command>(
    tpm: &mut Simulator<'_>,
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    num_sessions: usize,
    auth_value: &[u8],
) -> Result<(CmdT::Response<'static>, CmdT::RespHandles), u32>
where
    CmdT::Response<'static>: Unmarshal<'static>,
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut resp_buffer = [0u8; 16384];
    let (param_start, resp_size, resp_handles) = execute_with_password_sessions_raw(
        tpm,
        cmd,
        cmd_handles,
        num_sessions,
        auth_value,
        &mut resp_buffer,
    )?;
    let mut slice: &'static [u8] = leak_bytes(&resp_buffer[param_start..resp_size]);
    let resp = <CmdT::Response<'static>>::unmarshal(&mut slice).unwrap();
    Ok((resp, resp_handles))
}

pub fn execute_sign<'a>(
    tpm: &mut Simulator<'_>,
    cmd: &tpm2::commands::Sign<'_>,
    cmd_handles: tpm2::commands::SignHandles,
    num_sessions: usize,
    auth_value: &[u8],
    resp_buffer: &'a mut [u8; 4096],
) -> Result<(<Sign<'static> as Command>::Response<'a>, ()), u32> {
    let (param_start, resp_size, handles) = execute_with_password_sessions_raw(
        tpm,
        cmd,
        cmd_handles,
        num_sessions,
        auth_value,
        resp_buffer,
    )?;
    let mut slice = &resp_buffer[param_start..resp_size];
    let resp = Unmarshal::unmarshal(&mut slice).unwrap();
    Ok((resp, handles))
}

pub fn execute_certify<'a>(
    tpm: &mut Simulator<'_>,
    cmd: &tpm2::commands::Certify<'_>,
    cmd_handles: tpm2::commands::CertifyHandles,
    num_sessions: usize,
    auth_value: &[u8],
    resp_buffer: &'a mut [u8; 4096],
) -> Result<(<Certify<'static> as Command>::Response<'a>, ()), u32> {
    let (param_start, resp_size, handles) = execute_with_password_sessions_raw(
        tpm,
        cmd,
        cmd_handles,
        num_sessions,
        auth_value,
        resp_buffer,
    )?;
    let mut slice = &resp_buffer[param_start..resp_size];
    let resp = Unmarshal::unmarshal(&mut slice).unwrap();
    Ok((resp, handles))
}

pub fn execute_nv_certify<'a>(
    tpm: &mut Simulator<'_>,
    cmd: &tpm2::commands::NVCertify<'_>,
    cmd_handles: tpm2::commands::NVCertifyHandles,
    num_sessions: usize,
    auth_value: &[u8],
    resp_buffer: &'a mut [u8; 4096],
) -> Result<(<NVCertify<'static> as Command>::Response<'a>, ()), u32> {
    let (param_start, resp_size, handles) = execute_with_password_sessions_raw(
        tpm,
        cmd,
        cmd_handles,
        num_sessions,
        auth_value,
        resp_buffer,
    )?;
    let mut slice = &resp_buffer[param_start..resp_size];
    let resp = Unmarshal::unmarshal(&mut slice).unwrap();
    Ok((resp, handles))
}

pub fn execute_certify_creation<'a>(
    tpm: &mut Simulator<'_>,
    cmd: &tpm2::commands::CertifyCreation<'_>,
    cmd_handles: tpm2::commands::CertifyCreationHandles,
    num_sessions: usize,
    auth_value: &[u8],
    resp_buffer: &'a mut [u8; 4096],
) -> Result<(<CertifyCreation<'static> as Command>::Response<'a>, ()), u32> {
    let (param_start, resp_size, handles) = execute_with_password_sessions_raw(
        tpm,
        cmd,
        cmd_handles,
        num_sessions,
        auth_value,
        resp_buffer,
    )?;
    let mut slice = &resp_buffer[param_start..resp_size];
    let resp = Unmarshal::unmarshal(&mut slice).unwrap();
    Ok((resp, handles))
}

pub fn execute_get_time<'a>(
    tpm: &mut Simulator<'_>,
    cmd: &tpm2::commands::GetTime<'_>,
    cmd_handles: tpm2::commands::GetTimeHandles,
    num_sessions: usize,
    auth_value: &[u8],
    resp_buffer: &'a mut [u8; 4096],
) -> Result<(<GetTime<'static> as Command>::Response<'a>, ()), u32> {
    let (param_start, resp_size, handles) = execute_with_password_sessions_raw(
        tpm,
        cmd,
        cmd_handles,
        num_sessions,
        auth_value,
        resp_buffer,
    )?;
    let mut slice = &resp_buffer[param_start..resp_size];
    let resp = Unmarshal::unmarshal(&mut slice).unwrap();
    Ok((resp, handles))
}

pub fn execute_get_session_audit_digest<'a>(
    tpm: &mut Simulator<'_>,
    cmd: &tpm2::commands::GetSessionAuditDigest<'_>,
    cmd_handles: tpm2::commands::GetSessionAuditDigestHandles,
    num_sessions: usize,
    auth_value: &[u8],
    resp_buffer: &'a mut [u8; 4096],
) -> Result<
    (
        <GetSessionAuditDigest<'static> as Command>::Response<'a>,
        (),
    ),
    u32,
> {
    let (param_start, resp_size, handles) = execute_with_password_sessions_raw(
        tpm,
        cmd,
        cmd_handles,
        num_sessions,
        auth_value,
        resp_buffer,
    )?;
    let mut slice = &resp_buffer[param_start..resp_size];
    let resp = Unmarshal::unmarshal(&mut slice).unwrap();
    Ok((resp, handles))
}

pub fn execute_get_capability<'a>(
    tpm: &mut Simulator<'_>,
    cmd: &tpm2::commands::GetCapability,
    cmd_handles: (),
    num_sessions: usize,
    auth_value: &[u8],
    resp_buffer: &'a mut [u8; 4096],
) -> Result<(<GetCapability as Command>::Response<'a>, ()), u32> {
    let (param_start, resp_size, handles) = execute_with_password_sessions_raw(
        tpm,
        cmd,
        cmd_handles,
        num_sessions,
        auth_value,
        resp_buffer,
    )?;
    let mut slice = &resp_buffer[param_start..resp_size];
    let resp = Unmarshal::unmarshal(&mut slice).unwrap();
    Ok((resp, handles))
}

/// Reads a single fixed/variable TPM property with
/// `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, property, 1)`.
///
/// Panics if the TPM does not report the requested property.
pub fn get_tpm_property(tpm: &mut Simulator<'_>, property: tpm2::TpmPt) -> u32 {
    let cmd = GetCapability {
        capability: tpm2::TpmCap::TPMProperties,
        property: property.0,
        property_count: 1,
    };
    let (resp, _) = tpm
        .execute_with_handles(cmd, ())
        .expect("TPM2_GetCapability failed");
    match resp.capability_data {
        tpm2::TpmsCapabilityData::TpmProperties(props) => {
            props
                .as_ref()
                .iter()
                .find(|p| p.property == property)
                .unwrap_or_else(|| panic!("TPM did not report property {property:?}"))
                .value
        }
        other => panic!("unexpected capability data: {other:?}"),
    }
}

/// Number of authorization sessions that can be loaded at the same time, as
/// reported by the TPM (`TPM_PT_HR_LOADED_MIN`).
pub fn max_loaded_sessions(tpm: &mut Simulator<'_>) -> usize {
    get_tpm_property(tpm, tpm2::TpmPt::HR_LOADED_MIN) as usize
}

/// Enables or disables `hierarchy` (`TPM_RH_OWNER`, `TPM_RH_ENDORSEMENT`,
/// ...) with `TPM2_HierarchyControl`, authorized by the platform hierarchy
/// using its (default, empty) password.
pub fn set_hierarchy_enabled(tpm: &mut Simulator<'_>, hierarchy: Handle, state: bool) {
    let cmd = tpm2::commands::HierarchyControl {
        enable: hierarchy,
        state,
    };
    let handles = tpm2::commands::HierarchyControlHandles {
        auth_handle: Handle::RH_PLATFORM,
    };
    execute_with_password_sessions(tpm, &cmd, handles, 1, &[])
        .unwrap_or_else(|rc| panic!("TPM2_HierarchyControl failed: {rc:#x}"));
}

pub fn execute_pcr_event<'a>(
    tpm: &mut Simulator<'_>,
    cmd: &tpm2::commands::PCREvent<'_>,
    cmd_handles: tpm2::commands::PCREventHandles,
    num_sessions: usize,
    auth_value: &[u8],
    resp_buffer: &'a mut [u8; 4096],
) -> Result<(<PCREvent<'static> as Command>::Response<'a>, ()), u32> {
    let (param_start, resp_size, handles) = execute_with_password_sessions_raw(
        tpm,
        cmd,
        cmd_handles,
        num_sessions,
        auth_value,
        resp_buffer,
    )?;
    let mut slice = &resp_buffer[param_start..resp_size];
    let resp = Unmarshal::unmarshal(&mut slice).unwrap();
    Ok((resp, handles))
}

pub fn execute_with_corrupted_bytes_raw<CmdT: Command>(
    tpm: &mut Simulator<'_>,
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    num_sessions: usize,
    auth_value: &[u8],
    corrupt_fn: impl FnOnce(&mut [u8]),
    resp_buffer: &mut [u8],
) -> Result<(usize, usize, CmdT::RespHandles), u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut cmd_buffer = [0u8; 16384];
    let mut cmd_header = CmdHeader {
        tag: if num_sessions > 0 {
            TpmiStCommandTag::Sessions
        } else {
            TpmiStCommandTag::NoSessions
        },
        size: 0,
        code: CmdT::CMD_CODE,
    };
    let mut written = cmd_header.marshal((&mut cmd_buffer[0..10]).try_into().unwrap());
    let handles_len = marshal_to_slice(&cmd_handles, &mut cmd_buffer[written..]);
    written += handles_len;

    let mut auth_val = Tpm2bAuth::default();
    if !auth_value.is_empty() {
        auth_val = Tpm2bAuth::from_bytes(auth_value).unwrap();
    }

    let auth_cmd = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: auth_val,
    };

    let mut auth_buffer = [0u8; 1024];
    let mut auth_written = 0;
    for _ in 0..num_sessions {
        auth_written += marshal_to_slice(&auth_cmd, &mut auth_buffer[auth_written..]);
    }

    if num_sessions > 0 {
        written += (auth_written as u32)
            .marshal((&mut cmd_buffer[written..written + 4]).try_into().unwrap());
        cmd_buffer[written..written + auth_written].copy_from_slice(&auth_buffer[..auth_written]);
        written += auth_written;
    }

    let payload_start = written;
    let cmd_len = marshal_to_slice(cmd, &mut cmd_buffer[written..]);
    written += cmd_len;

    corrupt_fn(&mut cmd_buffer[payload_start..written]);

    let mut header_buf = [0u8; 10];
    cmd_header.size = written as u32;
    cmd_header.marshal((&mut header_buf[0..10]).try_into().unwrap());
    cmd_buffer[..10].copy_from_slice(&header_buf[..10]);

    tpm.transact(&cmd_buffer[..written], resp_buffer).unwrap();

    let mut slice = &resp_buffer[..];
    let resp_header = RespHeader::unmarshal(&mut slice).unwrap();
    if resp_header.rc != 0 {
        return Err(resp_header.rc);
    }

    let orig_handles_len = slice.len();
    let resp_handles = CmdT::RespHandles::unmarshal(&mut slice).unwrap();
    let handles_consumed = orig_handles_len - slice.len();
    let mut param_start = 10 + handles_consumed;
    if resp_header.tag == TpmSt::SESSIONS {
        let _param_size = u32::unmarshal(&mut slice).unwrap();
        param_start += 4;
    }

    let resp_size = resp_header.size as usize;
    Ok((param_start, resp_size, resp_handles))
}

pub fn execute_with_corrupted_bytes_status<CmdT: Command>(
    tpm: &mut Simulator<'_>,
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    num_sessions: usize,
    auth_value: &[u8],
    corrupt_fn: impl FnOnce(&mut [u8]),
) -> Result<CmdT::RespHandles, u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut resp_buffer = [0u8; 16384];
    execute_with_corrupted_bytes_raw(
        tpm,
        cmd,
        cmd_handles,
        num_sessions,
        auth_value,
        corrupt_fn,
        &mut resp_buffer,
    )
    .map(|(_, _, handles)| handles)
}

pub fn execute_with_corrupted_bytes<CmdT: Command>(
    tpm: &mut Simulator<'_>,
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    num_sessions: usize,
    auth_value: &[u8],
    corrupt_fn: impl FnOnce(&mut [u8]),
) -> Result<(CmdT::Response<'static>, CmdT::RespHandles), u32>
where
    CmdT::Response<'static>: Unmarshal<'static>,
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut resp_buffer = [0u8; 16384];
    let (param_start, resp_size, resp_handles) = execute_with_corrupted_bytes_raw(
        tpm,
        cmd,
        cmd_handles,
        num_sessions,
        auth_value,
        corrupt_fn,
        &mut resp_buffer,
    )?;
    let mut slice: &'static [u8] = leak_bytes(&resp_buffer[param_start..resp_size]);
    let resp = <CmdT::Response<'static>>::unmarshal(&mut slice).unwrap();
    Ok((resp, resp_handles))
}

pub fn flush_context(tpm: &mut Simulator<'_>, handle: Handle) -> Result<(), u32> {
    let cmd = FlushContext {
        flush_handle: handle,
    };
    execute_with_password_sessions(tpm, &cmd, (), 0, &[]).map(|_| ())
}

pub fn read_public_name(tpm: &mut Simulator<'_>, handle: Handle) -> Tpm2bName<'static> {
    let cmd = ReadPublic::default();
    let handles = ReadPublicHandles {
        object_handle: handle,
    };
    let (resp, _) = execute_with_password_sessions(tpm, &cmd, handles, 0, &[]).unwrap();
    resp.name
}

pub fn create_test_keys() -> (Tpm2bSensitiveCreate<'static>, Tpm2bTemplate<'static>) {
    let tpmt_sensitive = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = Tpm2b(tpmt_sensitive);

    let rsa_parms = TpmsRsaParms {
        symmetric: None,
        scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        key_bits: TpmiRsaKeyBits(2048),
        exponent: 0,
    };
    let pubkey = Tpm2bPublicKeyRsa::default();

    let tpmt_public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::from_bits_retain(0x00040072),
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, pubkey),
    };
    let mut buf = [0u8; TpmtPublic::MAX_SIZE];
    let len = tpmt_public.marshal(&mut buf);
    let in_public = Tpm2bTemplate::from_bytes(leak_bytes(&buf[..len])).unwrap();

    (in_sensitive, in_public)
}

/// Client-side view of an authorization session started on the simulator.
///
/// Everything here is tracked by the test client itself (the TPM is treated
/// as a black box), mirroring what a real TPM software stack has to remember.
#[derive(Clone, Debug)]
pub struct ActiveSession {
    pub session_handle: Handle,
    pub nonce_caller: Tpm2bNonce<'static>,
    pub nonce_tpm: Tpm2bNonce<'static>,
    pub session_key: Vec<u8>,
    pub auth_hash: TpmiAlgHash,
    pub symmetric: Option<TpmtSymDefObject>,
    pub attributes: TpmaSession,
    pub bind_auth: Vec<u8>,
    pub bind_entity: Handle,
    /// The session type passed to `TPM2_StartAuthSession`.
    pub session_type: TpmSe,
    /// Set once `TPM2_PolicyAuthValue` has been executed on this (policy)
    /// session; see [`ActiveSession::mark_policy_auth_value`].
    pub policy_auth_value_needed: bool,
    /// Set once `TPM2_PolicyPassword` has been executed on this (policy)
    /// session; see [`ActiveSession::mark_policy_password`].
    pub policy_password_needed: bool,
}

impl ActiveSession {
    /// Records that `TPM2_PolicyAuthValue` succeeded on this policy session,
    /// so the authValue of the authorized entity is included in the session
    /// HMAC / parameter-encryption keys of the next authorized command.
    pub fn mark_policy_auth_value(&mut self) {
        self.policy_auth_value_needed = true;
    }

    /// Records that `TPM2_PolicyPassword` succeeded on this policy session.
    pub fn mark_policy_password(&mut self) {
        self.policy_password_needed = true;
    }

    /// Clears the policy flags, mirroring the TPM resetting a policy session
    /// after it has been used successfully for authorization (or after
    /// `TPM2_PolicyRestart`).
    pub fn reset_policy_flags(&mut self) {
        self.policy_auth_value_needed = false;
        self.policy_password_needed = false;
    }
}

fn kdfa_sha256(
    crypto: &PlatformCryptoProvider,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    bits: u32,
    out: &mut [u8],
) {
    kdfa(
        crypto,
        TpmiAlgHash::Sha256,
        key,
        label,
        context_u,
        context_v,
        bits,
        out,
    )
    .unwrap();
}

fn compute_client_hash(
    crypto: &PlatformCryptoProvider,
    auth_hash: TpmiAlgHash,
    updates: &[&[u8]],
) -> Vec<u8> {
    let mut state = tpm2::crypto::HashCtx::new(crypto, auth_hash).unwrap();
    for data in updates {
        state.update(data).unwrap();
    }
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    state.finalize(&mut out).unwrap().digest().to_vec()
}

fn compute_client_hmac(
    crypto: &PlatformCryptoProvider,
    auth_hash: TpmiAlgHash,
    key: &[u8],
    updates: &[&[u8]],
) -> Vec<u8> {
    let mut state = tpm2::crypto::HmacCtx::new(crypto, auth_hash, key).unwrap();
    for data in updates {
        state.update(data).unwrap();
    }
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    state.finalize(&mut out).unwrap().digest().to_vec()
}

pub fn start_auth_session(
    tpm: &mut Simulator<'_>,
    tpm_key: Handle,
    bind: Handle,
    bind_auth: &[u8],
    session_type: TpmSe,
    symmetric: Option<TpmtSymDefObject>,
    auth_hash: TpmiAlgHash,
) -> Result<ActiveSession, u32> {
    let mut nonce_bytes = [0u8; 16];
    CLIENT_CRYPTO.get_random(&mut nonce_bytes).unwrap();
    let nonce_caller = Tpm2bNonce::from_bytes(leak_bytes(&nonce_bytes)).unwrap();

    let cmd = StartAuthSession {
        nonce_caller,
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type,
        symmetric: symmetric.map(tpm2::TpmtSymDef::from),
        auth_hash,
    };
    let handles = StartAuthSessionHandles { tpm_key, bind };

    let (resp, resp_handles) = execute_with_password_sessions(tpm, &cmd, handles, 0, &[])?;

    let session_key = if bind == Handle::RH_NULL && tpm_key == Handle::RH_NULL {
        Vec::new()
    } else {
        let key = bind_auth.to_vec();
        let hash_size = match auth_hash {
            TpmiAlgHash::Sha1 => 20,
            TpmiAlgHash::Sha256 => 32,
            TpmiAlgHash::Sha384 => 48,
            TpmiAlgHash::Sha512 => 64,
            _ => 32,
        };
        let session_key_bits = (hash_size as u32) * 8;
        let mut derived = vec![0u8; (session_key_bits.div_ceil(8)) as usize];

        kdfa_by_alg(
            CLIENT_CRYPTO,
            auth_hash,
            &key,
            b"ATH",
            resp.nonce_tpm.get_buffer(),
            nonce_caller.get_buffer(),
            session_key_bits,
            &mut derived,
        );
        derived
    };

    Ok(ActiveSession {
        session_handle: resp_handles.session_handle,
        nonce_caller,
        nonce_tpm: resp.nonce_tpm,
        session_key,
        auth_hash,
        symmetric,
        attributes: TpmaSession::from_bits_retain(0),
        bind_auth: bind_auth.to_vec(),
        bind_entity: bind,
        session_type,
        policy_auth_value_needed: false,
        policy_password_needed: false,
    })
}

/// Returns the Name of `handle` as used in cpHash/rpHash computations.
///
/// For loaded transient and persistent objects the Name is queried from the TPM with
/// `TPM2_ReadPublic` (as a real TSS would), and NV Indices with `TPM2_NV_ReadPublic`. For every
/// other handle — or if the query fails, e.g. for sequence objects — the handle value itself is
/// used.
pub fn entity_name(tpm: &mut Simulator<'_>, handle: Handle) -> Vec<u8> {
    if (handle.0 >> 24 == 0x80 || handle.0 >> 24 == 0x81)
        && let Ok((resp, _)) = tpm.execute_with_handles(
            ReadPublic {},
            ReadPublicHandles {
                object_handle: handle,
            },
        )
    {
        return resp.name.get_buffer().to_vec();
    }
    // NV Indices are named by nameAlg || H(nvPublic), as reported by TPM2_NV_ReadPublic.
    if handle.0 >> 24 == 0x01
        && let Ok((resp, _)) = tpm.execute_with_handles(
            tpm2::commands::NVReadPublic {},
            tpm2::commands::NVReadPublicHandles { nv_index: handle },
        )
    {
        return resp.nv_name.get_buffer().to_vec();
    }
    handle.0.to_be_bytes().to_vec()
}

/// Decides whether the authorized entity's authValue must be appended to the
/// session key when computing HMAC / parameter-encryption keys for `session`.
///
/// The rules (TPM 2.0 Part 1, 19.6 and 21.3) are:
/// - HMAC sessions include the authValue unless the session is bound to the
///   entity being authorized.
/// - Policy sessions include the authValue only if `TPM2_PolicyAuthValue` (or
///   `TPM2_PolicyPassword`) has been executed on the session.
///
/// The policy flags are tracked client-side in [`ActiveSession`]. This MUST be
/// evaluated **before** the command is transacted: on a successful command
/// with `continueSession` set, the TPM resets a policy session *after* it has
/// computed the response HMAC and encrypted the response parameters with the
/// authValue included, and the client mirrors that reset once the response
/// has been processed.
fn session_includes_auth(session: &ActiveSession, is_bound: bool) -> bool {
    include_auth_for(
        session.session_type == TpmSe::Policy,
        is_bound,
        session.policy_auth_value_needed,
        session.policy_password_needed,
    )
}

/// Pure decision logic behind [`session_includes_auth`], split out so it can be
/// unit tested without a simulator.
fn include_auth_for(
    is_policy: bool,
    is_bound: bool,
    is_auth_value_needed: bool,
    is_password_needed: bool,
) -> bool {
    if is_policy {
        is_auth_value_needed || is_password_needed
    } else {
        !is_bound
    }
}

/// Builds the HMAC / KDF key for a session: `sessionKey || authValue` when
/// `include_auth` is set (with trailing zeros stripped from the authValue, as
/// the TPM does), otherwise just `sessionKey`.
///
/// `include_auth` should come from [`session_includes_auth`] evaluated before
/// the command was sent.
fn session_hmac_key(session: &ActiveSession, entity_auth: &[u8], include_auth: bool) -> Vec<u8> {
    if include_auth {
        [
            session.session_key.as_slice(),
            strip_trailing_zeros(entity_auth),
        ]
        .concat()
    } else {
        session.session_key.clone()
    }
}

pub fn execute_with_hmac_sessions_raw<CmdT: Command>(
    tpm: &mut Simulator<'_>,
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    _handle_names: &[&[u8]],
    sessions: &mut [ActiveSession],
    entity_auths: &[&[u8]],
) -> Result<(Vec<u8>, CmdT::RespHandles), u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut cmd_buffer = [0u8; 16384];
    let mut cmd_header = CmdHeader {
        tag: if sessions.is_empty() {
            TpmiStCommandTag::NoSessions
        } else {
            TpmiStCommandTag::Sessions
        },
        size: 0,
        code: CmdT::CMD_CODE,
    };

    let mut written = cmd_header.marshal((&mut cmd_buffer[0..10]).try_into().unwrap());
    let handles_len = marshal_to_slice(&cmd_handles, &mut cmd_buffer[written..]);
    written += handles_len;

    let session_size_pos = written;
    let num_handles = (session_size_pos - 10) / 4;
    let mut handles = Vec::new();
    for idx in 0..num_handles {
        let handle_bytes = [
            cmd_buffer[10 + idx * 4],
            cmd_buffer[11 + idx * 4],
            cmd_buffer[12 + idx * 4],
            cmd_buffer[13 + idx * 4],
        ];
        handles.push(Handle(u32::from_be_bytes(handle_bytes)));
    }
    let (session_to_handle_idx, session_to_handle_idx_len) =
        map_sessions_to_handles(CmdT::CMD_CODE, &handles, sessions.len());
    // Snapshot, per session, whether the authValue is part of the HMAC / KDF key.
    // This must happen before transacting: the TPM resets policy-session flags
    // (e.g. after PolicyAuthValue) once a continueSession command succeeds, but
    // the response HMAC and response encryption still use the pre-command state.
    let include_auths: Vec<bool> = sessions
        .iter()
        .enumerate()
        .map(|(i, session)| {
            let is_bound = session.bind_entity != Handle::RH_NULL
                && i < session_to_handle_idx_len
                && session.bind_entity == handles[session_to_handle_idx[i]];
            session_includes_auth(session, is_bound)
        })
        .collect();
    if !sessions.is_empty() {
        written += 4; // Reserve space for sessionSize
    }

    let sessions_start_pos = written;

    let command_handle_names = if _handle_names.is_empty() {
        let num_handles = (session_size_pos - 10) / 4;
        let mut extracted = Vec::new();
        for i in 0..num_handles {
            let handle_bytes = [
                cmd_buffer[10 + i * 4],
                cmd_buffer[11 + i * 4],
                cmd_buffer[12 + i * 4],
                cmd_buffer[13 + i * 4],
            ];
            let handle = u32::from_be_bytes(handle_bytes);
            let name = entity_name(tpm, Handle(handle));
            extracted.push(name);
        }
        extracted
    } else {
        _handle_names.iter().map(|n| n.to_vec()).collect()
    };

    // Generate new nonces and encrypt first parameter if needed
    let mut param_buf = [0u8; 16384];
    let param_len = marshal_to_slice(cmd, &mut param_buf);

    let mut nonce_callers_new = Vec::new();
    let mut decrypt_session_idx = None;
    let mut encrypt_session_idx = None;

    for (i, session) in sessions.iter_mut().enumerate() {
        let mut nonce_bytes = [0u8; 16];
        CLIENT_CRYPTO.get_random(&mut nonce_bytes).unwrap();
        let nonce_caller_new = Tpm2bNonce::from_bytes(leak_bytes(&nonce_bytes)).unwrap();
        nonce_callers_new.push(nonce_caller_new);

        if session.attributes.contains(TpmaSession::DECRYPT) {
            decrypt_session_idx = Some(i);
        }
        if session.attributes.contains(TpmaSession::ENCRYPT) {
            encrypt_session_idx = Some(i);
        }
    }

    let mut new_auth_bytes = Vec::new();
    let mut resp_entity_auths = entity_auths.to_vec();
    if CmdT::CMD_CODE == tpm2::TpmCc::HierarchyChangeAuth {
        let mut slice = &param_buf[..param_len];
        if let Ok(new_auth) = tpm2::Tpm2bAuth::unmarshal(&mut slice) {
            new_auth_bytes = new_auth.get_buffer().to_vec();
        }
    }
    if !new_auth_bytes.is_empty() {
        resp_entity_auths[0] = &new_auth_bytes;
    }

    // Encrypt parameter if decrypt session is active
    if let Some(idx) = decrypt_session_idx {
        let session = &sessions[idx];
        std::println!(
            "CLIENT PARAM DECRYPTION SESSION: handle={:x?}, idx={}",
            session.session_handle,
            idx
        );
        let session = &sessions[idx];
        let nonce_caller_new = &nonce_callers_new[idx];

        let leading_size = 2; // only 2B is supported
        let size = u16::from_be_bytes([param_buf[0], param_buf[1]]) as usize;

        let bits = match &session.symmetric {
            Some(TpmtSymDefObject::Aes128(_)) => 128 + 128,
            Some(TpmtSymDefObject::Aes256(_)) => 256 + 128,
            _ => 0,
        };

        if bits > 0 {
            let mut sym_key_bytes = vec![0u8; (bits / 8) as usize];
            let entity_auth = if idx < num_handles
                || (idx < entity_auths.len() && CmdT::CMD_CODE == tpm2::TpmCc::CreatePrimary)
            {
                entity_auths[idx]
            } else {
                &[]
            };
            let key = session_hmac_key(session, entity_auth, include_auths[idx]);
            kdfa_by_alg(
                CLIENT_CRYPTO,
                session.auth_hash,
                &key,
                b"CFB",
                nonce_caller_new.get_buffer(),
                session.nonce_tpm.get_buffer(),
                bits,
                &mut sym_key_bytes,
            );

            let key_size = (bits - 128) as usize / 8;
            let mut iv = sym_key_bytes[key_size..key_size + 16].to_vec();
            let sym_alg = tpm2::TpmtSymDefObject::aes_cfb((key_size * 8) as u16).unwrap();
            tpm2::crypto::encrypt(
                CLIENT_CRYPTO,
                sym_alg,
                &sym_key_bytes[0..key_size],
                &mut iv,
                &mut param_buf[leading_size..leading_size + size],
            )
            .unwrap();
        }
    }

    // Build auth commands (HMACs)
    let mut auth_written = 0;
    let mut auth_buffer = [0u8; 1024];

    for (i, session) in sessions.iter().enumerate() {
        let auth_hash = session.auth_hash;
        let mut cp_hash_updates = Vec::new();
        let cmd_code_bytes = (CmdT::CMD_CODE.code()).to_be_bytes();
        cp_hash_updates.push(cmd_code_bytes.as_slice());
        for name in &command_handle_names {
            cp_hash_updates.push(name.as_slice());
        }
        let param_bytes = &param_buf[..param_len];
        cp_hash_updates.push(param_bytes);

        let cp_hash = compute_client_hash(CLIENT_CRYPTO, auth_hash, &cp_hash_updates);

        let nonce_caller_new = &nonce_callers_new[i];
        let entity_auth = if i < num_handles
            || (i < entity_auths.len() && CmdT::CMD_CODE == tpm2::TpmCc::CreatePrimary)
        {
            entity_auths[i]
        } else {
            &[]
        };
        let hmac_key = session_hmac_key(session, entity_auth, include_auths[i]);

        let mut hmac_updates = Vec::new();
        hmac_updates.push(cp_hash.as_slice());
        hmac_updates.push(nonce_caller_new.get_buffer());
        hmac_updates.push(session.nonce_tpm.get_buffer());

        if i == 0 {
            if let Some(dec_idx) = decrypt_session_idx
                && dec_idx > 0
            {
                hmac_updates.push(sessions[dec_idx].nonce_tpm.get_buffer());
            }
            if let Some(enc_idx) = encrypt_session_idx
                && enc_idx > 0
                && Some(enc_idx) != decrypt_session_idx
            {
                hmac_updates.push(sessions[enc_idx].nonce_tpm.get_buffer());
            }
        }

        let attr_byte = [session.attributes.bits()];
        hmac_updates.push(&attr_byte);

        let hmac_bytes = compute_client_hmac(CLIENT_CRYPTO, auth_hash, &hmac_key, &hmac_updates);
        let hmac_val = Tpm2bAuth::from_bytes(&hmac_bytes).unwrap();

        let auth_cmd = TpmsAuthCommand {
            session_handle: session.session_handle,
            nonce: *nonce_caller_new,
            session_attributes: session.attributes,
            hmac: hmac_val,
        };

        auth_written += marshal_to_slice(&auth_cmd, &mut auth_buffer[auth_written..]);
    }

    // Marshal sessions into cmd_buffer
    if !sessions.is_empty() {
        let size_u32 = auth_written as u32;
        size_u32.marshal(
            (&mut cmd_buffer[session_size_pos..session_size_pos + 4])
                .try_into()
                .unwrap(),
        );
        cmd_buffer[sessions_start_pos..sessions_start_pos + auth_written]
            .copy_from_slice(&auth_buffer[..auth_written]);
        written = sessions_start_pos + auth_written;
    }

    // Marshal parameters
    cmd_buffer[written..written + param_len].copy_from_slice(&param_buf[..param_len]);
    written += param_len;

    // Update commandSize in header
    cmd_header.size = written as u32;
    let mut header_buf = [0u8; 10];
    cmd_header.marshal((&mut header_buf[0..10]).try_into().unwrap());
    cmd_buffer[..10].copy_from_slice(&header_buf[..10]);

    // Transact
    let mut resp_buffer = [0u8; 16384];
    let resp_bytes = tpm
        .transact(&cmd_buffer[..written], &mut resp_buffer)
        .unwrap();

    // Parse response
    let mut slice: &[u8] = resp_bytes;
    let resp_header = RespHeader::unmarshal(&mut slice).unwrap();
    if resp_header.rc != 0 {
        return Err(resp_header.rc);
    }

    let resp_handles = CmdT::RespHandles::unmarshal(&mut slice).unwrap();

    let mut parameter_size = 0;
    if resp_header.tag == TpmSt::SESSIONS {
        parameter_size = u32::unmarshal(&mut slice).unwrap() as usize;
    }
    // Get parameters slice
    let (encrypted_param_buf, rest) = slice.split_at(parameter_size);
    let mut slice_sess = rest;

    let mut nonce_tpms_new = Vec::new();
    let mut resp_attributes = Vec::new();
    let mut resp_hmacs = Vec::new();

    for _ in 0..sessions.len() {
        let auth_resp = TpmsAuthResponse::unmarshal(&mut slice_sess).unwrap();
        nonce_tpms_new
            .push(Tpm2bNonce::from_bytes(leak_bytes(auth_resp.nonce.get_buffer())).unwrap());
        resp_attributes.push(auth_resp.session_attributes);
        resp_hmacs.push(auth_resp.hmac);
    }

    // Decrypt parameters if encrypt session is active
    let mut decrypted_param_buf = encrypted_param_buf.to_vec();
    if let Some(idx) = encrypt_session_idx
        && !decrypted_param_buf.is_empty()
    {
        let session = &sessions[idx];
        let nonce_tpm_new = &nonce_tpms_new[idx];
        let nonce_caller_new = &nonce_callers_new[idx];

        let leading_size = 2;
        let size = u16::from_be_bytes([decrypted_param_buf[0], decrypted_param_buf[1]]) as usize;

        let bits = match &session.symmetric {
            Some(TpmtSymDefObject::Aes128(_)) => 128 + 128,
            Some(TpmtSymDefObject::Aes256(_)) => 256 + 128,
            _ => 0,
        };

        if bits > 0 {
            let mut sym_key_bytes = vec![0u8; (bits / 8) as usize];
            let entity_auth = if idx < num_handles {
                entity_auths[idx]
            } else {
                &[]
            };
            let key = session_hmac_key(session, entity_auth, include_auths[idx]);
            kdfa_by_alg(
                CLIENT_CRYPTO,
                session.auth_hash,
                &key,
                b"CFB",
                nonce_tpm_new.get_buffer(),
                nonce_caller_new.get_buffer(),
                bits,
                &mut sym_key_bytes,
            );

            let key_size = (bits - 128) as usize / 8;
            let mut iv = sym_key_bytes[key_size..key_size + 16].to_vec();
            let sym_alg = tpm2::TpmtSymDefObject::aes_cfb((key_size * 8) as u16).unwrap();
            tpm2::crypto::decrypt(
                CLIENT_CRYPTO,
                sym_alg,
                &sym_key_bytes[0..key_size],
                &mut iv,
                &mut decrypted_param_buf[leading_size..leading_size + size],
            )
            .unwrap();
        }
    }

    // Verify response HMACs
    for (i, session) in sessions.iter().enumerate() {
        let auth_hash = session.auth_hash;

        let mut rp_hash_updates = Vec::new();
        let rc_bytes = 0u32.to_be_bytes();
        let cmd_code_bytes = (CmdT::CMD_CODE.code()).to_be_bytes();
        rp_hash_updates.push(rc_bytes.as_slice());
        rp_hash_updates.push(cmd_code_bytes.as_slice());
        rp_hash_updates.push(encrypted_param_buf);

        let rp_hash = compute_client_hash(CLIENT_CRYPTO, auth_hash, &rp_hash_updates);

        let nonce_tpm_new = &nonce_tpms_new[i];
        let nonce_caller_new = &nonce_callers_new[i];
        let entity_auth = if i < num_handles {
            resp_entity_auths[i]
        } else {
            &[]
        };
        // Use the include-auth decision captured before the command was sent;
        // the TPM may have reset the policy session state since.
        let hmac_key = session_hmac_key(session, entity_auth, include_auths[i]);

        let mut hmac_updates = Vec::new();
        hmac_updates.push(rp_hash.as_slice());
        hmac_updates.push(nonce_tpm_new.get_buffer());
        hmac_updates.push(nonce_caller_new.get_buffer());

        let attr_byte = [resp_attributes[i].bits()];
        hmac_updates.push(&attr_byte);

        let hmac_bytes = compute_client_hmac(CLIENT_CRYPTO, auth_hash, &hmac_key, &hmac_updates);
        assert_eq!(
            hmac_bytes.as_slice(),
            resp_hmacs[i].get_buffer(),
            "Response HMAC verification failed"
        );
    }

    // Update session nonces
    for (i, session) in sessions.iter_mut().enumerate() {
        session.nonce_caller = nonce_callers_new[i];
        session.nonce_tpm = nonce_tpms_new[i];
        // A policy session used successfully for authorization is reset by the
        // TPM (TPM 2.0 Part 1, 19.7.1), clearing PolicyAuthValue/PolicyPassword.
        if session.session_type == TpmSe::Policy && i < session_to_handle_idx_len {
            session.reset_policy_flags();
        }
    }

    Ok((decrypted_param_buf[..parameter_size].to_vec(), resp_handles))
}

pub fn execute_with_hmac_sessions_status<CmdT: Command>(
    tpm: &mut Simulator<'_>,
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    handle_names: &[&[u8]],
    sessions: &mut [ActiveSession],
    entity_auths: &[&[u8]],
) -> Result<CmdT::RespHandles, u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    execute_with_hmac_sessions_raw(tpm, cmd, cmd_handles, handle_names, sessions, entity_auths)
        .map(|(_, h)| h)
}

pub fn execute_with_hmac_sessions<CmdT: Command>(
    tpm: &mut Simulator<'_>,
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    handle_names: &[&[u8]],
    sessions: &mut [ActiveSession],
    entity_auths: &[&[u8]],
) -> Result<(CmdT::Response<'static>, CmdT::RespHandles), u32>
where
    CmdT::Response<'static>: Unmarshal<'static>,
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let (decrypted_param_buf, resp_handles) = execute_with_hmac_sessions_raw(
        tpm,
        cmd,
        cmd_handles,
        handle_names,
        sessions,
        entity_auths,
    )?;
    let mut slice_params: &'static [u8] = leak_bytes(&decrypted_param_buf);
    let resp = <CmdT::Response<'static>>::unmarshal(&mut slice_params).unwrap();
    Ok((resp, resp_handles))
}

#[derive(Clone, Copy, Debug)]
pub enum ResponseCorruption {
    Hmac,
    NonceTpm,
    Attributes,
}

pub fn execute_with_hmac_sessions_mismatch_nonce<CmdT: Command>(
    tpm: &mut Simulator<'_>,
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    _handle_names: &[&[u8]],
    sessions: &mut [ActiveSession],
    entity_auths: &[&[u8]],
) -> Result<(CmdT::Response<'static>, CmdT::RespHandles), u32>
where
    CmdT::Response<'static>: Unmarshal<'static>,
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut cmd_buffer = [0u8; 16384];
    let mut cmd_header = CmdHeader {
        tag: if sessions.is_empty() {
            TpmiStCommandTag::NoSessions
        } else {
            TpmiStCommandTag::Sessions
        },
        size: 0,
        code: CmdT::CMD_CODE,
    };

    let mut written = cmd_header.marshal((&mut cmd_buffer[0..10]).try_into().unwrap());
    let handles_len = marshal_to_slice(&cmd_handles, &mut cmd_buffer[written..]);
    written += handles_len;

    let session_size_pos = written;
    let num_handles = (session_size_pos - 10) / 4;
    let mut handles = Vec::new();
    for idx in 0..num_handles {
        let handle_bytes = [
            cmd_buffer[10 + idx * 4],
            cmd_buffer[11 + idx * 4],
            cmd_buffer[12 + idx * 4],
            cmd_buffer[13 + idx * 4],
        ];
        handles.push(Handle(u32::from_be_bytes(handle_bytes)));
    }
    let (session_to_handle_idx, session_to_handle_idx_len) =
        map_sessions_to_handles(CmdT::CMD_CODE, &handles, sessions.len());
    if !sessions.is_empty() {
        written += 4; // Reserve space for sessionSize
    }

    let sessions_start_pos = written;

    let command_handle_names = if _handle_names.is_empty() {
        let num_handles = (session_size_pos - 10) / 4;
        let mut extracted = Vec::new();
        for i in 0..num_handles {
            let handle_bytes = [
                cmd_buffer[10 + i * 4],
                cmd_buffer[11 + i * 4],
                cmd_buffer[12 + i * 4],
                cmd_buffer[13 + i * 4],
            ];
            let handle = u32::from_be_bytes(handle_bytes);
            let name = entity_name(tpm, Handle(handle));
            extracted.push(name);
        }
        extracted
    } else {
        _handle_names.iter().map(|n| n.to_vec()).collect()
    };

    // Generate new nonces and encrypt first parameter if needed
    let mut param_buf = [0u8; 16384];
    let param_len = marshal_to_slice(cmd, &mut param_buf);

    let mut nonce_callers_new = Vec::new();
    let mut decrypt_session_idx = None;
    let mut encrypt_session_idx = None;

    for (i, session) in sessions.iter_mut().enumerate() {
        let mut nonce_bytes = [0u8; 16];
        CLIENT_CRYPTO.get_random(&mut nonce_bytes).unwrap();
        let nonce_caller_new = Tpm2bNonce::from_bytes(leak_bytes(&nonce_bytes)).unwrap();
        nonce_callers_new.push(nonce_caller_new);

        if session.attributes.contains(TpmaSession::DECRYPT) {
            decrypt_session_idx = Some(i);
        }
        if session.attributes.contains(TpmaSession::ENCRYPT) {
            encrypt_session_idx = Some(i);
        }
    }

    let mut new_auth_bytes = Vec::new();
    let mut resp_entity_auths = entity_auths.to_vec();
    if CmdT::CMD_CODE == tpm2::TpmCc::HierarchyChangeAuth {
        let mut slice = &param_buf[..param_len];
        if let Ok(new_auth) = tpm2::Tpm2bAuth::unmarshal(&mut slice) {
            new_auth_bytes = new_auth.get_buffer().to_vec();
        }
    }
    if !new_auth_bytes.is_empty() {
        resp_entity_auths[0] = &new_auth_bytes;
    }

    // Encrypt parameter if decrypt session is active
    if let Some(idx) = decrypt_session_idx {
        let session = &sessions[idx];
        std::println!(
            "CLIENT PARAM DECRYPTION SESSION: handle={:x?}, idx={}",
            session.session_handle,
            idx
        );
        let session = &sessions[idx];
        let nonce_caller_new = &nonce_callers_new[idx];

        let leading_size = 2; // only 2B is supported
        let size = u16::from_be_bytes([param_buf[0], param_buf[1]]) as usize;

        let bits = match &session.symmetric {
            Some(TpmtSymDefObject::Aes128(_)) => 128 + 128,
            Some(TpmtSymDefObject::Aes256(_)) => 256 + 128,
            _ => 0,
        };

        if bits > 0 {
            let mut sym_key_bytes = vec![0u8; (bits / 8) as usize];
            let key = if idx < num_handles {
                [
                    session.session_key.as_slice(),
                    strip_trailing_zeros(entity_auths[idx]),
                ]
                .concat()
            } else {
                session.session_key.clone()
            };
            kdfa_by_alg(
                CLIENT_CRYPTO,
                session.auth_hash,
                &key,
                b"CFB",
                nonce_caller_new.get_buffer(),
                session.nonce_tpm.get_buffer(),
                bits,
                &mut sym_key_bytes,
            );

            let key_size = (bits - 128) as usize / 8;
            let mut iv = sym_key_bytes[key_size..key_size + 16].to_vec();
            let sym_alg = tpm2::TpmtSymDefObject::aes_cfb((key_size * 8) as u16).unwrap();
            tpm2::crypto::encrypt(
                CLIENT_CRYPTO,
                sym_alg,
                &sym_key_bytes[0..key_size],
                &mut iv,
                &mut param_buf[leading_size..leading_size + size],
            )
            .unwrap();
        }
    }

    // Build auth commands (HMACs)
    let mut auth_written = 0;
    let mut auth_buffer = [0u8; 1024];

    for (i, session) in sessions.iter().enumerate() {
        let auth_hash = session.auth_hash;
        let mut cp_hash_updates = Vec::new();
        let cmd_code_bytes = (CmdT::CMD_CODE.code()).to_be_bytes();
        cp_hash_updates.push(cmd_code_bytes.as_slice());
        for name in &command_handle_names {
            cp_hash_updates.push(name.as_slice());
        }
        let param_bytes = &param_buf[..param_len];
        cp_hash_updates.push(param_bytes);

        let cp_hash = compute_client_hash(CLIENT_CRYPTO, auth_hash, &cp_hash_updates);

        let nonce_caller_new = &nonce_callers_new[i];
        let entity_auth = if i < num_handles {
            entity_auths[i]
        } else {
            &[]
        };
        let is_bound = if session.bind_entity != Handle::RH_NULL {
            if i < session_to_handle_idx_len {
                let h_idx = session_to_handle_idx[i];
                let h = handles[h_idx];
                session.bind_entity == h
            } else {
                false
            }
        } else {
            false
        };

        let hmac_key = if is_bound {
            session.session_key.clone()
        } else {
            [
                session.session_key.as_slice(),
                strip_trailing_zeros(entity_auth),
            ]
            .concat()
        };

        let mut hmac_updates = Vec::new();
        hmac_updates.push(cp_hash.as_slice());
        hmac_updates.push(nonce_caller_new.get_buffer());
        hmac_updates.push(session.nonce_tpm.get_buffer());

        if i == 0 {
            if let Some(dec_idx) = decrypt_session_idx
                && dec_idx > 0
            {
                hmac_updates.push(sessions[dec_idx].nonce_tpm.get_buffer());
            }
            if let Some(enc_idx) = encrypt_session_idx
                && enc_idx > 0
                && Some(enc_idx) != decrypt_session_idx
            {
                hmac_updates.push(sessions[enc_idx].nonce_tpm.get_buffer());
            }
        }

        let attr_byte = [session.attributes.bits()];
        hmac_updates.push(&attr_byte);

        let hmac_bytes = compute_client_hmac(CLIENT_CRYPTO, auth_hash, &hmac_key, &hmac_updates);
        let hmac_val = Tpm2bAuth::from_bytes(&hmac_bytes).unwrap();

        // Mismatch: generate another random 16-byte nonce for wire but keep nonce_caller_new for HMAC
        let mut nonce_bytes_wire = [0u8; 16];
        CLIENT_CRYPTO.get_random(&mut nonce_bytes_wire).unwrap();
        let nonce_caller_wire = Tpm2bNonce::from_bytes(&nonce_bytes_wire).unwrap();

        let auth_cmd = TpmsAuthCommand {
            session_handle: session.session_handle,
            nonce: nonce_caller_wire,
            session_attributes: session.attributes,
            hmac: hmac_val,
        };

        auth_written += marshal_to_slice(&auth_cmd, &mut auth_buffer[auth_written..]);
    }

    // Marshal sessions into cmd_buffer
    if !sessions.is_empty() {
        let size_u32 = auth_written as u32;
        size_u32.marshal(
            (&mut cmd_buffer[session_size_pos..session_size_pos + 4])
                .try_into()
                .unwrap(),
        );
        cmd_buffer[sessions_start_pos..sessions_start_pos + auth_written]
            .copy_from_slice(&auth_buffer[..auth_written]);
        written = sessions_start_pos + auth_written;
    }

    // Marshal parameters
    cmd_buffer[written..written + param_len].copy_from_slice(&param_buf[..param_len]);
    written += param_len;

    // Update commandSize in header
    cmd_header.size = written as u32;
    let mut header_buf = [0u8; 10];
    cmd_header.marshal((&mut header_buf[0..10]).try_into().unwrap());
    cmd_buffer[..10].copy_from_slice(&header_buf[..10]);

    // Transact
    let mut resp_buffer = [0u8; 16384];
    let resp_bytes = tpm
        .transact(&cmd_buffer[..written], &mut resp_buffer)
        .unwrap();

    // Parse response
    let mut slice: &[u8] = resp_bytes;
    let resp_header = RespHeader::unmarshal(&mut slice).unwrap();
    if resp_header.rc != 0 {
        return Err(resp_header.rc);
    }

    let resp_handles = CmdT::RespHandles::unmarshal(&mut slice).unwrap();

    let mut parameter_size = 0;
    if resp_header.tag == TpmSt::SESSIONS {
        parameter_size = u32::unmarshal(&mut slice).unwrap() as usize;
    }
    // Get parameters slice
    let (encrypted_param_buf, rest) = slice.split_at(parameter_size);
    let mut slice_sess = rest;

    let mut nonce_tpms_new = Vec::new();
    let mut resp_attributes = Vec::new();
    let mut resp_hmacs = Vec::new();

    for _ in 0..sessions.len() {
        let auth_resp = TpmsAuthResponse::unmarshal(&mut slice_sess).unwrap();
        nonce_tpms_new
            .push(Tpm2bNonce::from_bytes(leak_bytes(auth_resp.nonce.get_buffer())).unwrap());
        resp_attributes.push(auth_resp.session_attributes);
        resp_hmacs.push(auth_resp.hmac);
    }

    // Decrypt parameters if encrypt session is active
    let mut decrypted_param_buf = encrypted_param_buf.to_vec();
    if let Some(idx) = encrypt_session_idx
        && !decrypted_param_buf.is_empty()
    {
        let session = &sessions[idx];
        let nonce_tpm_new = &nonce_tpms_new[idx];
        let nonce_caller_new = &nonce_callers_new[idx];

        let leading_size = 2;
        let size = u16::from_be_bytes([decrypted_param_buf[0], decrypted_param_buf[1]]) as usize;

        let bits = match &session.symmetric {
            Some(TpmtSymDefObject::Aes128(_)) => 128 + 128,
            Some(TpmtSymDefObject::Aes256(_)) => 256 + 128,
            _ => 0,
        };

        if bits > 0 {
            let mut sym_key_bytes = vec![0u8; (bits / 8) as usize];
            let key = if idx < num_handles {
                [
                    session.session_key.as_slice(),
                    strip_trailing_zeros(entity_auths[idx]),
                ]
                .concat()
            } else {
                session.session_key.clone()
            };
            kdfa_by_alg(
                CLIENT_CRYPTO,
                session.auth_hash,
                &key,
                b"CFB",
                nonce_tpm_new.get_buffer(),
                nonce_caller_new.get_buffer(),
                bits,
                &mut sym_key_bytes,
            );

            let key_size = (bits - 128) as usize / 8;
            let mut iv = sym_key_bytes[key_size..key_size + 16].to_vec();
            let sym_alg = tpm2::TpmtSymDefObject::aes_cfb((key_size * 8) as u16).unwrap();
            tpm2::crypto::decrypt(
                CLIENT_CRYPTO,
                sym_alg,
                &sym_key_bytes[0..key_size],
                &mut iv,
                &mut decrypted_param_buf[leading_size..leading_size + size],
            )
            .unwrap();
        }
    }

    // Verify response HMACs
    for (i, session) in sessions.iter().enumerate() {
        let auth_hash = session.auth_hash;

        let mut rp_hash_updates = Vec::new();
        let rc_bytes = 0u32.to_be_bytes();
        let cmd_code_bytes = (CmdT::CMD_CODE.code()).to_be_bytes();
        rp_hash_updates.push(rc_bytes.as_slice());
        rp_hash_updates.push(cmd_code_bytes.as_slice());
        rp_hash_updates.push(encrypted_param_buf);

        let rp_hash = compute_client_hash(CLIENT_CRYPTO, auth_hash, &rp_hash_updates);

        let nonce_tpm_new = &nonce_tpms_new[i];
        let nonce_caller_new = &nonce_callers_new[i];
        let entity_auth = if i < num_handles {
            resp_entity_auths[i]
        } else {
            &[]
        };
        let is_bound = if session.bind_entity != Handle::RH_NULL {
            if i < session_to_handle_idx_len {
                let h_idx = session_to_handle_idx[i];
                let h = handles[h_idx];
                session.bind_entity == h
            } else {
                false
            }
        } else {
            false
        };

        let hmac_key = if is_bound {
            session.session_key.clone()
        } else {
            [
                session.session_key.as_slice(),
                strip_trailing_zeros(entity_auth),
            ]
            .concat()
        };

        let mut hmac_updates = Vec::new();
        hmac_updates.push(rp_hash.as_slice());
        hmac_updates.push(nonce_tpm_new.get_buffer());
        hmac_updates.push(nonce_caller_new.get_buffer());

        let attr_byte = [resp_attributes[i].bits()];
        hmac_updates.push(&attr_byte);

        let hmac_bytes = compute_client_hmac(CLIENT_CRYPTO, auth_hash, &hmac_key, &hmac_updates);
        assert_eq!(
            hmac_bytes.as_slice(),
            resp_hmacs[i].get_buffer(),
            "Response HMAC verification failed"
        );
    }

    // Update session nonces
    for (i, session) in sessions.iter_mut().enumerate() {
        session.nonce_caller = nonce_callers_new[i];
        session.nonce_tpm = nonce_tpms_new[i];
    }

    // Unmarshal final response from decrypted parameters
    let mut slice_params: &'static [u8] = leak_bytes(&decrypted_param_buf[..parameter_size]);
    let resp = <CmdT::Response<'static>>::unmarshal(&mut slice_params).unwrap();

    Ok((resp, resp_handles))
}

pub fn execute_with_hmac_sessions_corrupt_response<CmdT: Command>(
    tpm: &mut Simulator<'_>,
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    _handle_names: &[&[u8]],
    sessions: &mut [ActiveSession],
    entity_auths: &[&[u8]],
    corruption: ResponseCorruption,
) -> Result<(CmdT::Response<'static>, CmdT::RespHandles), u32>
where
    CmdT::Response<'static>: Unmarshal<'static>,
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut cmd_buffer = [0u8; 16384];
    let mut cmd_header = CmdHeader {
        tag: if sessions.is_empty() {
            TpmiStCommandTag::NoSessions
        } else {
            TpmiStCommandTag::Sessions
        },
        size: 0,
        code: CmdT::CMD_CODE,
    };

    let mut written = cmd_header.marshal((&mut cmd_buffer[0..10]).try_into().unwrap());
    let handles_len = marshal_to_slice(&cmd_handles, &mut cmd_buffer[written..]);
    written += handles_len;

    let session_size_pos = written;
    let num_handles = (session_size_pos - 10) / 4;
    let mut handles = Vec::new();
    for idx in 0..num_handles {
        let handle_bytes = [
            cmd_buffer[10 + idx * 4],
            cmd_buffer[11 + idx * 4],
            cmd_buffer[12 + idx * 4],
            cmd_buffer[13 + idx * 4],
        ];
        handles.push(Handle(u32::from_be_bytes(handle_bytes)));
    }
    let (session_to_handle_idx, session_to_handle_idx_len) =
        map_sessions_to_handles(CmdT::CMD_CODE, &handles, sessions.len());
    if !sessions.is_empty() {
        written += 4; // Reserve space for sessionSize
    }

    let sessions_start_pos = written;

    let command_handle_names = if _handle_names.is_empty() {
        let num_handles = (session_size_pos - 10) / 4;
        let mut extracted = Vec::new();
        for i in 0..num_handles {
            let handle_bytes = [
                cmd_buffer[10 + i * 4],
                cmd_buffer[11 + i * 4],
                cmd_buffer[12 + i * 4],
                cmd_buffer[13 + i * 4],
            ];
            let handle = u32::from_be_bytes(handle_bytes);
            let name = entity_name(tpm, Handle(handle));
            extracted.push(name);
        }
        extracted
    } else {
        _handle_names.iter().map(|n| n.to_vec()).collect()
    };

    // Generate new nonces and encrypt first parameter if needed
    let mut param_buf = [0u8; 16384];
    let param_len = marshal_to_slice(cmd, &mut param_buf);

    let mut nonce_callers_new = Vec::new();
    let mut decrypt_session_idx = None;
    let mut encrypt_session_idx = None;

    for (i, session) in sessions.iter_mut().enumerate() {
        let mut nonce_bytes = [0u8; 16];
        CLIENT_CRYPTO.get_random(&mut nonce_bytes).unwrap();
        let nonce_caller_new = Tpm2bNonce::from_bytes(leak_bytes(&nonce_bytes)).unwrap();
        nonce_callers_new.push(nonce_caller_new);

        if session.attributes.contains(TpmaSession::DECRYPT) {
            decrypt_session_idx = Some(i);
        }
        if session.attributes.contains(TpmaSession::ENCRYPT) {
            encrypt_session_idx = Some(i);
        }
    }

    let mut new_auth_bytes = Vec::new();
    let mut resp_entity_auths = entity_auths.to_vec();
    if CmdT::CMD_CODE == tpm2::TpmCc::HierarchyChangeAuth {
        let mut slice = &param_buf[..param_len];
        if let Ok(new_auth) = tpm2::Tpm2bAuth::unmarshal(&mut slice) {
            new_auth_bytes = new_auth.get_buffer().to_vec();
        }
    }
    if !new_auth_bytes.is_empty() {
        resp_entity_auths[0] = &new_auth_bytes;
    }

    // Encrypt parameter if decrypt session is active
    if let Some(idx) = decrypt_session_idx {
        let session = &sessions[idx];
        std::println!(
            "CLIENT PARAM DECRYPTION SESSION: handle={:x?}, idx={}",
            session.session_handle,
            idx
        );
        let session = &sessions[idx];
        let nonce_caller_new = &nonce_callers_new[idx];

        let leading_size = 2; // only 2B is supported
        let size = u16::from_be_bytes([param_buf[0], param_buf[1]]) as usize;

        let bits = match &session.symmetric {
            Some(TpmtSymDefObject::Aes128(_)) => 128 + 128,
            Some(TpmtSymDefObject::Aes256(_)) => 256 + 128,
            _ => 0,
        };

        if bits > 0 {
            let mut sym_key_bytes = vec![0u8; (bits / 8) as usize];
            let key = if idx < num_handles {
                [
                    session.session_key.as_slice(),
                    strip_trailing_zeros(entity_auths[idx]),
                ]
                .concat()
            } else {
                session.session_key.clone()
            };
            kdfa_by_alg(
                CLIENT_CRYPTO,
                session.auth_hash,
                &key,
                b"CFB",
                nonce_caller_new.get_buffer(),
                session.nonce_tpm.get_buffer(),
                bits,
                &mut sym_key_bytes,
            );

            let key_size = (bits - 128) as usize / 8;
            let mut iv = sym_key_bytes[key_size..key_size + 16].to_vec();
            let sym_alg = tpm2::TpmtSymDefObject::aes_cfb((key_size * 8) as u16).unwrap();
            tpm2::crypto::encrypt(
                CLIENT_CRYPTO,
                sym_alg,
                &sym_key_bytes[0..key_size],
                &mut iv,
                &mut param_buf[leading_size..leading_size + size],
            )
            .unwrap();
        }
    }

    // Build auth commands (HMACs)
    let mut auth_written = 0;
    let mut auth_buffer = [0u8; 1024];

    for (i, session) in sessions.iter().enumerate() {
        let auth_hash = session.auth_hash;
        let mut cp_hash_updates = Vec::new();
        let cmd_code_bytes = (CmdT::CMD_CODE.code()).to_be_bytes();
        cp_hash_updates.push(cmd_code_bytes.as_slice());
        for name in &command_handle_names {
            cp_hash_updates.push(name.as_slice());
        }
        let param_bytes = &param_buf[..param_len];
        cp_hash_updates.push(param_bytes);

        let cp_hash = compute_client_hash(CLIENT_CRYPTO, auth_hash, &cp_hash_updates);

        let nonce_caller_new = &nonce_callers_new[i];
        let entity_auth = if i < num_handles {
            entity_auths[i]
        } else {
            &[]
        };
        let is_bound = if session.bind_entity != Handle::RH_NULL {
            if i < session_to_handle_idx_len {
                let h_idx = session_to_handle_idx[i];
                let h = handles[h_idx];
                session.bind_entity == h
            } else {
                false
            }
        } else {
            false
        };

        let hmac_key = if is_bound {
            session.session_key.clone()
        } else {
            [
                session.session_key.as_slice(),
                strip_trailing_zeros(entity_auth),
            ]
            .concat()
        };

        let mut hmac_updates = Vec::new();
        hmac_updates.push(cp_hash.as_slice());
        hmac_updates.push(nonce_caller_new.get_buffer());
        hmac_updates.push(session.nonce_tpm.get_buffer());

        if i == 0 {
            if let Some(dec_idx) = decrypt_session_idx
                && dec_idx > 0
            {
                hmac_updates.push(sessions[dec_idx].nonce_tpm.get_buffer());
            }
            if let Some(enc_idx) = encrypt_session_idx
                && enc_idx > 0
                && Some(enc_idx) != decrypt_session_idx
            {
                hmac_updates.push(sessions[enc_idx].nonce_tpm.get_buffer());
            }
        }

        let attr_byte = [session.attributes.bits()];
        hmac_updates.push(&attr_byte);

        let hmac_bytes = compute_client_hmac(CLIENT_CRYPTO, auth_hash, &hmac_key, &hmac_updates);
        let hmac_val = Tpm2bAuth::from_bytes(&hmac_bytes).unwrap();

        let auth_cmd = TpmsAuthCommand {
            session_handle: session.session_handle,
            nonce: *nonce_caller_new,
            session_attributes: session.attributes,
            hmac: hmac_val,
        };

        auth_written += marshal_to_slice(&auth_cmd, &mut auth_buffer[auth_written..]);
    }

    // Marshal sessions into cmd_buffer
    if !sessions.is_empty() {
        let size_u32 = auth_written as u32;
        size_u32.marshal(
            (&mut cmd_buffer[session_size_pos..session_size_pos + 4])
                .try_into()
                .unwrap(),
        );
        cmd_buffer[sessions_start_pos..sessions_start_pos + auth_written]
            .copy_from_slice(&auth_buffer[..auth_written]);
        written = sessions_start_pos + auth_written;
    }

    // Marshal parameters
    cmd_buffer[written..written + param_len].copy_from_slice(&param_buf[..param_len]);
    written += param_len;

    // Update commandSize in header
    cmd_header.size = written as u32;
    let mut header_buf = [0u8; 10];
    cmd_header.marshal((&mut header_buf[0..10]).try_into().unwrap());
    cmd_buffer[..10].copy_from_slice(&header_buf[..10]);

    // Transact
    let mut resp_buffer = [0u8; 16384];
    let resp_bytes = tpm
        .transact(&cmd_buffer[..written], &mut resp_buffer)
        .unwrap();

    // Parse response
    let mut slice: &[u8] = resp_bytes;
    let resp_header = RespHeader::unmarshal(&mut slice).unwrap();
    if resp_header.rc != 0 {
        return Err(resp_header.rc);
    }

    let resp_handles = CmdT::RespHandles::unmarshal(&mut slice).unwrap();

    let mut parameter_size = 0;
    if resp_header.tag == TpmSt::SESSIONS {
        parameter_size = u32::unmarshal(&mut slice).unwrap() as usize;
    }
    // Get parameters slice
    let (encrypted_param_buf, rest) = slice.split_at(parameter_size);
    let mut slice_sess = rest;

    let mut nonce_tpms_new = Vec::new();
    let mut resp_attributes = Vec::new();
    let mut resp_hmacs = Vec::new();

    for _ in 0..sessions.len() {
        let auth_resp = TpmsAuthResponse::unmarshal(&mut slice_sess).unwrap();
        nonce_tpms_new
            .push(Tpm2bNonce::from_bytes(leak_bytes(auth_resp.nonce.get_buffer())).unwrap());
        resp_attributes.push(auth_resp.session_attributes);
        resp_hmacs.push(auth_resp.hmac);
    }

    // Corrupt response field before verification
    match corruption {
        ResponseCorruption::Hmac => {
            if !resp_hmacs.is_empty() {
                let mut hmac_bytes = resp_hmacs[0].get_buffer().to_vec();
                if !hmac_bytes.is_empty() {
                    hmac_bytes[0] ^= 1;
                }
                resp_hmacs[0] = tpm2::Tpm2bAuth::from_bytes(leak_bytes(&hmac_bytes)).unwrap();
            }
        }
        ResponseCorruption::NonceTpm => {
            if !nonce_tpms_new.is_empty() {
                let mut nonce_bytes = nonce_tpms_new[0].get_buffer().to_vec();
                if !nonce_bytes.is_empty() {
                    nonce_bytes[0] ^= 1;
                }
                nonce_tpms_new[0] = Tpm2bNonce::from_bytes(leak_bytes(&nonce_bytes)).unwrap();
            }
        }
        ResponseCorruption::Attributes => {
            if !resp_attributes.is_empty() {
                resp_attributes[0] = TpmaSession::from_bits_retain(resp_attributes[0].bits() ^ 1);
            }
        }
    }

    // Decrypt parameters if encrypt session is active
    let mut decrypted_param_buf = encrypted_param_buf.to_vec();
    if let Some(idx) = encrypt_session_idx
        && !decrypted_param_buf.is_empty()
    {
        let session = &sessions[idx];
        let nonce_tpm_new = &nonce_tpms_new[idx];
        let nonce_caller_new = &nonce_callers_new[idx];

        let leading_size = 2;
        let size = u16::from_be_bytes([decrypted_param_buf[0], decrypted_param_buf[1]]) as usize;

        let bits = match &session.symmetric {
            Some(TpmtSymDefObject::Aes128(_)) => 128 + 128,
            Some(TpmtSymDefObject::Aes256(_)) => 256 + 128,
            _ => 0,
        };

        if bits > 0 {
            let mut sym_key_bytes = vec![0u8; (bits / 8) as usize];
            let key = if idx < num_handles {
                [
                    session.session_key.as_slice(),
                    strip_trailing_zeros(entity_auths[idx]),
                ]
                .concat()
            } else {
                session.session_key.clone()
            };
            kdfa_by_alg(
                CLIENT_CRYPTO,
                session.auth_hash,
                &key,
                b"CFB",
                nonce_tpm_new.get_buffer(),
                nonce_caller_new.get_buffer(),
                bits,
                &mut sym_key_bytes,
            );

            let key_size = (bits - 128) as usize / 8;
            let mut iv = sym_key_bytes[key_size..key_size + 16].to_vec();
            let sym_alg = tpm2::TpmtSymDefObject::aes_cfb((key_size * 8) as u16).unwrap();
            tpm2::crypto::decrypt(
                CLIENT_CRYPTO,
                sym_alg,
                &sym_key_bytes[0..key_size],
                &mut iv,
                &mut decrypted_param_buf[leading_size..leading_size + size],
            )
            .unwrap();
        }
    }

    // Verify response HMACs
    for (i, session) in sessions.iter().enumerate() {
        let auth_hash = session.auth_hash;

        let mut rp_hash_updates = Vec::new();
        let rc_bytes = 0u32.to_be_bytes();
        let cmd_code_bytes = (CmdT::CMD_CODE.code()).to_be_bytes();
        rp_hash_updates.push(rc_bytes.as_slice());
        rp_hash_updates.push(cmd_code_bytes.as_slice());
        rp_hash_updates.push(encrypted_param_buf);

        let rp_hash = compute_client_hash(CLIENT_CRYPTO, auth_hash, &rp_hash_updates);

        let nonce_tpm_new = &nonce_tpms_new[i];
        let nonce_caller_new = &nonce_callers_new[i];
        let entity_auth = if i < num_handles {
            resp_entity_auths[i]
        } else {
            &[]
        };
        let is_bound = if session.bind_entity != Handle::RH_NULL {
            if i < session_to_handle_idx_len {
                let h_idx = session_to_handle_idx[i];
                let h = handles[h_idx];
                session.bind_entity == h
            } else {
                false
            }
        } else {
            false
        };

        let hmac_key = if is_bound {
            session.session_key.clone()
        } else {
            [
                session.session_key.as_slice(),
                strip_trailing_zeros(entity_auth),
            ]
            .concat()
        };

        let mut hmac_updates = Vec::new();
        hmac_updates.push(rp_hash.as_slice());
        hmac_updates.push(nonce_tpm_new.get_buffer());
        hmac_updates.push(nonce_caller_new.get_buffer());

        if i == 0 {
            if let Some(dec_idx) = decrypt_session_idx
                && dec_idx > 0
            {
                hmac_updates.push(nonce_callers_new[dec_idx].get_buffer());
            }
            if let Some(enc_idx) = encrypt_session_idx
                && enc_idx > 0
                && Some(enc_idx) != decrypt_session_idx
            {
                hmac_updates.push(nonce_callers_new[enc_idx].get_buffer());
            }
        }

        let attr_byte = [resp_attributes[i].bits()];
        hmac_updates.push(&attr_byte);

        let hmac_bytes = compute_client_hmac(CLIENT_CRYPTO, auth_hash, &hmac_key, &hmac_updates);
        assert_eq!(
            hmac_bytes.as_slice(),
            resp_hmacs[i].get_buffer(),
            "Response HMAC verification failed"
        );
    }

    // Update session nonces
    for (i, session) in sessions.iter_mut().enumerate() {
        session.nonce_caller = nonce_callers_new[i];
        session.nonce_tpm = nonce_tpms_new[i];
    }

    // Unmarshal final response from decrypted parameters
    let mut slice_params: &'static [u8] = leak_bytes(&decrypted_param_buf[..parameter_size]);
    let resp = <CmdT::Response<'static>>::unmarshal(&mut slice_params).unwrap();

    Ok((resp, resp_handles))
}

pub struct PolicyCalculator {
    pub policy_digest: Vec<u8>,
    pub auth_hash: TpmiAlgHash,
}

impl PolicyCalculator {
    pub fn new(auth_hash: TpmiAlgHash) -> Self {
        let digest_size = match auth_hash {
            TpmiAlgHash::Sha1 => 20,
            TpmiAlgHash::Sha256 => 32,
            TpmiAlgHash::Sha384 => 48,
            TpmiAlgHash::Sha512 => 64,
            _ => panic!("Unsupported auth hash"),
        };
        Self {
            policy_digest: vec![0u8; digest_size],
            auth_hash,
        }
    }

    pub fn policy_or(&mut self, p_hash_list: &[Tpm2bDigest]) {
        let crypto = PlatformCryptoProvider;
        let digest_size = self.policy_digest.len();
        let zero_digest = vec![0u8; digest_size];

        let mut concat = Vec::new();
        for digest in p_hash_list {
            concat.extend_from_slice(digest.get_buffer());
        }

        let new_digest = compute_client_hash(
            &crypto,
            self.auth_hash,
            &[
                &zero_digest,
                &(tpm2::TpmCc::PolicyOR.code()).to_be_bytes(),
                &concat,
            ],
        );
        self.policy_digest = new_digest;
    }

    pub fn policy_authorize_nv(&mut self, nv_name: &Tpm2bName) {
        let crypto = PlatformCryptoProvider;
        let new_digest = compute_client_hash(
            &crypto,
            self.auth_hash,
            &[
                &self.policy_digest,
                &(tpm2::TpmCc::PolicyAuthorizeNV.code()).to_be_bytes(),
                nv_name.get_buffer(),
            ],
        );
        self.policy_digest = new_digest;
    }

    pub fn policy_secret(&mut self, auth_name: &[u8], policy_ref: &[u8]) {
        let crypto = PlatformCryptoProvider;
        let intermediate = compute_client_hash(
            &crypto,
            self.auth_hash,
            &[
                &self.policy_digest,
                &(tpm2::TpmCc::PolicySecret.code()).to_be_bytes(),
                auth_name,
            ],
        );
        let final_digest =
            compute_client_hash(&crypto, self.auth_hash, &[&intermediate, policy_ref]);
        self.policy_digest = final_digest;
    }

    pub fn policy_signed(&mut self, auth_name: &[u8], policy_ref: &[u8]) {
        let crypto = PlatformCryptoProvider;
        let intermediate = compute_client_hash(
            &crypto,
            self.auth_hash,
            &[
                &self.policy_digest,
                &(tpm2::TpmCc::PolicySigned.code()).to_be_bytes(),
                auth_name,
            ],
        );
        let final_digest =
            compute_client_hash(&crypto, self.auth_hash, &[&intermediate, policy_ref]);
        self.policy_digest = final_digest;
    }

    pub fn policy_pcr(&mut self, pcrs: &tpm2::TpmlPcrSelection, pcr_digest: &[u8]) {
        let crypto = PlatformCryptoProvider;
        let mut pcrs_buf = [0u8; 1024];
        let pcrs_len = marshal_to_slice(pcrs, &mut pcrs_buf);
        let new_digest = compute_client_hash(
            &crypto,
            self.auth_hash,
            &[
                &self.policy_digest,
                &(tpm2::TpmCc::PolicyPCR.code()).to_be_bytes(),
                &pcrs_buf[..pcrs_len],
                pcr_digest,
            ],
        );
        self.policy_digest = new_digest;
    }

    pub fn policy_cp_hash(&mut self, cp_hash_a: &[u8]) {
        let crypto = PlatformCryptoProvider;
        let new_digest = compute_client_hash(
            &crypto,
            self.auth_hash,
            &[
                &self.policy_digest,
                &(tpm2::TpmCc::PolicyCpHash.code()).to_be_bytes(),
                cp_hash_a,
            ],
        );
        self.policy_digest = new_digest;
    }

    pub fn policy_authorize(&mut self, key_sign: &[u8], policy_ref: &[u8]) {
        let crypto = PlatformCryptoProvider;
        let intermediate = compute_client_hash(
            &crypto,
            self.auth_hash,
            &[
                &self.policy_digest,
                &(tpm2::TpmCc::PolicyAuthorize.code()).to_be_bytes(),
                key_sign,
            ],
        );
        let final_digest =
            compute_client_hash(&crypto, self.auth_hash, &[&intermediate, policy_ref]);
        self.policy_digest = final_digest;
    }

    pub fn policy_nv_written(&mut self, written_set: bool) {
        let crypto = PlatformCryptoProvider;
        let mut written_set_buf = [0u8; 1];
        written_set.marshal(&mut written_set_buf);
        let new_digest = compute_client_hash(
            &crypto,
            self.auth_hash,
            &[
                &self.policy_digest,
                &(tpm2::TpmCc::PolicyNvWritten.code()).to_be_bytes(),
                &written_set_buf,
            ],
        );
        self.policy_digest = new_digest;
    }

    pub fn policy_nv(
        &mut self,
        operand_b: &[u8],
        offset: u16,
        operation: tpm2::TpmEo,
        nv_name: &Tpm2bName,
    ) {
        let crypto = PlatformCryptoProvider;
        let offset_bytes = offset.to_be_bytes();
        let operation_bytes = u16::from(operation).to_be_bytes();
        let args = compute_client_hash(
            &crypto,
            self.auth_hash,
            &[operand_b, &offset_bytes, &operation_bytes],
        );
        let new_digest = compute_client_hash(
            &crypto,
            self.auth_hash,
            &[
                &self.policy_digest,
                &(tpm2::TpmCc::PolicyNV.code()).to_be_bytes(),
                &args,
                nv_name.get_buffer(),
            ],
        );
        self.policy_digest = new_digest;
    }

    pub fn policy_auth_value(&mut self) {
        let crypto = PlatformCryptoProvider;
        let new_digest = compute_client_hash(
            &crypto,
            self.auth_hash,
            &[
                &self.policy_digest,
                &(tpm2::TpmCc::PolicyAuthValue.code()).to_be_bytes(),
            ],
        );
        self.policy_digest = new_digest;
    }

    pub fn policy_duplication_select(
        &mut self,
        object_name: &[u8],
        new_parent_name: &[u8],
        include_object: bool,
    ) {
        let crypto = PlatformCryptoProvider;
        let mut include_object_buf = [0u8; 1];
        include_object.marshal(&mut include_object_buf);
        let new_digest = if include_object {
            compute_client_hash(
                &crypto,
                self.auth_hash,
                &[
                    &self.policy_digest,
                    &(tpm2::TpmCc::PolicyDuplicationSelect.code()).to_be_bytes(),
                    object_name,
                    new_parent_name,
                    &include_object_buf,
                ],
            )
        } else {
            compute_client_hash(
                &crypto,
                self.auth_hash,
                &[
                    &self.policy_digest,
                    &(tpm2::TpmCc::PolicyDuplicationSelect.code()).to_be_bytes(),
                    new_parent_name,
                    &include_object_buf,
                ],
            )
        };
        self.policy_digest = new_digest;
    }
}

pub fn nv_name(nv_public: &TpmsNvPublic<'_>) -> Tpm2bName<'static> {
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(nv_public, &mut buf);
    let crypto = PlatformCryptoProvider;
    let digest = compute_client_hash(&crypto, nv_public.name_alg, &[&buf[..len]]);
    let mut name_bytes = [0u8; 66];
    name_bytes[0..2].copy_from_slice(&tpm2::Alg::from(nv_public.name_alg).id().to_be_bytes());
    name_bytes[2..2 + digest.len()].copy_from_slice(&digest);
    Tpm2bName::from_bytes(leak_bytes(&name_bytes[..2 + digest.len()])).unwrap()
}

pub fn rsa_ek_template() -> TpmtPublic<'static> {
    static AUTH_POLICY: [u8; 32] = [
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7,
        0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
        0x69, 0xAA,
    ];
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::ADMIN_WITH_POLICY
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::from_bytes(&AUTH_POLICY).unwrap(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    }
}

pub fn ecc_ek_template() -> TpmtPublic<'static> {
    static AUTH_POLICY: [u8; 32] = [
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7,
        0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
        0x69, 0xAA,
    ];
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::ADMIN_WITH_POLICY
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::from_bytes(&AUTH_POLICY).unwrap(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            tpm2::TpmsEccPoint {
                x: tpm2::Tpm2bEccParameter::default(),
                y: tpm2::Tpm2bEccParameter::default(),
            },
        ),
    }
}

pub fn strip_trailing_zeros(auth: &[u8]) -> &[u8] {
    let mut len = auth.len();
    while len > 0 && auth[len - 1] == 0 {
        len -= 1;
    }
    &auth[..len]
}

#[allow(clippy::too_many_arguments)]
pub fn kdfa_by_alg(
    crypto: &PlatformCryptoProvider,
    auth_hash: TpmiAlgHash,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    bits: u32,
    out: &mut [u8],
) {
    kdfa(
        crypto, auth_hash, key, label, context_u, context_v, bits, out,
    )
    .unwrap();
}

pub fn handle_requires_auth(cc: TpmCc, handle_index: usize) -> bool {
    if handle_index == 0 {
        matches!(
            cc,
            TpmCc::HierarchyChangeAuth
                | TpmCc::Clear
                | TpmCc::ClearControl
                | TpmCc::HierarchyControl
                | TpmCc::SetPrimaryPolicy
                | TpmCc::ChangePPS
                | TpmCc::ChangeEPS
                | TpmCc::PCRSetAuthValue
                | TpmCc::PCRSetAuthPolicy
                | TpmCc::DictionaryAttackLockReset
                | TpmCc::DictionaryAttackParameters
                | TpmCc::PPCommands
                | TpmCc::SetAlgorithmSet
                | TpmCc::FieldUpgradeStart
                | TpmCc::FieldUpgradeData
                | TpmCc::FirmwareRead
                | TpmCc::CreatePrimary
                | TpmCc::Create
                | TpmCc::CreateLoaded
                | TpmCc::Load
                | TpmCc::LoadExternal
                | TpmCc::Unseal
                | TpmCc::ReadPublic
                | TpmCc::ActivateCredential
                | TpmCc::MakeCredential
                | TpmCc::EvictControl
                | TpmCc::ContextSave
                | TpmCc::ContextLoad
                | TpmCc::FlushContext
                | TpmCc::GetTestResult
                | TpmCc::Certify
                | TpmCc::CertifyCreation
                | TpmCc::Duplicate
                | TpmCc::Import
                | TpmCc::ObjectChangeAuth
                | TpmCc::ReadClock
                | TpmCc::GetTime
                | TpmCc::GetSessionAuditDigest
                | TpmCc::GetCommandAuditDigest
                | TpmCc::HashSequenceStart
                | TpmCc::Hash
                | TpmCc::SequenceComplete
                | TpmCc::Sign
                | TpmCc::VerifySignature
                | TpmCc::RSAEncrypt
                | TpmCc::RSADecrypt
                | TpmCc::ECDHZGen
                | TpmCc::ECCParameters
                | TpmCc::ZGen2Phase
                | TpmCc::EncryptDecrypt
                | TpmCc::EncryptDecrypt2
                | TpmCc::GetRandom
                | TpmCc::StirRandom
                | TpmCc::MAC
                | TpmCc::MACStart
                | TpmCc::PolicySigned
                | TpmCc::PolicySecret
                | TpmCc::PolicyTicket
                | TpmCc::PolicyOR
                | TpmCc::PolicyPCR
                | TpmCc::PolicyLocality
                | TpmCc::PolicyNV
                | TpmCc::PolicyCounterTimer
                | TpmCc::PolicyCommandCode
                | TpmCc::PolicyPhysicalPresence
                | TpmCc::PolicyCpHash
                | TpmCc::PolicyNameHash
                | TpmCc::PolicyAuthorize
                | TpmCc::PolicyAuthValue
                | TpmCc::PolicyPassword
                | TpmCc::PolicyGetDigest
                | TpmCc::PolicyNvWritten
                | TpmCc::PolicyTemplate
                | TpmCc::PolicyAuthorizeNV
                | TpmCc::NVWrite
                | TpmCc::NVIncrement
                | TpmCc::NVRead
                | TpmCc::NVReadPublic
                | TpmCc::NVWriteLock
                | TpmCc::NVReadLock
                | TpmCc::NVSetBits
                | TpmCc::NVExtend
                | TpmCc::NVDefineSpace
                | TpmCc::NVUndefineSpace
                | TpmCc::NVUndefineSpaceSpecial
                | TpmCc::NVChangeAuth
                | TpmCc::PCRRead
                | TpmCc::PCRExtend
                | TpmCc::PCRAllocate
                | TpmCc::PCRReset
        )
    } else if handle_index == 1 {
        matches!(
            cc,
            TpmCc::GetTime
                | TpmCc::Certify
                | TpmCc::GetSessionAuditDigest
                | TpmCc::NVCertify
                | TpmCc::ActivateCredential
        )
    } else {
        false
    }
}

fn remaining_strict_auth_handles(
    command_code: TpmCc,
    handles: &[Handle],
    start_index: usize,
) -> usize {
    let mut count = 0;
    for (i, &h) in handles.iter().enumerate().skip(start_index) {
        if handle_requires_auth(command_code, i) && h != Handle::RH_NULL {
            count += 1;
        }
    }
    count
}

pub fn map_sessions_to_handles(
    command_code: TpmCc,
    handles: &[Handle],
    auth_sessions_len: usize,
) -> (Vec<usize>, usize) {
    let mut session_to_handle_idx = Vec::new();
    let mut session_idx = 0;
    for (h_idx, &h) in handles.iter().enumerate() {
        if handle_requires_auth(command_code, h_idx) {
            let is_optional = h == Handle::RH_NULL;
            let should_map = if is_optional {
                let remaining_strict =
                    remaining_strict_auth_handles(command_code, handles, h_idx + 1);
                let available = auth_sessions_len - session_idx;
                if available > remaining_strict {
                    session_idx += 1;
                    true
                } else {
                    false
                }
            } else {
                session_idx += 1;
                true
            };
            if should_map {
                session_to_handle_idx.push(h_idx);
            }
        }
    }
    let len = session_to_handle_idx.len();
    (session_to_handle_idx, len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_session(session_key: &[u8]) -> ActiveSession {
        ActiveSession {
            session_handle: Handle(0x0300_0000),
            nonce_caller: Tpm2bNonce::default(),
            nonce_tpm: Tpm2bNonce::default(),
            session_key: session_key.to_vec(),
            auth_hash: TpmiAlgHash::Sha256,
            symmetric: None,
            attributes: TpmaSession::CONTINUE_SESSION,
            bind_auth: Vec::new(),
            bind_entity: Handle::RH_NULL,
            session_type: TpmSe::HMAC,
            policy_auth_value_needed: false,
            policy_password_needed: false,
        }
    }

    #[test]
    fn include_auth_hmac_session_unbound_includes_auth() {
        assert!(include_auth_for(false, false, false, false));
        // Policy flags are irrelevant for HMAC sessions.
        assert!(include_auth_for(false, false, true, true));
    }

    #[test]
    fn include_auth_hmac_session_bound_excludes_auth() {
        assert!(!include_auth_for(false, true, false, false));
        assert!(!include_auth_for(false, true, true, true));
    }

    #[test]
    fn include_auth_policy_session_follows_policy_flags() {
        // Binding never matters for policy sessions.
        for is_bound in [false, true] {
            assert!(!include_auth_for(true, is_bound, false, false));
            assert!(include_auth_for(true, is_bound, true, false));
            assert!(include_auth_for(true, is_bound, false, true));
            assert!(include_auth_for(true, is_bound, true, true));
        }
    }

    #[test]
    fn session_hmac_key_appends_stripped_auth_only_when_included() {
        let session = dummy_session(&[1, 2, 3]);
        assert_eq!(
            session_hmac_key(&session, b"ab\0\0", true),
            b"\x01\x02\x03ab"
        );
        assert_eq!(session_hmac_key(&session, b"ab", false), [1, 2, 3]);
        assert_eq!(session_hmac_key(&session, b"", true), [1, 2, 3]);
    }
}
