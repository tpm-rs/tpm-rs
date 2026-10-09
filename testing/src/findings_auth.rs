//! End-to-end regression tests for the `auth` findings in command-handlers.toml.
//!
//! Owned by the `fix-auth` worker; add submodules under `findings_auth/` if this grows.
//!
//! Every test is named after the finding it covers and drives the simulator strictly through its
//! command interface. Commands are built byte by byte so that the authorization area (session
//! handles, attributes and HMAC/password values) is fully under the test's control. Expected
//! response codes follow the C reference (`SessionProcess.c`: `ParseSessionBuffer()`,
//! `CheckAuthSession()`, `CheckPWAuthSession()`, `CheckSessionHMAC()`, `IncrementLockout()`,
//! `CheckLockedOut()`).

#![allow(unused_imports)]

use crate::test_utils::*;
use tpm2::commands::{CreatePrimary, CreatePrimaryHandles};
use tpm2::crypto::Rng;
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bSensitiveData, TpmCc, TpmPt, TpmSe,
    TpmaObject, TpmiAlgHash, TpmiAlgSymMode, TpmsSensitiveCreate, TpmtHa, TpmtKeyedHashScheme,
    TpmtPublic, TpmtSymDefObject,
};
use tpm2_simulator::{Simulator, SimulatorPlatformSignal, create_simulator};

// ---------------------------------------------------------------------------
// Response codes
// ---------------------------------------------------------------------------

const RC_SUCCESS: u32 = 0;
/// `TPM_RC_AUTH_FAIL + RC_S1`.
const RC_AUTH_FAIL_S1: u32 = 0x98E;
/// `TPM_RC_BAD_AUTH + RC_S1`.
const RC_BAD_AUTH_S1: u32 = 0x9A2;
/// `TPM_RC_AUTH_TYPE` (format zero, no position).
const RC_AUTH_TYPE: u32 = 0x124;
/// `TPM_RC_AUTH_MISSING` (format zero, no position).
const RC_AUTH_MISSING: u32 = 0x125;
/// `TPM_RC_AUTH_UNAVAILABLE` (format zero, no position).
const RC_AUTH_UNAVAILABLE: u32 = 0x12F;
/// `TPM_RC_LOCKOUT` (warning).
const RC_LOCKOUT: u32 = 0x921;
/// `TPM_RC_NV_UNAVAILABLE` (warning).
const RC_NV_UNAVAILABLE: u32 = 0x923;

/// `TPM_RS_PW`.
const RS_PW: u32 = 0x4000_0009;
/// `continueSession`.
const ATTR_CONTINUE: u8 = 0x01;
/// `encrypt`.
const ATTR_ENCRYPT: u8 = 0x40;
/// `audit`.
const ATTR_AUDIT: u8 = 0x80;

// TPMA_NV bits.
const NV_OWNERWRITE: u32 = 0x0000_0002;
const NV_AUTHWRITE: u32 = 0x0000_0004;
const NV_OWNERREAD: u32 = 0x0002_0000;
const NV_AUTHREAD: u32 = 0x0004_0000;
const NV_NO_DA: u32 = 0x0200_0000;
const NV_TYPE_PIN_FAIL: u32 = 0x8 << 4;
const NV_TYPE_PIN_PASS: u32 = 0x9 << 4;

// ---------------------------------------------------------------------------
// Raw command helpers
// ---------------------------------------------------------------------------

/// One entry of a command authorization area (`TPMS_AUTH_COMMAND`).
struct AuthEntry {
    handle: u32,
    nonce: Vec<u8>,
    attrs: u8,
    hmac: Vec<u8>,
}

impl AuthEntry {
    /// A password (`TPM_RS_PW`) session carrying `password`.
    fn pw(password: &[u8]) -> Self {
        Self {
            handle: RS_PW,
            nonce: Vec::new(),
            attrs: ATTR_CONTINUE,
            hmac: password.to_vec(),
        }
    }
}

fn put_tpm2b(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Sends a command and returns its response code and full response bytes.
///
/// Without `auths` the command is sent with `TPM_ST_NO_SESSIONS`.
fn send(
    sim: &mut Simulator<'_>,
    cc: TpmCc,
    handles: &[u32],
    auths: &[AuthEntry],
    params: &[u8],
) -> (u32, Vec<u8>) {
    let mut cmd = Vec::new();
    let tag: u16 = if auths.is_empty() { 0x8001 } else { 0x8002 };
    cmd.extend_from_slice(&tag.to_be_bytes());
    cmd.extend_from_slice(&0u32.to_be_bytes());
    cmd.extend_from_slice(&u32::from(cc).to_be_bytes());
    for h in handles {
        cmd.extend_from_slice(&h.to_be_bytes());
    }
    if !auths.is_empty() {
        let mut area = Vec::new();
        for a in auths {
            area.extend_from_slice(&a.handle.to_be_bytes());
            put_tpm2b(&mut area, &a.nonce);
            area.push(a.attrs);
            put_tpm2b(&mut area, &a.hmac);
        }
        cmd.extend_from_slice(&(area.len() as u32).to_be_bytes());
        cmd.extend_from_slice(&area);
    }
    cmd.extend_from_slice(params);
    let size = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&size.to_be_bytes());

    let mut rsp = vec![0u8; 8192];
    let out = sim.transact(&cmd, &mut rsp).expect("transact").to_vec();
    let rc = u32::from_be_bytes([out[6], out[7], out[8], out[9]]);
    (rc, out)
}

/// Sends a command and returns only its response code.
fn rc(
    sim: &mut Simulator<'_>,
    cc: TpmCc,
    handles: &[u32],
    auths: &[AuthEntry],
    params: &[u8],
) -> u32 {
    send(sim, cc, handles, auths, params).0
}

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut state = tpm2::crypto::HashCtx::new(CLIENT_CRYPTO, TpmiAlgHash::Sha256).unwrap();
    for part in parts {
        state.update(part).unwrap();
    }
    let mut out = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    state.finalize(&mut out).unwrap().digest().to_vec()
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut state = tpm2::crypto::HmacCtx::new(CLIENT_CRYPTO, TpmiAlgHash::Sha256, key).unwrap();
    for part in parts {
        state.update(part).unwrap();
    }
    let mut out = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    state.finalize(&mut out).unwrap().digest().to_vec()
}

/// Builds an HMAC-session authorization (SHA-256 sessions only) for a command with the given
/// handle `names` and (unencrypted) `params`. The HMAC key is `sessionKey || entity_auth`
/// (`entity_auth` with trailing zeros removed); pass an empty `entity_auth` when the authValue
/// is not part of the key (bound sessions, policy sessions without PolicyAuthValue, sessions that
/// authorize no handle).
fn hmac_entry(
    session: &ActiveSession,
    cc: TpmCc,
    names: &[Vec<u8>],
    params: &[u8],
    entity_auth: &[u8],
    attrs: u8,
) -> AuthEntry {
    let cc_bytes = u32::from(cc).to_be_bytes();
    let mut cp_parts: Vec<&[u8]> = vec![&cc_bytes];
    for n in names {
        cp_parts.push(n);
    }
    cp_parts.push(params);
    let cp_hash = sha256(&cp_parts);

    let mut nonce = [0u8; 16];
    CLIENT_CRYPTO.get_random(&mut nonce).unwrap();
    let key = [
        session.session_key.as_slice(),
        strip_trailing_zeros(entity_auth),
    ]
    .concat();
    let hmac = hmac_sha256(
        &key,
        &[&cp_hash, &nonce, session.nonce_tpm.get_buffer(), &[attrs]],
    );
    AuthEntry {
        handle: session.session_handle.0,
        nonce: nonce.to_vec(),
        attrs,
        hmac,
    }
}

/// An authorization entry for `session` with an explicit `hmac` value.
fn raw_entry(session: &ActiveSession, attrs: u8, hmac: &[u8]) -> AuthEntry {
    let mut nonce = [0u8; 16];
    CLIENT_CRYPTO.get_random(&mut nonce).unwrap();
    AuthEntry {
        handle: session.session_handle.0,
        nonce: nonce.to_vec(),
        attrs,
        hmac: hmac.to_vec(),
    }
}

/// Starts an unbound, unsalted SHA-256 session (empty session key).
fn start(sim: &mut Simulator<'_>, session_type: TpmSe) -> ActiveSession {
    start_auth_session(
        sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        session_type,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("StartAuthSession")
}

/// The Name of a permanent handle (the handle value).
fn handle_name(h: u32) -> Vec<u8> {
    h.to_be_bytes().to_vec()
}

/// The Name of a loaded or persistent object.
fn object_name(sim: &mut Simulator<'_>, h: u32) -> Vec<u8> {
    read_public_name(sim, Handle(h)).get_buffer().to_vec()
}

/// The Name of an NV Index (from `TPM2_NV_ReadPublic`).
fn nv_name(sim: &mut Simulator<'_>, index: u32) -> Vec<u8> {
    let (code, out) = send(sim, TpmCc::NVReadPublic, &[index], &[], &[]);
    assert_eq!(code, RC_SUCCESS, "NV_ReadPublic");
    let pub_len = u16::from_be_bytes([out[10], out[11]]) as usize;
    let name_off = 12 + pub_len;
    let name_len = u16::from_be_bytes([out[name_off], out[name_off + 1]]) as usize;
    out[name_off + 2..name_off + 2 + name_len].to_vec()
}

fn tpm2b_params(data: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    put_tpm2b(&mut p, data);
    p
}

// ---------------------------------------------------------------------------
// Entity helpers
// ---------------------------------------------------------------------------

/// Template for a keyedhash sealed-data object.
fn sealed_template(attrs: TpmaObject, auth_policy: &[u8]) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs | TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT,
        auth_policy: Tpm2bDigest::from_bytes(leak_bytes(auth_policy)).unwrap(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
    }
}

/// Creates a primary object in the owner hierarchy with authValue `auth` and sensitive `data`.
fn create_primary_obj(
    sim: &mut Simulator<'_>,
    public: TpmtPublic<'static>,
    auth: &[u8],
    data: &[u8],
) -> u32 {
    let cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(leak_bytes(auth)).unwrap(),
            data: Tpm2bSensitiveData::from_bytes(leak_bytes(data)).unwrap(),
        }),
        in_public: tpm2::Tpm2b(public),
        ..Default::default()
    };
    let handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (_, rsp_handles) =
        execute_with_password_sessions(sim, &cmd, handles, 1, &[]).expect("CreatePrimary");
    rsp_handles.object_handle.0
}

/// Creates a sealed-data primary object.
fn create_sealed(sim: &mut Simulator<'_>, attrs: TpmaObject, auth: &[u8], policy: &[u8]) -> u32 {
    create_primary_obj(sim, sealed_template(attrs, policy), auth, b"sealed secret")
}

/// Loads `public` with `TPM2_LoadExternal` without a private area (a public-only object).
///
/// An empty keyedhash `unique` is replaced by a digest-sized value, as required for any loaded
/// keyedhash object (C `CryptValidateKeys()`).
fn load_public_only(sim: &mut Simulator<'_>, public: &TpmtPublic<'static>) -> u32 {
    let mut public = *public;
    if let PublicParmsAndId::KeyedHash(scheme, unique) = public.parms_and_id
        && unique.get_size() == 0
    {
        public.parms_and_id = PublicParmsAndId::KeyedHash(
            scheme,
            Tpm2bDigest::from_bytes(leak_bytes(&[5; 32])).unwrap(),
        );
    }
    let public = &public;
    let mut params = Vec::new();
    put_tpm2b(&mut params, &[]);
    put_tpm2b(&mut params, &marshal_to_vec(public));
    params.extend_from_slice(&Handle::RH_NULL.0.to_be_bytes());
    let (code, out) = send(sim, TpmCc::LoadExternal, &[], &[], &params);
    assert_eq!(code, RC_SUCCESS, "LoadExternal");
    u32::from_be_bytes([out[10], out[11], out[12], out[13]])
}

/// Sets the owner authValue (from an empty one).
fn set_owner_auth(sim: &mut Simulator<'_>, auth: &[u8]) {
    let code = rc(
        sim,
        TpmCc::HierarchyChangeAuth,
        &[Handle::RH_OWNER.0],
        &[AuthEntry::pw(&[])],
        &tpm2b_params(auth),
    );
    assert_eq!(code, RC_SUCCESS, "HierarchyChangeAuth");
}

/// Sets the DA parameters with lockoutAuth (empty).
fn set_da_parameters(sim: &mut Simulator<'_>, max_tries: u32, recovery: u32, lockout: u32) {
    let mut params = Vec::new();
    params.extend_from_slice(&max_tries.to_be_bytes());
    params.extend_from_slice(&recovery.to_be_bytes());
    params.extend_from_slice(&lockout.to_be_bytes());
    let code = rc(
        sim,
        TpmCc::DictionaryAttackParameters,
        &[Handle::RH_LOCKOUT.0],
        &[AuthEntry::pw(&[])],
        &params,
    );
    assert_eq!(code, RC_SUCCESS, "DictionaryAttackParameters");
}

/// Defines an owner NV Index with the given attributes, authValue and authPolicy.
fn define_nv(
    sim: &mut Simulator<'_>,
    index: u32,
    attributes: u32,
    auth: &[u8],
    policy: &[u8],
    data_size: u16,
) {
    let mut public = Vec::new();
    public.extend_from_slice(&index.to_be_bytes());
    public.extend_from_slice(&0x000Bu16.to_be_bytes());
    public.extend_from_slice(&attributes.to_be_bytes());
    put_tpm2b(&mut public, policy);
    public.extend_from_slice(&data_size.to_be_bytes());
    let mut params = Vec::new();
    put_tpm2b(&mut params, auth);
    put_tpm2b(&mut params, &public);
    let code = rc(
        sim,
        TpmCc::NVDefineSpace,
        &[Handle::RH_OWNER.0],
        &[AuthEntry::pw(&[])],
        &params,
    );
    assert_eq!(code, RC_SUCCESS, "NV_DefineSpace");
}

fn nv_write_params(data: &[u8], offset: u16) -> Vec<u8> {
    let mut params = tpm2b_params(data);
    params.extend_from_slice(&offset.to_be_bytes());
    params
}

fn nv_read_params(size: u16, offset: u16) -> Vec<u8> {
    let mut params = Vec::new();
    params.extend_from_slice(&size.to_be_bytes());
    params.extend_from_slice(&offset.to_be_bytes());
    params
}

/// Writes `pinCount || pinLimit` to a PIN index with ownerAuth.
fn write_pin(sim: &mut Simulator<'_>, index: u32, count: u32, limit: u32) {
    let data = [count.to_be_bytes(), limit.to_be_bytes()].concat();
    let code = rc(
        sim,
        TpmCc::NVWrite,
        &[Handle::RH_OWNER.0, index],
        &[AuthEntry::pw(&[])],
        &nv_write_params(&data, 0),
    );
    assert_eq!(code, RC_SUCCESS, "NV_Write(pin)");
}

/// Reads `pinCount` of a PIN index with ownerAuth.
fn read_pin_count(sim: &mut Simulator<'_>, index: u32) -> u32 {
    let (code, out) = send(
        sim,
        TpmCc::NVRead,
        &[Handle::RH_OWNER.0, index],
        &[AuthEntry::pw(&[])],
        &nv_read_params(8, 0),
    );
    assert_eq!(code, RC_SUCCESS, "NV_Read(owner)");
    // header(10) || parameterSize(4) || TPM2B size(2) || data
    u32::from_be_bytes([out[16], out[17], out[18], out[19]])
}

/// `TPM2_NV_Read` of a PIN index authorized by the index itself with `password`.
fn read_pin_with_password(sim: &mut Simulator<'_>, index: u32, password: &[u8]) -> u32 {
    rc(
        sim,
        TpmCc::NVRead,
        &[index, index],
        &[AuthEntry::pw(password)],
        &nv_read_params(8, 0),
    )
}

fn lockout_counter(sim: &mut Simulator<'_>) -> u32 {
    get_tpm_property(sim, TpmPt::LOCKOUT_COUNTER)
}

/// `TPM2_Unseal(item)` authorized by `auth`.
fn unseal(sim: &mut Simulator<'_>, item: u32, auth: AuthEntry) -> u32 {
    rc(sim, TpmCc::Unseal, &[item], &[auth], &[])
}

/// The policy digest of a fresh SHA-256 policy session (32 zero bytes).
const EMPTY_POLICY: [u8; 32] = [0u8; 32];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Password authorization requires the complete authValue: a prefix of it must fail
/// (C `CheckPWAuthSession()` compares with `MemoryEqual2B`, i.e. equal length and contents).
#[test]
fn password_auth_prefix_matching_vulnerability() {
    let mut sim = create_simulator!();
    let item = create_sealed(&mut sim, TpmaObject::USER_WITH_AUTH, b"secret", &[]);
    set_owner_auth(&mut sim, b"secret");

    // ownerAuth is DA-exempt: TPM_RC_BAD_AUTH + RC_S1.
    for prefix in [&b"s"[..], b"secre"] {
        let code = rc(
            &mut sim,
            TpmCc::HierarchyChangeAuth,
            &[Handle::RH_OWNER.0],
            &[AuthEntry::pw(prefix)],
            &tpm2b_params(b"other"),
        );
        assert_eq!(code, RC_BAD_AUTH_S1, "prefix {prefix:?} must be rejected");
    }

    // A DA-protected object: TPM_RC_AUTH_FAIL + RC_S1.
    assert_eq!(
        unseal(&mut sim, item, AuthEntry::pw(b"sec")),
        RC_AUTH_FAIL_S1
    );

    // Trailing zeros are still ignored, and the full value works.
    assert_eq!(
        unseal(&mut sim, item, AuthEntry::pw(b"secret\0\0")),
        RC_SUCCESS
    );
    let code = rc(
        &mut sim,
        TpmCc::HierarchyChangeAuth,
        &[Handle::RH_OWNER.0],
        &[AuthEntry::pw(b"secret")],
        &tpm2b_params(b""),
    );
    assert_eq!(code, RC_SUCCESS);
}

/// PIN Fail / PIN Pass indices: the authValue is only available once written and while
/// `pinCount < pinLimit`, and `pinCount` is maintained on every use (C `IsAuthValueAvailable()`
/// and the PIN processing in `CheckAuthSession()`).
#[test]
fn nv_pinpass_pinfail_auth_and_counter_omissions() {
    let mut sim = create_simulator!();

    // --- PIN Fail ---
    let pin_fail = 0x0150_0010;
    define_nv(
        &mut sim,
        pin_fail,
        NV_TYPE_PIN_FAIL | NV_AUTHREAD | NV_OWNERWRITE | NV_OWNERREAD | NV_NO_DA,
        b"pin",
        &[],
        8,
    );
    // Not written yet: authValue unavailable.
    assert_eq!(
        read_pin_with_password(&mut sim, pin_fail, b"pin"),
        RC_AUTH_UNAVAILABLE
    );

    write_pin(&mut sim, pin_fail, 0, 2);
    assert_eq!(
        read_pin_with_password(&mut sim, pin_fail, b"pin"),
        RC_SUCCESS
    );
    assert_eq!(read_pin_count(&mut sim, pin_fail), 0);

    // A failure increments pinCount (NO_DA, so TPM_RC_BAD_AUTH), a success clears it.
    assert_eq!(
        read_pin_with_password(&mut sim, pin_fail, b"bad"),
        RC_BAD_AUTH_S1
    );
    assert_eq!(read_pin_count(&mut sim, pin_fail), 1);
    assert_eq!(
        read_pin_with_password(&mut sim, pin_fail, b"pin"),
        RC_SUCCESS
    );
    assert_eq!(read_pin_count(&mut sim, pin_fail), 0);

    // Reaching pinLimit makes the authValue unavailable, even with the right PIN.
    assert_eq!(
        read_pin_with_password(&mut sim, pin_fail, b"bad"),
        RC_BAD_AUTH_S1
    );
    assert_eq!(
        read_pin_with_password(&mut sim, pin_fail, b"bad"),
        RC_BAD_AUTH_S1
    );
    assert_eq!(read_pin_count(&mut sim, pin_fail), 2);
    assert_eq!(
        read_pin_with_password(&mut sim, pin_fail, b"pin"),
        RC_AUTH_UNAVAILABLE
    );
    assert_eq!(read_pin_count(&mut sim, pin_fail), 2);

    // --- PIN Pass ---
    let pin_pass = 0x0150_0011;
    define_nv(
        &mut sim,
        pin_pass,
        NV_TYPE_PIN_PASS | NV_AUTHREAD | NV_OWNERWRITE | NV_OWNERREAD | NV_NO_DA,
        b"pin",
        &[],
        8,
    );
    write_pin(&mut sim, pin_pass, 0, 1);
    // A failure does not change pinCount of a PIN Pass index.
    assert_eq!(
        read_pin_with_password(&mut sim, pin_pass, b"bad"),
        RC_BAD_AUTH_S1
    );
    assert_eq!(read_pin_count(&mut sim, pin_pass), 0);
    // Each success consumes one use.
    assert_eq!(
        read_pin_with_password(&mut sim, pin_pass, b"pin"),
        RC_SUCCESS
    );
    assert_eq!(read_pin_count(&mut sim, pin_pass), 1);
    assert_eq!(
        read_pin_with_password(&mut sim, pin_pass, b"pin"),
        RC_AUTH_UNAVAILABLE
    );
    assert_eq!(read_pin_count(&mut sim, pin_pass), 1);
}

/// A handle that requires authorization always needs a session, even when its authValue is
/// empty (C `CheckAuthNoSession()` and the handle loop of `ParseSessionBuffer()`), and
/// `TPM2_PCR_Allocate` requires authorization of `TPM_RH_PLATFORM`.
#[test]
fn mandatory_auth_sessions_bypassed_when_authvalue_empty() {
    let mut sim = create_simulator!();

    // No session area at all, empty ownerAuth.
    let code = rc(
        &mut sim,
        TpmCc::HierarchyChangeAuth,
        &[Handle::RH_OWNER.0],
        &[],
        &tpm2b_params(b""),
    );
    assert_eq!(code, RC_AUTH_MISSING);

    // TPM2_PCR_Allocate: platform authorization is required and a password session is
    // associated with the platform handle.
    let allocation = [
        0u8, 0, 0, 1, // count
        0x00, 0x0B, // SHA-256
        3, 0xFF, 0xFF, 0xFF, // all 24 PCRs
    ];
    let code = rc(
        &mut sim,
        TpmCc::PCRAllocate,
        &[Handle::RH_PLATFORM.0],
        &[],
        &allocation,
    );
    assert_eq!(code, RC_AUTH_MISSING);
    let code = rc(
        &mut sim,
        TpmCc::PCRAllocate,
        &[Handle::RH_PLATFORM.0],
        &[AuthEntry::pw(&[])],
        &allocation,
    );
    assert_eq!(code, RC_SUCCESS);

    // Fewer sessions than authorized handles: TPM2_Certify authorizes both objectHandle and
    // signHandle, even if signHandle is TPM_RH_NULL.
    let item = create_sealed(
        &mut sim,
        TpmaObject::USER_WITH_AUTH | TpmaObject::NO_DA,
        b"",
        &[],
    );
    let mut certify_params = tpm2b_params(&[]);
    certify_params.extend_from_slice(&0x0010u16.to_be_bytes()); // TPM_ALG_NULL scheme
    let code = rc(
        &mut sim,
        TpmCc::Certify,
        &[item, Handle::RH_NULL.0],
        &[AuthEntry::pw(&[])],
        &certify_params,
    );
    assert_eq!(code, RC_AUTH_MISSING);

    // The same with two real (loaded, non-NULL) entities: the single session authorizes only
    // objectHandle, so signHandle has no authorization (C `ParseSessionBuffer()` handle loop).
    let signer = create_sealed(
        &mut sim,
        TpmaObject::USER_WITH_AUTH | TpmaObject::NO_DA,
        b"signer",
        &[],
    );
    let code = rc(
        &mut sim,
        TpmCc::Certify,
        &[item, signer],
        &[AuthEntry::pw(&[])],
        &certify_params,
    );
    assert_eq!(code, RC_AUTH_MISSING);
    let code = rc(
        &mut sim,
        TpmCc::ActivateCredential,
        &[item, signer],
        &[AuthEntry::pw(&[])],
        &[0, 0, 0, 0],
    );
    assert_eq!(code, RC_AUTH_MISSING);
}

/// `TPM2_PCR_Allocate` is a `HANDLE_1_USER` command (the duplicate finding owned by fix-capctx).
#[test]
fn tpm2_pcr_allocate_missing_from_handle_requires_auth() {
    let mut sim = create_simulator!();
    let allocation = [0u8, 0, 0, 1, 0x00, 0x0B, 3, 0xFF, 0xFF, 0xFF];

    // A password session is associated with (and checked against) platformAuth.
    let code = rc(
        &mut sim,
        TpmCc::HierarchyChangeAuth,
        &[Handle::RH_PLATFORM.0],
        &[AuthEntry::pw(&[])],
        &tpm2b_params(b"platform"),
    );
    assert_eq!(code, RC_SUCCESS);
    let code = rc(
        &mut sim,
        TpmCc::PCRAllocate,
        &[Handle::RH_PLATFORM.0],
        &[AuthEntry::pw(b"wrong")],
        &allocation,
    );
    assert_eq!(code, RC_BAD_AUTH_S1);

    // An HMAC session must prove knowledge of platformAuth too.
    let session = start(&mut sim, TpmSe::HMAC);
    let auth = raw_entry(&session, ATTR_CONTINUE, &[0x55; 32]);
    let code = rc(
        &mut sim,
        TpmCc::PCRAllocate,
        &[Handle::RH_PLATFORM.0],
        &[auth],
        &allocation,
    );
    assert_eq!(code, RC_BAD_AUTH_S1);

    let code = rc(
        &mut sim,
        TpmCc::PCRAllocate,
        &[Handle::RH_PLATFORM.0],
        &[AuthEntry::pw(b"platform")],
        &allocation,
    );
    assert_eq!(code, RC_SUCCESS);
}

/// DA handling of session authorizations (C `CheckAuthSession()`, `IncrementLockout()`):
/// lockout only blocks sessions that use the authValue, failures that do not involve a DA
/// protected authValue are `TPM_RC_BAD_AUTH` without side effects, and the `audit` attribute does
/// not influence the response code.
#[test]
fn verify_session_hmacs_da_lockout_increment_and_error_code_bugs() {
    // 1. A policy session that does not use the authValue still works in lockout.
    {
        let mut sim = create_simulator!();
        set_da_parameters(&mut sim, 1, 1000, 1000);
        let item = create_sealed(&mut sim, TpmaObject::USER_WITH_AUTH, b"a", &EMPTY_POLICY);
        assert_eq!(unseal(&mut sim, item, AuthEntry::pw(b"x")), RC_AUTH_FAIL_S1);
        assert_eq!(unseal(&mut sim, item, AuthEntry::pw(b"a")), RC_LOCKOUT);

        let policy = start(&mut sim, TpmSe::Policy);
        assert_eq!(
            unseal(&mut sim, item, raw_entry(&policy, 0, &[])),
            RC_SUCCESS
        );
    }

    // 2. A failing policy session that does not include the authValue does not count as a DA
    //    failure.
    {
        let mut sim = create_simulator!();
        let item = create_sealed(&mut sim, TpmaObject::USER_WITH_AUTH, b"a", &EMPTY_POLICY);
        let before = lockout_counter(&mut sim);
        let policy = start(&mut sim, TpmSe::Policy);
        let code = unseal(
            &mut sim,
            item,
            raw_entry(&policy, ATTR_CONTINUE, &[1, 2, 3]),
        );
        assert_eq!(code, RC_BAD_AUTH_S1);
        assert_eq!(lockout_counter(&mut sim), before);
    }

    // 3. HMAC failure on a DA-exempt entity: TPM_RC_BAD_AUTH (no audit attribute involved).
    {
        let mut sim = create_simulator!();
        let session = start(&mut sim, TpmSe::HMAC);
        let auth = raw_entry(&session, ATTR_CONTINUE, &[0x55; 32]);
        let code = rc(
            &mut sim,
            TpmCc::HierarchyChangeAuth,
            &[Handle::RH_OWNER.0],
            &[auth],
            &tpm2b_params(b""),
        );
        assert_eq!(code, RC_BAD_AUTH_S1);
    }

    // 4. HMAC failure on a DA-protected entity with `audit` set: TPM_RC_AUTH_FAIL, and the
    //    failure is counted.
    {
        let mut sim = create_simulator!();
        let item = create_sealed(&mut sim, TpmaObject::USER_WITH_AUTH, b"a", &[]);
        let before = lockout_counter(&mut sim);
        let session = start(&mut sim, TpmSe::HMAC);
        let auth = raw_entry(&session, ATTR_CONTINUE | ATTR_AUDIT, &[0x55; 32]);
        assert_eq!(unseal(&mut sim, item, auth), RC_AUTH_FAIL_S1);
        assert_eq!(lockout_counter(&mut sim), before + 1);
    }
}

/// `maxTries == 0` puts the TPM in lockout (C `CheckLockedOut()`: `failedTries >= maxTries`).
#[test]
fn tpm2_dictionaryattackparameters_maxtries_zero_disables_lockout_and_omits_nv_sync() {
    let mut sim = create_simulator!();
    let item = create_sealed(&mut sim, TpmaObject::USER_WITH_AUTH, b"a", &[]);
    set_da_parameters(&mut sim, 0, 1000, 1000);
    assert_eq!(unseal(&mut sim, item, AuthEntry::pw(b"a")), RC_LOCKOUT);
}

/// A pending DA update that cannot be written to NV blocks further DA-protected
/// authorizations with `TPM_RC_NV_UNAVAILABLE` (C `CheckLockedOut()`:
/// `RETURN_IF_NV_IS_NOT_AVAILABLE` while `s_DAPendingOnNV`).
#[test]
fn validate_lockout_auth_and_da_handlers_execution_order_and_nv_pending_bugs() {
    let mut sim = create_simulator!();
    let item = create_sealed(&mut sim, TpmaObject::USER_WITH_AUTH, b"a", &[]);
    // A DA-protected authorization with NV available records SU_DA_USED_VALUE.
    assert_eq!(unseal(&mut sim, item, AuthEntry::pw(b"a")), RC_SUCCESS);

    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
    // The failure cannot be recorded in NV: it becomes pending.
    assert_eq!(unseal(&mut sim, item, AuthEntry::pw(b"x")), RC_AUTH_FAIL_S1);
    // While the update is pending and NV is off, DA-protected authorization is refused.
    assert_eq!(
        unseal(&mut sim, item, AuthEntry::pw(b"a")),
        RC_NV_UNAVAILABLE
    );

    sim.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();
    assert_eq!(unseal(&mut sim, item, AuthEntry::pw(b"a")), RC_SUCCESS);
}

/// An empty authHMAC is accepted for any session type when the HMAC key is empty (C
/// `ComputeCommandHMAC()`), and a `TPM2_PolicyPassword` session that authorizes no handle is
/// verified by its HMAC, not as a password.
#[test]
fn unassociated_session_policy_and_empty_hmac_bugs() {
    let mut sim = create_simulator!();

    // Unbound, unsalted HMAC session authorizing an entity with an empty authValue.
    let session = start(&mut sim, TpmSe::HMAC);
    let code = rc(
        &mut sim,
        TpmCc::HierarchyChangeAuth,
        &[Handle::RH_OWNER.0],
        &[raw_entry(&session, ATTR_CONTINUE, &[])],
        &tpm2b_params(b""),
    );
    assert_eq!(code, RC_SUCCESS);

    // A PolicyPassword policy session used only for response encryption.
    let policy = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    let code = rc(
        &mut sim,
        TpmCc::PolicyPassword,
        &[policy.session_handle.0],
        &[],
        &[],
    );
    assert_eq!(code, RC_SUCCESS);
    let params = 8u16.to_be_bytes();
    let auth = hmac_entry(
        &policy,
        TpmCc::GetRandom,
        &[],
        &params,
        &[],
        ATTR_CONTINUE | ATTR_ENCRYPT,
    );
    assert_eq!(
        rc(&mut sim, TpmCc::GetRandom, &[], &[auth], &params),
        RC_SUCCESS
    );
}

/// HMAC tags are compared exactly: neither trailing zero padding nor an all-zero tag with an
/// empty HMAC key is accepted (C `CheckSessionHMAC()` uses `MemoryEqual2B`).
#[test]
fn verify_session_hmacs_strips_trailing_zeros_on_hmac_and_checks_auth_before_cphash() {
    let mut sim = create_simulator!();
    let item = create_sealed(
        &mut sim,
        TpmaObject::USER_WITH_AUTH | TpmaObject::NO_DA,
        b"",
        &EMPTY_POLICY,
    );
    set_owner_auth(&mut sim, b"owner");
    let names = [handle_name(Handle::RH_OWNER.0)];
    let params = tpm2b_params(b"owner");

    // A valid HMAC padded with a zero byte.
    let session = start(&mut sim, TpmSe::HMAC);
    let mut auth = hmac_entry(
        &session,
        TpmCc::HierarchyChangeAuth,
        &names,
        &params,
        b"owner",
        ATTR_CONTINUE,
    );
    auth.hmac.push(0);
    let code = rc(
        &mut sim,
        TpmCc::HierarchyChangeAuth,
        &[Handle::RH_OWNER.0],
        &[auth],
        &params,
    );
    assert_eq!(code, RC_BAD_AUTH_S1);

    // The same HMAC without padding is accepted (the session is still usable: a failed
    // authorization does not consume the nonce).
    let auth = hmac_entry(
        &session,
        TpmCc::HierarchyChangeAuth,
        &names,
        &params,
        b"owner",
        ATTR_CONTINUE,
    );
    let code = rc(
        &mut sim,
        TpmCc::HierarchyChangeAuth,
        &[Handle::RH_OWNER.0],
        &[auth],
        &params,
    );
    assert_eq!(code, RC_SUCCESS);

    // Empty HMAC key (policy session without PolicyAuthValue): a non-empty all-zero authHMAC
    // is not an empty one.
    let policy = start(&mut sim, TpmSe::Policy);
    assert_eq!(
        unseal(&mut sim, item, raw_entry(&policy, ATTR_CONTINUE, &[0])),
        RC_BAD_AUTH_S1
    );
    assert_eq!(
        unseal(&mut sim, item, raw_entry(&policy, ATTR_CONTINUE, &[])),
        RC_SUCCESS
    );
}

/// USER role authorization of an object with `userWithAuth` clear by a password or HMAC
/// session: `TPM_RC_AUTH_UNAVAILABLE` (C `IsAuthValueAvailable()`), not `TPM_RC_AUTH_TYPE`.
#[test]
fn verify_session_hmacs_user_with_auth_clear_returns_auth_type_instead_of_auth_unavailable() {
    let mut sim = create_simulator!();
    let item = create_sealed(&mut sim, TpmaObject::NO_DA, b"a", &EMPTY_POLICY);
    assert_eq!(
        unseal(&mut sim, item, AuthEntry::pw(b"a")),
        RC_AUTH_UNAVAILABLE
    );

    let session = start(&mut sim, TpmSe::HMAC);
    let names = [object_name(&mut sim, item)];
    let auth = hmac_entry(&session, TpmCc::Unseal, &names, &[], b"a", ATTR_CONTINUE);
    assert_eq!(unseal(&mut sim, item, auth), RC_AUTH_UNAVAILABLE);

    // The policy is still usable.
    let policy = start(&mut sim, TpmSe::Policy);
    assert_eq!(
        unseal(&mut sim, item, raw_entry(&policy, 0, &[])),
        RC_SUCCESS
    );
}

/// `IsPolicySessionRequired()`: the DUP role, the ADMIN role on non-objects, and PCRs with an
/// authPolicy require a policy session (`TPM_RC_AUTH_TYPE` otherwise).
#[test]
fn auth_role_dup_admin_and_policy_commandcode_bypass() {
    let mut sim = create_simulator!();

    // TPM2_Duplicate (DUP role) with a password session.
    let item = create_sealed(
        &mut sim,
        TpmaObject::USER_WITH_AUTH | TpmaObject::NO_DA,
        b"",
        &EMPTY_POLICY,
    );
    let mut dup_params = tpm2b_params(&[]);
    dup_params.extend_from_slice(&0x0010u16.to_be_bytes());
    let code = rc(
        &mut sim,
        TpmCc::Duplicate,
        &[item, Handle::RH_NULL.0],
        &[AuthEntry::pw(&[])],
        &dup_params,
    );
    assert_eq!(code, RC_AUTH_TYPE);

    // TPM2_NV_ChangeAuth (ADMIN role on an NV Index) with an HMAC session.
    let index = 0x0150_0020;
    define_nv(
        &mut sim,
        index,
        NV_AUTHWRITE | NV_AUTHREAD | NV_NO_DA,
        b"nv",
        &EMPTY_POLICY,
        8,
    );
    let session = start(&mut sim, TpmSe::HMAC);
    let names = [nv_name(&mut sim, index)];
    let params = tpm2b_params(b"new");
    let auth = hmac_entry(
        &session,
        TpmCc::NVChangeAuth,
        &names,
        &params,
        b"nv",
        ATTR_CONTINUE,
    );
    assert_eq!(
        rc(&mut sim, TpmCc::NVChangeAuth, &[index], &[auth], &params),
        RC_AUTH_TYPE
    );

    // A PCR with an authPolicy.
    let mut set_policy = tpm2b_params(&EMPTY_POLICY);
    set_policy.extend_from_slice(&0x000Bu16.to_be_bytes());
    set_policy.extend_from_slice(&20u32.to_be_bytes());
    let code = rc(
        &mut sim,
        TpmCc::PCRSetAuthPolicy,
        &[Handle::RH_PLATFORM.0],
        &[AuthEntry::pw(&[])],
        &set_policy,
    );
    assert_eq!(code, RC_SUCCESS);
    let mut extend = Vec::new();
    extend.extend_from_slice(&1u32.to_be_bytes());
    extend.extend_from_slice(&0x000Bu16.to_be_bytes());
    extend.extend_from_slice(&[0xAB; 32]);
    let code = rc(
        &mut sim,
        TpmCc::PCRExtend,
        &[20],
        &[AuthEntry::pw(&[])],
        &extend,
    );
    assert_eq!(code, RC_AUTH_TYPE);
    // A PCR outside the policy group is unaffected.
    let code = rc(
        &mut sim,
        TpmCc::PCRExtend,
        &[16],
        &[AuthEntry::pw(&[])],
        &extend,
    );
    assert_eq!(code, RC_SUCCESS);

    // TPM2_HierarchyChangeAuth is a USER role command: a password session is fine.
    set_owner_auth(&mut sim, b"x");
}

/// NV Indices authorizing themselves: password/HMAC sessions need `TPMA_NV_AUTHREAD` (read
/// operations such as `TPM2_PolicySecret`) or `TPMA_NV_AUTHWRITE`, policy sessions need
/// `TPMA_NV_POLICYREAD` / `TPMA_NV_POLICYWRITE` (C `IsAuthValueAvailable()` /
/// `IsAuthPolicyAvailable()`).
#[test]
fn nv_index_isauthvalueavailable_isauthpolicyavailable_bypass() {
    let mut sim = create_simulator!();
    let index = 0x0150_0030;
    // Write-only by authValue; authPolicy set but no POLICYREAD/POLICYWRITE.
    define_nv(
        &mut sim,
        index,
        NV_AUTHWRITE | NV_OWNERREAD | NV_NO_DA,
        b"nv",
        &EMPTY_POLICY,
        8,
    );
    let secret_params = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    // Password session on TPM2_PolicySecret (a read operation): AUTHREAD is clear.
    let target = start(&mut sim, TpmSe::Policy);
    let code = rc(
        &mut sim,
        TpmCc::PolicySecret,
        &[index, target.session_handle.0],
        &[AuthEntry::pw(b"nv")],
        &secret_params,
    );
    assert_eq!(code, RC_AUTH_UNAVAILABLE);

    // Policy session on TPM2_PolicySecret: POLICYREAD is clear.
    let policy = start(&mut sim, TpmSe::Policy);
    let code = rc(
        &mut sim,
        TpmCc::PolicySecret,
        &[index, target.session_handle.0],
        &[raw_entry(&policy, ATTR_CONTINUE, &[])],
        &secret_params,
    );
    assert_eq!(code, RC_AUTH_UNAVAILABLE);

    // Writing with the authValue is allowed.
    let code = rc(
        &mut sim,
        TpmCc::NVWrite,
        &[index, index],
        &[AuthEntry::pw(b"nv")],
        &nv_write_params(&[1; 8], 0),
    );
    assert_eq!(code, RC_SUCCESS);
}

/// Public-only objects (loaded without a private area) cannot be authorized at all: neither
/// their authValue nor their authPolicy is available (C `IsAuthValueAvailable()` /
/// `IsAuthPolicyAvailable()` require `publicOnly == CLEAR`).
#[test]
fn public_only_objects_bypass_isauthvalueavailable_isauthpolicyavailable_checks() {
    let mut sim = create_simulator!();
    let public = sealed_template(
        TpmaObject::USER_WITH_AUTH | TpmaObject::NO_DA,
        &EMPTY_POLICY,
    );
    let item = load_public_only(&mut sim, &public);
    assert_eq!(
        unseal(&mut sim, item, AuthEntry::pw(&[])),
        RC_AUTH_UNAVAILABLE
    );
    let policy = start(&mut sim, TpmSe::Policy);
    assert_eq!(
        unseal(&mut sim, item, raw_entry(&policy, 0, &[])),
        RC_AUTH_UNAVAILABLE
    );
}

/// `TPM2_Unseal` of a public-only sealed-data object.
#[test]
fn unseal_public_only_keyedhash_and_oversized_private_failure_mode() {
    let mut sim = create_simulator!();
    let public = sealed_template(TpmaObject::USER_WITH_AUTH | TpmaObject::NO_DA, &[]);
    let item = load_public_only(&mut sim, &public);
    assert_eq!(
        unseal(&mut sim, item, AuthEntry::pw(&[])),
        RC_AUTH_UNAVAILABLE
    );
}

/// `TPM2_Sign` with a public-only HMAC key.
#[test]
fn sign_public_only_keyedhash_zero_byte_key_and_asymmetric_error_code_bugs() {
    let mut sim = create_simulator!();
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            Tpm2bDigest::from_bytes(leak_bytes(&[7; 32])).unwrap(),
        ),
    };
    let key = load_public_only(&mut sim, &public);
    let mut params = tpm2b_params(&[0x11; 32]);
    params.extend_from_slice(&0x0010u16.to_be_bytes()); // inScheme: TPM_ALG_NULL
    params.extend_from_slice(&0x8024u16.to_be_bytes()); // TPM_ST_HASHCHECK
    params.extend_from_slice(&Handle::RH_NULL.0.to_be_bytes());
    put_tpm2b(&mut params, &[]);
    let code = rc(
        &mut sim,
        TpmCc::Sign,
        &[key],
        &[AuthEntry::pw(&[])],
        &params,
    );
    assert_eq!(code, RC_AUTH_UNAVAILABLE);
}

/// Symmetric public-only key used by `TPM2_EncryptDecrypt` / `TPM2_EncryptDecrypt2`.
fn public_only_sym_key(sim: &mut Simulator<'_>) -> u32 {
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::DECRYPT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)),
            Tpm2bDigest::from_bytes(leak_bytes(&[9; 32])).unwrap(),
        ),
    };
    load_public_only(sim, &public)
}

/// `TPM2_EncryptDecrypt2` with a public-only symmetric key.
#[test]
fn encrypt_decrypt_public_only_key_panic_and_error_code_bugs() {
    let mut sim = create_simulator!();
    let key = public_only_sym_key(&mut sim);
    let mut params = tpm2b_params(&[0x22; 16]); // inData
    params.push(0); // decrypt = NO
    params.extend_from_slice(&0x0043u16.to_be_bytes()); // CFB
    put_tpm2b(&mut params, &[0; 16]); // ivIn
    let code = rc(
        &mut sim,
        TpmCc::EncryptDecrypt2,
        &[key],
        &[AuthEntry::pw(&[])],
        &params,
    );
    assert_eq!(code, RC_AUTH_UNAVAILABLE);
}

/// `TPM2_EncryptDecrypt` with a public-only symmetric key.
#[test]
fn tpm2_encryptdecrypt_and_encryptdecrypt2_public_only_failure_mode_and_unmarshal_error_codes() {
    let mut sim = create_simulator!();
    let key = public_only_sym_key(&mut sim);
    let mut params = Vec::new();
    params.push(0); // decrypt = NO
    params.extend_from_slice(&0x0043u16.to_be_bytes()); // CFB
    put_tpm2b(&mut params, &[0; 16]); // ivIn
    put_tpm2b(&mut params, &[0x22; 16]); // inData
    let code = rc(
        &mut sim,
        TpmCc::EncryptDecrypt,
        &[key],
        &[AuthEntry::pw(&[])],
        &params,
    );
    assert_eq!(code, RC_AUTH_UNAVAILABLE);
}

/// A bound HMAC session recognizes its bind entity by its bind value, whatever handle the
/// entity is referenced by, and SHA-512 Names are supported (C `IsSessionBindEntity()`).
#[test]
fn verify_session_hmacs_bound_entity_handle_equality_and_sha512_name_panic() {
    // SHA-512 Name.
    {
        let mut sim = create_simulator!();
        let mut public = sealed_template(TpmaObject::USER_WITH_AUTH | TpmaObject::NO_DA, &[]);
        public.name_alg = Some(TpmiAlgHash::Sha512);
        let item = create_primary_obj(&mut sim, public, b"key", b"data");
        let session = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle(item),
            b"key",
            TpmSe::HMAC,
            None,
            TpmiAlgHash::Sha256,
        )
        .unwrap();
        let names = [object_name(&mut sim, item)];
        // Bound to the entity: the authValue is not part of the HMAC key.
        let auth = hmac_entry(&session, TpmCc::Unseal, &names, &[], &[], ATTR_CONTINUE);
        assert_eq!(unseal(&mut sim, item, auth), RC_SUCCESS);
    }

    // Same entity under another handle (persistent copy of the bind object).
    {
        let mut sim = create_simulator!();
        let item = create_sealed(
            &mut sim,
            TpmaObject::USER_WITH_AUTH | TpmaObject::NO_DA,
            b"key",
            &[],
        );
        let session = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle(item),
            b"key",
            TpmSe::HMAC,
            None,
            TpmiAlgHash::Sha256,
        )
        .unwrap();
        let persistent: u32 = 0x8100_0100;
        let code = rc(
            &mut sim,
            TpmCc::EvictControl,
            &[Handle::RH_OWNER.0, item],
            &[AuthEntry::pw(&[])],
            &persistent.to_be_bytes(),
        );
        assert_eq!(code, RC_SUCCESS, "EvictControl");
        let names = [object_name(&mut sim, persistent)];
        let auth = hmac_entry(&session, TpmCc::Unseal, &names, &[], &[], ATTR_CONTINUE);
        assert_eq!(unseal(&mut sim, persistent, auth), RC_SUCCESS);
    }
}

/// Sessions bound to a DA-protected entity (C `isDaBound` / `isLockoutBound`, set by
/// `SessionCreate()`) are subject to DA however they are used: `ParseSessionBuffer()` checks
/// lockout for them and `IncrementLockout()` always counts their failures (against lockoutAuth
/// for a session bound to `TPM_RH_LOCKOUT`).
#[test]
fn verify_session_hmacs_da_lockout_increment_and_error_code_bugs_da_bound_sessions() {
    let owner = [handle_name(Handle::RH_OWNER.0)];
    let params = tpm2b_params(b"");

    // A failure of a DA-bound session authorizing the (DA-exempt) owner counts as a DA failure.
    {
        let mut sim = create_simulator!();
        let item = create_sealed(&mut sim, TpmaObject::USER_WITH_AUTH, b"k", &[]);
        let session = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle(item),
            b"k",
            TpmSe::HMAC,
            None,
            TpmiAlgHash::Sha256,
        )
        .unwrap();
        let before = lockout_counter(&mut sim);
        let auth = raw_entry(&session, ATTR_CONTINUE, &[0x55; 32]);
        let code = rc(
            &mut sim,
            TpmCc::HierarchyChangeAuth,
            &[Handle::RH_OWNER.0],
            &[auth],
            &params,
        );
        assert_eq!(code, RC_AUTH_FAIL_S1);
        assert_eq!(lockout_counter(&mut sim), before + 1);
    }

    // In lockout, a DA-bound session cannot be used, even with a correct HMAC for a DA-exempt
    // entity; an unbound session still can.
    {
        let mut sim = create_simulator!();
        set_da_parameters(&mut sim, 1, 1000, 1000);
        let item = create_sealed(&mut sim, TpmaObject::USER_WITH_AUTH, b"k", &[]);
        let session = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle(item),
            b"k",
            TpmSe::HMAC,
            None,
            TpmiAlgHash::Sha256,
        )
        .unwrap();
        assert_eq!(unseal(&mut sim, item, AuthEntry::pw(b"x")), RC_AUTH_FAIL_S1);
        let auth = hmac_entry(
            &session,
            TpmCc::HierarchyChangeAuth,
            &owner,
            &params,
            &[],
            ATTR_CONTINUE,
        );
        let code = rc(
            &mut sim,
            TpmCc::HierarchyChangeAuth,
            &[Handle::RH_OWNER.0],
            &[auth],
            &params,
        );
        assert_eq!(code, RC_LOCKOUT);
        let unbound = start(&mut sim, TpmSe::HMAC);
        let auth = hmac_entry(
            &unbound,
            TpmCc::HierarchyChangeAuth,
            &owner,
            &params,
            &[],
            ATTR_CONTINUE,
        );
        let code = rc(
            &mut sim,
            TpmCc::HierarchyChangeAuth,
            &[Handle::RH_OWNER.0],
            &[auth],
            &params,
        );
        assert_eq!(code, RC_SUCCESS);
    }

    // A failure of a session bound to TPM_RH_LOCKOUT disables lockoutAuth.
    {
        let mut sim = create_simulator!();
        let session = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle::RH_LOCKOUT,
            &[],
            TpmSe::HMAC,
            None,
            TpmiAlgHash::Sha256,
        )
        .unwrap();
        let before = lockout_counter(&mut sim);
        let auth = raw_entry(&session, ATTR_CONTINUE, &[0x55; 32]);
        let code = rc(
            &mut sim,
            TpmCc::HierarchyChangeAuth,
            &[Handle::RH_OWNER.0],
            &[auth],
            &params,
        );
        assert_eq!(code, RC_AUTH_FAIL_S1);
        assert_eq!(lockout_counter(&mut sim), before);
        let code = rc(
            &mut sim,
            TpmCc::DictionaryAttackLockReset,
            &[Handle::RH_LOCKOUT.0],
            &[AuthEntry::pw(&[])],
            &[],
        );
        assert_eq!(code, RC_LOCKOUT);
    }
}
