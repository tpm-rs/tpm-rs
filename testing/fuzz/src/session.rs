//! The session engine of the differential fuzz driver: client-side state of
//! every authorization session a fuzzed conversation starts, plus building
//! command authorization areas and checking response authorization areas.
//!
//! A conversation is a sequence of TPM commands sent to one fresh TPM (see the
//! crate docs). Commands that need authorization reach deep TPM behavior only
//! if their authorization is *correct*, so the driver delegates the
//! authorization area to this engine:
//!
//! * [`SessionEngine::authorize`] builds the `TPMS_AUTH_COMMAND`s of one
//!   command (password, HMAC and policy sessions, or raw bytes). For HMAC and
//!   policy sessions it derives a deterministic `nonceCaller`, computes the
//!   cpHash and the command HMAC (optionally corrupted by one bit flip), and
//!   CFB/XOR-encrypts the first command parameter when a session has the
//!   `decrypt` attribute.
//! * [`SessionEngine::on_response`] sees every round's command and response.
//!   It creates sessions on a successful `TPM2_StartAuthSession` (session key
//!   via KDFa), rolls `nonceTPM` from the response authorization area,
//!   verifies the response HMACs, decrypts `encrypt`-session response
//!   parameters, tracks the policy flags (`TPM2_PolicyAuthValue`,
//!   `TPM2_PolicyPassword`, `TPM2_PolicyRestart`) and drops sessions on
//!   `continueSession = 0` or `TPM2_FlushContext`.
//!
//! The rules follow the TCG reference implementation (`SessionProcess.c`,
//! `Session.c`, `CryptUtil.c`), which is what the references and `tpm-rs` are
//! compared against:
//!
//! * The session key is `KDFa(authHash, authValue(bind) || salt, "ATH",
//!   nonceTPM, nonceCaller, digestBits)`, or empty for an unbound, unsalted
//!   session. For a `TPM2_StartAuthSession` with a `tpmKey` and an empty
//!   `encryptedSalt`, [`SessionEngine::prepare_params`] generates the salt and
//!   encrypts it to the key's public area (seen in an earlier round), so the
//!   key is known; a session with any other (fuzzed or replayed) salt is
//!   tracked, but its key is unknown and its HMACs are never verified.
//! * Session `i` is associated with command handle `i` when that handle has an
//!   authorization role. The HMAC key is `sessionKey || authValue` where the
//!   authValue (trailing zeros removed) is included for an associated HMAC
//!   session unless the session is bound to the entity (same Name and
//!   authValue as at `TPM2_StartAuthSession`), and for an associated policy
//!   session only after `TPM2_PolicyAuthValue`/`TPM2_PolicyPassword`. After
//!   `TPM2_PolicyPassword` the HMAC field carries the plain authValue and the
//!   response HMAC is empty.
//! * An empty HMAC key with an empty command HMAC is a valid "null HMAC" (and
//!   gives an empty response HMAC).
//! * The command HMAC of the first session additionally covers the `nonceTPM`
//!   of a different decrypt session and of a different encrypt session.
//! * Parameter encryption keys always include the authValue of the
//!   associated entity, bound or not.
//! * Policy sessions used with `continueSession` set are reset after the
//!   command (`UpdateInternalSession`), which clears the policy flags.
//!
//! # Findings
//!
//! Every check here runs on a response that already matched the references
//! (or a documented exception), so a failing check means a bug in `tpm-rs`
//! (and possibly in the references too). The engine panics with:
//!
//! * `BAD_RESPONSE_HMAC[round<r>:cc<code>:slot<i>:<handle>]`: the response HMAC
//!   of a success response is not the one the session's key gives.
//! * `BAD_RESPONSE_AUTH[round<r>:cc<code>:...]`: a success response to a
//!   command with sessions has no well-formed authorization area with one
//!   entry per command session.
//! * `ACCEPTED_CORRUPT_HMAC[round<r>:cc<code>:slot<i>:<handle>]`: a command
//!   whose HMAC was deliberately corrupted succeeded.
//!
//! The checks only run when the command bytes sent carry exactly the
//! authorization area [`SessionEngine::authorize`] built (driver fix-ups that
//! damage it, or raw sessions, are only tracked, never verified).

#![forbid(unsafe_code)]

use testing::_common::{self, CLIENT_CRYPTO};
use testing::differential::server::handle_counts;
use tpm2::crypto::{Direction, HashStream, HmacStream};
use tpm2::{Alg, TpmCc, TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode, TpmtSymDefObject};

/// Wire constants used by the engine (TPM 2.0 Library Part 2).
pub mod wire {
    /// `TPM_ST_NO_SESSIONS`.
    pub const ST_NO_SESSIONS: u16 = 0x8001;
    /// `TPM_ST_SESSIONS`.
    pub const ST_SESSIONS: u16 = 0x8002;
    /// `TPM_RS_PW`, the password session handle.
    pub const RS_PW: u32 = 0x4000_0009;
    /// `TPM_RH_NULL`.
    pub const RH_NULL: u32 = 0x4000_0007;
    /// `TPM_RH_LOCKOUT`.
    pub const RH_LOCKOUT: u32 = 0x4000_000A;
    /// `TPM_ALG_XOR`.
    pub const ALG_XOR: u16 = 0x000A;
    /// `TPM_ALG_NULL`.
    pub const ALG_NULL: u16 = 0x0010;
    /// `TPM_ALG_CFB`.
    pub const ALG_CFB: u16 = 0x0043;
    /// `TPM_SE_HMAC`.
    pub const SE_HMAC: u8 = 0x00;
    /// `TPM_SE_POLICY`.
    pub const SE_POLICY: u8 = 0x01;
    /// `TPM_SE_TRIAL`.
    pub const SE_TRIAL: u8 = 0x03;
    /// `TPMA_SESSION.continueSession`.
    pub const ATTR_CONTINUE: u8 = 0x01;
    /// `TPMA_SESSION.auditExclusive`.
    pub const ATTR_AUDIT_EXCLUSIVE: u8 = 0x02;
    /// `TPMA_SESSION.auditReset`.
    pub const ATTR_AUDIT_RESET: u8 = 0x04;
    /// `TPMA_SESSION.decrypt`.
    pub const ATTR_DECRYPT: u8 = 0x20;
    /// `TPMA_SESSION.encrypt`.
    pub const ATTR_ENCRYPT: u8 = 0x40;
    /// `TPMA_SESSION.audit`.
    pub const ATTR_AUDIT: u8 = 0x80;
    /// `TPM_CC_NV_UndefineSpaceSpecial`.
    pub const CC_NV_UNDEFINE_SPACE_SPECIAL: u32 = 0x11F;
    /// `TPM_CC_Clear`.
    pub const CC_CLEAR: u32 = 0x126;
    /// `TPM_CC_HierarchyChangeAuth`.
    pub const CC_HIERARCHY_CHANGE_AUTH: u32 = 0x129;
    /// `TPM_CC_NV_ChangeAuth`.
    pub const CC_NV_CHANGE_AUTH: u32 = 0x13B;
    /// `TPM_CC_FlushContext`.
    pub const CC_FLUSH_CONTEXT: u32 = 0x165;
    /// `TPM_CC_PolicyAuthValue`.
    pub const CC_POLICY_AUTH_VALUE: u32 = 0x16B;
    /// `TPM_CC_StartAuthSession`.
    pub const CC_START_AUTH_SESSION: u32 = 0x176;
    /// `TPM_CC_PolicyRestart`.
    pub const CC_POLICY_RESTART: u32 = 0x180;
    /// `TPM_CC_PCR_SetAuthValue`.
    pub const CC_PCR_SET_AUTH_VALUE: u32 = 0x183;
    /// `TPM_CC_PolicyPassword`.
    pub const CC_POLICY_PASSWORD: u32 = 0x18C;
    /// `TPM_CC_EvictControl`.
    pub const CC_EVICT_CONTROL: u32 = 0x120;
    /// `TPM_CC_CreatePrimary`.
    pub const CC_CREATE_PRIMARY: u32 = 0x131;
    /// `TPM_CC_Load`.
    pub const CC_LOAD: u32 = 0x157;
    /// `TPM_CC_LoadExternal`.
    pub const CC_LOAD_EXTERNAL: u32 = 0x167;
    /// `TPM_CC_ReadPublic`.
    pub const CC_READ_PUBLIC: u32 = 0x173;
    /// `TPM_CC_CreateLoaded`.
    pub const CC_CREATE_LOADED: u32 = 0x191;
}

use wire::*;

/// What the driver knows about the command being authorized.
#[derive(Clone, Copy, Debug)]
pub struct CommandInfo<'a> {
    /// Index of the round in the conversation (used in finding signatures and
    /// for the deterministic `nonceCaller`).
    pub round: usize,
    /// The command code sent.
    pub code: u32,
    /// The command handles sent, in order.
    pub handles: &'a [u32],
    /// The Name of every command handle (cpHash input): the object Name for
    /// transient/persistent objects, the NV Name for NV indices, and the
    /// big-endian handle for everything else.
    pub names: &'a [Vec<u8>],
    /// The authValue the driver believes every command handle has (empty if
    /// unknown). Only used for the bind entity of `TPM2_StartAuthSession`.
    pub handle_auths: &'a [Vec<u8>],
}

/// The kind of session the fuzz input asks for in one authorization slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionChoice<'a> {
    /// A `TPM_RS_PW` password session carrying the request's `auth`.
    Password,
    /// An HMAC session: the `session`-th live HMAC session (modulo the
    /// number of live HMAC sessions), with session attributes `attrs`.
    /// `corrupt_hmac` flips one bit of the computed HMAC. Falls back to a
    /// password session when there is no live HMAC session.
    Hmac {
        /// Selector into the live HMAC sessions (modulo their count).
        session: u8,
        /// The `TPMA_SESSION` byte sent.
        attrs: u8,
        /// Whether to flip one bit of the HMAC.
        corrupt_hmac: bool,
    },
    /// A policy session: the `session`-th live policy or trial session
    /// (modulo their count). Falls back to a password session when there is
    /// none.
    Policy {
        /// Selector into the live policy/trial sessions (modulo their count).
        session: u8,
        /// The `TPMA_SESSION` byte sent.
        attrs: u8,
    },
    /// Raw bytes, appended to the authorization area as is.
    Raw(&'a [u8]),
}

/// One authorization slot of a command.
#[derive(Clone, Copy, Debug)]
pub struct SessionRequest<'a> {
    /// The slot number the driver assigned (informational; the position in
    /// the request slice is the session's index in the authorization area).
    pub slot: usize,
    /// The session to use.
    pub choice: SessionChoice<'a>,
    /// The authValue to authorize with (the password, or the authValue mixed
    /// into the HMAC key), as resolved by the driver.
    pub auth: &'a [u8],
}

/// The type of a tracked session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionType {
    /// `TPM_SE_HMAC`.
    Hmac,
    /// `TPM_SE_POLICY`.
    Policy,
    /// `TPM_SE_TRIAL` (a policy session that cannot authorize).
    Trial,
}

/// The parameter-encryption algorithm of a session (`symmetric` of
/// `TPM2_StartAuthSession`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParamCipher {
    /// `TPM_ALG_NULL`: no parameter encryption.
    None,
    /// `TPM_ALG_XOR` obfuscation with the session's authHash.
    Xor,
    /// A block cipher in CFB mode with `key_bits`-bit keys.
    Cfb {
        /// The algorithm, key size and mode.
        def: TpmtSymDefObject,
        /// The key size in bits.
        key_bits: u32,
    },
    /// A cipher the client crypto cannot model; parameters stay plain.
    Unsupported,
}

/// The entity a session was bound to by `TPM2_StartAuthSession`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BoundEntity {
    /// The Name of the bind entity at the time of binding.
    name: Vec<u8>,
    /// The authValue of the bind entity (trailing zeros removed).
    auth: Vec<u8>,
}

/// Client-side state of one session the TPM started.
#[derive(Clone, Debug)]
pub struct Session {
    /// The session handle.
    handle: u32,
    /// The session type.
    session_type: SessionType,
    /// The session's hash algorithm.
    auth_hash: TpmiAlgHash,
    /// The current (rolling) `nonceTPM`.
    nonce_tpm: Vec<u8>,
    /// The last `nonceCaller` sent with this session.
    nonce_caller: Vec<u8>,
    /// The session key, or `None` for a session with a salt the engine did not
    /// generate (unknown key).
    session_key: Option<Vec<u8>>,
    /// The bind entity of a bound HMAC session.
    bind: Option<BoundEntity>,
    /// The parameter-encryption algorithm.
    cipher: ParamCipher,
    /// Set by a successful `TPM2_PolicyAuthValue`.
    policy_auth_value: bool,
    /// Set by a successful `TPM2_PolicyPassword`.
    policy_password: bool,
    /// The round in which the session was started.
    started_round: usize,
    /// Whether the session is salted with a salt the engine generated.
    salted: bool,
}

impl Session {
    /// The session handle.
    pub fn handle(&self) -> u32 {
        self.handle
    }

    /// The session type.
    pub fn session_type(&self) -> SessionType {
        self.session_type
    }

    /// The session's current `nonceTPM`.
    pub fn nonce_tpm(&self) -> &[u8] {
        &self.nonce_tpm
    }

    /// The last `nonceCaller` sent with the session (the one of
    /// `TPM2_StartAuthSession` until the session is first used).
    pub fn nonce_caller(&self) -> &[u8] {
        &self.nonce_caller
    }

    /// The session key, or `None` if it is unknown (a salt the engine did not
    /// generate).
    pub fn session_key(&self) -> Option<&[u8]> {
        self.session_key.as_deref()
    }

    /// The round in which the session was started.
    pub fn started_round(&self) -> usize {
        self.started_round
    }

    /// Whether `TPM2_PolicyAuthValue` (`.0`) / `TPM2_PolicyPassword` (`.1`)
    /// succeeded on this policy session since its last reset.
    pub fn policy_flags(&self) -> (bool, bool) {
        (self.policy_auth_value, self.policy_password)
    }

    /// Whether the session is a policy (or trial) session.
    fn is_policy(&self) -> bool {
        self.session_type != SessionType::Hmac
    }
}

/// Counters for the success rate of engine-built HMAC/policy authorizations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HmacStats {
    /// HMAC-session slots built by [`SessionEngine::authorize`].
    pub hmac_built: u64,
    /// HMAC-session slots whose command succeeded.
    pub hmac_succeeded: u64,
    /// Policy-session slots built.
    pub policy_built: u64,
    /// Policy-session slots whose command succeeded.
    pub policy_succeeded: u64,
    /// Response HMACs verified (success responses).
    pub responses_verified: u64,
    /// HMAC-session slots built with a deliberately corrupted HMAC.
    pub hmac_corrupted: u64,
    /// Uncorrupted HMAC-session slots whose command failed with
    /// `TPM_RC_AUTH_FAIL`/`TPM_RC_BAD_AUTH` attributed to that session: the
    /// TPM rejected the HMAC (a wrong authValue chosen by the input, a stale
    /// Name, or an engine bug). The rate of these among the built slots is
    /// the engine's health metric.
    pub hmac_auth_failed: u64,
    /// Salts generated and encrypted by [`SessionEngine::prepare_params`].
    pub salts_generated: u64,
    /// Salted sessions started with a generated salt (known session key).
    pub salted_started: u64,
    /// HMAC-session slots built with a salted session of known key.
    pub salted_built: u64,
    /// Of those, slots whose command succeeded (response HMAC verified).
    pub salted_succeeded: u64,
}

impl HmacStats {
    /// Adds `other`'s counters to `self` (aggregation over inputs).
    pub fn add(&mut self, other: &HmacStats) {
        self.hmac_built += other.hmac_built;
        self.hmac_succeeded += other.hmac_succeeded;
        self.policy_built += other.policy_built;
        self.policy_succeeded += other.policy_succeeded;
        self.responses_verified += other.responses_verified;
        self.hmac_corrupted += other.hmac_corrupted;
        self.hmac_auth_failed += other.hmac_auth_failed;
        self.salts_generated += other.salts_generated;
        self.salted_started += other.salted_started;
        self.salted_built += other.salted_built;
        self.salted_succeeded += other.salted_succeeded;
    }
}

/// The session index (0-based) a format-1 response code blames for
/// `TPM_RC_AUTH_FAIL` or `TPM_RC_BAD_AUTH`, if it is one of those.
fn auth_failure_session(rc: u32) -> Option<usize> {
    /// Format-1 `TPM_RC_AUTH_FAIL`.
    const AUTH_FAIL: u32 = 0x0E;
    /// Format-1 `TPM_RC_BAD_AUTH`.
    const BAD_AUTH: u32 = 0x22;
    let is_format1_session = rc & 0x80 != 0 && rc & 0x40 == 0 && rc & 0x800 != 0;
    let code = rc & 0x3F;
    (is_format1_session && (code == AUTH_FAIL || code == BAD_AUTH))
        .then_some(((rc >> 8) & 0x7) as usize)
        .and_then(|n| n.checked_sub(1))
}

/// Details of the last uncorrupted, engine-built HMAC slot the TPM rejected
/// with `TPM_RC_AUTH_FAIL`/`TPM_RC_BAD_AUTH` (see
/// [`HmacStats::hmac_auth_failed`]), for diagnosing the rejection rate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthFailure {
    /// The round.
    pub round: usize,
    /// The command code.
    pub code: u32,
    /// The response code.
    pub rc: u32,
    /// The rejected slot.
    pub slot: usize,
    /// The session handle.
    pub session: u32,
    /// The command handle the slot authorizes, if it is associated.
    pub entity: Option<u32>,
    /// Whether the authValue was part of the HMAC key.
    pub include_auth: bool,
    /// The authValue the engine used (trailing zeros removed).
    pub entity_auth: Vec<u8>,
}

/// One slot of the authorization area as built by
/// [`SessionEngine::authorize`].
#[derive(Clone, Debug)]
enum Slot {
    /// A password session.
    Password,
    /// Raw bytes (not tracked).
    Raw,
    /// An HMAC or policy session built by the engine.
    Built(Built),
}

/// The state of an engine-built session slot needed to check the response.
#[derive(Clone, Debug)]
struct Built {
    /// The session handle.
    handle: u32,
    /// The session type at build time.
    session_type: SessionType,
    /// The `nonceCaller` sent.
    nonce_caller: Vec<u8>,
    /// The command HMAC sent (or the password, in password mode).
    hmac: Vec<u8>,
    /// Whether the session is associated with a command handle.
    associated: bool,
    /// Whether the authValue was part of the HMAC key.
    include_auth: bool,
    /// The authValue used (trailing zeros removed).
    entity_auth: Vec<u8>,
    /// Policy session after `TPM2_PolicyPassword`: the HMAC field is the
    /// password and the response HMAC is empty.
    password_mode: bool,
    /// Whether the HMAC was deliberately corrupted.
    corrupted: bool,
    /// Whether the session is salted (with a known key).
    salted: bool,
}

/// What [`SessionEngine::authorize`] built for the command in flight.
#[derive(Clone, Debug)]
struct Pending {
    /// The round of the command.
    round: usize,
    /// The command code.
    code: u32,
    /// The plaintext parameter area (before parameter encryption).
    plain_params: Vec<u8>,
    /// The authorization area built (without `authSize`).
    auth_area: Vec<u8>,
    /// One entry per authorization slot.
    slots: Vec<Slot>,
    /// The slot of the (first) encrypt session.
    encrypt_slot: Option<usize>,
}

/// One `TPMS_AUTH_COMMAND` parsed from command bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthCommand {
    /// `sessionHandle`.
    handle: u32,
    /// `nonce`.
    nonce: Vec<u8>,
    /// `sessionAttributes`.
    attrs: u8,
    /// `hmac`.
    hmac: Vec<u8>,
}

/// One `TPMS_AUTH_RESPONSE` parsed from response bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthResponse {
    /// `nonce` (the new `nonceTPM`).
    nonce: Vec<u8>,
    /// `sessionAttributes`.
    attrs: u8,
    /// `hmac`.
    hmac: Vec<u8>,
}

/// A command parsed from its wire bytes.
#[derive(Clone, Debug)]
struct ParsedCommand<'a> {
    /// The tag.
    tag: u16,
    /// The command code.
    code: u32,
    /// The handle area (count from [`handle_counts`]).
    handles: Vec<u32>,
    /// The raw authorization area (without `authSize`); empty without
    /// sessions.
    auth_area: &'a [u8],
    /// The parsed sessions (empty if the area does not parse).
    sessions: Vec<AuthCommand>,
    /// The parameter area.
    params: &'a [u8],
}

/// The body of a success response parsed from its wire bytes.
#[derive(Clone, Debug)]
struct ParsedResponse<'a> {
    /// The response handles.
    handles: Vec<u32>,
    /// The parameter area.
    params: &'a [u8],
    /// One authorization entry per command session.
    auths: Vec<AuthResponse>,
}

/// A big-endian reader over wire bytes; every read returns `None` past the
/// end.
struct Reader<'a> {
    /// The unread bytes.
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Starts reading `bytes`.
    fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// Reads `n` bytes.
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.rest.len() < n {
            return None;
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Some(head)
    }

    /// Reads a `u8`.
    fn u8(&mut self) -> Option<u8> {
        self.bytes(1).map(|b| b[0])
    }

    /// Reads a big-endian `u16`.
    fn u16(&mut self) -> Option<u16> {
        self.bytes(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    /// Reads a big-endian `u32`.
    fn u32(&mut self) -> Option<u32> {
        self.bytes(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a `TPM2B` (u16 size, then the buffer).
    fn tpm2b(&mut self) -> Option<&'a [u8]> {
        let size = self.u16()? as usize;
        self.bytes(size)
    }
}

/// Appends a `TPM2B` (u16 size prefix) to `out`.
fn put_tpm2b(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// Marshals one `TPMS_AUTH_COMMAND`.
fn marshal_auth_command(out: &mut Vec<u8>, auth: &AuthCommand) {
    out.extend_from_slice(&auth.handle.to_be_bytes());
    put_tpm2b(out, &auth.nonce);
    out.push(auth.attrs);
    put_tpm2b(out, &auth.hmac);
}

/// Parses an authorization area into its `TPMS_AUTH_COMMAND`s, or `None` if
/// it is not a well-formed sequence of them.
fn parse_auth_area(area: &[u8]) -> Option<Vec<AuthCommand>> {
    let mut r = Reader::new(area);
    let mut out = Vec::new();
    while !r.rest.is_empty() {
        out.push(AuthCommand {
            handle: r.u32()?,
            nonce: r.tpm2b()?.to_vec(),
            attrs: r.u8()?,
            hmac: r.tpm2b()?.to_vec(),
        });
    }
    Some(out)
}

/// Parses command bytes (header, handles, authorization area, parameters).
/// Returns `None` if the command cannot be split into those parts.
fn parse_command(command: &[u8]) -> Option<ParsedCommand<'_>> {
    let mut r = Reader::new(command);
    let tag = r.u16()?;
    let _size = r.u32()?;
    let code = r.u32()?;
    let (handle_count, _) = handle_counts(code)?;
    let handles = (0..handle_count)
        .map(|_| r.u32())
        .collect::<Option<Vec<_>>>()?;
    let mut auth_area: &[u8] = &[];
    let mut sessions = Vec::new();
    if tag == ST_SESSIONS {
        let auth_size = r.u32()? as usize;
        auth_area = r.bytes(auth_size)?;
        sessions = parse_auth_area(auth_area).unwrap_or_default();
    }
    Some(ParsedCommand {
        tag,
        code,
        handles,
        auth_area,
        sessions,
        params: r.rest,
    })
}

/// Parses the header of response bytes into `(tag, responseCode)`.
fn parse_response_header(response: &[u8]) -> Option<(u16, u32)> {
    let mut r = Reader::new(response);
    let tag = r.u16()?;
    let _size = r.u32()?;
    let rc = r.u32()?;
    Some((tag, rc))
}

/// Parses the body of a success response to command `code` with
/// `session_count` command sessions. Requires exactly one authorization entry
/// per command session and no trailing bytes.
fn parse_response(
    response: &[u8],
    code: u32,
    session_count: usize,
) -> Result<ParsedResponse<'_>, &'static str> {
    let mut r = Reader::new(response);
    let tag = r.u16().ok_or("short header")?;
    r.u32().ok_or("short header")?;
    r.u32().ok_or("short header")?;
    let (_, rsp_handles) = handle_counts(code).ok_or("unknown command code")?;
    let handles = (0..rsp_handles)
        .map(|_| r.u32())
        .collect::<Option<Vec<_>>>()
        .ok_or("short handle area")?;
    if session_count == 0 {
        if tag != ST_NO_SESSIONS {
            return Err("sessions tag without command sessions");
        }
        return Ok(ParsedResponse {
            handles,
            params: r.rest,
            auths: Vec::new(),
        });
    }
    if tag != ST_SESSIONS {
        return Err("no sessions tag");
    }
    let param_size = r.u32().ok_or("short parameterSize")? as usize;
    let params = r.bytes(param_size).ok_or("parameterSize too large")?;
    let mut auths = Vec::with_capacity(session_count);
    for _ in 0..session_count {
        let entry = (|| {
            Some(AuthResponse {
                nonce: r.tpm2b()?.to_vec(),
                attrs: r.u8()?,
                hmac: r.tpm2b()?.to_vec(),
            })
        })()
        .ok_or("short authorization area")?;
        auths.push(entry);
    }
    if !r.rest.is_empty() {
        return Err("trailing bytes after the authorization area");
    }
    Ok(ParsedResponse {
        handles,
        params,
        auths,
    })
}

/// Hashes the concatenation of `parts` with `alg` (client crypto).
fn digest(alg: TpmiAlgHash, parts: &[&[u8]]) -> Vec<u8> {
    let mut state = HashStream::new(CLIENT_CRYPTO, alg).expect("client hash");
    for part in parts {
        state.update(part).expect("client hash update");
    }
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    state
        .finalize(&mut out)
        .expect("client hash finalize")
        .digest()
        .to_vec()
}

/// HMACs the concatenation of `parts` under `key` with `alg` (client crypto).
fn hmac(alg: TpmiAlgHash, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut state = HmacStream::new(CLIENT_CRYPTO, alg, key).expect("client hmac");
    for part in parts {
        state.update(part).expect("client hmac update");
    }
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    state
        .finalize(&mut out)
        .expect("client hmac finalize")
        .digest()
        .to_vec()
}

/// Runs `KDFa(alg, key, label, context_u, context_v, bits)` (client crypto).
fn kdfa(
    alg: TpmiAlgHash,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    bits: u32,
) -> Vec<u8> {
    let mut out = vec![0u8; bits.div_ceil(8) as usize];
    _common::kdfa_by_alg(
        CLIENT_CRYPTO,
        alg,
        key,
        label,
        context_u,
        context_v,
        bits,
        &mut out,
    );
    out
}

/// Computes the session key of a new session:
/// `KDFa(authHash, bindAuth || salt, "ATH", nonceTPM, nonceCaller, digestBits)`, or empty when
/// there is neither a bind entity (`bind_auth` is `None`) nor a salt (TPM 2.0 Part 1, 19.6.8;
/// reference `SessionCreate()`). `bind_auth` must already have its trailing zeros removed.
pub fn session_key(
    auth_hash: TpmiAlgHash,
    bind_auth: Option<&[u8]>,
    salt: &[u8],
    nonce_tpm: &[u8],
    nonce_caller: &[u8],
) -> Vec<u8> {
    if bind_auth.is_none() && salt.is_empty() {
        return Vec::new();
    }
    let key = [bind_auth.unwrap_or_default(), salt].concat();
    kdfa(
        auth_hash,
        &key,
        b"ATH",
        nonce_tpm,
        nonce_caller,
        (auth_hash.digest_size() * 8) as u32,
    )
}

/// Computes `cpHash = H(commandCode || names || parameters)`.
pub fn cp_hash(alg: TpmiAlgHash, code: u32, names: &[Vec<u8>], params: &[u8]) -> Vec<u8> {
    let code = code.to_be_bytes();
    let mut parts: Vec<&[u8]> = vec![&code];
    parts.extend(names.iter().map(Vec::as_slice));
    parts.push(params);
    digest(alg, &parts)
}

/// Computes `rpHash = H(responseCode || commandCode || parameters)`.
pub fn rp_hash(alg: TpmiAlgHash, rc: u32, code: u32, params: &[u8]) -> Vec<u8> {
    digest(alg, &[&rc.to_be_bytes(), &code.to_be_bytes(), params])
}

/// Applies session parameter encryption (`dir`) to the first `TPM2B`
/// parameter in `params` (its size prefix stays plain), with the key and IV
/// (CFB) or mask (XOR) derived from `key`, `nonce_newer` and `nonce_older`
/// (TPM 2.0 Part 1, 21; reference `CryptParameterEncryption()`/
/// `CryptParameterDecryption()`). Returns whether `params` was transformed
/// (`false` for no or an unsupported cipher, or a malformed size prefix).
fn apply_param_cipher(
    cipher: ParamCipher,
    auth_hash: TpmiAlgHash,
    key: &[u8],
    nonce_newer: &[u8],
    nonce_older: &[u8],
    dir: Direction,
    params: &mut [u8],
) -> bool {
    if params.len() < 2 {
        return false;
    }
    let size = u16::from_be_bytes([params[0], params[1]]) as usize;
    if size > params.len() - 2 {
        return false;
    }
    let data = &mut params[2..2 + size];
    if data.is_empty() {
        return matches!(cipher, ParamCipher::Xor | ParamCipher::Cfb { .. });
    }
    match cipher {
        ParamCipher::None | ParamCipher::Unsupported => false,
        ParamCipher::Xor => {
            let mask = kdfa(
                auth_hash,
                key,
                b"XOR",
                nonce_newer,
                nonce_older,
                (data.len() * 8) as u32,
            );
            data.iter_mut().zip(mask).for_each(|(d, m)| *d ^= m);
            true
        }
        ParamCipher::Cfb { def, key_bits } => {
            let block_bits = 128;
            let material = kdfa(
                auth_hash,
                key,
                b"CFB",
                nonce_newer,
                nonce_older,
                key_bits + block_bits,
            );
            let (sym_key, iv) = material.split_at(key_bits as usize / 8);
            let mut iv = iv.to_vec();
            _common::sym_encrypt_decrypt(CLIENT_CRYPTO, def, sym_key, &mut iv, dir, data).is_ok()
        }
    }
}

/// Maps the `symmetric` of `TPM2_StartAuthSession` to a [`ParamCipher`].
fn param_cipher(alg: u16, key_bits: u16, mode: u16) -> ParamCipher {
    match alg {
        ALG_NULL => ParamCipher::None,
        ALG_XOR => ParamCipher::Xor,
        _ if mode == ALG_CFB => TpmtSymDefObject::from_parts(
            Alg::from(alg),
            key_bits,
            Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
        )
        .map_or(ParamCipher::Unsupported, |def| ParamCipher::Cfb {
            def,
            key_bits: key_bits as u32,
        }),
        _ => ParamCipher::Unsupported,
    }
}

/// SplitMix64: a tiny deterministic generator for `nonceCaller` values.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Derives `len` deterministic bytes from `seed` (SplitMix64 stream).
fn derive_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        out.extend_from_slice(&splitmix64(&mut state).to_be_bytes());
    }
    out.truncate(len);
    out
}

/// Whether session index `index` of command `code` (with `handle_count`
/// handles sent) is associated with a command handle, i.e. that handle has an
/// authorization role (reference `ParseSessionBuffer()`).
fn is_associated(code: u32, handle_count: usize, index: usize) -> bool {
    index < handle_count && _common::handle_requires_auth(TpmCc::from(code), index)
}

/// The per-conversation session engine (see the module docs).
#[derive(Clone, Debug, Default)]
pub struct SessionEngine {
    /// The live sessions, in creation order.
    sessions: Vec<Session>,
    /// What `authorize` built for the command in flight.
    pending: Option<Pending>,
    /// Counter mixed into every derived `nonceCaller`.
    nonce_counter: u64,
    /// Success-rate counters.
    stats: HmacStats,
    /// The last rejected HMAC slot (see [`AuthFailure`]).
    last_auth_failure: Option<AuthFailure>,
    /// The plaintext parameters of an encrypted command (see
    /// [`SessionEngine::plain_params`]).
    last_plain_params: Option<Vec<u8>>,
    /// The `TPMT_PUBLIC` wire bytes of loaded and persistent objects, by
    /// handle (the keys salts are encrypted to).
    publics: Vec<(u32, Vec<u8>)>,
    /// The salt [`SessionEngine::prepare_params`] generated for the
    /// `TPM2_StartAuthSession` in flight.
    pending_salt: Option<GeneratedSalt>,
}

/// A salt the engine generated and encrypted for a `TPM2_StartAuthSession`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct GeneratedSalt {
    /// The salt.
    salt: Vec<u8>,
    /// The `encryptedSalt` contents placed into the command.
    encrypted: Vec<u8>,
}

impl SessionEngine {
    /// Creates an engine without sessions (one per conversation).
    pub fn new() -> Self {
        Self::default()
    }

    /// The handles of the live sessions, in creation order.
    pub fn live_handles(&self) -> Vec<u32> {
        self.sessions.iter().map(|s| s.handle).collect()
    }

    /// The live sessions, in creation order.
    pub fn sessions(&self) -> &[Session] {
        &self.sessions
    }

    /// The live session with handle `handle`.
    pub fn session(&self, handle: u32) -> Option<&Session> {
        self.sessions.iter().find(|s| s.handle == handle)
    }

    /// The current `nonceTPM` of session `handle` (for `TPM2_PolicySigned`/
    /// `TPM2_PolicySecret` operands).
    pub fn nonce_tpm(&self, handle: u32) -> Option<&[u8]> {
        self.session(handle).map(Session::nonce_tpm)
    }

    /// The success-rate counters.
    pub fn hmac_stats(&self) -> HmacStats {
        self.stats
    }

    /// The HMAC slot the TPM rejected in the last round, if any (cleared by
    /// every [`Self::on_response`]).
    pub fn last_auth_failure(&self) -> Option<&AuthFailure> {
        self.last_auth_failure.as_ref()
    }

    /// Forgets what [`Self::authorize`] built, for a command the transport
    /// rejected (no response, so no session state changes).
    pub fn abort_pending(&mut self) {
        self.pending = None;
        self.last_plain_params = None;
    }

    /// The plaintext parameter area of the current round's command when
    /// [`Self::authorize`] encrypted its first parameter (a `decrypt`
    /// session), else `None`. Valid from `authorize` until the next round's
    /// `authorize` (or the next `on_response` of a round without one), so the
    /// driver can extract facts (e.g. a new authValue) from the plaintext
    /// instead of the ciphertext the TPM received.
    pub fn plain_params(&self) -> Option<&[u8]> {
        self.last_plain_params.as_deref()
    }

    /// The `TPMT_PUBLIC` wire bytes of the object `handle`, as seen in
    /// earlier rounds (`TPM2_CreatePrimary`, `TPM2_CreateLoaded`,
    /// `TPM2_Load`, `TPM2_LoadExternal`, `TPM2_ReadPublic`, carried over by
    /// `TPM2_EvictControl`).
    pub fn public_of(&self, handle: u32) -> Option<&[u8]> {
        self.publics
            .iter()
            .rev()
            .find(|(h, _)| *h == handle)
            .map(|(_, p)| p.as_slice())
    }

    /// Remembers the public area of `handle` (replacing an older one).
    fn record_public(&mut self, handle: u32, public: &[u8]) {
        self.publics.retain(|(h, _)| *h != handle);
        self.publics.push((handle, public.to_vec()));
    }

    /// Rewrites the parameter area of a command before it is assembled (call
    /// it for every structured command, before [`Self::authorize`]).
    ///
    /// Today this generates salts: for a `TPM2_StartAuthSession` with a
    /// `tpmKey` other than `TPM_RH_NULL` whose `encryptedSalt` is empty and
    /// whose public area the engine has seen, it draws a deterministic salt,
    /// encrypts it to the key (`_common::encapsulate_secret`, label
    /// "SECRET": RSA-OAEP or ECC P-256 KDFe) and splices the encrypted salt
    /// into `params` (which therefore may grow). The session key of the
    /// resulting session is then known, so its HMACs are built and verified
    /// like those of any other session. A non-empty (fuzzed or replayed)
    /// `encryptedSalt` is left alone, and its session's key stays unknown.
    pub fn prepare_params(&mut self, cmd: &CommandInfo<'_>, params: &mut Vec<u8>) {
        self.pending_salt = None;
        if cmd.code != CC_START_AUTH_SESSION {
            return;
        }
        let Some(&tpm_key) = cmd.handles.first() else {
            return;
        };
        if tpm_key == RH_NULL {
            return;
        }
        let mut r = Reader::new(params);
        let Some(nonce) = r.tpm2b() else { return };
        let nonce_len = 2 + nonce.len();
        if r.u16() != Some(0) {
            return;
        }
        let Some(public) = self.public_of(tpm_key).map(<[u8]>::to_vec) else {
            return;
        };
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        let seed = ((cmd.round as u64) << 32) ^ self.nonce_counter ^ u64::from(tpm_key);
        let Some((salt, encrypted)) = _common::encapsulate_secret(&public, "SECRET", seed) else {
            return;
        };
        let mut spliced = params[..nonce_len].to_vec();
        put_tpm2b(&mut spliced, &encrypted);
        spliced.extend_from_slice(&params[nonce_len + 2..]);
        *params = spliced;
        self.stats.salts_generated += 1;
        self.pending_salt = Some(GeneratedSalt { salt, encrypted });
    }

    /// Index into `self.sessions` of the `selector`-th session matching
    /// `policy` (modulo their count), or `None` if there is none.
    fn select(&self, policy: bool, selector: u8) -> Option<usize> {
        let candidates: Vec<usize> = self
            .sessions
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_policy() == policy)
            .map(|(i, _)| i)
            .collect();
        if candidates.is_empty() {
            None
        } else {
            Some(candidates[selector as usize % candidates.len()])
        }
    }

    /// Derives the deterministic `nonceCaller` for slot `index` of round
    /// `round` with session `handle` (digest-sized, as the TPM requires at
    /// least 16 bytes and at most the digest size).
    fn derive_nonce(&mut self, round: usize, index: usize, handle: u32, len: usize) -> Vec<u8> {
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        let seed = (round as u64).wrapping_mul(0x1000_0000_01B3)
            ^ ((index as u64) << 56)
            ^ ((handle as u64) << 8)
            ^ self.nonce_counter.wrapping_mul(0xA24B_AED4_963E_E407);
        derive_bytes(seed, len)
    }

    /// Builds the authorization area (the concatenated `TPMS_AUTH_COMMAND`s,
    /// without `authSize`) of the command described by `cmd` with parameter
    /// area `params`, one entry per request.
    ///
    /// When an engine-built session has the `decrypt` attribute, the first
    /// `TPM2B` parameter in `params` is encrypted in place (same length), so
    /// the driver must assemble the command from `params` after this call.
    /// The result is remembered until [`Self::on_response`] (or
    /// [`Self::abort_pending`]).
    pub fn authorize(
        &mut self,
        cmd: &CommandInfo<'_>,
        params: &mut [u8],
        reqs: &[SessionRequest<'_>],
    ) -> Vec<u8> {
        /// A slot after session selection.
        enum Plan<'r> {
            /// Password session with this auth.
            Password,
            /// Raw bytes.
            Raw(&'r [u8]),
            /// Engine session: index into `sessions`, attrs, corrupt flag.
            Session(usize, u8, bool),
        }
        let plain_params = params.to_vec();
        self.last_plain_params = None;
        let plans: Vec<Plan<'_>> = reqs
            .iter()
            .map(|req| match req.choice {
                SessionChoice::Password => Plan::Password,
                SessionChoice::Raw(bytes) => Plan::Raw(bytes),
                SessionChoice::Hmac {
                    session,
                    attrs,
                    corrupt_hmac,
                } => self
                    .select(false, session)
                    .map_or(Plan::Password, |k| Plan::Session(k, attrs, corrupt_hmac)),
                SessionChoice::Policy { session, attrs } => self
                    .select(true, session)
                    .map_or(Plan::Password, |k| Plan::Session(k, attrs, false)),
            })
            .collect();

        // nonceCaller per engine session slot.
        let mut nonces: Vec<Vec<u8>> = Vec::with_capacity(plans.len());
        for (i, plan) in plans.iter().enumerate() {
            nonces.push(match plan {
                Plan::Session(k, ..) => {
                    let (handle, len) = {
                        let s = &self.sessions[*k];
                        (s.handle, s.auth_hash.digest_size().max(16))
                    };
                    self.derive_nonce(cmd.round, i, handle, len)
                }
                _ => Vec::new(),
            });
        }
        let first_with = |attr: u8| {
            plans
                .iter()
                .position(|p| matches!(p, Plan::Session(_, attrs, _) if attrs & attr != 0))
        };
        let decrypt_slot = first_with(ATTR_DECRYPT);
        let encrypt_slot = first_with(ATTR_ENCRYPT);
        let associated = |i: usize| is_associated(cmd.code, cmd.handles.len(), i);

        // Parameter encryption (before the cpHash, which covers the
        // ciphertext).
        if let Some(d) = decrypt_slot
            && let Plan::Session(k, ..) = plans[d]
        {
            let s = &self.sessions[k];
            if let Some(sk) = &s.session_key {
                let extra = if associated(d) {
                    _common::strip_trailing_zeros(reqs[d].auth)
                } else {
                    &[]
                };
                let key = [sk.as_slice(), extra].concat();
                if apply_param_cipher(
                    s.cipher,
                    s.auth_hash,
                    &key,
                    &nonces[d],
                    &s.nonce_tpm,
                    Direction::Encrypt,
                    params,
                ) {
                    self.last_plain_params = Some(plain_params.clone());
                }
            }
        }

        let mut auth_area = Vec::new();
        let mut slots = Vec::with_capacity(plans.len());
        for (i, plan) in plans.iter().enumerate() {
            let req = &reqs[i];
            match *plan {
                Plan::Password => {
                    marshal_auth_command(
                        &mut auth_area,
                        &AuthCommand {
                            handle: RS_PW,
                            nonce: Vec::new(),
                            attrs: ATTR_CONTINUE,
                            hmac: req.auth.to_vec(),
                        },
                    );
                    slots.push(Slot::Password);
                }
                Plan::Raw(bytes) => {
                    auth_area.extend_from_slice(bytes);
                    slots.push(Slot::Raw);
                }
                Plan::Session(k, attrs, corrupt) => {
                    let s = &self.sessions[k];
                    let is_assoc = associated(i);
                    let entity_auth = _common::strip_trailing_zeros(req.auth).to_vec();
                    let include_auth = is_assoc
                        && if s.is_policy() {
                            s.policy_auth_value || s.policy_password
                        } else {
                            !s.bind.as_ref().is_some_and(|b| {
                                cmd.names.get(i) == Some(&b.name) && b.auth == entity_auth
                            })
                        };
                    let password_mode = is_assoc && s.is_policy() && s.policy_password;
                    let mut mac = if password_mode {
                        req.auth.to_vec()
                    } else if let Some(sk) = &s.session_key {
                        let key = if include_auth {
                            [sk.as_slice(), &entity_auth].concat()
                        } else {
                            sk.clone()
                        };
                        if key.is_empty() {
                            // A null HMAC: valid for an empty key.
                            Vec::new()
                        } else {
                            let cp = cp_hash(s.auth_hash, cmd.code, cmd.names, params);
                            let mut extra_nonces: Vec<&[u8]> = Vec::new();
                            if i == 0 && is_assoc {
                                if let Some(d) = decrypt_slot
                                    && d != 0
                                    && let Plan::Session(dk, ..) = plans[d]
                                {
                                    extra_nonces.push(&self.sessions[dk].nonce_tpm);
                                }
                                if let Some(e) = encrypt_slot
                                    && e != 0
                                    && Some(e) != decrypt_slot
                                    && let Plan::Session(ek, ..) = plans[e]
                                {
                                    extra_nonces.push(&self.sessions[ek].nonce_tpm);
                                }
                            }
                            let attr_byte = [attrs];
                            let mut parts: Vec<&[u8]> = vec![&cp, &nonces[i], &s.nonce_tpm];
                            parts.extend(extra_nonces);
                            parts.push(&attr_byte);
                            hmac(s.auth_hash, &key, &parts)
                        }
                    } else {
                        // Salted session: the key is unknown, send a
                        // deterministic (wrong) HMAC.
                        derive_bytes(
                            s.handle as u64 ^ cmd.round as u64,
                            s.auth_hash.digest_size(),
                        )
                    };
                    if corrupt {
                        if mac.is_empty() {
                            mac.push(0x01);
                        } else {
                            let bit = derive_bytes(cmd.round as u64 ^ (i as u64) << 32, 2);
                            let bit =
                                u16::from_be_bytes([bit[0], bit[1]]) as usize % (mac.len() * 8);
                            mac[bit / 8] ^= 1 << (bit % 8);
                        }
                    }
                    if s.is_policy() {
                        self.stats.policy_built += 1;
                    } else {
                        self.stats.hmac_built += 1;
                        self.stats.hmac_corrupted += u64::from(corrupt);
                        self.stats.salted_built += u64::from(s.salted);
                    }
                    let built = Built {
                        handle: s.handle,
                        session_type: s.session_type,
                        nonce_caller: nonces[i].clone(),
                        hmac: mac,
                        associated: is_assoc,
                        include_auth,
                        entity_auth,
                        password_mode,
                        corrupted: corrupt,
                        salted: s.salted,
                    };
                    marshal_auth_command(
                        &mut auth_area,
                        &AuthCommand {
                            handle: built.handle,
                            nonce: built.nonce_caller.clone(),
                            attrs,
                            hmac: built.hmac.clone(),
                        },
                    );
                    slots.push(Slot::Built(built));
                }
            }
        }
        self.pending = Some(Pending {
            round: cmd.round,
            code: cmd.code,
            plain_params,
            auth_area: auth_area.clone(),
            slots,
            encrypt_slot,
        });
        auth_area
    }

    /// Processes the response of one round (call it for every round,
    /// including raw steps and rounds without sessions): creates, updates and
    /// drops sessions, and checks the response authorization area (see the
    /// module docs for the findings it panics with).
    ///
    /// `command` and `response` are the full bytes sent and received. Returns
    /// the decrypted response parameter area when an engine-built `encrypt`
    /// session decrypted it, or `None` (use the response bytes as they are).
    pub fn on_response(
        &mut self,
        cmd: &CommandInfo<'_>,
        command: &[u8],
        response: &[u8],
    ) -> Option<Vec<u8>> {
        let pending = self.pending.take();
        self.last_auth_failure = None;
        if pending.is_none() {
            self.last_plain_params = None;
        }
        let (_, rc) = parse_response_header(response)?;
        if rc != 0 {
            if let Some(p) = &pending
                && let Some(i) = auth_failure_session(rc)
                && let Some(Slot::Built(built)) = p.slots.get(i)
                && built.session_type == SessionType::Hmac
                && !built.corrupted
                && let Some(parsed) = parse_command(command)
                && parsed.auth_area == p.auth_area
            {
                self.stats.hmac_auth_failed += 1;
                self.last_auth_failure = Some(AuthFailure {
                    round: p.round,
                    code: p.code,
                    rc,
                    slot: i,
                    session: built.handle,
                    entity: built
                        .associated
                        .then(|| parsed.handles.get(i).copied())
                        .flatten(),
                    include_auth: built.include_auth,
                    entity_auth: built.entity_auth.clone(),
                });
            }
            return None;
        }
        let parsed = parse_command(command)?;
        // The checks only apply if the TPM saw exactly what `authorize` built.
        let pending = pending.filter(|p| {
            p.code == parsed.code
                && !p.slots.is_empty()
                && parsed.tag == ST_SESSIONS
                && p.auth_area == parsed.auth_area
                && parsed.sessions.len() == p.slots.len()
        });
        let session_count = parsed.sessions.len();
        let resp = match parse_response(response, parsed.code, session_count) {
            Ok(resp) => resp,
            Err(reason) => {
                if let Some(p) = &pending {
                    panic!(
                        "BAD_RESPONSE_AUTH[round{}:cc{:#x}:{reason}] success response to a \
                         command with {} session(s) is malformed: {}",
                        p.round,
                        p.code,
                        session_count,
                        hex(response)
                    );
                }
                return None;
            }
        };

        // Post-command authValue of the entity associated with slot 0 for
        // the commands that change or delete it (the response HMAC and
        // response encryption use the authValue after the command).
        let plain_cmd_params: &[u8] = pending
            .as_ref()
            .map_or(parsed.params, |p| p.plain_params.as_slice());
        let changed_auth: Option<Vec<u8>> = match parsed.code {
            CC_HIERARCHY_CHANGE_AUTH | CC_NV_CHANGE_AUTH | CC_PCR_SET_AUTH_VALUE => {
                Reader::new(plain_cmd_params)
                    .tpm2b()
                    .map(|a| _common::strip_trailing_zeros(a).to_vec())
            }
            CC_CLEAR if parsed.handles.first() == Some(&RH_LOCKOUT) => Some(Vec::new()),
            CC_NV_UNDEFINE_SPACE_SPECIAL => Some(Vec::new()),
            _ => None,
        };
        let auth_after = |i: usize, built: &Built| -> Vec<u8> {
            match &changed_auth {
                Some(a) if i == 0 => a.clone(),
                _ => built.entity_auth.clone(),
            }
        };

        let mut decrypted = None;
        if let Some(p) = &pending {
            // 1. Verify the response HMACs (pre-command session state).
            for (i, slot) in p.slots.iter().enumerate() {
                let Slot::Built(built) = slot else { continue };
                if built.session_type == SessionType::Hmac {
                    self.stats.hmac_succeeded += 1;
                    self.stats.salted_succeeded += u64::from(built.salted);
                } else {
                    self.stats.policy_succeeded += 1;
                }
                if built.corrupted {
                    panic!(
                        "ACCEPTED_CORRUPT_HMAC[round{}:cc{:#x}:slot{i}:{:#010x}] a command with a \
                         corrupted HMAC succeeded: command {} response {}",
                        p.round,
                        p.code,
                        built.handle,
                        hex(command),
                        hex(response)
                    );
                }
                let Some(s) = self.session(built.handle) else {
                    continue;
                };
                let Some(sk) = s.session_key.clone() else {
                    continue;
                };
                let ra = &resp.auths[i];
                let expected = if built.password_mode {
                    Vec::new()
                } else {
                    let key = if built.include_auth {
                        [sk.as_slice(), &auth_after(i, built)].concat()
                    } else {
                        sk
                    };
                    if key.is_empty() && built.hmac.is_empty() {
                        Vec::new()
                    } else {
                        let rp = rp_hash(s.auth_hash, 0, parsed.code, resp.params);
                        hmac(
                            s.auth_hash,
                            &key,
                            &[&rp, &ra.nonce, &built.nonce_caller, &[ra.attrs]],
                        )
                    }
                };
                if expected != ra.hmac {
                    panic!(
                        "BAD_RESPONSE_HMAC[round{}:cc{:#x}:slot{i}:{:#010x}] expected {} got {} \
                         (include_auth={}, associated={}, password_mode={}): command {} response {}",
                        p.round,
                        p.code,
                        built.handle,
                        hex(&expected),
                        hex(&ra.hmac),
                        built.include_auth,
                        built.associated,
                        built.password_mode,
                        hex(command),
                        hex(response)
                    );
                }
                self.stats.responses_verified += 1;
            }
            // 2. Decrypt the response parameters of an encrypt session.
            if let Some(e) = p.encrypt_slot
                && let Slot::Built(built) = &p.slots[e]
                && let Some(s) = self.session(built.handle)
                && let Some(sk) = &s.session_key
                && !resp.params.is_empty()
            {
                let extra = if built.associated {
                    auth_after(e, built)
                } else {
                    Vec::new()
                };
                let key = [sk.as_slice(), &extra].concat();
                let mut params = resp.params.to_vec();
                if apply_param_cipher(
                    s.cipher,
                    s.auth_hash,
                    &key,
                    &resp.auths[e].nonce,
                    &built.nonce_caller,
                    Direction::Decrypt,
                    &mut params,
                ) {
                    decrypted = Some(params);
                }
            }
        }

        // 3. Command effects.
        let plain_rsp_params = decrypted.as_deref().unwrap_or(resp.params);
        self.apply_command_effects(cmd, &parsed, plain_cmd_params, &resp, plain_rsp_params);

        // 4. Roll the nonces, reset used policy sessions, drop closed ones.
        for (i, auth) in parsed.sessions.iter().enumerate() {
            if auth.handle == RS_PW {
                continue;
            }
            let Some(pos) = self.sessions.iter().position(|s| s.handle == auth.handle) else {
                continue;
            };
            if auth.attrs & ATTR_CONTINUE == 0 {
                self.sessions.remove(pos);
                continue;
            }
            let s = &mut self.sessions[pos];
            s.nonce_tpm = resp.auths[i].nonce.clone();
            s.nonce_caller = auth.nonce.clone();
            if s.is_policy() {
                s.policy_auth_value = false;
                s.policy_password = false;
            }
        }
        decrypted
    }

    /// Applies the session-relevant effects of a successful command: session
    /// creation (`TPM2_StartAuthSession`), flushing (`TPM2_FlushContext`) and
    /// the policy flags.
    fn apply_command_effects(
        &mut self,
        cmd: &CommandInfo<'_>,
        parsed: &ParsedCommand<'_>,
        cmd_params: &[u8],
        resp: &ParsedResponse<'_>,
        rsp_params: &[u8],
    ) {
        match parsed.code {
            CC_START_AUTH_SESSION => {
                let salt = self.pending_salt.take();
                if let Some(session) =
                    Self::new_session(cmd, parsed, cmd_params, resp, rsp_params, salt.as_ref())
                {
                    self.stats.salted_started += u64::from(session.salted);
                    self.sessions.retain(|s| s.handle != session.handle);
                    self.sessions.push(session);
                }
            }
            CC_FLUSH_CONTEXT => {
                if let Some(handle) = Reader::new(cmd_params).u32() {
                    self.sessions.retain(|s| s.handle != handle);
                    self.publics.retain(|(h, _)| *h != handle);
                }
            }
            CC_CREATE_PRIMARY | CC_READ_PUBLIC => {
                // The first response parameter is the TPM2B_PUBLIC.
                let handle = if parsed.code == CC_READ_PUBLIC {
                    parsed.handles.first()
                } else {
                    resp.handles.first()
                };
                if let Some(&handle) = handle
                    && let Some(public) = Reader::new(rsp_params).tpm2b()
                {
                    self.record_public(handle, public);
                }
            }
            CC_CREATE_LOADED => {
                let mut r = Reader::new(rsp_params);
                if let Some(&handle) = resp.handles.first()
                    && r.tpm2b().is_some()
                    && let Some(public) = r.tpm2b()
                {
                    self.record_public(handle, public);
                }
            }
            CC_LOAD | CC_LOAD_EXTERNAL => {
                // inPrivate, then inPublic.
                let mut r = Reader::new(cmd_params);
                if let Some(&handle) = resp.handles.first()
                    && r.tpm2b().is_some()
                    && let Some(public) = r.tpm2b()
                {
                    self.record_public(handle, public);
                }
            }
            CC_EVICT_CONTROL => {
                if let Some(&object) = parsed.handles.get(1)
                    && let Some(persistent) = Reader::new(cmd_params).u32()
                {
                    if object >> 24 == 0x81 {
                        self.publics.retain(|(h, _)| *h != object);
                    } else if let Some(public) = self.public_of(object).map(<[u8]>::to_vec) {
                        self.record_public(persistent, &public);
                    }
                }
            }
            CC_POLICY_AUTH_VALUE | CC_POLICY_PASSWORD | CC_POLICY_RESTART => {
                let Some(&handle) = parsed.handles.first() else {
                    return;
                };
                if let Some(s) = self.sessions.iter_mut().find(|s| s.handle == handle) {
                    match parsed.code {
                        CC_POLICY_AUTH_VALUE => s.policy_auth_value = true,
                        CC_POLICY_PASSWORD => s.policy_password = true,
                        _ => {
                            s.policy_auth_value = false;
                            s.policy_password = false;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Builds the client state of the session a successful
    /// `TPM2_StartAuthSession` created, or `None` if the command or response
    /// does not parse.
    fn new_session(
        cmd: &CommandInfo<'_>,
        parsed: &ParsedCommand<'_>,
        cmd_params: &[u8],
        resp: &ParsedResponse<'_>,
        rsp_params: &[u8],
        salt: Option<&GeneratedSalt>,
    ) -> Option<Session> {
        let tpm_key = *parsed.handles.first()?;
        let bind = *parsed.handles.get(1)?;
        let mut r = Reader::new(cmd_params);
        let nonce_caller = r.tpm2b()?.to_vec();
        let encrypted_salt = r.tpm2b()?;
        let session_type = match r.u8()? {
            SE_HMAC => SessionType::Hmac,
            SE_POLICY => SessionType::Policy,
            SE_TRIAL => SessionType::Trial,
            _ => return None,
        };
        let sym_alg = r.u16()?;
        let (key_bits, mode) = match sym_alg {
            ALG_NULL => (0, ALG_NULL),
            ALG_XOR => (r.u16()?, ALG_NULL),
            _ => (r.u16()?, r.u16()?),
        };
        let auth_hash = TpmiAlgHash::try_from(r.u16()?).ok()?;
        let handle = *resp.handles.first()?;
        let nonce_tpm = Reader::new(rsp_params).tpm2b()?.to_vec();
        let bind_auth = cmd
            .handle_auths
            .get(1)
            .map(|a| _common::strip_trailing_zeros(a).to_vec())
            .unwrap_or_default();
        // A salted session's key is known only if the engine generated the
        // salt (`prepare_params`) and the TPM received exactly that
        // encrypted salt.
        let salt: Option<&[u8]> = if tpm_key == RH_NULL {
            Some(&[])
        } else {
            salt.filter(|s| s.encrypted == encrypted_salt)
                .map(|s| s.salt.as_slice())
        };
        let session_key = salt.map(|salt| {
            session_key(
                auth_hash,
                (bind != RH_NULL).then_some(bind_auth.as_slice()),
                salt,
                &nonce_tpm,
                &nonce_caller,
            )
        });
        let bound = (session_type == SessionType::Hmac && bind != RH_NULL).then(|| BoundEntity {
            name: cmd
                .names
                .get(1)
                .cloned()
                .unwrap_or_else(|| bind.to_be_bytes().to_vec()),
            auth: bind_auth.clone(),
        });
        let salted = tpm_key != RH_NULL && session_key.is_some();
        Some(Session {
            handle,
            session_type,
            auth_hash,
            nonce_tpm,
            nonce_caller,
            session_key,
            bind: bound,
            cipher: param_cipher(sym_alg, key_bits, mode),
            policy_auth_value: false,
            policy_password: false,
            started_round: cmd.round,
            salted,
        })
    }
}

/// Lowercase hex of `bytes` (finding messages).
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests;
