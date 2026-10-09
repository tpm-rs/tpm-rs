//! Byte-level command builders used by the `sessions` findings tests.
//!
//! Commands are assembled by hand so that tests can control every field of the header, the
//! handle area and the authorization area. Session HMACs (and the response HMACs) are computed
//! on the client side with [`CLIENT_CRYPTO`]; the simulator is only reached through its command
//! interface.

use crate::test_utils::{CLIENT_CRYPTO, entity_name, marshal_to_vec, start_auth_session};
use tpm2::crypto::Rng;
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEccParameter, Tpm2bSensitiveData,
    TpmEccCurve, TpmSe, TpmaObject, TpmiAlgHash, TpmsEccParms, TpmsEccPoint, TpmsSensitiveCreate,
    TpmtEccScheme, TpmtPublic, TpmtSymDefObject,
};

pub type Sim = tpm2_simulator::Simulator<'static>;

pub const ST_NO_SESSIONS: u16 = 0x8001;
pub const ST_SESSIONS: u16 = 0x8002;

pub const RH_OWNER: u32 = 0x4000_0001;
pub const RH_NULL: u32 = 0x4000_0007;
pub const RS_PW: u32 = 0x4000_0009;

pub const ALG_SHA256: u16 = 0x000B;

pub const CC_NV_DEFINE_SPACE: u32 = 0x12A;
pub const CC_HIERARCHY_CHANGE_AUTH: u32 = 0x129;
pub const CC_SET_PRIMARY_POLICY: u32 = 0x12E;
pub const CC_CREATE_PRIMARY: u32 = 0x131;
pub const CC_OBJECT_CHANGE_AUTH: u32 = 0x150;
pub const CC_POLICY_SECRET: u32 = 0x151;
pub const CC_ENCRYPT_DECRYPT: u32 = 0x164;
pub const CC_FLUSH_CONTEXT: u32 = 0x165;
pub const CC_LOAD_EXTERNAL: u32 = 0x167;
pub const CC_POLICY_AUTH_VALUE: u32 = 0x16B;
pub const CC_POLICY_COMMAND_CODE: u32 = 0x16C;
pub const CC_POLICY_CP_HASH: u32 = 0x16E;
pub const CC_POLICY_LOCALITY: u32 = 0x16F;
pub const CC_READ_PUBLIC: u32 = 0x173;
pub const CC_GET_RANDOM: u32 = 0x17B;
pub const CC_POLICY_RESTART: u32 = 0x180;
pub const CC_HASH_SEQUENCE_START: u32 = 0x186;
pub const CC_POLICY_GET_DIGEST: u32 = 0x189;
pub const CC_POLICY_PASSWORD: u32 = 0x18C;
pub const CC_POLICY_NV_WRITTEN: u32 = 0x18F;

pub const ATTR_CONT: u8 = 0x01;
pub const ATTR_AUDIT_EXCLUSIVE: u8 = 0x02;
pub const ATTR_DECRYPT: u8 = 0x20;
pub const ATTR_ENCRYPT: u8 = 0x40;
pub const ATTR_AUDIT: u8 = 0x80;

pub const RC_BAD_TAG: u32 = 0x01E;
pub const RC_ATTRIBUTES: u32 = 0x082;
pub const RC_MODE: u32 = 0x089;
pub const RC_HANDLE: u32 = 0x08B;
pub const RC_AUTH_FAIL: u32 = 0x08E;
pub const RC_NONCE: u32 = 0x08F;
pub const RC_SIZE: u32 = 0x095;
pub const RC_SYMMETRIC: u32 = 0x096;
pub const RC_INSUFFICIENT: u32 = 0x09A;
pub const RC_POLICY_FAIL: u32 = 0x09D;
pub const RC_BAD_AUTH: u32 = 0x0A2;
pub const RC_EXPIRED: u32 = 0x0A3;
pub const RC_POLICY_CC: u32 = 0x0A4;
pub const RC_AUTH_UNAVAILABLE: u32 = 0x12F;
pub const RC_COMMAND_SIZE: u32 = 0x142;
pub const RC_REFERENCE_H0: u32 = 0x910;
pub const RC_REFERENCE_S0: u32 = 0x918;

/// Adds the `TPM_RC_S + TPM_RC_1` position (first session) to a format-one response code.
pub fn rc_s1(rc: u32) -> u32 {
    rc | 0x900
}

/// Creates a powered-on, started simulator.
pub fn new_sim() -> Sim {
    tpm2_simulator::create_simulator!()
}

/// Sends raw command bytes and returns the raw response.
pub fn transact(sim: &mut Sim, cmd: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 8192];
    sim.transact(cmd, &mut buf).unwrap().to_vec()
}

/// Returns the response code of a raw response.
pub fn rc_of(resp: &[u8]) -> u32 {
    u32::from_be_bytes(resp[6..10].try_into().unwrap())
}

/// Builds a command: header (with a correct `commandSize`), handles, optional authorization area
/// (prefixed by its size) and parameters.
pub fn build(tag: u16, cc: u32, handles: &[u32], auth: Option<&[u8]>, params: &[u8]) -> Vec<u8> {
    let mut cmd = Vec::new();
    cmd.extend_from_slice(&tag.to_be_bytes());
    cmd.extend_from_slice(&0u32.to_be_bytes());
    cmd.extend_from_slice(&cc.to_be_bytes());
    for h in handles {
        cmd.extend_from_slice(&h.to_be_bytes());
    }
    if let Some(auth) = auth {
        cmd.extend_from_slice(&(auth.len() as u32).to_be_bytes());
        cmd.extend_from_slice(auth);
    }
    cmd.extend_from_slice(params);
    let size = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&size.to_be_bytes());
    cmd
}

/// Client-side state of an (unbound, unsalted, SHA-256) session.
#[derive(Clone, Debug)]
pub struct Sess {
    pub handle: u32,
    pub nonce_tpm: Vec<u8>,
    pub session_key: Vec<u8>,
}

/// Starts an unbound, unsalted SHA-256 session, optionally with AES-128-CFB parameter encryption.
pub fn start_session(sim: &mut Sim, session_type: TpmSe, aes: bool) -> Sess {
    let symmetric = aes.then(|| TpmtSymDefObject::aes_cfb(128).unwrap());
    let s = start_auth_session(
        sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        session_type,
        symmetric,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    Sess {
        handle: s.session_handle.0,
        nonce_tpm: s.nonce_tpm.get_buffer().to_vec(),
        session_key: s.session_key,
    }
}

/// One entry of the authorization area.
pub struct SessUse<'a> {
    sess: Option<&'a mut Sess>,
    attrs: u8,
    /// Bytes appended to the session key to form the HMAC key (the entity authValue, if the
    /// session includes it).
    key_auth: Vec<u8>,
    /// Plaintext sent in the `hmac` field (password sessions and `PolicyPassword` sessions).
    password: Option<Vec<u8>>,
    nonce: Vec<u8>,
    bad_hmac: bool,
}

impl<'a> SessUse<'a> {
    /// A password (`TPM_RS_PW`) session.
    pub fn pw(password: &[u8]) -> Self {
        Self {
            sess: None,
            attrs: ATTR_CONT,
            key_auth: Vec::new(),
            password: Some(password.to_vec()),
            nonce: Vec::new(),
            bad_hmac: false,
        }
    }

    /// An HMAC or policy session authorized with a correct HMAC.
    pub fn hmac(sess: &'a mut Sess, attrs: u8, key_auth: &[u8]) -> Self {
        Self {
            sess: Some(sess),
            attrs,
            key_auth: key_auth.to_vec(),
            password: None,
            nonce: Vec::new(),
            bad_hmac: false,
        }
    }

    /// A policy session on which `TPM2_PolicyPassword` was run: the `hmac` field carries the
    /// plaintext password.
    pub fn policy_password(sess: &'a mut Sess, password: &[u8]) -> Self {
        Self {
            sess: Some(sess),
            attrs: ATTR_CONT,
            key_auth: password.to_vec(),
            password: Some(password.to_vec()),
            nonce: Vec::new(),
            bad_hmac: false,
        }
    }

    /// Corrupts the HMAC.
    pub fn bad_hmac(mut self) -> Self {
        self.bad_hmac = true;
        self
    }

    /// Overrides the caller nonce (only meaningful for password sessions).
    pub fn with_nonce(mut self, nonce: &[u8]) -> Self {
        self.nonce = nonce.to_vec();
        self
    }

    /// Overrides the session attributes.
    pub fn with_attrs(mut self, attrs: u8) -> Self {
        self.attrs = attrs;
        self
    }
}

/// Parsed response of [`exec`].
#[derive(Debug, Default)]
pub struct Resp {
    pub rc: u32,
    pub raw: Vec<u8>,
    pub params: Vec<u8>,
    pub session_attrs: Vec<u8>,
    pub session_hmacs: Vec<Vec<u8>>,
    /// Whether every non-empty response HMAC matched the client-side computation.
    pub response_hmac_ok: bool,
}

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut ctx = tpm2::crypto::HashCtx::new(CLIENT_CRYPTO, TpmiAlgHash::Sha256).unwrap();
    for p in parts {
        ctx.update(p).unwrap();
    }
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    ctx.finalize(&mut out).unwrap().digest().to_vec()
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut ctx = tpm2::crypto::HmacCtx::new(CLIENT_CRYPTO, TpmiAlgHash::Sha256, key).unwrap();
    for p in parts {
        ctx.update(p).unwrap();
    }
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    ctx.finalize(&mut out).unwrap().digest().to_vec()
}

fn push_2b(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

fn read_2b(buf: &[u8], off: &mut usize) -> Vec<u8> {
    let len = u16::from_be_bytes([buf[*off], buf[*off + 1]]) as usize;
    let data = buf[*off + 2..*off + 2 + len].to_vec();
    *off += 2 + len;
    data
}

/// Executes a `TPM_ST_SESSIONS` command with the given sessions (parameters are sent as-is, no
/// client-side parameter encryption). On success, session nonces are rolled and the response
/// HMACs are checked. `resp_handles` is the number of handles in the response.
pub fn exec(
    sim: &mut Sim,
    cc: u32,
    handles: &[u32],
    uses: &mut [SessUse<'_>],
    params: &[u8],
    resp_handles: usize,
) -> Resp {
    let names: Vec<Vec<u8>> = handles
        .iter()
        .map(|&h| entity_name(sim, Handle(h)))
        .collect();
    let mut cp_parts: Vec<&[u8]> = Vec::new();
    let cc_bytes = cc.to_be_bytes();
    cp_parts.push(&cc_bytes);
    for n in &names {
        cp_parts.push(n);
    }
    cp_parts.push(params);
    let cp_hash = sha256(&cp_parts);

    let mut auth = Vec::new();
    let mut nonce_callers = Vec::new();
    for u in uses.iter() {
        match &u.sess {
            None => {
                auth.extend_from_slice(&RS_PW.to_be_bytes());
                push_2b(&mut auth, &u.nonce);
                auth.push(u.attrs);
                push_2b(&mut auth, u.password.as_deref().unwrap_or(&[]));
                nonce_callers.push(Vec::new());
            }
            Some(s) => {
                let mut nonce = [0u8; 16];
                CLIENT_CRYPTO.get_random(&mut nonce).unwrap();
                let hmac = if let Some(pw) = &u.password {
                    pw.clone()
                } else {
                    let key = [s.session_key.as_slice(), u.key_auth.as_slice()].concat();
                    let mut h = hmac_sha256(&key, &[&cp_hash, &nonce, &s.nonce_tpm, &[u.attrs]]);
                    if u.bad_hmac {
                        h[0] ^= 0xFF;
                    }
                    h
                };
                auth.extend_from_slice(&s.handle.to_be_bytes());
                push_2b(&mut auth, &nonce);
                auth.push(u.attrs);
                push_2b(&mut auth, &hmac);
                nonce_callers.push(nonce.to_vec());
            }
        }
    }

    let cmd = build(ST_SESSIONS, cc, handles, Some(&auth), params);
    let raw = transact(sim, &cmd);
    let rc = rc_of(&raw);
    let mut resp = Resp {
        rc,
        raw: raw.clone(),
        ..Default::default()
    };
    if rc != 0 {
        return resp;
    }
    let mut off = 10 + 4 * resp_handles;
    let param_size = u32::from_be_bytes(raw[off..off + 4].try_into().unwrap()) as usize;
    off += 4;
    resp.params = raw[off..off + param_size].to_vec();
    off += param_size;
    let rp_hash = sha256(&[&0u32.to_be_bytes(), &cc_bytes, &resp.params]);
    resp.response_hmac_ok = true;
    for (i, u) in uses.iter_mut().enumerate() {
        let nonce_tpm = read_2b(&raw, &mut off);
        let attrs = raw[off];
        off += 1;
        let hmac = read_2b(&raw, &mut off);
        if let Some(s) = u.sess.as_deref_mut() {
            if !hmac.is_empty() {
                let key = [s.session_key.as_slice(), u.key_auth.as_slice()].concat();
                let expected =
                    hmac_sha256(&key, &[&rp_hash, &nonce_tpm, &nonce_callers[i], &[attrs]]);
                resp.response_hmac_ok &= expected == hmac;
            }
            s.nonce_tpm = nonce_tpm;
        }
        resp.session_attrs.push(attrs);
        resp.session_hmacs.push(hmac);
    }
    resp
}

/// Runs a policy command without sessions (`policySession` is the only handle).
pub fn policy_cmd(sim: &mut Sim, cc: u32, session: u32, params: &[u8]) -> u32 {
    rc_of(&transact(
        sim,
        &build(ST_NO_SESSIONS, cc, &[session], None, params),
    ))
}

/// `TPM2_PolicyCommandCode(session, code)`.
pub fn policy_command_code(sim: &mut Sim, session: u32, code: u32) -> u32 {
    policy_cmd(sim, CC_POLICY_COMMAND_CODE, session, &code.to_be_bytes())
}

/// `TPM2_PolicyGetDigest(session)`.
pub fn policy_get_digest(sim: &mut Sim, session: u32) -> Vec<u8> {
    let r = transact(
        sim,
        &build(ST_NO_SESSIONS, CC_POLICY_GET_DIGEST, &[session], None, &[]),
    );
    assert_eq!(rc_of(&r), 0, "TPM2_PolicyGetDigest failed");
    let mut off = 10;
    read_2b(&r, &mut off)
}

/// Parameters of `TPM2_PolicySecret` with empty cpHashA and policyRef.
pub fn policy_secret_params(nonce_tpm: &[u8], expiration: i32) -> Vec<u8> {
    let mut p = Vec::new();
    push_2b(&mut p, nonce_tpm);
    push_2b(&mut p, &[]);
    push_2b(&mut p, &[]);
    p.extend_from_slice(&expiration.to_be_bytes());
    p
}

/// `TPM2_PolicySecret(authHandle = TPM_RH_OWNER (empty password), session)`.
pub fn policy_secret(sim: &mut Sim, session: u32, nonce_tpm: &[u8], expiration: i32) -> u32 {
    exec(
        sim,
        CC_POLICY_SECRET,
        &[RH_OWNER, session],
        &mut [SessUse::pw(&[])],
        &policy_secret_params(nonce_tpm, expiration),
        0,
    )
    .rc
}

/// `TPM2_FlushContext(handle)`.
pub fn flush(sim: &mut Sim, handle: u32) {
    let cmd = build(
        ST_NO_SESSIONS,
        CC_FLUSH_CONTEXT,
        &[],
        None,
        &handle.to_be_bytes(),
    );
    let rc = rc_of(&transact(sim, &cmd));
    assert_eq!(rc, 0, "TPM2_FlushContext failed: {rc:#x}");
}

/// Computes a policy digest by running `f` on a fresh trial session.
pub fn trial_digest(sim: &mut Sim, f: impl FnOnce(&mut Sim, u32)) -> Vec<u8> {
    let t = start_session(sim, TpmSe::Trial, false);
    f(sim, t.handle);
    let digest = policy_get_digest(sim, t.handle);
    flush(sim, t.handle);
    digest
}

/// Parameters of `TPM2_SetPrimaryPolicy` with a SHA-256 policy.
pub fn set_primary_policy_params(digest: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    push_2b(&mut p, digest);
    p.extend_from_slice(&ALG_SHA256.to_be_bytes());
    p
}

/// Sets the owner hierarchy's SHA-256 authPolicy, authorizing with the owner password.
pub fn set_owner_policy(sim: &mut Sim, digest: &[u8], owner_password: &[u8]) {
    let rc = exec(
        sim,
        CC_SET_PRIMARY_POLICY,
        &[RH_OWNER],
        &mut [SessUse::pw(owner_password)],
        &set_primary_policy_params(digest),
        0,
    )
    .rc;
    assert_eq!(rc, 0, "TPM2_SetPrimaryPolicy failed: {rc:#x}");
}

/// Parameters of a `TPM2_CreatePrimary` for an unrestricted ECDSA P-256 signing key with an empty
/// authValue and authPolicy.
pub fn create_primary_params() -> Vec<u8> {
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let cmd = tpm2::commands::CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(pub_area),
        ..Default::default()
    };
    marshal_to_vec(&cmd)
}

/// Creates the key of [`create_primary_params`] under the owner hierarchy and returns its handle.
pub fn create_primary_ecc(sim: &mut Sim) -> u32 {
    let r = exec(
        sim,
        CC_CREATE_PRIMARY,
        &[RH_OWNER],
        &mut [SessUse::pw(&[])],
        &create_primary_params(),
        1,
    );
    assert_eq!(r.rc, 0, "TPM2_CreatePrimary failed: {:#x}", r.rc);
    u32::from_be_bytes(r.raw[10..14].try_into().unwrap())
}
