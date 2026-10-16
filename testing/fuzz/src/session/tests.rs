//! Tests of the session engine: pure tests of the parsing, key-derivation
//! and parameter-encryption helpers, cross-checks against the known-good
//! `_common` HMAC-session helpers, and live tests against a differential
//! [`Tpm`] (every command is also mirrored to the C references), where an
//! engine-authorized command must succeed and its response HMAC must verify.

use std::panic::{AssertUnwindSafe, catch_unwind};

use super::*;
use testing::_common::{ActiveSession, PolicyCalculator};
use testing::tpm::Tpm;
use tpm2::commands::HierarchyChangeAuth;
use tpm2::{Handle, Tpm2bAuth, Tpm2bNonce, TpmSe, TpmaSession};

/// `TPM_RH_OWNER`.
const RH_OWNER: u32 = 0x4000_0001;
/// `TPM_CC_CreatePrimary`.
const CC_CREATE_PRIMARY: u32 = 0x131;
/// `TPM_CC_Create`.
const CC_CREATE: u32 = 0x153;
/// `TPM_CC_NV_DefineSpace`.
const CC_NV_DEFINE_SPACE: u32 = 0x12A;
/// `TPM_CC_NV_Write`.
const CC_NV_WRITE: u32 = 0x137;
/// `TPM_CC_NV_Read`.
const CC_NV_READ: u32 = 0x14E;
/// `TPM_CC_PolicyCommandCode`.
const CC_POLICY_COMMAND_CODE: u32 = 0x16C;
/// `TPM_CC_GetRandom`.
const CC_GET_RANDOM: u32 = 0x17B;
/// `TPM_ALG_SHA1`.
const SHA1: u16 = 0x0004;
/// `TPM_ALG_SHA256`.
const SHA256: u16 = 0x000B;
/// `TPM_ALG_SHA384`.
const SHA384: u16 = 0x000C;
/// `TPM_ALG_SHA512`.
const SHA512: u16 = 0x000D;
/// `TPMT_SYM_DEF` of `TPM_ALG_NULL`.
const SYM_NULL: &[u8] = &[0x00, 0x10];
/// `TPMT_SYM_DEF` of AES-128-CFB.
const SYM_AES128_CFB: &[u8] = &[0x00, 0x06, 0x00, 0x80, 0x00, 0x43];
/// `TPMT_SYM_DEF` of AES-256-CFB.
const SYM_AES256_CFB: &[u8] = &[0x00, 0x06, 0x01, 0x00, 0x00, 0x43];
/// `TPMT_SYM_DEF` of XOR with SHA-256.
const SYM_XOR_SHA256: &[u8] = &[0x00, 0x0A, 0x00, 0x0B];
/// `TPMA_NV` of an ordinary index written and read with its authValue
/// (`AUTHWRITE | AUTHREAD | NO_DA`).
const NV_AUTH_RW: u32 = 0x0004 | 0x0004_0000 | 0x0200_0000;
/// `TPMA_NV` of an ordinary index written with a policy and read with its
/// authValue (`POLICYWRITE | AUTHREAD | NO_DA`).
const NV_POLICY_W: u32 = 0x0008 | 0x0004_0000 | 0x0200_0000;
/// Size of the test NV indices.
const NV_SIZE: u16 = 32;

/// The outcome of one round.
struct Outcome {
    /// The response code.
    rc: u32,
    /// The response bytes.
    response: Vec<u8>,
    /// The decrypted response parameters, if an encrypt session decrypted
    /// them.
    decrypted: Option<Vec<u8>>,
}

/// One conversation: a differential [`Tpm`] driven through the engine the
/// way the fuzz driver drives it.
struct Conv {
    /// The TPM (tpm-rs, mirrored to the C references).
    tpm: Tpm,
    /// The engine under test.
    engine: SessionEngine,
    /// The next round index.
    round: usize,
}

/// Builds command bytes; `auth` is the authorization area (`None` for
/// `TPM_ST_NO_SESSIONS`).
fn build_command(code: u32, handles: &[u32], auth: Option<&[u8]>, params: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let tag = if auth.is_some() {
        ST_SESSIONS
    } else {
        ST_NO_SESSIONS
    };
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&code.to_be_bytes());
    for h in handles {
        out.extend_from_slice(&h.to_be_bytes());
    }
    if let Some(auth) = auth {
        out.extend_from_slice(&(auth.len() as u32).to_be_bytes());
        out.extend_from_slice(auth);
    }
    out.extend_from_slice(params);
    let size = (out.len() as u32).to_be_bytes();
    out[2..6].copy_from_slice(&size);
    out
}

/// Returns `data` as a `TPM2B`.
fn tpm2b(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_tpm2b(&mut out, data);
    out
}

/// The response code of response bytes.
fn rc_of(response: &[u8]) -> u32 {
    parse_response_header(response).expect("response header").1
}

/// A request for the `session`-th HMAC session.
fn hmac_req<'a>(session: u8, auth: &'a [u8], attrs: u8) -> SessionRequest<'a> {
    SessionRequest {
        slot: 0,
        choice: SessionChoice::Hmac {
            session,
            attrs,
            corrupt_hmac: false,
        },
        auth,
    }
}

/// A request for the `session`-th policy session.
fn policy_req<'a>(session: u8, auth: &'a [u8], attrs: u8) -> SessionRequest<'a> {
    SessionRequest {
        slot: 0,
        choice: SessionChoice::Policy { session, attrs },
        auth,
    }
}

/// A password request.
fn password_req(auth: &[u8]) -> SessionRequest<'_> {
    SessionRequest {
        slot: 0,
        choice: SessionChoice::Password,
        auth,
    }
}

/// The `TPM2B_NV_PUBLIC` parameter of `TPM2_NV_DefineSpace`.
fn nv_public(index: u32, attributes: u32, policy: &[u8]) -> Vec<u8> {
    let mut public = Vec::new();
    public.extend_from_slice(&index.to_be_bytes());
    public.extend_from_slice(&SHA256.to_be_bytes());
    public.extend_from_slice(&attributes.to_be_bytes());
    put_tpm2b(&mut public, policy);
    public.extend_from_slice(&NV_SIZE.to_be_bytes());
    tpm2b(&public)
}

/// The `TPM2B_PUBLIC` of an ECC P-256 key: a restricted AES-128-CFB storage
/// key (`storage`) or an ECDSA-SHA256 signing key, both `userWithAuth`.
fn ecc_template(storage: bool) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&0x0023u16.to_be_bytes()); // TPM_ALG_ECC
    t.extend_from_slice(&SHA256.to_be_bytes());
    let attrs: u32 = if storage { 0x0003_0472 } else { 0x0004_0472 };
    t.extend_from_slice(&attrs.to_be_bytes());
    put_tpm2b(&mut t, &[]);
    if storage {
        t.extend_from_slice(SYM_AES128_CFB);
        t.extend_from_slice(&0x0010u16.to_be_bytes()); // scheme NULL
    } else {
        t.extend_from_slice(SYM_NULL);
        t.extend_from_slice(&0x0018u16.to_be_bytes()); // ECDSA
        t.extend_from_slice(&SHA256.to_be_bytes());
    }
    t.extend_from_slice(&0x0003u16.to_be_bytes()); // NIST P-256
    t.extend_from_slice(&0x0010u16.to_be_bytes()); // kdf NULL
    put_tpm2b(&mut t, &[]);
    put_tpm2b(&mut t, &[]);
    tpm2b(&t)
}

/// The parameters of `TPM2_CreatePrimary`/`TPM2_Create` for a key with
/// `user_auth`.
fn create_params(user_auth: &[u8], storage: bool) -> Vec<u8> {
    let mut sensitive = Vec::new();
    put_tpm2b(&mut sensitive, user_auth);
    put_tpm2b(&mut sensitive, &[]);
    let mut p = tpm2b(&sensitive);
    p.extend_from_slice(&ecc_template(storage));
    put_tpm2b(&mut p, &[]); // outsideInfo
    p.extend_from_slice(&0u32.to_be_bytes()); // creationPCR
    p
}

/// The parameters of `TPM2_NV_Write`.
fn nv_write_params(data: &[u8]) -> Vec<u8> {
    let mut p = tpm2b(data);
    p.extend_from_slice(&0u16.to_be_bytes());
    p
}

/// The parameters of `TPM2_NV_Read` (`size`, offset 0).
fn nv_read_params(size: u16) -> Vec<u8> {
    let mut p = size.to_be_bytes().to_vec();
    p.extend_from_slice(&0u16.to_be_bytes());
    p
}

/// The parameter area of a success response without response handles.
fn response_params(response: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(response);
    r.bytes(10).unwrap();
    let size = r.u32().unwrap() as usize;
    r.bytes(size).unwrap().to_vec()
}

/// A digest-sized test nonce.
fn test_nonce(alg: TpmiAlgHash) -> Vec<u8> {
    (0..alg.digest_size()).map(|i| 0x5A ^ i as u8).collect()
}

impl Conv {
    /// A fresh, started TPM and an empty engine.
    fn new() -> Self {
        Self {
            tpm: Tpm::new(),
            engine: SessionEngine::new(),
            round: 0,
        }
    }

    /// The cpHash Names of `handles`, queried like a TSS would.
    fn names(&mut self, handles: &[u32]) -> Vec<Vec<u8>> {
        handles
            .iter()
            .map(|&h| _common::entity_name(&mut self.tpm, Handle(h)))
            .collect()
    }

    /// The [`CommandInfo`] parts of a command.
    fn info_parts(
        &mut self,
        handles: &[u32],
        handle_auths: &[&[u8]],
    ) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let names = self.names(handles);
        let mut auths: Vec<Vec<u8>> = handle_auths.iter().map(|a| a.to_vec()).collect();
        auths.resize(handles.len(), Vec::new());
        (names, auths)
    }

    /// Runs one round: authorize (if `reqs` is not empty), send, process the
    /// response.
    fn send(
        &mut self,
        code: u32,
        handles: &[u32],
        handle_auths: &[&[u8]],
        params: &[u8],
        reqs: &[SessionRequest<'_>],
    ) -> Outcome {
        let (names, auths) = self.info_parts(handles, handle_auths);
        let info = CommandInfo {
            round: self.round,
            code,
            handles,
            names: &names,
            handle_auths: &auths,
        };
        let mut params = params.to_vec();
        self.engine.prepare_params(&info, &mut params);
        let auth = (!reqs.is_empty()).then(|| self.engine.authorize(&info, &mut params, reqs));
        let command = build_command(code, handles, auth.as_deref(), &params);
        let response = self.tpm.send_command(0, &command);
        let decrypted = self.engine.on_response(&info, &command, &response);
        self.round += 1;
        Outcome {
            rc: rc_of(&response),
            response,
            decrypted,
        }
    }

    /// Starts a session through the engine and returns its handle.
    fn start_session(
        &mut self,
        bind: u32,
        bind_auth: &[u8],
        session_type: u8,
        symmetric: &[u8],
        auth_hash: u16,
    ) -> u32 {
        let alg = TpmiAlgHash::try_from(auth_hash).unwrap();
        let mut params = tpm2b(&test_nonce(alg));
        put_tpm2b(&mut params, &[]);
        params.push(session_type);
        params.extend_from_slice(symmetric);
        params.extend_from_slice(&auth_hash.to_be_bytes());
        let before = self.engine.live_handles();
        let out = self.send(
            CC_START_AUTH_SESSION,
            &[RH_NULL, bind],
            &[&[], bind_auth],
            &params,
            &[],
        );
        assert_eq!(out.rc, 0, "StartAuthSession failed: {:#x}", out.rc);
        let after = self.engine.live_handles();
        assert_eq!(after.len(), before.len() + 1, "session not tracked");
        *after.last().unwrap()
    }

    /// Sets the authValue of `hierarchy` (whose current authValue is
    /// `old`) with a password session.
    fn set_hierarchy_auth(&mut self, hierarchy: u32, old: &[u8], new: &[u8]) {
        let out = self.send(
            CC_HIERARCHY_CHANGE_AUTH,
            &[hierarchy],
            &[old],
            &tpm2b(new),
            &[password_req(old)],
        );
        assert_eq!(out.rc, 0, "HierarchyChangeAuth failed: {:#x}", out.rc);
    }

    /// Defines NV index `index` (authValue `nv_auth`) with a password
    /// session for the owner (authValue `owner_auth`).
    fn define_nv(
        &mut self,
        index: u32,
        nv_auth: &[u8],
        attributes: u32,
        policy: &[u8],
        owner_auth: &[u8],
    ) {
        let mut params = tpm2b(nv_auth);
        params.extend_from_slice(&nv_public(index, attributes, policy));
        let out = self.send(
            CC_NV_DEFINE_SPACE,
            &[RH_OWNER],
            &[owner_auth],
            &params,
            &[password_req(owner_auth)],
        );
        assert_eq!(out.rc, 0, "NV_DefineSpace failed: {:#x}", out.rc);
    }

    /// The selector of live session `handle` among the sessions of its kind.
    fn selector(&self, handle: u32) -> u8 {
        let policy = self.engine.session(handle).unwrap().is_policy();
        self.engine
            .sessions()
            .iter()
            .filter(|s| s.is_policy() == policy)
            .position(|s| s.handle == handle)
            .unwrap() as u8
    }
}

// ---------------------------------------------------------------------------
// Pure tests
// ---------------------------------------------------------------------------

/// The session key is KDFa over the bind authValue and both nonces, and
/// empty for an unbound session; it matches `_common::kdfa_by_alg`.
#[test]
fn session_key_matches_common_kdfa() {
    let alg = TpmiAlgHash::Sha256;
    let (nt, nc) = (vec![1u8; 32], vec![2u8; 16]);
    assert!(session_key(alg, None, b"", &nt, &nc).is_empty());
    let mut expected = vec![0u8; 32];
    _common::kdfa_by_alg(
        CLIENT_CRYPTO,
        alg,
        b"auth",
        b"ATH",
        &nt,
        &nc,
        256,
        &mut expected,
    );
    assert_eq!(session_key(alg, Some(b"auth"), b"", &nt, &nc), expected);
    let sha1 = session_key(TpmiAlgHash::Sha1, Some(b"auth"), b"", &nt, &nc);
    assert_eq!(sha1.len(), 20);
}

/// The cpHash covers the command code, every Name and the parameters.
#[test]
fn cp_hash_covers_code_names_and_params() {
    let alg = TpmiAlgHash::Sha256;
    let names = vec![vec![0x40, 0, 0, 1], vec![0, 0x0B, 9, 9]];
    let base = cp_hash(alg, 0x12A, &names, b"params");
    let expected = _common::digest_parts(
        alg,
        &[&0x12Au32.to_be_bytes(), &names[0], &names[1], b"params"],
    );
    assert_eq!(base, expected);
    assert_ne!(base, cp_hash(alg, 0x12B, &names, b"params"));
    assert_ne!(base, cp_hash(alg, 0x12A, &names[..1], b"params"));
    assert_ne!(base, cp_hash(alg, 0x12A, &names, b"paramz"));
    assert_eq!(
        rp_hash(alg, 0, 0x12A, b"p"),
        _common::digest_parts(alg, &[&[0; 4], &0x12Au32.to_be_bytes(), b"p"])
    );
}

/// XOR and CFB parameter encryption round-trip, transform only the first
/// TPM2B's buffer, depend on the nonce order, and refuse malformed sizes.
#[test]
fn param_cipher_round_trips_and_keeps_the_size_prefix() {
    let alg = TpmiAlgHash::Sha256;
    let ciphers = [
        param_cipher(ALG_XOR, SHA256, 0),
        param_cipher(0x0006, 128, ALG_CFB),
        param_cipher(0x0006, 256, ALG_CFB),
    ];
    assert!(matches!(ciphers[1], ParamCipher::Cfb { key_bits: 128, .. }));
    for cipher in ciphers {
        let plain = [&[0u8, 5][..], b"hello", b"tail"].concat();
        let mut data = plain.clone();
        assert!(apply_param_cipher(
            cipher,
            alg,
            b"key",
            b"newer",
            b"older",
            Direction::Encrypt,
            &mut data
        ));
        assert_eq!(&data[..2], &plain[..2]);
        assert_eq!(&data[7..], b"tail");
        assert_ne!(&data[2..7], b"hello");
        let mut swapped = data.clone();
        apply_param_cipher(
            cipher,
            alg,
            b"key",
            b"older",
            b"newer",
            Direction::Decrypt,
            &mut swapped,
        );
        assert_ne!(swapped, plain, "nonce order must matter");
        assert!(apply_param_cipher(
            cipher,
            alg,
            b"key",
            b"newer",
            b"older",
            Direction::Decrypt,
            &mut data
        ));
        assert_eq!(data, plain);
        let mut short = vec![0u8, 9, 1];
        assert!(!apply_param_cipher(
            cipher,
            alg,
            b"key",
            b"n",
            b"o",
            Direction::Encrypt,
            &mut short
        ));
        assert_eq!(short, vec![0u8, 9, 1]);
    }
    let mut data = vec![0u8, 1, 7];
    assert!(!apply_param_cipher(
        ParamCipher::None,
        alg,
        b"k",
        b"n",
        b"o",
        Direction::Encrypt,
        &mut data
    ));
    assert_eq!(param_cipher(0x0006, 128, 0x0040), ParamCipher::Unsupported);
    assert_eq!(param_cipher(ALG_NULL, 0, 0), ParamCipher::None);
}

/// Derived nonces are deterministic, digest-sized and differ per slot,
/// handle and use.
#[test]
fn derived_nonces_are_deterministic_and_distinct() {
    let mut a = SessionEngine::new();
    let mut b = SessionEngine::new();
    let n1 = a.derive_nonce(3, 0, 0x0200_0000, 32);
    assert_eq!(n1, b.derive_nonce(3, 0, 0x0200_0000, 32));
    assert_eq!(n1.len(), 32);
    assert_ne!(n1, a.derive_nonce(3, 0, 0x0200_0000, 32));
    assert_ne!(
        b.derive_nonce(3, 1, 0x0200_0000, 32),
        a.derive_nonce(3, 1, 0x0200_0001, 32)
    );
    assert_eq!(derive_bytes(7, 20).len(), 20);
}

/// Command and response parsing: auth areas, missing or extra response
/// authorizations, and the sessions tag rules.
#[test]
fn parsing_detects_malformed_authorization_areas() {
    let mut area = Vec::new();
    let auth = AuthCommand {
        handle: 0x0200_0000,
        nonce: vec![1; 16],
        attrs: 1,
        hmac: vec![2; 32],
    };
    marshal_auth_command(&mut area, &auth);
    assert_eq!(parse_auth_area(&area), Some(vec![auth]));
    assert_eq!(parse_auth_area(&area[..area.len() - 1]), None);
    let command = build_command(CC_GET_RANDOM, &[], Some(&area), &[0, 8]);
    let parsed = parse_command(&command).unwrap();
    assert_eq!(parsed.sessions.len(), 1);
    assert_eq!(parsed.params, &[0, 8]);

    // GetRandom response with one session: header, paramSize, params, auth.
    let mut ok = vec![0x80, 0x02, 0, 0, 0, 0, 0, 0, 0, 0];
    ok.extend_from_slice(&4u32.to_be_bytes());
    ok.extend_from_slice(&[0, 2, 0xAA, 0xBB]);
    ok.extend_from_slice(&tpm2b(&[3; 16]));
    ok.push(1);
    ok.extend_from_slice(&tpm2b(&[4; 32]));
    let parsed = parse_response(&ok, CC_GET_RANDOM, 1).unwrap();
    assert_eq!(parsed.params, &[0, 2, 0xAA, 0xBB]);
    assert_eq!(parsed.auths[0].nonce, vec![3; 16]);
    assert!(parse_response(&ok, CC_GET_RANDOM, 2).is_err());
    assert!(parse_response(&ok[..ok.len() - 1], CC_GET_RANDOM, 1).is_err());
    let mut trailing = ok.clone();
    trailing.push(0);
    assert!(parse_response(&trailing, CC_GET_RANDOM, 1).is_err());
    assert!(parse_response(&ok, CC_GET_RANDOM, 0).is_err());
    let mut no_sessions = vec![0x80, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0xAA, 0xBB];
    assert!(parse_response(&no_sessions, CC_GET_RANDOM, 1).is_err());
    assert_eq!(
        parse_response(&no_sessions, CC_GET_RANDOM, 0)
            .unwrap()
            .params,
        &[0, 2, 0xAA, 0xBB]
    );
    no_sessions.truncate(4);
    assert!(parse_response_header(&no_sessions).is_none());
}

/// Without live sessions, HMAC and policy requests fall back to password
/// sessions; raw requests are copied verbatim.
#[test]
fn requests_without_sessions_fall_back_to_password() {
    let mut engine = SessionEngine::new();
    let info = CommandInfo {
        round: 0,
        code: CC_NV_DEFINE_SPACE,
        handles: &[RH_OWNER],
        names: &[RH_OWNER.to_be_bytes().to_vec()],
        handle_auths: &[Vec::new()],
    };
    let mut params = vec![0, 0];
    let area = engine.authorize(
        &info,
        &mut params,
        &[
            hmac_req(3, b"pw", 1),
            policy_req(0, b"pw", 1),
            SessionRequest {
                slot: 2,
                choice: SessionChoice::Raw(&[0xDE, 0xAD]),
                auth: &[],
            },
        ],
    );
    let mut expected = Vec::new();
    for _ in 0..2 {
        marshal_auth_command(
            &mut expected,
            &AuthCommand {
                handle: RS_PW,
                nonce: Vec::new(),
                attrs: ATTR_CONTINUE,
                hmac: b"pw".to_vec(),
            },
        );
    }
    expected.extend_from_slice(&[0xDE, 0xAD]);
    assert_eq!(area, expected);
    assert_eq!(engine.hmac_stats(), HmacStats::default());
}

// ---------------------------------------------------------------------------
// Live tests
// ---------------------------------------------------------------------------

/// An unbound HMAC session authorizes `TPM2_NV_DefineSpace` with the owner's
/// authValue for every session hash; the nonces roll and the response HMACs
/// verify on consecutive uses.
#[test]
fn hmac_session_authorizes_nv_define_space_with_every_hash() {
    for hash in [SHA1, SHA256, SHA384, SHA512] {
        let mut c = Conv::new();
        c.set_hierarchy_auth(RH_OWNER, b"", b"owner-secret");
        let h = c.start_session(RH_NULL, b"", SE_HMAC, SYM_NULL, hash);
        assert_eq!(c.engine.session(h).unwrap().session_key(), Some(&[][..]));
        for (i, index) in [0x0150_0001u32, 0x0150_0002].into_iter().enumerate() {
            let nonce_before = c.engine.nonce_tpm(h).unwrap().to_vec();
            let mut params = tpm2b(b"nv");
            params.extend_from_slice(&nv_public(index, NV_AUTH_RW, &[]));
            let out = c.send(
                CC_NV_DEFINE_SPACE,
                &[RH_OWNER],
                &[b"owner-secret"],
                &params,
                &[hmac_req(0, b"owner-secret", ATTR_CONTINUE)],
            );
            assert_eq!(out.rc, 0, "hash {hash:#x} use {i}: rc {:#x}", out.rc);
            assert_ne!(c.engine.nonce_tpm(h).unwrap(), nonce_before.as_slice());
        }
        let stats = c.engine.hmac_stats();
        assert_eq!(
            (
                stats.hmac_built,
                stats.hmac_succeeded,
                stats.responses_verified
            ),
            (2, 2, 2)
        );
    }
}

/// With the empty owner authValue and an unbound session the HMAC key is
/// empty: the engine sends a null HMAC, which the TPM accepts.
#[test]
fn empty_key_sends_null_hmac() {
    let mut c = Conv::new();
    c.start_session(RH_NULL, b"", SE_HMAC, SYM_NULL, SHA256);
    let mut params = tpm2b(b"");
    params.extend_from_slice(&nv_public(0x0150_0003, NV_AUTH_RW, &[]));
    let out = c.send(
        CC_NV_DEFINE_SPACE,
        &[RH_OWNER],
        &[b""],
        &params,
        &[hmac_req(0, b"", 1)],
    );
    assert_eq!(out.rc, 0);
    let parsed = parse_response(&out.response, CC_NV_DEFINE_SPACE, 1).unwrap();
    assert!(parsed.auths[0].hmac.is_empty());
}

/// A session bound to the owner omits the owner's authValue from the HMAC
/// key when authorizing the owner, but includes the authValue of another
/// entity (an NV index).
#[test]
fn bound_hmac_session_omits_only_the_bind_entity_auth() {
    let mut c = Conv::new();
    c.set_hierarchy_auth(RH_OWNER, b"", b"owner-secret");
    let h = c.start_session(RH_OWNER, b"owner-secret", SE_HMAC, SYM_NULL, SHA256);
    assert_eq!(
        c.engine.session(h).unwrap().session_key().unwrap().len(),
        32
    );
    let index = 0x0150_0004;
    let mut params = tpm2b(b"nv-auth");
    params.extend_from_slice(&nv_public(index, NV_AUTH_RW, &[]));
    let out = c.send(
        CC_NV_DEFINE_SPACE,
        &[RH_OWNER],
        &[b"owner-secret"],
        &params,
        &[hmac_req(0, b"owner-secret", 1)],
    );
    assert_eq!(out.rc, 0);
    let out = c.send(
        CC_NV_WRITE,
        &[index, index],
        &[b"nv-auth", b"nv-auth"],
        &nv_write_params(b"data"),
        &[hmac_req(0, b"nv-auth", 1)],
    );
    assert_eq!(out.rc, 0);
    assert_eq!(c.engine.hmac_stats().responses_verified, 2);
}

/// The bind authValue enters the session key without its trailing zeros (as
/// the TPM strips them), and authorizing with the zero-padded authValue
/// works.
#[test]
fn bind_auth_trailing_zeros_are_stripped() {
    let mut c = Conv::new();
    c.set_hierarchy_auth(RH_OWNER, b"", b"pad\0\0");
    c.start_session(RH_OWNER, b"pad\0\0", SE_HMAC, SYM_NULL, SHA256);
    // Bound to the owner: authorize a different entity (owner via
    // HierarchyChangeAuth is the bind entity, so use NV_DefineSpace with the
    // stripped auth, still bound).
    let mut params = tpm2b(b"");
    params.extend_from_slice(&nv_public(0x0150_0005, NV_AUTH_RW, &[]));
    let out = c.send(
        CC_NV_DEFINE_SPACE,
        &[RH_OWNER],
        &[b"pad"],
        &params,
        &[hmac_req(0, b"pad", 1)],
    );
    assert_eq!(out.rc, 0);
    // An unbound session includes the authValue (stripped) in the key.
    c.start_session(RH_NULL, b"", SE_HMAC, SYM_NULL, SHA256);
    let mut params = tpm2b(b"");
    params.extend_from_slice(&nv_public(0x0150_0006, NV_AUTH_RW, &[]));
    let out = c.send(
        CC_NV_DEFINE_SPACE,
        &[RH_OWNER],
        &[b"pad\0"],
        &params,
        &[hmac_req(1, b"pad\0", 1)],
    );
    assert_eq!(out.rc, 0);
}

/// An HMAC session authorizes `TPM2_Create` under a primary key with the
/// parent's userAuth (an object Name in the cpHash).
#[test]
fn hmac_session_authorizes_create_under_primary() {
    let mut c = Conv::new();
    let out = c.send(
        CC_CREATE_PRIMARY,
        &[RH_OWNER],
        &[b""],
        &create_params(b"parent-auth", true),
        &[password_req(b"")],
    );
    assert_eq!(out.rc, 0, "CreatePrimary: {:#x}", out.rc);
    let parent = u32::from_be_bytes(out.response[10..14].try_into().unwrap());
    c.start_session(RH_NULL, b"", SE_HMAC, SYM_AES128_CFB, SHA256);
    let out = c.send(
        CC_CREATE,
        &[parent],
        &[b"parent-auth"],
        &create_params(b"child", false),
        &[hmac_req(0, b"parent-auth", ATTR_CONTINUE | ATTR_ENCRYPT)],
    );
    assert_eq!(out.rc, 0, "Create: {:#x}", out.rc);
    // The encrypted outPrivate was decrypted, keeping its size.
    let raw = response_params(&out.response);
    let decrypted = out.decrypted.expect("encrypt session decrypts outPrivate");
    assert_eq!(decrypted.len(), raw.len());
    assert_ne!(decrypted, raw);
    // A wrong parent auth fails the HMAC check.
    let out = c.send(
        CC_CREATE,
        &[parent],
        &[b"wrong"],
        &create_params(b"child", false),
        &[hmac_req(0, b"wrong", 1)],
    );
    assert_ne!(out.rc, 0);
}

/// A policy session after `TPM2_PolicyAuthValue` includes the authValue in
/// the HMAC key; using it with continueSession resets the policy flags.
#[test]
fn policy_auth_value_session_authorizes_nv_write() {
    for password in [false, true] {
        let mut c = Conv::new();
        let mut calc = PolicyCalculator::new(TpmiAlgHash::Sha256);
        calc.policy_auth_value();
        let index = 0x0150_0007;
        c.define_nv(index, b"nv-auth", NV_POLICY_W, &calc.policy_digest, b"");
        let h = c.start_session(RH_NULL, b"", SE_POLICY, SYM_NULL, SHA256);
        let cc = if password {
            CC_POLICY_PASSWORD
        } else {
            CC_POLICY_AUTH_VALUE
        };
        assert_eq!(c.send(cc, &[h], &[], &[], &[]).rc, 0);
        assert_eq!(
            c.engine.session(h).unwrap().policy_flags(),
            (!password, password)
        );
        let out = c.send(
            CC_NV_WRITE,
            &[index, index],
            &[b"nv-auth", b"nv-auth"],
            &nv_write_params(b"policy"),
            &[policy_req(0, b"nv-auth", ATTR_CONTINUE)],
        );
        assert_eq!(out.rc, 0, "password={password}: rc {:#x}", out.rc);
        let parsed = parse_response(&out.response, CC_NV_WRITE, 1).unwrap();
        assert_eq!(parsed.auths[0].hmac.is_empty(), password);
        assert_eq!(c.engine.session(h).unwrap().policy_flags(), (false, false));
        assert_eq!(c.engine.hmac_stats().policy_succeeded, 1);
        // The reset policy no longer satisfies the index's policy.
        let out = c.send(
            CC_NV_WRITE,
            &[index, index],
            &[b"nv-auth", b"nv-auth"],
            &nv_write_params(b"x"),
            &[policy_req(0, b"nv-auth", 1)],
        );
        assert_ne!(out.rc, 0);
    }
}

/// A policy session bound to the owner has a non-empty session key, which
/// keys the HMAC even without `TPM2_PolicyAuthValue` (authValue excluded);
/// `TPM2_PolicyRestart` clears the flags.
#[test]
fn bound_policy_session_hmac_uses_session_key_only() {
    let mut c = Conv::new();
    c.set_hierarchy_auth(RH_OWNER, b"", b"owner-secret");
    let policy = _common::digest_parts(
        TpmiAlgHash::Sha256,
        &[
            &[0u8; 32],
            &CC_POLICY_COMMAND_CODE.to_be_bytes(),
            &CC_NV_WRITE.to_be_bytes(),
        ],
    );
    let index = 0x0150_0008;
    c.define_nv(index, b"nv-auth", NV_POLICY_W, &policy, b"owner-secret");
    let h = c.start_session(RH_OWNER, b"owner-secret", SE_POLICY, SYM_NULL, SHA256);
    assert!(
        !c.engine
            .session(h)
            .unwrap()
            .session_key()
            .unwrap()
            .is_empty()
    );
    assert_eq!(c.send(CC_POLICY_AUTH_VALUE, &[h], &[], &[], &[]).rc, 0);
    assert_eq!(c.send(CC_POLICY_RESTART, &[h], &[], &[], &[]).rc, 0);
    assert_eq!(c.engine.session(h).unwrap().policy_flags(), (false, false));
    let cc = CC_NV_WRITE.to_be_bytes();
    assert_eq!(c.send(CC_POLICY_COMMAND_CODE, &[h], &[], &cc, &[]).rc, 0);
    let out = c.send(
        CC_NV_WRITE,
        &[index, index],
        &[b"nv-auth", b"nv-auth"],
        &nv_write_params(b"cc-policy"),
        &[policy_req(0, b"nv-auth", ATTR_CONTINUE)],
    );
    assert_eq!(out.rc, 0, "rc {:#x}", out.rc);
    assert_eq!(c.engine.hmac_stats().responses_verified, 1);
}

/// A decrypt session (AES-CFB or XOR) encrypts the data of `TPM2_NV_Write`;
/// an encrypt session's response to `TPM2_NV_Read` is decrypted to the same
/// data. Covers bound and unbound sessions.
#[test]
fn parameter_encryption_round_trips_through_nv() {
    for (sym, bind) in [
        (SYM_AES128_CFB, RH_NULL),
        (SYM_AES256_CFB, RH_OWNER),
        (SYM_XOR_SHA256, RH_NULL),
        (SYM_XOR_SHA256, RH_OWNER),
    ] {
        let mut c = Conv::new();
        c.set_hierarchy_auth(RH_OWNER, b"", b"owner-secret");
        let index = 0x0150_0009;
        c.define_nv(index, b"nv-auth", NV_AUTH_RW, &[], b"owner-secret");
        c.start_session(bind, b"owner-secret", SE_HMAC, sym, SHA256);
        let data: Vec<u8> = (0..NV_SIZE as u8).collect();
        let out = c.send(
            CC_NV_WRITE,
            &[index, index],
            &[b"nv-auth", b"nv-auth"],
            &nv_write_params(&data),
            &[hmac_req(0, b"nv-auth", ATTR_CONTINUE | ATTR_DECRYPT)],
        );
        assert_eq!(out.rc, 0, "{sym:02x?}: write rc {:#x}", out.rc);
        assert_eq!(
            c.engine.plain_params(),
            Some(nv_write_params(&data).as_slice())
        );
        let out = c.send(
            CC_NV_READ,
            &[index, index],
            &[b"nv-auth", b"nv-auth"],
            &nv_read_params(NV_SIZE),
            &[password_req(b"nv-auth")],
        );
        assert_eq!(out.rc, 0);
        assert_eq!(
            response_params(&out.response),
            tpm2b(&data),
            "{sym:02x?}: plaintext written"
        );
        let out = c.send(
            CC_NV_READ,
            &[index, index],
            &[b"nv-auth", b"nv-auth"],
            &nv_read_params(NV_SIZE),
            &[hmac_req(0, b"nv-auth", ATTR_CONTINUE | ATTR_ENCRYPT)],
        );
        assert_eq!(out.rc, 0);
        assert_ne!(response_params(&out.response), tpm2b(&data));
        assert_eq!(
            out.decrypted,
            Some(tpm2b(&data)),
            "{sym:02x?}: decrypted read"
        );
    }
}

/// A second, non-authorization session with decrypt/encrypt: its nonceTPM
/// enters the first session's HMAC, its own HMAC is keyed by its session key
/// only, and it encrypts/decrypts the parameters.
#[test]
fn extra_encryption_session_nonce_enters_first_session_hmac() {
    let mut c = Conv::new();
    c.set_hierarchy_auth(RH_OWNER, b"", b"owner-secret");
    let index = 0x0150_000A;
    c.define_nv(index, b"nv-auth", NV_AUTH_RW, &[], b"owner-secret");
    let auth = c.start_session(RH_NULL, b"", SE_HMAC, SYM_NULL, SHA256);
    let enc = c.start_session(RH_OWNER, b"owner-secret", SE_HMAC, SYM_AES128_CFB, SHA256);
    let (a, e) = (c.selector(auth), c.selector(enc));
    let data = [0x42u8; NV_SIZE as usize];
    for attrs in [
        ATTR_CONTINUE | ATTR_DECRYPT,
        ATTR_CONTINUE | ATTR_DECRYPT | ATTR_AUDIT,
    ] {
        let out = c.send(
            CC_NV_WRITE,
            &[index, index],
            &[b"nv-auth", b"nv-auth"],
            &nv_write_params(&data),
            &[
                hmac_req(a, b"nv-auth", ATTR_CONTINUE),
                hmac_req(e, b"", attrs),
            ],
        );
        assert_eq!(out.rc, 0, "attrs {attrs:#x}: rc {:#x}", out.rc);
    }
    let out = c.send(
        CC_NV_READ,
        &[index, index],
        &[b"nv-auth", b"nv-auth"],
        &nv_read_params(NV_SIZE),
        &[
            hmac_req(a, b"nv-auth", ATTR_CONTINUE),
            hmac_req(e, b"", ATTR_CONTINUE | ATTR_ENCRYPT),
        ],
    );
    assert_eq!(out.rc, 0);
    assert_eq!(out.decrypted, Some(tpm2b(&data)));
    assert_eq!(c.engine.hmac_stats().responses_verified, 6);
}

/// A session used with continueSession clear is dropped; a flushed session
/// is dropped; a failed command neither rolls the nonce nor drops the
/// session.
#[test]
fn sessions_are_dropped_on_continue_clear_and_flush_only() {
    let mut c = Conv::new();
    c.set_hierarchy_auth(RH_OWNER, b"", b"owner-secret");
    let h1 = c.start_session(RH_NULL, b"", SE_HMAC, SYM_NULL, SHA256);
    let h2 = c.start_session(RH_NULL, b"", SE_HMAC, SYM_NULL, SHA256);
    // Failure: wrong auth.
    let nonce = c.engine.nonce_tpm(h1).unwrap().to_vec();
    let mut params = tpm2b(b"");
    params.extend_from_slice(&nv_public(0x0150_000B, NV_AUTH_RW, &[]));
    let out = c.send(
        CC_NV_DEFINE_SPACE,
        &[RH_OWNER],
        &[b"bad"],
        &params,
        &[hmac_req(0, b"bad", 0)],
    );
    assert_ne!(out.rc, 0);
    assert_eq!(c.engine.nonce_tpm(h1).unwrap(), nonce.as_slice());
    assert_eq!(c.engine.live_handles(), vec![h1, h2]);
    assert_eq!(
        c.engine.hmac_stats().hmac_auth_failed,
        1,
        "rc {:#x}",
        out.rc
    );
    // Success with continueSession clear drops the session.
    let out = c.send(
        CC_NV_DEFINE_SPACE,
        &[RH_OWNER],
        &[b"owner-secret"],
        &params,
        &[hmac_req(0, b"owner-secret", 0)],
    );
    assert_eq!(out.rc, 0);
    assert_eq!(c.engine.live_handles(), vec![h2]);
    // FlushContext drops the other one.
    let out = c.send(CC_FLUSH_CONTEXT, &[], &[], &h2.to_be_bytes(), &[]);
    assert_eq!(out.rc, 0);
    assert!(c.engine.live_handles().is_empty());
}

/// A corrupted HMAC is rejected, leaving the session usable; a corrupted
/// null HMAC (empty key) is rejected too.
#[test]
fn corrupted_hmac_is_rejected() {
    for owner_auth in [&b"owner-secret"[..], b""] {
        let mut c = Conv::new();
        if !owner_auth.is_empty() {
            c.set_hierarchy_auth(RH_OWNER, b"", owner_auth);
        }
        let h = c.start_session(RH_NULL, b"", SE_HMAC, SYM_NULL, SHA256);
        let mut params = tpm2b(b"");
        params.extend_from_slice(&nv_public(0x0150_000C, NV_AUTH_RW, &[]));
        let corrupt = SessionRequest {
            slot: 0,
            choice: SessionChoice::Hmac {
                session: 0,
                attrs: ATTR_CONTINUE,
                corrupt_hmac: true,
            },
            auth: owner_auth,
        };
        let out = c.send(
            CC_NV_DEFINE_SPACE,
            &[RH_OWNER],
            &[owner_auth],
            &params,
            &[corrupt],
        );
        assert_ne!(out.rc, 0, "corrupted HMAC accepted");
        assert_eq!(
            out.rc & 0xF00,
            0x900,
            "error must point at session 1: {:#x}",
            out.rc
        );
        let out = c.send(
            CC_NV_DEFINE_SPACE,
            &[RH_OWNER],
            &[owner_auth],
            &params,
            &[hmac_req(0, owner_auth, 1)],
        );
        assert_eq!(out.rc, 0);
        assert_eq!(c.engine.live_handles(), vec![h]);
        let stats = c.engine.hmac_stats();
        assert_eq!((stats.hmac_corrupted, stats.hmac_auth_failed), (1, 0));
    }
}

/// Only format-1 `TPM_RC_AUTH_FAIL`/`TPM_RC_BAD_AUTH` with a session number
/// count as authorization failures.
#[test]
fn auth_failures_are_attributed_to_sessions() {
    assert_eq!(auth_failure_session(0x98E), Some(0));
    assert_eq!(auth_failure_session(0xAA2), Some(1));
    assert_eq!(auth_failure_session(0x18E), None, "handle 1, not a session");
    assert_eq!(auth_failure_session(0x08E), None, "no index");
    assert_eq!(auth_failure_session(0x9C4), None, "parameter error");
    assert_eq!(auth_failure_session(0x99D), None, "policy failure");
    assert_eq!(auth_failure_session(0x921), None, "format 0 (lockout)");
    let mut total = HmacStats::default();
    let one = HmacStats {
        hmac_built: 2,
        hmac_auth_failed: 1,
        ..HmacStats::default()
    };
    total.add(&one);
    total.add(&one);
    assert_eq!((total.hmac_built, total.hmac_auth_failed), (4, 2));
}

/// Runs one HMAC-authorized `TPM2_NV_DefineSpace` by hand and returns the
/// engine state before `on_response`, the command info parts, command and
/// response.
fn manual_round(c: &mut Conv) -> (SessionEngine, Vec<Vec<u8>>, Vec<u8>, Vec<u8>) {
    let mut params = tpm2b(b"");
    params.extend_from_slice(&nv_public(0x0150_000D, NV_AUTH_RW, &[]));
    let names = c.names(&[RH_OWNER]);
    let auths = vec![b"owner-secret".to_vec()];
    let info = CommandInfo {
        round: c.round,
        code: CC_NV_DEFINE_SPACE,
        handles: &[RH_OWNER],
        names: &names,
        handle_auths: &auths,
    };
    let area = c
        .engine
        .authorize(&info, &mut params, &[hmac_req(0, b"owner-secret", 1)]);
    let command = build_command(CC_NV_DEFINE_SPACE, &[RH_OWNER], Some(&area), &params);
    let response = c.tpm.send_command(0, &command);
    assert_eq!(rc_of(&response), 0);
    (c.engine.clone(), names, command, response)
}

/// A response HMAC that does not verify is reported as
/// `BAD_RESPONSE_HMAC`; a success response with a missing authorization is
/// `BAD_RESPONSE_AUTH`; a success after a corrupted HMAC is
/// `ACCEPTED_CORRUPT_HMAC`. The genuine response passes.
#[test]
fn response_authorization_findings_panic_with_signatures() {
    let mut c = Conv::new();
    c.set_hierarchy_auth(RH_OWNER, b"", b"owner-secret");
    c.start_session(RH_NULL, b"", SE_HMAC, SYM_NULL, SHA256);
    let (engine, names, command, response) = manual_round(&mut c);
    let auths = vec![b"owner-secret".to_vec()];
    let info = CommandInfo {
        round: 7,
        code: CC_NV_DEFINE_SPACE,
        handles: &[RH_OWNER],
        names: &names,
        handle_auths: &auths,
    };
    let expect_panic = |mut engine: SessionEngine, response: Vec<u8>, signature: &str| {
        let err = catch_unwind(AssertUnwindSafe(|| {
            engine.on_response(&info, &command, &response);
        }))
        .expect_err("finding must panic");
        let msg = err.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(msg.starts_with(signature), "unexpected panic: {msg}");
    };
    let mut tampered = response.clone();
    *tampered.last_mut().unwrap() ^= 1;
    expect_panic(engine.clone(), tampered, "BAD_RESPONSE_HMAC[round");
    let mut truncated = response[..response.len() - 1].to_vec();
    let size = (truncated.len() as u32).to_be_bytes();
    truncated[2..6].copy_from_slice(&size);
    expect_panic(engine.clone(), truncated, "BAD_RESPONSE_AUTH[round");
    let mut corrupted = engine.clone();
    if let Some(Slot::Built(b)) = corrupted.pending.as_mut().unwrap().slots.first_mut() {
        b.corrupted = true;
    }
    expect_panic(corrupted, response.clone(), "ACCEPTED_CORRUPT_HMAC[round");
    let mut genuine = engine;
    genuine.on_response(&info, &command, &response);
    assert_eq!(genuine.hmac_stats().responses_verified, 1);
}

/// `TPM2_HierarchyChangeAuth` through an HMAC session: the response HMAC is
/// keyed with the new authValue; `TPM2_Clear` with lockout: with the emptied
/// lockout authValue.
#[test]
fn auth_changing_commands_verify_with_the_new_auth() {
    let mut c = Conv::new();
    c.set_hierarchy_auth(RH_OWNER, b"", b"old-owner");
    c.set_hierarchy_auth(RH_LOCKOUT, b"", b"lock");
    c.start_session(RH_NULL, b"", SE_HMAC, SYM_NULL, SHA256);
    let out = c.send(
        CC_HIERARCHY_CHANGE_AUTH,
        &[RH_OWNER],
        &[b"old-owner"],
        &tpm2b(b"new-owner"),
        &[hmac_req(0, b"old-owner", 1)],
    );
    assert_eq!(out.rc, 0);
    // The same with parameter encryption of the new authValue.
    c.start_session(RH_NULL, b"", SE_HMAC, SYM_AES128_CFB, SHA256);
    let out = c.send(
        CC_HIERARCHY_CHANGE_AUTH,
        &[RH_OWNER],
        &[b"new-owner"],
        &tpm2b(b"newer-owner"),
        &[hmac_req(1, b"new-owner", ATTR_CONTINUE | ATTR_DECRYPT)],
    );
    assert_eq!(out.rc, 0);
    let out = c.send(
        CC_CLEAR,
        &[RH_LOCKOUT],
        &[b"lock"],
        &[],
        &[hmac_req(0, b"lock", 1)],
    );
    assert_eq!(out.rc, 0, "Clear: {:#x}", out.rc);
    assert_eq!(c.engine.hmac_stats().responses_verified, 3);
}

/// The engine's session key agrees with `_common`: a session the engine
/// started authorizes a command through `_common::execute_with_hmac_sessions`
/// and, after that, through the engine again (with the nonces `_common`
/// rolled).
#[test]
fn engine_started_session_works_with_common_helpers() {
    let mut c = Conv::new();
    c.set_hierarchy_auth(RH_OWNER, b"", b"owner-secret");
    let h = c.start_session(RH_OWNER, b"owner-secret", SE_HMAC, SYM_NULL, SHA256);
    let s = c.engine.session(h).unwrap().clone();
    let mut active = ActiveSession {
        session_handle: Handle(h),
        nonce_caller: Tpm2bNonce::from_bytes(_common::leak_bytes(&s.nonce_caller)).unwrap(),
        nonce_tpm: Tpm2bNonce::from_bytes(_common::leak_bytes(&s.nonce_tpm)).unwrap(),
        session_key: s.session_key.clone().unwrap(),
        auth_hash: s.auth_hash,
        symmetric: None,
        attributes: TpmaSession::CONTINUE_SESSION,
        bind_auth: b"owner-secret".to_vec(),
        bind_entity: Handle(RH_OWNER),
        session_type: TpmSe::HMAC,
        policy_auth_value_needed: false,
        policy_password_needed: false,
    };
    let cmd = HierarchyChangeAuth {
        auth_handle: Handle(RH_OWNER),
        new_auth: Tpm2bAuth::from_bytes(b"common-new").unwrap(),
    };
    _common::execute_with_hmac_sessions(
        &mut c.tpm,
        &cmd,
        &[],
        std::slice::from_mut(&mut active),
        &[b"owner-secret"],
    )
    .expect("_common accepts the engine's session key");
    // Continue with the engine, adopting the nonces `_common` rolled. The
    // owner's authValue changed, so the session is no longer bound to it.
    let pos = c
        .engine
        .sessions
        .iter()
        .position(|s| s.handle == h)
        .unwrap();
    c.engine.sessions[pos].nonce_tpm = active.nonce_tpm.get_buffer().to_vec();
    let mut params = tpm2b(b"");
    params.extend_from_slice(&nv_public(0x0150_000E, NV_AUTH_RW, &[]));
    let out = c.send(
        CC_NV_DEFINE_SPACE,
        &[RH_OWNER],
        &[b"common-new"],
        &params,
        &[hmac_req(0, b"common-new", 1)],
    );
    assert_eq!(out.rc, 0, "rc {:#x}", out.rc);
}

/// A session `_common::start_auth_session` started (bound, SHA-384) is
/// usable by the engine once adopted with `_common`'s view of it.
#[test]
fn common_started_session_works_with_engine() {
    let mut c = Conv::new();
    c.set_hierarchy_auth(RH_OWNER, b"", b"owner-secret");
    let active = _common::start_auth_session(
        &mut c.tpm,
        Handle(RH_NULL),
        Handle(RH_OWNER),
        b"owner-secret",
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha384,
    )
    .expect("StartAuthSession");
    // The engine's KDFa agrees with `_common`'s.
    assert_eq!(
        session_key(
            TpmiAlgHash::Sha384,
            Some(b"owner-secret"),
            b"",
            active.nonce_tpm.get_buffer(),
            active.nonce_caller.get_buffer()
        ),
        active.session_key
    );
    c.engine.sessions.push(Session {
        handle: active.session_handle.0,
        session_type: SessionType::Hmac,
        auth_hash: active.auth_hash,
        nonce_tpm: active.nonce_tpm.get_buffer().to_vec(),
        nonce_caller: active.nonce_caller.get_buffer().to_vec(),
        session_key: Some(active.session_key.clone()),
        bind: Some(BoundEntity {
            name: RH_OWNER.to_be_bytes().to_vec(),
            auth: b"owner-secret".to_vec(),
        }),
        cipher: ParamCipher::None,
        policy_auth_value: false,
        policy_password: false,
        started_round: 0,
        salted: false,
    });
    for index in [0x0150_000F, 0x0150_0010] {
        let mut params = tpm2b(b"");
        params.extend_from_slice(&nv_public(index, NV_AUTH_RW, &[]));
        let out = c.send(
            CC_NV_DEFINE_SPACE,
            &[RH_OWNER],
            &[b"owner-secret"],
            &params,
            &[hmac_req(0, b"owner-secret", 1)],
        );
        assert_eq!(out.rc, 0, "rc {:#x}", out.rc);
    }
}

/// Raw slots and damaged authorization areas are tracked (nonces roll) but
/// never verified.
#[test]
fn raw_sessions_are_tracked_but_not_verified() {
    let mut c = Conv::new();
    let h = c.start_session(RH_NULL, b"", SE_HMAC, SYM_NULL, SHA256);
    // A raw HMAC-session entry with a null HMAC (empty key) and an audit
    // attribute on GetRandom (no authorization handle).
    let mut raw = Vec::new();
    marshal_auth_command(
        &mut raw,
        &AuthCommand {
            handle: h,
            nonce: vec![9; 32],
            attrs: ATTR_CONTINUE | ATTR_AUDIT,
            hmac: Vec::new(),
        },
    );
    let nonce = c.engine.nonce_tpm(h).unwrap().to_vec();
    let req = SessionRequest {
        slot: 0,
        choice: SessionChoice::Raw(&raw),
        auth: &[],
    };
    let out = c.send(CC_GET_RANDOM, &[], &[], &8u16.to_be_bytes(), &[req]);
    assert_eq!(out.rc, 0, "rc {:#x}", out.rc);
    assert_ne!(c.engine.nonce_tpm(h).unwrap(), nonce.as_slice());
    assert_eq!(c.engine.session(h).unwrap().nonce_caller(), &[9; 32]);
    assert_eq!(c.engine.hmac_stats().responses_verified, 0);
}

/// A transport-rejected round (`abort_pending`) forgets what `authorize`
/// built.
#[test]
fn engine_handles_aborted_rounds() {
    let mut c = Conv::new();
    c.start_session(RH_NULL, b"", SE_HMAC, SYM_NULL, SHA256);
    let info = CommandInfo {
        round: 0,
        code: CC_GET_RANDOM,
        handles: &[],
        names: &[],
        handle_auths: &[],
    };
    let mut params = vec![0, 8];
    c.engine.authorize(
        &info,
        &mut params,
        &[hmac_req(0, b"", ATTR_CONTINUE | ATTR_AUDIT)],
    );
    assert!(c.engine.pending.is_some());
    c.engine.abort_pending();
    assert!(c.engine.pending.is_none());
}

// ---------------------------------------------------------------------------
// Driver integration
// ---------------------------------------------------------------------------

/// A conversation of the fuzz model that uses HMAC sessions for an NV index
/// lifecycle (with parameter encryption) and a key hierarchy. Every round
/// must succeed through the driver (Names from its value pool, authValues
/// from `AuthSel::Entity`), so the engine/driver integration builds correct
/// HMACs. Seeds for the fuzz corpus can be written with
/// `TPM_FUZZ_SESSION_SEEDS=<dir>`.
fn hmac_conversations() -> Vec<(&'static str, crate::model::Conversation)> {
    use crate::model::{AuthSel, Cmd, Conversation, HandleOperand, Segment, SessionSel, Step};
    let hmac = |attrs: u8| SessionSel::Hmac {
        session: 0,
        auth: AuthSel::Entity,
        attrs,
        corrupt_hmac: false,
    };
    let cmd =
        |code: u32, handles: Vec<HandleOperand>, sessions: Vec<SessionSel>, params: Vec<u8>| {
            let mut c = Cmd::new(code);
            c.handles = handles;
            c.sessions = sessions;
            c.params = vec![Segment::Bytes(params)];
            Step::Cmd(c)
        };
    let start = |bind: u32, sym: &[u8]| {
        let mut params = tpm2b(&test_nonce(TpmiAlgHash::Sha256));
        put_tpm2b(&mut params, &[]);
        params.push(SE_HMAC);
        params.extend_from_slice(sym);
        params.extend_from_slice(&SHA256.to_be_bytes());
        cmd(
            CC_START_AUTH_SESSION,
            vec![HandleOperand::Raw(RH_NULL), HandleOperand::Raw(bind)],
            vec![],
            params,
        )
    };
    let owner = || vec![HandleOperand::Raw(RH_OWNER)];
    let nv = || vec![HandleOperand::Nv { back: 0 }, HandleOperand::Nv { back: 0 }];
    let set_owner_auth = cmd(
        CC_HIERARCHY_CHANGE_AUTH,
        owner(),
        vec![SessionSel::Password {
            auth: AuthSel::Empty,
        }],
        tpm2b(b"owner-secret"),
    );
    let mut define = tpm2b(b"nv-auth");
    define.extend_from_slice(&nv_public(0x0150_0020, NV_AUTH_RW, &[]));
    let nv_steps = vec![
        set_owner_auth.clone(),
        start(RH_NULL, SYM_AES128_CFB),
        cmd(
            CC_NV_DEFINE_SPACE,
            owner(),
            vec![hmac(ATTR_CONTINUE)],
            define,
        ),
        cmd(
            CC_NV_WRITE,
            nv(),
            vec![hmac(ATTR_CONTINUE | ATTR_DECRYPT)],
            nv_write_params(&[7; 32]),
        ),
        cmd(
            CC_NV_READ,
            nv(),
            vec![hmac(ATTR_CONTINUE | ATTR_ENCRYPT)],
            nv_read_params(NV_SIZE),
        ),
        cmd(
            CC_NV_READ,
            nv(),
            vec![hmac(ATTR_CONTINUE)],
            nv_read_params(8),
        ),
    ];
    let key_steps = vec![
        set_owner_auth,
        start(RH_OWNER, SYM_XOR_SHA256),
        cmd(
            CC_CREATE_PRIMARY,
            owner(),
            vec![hmac(ATTR_CONTINUE)],
            create_params(b"parent-auth", true),
        ),
        cmd(
            CC_CREATE,
            vec![HandleOperand::Response { back: 0 }],
            vec![hmac(ATTR_CONTINUE | ATTR_DECRYPT)],
            create_params(b"child-auth", false),
        ),
        cmd(
            CC_GET_RANDOM,
            vec![],
            vec![hmac(ATTR_CONTINUE | ATTR_AUDIT | ATTR_ENCRYPT)],
            16u16.to_be_bytes().to_vec(),
        ),
    ];
    vec![
        ("hmac_nv_lifecycle", Conversation { steps: nv_steps }),
        ("hmac_key_hierarchy", Conversation { steps: key_steps }),
    ]
}

/// Every round of the HMAC conversations succeeds through the driver, and
/// every engine-built HMAC authorization succeeds and verifies.
#[test]
fn driver_conversations_with_hmac_sessions_succeed() {
    use crate::driver::{Driver, RoundOutcome};
    let mut tpm = Tpm::new();
    for (i, (name, conv)) in hmac_conversations().into_iter().enumerate() {
        if i > 0 {
            tpm.reset();
        }
        if let Some(dir) = std::env::var_os("TPM_FUZZ_SESSION_SEEDS") {
            std::fs::write(std::path::Path::new(&dir).join(name), conv.to_bytes()).unwrap();
        }
        let mut driver = Driver::default();
        for (round, step) in conv.steps.iter().enumerate() {
            let outcome = driver
                .round(&mut tpm, step)
                .unwrap_or_else(|f| panic!("{name}: {}", f.report()));
            assert!(
                matches!(outcome, RoundOutcome::Executed(0)),
                "{name} round {round}: {outcome:?}"
            );
        }
        let stats = driver.sessions.hmac_stats();
        assert!(stats.hmac_built >= 3, "{name}: {stats:?}");
        assert_eq!(stats.hmac_built, stats.hmac_succeeded, "{name}: {stats:?}");
        assert_eq!(
            stats.hmac_built, stats.responses_verified,
            "{name}: {stats:?}"
        );
    }
}

/// Diagnostic (ignored; run with `TPM_FUZZ_SESSION_DIAG=<corpus dir>` and
/// `--ignored --nocapture`): replays every fuzz input in the directory and
/// classifies each HMAC slot the TPM rejected ([`AuthFailure`]) by whether
/// the input chose an authValue other than the entity's known one, the
/// entity's authValue is unknown, or neither (printed in full for review).
#[test]
#[ignore]
fn diagnose_rejected_hmac_slots() {
    use crate::driver::{Driver, FIXED_SEED};
    use crate::model::{AuthSel, Conversation, SessionSel, Step};
    use std::collections::BTreeMap;
    let Some(dir) = std::env::var_os("TPM_FUZZ_SESSION_DIAG") else {
        return;
    };
    let mut tpm = Tpm::with_seed(FIXED_SEED);
    let mut classes: BTreeMap<String, usize> = BTreeMap::new();
    let mut total = HmacStats::default();
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    paths.sort();
    // Optional deterministic byte mutations per input
    // (`TPM_FUZZ_SESSION_DIAG_MUTATIONS=<n>`), to sample rejections the way
    // the fuzzer produces them.
    let mutations: u64 = std::env::var("TPM_FUZZ_SESSION_DIAG_MUTATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut inputs: Vec<(String, Vec<u8>)> = Vec::new();
    for path in &paths {
        let bytes = std::fs::read(path).unwrap();
        for m in 0..=mutations {
            let mut variant = bytes.clone();
            if m > 0 && !variant.is_empty() {
                let checksum: u64 = bytes.iter().map(|&b| u64::from(b)).sum();
                let r = derive_bytes(m ^ ((variant.len() as u64) << 20) ^ (checksum << 36), 4);
                let pos = u16::from_be_bytes([r[0], r[1]]) as usize % variant.len();
                variant[pos] ^= r[2] | 1;
            }
            inputs.push((format!("{}#{m}", path.display()), variant));
        }
    }
    for (name, bytes) in inputs {
        let path = std::path::PathBuf::from(name);
        let conv = Conversation::from_bytes(&bytes);
        tpm.reset();
        let mut driver = Driver::default();
        for step in &conv.steps {
            if driver.round(&mut tpm, step).is_err() {
                break;
            }
            if std::env::var_os("TPM_FUZZ_SESSION_DIAG_VERBOSE").is_some() {
                eprintln!(
                    "  round {}: {step:?}\n    cmd {}\n    rsp {}",
                    driver.next_round() - 1,
                    hex(driver.last_command()),
                    hex(driver.last_response())
                );
            }
            let Some(failure) = driver.sessions.last_auth_failure().cloned() else {
                continue;
            };
            let Step::Cmd(cmd) = step else { continue };
            let sel = cmd.sessions.get(failure.slot);
            let known = failure
                .entity
                .and_then(|h| driver.pool.handle_auth(h))
                .map(|a| _common::strip_trailing_zeros(a).to_vec());
            let auth_sel = match sel {
                Some(SessionSel::Hmac { auth, .. }) => auth.clone(),
                _ => AuthSel::Empty,
            };
            let is_entity = matches!(auth_sel, AuthSel::Entity);
            let class = match (&known, failure.entity) {
                (_, None) => "unassociated (session key only)".to_string(),
                (Some(k), Some(_)) if *k != failure.entity_auth => {
                    format!(
                        "input chose a different authValue ({})",
                        if is_entity { "Entity?!" } else { "not Entity" }
                    )
                }
                (None, Some(_)) if !failure.entity_auth.is_empty() || !is_entity => {
                    "entity authValue unknown, input chose bytes".to_string()
                }
                (None, Some(_)) => "entity authValue unknown (Entity -> empty)".to_string(),
                (Some(_), Some(_)) => "authValue matches the known one".to_string(),
            };
            if class.starts_with("authValue matches")
                || class.starts_with("unassociated")
                || class.contains("?!")
            {
                let s = driver.sessions.session(failure.session);
                eprintln!(
                    "{} :: {class} :: {failure:x?} sel={sel:?} session_bound={:?} key_known={:?} cmd={}",
                    path.display(),
                    s.map(|s| s.bind.clone()),
                    s.map(|s| s.session_key.is_some()),
                    hex(driver.last_command())
                );
            }
            *classes.entry(class).or_default() += 1;
        }
        total.add(&driver.sessions.hmac_stats());
    }
    eprintln!("totals: {total:?}");
    for (class, n) in &classes {
        eprintln!("{n:6}  {class}");
    }
}

// ---------------------------------------------------------------------------
// Policy seed conversations
// ---------------------------------------------------------------------------

/// `TPM_CC_PolicySecret`.
const CC_POLICY_SECRET: u32 = 0x151;
/// `TPM_CC_PolicyOR`.
const CC_POLICY_OR: u32 = 0x171;
/// `TPM_CC_PolicyPCR`.
const CC_POLICY_PCR: u32 = 0x17F;
/// `TPM_CC_PolicyAuthorize`.
const CC_POLICY_AUTHORIZE: u32 = 0x16A;
/// `TPM_CC_PolicyNV`.
const CC_POLICY_NV: u32 = 0x149;
/// `TPM_CC_LoadExternal`.
const CC_LOAD_EXTERNAL: u32 = 0x167;
/// `TPM_CC_Load`.
const CC_LOAD: u32 = 0x157;
/// `TPM_CC_Sign`.
const CC_SIGN: u32 = 0x15D;
/// `TPM_CC_VerifySignature`.
const CC_VERIFY_SIGNATURE: u32 = 0x177;
/// `TPMA_NV_WRITTEN`.
const NV_WRITTEN: u32 = 0x2000_0000;

/// Extends a SHA-256 policy digest: `H(digest || commandCode || extra...)`.
fn policy_extend(digest: &[u8], code: u32, extra: &[&[u8]]) -> Vec<u8> {
    let code = code.to_be_bytes();
    let mut parts: Vec<&[u8]> = vec![digest, &code];
    parts.extend_from_slice(extra);
    super::digest(TpmiAlgHash::Sha256, &parts)
}

/// `TPM2_PolicyCommandCode(code)` from an empty policy.
fn policy_command_code(code: u32) -> Vec<u8> {
    policy_extend(&[0; 32], CC_POLICY_COMMAND_CODE, &[&code.to_be_bytes()])
}

/// `TPM2_PolicyAuthValue` (or `TPM2_PolicyPassword`) from an empty policy.
fn policy_auth_value() -> Vec<u8> {
    policy_extend(&[0; 32], CC_POLICY_AUTH_VALUE, &[])
}

/// The `TPML_PCR_SELECTION` of SHA-256 PCR 16 (zero after `TPM2_Startup`).
const PCR16_SELECTION: &[u8] = &[0, 0, 0, 1, 0x00, 0x0B, 3, 0x00, 0x00, 0x01];

/// The Name of an NV index from its `TPM2B_NV_PUBLIC` (with extra attribute
/// bits `extra_attrs` set, e.g. `TPMA_NV_WRITTEN`).
fn nv_name_of(public: &[u8], extra_attrs: u32) -> Vec<u8> {
    let mut inner = public[2..].to_vec();
    let attrs = u32::from_be_bytes(inner[6..10].try_into().unwrap()) | extra_attrs;
    inner[6..10].copy_from_slice(&attrs.to_be_bytes());
    [
        &SHA256.to_be_bytes()[..],
        &super::digest(TpmiAlgHash::Sha256, &[&inner]),
    ]
    .concat()
}

/// The `TPM2B_PUBLIC` of the fixed `_common` ECC P-256 ECDSA-SHA256 key, for
/// `TPM2_LoadExternal`, and its Name.
fn external_ecc_key() -> (Vec<u8>, Vec<u8>) {
    let mut t = Vec::new();
    t.extend_from_slice(&0x0023u16.to_be_bytes());
    t.extend_from_slice(&SHA256.to_be_bytes());
    t.extend_from_slice(&0x0004_0440u32.to_be_bytes()); // userWithAuth|noDA|sign
    put_tpm2b(&mut t, &[]);
    t.extend_from_slice(SYM_NULL);
    t.extend_from_slice(&0x0018u16.to_be_bytes());
    t.extend_from_slice(&SHA256.to_be_bytes());
    t.extend_from_slice(&0x0003u16.to_be_bytes());
    t.extend_from_slice(&0x0010u16.to_be_bytes());
    put_tpm2b(&mut t, _common::ECC_X);
    put_tpm2b(&mut t, _common::ECC_Y);
    let name = [
        &SHA256.to_be_bytes()[..],
        &super::digest(TpmiAlgHash::Sha256, &[&t]),
    ]
    .concat();
    (tpm2b(&t), name)
}

/// The `TPM2B_PUBLIC` of an ECC P-256 ECDSA signing key that can only be
/// used through `policy` (`userWithAuth` clear).
fn policy_sign_template(policy: &[u8]) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&0x0023u16.to_be_bytes());
    t.extend_from_slice(&SHA256.to_be_bytes());
    t.extend_from_slice(&0x0004_0432u32.to_be_bytes()); // fixedTPM|fixedParent|sDO|noDA|sign
    put_tpm2b(&mut t, policy);
    t.extend_from_slice(SYM_NULL);
    t.extend_from_slice(&0x0018u16.to_be_bytes());
    t.extend_from_slice(&SHA256.to_be_bytes());
    t.extend_from_slice(&0x0003u16.to_be_bytes());
    t.extend_from_slice(&0x0010u16.to_be_bytes());
    put_tpm2b(&mut t, &[]);
    put_tpm2b(&mut t, &[]);
    tpm2b(&t)
}

/// The parameters of `TPM2_Sign` over `digest` with ECDSA-SHA256 and a NULL
/// hashcheck ticket.
fn sign_params(digest: &[u8]) -> Vec<u8> {
    let mut p = tpm2b(digest);
    p.extend_from_slice(&0x0018u16.to_be_bytes());
    p.extend_from_slice(&SHA256.to_be_bytes());
    p.extend_from_slice(&0x8024u16.to_be_bytes()); // TPM_ST_HASHCHECK
    p.extend_from_slice(&RH_NULL.to_be_bytes());
    put_tpm2b(&mut p, &[]);
    p
}

/// Seed conversations with satisfied policy chains, each followed by the
/// command the policy authorizes through a policy session.
fn policy_conversations() -> Vec<(&'static str, crate::model::Conversation)> {
    use crate::model::{
        AuthSel, Cmd, Conversation, FieldKind, HandleOperand, Segment, SessionSel, Step, ValueRef,
    };
    let step = |code: u32,
                handles: Vec<HandleOperand>,
                sessions: Vec<SessionSel>,
                params: Vec<Segment>| {
        let mut c = Cmd::new(code);
        c.handles = handles;
        c.sessions = sessions;
        c.params = params;
        Step::Cmd(c)
    };
    let bytes = |b: Vec<u8>| vec![Segment::Bytes(b)];
    let password = |auth: AuthSel| SessionSel::Password { auth };
    let policy = || SessionSel::Policy {
        session: 0,
        auth: AuthSel::Entity,
        attrs: ATTR_CONTINUE,
    };
    let session = || HandleOperand::Session { back: 0 };
    let nv = |back: u8| HandleOperand::Nv { back };
    let start_policy = |bind: u32| {
        let mut params = tpm2b(&test_nonce(TpmiAlgHash::Sha256));
        put_tpm2b(&mut params, &[]);
        params.push(SE_POLICY);
        params.extend_from_slice(SYM_NULL);
        params.extend_from_slice(&SHA256.to_be_bytes());
        step(
            CC_START_AUTH_SESSION,
            vec![HandleOperand::Raw(RH_NULL), HandleOperand::Raw(bind)],
            vec![],
            bytes(params),
        )
    };
    let define = |index: u32, attrs: u32, auth_policy: &[u8], auth: &[u8]| {
        let mut params = tpm2b(auth);
        params.extend_from_slice(&nv_public(index, attrs, auth_policy));
        step(
            CC_NV_DEFINE_SPACE,
            vec![HandleOperand::Raw(RH_OWNER)],
            vec![password(AuthSel::Empty)],
            bytes(params),
        )
    };
    let nv_write_policy = |data: &[u8]| {
        step(
            CC_NV_WRITE,
            vec![nv(0), nv(0)],
            vec![policy()],
            bytes(nv_write_params(data)),
        )
    };
    let cc_nv_write = CC_NV_WRITE.to_be_bytes().to_vec();
    let index = 0x0150_0030;

    let mut out = Vec::new();
    // PolicyAuthValue / PolicyPassword (authValue in the HMAC key / the
    // password in clear), the latter with a session bound to the owner.
    for (name, cc, bind) in [
        ("policy_auth_value_nv_write", CC_POLICY_AUTH_VALUE, RH_NULL),
        ("policy_password_nv_write", CC_POLICY_PASSWORD, RH_OWNER),
    ] {
        out.push((
            name,
            vec![
                define(index, NV_POLICY_W, &policy_auth_value(), b"nv-auth"),
                start_policy(bind),
                step(cc, vec![session()], vec![], vec![]),
                nv_write_policy(b"auth-value"),
            ],
        ));
    }
    // PolicyCommandCode, with a bound (non-empty session key) session.
    out.push((
        "policy_command_code_nv_write",
        vec![
            define(
                index,
                NV_POLICY_W,
                &policy_command_code(CC_NV_WRITE),
                b"nv-auth",
            ),
            start_policy(RH_OWNER),
            step(
                CC_POLICY_COMMAND_CODE,
                vec![session()],
                vec![],
                bytes(cc_nv_write.clone()),
            ),
            nv_write_policy(b"command-code"),
        ],
    ));
    // PolicyPCR over PCR 16 (all zeros), with the TPM computing the digest.
    let pcr_digest = super::digest(TpmiAlgHash::Sha256, &[&[0u8; 32]]);
    let pcr_policy = policy_extend(&[0; 32], CC_POLICY_PCR, &[PCR16_SELECTION, &pcr_digest]);
    let mut pcr_params = tpm2b(&[]);
    pcr_params.extend_from_slice(PCR16_SELECTION);
    out.push((
        "policy_pcr_nv_write",
        vec![
            define(index, NV_POLICY_W, &pcr_policy, b"nv-auth"),
            start_policy(RH_NULL),
            step(CC_POLICY_PCR, vec![session()], vec![], bytes(pcr_params)),
            nv_write_policy(b"pcr"),
        ],
    ));
    // PolicySecret with the owner's (empty) authValue.
    let secret_policy = super::digest(
        TpmiAlgHash::Sha256,
        &[&policy_extend(
            &[0; 32],
            CC_POLICY_SECRET,
            &[&RH_OWNER.to_be_bytes()],
        )],
    );
    let mut secret_params = tpm2b(&[]); // nonceTPM
    put_tpm2b(&mut secret_params, &[]); // cpHashA
    put_tpm2b(&mut secret_params, &[]); // policyRef
    secret_params.extend_from_slice(&0i32.to_be_bytes()); // expiration
    out.push((
        "policy_secret_nv_write",
        vec![
            define(index, NV_POLICY_W, &secret_policy, b"nv-auth"),
            start_policy(RH_NULL),
            step(
                CC_POLICY_SECRET,
                vec![HandleOperand::Raw(RH_OWNER), session()],
                vec![password(AuthSel::Empty)],
                bytes(secret_params),
            ),
            nv_write_policy(b"secret"),
        ],
    ));
    // PolicyOR over {PolicyAuthValue, PolicyCommandCode(NV_Write)}.
    let (branch_a, branch_b) = (policy_auth_value(), policy_command_code(CC_NV_WRITE));
    let or_policy = policy_extend(&[0; 32], CC_POLICY_OR, &[&branch_a, &branch_b]);
    let mut or_params = 2u32.to_be_bytes().to_vec();
    or_params.extend_from_slice(&tpm2b(&branch_a));
    or_params.extend_from_slice(&tpm2b(&branch_b));
    out.push((
        "policy_or_nv_write",
        vec![
            define(index, NV_POLICY_W, &or_policy, b"nv-auth"),
            start_policy(RH_NULL),
            step(CC_POLICY_AUTH_VALUE, vec![session()], vec![], vec![]),
            step(CC_POLICY_OR, vec![session()], vec![], bytes(or_params)),
            nv_write_policy(b"or"),
        ],
    ));
    // PolicyAuthorize: an approved PolicyCommandCode(NV_Write) signed by an
    // external key (signature by the TPM itself, ticket from
    // TPM2_VerifySignature).
    let (key_public, key_name) = external_ecc_key();
    let approved = policy_command_code(CC_NV_WRITE);
    let policy_ref = b"approval".to_vec();
    let a_hash = super::digest(TpmiAlgHash::Sha256, &[&approved, &policy_ref]);
    let authorize_policy = super::digest(
        TpmiAlgHash::Sha256,
        &[
            &policy_extend(&[0; 32], CC_POLICY_AUTHORIZE, &[&key_name]),
            &policy_ref,
        ],
    );
    let mut sensitive = 0x0023u16.to_be_bytes().to_vec();
    put_tpm2b(&mut sensitive, &[]);
    put_tpm2b(&mut sensitive, &[]);
    put_tpm2b(&mut sensitive, _common::ECC_D);
    let mut load_external = tpm2b(&sensitive);
    load_external.extend_from_slice(&key_public);
    load_external.extend_from_slice(&RH_NULL.to_be_bytes());
    // A NULL-hierarchy key yields a NULL verification ticket, which
    // PolicyAuthorize rejects: verify with the public part loaded in the
    // owner hierarchy.
    let mut load_external_public = tpm2b(&[]);
    load_external_public.extend_from_slice(&key_public);
    load_external_public.extend_from_slice(&RH_OWNER.to_be_bytes());
    let mut authorize_params = tpm2b(&approved);
    authorize_params.extend_from_slice(&tpm2b(&policy_ref));
    authorize_params.extend_from_slice(&tpm2b(&key_name));
    out.push((
        "policy_authorize_nv_write",
        vec![
            define(index, NV_POLICY_W, &authorize_policy, b"nv-auth"),
            step(CC_LOAD_EXTERNAL, vec![], vec![], bytes(load_external)),
            step(
                CC_SIGN,
                vec![HandleOperand::Response { back: 0 }],
                vec![password(AuthSel::Empty)],
                bytes(sign_params(&a_hash)),
            ),
            step(
                CC_LOAD_EXTERNAL,
                vec![],
                vec![],
                bytes(load_external_public),
            ),
            step(
                CC_VERIFY_SIGNATURE,
                vec![HandleOperand::Response { back: 0 }],
                vec![],
                vec![
                    Segment::Bytes(tpm2b(&a_hash)),
                    Segment::Value(ValueRef {
                        kind: FieldKind::Signature,
                        back: 0,
                    }),
                ],
            ),
            start_policy(RH_NULL),
            step(
                CC_POLICY_COMMAND_CODE,
                vec![session()],
                vec![],
                bytes(cc_nv_write.clone()),
            ),
            step(
                CC_POLICY_AUTHORIZE,
                vec![session()],
                vec![],
                vec![
                    Segment::Bytes(authorize_params),
                    Segment::Value(ValueRef {
                        kind: FieldKind::Ticket,
                        back: 0,
                    }),
                ],
            ),
            nv_write_policy(b"authorized"),
        ],
    ));
    // PolicyNV: index A holds an operand; index B is written through a
    // policy comparing A's contents.
    let index_a = 0x0150_0031;
    let public_a = nv_public(index_a, NV_AUTH_RW, &[]);
    let operand = [0x11u8; 8];
    let args = super::digest(
        TpmiAlgHash::Sha256,
        &[&operand, &0u16.to_be_bytes(), &0u16.to_be_bytes()],
    );
    let nv_policy = policy_extend(
        &[0; 32],
        CC_POLICY_NV,
        &[&args, &nv_name_of(&public_a, NV_WRITTEN)],
    );
    let mut policy_nv_params = tpm2b(&operand);
    policy_nv_params.extend_from_slice(&0u16.to_be_bytes()); // offset
    policy_nv_params.extend_from_slice(&0u16.to_be_bytes()); // TPM_EO_EQ
    out.push((
        "policy_nv_nv_write",
        vec![
            define(index_a, NV_AUTH_RW, &[], b"a-auth"),
            step(
                CC_NV_WRITE,
                vec![nv(0), nv(0)],
                vec![password(AuthSel::Entity)],
                bytes(nv_write_params(&operand)),
            ),
            define(index, NV_POLICY_W, &nv_policy, b"nv-auth"),
            start_policy(RH_NULL),
            step(
                CC_POLICY_NV,
                vec![nv(1), nv(1), session()],
                vec![password(AuthSel::Entity)],
                bytes(policy_nv_params),
            ),
            nv_write_policy(b"nv"),
        ],
    ));
    // A key usable only through PolicyCommandCode(Sign).
    let sign_policy = policy_command_code(CC_SIGN);
    let mut create = Vec::new();
    put_tpm2b(&mut create, &[0, 0, 0, 0]); // empty userAuth and data
    create.extend_from_slice(&policy_sign_template(&sign_policy));
    put_tpm2b(&mut create, &[]);
    create.extend_from_slice(&0u32.to_be_bytes());
    out.push((
        "policy_command_code_sign",
        vec![
            step(
                CC_CREATE_PRIMARY,
                vec![HandleOperand::Raw(RH_OWNER)],
                vec![password(AuthSel::Empty)],
                bytes(create_params(b"parent", true)),
            ),
            step(
                CC_CREATE,
                vec![HandleOperand::Response { back: 0 }],
                vec![password(AuthSel::Entity)],
                bytes(create),
            ),
            step(
                CC_LOAD,
                vec![HandleOperand::Response { back: 0 }],
                vec![password(AuthSel::Entity)],
                vec![
                    Segment::Value(ValueRef {
                        kind: FieldKind::Private,
                        back: 0,
                    }),
                    Segment::Value(ValueRef {
                        kind: FieldKind::Public,
                        back: 0,
                    }),
                ],
            ),
            start_policy(RH_NULL),
            step(
                CC_POLICY_COMMAND_CODE,
                vec![session()],
                vec![],
                bytes(CC_SIGN.to_be_bytes().to_vec()),
            ),
            step(
                CC_SIGN,
                // back 0 is the policy session (StartAuthSession's response
                // handle); back 1 the loaded key.
                vec![HandleOperand::Response { back: 1 }],
                vec![policy()],
                bytes(sign_params(&[0x42; 32])),
            ),
        ],
    ));
    out.into_iter()
        .map(|(name, steps)| (name, Conversation { steps }))
        .collect()
}

/// Every policy seed conversation succeeds round by round through the
/// driver, and its policy-session authorization succeeds and verifies.
/// Seeds are written with `TPM_FUZZ_SESSION_SEEDS=<dir>`.
#[test]
fn driver_conversations_with_policy_sessions_succeed() {
    use crate::driver::{Driver, FIXED_SEED, RoundOutcome};
    let mut tpm = Tpm::with_seed(FIXED_SEED);
    for (i, (name, conv)) in policy_conversations().into_iter().enumerate() {
        if i > 0 {
            tpm.reset();
        }
        if let Some(dir) = std::env::var_os("TPM_FUZZ_SESSION_SEEDS") {
            std::fs::write(std::path::Path::new(&dir).join(name), conv.to_bytes()).unwrap();
        }
        let mut driver = Driver::default();
        for (round, step) in conv.steps.iter().enumerate() {
            let outcome = driver
                .round(&mut tpm, step)
                .unwrap_or_else(|f| panic!("{name}: {}", f.report()));
            assert!(
                matches!(outcome, RoundOutcome::Executed(0)),
                "{name} round {round}: {outcome:x?} cmd {}",
                hex(driver.last_command())
            );
        }
        let stats = driver.sessions.hmac_stats();
        assert_eq!(
            (stats.policy_built, stats.policy_succeeded),
            (1, 1),
            "{name}: {stats:?}"
        );
        assert_eq!(stats.responses_verified, 1, "{name}: {stats:?}");
    }
}

// ---------------------------------------------------------------------------
// Salted sessions
// ---------------------------------------------------------------------------

/// The `TPM2B_PUBLIC` of an RSA-2048 restricted AES-128-CFB storage key.
fn rsa_storage_template() -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&0x0001u16.to_be_bytes()); // TPM_ALG_RSA
    t.extend_from_slice(&SHA256.to_be_bytes());
    t.extend_from_slice(&0x0003_0472u32.to_be_bytes());
    put_tpm2b(&mut t, &[]);
    t.extend_from_slice(SYM_AES128_CFB);
    t.extend_from_slice(&0x0010u16.to_be_bytes()); // scheme NULL
    t.extend_from_slice(&2048u16.to_be_bytes());
    t.extend_from_slice(&0u32.to_be_bytes());
    put_tpm2b(&mut t, &[]);
    tpm2b(&t)
}

/// The parameters of `TPM2_CreatePrimary` with template `template`.
fn create_primary_params(template: &[u8]) -> Vec<u8> {
    let mut p = tpm2b(&[0, 0, 0, 0]);
    p.extend_from_slice(template);
    put_tpm2b(&mut p, &[]);
    p.extend_from_slice(&0u32.to_be_bytes());
    p
}

/// `encapsulate_secret` is deterministic in its seed, sizes the salt by the
/// key's nameAlg, and rejects garbage without panicking.
#[test]
fn salt_encapsulation_is_deterministic_and_total() {
    let ecc = ecc_template(true);
    let rsa = rsa_storage_template();
    // An RSA template has no modulus, so it is rejected; the ECC template
    // has no point, so it is rejected too: use the fixed _common key.
    assert!(_common::encapsulate_secret(&rsa[2..], "SECRET", 1).is_none());
    assert!(_common::encapsulate_secret(&ecc[2..], "SECRET", 1).is_none());
    let (public, _) = external_ecc_key();
    let a = _common::encapsulate_secret(&public[2..], "SECRET", 7).unwrap();
    assert_eq!(
        a,
        _common::encapsulate_secret(&public[2..], "SECRET", 7).unwrap()
    );
    assert_ne!(
        a,
        _common::encapsulate_secret(&public[2..], "SECRET", 8).unwrap()
    );
    assert_eq!(a.0.len(), 32);
    assert_eq!(a.1.len(), 2 + 32 + 2 + 32);
    for garbage in [&[][..], &[0xFF; 3], &public[2..public.len() - 1]] {
        assert!(_common::encapsulate_secret(garbage, "SECRET", 1).is_none());
    }
}

/// Without a known public area for `tpmKey`, or with a non-empty
/// `encryptedSalt`, `prepare_params` leaves the parameters alone.
#[test]
fn prepare_params_only_fills_empty_salts_of_known_keys() {
    let mut engine = SessionEngine::new();
    let mut params = tpm2b(&[1; 16]);
    put_tpm2b(&mut params, &[]);
    params.extend_from_slice(&[SE_HMAC, 0x00, 0x10, 0x00, 0x0B]);
    let info = |handles: &'static [u32]| CommandInfo {
        round: 0,
        code: CC_START_AUTH_SESSION,
        handles,
        names: &[],
        handle_auths: &[],
    };
    let original = params.clone();
    engine.prepare_params(&info(&[0x8000_0000, RH_NULL]), &mut params);
    assert_eq!(params, original, "unknown key");
    let (public, _) = external_ecc_key();
    engine.record_public(0x8000_0000, &public[2..]);
    engine.prepare_params(&info(&[RH_NULL, RH_NULL]), &mut params);
    assert_eq!(params, original, "unsalted");
    let mut fuzzed = tpm2b(&[1; 16]);
    put_tpm2b(&mut fuzzed, &[9; 5]);
    let fuzzed_original = fuzzed.clone();
    engine.prepare_params(&info(&[0x8000_0000, RH_NULL]), &mut fuzzed);
    assert_eq!(fuzzed, fuzzed_original, "fuzzed salt");
    engine.prepare_params(&info(&[0x8000_0000, RH_NULL]), &mut params);
    assert_eq!(params.len(), original.len() + 68);
    assert_eq!(&params[..18], &original[..18]);
    assert_eq!(&params[params.len() - 5..], &original[original.len() - 5..]);
    assert!(engine.pending_salt.is_some());
}

/// Salted sessions to an ECC P-256 and an RSA-2048 storage key, unbound and
/// bound to the owner: the engine generates and encrypts the salt, the
/// session key is known, and HMAC-authorized (and parameter-encrypted)
/// commands succeed with verified response HMACs.
#[test]
fn salted_sessions_authorize_and_verify() {
    for (template, bind) in [
        (ecc_template(true), RH_NULL),
        (ecc_template(true), RH_OWNER),
        (rsa_storage_template(), RH_NULL),
        (rsa_storage_template(), RH_OWNER),
    ] {
        let mut c = Conv::new();
        c.set_hierarchy_auth(RH_OWNER, b"", b"owner-secret");
        let out = c.send(
            CC_CREATE_PRIMARY,
            &[RH_OWNER],
            &[b"owner-secret"],
            &create_primary_params(&template),
            &[password_req(b"owner-secret")],
        );
        assert_eq!(out.rc, 0, "CreatePrimary: {:#x}", out.rc);
        let key = u32::from_be_bytes(out.response[10..14].try_into().unwrap());
        assert!(c.engine.public_of(key).is_some());
        let mut params = tpm2b(&test_nonce(TpmiAlgHash::Sha256));
        put_tpm2b(&mut params, &[]);
        params.push(SE_HMAC);
        params.extend_from_slice(SYM_AES128_CFB);
        params.extend_from_slice(&SHA256.to_be_bytes());
        let out = c.send(
            CC_START_AUTH_SESSION,
            &[key, bind],
            &[&[], b"owner-secret"],
            &params,
            &[],
        );
        assert_eq!(out.rc, 0, "salted StartAuthSession: {:#x}", out.rc);
        let h = *c.engine.live_handles().last().unwrap();
        assert_eq!(
            c.engine.session(h).unwrap().session_key().map(<[u8]>::len),
            Some(32)
        );
        let index = 0x0150_0040;
        let mut params = tpm2b(b"nv-auth");
        params.extend_from_slice(&nv_public(index, NV_AUTH_RW, &[]));
        let out = c.send(
            CC_NV_DEFINE_SPACE,
            &[RH_OWNER],
            &[b"owner-secret"],
            &params,
            &[hmac_req(0, b"owner-secret", ATTR_CONTINUE | ATTR_DECRYPT)],
        );
        assert_eq!(out.rc, 0, "bind {bind:#x}: NV_DefineSpace {:#x}", out.rc);
        let out = c.send(
            CC_NV_WRITE,
            &[index, index],
            &[b"nv-auth", b"nv-auth"],
            &nv_write_params(b"salted"),
            &[hmac_req(0, b"nv-auth", ATTR_CONTINUE | ATTR_DECRYPT)],
        );
        assert_eq!(out.rc, 0, "NV_Write {:#x}", out.rc);
        let out = c.send(
            CC_NV_READ,
            &[index, index],
            &[b"nv-auth", b"nv-auth"],
            &nv_read_params(6),
            &[hmac_req(0, b"nv-auth", ATTR_CONTINUE | ATTR_ENCRYPT)],
        );
        assert_eq!(out.rc, 0, "NV_Read {:#x}", out.rc);
        assert_eq!(out.decrypted, Some(tpm2b(b"salted")));
        let stats = c.engine.hmac_stats();
        assert_eq!(stats.responses_verified, 3);
        assert_eq!(
            (
                stats.salts_generated,
                stats.salted_started,
                stats.salted_built,
                stats.salted_succeeded
            ),
            (1, 1, 3, 3)
        );
    }
}

/// A fuzzed (non-generated) salt leaves the key unknown: the TPM rejects
/// the garbage salt, and a session started that way is never verified.
#[test]
fn fuzzed_salt_is_rejected_by_the_tpm() {
    let mut c = Conv::new();
    let out = c.send(
        CC_CREATE_PRIMARY,
        &[RH_OWNER],
        &[b""],
        &create_primary_params(&ecc_template(true)),
        &[password_req(b"")],
    );
    let key = u32::from_be_bytes(out.response[10..14].try_into().unwrap());
    let mut params = tpm2b(&test_nonce(TpmiAlgHash::Sha256));
    put_tpm2b(&mut params, &[7; 68]);
    params.extend_from_slice(&[SE_HMAC, 0x00, 0x10, 0x00, 0x0B]);
    let out = c.send(CC_START_AUTH_SESSION, &[key, RH_NULL], &[], &params, &[]);
    assert_ne!(out.rc, 0);
    assert!(c.engine.live_handles().is_empty());
}

/// Seed conversations with salted HMAC sessions (ECC unbound, RSA bound to
/// the owner), using parameter encryption.
fn salted_conversations() -> Vec<(&'static str, crate::model::Conversation)> {
    use crate::model::{AuthSel, Cmd, Conversation, HandleOperand, Segment, SessionSel, Step};
    let step =
        |code: u32, handles: Vec<HandleOperand>, sessions: Vec<SessionSel>, params: Vec<u8>| {
            let mut c = Cmd::new(code);
            c.handles = handles;
            c.sessions = sessions;
            c.params = vec![Segment::Bytes(params)];
            Step::Cmd(c)
        };
    let hmac = |attrs: u8| SessionSel::Hmac {
        session: 0,
        auth: AuthSel::Entity,
        attrs,
        corrupt_hmac: false,
    };
    let owner = || vec![HandleOperand::Raw(RH_OWNER)];
    let nv = || vec![HandleOperand::Nv { back: 0 }, HandleOperand::Nv { back: 0 }];
    let mut out = Vec::new();
    for (name, template, bind) in [
        ("salted_ecc_hmac_nv", ecc_template(true), RH_NULL),
        ("salted_rsa_bound_hmac_nv", rsa_storage_template(), RH_OWNER),
    ] {
        let mut start = tpm2b(&test_nonce(TpmiAlgHash::Sha256));
        put_tpm2b(&mut start, &[]);
        start.push(SE_HMAC);
        start.extend_from_slice(SYM_AES128_CFB);
        start.extend_from_slice(&SHA256.to_be_bytes());
        let mut define = tpm2b(b"nv-auth");
        define.extend_from_slice(&nv_public(0x0150_0041, NV_AUTH_RW, &[]));
        let steps = vec![
            step(
                CC_HIERARCHY_CHANGE_AUTH,
                owner(),
                vec![SessionSel::Password {
                    auth: AuthSel::Empty,
                }],
                tpm2b(b"owner-secret"),
            ),
            step(
                CC_CREATE_PRIMARY,
                owner(),
                vec![SessionSel::Password {
                    auth: AuthSel::Entity,
                }],
                create_primary_params(&template),
            ),
            step(
                CC_START_AUTH_SESSION,
                vec![
                    HandleOperand::Response { back: 0 },
                    HandleOperand::Raw(bind),
                ],
                vec![],
                start,
            ),
            step(
                CC_NV_DEFINE_SPACE,
                owner(),
                vec![hmac(ATTR_CONTINUE | ATTR_DECRYPT)],
                define,
            ),
            step(
                CC_NV_WRITE,
                nv(),
                vec![hmac(ATTR_CONTINUE | ATTR_DECRYPT)],
                nv_write_params(b"salted"),
            ),
            step(
                CC_NV_READ,
                nv(),
                vec![hmac(ATTR_CONTINUE | ATTR_ENCRYPT)],
                nv_read_params(6),
            ),
        ];
        out.push((name, Conversation { steps }));
    }
    out
}

/// Every salted seed conversation succeeds through the driver with verified
/// HMACs. Seeds are written with `TPM_FUZZ_SESSION_SEEDS=<dir>`.
#[test]
fn driver_conversations_with_salted_sessions_succeed() {
    use crate::driver::{Driver, FIXED_SEED, RoundOutcome};
    let mut tpm = Tpm::with_seed(FIXED_SEED);
    for (i, (name, conv)) in salted_conversations().into_iter().enumerate() {
        if i > 0 {
            tpm.reset();
        }
        if let Some(dir) = std::env::var_os("TPM_FUZZ_SESSION_SEEDS") {
            std::fs::write(std::path::Path::new(&dir).join(name), conv.to_bytes()).unwrap();
        }
        let mut driver = Driver::default();
        for (round, step) in conv.steps.iter().enumerate() {
            let outcome = driver
                .round(&mut tpm, step)
                .unwrap_or_else(|f| panic!("{name}: {}", f.report()));
            assert!(
                matches!(outcome, RoundOutcome::Executed(0)),
                "{name} round {round}: {outcome:x?} cmd {}",
                hex(driver.last_command())
            );
        }
        let stats = driver.sessions.hmac_stats();
        assert_eq!(
            (
                stats.hmac_built,
                stats.hmac_succeeded,
                stats.responses_verified
            ),
            (3, 3, 3),
            "{name}"
        );
    }
}

/// Triage helper (ignored; run with `TPM_FUZZ_SESSION_REPLAY=<input>[,<input>...]` and
/// `--ignored --nocapture`): replays fuzz inputs through the driver on the fixed seed, printing
/// every round's step, command, response and session state, and the finding report at the end.
#[test]
#[ignore]
fn replay_inputs_for_triage() {
    use crate::driver::{Driver, FIXED_SEED};
    use crate::model::Conversation;
    let Ok(inputs) = std::env::var("TPM_FUZZ_SESSION_REPLAY") else {
        return;
    };
    let mut tpm = Tpm::with_seed(FIXED_SEED);
    for (i, path) in inputs.split(',').enumerate() {
        if i > 0 {
            tpm.reset();
        }
        eprintln!("=== {path}");
        let conv = Conversation::from_bytes(&std::fs::read(path).unwrap());
        let mut driver = Driver::default();
        for (round, step) in conv.steps.iter().enumerate() {
            let result = driver.round(&mut tpm, step);
            eprintln!(
                "round {round}: {step:?}\n  cmd {}\n  rsp {}\n  sessions {:x?}",
                hex(driver.last_command()),
                hex(driver.last_response()),
                driver.sessions.live_handles()
            );
            if let Err(finding) = result {
                eprintln!("FINDING:\n{}", finding.report());
                break;
            }
        }
    }
}

/// Triage probe (ignored): evicts ECC primaries to persistent handles until the TPM runs out of
/// NV space; a divergence panics at the first differing response.
#[test]
#[ignore]
fn probe_persistent_capacity() {
    let mut c = Conv::new();
    for i in 0..12u32 {
        let out = c.send(
            CC_CREATE_PRIMARY,
            &[RH_OWNER],
            &[b""],
            &create_primary_params(&ecc_template(true)),
            &[password_req(b"")],
        );
        assert_eq!(out.rc, 0);
        let key = u32::from_be_bytes(out.response[10..14].try_into().unwrap());
        let out = c.send(
            0x120,
            &[RH_OWNER, key],
            &[b"", b""],
            &(0x8100_0300 + i).to_be_bytes(),
            &[password_req(b"")],
        );
        eprintln!("evict {i}: rc {:#x}", out.rc);
        c.send(CC_FLUSH_CONTEXT, &[], &[], &key.to_be_bytes(), &[]);
        if out.rc != 0 {
            break;
        }
    }
}
