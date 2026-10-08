// Ported from go-tpm/tpm2/test/audit_test.go

use crate::test_utils::{
    ActiveSession, CmdHeader, RespHeader, flush_context, leak_bytes, marshal_to_vec,
    start_auth_session, strip_trailing_zeros,
};
use sha2::{Digest as _, Sha256};
use tpm2::Marshal;
use tpm2::Unmarshal;
use tpm2::commands::{
    Certify, CertifyHandles, Command, CreatePrimary, CreatePrimaryHandles, GetCapability,
    GetSessionAuditDigest, GetSessionAuditDigestHandles,
};
use tpm2::crypto::Rng;
use tpm2::{Handle, TpmCap, TpmEccCurve, TpmPt, TpmSe, TpmSt};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter, Tpm2bName, Tpm2bNonce,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmaObject, TpmaSession, TpmiAlgHash, TpmiRsaKeyBits,
    TpmiStCommandTag, TpmsAuthCommand, TpmsAuthResponse, TpmsEccParms, TpmsEccPoint, TpmsRsaParms,
    TpmsSensitiveCreate, TpmtEccScheme, TpmtPublic, TpmtSigScheme,
};
use tpm2_platform_linux::{LinuxRng, PlatformCryptoProvider};
use tpm2_simulator::{Simulator, create_simulator};

// =========================================================================
// Mixed-session command execution (mirrors go-tpm session handling)
// =========================================================================

/// One authorization slot in the session area of a command, mirroring the
/// go-tpm `Session` implementations used by the Go tests.
pub(crate) enum SessionAuth<'a> {
    /// A password pseudo-session (`TPM_RS_PW`) carrying the given auth value,
    /// like go-tpm's `PasswordAuth(auth)`. Sent with no session attributes set.
    Password(&'a [u8]),
    /// An (unbound, unsalted, unencrypted) HMAC or policy session, like go-tpm's
    /// `HMACSession`/`Policy`. The HMAC key is `sessionKey || auth`, where `auth`
    /// is the auth value configured on the session (empty for e.g. audit-only
    /// sessions or go-tpm `Policy(...)` sessions without an `Auth` option).
    Session {
        session: &'a mut ActiveSession,
        auth: &'a [u8],
    },
}

fn hash_parts(alg: TpmiAlgHash, parts: &[&[u8]]) -> Vec<u8> {
    let crypto = PlatformCryptoProvider;
    let mut state = tpm2::crypto::HashCtx::new(&crypto, alg).unwrap();
    for part in parts {
        state.update(part).unwrap();
    }
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    state.finalize(&mut out).unwrap().digest().to_vec()
}

fn hmac_parts(alg: TpmiAlgHash, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let crypto = PlatformCryptoProvider;
    let mut state = tpm2::crypto::HmacCtx::new(&crypto, alg, key).unwrap();
    for part in parts {
        state.update(part).unwrap();
    }
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    state.finalize(&mut out).unwrap().digest().to_vec()
}

/// Executes `cmd` with an arbitrary mix of password and HMAC/policy sessions,
/// in the given order, the way go-tpm's `Command.Execute(tpm, sessions...)`
/// does: auth-handle sessions first, followed by any extra sessions (e.g. an
/// audit session).
///
/// `handle_names` are the Names of the command handles (used for cpHash).
/// Response session areas are validated like go-tpm does (password sessions
/// must echo an empty nonce/HMAC with only `continueSession` set; HMAC/policy
/// sessions must carry a valid response HMAC), and the nonces of HMAC/policy
/// sessions are updated.
///
/// Returns the raw response parameter bytes and the response handles.
pub(crate) fn execute_with_mixed_sessions<CmdT: Command>(
    sim: &mut Simulator<'_>,
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    handle_names: &[&[u8]],
    auths: &mut [SessionAuth<'_>],
) -> Result<(Vec<u8>, CmdT::RespHandles), u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let cc_bytes = CmdT::CMD_CODE.code().to_be_bytes();
    let params = marshal_to_vec(cmd);

    // Build the authorization area.
    let mut nonce_callers = Vec::with_capacity(auths.len());
    let mut hmac_keys = Vec::with_capacity(auths.len());
    let mut auth_area = Vec::new();
    for auth in auths.iter() {
        let auth_cmd = match auth {
            SessionAuth::Password(value) => {
                nonce_callers.push(Tpm2bNonce::default());
                hmac_keys.push(Vec::new());
                TpmsAuthCommand {
                    session_handle: Handle::RS_PW,
                    nonce: Tpm2bNonce::default(),
                    session_attributes: TpmaSession::from_bits_retain(0),
                    hmac: Tpm2bAuth::from_bytes(value).unwrap(),
                }
            }
            SessionAuth::Session { session, auth } => {
                assert!(
                    !session
                        .attributes
                        .intersects(TpmaSession::DECRYPT | TpmaSession::ENCRYPT),
                    "parameter encryption is not supported by this helper"
                );
                let mut nonce_bytes = [0u8; 16];
                sim.context
                    .platform
                    .crypto
                    .get_random(&mut nonce_bytes)
                    .unwrap();
                let nonce_caller = Tpm2bNonce::from_bytes(leak_bytes(&nonce_bytes)).unwrap();
                let key = [session.session_key.as_slice(), strip_trailing_zeros(auth)].concat();
                let mut cp_parts: Vec<&[u8]> = vec![&cc_bytes];
                cp_parts.extend_from_slice(handle_names);
                cp_parts.push(&params);
                let cp_hash = hash_parts(session.auth_hash, &cp_parts);
                let attrs = [session.attributes.bits()];
                let hmac = hmac_parts(
                    session.auth_hash,
                    &key,
                    &[
                        &cp_hash,
                        nonce_caller.get_buffer(),
                        session.nonce_tpm.get_buffer(),
                        &attrs,
                    ],
                );
                nonce_callers.push(nonce_caller);
                hmac_keys.push(key);
                TpmsAuthCommand {
                    session_handle: session.session_handle,
                    nonce: nonce_caller,
                    session_attributes: session.attributes,
                    hmac: Tpm2bAuth::from_bytes(leak_bytes(&hmac)).unwrap(),
                }
            }
        };
        auth_area.extend_from_slice(&marshal_to_vec(&auth_cmd));
    }

    // Assemble the command.
    let mut cmd_header = CmdHeader {
        tag: if auths.is_empty() {
            TpmiStCommandTag::NoSessions
        } else {
            TpmiStCommandTag::Sessions
        },
        size: 0,
        code: CmdT::CMD_CODE,
    };
    let mut cmd_buffer = vec![0u8; 10];
    cmd_buffer.extend_from_slice(&marshal_to_vec(&cmd_handles));
    if !auths.is_empty() {
        cmd_buffer.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
        cmd_buffer.extend_from_slice(&auth_area);
    }
    cmd_buffer.extend_from_slice(&params);
    cmd_header.size = cmd_buffer.len() as u32;
    cmd_header.marshal((&mut cmd_buffer[0..10]).try_into().unwrap());

    // Transact.
    let mut resp_buffer = vec![0u8; 16384];
    let resp_bytes = sim.transact(&cmd_buffer, &mut resp_buffer).unwrap();

    // Parse the response.
    let mut slice: &[u8] = resp_bytes;
    let resp_header = RespHeader::unmarshal(&mut slice).unwrap();
    if resp_header.rc != 0 {
        return Err(resp_header.rc);
    }
    let resp_handles = CmdT::RespHandles::unmarshal(&mut slice).unwrap();
    let parameter_size = if resp_header.tag == TpmSt::SESSIONS {
        u32::unmarshal(&mut slice).unwrap() as usize
    } else {
        slice.len()
    };
    let (resp_params, mut sess_slice) = slice.split_at(parameter_size);
    let rc_bytes = 0u32.to_be_bytes();

    for (i, auth) in auths.iter_mut().enumerate() {
        let auth_resp = TpmsAuthResponse::unmarshal(&mut sess_slice).unwrap();
        match auth {
            SessionAuth::Password(_) => {
                assert!(
                    auth_resp.nonce.get_buffer().is_empty(),
                    "expected empty nonce in response auth to PW session"
                );
                assert_eq!(
                    auth_resp.session_attributes,
                    TpmaSession::CONTINUE_SESSION,
                    "expected only ContinueSession in response auth to PW session"
                );
                assert!(
                    auth_resp.hmac.get_buffer().is_empty(),
                    "expected empty HMAC in response auth to PW session"
                );
            }
            SessionAuth::Session { session, .. } => {
                let rp_hash = hash_parts(session.auth_hash, &[&rc_bytes, &cc_bytes, resp_params]);
                let attrs = [auth_resp.session_attributes.bits()];
                let expected = hmac_parts(
                    session.auth_hash,
                    &hmac_keys[i],
                    &[
                        &rp_hash,
                        auth_resp.nonce.get_buffer(),
                        nonce_callers[i].get_buffer(),
                        &attrs,
                    ],
                );
                assert_eq!(
                    expected.as_slice(),
                    auth_resp.hmac.get_buffer(),
                    "response HMAC verification failed"
                );
                session.nonce_caller = nonce_callers[i];
                session.nonce_tpm =
                    Tpm2bNonce::from_bytes(leak_bytes(auth_resp.nonce.get_buffer())).unwrap();
            }
        }
    }

    Ok((resp_params.to_vec(), resp_handles))
}

/// Like [`execute_with_mixed_sessions`], but unmarshals the response
/// parameters.
pub(crate) fn execute_mixed<CmdT: Command>(
    sim: &mut Simulator<'_>,
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    handle_names: &[&[u8]],
    auths: &mut [SessionAuth<'_>],
) -> Result<(CmdT::Response<'static>, CmdT::RespHandles), u32>
where
    CmdT::Response<'static>: Unmarshal<'static>,
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let (params, resp_handles) =
        execute_with_mixed_sessions(sim, cmd, cmd_handles, handle_names, auths)?;
    let mut slice: &'static [u8] = leak_bytes(&params);
    let resp = <CmdT::Response<'static>>::unmarshal(&mut slice).unwrap();
    Ok((resp, resp_handles))
}

/// Executes `CreatePrimary` under `hierarchy` the way go-tpm does when the
/// primary handle is a plain handle: authorized with `PasswordAuth(nil)`.
pub(crate) fn create_primary_pw(
    sim: &mut Simulator<'_>,
    hierarchy: Handle,
    cmd: &CreatePrimary<'_>,
) -> Result<
    (
        <CreatePrimary<'static> as Command>::Response<'static>,
        <CreatePrimary<'static> as Command>::RespHandles,
    ),
    u32,
> {
    execute_mixed(
        sim,
        cmd,
        CreatePrimaryHandles {
            primary_handle: hierarchy,
        },
        &[&hierarchy.0.to_be_bytes()],
        &mut [SessionAuth::Password(&[])],
    )
}

// =========================================================================
// Audit helpers (mirror go-tpm's CommandAudit / MarshalCommand / ...)
// =========================================================================

/// Mirrors go-tpm `CommandAudit` with SHA-256.
struct CommandAudit {
    digest: [u8; 32],
}

impl CommandAudit {
    /// Mirrors go-tpm `NewAudit(TPMAlgSHA256)`: an all-zero digest.
    fn new() -> Self {
        Self { digest: [0u8; 32] }
    }

    /// Mirrors go-tpm `AuditCommand`: extends the digest with
    /// `cpHash(cc || names || cmdParams)` and `rpHash(0 || cc || rspParams)`.
    fn audit_command<CmdT: Command>(
        &mut self,
        cmd: &CmdT,
        names: &[&[u8]],
        rsp: &CmdT::Response<'_>,
    ) where
        for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
        for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
        for<'b, 'c> &'b mut <CmdT::Response<'c> as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    {
        let cp_hash = Sha256::digest(marshal_command(cmd, names));
        let rp_hash = Sha256::digest(marshal_response::<CmdT>(rsp));
        let mut h = Sha256::new();
        h.update(self.digest);
        h.update(cp_hash);
        h.update(rp_hash);
        self.digest.copy_from_slice(&h.finalize());
    }

    fn digest(&self) -> &[u8] {
        &self.digest
    }
}

/// Mirrors go-tpm `MarshalCommand`: the raw cpHash preimage
/// `CommandCode || Name1 || ... || Parameters`.
fn marshal_command<CmdT: Command>(cmd: &CmdT, names: &[&[u8]]) -> Vec<u8>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut buf = CmdT::CMD_CODE.code().to_be_bytes().to_vec();
    for name in names {
        buf.extend_from_slice(name);
    }
    buf.extend_from_slice(&marshal_to_vec(cmd));
    buf
}

/// Mirrors go-tpm `MarshalResponse`: the raw rpHash preimage
/// `ResponseCode(0) || CommandCode || Parameters`.
fn marshal_response<CmdT: Command>(rsp: &CmdT::Response<'_>) -> Vec<u8>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b, 'c> &'b mut <CmdT::Response<'c> as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut buf = 0u32.to_be_bytes().to_vec();
    buf.extend_from_slice(&CmdT::CMD_CODE.code().to_be_bytes());
    buf.extend_from_slice(&marshal_to_vec(rsp));
    buf
}

/// Mirrors go-tpm `parseNameSize`: determines the size of a Name by
/// inspecting its first bytes.
fn parse_name_size(buf: &[u8]) -> usize {
    assert!(buf.len() >= 2, "buffer too short to parse name");
    let first_two = u16::from_be_bytes([buf[0], buf[1]]);
    match (first_two, buf[0]) {
        // PCR, HMAC session, policy session or permanent handle.
        (0x0000, _) | (_, 0x02) | (_, 0x03) | (_, 0x40) => 4,
        (alg, _) => {
            let hash = match alg {
                0x0004 => TpmiAlgHash::Sha1,
                0x000B => TpmiAlgHash::Sha256,
                0x000C => TpmiAlgHash::Sha384,
                0x000D => TpmiAlgHash::Sha512,
                _ => panic!("unsupported hash algorithm 0x{alg:x} in name"),
            };
            2 + hash.digest_size()
        }
    }
}

/// Mirrors go-tpm `UnmarshalCommand`: parses a raw cpHash preimage produced by
/// [`marshal_command`] back into the command's handle Names and parameters.
fn unmarshal_command<CmdT>(data: &'static [u8], num_names: usize) -> (Vec<&'static [u8]>, CmdT)
where
    CmdT: Command + Unmarshal<'static>,
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let (cc, mut rest) = data.split_at(4);
    assert_eq!(
        cc,
        CmdT::CMD_CODE.code().to_be_bytes(),
        "command code mismatch"
    );
    let mut names = Vec::with_capacity(num_names);
    for _ in 0..num_names {
        let size = parse_name_size(rest);
        let (name, tail) = rest.split_at(size);
        names.push(name);
        rest = tail;
    }
    let cmd = CmdT::unmarshal(&mut rest).unwrap();
    (names, cmd)
}

/// Mirrors go-tpm `UnmarshalResponse`: parses a raw rpHash preimage produced
/// by [`marshal_response`] back into the response parameters.
fn unmarshal_response<CmdT: Command>(data: &'static [u8]) -> CmdT::Response<'static>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    assert!(data.len() >= 8, "data too short");
    let (rc, rest) = data.split_at(4);
    assert_eq!(rc, [0u8; 4], "invalid response code");
    let (_cc, mut params) = rest.split_at(4);
    <CmdT::Response<'static>>::unmarshal(&mut params).unwrap()
}

// =========================================================================
// Key creation helpers
// =========================================================================

/// Creates the ECDSA-P256 restricted signing AK used by both Go tests, under
/// the owner hierarchy, with the given user auth.
fn create_ak_ecc(sim: &mut Simulator<'_>, auth: &[u8]) -> (Handle, Tpm2bName<'static>) {
    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::RESTRICTED
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
    let create_cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(leak_bytes(auth)).unwrap(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(public_area),
        ..Default::default()
    };
    let (rsp, rsp_handles) = create_primary_pw(sim, Handle::RH_OWNER, &create_cmd)
        .expect("could not generate AK ECC key");

    (rsp_handles.object_handle, rsp.name)
}

/// Creates the RSA-2048 sign+decrypt key certified in
/// `TestAuditSessionWithCertify`.
fn create_certifiable_key_rsa(sim: &mut Simulator<'_>) -> (Handle, Tpm2bName<'static>) {
    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let create_cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(public_area),
        ..Default::default()
    };
    let (rsp, rsp_handles) = create_primary_pw(sim, Handle::RH_OWNER, &create_cmd)
        .expect("could not generate RSA key to certify");

    (rsp_handles.object_handle, rsp.name)
}

/// Mirrors go-tpm `HMACSession(tpm, TPMAlgSHA256, 16, Audit())`: an unbound,
/// unsalted HMAC session with `continueSession` and `audit` set.
fn start_audit_session(sim: &mut Simulator<'_>) -> ActiveSession {
    let mut sess = start_auth_session(
        sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    sess.attributes = TpmaSession::AUDIT | TpmaSession::CONTINUE_SESSION;
    sess
}

/// Extracts the session digest from a `GetSessionAuditDigest` response.
fn session_audit_digest(
    rsp: &<GetSessionAuditDigest<'static> as Command>::Response<'static>,
) -> Vec<u8> {
    let attest = rsp
        .audit_info
        .to_struct()
        .expect("failed to unmarshal audit_info");
    match attest.attested {
        tpm2::TpmuAttest::SessionAudit(info) => info.session_digest.get_buffer().to_vec(),
        _ => panic!("Expected SessionAudit attestation type"),
    }
}

// =========================================================================
// Tests
// =========================================================================

// Original Go test: audit_test.go - TestAuditSession
#[test]
fn test_audit_session() {
    let mut sim = create_simulator!();

    // Create the audit session
    let mut sess = start_audit_session(&mut sim);

    // Create the AK for audit
    let (ak_handle, ak_name) = create_ak_ecc(&mut sim, &[]);

    let mut audit = CommandAudit::new();
    let mut audit2 = CommandAudit::new();
    let mut accumulated_digest = [0u8; 32];

    // Call GetCapability a bunch of times with the audit session and make sure
    // it extends like we expect it to.
    let props = [
        TpmPt::FAMILY_INDICATOR,
        TpmPt::LEVEL,
        TpmPt::REVISION,
        TpmPt::DAY_OF_YEAR,
        TpmPt::YEAR,
        TpmPt::MANUFACTURER,
    ];
    for prop in props {
        let get_cmd = GetCapability {
            capability: TpmCap::TPMProperties,
            property: u32::from(prop),
            property_count: 1,
        };
        let (get_rsp, _) = execute_mixed(
            &mut sim,
            &get_cmd,
            (),
            &[],
            &mut [SessionAuth::Session {
                session: &mut sess,
                auth: &[],
            }],
        )
        .unwrap();
        audit.audit_command(&get_cmd, &[], &get_rsp);

        // mimic an external audit log
        let cmd_bytes = marshal_command(&get_cmd, &[]);
        let rsp_bytes = marshal_response::<GetCapability>(&get_rsp);
        let audit_log_command = leak_bytes(&cmd_bytes);
        let audit_log_response = leak_bytes(&rsp_bytes);

        // Get the audit digest signed by the AK
        let get_audit_cmd = GetSessionAuditDigest {
            qualifying_data: Tpm2bData::from_bytes(b"foobar").unwrap(),
            in_scheme: None,
        };
        let get_audit_handles = GetSessionAuditDigestHandles {
            privacy_admin_handle: Handle::RH_ENDORSEMENT,
            sign_handle: ak_handle,
            session_handle: sess.session_handle,
        };
        // PrivacyAdminHandle and SignHandle (a NamedHandle) are both
        // authorized by go-tpm with PasswordAuth(nil).
        let (get_audit_rsp, _) = execute_mixed(
            &mut sim,
            &get_audit_cmd,
            get_audit_handles,
            &[
                &Handle::RH_ENDORSEMENT.0.to_be_bytes(),
                ak_name.get_buffer(),
                &sess.session_handle.0.to_be_bytes(),
            ],
            &mut [SessionAuth::Password(&[]), SessionAuth::Password(&[])],
        )
        .unwrap();
        // TODO check the signature with the AK pub
        let want = audit.digest().to_vec();
        let got = session_audit_digest(&get_audit_rsp);
        assert_eq!(got, want, "unexpected audit value");

        // This demonstrates that audit value can be replayed from an audit log
        let (_, cmd) = unmarshal_command::<GetCapability>(audit_log_command, 0);
        let rsp = unmarshal_response::<GetCapability>(audit_log_response);
        audit2.audit_command(&cmd, &[], &rsp);
        let got2 = audit2.digest();
        assert_eq!(got2, want.as_slice(), "unexpected audit value from replay");

        // This demonstrates that MarshalCommand/MarshalResponse provide
        // everything needed
        let cp_hash_from_bytes = Sha256::digest(&cmd_bytes);
        let rp_hash_from_bytes = Sha256::digest(&rsp_bytes);
        let mut h = Sha256::new();
        h.update(accumulated_digest);
        h.update(cp_hash_from_bytes);
        h.update(rp_hash_from_bytes);
        accumulated_digest.copy_from_slice(&h.finalize());
        assert_eq!(
            want.as_slice(),
            accumulated_digest.as_slice(),
            "unexpected audit value from direct hash reconstruction"
        );
    }

    // Deferred cleanup (Go runs defers in reverse order): flush the AK, then
    // the audit session (Go ignores the session cleanup error).
    flush_context(&mut sim, ak_handle).unwrap();
    let _ = flush_context(&mut sim, sess.session_handle);
}

// Original Go test: audit_test.go - TestAuditSessionWithCertify
#[test]
fn test_audit_session_with_certify() {
    let mut sim = create_simulator!();

    // Create the audit session
    let mut sess = start_audit_session(&mut sim);

    let auth: &[u8] = b"password";

    // Create the AK for audit
    let (ak_handle, ak_name) = create_ak_ecc(&mut sim, auth);

    // Create a key to certify
    let (key_handle, key_name) = create_certifiable_key_rsa(&mut sim);

    let original_cmd = Certify {
        qualifying_data: Tpm2bData::from_bytes(b"test").unwrap(),
        in_scheme: Some(TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha256)),
    };
    let certify_handles = CertifyHandles {
        object_handle: key_handle,
        sign_handle: ak_handle,
    };
    let names: [&[u8]; 2] = [key_name.get_buffer(), ak_name.get_buffer()];

    // Execute the command with audit session: PasswordAuth(nil) for
    // ObjectHandle, PasswordAuth(Auth) for SignHandle, plus the audit session.
    let (original_rsp, _) = execute_mixed(
        &mut sim,
        &original_cmd,
        certify_handles,
        &names,
        &mut [
            SessionAuth::Password(&[]),
            SessionAuth::Password(auth),
            SessionAuth::Session {
                session: &mut sess,
                auth: &[],
            },
        ],
    )
    .unwrap();

    // Calculate audit digest with the command/response
    let mut audit = CommandAudit::new();
    audit.audit_command(&original_cmd, &names, &original_rsp);

    // Get the audit digest signed by the AK
    let get_audit_cmd = GetSessionAuditDigest {
        qualifying_data: Tpm2bData::from_bytes(b"foobar").unwrap(),
        in_scheme: None,
    };
    let get_audit_handles = GetSessionAuditDigestHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: ak_handle,
        session_handle: sess.session_handle,
    };
    let (get_audit_rsp, _) = execute_mixed(
        &mut sim,
        &get_audit_cmd,
        get_audit_handles,
        &[
            &Handle::RH_ENDORSEMENT.0.to_be_bytes(),
            ak_name.get_buffer(),
            &sess.session_handle.0.to_be_bytes(),
        ],
        &mut [SessionAuth::Password(&[]), SessionAuth::Password(auth)],
    )
    .unwrap();

    // Verify the TPM's audit digest matches our calculated digest
    let want = session_audit_digest(&get_audit_rsp);
    let got = audit.digest();
    assert_eq!(
        want.as_slice(),
        got,
        "TPM audit digest doesn't match calculated digest"
    );

    // Marshal the command and response
    let cmd_bytes = leak_bytes(&marshal_command(&original_cmd, &names));
    let rsp_bytes = leak_bytes(&marshal_response::<Certify>(&original_rsp));

    // Unmarshal the command
    let (unmarshalled_names, unmarshalled_cmd) = unmarshal_command::<Certify>(cmd_bytes, 2);

    // Unmarshal the response
    let unmarshalled_rsp = unmarshal_response::<Certify>(rsp_bytes);

    // Calculate audit digest with unmarshalled command/response
    let mut audit2 = CommandAudit::new();
    audit2.audit_command(&unmarshalled_cmd, &unmarshalled_names, &unmarshalled_rsp);
    let got2 = audit2.digest();

    // Verify unmarshalled digest matches the original calculated digest
    assert_eq!(
        want.as_slice(),
        got2,
        "unmarshalled audit digest doesn't match original"
    );

    // Deferred cleanup (Go runs defers in reverse order): flush the key, the
    // AK, then the audit session (Go ignores the session cleanup error).
    flush_context(&mut sim, key_handle).unwrap();
    flush_context(&mut sim, ak_handle).unwrap();
    let _ = flush_context(&mut sim, sess.session_handle);
}
