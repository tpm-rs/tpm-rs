#![forbid(unsafe_code)]
//! Rust port of `sealing_test.go` (`TestUnseal`).
//!
//! The Go test runs one long sequence per SRK type (RSA, ECC) in which each
//! `t.Run` subtest mutates shared state. Here every Go subtest is its own Rust
//! `#[test]`; the state the subtest depends on is re-created by shared helpers:
//!
//! * `Create*` subtests: create the SRK, then run the single `TPM2_Create`
//!   performed by the subtest.
//! * `With*` (unseal) subtests: create the SRK, create the sealed blob exactly as
//!   the last Go `Create*` subtest did (its response is what Go loads), load it
//!   with a use-once HMAC session, then run the subtest's unseal operations.
//!
//! To match go-tpm semantics exactly (per-session nonce sizes, use-once
//! sessions that the TPM flushes, salted/bound session keys, parameter
//! encryption keys and the extra decrypt/encrypt nonces in the first session's
//! HMAC), this file contains a small go-tpm style session implementation
//! ([`GoHmacSession`]) and command executor ([`execute_go`]).

use crate::test_utils::CLIENT_CRYPTO;
use crate::test_utils::{
    CmdHeader, RespHeader, execute_with_password_sessions, flush_context, kdfa_by_alg, leak_bytes,
    marshal_to_slice, strip_trailing_zeros,
};
use tpm2::commands::{
    Command, Create, CreateHandles, CreatePrimary, CreatePrimaryHandles, Load, LoadHandles,
    StartAuthSession, StartAuthSessionHandles, Unseal, UnsealHandles,
};
use tpm2::crypto::Rng;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, Marshal, TpmSe, TpmSt, Unmarshal};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter, Tpm2bEncryptedSecret,
    Tpm2bNonce, Tpm2bPrivate, Tpm2bPublic, Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmaObject,
    TpmaSession, TpmiAlgHash, TpmiAlgSymMode, TpmiRsaKeyBits, TpmiStCommandTag, TpmlPcrSelection,
    TpmsAuthCommand, TpmsAuthResponse, TpmsEccParms, TpmsEccPoint, TpmsRsaParms,
    TpmsSensitiveCreate, TpmtPublic, TpmtSymDefObject,
};
use tpm2_simulator::{Simulator, create_simulator};

// =========================================================================
// Constants from the Go test
// =========================================================================

/// `srkAuth` in the Go test.
const SRK_AUTH: &[u8] = b"mySRK";
/// `data` in the Go test.
const DATA: &[u8] = b"secrets";
/// `auth` in the Go test (with trailing zeros to exercise TPM trimming).
const AUTH: &[u8] = b"p@ssw0rd\x00\x00";
/// `auth2` in the Go test.
const AUTH2: &[u8] = b"p@ssw0rd";

/// Zero-filled unique fields used by go-tpm's `RSASRKTemplate` (256 bytes)
/// and `ECCSRKTemplate` (32-byte X and Y).
static ZEROS_256: [u8; 256] = [0u8; 256];
static ZEROS_32: [u8; 32] = [0u8; 32];

// =========================================================================
// SRK templates (go-tpm `RSASRKTemplate` / `ECCSRKTemplate`)
// =========================================================================

/// The SRK flavor a `TestUnseal` subtest runs with.
#[derive(Clone, Copy, Debug)]
enum SrkKind {
    Rsa,
    Ecc,
}

/// Object attributes shared by go-tpm's RSA and ECC SRK templates.
fn srk_attributes() -> TpmaObject {
    TpmaObject::FIXED_TPM
        | TpmaObject::FIXED_PARENT
        | TpmaObject::SENSITIVE_DATA_ORIGIN
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::NO_DA
        | TpmaObject::RESTRICTED
        | TpmaObject::DECRYPT
}

/// go-tpm `RSASRKTemplate`.
fn rsa_srk_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: srk_attributes(),
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(&ZEROS_256).unwrap(),
        ),
    }
}

/// go-tpm `ECCSRKTemplate`.
fn ecc_srk_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: srk_attributes(),
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                scheme: None,
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(&ZEROS_32).unwrap(),
                y: Tpm2bEccParameter::from_bytes(&ZEROS_32).unwrap(),
            },
        ),
    }
}

impl SrkKind {
    fn template(self) -> TpmtPublic<'static> {
        match self {
            SrkKind::Rsa => rsa_srk_template(),
            SrkKind::Ecc => ecc_srk_template(),
        }
    }
}

// =========================================================================
// go-tpm style HMAC sessions
// =========================================================================

/// Digest size in bytes of a session hash algorithm.
fn digest_size(hash: TpmiAlgHash) -> usize {
    match hash {
        TpmiAlgHash::Sha1 => 20,
        TpmiAlgHash::Sha256 => 32,
        TpmiAlgHash::Sha384 => 48,
        TpmiAlgHash::Sha512 => 64,
        other => panic!("unsupported session hash {other:?}"),
    }
}

/// Mirrors go-tpm's `parameterEncryptiontpm2ion` (`EncryptIn`, `EncryptOut`,
/// `EncryptInOut`).
#[derive(Clone, Copy, Debug)]
enum EncryptDir {
    In,
    Out,
    InOut,
}

/// A go-tpm style HMAC session (`tpm2.HMAC(...)` / `tpm2.HMACSession(...)`).
///
/// Sessions created with [`GoHmacSession::new`] behave like `tpm2.HMAC`:
/// they are started just in time before a command, do not set
/// `continueSession`, and are therefore flushed by the TPM after one use.
/// [`GoHmacSession::start`] behaves like `tpm2.HMACSession`: it sets
/// `continueSession`, starts the session immediately, and the caller must flush
/// it (via [`GoHmacSession::close`]).
#[derive(Clone, Debug)]
struct GoHmacSession {
    hash: TpmiAlgHash,
    nonce_size: usize,
    /// `Auth(...)` value; empty when not given.
    auth: Vec<u8>,
    /// `Bound(handle, name, auth)`.
    bind: Option<(Handle, Vec<u8>, Vec<u8>)>,
    /// `Salted(handle, pub)`.
    salt: Option<(Handle, TpmtPublic<'static>)>,
    attrs: TpmaSession,
    symmetric: Option<TpmtSymDefObject>,
    /// `RH_NULL` while the session is not started.
    handle: Handle,
    session_key: Vec<u8>,
    nonce_caller: Vec<u8>,
    nonce_tpm: Vec<u8>,
}

impl GoHmacSession {
    /// `tpm2.HMAC(hash, nonceSize)` (use-once, just-in-time session).
    fn new(hash: TpmiAlgHash, nonce_size: usize) -> Self {
        Self {
            hash,
            nonce_size,
            auth: Vec::new(),
            bind: None,
            salt: None,
            attrs: TpmaSession::empty(),
            symmetric: None,
            handle: Handle::RH_NULL,
            session_key: Vec::new(),
            nonce_caller: Vec::new(),
            nonce_tpm: Vec::new(),
        }
    }

    /// `tpm2.Auth(auth)`.
    fn auth(mut self, auth: &[u8]) -> Self {
        self.auth = auth.to_vec();
        self
    }

    /// `tpm2.AESEncryption(128, dir)`.
    fn aes128(mut self, dir: EncryptDir) -> Self {
        self.attrs.set(
            TpmaSession::DECRYPT,
            matches!(dir, EncryptDir::In | EncryptDir::InOut),
        );
        self.attrs.set(
            TpmaSession::ENCRYPT,
            matches!(dir, EncryptDir::Out | EncryptDir::InOut),
        );
        self.symmetric = Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)));
        self
    }

    /// `tpm2.Audit()`.
    fn audit(mut self) -> Self {
        self.attrs |= TpmaSession::AUDIT;
        self
    }

    /// `tpm2.AuditExclusive()`.
    fn audit_exclusive(mut self) -> Self {
        self.attrs |= TpmaSession::AUDIT | TpmaSession::AUDIT_EXCLUSIVE;
        self
    }

    /// `tpm2.Salted(handle, pub)`.
    fn salted(mut self, handle: Handle, public: TpmtPublic<'static>) -> Self {
        self.salt = Some((handle, public));
        self
    }

    /// `tpm2.Bound(handle, name, auth)`.
    fn bound(mut self, handle: Handle, name: &[u8], auth: &[u8]) -> Self {
        self.bind = Some((handle, name.to_vec(), auth.to_vec()));
        self
    }

    /// `tpm2.HMACSession(...)`: marks the session reusable and starts it.
    fn start(mut self, sim: &mut Simulator<'_>) -> Self {
        self.attrs |= TpmaSession::CONTINUE_SESSION;
        self.init(sim);
        self
    }

    /// The `close` function returned by `tpm2.HMACSession`. Go calls it via
    /// `defer cleanup()`, ignoring its error, so the result is ignored here too.
    fn close(self, sim: &mut Simulator<'_>) {
        let _ = flush_context(sim, self.handle);
    }

    /// go-tpm `hmacSession.Init`: starts the session if not yet started.
    fn init(&mut self, sim: &mut Simulator<'_>) {
        if self.handle != Handle::RH_NULL {
            return;
        }
        self.nonce_caller = vec![0u8; self.nonce_size];
        CLIENT_CRYPTO.get_random(&mut self.nonce_caller).unwrap();

        let (tpm_key, encrypted_salt, salt) = match &self.salt {
            Some((handle, public)) => {
                let (encrypted_salt, salt) = encrypted_salt(sim, public);
                (*handle, encrypted_salt, salt)
            }
            None => (Handle::RH_NULL, Tpm2bEncryptedSecret::default(), Vec::new()),
        };
        let bind = self.bind.as_ref().map_or(Handle::RH_NULL, |b| b.0);
        let cmd = StartAuthSession {
            nonce_caller: Tpm2bNonce::from_bytes(leak_bytes(&self.nonce_caller)).unwrap(),
            encrypted_salt,
            session_type: TpmSe::HMAC,
            symmetric: self.symmetric.map(tpm2::TpmtSymDef::from),
            auth_hash: self.hash,
        };
        let handles = StartAuthSessionHandles { tpm_key, bind };
        let (rsp, rsp_handles) = execute_with_password_sessions(sim, &cmd, handles, 0, &[])
            .expect("TPM2_StartAuthSession failed");
        self.handle = rsp_handles.session_handle;
        self.nonce_tpm = rsp.nonce_tpm.get_buffer().to_vec();

        // Part 1, 19.6
        self.session_key = if self.bind.is_some() || !salt.is_empty() {
            let mut key = self
                .bind
                .as_ref()
                .map_or_else(Vec::new, |(_, _, auth)| auth.clone());
            key.extend_from_slice(&salt);
            let bits = (digest_size(self.hash) * 8) as u32;
            let mut out = vec![0u8; digest_size(self.hash)];
            kdfa_by_alg(
                CLIENT_CRYPTO,
                self.hash,
                &key,
                b"ATH",
                &self.nonce_tpm,
                &self.nonce_caller,
                bits,
                &mut out,
            );
            out
        } else {
            Vec::new()
        };
    }

    /// go-tpm `hmacSession.NewNonceCaller`.
    fn new_nonce_caller(&mut self, _sim: &mut Simulator<'_>) {
        CLIENT_CRYPTO.get_random(&mut self.nonce_caller).unwrap();
    }

    /// HMAC key (Part 1, 19.6): sessionKey || auth, unless this session is
    /// authorizing its bind target.
    fn hmac_key(&self, names: &[&[u8]], auth_index: usize) -> Vec<u8> {
        let mut key = self.session_key.clone();
        let is_bind_target = match &self.bind {
            Some((_, bind_name, _)) => {
                !bind_name.is_empty()
                    && auth_index < names.len()
                    && names[auth_index] == bind_name.as_slice()
            }
            None => false,
        };
        if !is_bind_target {
            key.extend_from_slice(strip_trailing_zeros(&self.auth));
        }
        key
    }

    /// Runs AES-CFB parameter encryption/decryption as go-tpm does: the key is
    /// derived from sessionKey || auth with the given nonce order.
    fn param_crypt(
        &self,
        _sim: &Simulator<'_>,
        nonce_newer: &[u8],
        nonce_older: &[u8],
        decrypt: bool,
        param: &mut [u8],
    ) {
        let sym = self.symmetric.expect("parameter encryption needs AES");
        let key_bytes = match sym {
            TpmtSymDefObject::Aes128(_) => 16,
            TpmtSymDefObject::Aes256(_) => 32,
            other => panic!("unsupported session symmetric {other:?}"),
        };
        let mut session_value = self.session_key.clone();
        session_value.extend_from_slice(&self.auth);
        let mut key_iv = vec![0u8; key_bytes + 16];
        kdfa_by_alg(
            CLIENT_CRYPTO,
            self.hash,
            &session_value,
            b"CFB",
            nonce_newer,
            nonce_older,
            ((key_bytes + 16) * 8) as u32,
            &mut key_iv,
        );
        let (key, iv) = key_iv.split_at_mut(key_bytes);
        let alg = TpmtSymDefObject::aes_cfb((key_bytes * 8) as u16).unwrap();
        if decrypt {
            tpm2::crypto::decrypt(CLIENT_CRYPTO, alg, key, iv, param).unwrap();
        } else {
            tpm2::crypto::encrypt(CLIENT_CRYPTO, alg, key, iv, param).unwrap();
        }
    }
}

/// go-tpm `getEncryptedSalt`: RSA-OAEP or ECDH (KDFe) salt encapsulation with
/// label "SECRET" against the salt key's public area.
fn encrypted_salt(
    _sim: &mut Simulator<'_>,
    public: &TpmtPublic<'static>,
) -> (Tpm2bEncryptedSecret<'static>, Vec<u8>) {
    let name_alg = public.name_alg.expect("salt key must have a name alg");
    match &public.parms_and_id {
        PublicParmsAndId::Rsa(_, pub_key_rsa) => {
            use tpm2::crypto::Asymmetric;
            let mut salt = vec![0u8; digest_size(name_alg)];
            CLIENT_CRYPTO.get_random(&mut salt).unwrap();
            let mut ciphertext = [0u8; 512];
            let len = CLIENT_CRYPTO
                .encrypt(
                    tpm2::Alg::OAEP,
                    name_alg.into(),
                    pub_key_rsa.get_buffer(),
                    &salt,
                    &mut ciphertext,
                    b"SECRET\0",
                )
                .unwrap();
            (
                Tpm2bEncryptedSecret::from_bytes(leak_bytes(&ciphertext[..len])).unwrap(),
                salt,
            )
        }
        PublicParmsAndId::Ecc(_, ecc_unique) => {
            use p256::{PublicKey, SecretKey, elliptic_curve::sec1::ToEncodedPoint};
            assert_eq!(name_alg, TpmiAlgHash::Sha256, "only SHA256 KDFe supported");

            // Ephemeral P-256 key pair.
            let eph_priv = SecretKey::random(&mut rand::thread_rng());
            let eph_encoded = eph_priv.public_key().to_encoded_point(false);
            let eph_x = eph_encoded.x().unwrap();
            let eph_y = eph_encoded.y().unwrap();

            // TPM public key.
            let tpm_x = ecc_unique.x.get_buffer();
            let tpm_y = ecc_unique.y.get_buffer();
            let mut tpm_sec1 = [0u8; 65];
            tpm_sec1[0] = 0x04;
            tpm_sec1[33 - tpm_x.len()..33].copy_from_slice(tpm_x);
            tpm_sec1[65 - tpm_y.len()..65].copy_from_slice(tpm_y);
            let tpm_pub = PublicKey::from_sec1_bytes(&tpm_sec1).unwrap();

            let z = p256::ecdh::diffie_hellman(eph_priv.to_nonzero_scalar(), tpm_pub.as_affine());
            let mut padded_tpm_x = [0u8; 32];
            padded_tpm_x[32 - tpm_x.len()..].copy_from_slice(tpm_x);
            let mut salt = vec![0u8; 32];
            tpm2::crypto::kdf::kdfe(
                CLIENT_CRYPTO,
                TpmiAlgHash::Sha256,
                z.raw_secret_bytes().as_slice(),
                b"SECRET",
                eph_x,
                &padded_tpm_x,
                256,
                &mut salt,
            )
            .unwrap();

            let point = TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(eph_x).unwrap(),
                y: Tpm2bEccParameter::from_bytes(eph_y).unwrap(),
            };
            let mut buf = [0u8; 1024];
            let len = marshal_to_slice(&point, &mut buf);
            (
                Tpm2bEncryptedSecret::from_bytes(leak_bytes(&buf[..len])).unwrap(),
                salt,
            )
        }
        _ => panic!("unsupported salt key type"),
    }
}

/// Computes a digest with the simulator's crypto provider.
fn hash(_sim: &Simulator<'_>, alg: TpmiAlgHash, parts: &[&[u8]]) -> Vec<u8> {
    let mut ctx = tpm2::crypto::HashCtx::new(CLIENT_CRYPTO, alg).unwrap();
    for p in parts {
        ctx.update(p).unwrap();
    }
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    ctx.finalize(&mut out).unwrap().digest().to_vec()
}

/// Computes an HMAC with the simulator's crypto provider.
fn hmac(_sim: &Simulator<'_>, alg: TpmiAlgHash, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut ctx = tpm2::crypto::HmacCtx::new(CLIENT_CRYPTO, alg, key).unwrap();
    for p in parts {
        ctx.update(p).unwrap();
    }
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    ctx.finalize(&mut out).unwrap().digest().to_vec()
}

/// go-tpm `execute(...)` with HMAC sessions: the sessions authorizing the
/// command handles come first, followed by any extra sessions. `names` are the
/// names of the command handles (as supplied via `AuthHandle`/`NamedHandle` in
/// Go). Returns the TPM response code on failure, after flushing use-once
/// sessions (go-tpm `CleanupFailure`).
fn execute_go<CmdT: Command>(
    sim: &mut Simulator<'_>,
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    names: &[&[u8]],
    sessions: &mut [&mut GoHmacSession],
) -> Result<(CmdT::Response<'static>, CmdT::RespHandles), u32>
where
    CmdT::Response<'static>: Unmarshal<'static>,
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    assert!(
        !sessions.is_empty() && sessions.len() <= 3,
        "bad session count"
    );
    for s in sessions.iter_mut() {
        s.init(sim);
        s.new_nonce_caller(sim);
    }

    // Parameters, with the first parameter encrypted by a decrypt session.
    let mut param_buf = vec![0u8; 16384];
    let param_len = marshal_to_slice(cmd, &mut param_buf);
    param_buf.truncate(param_len);
    for s in sessions.iter() {
        if s.attrs.contains(TpmaSession::DECRYPT) {
            let size = u16::from_be_bytes([param_buf[0], param_buf[1]]) as usize;
            s.param_crypt(
                sim,
                &s.nonce_caller,
                &s.nonce_tpm,
                false,
                &mut param_buf[2..2 + size],
            );
        }
    }

    // Extra nonceTPMs (decrypt, then encrypt) for the first session's HMAC.
    let mut enc_nonce_tpm: Option<Vec<u8>> = None;
    let mut dec_nonce_tpm: Option<Vec<u8>> = None;
    for s in sessions.iter().skip(1) {
        if s.attrs.contains(TpmaSession::ENCRYPT) {
            assert!(enc_nonce_tpm.is_none(), "too many encrypt sessions");
            enc_nonce_tpm = Some(s.nonce_tpm.clone());
            continue;
        }
        if s.attrs.contains(TpmaSession::DECRYPT) {
            assert!(dec_nonce_tpm.is_none(), "too many decrypt sessions");
            dec_nonce_tpm = Some(s.nonce_tpm.clone());
        }
    }

    // Authorization area.
    let cc = CmdT::CMD_CODE.code().to_be_bytes();
    let mut auth_area = Vec::new();
    for (i, s) in sessions.iter().enumerate() {
        let mut add_nonces = Vec::new();
        if i == 0 {
            add_nonces.extend_from_slice(dec_nonce_tpm.as_deref().unwrap_or_default());
            add_nonces.extend_from_slice(enc_nonce_tpm.as_deref().unwrap_or_default());
        }
        let mut cp_parts: Vec<&[u8]> = vec![&cc];
        cp_parts.extend_from_slice(names);
        cp_parts.push(&param_buf);
        let cp_hash = hash(sim, s.hash, &cp_parts);
        let key = s.hmac_key(names, i);
        let mac = hmac(
            sim,
            s.hash,
            &key,
            &[
                &cp_hash,
                &s.nonce_caller,
                &s.nonce_tpm,
                &add_nonces,
                &[s.attrs.bits()],
            ],
        );
        let auth_cmd = TpmsAuthCommand {
            session_handle: s.handle,
            nonce: Tpm2bNonce::from_bytes(leak_bytes(&s.nonce_caller)).unwrap(),
            session_attributes: s.attrs,
            hmac: Tpm2bAuth::from_bytes(leak_bytes(&mac)).unwrap(),
        };
        let mut buf = [0u8; 1024];
        let len = marshal_to_slice(&auth_cmd, &mut buf);
        auth_area.extend_from_slice(&buf[..len]);
    }

    // Assemble the command.
    let mut cmd_buf = vec![0u8; 16384];
    let mut header = CmdHeader {
        tag: TpmiStCommandTag::Sessions,
        size: 0,
        code: CmdT::CMD_CODE,
    };
    let mut written = 10;
    written += marshal_to_slice(&cmd_handles, &mut cmd_buf[written..]);
    cmd_buf[written..written + 4].copy_from_slice(&(auth_area.len() as u32).to_be_bytes());
    written += 4;
    cmd_buf[written..written + auth_area.len()].copy_from_slice(&auth_area);
    written += auth_area.len();
    cmd_buf[written..written + param_buf.len()].copy_from_slice(&param_buf);
    written += param_buf.len();
    header.size = written as u32;
    header.marshal((&mut cmd_buf[0..10]).try_into().unwrap());

    let mut rsp_buf = [0u8; 16384];
    let rsp_bytes = sim
        .transact(&cmd_buf[..written], &mut rsp_buf)
        .unwrap()
        .to_vec();

    let mut slice: &[u8] = &rsp_bytes;
    let rsp_header = RespHeader::unmarshal(&mut slice).unwrap();
    if rsp_header.rc != 0 {
        // go-tpm CleanupFailure: flush sessions the TPM would otherwise have
        // flushed after use.
        for s in sessions.iter_mut() {
            if !s.attrs.contains(TpmaSession::CONTINUE_SESSION) {
                flush_context(sim, s.handle).expect("flushing use-once session");
                s.handle = Handle::RH_NULL;
            }
        }
        return Err(rsp_header.rc);
    }
    let rsp_handles = CmdT::RespHandles::unmarshal(&mut slice).unwrap();
    assert_eq!(rsp_header.tag, TpmSt::SESSIONS);
    let param_size = u32::unmarshal(&mut slice).unwrap() as usize;
    let (rsp_params, mut sess_slice) = slice.split_at(param_size);
    let mut rsp_params = rsp_params.to_vec();

    // Validate response sessions.
    let rc = 0u32.to_be_bytes();
    for (i, s) in sessions.iter_mut().enumerate() {
        let auth_rsp = TpmsAuthResponse::unmarshal(&mut sess_slice).unwrap();
        s.nonce_tpm = auth_rsp.nonce.get_buffer().to_vec();
        if !auth_rsp
            .session_attributes
            .contains(TpmaSession::CONTINUE_SESSION)
        {
            s.handle = Handle::RH_NULL;
        }
        let rp_hash = hash(sim, s.hash, &[&rc, &cc, &rsp_params]);
        let key = s.hmac_key(names, i);
        let mac = hmac(
            sim,
            s.hash,
            &key,
            &[
                &rp_hash,
                &s.nonce_tpm,
                &s.nonce_caller,
                &[auth_rsp.session_attributes.bits()],
            ],
        );
        assert_eq!(
            mac.as_slice(),
            auth_rsp.hmac.get_buffer(),
            "session {i}: incorrect authorization HMAC"
        );
    }

    // Decrypt the first response parameter with an encrypt session.
    for s in sessions.iter() {
        if s.attrs.contains(TpmaSession::ENCRYPT) && !rsp_params.is_empty() {
            let size = u16::from_be_bytes([rsp_params[0], rsp_params[1]]) as usize;
            s.param_crypt(
                sim,
                &s.nonce_tpm,
                &s.nonce_caller,
                true,
                &mut rsp_params[2..2 + size],
            );
        }
    }

    let mut params: &'static [u8] = leak_bytes(&rsp_params);
    let rsp = <CmdT::Response<'static>>::unmarshal(&mut params).unwrap();
    Ok((rsp, rsp_handles))
}

// =========================================================================
// Test fixture
// =========================================================================

/// The SRK created at the start of `unsealingTest`.
struct Srk {
    handle: Handle,
    name: Vec<u8>,
    /// `createSRKRsp.OutPublic`.
    public: TpmtPublic<'static>,
}

/// `unsealingTest` prologue: creates the SRK with `srkAuth`.
fn create_srk(sim: &mut Simulator<'_>, kind: SrkKind) -> Srk {
    let cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(SRK_AUTH).unwrap(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(kind.template()),
        ..Default::default()
    };
    let handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (rsp, rsp_handles) = execute_with_password_sessions(sim, &cmd, handles, 1, &[])
        .expect("TPM2_CreatePrimary failed");
    Srk {
        handle: rsp_handles.object_handle,
        name: rsp.name.get_buffer().to_vec(),
        public: rsp.out_public.0,
    }
}

/// `createBlobCmd` from the Go test (without the parent auth).
fn create_blob_cmd() -> Create<'static> {
    Create {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(AUTH).unwrap(),
            data: Tpm2bSensitiveData::from_bytes(DATA).unwrap(),
        }),
        in_public: tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::NO_DA,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    }
}

/// Runs `createBlobCmd` with `PasswordAuth(srkAuth)` on the parent.
fn create_blob_with_password(sim: &mut Simulator<'_>, srk: &Srk) {
    let handles = CreateHandles {
        parent_handle: srk.handle,
    };
    execute_with_password_sessions(sim, &create_blob_cmd(), handles, 1, SRK_AUTH)
        .expect("TPM2_Create failed");
}

/// Runs `createBlobCmd` with the given parent auth session followed by extra
/// sessions, returning `(OutPrivate, OutPublic)`.
fn create_blob_with_sessions(
    sim: &mut Simulator<'_>,
    srk: &Srk,
    sessions: &mut [&mut GoHmacSession],
) -> (Tpm2bPrivate<'static>, Tpm2bPublic<'static>) {
    let handles = CreateHandles {
        parent_handle: srk.handle,
    };
    let (rsp, _) = execute_go(sim, &create_blob_cmd(), handles, &[&srk.name], sessions)
        .expect("TPM2_Create failed");
    (rsp.out_private, rsp.out_public)
}

/// Runs a `Create*` subtest: creates the SRK, runs `create` and flushes the
/// SRK (the deferred cleanup in `unsealingTest`).
fn run_create_subtest(kind: SrkKind, create: impl FnOnce(&mut Simulator<'_>, &Srk)) {
    let mut sim = create_simulator!();
    let srk = create_srk(&mut sim, kind);
    create(&mut sim, &srk);
    flush_context(&mut sim, srk.handle).expect("flushing SRK");
}

/// A `Create*` subtest whose parent auth is a single use-once HMAC session
/// (`HMAC(TPMAlgSHA256, 16, Auth(srkAuth), opts...)`).
fn run_create_parent_hmac(kind: SrkKind, opts: impl FnOnce(GoHmacSession, &Srk) -> GoHmacSession) {
    run_create_subtest(kind, |sim, srk| {
        let mut parent = opts(
            GoHmacSession::new(TpmiAlgHash::Sha256, 16).auth(SRK_AUTH),
            srk,
        );
        create_blob_with_sessions(sim, srk, &mut [&mut parent]);
    });
}

/// A `Create*Separate` subtest: parent auth is
/// `HMAC(TPMAlgSHA256, 16, Auth(srkAuth))`, plus the given extra sessions.
fn run_create_separate(kind: SrkKind, mut extra: Vec<GoHmacSession>) {
    run_create_subtest(kind, |sim, srk| {
        let mut parent = GoHmacSession::new(TpmiAlgHash::Sha256, 16).auth(SRK_AUTH);
        let mut sessions: Vec<&mut GoHmacSession> = vec![&mut parent];
        sessions.extend(extra.iter_mut());
        create_blob_with_sessions(sim, srk, &mut sessions);
    });
}

/// The state shared by the unseal (`With*`) subtests.
struct LoadedBlob {
    handle: Handle,
    name: Vec<u8>,
}

/// Runs an unseal (`With*`) subtest.
///
/// Reproduces the Go state before the unseal subtests: the SRK, the blob from
/// the final `Create*` subtest (`CreateDecryptEncrypt2Separate#01`, whose
/// response Go loads), and the blob loaded with
/// `HMAC(TPMAlgSHA256, 16, Auth(srkAuth))`. Then runs `unseal` and performs the
/// deferred cleanup (flush blob, then SRK).
fn run_unseal_subtest(kind: SrkKind, unseal: impl FnOnce(&mut Simulator<'_>, &Srk, &LoadedBlob)) {
    let mut sim = create_simulator!();
    let srk = create_srk(&mut sim, kind);

    let mut parent = GoHmacSession::new(TpmiAlgHash::Sha256, 16).auth(SRK_AUTH);
    let mut enc = GoHmacSession::new(TpmiAlgHash::Sha1, 17).aes128(EncryptDir::Out);
    let mut dec = GoHmacSession::new(TpmiAlgHash::Sha256, 32).aes128(EncryptDir::In);
    let (out_private, out_public) =
        create_blob_with_sessions(&mut sim, &srk, &mut [&mut parent, &mut enc, &mut dec]);

    // Load the sealed blob.
    let mut load_auth = GoHmacSession::new(TpmiAlgHash::Sha256, 16).auth(SRK_AUTH);
    let (load_rsp, load_handles) = execute_go(
        &mut sim,
        &Load {
            in_private: out_private,
            in_public: out_public,
        },
        LoadHandles {
            parent_handle: srk.handle,
        },
        &[&srk.name],
        &mut [&mut load_auth],
    )
    .expect("TPM2_Load failed");
    let blob = LoadedBlob {
        handle: load_handles.object_handle,
        name: load_rsp.name.get_buffer().to_vec(),
    };

    unseal(&mut sim, &srk, &blob);

    flush_context(&mut sim, blob.handle).expect("flushing blob");
    flush_context(&mut sim, srk.handle).expect("flushing SRK");
}

/// `unsealCmd.Execute(thetpm, extra...)` with the item authorized by `auth`;
/// asserts the unsealed data equals `data`.
fn unseal_with_sessions(
    sim: &mut Simulator<'_>,
    blob: &LoadedBlob,
    sessions: &mut [&mut GoHmacSession],
) {
    let (rsp, _) = execute_go(
        sim,
        &Unseal {},
        UnsealHandles {
            item_handle: blob.handle,
        },
        &[&blob.name],
        sessions,
    )
    .expect("TPM2_Unseal failed");
    assert_eq!(rsp.out_data.get_buffer(), DATA);
}

// =========================================================================
// Subtest bodies (shared by RSA and ECC)
// =========================================================================

fn create(kind: SrkKind) {
    run_create_subtest(kind, create_blob_with_password);
}

fn create_audit(kind: SrkKind) {
    run_create_parent_hmac(kind, |s, _| s.audit_exclusive());
}

fn create_decrypt(kind: SrkKind) {
    run_create_parent_hmac(kind, |s, _| s.aes128(EncryptDir::In));
}

fn create_encrypt(kind: SrkKind) {
    run_create_parent_hmac(kind, |s, _| s.aes128(EncryptDir::Out));
}

fn create_decrypt_encrypt(kind: SrkKind) {
    run_create_parent_hmac(kind, |s, _| s.aes128(EncryptDir::InOut));
}

fn create_decrypt_encrypt_audit(kind: SrkKind) {
    run_create_parent_hmac(kind, |s, _| s.aes128(EncryptDir::InOut).audit());
}

fn create_decrypt_encrypt_salted(kind: SrkKind) {
    run_create_parent_hmac(kind, |s, srk| {
        s.aes128(EncryptDir::InOut).salted(srk.handle, srk.public)
    });
}

fn create_decrypt_encrypt_separate(kind: SrkKind) {
    run_create_separate(
        kind,
        vec![GoHmacSession::new(TpmiAlgHash::Sha256, 16).aes128(EncryptDir::InOut)],
    );
}

fn create_decrypt_encrypt_audit_separate(kind: SrkKind) {
    run_create_separate(
        kind,
        vec![
            GoHmacSession::new(TpmiAlgHash::Sha256, 16).aes128(EncryptDir::InOut),
            GoHmacSession::new(TpmiAlgHash::Sha256, 16).audit(),
        ],
    );
}

fn create_decrypt_encrypt_audit_exclusive_separate(kind: SrkKind) {
    run_create_separate(
        kind,
        vec![
            GoHmacSession::new(TpmiAlgHash::Sha256, 16).aes128(EncryptDir::InOut),
            GoHmacSession::new(TpmiAlgHash::Sha256, 16).audit_exclusive(),
        ],
    );
}

fn create_decrypt_encrypt2_separate(kind: SrkKind) {
    run_create_separate(
        kind,
        vec![
            GoHmacSession::new(TpmiAlgHash::Sha1, 20).aes128(EncryptDir::In),
            GoHmacSession::new(TpmiAlgHash::Sha384, 23).aes128(EncryptDir::Out),
        ],
    );
}

fn create_decrypt_encrypt2_separate_01(kind: SrkKind) {
    run_create_separate(
        kind,
        vec![
            GoHmacSession::new(TpmiAlgHash::Sha1, 17).aes128(EncryptDir::Out),
            GoHmacSession::new(TpmiAlgHash::Sha256, 32).aes128(EncryptDir::In),
        ],
    );
}

fn with_password(kind: SrkKind) {
    run_unseal_subtest(kind, |sim, _srk, blob| {
        let (rsp, _) = execute_with_password_sessions(
            sim,
            &Unseal {},
            UnsealHandles {
                item_handle: blob.handle,
            },
            1,
            AUTH,
        )
        .expect("TPM2_Unseal failed");
        assert_eq!(rsp.out_data.get_buffer(), DATA);
    });
}

fn with_wrong_password(kind: SrkKind) {
    run_unseal_subtest(kind, |sim, _srk, blob| {
        let err = execute_with_password_sessions(
            sim,
            &Unseal {},
            UnsealHandles {
                item_handle: blob.handle,
            },
            1,
            b"NotThePassword",
        )
        .expect_err("unseal with wrong password must fail");
        // TPM_RC_BAD_AUTH, as a format-1 error on session 1.
        assert_eq!(err, TpmRc::BAD_AUTH.with(Position::session(1)).get());
    });
}

fn with_hmac(kind: SrkKind) {
    run_unseal_subtest(kind, |sim, _srk, blob| {
        let mut sess = GoHmacSession::new(TpmiAlgHash::Sha256, 16).auth(AUTH2);
        unseal_with_sessions(sim, blob, &mut [&mut sess]);
    });
}

fn with_hmac_encrypt(kind: SrkKind) {
    run_unseal_subtest(kind, |sim, _srk, blob| {
        let mut sess = GoHmacSession::new(TpmiAlgHash::Sha256, 16)
            .auth(AUTH2)
            .aes128(EncryptDir::Out);
        unseal_with_sessions(sim, blob, &mut [&mut sess]);
    });
}

fn with_hmac_session(kind: SrkKind) {
    run_unseal_subtest(kind, |sim, _srk, blob| {
        let mut sess = GoHmacSession::new(TpmiAlgHash::Sha1, 20)
            .auth(AUTH2)
            .start(sim);
        // It should be possible to use the session multiple times.
        for _ in 0..3 {
            unseal_with_sessions(sim, blob, &mut [&mut sess]);
        }
        sess.close(sim);
    });
}

fn with_hmac_session_encrypt(kind: SrkKind) {
    run_unseal_subtest(kind, |sim, srk, blob| {
        let mut sess = GoHmacSession::new(TpmiAlgHash::Sha256, 16)
            .auth(AUTH2)
            .aes128(EncryptDir::Out)
            .bound(srk.handle, &srk.name, SRK_AUTH)
            .start(sim);
        // It should be possible to use the session multiple times.
        for _ in 0..3 {
            unseal_with_sessions(sim, blob, &mut [&mut sess]);
        }
        sess.close(sim);
    });
}

fn with_hmac_session_encrypt_separate(kind: SrkKind) {
    run_unseal_subtest(kind, |sim, srk, blob| {
        let mut sess1 = GoHmacSession::new(TpmiAlgHash::Sha1, 16)
            .auth(AUTH2)
            .start(sim);
        let mut sess2 = GoHmacSession::new(TpmiAlgHash::Sha384, 16)
            .aes128(EncryptDir::Out)
            .bound(srk.handle, &srk.name, SRK_AUTH)
            .start(sim);
        // It should be possible to use the sessions multiple times.
        for _ in 0..3 {
            unseal_with_sessions(sim, blob, &mut [&mut sess1, &mut sess2]);
        }
        // Deferred cleanups run in reverse order.
        sess2.close(sim);
        sess1.close(sim);
    });
}

// =========================================================================
// TestUnseal/RSA
// =========================================================================

// Original Go test: sealing_test.go - TestUnseal/RSA/Create
#[test]
fn test_unseal_rsa_create() {
    create(SrkKind::Rsa);
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateAudit
#[test]
fn test_unseal_rsa_create_audit() {
    create_audit(SrkKind::Rsa);
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateDecrypt
#[test]
fn test_unseal_rsa_create_decrypt() {
    create_decrypt(SrkKind::Rsa);
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateEncrypt
#[test]
fn test_unseal_rsa_create_encrypt() {
    create_encrypt(SrkKind::Rsa);
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateDecryptEncrypt
#[test]
fn test_unseal_rsa_create_decrypt_encrypt() {
    create_decrypt_encrypt(SrkKind::Rsa);
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateDecryptEncryptAudit
#[test]
fn test_unseal_rsa_create_decrypt_encrypt_audit() {
    create_decrypt_encrypt_audit(SrkKind::Rsa);
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateDecryptEncryptSalted
#[test]
fn test_unseal_rsa_create_decrypt_encrypt_salted() {
    create_decrypt_encrypt_salted(SrkKind::Rsa);
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateDecryptEncryptSeparate
#[test]
fn test_unseal_rsa_create_decrypt_encrypt_separate() {
    create_decrypt_encrypt_separate(SrkKind::Rsa);
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateDecryptEncryptAuditSeparate
#[test]
fn test_unseal_rsa_create_decrypt_encrypt_audit_separate() {
    create_decrypt_encrypt_audit_separate(SrkKind::Rsa);
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateDecryptEncryptAuditExclusiveSeparate
#[test]
fn test_unseal_rsa_create_decrypt_encrypt_audit_exclusive_separate() {
    create_decrypt_encrypt_audit_exclusive_separate(SrkKind::Rsa);
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateDecryptEncrypt2Separate
#[test]
fn test_unseal_rsa_create_decrypt_encrypt2_separate() {
    create_decrypt_encrypt2_separate(SrkKind::Rsa);
}

// Original Go test: sealing_test.go - TestUnseal/RSA/CreateDecryptEncrypt2Separate#01
#[test]
fn test_unseal_rsa_create_decrypt_encrypt2_separate_01() {
    create_decrypt_encrypt2_separate_01(SrkKind::Rsa);
}

// Original Go test: sealing_test.go - TestUnseal/RSA/WithPassword
#[test]
fn test_unseal_rsa_with_password() {
    with_password(SrkKind::Rsa);
}

// Original Go test: sealing_test.go - TestUnseal/RSA/WithWrongPassword
#[test]
fn test_unseal_rsa_with_wrong_password() {
    with_wrong_password(SrkKind::Rsa);
}

// Original Go test: sealing_test.go - TestUnseal/RSA/WithHMAC
#[test]
fn test_unseal_rsa_with_hmac() {
    with_hmac(SrkKind::Rsa);
}

// Original Go test: sealing_test.go - TestUnseal/RSA/WithHMACEncrypt
#[test]
fn test_unseal_rsa_with_hmac_encrypt() {
    with_hmac_encrypt(SrkKind::Rsa);
}

// Original Go test: sealing_test.go - TestUnseal/RSA/WithHMACSession
#[test]
fn test_unseal_rsa_with_hmac_session() {
    with_hmac_session(SrkKind::Rsa);
}

// Original Go test: sealing_test.go - TestUnseal/RSA/WithHMACSessionEncrypt
#[test]
fn test_unseal_rsa_with_hmac_session_encrypt() {
    with_hmac_session_encrypt(SrkKind::Rsa);
}

// Original Go test: sealing_test.go - TestUnseal/RSA/WithHMACSessionEncryptSeparate
#[test]
fn test_unseal_rsa_with_hmac_session_encrypt_separate() {
    with_hmac_session_encrypt_separate(SrkKind::Rsa);
}

// =========================================================================
// TestUnseal/ECC
// =========================================================================

// Original Go test: sealing_test.go - TestUnseal/ECC/Create
#[test]
fn test_unseal_ecc_create() {
    create(SrkKind::Ecc);
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateAudit
#[test]
fn test_unseal_ecc_create_audit() {
    create_audit(SrkKind::Ecc);
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateDecrypt
#[test]
fn test_unseal_ecc_create_decrypt() {
    create_decrypt(SrkKind::Ecc);
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateEncrypt
#[test]
fn test_unseal_ecc_create_encrypt() {
    create_encrypt(SrkKind::Ecc);
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateDecryptEncrypt
#[test]
fn test_unseal_ecc_create_decrypt_encrypt() {
    create_decrypt_encrypt(SrkKind::Ecc);
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateDecryptEncryptAudit
#[test]
fn test_unseal_ecc_create_decrypt_encrypt_audit() {
    create_decrypt_encrypt_audit(SrkKind::Ecc);
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateDecryptEncryptSalted
#[test]
fn test_unseal_ecc_create_decrypt_encrypt_salted() {
    create_decrypt_encrypt_salted(SrkKind::Ecc);
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateDecryptEncryptSeparate
#[test]
fn test_unseal_ecc_create_decrypt_encrypt_separate() {
    create_decrypt_encrypt_separate(SrkKind::Ecc);
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateDecryptEncryptAuditSeparate
#[test]
fn test_unseal_ecc_create_decrypt_encrypt_audit_separate() {
    create_decrypt_encrypt_audit_separate(SrkKind::Ecc);
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateDecryptEncryptAuditExclusiveSeparate
#[test]
fn test_unseal_ecc_create_decrypt_encrypt_audit_exclusive_separate() {
    create_decrypt_encrypt_audit_exclusive_separate(SrkKind::Ecc);
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateDecryptEncrypt2Separate
#[test]
fn test_unseal_ecc_create_decrypt_encrypt2_separate() {
    create_decrypt_encrypt2_separate(SrkKind::Ecc);
}

// Original Go test: sealing_test.go - TestUnseal/ECC/CreateDecryptEncrypt2Separate#01
#[test]
fn test_unseal_ecc_create_decrypt_encrypt2_separate_01() {
    create_decrypt_encrypt2_separate_01(SrkKind::Ecc);
}

// Original Go test: sealing_test.go - TestUnseal/ECC/WithPassword
#[test]
fn test_unseal_ecc_with_password() {
    with_password(SrkKind::Ecc);
}

// Original Go test: sealing_test.go - TestUnseal/ECC/WithWrongPassword
#[test]
fn test_unseal_ecc_with_wrong_password() {
    with_wrong_password(SrkKind::Ecc);
}

// Original Go test: sealing_test.go - TestUnseal/ECC/WithHMAC
#[test]
fn test_unseal_ecc_with_hmac() {
    with_hmac(SrkKind::Ecc);
}

// Original Go test: sealing_test.go - TestUnseal/ECC/WithHMACEncrypt
#[test]
fn test_unseal_ecc_with_hmac_encrypt() {
    with_hmac_encrypt(SrkKind::Ecc);
}

// Original Go test: sealing_test.go - TestUnseal/ECC/WithHMACSession
#[test]
fn test_unseal_ecc_with_hmac_session() {
    with_hmac_session(SrkKind::Ecc);
}

// Original Go test: sealing_test.go - TestUnseal/ECC/WithHMACSessionEncrypt
#[test]
fn test_unseal_ecc_with_hmac_session_encrypt() {
    with_hmac_session_encrypt(SrkKind::Ecc);
}

// Original Go test: sealing_test.go - TestUnseal/ECC/WithHMACSessionEncryptSeparate
#[test]
fn test_unseal_ecc_with_hmac_session_encrypt_separate() {
    with_hmac_session_encrypt_separate(SrkKind::Ecc);
}
