//! Shared helpers for the end-to-end tests in `testing/tests/`.
//!
//! This module collects every reusable, non-test item used by the black-box
//! E2E tests: client-side crypto ([`CLIENT_CRYPTO`], [`client_rng`]), command
//! execution with password/HMAC sessions, raw command builders, object
//! templates, reference computations and assorted constants. It is also
//! re-exported as `testing::test_utils` (used by the Go parity tests in `tests/go/`).
//!
//! Tests treat the TPM as a black box: every helper talks to it only through
//! the command interface of [`Tpm`] (which, with the `differential` feature,
//! mirrors every interaction to the C reference TPM). Client-side randomness
//! comes from [`client_rng`] / [`CLIENT_CRYPTO`] (OS entropy), and sleeps must
//! go through [`sleep`], which advances the TPMs' virtual clocks (keeping the
//! C reference TPM, whose randomness depends on its clock, in lockstep).

pub use crate::tpm::{SimulatorPlatformSignal, Tpm, sleep};
pub use tpm2::Connection;
use tpm2::commands::{
    Command, FlushContext, GetCapability, Message, ReadPublic, StartAuthSession, UnmarshalMessage,
    responses,
};
use tpm2::{Handle, TpmCc, TpmEccCurve, TpmSe, TpmSt};
use tpm2::{Marshal, Unmarshal};

use tpm2::crypto::kdf::kdfa_bits;
use tpm2::crypto::{CryptoError, CryptoProvider, Direction, ModeIv, Symmetric, SymmetricKey};

use tpm2::Tpm2b;
use tpm2::{
    AlgSym, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bNonce,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveCreate, Tpm2bSensitiveData, Tpm2bTemplate, TpmaObject,
    TpmaSession, TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode, TpmiRsaKeyBits, TpmiStCommandTag,
    TpmsAuthCommand, TpmsAuthResponse, TpmsEccParms, TpmsNvPublic, TpmsRsaParms,
    TpmsSensitiveCreate, TpmtPublic, TpmtRsaScheme, TpmtSymDefObject,
};
use tpm2_platform_linux::PlatformCryptoProvider;
pub use tpm2_simulator::execute::{CmdHeader, RespHeader};

// Imports used by helpers collected from the individual test files.
use hmac::Hmac;
use hmac::Mac;
use p256::elliptic_curve::sec1::FromEncodedPoint as _;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use rand::RngCore;
use sha1::Sha1;
use sha2::Digest;
use sha2::Sha256;
use sha2::Sha384;
use sha2::Sha512;
use std::time::Duration;
use tpm2::Alg;
use tpm2::TPM2_PCR_SELECT_MAX;
use tpm2::Tpm2bContextData;
use tpm2::Tpm2bData;
use tpm2::Tpm2bEccParameter;
use tpm2::Tpm2bEccPoint;
use tpm2::Tpm2bMaxBuffer;
use tpm2::Tpm2bMaxNvBuffer;
use tpm2::Tpm2bOperand;
use tpm2::Tpm2bPrivate;
use tpm2::Tpm2bPrivateKeyRsa;
use tpm2::Tpm2bPublic;
use tpm2::Tpm2bTimeout;
use tpm2::TpmCap;
use tpm2::TpmEo;
use tpm2::TpmNt;
use tpm2::TpmPt;
use tpm2::TpmaNv;
use tpm2::TpmiAlgKdf;
use tpm2::TpmlDigestValues;
use tpm2::TpmlPcrSelection;
use tpm2::TpmsAttest;
use tpm2::TpmsCapabilityData;
use tpm2::TpmsContext;
use tpm2::TpmsEccPoint;
use tpm2::TpmsPcrSelection;
use tpm2::TpmsSchemeEcdaa;
use tpm2::TpmsSchemeXor;
use tpm2::TpmsTimeInfo;
use tpm2::TpmtEccScheme;
use tpm2::TpmtHa;
use tpm2::TpmtKdfScheme;
use tpm2::TpmtKeyedHashScheme;
use tpm2::TpmtPublicParms;
use tpm2::TpmtSensitive;
use tpm2::TpmtSigScheme;
use tpm2::TpmtSignature;
use tpm2::TpmtTkAuth;
use tpm2::TpmtTkCreation;
use tpm2::TpmtTkHashcheck;
use tpm2::TpmtTkVerified;
use tpm2::TpmuAttest;
use tpm2::TpmuSensitiveComposite;
use tpm2::commands::Clear;
use tpm2::commands::ClearControl;
use tpm2::commands::Commit;
use tpm2::commands::ContextLoad;
use tpm2::commands::ContextSave;
use tpm2::commands::Create;
#[allow(deprecated)]
use tpm2::commands::CreateLoaded;
use tpm2::commands::CreatePrimary;
use tpm2::commands::DictionaryAttackLockReset;
use tpm2::commands::DictionaryAttackParameters;
use tpm2::commands::Duplicate;
use tpm2::commands::EventSequenceComplete;
use tpm2::commands::EvictControl;
use tpm2::commands::Hash;
use tpm2::commands::HashSequenceStart;
use tpm2::commands::HierarchyChangeAuth;
use tpm2::commands::HierarchyControl;
use tpm2::commands::Import;
use tpm2::commands::Load;
use tpm2::commands::LoadExternal;
use tpm2::commands::NVChangeAuth;
use tpm2::commands::NVDefineSpace;
use tpm2::commands::NVRead;
use tpm2::commands::NVReadPublic;
use tpm2::commands::NVWrite;
use tpm2::commands::PCRRead;
use tpm2::commands::PolicyAuthorize;
use tpm2::commands::PolicyAuthorizeNV;
use tpm2::commands::PolicyCommandCode;
use tpm2::commands::PolicyCpHash;
use tpm2::commands::PolicyDuplicationSelect;
use tpm2::commands::PolicyGetDigest;
use tpm2::commands::PolicyNV;
use tpm2::commands::PolicyNameHash;
use tpm2::commands::PolicyPCR;
use tpm2::commands::PolicySecret;
use tpm2::commands::PolicySigned;
use tpm2::commands::PolicyTemplate;
use tpm2::commands::PolicyTicket;
use tpm2::commands::Quote;
use tpm2::commands::ReadClock;
use tpm2::commands::Rewrap;
use tpm2::commands::SequenceComplete;
use tpm2::commands::SequenceUpdate;
use tpm2::commands::SetPrimaryPolicy;
use tpm2::commands::TestParms;
use tpm2::commands::Unseal;
#[allow(deprecated)]
use tpm2::commands::VerifySignature;
use tpm2::commands::*;
use tpm2::crypto::Asymmetric;
use tpm2::crypto::HashStream;
use tpm2::crypto::asymmetric::KeyParams;
use tpm2::errors::Fmt1;
use tpm2::errors::Position;
use tpm2::errors::TpmRc;
use tpm2::errors::UnmarshalError;
use tpm2::*;
use tpm2_simulator::execute::ExecuteError;

// ===========================================================================
// Command execution, sessions and policy computation (formerly `test_utils`)
// ===========================================================================

/// Copies `bytes` into a leaked heap allocation and returns it as a `'static` slice (tests use
/// this to build `'static` TPM2B values from temporaries).
pub fn leak_bytes(bytes: &[u8]) -> &'static [u8] {
    Vec::leak(bytes.to_vec())
}

/// Marshals `item` into a freshly allocated `Vec<u8>` holding exactly its wire encoding.
pub fn marshal_to_vec<M: Marshal>(item: &M) -> Vec<u8>
where
    for<'a> &'a mut M::MaxBuffer: TryFrom<&'a mut [u8]>,
{
    let mut tmp = vec![0u8; M::MAX_SIZE];
    let len = item.marshal((&mut tmp[..M::MAX_SIZE]).try_into().ok().unwrap());
    tmp.truncate(len);
    tmp
}

/// Marshals a public area (or any marshallable value) into a `'static` `Tpm2bTemplate`.
pub fn make_template<M: Marshal>(item: &M) -> Tpm2bTemplate<'static>
where
    for<'a> &'a mut M::MaxBuffer: TryFrom<&'a mut [u8]>,
{
    Tpm2bTemplate::from_bytes(leak_bytes(&marshal_to_vec(item))).unwrap()
}

/// Builds a `TPM2B_TEMPLATE` for `TPM2_CreateLoaded` with a derivation parent: the public area
/// with its `unique` field replaced by the marshalled `TPMS_DERIVE` (`derive`).
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

/// Crypto provider used by the *client* side of the tests (HMAC/KDF/nonce
/// generation, parameter encryption, expected-value computation, ...).
///
/// Tests treat the simulator as a black box, so they never borrow the TPM's
/// own crypto provider; instead they use this independent instance.
pub const CLIENT_CRYPTO: &PlatformCryptoProvider = &PlatformCryptoProvider;

/// Fills `dest` with client-side random bytes (nonces, salts, keys, test
/// data).
///
/// By default the bytes come from the OS through [`CLIENT_CRYPTO`]
/// (BoringSSL's `RAND_bytes`), so they differ between runs. When a test run is
/// reproduced with [`crate::seed::SEED_ENV`] set, they instead come from a
/// per-thread [`rand::rngs::StdRng`] seeded from that seed and the name of the
/// test thread, so the commands a test sends (and hence, with the TPM's own
/// randomness fixed by the same seed, the responses) repeat exactly. Client
/// randomness drawn inside BoringSSL itself (e.g. client-side signatures)
/// stays OS-random; tests whose TPM-visible inputs depend on it are not fully
/// reproducible.
///
/// Returns the [`CryptoError`] of [`CLIENT_CRYPTO`] on failure (only possible
/// on the OS path).
pub fn client_random(dest: &mut [u8]) -> Result<(), CryptoError> {
    use rand::{RngCore, SeedableRng};
    thread_local! {
        static SEEDED: core::cell::RefCell<Option<rand::rngs::StdRng>> =
            core::cell::RefCell::new(crate::seed::ReferenceSeed::from_env().map(|seed| {
                // FNV-1a over the seed and the test name: stable across builds.
                let thread = std::thread::current();
                let text = format!("{seed}/{}", thread.name().unwrap_or(""));
                let hash = text.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
                    (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
                });
                rand::rngs::StdRng::seed_from_u64(hash)
            }));
    }
    let seeded = SEEDED.with(|rng| {
        rng.borrow_mut()
            .as_mut()
            .map(|rng| rng.fill_bytes(dest))
            .is_some()
    });
    if seeded {
        Ok(())
    } else {
        CLIENT_CRYPTO.get_random(dest)
    }
}

/// Random number generator for the client side of the tests (nonces, keys,
/// test data), drawing from [`client_random`].
///
/// The randomness comes from the OS (BoringSSL's `RAND_bytes`), so the
/// client-side values differ between runs, unless the run is reproduced with
/// [`crate::seed::SEED_ENV`] (see [`client_random`]). Differential comparisons
/// do not depend on them: the C reference receives exactly the commands
/// `tpm-rs` received.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClientRng;

/// Returns the client-side random number generator (see [`ClientRng`]).
pub fn client_rng() -> ClientRng {
    ClientRng
}

impl rand::RngCore for ClientRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        client_random(dest).expect("client RNG failure");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand::CryptoRng for ClientRng {}

/// Marshals `item` into `buf` and returns the encoded length; uses a temporary buffer when `buf`
/// is shorter than `M::MAX_SIZE`.
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

/// The response handle area of command `C`: one [`Handle`] per response handle
/// of `C`'s response (`[Handle; N]`, e.g. `[object_handle]` for
/// `TPM2_CreatePrimary` and `[]` for most commands).
///
/// The `*_status` and `*_raw` helpers return it where exp's helpers returned
/// `C::RespHandles`. The other helpers return the full response, which carries
/// the same handles in its fields (e.g. `rsp.object_handle`).
pub type RespHandles<C> = <<C as Command>::Response<'static> as Message>::Handles;

/// Marshals the handle area `handles` into `buf` (one big-endian `u32` per
/// handle, the same bytes exp's `XxxHandles` produced) and returns the number
/// of bytes written.
fn marshal_handles(handles: &[Handle], buf: &mut [u8]) -> usize {
    let mut written = 0;
    for handle in handles {
        written += marshal_to_slice(handle, &mut buf[written..]);
    }
    written
}

/// Unmarshals the handle area of message `M` (`M::Handles`) from `src`.
///
/// Panics if `src` is too short.
fn unmarshal_handles<M: Message>(src: &mut &[u8]) -> M::Handles {
    let mut handles = M::Handles::default();
    for handle in handles.as_mut() {
        *handle = Handle::unmarshal(src).unwrap();
    }
    handles
}

/// Marshals `cmd` (header, the command's handle area, `num_sessions` password
/// sessions carrying `auth_value`, parameter area), lets `corrupt_fn` modify
/// the marshalled parameter area, sends the command to the TPM and checks the
/// response code.
///
/// Returns the response header; the response itself is left in `resp_buffer`.
/// A non-success response code is returned as `Err(rc)`.
fn transact_with_password_sessions<CmdT: Command>(
    tpm: &mut Tpm,
    cmd: &CmdT,
    num_sessions: usize,
    auth_value: &[u8],
    corrupt_fn: impl FnOnce(&mut [u8]),
    resp_buffer: &mut [u8],
) -> Result<RespHeader, u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
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
    let handles_len = marshal_handles(cmd.handles().as_ref(), &mut cmd_buffer[written..]);
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
        auth_written += marshal_auth_command(&auth_cmd, &mut auth_buffer[auth_written..]);
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
    Ok(resp_header)
}

/// Reads the response handles of response message `M` from the successful
/// response in `resp_buffer` (described by `resp_header`), skipping
/// `parameterSize` if the response has sessions.
///
/// Returns the handles and the offset of the response parameter area.
fn parse_response_handles<M: Message>(
    resp_buffer: &[u8],
    resp_header: &RespHeader,
) -> (M::Handles, usize) {
    let mut slice = &resp_buffer[10..];
    let orig_handles_len = slice.len();
    let resp_handles = unmarshal_handles::<M>(&mut slice);
    let handles_consumed = orig_handles_len - slice.len();
    let mut param_start = 10 + handles_consumed;
    if resp_header.tag == TpmSt::SESSIONS {
        let _param_size = u32::unmarshal(&mut slice).unwrap();
        param_start += 4;
    }
    (resp_handles, param_start)
}

/// Runs `cmd` like [`execute_with_password_sessions`], but unmarshals the
/// response from `resp_buffer`, so that it borrows `resp_buffer` instead of
/// leaked memory.
fn execute_with_password_sessions_into<'a, CmdT: Command>(
    tpm: &mut Tpm,
    cmd: &CmdT,
    num_sessions: usize,
    auth_value: &[u8],
    resp_buffer: &'a mut [u8; 4096],
) -> Result<CmdT::Response<'a>, u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let resp_header =
        transact_with_password_sessions(tpm, cmd, num_sessions, auth_value, |_| {}, resp_buffer)?;
    let resp_buffer: &'a [u8] = resp_buffer;
    let (resp_handles, param_start) =
        parse_response_handles::<CmdT::Response<'a>>(resp_buffer, &resp_header);
    let mut slice = &resp_buffer[param_start..resp_header.size as usize];
    Ok(<CmdT::Response<'a>>::unmarshal_with_handles(resp_handles, &mut slice).unwrap())
}

/// Marshals one authorization session (`TPMS_AUTH_COMMAND`) into `buf` and
/// returns the number of bytes written.
///
/// Deliberately non-generic: inside a function bounded by
/// `for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>`, calling the generic
/// [`marshal_to_slice`] on a type with a lifetime (such as
/// `TpmsAuthCommand<'_>`) makes rustc select that bound and fail with E0271.
pub fn marshal_auth_command(auth_cmd: &TpmsAuthCommand<'_>, buf: &mut [u8]) -> usize {
    marshal_to_slice(auth_cmd, buf)
}

/// Runs `cmd` with `num_sessions` password sessions (`TPM_RS_PW`, each
/// carrying `auth_value`) and returns the layout of the response left in
/// `resp_buffer`: `(param_start, resp_size, resp_handles)`, where the response
/// parameters are `resp_buffer[param_start..resp_size]`.
///
/// The command's handles (`cmd.handles()`) are sent in the handle area. A
/// non-success response code is returned as `Err(rc)`.
pub fn execute_with_password_sessions_raw<CmdT: Command>(
    tpm: &mut Tpm,
    cmd: &CmdT,
    num_sessions: usize,
    auth_value: &[u8],
    resp_buffer: &mut [u8],
) -> Result<(usize, usize, RespHandles<CmdT>), u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    execute_with_corrupted_bytes_raw(tpm, cmd, num_sessions, auth_value, |_| {}, resp_buffer)
}

/// Runs `cmd` like [`execute_with_password_sessions`], but only returns the
/// response handles (or the response code).
pub fn execute_with_password_sessions_status<CmdT: Command>(
    tpm: &mut Tpm,
    cmd: &CmdT,
    num_sessions: usize,
    auth_value: &[u8],
) -> Result<RespHandles<CmdT>, u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut resp_buffer = [0u8; 16384];
    execute_with_password_sessions_raw(tpm, cmd, num_sessions, auth_value, &mut resp_buffer)
        .map(|(_, _, handles)| handles)
}

/// Runs `cmd` with `num_sessions` password sessions (`TPM_RS_PW`, each
/// carrying `auth_value`) and returns its response, which carries the
/// response handles. A non-success response code is returned as `Err(rc)`.
pub fn execute_with_password_sessions<CmdT: Command>(
    tpm: &mut Tpm,
    cmd: &CmdT,
    num_sessions: usize,
    auth_value: &[u8],
) -> Result<CmdT::Response<'static>, u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut resp_buffer = [0u8; 16384];
    let (param_start, resp_size, resp_handles) =
        execute_with_password_sessions_raw(tpm, cmd, num_sessions, auth_value, &mut resp_buffer)?;
    let mut slice: &'static [u8] = leak_bytes(&resp_buffer[param_start..resp_size]);
    let resp = <CmdT::Response<'static>>::unmarshal_with_handles(resp_handles, &mut slice).unwrap();
    Ok(resp)
}

/// Runs `TPM2_Sign` with `num_sessions` password sessions; the response
/// borrows `resp_buffer`.
#[allow(deprecated)] // TPM2_Sign is deprecated upstream, but the TPM implements it.
pub fn execute_sign<'a>(
    tpm: &mut Tpm,
    cmd: &tpm2::commands::Sign<'_>,
    num_sessions: usize,
    auth_value: &[u8],
    resp_buffer: &'a mut [u8; 4096],
) -> Result<responses::Sign<'a>, u32> {
    execute_with_password_sessions_into(tpm, cmd, num_sessions, auth_value, resp_buffer)
}

/// Runs `TPM2_Certify` with `num_sessions` password sessions; the response
/// borrows `resp_buffer`.
pub fn execute_certify<'a>(
    tpm: &mut Tpm,
    cmd: &tpm2::commands::Certify<'_>,
    num_sessions: usize,
    auth_value: &[u8],
    resp_buffer: &'a mut [u8; 4096],
) -> Result<responses::Certify<'a>, u32> {
    execute_with_password_sessions_into(tpm, cmd, num_sessions, auth_value, resp_buffer)
}

/// Runs `TPM2_NV_Certify` with `num_sessions` password sessions; the response
/// borrows `resp_buffer`.
pub fn execute_nv_certify<'a>(
    tpm: &mut Tpm,
    cmd: &tpm2::commands::NVCertify<'_>,
    num_sessions: usize,
    auth_value: &[u8],
    resp_buffer: &'a mut [u8; 4096],
) -> Result<responses::NVCertify<'a>, u32> {
    execute_with_password_sessions_into(tpm, cmd, num_sessions, auth_value, resp_buffer)
}

/// Runs `TPM2_CertifyCreation` with `num_sessions` password sessions; the
/// response borrows `resp_buffer`.
pub fn execute_certify_creation<'a>(
    tpm: &mut Tpm,
    cmd: &tpm2::commands::CertifyCreation<'_>,
    num_sessions: usize,
    auth_value: &[u8],
    resp_buffer: &'a mut [u8; 4096],
) -> Result<responses::CertifyCreation<'a>, u32> {
    execute_with_password_sessions_into(tpm, cmd, num_sessions, auth_value, resp_buffer)
}

/// Runs `TPM2_GetTime` with `num_sessions` password sessions; the response
/// borrows `resp_buffer`.
pub fn execute_get_time<'a>(
    tpm: &mut Tpm,
    cmd: &tpm2::commands::GetTime<'_>,
    num_sessions: usize,
    auth_value: &[u8],
    resp_buffer: &'a mut [u8; 4096],
) -> Result<responses::GetTime<'a>, u32> {
    execute_with_password_sessions_into(tpm, cmd, num_sessions, auth_value, resp_buffer)
}

/// Runs `TPM2_GetSessionAuditDigest` with `num_sessions` password sessions;
/// the response borrows `resp_buffer`.
pub fn execute_get_session_audit_digest<'a>(
    tpm: &mut Tpm,
    cmd: &tpm2::commands::GetSessionAuditDigest<'_>,
    num_sessions: usize,
    auth_value: &[u8],
    resp_buffer: &'a mut [u8; 4096],
) -> Result<responses::GetSessionAuditDigest<'a>, u32> {
    execute_with_password_sessions_into(tpm, cmd, num_sessions, auth_value, resp_buffer)
}

/// Runs `TPM2_GetCapability` with `num_sessions` password sessions; the
/// response borrows `resp_buffer`.
pub fn execute_get_capability<'a>(
    tpm: &mut Tpm,
    cmd: &tpm2::commands::GetCapability,
    num_sessions: usize,
    auth_value: &[u8],
    resp_buffer: &'a mut [u8; 4096],
) -> Result<responses::GetCapability<'a>, u32> {
    execute_with_password_sessions_into(tpm, cmd, num_sessions, auth_value, resp_buffer)
}

/// Reads a single fixed/variable TPM property with
/// `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, property, 1)`.
///
/// Panics if the TPM does not report the requested property.
pub fn get_tpm_property(tpm: &mut Tpm, property: tpm2::TpmPt) -> u32 {
    let cmd = GetCapability {
        capability: tpm2::TpmCap::TPMProperties,
        property: property.0,
        property_count: 1,
    };
    let resp = tpm.execute(cmd).expect("TPM2_GetCapability failed");
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
pub fn max_loaded_sessions(tpm: &mut Tpm) -> usize {
    get_tpm_property(tpm, tpm2::TpmPt::HR_LOADED_MIN) as usize
}

/// Enables or disables `hierarchy` (`TPM_RH_OWNER`, `TPM_RH_ENDORSEMENT`,
/// ...) with `TPM2_HierarchyControl`, authorized by the platform hierarchy
/// using its (default, empty) password.
pub fn set_hierarchy_enabled(tpm: &mut Tpm, hierarchy: Handle, state: bool) {
    let cmd = tpm2::commands::HierarchyControl {
        auth_handle: Handle::RH_PLATFORM,
        enable: hierarchy,
        state,
    };
    execute_with_password_sessions(tpm, &cmd, 1, &[])
        .unwrap_or_else(|rc| panic!("TPM2_HierarchyControl failed: {rc:#x}"));
}

/// Runs `TPM2_PCR_Event` with `num_sessions` password sessions; the response
/// borrows `resp_buffer`.
pub fn execute_pcr_event<'a>(
    tpm: &mut Tpm,
    cmd: &tpm2::commands::PCREvent<'_>,
    num_sessions: usize,
    auth_value: &[u8],
    resp_buffer: &'a mut [u8; 4096],
) -> Result<responses::PCREvent<'a>, u32> {
    execute_with_password_sessions_into(tpm, cmd, num_sessions, auth_value, resp_buffer)
}

/// Like [`execute_with_password_sessions_raw`], but lets `corrupt_fn` modify
/// the marshalled parameter area before the command is sent.
pub fn execute_with_corrupted_bytes_raw<CmdT: Command>(
    tpm: &mut Tpm,
    cmd: &CmdT,
    num_sessions: usize,
    auth_value: &[u8],
    corrupt_fn: impl FnOnce(&mut [u8]),
    resp_buffer: &mut [u8],
) -> Result<(usize, usize, RespHandles<CmdT>), u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let resp_header = transact_with_password_sessions(
        tpm,
        cmd,
        num_sessions,
        auth_value,
        corrupt_fn,
        resp_buffer,
    )?;
    let (resp_handles, param_start) =
        parse_response_handles::<CmdT::Response<'static>>(resp_buffer, &resp_header);
    let resp_size = resp_header.size as usize;
    Ok((param_start, resp_size, resp_handles))
}

/// Like [`execute_with_password_sessions_status`], but lets `corrupt_fn`
/// modify the marshalled parameter area before the command is sent.
pub fn execute_with_corrupted_bytes_status<CmdT: Command>(
    tpm: &mut Tpm,
    cmd: &CmdT,
    num_sessions: usize,
    auth_value: &[u8],
    corrupt_fn: impl FnOnce(&mut [u8]),
) -> Result<RespHandles<CmdT>, u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut resp_buffer = [0u8; 16384];
    execute_with_corrupted_bytes_raw(
        tpm,
        cmd,
        num_sessions,
        auth_value,
        corrupt_fn,
        &mut resp_buffer,
    )
    .map(|(_, _, handles)| handles)
}

/// Like [`execute_with_password_sessions`], but lets `corrupt_fn` modify the
/// marshalled parameter area before the command is sent.
pub fn execute_with_corrupted_bytes<CmdT: Command>(
    tpm: &mut Tpm,
    cmd: &CmdT,
    num_sessions: usize,
    auth_value: &[u8],
    corrupt_fn: impl FnOnce(&mut [u8]),
) -> Result<CmdT::Response<'static>, u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut resp_buffer = [0u8; 16384];
    let (param_start, resp_size, resp_handles) = execute_with_corrupted_bytes_raw(
        tpm,
        cmd,
        num_sessions,
        auth_value,
        corrupt_fn,
        &mut resp_buffer,
    )?;
    let mut slice: &'static [u8] = leak_bytes(&resp_buffer[param_start..resp_size]);
    let resp = <CmdT::Response<'static>>::unmarshal_with_handles(resp_handles, &mut slice).unwrap();
    Ok(resp)
}

/// Flushes `handle` with `TPM2_FlushContext`, returning the TPM response code on failure.
pub fn flush_context(tpm: &mut Tpm, handle: Handle) -> Result<(), u32> {
    let cmd = FlushContext {
        flush_handle: handle,
    };
    execute_with_password_sessions(tpm, &cmd, 0, &[]).map(|_| ())
}

pub fn read_public_name(tpm: &mut Tpm, handle: Handle) -> Tpm2bName<'static> {
    let cmd = ReadPublic {
        object_handle: handle,
    };
    let resp = execute_with_password_sessions(tpm, &cmd, 0, &[]).unwrap();
    resp.name
}

/// Returns an empty sensitive area and a template for an RSA-2048 RSASSA-SHA256 signing key
/// (`fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | sign`).
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

/// Runs `KDFa` with SHA-256 using the given crypto provider, writing `bits` of output to `out`.
fn kdfa_sha256(
    crypto: &PlatformCryptoProvider,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    bits: u32,
    out: &mut [u8],
) {
    kdfa_bits(
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

/// Hashes the concatenation of `updates` with `auth_hash` using the given client-side provider.
fn compute_client_hash(
    crypto: &PlatformCryptoProvider,
    auth_hash: TpmiAlgHash,
    updates: &[&[u8]],
) -> Vec<u8> {
    let mut state = tpm2::crypto::HashStream::new(crypto, auth_hash).unwrap();
    for data in updates {
        state.update(data).unwrap();
    }
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    state.finalize(&mut out).unwrap().digest().to_vec()
}

/// HMACs the concatenation of `updates` with `auth_hash` under `key` using the given client-side
/// provider.
fn compute_client_hmac(
    crypto: &PlatformCryptoProvider,
    auth_hash: TpmiAlgHash,
    key: &[u8],
    updates: &[&[u8]],
) -> Vec<u8> {
    let mut state = tpm2::crypto::HmacStream::new(crypto, auth_hash, key).unwrap();
    for data in updates {
        state.update(data).unwrap();
    }
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    state.finalize(&mut out).unwrap().digest().to_vec()
}

/// Starts an unsalted authorization session (`TPM2_StartAuthSession`) with a random caller nonce
/// and returns its client-side state (handle, nonces, session key), or the TPM response code.
pub fn start_auth_session(
    tpm: &mut Tpm,
    tpm_key: Handle,
    bind: Handle,
    bind_auth: &[u8],
    session_type: TpmSe,
    symmetric: Option<TpmtSymDefObject>,
    auth_hash: TpmiAlgHash,
) -> Result<ActiveSession, u32> {
    let mut nonce_bytes = [0u8; 16];
    crate::_common::client_random(&mut nonce_bytes).unwrap();
    let nonce_caller = Tpm2bNonce::from_bytes(leak_bytes(&nonce_bytes)).unwrap();

    let cmd = StartAuthSession {
        tpm_key,
        bind,
        nonce_caller,
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type,
        symmetric: symmetric.map(tpm2::TpmtSymDef::from),
        auth_hash,
    };

    let resp = execute_with_password_sessions(tpm, &cmd, 0, &[])?;

    let session_key = if bind == Handle::RH_NULL && tpm_key == Handle::RH_NULL {
        Vec::new()
    } else {
        let key = bind_auth.to_vec();
        let hash_size = match auth_hash {
            TpmiAlgHash::Sha1 => 20,
            TpmiAlgHash::Sha256 => 32,
            TpmiAlgHash::Sha384 => 48,
            TpmiAlgHash::Sha512 => 64,
            #[allow(unreachable_patterns)]
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
        session_handle: resp.session_handle,
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
pub fn entity_name(tpm: &mut Tpm, handle: Handle) -> Vec<u8> {
    if (handle.0 >> 24 == 0x80 || handle.0 >> 24 == 0x81)
        && let Ok(resp) = tpm.execute(ReadPublic {
            object_handle: handle,
        })
    {
        return resp.name.get_buffer().to_vec();
    }
    // NV Indices are named by nameAlg || H(nvPublic), as reported by TPM2_NV_ReadPublic.
    if handle.0 >> 24 == 0x01
        && let Ok(resp) = tpm.execute(tpm2::commands::NVReadPublic { nv_index: handle })
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

/// Executes `cmd` with the given HMAC/policy `sessions` (computing command HMACs and parameter
/// encryption client-side, verifying response HMACs) and returns the decrypted response parameter
/// bytes and response handles, or the TPM response code.
pub fn execute_with_hmac_sessions_raw<CmdT: Command>(
    tpm: &mut Tpm,
    cmd: &CmdT,
    _handle_names: &[&[u8]],
    sessions: &mut [ActiveSession],
    entity_auths: &[&[u8]],
) -> Result<(Vec<u8>, RespHandles<CmdT>), u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
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
    let handles_len = marshal_handles(cmd.handles().as_ref(), &mut cmd_buffer[written..]);
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
        crate::_common::client_random(&mut nonce_bytes).unwrap();
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
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes128,
                ..
            }) => 128 + 128,
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes256,
                ..
            }) => 256 + 128,
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
            sym_encrypt(
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

        if i == 0 && i < session_to_handle_idx_len {
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

        auth_written += marshal_auth_command(&auth_cmd, &mut auth_buffer[auth_written..]);
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

    let resp_handles = unmarshal_handles::<CmdT::Response<'static>>(&mut slice);

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
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes128,
                ..
            }) => 128 + 128,
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes256,
                ..
            }) => 256 + 128,
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
            sym_decrypt(
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

/// Like [`execute_with_hmac_sessions`] but only returns the response handles (or the response
/// code).
pub fn execute_with_hmac_sessions_status<CmdT: Command>(
    tpm: &mut Tpm,
    cmd: &CmdT,
    handle_names: &[&[u8]],
    sessions: &mut [ActiveSession],
    entity_auths: &[&[u8]],
) -> Result<RespHandles<CmdT>, u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    execute_with_hmac_sessions_raw(tpm, cmd, handle_names, sessions, entity_auths).map(|(_, h)| h)
}

/// Executes `cmd` with HMAC/policy `sessions` (see [`execute_with_hmac_sessions_raw`]) and returns
/// the unmarshalled response parameters and handles, or the TPM response code.
pub fn execute_with_hmac_sessions<CmdT: Command>(
    tpm: &mut Tpm,
    cmd: &CmdT,
    handle_names: &[&[u8]],
    sessions: &mut [ActiveSession],
    entity_auths: &[&[u8]],
) -> Result<CmdT::Response<'static>, u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let (decrypted_param_buf, resp_handles) =
        execute_with_hmac_sessions_raw(tpm, cmd, handle_names, sessions, entity_auths)?;
    let mut slice_params: &'static [u8] = leak_bytes(&decrypted_param_buf);
    let resp =
        <CmdT::Response<'static>>::unmarshal_with_handles(resp_handles, &mut slice_params).unwrap();
    Ok(resp)
}

/// Which part of a session's response authorization area
/// [`execute_with_hmac_sessions_corrupt_response`] tampers with before verification.
#[derive(Clone, Copy, Debug)]
pub enum ResponseCorruption {
    Hmac,
    NonceTpm,
    Attributes,
}

/// Like [`execute_with_hmac_sessions_raw`] but puts a different random caller nonce on the wire
/// than the one used to compute the command HMAC, so the TPM is expected to reject the
/// authorization.
pub fn execute_with_hmac_sessions_mismatch_nonce<CmdT: Command>(
    tpm: &mut Tpm,
    cmd: &CmdT,
    _handle_names: &[&[u8]],
    sessions: &mut [ActiveSession],
    entity_auths: &[&[u8]],
) -> Result<CmdT::Response<'static>, u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
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
    let handles_len = marshal_handles(cmd.handles().as_ref(), &mut cmd_buffer[written..]);
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
        crate::_common::client_random(&mut nonce_bytes).unwrap();
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
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes128,
                ..
            }) => 128 + 128,
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes256,
                ..
            }) => 256 + 128,
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
            sym_encrypt(
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
        crate::_common::client_random(&mut nonce_bytes_wire).unwrap();
        let nonce_caller_wire = Tpm2bNonce::from_bytes(&nonce_bytes_wire).unwrap();

        let auth_cmd = TpmsAuthCommand {
            session_handle: session.session_handle,
            nonce: nonce_caller_wire,
            session_attributes: session.attributes,
            hmac: hmac_val,
        };

        auth_written += marshal_auth_command(&auth_cmd, &mut auth_buffer[auth_written..]);
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

    let resp_handles = unmarshal_handles::<CmdT::Response<'static>>(&mut slice);

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
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes128,
                ..
            }) => 128 + 128,
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes256,
                ..
            }) => 256 + 128,
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
            sym_decrypt(
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
    let resp =
        <CmdT::Response<'static>>::unmarshal_with_handles(resp_handles, &mut slice_params).unwrap();

    Ok(resp)
}

/// Like [`execute_with_hmac_sessions_raw`] but corrupts the response authorization area as
/// selected by `corruption` before verifying it client-side (tests HMAC response checking).
pub fn execute_with_hmac_sessions_corrupt_response<CmdT: Command>(
    tpm: &mut Tpm,
    cmd: &CmdT,
    _handle_names: &[&[u8]],
    sessions: &mut [ActiveSession],
    entity_auths: &[&[u8]],
    corruption: ResponseCorruption,
) -> Result<CmdT::Response<'static>, u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
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
    let handles_len = marshal_handles(cmd.handles().as_ref(), &mut cmd_buffer[written..]);
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
        crate::_common::client_random(&mut nonce_bytes).unwrap();
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
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes128,
                ..
            }) => 128 + 128,
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes256,
                ..
            }) => 256 + 128,
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
            sym_encrypt(
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

        auth_written += marshal_auth_command(&auth_cmd, &mut auth_buffer[auth_written..]);
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

    let resp_handles = unmarshal_handles::<CmdT::Response<'static>>(&mut slice);

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
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes128,
                ..
            }) => 128 + 128,
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes256,
                ..
            }) => 256 + 128,
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
            sym_decrypt(
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
    let resp =
        <CmdT::Response<'static>>::unmarshal_with_handles(resp_handles, &mut slice_params).unwrap();

    Ok(resp)
}

/// Client-side policy digest calculator: tracks a running `policyDigest` for `auth_hash` and
/// extends it like the corresponding `TPM2_Policy*` commands do.
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
            #[allow(unreachable_patterns)]
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

/// Computes the Name of an NV Index from its public area (`nameAlg || H(TPMS_NV_PUBLIC)`).
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

/// The TCG default RSA-2048 Endorsement Key template (EK Credential Profile, template L-1).
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
                symmetric: Some(TpmtSymDefObject {
                    alg: AlgSym::Aes128,
                    mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
                }),
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    }
}

/// The TCG default ECC NIST P-256 Endorsement Key template (EK Credential Profile, template L-2).
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
                symmetric: Some(TpmtSymDefObject {
                    alg: AlgSym::Aes128,
                    mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
                }),
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

/// Strips trailing zero bytes from an authValue, as the TPM does before using it in HMAC keys.
pub fn strip_trailing_zeros(auth: &[u8]) -> &[u8] {
    let mut len = auth.len();
    while len > 0 && auth[len - 1] == 0 {
        len -= 1;
    }
    &auth[..len]
}

/// Runs `KDFa` with hash `auth_hash` using the given provider, writing `bits` of output to `out`;
/// panics on failure.
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
    kdfa_bits(
        crypto, auth_hash, key, label, context_u, context_v, bits, out,
    )
    .unwrap();
}

/// Encrypts or decrypts (`dir`) `data` in place with the symmetric algorithm,
/// key size and cipher mode of `alg` (e.g. AES-128-CFB), updating `iv` in
/// place (`ivOut`, for chaining).
///
/// This is exp's `tpm2::crypto::encrypt_decrypt(s, alg, key, iv, is_decrypt,
/// data)` on top of the upstream one-shot [`tpm2::crypto::encrypt_decrypt`].
///
/// # Errors
/// * [`CryptoError::Unsupported`] - `alg` has no cipher mode (`mode` is `None`
///   or CMAC), or `s` does not implement the algorithm/mode.
/// * [`CryptoError::Internal`] - `key` does not have `alg`'s key size, or `iv`
///   does not have the length the mode needs (16 bytes, 0 for ECB).
pub fn sym_encrypt_decrypt(
    s: &impl Symmetric,
    alg: TpmtSymDefObject,
    key: &[u8],
    iv: &mut [u8],
    dir: Direction,
    data: &mut [u8],
) -> Result<(), CryptoError> {
    let Some(TpmiAlgSymMode::Cipher(mode)) = alg.mode else {
        return Err(CryptoError::Unsupported);
    };
    let key = SymmetricKey::new(alg.alg, key).ok_or(CryptoError::Internal)?;
    let mode = ModeIv::new(mode, iv).ok_or(CryptoError::Internal)?;
    tpm2::crypto::encrypt_decrypt(s, key, mode, dir, data)
}

/// Encrypts `data` in place with `alg` (see [`sym_encrypt_decrypt`]),
/// updating `iv` in place. Drop-in replacement for exp's
/// `tpm2::crypto::encrypt(s, alg, key, iv, data)`.
pub fn sym_encrypt(
    s: &impl Symmetric,
    alg: TpmtSymDefObject,
    key: &[u8],
    iv: &mut [u8],
    data: &mut [u8],
) -> Result<(), CryptoError> {
    sym_encrypt_decrypt(s, alg, key, iv, Direction::Encrypt, data)
}

/// Decrypts `data` in place with `alg` (see [`sym_encrypt_decrypt`]),
/// updating `iv` in place. Drop-in replacement for exp's
/// `tpm2::crypto::decrypt(s, alg, key, iv, data)`.
pub fn sym_decrypt(
    s: &impl Symmetric,
    alg: TpmtSymDefObject,
    key: &[u8],
    iv: &mut [u8],
    data: &mut [u8],
) -> Result<(), CryptoError> {
    sym_encrypt_decrypt(s, alg, key, iv, Direction::Decrypt, data)
}

/// Whether handle number `handle_index` of command `cc` has an authorization role (USER/ADMIN/
/// DUP), i.e. needs an authorization session.
pub fn handle_requires_auth(cc: TpmCc, handle_index: usize) -> bool {
    if handle_index == 0 {
        matches!(
            cc,
            TpmCc::HierarchyChangeAuth
                | TpmCc::HierarchyControl
                | TpmCc::SetPrimaryPolicy
                | TpmCc::PCRExtend
                | TpmCc::PCREvent
                | TpmCc::PCRReset
                | TpmCc::PCRSetAuthPolicy
                | TpmCc::PCRSetAuthValue
                | TpmCc::PCRAllocate
                | TpmCc::Clear
                | TpmCc::ClearControl
                | TpmCc::ChangePPS
                | TpmCc::ChangeEPS
                | TpmCc::EvictControl
                | TpmCc::CreatePrimary
                | TpmCc::CreateLoaded
                | TpmCc::GetTime
                | TpmCc::ClockSet
                | TpmCc::ClockRateAdjust
                | TpmCc::Commit
                | TpmCc::Sign
                | TpmCc::RSADecrypt
                | TpmCc::ECDHZGen
                | TpmCc::ZGen2Phase
                | TpmCc::MAC
                | TpmCc::NVDefineSpace
                | TpmCc::NVUndefineSpace
                | TpmCc::NVUndefineSpaceSpecial
                | TpmCc::Certify
                | TpmCc::Quote
                | TpmCc::GetSessionAuditDigest
                | TpmCc::GetCommandAuditDigest
                | TpmCc::CertifyCreation
                | TpmCc::NVWrite
                | TpmCc::NVCertify
                | TpmCc::NVRead
                | TpmCc::NVIncrement
                | TpmCc::NVExtend
                | TpmCc::NVSetBits
                | TpmCc::NVChangeAuth
                | TpmCc::NVWriteLock
                | TpmCc::NVGlobalWriteLock
                | TpmCc::NVReadLock
                | TpmCc::Duplicate
                | TpmCc::Import
                | TpmCc::Rewrap
                | TpmCc::EncryptDecrypt
                | TpmCc::EncryptDecrypt2
                | TpmCc::Load
                | TpmCc::Unseal
                | TpmCc::ObjectChangeAuth
                | TpmCc::ActivateCredential
                | TpmCc::PolicySecret
                | TpmCc::PolicyNV
                | TpmCc::Create
                | TpmCc::PolicyAuthorizeNV
                | TpmCc::SequenceUpdate
                | TpmCc::SequenceComplete
                | TpmCc::EventSequenceComplete
                | TpmCc::MACStart
                | TpmCc::DictionaryAttackLockReset
                | TpmCc::DictionaryAttackParameters
                | TpmCc::SetCommandCodeAuditStatus
                // `@`-decorated handles of commands tpm-rs does not implement.
                | TpmCc::PPCommands
                | TpmCc::SetAlgorithmSet
                | TpmCc::FieldUpgradeStart
        )
    } else if handle_index == 1 {
        matches!(
            cc,
            TpmCc::GetTime
                | TpmCc::Certify
                | TpmCc::GetSessionAuditDigest
                | TpmCc::GetCommandAuditDigest
                | TpmCc::NVCertify
                | TpmCc::ActivateCredential
                | TpmCc::EventSequenceComplete
                | TpmCc::NVUndefineSpaceSpecial
        )
    } else {
        false
    }
}

/// Counts the handles from `start_index` on that require authorization and are not `TPM_RH_NULL`.
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

/// Maps each authorization session to the index of the handle it authorizes for `command_code`,
/// skipping optional (`TPM_RH_NULL`) handles when there are not enough sessions. Returns the
/// mapping and the number of authorized handles.
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

// ===========================================================================
// Command-code constants
//
// Raw `TPM_CC_*` values used by tests that build command buffers by hand.
// ===========================================================================

/// Raw command code `TPM_CC_ClockSet` (`TPM2_ClockSet`).
pub const CC_CLOCK_SET: u32 = 0x128;

/// Raw command code `TPM_CC_Commit` (`TPM2_Commit`).
pub const CC_COMMIT: u32 = 0x18B;

/// Raw command code `TPM_CC_ContextLoad` (`TPM2_ContextLoad`).
pub const CC_CONTEXT_LOAD: u32 = 0x161;

/// Raw command code `TPM_CC_ContextSave` (`TPM2_ContextSave`).
pub const CC_CONTEXT_SAVE: u32 = 0x162;

/// Raw command code `TPM_CC_CreatePrimary` (`TPM2_CreatePrimary`).
pub const CC_CREATE_PRIMARY: u32 = 0x131;

/// Raw command code `TPM_CC_DictionaryAttackParameters` (`TPM2_DictionaryAttackParameters`).
pub const CC_DA_PARAMETERS: u32 = 0x13A;

/// Raw command code `TPM_CC_ECC_Parameters` (`TPM2_ECC_Parameters`).
pub const CC_ECC_PARAMETERS: u32 = 0x178;

/// Raw command code `TPM_CC_ECDH_ZGen` (`TPM2_ECDH_ZGen`).
pub const CC_ECDH_ZGEN: u32 = 0x154;

/// Raw command code `TPM_CC_EncryptDecrypt` (`TPM2_EncryptDecrypt`).
pub const CC_ENCRYPT_DECRYPT: u32 = 0x164;

/// Raw command code `TPM_CC_EvictControl` (`TPM2_EvictControl`).
pub const CC_EVICT_CONTROL: u32 = 0x120;

/// Raw command code `TPM_CC_FlushContext` (`TPM2_FlushContext`).
pub const CC_FLUSH_CONTEXT: u32 = 0x165;

/// Raw command code `TPM_CC_GetCapability` (`TPM2_GetCapability`).
pub const CC_GET_CAPABILITY: u32 = 0x17A;

/// Raw command code `TPM_CC_GetRandom` (`TPM2_GetRandom`).
pub const CC_GET_RANDOM: u32 = 0x17B;

/// Raw command code `TPM_CC_GetSessionAuditDigest` (`TPM2_GetSessionAuditDigest`).
pub const CC_GET_SESSION_AUDIT_DIGEST: u32 = 0x14D;

/// Raw command code `TPM_CC_GetTime` (`TPM2_GetTime`).
pub const CC_GET_TIME: u32 = 0x14C;

/// Raw command code `TPM_CC_HashSequenceStart` (`TPM2_HashSequenceStart`).
pub const CC_HASH_SEQUENCE_START: u32 = 0x186;

/// Raw command code `TPM_CC_HierarchyChangeAuth` (`TPM2_HierarchyChangeAuth`).
pub const CC_HIERARCHY_CHANGE_AUTH: u32 = 0x129;

/// Raw command code `TPM_CC_HierarchyControl` (`TPM2_HierarchyControl`).
pub const CC_HIERARCHY_CONTROL: u32 = 0x121;

/// Raw command code `TPM_CC_LoadExternal` (`TPM2_LoadExternal`).
pub const CC_LOAD_EXTERNAL: u32 = 0x167;

/// Raw command code `TPM_CC_MAC` (`TPM2_MAC`).
pub const CC_MAC: u32 = 0x155;

/// Raw command code `TPM_CC_NV_DefineSpace` (`TPM2_NV_DefineSpace`).
pub const CC_NV_DEFINE_SPACE: u32 = 0x12A;

/// Raw command code `TPM_CC_ObjectChangeAuth` (`TPM2_ObjectChangeAuth`).
pub const CC_OBJECT_CHANGE_AUTH: u32 = 0x150;

/// Raw command code `TPM_CC_PCR_Allocate` (`TPM2_PCR_Allocate`).
pub const CC_PCR_ALLOCATE: u32 = 0x12B;

/// Raw command code `TPM_CC_PCR_Event` (`TPM2_PCR_Event`).
pub const CC_PCR_EVENT: u32 = 0x13C;

/// Raw command code `TPM_CC_PCR_Extend` (`TPM2_PCR_Extend`).
pub const CC_PCR_EXTEND: u32 = 0x182;

/// Raw command code `TPM_CC_PCR_Read` (`TPM2_PCR_Read`).
pub const CC_PCR_READ: u32 = 0x17E;

/// Raw command code `TPM_CC_PCR_Reset` (`TPM2_PCR_Reset`).
pub const CC_PCR_RESET: u32 = 0x13D;

/// Raw command code `TPM_CC_PCR_SetAuthPolicy` (`TPM2_PCR_SetAuthPolicy`).
pub const CC_PCR_SET_AUTH_POLICY: u32 = 0x12C;

/// Raw command code `TPM_CC_PCR_SetAuthValue` (`TPM2_PCR_SetAuthValue`).
pub const CC_PCR_SET_AUTH_VALUE: u32 = 0x183;

/// Raw command code `TPM_CC_PolicyAuthValue` (`TPM2_PolicyAuthValue`).
pub const CC_POLICY_AUTH_VALUE: u32 = 0x16B;

/// Raw command code `TPM_CC_PolicyCommandCode` (`TPM2_PolicyCommandCode`).
pub const CC_POLICY_COMMAND_CODE: u32 = 0x16C;

/// Raw command code `TPM_CC_PolicyCpHash` (`TPM2_PolicyCpHash`).
pub const CC_POLICY_CP_HASH: u32 = 0x16E;

/// Raw command code `TPM_CC_PolicyGetDigest` (`TPM2_PolicyGetDigest`).
pub const CC_POLICY_GET_DIGEST: u32 = 0x189;

/// Raw command code `TPM_CC_PolicyLocality` (`TPM2_PolicyLocality`).
pub const CC_POLICY_LOCALITY: u32 = 0x16F;

/// Raw command code `TPM_CC_PolicyNV` (`TPM2_PolicyNV`).
pub const CC_POLICY_NV: u32 = 0x149;

/// Raw command code `TPM_CC_PolicyNvWritten` (`TPM2_PolicyNvWritten`).
pub const CC_POLICY_NV_WRITTEN: u32 = 0x18F;

/// Raw command code `TPM_CC_PolicyPassword` (`TPM2_PolicyPassword`).
pub const CC_POLICY_PASSWORD: u32 = 0x18C;

/// The command code of `TPM2_PolicyPCR`.
pub const CC_POLICY_PCR: u32 = 0x0000_017F;

/// Raw command code `TPM_CC_PolicyRestart` (`TPM2_PolicyRestart`).
pub const CC_POLICY_RESTART: u32 = 0x180;

/// Raw command code `TPM_CC_PolicySecret` (`TPM2_PolicySecret`).
pub const CC_POLICY_SECRET: u32 = 0x151;

/// Raw command code `TPM_CC_PolicySigned` (`TPM2_PolicySigned`).
pub const CC_POLICY_SIGNED: u32 = 0x160;

/// Raw command code `TPM_CC_PolicyTemplate` (`TPM2_PolicyTemplate`).
pub const CC_POLICY_TEMPLATE: u32 = 0x190;

/// Raw command code `TPM_CC_ReadPublic` (`TPM2_ReadPublic`).
pub const CC_READ_PUBLIC: u32 = 0x173;

/// Raw command code `TPM_CC_Rewrap` (`TPM2_Rewrap`).
pub const CC_REWRAP: u32 = 0x152;

/// Raw command code `TPM_CC_RSA_Decrypt` (`TPM2_RSA_Decrypt`).
pub const CC_RSA_DECRYPT: u32 = 0x159;

/// Raw command code `TPM_CC_SetPrimaryPolicy` (`TPM2_SetPrimaryPolicy`).
pub const CC_SET_PRIMARY_POLICY: u32 = 0x12E;

/// Raw command code `TPM_CC_Sign` (`TPM2_Sign`).
pub const CC_SIGN: u32 = 0x15D;

/// Raw command code `TPM_CC_StartAuthSession` (`TPM2_StartAuthSession`).
pub const CC_START_AUTH_SESSION: u32 = 0x176;

/// Raw command code `TPM_CC_Startup` (`TPM2_Startup`).
pub const CC_STARTUP: u32 = 0x144;

/// Raw command code `TPM_CC_TestParms` (`TPM2_TestParms`).
pub const CC_TEST_PARMS: u32 = 0x18A;

/// Raw command code `TPM_CC_VerifySignature` (`TPM2_VerifySignature`).
pub const CC_VERIFY_SIGNATURE: u32 = 0x177;

// ===========================================================================
// Response-code constants
//
// Raw `TPM_RC_*` values (with or without handle/parameter/session position bits).
// ===========================================================================

/// `TPM_RC_ATTRIBUTES` format-one response code base value (no handle/parameter/session position bits).
pub const RC_ATTRIBUTES: u32 = 0x082;

/// `TPM_RC_AUTH_FAIL` format-one response code base value (no handle/parameter/session position bits).
pub const RC_AUTH_FAIL: u32 = 0x08E;

/// `TPM_RC_AUTH_FAIL + RC_S1`.
pub const RC_AUTH_FAIL_S1: u32 = 0x98E;

/// `TPM_RC_AUTH_MISSING` (format zero, no position).
pub const RC_AUTH_MISSING: u32 = 0x125;

/// `TPM_RC_AUTH_TYPE` (format zero, no position).
pub const RC_AUTH_TYPE: u32 = 0x124;

/// `TPM_RC_AUTH_UNAVAILABLE` (format zero, no position).
pub const RC_AUTH_UNAVAILABLE: u32 = 0x12F;

/// `TPM_RC_BAD_AUTH` format-one response code base value (no handle/parameter/session position bits).
pub const RC_BAD_AUTH: u32 = 0x0A2;

/// `TPM_RC_BAD_AUTH + RC_S1`.
pub const RC_BAD_AUTH_S1: u32 = 0x9A2;

/// `TPM_RC_BAD_TAG` response code (bad command tag).
pub const RC_BAD_TAG: u32 = 0x01E;

/// `TPM_RC_COMMAND_SIZE` response code (command size does not match the header size field).
pub const RC_COMMAND_SIZE: u32 = 0x142;

/// `TPM_RC_EXCLUSIVE`.
pub const RC_EXCLUSIVE: u32 = 0x121;

/// `TPM_RC_EXPIRED` format-one response code base value (no handle/parameter/session position bits).
pub const RC_EXPIRED: u32 = 0x0A3;

/// `TPM_RC_HANDLE` format-one response code base value (no handle/parameter/session position bits).
pub const RC_HANDLE: u32 = 0x08B;

/// `TPM_RC_INSUFFICIENT` format-one response code base value (no handle/parameter/session position bits).
pub const RC_INSUFFICIENT: u32 = 0x09A;

/// `TPM_RC_KEY` without a position.
pub const RC_KEY: u32 = 0x09C;

/// `TPM_RC_KEY + RC_H1`.
pub const RC_KEY_H1: u32 = 0x19C;

/// `TPM_RC_KEY + RC_H2`.
pub const RC_KEY_H2: u32 = 0x29C;

/// `TPM_RC_LOCKOUT` (warning).
pub const RC_LOCKOUT: u32 = 0x921;

/// `TPM_RC_MODE` format-one response code base value (no handle/parameter/session position bits).
pub const RC_MODE: u32 = 0x089;

/// `TPM_RC_NONCE` format-one response code base value (no handle/parameter/session position bits).
pub const RC_NONCE: u32 = 0x08F;

/// `TPM_RC_NV_UNAVAILABLE` (a warning: `RC_WARN + 0x023`).
pub const RC_NV_UNAVAILABLE: u32 = 0x923;

/// `TPM_RC_POLICY_CC` format-one response code base value (no handle/parameter/session position bits).
pub const RC_POLICY_CC: u32 = 0x0A4;

/// `TPM_RC_POLICY_FAIL` format-one response code base value (no handle/parameter/session position bits).
pub const RC_POLICY_FAIL: u32 = 0x09D;

/// `TPM_RC_REFERENCE_H0`: the first handle references a transient object or session that is not loaded.
pub const RC_REFERENCE_H0: u32 = 0x910;

/// `TPM_RC_REFERENCE_S0`: the first authorization session handle references a session that is not loaded.
pub const RC_REFERENCE_S0: u32 = 0x918;

/// `TPM_RC_SCHEME` without a position.
pub const RC_SCHEME: u32 = 0x092;

/// `TPM_RC_SCHEME + RC_P2`.
pub const RC_SCHEME_P2: u32 = 0x2D2;

/// `TPM_RC_SCHEME + RC_P3`.
pub const RC_SCHEME_P3: u32 = 0x3D2;

/// `TPM_RC_SIZE` format-one response code base value (no handle/parameter/session position bits).
pub const RC_SIZE: u32 = 0x095;

/// `TPM_RC_SUCCESS`.
pub const RC_SUCCESS: u32 = 0;

/// `TPM_RC_SYMMETRIC` format-one response code base value (no handle/parameter/session position bits).
pub const RC_SYMMETRIC: u32 = 0x096;

/// `TPM_RC_TICKET + RC_P4`.
pub const RC_TICKET_P4: u32 = 0x4E0;

/// `TPM_RC_TYPE + RC_H3`.
pub const RC_TYPE_H3: u32 = 0x38A;

/// `TPM_RC_VALUE + RC_H1`.
pub const RC_VALUE_H1: u32 = 0x184;

/// `TPM_RC_VALUE | TPM_RC_P | TPM_RC_1`.
pub const RC_VALUE_P1: u32 = 0x000001C4;

// ===========================================================================
// Other constants and static buffers
//
// Handles, tags, attributes, algorithm IDs, key material and other fixed test data.
// ===========================================================================

/// AES-128 in CFB mode, the usual object symmetric definition.
pub const AES128_CFB: TpmtSymDefObject = TpmtSymDefObject {
    alg: AlgSym::Aes128,
    mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
};

/// AES-256 in CFB mode.
pub const AES256_CFB: TpmtSymDefObject = TpmtSymDefObject {
    alg: AlgSym::Aes256,
    mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
};

/// Raw `TPM_ALG_SHA1` algorithm ID.
pub const ALG_SHA1: u16 = 0x0004;

/// Raw `TPM_ALG_SHA256` algorithm ID.
pub const ALG_SHA256: u16 = 0x000B;

/// Raw `TPM_ALG_SHA384` algorithm ID.
pub const ALG_SHA384: u16 = 0x000C;

/// Raw `TPM_ALG_SHA512` algorithm ID.
pub const ALG_SHA512: u16 = 0x000D;

/// `audit`.
pub const ATTR_AUDIT: u8 = 0x80;

/// `TPMA_SESSION.auditExclusive` bit.
pub const ATTR_AUDIT_EXCLUSIVE: u8 = 0x02;

/// `TPMA_SESSION.auditReset` bit.
pub const ATTR_AUDIT_RESET: u8 = 0x04;

/// `TPMA_SESSION.continueSession` bit.
pub const ATTR_CONT: u8 = 0x01;

/// `continueSession`.
pub const ATTR_CONTINUE: u8 = 0x01;

/// `TPMA_SESSION.decrypt` bit.
pub const ATTR_DECRYPT: u8 = 0x20;

/// `encrypt`.
pub const ATTR_ENCRYPT: u8 = 0x40;

/// 1000 bytes of `0xAA` (static test data for hash sequences).
pub static BUF_1000_AA: [u8; 1000] = [0xAA; 1000];

/// 1000 bytes of `0xBB` (static test data for hash sequences).
pub static BUF_1000_BB: [u8; 1000] = [0xBB; 1000];

/// 1000 bytes of `0xCC` (static test data for hash sequences).
pub static BUF_1000_CC: [u8; 1000] = [0xCC; 1000];

/// 1024 bytes of `0x55` (static test data for hash sequences).
pub static BUF_1024_55: [u8; 1024] = [0x55; 1024];

/// The single byte `b"a"` (static test data for hash sequences).
pub static BUF_A: [u8; 1] = *b"a";

/// Raw `TPM_CAP_ACT` capability.
pub const CAP_ACT: u32 = 0xA;

/// Raw `TPM_CAP_ALGS` capability.
pub const CAP_ALGS: u32 = 0;

/// Raw `TPM_CAP_COMMANDS` capability.
pub const CAP_COMMANDS: u32 = 2;

/// Raw `TPM_CAP_HANDLES` capability.
pub const CAP_HANDLES: u32 = 1;

/// Raw `TPM_CAP_PCR_PROPERTIES` capability.
pub const CAP_PCR_PROPERTIES: u32 = 7;

/// Raw `TPM_CAP_PCRS` capability.
pub const CAP_PCRS: u32 = 5;

/// Private scalar of a fixed NIST P-256 test key (matches [`ECC_X`]/[`ECC_Y`]).
pub const ECC_D: &[u8] = &[
    0xcb, 0x53, 0x36, 0x6e, 0xee, 0x57, 0xf7, 0xed, 0x84, 0x8e, 0xc5, 0x88, 0xa2, 0x61, 0xbd, 0xfb,
    0xae, 0x21, 0x65, 0x46, 0x6e, 0x43, 0x45, 0xc5, 0xb5, 0x80, 0xcf, 0x95, 0xd4, 0x84, 0xfa, 0x5b,
];

// NIST P-256 ECC Coordinates and Private Scalar (same as in load_external_tests.rs)
/// X coordinate of a fixed NIST P-256 test public key.
pub const ECC_X: &[u8] = &[
    0x35, 0x61, 0x24, 0x4d, 0x85, 0x34, 0x89, 0x75, 0x4c, 0xf0, 0x71, 0x0d, 0x87, 0x5a, 0x7b, 0xa4,
    0xb2, 0xac, 0xa9, 0xcc, 0x38, 0xa5, 0xd0, 0x29, 0x85, 0xd4, 0xce, 0xb8, 0x3b, 0xcb, 0xd0, 0xa2,
];

/// Y coordinate of a fixed NIST P-256 test public key.
pub const ECC_Y: &[u8] = &[
    0xf8, 0xf0, 0xb6, 0x85, 0x0f, 0x09, 0x25, 0x25, 0x4f, 0xf6, 0x3a, 0x19, 0xa0, 0x11, 0x25, 0xa8,
    0x89, 0x94, 0xfc, 0x86, 0x60, 0x60, 0x35, 0x4d, 0x93, 0x05, 0xa7, 0x11, 0x68, 0x6d, 0x71, 0x77,
];

/// The policy digest of a fresh SHA-256 policy session (32 zero bytes).
pub const EMPTY_POLICY: [u8; 32] = [0u8; 32];

/// Size of a context integrity HMAC or ticket digest: the digest size of the context-integrity
/// hash, which is the strongest implemented hash (TPM 2.0 Part 1, "Context Integrity
/// Protection"): SHA-512.
pub const CONTEXT_INTEGRITY_DIGEST_SIZE: usize = 64;

/// Offset of `encrypted.size` in the blob: `integrity.size (2) || integrity (64)`.
pub const ENC_SIZE_OFFSET: usize = 2 + CONTEXT_INTEGRITY_DIGEST_SIZE;

/// Size of the sequence fingerprint at the start of the encrypted plaintext.
pub const FINGERPRINT_SIZE: usize = 8;

/// `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, TPM_PT_FAMILY_INDICATOR, 1)` parameters.
pub const GET_CAP_PARAMS: [u8; 12] = [0, 0, 0, 6, 0, 0, 1, 0, 0, 0, 0, 1];

/// Fixed policy digest used where any non-empty `authPolicy` will do.
pub const JUNK_DIGEST: [u8; 32] = [0x11; 32];

/// seedValue of the keyedhash sensitives loaded below. With a nameAlg, C
/// requires a digest-sized seedValue (CryptValidateKeys, else KEY_SIZE+P1).
pub const KEYED_HASH_SEED: [u8; 32] = [0x33; 32];

/// First handle of the `TPM_HT_LOADED_SESSION` range of `TPM_CAP_HANDLES`.
pub const LOADED_SESSION_FIRST: u32 = 0x0200_0000;

/// Maximum number of concurrently active hash/HMAC sequences supported by the TPM.
pub const MAX_ACTIVE_SEQUENCES: usize = 3;

/// Upper bound on the number of sequences the tests try to start when probing the TPM's
/// object capacity (the actual capacity is reported by the TPM through `TPM_RC_OBJECT_MEMORY`).
pub const MAX_PROBED_SEQUENCES: usize = 64;

/// Raw `TPMA_NV_AUTHREAD` bit.
pub const NV_AUTHREAD: u32 = 0x0004_0000;

/// Raw `TPMA_NV_AUTHWRITE` bit.
pub const NV_AUTHWRITE: u32 = 0x0000_0004;

/// Raw `TPMA_NV_NO_DA` bit.
pub const NV_NO_DA: u32 = 0x0200_0000;

/// Raw `TPMA_NV_OWNERREAD` bit.
pub const NV_OWNERREAD: u32 = 0x0002_0000;

// TPMA_NV bits.
/// Raw `TPMA_NV_OWNERWRITE` bit.
pub const NV_OWNERWRITE: u32 = 0x0000_0002;

/// `OWNERWRITE | OWNERREAD` NV attributes.
pub const NV_RW: TpmaNv = TpmaNv::OWNERWRITE.union(TpmaNv::OWNERREAD);

/// Raw `TPMA_NV` type field value for `TPM_NT_PIN_FAIL`.
pub const NV_TYPE_PIN_FAIL: u32 = 0x8 << 4;

/// Raw `TPMA_NV` type field value for `TPM_NT_PIN_PASS`.
pub const NV_TYPE_PIN_PASS: u32 = 0x9 << 4;

/// authValue of the DA-protected sealed object used to provoke authorization failures.
pub const OBJECT_AUTH: &[u8] = b"secret";

/// `OWNERREAD | OWNERWRITE` NV attributes.
pub const OWNER_RW: TpmaNv = TpmaNv::OWNERREAD.union(TpmaNv::OWNERWRITE);

/// The authorization area of one empty `TPM_RS_PW` session (including its size field).
pub const PW_AREA: [u8; 13] = [0, 0, 0, 9, 0x40, 0, 0, 9, 0, 0, 0, 0, 0];

/// An empty-password `TPM_RS_PW` session. In C every handle with an authorization role
/// needs a session even if its authValue is empty; with no session C returns
/// TPM_RC_AUTH_MISSING (SessionProcess.c CheckAuthNoSession).
pub const PW_SESSION: [u8; 9] = [0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00];

/// A password authorization (`TPM_RS_PW`) with an empty password and `continueSession` set.
pub const PW_SESSION_CONTINUE: [u8; 9] = [0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00];

/// Raw `TPM_RH_NULL` handle.
pub const RH_NULL: u32 = 0x4000_0007;

/// Raw `TPM_RH_OWNER` handle.
pub const RH_OWNER: u32 = 0x4000_0001;

/// `TPM_RS_PW`.
pub const RS_PW: u32 = 0x4000_0009;

/// Modulus of a fixed RSA-2048 test key (see [`RSA_P`], [`RSA_Q`]).
pub const RSA_N: &[u8] = &[
    0x9e, 0x67, 0x7c, 0x31, 0xb1, 0xf9, 0x15, 0x8a, 0x41, 0x4d, 0x16, 0xf0, 0x73, 0xbe, 0x59, 0x66,
    0xc0, 0xe3, 0x8d, 0xc3, 0x64, 0x4b, 0x01, 0x3c, 0xce, 0x5c, 0x13, 0x10, 0x41, 0x9f, 0xbc, 0x43,
    0x2d, 0xfa, 0xcb, 0xfc, 0xa4, 0xd8, 0x41, 0x05, 0xbc, 0xcb, 0xe5, 0xc8, 0xd9, 0x13, 0x21, 0x6c,
    0xb0, 0x13, 0xea, 0x10, 0x3a, 0x3b, 0x73, 0xe0, 0x9e, 0x59, 0x11, 0x0f, 0x5c, 0x1f, 0x54, 0x5c,
    0x39, 0x42, 0x1d, 0x45, 0xb4, 0x67, 0x2c, 0x19, 0xf7, 0x6c, 0xe6, 0x13, 0xdd, 0xb7, 0x55, 0x5b,
    0x00, 0xa6, 0xaa, 0x2f, 0x06, 0x2a, 0xa9, 0x23, 0x7f, 0xc0, 0xb8, 0xdd, 0x32, 0xb5, 0x00, 0xc1,
    0xe7, 0x51, 0xe1, 0x71, 0xc1, 0xa3, 0xb3, 0x3a, 0x44, 0x45, 0x6c, 0x43, 0xbb, 0xc1, 0x23, 0x6f,
    0x65, 0x15, 0x6e, 0x25, 0xdd, 0x51, 0x8b, 0x49, 0x04, 0x44, 0xd1, 0x55, 0xd3, 0x88, 0x5f, 0x6a,
    0xd3, 0xc1, 0x58, 0x4b, 0xca, 0xe9, 0xbe, 0x6d, 0x30, 0x46, 0xdd, 0x3c, 0x2b, 0xbb, 0xd7, 0xbd,
    0x94, 0x10, 0x5e, 0x32, 0x6e, 0xcd, 0x24, 0x96, 0x17, 0x7a, 0x88, 0xd7, 0xee, 0x60, 0x58, 0x95,
    0x6a, 0x18, 0x7f, 0x40, 0x53, 0x24, 0xc0, 0x0e, 0xa9, 0x08, 0x9c, 0x03, 0x27, 0xce, 0x0b, 0xcb,
    0xc5, 0x2c, 0xf2, 0xb0, 0xe7, 0xac, 0xe0, 0xfa, 0x84, 0xc4, 0x77, 0x2f, 0x83, 0x3d, 0xe5, 0x7c,
    0x67, 0x94, 0x93, 0x3e, 0x52, 0x6e, 0x21, 0xf3, 0x30, 0xb1, 0x5e, 0xca, 0x39, 0xf5, 0x0b, 0x28,
    0xb4, 0x87, 0x76, 0x77, 0xc3, 0xaf, 0x4f, 0x9c, 0x7f, 0x0c, 0x58, 0x9d, 0x80, 0xf2, 0xf4, 0x93,
    0x6e, 0x03, 0x1e, 0x1d, 0x15, 0x6c, 0xb7, 0xfb, 0xd6, 0x43, 0xe3, 0xd2, 0x58, 0x5a, 0x2e, 0x2d,
    0xc2, 0xb3, 0x69, 0xff, 0x93, 0x35, 0x53, 0x71, 0x51, 0x64, 0x76, 0x41, 0x85, 0x3d, 0x3e, 0x31,
];

/// First prime factor of the fixed RSA-2048 test key [`RSA_N`].
pub const RSA_P: &[u8] = &[
    0xd9, 0xb4, 0x4e, 0xda, 0x74, 0x15, 0xd2, 0xb4, 0x06, 0x7c, 0xff, 0x45, 0xb7, 0xb6, 0xcf, 0xd6,
    0xb2, 0x20, 0xdf, 0x6f, 0xe6, 0x79, 0x8f, 0xc7, 0x42, 0x7e, 0xa1, 0x33, 0xdf, 0x06, 0x2b, 0x92,
    0xc0, 0xb7, 0xa5, 0xcf, 0x03, 0x0b, 0x7b, 0xd5, 0x22, 0x69, 0x7c, 0x7f, 0x4d, 0x8d, 0xe6, 0xcb,
    0x37, 0x1b, 0xe1, 0x39, 0x59, 0x50, 0x1e, 0x6b, 0xe3, 0x81, 0x3b, 0xbe, 0x01, 0x04, 0x45, 0xa3,
    0xab, 0x9a, 0xd5, 0xa4, 0x0a, 0x67, 0xc4, 0xcb, 0xc4, 0xa6, 0x1d, 0x6f, 0xf1, 0x81, 0x15, 0xcc,
    0x76, 0xa7, 0x92, 0x55, 0x0d, 0x5a, 0xa5, 0xf5, 0x46, 0x9c, 0x20, 0x68, 0x77, 0xe6, 0x28, 0x51,
    0x4b, 0x0f, 0x8a, 0x74, 0xe0, 0xa5, 0x3c, 0x13, 0x43, 0x0b, 0x28, 0x4e, 0xe0, 0x15, 0x5e, 0xd6,
    0xce, 0x23, 0x45, 0xbe, 0xc8, 0x34, 0x9b, 0xc9, 0x01, 0x3a, 0x80, 0x27, 0xf4, 0xfe, 0x59, 0xfd,
];

/// Second prime factor of the fixed RSA-2048 test key [`RSA_N`].
pub const RSA_Q: &[u8] = &[
    0xba, 0x44, 0xc4, 0x62, 0xc1, 0x17, 0x8a, 0x2b, 0xf0, 0x11, 0xca, 0xba, 0x79, 0xcb, 0xcd, 0x38,
    0x35, 0x10, 0x73, 0xd0, 0xd4, 0xf4, 0x91, 0xc4, 0x63, 0xa4, 0x7d, 0xa5, 0xcb, 0xab, 0xe5, 0x95,
    0x30, 0x08, 0x47, 0x93, 0x95, 0xca, 0x36, 0x04, 0x3a, 0xf2, 0xb8, 0x8a, 0x78, 0x0a, 0x35, 0xde,
    0x0c, 0xc3, 0xdb, 0xeb, 0x42, 0x9f, 0xdb, 0xf0, 0x94, 0xd0, 0x72, 0x32, 0x91, 0x4f, 0xef, 0x7b,
    0xc3, 0x81, 0x5a, 0x80, 0x00, 0x6c, 0x60, 0x44, 0xbc, 0x36, 0x56, 0xb5, 0x74, 0x65, 0x33, 0x86,
    0x5d, 0x86, 0x6a, 0x45, 0x0b, 0x9b, 0xa5, 0x66, 0xe9, 0x1b, 0x69, 0x16, 0x70, 0xad, 0xd2, 0x87,
    0x2d, 0x5f, 0x2f, 0x10, 0x86, 0xf8, 0x52, 0xe4, 0x2b, 0xbd, 0x96, 0xc6, 0xd1, 0x1f, 0x0d, 0x87,
    0xb1, 0x91, 0x8f, 0x7a, 0xdf, 0x30, 0x5d, 0x2b, 0xa6, 0xe6, 0x4a, 0x76, 0xd9, 0x39, 0x01, 0x45,
];

/// Raw `TPM2_Shutdown(TPM_SU_CLEAR)` command.
pub const SHUTDOWN_CLEAR: [u8; 12] = [0x80, 0x01, 0, 0, 0, 0x0c, 0, 0, 0x01, 0x45, 0x00, 0x00];

/// Raw `TPM2_Shutdown` / `TPM2_Startup` commands.
pub const SHUTDOWN_STATE: [u8; 12] = [0x80, 0x01, 0, 0, 0, 0x0c, 0, 0, 0x01, 0x45, 0x00, 0x01];

/// `TPM_ST_NO_SESSIONS`.
pub const ST_NO_SESSIONS: u16 = 0x8001;

/// `TPM_ST_SESSIONS`.
pub const ST_SESSIONS: u16 = 0x8002;

/// Raw `TPM2_Startup(TPM_SU_CLEAR)` command.
pub const STARTUP_CLEAR: [u8; 12] = [0x80, 0x01, 0, 0, 0, 0x0c, 0, 0, 0x01, 0x44, 0x00, 0x00];

/// Time advanced by each `sleep` in these tests, in milliseconds.
pub const STEP_MS: u64 = 150;

/// `TPM_SU_CLEAR`.
pub const SU_CLEAR: u16 = 0x0000;

/// `TPM_SU_STATE`.
pub const SU_STATE: u16 = 0x0001;

/// Raw command code `TPM_CC_Shutdown` (`TPM2_Shutdown`).
pub const TPM_CC_SHUTDOWN: u32 = 0x145;

/// Raw command code `TPM_CC_Startup` (`TPM2_Startup`).
pub const TPM_CC_STARTUP: u32 = 0x144;

/// `TPM_SU_CLEAR`.
pub const TPM_SU_CLEAR: u16 = 0x0000;

/// `TPM_SU_STATE`.
pub const TPM_SU_STATE: u16 = 0x0001;

/// `TPMA_CC.extensive` bit.
pub const TPMA_CC_EXTENSIVE: u32 = 1 << 23;

/// `TPMA_CC.flushed` bit.
pub const TPMA_CC_FLUSHED: u32 = 1 << 24;

/// `TPMA_CC.nv` bit.
pub const TPMA_CC_NV: u32 = 1 << 22;

/// First handle of the transient object range.
pub const TRANSIENT_FIRST: u32 = 0x8000_0000;

// ===========================================================================
// Raw command transport and response decoding
//
// Building raw command buffers, sending them to the simulator (optionally at a locality) and decoding response codes/headers.
// ===========================================================================

/// Response code with the same `get()` accessor as the simulator's execute errors.
#[derive(Debug)]
pub struct RawRc(pub u32);

impl RawRc {
    pub fn get(&self) -> u32 {
        self.0
    }
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

/// The marshalled handle area of `cmd` (one big-endian `u32` per handle of
/// [`Message::handles`]).
pub fn handle_area<C: Message>(cmd: &C) -> Vec<u8> {
    cmd.handles()
        .as_ref()
        .iter()
        .flat_map(|h| h.0.to_be_bytes())
        .collect()
}

/// Unmarshals the response of command `C` from the successful raw response `rsp` (header
/// included): the response handles, `parameterSize` (if the tag is `TPM_ST_SESSIONS`) and
/// the response parameters, which borrow leaked memory.
pub fn unmarshal_response<C: Command>(rsp: &[u8]) -> Result<C::Response<'static>, UnmarshalError> {
    let mut slice: &'static [u8] = leak_bytes(rsp.get(10..).ok_or(UnmarshalError::INSUFFICIENT)?);
    let mut handles = <C::Response<'static> as Message>::Handles::default();
    for handle in handles.as_mut() {
        *handle = Handle::unmarshal(&mut slice)?;
    }
    if rsp[0..2] == [0x80, 0x02] {
        let size = u32::unmarshal(&mut slice)? as usize;
        slice = slice.get(..size).ok_or(UnmarshalError::INSUFFICIENT)?;
    }
    <C::Response<'static>>::unmarshal_with_handles(handles, &mut slice)
}

/// Marshals the authorization sessions `auths` (without the `authorizationSize` prefix).
///
/// Non-generic for the same reason as [`marshal_auth_command`].
pub fn marshal_auth_area(auths: &[TpmsAuthCommand<'_>]) -> Vec<u8> {
    auths.iter().flat_map(marshal_to_vec).collect()
}

/// Marshals `cmd` (its handles and the authorization area `auths`) into a raw command.
pub fn build_cmd<C: Command>(cmd: &C, auths: &[TpmsAuthCommand<'_>]) -> Vec<u8>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let tag: u16 = if auths.is_empty() { 0x8001 } else { 0x8002 };
    let mut req = Vec::new();
    req.extend_from_slice(&tag.to_be_bytes());
    req.extend_from_slice(&[0u8; 4]);
    req.extend_from_slice(&C::CMD_CODE.code().to_be_bytes());
    req.extend_from_slice(&handle_area(cmd));
    if !auths.is_empty() {
        let area = marshal_auth_area(auths);
        req.extend_from_slice(&(area.len() as u32).to_be_bytes());
        req.extend_from_slice(&area);
    }
    req.extend_from_slice(&marshal_to_vec(cmd));
    let len = req.len() as u32;
    req[2..6].copy_from_slice(&len.to_be_bytes());
    req
}

/// Marshals `cmd` (its handles and the authorization area `auths`) into a raw command
/// and returns it together with the offset of the parameter area. The size field is filled
/// in by [`send`].
pub fn build_cmd_with_param_offset<C: Command>(
    cmd: &C,
    auths: &[TpmsAuthCommand<'_>],
) -> (Vec<u8>, usize)
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let tag: u16 = if auths.is_empty() { 0x8001 } else { 0x8002 };
    let mut req = Vec::new();
    req.extend_from_slice(&tag.to_be_bytes());
    req.extend_from_slice(&[0u8; 4]);
    req.extend_from_slice(&C::CMD_CODE.code().to_be_bytes());
    req.extend_from_slice(&handle_area(cmd));
    if !auths.is_empty() {
        let area = marshal_auth_area(auths);
        req.extend_from_slice(&(area.len() as u32).to_be_bytes());
        req.extend_from_slice(&area);
    }
    let param_start = req.len();
    req.extend_from_slice(&marshal_to_vec(cmd));
    (req, param_start)
}

/// Marshals `cmd` (its handles, the authorization area `auths` and `trailing` extra
/// bytes after the parameters) into a raw command.
pub fn build_cmd_with_trailing<C: Command>(
    cmd: &C,
    auths: &[TpmsAuthCommand<'_>],
    trailing: &[u8],
) -> Vec<u8>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let tag: u16 = if auths.is_empty() { 0x8001 } else { 0x8002 };
    let mut req = Vec::new();
    req.extend_from_slice(&tag.to_be_bytes());
    req.extend_from_slice(&[0u8; 4]);
    req.extend_from_slice(&C::CMD_CODE.code().to_be_bytes());
    req.extend_from_slice(&handle_area(cmd));
    if !auths.is_empty() {
        let area = marshal_auth_area(auths);
        req.extend_from_slice(&(area.len() as u32).to_be_bytes());
        req.extend_from_slice(&area);
    }
    req.extend_from_slice(&marshal_to_vec(cmd));
    req.extend_from_slice(trailing);
    let len = req.len() as u32;
    req[2..6].copy_from_slice(&len.to_be_bytes());
    req
}

/// Builds a raw command authorized with one empty-password session per entry of `handles`
/// that is listed in `auth_count` (the first `auth_count` handles).
pub fn build_pw_cmd(cc: u32, handles: &[u32], auth_count: usize, params: &[u8]) -> Vec<u8> {
    let sessions: Vec<u8> = PW_SESSION_CONTINUE.repeat(auth_count);
    build_raw_cmd(ST_SESSIONS, cc, handles, Some(&sessions), params)
}

/// Builds a raw command with the given tag, command code, handle area, optional session area
/// (the concatenated `TPMS_AUTH_COMMAND`s, without the `authorizationSize` prefix) and
/// parameter area.
pub fn build_raw_cmd(
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

/// Builds a `TPM2_Certify` of `key_handle` signed by itself, a command with two
/// authorization handles (objectHandle ADMIN, signHandle USER).
pub fn certify_cmd_and_handles(key_handle: Handle) -> Certify<'static> {
    Certify {
        object_handle: key_handle,
        sign_handle: key_handle,
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    }
}

/// Returns the response code of executing `cmd` (0 on success).
pub fn command_rc<C: Command>(sim: &mut Tpm, cmd: &C, sessions: usize) -> u32
where
    for<'b> &'b mut C::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    match run(sim, cmd, sessions) {
        Ok(_) => 0,
        Err(rc) => rc,
    }
}

/// Computes `HASH(old || new)` with the client-side crypto provider.
pub fn compute_expected_extend(alg: TpmiAlgHash, old: &[u8], new: &[u8]) -> Vec<u8> {
    let mut ctx = HashStream::new(CLIENT_CRYPTO, alg).unwrap();
    ctx.update(old).unwrap();
    ctx.update(new).unwrap();
    let mut out = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    ctx.finalize(&mut out).unwrap().digest().to_vec()
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
                crate::_common::client_random(&mut nonce).unwrap();
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

/// Executes `cmd` with the given authorizations; returns the response (which carries the
/// response handles), or the response code on failure.
pub fn exec_command<C: Command>(
    sim: &mut Tpm,
    cmd: &C,
    auths: &[TpmsAuthCommand<'_>],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let req = build_cmd(cmd, auths);
    let mut buf = vec![0u8; 8192];
    let rsp = sim.transact(&req, &mut buf).unwrap().to_vec();
    let rc = u32::from_be_bytes(rsp[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }
    Ok(unmarshal_response::<C>(&rsp).unwrap())
}

/// Executes `cmd` with one empty password session. TPM2_HMAC, TPM2_RSA_Decrypt and TPM2_Sign
/// require USER authorization of their key handle, so C rejects them without a session
/// (TPM_RC_AUTH_MISSING); the session makes the command reach the checks under test.
pub fn exec_pw<C: Command>(sim: &mut Tpm, cmd: C) -> Result<C::Response<'static>, RawRc>
where
    for<'b> &'b mut C::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    execute_with_password_sessions(sim, &cmd, 1, &[]).map_err(RawRc)
}

/// Executes `cmd` with one `TPM_RS_PW` session per entry of `passwords` (in handle order) and
/// returns the response parameters or the response code.
pub fn exec_pws<C: Command>(
    sim: &mut Tpm,
    cmd: &C,
    passwords: &[&[u8]],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut C::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let tag: u16 = if passwords.is_empty() { 0x8001 } else { 0x8002 };
    let mut req = Vec::new();
    req.extend_from_slice(&tag.to_be_bytes());
    req.extend_from_slice(&0u32.to_be_bytes());
    req.extend_from_slice(&C::CMD_CODE.code().to_be_bytes());
    req.extend_from_slice(&handle_area(cmd));
    if !passwords.is_empty() {
        let mut auth = Vec::new();
        for pw in passwords {
            auth.extend_from_slice(&Handle::RS_PW.0.to_be_bytes());
            auth.extend_from_slice(&0u16.to_be_bytes()); // nonce
            auth.push(0x01); // continueSession
            auth.extend_from_slice(&(pw.len() as u16).to_be_bytes());
            auth.extend_from_slice(pw);
        }
        req.extend_from_slice(&(auth.len() as u32).to_be_bytes());
        req.extend_from_slice(&auth);
    }
    req.extend_from_slice(&marshal_to_vec(cmd));
    let len = req.len() as u32;
    req[2..6].copy_from_slice(&len.to_be_bytes());

    let mut buf = vec![0u8; 8192];
    let resp = sim.transact(&req, &mut buf).unwrap().to_vec();
    let rc = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }
    Ok(unmarshal_response::<C>(&resp).unwrap())
}

/// Executes `cmd` at `locality` and returns the response (which carries the response
/// handles), or the response code on failure.
pub fn execute_at<C: Command>(
    sim: &mut Tpm,
    locality: u8,
    cmd: &C,
    auths: &[TpmsAuthCommand<'_>],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let resp = send_raw_at(sim, locality, &build_cmd(cmd, auths));
    let rc = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }
    Ok(unmarshal_response::<C>(&resp).unwrap())
}

/// Sends the raw command `cmd_bytes` and returns `Err(rc)` if the response code is non-zero.
pub fn execute_raw_transact(tpm: &mut Tpm, cmd_bytes: &[u8]) -> Result<(), u32> {
    let mut resp_buffer = [0u8; 4096];
    tpm.transact(cmd_bytes, &mut resp_buffer).unwrap();

    let mut slice = &resp_buffer[..];
    let resp_header = RespHeader::unmarshal(&mut slice).unwrap();
    if resp_header.rc != 0 {
        return Err(resp_header.rc);
    }
    Ok(())
}

/// Executes `cmd` with the authorization area `auths` and returns the response code.
pub fn execute_rc<C: Command>(sim: &mut Tpm, cmd: &C, auths: &[TpmsAuthCommand<'_>]) -> u32
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let tag: u16 = if auths.is_empty() { 0x8001 } else { 0x8002 };
    let mut req = Vec::new();
    req.extend_from_slice(&tag.to_be_bytes());
    req.extend_from_slice(&[0u8; 4]);
    req.extend_from_slice(&C::CMD_CODE.code().to_be_bytes());
    req.extend_from_slice(&handle_area(cmd));
    if !auths.is_empty() {
        let area = marshal_auth_area(auths);
        req.extend_from_slice(&(area.len() as u32).to_be_bytes());
        req.extend_from_slice(&area);
    }
    req.extend_from_slice(&marshal_to_vec(cmd));
    let len = req.len() as u32;
    req[2..6].copy_from_slice(&len.to_be_bytes());
    let mut resp = vec![0u8; 4096];
    let resp = sim.transact(&req, &mut resp).unwrap();
    u32::from_be_bytes(resp[6..10].try_into().unwrap())
}

/// Executes `cmd` and returns the response (which carries the response handles), or the
/// response code.
pub fn execute_tpm_command<C: Command>(
    sim: &mut Tpm,
    cmd: &C,
    auths: &[TpmsAuthCommand<'_>],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let req = build_cmd(cmd, auths);
    let mut buf = vec![0u8; 16384];
    let resp = sim.transact(&req, &mut buf).unwrap();
    let rc = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }
    Ok(unmarshal_response::<C>(resp).unwrap())
}

/// Executes `cmd` at locality 0.
pub fn execute_tpm_command_at_locality0<C: Command>(
    sim: &mut Tpm,
    cmd: &C,
    auths: &[TpmsAuthCommand<'_>],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    execute_at(sim, 0, cmd, auths)
}

/// Builds and sends `cmd`; when it has handles, adds one empty `TPM_RS_PW`
/// session. Returns the parsed response or the response code (`0xFFFFFFFF` if parsing fails).
pub fn execute_tpm_command_auto_pw<Cmd>(
    sim: &mut Tpm,
    cmd: &Cmd,
) -> Result<Cmd::Response<'static>, u32>
where
    Cmd: Command,
    for<'b> &'b mut <Cmd as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let handles_bytes = handle_area(cmd);
    // Every handle passed to this helper is a sequence handle, which has the USER auth role:
    // C requires a session even for an empty authValue (TPM_RC_AUTH_MISSING otherwise,
    // SessionProcess.c CheckAuthNoSession), so send an empty TPM_RS_PW session.
    let with_session = !handles_bytes.is_empty();
    let tag = if with_session { 0x8002u16 } else { 0x8001u16 };

    let mut req = tag.to_be_bytes().to_vec();
    req.extend_from_slice(&0u32.to_be_bytes());
    req.extend_from_slice(&Cmd::CMD_CODE.code().to_be_bytes());
    req.extend_from_slice(&handles_bytes);
    if with_session {
        req.extend_from_slice(&PW_AREA);
    }
    req.extend_from_slice(&marshal_to_vec(cmd));
    let len = req.len() as u32;
    req[2..6].copy_from_slice(&len.to_be_bytes());

    let mut resp_buf = [0u8; 32768];
    let resp = sim.transact(&req, &mut resp_buf).expect("transact failed");

    let rc = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    unmarshal_response::<Cmd>(resp).map_err(|_| 0xFFFFFFFFu32)
}

/// Executes `cmd` and returns its response (which carries the response handles), or the
/// response code.
///
/// Every handle passed to this helper is a sequence handle, which has the USER auth role:
/// C requires a session even for an empty authValue (TPM_RC_AUTH_MISSING otherwise,
/// SessionProcess.c CheckAuthNoSession), so an empty `TPM_RS_PW` session is sent whenever
/// the command has handles.
pub fn execute_tpm_command_auto_pw_unwrap<C: Command>(
    sim: &mut Tpm,
    cmd: &C,
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let handle_bytes = handle_area(cmd);
    let with_session = !handle_bytes.is_empty();
    let tag: u16 = if with_session { 0x8002 } else { 0x8001 };
    let mut req = Vec::new();
    req.extend_from_slice(&tag.to_be_bytes());
    req.extend_from_slice(&[0u8; 4]);
    req.extend_from_slice(&C::CMD_CODE.code().to_be_bytes());
    req.extend_from_slice(&handle_bytes);
    if with_session {
        // authSize = 9, then an empty TPM_RS_PW session.
        req.extend_from_slice(&[0, 0, 0, 9, 0x40, 0, 0, 9, 0, 0, 0, 0, 0]);
    }
    req.extend_from_slice(&marshal_to_vec(cmd));
    let len = req.len() as u32;
    req[2..6].copy_from_slice(&len.to_be_bytes());

    let mut resp_buf = vec![0u8; 8192];
    let resp = sim.transact(&req, &mut resp_buf).unwrap().to_vec();
    let rc = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }
    Ok(unmarshal_response::<C>(&resp).unwrap())
}

/// Marshals `cmd` (with its handles) and the authorization area `auths`,
/// executes it, and unmarshals the response (which carries the response handles).
///
/// Returns the raw response code on failure.
pub fn execute_tpm_command_full<C: Command>(
    sim: &mut Tpm,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut request = Vec::new();
    request.extend_from_slice(
        &(if auths.is_empty() {
            0x8001u16
        } else {
            0x8002u16
        })
        .to_be_bytes(),
    );
    request.extend_from_slice(&[0u8; 4]); // commandSize, patched below
    request.extend_from_slice(&C::CMD_CODE.code().to_be_bytes());
    request.extend_from_slice(&handle_area(cmd));
    if !auths.is_empty() {
        request.extend_from_slice(&auth_area(auths));
    }
    request.extend_from_slice(&marshal_to_vec(cmd));
    let size = request.len() as u32;
    request[2..6].copy_from_slice(&size.to_be_bytes());

    let mut response = [0u8; 16384];
    let response = sim.transact(&request, &mut response).expect("transact");
    parse_response::<C>(response)
}

/// Marshals `cmd` (with its handles) and the authorization area `auths`,
/// executes it, and unmarshals the response (which carries the response handles).
///
/// Returns the raw response code on failure.
pub fn execute_tpm_command_mapping_parse_errors<C: Command>(
    sim: &mut Tpm,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut request = Vec::new();
    request.extend_from_slice(
        &(if auths.is_empty() {
            0x8001u16
        } else {
            0x8002u16
        })
        .to_be_bytes(),
    );
    request.extend_from_slice(&[0u8; 4]); // commandSize, patched below
    request.extend_from_slice(&C::CMD_CODE.code().to_be_bytes());
    request.extend_from_slice(&handle_area(cmd));
    if !auths.is_empty() {
        request.extend_from_slice(&auth_area(auths));
    }
    request.extend_from_slice(&marshal_to_vec(cmd));
    let size = request.len() as u32;
    request[2..6].copy_from_slice(&size.to_be_bytes());

    let mut response = [0u8; 16384];
    let response = sim.transact(&request, &mut response).expect("transact");
    parse_response::<C>(response)
}

/// Executes a typed TPM command with the given authorizations and returns either its
/// unmarshalled output or the raw response code.
pub fn execute_tpm_command_offsets<C: Command>(
    sim: &mut Tpm,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut request = header(!auths.is_empty(), C::CMD_CODE);
    request.extend_from_slice(&handle_area(cmd));
    if !auths.is_empty() {
        request.extend_from_slice(&auth_area(auths));
    }
    request.extend_from_slice(&marshal_to_vec(cmd));
    let response = run_raw(sim, &finish(request));
    parse_response::<C>(&response)
}

/// Executes a typed TPM command with the given authorizations and returns either its
/// unmarshalled output or the raw response code.
pub fn execute_tpm_command_uncorrupted<C: Command>(
    sim: &mut Tpm,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    execute_tpm_command_with_corrupted_bytes(sim, cmd, auths, |_| {})
}

/// Executes `cmd` and returns its response (carrying the response handles), or the response code.
pub fn execute_tpm_command_via_run<C: Command>(
    sim: &mut Tpm,
    cmd: &C,
    auths: &[TpmsAuthCommand<'_>],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    run_with_trailing(sim, cmd, auths, &[])
}

/// Executes `cmd` and returns the response (carrying the response handles), or the response code.
pub fn execute_tpm_command_via_send<C: Command>(
    sim: &mut Tpm,
    cmd: &C,
    auths: &[TpmsAuthCommand<'_>],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let (req, _) = build_cmd_with_param_offset(cmd, auths);
    send_and_parse::<C>(sim, req)
}

/// Executes a typed TPM command with the given authorizations and returns either its
/// unmarshalled output or the raw response code. `corrupt_fn` may modify the marshalled
/// parameter area before it is sent.
pub fn execute_tpm_command_with_corrupted_bytes<C: Command>(
    sim: &mut Tpm,
    cmd: &C,
    auths: &[TpmsAuthCommand],
    corrupt_fn: impl FnOnce(&mut [u8]),
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut request = header(!auths.is_empty(), C::CMD_CODE);
    request.extend_from_slice(&handle_area(cmd));
    if !auths.is_empty() {
        request.extend_from_slice(&auth_area(auths));
    }
    let mut payload = marshal_to_vec(cmd);
    corrupt_fn(&mut payload);
    request.extend_from_slice(&payload);
    let response = run_raw(sim, &finish(request));
    parse_response::<C>(&response)
}

/// Executes `cmd` after `corrupt_fn` has modified its marshaled parameter area.
pub fn execute_tpm_command_with_corrupted_bytes_via_send<C: Command>(
    sim: &mut Tpm,
    cmd: &C,
    auths: &[TpmsAuthCommand<'_>],
    corrupt_fn: impl FnOnce(&mut [u8]),
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let (mut req, param_start) = build_cmd_with_param_offset(cmd, auths);
    corrupt_fn(&mut req[param_start..]);
    send_and_parse::<C>(sim, req)
}

/// Like [`execute_tpm_command`], but appends 4 dummy bytes after the parameter area.
pub fn execute_tpm_command_with_extra_bytes<C: Command>(
    sim: &mut Tpm,
    cmd: &C,
    auths: &[TpmsAuthCommand<'_>],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    run_with_trailing(sim, cmd, auths, &[0xDE, 0xAD, 0xBE, 0xEF])
}

/// Executes `cmd` with one trailing byte (0xFF) appended to the command and returns only
/// the response code.
pub fn execute_tpm_command_with_trailing<C: Command>(
    sim: &mut Tpm,
    cmd: &C,
    auths: &[TpmsAuthCommand<'_>],
) -> Result<(), u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let (mut req, _) = build_cmd_with_param_offset(cmd, auths);
    req.push(0xFF);
    let len = req.len() as u32;
    req[2..6].copy_from_slice(&len.to_be_bytes());
    let mut buf = vec![0u8; 16384];
    let resp = sim.transact(&req, &mut buf).unwrap();
    match u32::from_be_bytes(resp[6..10].try_into().unwrap()) {
        0 => Ok(()),
        rc => Err(rc),
    }
}

/// Expected `TPM2_Import` response code for an inner-wrapped `duplicate` without an outer
/// wrapper, following C `DuplicateToSensitive()` / `CheckInnerIntegrity()`: the blob is decrypted
/// with AES-128-CFB (zero IV), then the leading `TPM2B_DIGEST` integrity is unmarshaled
/// (TPM_RC_SIZE if its size exceeds a digest, TPM_RC_INSUFFICIENT if the data is too short) and
/// otherwise compared (TPM_RC_INTEGRITY for these garbage blobs). TPM2_Import reports it against
/// `duplicate` (+P3).
pub fn expected_inner_wrapper_rc(key: &[u8], duplicate: &[u8]) -> u32 {
    let mut data = duplicate.to_vec();
    let mut iv = [0u8; 16];
    sym_decrypt(CLIENT_CRYPTO, AES128_CFB, key, &mut iv, &mut data).unwrap();
    let rc = if data.len() < 2 {
        TpmRc::INSUFFICIENT
    } else {
        let size = u16::from_be_bytes([data[0], data[1]]) as usize;
        if size > 64 {
            TpmRc::SIZE
        } else if 2 + size > data.len() {
            TpmRc::INSUFFICIENT
        } else {
            TpmRc::INTEGRITY
        }
    };
    rc.with(Position::parameter(3)).get()
}

/// Builds a command header with the given tag and command code (size filled in later).
pub fn header(sessions: bool, cc: tpm2::TpmCc) -> Vec<u8> {
    let tag: u16 = if sessions { 0x8002 } else { 0x8001 };
    let mut out = tag.to_be_bytes().to_vec();
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&cc.code().to_be_bytes());
    out
}

/// Decodes a hex string, ignoring whitespace.
pub fn hex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

/// Decodes a hex string, ignoring whitespace.
pub fn hex_checked(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert_eq!(digits.len() % 2, 0, "odd number of hex digits");
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

/// Decodes a hex string (whitespace ignored) into bytes; panics on invalid digits.
pub fn hex_decode(s: &str) -> Vec<u8> {
    let mut res = Vec::with_capacity(s.len() / 2);
    let mut iter = s.chars().filter(|c| !c.is_whitespace());
    while let (Some(c1), Some(c2)) = (iter.next(), iter.next()) {
        let hex_str = format!("{}{}", c1, c2);
        res.push(u8::from_str_radix(&hex_str, 16).unwrap());
    }
    res
}

/// `TPM_RC_INTEGRITY + TPM_RC_P + TPM_RC_1`, the error `TPM2_ContextLoad` returns for a context
/// blob whose integrity check fails.
pub fn integrity_rc() -> u32 {
    // C: TPM_RCS_INTEGRITY + RC_ContextLoad_context (0x1DF), ContextLoad.c:76.
    TpmRc::INTEGRITY.with(Position::parameter(1)).get()
}

/// `TPM2_MAC` parameters: `TPM2B("hello")` and the given MAC scheme.
pub fn mac_params(scheme: u16) -> Vec<u8> {
    let mut p = 5u16.to_be_bytes().to_vec();
    p.extend_from_slice(b"hello");
    p.extend_from_slice(&scheme.to_be_bytes());
    p
}

/// Sends a raw command at locality 0 and returns only the response code.
pub fn mssim_rc_of(sim: &mut Tpm, cmd: &[u8]) -> u32 {
    send_with_rc(sim, cmd).0
}

/// Parses a successful response into the response of `C` (which carries the response
/// handles). Returns the response code on failure (`TPM_RC_FAILURE` if the response cannot
/// be unmarshalled).
pub fn parse_response<C: Command>(response: &[u8]) -> Result<C::Response<'static>, u32> {
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }
    unmarshal_response::<C>(response).map_err(|_| TpmRc::FAILURE.get())
}

/// Appends a TPM2B (big-endian `u16` size followed by `data`) to `buf`.
pub fn push_2b(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Appends a TPM2B (big-endian `u16` size followed by `data`) to `buf`.
pub fn put_tpm2b(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Sends the raw command `cmd` and returns the full response.
pub fn raw(sim: &mut Tpm, cmd: &[u8]) -> Vec<u8> {
    let mut rsp = [0u8; 4096];
    sim.transact(cmd, &mut rsp)
        .expect("transact failed")
        .to_vec()
}

/// Sends the raw command `cmd` at `locality` and
/// returns the full response.
pub fn raw_at(sim: &mut Tpm, locality: u8, cmd: &[u8]) -> Vec<u8> {
    sim.send_command(locality, cmd)
}

/// Sends a raw command at `locality` and returns the full response.
pub fn raw_at_checked(sim: &mut Tpm, locality: u8, cmd: &[u8]) -> Vec<u8> {
    let rsp = sim.send_command(locality, cmd);
    assert!(rsp.len() >= 10, "short response");
    rsp
}

/// An authorization entry for `session` with an explicit `hmac` value.
pub fn raw_entry(session: &ActiveSession, attrs: u8, hmac: &[u8]) -> AuthEntry {
    let mut nonce = [0u8; 16];
    crate::_common::client_random(&mut nonce).unwrap();
    AuthEntry {
        handle: session.session_handle.0,
        nonce: nonce.to_vec(),
        attrs,
        hmac: hmac.to_vec(),
    }
}

/// Sends a raw command at locality 0 and returns the full response.
pub fn raw_mssim(sim: &mut Tpm, cmd: &[u8]) -> Vec<u8> {
    raw_at_checked(sim, 0, cmd)
}

/// Sends the raw command `cmd` and returns the response code.
pub fn raw_rc(sim: &mut Tpm, cmd: &[u8]) -> u32 {
    let rsp = run_raw(sim, cmd);
    u32::from_be_bytes(rsp[6..10].try_into().unwrap())
}

/// Sends a raw command at `locality` and returns the response code.
pub fn raw_rc_at(sim: &mut Tpm, locality: u8, cmd: &[u8]) -> u32 {
    let rsp = raw_at_checked(sim, locality, cmd);
    u32::from_be_bytes(rsp[6..10].try_into().unwrap())
}

/// Response code of a format-zero error.
pub fn rc0(rc: TpmRc) -> u32 {
    rc.get()
}

/// Response code of a format-one error without a position.
pub fn rc1(rc: tpm2::errors::Fmt1) -> u32 {
    rc.to_rc().get()
}

/// Returns the raw response code of a positioned format-one error.
pub fn rc_at(rc: tpm2::errors::Fmt1, pos: Position) -> u32 {
    rc.with(pos).get()
}

/// Sends the raw command `cmd` at `locality` and returns the response code.
pub fn rc_at_locality(sim: &mut Tpm, locality: u8, cmd: &[u8]) -> u32 {
    let rsp = raw_at(sim, locality, cmd);
    assert!(rsp.len() >= 10, "short response");
    u32::from_be_bytes(rsp[6..10].try_into().unwrap())
}

/// Returns the raw response code of a bare format-one error.
pub fn rc_bare(rc: tpm2::errors::Fmt1) -> u32 {
    rc.to_rc().get()
}

/// Expected response code `rc` with a handle position.
pub fn rc_h(rc: Fmt1, h: u8) -> u32 {
    rc.with(Position::handle(h)).get()
}

/// Returns the response code of a raw response.
pub fn rc_of(resp: &[u8]) -> u32 {
    u32::from_be_bytes(resp[6..10].try_into().unwrap())
}

/// Returns the TPM response code carried by `err`.
pub fn rc_of_error(err: ExecuteError) -> u32 {
    match err {
        ExecuteError::Tpm(rc) => rc.get(),
        other => panic!("unexpected execute error: {other}"),
    }
}

/// Expected response code `rc` with a parameter position.
pub fn rc_p(rc: Fmt1, p: u8) -> u32 {
    rc.with(Position::parameter(p)).get()
}

/// Expected response code `rc` with a session position.
pub fn rc_s(rc: Fmt1, s: u8) -> u32 {
    rc.with(Position::session(s)).get()
}

/// Adds the `TPM_RC_S + TPM_RC_1` position (first session) to a format-one response code.
pub fn rc_s1(rc: u32) -> u32 {
    rc | 0x900
}

/// Returns the response code of `resp`.
pub fn response_rc(resp: &[u8]) -> u32 {
    u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]])
}

/// Executes `cmd` with `sessions` empty password sessions (no session area if 0).
pub fn run<C: Command>(sim: &mut Tpm, cmd: &C, sessions: usize) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut C::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    execute_with_password_sessions(sim, cmd, sessions, &[])
}

/// Runs a session-less command (policy commands authorize nothing).
pub fn run_command<C: tpm2::commands::Command>(
    sim: &mut Tpm,
    cmd: C,
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut C::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    execute_with_password_sessions(sim, &cmd, 0, &[])
}

/// Hashes `chunks` + `final_chunk` with a `TPM2_HashSequenceStart`/`SequenceUpdate`/
/// `SequenceComplete` sequence and checks the result against a client-side hash with `alg`.
pub fn run_differential_case(
    sim: &mut Tpm,
    alg: TpmiAlgHash,
    chunks: &[&[u8]],
    final_chunk: &[u8],
) {
    // 1. Start sequence
    let start_cmd = HashSequenceStart {
        auth: Default::default(),
        hash_alg: Some(alg),
    };
    let start_resp = execute_tpm_command_auto_pw(sim, &start_cmd).unwrap();
    let handle = start_resp.sequence_handle;

    // 2. Perform updates. C streams sequence data into the hash state and has no length
    // limit (SequenceUpdate.c has no TPM_RC_MEMORY path), so every update must succeed.
    for chunk in chunks {
        let update_cmd = SequenceUpdate {
            sequence_handle: handle,
            buffer: tpm2::Tpm2bMaxBuffer::from_bytes(chunk).unwrap(),
        };

        execute_tpm_command_auto_pw(sim, &update_cmd).unwrap();
    }

    // 3. Complete sequence
    let complete_cmd = SequenceComplete {
        sequence_handle: handle,
        buffer: tpm2::Tpm2bMaxBuffer::from_bytes(final_chunk).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let complete_resp = execute_tpm_command_auto_pw(sim, &complete_cmd).unwrap();

    // Verify against direct hashing
    let mut concatenated = Vec::new();
    for chunk in chunks {
        concatenated.extend_from_slice(chunk);
    }
    concatenated.extend_from_slice(final_chunk);

    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let expected_digest_bytes = tpm2::crypto::hash(CLIENT_CRYPTO, alg, &concatenated, &mut out)
        .unwrap()
        .digest()
        .to_vec();

    assert_eq!(
        complete_resp.result.get_buffer(),
        &expected_digest_bytes[..]
    );
}

/// Executes a command with one (empty) password session for its first handle.
pub fn run_pw<C: tpm2::commands::Command>(
    sim: &mut Tpm,
    cmd: C,
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut C::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    execute_with_password_sessions(sim, &cmd, 1, &[])
}

/// Sends the raw command `cmd` and returns the complete response bytes.
pub fn run_raw(sim: &mut Tpm, cmd: &[u8]) -> Vec<u8> {
    let mut rsp = [0u8; 16384];
    let rsp = sim.transact(cmd, &mut rsp).expect("transact failed");
    assert!(rsp.len() >= 10, "short response");
    rsp.to_vec()
}

/// Sends a raw command built by [`build_cmd`] and parses the response.
pub fn run_with_trailing<C: Command>(
    sim: &mut Tpm,
    cmd: &C,
    auths: &[TpmsAuthCommand<'_>],
    trailing: &[u8],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let req = build_cmd_with_trailing(cmd, auths, trailing);
    let mut resp_buf = vec![0u8; 8192];
    let resp = sim.transact(&req, &mut resp_buf).unwrap().to_vec();
    let rc = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }
    Ok(unmarshal_response::<C>(&resp).unwrap())
}

/// Sends the raw command `cmd` and returns the full response.
pub fn send(sim: &mut Tpm, cmd: &[u8]) -> Vec<u8> {
    let mut resp = vec![0u8; 8192];
    sim.transact(cmd, &mut resp).unwrap().to_vec()
}

/// Fixes up the size field of the raw command `req`, sends it and parses the response of
/// command `C`, or returns the response code on failure.
pub fn send_and_parse<C: Command>(
    sim: &mut Tpm,
    mut req: Vec<u8>,
) -> Result<C::Response<'static>, u32> {
    let len = req.len() as u32;
    req[2..6].copy_from_slice(&len.to_be_bytes());
    let mut buf = vec![0u8; 16384];
    let resp = sim.transact(&req, &mut buf).unwrap();
    let rc = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }
    Ok(unmarshal_response::<C>(resp).unwrap())
}

/// Sends a raw command at `locality` and returns the response code and the full response.
pub fn send_at(sim: &mut Tpm, locality: u8, cmd: &[u8]) -> (u32, Vec<u8>) {
    let resp = raw_at_checked(sim, locality, cmd);
    let rc = u32::from_be_bytes(resp[6..10].try_into().unwrap());
    (rc, resp)
}

/// Sends raw command bytes and returns the raw response.
pub fn send_raw(sim: &mut Tpm, cmd: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 4096];
    sim.transact(cmd, &mut buf).unwrap().to_vec()
}

/// Sends the raw command `cmd` at `locality` and returns the full response.
pub fn send_raw_at(sim: &mut Tpm, locality: u8, cmd: &[u8]) -> Vec<u8> {
    raw_at_checked(sim, locality, cmd)
}

/// Fills in the size field of the raw command `req`, sends it and returns the response
/// code.
pub fn send_raw_rc(sim: &mut Tpm, mut req: Vec<u8>) -> u32 {
    let len = req.len() as u32;
    req[2..6].copy_from_slice(&len.to_be_bytes());
    let mut rsp = vec![0u8; 4096];
    let rsp = sim.transact(&req, &mut rsp).unwrap();
    u32::from_be_bytes(rsp[6..10].try_into().unwrap())
}

/// Sends a raw command and returns its response code.
pub fn send_rc(sim: &mut Tpm, cmd: &[u8]) -> u32 {
    let mut response = [0u8; 1024];
    let rsp = sim.transact(cmd, &mut response).unwrap();
    u32::from_be_bytes(rsp[6..10].try_into().unwrap())
}

/// Sends a `TPM_ST_NO_SESSIONS` command with a single `UINT16` parameter and returns the
/// response code.
pub fn send_u16_param_command(sim: &mut Tpm, cc: u32, param: u16) -> u32 {
    let mut cmd = Vec::new();
    cmd.extend_from_slice(&0x8001u16.to_be_bytes());
    cmd.extend_from_slice(&12u32.to_be_bytes());
    cmd.extend_from_slice(&cc.to_be_bytes());
    cmd.extend_from_slice(&param.to_be_bytes());
    let mut rsp = [0u8; 64];
    let rsp = sim.transact(&cmd, &mut rsp).unwrap();
    u32::from_be_bytes(rsp[6..10].try_into().unwrap())
}

/// Sends a raw command at locality 0 and returns the response code and the full response.
pub fn send_with_rc(sim: &mut Tpm, cmd: &[u8]) -> (u32, Vec<u8>) {
    send_at(sim, 0, cmd)
}

/// Sends `cmd` with optional password sessions, appending `trailing` bytes after the
/// parameters (the command size covers them), and returns the response code.
pub fn send_with_trailing<CmdT: Command>(
    sim: &mut Tpm,
    cmd: &CmdT,
    num_sessions: usize,
    auth: &[u8],
    trailing: &[u8],
) -> u32
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut buf = vec![0u8; 10];
    buf.extend_from_slice(&handle_area(cmd));
    if num_sessions > 0 {
        let auth_cmd = TpmsAuthCommand {
            session_handle: Handle::RS_PW,
            nonce: Tpm2bNonce::default(),
            session_attributes: TpmaSession(1),
            hmac: Tpm2bAuth::from_bytes(leak_bytes(auth)).unwrap(),
        };
        let mut one = [0u8; TpmsAuthCommand::MAX_SIZE];
        let one_len = marshal_auth_command(&auth_cmd, &mut one);
        let area: Vec<u8> = one[..one_len].repeat(num_sessions);
        buf.extend_from_slice(&(area.len() as u32).to_be_bytes());
        buf.extend_from_slice(&area);
    }
    buf.extend_from_slice(&marshal_to_vec(cmd));
    buf.extend_from_slice(trailing);
    let header = CmdHeader {
        tag: if num_sessions > 0 {
            TpmiStCommandTag::Sessions
        } else {
            TpmiStCommandTag::NoSessions
        },
        size: buf.len() as u32,
        code: CmdT::CMD_CODE,
    };
    let mut header_buf = [0u8; 10];
    header.marshal((&mut header_buf[..]).try_into().unwrap());
    buf[..10].copy_from_slice(&header_buf);
    let mut rsp = [0u8; 4096];
    sim.transact(&buf, &mut rsp).unwrap();
    let mut slice = &rsp[..];
    RespHeader::unmarshal(&mut slice).unwrap().rc
}

/// `TPM_RC_SIZE + TPM_RC_P + TPM_RC_1` (size error on the first parameter).
pub fn size_rc() -> u32 {
    TpmRc::SIZE.with(Position::parameter(1)).get()
}

/// Raw `TPM2_Shutdown`/`TPM2_Startup` with a `UINT16` parameter; returns the response code.
pub fn su_command(sim: &mut Tpm, cc: u32, su: u16) -> u32 {
    let mut cmd = vec![0x80, 0x01, 0, 0, 0, 12];
    cmd.extend_from_slice(&cc.to_be_bytes());
    cmd.extend_from_slice(&su.to_be_bytes());
    send_rc(sim, &cmd)
}

/// Returns a parameter area containing just `data` encoded as a TPM2B.
pub fn tpm2b_params(data: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    put_tpm2b(&mut p, data);
    p
}

/// Sends raw command bytes and returns the raw response.
pub fn transact(sim: &mut Sim, cmd: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 8192];
    sim.transact(cmd, &mut buf).unwrap().to_vec()
}

/// Sends the raw command `cmd` and returns its response code.
pub fn transact_rc_of(sim: &mut Tpm, cmd: &[u8]) -> u32 {
    response_rc(&send(sim, cmd))
}

/// Builds a `TPM_ST_NO_SESSIONS` command with a single `UINT16` parameter.
pub fn u16_param_command(cc: u32, param: u16) -> Vec<u8> {
    let mut cmd = Vec::new();
    cmd.extend_from_slice(&0x8001u16.to_be_bytes());
    cmd.extend_from_slice(&12u32.to_be_bytes());
    cmd.extend_from_slice(&cc.to_be_bytes());
    cmd.extend_from_slice(&param.to_be_bytes());
    cmd
}

/// Decodes a hex string (test fixtures only).
pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ===========================================================================
// Locally defined command structures
//
// Command/handle/response structures that are not (or differently) exposed by `tpm2::commands`, with their wire marshalling.
// ===========================================================================

/// `TPM2_HMAC` command (`handle`; parameters `buffer`, `hashAlg`), marshalled via
/// `Option<TpmiAlgHash>`.
#[derive(Clone, PartialEq, Default, Debug)]
pub struct LocalHmacCmd {
    /// The HMAC/MAC key handle (the command's handle area).
    pub handle: Handle,
    pub in_buffer: Tpm2bMaxBuffer<'static>,
    pub hash_alg: Option<TpmiAlgHash>,
}

impl tpm2::Marshal for LocalHmacCmd {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE + <Option<TpmiAlgHash>>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let mut offset = self
            .in_buffer
            .marshal((&mut dst[0..Tpm2bMaxBuffer::MAX_SIZE]).try_into().unwrap());
        offset += self.hash_alg.marshal(
            (&mut dst[offset..offset + <Option<TpmiAlgHash>>::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset
    }
}

impl Message for LocalHmacCmd {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.handle]
    }
}

impl<'a> UnmarshalMessage<'a> for LocalHmacCmd {
    fn unmarshal_with_handles(
        [handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, tpm2::errors::UnmarshalError> {
        let orig_len = src.len();
        let mut leaked: &'static [u8] = std::vec::Vec::leak(src.to_vec());
        let res = (|| -> Result<Self, tpm2::errors::UnmarshalError> {
            let src = &mut leaked;

            let in_buffer = Tpm2bMaxBuffer::unmarshal(src)?;
            let hash_alg = <Option<TpmiAlgHash>>::unmarshal(src)?;
            Ok(Self {
                handle,
                in_buffer,
                hash_alg,
            })
        })();
        if res.is_ok() {
            let consumed = orig_len - leaked.len();
            *src = &src[consumed..];
        }
        res
    }
}

impl Command for LocalHmacCmd {
    const CMD_CODE: TpmCc = TpmCc::MAC;
    type Response<'a> = LocalMacRsp;
}

/// `TPM2_HMAC` command (`handle`; parameters `buffer`, `hashAlg`); a `None` hash algorithm is
/// marshalled as an explicit `TPM_ALG_NULL`.
#[derive(Clone, PartialEq, Default, Debug)]
pub struct LocalHmacCmdExplicitNullAlg {
    /// The HMAC/MAC key handle (the command's handle area).
    pub handle: Handle,
    pub in_buffer: Tpm2bMaxBuffer<'static>,
    pub hash_alg: Option<TpmiAlgHash>,
}

impl tpm2::Marshal for LocalHmacCmdExplicitNullAlg {
    const MAX_SIZE: usize = Tpm2bMaxBuffer::MAX_SIZE + 2;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let mut offset = self
            .in_buffer
            .marshal((&mut dst[0..Tpm2bMaxBuffer::MAX_SIZE]).try_into().unwrap());
        offset += match self.hash_alg {
            Some(a) => a.marshal((&mut dst[offset..offset + 2]).try_into().unwrap()),
            None => {
                (tpm2::Alg::NULL.id()).marshal((&mut dst[offset..offset + 2]).try_into().unwrap())
            }
        };
        offset
    }
}

impl Message for LocalHmacCmdExplicitNullAlg {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.handle]
    }
}

impl<'a> UnmarshalMessage<'a> for LocalHmacCmdExplicitNullAlg {
    fn unmarshal_with_handles(
        [handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, tpm2::errors::UnmarshalError> {
        let orig_len = src.len();
        let mut leaked: &'static [u8] = std::vec::Vec::leak(src.to_vec());
        let res = (|| -> Result<Self, tpm2::errors::UnmarshalError> {
            let src = &mut leaked;

            let in_buffer = Tpm2bMaxBuffer::unmarshal(src)?;
            let hash_alg = <Option<TpmiAlgHash>>::unmarshal(src)?;
            Ok(Self {
                handle,
                in_buffer,
                hash_alg,
            })
        })();
        if res.is_ok() {
            let consumed = orig_len - leaked.len();
            *src = &src[consumed..];
        }
        res
    }
}

impl Command for LocalHmacCmdExplicitNullAlg {
    const CMD_CODE: TpmCc = TpmCc::MAC;
    type Response<'a> = LocalMacRsp;
}

/// Response parameters of `TPM2_HMAC`/`TPM2_MAC`: the computed `outHMAC`.
#[derive(Clone, PartialEq, Default, Debug)]
pub struct LocalMacRsp {
    pub out_hmac: Tpm2bDigest<'static>,
}

impl tpm2::Marshal for LocalMacRsp {
    const MAX_SIZE: usize = Tpm2bDigest::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.out_hmac.marshal(dst)
    }
}

impl<'a> tpm2::Unmarshal<'a> for LocalMacRsp {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, tpm2::errors::UnmarshalError> {
        let orig_len = src.len();
        let mut leaked: &'static [u8] = std::vec::Vec::leak(src.to_vec());
        let res = (|| -> Result<Self, tpm2::errors::UnmarshalError> {
            let src = &mut leaked;

            let out_hmac = Tpm2bDigest::unmarshal(src)?;
            Ok(Self { out_hmac })
        })();
        if res.is_ok() {
            let consumed = orig_len - leaked.len();
            *src = &src[consumed..];
        }
        res
    }
}

impl Message for LocalMacRsp {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}

impl<'a> UnmarshalMessage<'a> for LocalMacRsp {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, tpm2::errors::UnmarshalError> {
        <Self as tpm2::Unmarshal>::unmarshal(src)
    }
}

/// `TPM2_MAC_Start` command (`handle`, the MAC key; parameters `auth` of the new sequence,
/// `inScheme`).
#[derive(Clone, PartialEq, Default, Debug)]
pub struct LocalMacStartCmd {
    /// The MAC key handle (the command's handle area).
    pub handle: Handle,
    pub auth: Tpm2bAuth<'static>,
    pub hash_alg: Option<TpmiAlgHash>,
}

impl tpm2::Marshal for LocalMacStartCmd {
    const MAX_SIZE: usize = Tpm2bAuth::MAX_SIZE + <Option<TpmiAlgHash>>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let mut offset = self
            .auth
            .marshal((&mut dst[0..Tpm2bAuth::MAX_SIZE]).try_into().unwrap());
        offset += self.hash_alg.marshal(
            (&mut dst[offset..offset + <Option<TpmiAlgHash>>::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset
    }
}

impl Message for LocalMacStartCmd {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.handle]
    }
}

impl<'a> UnmarshalMessage<'a> for LocalMacStartCmd {
    fn unmarshal_with_handles(
        [handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, tpm2::errors::UnmarshalError> {
        let orig_len = src.len();
        let mut leaked: &'static [u8] = std::vec::Vec::leak(src.to_vec());
        let res = (|| -> Result<Self, tpm2::errors::UnmarshalError> {
            let src = &mut leaked;

            let auth = Tpm2bAuth::unmarshal(src)?;
            let hash_alg = <Option<TpmiAlgHash>>::unmarshal(src)?;
            Ok(Self {
                handle,
                auth,
                hash_alg,
            })
        })();
        if res.is_ok() {
            let consumed = orig_len - leaked.len();
            *src = &src[consumed..];
        }
        res
    }
}

impl Command for LocalMacStartCmd {
    const CMD_CODE: TpmCc = TpmCc::MACStart;
    type Response<'a> = LocalMacStartRsp;
}

/// `TPM2_MAC_Start` response: the response handle `sequenceHandle` (the new sequence) and no
/// parameters.
#[derive(Clone, Copy, PartialEq, Default, Debug)]
pub struct LocalMacStartRsp {
    pub sequence_handle: Handle,
}

impl tpm2::Marshal for LocalMacStartRsp {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, _dst: &mut Self::MaxBuffer) -> usize {
        0
    }
}

impl Message for LocalMacStartRsp {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.sequence_handle]
    }
}

impl<'a> UnmarshalMessage<'a> for LocalMacStartRsp {
    fn unmarshal_with_handles(
        [sequence_handle]: Self::Handles,
        _src: &mut &'a [u8],
    ) -> Result<Self, tpm2::errors::UnmarshalError> {
        Ok(Self { sequence_handle })
    }
}

/// `TPM2_RSA_Decrypt` command (`keyHandle`; parameters `cipherText`, `inScheme`, `label`).
#[derive(Clone, PartialEq, Debug, Default)]
pub struct LocalRSADecryptCmd {
    /// The RSA key handle (the command's handle area).
    pub key_handle: Handle,
    pub cipher_text: Tpm2bPublicKeyRsa<'static>,
    pub in_scheme: Option<tpm2::TpmtRsaScheme>,
    pub label: tpm2::Tpm2bLabel<'static>,
}

impl tpm2::Marshal for LocalRSADecryptCmd {
    const MAX_SIZE: usize = Tpm2bPublicKeyRsa::MAX_SIZE
        + <Option<tpm2::TpmtRsaScheme>>::MAX_SIZE
        + tpm2::Tpm2bLabel::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let mut offset = self.cipher_text.marshal(
            (&mut dst[0..Tpm2bPublicKeyRsa::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset += self.in_scheme.marshal(
            (&mut dst[offset..offset + <Option<tpm2::TpmtRsaScheme>>::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset += self.label.marshal(
            (&mut dst[offset..offset + tpm2::Tpm2bLabel::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset
    }
}

impl Message for LocalRSADecryptCmd {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.key_handle]
    }
}

impl<'a> UnmarshalMessage<'a> for LocalRSADecryptCmd {
    fn unmarshal_with_handles(
        [key_handle]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, tpm2::errors::UnmarshalError> {
        let orig_len = src.len();
        let mut leaked: &'static [u8] = std::vec::Vec::leak(src.to_vec());
        let res = (|| -> Result<Self, tpm2::errors::UnmarshalError> {
            let src = &mut leaked;

            let cipher_text = Tpm2bPublicKeyRsa::unmarshal(src)?;
            let in_scheme = <Option<tpm2::TpmtRsaScheme>>::unmarshal(src)?;
            let label = tpm2::Tpm2bLabel::unmarshal(src)?;
            Ok(Self {
                key_handle,
                cipher_text,
                in_scheme,
                label,
            })
        })();
        if res.is_ok() {
            let consumed = orig_len - leaked.len();
            *src = &src[consumed..];
        }
        res
    }
}

impl tpm2::commands::Command for LocalRSADecryptCmd {
    const CMD_CODE: tpm2::TpmCc = tpm2::TpmCc::RSADecrypt;
    type Response<'a> = LocalRSADecryptRsp;
}

/// Response parameters of `TPM2_RSA_Decrypt`: the decrypted `message`.
#[derive(Clone, PartialEq, Default, Debug)]
pub struct LocalRSADecryptRsp {
    pub message: Tpm2bPublicKeyRsa<'static>,
}

impl tpm2::Marshal for LocalRSADecryptRsp {
    const MAX_SIZE: usize = Tpm2bPublicKeyRsa::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.message.marshal(dst)
    }
}

impl<'a> tpm2::Unmarshal<'a> for LocalRSADecryptRsp {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, tpm2::errors::UnmarshalError> {
        let orig_len = src.len();
        let mut leaked: &'static [u8] = std::vec::Vec::leak(src.to_vec());
        let res = (|| -> Result<Self, tpm2::errors::UnmarshalError> {
            let src = &mut leaked;

            let message = Tpm2bPublicKeyRsa::unmarshal(src)?;
            Ok(Self { message })
        })();
        if res.is_ok() {
            let consumed = orig_len - leaked.len();
            *src = &src[consumed..];
        }
        res
    }
}

impl Message for LocalRSADecryptRsp {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}

impl<'a> UnmarshalMessage<'a> for LocalRSADecryptRsp {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, tpm2::errors::UnmarshalError> {
        <Self as tpm2::Unmarshal>::unmarshal(src)
    }
}

/// A TPM2B_NAME whose declared `size` and `buffer` may exceed the `TPMU_NAME` maximum, to send
/// malformed names.
#[derive(Clone, PartialEq, Debug)]
pub struct OversizedTpm2bName {
    pub size: u16,
    pub buffer: Vec<u8>,
}

impl tpm2::Marshal for OversizedTpm2bName {
    const MAX_SIZE: usize = 2048;
    type MaxBuffer = [u8; 2048];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let written = self.size.marshal((&mut dst[0..2]).try_into().unwrap());
        dst[written..written + self.buffer.len()].copy_from_slice(&self.buffer);
        written + self.buffer.len()
    }
}

impl<'a> tpm2::Unmarshal<'a> for OversizedTpm2bName {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, tpm2::errors::UnmarshalError> {
        let size = u16::unmarshal(src)?;
        if src.len() < size as usize {
            return Err(tpm2::errors::UnmarshalError::INSUFFICIENT);
        }
        let (sized_buffer, rest) = src.split_at(size as usize);
        *src = rest;
        Ok(OversizedTpm2bName {
            size,
            buffer: sized_buffer.to_vec(),
        })
    }
}

/// `TPM2_PolicyDuplicationSelect` parameters with an [`OversizedTpm2bName`] `objectName`, used to
/// check that oversized names are rejected.
#[derive(Clone, PartialEq, Debug)]
pub struct TestPolicyDuplicationSelectOversizedCmd {
    /// The policy session (the command's handle area).
    pub policy_session: Handle,
    pub object_name: OversizedTpm2bName,
    pub new_parent_name: Tpm2bName<'static>,
    pub include_object: bool,
}

impl tpm2::Marshal for TestPolicyDuplicationSelectOversizedCmd {
    const MAX_SIZE: usize = 2048 + Tpm2bName::MAX_SIZE + bool::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let mut offset = self
            .object_name
            .marshal((&mut dst[0..2048]).try_into().unwrap());
        offset += self.new_parent_name.marshal(
            (&mut dst[offset..offset + Tpm2bName::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset += self.include_object.marshal(
            (&mut dst[offset..offset + bool::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset
    }
}

impl Message for TestPolicyDuplicationSelectOversizedCmd {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.policy_session]
    }
}

impl<'a> UnmarshalMessage<'a> for TestPolicyDuplicationSelectOversizedCmd {
    fn unmarshal_with_handles(
        [policy_session]: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, tpm2::errors::UnmarshalError> {
        let orig_len = src.len();
        let mut leaked: &'static [u8] = crate::test_utils::leak_bytes(src);
        let object_name = OversizedTpm2bName::unmarshal(&mut leaked)?;
        let new_parent_name = Tpm2bName::unmarshal(&mut leaked)?;
        let include_object = bool::unmarshal(&mut leaked)?;
        let consumed = orig_len - leaked.len();
        *src = &src[consumed..];
        Ok(Self {
            policy_session,
            object_name,
            new_parent_name,
            include_object,
        })
    }
}

impl tpm2::commands::Command for TestPolicyDuplicationSelectOversizedCmd {
    const CMD_CODE: TpmCc = TpmCc::PolicyDuplicationSelect;
    type Response<'a> = ();
}

// ===========================================================================
// Authorization sessions
//
// Password/HMAC session construction, session start helpers and session-based command execution.
// ===========================================================================

/// One entry of a command authorization area (`TPMS_AUTH_COMMAND`).
pub struct AuthEntry {
    pub handle: u32,
    pub nonce: Vec<u8>,
    pub attrs: u8,
    pub hmac: Vec<u8>,
}

impl AuthEntry {
    /// A password (`TPM_RS_PW`) session carrying `password`.
    pub fn pw(password: &[u8]) -> Self {
        Self {
            handle: RS_PW,
            nonce: Vec::new(),
            attrs: ATTR_CONTINUE,
            hmac: password.to_vec(),
        }
    }
}

/// Client-side state of an (unbound, unsalted, SHA-256) session.
#[derive(Clone, Debug)]
pub struct Sess {
    pub handle: u32,
    pub nonce_tpm: Vec<u8>,
    pub session_key: Vec<u8>,
}

/// One entry of the authorization area.
pub struct SessUse<'a> {
    pub sess: Option<&'a mut Sess>,
    pub attrs: u8,
    /// Bytes appended to the session key to form the HMAC key (the entity authValue, if the
    /// session includes it).
    pub key_auth: Vec<u8>,
    /// Plaintext sent in the `hmac` field (password sessions and `PolicyPassword` sessions).
    pub password: Option<Vec<u8>>,
    pub nonce: Vec<u8>,
    pub bad_hmac: bool,
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

/// Returns the response code of an audited command that requires `sess` to be exclusive.
pub fn audit_exclusive_rc(sim: &mut Sim, sess: &mut Sess) -> u32 {
    audited_get_cap(sim, sess, ATTR_CONT | ATTR_AUDIT | ATTR_AUDIT_EXCLUSIVE).rc
}

/// Runs `TPM2_GetCapability` audited by `sess` with `attrs`.
pub fn audited_get_cap(sim: &mut Sim, sess: &mut Sess, attrs: u8) -> Resp {
    exec(
        sim,
        CC_GET_CAPABILITY,
        &[],
        &mut [SessUse::hmac(sess, attrs, &[])],
        &GET_CAP_PARAMS,
        0,
    )
}

/// Executes `TPM2_GetCapability(TPM_PROPERTIES, FAMILY_INDICATOR, 1)` with `session` as an
/// audit session using `attrs`; updates the session's nonceTPM and returns the response
/// parameters and the response session attributes.
pub fn audited_get_capability(
    sim: &mut Tpm,
    session: &mut ActiveSession,
    attrs: u8,
) -> (Vec<u8>, u8) {
    let params = marshal_to_vec(&GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    });
    let cp = cp_hash(TpmCc::GetCapability, &[], &params);
    let auth = hmac_auth(session, &cp, attrs, &[]);
    let (resp_params, resp_auths) =
        send_with_sessions(sim, TpmCc::GetCapability, &[], &[auth], &params)
            .expect("GetCapability failed");
    assert_eq!(resp_auths.len(), 1);
    session.nonce_tpm =
        Tpm2bNonce::from_bytes(leak_bytes(resp_auths[0].nonce.get_buffer())).unwrap();
    (resp_params, resp_auths[0].session_attributes.0)
}

/// Marshals the authorization area (size followed by the sessions) for `auths`.
pub fn auth_area(auths: &[TpmsAuthCommand]) -> Vec<u8> {
    let mut area = Vec::new();
    for auth in auths {
        area.extend_from_slice(&marshal_to_vec(auth));
    }
    let mut out = (area.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&area);
    out
}

/// Builds a command with handle `auth_handle` (authorized by an empty password session when
/// `tag` is `TPM_ST_SESSIONS`) and parameter area `params`.
pub fn auth_command(cc: tpm2::TpmCc, auth_handle: u32, tag: u16, params: &[u8]) -> Vec<u8> {
    let mut req = tag.to_be_bytes().to_vec();
    req.extend_from_slice(&0u32.to_be_bytes()); // placeholder size
    req.extend_from_slice(&cc.code().to_be_bytes());
    req.extend_from_slice(&auth_handle.to_be_bytes());
    if tag == 0x8002 {
        let auth = TpmsAuthCommand {
            session_handle: tpm2::Handle::RS_PW,
            nonce: tpm2::Tpm2bNonce::default(),
            session_attributes: tpm2::TpmaSession(1),
            hmac: tpm2::Tpm2bAuth::default(),
        };
        let mut auth_buf = [0u8; TpmsAuthCommand::MAX_SIZE];
        let auth_len = auth.marshal(&mut auth_buf);
        req.extend_from_slice(&(auth_len as u32).to_be_bytes());
        req.extend_from_slice(&auth_buf[..auth_len]);
    }
    req.extend_from_slice(params);
    let size = req.len() as u32;
    req[2..6].copy_from_slice(&size.to_be_bytes());
    req
}

/// Builds a `TPM2_NV_ChangeAuth` command for `nv_index` setting `new_auth`.
pub fn change_auth_cmd(nv_index: Handle, new_auth: &[u8]) -> NVChangeAuth<'static> {
    NVChangeAuth {
        nv_index,
        new_auth: Tpm2bAuth::from_bytes(leak_bytes(new_auth)).unwrap(),
    }
}

/// Builds a raw `TPM2_HierarchyChangeAuth(auth_handle, new_auth)` command.
///
/// With `sessions == None` the command is sent with `TPM_ST_NO_SESSIONS`; otherwise every entry
/// becomes a password session (`TPM_RS_PW`) whose hmac is that entry.
pub fn change_auth_command(
    auth_handle: Handle,
    sessions: Option<&[&[u8]]>,
    new_auth: &[u8],
) -> Vec<u8> {
    let mut cmd = Vec::new();
    let tag: u16 = if sessions.is_some() { 0x8002 } else { 0x8001 };
    cmd.extend_from_slice(&tag.to_be_bytes());
    cmd.extend_from_slice(&0u32.to_be_bytes()); // size placeholder
    cmd.extend_from_slice(&0x129u32.to_be_bytes()); // TPM_CC_HierarchyChangeAuth
    cmd.extend_from_slice(&auth_handle.0.to_be_bytes());
    if let Some(sessions) = sessions {
        let mut auth_area = Vec::new();
        for hmac in sessions {
            auth_area.extend_from_slice(&marshal_to_vec(&TpmsAuthCommand {
                session_handle: Handle::RS_PW,
                nonce: Tpm2bNonce::default(),
                session_attributes: TpmaSession(1),
                hmac: Tpm2bAuth::from_bytes(hmac).unwrap(),
            }));
        }
        cmd.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
        cmd.extend_from_slice(&auth_area);
    }
    cmd.extend_from_slice(&marshal_to_vec(&HierarchyChangeAuth {
        auth_handle,
        new_auth: Tpm2bAuth::from_bytes(new_auth).unwrap(),
    }));
    let len = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&len.to_be_bytes());
    cmd
}

/// Creates an ECDSA P-256 signing primary key under the owner hierarchy with authValue `auth` and
/// returns its handle; panics on failure.
pub fn create_ecc_key_with_auth(sim: &mut Tpm, auth: &[u8]) -> Handle {
    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            ecc_parms,
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(auth).unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_ENDORSEMENT,
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let rsp =
        execute_with_password_sessions(sim, &create_cmd, 1, &[]).expect("could not generate key");
    rsp.object_handle
}

/// Creates an ECDSA P-256 signing primary key under the owner hierarchy with authValue `auth` and
/// returns its handle; panics on failure.
pub fn create_primary_key_with_auth(sim: &mut Tpm, auth: &[u8]) -> Handle {
    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            ecc_parms,
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(auth).unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_rsp = execute_with_password_sessions(sim, &create_cmd, 1, &[]).unwrap();
    create_rsp.object_handle
}

/// Creates a primary key with authValue `auth` under the owner hierarchy and returns its handle.
pub fn create_primary_with_auth(sim: &mut Tpm, public: TpmtPublic<'static>, auth: &[u8]) -> Handle {
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(leak_bytes(auth)).unwrap(),
            data: Default::default(),
        }),
        in_public: tpm2::Tpm2b(public),
        ..Default::default()
    };
    let rsp = execute_with_password_sessions(sim, &cmd, 1, &[])
        .unwrap_or_else(|rc| panic!("TPM2_CreatePrimary failed: {rc:#x}"));
    rsp.object_handle
}

/// Creates a primary object under the owner hierarchy from `public`,
/// `user_auth` and sensitive `data`; returns its handle and name.
pub fn create_primary_with_auth_and_data(
    sim: &mut Tpm,
    public: TpmtPublic<'static>,
    user_auth: &'static [u8],
    data: &'static [u8],
) -> (Handle, Tpm2bName<'static>) {
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(user_auth).unwrap(),
            data: Tpm2bSensitiveData::from_bytes(data).unwrap(),
        }),
        in_public: Tpm2b(public),
        ..Default::default()
    };
    let rsp =
        execute_tpm_command_mapping_parse_errors(sim, &cmd, &[pw()]).expect("CreatePrimary failed");
    (rsp.object_handle, rsp.name)
}

/// Creates a primary object from `public` in `hierarchy` (empty hierarchy auth) and returns its
/// handle.
pub fn create_primary_with_auth_in(
    sim: &mut Tpm,
    hierarchy: Handle,
    public: TpmtPublic<'static>,
    user_auth: &'static [u8],
) -> Handle {
    let cmd = CreatePrimary {
        primary_handle: hierarchy,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(user_auth).unwrap(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(public),
        ..Default::default()
    };
    let rsp = execute_with_password_sessions(sim, &cmd, 1, &[]).expect("CreatePrimary failed");
    rsp.object_handle
}

/// Creates an ECC primary key under `hierarchy` and returns its handle and Name.
pub fn create_storage_primary_with_auth(
    sim: &mut Tpm,
    hierarchy: Handle,
    auth: &[u8],
) -> (Handle, Vec<u8>) {
    let cmd = CreatePrimary {
        primary_handle: hierarchy,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(ecc_primary_template()),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let rsp = execute_with_password_sessions(sim, &cmd, 1, auth)
        .unwrap_or_else(|rc| panic!("CreatePrimary({hierarchy:?}) failed: {rc:#x}"));
    (rsp.object_handle, rsp.name.get_buffer().to_vec())
}

// auth-role-dup-admin-and-policy-commandcode-bypass (NV_ChangeAuth part) and
/// Defines an index whose authPolicy is `TPM2_PolicyCommandCode(TPM_CC_NV_ChangeAuth)`.
pub fn define_change_auth_index(sim: &mut Tpm, index: u32, size: u16) {
    define_nv_with_policy_unwrap(
        sim,
        index,
        OWNER_RW | TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE,
        size,
        &command_code_policy(TpmCc::NVChangeAuth),
    );
}

/// An empty password authorization (`TPM_RS_PW`, `continueSession`).
pub fn empty_password_auth() -> TpmsAuthCommand<'static> {
    TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bAuth::default(),
    }
}

/// Runs `cmd` with `n` empty password sessions and returns the response code.
pub fn exec_with_empty_passwords<C: Command>(sim: &mut Tpm, cmd: &C, n: usize) -> Result<(), u32>
where
    for<'b> &'b mut C::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    execute_with_password_sessions_status(sim, cmd, n, &[]).map(|_| ())
}

/// Like [`execute_tpm_command_full`], returning only the response parameters.
pub fn execute_tpm_command_with_auths<C: Command>(
    sim: &mut Tpm,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    execute_tpm_command_full(sim, cmd, auths)
}

/// Extends a session audit digest with an audited, successful `TPM2_GetCapability` with the
/// parameters of [`get_cap_params`] that returned `resp_params`.
pub fn extend_audit(digest: &[u8], resp_params: &[u8]) -> Vec<u8> {
    let cc = CC_GET_CAPABILITY.to_be_bytes();
    let cp_hash = sha256(&[&cc, &get_cap_params()]);
    let rp_hash = sha256(&[&0u32.to_be_bytes(), &cc, resp_params]);
    sha256(&[digest, &cp_hash, &rp_hash])
}

/// Produces `count` DA authorization failures against `object`.
pub fn fail_auth(sim: &mut Tpm, object: Handle, count: u32) {
    for _ in 0..count {
        assert_eq!(
            unseal(sim, object, b"wrong"),
            0x0000098E, // TPM_RC_AUTH_FAIL (session 1)
        );
    }
}

/// Flushes `handle` with `TPM2_FlushContext`, ignoring any error.
pub fn flush_session(sim: &mut Tpm, handle: Handle) {
    let _ = execute_with_password_sessions(
        sim,
        &FlushContext {
            flush_handle: handle,
        },
        0,
        &[],
    );
}

/// `TPM2_FlushContext(handle)`; returns the response size and code.
pub fn flush_session_raw(sim: &mut Tpm, handle: u32) -> (usize, u32) {
    let mut req = hex("8001 0000000e 00000165 00000000");
    req[10..14].copy_from_slice(&handle.to_be_bytes());
    let resp = send(sim, &req);
    (resp.len(), rc_of(&resp))
}

/// Flushes every loaded authorization session except those in `keep` (the TPM only holds a
/// few sessions at a time).
pub fn flush_sessions_except(sim: &mut Tpm, keep: &[Handle]) {
    for slot in 0..tpm2::TPM2_MAX_ACTIVE_SESSIONS {
        for prefix in [0x0200_0000, 0x0300_0000] {
            let handle = Handle(prefix | slot);
            if !keep.contains(&handle) {
                let _ = flush_context(sim, handle);
            }
        }
    }
}

/// Changes the authValue of `hierarchy` from `current` to `new_auth` (`TPM2_HierarchyChangeAuth`
/// with a password session), returning the response code on failure.
pub fn hierarchy_change_auth(
    sim: &mut Tpm,
    hierarchy: Handle,
    current: &[u8],
    new_auth: &[u8],
) -> Result<(), u32> {
    execute_with_password_sessions(
        sim,
        &HierarchyChangeAuth {
            auth_handle: hierarchy,
            new_auth: Tpm2bAuth::from_bytes(new_auth).unwrap(),
        },
        1,
        current,
    )
    .map(|_| ())
}

/// Returns the handles of all loaded sessions (`TPM2_GetCapability(TPM_CAP_HANDLES,
/// TPM_HT_LOADED_SESSION)`).
pub fn loaded_sessions(sim: &mut Tpm) -> Vec<u32> {
    let rsp = sim
        .execute(GetCapability {
            capability: TpmCap::Handles,
            property: 0x0200_0000,
            property_count: 64,
        })
        .expect("GetCapability(TPM_CAP_HANDLES) failed");
    let TpmsCapabilityData::Handles(handles) = rsp.capability_data else {
        panic!("unexpected capability data");
    };
    handles.as_ref().iter().map(|h| h.0).collect()
}

/// A `TPM_RS_PW` password session (continueSession set) carrying `hmac` as the password.
pub fn make_auth_session(hmac: &[u8]) -> TpmsAuthCommand<'_> {
    TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(hmac).unwrap(),
    }
}

/// Builds a `TPM_ST_NO_SESSIONS` command without handles whose parameter area is `params`.
pub fn no_session_command<M: tpm2::Marshal>(cc: TpmCc, params: &M) -> Vec<u8>
where
    for<'a> &'a mut M::MaxBuffer: TryFrom<&'a mut [u8]>,
{
    let mut request = Vec::new();
    request.extend_from_slice(&0x8001u16.to_be_bytes());
    request.extend_from_slice(&0u32.to_be_bytes()); // Placeholder for size
    request.extend_from_slice(&cc.code().to_be_bytes());
    request.extend_from_slice(&marshal_to_vec(params));
    let total_size = request.len() as u32;
    request[2..6].copy_from_slice(&total_size.to_be_bytes());
    request
}

/// A `TPM_RS_PW` session (continueSession set) carrying the password `auth`.
pub fn password_auth(auth: &[u8]) -> TpmsAuthCommand<'_> {
    TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(auth).unwrap(),
    }
}

/// An empty-password `TPM_RS_PW` session. In C every handle with an authorization role
/// needs a session even if its authValue is empty; with no session C returns
/// TPM_RC_AUTH_MISSING (SessionProcess.c CheckAuthNoSession).
pub fn pw() -> TpmsAuthCommand<'static> {
    TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(0),
        hmac: Tpm2bAuth::default(),
    }
}

/// An empty-password `TPM_RS_PW` session.
pub fn pw_continue() -> TpmsAuthCommand<'static> {
    TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    }
}

/// An empty-password authorization session (`TPM_RS_PW`).
pub fn pw_session() -> TpmsAuthCommand<'static> {
    TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Default::default(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Default::default(),
    }
}

/// A `TPM_RS_PW` session (continueSession) carrying `auth`.
pub fn pw_with(auth: &'static [u8]) -> TpmsAuthCommand<'static> {
    TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(auth).unwrap(),
    }
}

/// `TPM2_NV_Read` of a PIN index authorized by the index itself with `password`.
pub fn read_pin_with_password(sim: &mut Tpm, index: u32, password: &[u8]) -> u32 {
    send_rc_with_auth_entries(
        sim,
        TpmCc::NVRead,
        &[index, index],
        &[AuthEntry::pw(password)],
        &nv_read_params(8, 0),
    )
}

/// Sends a parameter-only (no handles, no sessions) command `cmd` and returns the response
/// header and the parameter area.
pub fn send_no_sessions<C: Command>(sim: &mut Tpm, cmd: &C) -> (ResponseHeader, Vec<u8>)
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let body = marshal_to_vec(cmd);
    // TPM_ST_NO_SESSIONS command header.
    let mut req = Vec::new();
    req.extend_from_slice(&0x8001u16.to_be_bytes());
    req.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    req.extend_from_slice(&C::CMD_CODE.code().to_be_bytes());
    req.extend_from_slice(&body);
    let resp = send(sim, &req);
    let mut slice = &resp[..];
    let rsp_hdr = ResponseHeader::unmarshal(&mut slice).unwrap();
    (rsp_hdr, slice.to_vec())
}

/// Sends a command and returns only its response code.
pub fn send_rc_with_auth_entries(
    sim: &mut Tpm,
    cc: TpmCc,
    handles: &[u32],
    auths: &[AuthEntry],
    params: &[u8],
) -> u32 {
    send_with_auth_entries(sim, cc, handles, auths, params).0
}

/// Sends a command and returns its response code and full response bytes.
///
/// Without `auths` the command is sent with `TPM_ST_NO_SESSIONS`.
pub fn send_with_auth_entries(
    sim: &mut Tpm,
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

/// Sends a `TPM_ST_SESSIONS` command without response handles; returns the response
/// parameters and the response authorizations, or the response code on failure.
pub fn send_with_sessions(
    sim: &mut Tpm,
    cc: TpmCc,
    handles: &[Handle],
    auths: &[TpmsAuthCommand<'_>],
    params: &[u8],
) -> Result<(Vec<u8>, Vec<TpmsAuthResponse<'static>>), u32> {
    let mut req = Vec::new();
    req.extend_from_slice(&0x8002u16.to_be_bytes());
    req.extend_from_slice(&[0u8; 4]);
    req.extend_from_slice(&cc.code().to_be_bytes());
    for h in handles {
        req.extend_from_slice(&h.0.to_be_bytes());
    }
    let area: Vec<u8> = auths.iter().flat_map(marshal_to_vec).collect();
    req.extend_from_slice(&(area.len() as u32).to_be_bytes());
    req.extend_from_slice(&area);
    req.extend_from_slice(params);
    let len = req.len() as u32;
    req[2..6].copy_from_slice(&len.to_be_bytes());

    let mut buf = vec![0u8; 8192];
    let rsp = sim.transact(&req, &mut buf).unwrap().to_vec();
    let rc = u32::from_be_bytes(rsp[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }
    let param_size = u32::from_be_bytes(rsp[10..14].try_into().unwrap()) as usize;
    let resp_params = rsp[14..14 + param_size].to_vec();
    let mut rest: &'static [u8] = leak_bytes(&rsp[14 + param_size..]);
    let mut resp_auths = Vec::new();
    while !rest.is_empty() {
        resp_auths.push(TpmsAuthResponse::unmarshal(&mut rest).unwrap());
    }
    Ok((resp_params, resp_auths))
}

/// Reads the audit information of `session` with `TPM2_GetSessionAuditDigest` (unsigned).
pub fn session_audit_info(sim: &mut Sim, session: u32) -> (bool, Vec<u8>) {
    let resp = sim
        .execute(GetSessionAuditDigest {
            privacy_admin_handle: Handle::RH_ENDORSEMENT,
            sign_handle: Handle::RH_NULL,
            session_handle: Handle(session),
            qualifying_data: Default::default(),
            in_scheme: None,
        })
        .expect("TPM2_GetSessionAuditDigest failed");
    match resp.audit_info.0.attested {
        TpmuAttest::SessionAudit(info) => (
            info.exclusive_session,
            info.session_digest.get_buffer().to_vec(),
        ),
        other => panic!("Expected SessionAudit, got {other:?}"),
    }
}

/// Returns the loaded / saved session handles reported by `TPM_CAP_HANDLES`.
pub fn session_handles(sim: &mut Tpm, saved: bool) -> Vec<u32> {
    let property = if saved { 0x0300_0000 } else { 0x0200_0000 };
    let (_, data) = get_cap(sim, 1, property, 64).unwrap();
    let n = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
    (0..n)
        .map(|i| u32::from_be_bytes(data[4 + 4 * i..8 + 4 * i].try_into().unwrap()))
        .collect()
}

/// Returns whether the session `handle` is loaded.
pub fn session_loaded(sim: &mut Tpm, handle: u32) -> bool {
    loaded_sessions(sim).contains(&handle)
}

/// Returns the parameter area of a successful response to a command sent with
/// `TPM_ST_SESSIONS` (skipping `resp_handles` response handles and `parameterSize`).
pub fn session_rsp_params(resp: &[u8], resp_handles: usize) -> &[u8] {
    let start = 10 + 4 * resp_handles;
    let size = u32::from_be_bytes(resp[start..start + 4].try_into().unwrap()) as usize;
    &resp[start + 4..start + 4 + size]
}

/// Sets the authValue of `hierarchy` (currently empty) to `auth`.
pub fn set_hierarchy_auth(sim: &mut Tpm, hierarchy: Handle, auth: &[u8]) {
    let cmd = change_auth_command(hierarchy, Some(&[&[]]), auth);
    assert_eq!(send_rc(sim, &cmd), 0);
}

/// Sets the owner authValue (from an empty one).
pub fn set_owner_auth(sim: &mut Tpm, auth: &[u8]) {
    let code = send_rc_with_auth_entries(
        sim,
        TpmCc::HierarchyChangeAuth,
        &[Handle::RH_OWNER.0],
        &[AuthEntry::pw(&[])],
        &tpm2b_params(auth),
    );
    assert_eq!(code, RC_SUCCESS, "HierarchyChangeAuth");
}

/// Builds a salted `TPM2_StartAuthSession` request (tpmKey = `tpm_key`, bind = platform) with
/// `symmetric = TPMT_SYM_DEF(AES, 0, NULL)` and the given encrypted salt.
pub fn start_auth_session_request(tpm_key: Handle, salt: &[u8]) -> Vec<u8> {
    let mut req = Vec::new();
    req.extend_from_slice(&0x8001u16.to_be_bytes()); // NO_SESSIONS
    req.extend_from_slice(&0u32.to_be_bytes()); // size placeholder
    req.extend_from_slice(&0x00000176u32.to_be_bytes()); // TPM_CC_StartAuthSession
    req.extend_from_slice(&tpm_key.0.to_be_bytes()); // tpmKey
    req.extend_from_slice(&0x4000000cu32.to_be_bytes()); // bind: TPM_RH_PLATFORM
    req.extend_from_slice(&16u16.to_be_bytes()); // nonceCaller size: 16
    req.extend_from_slice(&[1u8; 16]);
    req.extend_from_slice(&(salt.len() as u16).to_be_bytes()); // encryptedSalt size
    req.extend_from_slice(salt);
    req.push(0x00); // sessionType: TPM_SE_HMAC
    // symmetric: TPM_ALG_AES (0x0006), keyBits=0 (0x0000), mode=TPM_ALG_NULL (0x0010)
    req.extend_from_slice(&0x0006u16.to_be_bytes());
    req.extend_from_slice(&0x0000u16.to_be_bytes());
    req.extend_from_slice(&0x0010u16.to_be_bytes());
    req.extend_from_slice(&0x0004u16.to_be_bytes()); // authHash: TPM_ALG_SHA1 (0x0004)
    finish(req)
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

/// Starts an unbound, unsalted SHA-256 session of type `session_type`.
pub fn start_session_active(sim: &mut Tpm, session_type: TpmSe) -> ActiveSession {
    let mut session = start_auth_session(
        sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        session_type,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("StartAuthSession failed");
    session.attributes = TpmaSession::CONTINUE_SESSION;
    session
}

/// Starts an unbound, unsalted SHA-256 session of `session_type` and returns its handle.
pub fn start_session_handle(sim: &mut Tpm, session_type: TpmSe) -> Handle {
    let mut nonce = [0u8; 16];
    crate::_common::client_random(&mut nonce).unwrap();
    let rsp = sim
        .execute(StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::from_bytes(&nonce).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        })
        .expect("StartAuthSession failed");
    rsp.session_handle
}

/// Starts an unbound, unsalted SHA-256 session (empty session key).
pub fn start_session_of_type(sim: &mut Tpm, session_type: TpmSe) -> ActiveSession {
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

/// Starts an unbound, unsalted session of `session_type` (`0x00` HMAC, `0x01` policy) with
/// SHA-256 and returns its handle.
pub fn start_session_raw(sim: &mut Tpm, session_type: u8) -> u32 {
    let mut params = Vec::new();
    params.extend_from_slice(&32u16.to_be_bytes());
    params.extend_from_slice(&[0x11; 32]); // nonceCaller
    params.extend_from_slice(&0u16.to_be_bytes()); // encryptedSalt
    params.push(session_type);
    params.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric = TPM_ALG_NULL
    params.extend_from_slice(&0x000Bu16.to_be_bytes()); // authHash = SHA256
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        0x176,
        &[Handle::RH_NULL.0, Handle::RH_NULL.0],
        None,
        &params,
    );
    let (rc, resp) = send_with_rc(sim, &cmd);
    assert_eq!(rc, 0, "StartAuthSession failed: {rc:#x}");
    u32::from_be_bytes(resp[10..14].try_into().unwrap())
}

/// Starts an unbound, unsalted session of `session_type` (`TPM_SE`) with no symmetric
/// algorithm and SHA-256 as authHash; returns the session handle.
pub fn start_session_raw_attrs(sim: &mut Tpm, session_type: u8) -> u32 {
    let mut req = hex(concat!(
        "8001 0000002b 00000176",
        "40000007 40000007",
        "00100102030405060708090a0b0c0d0e0f10",
        "0000",
        "00",
        "0010",
        "000b",
    ));
    // sessionType
    req[38] = session_type;
    let resp = send(sim, &req);
    assert_eq!(rc_of(&resp), 0, "StartAuthSession failed");
    u32::from_be_bytes(resp[10..14].try_into().unwrap())
}

/// Starts an unbound, unsalted SHA-256 session of `session_type`.
pub fn start_session_u32(sim: &mut Tpm, session_type: TpmSe) -> u32 {
    start_auth_session(
        sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        session_type,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("StartAuthSession failed")
    .session_handle
    .0
}

/// Starts an unbound, unsalted session of `session_type` with a fixed caller nonce.
pub fn start_session_with_nonce(
    sim: &mut Tpm,
    session_type: TpmSe,
    auth_hash: TpmiAlgHash,
    nonce_caller: &'static [u8],
) -> Handle {
    let rsp = execute_with_password_sessions(
        sim,
        &StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::from_bytes(nonce_caller).unwrap(),
            encrypted_salt: tpm2::Tpm2bEncryptedSecret::default(),
            session_type,
            symmetric: None,
            auth_hash,
        },
        0,
        &[],
    )
    .expect("StartAuthSession failed");
    rsp.session_handle
}

/// Starts an unbound, unsalted SHA-256 trial session and returns its handle.
pub fn start_trial_session(sim: &mut Tpm) -> Handle {
    let start_cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[1; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let policy_session_resp = execute_tpm_command_uncorrupted(sim, &start_cmd, &[]).unwrap();
    policy_session_resp.session_handle
}

/// `TPM2_Unseal(item)` authorized by `auth`.
pub fn unseal_with_auth_entry(sim: &mut Tpm, item: u32, auth: AuthEntry) -> u32 {
    send_rc_with_auth_entries(sim, TpmCc::Unseal, &[item], &[auth], &[])
}

/// Runs `cmd` authorized by the single `session` for an entity named `names` with an empty
/// authValue.
pub fn with_session<C: Command>(
    sim: &mut Tpm,
    cmd: &C,
    names: &[&[u8]],
    session: &mut ActiveSession,
) -> Result<(), u32>
where
    for<'b> &'b mut C::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    execute_with_hmac_sessions_status(sim, cmd, names, core::slice::from_mut(session), &[&[]])
        .map(|_| ())
}

// ===========================================================================
// Policy sessions
//
// Policy command wrappers and policy digest helpers.
// ===========================================================================

/// The SHA-256 policy digest after `TPM2_PolicyCommandCode(cc)` on a fresh session.
pub fn command_code_policy(cc: TpmCc) -> Vec<u8> {
    sha256(&[
        &EMPTY_POLICY,
        &TpmCc::PolicyCommandCode.code().to_be_bytes(),
        &cc.code().to_be_bytes(),
    ])
}

/// A POLICYREAD-only index (no AUTHREAD) whose authHandle is the index itself, authorized by a
/// policy session, stores a SHA-256 TPMT_HA of the zero policy digest.
pub fn define_policy_read_authorize_index(sim: &mut Tpm, index: u32) {
    define_nv_with_policy(
        sim,
        index,
        TpmaNv::OWNERWRITE | TpmaNv::POLICYREAD,
        34,
        &[0; 32],
    );
    let mut tpmt_ha = vec![0x00, 0x0B];
    tpmt_ha.extend_from_slice(&[0; 32]);
    write_nv_owner(sim, index, &tpmt_ha);
}

/// `TPM2_PolicyCommandCode(TPM_CC_Duplicate)` policy digest with `alg`, used as the authPolicy
/// of duplicable test objects: the DUP role of `TPM2_Duplicate` always requires a policy
/// session in the C reference (`IsPolicySessionRequired`).
pub fn dup_policy(alg: TpmiAlgHash) -> &'static [u8] {
    let zeros = vec![0u8; digest_parts(alg, &[]).len()];
    leak_bytes(&digest_parts(
        alg,
        &[
            &zeros,
            &TpmCc::PolicyCommandCode.code().to_be_bytes(),
            &TpmCc::Duplicate.code().to_be_bytes(),
        ],
    ))
}

/// Digest of a policy consisting only of `TPM2_PolicyCommandCode(Duplicate)` (SHA-256).
pub fn dup_policy_digest() -> Tpm2bDigest<'static> {
    dup_policy_digest_for(TpmiAlgHash::Sha256)
}

/// Digest of a policy consisting only of `TPM2_PolicyCommandCode(Duplicate)` with `alg`.
pub fn dup_policy_digest_for(alg: TpmiAlgHash) -> Tpm2bDigest<'static> {
    let mut data = vec![0u8; alg.digest_size()];
    data.extend_from_slice(&u32::from(TpmCc::PolicyCommandCode).to_be_bytes());
    data.extend_from_slice(&u32::from(TpmCc::Duplicate).to_be_bytes());
    let digest = hash_parts(alg, &[&data]);
    Tpm2bDigest::from_bytes(leak_bytes(&digest)).unwrap()
}

/// Starts a policy session with `auth_hash` and satisfies
/// `PolicyCommandCode(TPM_CC_Duplicate)` on it; returns its handle.
pub fn dup_policy_session(sim: &mut Tpm, auth_hash: TpmiAlgHash) -> Handle {
    let h = exec_command(
        sim,
        &StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::from_bytes(random_bytes(16)).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::Policy,
            symmetric: None,
            auth_hash,
        },
        &[],
    )
    .expect("StartAuthSession failed");
    exec_command(
        sim,
        &PolicyCommandCode {
            policy_session: h.session_handle,
            code: TpmCc::Duplicate,
        },
        &[],
    )
    .expect("PolicyCommandCode failed");
    h.session_handle
}

/// Starts an `alg` policy session that satisfies `dup_policy_digest_for(alg)`.
pub fn dup_policy_session_alg(sim: &mut Tpm, alg: TpmiAlgHash) -> ActiveSession {
    let sess = start_auth_session(
        sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        alg,
    )
    .unwrap();
    run(
        sim,
        &PolicyCommandCode {
            policy_session: sess.session_handle,
            code: TpmCc::Duplicate,
        },
        0,
    )
    .expect("PolicyCommandCode");
    sess
}

/// SHA-256 `TPM2_PolicyCommandCode(TPM_CC_Duplicate)` policy digest.
pub fn dup_policy_sha256() -> &'static [u8] {
    let mut ctx = tpm2::crypto::HashStream::new(CLIENT_CRYPTO, TpmiAlgHash::Sha256).unwrap();
    ctx.update(&[0u8; 32]).unwrap();
    ctx.update(&TpmCc::PolicyCommandCode.code().to_be_bytes())
        .unwrap();
    ctx.update(&TpmCc::Duplicate.code().to_be_bytes()).unwrap();
    let mut out = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    leak_bytes(ctx.finalize(&mut out).unwrap().digest())
}

/// Duplicates `object` to TPM_RH_NULL (no wrappers) with an `alg` policy session.
pub fn duplicate_with_policy(
    sim: &mut Tpm,
    object: Handle,
    alg: TpmiAlgHash,
) -> responses::Duplicate<'static> {
    let sess = start_auth_session(
        sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        alg,
    )
    .unwrap();
    run(
        sim,
        &PolicyCommandCode {
            policy_session: sess.session_handle,
            code: TpmCc::Duplicate,
        },
        0,
    )
    .unwrap();
    execute_with_hmac_sessions(
        sim,
        &Duplicate {
            object_handle: object,
            new_parent_handle: Handle::RH_NULL,
            encryption_key_in: Tpm2bData::default(),
            symmetric_alg: None,
        },
        &[],
        &mut [sess],
        &[&[]],
    )
    .expect("Duplicate")
}

/// HMAC over `aHash = SHA256(nonceTPM || expiration || cpHashA || policyRef)` with all fields
/// empty and expiration 0.
pub fn empty_policy_signed_hmac(key: &[u8]) -> TpmtSignature<'static> {
    let a_hash = sha(TpmiAlgHash::Sha256, &[&0i32.to_be_bytes()]);
    let mac = hmac(TpmiAlgHash::Sha256, key, &a_hash);
    TpmtSignature::Hmac(TpmtHa::new(TpmiAlgHash::Sha256, leak_bytes(&mac)).unwrap())
}

/// Policy sessions with an expired timeout:
/// - when the policy matches, authorization fails with `TPM_RC_EXPIRED + RC_S1` and the session
///   stays loaded (it can still be restarted);
/// - when the policy does not match, the digest mismatch is reported first.
pub fn expired_policy_session_scenario(sim: &mut Sim) {
    let digest = trial_digest(sim, |sim, t| {
        assert_eq!(policy_secret_raw(sim, t, &[], 0), 0);
    });
    set_owner_policy(sim, &digest, &[]);
    let mut p1 = start_session(sim, TpmSe::Policy, false);
    let mut p2 = start_session(sim, TpmSe::Policy, false);
    let nonce1 = p1.nonce_tpm.clone();
    let nonce2 = p2.nonce_tpm.clone();
    assert_eq!(policy_secret_raw(sim, p1.handle, &nonce1, 1), 0);
    assert_eq!(policy_secret_raw(sim, p2.handle, &nonce2, 1), 0);
    crate::test_utils::sleep(Duration::from_millis(1500));

    let rc = exec(
        sim,
        CC_CREATE_PRIMARY,
        &[RH_OWNER],
        &mut [SessUse::hmac(&mut p1, ATTR_CONT, &[])],
        &create_primary_params(),
        1,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_EXPIRED));
    assert_eq!(policy_cmd(sim, CC_POLICY_RESTART, p1.handle, &[]), 0);

    set_owner_policy(sim, &JUNK_DIGEST, &[]);
    let rc = exec(
        sim,
        CC_CREATE_PRIMARY,
        &[RH_OWNER],
        &mut [SessUse::hmac(&mut p2, ATTR_CONT, &[])],
        &create_primary_params(),
        1,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_POLICY_FAIL));
}

/// Returns the authPolicy digest of `hierarchy` as reported by
/// `TPM2_GetCapability(TPM_CAP_AUTH_POLICIES)` (empty if no policy is set).
pub fn hierarchy_policy(sim: &mut Tpm, hierarchy: Handle) -> Vec<u8> {
    let rsp = sim
        .execute(GetCapability {
            capability: TpmCap::AuthPolicies,
            property: hierarchy.0,
            property_count: 1,
        })
        .unwrap();
    match rsp.capability_data {
        TpmsCapabilityData::AuthPolicies(policies) => policies
            .as_ref()
            .iter()
            .find(|p| p.handle == hierarchy)
            .expect("hierarchy policy missing")
            .policy_hash
            .map(|ha| ha.digest().to_vec())
            .unwrap_or_default(),
        other => panic!("unexpected capability data {other:?}"),
    }
}

/// `TPM2_PolicyAuthorize`.
pub fn policy_authorize(
    sim: &mut Tpm,
    session: Handle,
    approved_policy: &[u8],
    policy_ref: &[u8],
    key_sign: Tpm2bName<'static>,
    check_ticket: TpmtTkVerified<'static>,
) -> Result<(), u32> {
    run_command(
        sim,
        PolicyAuthorize {
            policy_session: session,
            approved_policy: Tpm2bDigest::from_bytes(leak_bytes(approved_policy)).unwrap(),
            policy_ref: Tpm2bNonce::from_bytes(leak_bytes(policy_ref)).unwrap(),
            key_sign,
            check_ticket,
        },
    )
    .map(|_| ())
}

/// A policy session bound to another command code: `TPM_RC_POLICY_CC + RC_S1`.
pub fn policy_cc_mismatch_scenario(sim: &mut Sim) {
    let digest = trial_digest(sim, |sim, t| {
        assert_eq!(policy_command_code_raw(sim, t, CC_NV_DEFINE_SPACE), 0);
    });
    set_owner_policy(sim, &digest, &[]);
    let mut p = start_session(sim, TpmSe::Policy, false);
    assert_eq!(
        policy_command_code_raw(sim, p.handle, CC_NV_DEFINE_SPACE),
        0
    );
    let rc = exec(
        sim,
        CC_CREATE_PRIMARY,
        &[RH_OWNER],
        &mut [SessUse::hmac(&mut p, ATTR_CONT, &[])],
        &create_primary_params(),
        1,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_POLICY_CC));
}

/// Runs a policy command without sessions (`policySession` is the only handle).
pub fn policy_cmd(sim: &mut Sim, cc: u32, session: u32, params: &[u8]) -> u32 {
    rc_of(&transact(
        sim,
        &build(ST_NO_SESSIONS, cc, &[session], None, params),
    ))
}

/// Executes `TPM2_PolicyCommandCode(code)` on `session`.
pub fn policy_command_code(sim: &mut Tpm, session: Handle, code: TpmCc) -> Result<(), u32> {
    sim.execute(PolicyCommandCode {
        policy_session: session,
        code,
    })
    .map(|_| ())
    .map_err(rc_of_error)
}

/// Runs `TPM2_PolicyCommandCode(cc)` on `session`.
pub fn policy_command_code_active(sim: &mut Tpm, session: &ActiveSession, cc: TpmCc) {
    sim.execute(PolicyCommandCode {
        policy_session: session.session_handle,
        code: cc,
    })
    .expect("PolicyCommandCode failed");
}

/// Digest of a policy consisting only of `TPM2_PolicyCommandCode(code)` with `alg`.
pub fn policy_command_code_digest(alg: TpmiAlgHash, code: TpmCc) -> Tpm2bDigest<'static> {
    let mut data = vec![0u8; alg.digest_size()];
    data.extend_from_slice(&u32::from(TpmCc::PolicyCommandCode).to_be_bytes());
    data.extend_from_slice(&u32::from(code).to_be_bytes());
    Tpm2bDigest::from_bytes(leak_bytes(&hash_parts(alg, &[&data]))).unwrap()
}

/// `TPM2_PolicyCommandCode(TPM_CC_GetRandom)`.
pub fn policy_command_code_get_random(sim: &mut Tpm, session: Handle) {
    run_command(
        sim,
        PolicyCommandCode {
            policy_session: session,
            code: TpmCc::GetRandom,
        },
    )
    .expect("PolicyCommandCode failed");
}

/// `TPM2_PolicyCommandCode(session, code)`.
pub fn policy_command_code_raw(sim: &mut Sim, session: u32, code: u32) -> u32 {
    policy_cmd(sim, CC_POLICY_COMMAND_CODE, session, &code.to_be_bytes())
}

/// Starts an `alg` policy session and applies `TPM2_PolicyCommandCode(code)`.
pub fn policy_command_code_session(sim: &mut Tpm, alg: TpmiAlgHash, code: TpmCc) -> ActiveSession {
    let sess = start_auth_session(
        sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        alg,
    )
    .unwrap();
    run(
        sim,
        &PolicyCommandCode {
            policy_session: sess.session_handle,
            code,
        },
        0,
    )
    .expect("PolicyCommandCode");
    sess
}

/// Policy commands keep working on a policy session whose timeout has passed; expiration is
/// only enforced when the session authorizes a command.
pub fn policy_command_on_expired_session_scenario(sim: &mut Sim) {
    let p = start_session(sim, TpmSe::Policy, false);
    let nonce = p.nonce_tpm.clone();
    assert_eq!(policy_secret_raw(sim, p.handle, &nonce, 1), 0);
    crate::test_utils::sleep(Duration::from_millis(1500));
    assert_eq!(policy_cmd(sim, CC_POLICY_AUTH_VALUE, p.handle, &[]), 0);
    let r = transact(
        sim,
        &build(ST_NO_SESSIONS, CC_POLICY_GET_DIGEST, &[p.handle], None, &[]),
    );
    assert_eq!(rc_of(&r), 0);
}

/// Runs `TPM2_PolicyCpHash(cp_hash)` on policy `session`, returning the response code on failure.
pub fn policy_cp_hash(sim: &mut Tpm, session: Handle, cp_hash: &[u8]) -> Result<(), u32> {
    run_command(
        sim,
        PolicyCpHash {
            policy_session: session,
            cp_hash_a: to_digest(cp_hash),
        },
    )
    .map(|_| ())
}

/// Returns the current policy digest of `session` (`TPM2_PolicyGetDigest`).
pub fn policy_digest(sim: &mut Tpm, session: Handle) -> Vec<u8> {
    let rsp = sim
        .execute(PolicyGetDigest {
            policy_session: session,
        })
        .expect("PolicyGetDigest failed");
    rsp.policy_digest.get_buffer().to_vec()
}

/// Runs `TPM2_PolicyDuplicationSelect` on policy `session`, returning the response code on failure.
pub fn policy_duplication_select(
    sim: &mut Tpm,
    session: Handle,
    object_name: &[u8],
    new_parent_name: &[u8],
    include_object: bool,
) -> Result<(), u32> {
    run_command(
        sim,
        PolicyDuplicationSelect {
            policy_session: session,
            object_name: Tpm2bName::from_bytes(leak_bytes(object_name)).unwrap(),
            new_parent_name: Tpm2bName::from_bytes(leak_bytes(new_parent_name)).unwrap(),
            include_object,
        },
    )
    .map(|_| ())
}

/// `TPM2_PolicyDuplicationSelect` with a 66-byte (SHA-512) object name and a
/// 34-byte (SHA-256) new parent name.
pub fn policy_duplication_select_66(include_object: bool) -> Result<(), u32> {
    let mut sim = Tpm::new();
    let session = start_policy_session(&mut sim);

    let mut object_name_bytes = [0u8; 66];
    object_name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha512).id().to_be_bytes()); // SHA512
    let object_name = Tpm2bName::from_bytes(&object_name_bytes).unwrap();

    let mut parent_name_bytes = [0u8; 34];
    parent_name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes()); // SHA256
    let new_parent_name = Tpm2bName::from_bytes(&parent_name_bytes).unwrap();

    let cmd = PolicyDuplicationSelect {
        policy_session: session.session_handle,
        object_name,
        new_parent_name,
        include_object,
    };
    execute_with_password_sessions(&mut sim, &cmd, 0, &[]).map(|_| ())
}

/// `TPM2_PolicyGetDigest`.
pub fn policy_get_digest(sim: &mut Tpm, session: Handle) -> Vec<u8> {
    run_command(
        sim,
        PolicyGetDigest {
            policy_session: session,
        },
    )
    .expect("PolicyGetDigest failed")
    .policy_digest
    .get_buffer()
    .to_vec()
}

/// `TPM2_PolicyGetDigest(session)`.
pub fn policy_get_digest_checked(sim: &mut Tpm, policy_session: Handle) -> Vec<u8> {
    let resp = execute_with_password_sessions(sim, &PolicyGetDigest { policy_session }, 0, &[])
        .expect("PolicyGetDigest failed");
    resp.policy_digest.get_buffer().to_vec()
}

/// `TPM2_PolicyGetDigest(session)`.
pub fn policy_get_digest_raw(sim: &mut Sim, session: u32) -> Vec<u8> {
    let r = transact(
        sim,
        &build(ST_NO_SESSIONS, CC_POLICY_GET_DIGEST, &[session], None, &[]),
    );
    assert_eq!(rc_of(&r), 0, "TPM2_PolicyGetDigest failed");
    let mut off = 10;
    read_2b(&r, &mut off)
}

/// Runs `TPM2_PolicyNameHash(name_hash)` on policy `session`, returning the response code on
/// failure.
pub fn policy_name_hash(sim: &mut Tpm, session: Handle, name_hash: &[u8]) -> Result<(), u32> {
    run_command(
        sim,
        PolicyNameHash {
            policy_session: session,
            name_hash: to_digest(name_hash),
        },
    )
    .map(|_| ())
}

/// Client-side expected `TPM2_PolicyOR` digest: `H(zeros || TPM_CC_PolicyOR || digests...)` with
/// `alg`.
pub fn policy_or_expected(alg: TpmiAlgHash, digests: &[&[u8]]) -> Vec<u8> {
    let digest_size = match alg {
        TpmiAlgHash::Sha1 => 20,
        TpmiAlgHash::Sha256 => 32,
        TpmiAlgHash::Sha384 => 48,
        TpmiAlgHash::Sha512 => 64,
        #[allow(unreachable_patterns)]
        _ => panic!("Unsupported hash"),
    };
    let zero_digest = vec![0u8; digest_size];
    let cc_bytes = (tpm2::TpmCc::PolicyOR.code()).to_be_bytes();
    let mut updates = vec![zero_digest.as_slice(), &cc_bytes];
    for d in digests {
        updates.push(*d);
    }
    compute_hash(alg, &updates)
}

/// Client-side expected `TPM2_PolicyOR` digest with `alg`, computed like the Go TPM library does
/// (`H(zeros || TPM_CC_PolicyOR || digests...)`).
pub fn policy_or_go(alg: TpmiAlgHash, digests: &[&[u8]]) -> Vec<u8> {
    let digest_size = match alg {
        TpmiAlgHash::Sha1 => 20,
        TpmiAlgHash::Sha256 => 32,
        TpmiAlgHash::Sha384 => 48,
        TpmiAlgHash::Sha512 => 64,
        #[allow(unreachable_patterns)]
        _ => panic!("Unsupported hash"),
    };
    let zero_digest = vec![0u8; digest_size];
    let cc_bytes = (tpm2::TpmCc::PolicyOR.code()).to_be_bytes();
    let mut updates = vec![zero_digest.as_slice(), &cc_bytes];
    for d in digests {
        updates.push(*d);
    }
    compute_hash(alg, &updates)
}

/// Starts a policy session and runs `TPM2_PolicyPassword` on it.
pub fn policy_password_session(sim: &mut Tpm) -> Handle {
    let session = start_auth_session(
        sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("StartAuthSession failed")
    .session_handle;
    sim.execute(tpm2::commands::PolicyPassword {
        policy_session: session,
    })
    .expect("PolicyPassword failed");
    session
}

/// Raw policy command with a single session handle and `params`.
pub fn policy_raw(sim: &mut Tpm, cc: u32, session: u32, params: &[u8]) -> Vec<u8> {
    let mut cmd = Vec::new();
    cmd.extend_from_slice(&0x8001u16.to_be_bytes());
    cmd.extend_from_slice(&((14 + params.len()) as u32).to_be_bytes());
    cmd.extend_from_slice(&cc.to_be_bytes());
    cmd.extend_from_slice(&session.to_be_bytes());
    cmd.extend_from_slice(params);
    raw(sim, &cmd)
}

/// Runs `TPM2_PolicySecret` (authorized by a password session for `auth_handle`) on the policy
/// `session`; uses the session's `nonceTPM` only when `expiration` is non-zero. Returns the response
/// or the response code.
pub fn policy_secret(
    sim: &mut Tpm,
    auth_handle: Handle,
    session: &ActiveSession,
    cp_hash_a: &[u8],
    expiration: i32,
) -> Result<tpm2::commands::responses::PolicySecret<'static>, u32> {
    let nonce_tpm = if expiration != 0 {
        session.nonce_tpm
    } else {
        Tpm2bNonce::default()
    };
    run_pw(
        sim,
        PolicySecret {
            auth_handle,
            policy_session: session.session_handle,
            nonce_tpm,
            cp_hash_a: to_digest(cp_hash_a),
            policy_ref: Tpm2bNonce::default(),
            expiration,
        },
    )
}

/// Parameters of `TPM2_PolicySecret` (empty nonce, cpHash, policyRef; expiration 0).
pub fn policy_secret_default_params() -> Vec<u8> {
    vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
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
pub fn policy_secret_raw(sim: &mut Sim, session: u32, nonce_tpm: &[u8], expiration: i32) -> u32 {
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

/// Starts an unbound, unsalted SHA-256 policy session and returns its handle.
pub fn policy_session(sim: &mut Tpm) -> Handle {
    Handle(start_session(sim, TpmSe::Policy, false).handle)
}

/// `TPM2_PolicySigned` with empty nonce/cpHash/policyRef and expiration 0.
pub fn policy_signed(
    sim: &mut Tpm,
    auth_object: Handle,
    session: Handle,
    auth: TpmtSignature<'static>,
) -> Result<(), u32> {
    run_command(
        sim,
        PolicySigned {
            auth_object,
            policy_session: session,
            nonce_tpm: Tpm2bNonce::default(),
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: Tpm2bNonce::default(),
            expiration: 0,
            auth,
        },
    )
    .map(|_| ())
}

/// The digest signed for `TPM2_PolicySigned` with empty cpHashA and policyRef:
/// `H(nonceTPM || expiration)`.
pub fn policy_signed_digest(nonce_tpm: &[u8], expiration: i32) -> Vec<u8> {
    sha256(&[nonce_tpm, &expiration.to_be_bytes()])
}

/// `TPM2_PolicySigned` with empty cpHashA and policyRef.
pub fn policy_signed_with_nonce(
    sim: &mut Tpm,
    auth_object: Handle,
    session: Handle,
    nonce_tpm: Tpm2bNonce<'static>,
    expiration: i32,
    auth: TpmtSignature<'static>,
) -> Result<tpm2::commands::responses::PolicySigned<'static>, u32> {
    run_command(
        sim,
        PolicySigned {
            auth_object,
            policy_session: session,
            nonce_tpm,
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: Tpm2bNonce::default(),
            expiration,
            auth,
        },
    )
}

/// Runs `TPM2_PolicyTicket` on policy `session` with the given timeout, cpHash, authName and
/// ticket, returning the response code on failure.
pub fn policy_ticket(
    sim: &mut Tpm,
    session: Handle,
    timeout: &[u8],
    cp_hash_a: &[u8],
    auth_name: &[u8],
    ticket: TpmtTkAuth<'static>,
) -> Result<(), u32> {
    run_command(
        sim,
        PolicyTicket {
            policy_session: session,
            timeout: Tpm2bTimeout::from_bytes(leak_bytes(timeout)).unwrap(),
            cp_hash_a: to_digest(cp_hash_a),
            policy_ref: Tpm2bNonce::default(),
            auth_name: Tpm2bName::from_bytes(leak_bytes(auth_name)).unwrap(),
            ticket,
        },
    )
    .map(|_| ())
}

/// Scenario: on a fresh simulator, starts a policy session with `alg` and checks that
/// `TPM2_PolicyCpHash` accepts/rejects a cpHash of `cp_hash_len` bytes as required for that digest
/// size.
pub fn run_policy_cphash_for_alg(alg: TpmiAlgHash, cp_hash_len: usize) {
    let mut sim = Tpm::new();

    // Start policy session
    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        alg,
    )
    .unwrap();

    let cp_hash_val = vec![0xaa; cp_hash_len];
    let cp_hash_a = Tpm2bDigest::from_bytes(&cp_hash_val).unwrap();

    let cp_hash_cmd = PolicyCpHash {
        policy_session: sess.session_handle,
        cp_hash_a,
    };

    let res = execute_with_password_sessions(&mut sim, &cp_hash_cmd, 0, &[]);
    assert!(
        res.is_ok(),
        "PolicyCpHash failed for {:?} with: {:?}",
        alg,
        res.err()
    );

    // Verify policy digest against PolicyCalculator
    let get_digest_cmd = PolicyGetDigest {
        policy_session: sess.session_handle,
    };
    let get_digest_rsp = execute_with_password_sessions(&mut sim, &get_digest_cmd, 0, &[]).unwrap();

    let mut calc = PolicyCalculator::new(alg);
    calc.policy_cp_hash(&cp_hash_val);

    assert_eq!(
        get_digest_rsp.policy_digest.get_buffer(),
        calc.policy_digest.as_slice(),
        "PolicyCpHash digest mismatch for {:?}",
        alg
    );
}

/// Scenario: on a fresh simulator, starts a policy session with `alg` and runs
/// `TPM2_PolicyDuplicationSelect` (with `include_obj`), checking the resulting policy digest.
pub fn run_policy_dup_select_for_alg(alg: TpmiAlgHash, include_obj: bool) {
    let mut sim = Tpm::new();

    // Start policy session
    let sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        alg,
    )
    .unwrap();

    let object_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x11; 32].as_slice()].concat(),
    ))
    .unwrap();
    let new_parent_name = Tpm2bName::from_bytes(crate::test_utils::leak_bytes(
        &[[0x00, 0x0b].as_slice(), [0x22; 32].as_slice()].concat(),
    ))
    .unwrap();

    let dup_cmd = PolicyDuplicationSelect {
        policy_session: sess.session_handle,
        object_name,
        new_parent_name,
        include_object: include_obj,
    };

    let res = execute_with_password_sessions(&mut sim, &dup_cmd, 0, &[]);
    assert!(
        res.is_ok(),
        "PolicyDuplicationSelect failed for {:?}, include={:?}: {:?}",
        alg,
        include_obj,
        res.err()
    );

    // Verify policy digest against PolicyCalculator
    let get_digest_cmd = PolicyGetDigest {
        policy_session: sess.session_handle,
    };
    let get_digest_rsp = execute_with_password_sessions(&mut sim, &get_digest_cmd, 0, &[]).unwrap();

    let mut calc = PolicyCalculator::new(alg);
    calc.policy_duplication_select(
        object_name.get_buffer(),
        new_parent_name.get_buffer(),
        include_obj,
    );

    assert_eq!(
        get_digest_rsp.policy_digest.get_buffer(),
        calc.policy_digest.as_slice(),
        "PolicyDuplicationSelect digest mismatch for {:?}, include={}",
        alg,
        include_obj
    );
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

/// `TPM2_SetPrimaryPolicy(auth_handle, policy, SHA-256)` authorized with an empty password
/// session; returns the response code.
pub fn set_primary_policy(sim: &mut Tpm, auth_handle: Handle, policy: &[u8]) -> u32 {
    let cmd = SetPrimaryPolicy {
        auth_handle,
        auth_policy: Tpm2bDigest::from_bytes(policy).unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    match execute_with_password_sessions_status(sim, &cmd, 1, &[]) {
        Ok([]) => 0,
        Err(rc) => rc,
    }
}

/// Parameters of `TPM2_SetPrimaryPolicy` with a SHA-256 policy.
pub fn set_primary_policy_params(digest: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    push_2b(&mut p, digest);
    p.extend_from_slice(&ALG_SHA256.to_be_bytes());
    p
}

/// Starts an unbound, unsalted SHA-256 session of `session_type`; returns its handle and
/// nonceTPM.
pub fn start_policy(sim: &mut Tpm, session_type: TpmSe) -> (Handle, Tpm2bNonce<'static>) {
    let s = start_auth_session(
        sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        session_type,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("StartAuthSession failed");
    (s.session_handle, s.nonce_tpm)
}

/// Starts an unbound, unsalted SHA-256 policy session.
pub fn start_policy_session(sim: &mut Tpm) -> ActiveSession {
    start_auth_session(
        sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("StartAuthSession failed")
}

/// Executes `TPM2_PolicyGetDigest` on `session`.
pub fn try_policy_get_digest(sim: &mut Tpm, session: Handle) -> Result<Vec<u8>, u32> {
    sim.execute(PolicyGetDigest {
        policy_session: session,
    })
    .map(|rsp| rsp.policy_digest.get_buffer().to_vec())
    .map_err(rc_of_error)
}

// ===========================================================================
// Object templates and public areas
//
// Builders for `TpmtPublic` templates, schemes, parameters and sensitive areas.
// ===========================================================================

/// Attributes shared by every key created here.
pub fn base_attributes() -> TpmaObject {
    TpmaObject::FIXED_TPM
        | TpmaObject::FIXED_PARENT
        | TpmaObject::SENSITIVE_DATA_ORIGIN
        | TpmaObject::USER_WITH_AUTH
}

/// A TPM-generated, USER_WITH_AUTH child template of the given algorithm-specific shape.
pub fn child_template(parms_and_id: PublicParmsAndId<'static>) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id,
    }
}

/// Returns the `TPMA_CC` of command `cc` from `TPM_CAP_COMMANDS`.
pub fn command_attributes(sim: &mut Tpm, cc: u32) -> u32 {
    let (_, data) = get_cap(sim, CAP_COMMANDS, cc, 1).unwrap();
    assert_eq!(u32::from_be_bytes(data[0..4].try_into().unwrap()), 1);
    let attr = u32::from_be_bytes(data[4..8].try_into().unwrap());
    assert_eq!(attr & 0xFFFF, cc, "command not implemented");
    attr
}

/// Like [`try_create_primary`], panicking on failure.
pub fn create_primary_returning_public(
    sim: &mut Tpm,
    public: TpmtPublic<'static>,
    data: &'static [u8],
) -> (Handle, TpmtPublic<'static>) {
    try_create_primary(sim, public, data)
        .unwrap_or_else(|rc| panic!("TPM2_CreatePrimary failed: {rc:#x}"))
}

/// Creates an unrestricted signing primary key (empty authValue, no scheme)
/// under the owner hierarchy; returns its handle and name.
pub fn create_signing_key_with_parms(
    sim: &mut Tpm,
    parms_and_id: PublicParmsAndId<'static>,
) -> (Handle, Tpm2bName<'static>) {
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id,
    };
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_public: Tpm2b(public),
        ..Default::default()
    };
    let rsp = execute_with_password_sessions(sim, &cmd, 1, &[]).expect("CreatePrimary failed");
    (rsp.object_handle, rsp.name)
}

/// Creates a primary storage key from `srk_template` with authValue `srk_auth` under the owner
/// hierarchy and returns its handle and Name; panics on failure.
pub fn create_srk_with_template(
    sim: &mut Tpm,
    srk_template: &TpmtPublic,
    srk_auth: &[u8],
) -> (Handle, Tpm2bName<'static>) {
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(srk_auth).unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(*srk_template);
    let create_primary = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let rsp = execute_with_password_sessions(sim, &create_primary, 1, &[])
        .expect("could not call TPM2_CreatePrimary");

    (rsp.object_handle, rsp.name)
}

/// ECC NIST P-256 restricted decryption (storage) key template with AES-128-CFB.
pub fn default_ecc_public() -> TpmtPublic<'static> {
    let ecc_parms = TpmsEccParms {
        symmetric: Some(TpmtSymDefObject::aes_cfb(128).unwrap()),
        scheme: None,
        curve_id: tpm2::TpmEccCurve::NistP256,
        kdf: None,
    };

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
            ecc_parms,
            tpm2::TpmsEccPoint {
                x: tpm2::Tpm2bEccParameter::default(),
                y: tpm2::Tpm2bEccParameter::default(),
            },
        ),
    }
}

/// Derivation parent template (restricted decrypt KEYEDHASH, XOR/SP800-108 with `hash`).
pub fn derivation_parent_template(hash: TpmiAlgHash, attrs: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::ExclusiveOr(TpmsSchemeXor {
                hash_alg: hash,
                kdf: Some(TpmiAlgKdf::Kdf1Sp800_108),
            })),
            Tpm2bDigest::default(),
        ),
    }
}

/// A duplicable ECC signing key template whose authPolicy is `PolicyCommandCode(Duplicate)`
/// (computed with `name_alg`).
pub fn duplicable_sign_template(name_alg: TpmiAlgHash) -> TpmtPublic<'static> {
    let mut t = ecc_sign_template(name_alg, TpmaObject::empty());
    t.auth_policy = dup_policy_digest_for(name_alg);
    t
}

/// Small, fast-to-generate ECC storage key template.
pub fn ecc_primary_template() -> TpmtPublic<'static> {
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
                symmetric: Some(TpmtSymDefObject::aes_cfb(128).unwrap()),
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

/// A NIST P-256 ECC key template.
pub fn ecc_public(
    attributes: TpmaObject,
    symmetric: Option<TpmtSymDefObject>,
    scheme: Option<TpmtEccScheme>,
) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attributes,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric,
                scheme,
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

/// Public area of an ECC key on `curve` without a scheme.
pub fn ecc_public_with_policy(
    name_alg: TpmiAlgHash,
    attrs: TpmaObject,
    policy: &'static [u8],
    curve: TpmEccCurve,
    symmetric: Option<TpmtSymDefObject>,
) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::from_bytes(policy).unwrap(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric,
                scheme: None,
                curve_id: curve,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    }
}

/// ECC P-256 ECDSA signing key template.
pub fn ecc_sign_template(name_alg: TpmiAlgHash, attrs: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: attrs
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
            TpmsEccPoint::default(),
        ),
    }
}

/// Template for a NIST P-256 signing key with the given default scheme.
pub fn ecc_sign_template_with_scheme(scheme: Option<TpmtEccScheme>) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint::default(),
        ),
    }
}

/// ECC NIST P-256 unrestricted signing key template using `name_alg`.
pub fn ecc_signing_template(name_alg: TpmiAlgHash) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(name_alg),
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
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            tpm2::TpmsEccPoint::default(),
        ),
    }
}

/// Small, fast-to-generate ECC restricted storage key template.
pub fn ecc_storage_template() -> TpmtPublic<'static> {
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
                symmetric: Some(TpmtSymDefObject::aes_cfb(128).unwrap()),
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

/// An ECC P-256 restricted decryption (storage) key template.
pub fn ecc_storage_template_derived() -> TpmtPublic<'static> {
    let mut t = ecc_template(
        base_attrs() | TpmaObject::RESTRICTED | TpmaObject::DECRYPT,
        None,
    );
    if let PublicParmsAndId::Ecc(parms, _) = &mut t.parms_and_id {
        parms.symmetric = Some(TpmtSymDefObject::aes_cfb(128).unwrap());
    }
    t
}

/// ECC P-256 storage key template (restricted decrypt, AES-128-CFB).
pub fn ecc_storage_template_with(name_alg: TpmiAlgHash, attrs: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: attrs
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: Some(TpmtSymDefObject::aes_cfb(128).unwrap()),
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint::default(),
        ),
    }
}

/// An ECC NIST P-256 key template.
pub fn ecc_template(attrs: TpmaObject, scheme: Option<TpmtEccScheme>) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme,
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

/// The ECDAA signing scheme for commit `count`.
pub fn ecdaa_scheme(count: u16) -> Option<TpmtSigScheme> {
    Some(TpmtSigScheme::Ecdaa(TpmsSchemeEcdaa {
        hash_alg: TpmiAlgHash::Sha256,
        count,
    }))
}

/// An ECDAA (SHA-256) NIST P-256 signing key template.
pub fn ecdaa_template(attrs: TpmaObject) -> TpmtPublic<'static> {
    ecc_template(
        attrs,
        Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
            hash_alg: TpmiAlgHash::Sha256,
            count: 0,
        })),
    )
}

/// A NIST P-256 ECDSA-SHA256 unrestricted signing key template.
pub fn ecdsa_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: base_attributes() | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint::default(),
        ),
    }
}

/// Empty sensitive area (no authValue, no data).
pub fn empty_sensitive() -> tpm2::Tpm2b<TpmsSensitiveCreate<'static>> {
    tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    })
}

/// Sends `TPM2_TestParms(parameters)` and returns its response code as a `Result`.
pub fn execute_test_parms(sim: &mut Tpm, parameters: TpmtPublicParms) -> Result<(), u32> {
    execute_with_password_sessions_status(sim, &TestParms { parameters }, 0, &[]).map(|[]| ())
}

/// Sends `TPM2_TestParms(parameters)` after `corrupt_fn` has modified the marshaled
/// parameter area, and returns its response code as a `Result`.
pub fn execute_test_parms_corrupted(
    sim: &mut Tpm,
    parameters: TpmtPublicParms,
    corrupt_fn: impl FnOnce(&mut [u8]),
) -> Result<(), u32> {
    execute_with_corrupted_bytes_status(sim, &TestParms { parameters }, 0, &[], corrupt_fn)
        .map(|[]| ())
}

/// A public-only RSA-2048 storage key public area with a fake (but well-formed) modulus.
pub fn external_storage_public() -> TpmtPublic<'static> {
    let mut modulus = [0x5au8; 256];
    modulus[0] = 0xc1;
    let mut t = rsa_storage_template_with(TpmiAlgHash::Sha256, TpmaObject::empty());
    if let PublicParmsAndId::Rsa(_, unique) = &mut t.parms_and_id {
        *unique = Tpm2bPublicKeyRsa::from_bytes(leak_bytes(&modulus)).unwrap();
    }
    t
}

/// Random ECC KDF scheme for `TPM2_TestParms` fuzzing; only valid choices when `make_valid`.
pub fn gen_ecc_kdf(rng: &mut SimpleRng, make_valid: bool) -> Option<TpmtKdfScheme> {
    if make_valid {
        let hash_alg = gen_hash_alg(rng, true);
        rng.choose(&[
            Some(TpmtKdfScheme::Kdf1Sp800_56a(hash_alg)),
            Some(TpmtKdfScheme::Kdf2(hash_alg)),
            Some(TpmtKdfScheme::Kdf1Sp800_108(hash_alg)),
            None,
        ])
    } else {
        let hash_alg = gen_hash_alg(rng, false);
        rng.choose(&[
            Some(TpmtKdfScheme::Kdf1Sp800_56a(hash_alg)),
            Some(TpmtKdfScheme::Kdf2(hash_alg)),
            Some(TpmtKdfScheme::Kdf1Sp800_108(hash_alg)),
            Some(TpmtKdfScheme::Mgf1(hash_alg)),
        ])
    }
}

/// Random ECC signing/key-exchange scheme for `TPM2_TestParms` fuzzing; only valid choices when
/// `make_valid`.
pub fn gen_ecc_scheme(rng: &mut SimpleRng, make_valid: bool) -> Option<TpmtEccScheme> {
    if make_valid {
        let hash_alg = gen_hash_alg(rng, true);
        rng.choose(&[
            Some(TpmtEccScheme::Ecdsa(hash_alg)),
            Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa { hash_alg, count: 0 })),
            None,
        ])
    } else {
        let hash_alg = gen_hash_alg(rng, false);
        rng.choose(&[
            Some(TpmtEccScheme::Ecdsa(hash_alg)),
            Some(TpmtEccScheme::Ecdh(hash_alg)),
        ])
    }
}

/// Random hash algorithm for `TPM2_TestParms` fuzzing; may return unsupported values unless
/// `make_valid`.
pub fn gen_hash_alg(rng: &mut SimpleRng, make_valid: bool) -> TpmiAlgHash {
    if make_valid {
        rng.choose(&[
            TpmiAlgHash::Sha1,
            TpmiAlgHash::Sha256,
            TpmiAlgHash::Sha384,
            TpmiAlgHash::Sha512,
        ])
    } else {
        // The hash algorithms this TPM does not implement (SM3, SHA-3) are not `TpmiAlgHash`
        // values (the `tpm2` features of the TPM), so invalid parameter sets are invalid
        // elsewhere (e.g. a hash where `TPM_ALG_NULL` is required or a missing KDF).
        rng.choose(&[
            TpmiAlgHash::Sha1,
            TpmiAlgHash::Sha256,
            TpmiAlgHash::Sha384,
            TpmiAlgHash::Sha512,
        ])
    }
}

/// Random keyed-hash (HMAC/XOR) scheme for `TPM2_TestParms` fuzzing; only valid choices when
/// `make_valid`.
pub fn gen_keyed_hash_scheme(rng: &mut SimpleRng, make_valid: bool) -> Option<TpmtKeyedHashScheme> {
    if make_valid {
        let hash_alg = gen_hash_alg(rng, true);
        let kdf_val = rng.choose(&[
            Some(TpmiAlgKdf::Mgf1),
            Some(TpmiAlgKdf::Kdf1Sp800_56a),
            Some(TpmiAlgKdf::Kdf2),
            Some(TpmiAlgKdf::Kdf1Sp800_108),
            None,
        ]);
        rng.choose(&[
            Some(TpmtKeyedHashScheme::Hmac(hash_alg)),
            Some(TpmtKeyedHashScheme::ExclusiveOr(TpmsSchemeXor {
                hash_alg,
                kdf: kdf_val,
            })),
            None,
        ])
    } else {
        let hash_alg = gen_hash_alg(rng, false);
        rng.choose(&[
            Some(TpmtKeyedHashScheme::Hmac(hash_alg)),
            Some(TpmtKeyedHashScheme::ExclusiveOr(TpmsSchemeXor {
                hash_alg,
                kdf: None,
            })),
        ])
    }
}

/// Random `TPMT_PUBLIC_PARMS` (RSA, ECC, keyed-hash or symmetric; ~40% intended to be valid) for
/// `TPM2_TestParms` fuzzing.
pub fn gen_random_parms(rng: &mut SimpleRng) -> TpmtPublicParms {
    // 0: RSA, 1: ECC, 2: KeyedHash, 3: Sym
    let variant = rng.next_u64() % 4;
    let make_valid = rng.next_u64() % 10 < 4;

    match variant {
        0 => {
            let key_bits = if make_valid {
                rng.choose(&[TpmiRsaKeyBits(1024), TpmiRsaKeyBits(2048)])
            } else {
                rng.choose(&[
                    TpmiRsaKeyBits(512),
                    TpmiRsaKeyBits(3072),
                    TpmiRsaKeyBits(4096),
                    TpmiRsaKeyBits(9999),
                ])
            };
            let exponent = if make_valid {
                rng.choose(&[0, 65537])
            } else {
                rng.choose(&[3, 17, 65535])
            };
            let symmetric = gen_symmetric(rng, make_valid);
            let scheme = gen_rsa_scheme(rng, make_valid);

            TpmtPublicParms::Rsa(TpmsRsaParms {
                symmetric,
                scheme,
                key_bits,
                exponent,
            })
        }
        1 => {
            let curve_id = if make_valid {
                rng.choose(&[
                    TpmEccCurve::NistP256,
                    TpmEccCurve::NistP384,
                    TpmEccCurve::BNP256,
                ])
            } else {
                TpmEccCurve::NistP256
            };
            let symmetric = gen_symmetric(rng, make_valid);
            let scheme = gen_ecc_scheme(rng, make_valid);
            let kdf = gen_ecc_kdf(rng, make_valid);

            TpmtPublicParms::Ecc(TpmsEccParms {
                symmetric,
                scheme,
                curve_id,
                kdf,
            })
        }
        2 => {
            let scheme = gen_keyed_hash_scheme(rng, make_valid);
            TpmtPublicParms::KeyedHash(scheme)
        }
        _ => {
            let sym = if make_valid {
                rng.choose(&[
                    TpmtSymDefObject::aes_cfb(128).unwrap(),
                    TpmtSymDefObject {
                        alg: AlgSym::Aes256,
                        mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
                    },
                ])
            } else {
                rng.choose(&[
                    TpmtSymDefObject {
                        alg: AlgSym::Aes256,
                        mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Ofb)),
                    },
                    TpmtSymDefObject {
                        alg: AlgSym::Aes128,
                        mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cbc)),
                    },
                ])
            };
            TpmtPublicParms::Sym(sym)
        }
    }
}

/// Random RSA scheme for `TPM2_TestParms` fuzzing; only valid choices when `make_valid`.
pub fn gen_rsa_scheme(rng: &mut SimpleRng, make_valid: bool) -> Option<TpmtRsaScheme> {
    if make_valid {
        let hash_alg = gen_hash_alg(rng, true);
        rng.choose(&[
            Some(TpmtRsaScheme::Rsapss(hash_alg)),
            Some(TpmtRsaScheme::Rsassa(hash_alg)),
            Some(TpmtRsaScheme::Oaep(hash_alg)),
            Some(TpmtRsaScheme::Rsaes),
            None,
        ])
    } else {
        let hash_alg = gen_hash_alg(rng, false);
        rng.choose(&[
            Some(TpmtRsaScheme::Rsapss(hash_alg)),
            Some(TpmtRsaScheme::Rsassa(hash_alg)),
            Some(TpmtRsaScheme::Oaep(hash_alg)),
        ])
    }
}

/// Random symmetric definition for `TPM2_TestParms` fuzzing; only valid choices when `make_valid`.
pub fn gen_symmetric(rng: &mut SimpleRng, make_valid: bool) -> Option<TpmtSymDefObject> {
    if make_valid {
        rng.choose(&[
            Some(TpmtSymDefObject::aes_cfb(128).unwrap()),
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes256,
                mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
            }),
            None,
        ])
    } else {
        rng.choose(&[
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes256,
                mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Ecb)),
            }),
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes128,
                mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cbc)),
            }),
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes256,
                mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Ctr)),
            }),
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes128,
                mode: None,
            }),
            None,
        ])
    }
}

/// ECC NIST P-256 restricted decryption parent template (not fixedTPM/fixedParent, so children can
/// be duplicated/imported).
pub fn get_ecc_decrypt_parent_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED, // decrypt and restricted parent key
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: Some(TpmtSymDefObject::aes_cfb(128).unwrap()),
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

/// ECC NIST P-256 decryption key template without `restricted` (not usable as a parent).
pub fn get_ecc_decrypt_unrestricted_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT, // No RESTRICTED
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    }
}

/// ECC NIST P-256 endorsement-key style template (restricted decrypt, adminWithPolicy).
pub fn get_ecc_ek_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::ADMIN_WITH_POLICY
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::from_bytes(&[
            // PolicyA SHA256 value from TCG EK Profile
            0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5,
            0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B,
            0x33, 0x14, 0x69, 0xAA,
        ])
        .unwrap(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: Some(TpmtSymDefObject::aes_cfb(128).unwrap()),
                scheme: None,
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    }
}

/// ECC NIST P-256 restricted *signing* key template (not usable as a storage parent).
pub fn get_ecc_sign_restricted_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::SIGN_ENCRYPT, // SIGN instead of DECRYPT
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    }
}

/// ECC NIST P-256 unrestricted signing key template (neither decrypt nor restricted).
pub fn get_ecc_signing_key_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT, // Not decrypt, not restricted
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
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

/// ECC NIST P-256 storage root key template (restricted decrypt, AES-128-CFB, fixedTPM/fixedParent).
pub fn get_ecc_srk_template() -> TpmtPublic<'static> {
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
                symmetric: Some(TpmtSymDefObject::aes_cfb(128).unwrap()),
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

/// ECC NIST P-256 SRK template whose `unique.x` is derived from `unique`, so different values yield
/// different primary keys.
pub fn get_ecc_srk_template_unique(unique: u8) -> TpmtPublic<'static> {
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
                symmetric: Some(TpmtSymDefObject::aes_cfb(128).unwrap()),
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(crate::test_utils::leak_bytes(&[unique; 32]))
                    .unwrap(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    }
}

/// ECC NIST P-256 SRK template built with [`get_ecc_srk_template_with_unique`]`(0)`.
pub fn get_ecc_srk_template_unique0() -> TpmtPublic<'static> {
    get_ecc_srk_template_with_unique(0)
}

/// ECC NIST P-256 SRK template whose `unique` field is seeded with `unique`, so different values
/// yield different primary keys.
pub fn get_ecc_srk_template_with_unique(unique: u8) -> TpmtPublic<'static> {
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
                symmetric: Some(TpmtSymDefObject::aes_cfb(128).unwrap()),
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(crate::test_utils::leak_bytes(&[unique; 32]))
                    .unwrap(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    }
}

/// ECC NIST P-256 unrestricted signing key template.
pub fn get_ecc_template() -> TpmtPublic<'static> {
    TpmtPublic {
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

/// RSA-2048 storage root key template (restricted decrypt, AES-128-CFB).
pub fn get_rsa_srk_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: Some(TpmtSymDefObject::aes_cfb(128).unwrap()),
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    }
}

/// RSA-2048 restricted decryption (storage) key template used by the compliance regression tests.
pub fn get_test_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Default::default(),
        // A restricted decrypt KEYEDHASH object would need an XOR scheme (C `SchemeChecks()`);
        // use a symmetric storage key instead.
        parms_and_id: PublicParmsAndId::Sym(
            tpm2::TpmtSymDefObject {
                alg: tpm2::AlgSym::Aes128,
                mode: Some(tpm2::TpmiAlgSymMode::Cipher(tpm2::TpmiAlgCipherMode::Cfb)),
            },
            tpm2::Tpm2bDigest::default(),
        ),
    }
}

/// RSA-2048 restricted decryption key template, with `stClear` set when `st_clear`.
pub fn get_test_template_st_clear(st_clear: bool) -> TpmtPublic<'static> {
    let mut attrs = TpmaObject::FIXED_TPM
        | TpmaObject::FIXED_PARENT
        | TpmaObject::SENSITIVE_DATA_ORIGIN
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::RESTRICTED
        | TpmaObject::DECRYPT;
    if st_clear {
        attrs |= TpmaObject::ST_CLEAR;
    }
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Default::default(),
        // A restricted decrypt KEYEDHASH object would need an XOR scheme (C `SchemeChecks()`);
        // use a symmetric storage key instead.
        parms_and_id: PublicParmsAndId::Sym(
            tpm2::TpmtSymDefObject {
                alg: tpm2::AlgSym::Aes128,
                mode: Some(tpm2::TpmiAlgSymMode::Cipher(tpm2::TpmiAlgCipherMode::Cfb)),
            },
            tpm2::Tpm2bDigest::default(),
        ),
    }
}

/// Keyed-hash HMAC signing key template whose HMAC scheme uses `scheme_hash`.
pub fn hmac_key_template(scheme_hash: TpmiAlgHash) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::Hmac(scheme_hash)),
            Tpm2bDigest::default(),
        ),
    }
}

/// A KeyedHash HMAC-SHA256 signing key template with the given authPolicy.
pub fn hmac_key_template_with_policy(auth_policy: Tpm2bDigest<'static>) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: base_attributes() | TpmaObject::SIGN_ENCRYPT,
        auth_policy,
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            Tpm2bDigest::default(),
        ),
    }
}

/// A small keyed-hash (HMAC) primary key template, fast to create.
pub fn hmac_primary_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            Tpm2bDigest::default(),
        ),
    }
}

/// Template for a keyed-hash (HMAC-SHA256) signing key whose key bits are supplied by the
/// caller in the sensitive data.
pub fn hmac_sign_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            Tpm2bDigest::default(),
        ),
    }
}

/// A keyed-hash (HMAC) key template.
pub fn hmac_template(
    attrs: TpmaObject,
    scheme: Option<TpmtKeyedHashScheme>,
) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(scheme, Tpm2bDigest::default()),
    }
}

/// A KeyedHash signing key template with an HMAC-SHA256 scheme (a signing KeyedHash key
/// cannot be created with a NULL scheme).
pub fn keyed_hash_public(attributes: TpmaObject, unique: &'static [u8]) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attributes,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            Tpm2bDigest::from_bytes(unique).unwrap(),
        ),
    }
}

/// A KeyedHash HMAC-SHA256 key template.
pub fn keyed_hash_template() -> TpmtPublic<'static> {
    child_template(PublicParmsAndId::KeyedHash(
        Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
        Tpm2bDigest::default(),
    ))
}

/// Loads `public` (without a sensitive area) into the NULL hierarchy.
pub fn load_external_public(sim: &mut Tpm, public: TpmtPublic<'static>) -> Handle {
    let rsp = execute_with_password_sessions(
        sim,
        &LoadExternal {
            in_private: None,
            in_public: Tpm2b(public),
            hierarchy: Handle::RH_NULL,
        },
        0,
        &[],
    )
    .unwrap_or_else(|rc| panic!("TPM2_LoadExternal failed: {rc:#x}"));
    rsp.object_handle
}

/// External ECC P-256 public area with point (`x`, `y`) and `attrs | userWithAuth`.
pub fn make_ecc_public_area(x: &[u8], y: &[u8], attrs: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(crate::test_utils::leak_bytes(x)).unwrap(),
                y: Tpm2bEccParameter::from_bytes(crate::test_utils::leak_bytes(y)).unwrap(),
            },
        ),
    }
}

/// External ECC P-256 public area with point (`x`, `y`) and exactly `attrs`.
pub fn make_ecc_public_area_exact_attrs(
    x: &[u8],
    y: &[u8],
    attrs: TpmaObject,
) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(crate::test_utils::leak_bytes(x)).unwrap(),
                y: Tpm2bEccParameter::from_bytes(crate::test_utils::leak_bytes(y)).unwrap(),
            },
        ),
    }
}

/// External keyed-hash public area for `TPM2_LoadExternal` (see
/// [`make_keyed_hash_public_area_with_sensitive`] with sensitive data `b"secrets"`).
pub fn make_keyed_hash_public_area(unique: &[u8], attrs: TpmaObject) -> TpmtPublic<'static> {
    make_keyed_hash_public_area_with_sensitive(unique, attrs, b"secrets")
}

/// External keyed-hash public area; when `unique` is `[0x11; 32]` it is replaced by
/// `H(KEYED_HASH_SEED)` so it matches the sensitive area used by the LoadExternal tests.
pub fn make_keyed_hash_public_area_local(unique: &[u8], attrs: TpmaObject) -> TpmtPublic<'static> {
    let mut actual_unique = unique.to_vec();
    if unique == [0x11; 32] {
        // unique = H(seedValue || data) for the KEYED_HASH_SEED / empty data
        // sensitive used by the LoadExternal tests below.
        let mut hasher = Sha256::new();
        hasher.update(KEYED_HASH_SEED);
        hasher.update([]);
        actual_unique = hasher.finalize().to_vec();
    }
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        // C SchemeChecks (Object_spt.c:437-439): a sign-only keyedhash object
        // needs an HMAC scheme (NULL -> SCHEME).
        parms_and_id: tpm2::PublicParmsAndId::KeyedHash(
            attrs
                .contains(TpmaObject::SIGN_ENCRYPT)
                .then_some(tpm2::TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            Tpm2bDigest::from_bytes(crate::test_utils::leak_bytes(&actual_unique)).unwrap(),
        ),
    }
}

/// External keyed-hash public area with no scheme, the given `unique` and exactly `attrs`.
pub fn make_keyed_hash_public_area_no_scheme(
    unique: &[u8],
    attrs: TpmaObject,
) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            None,
            Tpm2bDigest::from_bytes(crate::test_utils::leak_bytes(unique)).unwrap(),
        ),
    }
}

/// External keyed-hash public area (HMAC scheme for signing keys); `unique` `[0x01; 32]`/`[0x02; 32]`
/// is replaced by the digest matching the obfuscation value and `b"secrets"`.
pub fn make_keyed_hash_public_area_obfuscated(
    unique: &[u8],
    attrs: TpmaObject,
) -> TpmtPublic<'static> {
    let mut actual_unique = unique.to_vec();
    if unique == [0x01; 32] || unique == [0x02; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"obfuscation is my middle name!!!");
        hasher.update(b"secrets");
        actual_unique = hasher.finalize().to_vec();
    }
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        // C SchemeChecks (Object_spt.c:429-439): a sign-only keyedhash object
        // needs an HMAC scheme (NULL -> SCHEME+P2).
        parms_and_id: PublicParmsAndId::KeyedHash(
            (attrs.contains(TpmaObject::SIGN_ENCRYPT) && !attrs.contains(TpmaObject::DECRYPT))
                .then_some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            Tpm2bDigest::from_bytes(crate::test_utils::leak_bytes(&actual_unique)).unwrap(),
        ),
    }
}

/// External keyed-hash public area; `unique == [0x01; 32]` is replaced by
/// `H([0x02; 32] || sensitive_bytes)` so it matches the corresponding sensitive area.
pub fn make_keyed_hash_public_area_with_sensitive(
    unique: &[u8],
    attrs: TpmaObject,
    sensitive_bytes: &[u8],
) -> TpmtPublic<'static> {
    let mut actual_unique = unique.to_vec();
    if unique == [0x01; 32] {
        let mut hasher = Sha256::new();
        hasher.update([0x02; 32]);
        hasher.update(sensitive_bytes);
        actual_unique = hasher.finalize().to_vec();
    }
    // C `SchemeChecks`: a sign-only keyed hash needs an HMAC scheme, a decrypt-only one an XOR
    // scheme, and only sign+decrypt (or neither) keys may have a NULL scheme.
    let sign = attrs.contains(TpmaObject::SIGN_ENCRYPT);
    let decrypt = attrs.contains(TpmaObject::DECRYPT);
    let scheme = match (sign, decrypt) {
        (true, false) => Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
        (false, true) => Some(TpmtKeyedHashScheme::ExclusiveOr(TpmsSchemeXor {
            hash_alg: TpmiAlgHash::Sha256,
            kdf: Some(TpmiAlgKdf::Kdf1Sp800_108),
        })),
        _ => None,
    };
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            scheme,
            Tpm2bDigest::from_bytes(crate::test_utils::leak_bytes(&actual_unique)).unwrap(),
        ),
    }
}

/// External RSA-2048 public area with modulus `n`, `name_alg` and `attrs | userWithAuth`.
pub fn make_rsa_public_area(
    n: &[u8],
    name_alg: TpmiAlgHash,
    attrs: TpmaObject,
) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: attrs | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(crate::test_utils::leak_bytes(n)).unwrap(),
        ),
    }
}

/// External RSA-2048 public area with modulus `n`, `name_alg` and exactly `attrs`.
pub fn make_rsa_public_area_exact_attrs(
    n: &[u8],
    name_alg: TpmiAlgHash,
    attrs: TpmaObject,
) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiCode::from(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(crate::test_utils::leak_bytes(n)).unwrap(),
        ),
    }
}

/// External RSA-2048 public area with modulus `n`, optional `name_alg` (`None` = `TPM_ALG_NULL`)
/// and `attrs | userWithAuth`.
pub fn make_rsa_public_area_opt_name_alg(
    n: &[u8],
    name_alg: Option<TpmiAlgHash>,
    attrs: TpmaObject,
) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg,
        object_attributes: attrs | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(crate::test_utils::leak_bytes(n)).unwrap(),
        ),
    }
}

/// Builds the public area of an NV Index.
pub fn nv_public(
    index: u32,
    attributes: TpmaNv,
    data_size: u16,
    policy: &[u8],
) -> TpmsNvPublic<'static> {
    TpmsNvPublic {
        nv_index: Handle(index),
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::from_bytes(leak_bytes(policy)).unwrap(),
        data_size,
    }
}

/// Reference model of `TPM2_TestParms` validation: returns the error the TPM is expected to report
/// for `parms`, or `Ok(())`.
pub fn oracle_validate_parms(parms: &TpmtPublicParms) -> Result<(), TpmRc> {
    match parms {
        TpmtPublicParms::Rsa(parms) => {
            // `TPMS_RSA_PARMS` unmarshaling order: symmetric, scheme, keyBits, exponent.
            oracle_validate_symmetric(parms.symmetric)?;
            match parms.scheme {
                Some(TpmtRsaScheme::Rsapss(scheme)) => {
                    oracle_validate_hash_alg(scheme)?;
                }
                Some(TpmtRsaScheme::Rsassa(scheme)) => {
                    oracle_validate_hash_alg(scheme)?;
                }
                Some(TpmtRsaScheme::Oaep(scheme)) => {
                    oracle_validate_hash_alg(scheme)?;
                }
                Some(TpmtRsaScheme::Rsaes) | None => {}
            }
            if parms.key_bits.0 != 1024 && parms.key_bits.0 != 2048 {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
            // `exponent` is a plain UINT32: it always unmarshals, and TPM2_TestParms reports only
            // unmarshaling errors (Part 3, TPM2_TestParms).
        }
        TpmtPublicParms::Ecc(parms) => {
            // `TPMS_ECC_PARMS` unmarshaling order: symmetric, scheme, curveID, kdf.
            oracle_validate_symmetric(parms.symmetric)?;
            match parms.scheme {
                Some(TpmtEccScheme::Ecdsa(scheme)) | Some(TpmtEccScheme::Ecdh(scheme)) => {
                    oracle_validate_hash_alg(scheme)?;
                }
                Some(TpmtEccScheme::Ecdaa(scheme)) => {
                    oracle_validate_hash_alg(scheme.hash_alg)?;
                }
                // `TPMI_ALG_ECC_SCHEME` only includes implemented schemes (not SM2, EC-Schnorr,
                // ECMQV, EdDSA).
                Some(_) => {
                    return Err(TpmRc::SCHEME.with(Position::parameter(1)));
                }
                None => {}
            }
            if parms.curve_id != TpmEccCurve::NistP224
                && parms.curve_id != TpmEccCurve::NistP256
                && parms.curve_id != TpmEccCurve::NistP384
                && parms.curve_id != TpmEccCurve::NistP521
                && parms.curve_id != TpmEccCurve::BNP256
            {
                return Err(TpmRc::CURVE.with(Position::parameter(1)));
            }
            if let Some(kdf) = parms.kdf {
                match kdf {
                    TpmtKdfScheme::Kdf1Sp800_56a(scheme) => {
                        oracle_validate_hash_alg(scheme)?;
                    }
                    TpmtKdfScheme::Kdf2(scheme) => {
                        oracle_validate_hash_alg(scheme)?;
                    }
                    TpmtKdfScheme::Kdf1Sp800_108(scheme) => {
                        oracle_validate_hash_alg(scheme)?;
                    }
                    // C TPMI_ALG_KDF_Unmarshal accepts MGF1 (implemented); HKDF is not.
                    TpmtKdfScheme::Mgf1(scheme) => {
                        oracle_validate_hash_alg(scheme)?;
                    }
                    TpmtKdfScheme::Hkdf(_) => {
                        return Err(TpmRc::KDF.with(Position::parameter(1)));
                    }
                }
            }
        }
        TpmtPublicParms::KeyedHash(scheme) => match scheme {
            Some(TpmtKeyedHashScheme::Hmac(h)) => {
                oracle_validate_hash_alg(*h)?;
            }
            Some(TpmtKeyedHashScheme::ExclusiveOr(scheme)) => {
                oracle_validate_hash_alg(scheme.hash_alg)?;
                // C TPMS_SCHEME_XOR_Unmarshal: TPMI_ALG_KDF+ (NULL allowed); HKDF unimplemented.
                if scheme.kdf == Some(TpmiAlgKdf::Hkdf) {
                    return Err(TpmRc::KDF.with(Position::parameter(1)));
                }
            }
            None => {}
        },
        TpmtPublicParms::Sym(sym) => {
            oracle_validate_symmetric(Some(*sym))?;
        }
        TpmtPublicParms::Mldsa(_) | TpmtPublicParms::HashMldsa(_) | TpmtPublicParms::Mlkem(_) => {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }
    }
    Ok(())
}

/// Reference model of the symmetric-definition check in `TPM2_TestParms` (any implemented mode or
/// `TPM_ALG_NULL` is accepted).
pub fn oracle_validate_symmetric(symmetric: Option<TpmtSymDefObject>) -> Result<(), TpmRc> {
    match symmetric {
        Some(TpmtSymDefObject {
            alg: AlgSym::Aes128 | AlgSym::Aes256,
            mode,
        }) => {
            // TPM2_TestParms only unmarshals (C TestParms.c): TPMI_ALG_SYM_MODE+ accepts every
            // implemented mode (CTR, OFB, CBC, CFB, ECB) and TPM_ALG_NULL. The CFB requirement
            // only applies when an object is created (PublicAttributesValidation).
            if !matches!(
                mode,
                None | Some(TpmiAlgSymMode::Cipher(
                    TpmiAlgCipherMode::Ctr
                        | TpmiAlgCipherMode::Ofb
                        | TpmiAlgCipherMode::Cbc
                        | TpmiAlgCipherMode::Cfb
                        | TpmiAlgCipherMode::Ecb
                ))
            ) {
                return Err(TpmRc::MODE.with(Position::parameter(1)));
            }
        }
        None => {}
        // `TPMI_AES_KEY_BITS` only admits implemented key sizes (128, 256): TPM_RC_VALUE.
        #[allow(unreachable_patterns)]
        Some(sym) if sym.algorithm() == tpm2::Alg::AES => {
            return Err(TpmRc::VALUE.with(Position::parameter(1)));
        }
        #[allow(unreachable_patterns)]
        _ => {
            return Err(TpmRc::SYMMETRIC.with(Position::parameter(1)));
        }
    }
    Ok(())
}

/// Runs `TPM2_PolicyTemplate(hash)` on policy `session`, returning the response code on failure.
pub fn policy_template(sim: &mut Tpm, session: Handle, hash: &[u8]) -> Result<(), u32> {
    run_command(
        sim,
        PolicyTemplate {
            policy_session: session,
            template_hash: to_digest(hash),
        },
    )
    .map(|_| ())
}

/// Creates a primary key from the fixed ECC EK template under `hierarchy`, returns its
/// marshaled public area and flushes it. The public key is derived from the hierarchy's
/// primary seed, so it changes exactly when the seed changes.
pub fn primary_public(sim: &mut Tpm, hierarchy: Handle) -> Vec<u8> {
    let cmd = CreatePrimary {
        primary_handle: hierarchy,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(ecc_ek_template()),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let rsp = execute_with_password_sessions(sim, &cmd, 1, &[])
        .unwrap_or_else(|rc| panic!("CreatePrimary failed: {rc:#x}"));
    flush_context(sim, rsp.object_handle).unwrap();
    marshal_to_vec(&rsp.out_public)
}

/// `TPM2_ReadPublic`.
pub fn read_public(sim: &mut Tpm, handle: Handle) -> Result<responses::ReadPublic<'static>, u32> {
    run(
        sim,
        &ReadPublic {
            object_handle: handle,
        },
        0,
    )
}

/// RSA decryption key template of `bits` bits with no scheme or symmetric algorithm.
pub fn rsa_decrypt_public(bits: u16) -> TpmtPublic<'static> {
    let rsa_parms = TpmsRsaParms {
        symmetric: None,
        scheme: None,
        key_bits: TpmiRsaKeyBits(bits),
        exponent: 0,
    };

    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, Tpm2bPublicKeyRsa::default()),
    }
}

/// Template for an RSA-2048 decrypt-only key (`sign` clear), i.e. not a signing object.
pub fn rsa_decrypt_template() -> TpmtPublic<'static> {
    let mut public = rsa_sign_template(None);
    public.object_attributes = TpmaObject::DECRYPT
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::SENSITIVE_DATA_ORIGIN
        | TpmaObject::FIXED_PARENT
        | TpmaObject::FIXED_TPM;
    public
}

/// RSA-2048 restricted decryption (storage) parent template.
pub fn rsa_parent_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM
            | TpmaObject::SENSITIVE_DATA_ORIGIN,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: Some(TpmtSymDefObject::aes_cfb(128).unwrap()),
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    }
}

/// `TPMT_PUBLIC_PARMS` of an RSA key without symmetric/scheme and `key_bits`.
pub fn rsa_parms(symmetric: &[u8], key_bits: u16) -> Vec<u8> {
    let mut v = 0x0001u16.to_be_bytes().to_vec();
    v.extend_from_slice(symmetric);
    v.extend_from_slice(&0x0010u16.to_be_bytes()); // scheme NULL
    v.extend_from_slice(&key_bits.to_be_bytes());
    v.extend_from_slice(&0u32.to_be_bytes());
    v
}

/// Public area of an RSA-2048 key without a scheme.
pub fn rsa_public(
    name_alg: TpmiAlgHash,
    attrs: TpmaObject,
    policy: &'static [u8],
    symmetric: Option<TpmtSymDefObject>,
) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::from_bytes(policy).unwrap(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    }
}

/// RSA restricted decryption (storage) key template of `bits` bits with AES-128-CFB.
pub fn rsa_public_bits(bits: u16) -> TpmtPublic<'static> {
    let rsa_parms = TpmsRsaParms {
        symmetric: Some(TpmtSymDefObject::aes_cfb(128).unwrap()),
        scheme: None,
        key_bits: TpmiRsaKeyBits(bits),
        exponent: 0,
    };

    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, Tpm2bPublicKeyRsa::default()),
    }
}

/// An unrestricted/restricted 2048-bit RSA key template.
pub fn rsa_public_with_symmetric(
    attributes: TpmaObject,
    symmetric: Option<TpmtSymDefObject>,
) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attributes,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    }
}

/// Template for an RSA-2048 signing key with the given default scheme.
pub fn rsa_sign_template(scheme: Option<TpmtRsaScheme>) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    }
}

/// An RSA-2048 RSASSA-SHA256 signing key template.
pub fn rsa_signing_template() -> TpmtPublic<'static> {
    child_template(PublicParmsAndId::Rsa(
        TpmsRsaParms {
            symmetric: None,
            scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
            key_bits: TpmiRsaKeyBits(2048),
            exponent: 0,
        },
        Tpm2bPublicKeyRsa::default(),
    ))
}

/// An RSA-2048 RSASSA-SHA256 signing key template with `extra` attributes.
pub fn rsa_signing_template_with(extra: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: base_attributes() | TpmaObject::SIGN_ENCRYPT | extra,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    }
}

/// RSA-2048 restricted decryption (storage) primary template.
pub fn rsa_storage_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Default::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            tpm2::TpmsRsaParms {
                symmetric: Some(TpmtSymDefObject::aes_cfb(128).unwrap()),
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0x00010001,
            },
            tpm2::Tpm2bPublicKeyRsa::default(),
        ),
    }
}

/// RSA-2048 storage key template (restricted decrypt, AES-128-CFB).
pub fn rsa_storage_template_with(name_alg: TpmiAlgHash, attrs: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: attrs
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: Some(TpmtSymDefObject::aes_cfb(128).unwrap()),
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    }
}

/// An RSA-2048 key template with the given extra attributes and scheme.
pub fn rsa_template(attributes: TpmaObject, scheme: Option<TpmtRsaScheme>) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: base_attributes() | attributes,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    }
}

/// An RSA-2048 key template.
pub fn rsa_template_with_symmetric(
    attrs: TpmaObject,
    scheme: Option<TpmtRsaScheme>,
    symmetric: Option<TpmtSymDefObject>,
) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric,
                scheme,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    }
}

/// An unrestricted RSASSA-SHA256 signing key template.
pub fn rsassa_signer_template() -> TpmtPublic<'static> {
    rsa_template(
        TpmaObject::SIGN_ENCRYPT,
        Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
    )
}

/// Sealed data object template (KEYEDHASH, sign = decrypt = CLEAR, NULL scheme).
pub fn sealed_template(name_alg: TpmiAlgHash, attrs: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: attrs | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
    }
}

/// Template for a keyedhash sealed-data object.
pub fn sealed_template_with_policy(attrs: TpmaObject, auth_policy: &[u8]) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs | TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT,
        auth_policy: Tpm2bDigest::from_bytes(leak_bytes(auth_policy)).unwrap(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
    }
}

/// Owned copy of a public area (so that tests can keep it beyond a response buffer).
pub fn sensitive_create(auth: &[u8], data: &[u8]) -> Tpm2bSensitiveCreate<'static> {
    Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(leak_bytes(auth)).unwrap(),
        data: Tpm2bSensitiveData::from_bytes(leak_bytes(data)).unwrap(),
    })
}

/// An AES-128-CFB symmetric cipher key template.
pub fn sym_template(attrs: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject::aes_cfb(128).unwrap(),
            Tpm2bDigest::default(),
        ),
    }
}

/// SYMCIPHER AES-128-CFB decryption key template.
pub fn sym_template_with(name_alg: TpmiAlgHash, attrs: TpmaObject) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: attrs
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject::aes_cfb(128).unwrap(),
            Tpm2bDigest::default(),
        ),
    }
}

/// `TPMT_PUBLIC_PARMS` of a SYMCIPHER AES-128 key with `mode`.
pub fn symcipher_parms(mode: u16) -> Vec<u8> {
    let mut v = 0x0025u16.to_be_bytes().to_vec();
    v.extend_from_slice(&0x0006u16.to_be_bytes());
    v.extend_from_slice(&128u16.to_be_bytes());
    v.extend_from_slice(&mode.to_be_bytes());
    v
}

/// Creates an EK from `ek_template`, checks that its auth policy (via
/// ReadPublic) and the TPM-computed PolicySecret(RH_ENDORSEMENT) digest
/// (via PolicyGetDigest) match the template, then creates a sealed blob under
/// the EK using that policy session.
///
/// (Formerly an unused helper in `go/ek.rs`; it has no Go counterpart.)
pub fn test_ek_policy_with_template(ek_template: TpmtPublic) {
    let mut sim = Tpm::new();

    let in_public = tpm2::Tpm2b(ek_template);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);
    let create_primary_cmd = CreatePrimary {
        primary_handle: Handle::RH_ENDORSEMENT,
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };
    let create_primary_resp =
        execute_with_password_sessions(&mut sim, &create_primary_cmd, 1, &[]).unwrap();

    let ek_handle = create_primary_resp.object_handle;
    let ek_name = create_primary_resp.name;

    let read_pub_cmd = ReadPublic {
        object_handle: ek_handle,
    };
    let read_pub_resp = execute_with_password_sessions(&mut sim, &read_pub_cmd, 0, &[]).unwrap();
    assert_eq!(
        read_pub_resp.out_public.0.auth_policy,
        ek_template.auth_policy
    );

    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::Policy,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let policy_secret_cmd = PolicySecret {
        auth_handle: Handle::RH_ENDORSEMENT,
        policy_session: session.session_handle,
        nonce_tpm: session.nonce_tpm,
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: 0,
    };
    let _ = execute_with_password_sessions(&mut sim, &policy_secret_cmd, 1, &[]).unwrap();

    let get_digest_cmd = PolicyGetDigest {
        policy_session: session.session_handle,
    };
    let get_digest_rsp = execute_with_password_sessions(&mut sim, &get_digest_cmd, 0, &[]).unwrap();
    assert_eq!(
        get_digest_rsp.policy_digest.get_buffer(),
        ek_template.auth_policy.get_buffer()
    );

    let create_cmd = Create {
        parent_handle: ek_handle,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::from_bytes(b"secrets").unwrap(),
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
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };

    let mut sessions = [session];
    let _ = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        &[ek_name.get_buffer()],
        &mut sessions,
        &[&[]],
    )
    .unwrap();

    flush_context(&mut sim, ek_handle).unwrap();
}

/// Sends `TPM2_TestParms` with the raw `TPMT_PUBLIC_PARMS` bytes.
pub fn test_parms(sim: &mut Tpm, parms: &[u8]) -> u32 {
    let cmd = build_raw_cmd(ST_NO_SESSIONS, CC_TEST_PARMS, &[], None, parms);
    mssim_rc_of(sim, &cmd)
}

// ===========================================================================
// Object lifecycle
//
// Creating, loading, importing, duplicating, evicting, saving/loading contexts and flushing objects.
// ===========================================================================

// Software helper implementation for parent keys
/// Public part of a parent key used client-side to encapsulate a duplication seed (ECDH for ECC,
/// OAEP for RSA), together with its name and symmetric algorithms.
pub enum EncapsulationKey {
    Ecc {
        pub_x: Vec<u8>,
        pub_y: Vec<u8>,
        name_alg: TpmiAlgHash,
        sym_def: Option<TpmtSymDefObject>,
    },
    Rsa {
        pub_key: rsa::RsaPublicKey,
        hash_alg: TpmiAlgHash,
        name_alg: TpmiAlgHash,
        sym_def: Option<TpmtSymDefObject>,
    },
}

/// Asserts that a context with `blob` is rejected with `expected`, and that
/// the TPM keeps working afterwards (the untouched `context` still loads).
pub fn assert_load_rejected(
    sim: &mut Tpm,
    context: TpmsContext<'static>,
    blob: Vec<u8>,
    expected: u32,
    what: &str,
) {
    assert_eq!(
        load_context(sim, with_blob(context, blob)),
        Err(expected),
        "{what}: unexpected ContextLoad result"
    );
    let handle = load_context(sim, context).expect("untouched context must still load");
    flush_handle(sim, handle);
}

/// Computes an object's Name (`nameAlg || H(TPMT_PUBLIC)`) client-side.
pub fn compute_object_name(public: &TpmtPublic) -> Tpm2bName<'static> {
    let mut pub_buf = vec![0u8; 4096];
    let pub_len = marshal_to_slice(public, &mut pub_buf);
    pub_buf.truncate(pub_len);

    let digest_bytes = match public.name_alg {
        Some(TpmiAlgHash::Sha256) => {
            let mut hasher = Sha256::new();
            hasher.update(&pub_buf);
            hasher.finalize().to_vec()
        }
        Some(TpmiAlgHash::Sha1) => {
            let mut hasher = Sha1::new();
            hasher.update(&pub_buf);
            hasher.finalize().to_vec()
        }
        _ => panic!("Unsupported name_alg for hashing public area"),
    };

    let mut name_bytes = vec![0u8; 2 + digest_bytes.len()];
    name_bytes[0..2].copy_from_slice(&Alg::from(public.name_alg.unwrap()).id().to_be_bytes());
    name_bytes[2..].copy_from_slice(&digest_bytes);
    Tpm2bName::from_bytes(crate::test_utils::leak_bytes(&name_bytes)).unwrap()
}

/// Loads `context` with `TPM2_ContextLoad` and returns the loaded handle or the response code.
pub fn context_load(sim: &mut Tpm, context: TpmsContext<'static>) -> Result<Handle, u32> {
    execute_with_password_sessions(sim, &ContextLoad { context }, 0, &[])
        .map(|rsp| rsp.loaded_handle)
}

/// `TPM2_ContextLoad(context)`; returns the loaded handle on success.
pub fn context_load_raw(sim: &mut Tpm, context: &[u8]) -> Result<u32, u32> {
    let cmd = build_raw_cmd(ST_NO_SESSIONS, CC_CONTEXT_LOAD, &[], None, context);
    let (rc, resp) = send_with_rc(sim, &cmd);
    if rc != 0 {
        return Err(rc);
    }
    Ok(u32::from_be_bytes(resp[10..14].try_into().unwrap()))
}

/// Saves the context of `handle` with `TPM2_ContextSave`.
pub fn context_save(sim: &mut Tpm, handle: Handle) -> TpmsContext<'static> {
    let cmd = ContextSave {
        save_handle: handle,
    };
    let rsp = execute_with_password_sessions(sim, &cmd, 0, &[])
        .unwrap_or_else(|rc| panic!("ContextSave failed: {rc:#x}"));
    rsp.context
}

/// `TPM2_ContextSave(handle)`; returns the marshaled `TPMS_CONTEXT` on success.
pub fn context_save_raw(sim: &mut Tpm, handle: u32) -> Result<Vec<u8>, u32> {
    let cmd = build_raw_cmd(ST_NO_SESSIONS, CC_CONTEXT_SAVE, &[handle], None, &[]);
    let (rc, resp) = send_with_rc(sim, &cmd);
    if rc != 0 {
        return Err(rc);
    }
    Ok(resp[10..].to_vec())
}

/// Returns the `sequence` of a marshaled `TPMS_CONTEXT`.
pub fn context_sequence(context: &[u8]) -> u64 {
    u64::from_be_bytes(context[0..8].try_into().unwrap())
}

/// `TPM2_Create` under `parent`.
pub fn create(
    sim: &mut Tpm,
    parent: Handle,
    template: TpmtPublic<'static>,
    auth: &[u8],
    data: &[u8],
) -> Result<responses::Create<'static>, u32> {
    let cmd = Create {
        parent_handle: parent,
        in_sensitive: sensitive_create(auth, data),
        in_public: Tpm2b(template),
        ..Default::default()
    };
    run(sim, &cmd, 1)
}

/// Creates and loads a child of `parent`; returns (handle, create response).
pub fn create_and_load(
    sim: &mut Tpm,
    parent: Handle,
    template: TpmtPublic<'static>,
    auth: &[u8],
    data: &[u8],
) -> (Handle, responses::Create<'static>) {
    let rsp = create(sim, parent, template, auth, data).expect("Create");
    let handle = load(sim, parent, rsp.out_private, rsp.out_public).expect("Load");
    (handle, rsp)
}

/// Creates and loads a child of `parent` from `template` with authValue `auth`.
pub fn create_and_load_child(
    sim: &mut Tpm,
    parent: Handle,
    template: TpmtPublic<'static>,
    auth: &[u8],
) -> Handle {
    let (private, public) = create_child(sim, parent, template, auth);
    load_child(sim, parent, private, public).0
}

/// Creates a child of `parent` from `template` with authValue `auth`; returns its private
/// and public areas.
pub fn create_child(
    sim: &mut Tpm,
    parent: Handle,
    template: TpmtPublic<'static>,
    auth: &[u8],
) -> (Tpm2bPrivate<'static>, Tpm2bPublic<'static>) {
    let cmd = Create {
        parent_handle: parent,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(auth).unwrap(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(template),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let rsp = execute_tpm_command(sim, &cmd, &[password_auth(b"")])
        .unwrap_or_else(|rc| panic!("Create failed: {rc:#x}"));
    (rsp.out_private, rsp.out_public)
}

/// Creates a DA-protected (noDA CLEAR) sealed data object with authValue [`OBJECT_AUTH`].
pub fn create_da_protected_object(sim: &mut Tpm) -> Handle {
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::USER_WITH_AUTH
            | TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
    };
    let rsp = execute_with_password_sessions(
        sim,
        &CreatePrimary {
            primary_handle: Handle::RH_OWNER,
            in_sensitive: Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::from_bytes(OBJECT_AUTH).unwrap(),
                data: Tpm2bSensitiveData::from_bytes(b"sealed").unwrap(),
            }),
            in_public: Tpm2b(public),
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        },
        1,
        &[],
    )
    .unwrap_or_else(|rc| panic!("TPM2_CreatePrimary failed: {rc:#x}"));
    rsp.object_handle
}

/// Creates and loads a duplicable RSA signing key (SHA-256) under `parent`; returns its handle
/// and public area.
pub fn create_dup_target(sim: &mut Tpm, parent: Handle) -> (Handle, Tpm2bPublic<'static>) {
    let public = rsa_public(
        TpmiAlgHash::Sha256,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH | TpmaObject::SENSITIVE_DATA_ORIGIN,
        dup_policy_sha256(),
        None,
    );
    let created = exec_command(
        sim,
        &Create {
            parent_handle: parent,
            in_sensitive: Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::default(),
                data: Tpm2bSensitiveData::default(),
            }),
            in_public: Tpm2b(public),
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        },
        &[pw()],
    )
    .expect("Create failed");
    let loaded = exec_command(
        sim,
        &Load {
            parent_handle: parent,
            in_private: created.out_private,
            in_public: created.out_public,
        },
        &[pw()],
    )
    .expect("Load failed");
    (loaded.object_handle, created.out_public)
}

// Derives a symmetric key and encrypts/HMACs sensitive data to create the duplicate blob.
/// Creates a duplication blob client-side for `TPM2_Import`: encapsulates a fresh seed to `key`,
/// then protects `sensitive` (outer integrity HMAC + CFB encryption bound to `name`). Returns
/// `(duplicate, encrypted seed)`.
pub fn create_duplicate(
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
    key: &EncapsulationKey,
    name: &[u8],
    sensitive: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let crypto = PlatformCryptoProvider;

    // 1. Labeled Key Encapsulation (Encapsulate)
    let (secret, ciphertext) = match key {
        EncapsulationKey::Ecc { pub_x, pub_y, .. } => {
            // Generate ephemeral ECC key pair
            let eph_private = p256::SecretKey::random(rng);
            let eph_public = eph_private.public_key();
            let eph_point = eph_public.to_encoded_point(false);
            let eph_x = eph_point.x().unwrap().to_vec();
            let eph_y = eph_point.y().unwrap().to_vec();

            // Perform ECDH key exchange
            let parent_pub_point =
                p256::PublicKey::from_encoded_point(&p256::EncodedPoint::from_affine_coordinates(
                    pub_x.as_slice().into(),
                    pub_y.as_slice().into(),
                    false,
                ))
                .expect("Failed to parse parent ECC public key");
            let shared_secret = p256::ecdh::diffie_hellman(
                eph_private.to_nonzero_scalar(),
                parent_pub_point.as_affine(),
            );
            let z = shared_secret.raw_secret_bytes();

            // KDFe derivation
            let mut secret_derived = [0u8; 32];
            tpm2::crypto::kdf::kdfe_bits(
                &crypto,
                TpmiAlgHash::Sha256,
                z.as_slice(),
                b"DUPLICATE",
                &eph_x,
                pub_x,
                256,
                &mut secret_derived,
            )
            .unwrap();

            let ciphertext_point = TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(&eph_x).unwrap(),
                y: Tpm2bEccParameter::from_bytes(&eph_y).unwrap(),
            };
            let mut cipher_bytes = vec![0u8; 1024];
            let cipher_len = marshal_to_slice(&ciphertext_point, &mut cipher_bytes);
            cipher_bytes.truncate(cipher_len);

            (secret_derived.to_vec(), cipher_bytes)
        }
        EncapsulationKey::Rsa {
            pub_key, hash_alg, ..
        } => {
            let digest_size = match *hash_alg {
                TpmiAlgHash::Sha256 => 32,
                TpmiAlgHash::Sha1 => 20,
                _ => panic!("Unsupported hash alg for RSA-OAEP"),
            };
            let mut secret = vec![0u8; digest_size];
            rng.fill_bytes(&mut secret);

            // OAEP Label is "DUPLICATE\0"
            let label = "DUPLICATE\0";

            let enc_secret = match *hash_alg {
                TpmiAlgHash::Sha256 => pub_key
                    .encrypt(rng, rsa::Oaep::new_with_label::<Sha256, _>(label), &secret)
                    .expect("RSA-OAEP encryption failed"),
                TpmiAlgHash::Sha1 => pub_key
                    .encrypt(rng, rsa::Oaep::new_with_label::<Sha1, _>(label), &secret)
                    .expect("RSA-OAEP encryption failed"),
                _ => panic!("Unsupported hash alg"),
            };

            (secret, enc_secret)
        }
    };

    // 2. Symmetric parameter evaluation
    let (sym_alg, sym_key_bits, sym_mode) = match key {
        EncapsulationKey::Ecc { sym_def, .. } | EncapsulationKey::Rsa { sym_def, .. } => {
            match sym_def {
                Some(TpmtSymDefObject {
                    alg: AlgSym::Aes128,
                    mode,
                }) => (Alg::AES, 128, *mode),
                Some(TpmtSymDefObject {
                    alg: AlgSym::Aes256,
                    mode,
                }) => (Alg::AES, 256, *mode),
                _ => panic!("Unsupported symmetric algorithm"),
            }
        }
    };
    assert_eq!(sym_alg, Alg::AES);
    assert_eq!(
        sym_mode.unwrap(),
        TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)
    );

    // 3. Marshal sensitive structure to TPM2B_SENSITIVE (2B wrapper)
    let mut sensitive_2b = vec![0u8; 2 + sensitive.len()];
    sensitive_2b[0..2].copy_from_slice(&(sensitive.len() as u16).to_be_bytes());
    sensitive_2b[2..].copy_from_slice(sensitive);

    // 4. Derive AES CFB key using KDFa
    let mut derived_aes_key = vec![0u8; (sym_key_bits / 8) as usize];
    kdfa_bits(
        &crypto,
        TpmiAlgHash::Sha256,
        &secret,
        b"STORAGE",
        name,
        &[],
        (sym_key_bits) as u32,
        &mut derived_aes_key,
    )
    .unwrap();

    // 5. Encrypt sensitive data using AES-CFB
    use aes::cipher::{AsyncStreamCipher, KeyIvInit};
    type Aes128Cfb8 = cfb_mode::Encryptor<aes::Aes128>;
    type Aes256Cfb8 = cfb_mode::Encryptor<aes::Aes256>;

    let mut dup_sensitive = sensitive_2b.clone();
    let iv = vec![0u8; 16];
    if sym_key_bits == 128 {
        let cipher = Aes128Cfb8::new_from_slices(&derived_aes_key, &iv).unwrap();
        cipher.encrypt(&mut dup_sensitive);
    } else if sym_key_bits == 256 {
        let cipher = Aes256Cfb8::new_from_slices(&derived_aes_key, &iv).unwrap();
        cipher.encrypt(&mut dup_sensitive);
    } else {
        panic!("Unsupported AES key size");
    }

    // 6. Compute HMAC of (dupSensitive || name)
    let mut hmac_key = vec![0u8; 32];
    kdfa_bits(
        &crypto,
        TpmiAlgHash::Sha256,
        &secret,
        b"INTEGRITY",
        &[],
        &[],
        256,
        &mut hmac_key,
    )
    .unwrap();

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&hmac_key).unwrap();
    mac.update(&dup_sensitive);
    mac.update(name);
    let outer_hmac = mac.finalize().into_bytes().to_vec();

    // 7. Marshal virtual _PRIVATE (2B size prefix of HMAC + HMAC + dup_sensitive)
    let mut duplicate = vec![0u8; 2 + outer_hmac.len() + dup_sensitive.len()];
    duplicate[0..2].copy_from_slice(&(outer_hmac.len() as u16).to_be_bytes());
    duplicate[2..2 + outer_hmac.len()].copy_from_slice(&outer_hmac);
    duplicate[2 + outer_hmac.len()..].copy_from_slice(&dup_sensitive);

    (duplicate, ciphertext)
}

/// Like [`create_duplicate`] but with knobs to produce malformed blobs (inner wrapper, explicit
/// inner key, tampering) for negative `TPM2_Import` tests.
#[allow(clippy::too_many_arguments)]
pub fn create_duplicate_challenged(
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
    key: &EncapsulationKey,
    name: &[u8],
    sensitive: &[u8],
    inner_sym_def: Option<TpmtSymDefObject>,
    explicit_inner_key: Option<&[u8]>,
    tamper_outer_hmac: bool,
    tamper_ciphertext: bool,
    tamper_seed: bool,
    wrong_name: Option<&[u8]>,
    tamper_inner_hmac: bool,
) -> (Vec<u8>, Vec<u8>) {
    let crypto = PlatformCryptoProvider;

    // 1. Labeled Key Encapsulation (Encapsulate)
    let (secret, mut ciphertext) = match key {
        EncapsulationKey::Ecc { pub_x, pub_y, .. } => {
            // Ephemeral ECC key pair
            let eph_private = p256::SecretKey::random(rng);
            let eph_public = eph_private.public_key();
            let eph_point = eph_public.to_encoded_point(false);
            let eph_x = eph_point.x().unwrap().to_vec();
            let eph_y = eph_point.y().unwrap().to_vec();

            // ECDH
            let parent_pub_point =
                p256::PublicKey::from_encoded_point(&p256::EncodedPoint::from_affine_coordinates(
                    pub_x.as_slice().into(),
                    pub_y.as_slice().into(),
                    false,
                ))
                .expect("Failed to parse parent ECC public key");
            let shared_secret = p256::ecdh::diffie_hellman(
                eph_private.to_nonzero_scalar(),
                parent_pub_point.as_affine(),
            );
            let z = shared_secret.raw_secret_bytes();

            // KDFe
            let mut secret_derived = [0u8; 32];
            tpm2::crypto::kdf::kdfe_bits(
                &crypto,
                TpmiAlgHash::Sha256,
                z.as_slice(),
                b"DUPLICATE",
                &eph_x,
                pub_x,
                256,
                &mut secret_derived,
            )
            .unwrap();

            let ciphertext_point = TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(&eph_x).unwrap(),
                y: Tpm2bEccParameter::from_bytes(&eph_y).unwrap(),
            };
            let mut cipher_bytes = vec![0u8; 1024];
            let cipher_len = marshal_to_slice(&ciphertext_point, &mut cipher_bytes);
            cipher_bytes.truncate(cipher_len);

            (secret_derived.to_vec(), cipher_bytes)
        }
        EncapsulationKey::Rsa {
            pub_key, hash_alg, ..
        } => {
            let digest_size = match *hash_alg {
                TpmiAlgHash::Sha256 => 32,
                TpmiAlgHash::Sha1 => 20,
                _ => panic!("Unsupported hash alg"),
            };
            let mut secret = vec![0u8; digest_size];
            rng.fill_bytes(&mut secret);

            let label = "DUPLICATE\0";
            let enc_secret = match *hash_alg {
                TpmiAlgHash::Sha256 => pub_key
                    .encrypt(rng, rsa::Oaep::new_with_label::<Sha256, _>(label), &secret)
                    .expect("RSA-OAEP encryption failed"),
                TpmiAlgHash::Sha1 => pub_key
                    .encrypt(rng, rsa::Oaep::new_with_label::<Sha1, _>(label), &secret)
                    .expect("RSA-OAEP encryption failed"),
                _ => panic!("Unsupported hash alg"),
            };

            (secret, enc_secret)
        }
    };

    if tamper_seed && !ciphertext.is_empty() {
        ciphertext[0] ^= 1;
    }

    // Outer symmetric param evaluation
    let (outer_sym_alg, outer_sym_key_bits, outer_sym_mode) = match key {
        EncapsulationKey::Ecc { sym_def, .. } | EncapsulationKey::Rsa { sym_def, .. } => {
            match sym_def {
                Some(TpmtSymDefObject {
                    alg: AlgSym::Aes128,
                    mode,
                }) => (Alg::AES, 128, *mode),
                Some(TpmtSymDefObject {
                    alg: AlgSym::Aes256,
                    mode,
                }) => (Alg::AES, 256, *mode),
                _ => panic!("Unsupported symmetric algorithm"),
            }
        }
    };
    assert_eq!(outer_sym_alg, Alg::AES);
    assert_eq!(
        outer_sym_mode.unwrap(),
        TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)
    );

    // Inner wrapper symmetric key
    let mut inner_key = [0u8; 32];
    let mut inner_key_len = 0;
    let has_inner = inner_sym_def.is_some();
    if has_inner {
        inner_key_len = match inner_sym_def {
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes128,
                ..
            }) => 16,
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes256,
                ..
            }) => 32,
            _ => panic!("Unsupported inner sym alg"),
        };
        if let Some(k) = explicit_inner_key {
            inner_key[..inner_key_len].copy_from_slice(k);
        } else {
            // Derive inner symmetric wrapper key from the decrypted seed
            kdfa_bits(
                &crypto,
                TpmiAlgHash::Sha256,
                &secret,
                b"STORAGE",
                name,
                &[],
                (inner_key_len * 8) as u32,
                &mut inner_key[..inner_key_len],
            )
            .unwrap();
        }
    }

    // Marshal sensitive structure
    let mut inner_blob_plaintext = Vec::new();
    if has_inner {
        let mut sens_buf = vec![0u8; 2 + sensitive.len()];
        sens_buf[0..2].copy_from_slice(&(sensitive.len() as u16).to_be_bytes());
        sens_buf[2..].copy_from_slice(sensitive);

        // Compute inner integrity hash (plain hash per TPM 2.0 Spec Part 1 Section 23.3.1)
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(&sens_buf);
        hasher.update(name);
        let mut inner_hmac = hasher.finalize().to_vec();

        if tamper_inner_hmac {
            inner_hmac[0] ^= 1;
        }

        inner_blob_plaintext.extend_from_slice(&(inner_hmac.len() as u16).to_be_bytes());
        inner_blob_plaintext.extend_from_slice(&inner_hmac);
        inner_blob_plaintext.extend_from_slice(&sens_buf);

        // Encrypt inner blob using AES-CFB
        use aes::cipher::{AsyncStreamCipher, KeyIvInit};
        type Aes128Cfb8 = cfb_mode::Encryptor<aes::Aes128>;
        type Aes256Cfb8 = cfb_mode::Encryptor<aes::Aes256>;

        let iv = vec![0u8; 16];
        if inner_key_len == 16 {
            let cipher = Aes128Cfb8::new_from_slices(&inner_key[..inner_key_len], &iv).unwrap();
            cipher.encrypt(&mut inner_blob_plaintext);
        } else if inner_key_len == 32 {
            let cipher = Aes256Cfb8::new_from_slices(&inner_key[..inner_key_len], &iv).unwrap();
            cipher.encrypt(&mut inner_blob_plaintext);
        } else {
            panic!("Unsupported AES key size");
        }
    } else {
        inner_blob_plaintext.extend_from_slice(&(sensitive.len() as u16).to_be_bytes());
        inner_blob_plaintext.extend_from_slice(sensitive);
    }

    // Derive outer AES CFB key using KDFa
    let mut derived_outer_aes_key = vec![0u8; (outer_sym_key_bits / 8) as usize];
    kdfa_bits(
        &crypto,
        TpmiAlgHash::Sha256,
        &secret,
        b"STORAGE",
        name,
        &[],
        (outer_sym_key_bits) as u32,
        &mut derived_outer_aes_key,
    )
    .unwrap();

    // Encrypt inner_blob_plaintext using outer AES-CFB
    use aes::cipher::{AsyncStreamCipher, KeyIvInit};
    type Aes128Cfb8 = cfb_mode::Encryptor<aes::Aes128>;
    type Aes256Cfb8 = cfb_mode::Encryptor<aes::Aes256>;

    let mut dup_sensitive = inner_blob_plaintext.clone();
    let iv = vec![0u8; 16];
    if outer_sym_key_bits == 128 {
        let cipher = Aes128Cfb8::new_from_slices(&derived_outer_aes_key, &iv).unwrap();
        cipher.encrypt(&mut dup_sensitive);
    } else if outer_sym_key_bits == 256 {
        let cipher = Aes256Cfb8::new_from_slices(&derived_outer_aes_key, &iv).unwrap();
        cipher.encrypt(&mut dup_sensitive);
    } else {
        panic!("Unsupported AES key size");
    }
    // Compute outer HMAC of (dupSensitive || name)
    let hmac_name = wrong_name.unwrap_or(name);
    let mut hmac_key = vec![0u8; 32];
    kdfa_bits(
        &crypto,
        TpmiAlgHash::Sha256,
        &secret,
        b"INTEGRITY",
        &[],
        &[],
        256,
        &mut hmac_key,
    )
    .unwrap();

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&hmac_key).unwrap();
    mac.update(&dup_sensitive);
    mac.update(hmac_name);
    let mut outer_hmac = mac.finalize().into_bytes().to_vec();

    if tamper_ciphertext {
        dup_sensitive[0] ^= 1;
    }

    if tamper_outer_hmac {
        outer_hmac[0] ^= 1;
    }

    // Marshal virtual _PRIVATE (2B size prefix of HMAC + HMAC + dup_sensitive)
    let mut duplicate = vec![0u8; 2 + outer_hmac.len() + dup_sensitive.len()];
    duplicate[0..2].copy_from_slice(&(outer_hmac.len() as u16).to_be_bytes());
    duplicate[2..2 + outer_hmac.len()].copy_from_slice(&outer_hmac);
    duplicate[2 + outer_hmac.len()..].copy_from_slice(&dup_sensitive);

    (duplicate, ciphertext)
}

/// Creates a NIST P-256 signing key.
pub fn create_ecc_key(sim: &mut Tpm) -> (Handle, Tpm2bName<'static>) {
    create_signing_key_with_parms(
        sim,
        PublicParmsAndId::Ecc(
            tpm2::TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint::default(),
        ),
    )
}

/// Creates a primary from [`get_ecc_decrypt_parent_template`] under the owner hierarchy and
/// returns its handle; panics on failure.
#[allow(deprecated)] // TPM2_CreateLoaded is deprecated upstream, but the TPM implements it.
pub fn create_ecc_parent_key(sim: &mut Tpm) -> Handle {
    let t_sens = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(t_sens);
    let pub_area = get_ecc_decrypt_parent_template();
    let in_public_template = crate::test_utils::make_template(&pub_area);

    let load_cmd = CreateLoaded {
        parent_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public: in_public_template,
    };
    let rsp = execute_with_password_sessions(sim, &load_cmd, 1, &[]).unwrap();
    rsp.object_handle
}

/// Creates a primary object from `template` under the owner hierarchy and returns its handle.
pub fn create_owner_primary(sim: &mut Tpm, template: TpmtPublic<'static>) -> Handle {
    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(template),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let primary_resp =
        execute_tpm_command_uncorrupted(sim, &create_cmd, &[empty_password_auth()]).unwrap();
    primary_resp.object_handle
}

/// Creates the RSA storage parent under the owner hierarchy and returns its handle.
pub fn create_parent(sim: &mut Tpm) -> Handle {
    let cp_cmd = CreatePrimary {
        primary_handle: Handle(0x40000001),
        in_sensitive: empty_sensitive(),
        in_public: tpm2::Tpm2b(rsa_parent_template()),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let cp_resp = execute_tpm_command_offsets(sim, &cp_cmd, &[empty_password_auth()]).unwrap();
    cp_resp.object_handle
}

/// Creates an RSA restricted decryption primary key under the owner hierarchy and returns its
/// handle; panics on failure.
pub fn create_parent_key(sim: &mut Tpm) -> Handle {
    let primary_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: Some(TpmtSymDefObject {
                    alg: AlgSym::Aes128,
                    mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
                }),
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let in_sensitive = tpm2::Tpm2b(tpm2::TpmsSensitiveCreate {
        user_auth: tpm2::Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    });
    let cp_cmd = CreatePrimary {
        primary_handle: Handle(0x40000001), // Owner hierarchy
        in_sensitive,
        in_public: tpm2::Tpm2b(primary_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };
    let resp = execute_with_password_sessions(sim, &cp_cmd, 1, &[]).unwrap();
    resp.object_handle
}

/// Creates a primary key with an empty authValue under the owner hierarchy; returns its handle
/// and Name.
pub fn create_primary(sim: &mut Tpm, public: TpmtPublic<'static>) -> (Handle, Vec<u8>) {
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Default::default(),
        }),
        in_public: tpm2::Tpm2b(public),
        ..Default::default()
    };
    let resp = execute_with_password_sessions(sim, &cmd, 1, &[])
        .unwrap_or_else(|rc| panic!("TPM2_CreatePrimary failed: {rc:#x}"));
    (resp.object_handle, resp.name.get_buffer().to_vec())
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

/// Creates a primary object from `public` (with optional sensitive `data`) in `hierarchy` and
/// returns the full `TPM2_CreatePrimary` response together with the new handle.
pub fn create_primary_full(
    sim: &mut Tpm,
    hierarchy: Handle,
    public: TpmtPublic<'static>,
    data: &'static [u8],
) -> (tpm2::commands::responses::CreatePrimary<'static>, Handle) {
    let cmd = CreatePrimary {
        primary_handle: hierarchy,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::from_bytes(data).unwrap(),
        }),
        in_public: tpm2::Tpm2b(public),
        ..Default::default()
    };
    let rsp = execute_with_password_sessions(sim, &cmd, 1, &[]).expect("CreatePrimary failed");
    let object_handle = rsp.object_handle;
    (rsp, object_handle)
}

/// Creates a primary key from `public` under the owner hierarchy and returns its handle.
pub fn create_primary_handle(sim: &mut Tpm, public: TpmtPublic<'static>) -> Handle {
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(public),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let rsp = execute_with_password_sessions(sim, &cmd, 1, &[])
        .unwrap_or_else(|rc| panic!("CreatePrimary failed: {rc:#x}"));
    rsp.object_handle
}

/// Creates a primary object and returns only its handle.
pub fn create_primary_in(sim: &mut Tpm, hierarchy: Handle, public: TpmtPublic<'static>) -> Handle {
    create_primary_full(sim, hierarchy, public, &[]).1
}

/// Creates an ECDSA P-256 signing primary key under the owner hierarchy and returns its handle;
/// panics on failure.
pub fn create_primary_key(sim: &mut Tpm) -> Handle {
    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            ecc_parms,
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    use tpm2::Tpm2bEccParameter;
    let in_public = tpm2::Tpm2b(pub_area);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_rsp = execute_with_password_sessions(sim, &create_cmd, 1, &[]).unwrap();
    create_rsp.object_handle
}

/// Creates a primary object from `public` in the NULL hierarchy (empty password session).
pub fn create_primary_null(sim: &mut Tpm, public: TpmtPublic<'static>) -> Handle {
    let cmd = tpm2::commands::CreatePrimary {
        primary_handle: Handle::RH_NULL,
        in_sensitive: tpm2::Tpm2b(tpm2::TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(public),
        ..Default::default()
    };
    execute_with_password_sessions(sim, &cmd, 1, &[])
        .expect("CreatePrimary failed")
        .object_handle
}

/// Creates a primary object in the owner hierarchy with authValue `auth` and sensitive `data`.
pub fn create_primary_obj(
    sim: &mut Tpm,
    public: TpmtPublic<'static>,
    auth: &[u8],
    data: &[u8],
) -> u32 {
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(leak_bytes(auth)).unwrap(),
            data: Tpm2bSensitiveData::from_bytes(leak_bytes(data)).unwrap(),
        }),
        in_public: tpm2::Tpm2b(public),
        ..Default::default()
    };
    let rsp = execute_with_password_sessions(sim, &cmd, 1, &[]).expect("CreatePrimary");
    rsp.object_handle.0
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

/// Creates a primary object from `public` under the owner hierarchy (empty auth) and
/// returns its handle.
pub fn create_primary_raw_handle(sim: &mut Tpm, public: TpmtPublic<'static>) -> u32 {
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(public),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    execute_with_password_sessions_status(sim, &cmd, 1, &[])
        .unwrap_or_else(|rc| panic!("CreatePrimary failed: {rc:#x}"))[0]
        .0
}

/// Creates a primary object under `hierarchy` (empty auth); returns its handle.
pub fn create_primary_st_clear(
    sim: &mut Tpm,
    hierarchy: Handle,
    st_clear: bool,
) -> Result<u32, u32> {
    let cmd = CreatePrimary {
        primary_handle: hierarchy,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(get_test_template_st_clear(st_clear)),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    execute_with_password_sessions(sim, &cmd, 1, &[]).map(|h| h.object_handle.0)
}

/// Creates an owner primary from `public` with empty authValue and sensitive `data`, returning its
/// handle and Name; panics on failure.
pub fn create_primary_with_data(
    sim: &mut Tpm,
    public: TpmtPublic<'static>,
    data: &[u8],
) -> (Handle, Vec<u8>) {
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::from_bytes(leak_bytes(data)).unwrap(),
        }),
        in_public: Tpm2b(public),
        ..Default::default()
    };
    let rsp = execute_with_password_sessions(sim, &cmd, 1, &[]).expect("CreatePrimary");
    (rsp.object_handle, rsp.name.get_buffer().to_vec())
}

/// `TPM2_CreatePrimary` under the owner hierarchy with an empty authValue.
pub fn create_primary_with_data_handle(
    sim: &mut Tpm,
    public: TpmtPublic<'static>,
    data: &'static [u8],
) -> Handle {
    let handles = execute_with_password_sessions(
        sim,
        &CreatePrimary {
            primary_handle: Handle::RH_OWNER,
            in_sensitive: Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::default(),
                data: Tpm2bSensitiveData::from_bytes(data).unwrap(),
            }),
            in_public: Tpm2b(public),
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        },
        1,
        &[],
    )
    .unwrap_or_else(|rc| panic!("TPM2_CreatePrimary failed: {rc:#x}"));
    handles.object_handle
}

/// Creates an RSA-2048 signing key.
pub fn create_rsa_key(sim: &mut Tpm) -> (Handle, Tpm2bName<'static>) {
    create_signing_key_with_parms(
        sim,
        PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    )
}

/// Creates an RSA-2048 primary key with `attributes` and `scheme` under the owner hierarchy
/// and returns its handle and RSA modulus.
pub fn create_rsa_primary(
    sim: &mut Tpm,
    attributes: TpmaObject,
    scheme: Option<TpmtRsaScheme>,
) -> (Handle, Vec<u8>) {
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::USER_WITH_AUTH
                | attributes,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme,
                    key_bits: TpmiRsaKeyBits(2048),
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::default(),
            ),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let rsp = execute_with_password_sessions(sim, &cmd, 1, &[])
        .unwrap_or_else(|rc| panic!("CreatePrimary failed: {rc:#x}"));
    let PublicParmsAndId::Rsa(_, modulus) = rsp.out_public.0.parms_and_id else {
        panic!("expected an RSA public area");
    };
    (rsp.object_handle, modulus.get_buffer().to_vec())
}

/// Creates a sealed-data primary object.
pub fn create_sealed(sim: &mut Tpm, attrs: TpmaObject, auth: &[u8], policy: &[u8]) -> u32 {
    create_primary_obj(
        sim,
        sealed_template_with_policy(attrs, policy),
        auth,
        b"sealed secret",
    )
}

/// The SRK used as the parent of created objects: RSA-2048 storage key (SHA-256, AES-128-CFB).
pub fn create_srk(sim: &mut Tpm) -> Handle {
    try_create_owner_primary(
        sim,
        rsa_public(TpmiAlgHash::Sha256, storage_attrs(), &[], Some(AES128_CFB)),
    )
    .expect("CreatePrimary(SRK) failed")
    .0
}

/// Creates an ECC P-256 storage key (restricted decryption key with AES-128-CFB) as a
/// primary object of `hierarchy` and returns its handle.
pub fn create_storage_parent(sim: &mut Tpm, hierarchy: Handle) -> Handle {
    let cmd = CreatePrimary {
        primary_handle: hierarchy,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(TpmtPublic {
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
                    symmetric: Some(TpmtSymDefObject {
                        alg: AlgSym::Aes128,
                        mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
                    }),
                    scheme: None,
                    curve_id: TpmEccCurve::NistP256,
                    kdf: None,
                },
                TpmsEccPoint {
                    x: Tpm2bEccParameter::default(),
                    y: Tpm2bEccParameter::default(),
                },
            ),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let rsp_handles = execute_tpm_command(sim, &cmd, &[password_auth(b"")])
        .unwrap_or_else(|rc| panic!("CreatePrimary failed: {rc:#x}"));
    rsp_handles.object_handle
}

/// `TPM2_CreatePrimary` of an RSA storage key with `name_alg` and AES-128-CFB.
pub fn create_storage_primary(sim: &mut Tpm, name_alg: TpmiAlgHash) -> Handle {
    let public = rsa_public(
        name_alg,
        TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM,
        &[],
        Some(AES128_CFB),
    );
    exec_command(
        sim,
        &CreatePrimary {
            primary_handle: Handle::RH_OWNER,
            in_sensitive: Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::default(),
                data: Tpm2bSensitiveData::default(),
            }),
            in_public: Tpm2b(public),
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        },
        &[pw()],
    )
    .expect("CreatePrimary failed")
    .object_handle
}

/// Creates an ECC primary storage key under `hierarchy` (empty hierarchy password) and returns
/// its handle.
pub fn create_storage_primary_in(sim: &mut Tpm, hierarchy: Handle) -> Handle {
    let cmd = CreatePrimary {
        primary_handle: hierarchy,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(ecc_storage_template()),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let rsp_handles = execute_with_password_sessions(sim, &cmd, 1, &[])
        .unwrap_or_else(|rc| panic!("CreatePrimary({hierarchy:?}) failed: {rc:#x}"));
    rsp_handles.object_handle
}

/// Creates an RSA-2048 unrestricted signing primary key with authValue `auth` and `scheme`,
/// returning its handle; panics on failure.
pub fn create_test_key(sim: &mut Tpm, auth: &[u8], scheme: Option<TpmtRsaScheme>) -> Handle {
    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let in_public = tpm2::Tpm2b(public_area);

    let mut user_auth = Tpm2bAuth::default();
    if !auth.is_empty() {
        user_auth = Tpm2bAuth::from_bytes(auth).unwrap();
    }

    let sensitive_create = TpmsSensitiveCreate {
        user_auth,
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_ENDORSEMENT,
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let rsp_handles =
        execute_with_password_sessions(sim, &create_cmd, 1, &[]).expect("could not generate key");

    rsp_handles.object_handle
}

/// Like [`create_test_key`] but optionally `restricted` and with a custom `name_alg`.
pub fn create_test_key_with_options(
    sim: &mut Tpm,
    auth: &[u8],
    scheme: Option<TpmtRsaScheme>,
    is_restricted: bool,
    name_alg: TpmiAlgHash,
) -> Handle {
    let mut attrs = TpmaObject::SIGN_ENCRYPT
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::SENSITIVE_DATA_ORIGIN
        | TpmaObject::FIXED_PARENT
        | TpmaObject::FIXED_TPM;
    if is_restricted {
        attrs |= TpmaObject::RESTRICTED;
    }
    let public_area = TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme,
                key_bits: TpmiRsaKeyBits(1024),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let in_public = tpm2::Tpm2b(public_area);

    let mut user_auth = Tpm2bAuth::default();
    if !auth.is_empty() {
        user_auth = Tpm2bAuth::from_bytes(auth).unwrap();
    }

    let sensitive_create = TpmsSensitiveCreate {
        user_auth,
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_ENDORSEMENT,
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let rsp_handles =
        execute_with_password_sessions(sim, &create_cmd, 1, &[]).expect("could not generate key");

    rsp_handles.object_handle
}

/// Creates a symmetric (AES-128-CFB) restricted-decrypt storage primary under the owner
/// hierarchy and returns its handle.
pub fn create_test_primary(sim: &mut Tpm) -> Handle {
    let attrs = TpmaObject::FIXED_TPM
        | TpmaObject::FIXED_PARENT
        | TpmaObject::SENSITIVE_DATA_ORIGIN
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::RESTRICTED
        | TpmaObject::DECRYPT;
    let pub_tmpl = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Default::default(),
        // A restricted decrypt KEYEDHASH object would need an XOR scheme (C `SchemeChecks()`);
        // use a symmetric storage parent instead.
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject {
                alg: AlgSym::Aes128,
                mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
            },
            Tpm2bDigest::default(),
        ),
    };
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(pub_tmpl),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    execute_with_password_sessions_status(sim, &cmd, 1, &[]).expect("CreatePrimary failed")[0]
}

/// Creates a keyed-hash (HMAC) primary key under the owner hierarchy and
/// returns its transient handle.
pub fn create_transient_object(sim: &mut Tpm) -> u32 {
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            Tpm2bDigest::default(),
        ),
    };
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_public: Tpm2b(public),
        ..Default::default()
    };
    let handles = execute_with_password_sessions(sim, &cmd, 1, &[]).expect("CreatePrimary failed");
    handles.object_handle.0
}

/// `TPM2_Create` of `public` (with sensitive `data`) under `parent`.
pub fn create_unwrap(
    sim: &mut Tpm,
    parent: Handle,
    public: TpmtPublic<'_>,
    data: &[u8],
) -> responses::Create<'static> {
    exec_command(
        sim,
        &Create {
            parent_handle: parent,
            in_sensitive: Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::default(),
                data: Tpm2bSensitiveData::from_bytes(data).unwrap(),
            }),
            in_public: Tpm2b(public),
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        },
        &[pw()],
    )
    .expect("Create failed")
}

/// Reference derivation of a symmetric key and 16-byte IV with KDFa (used for parameter
/// encryption checks).
pub fn derive_key_and_iv_ref<H: tpm2::crypto::Hmac>(
    crypto: &H,
    auth_hash: TpmiAlgHash,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    key_size_bytes: usize,
) -> (Vec<u8>, [u8; 16]) {
    let total_bytes = key_size_bytes + 16;
    let total_bits = (total_bytes * 8) as u32;
    let out_buffer = reference_kdfa(
        crypto, auth_hash, key, label, context_u, context_v, total_bits,
    );
    let derived_key = out_buffer[..key_size_bytes].to_vec();
    let mut derived_iv = [0u8; 16];
    derived_iv.copy_from_slice(&out_buffer[key_size_bytes..]);
    (derived_key, derived_iv)
}

/// Duplicates `target` to `parent`, imports the result under `parent`, loads it and checks that
/// the loaded object has the Name `target_name`.
///
/// `target` is flushed right after `TPM2_Duplicate`, so that the imported copy can be loaded
/// even when the TPM's few object slots are otherwise occupied (e.g. by the target's parent and
/// `parent`); the imported copy is flushed again after the check.
#[allow(clippy::too_many_arguments)]
pub fn dup_import_load(
    sim: &mut Tpm,
    target: Handle,
    target_public: Tpm2bPublic<'_>,
    target_name: &[u8],
    target_hash: TpmiAlgHash,
    parent: Handle,
    sym_alg: Option<TpmtSymDefObject>,
    ctx: &str,
) {
    let encryption_key_in = match sym_alg {
        Some(TpmtSymDefObject {
            alg: AlgSym::Aes128,
            ..
        }) => Tpm2bData::from_bytes(random_bytes(16)).unwrap(),
        Some(TpmtSymDefObject {
            alg: AlgSym::Aes256,
            ..
        }) => Tpm2bData::from_bytes(random_bytes(32)).unwrap(),
        _ => Tpm2bData::default(),
    };
    let dup_resp = duplicate_command_with_name_alg(
        sim,
        target,
        parent,
        &Duplicate {
            object_handle: target,
            new_parent_handle: parent,
            encryption_key_in,
            symmetric_alg: sym_alg,
        },
        target_hash,
    )
    .unwrap_or_else(|e| panic!("Duplicate failed for {ctx}, error={e:08X}"));
    flush_context(sim, target).unwrap();

    let imp_resp = import_command(
        sim,
        parent,
        &Import {
            parent_handle: parent,
            encryption_key: encryption_key_in,
            object_public: target_public,
            duplicate: dup_resp.duplicate,
            in_sym_seed: dup_resp.out_sym_seed,
            symmetric_alg: sym_alg,
        },
    )
    .unwrap_or_else(|e| panic!("Import failed for {ctx}, error={e:08X}"));

    let (handle, name) = load_with_name(sim, parent, imp_resp.out_private, target_public)
        .unwrap_or_else(|e| panic!("Load failed for {ctx}, error={e:08X}"));
    // Loaded object name should match target name
    assert_eq!(name, target_name, "{ctx}");
    // Verify that the new handle is a transient handle (starts with 0x80)
    assert_eq!(handle.0 >> 24, 0x80, "{ctx}");
    flush_context(sim, handle).unwrap();
}

/// `TPM2_Duplicate` authorized with a SHA-256 `PolicyCommandCode(Duplicate)` policy session.
pub fn duplicate(
    sim: &mut Tpm,
    object: Handle,
    new_parent: Handle,
    symmetric: Option<TpmtSymDefObject>,
) -> Result<responses::Duplicate<'static>, u32> {
    duplicate_alg(sim, object, new_parent, symmetric, TpmiAlgHash::Sha256)
}

/// `TPM2_Duplicate` authorized with an `alg` `PolicyCommandCode(Duplicate)` policy session.
pub fn duplicate_alg(
    sim: &mut Tpm,
    object: Handle,
    new_parent: Handle,
    symmetric: Option<TpmtSymDefObject>,
    alg: TpmiAlgHash,
) -> Result<responses::Duplicate<'static>, u32> {
    let sess = dup_policy_session_alg(sim, alg);
    let cmd = Duplicate {
        object_handle: object,
        new_parent_handle: new_parent,
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: symmetric,
    };
    let rsp = execute_with_hmac_sessions(sim, &cmd, &[], &mut [sess.clone()], &[&[]]);
    let _ = flush_context(sim, sess.session_handle);
    rsp
}

/// `TPM2_Duplicate` authorized with a SHA-256 policy session that satisfied
/// `PolicyCommandCode(TPM_CC_Duplicate)`. `object` and `new_parent` replace the handles of `cmd`.
pub fn duplicate_command(
    sim: &mut Tpm,
    object: Handle,
    new_parent: Handle,
    cmd: &Duplicate<'_>,
) -> Result<responses::Duplicate<'static>, u32> {
    let session = exec_command(
        sim,
        &StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::from_bytes(random_bytes(16)).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::Policy,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        },
        &[],
    )
    .expect("StartAuthSession failed");
    exec_command(
        sim,
        &PolicyCommandCode {
            policy_session: session.session_handle,
            code: TpmCc::Duplicate,
        },
        &[],
    )
    .expect("PolicyCommandCode failed");
    let auth = TpmsAuthCommand {
        session_handle: session.session_handle,
        nonce: Tpm2bNonce::from_bytes(random_bytes(16)).unwrap(),
        session_attributes: TpmaSession(0),
        hmac: Tpm2bAuth::default(),
    };
    exec_command(
        sim,
        &Duplicate {
            object_handle: object,
            new_parent_handle: new_parent,
            ..*cmd
        },
        &[auth],
    )
}

/// `TPM2_Duplicate` of `object` (whose nameAlg is `name_alg`) to `new_parent`, authorized with
/// a policy session that satisfied `PolicyCommandCode(TPM_CC_Duplicate)`. `object` and
/// `new_parent` replace the handles of `cmd`.
pub fn duplicate_command_with_name_alg(
    sim: &mut Tpm,
    object: Handle,
    new_parent: Handle,
    cmd: &Duplicate<'_>,
    name_alg: TpmiAlgHash,
) -> Result<responses::Duplicate<'static>, u32> {
    let session = dup_policy_session(sim, name_alg);
    let auth = TpmsAuthCommand {
        session_handle: session,
        nonce: Tpm2bNonce::from_bytes(random_bytes(16)).unwrap(),
        session_attributes: TpmaSession(0),
        hmac: Tpm2bAuth::default(),
    };
    let res = exec_command(
        sim,
        &Duplicate {
            object_handle: object,
            new_parent_handle: new_parent,
            ..*cmd
        },
        &[auth],
    );
    if res.is_err() {
        // A failed command leaves the session loaded.
        flush_context(sim, session).unwrap();
    }
    res
}

/// A NIST P-256 key with the given attributes and scheme.
pub fn ecc_key(object_attributes: TpmaObject, scheme: TpmtEccScheme) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: object_attributes | TpmaObject::SENSITIVE_DATA_ORIGIN,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(scheme),
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint::default(),
        ),
    }
}

/// Makes `object` persistent at `persistent`, authorized by `auth` (empty password).
pub fn evict(sim: &mut Tpm, auth: Handle, object: Handle, persistent: u32) {
    let cmd = EvictControl {
        auth,
        object_handle: object,
        persistent_handle: Handle(persistent),
    };
    execute_with_password_sessions(sim, &cmd, 1, &[])
        .unwrap_or_else(|rc| panic!("EvictControl({persistent:#x}) failed: {rc:#x}"));
}

/// `TPM2_EvictControl` with an empty password for `auth`.
pub fn evict_control(
    sim: &mut Tpm,
    auth: Handle,
    object: Handle,
    persistent: Handle,
) -> Result<(), u32> {
    let cmd = EvictControl {
        auth,
        object_handle: object,
        persistent_handle: persistent,
    };
    run(sim, &cmd, 1).map(|_| ())
}

/// `TPM2_EvictControl` with an empty password for `auth`; returns the response code.
pub fn evict_control_rc(
    sim: &mut Tpm,
    auth: Handle,
    object_handle: u32,
    persistent_handle: u32,
) -> u32 {
    let cmd = EvictControl {
        auth,
        object_handle: Handle(object_handle),
        persistent_handle: Handle(persistent_handle),
    };
    execute_with_password_sessions(sim, &cmd, 1, &[]).map_or_else(|rc| rc, |_| 0)
}

/// Makes the transient object `object` persistent at `persistent` (owner
/// authorization) and flushes the transient copy.
pub fn evict_owner(sim: &mut Tpm, object: Handle, persistent: Handle) {
    execute_tpm_command_mapping_parse_errors(
        sim,
        &EvictControl {
            auth: Handle::RH_OWNER,
            object_handle: object,
            persistent_handle: persistent,
        },
        &[pw_with(b"")],
    )
    .expect("EvictControl failed");
    flush_context(sim, object).expect("FlushContext failed");
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

/// Flushes `handle`, panicking on failure.
pub fn flush_handle(sim: &mut Tpm, handle: Handle) {
    flush_context(sim, handle).expect("FlushContext failed");
}

/// Raw `TPM2_FlushContext(flush_handle)`.
pub fn flush_raw(sim: &mut Tpm, flush_handle: u32) -> Vec<u8> {
    let mut cmd = Vec::new();
    cmd.extend_from_slice(&0x8001u16.to_be_bytes());
    cmd.extend_from_slice(&14u32.to_be_bytes());
    cmd.extend_from_slice(&0x0000_0165u32.to_be_bytes());
    cmd.extend_from_slice(&flush_handle.to_be_bytes());
    raw(sim, &cmd)
}

/// `TPM2_FlushContext(handle)`.
pub fn flush_rc(sim: &mut Tpm, handle: u32) -> u32 {
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_FLUSH_CONTEXT,
        &[],
        None,
        &handle.to_be_bytes(),
    );
    mssim_rc_of(sim, &cmd)
}

/// `TPM2_CreatePrimary` command (its handle is the owner hierarchy) for an ECDSA P-256 signing
/// key under the owner hierarchy.
pub fn get_create_primary_cmd_and_handles() -> CreatePrimary<'static> {
    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            ecc_parms,
            TpmsEccPoint {
                x: Tpm2bEccParameter::default(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    }
}

/// The Name of a permanent handle (the handle value).
pub fn handle_name(h: u32) -> Vec<u8> {
    h.to_be_bytes().to_vec()
}

/// The Name of a permanent handle (the handle value).
pub fn handle_name_of(handle: Handle) -> Vec<u8> {
    handle.0.to_be_bytes().to_vec()
}

/// `TPM2_Import` under `parent` (no inner wrapper).
pub fn import(
    sim: &mut Tpm,
    parent: Handle,
    public: Tpm2bPublic<'static>,
    duplicate: Tpm2bPrivate<'static>,
    seed: Tpm2bEncryptedSecret<'static>,
) -> Result<Tpm2bPrivate<'static>, u32> {
    let cmd = Import {
        parent_handle: parent,
        encryption_key: Tpm2bData::default(),
        object_public: public,
        duplicate,
        in_sym_seed: seed,
        symmetric_alg: None,
    };
    run(sim, &cmd, 1).map(|rsp| rsp.out_private)
}

/// Imports a plaintext duplicate of an ECC key (`d`, `seed`) under `srk` and loads it.
pub fn import_and_load(
    sim: &mut Tpm,
    srk: Handle,
    public: TpmtPublic<'static>,
    d: &[u8],
    seed: &[u8],
) -> Handle {
    let sensitive = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(leak_bytes(seed)).unwrap(),
        sensitive: TpmuSensitiveComposite::Ecc(
            Tpm2bEccParameter::from_bytes(leak_bytes(d)).unwrap(),
        ),
    };
    let sens = marshal_to_vec(&sensitive);
    let mut blob = (sens.len() as u16).to_be_bytes().to_vec();
    blob.extend(sens);
    let private = import(
        sim,
        srk,
        Tpm2b(public),
        Tpm2bPrivate::from_bytes(leak_bytes(&blob)).unwrap(),
        Tpm2bEncryptedSecret::default(),
    )
    .expect("Import");
    load(sim, srk, private, Tpm2b(public)).expect("Load of the imported key")
}

/// `TPM2_Import` under `parent` (which replaces `cmd.parent_handle`).
pub fn import_command(
    sim: &mut Tpm,
    parent: Handle,
    cmd: &Import<'_>,
) -> Result<responses::Import<'static>, u32> {
    exec_command(
        sim,
        &Import {
            parent_handle: parent,
            ..*cmd
        },
        &[pw()],
    )
}

/// Extracts the [`EncapsulationKey`] (public key, name algorithm, symmetric definition) from a
/// parent's public area.
pub fn import_encapsulation_key(public: &TpmtPublic) -> EncapsulationKey {
    match &public.parms_and_id {
        PublicParmsAndId::Ecc(ecc_parms, ecc_point) => EncapsulationKey::Ecc {
            pub_x: ecc_point.x.get_buffer().to_vec(),
            pub_y: ecc_point.y.get_buffer().to_vec(),
            name_alg: public.name_alg.unwrap(),
            sym_def: ecc_parms.symmetric,
        },
        PublicParmsAndId::Rsa(rsa_parms, rsa_pub) => {
            let n_bytes = rsa_pub.get_buffer();
            let n = rsa::BigUint::from_bytes_be(n_bytes);
            let exponent = if rsa_parms.exponent == 0 {
                65537u32
            } else {
                rsa_parms.exponent
            };
            let e = rsa::BigUint::from(exponent);
            let pub_key = rsa::RsaPublicKey::new(n, e).expect("Failed to build RSA public key");

            // Decide OAEP scheme hash alg
            let hash_alg = match &rsa_parms.scheme {
                Some(TpmtRsaScheme::Oaep(alg)) => Some(*alg),
                _ => public.name_alg,
            };

            EncapsulationKey::Rsa {
                pub_key,
                hash_alg: hash_alg.expect("REASON"),
                name_alg: public.name_alg.unwrap(),
                sym_def: rsa_parms.symmetric,
            }
        }
        _ => panic!("Unsupported encapsulation key type"),
    }
}

/// Builds a `TPM2_Import` request under `parent` (empty password session) from the given
/// marshalled `objectPublic`, `inSymSeed` contents and raw `symmetricAlg` bytes; the
/// `encryptionKey` and `duplicate` buffers are empty.
pub fn import_request(
    parent: Handle,
    object_public: &[u8],
    seed: &[u8],
    symmetric: &[u8],
) -> Vec<u8> {
    let mut req = Vec::new();
    req.extend_from_slice(&0x8002u16.to_be_bytes()); // SESSIONS
    req.extend_from_slice(&0u32.to_be_bytes()); // size placeholder
    req.extend_from_slice(&0x00000156u32.to_be_bytes()); // TPM_CC_Import
    req.extend_from_slice(&parent.0.to_be_bytes());
    // Auth session RS_PW
    req.extend_from_slice(&9u32.to_be_bytes());
    req.extend_from_slice(&0x40000009u32.to_be_bytes());
    req.extend_from_slice(&0u16.to_be_bytes());
    req.push(0x01);
    req.extend_from_slice(&0u16.to_be_bytes());
    // encryptionKey: empty 2B
    req.extend_from_slice(&0u16.to_be_bytes());
    // objectPublic
    req.extend_from_slice(object_public);
    // duplicate: empty 2B
    req.extend_from_slice(&0u16.to_be_bytes());
    // inSymSeed
    req.extend_from_slice(&(seed.len() as u16).to_be_bytes());
    req.extend_from_slice(seed);
    // symmetricAlg
    req.extend_from_slice(symmetric);
    finish(req)
}

/// Returns whether `handle` (a session or transient object) is loaded.
///
/// Loaded sessions of both types (HMAC `0x02xxxxxx` and policy `0x03xxxxxx`)
/// are reported in the `TPM_HT_LOADED_SESSION` range; `0x03` as a capability
/// range selects *saved* sessions instead.
pub fn is_loaded(sim: &mut Tpm, handle: u32) -> bool {
    let first = match handle >> 24 {
        0x02 | 0x03 => LOADED_SESSION_FIRST,
        _ => handle & 0xFF00_0000,
    };
    loaded_handles(sim, first).contains(&handle)
}

/// `TPM2_Load` under `parent`.
pub fn load(
    sim: &mut Tpm,
    parent: Handle,
    private: Tpm2bPrivate<'static>,
    public: Tpm2bPublic<'static>,
) -> Result<Handle, u32> {
    let cmd = Load {
        parent_handle: parent,
        in_private: private,
        in_public: public,
    };
    run(sim, &cmd, 1).map(|h| h.object_handle)
}

/// Loads a child of `parent`; returns its handle and Name.
pub fn load_child(
    sim: &mut Tpm,
    parent: Handle,
    in_private: Tpm2bPrivate<'static>,
    in_public: Tpm2bPublic<'static>,
) -> (Handle, Vec<u8>) {
    let cmd = Load {
        parent_handle: parent,
        in_private,
        in_public,
    };
    let rsp = execute_tpm_command(sim, &cmd, &[password_auth(b"")])
        .unwrap_or_else(|rc| panic!("Load failed: {rc:#x}"));
    (rsp.object_handle, rsp.name.get_buffer().to_vec())
}

/// Loads a saved context with `TPM2_ContextLoad`, returning the new handle or the response code.
pub fn load_context(sim: &mut Tpm, context: TpmsContext<'static>) -> Result<Handle, u32> {
    execute_with_password_sessions(sim, &ContextLoad { context }, 0, &[]).map(|h| h.loaded_handle)
}

/// Loads the test NIST P-256 key (public and private parts) with `attrs`.
pub fn load_ecc_with_private(sim: &mut Tpm, attrs: TpmaObject) -> Handle {
    load_with_private(
        sim,
        make_ecc_public_area(ECC_X, ECC_Y, attrs),
        TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(ECC_D).unwrap()),
        &[],
    )
}

/// `TPM2_LoadExternal` of a public area (and optional sensitive area) into `hierarchy`.
pub fn load_external(
    sim: &mut Tpm,
    public: TpmtPublic<'static>,
    sensitive: Option<TpmtSensitive<'static>>,
    hierarchy: Handle,
) -> Result<Handle, u32> {
    let cmd = LoadExternal {
        in_private: sensitive.map(Tpm2b),
        in_public: Tpm2b(public),
        hierarchy,
    };
    run(sim, &cmd, 0).map(|h| h.object_handle)
}

/// Loads a NIST P-256 key with a client-generated private scalar through
/// `TPM2_LoadExternal` and returns `(handle, private scalar)`.
pub fn load_external_ecc_key(sim: &mut Tpm, attrs: TpmaObject) -> (Handle, Vec<u8>) {
    let mut pub_buf = [0u8; 512];
    let mut priv_buf = [0u8; 1024];
    let (pub_len, priv_len) = CLIENT_CRYPTO
        .generate_key(
            Alg::ECC,
            Some(KeyParams::Ecc(TpmEccCurve::NistP256)),
            &mut pub_buf,
            &mut priv_buf,
            None,
        )
        .unwrap();
    let x = leak_bytes(&pub_buf[..pub_len / 2]);
    let y = leak_bytes(&pub_buf[pub_len / 2..pub_len]);
    let d = leak_bytes(&priv_buf[..priv_len]);

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint {
                x: Tpm2bEccParameter::from_bytes(x).unwrap(),
                y: Tpm2bEccParameter::from_bytes(y).unwrap(),
            },
        ),
    };
    let sensitive = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::Ecc(Tpm2bEccParameter::from_bytes(d).unwrap()),
    };
    let handles = sim
        .execute(LoadExternal {
            in_private: Some(Tpm2b(sensitive)),
            in_public: Tpm2b(public),
            hierarchy: Handle::RH_NULL,
        })
        .expect("LoadExternal failed");
    (handles.object_handle, d.to_vec())
}

/// Imports an ECC P-256 storage key with private scalar 1 and protection seed `seed` under
/// `srk` (plaintext duplicate) and loads it; returns its handle.
pub fn load_known_seed_parent(sim: &mut Tpm, srk: Handle, seed: &[u8]) -> Handle {
    let mut public = ecc_storage_template_with(TpmiAlgHash::Sha256, TpmaObject::empty());
    if let PublicParmsAndId::Ecc(_, point) = &mut public.parms_and_id {
        *point = p256_generator();
    }
    let mut d = [0u8; 32];
    d[31] = 1;
    import_and_load(sim, srk, public, &d, seed)
}

/// Loads `public` with `TPM2_LoadExternal` without a private area (a public-only object).
///
/// An empty keyedhash `unique` is replaced by a digest-sized value, as required for any loaded
/// keyedhash object (C `CryptValidateKeys()`).
pub fn load_public_only(sim: &mut Tpm, public: &TpmtPublic<'static>) -> u32 {
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
    let (code, out) = send_with_auth_entries(sim, TpmCc::LoadExternal, &[], &[], &params);
    assert_eq!(code, RC_SUCCESS, "LoadExternal");
    u32::from_be_bytes([out[10], out[11], out[12], out[13]])
}

/// Loads a public-only AES key (no sensitive area) in the NULL hierarchy.
pub fn load_public_only_sym_key(sim: &mut Tpm) -> Handle {
    let cmd = LoadExternal {
        in_private: None,
        in_public: Tpm2b(with_unique(sym_template(
            TpmaObject::USER_WITH_AUTH | TpmaObject::SIGN_ENCRYPT | TpmaObject::DECRYPT,
        ))),
        hierarchy: Handle::RH_NULL,
    };
    let handles = sim.execute(cmd).unwrap();
    handles.object_handle
}

/// Loads a fixed RSA-2048 public key (no private part) with `TPM2_LoadExternal` into the null
/// hierarchy and returns its handle; panics on failure.
pub fn load_rsa_public_only_key(sim: &mut Tpm) -> Handle {
    const RSA_N: &[u8] = &[
        0x9e, 0x67, 0x7c, 0x31, 0xb1, 0xf9, 0x15, 0x8a, 0x41, 0x4d, 0x16, 0xf0, 0x73, 0xbe, 0x59,
        0x66, 0xc0, 0xe3, 0x8d, 0xc3, 0x64, 0x4b, 0x01, 0x3c, 0xce, 0x5c, 0x13, 0x10, 0x41, 0x9f,
        0xbc, 0x43, 0x2d, 0xfa, 0xcb, 0xfc, 0xa4, 0xd8, 0x41, 0x05, 0xbc, 0xcb, 0xe5, 0xc8, 0xd9,
        0x13, 0x21, 0x6c, 0xb0, 0x13, 0xea, 0x10, 0x3a, 0x3b, 0x73, 0xe0, 0x9e, 0x59, 0x11, 0x0f,
        0x5c, 0x1f, 0x54, 0x5c, 0x39, 0x42, 0x1d, 0x45, 0xb4, 0x67, 0x2c, 0x19, 0xf7, 0x6c, 0xe6,
        0x13, 0xdd, 0xb7, 0x55, 0x5b, 0x00, 0xa6, 0xaa, 0x2f, 0x06, 0x2a, 0xa9, 0x23, 0x7f, 0xc0,
        0xb8, 0xdd, 0x32, 0xb5, 0x00, 0xc1, 0xe7, 0x51, 0xe1, 0x71, 0xc1, 0xa3, 0xb3, 0x3a, 0x44,
        0x45, 0x6c, 0x43, 0xbb, 0xc1, 0x23, 0x6f, 0x65, 0x15, 0x6e, 0x25, 0xdd, 0x51, 0x8b, 0x49,
        0x04, 0x44, 0xd1, 0x55, 0xd3, 0x88, 0x5f, 0x6a, 0xd3, 0xc1, 0x58, 0x4b, 0xca, 0xe9, 0xbe,
        0x6d, 0x30, 0x46, 0xdd, 0x3c, 0x2b, 0xbb, 0xd7, 0xbd, 0x94, 0x10, 0x5e, 0x32, 0x6e, 0xcd,
        0x24, 0x96, 0x17, 0x7a, 0x88, 0xd7, 0xee, 0x60, 0x58, 0x95, 0x6a, 0x18, 0x7f, 0x40, 0x53,
        0x24, 0xc0, 0x0e, 0xa9, 0x08, 0x9c, 0x03, 0x27, 0xce, 0x0b, 0xcb, 0xc5, 0x2c, 0xf2, 0xb0,
        0xe7, 0xac, 0xe0, 0xfa, 0x84, 0xc4, 0x77, 0x2f, 0x83, 0x3d, 0xe5, 0x7c, 0x67, 0x94, 0x93,
        0x3e, 0x52, 0x6e, 0x21, 0xf3, 0x30, 0xb1, 0x5e, 0xca, 0x39, 0xf5, 0x0b, 0x28, 0xb4, 0x87,
        0x76, 0x77, 0xc3, 0xaf, 0x4f, 0x9c, 0x7f, 0x0c, 0x58, 0x9d, 0x80, 0xf2, 0xf4, 0x93, 0x6e,
        0x03, 0x1e, 0x1d, 0x15, 0x6c, 0xb7, 0xfb, 0xd6, 0x43, 0xe3, 0xd2, 0x58, 0x5a, 0x2e, 0x2d,
        0xc2, 0xb3, 0x69, 0xff, 0x93, 0x35, 0x53, 0x71, 0x51, 0x64, 0x76, 0x41, 0x85, 0x3d, 0x3e,
        0x31,
    ];

    let rsa_parms = TpmsRsaParms {
        symmetric: None,
        scheme: None,
        key_bits: TpmiCode::from(2048),
        exponent: 0,
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            rsa_parms,
            Tpm2bPublicKeyRsa::from_bytes(RSA_N).unwrap(),
        ),
    };
    let in_public = tpm2::Tpm2b(pub_area);

    let cmd = LoadExternal {
        in_private: None,
        in_public,
        hierarchy: Handle::RH_NULL,
    };

    let resp_handles = execute_with_password_sessions(sim, &cmd, 0, &[]).unwrap();
    resp_handles.object_handle
}

/// Loads the test RSA-2048 key (public and private parts) with `attrs`.
pub fn load_rsa_with_private(
    sim: &mut Tpm,
    attrs: TpmaObject,
    symmetric: Option<TpmtSymDefObject>,
) -> Handle {
    let mut public = make_rsa_public_area(RSA_N, TpmiAlgHash::Sha256, attrs);
    if let PublicParmsAndId::Rsa(parms, _) = &mut public.parms_and_id {
        parms.symmetric = symmetric;
    }
    load_with_private(
        sim,
        public,
        TpmuSensitiveComposite::Rsa(Tpm2bPrivateKeyRsa::from_bytes(RSA_P).unwrap()),
        &[],
    )
}

/// Imports (plaintext duplicate) and loads under `srk` an ECC P-256 storage key with private
/// scalar 379 whose public point is [`p256_point_with_stripped_x`] (31-byte x).
pub fn load_stripped_ecc_storage_key(sim: &mut Tpm, srk: Handle) -> Handle {
    let mut public = ecc_storage_template_with(TpmiAlgHash::Sha256, TpmaObject::empty());
    if let PublicParmsAndId::Ecc(_, point) = &mut public.parms_and_id {
        *point = p256_point_with_stripped_x();
    }
    let mut d = [0u8; 32];
    d[30..].copy_from_slice(&379u16.to_be_bytes());
    import_and_load(sim, srk, public, &d, &[0x11; 32])
}

/// `TPM2_Load` of `private`/`public` under `parent`; returns the handle and the Name.
pub fn load_with_name(
    sim: &mut Tpm,
    parent: Handle,
    private: Tpm2bPrivate<'_>,
    public: Tpm2bPublic<'_>,
) -> Result<(Handle, Vec<u8>), u32> {
    exec_command(
        sim,
        &Load {
            parent_handle: parent,
            in_private: private,
            in_public: public,
        },
        &[pw()],
    )
    .map(|r| (r.object_handle, r.name.get_buffer().to_vec()))
}

/// Loads `public` with its sensitive area into the NULL hierarchy.
pub fn load_with_private(
    sim: &mut Tpm,
    public: TpmtPublic<'static>,
    sensitive: TpmuSensitiveComposite<'static>,
    seed: &'static [u8],
) -> Handle {
    let load_cmd = LoadExternal {
        in_private: Some(tpm2::Tpm2b(TpmtSensitive {
            auth_value: Tpm2bAuth::default(),
            seed_value: Tpm2bDigest::from_bytes(seed).unwrap(),
            sensitive,
        })),
        in_public: tpm2::Tpm2b(public),
        hierarchy: Handle::RH_NULL,
    };
    sim.execute(load_cmd).unwrap().object_handle
}

/// Returns the loaded handles of the range starting at `first`
/// (`TPM2_GetCapability(TPM_CAP_HANDLES)`).
pub fn loaded_handles(sim: &mut Tpm, first: u32) -> Vec<u32> {
    let rsp = sim
        .execute(GetCapability {
            capability: TpmCap::Handles,
            property: first,
            property_count: 64,
        })
        .expect("GetCapability(TPM_CAP_HANDLES) failed");
    let TpmsCapabilityData::Handles(handles) = rsp.capability_data else {
        panic!("unexpected capability data");
    };
    handles.as_ref().iter().map(|h| h.0).collect()
}

/// Builds the public area and marshalled sensitive area of an external sealed data object with
/// `contents`, whose `unique` is `H(obfuscation || contents)` under `name_alg`.
pub fn make_sealed_blob(
    name_alg: TpmiAlgHash,
    obfuscation: &[u8],
    contents: &[u8],
) -> (TpmtPublic<'static>, Vec<u8>) {
    let unique_digest = match name_alg {
        TpmiAlgHash::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(obfuscation);
            hasher.update(contents);
            hasher.finalize().to_vec()
        }
        TpmiAlgHash::Sha1 => {
            let mut hasher = Sha1::new();
            hasher.update(obfuscation);
            hasher.update(contents);
            hasher.finalize().to_vec()
        }
        _ => panic!("Unsupported name_alg"),
    };

    let public = TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: TpmaObject::USER_WITH_AUTH | TpmaObject::NO_DA,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            None,
            Tpm2bDigest::from_bytes(crate::test_utils::leak_bytes(&unique_digest)).unwrap(),
        ),
    };

    let sensitive = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(obfuscation).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(contents).unwrap(),
        ),
    };

    let mut buf = vec![0u8; 4096];
    let len = marshal_to_slice(&sensitive, &mut buf);
    buf.truncate(len);

    (public, buf)
}

/// Returns whether a persistent/transient object handle is present (`TPM2_ReadPublic`).
pub fn object_exists(sim: &mut Tpm, handle: u32) -> bool {
    sim.execute(ReadPublic {
        object_handle: Handle(handle),
    })
    .is_ok()
}

/// The Name of a loaded or persistent object.
pub fn object_name(sim: &mut Tpm, h: u32) -> Vec<u8> {
    read_public_name(sim, Handle(h)).get_buffer().to_vec()
}

/// Creates the default fixed RSA storage primary key under the owner hierarchy.
pub fn owner_srk(sim: &mut Tpm) -> Handle {
    try_create_primary_in(sim, Handle::RH_OWNER, fixed_rsa_storage(), &[])
        .expect("CreatePrimary")
        .0
}

/// Parses a plaintext (unwrapped) duplication blob: `UINT16 size || TPMT_SENSITIVE`.
pub fn parse_plain_duplicate(blob: &[u8]) -> TpmtSensitive<'static> {
    let size = u16::from_be_bytes([blob[0], blob[1]]) as usize;
    assert_eq!(
        size + 2,
        blob.len(),
        "TPM2B_SENSITIVE size must cover the blob"
    );
    let mut slice: &'static [u8] = leak_bytes(&blob[2..]);
    let sensitive = TpmtSensitive::unmarshal(&mut slice).unwrap();
    assert!(slice.is_empty());
    sensitive
}

/// Computes `nameAlg || H(marshal(public))` (SHA-256).
pub fn public_name(public: &TpmtPublic<'_>) -> Vec<u8> {
    let mut name = vec![0x00, 0x0b];
    name.extend(hash_parts(TpmiAlgHash::Sha256, &[&marshal_to_vec(public)]));
    name
}

/// Symmetric public-only key used by `TPM2_EncryptDecrypt` / `TPM2_EncryptDecrypt2`.
pub fn public_only_sym_key(sim: &mut Tpm) -> u32 {
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::DECRYPT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject {
                alg: AlgSym::Aes128,
                mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
            },
            Tpm2bDigest::from_bytes(leak_bytes(&[9; 32])).unwrap(),
        ),
    };
    load_public_only(sim, &public)
}

/// `nameAlg || SHA-256(parentQN || name)`: the qualified Name of an object with Name `name`
/// whose parent has qualified Name `parent_qn` (a hierarchy's qualified Name is its handle).
pub fn qualified_name(parent_qn: &[u8], name: &[u8]) -> Vec<u8> {
    let mut ctx = tpm2::crypto::HashStream::new(CLIENT_CRYPTO, TpmiAlgHash::Sha256).unwrap();
    ctx.update(parent_qn).unwrap();
    ctx.update(name).unwrap();
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = ctx.finalize(&mut out).unwrap().digest().to_vec();
    [&0x000Bu16.to_be_bytes()[..], &digest].concat()
}

/// 32 bytes of client-side randomness, leaked for use as sensitive data.
pub fn random_key() -> &'static [u8] {
    let mut key = [0u8; 32];
    client_rng().fill_bytes(&mut key);
    leak_bytes(&key)
}

/// `TPM2_ReadPublic(handle)` (no sessions); returns the response code.
pub fn read_public_rc(sim: &mut Tpm, handle: u32) -> u32 {
    mssim_rc_of(
        sim,
        &build_raw_cmd(ST_NO_SESSIONS, CC_READ_PUBLIC, &[handle], None, &[]),
    )
}

/// `TPM2_Rewrap` (oldParent authorized with an empty password).
pub fn rewrap(
    sim: &mut Tpm,
    old_parent: Handle,
    new_parent: Handle,
    in_duplicate: Tpm2bPrivate<'static>,
    name: Tpm2bName<'static>,
    in_sym_seed: Tpm2bEncryptedSecret<'static>,
) -> Result<responses::Rewrap<'static>, u32> {
    let cmd = Rewrap {
        old_parent,
        new_parent,
        in_duplicate,
        name,
        in_sym_seed,
    };
    run(sim, &cmd, 1)
}

/// An RSA-2048 key with the given attributes, scheme and symmetric algorithm.
pub fn rsa_key(
    object_attributes: TpmaObject,
    scheme: Option<TpmtRsaScheme>,
    symmetric: Option<TpmtSymDefObject>,
) -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: object_attributes | TpmaObject::SENSITIVE_DATA_ORIGIN,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric,
                scheme,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    }
}

/// Creates an ECDSA primary key under the owner hierarchy, saves its context
/// and flushes it. Returns the saved context.
pub fn save_object_context(sim: &mut Tpm) -> TpmsContext<'static> {
    let create = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(b"pass").unwrap(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(TpmtPublic {
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
                tpm2::TpmsEccPoint::default(),
            ),
        }),
        ..Default::default()
    };
    let handles =
        execute_with_password_sessions(sim, &create, 1, &[]).expect("CreatePrimary failed");
    let save = sim
        .execute(ContextSave {
            save_handle: handles.object_handle,
        })
        .expect("ContextSave failed");
    flush_handle(sim, handles.object_handle);
    save.context
}

/// Sends a command with one key handle, optionally with an empty password session, and returns
/// its response code.
pub fn send_key_command(sim: &mut Tpm, cc: u32, key: Handle, pw: bool, params: &[u8]) -> u32 {
    let cmd = if pw {
        build(
            ST_SESSIONS,
            cc,
            &[key.0],
            Some(&PW_SESSION_CONTINUE),
            params,
        )
    } else {
        build(ST_NO_SESSIONS, cc, &[key.0], None, params)
    };
    rc_of(&transact(sim, &cmd))
}

/// `TPM2_CreatePrimary` under the owner hierarchy; returns the object handle and its Name.
pub fn try_create_owner_primary(
    sim: &mut Tpm,
    public: TpmtPublic<'_>,
) -> Result<(Handle, Vec<u8>), u32> {
    exec_command(
        sim,
        &CreatePrimary {
            primary_handle: Handle::RH_OWNER,
            in_sensitive: Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::default(),
                data: Tpm2bSensitiveData::default(),
            }),
            in_public: Tpm2b(public),
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        },
        &[pw()],
    )
    .map(|r| (r.object_handle, r.name.get_buffer().to_vec()))
}

/// `TPM2_CreatePrimary` under the owner hierarchy (empty authValue); returns the handle and the
/// created public area.
pub fn try_create_primary(
    sim: &mut Tpm,
    public: TpmtPublic<'static>,
    data: &'static [u8],
) -> Result<(Handle, TpmtPublic<'static>), u32> {
    execute_with_password_sessions(
        sim,
        &CreatePrimary {
            primary_handle: Handle::RH_OWNER,
            in_sensitive: Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::default(),
                data: Tpm2bSensitiveData::from_bytes(data).unwrap(),
            }),
            in_public: Tpm2b(public),
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        },
        1,
        &[],
    )
    .map(|resp| (resp.object_handle, resp.out_public.0))
}

/// `TPM2_CreatePrimary` under `hierarchy`; returns (handle, response).
pub fn try_create_primary_in(
    sim: &mut Tpm,
    hierarchy: Handle,
    template: TpmtPublic<'static>,
    data: &[u8],
) -> Result<(Handle, responses::CreatePrimary<'static>), u32> {
    let cmd = CreatePrimary {
        primary_handle: hierarchy,
        in_sensitive: sensitive_create(&[], data),
        in_public: Tpm2b(template),
        ..Default::default()
    };
    run(sim, &cmd, 1).map(|rsp| (rsp.object_handle, rsp))
}

/// `TPM2_Unseal(object)` with the given password; returns the response code.
pub fn unseal(sim: &mut Tpm, object: Handle, password: &[u8]) -> u32 {
    execute_with_password_sessions_status(
        sim,
        &Unseal {
            item_handle: object,
        },
        1,
        password,
    )
    .err()
    .unwrap_or(0)
}

// ===========================================================================
// Client-side cryptography and reference computations
//
// Hashes, HMACs, KDFs, symmetric/asymmetric reference implementations and signature checks computed on the client.
// ===========================================================================

/// AES-128-CFB encryption in place with a zero IV (duplication inner wrapper).
pub fn aes128_cfb_zero_iv_encrypt(key: &[u8], data: &mut [u8]) {
    aes_cfb(key, &[0u8; 16], data, true);
}

/// AES-128-CFB in place.
pub fn aes_cfb(key: &[u8], iv: &[u8; 16], data: &mut [u8], encrypt: bool) {
    let alg = TpmtSymDefObject::aes_cfb(128).unwrap();
    let mut iv = *iv;
    if encrypt {
        sym_encrypt(CLIENT_CRYPTO, alg, key, &mut iv, data).unwrap();
    } else {
        sym_decrypt(CLIENT_CRYPTO, alg, key, &mut iv, data).unwrap();
    }
}

/// Computes `alg(data)` on the client side.
pub fn client_hash(alg: TpmiAlgHash, data: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    tpm2::crypto::hash(CLIENT_CRYPTO, alg, data, &mut buf)
        .unwrap()
        .digest()
        .to_vec()
}

/// Hashes the concatenation of `data` with `alg` using the RustCrypto implementations (SHA-1/
/// SHA-256/SHA-384/SHA-512).
pub fn compute_hash(alg: TpmiAlgHash, data: &[&[u8]]) -> Vec<u8> {
    use sha1::Sha1;
    use sha2::{Digest, Sha256, Sha384, Sha512};
    match alg {
        TpmiAlgHash::Sha1 => {
            let mut hasher = Sha1::new();
            for d in data {
                hasher.update(d);
            }
            hasher.finalize().to_vec()
        }
        TpmiAlgHash::Sha256 => {
            let mut hasher = Sha256::new();
            for d in data {
                hasher.update(d);
            }
            hasher.finalize().to_vec()
        }
        TpmiAlgHash::Sha384 => {
            let mut hasher = Sha384::new();
            for d in data {
                hasher.update(d);
            }
            hasher.finalize().to_vec()
        }
        TpmiAlgHash::Sha512 => {
            let mut hasher = Sha512::new();
            for d in data {
                hasher.update(d);
            }
            hasher.finalize().to_vec()
        }
        #[allow(unreachable_patterns)]
        _ => panic!("Unsupported hash"),
    }
}

/// Computes `HASH(data)` with the client-side crypto provider.
pub fn compute_hash_single(alg: TpmiAlgHash, data: &[u8]) -> Vec<u8> {
    let mut out = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    tpm2::crypto::hash(CLIENT_CRYPTO, alg, data, &mut out)
        .unwrap()
        .digest()
        .to_vec()
}

/// Hashes the concatenation of `updates` with `auth_hash` using the given crypto provider.
pub fn compute_hash_with<H: tpm2::crypto::Hash>(
    crypto: &H,
    auth_hash: TpmiAlgHash,
    updates: &[&[u8]],
) -> Vec<u8> {
    let mut state = tpm2::crypto::HashStream::new(crypto, auth_hash).unwrap();
    for data in updates {
        state.update(data).unwrap();
    }
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    state.finalize(&mut out).unwrap().digest().to_vec()
}

/// HMACs the concatenation of `updates` with `auth_hash` under `key` using the given crypto
/// provider.
pub fn compute_hmac_with<H: tpm2::crypto::Hmac>(
    crypto: &H,
    auth_hash: TpmiAlgHash,
    key: &[u8],
    updates: &[&[u8]],
) -> Vec<u8> {
    let mut state = tpm2::crypto::HmacStream::new(crypto, auth_hash, key).unwrap();
    for data in updates {
        state.update(data).unwrap();
    }
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    state.finalize(&mut out).unwrap().digest().to_vec()
}

/// SHA-256 of `data`, computed with the client-side crypto provider.
pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(CLIENT_CRYPTO, TpmiAlgHash::Sha256, data, &mut out).unwrap();
    digest.digest().try_into().unwrap()
}

/// `cpHash = H(commandCode || names || parameters)`.
pub fn cp_hash(cc: TpmCc, names: &[&[u8]], params: &[u8]) -> Vec<u8> {
    let cc_bytes = cc.code().to_be_bytes();
    let mut parts: Vec<&[u8]> = vec![&cc_bytes];
    parts.extend_from_slice(names);
    parts.push(params);
    sha256(&parts)
}

/// Creates an AES-128 primary key in `mode` with authValue `"password"` and returns its handle.
///
/// The key is usable for encryption (`sign`) and, unless `mode` is CMAC (which the TPM only
/// accepts for sign-only keys), for decryption.
pub fn create_aes_key(sim: &mut Tpm, mode: TpmiAlgSymMode) -> Handle {
    try_create_aes_key(sim, mode).expect("CreatePrimary(AES) failed")
}

/// Like [`create_aes_key`], but returns the `TPM2_CreatePrimary` response code on failure.
pub fn try_create_aes_key(sim: &mut Tpm, mode: TpmiAlgSymMode) -> Result<Handle, u32> {
    try_create_aes_key_with_mode(sim, Alg::from(mode))
}

/// Like [`try_create_aes_key`], but the mode is any algorithm ID, including modes this TPM does
/// not implement (e.g. `TPM_ALG_CMAC`, which is not a [`TpmiAlgSymMode`] of this TPM): the
/// template is marshaled with CFB and its mode is then replaced by `mode`.
pub fn try_create_aes_key_with_mode(sim: &mut Tpm, mode: Alg) -> Result<Handle, u32> {
    let mut attributes = TpmaObject::USER_WITH_AUTH
        | TpmaObject::SIGN_ENCRYPT
        | TpmaObject::FIXED_TPM
        | TpmaObject::FIXED_PARENT
        | TpmaObject::SENSITIVE_DATA_ORIGIN;
    if mode != Alg::CMAC {
        attributes |= TpmaObject::DECRYPT;
    }
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(b"password").unwrap(),
            data: Default::default(),
        }),
        in_public: Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: attributes,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Sym(
                TpmtSymDefObject {
                    alg: AlgSym::Aes128,
                    mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
                },
                Tpm2bDigest::default(),
            ),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let handles = execute_with_corrupted_bytes_status(sim, &cmd, 1, &[], |params| {
        // inSensitive, then inPublic: size, type, nameAlg, objectAttributes, authPolicy and the
        // TPMT_SYM_DEF_OBJECT (algorithm, keyBits, mode).
        let auth_policy = tpm2b_public_name_alg(tpm2b_end(params, 0)) + 2 + 4;
        put_u16(params, tpm2b_end(params, auth_policy) + 4, mode.id());
    })?;
    Ok(handles.as_ref()[0])
}

/// The offset just past the `TPM2B` (a `UINT16` size and its buffer) at `offset` in `buf`.
pub fn tpm2b_end(buf: &[u8], offset: usize) -> usize {
    offset + 2 + usize::from(u16::from_be_bytes([buf[offset], buf[offset + 1]]))
}

/// The offset of `nameAlg` in the `TPM2B_PUBLIC` at `offset` (after its size and `type`).
pub fn tpm2b_public_name_alg(offset: usize) -> usize {
    offset + 2 + 2
}

/// Inserts `extra` at offset `at` of the raw command `cmd` (e.g. into the buffer of a `TPM2B`, to
/// exceed the capacity that the `tpm2` types of this TPM can represent), adds its length to the
/// `UINT16` size fields at the offsets `sizes` (the enclosing `TPM2B`s) and updates the command
/// size.
pub fn grow_command(cmd: &mut Vec<u8>, sizes: &[usize], at: usize, extra: &[u8]) {
    cmd.splice(at..at, extra.iter().copied());
    for &offset in sizes {
        let size = u16::from_be_bytes([cmd[offset], cmd[offset + 1]]) + extra.len() as u16;
        put_u16(cmd, offset, size);
    }
    let len = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&len.to_be_bytes());
}

/// Replaces the big-endian `UINT16` at `offset` in `buf` by `value`. Used to send values that the
/// `tpm2` types of this TPM cannot represent (algorithms, curves and key sizes whose `tpm2`
/// features are disabled), which the TPM must reject while unmarshaling.
pub fn put_u16(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

/// Creates an ECDSA P-256 signing primary key in `hierarchy` (optionally `restricted`) and returns
/// its handle and Name; panics on failure.
pub fn create_ecc_signing_key(
    sim: &mut Tpm,
    hierarchy: Handle,
    restricted: bool,
) -> (Handle, Tpm2bName<'static>) {
    let mut object_attributes = TpmaObject::FIXED_TPM
        | TpmaObject::FIXED_PARENT
        | TpmaObject::SENSITIVE_DATA_ORIGIN
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::SIGN_ENCRYPT;
    if restricted {
        object_attributes |= TpmaObject::RESTRICTED;
    }

    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };

    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(ecc_parms, TpmsEccPoint::default()),
    };
    let in_public = tpm2::Tpm2b(public_area);

    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_primary = CreatePrimary {
        primary_handle: hierarchy,
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let rsp = execute_with_password_sessions(sim, &create_primary, 1, &[])
        .expect("could not create ECC primary key");
    (rsp.object_handle, rsp.name)
}

/// Creates a KeyedHash HMAC-SHA256 signing key with authValue `auth` and HMAC key
/// `secret_key` as a primary object of the owner hierarchy and returns its handle.
pub fn create_keyed_hash_key(sim: &mut Tpm, auth: &[u8], secret_key: &[u8]) -> Handle {
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(auth).unwrap(),
            data: Tpm2bSensitiveData::from_bytes(secret_key).unwrap(),
        }),
        in_public: Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SIGN_ENCRYPT
                | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(
                Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
                Tpm2bDigest::default(),
            ),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let rsp_handles = execute_tpm_command(sim, &cmd, &[password_auth(b"")])
        .unwrap_or_else(|rc| panic!("CreatePrimary failed: {rc:#x}"));
    rsp_handles.object_handle
}

/// Creates a KeyedHash data object (null scheme, SHA-256 Name) as a primary object of the
/// owner hierarchy and returns its handle.
pub fn create_keyed_hash_object(sim: &mut Tpm) -> Handle {
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::from_bytes(b"context save data").unwrap(),
        }),
        in_public: Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let rsp_handles = execute_with_password_sessions(sim, &cmd, 1, &[])
        .unwrap_or_else(|rc| panic!("CreatePrimary failed: {rc:#x}"));
    rsp_handles.object_handle
}

/// Creates a KeyedHash data object (null scheme, SHA-256 Name) with the given extra
/// attributes as a primary object of the owner hierarchy and returns its handle.
pub fn create_keyed_hash_object_with_attrs(sim: &mut Tpm, extra_attributes: TpmaObject) -> Handle {
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::from_bytes(b"context load data").unwrap(),
        }),
        in_public: Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::USER_WITH_AUTH
                | extra_attributes,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let rsp_handles = execute_with_password_sessions(sim, &cmd, 1, &[])
        .unwrap_or_else(|rc| panic!("CreatePrimary failed: {rc:#x}"));
    rsp_handles.object_handle
}

/// Creates an RSA decryption-only (no `sign`) primary key and returns its handle and Name; panics
/// on failure.
pub fn create_non_signing_key_rsa(sim: &mut Tpm) -> (Handle, tpm2::Tpm2bName<'static>) {
    // A key without SIGN_ENCRYPT, e.g. DECRYPT only
    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT,
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
    let in_public = tpm2::Tpm2b(public_area);

    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let rsp = execute_with_password_sessions(sim, &create_cmd, 1, &[])
        .expect("could not generate RSA non-signing key");

    (rsp.object_handle, rsp.name)
}

/// A restricted RSASSA-SHA256 signing key (attestation key).
pub fn create_restricted_signer(sim: &mut Tpm) -> (Handle, Vec<u8>) {
    create_rsa_primary(
        sim,
        TpmaObject::RESTRICTED | TpmaObject::SIGN_ENCRYPT,
        Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
    )
}

/// Creates an RSA-2048 unrestricted decryption primary key under the owner hierarchy and returns
/// its handle; panics on failure.
pub fn create_rsa_decrypt_key(sim: &mut Tpm) -> Handle {
    let rsa_parms = TpmsRsaParms {
        symmetric: None,
        scheme: None,
        key_bits: TpmiRsaKeyBits(2048),
        exponent: 0,
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, Tpm2bPublicKeyRsa::default()),
    };
    let in_public = tpm2::Tpm2b(pub_area);
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_rsp_handles = execute_with_password_sessions(sim, &create_cmd, 1, &[]).unwrap();
    create_rsp_handles.object_handle
}

/// Creates an ECDSA P-256 unrestricted signing primary key under the owner hierarchy and returns
/// its handle and Name; panics on failure.
pub fn create_signing_key(sim: &mut Tpm) -> (Handle, Tpm2bName<'static>) {
    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };

    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(ecc_parms, tpm2::TpmsEccPoint::default()),
    };
    let in_public = tpm2::Tpm2b(public_area);

    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_primary = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let rsp = execute_with_password_sessions(sim, &create_primary, 1, &[])
        .expect("could not call TPM2_CreatePrimary");
    (rsp.object_handle, rsp.name)
}

/// Creates an ECDSA P-256 signing primary key with authValue `auth` (see
/// [`create_signing_key_ecc_with_unique`] with `unique = 0`).
pub fn create_signing_key_ecc(sim: &mut Tpm, auth: &[u8]) -> (Handle, tpm2::Tpm2bName<'static>) {
    create_signing_key_ecc_with_unique(sim, auth, 0)
}

/// Creates an ECDSA P-256 signing primary key (`noDA`) with authValue `auth`, using `unique` to
/// make the key distinct, and returns its handle and Name; panics on failure.
pub fn create_signing_key_ecc_with_unique(
    sim: &mut Tpm,
    auth: &[u8],
    unique: u8,
) -> (Handle, tpm2::Tpm2bName<'static>) {
    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
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
                x: Tpm2bEccParameter::from_bytes(crate::test_utils::leak_bytes(&[unique; 32]))
                    .unwrap(),
                y: Tpm2bEccParameter::default(),
            },
        ),
    };
    let in_public = tpm2::Tpm2b(public_area);

    let mut user_auth = Tpm2bAuth::default();
    if !auth.is_empty() {
        user_auth = Tpm2bAuth::from_bytes(auth).unwrap();
    }

    let sensitive_create = TpmsSensitiveCreate {
        user_auth,
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let rsp = execute_with_password_sessions(sim, &create_cmd, 1, &[])
        .expect("could not generate ECC signing key");

    (rsp.object_handle, rsp.name)
}

/// Creates an ECDSA P-256 signing primary key with an empty `unique` field (see
/// [`create_signing_key_with_unique`]).
pub fn create_signing_key_empty_unique(sim: &mut Tpm) -> (Handle, Tpm2bName<'static>) {
    create_signing_key_with_unique(sim, &[])
}

/// Creates an ECC NIST P-256 ECDSA/SHA-256 signing primary key in the owner hierarchy.
pub fn create_signing_key_handle(sim: &mut Tpm) -> Handle {
    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: TpmEccCurve::NistP256,
        kdf: None,
    };
    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(ecc_parms, TpmsEccPoint::default()),
    };
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(public_area),
        ..Default::default()
    };
    let handles = execute_with_password_sessions(sim, &cmd, 1, &[]).expect("CreatePrimary failed");
    handles.object_handle
}

/// Creates an unrestricted RSA-2048 signing key without a default scheme; returns its handle
/// and Name.
pub fn create_signing_key_name_bytes(sim: &mut Tpm) -> (Handle, Vec<u8>) {
    create_primary(
        sim,
        TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: None,
                    key_bits: tpm2::TpmiRsaKeyBits(2048),
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::default(),
            ),
        },
    )
}

/// Creates an ECDSA P-256 signing primary key under the owner hierarchy whose `unique.x` is
/// `unique_id`, returning its handle and Name; panics on failure.
pub fn create_signing_key_with_unique(
    sim: &mut Tpm,
    unique_id: &[u8],
) -> (Handle, Tpm2bName<'static>) {
    let ecc_parms = TpmsEccParms {
        symmetric: None,
        scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
        curve_id: tpm2::TpmEccCurve::NistP256,
        kdf: None,
    };

    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            ecc_parms,
            tpm2::TpmsEccPoint {
                x: tpm2::Tpm2bEccParameter::from_bytes(unique_id).unwrap_or_default(),
                y: tpm2::Tpm2bEccParameter::default(),
            },
        ),
    };
    let in_public = tpm2::Tpm2b(public_area);

    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_primary = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive,
        in_public,
        ..Default::default()
    };

    let rsp = execute_with_password_sessions(sim, &create_primary, 1, &[])
        .expect("could not call TPM2_CreatePrimary");
    (rsp.object_handle, rsp.name)
}

/// `TPM2B_DIGEST("digest12")`.
pub fn digest12() -> Vec<u8> {
    let mut p = 8u16.to_be_bytes().to_vec();
    p.extend_from_slice(b"digest12");
    p
}

/// Digest of the concatenation of `parts` with `alg`.
pub fn digest_parts(alg: TpmiAlgHash, parts: &[&[u8]]) -> Vec<u8> {
    let mut ctx = tpm2::crypto::HashStream::new(CLIENT_CRYPTO, alg).unwrap();
    for part in parts {
        ctx.update(part).unwrap();
    }
    let mut out = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    ctx.finalize(&mut out).unwrap().digest().to_vec()
}

/// Marshals a `TPML_DIGEST_VALUES` from `(hashAlg, digest)` pairs.
pub fn digest_values(digests: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut v = (digests.len() as u32).to_be_bytes().to_vec();
    for (alg, d) in digests {
        v.extend_from_slice(&alg.to_be_bytes());
        v.extend_from_slice(d);
    }
    v
}

/// A SHA-256 Name `0x000B || [3; 32]` of a (non-existent) authorizing key.
pub fn dummy_key_sign() -> Tpm2bName<'static> {
    let mut key_sign_bytes = [3u8; 34];
    key_sign_bytes[0..2].copy_from_slice(&0x000Bu16.to_be_bytes());
    Tpm2bName::from_bytes(leak_bytes(&key_sign_bytes)).unwrap()
}

/// Attributes of a duplicable signing key (plus `extra`).
pub fn dup_sign_attrs(extra: TpmaObject) -> TpmaObject {
    TpmaObject::SIGN_ENCRYPT
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::SENSITIVE_DATA_ORIGIN
        | extra
}

/// Returns the ECC public point (x, y) of a public area.
pub fn ecc_point(public: &TpmtPublic<'static>) -> (Vec<u8>, Vec<u8>) {
    match &public.parms_and_id {
        PublicParmsAndId::Ecc(_, p) => (p.x.get_buffer().to_vec(), p.y.get_buffer().to_vec()),
        _ => panic!("not an ECC key"),
    }
}

/// The marshaled `TPM2B_ECC_POINT` of an ECC public area.
pub fn ecc_point_param(public: &TpmtPublic<'_>) -> Vec<u8> {
    let PublicParmsAndId::Ecc(_, point) = &public.parms_and_id else {
        panic!("not an ECC key");
    };
    let inner = marshal_to_vec(point);
    let mut out = (inner.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&inner);
    out
}

// Custom E2E execution helper that allows corrupting ciphertext parameters after encryption
// but before HMAC calculation, to verify correct parsing/unmarshalling failure handling.
/// Like [`execute_with_hmac_sessions_raw`] but flips a byte of the encrypted first parameter after
/// parameter encryption and before the HMAC is computed, to test decryption/unmarshal failures.
pub fn execute_with_hmac_sessions_corrupt_ciphertext<CmdT: tpm2::commands::Command>(
    tpm: &mut Tpm,
    cmd: &CmdT,
    sessions: &mut [ActiveSession],
    entity_auths: &[&[u8]],
    corrupt_byte_offset: usize,
) -> Result<CmdT::Response<'static>, u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut cmd_buffer = [0u8; 4096];
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
    for handle in cmd.handles().as_ref() {
        written += handle.marshal((&mut cmd_buffer[written..written + 4]).try_into().unwrap());
    }

    let session_size_pos = written;
    if !sessions.is_empty() {
        written += 4;
    }

    let sessions_start_pos = written;

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
    let mut command_handle_names = Vec::new();
    for i in 0..num_handles {
        let handle_bytes = [
            cmd_buffer[10 + i * 4],
            cmd_buffer[11 + i * 4],
            cmd_buffer[12 + i * 4],
            cmd_buffer[13 + i * 4],
        ];
        let handle = u32::from_be_bytes(handle_bytes);
        let name = entity_name(tpm, Handle(handle));
        command_handle_names.push(name);
    }

    let mut param_buf = [0u8; 4096];
    let param_len = marshal_to_slice(cmd, &mut param_buf);

    let mut nonce_callers_new = Vec::new();
    let mut decrypt_session_idx = None;

    for (i, session) in sessions.iter_mut().enumerate() {
        let mut nonce_bytes = [0u8; 16];
        crate::_common::client_random(&mut nonce_bytes).unwrap();
        let nonce_caller_new =
            Tpm2bNonce::from_bytes(crate::test_utils::leak_bytes(&nonce_bytes)).unwrap();
        nonce_callers_new.push(nonce_caller_new);

        if session.attributes.contains(TpmaSession::DECRYPT) {
            decrypt_session_idx = Some(i);
        }
    }

    // Encrypt parameter
    if let Some(idx) = decrypt_session_idx {
        let session = &sessions[idx];
        let nonce_caller_new = &nonce_callers_new[idx];

        let leading_size = 2;
        let size = u16::from_be_bytes([param_buf[0], param_buf[1]]) as usize;

        let bits = match &session.symmetric {
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes128,
                ..
            }) => 128 + 128,
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes256,
                ..
            }) => 256 + 128,
            _ => 0,
        };

        if bits > 0 {
            let key = if idx < num_handles {
                [
                    session.session_key.as_slice(),
                    strip_trailing_zeros(entity_auths[idx]),
                ]
                .concat()
            } else {
                session.session_key.clone()
            };
            let (derived_key, derived_iv) = derive_key_and_iv_ref(
                CLIENT_CRYPTO,
                session.auth_hash,
                &key,
                b"CFB",
                nonce_caller_new.get_buffer(),
                session.nonce_tpm.get_buffer(),
                ((bits - 128) / 8) as usize,
            );

            let mut iv = derived_iv;
            let sym_alg = tpm2::TpmtSymDefObject::aes_cfb((derived_key.len() * 8) as u16).unwrap();
            sym_encrypt(
                CLIENT_CRYPTO,
                sym_alg,
                &derived_key,
                &mut iv,
                &mut param_buf[leading_size..leading_size + size],
            )
            .unwrap();
        }
    }

    // Corrupt ciphertext parameter byte
    if param_len > corrupt_byte_offset {
        param_buf[corrupt_byte_offset] ^= 0xFF;
    }

    // Build HMACs using corrupted param_buf (so HMAC verification will PASS, but decryption will yield junk)
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

        let cp_hash = compute_hash_with(CLIENT_CRYPTO, auth_hash, &cp_hash_updates);

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
        let attr_byte = [session.attributes.bits()];
        hmac_updates.push(&attr_byte);

        let hmac_bytes = compute_hmac_with(CLIENT_CRYPTO, auth_hash, &hmac_key, &hmac_updates);
        let hmac_val = Tpm2bAuth::from_bytes(&hmac_bytes).unwrap();

        let auth_cmd = TpmsAuthCommand {
            session_handle: Handle(session.session_handle.0),
            nonce: *nonce_caller_new,
            session_attributes: session.attributes,
            hmac: hmac_val,
        };

        auth_written += marshal_auth_command(&auth_cmd, &mut auth_buffer[auth_written..]);
    }

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

    cmd_buffer[written..written + param_len].copy_from_slice(&param_buf[..param_len]);
    written += param_len;

    cmd_header.size = written as u32;
    let mut header_buf = [0u8; 10];
    cmd_header.marshal(&mut header_buf);
    cmd_buffer[..10].copy_from_slice(&header_buf[..10]);

    let mut resp_buffer = [0u8; 4096];
    let resp_bytes = tpm
        .transact(&cmd_buffer[..written], &mut resp_buffer)
        .unwrap();

    let mut unmarsh: &'static [u8] = crate::test_utils::leak_bytes(resp_bytes);
    let resp_header = RespHeader::unmarshal(&mut unmarsh).unwrap();
    if resp_header.rc != 0 {
        return Err(resp_header.rc);
    }

    let mut resp_handles = RespHandles::<CmdT>::default();
    for handle in resp_handles.as_mut() {
        *handle = Handle::unmarshal(&mut unmarsh).unwrap();
    }
    let mut parameter_size = 0;
    if resp_header.tag == TpmSt::SESSIONS {
        parameter_size = u32::unmarshal(&mut unmarsh).unwrap() as usize;
    }
    let (encrypted_param_buf, rest) = unmarsh.split_at(parameter_size);
    let mut unmarsh_sess: &[u8] = rest;

    let mut nonce_tpms_new = Vec::new();
    for _ in 0..sessions.len() {
        let auth_resp = TpmsAuthResponse::unmarshal(&mut unmarsh_sess).unwrap();
        nonce_tpms_new.push(auth_resp.nonce);
    }

    for (i, session) in sessions.iter_mut().enumerate() {
        session.nonce_caller = nonce_callers_new[i];
        session.nonce_tpm = nonce_tpms_new[i];
    }

    let mut resp_unmarsh: &'static [u8] = crate::test_utils::leak_bytes(encrypted_param_buf);
    let resp_struct =
        <CmdT::Response<'static>>::unmarshal_with_handles(resp_handles, &mut resp_unmarsh).unwrap();

    Ok(resp_struct)
}

/// Executes `cmd` with HMAC/policy `sessions` via [`execute_with_hmac_sessions_custom_raw`] and
/// unmarshals the response parameters.
pub fn execute_with_hmac_sessions_custom<CmdT: tpm2::commands::Command>(
    tpm: &mut Tpm,
    cmd: &CmdT,
    sessions: &mut [ActiveSession],
    entity_auths: &[&[u8]],
) -> Result<CmdT::Response<'static>, u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let (buf, handles) = execute_with_hmac_sessions_custom_raw(tpm, cmd, sessions, entity_auths)?;
    let mut resp_unmarsh: &'static [u8] = crate::test_utils::leak_bytes(&buf);
    let resp_struct =
        <CmdT::Response<'static>>::unmarshal_with_handles(handles, &mut resp_unmarsh).unwrap();
    Ok(resp_struct)
}

/// Variant of [`execute_with_hmac_sessions_raw`] (4 KiB command buffer) returning the decrypted
/// response parameter bytes and response handles, or the response code.
pub fn execute_with_hmac_sessions_custom_raw<CmdT: tpm2::commands::Command>(
    tpm: &mut Tpm,
    cmd: &CmdT,
    sessions: &mut [ActiveSession],
    entity_auths: &[&[u8]],
) -> Result<(Vec<u8>, RespHandles<CmdT>), u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut cmd_buffer = [0u8; 4096];
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
    written += marshal_handles(cmd.handles().as_ref(), &mut cmd_buffer[written..]);

    let session_size_pos = written;
    if !sessions.is_empty() {
        written += 4; // Reserve space for sessionSize
    }

    let sessions_start_pos = written;

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
    let mut command_handle_names = Vec::new();
    for i in 0..num_handles {
        let handle_bytes = [
            cmd_buffer[10 + i * 4],
            cmd_buffer[11 + i * 4],
            cmd_buffer[12 + i * 4],
            cmd_buffer[13 + i * 4],
        ];
        let handle = u32::from_be_bytes(handle_bytes);
        let name = entity_name(tpm, Handle(handle));
        command_handle_names.push(name);
    }

    // Generate new nonces and encrypt first parameter if needed
    let mut param_buf = [0u8; 4096];
    let param_len = marshal_to_slice(cmd, &mut param_buf);

    let mut nonce_callers_new = Vec::new();
    let mut decrypt_session_idx = None;
    let mut encrypt_session_idx = None;

    for (i, session) in sessions.iter_mut().enumerate() {
        let mut nonce_bytes = [0u8; 16];
        crate::_common::client_random(&mut nonce_bytes).unwrap();
        let nonce_caller_new =
            Tpm2bNonce::from_bytes(crate::test_utils::leak_bytes(&nonce_bytes)).unwrap();
        nonce_callers_new.push(nonce_caller_new);

        if session.attributes.contains(TpmaSession::DECRYPT) {
            decrypt_session_idx = Some(i);
        }
        if session.attributes.contains(TpmaSession::ENCRYPT) {
            encrypt_session_idx = Some(i);
        }
    }

    // Encrypt parameter if decrypt session is active
    if let Some(idx) = decrypt_session_idx {
        let session = &sessions[idx];
        let nonce_caller_new = &nonce_callers_new[idx];

        let leading_size = 2; // only 2B is supported
        let size = u16::from_be_bytes([param_buf[0], param_buf[1]]) as usize;

        let bits = match &session.symmetric {
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes128,
                ..
            }) => 128 + 128,
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes256,
                ..
            }) => 256 + 128,
            _ => 0,
        };

        if bits > 0 {
            let key = if idx < num_handles {
                [
                    session.session_key.as_slice(),
                    strip_trailing_zeros(entity_auths[idx]),
                ]
                .concat()
            } else {
                session.session_key.clone()
            };
            let (derived_key, derived_iv) = derive_key_and_iv_ref(
                CLIENT_CRYPTO,
                session.auth_hash,
                &key,
                b"CFB",
                nonce_caller_new.get_buffer(),
                session.nonce_tpm.get_buffer(),
                ((bits - 128) / 8) as usize,
            );

            let mut iv = derived_iv;
            let sym_alg = tpm2::TpmtSymDefObject::aes_cfb((derived_key.len() * 8) as u16).unwrap();
            sym_encrypt(
                CLIENT_CRYPTO,
                sym_alg,
                &derived_key,
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

        let cp_hash = compute_hash_with(CLIENT_CRYPTO, auth_hash, &cp_hash_updates);

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

        if i == 0 && i < session_to_handle_idx_len {
            if let Some(dec_idx) = decrypt_session_idx
                && dec_idx != i
            {
                hmac_updates.push(sessions[dec_idx].nonce_tpm.get_buffer());
            }
            if let Some(enc_idx) = encrypt_session_idx
                && enc_idx != i
                && Some(enc_idx) != decrypt_session_idx
            {
                hmac_updates.push(sessions[enc_idx].nonce_tpm.get_buffer());
            }
        }

        let attr_byte = [session.attributes.bits()];
        hmac_updates.push(&attr_byte);

        let hmac_bytes = compute_hmac_with(CLIENT_CRYPTO, auth_hash, &hmac_key, &hmac_updates);
        let hmac_val = Tpm2bAuth::from_bytes(&hmac_bytes).unwrap();

        let auth_cmd = TpmsAuthCommand {
            session_handle: Handle(session.session_handle.0),
            nonce: *nonce_caller_new,
            session_attributes: session.attributes,
            hmac: hmac_val,
        };

        auth_written += marshal_auth_command(&auth_cmd, &mut auth_buffer[auth_written..]);
    }

    // Marshal sessions into cmd_buffer
    if !sessions.is_empty() {
        let size_u32 = auth_written as u32;
        cmd_buffer[session_size_pos..session_size_pos + 4].copy_from_slice(&size_u32.to_be_bytes());
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
    cmd_header.marshal(&mut header_buf);
    cmd_buffer[..10].copy_from_slice(&header_buf[..10]);

    // Transact
    let mut resp_buffer = [0u8; 4096];
    let resp_bytes = tpm
        .transact(&cmd_buffer[..written], &mut resp_buffer)
        .unwrap();

    // Parse response
    let mut unmarsh: &'static [u8] = crate::test_utils::leak_bytes(resp_bytes);
    let resp_header = RespHeader::unmarshal(&mut unmarsh).unwrap();
    if resp_header.rc != 0 {
        return Err(resp_header.rc);
    }

    let mut resp_handles = RespHandles::<CmdT>::default();
    for handle in resp_handles.as_mut() {
        *handle = Handle::unmarshal(&mut unmarsh).unwrap();
    }

    let mut parameter_size = 0;
    if resp_header.tag == TpmSt::SESSIONS {
        parameter_size = u32::unmarshal(&mut unmarsh).unwrap() as usize;
    }
    // Get parameters slice
    let (encrypted_param_buf, rest) = unmarsh.split_at(parameter_size);
    unmarsh = rest;

    // The remaining bytes in unmarsh are the response sessions
    let mut unmarsh_sess: &[u8] = unmarsh;

    let mut nonce_tpms_new = Vec::new();
    let mut resp_attributes = Vec::new();
    let mut resp_hmacs = Vec::new();

    for _ in 0..sessions.len() {
        let auth_resp = TpmsAuthResponse::unmarshal(&mut unmarsh_sess).unwrap();
        nonce_tpms_new.push(auth_resp.nonce);
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
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes128,
                ..
            }) => 128 + 128,
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes256,
                ..
            }) => 256 + 128,
            _ => 0,
        };

        if bits > 0 {
            let key = if idx < num_handles {
                [
                    session.session_key.as_slice(),
                    strip_trailing_zeros(entity_auths[idx]),
                ]
                .concat()
            } else {
                session.session_key.clone()
            };
            let (derived_key, derived_iv) = derive_key_and_iv_ref(
                CLIENT_CRYPTO,
                session.auth_hash,
                &key,
                b"CFB",
                nonce_tpm_new.get_buffer(),
                nonce_caller_new.get_buffer(),
                ((bits - 128) / 8) as usize,
            );

            let mut iv = derived_iv;
            let sym_alg = tpm2::TpmtSymDefObject::aes_cfb((derived_key.len() * 8) as u16).unwrap();
            sym_decrypt(
                CLIENT_CRYPTO,
                sym_alg,
                &derived_key,
                &mut iv,
                &mut decrypted_param_buf[leading_size..leading_size + size],
            )
            .unwrap();
        }
    }

    // Update active sessions state for the caller
    for (i, session) in sessions.iter_mut().enumerate() {
        session.nonce_caller = nonce_callers_new[i];
        session.nonce_tpm = nonce_tpms_new[i];
    }

    Ok((decrypted_param_buf, resp_handles))
}

/// Like [`execute_with_hmac_sessions_custom`] but only returns the response handles (or the
/// response code).
pub fn execute_with_hmac_sessions_custom_status<CmdT: tpm2::commands::Command>(
    tpm: &mut Tpm,
    cmd: &CmdT,
    sessions: &mut [ActiveSession],
    entity_auths: &[&[u8]],
) -> Result<RespHandles<CmdT>, u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    execute_with_hmac_sessions_custom_raw(tpm, cmd, sessions, entity_auths).map(|(_, h)| h)
}

/// Expected SHA-256 policy digest after `TPM2_PolicyCommandCode(code)` on a digest of `old`.
pub fn expected_command_code_digest(old: &[u8], code: TpmCc) -> Vec<u8> {
    let mut data = old.to_vec();
    data.extend_from_slice(&TpmCc::PolicyCommandCode.code().to_be_bytes());
    data.extend_from_slice(&code.code().to_be_bytes());
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    tpm2::crypto::hash(CLIENT_CRYPTO, TpmiAlgHash::Sha256, &data, &mut out)
        .unwrap()
        .digest()
        .to_vec()
}

/// Expected SHA-1 PCR value after extending `old` with `val`: `SHA1(old || val)`.
pub fn expected_extend_sha1(old: &[u8; 20], val: &[u8; 20]) -> [u8; 20] {
    let mut data = [0u8; 40];
    data[..20].copy_from_slice(old);
    data[20..40].copy_from_slice(val);
    hash_array::<20>(TpmiAlgHash::Sha1, &data)
}

/// Expected SHA-256 PCR value after extending `old` with `val`: `SHA256(old || val)`.
pub fn expected_extend_sha256(old: &[u8; 32], val: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(old);
    data[32..64].copy_from_slice(val);
    hash_array::<32>(TpmiAlgHash::Sha256, &data)
}

/// Client-side HMAC-SHA256 of `data` under `key`.
pub fn expected_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    tpm2::crypto::hmac(CLIENT_CRYPTO, TpmiAlgHash::Sha256, key, data, &mut out)
        .unwrap()
        .digest()
        .to_vec()
}

/// Extends a SHA-256 session audit digest client-side with the command's cpHash and the response's
/// rpHash (`audit = H(audit || cpHash || rpHash)`).
pub fn extend_audit_digest_local(
    current_digest: &mut [u8; 32],
    cmd_code: TpmCc,
    handle_names: &[&[u8]],
    cmd_params: &[u8],
    resp_params: &[u8],
) {
    use sha2::Digest as _;
    // cpHash
    let mut cp_hasher = sha2::Sha256::new();
    cp_hasher.update(cmd_code.code().to_be_bytes());
    for name in handle_names {
        cp_hasher.update(name);
    }
    cp_hasher.update(cmd_params);
    let cp_hash = cp_hasher.finalize();

    // rpHash
    let mut rp_hasher = sha2::Sha256::new();
    rp_hasher.update(0u32.to_be_bytes()); // responseCode = TPM_RC_SUCCESS (0)
    rp_hasher.update(cmd_code.code().to_be_bytes());
    rp_hasher.update(resp_params);
    let rp_hash = rp_hasher.finalize();

    // extend digest: digest = SHA256(digest || cpHash || rpHash)
    let mut extend_hasher = sha2::Sha256::new();
    extend_hasher.update(current_digest.as_slice());
    extend_hasher.update(cp_hash.as_slice());
    extend_hasher.update(rp_hash.as_slice());
    current_digest.copy_from_slice(&extend_hasher.finalize());
}

/// A fixed point used for `TPM2_ECDH_ZGen` calls that must fail before the point is used.
pub fn fixed_zgen_point() -> Vec<u8> {
    let mut p = vec![0x00, 0x44, 0x00, 0x20];
    p.extend_from_slice(&[0x35; 32]);
    p.extend_from_slice(&[0x00, 0x20]);
    p.extend_from_slice(&[0xf8; 32]);
    p
}

/// `TPM2_GetSessionAuditDigest` with a NULL signing key; returns the session digest.
pub fn get_session_audit_digest(
    sim: &mut Tpm,
    privacy_admin_handle: Handle,
    session_handle: u32,
) -> Result<Vec<u8>, u32> {
    let mut resp_buffer = [0u8; 4096];
    let resp = execute_get_session_audit_digest(
        sim,
        &GetSessionAuditDigest {
            privacy_admin_handle,
            sign_handle: Handle::RH_NULL,
            session_handle: Handle(session_handle),
            qualifying_data: Tpm2bData::default(),
            in_scheme: None,
        },
        // One session per authorization handle, incl. the TPM_RH_NULL signHandle.
        2,
        &[],
        &mut resp_buffer,
    )?;
    match resp.audit_info.0.attested {
        TpmuAttest::SessionAudit(info) => Ok(info.session_digest.get_buffer().to_vec()),
        other => panic!("unexpected attestation: {other:?}"),
    }
}

/// Hashes `data` with `alg` using the client-side crypto provider.
pub fn hash(alg: TpmiAlgHash, data: &[u8]) -> Vec<u8> {
    let mut out = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    tpm2::crypto::hash(CLIENT_CRYPTO, alg, data, &mut out)
        .unwrap()
        .digest()
        .to_vec()
}

/// Hashes `data` with `alg` client-side and returns the digest as an `N`-byte array (panics if the
/// digest size differs).
pub fn hash_array<const N: usize>(alg: TpmiAlgHash, data: &[u8]) -> [u8; N] {
    let mut out = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    let d = tpm2::crypto::hash(CLIENT_CRYPTO, alg, data, &mut out)
        .unwrap()
        .digest();
    d.try_into().unwrap()
}

/// Hashes `data` with `alg` using the client-side crypto provider.
pub fn hash_bytes(alg: TpmiAlgHash, data: &[u8]) -> Vec<u8> {
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    tpm2::crypto::hash(CLIENT_CRYPTO, alg, data, &mut out)
        .unwrap()
        .digest()
        .to_vec()
}

/// Sends `_TPM_Hash_Data(data)`.
pub fn hash_data(sim: &mut Tpm, data: &[u8]) {
    sim.hash_data(data);
}

/// Sends `_TPM_Hash_End`.
pub fn hash_end(sim: &mut Tpm) {
    sim.hash_end();
}

/// Hashes the concatenation of `parts` with `alg` on the client.
pub fn hash_parts(alg: TpmiAlgHash, parts: &[&[u8]]) -> Vec<u8> {
    let mut ctx = tpm2::crypto::HashStream::new(CLIENT_CRYPTO, alg).unwrap();
    for p in parts {
        ctx.update(p).unwrap();
    }
    let mut out = [0u8; 64];
    ctx.finalize(&mut out).unwrap().digest().to_vec()
}

/// Builds a `TPM2_Hash("test", hash_alg, TPM_RH_NULL)` request with a raw `hashAlg`.
pub fn hash_request(hash_alg: u16) -> Vec<u8> {
    let mut hash_req = Vec::new();
    hash_req.extend_from_slice(&0x8001u16.to_be_bytes()); // NO_SESSIONS
    hash_req.extend_from_slice(&0u32.to_be_bytes()); // commandSize placeholder
    hash_req.extend_from_slice(&0x0000017du32.to_be_bytes()); // TPM_CC_Hash
    hash_req.extend_from_slice(&4u16.to_be_bytes()); // data size: 4
    hash_req.extend_from_slice(b"test"); // data
    hash_req.extend_from_slice(&hash_alg.to_be_bytes()); // hashAlg
    hash_req.extend_from_slice(&0x40000007u32.to_be_bytes()); // hierarchy: TPM_RH_NULL
    finish(hash_req)
}

/// `TPM2_HashSequenceStart` (SHA-256, empty auth); returns the sequence handle.
pub fn hash_sequence_start(sim: &mut Tpm) -> Handle {
    let cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    run(sim, &cmd, 0)
        .expect("HashSequenceStart")
        .sequence_handle
}

/// Sends `_TPM_Hash_Start`.
pub fn hash_start(sim: &mut Tpm) {
    sim.hash_start();
}

/// Returns the HMAC of the `TPM2_Hash` ticket produced for `hierarchy`. The ticket is keyed
/// with the hierarchy's proof value, so it changes exactly when the proof changes.
pub fn hash_ticket_digest(sim: &mut Tpm, hierarchy: Handle) -> Vec<u8> {
    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(b"proof probe").unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy,
    };
    let rsp = sim.execute(cmd).unwrap();
    rsp.validation.digest().get_buffer().to_vec()
}

/// HMAC of `data` under `key` with hash `hash`, computed client-side.
pub fn hmac(hash: TpmiAlgHash, key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut state = tpm2::crypto::HmacStream::new(CLIENT_CRYPTO, hash, key).unwrap();
    state.update(data).unwrap();
    let mut out = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    state.finalize(&mut out).unwrap().digest().to_vec()
}

/// HMAC-SHA-256 of the concatenation of `parts`.
pub fn hmac256(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut ctx = tpm2::crypto::HmacStream::new(CLIENT_CRYPTO, TpmiAlgHash::Sha256, key).unwrap();
    for p in parts {
        ctx.update(p).unwrap();
    }
    let mut out = [0u8; 64];
    ctx.finalize(&mut out).unwrap().digest().to_vec()
}

/// The authorization of `session` for a command with `cp_hash`, session attributes `attrs`
/// and entity authValue `auth_value`: `HMAC(sessionKey || authValue, cpHash || nonceCaller ||
/// nonceTPM || attrs)`.
pub fn hmac_auth(
    session: &ActiveSession,
    cp_hash: &[u8],
    attrs: u8,
    auth_value: &[u8],
) -> TpmsAuthCommand<'static> {
    let mut nonce = [0u8; 16];
    crate::_common::client_random(&mut nonce).unwrap();
    let key = [session.session_key.as_slice(), auth_value].concat();
    let hmac = hmac_sha256(
        &key,
        &[cp_hash, &nonce, session.nonce_tpm.get_buffer(), &[attrs]],
    );
    TpmsAuthCommand {
        session_handle: session.session_handle,
        nonce: Tpm2bNonce::from_bytes(leak_bytes(&nonce)).unwrap(),
        session_attributes: TpmaSession(attrs),
        hmac: Tpm2bAuth::from_bytes(leak_bytes(&hmac)).unwrap(),
    }
}

/// Builds an HMAC-session authorization (SHA-256 sessions only) for a command with the given
/// handle `names` and (unencrypted) `params`. The HMAC key is `sessionKey || entity_auth`
/// (`entity_auth` with trailing zeros removed); pass an empty `entity_auth` when the authValue
/// is not part of the key (bound sessions, policy sessions without PolicyAuthValue, sessions that
/// authorize no handle).
pub fn hmac_entry(
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
    crate::_common::client_random(&mut nonce).unwrap();
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

/// Signs `digest` with a new HMAC key in `hierarchy` and returns the key and signature.
pub fn hmac_key_and_signature(
    sim: &mut Tpm,
    hierarchy: Handle,
    digest: &'static [u8],
) -> (Handle, TpmtSignature<'static>) {
    let key = create_primary_with_auth_in(
        sim,
        hierarchy,
        hmac_template(
            base_attrs() | TpmaObject::SIGN_ENCRYPT,
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
        ),
        b"",
    );
    let signature = sign(sim, key, b"", digest, None).expect("HMAC sign failed");
    (key, signature)
}

/// Starts an unbound, unsalted SHA-256 HMAC session.
pub fn hmac_session(sim: &mut Sim) -> Sess {
    start_session(sim, TpmSe::HMAC, false)
}

/// HMAC-SHA-256 of the concatenation of `parts` under `key`, computed client-side.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut state = tpm2::crypto::HmacStream::new(CLIENT_CRYPTO, TpmiAlgHash::Sha256, key).unwrap();
    for part in parts {
        state.update(part).unwrap();
    }
    let mut out = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    state.finalize(&mut out).unwrap().digest().to_vec()
}

/// HMAC-SHA256 of `data` under `key`, computed with the client-side crypto provider.
pub fn hmac_sha256_single(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    tpm2::crypto::hmac(CLIENT_CRYPTO, TpmiAlgHash::Sha256, key, data, &mut out)
        .unwrap()
        .digest()
        .to_vec()
}

/// Returns `true` if `ticket` is the NULL hashcheck ticket.
pub fn is_null_hashcheck(ticket: &TpmtTkHashcheck<'_>) -> bool {
    ticket.hierarchy() == Handle::RH_NULL && ticket.digest().get_size() == 0
}

/// `KDFa(SHA-256, key, label, context, NULL, bits)`.
pub fn kdfa256(key: &[u8], label: &[u8], context: &[u8], bits: u32) -> Vec<u8> {
    let mut out = vec![0u8; bits.div_ceil(8) as usize];
    kdfa_by_alg(
        CLIENT_CRYPTO,
        TpmiAlgHash::Sha256,
        key,
        label,
        context,
        &[],
        bits,
        &mut out,
    );
    out
}

/// Loads a public-only keyed-hash HMAC key (fixed `unique`) with `TPM2_LoadExternal` and returns
/// its handle; panics on failure.
pub fn load_public_only_hmac_key(sim: &mut Tpm) -> Handle {
    let mut public = hmac_key_template(TpmiAlgHash::Sha256);
    public.object_attributes = TpmaObject::USER_WITH_AUTH | TpmaObject::SIGN_ENCRYPT;
    if let PublicParmsAndId::KeyedHash(_, ref mut unique) = public.parms_and_id {
        *unique = to_digest(&[0x42; 32]);
    }
    let rsp = sim
        .execute(LoadExternal {
            in_private: None,
            in_public: Tpm2b(public),
            hierarchy: Handle::RH_NULL,
        })
        .expect("LoadExternal (public only)");
    rsp.object_handle
}

/// Creates a keyed-hash (HMAC) primary key whose key is `key_bytes`.
pub fn make_keyed_hash_key(sim: &mut Tpm, key_bytes: &'static [u8]) -> Handle {
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            Tpm2bDigest::default(),
        ),
    };
    create_primary_with_auth_and_data(sim, public, b"", key_bytes).0
}

/// Reference check that `hash_alg` is an implemented hash (`TPM_RC_HASH + TPM_RC_P + TPM_RC_1`
/// otherwise).
pub fn oracle_validate_hash_alg(hash_alg: TpmiAlgHash) -> Result<(), TpmRc> {
    if hash_alg != TpmiAlgHash::Sha1
        && hash_alg != TpmiAlgHash::Sha256
        && hash_alg != TpmiAlgHash::Sha384
        && hash_alg != TpmiAlgHash::Sha512
    {
        return Err(TpmRc::HASH.with(Position::parameter(1)));
    }
    Ok(())
}

/// `[379]G` on NIST P-256, whose x coordinate starts with a zero byte. The point is returned
/// with that leading zero stripped (31-byte x), as TPM 2.0 encodings allow.
pub fn p256_point_with_stripped_x() -> TpmsEccPoint<'static> {
    TpmsEccPoint {
        x: Tpm2bEccParameter::from_bytes(leak_bytes(&unhex(
            "5543894af3d00ed7d740abdbd75c96b06877b787db5f70eea78b90a8d7c00a",
        )))
        .unwrap(),
        y: Tpm2bEccParameter::from_bytes(leak_bytes(&unhex(
            "bb4c85a3d8ea29efaafa24406912dd84d5b14dc32bf656ef6c6bd58a5d943f92",
        )))
        .unwrap(),
    }
}

/// Reference SP 800-108 counter-mode KDFa implementation (HMAC with `auth_hash`) producing `bits`
/// bits of output.
pub fn reference_kdfa<H: tpm2::crypto::Hmac>(
    crypto: &H,
    auth_hash: TpmiAlgHash,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    bits: u32,
) -> Vec<u8> {
    let required_bytes = bits.div_ceil(8) as usize;
    let mut out = vec![0u8; required_bytes];
    let mut counter = 1u32;
    let mut generated = 0;
    while generated < required_bytes {
        let mut state = tpm2::crypto::HmacStream::new(crypto, auth_hash, key).unwrap();
        state.update(&counter.to_be_bytes()).unwrap();
        state.update(label).unwrap();
        state.update(&[0x00]).unwrap();
        state.update(context_u).unwrap();
        state.update(context_v).unwrap();
        state.update(&bits.to_be_bytes()).unwrap();
        let mut mac_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
        let digest = state.finalize(&mut mac_buf).unwrap();
        let mac = digest.digest();
        let to_copy = std::cmp::min(mac.len(), required_bytes - generated);
        out[generated..generated + to_copy].copy_from_slice(&mac[..to_copy]);
        generated += to_copy;
        counter += 1;
    }
    out
}

/// `TPM2_RSA_Decrypt` parameters: `TPM2B("cipher12")`, `TPM_ALG_NULL` scheme, empty label.
pub fn rsa_decrypt_params() -> Vec<u8> {
    let mut p = 8u16.to_be_bytes().to_vec();
    p.extend_from_slice(b"cipher12");
    p.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]);
    p
}

/// An RSASSA-SHA256 RSA signing key.
pub fn rsa_signing_key() -> TpmtPublic<'static> {
    rsa_key(
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        None,
    )
}

/// Scenario: hashes `buffer_size` bytes through a `TPM2_HashSequenceStart`/`SequenceUpdate`/
/// `SequenceComplete` sequence (authValue `password`, ticket hierarchy `hierarchy`) and checks the
/// digest against a client-side hash.
pub fn run_hash_sequence(
    sim: &mut Tpm,
    buffer_size: usize,
    password: &str,
    hierarchy: Handle,
    hash_alg: TpmiAlgHash,
) {
    let max_digest_buffer = 1024;
    let auth_bytes = password.as_bytes();

    let cmd_start = HashSequenceStart {
        auth: Tpm2bAuth::from_bytes(auth_bytes).unwrap(),
        hash_alg: Some(hash_alg),
    };

    let resp_start = sim.execute(cmd_start).unwrap();
    let sequence_handle = resp_start.sequence_handle;

    let mut data = vec![0u8; buffer_size];
    crate::test_utils::client_rng().fill_bytes(&mut data);
    let expected_digest = match hash_alg {
        TpmiAlgHash::Sha1 => Sha1::digest(&data).to_vec(),
        TpmiAlgHash::Sha256 => Sha256::digest(&data).to_vec(),
        TpmiAlgHash::Sha384 => Sha384::digest(&data).to_vec(),
        TpmiAlgHash::Sha512 => Sha512::digest(&data).to_vec(),
        #[allow(unreachable_patterns)]
        _ => panic!("Unsupported hash algorithm for test"),
    };

    let mut remaining_data = data.as_slice();
    while remaining_data.len() > max_digest_buffer {
        let chunk = &remaining_data[..max_digest_buffer];
        let cmd_update = SequenceUpdate {
            sequence_handle,
            buffer: Tpm2bMaxBuffer::from_bytes(chunk).unwrap(),
        };
        execute_with_password_sessions(sim, &cmd_update, 1, auth_bytes)
            .expect("SequenceUpdate failed");
        remaining_data = &remaining_data[max_digest_buffer..];
    }

    let cmd_complete = SequenceComplete {
        sequence_handle,
        buffer: Tpm2bMaxBuffer::from_bytes(remaining_data).unwrap(),
        hierarchy,
    };
    let resp_complete = execute_with_password_sessions(sim, &cmd_complete, 1, auth_bytes)
        .expect("SequenceComplete failed");

    assert_eq!(resp_complete.result.as_ref(), expected_digest.as_slice());
}

/// Reads the session audit digest of `session` with `TPM2_GetSessionAuditDigest` (unsigned).
pub fn session_audit_digest(sim: &mut Tpm, session: u32) -> Vec<u8> {
    let resp = exec_pws(
        sim,
        &GetSessionAuditDigest {
            privacy_admin_handle: Handle::RH_ENDORSEMENT,
            sign_handle: Handle::RH_NULL,
            session_handle: Handle(session),
            qualifying_data: Tpm2bData::default(),
            in_scheme: None,
        },
        &[&[], &[]],
    )
    .unwrap_or_else(|rc| panic!("TPM2_GetSessionAuditDigest failed: {rc:#x}"));
    match resp.audit_info.0.attested {
        TpmuAttest::SessionAudit(info) => info.session_digest.get_buffer().to_vec(),
        other => panic!("Expected SessionAudit, got {other:?}"),
    }
}

/// Hash of the concatenation of `parts` with `hash`, computed client-side.
pub fn sha(hash: TpmiAlgHash, parts: &[&[u8]]) -> Vec<u8> {
    let mut state = tpm2::crypto::HashStream::new(CLIENT_CRYPTO, hash).unwrap();
    for part in parts {
        state.update(part).unwrap();
    }
    let mut out = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    state.finalize(&mut out).unwrap().digest().to_vec()
}

/// SHA-256 of the concatenation of `parts`, computed client-side.
pub fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut state = tpm2::crypto::HashStream::new(CLIENT_CRYPTO, TpmiAlgHash::Sha256).unwrap();
    for part in parts {
        state.update(part).unwrap();
    }
    let mut out = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    state.finalize(&mut out).unwrap().digest().to_vec()
}

/// Computes a SHA-256 digest client-side.
pub fn sha256_array(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut state = tpm2::crypto::HashStream::new(CLIENT_CRYPTO, TpmiAlgHash::Sha256).unwrap();
    state.update(data).unwrap();
    out.copy_from_slice(state.finalize(&mut [0u8; 64]).unwrap().digest());
    out
}

/// SHA-256 of `data` as a 32-byte array, computed client-side.
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    tpm2::crypto::hash(CLIENT_CRYPTO, TpmiAlgHash::Sha256, data, &mut out)
        .unwrap()
        .digest()
        .try_into()
        .unwrap()
}

/// Hashes `data` with a SHA-256 sequence: `updates` are `(start, end)` ranges of `data` sent
/// with `TPM2_SequenceUpdate`, and `data[complete_from..]` is sent with
/// `TPM2_SequenceComplete`. Returns the resulting digest.
pub fn sha256_sequence(
    sim: &mut Tpm,
    data: &[u8],
    updates: &[(usize, usize)],
    complete_from: usize,
) -> Vec<u8> {
    let start_cmd = HashSequenceStart {
        auth: Default::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let start_rsp = execute_tpm_command_auto_pw(sim, &start_cmd).unwrap();
    let handle = start_rsp.sequence_handle;

    for &(start, end) in updates {
        let update_cmd = SequenceUpdate {
            sequence_handle: handle,
            buffer: tpm2::Tpm2bMaxBuffer::from_bytes(&data[start..end]).unwrap(),
        };
        execute_tpm_command_auto_pw(sim, &update_cmd).unwrap();
    }

    let complete_cmd = SequenceComplete {
        sequence_handle: handle,
        buffer: tpm2::Tpm2bMaxBuffer::from_bytes(&data[complete_from..]).unwrap(),
        hierarchy: Handle::RH_NULL,
    };
    let resp = execute_tpm_command_auto_pw(sim, &complete_cmd).unwrap();
    resp.result.get_buffer().to_vec()
}

/// SHA-256 of `data`, computed with the client-side crypto provider.
pub fn sha256_single(data: &[u8]) -> Vec<u8> {
    let mut out = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    tpm2::crypto::hash(CLIENT_CRYPTO, TpmiAlgHash::Sha256, data, &mut out)
        .unwrap()
        .digest()
        .to_vec()
}

/// Runs TPM2_Sign with one password session.
#[allow(deprecated)] // `TPM2_Sign` is deprecated upstream.
pub fn sign(
    sim: &mut Tpm,
    key: Handle,
    auth: &[u8],
    digest: &'static [u8],
    in_scheme: Option<TpmtSigScheme>,
) -> Result<TpmtSignature<'static>, u32> {
    let cmd = Sign {
        key_handle: key,
        digest: Tpm2bDigest::from_bytes(digest).unwrap(),
        in_scheme,
        validation: TpmtTkHashcheck::new(Handle::RH_NULL, Tpm2bDigest::default()),
    };
    execute_with_password_sessions(sim, &cmd, 1, auth).map(|rsp| rsp.signature)
}

/// Builds a `TPM2_Sign` of a zero SHA-256 digest with `key_handle` (USER
/// role), for tests that need an HMAC session to authorize a handle.
#[allow(deprecated)] // `TPM2_Sign` is deprecated upstream.
pub fn sign_cmd_and_handles(key_handle: Handle) -> Sign<'static> {
    Sign {
        key_handle,
        digest: Tpm2bDigest::from_bytes(&[0u8; 32]).unwrap(),
        in_scheme: None,
        validation: TpmtTkHashcheck::default(),
    }
}

/// `TPM2_Sign` parameters: `TPM2B("digest12")`, `TPM_ALG_NULL` scheme and a NULL hashcheck ticket.
pub fn sign_params() -> Vec<u8> {
    let mut p = digest12();
    p.extend_from_slice(&[0x00, 0x10]);
    p.extend_from_slice(&[0x80, 0x24, 0x40, 0x00, 0x00, 0x07, 0x00, 0x00]);
    p
}

/// Signs `digest` (SHA-256) with `key` using RSASSA-PSS (`TPM2_Sign`).
#[allow(deprecated)] // `TPM2_Sign` is deprecated upstream.
pub fn sign_pss(sim: &mut Tpm, key: Handle, digest: &[u8]) -> TpmtSignature<'static> {
    let cmd = Sign {
        key_handle: key,
        digest: Tpm2bDigest::from_bytes(leak_bytes(digest)).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsapss(TpmiAlgHash::Sha256)),
        validation: TpmtTkHashcheck::default(),
    };
    let rsp = execute_with_password_sessions(sim, &cmd, 1, &[]).expect("Sign failed");
    rsp.signature
}

/// Signs `digest` with `key` using `scheme` (`TPM2_Sign`).
#[allow(deprecated)] // `TPM2_Sign` is deprecated upstream.
pub fn sign_unwrap(
    sim: &mut Tpm,
    key: Handle,
    digest: &[u8],
    scheme: TpmtSigScheme,
) -> TpmtSignature<'static> {
    let cmd = Sign {
        key_handle: key,
        digest: Tpm2bDigest::from_bytes(leak_bytes(digest)).unwrap(),
        in_scheme: Some(scheme),
        validation: TpmtTkHashcheck::default(),
    };
    let rsp = execute_with_password_sessions(sim, &cmd, 1, &[]).expect("Sign failed");
    rsp.signature
}

/// Starts a hash (or event, for `None`) sequence with an empty auth value.
pub fn start_hash_sequence(sim: &mut Tpm, alg: Option<TpmiAlgHash>) -> Handle {
    let cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: alg,
    };
    let rsp = execute_with_password_sessions(sim, &cmd, 0, &[]).unwrap();
    rsp.sequence_handle
}

/// Starts an unbound, unsalted SHA-256 HMAC session.
pub fn start_hmac_session(sim: &mut Tpm) -> ActiveSession {
    start_auth_session(
        sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("StartAuthSession failed")
}

/// Starts an HMAC session (see [`start_session`]).
pub fn start_hmac_session_raw(sim: &mut Tpm) -> u32 {
    start_session_raw_attrs(sim, 0x00)
}

/// Starts an unbound, unsalted session of `session_type` (flushing all other sessions).
pub fn start_session_with_hash(
    sim: &mut Tpm,
    session_type: TpmSe,
    hash: TpmiAlgHash,
) -> ActiveSession {
    start_keep(sim, session_type, hash, &[])
}

/// Wraps `bytes` in a `'static` `Tpm2bDigest` (panics if too long).
pub fn to_digest(bytes: &[u8]) -> Tpm2bDigest<'static> {
    Tpm2bDigest::from_bytes(leak_bytes(bytes)).unwrap()
}

/// Computes a policy digest by running `f` on a fresh trial session.
pub fn trial_digest(sim: &mut Sim, f: impl FnOnce(&mut Sim, u32)) -> Vec<u8> {
    let t = start_session(sim, TpmSe::Trial, false);
    f(sim, t.handle);
    let digest = policy_get_digest_raw(sim, t.handle);
    flush(sim, t.handle);
    digest
}

/// `TPM2_VerifySignature` parameters: `TPM2B("digest12")` and an HMAC-SHA256 signature.
pub fn verify_hmac_params(hmac: &[u8; 32]) -> Vec<u8> {
    let mut p = digest12();
    p.extend_from_slice(&[0x00, 0x05, 0x00, 0x0b]);
    p.extend_from_slice(hmac);
    p
}

/// Runs TPM2_VerifySignature (no sessions).
#[allow(deprecated)] // `TPM2_VerifySignature` is deprecated upstream.
pub fn verify_signature(
    sim: &mut Tpm,
    key: Handle,
    digest: &'static [u8],
    signature: TpmtSignature<'static>,
) -> Result<TpmtTkVerified<'static>, u32> {
    let cmd = VerifySignature {
        key_handle: key,
        digest: Tpm2bDigest::from_bytes(digest).unwrap(),
        signature,
    };
    execute_with_password_sessions(sim, &cmd, 0, &[]).map(|rsp| rsp.validation)
}

/// `TPM2_VerifySignature` of an RSASSA-PSS signature over `digest`; returns the ticket.
#[allow(deprecated)] // `TPM2_VerifySignature` is deprecated upstream.
pub fn verify_signature_unwrap(
    sim: &mut Tpm,
    key: Handle,
    digest: &[u8],
    signature: TpmtSignature<'static>,
) -> TpmtTkVerified<'static> {
    run_command(
        sim,
        VerifySignature {
            key_handle: key,
            digest: Tpm2bDigest::from_bytes(leak_bytes(digest)).unwrap(),
            signature,
        },
    )
    .expect("VerifySignature failed")
    .validation
}

/// Writes `alg || digest` (a `TPMT_HA`) to NV index `nv_index_val` with an owner password session,
/// as expected by `TPM2_PolicyAuthorizeNV`; panics on failure.
pub fn write_digest_to_nv(sim: &mut Tpm, nv_index_val: u32, alg: TpmiAlgHash, digest: &[u8]) {
    let mut data = Vec::new();
    data.extend_from_slice(&Alg::from(alg).id().to_be_bytes());
    data.extend_from_slice(digest);

    let write_cmd = NVWrite {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(&data).unwrap(),
        offset: 0,
    };
    execute_with_password_sessions(sim, &write_cmd, 1, &[]).unwrap();
}

// ===========================================================================
// PCR helpers
//
// PCR selection, read, extend, event and reset helpers.
// ===========================================================================

/// Parsed `TPM2_PCR_Read` response.
pub struct PcrReadRsp {
    pub update_counter: u32,
    pub selection_out: Vec<(u16, Vec<u8>)>,
    pub values: Vec<Vec<u8>>,
}

/// Returns the number of PCR banks in which `pcr` is allocated (`TPM_CAP_PCRS`).
pub fn allocated_banks_for_pcr(sim: &mut Tpm, pcr: usize) -> u32 {
    let cmd = tpm2::commands::GetCapability {
        capability: TpmCap::PCRs,
        property: 0,
        property_count: 16,
    };
    let mut buf = [0u8; 4096];
    let rsp = execute_get_capability(sim, &cmd, 0, &[], &mut buf).unwrap();
    match rsp.capability_data {
        TpmsCapabilityData::AssignedPcr(sel) => sel
            .pcr_selections()
            .filter(|s| {
                s.pcr_select()
                    .get(pcr / 8)
                    .is_some_and(|b| b & (1 << (pcr % 8)) != 0)
            })
            .count() as u32,
        _ => panic!("unexpected capability data"),
    }
}

/// The PCR selection of the `alg` bank in the active allocation (`TPM_CAP_PCRS`); an absent
/// bank is reported as an empty selection.
pub fn allocated_pcrs(sim: &mut Tpm, alg: TpmiAlgHash) -> Vec<u8> {
    let rsp = sim
        .execute(GetCapability {
            capability: TpmCap::PCRs,
            property: 0,
            property_count: 1,
        })
        .unwrap();
    let TpmsCapabilityData::AssignedPcr(selection) = rsp.capability_data else {
        panic!("expected TPM_CAP_PCRS data");
    };
    selection
        .pcr_selections()
        .find(|s| s.hash() == alg)
        .map(|s| s.pcr_select().to_vec())
        .unwrap_or_else(|| vec![0, 0, 0])
}

/// Returns the list of `(tag, pcrSelect)` from `TPM_CAP_PCR_PROPERTIES` and `moreData`.
pub fn cap_pcr_properties(sim: &mut Tpm, property: u32, count: u32) -> (Vec<(u32, Vec<u8>)>, bool) {
    let (more, data) = get_cap(sim, CAP_PCR_PROPERTIES, property, count)
        .unwrap_or_else(|rc| panic!("GetCapability(PCR_PROPERTIES) failed: {rc:#x}"));
    let n = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
    let mut off = 4;
    let mut out = Vec::new();
    for _ in 0..n {
        let tag = u32::from_be_bytes(data[off..off + 4].try_into().unwrap());
        let size = data[off + 4] as usize;
        out.push((tag, data[off + 5..off + 5 + size].to_vec()));
        off += 5 + size;
    }
    (out, more)
}

/// Returns the active allocation reported by `TPM2_GetCapability(TPM_CAP_PCRS)`.
pub fn cap_pcrs(sim: &mut Tpm) -> Vec<(u16, Vec<u8>)> {
    let mut params = Vec::new();
    params.extend_from_slice(&5u32.to_be_bytes()); // TPM_CAP_PCRS
    params.extend_from_slice(&0u32.to_be_bytes());
    params.extend_from_slice(&1u32.to_be_bytes());
    let cmd = build_raw_cmd(ST_NO_SESSIONS, 0x17A, &[], None, &params);
    let (rc, resp) = send_with_rc(sim, &cmd);
    assert_eq!(rc, 0, "GetCapability(PCRS) failed: {rc:#x}");
    let p = &resp[10 + 1 + 4..];
    let count = u32::from_be_bytes(p[0..4].try_into().unwrap()) as usize;
    let mut off = 4;
    let mut out = Vec::new();
    for _ in 0..count {
        let alg = u16::from_be_bytes(p[off..off + 2].try_into().unwrap());
        let size = p[off + 2] as usize;
        out.push((alg, p[off + 3..off + 3 + size].to_vec()));
        off += 3 + size;
    }
    out
}

/// Client-side expected `TPM2_PolicyPCR` digest from a zero policy for `pcrs` and the given PCR
/// values.
pub fn expected_policy_pcr(
    hash: TpmiAlgHash,
    pcrs: &[TpmsPcrSelection],
    pcr_values: &[&[u8]],
) -> Vec<u8> {
    let zero = vec![0u8; sha(hash, &[]).len()];
    let pcr_digest = sha(hash, pcr_values);
    sha(
        hash,
        &[
            &zero,
            &CC_POLICY_PCR.to_be_bytes(),
            &marshal_pcrs(pcrs),
            &pcr_digest,
        ],
    )
}

/// Marshals `pcrs` as a `TPML_PCR_SELECTION`.
pub fn marshal_pcrs(pcrs: &[TpmsPcrSelection]) -> Vec<u8> {
    marshal_to_vec(&TpmlPcrSelection::from_slice(pcrs).unwrap())
}

/// PCR selection of PCR 0 in the SHA-256 bank.
pub fn pcr0_sha256_selection() -> TpmlPcrSelection {
    TpmlPcrSelection::from_slice(&[
        TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0x01, 0x00, 0x00]).unwrap(),
    ])
    .unwrap()
}

/// Builds a `TPM2_PCR_Extend(PCR 20)` command authorized by the policy
/// session `session` (empty nonce, continueSession, empty HMAC/password).
pub fn pcr20_extend_with_policy_session(session: Handle) -> Vec<u8> {
    let mut cmd = Vec::new();
    cmd.extend_from_slice(&0x8002u16.to_be_bytes()); // TPM_ST_SESSIONS
    cmd.extend_from_slice(&[0u8; 4]); // size, patched below
    cmd.extend_from_slice(&TpmCc::PCRExtend.code().to_be_bytes());
    cmd.extend_from_slice(&20u32.to_be_bytes()); // pcrHandle: PCR 20
    cmd.extend_from_slice(&9u32.to_be_bytes()); // authSize
    cmd.extend_from_slice(&session.0.to_be_bytes());
    cmd.extend_from_slice(&0u16.to_be_bytes()); // nonce: empty
    cmd.push(0x01); // attributes: continueSession
    cmd.extend_from_slice(&0u16.to_be_bytes()); // hmac: empty (PolicyPassword, empty authValue)
    cmd.extend_from_slice(&1u32.to_be_bytes()); // count: 1 digest
    cmd.extend_from_slice(&0x0004u16.to_be_bytes()); // SHA1
    cmd.extend_from_slice(&[0x5a; 20]);
    let size = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&size.to_be_bytes());
    cmd
}

/// `TPM2_PCR_Allocate` with platform authorization; returns the response code and the
/// response parameters (`allocationSuccess`, `maxPCR`, `sizeNeeded`, `sizeAvailable`).
pub fn pcr_allocate(sim: &mut Tpm, banks: &[(u16, [u8; 3])]) -> (u32, Option<(u8, u32, u32, u32)>) {
    let cmd = build_pw_cmd(
        CC_PCR_ALLOCATE,
        &[Handle::RH_PLATFORM.0],
        1,
        &pcr_selection(banks),
    );
    let (rc, resp) = send_with_rc(sim, &cmd);
    if rc != 0 {
        return (rc, None);
    }
    let p = session_rsp_params(&resp, 0);
    let be = |o: usize| u32::from_be_bytes(p[o..o + 4].try_into().unwrap());
    (rc, Some((p[0], be(1), be(5), be(9))))
}

/// Builds a raw `TPM2_PCR_Allocate(authHandle)` command with an empty password session.
pub fn pcr_allocate_cmd(auth_handle: Handle, selections: &[TpmsPcrSelection]) -> Vec<u8> {
    let cmd = PCRAllocate {
        auth_handle,
        pcr_allocation: TpmlPcrSelection::from_slice(selections).unwrap(),
    };
    let mut req = Vec::new();
    req.extend_from_slice(&0x8002u16.to_be_bytes());
    req.extend_from_slice(&[0u8; 4]);
    req.extend_from_slice(&TpmCc::PCRAllocate.code().to_be_bytes());
    for handle in cmd.handles() {
        req.extend_from_slice(&handle.0.to_be_bytes());
    }
    // authHandle (platform) has the USER auth role; C requires a session even for an empty
    // authValue (TPM_RC_AUTH_MISSING otherwise, SessionProcess.c CheckAuthNoSession).
    req.extend_from_slice(&PW_AREA);
    req.extend_from_slice(&marshal_to_vec(&cmd));
    let len = req.len() as u32;
    req[2..6].copy_from_slice(&len.to_be_bytes());
    req
}

/// `TPM2_PCR_Event(pcr)` at `locality`; returns the response code and the response.
pub fn pcr_event_at(sim: &mut Tpm, locality: u8, pcr: u32, data: &[u8]) -> (u32, Vec<u8>) {
    let mut params = (data.len() as u16).to_be_bytes().to_vec();
    params.extend_from_slice(data);
    let cmd = build_pw_cmd(CC_PCR_EVENT, &[pcr], 1, &params);
    send_at(sim, locality, &cmd)
}

/// `TPM2_PCR_Event(pcr)` at `locality`, authorized with an empty password; returns the response
/// code and, on success, the returned digests.
pub fn pcr_event_at_digests(
    sim: &mut Tpm,
    locality: u8,
    pcr: u32,
    data: &[u8],
) -> (u32, Option<TpmlDigestValues<'static>>) {
    let mut params = (data.len() as u16).to_be_bytes().to_vec();
    params.extend_from_slice(data);
    let cmd = build_raw_cmd(
        ST_SESSIONS,
        CC_PCR_EVENT,
        &[pcr],
        Some(&PW_SESSION),
        &params,
    );
    let (rc, resp) = send_at(sim, locality, &cmd);
    if rc != 0 {
        return (rc, None);
    }
    // Skip the parameterSize field of the TPM_ST_SESSIONS response.
    let mut p: &'static [u8] = leak_bytes(&resp[14..]);
    (rc, Some(TpmlDigestValues::unmarshal(&mut p).unwrap()))
}

/// `TPM2_PCR_Extend(pcr)` at `locality`, authorized with an empty password.
pub fn pcr_extend_at(sim: &mut Tpm, locality: u8, pcr: u32, digests: &[(u16, Vec<u8>)]) -> u32 {
    let cmd = build_pw_cmd(CC_PCR_EXTEND, &[pcr], 1, &digest_values(digests));
    send_at(sim, locality, &cmd).0
}

/// `TPM2_PCR_Extend(pcr)` at `locality`, authorized with an empty password.
pub fn pcr_extend_at_no_continue(
    sim: &mut Tpm,
    locality: u8,
    pcr: u32,
    digests: &[(u16, Vec<u8>)],
) -> u32 {
    let cmd = build_raw_cmd(
        ST_SESSIONS,
        CC_PCR_EXTEND,
        &[pcr],
        Some(&PW_SESSION),
        &digest_values(digests),
    );
    send_at(sim, locality, &cmd).0
}

/// Sends `TPM2_PCR_Read` for `banks` and parses the response.
pub fn pcr_read(sim: &mut Tpm, banks: &[(u16, [u8; 3])]) -> PcrReadRsp {
    let cmd = build_raw_cmd(
        ST_NO_SESSIONS,
        CC_PCR_READ,
        &[],
        None,
        &pcr_selection(banks),
    );
    let (rc, resp) = send_with_rc(sim, &cmd);
    assert_eq!(rc, 0, "PCR_Read failed: {rc:#x}");
    let p = &resp[10..];
    let update_counter = u32::from_be_bytes(p[0..4].try_into().unwrap());
    let count = u32::from_be_bytes(p[4..8].try_into().unwrap()) as usize;
    let mut off = 8;
    let mut selection_out = Vec::new();
    for _ in 0..count {
        let alg = u16::from_be_bytes(p[off..off + 2].try_into().unwrap());
        let size = p[off + 2] as usize;
        selection_out.push((alg, p[off + 3..off + 3 + size].to_vec()));
        off += 3 + size;
    }
    let n = u32::from_be_bytes(p[off..off + 4].try_into().unwrap()) as usize;
    off += 4;
    let mut values = Vec::new();
    for _ in 0..n {
        let size = u16::from_be_bytes(p[off..off + 2].try_into().unwrap()) as usize;
        values.push(p[off + 2..off + 2 + size].to_vec());
        off += 2 + size;
    }
    PcrReadRsp {
        update_counter,
        selection_out,
        values,
    }
}

/// Runs `TPM2_PCR_Read` for `selection`, returning the response or the response code.
pub fn pcr_read_selection(
    sim: &mut Tpm,
    selection: TpmlPcrSelection,
) -> Result<responses::PCRRead<'static>, u32> {
    exec_command(
        sim,
        &PCRRead {
            pcr_selection_in: selection,
        },
        &[],
    )
}

/// `TPM2_PCR_Reset(pcr)` at `locality`.
pub fn pcr_reset_at(sim: &mut Tpm, locality: u8, pcr: u32) -> u32 {
    let cmd = build_pw_cmd(CC_PCR_RESET, &[pcr], 1, &[]);
    send_at(sim, locality, &cmd).0
}

/// `TPM2_PCR_Reset(pcr)` at `locality`, authorized with an empty password.
pub fn pcr_reset_at_no_continue(sim: &mut Tpm, locality: u8, pcr: u32) -> u32 {
    let cmd = build_raw_cmd(ST_SESSIONS, CC_PCR_RESET, &[pcr], Some(&PW_SESSION), &[]);
    send_at(sim, locality, &cmd).0
}

/// `TPMS_PCR_SELECTION` for bank `hash` with the raw select bitmap `select`.
pub fn pcr_sel(hash: TpmiAlgHash, select: &[u8]) -> TpmsPcrSelection {
    TpmsPcrSelection::new(hash, select).unwrap()
}

/// Marshals a `TPML_PCR_SELECTION` from `(hashAlg, pcrSelect)` pairs.
pub fn pcr_selection(banks: &[(u16, [u8; 3])]) -> Vec<u8> {
    let mut v = (banks.len() as u32).to_be_bytes().to_vec();
    for (alg, bits) in banks {
        v.extend_from_slice(&alg.to_be_bytes());
        v.push(3);
        v.extend_from_slice(bits);
    }
    v
}

/// `TPMS_PCR_SELECTION` for bank `hash` selecting the PCR indices in `pcrs` (indices >= 32 are
/// ignored).
pub fn pcr_selection_of(hash: TpmiAlgHash, pcrs: &[u32]) -> TpmsPcrSelection {
    let mut pcr_select = [0u8; TPM2_PCR_SELECT_MAX as usize];
    let mut max_pcr = 0;
    for &pcr in pcrs {
        if pcr < 32 {
            let byte_idx = (pcr / 8) as usize;
            let bit_idx = (pcr % 8) as usize;
            pcr_select[byte_idx] |= 1 << bit_idx;
            if pcr > max_pcr {
                max_pcr = pcr;
            }
        }
    }
    let sizeof_select = if pcrs.is_empty() {
        3
    } else {
        std::cmp::max(3, (max_pcr / 8) + 1) as u8
    };
    TpmsPcrSelection::new(hash, &pcr_select[..sizeof_select as usize]).unwrap()
}

/// `TPML_PCR_SELECTION` with a single bank `hash` selecting `pcrs`.
pub fn pcr_selections(hash: TpmiAlgHash, pcrs: &[u32]) -> TpmlPcrSelection {
    TpmlPcrSelection::from_slice(&[pcr_selection_of(hash, pcrs)]).unwrap()
}

/// Reads the PCR update counter.
pub fn pcr_update_counter(sim: &mut Tpm) -> u32 {
    sim.execute(PCRRead {
        pcr_selection_in: TpmlPcrSelection::default(),
    })
    .unwrap()
    .pcr_update_counter
}

/// Runs `TPM2_PolicyPCR` on policy `session`, returning the response code on failure.
pub fn policy_pcr(
    sim: &mut Tpm,
    session: Handle,
    pcr_digest: &[u8],
    pcrs: &[TpmsPcrSelection],
) -> Result<(), u32> {
    run_command(
        sim,
        PolicyPCR {
            policy_session: session,
            pcr_digest: to_digest(pcr_digest),
            pcrs: TpmlPcrSelection::from_slice(pcrs).unwrap(),
        },
    )
    .map(|_| ())
}

/// Reads PCR `pcr` of the `alg` bank with `TPM2_PCR_Read`. Returns `None` if the TPM
/// returns no digest for it (e.g. the bank is not allocated).
pub fn read_pcr(sim: &mut Tpm, alg: TpmiAlgHash, pcr: usize) -> Option<Vec<u8>> {
    let mut select = [0u8; 3];
    select[pcr / 8] = 1 << (pcr % 8);
    let mut pcr_selection_in = TpmlPcrSelection::default();
    pcr_selection_in
        .add(&TpmsPcrSelection::new(alg, &select).unwrap())
        .unwrap();
    let resp = execute_tpm_command_at_locality0(sim, &PCRRead { pcr_selection_in }, &[]).unwrap();
    resp.pcr_values
        .digests()
        .first()
        .map(|d| d.get_buffer().to_vec())
}

/// Reads the value of `pcr` in bank `alg`, or `None` if the bank is not allocated.
pub fn read_pcr_by_alg_id(sim: &mut Tpm, alg: u16, pcr: usize) -> Option<Vec<u8>> {
    let rsp = pcr_read(sim, &[(alg, bit(pcr))]);
    assert!(rsp.values.len() <= 1);
    rsp.values.into_iter().next()
}

/// Reads one PCR of one bank with `TPM2_PCR_Read`.
pub fn read_pcr_value(sim: &mut Tpm, alg: TpmiAlgHash, pcr: usize) -> Vec<u8> {
    let mut select = [0u8; 3];
    select[pcr / 8] = 1 << (pcr % 8);
    let mut selection = TpmlPcrSelection::default();
    selection
        .add(&TpmsPcrSelection::new(alg, &select).unwrap())
        .unwrap();
    let rsp = sim
        .execute(PCRRead {
            pcr_selection_in: selection,
        })
        .unwrap();
    assert_eq!(rsp.pcr_values.count(), 1);
    rsp.pcr_values.digests()[0].get_buffer().to_vec()
}

// ===========================================================================
// NV index helpers
//
// NV index definition, read/write and NV name helpers.
// ===========================================================================

/// Sets the owner policy to `TPM2_PolicyNvWritten(YES)` and uses a satisfying policy session to
/// authorize the owner hierarchy (not an NV index): `TPM_RC_POLICY_FAIL + RC_S1`.
pub fn check_nv_written_on_non_nv_entity(sim: &mut Sim) {
    let digest = trial_digest(sim, |sim, t| {
        assert_eq!(policy_cmd(sim, CC_POLICY_NV_WRITTEN, t, &[0x01]), 0);
    });
    set_owner_policy(sim, &digest, &[]);
    let mut p = start_session(sim, TpmSe::Policy, false);
    assert_eq!(policy_cmd(sim, CC_POLICY_NV_WRITTEN, p.handle, &[0x01]), 0);
    let rc = exec(
        sim,
        CC_CREATE_PRIMARY,
        &[RH_OWNER],
        &mut [SessUse::hmac(&mut p, ATTR_CONT, &[])],
        &create_primary_params(),
        1,
    )
    .rc;
    assert_eq!(rc, rc_s1(RC_POLICY_FAIL));
}

/// Defines a policy-read/write NV index (`0x01800001`) and returns its handle and Name; panics on
/// failure.
pub fn create_nv_index(sim: &mut Tpm) -> (Handle, Tpm2bName<'static>) {
    let nv_public = TpmsNvPublic {
        nv_index: Handle(0x01800001),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE
            | TpmaNv::AUTHREAD
            | TpmaNv::POLICYREAD
            | TpmaNv::POLICYWRITE,
        auth_policy: Tpm2bDigest::default(),
        data_size: 32,
    };
    let in_public = tpm2::Tpm2b(nv_public);
    let def_space = tpm2::commands::NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        public_info: in_public,
        auth: Tpm2bAuth::default(),
    };
    execute_with_password_sessions(sim, &def_space, 1, &[]).expect("could not define NV space");

    // Read the NV index Name
    let read_pub = tpm2::commands::NVReadPublic {
        nv_index: Handle(0x01800001),
    };
    let read_pub_rsp =
        execute_with_password_sessions(sim, &read_pub, 0, &[]).expect("could not read NV public");

    (Handle(0x01800001), read_pub_rsp.nv_name)
}

/// Defines owner NV index `index` with empty authValue/policy, `attributes` and `size` bytes;
/// panics on failure.
pub fn define_nv(sim: &mut Tpm, index: u32, attributes: TpmaNv, size: u16) {
    let cmd = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info: Tpm2b(TpmsNvPublic {
            nv_index: Handle(index),
            name_alg: TpmiAlgHash::Sha256,
            attributes,
            auth_policy: Tpm2bDigest::default(),
            data_size: size,
        }),
    };
    execute_with_password_sessions(sim, &cmd, 1, &[])
        .unwrap_or_else(|rc| panic!("NV_DefineSpace({index:#x}) failed: {rc:#x}"));
}

/// Defines an owner-created NV Index with an empty authValue.
pub fn define_nv_empty_policy(sim: &mut Tpm, index: u32, attributes: TpmaNv, data_size: u16) {
    define_nv_with_policy(sim, index, attributes, data_size, &[]);
}

/// Defines an owner NV Index with the given attributes, authValue and authPolicy.
pub fn define_nv_raw(
    sim: &mut Tpm,
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
    let code = send_rc_with_auth_entries(
        sim,
        TpmCc::NVDefineSpace,
        &[Handle::RH_OWNER.0],
        &[AuthEntry::pw(&[])],
        &params,
    );
    assert_eq!(code, RC_SUCCESS, "NV_DefineSpace");
}

/// Defines an NV index with an empty authValue and policy, authorized by `auth_handle` with an
/// empty password session.
pub fn define_nv_space(
    sim: &mut Tpm,
    auth_handle: Handle,
    nv_index: Handle,
    attributes: TpmaNv,
    data_size: u16,
) -> Result<(), u32> {
    execute_with_password_sessions(
        sim,
        &NVDefineSpace {
            auth_handle,
            auth: Tpm2bAuth::default(),
            public_info: Tpm2b(TpmsNvPublic {
                nv_index,
                name_alg: TpmiAlgHash::Sha256,
                attributes,
                auth_policy: Tpm2bDigest::default(),
                data_size,
            }),
        },
        1,
        &[],
    )
    .map(|_| ())
}

/// Defines owner NV index `index` with empty authValue and authPolicy `auth_policy`; panics on
/// failure.
pub fn define_nv_with_policy(
    sim: &mut Tpm,
    index: u32,
    attributes: TpmaNv,
    data_size: u16,
    auth_policy: &[u8],
) {
    let public = TpmsNvPublic {
        nv_index: Handle(index),
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: to_digest(auth_policy),
        data_size,
    };
    run_pw(
        sim,
        NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: Tpm2b(public),
        },
    )
    .expect("NV_DefineSpace");
}

/// Defines an owner index with an empty authValue.
pub fn define_nv_with_policy_unwrap(
    sim: &mut Tpm,
    index: u32,
    attributes: TpmaNv,
    size: u16,
    policy: &[u8],
) {
    try_define(
        sim,
        Handle::RH_OWNER,
        &[],
        nv_public(index, attributes, size, policy),
    )
    .unwrap_or_else(|rc| panic!("NV_DefineSpace({index:#x}) failed: {rc:#x}"));
}

/// `TPMA_NV` for an owner-written index with authValue reads.
pub fn nv_attrs(extra: TpmaNv) -> TpmaNv {
    TpmaNv::OWNERWRITE | TpmaNv::AUTHREAD | extra
}

/// `TPM2_NV_Certify(signHandle, authHandle, nvIndex)` with password sessions; returns the
/// attestation structure.
#[allow(clippy::too_many_arguments)]
pub fn nv_certify(
    sim: &mut Tpm,
    sign_handle: Handle,
    auth_handle: Handle,
    nv_index: Handle,
    in_scheme: Option<TpmtSigScheme>,
    size: u16,
    offset: u16,
    sessions: usize,
) -> Result<TpmsAttest<'static>, u32> {
    let cmd = NVCertify {
        sign_handle,
        auth_handle,
        nv_index,
        qualifying_data: Tpm2bData::default(),
        in_scheme,
        size,
        offset,
    };
    execute_with_password_sessions(sim, &cmd, sessions, &[]).map(|rsp| rsp.certify_info.0)
}

/// Runs `TPM2_NV_Certify` with one password session per authorization handle: `sign_auth` for
/// `signHandle` (empty for `TPM_RH_NULL`) and `nv_auth` for `authHandle`. Every authorization
/// handle needs a session, including a `TPM_RH_NULL` signHandle (C `ParseSessionBuffer`).
pub fn nv_certify_pw(
    sim: &mut Tpm,
    cmd: &NVCertify<'_>,
    sign_auth: &[u8],
    nv_auth: &[u8],
) -> Result<(), u32> {
    use crate::test_utils::{RespHeader, marshal_to_vec};
    let mut auth_area = Vec::new();
    for auth in [sign_auth, nv_auth] {
        auth_area.extend_from_slice(&marshal_to_vec(&tpm2::TpmsAuthCommand {
            session_handle: Handle::RS_PW,
            nonce: tpm2::Tpm2bNonce::default(),
            session_attributes: tpm2::TpmaSession(1),
            hmac: Tpm2bAuth::from_bytes(auth).unwrap(),
        }));
    }
    let mut body = Vec::new();
    for handle in cmd.handles() {
        body.extend_from_slice(&handle.0.to_be_bytes());
    }
    body.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
    body.extend_from_slice(&auth_area);
    body.extend_from_slice(&marshal_to_vec(cmd));
    let mut command = Vec::new();
    command.extend_from_slice(&0x8002u16.to_be_bytes());
    command.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    command.extend_from_slice(&tpm2::TpmCc::NVCertify.code().to_be_bytes());
    command.extend_from_slice(&body);
    let mut response = [0u8; 4096];
    sim.transact(&command, &mut response).unwrap();
    let rc = RespHeader::unmarshal(&mut &response[..]).unwrap().rc;
    if rc != 0 { Err(rc) } else { Ok(()) }
}

/// Reads the current Name of an NV Index (it changes when TPMA_NV_WRITTEN is set).
pub fn nv_index_name(sim: &mut Tpm, index: u32) -> Vec<u8> {
    let rsp = sim
        .execute(NVReadPublic {
            nv_index: Handle(index),
        })
        .expect("NV_ReadPublic failed");
    rsp.nv_name.get_buffer().to_vec()
}

/// Makes NV unavailable to the TPM.
pub fn nv_off(sim: &mut Tpm) {
    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
}

/// Powers on the TPM (`_TPM_Init`), makes NV available and sends
/// `TPM2_Startup(TPM_SU_CLEAR)`, as a platform does at boot.
///
/// Panics if a signal or the startup command fails.
pub fn power_on_start_up(sim: &mut Tpm) {
    sim.signal_platform(SimulatorPlatformSignal::PowerOn)
        .unwrap();
    nv_on(sim);
    sim.execute(Startup {
        startup_type: TpmSu::Clear,
    })
    .unwrap();
}

/// Makes NV available to the TPM again.
pub fn nv_on(sim: &mut Tpm) {
    sim.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();
}

/// `TPM2_NV_Read` authorized by the index itself (empty password).
pub fn nv_read(sim: &mut Tpm, nv_index: Handle, size: u16, offset: u16) -> Result<Vec<u8>, u32> {
    execute_with_password_sessions(
        sim,
        &NVRead {
            auth_handle: nv_index,
            nv_index,
            size,
            offset,
        },
        1,
        &[],
    )
    .map(|resp| resp.data.get_buffer().to_vec())
}

/// Raw `TPM2_NV_Read` parameter area: `size` followed by `offset`.
pub fn nv_read_params(size: u16, offset: u16) -> Vec<u8> {
    let mut params = Vec::new();
    params.extend_from_slice(&size.to_be_bytes());
    params.extend_from_slice(&offset.to_be_bytes());
    params
}

/// The Name of an NV Index (from `TPM2_NV_ReadPublic`).
pub fn nv_read_public_name(sim: &mut Tpm, index: u32) -> Vec<u8> {
    let (code, out) = send_with_auth_entries(sim, TpmCc::NVReadPublic, &[index], &[], &[]);
    assert_eq!(code, RC_SUCCESS, "NV_ReadPublic");
    let pub_len = u16::from_be_bytes([out[10], out[11]]) as usize;
    let name_off = 12 + pub_len;
    let name_len = u16::from_be_bytes([out[name_off], out[name_off + 1]]) as usize;
    out[name_off + 2..name_off + 2 + name_len].to_vec()
}

/// Reads `size` bytes of NV index `index` with an owner password session, returning only success
/// or the response code.
pub fn nv_read_status(sim: &mut Tpm, index: u32, size: u16) -> Result<(), u32> {
    execute_with_password_sessions(
        sim,
        &NVRead {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(index),
            size,
            offset: 0,
        },
        1,
        &[],
    )
    .map(|_| ())
}

/// `TPM_RC_NV_UNAVAILABLE` as returned by `RETURN_IF_NV_IS_NOT_AVAILABLE`.
pub fn nv_unavailable() -> u32 {
    TpmRc::NV_UNAVAILABLE.get()
}

/// `TPM2_NV_Write` authorized by the index itself (empty password).
pub fn nv_write(sim: &mut Tpm, nv_index: Handle, data: &[u8]) -> Result<(), u32> {
    execute_with_password_sessions(
        sim,
        &NVWrite {
            auth_handle: nv_index,
            nv_index,
            data: Tpm2bMaxNvBuffer::from_bytes(data).unwrap(),
            offset: 0,
        },
        1,
        &[],
    )
    .map(|_| ())
}

/// Writes `data` at offset 0 of NV index `index` with an owner password session, returning the
/// response code on failure.
pub fn nv_write_index(sim: &mut Tpm, index: u32, data: &[u8]) -> Result<(), u32> {
    execute_with_password_sessions(
        sim,
        &NVWrite {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(index),
            data: Tpm2bMaxNvBuffer::from_bytes(data).unwrap(),
            offset: 0,
        },
        1,
        &[],
    )
    .map(|_| ())
}

/// Raw `TPM2_NV_Write` parameter area: `data` as a TPM2B followed by `offset`.
pub fn nv_write_params(data: &[u8], offset: u16) -> Vec<u8> {
    let mut params = tpm2b_params(data);
    params.extend_from_slice(&offset.to_be_bytes());
    params
}

/// Runs `TPM2_PolicyAuthorizeNV` on policy `session` (NV index authorized by a password session for
/// `auth_handle`), returning the response code on failure.
pub fn policy_authorize_nv(
    sim: &mut Tpm,
    auth_handle: Handle,
    nv_index: u32,
    session: Handle,
) -> Result<(), u32> {
    run_pw(
        sim,
        PolicyAuthorizeNV {
            auth_handle,
            nv_index: Handle(nv_index),
            policy_session: session,
        },
    )
    .map(|_| ())
}

/// Authorizes `TPM2_PolicyAuthorizeNV` for `index` (authHandle == nvIndex) with a fresh policy
/// session whose (zero) policy digest equals the index's authPolicy.
pub fn policy_authorize_nv_with_policy_auth(
    sim: &mut Tpm,
    index: u32,
    target: Handle,
) -> Result<(), u32> {
    let mut auth = start_keep(sim, TpmSe::Policy, TpmiAlgHash::Sha256, &[target]);
    auth.attributes.insert(tpm2::TpmaSession::CONTINUE_SESSION);
    execute_with_hmac_sessions(
        sim,
        &PolicyAuthorizeNV {
            auth_handle: Handle(index),
            nv_index: Handle(index),
            policy_session: target,
        },
        &[],
        &mut [auth],
        &[&[]],
    )
    .map(|_| ())
}

/// Runs `TPM2_PolicyNV` (operation `TPM_EO_EQ`) on policy `session`, returning the response code on
/// failure.
pub fn policy_nv(
    sim: &mut Tpm,
    auth_handle: Handle,
    nv_index: u32,
    session: Handle,
    operand_b: &[u8],
    offset: u16,
) -> Result<(), u32> {
    run_pw(
        sim,
        PolicyNV {
            auth_handle,
            nv_index: Handle(nv_index),
            policy_session: session,
            operand_b: Tpm2bOperand::from_bytes(leak_bytes(operand_b)).unwrap(),
            offset,
            operation: TpmEo::Eq,
        },
    )
    .map(|_| ())
}

/// Asserts that `TPM2_SetPrimaryPolicy` on `hierarchy` fails with `TPM_RC_NV_UNAVAILABLE` (to be
/// called while NV is off).
pub fn set_primary_policy_nv_off_check(sim: &mut Tpm, hierarchy: Handle) {
    let rc = execute_with_password_sessions(
        sim,
        &SetPrimaryPolicy {
            auth_handle: hierarchy,
            auth_policy: Tpm2bDigest::from_bytes(&[0x33; 32]).unwrap(),
            hash_alg: Some(TpmiAlgHash::Sha256),
        },
        1,
        &[],
    )
    .unwrap_err();
    assert_eq!(rc, nv_unavailable(), "{hierarchy:?}");
}

/// Writes `data` at offset 0 of `index`, authorized by the owner.
pub fn write_nv_owner(sim: &mut Tpm, index: u32, data: &[u8]) {
    run_pw(
        sim,
        NVWrite {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(index),
            data: tpm2::Tpm2bMaxNvBuffer::from_bytes(leak_bytes(data)).unwrap(),
            offset: 0,
        },
    )
    .expect("NV_Write");
}

// ===========================================================================
// TPM lifecycle, clock, capabilities and dictionary-attack state
//
// Startup/shutdown/power cycling, clock reads, capability queries, hierarchy control, DA parameters and RNG helpers.
// ===========================================================================

/// Small deterministic linear congruential generator used to derive reproducible test data.
pub struct Lcg {
    pub seed: u64,
}

impl Lcg {
    pub fn next_byte(&mut self) -> u8 {
        self.seed = self.seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        (self.seed >> 24) as u8
    }
    pub fn next_range(&mut self, min: usize, max: usize) -> usize {
        let span = max - min + 1;
        let r = ((self.next_byte() as usize) << 8) | (self.next_byte() as usize);
        min + (r % span)
    }
}

/// Small deterministic xorshift64 RNG used to generate reproducible fuzzing inputs.
pub struct SimpleRng(pub u64);

impl SimpleRng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    pub fn choose<T: Clone>(&mut self, choices: &[T]) -> T {
        let idx = (self.next_u64() as usize) % choices.len();
        choices[idx].clone()
    }
}

/// Returns the list of handles from `TPM_CAP_HANDLES` and `moreData`.
pub fn cap_handles(sim: &mut Tpm, property: u32, count: u32) -> Result<(Vec<u32>, bool), u32> {
    let (more, data) = get_cap(sim, CAP_HANDLES, property, count)?;
    let n = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
    let handles = (0..n)
        .map(|i| u32::from_be_bytes(data[4 + 4 * i..8 + 4 * i].try_into().unwrap()))
        .collect();
    Ok((handles, more))
}

/// Runs `TPM2_Clear` authorized by `auth` with an empty password session, returning the response
/// code on failure.
pub fn clear(sim: &mut Tpm, auth: Handle) -> Result<(), u32> {
    execute_with_password_sessions(sim, &Clear { auth_handle: auth }, 1, &[]).map(|_| ())
}

/// Runs `TPM2_ClearControl(disable)` authorized by `auth`, returning the response code on failure.
pub fn clear_control(sim: &mut Tpm, auth: Handle, disable: bool) -> Result<(), u32> {
    execute_with_password_sessions(sim, &ClearControl { auth, disable }, 1, &[]).map(|_| ())
}

/// Runs `TPM2_DictionaryAttackLockReset` with an empty lockout password, returning the response code
/// on failure.
pub fn da_lock_reset(sim: &mut Tpm) -> Result<(), u32> {
    execute_with_password_sessions(
        sim,
        &DictionaryAttackLockReset {
            lock_handle: Handle::RH_LOCKOUT,
        },
        1,
        &[],
    )
    .map(|_| ())
}

/// Runs `TPM2_DictionaryAttackParameters` with an empty lockout password, returning the response
/// code on failure.
pub fn da_parameters(sim: &mut Tpm, max: u32, recovery: u32, lockout: u32) -> Result<(), u32> {
    execute_with_password_sessions(
        sim,
        &DictionaryAttackParameters {
            lock_handle: Handle::RH_LOCKOUT,
            new_max_tries: max,
            new_recovery_time: recovery,
            lockout_recovery: lockout,
        },
        1,
        &[],
    )
    .map(|_| ())
}

/// Sets the dictionary-attack parameters with lockout authorization (empty password).
pub fn da_parameters_unwrap(sim: &mut Tpm, max_tries: u32, recovery: u32, lockout_recovery: u32) {
    let mut params = max_tries.to_be_bytes().to_vec();
    params.extend_from_slice(&recovery.to_be_bytes());
    params.extend_from_slice(&lockout_recovery.to_be_bytes());
    let cmd = build_pw_cmd(CC_DA_PARAMETERS, &[Handle::RH_LOCKOUT.0], 1, &params);
    assert_eq!(
        mssim_rc_of(sim, &cmd),
        0,
        "DictionaryAttackParameters failed"
    );
}

/// Sends `TPM2_GetCapability(capability, property, count)`. On success returns `moreData` and
/// the capability data that follows the `capability` selector.
pub fn get_cap(
    sim: &mut Tpm,
    capability: u32,
    property: u32,
    count: u32,
) -> Result<(bool, Vec<u8>), u32> {
    let mut params = Vec::new();
    params.extend_from_slice(&capability.to_be_bytes());
    params.extend_from_slice(&property.to_be_bytes());
    params.extend_from_slice(&count.to_be_bytes());
    let cmd = build_raw_cmd(ST_NO_SESSIONS, CC_GET_CAPABILITY, &[], None, &params);
    let (rc, resp) = send_with_rc(sim, &cmd);
    if rc != 0 {
        return Err(rc);
    }
    let more = resp[10] != 0;
    assert_eq!(
        u32::from_be_bytes(resp[11..15].try_into().unwrap()),
        capability
    );
    Ok((more, resp[15..].to_vec()))
}

/// Parameters of the audited `TPM2_GetCapability(TPM_PT_FAMILY_INDICATOR)`.
pub fn get_cap_params() -> Vec<u8> {
    marshal_to_vec(&GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    })
}

/// Runs `TPM2_GetCapability(TPM_PT_FAMILY_INDICATOR)` with `sess` as the only session, using
/// `attrs`.
pub fn get_cap_with(sim: &mut Sim, sess: &mut Sess, attrs: u8) -> Resp {
    let params = marshal_to_vec(&GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    });
    exec(
        sim,
        CC_GET_CAPABILITY,
        &[],
        &mut [SessUse::hmac(sess, attrs, &[])],
        &params,
        0,
    )
}

/// Runs `TPM2_GetTime` with password sessions; returns the decoded response or the error code.
pub fn get_time(
    sim: &mut Tpm,
    privacy_admin_handle: Handle,
    sign_handle: Handle,
    in_scheme: Option<TpmtSigScheme>,
    num_sessions: usize,
) -> Result<tpm2::commands::responses::GetTime<'static>, u32> {
    let cmd = GetTime {
        privacy_admin_handle,
        sign_handle,
        qualifying_data: Tpm2bData::from_bytes(b"attest-findings").unwrap(),
        in_scheme,
    };
    execute_with_password_sessions(sim, &cmd, num_sessions, &[])
}

/// Runs `TPM2_HierarchyControl(enable, state)` authorized by `auth`, returning the response code on
/// failure.
pub fn hierarchy_control(
    sim: &mut Tpm,
    auth: Handle,
    enable: Handle,
    state: bool,
) -> Result<(), u32> {
    execute_with_password_sessions(
        sim,
        &HierarchyControl {
            auth_handle: auth,
            enable,
            state,
        },
        1,
        &[],
    )
    .map(|_| ())
}

/// `TPM2_HierarchyControl` with an empty password for `auth`; returns the response code.
pub fn hierarchy_control_rc(sim: &mut Tpm, auth: Handle, enable: Handle, state: bool) -> u32 {
    let cmd = HierarchyControl {
        auth_handle: auth,
        enable,
        state,
    };
    execute_with_password_sessions(sim, &cmd, 1, &[]).map_or_else(|rc| rc, |_| 0)
}

/// Current `TPM_PT_LOCKOUT_COUNTER` value.
pub fn lockout_counter(sim: &mut Tpm) -> u32 {
    get_tpm_property(sim, TpmPt::LOCKOUT_COUNTER)
}

/// Power-cycles the TPM (`_TPM_Init`) and makes NV available again.
pub fn power_cycle(sim: &mut Tpm) {
    sim.signal_platform(SimulatorPlatformSignal::PowerOff)
        .unwrap();
    sim.signal_platform(SimulatorPlatformSignal::PowerOn)
        .unwrap();
    sim.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();
}

/// Power cycles the TPM, optionally after an orderly `TPM2_Shutdown(TPM_SU_CLEAR)`.
pub fn power_cycle_orderly(sim: &mut Tpm, orderly: bool) {
    if orderly {
        let shutdown = build_raw_cmd(ST_NO_SESSIONS, 0x145, &[], None, &0u16.to_be_bytes());
        assert_eq!(mssim_rc_of(sim, &shutdown), 0);
    }
    sim.signal_platform(SimulatorPlatformSignal::PowerOff)
        .unwrap();
    power_on_start_up(sim);
}

/// Optionally sends `TPM2_Shutdown(shutdown)`, power-cycles the TPM (`_TPM_Init`), enables NV
/// and sends `TPM2_Startup(startup)`. Returns the Startup response code.
pub fn power_cycle_with(sim: &mut Tpm, shutdown: Option<u16>, startup: u16) -> u32 {
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

/// Client-side random bytes.
pub fn random_bytes(len: usize) -> &'static [u8] {
    let mut buf = vec![0u8; len];
    crate::_common::client_random(&mut buf).unwrap();
    leak_bytes(&buf)
}

/// Executes `TPM2_ReadClock` and returns the current time info.
pub fn read_clock(sim: &mut Tpm) -> TpmsTimeInfo {
    sim.execute(ReadClock {})
        .expect("ReadClock failed")
        .current_time
}

/// Returns `(resetCount, restartCount)` as reported by `TPM2_ReadClock`.
pub fn reset_restart_counts(sim: &mut Tpm) -> (u32, u32) {
    let info = sim.execute(ReadClock {}).unwrap().current_time.clock_info;
    (info.reset_count, info.restart_count)
}

/// The current `restartCount` as reported by `TPM2_ReadClock`.
pub fn restart_count(sim: &mut Tpm) -> u32 {
    sim.execute(ReadClock {})
        .unwrap()
        .current_time
        .clock_info
        .restart_count
}

/// Sends a raw `TPM2_ClockRateAdjust(raw_adjust)` authorized by `auth_handle` with command tag
/// `tag` and returns the response code.
pub fn send_clock_rate_adjust(sim: &mut Tpm, auth_handle: u32, raw_adjust: i8, tag: u16) -> u32 {
    let req = auth_command(
        tpm2::TpmCc::ClockRateAdjust,
        auth_handle,
        tag,
        &[raw_adjust as u8],
    );
    raw_rc(sim, &req)
}

/// Sends a raw `TPM2_ClockSet(new_time)` authorized by `auth_handle` with command tag `tag` and
/// returns the response code.
pub fn send_clock_set(sim: &mut Tpm, auth_handle: u32, new_time: u64, tag: u16) -> u32 {
    let req = auth_command(
        tpm2::TpmCc::ClockSet,
        auth_handle,
        tag,
        &new_time.to_be_bytes(),
    );
    raw_rc(sim, &req)
}

/// `TPM2_DictionaryAttackLockReset(TPM_RH_LOCKOUT)`, with an empty password session if
/// `with_session` is set (otherwise as a `TPM_ST_NO_SESSIONS` command).
pub fn send_da_lock_reset(sim: &mut Tpm, with_session: bool) -> u32 {
    let num_sessions = usize::from(with_session);
    execute_with_password_sessions_status(
        sim,
        &DictionaryAttackLockReset {
            lock_handle: Handle::RH_LOCKOUT,
        },
        num_sessions,
        &[],
    )
    .err()
    .unwrap_or(0)
}

/// `TPM2_DictionaryAttackParameters(TPM_RH_LOCKOUT, ...)` with an empty password session.
pub fn send_da_parameters(
    sim: &mut Tpm,
    new_max_tries: u32,
    new_recovery_time: u32,
    lockout_recovery: u32,
) -> u32 {
    execute_with_password_sessions_status(
        sim,
        &DictionaryAttackParameters {
            lock_handle: Handle::RH_LOCKOUT,
            new_max_tries,
            new_recovery_time,
            lockout_recovery,
        },
        1,
        &[],
    )
    .err()
    .unwrap_or(0)
}

/// Sets the DA parameters with lockoutAuth (empty).
pub fn set_da_parameters(sim: &mut Tpm, max_tries: u32, recovery: u32, lockout: u32) {
    let mut params = Vec::new();
    params.extend_from_slice(&max_tries.to_be_bytes());
    params.extend_from_slice(&recovery.to_be_bytes());
    params.extend_from_slice(&lockout.to_be_bytes());
    let code = send_rc_with_auth_entries(
        sim,
        TpmCc::DictionaryAttackParameters,
        &[Handle::RH_LOCKOUT.0],
        &[AuthEntry::pw(&[])],
        &params,
    );
    assert_eq!(code, RC_SUCCESS, "DictionaryAttackParameters");
}

/// Raw `TPM2_Shutdown(shutdown_type)`; returns the response code.
pub fn shutdown(sim: &mut Tpm, shutdown_type: u16) -> u32 {
    rc_of(&raw_mssim(sim, &u16_param_command(0x145, shutdown_type)))
}

/// Sends `TPM2_Shutdown(shutdown)`, power-cycles the TPM, enables NV and sends
/// `TPM2_Startup(TPM_SU_CLEAR)`: with `TPM_SU_STATE` this is a TPM Restart (the clear
/// count changes), with `TPM_SU_CLEAR` a TPM Reset (the total reset count changes).
pub fn shutdown_and_start_clear(sim: &mut Tpm, shutdown: u16) {
    assert_eq!(send_u16_param_command(sim, TPM_CC_SHUTDOWN, shutdown), 0);
    sim.signal_platform(SimulatorPlatformSignal::PowerOff)
        .unwrap();
    sim.signal_platform(SimulatorPlatformSignal::PowerOn)
        .unwrap();
    sim.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();
    assert_eq!(send_u16_param_command(sim, TPM_CC_STARTUP, TPM_SU_CLEAR), 0);
}

/// Raw `TPM2_Shutdown(shutdown_type)`.
pub fn shutdown_raw(sim: &mut Tpm, shutdown_type: u16) -> u32 {
    raw_rc_at(sim, 0, &u16_param_command(0x145, shutdown_type))
}

/// Raw `TPM2_Shutdown(shutdown_type)`.
pub fn shutdown_with_type(sim: &mut Tpm, shutdown_type: u8) -> u32 {
    raw_rc(
        sim,
        &[
            0x80,
            0x01,
            0,
            0,
            0,
            0x0c,
            0,
            0,
            0x01,
            0x45,
            0,
            shutdown_type,
        ],
    )
}

/// Raw `TPM2_Startup(startup_type)` at locality 0; returns the response code.
pub fn startup(sim: &mut Tpm, startup_type: u16) -> u32 {
    rc_of(&raw_mssim(sim, &u16_param_command(0x144, startup_type)))
}

/// Raw `TPM2_Startup(startup_type)` at `locality`.
pub fn startup_raw(sim: &mut Tpm, locality: u8, startup_type: u16) -> u32 {
    raw_rc_at(sim, locality, &u16_param_command(0x144, startup_type))
}

/// Raw `TPM2_Startup(startup_type)`.
pub fn startup_with_type(sim: &mut Tpm, startup_type: u8) -> u32 {
    raw_rc(
        sim,
        &[0x80, 0x01, 0, 0, 0, 0x0c, 0, 0, 0x01, 0x44, 0, startup_type],
    )
}

/// Returns the attested `TPMS_TIME_ATTEST_INFO` of a `TPM2_GetTime` response.
pub fn time_attest_info(attest: &TpmsAttest<'_>) -> tpm2::TpmsTimeAttestInfo {
    match attest.attested {
        TpmuAttest::Time(info) => info,
        _ => panic!("GetTime did not return TPM_ST_ATTEST_TIME"),
    }
}

// ===========================================================================
// Miscellaneous helpers
//
// Helpers that do not fit any other section.
// ===========================================================================

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

/// The simulator type used by the raw-session helpers.
pub type Sim = Tpm;

/// Helper to build `TpmiRsaKeyBits` values from integers (`TpmiCode::from(2048)`).
pub struct TpmiCode;

impl TpmiCode {
    pub fn from(val: u16) -> TpmiRsaKeyBits {
        TpmiRsaKeyBits(val)
    }
}

/// Lets `STEP_MS` milliseconds of TPM time pass.
pub fn advance() {
    sleep(Duration::from_millis(STEP_MS));
}

/// Default attributes of a TPM-generated key with password (userWithAuth) authorization.
pub fn base_attrs() -> TpmaObject {
    TpmaObject::FIXED_TPM
        | TpmaObject::FIXED_PARENT
        | TpmaObject::SENSITIVE_DATA_ORIGIN
        | TpmaObject::USER_WITH_AUTH
}

/// Selection bits for a single PCR.
pub fn bit(pcr: usize) -> [u8; 3] {
    let mut b = [0u8; 3];
    b[pcr / 8] |= 1 << (pcr % 8);
    b
}

/// Runs `TPM2_Certify` with password sessions.
pub fn certify(
    sim: &mut Tpm,
    object_handle: Handle,
    sign_handle: Handle,
    in_scheme: Option<TpmtSigScheme>,
) -> Result<tpm2::commands::responses::Certify<'static>, u32> {
    let cmd = Certify {
        object_handle,
        sign_handle,
        qualifying_data: Tpm2bData::from_bytes(b"nonce").unwrap(),
        in_scheme,
    };
    // Every handle with an authorization role needs a session, even TPM_RH_NULL (C
    // ParseSessionBuffer); TPM_RH_NULL has an empty authValue.
    let sessions = 2;
    execute_with_password_sessions(sim, &cmd, sessions, &[])
}

/// Runs `TPM2_CertifyCreation` with password sessions.
pub fn certify_creation(
    sim: &mut Tpm,
    sign_handle: Handle,
    object_handle: Handle,
    creation_hash: Tpm2bDigest<'static>,
    creation_ticket: TpmtTkCreation<'static>,
    in_scheme: Option<TpmtSigScheme>,
) -> Result<tpm2::commands::responses::CertifyCreation<'static>, u32> {
    let cmd = CertifyCreation {
        sign_handle,
        object_handle,
        qualifying_data: Tpm2bData::default(),
        creation_hash,
        in_scheme,
        creation_ticket,
    };
    // signHandle has the USER role, so a session is needed even for TPM_RH_NULL.
    let sessions = 1;
    execute_with_password_sessions(sim, &cmd, sessions, &[])
}

/// Runs TPM2_Commit without P1/P2 and returns the commit counter.
pub fn commit(sim: &mut Tpm, key: Handle, auth: &[u8]) -> Result<u16, u32> {
    let cmd = Commit {
        sign_handle: key,
        p1: Tpm2bEccPoint::default(),
        s2: Tpm2bSensitiveData::default(),
        y2: Tpm2bEccParameter::default(),
    };
    execute_with_password_sessions(sim, &cmd, 1, auth).map(|rsp| rsp.counter)
}

/// NV attributes with only the type set to `TPM_NT_COUNTER`.
pub fn counter_attrs() -> TpmaNv {
    TpmaNv::from(TpmNt::Counter)
}

/// Defines a PIN-pass NV index `index` (owner write, auth read, `noDA`) and initializes it with
/// `pinCount = 0`, `pinLimit = 10`.
pub fn define_pin_pass(sim: &mut Tpm, index: u32) {
    let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::AUTHREAD | TpmaNv::NO_DA;
    attributes.set_type(TpmNt::PinPass);
    define_nv_empty_policy(sim, index, attributes, 8);
    // pinCount = 0, pinLimit = 10
    write_nv_owner(sim, index, &[0, 0, 0, 0, 0, 0, 0, 10]);
}

/// Defines a platform index with an empty authValue.
pub fn define_platform(sim: &mut Tpm, index: u32, attributes: TpmaNv, size: u16, policy: &[u8]) {
    try_define(
        sim,
        Handle::RH_PLATFORM,
        &[],
        nv_public(index, attributes | TpmaNv::PLATFORMCREATE, size, policy),
    )
    .unwrap_or_else(|rc| panic!("NV_DefineSpace({index:#x}) failed: {rc:#x}"));
}

/// A dummy signature (an RSASSA-tagged 32-byte blob) for tests that only need a syntactically
/// valid `TPMT_SIGNATURE`.
pub fn ecdsa_dummy_sig() -> TpmtSignature<'static> {
    TpmtSignature::Rsassa(tpm2::TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: tpm2::Tpm2bPublicKeyRsa::from_bytes(&[0x5A; 32]).unwrap(),
    })
}

/// Completes an event sequence, extending `pcr` (or `TPM_RH_NULL`).
pub fn event_sequence_complete(
    sim: &mut Tpm,
    pcr: Handle,
    seq: Handle,
    data: &'static [u8],
) -> Result<usize, u32> {
    let cmd = EventSequenceComplete {
        pcr_handle: pcr,
        sequence_handle: seq,
        buffer: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
    };
    execute_with_password_sessions(sim, &cmd, 2, &[]).map(|rsp| rsp.results.digests().count())
}

/// Starts SHA-256 sequences until the TPM runs out of object memory and returns the
/// handles of the started sequences, asserting that the failing start returns
/// `TPM_RC_OBJECT_MEMORY`.
pub fn fill_sequence_slots(sim: &mut Tpm) -> Vec<Handle> {
    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let mut handles = Vec::new();
    loop {
        match execute_tpm_command_via_send(sim, &start_cmd, &[]) {
            Ok(resp) => handles.push(resp.sequence_handle),
            Err(rc) => {
                assert_eq!(rc, TpmRc::OBJECT_MEMORY.get());
                break;
            }
        }
        assert!(
            handles.len() < MAX_PROBED_SEQUENCES,
            "TPM never ran out of object memory"
        );
    }
    assert!(!handles.is_empty(), "no sequence could be started");
    handles
}

/// Fills in the `commandSize` field of `request`.
pub fn finish(mut request: Vec<u8>) -> Vec<u8> {
    let len = request.len() as u32;
    request[2..6].copy_from_slice(&len.to_be_bytes());
    request
}

/// Fixed (fixedTPM | fixedParent) RSA-2048 storage key template.
pub fn fixed_rsa_storage() -> TpmtPublic<'static> {
    rsa_storage_template_with(
        TpmiAlgHash::Sha256,
        TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT,
    )
}

/// `unique` value matching a keyed-hash sensitive area with seed `[0x02; 32]` and
/// `sensitive_bytes`: `SHA256(seed || sensitive_bytes)`.
pub fn get_bound_unique(sensitive_bytes: &[u8]) -> Tpm2bDigest<'_> {
    let mut hasher = Sha256::new();
    hasher.update([0x02; 32]);
    hasher.update(sensitive_bytes);
    Tpm2bDigest::from_bytes(crate::test_utils::leak_bytes(&hasher.finalize())).unwrap()
}

/// Decodes a hex string (the `testing` crate has no `hex-literal` dependency).
pub fn hx(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Runs `TPM2_IncrementalSelfTest(algs)` and returns the `toDoList`, or the response code.
pub fn incremental_self_test(sim: &mut Tpm, algs: &[Alg]) -> Result<Vec<Alg>, u32> {
    let cmd = IncrementalSelfTest {
        to_test: TpmlAlg::from_slice(algs).unwrap(),
    };
    sim.execute(cmd)
        .map(|rsp| rsp.to_do_list.algorithms().to_vec())
        .map_err(|e| e.get())
}

/// Whether `TPM2_ReadPublic` of `handle` succeeds.
pub fn is_accessible(sim: &mut Tpm, handle: u32) -> bool {
    let cmd = ReadPublic {
        object_handle: Handle(handle),
    };
    execute_with_password_sessions(sim, &cmd, 0, &[]).is_ok()
}

/// Returns whether `sess` (an initialized audit session) is the exclusive audit session, by
/// asking for an exclusive audit session (`TPM_RC_EXCLUSIVE` otherwise). The probe keeps the
/// exclusivity state unchanged.
pub fn is_exclusive(sim: &mut Sim, sess: &mut Sess) -> bool {
    let r = get_cap_with(sim, sess, ATTR_CONT | ATTR_AUDIT | ATTR_AUDIT_EXCLUSIVE);
    match r.rc {
        0 => {
            assert_ne!(r.session_attrs[0] & ATTR_AUDIT_EXCLUSIVE, 0);
            true
        }
        RC_EXCLUSIVE => false,
        rc => panic!("unexpected response code {rc:#x}"),
    }
}

/// Makes `sess` the exclusive audit session and checks that the TPM reports it as such.
pub fn make_exclusive(sim: &mut Sim, sess: &mut Sess) {
    let r = audited_get_cap(sim, sess, ATTR_CONT | ATTR_AUDIT);
    assert_eq!(r.rc, 0);
    assert_ne!(
        r.session_attrs[0] & ATTR_AUDIT_EXCLUSIVE,
        0,
        "the audit session should be exclusive after an audited command"
    );
}

/// Creates a powered-on, started simulator.
pub fn new_sim() -> Sim {
    Tpm::new()
}

/// A `TPM2_PolicySecret` ticket for the owner hierarchy with an all-zero digest (a NULL-like
/// ticket).
pub fn null_secret_ticket() -> TpmtTkAuth<'static> {
    TpmtTkAuth::Secret(Handle::RH_OWNER, to_digest(&[0; 32]))
}

/// `TPM2_NV_Write` of `data` at `offset`, authorized by `TPM_RH_OWNER`.
pub fn owner_write(sim: &mut Tpm, index: u32, offset: u16, data: &[u8]) -> Result<(), u32> {
    let cmd = NVWrite {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(index),
        data: Tpm2bMaxNvBuffer::from_bytes(leak_bytes(data)).unwrap(),
        offset,
    };
    exec_with_empty_passwords(sim, &cmd, 1)
}

/// Generator `G` of NIST P-256 (the public key of the private scalar `d = 1`).
pub fn p256_generator() -> TpmsEccPoint<'static> {
    TpmsEccPoint {
        x: Tpm2bEccParameter::from_bytes(leak_bytes(&unhex(
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
        )))
        .unwrap(),
        y: Tpm2bEccParameter::from_bytes(leak_bytes(&unhex(
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
        )))
        .unwrap(),
    }
}

/// Order `n` of NIST P-256.
pub fn p256_order() -> Vec<u8> {
    unhex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
}

/// Overwrites the 4-byte handle at byte `offset` of the raw command `cmd`.
pub fn patch_handle(mut cmd: Vec<u8>, offset: usize, handle: u32) -> Vec<u8> {
    cmd[offset..offset + 4].copy_from_slice(&handle.to_be_bytes());
    cmd
}

/// Ordinary/counter/... attributes with `AUTHREAD | AUTHWRITE | PLATFORMCREATE`.
pub fn platform_attrs(nt: TpmNt, extra: TpmaNv) -> TpmaNv {
    let mut attributes = TpmaNv::from(nt);
    attributes.insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::PLATFORMCREATE | extra);
    attributes
}

/// Checks the `TPM2B_PRIVATE` format of ordinary objects in both directions:
/// - `TPM2_Create` output decrypts (with the known parent seed) to `UINT16 size ||
///   TPMT_SENSITIVE` with the authValue padded to the nameAlg digest size;
/// - a C-format blob built by the client loads with `TPM2_Load` and unseals.
pub fn private_area_format_round_trip() {
    let mut sim = Tpm::new();
    let srk = owner_srk(&mut sim);
    let parent_seed = [0xa5u8; 32];
    let parent = load_known_seed_parent(&mut sim, srk, &parent_seed);
    let integrity_key = kdfa256(&parent_seed, b"INTEGRITY", &[], 256);

    // TPM -> client.
    let created = create(
        &mut sim,
        parent,
        sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty()),
        b"ab",
        b"hello",
    )
    .unwrap();
    let name = public_name(&created.out_public.0);
    let blob = created.out_private.get_buffer();
    assert_eq!(u16::from_be_bytes([blob[0], blob[1]]), 32);
    let integrity = &blob[2..34];
    assert_eq!(u16::from_be_bytes([blob[34], blob[35]]), 16);
    let iv: [u8; 16] = blob[36..52].try_into().unwrap();
    assert_eq!(
        hmac256(&integrity_key, &[&blob[34..], &name]),
        integrity.to_vec(),
        "outer integrity"
    );
    let mut plain = blob[52..].to_vec();
    let sym_key = kdfa256(&parent_seed, b"STORAGE", &name, 128);
    aes_cfb(&sym_key, &iv, &mut plain, false);
    let sensitive = parse_plain_duplicate(&plain);
    assert_eq!(
        sensitive.auth_value.get_buffer(),
        {
            let mut a = [0u8; 32];
            a[..2].copy_from_slice(b"ab");
            a
        }
        .as_slice(),
        "authValue must be zero-padded to the nameAlg digest size"
    );
    match sensitive.sensitive {
        TpmuSensitiveComposite::KeyedHash(d) => assert_eq!(d.get_buffer(), b"hello"),
        _ => panic!("not a KEYEDHASH sensitive area"),
    }

    // Client -> TPM.
    let seed = [0x3cu8; 32];
    let mut public = sealed_template(TpmiAlgHash::Sha256, TpmaObject::empty());
    public.parms_and_id = PublicParmsAndId::KeyedHash(
        None,
        Tpm2bDigest::from_bytes(leak_bytes(&hash_parts(
            TpmiAlgHash::Sha256,
            &[&seed, b"world"],
        )))
        .unwrap(),
    );
    let name = public_name(&public);
    let sensitive = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::from_bytes(leak_bytes(&seed)).unwrap(),
        sensitive: TpmuSensitiveComposite::KeyedHash(
            Tpm2bSensitiveData::from_bytes(b"world").unwrap(),
        ),
    };
    let sens = marshal_to_vec(&sensitive);
    let mut enc = (sens.len() as u16).to_be_bytes().to_vec();
    enc.extend(sens);
    let iv = [7u8; 16];
    aes_cfb(
        &kdfa256(&parent_seed, b"STORAGE", &name, 128),
        &iv,
        &mut enc,
        true,
    );
    let mut iv_and_enc = 16u16.to_be_bytes().to_vec();
    iv_and_enc.extend(iv);
    iv_and_enc.extend(enc);
    let mut private = 32u16.to_be_bytes().to_vec();
    private.extend(hmac256(&integrity_key, &[&iv_and_enc, &name]));
    private.extend(iv_and_enc);
    let handle = load(
        &mut sim,
        parent,
        Tpm2bPrivate::from_bytes(leak_bytes(&private)).unwrap(),
        Tpm2b(public),
    )
    .expect("C-format TPM2B_PRIVATE must load");
    let unsealed = run(
        &mut sim,
        &Unseal {
            item_handle: handle,
        },
        1,
    )
    .unwrap();
    assert_eq!(unsealed.out_data.get_buffer(), b"world");
}

/// Returns the public area carried in a `TPM2B_PUBLIC`.
pub fn public_of(public: &Tpm2bPublic<'static>) -> TpmtPublic<'static> {
    public.0
}

/// Runs `TPM2_Quote` (empty PCR selection) with password sessions.
pub fn quote(
    sim: &mut Tpm,
    sign_handle: Handle,
    in_scheme: Option<TpmtSigScheme>,
) -> Result<tpm2::commands::responses::Quote<'static>, u32> {
    let cmd = Quote {
        sign_handle,
        qualifying_data: Tpm2bData::from_bytes(b"nonce").unwrap(),
        in_scheme,
        pcr_select: TpmlPcrSelection::default(),
    };
    // signHandle has the USER role, so a session is needed even for TPM_RH_NULL.
    let sessions = 1;
    execute_with_password_sessions(sim, &cmd, sessions, &[])
}

/// Reads a TPM2B at `*off` in `buf`, advancing `*off` past it.
pub fn read_2b(buf: &[u8], off: &mut usize) -> Vec<u8> {
    let len = u16::from_be_bytes([buf[*off], buf[*off + 1]]) as usize;
    let data = buf[*off + 2..*off + 2 + len].to_vec();
    *off += 2 + len;
    data
}

/// `TPM2_NV_Read`, authorized by `auth_handle` with an empty password.
pub fn read_as(
    sim: &mut Tpm,
    auth_handle: Handle,
    index: u32,
    offset: u16,
    size: u16,
) -> Result<Vec<u8>, u32> {
    let cmd = NVRead {
        auth_handle,
        nv_index: Handle(index),
        size,
        offset,
    };
    execute_with_password_sessions(sim, &cmd, 1, &[]).map(|rsp| rsp.data.get_buffer().to_vec())
}

/// Reads `pinCount` of a PIN index with ownerAuth.
pub fn read_pin_count(sim: &mut Tpm, index: u32) -> u32 {
    let (code, out) = send_with_auth_entries(
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

/// The plain-text firmware version reported by `TPM_PT_FIRMWARE_VERSION_1/2`.
pub fn reported_firmware_version(sim: &mut Tpm) -> u64 {
    let v1 = get_tpm_property(sim, TpmPt::FIRMWARE_VERSION_1) as u64;
    let v2 = get_tpm_property(sim, TpmPt::FIRMWARE_VERSION_2) as u64;
    (v1 << 32) | v2
}

/// Duplicable RSA signing key template (authPolicy = `dup_policy(name_alg)`).
pub fn rsa_dup_target(name_alg: TpmiAlgHash, extra: TpmaObject) -> TpmtPublic<'static> {
    rsa_public(name_alg, dup_sign_attrs(extra), dup_policy(name_alg), None)
}

/// `userWithAuth | sensitiveDataOrigin` object attributes.
pub fn sdo_user() -> TpmaObject {
    TpmaObject::USER_WITH_AUTH | TpmaObject::SENSITIVE_DATA_ORIGIN
}

/// Completes a hash sequence for `hierarchy`.
pub fn sequence_complete(
    sim: &mut Tpm,
    seq: Handle,
    data: &'static [u8],
    hierarchy: Handle,
) -> Result<TpmtTkHashcheck<'static>, u32> {
    let cmd = SequenceComplete {
        sequence_handle: seq,
        buffer: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hierarchy,
    };
    execute_with_password_sessions(sim, &cmd, 1, &[]).map(|rsp| rsp.validation)
}

/// Feeds `data` into a sequence.
pub fn sequence_update(sim: &mut Tpm, seq: Handle, data: &'static [u8]) -> Result<(), u32> {
    let cmd = SequenceUpdate {
        sequence_handle: seq,
        buffer: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
    };
    execute_with_password_sessions(sim, &cmd, 1, &[]).map(|_| ())
}

/// Starts a SHA-256 session bound to `bind` (flushing all other sessions).
pub fn start_bound(
    sim: &mut Tpm,
    bind: Handle,
    bind_auth: &[u8],
    session_type: TpmSe,
) -> ActiveSession {
    flush_sessions_except(sim, &[]);
    start_auth_session(
        sim,
        Handle::RH_NULL,
        bind,
        bind_auth,
        session_type,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("StartAuthSession (bound)")
}

/// Starts an unbound, unsalted session of `session_type`, keeping the sessions in `keep` loaded
/// and flushing all others.
pub fn start_keep(
    sim: &mut Tpm,
    session_type: TpmSe,
    hash: TpmiAlgHash,
    keep: &[Handle],
) -> ActiveSession {
    flush_sessions_except(sim, keep);
    start_auth_session(
        sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        session_type,
        None,
        hash,
    )
    .expect("StartAuthSession")
}

/// Starts a salted HMAC session with `tpm_key`, `bind` and the encrypted `salt`, returning the
/// response code on failure.
pub fn start_salted(sim: &mut Tpm, tpm_key: Handle, bind: Handle, salt: &[u8]) -> Result<(), u32> {
    run_command(
        sim,
        StartAuthSession {
            tpm_key,
            bind,
            nonce_caller: Tpm2bNonce::from_bytes(&[1; 16]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::from_bytes(leak_bytes(salt)).unwrap(),
            session_type: TpmSe::HMAC,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        },
    )
    .map(|_| ())
}

/// Starts a hash (or, with `hash_alg == None`, event) sequence with an empty authValue.
pub fn start_sequence(sim: &mut Tpm, hash_alg: Option<TpmiAlgHash>) -> Handle {
    let start_cmd = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg,
    };
    let resp = execute_tpm_command_via_send(sim, &start_cmd, &[]).unwrap();
    resp.sequence_handle
}

/// Starts a hash sequence for `alg` and returns its handle.
pub fn start_sequence_alg(sim: &mut Tpm, alg: TpmiAlgHash) -> Handle {
    let start_cmd = HashSequenceStart {
        auth: Default::default(),
        hash_alg: Some(alg),
    };
    let start_resp = execute_tpm_command_auto_pw_unwrap(sim, &start_cmd).unwrap();
    start_resp.sequence_handle
}

/// Attributes of a storage key (restricted decryption key).
pub fn storage_attrs() -> TpmaObject {
    TpmaObject::DECRYPT
        | TpmaObject::RESTRICTED
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::NO_DA
        | TpmaObject::SENSITIVE_DATA_ORIGIN
        | TpmaObject::FIXED_PARENT
        | TpmaObject::FIXED_TPM
}

/// Performs `TPM2_Shutdown(TPM_SU_CLEAR)`, a power cycle and `TPM2_Startup(TPM_SU_CLEAR)`
/// (a TPM Reset).
pub fn tpm_reset(sim: &mut Tpm) {
    let shutdown = build_raw_cmd(ST_NO_SESSIONS, 0x145, &[], None, &0u16.to_be_bytes());
    assert_eq!(mssim_rc_of(sim, &shutdown), 0, "TPM2_Shutdown failed");
    sim.signal_platform(SimulatorPlatformSignal::PowerOff)
        .unwrap();
    power_on_start_up(sim);
}

/// `TPM2_NV_DefineSpace` with a password session (empty hierarchy auth).
pub fn try_define(
    sim: &mut Tpm,
    auth_handle: Handle,
    auth: &[u8],
    public: TpmsNvPublic<'static>,
) -> Result<(), u32> {
    let cmd = NVDefineSpace {
        auth_handle,
        auth: Tpm2bAuth::from_bytes(leak_bytes(auth)).unwrap(),
        public_info: Tpm2b(public),
    };
    execute_with_password_sessions(sim, &cmd, 1, &[]).map(|_| ())
}

/// Returns a simulator that has been powered on with NV available but has not yet received
/// `TPM2_Startup`, and that has never been shut down orderly (so only `TPM_SU_CLEAR` is valid).
pub fn unstarted_simulator() -> Tpm {
    let mut sim = Tpm::new();
    power_cycle(&mut sim);
    sim
}

/// Current `pcrUpdateCounter` as reported by `TPM2_PCR_Read`.
pub fn update_counter(sim: &mut Tpm) -> u32 {
    pcr_read(sim, &[(ALG_SHA256, [0, 0, 0])]).update_counter
}

/// Returns `context` with its blob replaced by `blob`.
pub fn with_blob(context: TpmsContext<'static>, blob: Vec<u8>) -> TpmsContext<'static> {
    let mut context = context;
    context.context_blob = Tpm2bContextData::from_bytes(Vec::leak(blob)).unwrap();
    context
}

/// Gives a symmetric / keyed-hash public area a (nameAlg-sized) `unique` value, as required
/// for objects loaded without their sensitive area.
pub fn with_unique(mut public: TpmtPublic<'static>) -> TpmtPublic<'static> {
    let unique = Tpm2bDigest::from_bytes(leak_bytes(&[0xA5; 32])).unwrap();
    match &mut public.parms_and_id {
        PublicParmsAndId::Sym(_, u) | PublicParmsAndId::KeyedHash(_, u) => *u = unique,
        _ => unreachable!(),
    }
    public
}

/// Writes `pinCount || pinLimit` to a PIN index with ownerAuth.
pub fn write_pin(sim: &mut Tpm, index: u32, count: u32, limit: u32) {
    let data = [count.to_be_bytes(), limit.to_be_bytes()].concat();
    let code = send_rc_with_auth_entries(
        sim,
        TpmCc::NVWrite,
        &[Handle::RH_OWNER.0, index],
        &[AuthEntry::pw(&[])],
        &nv_write_params(&data, 0),
    );
    assert_eq!(code, RC_SUCCESS, "NV_Write(pin)");
}

/// Equivalent of the Go `getExpectedPCRDigest` helper: reads the selected
/// PCRs and returns the SHA-256 digest of their concatenated values.
pub fn get_expected_pcr_digest(sim: &mut Tpm, selection: &TpmlPcrSelection) -> Vec<u8> {
    let read_cmd = tpm2::commands::PCRRead {
        pcr_selection_in: *selection,
    };
    let read_rsp = sim.execute(read_cmd).expect("failed to read PCRs");
    let mut expected_val = Vec::new();
    for val in read_rsp.pcr_values.digests() {
        expected_val.extend_from_slice(val.as_ref());
    }

    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    tpm2::crypto::hash(
        CLIENT_CRYPTO,
        TpmiAlgHash::Sha256,
        &expected_val,
        &mut digest_buf,
    )
    .unwrap()
    .digest()
    .to_vec()
}

/// Sends `TPM2_SetCommandCodeAuditStatus(auth, auditAlg, setList, clearList)` with an
/// empty-password session for `auth` and returns the response code.
pub fn set_command_code_audit_status(
    sim: &mut Tpm,
    auth: u32,
    audit_alg: u16,
    set_list: &[u32],
    clear_list: &[u32],
) -> u32 {
    let mut params = audit_alg.to_be_bytes().to_vec();
    for list in [set_list, clear_list] {
        params.extend_from_slice(&(list.len() as u32).to_be_bytes());
        for cc in list {
            params.extend_from_slice(&cc.to_be_bytes());
        }
    }
    let cmd = build_pw_cmd(0x140, &[auth], 1, &params);
    send_rc(sim, &cmd)
}

/// Returns `(moreData, commandCodes)` of
/// `TPM2_GetCapability(TPM_CAP_AUDIT_COMMANDS, property, propertyCount)`.
pub fn audit_commands(sim: &mut Tpm, property: u32, count: u32) -> (bool, Vec<u32>) {
    let mut params = 4u32.to_be_bytes().to_vec();
    params.extend_from_slice(&property.to_be_bytes());
    params.extend_from_slice(&count.to_be_bytes());
    let rsp = send_raw(
        sim,
        &build_raw_cmd(ST_NO_SESSIONS, 0x17A, &[], None, &params),
    );
    assert_eq!(
        u32_be(&rsp[6..10]),
        0,
        "GetCapability(TPM_CAP_AUDIT_COMMANDS) failed"
    );
    assert_eq!(u32_be(&rsp[11..15]), 4, "unexpected capability");
    let n = u32_be(&rsp[15..19]) as usize;
    let list = (0..n)
        .map(|i| u32_be(&rsp[19 + 4 * i..23 + 4 * i]))
        .collect();
    (rsp[10] != 0, list)
}

/// The `TPMS_COMMAND_AUDIT_INFO` of an unsigned `TPM2_GetCommandAuditDigest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandAuditReport {
    /// `auditCounter`.
    pub audit_counter: u64,
    /// `digestAlg`.
    pub digest_alg: u16,
    /// `auditDigest` (empty when no audit log is in progress).
    pub audit_digest: Vec<u8>,
    /// `commandDigest`: digest of the list of audited commands.
    pub command_digest: Vec<u8>,
}

/// Executes `TPM2_GetCommandAuditDigest(TPM_RH_ENDORSEMENT, TPM_RH_NULL)` with empty-password
/// sessions (an unsigned report, which leaves the audit digest unchanged) and returns its
/// command audit information.
pub fn command_audit_report(sim: &mut Tpm) -> CommandAuditReport {
    // qualifyingData = empty, inScheme = TPM_ALG_NULL.
    let cmd = build_pw_cmd(
        0x133,
        &[Handle::RH_ENDORSEMENT.0, Handle::RH_NULL.0],
        2,
        &[0x00, 0x00, 0x00, 0x10],
    );
    let rsp = send_raw(sim, &cmd);
    assert_eq!(u32_be(&rsp[6..10]), 0, "GetCommandAuditDigest failed");
    parse_command_audit_report(&rsp)
}

/// Parses the `TPMS_COMMAND_AUDIT_INFO` of a successful `TPM_ST_SESSIONS` response to
/// `TPM2_GetCommandAuditDigest`.
pub fn parse_command_audit_report(rsp: &[u8]) -> CommandAuditReport {
    // parameterSize (4), TPM2B_ATTEST size (2), magic (4), type (2).
    let mut at = 10 + 4 + 2 + 4;
    assert_eq!(
        u16_be(&rsp[at..at + 2]),
        0x8015,
        "not TPM_ST_ATTEST_COMMAND_AUDIT"
    );
    at += 2;
    // qualifiedSigner and extraData (TPM2Bs), clockInfo (17), firmwareVersion (8).
    for _ in 0..2 {
        at += 2 + u16_be(&rsp[at..at + 2]) as usize;
    }
    at += 17 + 8;
    let audit_counter = u64::from_be_bytes(rsp[at..at + 8].try_into().unwrap());
    let digest_alg = u16_be(&rsp[at + 8..at + 10]);
    at += 10;
    let tpm2b = |at: &mut usize| {
        let len = u16_be(&rsp[*at..*at + 2]) as usize;
        let value = rsp[*at + 2..*at + 2 + len].to_vec();
        *at += 2 + len;
        value
    };
    let audit_digest = tpm2b(&mut at);
    let command_digest = tpm2b(&mut at);
    CommandAuditReport {
        audit_counter,
        digest_alg,
        audit_digest,
        command_digest,
    }
}

/// Reads a big-endian `u32` from the first four bytes of `b`.
fn u32_be(b: &[u8]) -> u32 {
    u32::from_be_bytes(b[..4].try_into().unwrap())
}

/// Reads a big-endian `u16` from the first two bytes of `b`.
fn u16_be(b: &[u8]) -> u16 {
    u16::from_be_bytes(b[..2].try_into().unwrap())
}

/// Labeled key encapsulation of a fresh secret to the key whose `TPMT_PUBLIC` wire bytes are
/// `public` (TPM 2.0 Part 1, 11.4.10.2 / Annex B.10.3 RSA-OAEP and Annex C.6.4 ECC), as used for
/// the salt of `TPM2_StartAuthSession` (`label` "SECRET"), the seed of `TPM2_Import`
/// ("DUPLICATE") or `TPM2_MakeCredential` ("IDENTITY"). Mirrors the reference's
/// `CryptSecretDecrypt()`:
/// - RSA: a secret of the OAEP hash's digest size, RSA-OAEP encrypted with the key's OAEP scheme
///   hash (its nameAlg if the scheme is `TPM_ALG_NULL`) and the label with its NUL terminator.
/// - ECC (NIST P-256 only): an ephemeral key `Qe`, `Z = x(de * Qs)`, and the secret
///   `KDFe(nameAlg, Z, label, x(Qe), x(Qs), digestBits(nameAlg))`; the encrypted secret is the
///   marshalled `TPMS_ECC_POINT` `Qe`.
///
/// Returns `(secret, encrypted secret)` (the contents of the `TPM2B_ENCRYPTED_SECRET`), or `None`
/// if `public` does not parse or uses a key type, curve or hash this helper does not support.
/// Never panics, so fuzzers may feed it arbitrary public areas. Randomness (the RSA secret and
/// OAEP seed, the ECC ephemeral key) is drawn from a `StdRng` seeded with `seed`, so equal inputs
/// give equal outputs.
pub fn encapsulate_secret(public: &[u8], label: &str, seed: u64) -> Option<(Vec<u8>, Vec<u8>)> {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut src = public;
    let public = TpmtPublic::unmarshal(&mut src).ok()?;
    let name_alg = public.name_alg?;
    match &public.parms_and_id {
        PublicParmsAndId::Ecc(parms, point) => {
            if parms.curve_id != TpmEccCurve::NistP256 {
                return None;
            }
            let (qs_x, qs_y) = (point.x.get_buffer(), point.y.get_buffer());
            if qs_x.len() != 32 || qs_y.len() != 32 {
                return None;
            }
            let qs = p256::PublicKey::from_encoded_point(
                &p256::EncodedPoint::from_affine_coordinates(qs_x.into(), qs_y.into(), false),
            );
            let qs = Option::<p256::PublicKey>::from(qs)?;
            let de = p256::SecretKey::random(&mut rng);
            let qe = de.public_key().to_encoded_point(false);
            let (qe_x, qe_y) = (qe.x()?.to_vec(), qe.y()?.to_vec());
            let z = p256::ecdh::diffie_hellman(de.to_nonzero_scalar(), qs.as_affine());
            let bits = (name_alg.digest_size() * 8) as u32;
            let mut secret = vec![0u8; name_alg.digest_size()];
            tpm2::crypto::kdf::kdfe_bits(
                CLIENT_CRYPTO,
                name_alg,
                z.raw_secret_bytes().as_slice(),
                label.as_bytes(),
                &qe_x,
                qs_x,
                bits,
                &mut secret,
            )
            .ok()?;
            let mut encrypted = Vec::new();
            for coordinate in [&qe_x, &qe_y] {
                encrypted.extend_from_slice(&(coordinate.len() as u16).to_be_bytes());
                encrypted.extend_from_slice(coordinate);
            }
            Some((secret, encrypted))
        }
        PublicParmsAndId::Rsa(parms, modulus) => {
            let hash = match &parms.scheme {
                None => name_alg,
                Some(TpmtRsaScheme::Oaep(hash)) => *hash,
                Some(_) => return None,
            };
            let n = rsa::BigUint::from_bytes_be(modulus.get_buffer());
            let exponent = if parms.exponent == 0 {
                65537
            } else {
                parms.exponent
            };
            let key = rsa::RsaPublicKey::new(n, rsa::BigUint::from(exponent)).ok()?;
            let mut secret = vec![0u8; hash.digest_size()];
            rng.fill_bytes(&mut secret);
            let label = format!("{label}\0");
            let encrypted = match hash {
                TpmiAlgHash::Sha1 => key.encrypt(
                    &mut rng,
                    rsa::Oaep::new_with_label::<Sha1, _>(label),
                    &secret,
                ),
                TpmiAlgHash::Sha256 => key.encrypt(
                    &mut rng,
                    rsa::Oaep::new_with_label::<Sha256, _>(label),
                    &secret,
                ),
                TpmiAlgHash::Sha384 => key.encrypt(
                    &mut rng,
                    rsa::Oaep::new_with_label::<Sha384, _>(label),
                    &secret,
                ),
                TpmiAlgHash::Sha512 => key.encrypt(
                    &mut rng,
                    rsa::Oaep::new_with_label::<Sha512, _>(label),
                    &secret,
                ),
                #[allow(unreachable_patterns)]
                _ => return None,
            }
            .ok()?;
            Some((secret, encrypted))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An unbound HMAC session with the given `session_key`, for unit-testing the HMAC key helpers.
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

    /// An unbound HMAC session always includes the entity authValue in the HMAC key.
    #[test]
    fn include_auth_hmac_session_unbound_includes_auth() {
        assert!(include_auth_for(false, false, false, false));
        // Policy flags are irrelevant for HMAC sessions.
        assert!(include_auth_for(false, false, true, true));
    }

    /// An HMAC session bound to the authorized entity excludes its authValue from the HMAC key.
    #[test]
    fn include_auth_hmac_session_bound_excludes_auth() {
        assert!(!include_auth_for(false, true, false, false));
        assert!(!include_auth_for(false, true, true, true));
    }

    /// A policy session includes the authValue only after `PolicyAuthValue`/`PolicyPassword`,
    /// regardless of binding.
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

    /// The session HMAC key is `sessionKey || authValue` (trailing zeros stripped) only when the
    /// authValue is included, and just `sessionKey` otherwise.
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
