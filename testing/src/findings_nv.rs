//! End-to-end regression tests for the `nv` findings in command-handlers.toml.
//!
//! Owned by the `fix-nv` worker; add submodules under `findings_nv/` if this grows.
//!
//! Every test drives the simulator exclusively through its command interface and platform
//! signals, and is named after the finding it covers. Expected response codes follow the C
//! reference implementation (`TPMCmd/tpm/src/command/NVStorage`).

#![allow(unused_imports)]

use crate::test_utils::*;
use tpm2::commands::*;
use tpm2::errors::{Position, TpmRc};
use tpm2::*;
use tpm2_simulator::{Simulator, SimulatorPlatformSignal, create_simulator};

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// SHA-256 digest of the concatenation of `parts`.
fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut ctx = tpm2::crypto::HashCtx::new(CLIENT_CRYPTO, TpmiAlgHash::Sha256).unwrap();
    for part in parts {
        ctx.update(part).unwrap();
    }
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    ctx.finalize(&mut out).unwrap().digest().to_vec()
}

/// The policy digest of a fresh SHA-256 policy session (all zeros). An index with this
/// authPolicy is satisfied by an unmodified policy session.
const EMPTY_POLICY: [u8; 32] = [0u8; 32];

/// The SHA-256 policy digest after `TPM2_PolicyCommandCode(cc)` on a fresh session.
fn command_code_policy(cc: TpmCc) -> Vec<u8> {
    sha256(&[
        &EMPTY_POLICY,
        &TpmCc::PolicyCommandCode.code().to_be_bytes(),
        &cc.code().to_be_bytes(),
    ])
}

/// Builds the public area of an NV Index.
fn nv_public(
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

/// `TPM2_NV_DefineSpace` with a password session (empty hierarchy auth).
fn try_define(
    sim: &mut Simulator<'_>,
    auth_handle: Handle,
    auth: &[u8],
    public: TpmsNvPublic<'static>,
) -> Result<(), u32> {
    let cmd = NVDefineSpace {
        auth: Tpm2bAuth::from_bytes(leak_bytes(auth)).unwrap(),
        public_info: Tpm2b(public),
    };
    execute_with_password_sessions(sim, &cmd, NVDefineSpaceHandles { auth_handle }, 1, &[])
        .map(|_| ())
}

/// Defines an owner index with an empty authValue.
fn define(sim: &mut Simulator<'_>, index: u32, attributes: TpmaNv, size: u16, policy: &[u8]) {
    try_define(
        sim,
        Handle::RH_OWNER,
        &[],
        nv_public(index, attributes, size, policy),
    )
    .unwrap_or_else(|rc| panic!("NV_DefineSpace({index:#x}) failed: {rc:#x}"));
}

/// Defines a platform index with an empty authValue.
fn define_platform(
    sim: &mut Simulator<'_>,
    index: u32,
    attributes: TpmaNv,
    size: u16,
    policy: &[u8],
) {
    try_define(
        sim,
        Handle::RH_PLATFORM,
        &[],
        nv_public(index, attributes | TpmaNv::PLATFORMCREATE, size, policy),
    )
    .unwrap_or_else(|rc| panic!("NV_DefineSpace({index:#x}) failed: {rc:#x}"));
}

/// Runs `cmd` with `n` empty password sessions and returns the response code.
fn pw<C: Command>(
    sim: &mut Simulator<'_>,
    cmd: &C,
    handles: C::Handles,
    n: usize,
) -> Result<(), u32>
where
    for<'b> &'b mut C::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <C::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    execute_with_password_sessions_status(sim, cmd, handles, n, &[]).map(|_| ())
}

/// `TPM2_NV_Write` of `data` at `offset`, authorized by `TPM_RH_OWNER`.
fn owner_write(sim: &mut Simulator<'_>, index: u32, offset: u16, data: &[u8]) -> Result<(), u32> {
    let cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(leak_bytes(data)).unwrap(),
        offset,
    };
    let handles = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(index),
    };
    pw(sim, &cmd, handles, 1)
}

/// `TPM2_NV_Read`, authorized by `auth_handle` with an empty password.
fn read_as(
    sim: &mut Simulator<'_>,
    auth_handle: Handle,
    index: u32,
    offset: u16,
    size: u16,
) -> Result<Vec<u8>, u32> {
    let cmd = NVRead { size, offset };
    let handles = NVReadHandles {
        auth_handle,
        nv_index: Handle(index),
    };
    execute_with_password_sessions(sim, &cmd, handles, 1, &[])
        .map(|(rsp, _)| rsp.data.get_buffer().to_vec())
}

/// Reads the current Name of an NV Index (it changes when TPMA_NV_WRITTEN is set).
fn nv_index_name(sim: &mut Simulator<'_>, index: u32) -> Vec<u8> {
    let (rsp, _) = sim
        .execute_with_handles(
            NVReadPublic {},
            NVReadPublicHandles {
                nv_index: Handle(index),
            },
        )
        .expect("NV_ReadPublic failed");
    rsp.nv_name.get_buffer().to_vec()
}

/// Starts an unbound, unsalted SHA-256 session of type `session_type`.
fn start_session(sim: &mut Simulator<'_>, session_type: TpmSe) -> ActiveSession {
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

/// Runs `TPM2_PolicyCommandCode(cc)` on `session`.
fn policy_command_code(sim: &mut Simulator<'_>, session: &ActiveSession, cc: TpmCc) {
    sim.execute_with_handles(
        PolicyCommandCode { code: cc },
        PolicyCommandCodeHandles {
            policy_session: session.session_handle,
        },
    )
    .expect("PolicyCommandCode failed");
}

/// Runs `cmd` authorized by the single `session` for an entity named `names` with an empty
/// authValue.
fn with_session<C: Command>(
    sim: &mut Simulator<'_>,
    cmd: &C,
    handles: C::Handles,
    names: &[&[u8]],
    session: &mut ActiveSession,
) -> Result<(), u32>
where
    for<'b> &'b mut C::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <C::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    execute_with_hmac_sessions_status(
        sim,
        cmd,
        handles,
        names,
        core::slice::from_mut(session),
        &[&[]],
    )
    .map(|_| ())
}

/// The Name of a permanent handle (the handle value).
fn handle_name(handle: Handle) -> Vec<u8> {
    handle.0.to_be_bytes().to_vec()
}

/// Creates an ECC NIST P-256 ECDSA/SHA-256 signing primary key in the owner hierarchy.
fn create_signing_key(sim: &mut Simulator<'_>) -> Handle {
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
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(public_area),
        ..Default::default()
    };
    let (_, handles) = execute_with_password_sessions(
        sim,
        &cmd,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        },
        1,
        &[],
    )
    .expect("CreatePrimary failed");
    handles.object_handle
}

/// `TPM2_NV_Certify` with password sessions; returns the attestation structure.
fn nv_certify(
    sim: &mut Simulator<'_>,
    handles: NVCertifyHandles,
    in_scheme: Option<TpmtSigScheme>,
    size: u16,
    offset: u16,
    sessions: usize,
) -> Result<TpmsAttest<'static>, u32> {
    let cmd = NVCertify {
        qualifying_data: Tpm2bData::default(),
        in_scheme,
        size,
        offset,
    };
    execute_with_password_sessions(sim, &cmd, handles, sessions, &[])
        .map(|(rsp, _)| rsp.certify_info.0)
}

const OWNER_RW: TpmaNv = TpmaNv::OWNERREAD.union(TpmaNv::OWNERWRITE);

// ---------------------------------------------------------------------------------------------
// tpm2-nv-certify-omits-nv-digest-format-signing-key-check-and-policyread
// ---------------------------------------------------------------------------------------------

/// `size == 0 && offset == 0` produces a `TPM_ST_ATTEST_NV_DIGEST` attestation whose digest is
/// H_schemeHash(whole index data); an unsigned one has an empty digest.
#[test]
fn tpm2_nv_certify_omits_nv_digest_format_digest_attestation() {
    let mut sim = create_simulator!();
    let index = 0x0150_0100;
    define(&mut sim, index, OWNER_RW, 16, &[]);
    let data = [0x5au8; 16];
    owner_write(&mut sim, index, 0, &data).unwrap();
    let name = nv_index_name(&mut sim, index);

    // Signed with an ECDSA/SHA-256 key.
    let key = create_signing_key(&mut sim);
    let handles = NVCertifyHandles {
        sign_handle: key,
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(index),
    };
    let attest = nv_certify(&mut sim, handles, None, 0, 0, 2).expect("NV_Certify failed");
    match attest.attested {
        TpmuAttest::NvDigest(info) => {
            assert_eq!(info.index_name.get_buffer(), name.as_slice());
            assert_eq!(info.nv_digest.get_buffer(), sha256(&[&data]).as_slice());
        }
        other => panic!("expected TPM_ST_ATTEST_NV_DIGEST, got {other:?}"),
    }

    // Unsigned (TPM_RH_NULL): the scheme hash is TPM_ALG_NULL, so the digest is empty.
    let handles = NVCertifyHandles {
        sign_handle: Handle::RH_NULL,
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(index),
    };
    let attest = nv_certify(&mut sim, handles, None, 0, 0, 2).expect("NV_Certify failed");
    match attest.attested {
        TpmuAttest::NvDigest(info) => assert!(info.nv_digest.get_buffer().is_empty()),
        other => panic!("expected TPM_ST_ATTEST_NV_DIGEST, got {other:?}"),
    }
}

/// The signing scheme is validated (`TPM_RC_SCHEME + RC_P2`) before any NV access check, so an
/// unwritten index does not mask it with `TPM_RC_NV_UNINITIALIZED`.
#[test]
fn tpm2_nv_certify_omits_nv_digest_format_scheme_checked_first() {
    let mut sim = create_simulator!();
    let index = 0x0150_0101;
    define(&mut sim, index, OWNER_RW, 16, &[]);
    let key = create_signing_key(&mut sim);
    let handles = NVCertifyHandles {
        sign_handle: key,
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(index),
    };
    // The key's scheme is ECDSA/SHA-256; asking for ECDSA/SHA-384 is a scheme error.
    let rc = nv_certify(
        &mut sim,
        handles,
        Some(TpmtSigScheme::Ecdsa(TpmiAlgHash::Sha384)),
        4,
        0,
        2,
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::SCHEME.with(Position::parameter(2)).get());
}

/// An index readable only with its authPolicy (`TPMA_NV_POLICYREAD`) can be certified with a
/// satisfied policy session.
#[test]
fn tpm2_nv_certify_omits_nv_digest_format_policyread() {
    let mut sim = create_simulator!();
    let index = 0x0150_0102;
    define(
        &mut sim,
        index,
        TpmaNv::POLICYREAD | TpmaNv::OWNERWRITE,
        8,
        &EMPTY_POLICY,
    );
    owner_write(&mut sim, index, 0, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    let name = nv_index_name(&mut sim, index);

    // C requires a session for every authorization handle, including a TPM_RH_NULL
    // signHandle: an (empty-auth) HMAC session for it, the policy session for the index.
    let hmac = start_session(&mut sim, TpmSe::HMAC);
    let policy = start_session(&mut sim, TpmSe::Policy);
    let mut sessions = [hmac, policy];
    let cmd = NVCertify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        size: 4,
        offset: 0,
    };
    let handles = NVCertifyHandles {
        sign_handle: Handle::RH_NULL,
        auth_handle: Handle(index),
        nv_index: Handle(index),
    };
    let null_name = handle_name(Handle::RH_NULL);
    execute_with_hmac_sessions_status(
        &mut sim,
        &cmd,
        handles,
        &[&null_name, &name, &name],
        &mut sessions,
        &[&[], &[]],
    )
    .expect("NV_Certify with a POLICYREAD policy session failed");
}

/// `size > MAX_NV_BUFFER_SIZE` is `TPM_RC_VALUE + RC_P3` (checked after the range check).
#[test]
fn tpm2_nv_certify_omits_nv_digest_format_size_value() {
    let mut sim = create_simulator!();
    let index = 0x0150_0103;
    define(&mut sim, index, OWNER_RW, 1100, &[]);
    owner_write(&mut sim, index, 0, &[0x11; 1024]).unwrap();
    let handles = NVCertifyHandles {
        sign_handle: Handle::RH_NULL,
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(index),
    };
    let rc = nv_certify(&mut sim, handles, None, 1025, 0, 2).unwrap_err();
    assert_eq!(rc, TpmRc::VALUE.with(Position::parameter(3)).get());
    // The range check comes first.
    let rc = nv_certify(&mut sim, handles, None, 1025, 100, 2).unwrap_err();
    assert_eq!(rc, TpmRc::NV_RANGE.get());
}

// ---------------------------------------------------------------------------------------------
// tpm2-nv-definespace-and-undefinespacespecial-validation-bugs
// ---------------------------------------------------------------------------------------------

#[test]
fn tpm2_nv_definespace_and_undefinespacespecial_validation_bugs_auth_policy_size() {
    let mut sim = create_simulator!();
    let rc = try_define(
        &mut sim,
        Handle::RH_OWNER,
        &[],
        nv_public(0x0150_0200, OWNER_RW, 8, &[0xAA; 20]),
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::SIZE.with(Position::parameter(2)).get());
}

#[test]
fn tpm2_nv_definespace_and_undefinespacespecial_validation_bugs_auth_trailing_zeros() {
    let mut sim = create_simulator!();
    // 32 significant bytes followed by zeros: fits a SHA-256 nameAlg once zeros are removed.
    let mut auth = vec![0x42u8; 32];
    auth.extend_from_slice(&[0, 0, 0]);
    try_define(
        &mut sim,
        Handle::RH_OWNER,
        &auth,
        nv_public(0x0150_0201, OWNER_RW, 8, &[]),
    )
    .expect("auth with trailing zeros must be accepted");
    // 33 significant bytes are too many.
    let rc = try_define(
        &mut sim,
        Handle::RH_OWNER,
        &[0x42u8; 33],
        nv_public(0x0150_0202, OWNER_RW, 8, &[]),
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::SIZE.with(Position::parameter(1)).get());
}

#[test]
fn tpm2_nv_definespace_and_undefinespacespecial_validation_bugs_pin_locks() {
    let mut sim = create_simulator!();
    let pin_pass = TpmaNv::from(TpmNt::PinPass) | TpmaNv::OWNERWRITE | TpmaNv::AUTHREAD;
    let rc = try_define(
        &mut sim,
        Handle::RH_OWNER,
        &[],
        nv_public(0x0150_0203, pin_pass | TpmaNv::GLOBALLOCK, 8, &[]),
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::ATTRIBUTES.with(Position::parameter(2)).get());

    let pin_fail =
        TpmaNv::from(TpmNt::PinFail) | TpmaNv::OWNERWRITE | TpmaNv::AUTHREAD | TpmaNv::NO_DA;
    let rc = try_define(
        &mut sim,
        Handle::RH_OWNER,
        &[],
        nv_public(0x0150_0204, pin_fail | TpmaNv::WRITEDEFINE, 8, &[]),
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::ATTRIBUTES.with(Position::parameter(2)).get());
}

#[test]
fn tpm2_nv_definespace_and_undefinespacespecial_validation_bugs_positions() {
    let mut sim = create_simulator!();
    let rc = try_define(
        &mut sim,
        Handle::RH_OWNER,
        &[],
        nv_public(0x0150_0205, OWNER_RW | TpmaNv::WRITTEN, 8, &[]),
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::ATTRIBUTES.with(Position::parameter(2)).get());

    let rc = try_define(
        &mut sim,
        Handle::RH_OWNER,
        &[],
        nv_public(0x0150_0206, OWNER_RW, 2049, &[]),
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::SIZE.with(Position::parameter(2)).get());

    // An owner-defined index can't be platform-created (blames authHandle).
    let rc = try_define(
        &mut sim,
        Handle::RH_OWNER,
        &[],
        nv_public(0x0150_0207, OWNER_RW | TpmaNv::PLATFORMCREATE, 8, &[]),
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::ATTRIBUTES.with(Position::handle(1)).get());

    // WRITEALL is limited by MAX_NV_BUFFER_SIZE (1024), not MAX_NV_INDEX_SIZE.
    let rc = try_define(
        &mut sim,
        Handle::RH_OWNER,
        &[],
        nv_public(0x0150_0208, OWNER_RW | TpmaNv::WRITEALL, 1025, &[]),
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::SIZE.with(Position::parameter(2)).get());

    // CLEAR_STCLEAR and WRITEDEFINE are mutually exclusive.
    let rc = try_define(
        &mut sim,
        Handle::RH_OWNER,
        &[],
        nv_public(
            0x0150_0209,
            OWNER_RW | TpmaNv::CLEAR_STCLEAR | TpmaNv::WRITEDEFINE,
            8,
            &[],
        ),
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::ATTRIBUTES.with(Position::parameter(2)).get());
}

#[test]
fn tpm2_nv_definespace_and_undefinespacespecial_validation_bugs_special_platform_handle() {
    let mut sim = create_simulator!();
    let index = 0x0150_020a;
    define_platform(
        &mut sim,
        index,
        TpmaNv::PPREAD | TpmaNv::PPWRITE | TpmaNv::POLICY_DELETE,
        8,
        &command_code_policy(TpmCc::NVUndefineSpaceSpecial),
    );
    let handles = NVUndefineSpaceSpecialHandles {
        nv_index: Handle(index),
        platform: Handle::RH_OWNER,
    };
    let rc = pw(&mut sim, &NVUndefineSpaceSpecial {}, handles, 2).unwrap_err();
    assert_eq!(rc, TpmRc::VALUE.with(Position::handle(2)).get());
}

// ---------------------------------------------------------------------------------------------
// auth-role-dup-admin-and-policy-commandcode-bypass (NV_ChangeAuth part) and
// nv-change-auth-hmac-session-bypass-and-command-code-bugs
// ---------------------------------------------------------------------------------------------

/// Defines an index whose authPolicy is `TPM2_PolicyCommandCode(TPM_CC_NV_ChangeAuth)`.
fn define_change_auth_index(sim: &mut Simulator<'_>, index: u32, size: u16) {
    define(
        sim,
        index,
        OWNER_RW | TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE,
        size,
        &command_code_policy(TpmCc::NVChangeAuth),
    );
}

fn change_auth_cmd(new_auth: &[u8]) -> NVChangeAuth<'static> {
    NVChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(leak_bytes(new_auth)).unwrap(),
    }
}

#[test]
fn auth_role_dup_admin_and_policy_commandcode_bypass_nv_change_auth_hmac() {
    let mut sim = create_simulator!();
    let index = 0x0150_0300;
    define_change_auth_index(&mut sim, index, 8);
    let name = nv_index_name(&mut sim, index);
    let mut session = start_session(&mut sim, TpmSe::HMAC);
    let rc = with_session(
        &mut sim,
        &change_auth_cmd(b"new"),
        NVChangeAuthHandles {
            nv_index: Handle(index),
        },
        &[&name],
        &mut session,
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::AUTH_TYPE.get());
}

#[test]
fn nv_change_auth_hmac_session_bypass_and_command_code_bugs() {
    let mut sim = create_simulator!();
    let index = 0x0150_0301;
    // The authPolicy is the empty policy, so a policy session without
    // TPM2_PolicyCommandCode satisfies the digest but not the ADMIN role.
    define(
        &mut sim,
        index,
        OWNER_RW | TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE,
        8,
        &EMPTY_POLICY,
    );
    let name = nv_index_name(&mut sim, index);
    let handles = NVChangeAuthHandles {
        nv_index: Handle(index),
    };

    // HMAC sessions can't provide ADMIN authorization of an NV Index.
    let mut hmac = start_session(&mut sim, TpmSe::HMAC);
    let rc = with_session(
        &mut sim,
        &change_auth_cmd(b"x"),
        handles,
        &[&name],
        &mut hmac,
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::AUTH_TYPE.get());

    // A policy session that never ran TPM2_PolicyCommandCode fails with POLICY_FAIL.
    let mut policy = start_session(&mut sim, TpmSe::Policy);
    let rc = with_session(
        &mut sim,
        &change_auth_cmd(b"x"),
        handles,
        &[&name],
        &mut policy,
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::POLICY_FAIL.with(Position::session(1)).get());
}

// ---------------------------------------------------------------------------------------------
// tpm2-nv-access-commands-reject-policywrite-policyread-and-wrong-errors
// ---------------------------------------------------------------------------------------------

/// Extend, SetBits, WriteLock (POLICYWRITE) and ReadLock (POLICYREAD) accept a satisfied policy
/// session on an index without AUTHWRITE / AUTHREAD.
#[test]
fn tpm2_nv_access_commands_reject_policywrite_policyread_and_wrong_errors_policy_sessions() {
    let mut sim = create_simulator!();
    let policy_rw = TpmaNv::POLICYWRITE | TpmaNv::POLICYREAD | TpmaNv::OWNERREAD;

    let ext = 0x0150_0400;
    define(
        &mut sim,
        ext,
        TpmaNv::from(TpmNt::Extend) | policy_rw,
        32,
        &EMPTY_POLICY,
    );
    let name = nv_index_name(&mut sim, ext);
    let mut session = start_session(&mut sim, TpmSe::Policy);
    let cmd = NVExtend {
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xaa; 8]).unwrap(),
    };
    let handles = NVExtendHandles {
        auth_handle: Handle(ext),
        nv_index: Handle(ext),
    };
    with_session(&mut sim, &cmd, handles, &[&name, &name], &mut session)
        .expect("NV_Extend with a POLICYWRITE policy session failed");

    let bits = 0x0150_0401;
    define(
        &mut sim,
        bits,
        TpmaNv::from(TpmNt::Bits) | policy_rw,
        8,
        &EMPTY_POLICY,
    );
    let name = nv_index_name(&mut sim, bits);
    let handles = NVSetBitsHandles {
        auth_handle: Handle(bits),
        nv_index: Handle(bits),
    };
    with_session(
        &mut sim,
        &NVSetBits { bits: 1 },
        handles,
        &[&name, &name],
        &mut session,
    )
    .expect("NV_SetBits with a POLICYWRITE policy session failed");

    let locks = 0x0150_0402;
    define(
        &mut sim,
        locks,
        policy_rw | TpmaNv::WRITE_STCLEAR | TpmaNv::READ_STCLEAR,
        8,
        &EMPTY_POLICY,
    );
    let name = nv_index_name(&mut sim, locks);
    let handles = NVWriteLockHandles {
        auth_handle: Handle(locks),
        nv_index: Handle(locks),
    };
    with_session(
        &mut sim,
        &NVWriteLock {},
        handles,
        &[&name, &name],
        &mut session,
    )
    .expect("NV_WriteLock with a POLICYWRITE policy session failed");
    let name = nv_index_name(&mut sim, locks);
    let handles = NVReadLockHandles {
        auth_handle: Handle(locks),
        nv_index: Handle(locks),
    };
    with_session(
        &mut sim,
        &NVReadLock {},
        handles,
        &[&name, &name],
        &mut session,
    )
    .expect("NV_ReadLock with a POLICYREAD policy session failed");
}

/// Owner/platform authorization without the matching attribute is `TPM_RC_NV_AUTHORIZATION`.
#[test]
fn tpm2_nv_access_commands_reject_policywrite_policyread_and_wrong_errors_nv_authorization() {
    let mut sim = create_simulator!();
    let ext = 0x0150_0410;
    define(
        &mut sim,
        ext,
        TpmaNv::from(TpmNt::Extend) | OWNER_RW,
        32,
        &[],
    );
    let handles = NVExtendHandles {
        auth_handle: Handle::RH_PLATFORM,
        nv_index: Handle(ext),
    };
    let cmd = NVExtend {
        data: Tpm2bMaxNvBuffer::from_bytes(&[1]).unwrap(),
    };
    assert_eq!(
        pw(&mut sim, &cmd, handles, 1).unwrap_err(),
        TpmRc::NV_AUTHORIZATION.get()
    );

    let bits = 0x0150_0411;
    define(&mut sim, bits, TpmaNv::from(TpmNt::Bits) | OWNER_RW, 8, &[]);
    let handles = NVSetBitsHandles {
        auth_handle: Handle::RH_PLATFORM,
        nv_index: Handle(bits),
    };
    assert_eq!(
        pw(&mut sim, &NVSetBits { bits: 1 }, handles, 1).unwrap_err(),
        TpmRc::NV_AUTHORIZATION.get()
    );

    let locks = 0x0150_0412;
    define(
        &mut sim,
        locks,
        TpmaNv::PPREAD
            | TpmaNv::PPWRITE
            | TpmaNv::AUTHREAD
            | TpmaNv::AUTHWRITE
            | TpmaNv::WRITEDEFINE
            | TpmaNv::READ_STCLEAR,
        8,
        &[],
    );
    let handles = NVWriteLockHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(locks),
    };
    assert_eq!(
        pw(&mut sim, &NVWriteLock {}, handles, 1).unwrap_err(),
        TpmRc::NV_AUTHORIZATION.get()
    );
    let handles = NVReadLockHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(locks),
    };
    assert_eq!(
        pw(&mut sim, &NVReadLock {}, handles, 1).unwrap_err(),
        TpmRc::NV_AUTHORIZATION.get()
    );
}

/// `NvWriteAccessChecks` (WRITELOCKED) runs before the index-type check in NV_Extend and
/// NV_SetBits, and type/attribute errors carry the nvIndex handle position.
#[test]
fn tpm2_nv_access_commands_reject_policywrite_policyread_and_wrong_errors_order_and_positions() {
    let mut sim = create_simulator!();
    let ordinary = 0x0150_0420;
    define(&mut sim, ordinary, OWNER_RW | TpmaNv::WRITEDEFINE, 8, &[]);
    let lock = NVWriteLockHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(ordinary),
    };
    pw(&mut sim, &NVWriteLock {}, lock, 1).unwrap();

    let ext = NVExtendHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(ordinary),
    };
    let cmd = NVExtend {
        data: Tpm2bMaxNvBuffer::from_bytes(&[1]).unwrap(),
    };
    assert_eq!(
        pw(&mut sim, &cmd, ext, 1).unwrap_err(),
        TpmRc::NV_LOCKED.get()
    );
    let bits = NVSetBitsHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(ordinary),
    };
    assert_eq!(
        pw(&mut sim, &NVSetBits { bits: 1 }, bits, 1).unwrap_err(),
        TpmRc::NV_LOCKED.get()
    );

    // Unlocked ordinary index: the type error is ATTRIBUTES + RC_H2.
    let other = 0x0150_0421;
    define(&mut sim, other, OWNER_RW, 8, &[]);
    let ext = NVExtendHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(other),
    };
    assert_eq!(
        pw(&mut sim, &cmd, ext, 1).unwrap_err(),
        TpmRc::ATTRIBUTES.with(Position::handle(2)).get()
    );
    let bits = NVSetBitsHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(other),
    };
    assert_eq!(
        pw(&mut sim, &NVSetBits { bits: 1 }, bits, 1).unwrap_err(),
        TpmRc::ATTRIBUTES.with(Position::handle(2)).get()
    );
    // No WRITEDEFINE/WRITE_STCLEAR or READ_STCLEAR.
    let lock = NVWriteLockHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(other),
    };
    assert_eq!(
        pw(&mut sim, &NVWriteLock {}, lock, 1).unwrap_err(),
        TpmRc::ATTRIBUTES.with(Position::handle(2)).get()
    );
    let lock = NVReadLockHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(other),
    };
    assert_eq!(
        pw(&mut sim, &NVReadLock {}, lock, 1).unwrap_err(),
        TpmRc::ATTRIBUTES.with(Position::handle(2)).get()
    );
}

// ---------------------------------------------------------------------------------------------
// nv-write-read-changeauth-partial-write-and-truncation-bugs
// ---------------------------------------------------------------------------------------------

/// NV_ChangeAuth with a different authValue size keeps all data of a large index.
#[test]
fn nv_write_read_changeauth_partial_write_and_truncation_bugs_change_auth_keeps_data() {
    let mut sim = create_simulator!();
    let index = 0x0150_0500;
    let size = 1600u16;
    define_change_auth_index(&mut sim, index, size);
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    owner_write(&mut sim, index, 0, &data[..1000]).unwrap();
    owner_write(&mut sim, index, 1000, &data[1000..]).unwrap();

    let name = nv_index_name(&mut sim, index);
    let mut session = start_session(&mut sim, TpmSe::Policy);
    policy_command_code(&mut sim, &session, TpmCc::NVChangeAuth);
    with_session(
        &mut sim,
        &change_auth_cmd(&[0x77; 20]),
        NVChangeAuthHandles {
            nv_index: Handle(index),
        },
        &[&name],
        &mut session,
    )
    .expect("NV_ChangeAuth failed");

    let mut read_back = read_as(&mut sim, Handle::RH_OWNER, index, 0, 1000).unwrap();
    read_back.extend(read_as(&mut sim, Handle::RH_OWNER, index, 1000, size - 1000).unwrap());
    assert_eq!(read_back, data);
}

/// The first partial write of an ordinary index clears the rest of the index.
#[test]
fn nv_write_read_changeauth_partial_write_and_truncation_bugs_partial_write_clears() {
    let mut sim = create_simulator!();
    let index = 0x0150_0501;
    define(&mut sim, index, OWNER_RW, 64, &[]);
    owner_write(&mut sim, index, 0, &[0xAA; 64]).unwrap();
    let undefine = NVUndefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(index),
    };
    pw(&mut sim, &NVUndefineSpace {}, undefine, 1).unwrap();

    // The new index reuses the storage of the deleted one.
    define(&mut sim, index, OWNER_RW, 64, &[]);
    owner_write(&mut sim, index, 0, &[0x01]).unwrap();
    let data = read_as(&mut sim, Handle::RH_OWNER, index, 0, 64).unwrap();
    let mut expected = vec![0u8; 64];
    expected[0] = 0x01;
    assert_eq!(data, expected);
}

/// Access checks come before the size/offset checks, and an offset past the end of the index
/// is `TPM_RC_VALUE + RC_P2`.
#[test]
fn nv_write_read_changeauth_partial_write_and_truncation_bugs_validation_order() {
    let mut sim = create_simulator!();
    let index = 0x0150_0502;
    define(&mut sim, index, OWNER_RW | TpmaNv::WRITEDEFINE, 16, &[]);

    // Not written yet: NV_UNINITIALIZED wins over the range error.
    assert_eq!(
        read_as(&mut sim, Handle::RH_OWNER, index, 0, 32).unwrap_err(),
        TpmRc::NV_UNINITIALIZED.get()
    );
    // Platform can't read: NV_AUTHORIZATION wins over the range error.
    assert_eq!(
        read_as(&mut sim, Handle::RH_PLATFORM, index, 0, 32).unwrap_err(),
        TpmRc::NV_AUTHORIZATION.get()
    );

    assert_eq!(
        owner_write(&mut sim, index, 17, &[1]).unwrap_err(),
        TpmRc::VALUE.with(Position::parameter(2)).get()
    );
    owner_write(&mut sim, index, 0, &[1; 16]).unwrap();
    assert_eq!(
        read_as(&mut sim, Handle::RH_OWNER, index, 17, 0).unwrap_err(),
        TpmRc::VALUE.with(Position::parameter(2)).get()
    );
    assert_eq!(
        read_as(&mut sim, Handle::RH_OWNER, index, 8, 9).unwrap_err(),
        TpmRc::NV_RANGE.get()
    );

    // NV_Write by platform on an owner-only index: NV_AUTHORIZATION before the type check.
    let handles = NVWriteHandles {
        auth_handle: Handle::RH_PLATFORM,
        nv_index: Handle(index),
    };
    let cmd = NVWrite {
        data: Tpm2bMaxNvBuffer::from_bytes(&[1; 32]).unwrap(),
        offset: 0,
    };
    assert_eq!(
        pw(&mut sim, &cmd, handles, 1).unwrap_err(),
        TpmRc::NV_AUTHORIZATION.get()
    );
}

// ---------------------------------------------------------------------------------------------
// nv-index-accessibility-hierarchy-and-handle-error-omissions
// ---------------------------------------------------------------------------------------------

#[test]
fn nv_index_accessibility_hierarchy_and_handle_error_omissions_read_public() {
    let mut sim = create_simulator!();
    let missing = sim
        .execute_with_handles(
            NVReadPublic {},
            NVReadPublicHandles {
                nv_index: Handle(0x0150_0600),
            },
        )
        .unwrap_err();
    assert_eq!(missing.get(), TpmRc::HANDLE.with(Position::handle(1)).get());

    let index = 0x0150_0601;
    define(&mut sim, index, OWNER_RW, 8, &[]);
    set_hierarchy_enabled(&mut sim, Handle::RH_OWNER, false);
    let hidden = sim
        .execute_with_handles(
            NVReadPublic {},
            NVReadPublicHandles {
                nv_index: Handle(index),
            },
        )
        .unwrap_err();
    assert_eq!(hidden.get(), TpmRc::HANDLE.with(Position::handle(1)).get());
}

/// With `phEnableNV` clear, a platform index is reported as `TPM_RC_HANDLE + RC_H2` before the
/// `TPMA_NV_POLICY_DELETE` attribute check.
#[test]
fn nv_index_accessibility_hierarchy_and_handle_error_omissions_undefine_order() {
    let mut sim = create_simulator!();
    let index = 0x0150_0602;
    define_platform(
        &mut sim,
        index,
        TpmaNv::PPREAD | TpmaNv::PPWRITE | TpmaNv::POLICY_DELETE,
        8,
        &EMPTY_POLICY,
    );
    set_hierarchy_enabled(&mut sim, Handle::RH_PLATFORM_NV, false);
    let handles = NVUndefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
        nv_index: Handle(index),
    };
    assert_eq!(
        pw(&mut sim, &NVUndefineSpace {}, handles, 1).unwrap_err(),
        TpmRc::HANDLE.with(Position::handle(2)).get()
    );
}

#[test]
fn nv_index_accessibility_hierarchy_and_handle_error_omissions_policy_nv() {
    let mut sim = create_simulator!();
    let index = 0x0150_0603;
    define(&mut sim, index, OWNER_RW | TpmaNv::AUTHREAD, 8, &[]);
    owner_write(&mut sim, index, 0, &[0; 8]).unwrap();
    set_hierarchy_enabled(&mut sim, Handle::RH_OWNER, false);
    let session = start_session(&mut sim, TpmSe::Policy);
    let cmd = PolicyNV {
        operand_b: Tpm2bOperand::from_bytes(&[0]).unwrap(),
        offset: 0,
        operation: TpmEo::Eq,
    };
    let handles = PolicyNVHandles {
        auth_handle: Handle(index),
        nv_index: Handle(index),
        policy_session: session.session_handle,
    };
    assert_eq!(
        pw(&mut sim, &cmd, handles, 1).unwrap_err(),
        TpmRc::HANDLE.with(Position::handle(1)).get()
    );
}

#[test]
fn nv_index_accessibility_hierarchy_and_handle_error_omissions_start_auth_session_bind() {
    let mut sim = create_simulator!();
    let rc = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle(0x0150_0604),
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::HANDLE.with(Position::handle(2)).get());
}

// ---------------------------------------------------------------------------------------------
// tpm2-hash-and-nv-globalwritelock-ticket-and-nv-availability-bugs and
// nv-storage-commands-omit-nv-available-checks-and-globallock-cap
// ---------------------------------------------------------------------------------------------

#[test]
fn tpm2_hash_and_nv_globalwritelock_ticket_and_nv_availability_bugs() {
    let mut sim = create_simulator!();
    let index = 0x0150_0700;
    define(&mut sim, index, OWNER_RW | TpmaNv::GLOBALLOCK, 8, &[]);
    let handles = NVGlobalWriteLockHandles {
        auth_handle: Handle::RH_OWNER,
    };
    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
    assert_eq!(
        pw(&mut sim, &NVGlobalWriteLock {}, handles, 1).unwrap_err(),
        TpmRc::NV_UNAVAILABLE.get()
    );
    sim.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();
    // The index was not locked.
    owner_write(&mut sim, index, 0, &[1; 8]).unwrap();
    pw(&mut sim, &NVGlobalWriteLock {}, handles, 1).unwrap();
    assert_eq!(
        owner_write(&mut sim, index, 0, &[2; 8]).unwrap_err(),
        TpmRc::NV_LOCKED.get()
    );
}

#[test]
fn nv_storage_commands_omit_nv_available_checks_and_globallock_cap() {
    let mut sim = create_simulator!();
    let index = 0x0150_0701;
    define(&mut sim, index, OWNER_RW, 8, &[]);
    owner_write(&mut sim, index, 0, &[1; 8]).unwrap();

    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
    let rc = try_define(
        &mut sim,
        Handle::RH_OWNER,
        &[],
        nv_public(0x0150_0702, OWNER_RW, 8, &[]),
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::NV_UNAVAILABLE.get());
    assert_eq!(
        owner_write(&mut sim, index, 0, &[2; 8]).unwrap_err(),
        TpmRc::NV_UNAVAILABLE.get()
    );
    let undefine = NVUndefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(index),
    };
    assert_eq!(
        pw(&mut sim, &NVUndefineSpace {}, undefine, 1).unwrap_err(),
        TpmRc::NV_UNAVAILABLE.get()
    );
    sim.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();

    // Nothing was changed while NV was unavailable.
    assert_eq!(
        read_as(&mut sim, Handle::RH_OWNER, index, 0, 8).unwrap(),
        vec![1; 8]
    );
}

// ---------------------------------------------------------------------------------------------
// nv-global-write-lock-hierarchy-enable-orderly-dirty-flag-and-auth-error-bugs
// ---------------------------------------------------------------------------------------------

/// A wrong owner password is reported by session processing as `TPM_RC_BAD_AUTH + RC_S1`
/// (owner authorization is DA-exempt), not as an unpositioned handler `TPM_RC_AUTH_FAIL`.
#[test]
fn nv_global_write_lock_hierarchy_enable_orderly_dirty_flag_and_auth_error_bugs() {
    let mut sim = create_simulator!();
    let change = HierarchyChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(b"abcd").unwrap(),
    };
    pw(
        &mut sim,
        &change,
        HierarchyChangeAuthHandles {
            auth_handle: Handle::RH_OWNER,
        },
        1,
    )
    .unwrap();
    let rc = execute_with_password_sessions_status(
        &mut sim,
        &NVGlobalWriteLock {},
        NVGlobalWriteLockHandles {
            auth_handle: Handle::RH_OWNER,
        },
        1,
        b"ab",
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::BAD_AUTH.with(Position::session(1)).get());
    execute_with_password_sessions_status(
        &mut sim,
        &NVGlobalWriteLock {},
        NVGlobalWriteLockHandles {
            auth_handle: Handle::RH_OWNER,
        },
        1,
        b"abcd",
    )
    .expect("NV_GlobalWriteLock with the owner password failed");
}

// ---------------------------------------------------------------------------------------------
// quote-and-nv-certify-handle-null-and-validation-order-bugs
// ---------------------------------------------------------------------------------------------

#[test]
fn quote_and_nv_certify_handle_null_and_validation_order_bugs_quote_null() {
    let mut sim = create_simulator!();
    let cmd = Quote {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
        pcr_select: TpmlPcrSelection::default(),
    };
    let handles = QuoteHandles {
        sign_handle: Handle::RH_NULL,
    };
    // `signHandle` is a `TPMI_DH_OBJECT+`, so TPM_RH_NULL passes handle validation (it used to
    // fail with TPM_RC_VALUE + RC_H1). The C command action then rejects the NULL scheme's
    // TPM_ALG_NULL hash with TPM_RC_SCHEME + RC_P2 (`Quote.c`).
    assert_eq!(
        pw(&mut sim, &cmd, handles, 1).unwrap_err(),
        TpmRc::SCHEME.with(Position::parameter(2)).get()
    );
}

#[test]
fn quote_and_nv_certify_handle_null_and_validation_order_bugs_nv_certify_handles() {
    let mut sim = create_simulator!();
    // Unloaded signHandle and undefined nvIndex: handle 1 is reported first.
    let handles = NVCertifyHandles {
        sign_handle: Handle(0x8000_0042),
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(0x0150_0800),
    };
    assert_eq!(
        nv_certify(&mut sim, handles, None, 0, 0, 2).unwrap_err(),
        TpmRc::REFERENCE_H0.get()
    );

    // authHandle must be a TPMI_RH_NV_AUTH.
    let index = 0x0150_0801;
    define(&mut sim, index, OWNER_RW, 8, &[]);
    let handles = NVCertifyHandles {
        sign_handle: Handle::RH_NULL,
        auth_handle: Handle::RH_ENDORSEMENT,
        nv_index: Handle(index),
    };
    assert_eq!(
        nv_certify(&mut sim, handles, None, 0, 0, 2).unwrap_err(),
        TpmRc::VALUE.with(Position::handle(2)).get()
    );

    // A valid index but an unloaded signing key: the key is resolved before NV checks.
    let handles = NVCertifyHandles {
        sign_handle: Handle(0x8000_0042),
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(index),
    };
    assert_eq!(
        nv_certify(&mut sim, handles, None, 4, 0, 2).unwrap_err(),
        TpmRc::REFERENCE_H0.get()
    );
}

// ---------------------------------------------------------------------------------------------
// nv-define-space-undefine-space-and-special-auth-order-unmarshal-failure-and-error-code-bugs
// ---------------------------------------------------------------------------------------------

#[test]
fn nv_define_space_undefine_space_and_special_auth_order_unmarshal_failure_and_error_code_bugs_nv_index_type()
 {
    let mut sim = create_simulator!();
    // `TPMS_NV_PUBLIC.nvIndex` is a `TPMI_RH_NV_LEGACY_INDEX` in the C reference
    // (`TPMS_NV_PUBLIC_Unmarshal`), so external/permanent NV handles fail unmarshaling with
    // `TPM_RC_VALUE` just like any other non-NV handle (the finding's `TPM_RC_HANDLE` claim does
    // not hold).
    for (index, expected) in [
        (0x1150_0000, TpmRc::VALUE.with(Position::parameter(2))),
        (0x1250_0000, TpmRc::VALUE.with(Position::parameter(2))),
        (0x0250_0000, TpmRc::VALUE.with(Position::parameter(2))),
    ] {
        let rc = try_define(
            &mut sim,
            Handle::RH_OWNER,
            &[],
            nv_public(index, OWNER_RW, 8, &[]),
        )
        .unwrap_err();
        assert_eq!(rc, expected.get(), "nvIndex {index:#x}");
    }
}

/// Without sessions, NV_UndefineSpace(Special) report `TPM_RC_AUTH_MISSING` before the
/// command action inspects the index attributes.
#[test]
fn nv_define_space_undefine_space_and_special_auth_order_unmarshal_failure_and_error_code_bugs_auth_missing()
 {
    let mut sim = create_simulator!();
    let index = 0x0150_0900;
    define_platform(
        &mut sim,
        index,
        TpmaNv::PPREAD | TpmaNv::PPWRITE | TpmaNv::POLICY_DELETE,
        8,
        &command_code_policy(TpmCc::NVUndefineSpaceSpecial),
    );
    let handles = NVUndefineSpaceHandles {
        auth_handle: Handle::RH_PLATFORM,
        nv_index: Handle(index),
    };
    assert_eq!(
        pw(&mut sim, &NVUndefineSpace {}, handles, 0).unwrap_err(),
        TpmRc::AUTH_MISSING.get()
    );

    let owner_index = 0x0150_0901;
    define(&mut sim, owner_index, OWNER_RW, 8, &[]);
    let handles = NVUndefineSpaceSpecialHandles {
        nv_index: Handle(owner_index),
        platform: Handle::RH_PLATFORM,
    };
    assert_eq!(
        pw(&mut sim, &NVUndefineSpaceSpecial {}, handles, 0).unwrap_err(),
        TpmRc::AUTH_MISSING.get()
    );
}

// ---------------------------------------------------------------------------------------------
// nv-increment-unpositioned-auth-errors-and-missing-policywrite-and-orderly-rollover
// ---------------------------------------------------------------------------------------------

fn counter_attrs() -> TpmaNv {
    TpmaNv::from(TpmNt::Counter)
}

#[test]
fn nv_increment_unpositioned_auth_errors_and_missing_policywrite_and_orderly_rollover_errors() {
    let mut sim = create_simulator!();
    let index = 0x0150_0a00;
    define(&mut sim, index, counter_attrs() | OWNER_RW, 8, &[]);
    let handles = NVIncrementHandles {
        auth_handle: Handle::RH_PLATFORM,
        nv_index: Handle(index),
    };
    assert_eq!(
        pw(&mut sim, &NVIncrement {}, handles, 1).unwrap_err(),
        TpmRc::NV_AUTHORIZATION.get()
    );
}

#[test]
fn nv_increment_unpositioned_auth_errors_and_missing_policywrite_and_orderly_rollover_policywrite()
{
    let mut sim = create_simulator!();
    let index = 0x0150_0a01;
    define(
        &mut sim,
        index,
        counter_attrs() | TpmaNv::POLICYWRITE | TpmaNv::OWNERREAD,
        8,
        &EMPTY_POLICY,
    );
    let name = nv_index_name(&mut sim, index);
    let mut session = start_session(&mut sim, TpmSe::Policy);
    let handles = NVIncrementHandles {
        auth_handle: Handle(index),
        nv_index: Handle(index),
    };
    with_session(
        &mut sim,
        &NVIncrement {},
        handles,
        &[&name, &name],
        &mut session,
    )
    .expect("NV_Increment with a POLICYWRITE policy session failed");
    assert_eq!(
        read_as(&mut sim, Handle::RH_OWNER, index, 0, 8).unwrap(),
        1u64.to_be_bytes().to_vec()
    );
}

/// A new counter starts from the largest value of a *deleted* counter (C `s_maxCounter`), not
/// from the value of other live counters.
#[test]
fn nv_increment_unpositioned_auth_errors_and_missing_policywrite_and_orderly_rollover_max_counter()
{
    let mut sim = create_simulator!();
    let first = 0x0150_0a02;
    define(&mut sim, first, counter_attrs() | OWNER_RW, 8, &[]);
    let inc = |sim: &mut Simulator<'_>, index: u32| {
        let handles = NVIncrementHandles {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(index),
        };
        pw(sim, &NVIncrement {}, handles, 1).unwrap();
    };
    for _ in 0..5 {
        inc(&mut sim, first);
    }
    let second = 0x0150_0a03;
    define(&mut sim, second, counter_attrs() | OWNER_RW, 8, &[]);
    inc(&mut sim, second);
    assert_eq!(
        read_as(&mut sim, Handle::RH_OWNER, second, 0, 8).unwrap(),
        1u64.to_be_bytes().to_vec()
    );

    // Deleting the first counter makes its value the floor for new counters.
    let undefine = NVUndefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(first),
    };
    pw(&mut sim, &NVUndefineSpace {}, undefine, 1).unwrap();
    let third = 0x0150_0a04;
    define(&mut sim, third, counter_attrs() | OWNER_RW, 8, &[]);
    inc(&mut sim, third);
    assert_eq!(
        read_as(&mut sim, Handle::RH_OWNER, third, 0, 8).unwrap(),
        6u64.to_be_bytes().to_vec()
    );
}

/// NV_ChangeAuth needs NV only when the authValue actually changes (C `NvWriteIndexAuth` ->
/// `NvConditionallyWrite`).
#[test]
fn nv_storage_commands_omit_nv_available_checks_and_globallock_cap_change_auth() {
    let mut sim = create_simulator!();
    let index = 0x0150_0703;
    define_change_auth_index(&mut sim, index, 8);
    let name = nv_index_name(&mut sim, index);
    let handles = NVChangeAuthHandles {
        nv_index: Handle(index),
    };
    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();

    // Same (empty) authValue: nothing to write.
    let mut session = start_session(&mut sim, TpmSe::Policy);
    policy_command_code(&mut sim, &session, TpmCc::NVChangeAuth);
    with_session(
        &mut sim,
        &change_auth_cmd(&[]),
        handles,
        &[&name],
        &mut session,
    )
    .expect("NV_ChangeAuth without a change must not need NV");

    // A new authValue must be written to NV.
    policy_command_code(&mut sim, &session, TpmCc::NVChangeAuth);
    let rc = with_session(
        &mut sim,
        &change_auth_cmd(b"new"),
        handles,
        &[&name],
        &mut session,
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::NV_UNAVAILABLE.get());
}

/// The NV accessibility check only applies to positions that can hold an NV Index; a
/// `TPMI_DH_OBJECT` position rejects an NV Index handle at unmarshaling (`TPM_RC_VALUE`).
#[test]
fn nv_index_accessibility_hierarchy_and_handle_error_omissions_object_slot() {
    let mut sim = create_simulator!();
    let cmd = ObjectChangeAuth {
        new_auth: Tpm2bAuth::default(),
    };
    let handles = ObjectChangeAuthHandles {
        object_handle: Handle(0x0150_0605),
        parent_handle: Handle::RH_OWNER,
    };
    assert_eq!(
        pw(&mut sim, &cmd, handles, 1).unwrap_err(),
        TpmRc::VALUE.with(Position::handle(1)).get()
    );
}
