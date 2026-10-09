//! End-to-end regression tests for the `policy` findings in command-handlers.toml.
//!
//! Owned by the `fix-policy` worker; add submodules under `findings_policy/` if this grows.
//!
//! Every test is named after the finding it covers and drives the TPM strictly through the
//! simulator's command interface. Each one fails on the code before the corresponding fix.

#![allow(unused_imports)]

use crate::test_utils::*;
use tpm2::commands::{
    CreatePrimary, CreatePrimaryHandles, HierarchyChangeAuth, HierarchyChangeAuthHandles,
    LoadExternal, NVDefineSpace, NVDefineSpaceHandles, NVWrite, NVWriteHandles, PCRSetAuthValue,
    PCRSetAuthValueHandles, PolicyAuthorizeNV, PolicyAuthorizeNVHandles, PolicyCommandCode,
    PolicyCommandCodeHandles, PolicyCounterTimer, PolicyCounterTimerHandles, PolicyCpHash,
    PolicyCpHashHandles, PolicyDuplicationSelect, PolicyDuplicationSelectHandles, PolicyGetDigest,
    PolicyGetDigestHandles, PolicyNV, PolicyNVHandles, PolicyNameHash, PolicyNameHashHandles,
    PolicyOR, PolicyORHandles, PolicyPCR, PolicyPCRHandles, PolicyRestart, PolicyRestartHandles,
    PolicySecret, PolicySecretHandles, PolicySigned, PolicySignedHandles, PolicyTemplate,
    PolicyTemplateHandles, PolicyTicket, PolicyTicketHandles, StartAuthSession,
    StartAuthSessionHandles,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bNonce,
    Tpm2bOperand, Tpm2bSensitiveData, Tpm2bTimeout, TpmCc, TpmEo, TpmNt, TpmSe, TpmaNv, TpmaObject,
    TpmiAlgHash, TpmiAlgSymMode, TpmlDigest, TpmlPcrSelection, TpmsEccParms, TpmsNvPublic,
    TpmsPcrSelection, TpmsSensitiveCreate, TpmtEccScheme, TpmtHa, TpmtKeyedHashScheme, TpmtPublic,
    TpmtSignature, TpmtSymDefObject, TpmtTkAuth,
};
use tpm2::{Marshal, Tpm2b};
use tpm2_simulator::{Simulator, SimulatorPlatformSignal, create_simulator};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Executes a command that needs no authorization sessions.
fn run<C: tpm2::commands::Command>(
    sim: &mut Simulator<'_>,
    cmd: C,
    handles: C::Handles,
) -> Result<C::Response<'static>, u32>
where
    C::Response<'static>: tpm2::Unmarshal<'static>,
    for<'b> &'b mut C::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <C::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    execute_with_password_sessions(sim, &cmd, handles, 0, &[]).map(|(rsp, _)| rsp)
}

/// Executes a command with one (empty) password session for its first handle.
fn run_pw<C: tpm2::commands::Command>(
    sim: &mut Simulator<'_>,
    cmd: C,
    handles: C::Handles,
) -> Result<C::Response<'static>, u32>
where
    C::Response<'static>: tpm2::Unmarshal<'static>,
    for<'b> &'b mut C::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <C::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    execute_with_password_sessions(sim, &cmd, handles, 1, &[]).map(|(rsp, _)| rsp)
}

/// Flushes every loaded authorization session except those in `keep` (the TPM only holds a
/// few sessions at a time).
fn flush_sessions_except(sim: &mut Simulator<'_>, keep: &[Handle]) {
    for slot in 0..tpm2::TPM2_MAX_ACTIVE_SESSIONS {
        for prefix in [0x0200_0000, 0x0300_0000] {
            let handle = Handle(prefix | slot);
            if !keep.contains(&handle) {
                let _ = flush_context(sim, handle);
            }
        }
    }
}

/// Starts an unbound, unsalted session of `session_type`, keeping the sessions in `keep` loaded
/// and flushing all others.
fn start_keep(
    sim: &mut Simulator<'_>,
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

/// Starts an unbound, unsalted session of `session_type` (flushing all other sessions).
fn start(sim: &mut Simulator<'_>, session_type: TpmSe, hash: TpmiAlgHash) -> ActiveSession {
    start_keep(sim, session_type, hash, &[])
}

/// Starts a SHA-256 session bound to `bind` (flushing all other sessions).
fn start_bound(
    sim: &mut Simulator<'_>,
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

fn policy_digest(sim: &mut Simulator<'_>, session: Handle) -> Vec<u8> {
    let rsp = run(
        sim,
        PolicyGetDigest {},
        PolicyGetDigestHandles {
            policy_session: session,
        },
    )
    .expect("PolicyGetDigest");
    rsp.policy_digest.get_buffer().to_vec()
}

fn digest(bytes: &[u8]) -> Tpm2bDigest<'static> {
    Tpm2bDigest::from_bytes(leak_bytes(bytes)).unwrap()
}

fn sha(hash: TpmiAlgHash, parts: &[&[u8]]) -> Vec<u8> {
    let mut state = tpm2::crypto::HashCtx::new(CLIENT_CRYPTO, hash).unwrap();
    for part in parts {
        state.update(part).unwrap();
    }
    let mut out = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    state.finalize(&mut out).unwrap().digest().to_vec()
}

fn hmac(hash: TpmiAlgHash, key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut state = tpm2::crypto::HmacCtx::new(CLIENT_CRYPTO, hash, key).unwrap();
    state.update(data).unwrap();
    let mut out = [0u8; TpmtHa::MAX_DIGEST_SIZE];
    state.finalize(&mut out).unwrap().digest().to_vec()
}

/// Defines an owner-created NV Index with an empty authValue.
fn define_nv(sim: &mut Simulator<'_>, index: u32, attributes: TpmaNv, data_size: u16) {
    define_nv_with_policy(sim, index, attributes, data_size, &[]);
}

fn define_nv_with_policy(
    sim: &mut Simulator<'_>,
    index: u32,
    attributes: TpmaNv,
    data_size: u16,
    auth_policy: &[u8],
) {
    let public = TpmsNvPublic {
        nv_index: Handle(index),
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: digest(auth_policy),
        data_size,
    };
    run_pw(
        sim,
        NVDefineSpace {
            auth: Tpm2bAuth::default(),
            public_info: Tpm2b(public),
        },
        NVDefineSpaceHandles {
            auth_handle: Handle::RH_OWNER,
        },
    )
    .expect("NV_DefineSpace");
}

/// Writes `data` at offset 0 of `index`, authorized by the owner.
fn write_nv_owner(sim: &mut Simulator<'_>, index: u32, data: &[u8]) {
    run_pw(
        sim,
        NVWrite {
            data: tpm2::Tpm2bMaxNvBuffer::from_bytes(leak_bytes(data)).unwrap(),
            offset: 0,
        },
        NVWriteHandles {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(index),
        },
    )
    .expect("NV_Write");
}

fn create_primary(sim: &mut Simulator<'_>, public: TpmtPublic<'static>) -> (Handle, Vec<u8>) {
    create_primary_with_data(sim, public, &[])
}

fn create_primary_with_data(
    sim: &mut Simulator<'_>,
    public: TpmtPublic<'static>,
    data: &[u8],
) -> (Handle, Vec<u8>) {
    let cmd = CreatePrimary {
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::from_bytes(leak_bytes(data)).unwrap(),
        }),
        in_public: Tpm2b(public),
        ..Default::default()
    };
    let (rsp, handles) = execute_with_password_sessions(
        sim,
        &cmd,
        CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        },
        1,
        &[],
    )
    .expect("CreatePrimary");
    (handles.object_handle, rsp.name.get_buffer().to_vec())
}

fn ecc_signing_template(name_alg: TpmiAlgHash) -> TpmtPublic<'static> {
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

fn hmac_key_template(scheme_hash: TpmiAlgHash) -> TpmtPublic<'static> {
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

/// `TPM2_PolicySigned` with empty nonce/cpHash/policyRef and expiration 0.
fn policy_signed(
    sim: &mut Simulator<'_>,
    auth_object: Handle,
    session: Handle,
    auth: TpmtSignature<'static>,
) -> Result<(), u32> {
    run(
        sim,
        PolicySigned {
            nonce_tpm: Tpm2bNonce::default(),
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: Tpm2bNonce::default(),
            expiration: 0,
            auth,
        },
        PolicySignedHandles {
            auth_object,
            policy_session: session,
        },
    )
    .map(|_| ())
}

fn policy_secret(
    sim: &mut Simulator<'_>,
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
            nonce_tpm,
            cp_hash_a: digest(cp_hash_a),
            policy_ref: Tpm2bNonce::default(),
            expiration,
        },
        PolicySecretHandles {
            auth_handle,
            policy_session: session.session_handle,
        },
    )
}

fn policy_cp_hash(sim: &mut Simulator<'_>, session: Handle, cp_hash: &[u8]) -> Result<(), u32> {
    run(
        sim,
        PolicyCpHash {
            cp_hash_a: digest(cp_hash),
        },
        PolicyCpHashHandles {
            policy_session: session,
        },
    )
    .map(|_| ())
}

fn policy_name_hash(sim: &mut Simulator<'_>, session: Handle, name_hash: &[u8]) -> Result<(), u32> {
    run(
        sim,
        PolicyNameHash {
            name_hash: digest(name_hash),
        },
        PolicyNameHashHandles {
            policy_session: session,
        },
    )
    .map(|_| ())
}

fn policy_template(sim: &mut Simulator<'_>, session: Handle, hash: &[u8]) -> Result<(), u32> {
    run(
        sim,
        PolicyTemplate {
            template_hash: digest(hash),
        },
        PolicyTemplateHandles {
            policy_session: session,
        },
    )
    .map(|_| ())
}

fn policy_duplication_select(
    sim: &mut Simulator<'_>,
    session: Handle,
    object_name: &[u8],
    new_parent_name: &[u8],
    include_object: bool,
) -> Result<(), u32> {
    run(
        sim,
        PolicyDuplicationSelect {
            object_name: Tpm2bName::from_bytes(leak_bytes(object_name)).unwrap(),
            new_parent_name: Tpm2bName::from_bytes(leak_bytes(new_parent_name)).unwrap(),
            include_object,
        },
        PolicyDuplicationSelectHandles {
            policy_session: session,
        },
    )
    .map(|_| ())
}

fn policy_ticket(
    sim: &mut Simulator<'_>,
    session: Handle,
    timeout: &[u8],
    cp_hash_a: &[u8],
    auth_name: &[u8],
    ticket: TpmtTkAuth<'static>,
) -> Result<(), u32> {
    run(
        sim,
        PolicyTicket {
            timeout: Tpm2bTimeout::from_bytes(leak_bytes(timeout)).unwrap(),
            cp_hash_a: digest(cp_hash_a),
            policy_ref: Tpm2bNonce::default(),
            auth_name: Tpm2bName::from_bytes(leak_bytes(auth_name)).unwrap(),
            ticket,
        },
        PolicyTicketHandles {
            policy_session: session,
        },
    )
    .map(|_| ())
}

fn policy_pcr(
    sim: &mut Simulator<'_>,
    session: Handle,
    pcr_digest: &[u8],
    pcrs: &[TpmsPcrSelection],
) -> Result<(), u32> {
    run(
        sim,
        PolicyPCR {
            pcr_digest: digest(pcr_digest),
            pcrs: TpmlPcrSelection::from_slice(pcrs).unwrap(),
        },
        PolicyPCRHandles {
            policy_session: session,
        },
    )
    .map(|_| ())
}

fn policy_nv(
    sim: &mut Simulator<'_>,
    auth_handle: Handle,
    nv_index: u32,
    session: Handle,
    operand_b: &[u8],
    offset: u16,
) -> Result<(), u32> {
    run_pw(
        sim,
        PolicyNV {
            operand_b: Tpm2bOperand::from_bytes(leak_bytes(operand_b)).unwrap(),
            offset,
            operation: TpmEo::Eq,
        },
        PolicyNVHandles {
            auth_handle,
            nv_index: Handle(nv_index),
            policy_session: session,
        },
    )
    .map(|_| ())
}

fn policy_authorize_nv(
    sim: &mut Simulator<'_>,
    auth_handle: Handle,
    nv_index: u32,
    session: Handle,
) -> Result<(), u32> {
    run_pw(
        sim,
        PolicyAuthorizeNV {},
        PolicyAuthorizeNVHandles {
            auth_handle,
            nv_index: Handle(nv_index),
            policy_session: session,
        },
    )
    .map(|_| ())
}

fn policy_command_code(sim: &mut Simulator<'_>, session: Handle, code: TpmCc) -> Result<(), u32> {
    run(
        sim,
        PolicyCommandCode { code },
        PolicyCommandCodeHandles {
            policy_session: session,
        },
    )
    .map(|_| ())
}

fn pcr_sel(hash: TpmiAlgHash, select: &[u8]) -> TpmsPcrSelection {
    TpmsPcrSelection::new(hash, select).unwrap()
}

fn marshal_pcrs(pcrs: &[TpmsPcrSelection]) -> Vec<u8> {
    marshal_to_vec(&TpmlPcrSelection::from_slice(pcrs).unwrap())
}

/// The command code of `TPM2_PolicyPCR`.
const CC_POLICY_PCR: u32 = 0x0000_017F;

/// `TPMA_NV` for an owner-written index with authValue reads.
fn nv_attrs(extra: TpmaNv) -> TpmaNv {
    TpmaNv::OWNERWRITE | TpmaNv::AUTHREAD | extra
}

// ---------------------------------------------------------------------------
// cpHash union: bound policy sessions, templateHash occupancy, nameHash repeats,
// PolicyTemplate check order, PolicyDuplicationSelect Names
// ---------------------------------------------------------------------------

/// A policy session started with `bind != TPM_RH_NULL` is not bound (C `SessionCreate` only
/// binds HMAC sessions), so the cpHash-union commands must not fail with `TPM_RC_CPHASH`.
#[test]
fn policy_session_bind_entity_cphash_rejection() {
    let mut sim = create_simulator!();
    let bound = |sim: &mut Simulator<'_>, session_type| {
        start_bound(sim, Handle::RH_OWNER, &[], session_type).session_handle
    };
    for session_type in [TpmSe::Policy, TpmSe::Trial] {
        let s = bound(&mut sim, session_type);
        policy_cp_hash(&mut sim, s, &[0x11; 32]).expect("PolicyCpHash on bound policy session");
        let s = bound(&mut sim, session_type);
        policy_name_hash(&mut sim, s, &[0x22; 32]).expect("PolicyNameHash on bound session");
        let s = bound(&mut sim, session_type);
        policy_template(&mut sim, s, &[0x33; 32]).expect("PolicyTemplate on bound session");
        let s = bound(&mut sim, session_type);
        policy_duplication_select(&mut sim, s, &[], &[0x40, 0, 0, 1], false)
            .expect("PolicyDuplicationSelect on bound session");
    }
}

/// Covers the same bug as reported in the combined cpHash-union finding (part 5).
#[test]
fn tpm2_policycphash_policynamehash_union_and_policyor_error_bugs() {
    let mut sim = create_simulator!();
    // Part 5: bound policy session (see also `policy_session_bind_entity_cphash_rejection`).
    let s = start_bound(&mut sim, Handle::RH_ENDORSEMENT, &[], TpmSe::Policy).session_handle;
    policy_cp_hash(&mut sim, s, &[0x11; 32]).unwrap();

    // Part 1: templateHash occupies the union for PolicyCpHash and PolicyNameHash.
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    policy_template(&mut sim, s, &[0x33; 32]).unwrap();
    assert_eq!(
        policy_cp_hash(&mut sim, s, &[0x33; 32]),
        Err(TpmRc::CPHASH.get())
    );
    assert_eq!(
        policy_name_hash(&mut sim, s, &[0x33; 32]),
        Err(TpmRc::CPHASH.get())
    );

    // Part 1: PolicyNameHash never accepts a repeat, even of the same value.
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    policy_name_hash(&mut sim, s, &[0x22; 32]).unwrap();
    assert_eq!(
        policy_name_hash(&mut sim, s, &[0x22; 32]),
        Err(TpmRc::CPHASH.get())
    );

    // Part 2: PolicyTemplate checks the union before the templateHash size.
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    policy_cp_hash(&mut sim, s, &[0x11; 32]).unwrap();
    assert_eq!(
        policy_template(&mut sim, s, &[0x33; 5]),
        Err(TpmRc::CPHASH.get())
    );

    // Part 3: PolicyOR no-match error carries RC_P1.
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    let err = run(
        &mut sim,
        PolicyOR {
            p_hash_list: TpmlDigest::from_slice(&[digest(&[1; 32]), digest(&[2; 32])]).unwrap(),
        },
        PolicyORHandles { policy_session: s },
    )
    .unwrap_err();
    assert_eq!(err, TpmRc::VALUE.with(Position::parameter(1)).get());
}

#[test]
fn policy_cp_hash_and_policy_name_hash_is_cp_hash_union_occupied_omissions() {
    let mut sim = create_simulator!();
    let s = start(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    policy_template(&mut sim, s, &[0x33; 32]).unwrap();
    assert_eq!(
        policy_cp_hash(&mut sim, s, &[0x44; 32]),
        Err(TpmRc::CPHASH.get())
    );
    assert_eq!(
        policy_name_hash(&mut sim, s, &[0x44; 32]),
        Err(TpmRc::CPHASH.get())
    );

    let s = start(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    policy_name_hash(&mut sim, s, &[0x55; 32]).unwrap();
    let before = policy_digest(&mut sim, s);
    assert_eq!(
        policy_name_hash(&mut sim, s, &[0x55; 32]),
        Err(TpmRc::CPHASH.get())
    );
    assert_eq!(
        policy_digest(&mut sim, s),
        before,
        "digest must not be extended twice"
    );
}

#[test]
fn policy_cphash_namehash_template_duplication_select_union_occupancy_and_validation_bugs() {
    let mut sim = create_simulator!();
    // 1. Bound policy session + PolicyDuplicationSelect.
    let s = start_bound(&mut sim, Handle::RH_OWNER, &[], TpmSe::Policy).session_handle;
    policy_duplication_select(&mut sim, s, &[1, 2, 3], &[4, 5, 6, 7, 8], true).unwrap();

    // 4. PolicyTemplate: occupancy (CPHASH) before size (SIZE + RC_P1).
    let s = start(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    policy_name_hash(&mut sim, s, &[0x55; 32]).unwrap();
    assert_eq!(
        policy_template(&mut sim, s, &[0x66; 20]),
        Err(TpmRc::CPHASH.get())
    );
}

/// Names are opaque TPM2B_NAME values: no algorithm-prefix/length validation.
#[test]
fn tpm2_policyduplicationselect_erroneous_name_structure_validation() {
    let mut sim = create_simulator!();
    let s = start(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    // 0xFFFF is not a hash algorithm; the length matches no digest.
    let object_name = [0xFF, 0xFF, 1, 2, 3];
    let new_parent_name = [0x00, 0x0B, 9, 9, 9];
    policy_duplication_select(&mut sim, s, &object_name, &new_parent_name, true).unwrap();

    // The policy digest matches the C reference computation.
    let name_digest = sha(
        TpmiAlgHash::Sha256,
        &[
            &[0u8; 32],
            &TpmCc::PolicyDuplicationSelect.code().to_be_bytes(),
            &object_name,
            &new_parent_name,
            &[1],
        ],
    );
    assert_eq!(policy_digest(&mut sim, s), name_digest);
}

#[test]
fn tpm2_policyduplicationselect_name_structure_validation_and_union_bugs() {
    let mut sim = create_simulator!();
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    // A 2-byte SHA-256 prefix with a truncated digest was rejected with TPM_RC_SIZE + RC_P2.
    policy_duplication_select(&mut sim, s, &[], &[0x00, 0x0B, 1, 2], false).unwrap();
}

// ---------------------------------------------------------------------------
// PolicyOR
// ---------------------------------------------------------------------------

#[test]
fn tpm2_policyor_error_position_and_sm3_rejection_bugs() {
    let mut sim = create_simulator!();
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    let err = run(
        &mut sim,
        PolicyOR {
            p_hash_list: TpmlDigest::from_slice(&[digest(&[7; 32]), digest(&[8; 32])]).unwrap(),
        },
        PolicyORHandles { policy_session: s },
    )
    .unwrap_err();
    assert_eq!(err, TpmRc::VALUE.with(Position::parameter(1)).get());

    // A matching digest is still accepted.
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    run(
        &mut sim,
        PolicyOR {
            p_hash_list: TpmlDigest::from_slice(&[digest(&[0; 32]), digest(&[8; 32])]).unwrap(),
        },
        PolicyORHandles { policy_session: s },
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// PolicyTicket / PolicySecret tickets / PolicyParameterChecks
// ---------------------------------------------------------------------------

fn null_secret_ticket() -> TpmtTkAuth<'static> {
    TpmtTkAuth::Secret(Handle::RH_OWNER, digest(&[0; 32]))
}

#[test]
fn policy_ticket_trial_session_allowed_and_validation_order() {
    let mut sim = create_simulator!();
    let owner_name = Handle::RH_OWNER.0.to_be_bytes();

    // 1. Trial sessions are rejected (TPM_RCS_ATTRIBUTES + RC_PolicyTicket_policySession).
    let s = start(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_ticket(&mut sim, s, &[0; 8], &[], &owner_name, null_secret_ticket()),
        Err(TpmRc::ATTRIBUTES.with(Position::handle(1)).get())
    );

    // 2. The timeout must be exactly 8 bytes (TPM_RCS_SIZE + RC_PolicyTicket_timeout).
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_ticket(&mut sim, s, &[], &[], &owner_name, null_secret_ticket()),
        Err(TpmRc::SIZE.with(Position::parameter(1)).get())
    );
    assert_eq!(
        policy_ticket(&mut sim, s, &[0; 4], &[], &owner_name, null_secret_ticket()),
        Err(TpmRc::SIZE.with(Position::parameter(1)).get())
    );

    // 3. PolicyParameterChecks (cpHashA size) run before the ticket is validated.
    assert_eq!(
        policy_ticket(
            &mut sim,
            s,
            &[0; 8],
            &[0xAA; 5],
            &owner_name,
            null_secret_ticket()
        ),
        Err(TpmRc::SIZE.with(Position::parameter(2)).get())
    );
    // ... and a cpHashA conflicting with the session's cpHash is TPM_RC_CPHASH, not TICKET.
    policy_cp_hash(&mut sim, s, &[0x11; 32]).unwrap();
    assert_eq!(
        policy_ticket(
            &mut sim,
            s,
            &[0; 8],
            &[0x22; 32],
            &owner_name,
            null_secret_ticket()
        ),
        Err(TpmRc::CPHASH.get())
    );
    // A bad ticket with otherwise valid parameters is still TPM_RC_TICKET + RC_P5.
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_ticket(&mut sim, s, &[0; 8], &[], &owner_name, null_secret_ticket()),
        Err(TpmRc::TICKET.with(Position::parameter(5)).get())
    );
}

/// PolicySecret tickets use `EntityGetHierarchy`: lockout, PCR and owner-created NV indices
/// belong to the owner hierarchy; PIN Pass indices never get a ticket. PolicyTicket rejects
/// trial sessions and empty timeouts.
#[test]
fn tpm2_policysecret_and_tpm2_policyticket_hierarchy_resolution_and_trial_session_bugs() {
    let mut sim = create_simulator!();

    // TPM_RH_LOCKOUT -> TPM_RH_OWNER, and the ticket validates with the owner proof.
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256);
    let rsp = policy_secret(&mut sim, Handle::RH_LOCKOUT, &s, &[], -100).unwrap();
    assert_eq!(rsp.policy_ticket.hierarchy(), Handle::RH_OWNER);
    assert_eq!(rsp.timeout.get_size(), 8);
    let s2 = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    policy_ticket(
        &mut sim,
        s2,
        rsp.timeout.get_buffer(),
        &[],
        &Handle::RH_LOCKOUT.0.to_be_bytes(),
        rsp.policy_ticket,
    )
    .expect("PolicyTicket with a lockout PolicySecret ticket");

    // Ordinary NV Index without PLATFORMCREATE -> TPM_RH_OWNER.
    let index = 0x0150_0010;
    define_nv(&mut sim, index, nv_attrs(TpmaNv::empty()), 8);
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256);
    let rsp = policy_secret(&mut sim, Handle(index), &s, &[], -100).unwrap();
    assert_eq!(rsp.policy_ticket.hierarchy(), Handle::RH_OWNER);

    // Trial session on PolicyTicket.
    let t = start(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_ticket(
            &mut sim,
            t,
            &[0; 8],
            &[],
            &Handle::RH_OWNER.0.to_be_bytes(),
            null_secret_ticket()
        ),
        Err(TpmRc::ATTRIBUTES.with(Position::handle(1)).get())
    );
}

fn define_pin_pass(sim: &mut Simulator<'_>, index: u32) {
    let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::AUTHREAD | TpmaNv::NO_DA;
    attributes.set_type(TpmNt::PinPass);
    define_nv(sim, index, attributes, 8);
    // pinCount = 0, pinLimit = 10
    write_nv_owner(sim, index, &[0, 0, 0, 0, 0, 0, 0, 10]);
}

#[test]
fn policy_parameter_checks_nv_unavailable_and_pinpass_ticket_bugs() {
    let mut sim = create_simulator!();

    // PIN Pass index: no ticket (null ticket, empty timeout).
    let index = 0x0150_0011;
    define_pin_pass(&mut sim, index);
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256);
    let rsp = policy_secret(&mut sim, Handle(index), &s, &[], -100).unwrap();
    assert_eq!(rsp.timeout.get_size(), 0);
    assert_eq!(rsp.policy_ticket.hierarchy(), Handle::RH_NULL);
    assert_eq!(rsp.policy_ticket.digest().get_size(), 0);

    // NV unavailable: an expiration cannot be checked (RETURN_IF_NV_IS_NOT_AVAILABLE).
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256);
    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
    assert_eq!(
        policy_secret(&mut sim, Handle::RH_OWNER, &s, &[], 100).map(|_| ()),
        Err(TpmRc::NV_UNAVAILABLE.get())
    );
    // Without an expiration NV is not needed.
    policy_secret(&mut sim, Handle::RH_OWNER, &s, &[], 0).unwrap();
    sim.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();
    policy_secret(&mut sim, Handle::RH_OWNER, &s, &[], 100).unwrap();
}

#[test]
fn nv_index_isauthvalueavailable_isauthpolicyavailable_bypass() {
    // Part 3 (PIN Pass tickets); parts 1-2 are engine authorization checks (fix-auth).
    let mut sim = create_simulator!();
    let index = 0x0150_0012;
    define_pin_pass(&mut sim, index);
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256);
    let rsp = policy_secret(&mut sim, Handle(index), &s, &[], -1).unwrap();
    assert_eq!(rsp.timeout.get_size(), 0);
    assert_eq!(rsp.policy_ticket.tag(), tpm2::TpmSt::AUTH_SECRET.id());
    assert_eq!(rsp.policy_ticket.hierarchy(), Handle::RH_NULL);
    assert_eq!(rsp.policy_ticket.digest().get_size(), 0);
}

// ---------------------------------------------------------------------------
// PolicyRestart / SessionResetPolicyData
// ---------------------------------------------------------------------------

#[test]
fn policy_session_reset_omits_timeout_and_include_auth() {
    let mut sim = create_simulator!();

    // 1. PolicyRestart clears the cpHash union (`u1.cpHash.b.size = 0`).
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256);
    policy_cp_hash(&mut sim, s.session_handle, &[0x11; 32]).unwrap();
    run(
        &mut sim,
        PolicyRestart {},
        PolicyRestartHandles {
            session_handle: s.session_handle,
        },
    )
    .unwrap();
    policy_secret(&mut sim, Handle::RH_OWNER, &s, &[0x22; 32], 0)
        .expect("cpHashA after PolicyRestart");
    run(
        &mut sim,
        PolicyRestart {},
        PolicyRestartHandles {
            session_handle: s.session_handle,
        },
    )
    .unwrap();
    policy_duplication_select(&mut sim, s.session_handle, &[], &[1, 2, 3, 4], false)
        .expect("PolicyDuplicationSelect after PolicyRestart");

    // 2. PolicyRestart clears the timeout: a 1 s PolicySecret expiration must not expire the
    //    restarted session.
    let index = 0x0150_0013;
    let mut s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256);
    define_nv_with_policy(
        &mut sim,
        index,
        TpmaNv::POLICYWRITE | TpmaNv::AUTHREAD,
        8,
        &[0; 32],
    );
    policy_secret(&mut sim, Handle::RH_OWNER, &s, &[], 1).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1500));
    run(
        &mut sim,
        PolicyRestart {},
        PolicyRestartHandles {
            session_handle: s.session_handle,
        },
    )
    .unwrap();
    s.attributes.insert(tpm2::TpmaSession::CONTINUE_SESSION);
    execute_with_hmac_sessions(
        &mut sim,
        &NVWrite {
            data: tpm2::Tpm2bMaxNvBuffer::from_bytes(&[1; 8]).unwrap(),
            offset: 0,
        },
        NVWriteHandles {
            auth_handle: Handle(index),
            nv_index: Handle(index),
        },
        &[],
        &mut [s],
        &[&[]],
    )
    .expect("restarted policy session must not be expired");
}

// ---------------------------------------------------------------------------
// PolicyCommandCode
// ---------------------------------------------------------------------------

#[test]
fn startauthsession_and_policycommandcode_session_parsing_and_error_bugs() {
    let mut sim = create_simulator!();
    let unimplemented = TpmCc::new(0x0000_FFFF);

    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_command_code(&mut sim, s, unimplemented),
        Err(TpmRc::POLICY_CC.with(Position::parameter(1)).get())
    );

    // A conflicting command code is reported first (TPM_RCS_VALUE + RC_P1).
    policy_command_code(&mut sim, s, TpmCc::Sign).unwrap();
    assert_eq!(
        policy_command_code(&mut sim, s, unimplemented),
        Err(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
    assert_eq!(
        policy_command_code(&mut sim, s, TpmCc::Unseal),
        Err(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
}

#[test]
fn verify_session_hmacs_policy_secret_mode_and_policy_alg_omissions() {
    // Part 4 (policy_command_code); parts 1-3 are engine checks handed over to fix-sessions.
    let mut sim = create_simulator!();
    let s = start(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    policy_command_code(&mut sim, s, TpmCc::NVRead).unwrap();
    assert_eq!(
        policy_command_code(&mut sim, s, TpmCc::NVWrite),
        Err(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
}

// ---------------------------------------------------------------------------
// PolicyCounterTimer
// ---------------------------------------------------------------------------

#[test]
fn tpm2_policycountertimer_unsigned_lt_offset_0_divergence() {
    let mut sim = create_simulator!();
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    let counter_timer = |sim: &mut Simulator<'_>, offset: u16| {
        run(
            sim,
            PolicyCounterTimer {
                operand_b: Tpm2bOperand::from_bytes(&[0; 8]).unwrap(),
                offset,
                operation: TpmEo::UnsignedGE,
            },
            PolicyCounterTimerHandles { policy_session: s },
        )
        .map(|_| ())
    };
    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
    // time (offset 0) and clock (offset 8) need a running Clock.
    assert_eq!(counter_timer(&mut sim, 0), Err(TpmRc::NV_UNAVAILABLE.get()));
    assert_eq!(counter_timer(&mut sim, 8), Err(TpmRc::NV_UNAVAILABLE.get()));
    // resetCount/restartCount (offset >= 16) do not.
    counter_timer(&mut sim, 16).unwrap();
    sim.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();
    counter_timer(&mut sim, 8).unwrap();
}

// ---------------------------------------------------------------------------
// PolicyPCR
// ---------------------------------------------------------------------------

fn expected_policy_pcr(
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

#[test]
fn tpm2_policypcr_reorders_banks_corrupts_sha1_trial_sessions_and_wrong_error_positions() {
    let mut sim = create_simulator!();
    // Banks deliberately not in algorithm-ID order: SHA-256 (0x0B) before SHA-1 (0x04).
    let pcrs = [
        pcr_sel(TpmiAlgHash::Sha256, &[1, 0, 0]),
        pcr_sel(TpmiAlgHash::Sha1, &[1, 0, 0]),
    ];
    // PCR 0 is all-zero after TPM2_Startup(CLEAR).
    let expected = expected_policy_pcr(TpmiAlgHash::Sha256, &pcrs, &[&[0; 32], &[0; 20]]);

    let trial = start(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    policy_pcr(&mut sim, trial, &[], &pcrs).unwrap();
    assert_eq!(policy_digest(&mut sim, trial), expected);

    let policy = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    policy_pcr(&mut sim, policy, &[], &pcrs).unwrap();
    assert_eq!(policy_digest(&mut sim, policy), expected);

    // SHA-1 trial session with an empty pcrDigest uses the computed PCR digest.
    let pcrs1 = [pcr_sel(TpmiAlgHash::Sha256, &[1, 0, 0])];
    let trial = start(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha1).session_handle;
    policy_pcr(&mut sim, trial, &[], &pcrs1).unwrap();
    assert_eq!(
        policy_digest(&mut sim, trial),
        expected_policy_pcr(TpmiAlgHash::Sha1, &pcrs1, &[&[0; 32]])
    );

    // pcrDigest is parameter 1.
    let policy = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_pcr(&mut sim, policy, &[0xEE; 32], &pcrs1),
        Err(TpmRc::VALUE.with(Position::parameter(1)).get())
    );
}

#[test]
fn tpm2_policypcr_reorders_banks_inverts_error_positions_and_corrupts_sha1_trial_digests() {
    let mut sim = create_simulator!();
    // The SHA-384 bank is not allocated by default: FilterPcr clears its selection, so both the
    // hashed selection and the PCR digest are those of an empty selection.
    let requested = [pcr_sel(TpmiAlgHash::Sha384, &[0x81, 0, 0])];
    let filtered = [pcr_sel(TpmiAlgHash::Sha384, &[0, 0, 0])];
    let expected = expected_policy_pcr(TpmiAlgHash::Sha256, &filtered, &[]);
    for session_type in [TpmSe::Trial, TpmSe::Policy] {
        let s = start(&mut sim, session_type, TpmiAlgHash::Sha256).session_handle;
        policy_pcr(&mut sim, s, &[], &requested).unwrap();
        assert_eq!(policy_digest(&mut sim, s), expected);
    }

    // Like C (TPML_PCR_SELECTION_Unmarshal / PCRComputeCurrentDigest), a repeated bank is not
    // an error: each selection is hashed in order.
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    let dup = [
        pcr_sel(TpmiAlgHash::Sha256, &[1, 0, 0]),
        pcr_sel(TpmiAlgHash::Sha256, &[2, 0, 0]),
    ];
    policy_pcr(&mut sim, s, &[], &dup).unwrap();
    assert_eq!(
        policy_digest(&mut sim, s),
        expected_policy_pcr(TpmiAlgHash::Sha256, &dup, &[&[0; 32], &[0; 32]])
    );
}

#[test]
fn tpm2_policypcr_reorders_banks_inverts_error_positions_and_corrupts_sha1_trial_digests_union() {
    // Part 4-5 of this finding (cpHash/nameHash template occupancy, PolicyOR RC_P1,
    // PolicyDuplicationSelect Names).
    let mut sim = create_simulator!();
    let s = start(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    policy_template(&mut sim, s, &[1; 32]).unwrap();
    assert_eq!(
        policy_cp_hash(&mut sim, s, &[1; 32]),
        Err(TpmRc::CPHASH.get())
    );
    let s = start(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    policy_duplication_select(&mut sim, s, &[0xAB], &[0xCD], true).unwrap();
}

// ---------------------------------------------------------------------------
// PolicySigned
// ---------------------------------------------------------------------------

#[test]
fn tpm2_policysigned_trial_session_bypasses_object_load_validation() {
    let mut sim = create_simulator!();
    let trial = start(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    let sig = TpmtSignature::Hmac(TpmtHa::new(TpmiAlgHash::Sha256, &[0; 32]).unwrap());
    assert_eq!(
        policy_signed(&mut sim, Handle(0x8000_0002), trial, sig),
        Err(TpmRc::REFERENCE_H0.get())
    );
    // Trial digest uses the loaded object's Name.
    let (key, name) = create_primary(&mut sim, ecc_signing_template(TpmiAlgHash::Sha256));
    let trial = start(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    policy_signed(&mut sim, key, trial, sig).unwrap();
    let d1 = sha(
        TpmiAlgHash::Sha256,
        &[&[0; 32], &TpmCc::PolicySigned.code().to_be_bytes(), &name],
    );
    assert_eq!(
        policy_digest(&mut sim, trial),
        sha(TpmiAlgHash::Sha256, &[&d1])
    );
}

#[test]
fn expects_object_handle_spurious_ecc_parameters_and_missing_policy_signed() {
    let mut sim = create_simulator!();
    let sig = TpmtSignature::Hmac(TpmtHa::new(TpmiAlgHash::Sha256, &[0; 32]).unwrap());
    // Trial session: unloaded transient and non-object handles are rejected.
    let trial = start(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_signed(&mut sim, Handle(0x8000_0002), trial, sig),
        Err(TpmRc::REFERENCE_H0.get())
    );
    assert_eq!(
        policy_signed(&mut sim, Handle::RH_OWNER, trial, sig),
        Err(TpmRc::VALUE.with(Position::handle(1)).get())
    );
    // Policy session: the handle is validated before PolicyParameterChecks (bad nonce).
    let policy = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    let err = run(
        &mut sim,
        PolicySigned {
            nonce_tpm: Tpm2bNonce::from_bytes(&[0xEE; 16]).unwrap(),
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: Tpm2bNonce::default(),
            expiration: 0,
            auth: sig,
        },
        PolicySignedHandles {
            auth_object: Handle(0x8000_0002),
            policy_session: policy,
        },
    )
    .map(|_| ())
    .unwrap_err();
    assert_eq!(err, TpmRc::REFERENCE_H0.get());
}

fn ecdsa_dummy_sig() -> TpmtSignature<'static> {
    TpmtSignature::Rsassa(tpm2::TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig: tpm2::Tpm2bPublicKeyRsa::from_bytes(&[0x5A; 32]).unwrap(),
    })
}

#[test]
fn tpm2_policysigned_ecschnorr_rejection_asymmetric_scheme_and_trial_handle_bugs() {
    let mut sim = create_simulator!();
    let (ecc_key, _) = create_primary(&mut sim, ecc_signing_template(TpmiAlgHash::Sha256));
    let policy = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    // An RSA signature on an ECC key is a scheme error (CryptEccValidateSignature).
    assert_eq!(
        policy_signed(&mut sim, ecc_key, policy, ecdsa_dummy_sig()),
        Err(TpmRc::SCHEME.with(Position::parameter(5)).get())
    );
    // Trial: unloaded authObject.
    let trial = start(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_signed(&mut sim, Handle(0x8000_0002), trial, ecdsa_dummy_sig()),
        Err(TpmRc::REFERENCE_H0.get())
    );
}

fn load_public_only_hmac_key(sim: &mut Simulator<'_>) -> Handle {
    let mut public = hmac_key_template(TpmiAlgHash::Sha256);
    public.object_attributes = TpmaObject::USER_WITH_AUTH | TpmaObject::SIGN_ENCRYPT;
    if let PublicParmsAndId::KeyedHash(_, ref mut unique) = public.parms_and_id {
        *unique = digest(&[0x42; 32]);
    }
    let (_, handles) = sim
        .execute_with_handles(
            LoadExternal {
                in_private: None,
                in_public: Tpm2b(public),
                hierarchy: Handle::RH_NULL,
            },
            (),
        )
        .expect("LoadExternal (public only)");
    handles.object_handle
}

/// HMAC over `aHash = SHA256(nonceTPM || expiration || cpHashA || policyRef)` with all fields
/// empty and expiration 0.
fn empty_policy_signed_hmac(key: &[u8]) -> TpmtSignature<'static> {
    let a_hash = sha(TpmiAlgHash::Sha256, &[&0i32.to_be_bytes()]);
    let mac = hmac(TpmiAlgHash::Sha256, key, &a_hash);
    TpmtSignature::Hmac(TpmtHa::new(TpmiAlgHash::Sha256, leak_bytes(&mac)).unwrap())
}

#[test]
fn tpm2_policysigned_keyedhash_public_only_and_scheme_mismatch_bugs() {
    let mut sim = create_simulator!();
    // 1. A public-only KEYEDHASH key cannot verify (forgeable with an empty HMAC key).
    let key = load_public_only_hmac_key(&mut sim);
    let policy = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_signed(&mut sim, key, policy, empty_policy_signed_hmac(&[])),
        Err(TpmRc::HANDLE.with(Position::parameter(5)).get())
    );

    // 2. Key scheme HMAC(SHA-256) vs. signature HMAC(SHA-1): TPM_RC_SIGNATURE + RC_P5.
    // Without SENSITIVE_DATA_ORIGIN the provided data is the HMAC key.
    let mut template = hmac_key_template(TpmiAlgHash::Sha256);
    template
        .object_attributes
        .remove(TpmaObject::SENSITIVE_DATA_ORIGIN);
    let (hmac_key, _) = create_primary_with_data(&mut sim, template, &[7; 32]);
    let policy = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    let sig = TpmtSignature::Hmac(TpmtHa::new(TpmiAlgHash::Sha1, &[0; 20]).unwrap());
    assert_eq!(
        policy_signed(&mut sim, hmac_key, policy, sig),
        Err(TpmRc::SIGNATURE.with(Position::parameter(5)).get())
    );
    // A correct HMAC with the loaded key still verifies.
    policy_signed(
        &mut sim,
        hmac_key,
        policy,
        empty_policy_signed_hmac(&[7; 32]),
    )
    .unwrap();
}

#[test]
fn policy_signed_and_load_external_public_only_keyedhash_and_platform_hierarchy_bugs() {
    // Parts 1-3 (part 4, LoadExternal phEnable, is handed over to fix-objects).
    let mut sim = create_simulator!();
    let key = load_public_only_hmac_key(&mut sim);
    let policy = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_signed(&mut sim, key, policy, empty_policy_signed_hmac(&[])),
        Err(TpmRc::HANDLE.with(Position::parameter(5)).get())
    );
    let (ecc_key, _) = create_primary(&mut sim, ecc_signing_template(TpmiAlgHash::Sha256));
    assert_eq!(
        policy_signed(&mut sim, ecc_key, policy, ecdsa_dummy_sig()),
        Err(TpmRc::SCHEME.with(Position::parameter(5)).get())
    );
    let trial = start(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_signed(&mut sim, Handle(0x8000_0002), trial, ecdsa_dummy_sig()),
        Err(TpmRc::REFERENCE_H0.get())
    );
}

// ---------------------------------------------------------------------------
// PolicyNV / PolicyAuthorizeNV
// ---------------------------------------------------------------------------

#[test]
fn tpm2_policynv_and_tpm2_policyauthorizenv_nvreadaccesschecks_and_error_bugs() {
    let mut sim = create_simulator!();
    let readable = 0x0150_0020;
    define_nv(&mut sim, readable, nv_attrs(TpmaNv::OWNERREAD), 32);
    write_nv_owner(&mut sim, readable, &[0x11; 32]);

    // operandB is not limited to the session's digest size (SHA-1 = 20 bytes).
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha1).session_handle;
    policy_nv(&mut sim, Handle::RH_OWNER, readable, s, &[0x11; 24], 0)
        .expect("24-byte operandB with a SHA-1 session");

    // offset > dataSize: TPM_RCS_VALUE + RC_PolicyNV_offset (parameter 2).
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_nv(&mut sim, Handle::RH_OWNER, readable, s, &[0x11; 1], 33),
        Err(TpmRc::VALUE.with(Position::parameter(2)).get())
    );
    // dataSize - offset < operandB size: TPM_RCS_SIZE + RC_PolicyNV_operandB.
    assert_eq!(
        policy_nv(&mut sim, Handle::RH_OWNER, readable, s, &[0x11; 4], 30),
        Err(TpmRc::SIZE.with(Position::parameter(1)).get())
    );

    // authHandle = TPM_RH_OWNER without TPMA_NV_OWNERREAD: TPM_RC_NV_AUTHORIZATION.
    let no_owner_read = 0x0150_0021;
    define_nv(&mut sim, no_owner_read, nv_attrs(TpmaNv::empty()), 32);
    write_nv_owner(&mut sim, no_owner_read, &[0x11; 32]);
    assert_eq!(
        policy_nv(&mut sim, Handle::RH_OWNER, no_owner_read, s, &[0x11; 4], 0),
        Err(TpmRc::NV_AUTHORIZATION.get())
    );

    // Trial session: an undefined nvIndex is rejected against handle 2.
    let t = start(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_nv(&mut sim, Handle::RH_OWNER, 0x0150_0099, t, &[0x11; 4], 0),
        Err(TpmRc::HANDLE.with(Position::handle(2)).get())
    );

    // PolicyAuthorizeNV: a SHA-1 TPMT_HA in the index with a SHA-256 session is TPM_RC_HASH.
    let policy_index = 0x0150_0022;
    define_nv(&mut sim, policy_index, nv_attrs(TpmaNv::OWNERREAD), 22);
    let mut tpmt_ha = vec![0x00, 0x04];
    tpmt_ha.extend_from_slice(&[0; 20]);
    write_nv_owner(&mut sim, policy_index, &tpmt_ha);
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_authorize_nv(&mut sim, Handle::RH_OWNER, policy_index, s),
        Err(TpmRc::HASH.get())
    );

    // PolicyAuthorizeNV accepts a POLICYREAD index authorized by a policy session.
    let policy_read = 0x0150_0028;
    define_policy_read_authorize_index(&mut sim, policy_read);
    let target = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    policy_authorize_nv_with_policy_auth(&mut sim, policy_read, target).unwrap();
}

#[test]
fn tpm2_policyauthorizenv_tpmatha_unmarshal_and_error_position_bugs() {
    let mut sim = create_simulator!();
    // A complete SHA-256 TPMT_HA with a SHA-384 session: TPM_RC_HASH, not TPM_RC_INSUFFICIENT.
    let index = 0x0150_0023;
    define_nv(&mut sim, index, nv_attrs(TpmaNv::OWNERREAD), 34);
    let mut tpmt_ha = vec![0x00, 0x0B];
    tpmt_ha.extend_from_slice(&[0; 32]);
    write_nv_owner(&mut sim, index, &tpmt_ha);
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha384).session_handle;
    assert_eq!(
        policy_authorize_nv(&mut sim, Handle::RH_OWNER, index, s),
        Err(TpmRc::HASH.get())
    );

    // A truncated SHA-256 TPMT_HA with a SHA-1 session: TPM_RC_INSUFFICIENT, not TPM_RC_HASH.
    let short = 0x0150_0024;
    define_nv(&mut sim, short, nv_attrs(TpmaNv::OWNERREAD), 24);
    let mut truncated = vec![0x00, 0x0B];
    truncated.extend_from_slice(&[0; 22]);
    write_nv_owner(&mut sim, short, &truncated);
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha1).session_handle;
    assert_eq!(
        policy_authorize_nv(&mut sim, Handle::RH_OWNER, short, s),
        Err(TpmRc::INSUFFICIENT.get())
    );

    // authHandle is a different NV Index: TPM_RC_NV_AUTHORIZATION.
    let other = 0x0150_0025;
    define_nv(&mut sim, other, nv_attrs(TpmaNv::empty()), 8);
    write_nv_owner(&mut sim, other, &[0; 8]);
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_authorize_nv(&mut sim, Handle(other), index, s),
        Err(TpmRc::NV_AUTHORIZATION.get())
    );

    // Undefined nvIndex: TPM_RC_HANDLE + RC_H2.
    let s = start(&mut sim, TpmSe::Trial, TpmiAlgHash::Sha256).session_handle;
    assert_eq!(
        policy_authorize_nv(&mut sim, Handle::RH_OWNER, 0x0150_0098, s),
        Err(TpmRc::HANDLE.with(Position::handle(2)).get())
    );
}

/// Authorizes `TPM2_PolicyAuthorizeNV` for `index` (authHandle == nvIndex) with a fresh policy
/// session whose (zero) policy digest equals the index's authPolicy.
fn policy_authorize_nv_with_policy_auth(
    sim: &mut Simulator<'_>,
    index: u32,
    target: Handle,
) -> Result<(), u32> {
    let mut auth = start_keep(sim, TpmSe::Policy, TpmiAlgHash::Sha256, &[target]);
    auth.attributes.insert(tpm2::TpmaSession::CONTINUE_SESSION);
    execute_with_hmac_sessions(
        sim,
        &PolicyAuthorizeNV {},
        PolicyAuthorizeNVHandles {
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

/// A POLICYREAD-only index (no AUTHREAD) whose authHandle is the index itself, authorized by a
/// policy session, stores a SHA-256 TPMT_HA of the zero policy digest.
fn define_policy_read_authorize_index(sim: &mut Simulator<'_>, index: u32) {
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

#[test]
fn policy_authorize_nv_manual_password_check_omits_session_position_and_bad_auth() {
    // The handler no longer re-verifies authorization (the engine does, with properly positioned
    // errors), so an index authorized by a policy session is no longer rejected for lacking
    // TPMA_NV_AUTHREAD.
    let mut sim = create_simulator!();
    let index = 0x0150_0026;
    define_policy_read_authorize_index(&mut sim, index);
    let target = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    policy_authorize_nv_with_policy_auth(&mut sim, index, target).unwrap();

    // A wrong owner password is rejected with a session-positioned error.
    let s = start(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    let owner_index = 0x0150_0027;
    define_nv(&mut sim, owner_index, nv_attrs(TpmaNv::OWNERREAD), 34);
    let err = execute_with_password_sessions(
        &mut sim,
        &PolicyAuthorizeNV {},
        PolicyAuthorizeNVHandles {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(owner_index),
            policy_session: s,
        },
        1,
        b"wrong",
    )
    .map(|_| ())
    .unwrap_err();
    // The owner is DA-exempt (C IsDAExempted), so the failure is TPM_RC_BAD_AUTH + RC_S1.
    assert_eq!(err, TpmRc::BAD_AUTH.with(Position::session(1)).get());
}

// ---------------------------------------------------------------------------
// StartAuthSession
// ---------------------------------------------------------------------------

fn start_salted(
    sim: &mut Simulator<'_>,
    tpm_key: Handle,
    bind: Handle,
    salt: &[u8],
) -> Result<(), u32> {
    run(
        sim,
        StartAuthSession {
            nonce_caller: Tpm2bNonce::from_bytes(&[1; 16]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::from_bytes(leak_bytes(salt)).unwrap(),
            session_type: TpmSe::HMAC,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        },
        StartAuthSessionHandles { tpm_key, bind },
    )
    .map(|_| ())
}

#[test]
fn tpm2_startauthsession_accepts_symcipher_tpmkey_and_omits_bind_validation() {
    let mut sim = create_simulator!();

    // 1. A symmetric key cannot be tpmKey (TPM_RCS_KEY + RC_StartAuthSession_tpmKey).
    let sym_template = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)),
            Tpm2bDigest::default(),
        ),
    };
    let (sym_key, _) = create_primary(&mut sim, sym_template);
    assert_eq!(
        start_salted(&mut sim, sym_key, Handle::RH_NULL, &[0x33; 16]),
        Err(TpmRc::KEY.with(Position::handle(1)).get())
    );

    // 2. Empty salt is checked before the DECRYPT attribute.
    let (sign_key, _) = create_primary(&mut sim, ecc_signing_template(TpmiAlgHash::Sha256));
    assert_eq!(
        start_salted(&mut sim, sign_key, Handle::RH_NULL, &[]),
        Err(TpmRc::VALUE.with(Position::parameter(2)).get())
    );

    // 4. PIN indices cannot be bind entities (TPM_RCS_HANDLE + RC_StartAuthSession_bind).
    let pin = 0x0150_0030;
    define_pin_pass(&mut sim, pin);
    assert_eq!(
        start_salted(&mut sim, Handle::RH_NULL, Handle(pin), &[]),
        Err(TpmRc::HANDLE.with(Position::handle(2)).get())
    );
    let mut fail_attrs = TpmaNv::OWNERWRITE | TpmaNv::AUTHREAD | TpmaNv::NO_DA;
    fail_attrs.set_type(TpmNt::PinFail);
    let pin_fail = 0x0150_0031;
    define_nv(&mut sim, pin_fail, fail_attrs, 8);
    assert_eq!(
        start_salted(&mut sim, Handle::RH_NULL, Handle(pin_fail), &[]),
        Err(TpmRc::HANDLE.with(Position::handle(2)).get())
    );

    // 4. Public-only objects cannot be bind entities.
    let public_only = load_public_only_hmac_key(&mut sim);
    assert_eq!(
        start_salted(&mut sim, Handle::RH_NULL, public_only, &[]),
        Err(TpmRc::HANDLE.with(Position::handle(2)).get())
    );

    // 3. Binding to a PCR in an auth group uses its authValue in the session key: an HMAC
    //    session bound to PCR 20 (authValue "abc") authorizes the owner with
    //    HMAC key = KDFa(authValue(PCR20)) || ownerAuth.
    run_pw(
        &mut sim,
        PCRSetAuthValue {
            auth: digest(b"abc"),
        },
        PCRSetAuthValueHandles {
            pcr_handle: Handle(20),
        },
    )
    .expect("PCR_SetAuthValue");
    let mut session = start_bound(&mut sim, Handle(20), b"abc", TpmSe::HMAC);
    session
        .attributes
        .insert(tpm2::TpmaSession::CONTINUE_SESSION);
    execute_with_hmac_sessions(
        &mut sim,
        &HierarchyChangeAuth {
            new_auth: Tpm2bAuth::default(),
        },
        HierarchyChangeAuthHandles {
            auth_handle: Handle::RH_OWNER,
        },
        &[],
        &mut [session],
        &[&[]],
    )
    .expect("session bound to PCR 20 must derive its key from the PCR authValue");
}

#[test]
fn session_bind_sha512_panic_handle_equality_and_policypassword_response_hmac() {
    // Part 1 (StartAuthSession side): binding to an entity with a 66-byte SHA-512 Name must not
    // panic. Parts 2-3 are engine-side (fix-auth / fix-sessions).
    let mut sim = create_simulator!();
    let (key, name) = create_primary(&mut sim, ecc_signing_template(TpmiAlgHash::Sha512));
    assert_eq!(name.len(), 66);
    let mut session = start_bound(&mut sim, key, &[], TpmSe::HMAC);
    session
        .attributes
        .insert(tpm2::TpmaSession::CONTINUE_SESSION);
    // The session works for an unrelated (unbound) entity.
    execute_with_hmac_sessions(
        &mut sim,
        &HierarchyChangeAuth {
            new_auth: Tpm2bAuth::default(),
        },
        HierarchyChangeAuthHandles {
            auth_handle: Handle::RH_OWNER,
        },
        &[],
        &mut [session],
        &[&[]],
    )
    .unwrap();
}

#[test]
fn verify_session_hmacs_bound_entity_handle_equality_and_sha512_name_panic() {
    // StartAuthSession side of the SHA-512 bind panic (the engine side is fix-auth's).
    let mut sim = create_simulator!();
    let (key, _) = create_primary(&mut sim, ecc_signing_template(TpmiAlgHash::Sha512));
    start_salted(&mut sim, Handle::RH_NULL, key, &[]).expect("bind to a SHA-512 object");
}
