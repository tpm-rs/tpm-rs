//! Tests of the persistence of the complete TPM state (`tpm2_engine::persistence`): the
//! conversion between `GlobalState` + `NvStorage` and the `PersistedTpmState`
//! (ported from `tpm_rs_serializer_core`), its losslessness (a round trip reproduces the same
//! persisted state and the same canonical NV storage), the reload of the NV-synced fields from
//! the NV records of the persisted NV image and the RAM values that are ahead of NV
//! (`clearCount`, a deferred DA update), the platform time relative to the timer reading, the
//! validation of a corrupted persisted state, and a live migration between two engines that
//! continue with the same results, also across a TPM Reset of the target and a change of the
//! platform timer, and the `serde` serialization of the persisted state.
#![cfg(feature = "persistence")]
#![allow(clippy::field_reassign_with_default)]

mod common;

use common::{
    FakeRng, FakeStorage, FakeTimer, RealCryptoEngine, TestCryptoProvider, execute_command,
    password_auth, setup_real_crypto_tpm,
};
use tpm2::commands::{
    CreatePrimary, EvictControl, HashSequenceStart, HierarchyChangeAuth, NVDefineSpace, NVRead,
    NVWrite, ObjectChangeAuth, PCRExtend, PCRRead, PolicyAuthValue, PolicyGetDigest, ReadClock,
    ReadPublic, SequenceComplete, SequenceUpdate, Shutdown, StartAuthSession, Startup,
};
use tpm2::{
    Handle, Marshal, PublicParmsAndId, Tpm2b, Tpm2bAuth, Tpm2bDigest, Tpm2bMaxBuffer,
    Tpm2bMaxNvBuffer, Tpm2bName, Tpm2bNonce, Tpm2bNvPublic, TpmEccCurve, TpmSe, TpmSu, TpmaNv,
    TpmaObject, TpmiAlgHash, TpmlDigestValues, TpmlPcrSelection, TpmsEccParms, TpmsNvPublic,
    TpmsPcrSelection, TpmtHa, TpmtPublic, TpmtSymDefObject,
};
use tpm2_engine::handler::SessionState;
use tpm2_engine::persistence::{
    self, Array, DeserializeError, PersistedSequenceType, PersistedTpmState,
};
use tpm2_engine::storage::Tpm2Storage;
use tpm2_engine::storage::manager::StorageManager;
use tpm2_engine::storage::nv::{
    HIERARCHY_RECORD_HANDLE, HIERARCHY_RECORD_SIZE, NvHeader, NvHierarchyRecord,
};
use tpm2_engine::storage::ram_storage_mock::RamStorageMock;
use tpm2_engine::{ActiveSequence, GlobalState, SequenceType};

/// The size of the NV backing store of the simulator (twice the accounted NV memory).
const NV_STORAGE_SIZE: usize = 2 * tpm2_engine::storage::nv_capacity::NV_MEMORY_SIZE as usize;

/// A new, zeroed persisted state on the heap (it is too large for a test thread's stack).
fn new_persisted() -> Box<PersistedTpmState> {
    Box::default()
}

/// The persisted state of `state` and `storage`, with the platform timer at `now_ms`.
fn persisted_of<S: tpm2_engine::storage::NvStorage>(
    state: &GlobalState,
    storage: &S,
    now_ms: u64,
) -> Box<PersistedTpmState> {
    let mut persisted = new_persisted();
    persistence::try_serialize(state, storage, now_ms, &mut persisted).expect("serialize");
    persisted
}

/// Restores `persisted` into `state` and `storage`, with the platform timer at `now_ms`.
fn restore_into<S: tpm2_engine::storage::NvStorage>(
    persisted: &PersistedTpmState,
    state: &mut GlobalState,
    storage: &mut S,
    now_ms: u64,
) -> Result<(), DeserializeError> {
    persistence::try_deserialize(persisted, state, storage, now_ms, &TestCryptoProvider)
}

/// The payload of the NV item `handle` of `persisted`.
fn nv_payload(persisted: &PersistedTpmState, handle: u32) -> &[u8] {
    let range = persisted.nv.item_range(handle).expect("NV item");
    &persisted.nv.data.as_slice()[range]
}

/// Builds two engines over their own platform components: `$a` is manufactured and started
/// (`TPM2_Startup(TPM_SU_CLEAR)`), `$b` is a new, unmanufactured engine (the target of a live
/// migration).
macro_rules! two_engines {
    ($a:ident, $b:ident) => {
        let mut crypto_a = TestCryptoProvider;
        let mut storage_a = FakeStorage::default();
        let mut timer_a = FakeTimer;
        let mut rng_a = FakeRng::new();
        let mut $a = setup_real_crypto_tpm(&mut crypto_a, &mut storage_a, &mut timer_a, &mut rng_a);
        let mut crypto_b = TestCryptoProvider;
        let mut storage_b = FakeStorage::default();
        let mut timer_b = FakeTimer;
        let mut rng_b = FakeRng::new();
        #[allow(unused_mut)]
        let mut $b = tpm2_engine::TpmEngine::new(tpm2_engine::TpmPlatform::new(
            &mut crypto_b,
            &mut storage_b,
            &mut timer_b,
            &mut rng_b,
        ))
        .unwrap();
    };
}

/// A fixedTPM NIST P-256 storage primary key (SHA-256, AES-128-CFB) under the owner hierarchy.
fn create_storage_primary(tpm: &mut RealCryptoEngine<'_>, owner_auth: &'static [u8]) -> Handle {
    let create = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
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
                    symmetric: Some(TpmtSymDefObject::aes_cfb(128).unwrap()),
                    scheme: None,
                    curve_id: TpmEccCurve::NistP256,
                    kdf: None,
                },
                tpm2::TpmsEccPoint::default(),
            ),
        }),
        ..Default::default()
    };
    execute_command(tpm, &create, &[password_auth(owner_auth)])
        .expect("CreatePrimary")
        .object_handle
}

/// The Name of the object `handle` (`TPM2_ReadPublic`).
fn name_of(tpm: &mut RealCryptoEngine<'_>, handle: Handle) -> Vec<u8> {
    let rsp = execute_command(
        tpm,
        &ReadPublic {
            object_handle: handle,
        },
        &[],
    )
    .expect("ReadPublic");
    rsp.name.as_slice().to_vec()
}

/// The SHA-256 bank selection of `pcr`.
fn sha256_pcr_selection(pcr: usize) -> TpmlPcrSelection {
    let mut select = [0u8; 3];
    select[pcr / 8] |= 1 << (pcr % 8);
    let mut list = TpmlPcrSelection::default();
    list.add(&TpmsPcrSelection::new(TpmiAlgHash::Sha256, &select).unwrap())
        .unwrap();
    list
}

/// The SHA-256 value of `pcr` (`TPM2_PCR_Read`) and the PCR update counter.
fn read_pcr(tpm: &mut RealCryptoEngine<'_>, pcr: usize) -> (Vec<u8>, u32) {
    let rsp = execute_command(
        tpm,
        &PCRRead {
            pcr_selection_in: sha256_pcr_selection(pcr),
        },
        &[],
    )
    .expect("PCR_Read");
    let value = rsp.pcr_values.as_ref()[0].as_slice().to_vec();
    (value, rsp.pcr_update_counter)
}

const NV_INDEX: Handle = Handle(0x0150_0001);
const PERSISTENT_HANDLE: Handle = Handle(0x8100_0001);

/// Drives `tpm` into a state that exercises most of the persisted state: a new owner
/// authValue, a primary key (also made persistent), an extended PCR, a written NV index, a hash
/// sequence with data and a policy session. Returns the primary key, the sequence and the
/// session.
fn populate(tpm: &mut RealCryptoEngine<'_>) -> (Handle, Handle, Handle) {
    execute_command(
        tpm,
        &HierarchyChangeAuth {
            auth_handle: Handle::RH_OWNER,
            new_auth: Tpm2bAuth::from_bytes(b"owner-pw").unwrap(),
        },
        &[password_auth(b"")],
    )
    .expect("HierarchyChangeAuth");

    let primary = create_storage_primary(tpm, b"owner-pw");
    execute_command(
        tpm,
        &EvictControl {
            auth: Handle::RH_OWNER,
            object_handle: primary,
            persistent_handle: PERSISTENT_HANDLE,
        },
        &[password_auth(b"owner-pw")],
    )
    .expect("EvictControl");

    let mut digests = TpmlDigestValues::default();
    digests.add(&TpmtHa::Sha256(&[0xAA; 32])).unwrap();
    execute_command(
        tpm,
        &PCRExtend {
            pcr_handle: Handle(16),
            digests,
        },
        &[password_auth(b"")],
    )
    .expect("PCR_Extend");

    execute_command(
        tpm,
        &NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: Tpm2b(TpmsNvPublic {
                nv_index: NV_INDEX,
                name_alg: TpmiAlgHash::Sha256,
                attributes: TpmaNv::OWNERREAD | TpmaNv::OWNERWRITE,
                auth_policy: Tpm2bDigest::default(),
                data_size: 16,
            }),
        },
        &[password_auth(b"owner-pw")],
    )
    .expect("NV_DefineSpace");
    execute_command(
        tpm,
        &NVWrite {
            auth_handle: Handle::RH_OWNER,
            nv_index: NV_INDEX,
            data: Tpm2bMaxNvBuffer::from_bytes(&[0x42; 16]).unwrap(),
            offset: 0,
        },
        &[password_auth(b"owner-pw")],
    )
    .expect("NV_Write");

    let sequence = execute_command(
        tpm,
        &HashSequenceStart {
            auth: Tpm2bAuth::from_bytes(b"seq").unwrap(),
            hash_alg: Some(TpmiAlgHash::Sha256),
        },
        &[],
    )
    .expect("HashSequenceStart")
    .sequence_handle;
    execute_command(
        tpm,
        &SequenceUpdate {
            sequence_handle: sequence,
            buffer: Tpm2bMaxBuffer::from_bytes(b"hello, ").unwrap(),
        },
        &[password_auth(b"seq")],
    )
    .expect("SequenceUpdate");

    let session = execute_command(
        tpm,
        &StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::from_bytes(&[0x11; 32]).unwrap(),
            encrypted_salt: Default::default(),
            session_type: TpmSe::Policy,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        },
        &[],
    )
    .expect("StartAuthSession")
    .session_handle;
    execute_command(
        tpm,
        &PolicyAuthValue {
            policy_session: session,
        },
        &[],
    )
    .expect("PolicyAuthValue");

    (primary, sequence, session)
}

/// Runs the same deterministic commands on a TPM after `populate` and returns their results:
/// the Names of the primary key and the persistent key, the NV data, PCR 16 and the update
/// counter, the policy digest and the digest that completes the hash sequence.
fn continue_after_populate(
    tpm: &mut RealCryptoEngine<'_>,
    (primary, sequence, session): (Handle, Handle, Handle),
) -> Vec<Vec<u8>> {
    let primary_name = name_of(tpm, primary);
    let persistent_name = name_of(tpm, PERSISTENT_HANDLE);
    let nv = execute_command(
        tpm,
        &NVRead {
            auth_handle: Handle::RH_OWNER,
            nv_index: NV_INDEX,
            size: 16,
            offset: 0,
        },
        &[password_auth(b"owner-pw")],
    )
    .expect("NV_Read")
    .data
    .as_slice()
    .to_vec();
    let (pcr, counter) = read_pcr(tpm, 16);
    let policy = execute_command(
        tpm,
        &PolicyGetDigest {
            policy_session: session,
        },
        &[],
    )
    .expect("PolicyGetDigest")
    .policy_digest
    .as_slice()
    .to_vec();
    let digest = execute_command(
        tpm,
        &SequenceComplete {
            sequence_handle: sequence,
            buffer: Tpm2bMaxBuffer::from_bytes(b"world").unwrap(),
            hierarchy: Handle::RH_OWNER,
        },
        &[password_auth(b"seq")],
    )
    .expect("SequenceComplete")
    .result
    .as_slice()
    .to_vec();
    vec![
        primary_name,
        persistent_name,
        nv,
        pcr,
        counter.to_be_bytes().to_vec(),
        policy,
        digest,
    ]
}

/// `Array::from_slice` copies up to its capacity and truncates longer input;
/// `try_from_slice` rejects it.
#[test]
fn array_from_slice_and_truncation() {
    let empty: Array<u8, 16> = Array::new();
    assert_eq!(empty.len, 0);
    assert!(empty.as_slice().is_empty());

    let exact: Array<u8, 4> = Array::from_slice(&[1, 2, 3, 4]);
    assert_eq!(exact.len, 4);
    assert_eq!(exact.as_slice(), &[1, 2, 3, 4]);

    let truncated: Array<u8, 4> = Array::from_slice(&[10, 20, 30, 40, 50, 60]);
    assert_eq!(truncated.len, 4);
    assert_eq!(truncated.as_slice(), &[10, 20, 30, 40]);

    assert!(Array::<u8, 4>::try_from_slice(&[0; 5]).is_none());
}

/// Arrays compare equal by their active elements only, and an out-of-range length is clamped
/// by the accessors.
#[test]
fn array_equality_ignores_inactive_elements() {
    let mut a: Array<u8, 4> = Array::from_slice(&[1, 2]);
    let b: Array<u8, 4> = Array::from_slice(&[1, 2]);
    a.data[3] = 0xFF;
    assert_eq!(a, b);
    a.len = 9;
    assert_eq!(a.as_slice().len(), 4);
}

/// The NV item of an NV Index: `TPM2B_AUTH || TPM2B_NV_PUBLIC || data`.
fn nv_index_item(public: TpmsNvPublic<'_>, data: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; Tpm2bAuth::MAX_SIZE + Tpm2bNvPublic::MAX_SIZE];
    let mut len =
        Tpm2bAuth::default().marshal((&mut buf[..Tpm2bAuth::MAX_SIZE]).try_into().unwrap());
    len += Tpm2b(public).marshal(
        (&mut buf[len..len + Tpm2bNvPublic::MAX_SIZE])
            .try_into()
            .unwrap(),
    );
    buf.truncate(len);
    buf.extend_from_slice(data);
    buf
}

/// A hand-built `GlobalState` with sessions, a sequence and an NV index survives
/// `GlobalState` -> `PersistedTpmState` -> `GlobalState` -> `PersistedTpmState` unchanged,
/// and restoring both persisted states produces the same NV storage, which is the canonical
/// storage of the original (items in handle order, their metadata derived). The NV-synced
/// fields come from the NV image (here the reset count of the header) unless their RAM value is
/// persisted, the derived and per-command fields get their values between two commands, the
/// loaded entities get the slots of their handle order, and the platform time is rebased on the
/// timer reading of the restore.
#[test]
fn global_state_to_persisted_and_back_round_trip() {
    let mut state = Box::<GlobalState>::default();
    state.initialized = true;
    state.reset_count = 77;
    state.restart_count = 5;
    state.clear_count = 3;
    state.orderly_state = 0xFFFF;
    state.failed_tries = 2;
    state.da_pending_on_nv = true;
    state.locality = 3;
    state.g_nv_ok = true;
    state.prev_orderly_state = 0x0000;
    state.update_nv = 1;
    state.clear_orderly = true;
    state.drtm_handle = 0x8000_0001;
    state.startup_locality_3 = true;
    state.pcr_reconfig = true;
    state.read_only = true;
    state.exclusive_audit_session = Some(0x0200_0000);

    state.drbg_state.reseed_counter = 99;
    state.drbg_state.magic = 0x4742_5244;
    state.drbg_state.seed = [0x42; 48];
    state.drbg_state.last_value = [10, 20, 30, 40];

    state.platform_auth = Tpm2bAuth::from_bytes(&[0x11, 0x22, 0x33]).unwrap().into();
    state.platform_unique_details = Tpm2bAuth::from_bytes(&[0x88; 16]).unwrap().into();
    state.platform_alg = Some(TpmiAlgHash::Sha256);
    state.null_proof = [0x22; 64];
    state.null_proof_size = 48;

    state.da_used = true;
    state.lockout_auth_enabled = false;
    state.self_heal_timer = 15000;
    state.lockout_timer = -30000;
    state.tpm_time_ms = 555_666_777;
    state.clock_offset = -12;
    state.last_timer_read_ms = Some(1234);
    state.clock_adjust_remainder = 6;

    state.pcrs.sha1[0] = [0x01; 20];
    state.pcrs.sha256[5] = [0x02; 32];
    state.pcrs.sha384[23] = [0x03; 48];
    state.pcrs.update_counter = 27;

    state.commit_counter = 0x1_0009;
    state.commit_array[1] = 0x80;
    state.act.tick_last_read_ms = 1000;
    state.act.tick_phase_ms = 300;
    state.physical_presence = true;

    let mut session = SessionState {
        session_handle: 0x0300_0001,
        session_type: TpmSe::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: Tpm2bNonce::from_bytes(&[0x44; 32]).unwrap().into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bound_entity: Tpm2bName::from_bytes(&[0x77; 34]).unwrap().into(),
        audit_digest: Some([0x88; 64]),
        audit_digest_len: 32,
        policy_hash: [0; 64],
        policy_hash_len: 32,
        is_cp_hash_defined: true,
        is_template_hash_defined: true,
        is_parameters_hash_defined: false,
        is_pp_required: true,
        policy_digest: [0; 64],
        policy_digest_len: 32,
        command_code: 0x0000_0176,
        start_time: 100,
        timeout: 200,
        epoch: 300,
        is_auth_value_needed: true,
        is_password_needed: false,
        pcr_counter: Some(15),
        check_nv_written: true,
        nv_written_state: false,
        command_locality: 3,
        include_auth: false,
        is_da_bound: true,
        is_lockout_bound: false,
        sec_channel: Default::default(),
    };
    session.session_key[..32].fill(0x66);
    session.policy_hash[..32].fill(0x7A);
    session.policy_digest[..32].fill(0x99);
    // The session is in the second slot: restore puts it in the first one.
    state.active_sessions[1] = Some(session);
    state.context_counter = 0x2000;
    state.saved_sessions[2] = Some(0x0200_0002);
    state.saved_session_sequences[2] = 0x1234;

    let mut seq = ActiveSequence::new(
        0x8000_0002,
        Tpm2bAuth::from_bytes(&[0xAB; 8]).unwrap(),
        SequenceType::Hash {
            alg: TpmiAlgHash::Sha256,
        },
    );
    seq.update_hash_states(b"partial data");
    seq.first_block = true;
    seq.ticket_safe = true;
    state.active_sequences[2] = Some(seq);

    // The canonical NV storage: the items in handle order, the hierarchy record with its fixed
    // size, and the NV Index with the attributes of its public area.
    let attributes = TpmaNv::OWNERREAD | TpmaNv::OWNERWRITE | TpmaNv::PLATFORMCREATE;
    let index = nv_index_item(
        TpmsNvPublic {
            nv_index: Handle(0x0150_0001),
            name_alg: TpmiAlgHash::Sha256,
            attributes,
            auth_policy: Tpm2bDigest::default(),
            data_size: 16,
        },
        &[0x42; 16],
    );
    let mut hierarchy = [0u8; HIERARCHY_RECORD_SIZE];
    let hierarchy_len = NvHierarchyRecord::default().encode(&mut hierarchy);
    let mut storage = Box::new(RamStorageMock::<NV_STORAGE_SIZE>::new());
    {
        let mut mgr = StorageManager::new(&mut *storage);
        mgr.define_space(HIERARCHY_RECORD_HANDLE, HIERARCHY_RECORD_SIZE as u16, 0)
            .unwrap();
        mgr.write_item(HIERARCHY_RECORD_HANDLE, 0, &hierarchy[..hierarchy_len])
            .unwrap();
        mgr.define_space(0x0150_0001, index.len() as u16, attributes.0)
            .unwrap();
        mgr.write_item(0x0150_0001, 0, &index).unwrap();
    }
    storage.as_mut_slice()[0..4].copy_from_slice(&77u32.to_be_bytes());

    let persisted = persisted_of(&state, &*storage, 2000);
    assert_eq!(
        persisted.nv.handles.as_slice(),
        &[HIERARCHY_RECORD_HANDLE, 0x0150_0001]
    );
    assert_eq!(nv_payload(&persisted, 0x0150_0001), &index[..]);
    assert_eq!(
        nv_payload(&persisted, HIERARCHY_RECORD_HANDLE),
        &hierarchy[..hierarchy_len]
    );
    assert_eq!(NvHeader::decode(&persisted.nv.header).reset_count, 77);
    assert_eq!(persisted.reset.null_proof.as_slice(), &[0x22; 48]);
    assert_eq!(persisted.reset.clear_count, 3);
    assert_eq!(persisted.reset.commit.counter, 0x1_0009);
    assert_eq!(persisted.clear.platform_alg, Some(0x000B));
    assert_eq!(persisted.runtime.drtm_handle, Some(0x8000_0001));
    assert_eq!(
        (
            persisted.runtime.orderly_state,
            persisted.runtime.failed_tries,
            persisted.runtime.da_pending_on_nv
        ),
        (0xFFFF, 2, true)
    );
    // The platform time not yet in *Time*: 2000 - 1234 ms since the last read plus the
    // remainder; 300 + 2000 - 1000 ms since the last ACT tick.
    assert_eq!(persisted.time.pending_platform_ms, 766 + 6);
    assert_eq!(persisted.act.tick_phase_ms, 1300);
    assert_eq!(persisted.reset.saved_sessions.as_slice()[0].slot, 2);
    assert_eq!(
        persisted.reset.saved_sessions.as_slice()[0].sequence,
        0x1234
    );
    assert!(matches!(
        persisted.loaded.sequences.as_slice()[0].sequence_type,
        PersistedSequenceType::Hash { .. }
    ));

    // Restore on another platform timer, which reads 50.
    let mut restored_storage = Box::new(RamStorageMock::<NV_STORAGE_SIZE>::new());
    let mut restored_state = Box::<GlobalState>::default();
    restore_into(&persisted, &mut restored_state, &mut *restored_storage, 50)
        .expect("Conversion to GlobalState must succeed");
    assert!(restored_state.active_sessions[0].is_some());
    assert!(restored_state.active_sequences[0].is_some());
    assert_eq!(restored_state.saved_sessions[2], Some(0x0200_0002));
    assert_eq!(restored_state.saved_session_sequences[2], 0x1234);
    assert_eq!(restored_state.reset_count, 77);
    assert_eq!(restored_state.clear_count, 3);
    assert_eq!(restored_state.failed_tries, 2);
    assert!(restored_state.da_pending_on_nv);
    assert_eq!(restored_state.locality, 3);
    assert!(!restored_state.lockout_auth_enabled);
    assert_eq!(restored_state.update_nv, GlobalState::default().update_nv);
    assert!(!restored_state.clear_orderly);
    assert_eq!(restored_state.last_timer_read_ms, Some(50));
    assert_eq!(restored_state.clock_adjust_remainder, 772);
    assert_eq!(
        (
            restored_state.act.tick_last_read_ms,
            restored_state.act.tick_phase_ms
        ),
        (50, 1300)
    );

    let re_persisted = persisted_of(&restored_state, &*restored_storage, 50);
    assert_eq!(persisted, re_persisted);

    let mut restored_storage_2 = Box::new(RamStorageMock::<NV_STORAGE_SIZE>::new());
    let mut restored_state_2 = Box::<GlobalState>::default();
    persistence::deserialize(
        &re_persisted,
        &mut restored_state_2,
        &mut *restored_storage_2,
        50,
        &TestCryptoProvider,
    );
    assert_eq!(restored_storage.as_slice(), restored_storage_2.as_slice());
    // The restored storage holds the same NV header and items as the original one.
    assert_eq!(restored_storage.as_slice(), storage.as_slice());

    // The ACTs tick on from the persisted phase: the pending second and one more after 700 ms
    // (the restored TPM is initialized).
    let act = &mut restored_state.act;
    act.counters[0].remaining = 5;
    act.catch_up(749, true);
    assert_eq!(act.counters[0].remaining, 4);
    act.catch_up(750, true);
    assert_eq!(act.counters[0].remaining, 3);
}

/// An unknown hash algorithm in the persisted state is rejected.
#[test]
fn invalid_alg_hash_returns_deserialize_error() {
    let state = Box::<GlobalState>::default();
    let storage = Box::new(RamStorageMock::<NV_STORAGE_SIZE>::new());
    let mut persisted = persisted_of(&state, &*storage, 0);
    persisted.clear.platform_alg = Some(0xFFFF);
    let mut out_storage = Box::new(RamStorageMock::<NV_STORAGE_SIZE>::new());
    let mut out_state = Box::<GlobalState>::default();
    assert_eq!(
        restore_into(&persisted, &mut out_state, &mut *out_storage, 0).unwrap_err(),
        DeserializeError::InvalidValue("clear.platform_alg")
    );
}

/// Corrupted persisted states are rejected without modifying the target state or storage:
/// a length beyond the capacity, a transient handle used twice (by two objects or two
/// sequences), a session slot used by a loaded and a saved session, a saved session whose
/// sequence number would be a loaded-session marker, NV payloads that do not match the NV
/// items, a duplicate NV handle, a DRTM handle of `TPM_RH_UNASSIGNED` (which is persisted as
/// `None`) and an unknown algorithm that needs a self test.
#[test]
fn corrupted_persisted_state_is_rejected_without_side_effects() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let mut tpm = setup_real_crypto_tpm(&mut crypto, &mut storage, &mut timer, &mut rng);
    populate(&mut tpm);
    let mut good = new_persisted();
    tpm.save_persisted_state(&mut good).unwrap();

    type Corruption = (fn(&mut PersistedTpmState), &'static str);
    let corruptions: [Corruption; 9] = [
        (|p| p.clear.platform_auth.len = 65, "clear.platform_auth"),
        (
            |p| p.loaded.objects.data[0].handle = p.loaded.sequences.data[0].handle,
            "loaded.handle",
        ),
        (
            |p| {
                let first = p.loaded.sequences.data[0];
                p.loaded.sequences.push(first);
            },
            "loaded.handle",
        ),
        (
            |p| {
                let slot = p.loaded.sessions.data[0].session_handle & 0x00FF_FFFF;
                p.reset.context_counter = 0x1000;
                p.reset
                    .saved_sessions
                    .push(persistence::PersistedSavedSession {
                        slot,
                        sequence: 0x0100,
                    });
            },
            "session.session_handle",
        ),
        (
            |p| {
                p.reset
                    .saved_sessions
                    .push(persistence::PersistedSavedSession {
                        slot: 9,
                        sequence: 2,
                    })
            },
            "reset.saved_sessions.sequence",
        ),
        (|p| p.nv.data.len -= 1, "nv.data"),
        (
            |p| {
                let first = p.nv.handles.data[0];
                let range = p.nv.item_range(first).unwrap();
                p.nv.handles.push(first);
                for i in range {
                    let b = p.nv.data.data[i];
                    p.nv.data.push(b);
                }
            },
            "nv.handles",
        ),
        (
            |p| p.runtime.drtm_handle = Some(Handle::RH_UNASSIGNED.0),
            "runtime.drtm_handle",
        ),
        (
            |p| p.self_test.untested_algorithms.push(0x7FFF),
            "untested_algorithms",
        ),
    ];

    let mut before = new_persisted();
    tpm.save_persisted_state(&mut before).unwrap();
    assert_eq!(before, good);
    for (corrupt, field) in corruptions {
        let mut bad = good.clone();
        corrupt(&mut bad);
        let err = tpm.restore_persisted_state(&bad).unwrap_err();
        assert_eq!(field_of(err), field, "{err}");
        let mut after = new_persisted();
        tpm.save_persisted_state(&mut after).unwrap();
        assert_eq!(before, after, "a rejected state must not modify the TPM");
    }
}

/// The field a [`DeserializeError`] reports.
fn field_of(err: DeserializeError) -> &'static str {
    match err {
        DeserializeError::MissingField(field) | DeserializeError::InvalidValue(field) => field,
        DeserializeError::InvalidType { field, .. }
        | DeserializeError::InvalidLength { field, .. } => field,
        DeserializeError::Storage(_) => "storage",
    }
}

/// The persisted state of a running TPM survives a `serde` round trip (JSON): the deserialized
/// state is equal to the original and restores a TPM that continues with the same results.
#[cfg(feature = "serde")]
#[test]
fn persisted_state_serde_json_round_trip() {
    two_engines!(source, target);
    let handles = populate(&mut source);
    let mut persisted = new_persisted();
    source.save_persisted_state(&mut persisted).unwrap();

    let json = serde_json::to_vec(&*persisted).unwrap();
    let decoded: Box<PersistedTpmState> = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded, persisted);
    // Only the active elements of the arrays are written.
    assert!(json.len() < 64 * 1024, "{} bytes", json.len());

    target.restore_persisted_state(&decoded).unwrap();
    assert_eq!(
        continue_after_populate(&mut source, handles),
        continue_after_populate(&mut target, handles)
    );
}

/// `Array` serializes its active elements only and rejects a sequence longer than
/// its capacity.
#[cfg(feature = "serde")]
#[test]
fn array_serde_uses_active_elements_and_checks_capacity() {
    let mut array: Array<u8, 4> = Array::from_slice(&[1, 2]);
    array.data[3] = 0xFF;
    assert_eq!(serde_json::to_string(&array).unwrap(), "[1,2]");
    let decoded: Array<u8, 4> = serde_json::from_str("[1,2]").unwrap();
    assert_eq!(decoded, array);
    assert_eq!(decoded.data, [1, 2, 0, 0]);
    assert!(serde_json::from_str::<Array<u8, 4>>("[1,2,3,4,5]").is_err());
}

/// The fixed byte arrays (DRBG seed, PCR values, ...) must have their exact length.
#[cfg(feature = "serde")]
#[test]
fn fixed_byte_arrays_require_their_exact_length() {
    let state = Box::<GlobalState>::default();
    let storage = Box::new(RamStorageMock::<NV_STORAGE_SIZE>::new());
    let persisted = persisted_of(&state, &*storage, 0);
    let mut json: serde_json::Value = serde_json::to_value(&*persisted).unwrap();
    let seed = json["orderly"]["drbg"]["seed"].as_array_mut().unwrap();
    assert_eq!(seed.len(), 48);
    seed.pop();
    assert!(serde_json::from_value::<Box<PersistedTpmState>>(json.clone()).is_err());
    json["orderly"]["drbg"]["seed"]
        .as_array_mut()
        .unwrap()
        .push(0.into());
    json["orderly"]["drbg"]["seed"]
        .as_array_mut()
        .unwrap()
        .push(0.into());
    assert!(serde_json::from_value::<Box<PersistedTpmState>>(json).is_err());
}

/// A live migration: the persisted state of a running TPM (loaded and persistent objects, an
/// owner authValue, an NV index, an extended PCR, an open hash sequence and a policy session)
/// restored into a new, unmanufactured engine reproduces the same persisted state, and both
/// TPMs then answer the same commands identically and end in the same state.
#[test]
fn live_migration_continues_with_the_same_results() {
    two_engines!(source, target);
    let handles = populate(&mut source);

    let mut persisted = new_persisted();
    source.save_persisted_state(&mut persisted).unwrap();
    assert_eq!(persisted.loaded.objects.len, 1);
    assert_eq!(persisted.loaded.sequences.len, 1);
    assert_eq!(persisted.loaded.sessions.len, 1);
    assert!(persisted.nv.handles.iter().any(|&h| h == NV_INDEX.0));
    assert!(
        persisted
            .nv
            .handles
            .iter()
            .any(|&h| h == PERSISTENT_HANDLE.0)
    );
    // The handles are in ascending order.
    assert!(persisted.nv.handles.as_slice().is_sorted());

    target.restore_persisted_state(&persisted).unwrap();
    let mut restored = new_persisted();
    target.save_persisted_state(&mut restored).unwrap();
    assert_eq!(persisted, restored);

    let expected = continue_after_populate(&mut source, handles);
    let actual = continue_after_populate(&mut target, handles);
    assert_eq!(expected, actual);
    // SHA-256("hello, world").
    assert_eq!(
        expected[6],
        hex_literal::hex!("09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b")
    );

    let mut source_after = new_persisted();
    source.save_persisted_state(&mut source_after).unwrap();
    let mut target_after = new_persisted();
    target.save_persisted_state(&mut target_after).unwrap();
    assert_eq!(source_after, target_after);
}

/// The NV storage of a migrated TPM is complete: after a TPM Reset (`_TPM_Init` and
/// `TPM2_Startup(TPM_SU_CLEAR)`) of the target, which reloads the persistent state from NV
/// only, the owner authValue, the NV index and the persistent key are still there.
#[test]
fn migrated_tpm_keeps_its_persistent_state_across_a_tpm_reset() {
    two_engines!(source, target);
    let (primary, _, _) = populate(&mut source);
    let persistent_name = name_of(&mut source, PERSISTENT_HANDLE);
    let primary_name = name_of(&mut source, primary);

    let mut persisted = new_persisted();
    source.save_persisted_state(&mut persisted).unwrap();
    target.restore_persisted_state(&persisted).unwrap();

    target.reset();
    execute_command(
        &mut target,
        &Startup {
            startup_type: TpmSu::Clear,
        },
        &[],
    )
    .expect("Startup");

    // Transient objects do not survive a TPM Reset; the persistent key does.
    assert!(
        execute_command(
            &mut target,
            &ReadPublic {
                object_handle: primary
            },
            &[]
        )
        .is_err()
    );
    assert_eq!(name_of(&mut target, PERSISTENT_HANDLE), persistent_name);
    assert_eq!(persistent_name, primary_name);

    // The owner authValue is "owner-pw" (the empty one is rejected).
    let read = NVRead {
        auth_handle: Handle::RH_OWNER,
        nv_index: NV_INDEX,
        size: 16,
        offset: 0,
    };
    assert!(execute_command(&mut target, &read, &[password_auth(b"")]).is_err());
    let data = execute_command(&mut target, &read, &[password_auth(b"owner-pw")])
        .expect("NV_Read")
        .data;
    assert_eq!(data.as_slice(), &[0x42; 16]);

    // The primary seed survived: the same template gives the same primary key.
    let recreated = create_storage_primary(&mut target, b"owner-pw");
    assert_eq!(name_of(&mut target, recreated), primary_name);

    // The reset counter moved on from the source's.
    assert_eq!(target.state.reset_count, source.state.reset_count + 1);
}

/// The algorithm self-test state (outside `GlobalState`) is persisted and restored by the
/// engine methods, including Failure mode; the free functions persist the state after
/// `_TPM_Init`.
#[test]
fn self_test_state_is_persisted_by_the_engine() {
    two_engines!(source, target);
    populate(&mut source);
    source.self_test.fail();

    let mut persisted = new_persisted();
    source.save_persisted_state(&mut persisted).unwrap();
    assert!(persisted.self_test.failed);
    let untested: Vec<u16> = source.self_test.load().iter().collect();
    assert_eq!(
        persisted.self_test.untested_algorithms.as_slice(),
        &untested[..]
    );

    target.restore_persisted_state(&persisted).unwrap();
    assert!(target.self_test.failed());
    assert_eq!(target.self_test.load(), source.self_test.load());

    let mut from_free_fn = new_persisted();
    persistence::try_serialize(
        &source.state,
        &*source.platform.storage,
        0,
        &mut from_free_fn,
    )
    .unwrap();
    assert!(!from_free_fn.self_test.failed);
    let initial: Vec<u16> = tpm2_engine::self_test::SelfTestState::default()
        .load()
        .iter()
        .collect();
    assert_eq!(
        from_free_fn.self_test.untested_algorithms.as_slice(),
        &initial[..]
    );
}

/// The NV-synced fields are not persisted twice: restore reloads them from the NV records of the
/// persisted NV image, so an owner authValue changed in the hierarchy record of the image is
/// the owner authValue of the restored TPM (in RAM and in NV).
#[test]
fn restore_reloads_nv_synced_fields_from_the_nv_records() {
    two_engines!(source, target);
    populate(&mut source);
    let mut persisted = new_persisted();
    source.save_persisted_state(&mut persisted).unwrap();

    // Re-encode the hierarchy record of the image with another owner authValue (of the same
    // size, so that the payload keeps its length).
    let range = persisted
        .nv
        .item_range(HIERARCHY_RECORD_HANDLE)
        .expect("hierarchy record");
    let item = &mut persisted.nv.data.data[range];
    let mut record = NvHierarchyRecord::decode(item).expect("decode");
    assert_eq!(record.owner_auth.get_buffer(), b"owner-pw");
    record.owner_auth = Tpm2bAuth::from_bytes(b"other-pw").unwrap().into();
    let mut buf = [0u8; HIERARCHY_RECORD_SIZE];
    let len = record.encode(&mut buf);
    assert_eq!(len, item.len());
    item.copy_from_slice(&buf[..len]);

    target.restore_persisted_state(&persisted).unwrap();
    assert_eq!(target.state.owner_auth.get_buffer(), b"other-pw");
    assert_eq!(target.state.reset_count, source.state.reset_count);
    assert_eq!(target.state.clear_count, source.state.clear_count);
    assert_eq!(target.state.sp_seed, source.state.sp_seed);
    let read = NVRead {
        auth_handle: Handle::RH_OWNER,
        nv_index: NV_INDEX,
        size: 16,
        offset: 0,
    };
    assert!(execute_command(&mut target, &read, &[password_auth(b"owner-pw")]).is_err());
    let data = execute_command(&mut target, &read, &[password_auth(b"other-pw")])
        .expect("NV_Read")
        .data;
    assert_eq!(data.as_slice(), &[0x42; 16]);
}

/// *Time* and *Clock* (`TPM2_ReadClock`).
fn read_clock(tpm: &mut RealCryptoEngine<'_>) -> (u64, u64) {
    let info = execute_command(tpm, &ReadClock {}, &[])
        .expect("ReadClock")
        .current_time;
    (info.time, info.clock_info.clock)
}

/// The persisted platform time is relative to the timer reading of the save: restored on a
/// platform timer that reads less than the source's (a new platform), *Time* and *Clock* go on
/// with the target's timer instead of stopping until it catches up with the source's readings.
#[test]
fn restore_on_another_platform_timer_continues_time() {
    two_engines!(source, target);
    let timer = FakeTimer::new();
    populate(&mut source);
    timer.set_time(1_000_000);
    let (time, clock) = read_clock(&mut source);
    let mut persisted = new_persisted();
    source.save_persisted_state(&mut persisted).unwrap();
    assert_eq!(persisted.time.pending_platform_ms, 0);

    // The target's platform timer reads 250 at the restore and 3250 three seconds later.
    timer.set_time(250);
    target.restore_persisted_state(&persisted).unwrap();
    timer.set_time(3250);
    assert_eq!(read_clock(&mut target), (time + 3000, clock + 3000));
}

/// `clearCount` is ahead of NV after a TPM Restart (`TPM2_Startup` increments it in RAM only),
/// and a migration keeps the RAM value, which the context integrity of `stClear` objects mixes
/// in.
#[test]
fn clear_count_after_tpm_restart_survives_migration() {
    two_engines!(source, target);
    execute_command(
        &mut source,
        &Shutdown {
            shutdown_type: TpmSu::State,
        },
        &[],
    )
    .expect("Shutdown");
    source.reset();
    execute_command(
        &mut source,
        &Startup {
            startup_type: TpmSu::Clear,
        },
        &[],
    )
    .expect("Startup");
    assert_eq!(source.state.clear_count, 1);

    let mut persisted = new_persisted();
    source.save_persisted_state(&mut persisted).unwrap();
    assert_eq!(persisted.reset.clear_count, 1);
    let record =
        NvHierarchyRecord::decode(nv_payload(&persisted, HIERARCHY_RECORD_HANDLE)).unwrap();
    assert_eq!(record.seeds.unwrap().clear_count, 0, "NV is behind RAM");

    target.restore_persisted_state(&persisted).unwrap();
    assert_eq!(target.state.clear_count, 1);
}

/// A DA failure while NV is unavailable updates `failedTries` in RAM only and defers the NV
/// update to the next command that checks the lockout with NV available. A migration in
/// between keeps the RAM value and the pending update, which the target then writes to NV like
/// the source.
#[test]
fn deferred_da_update_survives_migration() {
    two_engines!(source, target);
    let (primary, _, _) = populate(&mut source);
    let change_auth = ObjectChangeAuth {
        object_handle: primary,
        // Only the object's authorization matters here, not the outcome of the command.
        parent_handle: primary,
        new_auth: Tpm2bAuth::default(),
    };
    // A first failure with NV available, then one with NV unavailable.
    assert!(execute_command(&mut source, &change_auth, &[password_auth(b"wrong")]).is_err());
    source.set_nv_available(false);
    assert!(execute_command(&mut source, &change_auth, &[password_auth(b"wrong")]).is_err());
    source.set_nv_available(true);
    assert_eq!(source.state.failed_tries, 2);

    let mut persisted = new_persisted();
    source.save_persisted_state(&mut persisted).unwrap();
    assert_eq!(NvHeader::decode(&persisted.nv.header).failed_tries, 1);
    assert_eq!(persisted.runtime.failed_tries, 2);
    assert!(persisted.runtime.da_pending_on_nv);

    target.restore_persisted_state(&persisted).unwrap();
    assert_eq!(target.state.failed_tries, 2);
    assert!(target.state.da_pending_on_nv);

    // The next DA-protected authorization writes the pending update to NV on both TPMs.
    for tpm in [&mut source, &mut target] {
        let _ = execute_command(tpm, &change_auth, &[password_auth(b"")]);
        assert!(!tpm.state.da_pending_on_nv);
        assert_eq!(
            NvHeader::read(&*tpm.platform.storage).unwrap().failed_tries,
            2
        );
    }
    let mut source_after = new_persisted();
    source.save_persisted_state(&mut source_after).unwrap();
    let mut target_after = new_persisted();
    target.save_persisted_state(&mut target_after).unwrap();
    assert_eq!(source_after, target_after);
}

/// `orderly_state` in RAM may differ from NV: a `TPM2_Startup` after a DA-protected use
/// replaces `SU_DA_USED` with `SU_NONE` in RAM before checks that can still fail (here
/// `TPM2_Startup(TPM_SU_STATE)` without a saved state). A migration keeps the RAM value, so the
/// next `TPM2_Startup` of the target, like the source's, does not count the DA-protected use as
/// a failure again.
#[test]
fn ram_orderly_state_after_failed_startup_survives_migration() {
    two_engines!(source, target);
    let (primary, _, _) = populate(&mut source);
    let change_auth = ObjectChangeAuth {
        object_handle: primary,
        // Only the object's authorization matters here, not the outcome of the command.
        parent_handle: primary,
        new_auth: Tpm2bAuth::default(),
    };
    // A DA-protected use: NV records `SU_DA_USED`.
    let _ = execute_command(&mut source, &change_auth, &[password_auth(b"")]);
    source.reset();
    assert!(
        execute_command(
            &mut source,
            &Startup {
                startup_type: TpmSu::State,
            },
            &[],
        )
        .is_err()
    );
    let mut persisted = new_persisted();
    source.save_persisted_state(&mut persisted).unwrap();
    assert_eq!(NvHeader::decode(&persisted.nv.header).orderly_state, 0xFFFE);
    assert_eq!(persisted.runtime.orderly_state, 0xFFFF);

    target.restore_persisted_state(&persisted).unwrap();
    let failed_tries = source.state.failed_tries;
    for tpm in [&mut source, &mut target] {
        execute_command(
            tpm,
            &Startup {
                startup_type: TpmSu::Clear,
            },
            &[],
        )
        .expect("Startup");
        assert_eq!(tpm.state.failed_tries, failed_tries);
    }
}
