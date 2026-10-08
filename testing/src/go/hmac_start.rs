#![forbid(unsafe_code)]

use crate::test_utils::{
    ActiveSession, execute_with_hmac_sessions, execute_with_password_sessions, flush_context,
    start_auth_session,
};
use rand::{RngCore, thread_rng};
use tpm2::commands::{
    CreatePrimary, CreatePrimaryHandles, HmacStart, HmacStartHandles, SequenceComplete,
    SequenceCompleteHandles, SequenceUpdate, SequenceUpdateHandles,
};
use tpm2::{Handle, TpmSe};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, TpmaObject, TpmaSession, TpmiAlgHash,
    TpmsSensitiveCreate, TpmtKeyedHashScheme, TpmtPublic,
};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

/// Maximum input buffer size used by the Go test when splitting data into
/// `TPM2_SequenceUpdate` chunks.
const MAX_INPUT_BUFFER: usize = 1024;

/// Equivalent of go-tpm's `HMACSession(thetpm, TPMAlgSHA256, 16)`: an unbound,
/// unsalted HMAC session with a NULL symmetric algorithm and `continueSession`
/// set (no parameter encryption).
fn start_hmac_session(sim: &mut Simulator<'_>) -> ActiveSession {
    let mut session = start_auth_session(
        sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("could not create hmac key authorization session");
    session.attributes.insert(TpmaSession::CONTINUE_SESSION);
    session
}

/// The keyed-hash HMAC-SHA256 primary key template used by all tests in
/// `hmac_start_test.go`.
fn hmac_key_create_primary() -> CreatePrimary<'static> {
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
            Tpm2bDigest::default(),
        ),
    };
    CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: tpm2::Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(pub_area),
        ..Default::default()
    }
}

/// Feeds `data` into the sequence (in `MAX_INPUT_BUFFER` chunks via
/// `TPM2_SequenceUpdate`) and completes it with `TPM2_SequenceComplete`,
/// authorizing each command with a password session using `password`.
fn update_and_complete_sequence(
    sim: &mut Simulator<'_>,
    sequence_handle: Handle,
    mut data: &[u8],
    password: &[u8],
    hierarchy: Handle,
) -> Vec<u8> {
    while data.len() > MAX_INPUT_BUFFER {
        let cmd_update = SequenceUpdate {
            buffer: tpm2::Tpm2bMaxBuffer::from_bytes(&data[..MAX_INPUT_BUFFER]).unwrap(),
        };
        let cmd_handles = SequenceUpdateHandles { sequence_handle };
        execute_with_password_sessions(sim, &cmd_update, cmd_handles, 1, password)
            .expect("SequenceUpdate failed");
        data = &data[MAX_INPUT_BUFFER..];
    }

    let cmd_complete = SequenceComplete {
        buffer: tpm2::Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hierarchy,
    };
    let cmd_handles = SequenceCompleteHandles { sequence_handle };
    let (resp_complete, _) =
        execute_with_password_sessions(sim, &cmd_complete, cmd_handles, 1, password)
            .expect("SequenceComplete failed");
    resp_complete.result.as_ref().to_vec()
}

/// Port of the `run` closure in `TestHmacStart`: CreatePrimary and HmacStart
/// are authorized with an HMAC session; the sequence is driven with password
/// authorization.
fn run_hmac_start(
    sim: &mut Simulator<'_>,
    data: &[u8],
    password: &[u8],
    hierarchy: Handle,
) -> Vec<u8> {
    let mut sas = start_hmac_session(sim);

    let create_cmd = hmac_key_create_primary();
    let create_handles = CreatePrimaryHandles {
        primary_handle: hierarchy,
    };
    let (create_rsp, create_rsp_handles) = execute_with_hmac_sessions(
        sim,
        &create_cmd,
        create_handles,
        &[],
        core::slice::from_mut(&mut sas),
        &[&[]],
    )
    .expect("CreatePrimary HMAC key failed");
    let object_handle = create_rsp_handles.object_handle;
    let name = create_rsp.name;

    let start_cmd = HmacStart {
        auth: Tpm2bAuth::from_bytes(password).unwrap(),
        hash_alg: None,
    };
    let start_handles = HmacStartHandles {
        handle: object_handle,
    };
    let (_, start_resp_handles) = execute_with_hmac_sessions(
        sim,
        &start_cmd,
        start_handles,
        &[name.get_buffer()],
        core::slice::from_mut(&mut sas),
        &[&[]],
    )
    .expect("HmacStart failed");

    let result = update_and_complete_sequence(
        sim,
        start_resp_handles.sequence_handle,
        data,
        password,
        hierarchy,
    );

    // Deferred cleanup in Go runs in LIFO order: flush the key, then the session.
    let _ = flush_context(sim, object_handle);
    let _ = flush_context(sim, sas.session_handle);

    result
}

/// Port of the `run` closure in `TestHmacStartNoKeyAuth`: CreatePrimary and
/// HmacStart are authorized with empty password sessions.
fn run_hmac_start_no_key_auth(
    sim: &mut Simulator<'_>,
    data: &[u8],
    password: &[u8],
    hierarchy: Handle,
) -> Vec<u8> {
    let create_cmd = hmac_key_create_primary();
    let create_handles = CreatePrimaryHandles {
        primary_handle: hierarchy,
    };
    let (_, create_rsp_handles) =
        execute_with_password_sessions(sim, &create_cmd, create_handles, 1, &[])
            .expect("CreatePrimary HMAC key failed");
    let object_handle = create_rsp_handles.object_handle;

    let start_cmd = HmacStart {
        auth: Tpm2bAuth::from_bytes(password).unwrap(),
        hash_alg: None,
    };
    let start_handles = HmacStartHandles {
        handle: object_handle,
    };
    let (_, start_resp_handles) =
        execute_with_password_sessions(sim, &start_cmd, start_handles, 1, &[])
            .expect("HmacStart failed");

    let result = update_and_complete_sequence(
        sim,
        start_resp_handles.sequence_handle,
        data,
        password,
        hierarchy,
    );

    let _ = flush_context(sim, object_handle);

    result
}

/// Returns an 8-byte random password, as generated by the Go tests.
fn random_password() -> [u8; 8] {
    let mut password = [0u8; 8];
    thread_rng().fill_bytes(&mut password);
    password
}

/// Body of the `TestHmacStart/<name> hierarchy [bufferSize=N]` subtests: the
/// HMAC key is not exported, so HMAC the same random data twice and confirm
/// the results match.
fn hmac_start_subtest(buffer_size: usize, hierarchy: Handle) {
    let mut sim = create_simulator!();
    let password = random_password();
    let mut data = vec![0u8; buffer_size];
    thread_rng().fill_bytes(&mut data);
    let hmac1 = run_hmac_start(&mut sim, &data, &password, hierarchy);
    let hmac2 = run_hmac_start(&mut sim, &data, &password, hierarchy);
    assert_eq!(hmac1, hmac2, "hmac {hmac1:x?} is not expected {hmac2:x?}");
}

/// Body of the `TestHmacStartNoKeyAuth/<name> hierarchy [bufferSize=1024]`
/// subtests.
fn hmac_start_no_key_auth_subtest(hierarchy: Handle) {
    let mut sim = create_simulator!();
    let password = random_password();
    let mut data = vec![0u8; 1024];
    thread_rng().fill_bytes(&mut data);
    let hmac1 = run_hmac_start_no_key_auth(&mut sim, &data, &password, hierarchy);
    let hmac2 = run_hmac_start_no_key_auth(&mut sim, &data, &password, hierarchy);
    assert_eq!(hmac1, hmac2, "hmac {hmac1:x?} is not expected {hmac2:x?}");
}

// Original Go test: hmac_start_test.go - TestHmacStart/Null hierarchy [bufferSize=512]
#[test]
fn test_hmac_start_null_hierarchy_buffer_size_512() {
    hmac_start_subtest(512, Handle::RH_NULL);
}

// Original Go test: hmac_start_test.go - TestHmacStart/Owner hierarchy [bufferSize=512]
#[test]
fn test_hmac_start_owner_hierarchy_buffer_size_512() {
    hmac_start_subtest(512, Handle::RH_OWNER);
}

// Original Go test: hmac_start_test.go - TestHmacStart/Endorsement hierarchy [bufferSize=512]
#[test]
fn test_hmac_start_endorsement_hierarchy_buffer_size_512() {
    hmac_start_subtest(512, Handle::RH_ENDORSEMENT);
}

// Original Go test: hmac_start_test.go - TestHmacStart/Null hierarchy [bufferSize=1024]
#[test]
fn test_hmac_start_null_hierarchy_buffer_size_1024() {
    hmac_start_subtest(1024, Handle::RH_NULL);
}

// Original Go test: hmac_start_test.go - TestHmacStart/Owner hierarchy [bufferSize=1024]
#[test]
fn test_hmac_start_owner_hierarchy_buffer_size_1024() {
    hmac_start_subtest(1024, Handle::RH_OWNER);
}

// Original Go test: hmac_start_test.go - TestHmacStart/Endorsement hierarchy [bufferSize=1024]
#[test]
fn test_hmac_start_endorsement_hierarchy_buffer_size_1024() {
    hmac_start_subtest(1024, Handle::RH_ENDORSEMENT);
}

// Original Go test: hmac_start_test.go - TestHmacStart/Null hierarchy [bufferSize=2048]
#[test]
fn test_hmac_start_null_hierarchy_buffer_size_2048() {
    hmac_start_subtest(2048, Handle::RH_NULL);
}

// Original Go test: hmac_start_test.go - TestHmacStart/Owner hierarchy [bufferSize=2048]
#[test]
fn test_hmac_start_owner_hierarchy_buffer_size_2048() {
    hmac_start_subtest(2048, Handle::RH_OWNER);
}

// Original Go test: hmac_start_test.go - TestHmacStart/Endorsement hierarchy [bufferSize=2048]
#[test]
fn test_hmac_start_endorsement_hierarchy_buffer_size_2048() {
    hmac_start_subtest(2048, Handle::RH_ENDORSEMENT);
}

// Original Go test: hmac_start_test.go - TestHmacStart/Null hierarchy [bufferSize=4096]
#[test]
fn test_hmac_start_null_hierarchy_buffer_size_4096() {
    hmac_start_subtest(4096, Handle::RH_NULL);
}

// Original Go test: hmac_start_test.go - TestHmacStart/Owner hierarchy [bufferSize=4096]
#[test]
fn test_hmac_start_owner_hierarchy_buffer_size_4096() {
    hmac_start_subtest(4096, Handle::RH_OWNER);
}

// Original Go test: hmac_start_test.go - TestHmacStart/Endorsement hierarchy [bufferSize=4096]
#[test]
fn test_hmac_start_endorsement_hierarchy_buffer_size_4096() {
    hmac_start_subtest(4096, Handle::RH_ENDORSEMENT);
}

// Original Go test: hmac_start_test.go - TestHmacStart/Same key multiple sequences
#[test]
fn test_hmac_start_same_key_multiple_sequences() {
    let mut sim = create_simulator!();
    let password = random_password();

    let mut sas = start_hmac_session(&mut sim);

    let create_cmd = hmac_key_create_primary();
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_NULL,
    };
    let (create_rsp, create_rsp_handles) = execute_with_hmac_sessions(
        &mut sim,
        &create_cmd,
        create_handles,
        &[],
        core::slice::from_mut(&mut sas),
        &[&[]],
    )
    .expect("CreatePrimary HMAC key failed");
    let object_handle = create_rsp_handles.object_handle;
    let name = create_rsp.name;

    let start_cmd = HmacStart {
        auth: Tpm2bAuth::from_bytes(&password).unwrap(),
        hash_alg: None,
    };
    let start_handles = HmacStartHandles {
        handle: object_handle,
    };

    let (_, start_resp_handles1) = execute_with_hmac_sessions(
        &mut sim,
        &start_cmd,
        start_handles,
        &[name.get_buffer()],
        core::slice::from_mut(&mut sas),
        &[&[]],
    )
    .expect("HmacStart failed");

    let (_, start_resp_handles2) = execute_with_hmac_sessions(
        &mut sim,
        &start_cmd,
        start_handles,
        &[name.get_buffer()],
        core::slice::from_mut(&mut sas),
        &[&[]],
    )
    .expect("HmacStart failed");

    let h1 = start_resp_handles1.sequence_handle;
    let h2 = start_resp_handles2.sequence_handle;
    assert_ne!(h1.0, h2.0, "sequence handles are not unique");

    // go-tpm marshals the zero-valued nullable `Hierarchy` as TPM_RH_NULL and
    // the zero-valued `Buffer` as an empty TPM2B.
    let cmd_complete1 = SequenceComplete {
        buffer: tpm2::Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let cmd_handles1 = SequenceCompleteHandles {
        sequence_handle: h1,
    };
    execute_with_password_sessions(&mut sim, &cmd_complete1, cmd_handles1, 1, &password)
        .expect("SequenceComplete failed");

    let cmd_complete2 = SequenceComplete {
        buffer: tpm2::Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let cmd_handles2 = SequenceCompleteHandles {
        sequence_handle: h2,
    };
    execute_with_password_sessions(&mut sim, &cmd_complete2, cmd_handles2, 1, &password)
        .expect("SequenceComplete failed");

    // Deferred cleanup in Go runs in LIFO order: flush the key, then the session.
    let _ = flush_context(&mut sim, object_handle);
    let _ = flush_context(&mut sim, sas.session_handle);
}

// Original Go test: hmac_start_test.go - TestHmacStartNoKeyAuth/Null hierarchy [bufferSize=1024]
#[test]
fn test_hmac_start_no_key_auth_null_hierarchy_buffer_size_1024() {
    hmac_start_no_key_auth_subtest(Handle::RH_NULL);
}

// Original Go test: hmac_start_test.go - TestHmacStartNoKeyAuth/Owner hierarchy [bufferSize=1024]
#[test]
fn test_hmac_start_no_key_auth_owner_hierarchy_buffer_size_1024() {
    hmac_start_no_key_auth_subtest(Handle::RH_OWNER);
}

// Original Go test: hmac_start_test.go - TestHmacStartNoKeyAuth/Endorsement hierarchy [bufferSize=1024]
#[test]
fn test_hmac_start_no_key_auth_endorsement_hierarchy_buffer_size_1024() {
    hmac_start_no_key_auth_subtest(Handle::RH_ENDORSEMENT);
}
