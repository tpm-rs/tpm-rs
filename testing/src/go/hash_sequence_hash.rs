use crate::test_utils::execute_with_password_sessions;
use rand::{RngCore, thread_rng};
use sha2::{Digest, Sha256};
use tpm2::Handle;
use tpm2::commands::{
    Hash, HashSequenceStart, SequenceComplete, SequenceCompleteHandles, SequenceUpdate,
    SequenceUpdateHandles,
};
use tpm2::{Tpm2bAuth, Tpm2bMaxBuffer, TpmiAlgHash};
use tpm2_simulator::{Simulator, create_simulator};

/// Port of the `run` closure in `TestHash`: hashes `data` with SHA-256 using
/// `TPM2_Hash` in the given hierarchy and checks the digest.
fn run_hash(sim: &mut Simulator<'_>, data: &[u8], hierarchy: Handle) {
    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy,
    };
    let resp = sim.execute(cmd).expect("Hash failed");
    let want_digest = Sha256::digest(data);
    assert_eq!(
        resp.out_hash.as_ref(),
        want_digest.as_slice(),
        "Hash({data:?}) returned wrong digest"
    );
}

// Original Go test: hash_sequence_hash_test.go - TestHash/Null hierarchy
#[test]
fn test_hash_null_hierarchy_subtest() {
    let mut sim = create_simulator!();
    run_hash(&mut sim, b"fiona", Handle::RH_NULL);
}

// Original Go test: hash_sequence_hash_test.go - TestHash/Owner hierarchy
#[test]
fn test_hash_owner_hierarchy() {
    let mut sim = create_simulator!();
    run_hash(&mut sim, b"charlie", Handle::RH_OWNER);
}

// Original Go test: hash_sequence_hash_test.go - TestHashNullHierarchy
#[test]
fn test_hash_null_hierarchy() {
    let mut sim = create_simulator!();

    // go-tpm marshals the omitted (zero-valued, nullable) Hierarchy as TPM_RH_NULL.
    let data = b"carolyn";
    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle::RH_NULL,
    };
    let resp = sim.execute(cmd).expect("Hash failed");
    let want_digest = Sha256::digest(data);
    assert_eq!(
        resp.out_hash.as_ref(),
        want_digest.as_slice(),
        "Hash({data:?}) returned wrong digest"
    );
}

/// Port of the `run` closures in `TestHashSequence` and
/// `TestHashSequenceNullHierarchy`: starts a SHA-256 hash sequence protected by
/// `password`, feeds `buffer_size` random bytes (in 1024-byte
/// `TPM2_SequenceUpdate` chunks) and checks the `TPM2_SequenceComplete` digest.
///
/// For `TestHashSequenceNullHierarchy` the Go code omits `Hierarchy`, which
/// go-tpm marshals as TPM_RH_NULL, so callers pass `Handle::RH_NULL`.
fn run_hash_sequence(
    sim: &mut Simulator<'_>,
    buffer_size: usize,
    password: &str,
    hierarchy: Handle,
) {
    let max_digest_buffer = 1024;
    let auth = password.as_bytes();

    let cmd_start = HashSequenceStart {
        auth: Tpm2bAuth::from_bytes(auth).unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let (_, resp_start_handles) = sim
        .execute_with_handles(cmd_start, ())
        .expect("HashSequenceStart failed");
    let sequence_handle = resp_start_handles.sequence_handle;

    let mut data = vec![0u8; buffer_size];
    thread_rng().fill_bytes(&mut data);
    let want_digest = Sha256::digest(&data);

    let mut remaining_data = data.as_slice();
    while remaining_data.len() > max_digest_buffer {
        let cmd_update = SequenceUpdate {
            buffer: Tpm2bMaxBuffer::from_bytes(&remaining_data[..max_digest_buffer]).unwrap(),
        };
        let cmd_handles = SequenceUpdateHandles { sequence_handle };
        execute_with_password_sessions(sim, &cmd_update, cmd_handles, 1, auth)
            .expect("SequenceUpdate failed");
        remaining_data = &remaining_data[max_digest_buffer..];
    }

    let cmd_complete = SequenceComplete {
        buffer: Tpm2bMaxBuffer::from_bytes(remaining_data).unwrap(),
        hierarchy,
    };
    let cmd_handles = SequenceCompleteHandles { sequence_handle };
    let (resp_complete, _) =
        execute_with_password_sessions(sim, &cmd_complete, cmd_handles, 1, auth)
            .expect("SequenceComplete failed");

    assert_eq!(
        resp_complete.result.as_ref(),
        want_digest.as_slice(),
        "The resulting digest is not expected"
    );
}

/// Body of the `TestHashSequence/*` and `TestHashSequenceNullHierarchy/*` subtests.
fn hash_sequence_subtest(buffer_size: usize, hierarchy: Handle) {
    let mut sim = create_simulator!();
    run_hash_sequence(&mut sim, buffer_size, "password", hierarchy);
}

// Original Go test: hash_sequence_hash_test.go - TestHashSequence/Null hierarchy [bufferSize=512]
#[test]
fn test_hash_sequence_null_hierarchy_buffer_size_512() {
    hash_sequence_subtest(512, Handle::RH_NULL);
}

// Original Go test: hash_sequence_hash_test.go - TestHashSequence/Owner hierarchy [bufferSize=512]
#[test]
fn test_hash_sequence_owner_hierarchy_buffer_size_512() {
    hash_sequence_subtest(512, Handle::RH_OWNER);
}

// Original Go test: hash_sequence_hash_test.go - TestHashSequence/Null hierarchy [bufferSize=1024]
#[test]
fn test_hash_sequence_null_hierarchy_buffer_size_1024() {
    hash_sequence_subtest(1024, Handle::RH_NULL);
}

// Original Go test: hash_sequence_hash_test.go - TestHashSequence/Owner hierarchy [bufferSize=1024]
#[test]
fn test_hash_sequence_owner_hierarchy_buffer_size_1024() {
    hash_sequence_subtest(1024, Handle::RH_OWNER);
}

// Original Go test: hash_sequence_hash_test.go - TestHashSequence/Null hierarchy [bufferSize=2048]
#[test]
fn test_hash_sequence_null_hierarchy_buffer_size_2048() {
    hash_sequence_subtest(2048, Handle::RH_NULL);
}

// Original Go test: hash_sequence_hash_test.go - TestHashSequence/Owner hierarchy [bufferSize=2048]
#[test]
fn test_hash_sequence_owner_hierarchy_buffer_size_2048() {
    hash_sequence_subtest(2048, Handle::RH_OWNER);
}

// Original Go test: hash_sequence_hash_test.go - TestHashSequence/Null hierarchy [bufferSize=4096]
#[test]
fn test_hash_sequence_null_hierarchy_buffer_size_4096() {
    hash_sequence_subtest(4096, Handle::RH_NULL);
}

// Original Go test: hash_sequence_hash_test.go - TestHashSequence/Owner hierarchy [bufferSize=4096]
#[test]
fn test_hash_sequence_owner_hierarchy_buffer_size_4096() {
    hash_sequence_subtest(4096, Handle::RH_OWNER);
}

// Original Go test: hash_sequence_hash_test.go - TestHashSequenceNullHierarchy/Null hierarchy [bufferSize=512]
#[test]
fn test_hash_sequence_null_hierarchy_null_hierarchy_buffer_size_512() {
    hash_sequence_subtest(512, Handle::RH_NULL);
}

// Original Go test: hash_sequence_hash_test.go - TestHashSequenceNullHierarchy/Null hierarchy [bufferSize=1024]
#[test]
fn test_hash_sequence_null_hierarchy_null_hierarchy_buffer_size_1024() {
    hash_sequence_subtest(1024, Handle::RH_NULL);
}

// Original Go test: hash_sequence_hash_test.go - TestHashSequenceNullHierarchy/Null hierarchy [bufferSize=2048]
#[test]
fn test_hash_sequence_null_hierarchy_null_hierarchy_buffer_size_2048() {
    hash_sequence_subtest(2048, Handle::RH_NULL);
}

// Original Go test: hash_sequence_hash_test.go - TestHashSequenceNullHierarchy/Null hierarchy [bufferSize=4096]
#[test]
fn test_hash_sequence_null_hierarchy_null_hierarchy_buffer_size_4096() {
    hash_sequence_subtest(4096, Handle::RH_NULL);
}
