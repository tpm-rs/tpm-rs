use crate::test_utils::execute_with_password_sessions;
use rand::{RngCore, thread_rng};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use tpm2::Handle;
use tpm2::commands::{
    Hash, HashSequenceStart, SequenceComplete, SequenceCompleteHandles, SequenceUpdate,
    SequenceUpdateHandles,
};
use tpm2::{Tpm2bAuth, Tpm2bMaxBuffer, TpmiAlgHash};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

// Original Go test: hash_sequence_hash_test.go - TestHash
#[test]
fn test_hash() {
    let mut sim = create_simulator!();

    let data = b"fiona";

    // Test SHA-256
    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle::RH_NULL,
    };
    let resp = sim.execute(cmd).unwrap();
    let expected = Sha256::digest(data);
    assert_eq!(resp.out_hash.as_ref(), expected.as_slice());

    // Test SHA-1
    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hash_alg: TpmiAlgHash::Sha1,
        hierarchy: Handle::RH_NULL,
    };
    let resp = sim.execute(cmd).unwrap();
    let expected = Sha1::digest(data);
    assert_eq!(resp.out_hash.as_ref(), expected.as_slice());

    // Test SHA-384
    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hash_alg: TpmiAlgHash::Sha384,
        hierarchy: Handle::RH_NULL,
    };
    let resp = sim.execute(cmd).unwrap();
    let expected = Sha384::digest(data);
    assert_eq!(resp.out_hash.as_ref(), expected.as_slice());

    // Test SHA-512
    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hash_alg: TpmiAlgHash::Sha512,
        hierarchy: Handle::RH_NULL,
    };
    let resp = sim.execute(cmd).unwrap();
    let expected = Sha512::digest(data);
    assert_eq!(resp.out_hash.as_ref(), expected.as_slice());

    // Test invalid hash algorithm
    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hash_alg: TpmiAlgHash::Sm3_256,
        hierarchy: Handle::RH_NULL,
    };
    assert!(sim.execute(cmd).is_err());

    let data_owner = b"charlie";
    let cmd_owner = Hash {
        data: Tpm2bMaxBuffer::from_bytes(data_owner).unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle::RH_OWNER,
    };
    let resp_owner = sim.execute(cmd_owner).unwrap();
    let expected_owner = Sha256::digest(data_owner);
    assert_eq!(resp_owner.out_hash.as_ref(), expected_owner.as_slice());
}

// Original Go test: hash_sequence_hash_test.go - TestHashNullHierarchy
#[test]
fn test_hash_null_hierarchy() {
    let mut sim = create_simulator!();

    let data = b"carolyn";
    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle::RH_NULL,
    };
    let resp = sim.execute(cmd).unwrap();
    let expected = Sha256::digest(data);
    assert_eq!(resp.out_hash.as_ref(), expected.as_slice());
}

fn run_hash_sequence(
    sim: &mut Simulator<'_>,
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

    let (_, resp_start_handles) = sim.execute_with_handles(cmd_start, ()).unwrap();
    let sequence_handle = resp_start_handles.sequence_handle;

    let mut data = vec![0u8; buffer_size];
    thread_rng().fill_bytes(&mut data);
    let expected_digest = match hash_alg {
        TpmiAlgHash::Sha1 => Sha1::digest(&data).to_vec(),
        TpmiAlgHash::Sha256 => Sha256::digest(&data).to_vec(),
        TpmiAlgHash::Sha384 => Sha384::digest(&data).to_vec(),
        TpmiAlgHash::Sha512 => Sha512::digest(&data).to_vec(),
        _ => panic!("Unsupported hash algorithm for test"),
    };

    let mut remaining_data = data.as_slice();
    while remaining_data.len() > max_digest_buffer {
        let chunk = &remaining_data[..max_digest_buffer];
        let cmd_update = SequenceUpdate {
            buffer: Tpm2bMaxBuffer::from_bytes(chunk).unwrap(),
        };
        let cmd_handles = SequenceUpdateHandles { sequence_handle };
        let _ = execute_with_password_sessions(sim, &cmd_update, cmd_handles, 1, auth_bytes)
            .expect("SequenceUpdate failed");
        remaining_data = &remaining_data[max_digest_buffer..];
    }

    let cmd_complete = SequenceComplete {
        buffer: Tpm2bMaxBuffer::from_bytes(remaining_data).unwrap(),
        hierarchy,
    };
    let cmd_handles = SequenceCompleteHandles { sequence_handle };
    let (resp_complete, _) =
        execute_with_password_sessions(sim, &cmd_complete, cmd_handles, 1, auth_bytes)
            .expect("SequenceComplete failed");

    assert_eq!(resp_complete.result.as_ref(), expected_digest.as_slice());
}

// Original Go test: hash_sequence_hash_test.go - TestHashSequence
#[test]
fn test_hash_sequence() {
    let mut sim = create_simulator!();
    let password = "password";
    let buffer_sizes = [512, 1024, 2048, 4096];
    let hash_algs = [
        TpmiAlgHash::Sha1,
        TpmiAlgHash::Sha256,
        TpmiAlgHash::Sha384,
        TpmiAlgHash::Sha512,
    ];

    for &size in &buffer_sizes {
        for &alg in &hash_algs {
            run_hash_sequence(&mut sim, size, password, Handle::RH_NULL, alg);
            run_hash_sequence(&mut sim, size, password, Handle::RH_OWNER, alg);
        }
    }
}

// Original Go test: hash_sequence_hash_test.go - TestHashSequenceNullHierarchy
#[test]
fn test_hash_sequence_null_hierarchy() {
    let mut sim = create_simulator!();
    let password = "password";
    let buffer_sizes = [512, 1024, 2048, 4096];
    let hash_algs = [
        TpmiAlgHash::Sha1,
        TpmiAlgHash::Sha256,
        TpmiAlgHash::Sha384,
        TpmiAlgHash::Sha512,
    ];

    for &size in &buffer_sizes {
        for &alg in &hash_algs {
            // Omitting hierarchy field defaults to RHNull in the Go test, so we pass RHNull here.
            run_hash_sequence(&mut sim, size, password, Handle::RH_NULL, alg);
        }
    }
}
