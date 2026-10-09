#![allow(unused_imports, dead_code)]
use crate::test_utils::execute_with_password_sessions;
use rand::{RngCore, thread_rng};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use tpm2::Handle;
use tpm2::commands::{
    Hash, HashSequenceStart, SequenceComplete, SequenceCompleteHandles, SequenceUpdate,
    SequenceUpdateHandles,
};
use tpm2::errors::TpmRc;
use tpm2::{Tpm2bAuth, Tpm2bMaxBuffer, TpmiAlgHash};
use tpm2_simulator::{Simulator, create_simulator};

#[test]
fn test_hash_sequence_unsupported_alg() {
    let mut sim = create_simulator!();
    let cmd_start = HashSequenceStart {
        auth: Tpm2bAuth::default(),
        hash_alg: Some(TpmiAlgHash::Sm3_256),
    };
    let err = sim.execute_with_handles(cmd_start, ()).unwrap_err();
    assert_eq!(err.get(), TpmRc::HASH.get());
}
