// Ported from _agents/skills/go-tests/tests/nv_test.go

use crate::test_utils::*;
use tpm2::commands::{
    NVDefineSpace, NVDefineSpaceHandles, NVIncrement, NVIncrementHandles, NVRead, NVReadHandles,
    NVReadLock, NVReadLockHandles, NVReadPublic, NVReadPublicHandles, NVWrite, NVWriteHandles,
    NVWriteLock, NVWriteLockHandles,
};
use tpm2::errors::TpmRc;
use tpm2::{Handle, TpmSe};
use tpm2::{Tpm2bAuth, Tpm2bDigest, TpmaNv, TpmiAlgHash, TpmsNvPublic};
use tpm2_simulator::{Simulator, create_simulator};

/// NV index used by every test in this file (`TPMHandle(0x0180000F)` in Go).
const NV_INDEX: Handle = Handle(0x0180000F);

/// Starts a one-shot HMAC session equivalent to go-tpm's
/// `HMAC(TPMAlgSHA256, 16, Auth([]byte{}))`: unbound, unsalted, no symmetric
/// cipher, SHA-256, 16-byte caller nonce and `continueSession` clear (so the
/// TPM flushes it after a single command).
fn one_shot_hmac_session(sim: &mut Simulator<'_>) -> ActiveSession {
    start_auth_session(
        sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .expect("Starting HMAC session")
}

// Original Go test: nv_test.go - TestNVAuthWrite
#[test]
fn test_nv_auth_write() {
    let mut sim = create_simulator!();

    let mut attributes = TpmaNv::OWNERWRITE
        | TpmaNv::OWNERREAD
        | TpmaNv::AUTHWRITE
        | TpmaNv::AUTHREAD
        | TpmaNv::NO_DA;
    attributes.set_type(tpm2::TpmNt::Ordinary);

    let public_info_struct = TpmsNvPublic {
        nv_index: NV_INDEX,
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 4,
    };
    let public_info = tpm2::Tpm2b(public_info_struct);

    let define_space = NVDefineSpace {
        auth: Tpm2bAuth::from_bytes(b"p@ssw0rd").unwrap(),
        public_info,
    };
    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &define_space, define_handles, 1, &[])
        .expect("Calling TPM2_NV_DefineSpace");

    // Write with the index's own auth value through a password session.
    let prewrite = NVWrite {
        data: tpm2::Tpm2bMaxNvBuffer::from_bytes(&[0x01, 0x02, 0x03, 0x04]).unwrap(),
        offset: 0,
    };
    let prewrite_handles = NVWriteHandles {
        auth_handle: NV_INDEX,
        nv_index: NV_INDEX,
    };
    execute_with_password_sessions(&mut sim, &prewrite, prewrite_handles, 1, b"p@ssw0rd")
        .expect("Calling TPM2_NV_Write");

    let read_pub = NVReadPublic {};
    let read_pub_handles = NVReadPublicHandles { nv_index: NV_INDEX };
    let (read_pub_rsp, _) =
        execute_with_password_sessions(&mut sim, &read_pub, read_pub_handles, 0, &[])
            .expect("Calling TPM2_NV_ReadPublic");
    println!("Name: {:x?}", read_pub_rsp.nv_name.get_buffer());

    // Write with owner authorization through a one-shot HMAC session, using
    // the (now NV_WRITTEN) name returned by the TPM.
    let write = NVWrite {
        data: tpm2::Tpm2bMaxNvBuffer::from_bytes(&[0x01, 0x02, 0x03, 0x04]).unwrap(),
        offset: 0,
    };
    let write_handles = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: NV_INDEX,
    };
    let mut sessions = [one_shot_hmac_session(&mut sim)];
    execute_with_hmac_sessions(
        &mut sim,
        &write,
        write_handles,
        &[
            &Handle::RH_OWNER.0.to_be_bytes(),
            read_pub_rsp.nv_name.get_buffer(),
        ],
        &mut sessions,
        &[&[]],
    )
    .expect("Calling TPM2_NV_Write");
}

// Original Go test: nv_test.go - TestNVAuthIncrement
#[test]
fn test_nv_auth_increment() {
    let mut sim = create_simulator!();

    // Define the counter space
    let mut attributes = TpmaNv::OWNERWRITE
        | TpmaNv::OWNERREAD
        | TpmaNv::AUTHWRITE
        | TpmaNv::AUTHREAD
        | TpmaNv::NO_DA;
    attributes.set_type(tpm2::TpmNt::Counter);

    let public_info_struct = TpmsNvPublic {
        nv_index: NV_INDEX,
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 8,
    };
    let public_info = tpm2::Tpm2b(public_info_struct);

    let define_space = NVDefineSpace {
        auth: Tpm2bAuth::from_bytes(b"p@ssw0rd").unwrap(),
        public_info,
    };
    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &define_space, define_handles, 1, &[])
        .expect("Calling TPM2_NV_DefineSpace");

    // Calculate the Name of the index as of its creation
    // (i.e., without NV_WRITTEN set).
    let initial_nv_name = nv_name(&public_info_struct);
    let owner_name = Handle::RH_OWNER.0.to_be_bytes();

    let incr = NVIncrement {};
    let incr_handles = NVIncrementHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: NV_INDEX,
    };
    let mut sessions = [one_shot_hmac_session(&mut sim)];
    execute_with_hmac_sessions(
        &mut sim,
        &incr,
        incr_handles,
        &[&owner_name, initial_nv_name.get_buffer()],
        &mut sessions,
        &[&[]],
    )
    .expect("Calling TPM2_NV_Increment");

    // The NV index's Name has changed. Ask the TPM for it.
    let read_pub = NVReadPublic {};
    let read_pub_handles = NVReadPublicHandles { nv_index: NV_INDEX };
    let (read_pub_rsp, _) =
        execute_with_password_sessions(&mut sim, &read_pub, read_pub_handles, 0, &[])
            .expect("Calling TPM2_NV_ReadPublic");
    let written_nv_name = read_pub_rsp.nv_name.get_buffer();

    let read = NVRead { size: 8, offset: 0 };
    let read_handles = NVReadHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: NV_INDEX,
    };
    let mut sessions = [one_shot_hmac_session(&mut sim)];
    let (read_rsp, _) = execute_with_hmac_sessions(
        &mut sim,
        &read,
        read_handles,
        &[&owner_name, written_nv_name],
        &mut sessions,
        &[&[]],
    )
    .expect("Calling TPM2_NV_Read");

    let mut sessions = [one_shot_hmac_session(&mut sim)];
    execute_with_hmac_sessions(
        &mut sim,
        &incr,
        incr_handles,
        &[&owner_name, written_nv_name],
        &mut sessions,
        &[&[]],
    )
    .expect("Calling TPM2_NV_Increment");

    let val1 = u64::from_be_bytes(
        read_rsp
            .data
            .get_buffer()
            .try_into()
            .expect("Parsing counter"),
    );

    let mut sessions = [one_shot_hmac_session(&mut sim)];
    let (read_rsp2, _) = execute_with_hmac_sessions(
        &mut sim,
        &read,
        read_handles,
        &[&owner_name, written_nv_name],
        &mut sessions,
        &[&[]],
    )
    .expect("Calling TPM2_NV_Read");

    let val2 = u64::from_be_bytes(
        read_rsp2
            .data
            .get_buffer()
            .try_into()
            .expect("Parsing counter"),
    );

    assert_eq!(val2, val1 + 1, "want {} got {}", val1 + 1, val2);
}

// Original Go test: nv_test.go - TestNVWriteLock
#[test]
fn test_nv_write_lock() {
    let mut sim = create_simulator!();

    // Define the NV space with attributes that allow it to be locked
    let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD | TpmaNv::WRITE_STCLEAR;
    attributes.set_type(tpm2::TpmNt::Ordinary);

    let public_info_struct = TpmsNvPublic {
        nv_index: NV_INDEX,
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 4,
    };
    let public_info = tpm2::Tpm2b(public_info_struct);

    let define_space = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &define_space, define_handles, 1, &[])
        .expect("Calling TPM2_NV_DefineSpace");

    // Write data to the NV space
    let write = NVWrite {
        data: tpm2::Tpm2bMaxNvBuffer::from_bytes(&[0x01, 0x02, 0x03, 0x04]).unwrap(),
        offset: 0,
    };
    let write_handles = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: NV_INDEX,
    };
    execute_with_password_sessions(&mut sim, &write, write_handles, 1, &[])
        .expect("Calling TPM2_NV_Write");

    // Lock the NV space against further writes
    let lock = NVWriteLock {};
    let lock_handles = NVWriteLockHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: NV_INDEX,
    };
    execute_with_password_sessions(&mut sim, &lock, lock_handles, 1, &[])
        .expect("Calling TPM2_NV_WriteLock");

    // Try to write to the NV space again, which should fail because it's locked
    let write2 = NVWrite {
        data: tpm2::Tpm2bMaxNvBuffer::from_bytes(&[0x05, 0x06, 0x07, 0x08]).unwrap(),
        offset: 0,
    };
    let err = execute_with_password_sessions(&mut sim, &write2, write_handles, 1, &[]).unwrap_err();
    assert_eq!(
        err,
        TpmRc::NV_LOCKED.get(),
        "TPM2_NV_Write succeeded after NV_WriteLock, expected it to fail"
    );

    // Verify we can still read the data
    let read = NVRead { size: 4, offset: 0 };
    let read_handles = NVReadHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: NV_INDEX,
    };
    let (read_rsp, _) = execute_with_password_sessions(&mut sim, &read, read_handles, 1, &[])
        .expect("Calling TPM2_NV_Read");

    // Verify the data is still the original data
    assert_eq!(read_rsp.data.get_buffer(), [0x01, 0x02, 0x03, 0x04]);
}

// Original Go test: nv_test.go - TestNVReadLock
#[test]
fn test_nv_read_lock() {
    let mut sim = create_simulator!();

    // Define the NV space with attributes that allow it to be locked for reading
    let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD | TpmaNv::READ_STCLEAR;
    attributes.set_type(tpm2::TpmNt::Ordinary);

    let public_info_struct = TpmsNvPublic {
        nv_index: NV_INDEX,
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 4,
    };
    let public_info = tpm2::Tpm2b(public_info_struct);

    let define_space = NVDefineSpace {
        auth: Tpm2bAuth::default(),
        public_info,
    };
    let define_handles = NVDefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
    };
    execute_with_password_sessions(&mut sim, &define_space, define_handles, 1, &[])
        .expect("Calling TPM2_NV_DefineSpace");

    // Write data to the NV space
    let write = NVWrite {
        data: tpm2::Tpm2bMaxNvBuffer::from_bytes(&[0x01, 0x02, 0x03, 0x04]).unwrap(),
        offset: 0,
    };
    let write_handles = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: NV_INDEX,
    };
    execute_with_password_sessions(&mut sim, &write, write_handles, 1, &[])
        .expect("Calling TPM2_NV_Write");

    // Read the data to verify it's accessible
    let read = NVRead { size: 4, offset: 0 };
    let read_handles = NVReadHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: NV_INDEX,
    };
    let (read_rsp, _) = execute_with_password_sessions(&mut sim, &read, read_handles, 1, &[])
        .expect("Calling TPM2_NV_Read before locking");

    // Verify the data is correct
    assert_eq!(read_rsp.data.get_buffer(), [0x01, 0x02, 0x03, 0x04]);

    // Lock the NV space against further reads
    let lock = NVReadLock {};
    let lock_handles = NVReadLockHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: NV_INDEX,
    };
    execute_with_password_sessions(&mut sim, &lock, lock_handles, 1, &[])
        .expect("Calling TPM2_NV_ReadLock");

    // Try to read from the NV space again, which should fail because it's locked
    let err = execute_with_password_sessions(&mut sim, &read, read_handles, 1, &[]).unwrap_err();
    assert_eq!(
        err,
        TpmRc::NV_LOCKED.get(),
        "TPM2_NV_Read succeeded after NV_ReadLock, expected it to fail"
    );
}
