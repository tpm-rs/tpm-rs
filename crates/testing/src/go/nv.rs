use crate::test_utils::marshal_to_slice;
use tpm2::Alg;
use tpm2::errors::TpmRc;

// Ported from tpm-go/tpm2/test/nv_test.go

use crate::test_utils::*;
use tpm2::Handle;
use tpm2::commands::{
    NVDefineSpace, NVDefineSpaceHandles, NVIncrement, NVIncrementHandles, NVRead, NVReadHandles,
    NVReadLock, NVReadLockHandles, NVReadPublic, NVReadPublicHandles, NVWrite, NVWriteHandles,
    NVWriteLock, NVWriteLockHandles,
};
use tpm2::{Tpm2bAuth, Tpm2bDigest, Tpm2bName, TpmaNv, TpmiAlgHash, TpmsNvPublic};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

fn compute_nv_name(sim: &mut Simulator<'_>, public_info: &TpmsNvPublic) -> Tpm2bName<'static> {
    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(public_info, &mut pub_buf);

    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(
        sim.context.platform.crypto,
        TpmiAlgHash::Sha256,
        &pub_buf[..pub_len],
        &mut digest_buf,
    )
    .unwrap()
    .digest();
    let mut name_bytes = [0u8; 34];
    name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    name_bytes[2..34].copy_from_slice(digest);
    Tpm2bName::from_bytes(crate::test_utils::leak_bytes(&name_bytes)).unwrap()
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
        nv_index: Handle(0x0180000F),
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

    let prewrite = NVWrite {
        data: tpm2::Tpm2bMaxNvBuffer::from_bytes(&[0x01, 0x02, 0x03, 0x04]).unwrap(),
        offset: 0,
    };
    let prewrite_handles = NVWriteHandles {
        auth_handle: Handle(0x0180000F),
        nv_index: Handle(0x0180000F),
    };
    execute_with_password_sessions(&mut sim, &prewrite, prewrite_handles, 1, b"p@ssw0rd")
        .expect("Calling TPM2_NV_Write");

    let read_pub = NVReadPublic {};
    let read_pub_handles = NVReadPublicHandles {
        nv_index: Handle(0x0180000F),
    };
    let (read_pub_rsp, _) =
        execute_with_password_sessions(&mut sim, &read_pub, read_pub_handles, 0, &[])
            .expect("Calling TPM2_NV_ReadPublic");

    // The name in read_pub_rsp should now reflect the WRITTEN state because the NV index has been written to.
    let mut expected_written_struct = public_info_struct;
    expected_written_struct.attributes |= TpmaNv::WRITTEN;
    let expected_nv_name_written = compute_nv_name(&mut sim, &expected_written_struct);
    assert_eq!(
        read_pub_rsp.nv_name.get_buffer(),
        expected_nv_name_written.get_buffer()
    );

    let write = NVWrite {
        data: tpm2::Tpm2bMaxNvBuffer::from_bytes(&[0x01, 0x02, 0x03, 0x04]).unwrap(),
        offset: 0,
    };
    let write_handles = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(0x0180000F),
    };
    execute_with_password_sessions(&mut sim, &write, write_handles, 1, &[])
        .expect("Calling TPM2_NV_Write");
}

// Original Go test: nv_test.go - TestNVAuthIncrement
#[test]
fn test_nv_auth_increment() {
    let mut sim = create_simulator!();

    let mut attributes = TpmaNv::OWNERWRITE
        | TpmaNv::OWNERREAD
        | TpmaNv::AUTHWRITE
        | TpmaNv::AUTHREAD
        | TpmaNv::NO_DA;
    attributes.set_type(tpm2::TpmNt::Counter);

    let public_info_struct = TpmsNvPublic {
        nv_index: Handle(0x0180000F),
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

    let incr = NVIncrement {};
    let incr_handles = NVIncrementHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(0x0180000F),
    };
    execute_with_password_sessions(&mut sim, &incr, incr_handles, 1, &[])
        .expect("Calling TPM2_NV_Increment");

    let read = NVRead { size: 8, offset: 0 };
    let read_handles = NVReadHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(0x0180000F),
    };
    let (read_rsp, _) = execute_with_password_sessions(&mut sim, &read, read_handles, 1, &[])
        .expect("Calling TPM2_NV_Read");

    execute_with_password_sessions(&mut sim, &incr, incr_handles, 1, &[])
        .expect("Calling TPM2_NV_Increment");

    let val1 = u64::from_be_bytes(read_rsp.data.get_buffer()[..8].try_into().unwrap());

    let (read_rsp2, _) = execute_with_password_sessions(&mut sim, &read, read_handles, 1, &[])
        .expect("Calling TPM2_NV_Read");

    let val2 = u64::from_be_bytes(read_rsp2.data.get_buffer()[..8].try_into().unwrap());

    assert_eq!(val2, val1 + 1);
}

// Original Go test: nv_test.go - TestNVWriteLock
#[test]
fn test_nv_write_lock() {
    let mut sim = create_simulator!();

    let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD | TpmaNv::WRITE_STCLEAR;
    attributes.set_type(tpm2::TpmNt::Ordinary);

    let public_info_struct = TpmsNvPublic {
        nv_index: Handle(0x0180000F),
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

    let write = NVWrite {
        data: tpm2::Tpm2bMaxNvBuffer::from_bytes(&[0x01, 0x02, 0x03, 0x04]).unwrap(),
        offset: 0,
    };
    let write_handles = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(0x0180000F),
    };
    execute_with_password_sessions(&mut sim, &write, write_handles, 1, &[])
        .expect("Calling TPM2_NV_Write");

    let lock = NVWriteLock {};
    let lock_handles = NVWriteLockHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(0x0180000F),
    };
    execute_with_password_sessions(&mut sim, &lock, lock_handles, 1, &[])
        .expect("Calling TPM2_NV_WriteLock");

    let write2 = NVWrite {
        data: tpm2::Tpm2bMaxNvBuffer::from_bytes(&[0x05, 0x06, 0x07, 0x08]).unwrap(),
        offset: 0,
    };
    let err = execute_with_password_sessions(&mut sim, &write2, write_handles, 1, &[]).unwrap_err();
    assert_eq!(err, TpmRc::NV_LOCKED.get());

    let read = NVRead { size: 4, offset: 0 };
    let read_handles = NVReadHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(0x0180000F),
    };
    let (read_rsp, _) = execute_with_password_sessions(&mut sim, &read, read_handles, 1, &[])
        .expect("Calling TPM2_NV_Read");

    assert_eq!(read_rsp.data.get_buffer()[..4], [0x01, 0x02, 0x03, 0x04]);
}

// Original Go test: nv_test.go - TestNVReadLock
#[test]
fn test_nv_read_lock() {
    let mut sim = create_simulator!();

    let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD | TpmaNv::READ_STCLEAR;
    attributes.set_type(tpm2::TpmNt::Ordinary);

    let public_info_struct = TpmsNvPublic {
        nv_index: Handle(0x0180000F),
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

    let write = NVWrite {
        data: tpm2::Tpm2bMaxNvBuffer::from_bytes(&[0x01, 0x02, 0x03, 0x04]).unwrap(),
        offset: 0,
    };
    let write_handles = NVWriteHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(0x0180000F),
    };
    execute_with_password_sessions(&mut sim, &write, write_handles, 1, &[])
        .expect("Calling TPM2_NV_Write");

    let read = NVRead { size: 4, offset: 0 };
    let read_handles = NVReadHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(0x0180000F),
    };
    let (read_rsp, _) = execute_with_password_sessions(&mut sim, &read, read_handles, 1, &[])
        .expect("Calling TPM2_NV_Read");
    assert_eq!(read_rsp.data.get_buffer()[..4], [0x01, 0x02, 0x03, 0x04]);

    let lock = NVReadLock {};
    let lock_handles = NVReadLockHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(0x0180000F),
    };
    execute_with_password_sessions(&mut sim, &lock, lock_handles, 1, &[])
        .expect("Calling TPM2_NV_ReadLock");

    let err = execute_with_password_sessions(&mut sim, &read, read_handles, 1, &[]).unwrap_err();
    assert_eq!(err, TpmRc::NV_LOCKED.get());
}
