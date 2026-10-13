//! TPM2_NV_Read / TPM2_NV_Write: access checks, offsets/sizes, partial writes and index types.

use crate::_common::{define_nv_space as define, exec_with_empty_passwords as pw, *};
use tpm2::commands::{NVDefineSpace, NVUndefineSpace, NVWrite, NVWriteLock};
use tpm2::errors::{Position, TpmRc};
use tpm2::*;
use tpm2_simulator::create_simulator;

/// NV_Read/NV_Write access checks precede size/offset checks; offset past end is TPM_RC_VALUE + RC_P2
///
/// Access checks come before the size/offset checks, and an offset past the end of the index
/// is `TPM_RC_VALUE + RC_P2`.
#[test]
fn access_checked_before_range() {
    let mut sim = create_simulator!();
    let index = 0x0150_0502;
    define_nv_with_policy_unwrap(&mut sim, index, OWNER_RW | TpmaNv::WRITEDEFINE, 16, &[]);

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
    let cmd = NVWrite {
        auth_handle: Handle::RH_PLATFORM,
        nv_index: Handle(index),
        data: Tpm2bMaxNvBuffer::from_bytes(&[1; 32]).unwrap(),
        offset: 0,
    };
    assert_eq!(
        pw(&mut sim, &cmd, 1).unwrap_err(),
        TpmRc::NV_AUTHORIZATION.get()
    );
}

// 1. Validate that writing to Counter/Bits/Extend indexes fails with TPM_RC_ATTRIBUTES.
/// NV_Write to counter, bits and extend indexes fails with TPM_RC_ATTRIBUTES.
#[test]
fn counter_bits_extend_index_rejected() {
    let mut sim = create_simulator!();

    // A. Define Counter index (NT=0x1, data_size=8)
    let nv_index_counter = Handle(0x01000001);
    define(
        &mut sim,
        Handle::RH_PLATFORM,
        nv_index_counter,
        platform_attrs(TpmNt::Counter, TpmaNv::empty()),
        8,
    )
    .expect("Failed to define Counter NV space");
    // Write to Counter index (should fail with TPM_RC_ATTRIBUTES)
    assert_eq!(
        nv_write(&mut sim, nv_index_counter, &[1, 2, 3, 4, 5, 6, 7, 8]).err(),
        Some(TpmRc::ATTRIBUTES.get())
    );

    // B. Define Bits index (NT=0x2, data_size=8)
    let nv_index_bits = Handle(0x01000002);
    define(
        &mut sim,
        Handle::RH_PLATFORM,
        nv_index_bits,
        platform_attrs(TpmNt::Bits, TpmaNv::empty()),
        8,
    )
    .expect("Failed to define Bits NV space");
    // Write to Bits index (should fail with TPM_RC_ATTRIBUTES)
    assert_eq!(
        nv_write(&mut sim, nv_index_bits, &[1, 2, 3, 4, 5, 6, 7, 8]).err(),
        Some(TpmRc::ATTRIBUTES.get())
    );

    // C. Define Extend index (NT=0x4, data_size=32)
    let nv_index_extend = Handle(0x01000003);
    define(
        &mut sim,
        Handle::RH_PLATFORM,
        nv_index_extend,
        platform_attrs(TpmNt::Extend, TpmaNv::empty()),
        32,
    )
    .expect("Failed to define Extend NV space");
    // Write to Extend index (should fail with TPM_RC_ATTRIBUTES)
    assert_eq!(
        nv_write(&mut sim, nv_index_extend, &[0u8; 32]).err(),
        Some(TpmRc::ATTRIBUTES.get())
    );
}

/// The first partial write of an ordinary index clears the rest of the index (even when reusing deleted storage)
///
/// The first partial write of an ordinary index clears the rest of the index.
#[test]
fn first_partial_write_clears_rest() {
    let mut sim = create_simulator!();
    let index = 0x0150_0501;
    define_nv_with_policy_unwrap(&mut sim, index, OWNER_RW, 64, &[]);
    owner_write(&mut sim, index, 0, &[0xAA; 64]).unwrap();
    pw(
        &mut sim,
        &NVUndefineSpace {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(index),
        },
        1,
    )
    .unwrap();

    // The new index reuses the storage of the deleted one.
    define_nv_with_policy_unwrap(&mut sim, index, OWNER_RW, 64, &[]);
    owner_write(&mut sim, index, 0, &[0x01]).unwrap();
    let data = read_as(&mut sim, Handle::RH_OWNER, index, 0, 64).unwrap();
    let mut expected = vec![0u8; 64];
    expected[0] = 0x01;
    assert_eq!(data, expected);
}

/// NV_Write on counter, bits and extend indexes fails with TPM_RC_ATTRIBUTES
#[test]
fn non_ordinary_index_types_rejected() {
    let mut sim = create_simulator!();

    // Test Counter index
    {
        let nv_index_val = 0x01500051;
        let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD;
        attributes.set_type(tpm2::TpmNt::Counter);
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(nv_index_val),
            name_alg: TpmiAlgHash::Sha256,
            attributes,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 8,
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();

        let write_cmd = NVWrite {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(nv_index_val),
            data: Tpm2bMaxNvBuffer::from_bytes(&[0x11; 8]).unwrap(),
            offset: 0,
        };
        let err = execute_with_password_sessions(&mut sim, &write_cmd, 1, &[]).unwrap_err();
        assert_eq!(err, TpmRc::ATTRIBUTES.get());
    }

    // Test Bits index
    {
        let nv_index_val = 0x01500052;
        let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD;
        attributes.set_type(tpm2::TpmNt::Bits);
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(nv_index_val),
            name_alg: TpmiAlgHash::Sha256,
            attributes,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 8,
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();

        let write_cmd = NVWrite {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(nv_index_val),
            data: Tpm2bMaxNvBuffer::from_bytes(&[0x11; 8]).unwrap(),
            offset: 0,
        };
        let err = execute_with_password_sessions(&mut sim, &write_cmd, 1, &[]).unwrap_err();
        assert_eq!(err, TpmRc::ATTRIBUTES.get());
    }

    // Test Extend index
    {
        let nv_index_val = 0x01500053;
        let mut attributes = TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD;
        attributes.set_type(tpm2::TpmNt::Extend);
        let nv_public_struct = TpmsNvPublic {
            nv_index: tpm2::Handle(nv_index_val),
            name_alg: TpmiAlgHash::Sha256,
            attributes,
            auth_policy: tpm2::Tpm2bDigest::default(),
            data_size: 32,
        };
        let cmd = NVDefineSpace {
            auth_handle: Handle::RH_OWNER,
            auth: Tpm2bAuth::default(),
            public_info: tpm2::Tpm2b(nv_public_struct),
        };
        execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();

        let write_cmd = NVWrite {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(nv_index_val),
            data: Tpm2bMaxNvBuffer::from_bytes(&[0x11; 32]).unwrap(),
            offset: 0,
        };
        let err = execute_with_password_sessions(&mut sim, &write_cmd, 1, &[]).unwrap_err();
        assert_eq!(err, TpmRc::ATTRIBUTES.get());
    }
}

/// NV_Write with offset+size wrapping u16 or offset > dataSize is rejected (no overflow)
#[test]
fn offset_overflow_rejected() {
    let mut sim = create_simulator!();
    let nv_index_val = 0x01500002;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let cmd = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();

    // 4. Wrapping overflow write: offset = 65530, size = 10 -> offset + size = 65540 -> wraps to 4.
    let write_cmd_overflow = NVWrite {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xDD; 10]).unwrap(),
        offset: 65530,
    };

    // This is expected to return TpmRc::SIZE. Instead, it currently panics (in debug) or wraps (in release).
    let res = execute_with_password_sessions(&mut sim, &write_cmd_overflow, 1, &[]);
    match res {
        // offset > dataSize: TPM_RC_VALUE + RC_NV_Write_offset (C `TPM2_NV_Write`).
        Err(err) => assert_eq!(
            err,
            TpmRc::VALUE
                .with(tpm2::errors::Position::parameter(2))
                .get()
        ),
        Ok(_) => panic!(
            "SECURITY BUG: nv_write overflow allowed writing to out-of-bounds offset (underflow/metadata overwrite)!"
        ),
    }
}

/// NV_Write at the end boundary succeeds; one byte past it is TPM_RC_NV_RANGE
#[test]
fn offset_plus_size_boundaries() {
    let mut sim = create_simulator!();
    let nv_index_val = 0x01500001;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let cmd = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();

    // 1. Normal write (offset = 0, size = 10)
    let write_cmd = NVWrite {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 10]).unwrap(),
        offset: 0,
    };
    execute_with_password_sessions(&mut sim, &write_cmd, 1, &[]).unwrap();

    // 2. Normal write at boundary (offset = 54, size = 10)
    let write_cmd_boundary = NVWrite {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xBB; 10]).unwrap(),
        offset: 54,
    };
    execute_with_password_sessions(&mut sim, &write_cmd_boundary, 1, &[]).unwrap();

    // 3. Out of bounds write (offset = 55, size = 10)
    let write_cmd_oob = NVWrite {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xCC; 10]).unwrap(),
        offset: 55,
    };
    let res = execute_with_password_sessions(&mut sim, &write_cmd_oob, 1, &[]);
    match res {
        Err(err) => assert_eq!(err, TpmRc::NV_RANGE.get()),
        Ok(_) => panic!("Expected Size error, but command succeeded"),
    }
}

// 2. Validate that writing partial sizes to a WRITEALL NV index fails with TPM_RC_NV_RANGE.
/// A partial write to a WRITEALL index fails with TPM_RC_NV_RANGE; a full write succeeds.
#[test]
fn partial_write_to_writeall_rejected() {
    let mut sim = create_simulator!();

    let nv_index = Handle(0x01000004);
    define(
        &mut sim,
        Handle::RH_PLATFORM,
        nv_index,
        platform_attrs(TpmNt::Ordinary, TpmaNv::WRITEALL),
        32,
    )
    .expect("Failed to define WRITEALL Ordinary NV space");

    // Write partial size (16 bytes instead of 32 bytes)
    assert_eq!(
        nv_write(&mut sim, nv_index, &[1u8; 16]).err(),
        Some(TpmRc::NV_RANGE.get())
    );

    // Write complete size (32 bytes) should succeed
    nv_write(&mut sim, nv_index, &[1u8; 32]).expect("Failed to write full size to WRITEALL index");
}

/// NV_Read: unwritten -> NV_UNINITIALIZED, written data reads back, out-of-bounds -> NV_RANGE.
#[test]
fn uninitialized_range_and_success() {
    let mut sim = create_simulator!();

    // 1. Define Ordinary NV index
    let nv_index = Handle(0x01000007);
    define(
        &mut sim,
        Handle::RH_PLATFORM,
        nv_index,
        platform_attrs(TpmNt::Ordinary, TpmaNv::empty()),
        16,
    )
    .expect("Failed to define Ordinary NV space");

    // 2. Try to read unwritten index (should fail with NvUninitialized)
    assert_eq!(
        nv_read(&mut sim, nv_index, 16, 0).err(),
        Some(TpmRc::NV_UNINITIALIZED.get())
    );

    // 3. Write data
    let write_data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    nv_write(&mut sim, nv_index, &write_data).expect("Failed to write data");

    // 4. Read data and verify
    let data = nv_read(&mut sim, nv_index, 16, 0).expect("Failed to read NV index");
    assert_eq!(data, write_data);

    // 5. Try reading out of bounds (should fail with NvRange)
    assert_eq!(
        nv_read(&mut sim, nv_index, 8, 10).err(),
        Some(TpmRc::NV_RANGE.get())
    );
}

/// After NV_WriteLock of a WRITE_STCLEAR index, NV_Write fails with TPM_RC_NV_LOCKED
#[test]
fn write_after_write_lock_rejected() {
    let mut sim = create_simulator!();
    let nv_index_val = 0x01500030;
    // WRITE_STCLEAR allows the index to be write-locked with TPM2_NV_WriteLock.
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD | TpmaNv::WRITE_STCLEAR,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 64,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let cmd = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();

    // Normal write -> success
    let write_cmd = NVWrite {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 10]).unwrap(),
        offset: 0,
    };
    execute_with_password_sessions(&mut sim, &write_cmd, 1, &[]).unwrap();

    // Set TPMA_NV_WRITELOCKED through the TPM interface.
    execute_with_password_sessions(
        &mut sim,
        &NVWriteLock {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(nv_index_val),
        },
        1,
        &[],
    )
    .unwrap();

    // Try writing again -> should fail with NvLocked (0x14F)
    let res = execute_with_password_sessions(&mut sim, &write_cmd, 1, &[]);
    match res {
        Err(err) => assert_eq!(err, TpmRc::NV_LOCKED.get()),
        Ok(_) => panic!("Expected NvLocked error, but write succeeded on WRITELOCKED index"),
    }
}

/// NV_Write on a write-locked index reports TPM_RC_NV_LOCKED before range errors
#[test]
fn write_lock_precedes_range_error() {
    let mut sim = create_simulator!();
    let auth_session = make_auth_session(&[]);

    let nv_idx = Handle(0x01000050);
    let define_cmd = NVDefineSpace {
        auth_handle: Handle::RH_PLATFORM,
        auth: Tpm2bAuth::default(),
        public_info: Tpm2b(TpmsNvPublic {
            nv_index: nv_idx,
            name_alg: TpmiAlgHash::Sha256,
            attributes: TpmaNv::AUTHWRITE
                | TpmaNv::AUTHREAD
                | TpmaNv::WRITEDEFINE
                | TpmaNv::PLATFORMCREATE,
            auth_policy: Tpm2bDigest::default(),
            data_size: 16,
        }),
    };
    execute_tpm_command_with_auths(&mut sim, &define_cmd, core::slice::from_ref(&auth_session))
        .expect("Failed to define NV index");

    // Lock index with NV_WriteLock
    execute_tpm_command_with_auths(
        &mut sim,
        &NVWriteLock {
            auth_handle: nv_idx,
            nv_index: nv_idx,
        },
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to lock NV index");

    // Attempt NV_Write with offset + size > 16 on write-locked index
    let write_cmd = NVWrite {
        auth_handle: nv_idx,
        nv_index: nv_idx,
        data: Tpm2bMaxNvBuffer::from_bytes(&[0x11; 10]).unwrap(),
        offset: 10,
    };
    let res =
        execute_tpm_command_with_auths(&mut sim, &write_cmd, core::slice::from_ref(&auth_session));

    // WRITELOCKED must take precedence over range errors per compliance test CPCTPM_TC2_3_33_07_10
    assert_eq!(res.unwrap_err() & 0xfff, TpmRc::NV_LOCKED.get());
}

/// NV_Write on a WRITEALL index requires writing the whole index (partial is TPM_RC_NV_RANGE)
#[test]
fn writeall_requires_full_write() {
    let mut sim = create_simulator!();
    let nv_index_val = 0x01500054;
    let nv_public_struct = TpmsNvPublic {
        nv_index: tpm2::Handle(nv_index_val),
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD | TpmaNv::WRITEALL,
        auth_policy: tpm2::Tpm2bDigest::default(),
        data_size: 16,
    };
    let public_info = tpm2::Tpm2b(nv_public_struct);
    let cmd = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_with_password_sessions(&mut sim, &cmd, 1, &[]).unwrap();

    // 1. Partial write (size = 8 != 16) -> must fail with NvRange (0x146)
    let write_cmd_partial = NVWrite {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 8]).unwrap(),
        offset: 0,
    };
    let err = execute_with_password_sessions(&mut sim, &write_cmd_partial, 1, &[]).unwrap_err();
    assert_eq!(err, TpmRc::NV_RANGE.get());

    // 2. Full write (size = 16) -> success
    let write_cmd_full = NVWrite {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(nv_index_val),
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xAA; 16]).unwrap(),
        offset: 0,
    };
    execute_with_password_sessions(&mut sim, &write_cmd_full, 1, &[]).unwrap();
}
