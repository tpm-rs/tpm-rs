//! TPM2_NV_Extend and TPM2_NV_SetBits on extend and bit-field indices.

use crate::_common::{define_nv_with_policy_unwrap as define, exec_with_empty_passwords as pw, *};
use testing::tpm::Tpm;
use tpm2::commands::*;
use tpm2::errors::{Position, TpmRc};
use tpm2::*;

/// NV_Extend of an extend index stores SHA256(zeros || data), verified with NV_Read
#[test]
fn extend_hashes_data_into_index() {
    let mut sim = Tpm::new();

    let auth_session = make_auth_session(&[]);

    // 1. Define Extend NV index with TPMA_NV_EXTEND | TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD, size=32 (SHA256 digest size)
    let nv_extend_idx = Handle(0x01000010);
    let mut attributes = TpmaNv::from(TpmNt::Extend);
    attributes.insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::PLATFORMCREATE);
    let public_info = Tpm2b(TpmsNvPublic {
        nv_index: nv_extend_idx,
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 32,
    });

    let define_cmd = NVDefineSpace {
        auth_handle: Handle::RH_PLATFORM,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_tpm_command_with_auths(&mut sim, &define_cmd, core::slice::from_ref(&auth_session))
        .expect("Failed to define Extend NV space");

    // 2. Call TPM2_NV_Extend with 32 bytes of input data
    let mut input_data = [0u8; 32];
    for (i, byte) in input_data.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(7);
    }

    let extend_cmd = NVExtend {
        auth_handle: nv_extend_idx,
        nv_index: nv_extend_idx,
        data: Tpm2bMaxNvBuffer::from_bytes(&input_data).unwrap(),
    };
    execute_tpm_command_with_auths(&mut sim, &extend_cmd, core::slice::from_ref(&auth_session))
        .expect("Failed to extend NV index");

    // 3. Verify using NV_Read that the stored index equals SHA256(zeros || input)
    let read_cmd = NVRead {
        auth_handle: nv_extend_idx,
        nv_index: nv_extend_idx,
        size: 32,
        offset: 0,
    };
    let read_resp =
        execute_tpm_command_with_auths(&mut sim, &read_cmd, core::slice::from_ref(&auth_session))
            .expect("Failed to read NV index after extend");

    // Compute expected SHA256(zeros || input)
    let mut expected_buf = [0u8; 64];
    expected_buf[32..64].copy_from_slice(&input_data);
    let expected_hash = sha256_bytes(&expected_buf[..]);

    assert_eq!(read_resp.data.get_buffer(), expected_hash.as_ref());
}

/// NV_Extend on an ordinary index is TPM_RC_ATTRIBUTES + RC_H2
#[test]
fn extend_on_ordinary_index_rejected() {
    let mut sim = Tpm::new();

    let auth_session = make_auth_session(&[]);

    // 1. Define Ordinary NV index without TPMA_NV_EXTEND (TpmNt::Ordinary)
    let nv_ord_idx = Handle(0x01000011);
    let mut attributes = TpmaNv::from(TpmNt::Ordinary);
    attributes.insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::PLATFORMCREATE);
    let public_info = Tpm2b(TpmsNvPublic {
        nv_index: nv_ord_idx,
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 32,
    });

    let define_cmd = NVDefineSpace {
        auth_handle: Handle::RH_PLATFORM,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_tpm_command_with_auths(&mut sim, &define_cmd, core::slice::from_ref(&auth_session))
        .expect("Failed to define Ordinary NV space");

    // 2. Call NV_Extend on the Ordinary index and verify it fails with TPM_RC_ATTRIBUTES
    let extend_cmd = NVExtend {
        auth_handle: nv_ord_idx,
        nv_index: nv_ord_idx,
        data: Tpm2bMaxNvBuffer::from_bytes(&[1u8; 32]).unwrap(),
    };
    let res =
        execute_tpm_command_with_auths(&mut sim, &extend_cmd, core::slice::from_ref(&auth_session));
    // TPM_RC_ATTRIBUTES + RC_NV_Extend_nvIndex (H2).
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::handle(2)).get())
    );
}

/// NV_SetBits ORs successive values into a bit-field index
#[test]
fn set_bits_ors_values() {
    let mut sim = Tpm::new();

    let auth_session = make_auth_session(&[]);

    // Define a 64-bit (8-byte) NV index with TPMA_NV_BITFIELD | TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD
    let nv_bits_idx = Handle(0x01000020);
    let mut attributes = TpmaNv::from(TpmNt::Bits);
    attributes.insert(TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE | TpmaNv::PLATFORMCREATE);
    let public_info = Tpm2b(TpmsNvPublic {
        nv_index: nv_bits_idx,
        name_alg: TpmiAlgHash::Sha256,
        attributes,
        auth_policy: Tpm2bDigest::default(),
        data_size: 8,
    });

    let define_cmd = NVDefineSpace {
        auth_handle: Handle::RH_PLATFORM,
        auth: Tpm2bAuth::default(),
        public_info,
    };
    execute_tpm_command_with_auths(&mut sim, &define_cmd, core::slice::from_ref(&auth_session))
        .expect("Failed to define Bits NV space");

    // Call NV_SetBits(0x0F0F)
    execute_tpm_command_with_auths(
        &mut sim,
        &NVSetBits {
            auth_handle: nv_bits_idx,
            nv_index: nv_bits_idx,
            bits: 0x0F0F,
        },
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed first NV_SetBits");

    // Verify value is 0x0F0F via NV_Read
    let read_cmd = NVRead {
        auth_handle: nv_bits_idx,
        nv_index: nv_bits_idx,
        size: 8,
        offset: 0,
    };
    let read_resp_1 =
        execute_tpm_command_with_auths(&mut sim, &read_cmd, core::slice::from_ref(&auth_session))
            .expect("Failed to read NV bits after first set");
    let val_1 = u64::from_be_bytes(read_resp_1.data.get_buffer().try_into().unwrap());
    assert_eq!(val_1, 0x0F0F);

    // Call NV_SetBits(0xF0F0)
    execute_tpm_command_with_auths(
        &mut sim,
        &NVSetBits {
            auth_handle: nv_bits_idx,
            nv_index: nv_bits_idx,
            bits: 0xF0F0,
        },
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed second NV_SetBits");

    // Verify value becomes 0xFFFF
    let read_resp_2 =
        execute_tpm_command_with_auths(&mut sim, &read_cmd, core::slice::from_ref(&auth_session))
            .expect("Failed to read NV bits after second set");
    let val_2 = u64::from_be_bytes(read_resp_2.data.get_buffer().try_into().unwrap());
    assert_eq!(val_2, 0xFFFF);
}

/// NV_Extend/NV_SetBits check WRITELOCKED before the index type; type errors carry the nvIndex handle position
///
/// `NvWriteAccessChecks` (WRITELOCKED) runs before the index-type check in NV_Extend and
/// NV_SetBits, and type/attribute errors carry the nvIndex handle position.
#[test]
fn write_lock_checked_before_index_type() {
    let mut sim = Tpm::new();
    let ordinary = 0x0150_0420;
    define(&mut sim, ordinary, OWNER_RW | TpmaNv::WRITEDEFINE, 8, &[]);
    pw(
        &mut sim,
        &NVWriteLock {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(ordinary),
        },
        1,
    )
    .unwrap();

    let cmd = NVExtend {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(ordinary),
        data: Tpm2bMaxNvBuffer::from_bytes(&[1]).unwrap(),
    };
    assert_eq!(pw(&mut sim, &cmd, 1).unwrap_err(), TpmRc::NV_LOCKED.get());
    assert_eq!(
        pw(
            &mut sim,
            &NVSetBits {
                auth_handle: Handle::RH_OWNER,
                nv_index: Handle(ordinary),
                bits: 1
            },
            1
        )
        .unwrap_err(),
        TpmRc::NV_LOCKED.get()
    );

    // Unlocked ordinary index: the type error is ATTRIBUTES + RC_H2.
    let other = 0x0150_0421;
    define(&mut sim, other, OWNER_RW, 8, &[]);
    assert_eq!(
        pw(
            &mut sim,
            &NVExtend {
                nv_index: Handle(other),
                ..cmd
            },
            1
        )
        .unwrap_err(),
        TpmRc::ATTRIBUTES.with(Position::handle(2)).get()
    );
    assert_eq!(
        pw(
            &mut sim,
            &NVSetBits {
                auth_handle: Handle::RH_OWNER,
                nv_index: Handle(other),
                bits: 1
            },
            1
        )
        .unwrap_err(),
        TpmRc::ATTRIBUTES.with(Position::handle(2)).get()
    );
    // No WRITEDEFINE/WRITE_STCLEAR or READ_STCLEAR.
    assert_eq!(
        pw(
            &mut sim,
            &NVWriteLock {
                auth_handle: Handle::RH_OWNER,
                nv_index: Handle(other)
            },
            1
        )
        .unwrap_err(),
        TpmRc::ATTRIBUTES.with(Position::handle(2)).get()
    );
    assert_eq!(
        pw(
            &mut sim,
            &NVReadLock {
                auth_handle: Handle::RH_OWNER,
                nv_index: Handle(other)
            },
            1
        )
        .unwrap_err(),
        TpmRc::ATTRIBUTES.with(Position::handle(2)).get()
    );
}

/// NV_Extend/NV_SetBits on a locked index report TPM_RC_NV_LOCKED before the OWNERWRITE authorization check
#[test]
fn write_lock_precedes_owner_write_check() {
    let mut sim = Tpm::new();
    let auth_session = make_auth_session(&[]);

    // 1. Test NV_Extend error precedence
    let nv_idx_ext = Handle(0x01000051);
    let mut attr_ext = TpmaNv::from(TpmNt::Extend);
    attr_ext.insert(
        TpmaNv::AUTHWRITE | TpmaNv::AUTHREAD | TpmaNv::WRITEDEFINE | TpmaNv::PLATFORMCREATE,
    );
    let define_cmd_ext = NVDefineSpace {
        auth_handle: Handle::RH_PLATFORM,
        auth: Tpm2bAuth::default(),
        public_info: Tpm2b(TpmsNvPublic {
            nv_index: nv_idx_ext,
            name_alg: TpmiAlgHash::Sha256,
            attributes: attr_ext,
            auth_policy: Tpm2bDigest::default(),
            data_size: 32,
        }),
    };
    execute_tpm_command_with_auths(
        &mut sim,
        &define_cmd_ext,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define extend NV index");

    execute_tpm_command_with_auths(
        &mut sim,
        &NVWriteLock {
            auth_handle: nv_idx_ext,
            nv_index: nv_idx_ext,
        },
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to lock extend NV index");

    // Call NV_Extend using RHOwner (where OWNERWRITE = 0) on locked index
    let ext_cmd = NVExtend {
        auth_handle: Handle::RH_OWNER,
        nv_index: nv_idx_ext,
        data: Tpm2bMaxNvBuffer::from_bytes(&[0xaa; 32]).unwrap(),
    };
    let res_ext =
        execute_tpm_command_with_auths(&mut sim, &ext_cmd, core::slice::from_ref(&auth_session));
    // C `NvWriteAccessChecks` reports WRITELOCKED before the OWNERWRITE check.
    assert_eq!(res_ext.unwrap_err() & 0xfff, TpmRc::NV_LOCKED.get());

    // 2. Test NV_SetBits error precedence
    let nv_idx_bits = Handle(0x01000052);
    let mut attr_bits = TpmaNv::from(TpmNt::Bits);
    attr_bits.insert(
        TpmaNv::AUTHWRITE | TpmaNv::AUTHREAD | TpmaNv::WRITEDEFINE | TpmaNv::PLATFORMCREATE,
    );
    let define_cmd_bits = NVDefineSpace {
        auth_handle: Handle::RH_PLATFORM,
        auth: Tpm2bAuth::default(),
        public_info: Tpm2b(TpmsNvPublic {
            nv_index: nv_idx_bits,
            name_alg: TpmiAlgHash::Sha256,
            attributes: attr_bits,
            auth_policy: Tpm2bDigest::default(),
            data_size: 8,
        }),
    };
    execute_tpm_command_with_auths(
        &mut sim,
        &define_cmd_bits,
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to define bits NV index");

    execute_tpm_command_with_auths(
        &mut sim,
        &NVWriteLock {
            auth_handle: nv_idx_bits,
            nv_index: nv_idx_bits,
        },
        core::slice::from_ref(&auth_session),
    )
    .expect("Failed to lock bits NV index");

    // Call NV_SetBits using RHOwner (where OWNERWRITE = 0) on locked index
    let res_bits = execute_tpm_command_with_auths(
        &mut sim,
        &NVSetBits {
            auth_handle: Handle::RH_OWNER,
            nv_index: nv_idx_bits,
            bits: 0x01,
        },
        core::slice::from_ref(&auth_session),
    );
    // C `NvWriteAccessChecks` reports WRITELOCKED before the OWNERWRITE check.
    assert_eq!(res_bits.unwrap_err() & 0xfff, TpmRc::NV_LOCKED.get());
}
