//! TPM2_NV_ReadLock, TPM2_NV_WriteLock and TPM2_NV_GlobalWriteLock.

use crate::_common::{define_nv_space as define, exec_with_empty_passwords as pw, *};
use tpm2::commands::*;
use tpm2::errors::{Position, TpmRc};
use tpm2::*;
use tpm2_simulator::{Simulator, SimulatorPlatformSignal, create_simulator};

/// NV_GlobalWriteLock with NV off is TPM_RC_NV_UNAVAILABLE and locks nothing; with NV on it locks GLOBALLOCK indexes
#[test]
fn nv_unavailable_does_not_lock() {
    let mut sim = create_simulator!();
    let index = 0x0150_0700;
    define_nv_with_policy_unwrap(&mut sim, index, OWNER_RW | TpmaNv::GLOBALLOCK, 8, &[]);
    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
    assert_eq!(
        pw(
            &mut sim,
            &NVGlobalWriteLock {
                auth_handle: Handle::RH_OWNER
            },
            1
        )
        .unwrap_err(),
        TpmRc::NV_UNAVAILABLE.get()
    );
    sim.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();
    // The index was not locked.
    owner_write(&mut sim, index, 0, &[1; 8]).unwrap();
    pw(
        &mut sim,
        &NVGlobalWriteLock {
            auth_handle: Handle::RH_OWNER,
        },
        1,
    )
    .unwrap();
    assert_eq!(
        owner_write(&mut sim, index, 0, &[2; 8]).unwrap_err(),
        TpmRc::NV_LOCKED.get()
    );
}

/// NV_ReadLock on a READ_STCLEAR index blocks reads with TPM_RC_NV_LOCKED.
#[test]
fn read_lock() {
    let mut sim = create_simulator!();

    // 1. Define Ordinary NV index with READ_STCLEAR attribute
    let nv_index = Handle(0x0100000c);
    define(
        &mut sim,
        Handle::RH_PLATFORM,
        nv_index,
        platform_attrs(TpmNt::Ordinary, TpmaNv::READ_STCLEAR),
        16,
    )
    .expect("Failed to define Ordinary NV space");

    // Write data initially
    nv_write(&mut sim, nv_index, &[1u8; 16]).expect("Failed to write data");

    // Read initially (should succeed)
    nv_read(&mut sim, nv_index, 16, 0).expect("Failed to read NV index initially");

    // 2. Call NV_ReadLock
    execute_with_password_sessions(
        &mut sim,
        &NVReadLock {
            auth_handle: nv_index,
            nv_index,
        },
        1,
        &[],
    )
    .expect("Failed to read lock NV index");

    // 3. Verify subsequent reads fail with NvLocked
    assert_eq!(
        nv_read(&mut sim, nv_index, 16, 0).err(),
        Some(TpmRc::NV_LOCKED.get())
    );
}

/// NV_WriteLock blocks writes with TPM_RC_NV_LOCKED; locking without WRITEDEFINE/WRITE_STCLEAR fails with ATTRIBUTES + H2.
#[test]
fn write_lock() {
    let mut sim = create_simulator!();

    // 1. Define Ordinary NV index with WRITEDEFINE attribute
    let nv_index = Handle(0x0100000a);
    define(
        &mut sim,
        Handle::RH_PLATFORM,
        nv_index,
        platform_attrs(TpmNt::Ordinary, TpmaNv::WRITEDEFINE),
        16,
    )
    .expect("Failed to define Ordinary NV space");

    // Write data initially
    nv_write(&mut sim, nv_index, &[1u8; 16]).expect("Failed to write data");

    let write_lock = |sim: &mut Simulator<'_>, nv_index: Handle| {
        execute_with_password_sessions(
            sim,
            &NVWriteLock {
                auth_handle: nv_index,
                nv_index,
            },
            1,
            &[],
        )
        .map(|_| ())
    };

    // 2. Call NV_WriteLock
    write_lock(&mut sim, nv_index).expect("Failed to write lock NV index");

    // 3. Verify subsequent writes fail with NvLocked
    assert_eq!(
        nv_write(&mut sim, nv_index, &[1u8; 16]).err(),
        Some(TpmRc::NV_LOCKED.get())
    );

    // 4. Verify locking an index without WRITEDEFINE or WRITE_STCLEAR fails with Attributes
    let nv_no_lock = Handle(0x0100000b);
    define(
        &mut sim,
        Handle::RH_PLATFORM,
        nv_no_lock,
        platform_attrs(TpmNt::Ordinary, TpmaNv::empty()),
        16,
    )
    .expect("Failed to define Ordinary NV space");
    // TPM_RC_ATTRIBUTES + RC_NV_WriteLock_nvIndex (H2).
    assert_eq!(
        write_lock(&mut sim, nv_no_lock).err(),
        Some(TpmRc::ATTRIBUTES.with(Position::handle(2)).get())
    );
}

/// NV_GlobalWriteLock with a wrong owner password is TPM_RC_BAD_AUTH + RC_S1; correct password succeeds
///
/// A wrong owner password is reported by session processing as `TPM_RC_BAD_AUTH + RC_S1`
/// (owner authorization is DA-exempt), not as an unpositioned handler `TPM_RC_AUTH_FAIL`.
#[test]
fn wrong_owner_password_is_bad_auth() {
    let mut sim = create_simulator!();
    let change = HierarchyChangeAuth {
        auth_handle: Handle::RH_OWNER,
        new_auth: Tpm2bAuth::from_bytes(b"abcd").unwrap(),
    };
    pw(&mut sim, &change, 1).unwrap();
    let rc = execute_with_password_sessions_status(
        &mut sim,
        &NVGlobalWriteLock {
            auth_handle: Handle::RH_OWNER,
        },
        1,
        b"ab",
    )
    .unwrap_err();
    assert_eq!(rc, TpmRc::BAD_AUTH.with(Position::session(1)).get());
    execute_with_password_sessions_status(
        &mut sim,
        &NVGlobalWriteLock {
            auth_handle: Handle::RH_OWNER,
        },
        1,
        b"abcd",
    )
    .expect("NV_GlobalWriteLock with the owner password failed");
}
