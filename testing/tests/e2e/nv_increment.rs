//! TPM2_NV_Increment: counter semantics, starting value and authorization.

use crate::_common::{
    define_nv_with_policy_unwrap as define, exec_with_empty_passwords as pw,
    start_session_active as start_session, *,
};
use tpm2::commands::{NVDefineSpace, NVIncrement, NVRead, NVUndefineSpace};
use tpm2::errors::{Position, TpmRc};
use tpm2::*;
use tpm2_simulator::{Simulator, SimulatorPlatformSignal, create_simulator};

/// NV_Increment counts up from 0, and incrementing an ordinary index fails with TPM_RC_ATTRIBUTES.
#[test]
fn counter_increments_and_ordinary_rejected() {
    let mut sim = create_simulator!();

    // 1. Define Counter index
    let nv_counter = Handle(0x01000008);
    define_nv_space(
        &mut sim,
        Handle::RH_PLATFORM,
        nv_counter,
        platform_attrs(TpmNt::Counter, TpmaNv::empty()),
        8,
    )
    .expect("Failed to define Counter NV space");

    let increment = |sim: &mut Simulator<'_>, nv_index: Handle| {
        execute_with_password_sessions(
            sim,
            &NVIncrement {
                auth_handle: nv_index,
                nv_index,
            },
            1,
            &[],
        )
        .map(|_| ())
    };

    // 2. Call NV_Increment (first time, starts at 0, should become 1)
    increment(&mut sim, nv_counter).expect("Failed to increment counter");
    let val = u64::from_be_bytes(
        nv_read(&mut sim, nv_counter, 8, 0)
            .expect("Failed to read counter")
            .try_into()
            .unwrap(),
    );
    assert_eq!(val, 1);

    // 3. Call NV_Increment again (should become 2)
    increment(&mut sim, nv_counter).expect("Failed to increment counter again");
    let val2 = u64::from_be_bytes(
        nv_read(&mut sim, nv_counter, 8, 0)
            .expect("Failed to read counter again")
            .try_into()
            .unwrap(),
    );
    assert_eq!(val2, 2);

    // 4. Try to increment an Ordinary index (should fail with Attributes)
    let nv_ordinary = Handle(0x01000009);
    define_nv_space(
        &mut sim,
        Handle::RH_PLATFORM,
        nv_ordinary,
        platform_attrs(TpmNt::Ordinary, TpmaNv::empty()),
        16,
    )
    .expect("Failed to define Ordinary NV space");
    assert_eq!(
        increment(&mut sim, nv_ordinary).err(),
        Some(TpmRc::ATTRIBUTES.with(Position::handle(2)).get())
    );
}

/// A new counter starts from the largest value of a deleted counter (s_maxCounter), not of live counters
///
/// A new counter starts from the largest value of a *deleted* counter (C `s_maxCounter`), not
/// from the value of other live counters.
#[test]
fn new_counter_starts_above_deleted_max() {
    let mut sim = create_simulator!();
    let first = 0x0150_0a02;
    define(&mut sim, first, counter_attrs() | OWNER_RW, 8, &[]);
    let inc = |sim: &mut Simulator<'_>, index: u32| {
        pw(
            sim,
            &NVIncrement {
                auth_handle: Handle::RH_OWNER,
                nv_index: Handle(index),
            },
            1,
        )
        .unwrap();
    };
    for _ in 0..5 {
        inc(&mut sim, first);
    }
    let second = 0x0150_0a03;
    define(&mut sim, second, counter_attrs() | OWNER_RW, 8, &[]);
    inc(&mut sim, second);
    assert_eq!(
        read_as(&mut sim, Handle::RH_OWNER, second, 0, 8).unwrap(),
        1u64.to_be_bytes().to_vec()
    );

    // Deleting the first counter makes its value the floor for new counters.
    pw(
        &mut sim,
        &NVUndefineSpace {
            auth_handle: Handle::RH_OWNER,
            nv_index: Handle(first),
        },
        1,
    )
    .unwrap();
    let third = 0x0150_0a04;
    define(&mut sim, third, counter_attrs() | OWNER_RW, 8, &[]);
    inc(&mut sim, third);
    assert_eq!(
        read_as(&mut sim, Handle::RH_OWNER, third, 0, 8).unwrap(),
        6u64.to_be_bytes().to_vec()
    );
}

/// NV_Increment with platform auth on an owner-only counter is TPM_RC_NV_AUTHORIZATION (unpositioned)
#[test]
fn platform_auth_without_ppwrite_rejected() {
    let mut sim = create_simulator!();
    let index = 0x0150_0a00;
    define(&mut sim, index, counter_attrs() | OWNER_RW, 8, &[]);
    assert_eq!(
        pw(
            &mut sim,
            &NVIncrement {
                auth_handle: Handle::RH_PLATFORM,
                nv_index: Handle(index)
            },
            1
        )
        .unwrap_err(),
        TpmRc::NV_AUTHORIZATION.get()
    );
}

/// NV_Increment of a POLICYWRITE counter succeeds with a satisfied policy session
#[test]
fn policywrite_increment_with_policy_session() {
    let mut sim = create_simulator!();
    let index = 0x0150_0a01;
    define(
        &mut sim,
        index,
        counter_attrs() | TpmaNv::POLICYWRITE | TpmaNv::OWNERREAD,
        8,
        &EMPTY_POLICY,
    );
    let name = nv_index_name(&mut sim, index);
    let mut session = start_session(&mut sim, TpmSe::Policy);
    with_session(
        &mut sim,
        &NVIncrement {
            auth_handle: Handle(index),
            nv_index: Handle(index),
        },
        &[&name, &name],
        &mut session,
    )
    .expect("NV_Increment with a POLICYWRITE policy session failed");
    assert_eq!(
        read_as(&mut sim, Handle::RH_OWNER, index, 0, 8).unwrap(),
        1u64.to_be_bytes().to_vec()
    );
}

/// A recreated counter starts above the deleted counter's max, and this persists across power cycle
///
/// Like C `s_maxCounter`, the TPM remembers the largest value of a deleted
/// counter (persistently), and a newly defined counter starts above it.
#[test]
fn recreated_counter_never_rolls_back() {
    let mut sim = create_simulator!();

    let nv_index = Handle(0x01000010);
    let mut attrs = TpmaNv::from(TpmNt::Counter);
    attrs.insert(TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD);
    let define_cmd = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info: Tpm2b(TpmsNvPublic {
            nv_index,
            name_alg: TpmiAlgHash::Sha256,
            attributes: attrs,
            auth_policy: Tpm2bDigest::default(),
            data_size: 8,
        }),
    };
    let auths = [make_auth_session(&[])];
    let read_cmd = NVRead {
        auth_handle: Handle::RH_OWNER,
        nv_index,
        size: 8,
        offset: 0,
    };
    let read_counter = |sim: &mut Simulator<'_>| -> u64 {
        let resp = execute_tpm_command_with_auths(sim, &read_cmd, &auths).unwrap();
        u64::from_be_bytes(resp.data.get_buffer().try_into().unwrap())
    };

    // 1. Define counter index 0x01000010 and increment it 3 times (values: 1, 2, 3)
    execute_tpm_command_with_auths(&mut sim, &define_cmd, &auths).unwrap();
    for expected in 1..=3u64 {
        execute_tpm_command_with_auths(
            &mut sim,
            &NVIncrement {
                auth_handle: Handle::RH_OWNER,
                nv_index,
            },
            &auths,
        )
        .unwrap();
        assert_eq!(read_counter(&mut sim), expected);
    }

    // 2. Delete the counter index and recreate it
    execute_tpm_command_with_auths(
        &mut sim,
        &NVUndefineSpace {
            auth_handle: Handle::RH_OWNER,
            nv_index,
        },
        &auths,
    )
    .unwrap();
    execute_tpm_command_with_auths(&mut sim, &define_cmd, &auths).unwrap();

    // 3. First increment of the recreated counter must initialize to max_counter + 1 (4), not 1
    execute_tpm_command_with_auths(
        &mut sim,
        &NVIncrement {
            auth_handle: Handle::RH_OWNER,
            nv_index,
        },
        &auths,
    )
    .unwrap();
    assert_eq!(read_counter(&mut sim), 4);

    // 4. Delete again, cold reboot (power cycle + Startup(CLEAR)), and verify persistence
    execute_tpm_command_with_auths(
        &mut sim,
        &NVUndefineSpace {
            auth_handle: Handle::RH_OWNER,
            nv_index,
        },
        &auths,
    )
    .unwrap();
    sim.signal_platform(SimulatorPlatformSignal::PowerOff, NO_STREAM)
        .unwrap();
    power_on_start_up(&mut sim);

    execute_tpm_command_with_auths(&mut sim, &define_cmd, &auths).unwrap();
    execute_tpm_command_with_auths(
        &mut sim,
        &NVIncrement {
            auth_handle: Handle::RH_OWNER,
            nv_index,
        },
        &auths,
    )
    .unwrap();
    assert_eq!(
        read_counter(&mut sim),
        5,
        "Counter after cold reboot must continue from persisted max_counter + 1"
    );
}
