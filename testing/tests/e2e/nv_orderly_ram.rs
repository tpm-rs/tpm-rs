//! Orderly NV Indices (`TPMA_NV_ORDERLY`): the references keep their data and attributes in the
//! orderly-Index RAM and save it to its NV copy only when an orderly Index is defined or deleted,
//! an orderly counter is written for the first time or rolls over its low `ORDERLY_BITS`, and at
//! `TPM2_Shutdown` (`NvUpdateIndexOrderlyData()`); every `TPM2_Startup` reloads the RAM from the
//! NV copy, and a startup after a power loss without `TPM2_Shutdown` sets the low bits of every
//! orderly counter (`NvEntityStartup()`). TPM 2.0 Part 1, "NV Index Orderly Attribute" and
//! "NV Counters": an orderly counter "may not be updated in NV until the TPM receives
//! TPM2_Shutdown()", and after a non-orderly shutdown it is advanced so that it never repeats a
//! reported value.

use crate::_common::*;
use testing::tpm::Tpm;
use tpm2::commands::NVIncrement;
use tpm2::*;

const COUNTER: u32 = 0x0150_0601;
const TPM_SU_CLEAR: u16 = 0x0000;
const TPM_SU_STATE: u16 = 0x0001;
/// `MAX_ORDERLY_COUNT`: the low `ORDERLY_BITS` (8) of an orderly counter.
const MAX_ORDERLY_COUNT: u64 = 0xFF;

/// Defines the owner-authorized orderly counter [`COUNTER`].
fn define_orderly_counter(sim: &mut Tpm) {
    define_nv_with_policy_unwrap(
        sim,
        COUNTER,
        TpmaNv::from(TpmNt::Counter) | OWNER_RW | TpmaNv::ORDERLY,
        8,
        &[],
    );
}

/// `TPM2_NV_Increment` of [`COUNTER`] with the owner authorization.
fn increment(sim: &mut Tpm) {
    let cmd = NVIncrement {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(COUNTER),
    };
    exec_with_empty_passwords(sim, &cmd, 1).expect("NV_Increment");
}

/// The value of [`COUNTER`].
fn counter(sim: &mut Tpm) -> u64 {
    let data = read_as(sim, Handle::RH_OWNER, COUNTER, 0, 8).expect("NV_Read");
    u64::from_be_bytes(data.try_into().unwrap())
}

/// Power-cycles the TPM without `TPM2_Shutdown` (`shutdown` `None`) or after
/// `TPM2_Shutdown(shutdown)`, then starts it with `TPM2_Startup(startup)`.
fn cycle(sim: &mut Tpm, shutdown: Option<u16>, startup: u16) {
    assert_eq!(power_cycle_with(sim, shutdown, startup), 0, "TPM2_Startup");
}

/// After a power loss without `TPM2_Shutdown`, an orderly counter restarts from the value of its
/// last save with the low bits set: the first increment (which sets `TPMA_NV_WRITTEN`) and every
/// rollover of the low bits save it.
#[test]
fn orderly_counter_skips_ahead_from_last_save_after_power_loss() {
    let mut sim = Tpm::new();
    define_orderly_counter(&mut sim);
    for _ in 0..3 {
        increment(&mut sim);
    }
    assert_eq!(counter(&mut sim), 3);
    // Saved at 1 (the first write).
    cycle(&mut sim, None, TPM_SU_CLEAR);
    assert_eq!(counter(&mut sim), 1 | MAX_ORDERLY_COUNT);
    // The next increment rolls the low bits over (saved at 0x100); two more are not saved.
    for _ in 0..3 {
        increment(&mut sim);
    }
    assert_eq!(counter(&mut sim), 0x102);
    cycle(&mut sim, None, TPM_SU_CLEAR);
    assert_eq!(counter(&mut sim), 0x100 | MAX_ORDERLY_COUNT);
}

/// `TPM2_Shutdown` of either type saves the orderly counters: an orderly power cycle (TPM Reset,
/// Restart or Resume) keeps their value exactly.
#[test]
fn orderly_counter_is_saved_by_shutdown() {
    let mut sim = Tpm::new();
    define_orderly_counter(&mut sim);
    for _ in 0..5 {
        increment(&mut sim);
    }
    cycle(&mut sim, Some(TPM_SU_CLEAR), TPM_SU_CLEAR);
    assert_eq!(counter(&mut sim), 5);
    increment(&mut sim);
    cycle(&mut sim, Some(TPM_SU_STATE), TPM_SU_STATE);
    assert_eq!(counter(&mut sim), 6);
    increment(&mut sim);
    cycle(&mut sim, Some(TPM_SU_STATE), TPM_SU_CLEAR);
    assert_eq!(counter(&mut sim), 7);
}

/// Increments after `TPM2_Shutdown` are not saved: a power loss before the next shutdown
/// reverts them to the value saved by the shutdown, with the low bits set.
#[test]
fn increments_after_shutdown_revert_on_power_loss() {
    let mut sim = Tpm::new();
    define_orderly_counter(&mut sim);
    for _ in 0..4 {
        increment(&mut sim);
    }
    assert_eq!(shutdown_raw(&mut sim, TPM_SU_CLEAR), 0);
    increment(&mut sim);
    assert_eq!(counter(&mut sim), 5);
    cycle(&mut sim, None, TPM_SU_CLEAR);
    assert_eq!(counter(&mut sim), 4 | MAX_ORDERLY_COUNT);
}

/// The data of an orderly ordinary Index written before `TPM2_Shutdown(TPM_SU_STATE)` survives a
/// TPM Restart; a TPM Reset clears its `TPMA_NV_WRITTEN` (`NvSetStartupAttributes()`).
#[test]
fn orderly_index_data_is_saved_by_shutdown_state() {
    let mut sim = Tpm::new();
    let index = 0x0150_0602;
    define_nv_with_policy_unwrap(&mut sim, index, OWNER_RW | TpmaNv::ORDERLY, 8, &[]);
    owner_write(&mut sim, index, 0, &[0xA5; 8]).unwrap();
    cycle(&mut sim, Some(TPM_SU_STATE), TPM_SU_CLEAR);
    assert_eq!(
        read_as(&mut sim, Handle::RH_OWNER, index, 0, 8).unwrap(),
        [0xA5; 8]
    );
    owner_write(&mut sim, index, 0, &[0x5A; 4]).unwrap();
    cycle(&mut sim, None, TPM_SU_CLEAR);
    assert_eq!(
        read_as(&mut sim, Handle::RH_OWNER, index, 0, 8),
        Err(tpm2::errors::TpmRc::NV_UNINITIALIZED.get())
    );
}

/// A platform-created orderly counter with `TPMA_NV_WRITEDEFINE`, authorized by its own (empty)
/// authValue, whose `TPMA_NV_WRITELOCKED` (set by `TPM2_NV_WriteLock` in the orderly-Index RAM
/// only) survives a startup exactly when the NV copy was saved after the lock
/// (`NvSetStartupAttributes()` keeps it for a written `TPMA_NV_WRITEDEFINE` Index).
const LOCKED_COUNTER: u32 = 0x0150_0610;

/// Defines [`LOCKED_COUNTER`], increments it (its first write saves the NV copy) and write-locks
/// it.
fn define_and_lock_counter(sim: &mut Tpm) {
    define_nv_space(
        sim,
        Handle::RH_PLATFORM,
        Handle(LOCKED_COUNTER),
        platform_attrs(TpmNt::Counter, TpmaNv::ORDERLY | TpmaNv::WRITEDEFINE),
        8,
    )
    .expect("NV_DefineSpace");
    increment_locked(sim).expect("NV_Increment");
    let lock = tpm2::commands::NVWriteLock {
        auth_handle: Handle(LOCKED_COUNTER),
        nv_index: Handle(LOCKED_COUNTER),
    };
    execute_with_password_sessions(sim, &lock, 1, &[]).expect("NV_WriteLock");
    assert_eq!(
        increment_locked(sim),
        Err(tpm2::errors::TpmRc::NV_LOCKED.get())
    );
}

/// `TPM2_NV_Increment` of [`LOCKED_COUNTER`] with its own authorization.
fn increment_locked(sim: &mut Tpm) -> Result<(), u32> {
    let cmd = NVIncrement {
        auth_handle: Handle(LOCKED_COUNTER),
        nv_index: Handle(LOCKED_COUNTER),
    };
    execute_with_password_sessions(sim, &cmd, 1, &[]).map(|_| ())
}

/// Without a save of the NV copy after the lock, a power loss without `TPM2_Shutdown` reverts
/// the lock (an attribute change of an orderly Index stays in RAM).
#[test]
fn orderly_write_lock_reverts_without_a_save() {
    let mut sim = Tpm::new();
    define_and_lock_counter(&mut sim);
    cycle(&mut sim, None, TPM_SU_CLEAR);
    increment_locked(&mut sim).expect("the lock was not saved");
}

/// Defining another orderly Index adds an entry to the orderly-Index RAM and saves it to its NV
/// copy at the end of the command (`NvAddRAM()`: `SET_NV_UPDATE(UT_ORDERLY)`), with the lock.
#[test]
fn defining_an_orderly_index_saves_the_orderly_ram() {
    let mut sim = Tpm::new();
    define_and_lock_counter(&mut sim);
    define_nv_with_policy_unwrap(&mut sim, 0x0150_0611, OWNER_RW | TpmaNv::ORDERLY, 8, &[]);
    cycle(&mut sim, None, TPM_SU_CLEAR);
    assert_eq!(
        increment_locked(&mut sim),
        Err(tpm2::errors::TpmRc::NV_LOCKED.get())
    );
}

/// Deleting an orderly Index removes its entry and saves the orderly-Index RAM
/// (`NvDeleteRAM()`), by `TPM2_NV_UndefineSpace` and by `TPM2_Clear` (which deletes the owner's
/// Indices, `NvFlushHierarchy()`).
#[test]
fn deleting_an_orderly_index_saves_the_orderly_ram() {
    for by_clear in [false, true] {
        let mut sim = Tpm::new();
        let index = 0x0150_0612;
        define_nv_with_policy_unwrap(&mut sim, index, OWNER_RW | TpmaNv::ORDERLY, 8, &[]);
        define_and_lock_counter(&mut sim);
        if by_clear {
            clear(&mut sim, Handle::RH_PLATFORM).expect("TPM2_Clear");
        } else {
            let undefine = tpm2::commands::NVUndefineSpace {
                auth_handle: Handle::RH_OWNER,
                nv_index: Handle(index),
            };
            exec_with_empty_passwords(&mut sim, &undefine, 1).expect("NV_UndefineSpace");
        }
        cycle(&mut sim, None, TPM_SU_CLEAR);
        assert_eq!(
            increment_locked(&mut sim),
            Err(tpm2::errors::TpmRc::NV_LOCKED.get()),
            "by_clear: {by_clear}"
        );
    }
}

/// The use of an orderly PIN Pass Index's authValue increments its `pinCount` in the
/// orderly-Index RAM, which makes the TPM no longer orderly (`NvWriteIndexData()`:
/// `g_clearOrderly = TRUE`): after a `TPM2_Shutdown(TPM_SU_STATE)` followed by such a use,
/// `TPM2_Startup(TPM_SU_STATE)` fails (`TPM_RC_VALUE`) and a TPM Reset follows instead.
#[test]
fn orderly_pin_use_clears_the_orderly_state() {
    let mut sim = Tpm::new();
    let index = 0x0150_0613;
    define_nv_with_policy_unwrap(
        &mut sim,
        index,
        TpmaNv::from(TpmNt::PinPass) | TpmaNv::OWNERWRITE | TpmaNv::AUTHREAD | TpmaNv::ORDERLY,
        8,
        &[],
    );
    // pinCount 0, pinLimit 5.
    owner_write(&mut sim, index, 0, &[0, 0, 0, 0, 0, 0, 0, 5]).unwrap();
    assert_eq!(shutdown_raw(&mut sim, TPM_SU_STATE), 0);
    // The read with the Index's authValue counts as a use: pinCount 1.
    let rsp = read_as(&mut sim, Handle(index), index, 0, 8).unwrap();
    assert_eq!(rsp, [0, 0, 0, 1, 0, 0, 0, 5]);
    assert_eq!(
        power_cycle_with(&mut sim, None, TPM_SU_STATE),
        tpm2::errors::TpmRc::VALUE
            .with(tpm2::errors::Position::parameter(1))
            .get()
    );
    assert_eq!(startup_raw(&mut sim, 0, TPM_SU_CLEAR), 0);
}
