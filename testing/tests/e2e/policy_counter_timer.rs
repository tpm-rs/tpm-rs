//! TPM2_PolicyCounterTimer: clock comparisons and NV/clock requirements.

use crate::_common::*;
use tpm2::commands::{PolicyCounterTimer, ReadClock};
use tpm2::errors::TpmRc;
use tpm2::{Tpm2bOperand, TpmCc, TpmEo, TpmSe, TpmiAlgHash};
use tpm2_simulator::{Simulator, SimulatorPlatformSignal, create_simulator};

/// PolicyCounterTimer comparing the clock read by ReadClock succeeds and updates the digest
#[test]
fn clock_comparison_updates_digest() {
    let mut sim = create_simulator!();

    // Start policy session via StartAuthSession
    let policy_session_handle =
        start_session_with_nonce(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256, &[1; 32]);

    // Call ReadClock to obtain the current clock value
    let rc_rsp = sim.execute(ReadClock {}).unwrap();
    let clock_val = rc_rsp.current_time.clock_info.clock;

    // Call TPM2_PolicyCounterTimer against the clock value (offset = 8). The simulator runs on
    // the wall clock, which may tick between the two commands, so the comparison uses
    // UNSIGNED_GE (clock >= the value just read) instead of EQ.
    let clock_bytes = clock_val.to_be_bytes();
    let pct_cmd = PolicyCounterTimer {
        policy_session: policy_session_handle,
        operand_b: Tpm2bOperand::from_bytes(&clock_bytes).unwrap(),
        offset: 8,
        operation: TpmEo::UnsignedGE,
    };
    let res = execute_with_password_sessions(&mut sim, &pct_cmd, 0, &[]);
    assert!(
        res.is_ok(),
        "Expected TPM2_PolicyCounterTimer to succeed, but failed with rc: {:?}",
        res.err()
    );

    // Verify PolicyGetDigest matches expected policy digest accumulation
    let policy_digest = policy_get_digest_checked(&mut sim, policy_session_handle);

    let mut arg_data = Vec::new();
    arg_data.extend_from_slice(pct_cmd.operand_b.get_buffer());
    arg_data.extend_from_slice(&8u16.to_be_bytes());
    arg_data.extend_from_slice(&u16::from(TpmEo::UnsignedGE).to_be_bytes());
    let arg_hash = hash_bytes(TpmiAlgHash::Sha256, &arg_data);

    let mut data_to_hash = Vec::new();
    data_to_hash.extend_from_slice(&[0u8; 32]);
    data_to_hash.extend_from_slice(&(TpmCc::PolicyCounterTimer.code()).to_be_bytes());
    data_to_hash.extend_from_slice(&arg_hash);
    let expected_digest = hash_bytes(TpmiAlgHash::Sha256, &data_to_hash);

    assert_eq!(policy_digest, expected_digest);
}

/// PolicyCounterTimer on time/clock offsets needs a running clock (NV_UNAVAILABLE); reset/restart counts do not.
#[test]
fn clock_operands_need_nv() {
    let mut sim = create_simulator!();
    let s = start_session_with_hash(&mut sim, TpmSe::Policy, TpmiAlgHash::Sha256).session_handle;
    let counter_timer = |sim: &mut Simulator<'_>, offset: u16| {
        run_command(
            sim,
            PolicyCounterTimer {
                policy_session: s,
                operand_b: Tpm2bOperand::from_bytes(&[0; 8]).unwrap(),
                offset,
                operation: TpmEo::UnsignedGE,
            },
        )
        .map(|_| ())
    };
    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
    // time (offset 0) and clock (offset 8) need a running Clock.
    assert_eq!(counter_timer(&mut sim, 0), Err(TpmRc::NV_UNAVAILABLE.get()));
    assert_eq!(counter_timer(&mut sim, 8), Err(TpmRc::NV_UNAVAILABLE.get()));
    // resetCount/restartCount (offset >= 16) do not.
    counter_timer(&mut sim, 16).unwrap();
    sim.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();
    counter_timer(&mut sim, 8).unwrap();
}
