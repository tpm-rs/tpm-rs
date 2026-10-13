//! Signed attestation commands (GetTime, Quote) clear the orderly state and therefore need NV after
//! an orderly shutdown.

use crate::_common::{
    RC_NV_UNAVAILABLE, create_primary_full, create_primary_in,
    execute_with_password_sessions_status, get_time, hmac_sign_template, quote, rsa_sign_template,
};
use tpm2::commands::Shutdown;
use tpm2::{Handle, TpmSu, TpmiAlgHash, TpmtRsaScheme};
use tpm2_simulator::{SimulatorPlatformSignal, create_simulator};

/// A Quote signed by an HMAC key also clears the orderly state (NV_UNAVAILABLE after orderly shutdown).
///
/// Quote by an HMAC key also clears the orderly state (NV unavailable after orderly shutdown).
#[test]
fn hmac_quote_clears_orderly() {
    let mut sim = create_simulator!();
    let (_, key) = create_primary_full(
        &mut sim,
        Handle::RH_OWNER,
        hmac_sign_template(),
        b"orderly-hmac-key",
    );
    execute_with_password_sessions_status(
        &mut sim,
        &Shutdown {
            shutdown_type: TpmSu::State,
        },
        0,
        &[],
    )
    .expect("Shutdown failed");
    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();
    assert_eq!(quote(&mut sim, key, None).err(), Some(RC_NV_UNAVAILABLE));
}

/// A signed GetTime after orderly shutdown with NV off fails with NV_UNAVAILABLE; unsigned succeeds.
///
/// A signed attestation clears the orderly state (`NvClearOrderly`): after an orderly
/// `TPM2_Shutdown` with NV unavailable it fails with `TPM_RC_NV_UNAVAILABLE`, whereas an
/// unsigned (`TPM_RH_NULL`) attestation still succeeds.
#[test]
fn signed_get_time_clears_orderly() {
    let mut sim = create_simulator!();
    let key = create_primary_in(
        &mut sim,
        Handle::RH_ENDORSEMENT,
        rsa_sign_template(Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256))),
    );
    execute_with_password_sessions_status(
        &mut sim,
        &Shutdown {
            shutdown_type: TpmSu::State,
        },
        0,
        &[],
    )
    .expect("Shutdown failed");
    sim.signal_platform(SimulatorPlatformSignal::NvOff).unwrap();

    get_time(&mut sim, Handle::RH_ENDORSEMENT, Handle::RH_NULL, None, 2)
        .expect("unsigned GetTime must not touch the orderly state");
    assert_eq!(
        get_time(&mut sim, Handle::RH_ENDORSEMENT, key, None, 2).err(),
        Some(RC_NV_UNAVAILABLE)
    );
}
