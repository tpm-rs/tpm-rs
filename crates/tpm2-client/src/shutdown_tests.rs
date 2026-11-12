//! TPM shutdown session tests.
//!
//! These focus on session lifecycle through a power transition.

use tpm2::commands::{ContextLoad, ContextSave, Shutdown, Startup};
use tpm2::*;
use tpm2_client::run_command;

use crate::{DIGEST_SIZE, RESP_BUFFER_SIZE, nonce_unchanged, start, start_hmac_session, stop};

//
// Tests.
//

/// The minimal test case for this category - save, suspend and resume, then restore -
/// and its variant, where fully shutting down the TPM loses the necessary backing data.
fn only_resume_maintains_internal_tracking(is_resume_test: bool) {
    let mut simulator = start(&format!("only_resume_maintains_internal_tracking(is_resume_test: {is_resume_test})"));
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];
    let mut last_nonce_bytes = [0u8; DIGEST_SIZE];

    let session = start_hmac_session(&mut simulator);
    // Test that the nonce rolls (and assume that the HMAC changes with, proven by command success, where applicable).
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);

    let context_save = ContextSave {
        save_handle: session.handle(),
    };
    let context_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];
    let context_save_rsp = run_command(&context_save, simulator.connection_mut(), context_buffer).unwrap();

    // This command doesn't take a session.
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == true);

    let shutdown_type = if is_resume_test {
        TpmSu::State
    } else {
        TpmSu::Clear
    };

    let shutdown = Shutdown {
        shutdown_type,
    };
    assert!(run_command(&shutdown, simulator.connection_mut(), resp_buffer).is_ok());

    // This command doesn't take a session.
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == true);

    assert!(simulator.connection_mut().reinit().is_ok());

    let startup = Startup {
        startup_type: shutdown_type,
    };
    assert!(run_command(&startup, simulator.connection_mut(), resp_buffer).is_ok());

    // This command doesn't take a session.
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == true);

    let context_load = ContextLoad {
        context: context_save_rsp.context,
    };
    let context_load_rsp = run_command(&context_load, simulator.connection_mut(), resp_buffer);
    if is_resume_test {
        assert!(context_load_rsp.is_ok());
    } else {
        assert!(context_load_rsp.is_err());
    }

    // This command doesn't take a session, and failures don't update the nonce anyways.
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == true);

    assert_eq!(stop(simulator, session.handle()).is_ok(), is_resume_test);
}

/// As the name suggests, active sessions must be saved to preserve them across any shutdown cycle.
fn active_sessions_are_never_saved() {
    let mut simulator = start("active_sessions_are_never_saved()");
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];
    let mut last_nonce_bytes = [0u8; DIGEST_SIZE];

    let session = start_hmac_session(&mut simulator);
    // Test that the nonce rolls (and assume that the HMAC changes with, proven by command success, where applicable).
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);

    let shutdown = Shutdown {
        shutdown_type: TpmSu::State,
    };
    assert!(run_command(&shutdown, simulator.connection_mut(), resp_buffer).is_ok());

    // This command doesn't take a session.
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == true);

    assert!(simulator.connection_mut().reinit().is_ok());

    let startup = Startup {
        startup_type: TpmSu::State,
    };
    assert!(run_command(&startup, simulator.connection_mut(), resp_buffer).is_ok());

    // This command doesn't take a session.
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == true);

    assert!(stop(simulator, session.handle()).is_err());
}

//
// Driver.
//
pub fn run() {
    only_resume_maintains_internal_tracking(true);
    only_resume_maintains_internal_tracking(false);
    active_sessions_are_never_saved();

    println!("TODO: Continue on orderly (TPM Restart) and disorderly shutdowns.");
}
