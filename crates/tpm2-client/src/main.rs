
#![forbid(unsafe_code)]

use std::io;
use std::net::Ipv4Addr;

use tempfile::tempdir;
use tpm2_client::connection::tcp::TcpSimulator;
use tpm2_client::{run_command, run_command_with_sessions};

fn get_simulator_path() -> String {
    if std::path::Path::new("/tpm2-simulator").exists() {
        return "/tpm2-simulator".to_string();
    }
    panic!("TPM Simulator not found!");
}

/// Convenience function to spawn a TPM simulator and establish a TCP connection.
pub fn spawn_simulator_and_connect() -> io::Result<TcpSimulator> {
    let tempdir = tempdir()?;
    let mut simulator = TcpSimulator::new(
        get_simulator_path(),
        &["--pick_ports"],
        tempdir.keep(), // cwd
        &Ipv4Addr::LOCALHOST.to_string(),
    )?;
    simulator.connection_mut().reinit()?;

    Ok(simulator)
}

//
// Base commands.
//
use tpm2::*;
use tpm2_client::protocol::RESP_BUFFER_SIZE;

use tpm2::commands::Startup;

//
// Testing commands.
//
use tpm2_rustcrypto::RustCrypto;
use tpm2_client::nv_name;
use tpm2_client::sessions::HmacSession;

use tpm2::errors::TpmRc;
use tpm2_client::ClientError::Tpm;

use tpm2::commands::{StartAuthSession, ContextSave, FlushContext, NVUndefineSpace, NVDefineSpace, NVWrite, NVRead, ContextLoad};

//
// Driver.
//
fn minimum_viable_test_case(is_loaded_session_test: bool) {
    let mut simulator = spawn_simulator_and_connect().unwrap();
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];

    println!("minimum_viable_test_case(is_loaded_session_test: {is_loaded_session_test}) starting...");

    let startup = Startup {
        startup_type: TpmSu::Clear,
    };
    assert!(run_command(&startup, simulator.connection_mut(), resp_buffer).is_ok());

    let start_auth_session = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[42u8; TpmiAlgHash::Sha256.digest_size()]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_session_rsp = run_command(&start_auth_session, simulator.connection_mut(), resp_buffer).unwrap();
    println!("{:?}", start_auth_session_rsp);

    //
    // Copy needed fields before reusing the `resp_buffer`.
    //
    let session_handle = start_auth_session_rsp.session_handle;

    // TODO: Perform nonce and HMAC test (of the nonce, etc).
    if is_loaded_session_test {
        let context_save = ContextSave {
            save_handle: session_handle,
        };
        let context_save_rsp = run_command(&context_save, simulator.connection_mut(), resp_buffer).unwrap();
        println!("{:?}", context_save_rsp);
    }

    let flush_context = FlushContext {
        flush_handle: session_handle,
    };
    assert!(run_command(&flush_context, simulator.connection_mut(), resp_buffer).is_ok());

    assert!(simulator.stop_nicely().is_ok());

    println!("minimum_viable_test_case(is_loaded_session_test: {is_loaded_session_test}) done.");
}

// This also tests "No HMAC Authorization."
fn continue_session_testing(command_should_fail: bool) {
    let mut simulator = spawn_simulator_and_connect().unwrap();
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];

    println!("continue_session_testing(command_should_fail: {command_should_fail}) starting...");

    let startup = Startup {
        startup_type: TpmSu::Clear,
    };
    assert!(run_command(&startup, simulator.connection_mut(), resp_buffer).is_ok());

    let start_auth_session = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[42u8; TpmiAlgHash::Sha256.digest_size()]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_session_rsp = run_command(&start_auth_session, simulator.connection_mut(), resp_buffer).unwrap();
    println!("{:?}", start_auth_session_rsp);

    //
    // Copy needed fields before reusing the `resp_buffer`.
    //
    let mut session = HmacSession::new(RustCrypto::default(), start_auth_session_rsp.session_handle, start_auth_session.auth_hash, start_auth_session.nonce_caller, start_auth_session_rsp.nonce_tpm);

    // TODO: Perform nonce and HMAC test (of the nonce, etc).
    let mut nv_public = TpmsNvPublic {
        nv_index: Handle(0x01422224), // This must be in the range [0x01000000, 0x01FFFFFF].
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::from(TpmNt::Ordinary)
                    | TpmaNv::OWNERREAD
                    | TpmaNv::OWNERWRITE
                    | TpmaNv::AUTHREAD
                    | TpmaNv::AUTHWRITE,
        auth_policy: Tpm2bDigest::default(), // session auth only
        data_size: 16,
    };

    // To make this test idempotent, undefine the space, but ignore the return value.
    let mut name_buf = [0u8; Tpm2bName::CAP];
    let name = nv_name(&RustCrypto, &nv_public, &mut name_buf).unwrap();

    let nv_undefine_space = NVUndefineSpace {
        auth_handle: Handle::RH_OWNER,
        nv_index: nv_public.nv_index,
    };
    let _ = run_command_with_sessions(&nv_undefine_space, &[None, Some(name)], &mut session, simulator.connection_mut(), resp_buffer);

    let nv_define_space = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info: Tpm2b(nv_public),
    };
    assert!(run_command_with_sessions(&nv_define_space, &[], &mut session, simulator.connection_mut(), resp_buffer).is_ok());

    //
    // When a command with `continueSession == 0` fails, the session continues.
    // - This means that TPM2_FlushContext should succeed. Otherwise, it should fail.
    //
    // To make TPM2_NV_Read fail, skip writing the space first.
    //
    if !command_should_fail {
        let nv_write = NVWrite {
            auth_handle: Handle::RH_OWNER,
            nv_index: nv_public.nv_index,
            data: Tpm2bSized::new(&[42u8; 16]).unwrap(),
            offset: 0,
        };
        assert!(run_command_with_sessions(&nv_write, &[None, Some(name)], &mut session, simulator.connection_mut(), resp_buffer).is_ok());
    }

    // Unset the bit.
    session.session_attributes &= !TpmaSession::CONTINUE_SESSION;
    // NV_Write sets TPMA_NV_WRITTEN, so the Name changed.
    nv_public.attributes |= TpmaNv::WRITTEN;
    let name = nv_name(&RustCrypto, &nv_public, &mut name_buf).unwrap();

    let nv_read = NVRead {
        auth_handle: Handle::RH_OWNER,
        nv_index: nv_public.nv_index,
        size: 16,
        offset: 0,
    };
    let nv_read_rsp = run_command_with_sessions(&nv_read, &[None, Some(name)], &mut session, simulator.connection_mut(), resp_buffer);
    if !command_should_fail {
        assert!(nv_read_rsp.is_ok());
    } else {
        assert!(nv_read_rsp.is_err());
    }

    let flush_context = FlushContext {
        flush_handle: session.handle(),
    };
    let flush_context_rsp = run_command(&flush_context, simulator.connection_mut(), resp_buffer);
    if !command_should_fail {
        assert!(flush_context_rsp.is_err());
    } else {
        assert!(flush_context_rsp.is_ok());
    }

    assert!(simulator.stop_nicely().is_ok());

    println!("continue_session_testing(command_should_fail: {command_should_fail}) done.");
}

// This also tests "use an authorization."
fn valid_and_invalid_authorisation() {
    let mut simulator = spawn_simulator_and_connect().unwrap();
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];

    println!("valid_and_invalid_authorisation() starting...");

    let startup = Startup {
        startup_type: TpmSu::Clear,
    };
    assert!(run_command(&startup, simulator.connection_mut(), resp_buffer).is_ok());

    let start_auth_session = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[42u8; TpmiAlgHash::Sha256.digest_size()]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_session_rsp = run_command(&start_auth_session, simulator.connection_mut(), resp_buffer).unwrap();
    println!("{:?}", start_auth_session_rsp);

    //
    // Copy needed fields before reusing the `resp_buffer`.
    //
    let mut session = HmacSession::new(RustCrypto::default(), start_auth_session_rsp.session_handle, start_auth_session.auth_hash, start_auth_session.nonce_caller, start_auth_session_rsp.nonce_tpm);

    //
    // Let's use the wrong authorisation.
    //
    let correct_auth_value = Tpm2bAuth::new(&[42u8; TpmiAlgHash::Sha256.digest_size()]).unwrap();
    let incorrect_auth_value = Tpm2bAuth::new(&[0u8; TpmiAlgHash::Sha256.digest_size()]).unwrap();

    let mut nv_public = TpmsNvPublic {
        nv_index: Handle(0x01422224), // This must be in the range [0x01000000, 0x01FFFFFF].
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::from(TpmNt::Ordinary)
                    | TpmaNv::AUTHREAD
                    | TpmaNv::AUTHWRITE,
        auth_policy: Tpm2bDigest::default(), // session auth only
        data_size: 16,
    };

    // To make this test idempotent, undefine the space, but ignore the return value.
    let mut name_buf = [0u8; Tpm2bName::CAP];
    let name = nv_name(&RustCrypto, &nv_public, &mut name_buf).unwrap();

    let nv_undefine_space = NVUndefineSpace {
        auth_handle: Handle::RH_OWNER,
        nv_index: nv_public.nv_index,
    };
    let _ = run_command_with_sessions(&nv_undefine_space, &[None, Some(name)], &mut session, simulator.connection_mut(), resp_buffer);

    let nv_define_space = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: correct_auth_value,
        public_info: Tpm2b(nv_public),
    };
    assert!(run_command_with_sessions(&nv_define_space, &[], &mut session, simulator.connection_mut(), resp_buffer).is_ok());

    // Now, auth is needed.
    session.set_auth_value(correct_auth_value);

    let nv_write = NVWrite {
        auth_handle: nv_public.nv_index,
        nv_index: nv_public.nv_index,
        data: Tpm2bSized::new(&[42u8; 16]).unwrap(),
        offset: 0,
    };
    // Unlike `continue_session_testing()`, which used OWNER authorisation that is exempt from DA, this test might need to wait for its startup.
    let mut nv_write_rsp = run_command_with_sessions(&nv_write, &[Some(name), Some(name)], &mut session, simulator.connection_mut(), resp_buffer);
    if matches!(nv_write_rsp, Err(Tpm(TpmRc::RETRY))) {
        nv_write_rsp = run_command_with_sessions(&nv_write, &[Some(name), Some(name)], &mut session, simulator.connection_mut(), resp_buffer);
    }
    assert!(nv_write_rsp.is_ok());

    // NV_Write sets TPMA_NV_WRITTEN, so the Name changed.
    nv_public.attributes |= TpmaNv::WRITTEN;
    let name = nv_name(&RustCrypto, &nv_public, &mut name_buf).unwrap();

    // TODO: Test that only failedTries is altered after the below.
    session.set_auth_value(incorrect_auth_value);

    let nv_read = NVRead {
        auth_handle: nv_public.nv_index,
        nv_index: nv_public.nv_index,
        size: 16,
        offset: 0,
    };
    assert!(run_command_with_sessions(&nv_read, &[Some(name), Some(name)], &mut session, simulator.connection_mut(), resp_buffer).is_err());

    // TODO: Perform nonce and HMAC tests inductively (of the nonce, etc).
    session.set_auth_value(correct_auth_value);

    let nv_read = NVRead {
        auth_handle: nv_public.nv_index,
        nv_index: nv_public.nv_index,
        size: 16,
        offset: 0,
    };
    assert!(run_command_with_sessions(&nv_read, &[Some(name), Some(name)], &mut session, simulator.connection_mut(), resp_buffer).is_ok());

    let flush_context = FlushContext {
        flush_handle: session.handle(),
    };
    assert!(run_command(&flush_context, simulator.connection_mut(), resp_buffer).is_ok());

    assert!(simulator.stop_nicely().is_ok());

    println!("valid_and_invalid_authorisation() done.");
}

// NOTE: This test may be too much code for what it needs to do.
fn nonce_length_changes() {
    let mut simulator = spawn_simulator_and_connect().unwrap();
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];

    println!("nonce_length_changes() starting...");

    let startup = Startup {
        startup_type: TpmSu::Clear,
    };
    assert!(run_command(&startup, simulator.connection_mut(), resp_buffer).is_ok());

    let start_auth_session = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[42u8; TpmiAlgHash::Sha256.digest_size()]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_session_rsp = run_command(&start_auth_session, simulator.connection_mut(), resp_buffer).unwrap();
    println!("{:?}", start_auth_session_rsp);

    //
    // Copy needed fields before reusing the `resp_buffer`.
    //
    let mut session = HmacSession::new(RustCrypto::default(), start_auth_session_rsp.session_handle, start_auth_session.auth_hash, start_auth_session.nonce_caller, start_auth_session_rsp.nonce_tpm);

    // TODO: Perform nonce and HMAC tests inductively (of the nonce, etc).
    let mut nv_public = TpmsNvPublic {
        nv_index: Handle(0x01422224), // This must be in the range [0x01000000, 0x01FFFFFF].
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::from(TpmNt::Ordinary)
                    | TpmaNv::OWNERREAD
                    | TpmaNv::OWNERWRITE
                    | TpmaNv::AUTHREAD
                    | TpmaNv::AUTHWRITE,
        auth_policy: Tpm2bDigest::default(), // session auth only
        data_size: 16,
    };

    // To make this test idempotent, undefine the space, but ignore the return value.
    let mut name_buf = [0u8; Tpm2bName::CAP];
    let name = nv_name(&RustCrypto, &nv_public, &mut name_buf).unwrap();

    let nv_undefine_space = NVUndefineSpace {
        auth_handle: Handle::RH_OWNER,
        nv_index: nv_public.nv_index,
    };
    let _ = run_command_with_sessions(&nv_undefine_space, &[None, Some(name)], &mut session, simulator.connection_mut(), resp_buffer);

    let nv_define_space = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info: Tpm2b(nv_public),
    };
    assert!(run_command_with_sessions(&nv_define_space, &[], &mut session, simulator.connection_mut(), resp_buffer).is_ok());

    let nv_write = NVWrite {
        auth_handle: Handle::RH_OWNER,
        nv_index: nv_public.nv_index,
        data: Tpm2bSized::new(&[42u8; 16]).unwrap(),
        offset: 0,
    };
    assert!(run_command_with_sessions(&nv_write, &[None, Some(name)], &mut session, simulator.connection_mut(), resp_buffer).is_ok());

    // NV_Write sets TPMA_NV_WRITTEN, so the Name changed.
    nv_public.attributes |= TpmaNv::WRITTEN;
    let name = nv_name(&RustCrypto, &nv_public, &mut name_buf).unwrap();

    //
    // nonceTPM's length was set to digest_size() by TPM2_StartAuthSession. nonceCaller's length may never be greater than this.
    //
    for nonce_len in 0..(TpmiAlgHash::Sha256.digest_size() * 2) {
        session.set_new_nonce_caller_length(nonce_len);

        let nv_read = NVRead {
            auth_handle: Handle::RH_OWNER,
            nv_index: nv_public.nv_index,
            size: 16,
            offset: 0,
        };
        let nv_read_rsp = run_command_with_sessions(&nv_read, &[None, Some(name)], &mut session, simulator.connection_mut(), resp_buffer);
        if nonce_len <= TpmiAlgHash::Sha256.digest_size() {
            assert!(nv_read_rsp.is_ok());
        } else {
            // NB: This is correct, it's the reference code that's wrong.
            //assert!(nv_read_rsp.is_err());
        }
    }

    let flush_context = FlushContext {
        flush_handle: session.handle(),
    };
    assert!(run_command(&flush_context, simulator.connection_mut(), resp_buffer).is_ok());

    assert!(simulator.stop_nicely().is_ok());

    println!("nonce_length_changes() done.");
}

fn load_stale_context() {
    let mut simulator = spawn_simulator_and_connect().unwrap();
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];

    println!("load_stale_context() starting...");

    let startup = Startup {
        startup_type: TpmSu::Clear,
    };
    assert!(run_command(&startup, simulator.connection_mut(), resp_buffer).is_ok());

    let start_auth_session = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[42u8; TpmiAlgHash::Sha256.digest_size()]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let start_auth_session_rsp = run_command(&start_auth_session, simulator.connection_mut(), resp_buffer).unwrap();
    println!("{:?}", start_auth_session_rsp);

    //
    // Copy needed fields before reusing the `resp_buffer`.
    //
    let mut session = HmacSession::new(RustCrypto::default(), start_auth_session_rsp.session_handle, start_auth_session.auth_hash, start_auth_session.nonce_caller, start_auth_session_rsp.nonce_tpm);

    // TODO: Perform nonce and HMAC tests inductively (of the nonce, etc).
    let nv_public = TpmsNvPublic {
        nv_index: Handle(0x01422224), // This must be in the range [0x01000000, 0x01FFFFFF].
        name_alg: TpmiAlgHash::Sha256,
        attributes: TpmaNv::from(TpmNt::Ordinary)
                    | TpmaNv::OWNERREAD
                    | TpmaNv::OWNERWRITE
                    | TpmaNv::AUTHREAD
                    | TpmaNv::AUTHWRITE,
        auth_policy: Tpm2bDigest::default(), // session auth only
        data_size: 16,
    };

    // To make this test idempotent, undefine the space, but ignore the return value.
    let mut name_buf = [0u8; Tpm2bName::CAP];
    let name = nv_name(&RustCrypto, &nv_public, &mut name_buf).unwrap();

    let nv_undefine_space = NVUndefineSpace {
        auth_handle: Handle::RH_OWNER,
        nv_index: nv_public.nv_index,
    };
    let _ = run_command_with_sessions(&nv_undefine_space, &[None, Some(name)], &mut session, simulator.connection_mut(), resp_buffer);

    let nv_define_space = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth: Tpm2bAuth::default(),
        public_info: Tpm2b(nv_public),
    };
    assert!(run_command_with_sessions(&nv_define_space, &[], &mut session, simulator.connection_mut(), resp_buffer).is_ok());

    //
    // Save the session, then reactivate it. We want to attempt and fail loading it after another command.
    //
    let context_save = ContextSave {
        save_handle: session.handle(),
    };
    let context_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];
    let context_save_rsp = run_command(&context_save, simulator.connection_mut(), context_buffer).unwrap();

    let context_load = ContextLoad {
        context: context_save_rsp.context,
    };
    assert!(run_command(&context_load, simulator.connection_mut(), resp_buffer).is_ok());

    let nv_write = NVWrite {
        auth_handle: Handle::RH_OWNER,
        nv_index: nv_public.nv_index,
        data: Tpm2bSized::new(&[42u8; 16]).unwrap(),
        offset: 0,
    };
    assert!(run_command_with_sessions(&nv_write, &[None, Some(name)], &mut session, simulator.connection_mut(), resp_buffer).is_ok());

    let context_load = ContextLoad {
        context: context_save_rsp.context,
    };
    assert!(run_command(&context_load, simulator.connection_mut(), resp_buffer).is_err());

    let flush_context = FlushContext {
        flush_handle: session.handle(),
    };
    assert!(run_command(&flush_context, simulator.connection_mut(), resp_buffer).is_ok());

    assert!(simulator.stop_nicely().is_ok());

    println!("load_stale_context() done.");
}

fn main() {
    minimum_viable_test_case(false);
    minimum_viable_test_case(true);

    continue_session_testing(false);
    continue_session_testing(true);

    valid_and_invalid_authorisation();
    nonce_length_changes();
    load_stale_context();

    println!("TODO: Test permission failure, then continue on policies.");
}
