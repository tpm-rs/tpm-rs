
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

use tpm2::commands::{StartAuthSession, ContextSave, FlushContext, NVUndefineSpace, NVDefineSpace, NVWrite, NVRead};

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

    // TODO: Perform a nonce and HMAC test (of the nonce, etc).
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

    // TODO: Perform a nonce and HMAC test (of the nonce, etc).
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

fn main() {
    minimum_viable_test_case(false);
    minimum_viable_test_case(true);

    continue_session_testing(false);
    continue_session_testing(true);
}
