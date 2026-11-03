
#![forbid(unsafe_code)]

//! Tests of the session state machine, currently run against the simulator.
//!
//! This file starts the tests and contains their boilerplate. Tests should look as follows:
//!
//! ```text
//! let mut simulator = start("name(param: {param})");
//! let mut last_nonce_bytes = [0u8; DIGEST_SIZE];
//!
//! let mut session = start_hmac_session(&mut simulator); // or start_policy_session()
//! // Test that the nonce rolls (...).
//! assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);
//!
//! // the test's target work goes here
//!
//! assert!(stop(simulator, session.handle()).is_ok());
//! ```
//!
//! After every command, the test asserts whether the nonce rolled. Whenever
//! it shouldn't, a comment says why. Unless otherwise specified, a session is an
//! HMAC session.

mod basic_and_auth_tests;
mod policy_tests;
mod shutdown_tests;

use std::io;
use std::net::Ipv4Addr;

use tempfile::tempdir;
use tpm2::commands::{
    FlushContext, NVDefineSpace, NVRead, NVUndefineSpace, NVWrite, StartAuthSession, Startup,
};
use tpm2::errors::TpmRc;
use tpm2::*;
use tpm2_client::ClientError;
use tpm2_client::ClientError::Tpm;
use tpm2_client::connection::tcp::TcpSimulator;
use tpm2_client::protocol::RESP_BUFFER_SIZE;
use tpm2_client::sessions::{AuthorizationArea, HmacSession};
use tpm2_client::{CryptoBackend, nv_name, run_command, run_command_with_sessions};

pub const ALG: TpmiAlgHash = TpmiAlgHash::Sha256;
pub const DIGEST_SIZE: usize = ALG.digest_size();

/// This must be in the range [0x01000000, 0x01FFFFFF].
pub const NV_INDEX: Handle = Handle(0x01422224);
pub const NV_DATA_SIZE: u16 = 16;

/// Environment variable used to override the TPM simulator program.
const ENV_VAR_SIMULATOR_PROGRAM: &str = "SIMULATOR_BIN";

/// Get the program to run to launch the TPM simulator. Set the environment
/// variable at the command line to specify a different program to run, e.g.
///
/// ```shell
/// SIMULATOR_BIN="/my/custom/simulator" cargo test
/// ```
fn get_simulator_path() -> String {
    if let Ok(s) = std::env::var(ENV_VAR_SIMULATOR_PROGRAM) {
        return s;
    }
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
// Setup and teardown.
//

/// Spawns a simulator, and sends `TPM2_Startup(TPM_SU_CLEAR)`.
pub fn start(name: &str) -> TcpSimulator {
    let mut simulator = spawn_simulator_and_connect().unwrap();
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];

    println!("{name} starting...");

    let startup = Startup {
        startup_type: TpmSu::Clear,
    };
    assert!(run_command(&startup, simulator.connection_mut(), resp_buffer).is_ok());

    simulator
}

/// Flushes the session under test, then stops the simulator. Returns the
/// result of the flush.
///
/// The end of a session doesn't update the nonce, nor could an attempt to use
/// a freed session. `TPM2_FlushContext` doesn't take a session, so this isn't
/// asserted.
pub fn stop(mut simulator: TcpSimulator, session_handle: Handle) -> Result<(), TpmRc> {
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];

    let flush_context = FlushContext {
        flush_handle: session_handle,
    };
    let flush_context_rsp = tpm_result(run_command(&flush_context, simulator.connection_mut(), resp_buffer));

    assert!(simulator.stop_nicely().is_ok());

    flush_context_rsp
}

/// Starts an unbound, unsalted SHA-256 HMAC session.
pub fn start_hmac_session(simulator: &mut TcpSimulator) -> HmacSession {
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];

    let start_auth_session = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::new(&[42u8; DIGEST_SIZE]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: ALG,
    };
    let start_auth_session_rsp = run_command(&start_auth_session, simulator.connection_mut(), resp_buffer).unwrap();
    println!("{:?}", start_auth_session_rsp);

    HmacSession::new(start_auth_session_rsp.session_handle, start_auth_session.auth_hash, start_auth_session.nonce_caller, start_auth_session_rsp.nonce_tpm)
}

//
// Results.
//

/// Returns whether `current_nonce` is the same as `last`, then updates `last`.
pub fn nonce_unchanged(last: &mut [u8], current_nonce: &Tpm2bNonce) -> bool {
    let current = current_nonce.as_slice();
    let same = *last == *current;
    last.copy_from_slice(current);
    same
}

/// Returns the response code of a command that the TPM failed.
///
/// Panics on errors other than a `TPM_RC`, as those are bugs in the test (or
/// the client), rather than results of the TPM's state machine.
pub fn tpm_result<T>(rsp: Result<T, ClientError<io::Error>>) -> Result<(), TpmRc> {
    match rsp {
        Ok(_) => Ok(()),
        Err(Tpm(rc)) => Err(rc),
        Err(e) => panic!("unexpected error: {e:?}"),
    }
}

//
// NV indices.
//

/// Returns an `NV_INDEX` with `attributes` and `auth_policy`, holding
/// `NV_DATA_SIZE` bytes.
pub fn nv_public<'a>(attributes: TpmaNv, auth_policy: Tpm2bDigest<'a>) -> TpmsNvPublic<'a> {
    TpmsNvPublic {
        nv_index: NV_INDEX,
        name_alg: ALG,
        attributes: TpmaNv::from(TpmNt::Ordinary) | attributes,
        auth_policy,
        data_size: NV_DATA_SIZE,
    }
}

/// Returns the Names of an NV command's handles (`authHandle`, then
/// `nvIndex`), where `auth_handle` is either the index itself or a hierarchy.
fn nv_names<'a>(nv_public: &TpmsNvPublic, auth_handle: Handle, name_buf: &'a mut [u8; Tpm2bName::CAP]) -> [Option<Tpm2bName<'a>>; 2] {
    let name = nv_name::<CryptoBackend>(nv_public, name_buf).unwrap();
    [(auth_handle == nv_public.nv_index).then_some(name), Some(name)]
}

/// Defines `nv_public` with `auth`, using OWNER authorization from `session`,
/// and asserts that this rolled the nonce.
pub fn define_nv_index(simulator: &mut TcpSimulator, nv_public: &TpmsNvPublic, auth: Tpm2bAuth, session: &mut HmacSession, last_nonce_bytes: &mut [u8]) {
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];
    let mut name_buf = [0u8; Tpm2bName::CAP];

    // To make this test idempotent, undefine the space, but ignore the return value.
    let nv_undefine_space = NVUndefineSpace {
        auth_handle: Handle::RH_OWNER,
        nv_index: nv_public.nv_index,
    };
    let _ = run_command_with_sessions(&nv_undefine_space, &nv_names(nv_public, Handle::RH_OWNER, &mut name_buf), session, simulator.connection_mut(), resp_buffer);

    // Reload the nonce, don't assert anything.
    nonce_unchanged(last_nonce_bytes, &session.nonce_tpm());

    let nv_define_space = NVDefineSpace {
        auth_handle: Handle::RH_OWNER,
        auth,
        public_info: Tpm2b(*nv_public),
    };
    assert!(run_command_with_sessions(&nv_define_space, &[], session, simulator.connection_mut(), resp_buffer).is_ok());

    assert!(nonce_unchanged(last_nonce_bytes, &session.nonce_tpm()) == false);
}

/// Writes `NV_DATA_SIZE` bytes to `nv_public`, authorizing `auth_handle` (the
/// index itself, or a hierarchy) with `session`. On success, this sets
/// `TPMA_NV_WRITTEN` in `nv_public`, as the TPM does, which changes its Name.
pub fn write_nv_index(simulator: &mut TcpSimulator, nv_public: &mut TpmsNvPublic, auth_handle: Handle, session: &mut impl AuthorizationArea) -> Result<(), TpmRc> {
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];
    let mut name_buf = [0u8; Tpm2bName::CAP];

    let nv_write = NVWrite {
        auth_handle,
        nv_index: nv_public.nv_index,
        data: Tpm2bSized::new(&[42u8; NV_DATA_SIZE as usize]).unwrap(),
        offset: 0,
    };
    let nv_write_rsp = tpm_result(run_command_with_sessions(&nv_write, &nv_names(nv_public, auth_handle, &mut name_buf), session, simulator.connection_mut(), resp_buffer));
    if nv_write_rsp.is_ok() {
        nv_public.attributes |= TpmaNv::WRITTEN;
    }
    nv_write_rsp
}

/// Reads all of `nv_public`, authorizing `auth_handle` (the index itself, or
/// a hierarchy) with `session`.
pub fn read_nv_index(simulator: &mut TcpSimulator, nv_public: &TpmsNvPublic, auth_handle: Handle, session: &mut impl AuthorizationArea) -> Result<(), TpmRc> {
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];
    let mut name_buf = [0u8; Tpm2bName::CAP];

    let nv_read = NVRead {
        auth_handle,
        nv_index: nv_public.nv_index,
        size: NV_DATA_SIZE,
        offset: 0,
    };
    tpm_result(run_command_with_sessions(&nv_read, &nv_names(nv_public, auth_handle, &mut name_buf), session, simulator.connection_mut(), resp_buffer))
}

fn main() {
    basic_and_auth_tests::run();
    shutdown_tests::run();
    policy_tests::run();

    todo!();
}
