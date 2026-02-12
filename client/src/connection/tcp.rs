//! A connection to the TCG TPM 2.0 Simulator over TCP.
//!
//! This module provides the [`TcpConnection`] struct, which implements the
//! [`Connection`] trait for communicating with a TPM simulator. It also
//! provides a [`TcpSimulator`] struct that manages the lifetime of a TPM
//! simulator process and a connection to it.
#![cfg(feature = "connection-tcp")]
extern crate std;

use std::ffi::{OsStr, OsString};
use std::format;
use std::io::{Error, ErrorKind, IoSlice, Read, Result, Write};
use std::net::TcpStream;
use std::process::{Child, Command};

use zerocopy::network_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::connection::Connection;

/// The default TPM port of the TPM simulator
const SIMULATOR_DEFAULT_TPM_PORT: u16 = 2321;

/// The default Platform port of the TPM simulator
const SIMULATOR_DEFAULT_PLATFORM_PORT: u16 = 2322;

/// A connection to a TPM over TCP, designed for use with the TCG TPM 2.0 Simulator.
///
/// This struct implements the [`Connection`] trait.
#[derive(Debug)]
pub struct TcpConnection {
    /// TCP connection to the TPM port of the TPM simulator
    tpm_tcp: TcpStream,

    /// TCP connection to the Platform port of the TPM simulator
    plat_tcp: TcpStream,

    /// The locality to use when sending commands to the TPM
    locality: u8,
}

impl TcpConnection {
    /// Connects to an already running TPM simulator using the specified ports.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection to the TPM or Platform port fails.
    pub fn connect(
        ip: &str,
        tpm_port: Option<u16>,
        plat_port: Option<u16>,
    ) -> Result<TcpConnection> {
        let tpm_port = tpm_port.unwrap_or(SIMULATOR_DEFAULT_TPM_PORT);
        let plat_port = plat_port.unwrap_or(SIMULATOR_DEFAULT_PLATFORM_PORT);

        Ok(TcpConnection {
            tpm_tcp: TcpStream::connect((ip, tpm_port))?,
            plat_tcp: TcpStream::connect((ip, plat_port))?,
            locality: 0,
        })
    }

    /// Connects to an already running TPM simulator with retries.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection to the TPM or Platform port fails
    /// after the number of retries has been exhausted.
    pub fn connect_with_retries(
        ip: &str,
        tpm_port: Option<u16>,
        plat_port: Option<u16>,
    ) -> Result<TcpConnection> {
        let mut attempts = 0;
        let conn = loop {
            attempts += 1;
            match TcpConnection::connect(ip, tpm_port, plat_port) {
                Ok(conn) => break conn,
                Err(err) => {
                    if attempts > 3 {
                        return Err(err);
                    }
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
        };
        Ok(conn)
    }

    /// Performs an H-CRTM Event Sequence against the TPM simulator.
    ///
    /// # Errors
    ///
    /// Returns an error if the communication with the TPM fails or if the
    /// response terminator is invalid.
    pub fn hcrtm_sequence(&mut self, data: &[u8]) -> Result<()> {
        // Send TPM_Hash_Start
        let cmd_code = U32::new(SimulatorTpmCommandCode::SignalHashStart as u32);
        self.tpm_tcp.write_all(cmd_code.as_bytes())?;
        Self::check_response_end(&mut self.tpm_tcp)?;

        // Send TPM_Hash_Data
        let cmd_code = U32::new(SimulatorTpmCommandCode::SignalHashData as u32);
        let cmd_hdr = &SignalHashDataRequestHeader {
            length: U32::new(data.len() as u32),
        };
        let bytes_written = self.tpm_tcp.write_vectored(&[
            IoSlice::new(cmd_code.as_bytes()),
            IoSlice::new(cmd_hdr.as_bytes()),
            IoSlice::new(data),
        ])?;
        if bytes_written != cmd_code.as_bytes().len() + cmd_hdr.as_bytes().len() + data.len() {
            return Err(Error::new(
                ErrorKind::WriteZero,
                "failed to write entire command to TPM",
            ));
        }
        Self::check_response_end(&mut self.tpm_tcp)?;

        // Send TPM_Hash_End
        let cmd_code = U32::new(SimulatorTpmCommandCode::SignalHashEnd as u32);
        self.tpm_tcp.write_all(cmd_code.as_bytes())?;
        Self::check_response_end(&mut self.tpm_tcp)?;

        Ok(())
    }

    /// Performs a remote handshake with the TPM simulator.
    ///
    /// # Errors
    ///
    /// Returns an error if the communication with the TPM fails or if the
    /// response terminator is invalid.
    pub fn remote_handshake(&mut self, client_version: u32) -> Result<RemoteHandshakeResponse> {
        let cmd_code = U32::new(SimulatorTpmCommandCode::RemoteHandshake as u32);
        let cmd_payload = &RemoteHandshakeRequest {
            client_version: U32::new(client_version),
        };

        let bytes_written = self.tpm_tcp.write_vectored(&[
            IoSlice::new(cmd_code.as_bytes()),
            IoSlice::new(cmd_payload.as_bytes()),
        ])?;
        if bytes_written != cmd_code.as_bytes().len() + cmd_payload.as_bytes().len() {
            return Err(Error::new(
                ErrorKind::WriteZero,
                "failed to write entire command to TPM",
            ));
        }

        let mut resp: RemoteHandshakeResponse = RemoteHandshakeResponse::default();
        self.tpm_tcp.read_exact(resp.as_mut_bytes())?;

        Self::check_response_end(&mut self.tpm_tcp)?;

        Ok(resp)
    }

    /// Sets an alternative result in the TPM simulator.
    ///
    /// # Errors
    ///
    /// Returns an error if the communication with the TPM fails or if the
    /// response terminator is invalid.
    pub fn set_alternative_result(&mut self, result: u32) -> Result<()> {
        let cmd_code = U32::new(SimulatorTpmCommandCode::SetAlternativeResult as u32);
        let cmd_payload = &SetAlternativeResultRequest {
            result: U32::new(result),
        };

        let bytes_written = self.tpm_tcp.write_vectored(&[
            IoSlice::new(cmd_code.as_bytes()),
            IoSlice::new(cmd_payload.as_bytes()),
        ])?;
        if bytes_written != cmd_code.as_bytes().len() + cmd_payload.as_bytes().len() {
            return Err(Error::new(
                ErrorKind::WriteZero,
                "failed to write entire command to TPM",
            ));
        }

        Self::check_response_end(&mut self.tpm_tcp)
    }

    /// Sends a signal to the Platform port of the TPM simulator.
    ///
    /// # Errors
    ///
    /// Returns an error if the communication with the Platform port fails or if the
    /// response terminator is invalid.
    pub fn platform_signal(&mut self, signal: SimulatorPlatformSignal) -> Result<()> {
        let cmd_code = U32::new(signal as u32);
        self.plat_tcp.write_all(cmd_code.as_bytes())?;

        Self::check_response_end(&mut self.plat_tcp)
    }

    /// Convenience function to reinitialize the TPM simulator, causing it to
    /// call _TPM_Init.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the plaform signals fail.
    pub fn reinit(&mut self) -> Result<()> {
        self.platform_signal(SimulatorPlatformSignal::NvOff)?;
        self.platform_signal(SimulatorPlatformSignal::PowerOff)?;
        self.platform_signal(SimulatorPlatformSignal::PowerOn)?;
        self.platform_signal(SimulatorPlatformSignal::NvOn)?;
        Ok(())
    }

    /// Puts the TPM simulator into failure mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the communication with the Platform port fails or if the
    /// response terminator is invalid.
    pub fn test_failure_mode(&mut self) -> Result<()> {
        let cmd_code = U32::new(SimulatorPlatformCommandCode::TestFailureMode as u32);
        self.plat_tcp.write_all(cmd_code.as_bytes())?;

        Self::check_response_end(&mut self.plat_tcp)
    }

    /// Gets the largest command/response the simulator received. Once received,
    /// the simulator will reset the largest command/response to zero.
    ///
    /// # Errors
    ///
    /// Returns an error if the communication with the Platform port fails or if the
    /// response terminator is invalid.
    pub fn get_command_response_sizes(&mut self) -> Result<GetCommandResponseSizesResponse> {
        let cmd_code = U32::new(SimulatorPlatformCommandCode::GetCommandResponseSizes as u32);
        self.plat_tcp.write_all(cmd_code.as_bytes())?;

        // The simulator sends the response as a variable-length byte array,
        // which is a `U32` length followed by the data.
        let mut length = U32::ZERO;
        self.plat_tcp.read_exact(length.as_mut_bytes())?;
        if length.get() as usize != std::mem::size_of::<GetCommandResponseSizesResponse>() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "received unexpected response size from simulator",
            ));
        }

        let mut resp: GetCommandResponseSizesResponse = GetCommandResponseSizesResponse::default();
        self.plat_tcp.read_exact(resp.as_mut_bytes())?;

        Self::check_response_end(&mut self.plat_tcp)?;

        Ok(resp)
    }

    /// Gets whether an Authenticated Countdown Timer (ACT) was signaled.
    ///
    /// # Errors
    ///
    /// Returns an error if the communication with the Platform port fails or if the
    /// response terminator is invalid.
    pub fn act_get_signaled(&mut self, act_handle: u32) -> Result<u32> {
        let cmd_code = U32::new(SimulatorPlatformCommandCode::ActGetSignaled as u32);
        let cmd_payload = &ActGetSignaledRequest {
            act_handle: U32::new(act_handle),
        };

        let bytes_written = self.plat_tcp.write_vectored(&[
            IoSlice::new(cmd_code.as_bytes()),
            IoSlice::new(cmd_payload.as_bytes()),
        ])?;
        if bytes_written != cmd_code.as_bytes().len() + cmd_payload.as_bytes().len() {
            return Err(Error::new(
                ErrorKind::WriteZero,
                "failed to write entire command to TPM",
            ));
        }

        let mut resp: ActGetSignaledResponse = ActGetSignaledResponse::default();
        self.plat_tcp.read_exact(resp.as_mut_bytes())?;

        Self::check_response_end(&mut self.plat_tcp)?;

        Ok(u32::from(resp.signaled))
    }

    /// Sets the firmware hash of the TPM.
    ///
    /// # Errors
    ///
    /// Returns an error if the communication with the Platform port fails or if the
    /// response terminator is invalid.
    pub fn set_firmware_hash(&mut self, hash: u32) -> Result<()> {
        let cmd_code = U32::new(SimulatorPlatformCommandCode::SetFirmwareHash as u32);
        let cmd_payload = &SetFirmwareHashRequest {
            hash: U32::new(hash),
        };

        let bytes_written = self.plat_tcp.write_vectored(&[
            IoSlice::new(cmd_code.as_bytes()),
            IoSlice::new(cmd_payload.as_bytes()),
        ])?;
        if bytes_written != cmd_code.as_bytes().len() + cmd_payload.as_bytes().len() {
            return Err(Error::new(
                ErrorKind::WriteZero,
                "failed to write entire command to TPM",
            ));
        }

        Self::check_response_end(&mut self.plat_tcp)
    }

    /// Sets the firmware SVN of the TPM.
    ///
    /// # Errors
    ///
    /// Returns an error if the communication with the Platform port fails or if the
    /// response terminator is invalid.
    pub fn set_firmware_svn(&mut self, svn: u32) -> Result<()> {
        let cmd_code = U32::new(SimulatorPlatformCommandCode::SetFirmwareSvn as u32);
        let cmd_payload = &SetFirmwareSvnRequest { svn: U32::new(svn) };

        let bytes_written = self.plat_tcp.write_vectored(&[
            IoSlice::new(cmd_code.as_bytes()),
            IoSlice::new(cmd_payload.as_bytes()),
        ])?;
        if bytes_written != cmd_code.as_bytes().len() + cmd_payload.as_bytes().len() {
            return Err(Error::new(
                ErrorKind::WriteZero,
                "failed to write entire command to TPM",
            ));
        }

        Self::check_response_end(&mut self.plat_tcp)
    }

    /// Sets the locality used when issuing subsequent commands.
    pub fn set_locality(&mut self, locality: u8) {
        self.locality = locality;
    }

    /// Ends the session with the TPM simulator. This causes the simulator to
    /// listen for new incoming connections.
    ///
    /// # Errors
    ///
    /// Returns an error if the communication with the TPM or Platform port fails.
    pub fn session_end(&mut self) -> Result<()> {
        let cmd_code = U32::new(SimulatorTpmCommandCode::SessionEnd as u32);
        self.tpm_tcp.write_all(cmd_code.as_bytes())?;
        self.tpm_tcp.shutdown(std::net::Shutdown::Both)?;

        let cmd_code = U32::new(SimulatorPlatformCommandCode::SessionEnd as u32);
        self.plat_tcp.write_all(cmd_code.as_bytes())?;
        self.plat_tcp.shutdown(std::net::Shutdown::Both)?;

        Ok(())
    }

    /// Stops the TPM simulator. This causes the simulator to exit the program.
    ///
    /// # Errors
    ///
    /// Returns an error if the communication with the TPM or Platform port fails.
    pub fn stop_simulator(&mut self) -> Result<()> {
        let cmd_code = U32::new(SimulatorTpmCommandCode::Stop as u32);
        self.tpm_tcp.write_all(cmd_code.as_bytes())?;
        self.tpm_tcp.shutdown(std::net::Shutdown::Both)?;

        let cmd_code = U32::new(SimulatorPlatformCommandCode::Stop as u32);
        self.plat_tcp.write_all(cmd_code.as_bytes())?;
        self.plat_tcp.shutdown(std::net::Shutdown::Both)?;

        Ok(())
    }

    /// Reads the trailing zero from the TPM simulator response.
    fn check_response_end(stream: &mut TcpStream) -> Result<()> {
        let mut resp_end = U32::ZERO;
        stream.read_exact(resp_end.as_mut_bytes())?;
        if resp_end != U32::ZERO {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "response terminator was not zero",
            ));
        }
        Ok(())
    }
}

impl Connection for TcpConnection {
    type Error = std::io::Error;
    fn transact<'a>(&mut self, command: &[u8], response: &'a mut [u8]) -> Result<&'a mut [u8]> {
        let cmd_size: u32 = command
            .len()
            .try_into()
            .map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;

        let cmd_code = U32::new(SimulatorTpmCommandCode::SendCommand as u32);
        let cmd_hdr = &SendCommandRequestHeader {
            locality: self.locality,
            length: U32::new(cmd_size),
        };

        let bytes_written = self.tpm_tcp.write_vectored(&[
            IoSlice::new(cmd_code.as_bytes()),
            IoSlice::new(cmd_hdr.as_bytes()),
            IoSlice::new(command),
        ])?;
        if bytes_written != cmd_code.as_bytes().len() + cmd_hdr.as_bytes().len() + command.len() {
            return Err(Error::new(
                ErrorKind::WriteZero,
                "failed to write entire command to TPM",
            ));
        };

        let mut resp_hdr: SendCommandResponseHeader = SendCommandResponseHeader::default();
        self.tpm_tcp.read_exact(resp_hdr.as_mut_bytes())?;
        if resp_hdr.length.get() as usize > response.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "response buffer too small",
            ));
        }
        self.tpm_tcp
            .read_exact(&mut response[..resp_hdr.length.get() as usize])?;

        // The TPM simulator completes each command with a u32 `0`.
        Self::check_response_end(&mut self.tpm_tcp)?;
        Ok(&mut response[..resp_hdr.length.get() as usize])
    }
}

/// A command that can be sent to the TPM port of the TPM simulator
#[repr(u32)]
enum SimulatorTpmCommandCode {
    /// Signal TPM_Hash_Start event.
    SignalHashStart = 5,
    /// Signal TPM_Hash_Data event.
    SignalHashData = 6,
    /// Signal TPM_Hash_End event.
    SignalHashEnd = 7,
    /// Send a command to the TPM.
    SendCommand = 8,
    /// Perform a remote handshake with the TPM.
    RemoteHandshake = 15,
    /// Set an alternative result in the TPM.
    SetAlternativeResult = 16,
    /// End the current session with the TPM simulator. The simulator will
    /// listen for new incoming connections.
    SessionEnd = 20,
    /// Stop the TPM simulator.
    Stop = 21,
}

/// Parameters for the TpmSignalHashData command
#[derive(IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
struct SignalHashDataRequestHeader {
    length: U32,
}

/// Parameters for the SendCommand command
#[derive(IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
struct SendCommandRequestHeader {
    locality: u8,
    length: U32,
}

/// Parameters for the SendCommand response
#[derive(Default, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
struct SendCommandResponseHeader {
    length: U32,
}

/// Parameters for the SetAlternativeResult command
#[derive(IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
struct SetAlternativeResultRequest {
    result: U32,
}

/// Parameters for the RemoteHandshake command
#[derive(IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
struct RemoteHandshakeRequest {
    client_version: U32,
}

/// Parameters for the RemoteHandshake response
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
#[repr(C, packed)]
pub struct RemoteHandshakeResponse {
    server_version: U32,
    endpoint_info: U32,
}

impl RemoteHandshakeResponse {
    /// Returns the version of the simulator server.
    pub fn server_version(&self) -> u32 {
        self.server_version.get()
    }
    /// Returns the endpoint information.
    pub fn endpoint_info(&self) -> u32 {
        self.endpoint_info.get()
    }
}

/// A signal that can be sent to the Platform port of the TPM simulator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SimulatorPlatformSignal {
    /// Signal that power is applied to the TPM.
    PowerOn = 1,
    /// Signal that power is removed from the TPM.
    PowerOff = 2,
    /// Signal that physical presence is asserted.
    PhysicalPresenceOn = 3,
    /// Signal that physical presence is removed.
    PhysicalPresenceOff = 4,
    /// Signal that the indication to cancel commands is asserted.
    CancelOn = 9,
    /// Signal that the indication to cancel commands is removed.
    CancelOff = 10,
    /// Signal that NV memory is available to the TPM.
    NvOn = 11,
    /// Signal that NV memory is no longer available to the TPM.
    NvOff = 12,
    /// Enable the use of the RSA key cache in the TPM simulator.
    KeyCacheOn = 13,
    /// Disable the use of the RSA key cache in the TPM simulator.
    KeyCacheOff = 14,
    /// Perform a TPM Reset (i.e. platorm reboot / power on).
    Reset = 17,
    /// Perform a TPM Restart (i.e. restore from hibernation).
    Restart = 18,
}

/// A command that can be sent to the Platform port of the TPM simulator
#[repr(u32)]
enum SimulatorPlatformCommandCode {
    /// End the current session with the TPM simulator. The simulator will
    /// listen for new incoming connections.
    SessionEnd = 20,
    /// Stop the TPM simulator.
    Stop = 21,
    /// Get the largest command/response sizes that the TPM simulator observed.
    GetCommandResponseSizes = 25,
    /// Get whether an ACT was signaled.
    ActGetSignaled = 26,
    /// Force the TPM into failure mode.
    TestFailureMode = 30,
    /// Set the TPM firmware hash.
    SetFirmwareHash = 35,
    /// Set the TPM firmware SVN.
    SetFirmwareSvn = 36,
}

/// Parameters for the GetCommandResponseSizes response
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
#[repr(C)]
pub struct GetCommandResponseSizesResponse {
    largest_command_size: u32,
    largest_command: U32,
    largest_response_size: u32,
    largest_response: U32,
}

impl GetCommandResponseSizesResponse {
    /// Returns the size of the largest command.
    pub fn largest_command_size(&self) -> u32 {
        self.largest_command_size
    }
    /// Returns the largest command code.
    pub fn largest_command(&self) -> u32 {
        self.largest_command.get()
    }
    /// Returns the size of the largest response.
    pub fn largest_response_size(&self) -> u32 {
        self.largest_response_size
    }
    /// Returns the largest response code.
    pub fn largest_response(&self) -> u32 {
        self.largest_response.get()
    }
}

/// Parameters for the ActGetSignaled command
#[derive(IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
struct ActGetSignaledRequest {
    act_handle: U32,
}

/// Parameters for the ActGetSignaled response
#[derive(Default, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
struct ActGetSignaledResponse {
    pub signaled: U32,
}

/// Parameters for the SetFirmwareHash command
#[derive(IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
struct SetFirmwareHashRequest {
    hash: U32,
}

/// Parameters for the SetFirmwareSvn command
#[derive(IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
struct SetFirmwareSvnRequest {
    svn: U32,
}

/// Structure to manage the subprocess used to spawn the TPM simulator.
#[derive(Debug)]
pub struct TcpSimulator {
    child: Child,
    conn: TcpConnection,
}

impl TcpSimulator {
    /// Starts the TPM simulator binary with the given arguments and connects to it.
    pub fn new<B: AsRef<OsStr>, A: AsRef<OsStr>>(
        bin: B,
        args: &[A],
        ip: &str,
    ) -> Result<TcpSimulator> {
        let mut command = Command::new(bin.as_ref());
        command.current_dir("/");
        if !args.is_empty() {
            command.args(args);
        }

        let child = command.spawn().map_err(|e| {
            let argstr = if !args.is_empty() {
                // Ideally this would just be `args.join(" ")`, but the join
                // impl for OsStr is a permanent unstable feature, see
                // https://github.com/rust-lang/rust/issues/27747.
                let mut argstr = OsString::new();
                for arg in args {
                    argstr.push(" ");
                    argstr.push(arg);
                }
                argstr
            } else {
                OsString::new()
            };
            Error::other(format!(
                "failed to start TCP simulator \"{}{}\": {e}",
                bin.as_ref().to_string_lossy(),
                argstr.to_string_lossy()
            ))
        })?;

        let conn = TcpConnection::connect_with_retries(ip, None, None)?;

        Ok(TcpSimulator { child, conn })
    }

    /// Stops the TPM simulator process.
    pub fn stop(&mut self) -> Result<()> {
        self.child
            .kill()
            .map_err(|e| Error::other(format!("failed to stop TCP simulator: {e}")))
    }

    /// Returns a reference to the underlying TCP connection.
    pub fn connection(&self) -> &TcpConnection {
        &self.conn
    }

    /// Returns a mutable reference to the underlying TCP connection.
    pub fn connection_mut(&mut self) -> &mut TcpConnection {
        &mut self.conn
    }
}

impl Drop for TcpSimulator {
    fn drop(&mut self) {
        _ = self.stop();
    }
}
