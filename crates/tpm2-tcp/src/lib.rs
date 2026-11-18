#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
// The `zerocopy` derive macros generate identifiers with a non-ASCII
// character in them, which nightly Rust warns about.
#![allow(uncommon_codepoints)]

use std::fs;
use std::io::{self, Error, ErrorKind, IoSlice, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(feature = "tempfile")]
use tempfile::TempDir;
use tpm2::Connection;
use zerocopy::network_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// Miri supports neither sockets nor child processes.
#[cfg(all(test, not(miri)))]
mod tests;

/// The simulator's default port for TPM commands.
pub const DEFAULT_TPM_PORT: u16 = 2321;

/// The simulator's default port for platform signals.
pub const DEFAULT_PLATFORM_PORT: u16 = 2322;

/// The environment variable read by [`TcpSimulator::launch_from_env`].
#[cfg(feature = "tempfile")]
pub const SIMULATOR_BIN_ENV: &str = "TPM_SIMULATOR_BIN";

/// A connection to a running TCG TPM 2.0 Simulator over TCP.
///
/// TPM commands are sent with the [`Connection`] trait. The other methods
/// control the simulator itself.
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
    /// Connects to a running TPM simulator, given the addresses of its TPM port
    /// and its Platform port.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection to the TPM or Platform port fails.
    pub fn connect(
        tpm: impl ToSocketAddrs,
        platform: impl ToSocketAddrs,
    ) -> io::Result<TcpConnection> {
        Ok(TcpConnection {
            tpm_tcp: TcpStream::connect(tpm)?,
            plat_tcp: TcpStream::connect(platform)?,
            locality: 0,
        })
    }

    /// Performs an H-CRTM Event Sequence against the TPM simulator.
    ///
    /// # Errors
    ///
    /// Returns an error if the communication with the TPM fails or if the
    /// response terminator is invalid.
    pub fn hcrtm_sequence(&mut self, data: &[u8]) -> io::Result<()> {
        // Send TPM_Hash_Start
        let cmd_code = U32::new(SimulatorTpmCommandCode::SignalHashStart as u32);
        self.tpm_tcp.write_all(cmd_code.as_bytes())?;
        Self::check_response_end(&mut self.tpm_tcp)?;

        // Send TPM_Hash_Data
        let cmd_code = U32::new(SimulatorTpmCommandCode::SignalHashData as u32);
        let cmd_hdr = &SignalHashDataRequestHeader {
            length: U32::new(data.len() as u32),
        };
        Self::write_parts(
            &mut self.tpm_tcp,
            &[cmd_code.as_bytes(), cmd_hdr.as_bytes(), data],
        )?;
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
    pub fn remote_handshake(&mut self, client_version: u32) -> io::Result<RemoteHandshakeResponse> {
        let cmd_code = U32::new(SimulatorTpmCommandCode::RemoteHandshake as u32);
        let cmd_payload = &RemoteHandshakeRequest {
            client_version: U32::new(client_version),
        };

        Self::write_parts(
            &mut self.tpm_tcp,
            &[cmd_code.as_bytes(), cmd_payload.as_bytes()],
        )?;

        let mut resp: RemoteHandshakeResponse = RemoteHandshakeResponse::default();
        self.tpm_tcp.read_exact(resp.as_mut_bytes())?;

        Self::check_response_end(&mut self.tpm_tcp)?;

        Ok(resp)
    }

    /// Sets an alternative result. The TCG simulator accepts this and ignores
    /// it.
    ///
    /// # Errors
    ///
    /// Returns an error if the communication with the TPM fails or if the
    /// response terminator is invalid.
    pub fn set_alternative_result(&mut self, result: u32) -> io::Result<()> {
        let cmd_code = U32::new(SimulatorTpmCommandCode::SetAlternativeResult as u32);
        let cmd_payload = &SetAlternativeResultRequest {
            result: U32::new(result),
        };

        Self::write_parts(
            &mut self.tpm_tcp,
            &[cmd_code.as_bytes(), cmd_payload.as_bytes()],
        )?;

        Self::check_response_end(&mut self.tpm_tcp)
    }

    /// Sends a signal to the Platform port of the TPM simulator.
    ///
    /// # Errors
    ///
    /// Returns an error if the communication with the Platform port fails or if
    /// the response terminator is invalid.
    pub fn platform_signal(&mut self, signal: SimulatorPlatformSignal) -> io::Result<()> {
        let cmd_code = U32::new(signal as u32);
        self.plat_tcp.write_all(cmd_code.as_bytes())?;

        Self::check_response_end(&mut self.plat_tcp)
    }

    /// Power cycles the TPM, causing the simulator to call `_TPM_Init`.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the platform signals fail.
    pub fn reinit(&mut self) -> io::Result<()> {
        self.platform_signal(SimulatorPlatformSignal::NvOff)?;
        self.platform_signal(SimulatorPlatformSignal::PowerOff)?;
        self.platform_signal(SimulatorPlatformSignal::PowerOn)?;
        self.platform_signal(SimulatorPlatformSignal::NvOn)?;
        Ok(())
    }

    /// Makes the TPM's next self-test fail, which puts the TPM into failure
    /// mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the communication with the Platform port fails or if
    /// the response terminator is invalid.
    pub fn test_failure_mode(&mut self) -> io::Result<()> {
        let cmd_code = U32::new(SimulatorPlatformCommandCode::TestFailureMode as u32);
        self.plat_tcp.write_all(cmd_code.as_bytes())?;

        Self::check_response_end(&mut self.plat_tcp)
    }

    /// Gets the largest command and the largest response the simulator has
    /// seen, and resets its record of them.
    ///
    /// # Errors
    ///
    /// Returns an error if the communication with the Platform port fails or if
    /// the response terminator is invalid.
    pub fn command_response_sizes(&mut self) -> io::Result<GetCommandResponseSizesResponse> {
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
    /// Returns an error if the communication with the Platform port fails or if
    /// the response terminator is invalid.
    pub fn act_signaled(&mut self, act_handle: u32) -> io::Result<u32> {
        let cmd_code = U32::new(SimulatorPlatformCommandCode::ActGetSignaled as u32);
        let cmd_payload = &ActGetSignaledRequest {
            act_handle: U32::new(act_handle),
        };

        Self::write_parts(
            &mut self.plat_tcp,
            &[cmd_code.as_bytes(), cmd_payload.as_bytes()],
        )?;

        let mut resp: ActGetSignaledResponse = ActGetSignaledResponse::default();
        self.plat_tcp.read_exact(resp.as_mut_bytes())?;

        Self::check_response_end(&mut self.plat_tcp)?;

        Ok(u32::from(resp.signaled))
    }

    /// Sets the firmware hash of the TPM.
    ///
    /// # Errors
    ///
    /// Returns an error if the communication with the Platform port fails or if
    /// the response terminator is invalid.
    pub fn set_firmware_hash(&mut self, hash: u32) -> io::Result<()> {
        let cmd_code = U32::new(SimulatorPlatformCommandCode::SetFirmwareHash as u32);
        let cmd_payload = &SetFirmwareHashRequest {
            hash: U32::new(hash),
        };

        Self::write_parts(
            &mut self.plat_tcp,
            &[cmd_code.as_bytes(), cmd_payload.as_bytes()],
        )?;

        Self::check_response_end(&mut self.plat_tcp)
    }

    /// Sets the firmware SVN of the TPM.
    ///
    /// # Errors
    ///
    /// Returns an error if the communication with the Platform port fails or if
    /// the response terminator is invalid.
    pub fn set_firmware_svn(&mut self, svn: u32) -> io::Result<()> {
        let cmd_code = U32::new(SimulatorPlatformCommandCode::SetFirmwareSvn as u32);
        let cmd_payload = &SetFirmwareSvnRequest { svn: U32::new(svn) };

        Self::write_parts(
            &mut self.plat_tcp,
            &[cmd_code.as_bytes(), cmd_payload.as_bytes()],
        )?;

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
    /// Returns an error if the communication with the TPM or Platform port
    /// fails.
    pub fn end_session(mut self) -> io::Result<()> {
        let cmd_code = U32::new(SimulatorTpmCommandCode::SessionEnd as u32);
        self.tpm_tcp.write_all(cmd_code.as_bytes())?;
        self.tpm_tcp.shutdown(Shutdown::Both)?;

        let cmd_code = U32::new(SimulatorPlatformCommandCode::SessionEnd as u32);
        self.plat_tcp.write_all(cmd_code.as_bytes())?;
        self.plat_tcp.shutdown(Shutdown::Both)?;

        Ok(())
    }

    /// Stops the TPM simulator, causing its process to exit.
    ///
    /// # Errors
    ///
    /// Returns an error if the communication with the TPM or Platform port
    /// fails.
    pub fn stop_simulator(mut self) -> io::Result<()> {
        self.send_stop()
    }

    /// Tells the simulator to exit. The connection is unusable afterwards.
    fn send_stop(&mut self) -> io::Result<()> {
        // The simulator exits once its TPM port is told to stop, so tell the
        // Platform port first, while the simulator is still there to hear it.
        let cmd_code = U32::new(SimulatorPlatformCommandCode::Stop as u32);
        self.plat_tcp.write_all(cmd_code.as_bytes())?;
        self.plat_tcp.shutdown(Shutdown::Both)?;

        let cmd_code = U32::new(SimulatorTpmCommandCode::Stop as u32);
        self.tpm_tcp.write_all(cmd_code.as_bytes())?;
        self.tpm_tcp.shutdown(Shutdown::Both)?;

        Ok(())
    }

    /// Limits how long reads from the simulator may block. `None` waits
    /// forever.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.tpm_tcp.set_read_timeout(timeout)?;
        self.plat_tcp.set_read_timeout(timeout)
    }

    /// Sends `parts` to the simulator in a single write.
    fn write_parts(stream: &mut TcpStream, parts: &[&[u8]]) -> io::Result<()> {
        let slices: Vec<_> = parts.iter().map(|part| IoSlice::new(part)).collect();
        let len: usize = parts.iter().map(|part| part.len()).sum();
        if stream.write_vectored(&slices)? != len {
            return Err(Error::new(
                ErrorKind::WriteZero,
                "failed to write entire command to TPM",
            ));
        }
        Ok(())
    }

    /// Reads the trailing zero from the TPM simulator response.
    fn check_response_end(stream: &mut TcpStream) -> io::Result<()> {
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
    fn transact<'a>(&mut self, command: &[u8], response: &'a mut [u8]) -> io::Result<&'a mut [u8]> {
        let cmd_size: u32 = command
            .len()
            .try_into()
            .map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;

        let cmd_code = U32::new(SimulatorTpmCommandCode::SendCommand as u32);
        let cmd_hdr = &SendCommandRequestHeader {
            locality: self.locality,
            length: U32::new(cmd_size),
        };

        Self::write_parts(
            &mut self.tpm_tcp,
            &[cmd_code.as_bytes(), cmd_hdr.as_bytes(), command],
        )?;

        let mut resp_hdr: SendCommandResponseHeader = SendCommandResponseHeader::default();
        self.tpm_tcp.read_exact(resp_hdr.as_mut_bytes())?;
        let resp_len = resp_hdr.length.get() as usize;
        if resp_len > response.len() {
            // Skip the response and its terminator, to stay in step with the
            // simulator.
            let unread = (resp_len + size_of::<U32>()) as u64;
            io::copy(&mut (&self.tpm_tcp).take(unread), &mut io::sink())?;
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "response buffer too small",
            ));
        }
        let response = &mut response[..resp_len];
        self.tpm_tcp.read_exact(response)?;

        // The TPM simulator completes each command with a u32 `0`.
        Self::check_response_end(&mut self.tpm_tcp)?;
        Ok(response)
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

/// The simulator's response to a remote handshake.
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

/// A signal that can be sent to the Platform port of the TPM simulator.
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
    /// Perform a TPM Reset (i.e. platform reboot / power on).
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

/// The largest command and the largest response the simulator has seen.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
#[repr(C)]
pub struct GetCommandResponseSizesResponse {
    // The simulator sends its C struct as it is in memory. The sizes are in
    // its native byte order. The codes are bytes copied from TPM buffers, so
    // they are big-endian.
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
    /// Returns the command code of the largest command.
    pub fn largest_command(&self) -> u32 {
        self.largest_command.get()
    }
    /// Returns the size of the largest response.
    pub fn largest_response_size(&self) -> u32 {
        self.largest_response_size
    }
    /// Returns the response code of the largest response.
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

/// How long a new simulator gets to start listening, and then to answer each
/// of its first requests.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a simulator gets to exit after it is asked to stop.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait between checks on a simulator that is starting or
/// stopping.
const POLL_INTERVAL: Duration = Duration::from_millis(1);

/// How many times to ask the OS for a free port that is followed by another.
const PORT_PICK_ATTEMPTS: usize = 16;

/// The client version sent in the startup handshake. Any non-zero value works.
const HANDSHAKE_CLIENT_VERSION: u32 = 1;

/// A TPM simulator process, and a connection to it.
///
/// The process is stopped, as by [`stop`](Self::stop), when this is dropped.
#[derive(Debug)]
pub struct TcpSimulator {
    /// The connection to the simulator.
    pub connection: TcpConnection,

    child: Child,

    /// The directory made by [`TcpSimulator::launch`]. It is removed when this
    /// is dropped, after the process has exited.
    #[cfg(feature = "tempfile")]
    _temp_dir: Option<TempDir>,
}

impl TcpSimulator {
    /// Starts the simulator binary at the absolute path `bin` in the
    /// directory `dir`, connects to it, and powers on its TPM.
    ///
    /// The simulator keeps its state (such as NV memory) in `dir`, which is
    /// created if needed. No other running simulator may use `dir`. Reusing
    /// it later resumes from the state left there.
    ///
    /// The binary is run as `<bin> <port>`, and must listen for TPM commands
    /// on `port` and for platform signals on `port + 1`. The port is picked
    /// so that any number of simulators can run at once.
    ///
    /// # Errors
    ///
    /// Returns an error if `bin` is not an absolute path, or if the simulator
    /// cannot be started, exits during startup, or does not answer on both
    /// ports in time.
    pub fn launch_in(bin: &Path, dir: &Path) -> io::Result<TcpSimulator> {
        // The simulator runs in `dir`, where a relative path would name a
        // different file.
        if !bin.is_absolute() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("simulator binary {bin:?} is not an absolute path"),
            ));
        }
        fs::create_dir_all(dir)?;

        // Nothing reserves the ports between us picking them and the simulator
        // listening on them, so only one thread starts a simulator at a time.
        static STARTUP_LOCK: Mutex<()> = Mutex::new(());
        let _startup = STARTUP_LOCK.lock().unwrap_or_else(PoisonError::into_inner);

        // Like the simulator, we listen on all interfaces to find out if a port
        // is free.
        let is_free = |port| TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).is_ok();
        let tpm_port = (0..PORT_PICK_ATTEMPTS)
            .find_map(|_| {
                // Port 0 asks the OS for any free port.
                let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
                let port = listener.local_addr().ok()?.port();
                drop(listener);
                // The simulator asks for its ports by number, which can fail
                // even for a port the OS just suggested. So ask by number too.
                (is_free(port) && is_free(port.checked_add(1)?)).then_some(port)
            })
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::AddrInUse,
                    "could not find two consecutive free ports",
                )
            })?;

        let mut child = Command::new(bin)
            .arg(tpm_port.to_string())
            .current_dir(dir)
            .stdin(Stdio::null())
            // TODO: Capture stdout/stderr to display when requested.
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| Error::new(e.kind(), format!("failed to start simulator {bin:?}: {e}")))?;

        // Connect as soon as the simulator listens on both of its ports.
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        let connection = loop {
            // A simulator that cannot listen on its TPM port exits, and
            // reports success when it does.
            if let Some(status) = child.try_wait()? {
                return Err(Error::other(format!(
                    "simulator exited during startup ({status})"
                )));
            }
            match TcpConnection::connect(
                (Ipv4Addr::LOCALHOST, tpm_port),
                (Ipv4Addr::LOCALHOST, tpm_port + 1),
            ) {
                Ok(connection) => break connection,
                Err(e) if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(Error::new(
                        e.kind(),
                        format!("simulator is not listening: {e}"),
                    ));
                }
                Err(_) => thread::sleep(POLL_INTERVAL),
            }
        };
        // From here on, an early return drops `simulator`, stopping the
        // process.
        let mut simulator = TcpSimulator {
            connection,
            child,
            #[cfg(feature = "tempfile")]
            _temp_dir: None,
        };

        // Another program may have taken one of our ports before the simulator
        // could, in which case we are now connected to that program. Make a
        // request on each port, with a timeout, to fail instead of hanging.
        // Powering on the TPM also makes it accept commands.
        let connection = &mut simulator.connection;
        connection.set_read_timeout(Some(STARTUP_TIMEOUT))?;
        connection
            .remote_handshake(HANDSHAKE_CLIENT_VERSION)
            .and_then(|_| connection.platform_signal(SimulatorPlatformSignal::PowerOn))
            .map_err(|e| Error::new(e.kind(), format!("simulator did not answer: {e}")))?;
        connection.set_read_timeout(None)?;

        Ok(simulator)
    }

    /// Like [`launch_in`](Self::launch_in), in a new temporary directory.
    ///
    /// The simulator starts from fresh state. The directory is removed when
    /// the simulator is dropped.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created, or if
    /// [`launch_in`](Self::launch_in) fails.
    #[cfg(feature = "tempfile")]
    pub fn launch(bin: &Path) -> io::Result<TcpSimulator> {
        let temp_dir = tempfile::tempdir()?;
        let mut simulator = Self::launch_in(bin, temp_dir.path())?;
        simulator._temp_dir = Some(temp_dir);
        Ok(simulator)
    }

    /// Like [`launch`](Self::launch), running the binary whose absolute path
    /// is in the `TPM_SIMULATOR_BIN` environment variable
    /// ([`SIMULATOR_BIN_ENV`]).
    ///
    /// # Errors
    ///
    /// Returns an error if the variable is unset or empty, or if
    /// [`launch`](Self::launch) fails.
    #[cfg(feature = "tempfile")]
    pub fn launch_from_env() -> io::Result<TcpSimulator> {
        match std::env::var_os(SIMULATOR_BIN_ENV) {
            Some(bin) if !bin.is_empty() => Self::launch(Path::new(&bin)),
            _ => Err(Error::new(
                ErrorKind::NotFound,
                format!("set {SIMULATOR_BIN_ENV} to the absolute path of a TPM simulator binary"),
            )),
        }
    }

    /// Stops the simulator process, and returns how it exited.
    ///
    /// The simulator is asked to exit, and is killed if it does not.
    ///
    /// # Errors
    ///
    /// Returns an error if waiting for the process fails.
    pub fn stop(mut self) -> io::Result<ExitStatus> {
        self.shut_down()
    }

    /// Makes sure the process has exited, and returns how it exited.
    fn shut_down(&mut self) -> io::Result<ExitStatus> {
        // Asking first lets the simulator finish up (a coverage build writes
        // its data on exit, for example).
        if self.connection.send_stop().is_ok() {
            let deadline = Instant::now() + STOP_TIMEOUT;
            while Instant::now() < deadline {
                if let Some(status) = self.child.try_wait()? {
                    return Ok(status);
                }
                thread::sleep(POLL_INTERVAL);
            }
        }
        // It could not be asked (as when this runs again on drop, after
        // `stop`), or it did not listen.
        let _ = self.child.kill();
        self.child.wait()
    }
}

impl Drop for TcpSimulator {
    fn drop(&mut self) {
        let _ = self.shut_down();
    }
}
