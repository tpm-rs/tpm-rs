#![forbid(unsafe_code)]
use std::io::{Read, Write};

use tpm2_impl::storage::ram_storage_mock::RamStorageMock;
pub mod execute;
pub use execute::ExecuteError;

use clap::Parser;

/// Simulator configuration arguments.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Port to listen on (will try subsequent ports if in use and --pick_ports is used)
    #[arg(short = 'p', long, alias = "pick_ports", default_value_t = false)]
    pub pick_ports: bool,
}

use tpm2::commands::{Command, Startup};
use tpm2::{Marshal, TpmSu, Unmarshal};
use tpm2_impl::{InternalError, TpmEngine};
use tpm2_platform_linux::{LinuxRng, LinuxTimer, PlatformCryptoProvider, create_linux_platform};

/// Commands for the command server.
const TPM_SIGNAL_HASH_START: u32 = 5;
const TPM_SIGNAL_HASH_DATA: u32 = 6;
const TPM_SIGNAL_HASH_END: u32 = 7;
const TPM_SEND_COMMAND: u32 = 8;
const TPM_REMOTE_HANDSHAKE: u32 = 15;
const TPM_SET_ALTERNATIVE_RESULT: u32 = 16;
const TPM_SESSION_END: u32 = 20;
const TPM_STOP: u32 = 21;

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

impl TryFrom<u32> for SimulatorPlatformSignal {
    type Error = ();

    fn try_from(v: u32) -> core::result::Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::PowerOn),
            2 => Ok(Self::PowerOff),
            3 => Ok(Self::PhysicalPresenceOn),
            4 => Ok(Self::PhysicalPresenceOff),
            9 => Ok(Self::CancelOn),
            10 => Ok(Self::CancelOff),
            11 => Ok(Self::NvOn),
            12 => Ok(Self::NvOff),
            13 => Ok(Self::KeyCacheOn),
            14 => Ok(Self::KeyCacheOff),
            17 => Ok(Self::Reset),
            18 => Ok(Self::Restart),
            20 => Ok(Self::SessionEnd),
            21 => Ok(Self::Stop),
            25 => Ok(Self::GetCommandResponseSizes),
            26 => Ok(Self::ActGetSignaled),
            30 => Ok(Self::TestFailureMode),
            35 => Ok(Self::SetFirmwareHash),
            36 => Ok(Self::SetFirmwareSvn),
            _ => Err(()),
        }
    }
}

pub struct SimCommand<'a> {
    pub command_code: u32,
    pub locality: u8,
    pub payload: &'a [u8],
}

impl<'a> SimCommand<'a> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.command_code.to_be_bytes());
        buf.push(self.locality);
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(self.payload);
        buf
    }
}

pub struct SimResponse {
    pub length: u32,
    pub response: Vec<u8>,
    pub success: u32,
}

impl SimResponse {
    pub fn parse(bytes: &[u8]) -> Self {
        let length = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let resp_len = length as usize;
        let response = bytes[4..4 + resp_len].to_vec();
        let success_offset = 4 + resp_len;
        let success = u32::from_be_bytes([
            bytes[success_offset],
            bytes[success_offset + 1],
            bytes[success_offset + 2],
            bytes[success_offset + 3],
        ]);
        Self {
            length,
            response,
            success,
        }
    }
}

/// An in-process TPM simulator.
///
/// The engine and its state are private: clients interact with the TPM only
/// through the command interface ([`Simulator::execute`],
/// [`Simulator::execute_with_handles`], [`Simulator::transact`]) and platform
/// signals ([`Simulator::signal_platform`]), exactly like a real TPM.
pub struct Simulator<'a> {
    context: Box<TpmEngine<'a, PlatformCryptoProvider, RamStorageMock<4096>, LinuxTimer, LinuxRng>>,
    global_state: Box<::tpm2_impl::GlobalState>,
    is_power_on: bool,
    is_nv_on: bool,
}

impl<'a> Simulator<'a> {
    pub fn new(
        crypto: &'a mut PlatformCryptoProvider,
        storage: &'a mut RamStorageMock<4096>,
        timer: &'a mut LinuxTimer,
        platform_rng: &'a LinuxRng,
    ) -> Result<Self, InternalError> {
        let platform = create_linux_platform(crypto, storage, timer, platform_rng);
        let mut context = Box::new(TpmEngine::new(platform).unwrap());
        let mut global_state = Box::new(::tpm2_impl::GlobalState::default());
        context.init_storage(&mut global_state);
        Ok(Self {
            context,
            global_state,
            is_power_on: false,
            is_nv_on: false,
        })
    }

    pub fn power_on_start_up(&mut self) {
        self.signal_platform(SimulatorPlatformSignal::PowerOn)
            .unwrap();
        self.signal_platform(SimulatorPlatformSignal::NvOn).unwrap();
        let startup = Startup {
            startup_type: TpmSu::Clear,
        };
        self.execute(startup).unwrap();
    }

    pub fn signal_platform(&mut self, command: SimulatorPlatformSignal) -> anyhow::Result<()> {
        let mut stream = std::io::Cursor::new(Vec::new());
        self.handle_platform_command_raw(command as u32, &mut stream)?;
        let output_data = stream.into_inner();
        if output_data.len() >= 4 {
            let result = u32::from_be_bytes(output_data[0..4].try_into().unwrap());
            if result != 0 {
                anyhow::bail!("Platform command {} failed with {}", command as u32, result);
            }
        }
        Ok(())
    }

    pub fn handle_regular_command_raw<S: Read + Write>(
        &mut self,
        command: u32,
        stream: &mut S,
    ) -> anyhow::Result<bool> {
        match command {
            TPM_SIGNAL_HASH_START => {
                self.context.hash_start(&mut self.global_state);
                stream.write_all(&0u32.to_be_bytes())?;
            }
            TPM_SIGNAL_HASH_DATA => {
                // SignalHashData
                let mut len_buf = [0u8; 4];
                stream.read_exact(&mut len_buf)?;
                let length = u32::from_be_bytes(len_buf) as usize;
                if length > 4096 {
                    anyhow::bail!("Hash data length {} exceeds maximum of 4096", length);
                }
                let mut input_buffer = vec![0u8; length];
                stream.read_exact(&mut input_buffer)?;
                self.context
                    .hash_data(&mut self.global_state, &input_buffer);
                stream.write_all(&0u32.to_be_bytes())?;
            }
            TPM_SIGNAL_HASH_END => {
                self.context.hash_end(&mut self.global_state);
                stream.write_all(&0u32.to_be_bytes())?;
            }
            TPM_SEND_COMMAND => {
                // 8
                let mut loc_buf = [0u8; 1];
                stream.read_exact(&mut loc_buf)?;

                let mut len_buf = [0u8; 4];
                stream.read_exact(&mut len_buf)?;
                let length = u32::from_be_bytes(len_buf) as usize;
                if length > 8192 {
                    anyhow::bail!("Command length {} exceeds maximum of 8192", length);
                }

                let mut input_buffer = vec![0u8; length];
                stream.read_exact(&mut input_buffer)?;

                if !self.is_power_on {
                    stream.write_all(&0u32.to_be_bytes())?; // return 0 response size
                    return Ok(false);
                }

                // Execute command
                self.global_state.locality = loc_buf[0];
                let mut output_buffer = vec![0u8; 4096];
                let written = self.context.execute_command_separate(
                    &mut self.global_state,
                    &input_buffer[..],
                    &mut output_buffer[..],
                );

                let cmd_code = if input_buffer.len() >= 10 {
                    u32::from_be_bytes(input_buffer[6..10].try_into().unwrap())
                } else {
                    0
                };
                let resp_rc = if written >= 10 {
                    u32::from_be_bytes(output_buffer[6..10].try_into().unwrap())
                } else {
                    0
                };
                if resp_rc != 0 {
                    eprintln!(
                        "SIMULATOR: CMD 0x{:X} -> RC 0x{:X} (cmd_len={}, resp_len={})",
                        cmd_code,
                        resp_rc,
                        input_buffer.len(),
                        written
                    );
                }

                // Write response
                // format: response length (4 bytes), response bytes, success code (4 bytes, 0)
                let resp_len = written as u32;
                stream.write_all(&resp_len.to_be_bytes())?;
                stream.write_all(&output_buffer[..written])?;
                stream.write_all(&0u32.to_be_bytes())?;
            }
            TPM_REMOTE_HANDSHAKE => {
                // RemoteHandshake
                let mut _payload = [0u8; 4];
                stream.read_exact(&mut _payload)?;

                let mut data = vec![];
                data.extend_from_slice(&1u32.to_be_bytes()); // server_version
                // endpoint_info: tpmPlatformAvailable (1) | tpmInRawMode (4) | tpmSupportsPP (8) = 13
                data.extend_from_slice(&13u32.to_be_bytes());

                stream.write_all(&data)?;
                stream.write_all(&0u32.to_be_bytes())?;
            }
            TPM_SET_ALTERNATIVE_RESULT => {
                // SetAlternativeResult
                let mut _payload = [0u8; 4];
                stream.read_exact(&mut _payload)?;
                stream.write_all(&0u32.to_be_bytes())?;
            }
            TPM_SESSION_END => {
                // 20
                let _ = stream.write_all(&0u32.to_be_bytes());
                return Ok(true); // Finish
            }
            TPM_STOP => {
                // Stop
                let _ = stream.write_all(&0u32.to_be_bytes());
                std::process::exit(0);
            }
            _ => {
                // SignalHashStart, SignalHashEnd, etc.
                stream.write_all(&0u32.to_be_bytes())?;
            }
        }
        Ok(false)
    }

    pub fn handle_platform_command_raw<S: Read + Write>(
        &mut self,
        command: u32,
        stream: &mut S,
    ) -> anyhow::Result<bool> {
        let Ok(code) = SimulatorPlatformSignal::try_from(command) else {
            anyhow::bail!("Invalid platform signal: {}", command);
        };
        match code {
            SimulatorPlatformSignal::SessionEnd => {
                // SessionEnd
                let _ = stream.write_all(&0u32.to_be_bytes());
                return Ok(true);
            }
            SimulatorPlatformSignal::Stop => {
                // Stop
                let _ = stream.write_all(&0u32.to_be_bytes());
                std::process::exit(0);
            }
            SimulatorPlatformSignal::GetCommandResponseSizes => {
                // GetCommandResponseSizes
                let mut data = vec![];
                data.extend_from_slice(&16u32.to_be_bytes()); // length
                data.extend_from_slice(&4096u32.to_be_bytes()); // largest_command_size
                data.extend_from_slice(&0u32.to_be_bytes()); // largest_command
                data.extend_from_slice(&4096u32.to_be_bytes()); // largest_response_size
                data.extend_from_slice(&0u32.to_be_bytes()); // largest_response

                stream.write_all(&data)?;
                stream.write_all(&0u32.to_be_bytes())?;
            }
            SimulatorPlatformSignal::ActGetSignaled => {
                // ActGetSignaled
                let mut _payload = [0u8; 4];
                stream.read_exact(&mut _payload)?;
                let data = 0u32.to_be_bytes(); // signaled (false)
                stream.write_all(&data)?;
                stream.write_all(&0u32.to_be_bytes())?;
            }
            SimulatorPlatformSignal::PowerOn => {
                self.is_power_on = true;
                self.context.reset(&mut self.global_state);
                stream.write_all(&0u32.to_be_bytes())?;
            }
            SimulatorPlatformSignal::PowerOff => {
                self.is_power_on = false;
                stream.write_all(&0u32.to_be_bytes())?;
            }
            SimulatorPlatformSignal::Reset => {
                self.is_power_on = true;
                self.context.reset(&mut self.global_state);
                stream.write_all(&0u32.to_be_bytes())?;
            }
            SimulatorPlatformSignal::NvOn => {
                if self.is_power_on {
                    self.is_nv_on = true;
                    // Matches `_plat__SetNvAvail()`: NV becomes available to the TPM again.
                    self.global_state.nv_available = true;
                }
                stream.write_all(&0u32.to_be_bytes())?;
            }
            SimulatorPlatformSignal::NvOff => {
                // Matches `_plat__ClearNvAvail()`: subsequent commands that need NV fail with
                // `TPM_RC_NV_UNAVAILABLE` (`NvCheckState` / `RETURN_IF_NV_IS_NOT_AVAILABLE`).
                self.is_nv_on = false;
                self.global_state.nv_available = false;
                stream.write_all(&0u32.to_be_bytes())?;
            }
            SimulatorPlatformSignal::SetFirmwareHash | SimulatorPlatformSignal::SetFirmwareSvn => {
                // SetFirmwareHash / SetFirmwareSvn
                let mut _payload = [0u8; 4];
                stream.read_exact(&mut _payload)?;
                stream.write_all(&0u32.to_be_bytes())?;
            }
            SimulatorPlatformSignal::TestFailureMode => {
                // All signals (PowerOn, PowerOff, etc.)
                stream.write_all(&0u32.to_be_bytes())?;
            }
            _ => {
                // All signals (PowerOn, PowerOff, etc.)
                stream.write_all(&0u32.to_be_bytes())?;
            }
        }
        Ok(false)
    }

    pub fn execute<Cmd: Command>(
        &mut self,
        cmd: Cmd,
    ) -> Result<Cmd::Response<'static>, ExecuteError>
    where
        Cmd::Response<'static>: Unmarshal<'static>,
        for<'d> &'d mut Cmd::MaxBuffer: TryFrom<&'d mut [u8]>,
        for<'d> &'d mut <Cmd::Handles as Marshal>::MaxBuffer: TryFrom<&'d mut [u8]>,
    {
        execute::run_command(&cmd, self)
    }

    pub fn execute_with_handles<Cmd: Command>(
        &mut self,
        cmd: Cmd,
        handles: Cmd::Handles,
    ) -> Result<(Cmd::Response<'static>, Cmd::RespHandles), ExecuteError>
    where
        Cmd::Response<'static>: Unmarshal<'static>,
        for<'d> &'d mut Cmd::MaxBuffer: TryFrom<&'d mut [u8]>,
        for<'d> &'d mut <Cmd::Handles as Marshal>::MaxBuffer: TryFrom<&'d mut [u8]>,
    {
        execute::run_command_with_handles(&cmd, handles, self)
    }

    pub fn transact<'b>(
        &mut self,
        cmd: &[u8],
        rsp: &'b mut [u8],
    ) -> Result<&'b mut [u8], ExecuteError> {
        let mut input_data = Vec::new();
        input_data.push(0u8); // Locality
        input_data.extend_from_slice(&(cmd.len() as u32).to_be_bytes()); // Length
        input_data.extend_from_slice(cmd); // Payload

        let mut stream = std::io::Cursor::new(input_data);

        self.handle_regular_command_raw(TPM_SEND_COMMAND, &mut stream)
            .map_err(|_| ExecuteError::Unexpected)?;

        let output_data = stream.into_inner();
        let resp_start = 1 + 4 + cmd.len();

        let resp_len_bytes: [u8; 4] = output_data[resp_start..resp_start + 4].try_into().unwrap();
        let resp_len = u32::from_be_bytes(resp_len_bytes) as usize;

        let response_bytes = &output_data[resp_start + 4..resp_start + 4 + resp_len];

        rsp[..resp_len].copy_from_slice(response_bytes);
        Ok(&mut rsp[..resp_len])
    }
}

/// Implementation details used by [`create_simulator!`].
///
/// These re-exports let the macro expand in downstream crates without
/// requiring them to depend on (or import anything from) `tpm2-impl` or
/// `tpm2-platform-linux`. Not part of the public API.
#[doc(hidden)]
pub mod __private {
    pub use tpm2_impl::storage::ram_storage_mock::RamStorageMock;
    pub use tpm2_platform_linux::{LinuxRng, LinuxTimer, PlatformCryptoProvider};
}

/// Creates a fresh, self-contained in-process [`Simulator`] that has been
/// powered on, had NV enabled, and received `TPM2_Startup(TPM_SU_CLEAR)`.
///
/// Every invocation allocates its own crypto provider, RAM-backed NV storage,
/// timer and platform RNG (leaked to obtain a `'static` lifetime), so
/// simulators created by different tests — or by repeated calls of the same
/// helper — never share TPM state.
///
/// The expansion only refers to items through `$crate`, so callers need no
/// imports besides the macro itself.
#[macro_export]
macro_rules! create_simulator {
    () => {{
        let crypto: &'static mut $crate::__private::PlatformCryptoProvider =
            ::std::boxed::Box::leak(::std::boxed::Box::new(
                $crate::__private::PlatformCryptoProvider,
            ));
        let storage: &'static mut $crate::__private::RamStorageMock<4096> = ::std::boxed::Box::leak(
            ::std::boxed::Box::new($crate::__private::RamStorageMock::new()),
        );
        let timer: &'static mut $crate::__private::LinuxTimer =
            ::std::boxed::Box::leak(::std::boxed::Box::new($crate::__private::LinuxTimer::new()));
        let platform_rng: &'static $crate::__private::LinuxRng =
            ::std::boxed::Box::leak(::std::boxed::Box::new($crate::__private::LinuxRng::new()));
        let mut sim = $crate::Simulator::new(crypto, storage, timer, platform_rng)
            .expect("failed to create TPM simulator");
        sim.power_on_start_up();
        sim
    }};
}
