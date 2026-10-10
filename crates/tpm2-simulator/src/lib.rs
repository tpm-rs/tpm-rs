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

use tpm2::TpmSu;
use tpm2::commands::{Command, Startup};
use tpm2_impl::{InternalError, TpmEngine};
use tpm2_platform_linux::{LinuxTimer, PlatformCryptoProvider, create_linux_platform};

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

impl From<SimulatorPlatformSignal> for u32 {
    fn from(signal: SimulatorPlatformSignal) -> Self {
        signal as u32
    }
}

/// Reads the big-endian `u32` at `offset` in `bytes`, if present.
fn be_u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..)?
        .first_chunk::<4>()
        .map(|b| u32::from_be_bytes(*b))
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
        // PORTING: exp truncated with `as u32`; saturate instead.
        let length = u32::try_from(self.payload.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&length.to_be_bytes());
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
    /// Parses a simulator response.
    ///
    /// PORTING: exp panicked on truncated input; returns `None` instead.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let length = be_u32_at(bytes, 0)?;
        let resp_len = usize::try_from(length).ok()?;
        let success_offset = resp_len.checked_add(4)?;
        let response = bytes.get(4..success_offset)?.to_vec();
        let success = be_u32_at(bytes, success_offset)?;
        Some(Self {
            length,
            response,
            success,
        })
    }
}

pub struct Simulator<'a> {
    pub context: Box<TpmEngine<'a, PlatformCryptoProvider, RamStorageMock<4096>, LinuxTimer>>,
    pub global_state: Box<::tpm2_impl::GlobalState>,
    pub is_power_on: bool,
    pub is_nv_on: bool,
}

impl<'a> Simulator<'a> {
    /// Creates a simulator using the given platform resources.
    ///
    /// PORTING: exp also took the platform RNG (`&LinuxRng`); the global RNG is now created
    /// from `crypto` (see [`create_linux_platform`]), which is only borrowed immutably.
    pub fn new(
        crypto: &'a PlatformCryptoProvider,
        storage: &'a mut RamStorageMock<4096>,
        timer: &'a mut LinuxTimer,
    ) -> Result<Self, InternalError> {
        let platform = create_linux_platform(crypto, storage, timer)
            .map_err(|_| InternalError::HardwareError)?;
        let mut context = Box::new(TpmEngine::new(platform)?);
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
            .expect("PowerOn signal failed");
        self.signal_platform(SimulatorPlatformSignal::NvOn)
            .expect("NvOn signal failed");
        let startup = Startup {
            startup_type: TpmSu::Clear,
        };
        self.execute(startup).expect("TPM2_Startup(CLEAR) failed");
    }

    pub fn signal_platform(&mut self, command: SimulatorPlatformSignal) -> anyhow::Result<()> {
        let mut stream = std::io::Cursor::new(Vec::new());
        self.handle_platform_command_raw(u32::from(command), &mut stream)?;
        let output_data = stream.into_inner();
        if let Some(result) = be_u32_at(&output_data, 0)
            && result != 0
        {
            anyhow::bail!(
                "Platform command {} failed with {}",
                u32::from(command),
                result
            );
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
                let length = usize::try_from(u32::from_be_bytes(len_buf))?;
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
                let length = usize::try_from(u32::from_be_bytes(len_buf))?;
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
                let [locality] = loc_buf;
                self.global_state.locality = locality;
                let mut output_buffer = vec![0u8; 4096];
                let written = self.context.execute_command_separate(
                    &mut self.global_state,
                    &input_buffer[..],
                    &mut output_buffer[..],
                );

                let cmd_code = be_u32_at(&input_buffer, 6).unwrap_or(0);
                let resp_rc = output_buffer
                    .get(..written)
                    .and_then(|response| be_u32_at(response, 6))
                    .unwrap_or(0);
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
                let response = output_buffer
                    .get(..written)
                    .ok_or_else(|| anyhow::anyhow!("Response length {} exceeds buffer", written))?;
                let resp_len = u32::try_from(written)?;
                stream.write_all(&resp_len.to_be_bytes())?;
                stream.write_all(response)?;
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
                }
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

    /// Executes `cmd`, adding an empty password session for each handle that requires
    /// authorization.
    ///
    /// PORTING: the new `tpm2` commands carry their handles (see [`tpm2::Message::handles`]) and
    /// responses carry their response handles, so exp's `execute_with_handles(cmd, handles)`
    /// (which returned `(response, response_handles)`) is folded into this method.
    pub fn execute<Cmd: Command<MaxBuffer = [u8; N]>, const N: usize>(
        &mut self,
        cmd: Cmd,
    ) -> Result<Cmd::Response<'static>, ExecuteError> {
        execute::run_command(&cmd, self)
    }

    pub fn transact<'b>(
        &mut self,
        cmd: &[u8],
        rsp: &'b mut [u8],
    ) -> Result<&'b mut [u8], ExecuteError> {
        let mut input_data = Vec::new();
        input_data.push(0u8); // Locality
        let cmd_len = u32::try_from(cmd.len()).map_err(|_| ExecuteError::CommandTooLarge)?;
        input_data.extend_from_slice(&cmd_len.to_be_bytes()); // Length
        input_data.extend_from_slice(cmd); // Payload

        let mut stream = std::io::Cursor::new(input_data);

        self.handle_regular_command_raw(TPM_SEND_COMMAND, &mut stream)
            .map_err(|_| ExecuteError::Unexpected)?;

        let output_data = stream.into_inner();
        let resp_start = 1 + 4 + cmd.len();

        let resp_len = be_u32_at(&output_data, resp_start).ok_or(ExecuteError::Unexpected)?;
        let resp_len = usize::try_from(resp_len).map_err(|_| ExecuteError::ResponseTooLarge)?;

        let response_bytes = output_data
            .get(resp_start + 4..)
            .and_then(|bytes| bytes.get(..resp_len))
            .ok_or(ExecuteError::Unexpected)?;

        let rsp = rsp
            .get_mut(..resp_len)
            .ok_or(ExecuteError::ResponseTooLarge)?;
        rsp.copy_from_slice(response_bytes);
        Ok(rsp)
    }
}

/// Creates a powered-on [`Simulator`] (after `TPM2_Startup(CLEAR)`) with `'static` platform
/// resources.
///
/// PORTING: exp backed each expansion with `static mut` resources (and `unsafe`), which aliases
/// them if an expansion runs more than once. Each expansion now leaks fresh resources instead,
/// so no `unsafe` (or `LinuxRng` import) is needed at the call site.
#[macro_export]
macro_rules! create_simulator {
    () => {{
        let crypto: &'static ::tpm2_platform_linux::PlatformCryptoProvider =
            ::std::boxed::Box::leak(::std::boxed::Box::new(
                ::tpm2_platform_linux::PlatformCryptoProvider,
            ));
        let storage: &'static mut ::tpm2_impl::storage::ram_storage_mock::RamStorageMock<4096> =
            ::std::boxed::Box::leak(::std::boxed::Box::new(
                ::tpm2_impl::storage::ram_storage_mock::RamStorageMock::new(),
            ));
        let timer: &'static mut ::tpm2_platform_linux::LinuxTimer = ::std::boxed::Box::leak(
            ::std::boxed::Box::new(::tpm2_platform_linux::LinuxTimer::new()),
        );
        let mut sim = $crate::Simulator::new(crypto, storage, timer)
            .expect("failed to create the TPM simulator");
        sim.power_on_start_up();
        sim
    }};
}
