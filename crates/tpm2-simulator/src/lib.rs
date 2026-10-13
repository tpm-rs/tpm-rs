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

use tpm2::Connection;
use tpm2::commands::Command;
use tpm2_impl::{InternalError, TpmEngine};
pub use tpm2_impl::{NO_STREAM, PlatformConnection, SimulatorPlatformSignal};
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
/// through the command interface ([`Simulator::execute`] and
/// [`Connection::transact`]) and platform signals
/// ([`PlatformConnection::signal_platform`]), exactly like a real TPM.
pub struct Simulator<'a> {
    context: Box<TpmEngine<'a, PlatformCryptoProvider, RamStorageMock<4096>, LinuxTimer, LinuxRng>>,
    is_power_on: bool,
    is_nv_on: bool,
    /// Seeded stream used as the crypto provider's randomness while this
    /// simulator executes commands and signals (see [`Simulator::pin_crypto_rng`]).
    #[cfg(all(feature = "reproducible", feature = "bssl"))]
    crypto_rng: Option<tpm2_platform_linux::CryptoReplayRng>,
}

impl<'a> Simulator<'a> {
    pub fn new(
        crypto: &'a mut PlatformCryptoProvider,
        storage: &'a mut RamStorageMock<4096>,
        timer: &'a mut LinuxTimer,
        platform_rng: &'a mut LinuxRng,
    ) -> Result<Self, InternalError> {
        let platform = create_linux_platform(crypto, storage, timer, platform_rng);
        let mut context = Box::new(TpmEngine::new(platform)?);
        context.init_storage();
        Ok(Self {
            context,
            is_power_on: false,
            is_nv_on: false,
            #[cfg(all(feature = "reproducible", feature = "bssl"))]
            crypto_rng: None,
        })
    }

    /// Runs `f` as TPM-side work: with the `reproducible` feature and a pinned crypto
    /// stream, the crypto provider draws its randomness from that stream while
    /// `f` runs, and only then.
    fn in_tpm_scope<R>(&mut self, f: impl FnOnce(&mut Self) -> R) -> R {
        #[cfg(all(feature = "reproducible", feature = "bssl"))]
        if let Some(mut rng) = self.crypto_rng.take() {
            let r = rng.scope(|| f(self));
            self.crypto_rng = Some(rng);
            return r;
        }
        f(self)
    }

    /// Handles one command-port transaction (see [`PlatformConnection::transact_platform`]).
    pub(crate) fn handle_regular_command_raw<S: Read + Write>(
        &mut self,
        command: u32,
        stream: &mut S,
    ) -> anyhow::Result<bool> {
        self.in_tpm_scope(|sim| sim.regular_command(command, stream))
    }

    fn regular_command<S: Read + Write>(
        &mut self,
        command: u32,
        stream: &mut S,
    ) -> anyhow::Result<bool> {
        match command {
            TPM_SIGNAL_HASH_START => {
                self.context.hash_start();
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
                self.context.hash_data(&input_buffer);
                stream.write_all(&0u32.to_be_bytes())?;
            }
            TPM_SIGNAL_HASH_END => {
                self.context.hash_end();
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
                self.context.set_locality(loc_buf[0]);
                let mut output_buffer = vec![0u8; 4096];
                let written = self
                    .context
                    .execute_command_separate(&input_buffer[..], &mut output_buffer[..]);

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

    /// Processes the platform signal `code`, reading its payload from and writing its reply
    /// (reply data, then a 4-byte result code) to `stream`. Returns `true` if the platform
    /// session ends.
    fn handle_platform_signal<S: Read + Write>(
        &mut self,
        code: SimulatorPlatformSignal,
        stream: &mut S,
    ) -> anyhow::Result<bool> {
        self.in_tpm_scope(|sim| sim.platform_signal(code, stream))
    }

    /// Implementation of [`Simulator::handle_platform_signal`], run inside
    /// [`Simulator::in_tpm_scope`].
    fn platform_signal<S: Read + Write>(
        &mut self,
        code: SimulatorPlatformSignal,
        stream: &mut S,
    ) -> anyhow::Result<bool> {
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
                self.context.reset();
                stream.write_all(&0u32.to_be_bytes())?;
            }
            SimulatorPlatformSignal::PowerOff => {
                self.is_power_on = false;
                stream.write_all(&0u32.to_be_bytes())?;
            }
            SimulatorPlatformSignal::Reset => {
                self.is_power_on = true;
                self.context.reset();
                stream.write_all(&0u32.to_be_bytes())?;
            }
            SimulatorPlatformSignal::NvOn => {
                if self.is_power_on {
                    self.is_nv_on = true;
                    // Matches `_plat__SetNvAvail()`: NV becomes available to the TPM again.
                    self.context.set_nv_available(true);
                }
                stream.write_all(&0u32.to_be_bytes())?;
            }
            SimulatorPlatformSignal::NvOff => {
                // Matches `_plat__ClearNvAvail()`: subsequent commands that need NV fail with
                // `TPM_RC_NV_UNAVAILABLE` (`NvCheckState` / `RETURN_IF_NV_IS_NOT_AVAILABLE`).
                self.is_nv_on = false;
                self.context.set_nv_available(false);
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

    /// Runs `cmd` and returns its response.
    ///
    /// The command carries its handles and the response carries its response
    /// handles. See [`execute::run_command`] for the sessions that are added
    /// and the errors that can occur.
    pub fn execute<Cmd: Command>(
        &mut self,
        cmd: Cmd,
    ) -> Result<Cmd::Response<'static>, ExecuteError>
    where
        for<'d> &'d mut Cmd::MaxBuffer: TryFrom<&'d mut [u8]>,
    {
        execute::run_command(&cmd, self)
    }
}

/// Sends commands through the simulator's MSSIM command path at locality 0: while the simulator
/// is powered off, the response is empty.
impl Connection for Simulator<'_> {
    type Error = ExecuteError;

    fn transact<'b>(&mut self, cmd: &[u8], rsp: &'b mut [u8]) -> Result<&'b mut [u8], Self::Error> {
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

impl PlatformConnection for Simulator<'_> {
    fn signal_platform<S: Read + Write>(
        &mut self,
        command: SimulatorPlatformSignal,
        stream: Option<&mut S>,
    ) -> anyhow::Result<bool> {
        if let Some(stream) = stream {
            return self.handle_platform_signal(command, stream);
        }
        // No stream: the signal carries no payload, and the reply is checked here. Every reply
        // ends with the 4-byte result code.
        let mut reply = std::io::Cursor::new(Vec::new());
        let session_end = self.handle_platform_signal(command, &mut reply)?;
        if let Some(rc) = reply.get_ref().last_chunk::<4>() {
            let rc = u32::from_be_bytes(*rc);
            if rc != 0 {
                anyhow::bail!("Platform command {} failed with {}", command as u32, rc);
            }
        }
        Ok(session_end)
    }

    fn transact_platform<S: Read + Write>(
        &mut self,
        command: u32,
        stream: &mut S,
    ) -> anyhow::Result<bool> {
        self.handle_regular_command_raw(command, stream)
    }
}

/// Implementation details used by [`create_simulator!`].
///
/// These re-exports let the macro expand in downstream crates without
/// requiring them to depend on (or import anything from) `tpm2-impl` or
/// `tpm2-platform-linux`. Not part of the public API.
#[doc(hidden)]
pub mod __private {
    pub use tpm2::TpmSu;
    pub use tpm2::commands::Startup;
    pub use tpm2_impl::storage::ram_storage_mock::RamStorageMock;
    pub use tpm2_platform_linux::{LinuxRng, LinuxTimer, PlatformCryptoProvider};
}

/// Powers `sim` on, enables NV and sends `TPM2_Startup(TPM_SU_CLEAR)`.
///
/// # Panics
/// If any of these steps fails.
fn power_on_start_up(sim: &mut Simulator<'_>) {
    sim.signal_platform(SimulatorPlatformSignal::PowerOn, NO_STREAM)
        .expect("failed to power on the TPM simulator");
    sim.signal_platform(SimulatorPlatformSignal::NvOn, NO_STREAM)
        .expect("failed to enable NV of the TPM simulator");
    sim.execute(tpm2::commands::Startup {
        startup_type: tpm2::TpmSu::Clear,
    })
    .expect("TPM2_Startup(TPM_SU_CLEAR) failed");
}

/// Builds a powered-on, NV-enabled, started simulator from leaked components.
fn new_started_simulator(timer: LinuxTimer, platform_rng: LinuxRng) -> Simulator<'static> {
    let crypto: &'static mut PlatformCryptoProvider = Box::leak(Box::new(PlatformCryptoProvider));
    let storage: &'static mut RamStorageMock<4096> = Box::leak(Box::new(RamStorageMock::new()));
    let timer: &'static mut LinuxTimer = Box::leak(Box::new(timer));
    let platform_rng: &'static mut LinuxRng = Box::leak(Box::new(platform_rng));
    let mut sim = Simulator::new(crypto, storage, timer, platform_rng)
        .expect("failed to create TPM simulator");
    power_on_start_up(&mut sim);
    sim
}

/// Implementation of [`create_simulator!`]. Not part of the public API.
#[doc(hidden)]
pub fn __new_simulator() -> Simulator<'static> {
    new_started_simulator(LinuxTimer::new(), LinuxRng::new())
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
    () => {
        $crate::__new_simulator()
    };
}

/// Seed used by [`create_replay_simulator!`] when none is given.
#[cfg(feature = "reproducible")]
pub const DEFAULT_REPLAY_SEED: u64 = 0x7470_6d2d_7273_0001;

/// XORed into the replay seed to derive the crypto provider's seed, so that the
/// platform RNG and the crypto RNG produce different streams.
#[cfg(feature = "reproducible")]
pub const REPLAY_CRYPTO_SEED_TWEAK: u64 = 0x6372_7970_746f_0000;

#[cfg(feature = "reproducible")]
impl Simulator<'_> {
    /// Advances the simulator's virtual clock by `ms` milliseconds.
    ///
    /// Returns `false` (and does nothing) if the simulator runs on the wall
    /// clock, i.e. was not created by [`create_replay_simulator!`].
    pub fn advance_clock(&mut self, ms: u64) -> bool {
        self.context.platform.timer.advance(ms)
    }

    /// Makes the crypto provider's randomness (key generation, ECDSA nonces,
    /// RSA padding, `get_random`) a stream seeded by `seed` whenever this
    /// simulator executes a command or signal.
    ///
    /// The stream belongs to this simulator: randomness drawn by other code
    /// (e.g. a test's client-side crypto using the same provider type) or by
    /// other simulators neither consumes nor perturbs it. Only the BoringSSL
    /// backend supports this; with other backends it is a no-op returning
    /// `false`.
    pub fn pin_crypto_rng(&mut self, seed: u64) -> bool {
        #[cfg(feature = "bssl")]
        {
            self.crypto_rng = Some(tpm2_platform_linux::CryptoReplayRng::new(seed));
            true
        }
        #[cfg(not(feature = "bssl"))]
        {
            let _ = seed;
            false
        }
    }
}

/// Implementation of [`create_replay_simulator!`]. Not part of the public API.
#[cfg(feature = "reproducible")]
#[doc(hidden)]
pub fn __new_replay_simulator(seed: u64) -> Simulator<'static> {
    let crypto: &'static mut PlatformCryptoProvider = Box::leak(Box::new(PlatformCryptoProvider));
    let storage: &'static mut RamStorageMock<4096> = Box::leak(Box::new(RamStorageMock::new()));
    let timer: &'static mut LinuxTimer = Box::leak(Box::new(LinuxTimer::new_virtual()));
    let platform_rng: &'static mut LinuxRng = Box::leak(Box::new(LinuxRng::seeded(seed)));
    let mut sim = Simulator::new(crypto, storage, timer, platform_rng)
        .expect("failed to create TPM simulator");
    // A distinct stream from the platform RNG, derived from the same seed.
    sim.pin_crypto_rng(seed ^ REPLAY_CRYPTO_SEED_TWEAK);
    power_on_start_up(&mut sim);
    sim
}

/// Like [`create_simulator!`], but every source of nondeterminism is pinned:
/// the platform RNG is a ChaCha20 stream seeded with `$seed` (default
/// [`DEFAULT_REPLAY_SEED`]), the crypto provider's randomness is pinned with
/// [`Simulator::pin_crypto_rng`] (BoringSSL backend only), and the timer is a
/// virtual clock starting at 0 ms that only moves via
/// [`Simulator::advance_clock`].
///
/// Two simulators created with the same seed and fed the same inputs produce
/// byte-identical responses.
#[cfg(feature = "reproducible")]
#[macro_export]
macro_rules! create_replay_simulator {
    () => {
        $crate::__new_replay_simulator($crate::DEFAULT_REPLAY_SEED)
    };
    ($seed:expr) => {
        $crate::__new_replay_simulator($seed)
    };
}
