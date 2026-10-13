//! Platform signals of a TPM and the [`PlatformConnection`] trait for delivering them.
//!
//! Besides commands (sent over a [`tpm2::Connection`]), a TPM receives platform signals:
//! power, physical presence, command cancel, NV availability, and so on. The TPM 2.0 Library
//! specification only describes some of them abstractly (for example `_TPM_Init`, physical
//! presence and command cancel); their encoding comes from the platform ("MSSIM") port of the
//! TCG reference simulator (`TPMCmd/Simulator/include/TpmTcpProtocol.h`), which
//! [`SimulatorPlatformSignal`] mirrors.
//!
//! [`SimulatorPlatformSignal`] is available in every build. [`PlatformConnection`] uses
//! `std::io` and `anyhow`, so it requires the `std` feature (`tpm2-impl` itself stays
//! `no_std`).

/// A signal that can be sent to the platform port of a TPM simulator.
///
/// The discriminants are the command codes of the platform port of the TCG reference
/// simulator (`TpmTcpProtocol.h`).
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

/// A `stream` argument for [`PlatformConnection::signal_platform`] that passes no stream.
///
/// `None` alone does not name the stream type; this constant does.
#[cfg(feature = "std")]
pub const NO_STREAM: Option<&'static mut std::io::Empty> = None;

/// A [`tpm2::Connection`] to a TPM that also accepts platform signals.
#[cfg(feature = "std")]
pub trait PlatformConnection: tpm2::Connection {
    /// Delivers the platform signal `command` to the TPM.
    ///
    /// `stream` is the platform-port byte stream of the signal: signals that carry a payload
    /// (e.g. [`SimulatorPlatformSignal::ActGetSignaled`],
    /// [`SimulatorPlatformSignal::SetFirmwareHash`]) read it from the stream, and the reply
    /// (any reply data followed by a 4-byte result code) is written to it. With `None`
    /// ([`NO_STREAM`]), the signal carries no payload, the reply is consumed internally, and a
    /// non-zero result code is returned as an error.
    ///
    /// Returns `true` if the signal ends the current platform session
    /// ([`SimulatorPlatformSignal::SessionEnd`]), `false` otherwise.
    ///
    /// # Errors
    /// Fails if the signal is not supported, if reading the payload or writing the reply fails,
    /// or (without a stream) if the TPM reports a non-zero result code.
    fn signal_platform<S: std::io::Read + std::io::Write>(
        &mut self,
        command: SimulatorPlatformSignal,
        stream: Option<&mut S>,
    ) -> anyhow::Result<bool>;

    /// Performs one raw transaction on the TPM command port ("MSSIM" command server).
    ///
    /// `command` is the command-port code of the TCG reference simulator (`TpmTcpProtocol.h`),
    /// e.g. `TPM_SIGNAL_HASH_START` (5), `TPM_SIGNAL_HASH_DATA` (6), `TPM_SIGNAL_HASH_END` (7),
    /// `TPM_SEND_COMMAND` (8, which carries the locality, unlike [`tpm2::Connection::transact`]),
    /// `TPM_REMOTE_HANDSHAKE` (15) or `TPM_SESSION_END` (20). Its payload is read from `stream`,
    /// and the reply (any reply data followed by a 4-byte result code) is written to `stream`.
    ///
    /// Returns `true` if the transaction ends the current command-port session, `false`
    /// otherwise.
    ///
    /// # Errors
    /// Fails if the payload is malformed (e.g. an oversized command) or if reading the payload or
    /// writing the reply fails.
    fn transact_platform<S: std::io::Read + std::io::Write>(
        &mut self,
        command: u32,
        stream: &mut S,
    ) -> anyhow::Result<bool>;
}
