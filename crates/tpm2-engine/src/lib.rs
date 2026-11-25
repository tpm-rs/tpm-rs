//! # TPM 2.0 Command Execution Engine
//!
//! This crate provides [`Engine`], a `no_std`, allocation-free TPM 2.0 command
//! execution engine parameterized over a [`Platform`].
#![no_std]
#![forbid(unsafe_code)]
#![forbid(unreachable_pub)]

mod handler;
pub mod platform;
pub mod state;

use core::{error::Error, fmt};

use tpm2::commands::{GetRandom, Shutdown, Startup, StirRandom};
use tpm2::errors::TpmRc;
use tpm2::{
    Command, CommandHeader, Connection, EntityHandle, Handle, Marshal, Response, ResponseHeader,
    TpmCc, TpmSt, TpmiStCommandTag, Unmarshal,
};

use crate::{
    platform::Platform,
    state::{Phase, State},
};

/// Maximum byte length of any command currently supported by [`Engine`].
///
/// Computed from the headers, handle areas, and parameter areas of the
/// implemented commands (session areas are not yet supported).
pub const MAX_COMMAND_SIZE: usize = max_size(&[
    cmd_max_size::<Startup>(),
    cmd_max_size::<Shutdown>(),
    cmd_max_size::<GetRandom>(),
    cmd_max_size::<StirRandom<'_>>(),
]);

/// Maximum byte length of any response currently produced by [`Engine`].
///
/// Computed from the headers, handle areas, and parameter areas of the
/// implemented commands (session areas are not yet supported).
pub const MAX_RESPONSE_SIZE: usize = max_size(&[
    rsp_max_size::<Startup>(),
    rsp_max_size::<Shutdown>(),
    rsp_max_size::<GetRandom>(),
    rsp_max_size::<StirRandom<'_>>(),
]);

/// Maximum response payload size following [`ResponseHeader`].
pub(crate) const MAX_RESPONSE_BODY: usize = MAX_RESPONSE_SIZE - ResponseHeader::MAX_SIZE;

const fn cmd_max_size<'a, C: Command + 'a>() -> usize {
    let num_handles = size_of::<C::Handles<'a>>() / size_of::<EntityHandle<'a>>();
    CommandHeader::MAX_SIZE + num_handles * Handle::MAX_SIZE + C::MAX_SIZE
}

const fn rsp_max_size<'a, C: Command + 'a>() -> usize {
    let num_handles = size_of::<<C::Response<'a> as Response>::Handles>() / size_of::<Handle>();
    ResponseHeader::MAX_SIZE + num_handles * Handle::MAX_SIZE + C::Response::MAX_SIZE
}

const fn max_size(mut sizes: &[usize]) -> usize {
    let mut max = 0;
    while let Some((&first, rest)) = sizes.split_first() {
        if first > max {
            max = first;
        }
        sizes = rest;
    }
    max
}

/// Error returned by [`Connection::transact`] when the caller's response buffer
/// is smaller than [`MAX_RESPONSE_SIZE`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseBufferTooSmall;

impl fmt::Display for ResponseBufferTooSmall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "response buffer is too small")
    }
}

impl Error for ResponseBufferTooSmall {}

/// TPM 2.0 command execution engine bound to a [`Platform`] and [`State`].
///
/// Construct an `Engine` with [`Engine::init`] to process a `_TPM_Init`
/// hardware indication. Commands can be executed directly via
/// [`Engine::execute_command`] or through [`Connection`].
pub struct Engine<'a, P: Platform> {
    platform: &'a mut P,
    state: &'a mut State<P>,
}

impl<'a, P: Platform> Engine<'a, P> {
    /// Initializes an [`Engine`] for a `_TPM_Init` indication.
    ///
    /// Clears failure state and resets volatile state inside `state` to await
    /// `TPM2_Startup` while preserving non-volatile state ([`State::nv`]).
    #[doc(alias = "_TPM_Init")]
    pub fn init(platform: &'a mut P, state: &'a mut State<P>) -> Self {
        state.failure = None;
        state.phase = Phase::NotStarted;
        Self { platform, state }
    }

    /// Returns a shared reference to the engine's [`Platform`].
    pub fn platform(&self) -> &P {
        self.platform
    }

    /// Returns a mutable reference to the engine's [`Platform`].
    pub fn platform_mut(&mut self) -> &mut P {
        self.platform
    }

    /// Returns a shared reference to the engine's [`State`].
    pub fn state(&self) -> &State<P> {
        self.state
    }

    /// Executes a marshaled TPM command in `cmd` and writes the response into
    /// `rsp`, returning the initialized prefix slice.
    ///
    /// TPM-level errors (`TPM_RC_*`) are serialized into `rsp` as a 10-byte
    /// [`ResponseHeader`]. A result of [`TpmRc::FAILURE`] enters sticky
    /// failure mode.
    #[doc(alias = "ExecuteCommand")]
    pub fn execute_command<'r>(
        &mut self,
        cmd: &[u8],
        rsp: &'r mut [u8; MAX_RESPONSE_SIZE],
    ) -> &'r mut [u8] {
        let (hdr_buf, rsp_body) = rsp
            .split_first_chunk_mut::<{ ResponseHeader::MAX_SIZE }>()
            .unwrap();
        let rsp_body: &mut [u8; MAX_RESPONSE_BODY] = rsp_body.try_into().unwrap();

        let result = self.try_execute(cmd, rsp_body);
        if result == Err(TpmRc::FAILURE) {
            self.state.failure.get_or_insert_default();
        }

        let len = ResponseHeader::MAX_SIZE + result.unwrap_or(0);
        ResponseHeader {
            tag: TpmiStCommandTag::NoSessions,
            size: len as u32,
            rc: result.map(|_| ()),
        }
        .marshal(hdr_buf);
        rsp.split_at_mut(len).0
    }

    /// Checks failure mode, parses the header, and handles everything that
    /// happens before `TPM2_Startup` completes.
    fn try_execute(
        &mut self,
        cmd: &[u8],
        rsp_body: &mut [u8; MAX_RESPONSE_BODY],
    ) -> Result<usize, TpmRc> {
        if self.state.failure.is_some() {
            return Err(TpmRc::FAILURE);
        }
        let (tag, code, cmd_body) = parse_command_header(cmd)?;

        match (&self.state.phase, code) {
            (Phase::NotStarted, TpmCc::Startup) => {
                reject_sessions(tag)?;
                handler::startup::startup(self.state, cmd_body)
            }
            (Phase::NotStarted, _) | (Phase::Started(_), TpmCc::Startup) => Err(TpmRc::INITIALIZE),
            (Phase::Started(_), _) => {
                reject_sessions(tag)?;
                self.dispatch(code, cmd_body, rsp_body)
            }
        }
    }

    /// Runs a command other than `TPM2_Startup` on a started TPM.
    fn dispatch(
        &mut self,
        code: TpmCc,
        cmd_body: &[u8],
        rsp_body: &mut [u8; MAX_RESPONSE_BODY],
    ) -> Result<usize, TpmRc> {
        let State {
            nv,
            phase: Phase::Started(rng),
            ..
        } = &mut *self.state
        else {
            return Err(TpmRc::INITIALIZE);
        };

        match code {
            TpmCc::Shutdown => handler::startup::shutdown(nv, cmd_body),
            TpmCc::GetRandom => handler::random::get_random(rng, cmd_body, rsp_body),
            TpmCc::StirRandom => handler::random::stir_random(rng, cmd_body),
            _ => Err(TpmRc::COMMAND_CODE),
        }
    }
}

impl<P: Platform> Connection for Engine<'_, P> {
    type Error = ResponseBufferTooSmall;

    fn transact<'r>(&mut self, cmd: &[u8], rsp: &'r mut [u8]) -> Result<&'r mut [u8], Self::Error> {
        let rsp = rsp
            .first_chunk_mut::<MAX_RESPONSE_SIZE>()
            .ok_or(ResponseBufferTooSmall)?;
        Ok(self.execute_command(cmd, rsp))
    }
}

/// Parses a 10-byte command header field-by-field following the check order of
/// TPM 2.0 Part 3, Section 5.2.
fn parse_command_header(cmd: &[u8]) -> Result<(TpmiStCommandTag, TpmCc, &[u8]), TpmRc> {
    let mut cursor = cmd;

    let raw_tag = u16::unmarshal(&mut cursor).map_err(|_| TpmRc::INSUFFICIENT.to_rc())?;
    let tag = match raw_tag {
        x if x == TpmSt::NO_SESSIONS.id() => TpmiStCommandTag::NoSessions,
        x if x == TpmSt::SESSIONS.id() => TpmiStCommandTag::Sessions,
        // Per Part 3 §5.2 (and reference `Marshal.c`), invalid tags return `TPM_RC_BAD_TAG`
        // (Part 3 §6.1 says `TPM_RC_TAG` for non-1.2 TPMs; we follow §5.2 / reference).
        _ => return Err(TpmRc::BAD_TAG),
    };

    let size = u32::unmarshal(&mut cursor).map_err(|_| TpmRc::INSUFFICIENT.to_rc())?;
    if u32::try_from(cmd.len()) != Ok(size) {
        return Err(TpmRc::COMMAND_SIZE);
    }

    let code = TpmCc::unmarshal(&mut cursor).map_err(|_| TpmRc::INSUFFICIENT.to_rc())?;
    Ok((tag, code, cursor))
}

fn reject_sessions(tag: TpmiStCommandTag) -> Result<(), TpmRc> {
    // TODO: Support session area parsing/handling for commands that allow
    // authorization, audit, or parameter encryption sessions.
    if tag == TpmiStCommandTag::Sessions {
        return Err(TpmRc::AUTH_CONTEXT);
    }
    Ok(())
}
