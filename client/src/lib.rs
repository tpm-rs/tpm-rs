#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]
use core::mem::size_of;
use sessions::CmdSessions;
use tpm2_rs_base::commands::*;
use tpm2_rs_base::constants::{TPM2CC, TPM2ST};
use tpm2_rs_base::errors::{TpmError, TpmResult, TssTcsError};
use tpm2_rs_base::marshal::{Marshal, Marshalable, UnmarshalBuf};
use tpm2_rs_base::{TpmiStCommandTag, TpmsAuthResponse};

pub const CMD_BUFFER_SIZE: usize = 4096;
pub const RESP_BUFFER_SIZE: usize = 4096;

pub mod sessions;

pub trait Tpm {
    fn transact(&mut self, command: &[u8], response: &mut [u8]) -> TpmResult<()>;
}

pub fn get_capability<T: Tpm + ?Sized>(
    tpm: &mut T,
    command: &GetCapabilityCmd,
) -> TpmResult<GetCapabilityResp> {
    run_command(command, tpm)
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal)]
pub struct CmdHeader {
    tag: TpmiStCommandTag,
    size: u32,
    code: TPM2CC,
}
impl CmdHeader {
    fn new(has_sessions: bool, code: TPM2CC) -> CmdHeader {
        let tag = if has_sessions {
            TpmiStCommandTag::NoSessions
        } else {
            TpmiStCommandTag::Sessions
        };
        CmdHeader { tag, size: 0, code }
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshal, Debug)]
pub struct RespHeader {
    pub tag: TPM2ST,
    pub size: u32,
    pub rc: u32,
}

/// Runs a command with default/unset handles.
pub fn run_command<CmdT, T>(cmd: &CmdT, tpm: &mut T) -> TpmResult<CmdT::RespT>
where
    CmdT: TpmCommand,
    T: Tpm + ?Sized,
{
    Ok(run_command_with_handles(cmd, CmdT::Handles::default(), CmdSessions::default(), tpm)?.0)
}

/// Adds any command sessions to the command buffer.
pub fn write_command_sessions(sessions: &CmdSessions, buffer: &mut [u8]) -> TpmResult<usize> {
    if sessions.is_empty() {
        return Ok(0);
    }
    let mut auth_offset = size_of::<u32>();
    for session in sessions {
        // TODO: Support parameter encryption.
        auth_offset += session
            .get_auth_command()
            .try_marshal(&mut buffer[auth_offset..])?;
    }
    let auth_size = (auth_offset - size_of::<u32>()) as u32;
    auth_size.try_marshal(buffer)?;
    Ok(auth_offset)
}

/// Umarshals the response header and checks the contained response code.
pub fn read_response_header(buffer: &[u8]) -> TpmResult<(RespHeader, usize)> {
    let mut unmarsh = UnmarshalBuf::new(buffer);
    let resp_header = RespHeader::try_unmarshal(&mut unmarsh)?;
    if let Ok(error) = TpmError::try_from(resp_header.rc) {
        return TpmResult::Err(error);
    }
    Ok((resp_header, buffer.len() - unmarsh.len()))
}

/// Unmarshals any response sessions.
pub fn read_response_sessions(sessions: &CmdSessions, buffer: &mut UnmarshalBuf) -> TpmResult<()> {
    for session in sessions {
        // TODO: Support parameter decryption.
        let auth = TpmsAuthResponse::try_unmarshal(buffer)?;
        session.validate_auth_response(&auth)?;
    }
    Ok(())
}

/// Runs a command with provided handles and sessions.
pub fn run_command_with_handles<CmdT, T>(
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    cmd_sessions: CmdSessions,
    tpm: &mut T,
) -> TpmResult<(CmdT::RespT, CmdT::RespHandles)>
where
    CmdT: TpmCommand,
    T: Tpm + ?Sized,
{
    let mut cmd_buffer = [0u8; CMD_BUFFER_SIZE];
    let mut cmd_header = CmdHeader::new(cmd_sessions.is_empty(), CmdT::CMD_CODE);
    let mut written = cmd_header.try_marshal(&mut cmd_buffer)?;

    written += cmd_handles.try_marshal(&mut cmd_buffer[written..])?;
    written += write_command_sessions(&cmd_sessions, &mut cmd_buffer[written..])?;
    written += cmd.try_marshal(&mut cmd_buffer[written..])?;

    // Update the command size
    cmd_header.size = written as u32;
    let _ = cmd_header.try_marshal(&mut cmd_buffer)?;

    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    tpm.transact(&cmd_buffer[..written], &mut resp_buffer)?;

    let (resp_header, read) = read_response_header(&resp_buffer)?;
    let resp_size = resp_header.size as usize;
    if resp_size > resp_buffer.len() {
        return TpmResult::Err(TssTcsError::OutOfMemory.into());
    }
    let mut unmarsh = UnmarshalBuf::new(&resp_buffer[read..resp_size]);
    let resp_handles = CmdT::RespHandles::try_unmarshal(&mut unmarsh)?;
    if resp_header.tag == TPM2ST::Sessions {
        let _param_size = u32::try_unmarshal(&mut unmarsh)?;
    }
    let resp = CmdT::RespT::try_unmarshal(&mut unmarsh)?;
    read_response_sessions(&cmd_sessions, &mut unmarsh)?;

    if !unmarsh.is_empty() {
        return TpmResult::Err(TssTcsError::TpmUnexpected.into());
    }
    Ok((resp, resp_handles))
}

#[cfg(test)]
mod tests {
    use crate::sessions::{PasswordSession, Session};

    use super::*;
    use tpm2_rs_base::constants::TPM2Handle;
    use tpm2_rs_base::errors::TpmRcError;
    use tpm2_rs_base::TpmaSession;

    // A Tpm that just returns a general failure error.
    struct ErrorTpm();
    impl Tpm for ErrorTpm {
        fn transact(&mut self, _: &[u8], _: &mut [u8]) -> TpmResult<()> {
            return Err(TssTcsError::GeneralFailure.into());
        }
    }

    #[derive(Marshal)]
    #[repr(C)]
    // Larger than the maximum size.
    struct HugeFakeCommand([u8; CMD_BUFFER_SIZE]);
    impl TpmCommand for HugeFakeCommand {
        const CMD_CODE: TPM2CC = TPM2CC::NVUndefineSpaceSpecial;
        type Handles = ();
        type RespT = u8;
        type RespHandles = ();
    }

    #[test]
    fn test_command_too_large() {
        let mut fake_tpm = ErrorTpm();
        let too_large = HugeFakeCommand([0; CMD_BUFFER_SIZE]);
        assert_eq!(
            run_command(&too_large, &mut fake_tpm),
            Err(TpmRcError::Memory.into())
        );
    }

    #[derive(Marshal)]
    #[repr(C)]
    struct TestCommand(u32);
    impl TpmCommand for TestCommand {
        const CMD_CODE: TPM2CC = TPM2CC::NVUndefineSpaceSpecial;
        type Handles = ();
        type RespT = u32;
        type RespHandles = ();
    }

    #[test]
    fn test_tpm_error() {
        let mut fake_tpm = ErrorTpm();
        let cmd = TestCommand(56789);
        assert_eq!(
            run_command(&cmd, &mut fake_tpm),
            Err(TssTcsError::GeneralFailure.into())
        );
    }

    // FakeU32LoopbackTpm reads/stores the command header and a u32 "command".
    // It responds with a response header and the same u32 "response".
    struct FakeU32LoopbackTpm {
        rxed_header: Option<CmdHeader>,
        rxed_bytes: usize,
    }
    impl Tpm for FakeU32LoopbackTpm {
        fn transact(&mut self, command: &[u8], response: &mut [u8]) -> TpmResult<()> {
            self.rxed_bytes = command.len();
            let mut buf = UnmarshalBuf::new(command);
            self.rxed_header = Some(CmdHeader::try_unmarshal(&mut buf)?);
            let rxed_value = u32::try_unmarshal(&mut buf)?;

            let mut tx_header = RespHeader {
                tag: TPM2ST::NoSessions,
                size: 0,
                rc: 0,
            };
            let mut written = tx_header.try_marshal(response)?;
            written += rxed_value.try_marshal(&mut response[written..])?;
            tx_header.size = written as u32;
            // Update the size.
            tx_header.try_marshal(response)?;
            Ok(())
        }
    }

    #[test]
    fn test_fake_command() {
        let mut fake_tpm = FakeU32LoopbackTpm {
            rxed_header: None,
            rxed_bytes: 0,
        };
        let cmd = TestCommand(56789);
        let result = run_command(&cmd, &mut fake_tpm);
        assert_eq!(fake_tpm.rxed_header.unwrap().code, TestCommand::CMD_CODE);
        assert_eq!(result.unwrap(), cmd.0);
    }

    // EvilSizeTpm writes a reponse header with a size value that is larger than the reponse buffer.
    struct EvilSizeTpm();
    impl Tpm for EvilSizeTpm {
        fn transact(&mut self, _: &[u8], response: &mut [u8]) -> TpmResult<()> {
            let tx_header = RespHeader {
                tag: TPM2ST::NoSessions,
                size: response.len() as u32 + 2,
                rc: 0,
            };
            tx_header.try_marshal(response)?;
            Ok(())
        }
    }

    #[test]
    fn test_bad_response_size() {
        let mut fake_tpm = EvilSizeTpm();
        let cmd = TestCommand(2);
        assert_eq!(
            run_command(&cmd, &mut fake_tpm),
            Err(TssTcsError::OutOfMemory.into())
        );
    }

    pub struct FakeTpm {
        len: usize,
        response: [u8; RESP_BUFFER_SIZE],
        header: RespHeader,
    }
    impl Default for FakeTpm {
        fn default() -> Self {
            FakeTpm {
                len: 0,
                response: [0; RESP_BUFFER_SIZE],
                header: RespHeader {
                    tag: TPM2ST::NoSessions,
                    size: 0,
                    rc: 0,
                },
            }
        }
    }
    impl Tpm for FakeTpm {
        fn transact(&mut self, _: &[u8], response: &mut [u8]) -> TpmResult<()> {
            let off = self.header.try_marshal(response)?;
            let length = off + self.len;
            if self.len > response.len() {
                return Err(TpmRcError::Size.into());
            }
            response[off..length].copy_from_slice(&self.response[..self.len]);
            self.header.size = length as u32;
            self.header.try_marshal(response)?;
            Ok(())
        }
    }
    impl FakeTpm {
        fn add_to_response<M: Marshalable>(&mut self, val: &M) {
            self.len += val.try_marshal(&mut self.response[self.len..]).unwrap()
        }
    }

    #[derive(Marshal)]
    #[repr(C)]
    struct TestHandlesCommand();
    impl TpmCommand for TestHandlesCommand {
        const CMD_CODE: TPM2CC = TPM2CC::NVUndefineSpaceSpecial;
        type Handles = TPM2Handle;
        type RespT = ();
        type RespHandles = TPM2Handle;
    }

    #[test]
    fn test_response_missing_handles() {
        let mut fake_tpm = FakeTpm::default();
        let cmd = TestHandlesCommand();
        assert_eq!(
            run_command(&cmd, &mut fake_tpm),
            Err(TpmRcError::Memory.into())
        );
    }

    #[test]
    fn test_response_missing_sessions() {
        let mut fake_tpm = FakeTpm::default();
        // Respond with the single response handle.
        fake_tpm.add_to_response(&TPM2Handle(77));

        let cmd = TestHandlesCommand();
        let mut sessions = CmdSessions::default();
        let mut session = PasswordSession::default();
        sessions.push(&mut session);
        assert_eq!(
            run_command_with_handles(&cmd, TPM2Handle::RSPW, sessions, &mut fake_tpm),
            Err(TpmRcError::Memory.into())
        );
    }

    #[test]
    fn test_response_session_fails_validation() {
        let mut fake_tpm = FakeTpm::default();
        // Respond with the single response handle, and an invalid password auth.
        fake_tpm.add_to_response(&TPM2Handle(77));
        let mut invalid_auth = TpmsAuthResponse::default();
        invalid_auth.session_attributes = TpmaSession(0xf);
        let validation_failure = PasswordSession::default().validate_auth_response(&invalid_auth);
        assert!(validation_failure.is_err());
        fake_tpm.add_to_response(&invalid_auth);

        let cmd = TestHandlesCommand();
        let mut sessions = CmdSessions::default();
        let mut session = PasswordSession::default();
        sessions.push(&mut session);
        assert_eq!(
            run_command_with_handles(&cmd, TPM2Handle::RSPW, sessions, &mut fake_tpm),
            Err(validation_failure.err().unwrap())
        );
    }
}
