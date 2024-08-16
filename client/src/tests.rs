use crate::sessions::{PasswordSession, Session};

use super::*;
use tpm2_rs_base::constants::TpmHandle;
use tpm2_rs_base::errors::TpmRcError;
use tpm2_rs_base::TpmaSession;

// A Tpm that just returns a general failure error.
struct ErrorTpm();
impl Tpm for ErrorTpm {
    fn transact(&mut self, _: &[u8], _: &mut [u8]) -> TssResult<()> {
        Err(TssTcsError::GeneralFailure.into())
    }
}

#[derive(Marshalable)]
#[repr(C)]
// Larger than the maximum size.
struct HugeFakeCommand([u8; CMD_BUFFER_SIZE]);
impl TpmCommand for HugeFakeCommand {
    const CMD_CODE: TpmCc = TpmCc::NVUndefineSpaceSpecial;
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

#[derive(Marshalable)]
#[repr(C)]
struct TestCommand(u32);
impl TpmCommand for TestCommand {
    const CMD_CODE: TpmCc = TpmCc::NVUndefineSpaceSpecial;
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
    fn transact(&mut self, command: &[u8], response: &mut [u8]) -> TssResult<()> {
        self.rxed_bytes = command.len();
        let mut buf = UnmarshalBuf::new(command);
        self.rxed_header = Some(CmdHeader::try_unmarshal(&mut buf)?);
        let rxed_value = u32::try_unmarshal(&mut buf)?;

        let mut tx_header = RespHeader {
            tag: TpmSt::NoSessions,
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
    fn transact(&mut self, _: &[u8], response: &mut [u8]) -> TssResult<()> {
        let tx_header = RespHeader {
            tag: TpmSt::NoSessions,
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
                tag: TpmSt::NoSessions,
                size: 0,
                rc: 0,
            },
        }
    }
}
impl Tpm for FakeTpm {
    fn transact(&mut self, _: &[u8], response: &mut [u8]) -> TssResult<()> {
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

#[derive(Marshalable)]
#[repr(C)]
struct TestHandlesCommand();
impl TpmCommand for TestHandlesCommand {
    const CMD_CODE: TpmCc = TpmCc::NVUndefineSpaceSpecial;
    type Handles = TpmHandle;
    type RespT = ();
    type RespHandles = TpmHandle;
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
    fake_tpm.add_to_response(&TpmHandle(77));

    let cmd = TestHandlesCommand();
    let session = PasswordSession::default();
    assert_eq!(
        run_command_with_handles(&cmd, TpmHandle::RSPW, session, &mut fake_tpm),
        Err(TpmRcError::Memory.into())
    );
}

#[test]
fn test_response_session_fails_validation() {
    let mut fake_tpm = FakeTpm::default();
    // Respond with the single response handle, and an invalid password auth.
    fake_tpm.add_to_response(&TpmHandle(77));
    let invalid_auth = TpmsAuthResponse {
        session_attributes: TpmaSession(0xf),
        ..Default::default()
    };
    let validation_failure = PasswordSession::default().validate_auth_response(&invalid_auth);
    assert!(validation_failure.is_err());
    fake_tpm.add_to_response(&invalid_auth);

    let cmd = TestHandlesCommand();
    let session = PasswordSession::default();
    assert_eq!(
        run_command_with_handles(&cmd, TpmHandle::RSPW, session, &mut fake_tpm),
        Err(validation_failure.err().unwrap())
    );
}
