//! Black-box tests of the `tpm2-client` command/response protocol.
//!
//! These tests drive the public API ([`run_command`],
//! [`run_command_with_sessions`] and [`marshal_command`]) against fake
//! [`Connection`]s. They cover command and response handles, the
//! authorization area, commands from [`tpm2::commands`], and malformed or
//! failing responses.
use core::fmt;
use tpm2::commands::*;
use tpm2::errors::UnmarshalError;
use tpm2::{
    CommandHeader, Handle, Marshal, ResponseHeader, Tpm2bAuth, TpmCc, TpmSt, TpmaSession,
    TpmiStCommandTag, TpmsAuthCommand, TpmsAuthResponse, Unmarshal,
};
use tpm2_client::connection::Connection;
use tpm2_client::protocol::*;
use tpm2_client::sessions::{PasswordSession, Session};
use tpm2_client::{ClientError, run_command, run_command_with_sessions};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct TransportError;

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "transport error")
    }
}

impl core::error::Error for TransportError {}

// A Tpm that just returns a transport failure error.
struct ErrorTpm();
impl Connection for ErrorTpm {
    type Error = TransportError;
    fn transact<'a>(&mut self, _: &[u8], _: &'a mut [u8]) -> Result<&'a mut [u8], TransportError> {
        Err(TransportError)
    }
}

/// Size of the largest parameter area of a command without handles: the
/// command header, `authorizationSize` and three maximum-size sessions must
/// also fit in [`CMD_BUFFER_SIZE`].
const MAX_PARAMETERS_SIZE: usize =
    CMD_BUFFER_SIZE - CommandHeader::MAX_SIZE - u32::MAX_SIZE - 3 * TpmsAuthCommand::MAX_SIZE;

// The largest command that fits in the command buffer: one more parameter
// byte would make it too large.
struct MaxSizeFakeCommand([u8; MAX_PARAMETERS_SIZE]);
impl Message for MaxSizeFakeCommand {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for MaxSizeFakeCommand {
    const MAX_SIZE: usize = MAX_PARAMETERS_SIZE;
    type MaxBuffer = [u8; MAX_PARAMETERS_SIZE];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        dst.copy_from_slice(&self.0);
        MAX_PARAMETERS_SIZE
    }
}
impl Command for MaxSizeFakeCommand {
    const CMD_CODE: TpmCc = TpmCc::NVUndefineSpaceSpecial;
    type Response<'a> = ();
}

/// Commands too large for the command buffer can no longer be built:
/// [`marshal_command`] asserts at compile time that the largest possible
/// command (header, handles, three sessions and parameters) fits in
/// [`CMD_BUFFER_SIZE`], so a too-large command is a compile error (see the
/// `compile_fail` doc test of [`marshal_command`]) instead of a runtime
/// error. This checks that the limit is exact: the largest command that fits
/// is marshaled completely, with three sessions, and handed to the connection.
#[test]
fn test_command_too_large() {
    let cmd = MaxSizeFakeCommand([0xA5; MAX_PARAMETERS_SIZE]);
    let password = [0x5A; Tpm2bAuth::CAP];
    let session = PasswordSession::new(&password).unwrap();
    let sessions = (session, session, session);

    let mut cmd_buffer = [0u8; CMD_BUFFER_SIZE];
    let written = marshal_command(&cmd, &sessions, &mut cmd_buffer);
    let mut src = &cmd_buffer[..written];
    let header = CommandHeader::unmarshal(&mut src).unwrap();
    assert_eq!(header.tag, TpmiStCommandTag::Sessions);
    assert_eq!(header.size as usize, written);
    assert_eq!(header.code, MaxSizeFakeCommand::CMD_CODE);
    let auth_size = u32::unmarshal(&mut src).unwrap() as usize;
    let (mut auth_area, parameters) = src.split_at(auth_size);
    for _ in 0..3 {
        assert_eq!(
            TpmsAuthCommand::unmarshal(&mut auth_area),
            Ok(session.auth_command())
        );
    }
    assert!(auth_area.is_empty());
    assert_eq!(parameters, &cmd.0[..]);

    // The command is handed to the connection rather than rejected.
    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    assert_eq!(
        run_command_with_sessions(&cmd, sessions, &mut ErrorTpm(), &mut resp_buffer),
        Err(ClientError::Connection(TransportError))
    );
}

// A command whose only parameter is a `u32`; its response echoes the `u32`.
#[derive(Debug, PartialEq, Eq)]
struct TestCommand(u32);
impl Message for TestCommand {
    type Handles = [Handle; 0];
    fn handles(&self) -> Self::Handles {
        []
    }
}
impl Marshal for TestCommand {
    const MAX_SIZE: usize = 4;
    type MaxBuffer = [u8; 4];
    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        self.0.marshal(dst)
    }
}
impl<'a> UnmarshalMessage<'a> for TestCommand {
    fn unmarshal_with_handles(
        []: Self::Handles,
        src: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        let val = u32::unmarshal(src)?;
        Ok(Self(val))
    }
}
impl Command for TestCommand {
    const CMD_CODE: TpmCc = TpmCc::NVUndefineSpaceSpecial;
    type Response<'a> = TestCommand;
}

#[test]
fn test_tpm_error() {
    let mut fake_tpm = ErrorTpm();
    let cmd = TestCommand(56789);
    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    assert_eq!(
        run_command(&cmd, &mut fake_tpm, &mut resp_buffer),
        Err(ClientError::Connection(TransportError))
    );
}

// FakeU32LoopbackTpm reads/stores the command header and a u32 "command".
// It responds with a response header and the same u32 "response".
struct FakeU32LoopbackTpm {
    rxed_header: Option<CommandHeader>,
    rxed_bytes: usize,
}
impl Connection for FakeU32LoopbackTpm {
    type Error = !;
    fn transact<'a>(&mut self, command: &[u8], response: &'a mut [u8]) -> Result<&'a mut [u8], !> {
        self.rxed_bytes = command.len();
        let mut slice = command;
        self.rxed_header = Some(CommandHeader::unmarshal(&mut slice).unwrap());
        let rxed_value = u32::unmarshal(&mut slice).unwrap();

        let mut tx_header = ResponseHeader {
            tag: TpmSt::NO_SESSIONS,
            size: 0,
            rc: Ok(()),
        };
        let mut written = tx_header.marshal(
            (&mut response[0..ResponseHeader::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        written += rxed_value.marshal((&mut response[written..written + 4]).try_into().unwrap());
        tx_header.size = written as u32;
        // Update the size.
        tx_header.marshal(
            (&mut response[0..ResponseHeader::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        Ok(&mut response[..written])
    }
}

#[test]
fn test_fake_command() {
    let mut fake_tpm = FakeU32LoopbackTpm {
        rxed_header: None,
        rxed_bytes: 0,
    };
    let cmd = TestCommand(56789);
    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    let result = run_command(&cmd, &mut fake_tpm, &mut resp_buffer);
    assert_eq!(fake_tpm.rxed_header.unwrap().code, TestCommand::CMD_CODE);
    assert_eq!(fake_tpm.rxed_bytes, CommandHeader::MAX_SIZE + u32::MAX_SIZE);
    assert_eq!(result.unwrap(), cmd);
}

// EvilSizeTpm writes a response header whose size value is larger than the
// returned response (and the response buffer).
struct EvilSizeTpm();
impl Connection for EvilSizeTpm {
    type Error = !;
    fn transact<'a>(&mut self, _: &[u8], response: &'a mut [u8]) -> Result<&'a mut [u8], !> {
        let tx_header = ResponseHeader {
            tag: TpmSt::NO_SESSIONS,
            size: response.len() as u32 + 2,
            rc: Ok(()),
        };
        let written = tx_header.marshal(
            (&mut response[0..ResponseHeader::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        // Return the slice of the response that was written.
        Ok(&mut response[..written])
    }
}

#[test]
fn test_bad_response_size() {
    let mut fake_tpm = EvilSizeTpm();
    let cmd = TestCommand(2);
    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    assert_eq!(
        run_command(&cmd, &mut fake_tpm, &mut resp_buffer),
        Err(ClientError::InvalidResponseSize)
    );
}

#[test]
fn test_response_parameter_size_too_large() {
    // A `parameterSize` larger than the rest of the response means the
    // response is truncated.
    let mut fake_tpm = FakeTpm::default();
    fake_tpm.header.tag = TpmSt::SESSIONS;
    fake_tpm.add_to_response(&5u32); // parameterSize
    fake_tpm.add_to_response(&56789u32);
    let session = PasswordSession::default();
    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    assert_eq!(
        run_command_with_sessions(&TestCommand(2), session, &mut fake_tpm, &mut resp_buffer),
        Err(ClientError::Unmarshal(UnmarshalError::INSUFFICIENT))
    );
}

#[test]
fn test_response_trailing_bytes() {
    let session = PasswordSession::default();
    let valid_auth = TpmsAuthResponse {
        session_attributes: TpmaSession::CONTINUE_SESSION,
        ..Default::default()
    };
    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];

    // Without sessions, bytes after the parameters are rejected.
    let mut fake_tpm = FakeTpm::default();
    fake_tpm.add_to_response(&56789u32);
    fake_tpm.add_to_response(&0u8);
    assert_eq!(
        run_command(&TestCommand(2), &mut fake_tpm, &mut resp_buffer),
        Err(ClientError::TrailingBytes)
    );

    // So are bytes after the parameters but within `parameterSize`.
    let mut fake_tpm = FakeTpm::default();
    fake_tpm.header.tag = TpmSt::SESSIONS;
    fake_tpm.add_to_response(&5u32); // parameterSize
    fake_tpm.add_to_response(&56789u32);
    fake_tpm.add_to_response(&0u8);
    fake_tpm.add_to_response(&valid_auth);
    assert_eq!(
        run_command_with_sessions(&TestCommand(2), session, &mut fake_tpm, &mut resp_buffer),
        Err(ClientError::TrailingBytes)
    );

    // And bytes after the authorization area.
    let mut fake_tpm = FakeTpm::default();
    fake_tpm.header.tag = TpmSt::SESSIONS;
    fake_tpm.add_to_response(&4u32); // parameterSize
    fake_tpm.add_to_response(&56789u32);
    fake_tpm.add_to_response(&valid_auth);
    fake_tpm.add_to_response(&0u8);
    assert_eq!(
        run_command_with_sessions(&TestCommand(2), session, &mut fake_tpm, &mut resp_buffer),
        Err(ClientError::TrailingBytes)
    );

    // Without the trailing byte, the same response is accepted.
    let mut fake_tpm = FakeTpm::default();
    fake_tpm.header.tag = TpmSt::SESSIONS;
    fake_tpm.add_to_response(&4u32); // parameterSize
    fake_tpm.add_to_response(&56789u32);
    fake_tpm.add_to_response(&valid_auth);
    assert_eq!(
        run_command_with_sessions(&TestCommand(2), session, &mut fake_tpm, &mut resp_buffer),
        Ok(TestCommand(56789))
    );
}

// FakeTpm responds to any command with `header` followed by the bytes added
// with `add_to_response`, fixing up the header's size.
pub struct FakeTpm {
    len: usize,
    response: [u8; RESP_BUFFER_SIZE],
    header: ResponseHeader,
}
impl Default for FakeTpm {
    fn default() -> Self {
        FakeTpm {
            len: 0,
            response: [0; RESP_BUFFER_SIZE],
            header: ResponseHeader {
                tag: TpmSt::NO_SESSIONS,
                size: 0,
                rc: Ok(()),
            },
        }
    }
}
impl Connection for FakeTpm {
    type Error = !;
    fn transact<'a>(&mut self, _: &[u8], response: &'a mut [u8]) -> Result<&'a mut [u8], !> {
        let off = self.header.marshal(
            (&mut response[0..ResponseHeader::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        let length = off + self.len;
        response[off..length].copy_from_slice(&self.response[..self.len]);
        self.header.size = length as u32;
        self.header.marshal(
            (&mut response[0..ResponseHeader::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        Ok(&mut response[..length])
    }
}
impl FakeTpm {
    fn add_to_response<M: Marshal<MaxBuffer = [u8; N]>, const N: usize>(&mut self, val: &M) {
        let mut tmp = [0u8; N];
        let written = val.marshal(&mut tmp);
        self.response[self.len..self.len + written].copy_from_slice(&tmp[..written]);
        self.len += written;
    }
}

// A command with a single handle and no parameters, whose response
// (`TestHandlesRsp`) also has a single handle and no parameters.
struct TestHandlesCommand {
    handle: Handle,
}
impl Message for TestHandlesCommand {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.handle]
    }
}
impl Marshal for TestHandlesCommand {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl Command for TestHandlesCommand {
    const CMD_CODE: TpmCc = TpmCc::NVUndefineSpaceSpecial;
    type Response<'a> = TestHandlesRsp;
}

#[derive(Debug, PartialEq, Eq)]
struct TestHandlesRsp {
    handle: Handle,
}
impl Message for TestHandlesRsp {
    type Handles = [Handle; 1];
    fn handles(&self) -> Self::Handles {
        [self.handle]
    }
}
impl Marshal for TestHandlesRsp {
    const MAX_SIZE: usize = 0;
    type MaxBuffer = [u8; 0];
    fn marshal(&self, _: &mut Self::MaxBuffer) -> usize {
        0
    }
}
impl<'a> UnmarshalMessage<'a> for TestHandlesRsp {
    fn unmarshal_with_handles(
        [handle]: Self::Handles,
        _: &mut &'a [u8],
    ) -> Result<Self, UnmarshalError> {
        Ok(Self { handle })
    }
}

#[test]
fn test_command_and_response_handles() {
    let cmd = TestHandlesCommand {
        handle: Handle(0x8100_0001),
    };
    let session = PasswordSession::new("password").unwrap();

    // The command handle precedes the authorization area.
    let mut cmd_buffer = [0u8; CMD_BUFFER_SIZE];
    let written = marshal_command(&cmd, &session, &mut cmd_buffer);
    let mut src = &cmd_buffer[..written];
    let header = CommandHeader::unmarshal(&mut src).unwrap();
    assert_eq!(header.tag, TpmiStCommandTag::Sessions);
    assert_eq!(header.size as usize, written);
    assert_eq!(Handle::unmarshal(&mut src), Ok(cmd.handle));
    let auth_size = u32::unmarshal(&mut src).unwrap() as usize;
    // The command has no parameters, so the authorization area comes last.
    assert_eq!(auth_size, src.len());
    assert_eq!(
        TpmsAuthCommand::unmarshal(&mut src),
        Ok(session.auth_command())
    );

    // The response handle is returned inside the response.
    let mut fake_tpm = FakeTpm::default();
    fake_tpm.header.tag = TpmSt::SESSIONS;
    fake_tpm.add_to_response(&Handle(0x8000_0002));
    fake_tpm.add_to_response(&0u32); // parameterSize
    fake_tpm.add_to_response(&TpmsAuthResponse {
        session_attributes: TpmaSession::CONTINUE_SESSION,
        ..Default::default()
    });
    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    assert_eq!(
        run_command_with_sessions(&cmd, session, &mut fake_tpm, &mut resp_buffer),
        Ok(TestHandlesRsp {
            handle: Handle(0x8000_0002)
        })
    );
}

#[test]
fn test_response_missing_handles() {
    let mut fake_tpm = FakeTpm::default();
    let cmd = TestHandlesCommand {
        handle: Handle::default(),
    };
    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    assert_eq!(
        run_command(&cmd, &mut fake_tpm, &mut resp_buffer),
        Err(ClientError::Unmarshal(UnmarshalError::INSUFFICIENT))
    );
}

#[test]
fn test_response_missing_sessions() {
    let cmd = TestHandlesCommand {
        handle: Handle::RS_PW,
    };
    let session = PasswordSession::default();
    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];

    // A `TPM_ST_NO_SESSIONS` response (with the single response handle) to a
    // command with a session is rejected.
    let mut fake_tpm = FakeTpm::default();
    fake_tpm.add_to_response(&Handle(77));
    assert_eq!(
        run_command_with_sessions(&cmd, session, &mut fake_tpm, &mut resp_buffer),
        Err(ClientError::UnexpectedTag)
    );

    // So is a `TPM_ST_SESSIONS` response whose authorization area is missing.
    let mut fake_tpm = FakeTpm::default();
    fake_tpm.header.tag = TpmSt::SESSIONS;
    fake_tpm.add_to_response(&Handle(77));
    fake_tpm.add_to_response(&0u32); // parameterSize
    assert_eq!(
        run_command_with_sessions(&cmd, session, &mut fake_tpm, &mut resp_buffer),
        Err(ClientError::Unmarshal(UnmarshalError::INSUFFICIENT))
    );
}

#[test]
fn test_response_session_fails_validation() {
    let mut fake_tpm = FakeTpm::default();
    // Respond with the single response handle, and an invalid password auth.
    fake_tpm.header.tag = TpmSt::SESSIONS;
    fake_tpm.add_to_response(&Handle(77));
    fake_tpm.add_to_response(&0u32); // parameterSize
    let invalid_auth = TpmsAuthResponse {
        session_attributes: TpmaSession(0x07),
        ..Default::default()
    };
    let validation_failure = PasswordSession::default().validate_auth_response(&invalid_auth);
    assert!(validation_failure.is_err());
    fake_tpm.add_to_response(&invalid_auth);

    let cmd = TestHandlesCommand {
        handle: Handle::RS_PW,
    };
    let session = PasswordSession::default();
    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    assert_eq!(
        run_command_with_sessions(&cmd, session, &mut fake_tpm, &mut resp_buffer),
        Err(ClientError::Auth(validation_failure.err().unwrap()))
    );
}

#[test]
fn test_testing_commands_client_roundtrip() {
    // 1. SelfTest
    let mut fake_tpm = FakeTpm::default();
    let self_test_cmd = SelfTest { full_test: true };
    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    assert_eq!(
        run_command(&self_test_cmd, &mut fake_tpm, &mut resp_buffer),
        Ok(())
    );

    // 2. IncrementalSelfTest
    let mut fake_tpm = FakeTpm::default();
    let expected_todo = tpm2::TpmlAlg::from_slice(&[tpm2::Alg::RSA, tpm2::Alg::AES]).unwrap();
    let inc_rsp = responses::IncrementalSelfTest {
        to_do_list: expected_todo,
    };
    fake_tpm.add_to_response(&inc_rsp);
    let inc_cmd = IncrementalSelfTest {
        to_test: tpm2::TpmlAlg::from_slice(&[tpm2::Alg::SHA256]).unwrap(),
    };
    assert_eq!(
        run_command(&inc_cmd, &mut fake_tpm, &mut resp_buffer),
        Ok(inc_rsp)
    );

    // 3. GetTestResult
    let mut fake_tpm = FakeTpm::default();
    let get_rsp = responses::GetTestResult {
        out_data: tpm2::Tpm2bMaxBuffer::new(&[0x11, 0x22, 0x33]).unwrap(),
        test_result: Err(tpm2::errors::TpmRc::NEEDS_TEST),
    };
    fake_tpm.add_to_response(&get_rsp);
    let get_cmd = GetTestResult;
    assert_eq!(
        run_command(&get_cmd, &mut fake_tpm, &mut resp_buffer),
        Ok(get_rsp)
    );
}

#[test]
fn test_response_header_rsp_command_bad_tag_client() {
    let mut fake_tpm = FakeTpm {
        header: ResponseHeader {
            tag: TpmSt::RSP_COMMAND,
            size: ResponseHeader::MAX_SIZE as u32,
            rc: Err(tpm2::errors::TpmRc::BAD_TAG),
        },
        ..Default::default()
    };
    let cmd = SelfTest { full_test: true };
    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    assert_eq!(
        run_command(&cmd, &mut fake_tpm, &mut resp_buffer),
        Err(ClientError::Tpm(tpm2::errors::TpmRc::BAD_TAG))
    );
}

#[test]
fn test_password_auth_command() {
    let session = PasswordSession::new("hello").unwrap();
    let tpm_auth = session.auth_command();
    assert_eq!(tpm_auth.session_handle, Handle::RS_PW);
    assert_eq!(tpm_auth.hmac.as_slice().len(), 5);
    assert_eq!(tpm_auth.hmac.as_slice(), b"hello");
}
