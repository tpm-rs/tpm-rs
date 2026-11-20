use crate::{
    ClientError,
    sessions::{AuthError, CommandData, ResponseData, Session},
};
use tpm2::{Marshal, TpmiStCommandTag, TpmsAuthCommand, TpmsAuthResponse, Unmarshal};

/// A trait for an authorization area with zero to three [`Session`]s.
pub trait AuthorizationArea {
    fn session1(&mut self) -> Option<&mut impl Session> {
        None::<&mut !>
    }
    fn session2(&mut self) -> Option<&mut impl Session> {
        None::<&mut !>
    }
    fn session3(&mut self) -> Option<&mut impl Session> {
        None::<&mut !>
    }

    /// Returns `Sessions` if at least one session is present, or `NoSessions` otherwise.
    fn tag(&mut self) -> TpmiStCommandTag {
        if self.session1().is_none() {
            TpmiStCommandTag::NoSessions
        } else {
            TpmiStCommandTag::Sessions
        }
    }

    /// Marshals all present session `TPMS_AUTH_COMMAND`s for `cmd` into `dst`,
    /// returning bytes written.
    fn marshal_auth_commands(
        &mut self,
        cmd: &CommandData,
        dst: &mut [u8; 3 * TpmsAuthCommand::MAX_SIZE]
    ) -> Result<usize, AuthError> {
        let mut remaining: &mut [u8] = dst;
        let mut bytes_written = 0;
        if let Some(session) = self.session1() {
            let chunk = remaining.first_chunk_mut().unwrap();
            let count = session.auth_command(cmd)?.marshal(chunk);
            remaining = &mut remaining[count..];
            bytes_written += count;
        }
        if let Some(session) = self.session2() {
            let chunk = remaining.first_chunk_mut().unwrap();
            let count = session.auth_command(cmd)?.marshal(chunk);
            remaining = &mut remaining[count..];
            bytes_written += count;
        }
        if let Some(session) = self.session3() {
            let chunk = remaining.first_chunk_mut().unwrap();
            let count = session.auth_command(cmd)?.marshal(chunk);
            bytes_written += count;
        }
        Ok(bytes_written)
    }

    /// Unmarshals and validates each session's `TPMS_AUTH_RESPONSE` for `rsp` from `src`,
    /// returning [`ClientError::TrailingBytes`] if any unconsumed bytes remain.
    fn validate_auth_responses<E>(
        &mut self,
        rsp: &ResponseData,
        mut src: &[u8]
    ) -> Result<(), ClientError<E>> {
        if let Some(session) = self.session1() {
            let auth = TpmsAuthResponse::unmarshal(&mut src)?;
            session.validate_auth_response(rsp, &auth)?;
        }
        if let Some(session) = self.session2() {
            let auth = TpmsAuthResponse::unmarshal(&mut src)?;
            session.validate_auth_response(rsp, &auth)?;
        }
        if let Some(session) = self.session3() {
            let auth = TpmsAuthResponse::unmarshal(&mut src)?;
            session.validate_auth_response(rsp, &auth)?;
        }
        if !src.is_empty() {
            return Err(ClientError::TrailingBytes);
        }
        Ok(())
    }
}

impl AuthorizationArea for () {}

impl<T: Session> AuthorizationArea for T {
    fn session1(&mut self) -> Option<&mut impl Session> {
        Some(self)
    }
}

impl<T: Session, U: Session> AuthorizationArea for (T, U) {
    fn session1(&mut self) -> Option<&mut impl Session> {
        Some(&mut self.0)
    }
    fn session2(&mut self) -> Option<&mut impl Session> {
        Some(&mut self.1)
    }
}

impl<T: Session, U: Session, V: Session> AuthorizationArea for (T, U, V) {
    fn session1(&mut self) -> Option<&mut impl Session> {
        Some(&mut self.0)
    }
    fn session2(&mut self) -> Option<&mut impl Session> {
        Some(&mut self.1)
    }
    fn session3(&mut self) -> Option<&mut impl Session> {
        Some(&mut self.2)
    }
}
