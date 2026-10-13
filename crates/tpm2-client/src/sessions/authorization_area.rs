use crate::{ClientError, sessions::Session};
use tpm2::{Marshal, TpmiStCommandTag, TpmsAuthCommand, TpmsAuthResponse, Unmarshal};

/// A trait for an authorization area with zero to three [`Session`]s.
pub trait AuthorizationArea {
    fn session1(&self) -> Option<&impl Session> {
        None::<&!>
    }
    fn session2(&self) -> Option<&impl Session> {
        None::<&!>
    }
    fn session3(&self) -> Option<&impl Session> {
        None::<&!>
    }

    /// Returns `Sessions` if at least one session is present, or `NoSessions` otherwise.
    fn tag(&self) -> TpmiStCommandTag {
        if self.session1().is_none() {
            TpmiStCommandTag::NoSessions
        } else {
            TpmiStCommandTag::Sessions
        }
    }

    /// Marshals all present session `TPMS_AUTH_COMMAND`s into `dst`, returning bytes written.
    fn marshal_auth_commands(&self, dst: &mut [u8; 3 * TpmsAuthCommand::MAX_SIZE]) -> usize {
        let mut remaining: &mut [u8] = dst;
        let mut bytes_written = 0;
        if let Some(session) = self.session1() {
            let chunk = remaining.first_chunk_mut().unwrap();
            let count = session.auth_command().marshal(chunk);
            remaining = &mut remaining[count..];
            bytes_written += count;
        }
        if let Some(session) = self.session2() {
            let chunk = remaining.first_chunk_mut().unwrap();
            let count = session.auth_command().marshal(chunk);
            remaining = &mut remaining[count..];
            bytes_written += count;
        }
        if let Some(session) = self.session3() {
            let chunk = remaining.first_chunk_mut().unwrap();
            let count = session.auth_command().marshal(chunk);
            bytes_written += count;
        }
        bytes_written
    }

    /// Unmarshals and validates each session's `TPMS_AUTH_RESPONSE` from `src`,
    /// returning [`ClientError::TrailingBytes`] if any unconsumed bytes remain.
    fn validate_auth_responses<E>(&self, mut src: &[u8]) -> Result<(), ClientError<E>> {
        if let Some(session) = self.session1() {
            let auth = TpmsAuthResponse::unmarshal(&mut src)?;
            session.validate_auth_response(&auth)?;
        }
        if let Some(session) = self.session2() {
            let auth = TpmsAuthResponse::unmarshal(&mut src)?;
            session.validate_auth_response(&auth)?;
        }
        if let Some(session) = self.session3() {
            let auth = TpmsAuthResponse::unmarshal(&mut src)?;
            session.validate_auth_response(&auth)?;
        }
        if !src.is_empty() {
            return Err(ClientError::TrailingBytes);
        }
        Ok(())
    }
}

impl AuthorizationArea for () {}

impl<T: Session> AuthorizationArea for T {
    fn session1(&self) -> Option<&impl Session> {
        Some(self)
    }
}

impl<T: Session, U: Session> AuthorizationArea for (T, U) {
    fn session1(&self) -> Option<&impl Session> {
        Some(&self.0)
    }
    fn session2(&self) -> Option<&impl Session> {
        Some(&self.1)
    }
}

impl<T: Session, U: Session, V: Session> AuthorizationArea for (T, U, V) {
    fn session1(&self) -> Option<&impl Session> {
        Some(&self.0)
    }
    fn session2(&self) -> Option<&impl Session> {
        Some(&self.1)
    }
    fn session3(&self) -> Option<&impl Session> {
        Some(&self.2)
    }
}
