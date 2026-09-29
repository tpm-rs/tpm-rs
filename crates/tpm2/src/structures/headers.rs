use crate::{
    TpmCc, TpmSt, TpmiStCommandTag,
    errors::{TpmRc, UnmarshalError},
    marshal::{Marshal, Unmarshal, marshal_helper},
};

/// TPM 2.0 10-byte standard command header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CommandHeader {
    /// Command tag indicating session presence (`TPM_ST_NO_SESSIONS` or `TPM_ST_SESSIONS`).
    pub tag: TpmiStCommandTag,
    /// Total size (in bytes) of the command, including this header.
    pub size: u32,
    /// Command code (`TPM_CC`).
    pub code: TpmCc,
}

impl CommandHeader {
    /// Creates a new `CommandHeader` with the given session indicator and command code.
    pub const fn with_sessions(has_sessions: bool, code: TpmCc) -> Self {
        Self {
            tag: if has_sessions {
                TpmiStCommandTag::Sessions
            } else {
                TpmiStCommandTag::NoSessions
            },
            size: 0,
            code,
        }
    }
}

impl Marshal for CommandHeader {
    const MAX_SIZE: usize = TpmiStCommandTag::MAX_SIZE + u32::MAX_SIZE + TpmCc::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.tag, dst, 0);
        let count = marshal_helper(&self.size, dst, count);
        marshal_helper(&self.code, dst, count)
    }
}

impl<'a> Unmarshal<'a> for CommandHeader {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        Ok(Self {
            tag: Unmarshal::unmarshal(src)?,
            size: Unmarshal::unmarshal(src)?,
            code: Unmarshal::unmarshal(src)?,
        })
    }
}

/// TPM 2.0 10-byte standard response header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ResponseHeader {
    /// Response tag (`TPM_ST_NO_SESSIONS`, `TPM_ST_SESSIONS`, or `TPM_ST_RSP_COMMAND`).
    pub tag: TpmSt,
    /// Total size (in bytes) of the response, including this header.
    pub size: u32,
    /// Response code: `Ok(())` for `TPM_RC_SUCCESS` (0), or `Err(TpmRc)` for failures.
    pub rc: Result<(), TpmRc>,
}

impl Marshal for ResponseHeader {
    const MAX_SIZE: usize = TpmSt::MAX_SIZE + u32::MAX_SIZE + <Result<(), TpmRc>>::MAX_SIZE;
    type MaxBuffer = [u8; Self::MAX_SIZE];

    fn marshal(&self, dst: &mut Self::MaxBuffer) -> usize {
        let count = marshal_helper(&self.tag, dst, 0);
        let count = marshal_helper(&self.size, dst, count);
        marshal_helper(&self.rc, dst, count)
    }
}

impl<'a> Unmarshal<'a> for ResponseHeader {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, UnmarshalError> {
        let tag: TpmSt = Unmarshal::unmarshal(src)?;
        if !matches!(
            tag,
            TpmSt::NO_SESSIONS | TpmSt::SESSIONS | TpmSt::RSP_COMMAND
        ) {
            return Err(UnmarshalError::BAD_TAG);
        }
        Ok(Self {
            tag,
            size: Unmarshal::unmarshal(src)?,
            rc: Unmarshal::unmarshal(src)?,
        })
    }
}
