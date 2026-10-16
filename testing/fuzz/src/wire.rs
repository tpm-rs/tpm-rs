//! Parsing and well-formedness checks of TPM command and response buffers.
//!
//! The driver parses every command it sends (also [`crate::model::Step::Raw`]
//! ones, when they parse) to learn its code, handles and parameters, and every
//! `tpm-rs` response to check that it is well formed (the "malformed
//! response" oracle) and to split it into handles, parameters and the
//! authorization area.

use testing::differential::server::handle_counts;

use crate::model::{TPM_ST_NO_SESSIONS, TPM_ST_SESSIONS};

/// `TPM_RC_SUCCESS`.
pub const TPM_RC_SUCCESS: u32 = 0;

/// A big-endian `u16` at `at`.
pub fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

/// A big-endian `u32` at `at`.
pub fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// A cursor over marshaled TPM data.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    /// The next `n` bytes.
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    /// The next `u8`.
    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    /// The next big-endian `u16`.
    pub fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    /// The next big-endian `u32`.
    pub fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// The next TPM2B in wire form (size field and buffer).
    pub fn tpm2b(&mut self) -> Option<&'a [u8]> {
        let size = usize::from(be16(self.0, 0)?);
        self.take(2 + size)
    }

    /// The buffer of the next TPM2B.
    pub fn tpm2b_body(&mut self) -> Option<&'a [u8]> {
        self.tpm2b().map(|b| &b[2..])
    }

    /// The unread bytes.
    pub fn rest(&self) -> &'a [u8] {
        self.0
    }
}

/// The parts of a command buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandView<'a> {
    /// The tag.
    pub tag: u16,
    /// The command code.
    pub code: u32,
    /// The handle area (as many handles as the command code has).
    pub handles: Vec<u32>,
    /// The authorization area without its size field (empty without
    /// `TPM_ST_SESSIONS`).
    pub auth: &'a [u8],
    /// The parameter area.
    pub params: &'a [u8],
}

/// Splits a command buffer into its parts; `None` if it is too short, its
/// command code is unknown, or its authorization area does not fit. The
/// `commandSize` field is not checked (the driver may have broken it on
/// purpose).
pub fn parse_command(cmd: &[u8]) -> Option<CommandView<'_>> {
    let tag = be16(cmd, 0)?;
    let code = be32(cmd, 6)?;
    let (n, _) = handle_counts(code)?;
    let mut r = Reader(cmd.get(10..)?);
    let handles = (0..n).map(|_| r.u32()).collect::<Option<Vec<_>>>()?;
    let auth = if tag == TPM_ST_SESSIONS {
        let size = r.u32()? as usize;
        r.take(size)?
    } else {
        &[]
    };
    Some(CommandView {
        tag,
        code,
        handles,
        auth,
        params: r.rest(),
    })
}

/// One `TPMS_AUTH_COMMAND`/`TPMS_AUTH_RESPONSE` session of an authorization
/// area, without its handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseSession<'a> {
    /// `nonceTPM` (the TPM2B buffer).
    pub nonce: &'a [u8],
    /// `TPMA_SESSION`.
    pub attrs: u8,
    /// The response HMAC (the TPM2B buffer).
    pub hmac: &'a [u8],
}

/// The parts of a well-formed response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseView<'a> {
    /// The tag.
    pub tag: u16,
    /// The response code.
    pub rc: u32,
    /// The response handles (none for error responses).
    pub handles: Vec<u32>,
    /// The parameter area (empty for error responses).
    pub params: &'a [u8],
    /// The response sessions (only for `TPM_ST_SESSIONS`).
    pub sessions: Vec<ResponseSession<'a>>,
}

/// Checks that `rsp`, the `tpm-rs` response to a command with tag
/// `command_tag` and code `code` (when the command parsed), is well formed and
/// splits it.
///
/// Well formed means: at least a 10-byte header whose `responseSize` equals
/// the length and whose tag is `TPM_ST_NO_SESSIONS` or `TPM_ST_SESSIONS`; an
/// error response is exactly a `TPM_ST_NO_SESSIONS` header; a success
/// response carries the command's tag and, for a known command code, all of
/// its response handles, and with `TPM_ST_SESSIONS` a `parameterSize` that
/// fits and an authorization area that parses exactly into sessions.
///
/// # Errors
/// A description of the first violation.
pub fn check_response(
    rsp: &[u8],
    command_tag: Option<u16>,
    code: Option<u32>,
) -> Result<ResponseView<'_>, String> {
    if rsp.len() < 10 {
        return Err(format!("{} bytes, shorter than a header", rsp.len()));
    }
    let tag = be16(rsp, 0).unwrap_or_default();
    let size = be32(rsp, 2).unwrap_or_default();
    let rc = be32(rsp, 6).unwrap_or_default();
    if size as usize != rsp.len() {
        return Err(format!("responseSize {size} != length {}", rsp.len()));
    }
    if tag != TPM_ST_NO_SESSIONS && tag != TPM_ST_SESSIONS {
        return Err(format!("invalid tag {tag:#06x}"));
    }
    if rc != TPM_RC_SUCCESS {
        if tag != TPM_ST_NO_SESSIONS || rsp.len() != 10 {
            return Err(format!(
                "error response {rc:#x} with tag {tag:#06x} and {} bytes",
                rsp.len()
            ));
        }
        return Ok(ResponseView {
            tag,
            rc,
            handles: Vec::new(),
            params: &[],
            sessions: Vec::new(),
        });
    }
    if let Some(command_tag) = command_tag
        && command_tag != tag
    {
        return Err(format!(
            "success response tag {tag:#06x} != command tag {command_tag:#06x}"
        ));
    }
    let n_handles = code.and_then(handle_counts).map_or(0, |(_, n)| n);
    let mut r = Reader(&rsp[10..]);
    let handles = (0..n_handles)
        .map(|_| r.u32())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| format!("missing response handles ({n_handles} expected)"))?;
    if tag == TPM_ST_NO_SESSIONS {
        return Ok(ResponseView {
            tag,
            rc,
            handles,
            params: r.rest(),
            sessions: Vec::new(),
        });
    }
    let param_size = r.u32().ok_or("missing parameterSize")? as usize;
    let params = r
        .take(param_size)
        .ok_or_else(|| format!("parameterSize {param_size} exceeds the response"))?;
    let mut sessions = Vec::new();
    while !r.rest().is_empty() {
        let session = (|| {
            Some(ResponseSession {
                nonce: r.tpm2b_body()?,
                attrs: r.u8()?,
                hmac: r.tpm2b_body()?,
            })
        })()
        .ok_or("truncated response session")?;
        sessions.push(session);
    }
    if sessions.is_empty() {
        return Err("TPM_ST_SESSIONS success response without sessions".into());
    }
    Ok(ResponseView {
        tag,
        rc,
        handles,
        params,
        sessions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_commands() {
        // NV_Write(owner, 0x01000000) with one password session.
        let cmd = [
            0x80, 0x02, 0, 0, 0, 0x20, 0, 0, 0x01, 0x37, 0x40, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 9,
            0x40, 0, 0, 9, 0, 0, 1, 0, 0, 0xAB,
        ];
        let v = parse_command(&cmd).unwrap();
        assert_eq!(v.tag, TPM_ST_SESSIONS);
        assert_eq!(v.code, 0x137);
        assert_eq!(v.handles, [0x4000_0001, 0x0100_0000]);
        assert_eq!(v.auth, [0x40, 0, 0, 9, 0, 0, 1, 0, 0]);
        assert_eq!(v.params, [0xAB]);
        // Unknown code, truncated handles, oversized auth area.
        assert!(parse_command(&[0x80, 1, 0, 0, 0, 10, 0, 0, 0, 0]).is_none());
        assert!(parse_command(&cmd[..12]).is_none());
        let mut bad = cmd;
        bad[21] = 0xFF;
        assert!(parse_command(&bad).is_none());
        assert!(parse_command(&[0x80]).is_none());
    }

    #[test]
    fn accepts_well_formed_responses() {
        let err = [0x80, 1, 0, 0, 0, 10, 0, 0, 1, 0x01];
        assert_eq!(
            check_response(&err, Some(0x8002), Some(0x131)).unwrap().rc,
            0x101
        );
        // StartAuthSession, no sessions: handle + nonce.
        let ok = [
            0x80, 1, 0, 0, 0, 18, 0, 0, 0, 0, 3, 0, 0, 0, 0, 2, 0xAA, 0xBB,
        ];
        let v = check_response(&ok, Some(0x8001), Some(0x176)).unwrap();
        assert_eq!(v.handles, [0x0300_0000]);
        assert_eq!(v.params, [0, 2, 0xAA, 0xBB]);
        // With sessions: parameterSize 2, one session (nonce 1 byte, attrs,
        // empty hmac).
        let ok = [
            0x80, 2, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1, 0x55, 1, 0, 0,
        ];
        let v = check_response(&ok, Some(0x8002), Some(0x17B)).unwrap();
        assert_eq!(v.params, [0, 0]);
        assert_eq!(
            v.sessions,
            [ResponseSession {
                nonce: &[0x55],
                attrs: 1,
                hmac: &[]
            }]
        );
    }

    #[test]
    fn rejects_malformed_responses() {
        assert!(check_response(&[0x80, 1], None, None).is_err());
        // Size mismatch.
        assert!(check_response(&[0x80, 1, 0, 0, 0, 11, 0, 0, 0, 0], None, None).is_err());
        // Bad tag.
        assert!(check_response(&[0x80, 3, 0, 0, 0, 10, 0, 0, 0, 0], None, None).is_err());
        // Error with sessions tag or a body.
        assert!(check_response(&[0x80, 2, 0, 0, 0, 10, 0, 0, 1, 1], None, None).is_err());
        assert!(check_response(&[0x80, 1, 0, 0, 0, 11, 0, 0, 1, 1, 0], None, None).is_err());
        // Success tag differs from the command's.
        assert!(check_response(&[0x80, 1, 0, 0, 0, 10, 0, 0, 0, 0], Some(0x8002), None).is_err());
        // Missing response handle.
        assert!(
            check_response(&[0x80, 1, 0, 0, 0, 12, 0, 0, 0, 0, 1, 2], None, Some(0x131)).is_err()
        );
        // parameterSize too large, truncated session, no sessions.
        let rsp = [0x80, 2, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 9];
        assert!(check_response(&rsp, None, Some(0x17B)).is_err());
        let rsp = [0x80, 2, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
        assert!(check_response(&rsp, None, Some(0x17B)).is_err());
        let rsp = [0x80, 2, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(check_response(&rsp, None, Some(0x17B)).is_err());
    }
}
