//! TPM Command and Response Buffer Cursor Management.
//!
//! This module provides safe cursor wrappers ([RequestThenResponse], [Response], and [RequestResponseCursor])
//! to manage the unmarshaling of TPM command requests and the marshaling of TPM responses. It serves three
//! major purposes, using Rust's typing to enforce correct command handling.
//!
//! 1. **Strict Ordering (TPM 2.0 Command Execution Lifecycle)**:
//!    Per the TCG TPM 2.0 Library Specification (Part 1: Architecture, Section 5), TPM command processing
//!    is structured into three non-overlapping phases:
//!    - **Parse & Validate**: Command headers, handles, authorizations, and parameters are read.
//!    - **Execute**: Command actions are performed.
//!    - **Response Construction**: Response headers, parameters, and acknowledge sessions are written.
//!
//!    [RequestThenResponse] enforces this strict state transition at compile time using Rust's ownership model.
//!    It only allows reading from the request. To write a response, it must be consumed via [RequestThenResponse::into_response()],
//!    transitioning to a write-only [Response] object and making it impossible to read more request data or
//!    interleave reads and writes.
//!
//! 2. **Physical and Memory Safety**:
//!    The physical TPM interface (defined by the TCG PC Client TPM Profile spec) is half-duplex and
//!    transaction-oriented (request packet -> execution -> response packet). While input and output buffers
//!    may reside in separate memory slices (or share a single buffer for in-place execution), they must never
//!    be accessed concurrently or out of order. By encapsulating offsets and slices, these wrappers guarantee
//!    memory safety and out-of-bounds safety ([WriteOutOfBounds]) without leaking raw offsets or slices to
//!    command handlers.
//!
//! 3. **Encapsulation & Ergonomics**:
//!    Instead of forcing handlers to manage individual offsets (`request_offset`, `response_offset`) and pass
//!    around multiple mutable slices, the cursor encapsulates buffer state and carries shared metadata (e.g.,
//!    `session_tag`) across the transition.

use tpm2::commands::{Message, UnmarshalMessage};
use tpm2::errors::{Position, TpmRc};

/// Error indicating that write would have written past the end of the response buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteOutOfBounds;

/// Provides access to the TPM command request object and then a one-way conversion to the mutable
/// response object for the TPM command.
pub struct RequestThenResponse<'a, 'b> {
    buffers: &'a mut RequestResponseCursor<'b>,
}

impl<'a, 'b> RequestThenResponse<'a, 'b> {
    /// Reads a `u16` encoded in big endian from the request's last read position. Increments the
    /// last position past this field. Returns `None` if the read would have read past the end of
    /// the request.
    pub fn read_be_u16(&mut self) -> Option<u16> {
        if self.remaining_bytes() < 2 {
            return None;
        }
        let result = u16::from_be_bytes([
            self.buffers.cmd_buf[self.buffers.request_offset],
            self.buffers.cmd_buf[self.buffers.request_offset + 1],
        ]);
        self.buffers.request_offset += 2;
        Some(result)
    }

    pub fn read_u8(&mut self) -> Option<u8> {
        if self.remaining_bytes() < 1 {
            return None;
        }
        let result = self.buffers.cmd_buf[self.buffers.request_offset];
        self.buffers.request_offset += 1;
        Some(result)
    }

    /// Reads a `u32` encoded in big endian from the request's last read position. Increments the
    /// last position past this field. Returns `None` if the read would have read past the end of
    /// the request.
    pub fn read_be_u32(&mut self) -> Option<u32> {
        if self.remaining_bytes() < 4 {
            return None;
        }
        let result = u32::from_be_bytes([
            self.buffers.cmd_buf[self.buffers.request_offset],
            self.buffers.cmd_buf[self.buffers.request_offset + 1],
            self.buffers.cmd_buf[self.buffers.request_offset + 2],
            self.buffers.cmd_buf[self.buffers.request_offset + 3],
        ]);
        self.buffers.request_offset += 4;
        Some(result)
    }

    /// Returns the number of unread bytes in the request buffer.
    pub fn remaining_bytes(&self) -> usize {
        self.buffers.cmd_buf.len() - self.buffers.request_offset
    }

    /// Returns a slice of the remaining unread bytes in the request buffer.
    pub fn remaining_slice(&self) -> &[u8] {
        &self.buffers.cmd_buf[self.buffers.request_offset..]
    }

    /// Reads a slice of exactly `size` unread bytes from the request buffer and increments the read offset.
    pub fn read_slice(&mut self, size: usize) -> Option<&[u8]> {
        if size > self.remaining_bytes() {
            return None;
        }
        let slice =
            &self.buffers.cmd_buf[self.buffers.request_offset..self.buffers.request_offset + size];
        self.buffers.request_offset += size;
        Some(slice)
    }

    /// Skips `size` bytes in the request buffer.
    pub fn skip(&mut self, size: usize) {
        if size <= self.remaining_bytes() {
            self.buffers.request_offset += size;
        }
    }

    /// Reads exactly `out.len()` bytes into `out`. Returns `None` if there are not enough bytes.
    pub fn read_bytes(&mut self, out: &mut [u8]) -> Option<()> {
        if out.len() > self.remaining_bytes() {
            return None;
        }
        out.copy_from_slice(
            &self.buffers.cmd_buf
                [self.buffers.request_offset..self.buffers.request_offset + out.len()],
        );
        self.buffers.request_offset += out.len();
        Some(())
    }

    /// Runs `f` on the unread request bytes and, on success, advances the read
    /// offset past the bytes `f` consumed.
    fn unmarshal_with<R>(
        &mut self,
        f: impl FnOnce(&mut &'b [u8]) -> Result<R, TpmRc>,
    ) -> Result<R, TpmRc> {
        let cmd_buf: &'b [u8] = self.buffers.cmd_buf;
        let mut slice = cmd_buf
            .get(self.buffers.request_offset..)
            .unwrap_or_default();
        let original_len = slice.len();
        let result = f(&mut slice)?;
        let read = original_len - slice.len();
        self.buffers.request_offset += read;
        Ok(result)
    }

    pub fn try_unmarshal<T: tpm2::Unmarshal<'b>>(&mut self) -> Result<T, TpmRc> {
        self.unmarshal_with(|src| T::unmarshal(src).map_err(TpmRc::from))
    }

    /// Unmarshals a single `T` from the request, reporting an unmarshal
    /// failure at `position`.
    ///
    /// PORTING: replaces exp's
    /// `request.try_unmarshal::<T>().map_err(|e| e.with_position(p))`.
    pub fn try_unmarshal_at<T: tpm2::Unmarshal<'b>>(
        &mut self,
        position: Position,
    ) -> Result<T, TpmRc> {
        self.unmarshal_with(|src| T::unmarshal(src).map_err(|e| e.fmt1().with(position)))
    }

    /// Reads the handle area of command `M` (`M::Handles`, i.e. `[Handle; N]`)
    /// from the request.
    ///
    /// PORTING: replaces exp's `request.try_unmarshal::<XHandles>()`. Handles
    /// are returned in specification order, e.g.
    /// `let [auth, object_handle] = request.try_unmarshal_handles::<EvictControl>()?;`.
    pub fn try_unmarshal_handles<M: Message>(&mut self) -> Result<M::Handles, TpmRc> {
        let mut handles = M::Handles::default();
        for handle in handles.as_mut() {
            *handle = self.try_unmarshal::<tpm2::Handle>()?;
        }
        Ok(handles)
    }

    /// Unmarshals the parameter area of command `M` and combines it with
    /// `handles` (previously read with [`Self::try_unmarshal_handles`], or `[]`
    /// for commands without a handle area).
    ///
    /// Parameter unmarshal failures are reported with their parameter
    /// [`Position`] (see [`UnmarshalMessage`]).
    ///
    /// PORTING: replaces exp's parameter-area `request.try_unmarshal::<X>()`.
    pub fn try_unmarshal_command<M: UnmarshalMessage<'b>>(
        &mut self,
        handles: M::Handles,
    ) -> Result<M, TpmRc> {
        self.unmarshal_with(|src| M::unmarshal_with_handles(handles, src))
    }

    /// Converts this request view into a mutable response that can be written to.
    pub fn into_response(self) -> Response<'a, 'b> {
        Response {
            buffers: self.buffers,
        }
    }

    pub fn session_tag(&self) -> tpm2::TpmiStCommandTag {
        self.buffers.session_tag
    }

    pub fn set_session_tag(&mut self, tag: tpm2::TpmiStCommandTag) {
        self.buffers.session_tag = tag;
    }

    pub fn last_request_byte_read(&self) -> usize {
        self.buffers.request_offset
    }
}

/// A mutable [`Response`] view of the output response buffer.
pub struct Response<'a, 'b> {
    buffers: &'a mut RequestResponseCursor<'b>,
}

impl Response<'_, '_> {
    /// Writes the specified `data` at the last written location and updates the internal
    /// last written location. Returns [`WriteOutOfBounds`] if write would have written past the end
    /// of the underlying response buffer.
    pub fn write(&mut self, data: &[u8]) -> Result<(), WriteOutOfBounds> {
        if self.buffers.resp_buf.len() < self.buffers.response_offset + data.len() {
            return Err(WriteOutOfBounds);
        }
        self.buffers.resp_buf
            [self.buffers.response_offset..self.buffers.response_offset + data.len()]
            .copy_from_slice(data);
        self.buffers.response_offset += data.len();
        Ok(())
    }

    /// Allows writing to the underlying response buffer in place at the current last written
    /// location and updates the last written location. Returns [`WriteOutOfBounds`] if write would
    /// have written past the end of the underlying response buffer.
    pub fn write_callback(
        &mut self,
        size: usize,
        callback: impl FnOnce(&mut [u8]),
    ) -> Result<(), WriteOutOfBounds> {
        if self.buffers.resp_buf.len() < self.buffers.response_offset + size {
            return Err(WriteOutOfBounds);
        }
        callback(
            &mut self.buffers.resp_buf
                [self.buffers.response_offset..self.buffers.response_offset + size],
        );
        self.buffers.response_offset += size;
        Ok(())
    }
}

/// Provides access to request and response slices while tracking read and written locations.
pub struct RequestResponseCursor<'a> {
    cmd_buf: &'a [u8],
    resp_buf: &'a mut [u8],
    request_offset: usize,
    response_offset: usize,
    pub session_tag: tpm2::TpmiStCommandTag,
}

impl<'a> RequestResponseCursor<'a> {
    /// Create a new [`RequestResponseCursor`] wrapping direct slices.
    pub fn new(cmd_buf: &'a [u8], resp_buf: &'a mut [u8], response_offset: usize) -> Self {
        Self {
            cmd_buf,
            resp_buf,
            request_offset: 0,
            response_offset,
            session_tag: tpm2::TpmiStCommandTag::NoSessions,
        }
    }

    /// Gets the [`RequestThenResponse`] that can access the request, then be converted into a
    /// response view.
    pub fn request(&mut self) -> RequestThenResponse<'_, 'a> {
        RequestThenResponse { buffers: self }
    }

    /// Gets the index of the last byte read from the request buffer.
    pub fn last_request_byte_read(&self) -> usize {
        self.request_offset
    }

    /// Gets the index of the last byte written to response buffer.
    pub fn last_response_byte_written(&self) -> usize {
        self.response_offset
    }

    /// Gets the full response buffer including any unwritten portions.
    pub fn response_mut(&mut self) -> &mut [u8] {
        self.resp_buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpm2::Handle;
    use tpm2::commands::{GetRandom, ReadPublic};

    const RESPONSE_OFFSET: usize = 10;

    #[test]
    fn unmarshal_command_reads_parameters() {
        let cmd = [0x00, 0x08];
        let mut resp = [0u8; 16];
        let mut cursor = RequestResponseCursor::new(&cmd, &mut resp, RESPONSE_OFFSET);
        let mut request = cursor.request();
        let get_random = request.try_unmarshal_command::<GetRandom>([]).unwrap();
        assert_eq!(get_random.bytes_requested, 8);
        assert_eq!(request.remaining_bytes(), 0);
        assert_eq!(cursor.last_request_byte_read(), 2);
    }

    #[test]
    fn unmarshal_errors_carry_positions_and_do_not_consume() {
        let cmd = [0x01];
        let mut resp = [0u8; 16];
        let mut cursor = RequestResponseCursor::new(&cmd, &mut resp, RESPONSE_OFFSET);
        let mut request = cursor.request();
        assert_eq!(
            request.try_unmarshal_command::<GetRandom>([]).err(),
            Some(TpmRc::INSUFFICIENT.with(Position::parameter(1)))
        );
        assert_eq!(
            request
                .try_unmarshal_at::<u16>(Position::parameter(2))
                .err(),
            Some(TpmRc::INSUFFICIENT.with(Position::parameter(2)))
        );
        assert_eq!(request.remaining_bytes(), 1);
    }

    #[test]
    fn unmarshal_handles_then_parameters() {
        let cmd = [0x80, 0x00, 0x00, 0x01, 0xAA];
        let mut resp = [0u8; 16];
        let mut cursor = RequestResponseCursor::new(&cmd, &mut resp, RESPONSE_OFFSET);
        let mut request = cursor.request();
        let handles = request.try_unmarshal_handles::<ReadPublic>().unwrap();
        assert_eq!(handles, [Handle(0x8000_0001)]);
        let read_public = request
            .try_unmarshal_command::<ReadPublic>(handles)
            .unwrap();
        assert_eq!(read_public.object_handle, Handle(0x8000_0001));
        assert_eq!(request.remaining_slice(), &[0xAA]);
    }

    #[test]
    fn response_writes_after_offset_and_checks_bounds() {
        let cmd = [];
        let mut resp = [0u8; 14];
        let mut cursor = RequestResponseCursor::new(&cmd, &mut resp, RESPONSE_OFFSET);
        let mut response = cursor.request().into_response();
        response.write(&[1, 2, 3]).unwrap();
        assert_eq!(response.write(&[4, 5]), Err(WriteOutOfBounds));
        response.write_callback(1, |buf| buf[0] = 4).unwrap();
        assert_eq!(response.write_callback(1, |_| {}), Err(WriteOutOfBounds));
        assert_eq!(cursor.last_response_byte_written(), 14);
        assert_eq!(cursor.response_mut()[RESPONSE_OFFSET..], [1, 2, 3, 4]);
    }
}
