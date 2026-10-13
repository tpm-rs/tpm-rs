//! The pipe protocol between a [`super::Reference`] and its reference TPM
//! process (`mstpm20` or `ibmswtpm2`, see [`super::Implementation`]).
//!
//! Every request is answered by exactly one reply. All integers are
//! big-endian; byte strings are a `u32` length followed by the bytes.
//!
//! * Request: a tag byte followed by its fields — `1` `Exchange` (locality
//!   `u8`, command bytes, `tpm-rs` response bytes), `2` `AdvanceClock` (`u64`
//!   milliseconds), `3` `Signal` (`u32` MSSIM platform signal code), `4`
//!   `HashStart`, `5` `HashData` (bytes), `6` `HashEnd`.
//! * Reply: `0` (success) or `1` (failure) followed by a message (bytes,
//!   UTF-8; empty on success).
//!
//! Right after start-up, before reading any request, the process sends one
//! reply telling whether its C reference TPM initialized successfully. Closing
//! its stdin ends the process.

use std::io::{self, Read, Write};

/// A request to a reference TPM process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Execute `command` at `locality` and compare the response with
    /// `expected`, the `tpm-rs` response.
    Exchange {
        /// Locality of the command.
        locality: u8,
        /// The command buffer.
        command: Vec<u8>,
        /// The response `tpm-rs` gave to `command`.
        expected: Vec<u8>,
    },
    /// Advance the virtual clock by this many milliseconds.
    AdvanceClock(u64),
    /// Deliver the platform signal with this MSSIM code.
    Signal(u32),
    /// `_TPM_Hash_Start`.
    HashStart,
    /// `_TPM_Hash_Data` with these bytes.
    HashData(Vec<u8>),
    /// `_TPM_Hash_End`.
    HashEnd,
}

fn write_bytes(w: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "buffer too large"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(bytes)
}

fn read_array<const N: usize>(r: &mut impl Read) -> io::Result<[u8; N]> {
    let mut b = [0u8; N];
    r.read_exact(&mut b)?;
    Ok(b)
}

fn read_bytes(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let len = u32::from_be_bytes(read_array(r)?) as usize;
    let mut bytes = vec![0u8; len];
    r.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Writes `request` (without flushing).
pub fn write_request(w: &mut impl Write, request: &Request) -> io::Result<()> {
    match request {
        Request::Exchange {
            locality,
            command,
            expected,
        } => {
            w.write_all(&[1, *locality])?;
            write_bytes(w, command)?;
            write_bytes(w, expected)
        }
        Request::AdvanceClock(ms) => {
            w.write_all(&[2])?;
            w.write_all(&ms.to_be_bytes())
        }
        Request::Signal(code) => {
            w.write_all(&[3])?;
            w.write_all(&code.to_be_bytes())
        }
        Request::HashStart => w.write_all(&[4]),
        Request::HashData(data) => {
            w.write_all(&[5])?;
            write_bytes(w, data)
        }
        Request::HashEnd => w.write_all(&[6]),
    }
}

/// Reads the next request; `None` at the end of the stream.
pub fn read_request(r: &mut impl Read) -> io::Result<Option<Request>> {
    let mut tag = [0u8; 1];
    if r.read(&mut tag)? == 0 {
        return Ok(None);
    }
    Ok(Some(match tag[0] {
        1 => {
            let [locality] = read_array(r)?;
            Request::Exchange {
                locality,
                command: read_bytes(r)?,
                expected: read_bytes(r)?,
            }
        }
        2 => Request::AdvanceClock(u64::from_be_bytes(read_array(r)?)),
        3 => Request::Signal(u32::from_be_bytes(read_array(r)?)),
        4 => Request::HashStart,
        5 => Request::HashData(read_bytes(r)?),
        6 => Request::HashEnd,
        t => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown request tag {t}"),
            ));
        }
    }))
}

/// Writes a reply (without flushing).
pub fn write_reply(w: &mut impl Write, result: &Result<(), String>) -> io::Result<()> {
    match result {
        Ok(()) => {
            w.write_all(&[0])?;
            write_bytes(w, &[])
        }
        Err(message) => {
            w.write_all(&[1])?;
            write_bytes(w, message.as_bytes())
        }
    }
}

/// Reads a reply.
pub fn read_reply(r: &mut impl Read) -> io::Result<Result<(), String>> {
    let [status] = read_array(r)?;
    let message = String::from_utf8_lossy(&read_bytes(r)?).into_owned();
    match status {
        0 => Ok(Ok(())),
        1 => Ok(Err(message)),
        s => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown reply status {s}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip() {
        let requests = [
            Request::Exchange {
                locality: 3,
                command: vec![0x80, 0x01, 2],
                expected: vec![],
            },
            Request::AdvanceClock(u64::MAX - 1),
            Request::Signal(17),
            Request::HashStart,
            Request::HashData(vec![9; 300]),
            Request::HashEnd,
        ];
        let mut buf = Vec::new();
        for r in &requests {
            write_request(&mut buf, r).unwrap();
        }
        let mut input = buf.as_slice();
        for r in &requests {
            assert_eq!(read_request(&mut input).unwrap().as_ref(), Some(r));
        }
        assert_eq!(read_request(&mut input).unwrap(), None);
    }

    #[test]
    fn replies_round_trip() {
        let mut buf = Vec::new();
        write_reply(&mut buf, &Ok(())).unwrap();
        write_reply(&mut buf, &Err("mismatch ✗".into())).unwrap();
        let mut input = buf.as_slice();
        assert_eq!(read_reply(&mut input).unwrap(), Ok(()));
        assert_eq!(read_reply(&mut input).unwrap(), Err("mismatch ✗".into()));
        assert!(read_reply(&mut input).is_err());
    }

    #[test]
    fn malformed_requests_are_rejected() {
        assert!(read_request(&mut [7u8].as_slice()).is_err());
        assert!(read_request(&mut [1u8, 0, 0, 0, 0, 9].as_slice()).is_err());
    }
}
