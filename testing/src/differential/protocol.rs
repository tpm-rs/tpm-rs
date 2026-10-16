//! The pipe protocol between a [`super::Reference`] and its reference TPM
//! process (`mstpm20` or `ibmswtpm2`, see [`super::Implementation`]).
//!
//! Every request is answered by exactly one reply. All integers are
//! big-endian; byte strings are a `u32` length followed by the bytes.
//!
//! * Request: a tag byte followed by its fields — `1` `Exchange` (locality
//!   `u8`, command bytes, `tpm-rs` response bytes), `2` `AdvanceClock` (`u64`
//!   milliseconds), `3` `Signal` (`u32` MSSIM platform signal code), `4`
//!   `HashStart`, `5` `HashData` (bytes), `6` `HashEnd`, `7` `Reinit`.
//! * Reply: a status byte followed by a message (bytes, UTF-8; empty on
//!   success): `0` success, `1` failure, or `2` failure of an `Exchange` that
//!   also carries the C reference's response (bytes) after the message (see
//!   [`Failure`]).
//!
//! The parent chooses the seed of the reference's random number generation
//! (`TPM_REFERENCE_SEED=<pid>:<realtime_ms>` in the process's environment,
//! see [`crate::seed`]). Right after start-up, the process sends a
//! [`Handshake`] confirming the values its C reference TPM uses: the process
//! ID its `getpid()` returns (`u32`) and its initial real time
//! (`_plat__RealTime()`, `u64` milliseconds). It sends the handshake before
//! initializing the C reference TPM. Then, still
//! before reading any request, it sends one reply telling whether its C
//! reference TPM initialized successfully. Closing its stdin ends the
//! process.

use std::io::{self, Read, Write};

/// The first message of a reference TPM process (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handshake {
    /// The process ID `getpid()` returns to the C reference TPM.
    pub pid: u32,
    /// The initial `_plat__RealTime()` of the C reference TPM, in
    /// milliseconds.
    pub realtime_ms: u64,
}

/// Writes `handshake` (without flushing).
pub fn write_handshake(w: &mut impl Write, handshake: &Handshake) -> io::Result<()> {
    w.write_all(&handshake.pid.to_be_bytes())?;
    w.write_all(&handshake.realtime_ms.to_be_bytes())
}

/// Reads a handshake.
pub fn read_handshake(r: &mut impl Read) -> io::Result<Handshake> {
    Ok(Handshake {
        pid: u32::from_be_bytes(read_array(r)?),
        realtime_ms: u64::from_be_bytes(read_array(r)?),
    })
}

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
    /// Re-initialize the C reference TPM like a new reference process with
    /// the same seed: reset the virtual clock to the seed's real time,
    /// manufacture, power on, NV on and `TPM2_Startup(TPM_SU_CLEAR)`, and
    /// forget the comparison state. A cheap replacement for a new process
    /// (e.g. one per fuzz input).
    Reinit,
}

/// A failure reply: why a request failed and, for a command whose responses
/// differ, the C reference's response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    /// What went wrong (for diagnostics; includes both responses for a
    /// divergence).
    pub message: String,
    /// The response of the C reference TPM to the command, if the request was
    /// an `Exchange` that the reference executed.
    pub reference_response: Option<Vec<u8>>,
}

impl Failure {
    /// A failure without a reference response.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            reference_response: None,
        }
    }
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self::new(message)
    }
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
        Request::Reinit => w.write_all(&[7]),
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
        7 => Request::Reinit,
        t => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown request tag {t}"),
            ));
        }
    }))
}

/// Writes a reply (without flushing).
pub fn write_reply(w: &mut impl Write, result: &Result<(), Failure>) -> io::Result<()> {
    match result {
        Ok(()) => {
            w.write_all(&[0])?;
            write_bytes(w, &[])
        }
        Err(Failure {
            message,
            reference_response: None,
        }) => {
            w.write_all(&[1])?;
            write_bytes(w, message.as_bytes())
        }
        Err(Failure {
            message,
            reference_response: Some(response),
        }) => {
            w.write_all(&[2])?;
            write_bytes(w, message.as_bytes())?;
            write_bytes(w, response)
        }
    }
}

/// Reads a reply.
pub fn read_reply(r: &mut impl Read) -> io::Result<Result<(), Failure>> {
    let [status] = read_array(r)?;
    let message = String::from_utf8_lossy(&read_bytes(r)?).into_owned();
    match status {
        0 => Ok(Ok(())),
        1 => Ok(Err(Failure::new(message))),
        2 => Ok(Err(Failure {
            message,
            reference_response: Some(read_bytes(r)?),
        })),
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
            Request::Reinit,
            Request::AdvanceClock(0),
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
    fn handshake_round_trips() {
        let handshake = Handshake {
            pid: 0x1234_5678,
            realtime_ms: 0x0102_0304_0506_0708,
        };
        let mut buf = Vec::new();
        write_handshake(&mut buf, &handshake).unwrap();
        assert_eq!(buf.len(), 12);
        let mut input = buf.as_slice();
        assert_eq!(read_handshake(&mut input).unwrap(), handshake);
        assert!(input.is_empty());
        assert!(read_handshake(&mut [0u8; 11].as_slice()).is_err());
    }

    #[test]
    fn replies_round_trip() {
        let mut buf = Vec::new();
        let divergence = Failure {
            message: "differs".into(),
            reference_response: Some(vec![0x80, 0x01, 0, 0, 0, 10, 0, 0, 1, 0x01]),
        };
        let empty_response = Failure {
            message: String::new(),
            reference_response: Some(Vec::new()),
        };
        write_reply(&mut buf, &Ok(())).unwrap();
        write_reply(&mut buf, &Err(Failure::new("mismatch ✗"))).unwrap();
        write_reply(&mut buf, &Err(divergence.clone())).unwrap();
        write_reply(&mut buf, &Err(empty_response.clone())).unwrap();
        let mut input = buf.as_slice();
        assert_eq!(read_reply(&mut input).unwrap(), Ok(()));
        assert_eq!(
            read_reply(&mut input).unwrap(),
            Err(Failure::new("mismatch ✗"))
        );
        assert_eq!(read_reply(&mut input).unwrap(), Err(divergence));
        assert_eq!(read_reply(&mut input).unwrap(), Err(empty_response));
        assert!(read_reply(&mut input).is_err());
        // An unknown status and a divergence without its response.
        assert!(read_reply(&mut [3u8, 0, 0, 0, 0].as_slice()).is_err());
        assert!(read_reply(&mut [2u8, 0, 0, 0, 0].as_slice()).is_err());
    }

    #[test]
    fn reinit_round_trips_as_a_single_tag_byte() {
        let mut buf = Vec::new();
        write_request(&mut buf, &Request::Reinit).unwrap();
        assert_eq!(buf, [7]);
        let mut input = buf.as_slice();
        assert_eq!(read_request(&mut input).unwrap(), Some(Request::Reinit));
        assert_eq!(read_request(&mut input).unwrap(), None);
    }

    #[test]
    fn malformed_requests_are_rejected() {
        assert!(read_request(&mut [8u8].as_slice()).is_err());
        assert!(read_request(&mut [1u8, 0, 0, 0, 0, 9].as_slice()).is_err());
    }
}
