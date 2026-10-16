//! The fuzz input model: a [`Conversation`] of TPM command [`Step`]s.
//!
//! One fuzz input is a conversation with a fresh, started TPM. Each step is
//! either raw bytes sent as is ([`Step::Raw`]) or a structured command
//! ([`Step::Cmd`]) whose handles, parameters and authorizations may refer to
//! values that earlier rounds returned (see [`crate::pool`]): response
//! handles, names, blobs, nonces, context blobs and so on. References index
//! by kind and recency, modulo what is available, so almost every byte string
//! decodes to a meaningful conversation.
//!
//! # Byte encoding
//!
//! The model has a hand-written, total decoder ([`Conversation::from_bytes`],
//! which also backs the [`Arbitrary`] implementation) and the matching
//! encoder ([`Conversation::to_bytes`]), so tools such as the corpus
//! converter can build conversations programmatically and write them as
//! fuzzer inputs. The guarantee is `from_bytes(&c.to_bytes()) == c` for every
//! conversation `c` within the documented limits ([`MAX_ROUNDS`] steps,
//! [`MAX_HANDLES`] handles, [`MAX_SESSIONS`] sessions, [`MAX_SEGMENTS`]
//! segments per list, [`MAX_SEGMENT_DEPTH`] nested [`Segment::Sized`] levels
//! and byte strings of at most `u16::MAX` bytes; the encoder truncates
//! anything longer). The reverse direction is not an identity: many byte
//! strings decode to the same conversation.
//!
//! The decoder never fails: when the input runs out, every remaining read
//! yields zero bytes, and lists stop early. All multi-byte integers are
//! big-endian. The wire format is, per item:
//!
//! | Item | Encoding |
//! |---|---|
//! | length | one byte `< 0xFF`, or `0xFF` followed by a `u16` |
//! | byte string | length, then that many bytes (truncated at the end of the input) |
//! | [`Conversation`] | steps until the input ends (at most [`MAX_ROUNDS`]) |
//! | [`Step`] | selector byte (`>= 0xF0`: [`Step::Raw`] + byte string, else [`Step::Cmd`]) |
//! | [`Cmd`] | tag, code, handle list, session list, segment list, fix-ups |
//! | [`TagSel`] | `< 0xF0`: `Auto`; else `(b - 0xF0) % 4`: `NoSessions`, `Sessions`, `Raw(u16)` (2 and 3) |
//! | command code | `< 0xF8`: `IMPLEMENTED_COMMANDS[b % len]`; else a `u32` |
//! | handle list | count byte (bit 7 clear: the command's handle count, else `b & 7`), then operands |
//! | session list | count byte (bit 7 clear: the command's auth handle count, else `b & 3`), then sessions |
//! | segment list | count byte (`b % (MAX_SEGMENTS + 1)`), then segments |
//! | [`Fixups`] | `< 0xE0`: all on; else bit 0/1/2 select the `u32`/`u32`/`i16` overrides that follow |
//!
//! Enum variants are chosen by a selector byte modulo a small number, with
//! the more useful variants owning several residues (see each `decode`
//! function).

use std::sync::LazyLock;

use arbitrary::{Arbitrary, Unstructured};
use testing::_common::handle_requires_auth;
use testing::differential::server::handle_counts;
use tpm2::TpmCc;

/// The maximum number of rounds of a conversation (the decoder ignores the
/// rest of the input), bounding the execution time of one input.
pub const MAX_ROUNDS: usize = 32;
/// The maximum number of handles of a [`Cmd`].
pub const MAX_HANDLES: usize = 7;
/// The maximum number of sessions of a [`Cmd`].
pub const MAX_SESSIONS: usize = 3;
/// The maximum number of segments of one segment list.
pub const MAX_SEGMENTS: usize = 32;
/// The maximum nesting of [`Segment::Sized`]: a `Sized` segment at this depth
/// is decoded without children.
pub const MAX_SEGMENT_DEPTH: usize = 4;

/// `TPM_ST_NO_SESSIONS`.
pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
/// `TPM_ST_SESSIONS`.
pub const TPM_ST_SESSIONS: u16 = 0x8002;

/// Every command code the TPMs know (the `handle_counts` table), in
/// ascending order; the decoder picks commands mostly from this list.
pub static IMPLEMENTED_COMMANDS: LazyLock<Vec<u32>> = LazyLock::new(|| {
    (0x100..0x200)
        .filter(|&code| handle_counts(code).is_some())
        .collect()
});

/// Well-known handles that the decoder can pick by index (see
/// [`HandleOperand::Raw`]): the permanent handles, PCRs, a few transient,
/// persistent, NV and session handles.
pub const WELL_KNOWN_HANDLES: &[u32] = &[
    0x4000_0001, // TPM_RH_OWNER
    0x4000_0007, // TPM_RH_NULL
    0x4000_0009, // TPM_RS_PW
    0x4000_000A, // TPM_RH_LOCKOUT
    0x4000_000B, // TPM_RH_ENDORSEMENT
    0x4000_000C, // TPM_RH_PLATFORM
    0x4000_000D, // TPM_RH_PLATFORM_NV
    0x4000_0010, // TPM_RH_AUTH_00
    0x4000_0110, // TPM_RH_ACT_0
    0x0000_0000, // PCR 0
    0x0000_0007, // PCR 7
    0x0000_0010, // PCR 16 (resettable)
    0x0000_0017, // PCR 23 (resettable)
    0x8000_0000, // first transient object
    0x8000_0001,
    0x8000_0002,
    0x8100_0000, // persistent (owner)
    0x8100_0001,
    0x8180_0000, // persistent (platform)
    0x0100_0000, // NV index
    0x0140_0000, // NV index (platform range)
    0x0200_0000, // HMAC session
    0x0300_0000, // policy session
];

/// The kinds of values the pool holds (see [`crate::pool`]). All values are
/// stored in wire form; TPM2B values include their size field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FieldKind {
    /// A 4-byte handle (response handles, NV indices, session handles).
    Handle,
    /// `TPM2B_NAME`.
    Name,
    /// `TPM2B_PUBLIC`.
    Public,
    /// `TPM2B_PRIVATE`.
    Private,
    /// `TPM2B_NV_PUBLIC`.
    NvPublic,
    /// `TPM2B_NONCE` (e.g. `nonceTPM`).
    Nonce,
    /// `TPMS_CONTEXT`.
    Context,
    /// `TPM2B_DIGEST`.
    Digest,
    /// A ticket (`TPMT_TK_*`).
    Ticket,
    /// `TPM2B_CREATION_DATA`.
    CreationData,
    /// `TPMT_SIGNATURE`.
    Signature,
    /// `TPM2B_ATTEST`.
    Attest,
    /// `TPM2B_DATA`.
    Data,
    /// `TPM2B_ENCRYPTED_SECRET`.
    EncryptedSecret,
    /// `TPM2B_ID_OBJECT`.
    IdObject,
    /// A TPM2B found while scanning an otherwise unparsed parameter area.
    Tpm2b,
    /// A raw response parameter area (or other opaque bytes).
    Bytes,
}

impl FieldKind {
    /// Every kind, in selector order.
    pub const ALL: [FieldKind; 17] = [
        FieldKind::Handle,
        FieldKind::Name,
        FieldKind::Public,
        FieldKind::Private,
        FieldKind::NvPublic,
        FieldKind::Nonce,
        FieldKind::Context,
        FieldKind::Digest,
        FieldKind::Ticket,
        FieldKind::CreationData,
        FieldKind::Signature,
        FieldKind::Attest,
        FieldKind::Data,
        FieldKind::EncryptedSecret,
        FieldKind::IdObject,
        FieldKind::Tpm2b,
        FieldKind::Bytes,
    ];

    /// The selector index of this kind (its position in [`Self::ALL`]).
    fn index(self) -> u8 {
        Self::ALL
            .iter()
            .position(|&k| k == self)
            .expect("listed kind") as u8
    }

    /// What a reference to this kind resolves to while the pool holds no
    /// value of the kind: four zero bytes for a handle, an empty TPM2B for
    /// sized kinds, nothing otherwise.
    pub fn placeholder(self) -> &'static [u8] {
        match self {
            FieldKind::Handle => &[0, 0, 0, 0],
            FieldKind::Context | FieldKind::Ticket | FieldKind::Signature | FieldKind::Bytes => &[],
            _ => &[0, 0],
        }
    }
}

/// One fuzz input: a conversation with a fresh, started TPM.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Conversation {
    /// The rounds, in order (at most [`MAX_ROUNDS`] are encodable).
    pub steps: Vec<Step>,
}

/// One round of a [`Conversation`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Arbitrary bytes, sent as is (parser and unmarshal divergences).
    Raw(Vec<u8>),
    /// A structured command whose operands may come from earlier responses.
    Cmd(Cmd),
}

/// A structured command (see [`crate::builder`] for how it becomes bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cmd {
    /// The command tag.
    pub tag: TagSel,
    /// The command code (any `u32`; mostly one of [`IMPLEMENTED_COMMANDS`]).
    pub code: u32,
    /// The handle area (at most [`MAX_HANDLES`]).
    pub handles: Vec<HandleOperand>,
    /// The authorization sessions, one per slot (at most [`MAX_SESSIONS`]);
    /// none means no authorization area.
    pub sessions: Vec<SessionSel>,
    /// The parameter area, as a concatenation of segments.
    pub params: Vec<Segment>,
    /// Which sizes the builder computes.
    pub fixups: Fixups,
}

impl Cmd {
    /// A command with code `code`, an automatic tag, all fix-ups on, and no
    /// handles, sessions or parameters.
    pub fn new(code: u32) -> Self {
        Self {
            tag: TagSel::Auto,
            code,
            handles: Vec::new(),
            sessions: Vec::new(),
            params: Vec::new(),
            fixups: Fixups::default(),
        }
    }
}

/// The command tag of a [`Cmd`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TagSel {
    /// `TPM_ST_SESSIONS` if the command has sessions, else
    /// `TPM_ST_NO_SESSIONS`.
    Auto,
    /// `TPM_ST_NO_SESSIONS` (whether or not there are sessions).
    NoSessions,
    /// `TPM_ST_SESSIONS` (whether or not there are sessions).
    Sessions,
    /// Any tag value.
    Raw(u16),
}

/// One handle of a [`Cmd`]'s handle area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandleOperand {
    /// The `back`-th most recent response handle of the conversation
    /// (`0` = the newest), modulo the number of response handles so far.
    Response {
        /// Recency index.
        back: u8,
    },
    /// The `back`-th most recently defined NV index that is still defined.
    Nv {
        /// Recency index.
        back: u8,
    },
    /// The `back`-th most recently started session that is still live.
    Session {
        /// Recency index.
        back: u8,
    },
    /// A literal handle (permanent handles, PCRs, stale handles, ...).
    Raw(u32),
}

/// A part of a [`Cmd`]'s parameter area.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Segment {
    /// Literal bytes.
    Bytes(Vec<u8>),
    /// An extracted value, spliced verbatim.
    Value(ValueRef),
    /// An extracted value, mutated.
    Mutated(ValueRef, Mutation),
    /// A TPM2B: a `u16` size field computed from the content (see
    /// [`Fixups::tpm2b_delta`]), then the content.
    Sized(Vec<Segment>),
}

/// A reference to a value in the pool: the `back`-th most recent value of
/// kind `kind` (`0` = the newest), modulo the number of such values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueRef {
    /// The kind of value.
    pub kind: FieldKind,
    /// Recency index among the values of that kind.
    pub back: u8,
}

/// A change applied to a spliced value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mutation {
    /// Flips bit `bit % (8 * len)` (nothing for an empty value).
    FlipBit(u16),
    /// Keeps only the first `len` bytes.
    Truncate(u16),
    /// Appends bytes.
    Extend(Vec<u8>),
    /// Sets byte `pos % len` to a value (nothing for an empty value).
    SetByte(u16, u8),
}

/// The authorization of one session slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionSel {
    /// A password session (`TPM_RS_PW`) with the given auth value.
    Password {
        /// The password.
        auth: AuthSel,
    },
    /// An HMAC session of the session table.
    Hmac {
        /// Session index (modulo the live sessions).
        session: u8,
        /// The auth value of the authorized entity.
        auth: AuthSel,
        /// `TPMA_SESSION`.
        attrs: u8,
        /// Whether to flip a bit of the computed HMAC.
        corrupt_hmac: bool,
    },
    /// A policy session of the session table.
    Policy {
        /// Session index (modulo the live sessions).
        session: u8,
        /// The auth value of the authorized entity (for `PolicyAuthValue`/
        /// `PolicyPassword`).
        auth: AuthSel,
        /// `TPMA_SESSION`.
        attrs: u8,
    },
    /// A literal `TPMS_AUTH_COMMAND` (or garbage).
    Raw(Vec<u8>),
}

/// The choice of an auth value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthSel {
    /// The empty auth value.
    Empty,
    /// The auth value the conversation set for the entity this slot
    /// authorizes (empty if unknown).
    Entity,
    /// The `n`-th most recently set auth value of the conversation (modulo
    /// their number; empty if none).
    Known(u8),
    /// Literal bytes.
    Bytes(Vec<u8>),
}

/// Which sizes the command builder computes. `None` computes the size;
/// `Some` writes the given value instead, to exercise size validation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fixups {
    /// The `commandSize` header field.
    pub command_size: Option<u32>,
    /// The `authorizationSize` field.
    pub auth_size: Option<u32>,
    /// Added (wrapping) to every [`Segment::Sized`] size field.
    pub tpm2b_delta: Option<i16>,
}

impl Fixups {
    /// Every size computed.
    pub fn all_on() -> Self {
        Self::default()
    }
}

/// A total reader over the fuzzer bytes: reads past the end yield zeros.
struct Decoder<'a> {
    data: &'a [u8],
}

impl Decoder<'_> {
    /// Whether the input is exhausted.
    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The next `n` bytes, or fewer at the end of the input.
    fn take(&mut self, n: usize) -> &[u8] {
        let (head, rest) = self.data.split_at(n.min(self.data.len()));
        self.data = rest;
        head
    }

    /// The next `N` bytes, zero-padded at the end of the input.
    fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0; N];
        let head = self.take(N);
        out[..head.len()].copy_from_slice(head);
        out
    }

    fn u8(&mut self) -> u8 {
        self.array::<1>()[0]
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.array())
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.array())
    }

    /// A length (see the module docs).
    fn len(&mut self) -> usize {
        match self.u8() {
            0xFF => usize::from(self.u16()),
            b => usize::from(b),
        }
    }

    /// A length-prefixed byte string.
    fn bytes(&mut self) -> Vec<u8> {
        let n = self.len();
        self.take(n).to_vec()
    }
}

/// The writer matching [`Decoder`].
#[derive(Default)]
struct Encoder {
    out: Vec<u8>,
}

impl Encoder {
    fn u8(&mut self, v: u8) {
        self.out.push(v);
    }

    fn u16(&mut self, v: u16) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }

    /// A length (see the module docs); `len <= u16::MAX`.
    fn len(&mut self, len: usize) {
        if len < 0xFF {
            self.u8(len as u8);
        } else {
            self.u8(0xFF);
            self.u16(len as u16);
        }
    }

    /// A length-prefixed byte string, truncated to `u16::MAX` bytes.
    fn bytes(&mut self, bytes: &[u8]) {
        let bytes = &bytes[..bytes.len().min(usize::from(u16::MAX))];
        self.len(bytes.len());
        self.out.extend_from_slice(bytes);
    }
}

/// The number of handles of command `code` (0 if unknown).
fn expected_handles(code: u32) -> usize {
    handle_counts(code).map_or(0, |(n, _)| n)
}

/// The number of handles of command `code` that need authorization.
fn expected_sessions(code: u32) -> usize {
    (0..expected_handles(code))
        .filter(|&i| handle_requires_auth(TpmCc::new(code), i))
        .count()
}

impl Conversation {
    /// Decodes a conversation from fuzzer bytes (never fails; see the module
    /// docs).
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut d = Decoder { data };
        let mut steps = Vec::new();
        while !d.is_empty() && steps.len() < MAX_ROUNDS {
            steps.push(Step::decode(&mut d));
        }
        Self { steps }
    }

    /// Encodes the conversation as fuzzer bytes that
    /// [`Conversation::from_bytes`] decodes back to an equal conversation
    /// (within the limits of the module docs).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::default();
        for step in self.steps.iter().take(MAX_ROUNDS) {
            step.encode(&mut e);
        }
        e.out
    }
}

/// Decodes the whole remaining input (like `arbitrary_take_rest`), so a
/// conversation is always the top-level fuzz input.
impl<'a> Arbitrary<'a> for Conversation {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.len();
        Ok(Self::from_bytes(u.bytes(len)?))
    }

    fn arbitrary_take_rest(u: Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from_bytes(u.take_rest()))
    }
}

impl Step {
    fn decode(d: &mut Decoder<'_>) -> Self {
        if d.u8() >= 0xF0 {
            Step::Raw(d.bytes())
        } else {
            Step::Cmd(Cmd::decode(d))
        }
    }

    fn encode(&self, e: &mut Encoder) {
        match self {
            Step::Raw(bytes) => {
                e.u8(0xF0);
                e.bytes(bytes);
            }
            Step::Cmd(cmd) => {
                e.u8(0);
                cmd.encode(e);
            }
        }
    }
}

impl Cmd {
    fn decode(d: &mut Decoder<'_>) -> Self {
        let tag = TagSel::decode(d);
        let code = match d.u8() {
            b @ 0..0xF8 => IMPLEMENTED_COMMANDS[usize::from(b) % IMPLEMENTED_COMMANDS.len()],
            _ => d.u32(),
        };
        let n = match d.u8() {
            b if b & 0x80 == 0 => expected_handles(code),
            b => usize::from(b & 7),
        };
        let mut handles = Vec::new();
        while handles.len() < n && !d.is_empty() {
            handles.push(HandleOperand::decode(d));
        }
        let n = match d.u8() {
            b if b & 0x80 == 0 => expected_sessions(code),
            b => usize::from(b & 3),
        };
        let mut sessions = Vec::new();
        while sessions.len() < n && !d.is_empty() {
            sessions.push(SessionSel::decode(d));
        }
        let params = decode_segments(d, 0);
        let fixups = Fixups::decode(d);
        Self {
            tag,
            code,
            handles,
            sessions,
            params,
            fixups,
        }
    }

    fn encode(&self, e: &mut Encoder) {
        self.tag.encode(e);
        match IMPLEMENTED_COMMANDS.iter().position(|&c| c == self.code) {
            Some(i) => e.u8(i as u8),
            None => {
                e.u8(0xF8);
                e.u32(self.code);
            }
        }
        let handles = &self.handles[..self.handles.len().min(MAX_HANDLES)];
        e.u8(0x80 | handles.len() as u8);
        for h in handles {
            h.encode(e);
        }
        let sessions = &self.sessions[..self.sessions.len().min(MAX_SESSIONS)];
        e.u8(0x80 | sessions.len() as u8);
        for s in sessions {
            s.encode(e);
        }
        encode_segments(e, &self.params, 0);
        self.fixups.encode(e);
    }
}

impl TagSel {
    fn decode(d: &mut Decoder<'_>) -> Self {
        match d.u8() {
            0..0xF0 => TagSel::Auto,
            b => match (b - 0xF0) % 4 {
                0 => TagSel::NoSessions,
                1 => TagSel::Sessions,
                _ => TagSel::Raw(d.u16()),
            },
        }
    }

    fn encode(&self, e: &mut Encoder) {
        match *self {
            TagSel::Auto => e.u8(0),
            TagSel::NoSessions => e.u8(0xF0),
            TagSel::Sessions => e.u8(0xF1),
            TagSel::Raw(tag) => {
                e.u8(0xF2);
                e.u16(tag);
            }
        }
    }

    /// The tag value for a command with or without sessions.
    pub fn value(self, has_sessions: bool) -> u16 {
        match self {
            TagSel::Auto if has_sessions => TPM_ST_SESSIONS,
            TagSel::Auto | TagSel::NoSessions => TPM_ST_NO_SESSIONS,
            TagSel::Sessions => TPM_ST_SESSIONS,
            TagSel::Raw(tag) => tag,
        }
    }
}

impl HandleOperand {
    /// Selector residues (mod 8): 0, 1 and 7 `Response`; 2 a well-known
    /// handle (`Raw`); 3 `Nv`; 4 `Session`; 5 and 6 a literal `Raw`.
    fn decode(d: &mut Decoder<'_>) -> Self {
        match d.u8() % 8 {
            2 => HandleOperand::Raw(
                WELL_KNOWN_HANDLES[usize::from(d.u8()) % WELL_KNOWN_HANDLES.len()],
            ),
            3 => HandleOperand::Nv { back: d.u8() },
            4 => HandleOperand::Session { back: d.u8() },
            5 | 6 => HandleOperand::Raw(d.u32()),
            _ => HandleOperand::Response { back: d.u8() },
        }
    }

    fn encode(&self, e: &mut Encoder) {
        match *self {
            HandleOperand::Response { back } => {
                e.u8(0);
                e.u8(back);
            }
            HandleOperand::Nv { back } => {
                e.u8(3);
                e.u8(back);
            }
            HandleOperand::Session { back } => {
                e.u8(4);
                e.u8(back);
            }
            HandleOperand::Raw(h) => match WELL_KNOWN_HANDLES.iter().position(|&w| w == h) {
                Some(i) => {
                    e.u8(2);
                    e.u8(i as u8);
                }
                None => {
                    e.u8(5);
                    e.u32(h);
                }
            },
        }
    }
}

/// Decodes a segment list at nesting `depth`.
fn decode_segments(d: &mut Decoder<'_>, depth: usize) -> Vec<Segment> {
    let n = usize::from(d.u8()) % (MAX_SEGMENTS + 1);
    let mut segments = Vec::new();
    while segments.len() < n && !d.is_empty() {
        segments.push(Segment::decode(d, depth));
    }
    segments
}

/// Encodes a segment list at nesting `depth`.
fn encode_segments(e: &mut Encoder, segments: &[Segment], depth: usize) {
    let segments = &segments[..segments.len().min(MAX_SEGMENTS)];
    e.u8(segments.len() as u8);
    for s in segments {
        s.encode(e, depth);
    }
}

impl Segment {
    /// Selector residues (mod 8): 0, 1 `Bytes`; 2, 3 `Value`; 4 `Mutated`;
    /// 5, 6, 7 `Sized` (children only below [`MAX_SEGMENT_DEPTH`]).
    fn decode(d: &mut Decoder<'_>, depth: usize) -> Self {
        match d.u8() % 8 {
            0 | 1 => Segment::Bytes(d.bytes()),
            2 | 3 => Segment::Value(ValueRef::decode(d)),
            4 => Segment::Mutated(ValueRef::decode(d), Mutation::decode(d)),
            _ if depth + 1 >= MAX_SEGMENT_DEPTH => Segment::Sized(Vec::new()),
            _ => Segment::Sized(decode_segments(d, depth + 1)),
        }
    }

    fn encode(&self, e: &mut Encoder, depth: usize) {
        match self {
            Segment::Bytes(bytes) => {
                e.u8(0);
                e.bytes(bytes);
            }
            Segment::Value(r) => {
                e.u8(2);
                r.encode(e);
            }
            Segment::Mutated(r, m) => {
                e.u8(4);
                r.encode(e);
                m.encode(e);
            }
            Segment::Sized(children) => {
                e.u8(5);
                if depth + 1 < MAX_SEGMENT_DEPTH {
                    encode_segments(e, children, depth + 1);
                }
            }
        }
    }
}

impl ValueRef {
    fn decode(d: &mut Decoder<'_>) -> Self {
        let kind = FieldKind::ALL[usize::from(d.u8()) % FieldKind::ALL.len()];
        Self { kind, back: d.u8() }
    }

    fn encode(&self, e: &mut Encoder) {
        e.u8(self.kind.index());
        e.u8(self.back);
    }
}

impl Mutation {
    fn decode(d: &mut Decoder<'_>) -> Self {
        match d.u8() % 4 {
            0 => Mutation::FlipBit(d.u16()),
            1 => Mutation::Truncate(d.u16()),
            2 => Mutation::Extend(d.bytes()),
            _ => Mutation::SetByte(d.u16(), d.u8()),
        }
    }

    fn encode(&self, e: &mut Encoder) {
        match self {
            Mutation::FlipBit(bit) => {
                e.u8(0);
                e.u16(*bit);
            }
            Mutation::Truncate(len) => {
                e.u8(1);
                e.u16(*len);
            }
            Mutation::Extend(bytes) => {
                e.u8(2);
                e.bytes(bytes);
            }
            Mutation::SetByte(pos, v) => {
                e.u8(3);
                e.u16(*pos);
                e.u8(*v);
            }
        }
    }

    /// Applies the mutation to `value`.
    pub fn apply(&self, value: &mut Vec<u8>) {
        match self {
            Mutation::FlipBit(bit) => {
                if !value.is_empty() {
                    let bit = usize::from(*bit) % (8 * value.len());
                    value[bit / 8] ^= 1 << (bit % 8);
                }
            }
            Mutation::Truncate(len) => value.truncate(usize::from(*len)),
            Mutation::Extend(bytes) => value.extend_from_slice(bytes),
            Mutation::SetByte(pos, v) => {
                if !value.is_empty() {
                    let at = usize::from(*pos) % value.len();
                    value[at] = *v;
                }
            }
        }
    }
}

impl SessionSel {
    /// Selector residues (mod 8): 0, 1, 2 `Password`; 3, 4 `Hmac`; 5, 6
    /// `Policy`; 7 `Raw`. `corrupt_hmac` is set only by the byte `0xFF`.
    fn decode(d: &mut Decoder<'_>) -> Self {
        match d.u8() % 8 {
            3 | 4 => SessionSel::Hmac {
                session: d.u8(),
                auth: AuthSel::decode(d),
                attrs: d.u8(),
                corrupt_hmac: d.u8() == 0xFF,
            },
            5 | 6 => SessionSel::Policy {
                session: d.u8(),
                auth: AuthSel::decode(d),
                attrs: d.u8(),
            },
            7 => SessionSel::Raw(d.bytes()),
            _ => SessionSel::Password {
                auth: AuthSel::decode(d),
            },
        }
    }

    fn encode(&self, e: &mut Encoder) {
        match self {
            SessionSel::Password { auth } => {
                e.u8(0);
                auth.encode(e);
            }
            SessionSel::Hmac {
                session,
                auth,
                attrs,
                corrupt_hmac,
            } => {
                e.u8(3);
                e.u8(*session);
                auth.encode(e);
                e.u8(*attrs);
                e.u8(if *corrupt_hmac { 0xFF } else { 0 });
            }
            SessionSel::Policy {
                session,
                auth,
                attrs,
            } => {
                e.u8(5);
                e.u8(*session);
                auth.encode(e);
                e.u8(*attrs);
            }
            SessionSel::Raw(bytes) => {
                e.u8(7);
                e.bytes(bytes);
            }
        }
    }

    /// The auth value selection of this slot (`None` for [`SessionSel::Raw`]).
    pub fn auth(&self) -> Option<&AuthSel> {
        match self {
            SessionSel::Password { auth }
            | SessionSel::Hmac { auth, .. }
            | SessionSel::Policy { auth, .. } => Some(auth),
            SessionSel::Raw(_) => None,
        }
    }
}

impl AuthSel {
    /// Selector residues (mod 8): 0 to 3 `Entity`; 4 `Empty`; 5 `Known`; 6, 7
    /// `Bytes`.
    fn decode(d: &mut Decoder<'_>) -> Self {
        match d.u8() % 8 {
            4 => AuthSel::Empty,
            5 => AuthSel::Known(d.u8()),
            6 | 7 => AuthSel::Bytes(d.bytes()),
            _ => AuthSel::Entity,
        }
    }

    fn encode(&self, e: &mut Encoder) {
        match self {
            AuthSel::Entity => e.u8(0),
            AuthSel::Empty => e.u8(4),
            AuthSel::Known(n) => {
                e.u8(5);
                e.u8(*n);
            }
            AuthSel::Bytes(bytes) => {
                e.u8(6);
                e.bytes(bytes);
            }
        }
    }
}

impl Fixups {
    fn decode(d: &mut Decoder<'_>) -> Self {
        let b = d.u8();
        if b < 0xE0 {
            return Self::default();
        }
        Self {
            command_size: (b & 1 != 0).then(|| d.u32()),
            auth_size: (b & 2 != 0).then(|| d.u32()),
            tpm2b_delta: (b & 4 != 0).then(|| d.u16() as i16),
        }
    }

    fn encode(&self, e: &mut Encoder) {
        let mask = u8::from(self.command_size.is_some())
            | (u8::from(self.auth_size.is_some()) << 1)
            | (u8::from(self.tpm2b_delta.is_some()) << 2);
        if mask == 0 {
            e.u8(0);
            return;
        }
        e.u8(0xE0 | mask);
        if let Some(v) = self.command_size {
            e.u32(v);
        }
        if let Some(v) = self.auth_size {
            e.u32(v);
        }
        if let Some(v) = self.tpm2b_delta {
            e.u16(v as u16);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A conversation using every variant of the model.
    fn every_variant() -> Conversation {
        let value = ValueRef {
            kind: FieldKind::Public,
            back: 3,
        };
        let mut cmd = Cmd::new(0x153);
        cmd.tag = TagSel::Raw(0x1234);
        cmd.handles = vec![
            HandleOperand::Response { back: 1 },
            HandleOperand::Nv { back: 2 },
            HandleOperand::Session { back: 0 },
            HandleOperand::Raw(0x4000_0001),
            HandleOperand::Raw(0xDEAD_BEEF),
        ];
        cmd.sessions = vec![
            SessionSel::Password {
                auth: AuthSel::Bytes(vec![1, 2, 3]),
            },
            SessionSel::Hmac {
                session: 1,
                auth: AuthSel::Known(4),
                attrs: 0x21,
                corrupt_hmac: true,
            },
            SessionSel::Policy {
                session: 2,
                auth: AuthSel::Entity,
                attrs: 1,
            },
        ];
        cmd.params = vec![
            Segment::Bytes(vec![9; 300]),
            Segment::Value(value),
            Segment::Mutated(value, Mutation::FlipBit(7)),
            Segment::Mutated(value, Mutation::Truncate(2)),
            Segment::Mutated(value, Mutation::Extend(vec![1])),
            Segment::Mutated(value, Mutation::SetByte(1, 0xAA)),
            Segment::Sized(vec![
                Segment::Sized(vec![Segment::Bytes(vec![])]),
                Segment::Value(ValueRef {
                    kind: FieldKind::Bytes,
                    back: 0,
                }),
            ]),
        ];
        cmd.fixups = Fixups {
            command_size: Some(7),
            auth_size: None,
            tpm2b_delta: Some(-3),
        };
        let mut plain = Cmd::new(0xFFFF_0000);
        plain.sessions = vec![
            SessionSel::Raw(vec![0; 9]),
            SessionSel::Password {
                auth: AuthSel::Empty,
            },
        ];
        Conversation {
            steps: vec![
                Step::Raw(vec![0x80, 0x01]),
                Step::Cmd(cmd),
                Step::Cmd(plain),
                Step::Cmd(Cmd::new(0x17B)),
                Step::Raw(vec![]),
            ],
        }
    }

    #[test]
    fn encoding_round_trips() {
        let conv = every_variant();
        assert_eq!(Conversation::from_bytes(&conv.to_bytes()), conv);
    }

    #[test]
    fn every_command_and_well_known_handle_round_trips() {
        let steps = IMPLEMENTED_COMMANDS
            .iter()
            .zip(WELL_KNOWN_HANDLES.iter().cycle())
            .map(|(&code, &h)| {
                let mut cmd = Cmd::new(code);
                cmd.handles = vec![HandleOperand::Raw(h)];
                Step::Cmd(cmd)
            })
            .collect::<Vec<_>>();
        for chunk in steps.chunks(MAX_ROUNDS) {
            let conv = Conversation {
                steps: chunk.to_vec(),
            };
            assert_eq!(Conversation::from_bytes(&conv.to_bytes()), conv);
        }
    }

    #[test]
    fn every_field_kind_round_trips() {
        let steps = FieldKind::ALL
            .iter()
            .map(|&kind| {
                let mut cmd = Cmd::new(0x173);
                cmd.params = vec![Segment::Value(ValueRef { kind, back: 9 })];
                Step::Cmd(cmd)
            })
            .collect();
        let conv = Conversation { steps };
        assert_eq!(Conversation::from_bytes(&conv.to_bytes()), conv);
    }

    #[test]
    fn decoding_is_total_and_capped() {
        assert_eq!(Conversation::from_bytes(&[]), Conversation::default());
        // Arbitrary bytes always decode, and re-encoding a decoded value is
        // stable.
        let mut seed = 0x1234_5678u32;
        for len in 0..400 {
            let data: Vec<u8> = (0..len)
                .map(|_| {
                    seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
                    (seed >> 16) as u8
                })
                .collect();
            let conv = Conversation::from_bytes(&data);
            assert!(conv.steps.len() <= MAX_ROUNDS);
            assert_eq!(Conversation::from_bytes(&conv.to_bytes()), conv);
        }
        // Empty raw steps take two bytes each; the rest is ignored.
        let conv = Conversation::from_bytes(&[0xF0, 0].repeat(500));
        assert_eq!(conv.steps.len(), MAX_ROUNDS);
    }

    #[test]
    fn automatic_counts_follow_the_command() {
        // Step::Cmd, Auto tag, CreatePrimary by index, auto handles and
        // sessions.
        let idx = IMPLEMENTED_COMMANDS
            .iter()
            .position(|&c| c == 0x131)
            .unwrap() as u8;
        let data = [0, 0, idx, 0, 0, 0x01, 0, 0, 0, 0];
        let conv = Conversation::from_bytes(&data);
        let Step::Cmd(cmd) = &conv.steps[0] else {
            panic!("expected a command: {conv:?}");
        };
        assert_eq!(cmd.code, 0x131);
        assert_eq!(cmd.handles, vec![HandleOperand::Response { back: 0x01 }]);
        assert_eq!(
            cmd.sessions,
            vec![SessionSel::Password {
                auth: AuthSel::Entity
            }]
        );
        assert_eq!(cmd.fixups, Fixups::all_on());
    }

    #[test]
    fn sized_segments_stop_at_the_depth_limit() {
        let mut nested = Segment::Sized(vec![]);
        for _ in 0..MAX_SEGMENT_DEPTH + 2 {
            nested = Segment::Sized(vec![nested]);
        }
        let mut cmd = Cmd::new(0x17B);
        cmd.params = vec![nested];
        let conv = Conversation {
            steps: vec![Step::Cmd(cmd)],
        };
        let decoded = Conversation::from_bytes(&conv.to_bytes());
        let Step::Cmd(cmd) = &decoded.steps[0] else {
            panic!()
        };
        let mut depth = 0;
        let mut seg = &cmd.params[0];
        while let Segment::Sized(children) = seg {
            depth += 1;
            match children.first() {
                Some(c) => seg = c,
                None => break,
            }
        }
        assert_eq!(depth, MAX_SEGMENT_DEPTH);
    }

    #[test]
    fn mutations_apply() {
        let mut v = vec![0u8, 0];
        Mutation::FlipBit(9).apply(&mut v);
        assert_eq!(v, [0, 2]);
        Mutation::SetByte(2, 7).apply(&mut v);
        assert_eq!(v, [7, 2]);
        Mutation::Extend(vec![1]).apply(&mut v);
        assert_eq!(v, [7, 2, 1]);
        Mutation::Truncate(1).apply(&mut v);
        assert_eq!(v, [7]);
        let mut empty = Vec::new();
        Mutation::FlipBit(3).apply(&mut empty);
        Mutation::SetByte(3, 1).apply(&mut empty);
        assert!(empty.is_empty());
    }

    #[test]
    fn tags_resolve() {
        assert_eq!(TagSel::Auto.value(true), TPM_ST_SESSIONS);
        assert_eq!(TagSel::Auto.value(false), TPM_ST_NO_SESSIONS);
        assert_eq!(TagSel::NoSessions.value(true), TPM_ST_NO_SESSIONS);
        assert_eq!(TagSel::Sessions.value(false), TPM_ST_SESSIONS);
        assert_eq!(TagSel::Raw(5).value(true), 5);
    }
}
