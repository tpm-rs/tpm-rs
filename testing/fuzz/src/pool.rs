//! The value pool: everything earlier rounds of a conversation produced that
//! later rounds may reuse.
//!
//! After every round, [`ValuePool::record`] adds (from the `tpm-rs` response,
//! which matched the references or a documented exception):
//!
//! 1. the **response handles** (count from `handle_counts`), plus handles made
//!    persistent with `TPM2_EvictControl`;
//! 2. **typed fields** of the responses that matter for state (see
//!    [`extract_fields`]), each tagged with a [`FieldKind`] and kept in wire
//!    form, parsed field by field with the `tpm2` `Unmarshal` types; other
//!    successful responses contribute their raw parameter area
//!    ([`FieldKind::Bytes`]) and every TPM2B found by scanning it
//!    ([`FieldKind::Tpm2b`]);
//! 3. **driver-tracked facts** taken from the command and its success: NV
//!    indices defined (and undefined), the auth value of every entity whose
//!    auth the conversation set (objects through their `outPrivate` blobs,
//!    hierarchies, NV indices, sequences, context blobs), the Name of every
//!    loaded entity (for cpHash computations), and flushed or evicted
//!    handles.
//!
//! Every successful response is also unmarshaled as a whole with the typed
//! `tpm2` response of its command ([`check_typed_response`]); a successful
//! `tpm-rs` response that `tpm2` cannot parse completely is a finding.
//!
//! References ([`ValueRef`], [`HandleOperand`]) resolve by kind and recency,
//! modulo the number of candidates, with live handles before stale ones.

use std::collections::{HashMap, HashSet};

use testing::_common::hash;
use tpm2::commands::{self, Command, UnmarshalMessage};
use tpm2::{
    Handle, Tpm2bAttest, Tpm2bCreationData, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret,
    Tpm2bIdObject, Tpm2bName, Tpm2bNonce, Tpm2bNvPublic, Tpm2bPrivate, Tpm2bPublic, Tpm2bTimeout,
    TpmiAlgHash, TpmsContext, TpmtTkAuth, TpmtTkCreation, TpmtTkHashcheck, TpmtTkVerified,
    Unmarshal,
};

use crate::model::{FieldKind, HandleOperand, ValueRef};
use crate::wire::{Reader, TPM_RC_SUCCESS, be32, check_response, parse_command};

/// Command codes the pool interprets.
pub mod cc {
    #![allow(missing_docs)]
    pub const NV_UNDEFINE_SPACE_SPECIAL: u32 = 0x11F;
    pub const EVICT_CONTROL: u32 = 0x120;
    pub const NV_UNDEFINE_SPACE: u32 = 0x122;
    pub const HIERARCHY_CHANGE_AUTH: u32 = 0x129;
    pub const NV_DEFINE_SPACE: u32 = 0x12A;
    pub const CREATE_PRIMARY: u32 = 0x131;
    pub const NV_INCREMENT: u32 = 0x134;
    pub const NV_SET_BITS: u32 = 0x135;
    pub const NV_EXTEND: u32 = 0x136;
    pub const NV_WRITE: u32 = 0x137;
    pub const NV_WRITE_LOCK: u32 = 0x138;
    pub const NV_CHANGE_AUTH: u32 = 0x13B;
    pub const SEQUENCE_COMPLETE: u32 = 0x13E;
    pub const CERTIFY: u32 = 0x148;
    pub const CERTIFY_CREATION: u32 = 0x14A;
    pub const DUPLICATE: u32 = 0x14B;
    pub const GET_TIME: u32 = 0x14C;
    pub const GET_SESSION_AUDIT_DIGEST: u32 = 0x14D;
    pub const NV_READ_LOCK: u32 = 0x14F;
    pub const OBJECT_CHANGE_AUTH: u32 = 0x150;
    pub const POLICY_SECRET: u32 = 0x151;
    pub const REWRAP: u32 = 0x152;
    pub const CREATE: u32 = 0x153;
    pub const IMPORT: u32 = 0x156;
    pub const LOAD: u32 = 0x157;
    pub const QUOTE: u32 = 0x158;
    pub const MAC_START: u32 = 0x15B;
    pub const SIGN: u32 = 0x15D;
    pub const POLICY_SIGNED: u32 = 0x160;
    pub const CONTEXT_LOAD: u32 = 0x161;
    pub const CONTEXT_SAVE: u32 = 0x162;
    pub const FLUSH_CONTEXT: u32 = 0x165;
    pub const LOAD_EXTERNAL: u32 = 0x167;
    pub const MAKE_CREDENTIAL: u32 = 0x168;
    pub const NV_READ_PUBLIC: u32 = 0x169;
    pub const READ_PUBLIC: u32 = 0x173;
    pub const START_AUTH_SESSION: u32 = 0x176;
    pub const VERIFY_SIGNATURE: u32 = 0x177;
    pub const GET_RANDOM: u32 = 0x17B;
    pub const HASH: u32 = 0x17D;
    pub const NV_CERTIFY: u32 = 0x184;
    pub const EVENT_SEQUENCE_COMPLETE: u32 = 0x185;
    pub const HASH_SEQUENCE_START: u32 = 0x186;
    pub const POLICY_GET_DIGEST: u32 = 0x189;
    pub const CREATE_LOADED: u32 = 0x191;
    pub const GET_COMMAND_AUDIT_DIGEST: u32 = 0x133;
}

/// `TPMA_NV_WRITTEN`.
const TPMA_NV_WRITTEN: u32 = 1 << 29;
/// `TPMA_NV_WRITELOCKED`.
const TPMA_NV_WRITELOCKED: u32 = 1 << 11;
/// `TPMA_NV_READLOCKED`.
const TPMA_NV_READLOCKED: u32 = 1 << 12;

/// One extracted value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The round that produced it.
    pub round: usize,
    /// Its kind.
    pub kind: FieldKind,
    /// Its wire form (TPM2B values include the size field).
    pub bytes: Vec<u8>,
}

/// An NV index the conversation defined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NvIndex {
    /// The NV index handle.
    pub index: u32,
    /// The `TPMS_NV_PUBLIC` in wire form, with the attribute bits the driver
    /// tracks (written, write/read locked) kept up to date.
    pub public: Vec<u8>,
    /// Whether it is still defined.
    pub live: bool,
}

/// The auth value and Name of an entity saved with `TPM2_ContextSave`,
/// restored to the handle `TPM2_ContextLoad` returns for its blob.
type SavedFacts = (Option<Vec<u8>>, Option<Vec<u8>>);

/// The value pool of one conversation (see the module docs).
#[derive(Clone, Debug, Default)]
pub struct ValuePool {
    /// The extracted values, oldest first.
    values: Vec<Entry>,
    /// The response handles, oldest first.
    handles: Vec<u32>,
    /// Handles flushed or evicted since they were returned.
    flushed: HashSet<u32>,
    /// The NV indices defined, oldest first.
    nv: Vec<NvIndex>,
    /// Every non-empty auth value the conversation set, oldest first, without
    /// duplicates.
    auths: Vec<Vec<u8>>,
    /// The auth value of entities whose auth the conversation set.
    handle_auths: HashMap<u32, Vec<u8>>,
    /// The Name (TPM2B buffer) of entities the conversation learned.
    names: HashMap<u32, Vec<u8>>,
    /// The `userAuth` of objects by their `outPrivate` (wire form).
    private_auths: HashMap<Vec<u8>, Vec<u8>>,
    /// The facts about the entity saved in a context blob (wire form).
    contexts: HashMap<Vec<u8>, SavedFacts>,
}

impl ValuePool {
    /// All extracted values, oldest first.
    pub fn values(&self) -> &[Entry] {
        &self.values
    }

    /// All response handles (plus persistent handles), oldest first.
    pub fn response_handles(&self) -> &[u32] {
        &self.handles
    }

    /// The NV indices defined, oldest first.
    pub fn nv_indices(&self) -> &[NvIndex] {
        &self.nv
    }

    /// Whether `handle` was flushed or evicted.
    pub fn is_flushed(&self, handle: u32) -> bool {
        self.flushed.contains(&handle)
    }

    /// Every non-empty auth value the conversation set, oldest first.
    pub fn auths(&self) -> &[Vec<u8>] {
        &self.auths
    }

    /// The auth value of `handle`, if the conversation set it.
    pub fn handle_auth(&self, handle: u32) -> Option<&[u8]> {
        self.handle_auths.get(&handle).map(Vec::as_slice)
    }

    /// The `n`-th most recently set auth value (modulo their number; empty if
    /// none).
    pub fn known_auth(&self, n: u8) -> &[u8] {
        pick_newest(&self.auths, n).map_or(&[], Vec::as_slice)
    }

    /// The Name of `handle` (the TPM2B buffer): learned from responses for
    /// objects and NV indices, else the handle itself (correct for permanent
    /// entities, PCRs and sessions).
    pub fn name_of(&self, handle: u32) -> Vec<u8> {
        self.names
            .get(&handle)
            .cloned()
            .unwrap_or_else(|| handle.to_be_bytes().to_vec())
    }

    /// The bytes `r` resolves to: the `back`-th newest value of its kind, or
    /// the kind's placeholder while there is none.
    pub fn resolve_value(&self, r: ValueRef) -> Vec<u8> {
        let of_kind: Vec<&Entry> = self.values.iter().filter(|e| e.kind == r.kind).collect();
        pick_newest(&of_kind, r.back)
            .map_or_else(|| r.kind.placeholder().to_vec(), |e| e.bytes.clone())
    }

    /// The handle `op` resolves to. `sessions` are the live session handles
    /// (oldest first; from the session engine). Live handles come before
    /// stale ones; with no candidate, a fixed fallback handle is used
    /// (`0x80000000`, `0x01000000` or `TPM_RS_PW`).
    pub fn resolve_handle(&self, op: HandleOperand, sessions: &[u32]) -> u32 {
        match op {
            HandleOperand::Raw(h) => h,
            HandleOperand::Response { back } => {
                let (live, stale): (Vec<u32>, Vec<u32>) = self
                    .handles
                    .iter()
                    .rev()
                    .partition(|h| !self.flushed.contains(h));
                let all: Vec<u32> = live.into_iter().chain(stale).collect();
                all.get(usize::from(back) % all.len().max(1))
                    .copied()
                    .unwrap_or(0x8000_0000)
            }
            HandleOperand::Nv { back } => {
                let (live, stale): (Vec<&NvIndex>, Vec<&NvIndex>) =
                    self.nv.iter().rev().partition(|n| n.live);
                let all: Vec<u32> = live.into_iter().chain(stale).map(|n| n.index).collect();
                all.get(usize::from(back) % all.len().max(1))
                    .copied()
                    .unwrap_or(0x0100_0000)
            }
            HandleOperand::Session { back } => {
                pick_newest(sessions, back).copied().unwrap_or(0x4000_0009)
            }
        }
    }

    /// Every value reference that currently resolves to an extracted value,
    /// with the bytes it resolves to (for the corpus converter).
    pub fn candidates(&self) -> Vec<(ValueRef, Vec<u8>)> {
        FieldKind::ALL
            .iter()
            .flat_map(|&kind| {
                let n = self.values.iter().filter(|e| e.kind == kind).count();
                (0..n.min(256)).map(move |back| ValueRef {
                    kind,
                    back: back as u8,
                })
            })
            .map(|r| (r, self.resolve_value(r)))
            .collect()
    }

    /// Every handle operand that currently resolves to a response handle or
    /// NV index (or one of `sessions`, see [`Self::resolve_handle`]), with
    /// the handle it resolves to (for the corpus converter).
    pub fn handle_candidates(&self, sessions: &[u32]) -> Vec<(HandleOperand, u32)> {
        let response =
            (0..self.handles.len().min(256)).map(|b| HandleOperand::Response { back: b as u8 });
        let nv = (0..self.nv.len().min(256)).map(|b| HandleOperand::Nv { back: b as u8 });
        let session =
            (0..sessions.len().min(256)).map(|b| HandleOperand::Session { back: b as u8 });
        response
            .chain(nv)
            .chain(session)
            .map(|op| (op, self.resolve_handle(op, sessions)))
            .collect()
    }

    /// Adds a value.
    fn push(&mut self, round: usize, kind: FieldKind, bytes: &[u8]) {
        self.values.push(Entry {
            round,
            kind,
            bytes: bytes.to_vec(),
        });
    }

    /// Remembers an auth value set for `handle` (if any).
    fn set_auth(&mut self, handle: Option<u32>, auth: &[u8]) {
        if let Some(h) = handle {
            self.handle_auths.insert(h, auth.to_vec());
        }
        if !auth.is_empty() && !self.auths.iter().any(|a| a == auth) {
            self.auths.push(auth.to_vec());
        }
    }

    /// Records round `round`: `command` (as sent) and `response` (the
    /// `tpm-rs` response). `decrypted_params` replaces the response parameter
    /// area when the session engine decrypted it. Nothing is recorded for
    /// error responses, malformed responses or unparseable commands, except
    /// that values are still extracted from a success response to a command
    /// that does not parse (with its code taken from the header).
    ///
    /// # Errors
    /// A description of the problem if the response is a success response
    /// that the typed `tpm2` response of its command cannot unmarshal
    /// completely, or whose fields cannot be extracted.
    pub fn record(
        &mut self,
        round: usize,
        command: &[u8],
        response: &[u8],
        decrypted_params: Option<&[u8]>,
    ) -> Result<(), String> {
        let parsed = parse_command(command);
        let code = parsed.as_ref().map(|c| c.code).or_else(|| be32(command, 6));
        let Ok(view) = check_response(response, None, code) else {
            return Ok(());
        };
        if view.rc != TPM_RC_SUCCESS {
            return Ok(());
        }
        let Some(code) = code else {
            return Ok(());
        };
        let params = decrypted_params.unwrap_or(view.params);
        for &h in &view.handles {
            self.handles.push(h);
            self.flushed.remove(&h);
            self.push(round, FieldKind::Handle, &h.to_be_bytes());
        }
        // A response encrypted by a session nobody decrypted is opaque: keep
        // its handles and facts, but neither check nor extract its fields.
        let opaque = decrypted_params.is_none()
            && parsed.as_ref().is_some_and(|c| has_encrypt_session(c.auth));
        if opaque {
            if let Some(cmd) = parsed {
                self.track_facts(&cmd.handles, cmd.params, code, &view.handles, &[]);
            }
            return Ok(());
        }
        check_typed_response(code, &view.handles, params)?;
        let fields = extract_fields(code, params)
            .map_err(|e| format!("cannot extract the fields of the {code:#x} response: {e}"))?;
        if fields.is_empty() && !params.is_empty() {
            self.push(round, FieldKind::Bytes, params);
            let mut r = Reader(params);
            while let Some(b) = r.tpm2b() {
                self.push(round, FieldKind::Tpm2b, b);
            }
        }
        for (kind, bytes) in &fields {
            self.push(round, *kind, bytes);
        }
        if let Some(cmd) = parsed {
            self.track_facts(&cmd.handles, cmd.params, code, &view.handles, &fields);
        }
        Ok(())
    }

    /// Updates the driver-tracked facts after a successful command `code`
    /// with `handles` and `params`, whose response returned `rsp_handles` and
    /// the typed `fields`.
    fn track_facts(
        &mut self,
        handles: &[u32],
        params: &[u8],
        code: u32,
        rsp_handles: &[u32],
        fields: &[(FieldKind, Vec<u8>)],
    ) {
        let field = |kind| {
            fields
                .iter()
                .find(|(k, _)| *k == kind)
                .map(|(_, b)| b.as_slice())
        };
        let rsp_handle = rsp_handles.first().copied();
        let mut p = Reader(params);
        let name_body = |kind| field(kind).and_then(|b| Reader(b).tpm2b_body());
        match code {
            cc::CREATE_PRIMARY | cc::CREATE_LOADED | cc::CREATE => {
                // TPM2B_SENSITIVE_CREATE { size, userAuth, data }.
                let user_auth = p.take(2).and_then(|_| p.tpm2b_body()).unwrap_or_default();
                if code == cc::CREATE {
                    if let Some(private) = field(FieldKind::Private) {
                        self.private_auths
                            .insert(private.to_vec(), user_auth.to_vec());
                    }
                    self.set_auth(None, user_auth);
                } else {
                    self.set_auth(rsp_handle, user_auth);
                    if let Some(private) = field(FieldKind::Private) {
                        self.private_auths
                            .insert(private.to_vec(), user_auth.to_vec());
                    }
                }
            }
            cc::LOAD => {
                if let Some(private) = p.tpm2b()
                    && let Some(auth) = self.private_auths.get(private).cloned()
                {
                    self.set_auth(rsp_handle, &auth);
                }
            }
            cc::LOAD_EXTERNAL => {
                // TPM2B_SENSITIVE { size, TPMT_SENSITIVE { type, authValue, .. } }.
                if p.u16().is_some_and(|size| size > 0)
                    && p.u16().is_some()
                    && let Some(auth) = p.tpm2b_body()
                {
                    self.set_auth(rsp_handle, auth);
                }
            }
            cc::OBJECT_CHANGE_AUTH => {
                if let (Some(auth), Some(private)) = (p.tpm2b_body(), field(FieldKind::Private)) {
                    self.private_auths.insert(private.to_vec(), auth.to_vec());
                    self.set_auth(None, auth);
                }
            }
            cc::HIERARCHY_CHANGE_AUTH | cc::NV_CHANGE_AUTH => {
                if let Some(auth) = p.tpm2b_body() {
                    self.set_auth(handles.first().copied(), auth);
                }
            }
            cc::HASH_SEQUENCE_START | cc::MAC_START => {
                if let Some(auth) = p.tpm2b_body() {
                    self.set_auth(rsp_handle, auth);
                }
            }
            cc::NV_DEFINE_SPACE => {
                let auth = p.tpm2b_body();
                let public = p.tpm2b_body();
                if let (Some(auth), Some(public)) = (auth, public)
                    && let Some(index) = be32(public, 0)
                {
                    self.set_auth(Some(index), auth);
                    self.nv.retain(|n| n.index != index);
                    self.nv.push(NvIndex {
                        index,
                        public: public.to_vec(),
                        live: true,
                    });
                    self.update_nv_name(index);
                }
            }
            cc::NV_UNDEFINE_SPACE | cc::NV_UNDEFINE_SPACE_SPECIAL => {
                let index = if code == cc::NV_UNDEFINE_SPACE {
                    handles.get(1)
                } else {
                    handles.first()
                };
                if let Some(&index) = index {
                    for n in self.nv.iter_mut().filter(|n| n.index == index) {
                        n.live = false;
                    }
                }
            }
            cc::NV_WRITE | cc::NV_INCREMENT | cc::NV_EXTEND | cc::NV_SET_BITS => {
                self.set_nv_attributes(handles.get(1).copied(), TPMA_NV_WRITTEN);
            }
            cc::NV_WRITE_LOCK => {
                self.set_nv_attributes(handles.get(1).copied(), TPMA_NV_WRITELOCKED);
            }
            cc::NV_READ_LOCK => {
                self.set_nv_attributes(handles.get(1).copied(), TPMA_NV_READLOCKED);
            }
            cc::NV_READ_PUBLIC => {
                if let (Some(&index), Some(name)) = (handles.first(), name_body(FieldKind::Name)) {
                    self.names.insert(index, name.to_vec());
                }
            }
            cc::FLUSH_CONTEXT => {
                if let Some(h) = p.u32() {
                    self.flushed.insert(h);
                }
            }
            cc::CONTEXT_SAVE => {
                if let (Some(&h), Some(context)) = (handles.first(), field(FieldKind::Context)) {
                    let facts = (
                        self.handle_auths.get(&h).cloned(),
                        self.names.get(&h).cloned(),
                    );
                    self.contexts.insert(context.to_vec(), facts);
                }
            }
            cc::CONTEXT_LOAD => {
                if let (Some(h), Some((auth, name))) =
                    (rsp_handle, self.contexts.get(params).cloned())
                {
                    if let Some(auth) = auth {
                        self.handle_auths.insert(h, auth);
                    }
                    if let Some(name) = name {
                        self.names.insert(h, name);
                    }
                }
            }
            cc::EVICT_CONTROL => {
                if let (Some(&object), Some(persistent)) = (handles.get(1), p.u32()) {
                    if object >> 24 == 0x81 {
                        self.flushed.insert(object);
                    } else {
                        if let Some(auth) = self.handle_auths.get(&object).cloned() {
                            self.handle_auths.insert(persistent, auth);
                        }
                        if let Some(name) = self.names.get(&object).cloned() {
                            self.names.insert(persistent, name);
                        }
                        self.handles.push(persistent);
                        self.flushed.remove(&persistent);
                    }
                }
            }
            _ => {}
        }
        // Objects whose Name the response reports.
        if let Some(name) = name_body(FieldKind::Name) {
            let target = match code {
                cc::READ_PUBLIC => handles.first().copied(),
                cc::NV_READ_PUBLIC => None,
                _ => rsp_handle,
            };
            if let Some(h) = target {
                self.names.insert(h, name.to_vec());
            }
        }
    }

    /// Sets `bits` in the tracked attributes of NV index `index` and updates
    /// its Name.
    fn set_nv_attributes(&mut self, index: Option<u32>, bits: u32) {
        let Some(index) = index else { return };
        let Some(nv) = self
            .nv
            .iter_mut()
            .rev()
            .find(|n| n.index == index && n.live)
        else {
            return;
        };
        if let Some(attrs) = be32(&nv.public, 6) {
            nv.public[6..10].copy_from_slice(&(attrs | bits).to_be_bytes());
        }
        self.update_nv_name(index);
    }

    /// Recomputes the Name of NV index `index` (`nameAlg || H(TPMS_NV_PUBLIC)`)
    /// from its tracked public area.
    fn update_nv_name(&mut self, index: u32) {
        let Some(nv) = self.nv.iter().rev().find(|n| n.index == index) else {
            return;
        };
        let Some(alg_id) = nv.public.get(4..6) else {
            return;
        };
        let Ok(alg) = TpmiAlgHash::unmarshal(&mut &alg_id[..]) else {
            return;
        };
        let mut name = alg_id.to_vec();
        name.extend_from_slice(&hash(alg, &nv.public));
        self.names.insert(index, name);
    }
}

/// Whether the command authorization area `auth` (without its size field)
/// has a session with the `encrypt` attribute (`TPMA_SESSION` bit 6), so the
/// first response parameter is encrypted. An area that does not parse
/// counts as having one only up to the session where parsing stops.
pub fn has_encrypt_session(auth: &[u8]) -> bool {
    let mut r = Reader(auth);
    while !r.rest().is_empty() {
        let attrs = (|| {
            r.u32()?;
            r.tpm2b()?;
            let attrs = r.u8()?;
            r.tpm2b()?;
            Some(attrs)
        })();
        match attrs {
            Some(a) if a & 0x40 != 0 => return true,
            Some(_) => {}
            None => return false,
        }
    }
    false
}

/// The `back`-th newest element of `items` (oldest first), modulo their
/// number.
fn pick_newest<T>(items: &[T], back: u8) -> Option<&T> {
    if items.is_empty() {
        return None;
    }
    items.get(items.len() - 1 - usize::from(back) % items.len())
}

/// `TPM2B_PUBLIC+`: a public area whose `nameAlg` may be `TPM_ALG_NULL` (as
/// `TPM2_ReadPublic` returns for an external object loaded without a Name).
struct PublicPlus;

impl<'a> Unmarshal<'a> for PublicPlus {
    fn unmarshal(src: &mut &'a [u8]) -> Result<Self, tpm2::errors::UnmarshalError> {
        Tpm2bPublic::unmarshal_nullable(src).map(|_| PublicPlus)
    }
}

/// Unmarshals one `T` from `src` and returns the bytes it occupied.
fn take<'a, T: Unmarshal<'a>>(src: &mut &'a [u8]) -> Result<&'a [u8], String> {
    let before = *src;
    T::unmarshal(src).map_err(|e| format!("{e:?}"))?;
    Ok(&before[..before.len() - src.len()])
}

/// Extracts the typed fields of the successful response parameter area
/// `params` of command `code`, in wire form; empty for commands without an
/// extractor.
///
/// # Errors
/// If a field does not unmarshal.
pub fn extract_fields(code: u32, params: &[u8]) -> Result<Vec<(FieldKind, Vec<u8>)>, String> {
    use FieldKind as K;
    let mut src = params;
    let mut out = Vec::new();
    macro_rules! fields {
        ($($kind:ident : $ty:ty),* $(,)?) => {{
            $( out.push((K::$kind, take::<$ty>(&mut src)?.to_vec())); )*
        }};
    }
    match code {
        cc::CREATE_PRIMARY => fields!(
            Public: PublicPlus, CreationData: Tpm2bCreationData, Digest: Tpm2bDigest,
            Ticket: TpmtTkCreation, Name: Tpm2bName,
        ),
        cc::CREATE => fields!(
            Private: Tpm2bPrivate, Public: PublicPlus, CreationData: Tpm2bCreationData,
            Digest: Tpm2bDigest, Ticket: TpmtTkCreation,
        ),
        cc::CREATE_LOADED => fields!(Private: Tpm2bPrivate, Public: PublicPlus, Name: Tpm2bName),
        cc::LOAD | cc::LOAD_EXTERNAL => fields!(Name: Tpm2bName),
        cc::START_AUTH_SESSION => fields!(Nonce: Tpm2bNonce),
        cc::CONTEXT_SAVE => fields!(Context: TpmsContext),
        cc::READ_PUBLIC => fields!(Public: PublicPlus, Name: Tpm2bName, Name: Tpm2bName),
        cc::NV_READ_PUBLIC => fields!(NvPublic: Tpm2bNvPublic, Name: Tpm2bName),
        cc::GET_RANDOM | cc::POLICY_GET_DIGEST => fields!(Digest: Tpm2bDigest),
        cc::DUPLICATE => fields!(
            Data: Tpm2bData, Private: Tpm2bPrivate, EncryptedSecret: Tpm2bEncryptedSecret,
        ),
        cc::REWRAP => fields!(Private: Tpm2bPrivate, EncryptedSecret: Tpm2bEncryptedSecret),
        cc::IMPORT | cc::OBJECT_CHANGE_AUTH => fields!(Private: Tpm2bPrivate),
        cc::MAKE_CREDENTIAL => {
            fields!(IdObject: Tpm2bIdObject, EncryptedSecret: Tpm2bEncryptedSecret)
        }
        cc::HASH | cc::SEQUENCE_COMPLETE => fields!(Digest: Tpm2bDigest, Ticket: TpmtTkHashcheck),
        cc::VERIFY_SIGNATURE => fields!(Ticket: TpmtTkVerified),
        cc::POLICY_SECRET | cc::POLICY_SIGNED => fields!(Bytes: Tpm2bTimeout, Ticket: TpmtTkAuth),
        cc::CERTIFY
        | cc::CERTIFY_CREATION
        | cc::QUOTE
        | cc::GET_TIME
        | cc::NV_CERTIFY
        | cc::GET_SESSION_AUDIT_DIGEST
        | cc::GET_COMMAND_AUDIT_DIGEST => {
            fields!(Attest: Tpm2bAttest);
            out.push((K::Signature, src.to_vec()));
            src = &[];
        }
        cc::SIGN => {
            out.push((K::Signature, src.to_vec()));
            src = &[];
        }
        _ => {}
    }
    let _ = src;
    Ok(out)
}

/// Unmarshals a whole response of type `R` from the response `handles` and
/// parameter area `params`, requiring every parameter byte to be consumed.
fn check_typed<'a, R: UnmarshalMessage<'a>>(
    handles: &[u32],
    params: &'a [u8],
) -> Result<(), String> {
    let mut hs = R::Handles::default();
    if hs.as_ref().len() != handles.len() {
        return Err(format!(
            "{} response handles, the typed response has {}",
            handles.len(),
            hs.as_ref().len()
        ));
    }
    for (dst, &h) in hs.as_mut().iter_mut().zip(handles) {
        *dst = Handle(h);
    }
    let mut src = params;
    R::unmarshal_with_handles(hs, &mut src).map_err(|e| format!("{e:?}"))?;
    if !src.is_empty() {
        return Err(format!("{} trailing parameter bytes", src.len()));
    }
    Ok(())
}

/// The response check of command type `C`.
fn check_command<C: Command>(handles: &[u32], params: &[u8]) -> Result<(), String> {
    check_typed::<C::Response<'_>>(handles, params)
}

/// Unmarshals the successful response (`handles`, `params`) of command
/// `code` with the typed `tpm2` response of that command (every command
/// `tpm2` defines); a no-op for other codes.
///
/// # Errors
/// If the typed response does not unmarshal or leaves parameter bytes.
#[allow(deprecated)] // Deprecated commands are still fuzzed.
pub fn check_typed_response(code: u32, handles: &[u32], params: &[u8]) -> Result<(), String> {
    macro_rules! typed {
        ($($name:ident),* $(,)?) => {
            $(
                if code == <commands::$name as Command>::CMD_CODE.code() {
                    return check_command::<commands::$name>(handles, params)
                        .map_err(|e| format!("typed {} response: {e}", stringify!($name)));
                }
            )*
        };
    }
    typed!(
        Decapsulate,
        ECCDecrypt,
        ECCEncrypt,
        ECCParameters,
        ECDHKeyGen,
        ECDHZGen,
        Encapsulate,
        RSADecrypt,
        RSAEncrypt,
        ZGen2Phase,
        ACGetCapability,
        ACSend,
        PolicyACSendSelect,
        Certify,
        CertifyCreation,
        CertifyX509,
        GetCommandAuditDigest,
        GetSessionAuditDigest,
        GetTime,
        Quote,
        GetCapability,
        SetCapability,
        TestParms,
        ACTSetTimeout,
        ClockRateAdjust,
        ClockSet,
        ReadClock,
        SetCommandCodeAuditStatus,
        ContextLoad,
        ContextSave,
        EvictControl,
        FlushContext,
        DictionaryAttackLockReset,
        DictionaryAttackParameters,
        Duplicate,
        Import,
        Rewrap,
        PolicyAuthValue,
        PolicyAuthorize,
        PolicyAuthorizeNV,
        PolicyCapability,
        PolicyCommandCode,
        PolicyCounterTimer,
        PolicyCpHash,
        PolicyDuplicationSelect,
        PolicyGetDigest,
        PolicyLocality,
        PolicyNV,
        PolicyNameHash,
        PolicyNvWritten,
        PolicyOR,
        PolicyPCR,
        PolicyParameters,
        PolicyPassword,
        PolicyPhysicalPresence,
        PolicySecret,
        PolicySigned,
        PolicyTemplate,
        PolicyTicket,
        PolicyTransportSPDM,
        Commit,
        ECEphemeral,
        FieldUpgradeData,
        FieldUpgradeStart,
        FirmwareRead,
        EventSequenceComplete,
        HMACStart,
        HashSequenceStart,
        SequenceComplete,
        SequenceUpdate,
        SignSequenceStart,
        VerifySequenceStart,
        ChangeEPS,
        ChangePPS,
        Clear,
        ClearControl,
        CreatePrimary,
        HierarchyChangeAuth,
        HierarchyControl,
        ReadOnlyControl,
        SetPrimaryPolicy,
        PPCommands,
        SetAlgorithmSet,
        NVCertify,
        NVChangeAuth,
        NVDefineSpace,
        NVDefineSpace2,
        NVExtend,
        NVGlobalWriteLock,
        NVIncrement,
        NVRead,
        NVReadLock,
        NVReadPublic,
        NVReadPublic2,
        NVSetBits,
        NVUndefineSpace,
        NVUndefineSpaceSpecial,
        NVWrite,
        NVWriteLock,
        ActivateCredential,
        Create,
        CreateLoaded,
        Load,
        LoadExternal,
        MakeCredential,
        ObjectChangeAuth,
        ReadPublic,
        Unseal,
        PCRAllocate,
        PCREvent,
        PCRExtend,
        PCRRead,
        PCRReset,
        PCRSetAuthPolicy,
        PCRSetAuthValue,
        GetRandom,
        StirRandom,
        PolicyRestart,
        StartAuthSession,
        Sign,
        SignDigest,
        SignSequenceComplete,
        VerifyDigestSignature,
        VerifySequenceComplete,
        VerifySignature,
        Shutdown,
        Startup,
        EncryptDecrypt,
        EncryptDecrypt2,
        HMAC,
        Hash,
        GetTestResult,
        IncrementalSelfTest,
        SelfTest,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A success response with `handles` and `params`, without sessions.
    fn response(handles: &[u32], params: &[u8]) -> Vec<u8> {
        let mut r = vec![0x80, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
        for h in handles {
            r.extend_from_slice(&h.to_be_bytes());
        }
        r.extend_from_slice(params);
        let len = r.len() as u32;
        r[2..6].copy_from_slice(&len.to_be_bytes());
        r
    }

    /// A no-session command with `handles` and `params`.
    fn command(code: u32, handles: &[u32], params: &[u8]) -> Vec<u8> {
        let mut c = vec![0x80, 0x01, 0, 0, 0, 0];
        c.extend_from_slice(&code.to_be_bytes());
        for h in handles {
            c.extend_from_slice(&h.to_be_bytes());
        }
        c.extend_from_slice(params);
        let len = c.len() as u32;
        c[2..6].copy_from_slice(&len.to_be_bytes());
        c
    }

    #[test]
    fn records_session_handles_and_nonces() {
        let mut pool = ValuePool::default();
        let rsp = response(&[0x0300_0000], &[0, 2, 0xAA, 0xBB]);
        let cmd = command(cc::START_AUTH_SESSION, &[0x4000_0007, 0x4000_0007], &[]);
        pool.record(0, &cmd, &rsp, None).unwrap();
        assert_eq!(pool.response_handles(), [0x0300_0000]);
        let nonce = ValueRef {
            kind: FieldKind::Nonce,
            back: 0,
        };
        assert_eq!(pool.resolve_value(nonce), [0, 2, 0xAA, 0xBB]);
        let handle = ValueRef {
            kind: FieldKind::Handle,
            back: 5,
        };
        assert_eq!(pool.resolve_value(handle), [3, 0, 0, 0]);
        // Error responses add nothing.
        pool.record(1, &cmd, &[0x80, 1, 0, 0, 0, 10, 0, 0, 1, 1], None)
            .unwrap();
        assert_eq!(pool.values().len(), 2);
    }

    #[test]
    fn unparseable_success_responses_are_reported() {
        let mut pool = ValuePool::default();
        let cmd = command(cc::GET_RANDOM, &[], &[0, 4]);
        // TPM2B size larger than the buffer.
        assert!(
            pool.record(0, &cmd, &response(&[], &[0, 9, 1]), None)
                .is_err()
        );
        // Trailing bytes.
        assert!(
            pool.record(0, &cmd, &response(&[], &[0, 1, 1, 7]), None)
                .is_err()
        );
        pool.record(0, &cmd, &response(&[], &[0, 1, 1]), None)
            .unwrap();
        let r = ValueRef {
            kind: FieldKind::Digest,
            back: 0,
        };
        assert_eq!(pool.resolve_value(r), [0, 1, 1]);
    }

    #[test]
    fn resolves_with_placeholders_when_empty() {
        let pool = ValuePool::default();
        for kind in FieldKind::ALL {
            assert_eq!(
                pool.resolve_value(ValueRef { kind, back: 7 }),
                kind.placeholder()
            );
        }
        assert_eq!(
            pool.resolve_handle(HandleOperand::Response { back: 3 }, &[]),
            0x8000_0000
        );
        assert_eq!(
            pool.resolve_handle(HandleOperand::Nv { back: 3 }, &[]),
            0x0100_0000
        );
        assert_eq!(
            pool.resolve_handle(HandleOperand::Session { back: 3 }, &[]),
            0x4000_0009
        );
        assert_eq!(
            pool.resolve_handle(HandleOperand::Session { back: 0 }, &[1, 2]),
            2
        );
        assert_eq!(pool.resolve_handle(HandleOperand::Raw(5), &[]), 5);
        assert_eq!(pool.name_of(0x4000_0001), [0x40, 0, 0, 1]);
    }

    #[test]
    fn tracks_nv_indices_and_flushes() {
        let mut pool = ValuePool::default();
        // NV_DefineSpace(owner, auth "ab", {0x01000005, sha256, attrs 0x40004, no policy, 8}).
        let mut params = vec![0, 2, b'a', b'b', 0, 14];
        params.extend_from_slice(&[1, 0, 0, 5, 0, 0x0B, 0, 4, 0, 4, 0, 0, 0, 8]);
        let cmd = command(cc::NV_DEFINE_SPACE, &[0x4000_0001], &params);
        pool.record(0, &cmd, &response(&[], &[]), None).unwrap();
        assert_eq!(pool.handle_auth(0x0100_0005), Some(&b"ab"[..]));
        assert_eq!(pool.known_auth(0), b"ab");
        assert_eq!(
            pool.resolve_handle(HandleOperand::Nv { back: 0 }, &[]),
            0x0100_0005
        );
        let name = pool.name_of(0x0100_0005);
        assert_eq!(name.len(), 34);
        assert_eq!(&name[..2], [0, 0x0B]);
        // Writing sets TPMA_NV_WRITTEN, which changes the Name.
        let cmd = command(cc::NV_WRITE, &[0x0100_0005, 0x0100_0005], &[0, 1, 1, 0, 0]);
        pool.record(1, &cmd, &response(&[], &[]), None).unwrap();
        assert_ne!(pool.name_of(0x0100_0005), name);
        assert_eq!(
            be32(&pool.nv_indices()[0].public, 6),
            Some(0x40004 | TPMA_NV_WRITTEN)
        );
        // Undefine.
        let cmd = command(cc::NV_UNDEFINE_SPACE, &[0x4000_0001, 0x0100_0005], &[]);
        pool.record(2, &cmd, &response(&[], &[]), None).unwrap();
        assert!(!pool.nv_indices()[0].live);

        // Response handles: live before flushed.
        let cmd = command(cc::HASH_SEQUENCE_START, &[], &[0, 1, 7, 0, 0x0B]);
        pool.record(3, &cmd, &response(&[0x8000_0000], &[]), None)
            .unwrap();
        assert_eq!(pool.handle_auth(0x8000_0000), Some(&[7][..]));
        pool.record(4, &cmd, &response(&[0x8000_0001], &[]), None)
            .unwrap();
        let flush = command(cc::FLUSH_CONTEXT, &[], &[0x80, 0, 0, 1]);
        pool.record(5, &flush, &response(&[], &[]), None).unwrap();
        assert!(pool.is_flushed(0x8000_0001));
        assert_eq!(
            pool.resolve_handle(HandleOperand::Response { back: 0 }, &[]),
            0x8000_0000
        );
        assert_eq!(
            pool.resolve_handle(HandleOperand::Response { back: 1 }, &[]),
            0x8000_0001
        );
        let candidates = pool.handle_candidates(&[0x0200_0000]);
        assert_eq!(candidates.len(), 4);
        assert!(candidates.contains(&(HandleOperand::Session { back: 0 }, 0x0200_0000)));
    }

    #[test]
    fn unknown_responses_contribute_raw_bytes_and_tpm2bs() {
        let mut pool = ValuePool::default();
        // PCR_Read-like code without an extractor but with a typed check would
        // fail, so use an unknown vendor-range code.
        let cmd = command(0x2000_0001, &[], &[]);
        pool.record(0, &cmd, &response(&[], &[0, 1, 5, 0, 0]), None)
            .unwrap();
        let kinds: Vec<FieldKind> = pool.values().iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            [FieldKind::Bytes, FieldKind::Tpm2b, FieldKind::Tpm2b]
        );
        assert_eq!(pool.candidates().len(), 3);
    }

    #[test]
    fn read_public_accepts_a_null_name_alg() {
        // KEYEDHASH public area with nameAlg TPM_ALG_NULL, empty Names (an
        // external object loaded without a Name).
        let params = [
            0, 0x10, 0, 8, 0, 0x10, 0, 4, 0, 0x40, 0, 0, 0, 5, 0, 0x0B, 0, 0, 0, 0, 0, 0,
        ];
        check_typed_response(cc::READ_PUBLIC, &[], &params).unwrap();
        let fields = extract_fields(cc::READ_PUBLIC, &params).unwrap();
        let kinds: Vec<FieldKind> = fields.iter().map(|(k, _)| *k).collect();
        assert_eq!(kinds, [FieldKind::Public, FieldKind::Name, FieldKind::Name]);
    }

    #[test]
    fn detects_encrypt_sessions() {
        let session = |attrs: u8| [0x02, 0, 0, 0, 0, 1, 0xAA, attrs, 0, 0];
        assert!(!has_encrypt_session(&[]));
        assert!(!has_encrypt_session(&session(0x21)));
        assert!(has_encrypt_session(&session(0x41)));
        assert!(has_encrypt_session(
            &[session(0x01), session(0x40)].concat()
        ));
        // Parsing stops at a truncated session.
        assert!(!has_encrypt_session(&[0x02, 0, 0, 0, 0, 9]));
    }

    #[test]
    fn responses_encrypted_for_untracked_sessions_are_opaque() {
        let mut pool = ValuePool::default();
        // GetRandom with a raw encrypt session; the "encrypted" response
        // would not parse (size 9 > buffer), but it is not checked.
        let mut cmd = vec![0x80, 0x02, 0, 0, 0, 0, 0, 0, 0x01, 0x7B, 0, 0, 0, 10];
        cmd.extend_from_slice(&[0x02, 0, 0, 0, 0, 1, 0xAA, 0x41, 0, 0, 0, 4]);
        let len = cmd.len() as u32;
        cmd[2..6].copy_from_slice(&len.to_be_bytes());
        let mut rsp = vec![0x80, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 9, 1];
        rsp.extend_from_slice(&[0, 1, 0xBB, 0x41, 0, 0]);
        let len = rsp.len() as u32;
        rsp[2..6].copy_from_slice(&len.to_be_bytes());
        pool.record(0, &cmd, &rsp, None).unwrap();
        assert!(pool.values().is_empty());
        // Decrypted by the engine: checked (and here rejected).
        assert!(pool.record(0, &cmd, &rsp, Some(&[0, 9, 1])).is_err());
    }

    #[test]
    fn tracks_object_auth_through_private_blobs() {
        let mut pool = ValuePool::default();
        // Create with userAuth "pw" returned outPrivate {0x77}.
        let sens = [0, 6, 0, 2, b'p', b'w', 0, 0];
        let cmd = command(cc::CREATE, &[0x8000_0000], &sens);
        // Only the outPrivate field matters for the facts.
        let fields = [(FieldKind::Private, vec![0, 1, 0x77])];
        let parsed = parse_command(&cmd).unwrap();
        pool.track_facts(&parsed.handles, parsed.params, cc::CREATE, &[], &fields);
        // Load of that private yields a handle with auth "pw".
        let cmd = command(cc::LOAD, &[0x8000_0000], &[0, 1, 0x77, 0, 0]);
        let parsed = parse_command(&cmd).unwrap();
        let fields = [(FieldKind::Name, vec![0, 2, 0, 0x0B])];
        pool.track_facts(
            &parsed.handles,
            parsed.params,
            cc::LOAD,
            &[0x8000_0001],
            &fields,
        );
        assert_eq!(pool.handle_auth(0x8000_0001), Some(&b"pw"[..]));
        assert_eq!(pool.name_of(0x8000_0001), [0, 0x0B]);
    }
}
