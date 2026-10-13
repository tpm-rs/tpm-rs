//! The server side of differential testing: hosts one C reference TPM in a
//! reference process (`mstpm20` or `ibmswtpm2`, see `src/bin/`) and compares
//! its responses with those of `tpm-rs`.
//!
//! A reference binary links its patched C reference TPM (built by
//! `testing/build.rs`), implements [`Backend`] over the C entry points
//! (`difftest_*`, the only `unsafe` FFI of this crate, in
//! `src/bin/shared/ffi.rs`) and calls [`serve`]. The C callbacks the patches
//! add (platform RNG, injected nonces and values `tpm-rs` produced, object
//! derivation) read the per-process [`ActiveRefState`] through
//! [`with_active_state`].
//!
//! On startup the server initializes the C reference like a new `Tpm`
//! (manufactured, powered on, NV on, `TPM2_Startup(TPM_SU_CLEAR)` done) and
//! answers with a reply; it then serves the requests of
//! [`super::protocol`] read from stdin, one reply each, until stdin is
//! closed.
//!
//! Each `Exchange` request carries a command and the response `tpm-rs` gave
//! to it. The command is executed by the C reference, and its response must
//! be byte-identical to the `tpm-rs` response, except for the
//! narrowly-scoped, documented rules in `compare_differential_response`
//! (each keyed to a command code, a response code pair and a checked
//! condition, and listed in `differential.md`), the `TPM_RC_RETRY` re-issue
//! rule, and the values C adopts from `tpm-rs` only after verifying them
//! ([`ActiveRefState::prepare_for_command`]). Any other difference is
//! replied as an error, which fails the test.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Write};
use std::sync::{Mutex, OnceLock};

use tpm2::crypto::{Asymmetric as _, KeyParams, Rng as _, kdf::kdfa_bits};
use tpm2::{Alg, TpmEccCurve, TpmaObject, TpmiAlgHash, TpmiRsaKeyBits};
use tpm2_platform_linux::{LinuxRng, PlatformCryptoProvider};
use tpm2_simulator::{DEFAULT_REPLAY_SEED, SimulatorPlatformSignal};

use super::Implementation;
use super::protocol::{self, Request};

/// Environment variable that makes reference processes log every applied
/// documented exception and `TPM_RC_RETRY` re-issue on stderr.
pub const LOG_EXCEPTIONS_ENV: &str = "DIFFERENTIAL_LOG_EXCEPTIONS";

/// A platform signal delivered to a C reference TPM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    /// Power on (`_rpc__Signal_PowerOn(false)`).
    PowerOn,
    /// Power off.
    PowerOff,
    /// Power cycle (`_rpc__Signal_PowerOn(true)`).
    Reset,
    /// NV available.
    NvOn,
    /// NV unavailable.
    NvOff,
    /// Physical presence asserted.
    PhysicalPresenceOn,
    /// Physical presence deasserted.
    PhysicalPresenceOff,
    /// Cancel asserted.
    CancelOn,
    /// Cancel deasserted.
    CancelOff,
}

/// The entry points of a patched C reference TPM (`difftest_*` in the
/// reference patches).
pub trait Backend {
    /// Manufactures the TPM (fresh RAM-backed NV), powers it on and makes NV
    /// available.
    fn init(&mut self);
    /// Advances the C reference's own clock by `ms` milliseconds (the
    /// virtual clock the patches read is advanced by the server).
    fn advance_clock(&mut self, ms: u64);
    /// Delivers a platform signal.
    fn signal(&mut self, signal: Signal);
    /// `_TPM_Hash_Start`.
    fn hash_start(&mut self);
    /// `_TPM_Hash_Data(data)`.
    fn hash_data(&mut self, data: &[u8]);
    /// `_TPM_Hash_End`.
    fn hash_end(&mut self);
    /// Executes `command` at `locality` and returns the response.
    fn run_command(&mut self, locality: u8, command: &[u8]) -> Vec<u8>;
}

/// Runs a reference process: initializes `backend`, then answers the
/// requests read from `input` on `output` until `input` ends (see the module
/// docs). `test` names the test the process serves, for diagnostics.
///
/// # Panics
/// If the protocol channel fails.
pub fn serve<B: Backend>(
    implementation: Implementation,
    backend: B,
    test: String,
    mut input: impl BufRead,
    mut output: impl Write,
) {
    let mut reply = |result: &Result<(), String>| {
        protocol::write_reply(&mut output, result)
            .and_then(|()| output.flush())
            .unwrap_or_else(|e| panic!("{implementation}: cannot write reply: {e}"));
    };
    let mut server = match Server::new(implementation, backend, test) {
        Ok(server) => {
            reply(&Ok(()));
            server
        }
        Err(e) => {
            reply(&Err(e));
            std::process::exit(1);
        }
    };
    loop {
        match protocol::read_request(&mut input) {
            Ok(Some(request)) => {
                let result = server.handle(request);
                reply(&result);
            }
            Ok(None) => return,
            Err(e) => panic!("{implementation}: cannot read request: {e}"),
        }
    }
}

/// Cache key for deterministic primary/derived object generation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DeriveKeyRequest {
    pub kdf_hash_alg: u16,
    pub parent_seed: Vec<u8>,
    pub label: Vec<u8>,
    pub context_u: Vec<u8>,
    pub context_v: Vec<u8>,
    pub obj_type: u16,
    pub name_alg: u16,
    pub object_attributes: u32,
    pub key_bits_or_curve: u16,
    pub fallback_data: Vec<u8>,
}

/// Derived sensitive/public components of a primary or derived object.
#[derive(Clone, Debug)]
pub struct DerivedObject {
    pub seed_value: Vec<u8>,
    pub private_key: Vec<u8>,
    pub unique_x: Vec<u8>,
    pub unique_y: Vec<u8>,
}

/// Derives a primary or derived object using `tpm-rs`'s KDFa and
/// `PlatformCryptoProvider`, memoizing the result.
pub fn derive_object_cached(req: &DeriveKeyRequest) -> Option<DerivedObject> {
    static CACHE: OnceLock<Mutex<HashMap<DeriveKeyRequest, DerivedObject>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(found) = cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(req)
        .cloned()
    {
        return Some(found);
    }
    let computed = derive_object_uncached(req)?;
    cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(req.clone(), computed.clone());
    Some(computed)
}

fn derive_object_uncached(req: &DeriveKeyRequest) -> Option<DerivedObject> {
    let kdf_hash = TpmiAlgHash::try_from(req.kdf_hash_alg).ok()?;
    let name_alg = TpmiAlgHash::try_from(req.name_alg).ok()?;
    let digest_size = name_alg.digest_size();
    let mut obj_seed = [0u8; 64];
    kdfa_bits(
        &PlatformCryptoProvider,
        kdf_hash,
        &req.parent_seed,
        &req.label,
        &req.context_u,
        &req.context_v,
        (digest_size * 8) as u32,
        &mut obj_seed,
    )
    .ok()?;
    let seed_slice = &obj_seed[..digest_size];

    let attrs = TpmaObject(req.object_attributes);
    let is_asymmetric = req.obj_type == Alg::RSA.id() || req.obj_type == Alg::ECC.id();
    let seed_value = if is_asymmetric
        && (attrs.contains(TpmaObject::SIGN_ENCRYPT) || !attrs.contains(TpmaObject::RESTRICTED))
    {
        Vec::new()
    } else {
        seed_slice.to_vec()
    };

    let compute_sym_unique = |key_bytes: &[u8]| -> Option<Vec<u8>> {
        let mut ctx = tpm2::crypto::HashStream::new(&PlatformCryptoProvider, name_alg).ok()?;
        ctx.update(seed_slice).ok()?;
        ctx.update(key_bytes).ok()?;
        let mut out = [0u8; 64];
        let digest = ctx.finalize(&mut out).ok()?;
        Some(digest.digest().to_vec())
    };

    match req.obj_type {
        x if x == Alg::RSA.id() => {
            let mut pub_buf = [0u8; 512];
            let mut priv_buf = [0u8; 1536];
            let (pub_len, priv_len) = PlatformCryptoProvider
                .generate_key(
                    Alg::RSA,
                    Some(KeyParams::Rsa(TpmiRsaKeyBits(req.key_bits_or_curve))),
                    &mut pub_buf,
                    &mut priv_buf,
                    Some(seed_slice),
                )
                .ok()?;
            let mut prime_p = [0u8; 256];
            let p_len = PlatformCryptoProvider
                .rsa_private_key_to_prime_p(&priv_buf[..priv_len], &mut prime_p)
                .ok()
                .flatten()?;
            Some(DerivedObject {
                seed_value,
                private_key: prime_p[..p_len].to_vec(),
                unique_x: pub_buf[..pub_len].to_vec(),
                unique_y: Vec::new(),
            })
        }
        x if x == Alg::ECC.id() => {
            let curve = TpmEccCurve::try_from(req.key_bits_or_curve).ok()?;
            let mut pub_buf = [0u8; 256];
            let mut priv_buf = [0u8; 128];
            let (pub_len, priv_len) = PlatformCryptoProvider
                .generate_key(
                    Alg::ECC,
                    Some(KeyParams::Ecc(curve)),
                    &mut pub_buf,
                    &mut priv_buf,
                    Some(seed_slice),
                )
                .ok()?;
            let coord_len = pub_len / 2;
            Some(DerivedObject {
                seed_value,
                private_key: priv_buf[..priv_len].to_vec(),
                unique_x: pub_buf[..coord_len].to_vec(),
                unique_y: pub_buf[coord_len..pub_len].to_vec(),
            })
        }
        x if x == Alg::SYMCIPHER.id() => {
            let sdo = attrs.contains(TpmaObject::SENSITIVE_DATA_ORIGIN);
            let private_key = if !sdo && !req.fallback_data.is_empty() {
                req.fallback_data.clone()
            } else {
                let sym_bytes = (req.key_bits_or_curve as usize) / 8;
                let mut key_buf = [0u8; 64];
                kdfa_bits(
                    &PlatformCryptoProvider,
                    name_alg,
                    seed_slice,
                    b"Symmetric Key",
                    &[],
                    &[],
                    (sym_bytes * 8) as u32,
                    &mut key_buf,
                )
                .ok()?;
                key_buf[..sym_bytes].to_vec()
            };
            let unique_x = compute_sym_unique(&private_key)?;
            Some(DerivedObject {
                seed_value,
                private_key,
                unique_x,
                unique_y: Vec::new(),
            })
        }
        x if x == Alg::KEYEDHASH.id() => {
            let sdo = attrs.contains(TpmaObject::SENSITIVE_DATA_ORIGIN);
            let private_key = if !sdo && !req.fallback_data.is_empty() {
                req.fallback_data.clone()
            } else {
                let key_size = 32usize;
                let mut key_buf = [0u8; 64];
                kdfa_bits(
                    &PlatformCryptoProvider,
                    name_alg,
                    seed_slice,
                    b"Symmetric Key",
                    &[],
                    &[],
                    (key_size * 8) as u32,
                    &mut key_buf,
                )
                .ok()?;
                key_buf[..key_size].to_vec()
            };
            let unique_x = compute_sym_unique(&private_key)?;
            Some(DerivedObject {
                seed_value,
                private_key,
                unique_x,
                unique_y: Vec::new(),
            })
        }
        _ => None,
    }
}

/// State shared with the C reference TPM callbacks.
pub struct ActiveRefState {
    pub virtual_ms: u64,
    pub plat_rng: LinuxRng,
    pub queued_nonces: Vec<Vec<u8>>,
    pub will_override_object: bool,
    pub recorded_ordinary_object: Option<(Vec<u8>, Vec<u8>)>,
    pub recorded_signature: Option<Vec<u8>>,
    pub recorded_secret: Option<Vec<u8>>,
    pub recorded_inner_sym_key: Option<Vec<u8>>,
    pub recorded_ecdh: Option<(Vec<u8>, Vec<u8>)>,
    pub recorded_rsa_encrypt: Option<Vec<u8>>,
    /// Mapping from `tpm-rs` `contextBlob` bytes to C reference `contextBlob` bytes.
    pub context_blobs: Vec<(Vec<u8>, Vec<u8>)>,
    /// Byte offsets successfully written (`TPM2_NV_Write`) per NV index since
    /// it was defined (for exception 5).
    pub nv_written: HashMap<u32, HashSet<usize>>,
    /// Handles of the hash/HMAC sequence objects currently loaded in
    /// tpm-rs (for exception 10).
    pub rs_sequences: Vec<u32>,
    /// Transient object handles that differ between the implementations,
    /// as `(tpm-rs handle, C handle)` pairs (exception 11). Handles in
    /// commands are translated with this map before they are sent to C.
    pub handle_map: Vec<(u32, u32)>,
}

impl Default for ActiveRefState {
    fn default() -> Self {
        Self::new()
    }
}

impl ActiveRefState {
    /// The state of a freshly initialized reference process.
    pub fn new() -> Self {
        Self {
            virtual_ms: 0,
            plat_rng: LinuxRng::seeded(DEFAULT_REPLAY_SEED),
            queued_nonces: Vec::new(),
            will_override_object: false,
            recorded_ordinary_object: None,
            recorded_signature: None,
            recorded_secret: None,
            recorded_inner_sym_key: None,
            recorded_ecdh: None,
            recorded_rsa_encrypt: None,
            context_blobs: Vec::new(),
            nv_written: HashMap::new(),
            rs_sequences: Vec::new(),
            handle_map: Vec::new(),
        }
    }

    pub fn fill_plat_rng(&mut self, dest: &mut [u8]) {
        let _ = self.plat_rng.fill_bytes(dest);
    }

    pub fn take_nonce(&mut self, dest: &mut [u8]) -> bool {
        if self.queued_nonces.is_empty() {
            return false;
        }
        let nonce = self.queued_nonces.remove(0);
        if nonce.len() == dest.len() {
            dest.copy_from_slice(&nonce);
            true
        } else {
            false
        }
    }

    pub fn peek_nonce(&self, index: usize, dest: &mut [u8]) -> bool {
        let Some(nonce) = self.queued_nonces.get(index) else {
            return false;
        };
        if nonce.len() == dest.len() {
            dest.copy_from_slice(nonce);
            true
        } else {
            false
        }
    }

    /// The command to send to C: `command` with every tpm-rs transient
    /// handle of `handle_map` in its handle area (and the `flushHandle`
    /// parameter of `TPM2_FlushContext`) replaced by the C handle.
    pub fn to_ref_command(&self, command: &[u8]) -> Vec<u8> {
        let mut out = command.to_vec();
        if self.handle_map.is_empty() {
            return out;
        }
        let Some((_, code)) = header(command) else {
            return out;
        };
        let mut positions: Vec<usize> = match handle_counts(code) {
            Some((n, _)) => (0..n).map(|i| 10 + 4 * i).collect(),
            None => Vec::new(),
        };
        if code == cc::FLUSH_CONTEXT
            && let Some((_, params)) = command_parts(command, 0)
        {
            positions.push(command.len() - params.len());
        }
        for at in positions {
            if let Some(h) = be32(command, at)
                && let Some(&(_, c)) = self.handle_map.iter().find(|(r, _)| *r == h)
            {
                out[at..at + 4].copy_from_slice(&c.to_be_bytes());
            }
        }
        out
    }

    /// Maps a `contextBlob` given to `TPM2_ContextLoad` to the C reference's
    /// blob for the same saved context.
    ///
    /// The `contextBlob` layout is implementation-defined, so a blob produced
    /// by `tpm-rs`'s `TPM2_ContextSave` can never be loaded by C. Only a blob
    /// that is byte-for-byte identical to one `tpm-rs` returned earlier on
    /// this TPM is translated (to the blob C returned for the same
    /// `TPM2_ContextSave`). Every other blob (tampered, truncated, foreign) is
    /// passed to C unchanged, so neither implementation's rejection of a
    /// modified blob is fabricated by the harness.
    pub fn translate_context_blob(&self, incoming: &[u8], out_buf: &mut [u8]) -> Option<usize> {
        let (_, ref_blob) = self
            .context_blobs
            .iter()
            .rev()
            .find(|(rs_blob, _)| rs_blob.as_slice() == incoming)?;
        let dest = out_buf.get_mut(..ref_blob.len())?;
        dest.copy_from_slice(ref_blob);
        Some(ref_blob.len())
    }

    /// Prepares the values the C reference may adopt from the `tpm-rs`
    /// response (`expected`) to the next command (all only on
    /// `TPM_RC_SUCCESS`):
    ///
    /// * `nonceTPM` values (random, unverifiable);
    /// * the created object of `TPM2_Create`/`TPM2_CreateLoaded` (C unwraps
    ///   the secret from `outPrivate` under its own parent, verifies it and
    ///   recomputes the public area itself);
    /// * nonce-dependent signatures, `TPM2_Duplicate`/`TPM2_Rewrap`/
    ///   `TPM2_MakeCredential` encrypted seeds and inner keys,
    ///   `TPM2_ECDH_KeyGen` points and `TPM2_RSA_Encrypt` ciphertexts, which
    ///   the patched C reference adopts only after verifying them with its
    ///   own key (see the reference patches and `differential.md`).
    ///
    /// Marshaled structures are handed to C in their wire form (a `TPM2B`
    /// with its size field); nonces as their buffer contents.
    pub fn prepare_for_command(&mut self, command: &[u8], expected: &[u8]) {
        self.queued_nonces.clear();
        self.will_override_object = false;
        self.recorded_ordinary_object = None;
        self.recorded_signature = None;
        self.recorded_secret = None;
        self.recorded_inner_sym_key = None;
        self.recorded_ecdh = None;
        self.recorded_rsa_encrypt = None;

        let Some((_, code)) = header(command) else {
            return;
        };
        let Some(rsp) = split_response(expected, code) else {
            return;
        };
        let mut p = Reader(rsp.params);
        if code == cc::START_AUTH_SESSION
            && let Some(nonce) = p.tpm2b_body()
        {
            self.queued_nonces.push(nonce.to_vec());
        }
        if let Some(nonces) = auth_response_nonces(rsp.auth) {
            self.queued_nonces.extend(
                nonces
                    .into_iter()
                    .filter(|n| !n.is_empty())
                    .map(<[u8]>::to_vec),
            );
        }
        // The signature (`TPMT_SIGNATURE`) is the last response parameter,
        // after `skip` TPM2B parameters.
        let signature_after = |mut p: Reader<'_>, skip: usize| -> Option<Vec<u8>> {
            for _ in 0..skip {
                p.tpm2b()?;
            }
            Some(p.0.to_vec())
        };
        match code {
            cc::CREATE | cc::CREATE_LOADED => {
                self.will_override_object = true;
                if let (Some(out_private), Some(out_public)) = (p.tpm2b(), p.tpm2b()) {
                    self.recorded_ordinary_object =
                        Some((out_public.to_vec(), out_private.to_vec()));
                }
            }
            cc::CREATE_PRIMARY => self.will_override_object = true,
            cc::SIGN => self.recorded_signature = signature_after(p, 0),
            cc::CERTIFY
            | cc::CERTIFY_CREATION
            | cc::QUOTE
            | cc::GET_SESSION_AUDIT_DIGEST
            | cc::GET_COMMAND_AUDIT_DIGEST
            | cc::GET_TIME
            | cc::NV_CERTIFY => self.recorded_signature = signature_after(p, 1),
            cc::CERTIFY_X509 => self.recorded_signature = signature_after(p, 2),
            cc::DUPLICATE => {
                if let (Some(key), Some(_), Some(seed)) = (p.tpm2b(), p.tpm2b(), p.tpm2b()) {
                    self.recorded_inner_sym_key = Some(key.to_vec());
                    self.recorded_secret = Some(seed.to_vec());
                }
            }
            cc::REWRAP | cc::MAKE_CREDENTIAL => {
                if let (Some(_), Some(secret)) = (p.tpm2b(), p.tpm2b()) {
                    self.recorded_secret = Some(secret.to_vec());
                }
            }
            cc::ECDH_KEYGEN => {
                if let (Some(z), Some(public)) = (p.tpm2b(), p.tpm2b()) {
                    self.recorded_ecdh = Some((z.to_vec(), public.to_vec()));
                }
            }
            cc::RSA_ENCRYPT => {
                self.recorded_rsa_encrypt = p.tpm2b().map(<[u8]>::to_vec);
            }
            _ => {}
        }
    }

    /// Records the `contextBlob` pair of a successful `TPM2_ContextSave`
    /// (`expected` from `tpm-rs`, `actual` from C) after a command
    /// completes.
    pub fn post_command(&mut self, command: &[u8], expected: &[u8], actual: &[u8]) {
        if header(command).map(|(_, code)| code) != Some(cc::CONTEXT_SAVE) {
            return;
        }
        fn blob(rsp: &[u8]) -> Option<&[u8]> {
            split_response(rsp, cc::CONTEXT_SAVE).and_then(|r| context_blob(r.params))
        }
        if let (Some(rs_blob), Some(ref_blob)) = (blob(expected), blob(actual)) {
            self.context_blobs
                .push((rs_blob.to_vec(), ref_blob.to_vec()));
        }
    }
}

std::thread_local! {
    static ACTIVE_STATE: RefCell<Option<ActiveRefState>> = const { RefCell::new(None) };
}

pub fn with_active_state<R>(f: impl FnOnce(&mut ActiveRefState) -> R) -> Option<R> {
    ACTIVE_STATE.with(|cell| cell.borrow_mut().as_mut().map(f))
}

/// `TPM_RC_RETRY` (a warning).
const TPM_RC_RETRY: u32 = 0x0000_0922;

/// The response code of a response, if it has a complete header.
fn response_code(rsp: &[u8]) -> Option<u32> {
    header(rsp).map(|(_, rc)| rc)
}

/// Hex encoding of `bytes`, for diagnostics.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether `DIFFERENTIAL_LOG_EXCEPTIONS` asks for logs of the applied rules.
fn logging() -> bool {
    std::env::var_os(LOG_EXCEPTIONS_ENV).is_some()
}

/// The C reference TPM of this process and the test it serves.
pub struct Server<B: Backend> {
    /// Which reference implementation `backend` is.
    implementation: Implementation,
    /// The C reference TPM.
    backend: B,
    /// Name of the test, for diagnostics.
    test: String,
    /// Number of commands exchanged so far, for diagnostics.
    commands: usize,
    /// Number of commands re-issued under the `TPM_RC_RETRY` rule.
    retries: usize,
}

impl<B: Backend> Server<B> {
    /// Initializes the C reference TPM like a new `Tpm`: manufactured,
    /// powered on, NV on and `TPM2_Startup(TPM_SU_CLEAR)` done.
    pub fn new(
        implementation: Implementation,
        mut backend: B,
        test: String,
    ) -> Result<Self, String> {
        ACTIVE_STATE.with(|cell| *cell.borrow_mut() = Some(ActiveRefState::new()));
        backend.init();
        let startup_clear = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ];
        let startup_rsp = backend.run_command(0, &startup_clear);
        if response_code(&startup_rsp) != Some(0) {
            return Err(format!(
                "test `{test}`: initial {implementation} TPM2_Startup(CLEAR) failed: {}",
                hex(&startup_rsp)
            ));
        }
        Ok(Self {
            implementation,
            backend,
            test,
            commands: 0,
            retries: 0,
        })
    }

    /// Handles one protocol request.
    pub fn handle(&mut self, request: Request) -> Result<(), String> {
        match request {
            Request::Exchange {
                locality,
                command,
                expected,
            } => {
                let index = self.commands;
                self.commands += 1;
                self.exchange(index, locality, &command, &expected)
            }
            Request::AdvanceClock(ms) => {
                with_active_state(|st| st.virtual_ms += ms);
                self.backend.advance_clock(ms);
                Ok(())
            }
            Request::Signal(code) => match SimulatorPlatformSignal::try_from(code) {
                Ok(signal) => self.signal(signal),
                Err(()) => Err(format!("test `{}`: unknown signal {code}", self.test)),
            },
            Request::HashStart => {
                self.backend.hash_start();
                Ok(())
            }
            Request::HashData(data) => {
                self.backend.hash_data(&data);
                Ok(())
            }
            Request::HashEnd => {
                self.backend.hash_end();
                Ok(())
            }
        }
    }

    /// Delivers a platform signal to the C reference.
    fn signal(&mut self, signal: SimulatorPlatformSignal) -> Result<(), String> {
        use SimulatorPlatformSignal as S;
        match signal {
            S::PowerOn => self.backend.signal(Signal::PowerOn),
            S::PowerOff => self.backend.signal(Signal::PowerOff),
            S::Reset => self.backend.signal(Signal::Reset),
            S::NvOn => self.backend.signal(Signal::NvOn),
            S::NvOff => self.backend.signal(Signal::NvOff),
            S::PhysicalPresenceOn => self.backend.signal(Signal::PhysicalPresenceOn),
            S::PhysicalPresenceOff => self.backend.signal(Signal::PhysicalPresenceOff),
            S::CancelOn => self.backend.signal(Signal::CancelOn),
            S::CancelOff => self.backend.signal(Signal::CancelOff),
            // Transport-level signals that leave the TPM untouched.
            S::KeyCacheOn
            | S::KeyCacheOff
            | S::SessionEnd
            | S::Stop
            | S::GetCommandResponseSizes
            | S::ActGetSignaled => {}
            // `Restart` is not a TPM Reset (the C simulator maps it to a
            // clock restart, tpm-rs ignores it): fail loudly rather than
            // mis-map it.
            S::Restart | S::TestFailureMode | S::SetFirmwareHash | S::SetFirmwareSvn => {
                return Err(format!(
                    "test `{}`: signal {signal:?} is not supported by {}",
                    self.test, self.implementation
                ));
            }
        }
        Ok(())
    }

    /// Executes `command` (which `tpm-rs` answered with `expected`) on
    /// the C reference at `locality` and compares the responses.
    fn exchange(
        &mut self,
        index: usize,
        locality: u8,
        command: &[u8],
        expected: &[u8],
    ) -> Result<(), String> {
        let test = self.test.as_str();
        let implementation = self.implementation;
        let ref_command = with_active_state(|st| {
            st.prepare_for_command(command, expected);
            st.to_ref_command(command)
        })
        .unwrap_or_else(|| command.to_vec());
        let mut actual = self.backend.run_command(locality, &ref_command);
        // TPM_RC_RETRY rule: the C reference (upstream `CheckLockedOut`)
        // answers the first DA-protected authorization after a boot with
        // the TPM_RC_RETRY warning while it records `daUsed` in NV;
        // tpm-rs records it inline. Both are spec-compliant. Like a TSS,
        // re-issue the identical command once; its response is then
        // compared byte for byte (a second RETRY fails the comparison).
        if response_code(&actual) == Some(TPM_RC_RETRY)
            && response_code(expected) != Some(TPM_RC_RETRY)
        {
            self.retries += 1;
            if logging() {
                eprintln!(
                    "differential: test `{test}`, command {index}: {implementation} returned \
                     TPM_RC_RETRY; re-issuing once ({} retries so far)",
                    self.retries
                );
            }
            with_active_state(|st| st.prepare_for_command(command, expected));
            actual = self.backend.run_command(locality, &ref_command);
        }
        let resync = with_active_state(|st| {
            st.post_command(command, expected, &actual);
            let result = compare_differential_response(
                st,
                implementation,
                test,
                index,
                locality,
                command,
                expected,
                &actual,
            );
            track_exception_state(st, command, expected, &actual);
            match result {
                Ok(Some(Resync::MapHandle { rs, c })) => {
                    st.handle_map.retain(|&(r, h)| r != rs && h != c);
                    st.handle_map.push((rs, c));
                    Ok(None)
                }
                other => other,
            }
        })
        .unwrap_or_else(|| Err("differential state missing".into()))?;
        match resync {
            None => {}
            Some(Resync::MapHandle { .. }) => unreachable!("applied above"),
            Some(Resync::FlushRefObject(handle)) => {
                let mut flush = vec![0x80, 0x01, 0, 0, 0, 14, 0, 0, 0x01, 0x65];
                flush.extend_from_slice(&handle.to_be_bytes());
                let rsp = self.backend.run_command(locality, &flush);
                if response_code(&rsp) != Some(0) {
                    return Err(format!(
                        "test `{test}`, command {index}: resync TPM2_FlushContext \
                         ({handle:#010x}) on {implementation} failed: {}",
                        hex(&rsp)
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Command codes referenced by the documented exceptions.
mod cc {
    pub const PCR_RESET: u32 = 0x0000_013D;
    pub const INCREMENTAL_SELF_TEST: u32 = 0x0000_0142;
    pub const REWRAP: u32 = 0x0000_0152;
    pub const HMAC_START: u32 = 0x0000_015B;
    pub const NV_DEFINE_SPACE: u32 = 0x0000_012A;
    pub const NV_UNDEFINE_SPACE: u32 = 0x0000_0122;
    pub const NV_UNDEFINE_SPACE_SPECIAL: u32 = 0x0000_011F;
    pub const NV_WRITE: u32 = 0x0000_0137;
    pub const NV_READ: u32 = 0x0000_014E;
    pub const ECC_PARAMETERS: u32 = 0x0000_0178;
    pub const SEQUENCE_COMPLETE: u32 = 0x0000_013E;
    pub const STARTUP: u32 = 0x0000_0144;
    pub const FLUSH_CONTEXT: u32 = 0x0000_0165;
    pub const EVENT_SEQUENCE_COMPLETE: u32 = 0x0000_0185;
    pub const HASH_SEQUENCE_START: u32 = 0x0000_0186;
    pub const CONTEXT_LOAD: u32 = 0x0000_0161;
    pub const CONTEXT_SAVE: u32 = 0x0000_0162;
    pub const LOAD_EXTERNAL: u32 = 0x0000_0167;
    pub const GET_CAPABILITY: u32 = 0x0000_017A;
    pub const CREATE: u32 = 0x0000_0153;
    pub const CREATE_PRIMARY: u32 = 0x0000_0131;
    pub const CREATE_LOADED: u32 = 0x0000_0191;
    pub const SIGN: u32 = 0x0000_015D;
    pub const CERTIFY: u32 = 0x0000_0148;
    pub const CERTIFY_CREATION: u32 = 0x0000_014A;
    pub const CERTIFY_X509: u32 = 0x0000_0197;
    pub const QUOTE: u32 = 0x0000_0158;
    pub const GET_SESSION_AUDIT_DIGEST: u32 = 0x0000_014D;
    pub const GET_COMMAND_AUDIT_DIGEST: u32 = 0x0000_0133;
    pub const GET_TIME: u32 = 0x0000_014C;
    pub const NV_CERTIFY: u32 = 0x0000_0184;
    pub const DUPLICATE: u32 = 0x0000_014B;
    pub const MAKE_CREDENTIAL: u32 = 0x0000_0168;
    pub const ECDH_KEYGEN: u32 = 0x0000_0163;
    pub const RSA_ENCRYPT: u32 = 0x0000_0174;
    pub const START_AUTH_SESSION: u32 = 0x0000_0176;
}

/// `(command handles, response handles)` of every command code (TPM 2.0
/// Library Part 3), or `None` for an unknown command code.
pub fn handle_counts(code: u32) -> Option<(usize, usize)> {
    Some(match code {
        0x11F => (2, 0), // NV_UndefineSpaceSpecial
        0x120 => (2, 0), // EvictControl
        0x121 => (1, 0), // HierarchyControl
        0x122 => (2, 0), // NV_UndefineSpace
        0x124 => (1, 0), // ChangeEPS
        0x125 => (1, 0), // ChangePPS
        0x126 => (1, 0), // Clear
        0x127 => (1, 0), // ClearControl
        0x128 => (1, 0), // ClockSet
        0x129 => (1, 0), // HierarchyChangeAuth
        0x12A => (1, 0), // NV_DefineSpace
        0x12B => (1, 0), // PCR_Allocate
        0x12C => (1, 0), // PCR_SetAuthPolicy
        0x12D => (1, 0), // PP_Commands
        0x12E => (1, 0), // SetPrimaryPolicy
        0x12F => (2, 0), // FieldUpgradeStart
        0x130 => (1, 0), // ClockRateAdjust
        0x131 => (1, 1), // CreatePrimary
        0x132 => (1, 0), // NV_GlobalWriteLock
        0x133 => (2, 0), // GetCommandAuditDigest
        0x134 => (2, 0), // NV_Increment
        0x135 => (2, 0), // NV_SetBits
        0x136 => (2, 0), // NV_Extend
        0x137 => (2, 0), // NV_Write
        0x138 => (2, 0), // NV_WriteLock
        0x139 => (1, 0), // DictionaryAttackLockReset
        0x13A => (1, 0), // DictionaryAttackParameters
        0x13B => (1, 0), // NV_ChangeAuth
        0x13C => (1, 0), // PCR_Event
        0x13D => (1, 0), // PCR_Reset
        0x13E => (1, 0), // SequenceComplete
        0x13F => (1, 0), // SetAlgorithmSet
        0x140 => (1, 0), // SetCommandCodeAuditStatus
        0x141 => (0, 0), // FieldUpgradeData
        0x142 => (0, 0), // IncrementalSelfTest
        0x143 => (0, 0), // SelfTest
        0x144 => (0, 0), // Startup
        0x145 => (0, 0), // Shutdown
        0x146 => (0, 0), // StirRandom
        0x147 => (2, 0), // ActivateCredential
        0x148 => (2, 0), // Certify
        0x149 => (3, 0), // PolicyNV
        0x14A => (2, 0), // CertifyCreation
        0x14B => (2, 0), // Duplicate
        0x14C => (2, 0), // GetTime
        0x14D => (3, 0), // GetSessionAuditDigest
        0x14E => (2, 0), // NV_Read
        0x14F => (2, 0), // NV_ReadLock
        0x150 => (2, 0), // ObjectChangeAuth
        0x151 => (2, 0), // PolicySecret
        0x152 => (2, 0), // Rewrap
        0x153 => (1, 0), // Create
        0x154 => (1, 0), // ECDH_ZGen
        0x155 => (1, 0), // MAC
        0x156 => (1, 0), // Import
        0x157 => (1, 1), // Load
        0x158 => (1, 0), // Quote
        0x159 => (1, 0), // RSA_Decrypt
        0x15B => (1, 1), // MAC_Start
        0x15C => (1, 0), // SequenceUpdate
        0x15D => (1, 0), // Sign
        0x15E => (1, 0), // Unseal
        0x160 => (2, 0), // PolicySigned
        0x161 => (0, 1), // ContextLoad
        0x162 => (1, 0), // ContextSave
        0x163 => (1, 0), // ECDH_KeyGen
        0x164 => (1, 0), // EncryptDecrypt
        0x165 => (0, 0), // FlushContext
        0x167 => (0, 1), // LoadExternal
        0x168 => (1, 0), // MakeCredential
        0x169 => (1, 0), // NV_ReadPublic
        0x16A => (1, 0), // PolicyAuthorize
        0x16B => (1, 0), // PolicyAuthValue
        0x16C => (1, 0), // PolicyCommandCode
        0x16D => (1, 0), // PolicyCounterTimer
        0x16E => (1, 0), // PolicyCpHash
        0x16F => (1, 0), // PolicyLocality
        0x170 => (1, 0), // PolicyNameHash
        0x171 => (1, 0), // PolicyOR
        0x172 => (1, 0), // PolicyTicket
        0x173 => (1, 0), // ReadPublic
        0x174 => (1, 0), // RSA_Encrypt
        0x176 => (2, 1), // StartAuthSession
        0x177 => (1, 0), // VerifySignature
        0x178 => (0, 0), // ECC_Parameters
        0x179 => (0, 0), // FirmwareRead
        0x17A => (0, 0), // GetCapability
        0x17B => (0, 0), // GetRandom
        0x17C => (0, 0), // GetTestResult
        0x17D => (0, 0), // Hash
        0x17E => (0, 0), // PCR_Read
        0x17F => (1, 0), // PolicyPCR
        0x180 => (1, 0), // PolicyRestart
        0x181 => (0, 0), // ReadClock
        0x182 => (1, 0), // PCR_Extend
        0x183 => (1, 0), // PCR_SetAuthValue
        0x184 => (3, 0), // NV_Certify
        0x185 => (2, 0), // EventSequenceComplete
        0x186 => (0, 1), // HashSequenceStart
        0x187 => (1, 0), // PolicyPhysicalPresence
        0x188 => (1, 0), // PolicyDuplicationSelect
        0x189 => (1, 0), // PolicyGetDigest
        0x18A => (0, 0), // TestParms
        0x18B => (1, 0), // Commit
        0x18C => (1, 0), // PolicyPassword
        0x18D => (1, 0), // ZGen_2Phase
        0x18E => (0, 0), // EC_Ephemeral
        0x18F => (1, 0), // PolicyNvWritten
        0x190 => (1, 0), // PolicyTemplate
        0x191 => (1, 1), // CreateLoaded
        0x192 => (3, 0), // PolicyAuthorizeNV
        0x193 => (1, 0), // EncryptDecrypt2
        0x194 => (1, 0), // AC_GetCapability
        0x195 => (3, 0), // AC_Send
        0x196 => (1, 0), // Policy_AC_SendSelect
        0x197 => (2, 0), // CertifyX509
        0x198 => (1, 0), // ACT_SetTimeout
        0x199 => (1, 0), // ECC_Encrypt
        0x19A => (1, 0), // ECC_Decrypt
        0x19B => (1, 0), // PolicyCapability
        0x19C => (1, 0), // PolicyParameters
        0x19D => (1, 0), // NV_DefineSpace2
        0x19E => (1, 0), // NV_ReadPublic2
        0x19F => (1, 0), // SetCapability
        0x1A0 => (1, 0), // ReadOnlyControl
        0x1A1 => (1, 0), // PolicyTransportSPDM
        0x1A3 => (2, 0), // VerifySequenceComplete
        0x1A4 => (2, 0), // SignSequenceComplete
        0x1A5 => (1, 0), // VerifyDigestSignature
        0x1A6 => (1, 0), // SignDigest
        0x1A7 => (1, 0), // Encapsulate
        0x1A8 => (1, 0), // Decapsulate
        0x1A9 => (1, 1), // VerifySequenceStart
        0x1AA => (1, 1), // SignSequenceStart
        _ => return None,
    })
}

/// A cursor over marshaled TPM data.
#[derive(Clone, Copy)]
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    /// The next `n` bytes.
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    /// The next `TPM2B` in wire form (size field and buffer).
    fn tpm2b(&mut self) -> Option<&'a [u8]> {
        let size = be16(self.0, 0)? as usize;
        self.take(2 + size)
    }

    /// The buffer of the next `TPM2B`.
    fn tpm2b_body(&mut self) -> Option<&'a [u8]> {
        self.tpm2b().map(|b| &b[2..])
    }
}

/// The areas of a well-formed, successful response.
struct ResponseParts<'a> {
    /// The parameter area.
    params: &'a [u8],
    /// The authorization area (empty for a `TPM_ST_NO_SESSIONS` response).
    auth: &'a [u8],
}

/// Splits a successful response to command `code` into its areas;
/// `None` for an error response, an unknown command code or a malformed
/// envelope.
fn split_response(rsp: &[u8], code: u32) -> Option<ResponseParts<'_>> {
    let (tag, rc) = header(rsp)?;
    if rc != 0 || be32(rsp, 2)? as usize != rsp.len() {
        return None;
    }
    let at = 10 + 4 * handle_counts(code)?.1;
    match tag {
        0x8001 => Some(ResponseParts {
            params: rsp.get(at..)?,
            auth: &[],
        }),
        0x8002 => {
            let size = be32(rsp, at)? as usize;
            Some(ResponseParts {
                params: rsp.get(at + 4..at + 4 + size)?,
                auth: rsp.get(at + 4 + size..)?,
            })
        }
        _ => None,
    }
}

/// The `nonce` buffers of a response authorization area (a list of
/// `TPMS_AUTH_RESPONSE`), or `None` if it is malformed.
fn auth_response_nonces(auth: &[u8]) -> Option<Vec<&[u8]>> {
    let mut r = Reader(auth);
    let mut nonces = Vec::new();
    while !r.0.is_empty() {
        nonces.push(r.tpm2b_body()?);
        r.u8()?;
        r.tpm2b()?;
    }
    Some(nonces)
}

/// The `contextBlob` buffer of a `TPM2_ContextSave` parameter area (a
/// `TPMS_CONTEXT`: sequence, savedHandle, hierarchy, contextBlob).
fn context_blob(params: &[u8]) -> Option<&[u8]> {
    let mut r = Reader(params);
    r.take(16)?;
    let blob = r.tpm2b_body()?;
    r.0.is_empty().then_some(blob)
}

/// Splits a `TPM2_ECC_Parameters` parameter area
/// (`TPMS_ALGORITHM_DETAIL_ECC`) into its scalar head (`curveID`,
/// `keySize`, `kdf`, `sign`) and the buffers of `p`, `a`, `b`, `gX`, `gY`,
/// `n` and `h`.
fn ecc_parameters(params: &[u8]) -> Option<(&[u8], Vec<&[u8]>)> {
    const TPM_ALG_NULL: u16 = 0x0010;
    const TPM_ALG_ECDAA: u16 = 0x001A;
    let mut r = Reader(params);
    r.take(4)?;
    // TPMT_KDF_SCHEME: every scheme but NULL carries a hash algorithm.
    if r.u16()? != TPM_ALG_NULL {
        r.u16()?;
    }
    // TPMT_ECC_SCHEME: a hash algorithm, plus `count` for ECDAA.
    match r.u16()? {
        TPM_ALG_NULL => {}
        TPM_ALG_ECDAA => {
            r.take(4)?;
        }
        _ => {
            r.u16()?;
        }
    }
    let head = &params[..params.len() - r.0.len()];
    let fields = (0..7).map(|_| r.tpm2b_body()).collect::<Option<Vec<_>>>()?;
    r.0.is_empty().then_some((head, fields))
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// `(tag, code)` of a command or response header (`code` is the command
/// code or the response code).
fn header(b: &[u8]) -> Option<(u16, u32)> {
    Some((be16(b, 0)?, be32(b, 6)?))
}

/// Splits a command into its `n_handles` handles and its parameter area
/// (skipping the authorization area of a `TPM_ST_SESSIONS` command).
fn command_parts(cmd: &[u8], n_handles: usize) -> Option<(Vec<u32>, &[u8])> {
    let (tag, _) = header(cmd)?;
    let mut at = 10;
    let mut handles = Vec::with_capacity(n_handles);
    for _ in 0..n_handles {
        handles.push(be32(cmd, at)?);
        at += 4;
    }
    if tag == 0x8002 {
        at += 4 + be32(cmd, at)? as usize;
    }
    Some((handles, cmd.get(at..)?))
}

/// The offset and contents of the parameter area of a successful response
/// with `n_handles` handles (without the trailing authorization area).
fn response_params_at(rsp: &[u8], n_handles: usize) -> Option<(usize, &[u8])> {
    let (tag, _) = header(rsp)?;
    let at = 10 + 4 * n_handles;
    if tag == 0x8002 {
        let size = be32(rsp, at)? as usize;
        Some((at + 4, rsp.get(at + 4..at + 4 + size)?))
    } else {
        Some((at, rsp.get(at..)?))
    }
}

/// The parameter area of a successful response with `n_handles` handles
/// (without the trailing authorization area).
fn response_params(rsp: &[u8], n_handles: usize) -> Option<&[u8]> {
    response_params_at(rsp, n_handles).map(|(_, p)| p)
}

/// Parses a `TPMS_CAPABILITY_DATA` list of a `TPM2_GetCapability`
/// response: `(moreData, capability, entries)`, each entry being its raw
/// bytes. `None` for capabilities without a known entry layout or trailing
/// bytes.
fn capability_list(rsp: &[u8]) -> Option<(u8, u32, Vec<&[u8]>)> {
    let p = response_params(rsp, 0)?;
    let more = *p.first()?;
    let cap = be32(p, 1)?;
    let count = be32(p, 5)? as usize;
    let mut at = 9;
    let mut entries = Vec::new();
    for _ in 0..count {
        let len = match cap {
            // TPM_CAP_ALGS: TPMS_ALG_PROPERTY.
            0 => 6,
            // TPM_CAP_HANDLES, TPM_CAP_COMMANDS, TPM_CAP_PP_COMMANDS,
            // TPM_CAP_AUDIT_COMMANDS: 32-bit values.
            1..=4 => 4,
            // TPM_CAP_PCRS: TPMS_PCR_SELECTION.
            5 => 3 + *p.get(at + 2)? as usize,
            // TPM_CAP_TPM_PROPERTIES: TPMS_TAGGED_PROPERTY.
            6 => 8,
            // TPM_CAP_PCR_PROPERTIES: TPMS_TAGGED_PCR_SELECT.
            7 => 5 + *p.get(at + 4)? as usize,
            // TPM_CAP_ECC_CURVES: TPM_ECC_CURVE.
            8 => 2,
            // TPM_CAP_AUTH_POLICIES: TPMS_TAGGED_POLICY (handle + TPMT_HA).
            9 => {
                6 + match be16(p, at + 4)? {
                    0x0004 => 20,
                    0x000B => 32,
                    0x000C => 48,
                    0x000D => 64,
                    0x0010 => 0,
                    _ => return None,
                }
            }
            _ => return None,
        };
        entries.push(p.get(at..at + len)?);
        at += len;
    }
    (at == p.len()).then_some((more, cap, entries))
}

/// Exception 2 (`TPM2_GetCapability`): the capability lists may differ
/// only by the documented implementation-specific entries; every other
/// entry, the entry order, `moreData` and the selector must be identical.
fn capability_difference_is_documented(command: &[u8], expected: &[u8], actual: &[u8]) -> bool {
    let Some((_, params)) = command_parts(command, 0) else {
        return false;
    };
    let (Some(requested_property), Some(requested_count)) = (be32(params, 4), be32(params, 8))
    else {
        return false;
    };
    let (Some((e_more, e_cap, e)), Some((a_more, a_cap, a))) =
        (capability_list(expected), capability_list(actual))
    else {
        return false;
    };
    if e_cap != a_cap {
        return false;
    }
    let keep = |list: &[&[u8]], drop: &dyn Fn(&[u8]) -> bool| -> Vec<Vec<u8>> {
        list.iter()
            .filter(|x| !drop(x))
            .map(|x| x.to_vec())
            .collect()
    };
    let none = |_: &[u8]| false;
    match e_cap {
        // TPM_CAP_HANDLES: the C reference implements the firmware-limited
        // and SVN-limited hierarchies (TPM_RH_FW_OWNER..TPM_RH_FW_NULL =
        // 0x40000140..=0x40000143, TPM_RH_SVN_*_BASE = 0x4001xxxx..0x4004xxxx,
        // TPM 2.0 Library spec 1.83+), which tpm-rs does not.
        1 => {
            let fw_or_svn = |x: &[u8]| {
                be32(x, 0).is_some_and(|h| {
                    (0x4000_0140..=0x4000_0143).contains(&h)
                        || (0x4001_0000..=0x4004_FFFF).contains(&h)
                })
            };
            e_more == a_more && keep(&e, &none) == keep(&a, &fw_or_svn)
        }
        // TPM_CAP_PCRS: tpm-rs additionally lists the SM3_256 (0x12) and
        // SHA3_256/384/512 (0x27..0x29) banks with no PCR allocated.
        5 => {
            let empty_extra_bank = |x: &[u8]| {
                matches!(be16(x, 0), Some(0x0012 | 0x0027..=0x0029))
                    && x[3..].iter().all(|&b| b == 0)
            };
            e_more == a_more && keep(&e, &empty_extra_bank) == keep(&a, &none)
        }
        // TPM_CAP_TPM_PROPERTIES: values of implementation-specific
        // properties may differ; C additionally reports
        // TPM_PT_FIRMWARE_SVN/TPM_PT_FIRMWARE_MAX_SVN (0x12F/0x130, spec
        // 1.83+); C never crosses from the PT_FIXED into the PT_VAR group in
        // one response (PropertyCap.c `TPMCapGetProperties`), so tpm-rs may
        // additionally report PT_VAR (>= 0x200) properties when the query
        // started in PT_FIXED. All other properties must match exactly.
        6 => {
            const IMPLEMENTATION_SPECIFIC: &[u32] = &[
                0x10E, // TPM_PT_HR_TRANSIENT_MIN (tpm-rs 3, C 16)
                0x10F, // TPM_PT_HR_PERSISTENT_MIN
                0x116, // TPM_PT_NV_COUNTERS_MAX
                0x118, // TPM_PT_MEMORY
                0x119, // TPM_PT_CLOCK_UPDATE
                0x11C, // TPM_PT_CONTEXT_SYM_SIZE
                0x11E, // TPM_PT_MAX_COMMAND_SIZE
                0x11F, // TPM_PT_MAX_RESPONSE_SIZE
                0x121, // TPM_PT_MAX_OBJECT_CONTEXT
                0x122, // TPM_PT_MAX_SESSION_CONTEXT
                0x12D, // TPM_PT_MODES (vendor certification modes)
            ];
            let prop = |x: &[u8]| be32(x, 0).unwrap_or(0);
            let rs_only = |x: &[u8]| requested_property < 0x200 && prop(x) >= 0x200;
            let ref_only = |x: &[u8]| matches!(prop(x), 0x12F | 0x130);
            let mask = |list: Vec<Vec<u8>>| -> Vec<Vec<u8>> {
                list.into_iter()
                    .map(|mut x| {
                        if IMPLEMENTATION_SPECIFIC.contains(&prop(&x)) {
                            x[4..].fill(0);
                        }
                        x
                    })
                    .collect()
            };
            e_more == a_more && mask(keep(&e, &rs_only)) == mask(keep(&a, &ref_only))
        }
        // TPM_CAP_AUTH_POLICIES: identical entries; C reports
        // moreData = YES when the list is full because its firmware/SVN
        // hierarchy handles (TPM_RH_FW_*/TPM_RH_SVN_*, spec 1.83+, not
        // implemented by tpm-rs) follow.
        9 => {
            keep(&e, &none) == keep(&a, &none)
                && e_more == 0
                && a_more == 1
                && a.len() as u32 == requested_count
        }
        _ => false,
    }
}

/// Exception 5 (`TPM2_NV_Read`): bytes of an NV index that were never
/// written since the index was defined read as `0x00` in tpm-rs and as
/// `0xFF` in C (flash-erased backing store). Only those bytes may differ;
/// every written byte and the rest of the response must match.
fn nv_read_difference_is_documented(
    st: &ActiveRefState,
    command: &[u8],
    expected: &[u8],
    actual: &[u8],
) -> bool {
    let Some((handles, params)) = command_parts(command, 2) else {
        return false;
    };
    let (Some(size), Some(offset)) = (be16(params, 0), be16(params, 2)) else {
        return false;
    };
    let (Some((start, e)), Some((a_start, a))) = (
        response_params_at(expected, 0),
        response_params_at(actual, 0),
    ) else {
        return false;
    };
    // Everything outside `data.buffer` (header, data size, authorization
    // area) must be identical.
    let data_end = start + 2 + size as usize;
    if expected.len() != actual.len()
        || start != a_start
        || be16(e, 0) != Some(size)
        || be16(a, 0) != Some(size)
        || expected[..start + 2] != actual[..start + 2]
        || expected.get(data_end..) != actual.get(data_end..)
    {
        return false;
    }
    let written = st.nv_written.get(&handles[1]);
    e[2..2 + size as usize]
        .iter()
        .zip(&a[2..2 + size as usize])
        .enumerate()
        .all(|(i, (&eb, &ab))| {
            let unwritten = !written.is_some_and(|w| w.contains(&(offset as usize + i)));
            eb == ab || (unwritten && eb == 0x00 && ab == 0xFF)
        })
}

/// Records state used by the narrowly-scoped exceptions after a command
/// has run on both implementations.
fn track_exception_state(st: &mut ActiveRefState, command: &[u8], expected: &[u8], actual: &[u8]) {
    let (Some((_, code)), Some((_, exp_rc)), Some((_, act_rc))) =
        (header(command), header(expected), header(actual))
    else {
        return;
    };
    // A new object that got the same handle in both implementations ends
    // any stale translation involving that handle.
    if exp_rc == 0
        && act_rc == 0
        && handle_counts(code).is_some_and(|(_, n)| n >= 1)
        && let (Some(rs), Some(c)) = (be32(expected, 10), be32(actual, 10))
        && rs == c
    {
        st.handle_map.retain(|&(r, h)| r != rs && h != c);
    }
    match code {
        cc::NV_WRITE if exp_rc == 0 && act_rc == 0 => {
            if let Some((handles, params)) = command_parts(command, 2)
                && let Some(len) = be16(params, 0)
                && let Some(offset) = be16(params, 2 + len as usize)
            {
                st.nv_written
                    .entry(handles[1])
                    .or_default()
                    .extend(offset as usize..offset as usize + len as usize);
            }
        }
        cc::NV_DEFINE_SPACE if exp_rc == 0 => {
            // TPM2B_NV_PUBLIC after auth (TPM2B_AUTH): nvIndex is first.
            if let Some((_, params)) = command_parts(command, 1)
                && let Some(auth_len) = be16(params, 0)
                && let Some(index) = be32(params, 2 + auth_len as usize + 2)
            {
                st.nv_written.remove(&index);
            }
        }
        cc::NV_UNDEFINE_SPACE | cc::NV_UNDEFINE_SPACE_SPECIAL if exp_rc == 0 => {
            let index_pos = if code == cc::NV_UNDEFINE_SPACE { 1 } else { 0 };
            if let Some((handles, _)) = command_parts(command, 2) {
                st.nv_written.remove(&handles[index_pos]);
            }
        }
        cc::HASH_SEQUENCE_START | cc::HMAC_START if exp_rc == 0 => {
            if let Some(handle) = be32(expected, 10) {
                st.rs_sequences.push(handle);
            }
        }
        cc::SEQUENCE_COMPLETE | cc::EVENT_SEQUENCE_COMPLETE | cc::FLUSH_CONTEXT if exp_rc == 0 => {
            let handle = match code {
                cc::SEQUENCE_COMPLETE => be32(command, 10),
                cc::EVENT_SEQUENCE_COMPLETE => be32(command, 14),
                _ => command_parts(command, 0).and_then(|(_, p)| be32(p, 0)),
            };
            st.rs_sequences.retain(|&h| Some(h) != handle);
            if code == cc::FLUSH_CONTEXT {
                st.handle_map.retain(|&(r, _)| Some(r) != handle);
            }
        }
        cc::STARTUP if exp_rc == 0 => {
            st.rs_sequences.clear();
            st.handle_map.clear();
        }
        _ => {}
    }
}

/// With `DIFFERENTIAL_LOG_EXCEPTIONS` set, logs every applied documented exception
/// (one `DIFFEXC` line with the command and both responses in base64), so
/// the exceptions' hit counts can be audited.
fn log_exception(
    test: &str,
    index: usize,
    code: u32,
    command: &[u8],
    expected: &[u8],
    actual: &[u8],
) {
    if logging() {
        eprintln!(
            "DIFFEXC test={test} command={index} cc={code:#010x} cmd={} rs={} ref={}",
            hex(command),
            hex(expected),
            hex(actual),
        );
    }
}

/// A C-side state correction the harness must apply after a documented
/// divergence that left C with state tpm-rs does not have.
#[derive(Debug)]
enum Resync {
    /// `TPM2_FlushContext` the given C object, which only C created.
    FlushRefObject(u32),
    /// Record that tpm-rs transient handle `rs` is C handle `c`.
    MapHandle { rs: u32, c: u32 },
}

/// Compares the C reference response (`actual`) with the recorded tpm-rs
/// response (`expected`): they must be byte-identical, except for the
/// narrowly-scoped, documented divergences below (each also listed in
/// `differential.md`). Every exception requires the same command code and
/// checks every response field it does not explicitly exempt.
#[allow(clippy::too_many_arguments)]
fn compare_differential_response(
    st: &ActiveRefState,
    implementation: Implementation,
    test: &str,
    index: usize,
    locality: u8,
    command: &[u8],
    expected: &[u8],
    actual: &[u8],
) -> Result<Option<Resync>, String> {
    if expected == actual {
        return Ok(None);
    }
    let code = header(command).map(|(_, c)| c).unwrap_or(0);
    let exp_rc = header(expected).map(|(_, rc)| rc);
    let act_rc = header(actual).map(|(_, rc)| rc);
    let same_tag = header(expected).map(|(t, _)| t) == header(actual).map(|(t, _)| t);

    // 11. Transient handle allocation: C loads a persistent object into a
    //     temporary transient slot for the duration of a command, so an
    //     object created by a command that references a persistent handle
    //     gets a different (implementation-defined) handle; afterwards the
    //     two implementations' slot assignments may stay shifted. Accepted
    //     only if the returned handle is the sole difference, both handles
    //     are transient, and the command references a persistent handle or
    //     a shift is already being tracked. The pair is then recorded and
    //     later commands are translated (`ActiveRefState::to_ref_command`).
    if exp_rc == Some(0)
        && act_rc == Some(0)
        && expected.len() == actual.len()
        && handle_counts(code).is_some_and(|(_, n)| n >= 1)
        && let (Some(rs), Some(c)) = (be32(expected, 10), be32(actual, 10))
        && rs != c
        && rs >> 24 == 0x80
        && c >> 24 == 0x80
        && expected[..10] == actual[..10]
        && expected[14..] == actual[14..]
    {
        let references_persistent = handle_counts(code)
            .and_then(|(n, _)| command_parts(command, n))
            .is_some_and(|(handles, _)| handles.iter().any(|h| h >> 24 == 0x81));
        if references_persistent || !st.handle_map.is_empty() {
            log_exception(test, index, code, command, expected, actual);
            return Ok(Some(Resync::MapHandle { rs, c }));
        }
    }

    let documented = match (code, exp_rc, act_rc) {
        // 1. TPM2_ContextSave: the `contextBlob` (encrypted OBJECT/SESSION
        //    image) is implementation-defined; `sequence`, `savedHandle` and
        //    `hierarchy` must match, and the blob is checked indirectly: a
        //    later TPM2_ContextLoad of it must behave identically.
        (cc::CONTEXT_SAVE, Some(0), Some(0)) => {
            same_tag
                && match (split_response(expected, code), split_response(actual, code)) {
                    (Some(e), Some(a)) => {
                        context_blob(e.params).is_some()
                            && context_blob(a.params).is_some()
                            && e.params[..16] == a.params[..16]
                            && e.auth == a.auth
                    }
                    _ => false,
                }
        }
        // 2. TPM2_GetCapability: see `capability_difference_is_documented`.
        (cc::GET_CAPABILITY, Some(0), Some(0)) => {
            header(expected).is_some_and(|(tag, _)| tag == 0x8001)
                && same_tag
                && capability_difference_is_documented(command, expected, actual)
        }
        // 3. TPM2_ECC_Parameters: tpm-rs pads every curve parameter to the
        //    curve's byte width; C's `CryptEccData.c` constants omit leading
        //    zero bytes (e.g. `a = 0` on BN_P256, `b` on NIST_P521). All
        //    fields must match up to leading zero bytes.
        (cc::ECC_PARAMETERS, Some(0), Some(0)) => {
            fn trim_zeros(mut s: &[u8]) -> &[u8] {
                while let Some((&0, rest)) = s.split_first() {
                    s = rest;
                }
                s
            }
            same_tag
                && match (split_response(expected, code), split_response(actual, code)) {
                    (Some(e), Some(a)) => {
                        e.auth == a.auth
                            && match (ecc_parameters(e.params), ecc_parameters(a.params)) {
                                (Some((e_head, e_fields)), Some((a_head, a_fields))) => {
                                    e_head == a_head
                                        && e_fields
                                            .iter()
                                            .zip(&a_fields)
                                            .all(|(e, a)| trim_zeros(e) == trim_zeros(a))
                                }
                                _ => false,
                            }
                    }
                    _ => false,
                }
        }
        // 4. TPM2_IncrementalSelfTest: `toDoList` is TPM-dependent (Part 3
        //    §10.3: the list of algorithms that still need testing); the C
        //    reference is built with ENABLE_SELF_TESTS = NO and a different
        //    algorithm set, so the lists differ in content and order. Both
        //    must be well-formed TPML_ALG responses with identical headers
        //    and no other content.
        (cc::INCREMENTAL_SELF_TEST, Some(0), Some(0)) => {
            let well_formed = |r: &[u8]| {
                header(r).is_some_and(|(tag, _)| tag == 0x8001)
                    && response_params(r, 0)
                        .is_some_and(|p| be32(p, 0).is_some_and(|n| p.len() == 4 + 2 * n as usize))
            };
            well_formed(expected) && well_formed(actual)
        }
        // 5. TPM2_NV_Read: see `nv_read_difference_is_documented`.
        (cc::NV_READ, Some(0), Some(0)) => {
            same_tag && nv_read_difference_is_documented(st, command, expected, actual)
        }
        // 6. TPM2_LoadExternal of a public-only RSA-3072 key: the C profile
        //    has RSA_3072 = NO (TPM_RC_VALUE + P2), tpm-rs supports it.
        (cc::LOAD_EXTERNAL, Some(0), Some(0x2C4)) => {
            command_parts(command, 0).is_some_and(|(_, p)| {
                // Empty inPrivate, then TPM2B_PUBLIC: size, type (RSA),
                // nameAlg, objectAttributes, authPolicy, then
                // TPMS_RSA_PARMS symmetric, scheme and keyBits (3072).
                be16(p, 0) == Some(0)
                    && be16(p, 4) == Some(0x0001)
                    && be16(p, 12).and_then(|policy| {
                        let mut at = 14 + policy as usize;
                        at += if be16(p, at)? == 0x0010 { 2 } else { 6 };
                        at += if matches!(be16(p, at)?, 0x0010 | 0x0015) {
                            2
                        } else {
                            4
                        };
                        be16(p, at)
                    }) == Some(3072)
            })
        }
        // 7. TPM2_Rewrap with an `inDuplicate` larger than C's
        //    TPM2B_PRIVATE buffer (sized for 2048-bit RSA keys): C rejects
        //    its size during unmarshaling (TPM_RC_SIZE + P1), tpm-rs
        //    (TPM2_MAX_PRIVATE_SIZE = 1618) unmarshals it and rejects the
        //    malformed content (TPM_RC_VALUE + P1).
        (cc::REWRAP, Some(0x1C4), Some(0x1D5)) => command_parts(command, 2)
            .and_then(|(_, p)| be16(p, 0))
            .is_some_and(|size| size > 1350 && size <= 1618),
        // 8. TPM2_PCR_Reset of PCR 16 at a reserved locality (5..=31):
        //    tpm-rs rejects the locality (TPM_RC_LOCALITY); the C
        //    simulator's platform layer (`_plat__LocalitySet`) silently
        //    maps localities 5..=31 to locality 0, at which PCR 16 may be
        //    reset (TPM_RC_SUCCESS).
        (cc::PCR_RESET, Some(0x907), Some(0)) => {
            (5..=31).contains(&locality)
                && command_parts(command, 1).is_some_and(|(h, _)| h[0] == 16)
        }
        // 9. TPM2_ContextLoad of a `contextBlob` that is not byte-identical
        //    to one tpm-rs returned (truncated or modified by the test): the
        //    blob layout is implementation-defined, so both must reject it
        //    as a malformed blob, but whether the size or the integrity
        //    check fires first depends on the layout (TPM_RC_SIZE + P1 vs
        //    TPM_RC_INTEGRITY + P1).
        (cc::CONTEXT_LOAD, Some(e @ (0x1D5 | 0x1DF)), Some(a @ (0x1D5 | 0x1DF))) => {
            e != a
                && command_parts(command, 0).is_some_and(|(_, p)| {
                    // TPMS_CONTEXT: sequence (8), savedHandle (4),
                    // hierarchy (4), contextBlob (TPM2B).
                    be16(p, 16).is_some_and(|len| {
                        p.get(18..18 + len as usize).is_some_and(|blob| {
                            !st.context_blobs.iter().any(|(rs, _)| rs.as_slice() == blob)
                        })
                    })
                })
        }
        // 10. TPM2_HashSequenceStart / TPM2_HMAC_Start while tpm-rs already
        //     holds its maximum of 3 sequence objects: tpm-rs reports
        //     TPM_RC_OBJECT_MEMORY, while C allocates sequences from its 16
        //     shared object slots and succeeds. The sequence then exists in
        //     C only; the harness flushes it from C (see `Resync`) so both
        //     TPMs hold the same objects afterwards.
        (cc::HASH_SEQUENCE_START | cc::HMAC_START, Some(0x902), Some(0))
            if st.rs_sequences.len() >= 3 =>
        {
            log_exception(test, index, code, command, expected, actual);
            return match be32(actual, 10) {
                Some(handle) => Ok(Some(Resync::FlushRefObject(handle))),
                None => Err(format!(
                    "test `{test}`, command {index}: no C sequence handle"
                )),
            };
        }
        _ => false,
    };
    if documented {
        log_exception(test, index, code, command, expected, actual);
        return Ok(None);
    }

    Err(format!(
        "differential mismatch with {implementation} in test `{test}`, command {index} \
         (cc={code:#010x}, locality {locality}):\n\
         command:              {}\n\
         tpm-rs    (rc={exp_rc:#x?}): {}\n\
         {implementation:<9} (rc={act_rc:#x?}): {}",
        hex(command),
        hex(expected),
        hex(actual),
    ))
}
