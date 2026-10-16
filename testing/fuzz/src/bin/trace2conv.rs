//! Converts the command/response traces that `testing::tpm::Tpm` records with
//! `TPM_FUZZ_RECORD_DIR` into seed inputs of the `diff_conversation` fuzz
//! target.
//!
//! Each trace is split into conversations (see `shared/trace.rs`), truncated
//! to [`MAX_ROUNDS`]. Every command becomes a structured [`Step::Cmd`] whose
//! operands refer to earlier responses wherever the recorded bytes equal what
//! the driver's value pool holds at that round:
//!
//! - a command handle that equals a response handle or a defined NV index of
//!   an earlier round becomes [`HandleOperand::Response`]/[`HandleOperand::Nv`]
//!   (permanent handles, PCRs and unknown handles stay literal);
//! - a parameter byte range that equals an extracted response field (a name,
//!   public area, private blob, nonce, context, ticket, ...) becomes a
//!   [`Segment::Value`]; the rest stays [`Segment::Bytes`];
//! - password sessions become [`SessionSel::Password`] and every other
//!   session a literal [`SessionSel::Raw`] (its HMAC stays valid because the
//!   replay is deterministic under the fixed seed).
//!
//! So a fuzzer mutation of an early round (e.g. a different key template)
//! flows into the later rounds that use its outputs. Each converted command is
//! rebuilt with the driver's builder and must equal the recorded bytes;
//! otherwise (e.g. a deliberately wrong `commandSize`) the round stays a
//! literal [`Step::Raw`]. The value pool is fed exactly like the driver feeds
//! it, so references resolve to the same bytes during fuzzing.
//!
//! With `--verify`, every converted conversation is replayed through the
//! driver on `Tpm::with_seed(FIXED_SEED)` (the traces must be recorded with
//! `TPM_REFERENCE_SEED=4242:1000000`) and must reproduce the recorded
//! commands and responses; conversations are cut before their first
//! mismatching round. This needs the reference binaries (`MSTPM20_BIN`,
//! `IBMSWTPM2_BIN`), because the fuzz crate's `Tpm` is differential.
//!
//! With `--ecc-variants` (needs `--verify`), every conversation with an RSA
//! key template (`TPM2_CreatePrimary`/`Create`/`CreateLoaded`) also yields
//! variants that make the fuzzer cheaper, because RSA key generation
//! dominates the cost of a round: one with every RSA template rewritten into
//! an ECC NIST P-256 template (same attributes, symmetric algorithm and
//! signing hash; `-ecc` suffix), and, if a template asks for more than 2048
//! bits, one with `keyBits` capped at 2048 (`-rsa2048` suffix). A variant's
//! responses differ from the recording, so it is replayed and cut before the
//! first round whose response code differs from the recorded one, and
//! dropped if that leaves no rewritten round; `cargo fuzz cmin` then keeps
//! whichever inputs add coverage.
//!
//! Usage:
//!
//! ```sh
//! cargo run --release --manifest-path testing/fuzz/Cargo.toml --bin trace2conv -- \
//!     [--verify [--ecc-variants]] <output dir> <trace file or dir>...
//! ```
#![forbid(unsafe_code)]

// `to_test` uses the rest of the replay details.
#[allow(dead_code)]
#[path = "shared/replay.rs"]
mod replay;
#[path = "shared/trace.rs"]
mod trace;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use testing::tpm::Tpm;
use tpm2_fuzz::builder::build;
use tpm2_fuzz::driver::FIXED_SEED;
use tpm2_fuzz::model::{
    AuthSel, Cmd, Conversation, FieldKind, HandleOperand, MAX_ROUNDS, MAX_SEGMENTS, MAX_SESSIONS,
    Segment, SessionSel, Step, TPM_ST_NO_SESSIONS, TPM_ST_SESSIONS, TagSel, ValueRef,
};
use tpm2_fuzz::pool::ValuePool;
use tpm2_fuzz::wire::{Reader, parse_command};

use crate::trace::Round;

/// `TPM_RS_PW`.
const TPM_RS_PW: u32 = 0x4000_0009;
/// `TPMA_SESSION_CONTINUESESSION`, the attributes the driver's password
/// sessions carry.
const ATTR_CONTINUE: u8 = 0x01;
/// The minimum length of a non-handle value spliced as a reference: shorter
/// matches (e.g. an empty TPM2B) are too likely to be coincidences.
const MIN_VALUE_LEN: usize = 6;

/// Whether `handle` is one the conversation cannot have produced: a
/// permanent handle (`0x40xxxxxx`) or a PCR (`0x00xxxxxx`).
fn is_fixed_handle(handle: u32) -> bool {
    matches!(handle >> 24, 0x00 | 0x40)
}

/// The operand for command handle `handle`: the first response handle or NV
/// index operand of the pool that resolves to it, else the literal.
fn convert_handle(handle: u32, pool: &ValuePool) -> HandleOperand {
    if is_fixed_handle(handle) {
        return HandleOperand::Raw(handle);
    }
    pool.handle_candidates(&[])
        .into_iter()
        .find(|(op, h)| *h == handle && !matches!(op, HandleOperand::Session { .. }))
        .map_or(HandleOperand::Raw(handle), |(op, _)| op)
}

/// One `TPMS_AUTH_COMMAND` parsed from an authorization area.
struct AuthCommand<'a> {
    /// The session handle.
    handle: u32,
    /// `nonceCaller` (TPM2B body).
    nonce: &'a [u8],
    /// `sessionAttributes`.
    attrs: u8,
    /// `hmac` (TPM2B body).
    hmac: &'a [u8],
    /// The whole wire form.
    raw: &'a [u8],
}

/// Splits an authorization area into its sessions; `None` if it does not
/// parse exactly.
fn split_auth_area(area: &[u8]) -> Option<Vec<AuthCommand<'_>>> {
    let mut out = Vec::new();
    let mut r = Reader(area);
    while !r.rest().is_empty() {
        let start = r.rest();
        let handle = r.u32()?;
        let nonce = r.tpm2b_body()?;
        let attrs = r.u8()?;
        let hmac = r.tpm2b_body()?;
        let raw = &start[..start.len() - r.rest().len()];
        out.push(AuthCommand {
            handle,
            nonce,
            attrs,
            hmac,
            raw,
        });
    }
    Some(out)
}

/// The sessions of an authorization area (at most [`MAX_SESSIONS`]; the
/// tail is merged into the last one as raw bytes), and the authorization
/// area the driver builds from them.
fn convert_sessions(area: &[u8]) -> Vec<SessionSel> {
    let Some(sessions) = split_auth_area(area).filter(|s| s.len() <= MAX_SESSIONS) else {
        return if area.is_empty() {
            Vec::new()
        } else {
            vec![SessionSel::Raw(area.to_vec())]
        };
    };
    sessions
        .iter()
        .map(|s| {
            if s.handle == TPM_RS_PW && s.nonce.is_empty() && s.attrs == ATTR_CONTINUE {
                SessionSel::Password {
                    auth: if s.hmac.is_empty() {
                        AuthSel::Empty
                    } else {
                        AuthSel::Bytes(s.hmac.to_vec())
                    },
                }
            } else {
                SessionSel::Raw(s.raw.to_vec())
            }
        })
        .collect()
}

/// The authorization area the session engine builds for `sessions` (which
/// hold only password and raw sessions).
fn auth_area_of(sessions: &[SessionSel]) -> Vec<u8> {
    let mut out = Vec::new();
    for s in sessions {
        match s {
            SessionSel::Password { auth } => {
                let auth: &[u8] = match auth {
                    AuthSel::Bytes(b) => b,
                    _ => &[],
                };
                out.extend_from_slice(&TPM_RS_PW.to_be_bytes());
                out.extend_from_slice(&[0, 0, ATTR_CONTINUE]);
                out.extend_from_slice(&(auth.len() as u16).to_be_bytes());
                out.extend_from_slice(auth);
            }
            SessionSel::Raw(bytes) => out.extend_from_slice(bytes),
            // The converter emits only password and raw sessions.
            SessionSel::Hmac { .. } | SessionSel::Policy { .. } => {}
        }
    }
    out
}

/// How much a match of `kind` is preferred among equally long matches:
/// typed fields before generic TPM2Bs before raw parameter areas.
fn kind_rank(kind: FieldKind) -> u8 {
    match kind {
        FieldKind::Bytes => 2,
        FieldKind::Tpm2b => 1,
        _ => 0,
    }
}

/// Splits a parameter area into literal bytes and references to pool values
/// (greedy, longest match first; see the module docs). At most
/// [`MAX_SEGMENTS`] segments are produced: once the limit is near, the rest
/// stays literal.
fn convert_params(params: &[u8], pool: &ValuePool) -> Vec<Segment> {
    let mut candidates: Vec<(ValueRef, Vec<u8>)> = pool
        .candidates()
        .into_iter()
        .filter(|(r, v)| match r.kind {
            FieldKind::Handle => {
                v.len() == 4 && !is_fixed_handle(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
            }
            _ => v.len() >= MIN_VALUE_LEN,
        })
        .collect();
    candidates.sort_by_key(|(r, v)| (std::cmp::Reverse(v.len()), kind_rank(r.kind), r.back));
    let mut segments = Vec::new();
    let mut literal = Vec::new();
    let mut i = 0;
    while i < params.len() {
        let found = (segments.len() + 2 < MAX_SEGMENTS)
            .then(|| candidates.iter().find(|(_, v)| params[i..].starts_with(v)))
            .flatten();
        match found {
            Some((r, v)) => {
                if !literal.is_empty() {
                    segments.push(Segment::Bytes(std::mem::take(&mut literal)));
                }
                segments.push(Segment::Value(*r));
                i += v.len();
            }
            None => {
                literal.push(params[i]);
                i += 1;
            }
        }
    }
    if !literal.is_empty() {
        segments.push(Segment::Bytes(literal));
    }
    segments
}

/// Converts one recorded command into a step, given the pool state before
/// the round. Falls back to [`Step::Raw`] if the structured step does not
/// rebuild the exact recorded bytes.
fn convert_command(command: &[u8], pool: &ValuePool) -> Step {
    let Some(view) = parse_command(command) else {
        return Step::Raw(command.to_vec());
    };
    let mut cmd = Cmd::new(view.code);
    cmd.handles = view
        .handles
        .iter()
        .map(|&h| convert_handle(h, pool))
        .collect();
    cmd.sessions = convert_sessions(view.auth);
    cmd.tag = match (view.tag, cmd.sessions.is_empty()) {
        (TPM_ST_SESSIONS, false) | (TPM_ST_NO_SESSIONS, true) => TagSel::Auto,
        (TPM_ST_SESSIONS, true) => TagSel::Sessions,
        (TPM_ST_NO_SESSIONS, false) => TagSel::NoSessions,
        (tag, _) => TagSel::Raw(tag),
    };
    cmd.params = convert_params(view.params, pool);
    let auth = auth_area_of(&cmd.sessions);
    if build(&cmd, pool, &[], Some(&auth)) == command {
        Step::Cmd(cmd)
    } else {
        Step::Raw(command.to_vec())
    }
}

/// Converts the rounds of one conversation (truncated to [`MAX_ROUNDS`]),
/// feeding the value pool exactly like the driver does.
fn convert_conversation(rounds: &[Round]) -> Conversation {
    let mut pool = ValuePool::default();
    let mut steps = Vec::new();
    for (i, round) in rounds.iter().take(MAX_ROUNDS).enumerate() {
        steps.push(convert_command(&round.command, &pool));
        // An unparseable success response ends the driver's conversation
        // with a finding; the error itself is irrelevant here.
        let _ = pool.record(i, &round.command, &round.response, None);
    }
    Conversation { steps }
}

/// How many references a conversation holds (handles and values), for the
/// summary.
fn count_refs(conv: &Conversation) -> usize {
    fn segs(s: &[Segment]) -> usize {
        s.iter()
            .map(|s| match s {
                Segment::Value(_) | Segment::Mutated(..) => 1,
                Segment::Sized(c) => segs(c),
                Segment::Bytes(_) => 0,
            })
            .sum()
    }
    conv.steps
        .iter()
        .map(|s| match s {
            Step::Cmd(c) => {
                c.handles
                    .iter()
                    .filter(|h| !matches!(h, HandleOperand::Raw(_)))
                    .count()
                    + segs(&c.params)
            }
            Step::Raw(_) => 0,
        })
        .sum()
}

/// The number of leading rounds of `conv` whose replay on `tpm` reproduces
/// `rounds` (same command and response bytes, no finding), and why the next
/// round does not (if there is one).
fn reproduced_prefix(tpm: &mut Tpm, conv: &Conversation, rounds: &[Round]) -> (usize, String) {
    let replayed = replay::replay(tpm, conv);
    for (i, (r, orig)) in replayed.iter().zip(rounds).enumerate() {
        let why = match &r.outcome {
            replay::Outcome::Finding(f) => f.signatures().join(", "),
            replay::Outcome::Panic(message) => format!("panic: {message}"),
            replay::Outcome::Skipped => "rejected at the transport level".into(),
            replay::Outcome::Executed(_) if r.command != orig.command => "different command".into(),
            replay::Outcome::Executed(_) if r.response != orig.response => format!(
                "different response {} (recorded {})",
                trace::encode_hex(&r.response),
                trace::encode_hex(&orig.response)
            ),
            replay::Outcome::Executed(_) => continue,
        };
        return (i, why);
    }
    let n = replayed.len().min(rounds.len());
    let why = if n < conv.steps.len() {
        "replay ended early".into()
    } else {
        String::new()
    };
    (n, why)
}

/// `TPM_ALG_RSA`.
const TPM_ALG_RSA: u16 = 0x0001;
/// `TPM_ALG_ECC`.
const TPM_ALG_ECC: u16 = 0x0023;
/// `TPM_ALG_NULL`.
const TPM_ALG_NULL: u16 = 0x0010;
/// `TPM_ALG_ECDSA`.
const TPM_ALG_ECDSA: u16 = 0x0018;
/// `TPM_ECC_NIST_P256`.
const TPM_ECC_NIST_P256: u16 = 0x0003;
/// The RSA signing schemes (`TPM_ALG_RSASSA`, `TPM_ALG_RSAPSS`), which the
/// ECC variant replaces with ECDSA.
const RSA_SIGNING_SCHEMES: [u16; 2] = [0x0014, 0x0016];
/// The largest RSA key the capped variant keeps.
const MAX_RSA_BITS: u16 = 2048;
/// The commands whose second parameter is a public template:
/// `TPM2_CreatePrimary`, `TPM2_Create` and `TPM2_CreateLoaded`.
const TEMPLATE_COMMANDS: [u32; 3] = [0x131, 0x153, 0x191];

/// How a variant rewrites RSA templates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rewrite {
    /// Into ECC NIST P-256 templates with the same attributes, symmetric
    /// algorithm and signing hash (RSA signing schemes become ECDSA, others
    /// `TPM_ALG_NULL`).
    Ecc,
    /// Keep RSA, but cap `keyBits` at [`MAX_RSA_BITS`].
    CapRsaBits,
}

impl Rewrite {
    /// The suffix of the variant's file names.
    fn suffix(self) -> &'static str {
        match self {
            Rewrite::Ecc => "ecc",
            Rewrite::CapRsaBits => "rsa2048",
        }
    }
}

/// Rewrites an RSA `TPMT_PUBLIC` (the body of a `TPM2B_PUBLIC` template) as
/// `rewrite` says; `None` if it is not an RSA template, does not parse, or
/// would not change.
fn rewrite_rsa_public(public: &[u8], rewrite: Rewrite) -> Option<Vec<u8>> {
    let mut r = Reader(public);
    if r.u16()? != TPM_ALG_RSA {
        return None;
    }
    let name_alg = r.u16()?;
    let attributes = r.u32()?;
    let policy = r.tpm2b_body()?;
    let sym_start = r.rest();
    if r.u16()? != TPM_ALG_NULL {
        r.u32()?; // keyBits and mode.
    }
    let symmetric = &sym_start[..sym_start.len() - r.rest().len()];
    let scheme = r.u16()?;
    let scheme_hash = if scheme == TPM_ALG_NULL {
        None
    } else {
        Some(r.u16()?)
    };
    let before_key_bits = public.len() - r.rest().len();
    let key_bits = r.u16()?;
    let exponent = r.u32()?;
    let unique = r.tpm2b_body()?;
    if !r.rest().is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(public.len());
    let put_scheme = |out: &mut Vec<u8>, scheme: u16, hash: Option<u16>| {
        out.extend_from_slice(&scheme.to_be_bytes());
        if let Some(h) = hash {
            out.extend_from_slice(&h.to_be_bytes());
        }
    };
    match rewrite {
        Rewrite::Ecc => {
            out.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
            out.extend_from_slice(&name_alg.to_be_bytes());
            out.extend_from_slice(&attributes.to_be_bytes());
            out.extend_from_slice(&(policy.len() as u16).to_be_bytes());
            out.extend_from_slice(policy);
            out.extend_from_slice(symmetric);
            match scheme_hash {
                Some(h) if RSA_SIGNING_SCHEMES.contains(&scheme) => {
                    put_scheme(&mut out, TPM_ALG_ECDSA, Some(h));
                }
                _ => put_scheme(&mut out, TPM_ALG_NULL, None),
            }
            out.extend_from_slice(&TPM_ECC_NIST_P256.to_be_bytes());
            out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // kdf
            out.extend_from_slice(&[0, 0, 0, 0]); // unique: empty x and y
        }
        Rewrite::CapRsaBits => {
            if key_bits <= MAX_RSA_BITS {
                return None;
            }
            let unique = &unique[..unique.len().min(usize::from(MAX_RSA_BITS / 8))];
            out.extend_from_slice(&public[..before_key_bits]);
            out.extend_from_slice(&MAX_RSA_BITS.to_be_bytes());
            out.extend_from_slice(&exponent.to_be_bytes());
            out.extend_from_slice(&(unique.len() as u16).to_be_bytes());
            out.extend_from_slice(unique);
        }
    }
    Some(out)
}

/// Rewrites the RSA template of a `TPM2_CreatePrimary`/`Create`/
/// `CreateLoaded` command as `rewrite` says (fixing the TPM2B and command
/// sizes); `None` if the command has no such template.
fn rewrite_template_command(command: &[u8], rewrite: Rewrite) -> Option<Vec<u8>> {
    let view = parse_command(command)?;
    if !TEMPLATE_COMMANDS.contains(&view.code) {
        return None;
    }
    let mut r = Reader(view.params);
    let in_sensitive = r.tpm2b()?;
    let public = r.tpm2b_body()?;
    let rest = r.rest();
    let new_public = rewrite_rsa_public(public, rewrite)?;
    let header_len = command.len() - view.params.len();
    let mut out = command[..header_len].to_vec();
    out.extend_from_slice(in_sensitive);
    out.extend_from_slice(&(new_public.len() as u16).to_be_bytes());
    out.extend_from_slice(&new_public);
    out.extend_from_slice(rest);
    let size = out.len() as u32;
    out[2..6].copy_from_slice(&size.to_be_bytes());
    Some(out)
}

/// The rounds of `rounds` with every RSA template rewritten as `rewrite`
/// says (the recorded responses are kept: they only guide the conversion,
/// whose references then resolve to the variant's own responses), and the
/// index of the first rewritten round; `None` if nothing changed.
fn rewrite_rounds(rounds: &[Round], rewrite: Rewrite) -> Option<(Vec<Round>, usize)> {
    let mut first = None;
    let out = rounds
        .iter()
        .enumerate()
        .map(
            |(i, round)| match rewrite_template_command(&round.command, rewrite) {
                Some(command) => {
                    first.get_or_insert(i);
                    Round {
                        command,
                        response: round.response.clone(),
                    }
                }
                None => round.clone(),
            },
        )
        .collect();
    first.map(|f| (out, f))
}

/// The number of leading rounds of the variant `conv` whose replay on `tpm`
/// gives the same response codes as the recorded `rounds` (without a
/// finding): a variant's responses differ from the recording, but its rounds
/// should still succeed or fail like the original's.
fn same_rc_prefix(tpm: &mut Tpm, conv: &Conversation, rounds: &[Round]) -> usize {
    let rc = |rsp: &[u8]| rsp.get(6..10).map(<[u8]>::to_vec);
    replay::replay(tpm, conv)
        .iter()
        .zip(rounds)
        .take_while(|(r, orig)| {
            matches!(r.outcome, replay::Outcome::Executed(_))
                && rc(&r.response) == rc(&orig.response)
        })
        .count()
}

/// Every `*.trace` file under the given paths (files are taken as given).
fn trace_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    for p in paths {
        if p.is_dir() {
            let entries = std::fs::read_dir(p).map_err(|e| format!("{}: {e}", p.display()))?;
            for entry in entries {
                let path = entry.map_err(|e| e.to_string())?.path();
                if path.extension().is_some_and(|e| e == "trace") {
                    out.push(path);
                }
            }
        } else {
            out.push(p.clone());
        }
    }
    out.sort();
    Ok(out)
}

/// A file-name-safe version of a test name (at most 80 characters).
fn file_stem(test: &str) -> String {
    test.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(80)
        .collect()
}

/// The command line options.
struct Options {
    /// Whether to replay and cut every conversation (`--verify`).
    verify: bool,
    /// Whether to also emit the RSA-template variants (`--ecc-variants`).
    ecc_variants: bool,
    /// Where to write the fuzzer inputs.
    out_dir: PathBuf,
    /// The trace files and directories.
    inputs: Vec<PathBuf>,
}

/// Parses the command line.
fn parse_args(args: &[String]) -> Result<Options, String> {
    let is_flag = |a: &String| a.starts_with("--");
    let mut verify = false;
    let mut ecc_variants = false;
    for flag in args.iter().filter(|a| is_flag(a)) {
        match flag.as_str() {
            "--verify" => verify = true,
            "--ecc-variants" => ecc_variants = true,
            other => return Err(format!("unknown option {other}")),
        }
    }
    if ecc_variants && !verify {
        return Err("--ecc-variants needs --verify (variants are checked by replay)".into());
    }
    let mut positional = args.iter().filter(|a| !is_flag(a)).map(PathBuf::from);
    let out_dir = positional.next().ok_or(
        "usage: trace2conv [--verify [--ecc-variants]] <output dir> <trace file or dir>...",
    )?;
    let inputs: Vec<PathBuf> = positional.collect();
    if inputs.is_empty() {
        return Err("no trace files or directories given".into());
    }
    Ok(Options {
        verify,
        ecc_variants,
        out_dir,
        inputs,
    })
}

/// Converts every trace and writes the inputs; returns a summary line.
fn run(opts: &Options) -> Result<String, String> {
    std::fs::create_dir_all(&opts.out_dir).map_err(|e| e.to_string())?;
    let mut tpm = opts.verify.then(|| Tpm::with_seed(FIXED_SEED));
    let mut seen = HashSet::new();
    let (mut written, mut rounds_total, mut refs_total, mut raw_total, mut cut) = (0, 0, 0, 0, 0);
    let (mut variants, mut variants_dropped) = (0, 0);
    for path in trace_files(&opts.inputs)? {
        let trace = testing::tpm::trace::read(&path)?;
        if trace.seed != FIXED_SEED {
            eprintln!(
                "warning: {} was recorded with seed {} (not {FIXED_SEED}); its literal values may not replay",
                path.display(),
                trace.seed
            );
        }
        for (k, rounds) in trace::conversations(&trace).iter().enumerate() {
            let mut conv = convert_conversation(rounds);
            if let Some(tpm) = tpm.as_mut() {
                tpm.reset();
                let (n, why) = reproduced_prefix(tpm, &conv, rounds);
                if n < conv.steps.len() {
                    cut += 1;
                    eprintln!(
                        "note: {} conversation {k}: round {n} does not reproduce ({why}); cut",
                        path.display()
                    );
                    conv.steps.truncate(n);
                }
            }
            if conv.steps.is_empty() {
                continue;
            }
            let bytes = conv.to_bytes();
            if !seen.insert(bytes.clone()) {
                continue;
            }
            rounds_total += conv.steps.len();
            refs_total += count_refs(&conv);
            raw_total += conv
                .steps
                .iter()
                .filter(|s| matches!(s, Step::Raw(_)))
                .count();
            let name = format!("{}-{k}", file_stem(&trace.test));
            write_input(&opts.out_dir, &name, &bytes)?;
            written += 1;
        }
        if let Some(tpm) = tpm.as_mut().filter(|_| opts.ecc_variants) {
            for (k, rounds) in trace::conversations(&trace).iter().enumerate() {
                let rounds = &rounds[..rounds.len().min(MAX_ROUNDS)];
                for rewrite in [Rewrite::Ecc, Rewrite::CapRsaBits] {
                    let Some((variant, first)) = rewrite_rounds(rounds, rewrite) else {
                        continue;
                    };
                    let mut conv = convert_conversation(&variant);
                    tpm.reset();
                    let n = same_rc_prefix(tpm, &conv, &variant);
                    if n <= first {
                        variants_dropped += 1;
                        continue;
                    }
                    conv.steps.truncate(n);
                    let bytes = conv.to_bytes();
                    if seen.insert(bytes.clone()) {
                        let name = format!("{}-{k}-{}", file_stem(&trace.test), rewrite.suffix());
                        write_input(&opts.out_dir, &name, &bytes)?;
                        variants += 1;
                    }
                }
            }
        }
    }
    Ok(format!(
        "wrote {written} inputs ({rounds_total} rounds, {refs_total} references, \
         {raw_total} raw rounds, {cut} cut by --verify) and {variants} RSA-template variants \
         ({variants_dropped} dropped) to {}",
        opts.out_dir.display()
    ))
}

/// Writes one input file (a numeric suffix avoids name clashes).
fn write_input(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let mut path = dir.join(name);
    let mut n = 1;
    while path.exists() {
        path = dir.join(format!("{name}.{n}"));
        n += 1;
    }
    std::fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&args).and_then(|opts| run(&opts)) {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("trace2conv: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The checked-in trace fixtures (recorded with the fixed seed).
    fn fixture(name: &str) -> testing::tpm::trace::Trace {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/bin/shared/testdata")
            .join(name);
        testing::tpm::trace::read(&path).unwrap()
    }

    /// A TPM2_GetRandom(16) command (no handles, no sessions).
    const GET_RANDOM: [u8; 12] = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x7B, 0, 16];

    /// A command without references converts to a structured step that
    /// rebuilds the same bytes.
    #[test]
    fn plain_command_becomes_structured() {
        let pool = ValuePool::default();
        let step = convert_command(&GET_RANDOM, &pool);
        let Step::Cmd(cmd) = &step else {
            panic!("expected Cmd, got {step:?}")
        };
        assert_eq!(cmd.code, 0x17B);
        assert_eq!(cmd.tag, TagSel::Auto);
        assert_eq!(cmd.params, vec![Segment::Bytes(vec![0, 16])]);
    }

    /// A command with a wrong commandSize stays raw, because the builder
    /// would fix the size.
    #[test]
    fn inconsistent_size_stays_raw() {
        let mut bad = GET_RANDOM;
        bad[5] = 13;
        assert_eq!(
            convert_command(&bad, &ValuePool::default()),
            Step::Raw(bad.to_vec())
        );
        let unknown = [0x80, 0x01, 0, 0, 0, 10, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(
            convert_command(&unknown, &ValuePool::default()),
            Step::Raw(unknown.to_vec())
        );
    }

    /// Password sessions become `Password`, other sessions stay raw, and
    /// the rebuilt area is identical.
    #[test]
    fn sessions_are_converted() {
        let pw = [0x40, 0, 0, 9, 0, 0, 1, 0, 2, 0xAA, 0xBB];
        let hmac = [0x02, 0, 0, 0, 0, 1, 0x11, 0x21, 0, 1, 0x22];
        let area: Vec<u8> = pw.iter().chain(&hmac).copied().collect();
        let sessions = convert_sessions(&area);
        assert_eq!(
            sessions,
            vec![
                SessionSel::Password {
                    auth: AuthSel::Bytes(vec![0xAA, 0xBB])
                },
                SessionSel::Raw(hmac.to_vec()),
            ]
        );
        assert_eq!(auth_area_of(&sessions), area);
        // Garbage stays one raw session.
        assert_eq!(
            convert_sessions(&[1, 2, 3]),
            vec![SessionSel::Raw(vec![1, 2, 3])]
        );
        assert!(convert_sessions(&[]).is_empty());
    }

    /// Handles of earlier responses and values of earlier responses become
    /// references in a recorded conversation, and every converted step
    /// rebuilds the recorded command.
    #[test]
    fn recorded_trace_gets_references() {
        let trace = fixture("object_lifecycle.trace");
        let convs = trace::conversations(&trace);
        assert!(!convs.is_empty());
        let mut total_refs = 0;
        for rounds in &convs {
            let conv = convert_conversation(rounds);
            total_refs += count_refs(&conv);
            let mut pool = ValuePool::default();
            for (i, (step, round)) in conv.steps.iter().zip(rounds).enumerate() {
                if let Step::Cmd(cmd) = step {
                    let auth = auth_area_of(&cmd.sessions);
                    assert_eq!(
                        build(cmd, &pool, &[], Some(&auth)),
                        round.command,
                        "round {i}"
                    );
                }
                let _ = pool.record(i, &round.command, &round.response, None);
            }
            assert_eq!(Conversation::from_bytes(&conv.to_bytes()), conv);
        }
        assert!(total_refs > 0, "no references found");
    }

    /// Replaying converted conversations through the driver on a TPM with
    /// the fixed seed reproduces every recorded command and response.
    #[test]
    fn replay_reproduces_recorded_responses() {
        let mut tpm = Tpm::with_seed(FIXED_SEED);
        for name in ["object_lifecycle.trace", "hmac_session.trace"] {
            let trace = fixture(name);
            for rounds in trace::conversations(&trace) {
                let conv = convert_conversation(&rounds);
                tpm.reset();
                let (n, why) = reproduced_prefix(&mut tpm, &conv, &rounds);
                assert_eq!(
                    n,
                    conv.steps.len(),
                    "{name}: round {n} does not reproduce: {why}"
                );
            }
        }
    }

    /// An RSA signing template (`TPM_ALG_RSASSA` with SHA-256, 2048 bits).
    const RSA_SIGNING: [u8; 24] = [
        0x00, 0x01, 0x00, 0x0b, 0x00, 0x04, 0x00, 0x72, 0x00,
        0x00, // type, nameAlg, attrs, policy
        0x00, 0x10, 0x00, 0x14, 0x00, 0x0b, // symmetric NULL, scheme RSASSA(SHA-256)
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // keyBits, exponent, unique
    ];
    /// An RSA 3072 storage-key template (AES-128 CFB, no scheme).
    const RSA_STORAGE_3072: [u8; 26] = [
        0x00, 0x01, 0x00, 0x0b, 0x00, 0x03, 0x00, 0x72, 0x00,
        0x00, // type, nameAlg, attrs, policy
        0x00, 0x06, 0x00, 0x80, 0x00, 0x43, 0x00, 0x10, // AES-128 CFB, scheme NULL
        0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // keyBits, exponent, unique
    ];

    /// RSA templates become ECC P-256 templates with the same attributes,
    /// symmetric algorithm and signing hash.
    #[test]
    fn rsa_templates_become_ecc() {
        assert_eq!(
            rewrite_rsa_public(&RSA_SIGNING, Rewrite::Ecc).unwrap(),
            [
                0x00, 0x23, 0x00, 0x0b, 0x00, 0x04, 0x00, 0x72, 0x00, 0x00, 0x00, 0x10, 0x00, 0x18,
                0x00, 0x0b, 0x00, 0x03, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00
            ]
        );
        assert_eq!(
            rewrite_rsa_public(&RSA_STORAGE_3072, Rewrite::Ecc).unwrap(),
            [
                0x00, 0x23, 0x00, 0x0b, 0x00, 0x03, 0x00, 0x72, 0x00, 0x00, 0x00, 0x06, 0x00, 0x80,
                0x00, 0x43, 0x00, 0x10, 0x00, 0x03, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00
            ]
        );
        // Not RSA, or malformed: unchanged.
        let mut ecc = RSA_SIGNING;
        ecc[1] = 0x23;
        assert_eq!(rewrite_rsa_public(&ecc, Rewrite::Ecc), None);
        assert_eq!(rewrite_rsa_public(&RSA_SIGNING[..20], Rewrite::Ecc), None);
    }

    /// Only RSA keys above 2048 bits are capped.
    #[test]
    fn large_rsa_keys_are_capped() {
        assert_eq!(rewrite_rsa_public(&RSA_SIGNING, Rewrite::CapRsaBits), None);
        let capped = rewrite_rsa_public(&RSA_STORAGE_3072, Rewrite::CapRsaBits).unwrap();
        assert_eq!(capped.len(), RSA_STORAGE_3072.len());
        assert_eq!(capped[18..20], [0x08, 0x00]);
        assert_eq!(capped[..18], RSA_STORAGE_3072[..18]);
    }

    /// A rewritten command keeps its handles and sessions and gets
    /// consistent sizes.
    #[test]
    fn template_commands_are_rewritten() {
        // TPM2_CreatePrimary(TPM_RH_OWNER, password session) with an empty
        // inSensitive, the RSA template, outsideInfo and creationPCR empty.
        let mut cmd = vec![0x80, 0x02, 0, 0, 0, 0, 0, 0, 0x01, 0x31, 0x40, 0, 0, 0x01];
        cmd.extend_from_slice(&[0, 0, 0, 9, 0x40, 0, 0, 9, 0, 0, 1, 0, 0]);
        cmd.extend_from_slice(&[0, 4, 0, 0, 0, 0]);
        cmd.extend_from_slice(&(RSA_SIGNING.len() as u16).to_be_bytes());
        cmd.extend_from_slice(&RSA_SIGNING);
        cmd.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        let size = cmd.len() as u32;
        cmd[2..6].copy_from_slice(&size.to_be_bytes());
        let ecc = rewrite_template_command(&cmd, Rewrite::Ecc).unwrap();
        let view = parse_command(&ecc).unwrap();
        assert_eq!(view.handles, [0x4000_0001]);
        assert_eq!(view.auth, &cmd[18..27]);
        assert_eq!(
            u32::from_be_bytes(ecc[2..6].try_into().unwrap()) as usize,
            ecc.len()
        );
        let mut r = Reader(view.params);
        assert_eq!(r.tpm2b(), Some(&[0, 4, 0, 0, 0, 0][..]));
        assert_eq!(
            r.tpm2b_body().map(|p| p[..2].to_vec()),
            Some(vec![0x00, 0x23])
        );
        assert_eq!(r.rest(), [0, 0, 0, 0, 0, 0]);
        assert_eq!(rewrite_template_command(&GET_RANDOM, Rewrite::Ecc), None);
    }

    /// The ECC variant of a recorded RSA conversation replays with the
    /// recorded response codes beyond its rewritten round.
    #[test]
    fn ecc_variant_replays_with_the_same_response_codes() {
        let trace = fixture("rsa_signing_key.trace");
        let rounds = &trace::conversations(&trace)[0];
        let (variant, first) = rewrite_rounds(rounds, Rewrite::Ecc).unwrap();
        assert_eq!(first, 0);
        let conv = convert_conversation(&variant);
        let mut tpm = Tpm::with_seed(FIXED_SEED);
        let n = same_rc_prefix(&mut tpm, &conv, &variant);
        assert!(n > first, "only {n} rounds keep their response codes");
        tpm.reset();
        let replayed = replay::replay(&mut tpm, &conv);
        // CreatePrimary's outPublic (after the handle and parameterSize) is
        // now an ECC key.
        assert_eq!(replayed[0].response[20..22], [0x00, 0x23]);
    }

    /// The command line needs an output directory and at least one input.
    #[test]
    fn argument_parsing() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(parse_args(&args(&[])).is_err());
        assert!(parse_args(&args(&["out"])).is_err());
        let opts = parse_args(&args(&["--verify", "out", "a.trace", "dir"])).unwrap();
        assert!(opts.verify);
        assert!(!opts.ecc_variants);
        assert_eq!(opts.out_dir, PathBuf::from("out"));
        assert_eq!(opts.inputs.len(), 2);
        assert!(parse_args(&args(&["--ecc-variants", "out", "a"])).is_err());
        assert!(parse_args(&args(&["--bogus", "out", "a"])).is_err());
        let opts = parse_args(&args(&["--verify", "--ecc-variants", "out", "a"])).unwrap();
        assert!(opts.ecc_variants);
        assert_eq!(opts.inputs.len(), 1);
    }

    /// File stems keep only safe characters.
    #[test]
    fn file_stems_are_safe() {
        assert_eq!(file_stem("nv::define space"), "nv__define_space");
    }
}
