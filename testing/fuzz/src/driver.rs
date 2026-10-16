//! The multi-round driver: one [`Driver::round`] per conversation step, the
//! findings it reports, and the suppression of known divergences.
//!
//! Per round the driver **resolves** the step against the value pool and the
//! session table, **builds** the command bytes (with the authorization area
//! from the [`SessionEngine`]), **sends** them through
//! [`Tpm::try_exchange`] at locality 0 (which compares the responses of
//! `tpm-rs` and the C references), **checks** that the `tpm-rs` response is
//! well formed, lets the session engine **update** its sessions, and
//! **extracts** the response fields into the [`ValuePool`]. Rounds the
//! simulator rejects at the transport level are skipped.
//!
//! # Findings
//!
//! A [`Finding`] ends the conversation. Each has a stable signature (used for
//! deduplication and for [`KnownDivergences`]):
//!
//! * `DIVERGENCE[<impl>:round<i>:<cc>:<rs_rc>:<ref_rc>]`: a reference's
//!   response differs from `tpm-rs`'s other than as documented (`<ref_rc>`
//!   is `none` when the reference has no response, e.g. it crashed);
//! * `MALFORMED_RESPONSE[round<i>:<cc>]`: the `tpm-rs` response is not well
//!   formed (see [`check_response`]);
//! * `UNPARSEABLE_RESPONSE[round<i>:<cc>]`: a successful `tpm-rs` response
//!   that the typed `tpm2` response cannot unmarshal.
//!
//! `<cc>` is the command code as `0x%x` (`raw` if a raw step has no complete
//! header) and the response codes are `0x%x`.

use std::fmt::Write as _;
use std::path::Path;

use testing::differential::Divergence;
use testing::seed::ReferenceSeed;
use testing::tpm::{SendError, Tpm};

use crate::builder::{assemble, has_auth_area, resolve_handles, resolve_params};
use crate::model::{AuthSel, Cmd, SessionSel, Step};
use crate::pool::ValuePool;
use crate::session::{CommandInfo, SessionChoice, SessionEngine, SessionRequest};
use crate::wire::{be16, be32, check_response, parse_command};

/// The seed of every fuzzed TPM (`TPM_REFERENCE_SEED=4242:1000000`), so every
/// conversation is deterministic and reproducible.
pub const FIXED_SEED: ReferenceSeed = ReferenceSeed {
    pid: 4242,
    realtime_ms: 1_000_000,
};

/// A finding (see the module docs).
#[derive(Debug)]
pub enum Finding {
    /// A reference's response differs from `tpm-rs`'s.
    Divergence {
        /// The round index.
        round: usize,
        /// The command code (if the command has a header).
        code: Option<u32>,
        /// The command sent.
        command: Vec<u8>,
        /// The `tpm-rs` response.
        response: Vec<u8>,
        /// Every diverging reference.
        divergences: Vec<Divergence>,
    },
    /// The `tpm-rs` response is malformed.
    Malformed {
        /// The round index.
        round: usize,
        /// The command code (if the command has a header).
        code: Option<u32>,
        /// The command sent.
        command: Vec<u8>,
        /// The `tpm-rs` response.
        response: Vec<u8>,
        /// What is wrong.
        reason: String,
    },
    /// A successful `tpm-rs` response the typed `tpm2` response cannot
    /// unmarshal.
    Unparseable {
        /// The round index.
        round: usize,
        /// The command code (if the command has a header).
        code: Option<u32>,
        /// The command sent.
        command: Vec<u8>,
        /// The `tpm-rs` response.
        response: Vec<u8>,
        /// The unmarshal error.
        reason: String,
    },
}

/// `0x%x`, or `none`.
fn hex_or_none(v: Option<u32>) -> String {
    v.map_or_else(|| "none".into(), |v| format!("{v:#x}"))
}

/// The response code of a response.
fn rc_of(rsp: &[u8]) -> Option<u32> {
    be32(rsp, 6)
}

/// Lowercase hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

impl Finding {
    /// The signatures of the finding (one per diverging reference for a
    /// divergence).
    pub fn signatures(&self) -> Vec<String> {
        let cc = |code: &Option<u32>| code.map_or_else(|| "raw".into(), |c| format!("{c:#x}"));
        match self {
            Finding::Divergence {
                round,
                code,
                response,
                divergences,
                ..
            } => divergences
                .iter()
                .map(|d| {
                    format!(
                        "DIVERGENCE[{}:round{round}:{}:{}:{}]",
                        d.implementation.name(),
                        cc(code),
                        hex_or_none(rc_of(response)),
                        hex_or_none(d.reference_response.as_deref().and_then(rc_of)),
                    )
                })
                .collect(),
            Finding::Malformed { round, code, .. } => {
                vec![format!("MALFORMED_RESPONSE[round{round}:{}]", cc(code))]
            }
            Finding::Unparseable { round, code, .. } => {
                vec![format!("UNPARSEABLE_RESPONSE[round{round}:{}]", cc(code))]
            }
        }
    }

    /// A full report: the signatures, then the command and response bytes and
    /// the details.
    pub fn report(&self) -> String {
        let mut out = self.signatures().join("\n");
        let (command, response) = match self {
            Finding::Divergence {
                command, response, ..
            }
            | Finding::Malformed {
                command, response, ..
            }
            | Finding::Unparseable {
                command, response, ..
            } => (command, response),
        };
        let _ = write!(
            out,
            "\ncommand:  {}\nresponse: {}",
            hex(command),
            hex(response)
        );
        match self {
            Finding::Divergence { divergences, .. } => {
                for d in divergences {
                    let _ = write!(out, "\n{d}");
                }
            }
            Finding::Malformed { reason, .. } | Finding::Unparseable { reason, .. } => {
                let _ = write!(out, "\n{reason}");
            }
        }
        out
    }
}

/// What happened in a round without a finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoundOutcome {
    /// The command was executed (and compared); its `tpm-rs` response code.
    Executed(u32),
    /// The simulator rejected the command at the transport level, so it was
    /// neither executed nor mirrored.
    Skipped,
}

/// Counters of one driver.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Rounds attempted.
    pub rounds: u64,
    /// Rounds skipped at the transport level.
    pub skipped: u64,
    /// Rounds whose `tpm-rs` response was `TPM_RC_SUCCESS`.
    pub succeeded: u64,
}

impl Stats {
    /// Adds `other` to these counters.
    pub fn add(&mut self, other: &Stats) {
        self.rounds += other.rounds;
        self.skipped += other.skipped;
        self.succeeded += other.succeeded;
    }
}

/// The state of one conversation (see the module docs).
#[derive(Default)]
pub struct Driver {
    /// The values earlier rounds produced.
    pub pool: ValuePool,
    /// The session table.
    pub sessions: SessionEngine,
    /// The counters.
    pub stats: Stats,
    /// The index of the next round.
    round: usize,
    /// The last command built.
    last_command: Vec<u8>,
    /// The last `tpm-rs` response (empty if the round was skipped).
    last_response: Vec<u8>,
}

/// A command ready to send, with what the session engine needs to know about
/// it.
struct Prepared {
    /// The command bytes.
    bytes: Vec<u8>,
    /// The command code (from the step or the header).
    code: Option<u32>,
    /// The command handles.
    handles: Vec<u32>,
}

impl Driver {
    /// The index of the next round.
    pub fn next_round(&self) -> usize {
        self.round
    }

    /// The command bytes of the last round.
    pub fn last_command(&self) -> &[u8] {
        &self.last_command
    }

    /// The `tpm-rs` response of the last round (empty if it was skipped).
    pub fn last_response(&self) -> &[u8] {
        &self.last_response
    }

    /// Resolves the auth value `sel` for the slot that authorizes `handle`.
    fn resolve_auth(&self, sel: &AuthSel, handle: Option<u32>) -> Vec<u8> {
        match sel {
            AuthSel::Empty => Vec::new(),
            AuthSel::Entity => handle
                .and_then(|h| self.pool.handle_auth(h))
                .unwrap_or_default()
                .to_vec(),
            AuthSel::Known(n) => self.pool.known_auth(*n).to_vec(),
            AuthSel::Bytes(bytes) => bytes.clone(),
        }
    }

    /// The command-info parts for `handles`: their Names and known auth
    /// values.
    fn handle_info(&self, handles: &[u32]) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let names = handles.iter().map(|&h| self.pool.name_of(h)).collect();
        let auths = handles
            .iter()
            .map(|&h| self.pool.handle_auth(h).unwrap_or_default().to_vec())
            .collect();
        (names, auths)
    }

    /// Builds the command of structured step `cmd`, authorizing it through
    /// the session engine.
    fn prepare_cmd(&mut self, cmd: &Cmd) -> Prepared {
        let live = self.sessions.live_handles();
        let handles = resolve_handles(cmd, &self.pool, &live);
        let mut params = resolve_params(cmd, &self.pool);
        let (names, handle_auths) = self.handle_info(&handles);
        let info = CommandInfo {
            round: self.round,
            code: cmd.code,
            handles: &handles,
            names: &names,
            handle_auths: &handle_auths,
        };
        // The engine may complete the parameters first (e.g. a generated, encrypted salt for
        // `TPM2_StartAuthSession`), so every size is computed from its result.
        self.sessions.prepare_params(&info, &mut params);
        let auth_area = if cmd.sessions.is_empty() {
            has_auth_area(cmd).then(Vec::new)
        } else {
            let auths: Vec<Vec<u8>> = cmd
                .sessions
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    s.auth()
                        .map(|a| self.resolve_auth(a, handles.get(i).copied()))
                        .unwrap_or_default()
                })
                .collect();
            let reqs: Vec<SessionRequest<'_>> = cmd
                .sessions
                .iter()
                .zip(&auths)
                .enumerate()
                .map(|(slot, (sel, auth))| SessionRequest {
                    slot,
                    choice: match sel {
                        SessionSel::Password { .. } => SessionChoice::Password,
                        SessionSel::Hmac {
                            session,
                            attrs,
                            corrupt_hmac,
                            ..
                        } => SessionChoice::Hmac {
                            session: *session,
                            attrs: *attrs,
                            corrupt_hmac: *corrupt_hmac,
                        },
                        SessionSel::Policy { session, attrs, .. } => SessionChoice::Policy {
                            session: *session,
                            attrs: *attrs,
                        },
                        SessionSel::Raw(bytes) => SessionChoice::Raw(bytes),
                    },
                    auth,
                })
                .collect();
            Some(self.sessions.authorize(&info, &mut params, &reqs))
        };
        let bytes = assemble(
            cmd.tag.value(!cmd.sessions.is_empty()),
            cmd.code,
            &handles,
            auth_area.as_deref(),
            &params,
            &cmd.fixups,
        );
        Prepared {
            bytes,
            code: Some(cmd.code),
            handles,
        }
    }

    /// Builds the command of `step`.
    fn prepare(&mut self, step: &Step) -> Prepared {
        match step {
            Step::Cmd(cmd) => self.prepare_cmd(cmd),
            Step::Raw(bytes) => {
                let parsed = parse_command(bytes);
                Prepared {
                    code: parsed.as_ref().map(|c| c.code).or_else(|| be32(bytes, 6)),
                    handles: parsed.map(|c| c.handles).unwrap_or_default(),
                    bytes: bytes.clone(),
                }
            }
        }
    }

    /// Runs one round: builds `step`, sends it to `tpm` at locality 0,
    /// checks the response and updates the session table and the value pool
    /// (see the module docs).
    ///
    /// # Errors
    /// A [`Finding`]; the conversation should end there (the `Tpm` must be
    /// reset before it is reused).
    ///
    /// # Panics
    /// If the session engine detects a finding (it panics with its own
    /// signature, see [`crate::session`]).
    pub fn round(&mut self, tpm: &mut Tpm, step: &Step) -> Result<RoundOutcome, Finding> {
        let round = self.round;
        self.stats.rounds += 1;
        // `prepare` builds the session engine's CommandInfo with `self.round`, so it must see
        // this round's index (the same one `on_response` gets).
        let prepared = self.prepare(step);
        self.round += 1;
        self.last_command.clone_from(&prepared.bytes);
        self.last_response.clear();
        let command = prepared.bytes;
        let response = match tpm.try_exchange(0, &command) {
            Ok(response) => response,
            Err(SendError::Transport(_)) => {
                self.sessions.abort_pending();
                self.stats.skipped += 1;
                return Ok(RoundOutcome::Skipped);
            }
            Err(SendError::Divergence {
                response,
                divergences,
            }) => {
                self.last_response.clone_from(&response);
                return Err(Finding::Divergence {
                    round,
                    code: prepared.code,
                    command,
                    response,
                    divergences,
                });
            }
        };
        self.last_response.clone_from(&response);
        let rc = match check_response(&response, be16(&command, 0), prepared.code) {
            Ok(view) => view.rc,
            Err(reason) => {
                return Err(Finding::Malformed {
                    round,
                    code: prepared.code,
                    command,
                    response,
                    reason,
                });
            }
        };
        if rc == 0 {
            self.stats.succeeded += 1;
        }
        let (names, handle_auths) = self.handle_info(&prepared.handles);
        let info = CommandInfo {
            round,
            code: prepared.code.unwrap_or_default(),
            handles: &prepared.handles,
            names: &names,
            handle_auths: &handle_auths,
        };
        // The facts (auth values, NV public areas, ...) come from the plaintext parameters:
        // a `decrypt` session encrypted the first parameter of the command sent. The parameter
        // area is the tail of the command.
        let plain_command = self.sessions.plain_params().and_then(|plain| {
            let at = command.len().checked_sub(plain.len())?;
            Some([&command[..at], plain].concat())
        });
        let decrypted = self.sessions.on_response(&info, &command, &response);
        if let Err(reason) = self.pool.record(
            round,
            plain_command.as_deref().unwrap_or(&command),
            &response,
            decrypted.as_deref(),
        ) {
            return Err(Finding::Unparseable {
                round,
                code: prepared.code,
                command,
                response,
                reason,
            });
        }
        Ok(RoundOutcome::Executed(rc))
    }
}

/// Finding signatures to suppress (`testing/fuzz/known_divergences.txt`):
/// a finding whose signatures all match a pattern ends the conversation
/// quietly instead of crashing, so long campaigns keep finding new issues.
///
/// One pattern per line; `#` starts a comment; blank lines are ignored. A
/// pattern is a signature in which `*` matches any (possibly empty) run of
/// characters, e.g. `DIVERGENCE[ibmswtpm2:*:0x17a:*:*]`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KnownDivergences {
    patterns: Vec<String>,
}

/// Environment variable naming an alternative known-divergences file.
pub const KNOWN_DIVERGENCES_ENV: &str = "TPM_FUZZ_KNOWN_DIVERGENCES";

impl KnownDivergences {
    /// Parses the patterns of a known-divergences file.
    pub fn parse(text: &str) -> Self {
        let patterns = text
            .lines()
            .map(|l| l.split('#').next().unwrap_or_default().trim())
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect();
        Self { patterns }
    }

    /// Loads the file named by [`KNOWN_DIVERGENCES_ENV`], or else
    /// `testing/fuzz/known_divergences.txt`; no patterns if it is missing.
    pub fn load() -> Self {
        let path = std::env::var_os(KNOWN_DIVERGENCES_ENV).map_or_else(
            || Path::new(env!("CARGO_MANIFEST_DIR")).join("known_divergences.txt"),
            Into::into,
        );
        std::fs::read_to_string(path)
            .map(|t| Self::parse(&t))
            .unwrap_or_default()
    }

    /// The patterns.
    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }

    /// Whether `signature` matches a pattern.
    pub fn matches(&self, signature: &str) -> bool {
        self.patterns.iter().any(|p| glob(p, signature))
    }

    /// Whether every signature of `finding` matches a pattern.
    pub fn suppresses(&self, finding: &Finding) -> bool {
        finding.signatures().iter().all(|s| self.matches(s))
    }
}

/// Whether `text` matches `pattern`, where `*` matches any run of characters.
fn glob(pattern: &str, text: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else {
        return rest.is_empty();
    };
    for part in middle {
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Conversation, FieldKind, HandleOperand, Segment, ValueRef};
    use testing::differential::Implementation;

    #[test]
    fn globs_match() {
        assert!(glob("abc", "abc"));
        assert!(!glob("abc", "abcd"));
        assert!(glob("a*", "abcd"));
        assert!(glob("*d", "abcd"));
        assert!(glob("a*c*", "abcd"));
        assert!(glob("*", ""));
        assert!(!glob("a*b*c", "acb"));
        assert!(glob("a*b*c", "abc"));
        assert!(!glob("ab*ba", "aba"));
    }

    fn divergence() -> Finding {
        Finding::Divergence {
            round: 3,
            code: Some(0x17A),
            command: vec![1],
            response: vec![0x80, 1, 0, 0, 0, 10, 0, 0, 0, 0],
            divergences: vec![
                Divergence {
                    implementation: Implementation::Mstpm20,
                    reference_response: Some(vec![0x80, 1, 0, 0, 0, 10, 0, 0, 1, 0x43]),
                    message: "differs".into(),
                },
                Divergence {
                    implementation: Implementation::Ibmswtpm2,
                    reference_response: None,
                    message: "died".into(),
                },
            ],
        }
    }

    #[test]
    fn signatures_have_the_documented_form() {
        let f = divergence();
        assert_eq!(
            f.signatures(),
            [
                "DIVERGENCE[mstpm20:round3:0x17a:0x0:0x143]",
                "DIVERGENCE[ibmswtpm2:round3:0x17a:0x0:none]",
            ]
        );
        let report = f.report();
        assert!(report.contains("command:  01"));
        assert!(report.contains("died"));
        let m = Finding::Malformed {
            round: 0,
            code: None,
            command: vec![],
            response: vec![],
            reason: "short".into(),
        };
        assert_eq!(m.signatures(), ["MALFORMED_RESPONSE[round0:raw]"]);
        assert!(m.report().ends_with("short"));
    }

    /// A command step with `handles`, password `sessions` and `params`.
    fn step(
        code: u32,
        handles: Vec<HandleOperand>,
        sessions: Vec<AuthSel>,
        params: Vec<Segment>,
    ) -> Step {
        let mut cmd = Cmd::new(code);
        cmd.handles = handles;
        cmd.sessions = sessions
            .into_iter()
            .map(|auth| SessionSel::Password { auth })
            .collect();
        cmd.params = params;
        Step::Cmd(cmd)
    }

    fn value(kind: FieldKind) -> Segment {
        Segment::Value(ValueRef { kind, back: 0 })
    }

    fn bytes(b: &[u8]) -> Segment {
        Segment::Bytes(b.to_vec())
    }

    /// A deep conversation whose later rounds only work if the earlier
    /// rounds' outputs (handles, Names, blobs, contexts, auth values) flow
    /// through the pool: CreatePrimary (auth "pw") → ReadPublic →
    /// ContextSave → FlushContext → ContextLoad → Create (sealed "secret",
    /// parent auth from the context facts) → Load → Unseal.
    ///
    /// Needs the reference binaries (`MSTPM20_BIN`/`IBMSWTPM2_BIN`).
    #[test]
    fn deep_conversation_reuses_earlier_outputs() {
        let last = HandleOperand::Response { back: 0 };
        let owner = HandleOperand::Raw(0x4000_0001);
        // ECC P-256 restricted decryption key, AES-128-CFB.
        let ecc_template = [
            0, 0x23, 0, 0x0B, 0, 3, 0, 0x72, 0, 0, 0, 6, 0, 0x80, 0, 0x43, 0, 0x10, 0, 3, 0, 0x10,
            0, 0, 0, 0,
        ];
        // Sealed data object (keyedhash, NULL scheme), userWithAuth.
        let sealed_template = [0, 8, 0, 0x0B, 0, 0, 0, 0x52, 0, 0, 0, 0x10, 0, 0];
        let sensitive = |auth: &[u8], data: &[u8]| {
            Segment::Sized(vec![
                Segment::Sized(vec![bytes(auth)]),
                Segment::Sized(vec![bytes(data)]),
            ])
        };
        let creation = || vec![Segment::Sized(vec![]), bytes(&[0, 0, 0, 0])];
        let mut create_primary = vec![
            sensitive(b"pw", b""),
            Segment::Sized(vec![bytes(&ecc_template)]),
        ];
        create_primary.extend(creation());
        let mut create = vec![
            sensitive(b"", b"secret"),
            Segment::Sized(vec![bytes(&sealed_template)]),
        ];
        create.extend(creation());
        let conv = Conversation {
            steps: vec![
                step(0x131, vec![owner], vec![AuthSel::Empty], create_primary),
                step(0x173, vec![last], vec![], vec![]),
                step(0x162, vec![last], vec![], vec![]),
                step(0x165, vec![], vec![], vec![value(FieldKind::Handle)]),
                step(0x161, vec![], vec![], vec![value(FieldKind::Context)]),
                step(0x153, vec![last], vec![AuthSel::Entity], create),
                step(
                    0x157,
                    vec![last],
                    vec![AuthSel::Entity],
                    vec![value(FieldKind::Private), value(FieldKind::Public)],
                ),
                step(0x15E, vec![last], vec![AuthSel::Entity], vec![]),
            ],
        };
        // The conversation survives the fuzzer encoding.
        let conv = Conversation::from_bytes(&conv.to_bytes());
        let mut tpm = Tpm::with_seed(FIXED_SEED);
        for _ in 0..2 {
            let mut driver = Driver::default();
            for (i, s) in conv.steps.iter().enumerate() {
                let outcome = driver
                    .round(&mut tpm, s)
                    .unwrap_or_else(|f| panic!("{}", f.report()));
                assert_eq!(
                    outcome,
                    RoundOutcome::Executed(0),
                    "round {i}: {}",
                    hex(driver.last_response())
                );
            }
            assert!(
                driver.last_response().windows(6).any(|w| w == b"secret"),
                "Unseal: {}",
                hex(driver.last_response())
            );
            assert_eq!(driver.stats.succeeded, conv.steps.len() as u64);
            // The same conversation again on the reset TPM.
            tpm.reset();
        }
    }

    #[test]
    fn known_divergences_suppress_only_full_matches() {
        let known =
            KnownDivergences::parse("# comment\n\nDIVERGENCE[mstpm20:*:0x17a:*:*]  # trailing\n");
        assert_eq!(known.patterns(), ["DIVERGENCE[mstpm20:*:0x17a:*:*]"]);
        let f = divergence();
        // The ibmswtpm2 signature is not covered.
        assert!(!known.suppresses(&f));
        let known = KnownDivergences::parse(
            "DIVERGENCE[mstpm20:*:0x17a:*:*]\nDIVERGENCE[ibmswtpm2:*:*:*:none]",
        );
        assert!(known.suppresses(&f));
    }
}
