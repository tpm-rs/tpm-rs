//! TPM 2.0 Command Execution Engine.
//!
//! This module implements [TpmEngine], the central coordinator and orchestrator for processing
//! incoming TPM 2.0 command packets and generating response packets.
//!
//! ## Overall Module Structure & Major Parts
//!
//! The module is organized around three primary components:
//!
//! 1. **Context & State Management**:
//!    - **[TpmEngine]**: The root orchestrator that owns its [`Platform`] (the platform dependencies: crypto, timer, RNG, firmware) and the [State]. It implements [`tpm2::Connection`].
//!    - **[State]**: Holds the volatile state of the TPM (e.g., loaded transient keys, active authorization/policy sessions, PCR tables, and execution flags) and, in [`State::nv`](crate::Nv), its non-volatile state with the NV data structure ([`crate::Nv::index`]).
//!
//! 2. **Execution Gateway & Routing**:
//!    - **[TpmEngine::execute_command]**: The primary entry point. Decodes the command tag to determine if the command has authorization sessions (tag `0x8002`) or is session-less (tag `0x8001`).
//!    - **[TpmEngine::execute_with_sessions]**: The security layer. It parses session fields, decrypts incoming parameters using session keys, verifies session HMACs, dispatches execution to a shadow session-less buffer, computes response HMACs, and encrypts outgoing parameters.
//!    - **[TpmEngine::execute_without_sessions]**: The command dispatch router. It wraps input/output buffers in a [RequestResponseCursor](req_resp.rs) and routes the request to the appropriate command-specific method on [CommandHandler](handler/mod.rs).
//!
//! 3. **Protocol Invariant Helpers**:
//!    - **Session Parsing/Verification**: Internal helpers that validate handles, compute KDFa session keys, verify session HMACs, and manage the dictionary attack (DA) protection state.
//!    - **Slot & Sequence Tracking**: Internal helpers to manage active hash/HMAC/event sequences and allocate/free slots in volatile object memory tables.
//!
//! ## Relationships
//!
//! ```mermaid
//! graph TD
//!     Host[Host System] -->|Command Slices| Engine[TpmEngine]
//!     Engine -->|1. Parse Tag/Header| Dec[tag == 0x8002?]
//!     Dec -->|Yes| SessionL[execute_with_sessions]
//!     Dec -->|No| DirectL[execute_without_sessions]
//!     SessionL -->|Decrypt Params & Verify HMACs| Shadow[Create Shadow Tag 0x8001 Request]
//!     Shadow --> DirectL
//!     DirectL -->|Create Cursors| Router[Match Command Code]
//!     Router -->|Dispatch| Handlers[CommandHandler Methods]
//!     Handlers -->|Mutate State & Read Platform| Engine
//!     Handlers -->|Write Output Parameters| Response[RequestResponseCursor/Response]
//!     SessionL -->|Encrypt Params & Calc HMACs| Response
//!     Response -->|Final Response Slices| Host
//! ```
//!
//! ## Alignment with the TPM 2.0 Specification
//!
//! This implementation directly maps to:
//! - **TCG TPM 2.0 Library Specification, Part 1: Architecture, Section 5 (Command Execution)**: Implements the three-phase execution flow (parsing and authorization check, command execution, and response generation).
//! - **Part 1, Section 11 (Session Cryptography)**: Enforces parameter encryption/decryption and HMAC computations using key derivation functions (KDFa).
//! - **Part 2: Structures**: Implements the memory structure layout and constraints for handles, session states, and `TPMS_CLOCK_INFO`.

use crate::InternalError;
use crate::Platform;
use crate::handler::CommandHandler;
use crate::handler::{SessionState, TransientObject};
use crate::owned::{
    OwnedAuth, OwnedAuthCommand, OwnedDigest, OwnedName, OwnedNonce, OwnedSensitiveData,
};
use crate::req_resp::RequestResponseCursor;
use crate::self_test::kdfa_bits;
use crate::state::State;
use crate::storage::IndexState;
use crate::timer::TpmTimer;
use tpm2::crypto::{Crypto, Direction};
use tpm2::errors::{Position, TpmRc};
use tpm2::{CommandHeader, Handle, ResponseHeader, TpmCc, TpmHt, TpmSe, TpmSt};
use tpm2::{Marshal, Unmarshal};
use tpm2::{
    Tpm2bAuth, Tpm2bNonce, TpmaSession, TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode,
    TpmiStCommandTag, TpmsAuthResponse,
};

/// The only symmetric block cipher mode allowed for session parameter encryption (TPM 2.0
/// Part 1, Section 21.3, "CFB Mode Parameter Encryption"); exp's `TpmiAlgSymMode::CFB`.
const CFB_MODE: TpmiAlgSymMode = TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb);

/// The object that processes incoming TPM requests and produces the corresponding TPM response.
///
/// A `TpmEngine` owns everything a TPM needs: the platform dependencies ([`Platform`]: crypto,
/// timer, RNG, firmware) and the TPM state ([`State`], with its
/// NV data). Commands are sent to it as marshaled byte buffers, either with the inherent
/// `execute_command*` methods or through its [`tpm2::Connection`] implementation.
///
/// A new engine starts with a default (unmanufactured) state. A typical lifecycle is
/// [`TpmEngine::init_storage`] once at manufacture, [`TpmEngine::reset`] on every `_TPM_Init`
/// (power on), and then `TPM2_Startup`.
#[non_exhaustive]
pub struct TpmEngine<P: Platform> {
    /// The platform dependencies (crypto, timer, RNG, firmware, ...).
    pub platform: P,
    /// The volatile and non-volatile TPM state, including the NV data ([`crate::Nv::index`]).
    pub state: State<P>,
    /// The algorithm self-test state (`g_toTest`, and whether a self test failed, i.e. Failure
    /// mode), which TPM 2.0 Part 1 ("Command Dispatch") considers "different from the command
    /// execution state": see [`crate::self_test`].
    pub self_test: crate::self_test::SelfTestState,
    /// The crypto backend's random number generator (`C::Rng`, created from the backend's
    /// entropy source with [`tpm2::crypto::Random::from_entropy`] by [`TpmEngine::new`]). It is
    /// not part of the [`State`]: it is neither persisted nor serialized. It
    /// draws the values the default build takes from the crypto backend (response nonces,
    /// TPM-generated keys and seeds, secrets, see the `rng` module), the randomness of the
    /// randomized key operations (RSA padding and blinding, signature nonces) and absorbs the
    /// data of `TPM2_StirRandom`.
    pub crypto_rng: <P::Crypto as tpm2::crypto::Random>::Rng,
}

/// Error returned by the [`tpm2::Connection`] implementation of [`TpmEngine`] when the response
/// buffer cannot even hold a response header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseBufferTooSmall;

impl core::fmt::Display for ResponseBufferTooSmall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "response buffer is smaller than a response header ({} bytes)",
            ResponseHeader::MAX_SIZE
        )
    }
}

impl core::error::Error for ResponseBufferTooSmall {}

/// A [`TpmEngine`] is a TPM that is reached directly, without any transport: each transaction
/// executes the command in-process at the engine's current locality.
impl<P: Platform> tpm2::Connection for TpmEngine<P> {
    type Error = ResponseBufferTooSmall;

    fn transact<'r>(&mut self, cmd: &[u8], rsp: &'r mut [u8]) -> Result<&'r mut [u8], Self::Error> {
        // Every response (including an error response) starts with a full header, so a buffer
        // that cannot hold one cannot receive any response at all.
        if rsp.len() < ResponseHeader::MAX_SIZE {
            return Err(ResponseBufferTooSmall);
        }
        let written = self.execute_command_separate(cmd, rsp);
        Ok(&mut rsp[..written])
    }
}

/// Maximum number of loaded transient objects in RAM.
pub const MAX_LOADED_OBJECTS: usize = tpm2::TPM2_MAX_LOADED_OBJECTS as usize;
/// Maximum number of active authorization sessions in RAM (aligns with the TCG PC Client spec and the TCG reference implementation).
pub const MAX_LOADED_SESSIONS: usize = 3;
/// Maximum number of active (loaded or saved) authorization sessions (`MAX_ACTIVE_SESSIONS`); the
/// low 24 bits of a session handle index this many session slots.
pub const MAX_ACTIVE_SESSIONS: usize = tpm2::TPM2_MAX_ACTIVE_SESSIONS as usize;
/// The C reference's `CONTEXT_SLOT`: the low-order bits of the session context counter that
/// identify a saved session context (`gr.contextArray`). 16 bits.
type ContextSlot = u16;
/// `MAX_CONTEXT_GAP` of the C reference (the `CONTEXT_SLOT` range, see `ContextSlot`): the
/// largest permitted distance between the current session context counter and the sequence
/// number of a saved session context (also reported as `TPM_PT_CONTEXT_GAP_MAX + 1`).
pub const MAX_CONTEXT_GAP: u64 = ContextSlot::MAX as u64 + 1;
/// Maximum number of active hash/HMAC sequences in RAM.
pub const MAX_ACTIVE_SEQUENCES: usize = 3;

/// Largest command accepted by `TpmEngine::execute_command` (`MAX_COMMAND_SIZE`; the value
/// reported for `TPM_PT_MAX_COMMAND_SIZE`). Larger commands fail with `TPM_RC_COMMAND_SIZE`.
///
/// The size is implementation-defined (TPM 2.0 Part 2, `TPM_PT_MAX_COMMAND_SIZE`: "the maximum
/// value for *commandSize* in a command"); this TPM uses the TCG reference profile's `MAX_COMMAND_SIZE`
/// (`4096 - 0x80`), so that the same commands are accepted, or 8192 with the
/// `max-command-size-8192` feature (the TCG reference implementation version 185).
pub const MAX_COMMAND_SIZE: usize = if cfg!(feature = "max-command-size-8192") {
    8192
} else {
    4096 - 0x80
};

/// The size of `gr.commitNonce` (a `TPM2B_DIGEST` the reference fills completely): the largest
/// digest of the profile, 64 octets with SHA-512 and 48 without.
pub(crate) const COMMIT_NONCE_SIZE: usize = tpm2::TpmiAlgHash::MAX_DIGEST_BYTES;

/// The value reported for `TPM_PT_MAX_RESPONSE_SIZE` ("the maximum value for *responseSize* in a
/// response"): 4096, or 8192 with the `max-command-size-8192` feature.
pub const MAX_RESPONSE_SIZE: usize = if cfg!(feature = "max-command-size-8192") {
    8192
} else {
    4096
};

/// Buffer size for decrypted command parameters.
/// The parameter area can never be larger than the whole command, so sizing the buffer to
/// `MAX_COMMAND_SIZE` lets commands with a decrypt session carry the same parameters as commands
/// without sessions.
const DECRYPT_BUF_SIZE: usize = MAX_COMMAND_SIZE;
type DecryptBuf = [u8; DECRYPT_BUF_SIZE];

/// Magic value (`"DRBG"`) identifying an initialized SP800-90A CTR_DRBG state (`go.drbgState`).
pub const DRBG_MAGIC: u32 = 0x47425244;

/// Represents the internal NIST SP800-90A CTR_DRBG state (`go.drbgState` in `ibmswtpm2`).
///
/// This structure is committed to non-volatile storage (`ORDERLY_DATA`) on orderly shutdown
/// (`TPM2_Shutdown`) and restored and reseeded on subsequent orderly startup (`TPM2_Startup`).
/// It preserves accumulated entropy across power cycles and satisfies `ibmswtpm2` rollback assertions
/// (`pAssert(drbgState->magic == DRBG_MAGIC)`).
///
/// With the `reference-rng` feature, it is converted field by field to and from the reference
/// code's `DRBG_STATE` around every call into that code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrbgState {
    /// Reseed counter tracking requests since last reseed.
    pub reseed_counter: u64,
    /// Magic number (`DRBG_MAGIC = 0x47425244`).
    pub magic: u32,
    /// AES-256 key (32 bytes) and IV (16 bytes) seed material.
    pub seed: [u8; 48],
    /// Continuous health test history block for FIPS compliance.
    pub last_value: [u32; 4],
}

impl Default for DrbgState {
    fn default() -> Self {
        Self {
            reseed_counter: 0,
            magic: 0,
            seed: [0u8; 48],
            last_value: [0u32; 4],
        }
    }
}

impl DrbgState {
    /// Serializes the DRBG state into a 76-byte big-endian buffer for NV persistence.
    pub fn to_bytes(&self) -> [u8; 76] {
        let mut buf = [0u8; 76];
        buf[0..8].copy_from_slice(&self.reseed_counter.to_be_bytes());
        buf[8..12].copy_from_slice(&self.magic.to_be_bytes());
        buf[12..60].copy_from_slice(&self.seed);
        for (i, val) in self.last_value.iter().enumerate() {
            buf[60 + i * 4..60 + (i + 1) * 4].copy_from_slice(&val.to_be_bytes());
        }
        buf
    }

    /// Deserializes a 76-byte big-endian buffer into a `DrbgState`.
    pub fn from_bytes(buf: &[u8; 76]) -> Self {
        let reseed_counter = u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        let magic = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let mut seed = [0u8; 48];
        seed.copy_from_slice(&buf[12..60]);
        let mut last_value = [0u32; 4];
        for (i, val) in last_value.iter_mut().enumerate() {
            let off = 60 + i * 4;
            *val = u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        }
        Self {
            reseed_counter,
            magic,
            seed,
            last_value,
        }
    }

    /// Instantiates a fresh DRBG state (`DRBG_Instantiate`), drawing fresh entropy from `rng`.
    ///
    /// Draws 48 bytes of seed material from `rng` ([`Rng::fill_bytes`](tpm2::crypto::Rng::fill_bytes)), then 16 bytes for the
    /// continuous health test history (`last_value`).
    pub fn instantiate<R: tpm2::crypto::Rng>(&mut self, rng: &mut R) -> Result<(), TpmRc> {
        self.magic = DRBG_MAGIC;
        self.reseed_counter = 1;
        rng.fill_bytes(&mut self.seed).map_err(|_| TpmRc::FAILURE)?;
        let mut last_bytes = [0u8; 16];
        rng.fill_bytes(&mut last_bytes)
            .map_err(|_| TpmRc::FAILURE)?;
        for (i, val) in self.last_value.iter_mut().enumerate() {
            let off = i * 4;
            *val = u32::from_be_bytes([
                last_bytes[off],
                last_bytes[off + 1],
                last_bytes[off + 2],
                last_bytes[off + 3],
            ]);
        }
        Ok(())
    }

    /// Reseeds an existing DRBG state (`DRBG_Reseed`), mixing fresh platform entropy into `seed`.
    ///
    /// Draws 48 bytes of fresh entropy from `rng` ([`Rng::fill_bytes`](tpm2::crypto::Rng::fill_bytes)).
    pub fn reseed<R: tpm2::crypto::Rng>(&mut self, rng: &mut R) -> Result<(), TpmRc> {
        let mut entropy = [0u8; 48];
        rng.fill_bytes(&mut entropy).map_err(|_| TpmRc::FAILURE)?;
        for (s, e) in self.seed.iter_mut().zip(entropy.iter()) {
            *s ^= *e;
        }
        self.reseed_counter = 1;
        Ok(())
    }
}

/// Update type constants matching `UPDATE_TYPE` in `Global.h` (`g_updateNV`).
pub const UT_NONE: u8 = 0;
pub const UT_NV: u8 = 1;
pub const UT_ORDERLY: u8 = 3;

#[derive(Debug, Clone)]
pub struct ActiveSequence {
    pub handle: u32,
    pub auth: OwnedAuth,
    pub sequence_type: SequenceType,
    /// Whether a data block has been received (C `firstBlock`, see
    /// `handler::sequence::record_first_block`).
    pub first_block: bool,
    /// Whether the first data block makes a ticket safe (C `ticketSafe`: it is at least 4
    /// octets long and does not start with `TPM_GENERATED_VALUE`); meaningful once
    /// `first_block` is set.
    pub ticket_safe: bool,
    /// Portable streaming hash contexts (`HASH_STATE` parity with `ibmswtpm2`).
    /// For Hash/HMAC sequences, index 0 holds the active hash/inner-HMAC state.
    /// For Event sequences, indices 0..4 hold SHA-1, SHA-256, SHA-384, and SHA-512 states (the
    /// first [`Self::EVENT_HASH_COUNT`]: without SHA-512, the last slot is unused).
    pub hash_states: [crate::hash_state::StreamingHashState; 4],
    /// The running SHAKE256 computation of the ML-DSA message representative `mu` of an ML-DSA
    /// or HashML-DSA signing/verification sequence ([`SignatureSequence`]); `None` for every
    /// other sequence. It is saved in place of `hash_states[MU_STATE_SLOT]`, which such a
    /// sequence does not use.
    pub(crate) mu_state: Option<crate::shake256::Shake256>,
}

impl ActiveSequence {
    /// The number of hash states of an Event sequence: one per implemented hash (SHA-1,
    /// SHA-256, SHA-384 and, with the `sha512` feature of `tpm2`, SHA-512).
    pub const EVENT_HASH_COUNT: usize = if TpmiAlgHash::HASH_COUNT < 4 {
        TpmiAlgHash::HASH_COUNT
    } else {
        4
    };

    /// The hash states of an Event sequence ([`Self::EVENT_HASH_COUNT`]).
    pub fn event_hash_states(&self) -> &[crate::hash_state::StreamingHashState] {
        &self.hash_states[..Self::EVENT_HASH_COUNT]
    }

    /// Creates a new `ActiveSequence` with its streaming `hash_states` initialized for `sequence_type`.
    pub fn new(handle: u32, auth: impl Into<OwnedAuth>, sequence_type: SequenceType) -> Self {
        let auth = auth.into();
        let mut hash_states = [crate::hash_state::StreamingHashState::default(); 4];
        match sequence_type {
            SequenceType::Hash { alg } => {
                hash_states[0] = crate::hash_state::StreamingHashState::new(alg);
            }
            SequenceType::Hmac { hash_alg, key } => {
                hash_states[0] =
                    crate::hash_state::init_hmac_inner_state(hash_alg, key.get_buffer());
            }
            // The CMAC state is in the sequence type.
            #[cfg(feature = "cmac")]
            SequenceType::Cmac { .. } => {}
            SequenceType::Event => {
                hash_states[0] = crate::hash_state::StreamingHashState::new(TpmiAlgHash::Sha1);
                hash_states[1] = crate::hash_state::StreamingHashState::new(TpmiAlgHash::Sha256);
                hash_states[2] = crate::hash_state::StreamingHashState::new(TpmiAlgHash::Sha384);
                if let Some(sha512) = crate::handler::capability::sha512() {
                    hash_states[3] = crate::hash_state::StreamingHashState::new(sha512);
                }
            }
            // The message state of a signing or verification sequence; the ticket states of a
            // verification sequence are keyed by the handler, which knows the hierarchy proof
            // (see [`SignatureSequence::ticket_hierarchy`]).
            SequenceType::Sign(seq) | SequenceType::Verify(seq) => {
                hash_states[0] = seq.initial_message_state();
            }
        }
        Self {
            handle,
            auth,
            sequence_type,
            first_block: false,
            ticket_safe: false,
            hash_states,
            mu_state: None,
        }
    }

    /// The index of `hash_states` whose place the ML-DSA `mu_state` takes when the sequence is
    /// saved.
    pub const MU_STATE_SLOT: usize = 3;

    /// Whether a sequence of `sequence_type` keeps an ML-DSA `mu_state`.
    pub fn has_mu_state(sequence_type: &SequenceType) -> bool {
        matches!(
            sequence_type,
            SequenceType::Sign(seq) | SequenceType::Verify(seq)
                if matches!(seq.scheme, tpm2::TpmtSigScheme::Mldsa | tpm2::TpmtSigScheme::HashMldsa)
        )
    }

    /// Serializes the state of slot `i` for a saved sequence:
    /// `hash_states[i]`, or for [`Self::MU_STATE_SLOT`] of an ML-DSA sequence its `mu_state`
    /// (zero-padded), always [`crate::hash_state::StreamingHashState::SERIALIZED_SIZE`] bytes.
    pub fn serialize_state(&self, i: usize, dst: &mut [u8]) -> usize {
        const SIZE: usize = crate::hash_state::StreamingHashState::SERIALIZED_SIZE;
        const _: () = assert!(crate::shake256::SHAKE256_EXPORT_SIZE <= SIZE);
        if i == Self::MU_STATE_SLOT
            && let Some(mu) = &self.mu_state
        {
            let bytes = mu.to_bytes();
            dst[..bytes.len()].copy_from_slice(&bytes);
            dst[bytes.len()..SIZE].fill(0);
            return SIZE;
        }
        self.hash_states[i].serialize(dst)
    }

    /// Restores the `mu_state` of an ML-DSA sequence from the saved slot
    /// [`Self::MU_STATE_SLOT`] (see [`Self::serialize_state`]).
    pub(crate) fn mu_state_from_slot(slot: &[u8]) -> Option<crate::shake256::Shake256> {
        let bytes = slot.get(..crate::shake256::SHAKE256_EXPORT_SIZE)?;
        crate::shake256::Shake256::from_bytes(bytes.try_into().ok()?)
    }

    /// Feeds `data` into the message state of a signing or verification sequence: the running
    /// `mu` of pure ML-DSA, which signs the message itself, or `hash_states[0]` (the digest of the
    /// message, its HMAC, or the pre-hash of HashML-DSA).
    fn update_message_state(&mut self, seq: &SignatureSequence, data: &[u8]) {
        match (seq.scheme, &mut self.mu_state) {
            (tpm2::TpmtSigScheme::Mldsa, Some(mu)) => mu.update(data),
            _ => self.hash_states[0].update(data),
        }
    }

    /// Feeds input data into the active streaming hash state(s). A CMAC sequence (whose
    /// update needs the block cipher of the crypto backend) is updated by
    /// `TPM2_SequenceUpdate` itself.
    pub fn update_hash_states(&mut self, data: &[u8]) {
        match self.sequence_type {
            SequenceType::Hash { .. } | SequenceType::Hmac { .. } => {
                self.hash_states[0].update(data);
            }
            #[cfg(feature = "cmac")]
            SequenceType::Cmac { .. } => {}
            SequenceType::Sign(seq) => self.update_message_state(&seq, data),
            SequenceType::Verify(seq) => {
                self.update_message_state(&seq, data);
                if seq.ticket_hierarchy.is_some() {
                    self.hash_states[SignatureSequence::TICKET_INNER_STATE].update(data);
                }
            }
            SequenceType::Event => {
                for state in &mut self.hash_states[..Self::EVENT_HASH_COUNT] {
                    state.update(data);
                }
            }
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceType {
    Hash {
        alg: TpmiAlgHash,
    },
    Hmac {
        hash_alg: TpmiAlgHash,
        key: OwnedSensitiveData,
    },
    /// A MAC sequence of `TPM2_MAC_Start` with `TPM_ALG_CMAC` (the `cmac` feature): the
    /// streaming CMAC state, which includes the key.
    #[cfg(feature = "cmac")]
    Cmac {
        state: crate::cmac::CmacState,
    },
    Event,
    /// A signing sequence started by `TPM2_SignSequenceStart` (C `attributes.signSeq`).
    Sign(SignatureSequence),
    /// A signature verification sequence started by `TPM2_VerifySequenceStart` (C
    /// `attributes.verifySeq`).
    Verify(SignatureSequence),
}

/// The state of a signing (`TPM2_SignSequenceStart`) or verification
/// (`TPM2_VerifySequenceStart`) sequence that is not in its streaming hash states (C
/// `SEQUENCE_OBJECT.signScheme`/`associatedName`).
///
/// `ActiveSequence::hash_states[0]` accumulates the message: a running hash with the hash of
/// [`Self::scheme`] for a scheme that signs a digest of the message (RSASSA, RSAPSS, ECDSA), or
/// the inner state of a running HMAC keyed with [`Self::hmac_key`] for `TPM_ALG_HMAC`, which signs
/// the message itself. For a verification sequence with a ticket,
/// `hash_states[TICKET_INNER_STATE]` and `hash_states[TICKET_OUTER_STATE]` are the inner state (with
/// the tag and the message so far) and the outer state of the running HMAC of the
/// `TPM_ST_MESSAGE_VERIFIED` ticket, keyed with the proof of [`Self::ticket_hierarchy`] when the
/// sequence was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureSequence {
    /// The signing scheme of the key that started the sequence: the scheme the signature is
    /// produced or checked with (the sequence commands cannot override it).
    pub scheme: tpm2::TpmtSigScheme,
    /// The Name of the key that started the sequence: `TPM2_SignSequenceComplete` /
    /// `TPM2_VerifySequenceComplete` require a key with the same Name
    /// (`TPM_RC_SIGN_CONTEXT_KEY`).
    pub key_name: OwnedName,
    /// The HMAC key (the key's sensitive `bits`) of a `TPM_ALG_HMAC` sequence, needed to finish
    /// the running HMAC; empty for the other schemes.
    pub hmac_key: OwnedSensitiveData,
    /// For a verification sequence, the hierarchy of the `TPM_ST_MESSAGE_VERIFIED` ticket the
    /// sequence produces (the hierarchy of the key when the sequence was started), whose proof
    /// keys the running ticket HMAC; `None` for a signing sequence and when the ticket is a NULL
    /// Ticket (a key in `TPM_RH_NULL` or with nameAlg `TPM_ALG_NULL`).
    pub ticket_hierarchy: Option<u32>,
    /// The pre-hash function of a HashML-DSA sequence (the key's `hashAlg`), whose running
    /// digest of the message is `hash_states[0]`; `None` for the other schemes.
    pub pre_hash: Option<TpmiAlgHash>,
}

impl SignatureSequence {
    /// The index of the inner state of the running ticket HMAC in `ActiveSequence::hash_states`.
    pub const TICKET_INNER_STATE: usize = 1;
    /// The index of the outer state of the running ticket HMAC in `ActiveSequence::hash_states`.
    pub const TICKET_OUTER_STATE: usize = 2;

    /// The largest serialization of [`Self::serialize`].
    pub const SERIALIZED_MAX_SIZE: usize = tpm2::TpmtSigScheme::MAX_SIZE
        + tpm2::Tpm2bName::MAX_SIZE
        + tpm2::Tpm2bSensitiveData::MAX_SIZE
        + 4
        + 2;

    /// Serializes the sequence state into `dst` (at least [`Self::SERIALIZED_MAX_SIZE`] bytes)
    /// for a saved context or the state-save data: the scheme (`TPMT_SIG_SCHEME`), the key
    /// Name and the HMAC key (`TPM2B`s), and the ticket hierarchy (0 for none). Returns the
    /// number of bytes written.
    pub fn serialize(&self, dst: &mut [u8]) -> usize {
        let mut offset = self.scheme.marshal(
            (&mut dst[..tpm2::TpmtSigScheme::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset += self.key_name.marshal(
            (&mut dst[offset..offset + tpm2::Tpm2bName::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        offset += self.hmac_key.marshal(
            (&mut dst[offset..offset + tpm2::Tpm2bSensitiveData::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        dst[offset..offset + 4].copy_from_slice(&self.ticket_hierarchy.unwrap_or(0).to_be_bytes());
        let pre_hash = self.pre_hash.map_or(0, |alg| tpm2::Alg::from(alg).id());
        dst[offset + 4..offset + 6].copy_from_slice(&pre_hash.to_be_bytes());
        offset + 6
    }

    /// Deserializes a state written by [`Self::serialize`], advancing `src`.
    pub fn deserialize(src: &mut &[u8]) -> Option<Self> {
        let scheme = tpm2::TpmtSigScheme::unmarshal(src).ok()?;
        let key_name = OwnedName::unmarshal(src).ok()?;
        let hmac_key = OwnedSensitiveData::unmarshal(src).ok()?;
        let ticket_hierarchy = u32::unmarshal(src).ok()?;
        let pre_hash_id = u16::unmarshal(src).ok()?;
        let pre_hash = match pre_hash_id {
            0 => None,
            id => Some(TpmiAlgHash::unmarshal(&mut &id.to_be_bytes()[..]).ok()?),
        };
        Some(Self {
            scheme,
            key_name,
            hmac_key,
            ticket_hierarchy: (ticket_hierarchy != 0).then_some(ticket_hierarchy),
            pre_hash,
        })
    }

    /// The initial message state for [`Self::scheme`] (see the type documentation).
    pub fn initial_message_state(&self) -> crate::hash_state::StreamingHashState {
        match self.scheme {
            tpm2::TpmtSigScheme::Hmac(hash_alg) => {
                crate::hash_state::init_hmac_inner_state(hash_alg, self.hmac_key.get_buffer())
            }
            scheme => match scheme.hash_alg().or(self.pre_hash) {
                Some(hash_alg) => crate::hash_state::StreamingHashState::new(hash_alg),
                None => crate::hash_state::StreamingHashState::default(),
            },
        }
    }
}

/// A parsed representation of an incoming TPM command with authorization sessions (tag 0x8002).
/// To avoid copying large arrays on the stack for every command, `parameters` and
/// `ciphertext_parameters` are stored as references (`&'cmd [u8]`) borrowing directly from
/// the input buffer or from a short-lived decryption buffer when parameter decryption is active.
struct ParsedCommand<'cmd> {
    handles: [u32; 3],
    handles_len: usize,
    auth_sessions: [OwnedAuthCommand; 3],
    auth_sessions_len: usize,
    session_to_handle_idx: [usize; 3],
    session_to_handle_idx_len: usize,
    parameters: &'cmd [u8],
    ciphertext_parameters: &'cmd [u8],
    handle_auths: [OwnedAuth; 3],
}

/// Inputs to [`TpmEngine::check_policy_auth_session`] describing one policy session that is
/// used to authorize one handle of the current command.
struct PolicyAuthCheck<'a> {
    /// Handle of the policy session (`0x03xxxxxx`).
    session_handle: u32,
    /// The entity whose authorization the session provides (C `s_associatedHandles[i]`).
    entity_handle: u32,
    /// Index of `entity_handle` in the command's handle area (used for the auth role).
    handle_index: usize,
    /// Command code of the command being authorized.
    command_code: u32,
    /// Command parameter area as received on the wire (still encrypted, as in the C reference).
    parameters: &'a [u8],
    /// cpHash of the command computed with the session's `authHashAlg`.
    cp_hash: &'a [u8],
    /// Names of all handles in the command's handle area, in order.
    handle_names: &'a [OwnedName],
    /// Response-code position of the session (`TPM_RC_S + index`).
    pos: Position,
}

/// Nominal clock-rate divisor of the platform timer (`CLOCK_NOMINAL` in the C platform `Clock.c`).
pub(crate) const CLOCK_NOMINAL: u32 = 30000;
/// Divisor step for `TPM_CLOCK_COARSE_SLOWER/FASTER` (`CLOCK_ADJUST_COARSE`).
pub(crate) const CLOCK_ADJUST_COARSE: u32 = 300;
/// Divisor step for `TPM_CLOCK_MEDIUM_SLOWER/FASTER` (`CLOCK_ADJUST_MEDIUM`).
pub(crate) const CLOCK_ADJUST_MEDIUM: u32 = 30;
/// Divisor step for `TPM_CLOCK_FINE_SLOWER/FASTER` (`CLOCK_ADJUST_FINE`).
pub(crate) const CLOCK_ADJUST_FINE: u32 = 1;
/// Maximum deviation of the divisor from [`CLOCK_NOMINAL`] (`CLOCK_ADJUST_LIMIT`).
pub(crate) const CLOCK_ADJUST_LIMIT: u32 = 5000;
/// `NV_CLOCK_UPDATE_INTERVAL`: `Clock` is written to NV whenever it crosses a multiple of
/// `2^NV_CLOCK_UPDATE_INTERVAL` ms (`TimeClockUpdate`).
pub(crate) const NV_CLOCK_UPDATE_INTERVAL: u32 = 22;

// The layouts of the engine's NV records (the reserved header and the internal records
// `0x00FF_FFFC..=0x00FF_FFFF`) are defined in `crate::storage::nv`.
pub(crate) use crate::storage::nv::PCR_ALLOCATION_HANDLE;
use crate::storage::nv::{
    HIERARCHY_RECORD_HANDLE, NvAuditExt, NvHeader, NvHierarchyRecord, NvHierarchySeeds,
    NvLifecycleExt, NvPcrAllocationRecord, NvPersistentObjectRecord, NvStateSaveRecord,
    STATE_SAVE_HANDLE,
};

impl<P: Platform> State<P> {
    pub fn init_zeroed(&mut self) {
        self.nv.persistent.total_reset_count = 1;
        self.nv_available = true;
        self.nv.clear.sh_enable = true;
        self.nv.clear.eh_enable = true;
        self.nv.clear.ph_enable_nv = true;
        self.ph_enable = true;
        // Seeds and proofs stay unprovisioned until manufacture (`init_storage`) or the NV
        // hierarchy record supplies them; nullProof is drawn at TPM Reset.
        self.nv.persistent.sh_proof_size = 0;
        self.nv.persistent.eh_proof_size = 0;
        self.nv.persistent.ph_proof = [0; 64];
        self.nv.persistent.ph_proof_size = 0;
        self.nv.reset.null_proof_size = 0;
        self.nv.persistent.failed_tries = 0;
        self.nv.persistent.max_tries = 3;
        self.nv.persistent.recovery_time = 1000;
        self.nv.persistent.lockout_recovery = 1000;
        self.nv.orderly.clock_offset = self
            .nv
            .orderly
            .clock_offset
            .wrapping_add(self.tpm_time_ms as i64);
        self.tpm_time_ms = 0;
        self.last_timer_read_ms = None;
        self.nv.orderly.self_heal_timer = 0;
        self.nv.orderly.lockout_timer = 0;
        self.nv.persistent.lockout_auth_enabled = true;
        self.da_pending_on_nv = false;
        self.nv.reset.commit_nonce = [0x5a; COMMIT_NONCE_SIZE];
        self.nv.persistent.audit_hash_alg =
            tpm2::Alg::from(crate::handler::context_integrity_hash_alg()).id();
        self.nv.persistent.audit_commands =
            crate::command_audit::CommandAuditList::manufacture_default();
    }

    pub fn reset_in_place(&mut self) {
        self.initialized = false;
        self.nv.persistent.reset_count = 0;
        self.nv.reset.restart_count = 0;
        self.nv.reset.clear_count = 0;
        self.locality = 0;
        self.nv_available = true;
        self.g_nv_ok = false;
        self.nv.persistent.orderly_state = 0;
        self.update_nv = UT_NONE;
        self.clear_orderly = false;
        self.drtm_pre_startup = false;
        self.drtm_handle = Handle::RH_UNASSIGNED.0;
        self.startup_locality_3 = false;
        self.da_used = false;
        self.da_pending_on_nv = false;
        self.nv.persistent.disable_clear = false;
        self.nv.clear.sh_enable = true;
        self.nv.clear.eh_enable = true;
        self.nv.clear.ph_enable_nv = true;
        self.ph_enable = true;
        self.nv.persistent.sh_proof = [0; 64];
        self.nv.persistent.eh_proof = [0; 64];
        self.nv.persistent.ph_proof = [0; 64];
        self.nv.persistent.sp_seed = [0; 64];
        self.nv.persistent.pp_seed = [0; 64];
        self.nv.persistent.ep_seed = [0; 64];
        // Unprovisioned until manufacture (`init_storage`) or the NV hierarchy record.
        self.nv.persistent.sh_proof_size = 0;
        self.nv.persistent.eh_proof_size = 0;
        self.nv.persistent.ph_proof_size = 0;
        self.nv.persistent.sp_seed_size = 0;
        self.nv.persistent.pp_seed_size = 0;
        self.nv.persistent.ep_seed_size = 0;
        self.nv.reset.null_seed = [0; 64];
        self.nv.reset.null_seed_size = 0;
        self.nv.reset.null_proof = [0; 64];
        self.nv.reset.null_proof_size = 0;
        for obj in self.transient_objects.iter_mut() {
            *obj = None;
        }
        for sess in self.active_sessions.iter_mut() {
            *sess = None;
        }
        for sess in self.nv.reset.saved_sessions.iter_mut() {
            *sess = None;
        }
        self.nv.reset.saved_session_sequences = [0; MAX_ACTIVE_SESSIONS];
        for seq in self.active_sequences.iter_mut() {
            *seq = None;
        }
        self.command_persistent_objects = 0;
        self.nv.persistent.owner_auth = Default::default();
        self.nv.persistent.endorsement_auth = Default::default();
        self.nv.clear.platform_auth = Default::default();
        self.nv.persistent.lockout_auth = Default::default();
        self.nv.persistent.owner_policy = Default::default();
        self.nv.persistent.endorsement_policy = Default::default();
        self.nv.clear.platform_policy = Default::default();
        self.nv.persistent.lockout_policy = Default::default();
        self.nv.persistent.owner_alg = None;
        self.nv.persistent.endorsement_alg = None;
        self.nv.clear.platform_alg = None;
        self.nv.persistent.lockout_alg = None;
        self.nv.reset.commit_counter = 0;
        self.nv.reset.commit_array = [0u8; 16];
        self.nv.reset.commit_nonce = [0x5a; COMMIT_NONCE_SIZE];
        self.nv.reset.context_counter = 0;
        self.nv.reset.object_context_counter = 0;
        for auth in self.parsed_auths.iter_mut() {
            *auth = Default::default();
        }
        self.parsed_auths_len = 0;
        self.session_audit_cp_hashes = [None; 3];
        self.sessions_validated_by_handler = false;
        self.exclusive_audit_session = None;
        self.in_shadow_execution = false;
        // *Time* and the platform clock-rate adjustment are kept: only a power on resets them
        // (`_plat__TimerReset()`, [`TpmEngine::platform_timer_reset`]).
        // The persistent command audit state is reloaded from NV by `restore_hierarchy_auths`;
        // these manufacture defaults only remain if NV holds no audit record.
        self.nv.persistent.audit_hash_alg =
            tpm2::Alg::from(crate::handler::context_integrity_hash_alg()).id();
        self.nv.persistent.audit_commands =
            crate::command_audit::CommandAuditList::manufacture_default();
        self.nv.persistent.audit_counter = 0;
        self.command_audit_cp_hash = None;
        self.command_audit_alg_changed = false;
        // `gp.ppList` and `gp.algorithmSet` are reloaded from NV by
        // `restore_platform_settings`; these manufacture defaults only remain without a record.
        // Physical Presence is a platform input and is kept.
        self.nv.persistent.pp_list = crate::physical_presence::PpList::manufacture_default();
        self.nv.persistent.algorithm_set = 0;
    }
    /// Adds a session to the active sessions array.
    /// Returns `Err(TpmRc::SESSION_MEMORY)` if there are no available slots.
    pub fn add_session(&mut self, session: SessionState) -> Result<(), TpmRc> {
        for slot in &mut self.active_sessions {
            if slot.is_none() {
                *slot = Some(session);
                return Ok(());
            }
        }
        Err(TpmRc::SESSION_MEMORY)
    }

    /// Gets a reference to an active session by its handle.
    pub fn session(&self, handle: u32) -> Option<&SessionState> {
        self.active_sessions
            .iter()
            .flatten()
            .find(|session| session.session_handle == handle)
    }

    /// Gets the active session occupying the session slot of `handle`, ignoring the handle type
    /// byte (C `SessionIsLoaded()`/`SessionGet()` index sessions by `handle & 0x00FF_FFFF`).
    ///
    /// The returned session's `session_handle` may differ from `handle` in its type byte (an HMAC
    /// session referenced as a policy session or vice versa); callers report that case as
    /// `TPM_RC_HANDLE`, and a missing slot as `TPM_RC_REFERENCE_*`.
    pub fn session_by_slot(&self, handle: u32) -> Option<&SessionState> {
        self.active_sessions
            .iter()
            .flatten()
            .find(|session| session.session_handle & 0x00FF_FFFF == handle & 0x00FF_FFFF)
    }

    /// Gets a mutable reference to an active session by its handle.
    pub fn session_mut(&mut self, handle: u32) -> Option<&mut SessionState> {
        self.active_sessions
            .iter_mut()
            .flatten()
            .find(|session| session.session_handle == handle)
    }

    /// Removes and returns an active session by its handle.
    pub fn remove_session(&mut self, handle: u32) -> Option<SessionState> {
        for slot in &mut self.active_sessions {
            if let Some(session) = slot
                && session.session_handle == handle
            {
                if self.exclusive_audit_session == Some(handle) {
                    self.exclusive_audit_session = None;
                }
                return slot.take();
            }
        }
        None
    }

    /// Flushes (removes) an active session by its handle, returning an error if not found.
    pub fn flush_session(&mut self, handle: u32) -> Result<(), TpmRc> {
        if self.remove_session(handle).is_none() {
            Err(TpmRc::HANDLE.to_rc())
        } else {
            Ok(())
        }
    }

    /// Returns the session slot (`handle & HR_HANDLE_MASK`) of `handle` if that slot holds a
    /// saved session context (`SessionIsSaved`). The handle type byte is ignored, as in C.
    pub fn saved_session_slot(&self, handle: u32) -> Option<usize> {
        let slot = (handle & 0x00FF_FFFF) as usize;
        (slot < MAX_ACTIVE_SESSIONS && self.nv.reset.saved_sessions[slot].is_some()).then_some(slot)
    }

    /// Returns the slot of the oldest saved session context (smallest sequence number), if any
    /// (`s_oldestSavedSession` / `ContextIdSetOldest`).
    pub fn oldest_saved_session_slot(&self) -> Option<usize> {
        (0..MAX_ACTIVE_SESSIONS)
            .filter(|&slot| self.nv.reset.saved_sessions[slot].is_some())
            .min_by_key(|&slot| self.nv.reset.saved_session_sequences[slot])
    }

    /// Returns `true` if the context gap is exhausted: the low bits (`ContextSlot`) of the
    /// session context counter (the `CONTEXT_SLOT` value the next save would use) equal those of
    /// the oldest saved session context, so saving another context would make the oldest
    /// ambiguous.
    pub fn context_gap_exhausted(&self) -> bool {
        self.oldest_saved_session_slot().is_some_and(|slot| {
            (self.nv.reset.saved_session_sequences[slot] as ContextSlot)
                == (self.nv.reset.context_counter as ContextSlot)
        })
    }

    /// Assigns the context sequence number for saving the loaded session `handle` and moves
    /// it from the loaded to the saved session table (`SessionContextSave`).
    ///
    /// Returns `TPM_RC_CONTEXT_GAP` if the gap to the oldest saved session is exhausted and
    /// `TPM_RC_TOO_MANY_CONTEXTS` if the 64-bit counter would roll over. Saving a session does
    /// not affect its exclusive-audit status (only a flush or a later command can end that).
    pub fn save_session_context(&mut self, handle: u32) -> Result<u64, TpmRc> {
        let slot = (handle & 0x00FF_FFFF) as usize;
        if slot >= MAX_ACTIVE_SESSIONS || self.session(handle).is_none() {
            return Err(TpmRc::FAILURE);
        }
        // The low counter values 0..=MAX_LOADED_SESSIONS mark loaded sessions in the C
        // `contextArray` and are never used as context IDs.
        let low = self.nv.reset.context_counter as ContextSlot as u64;
        if low <= MAX_LOADED_SESSIONS as u64 {
            self.nv.reset.context_counter += MAX_LOADED_SESSIONS as u64 + 1 - low;
        }
        if self.context_gap_exhausted() {
            return Err(TpmRc::CONTEXT_GAP);
        }
        let sequence = self.nv.reset.context_counter;
        self.nv.reset.context_counter = self
            .nv
            .reset
            .context_counter
            .checked_add(1)
            .ok_or(TpmRc::TOO_MANY_CONTEXTS)?;
        if (self.nv.reset.context_counter as ContextSlot) == 0 {
            self.nv.reset.context_counter += MAX_LOADED_SESSIONS as u64 + 1;
        }
        self.nv.reset.saved_sessions[slot] = Some(handle);
        self.nv.reset.saved_session_sequences[slot] = sequence;
        for entry in &mut self.active_sessions {
            if entry
                .as_ref()
                .is_some_and(|session| session.session_handle == handle)
            {
                *entry = None;
            }
        }
        Ok(sequence)
    }

    /// Returns `true` if `sequence` is the context sequence number of the saved session in the
    /// slot of `handle` and lies within the context gap window
    /// (`SequenceNumberForSavedContextIsValid`).
    pub fn saved_session_sequence_is_valid(&self, handle: u32, sequence: u64) -> bool {
        self.saved_session_slot(handle).is_some_and(|slot| {
            self.nv.reset.saved_session_sequences[slot] == sequence
                && sequence <= self.nv.reset.context_counter
                && self.nv.reset.context_counter - sequence <= MAX_CONTEXT_GAP
        })
    }

    /// Removes the saved-session record of the slot of `handle` (on load or flush).
    pub fn remove_saved_session(&mut self, handle: u32) {
        if let Some(slot) = self.saved_session_slot(handle) {
            self.nv.reset.saved_sessions[slot] = None;
            self.nv.reset.saved_session_sequences[slot] = 0;
        }
    }

    /// Finds the index in transient_objects of a transient object by its handle.
    pub fn find_transient_index(&self, handle: u32) -> Option<usize> {
        self.transient_objects
            .iter()
            .enumerate()
            .find_map(|(i, slot)| {
                if let Some(obj) = slot
                    && obj.handle == handle
                {
                    return Some(i);
                }
                None
            })
    }

    /// Finds a transient object by its handle.
    pub fn find_transient_object(&self, handle: u32) -> Option<&TransientObject> {
        self.transient_objects
            .iter()
            .flatten()
            .find(|obj| obj.handle == handle)
    }

    /// Finds a transient object by its handle mutably.
    pub fn find_transient_object_mut(&mut self, handle: u32) -> Option<&mut TransientObject> {
        self.transient_objects
            .iter_mut()
            .flatten()
            .find(|obj| obj.handle == handle)
    }

    /// Removes a transient object by its handle, returning `Ok(())` if found and removed.
    pub fn remove_transient_object(&mut self, handle: u32) -> Result<(), TpmRc> {
        for slot in self.transient_objects.iter_mut() {
            if let Some(obj) = slot
                && obj.handle == handle
            {
                *slot = None;
                return Ok(());
            }
        }
        Err(TpmRc::HANDLE.to_rc())
    }

    /// Finds an active sequence by its handle.
    pub fn find_active_sequence(&self, handle: u32) -> Option<&ActiveSequence> {
        self.active_sequences
            .iter()
            .flatten()
            .find(|seq| seq.handle == handle)
    }

    /// Finds an active sequence by its handle mutably.
    pub fn find_active_sequence_mut(&mut self, handle: u32) -> Option<&mut ActiveSequence> {
        self.active_sequences
            .iter_mut()
            .flatten()
            .find(|seq| seq.handle == handle)
    }

    /// Removes an active sequence by its handle, returning `Ok(())` if found and removed.
    pub fn remove_active_sequence(&mut self, handle: u32) -> Result<(), TpmRc> {
        for slot in &mut self.active_sequences {
            if let Some(seq) = slot
                && seq.handle == handle
            {
                *slot = None;
                return Ok(());
            }
        }
        Err(TpmRc::HANDLE.to_rc())
    }

    /// Finds the lowest free transient handle (`TRANSIENT_FIRST..=TRANSIENT_LAST`) that is not in use by either
    /// loaded transient objects or active sequences, enforcing the shared `MAX_LOADED_OBJECTS` (`3`)
    /// capacity across transient objects, sequences and the persistent objects referenced by the
    /// current command (`s_objects` parity with the C references).
    ///
    /// The handle of a new object is implementation-specific (Part 1, "Transient Object Handles":
    /// "The TPM assigns Object handles when an Object is loaded [...] Transient Objects in TPM
    /// RAM have handles with an MSO of $80_{16}$."; the three LSOs are not specified), so tpm-rs
    /// numbers objects like the TCG reference: each persistent object referenced by the command
    /// has been copied into the lowest free object slot (`ObjectLoadEvict` →
    /// `ObjectAllocateSlot`, in handle order) for the duration of the command, so a new object
    /// gets the first free slot after those `command_persistent_objects` copies (e.g.
    /// `TPM2_HMAC_Start` with a persistent key and nothing else loaded returns `0x80000001`).
    pub fn find_next_transient_handle(&self) -> Result<u32, TpmRc> {
        let total_loaded = self.transient_objects.iter().flatten().count()
            + self.active_sequences.iter().flatten().count()
            + self.command_persistent_objects;
        if total_loaded >= MAX_LOADED_OBJECTS {
            return Err(TpmRc::OBJECT_MEMORY);
        }
        (0..(MAX_LOADED_OBJECTS as u32))
            .map(|i| 0x8000_0000 | i)
            .filter(|&handle| {
                self.find_transient_object(handle).is_none()
                    && self.find_active_sequence(handle).is_none()
            })
            .nth(self.command_persistent_objects)
            .ok_or(TpmRc::OBJECT_MEMORY)
    }

    /// Finds an empty slot for a new active sequence and returns its index and the transient handle to be assigned.
    pub fn find_empty_sequence_slot(&mut self) -> Result<(usize, u32), TpmRc> {
        let handle = self.find_next_transient_handle()?;
        let index = self
            .active_sequences
            .iter()
            .position(|seq| seq.is_none())
            .ok_or(TpmRc::OBJECT_MEMORY)?;
        Ok((index, handle))
    }

    pub fn find_empty_transient_slot(&mut self, _is_primary: bool) -> Result<(usize, u32), TpmRc> {
        let index = self
            .transient_objects
            .iter()
            .position(|obj| obj.is_none())
            .ok_or(TpmRc::OBJECT_MEMORY)?;
        let handle = self.find_next_transient_handle()?;
        Ok((index, handle))
    }
}

impl<P: Platform> TpmEngine<P> {
    /// Returns the current adjusted clock value in milliseconds (`go.clock`).
    pub fn get_clock(&self) -> u64 {
        // `clock_offset` is the two's-complement difference `Clock - Time`, so wrapping arithmetic
        // yields the exact clock for every value up to `0xFFFF_0000_0000_0000` (`TPM2_ClockSet`).
        self.state
            .tpm_time_ms
            .wrapping_add(self.state.nv.orderly.clock_offset as u64)
    }

    /// Returns the current `TpmsClockInfo` structure.
    pub fn get_clock_info(&self) -> tpm2::TpmsClockInfo {
        tpm2::TpmsClockInfo {
            clock: self.get_clock(),
            reset_count: self.state.nv.persistent.reset_count,
            restart_count: self.state.nv.reset.restart_count,
            // `TimeFillInfo`: the clock is not "safe" while NV is unavailable (it stops advancing).
            safe: self.state.nv_available && self.state.nv.orderly.clock_safe,
        }
    }

    /// Returns the current `TpmsTimeInfo` structure (`g_time` and `clock_info`).
    pub fn get_time_info(&self) -> tpm2::TpmsTimeInfo {
        tpm2::TpmsTimeInfo {
            time: self.state.tpm_time_ms,
            clock_info: self.get_clock_info(),
        }
    }

    /// Gets the authorization value associated with a handle (either a hierarchy, a transient object, an NV Index, or a persistent object).
    pub fn handle_auth(&mut self, handle: u32) -> OwnedAuth {
        // A firmware-limited or SVN-limited hierarchy is authorized by its base hierarchy (TPM
        // 2.0 Part 1, "Primary Seed Authorizations"; C `HierarchyNormalizeHandle`).
        let handle = crate::hierarchy::normalize(handle);
        if handle == Handle::RH_OWNER.0 {
            self.state.nv.persistent.owner_auth
        } else if handle == Handle::RH_ENDORSEMENT.0 {
            self.state.nv.persistent.endorsement_auth
        } else if handle == Handle::RH_PLATFORM.0 || crate::act::is_implemented_act(handle) {
            // Part 1, "Authenticated Countdown Timer (ACT)": "The *authValue* is the same as the
            // current *platformAuth*".
            self.state.nv.clear.platform_auth
        } else if handle == Handle::RH_LOCKOUT.0 {
            self.state.nv.persistent.lockout_auth
        } else if is_vendor_permanent_auth(handle) {
            self.state.platform_unique_details
        } else if let Some(seq) = self.state.find_active_sequence(handle) {
            seq.auth
        } else if let Some(obj) = self.state.find_transient_object(handle) {
            obj.auth
        } else if Handle(handle).handle_type() == Some(TpmHt::NVIndex) {
            let storage_mgr = &mut self.state.nv.index;
            if let Ok(metadata) = storage_mgr.get_metadata(handle) {
                let read_len = core::cmp::min(metadata.data_size as usize, 1536);
                let mut read_buf = [0u8; 1536];
                if storage_mgr
                    .read_item(handle, 0, &mut read_buf[..read_len])
                    .is_ok()
                    && let Ok((_, _, auth, _)) =
                        crate::handler::nv_storage::unmarshal_nv_header(&read_buf[..read_len])
                {
                    return OwnedAuth::from(auth);
                }
            }
            OwnedAuth::default()
        } else if (0x81000000..=0x81FFFFFF).contains(&handle) {
            // A persistent object of a disabled hierarchy looks undefined (`ObjectLoadEvict`).
            self.load_persistent_object(handle)
                .map(|obj| obj.auth)
                .unwrap_or_default()
        } else if crate::handler::pcr::pcr_belongs_auth_group(handle) {
            self.state.nv.clear.pcr_auth_value
        } else {
            OwnedAuth::default()
        }
    }

    /// Gets the Name associated with a handle.
    pub fn handle_name(&mut self, handle: u32) -> OwnedName {
        if self.state.find_active_sequence(handle).is_some() {
            return OwnedName::default();
        }
        handle_name(self, handle)
    }

    /// Gets the auth policy associated with a handle.
    pub fn handle_policy(&mut self, handle: u32) -> Result<OwnedDigest, TpmRc> {
        // A firmware-limited or SVN-limited hierarchy is authorized by its base hierarchy (TPM
        // 2.0 Part 1, "Primary Seed Authorizations"; C `HierarchyNormalizeHandle`).
        let handle = crate::hierarchy::normalize(handle);
        if handle == Handle::RH_OWNER.0 {
            return Ok(self.state.nv.persistent.owner_policy);
        }
        if handle == Handle::RH_ENDORSEMENT.0 {
            return Ok(self.state.nv.persistent.endorsement_policy);
        }
        if handle == Handle::RH_PLATFORM.0 {
            return Ok(self.state.nv.clear.platform_policy);
        }
        if handle == Handle::RH_LOCKOUT.0 {
            return Ok(self.state.nv.persistent.lockout_policy);
        }
        if let Some(index) = crate::act::act_index(handle) {
            return Ok(self.state.act.policies[index].auth_policy);
        }
        if let Some(obj) = self.state.find_transient_object(handle) {
            Ok(obj.public.auth_policy)
        } else if self.state.find_active_sequence(handle).is_some() {
            Ok(Default::default())
        } else if Handle(handle).handle_type() == Some(TpmHt::NVIndex) {
            let storage_mgr = &mut self.state.nv.index;
            if let Ok(metadata) = storage_mgr.get_metadata(handle) {
                let read_len = core::cmp::min(metadata.data_size as usize, 1536);
                let mut read_buf = [0u8; 1536];
                if storage_mgr
                    .read_item(handle, 0, &mut read_buf[..read_len])
                    .is_ok()
                    && let Ok((_, nv_public_struct, _, _)) =
                        crate::handler::nv_storage::unmarshal_nv_header(&read_buf[..read_len])
                {
                    return Ok(OwnedDigest::from(nv_public_struct.auth_policy));
                }
            }
            Ok(OwnedDigest::default())
        } else if (0x81000000..=0x81FFFFFF).contains(&handle) {
            let obj = self.load_persistent_object(handle)?;
            Ok(obj.public.auth_policy)
        } else if crate::handler::pcr::pcr_belongs_policy_group(handle) {
            Ok(self.state.nv.persistent.pcr_policy)
        } else {
            Ok(OwnedDigest::default())
        }
    }

    pub fn has_da_protection(&mut self, handle: u32) -> bool {
        // A firmware-limited or SVN-limited hierarchy is authorized by its base hierarchy (TPM
        // 2.0 Part 1, "Primary Seed Authorizations"; C `HierarchyNormalizeHandle`).
        let handle = crate::hierarchy::normalize(handle);
        if handle == Handle::RH_OWNER.0
            || handle == Handle::RH_ENDORSEMENT.0
            || handle == Handle::RH_PLATFORM.0
            || is_vendor_permanent_auth(handle)
        {
            return false;
        }
        if handle == Handle::RH_LOCKOUT.0 {
            return true;
        }
        if (0x80000000..=0x80FFFFFF).contains(&handle) {
            if self.state.find_active_sequence(handle).is_some() {
                return false;
            }
            if let Some(obj) = self.state.find_transient_object(handle) {
                return !obj
                    .public
                    .object_attributes
                    .contains(tpm2::TpmaObject::NO_DA);
            }
            return true;
        }
        if (0x81000000..=0x81FFFFFF).contains(&handle) {
            if let Ok(obj) = self.load_persistent_object(handle) {
                return !obj
                    .public
                    .object_attributes
                    .contains(tpm2::TpmaObject::NO_DA);
            }
            return true;
        }
        if Handle(handle).handle_type() == Some(TpmHt::NVIndex) {
            let storage_mgr = &mut self.state.nv.index;
            if let Ok(metadata) = storage_mgr.get_metadata(handle) {
                let read_len = core::cmp::min(metadata.data_size as usize, 1536);
                let mut read_buf = [0u8; 1536];
                if storage_mgr
                    .read_item(handle, 0, &mut read_buf[..read_len])
                    .is_ok()
                    && let Ok((_, nv_public_struct, _, _)) =
                        crate::handler::nv_storage::unmarshal_nv_header(&read_buf[..read_len])
                {
                    return !nv_public_struct.attributes.contains(tpm2::TpmaNv::NO_DA);
                }
            }
            return true;
        }
        false
    }

    /// Checks whether Dictionary Attack lockout applies (`CheckLockedOut()` in `SessionProcess.c`).
    /// If NV storage is unavailable during an orderly state (`orderly_state < 0xFFFE`), returns `TPM_RC_NV_UNAVAILABLE`.
    /// If a DA counter update was deferred while NV was unavailable (`da_pending_on_nv`), returns
    /// `TPM_RC_NV_UNAVAILABLE` while NV is still unavailable; otherwise flushes `failed_tries` to
    /// NV storage and clears `da_pending_on_nv`.
    ///
    /// The TPM is locked out for `lockoutAuth` when its use is disabled, and for any other
    /// DA-protected entity when `failedTries >= maxTries` (so `maxTries == 0` always locks out,
    /// as in the C reference).
    pub(crate) fn check_locked_out(&mut self, is_lockout_auth: bool) -> Result<(), TpmRc> {
        if !self.state.nv_available && self.state.nv.persistent.orderly_state < 0xFFFE {
            return Err(TpmRc::NV_UNAVAILABLE);
        }
        if self.state.da_pending_on_nv {
            if !self.state.nv_available {
                return Err(TpmRc::NV_UNAVAILABLE);
            }
            let _ = self.state.nv.index.write_reserved(
                crate::storage::nv::NvHeader::FAILED_TRIES_OFFSET,
                &self.state.nv.persistent.failed_tries.to_be_bytes(),
            );
            self.save_hierarchy_auths();
            self.state.da_pending_on_nv = false;
        }
        if is_lockout_auth {
            if !self.state.nv.persistent.lockout_auth_enabled {
                return Err(TpmRc::LOCKOUT);
            }
        } else if self.state.nv.persistent.failed_tries >= self.state.nv.persistent.max_tries {
            return Err(TpmRc::LOCKOUT);
        }
        Ok(())
    }

    pub(crate) fn lookup_transient_object(
        &self,
        handle: u32,
        pos: Position,
    ) -> Result<&TransientObject, TpmRc> {
        if (handle & 0x00FF_FFFF) > (Handle::TRANSIENT_LAST.0 & 0x00FF_FFFF) {
            return Err(TpmRc::VALUE.with(pos));
        }
        self.state.find_transient_object(handle).ok_or({
            if pos == Position::handle(1) {
                TpmRc::REFERENCE_H0
            } else if pos == Position::handle(2) {
                TpmRc::REFERENCE_H1
            } else {
                TpmRc::REFERENCE_H2
            }
        })
    }

    /// Loads the persistent object `handle` for use by a command (`ObjectLoadEvict` without the
    /// object-slot accounting, which `Self::validate_command_handles` performs).
    ///
    /// A persistent handle whose hierarchy is disabled looks undefined, as in the C reference:
    /// platform handles (`0x8180_0000..`) need `phEnable`, all others `shEnable`, and objects of
    /// the endorsement hierarchy additionally `ehEnable`. Every failure to find or use the object
    /// is reported as `TPM_RC_HANDLE` (without position); see `Self::read_persistent_object`
    /// for an unchecked read.
    pub fn load_persistent_object(&mut self, handle: u32) -> Result<TransientObject, TpmRc> {
        let hierarchy_enabled = if handle >= 0x8180_0000 {
            self.state.ph_enable
        } else {
            self.state.nv.clear.sh_enable
        };
        if !hierarchy_enabled {
            return Err(TpmRc::HANDLE.to_rc());
        }
        let obj = self.read_persistent_object(handle)?;
        if obj.hierarchy == tpm2::Handle::RH_ENDORSEMENT.0 && !self.state.nv.clear.eh_enable {
            return Err(TpmRc::HANDLE.to_rc());
        }
        Ok(obj)
    }

    /// Reads the persistent object `handle` from NV without any hierarchy-enable checks
    /// (`NvGetEvictObject`, [`NvPersistentObjectRecord`]). Returns `TPM_RC_HANDLE` if it is not
    /// defined.
    pub(crate) fn read_persistent_object(&mut self, handle: u32) -> Result<TransientObject, TpmRc> {
        Ok(NvPersistentObjectRecord::read(&mut self.state.nv.index, handle)?.into_object(handle))
    }

    /// Manufactures the TPM (`TPM_Manufacture` / `HierarchyPreInstall_Init`): draws the three
    /// Primary Seeds and the three hierarchy proofs as independent values from the platform RNG
    /// and persists them, and clears the reserved NV entries.
    ///
    /// TPM 2.0 Part 1, "Primary Seeds" and "Hierarchy Proofs": each seed and proof is a
    /// secret, statistically unique random value. The draw order and sizes follow the reference
    /// (EPS, SPS, PPS, then phProof, shProof, ehProof; 64 bytes each).
    pub fn init_storage(&mut self) {
        const SEED_AND_PROOF_SIZE: u16 = 64;
        // `CryptInit()` and `CryptStartup(SU_RESET)` of `TPM_Manufacture()` come first: the
        // DRBG the hierarchy secrets are drawn from is instantiated here.
        #[cfg(feature = "reference-rng")]
        let rng_ok = self.manufacture_rng().is_ok();
        #[cfg(not(feature = "reference-rng"))]
        let rng_ok = true;
        // A value the platform RNG cannot produce stays unprovisioned (zeroed, size 0): every
        // command that needs it as key material then fails with `TPM_RC_FAILURE`
        // (`handler::provisioned_secret`) instead of using a predictable value.
        let draw = |engine: &mut Self| -> ([u8; 64], u16) {
            let mut buf = [0u8; 64];
            if rng_ok && engine.random_platform(&mut buf).is_ok() {
                (buf, SEED_AND_PROOF_SIZE)
            } else {
                ([0u8; 64], 0)
            }
        };
        (
            self.state.nv.persistent.ep_seed,
            self.state.nv.persistent.ep_seed_size,
        ) = draw(self);
        (
            self.state.nv.persistent.sp_seed,
            self.state.nv.persistent.sp_seed_size,
        ) = draw(self);
        (
            self.state.nv.persistent.pp_seed,
            self.state.nv.persistent.pp_seed_size,
        ) = draw(self);
        (
            self.state.nv.persistent.ph_proof,
            self.state.nv.persistent.ph_proof_size,
        ) = draw(self);
        (
            self.state.nv.persistent.sh_proof,
            self.state.nv.persistent.sh_proof_size,
        ) = draw(self);
        (
            self.state.nv.persistent.eh_proof,
            self.state.nv.persistent.eh_proof_size,
        ) = draw(self);
        let storage = &mut self.state.nv.index;
        let _ = storage.undefine_space(HIERARCHY_RECORD_HANDLE);
        let _ = storage.undefine_space(PCR_ALLOCATION_HANDLE);
        // `PhysicalPresencePreInstall_Init()` and `gp.algorithmSet = 0`.
        self.clear_platform_settings();
        self.save_hierarchy_auths();
        // `NvWrite(NV_ORDERLY_DATA, ...)`: the DRBG state after manufacture is persisted.
        #[cfg(feature = "reference-rng")]
        self.save_drbg_state();
        self.platform.store_nv(&self.state.nv);
    }

    /// Creates a new [`TpmEngine`] over `platform` with the state of a new (unmanufactured)
    /// TPM ([`State::new`]) whose NV data is held in `index` (e.g. the platform's NV medium).
    pub fn new(platform: P, index: P::IndexState) -> Result<Self, InternalError> {
        Ok(Self {
            platform,
            state: State::new(index),
            self_test: Default::default(),
            crypto_rng: <P::Crypto as tpm2::crypto::Random>::from_entropy()
                .map_err(|_| InternalError::HardwareError)?,
        })
    }

    /// Sets the locality of the following commands (`_plat__LocalityGet`).
    ///
    /// TPM 2.0 Part 1, "Locality": "Locality 5 through 31 cannot be selected." The
    /// specification leaves to the platform what a request for such a locality does; like the
    /// TCG reference platform (`_plat__LocalitySet()`), it selects locality 0.
    pub fn set_locality(&mut self, locality: u8) {
        self.state.locality = if (5..32).contains(&locality) {
            0
        } else {
            locality
        };
    }

    /// Sets whether NV memory is available to the TPM (`_plat__SetNvAvail` /
    /// `_plat__ClearNvAvail`). While NV is unavailable, commands that need NV fail with
    /// `TPM_RC_NV_UNAVAILABLE`.
    pub fn set_nv_available(&mut self, available: bool) {
        self.state.nv_available = available;
    }

    /// `_TPM_Init`: resets the volatile state and reloads the persistent state from NV,
    /// including the Primary Seeds and hierarchy proofs written at manufacture
    /// ([`Self::init_storage`]) or by `TPM2_Clear`/`TPM2_ChangeEPS`/`TPM2_ChangePPS`.
    pub fn reset(&mut self) {
        // `CryptInit()` re-seeds the platform entropy source.
        #[cfg(feature = "reference-rng")]
        self.crypt_rand_init();
        self.time_power_on();
        // `_plat__ACT_EnableTicks(FALSE)`: the ACTs do not count until the next TPM2_Startup
        // (`reset_in_place` clears `initialized`, see `Self::act_catch_up`).
        self.act_catch_up();
        self.state.reset_in_place();
        // `CryptInitializeToTest()` (`CryptInit()`): every algorithm needs its test again, and
        // Failure mode ends.
        self.self_test.initialize();
        // The platform reads the NV data from external storage before the NV-synced state is
        // reloaded from it.
        self.platform.load_nv(&mut self.state.nv);
        self.restore_hierarchy_auths();
        self.restore_platform_settings();
        self.restore_persistent_state();
        self.restore_pcr_allocation();
        // `NvRead(&go, NV_ORDERLY_DATA, ...)`: the DRBG reverts to its last persisted state.
        #[cfg(feature = "reference-rng")]
        self.load_drbg_state();
        self.platform.store_nv(&self.state.nv);
    }

    /// Replaces the active PCR allocation with the NV copy written by `TPM2_PCR_Allocate`
    /// ([`NvPcrAllocationRecord`]), if one exists. Called at `_TPM_Init`, mirroring the C
    /// reference where `gp.pcrAllocated` is (re)loaded from NV on initialization.
    fn restore_pcr_allocation(&mut self) {
        if let Some(record) = NvPcrAllocationRecord::read(&mut self.state.nv.index) {
            self.state.pcrs.pcr_allocation = record.allocation;
        }
    }

    /// Writes the hierarchy record ([`NvHierarchyRecord`], `0x00FF_FFFF`): the persistent
    /// hierarchy data, the DA parameters, `go.clock`/`go.clockSafe` and the command audit
    /// settings (`NV_SYNC_PERSISTENT`).
    pub(crate) fn save_hierarchy_auths(&mut self) {
        let s = &self.state;
        let record = NvHierarchyRecord {
            owner_auth: s.nv.persistent.owner_auth,
            endorsement_auth: s.nv.persistent.endorsement_auth,
            lockout_auth: s.nv.persistent.lockout_auth,
            owner_policy: s.nv.persistent.owner_policy,
            endorsement_policy: s.nv.persistent.endorsement_policy,
            lockout_policy: s.nv.persistent.lockout_policy,
            owner_alg: s.nv.persistent.owner_alg,
            endorsement_alg: s.nv.persistent.endorsement_alg,
            lockout_alg: s.nv.persistent.lockout_alg,
            seeds: Some(NvHierarchySeeds {
                sp_seed: s.nv.persistent.sp_seed,
                sp_seed_size: s.nv.persistent.sp_seed_size,
                sh_proof: s.nv.persistent.sh_proof,
                sh_proof_size: s.nv.persistent.sh_proof_size,
                eh_proof: s.nv.persistent.eh_proof,
                eh_proof_size: s.nv.persistent.eh_proof_size,
                clear_count: s.nv.reset.clear_count,
                pp_seed: s.nv.persistent.pp_seed,
                pp_seed_size: s.nv.persistent.pp_seed_size,
                ph_proof: s.nv.persistent.ph_proof,
                ph_proof_size: s.nv.persistent.ph_proof_size,
                ep_seed: s.nv.persistent.ep_seed,
                ep_seed_size: s.nv.persistent.ep_seed_size,
                pcr_policy_alg: Some(s.nv.persistent.pcr_policy_alg),
                pcr_policy: Some(s.nv.persistent.pcr_policy),
                pcr_auth_value: Some(s.nv.clear.pcr_auth_value),
            }),
            lifecycle: Some(NvLifecycleExt {
                disable_clear: s.nv.persistent.disable_clear,
                lockout_auth_enabled: s.nv.persistent.lockout_auth_enabled,
                max_tries: s.nv.persistent.max_tries,
                recovery_time: s.nv.persistent.recovery_time,
                lockout_recovery: s.nv.persistent.lockout_recovery,
                clock: self.get_clock(),
                clock_safe: s.nv.orderly.clock_safe,
            }),
            audit: Some(NvAuditExt {
                hash_alg: s.nv.persistent.audit_hash_alg,
                counter: s.nv.persistent.audit_counter,
                commands: *s.nv.persistent.audit_commands.as_bytes(),
            }),
        };
        record.write(&mut self.state.nv.index);
    }

    /// Reloads the hierarchy record ([`NvHierarchyRecord`]) at `_TPM_Init`. The record has no
    /// `platformAuth`, `platformPolicy`, `platformAlg`, `shEnable`, `ehEnable` or `phEnableNV`:
    /// they are `gc` state, which `TPM2_Startup` sets (TPM Reset/Restart; TPM 2.0 Part 1,
    /// "Hierarchy Control") or restores from the state-save record (TPM Resume).
    pub fn restore_hierarchy_auths(&mut self) {
        let Some(r) = NvHierarchyRecord::read(&mut self.state.nv.index) else {
            return;
        };
        let st = &mut self.state;
        st.nv.persistent.owner_auth = r.owner_auth;
        st.nv.persistent.endorsement_auth = r.endorsement_auth;
        st.nv.persistent.lockout_auth = r.lockout_auth;
        st.nv.persistent.owner_policy = r.owner_policy;
        st.nv.persistent.endorsement_policy = r.endorsement_policy;
        st.nv.persistent.lockout_policy = r.lockout_policy;
        st.nv.persistent.owner_alg = r.owner_alg;
        st.nv.persistent.endorsement_alg = r.endorsement_alg;
        st.nv.persistent.lockout_alg = r.lockout_alg;
        if let Some(seeds) = &r.seeds {
            st.nv.persistent.sp_seed = seeds.sp_seed;
            st.nv.persistent.sp_seed_size = seeds.sp_seed_size;
            st.nv.persistent.sh_proof = seeds.sh_proof;
            st.nv.persistent.sh_proof_size = seeds.sh_proof_size;
            st.nv.persistent.eh_proof = seeds.eh_proof;
            st.nv.persistent.eh_proof_size = seeds.eh_proof_size;
            st.nv.reset.clear_count = seeds.clear_count;
            st.nv.persistent.pp_seed = seeds.pp_seed;
            st.nv.persistent.pp_seed_size = seeds.pp_seed_size;
            st.nv.persistent.ph_proof = seeds.ph_proof;
            st.nv.persistent.ph_proof_size = seeds.ph_proof_size;
            st.nv.persistent.ep_seed = seeds.ep_seed;
            st.nv.persistent.ep_seed_size = seeds.ep_seed_size;
            if let Some(alg) = seeds.pcr_policy_alg {
                st.nv.persistent.pcr_policy_alg = alg;
            }
            if let Some(policy) = seeds.pcr_policy {
                st.nv.persistent.pcr_policy = policy;
            }
            if let Some(auth) = seeds.pcr_auth_value {
                st.nv.clear.pcr_auth_value = auth;
            }
        }
        if let Some(ext) = &r.lifecycle {
            st.nv.persistent.disable_clear = ext.disable_clear;
            st.nv.persistent.lockout_auth_enabled = ext.lockout_auth_enabled;
            st.nv.persistent.max_tries = ext.max_tries;
            st.nv.persistent.recovery_time = ext.recovery_time;
            st.nv.persistent.lockout_recovery = ext.lockout_recovery;
            // Make `get_clock()` report the persisted `go.clock`.
            st.nv.orderly.clock_offset = ext.clock.wrapping_sub(st.tpm_time_ms) as i64;
            st.nv.orderly.clock_safe = ext.clock_safe;
        }
        if let Some(audit) = &r.audit {
            st.nv.persistent.audit_hash_alg = audit.hash_alg;
            st.nv.persistent.audit_counter = audit.counter;
            st.nv.persistent.audit_commands =
                crate::command_audit::CommandAuditList::from_bytes(&audit.commands);
        }
    }

    /// Loads the persistent counters and orderly state kept in the reserved NV header
    /// ([`NvHeader`]; `NvReadPersistent()` / `NvRead(&go, ...)` in `_TPM_Init`) and, after an
    /// orderly `TPM2_Shutdown(TPM_SU_STATE)`, the saved `STATE_RESET_DATA` / `STATE_CLEAR_DATA`.
    ///
    /// `g_nv_ok` is SET when the persistent data was read; it is CLEAR if the previous shutdown
    /// was `TPM_SU_STATE` but the saved state could not be recovered (so that
    /// `TPM2_Startup(TPM_SU_STATE)` fails with `TPM_RC_NV_UNINITIALIZED`).
    fn restore_persistent_state(&mut self) {
        let Ok(header) = NvHeader::read(&self.state.nv.index) else {
            self.state.g_nv_ok = false;
            return;
        };
        self.state.nv.persistent.reset_count = header.reset_count;
        self.state.nv.persistent.orderly_state = header.orderly_state;
        self.state.nv.persistent.total_reset_count = header.total_reset_count;
        self.state.nv.persistent.time_epoch = header.time_epoch;
        self.state.nv.persistent.failed_tries = header.failed_tries;
        self.state.g_nv_ok = true;

        // `TPM_SU_STATE` possibly combined with the `PRE_STARTUP_FLAG` / `STARTUP_LOCALITY_3` bits.
        let orderly = self.state.nv.persistent.orderly_state;
        if orderly < 0xFFFE && (orderly & !(0x8000 | 0x4000)) == 0x0001 {
            self.state.g_nv_ok = self.restore_state_data();
        }
    }

    /// Persists the state that must survive a `TPM2_Shutdown(TPM_SU_STATE)` for a subsequent
    /// TPM Restart or TPM Resume (`NV_STATE_RESET_DATA` / `NV_STATE_CLEAR_DATA` in `Shutdown.c`)
    /// as the state-save record ([`NvStateSaveRecord`]).
    ///
    /// `STATE_RESET_DATA` (restored on Restart and Resume): `nullSeed`, `nullProof`,
    /// `restartCount`, `pcrCounter`, the context counters, the saved-session table,
    /// `commitCounter`, `commitNonce`, `commitArray` and `commandAuditDigest`. `STATE_CLEAR_DATA` (restored on Resume only): `platformAuth`,
    /// `platformPolicy`, `platformAlg`, `shEnable`, `ehEnable`, `phEnableNV` and `readOnly`. The ACT state
    /// of `ORDERLY_DATA` (restored on Resume only): the timeouts and `signaled` attributes
    /// saved by [`crate::act::ActState::shutdown_state`] and the ACT policies.
    ///
    /// PCR values and the remaining `State` fields are not written here; they are kept by
    /// the platform RAM, which `_TPM_Init` ([`State::reset_in_place`]) does not clear. The
    /// PCR update counter, which is `gr` state, is: TPM Restart and TPM Resume continue from its
    /// value at the shutdown, as in the references, where `TPM2_Startup` reads `gr` back from NV.
    pub(crate) fn save_state_data(&mut self) -> Result<(), TpmRc> {
        let s = &self.state;
        let record = NvStateSaveRecord {
            null_seed: s.nv.reset.null_seed,
            null_seed_size: s.nv.reset.null_seed_size,
            null_proof: s.nv.reset.null_proof,
            null_proof_size: s.nv.reset.null_proof_size,
            restart_count: s.nv.reset.restart_count,
            pcr_update_counter: s.pcrs.update_counter,
            context_counter: s.nv.reset.context_counter,
            object_context_counter: s.nv.reset.object_context_counter,
            saved_sessions: s.nv.reset.saved_sessions,
            saved_session_sequences: s.nv.reset.saved_session_sequences,
            commit_counter: s.nv.reset.commit_counter,
            commit_nonce: s.nv.reset.commit_nonce,
            commit_array: s.nv.reset.commit_array,
            sh_enable: s.nv.clear.sh_enable,
            eh_enable: s.nv.clear.eh_enable,
            ph_enable_nv: s.nv.clear.ph_enable_nv,
            read_only: s.nv.clear.read_only,
            platform_auth: s.nv.clear.platform_auth,
            platform_policy: s.nv.clear.platform_policy,
            platform_alg: s.nv.clear.platform_alg,
            command_audit_digest: s.nv.reset.command_audit_digest,
            act_saved_signaled: s.act.saved_signaled,
            act_saved_timeouts: s.act.saved_timeouts,
            act_policies: s.act.policies,
        };
        record.write(&mut self.state.nv.index)
    }

    /// Deletes the saved `TPM_SU_STATE` data written by [`Self::save_state_data`] once it has been
    /// consumed (or invalidated) by `TPM2_Startup`, releasing its NV space.
    pub(crate) fn delete_state_data(&mut self) {
        crate::storage::nv::delete_item(&mut self.state.nv.index, STATE_SAVE_HANDLE);
    }

    /// Restores the data written by [`Self::save_state_data`]. Returns `false` if it is missing
    /// or malformed.
    fn restore_state_data(&mut self) -> bool {
        let Some(r) = NvStateSaveRecord::read(&mut self.state.nv.index) else {
            return false;
        };
        let st = &mut self.state;
        st.nv.reset.null_seed_size = r.null_seed_size;
        st.nv.reset.null_seed = r.null_seed;
        st.nv.reset.null_proof_size = r.null_proof_size;
        st.nv.reset.null_proof = r.null_proof;
        st.nv.reset.restart_count = r.restart_count;
        st.pcrs.update_counter = r.pcr_update_counter;
        st.nv.reset.context_counter = r.context_counter;
        st.nv.reset.object_context_counter = r.object_context_counter;
        st.nv.reset.saved_sessions = r.saved_sessions;
        st.nv.reset.saved_session_sequences = r.saved_session_sequences;
        st.nv.reset.commit_counter = r.commit_counter;
        st.nv.reset.commit_nonce = r.commit_nonce;
        st.nv.reset.commit_array = r.commit_array;
        st.nv.clear.sh_enable = r.sh_enable;
        st.nv.clear.eh_enable = r.eh_enable;
        st.nv.clear.ph_enable_nv = r.ph_enable_nv;
        st.nv.clear.read_only = r.read_only;
        st.nv.clear.platform_auth = r.platform_auth;
        st.nv.clear.platform_policy = r.platform_policy;
        st.nv.clear.platform_alg = r.platform_alg;
        st.nv.reset.command_audit_digest = r.command_audit_digest;
        st.act.saved_signaled = r.act_saved_signaled;
        st.act.saved_timeouts = r.act_saved_timeouts;
        st.act.policies = r.act_policies;
        true
    }

    /// Process a TPM request and writes the response in a separate buffer. Returns the number of
    /// bytes written to the response buffer.
    pub fn execute_command_separate(&mut self, request: &[u8], response: &mut [u8]) -> usize {
        match self.execute_command(request, response) {
            Ok(size) => size,
            Err(err) => self.fill_error(response, err),
        }
    }

    /// Process a TPM request and write the response back into the same buffer. Returns the number
    /// of bytes written to the response buffer.
    pub fn execute_command_in_place(&mut self, in_out: &mut [u8], request_size: usize) -> usize {
        let mut tmp_request = [0u8; MAX_COMMAND_SIZE];
        if request_size > tmp_request.len() {
            return self.fill_error(in_out, TpmRc::SIZE.to_rc());
        }
        tmp_request[..request_size].copy_from_slice(&in_out[..request_size]);
        match self.execute_command(&tmp_request[..request_size], in_out) {
            Ok(size) => size,
            Err(err) => self.fill_error(in_out, err),
        }
    }

    fn fill_error(&mut self, response: &mut [u8], error: TpmRc) -> usize {
        if response.len() < ResponseHeader::MAX_SIZE {
            return 0;
        }
        let header = ResponseHeader {
            tag: TpmSt::NO_SESSIONS,
            size: ResponseHeader::MAX_SIZE as u32,
            rc: Err(error),
        };
        header.marshal(
            (&mut response[..ResponseHeader::MAX_SIZE])
                .try_into()
                .unwrap(),
        )
    }

    /// Processes a `_TPM_Hash_Start` indication (TCG DRTM / H-CRTM hardware event sequence).
    ///
    /// Allocates a sequence object for DRTM/H-CRTM hashing, freeing an existing transient/sequence
    /// slot if all `MAX_LOADED_OBJECTS` slots are occupied, and stores its transient handle in
    /// `self.state.drtm_handle` (`g_DRTMHandle`).
    pub fn hash_start(&mut self) -> bool {
        if self.state.drtm_handle != Handle::RH_UNASSIGNED.0 {
            let old_handle = self.state.drtm_handle;
            self.state.drtm_handle = Handle::RH_UNASSIGNED.0;
            let _ = self.state.remove_active_sequence(old_handle);
        }

        let (index, handle) = match self.state.find_empty_sequence_slot() {
            Ok((idx, h)) => (idx, h),
            Err(_) => {
                // Free the lowest assigned transient/sequence handle slot (TRANSIENT_FIRST = 0x80000000)
                let mut freed = false;
                for i in 0..(MAX_LOADED_OBJECTS as u32) {
                    let candidate = 0x8000_0000 | i;
                    if self.state.remove_transient_object(candidate).is_ok()
                        || self.state.remove_active_sequence(candidate).is_ok()
                    {
                        freed = true;
                        break;
                    }
                }
                if !freed {
                    return false;
                }
                match self.state.find_empty_sequence_slot() {
                    Ok((idx, h)) => (idx, h),
                    Err(_) => return false,
                }
            }
        };

        // The event sequence starts a hash of every implemented algorithm (a failed self test
        // has put the TPM into Failure mode).
        let _ = self.self_test_sequence_start(&SequenceType::Event);
        let seq = ActiveSequence::new(handle, Tpm2bAuth::default(), SequenceType::Event);
        self.state.active_sequences[index] = Some(seq);
        self.state.drtm_handle = handle;
        true
    }

    /// Processes a `_TPM_Hash_Data` indication (TCG DRTM / H-CRTM hardware event sequence).
    ///
    /// Updates the streaming hash state for each active bank where the target PCR (`0` before
    /// startup, `17` after startup) is allocated.
    pub fn hash_data(&mut self, data: &[u8]) -> bool {
        if self.state.drtm_handle == Handle::RH_UNASSIGNED.0 {
            return false;
        }
        let target_pcr: u32 = if self.state.initialized { 17 } else { 0 };
        let pcr_alloc = self.state.pcrs.pcr_allocation;

        let Some(seq) = self.state.find_active_sequence_mut(self.state.drtm_handle) else {
            return false;
        };

        for state in &mut seq.hash_states[..ActiveSequence::EVENT_HASH_COUNT] {
            if is_pcr_allocated(&pcr_alloc, state.alg, target_pcr) {
                state.update(data);
            }
        }
        true
    }

    /// Processes a `_TPM_Hash_End` indication (TCG DRTM / H-CRTM hardware event sequence).
    ///
    /// Completes the active DRTM/H-CRTM event sequence:
    /// - If post-startup (`self.state.initialized == true`):
    ///   - Resets all dynamic PCRs (`17..=22`) to `0x00`.
    ///   - Increments `self.state.restart_count`.
    ///   - Resets PCR 17 to `0x00` and extends it with the finalized event digest in each allocated bank.
    /// - If pre-startup (`self.state.initialized == false`):
    ///   - Sets `self.state.drtm_pre_startup = true`.
    ///   - Sets PCR 0 to `0x00...04` and extends it with the finalized event digest in each allocated bank.
    /// - Flushes the sequence object and resets `self.state.drtm_handle` to `TPM_RH_UNASSIGNED`.
    pub fn hash_end(&mut self) -> bool {
        if self.state.drtm_handle == Handle::RH_UNASSIGNED.0 {
            return false;
        }

        let old_handle = self.state.drtm_handle;
        self.state.drtm_handle = Handle::RH_UNASSIGNED.0;
        let Some(seq) = self.state.find_active_sequence(old_handle).cloned() else {
            return false;
        };
        let _ = self.state.remove_active_sequence(old_handle);

        let target_pcr: usize = if self.state.initialized {
            // PCRResetDynamics: reset PCRs 17..=22 to 0 across all banks (every implemented
            // hash, SHA-512 included).
            for pcr in 17..=22 {
                for alg in seq.event_hash_states().iter().map(|state| state.alg) {
                    if let Some(value) = self.state.pcrs.value_mut(alg, pcr) {
                        value.fill(0);
                    }
                }
            }
            self.state.nv.reset.restart_count = self.state.nv.reset.restart_count.wrapping_add(1);
            17
        } else {
            self.state.drtm_pre_startup = true;
            0
        };

        // Each allocated bank of the target PCR is set to its initial value (0, or 4 in the
        // last octet for the H-CRTM PCR 0 before Startup) and extended once with the event
        // digest of its algorithm; each extension counts as a PCR change.
        let pcr_alloc = self.state.pcrs.pcr_allocation;
        for state in seq.event_hash_states() {
            if !is_pcr_allocated(&pcr_alloc, state.alg, target_pcr as u32) {
                continue;
            }
            let (digest, digest_len) = state.finalize();
            let initialized = self.state.initialized;
            let Some(pcr_data) = self.state.pcrs.value_mut(state.alg, target_pcr) else {
                continue;
            };
            pcr_data.fill(0);
            if !initialized && let Some(last) = pcr_data.last_mut() {
                *last = 4;
            }
            let mut h = crate::hash_state::StreamingHashState::new(state.alg);
            h.update(pcr_data);
            h.update(&digest[..digest_len]);
            let (new_pcr, new_len) = h.finalize();
            pcr_data.copy_from_slice(&new_pcr[..new_len]);
            self.state.pcrs.update_counter = self.state.pcrs.update_counter.wrapping_add(1);
        }
        true
    }

    /// Executes a TPM command from the input request buffer and writes the response
    /// into the output response buffer. Decides whether to parse and process sessions
    /// based on the tag in the command header.
    /// Advances `Time` (`tpm_time_ms`) and `Clock` by the platform time elapsed since the last
    /// update and runs the dictionary-attack self-healing logic (`TimeUpdate()` in `Time.c`).
    ///
    /// The elapsed platform time is scaled by the `TPM2_ClockRateAdjust` divisor
    /// (`_plat__TimerRead()` in the C platform `Clock.c`). When `Clock` crosses a multiple of
    /// `2^NV_CLOCK_UPDATE_INTERVAL` ms it is written to NV and `clockSafe` is SET
    /// (`TimeClockUpdate()`).
    pub(crate) fn time_update(&mut self) {
        // `if(_plat__TimerWasStopped()) { TimeNewEpoch(); }`: `gp.timeEpoch++;
        // NV_SYNC_PERSISTENT(timeEpoch);`.
        if self.state.timer_stopped {
            self.state.timer_stopped = false;
            self.state.nv.persistent.time_epoch =
                self.state.nv.persistent.time_epoch.wrapping_add(1);
            let _ = self.state.nv.index.write_reserved(
                crate::storage::nv::NvHeader::TIME_EPOCH_OFFSET,
                &crate::storage::nv::NvHeader::encode_time_epoch(
                    self.state.nv.persistent.time_epoch,
                ),
            );
        }
        let elapsed_ms = self.advance_time();
        let old_clock = self.get_clock();
        self.state.tpm_time_ms = self.state.tpm_time_ms.saturating_add(elapsed_ms);
        let new_clock = self.get_clock();
        self.clock_update(old_clock, new_clock);

        self.da_self_heal();
    }

    /// A power on (`_plat__TimerReset()` of the TCG reference platform): *Time* restarts at 0,
    /// "the time in milliseconds that the circuit providing *Time* has been powered" (TPM 2.0
    /// Part 1, "Time"), `Clock` keeps its value, the clock-rate adjustment returns to nominal,
    /// and the timer records that it was stopped (a new time epoch, see
    /// [`State::timer_stopped`]) and reset (see [`State::timer_was_reset`]).
    pub fn platform_timer_reset(&mut self) {
        self.state.nv.orderly.clock_offset = self
            .state
            .nv
            .orderly
            .clock_offset
            .wrapping_add(self.state.tpm_time_ms as i64);
        self.state.tpm_time_ms = 0;
        let now_ms = self.platform.timer().timer_read();
        self.state.last_timer_read_ms = Some(now_ms);
        // The once-per-second ACT ticks restart with the platform timer.
        self.state.act.power_on(now_ms);
        self.state.clock_adjust_rate = CLOCK_NOMINAL;
        self.state.clock_adjust_remainder = 0;
        self.state.timer_stopped = true;
        self.state.timer_was_reset = true;
    }

    /// `TimePowerOn()` at `_TPM_Init` (`g_time = _plat__TimerRead();`): *Time* catches up with the
    /// platform timer, while `Clock` (`go.clock`) does not advance by that interval.
    fn time_power_on(&mut self) {
        let elapsed_ms = self.advance_time();
        self.state.tpm_time_ms = self.state.tpm_time_ms.saturating_add(elapsed_ms);
        self.state.nv.orderly.clock_offset = self
            .state
            .nv
            .orderly
            .clock_offset
            .wrapping_sub(elapsed_ms as i64);
    }

    /// Reads the platform timer and returns the rate-adjusted ms elapsed since the last read
    /// (`_plat__TimerRead()`), without adding them to *Time*.
    fn advance_time(&mut self) -> u64 {
        let raw_timer_ms = self.platform.timer().timer_read();
        let elapsed_raw_ms = if let Some(prev_raw) = self.state.last_timer_read_ms {
            raw_timer_ms.saturating_sub(prev_raw)
        } else {
            0
        };
        self.state.last_timer_read_ms = Some(raw_timer_ms);

        // As the C platform (`_plat__TimerRead()`): `adjustedTimeDiff = timeDiff * CLOCK_NOMINAL /
        // adjustRate` ms are added to Time, and only the platform time that maps back to them
        // (`adjustedTimeDiff * adjustRate / CLOCK_NOMINAL`) is consumed; the rest of `timeDiff`
        // (in platform ms) carries over and is scaled with the rate of the next update.
        let rate = u128::from(self.state.clock_adjust_rate.max(1));
        let time_diff = u128::from(elapsed_raw_ms) + u128::from(self.state.clock_adjust_remainder);
        let adjusted = time_diff * u128::from(CLOCK_NOMINAL) / rate;
        let readjusted = adjusted * rate / u128::from(CLOCK_NOMINAL);
        let elapsed_ms = u64::try_from(adjusted).unwrap_or(u64::MAX);
        self.state.clock_adjust_remainder =
            u64::try_from(time_diff.saturating_sub(readjusted)).unwrap_or(u64::MAX);
        elapsed_ms
    }

    /// Records a change of `Clock` from `old_clock` to `new_clock` (`TimeClockUpdate()` in
    /// `Time.c`): if the new value crosses an `NV_CLOCK_UPDATE_INTERVAL` boundary, `clockSafe`
    /// is SET and the clock is written to NV. The caller must have checked NV availability.
    pub(crate) fn clock_update(&mut self, old_clock: u64, new_clock: u64) {
        const CLOCK_UPDATE_MASK: u64 = (1u64 << NV_CLOCK_UPDATE_INTERVAL) - 1;
        if (new_clock | CLOCK_UPDATE_MASK) > (old_clock | CLOCK_UPDATE_MASK) {
            self.state.nv.orderly.clock_safe = true;
            // The clock is persisted with the rest of the persistent hierarchy data.
            self.save_hierarchy_auths();
            // The reference writes all of `go`, including the DRBG state.
            #[cfg(feature = "reference-rng")]
            self.save_drbg_state();
        }
    }

    /// Dictionary-attack self-healing (`DASelfHeal()` in `DA.c`): decrements `failedTries` once
    /// per `recoveryTime` seconds (or clears it when `recoveryTime` is 0) and re-enables
    /// `lockoutAuth` once `lockoutRecovery` seconds have elapsed since the last lockout failure.
    /// Every change is synchronized to NV (`NV_SYNC_PERSISTENT`).
    fn da_self_heal(&mut self) {
        // 1. Regular authorization self-healing (failedTries decrement every recoveryTime seconds)
        if self.state.nv.persistent.failed_tries != 0 {
            if self.state.nv.persistent.recovery_time == 0 {
                self.state.nv.persistent.failed_tries = 0;
                let _ = self.state.nv.index.write_reserved(
                    crate::storage::nv::NvHeader::FAILED_TRIES_OFFSET,
                    &self.state.nv.persistent.failed_tries.to_be_bytes(),
                );
            } else {
                let elapsed_heal_ms = (self.state.tpm_time_ms as i64)
                    .saturating_sub(self.state.nv.orderly.self_heal_timer);
                if elapsed_heal_ms >= 0 {
                    let decrease_count = ((elapsed_heal_ms as u64) / 1000)
                        / (self.state.nv.persistent.recovery_time as u64);
                    if decrease_count > 0 {
                        self.state.nv.persistent.failed_tries = self
                            .state
                            .nv
                            .persistent
                            .failed_tries
                            .saturating_sub(decrease_count as u32);
                        self.state.nv.orderly.self_heal_timer =
                            self.state.nv.orderly.self_heal_timer.saturating_add(
                                (decrease_count
                                    * (self.state.nv.persistent.recovery_time as u64)
                                    * 1000) as i64,
                            );
                        let _ = self.state.nv.index.write_reserved(
                            crate::storage::nv::NvHeader::FAILED_TRIES_OFFSET,
                            &self.state.nv.persistent.failed_tries.to_be_bytes(),
                        );
                    }
                }
            }
        }

        // 2. LockoutAuth self-healing (re-enable lockoutAuth after lockoutRecovery seconds)
        if !self.state.nv.persistent.lockout_auth_enabled
            && self.state.nv.persistent.lockout_recovery != 0
        {
            let elapsed_lockout_ms =
                (self.state.tpm_time_ms as i64).saturating_sub(self.state.nv.orderly.lockout_timer);
            if elapsed_lockout_ms >= 0
                && ((elapsed_lockout_ms as u64) / 1000)
                    >= (self.state.nv.persistent.lockout_recovery as u64)
            {
                self.state.nv.persistent.lockout_auth_enabled = true;
                // NV_SYNC_PERSISTENT(lockOutAuthEnabled)
                self.save_hierarchy_auths();
            }
        }
    }

    /// Processes the once-per-second ACT ticks that elapsed since the last call (see
    /// [`crate::act`]). The ticks are applied lazily, before each command and at `_TPM_Init`:
    /// only commands observe the ACTs. Ticks are allowed (C `actTicksAllowed`) exactly while
    /// the TPM is initialized: from `TPM2_Startup` until the next `_TPM_Init`.
    pub(crate) fn act_catch_up(&mut self) {
        let now_ms = self.platform.timer().timer_read();
        self.state.act.catch_up(now_ms, self.state.initialized);
    }

    /// The `signaled` attribute of the ACT with handle `handle` (`_plat__ACT_GetSignaled()`,
    /// the MSSIM `TPM_ACT_GET_SIGNALED` platform signal), after the ticks that elapsed;
    /// `false` if `handle` is not an implemented ACT.
    pub fn act_signaled(&mut self, handle: u32) -> bool {
        self.act_catch_up();
        crate::act::act_index(handle).is_some_and(|index| self.state.act.counters[index].signaled)
    }

    /// Processes the TPM command `cmd_buf` and writes its response to `resp_buf`, returning the
    /// size of the response, or the response code of a command that fails before its response
    /// is written. The NV data is then synced to external storage ([`Platform::store_nv`]).
    pub fn execute_command(&mut self, cmd_buf: &[u8], resp_buf: &mut [u8]) -> Result<usize, TpmRc> {
        let result = self.dispatch_command(cmd_buf, resp_buf);
        self.platform.store_nv(&self.state.nv);
        result
    }

    /// Implementation of [`Self::execute_command`] (without the NV sync).
    fn dispatch_command(&mut self, cmd_buf: &[u8], resp_buf: &mut [u8]) -> Result<usize, TpmRc> {
        // The ACTs count down with the platform timer, whatever the state of the TPM (the ticks
        // are dropped before TPM2_Startup; Part 1, ACT "Failure Mode": "the ACT should continue
        // to count down").
        self.act_catch_up();
        // TPM 2.0 Part 1, "Failure Mode": "While in Failure mode, the TPM returns
        // `TPM_RC_FAILURE` in response to any command except `TPM2_GetTestResult()` or
        // `TPM2_GetCapability()`." A self test that fails during a command puts the TPM into
        // Failure mode and fails the command (`TPM_RC_FAILURE`), whatever it would have returned.
        if self.self_test.failed() {
            return self.execute_in_failure_mode(cmd_buf, resp_buf);
        }
        let result = self.execute_command_tested(cmd_buf, resp_buf);
        if self.self_test.failed() {
            return Err(TpmRc::FAILURE);
        }
        result
    }

    /// A command in Failure mode (`TpmFailureMode()`): `TPM2_GetTestResult` returns the failure
    /// information (`outData`: the 64-bit failure location, which is 0 here, and the failure
    /// code `FATAL_ERROR_SELF_TEST`; `testResult`: `TPM_RC_FAILURE`), and `TPM2_GetCapability` of
    /// `TPM_CAP_TPM_PROPERTIES` executes normally (the specification requires only a few
    /// properties; "An implementation is allowed to return other property values"). Both must
    /// be sent without sessions (Part 3, TPM2_GetTestResult: "If the TPM is in Failure mode, then
    /// *tag* is required to be `TPM_ST_NO_SESSIONS` or the TPM shall return `TPM_RC_FAILURE`").
    /// Every other command is `TPM_RC_FAILURE`.
    fn execute_in_failure_mode(
        &mut self,
        cmd_buf: &[u8],
        resp_buf: &mut [u8],
    ) -> Result<usize, TpmRc> {
        const GET_TEST_RESULT_SIZE: usize = CommandHeader::MAX_SIZE;
        const GET_CAPABILITY_SIZE: usize = CommandHeader::MAX_SIZE + 12;
        if cmd_buf.len() < CommandHeader::MAX_SIZE {
            return Err(TpmRc::FAILURE);
        }
        let be16 = |i: usize| u16::from_be_bytes([cmd_buf[i], cmd_buf[i + 1]]);
        let be32 = |i: usize| {
            u32::from_be_bytes([cmd_buf[i], cmd_buf[i + 1], cmd_buf[i + 2], cmd_buf[i + 3]])
        };
        if be16(0) != u16::from(TpmiStCommandTag::NoSessions) || be32(2) as usize != cmd_buf.len() {
            return Err(TpmRc::FAILURE);
        }
        let code = be32(6);
        if code == TpmCc::GetTestResult.code() && cmd_buf.len() == GET_TEST_RESULT_SIZE {
            let mut body = [0u8; 2 + 12 + 4];
            body[..2].copy_from_slice(&12u16.to_be_bytes());
            // The failure location (8 octets, 0) and the failure code.
            body[10..14].copy_from_slice(&crate::self_test::FATAL_ERROR_SELF_TEST.to_be_bytes());
            body[14..].copy_from_slice(&TpmRc::FAILURE.get().to_be_bytes());
            let size = ResponseHeader::MAX_SIZE + body.len();
            let out = resp_buf.get_mut(..size).ok_or(TpmRc::FAILURE)?;
            let header = ResponseHeader {
                tag: TpmSt::NO_SESSIONS,
                size: size as u32,
                rc: Ok(()),
            };
            header.marshal((&mut out[..ResponseHeader::MAX_SIZE]).try_into().unwrap());
            out[ResponseHeader::MAX_SIZE..].copy_from_slice(&body);
            return Ok(size);
        }
        if code == TpmCc::GetCapability.code()
            && cmd_buf.len() == GET_CAPABILITY_SIZE
            && be32(CommandHeader::MAX_SIZE) == tpm2::TpmCap::TPMProperties as u32
        {
            return self.execute_command_tested(cmd_buf, resp_buf);
        }
        Err(TpmRc::FAILURE)
    }

    fn execute_command_tested(
        &mut self,
        cmd_buf: &[u8],
        resp_buf: &mut [u8],
    ) -> Result<usize, TpmRc> {
        // The temporary object slots of the persistent objects referenced by the previous command
        // are released when it ends (`ObjectCleanupEvict()` in `ExecCommand.c`).
        self.state.command_persistent_objects = 0;
        // `TimeUpdateToCurrent()` (`Time.c`): Time/Clock only advance, and `DASelfHeal()` only
        // runs, once TPM2_Startup has completed and while NV is available. Otherwise the elapsed
        // platform time is deferred (the last timer sample is kept) until the next update. As in
        // the C reference `ExecuteCommand()`, this happens for every command before its header is
        // parsed, so even a rejected command (e.g. an unimplemented command code) advances Clock
        // and records it in NV when it crosses an `NV_CLOCK_UPDATE_INTERVAL` boundary.
        if self.state.initialized && self.state.nv_available {
            self.time_update();
        }
        // Any command through this function unceremoniously ends an active DRTM event sequence
        // (`ObjectTerminateEvent()` in `ExecCommand.c`).
        if self.state.drtm_handle != Handle::RH_UNASSIGNED.0 {
            let old_handle = self.state.drtm_handle;
            self.state.drtm_handle = Handle::RH_UNASSIGNED.0;
            let _ = self.state.remove_active_sequence(old_handle);
        }

        // Parse the command header field by field, as the C reference `ExecuteCommand()` does:
        // a truncated field is `TPM_RC_INSUFFICIENT`, an invalid tag is `TPM_RC_BAD_TAG`, and a
        // `commandSize` that differs from the number of received bytes (or exceeds
        // `MAX_COMMAND_SIZE`) is `TPM_RC_COMMAND_SIZE`.
        let request_size = cmd_buf.len();
        if request_size < 2 {
            return Err(TpmRc::INSUFFICIENT.to_rc());
        }
        let tag = u16::from_be_bytes([cmd_buf[0], cmd_buf[1]]);
        if tag != u16::from(TpmiStCommandTag::NoSessions)
            && tag != u16::from(TpmiStCommandTag::Sessions)
        {
            return Err(TpmRc::BAD_TAG);
        }
        if request_size < 6 {
            return Err(TpmRc::INSUFFICIENT.to_rc());
        }
        let size = u32::from_be_bytes([cmd_buf[2], cmd_buf[3], cmd_buf[4], cmd_buf[5]]) as usize;
        if size != request_size || size > MAX_COMMAND_SIZE {
            return Err(TpmRc::COMMAND_SIZE);
        }
        if request_size < CommandHeader::MAX_SIZE {
            return Err(TpmRc::INSUFFICIENT.to_rc());
        }
        let mut slice = cmd_buf;
        let header = CommandHeader::unmarshal(&mut slice).map_err(|_| TpmRc::COMMAND_CODE)?;
        let cc = header.code;
        let command_code = cc.code();

        if !is_command_supported(cc) {
            return Err(TpmRc::COMMAND_CODE);
        }

        // `ExecCommand.c`: only `TPM2_Startup` is accepted before the TPM is started, and it is
        // not accepted afterwards. This is checked (after
        // `TimeUpdateToCurrent`) before any handle or session processing.
        if self.state.initialized == (cc == TpmCc::Startup) {
            return Err(TpmRc::INITIALIZE);
        }

        // Read-Only mode (Part 1, "Read-Only Mode of Operation"): a command that is not
        // permitted fails with `TPM_RC_READ_ONLY` "before performing authorization checks".
        // Before `TPM2_Startup` every command but `TPM2_Startup` fails with
        // `TPM_RC_INITIALIZE` (the mode is part of the state that `TPM2_Startup` establishes),
        // so the check follows the initialization check and precedes any handle or session
        // processing.
        if cfg!(feature = "cc-read-only-control")
            && self.state.nv.clear.read_only
            && crate::read_only::is_disallowed_in_read_only_mode(cc)
        {
            return Err(TpmRc::READ_ONLY);
        }

        // Reset per-command state-tracking flags at the beginning of each command
        // (`g_updateNV = UT_NONE; g_clearOrderly = FALSE;` in `ExecCommand.c`).
        self.state.update_nv = UT_NONE;
        self.state.clear_orderly = false;
        self.state.command_audit_cp_hash = None;
        self.state.command_audit_alg_changed = false;
        self.state.session_audit_cp_hashes = [None; 3];

        let res = (|| -> Result<usize, TpmRc> {
            // Command dispatch based on authorization session tag
            if header.tag == TpmiStCommandTag::Sessions {
                self.execute_with_sessions(cmd_buf, resp_buf, cc, command_code, size)
            } else {
                let mut handles = [0u32; 3];
                let handles_len = command_handles_count(cc);
                if let Some(rc) = handle_area_unmarshal_error(cmd_buf, size, cc, handles_len) {
                    return Err(rc);
                }
                for (i, handle) in handles[..handles_len].iter_mut().enumerate() {
                    let offset = 10 + i * 4;
                    *handle = u32::from_be_bytes([
                        cmd_buf[offset],
                        cmd_buf[offset + 1],
                        cmd_buf[offset + 2],
                        cmd_buf[offset + 3],
                    ]);
                }
                if !self.state.in_shadow_execution {
                    // As in `ExecCommand.c`, the handles are validated (`ParseHandleBuffer` /
                    // `EntityGetLoadStatus`) before missing authorizations are reported
                    // (`CheckAuthNoSession`).
                    let params_len = size.saturating_sub(10 + handles_len * 4);
                    self.validate_command_handles(
                        cc,
                        &handles,
                        handles_len,
                        &cmd_buf[10 + handles_len * 4..10 + handles_len * 4 + params_len],
                    )?;
                    self.check_unauthorized_handles(cc, &handles, handles_len, &[], 0)?;
                    // `CheckAuthNoSession` ends with `CheckCommandAudit`.
                    self.check_command_audit(
                        cc,
                        &handles[..handles_len],
                        &cmd_buf[10 + handles_len * 4..size],
                    )?;
                }

                let result = self.execute_without_sessions(cmd_buf, resp_buf, cc, size);
                // A successful command without an audit session ends audit exclusivity. As in the
                // C reference (`UpdateAuditSessionStatus()` from `BuildResponseSession()`), this
                // only happens once the command has succeeded; failed commands leave it intact.
                if result.is_ok()
                    && !matches!(
                        cc,
                        TpmCc::Startup
                            | TpmCc::ContextLoad
                            | TpmCc::ContextSave
                            | TpmCc::FlushContext
                    )
                {
                    self.state.exclusive_audit_session = None;
                }
                result
            }
        })();

        // Command audit (`CommandAudit()` from `BuildResponseSession()`): only a successful
        // command for which `check_command_audit` prepared a cpHash extends the audit digest.
        let res = match res {
            Ok(size) => self.command_audit(cc, &resp_buf[..size]).map(|()| size),
            Err(rc) => Err(rc),
        };
        self.state.command_audit_cp_hash = None;
        self.state.command_audit_alg_changed = false;
        self.state.session_audit_cp_hashes = [None; 3];

        // Post-command cleanup (`Cleanup:` in `ExecCommand.c`):
        // 1. If clear_orderly is set and NV is currently orderly (`orderly_state < SU_DA_USED_VALUE`),
        //    invalidate orderly_state to SU_DA_USED_VALUE (0xFFFE) or SU_NONE_VALUE (0xFFFF)
        //    and sync to persistent NV storage (offset 16).
        if self.state.clear_orderly && self.state.nv.persistent.orderly_state < 0xFFFE {
            self.state.nv.persistent.orderly_state =
                if self.state.da_used { 0xFFFE } else { 0xFFFF };
            let _ = self.state.nv.index.write_reserved(
                crate::storage::nv::NvHeader::ORDERLY_STATE_OFFSET,
                &self.state.nv.persistent.orderly_state.to_be_bytes(),
            );
            self.state.update_nv |= UT_NV;
        }

        // 2. Commit NV updates and reset update_nv flag (`g_updateNV = UT_NONE`).
        if self.state.update_nv != UT_NONE {
            self.state.update_nv = UT_NONE;
        }

        res
    }

    /// Helper function to execute a TPM command containing authorization sessions (tag 0x8002).
    /// Performs key derivation, parameter decryption, session HMAC verification, routes to the actual
    /// command handler, and then processes the response (parameter encryption, session HMAC generation).
    fn execute_with_sessions(
        &mut self,
        cmd_buf: &[u8],
        resp_buf: &mut [u8],
        cc: TpmCc,
        command_code: u32,
        request_size: usize,
    ) -> Result<usize, TpmRc> {
        // Commands with the `NO_SESSIONS` attribute must not carry a session area. As in C, this
        // is checked after the handles have been validated and the `authorizationSize` passed
        // its sanity check, but before any session structure is unmarshaled
        // (`IsSessionAllowed` is the first check of `ParseSessionBuffer`).
        if !is_session_allowed(cc) {
            self.reject_sessions_for_no_sessions_command(cmd_buf, cc, request_size)?;
        }
        // 1. Parse and validate the handles, then parse the session area (see
        // `parse_command_and_sessions` for the order).
        // Every session is validated as it is unmarshaled (`validate_session`).
        let mut cmd = self.parse_command_and_sessions(cmd_buf, cc, command_code, request_size)?;
        self.validate_encrypt_session_mode(&cmd)?;

        // 2. Session authorization (HMAC/password/policy) for all sessions. As in the C reference
        // `ParseSessionBuffer`, missing authorizations are reported first, and authorization
        // happens before parameter decryption, so a malformed encrypted parameter cannot mask an
        // authorization failure (or skip the DA accounting). The cpHash is computed over the
        // still-encrypted wire parameters.
        self.check_unauthorized_handles(
            cc,
            &cmd.handles,
            cmd.handles_len,
            &cmd.session_to_handle_idx,
            cmd.session_to_handle_idx_len,
        )?;
        self.verify_session_hmacs(&mut cmd, command_code)?;
        // `ParseSessionBuffer`: the command audit check runs after authorization and before any
        // parameter decryption, so the audit cpHash covers the parameters as received.
        self.check_command_audit(
            cc,
            &cmd.handles[..cmd.handles_len],
            cmd.ciphertext_parameters,
        )?;

        // 3. Parameter Decryption (the last step of session processing).
        let has_decrypt_session = cmd.auth_sessions[..cmd.auth_sessions_len]
            .iter()
            .any(|auth| auth.session_attributes.0 & 0x20 != 0);

        if has_decrypt_session {
            self.execute_with_param_decryption(cmd, resp_buf, cc, command_code)
        } else {
            self.execute_after_decryption(&mut cmd, resp_buf, cc, command_code)
        }
    }

    /// Returns `TPM_RC_AUTH_CONTEXT` for a `NO_SESSIONS` command sent with `TPM_ST_SESSIONS`
    /// once its handles are valid and its `authorizationSize` is sane. Returns `Ok(())` if the
    /// handle or authorization-size area is truncated or malformed, so that the regular parser
    /// reports that error exactly as for any other command.
    fn reject_sessions_for_no_sessions_command(
        &mut self,
        cmd_buf: &[u8],
        cc: TpmCc,
        request_size: usize,
    ) -> Result<(), TpmRc> {
        let num_handles = command_handles_count(cc).min(3);
        let auth_size_offset = 10 + 4 * num_handles;
        if request_size < auth_size_offset + 4 || cmd_buf.len() < auth_size_offset + 4 {
            return Ok(());
        }
        let mut handles = [0u32; 3];
        for (i, handle) in handles.iter_mut().take(num_handles).enumerate() {
            let offset = 10 + 4 * i;
            *handle = u32::from_be_bytes([
                cmd_buf[offset],
                cmd_buf[offset + 1],
                cmd_buf[offset + 2],
                cmd_buf[offset + 3],
            ]);
        }
        self.validate_command_handles(cc, &handles, num_handles, &[])?;
        let auth_size = u32::from_be_bytes([
            cmd_buf[auth_size_offset],
            cmd_buf[auth_size_offset + 1],
            cmd_buf[auth_size_offset + 2],
            cmd_buf[auth_size_offset + 3],
        ]) as usize;
        if auth_size < 9 || request_size - (auth_size_offset + 4) < auth_size {
            return Ok(());
        }
        Err(TpmRc::AUTH_CONTEXT)
    }

    /// Helper to execute a command with session parameter decryption enabled.
    ///
    /// Allocates a temporary stack buffer (`decrypt_buf`) of size `DECRYPT_BUF_SIZE`
    /// to receive decrypted command parameters and calls `decrypt_command_parameters`.
    ///
    /// This function is explicitly marked `#[inline(never)]` so that the buffer is only
    /// allocated on the call stack when an authorization session specifies the `TPMA_SESSION_DECRYPT`
    /// attribute flag, reducing stack memory usage for standard commands without parameter encryption.
    #[inline(never)]
    fn execute_with_param_decryption(
        &mut self,
        cmd: ParsedCommand,
        resp_buf: &mut [u8],
        cc: TpmCc,
        command_code: u32,
    ) -> Result<usize, TpmRc> {
        let mut decrypt_buf: DecryptBuf = [0u8; DECRYPT_BUF_SIZE];
        let mut cmd = self.decrypt_command_parameters(cmd, &mut decrypt_buf)?;
        self.execute_after_decryption(&mut cmd, resp_buf, cc, command_code)
    }

    /// Continuation helper to execute a command with authorization sessions after parameter decryption.
    ///
    /// Performs the remaining execution pipeline for session-authenticated commands (session
    /// authorization has already been verified by `execute_with_sessions`):
    /// 1. Dispatches command execution to the underlying handler via a session-less shadow buffer.
    /// 2. Processes the response, including parameter encryption (if `TPMA_SESSION_ENCRYPT` is set),
    ///    audit session tracking, nonce generation, and response HMAC computation.
    fn execute_after_decryption(
        &mut self,
        cmd: &mut ParsedCommand,
        resp_buf: &mut [u8],
        cc: TpmCc,
        command_code: u32,
    ) -> Result<usize, TpmRc> {
        // 4. Execute Command via a Shadow Buffer
        // The shadow request drops the session area, so it is never larger than the original
        // command (bounded by `MAX_COMMAND_SIZE`).
        let shadow_request_size =
            CommandHeader::MAX_SIZE + (cmd.handles_len * 4) + cmd.parameters.len();
        if shadow_request_size > MAX_COMMAND_SIZE {
            return Err(TpmRc::SIZE.to_rc());
        }
        let mut shadow_request = [0u8; MAX_COMMAND_SIZE];
        let shadow_header = CommandHeader {
            tag: TpmiStCommandTag::NoSessions,
            size: shadow_request_size as u32,
            code: cc,
        };
        shadow_header.marshal(
            (&mut shadow_request[..CommandHeader::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        for (i, handle) in cmd.handles[..cmd.handles_len].iter().enumerate() {
            shadow_request[10 + i * 4..14 + i * 4].copy_from_slice(&handle.to_be_bytes());
        }
        shadow_request[10 + (cmd.handles_len * 4)..shadow_request_size]
            .copy_from_slice(cmd.parameters);

        // Track validation state and route to execution
        self.state.sessions_validated_by_handler = false;
        self.state.parsed_auths[..cmd.auth_sessions_len]
            .copy_from_slice(&cmd.auth_sessions[..cmd.auth_sessions_len]);
        self.state.parsed_auths_len = cmd.auth_sessions_len;
        self.state.in_shadow_execution = true;
        let shadow_res = self.execute_without_sessions(
            &shadow_request[..shadow_request_size],
            resp_buf,
            cc,
            shadow_request_size,
        );
        self.state.in_shadow_execution = false;
        self.state.parsed_auths_len = 0;

        if let Ok(shadow_len) = shadow_res {
            let mut has_audit_session = false;
            for auth in &cmd.auth_sessions[..cmd.auth_sessions_len] {
                if auth.session_attributes.0 & 0x80 != 0 {
                    has_audit_session = true;
                    let session_handle = auth.session_handle.0;
                    let mut is_first_use = false;
                    let has_audit_reset = auth.session_attributes.0 & 0x04 != 0; // TpmaSession::AUDIT_RESET
                    if let Some(session_state) = self.state.session_mut(session_handle) {
                        is_first_use = session_state.audit_digest.is_none();
                        if has_audit_reset || is_first_use {
                            let size = session_state.auth_hash.digest_size();
                            let zero_digest = [0u8; 64];
                            session_state.audit_digest = Some(zero_digest);
                            session_state.audit_digest_len = size;
                        }
                    }
                    if is_first_use || has_audit_reset {
                        self.state.exclusive_audit_session = Some(session_handle);
                    } else if self.state.exclusive_audit_session != Some(session_handle) {
                        self.state.exclusive_audit_session = None;
                    }
                }
            }
            if !has_audit_session
                && !matches!(
                    cc,
                    TpmCc::Startup | TpmCc::ContextLoad | TpmCc::ContextSave | TpmCc::FlushContext
                )
            {
                self.state.exclusive_audit_session = None;
            }

            let resp_buffer = resp_buf;
            let mut nonces_tpm_new: [Option<OwnedNonce>; 3] = [None; 3];
            for (i, auth) in cmd.auth_sessions[..cmd.auth_sessions_len]
                .iter()
                .enumerate()
            {
                let session_handle = auth.session_handle.0;
                if (0x02000000..=0x03FFFFFF).contains(&session_handle) {
                    let nonce_size = self
                        .state
                        .session(session_handle)
                        .map(|s| s.nonce_tpm.get_size() as usize)
                        .unwrap_or(32);
                    let mut nonce_bytes = [0u8; 64];
                    self.random_crypto(&mut nonce_bytes[..nonce_size])
                        .map_err(|_| TpmRc::MEMORY)?;
                    nonces_tpm_new[i] = Some(
                        OwnedNonce::from_bytes(&nonce_bytes[..nonce_size])
                            .map_err(|_| TpmRc::MEMORY)?,
                    );
                } else {
                    nonces_tpm_new[i] = None;
                }
            }

            if self.state.sessions_validated_by_handler {
                self.process_response_parameters_with_handler_validation(
                    cmd,
                    cc,
                    command_code,
                    resp_buffer,
                    &nonces_tpm_new,
                )
            } else {
                self.process_response_parameters_without_handler_validation(
                    cmd,
                    cc,
                    command_code,
                    shadow_len,
                    resp_buffer,
                    &nonces_tpm_new,
                )
            }
        } else {
            // On command failure the C reference skips `BuildResponseSession`, so session state
            // (including policy session digests) is left untouched.
            shadow_res
        }
    }

    /// Helper to parse handles, auth sessions area, and extract parameters from the incoming request.
    fn parse_command_and_sessions<'cmd>(
        &mut self,
        cmd_buf: &'cmd [u8],
        cc: TpmCc,
        command_code: u32,
        request_size: usize,
    ) -> Result<ParsedCommand<'cmd>, TpmRc> {
        // 1. Parse Handles
        let num_handles = command_handles_count(cc);
        let handles_size = num_handles * 4;
        if let Some(rc) = handle_area_unmarshal_error(cmd_buf, request_size, cc, num_handles) {
            return Err(rc);
        }
        if num_handles > 3 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let mut handles = [0u32; 3];
        let handles_len = num_handles;
        for (handle_idx, handle) in handles.iter_mut().take(handles_len).enumerate() {
            let offset = 10 + handle_idx * 4;
            *handle = u32::from_be_bytes([
                cmd_buf[offset],
                cmd_buf[offset + 1],
                cmd_buf[offset + 2],
                cmd_buf[offset + 3],
            ]);
        }
        let handle_bytes_read = handles_size;
        // The handles are validated before anything of the authorization area is read, matching
        // the C reference `ExecuteCommand()`: `ParseHandleBuffer`/`EntityGetLoadStatus` run
        // before the `authorizationSize` is unmarshaled (`TPM_RC_INSUFFICIENT` if truncated) and
        // sanity-checked (`TPM_RC_SIZE`), and before `ParseSessionBuffer`. A command whose
        // `authorizationSize` is missing therefore still reports an invalid handle first.
        // TPM 2.0 Part 3, "Handle Area Validation": "A TPM is required to perform the handle area
        // validation before the authorization checks because an authorization cannot be
        // performed unless the authorization values and attributes for the referenced entity are
        // known by the TPM." The handle and session checks "may be performed in any order"; the
        // order of the TCG reference is followed.
        self.validate_command_handles(cc, &handles, handles_len, &[])?;

        // 2. Parse Auth Sessions Area
        let auth_size_offset = 10 + handle_bytes_read;
        if request_size < auth_size_offset + 4 {
            return Err(TpmRc::INSUFFICIENT.to_rc());
        }
        let auth_size = u32::from_be_bytes([
            cmd_buf[auth_size_offset],
            cmd_buf[auth_size_offset + 1],
            cmd_buf[auth_size_offset + 2],
            cmd_buf[auth_size_offset + 3],
        ]) as usize;
        // Sanity check from the C reference `ExecuteCommand()`: the authorization area must be
        // able to hold at least one minimal session (9 bytes) and must fit in the command.
        if auth_size < 9 || request_size - (auth_size_offset + 4) < auth_size {
            return Err(TpmRc::SIZE.to_rc());
        }

        let mut auth_sessions = [OwnedAuthCommand::default(); 3];
        let mut auth_sessions_len = 0;
        let mut session_roles = SessionRoles::default();
        let mut unmarsh = &cmd_buf[auth_size_offset + 4..auth_size_offset + 4 + auth_size];
        while !unmarsh.is_empty() {
            if auth_sessions_len >= 3 {
                return Err(TpmRc::SIZE.with(Position::session(4)));
            }
            let auth = OwnedAuthCommand::unmarshal(&mut unmarsh).map_err(|e| {
                e.with_position(Position::session((auth_sessions_len + 1) as u8))
                    .to_rc()
            })?;
            auth_sessions[auth_sessions_len] = auth;
            auth_sessions_len += 1;
            // As in the C reference `RetrieveSessionData()`, each session is checked right
            // after it is unmarshaled, before the next one is read.
            self.validate_session(
                &auth_sessions[..auth_sessions_len],
                command_code,
                &mut session_roles,
            )?;
        }

        // Map sessions to authorizing handles (C `ParseSessionBuffer()`): the handles that need
        // authorization always come first, and session `i` authorizes the `i`-th of them
        // (`TPM_RH_NULL` included). A handle left without a session is reported as
        // TPM_RC_AUTH_MISSING by `check_unauthorized_handles`.
        let mut session_to_handle_idx = [0usize; 3];
        let mut session_to_handle_idx_len = 0;
        for h_idx in 0..handles_len {
            if handle_requires_auth(TpmCc::new(command_code), h_idx)
                && session_to_handle_idx_len < auth_sessions_len
            {
                if session_to_handle_idx_len >= session_to_handle_idx.len() {
                    return Err(TpmRc::SIZE.to_rc());
                }
                session_to_handle_idx[session_to_handle_idx_len] = h_idx;
                session_to_handle_idx_len += 1;
            }
        }

        // 3. Extract Command Parameters Area
        let parameters_offset = auth_size_offset + 4 + auth_size;
        let parameters_len = request_size - parameters_offset;
        if parameters_len > DECRYPT_BUF_SIZE {
            return Err(TpmRc::SIZE.to_rc());
        }
        let parameters = &cmd_buf[parameters_offset..parameters_offset + parameters_len];

        let mut handle_auths = [OwnedAuth::default(); 3];
        for (i, &h) in handles.iter().take(handles_len).enumerate() {
            handle_auths[i] = self.handle_auth(h);
        }

        Ok(ParsedCommand {
            handles,
            handles_len,
            auth_sessions,
            auth_sessions_len,
            session_to_handle_idx,
            session_to_handle_idx_len,
            parameters,
            ciphertext_parameters: parameters,
            handle_auths,
        })
    }

    /// Validates the last session of `sessions` (the one just unmarshaled), in the order of the
    /// C reference `RetrieveSessionData()`, recording its decrypt/encrypt/audit role in `roles`:
    ///
    /// * a password session must not have the `decrypt`, `encrypt`, `audit`, `auditExclusive`
    ///   or `auditReset` attribute (`TPM_RC_ATTRIBUTES`) and must have an empty nonce
    ///   (`TPM_RC_NONCE`);
    /// * any other session must be loaded (`TPM_RC_REFERENCE_S0 + i`), be referenced with the
    ///   handle type of its kind (`TPM_RC_HANDLE`) and appear only once (`TPM_RC_HANDLE`); a
    ///   session that is also named in the handle area is allowed (e.g. `TPM2_PolicyGetDigest`
    ///   with the same session encrypting);
    /// * `auditExclusive`/`auditReset` need `audit` (`TPM_RC_ATTRIBUTES`);
    /// * `decrypt`, then `encrypt`: the command must allow it and only one session may have it
    ///   (`TPM_RC_ATTRIBUTES`), and the session needs a symmetric algorithm
    ///   (`TPM_RC_SYMMETRIC`);
    /// * `audit`: only one session, not a policy session (`TPM_RC_ATTRIBUTES`), and an
    ///   `auditExclusive` use of an audit session that is not exclusive is `TPM_RC_EXCLUSIVE`.
    ///
    /// TPM 2.0 Part 3, "Session Area Validation": "4. The TPM will unmarshal the authorization
    /// sessions and perform the following validations: [...] 2. If the session is not loaded,
    /// the TPM will return the warning `TPM_RC_REFERENCE_S0` + N where N is the number of the
    /// session. The first session is session zero, N = 0." The specification does not order the
    /// checks of one session against the unmarshaling of the next; like the TCG reference
    /// (`RetrieveSessionData()`), each session is checked before the next one is unmarshaled.
    fn validate_session(
        &self,
        sessions: &[OwnedAuthCommand],
        command_code: u32,
        roles: &mut SessionRoles,
    ) -> Result<(), TpmRc> {
        let Some((auth, earlier)) = sessions.split_last() else {
            return Ok(());
        };
        let i = earlier.len();
        let pos = Position::session((i + 1) as u8);
        let session_handle = auth.session_handle.0;
        let attrs = auth.session_attributes;

        if session_handle == Handle::RS_PW.0 {
            if attrs.intersects(
                TpmaSession::DECRYPT
                    | TpmaSession::ENCRYPT
                    | TpmaSession::AUDIT
                    | TpmaSession::AUDIT_EXCLUSIVE
                    | TpmaSession::AUDIT_RESET,
            ) {
                return Err(TpmRc::ATTRIBUTES.with(pos));
            }
            if auth.nonce.get_size() != 0 {
                return Err(TpmRc::NONCE.with(pos));
            }
            return Ok(());
        }

        // An unloaded session slot is `TPM_RC_REFERENCE_S0 + i`; a loaded slot referenced
        // with the wrong session handle type is `TPM_RC_HANDLE`.
        let Some(session_state) = self.state.session_by_slot(session_handle) else {
            return Err(reference_s(i));
        };
        if session_state.session_handle != session_handle {
            return Err(TpmRc::HANDLE.with(pos));
        }
        if earlier
            .iter()
            .any(|prev| prev.session_handle.0 == session_handle)
        {
            return Err(TpmRc::HANDLE.with(pos));
        }

        if (attrs.contains(TpmaSession::AUDIT_EXCLUSIVE)
            || attrs.contains(TpmaSession::AUDIT_RESET))
            && !attrs.contains(TpmaSession::AUDIT)
        {
            return Err(TpmRc::ATTRIBUTES.with(pos));
        }

        if attrs.contains(TpmaSession::DECRYPT) {
            if !command_supports_decryption(TpmCc::new(command_code)) || roles.decrypt.is_some() {
                return Err(TpmRc::ATTRIBUTES.with(pos));
            }
            if session_state.symmetric.is_none() {
                return Err(TpmRc::SYMMETRIC.with(pos));
            }
            roles.decrypt = Some(i);
        }
        if attrs.contains(TpmaSession::ENCRYPT) {
            if !command_supports_encryption(TpmCc::new(command_code)) || roles.encrypt.is_some() {
                return Err(TpmRc::ATTRIBUTES.with(pos));
            }
            if session_state.symmetric.is_none() {
                return Err(TpmRc::SYMMETRIC.with(pos));
            }
            roles.encrypt = Some(i);
        }
        if attrs.contains(TpmaSession::AUDIT) {
            if roles.audit.is_some() || session_state.session_type != tpm2::TpmSe::HMAC {
                return Err(TpmRc::ATTRIBUTES.with(pos));
            }
            if attrs.contains(TpmaSession::AUDIT_EXCLUSIVE)
                && !attrs.contains(TpmaSession::AUDIT_RESET)
                && session_state.audit_digest.is_some()
                && self.state.exclusive_audit_session != Some(session_handle)
            {
                return Err(TpmRc::EXCLUSIVE);
            }
            roles.audit = Some(i);
        }
        Ok(())
    }

    /// Checks the symmetric mode of the session with the `encrypt` attribute, once all sessions
    /// have been validated (`validate_session`): response parameter encryption uses CFB
    /// (`TPM_RC_MODE` otherwise) or XOR.
    fn validate_encrypt_session_mode(&self, cmd: &ParsedCommand) -> Result<(), TpmRc> {
        let Some((i, auth)) = cmd.auth_sessions[..cmd.auth_sessions_len]
            .iter()
            .enumerate()
            .find(|(_, auth)| {
                auth.session_handle.0 != Handle::RS_PW.0
                    && auth.session_attributes.contains(TpmaSession::ENCRYPT)
            })
        else {
            return Ok(());
        };
        let session_handle = auth.session_handle.0;
        let pos = Position::session((i + 1) as u8);
        if !(0x02000000..=0x03FFFFFF).contains(&session_handle) {
            return Err(TpmRc::VALUE.with(pos));
        }
        let session_state = self
            .state
            .session(session_handle)
            .ok_or(TpmRc::HANDLE.with(pos))?;
        match session_state.symmetric {
            Some(tpm2::TpmtSymDef::Cipher(sym_obj)) => {
                if sym_obj.mode() != Some(CFB_MODE) {
                    return Err(TpmRc::MODE.with(pos));
                }
            }
            Some(tpm2::TpmtSymDef::Xor(_)) => {}
            None => {
                return Err(TpmRc::SYMMETRIC.with(pos));
            }
        }
        Ok(())
    }

    /// Helper to decrypt command parameters if decrypt session attribute is set.
    /// When parameter decryption is active, the decrypted parameter bytes are written into
    /// `decrypt_buf`, and `cmd.parameters` is updated to reference this buffer while
    /// `cmd.ciphertext_parameters` retains its reference to the original ciphertext.
    fn decrypt_command_parameters<'cmd>(
        &mut self,
        mut cmd: ParsedCommand<'cmd>,
        decrypt_buf: &'cmd mut DecryptBuf,
    ) -> Result<ParsedCommand<'cmd>, TpmRc> {
        let mut decrypt_session = None;
        for (i, auth) in cmd
            .auth_sessions
            .iter()
            .enumerate()
            .take(cmd.auth_sessions_len)
        {
            if auth.session_attributes.0 & 0x20 != 0 {
                decrypt_session = Some((i, auth));
                break;
            }
        }
        if let Some((idx, auth_session)) = decrypt_session {
            let session_handle = auth_session.session_handle.0;
            let pos = Position::session((idx + 1) as u8);
            if !(0x02000000..=0x03FFFFFF).contains(&session_handle) {
                return Err(TpmRc::VALUE.with(pos));
            }
            let mut session_key_buf = [0u8; 128];
            let session_key_len;
            let (
                nonce_tpm,
                symmetric,
                auth_hash,
                _bound_entity,
                _is_policy,
                _is_auth_value_needed,
                _is_password_needed,
            ) = {
                let session_state = self
                    .state
                    .session(session_handle)
                    .ok_or(TpmRc::HANDLE.with(pos))?;
                session_key_buf[..session_state.session_key_len]
                    .copy_from_slice(&session_state.session_key[..session_state.session_key_len]);
                session_key_len = session_state.session_key_len;
                (
                    session_state.nonce_tpm,
                    session_state.symmetric,
                    session_state.auth_hash,
                    session_state.bound_entity,
                    session_state.session_type == TpmSe::Policy,
                    session_state.is_auth_value_needed,
                    session_state.is_password_needed,
                )
            };
            let (is_xor, key_bits, sym_obj) = match symmetric {
                Some(tpm2::TpmtSymDef::Cipher(sym_obj)) => {
                    if sym_obj.mode() != Some(CFB_MODE) {
                        return Err(TpmRc::MODE.with(pos));
                    }
                    (false, sym_obj.key_bits(), Some(sym_obj))
                }
                Some(tpm2::TpmtSymDef::Xor(_)) => (true, 0, None),
                None => {
                    return Err(TpmRc::SYMMETRIC.with(pos));
                }
            };

            // Same checks and response codes as the C reference `CryptParameterDecryption()`,
            // with the decrypt session's position added (`RcSafeAddToResult`): the size field
            // must be present (`TPM_RC_INSUFFICIENT`), and the ciphertext must fit in the
            // remaining buffer, which itself must not be empty (`TPM_RC_SIZE`).
            let param_len = cmd.parameters.len();
            if param_len < 2 {
                return Err(TpmRc::INSUFFICIENT.with(pos));
            }
            let param_size = u16::from_be_bytes([cmd.parameters[0], cmd.parameters[1]]) as usize;
            if param_len == 2 || param_len < 2 + param_size {
                return Err(TpmRc::SIZE.with(pos));
            }
            {
                let entity_auth = if idx < cmd.session_to_handle_idx_len {
                    let h_idx = cmd.session_to_handle_idx[idx];
                    self.handle_auth(cmd.handles[h_idx])
                } else {
                    OwnedAuth::default()
                };

                let entity_auth_stripped =
                    crate::util::strip_trailing_zeros(entity_auth.get_buffer());
                let mut kdfa_key = [0u8; 256];
                let kdfa_key_len = session_key_len + entity_auth_stripped.len();
                if kdfa_key_len > 256 {
                    return Err(TpmRc::FAILURE);
                }
                kdfa_key[..session_key_len].copy_from_slice(&session_key_buf[..session_key_len]);
                kdfa_key[session_key_len..kdfa_key_len].copy_from_slice(entity_auth_stripped);

                decrypt_buf[..param_len].copy_from_slice(cmd.parameters);

                if is_xor {
                    xor_obfuscation(
                        &self.crypto(),
                        auth_hash,
                        &kdfa_key[..kdfa_key_len],
                        auth_session.nonce.get_buffer(),
                        nonce_tpm.get_buffer(),
                        &mut decrypt_buf[2..2 + param_size],
                    )?;
                } else {
                    let sym_obj = sym_obj.ok_or_else(|| TpmRc::SYMMETRIC.with(pos))?;
                    let mut derived_key = [0u8; 64];
                    let mut derived_iv = [0u8; 16];
                    derive_key_and_iv(
                        &self.crypto(),
                        auth_hash,
                        &kdfa_key[..kdfa_key_len],
                        b"CFB",
                        auth_session.nonce.get_buffer(),
                        nonce_tpm.get_buffer(),
                        (key_bits / 8) as usize,
                        &mut derived_key[..(key_bits / 8) as usize],
                        &mut derived_iv,
                    )?;

                    let mut iv = derived_iv;
                    crate::handler::sym_encrypt_decrypt(
                        &self.crypto(),
                        sym_obj,
                        &derived_key[..(key_bits / 8) as usize],
                        &mut iv,
                        Direction::Decrypt,
                        &mut decrypt_buf[2..2 + param_size],
                    )
                    .map_err(|_| TpmRc::SYMMETRIC.with(pos))?;
                }
                cmd.parameters = &decrypt_buf[..param_len];
            }
        }
        Ok(cmd)
    }

    /// Reads the public area of NV Index `handle` together with the storage offset of its data.
    ///
    /// Returns `None` if the index is not defined or its header cannot be parsed.
    fn read_nv_index_public(&mut self, handle: u32) -> Option<(u16, crate::owned::OwnedNvPublic)> {
        let storage_mgr = &mut self.state.nv.index;
        let metadata = storage_mgr.get_metadata(handle).ok()?;
        let read_len = core::cmp::min(metadata.data_size as usize, 1536);
        let mut read_buf = [0u8; 1536];
        storage_mgr
            .read_item(handle, 0, &mut read_buf[..read_len])
            .ok()?;
        let (metadata_size, nv_public, _, _) =
            crate::handler::nv_storage::unmarshal_nv_header(&read_buf[..read_len]).ok()?;
        Some((u16::try_from(metadata_size).ok()?, nv_public))
    }

    /// Returns the object (transient or persistent) referenced by `handle`, if any.
    ///
    /// Sequence objects are not returned.
    fn authorized_object(&mut self, handle: u32) -> Option<crate::handler::TransientObject> {
        if (0x80000000..=0x80FFFFFF).contains(&handle) {
            self.state.find_transient_object(handle).cloned()
        } else if (0x81000000..=0x81FFFFFF).contains(&handle) {
            self.load_persistent_object(handle).ok()
        } else {
            None
        }
    }

    /// Returns whether authorizing `handle` (handle `handle_index` of command `cc`) requires a
    /// policy session (C `IsPolicySessionRequired()`):
    /// - the DUP role always requires a policy session;
    /// - the ADMIN role requires one unless the entity is an object with `adminWithPolicy` clear;
    /// - a PCR in the policy group requires one once `TPM2_PCR_SetAuthPolicy` set a policy
    ///   algorithm for it.
    fn is_policy_session_required(&mut self, cc: TpmCc, handle_index: usize, handle: u32) -> bool {
        // A firmware-limited or SVN-limited hierarchy is authorized by its base hierarchy (TPM
        // 2.0 Part 1, "Primary Seed Authorizations"; C `HierarchyNormalizeHandle`).
        let handle = crate::hierarchy::normalize(handle);
        match command_auth_role(cc, handle_index) {
            AuthRole::Dup => true,
            AuthRole::Admin => {
                if self.state.find_active_sequence(handle).is_some() {
                    // A sequence object is a transient object whose adminWithPolicy is CLEAR.
                    false
                } else if (0x80000000..=0x81FFFFFF).contains(&handle) {
                    self.authorized_object(handle).is_none_or(|obj| {
                        obj.public
                            .object_attributes
                            .contains(tpm2::TpmaObject::ADMIN_WITH_POLICY)
                    })
                } else {
                    true
                }
            }
            AuthRole::User | AuthRole::None => {
                crate::handler::pcr::pcr_belongs_policy_group(handle)
                    && self.state.nv.persistent.pcr_policy_alg.is_some()
            }
        }
    }

    /// Returns whether the authValue of `handle` may be used to authorize handle `handle_index`
    /// of command `cc` with a password or HMAC session (C `IsAuthValueAvailable()`):
    /// - permanent handles: only the hierarchies, `TPM_RH_LOCKOUT` and `TPM_RH_NULL`, and the
    ///   implemented ACTs while `phEnable` is SET;
    /// - sequence objects: always;
    /// - other objects: only if the sensitive area is loaded (not public-only) and either
    ///   `userWithAuth` is SET or the ADMIN role is required and `adminWithPolicy` is CLEAR;
    /// - NV Indices: `TPMA_NV_AUTHWRITE` for write operations; for read operations PIN indices
    ///   need `TPMA_NV_WRITTEN` and `pinCount < pinLimit`, other indices `TPMA_NV_AUTHREAD`;
    /// - PCRs: always.
    fn is_auth_value_available(&mut self, cc: TpmCc, handle_index: usize, handle: u32) -> bool {
        // A firmware-limited or SVN-limited hierarchy is authorized by its base hierarchy (TPM
        // 2.0 Part 1, "Primary Seed Authorizations"; C `HierarchyNormalizeHandle`).
        let handle = crate::hierarchy::normalize(handle);
        match Handle(handle).handle_type() {
            // Part 1, "Authenticated Countdown Timer (ACT)": the ACT authValue "can only be used
            // if *phEnable* is SET".
            Some(TpmHt::Permanent) if crate::act::is_implemented_act(handle) => {
                self.state.ph_enable
            }
            Some(TpmHt::Permanent) => {
                matches!(
                    Handle(handle),
                    Handle::RH_OWNER
                        | Handle::RH_ENDORSEMENT
                        | Handle::RH_PLATFORM
                        | Handle::RH_LOCKOUT
                        | Handle::RH_NULL
                ) || is_vendor_permanent_auth(handle)
            }
            Some(TpmHt::Transient) | Some(TpmHt::Persistent) => {
                if self.state.find_active_sequence(handle).is_some() {
                    return true;
                }
                let Some(obj) = self.authorized_object(handle) else {
                    return false;
                };
                let attrs = obj.public.object_attributes;
                !obj.public_only
                    && (attrs.contains(tpm2::TpmaObject::USER_WITH_AUTH)
                        || (command_auth_role(cc, handle_index) == AuthRole::Admin
                            && !attrs.contains(tpm2::TpmaObject::ADMIN_WITH_POLICY)))
            }
            Some(TpmHt::NVIndex) => {
                let Some((data_offset, nv_public)) = self.read_nv_index_public(handle) else {
                    return false;
                };
                let attrs = nv_public.attributes;
                if is_nv_write_operation(cc) {
                    attrs.contains(tpm2::TpmaNv::AUTHWRITE)
                } else if matches!(
                    attrs.get_index_type(),
                    Ok(tpm2::TpmNt::PinFail) | Ok(tpm2::TpmNt::PinPass)
                ) {
                    attrs.contains(tpm2::TpmaNv::WRITTEN)
                        && self
                            .read_nv_pin(handle, data_offset)
                            .is_some_and(|(count, limit)| count < limit)
                } else {
                    attrs.contains(tpm2::TpmaNv::AUTHREAD)
                }
            }
            Some(TpmHt::PCR) => true,
            _ => false,
        }
    }

    /// Returns whether the entity-specific conditions of C `IsAuthPolicyAvailable()` that are
    /// not covered by `check_policy_auth_session` hold for `handle`:
    /// - objects whose sensitive area is not loaded (public-only) never have a policy available;
    /// - an NV Index with a non-empty `authPolicy` may only be authorized by policy if a policy
    ///   session is required anyway, or if `TPMA_NV_POLICYWRITE` (write operations) /
    ///   `TPMA_NV_POLICYREAD` (read operations) is SET.
    fn is_entity_auth_policy_allowed(
        &mut self,
        cc: TpmCc,
        handle_index: usize,
        handle: u32,
    ) -> bool {
        // A firmware-limited or SVN-limited hierarchy is authorized by its base hierarchy (TPM
        // 2.0 Part 1, "Primary Seed Authorizations"; C `HierarchyNormalizeHandle`).
        let handle = crate::hierarchy::normalize(handle);
        match Handle(handle).handle_type() {
            Some(TpmHt::Transient) | Some(TpmHt::Persistent) => self
                .authorized_object(handle)
                .is_none_or(|obj| !obj.public_only),
            Some(TpmHt::NVIndex) => {
                let Some((_, nv_public)) = self.read_nv_index_public(handle) else {
                    return false;
                };
                // An empty authPolicy is reported by `check_policy_auth_session`.
                if nv_public.auth_policy.get_size() == 0
                    || self.is_policy_session_required(cc, handle_index, handle)
                {
                    return true;
                }
                nv_public.attributes.contains(if is_nv_write_operation(cc) {
                    tpm2::TpmaNv::POLICYWRITE
                } else {
                    tpm2::TpmaNv::POLICYREAD
                })
            }
            _ => true,
        }
    }

    /// Reads `(pinCount, pinLimit)` (`TPMS_NV_PIN_COUNTER_PARAMETERS`) from the data of a PIN
    /// Index stored at `data_offset`.
    fn read_nv_pin(&mut self, handle: u32, data_offset: u16) -> Option<(u32, u32)> {
        let mut pin = [0u8; 8];
        self.state
            .nv
            .index
            .read_item(handle, data_offset, &mut pin)
            .ok()?;
        Some((
            u32::from_be_bytes([pin[0], pin[1], pin[2], pin[3]]),
            u32::from_be_bytes([pin[4], pin[5], pin[6], pin[7]]),
        ))
    }

    /// Updates the `pinCount` of a written PIN Index whose authValue was used for an
    /// authorization (the PIN processing at the end of C `CheckAuthSession()`):
    /// - `TPM_NT_PIN_FAIL`: incremented on failure, reset to 0 on success;
    /// - `TPM_NT_PIN_PASS`: incremented on success.
    ///
    /// Does nothing for any other entity.
    fn update_nv_pin_count(&mut self, handle: u32, success: bool) {
        if Handle(handle).handle_type() != Some(TpmHt::NVIndex) {
            return;
        }
        let Some((data_offset, nv_public)) = self.read_nv_index_public(handle) else {
            return;
        };
        let attrs = nv_public.attributes;
        if !attrs.contains(tpm2::TpmaNv::WRITTEN) {
            return;
        }
        // The counter of a non-orderly index lives in NV: while NV is unavailable it cannot be
        // updated, and the update is dropped (TCG reference: `NvWriteUINT64Data()` ->
        // `NvConditionallyWrite()` writes only while `g_NvStatus` is `TPM_RC_SUCCESS`, and the
        // authorization result stands).
        if !attrs.contains(tpm2::TpmaNv::ORDERLY) && !self.state.nv_available {
            return;
        }
        let Some((count, limit)) = self.read_nv_pin(handle, data_offset) else {
            return;
        };
        let new_count = match attrs.get_index_type() {
            Ok(tpm2::TpmNt::PinFail) if success => 0,
            Ok(tpm2::TpmNt::PinFail) => count.wrapping_add(1),
            Ok(tpm2::TpmNt::PinPass) if success => count.wrapping_add(1),
            _ => return,
        };
        let mut pin = [0u8; 8];
        pin[..4].copy_from_slice(&new_count.to_be_bytes());
        pin[4..].copy_from_slice(&limit.to_be_bytes());
        let storage_mgr = &mut self.state.nv.index;
        if storage_mgr.write_item(handle, data_offset, &pin).is_ok() {
            self.state.update_nv |= if attrs.contains(tpm2::TpmaNv::ORDERLY) {
                UT_ORDERLY
            } else {
                UT_NV
            };
        }
    }

    /// Fails if the TPM is in DA lockout for the authValue about to be used (C
    /// `CheckLockedOut()`; `lockout_auth` selects the `lockoutAuth` check), and records that a
    /// DA-protected object was used in this power cycle (`SU_DA_USED_VALUE`).
    ///
    /// The flag only covers the entities governed by `failedTries` (TPM 2.0 Part 1, "Non-orderly
    /// Shutdown": an NV flag "indicating that access to a DA protected object occurred");
    /// `lockoutAuth` has its own protection (`lockoutRecovery`), so its use does not set it, as
    /// in the reference `CheckLockedOut()`.
    ///
    /// The flag must reach NV before the DA-protected authorization is checked (TPM 2.0 Part 1,
    /// "Non-orderly Shutdown": "An alternative implementation sets an NV flag indicating that
    /// access to a DA protected object occurred during this boot cycle. After a non-orderly
    /// restart, if the flag is set, the TPM increments *failedTries* and clears the flag."), so
    /// while NV is unavailable the first such use in a power cycle fails with
    /// `TPM_RC_NV_UNAVAILABLE`, as in the reference (`CheckLockedOut()`, `USE_DA_USED`).
    fn check_da_lockout(&mut self, lockout_auth: bool) -> Result<(), TpmRc> {
        self.check_locked_out(lockout_auth)?;
        if !lockout_auth && !self.state.da_used {
            if !self.state.nv_available {
                return Err(TpmRc::NV_UNAVAILABLE);
            }
            self.state.da_used = true;
            self.state.nv.persistent.orderly_state = 0xFFFE;
            let _ = self.state.nv.index.write_reserved(
                crate::storage::nv::NvHeader::ORDERLY_STATE_OFFSET,
                &self.state.nv.persistent.orderly_state.to_be_bytes(),
            );
        }
        Ok(())
    }

    /// Registers a DA authorization failure (the side effects of C `IncrementLockout()` when DA
    /// applies): disables `lockoutAuth` if `lockout_auth`, otherwise increments `failedTries`
    /// (unless DA is disabled with `recoveryTime == 0`), and restarts the matching self-healing
    /// timer.
    fn register_da_failure(&mut self, lockout_auth: bool) {
        if lockout_auth {
            self.state.nv.persistent.lockout_auth_enabled = false;
            self.state.nv.orderly.lockout_timer = self.state.tpm_time_ms as i64;
            // With lockoutRecovery == 0, lockoutAuth is re-enabled at the next startup anyway,
            // so NV is not updated (C `IncrementLockout()`).
            if self.state.nv.persistent.lockout_recovery != 0 {
                if self.state.nv_available {
                    self.save_hierarchy_auths();
                } else {
                    self.state.da_pending_on_nv = true;
                }
            }
        } else {
            if self.state.nv.persistent.recovery_time != 0 {
                self.state.nv.persistent.failed_tries =
                    self.state.nv.persistent.failed_tries.saturating_add(1);
                if self.state.nv_available {
                    let _ = self.state.nv.index.write_reserved(
                        crate::storage::nv::NvHeader::FAILED_TRIES_OFFSET,
                        &self.state.nv.persistent.failed_tries.to_be_bytes(),
                    );
                } else {
                    self.state.da_pending_on_nv = true;
                }
            }
            self.state.nv.orderly.self_heal_timer = self.state.tpm_time_ms as i64;
            // A failure on a `failedTries`-governed entity is a DA-protected access (see
            // [`Self::check_da_lockout`]); a `lockoutAuth` failure is not.
            self.state.da_used = true;
            if self.state.nv_available {
                self.state.nv.persistent.orderly_state = 0xFFFE;
                let _ = self.state.nv.index.write_reserved(
                    crate::storage::nv::NvHeader::ORDERLY_STATE_OFFSET,
                    &self.state.nv.persistent.orderly_state.to_be_bytes(),
                );
            } else {
                self.state.clear_orderly = true;
            }
        }
    }

    /// Helper to verify HMACs of authorization sessions.
    fn verify_session_hmacs(
        &mut self,
        cmd: &mut ParsedCommand,
        command_code: u32,
    ) -> Result<(), TpmRc> {
        let mut decrypt_session_idx = None;
        let mut encrypt_session_idx = None;
        for (i, auth) in cmd
            .auth_sessions
            .iter()
            .enumerate()
            .take(cmd.auth_sessions_len)
        {
            if auth.session_attributes.0 & 0x20 != 0 {
                decrypt_session_idx = Some(i);
            }
            if auth.session_attributes.0 & 0x40 != 0 {
                encrypt_session_idx = Some(i);
            }
        }

        let mut auth_handle_names = [OwnedName::default(); 3];
        let mut auth_handle_names_len = 0;
        for &handle in cmd.handles.iter().take(cmd.handles_len) {
            auth_handle_names[auth_handle_names_len] = handle_name(self, handle);
            auth_handle_names_len += 1;
        }

        for (i, auth) in cmd
            .auth_sessions
            .iter()
            .enumerate()
            .take(cmd.auth_sessions_len)
        {
            let session_handle = auth.session_handle.0;
            let pos = Position::session((i + 1) as u8);

            if session_handle == 0x40000009 {
                // A password session must authorize a handle (C `ParseSessionBuffer`).
                if i >= cmd.session_to_handle_idx_len {
                    return Err(TpmRc::HANDLE.with(pos));
                }
                let h_idx = cmd.session_to_handle_idx[i];
                let handle = cmd.handles[h_idx];
                let cc = TpmCc::new(command_code);
                // Physical Presence comes before any other authorization check (TPM 2.0 Part 1,
                // "Physical Presence Authorization"; C `CheckAuthSession()`).
                if crate::hierarchy::normalize(handle) == Handle::RH_PLATFORM.0
                    && self.physical_presence_missing(cc)
                {
                    return Err(TpmRc::PP.with(pos));
                }
                let lockout_auth = handle == Handle::RH_LOCKOUT.0;
                let da_protected = self.has_da_protection(handle);

                // C `CheckAuthSession()`: a password session always uses the authValue, so DA
                // lockout is checked first, then whether the authValue may be used at all.
                if da_protected {
                    self.check_da_lockout(lockout_auth)?;
                }
                if self.is_policy_session_required(cc, h_idx, handle) {
                    return Err(TpmRc::AUTH_TYPE);
                }
                if !self.is_auth_value_available(cc, h_idx, handle) {
                    return Err(TpmRc::AUTH_UNAVAILABLE);
                }

                // C `CheckPWAuthSession()`: both values have their trailing zeros removed and
                // must then be identical (same length and contents).
                let expected_auth = self.handle_auth(handle);
                let provided_stripped = crate::util::strip_trailing_zeros(auth.hmac.get_buffer());
                let expected_stripped =
                    crate::util::strip_trailing_zeros(expected_auth.get_buffer());
                let auth_matches =
                    crate::util::constant_time_eq(expected_stripped, provided_stripped);
                self.update_nv_pin_count(handle, auth_matches);
                if !auth_matches {
                    // C `IncrementLockout()`: no DA side effects for a DA-exempt entity.
                    if da_protected {
                        self.register_da_failure(lockout_auth);
                        return Err(TpmRc::AUTH_FAIL.with(pos));
                    }
                    return Err(TpmRc::BAD_AUTH.with(pos));
                }
            } else {
                if !(0x02000000..=0x03FFFFFF).contains(&session_handle) {
                    return Err(TpmRc::VALUE.with(pos));
                }

                // Consistency checks from the C reference `ParseSessionBuffer`: a trial policy
                // session cannot appear in the session area at all, and a session that does not
                // authorize a handle must be an audit, encrypt or decrypt session.
                let session_type = self
                    .state
                    .session(session_handle)
                    .ok_or(TpmRc::HANDLE.with(pos))?
                    .session_type;
                if session_type == TpmSe::Trial {
                    return Err(TpmRc::ATTRIBUTES.with(pos));
                }
                // A session bound to a DA-protected entity (C `isDaBound`) is subject to DA
                // lockout however it is used, even if it authorizes nothing or a DA-exempt
                // entity (C `ParseSessionBuffer()`).
                let (is_da_bound, is_lockout_bound) = self
                    .state
                    .session(session_handle)
                    .map_or((false, false), |s| (s.is_da_bound, s.is_lockout_bound));
                if is_da_bound {
                    self.check_da_lockout(is_lockout_bound)?;
                }
                if i >= cmd.session_to_handle_idx_len
                    && !auth.session_attributes.intersects(
                        TpmaSession::AUDIT | TpmaSession::ENCRYPT | TpmaSession::DECRYPT,
                    )
                {
                    return Err(TpmRc::ATTRIBUTES.with(pos));
                }

                // Physical Presence comes before any other authorization check (TPM 2.0 Part 1,
                // "Physical Presence Authorization"; C `CheckAuthSession()`), for HMAC and
                // policy sessions alike (Part 3, TPM2_PP_Commands).
                if i < cmd.session_to_handle_idx_len
                    && crate::hierarchy::normalize(cmd.handles[cmd.session_to_handle_idx[i]])
                        == Handle::RH_PLATFORM.0
                    && self.physical_presence_missing(TpmCc::new(command_code))
                {
                    return Err(TpmRc::PP.with(pos));
                }

                let entity_auth = if i < cmd.session_to_handle_idx_len {
                    let h_idx = cmd.session_to_handle_idx[i];
                    self.handle_auth(cmd.handles[h_idx])
                } else {
                    OwnedAuth::default()
                };

                let dec_nonce = if i == 0 && i < cmd.session_to_handle_idx_len {
                    if let Some(dec_idx) = decrypt_session_idx {
                        if dec_idx != i {
                            let dec_handle = cmd.auth_sessions[dec_idx].session_handle.0;
                            self.state.session(dec_handle).map(|s| s.nonce_tpm)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                let enc_nonce = if i == 0 && i < cmd.session_to_handle_idx_len {
                    if let Some(enc_idx) = encrypt_session_idx {
                        if enc_idx != i && Some(enc_idx) != decrypt_session_idx {
                            let enc_handle = cmd.auth_sessions[enc_idx].session_handle.0;
                            self.state.session(enc_handle).map(|s| s.nonce_tpm)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                // C `s_associatedHandles[i] = HierarchyNormalizeHandle(command->handles[i])`: a
                // firmware-limited or SVN-limited hierarchy is authorized as its base hierarchy
                // (its authValue, authPolicy, and the entity a session can be bound to).
                let entity_handle = if i < cmd.session_to_handle_idx_len {
                    let h_idx = cmd.session_to_handle_idx[i];
                    Some(crate::hierarchy::normalize(cmd.handles[h_idx]))
                } else {
                    None
                };

                // Retrieve attributes first to avoid borrow-check conflicts
                let h_idx = if i < cmd.session_to_handle_idx_len {
                    cmd.session_to_handle_idx[i]
                } else {
                    9999
                };
                let cc = TpmCc::new(command_code);

                let mut session_key_buf = [0u8; 128];
                let mut hmac_key = [0u8; 256];
                let (
                    auth_hash,
                    nonce_tpm,
                    session_key_len,
                    bound_entity,
                    is_policy,
                    is_auth_value_needed,
                    is_password_needed,
                ) = {
                    let session_state = self
                        .state
                        .session(session_handle)
                        .ok_or(TpmRc::HANDLE.with(pos))?;
                    let session_key_len = session_state.session_key_len;

                    // Copy session key out
                    session_key_buf[..session_key_len]
                        .copy_from_slice(&session_state.session_key[..session_key_len]);

                    (
                        session_state.auth_hash,
                        session_state.nonce_tpm,
                        session_key_len,
                        session_state.bound_entity,
                        session_state.session_type == TpmSe::Policy,
                        session_state.is_auth_value_needed,
                        session_state.is_password_needed,
                    )
                };

                // C `IsSessionBindEntity()`: a bound HMAC session is bound to the authorized
                // entity if the bind value recomputed for that entity (whatever handle it is
                // referenced by) equals the one recorded by `TPM2_StartAuthSession`.
                let entity_auth_stripped =
                    crate::util::strip_trailing_zeros(entity_auth.get_buffer());
                let is_bound = match entity_handle {
                    // Only a bound session has a bind value (`isBound`).
                    Some(h) if bound_entity.get_size() > 0 => {
                        let name = self.handle_name(h);
                        crate::handler::session::compute_bound_entity(
                            name.get_buffer(),
                            entity_auth_stripped,
                        )
                        .is_ok_and(|bind_value| bind_value == bound_entity)
                    }
                    _ => false,
                };

                // C `CheckAuthSession()` (`includeAuth`, which is also `authUsed`): a policy
                // session uses the authValue only after `TPM2_PolicyAuthValue` or
                // `TPM2_PolicyPassword`, an HMAC session unless it is bound to the entity. A
                // session that authorizes no handle never uses an authValue
                // (`ParseSessionBuffer()`).
                let include_auth = entity_handle.is_some()
                    && if is_policy {
                        is_auth_value_needed || is_password_needed
                    } else {
                        !is_bound
                    };
                if let Some(s) = self.state.session_mut(session_handle) {
                    s.include_auth = include_auth;
                }

                let mut da_protected = false;
                if let Some(h) = entity_handle {
                    da_protected = self.has_da_protection(h);
                    // DA lockout only matters if the authValue is going to be used.
                    if include_auth && da_protected {
                        self.check_da_lockout(h == Handle::RH_LOCKOUT.0)?;
                    }
                    if is_policy {
                        if !self.is_entity_auth_policy_allowed(cc, h_idx, h) {
                            return Err(TpmRc::AUTH_UNAVAILABLE);
                        }
                    } else {
                        if self.is_policy_session_required(cc, h_idx, h) {
                            return Err(TpmRc::AUTH_TYPE);
                        }
                        if !self.is_auth_value_available(cc, h_idx, h) {
                            return Err(TpmRc::AUTH_UNAVAILABLE);
                        }
                    }
                }

                let hmac_key_len = if include_auth {
                    session_key_len + entity_auth_stripped.len()
                } else {
                    session_key_len
                };
                if hmac_key_len > 256 {
                    return Err(TpmRc::FAILURE);
                }
                // Copy session key to hmac_key
                hmac_key[..session_key_len].copy_from_slice(&session_key_buf[..session_key_len]);
                if include_auth {
                    hmac_key[session_key_len..hmac_key_len].copy_from_slice(entity_auth_stripped);
                }

                let command_code_bytes = command_code.to_be_bytes();
                let mut updates_hash_refs: [&[u8]; 5] = [&[]; 5];
                let mut updates_hash_refs_len = 0;
                updates_hash_refs[updates_hash_refs_len] = &command_code_bytes;
                updates_hash_refs_len += 1;
                for name in auth_handle_names.iter().take(auth_handle_names_len) {
                    updates_hash_refs[updates_hash_refs_len] = name.get_buffer();
                    updates_hash_refs_len += 1;
                }
                updates_hash_refs[updates_hash_refs_len] = cmd.ciphertext_parameters;
                updates_hash_refs_len += 1;

                let mut updates_hmac_refs: [&[u8]; 5] = [&[]; 5];
                let mut updates_hmac_refs_len = 0;
                updates_hmac_refs[updates_hmac_refs_len] = auth.nonce.get_buffer();
                updates_hmac_refs_len += 1;
                updates_hmac_refs[updates_hmac_refs_len] = nonce_tpm.get_buffer();
                updates_hmac_refs_len += 1;
                if let Some(ref dn) = dec_nonce {
                    updates_hmac_refs[updates_hmac_refs_len] = dn.get_buffer();
                    updates_hmac_refs_len += 1;
                }
                if let Some(ref en) = enc_nonce {
                    updates_hmac_refs[updates_hmac_refs_len] = en.get_buffer();
                    updates_hmac_refs_len += 1;
                }
                let attr_byte = [auth.session_attributes.0];
                updates_hmac_refs[updates_hmac_refs_len] = &attr_byte;
                updates_hmac_refs_len += 1;

                let mut computed_hmac = [0u8; 64];
                let mut cp_hash = [0u8; 64];
                let (cp_hash_len, computed_hmac_len) = compute_hash_and_hmac(
                    &self.crypto(),
                    auth_hash,
                    &hmac_key[..hmac_key_len],
                    &updates_hash_refs[..updates_hash_refs_len],
                    &updates_hmac_refs[..updates_hmac_refs_len],
                    &mut cp_hash,
                    &mut computed_hmac,
                )?;

                // Policy session checks (C `IsAuthPolicyAvailable` + `CheckPolicyAuthSession`).
                // These only apply to a policy session that authorizes a handle, and they run
                // before the HMAC/password check so that a failing policy never consumes a DA
                // attempt.
                if is_policy && let Some(h) = entity_handle {
                    self.check_policy_auth_session(PolicyAuthCheck {
                        session_handle,
                        entity_handle: h,
                        handle_index: h_idx,
                        command_code,
                        parameters: cmd.parameters,
                        cp_hash: &cp_hash[..cp_hash_len],
                        handle_names: &auth_handle_names[..auth_handle_names_len],
                        pos,
                    })?;
                }

                let auth_matches = if is_policy && is_password_needed && entity_handle.is_some() {
                    // C `CheckPWAuthSession()` (TPM2_PolicyPassword): plaintext authValue
                    // comparison with trailing zeros removed.
                    let provided_stripped =
                        crate::util::strip_trailing_zeros(auth.hmac.get_buffer());
                    crate::util::constant_time_eq(provided_stripped, entity_auth_stripped)
                } else if hmac_key_len == 0 && auth.hmac.get_size() == 0 {
                    // C `ComputeCommandHMAC()`: with an empty HMAC key, an empty authHMAC is
                    // accepted (for any session type).
                    true
                } else {
                    // C `CheckSessionHMAC()`: the HMAC must match exactly (length and value).
                    crate::util::constant_time_eq(
                        auth.hmac.get_buffer(),
                        &computed_hmac[..computed_hmac_len],
                    )
                };

                // PIN Index processing (end of C `CheckAuthSession()`), only when the PIN
                // Index authValue was used.
                if include_auth && let Some(h) = entity_handle {
                    self.update_nv_pin_count(h, auth_matches);
                }

                if !auth_matches {
                    // C `IncrementLockout()`: the failure counts against DA if the session is
                    // bound to a DA-protected entity (against lockoutAuth if bound to
                    // TPM_RH_LOCKOUT), or if the authValue of a DA-protected entity was used;
                    // otherwise it is reported as TPM_RC_BAD_AUTH without side effects.
                    if is_da_bound || (include_auth && da_protected) {
                        let lockout_auth =
                            is_lockout_bound || entity_handle == Some(Handle::RH_LOCKOUT.0);
                        self.register_da_failure(lockout_auth);
                        return Err(TpmRc::AUTH_FAIL.with(pos));
                    }
                    return Err(TpmRc::BAD_AUTH.with(pos));
                }

                if self.state.session(session_handle).is_none() {
                    return Err(TpmRc::AUTH_FAIL.with(pos));
                }

                if auth.session_attributes.0 & 0x80 != 0 {
                    self.state.session_audit_cp_hashes[i] =
                        OwnedDigest::new(&cp_hash[..cp_hash_len]);
                }
            }
        }
        Ok(())
    }

    /// Returns the hash algorithm associated with `handle`'s `authPolicy` (the return value of the
    /// C reference `EntityGetAuthPolicy()`), or `None` when the entity has no such algorithm
    /// (`TPM_ALG_NULL`).
    ///
    /// Permanent hierarchies use the algorithm set by `TPM2_SetPrimaryPolicy`, objects and NV
    /// indices use their `nameAlg`, and the PCR policy group (PCR 20–22) uses the algorithm set
    /// by `TPM2_PCR_SetAuthPolicy`.
    fn handle_policy_alg(&mut self, handle: u32) -> Option<TpmiAlgHash> {
        // A firmware-limited or SVN-limited hierarchy is authorized by its base hierarchy (TPM
        // 2.0 Part 1, "Primary Seed Authorizations"; C `HierarchyNormalizeHandle`).
        let handle = crate::hierarchy::normalize(handle);
        if handle == Handle::RH_OWNER.0 {
            self.state.nv.persistent.owner_alg
        } else if handle == Handle::RH_ENDORSEMENT.0 {
            self.state.nv.persistent.endorsement_alg
        } else if handle == Handle::RH_PLATFORM.0 {
            self.state.nv.clear.platform_alg
        } else if handle == Handle::RH_LOCKOUT.0 {
            self.state.nv.persistent.lockout_alg
        } else if let Some(index) = crate::act::act_index(handle) {
            self.state.act.policies[index].hash_alg
        } else if let Some(obj) = self.state.find_transient_object(handle) {
            obj.public.name_alg
        } else if (0x81000000..=0x81FFFFFF).contains(&handle) {
            self.load_persistent_object(handle)
                .ok()
                .and_then(|obj| obj.public.name_alg)
        } else if Handle(handle).handle_type() == Some(TpmHt::NVIndex) {
            let storage_mgr = &mut self.state.nv.index;
            let metadata = storage_mgr.get_metadata(handle).ok()?;
            let read_len = core::cmp::min(metadata.data_size as usize, 1536);
            let mut read_buf = [0u8; 1536];
            storage_mgr
                .read_item(handle, 0, &mut read_buf[..read_len])
                .ok()?;
            let (_, nv_public, _, _) =
                crate::handler::nv_storage::unmarshal_nv_header(&read_buf[..read_len]).ok()?;
            Some(nv_public.name_alg)
        } else if crate::handler::pcr::pcr_belongs_policy_group(handle) {
            self.state.nv.persistent.pcr_policy_alg
        } else {
            None
        }
    }

    /// Validates a policy session used to authorize `check.entity_handle`.
    ///
    /// This is the equivalent of the C reference `IsAuthPolicyAvailable()` followed by
    /// `CheckPolicyAuthSession()` (`SessionProcess.c`), performed in the same order and with the
    /// same response codes. Format-one codes carry the session position (`RcSafeAddToResult`):
    /// 1. Empty `authPolicy` on an entity other than an object or a PCR in the policy group:
    ///    `TPM_RC_AUTH_UNAVAILABLE`.
    /// 2. `TPM2_PolicySecret` authorized by a session without `PolicyPassword`/`PolicyAuthValue`:
    ///    `TPM_RC_MODE`.
    /// 3. PCRs changed since `TPM2_PolicyPCR`: `TPM_RC_PCR_CHANGED`.
    /// 4. `policyDigest != authPolicy`, then policy hash algorithm mismatch: `TPM_RC_POLICY_FAIL`.
    /// 5. Session timeout (only when a timeout is set): `TPM_RC_NV_UNAVAILABLE` if NV is not
    ///    available, else `TPM_RC_EXPIRED` if the timeout passed or the time epoch changed. The
    ///    session is *not* flushed, so it can still be restarted or flushed by the caller.
    /// 6. `commandCode` mismatch: `TPM_RC_POLICY_CC`; no `commandCode` for an ADMIN/DUP role
    ///    authorization: `TPM_RC_POLICY_FAIL`.
    /// 7. Locality: `TPM_RC_LOCALITY`.
    /// 8. cpHash / nameHash / templateHash: `TPM_RC_POLICY_FAIL`.
    /// 9. `TPM2_PolicyNvWritten` state: `TPM_RC_POLICY_FAIL`.
    /// 10. `TPM2_PolicyTransportSPDM` restrictions: `TPM_RC_CHANNEL`, `TPM_RC_CHANNEL_KEY`.
    fn check_policy_auth_session(&mut self, check: PolicyAuthCheck) -> Result<(), TpmRc> {
        let PolicyAuthCheck {
            session_handle,
            entity_handle,
            handle_index,
            command_code,
            parameters,
            cp_hash,
            handle_names,
            pos,
        } = check;
        let cc = TpmCc::new(command_code);

        let policy = self.handle_policy(entity_handle)?;
        let policy_alg = self.handle_policy_alg(entity_handle);
        let session = self
            .state
            .session(session_handle)
            .ok_or(TpmRc::HANDLE.with(pos))?;

        // IsAuthPolicyAvailable(): objects (other than sequence objects) and the PCR policy group
        // always have a policy available, even if it is empty; anything else needs a non-empty
        // authPolicy.
        let is_object = (0x80000000..=0x81FFFFFF).contains(&entity_handle)
            && self.state.find_active_sequence(entity_handle).is_none();
        let is_policy_pcr = crate::handler::pcr::pcr_belongs_policy_group(entity_handle);
        if policy.get_size() == 0 && !is_object && !is_policy_pcr {
            return Err(TpmRc::AUTH_UNAVAILABLE);
        }

        // TPM2_PolicySecret() requires proof of the authValue of authHandle.
        if cc == TpmCc::PolicySecret && !session.is_password_needed && !session.is_auth_value_needed
        {
            return Err(TpmRc::MODE.with(pos));
        }

        if let Some(pcr_counter) = session.pcr_counter
            && pcr_counter != self.state.pcrs.update_counter
        {
            return Err(TpmRc::PCR_CHANGED);
        }

        if policy.get_buffer() != &session.policy_digest[..session.policy_digest_len] {
            return Err(TpmRc::POLICY_FAIL.with(pos));
        }
        if policy_alg != Some(session.auth_hash) {
            return Err(TpmRc::POLICY_FAIL.with(pos));
        }

        if session.timeout != 0 {
            if !self.state.nv_available {
                return Err(TpmRc::NV_UNAVAILABLE);
            }
            if session.timeout < self.state.tpm_time_ms
                || session.epoch != self.state.nv.persistent.time_epoch
            {
                return Err(TpmRc::EXPIRED.with(pos));
            }
        }

        if session.command_code != 0 {
            if session.command_code != command_code {
                return Err(TpmRc::POLICY_CC.with(pos));
            }
        } else if matches!(
            command_auth_role(cc, handle_index),
            AuthRole::Admin | AuthRole::Dup
        ) {
            // ADMIN and DUP role authorizations require the policy to bind the command code.
            return Err(TpmRc::POLICY_FAIL.with(pos));
        }

        if session.command_locality != 0 {
            let curr_locality = self.state.locality;
            if session.command_locality > 31 {
                if curr_locality != session.command_locality {
                    return Err(TpmRc::LOCALITY);
                }
            } else if curr_locality > 4 || (session.command_locality & (1 << curr_locality)) == 0 {
                return Err(TpmRc::LOCALITY);
            }
        }

        // TPM 2.0 Part 3, TPM2_PolicyPhysicalPresence: "If this command is successful,
        // policySession→isPPRequired will be SET to indicate that this check is required when
        // the policy is used for authorization" (C `CheckPolicyAuthSession()`: `TPM_RC_PP`,
        // checked after the locality).
        if session.is_pp_required && !self.state.physical_presence {
            return Err(TpmRc::PP.with(pos));
        }

        if session.policy_hash_len > 0 {
            let expected = &session.policy_hash[..session.policy_hash_len];
            let ok = if session.is_cp_hash_defined {
                expected == cp_hash
            } else if session.is_parameters_hash_defined {
                // TPM 2.0 Part 3, TPM2_PolicyParameters: "The pHash is the hash of the
                // commandCode and all of the parameters of the command being authorized by the
                // policy session" (C `CompareParametersHash()`, over the parameters as received).
                let mut p_hash = [0u8; 64];
                let p_hash_len = compute_hash_parts(
                    &self.crypto(),
                    session.auth_hash,
                    &[&command_code.to_be_bytes(), parameters],
                    &mut p_hash,
                )?;
                expected == &p_hash[..p_hash_len]
            } else if session.is_name_hash_defined() {
                let mut name_hash_input = [0u8; 512];
                let mut name_hash_offset = 0;
                for name in handle_names {
                    let name_buf = name.get_buffer();
                    name_hash_input[name_hash_offset..name_hash_offset + name_buf.len()]
                        .copy_from_slice(name_buf);
                    name_hash_offset += name_buf.len();
                }
                let mut name_hash = [0u8; 64];
                let name_hash_len = compute_hash(
                    &self.crypto(),
                    session.auth_hash,
                    &name_hash_input[..name_hash_offset],
                    &mut name_hash,
                )?;
                expected == &name_hash[..name_hash_len]
            } else if session.is_template_hash_defined {
                self.compare_template_hash(session.auth_hash, cc, parameters, expected)?
            } else {
                false
            };
            if !ok {
                return Err(TpmRc::POLICY_FAIL.with(pos));
            }
        }

        if session.check_nv_written {
            // The policy only makes sense for an NV index.
            if Handle(entity_handle).handle_type() != Some(TpmHt::NVIndex) {
                return Err(TpmRc::POLICY_FAIL.with(pos));
            }
            let storage_mgr = &self.state.nv.index;
            let metadata = storage_mgr
                .get_metadata(entity_handle)
                .map_err(|_| TpmRc::POLICY_FAIL.with(pos))?;
            let read_len = core::cmp::min(metadata.data_size as usize, 1536);
            let mut read_buf = [0u8; 1536];
            storage_mgr
                .read_item(entity_handle, 0, &mut read_buf[..read_len])
                .map_err(|_| TpmRc::POLICY_FAIL.with(pos))?;
            let (_, nv_public, _, _) =
                crate::handler::nv_storage::unmarshal_nv_header(&read_buf[..read_len])
                    .map_err(|_| TpmRc::POLICY_FAIL.with(pos))?;
            if nv_public.attributes.contains(tpm2::TpmaNv::WRITTEN) != session.nv_written_state {
                return Err(TpmRc::POLICY_FAIL.with(pos));
            }
        }

        // `TPM2_PolicyTransportSPDM()`: the command must be protected by an SPDM session
        // (`TPM_RC_CHANNEL`) established with the required keys (`TPM_RC_CHANNEL_KEY`).
        #[cfg(feature = "sec-channel")]
        self.check_sec_channel_policy(&session.sec_channel, session.auth_hash, pos)?;

        Ok(())
    }

    /// Compares a policy session's templateHash with the hash of the `inPublic` template of a
    /// `TPM2_Create`, `TPM2_CreatePrimary` or `TPM2_CreateLoaded` command (C
    /// `CompareTemplateHash()`). Returns `false` for any other command or malformed parameters.
    fn compare_template_hash(
        &self,
        auth_hash: TpmiAlgHash,
        cc: TpmCc,
        parameters: &[u8],
        expected: &[u8],
    ) -> Result<bool, TpmRc> {
        if !matches!(
            cc,
            TpmCc::Create | TpmCc::CreatePrimary | TpmCc::CreateLoaded
        ) {
            return Ok(false);
        }
        // Skip the first TPM2B parameter (inSensitive), then read the template TPM2B.
        if parameters.len() < 2 {
            return Ok(false);
        }
        let in_sensitive_size = u16::from_be_bytes([parameters[0], parameters[1]]) as usize;
        let template_offset = 2 + in_sensitive_size;
        if parameters.len() < template_offset + 2 {
            return Ok(false);
        }
        let template_size =
            u16::from_be_bytes([parameters[template_offset], parameters[template_offset + 1]])
                as usize;
        let Some(template_bytes) =
            parameters.get(template_offset + 2..template_offset + 2 + template_size)
        else {
            return Ok(false);
        };
        let mut template_hash = [0u8; 64];
        let template_hash_len = compute_hash(
            &self.crypto(),
            auth_hash,
            template_bytes,
            &mut template_hash,
        )?;
        Ok(expected == &template_hash[..template_hash_len])
    }

    /// Process response parameters when authorization was validated inside the command handler.
    fn process_response_parameters_with_handler_validation(
        &mut self,
        cmd: &ParsedCommand,
        cc: TpmCc,
        command_code: u32,
        resp_buffer: &mut [u8],
        nonces_tpm_new: &[Option<OwnedNonce>],
    ) -> Result<usize, TpmRc> {
        // Formatting response with sessions (tag 0x8002)
        if resp_buffer.len() < 2 {
            return Err(TpmRc::MEMORY);
        }
        resp_buffer[0..2].copy_from_slice(&0x8002u16.to_be_bytes());

        let resp_handles_size = command_resp_handles_size(cc);

        let mut param_size_bytes = [0u8; 4];
        if resp_buffer.len() < 14 + resp_handles_size {
            return Err(TpmRc::MEMORY);
        }
        param_size_bytes
            .copy_from_slice(&resp_buffer[10 + resp_handles_size..14 + resp_handles_size]);
        let param_size = u32::from_be_bytes(param_size_bytes) as usize;

        if param_size > MAX_RESPONSE_SIZE {
            return Err(TpmRc::SIZE.to_rc());
        }
        let mut resp_params = [0u8; MAX_RESPONSE_SIZE];
        if param_size > 0 {
            if resp_buffer.len() < 14 + resp_handles_size + param_size {
                return Err(TpmRc::MEMORY);
            }
            resp_params[..param_size].copy_from_slice(
                &resp_buffer[14 + resp_handles_size..14 + resp_handles_size + param_size],
            );
        }

        // Response parameter encryption
        if param_size > 0 {
            let encrypt_session_idx = {
                let mut idx = None;
                for (i, auth) in cmd
                    .auth_sessions
                    .iter()
                    .enumerate()
                    .take(cmd.auth_sessions_len)
                {
                    let session_handle = auth.session_handle.0;
                    if (0x02000000..=0x03FFFFFF).contains(&session_handle)
                        && auth.session_attributes.0 & 0x40 != 0
                    {
                        idx = Some(i);
                        break;
                    }
                }
                idx
            };

            if let Some(i) = encrypt_session_idx {
                let first_auth = &cmd.auth_sessions[i];
                let session_handle = first_auth.session_handle.0;
                let mut session_key_buf = [0u8; 128];
                let session_key_len;
                let (
                    symmetric,
                    auth_hash,
                    _bound_entity,
                    _is_policy,
                    _is_auth_value_needed,
                    _is_password_needed,
                ) = {
                    let session_state = self
                        .state
                        .session(session_handle)
                        .ok_or(TpmRc::HANDLE.with(Position::session((i + 1) as u8)))?;
                    session_key_buf[..session_state.session_key_len].copy_from_slice(
                        &session_state.session_key[..session_state.session_key_len],
                    );
                    session_key_len = session_state.session_key_len;
                    (
                        session_state.symmetric,
                        session_state.auth_hash,
                        session_state.bound_entity,
                        session_state.session_type == TpmSe::Policy,
                        session_state.is_auth_value_needed,
                        session_state.is_password_needed,
                    )
                };

                let (is_xor, key_bits, sym_obj) = match symmetric {
                    Some(tpm2::TpmtSymDef::Cipher(sym_obj)) => {
                        if sym_obj.mode() != Some(CFB_MODE) {
                            return Err(TpmRc::MODE.with(Position::session(1)));
                        }
                        (false, sym_obj.key_bits(), Some(sym_obj))
                    }
                    Some(tpm2::TpmtSymDef::Xor(_)) => (true, 0, None),
                    None => {
                        return Err(TpmRc::SYMMETRIC.with(Position::session(1)));
                    }
                };

                let entity_auth = if i < cmd.session_to_handle_idx_len {
                    let h_idx = cmd.session_to_handle_idx[i];
                    if matches!(cc, TpmCc::SequenceComplete | TpmCc::EventSequenceComplete) {
                        cmd.handle_auths[h_idx]
                    } else {
                        self.handle_auth(cmd.handles[h_idx])
                    }
                } else {
                    OwnedAuth::default()
                };

                let entity_auth_stripped =
                    crate::util::strip_trailing_zeros(entity_auth.get_buffer());
                let mut kdfa_key = [0u8; 256];
                let kdfa_key_len = session_key_len + entity_auth_stripped.len();
                if kdfa_key_len > 256 {
                    return Err(TpmRc::FAILURE);
                }
                kdfa_key[..session_key_len].copy_from_slice(&session_key_buf[..session_key_len]);
                kdfa_key[session_key_len..kdfa_key_len].copy_from_slice(entity_auth_stripped);

                let nonce_tpm_new =
                    nonces_tpm_new[i].expect("nonce was generated for session handle");

                if param_size < 2 {
                    return Err(TpmRc::SIZE.to_rc());
                }
                let first_param_size =
                    u16::from_be_bytes([resp_params[0], resp_params[1]]) as usize;
                if param_size < 2 + first_param_size {
                    return Err(TpmRc::SIZE.to_rc());
                }

                if is_xor {
                    xor_obfuscation(
                        &self.crypto(),
                        auth_hash,
                        &kdfa_key[..kdfa_key_len],
                        nonce_tpm_new.get_buffer(),
                        first_auth.nonce.get_buffer(),
                        &mut resp_params[2..2 + first_param_size],
                    )?;
                } else {
                    let sym_obj =
                        sym_obj.ok_or_else(|| TpmRc::SYMMETRIC.with(Position::session(1)))?;
                    let mut derived_key = [0u8; 64];
                    let mut derived_iv = [0u8; 16];
                    derive_key_and_iv(
                        &self.crypto(),
                        auth_hash,
                        &kdfa_key[..kdfa_key_len],
                        b"CFB",
                        nonce_tpm_new.get_buffer(),
                        first_auth.nonce.get_buffer(),
                        (key_bits / 8) as usize,
                        &mut derived_key[..(key_bits / 8) as usize],
                        &mut derived_iv,
                    )?;

                    let mut iv = derived_iv;
                    crate::handler::sym_encrypt_decrypt(
                        &self.crypto(),
                        sym_obj,
                        &derived_key[..(key_bits / 8) as usize],
                        &mut iv,
                        Direction::Encrypt,
                        &mut resp_params[2..2 + first_param_size],
                    )
                    .map_err(|_| TpmRc::SYMMETRIC.with(Position::session(1)))?;
                }

                if resp_buffer.len() < 14 + resp_handles_size + param_size {
                    return Err(TpmRc::MEMORY);
                }
                resp_buffer[14 + resp_handles_size..14 + resp_handles_size + param_size]
                    .copy_from_slice(&resp_params[..param_size]);
            }
        }

        let rp_hash_input_len = 4 + 4 + param_size;
        if rp_hash_input_len > MAX_RESPONSE_SIZE + 8 {
            return Err(TpmRc::SIZE.to_rc());
        }
        let mut rp_hash_input = [0u8; MAX_RESPONSE_SIZE + 8];
        rp_hash_input[0..4].copy_from_slice(&0u32.to_be_bytes());
        rp_hash_input[4..8].copy_from_slice(&command_code.to_be_bytes());
        rp_hash_input[8..rp_hash_input_len].copy_from_slice(&resp_params[..param_size]);

        let mut session_responses_buf = [0u8; 1024];
        let mut session_responses_len = 0;
        for (i, auth) in cmd.auth_sessions[..cmd.auth_sessions_len]
            .iter()
            .enumerate()
        {
            let session_handle = auth.session_handle.0;
            if !(0x02000000..=0x03FFFFFF).contains(&session_handle) {
                let continue_bit = (auth.session_attributes.0 & 1) | 1;
                let session_resp = TpmsAuthResponse {
                    nonce: Tpm2bNonce::default(),
                    session_attributes: TpmaSession(continue_bit),
                    hmac: Tpm2bAuth::default(),
                };
                if session_responses_len + TpmsAuthResponse::MAX_SIZE > session_responses_buf.len()
                {
                    return Err(TpmRc::MEMORY);
                }
                session_responses_len += session_resp.marshal(
                    (&mut session_responses_buf[session_responses_len
                        ..session_responses_len + TpmsAuthResponse::MAX_SIZE])
                        .try_into()
                        .unwrap(),
                );
                continue;
            }

            let nonce_tpm_new = nonces_tpm_new[i].expect("nonce was generated for session handle");
            // The response attributes (also hashed into the response HMAC) are copied from the
            // command, including `decrypt`/`encrypt`; only `auditExclusive` is adjusted.
            let mut resp_attrs = auth.session_attributes.0;
            if auth.session_attributes.0 & 0x80 != 0 {
                if self.state.exclusive_audit_session == Some(session_handle) {
                    resp_attrs |= 0x02;
                } else {
                    resp_attrs &= !0x02;
                }
            }

            let mut session_key_buf = [0u8; 128];
            let session_key_len;
            let (auth_hash, include_auth, policy_password) = {
                let session_state = self
                    .state
                    .session(session_handle)
                    .ok_or(TpmRc::HANDLE.with(Position::session((i + 1) as u8)))?;
                session_key_buf[..session_state.session_key_len]
                    .copy_from_slice(&session_state.session_key[..session_state.session_key_len]);
                session_key_len = session_state.session_key_len;
                let is_policy = session_state.session_type == tpm2::TpmSe::Policy;
                let is_bound = session_state.bound_entity.get_size() > 0;
                let include_auth = (!is_policy && !is_bound)
                    || (is_policy
                        && (session_state.is_auth_value_needed
                            || session_state.is_password_needed))
                    || session_state.include_auth;
                (
                    session_state.auth_hash,
                    include_auth,
                    is_policy && session_state.is_password_needed,
                )
            };

            let mut rp_hash = [0u8; 64];
            let rp_hash_len = compute_hash(
                &self.crypto(),
                auth_hash,
                &rp_hash_input[..rp_hash_input_len],
                &mut rp_hash,
            )?;

            let entity_auth = if i < cmd.session_to_handle_idx_len {
                let h_idx = cmd.session_to_handle_idx[i];
                if matches!(cc, TpmCc::SequenceComplete | TpmCc::EventSequenceComplete) {
                    cmd.handle_auths[h_idx]
                } else {
                    self.handle_auth(cmd.handles[h_idx])
                }
            } else {
                OwnedAuth::default()
            };

            let mut hmac_key = [0u8; 256];
            let entity_auth_stripped = crate::util::strip_trailing_zeros(entity_auth.get_buffer());
            let hmac_key_len = if include_auth {
                session_key_len + entity_auth_stripped.len()
            } else {
                session_key_len
            };
            if hmac_key_len > 256 {
                return Err(TpmRc::FAILURE);
            }
            hmac_key[..session_key_len].copy_from_slice(&session_key_buf[..session_key_len]);
            if include_auth {
                hmac_key[session_key_len..hmac_key_len].copy_from_slice(entity_auth_stripped);
            }

            let mut updates_hmac_refs: [&[u8]; 4] = [&[]; 4];
            updates_hmac_refs[0] = &rp_hash[..rp_hash_len];
            updates_hmac_refs[1] = nonce_tpm_new.get_buffer();
            updates_hmac_refs[2] = auth.nonce.get_buffer();
            let attr_byte = [resp_attrs];
            updates_hmac_refs[3] = &attr_byte;

            let mut hmac_res = [0u8; 64];
            // A policy session with `isPasswordNeeded` returns an empty responseAuth
            // (C `BuildSingleResponseAuth()`).
            let hmac_res_len =
                if policy_password || (hmac_key_len == 0 && auth.hmac.get_size() == 0) {
                    0
                } else {
                    compute_response_hmac(
                        &self.crypto(),
                        auth_hash,
                        &hmac_key[..hmac_key_len],
                        &updates_hmac_refs,
                        &mut hmac_res,
                    )?
                };

            let session_resp = TpmsAuthResponse {
                nonce: nonce_tpm_new.as_tpm2b(),
                session_attributes: TpmaSession(resp_attrs),
                hmac: Tpm2bAuth::from_bytes(&hmac_res[..hmac_res_len])
                    .map_err(|_| TpmRc::MEMORY)?,
            };

            if session_responses_len + TpmsAuthResponse::MAX_SIZE > session_responses_buf.len() {
                return Err(TpmRc::MEMORY);
            }
            session_responses_len += session_resp.marshal(
                (&mut session_responses_buf
                    [session_responses_len..session_responses_len + TpmsAuthResponse::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );

            let continue_session = (resp_attrs & 1) != 0;
            let (now_ms, time_epoch) =
                (self.state.tpm_time_ms, self.state.nv.persistent.time_epoch);
            // Only a session with the `audit` attribute in this command extends its audit digest
            // (C `UpdateAuditSessionStatus()`/`Audit()`: `s_auditSessionIndex`), with the cpHash
            // of this command.
            let audit_cp_hash = if auth.session_attributes.0 & 0x80 != 0 {
                self.state.session_audit_cp_hashes[i].take()
            } else {
                None
            };
            if let Some(session_state) = self.state.session_mut(session_handle) {
                if let Some(audit_cp_hash) = audit_cp_hash {
                    let mut extend_buf = [0u8; 192];
                    let d_len = session_state.audit_digest_len;
                    if let Some(ref d) = session_state.audit_digest {
                        extend_buf[..d_len].copy_from_slice(&d[..d_len]);
                    } else {
                        extend_buf[..d_len].fill(0);
                    }
                    let cp_len = audit_cp_hash.get_buffer().len();
                    extend_buf[d_len..d_len + cp_len].copy_from_slice(audit_cp_hash.get_buffer());
                    extend_buf[d_len + cp_len..d_len + cp_len + rp_hash_len]
                        .copy_from_slice(&rp_hash[..rp_hash_len]);

                    let mut new_digest = [0u8; 64];
                    let new_digest_len = compute_hash(
                        &crate::self_test::Tested::<P::Crypto>::new(&self.self_test),
                        auth_hash,
                        &extend_buf[..d_len + cp_len + rp_hash_len],
                        &mut new_digest,
                    )?;
                    let mut d_array = [0u8; 64];
                    d_array[..new_digest_len].copy_from_slice(&new_digest[..new_digest_len]);
                    session_state.audit_digest = Some(d_array);
                    session_state.audit_digest_len = new_digest_len;
                }
                session_state.nonce_tpm = nonce_tpm_new;
                if auth.session_attributes.0 & 0x80 != 0 {
                    session_state.bound_entity = OwnedName::default();
                }
                // The nonce rolls, so a continued policy session is reset and starts a new
                // timing interval (C `UpdateInternalSession()`: `SessionResetPolicyData()` +
                // `SessionSetStartTime()`). This applies to every policy session in the session
                // area, including ones only used for parameter encryption/decryption.
                if session_state.session_type == tpm2::TpmSe::Policy && continue_session {
                    session_state.start_time = now_ms;
                    session_state.epoch = time_epoch;
                    session_state.timeout = 0;
                    session_state.include_auth = false;
                    session_state.policy_digest[..session_state.policy_digest_len].fill(0);
                    session_state.command_code = 0;
                    session_state.command_locality = 0;
                    session_state.pcr_counter = None;
                    session_state.is_cp_hash_defined = false;
                    session_state.policy_hash[..].fill(0);
                    session_state.policy_hash_len = 0;
                    session_state.is_template_hash_defined = false;
                    session_state.is_parameters_hash_defined = false;
                    session_state.is_pp_required = false;
                    session_state.is_auth_value_needed = false;
                    session_state.is_password_needed = false;
                    session_state.check_nv_written = false;
                    session_state.nv_written_state = false;
                    session_state.sec_channel = Default::default();
                }
            }

            if !continue_session {
                self.state.remove_session(session_handle);
            }
        }

        if session_responses_len > 0 {
            if resp_buffer.len() < 14 + resp_handles_size + param_size + session_responses_len {
                return Err(TpmRc::MEMORY);
            }
            resp_buffer[14 + resp_handles_size + param_size
                ..14 + resp_handles_size + param_size + session_responses_len]
                .copy_from_slice(&session_responses_buf[..session_responses_len]);
        }

        let new_len = 14 + resp_handles_size + param_size + session_responses_len;
        if resp_buffer.len() < 6 {
            return Err(TpmRc::MEMORY);
        }
        resp_buffer[2..6].copy_from_slice(&(new_len as u32).to_be_bytes());

        Ok(new_len)
    }

    /// Process response parameters when authorization was NOT validated inside the command handler.
    #[allow(clippy::too_many_arguments)]
    fn process_response_parameters_without_handler_validation(
        &mut self,
        cmd: &ParsedCommand,
        cc: TpmCc,
        command_code: u32,
        shadow_len: usize,
        resp_buffer: &mut [u8],
        nonces_tpm_new: &[Option<OwnedNonce>],
    ) -> Result<usize, TpmRc> {
        let resp_handles_size = command_resp_handles_size(cc);
        if resp_handles_size > 12 {
            return Err(TpmRc::SIZE.to_rc());
        }
        let mut resp_handles = [0u8; 12];
        if resp_handles_size > 0 {
            if resp_buffer.len() < 10 + resp_handles_size {
                return Err(TpmRc::MEMORY);
            }
            resp_handles[..resp_handles_size]
                .copy_from_slice(&resp_buffer[10..10 + resp_handles_size]);
        }

        let resp_params_size = shadow_len - 10 - resp_handles_size;
        if resp_params_size > MAX_RESPONSE_SIZE {
            return Err(TpmRc::SIZE.to_rc());
        }
        let mut resp_params = [0u8; MAX_RESPONSE_SIZE];
        if resp_params_size > 0 {
            if resp_buffer.len() < 10 + resp_handles_size + resp_params_size {
                return Err(TpmRc::MEMORY);
            }
            resp_params[..resp_params_size].copy_from_slice(
                &resp_buffer[10 + resp_handles_size..10 + resp_handles_size + resp_params_size],
            );
        }

        let encrypt_session_idx = {
            let mut idx = None;
            for (i, auth) in cmd
                .auth_sessions
                .iter()
                .enumerate()
                .take(cmd.auth_sessions_len)
            {
                let session_handle = auth.session_handle.0;
                if (0x02000000..=0x03FFFFFF).contains(&session_handle)
                    && auth.session_attributes.0 & 0x40 != 0
                {
                    idx = Some(i);
                    break;
                }
            }
            idx
        };

        if let Some(i) = encrypt_session_idx {
            let first_auth = &cmd.auth_sessions[i];
            let session_handle = first_auth.session_handle.0;
            let mut session_key_buf = [0u8; 128];
            let session_key_len;
            let (
                symmetric,
                auth_hash,
                _bound_entity,
                _is_policy,
                _is_auth_value_needed,
                _is_password_needed,
            ) = {
                let session_state = self
                    .state
                    .session(session_handle)
                    .ok_or(TpmRc::HANDLE.with(Position::session((i + 1) as u8)))?;
                session_key_buf[..session_state.session_key_len]
                    .copy_from_slice(&session_state.session_key[..session_state.session_key_len]);
                session_key_len = session_state.session_key_len;
                (
                    session_state.symmetric,
                    session_state.auth_hash,
                    session_state.bound_entity,
                    session_state.session_type == TpmSe::Policy,
                    session_state.is_auth_value_needed,
                    session_state.is_password_needed,
                )
            };

            let (is_xor, key_bits, sym_obj) = match symmetric {
                Some(tpm2::TpmtSymDef::Cipher(sym_obj)) => {
                    if sym_obj.mode() != Some(CFB_MODE) {
                        return Err(TpmRc::MODE.with(Position::session(1)));
                    }
                    (false, sym_obj.key_bits(), Some(sym_obj))
                }
                Some(tpm2::TpmtSymDef::Xor(_)) => (true, 0, None),
                None => {
                    return Err(TpmRc::SYMMETRIC.with(Position::session(1)));
                }
            };

            let entity_auth = if i < cmd.session_to_handle_idx_len {
                let h_idx = cmd.session_to_handle_idx[i];
                if matches!(cc, TpmCc::SequenceComplete | TpmCc::EventSequenceComplete) {
                    cmd.handle_auths[h_idx]
                } else {
                    self.handle_auth(cmd.handles[h_idx])
                }
            } else {
                OwnedAuth::default()
            };

            let entity_auth_stripped = crate::util::strip_trailing_zeros(entity_auth.get_buffer());
            let mut kdfa_key = [0u8; 256];
            let kdfa_key_len = session_key_len + entity_auth_stripped.len();
            if kdfa_key_len > 256 {
                return Err(TpmRc::FAILURE);
            }
            kdfa_key[..session_key_len].copy_from_slice(&session_key_buf[..session_key_len]);
            kdfa_key[session_key_len..kdfa_key_len].copy_from_slice(entity_auth_stripped);

            let nonce_tpm_new = nonces_tpm_new[i].expect("nonce was generated for session handle");

            if resp_params_size < 2 {
                return Err(TpmRc::SIZE.to_rc());
            }
            let first_param_size = u16::from_be_bytes([resp_params[0], resp_params[1]]) as usize;
            if resp_params_size < 2 + first_param_size {
                return Err(TpmRc::SIZE.to_rc());
            }

            if is_xor {
                xor_obfuscation(
                    &self.crypto(),
                    auth_hash,
                    &kdfa_key[..kdfa_key_len],
                    nonce_tpm_new.get_buffer(),
                    first_auth.nonce.get_buffer(),
                    &mut resp_params[2..2 + first_param_size],
                )?;
            } else {
                let sym_obj = sym_obj.ok_or_else(|| TpmRc::SYMMETRIC.with(Position::session(1)))?;
                let mut derived_key = [0u8; 64];
                let mut derived_iv = [0u8; 16];
                derive_key_and_iv(
                    &self.crypto(),
                    auth_hash,
                    &kdfa_key[..kdfa_key_len],
                    b"CFB",
                    nonce_tpm_new.get_buffer(),
                    first_auth.nonce.get_buffer(),
                    (key_bits / 8) as usize,
                    &mut derived_key[..(key_bits / 8) as usize],
                    &mut derived_iv,
                )?;

                let mut iv = derived_iv;
                crate::handler::sym_encrypt_decrypt(
                    &self.crypto(),
                    sym_obj,
                    &derived_key[..(key_bits / 8) as usize],
                    &mut iv,
                    Direction::Encrypt,
                    &mut resp_params[2..2 + first_param_size],
                )
                .map_err(|_| TpmRc::SYMMETRIC.with(Position::session(1)))?;
            }
        }

        let rp_hash_input_len = 4 + 4 + resp_params_size;
        if rp_hash_input_len > MAX_RESPONSE_SIZE + 8 {
            return Err(TpmRc::SIZE.to_rc());
        }
        let mut rp_hash_input = [0u8; MAX_RESPONSE_SIZE + 8];
        rp_hash_input[0..4].copy_from_slice(&0u32.to_be_bytes());
        rp_hash_input[4..8].copy_from_slice(&command_code.to_be_bytes());
        rp_hash_input[8..rp_hash_input_len].copy_from_slice(&resp_params[..resp_params_size]);

        let mut session_responses_buf = [0u8; 1024];
        let mut session_responses_len = 0;
        for (i, auth) in cmd.auth_sessions[..cmd.auth_sessions_len]
            .iter()
            .enumerate()
        {
            let session_handle = auth.session_handle.0;
            if !(0x02000000..=0x03FFFFFF).contains(&session_handle) {
                let continue_bit = (auth.session_attributes.0 & 1) | 1;
                let session_resp = TpmsAuthResponse {
                    nonce: Tpm2bNonce::default(),
                    session_attributes: TpmaSession(continue_bit),
                    hmac: Tpm2bAuth::default(),
                };
                if session_responses_len + TpmsAuthResponse::MAX_SIZE > session_responses_buf.len()
                {
                    return Err(TpmRc::MEMORY);
                }
                session_responses_len += session_resp.marshal(
                    (&mut session_responses_buf[session_responses_len
                        ..session_responses_len + TpmsAuthResponse::MAX_SIZE])
                        .try_into()
                        .unwrap(),
                );
                continue;
            }

            let nonce_tpm_new = nonces_tpm_new[i].expect("nonce was generated for session handle");
            // The response attributes (also hashed into the response HMAC) are copied from the
            // command, including `decrypt`/`encrypt`; only `auditExclusive` is adjusted.
            let mut resp_attrs = auth.session_attributes.0;
            if auth.session_attributes.0 & 0x80 != 0 {
                if self.state.exclusive_audit_session == Some(session_handle) {
                    resp_attrs |= 0x02;
                } else {
                    resp_attrs &= !0x02;
                }
            }

            let mut session_key_buf = [0u8; 128];
            let session_key_len;
            let (auth_hash, include_auth, policy_password) = {
                let session_state = self
                    .state
                    .session(session_handle)
                    .ok_or(TpmRc::HANDLE.with(Position::session((i + 1) as u8)))?;
                session_key_buf[..session_state.session_key_len]
                    .copy_from_slice(&session_state.session_key[..session_state.session_key_len]);
                session_key_len = session_state.session_key_len;
                let is_policy = session_state.session_type == tpm2::TpmSe::Policy;
                let is_bound = session_state.bound_entity.get_size() > 0;
                let include_auth = (!is_policy && !is_bound)
                    || (is_policy
                        && (session_state.is_auth_value_needed
                            || session_state.is_password_needed))
                    || session_state.include_auth;
                (
                    session_state.auth_hash,
                    include_auth,
                    is_policy && session_state.is_password_needed,
                )
            };

            let mut rp_hash = [0u8; 64];
            let rp_hash_len = compute_hash(
                &self.crypto(),
                auth_hash,
                &rp_hash_input[..rp_hash_input_len],
                &mut rp_hash,
            )?;

            let entity_auth = if i < cmd.session_to_handle_idx_len {
                let h_idx = cmd.session_to_handle_idx[i];
                if matches!(cc, TpmCc::SequenceComplete | TpmCc::EventSequenceComplete) {
                    cmd.handle_auths[h_idx]
                } else {
                    self.handle_auth(cmd.handles[h_idx])
                }
            } else {
                OwnedAuth::default()
            };

            let mut hmac_key = [0u8; 256];
            let entity_auth_stripped = crate::util::strip_trailing_zeros(entity_auth.get_buffer());
            let hmac_key_len = if include_auth {
                session_key_len + entity_auth_stripped.len()
            } else {
                session_key_len
            };
            if hmac_key_len > 256 {
                return Err(TpmRc::FAILURE);
            }
            hmac_key[..session_key_len].copy_from_slice(&session_key_buf[..session_key_len]);
            if include_auth {
                hmac_key[session_key_len..hmac_key_len].copy_from_slice(entity_auth_stripped);
            }

            let mut updates_hmac_refs: [&[u8]; 4] = [&[]; 4];
            updates_hmac_refs[0] = &rp_hash[..rp_hash_len];
            updates_hmac_refs[1] = nonce_tpm_new.get_buffer();
            updates_hmac_refs[2] = auth.nonce.get_buffer();
            let attr_byte = [resp_attrs];
            updates_hmac_refs[3] = &attr_byte;

            let mut hmac_res = [0u8; 64];
            // A policy session with `isPasswordNeeded` returns an empty responseAuth
            // (C `BuildSingleResponseAuth()`).
            let hmac_res_len =
                if policy_password || (hmac_key_len == 0 && auth.hmac.get_size() == 0) {
                    0
                } else {
                    compute_response_hmac(
                        &self.crypto(),
                        auth_hash,
                        &hmac_key[..hmac_key_len],
                        &updates_hmac_refs,
                        &mut hmac_res,
                    )?
                };

            let session_resp = TpmsAuthResponse {
                nonce: nonce_tpm_new.as_tpm2b(),
                session_attributes: TpmaSession(resp_attrs),
                hmac: Tpm2bAuth::from_bytes(&hmac_res[..hmac_res_len])
                    .map_err(|_| TpmRc::MEMORY)?,
            };

            if session_responses_len + TpmsAuthResponse::MAX_SIZE > session_responses_buf.len() {
                return Err(TpmRc::MEMORY);
            }
            session_responses_len += session_resp.marshal(
                (&mut session_responses_buf
                    [session_responses_len..session_responses_len + TpmsAuthResponse::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );

            let continue_session = (resp_attrs & 1) != 0;
            let (now_ms, time_epoch) =
                (self.state.tpm_time_ms, self.state.nv.persistent.time_epoch);
            // Only a session with the `audit` attribute in this command extends its audit digest
            // (C `UpdateAuditSessionStatus()`/`Audit()`: `s_auditSessionIndex`), with the cpHash
            // of this command.
            let audit_cp_hash = if auth.session_attributes.0 & 0x80 != 0 {
                self.state.session_audit_cp_hashes[i].take()
            } else {
                None
            };
            if let Some(session_state) = self.state.session_mut(session_handle) {
                if let Some(audit_cp_hash) = audit_cp_hash {
                    let mut extend_buf = [0u8; 192];
                    let d_len = session_state.audit_digest_len;
                    if let Some(ref d) = session_state.audit_digest {
                        extend_buf[..d_len].copy_from_slice(&d[..d_len]);
                    } else {
                        extend_buf[..d_len].fill(0);
                    }
                    let cp_len = audit_cp_hash.get_buffer().len();
                    extend_buf[d_len..d_len + cp_len].copy_from_slice(audit_cp_hash.get_buffer());
                    extend_buf[d_len + cp_len..d_len + cp_len + rp_hash_len]
                        .copy_from_slice(&rp_hash[..rp_hash_len]);

                    let mut new_digest = [0u8; 64];
                    let new_digest_len = compute_hash(
                        &crate::self_test::Tested::<P::Crypto>::new(&self.self_test),
                        auth_hash,
                        &extend_buf[..d_len + cp_len + rp_hash_len],
                        &mut new_digest,
                    )?;
                    let mut d_array = [0u8; 64];
                    d_array[..new_digest_len].copy_from_slice(&new_digest[..new_digest_len]);
                    session_state.audit_digest = Some(d_array);
                    session_state.audit_digest_len = new_digest_len;
                }
                session_state.nonce_tpm = nonce_tpm_new;
                if auth.session_attributes.0 & 0x80 != 0 {
                    session_state.bound_entity = OwnedName::default();
                }
                // The nonce rolls, so a continued policy session is reset and starts a new
                // timing interval (C `UpdateInternalSession()`: `SessionResetPolicyData()` +
                // `SessionSetStartTime()`). This applies to every policy session in the session
                // area, including ones only used for parameter encryption/decryption.
                if session_state.session_type == tpm2::TpmSe::Policy && continue_session {
                    session_state.start_time = now_ms;
                    session_state.epoch = time_epoch;
                    session_state.timeout = 0;
                    session_state.include_auth = false;
                    session_state.policy_digest[..session_state.policy_digest_len].fill(0);
                    session_state.command_code = 0;
                    session_state.command_locality = 0;
                    session_state.pcr_counter = None;
                    session_state.is_cp_hash_defined = false;
                    session_state.policy_hash[..].fill(0);
                    session_state.policy_hash_len = 0;
                    session_state.is_template_hash_defined = false;
                    session_state.is_parameters_hash_defined = false;
                    session_state.is_pp_required = false;
                    session_state.is_auth_value_needed = false;
                    session_state.is_password_needed = false;
                    session_state.check_nv_written = false;
                    session_state.nv_written_state = false;
                    session_state.sec_channel = Default::default();
                }
            }

            if !continue_session {
                self.state.remove_session(session_handle);
            }
        }

        if resp_buffer.len() < 10 {
            return Err(TpmRc::MEMORY);
        }
        resp_buffer[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
        resp_buffer[6..10].copy_from_slice(&0u32.to_be_bytes());

        let mut offset = 10;
        if resp_handles_size > 0 {
            if resp_buffer.len() < offset + resp_handles_size {
                return Err(TpmRc::MEMORY);
            }
            resp_buffer[offset..offset + resp_handles_size]
                .copy_from_slice(&resp_handles[..resp_handles_size]);
            offset += resp_handles_size;
        }

        if resp_buffer.len() < offset + 4 {
            return Err(TpmRc::MEMORY);
        }
        resp_buffer[offset..offset + 4].copy_from_slice(&(resp_params_size as u32).to_be_bytes());
        offset += 4;

        if resp_params_size > 0 {
            if resp_buffer.len() < offset + resp_params_size {
                return Err(TpmRc::MEMORY);
            }
            resp_buffer[offset..offset + resp_params_size]
                .copy_from_slice(&resp_params[..resp_params_size]);
            offset += resp_params_size;
        }

        if session_responses_len > 0 {
            if resp_buffer.len() < offset + session_responses_len {
                return Err(TpmRc::MEMORY);
            }
            resp_buffer[offset..offset + session_responses_len]
                .copy_from_slice(&session_responses_buf[..session_responses_len]);
            offset += session_responses_len;
        }

        if resp_buffer.len() < 6 {
            return Err(TpmRc::MEMORY);
        }
        resp_buffer[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

        Ok(offset)
    }

    /// Validates the handle area of command `cc` as the C reference does before any session is
    /// processed, in two passes over all handles:
    ///
    /// 1. `ParseHandleBuffer`: every handle is unmarshaled as its interface type (`TPMI_DH_*`,
    ///    `TPMI_RH_*`, `TPMI_SH_*`), so a value the type does not admit is `TPM_RC_VALUE` at its
    ///    position — for every handle before any is checked for presence;
    /// 2. `EntityGetLoadStatus`: every handle must reference an available entity (loaded
    ///    object or session, defined and accessible NV Index or persistent object, enabled
    ///    hierarchy): `TPM_RC_REFERENCE_H*`, `TPM_RC_HANDLE`, `TPM_RC_HIERARCHY`,
    ///    `TPM_RC_OBJECT_MEMORY`.
    ///
    /// So an invalid second handle is reported before a missing first one.
    ///
    /// TPM 2.0 Part 3, "Handle Area Validation": "1. The TPM shall successfully unmarshal the
    /// number of handles required by the command and validate that the value of the handle is
    /// consistent with the command syntax. If not, the TPM shall return `TPM_RC_VALUE`. The TPM
    /// is permitted to unmarshal a handle and validate that it references an entity on the TPM
    /// before unmarshaling a subsequent handle." and "2. For all handles in the handle area of
    /// the command, the TPM will validate that the referenced entity is present in the TPM." The
    /// specification permits both orders ("These checks may be performed in any order."); this
    /// follows the TCG reference, which unmarshals all handles first (`ParseHandleBuffer`).
    fn validate_command_handles(
        &mut self,
        cc: TpmCc,
        handles: &[u32],
        handles_len: usize,
        _parameters: &[u8],
    ) -> Result<(), TpmRc> {
        // Pass 1: the interface types, in handle order.
        for (h_idx, &handle) in handles.iter().enumerate().take(handles_len) {
            let types = crate::handle_checks::command_handle_types(cc);
            if let Some(&ty) = types.get(h_idx) {
                crate::handle_checks::check(
                    Handle(handle),
                    ty,
                    Position::handle((h_idx + 1) as u8),
                )?;
            }
        }
        // Pass 2: the load status (with the engine's remaining, implementation-specific value
        // checks, e.g. unimplemented hierarchies).
        self.check_command_handles(cc, handles, handles_len)?;
        // The Read-Only mode checks that depend on the referenced entities, which must precede
        // any authorization check (see `crate::read_only`).
        self.check_read_only_entities(cc, handles, handles_len)
    }

    /// Fails with `TPM_RC_READ_ONLY` if the TPM is in Read-Only mode and command `cc` is not
    /// permitted on the entities its (validated) handles reference: Part 3, TPM2_ReadOnlyControl,
    /// "Commands Permitted in Read-Only Mode": `TPM2_NV_Write`, `TPM2_NV_Extend`,
    /// `TPM2_NV_SetBits`, `TPM2_NV_WriteLock` and `TPM2_NV_ReadLock` are "Permitted only when
    /// the NV index is defined with `TPMA_NV_ORDERLY` and `TPMA_NV_CLEAR_STCLEAR`", and
    /// `TPM2_PolicySecret` is "Not permitted when used with a PIN Pass/Fail NV index". Part 1
    /// requires the rejection "before performing authorization checks which would be evaluated
    /// during the execution of the command", so this runs right after the handle validation.
    fn check_read_only_entities(
        &mut self,
        cc: TpmCc,
        handles: &[u32],
        handles_len: usize,
    ) -> Result<(), TpmRc> {
        if !cfg!(feature = "cc-read-only-control") || !self.state.nv.clear.read_only {
            return Ok(());
        }
        if let Some(h_idx) = crate::read_only::nv_restricted_index_handle(cc)
            && h_idx < handles_len
        {
            let permitted =
                self.read_nv_index_public(handles[h_idx])
                    .is_some_and(|(_, nv_public)| {
                        crate::read_only::nv_command_permitted(nv_public.attributes)
                    });
            if !permitted {
                return Err(TpmRc::READ_ONLY);
            }
        }
        if cc == TpmCc::PolicySecret
            && handles_len >= 1
            && Handle(handles[0]).handle_type() == Some(TpmHt::NVIndex)
            && self
                .read_nv_index_public(handles[0])
                .is_some_and(|(_, nv_public)| {
                    matches!(
                        nv_public.attributes.get_index_type(),
                        Ok(tpm2::TpmNt::PinPass | tpm2::TpmNt::PinFail)
                    )
                })
        {
            return Err(TpmRc::READ_ONLY);
        }
        Ok(())
    }

    /// Pass 2 of [`Self::validate_command_handles`]: the load status of the entities the
    /// handles reference (and the engine's remaining handle value checks).
    fn check_command_handles(
        &mut self,
        cc: TpmCc,
        handles: &[u32],
        handles_len: usize,
    ) -> Result<(), TpmRc> {
        if handles_len >= 1 {
            let auth_handle = handles[0];

            // `TPM2_HierarchyControl.authHandle` is a `TPMI_RH_HIERARCHY`. Its parameters
            // (`enable`, `state`) and the `TPM_RC_AUTH_TYPE` checks are evaluated by the handler,
            // i.e. after authorization, as in the C reference.
            if cc == TpmCc::HierarchyControl
                && auth_handle != Handle::RH_OWNER.0
                && auth_handle != Handle::RH_PLATFORM.0
                && auth_handle != Handle::RH_ENDORSEMENT.0
            {
                return Err(TpmRc::VALUE.with(Position::handle(1)));
            }

            if cc == TpmCc::HierarchyChangeAuth
                && auth_handle != Handle::RH_OWNER.0
                && auth_handle != Handle::RH_ENDORSEMENT.0
                && auth_handle != Handle::RH_PLATFORM.0
                && auth_handle != Handle::RH_LOCKOUT.0
            {
                return Err(TpmRc::VALUE.with(Position::handle(1)));
            }

            // The NV handle types (`TPMI_RH_NV_INDEX`, `TPMI_RH_NV_AUTH`, ...) are checked in pass
            // 1 (`handle_checks`); the accessibility of NV Index handles (C
            // `NvIndexIsAccessible`) in handle order by the loop below.
        }
        // Persistent objects already copied into a (temporary) object slot by this command
        // (`ObjectLoadEvict`) are counted in `state.command_persistent_objects`.
        self.state.command_persistent_objects = 0;
        for (h_idx, &handle) in handles.iter().enumerate().take(handles_len) {
            let pos = Position::handle((h_idx + 1) as u8);
            // C `EntityGetLoadStatus`: every NV Index handle must be accessible
            // (`NvIndexIsAccessible`), whatever command it is passed to. Positions whose
            // interface type cannot hold an NV Index (objects, contexts, sessions, permanent
            // handles) reject it at handle unmarshaling instead (`TPM_RC_VALUE`, below).
            // A firmware-limited or SVN-limited hierarchy (a `TPMI_RH_HIERARCHY` and
            // `TPMI_DH_PARENT` value) is present only if it is available: its base hierarchy is
            // enabled and the firmware provides its additional secret (`EntityGetLoadStatus` →
            // `ValidateHierarchy`, [`TpmEngine::validate_hierarchy`]).
            if crate::hierarchy::is_limited(handle) {
                self.validate_hierarchy(handle).map_err(|rc| rc.with(pos))?;
            }
            // External and permanent NV Indexes (valid `TPMI_RH_NV_INDEX` values) are not
            // implemented. The specification is silent on their load status; this follows the TCG
            // reference's `EntityGetLoadStatus` ("case TPM_HT_EXTERNAL_NV: case
            // TPM_HT_PERMANENT_NV: // Not yet supported. result = TPM_RC_VALUE;"), in handle
            // order.
            if matches!(handle >> 24, 0x11 | 0x12) {
                return Err(TpmRc::VALUE.with(pos));
            }
            if Handle(handle).handle_type() == Some(TpmHt::NVIndex)
                && !expects_object_handle(cc, h_idx)
                && !is_expected_session_handle(cc, h_idx)
                && !expects_permanent_handle(cc, h_idx)
                && !matches!(
                    (cc, h_idx),
                    (TpmCc::CreateLoaded, 0) | (TpmCc::StartAuthSession, 0)
                )
            {
                self.check_nv_index_accessible(handle, pos)?;
            }
            if expects_object_handle(cc, h_idx) {
                if handle == Handle::RH_NULL.0 {
                    // `TPMI_DH_OBJECT+` handles accept `TPM_RH_NULL`.
                    let allows_null = matches!(
                        (cc, h_idx),
                        (TpmCc::CertifyCreation, 0)
                            | (TpmCc::Duplicate, 1)
                            | (TpmCc::Certify, 1)
                            | (TpmCc::GetSessionAuditDigest, 1)
                            | (TpmCc::GetCommandAuditDigest, 1)
                            | (TpmCc::Quote, 0)
                            | (TpmCc::NVCertify, 0)
                            | (TpmCc::Rewrap, 0)
                            | (TpmCc::Rewrap, 1)
                            | (TpmCc::GetTime, 1)
                    );
                    if !allows_null {
                        return Err(TpmRc::VALUE.with(pos));
                    }
                } else if handle >> 24 == 0x80 {
                    if (handle & 0x00FF_FFFF) > (Handle::TRANSIENT_LAST.0 & 0x00FF_FFFF) {
                        return Err(TpmRc::VALUE.with(pos));
                    }
                    if let Some(obj) = self.state.find_transient_object(handle) {
                        // An object of a firmware-limited or SVN-limited hierarchy belongs to its
                        // base hierarchy.
                        let base = crate::hierarchy::normalize(obj.hierarchy);
                        if (base == 0x40000001 && !self.state.nv.clear.sh_enable)
                            || (base == 0x4000000B && !self.state.nv.clear.eh_enable)
                            || (base == 0x4000000C && !self.state.ph_enable)
                        {
                            return Err(TpmRc::HIERARCHY.with(pos));
                        }
                    } else if self.state.find_active_sequence(handle).is_none() {
                        return Err(match h_idx {
                            0 => TpmRc::REFERENCE_H0,
                            1 => TpmRc::REFERENCE_H1,
                            _ => TpmRc::REFERENCE_H2,
                        });
                    }
                } else if handle >> 24 == 0x81 {
                    self.load_evict_status(cc, handle, pos)?;
                } else {
                    // `TPMI_DH_OBJECT` accepts only transient and persistent handles
                    // (`TPMI_DH_OBJECT_Unmarshal`); permanent handles are invalid values,
                    // including for the parent handles of Create, Load and ObjectChangeAuth.
                    return Err(TpmRc::VALUE.with(pos));
                }
            } else if cc == TpmCc::CreateLoaded && h_idx == 0 {
                let mso = handle >> 24;
                if mso == 0x80 {
                    if handle > Handle::TRANSIENT_LAST.0 {
                        return Err(TpmRc::VALUE.with(pos));
                    }
                    // Sequence objects are loaded objects; the handler rejects them as
                    // non-parents (`TPM_RC_TYPE + RC_H1`).
                    if self.state.find_transient_object(handle).is_none()
                        && self.state.find_active_sequence(handle).is_none()
                    {
                        return Err(TpmRc::REFERENCE_H0);
                    }
                } else if mso == 0x81 {
                    self.load_evict_status(cc, handle, pos)?;
                } else if mso != 0x40 {
                    return Err(TpmRc::VALUE.with(pos));
                }
            } else if expects_context_handle(cc, h_idx) {
                // `TPMI_DH_CONTEXT` admits only HMAC/policy session and transient handles; every
                // other handle (persistent, permanent, ...) is `TPM_RC_VALUE` at its position.
                let mso = handle >> 24;
                if mso == 0x80 {
                    if (handle & 0x00FF_FFFF) > (Handle::TRANSIENT_LAST.0 & 0x00FF_FFFF) {
                        return Err(TpmRc::VALUE.with(pos));
                    }
                    if self.state.find_transient_object(handle).is_none()
                        && self.state.find_active_sequence(handle).is_none()
                    {
                        return Err(reference_h(h_idx));
                    }
                } else if mso == 0x02 || mso == 0x03 {
                    check_session_handle_status(&self.state, handle, h_idx, mso == 0x03)?;
                } else {
                    return Err(TpmRc::VALUE.with(pos));
                }
            } else if cc == TpmCc::GetSessionAuditDigest && h_idx == 2 {
                // `sessionHandle` is a `TPMI_SH_HMAC`.
                if handle >> 24 != 0x02 {
                    return Err(TpmRc::VALUE.with(pos));
                }
                check_session_handle_status(&self.state, handle, h_idx, false)?;
            } else if expects_policy_session_handle(cc, h_idx) {
                // `TPMI_SH_POLICY`: any other handle type is `TPM_RC_VALUE` at its position.
                if handle >> 24 != 0x03 {
                    return Err(TpmRc::VALUE.with(pos));
                }
                check_session_handle_status(&self.state, handle, h_idx, true)?;
            } else if matches!(
                (cc, h_idx),
                (TpmCc::PCRExtend, 0)
                    | (TpmCc::PCREvent, 0)
                    | (TpmCc::PCRReset, 0)
                    | (TpmCc::PCRSetAuthValue, 0)
            ) {
                // `TPMI_DH_PCR` (`+` for Extend/Event): only implemented PCRs, or `TPM_RH_NULL`.
                let allows_null = matches!(cc, TpmCc::PCRExtend | TpmCc::PCREvent);
                const PCR_LAST: u32 = 23;
                if handle > PCR_LAST && !(allows_null && handle == Handle::RH_NULL.0) {
                    return Err(TpmRc::VALUE.with(pos));
                }
            } else if cc == TpmCc::StartAuthSession && h_idx == 0 {
                if handle != Handle::RH_NULL.0 {
                    if handle >> 24 == 0x80 {
                        if handle > Handle::TRANSIENT_LAST.0 {
                            return Err(TpmRc::VALUE.with(pos));
                        }
                        // A loaded sequence object is present too (it then fails in the handler
                        // with TPM_RC_KEY). TPM 2.0 Part 3, "Handle Area Validation": "If the
                        // handle references a transient object, the handle shall reference a
                        // loaded object (`TPM_RC_REFERENCE_H0` + N ...)"; Part 1, "transient
                        // object": "object or sequence object that can be explicitly loaded and
                        // unloaded from TPM memory by the TRM".
                        if self.state.find_transient_object(handle).is_none()
                            && self.state.find_active_sequence(handle).is_none()
                        {
                            return Err(TpmRc::REFERENCE_H0);
                        }
                    } else if handle >> 24 == 0x81 {
                        self.load_evict_status(cc, handle, pos)?;
                    } else {
                        return Err(TpmRc::VALUE.with(pos));
                    }
                }
            } else if cc == TpmCc::StartAuthSession && h_idx == 1 {
                if handle != Handle::RH_NULL.0 {
                    let mso = handle >> 24;
                    if !matches!(mso, 0x40 | 0x01 | 0x80 | 0x81 | 0x00) {
                        return Err(TpmRc::VALUE.with(pos));
                    }
                    if mso == 0x40 {
                        let is_valid_entity = matches!(
                            handle,
                            0x40000001 // Owner
                            | 0x4000000B // Endorsement
                            | 0x4000000C // Platform
                            | 0x4000000A // Lockout
                            | 0x40000007 // Null
                        ) || is_vendor_permanent_auth(handle);
                        if !is_valid_entity {
                            return Err(TpmRc::VALUE.with(pos));
                        }
                    } else if mso == 0x80 {
                        if handle > Handle::TRANSIENT_LAST.0 {
                            return Err(TpmRc::VALUE.with(pos));
                        }
                        // A loaded sequence object is a loaded transient object too (see
                        // `tpmKey` above).
                        if self.state.find_transient_object(handle).is_none()
                            && self.state.find_active_sequence(handle).is_none()
                        {
                            return Err(TpmRc::REFERENCE_H1);
                        }
                    } else if mso == 0x81 {
                        self.load_evict_status(cc, handle, pos)?;
                    } else if mso == 0x00 && handle > 23 {
                        return Err(TpmRc::VALUE.with(pos));
                    }
                }
            } else if cc == TpmCc::SetPrimaryPolicy
                && (Handle::RH_ACT_0.0..=Handle::RH_ACT_F.0).contains(&handle)
            {
                // `TPMI_RH_HIERARCHY_POLICY` admits every ACT handle; an ACT that is not
                // implemented is not loaded (the reference's `EntityGetLoadStatus` reports it
                // like an invalid hierarchy, `TPM_RC_VALUE`).
                if !crate::act::is_implemented_act(handle) {
                    return Err(TpmRc::VALUE.with(pos));
                }
            } else if expects_permanent_handle(cc, h_idx) {
                if !(0x40000000..=0x40FFFFFF).contains(&handle) {
                    return Err(TpmRc::VALUE.with(pos));
                }
                // The exact `TPMI_RH_*` interface type of the handle (e.g. `TPMI_RH_ENDORSEMENT`,
                // `TPMI_RH_PROVISION`): any other value fails at handle unmarshaling.
                // `TPMI_RH_HIERARCHY` (`TPM2_CreatePrimary`) also holds the firmware-limited and
                // SVN-limited hierarchies.
                let limited_hierarchy =
                    cc == TpmCc::CreatePrimary && crate::hierarchy::is_limited(handle);
                if let Some(allowed) = permanent_handle_type(cc, h_idx)
                    && !allowed.contains(&handle)
                    && !limited_hierarchy
                {
                    return Err(TpmRc::VALUE.with(pos));
                }
                let is_valid_hierarchy = matches!(
                    handle,
                    0x40000001 // Owner
                    | 0x4000000B // Endorsement
                    | 0x4000000C // Platform
                    | 0x4000000A // Lockout
                    | 0x40000007 // Null
                ) || crate::hierarchy::is_limited(handle);
                if !is_valid_hierarchy {
                    return Err(TpmRc::VALUE.with(pos));
                }
            } else if (0x40000000..=0x40FFFFFF).contains(&handle) {
                // The implemented ACTs are always loaded (`EntityGetLoadStatus`); whether
                // their authValue may be used depends on phEnable (`is_auth_value_available`).
                let is_valid_hierarchy = matches!(
                    handle,
                    0x40000001 // Owner
                    | 0x4000000B // Endorsement
                    | 0x4000000C // Platform
                    | 0x4000000A // Lockout
                    | 0x40000007 // Null
                ) || is_vendor_permanent_auth(handle)
                    || crate::hierarchy::is_limited(handle)
                    || crate::act::is_implemented_act(handle);
                if !is_valid_hierarchy {
                    return Err(TpmRc::VALUE.with(pos));
                }
            } else if handle >> 24 == 0x80 {
                // Every handle interface type admits transient handles only in
                // {TRANSIENT_FIRST:TRANSIENT_LAST} (Part 2, Handle Value Constants).
                if handle > Handle::TRANSIENT_LAST.0 {
                    return Err(TpmRc::VALUE.with(pos));
                }
                // Any other transient handle must reference a loaded object (`IsObjectPresent`).
                if self.state.find_transient_object(handle).is_none()
                    && self.state.find_active_sequence(handle).is_none()
                {
                    return Err(reference_h(h_idx));
                }
            } else if handle >> 24 == 0x81 {
                // Any other persistent handle is loaded like an object handle (`ObjectLoadEvict`).
                self.load_evict_status(cc, handle, pos)?;
            }
            if (0x40000000..=0x40FFFFFF).contains(&handle)
                && !(cc == TpmCc::HierarchyControl && h_idx == 1)
                && cc != TpmCc::Load
            {
                // `VENDOR_PERMANENT_AUTH_HANDLE` (`TPM_RH_AUTH_00`) is part of the endorsement
                // hierarchy (`EntityGetLoadStatus`).
                if is_vendor_permanent_auth(handle) && !self.state.nv.clear.eh_enable {
                    return Err(TpmRc::HIERARCHY.with(pos));
                }
                if handle == 0x40000001 && !self.state.nv.clear.sh_enable {
                    return Err(TpmRc::HIERARCHY.with(pos));
                }
                if handle == 0x4000000B && !self.state.nv.clear.eh_enable {
                    return Err(TpmRc::HIERARCHY.with(pos));
                }
                if handle == 0x4000000C && !self.state.ph_enable {
                    return Err(TpmRc::HIERARCHY.with(pos));
                }
            }
        }
        Ok(())
    }

    /// Loads the persistent object `handle` referenced by the handle area of command `cc` the
    /// way `ObjectLoadEvict` does, and returns its load status:
    ///
    /// 1. A persistent handle of a disabled hierarchy (`phEnable` for platform handles
    ///    `0x8180_0000..`, `shEnable` otherwise) looks undefined: `TPM_RC_HANDLE` at `pos`.
    /// 2. A free object slot is needed for the duration of the command (shared with loaded
    ///    transient and sequence objects and the persistent objects already referenced by this
    ///    command, counted in `state.command_persistent_objects`): otherwise
    ///    `TPM_RC_OBJECT_MEMORY`.
    /// 3. An undefined persistent handle is `TPM_RC_HANDLE` at `pos`.
    /// 4. An endorsement-hierarchy object while `ehEnable` is clear is `TPM_RC_HANDLE` at `pos`,
    ///    except for `TPM2_EvictControl`.
    fn load_evict_status(&mut self, cc: TpmCc, handle: u32, pos: Position) -> Result<(), TpmRc> {
        let hierarchy_enabled = if handle >= 0x8180_0000 {
            self.state.ph_enable
        } else {
            self.state.nv.clear.sh_enable
        };
        if !hierarchy_enabled {
            return Err(TpmRc::HANDLE.with(pos));
        }
        let used = self.state.transient_objects.iter().flatten().count()
            + self.state.active_sequences.iter().flatten().count()
            + self.state.command_persistent_objects;
        if used >= MAX_LOADED_OBJECTS {
            return Err(TpmRc::OBJECT_MEMORY);
        }
        let hierarchy = match self.read_persistent_object(handle) {
            Ok(obj) => obj.hierarchy,
            Err(err) if err == TpmRc::HANDLE.to_rc() => return Err(TpmRc::HANDLE.with(pos)),
            Err(err) => return Err(err),
        };
        if hierarchy == Handle::RH_ENDORSEMENT.0
            && !self.state.nv.clear.eh_enable
            && cc != TpmCc::EvictControl
        {
            return Err(TpmRc::HANDLE.with(pos));
        }
        self.state.command_persistent_objects += 1;
        Ok(())
    }

    /// Checks that NV Index `handle` is accessible (C `NvIndexIsAccessible`): the index must be
    /// defined, and its hierarchy must be enabled (`phEnableNV` for `TPMA_NV_PLATFORMCREATE`
    /// indices, `shEnable` otherwise).
    ///
    /// Returns `TPM_RC_HANDLE` at `pos` if the index is not accessible.
    fn check_nv_index_accessible(&mut self, handle: u32, pos: Position) -> Result<(), TpmRc> {
        let storage = &mut self.state.nv.index;
        let metadata = storage
            .get_metadata(handle)
            .map_err(|_| TpmRc::HANDLE.with(pos))?;
        let enabled = if tpm2::TpmaNv(metadata.attributes).contains(tpm2::TpmaNv::PLATFORMCREATE) {
            self.state.nv.clear.ph_enable_nv
        } else {
            self.state.nv.clear.sh_enable
        };
        if !enabled {
            return Err(TpmRc::HANDLE.with(pos));
        }
        Ok(())
    }

    /// Fails with `TPM_RC_AUTH_MISSING` if a handle that requires authorization has no session.
    ///
    /// This matches the C reference: `CheckAuthNoSession()` for commands without a session area
    /// and the handle loop of `ParseSessionBuffer()` otherwise. Every handle whose authorization
    /// role (`CommandAuthRole()`) is not `AUTH_NONE` needs a session, even when the entity's
    /// authValue is empty (an empty authValue is still proven with a password or HMAC session).
    fn check_unauthorized_handles(
        &mut self,
        cc: TpmCc,
        handles: &[u32],
        handles_len: usize,
        session_to_handle_idx: &[usize],
        session_to_handle_idx_len: usize,
    ) -> Result<(), TpmRc> {
        let mapped = &session_to_handle_idx[..session_to_handle_idx_len];
        for h_idx in 0..handles_len.min(handles.len()) {
            if handle_requires_auth(cc, h_idx) && !mapped.contains(&h_idx) {
                return Err(TpmRc::AUTH_MISSING);
            }
        }
        Ok(())
    }

    fn execute_without_sessions(
        &mut self,
        cmd_buf: &[u8],
        resp_buf: &mut [u8],
        cc: TpmCc,
        request_size: usize,
    ) -> Result<usize, TpmRc> {
        let mut request_and_response =
            RequestResponseCursor::new(cmd_buf, resp_buf, ResponseHeader::MAX_SIZE);
        let mut request = request_and_response.request();
        let header: CommandHeader = request.try_unmarshal().map_err(|_| TpmRc::COMMAND_SIZE)?;
        request.set_session_tag(header.tag);
        if header.size as usize != request_size {
            return Err(TpmRc::COMMAND_SIZE);
        }

        if !self.state.initialized && cc != TpmCc::Startup {
            return Err(TpmRc::INITIALIZE);
        }

        let mut handler = CommandHandler::new(self);
        match cc {
            TpmCc::GetRandom => handler.get_random(request),
            TpmCc::StirRandom => handler.stir_random(request),
            TpmCc::PCRRead => handler.pcr_read(request),
            TpmCc::PCRExtend => handler.pcr_extend(request),
            TpmCc::PCREvent => handler.pcr_event(request),
            TpmCc::PCRReset => handler.pcr_reset(request),
            TpmCc::PCRAllocate => handler.pcr_allocate(request),
            TpmCc::PCRSetAuthPolicy => handler.pcr_set_auth_policy(request),
            TpmCc::PCRSetAuthValue => handler.pcr_set_auth_value(request),
            TpmCc::Startup => handler.startup(request),
            TpmCc::Shutdown => handler.shutdown(request),
            TpmCc::Clear => handler.clear(request),
            TpmCc::ClearControl => handler.clear_control(request),
            TpmCc::ChangePPS => handler.change_pps(request),
            TpmCc::ChangeEPS => handler.change_eps(request),
            TpmCc::CreatePrimary => handler.create_primary(request),
            TpmCc::CreateLoaded => handler.create_loaded(request),
            TpmCc::StartAuthSession => handler.start_auth_session(request),
            TpmCc::Commit => handler.commit(request),
            TpmCc::FlushContext => handler.flush_context(request),
            TpmCc::GetTime => handler.get_time(request),
            TpmCc::ReadClock => handler.read_clock(request),
            TpmCc::ClockSet => handler.clock_set(request),
            TpmCc::ClockRateAdjust => handler.clock_rate_adjust(request),
            TpmCc::ACTSetTimeout => handler.act_set_timeout(request),
            TpmCc::ContextSave => handler.context_save(request),
            TpmCc::ContextLoad => handler.context_load(request),
            TpmCc::ReadPublic => handler.read_public(request),
            TpmCc::EvictControl => handler.evict_control(request),
            TpmCc::HierarchyChangeAuth => handler.hierarchy_change_auth(request),
            TpmCc::HierarchyControl => handler.hierarchy_control(request),
            TpmCc::SetPrimaryPolicy => handler.set_primary_policy(request),
            TpmCc::LoadExternal => handler.load_external(request),
            TpmCc::VerifySignature => handler.verify_signature(request),
            TpmCc::Sign => handler.sign(request),
            TpmCc::EncryptDecrypt => handler.encrypt_decrypt(request),
            TpmCc::EncryptDecrypt2 => handler.encrypt_decrypt_2(request),
            TpmCc::RSADecrypt => handler.rsa_decrypt(request),
            TpmCc::RSAEncrypt => handler.rsa_encrypt(request),
            TpmCc::ECDHZGen => handler.ecdh_zgen(request),
            // With CMAC the TPM implements `TPM2_MAC` (same command code as `TPM2_HMAC`).
            #[cfg(feature = "cmac")]
            TpmCc::MAC => handler.mac_with_scheme(request),
            #[cfg(not(feature = "cmac"))]
            TpmCc::MAC => handler.mac(request),
            TpmCc::NVDefineSpace => handler.nv_define_space(request),
            TpmCc::NVUndefineSpace => handler.nv_undefine_space(request),
            TpmCc::NVUndefineSpaceSpecial => handler.nv_undefine_space_special(request),
            TpmCc::NVReadPublic => handler.nv_read_public(request),
            #[cfg(feature = "cc-nv-define-space2")]
            TpmCc::NVDefineSpace2 => handler.nv_define_space2(request),
            #[cfg(feature = "cc-nv-read-public2")]
            TpmCc::NVReadPublic2 => handler.nv_read_public2(request),
            #[cfg(feature = "cc-read-only-control")]
            TpmCc::ReadOnlyControl => handler.read_only_control(request),
            TpmCc::GetCapability => handler.get_capability(request),
            TpmCc::TestParms => handler.test_parms(request),
            TpmCc::SelfTest => handler.self_test(request),
            TpmCc::IncrementalSelfTest => handler.incremental_self_test(request),
            TpmCc::GetTestResult => handler.get_test_result(request),
            TpmCc::Certify => handler.certify(request),
            TpmCc::Quote => handler.quote(request),
            TpmCc::GetSessionAuditDigest => handler.get_session_audit_digest(request),
            TpmCc::GetCommandAuditDigest => handler.get_command_audit_digest(request),
            TpmCc::SetCommandCodeAuditStatus => handler.set_command_code_audit_status(request),
            TpmCc::CertifyCreation => handler.certify_creation(request),
            TpmCc::NVWrite => handler.nv_write(request),
            TpmCc::NVCertify => handler.nv_certify(request),
            TpmCc::NVRead => handler.nv_read(request),
            TpmCc::NVIncrement => handler.nv_increment(request),
            TpmCc::NVExtend => handler.nv_extend(request),
            TpmCc::NVSetBits => handler.nv_set_bits(request),
            TpmCc::NVChangeAuth => handler.nv_change_auth(request),
            TpmCc::DictionaryAttackLockReset => handler.dictionary_attack_lock_reset(request),
            TpmCc::DictionaryAttackParameters => handler.dictionary_attack_parameters(request),
            TpmCc::NVWriteLock => handler.nv_write_lock(request),
            TpmCc::NVGlobalWriteLock => handler.nv_global_write_lock(request),
            TpmCc::NVReadLock => handler.nv_read_lock(request),
            TpmCc::PolicyCommandCode => handler.policy_command_code(request),
            TpmCc::PolicyCounterTimer => handler.policy_counter_timer(request),
            TpmCc::PolicyCpHash => handler.policy_cp_hash(request),
            TpmCc::PolicyDuplicationSelect => handler.policy_duplication_select(request),
            TpmCc::PolicyLocality => handler.policy_locality(request),
            TpmCc::PolicyNameHash => handler.policy_name_hash(request),
            TpmCc::PolicyNV => handler.policy_nv(request),
            TpmCc::PolicyNvWritten => handler.policy_nv_written(request),
            TpmCc::PolicyGetDigest => handler.policy_get_digest(request),
            TpmCc::MakeCredential => handler.make_credential(request),
            TpmCc::ActivateCredential => handler.activate_credential(request),
            TpmCc::PolicySecret => handler.policy_secret(request),
            TpmCc::PolicySigned => handler.policy_signed(request),
            TpmCc::PolicyTicket => handler.policy_ticket(request),
            TpmCc::PolicyAuthorize => handler.policy_authorize(request),
            TpmCc::Duplicate => handler.duplicate(request),
            TpmCc::Import => handler.import(request),
            TpmCc::Rewrap => handler.rewrap(request),
            TpmCc::Load => handler.load(request),
            TpmCc::Unseal => handler.unseal(request),
            TpmCc::ObjectChangeAuth => handler.object_change_auth(request),
            TpmCc::Create => handler.create(request),
            TpmCc::PolicyOR => handler.policy_or(request),
            TpmCc::PolicyAuthorizeNV => handler.policy_authorize_nv(request),
            TpmCc::PolicyTemplate => handler.policy_template(request),
            #[cfg(feature = "cc-policy-transport-spdm")]
            TpmCc::PolicyTransportSPDM => handler.policy_transport_spdm(request),
            TpmCc::PolicyAuthValue => handler.policy_auth_value(request),
            TpmCc::PolicyPassword => handler.policy_password(request),
            TpmCc::PolicyPCR => handler.policy_pcr(request),
            TpmCc::Hash => handler.hash(request),
            TpmCc::HashSequenceStart => handler.hash_sequence_start(request),
            TpmCc::SequenceUpdate => handler.sequence_update(request),
            TpmCc::SequenceComplete => handler.sequence_complete(request),
            TpmCc::EventSequenceComplete => handler.event_sequence_complete(request),
            // With CMAC the TPM implements `TPM2_MAC_Start` (same command code as
            // `TPM2_HMAC_Start`).
            #[cfg(feature = "cmac")]
            TpmCc::MACStart => handler.mac_start_with_scheme(request),
            #[cfg(not(feature = "cmac"))]
            TpmCc::MACStart => handler.mac_start(request),
            #[cfg(feature = "cc-sign-digest")]
            TpmCc::SignDigest => handler.sign_digest(request),
            #[cfg(feature = "cc-verify-digest-signature")]
            TpmCc::VerifyDigestSignature => handler.verify_digest_signature(request),
            #[cfg(feature = "cc-sign-sequence-start")]
            TpmCc::SignSequenceStart => handler.sign_sequence_start(request),
            #[cfg(feature = "cc-sign-sequence-complete")]
            TpmCc::SignSequenceComplete => handler.sign_sequence_complete(request),
            #[cfg(feature = "cc-verify-sequence-start")]
            TpmCc::VerifySequenceStart => handler.verify_sequence_start(request),
            #[cfg(feature = "cc-verify-sequence-complete")]
            TpmCc::VerifySequenceComplete => handler.verify_sequence_complete(request),
            TpmCc::PolicyRestart => handler.policy_restart(request),
            TpmCc::ECDHKeyGen => handler.ecdh_keygen(request),
            #[cfg(feature = "cc-ec-ephemeral")]
            TpmCc::ECEphemeral => handler.ec_ephemeral(request),
            #[cfg(feature = "cc-zgen-2phase")]
            TpmCc::ZGen2Phase => handler.zgen_2phase(request),
            #[cfg(feature = "cc-ecc-encrypt")]
            TpmCc::ECCEncrypt => handler.ecc_encrypt(request),
            #[cfg(feature = "cc-ecc-decrypt")]
            TpmCc::ECCDecrypt => handler.ecc_decrypt(request),
            #[cfg(feature = "cc-encapsulate")]
            TpmCc::Encapsulate => handler.encapsulate(request),
            #[cfg(feature = "cc-decapsulate")]
            TpmCc::Decapsulate => handler.decapsulate(request),
            TpmCc::ECCParameters => handler.ecc_parameters(request),
            #[cfg(feature = "cc-pp-commands")]
            TpmCc::PPCommands => handler.pp_commands(request),
            #[cfg(feature = "cc-set-algorithm-set")]
            TpmCc::SetAlgorithmSet => handler.set_algorithm_set(request),
            #[cfg(feature = "cc-policy-physical-presence")]
            TpmCc::PolicyPhysicalPresence => handler.policy_physical_presence(request),
            #[cfg(feature = "cc-policy-ac-send-select")]
            TpmCc::PolicyACSendSelect => handler.policy_ac_send_select(request),
            #[cfg(feature = "cc-policy-capability")]
            TpmCc::PolicyCapability => handler.policy_capability(request),
            #[cfg(feature = "cc-policy-parameters")]
            TpmCc::PolicyParameters => handler.policy_parameters(request),
            TpmCc::VendorTcgTest => handler.vendor_tcg_test(request),
            #[cfg(feature = "ntc2-vendor-commands")]
            TpmCc::NTC2PreConfig => handler.ntc2_pre_config(request),
            #[cfg(feature = "ntc2-vendor-commands")]
            TpmCc::NTC2LockPreConfig => handler.ntc2_lock_pre_config(request),
            #[cfg(feature = "ntc2-vendor-commands")]
            TpmCc::NTC2GetConfig => handler.ntc2_get_config(request),
            _ => Err(TpmRc::COMMAND_CODE),
        }?;

        let last_read = request_and_response.last_request_byte_read();
        if last_read != request_size {
            return Err(TpmRc::SIZE.to_rc());
        }

        let response_size = request_and_response.last_response_byte_written();
        let session_tag = request_and_response.session_tag;
        let response = request_and_response.response_mut();
        if response.len() < response_size {
            return Err(TpmRc::MEMORY);
        }
        let resp_hdr = ResponseHeader {
            tag: session_tag.into(),
            size: response_size as u32,
            rc: Ok(()),
        };
        resp_hdr.marshal(
            (&mut response[..ResponseHeader::MAX_SIZE])
                .try_into()
                .unwrap(),
        );

        Ok(response_size)
    }
}

pub fn command_handles_count(cc: TpmCc) -> usize {
    match cc {
        TpmCc::GetRandom => 0,
        TpmCc::StirRandom => 0,
        TpmCc::Startup => 0,
        TpmCc::SelfTest => 0,
        TpmCc::PCRRead => 0,
        TpmCc::PCRExtend => 1,
        TpmCc::PCREvent => 1,
        TpmCc::PCRReset => 1,
        TpmCc::PCRAllocate => 1,
        TpmCc::PCRSetAuthPolicy => 1,
        TpmCc::PCRSetAuthValue => 1,
        TpmCc::Clear => 1,
        TpmCc::ClearControl => 1,
        TpmCc::ChangePPS => 1,
        TpmCc::ChangeEPS => 1,
        TpmCc::CreatePrimary => 1,
        TpmCc::CreateLoaded => 1,
        TpmCc::StartAuthSession => 2,
        TpmCc::Commit => 1,
        TpmCc::FlushContext => 0,
        TpmCc::GetTime => 2,
        TpmCc::ReadClock => 0,
        TpmCc::ClockSet => 1,
        TpmCc::ClockRateAdjust => 1,
        TpmCc::ACTSetTimeout => 1,
        TpmCc::ContextSave => 1,
        TpmCc::ContextLoad => 0,
        TpmCc::ReadPublic => 1,
        TpmCc::EvictControl => 2,
        TpmCc::HierarchyChangeAuth => 1,
        TpmCc::HierarchyControl => 1,
        TpmCc::SetPrimaryPolicy => 1,
        TpmCc::LoadExternal => 0,
        TpmCc::VerifySignature => 1,
        TpmCc::Sign => 1,
        TpmCc::EncryptDecrypt => 1,
        TpmCc::EncryptDecrypt2 => 1,
        TpmCc::RSADecrypt => 1,
        TpmCc::RSAEncrypt => 1,
        TpmCc::ECDHZGen => 1,
        TpmCc::ECDHKeyGen => 1,
        TpmCc::ZGen2Phase => 1,
        TpmCc::ECCEncrypt => 1,
        TpmCc::ECCDecrypt => 1,
        TpmCc::Encapsulate => 1,
        TpmCc::Decapsulate => 1,
        TpmCc::MAC => 1,
        TpmCc::NVDefineSpace => 1,
        TpmCc::NVUndefineSpace => 2,
        TpmCc::NVUndefineSpaceSpecial => 2,
        TpmCc::NVReadPublic => 1,
        TpmCc::NVDefineSpace2 => 1,
        TpmCc::NVReadPublic2 => 1,
        TpmCc::ReadOnlyControl => 1,
        TpmCc::GetCapability => 0,
        TpmCc::Certify => 2,
        TpmCc::Quote => 1,
        TpmCc::GetSessionAuditDigest => 3,
        TpmCc::GetCommandAuditDigest => 2,
        TpmCc::SetCommandCodeAuditStatus => 1,
        TpmCc::CertifyCreation => 2,
        TpmCc::NVWrite => 2,
        TpmCc::NVCertify => 3,
        TpmCc::NVRead => 2,
        TpmCc::NVIncrement => 2,
        TpmCc::NVExtend => 2,
        TpmCc::NVSetBits => 2,
        TpmCc::NVChangeAuth => 1,
        TpmCc::DictionaryAttackLockReset => 1,
        TpmCc::DictionaryAttackParameters => 1,
        TpmCc::NVWriteLock => 2,
        TpmCc::NVGlobalWriteLock => 1,
        TpmCc::NVReadLock => 2,
        TpmCc::Duplicate => 2,
        TpmCc::Import => 1,
        TpmCc::Rewrap => 2,
        TpmCc::Load => 1,
        TpmCc::Unseal => 1,
        TpmCc::ObjectChangeAuth => 2,
        TpmCc::MakeCredential => 1,
        TpmCc::ActivateCredential => 2,
        TpmCc::PolicySecret => 2,
        TpmCc::PolicySigned => 2,
        TpmCc::PolicyTicket => 1,
        TpmCc::PolicyAuthorize => 1,
        TpmCc::Create => 1,
        TpmCc::PolicyOR => 1,
        TpmCc::PolicyAuthorizeNV => 3,
        TpmCc::PolicyCommandCode => 1,
        TpmCc::PolicyCounterTimer => 1,
        TpmCc::PolicyCpHash => 1,
        TpmCc::PolicyDuplicationSelect => 1,
        TpmCc::PolicyLocality => 1,
        TpmCc::PolicyNameHash => 1,
        TpmCc::PolicyNV => 3,
        TpmCc::PolicyNvWritten => 1,
        TpmCc::PolicyGetDigest => 1,
        TpmCc::PolicyAuthValue => 1,
        TpmCc::PolicyPassword => 1,
        TpmCc::PolicyPCR => 1,
        TpmCc::PolicyTemplate => 1,
        TpmCc::PolicyTransportSPDM => 1,
        TpmCc::Hash => 0,
        TpmCc::HashSequenceStart => 0,
        TpmCc::SequenceUpdate => 1,
        TpmCc::SequenceComplete => 1,
        TpmCc::EventSequenceComplete => 2,
        TpmCc::MACStart => 1,
        TpmCc::SignDigest => 1,
        TpmCc::VerifyDigestSignature => 1,
        TpmCc::SignSequenceStart => 1,
        TpmCc::VerifySequenceStart => 1,
        TpmCc::SignSequenceComplete => 2,
        TpmCc::VerifySequenceComplete => 2,
        TpmCc::TestParms => 0,
        TpmCc::ECCParameters => 0,
        TpmCc::IncrementalSelfTest => 0,
        TpmCc::GetTestResult => 0,
        TpmCc::PolicyRestart => 1,
        TpmCc::PPCommands => 1,
        TpmCc::SetAlgorithmSet => 1,
        TpmCc::PolicyPhysicalPresence => 1,
        TpmCc::PolicyACSendSelect => 1,
        TpmCc::PolicyCapability => 1,
        TpmCc::PolicyParameters => 1,
        _ => 0,
    }
}

pub fn get_command_attribute(cc: TpmCc) -> tpm2::TpmaCc {
    let mut attr = tpm2::TpmaCc::command_index(cc.code() as u16);
    let handles = command_handles_count(cc) as u32;
    attr.0 |= (handles << 25) & 0x0E000000;
    if command_returns_handle(cc) {
        attr |= tpm2::TpmaCc::R_HANDLE;
    }
    if matches!(
        cc,
        TpmCc::NVUndefineSpaceSpecial
            | TpmCc::EvictControl
            | TpmCc::HierarchyControl
            | TpmCc::NVUndefineSpace
            | TpmCc::Clear
            | TpmCc::ClearControl
            | TpmCc::ClockSet
            | TpmCc::HierarchyChangeAuth
            | TpmCc::NVDefineSpace
            | TpmCc::PCRAllocate
            | TpmCc::PCRSetAuthPolicy
            | TpmCc::PPCommands
            | TpmCc::SetAlgorithmSet
            | TpmCc::SetPrimaryPolicy
            | TpmCc::NVGlobalWriteLock
            | TpmCc::GetCommandAuditDigest
            | TpmCc::SetCommandCodeAuditStatus
            | TpmCc::NVIncrement
            | TpmCc::NVSetBits
            | TpmCc::NVExtend
            | TpmCc::NVWrite
            | TpmCc::NVWriteLock
            | TpmCc::DictionaryAttackLockReset
            | TpmCc::DictionaryAttackParameters
            | TpmCc::NVChangeAuth
            | TpmCc::PCREvent
            | TpmCc::PCRReset
            | TpmCc::IncrementalSelfTest
            | TpmCc::SelfTest
            | TpmCc::Startup
            | TpmCc::Shutdown
            | TpmCc::StirRandom
            | TpmCc::NVReadLock
            | TpmCc::PCRExtend
            | TpmCc::EventSequenceComplete
            | TpmCc::ChangeEPS
            | TpmCc::ChangePPS
            | TpmCc::NVDefineSpace2
            | TpmCc::ReadOnlyControl
    ) {
        attr |= tpm2::TpmaCc::NV;
    }
    // `extensive` and `flushed` follow `s_ccAttr` in `CommandAttributeData.h`.
    if matches!(
        cc,
        TpmCc::HierarchyControl | TpmCc::Clear | TpmCc::ChangeEPS | TpmCc::ChangePPS
    ) {
        attr |= tpm2::TpmaCc::EXTENSIVE;
    }
    // TPM 2.0 Part 3 marks `TPM_CC_SignSequenceComplete {F}` and
    // `TPM_CC_VerifySequenceComplete {F}` (their sequence object is flushed) like
    // `TPM_CC_SequenceComplete {F}`.
    if matches!(
        cc,
        TpmCc::SequenceComplete
            | TpmCc::EventSequenceComplete
            | TpmCc::SignSequenceComplete
            | TpmCc::VerifySequenceComplete
    ) {
        attr |= tpm2::TpmaCc::FLUSHED;
    }
    // Vendor commands (`TPMA_CC_INITIALIZER(..., v = 1, ...)`): `commandIndex` is the low 16
    // bits of the command code and `V` is SET. `ibmswtpm2` gives its Nuvoton `NTC2_*` commands
    // the `nv` attribute.
    if cc.is_vendor() {
        attr |= tpm2::TpmaCc::V;
    }
    #[cfg(feature = "ntc2-vendor-commands")]
    if matches!(
        cc,
        TpmCc::NTC2PreConfig | TpmCc::NTC2LockPreConfig | TpmCc::NTC2GetConfig
    ) {
        attr |= tpm2::TpmaCc::NV;
    }
    attr
}

/// Returns whether `handle` is the vendor-specific permanent authorization handle
/// `TPM_RH_AUTH_00` (`VENDOR_PERMANENT_AUTH_HANDLE`) of a TPM that implements it (the
/// `vendor-permanent-auth` feature). It is an entity of the endorsement hierarchy whose
/// authValue is the platform's unique value (Part 1, "Permanent Resource Handles (MSO=40)").
/// Without the feature, `TPM_RH_AUTH_00` is a valid `TPMI_DH_ENTITY` value that references no
/// entity (`EntityGetLoadStatus`: `TPM_RC_VALUE`), like any other `TPM_RH_AUTH_xx`.
pub(crate) const fn is_vendor_permanent_auth(handle: u32) -> bool {
    cfg!(feature = "vendor-permanent-auth") && handle == Handle::RH_AUTH_00.0
}

/// Returns `false` for the commands that have the `NO_SESSIONS` attribute in
/// `CommandAttributeData.h` (`IsSessionAllowed`): `TPM2_Startup`, `TPM2_ContextLoad`,
/// `TPM2_ContextSave` and `TPM2_FlushContext`. Sending them with `TPM_ST_SESSIONS` fails with
/// `TPM_RC_AUTH_CONTEXT`.
///
/// `ibmswtpm2` also gives its Nuvoton `NTC2_*` vendor commands `NO_SESSIONS`.
pub(crate) fn is_session_allowed(cc: TpmCc) -> bool {
    #[cfg(feature = "ntc2-vendor-commands")]
    if matches!(
        cc,
        TpmCc::NTC2PreConfig | TpmCc::NTC2LockPreConfig | TpmCc::NTC2GetConfig
    ) {
        return false;
    }
    !matches!(
        cc,
        TpmCc::Startup | TpmCc::ContextLoad | TpmCc::ContextSave | TpmCc::FlushContext
    )
}

/// List of the TPM 2.0 library command codes supported by this engine implementation (the
/// vendor-specific commands are in [`VENDOR_COMMANDS`]).
/// The command codes (`TpmCc`) are defined in TCG TPM 2.0 Library Specification Part 3: Commands.
pub(crate) const SUPPORTED_COMMANDS: &[TpmCc] = &[
    TpmCc::GetRandom,
    TpmCc::StirRandom,
    TpmCc::Startup,
    TpmCc::Shutdown,
    TpmCc::PCRRead,
    TpmCc::PCRExtend,
    TpmCc::PCREvent,
    TpmCc::PCRReset,
    TpmCc::PCRSetAuthPolicy,
    TpmCc::PCRSetAuthValue,
    TpmCc::Clear,
    TpmCc::ClearControl,
    TpmCc::ChangePPS,
    TpmCc::ChangeEPS,
    TpmCc::CreatePrimary,
    TpmCc::CreateLoaded,
    TpmCc::StartAuthSession,
    TpmCc::Commit,
    TpmCc::FlushContext,
    TpmCc::GetTime,
    TpmCc::ReadClock,
    TpmCc::ClockSet,
    TpmCc::ClockRateAdjust,
    TpmCc::ContextSave,
    TpmCc::ContextLoad,
    TpmCc::ReadPublic,
    TpmCc::EvictControl,
    TpmCc::HierarchyChangeAuth,
    TpmCc::HierarchyControl,
    TpmCc::SetPrimaryPolicy,
    TpmCc::LoadExternal,
    TpmCc::VerifySignature,
    TpmCc::Sign,
    TpmCc::EncryptDecrypt,
    TpmCc::EncryptDecrypt2,
    TpmCc::RSADecrypt,
    TpmCc::RSAEncrypt,
    TpmCc::ECDHZGen,
    TpmCc::MAC,
    TpmCc::NVDefineSpace,
    TpmCc::NVUndefineSpace,
    TpmCc::NVUndefineSpaceSpecial,
    TpmCc::NVReadPublic,
    TpmCc::GetCapability,
    TpmCc::Certify,
    TpmCc::Quote,
    TpmCc::GetSessionAuditDigest,
    TpmCc::GetCommandAuditDigest,
    TpmCc::SetCommandCodeAuditStatus,
    TpmCc::CertifyCreation,
    TpmCc::NVWrite,
    TpmCc::NVCertify,
    TpmCc::PolicyCommandCode,
    TpmCc::PolicyCounterTimer,
    TpmCc::PolicyCpHash,
    TpmCc::PolicyDuplicationSelect,
    TpmCc::PolicyLocality,
    TpmCc::PolicyNameHash,
    TpmCc::PolicyNV,
    TpmCc::PolicyNvWritten,
    TpmCc::PolicyGetDigest,
    TpmCc::Duplicate,
    TpmCc::Import,
    TpmCc::Rewrap,
    TpmCc::Load,
    TpmCc::Unseal,
    TpmCc::ObjectChangeAuth,
    TpmCc::MakeCredential,
    TpmCc::ActivateCredential,
    TpmCc::PolicySecret,
    TpmCc::PolicySigned,
    TpmCc::PolicyTicket,
    TpmCc::PolicyAuthorize,
    TpmCc::Create,
    TpmCc::PolicyOR,
    TpmCc::PolicyAuthorizeNV,
    TpmCc::PolicyAuthValue,
    TpmCc::PolicyPassword,
    TpmCc::PolicyPCR,
    TpmCc::PolicyTemplate,
    TpmCc::Hash,
    TpmCc::HashSequenceStart,
    TpmCc::SequenceUpdate,
    TpmCc::SequenceComplete,
    TpmCc::EventSequenceComplete,
    TpmCc::MACStart,
    TpmCc::NVRead,
    TpmCc::NVIncrement,
    TpmCc::NVExtend,
    TpmCc::NVSetBits,
    TpmCc::NVChangeAuth,
    TpmCc::NVWriteLock,
    TpmCc::NVGlobalWriteLock,
    TpmCc::NVReadLock,
    TpmCc::TestParms,
    TpmCc::SelfTest,
    TpmCc::IncrementalSelfTest,
    TpmCc::GetTestResult,
    TpmCc::PolicyRestart,
    TpmCc::ECDHKeyGen,
    TpmCc::ECCParameters,
    TpmCc::DictionaryAttackLockReset,
    TpmCc::DictionaryAttackParameters,
    TpmCc::PCRAllocate,
    TpmCc::ACTSetTimeout,
    // policy: Physical Presence, the platform settings and the policy assertions.
    #[cfg(feature = "cc-pp-commands")]
    TpmCc::PPCommands,
    #[cfg(feature = "cc-set-algorithm-set")]
    TpmCc::SetAlgorithmSet,
    #[cfg(feature = "cc-policy-physical-presence")]
    TpmCc::PolicyPhysicalPresence,
    #[cfg(feature = "cc-policy-ac-send-select")]
    TpmCc::PolicyACSendSelect,
    #[cfg(feature = "cc-policy-capability")]
    TpmCc::PolicyCapability,
    #[cfg(feature = "cc-policy-parameters")]
    TpmCc::PolicyParameters,
    #[cfg(feature = "cc-nv-define-space2")]
    TpmCc::NVDefineSpace2,
    #[cfg(feature = "cc-nv-read-public2")]
    TpmCc::NVReadPublic2,
    #[cfg(feature = "cc-read-only-control")]
    TpmCc::ReadOnlyControl,
    // The version 185 signing commands (one profile feature each).
    #[cfg(feature = "cc-sign-digest")]
    TpmCc::SignDigest,
    #[cfg(feature = "cc-verify-digest-signature")]
    TpmCc::VerifyDigestSignature,
    #[cfg(feature = "cc-sign-sequence-start")]
    TpmCc::SignSequenceStart,
    #[cfg(feature = "cc-sign-sequence-complete")]
    TpmCc::SignSequenceComplete,
    #[cfg(feature = "cc-verify-sequence-start")]
    TpmCc::VerifySequenceStart,
    #[cfg(feature = "cc-verify-sequence-complete")]
    TpmCc::VerifySequenceComplete,
    // pqc: the KEM commands (version 185).
    #[cfg(feature = "cc-encapsulate")]
    TpmCc::Encapsulate,
    #[cfg(feature = "cc-decapsulate")]
    TpmCc::Decapsulate,
    // Secure channel support (spdm).
    #[cfg(feature = "cc-policy-transport-spdm")]
    TpmCc::PolicyTransportSPDM,
    // ECC key exchange and encryption (ecc-cmds).
    #[cfg(feature = "cc-ec-ephemeral")]
    TpmCc::ECEphemeral,
    #[cfg(feature = "cc-zgen-2phase")]
    TpmCc::ZGen2Phase,
    #[cfg(feature = "cc-ecc-encrypt")]
    TpmCc::ECCEncrypt,
    #[cfg(feature = "cc-ecc-decrypt")]
    TpmCc::ECCDecrypt,
];

/// The vendor-specific commands (command codes with the `V` bit, `CC_VEND`) this engine
/// implements, in ascending command-code order (the order of the vendor part of the
/// reference's `s_ccAttr`, which follows the library commands):
///
/// * `TPM2_Vendor_TCG_Test` (TPM 2.0 Part 3, "Vendor Specific"), which every C reference
///   implements (`CC_Vendor_TCG_Test CC_YES`);
/// * with the `ntc2-vendor-commands` profile feature, the Nuvoton `NTC2_PreConfig`,
///   `NTC2_LockPreConfig` and `NTC2_GetConfig` commands as emulated by `ibmswtpm2`
///   (`TPM_NUVOTON`).
pub(crate) const VENDOR_COMMANDS: &[TpmCc] = &[
    TpmCc::VendorTcgTest,
    #[cfg(feature = "ntc2-vendor-commands")]
    TpmCc::NTC2PreConfig,
    #[cfg(feature = "ntc2-vendor-commands")]
    TpmCc::NTC2LockPreConfig,
    #[cfg(feature = "ntc2-vendor-commands")]
    TpmCc::NTC2GetConfig,
];

/// The number of implemented commands, library and vendor (`COMMAND_COUNT`,
/// `TPM_PT_TOTAL_COMMANDS`).
pub(crate) const TOTAL_COMMAND_COUNT: usize = SUPPORTED_COMMANDS.len() + VENDOR_COMMANDS.len();

pub(crate) fn is_command_supported(cc: TpmCc) -> bool {
    SUPPORTED_COMMANDS.contains(&cc) || VENDOR_COMMANDS.contains(&cc)
}

/// Returns every implemented command in the order of the reference's command table
/// (`s_ccAttr`): the library commands in ascending command-code order, then the vendor
/// commands in ascending order (since every vendor code has the `V` bit, this is ascending
/// order of the 32-bit command codes). `TPM_CAP_COMMANDS`, `TPM_CAP_AUDIT_COMMANDS` and the
/// command audit digest list the commands in this order.
pub(crate) fn implemented_commands_in_order() -> [TpmCc; TOTAL_COMMAND_COUNT] {
    let mut all = [TpmCc::default(); TOTAL_COMMAND_COUNT];
    all[..SUPPORTED_COMMANDS.len()].copy_from_slice(SUPPORTED_COMMANDS);
    all[SUPPORTED_COMMANDS.len()..].copy_from_slice(VENDOR_COMMANDS);
    all.sort_unstable_by_key(|cc| cc.code());
    all
}

/// The lowest command code a capability list of commands (`TPM_CAP_COMMANDS`,
/// `TPM_CAP_PP_COMMANDS`, `TPM_CAP_AUDIT_COMMANDS`) starting at `property` may report, or
/// `None` if it reports none.
///
/// TPM 2.0 Part 3, TPM2_GetCapability: the list starts "with the `TPM_CC` indicated by the
/// *property* parameter. If vendor specific commands are implemented, the vendor-specific
/// command attribute with the lowest *commandIndex*, is returned after the
/// non-vendor-specific (base) command." The spec is silent on a `property` that is not a
/// command code; as in the reference (`GetClosestCommandIndex()`), a `property` with a bit
/// other than `V` set above its low 16 bits starts no list at all. Otherwise, the list starts
/// at the first implemented command whose code is at least `property` in the order of
/// [`implemented_commands_in_order`]: a library `property` continues with the vendor
/// commands, a vendor `property` (`V` SET) only lists vendor commands with a `commandIndex`
/// of at least its low 16 bits.
pub(crate) fn command_list_start(property: u32) -> Option<u32> {
    (property & !TpmCc::VEND.code() <= 0xFFFF).then_some(property)
}

/// Returns whether `cc` allows a session with `TPMA_SESSION_DECRYPT` (i.e. its first command
/// parameter is a `TPM2B` that may be encrypted).
///
/// Mirrors the `DECRYPT_2` attribute in the C reference `CommandAttributeData.h`, restricted to
/// the commands in [`SUPPORTED_COMMANDS`] and [`VENDOR_COMMANDS`]. Notably `TPM2_EncryptDecrypt` is absent because its
/// first parameter is a `TPMI_YES_NO`, not a `TPM2B`.
fn command_supports_decryption(cc: TpmCc) -> bool {
    matches!(
        cc,
        TpmCc::VendorTcgTest
            | TpmCc::ActivateCredential
            | TpmCc::Certify
            | TpmCc::CertifyCreation
            | TpmCc::Commit
            | TpmCc::Create
            | TpmCc::CreateLoaded
            | TpmCc::CreatePrimary
            | TpmCc::Duplicate
            | TpmCc::ECCDecrypt
            | TpmCc::ECCEncrypt
            | TpmCc::Decapsulate
            | TpmCc::ECDHZGen
            | TpmCc::EncryptDecrypt2
            | TpmCc::EventSequenceComplete
            | TpmCc::GetCommandAuditDigest
            | TpmCc::GetSessionAuditDigest
            | TpmCc::GetTime
            | TpmCc::Hash
            | TpmCc::HashSequenceStart
            | TpmCc::HierarchyChangeAuth
            | TpmCc::Import
            | TpmCc::Load
            | TpmCc::LoadExternal
            | TpmCc::MAC
            | TpmCc::MACStart
            | TpmCc::MakeCredential
            | TpmCc::NVCertify
            | TpmCc::NVChangeAuth
            | TpmCc::NVDefineSpace
            | TpmCc::NVDefineSpace2
            | TpmCc::NVExtend
            | TpmCc::NVWrite
            | TpmCc::ObjectChangeAuth
            | TpmCc::PCREvent
            | TpmCc::PCRSetAuthPolicy
            | TpmCc::PCRSetAuthValue
            | TpmCc::PolicyACSendSelect
            | TpmCc::PolicyAuthorize
            | TpmCc::PolicyCapability
            | TpmCc::PolicyCounterTimer
            | TpmCc::PolicyCpHash
            | TpmCc::PolicyDuplicationSelect
            | TpmCc::PolicyNV
            | TpmCc::PolicyNameHash
            | TpmCc::PolicyPCR
            | TpmCc::PolicyParameters
            | TpmCc::PolicySecret
            | TpmCc::PolicySigned
            | TpmCc::PolicyTemplate
            | TpmCc::PolicyTicket
            | TpmCc::PolicyTransportSPDM
            | TpmCc::Quote
            | TpmCc::RSADecrypt
            | TpmCc::RSAEncrypt
            | TpmCc::Rewrap
            | TpmCc::SequenceComplete
            | TpmCc::SequenceUpdate
            | TpmCc::SetPrimaryPolicy
            | TpmCc::Sign
            | TpmCc::SignDigest
            | TpmCc::SignSequenceComplete
            | TpmCc::SignSequenceStart
            | TpmCc::StartAuthSession
            | TpmCc::StirRandom
            | TpmCc::VerifyDigestSignature
            | TpmCc::VerifySequenceStart
            | TpmCc::VerifySignature
            | TpmCc::ZGen2Phase
    )
}

/// Returns whether `cc` allows a session with `TPMA_SESSION_ENCRYPT` (i.e. its first response
/// parameter is a `TPM2B` that may be encrypted).
///
/// Mirrors the `ENCRYPT_2` attribute in the C reference `CommandAttributeData.h`, restricted to
/// the commands in [`SUPPORTED_COMMANDS`] and [`VENDOR_COMMANDS`].
fn command_supports_encryption(cc: TpmCc) -> bool {
    matches!(
        cc,
        TpmCc::VendorTcgTest
            | TpmCc::ActivateCredential
            | TpmCc::Certify
            | TpmCc::CertifyCreation
            | TpmCc::Commit
            | TpmCc::Decapsulate
            | TpmCc::Encapsulate
            | TpmCc::Create
            | TpmCc::CreateLoaded
            | TpmCc::CreatePrimary
            | TpmCc::Duplicate
            | TpmCc::ECCDecrypt
            | TpmCc::ECCEncrypt
            | TpmCc::ECDHKeyGen
            | TpmCc::ECDHZGen
            | TpmCc::ECEphemeral
            | TpmCc::EncryptDecrypt
            | TpmCc::EncryptDecrypt2
            | TpmCc::GetCommandAuditDigest
            | TpmCc::GetRandom
            | TpmCc::GetSessionAuditDigest
            | TpmCc::GetTestResult
            | TpmCc::GetTime
            | TpmCc::Hash
            | TpmCc::Import
            | TpmCc::Load
            | TpmCc::LoadExternal
            | TpmCc::MAC
            | TpmCc::MakeCredential
            | TpmCc::NVCertify
            | TpmCc::NVRead
            | TpmCc::NVReadPublic
            | TpmCc::NVReadPublic2
            | TpmCc::ObjectChangeAuth
            | TpmCc::PolicyGetDigest
            | TpmCc::PolicySecret
            | TpmCc::PolicySigned
            | TpmCc::Quote
            | TpmCc::RSADecrypt
            | TpmCc::RSAEncrypt
            | TpmCc::ReadPublic
            | TpmCc::Rewrap
            | TpmCc::SequenceComplete
            | TpmCc::StartAuthSession
            | TpmCc::Unseal
            | TpmCc::ZGen2Phase
    )
}

pub(crate) fn command_resp_handles_size(cc: TpmCc) -> usize {
    match cc {
        TpmCc::CreatePrimary
        | TpmCc::StartAuthSession
        | TpmCc::ContextLoad
        | TpmCc::CreateLoaded
        | TpmCc::LoadExternal
        | TpmCc::Load
        | TpmCc::HashSequenceStart
        | TpmCc::MACStart
        | TpmCc::SignSequenceStart
        | TpmCc::VerifySequenceStart => 4,
        _ => 0,
    }
}

fn compute_nv_name<C: Crypto>(
    crypto: &crate::self_test::Tested<'_, C>,
    name_alg: TpmiAlgHash,
    public_area_bytes: &[u8],
) -> Result<OwnedName, TpmRc> {
    let mut name_bytes = [0u8; 66];
    let offset = name_alg.marshal((&mut name_bytes[..2]).try_into().unwrap());
    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = crypto
        .hash(name_alg, &[public_area_bytes], &mut digest_buf)
        .map_err(|_| TpmRc::FAILURE)?;
    let digest_slice = digest.digest();
    name_bytes[offset..offset + digest_slice.len()].copy_from_slice(digest_slice);
    OwnedName::from_bytes(&name_bytes[..offset + digest_slice.len()]).map_err(|_| TpmRc::FAILURE)
}

fn handle_name<P: Platform>(ctx: &mut TpmEngine<P>, handle: u32) -> OwnedName {
    if ctx.state.find_active_sequence(handle).is_some() {
        return OwnedName::default();
    }
    for obj in ctx.state.transient_objects.iter().flatten() {
        if obj.handle == handle {
            return obj.name;
        }
    }
    if Handle(handle).handle_type() == Some(TpmHt::NVIndex) {
        let storage_mgr = &mut ctx.state.nv.index;
        if let Ok(metadata) = storage_mgr.get_metadata(handle) {
            let read_len = core::cmp::min(metadata.data_size as usize, 1536);
            let mut read_buf = [0u8; 1536];
            if storage_mgr
                .read_item(handle, 0, &mut read_buf[..read_len])
                .is_ok()
                && let Ok((_, nv_public_struct, _, _, hash_target)) =
                    crate::handler::nv_storage::unmarshal_nv_header_bytes(&read_buf[..read_len])
                && let Ok(nv_name) =
                    compute_nv_name(&ctx.crypto(), nv_public_struct.name_alg, hash_target)
            {
                return nv_name;
            }
        }
    } else if (0x81000000..=0x81FFFFFF).contains(&handle) {
        // A persistent object of a disabled hierarchy looks undefined (`ObjectLoadEvict`).
        if let Ok(obj) = ctx.load_persistent_object(handle) {
            return obj.name;
        }
    }
    // Only permanent, session and PCR handles have the handle value as their Name
    // (`EntityGetName`); an object or NV Index that is not loaded/defined has no Name.
    if matches!(handle >> 24, 0x80 | 0x81 | 0x01) {
        return OwnedName::default();
    }
    let handle_bytes = handle.to_be_bytes();
    OwnedName::from_bytes(&handle_bytes).unwrap_or_default()
}

fn expects_permanent_handle(cc: TpmCc, handle_index: usize) -> bool {
    if handle_index == 0 {
        matches!(
            cc,
            TpmCc::EvictControl
                | TpmCc::CreatePrimary
                | TpmCc::Clear
                | TpmCc::ClearControl
                | TpmCc::HierarchyChangeAuth
                | TpmCc::HierarchyControl
                | TpmCc::SetPrimaryPolicy
                | TpmCc::ChangePPS
                | TpmCc::ChangeEPS
                | TpmCc::DictionaryAttackLockReset
                | TpmCc::DictionaryAttackParameters
                | TpmCc::GetSessionAuditDigest
                | TpmCc::GetCommandAuditDigest
                | TpmCc::SetCommandCodeAuditStatus
                | TpmCc::ClockSet
                | TpmCc::ClockRateAdjust
                | TpmCc::PCRAllocate
                | TpmCc::PCRSetAuthPolicy
                | TpmCc::GetTime
                | TpmCc::NVDefineSpace
                | TpmCc::NVGlobalWriteLock
                | TpmCc::PPCommands
                | TpmCc::SetAlgorithmSet
                | TpmCc::NVDefineSpace2
                | TpmCc::ReadOnlyControl
        )
    } else {
        false
    }
}

/// Returns the values admitted by the `TPMI_RH_*` interface type of the permanent handle at
/// `handle_index` of command `cc` (`Part 3` command tables / `Marshal.c`), or `None` if the
/// position is not checked against an exact type here.
fn permanent_handle_type(cc: TpmCc, handle_index: usize) -> Option<&'static [u32]> {
    const OWNER: u32 = Handle::RH_OWNER.0;
    const ENDORSEMENT: u32 = Handle::RH_ENDORSEMENT.0;
    const PLATFORM: u32 = Handle::RH_PLATFORM.0;
    const LOCKOUT: u32 = Handle::RH_LOCKOUT.0;
    const NULL: u32 = Handle::RH_NULL.0;
    if handle_index != 0 {
        return None;
    }
    Some(match cc {
        // TPMI_RH_HIERARCHY+
        TpmCc::CreatePrimary => &[OWNER, ENDORSEMENT, PLATFORM, NULL],
        // TPMI_RH_HIERARCHY
        TpmCc::HierarchyControl => &[OWNER, ENDORSEMENT, PLATFORM],
        // TPMI_RH_HIERARCHY_AUTH / TPMI_RH_HIERARCHY_POLICY (the ACT handles of
        // `TPMI_RH_HIERARCHY_POLICY` are checked by `check_command_handles`)
        TpmCc::HierarchyChangeAuth | TpmCc::SetPrimaryPolicy => {
            &[OWNER, ENDORSEMENT, PLATFORM, LOCKOUT]
        }
        // TPMI_RH_PROVISION
        TpmCc::EvictControl
        | TpmCc::ClockSet
        | TpmCc::ClockRateAdjust
        | TpmCc::NVDefineSpace
        | TpmCc::NVDefineSpace2
        | TpmCc::NVGlobalWriteLock
        | TpmCc::SetCommandCodeAuditStatus => &[OWNER, PLATFORM],
        // TPMI_RH_CLEAR
        TpmCc::Clear | TpmCc::ClearControl => &[LOCKOUT, PLATFORM],
        // TPMI_RH_PLATFORM
        TpmCc::ChangePPS
        | TpmCc::ChangeEPS
        | TpmCc::PCRAllocate
        | TpmCc::PCRSetAuthPolicy
        | TpmCc::PPCommands
        | TpmCc::SetAlgorithmSet
        | TpmCc::ReadOnlyControl => &[PLATFORM],
        // TPMI_RH_LOCKOUT
        TpmCc::DictionaryAttackLockReset | TpmCc::DictionaryAttackParameters => &[LOCKOUT],
        // TPMI_RH_ENDORSEMENT
        TpmCc::GetTime | TpmCc::GetSessionAuditDigest | TpmCc::GetCommandAuditDigest => {
            &[ENDORSEMENT]
        }
        _ => return None,
    })
}

fn expects_object_handle(cc: TpmCc, handle_index: usize) -> bool {
    if handle_index == 0 {
        matches!(
            cc,
            TpmCc::ReadPublic
                | TpmCc::Sign
                | TpmCc::RSADecrypt
                | TpmCc::Encapsulate
                | TpmCc::Decapsulate
                | TpmCc::ECDHZGen
                | TpmCc::MAC
                | TpmCc::Certify
                | TpmCc::Quote
                | TpmCc::NVCertify
                | TpmCc::CertifyCreation
                | TpmCc::ActivateCredential
                | TpmCc::MakeCredential
                | TpmCc::Load
                | TpmCc::Unseal
                | TpmCc::ObjectChangeAuth
                | TpmCc::Duplicate
                | TpmCc::SequenceUpdate
                | TpmCc::SequenceComplete
                | TpmCc::Create
                | TpmCc::VerifySignature
                | TpmCc::EncryptDecrypt
                | TpmCc::EncryptDecrypt2
                | TpmCc::Import
                | TpmCc::MACStart
                | TpmCc::RSAEncrypt
                | TpmCc::ECDHKeyGen
                | TpmCc::ZGen2Phase
                | TpmCc::ECCEncrypt
                | TpmCc::ECCDecrypt
                | TpmCc::Commit
                | TpmCc::Rewrap
                | TpmCc::PolicySigned
                | TpmCc::SignDigest
                | TpmCc::VerifyDigestSignature
                | TpmCc::SignSequenceStart
                | TpmCc::VerifySequenceStart
                | TpmCc::SignSequenceComplete
                | TpmCc::VerifySequenceComplete
        )
    } else if handle_index == 1 {
        matches!(
            cc,
            TpmCc::Certify
                | TpmCc::GetSessionAuditDigest
                | TpmCc::GetCommandAuditDigest
                | TpmCc::CertifyCreation
                | TpmCc::ActivateCredential
                | TpmCc::ObjectChangeAuth
                | TpmCc::Duplicate
                | TpmCc::EvictControl
                | TpmCc::EventSequenceComplete
                | TpmCc::Rewrap
                | TpmCc::GetTime
                | TpmCc::SignSequenceComplete
                | TpmCc::VerifySequenceComplete
        )
    } else {
        false
    }
}

/// The unmarshaling error of the handle area of command `cc` in `cmd_buf` (`request_size`
/// bytes), if any: the handles are unmarshaled one after the other, so the first handle that is
/// truncated is `TPM_RC_INSUFFICIENT` at its position, unless an earlier, complete handle is not
/// a value of its interface type (`TPM_RC_VALUE` at that earlier position), as in the C
/// reference `ParseHandleBuffer()`.
///
/// TPM 2.0 Part 3, "Handle Area Validation": "1. The TPM shall successfully unmarshal the number
/// of handles required by the command and validate that the value of the handle is consistent
/// with the command syntax. If not, the TPM shall return `TPM_RC_VALUE`." Running out of octets
/// while unmarshaling a handle is `TPM_RC_INSUFFICIENT` (TPM 2.0 Part 2, "Unmarshaling Errors":
/// "the input buffer did not contain enough octets to allow unmarshaling of the expected data
/// type").
fn handle_area_unmarshal_error(
    cmd_buf: &[u8],
    request_size: usize,
    cc: TpmCc,
    num_handles: usize,
) -> Option<TpmRc> {
    let types = crate::handle_checks::command_handle_types(cc);
    for h_idx in 0..num_handles {
        let pos = Position::handle((h_idx + 1) as u8);
        let at = 10 + 4 * h_idx;
        let Some(bytes) = cmd_buf.get(at..at + 4).filter(|_| request_size >= at + 4) else {
            return Some(TpmRc::INSUFFICIENT.with(pos));
        };
        let handle = Handle(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
        if let Some(&ty) = types.get(h_idx)
            && let Err(rc) = crate::handle_checks::check(handle, ty, pos)
        {
            return Some(rc);
        }
    }
    None
}

/// Returns `TPM_RC_REFERENCE_H0 + h_idx`, the error for a handle that does not reference a
/// loaded entity (`EntityGetLoadStatus`).
fn reference_h(h_idx: usize) -> TpmRc {
    match h_idx {
        0 => TpmRc::REFERENCE_H0,
        1 => TpmRc::REFERENCE_H1,
        _ => TpmRc::REFERENCE_H2,
    }
}

/// The sessions of a command's session area with the `decrypt`, `encrypt` and `audit` roles
/// (indexes into the session area), collected by `TpmEngine::validate_session`.
#[derive(Clone, Copy, Debug, Default)]
struct SessionRoles {
    /// The session with the `decrypt` attribute.
    decrypt: Option<usize>,
    /// The session with the `encrypt` attribute.
    encrypt: Option<usize>,
    /// The session with the `audit` attribute.
    audit: Option<usize>,
}

/// Validates a session handle of the handle area (`TPMI_SH_HMAC` / `TPMI_SH_POLICY` /
/// `TPMI_DH_CONTEXT` unmarshaling followed by `EntityGetLoadStatus`): the handle must lie within
/// the session handle range (`TPM_RC_VALUE`), its slot must hold a loaded session
/// (`TPM_RC_REFERENCE_H0 + h_idx`), and that session must be of the type named by the handle
/// (`TPM_RC_HANDLE`).
fn check_session_handle_status<P: Platform>(
    global_state: &State<P>,
    handle: u32,
    h_idx: usize,
    is_policy: bool,
) -> Result<(), TpmRc> {
    let pos = Position::handle((h_idx + 1) as u8);
    if (handle & 0x00FF_FFFF) as usize >= MAX_ACTIVE_SESSIONS {
        return Err(TpmRc::VALUE.with(pos));
    }
    let Some(session) = global_state.session_by_slot(handle) else {
        return Err(reference_h(h_idx));
    };
    if (session.session_handle >> 24 == 0x03) != is_policy {
        return Err(TpmRc::HANDLE.with(pos));
    }
    Ok(())
}

fn is_expected_session_handle(cc: TpmCc, handle_index: usize) -> bool {
    expects_context_handle(cc, handle_index)
        || expects_policy_session_handle(cc, handle_index)
        || (cc == TpmCc::GetSessionAuditDigest && handle_index == 2)
}

fn expects_context_handle(cc: TpmCc, handle_index: usize) -> bool {
    cc == TpmCc::ContextSave && handle_index == 0
}

fn expects_policy_session_handle(cc: TpmCc, handle_index: usize) -> bool {
    match cc {
        TpmCc::PolicySigned | TpmCc::PolicySecret => handle_index == 1,
        TpmCc::PolicyNV | TpmCc::PolicyAuthorizeNV => handle_index == 2,
        TpmCc::PolicyAuthValue
        | TpmCc::PolicyPassword
        | TpmCc::PolicyGetDigest
        | TpmCc::PolicyDuplicationSelect
        | TpmCc::PolicyPCR
        | TpmCc::PolicyAuthorize
        | TpmCc::PolicyCommandCode
        | TpmCc::PolicyCounterTimer
        | TpmCc::PolicyCpHash
        | TpmCc::PolicyLocality
        | TpmCc::PolicyNameHash
        | TpmCc::PolicyNvWritten
        | TpmCc::PolicyOR
        | TpmCc::PolicyRestart
        | TpmCc::PolicyTemplate
        | TpmCc::PolicyTicket
        | TpmCc::PolicyPhysicalPresence
        | TpmCc::PolicyACSendSelect
        | TpmCc::PolicyCapability
        | TpmCc::PolicyParameters
        | TpmCc::PolicyTransportSPDM => handle_index == 0,
        _ => false,
    }
}

/// The authorization role a command requires for one of its handles (C `AUTH_ROLE`, as encoded
/// by the `HANDLE_1_*` / `HANDLE_2_*` attributes in `CommandAttributeData.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthRole {
    /// The handle does not require authorization (`AUTH_NONE`).
    None,
    /// USER role (`AUTH_USER`).
    User,
    /// ADMIN role (`AUTH_ADMIN`): a policy session is required unless the entity is an object
    /// with `adminWithPolicy` clear.
    Admin,
    /// DUP role (`AUTH_DUP`): a policy session is always required.
    Dup,
}

/// Returns the authorization role `cc` requires for its handle at `handle_index` (C
/// `CommandAuthRole()`).
pub(crate) fn command_auth_role(cc: TpmCc, handle_index: usize) -> AuthRole {
    if !handle_requires_auth(cc, handle_index) {
        return AuthRole::None;
    }
    match (cc, handle_index) {
        (TpmCc::Duplicate, 0) => AuthRole::Dup,
        (
            TpmCc::Certify
            | TpmCc::ActivateCredential
            | TpmCc::ObjectChangeAuth
            | TpmCc::NVChangeAuth
            | TpmCc::NVUndefineSpaceSpecial,
            0,
        ) => AuthRole::Admin,
        _ => AuthRole::User,
    }
}

/// Returns whether `cc` modifies the NV Index it authorizes (C `IsWriteOperation()`), which
/// selects `TPMA_NV_AUTHWRITE`/`TPMA_NV_POLICYWRITE` instead of the READ attributes when an NV
/// Index authorizes itself.
pub(crate) fn is_nv_write_operation(cc: TpmCc) -> bool {
    matches!(
        cc,
        TpmCc::NVWrite
            | TpmCc::NVIncrement
            | TpmCc::NVSetBits
            | TpmCc::NVExtend
            | TpmCc::NVWriteLock
    )
}

/// Returns whether `cc` requires authorization for its handle at `handle_index` (C
/// `CommandAuthRole() != AUTH_NONE`, from the `HANDLE_1_*` / `HANDLE_2_*` attributes in
/// `CommandAttributeData.h`).
pub fn handle_requires_auth(cc: TpmCc, handle_index: usize) -> bool {
    if handle_index == 0 {
        matches!(
            cc,
            TpmCc::HierarchyChangeAuth
                | TpmCc::HierarchyControl
                | TpmCc::SetPrimaryPolicy
                | TpmCc::PCRExtend
                | TpmCc::PCREvent
                | TpmCc::PCRReset
                | TpmCc::PCRSetAuthPolicy
                | TpmCc::PCRSetAuthValue
                | TpmCc::PCRAllocate
                | TpmCc::Clear
                | TpmCc::ClearControl
                | TpmCc::ChangePPS
                | TpmCc::ChangeEPS
                | TpmCc::EvictControl
                | TpmCc::CreatePrimary
                | TpmCc::CreateLoaded
                | TpmCc::GetTime
                | TpmCc::ClockSet
                | TpmCc::ClockRateAdjust
                | TpmCc::ACTSetTimeout
                | TpmCc::Commit
                | TpmCc::Sign
                | TpmCc::RSADecrypt
                | TpmCc::Decapsulate
                | TpmCc::ECDHZGen
                | TpmCc::ZGen2Phase
                | TpmCc::ECCDecrypt
                | TpmCc::MAC
                | TpmCc::NVDefineSpace
                | TpmCc::NVDefineSpace2
                | TpmCc::ReadOnlyControl
                | TpmCc::NVUndefineSpace
                | TpmCc::NVUndefineSpaceSpecial
                | TpmCc::Certify
                | TpmCc::Quote
                | TpmCc::GetSessionAuditDigest
                | TpmCc::GetCommandAuditDigest
                | TpmCc::SetCommandCodeAuditStatus
                | TpmCc::CertifyCreation
                | TpmCc::NVWrite
                | TpmCc::NVCertify
                | TpmCc::NVRead
                | TpmCc::NVIncrement
                | TpmCc::NVExtend
                | TpmCc::NVSetBits
                | TpmCc::NVChangeAuth
                | TpmCc::NVWriteLock
                | TpmCc::NVGlobalWriteLock
                | TpmCc::NVReadLock
                | TpmCc::Duplicate
                | TpmCc::Import
                | TpmCc::Rewrap
                | TpmCc::EncryptDecrypt
                | TpmCc::EncryptDecrypt2
                | TpmCc::Load
                | TpmCc::Unseal
                | TpmCc::ObjectChangeAuth
                | TpmCc::ActivateCredential
                | TpmCc::PolicySecret
                | TpmCc::PolicyNV
                | TpmCc::Create
                | TpmCc::PolicyAuthorizeNV
                | TpmCc::SequenceUpdate
                | TpmCc::SequenceComplete
                | TpmCc::EventSequenceComplete
                | TpmCc::MACStart
                | TpmCc::DictionaryAttackLockReset
                | TpmCc::DictionaryAttackParameters
                | TpmCc::PPCommands
                | TpmCc::SetAlgorithmSet
                | TpmCc::SignDigest
                | TpmCc::SignSequenceComplete
                | TpmCc::VerifySequenceComplete
        )
    } else if handle_index == 1 {
        matches!(
            cc,
            TpmCc::GetTime
                | TpmCc::Certify
                | TpmCc::GetSessionAuditDigest
                | TpmCc::GetCommandAuditDigest
                | TpmCc::NVCertify
                | TpmCc::ActivateCredential
                | TpmCc::EventSequenceComplete
                | TpmCc::NVUndefineSpaceSpecial
                | TpmCc::SignSequenceComplete
        )
    } else {
        false
    }
}

fn compute_hash_and_hmac(
    crypto: &crate::self_test::Tested<'_, impl Crypto>,
    auth_hash: TpmiAlgHash,
    key: &[u8],
    updates_hash: &[&[u8]],
    updates_hmac: &[&[u8]],
    hash_out: &mut [u8],
    hmac_out: &mut [u8],
) -> Result<(usize, usize), TpmRc> {
    let mut hash_ctx = crypto
        .hash_stream(auth_hash)
        .map_err(|_| TpmRc::HASH.to_rc())?;
    for data in updates_hash {
        hash_ctx.update(data).map_err(|_| TpmRc::HASH.to_rc())?;
    }
    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = hash_ctx
        .finalize(&mut digest_buf)
        .map_err(|_| TpmRc::HASH.to_rc())?;
    let digest_slice = digest.digest();

    let mut hmac_state = crypto
        .hmac_stream(auth_hash, key)
        .map_err(|_| TpmRc::HASH.to_rc())?;
    hmac_state
        .update(digest_slice)
        .map_err(|_| TpmRc::HASH.to_rc())?;
    for data in updates_hmac {
        hmac_state.update(data).map_err(|_| TpmRc::HASH.to_rc())?;
    }
    let mut hmac_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let hmac_digest = hmac_state
        .finalize(&mut hmac_buf)
        .map_err(|_| TpmRc::HASH.to_rc())?;
    let hmac_slice = hmac_digest.digest();

    let h_len = digest_slice.len();
    hash_out[..h_len].copy_from_slice(digest_slice);
    let hm_len = hmac_slice.len();
    hmac_out[..hm_len].copy_from_slice(hmac_slice);
    Ok((h_len, hm_len))
}

#[allow(clippy::too_many_arguments)]
fn derive_key_and_iv(
    crypto: &crate::self_test::Tested<'_, impl Crypto>,
    auth_hash: TpmiAlgHash,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    key_size_bytes: usize,
    derived_key_out: &mut [u8],
    derived_iv_out: &mut [u8; 16],
) -> Result<(), TpmRc> {
    let total_bytes = key_size_bytes + 16;
    if total_bytes > 128 {
        return Err(TpmRc::HASH.to_rc());
    }
    let total_bits = (total_bytes * 8) as u32;
    let mut out_buffer = [0u8; 128];

    // `kdfa_bits` keeps exp's KDFa semantics (raw byte label, explicit `bits`), so the derived
    // key and IV are byte-identical to exp's `kdf::kdfa`.
    kdfa_bits(
        crypto,
        auth_hash,
        key,
        label,
        context_u,
        context_v,
        total_bits,
        &mut out_buffer[..total_bytes],
    )
    .map_err(|_| TpmRc::HASH.to_rc())?;

    derived_key_out[..key_size_bytes].copy_from_slice(&out_buffer[..key_size_bytes]);
    derived_iv_out.copy_from_slice(&out_buffer[key_size_bytes..total_bytes]);
    Ok(())
}

/// Returns `TPM_RC_REFERENCE_S0 + session_index`: the session at `session_index` (0-based) in the
/// session area references a session that is not loaded.
fn reference_s(session_index: usize) -> TpmRc {
    match session_index {
        0 => TpmRc::REFERENCE_S0,
        1 => TpmRc::REFERENCE_S1,
        _ => TpmRc::REFERENCE_S2,
    }
}

fn xor_obfuscation(
    crypto: &crate::self_test::Tested<'_, impl Crypto>,
    auth_hash: TpmiAlgHash,
    key: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    data: &mut [u8],
) -> Result<(), TpmRc> {
    let data_len = data.len();
    if data_len == 0 {
        return Ok(());
    }
    let total_bits = (data_len * 8) as u32;
    // The reference's `CryptParameterDecryption()` bounds the ciphertext only by the command
    // ("if(cipherSize > MAX_COMMAND_SIZE || bufferSize <= 0 || (UINT32)cipherSize >
    // (UINT32)bufferSize) return TPM_RC_SIZE;", checked by the caller with the session's
    // position), and TPM 2.0 Part 1, "XOR Parameter Obfuscation", obfuscates "a variable sized
    // buffer containing the parameter to be obfuscated" with "The obfuscated size of parameter
    // is the same as the size of the underlying parameter." So the mask covers a whole
    // command; a parameter that long is then rejected (or not) by its own unmarshaling, e.g.
    // `TPM2B_PRIVATE` → TPM_RC_SIZE + P1.
    let mut mask = [0u8; MAX_COMMAND_SIZE];
    if data_len > mask.len() {
        return Err(TpmRc::SIZE.to_rc());
    }
    let mask_buf = &mut mask[..data_len];
    // `kdfa_bits` keeps exp's KDFa semantics (raw byte label, explicit `bits`).
    kdfa_bits(
        crypto, auth_hash, key, b"XOR", context_u, context_v, total_bits, mask_buf,
    )
    .map_err(|_| TpmRc::HASH.to_rc())?;
    for (d, m) in data.iter_mut().zip(mask_buf.iter()) {
        *d ^= *m;
    }
    Ok(())
}

fn compute_hash(
    crypto: &crate::self_test::Tested<'_, impl Crypto>,
    auth_hash: TpmiAlgHash,
    data: &[u8],
    hash_out: &mut [u8],
) -> Result<usize, TpmRc> {
    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = crypto
        .hash(auth_hash, &[data], &mut digest_buf)
        .map_err(|_| TpmRc::HASH.to_rc())?;
    let slice = digest.digest();
    let len = slice.len();
    hash_out[..len].copy_from_slice(slice);
    Ok(len)
}

/// Hashes the concatenation of `parts` with `auth_hash` into `hash_out`, returning the digest
/// size.
fn compute_hash_parts(
    crypto: &crate::self_test::Tested<'_, impl Crypto>,
    auth_hash: TpmiAlgHash,
    parts: &[&[u8]],
    hash_out: &mut [u8],
) -> Result<usize, TpmRc> {
    let mut hash_ctx = crypto
        .hash_stream(auth_hash)
        .map_err(|_| TpmRc::HASH.to_rc())?;
    for data in parts {
        hash_ctx.update(data).map_err(|_| TpmRc::HASH.to_rc())?;
    }
    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = hash_ctx
        .finalize(&mut digest_buf)
        .map_err(|_| TpmRc::HASH.to_rc())?;
    let slice = digest.digest();
    hash_out[..slice.len()].copy_from_slice(slice);
    Ok(slice.len())
}

fn compute_response_hmac(
    crypto: &crate::self_test::Tested<'_, impl Crypto>,
    auth_hash: TpmiAlgHash,
    key: &[u8],
    updates_hmac: &[&[u8]],
    hmac_out: &mut [u8],
) -> Result<usize, TpmRc> {
    let mut hmac_state = crypto
        .hmac_stream(auth_hash, key)
        .map_err(|_| TpmRc::HASH.to_rc())?;
    for data in updates_hmac {
        hmac_state.update(data).map_err(|_| TpmRc::HASH.to_rc())?;
    }
    let mut hmac_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let hmac_digest = hmac_state
        .finalize(&mut hmac_buf)
        .map_err(|_| TpmRc::HASH.to_rc())?;
    let slice = hmac_digest.digest();
    let len = slice.len();
    hmac_out[..len].copy_from_slice(slice);
    Ok(len)
}

pub fn command_returns_handle(cc: TpmCc) -> bool {
    matches!(
        cc,
        TpmCc::CreatePrimary
            | TpmCc::CreateLoaded
            | TpmCc::StartAuthSession
            | TpmCc::ContextLoad
            | TpmCc::Load
            | TpmCc::LoadExternal
            | TpmCc::HashSequenceStart
            | TpmCc::MACStart
            | TpmCc::SignSequenceStart
            | TpmCc::VerifySequenceStart
    )
}

pub(crate) fn infer_alg_from_digest_size(size: usize) -> Option<tpm2::TpmiAlgHash> {
    match size {
        20 => Some(tpm2::TpmiAlgHash::Sha1),
        32 => Some(tpm2::TpmiAlgHash::Sha256),
        48 => Some(tpm2::TpmiAlgHash::Sha384),
        64 => crate::handler::capability::sha512(),
        _ => None,
    }
}

pub(crate) fn digest_to_tpmt_ha<'a>(
    alg: tpm2::TpmiAlgHash,
    digest: &'a OwnedDigest,
) -> tpm2::TpmtHa<'a> {
    let slice = digest.get_buffer();
    tpm2::TpmtHa::new(alg, &slice[..alg.digest_size()])
        .expect("the digest length always matches its hash algorithm")
}

fn is_pcr_allocated(
    pcr_allocation: &tpm2::TpmlPcrSelection,
    hash_alg: tpm2::TpmiAlgHash,
    pcr: u32,
) -> bool {
    let byte_idx = (pcr / 8) as usize;
    let bit_idx = (pcr % 8) as usize;
    for sel in pcr_allocation.pcr_selections() {
        if sel.hash() == hash_alg {
            if byte_idx < sel.sizeof_select() as usize {
                return (sel.pcr_select()[byte_idx] & (1 << bit_idx)) != 0;
            }
            return false;
        }
    }
    false
}
