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
//!    - **[TpmEngine]**: The root orchestrator that wraps [TpmPlatform](lib.rs) (the platform dependencies: crypto, storage, timer, RNG) and [GlobalState].
//!    - **[GlobalState]**: Holds the volatile and persistent state of the TPM (e.g., loaded transient keys, active authorization/policy sessions, PCR tables, and execution flags).
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
use crate::TpmPlatform;
use crate::handler::CommandHandler;
use crate::handler::{SessionState, TransientObject};
use crate::owned::{
    OwnedAuth, OwnedAuthCommand, OwnedDigest, OwnedName, OwnedNonce, OwnedPublic,
    OwnedSensitiveData,
};
use crate::req_resp::RequestResponseCursor;
use crate::storage::manager::StorageManager;
use crate::storage::{NvStorage, Tpm2Storage};
use crate::timer::TpmTimer;
use tpm2::crypto::kdf::kdfa;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::platform::PcrState;
use tpm2::{CommandHeader, Handle, ResponseHeader, TpmCc, TpmHt, TpmSe, TpmSt};
use tpm2::{Marshal, Unmarshal};
use tpm2::{
    Tpm2bAuth, Tpm2bNonce, TpmaSession, TpmiAlgHash, TpmiAlgSymMode, TpmiStCommandTag,
    TpmsAuthCommand, TpmsAuthResponse,
};

#[allow(clippy::large_enum_variant)]
/// The object that processes incoming TPM requests and produces the corresponding TPM response.
#[non_exhaustive]
pub struct TpmEngine<'a, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync> {
    pub platform: TpmPlatform<'a, C, S, T, R>,
}

/// Maximum number of loaded transient objects in RAM.
pub const MAX_LOADED_OBJECTS: usize = tpm2::TPM2_MAX_LOADED_OBJECTS as usize;
/// Maximum number of active authorization sessions in RAM (aligns with TCG PC Client spec & ms-tpm-20-ref).
pub const MAX_LOADED_SESSIONS: usize = 3;
/// Maximum number of active (loaded or saved) authorization sessions (`MAX_ACTIVE_SESSIONS`); the
/// low 24 bits of a session handle index this many session slots.
pub const MAX_ACTIVE_SESSIONS: usize = tpm2::TPM2_MAX_ACTIVE_SESSIONS as usize;
/// `MAX_CONTEXT_GAP` of the C reference with a 16-bit `CONTEXT_SLOT`: the largest permitted
/// distance between the current session context counter and the sequence number of a saved
/// session context (also reported as `TPM_PT_CONTEXT_GAP_MAX + 1`).
pub const MAX_CONTEXT_GAP: u64 = 0x1_0000;
/// Maximum number of active hash/HMAC sequences in RAM.
pub const MAX_ACTIVE_SEQUENCES: usize = 3;
/// Maximum sequence buffer size per active sequence.
pub const MAX_SEQUENCE_BUFFER: usize = 4096;

/// Largest command accepted by `TpmEngine::execute_command` (`MAX_COMMAND_SIZE`; the value
/// reported for `TPM_PT_MAX_COMMAND_SIZE`). Larger commands fail with `TPM_RC_COMMAND_SIZE`.
pub(crate) const MAX_COMMAND_SIZE: usize = 4096;

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
    pub fn instantiate<R: tpm2::crypto::Rng>(&mut self, rng: &R) -> Result<(), TpmRc> {
        self.magic = DRBG_MAGIC;
        self.reseed_counter = 1;
        rng.get_random(&mut self.seed).map_err(|_| TpmRc::FAILURE)?;
        let mut last_bytes = [0u8; 16];
        rng.get_random(&mut last_bytes)
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
    pub fn reseed<R: tpm2::crypto::Rng>(&mut self, rng: &R) -> Result<(), TpmRc> {
        let mut entropy = [0u8; 48];
        rng.get_random(&mut entropy).map_err(|_| TpmRc::FAILURE)?;
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

/// Represents the global state of the TPM.
/// This includes configuration flags, counters, hierarchy states, and other internal
/// values that persist across commands or power cycles.
#[derive(Debug, Clone)]
pub struct GlobalState {
    /// Indicates whether the TPM has been initialized (e.g., via TPM2_Startup).
    pub initialized: bool,
    /// Indicates if the TPM state was orderly saved before shutdown.
    pub state_saved: bool,
    /// Internal SP800-90A CTR_DRBG state (`go.drbgState`) preserved across orderly shutdowns.
    pub drbg_state: DrbgState,
    /// A counter that increments upon every TPM reset (TPM_PT_RESET_COUNT).
    pub reset_count: u32,
    /// A counter that increments upon every TPM restart (TPM_PT_RESTART_COUNT).
    pub restart_count: u32,
    /// A counter that increments upon every TPM clear operation (TPM_PT_CLEAR_COUNT).
    pub clear_count: u32,
    /// A random nonce that acts as an epoch identifier for the current continuous clock period.
    pub time_epoch: u64,
    /// The current locality of the TPM, used to enforce locality-based access controls.
    pub locality: u8,
    /// Indicates whether the Non-Volatile (NV) memory is available for read/write operations.
    pub nv_available: bool,
    /// Indicates if the internal NV state is verified and OK.
    pub g_nv_ok: bool,
    /// Represents the orderly state of the TPM (e.g., TPM_SU_CLEAR, TPM_SU_STATE).
    pub orderly_state: u16,
    /// Orderly state of the previous power cycle as seen by the last `TPM2_Startup`, with the
    /// startup modifier flags removed (`g_prevOrderlyState`); `SU_NONE_VALUE` (0xFFFF) if the
    /// previous shutdown was not orderly.
    pub prev_orderly_state: u16,
    /// Flag indicating if NV should be updated at the end of a command (`g_updateNV`: `UT_NONE`, `UT_NV`, `UT_ORDERLY`).
    pub update_nv: u8,
    /// Flag indicating if command execution should cause the orderly state to be cleared (`g_clearOrderly`).
    pub clear_orderly: bool,
    /// The total number of resets across the entire lifetime of the TPM.
    pub total_reset_count: u64,
    /// Flag indicating whether the TPM is in a DRTM (Dynamic Root of Trust for Measurement) pre-startup state.
    pub drtm_pre_startup: bool,
    /// Tracks the transient handle of the active hash sequence being used for the DRTM/H-CRTM at Locality 4 (`g_DRTMHandle`).
    pub drtm_handle: u32,
    /// Flag indicating whether the TPM startup occurred at locality 3.
    pub startup_locality_3: bool,
    /// Flag indicating if Dictionary Attack (DA) mitigation logic is currently active.
    pub da_used: bool,
    /// Tracks the identifier for the object context.
    pub object_context_id: u32,
    /// Flag indicating if the TPM detected a power loss without an orderly shutdown.
    pub power_was_lost: bool,
    /// If true, the TPM2_Clear command is disabled.
    pub disable_clear: bool,
    /// Flag indicating whether the Storage Hierarchy is enabled.
    pub sh_enable: bool,
    /// Flag indicating whether the Endorsement Hierarchy is enabled.
    pub eh_enable: bool,
    /// Flag indicating whether the Platform Hierarchy NV operations are enabled.
    pub ph_enable_nv: bool,
    /// Flag indicating whether the Platform Hierarchy is enabled.
    pub ph_enable: bool,
    /// Indicates whether the Non-Volatile (NV) memory is locked against certain operations.
    pub nv_locked: bool,
    /// The proof value for the Storage Hierarchy.
    pub sh_proof: [u8; 64],
    /// The proof value for the Endorsement Hierarchy.
    pub eh_proof: [u8; 64],
    /// The proof value for the Platform Hierarchy.
    pub ph_proof: [u8; 64],
    /// The seed value used for the Storage Primary Seed (SPS).
    pub sp_seed: [u8; 64],
    /// The seed value used for the Platform Primary Seed (PPS).
    pub pp_seed: [u8; 64],
    /// The seed value used for the Endorsement Primary Seed (EPS).
    pub ep_seed: [u8; 64],
    /// The actual length of the Storage Hierarchy proof.
    pub sh_proof_size: u16,
    /// The actual length of the Endorsement Hierarchy proof.
    pub eh_proof_size: u16,
    /// The actual length of the Platform Hierarchy proof.
    pub ph_proof_size: u16,
    /// The actual length of the Storage Primary Seed.
    pub sp_seed_size: u16,
    /// The actual length of the Platform Primary Seed.
    pub pp_seed_size: u16,
    /// The actual length of the Endorsement Primary Seed.
    pub ep_seed_size: u16,
    /// The seed value used for the Null Hierarchy.
    pub null_seed: [u8; 64],
    /// The actual length of the Null Hierarchy seed.
    pub null_seed_size: u16,
    /// The proof value for the Null Hierarchy.
    pub null_proof: [u8; 64],
    /// The actual length of the Null Hierarchy proof.
    pub null_proof_size: u16,
    /// An array holding the currently loaded transient objects.
    pub transient_objects: [Option<TransientObject>; MAX_LOADED_OBJECTS],
    /// An array tracking the parent handle for each transient object slot.
    pub transient_parents: [Option<u32>; MAX_LOADED_OBJECTS],
    /// An array holding the active authorization sessions.
    pub active_sessions: [Option<SessionState>; MAX_LOADED_SESSIONS],
    /// Handles of the sessions whose context has been saved (and that are neither flushed nor
    /// loaded again), indexed by session slot (`handle & 0x00FF_FFFF`). Together with
    /// [`GlobalState::saved_session_sequences`] this is the saved part of `gr.contextArray`.
    pub saved_sessions: [Option<u32>; MAX_ACTIVE_SESSIONS],
    /// Context sequence number (`TPMS_CONTEXT.sequence`) of the latest `TPM2_ContextSave` of
    /// the session in each slot of [`GlobalState::saved_sessions`]. Only that context may be
    /// loaded again (`SequenceNumberForSavedContextIsValid`).
    pub saved_session_sequences: [u64; MAX_ACTIVE_SESSIONS],
    /// An array holding the active hash sequences.
    pub active_sequences: [Option<ActiveSequence>; MAX_ACTIVE_SEQUENCES],
    /// A counter used to generate the next transient handle index.
    pub next_transient_index: u32,
    /// The authorization value for the Owner (Storage) Hierarchy.
    pub owner_auth: OwnedAuth,
    /// The authorization value for the Endorsement Hierarchy.
    pub endorsement_auth: OwnedAuth,
    /// The authorization value for the Platform Hierarchy.
    pub platform_auth: OwnedAuth,
    /// The authorization value for the Lockout Hierarchy.
    pub lockout_auth: OwnedAuth,
    /// Vendor-specific platform unique details (`g_platformUniqueDetails` / `g_platformUniqueAuth`).
    /// Stores device-unique secrets and vendor-permanent data referenced by `VENDOR_PERMANENT` (`TPM_RH_AUTH_00`).
    pub platform_unique_details: OwnedAuth,
    /// The authorization policy for the Owner (Storage) Hierarchy.
    pub owner_policy: OwnedDigest,
    /// The authorization policy for the Endorsement Hierarchy.
    pub endorsement_policy: OwnedDigest,
    /// The authorization policy for the Platform Hierarchy.
    pub platform_policy: OwnedDigest,
    /// The authorization policy for the Lockout Hierarchy.
    pub lockout_policy: OwnedDigest,
    /// The hash algorithm used when setting the Owner policy.
    pub owner_alg: Option<tpm2::TpmiAlgHash>,
    /// The hash algorithm used when setting the Endorsement policy.
    pub endorsement_alg: Option<tpm2::TpmiAlgHash>,
    /// The hash algorithm used when setting the Platform policy.
    pub platform_alg: Option<tpm2::TpmiAlgHash>,
    /// The hash algorithm used when setting the Lockout policy.
    pub lockout_alg: Option<tpm2::TpmiAlgHash>,
    /// List of algorithms that have not yet undergone self-testing.
    pub untested_algorithms: [tpm2::Alg; 32],
    /// Number of valid entries in `untested_algorithms`.
    pub untested_algorithms_len: usize,
    /// Counter tracking the number of failed authorization attempts (`failedTries`).
    pub failed_tries: u32,
    /// Count of authorization failures before the lockout is imposed (`maxTries`).
    pub max_tries: u32,
    /// Time in seconds before the authorization failure count is automatically decremented (`recoveryTime`).
    pub recovery_time: u32,
    /// Time in seconds after a lockoutAuth failure before use of lockoutAuth is allowed (`lockoutRecovery`).
    pub lockout_recovery: u32,
    /// Accumulated TPM uptime in milliseconds (`g_time` / `go.time` in C reference).
    pub tpm_time_ms: u64,
    /// Transient snapshot of the last platform timer read in milliseconds, used to compute elapsed delta.
    pub last_timer_read_ms: Option<u64>,
    /// Timestamp in `tpm_time_ms` ticks (signed for startup offset adjustment) tracking `failed_tries` self-healing (`s_selfHealTimer` / `go.selfHealTimer`).
    pub self_heal_timer: i64,
    /// Timestamp in `tpm_time_ms` ticks (signed for startup offset adjustment) tracking `lockoutAuth` recovery (`s_lockoutTimer` / `go.lockoutTimer`).
    pub lockout_timer: i64,
    /// Flag indicating whether use of `TPM_RH_LOCKOUT` authorization is enabled (`gp.lockOutAuthEnabled`).
    pub lockout_auth_enabled: bool,
    /// Flag indicating whether Dictionary Attack failure parameters (`failed_tries` or `lockout_auth_enabled`)
    /// were updated in RAM while NV storage was unavailable (`s_DAPendingOnNV` in `ibmswtpm2`).
    pub da_pending_on_nv: bool,
    /// Tracks the highest monotonic NV counter value ever allocated or incremented across the lifetime
    /// of the TPM (`s_maxCounter` in `ibmswtpm2`).
    pub max_counter: u64,
    /// A counter tracking the number of times TPM2_Commit has been executed.
    pub commit_counter: u16,
    /// Bitmap of outstanding commitments (`gr.commitArray`). Bit `count & COMMIT_INDEX_MASK` is
    /// set by TPM2_Commit and cleared once an ECDAA signature consumes the commitment, so each
    /// committed `r` can be used for at most one signature.
    pub commit_array: [u8; 16],
    /// A secret nonce used to derive commit scalars (`r`) deterministically via KDFa per `CryptGenerateR`.
    pub commit_nonce: [u8; 64],
    /// The X coordinate of the point committed during the last TPM2_Commit (`E` if `P1` was present, else `L`).
    /// Sized for the largest supported curve (NIST P-521, 66 bytes).
    pub commit_x: [u8; 66],
    /// The P1 point passed to the last TPM2_Commit (`x || y`), if any. Sized for NIST P-521.
    pub commit_p1: [u8; 132],
    pub debug_expected_auth: [u8; 64],
    pub debug_expected_auth_len: usize,
    pub debug_provided_auth: [u8; 64],
    pub debug_provided_auth_len: usize,
    /// A sequence number used for generating unique context identifiers for saved objects.
    pub context_counter: u64,
    pub object_context_counter: u64,
    /// The parsed authorization sessions from the command header.
    pub parsed_auths: [OwnedAuthCommand; 3],
    /// The number of parsed authorization sessions.
    pub parsed_auths_len: usize,
    /// Flag indicating if the authorization sessions have been validated by the command handler.
    pub sessions_validated_by_handler: bool,
    /// The handle of the session that currently holds the exclusive audit lock, if any.
    pub exclusive_audit_session: Option<u32>,
    /// Indicates whether the TPM is currently executing a shadow command (which bypasses auth checks).
    pub in_shadow_execution: bool,
    /// Offset added to the raw monotonic timer count to get the current TPM clock value (mutated via TPM2_ClockSet).
    pub clock_offset: i64,
    /// Current adjustment to the clock update rate (mutated via TPM2_ClockRateAdjust).
    pub clock_rate_adjust: tpm2::TpmClockAdjust,
    /// Whether the reported `Clock` is known not to have been rolled back (`go.clockSafe`).
    /// Cleared on a startup after an unorderly shutdown (`TimeStartup`) and set again whenever the
    /// clock is written to NV (`TimeClockUpdate`), by `TPM2_Clear`, and at manufacture.
    pub clock_safe: bool,
    /// Cumulative clock-rate divisor applied to elapsed platform time (`s_adjustRate` in the C
    /// platform `Clock.c`); [`CLOCK_NOMINAL`] means no adjustment. Changed by
    /// `TPM2_ClockRateAdjust` within `CLOCK_NOMINAL ± CLOCK_ADJUST_LIMIT`.
    pub clock_adjust_rate: u32,
    /// Sub-millisecond remainder (in units of `1 / CLOCK_NOMINAL` ms) carried between rate-adjusted
    /// time updates so that no time is lost to rounding.
    pub clock_adjust_remainder: u64,
    /// Platform seeds.
    pub seeds: [u8; 32],
    /// PCR state.
    pub pcrs: PcrState,
    /// Per-PCR authorization value for the PCR authorization group (PCRs 20-22, matching `gc.pcrAuthValues`).
    pub pcr_auth_value: OwnedAuth,
    /// Hash algorithm for the PCR policy group (PCRs 20-22, matching `gp.pcrPolicies.hashAlg`).
    pub pcr_policy_alg: Option<tpm2::TpmiAlgHash>,
    /// Policy digest for the PCR policy group (PCRs 20-22, matching `gp.pcrPolicies.policy`).
    pub pcr_policy: OwnedDigest,
    /// Flag indicating that PCR allocation has changed and is pending a reboot.
    pub pcr_reconfig: bool,
    pub audit_counter: u64,
    pub audit_hash_alg: u16,
    pub command_audit_digest: OwnedDigest,
}

#[derive(Debug, Clone)]
pub struct ActiveSequence {
    pub handle: u32,
    pub auth: OwnedAuth,
    pub sequence_type: SequenceType,
    pub sequence_buffer: [u8; MAX_SEQUENCE_BUFFER],
    pub sequence_len: usize,
    pub intermediate_digest: OwnedDigest,
    pub first_bytes: [u8; 4],
    pub first_bytes_len: usize,
    /// Portable streaming hash contexts (`HASH_STATE` parity with `ibmswtpm2`).
    /// For Hash/HMAC sequences, index 0 holds the active hash/inner-HMAC state.
    /// For Event sequences, indices 0..4 hold SHA-1, SHA-256, SHA-384, and SHA-512 states.
    pub hash_states: [crate::hash_state::StreamingHashState; 4],
}

impl ActiveSequence {
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
            SequenceType::Event => {
                hash_states[0] = crate::hash_state::StreamingHashState::new(TpmiAlgHash::Sha1);
                hash_states[1] = crate::hash_state::StreamingHashState::new(TpmiAlgHash::Sha256);
                hash_states[2] = crate::hash_state::StreamingHashState::new(TpmiAlgHash::Sha384);
                hash_states[3] = crate::hash_state::StreamingHashState::new(TpmiAlgHash::Sha512);
            }
        }
        Self {
            handle,
            auth,
            sequence_type,
            sequence_buffer: [0u8; MAX_SEQUENCE_BUFFER],
            sequence_len: 0,
            intermediate_digest: OwnedDigest::default(),
            first_bytes: [0u8; 4],
            first_bytes_len: 0,
            hash_states,
        }
    }

    /// Feeds input data into the active streaming hash state(s).
    pub fn update_hash_states(&mut self, data: &[u8]) {
        match self.sequence_type {
            SequenceType::Hash { .. } | SequenceType::Hmac { .. } => {
                self.hash_states[0].update(data);
            }
            SequenceType::Event => {
                for state in &mut self.hash_states {
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
    Event,
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

pub(crate) const INITIAL_UNTESTED_ALGORITHMS: [tpm2::Alg; 32] = [
    tpm2::Alg::SHA1,
    tpm2::Alg::AES,
    tpm2::Alg::SHA256,
    tpm2::Alg::SHA384,
    tpm2::Alg::SHA512,
    tpm2::Alg::RSASSA,
    tpm2::Alg::RSAES,
    tpm2::Alg::RSAPSS,
    tpm2::Alg::OAEP,
    tpm2::Alg::ECDSA,
    tpm2::Alg::ECDAA,
    tpm2::Alg::ECSCHNORR,
    tpm2::Alg::KDF1_SP800_108,
    tpm2::Alg::CFB,
    tpm2::Alg::RSA,
    tpm2::Alg::ECC,
    tpm2::Alg::KEYEDHASH,
    tpm2::Alg::HMAC,
    tpm2::Alg::NULL,
    tpm2::Alg::NULL,
    tpm2::Alg::NULL,
    tpm2::Alg::NULL,
    tpm2::Alg::NULL,
    tpm2::Alg::NULL,
    tpm2::Alg::NULL,
    tpm2::Alg::NULL,
    tpm2::Alg::NULL,
    tpm2::Alg::NULL,
    tpm2::Alg::NULL,
    tpm2::Alg::NULL,
    tpm2::Alg::NULL,
    tpm2::Alg::NULL,
];

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

/// Marker byte introducing the persistent lifecycle extension of the hierarchy-auth NV blob.
const PERSISTENT_EXT_MARKER: u8 = 0xBB;
/// Length of the persistent lifecycle extension (marker + disableClear + lockOutAuthEnabled +
/// maxTries + recoveryTime + lockoutRecovery + clock + clockSafe).
const PERSISTENT_EXT_LEN: usize = 1 + 1 + 1 + 4 + 4 + 4 + 8 + 1;

/// Implementation-specific virtual NV handle holding the `TPM2_Shutdown(TPM_SU_STATE)` data
/// (the equivalent of `NV_STATE_RESET_DATA` / `NV_STATE_CLEAR_DATA`). It only exists between an
/// orderly `TPM_SU_STATE` shutdown and the next `TPM2_Startup`.
const STATE_SAVE_HANDLE: u32 = 0x00FF_FFFE;
/// Marker byte identifying the layout of the saved-state blob.
const STATE_SAVE_MARKER: u8 = 0x5A;
/// Upper bound of the saved-state blob size.
const STATE_SAVE_MAX_LEN: usize = 512 + MAX_ACTIVE_SESSIONS * (1 + 4 + 8);
/// Implementation-specific virtual NV handle holding the NV copy of the PCR bank allocation
/// (`NV_WRITE_PERSISTENT(pcrAllocated, ...)` in `PCRAllocate`). `TPM2_PCR_Allocate` only writes
/// this NV copy; the active (RAM) allocation is replaced by it at the next `_TPM_Init`
/// ([`TpmEngine::reset`]), so a new allocation takes effect after the next TPM Reset.
pub(crate) const PCR_ALLOCATION_HANDLE: u32 = 0x00FF_FFFD;

impl Default for GlobalState {
    fn default() -> Self {
        Self {
            initialized: false,
            state_saved: false,
            drbg_state: DrbgState::default(),
            reset_count: 0,
            restart_count: 0,
            clear_count: 0,
            time_epoch: 0,
            locality: 0,
            nv_available: true,
            g_nv_ok: false,
            orderly_state: 0,
            prev_orderly_state: 0xFFFF,
            update_nv: UT_NONE,
            clear_orderly: false,
            total_reset_count: 0,
            drtm_pre_startup: false,
            drtm_handle: Handle::RH_UNASSIGNED.0,
            startup_locality_3: false,
            da_used: false,
            object_context_id: 0,
            power_was_lost: false,
            disable_clear: false,
            sh_enable: true,
            eh_enable: true,
            ph_enable_nv: true,
            ph_enable: true,
            nv_locked: false,
            sh_proof: [0; 64],
            eh_proof: [0; 64],
            ph_proof: [0x55; 64],
            sp_seed: [0; 64],
            pp_seed: [0; 64],
            ep_seed: [0; 64],
            sh_proof_size: 64,
            eh_proof_size: 64,
            ph_proof_size: 64,
            sp_seed_size: 0,
            pp_seed_size: 0,
            ep_seed_size: 0,
            null_seed: [0; 64],
            null_seed_size: 0,
            null_proof: [0; 64],
            null_proof_size: 64,
            transient_objects: [const { None }; MAX_LOADED_OBJECTS],
            transient_parents: [None; MAX_LOADED_OBJECTS],
            active_sessions: [const { None }; MAX_LOADED_SESSIONS],
            saved_sessions: [None; MAX_ACTIVE_SESSIONS],
            saved_session_sequences: [0; MAX_ACTIVE_SESSIONS],
            active_sequences: [const { None }; MAX_ACTIVE_SEQUENCES],
            next_transient_index: 0,
            owner_auth: OwnedAuth::default(),
            endorsement_auth: OwnedAuth::default(),
            platform_auth: OwnedAuth::default(),
            lockout_auth: OwnedAuth::default(),
            platform_unique_details: OwnedAuth::default(),
            owner_policy: OwnedDigest::default(),
            endorsement_policy: OwnedDigest::default(),
            platform_policy: OwnedDigest::default(),
            lockout_policy: OwnedDigest::default(),
            owner_alg: None,
            endorsement_alg: None,
            platform_alg: None,
            lockout_alg: None,
            untested_algorithms: INITIAL_UNTESTED_ALGORITHMS,
            untested_algorithms_len: 18,
            failed_tries: 0,
            max_tries: 3,
            recovery_time: 1000,
            lockout_recovery: 1000,
            tpm_time_ms: 0,
            last_timer_read_ms: None,
            self_heal_timer: 0,
            lockout_timer: 0,
            lockout_auth_enabled: true,
            da_pending_on_nv: false,
            max_counter: 0,
            commit_counter: 0,
            commit_array: [0u8; 16],
            commit_nonce: [0x5a; 64],
            commit_x: [0u8; 66],
            commit_p1: [0u8; 132],
            debug_expected_auth: [0u8; 64],
            debug_expected_auth_len: 0,
            debug_provided_auth: [0u8; 64],
            debug_provided_auth_len: 0,
            context_counter: 0,
            object_context_counter: 0,
            parsed_auths: [
                OwnedAuthCommand::default(),
                OwnedAuthCommand::default(),
                OwnedAuthCommand::default(),
            ],
            parsed_auths_len: 0,
            sessions_validated_by_handler: false,
            exclusive_audit_session: None,
            in_shadow_execution: false,
            clock_offset: 0,
            clock_rate_adjust: tpm2::TpmClockAdjust::NoChange,
            clock_safe: true,
            clock_adjust_rate: CLOCK_NOMINAL,
            clock_adjust_remainder: 0,
            seeds: [0; 32],
            pcrs: PcrState::default(),
            pcr_auth_value: OwnedAuth::default(),
            pcr_policy_alg: None,
            pcr_policy: OwnedDigest::default(),
            pcr_reconfig: false,
            audit_counter: 0,
            audit_hash_alg: tpm2::Alg::SHA256.id(),
            command_audit_digest: OwnedDigest::default(),
        }
    }
}

impl GlobalState {
    pub fn init_zeroed(&mut self) {
        self.total_reset_count = 1;
        self.nv_available = true;
        self.sh_enable = true;
        self.eh_enable = true;
        self.ph_enable_nv = true;
        self.ph_enable = true;
        self.sh_proof_size = 64;
        self.eh_proof_size = 64;
        self.ph_proof = [0x55; 64];
        self.ph_proof_size = 64;
        self.null_proof_size = 64;
        self.failed_tries = 0;
        self.max_tries = 3;
        self.recovery_time = 1000;
        self.lockout_recovery = 1000;
        self.clock_offset = self.clock_offset.wrapping_add(self.tpm_time_ms as i64);
        self.tpm_time_ms = 0;
        self.last_timer_read_ms = None;
        self.self_heal_timer = 0;
        self.lockout_timer = 0;
        self.lockout_auth_enabled = true;
        self.da_pending_on_nv = false;
        self.commit_nonce = [0x5a; 64];
        self.untested_algorithms = INITIAL_UNTESTED_ALGORITHMS;
        self.untested_algorithms_len = 18;
        self.audit_hash_alg = tpm2::Alg::SHA256.id();
    }

    pub fn reset_in_place(&mut self) {
        self.initialized = false;
        self.state_saved = false;
        self.reset_count = 0;
        self.restart_count = 0;
        self.clear_count = 0;
        self.locality = 0;
        self.nv_available = true;
        self.g_nv_ok = false;
        self.orderly_state = 0;
        self.update_nv = UT_NONE;
        self.clear_orderly = false;
        self.drtm_pre_startup = false;
        self.drtm_handle = Handle::RH_UNASSIGNED.0;
        self.startup_locality_3 = false;
        self.da_used = false;
        self.da_pending_on_nv = false;
        self.object_context_id = 0;
        self.power_was_lost = false;
        self.disable_clear = false;
        self.sh_enable = true;
        self.eh_enable = true;
        self.ph_enable_nv = true;
        self.ph_enable = true;
        self.nv_locked = false;
        self.sh_proof = [0; 64];
        self.eh_proof = [0; 64];
        self.ph_proof = [0x55; 64];
        self.sp_seed = [0; 64];
        self.pp_seed = [0; 64];
        self.ep_seed = [0; 64];
        self.sh_proof_size = 64;
        self.eh_proof_size = 64;
        self.ph_proof_size = 64;
        self.sp_seed_size = 0;
        self.pp_seed_size = 0;
        self.ep_seed_size = 0;
        self.null_seed = [0; 64];
        self.null_seed_size = 0;
        self.null_proof = [0; 64];
        self.null_proof_size = 64;
        for obj in self.transient_objects.iter_mut() {
            *obj = None;
        }
        for p in self.transient_parents.iter_mut() {
            *p = None;
        }
        for sess in self.active_sessions.iter_mut() {
            *sess = None;
        }
        for sess in self.saved_sessions.iter_mut() {
            *sess = None;
        }
        self.saved_session_sequences = [0; MAX_ACTIVE_SESSIONS];
        for seq in self.active_sequences.iter_mut() {
            *seq = None;
        }
        self.next_transient_index = 0;
        self.owner_auth = Default::default();
        self.endorsement_auth = Default::default();
        self.platform_auth = Default::default();
        self.lockout_auth = Default::default();
        self.owner_policy = Default::default();
        self.endorsement_policy = Default::default();
        self.platform_policy = Default::default();
        self.lockout_policy = Default::default();
        self.owner_alg = None;
        self.endorsement_alg = None;
        self.platform_alg = None;
        self.lockout_alg = None;
        self.untested_algorithms = INITIAL_UNTESTED_ALGORITHMS;
        self.untested_algorithms_len = 18;
        self.commit_counter = 0;
        self.commit_array = [0u8; 16];
        self.commit_nonce = [0x5a; 64];
        self.commit_x.fill(0);
        self.commit_p1.fill(0);
        self.context_counter = 0;
        self.object_context_counter = 0;
        for auth in self.parsed_auths.iter_mut() {
            *auth = Default::default();
        }
        self.parsed_auths_len = 0;
        self.sessions_validated_by_handler = false;
        self.exclusive_audit_session = None;
        self.in_shadow_execution = false;
        self.clock_rate_adjust = tpm2::TpmClockAdjust::NoChange;
        // The platform clock-rate adjustment is volatile (`_plat__TimerReset`).
        self.clock_adjust_rate = CLOCK_NOMINAL;
        self.clock_adjust_remainder = 0;
        self.audit_hash_alg = tpm2::Alg::SHA256.id();
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
        (slot < MAX_ACTIVE_SESSIONS && self.saved_sessions[slot].is_some()).then_some(slot)
    }

    /// Returns the slot of the oldest saved session context (smallest sequence number), if any
    /// (`s_oldestSavedSession` / `ContextIdSetOldest`).
    pub fn oldest_saved_session_slot(&self) -> Option<usize> {
        (0..MAX_ACTIVE_SESSIONS)
            .filter(|&slot| self.saved_sessions[slot].is_some())
            .min_by_key(|&slot| self.saved_session_sequences[slot])
    }

    /// Returns `true` if the context gap is exhausted: the low 16 bits of the session context
    /// counter (the `CONTEXT_SLOT` value the next save would use) equal those of the oldest
    /// saved session context, so saving another context would make the oldest ambiguous.
    pub fn context_gap_exhausted(&self) -> bool {
        self.oldest_saved_session_slot().is_some_and(|slot| {
            (self.saved_session_sequences[slot] as u16) == (self.context_counter as u16)
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
        let low = self.context_counter as u16 as u64;
        if low <= MAX_LOADED_SESSIONS as u64 {
            self.context_counter += MAX_LOADED_SESSIONS as u64 + 1 - low;
        }
        if self.context_gap_exhausted() {
            return Err(TpmRc::CONTEXT_GAP);
        }
        let sequence = self.context_counter;
        self.context_counter = self
            .context_counter
            .checked_add(1)
            .ok_or(TpmRc::TOO_MANY_CONTEXTS)?;
        if (self.context_counter as u16) == 0 {
            self.context_counter += MAX_LOADED_SESSIONS as u64 + 1;
        }
        self.saved_sessions[slot] = Some(handle);
        self.saved_session_sequences[slot] = sequence;
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
            self.saved_session_sequences[slot] == sequence
                && sequence <= self.context_counter
                && self.context_counter - sequence <= MAX_CONTEXT_GAP
        })
    }

    /// Removes the saved-session record of the slot of `handle` (on load or flush).
    pub fn remove_saved_session(&mut self, handle: u32) {
        if let Some(slot) = self.saved_session_slot(handle) {
            self.saved_sessions[slot] = None;
            self.saved_session_sequences[slot] = 0;
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
        for (i, slot) in self.transient_objects.iter_mut().enumerate() {
            if let Some(obj) = slot
                && obj.handle == handle
            {
                *slot = None;
                self.transient_parents[i] = None;
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

    /// Finds the lowest free transient handle (0x80000000..0x80000003) that is not in use by either
    /// loaded transient objects or active sequences, enforcing the shared `MAX_LOADED_OBJECTS` (`3`)
    /// capacity across transient objects and sequences (`s_objects` parity with `ibmswtpm2`).
    pub fn find_next_transient_handle(&self) -> Result<u32, TpmRc> {
        let total_loaded = self.transient_objects.iter().flatten().count()
            + self.active_sequences.iter().flatten().count();
        if total_loaded >= MAX_LOADED_OBJECTS {
            return Err(TpmRc::OBJECT_MEMORY);
        }
        for i in 0..(MAX_LOADED_OBJECTS as u32) {
            let handle = 0x8000_0000 | i;
            if self.find_transient_object(handle).is_none()
                && self.find_active_sequence(handle).is_none()
            {
                return Ok(handle);
            }
        }
        Err(TpmRc::OBJECT_MEMORY)
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

impl<'a, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync> TpmEngine<'a, C, S, T, R> {
    /// Returns the current adjusted clock value in milliseconds (`go.clock`).
    pub fn get_clock(&self, global_state: &GlobalState) -> u64 {
        // `clock_offset` is the two's-complement difference `Clock - Time`, so wrapping arithmetic
        // yields the exact clock for every value up to `0xFFFF_0000_0000_0000` (`TPM2_ClockSet`).
        global_state
            .tpm_time_ms
            .wrapping_add(global_state.clock_offset as u64)
    }

    /// Returns the current `TpmsClockInfo` structure.
    pub fn get_clock_info(&self, global_state: &GlobalState) -> tpm2::TpmsClockInfo {
        tpm2::TpmsClockInfo {
            clock: self.get_clock(global_state),
            reset_count: global_state.reset_count,
            restart_count: global_state.restart_count,
            // `TimeFillInfo`: the clock is not "safe" while NV is unavailable (it stops advancing).
            safe: global_state.nv_available && global_state.clock_safe,
        }
    }

    /// Returns the current `TpmsTimeInfo` structure (`g_time` and `clock_info`).
    pub fn get_time_info(&self, global_state: &GlobalState) -> tpm2::TpmsTimeInfo {
        tpm2::TpmsTimeInfo {
            time: global_state.tpm_time_ms,
            clock_info: self.get_clock_info(global_state),
        }
    }

    /// Gets the authorization value associated with a handle (either a hierarchy, a transient object, an NV Index, or a persistent object).
    pub fn handle_auth(&mut self, global_state: &GlobalState, handle: u32) -> OwnedAuth {
        if handle == Handle::RH_OWNER.0 {
            global_state.owner_auth
        } else if handle == Handle::RH_ENDORSEMENT.0 {
            global_state.endorsement_auth
        } else if handle == Handle::RH_PLATFORM.0 {
            global_state.platform_auth
        } else if handle == Handle::RH_LOCKOUT.0 {
            global_state.lockout_auth
        } else if handle == Handle::RH_AUTH_00.0 {
            global_state.platform_unique_details
        } else if let Some(seq) = global_state.find_active_sequence(handle) {
            seq.auth
        } else if let Some(obj) = global_state.find_transient_object(handle) {
            obj.auth
        } else if Handle(handle).handle_type() == Some(TpmHt::NVIndex) {
            let storage_mgr = StorageManager::new(&mut *self.platform.storage);
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
            self.load_persistent_object(global_state, handle)
                .map(|obj| obj.auth)
                .unwrap_or_default()
        } else if (20..=22).contains(&handle) {
            global_state.pcr_auth_value
        } else {
            OwnedAuth::default()
        }
    }

    /// Gets the Name associated with a handle.
    pub fn handle_name(&mut self, global_state: &mut GlobalState, handle: u32) -> OwnedName {
        if global_state.find_active_sequence(handle).is_some() {
            return OwnedName::default();
        }
        handle_name(self, &mut *global_state, handle)
    }

    /// Gets the auth policy associated with a handle.
    pub fn handle_policy(
        &mut self,
        global_state: &GlobalState,
        handle: u32,
    ) -> Result<OwnedDigest, TpmRc> {
        if handle == Handle::RH_OWNER.0 {
            return Ok(global_state.owner_policy);
        }
        if handle == Handle::RH_ENDORSEMENT.0 {
            return Ok(global_state.endorsement_policy);
        }
        if handle == Handle::RH_PLATFORM.0 {
            return Ok(global_state.platform_policy);
        }
        if handle == Handle::RH_LOCKOUT.0 {
            return Ok(global_state.lockout_policy);
        }
        if let Some(obj) = global_state.find_transient_object(handle) {
            Ok(obj.public.auth_policy)
        } else if global_state.find_active_sequence(handle).is_some() {
            Ok(Default::default())
        } else if Handle(handle).handle_type() == Some(TpmHt::NVIndex) {
            let storage_mgr = StorageManager::new(&mut *self.platform.storage);
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
            let obj = self.load_persistent_object(global_state, handle)?;
            Ok(obj.public.auth_policy)
        } else if (20..=22).contains(&handle) {
            Ok(global_state.pcr_policy)
        } else {
            Ok(OwnedDigest::default())
        }
    }

    pub fn has_da_protection(&mut self, global_state: &GlobalState, handle: u32) -> bool {
        if handle == Handle::RH_OWNER.0
            || handle == Handle::RH_ENDORSEMENT.0
            || handle == Handle::RH_PLATFORM.0
            || handle == Handle::RH_AUTH_00.0
        {
            return false;
        }
        if handle == Handle::RH_LOCKOUT.0 {
            return true;
        }
        if (0x80000000..=0x80FFFFFF).contains(&handle) {
            if global_state.find_active_sequence(handle).is_some() {
                return false;
            }
            if let Some(obj) = global_state.find_transient_object(handle) {
                return !obj
                    .public
                    .object_attributes
                    .contains(tpm2::TpmaObject::NO_DA);
            }
            return true;
        }
        if (0x81000000..=0x81FFFFFF).contains(&handle) {
            if let Ok(obj) = self.load_persistent_object(global_state, handle) {
                return !obj
                    .public
                    .object_attributes
                    .contains(tpm2::TpmaObject::NO_DA);
            }
            return true;
        }
        if Handle(handle).handle_type() == Some(TpmHt::NVIndex) {
            let storage_mgr = StorageManager::new(&mut *self.platform.storage);
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
    pub(crate) fn check_locked_out(
        &mut self,
        global_state: &mut GlobalState,
        is_lockout_auth: bool,
    ) -> Result<(), TpmRc> {
        if !global_state.nv_available && global_state.orderly_state < 0xFFFE {
            return Err(TpmRc::NV_UNAVAILABLE);
        }
        if global_state.da_pending_on_nv {
            if !global_state.nv_available {
                return Err(TpmRc::NV_UNAVAILABLE);
            }
            let _ = self
                .platform
                .storage
                .write_nv(32, &global_state.failed_tries.to_be_bytes());
            self.save_hierarchy_auths(global_state);
            global_state.da_pending_on_nv = false;
        }
        if is_lockout_auth {
            if !global_state.lockout_auth_enabled {
                return Err(TpmRc::LOCKOUT);
            }
        } else if global_state.failed_tries >= global_state.max_tries {
            return Err(TpmRc::LOCKOUT);
        }
        Ok(())
    }

    pub(crate) fn lookup_transient_object<'b>(
        &self,
        global_state: &'b GlobalState,
        handle: u32,
        pos: Position,
    ) -> Result<&'b TransientObject, TpmRc> {
        if (handle & 0x00FF_FFFF) > 0x0000_FFFF {
            return Err(TpmRc::VALUE.with(pos));
        }
        global_state.find_transient_object(handle).ok_or({
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
    /// object-slot accounting, which [`Self::validate_command_handles`] performs).
    ///
    /// A persistent handle whose hierarchy is disabled looks undefined, as in the C reference:
    /// platform handles (`0x8180_0000..`) need `phEnable`, all others `shEnable`, and objects of
    /// the endorsement hierarchy additionally `ehEnable`. Every failure to find or use the object
    /// is reported as `TPM_RC_HANDLE` (without position); see [`Self::read_persistent_object`]
    /// for an unchecked read.
    pub fn load_persistent_object(
        &mut self,
        global_state: &GlobalState,
        handle: u32,
    ) -> Result<TransientObject, TpmRc> {
        let hierarchy_enabled = if handle >= 0x8180_0000 {
            global_state.ph_enable
        } else {
            global_state.sh_enable
        };
        if !hierarchy_enabled {
            return Err(TpmRc::HANDLE.to_rc());
        }
        let obj = self.read_persistent_object(handle)?;
        if obj.hierarchy == tpm2::Handle::RH_ENDORSEMENT.0 && !global_state.eh_enable {
            return Err(TpmRc::HANDLE.to_rc());
        }
        Ok(obj)
    }

    /// Reads the persistent object `handle` from NV without any hierarchy-enable checks
    /// (`NvGetEvictObject`). Returns `TPM_RC_HANDLE` if it is not defined.
    pub(crate) fn read_persistent_object(&mut self, handle: u32) -> Result<TransientObject, TpmRc> {
        let storage = StorageManager::new(&mut *self.platform.storage);
        let metadata = storage
            .get_metadata(handle)
            .map_err(|_| TpmRc::HANDLE.to_rc())?;
        let mut buf = [0u8; 4096];
        storage
            .read_item(handle, 0, &mut buf[..metadata.data_size as usize])
            .map_err(|_| TpmRc::FAILURE)?;

        let mut slice = &buf[..metadata.data_size as usize];

        // seedValue is stored as a TPM2B (full nameAlg-sized seed, see `persist_transient_object`).
        let seed_value = tpm2::Tpm2bDigest::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let (seed, seed_len) = TransientObject::seed_from_bytes(seed_value.get_buffer());

        let name = OwnedName::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let auth = OwnedAuth::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let public = OwnedPublic::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;

        let priv_len = u16::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)? as usize;
        if slice.len() < priv_len {
            return Err(TpmRc::FAILURE);
        }
        let mut private = [0u8; 1536];
        private[..priv_len].copy_from_slice(&slice[..priv_len]);
        slice = &slice[priv_len..];

        let qualified_name = OwnedName::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let hierarchy = u32::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;

        Ok(TransientObject {
            handle,
            seed,
            seed_len,
            external: false,
            public_only: false,
            name,
            auth,
            public,
            private,
            private_len: priv_len,
            qualified_name,
            hierarchy,
            st_clear: false,
        })
    }

    pub fn init_storage(&mut self, global_state: &mut GlobalState) {
        let seeds = global_state.seeds;
        global_state.sp_seed[..32].copy_from_slice(&seeds);
        global_state.sp_seed_size = 32;
        for (i, &s) in seeds.iter().enumerate() {
            global_state.pp_seed[i] = s ^ 0x50;
            global_state.ep_seed[i] = s ^ 0x45;
        }
        global_state.pp_seed_size = 32;
        global_state.ep_seed_size = 32;
        let mut storage = StorageManager::new(&mut *self.platform.storage);
        let _ = storage.undefine_space(0x00FFFFFF);
        let _ = storage.undefine_space(PCR_ALLOCATION_HANDLE);
        self.save_hierarchy_auths(global_state);
    }

    /// Creates a new [`TpmEngine`] object that processes incoming TPM requests.
    pub fn new(platform: TpmPlatform<'a, C, S, T, R>) -> Result<Self, InternalError> {
        Ok(Self { platform })
    }

    /// Serializes the entire TPM execution state (`GlobalState` + persistent `NvStorage`)
    /// into an [`crate::storage::translator::Ibmswtpm2StateDto`] suitable for live migration.
    pub fn serialize_migration_state(
        &mut self,
        global_state: &GlobalState,
        dto: &mut crate::storage::translator::Ibmswtpm2StateDto,
    ) -> Result<(), crate::storage::StorageError> {
        self.save_hierarchy_auths(global_state);
        crate::storage::translator::TpmStateTranslator::serialize_state(
            global_state,
            &mut *self.platform.storage,
            dto,
        )
    }

    /// Deserializes an [`crate::storage::translator::Ibmswtpm2StateDto`] back into the TPM
    /// execution state (`GlobalState` + persistent `NvStorage`) for live migration restore.
    pub fn unserialize_migration_state(
        &mut self,
        dto: &crate::storage::translator::Ibmswtpm2StateDto,
        global_state: &mut GlobalState,
    ) -> Result<(), crate::storage::StorageError> {
        crate::storage::translator::TpmStateTranslator::unserialize_state(
            dto,
            global_state,
            &mut *self.platform.storage,
        )?;
        self.restore_hierarchy_auths(global_state);
        Ok(())
    }

    pub fn reset(&mut self, global_state: &mut GlobalState) {
        global_state.reset_in_place();
        let seeds = global_state.seeds;
        global_state.sp_seed[..32].copy_from_slice(&seeds);
        global_state.sp_seed_size = 32;
        for (i, &s) in seeds.iter().enumerate() {
            global_state.pp_seed[i] = s ^ 0x50;
            global_state.ep_seed[i] = s ^ 0x45;
        }
        global_state.pp_seed_size = 32;
        global_state.ep_seed_size = 32;
        self.restore_hierarchy_auths(global_state);
        self.restore_persistent_state(global_state);
        self.restore_pcr_allocation(global_state);
    }

    /// Replaces the active PCR allocation with the NV copy written by `TPM2_PCR_Allocate`
    /// ([`PCR_ALLOCATION_HANDLE`]), if one exists. Called at `_TPM_Init`, mirroring the C
    /// reference where `gp.pcrAllocated` is (re)loaded from NV on initialization.
    fn restore_pcr_allocation(&mut self, global_state: &mut GlobalState) {
        let storage = StorageManager::new(&mut *self.platform.storage);
        let Ok(meta) = storage.get_metadata(PCR_ALLOCATION_HANDLE) else {
            return;
        };
        let mut buf = [0u8; tpm2::TpmlPcrSelection::MAX_SIZE];
        let len = meta.data_size as usize;
        if len > buf.len()
            || storage
                .read_item(PCR_ALLOCATION_HANDLE, 0, &mut buf[..len])
                .is_err()
        {
            return;
        }
        let mut slice = &buf[..len];
        if let Ok(allocation) = tpm2::TpmlPcrSelection::unmarshal(&mut slice) {
            global_state.pcrs.pcr_allocation = allocation;
        }
    }

    pub(crate) fn save_hierarchy_auths(&mut self, global_state: &GlobalState) {
        /// Custom reserved handle used as a virtual NV index to store hierarchy authorization values.
        /// This is an implementation-specific value not defined in the TPM 2.0 specification.
        const HIERARCHY_AUTH_HANDLE: u32 = 0x00FFFFFF;
        let mut buf = [0u8; 1152];
        let mut offset = 0;
        if offset + Tpm2bAuth::MAX_SIZE <= buf.len() {
            offset += global_state.owner_auth.marshal(
                (&mut buf[offset..offset + Tpm2bAuth::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
        }
        if offset + Tpm2bAuth::MAX_SIZE <= buf.len() {
            offset += global_state.endorsement_auth.marshal(
                (&mut buf[offset..offset + Tpm2bAuth::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
        }
        if offset + Tpm2bAuth::MAX_SIZE <= buf.len() {
            offset += global_state.platform_auth.marshal(
                (&mut buf[offset..offset + Tpm2bAuth::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
        }
        if offset + Tpm2bAuth::MAX_SIZE <= buf.len() {
            offset += global_state.lockout_auth.marshal(
                (&mut buf[offset..offset + Tpm2bAuth::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
        }
        if offset + tpm2::Tpm2bDigest::MAX_SIZE <= buf.len() {
            offset += global_state.owner_policy.marshal(
                (&mut buf[offset..offset + tpm2::Tpm2bDigest::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
        }
        if offset + tpm2::Tpm2bDigest::MAX_SIZE <= buf.len() {
            offset += global_state.endorsement_policy.marshal(
                (&mut buf[offset..offset + tpm2::Tpm2bDigest::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
        }
        if offset + tpm2::Tpm2bDigest::MAX_SIZE <= buf.len() {
            offset += global_state.platform_policy.marshal(
                (&mut buf[offset..offset + tpm2::Tpm2bDigest::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
        }
        if offset + tpm2::Tpm2bDigest::MAX_SIZE <= buf.len() {
            offset += global_state.lockout_policy.marshal(
                (&mut buf[offset..offset + tpm2::Tpm2bDigest::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
        }
        if offset + TpmiAlgHash::MAX_SIZE <= buf.len() {
            offset += global_state.owner_alg.marshal(
                (&mut buf[offset..offset + TpmiAlgHash::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
        }
        if offset + TpmiAlgHash::MAX_SIZE <= buf.len() {
            offset += global_state.endorsement_alg.marshal(
                (&mut buf[offset..offset + TpmiAlgHash::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
        }
        if offset + TpmiAlgHash::MAX_SIZE <= buf.len() {
            offset += global_state.platform_alg.marshal(
                (&mut buf[offset..offset + TpmiAlgHash::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
        }
        if offset + TpmiAlgHash::MAX_SIZE <= buf.len() {
            offset += global_state.lockout_alg.marshal(
                (&mut buf[offset..offset + TpmiAlgHash::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
        }
        if offset + 405 <= buf.len() {
            buf[offset] = if global_state.sh_enable { 1 } else { 0 };
            offset += 1;
            buf[offset] = if global_state.eh_enable { 1 } else { 0 };
            offset += 1;
            buf[offset] = if global_state.ph_enable_nv { 1 } else { 0 };
            offset += 1;
            buf[offset] = 0xAA;
            offset += 1;
            buf[offset..offset + 2].copy_from_slice(&global_state.sp_seed_size.to_be_bytes());
            offset += 2;
            buf[offset..offset + 64].copy_from_slice(&global_state.sp_seed);
            offset += 64;
            buf[offset..offset + 2].copy_from_slice(&global_state.sh_proof_size.to_be_bytes());
            offset += 2;
            buf[offset..offset + 64].copy_from_slice(&global_state.sh_proof);
            offset += 64;
            buf[offset..offset + 2].copy_from_slice(&global_state.eh_proof_size.to_be_bytes());
            offset += 2;
            buf[offset..offset + 64].copy_from_slice(&global_state.eh_proof);
            offset += 64;
            buf[offset..offset + 4].copy_from_slice(&global_state.clear_count.to_be_bytes());
            offset += 4;
            buf[offset..offset + 2].copy_from_slice(&global_state.pp_seed_size.to_be_bytes());
            offset += 2;
            buf[offset..offset + 64].copy_from_slice(&global_state.pp_seed);
            offset += 64;
            buf[offset..offset + 2].copy_from_slice(&global_state.ph_proof_size.to_be_bytes());
            offset += 2;
            buf[offset..offset + 64].copy_from_slice(&global_state.ph_proof);
            offset += 64;
            buf[offset..offset + 2].copy_from_slice(&global_state.ep_seed_size.to_be_bytes());
            offset += 2;
            buf[offset..offset + 64].copy_from_slice(&global_state.ep_seed);
            offset += 64;
        }
        if offset + TpmiAlgHash::MAX_SIZE <= buf.len() {
            offset += global_state.pcr_policy_alg.marshal(
                (&mut buf[offset..offset + TpmiAlgHash::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
        }
        if offset + tpm2::Tpm2bDigest::MAX_SIZE <= buf.len() {
            offset += global_state.pcr_policy.marshal(
                (&mut buf[offset..offset + tpm2::Tpm2bDigest::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
        }
        if offset + Tpm2bAuth::MAX_SIZE <= buf.len() {
            offset += global_state.pcr_auth_value.marshal(
                (&mut buf[offset..offset + Tpm2bAuth::MAX_SIZE])
                    .try_into()
                    .unwrap(),
            );
        }
        // Persistent lifecycle data appended after a marker (older layouts simply end before it):
        // `gp.disableClear`, `gp.lockOutAuthEnabled`, `gp.maxTries`, `gp.recoveryTime`,
        // `gp.lockoutRecovery` (`NV_SYNC_PERSISTENT`) and `go.clock` / `go.clockSafe`.
        if offset + PERSISTENT_EXT_LEN <= buf.len() {
            buf[offset] = PERSISTENT_EXT_MARKER;
            buf[offset + 1] = u8::from(global_state.disable_clear);
            buf[offset + 2] = u8::from(global_state.lockout_auth_enabled);
            buf[offset + 3..offset + 7].copy_from_slice(&global_state.max_tries.to_be_bytes());
            buf[offset + 7..offset + 11].copy_from_slice(&global_state.recovery_time.to_be_bytes());
            buf[offset + 11..offset + 15]
                .copy_from_slice(&global_state.lockout_recovery.to_be_bytes());
            buf[offset + 15..offset + 23]
                .copy_from_slice(&self.get_clock(global_state).to_be_bytes());
            buf[offset + 23] = u8::from(global_state.clock_safe);
            offset += PERSISTENT_EXT_LEN;
        }
        let mut storage = StorageManager::new(&mut *self.platform.storage);
        if let Ok(meta) = storage.get_metadata(HIERARCHY_AUTH_HANDLE) {
            if (meta.data_size as usize) < offset {
                let _ = storage.undefine_space(HIERARCHY_AUTH_HANDLE);
                let _ = storage.define_space(HIERARCHY_AUTH_HANDLE, 1152, 0);
            }
        } else {
            let _ = storage.define_space(HIERARCHY_AUTH_HANDLE, 1152, 0);
        }
        let _ = storage.write_item(HIERARCHY_AUTH_HANDLE, 0, &buf[..offset]);
    }

    pub fn restore_hierarchy_auths(&mut self, global_state: &mut GlobalState) {
        /// Custom reserved handle used as a virtual NV index to store hierarchy authorization values.
        /// This is an implementation-specific value not defined in the TPM 2.0 specification.
        const HIERARCHY_AUTH_HANDLE: u32 = 0x00FFFFFF;
        let storage = StorageManager::new(&mut *self.platform.storage);
        let mut buf = [0u8; 1152];
        if let Ok(meta) = storage.get_metadata(HIERARCHY_AUTH_HANDLE) {
            let read_len = core::cmp::min(meta.data_size as usize, 1152);
            if storage
                .read_item(HIERARCHY_AUTH_HANDLE, 0, &mut buf[..read_len])
                .is_ok()
            {
                let mut slice = &buf[..read_len];
                if let Ok(auth) = OwnedAuth::unmarshal(&mut slice) {
                    global_state.owner_auth = auth;
                }
                if let Ok(auth) = OwnedAuth::unmarshal(&mut slice) {
                    global_state.endorsement_auth = auth;
                }
                if OwnedAuth::unmarshal(&mut slice).is_ok() {
                    // Read and discard platform_auth to maintain format compatibility.
                    // According to TPM 2.0 specification, platformAuth is volatile and resets
                    // to empty on TPM Reset (cold boot / initialization from NV data).
                }
                if let Ok(auth) = OwnedAuth::unmarshal(&mut slice) {
                    global_state.lockout_auth = auth;
                }
                if let Ok(policy) = OwnedDigest::unmarshal(&mut slice) {
                    global_state.owner_policy = policy;
                }
                if let Ok(policy) = OwnedDigest::unmarshal(&mut slice) {
                    global_state.endorsement_policy = policy;
                }
                if OwnedDigest::unmarshal(&mut slice).is_ok() {
                    // Read and discard platform_policy to maintain format compatibility, as
                    // platformPolicy resets on TPM Reset (cold boot / initialization from NV data).
                }
                if let Ok(policy) = OwnedDigest::unmarshal(&mut slice) {
                    global_state.lockout_policy = policy;
                }
                if let Ok(alg) = <Option<tpm2::TpmiAlgHash>>::unmarshal(&mut slice) {
                    global_state.owner_alg = alg;
                } else {
                    global_state.owner_alg =
                        infer_alg_from_digest_size(global_state.owner_policy.get_size() as usize);
                }
                if let Ok(alg) = <Option<tpm2::TpmiAlgHash>>::unmarshal(&mut slice) {
                    global_state.endorsement_alg = alg;
                } else {
                    global_state.endorsement_alg = infer_alg_from_digest_size(
                        global_state.endorsement_policy.get_size() as usize,
                    );
                }
                if let Ok(alg) = <Option<tpm2::TpmiAlgHash>>::unmarshal(&mut slice) {
                    global_state.platform_alg = alg;
                } else {
                    global_state.platform_alg = infer_alg_from_digest_size(
                        global_state.platform_policy.get_size() as usize,
                    );
                }
                if let Ok(alg) = <Option<tpm2::TpmiAlgHash>>::unmarshal(&mut slice) {
                    global_state.lockout_alg = alg;
                } else {
                    global_state.lockout_alg =
                        infer_alg_from_digest_size(global_state.lockout_policy.get_size() as usize);
                }
                if u8::unmarshal(&mut slice).is_ok() {
                    // Read and discard stored sh_enable to maintain NV layout compatibility.
                    // According to TPM 2.0 Part 1 Section 14.3, shEnable is volatile and always sets to YES upon _TPM_Init.
                }
                if u8::unmarshal(&mut slice).is_ok() {
                    // Read and discard stored eh_enable to maintain NV layout compatibility.
                    // According to TPM 2.0 Part 1 Section 14.3, ehEnable is volatile and always sets to YES upon _TPM_Init.
                }
                if let Ok(b) = u8::unmarshal(&mut slice) {
                    global_state.ph_enable_nv = b != 0;
                    if global_state.ph_enable_nv {
                        global_state.ph_enable = true;
                    }
                }
                if let Ok(marker) = u8::unmarshal(&mut slice)
                    && marker == 0xAA
                {
                    if let Ok(size) = u16::unmarshal(&mut slice) {
                        global_state.sp_seed_size = size;
                    }
                    if let Ok(seed) = <[u8; 64]>::unmarshal(&mut slice) {
                        global_state.sp_seed = seed;
                    }
                    if let Ok(size) = u16::unmarshal(&mut slice) {
                        global_state.sh_proof_size = size;
                    }
                    if let Ok(proof) = <[u8; 64]>::unmarshal(&mut slice) {
                        global_state.sh_proof = proof;
                    }
                    if let Ok(size) = u16::unmarshal(&mut slice) {
                        global_state.eh_proof_size = size;
                    }
                    if let Ok(proof) = <[u8; 64]>::unmarshal(&mut slice) {
                        global_state.eh_proof = proof;
                    }
                    if let Ok(count) = u32::unmarshal(&mut slice) {
                        global_state.clear_count = count;
                    }
                    if let Ok(size) = u16::unmarshal(&mut slice) {
                        global_state.pp_seed_size = size;
                    }
                    if let Ok(seed) = <[u8; 64]>::unmarshal(&mut slice) {
                        global_state.pp_seed = seed;
                    }
                    if let Ok(size) = u16::unmarshal(&mut slice) {
                        global_state.ph_proof_size = size;
                    }
                    if let Ok(proof) = <[u8; 64]>::unmarshal(&mut slice) {
                        global_state.ph_proof = proof;
                    }
                    if let Ok(size) = u16::unmarshal(&mut slice) {
                        global_state.ep_seed_size = size;
                    }
                    if let Ok(seed) = <[u8; 64]>::unmarshal(&mut slice) {
                        global_state.ep_seed = seed;
                    }
                    if let Ok(alg) = <Option<tpm2::TpmiAlgHash>>::unmarshal(&mut slice) {
                        global_state.pcr_policy_alg = alg;
                    }
                    if let Ok(policy) = OwnedDigest::unmarshal(&mut slice) {
                        global_state.pcr_policy = policy;
                    }
                    if let Ok(auth) = OwnedAuth::unmarshal(&mut slice) {
                        global_state.pcr_auth_value = auth;
                    }
                    if slice.len() >= PERSISTENT_EXT_LEN && slice[0] == PERSISTENT_EXT_MARKER {
                        let ext = &slice[..PERSISTENT_EXT_LEN];
                        let be_u32 = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                        global_state.disable_clear = ext[1] != 0;
                        global_state.lockout_auth_enabled = ext[2] != 0;
                        global_state.max_tries = be_u32(&ext[3..7]);
                        global_state.recovery_time = be_u32(&ext[7..11]);
                        global_state.lockout_recovery = be_u32(&ext[11..15]);
                        let mut clock = [0u8; 8];
                        clock.copy_from_slice(&ext[15..23]);
                        // Make `get_clock()` report the persisted `go.clock`.
                        global_state.clock_offset =
                            u64::from_be_bytes(clock).wrapping_sub(global_state.tpm_time_ms) as i64;
                        global_state.clock_safe = ext[23] != 0;
                    }
                }
            }
        }
    }

    /// Loads the persistent counters and orderly state kept in the reserved NV header
    /// (`NvReadPersistent()` / `NvRead(&go, ...)` in `_TPM_Init`) and, after an orderly
    /// `TPM2_Shutdown(TPM_SU_STATE)`, the saved `STATE_RESET_DATA` / `STATE_CLEAR_DATA`.
    ///
    /// Reserved header layout: `resetCount` (u32 @0), `orderlyState` (u16 @4), `totalResetCount`
    /// (u64 @8), `timeEpoch` (u64 @24), `failedTries` (u32 @32).
    ///
    /// `g_nv_ok` is SET when the persistent data was read; it is CLEAR if the previous shutdown
    /// was `TPM_SU_STATE` but the saved state could not be recovered (so that
    /// `TPM2_Startup(TPM_SU_STATE)` fails with `TPM_RC_NV_UNINITIALIZED`).
    fn restore_persistent_state(&mut self, global_state: &mut GlobalState) {
        let mut header = [0u8; 36];
        if self.platform.storage.read_nv(0, &mut header).is_err() {
            global_state.g_nv_ok = false;
            return;
        }
        let be_u32 = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let be_u64 = |b: &[u8]| {
            let mut v = [0u8; 8];
            v.copy_from_slice(&b[..8]);
            u64::from_be_bytes(v)
        };
        global_state.reset_count = be_u32(&header[0..4]);
        global_state.orderly_state = u16::from_be_bytes([header[4], header[5]]);
        global_state.total_reset_count = be_u64(&header[8..16]);
        global_state.time_epoch = be_u64(&header[24..32]);
        global_state.failed_tries = be_u32(&header[32..36]);
        global_state.g_nv_ok = true;

        // `TPM_SU_STATE` possibly combined with the `PRE_STARTUP_FLAG` / `STARTUP_LOCALITY_3` bits.
        let orderly = global_state.orderly_state;
        if orderly < 0xFFFE && (orderly & !(0x8000 | 0x4000)) == 0x0001 {
            global_state.g_nv_ok = self.restore_state_data(global_state);
        }
    }

    /// Persists the state that must survive a `TPM2_Shutdown(TPM_SU_STATE)` for a subsequent
    /// TPM Restart or TPM Resume (`NV_STATE_RESET_DATA` / `NV_STATE_CLEAR_DATA` in `Shutdown.c`).
    ///
    /// `STATE_RESET_DATA` (restored on Restart and Resume): `nullSeed`, `nullProof`,
    /// `restartCount`, `objectContextID`, the context counters, the saved-session table,
    /// `commitCounter`, `commitNonce` and `commitArray`. `STATE_CLEAR_DATA` (restored on Resume only): `platformAuth`,
    /// `platformPolicy`, `platformAlg`, `shEnable`, `ehEnable` and `phEnableNV`.
    ///
    /// PCR values and the remaining `GlobalState` fields are not written here; they are kept by
    /// the platform RAM, which `_TPM_Init` ([`GlobalState::reset_in_place`]) does not clear.
    pub(crate) fn save_state_data(&mut self, global_state: &GlobalState) -> Result<(), TpmRc> {
        let mut buf = [0u8; STATE_SAVE_MAX_LEN];
        let mut w = 0usize;
        let mut put = |bytes: &[u8], w: &mut usize| {
            buf[*w..*w + bytes.len()].copy_from_slice(bytes);
            *w += bytes.len();
        };
        put(&[STATE_SAVE_MARKER], &mut w);
        put(&global_state.null_seed_size.to_be_bytes(), &mut w);
        put(&global_state.null_seed, &mut w);
        put(&global_state.null_proof_size.to_be_bytes(), &mut w);
        put(&global_state.null_proof, &mut w);
        put(&global_state.restart_count.to_be_bytes(), &mut w);
        put(&global_state.object_context_id.to_be_bytes(), &mut w);
        put(&global_state.context_counter.to_be_bytes(), &mut w);
        put(&global_state.object_context_counter.to_be_bytes(), &mut w);
        // Saved session contexts, compactly: count, then `slot || handle || sequence` per entry.
        let saved_count = global_state.saved_sessions.iter().flatten().count();
        put(&[saved_count as u8], &mut w);
        for (slot, saved) in global_state.saved_sessions.iter().enumerate() {
            if let Some(handle) = saved {
                put(&[slot as u8], &mut w);
                put(&handle.to_be_bytes(), &mut w);
                put(
                    &global_state.saved_session_sequences[slot].to_be_bytes(),
                    &mut w,
                );
            }
        }
        put(&global_state.commit_counter.to_be_bytes(), &mut w);
        put(&global_state.commit_nonce, &mut w);
        put(&global_state.commit_array, &mut w);
        put(
            &[
                u8::from(global_state.sh_enable),
                u8::from(global_state.eh_enable),
                u8::from(global_state.ph_enable_nv),
            ],
            &mut w,
        );
        w += global_state
            .platform_auth
            .marshal((&mut buf[w..w + Tpm2bAuth::MAX_SIZE]).try_into().unwrap());
        w += global_state.platform_policy.marshal(
            (&mut buf[w..w + tpm2::Tpm2bDigest::MAX_SIZE])
                .try_into()
                .unwrap(),
        );
        w += global_state
            .platform_alg
            .marshal((&mut buf[w..w + TpmiAlgHash::MAX_SIZE]).try_into().unwrap());

        let mut storage = StorageManager::new(&mut *self.platform.storage);
        let _ = storage.undefine_space(STATE_SAVE_HANDLE);
        storage
            .define_space(STATE_SAVE_HANDLE, w as u16, 0)
            .map_err(|_| TpmRc::NV_SPACE)?;
        storage
            .write_item(STATE_SAVE_HANDLE, 0, &buf[..w])
            .map_err(|_| TpmRc::FAILURE)?;
        Ok(())
    }

    /// Deletes the saved `TPM_SU_STATE` data written by [`Self::save_state_data`] once it has been
    /// consumed (or invalidated) by `TPM2_Startup`, releasing its NV space.
    pub(crate) fn delete_state_data(&mut self) {
        let mut storage = StorageManager::new(&mut *self.platform.storage);
        let _ = storage.undefine_space(STATE_SAVE_HANDLE);
    }

    /// Restores the data written by [`Self::save_state_data`]. Returns `false` if it is missing
    /// or malformed.
    fn restore_state_data(&mut self, global_state: &mut GlobalState) -> bool {
        let storage = StorageManager::new(&mut *self.platform.storage);
        let Ok(meta) = storage.get_metadata(STATE_SAVE_HANDLE) else {
            return false;
        };
        let len = meta.data_size as usize;
        let mut buf = [0u8; STATE_SAVE_MAX_LEN];
        if len > buf.len()
            || storage
                .read_item(STATE_SAVE_HANDLE, 0, &mut buf[..len])
                .is_err()
        {
            return false;
        }
        let mut slice = &buf[..len];
        let parsed = (|| -> Option<()> {
            if u8::unmarshal(&mut slice).ok()? != STATE_SAVE_MARKER {
                return None;
            }
            let null_seed_size = u16::unmarshal(&mut slice).ok()?;
            let null_seed = <[u8; 64]>::unmarshal(&mut slice).ok()?;
            let null_proof_size = u16::unmarshal(&mut slice).ok()?;
            let null_proof = <[u8; 64]>::unmarshal(&mut slice).ok()?;
            let restart_count = u32::unmarshal(&mut slice).ok()?;
            let object_context_id = u32::unmarshal(&mut slice).ok()?;
            let context_counter = u64::unmarshal(&mut slice).ok()?;
            let object_context_counter = u64::unmarshal(&mut slice).ok()?;
            let mut saved_sessions = [None; MAX_ACTIVE_SESSIONS];
            let mut saved_session_sequences = [0u64; MAX_ACTIVE_SESSIONS];
            let saved_count = u8::unmarshal(&mut slice).ok()? as usize;
            for _ in 0..saved_count {
                let slot = u8::unmarshal(&mut slice).ok()? as usize;
                let handle = u32::unmarshal(&mut slice).ok()?;
                let sequence = u64::unmarshal(&mut slice).ok()?;
                if slot >= MAX_ACTIVE_SESSIONS {
                    return None;
                }
                saved_sessions[slot] = Some(handle);
                saved_session_sequences[slot] = sequence;
            }
            let commit_counter = u16::unmarshal(&mut slice).ok()?;
            let commit_nonce = <[u8; 64]>::unmarshal(&mut slice).ok()?;
            let commit_array = <[u8; 16]>::unmarshal(&mut slice).ok()?;
            let sh_enable = u8::unmarshal(&mut slice).ok()? != 0;
            let eh_enable = u8::unmarshal(&mut slice).ok()? != 0;
            let ph_enable_nv = u8::unmarshal(&mut slice).ok()? != 0;
            let platform_auth = OwnedAuth::unmarshal(&mut slice).ok()?;
            let platform_policy = OwnedDigest::unmarshal(&mut slice).ok()?;
            let platform_alg = <Option<tpm2::TpmiAlgHash>>::unmarshal(&mut slice).ok()?;

            global_state.null_seed_size = null_seed_size;
            global_state.null_seed = null_seed;
            global_state.null_proof_size = null_proof_size;
            global_state.null_proof = null_proof;
            global_state.restart_count = restart_count;
            global_state.object_context_id = object_context_id;
            global_state.context_counter = context_counter;
            global_state.object_context_counter = object_context_counter;
            global_state.saved_sessions = saved_sessions;
            global_state.saved_session_sequences = saved_session_sequences;
            global_state.commit_counter = commit_counter;
            global_state.commit_nonce = commit_nonce;
            global_state.commit_array = commit_array;
            global_state.sh_enable = sh_enable;
            global_state.eh_enable = eh_enable;
            global_state.ph_enable_nv = ph_enable_nv;
            global_state.platform_auth = platform_auth;
            global_state.platform_policy = platform_policy;
            global_state.platform_alg = platform_alg;
            Some(())
        })();
        parsed.is_some()
    }

    /// Process a TPM request and writes the response in a separate buffer. Returns the number of
    /// bytes written to the response buffer.
    pub fn execute_command_separate(
        &mut self,
        global_state: &mut GlobalState,
        request: &[u8],
        response: &mut [u8],
    ) -> usize {
        match self.execute_command(global_state, request, response) {
            Ok(size) => size,
            Err(err) => self.fill_error(response, err),
        }
    }

    /// Process a TPM request and write the response back into the same buffer. Returns the number
    /// of bytes written to the response buffer.
    pub fn execute_command_in_place(
        &mut self,
        global_state: &mut GlobalState,
        in_out: &mut [u8],
        request_size: usize,
    ) -> usize {
        let mut tmp_request = [0u8; 4096];
        if request_size > tmp_request.len() {
            return self.fill_error(in_out, TpmRc::SIZE.to_rc());
        }
        tmp_request[..request_size].copy_from_slice(&in_out[..request_size]);
        match self.execute_command(global_state, &tmp_request[..request_size], in_out) {
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
    /// `global_state.drtm_handle` (`g_DRTMHandle`).
    pub fn hash_start(&mut self, global_state: &mut GlobalState) -> bool {
        if global_state.drtm_handle != Handle::RH_UNASSIGNED.0 {
            let old_handle = global_state.drtm_handle;
            global_state.drtm_handle = Handle::RH_UNASSIGNED.0;
            let _ = global_state.remove_active_sequence(old_handle);
        }

        let (index, handle) = match global_state.find_empty_sequence_slot() {
            Ok((idx, h)) => (idx, h),
            Err(_) => {
                // Free the lowest assigned transient/sequence handle slot (TRANSIENT_FIRST = 0x80000000)
                let mut freed = false;
                for i in 0..(MAX_LOADED_OBJECTS as u32) {
                    let candidate = 0x8000_0000 | i;
                    if global_state.remove_transient_object(candidate).is_ok()
                        || global_state.remove_active_sequence(candidate).is_ok()
                    {
                        freed = true;
                        break;
                    }
                }
                if !freed {
                    return false;
                }
                match global_state.find_empty_sequence_slot() {
                    Ok((idx, h)) => (idx, h),
                    Err(_) => return false,
                }
            }
        };

        let seq = ActiveSequence::new(handle, Tpm2bAuth::default(), SequenceType::Event);
        global_state.active_sequences[index] = Some(seq);
        global_state.drtm_handle = handle;
        true
    }

    /// Processes a `_TPM_Hash_Data` indication (TCG DRTM / H-CRTM hardware event sequence).
    ///
    /// Updates the streaming hash state for each active bank where the target PCR (`0` before
    /// startup, `17` after startup) is allocated.
    pub fn hash_data(&mut self, global_state: &mut GlobalState, data: &[u8]) -> bool {
        if global_state.drtm_handle == Handle::RH_UNASSIGNED.0 {
            return false;
        }
        let target_pcr: u32 = if global_state.initialized { 17 } else { 0 };
        let pcr_alloc = global_state.pcrs.pcr_allocation;

        let Some(seq) = global_state.find_active_sequence_mut(global_state.drtm_handle) else {
            return false;
        };

        for state in &mut seq.hash_states {
            if is_pcr_allocated(&pcr_alloc, state.alg, target_pcr) {
                state.update(data);
            }
        }
        true
    }

    /// Processes a `_TPM_Hash_End` indication (TCG DRTM / H-CRTM hardware event sequence).
    ///
    /// Completes the active DRTM/H-CRTM event sequence:
    /// - If post-startup (`global_state.initialized == true`):
    ///   - Resets all dynamic PCRs (`17..=22`) to `0x00`.
    ///   - Increments `global_state.restart_count`.
    ///   - Resets PCR 17 to `0x00` and extends it with the finalized event digest in each allocated bank.
    /// - If pre-startup (`global_state.initialized == false`):
    ///   - Sets `global_state.drtm_pre_startup = true`.
    ///   - Sets PCR 0 to `0x00...04` and extends it with the finalized event digest in each allocated bank.
    /// - Flushes the sequence object and resets `global_state.drtm_handle` to `TPM_RH_UNASSIGNED`.
    pub fn hash_end(&mut self, global_state: &mut GlobalState) -> bool {
        if global_state.drtm_handle == Handle::RH_UNASSIGNED.0 {
            return false;
        }

        let old_handle = global_state.drtm_handle;
        global_state.drtm_handle = Handle::RH_UNASSIGNED.0;
        let Some(seq) = global_state.find_active_sequence(old_handle).cloned() else {
            return false;
        };
        let _ = global_state.remove_active_sequence(old_handle);

        let target_pcr: usize = if global_state.initialized {
            // PCRResetDynamics: reset PCRs 17..=22 to 0 across all banks
            for pcr in 17..=22 {
                global_state.pcrs.sha1[pcr] = [0u8; 20];
                global_state.pcrs.sha256[pcr] = [0u8; 32];
                global_state.pcrs.sha384[pcr] = [0u8; 48];
            }
            global_state.restart_count = global_state.restart_count.wrapping_add(1);
            17
        } else {
            global_state.drtm_pre_startup = true;
            0
        };

        let pcr_alloc = global_state.pcrs.pcr_allocation;
        for state in &seq.hash_states {
            if is_pcr_allocated(&pcr_alloc, state.alg, target_pcr as u32) {
                let (digest, digest_len) = state.finalize();
                match state.alg {
                    TpmiAlgHash::Sha1 => {
                        let pcr_data = &mut global_state.pcrs.sha1[target_pcr];
                        pcr_data.fill(0);
                        if !global_state.initialized {
                            pcr_data[19] = 4;
                        }
                        let mut h = crate::hash_state::StreamingHashState::new(TpmiAlgHash::Sha1);
                        h.update(pcr_data);
                        h.update(&digest[..digest_len]);
                        let (new_pcr, _) = h.finalize();
                        pcr_data.copy_from_slice(&new_pcr[..20]);
                        global_state.pcrs.update_counter =
                            global_state.pcrs.update_counter.wrapping_add(1);
                    }
                    TpmiAlgHash::Sha256 => {
                        let pcr_data = &mut global_state.pcrs.sha256[target_pcr];
                        pcr_data.fill(0);
                        if !global_state.initialized {
                            pcr_data[31] = 4;
                        }
                        let mut h = crate::hash_state::StreamingHashState::new(TpmiAlgHash::Sha256);
                        h.update(pcr_data);
                        h.update(&digest[..digest_len]);
                        let (new_pcr, _) = h.finalize();
                        pcr_data.copy_from_slice(&new_pcr[..32]);
                        global_state.pcrs.update_counter =
                            global_state.pcrs.update_counter.wrapping_add(1);
                    }
                    TpmiAlgHash::Sha384 => {
                        let pcr_data = &mut global_state.pcrs.sha384[target_pcr];
                        pcr_data.fill(0);
                        if !global_state.initialized {
                            pcr_data[47] = 4;
                        }
                        let mut h = crate::hash_state::StreamingHashState::new(TpmiAlgHash::Sha384);
                        h.update(pcr_data);
                        h.update(&digest[..digest_len]);
                        let (new_pcr, _) = h.finalize();
                        pcr_data.copy_from_slice(&new_pcr[..48]);
                        global_state.pcrs.update_counter =
                            global_state.pcrs.update_counter.wrapping_add(1);
                    }
                    _ => {}
                }
            }
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
    fn time_update(&mut self, global_state: &mut GlobalState) {
        let raw_timer_ms = self.platform.timer.timer_read();
        let elapsed_raw_ms = if let Some(prev_raw) = global_state.last_timer_read_ms {
            raw_timer_ms.saturating_sub(prev_raw)
        } else {
            0
        };
        global_state.last_timer_read_ms = Some(raw_timer_ms);

        // adjusted = elapsed * CLOCK_NOMINAL / adjustRate, carrying the remainder.
        let rate = u128::from(global_state.clock_adjust_rate.max(1));
        let scaled = u128::from(elapsed_raw_ms) * u128::from(CLOCK_NOMINAL)
            + u128::from(global_state.clock_adjust_remainder);
        let elapsed_ms = u64::try_from(scaled / rate).unwrap_or(u64::MAX);
        global_state.clock_adjust_remainder = (scaled % rate) as u64;

        let old_clock = self.get_clock(global_state);
        global_state.tpm_time_ms = global_state.tpm_time_ms.saturating_add(elapsed_ms);
        let new_clock = self.get_clock(global_state);
        self.clock_update(global_state, old_clock, new_clock);

        self.da_self_heal(global_state);
    }

    /// Records a change of `Clock` from `old_clock` to `new_clock` (`TimeClockUpdate()` in
    /// `Time.c`): if the new value crosses an `NV_CLOCK_UPDATE_INTERVAL` boundary, `clockSafe`
    /// is SET and the clock is written to NV. The caller must have checked NV availability.
    pub(crate) fn clock_update(
        &mut self,
        global_state: &mut GlobalState,
        old_clock: u64,
        new_clock: u64,
    ) {
        const CLOCK_UPDATE_MASK: u64 = (1u64 << NV_CLOCK_UPDATE_INTERVAL) - 1;
        if (new_clock | CLOCK_UPDATE_MASK) > (old_clock | CLOCK_UPDATE_MASK) {
            global_state.clock_safe = true;
            // The clock is persisted with the rest of the persistent hierarchy data.
            self.save_hierarchy_auths(global_state);
        }
    }

    /// Dictionary-attack self-healing (`DASelfHeal()` in `DA.c`): decrements `failedTries` once
    /// per `recoveryTime` seconds (or clears it when `recoveryTime` is 0) and re-enables
    /// `lockoutAuth` once `lockoutRecovery` seconds have elapsed since the last lockout failure.
    /// Every change is synchronized to NV (`NV_SYNC_PERSISTENT`).
    fn da_self_heal(&mut self, global_state: &mut GlobalState) {
        // 1. Regular authorization self-healing (failedTries decrement every recoveryTime seconds)
        if global_state.failed_tries != 0 {
            if global_state.recovery_time == 0 {
                global_state.failed_tries = 0;
                let _ = self
                    .platform
                    .storage
                    .write_nv(32, &global_state.failed_tries.to_be_bytes());
            } else {
                let elapsed_heal_ms =
                    (global_state.tpm_time_ms as i64).saturating_sub(global_state.self_heal_timer);
                if elapsed_heal_ms >= 0 {
                    let decrease_count =
                        ((elapsed_heal_ms as u64) / 1000) / (global_state.recovery_time as u64);
                    if decrease_count > 0 {
                        global_state.failed_tries = global_state
                            .failed_tries
                            .saturating_sub(decrease_count as u32);
                        global_state.self_heal_timer = global_state.self_heal_timer.saturating_add(
                            (decrease_count * (global_state.recovery_time as u64) * 1000) as i64,
                        );
                        let _ = self
                            .platform
                            .storage
                            .write_nv(32, &global_state.failed_tries.to_be_bytes());
                    }
                }
            }
        }

        // 2. LockoutAuth self-healing (re-enable lockoutAuth after lockoutRecovery seconds)
        if !global_state.lockout_auth_enabled && global_state.lockout_recovery != 0 {
            let elapsed_lockout_ms =
                (global_state.tpm_time_ms as i64).saturating_sub(global_state.lockout_timer);
            if elapsed_lockout_ms >= 0
                && ((elapsed_lockout_ms as u64) / 1000) >= (global_state.lockout_recovery as u64)
            {
                global_state.lockout_auth_enabled = true;
                // NV_SYNC_PERSISTENT(lockOutAuthEnabled)
                self.save_hierarchy_auths(global_state);
            }
        }
    }

    pub fn execute_command(
        &mut self,
        global_state: &mut GlobalState,
        cmd_buf: &[u8],
        resp_buf: &mut [u8],
    ) -> Result<usize, TpmRc> {
        // Any command through this function unceremoniously ends an active DRTM event sequence
        // (`ObjectTerminateEvent()` in `ExecCommand.c`).
        if global_state.drtm_handle != Handle::RH_UNASSIGNED.0 {
            let old_handle = global_state.drtm_handle;
            global_state.drtm_handle = Handle::RH_UNASSIGNED.0;
            let _ = global_state.remove_active_sequence(old_handle);
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

        // `TimeUpdateToCurrent()` (`Time.c`): Time/Clock only advance, and `DASelfHeal()` only
        // runs, once TPM2_Startup has completed and while NV is available. Otherwise the elapsed
        // platform time is deferred (the last timer sample is kept) until the next update.
        if global_state.initialized && global_state.nv_available {
            self.time_update(global_state);
        }

        // `ExecCommand.c`: only `TPM2_Startup` is accepted before the TPM is started, and it is
        // not accepted afterwards. This is checked (after
        // `TimeUpdateToCurrent`) before any handle or session processing.
        if global_state.initialized == (cc == TpmCc::Startup) {
            return Err(TpmRc::INITIALIZE);
        }

        // Reset per-command state-tracking flags at the beginning of each command
        // (`g_updateNV = UT_NONE; g_clearOrderly = FALSE;` in `ExecCommand.c`).
        global_state.update_nv = UT_NONE;
        global_state.clear_orderly = false;

        let res = (|| -> Result<usize, TpmRc> {
            // Command dispatch based on authorization session tag
            if header.tag == TpmiStCommandTag::Sessions {
                self.execute_with_sessions(global_state, cmd_buf, resp_buf, cc, command_code, size)
            } else {
                let mut handles = [0u32; 3];
                let handles_len = command_handles_count(cc);
                if size < 10 + handles_len * 4 {
                    return Err(TpmRc::SIZE.to_rc());
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
                if !global_state.in_shadow_execution {
                    // As in `ExecCommand.c`, the handles are validated (`ParseHandleBuffer` /
                    // `EntityGetLoadStatus`) before missing authorizations are reported
                    // (`CheckAuthNoSession`).
                    let params_len = size.saturating_sub(10 + handles_len * 4);
                    self.validate_command_handles(
                        global_state,
                        cc,
                        &handles,
                        handles_len,
                        &cmd_buf[10 + handles_len * 4..10 + handles_len * 4 + params_len],
                    )?;
                    self.check_unauthorized_handles(
                        global_state,
                        cc,
                        &handles,
                        handles_len,
                        &[],
                        0,
                    )?;
                }

                let result =
                    self.execute_without_sessions(global_state, cmd_buf, resp_buf, cc, size);
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
                    global_state.exclusive_audit_session = None;
                }
                result
            }
        })();

        // Post-command cleanup (`Cleanup:` in `ExecCommand.c`):
        // 1. If clear_orderly is set and NV is currently orderly (`orderly_state < SU_DA_USED_VALUE`),
        //    invalidate orderly_state to SU_DA_USED_VALUE (0xFFFE) or SU_NONE_VALUE (0xFFFF)
        //    and sync to persistent NV storage (offset 16).
        if global_state.clear_orderly && global_state.orderly_state < 0xFFFE {
            global_state.orderly_state = if global_state.da_used { 0xFFFE } else { 0xFFFF };
            global_state.state_saved = false;
            let _ = self
                .platform
                .storage
                .write_nv(4, &global_state.orderly_state.to_be_bytes());
            global_state.update_nv |= UT_NV;
        }

        // 2. Commit NV updates and reset update_nv flag (`g_updateNV = UT_NONE`).
        if global_state.update_nv != UT_NONE {
            global_state.update_nv = UT_NONE;
        }

        res
    }

    /// Helper function to execute a TPM command containing authorization sessions (tag 0x8002).
    /// Performs key derivation, parameter decryption, session HMAC verification, routes to the actual
    /// command handler, and then processes the response (parameter encryption, session HMAC generation).
    fn execute_with_sessions(
        &mut self,
        global_state: &mut GlobalState,
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
            self.reject_sessions_for_no_sessions_command(global_state, cmd_buf, cc, request_size)?;
        }
        // 1. Parse Handles and Session Area
        let mut cmd =
            self.parse_command_and_sessions(global_state, cmd_buf, cc, command_code, request_size)?;
        // Handles are validated before the session area is examined, matching the C reference
        // (`ParseHandleBuffer`/`EntityGetLoadStatus` run before `ParseSessionBuffer`).
        self.validate_command_handles(
            global_state,
            cc,
            &cmd.handles,
            cmd.handles_len,
            cmd.parameters,
        )?;
        self.validate_session_attributes(&cmd, global_state, command_code, true)?;
        self.validate_session_attributes(&cmd, global_state, command_code, false)?;

        // 2. Session authorization (HMAC/password/policy) for all sessions. As in the C reference
        // `ParseSessionBuffer`, missing authorizations are reported first, and authorization
        // happens before parameter decryption, so a malformed encrypted parameter cannot mask an
        // authorization failure (or skip the DA accounting). The cpHash is computed over the
        // still-encrypted wire parameters.
        self.check_unauthorized_handles(
            global_state,
            cc,
            &cmd.handles,
            cmd.handles_len,
            &cmd.session_to_handle_idx,
            cmd.session_to_handle_idx_len,
        )?;
        self.verify_session_hmacs(global_state, &mut cmd, command_code)?;

        // 3. Parameter Decryption (the last step of session processing).
        let has_decrypt_session = cmd.auth_sessions[..cmd.auth_sessions_len]
            .iter()
            .any(|auth| auth.session_attributes.0 & 0x20 != 0);

        if has_decrypt_session {
            self.execute_with_param_decryption(global_state, cmd, resp_buf, cc, command_code)
        } else {
            self.execute_after_decryption(global_state, &mut cmd, resp_buf, cc, command_code)
        }
    }

    /// Returns `TPM_RC_AUTH_CONTEXT` for a `NO_SESSIONS` command sent with `TPM_ST_SESSIONS`
    /// once its handles are valid and its `authorizationSize` is sane. Returns `Ok(())` if the
    /// handle or authorization-size area is truncated or malformed, so that the regular parser
    /// reports that error exactly as for any other command.
    fn reject_sessions_for_no_sessions_command(
        &mut self,
        global_state: &mut GlobalState,
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
        self.validate_command_handles(global_state, cc, &handles, num_handles, &[])?;
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
        global_state: &mut GlobalState,
        cmd: ParsedCommand,
        resp_buf: &mut [u8],
        cc: TpmCc,
        command_code: u32,
    ) -> Result<usize, TpmRc> {
        let mut decrypt_buf: DecryptBuf = [0u8; DECRYPT_BUF_SIZE];
        let mut cmd = self.decrypt_command_parameters(global_state, cmd, &mut decrypt_buf)?;
        self.execute_after_decryption(global_state, &mut cmd, resp_buf, cc, command_code)
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
        global_state: &mut GlobalState,
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
        global_state.sessions_validated_by_handler = false;
        global_state.parsed_auths[..cmd.auth_sessions_len]
            .copy_from_slice(&cmd.auth_sessions[..cmd.auth_sessions_len]);
        global_state.parsed_auths_len = cmd.auth_sessions_len;
        global_state.in_shadow_execution = true;
        let shadow_res = self.execute_without_sessions(
            global_state,
            &shadow_request[..shadow_request_size],
            resp_buf,
            cc,
            shadow_request_size,
        );
        global_state.in_shadow_execution = false;
        global_state.parsed_auths_len = 0;

        if let Ok(shadow_len) = shadow_res {
            let mut has_audit_session = false;
            for auth in &cmd.auth_sessions[..cmd.auth_sessions_len] {
                if auth.session_attributes.0 & 0x80 != 0 {
                    has_audit_session = true;
                    let session_handle = auth.session_handle.0;
                    let mut is_first_use = false;
                    let has_audit_reset = auth.session_attributes.0 & 0x04 != 0; // TpmaSession::AUDIT_RESET
                    if let Some(session_state) = global_state.session_mut(session_handle) {
                        is_first_use = session_state.audit_digest.is_none();
                        if has_audit_reset || is_first_use {
                            let size = session_state.auth_hash.digest_size();
                            let zero_digest = [0u8; 64];
                            session_state.audit_digest = Some(zero_digest);
                            session_state.audit_digest_len = size;
                        }
                    }
                    if is_first_use || has_audit_reset {
                        global_state.exclusive_audit_session = Some(session_handle);
                    } else if global_state.exclusive_audit_session != Some(session_handle) {
                        global_state.exclusive_audit_session = None;
                    }
                }
            }
            if !has_audit_session
                && !matches!(
                    cc,
                    TpmCc::Startup | TpmCc::ContextLoad | TpmCc::ContextSave | TpmCc::FlushContext
                )
            {
                global_state.exclusive_audit_session = None;
            }

            let resp_buffer = resp_buf;
            let mut nonces_tpm_new: [Option<OwnedNonce>; 3] = [None; 3];
            for (i, auth) in cmd.auth_sessions[..cmd.auth_sessions_len]
                .iter()
                .enumerate()
            {
                let session_handle = auth.session_handle.0;
                if (0x02000000..=0x03FFFFFF).contains(&session_handle) {
                    let nonce_size = global_state
                        .session(session_handle)
                        .map(|s| s.nonce_tpm.get_size() as usize)
                        .unwrap_or(32);
                    let mut nonce_bytes = [0u8; 64];
                    self.platform
                        .crypto
                        .get_random(&mut nonce_bytes[..nonce_size])
                        .map_err(|_| TpmRc::MEMORY)?;
                    nonces_tpm_new[i] = Some(
                        OwnedNonce::from_bytes(&nonce_bytes[..nonce_size])
                            .map_err(|_| TpmRc::MEMORY)?,
                    );
                } else {
                    nonces_tpm_new[i] = None;
                }
            }

            if global_state.sessions_validated_by_handler {
                self.process_response_parameters_with_handler_validation(
                    global_state,
                    cmd,
                    cc,
                    command_code,
                    resp_buffer,
                    &nonces_tpm_new,
                )
            } else {
                self.process_response_parameters_without_handler_validation(
                    global_state,
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
        global_state: &GlobalState,
        cmd_buf: &'cmd [u8],
        cc: TpmCc,
        command_code: u32,
        request_size: usize,
    ) -> Result<ParsedCommand<'cmd>, TpmRc> {
        // 1. Parse Handles
        let num_handles = command_handles_count(cc);
        let handles_size = num_handles * 4;
        if request_size < 10 + handles_size {
            return Err(TpmRc::SIZE.to_rc());
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
            handle_auths[i] = self.handle_auth(global_state, h);
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

    /// Helper to validate attributes of encryption/decryption sessions.
    fn validate_session_attributes(
        &self,
        cmd: &ParsedCommand,
        global_state: &mut GlobalState,
        command_code: u32,
        syntax_only: bool,
    ) -> Result<(), TpmRc> {
        let mut decrypt_session_idx = None;
        let mut encrypt_session_idx = None;
        let mut audit_session_idx = None;

        for (i, auth) in cmd
            .auth_sessions
            .iter()
            .enumerate()
            .take(cmd.auth_sessions_len)
        {
            let pos = Position::session((i + 1) as u8);
            let session_handle = auth.session_handle.0;
            let attrs = auth.session_attributes;

            if syntax_only {
                // 2.1 Password Session (PWAP) Validation
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
                    // The nonce of a password session must be empty (C `RetrieveSessionData`).
                    if auth.nonce.get_size() != 0 {
                        return Err(TpmRc::NONCE.with(pos));
                    }
                    continue;
                }

                // A session handle may appear only once in the session area (C
                // `RetrieveSessionData`). A session that is also named in the handle area is
                // allowed (e.g. `TPM2_PolicyGetDigest` with the same session encrypting).
                if cmd.auth_sessions[..i]
                    .iter()
                    .any(|prev| prev.session_handle.0 == session_handle)
                {
                    return Err(TpmRc::HANDLE.with(pos));
                }

                // 2.2 Attribute Dependency Check
                if (attrs.contains(TpmaSession::AUDIT_EXCLUSIVE)
                    || attrs.contains(TpmaSession::AUDIT_RESET))
                    && !attrs.contains(TpmaSession::AUDIT)
                {
                    return Err(TpmRc::ATTRIBUTES.with(pos));
                }

                // 2.3 Multiple Audit Sessions Check
                if attrs.contains(TpmaSession::AUDIT) {
                    if audit_session_idx.is_some() {
                        return Err(TpmRc::ATTRIBUTES.with(pos));
                    }
                    audit_session_idx = Some(i);
                }

                if attrs.contains(TpmaSession::DECRYPT) {
                    if decrypt_session_idx.is_some() {
                        return Err(TpmRc::ATTRIBUTES.with(pos));
                    }
                    if !command_supports_decryption(TpmCc::new(command_code)) {
                        return Err(TpmRc::ATTRIBUTES.with(pos));
                    }
                    decrypt_session_idx = Some(i);
                }
                if attrs.contains(TpmaSession::ENCRYPT) {
                    if !command_supports_encryption(TpmCc::new(command_code)) {
                        return Err(TpmRc::ATTRIBUTES.with(pos));
                    }
                    if encrypt_session_idx.is_some() {
                        return Err(TpmRc::ATTRIBUTES.with(pos));
                    }
                    encrypt_session_idx = Some(i);
                }
                continue;
            }

            if session_handle == Handle::RS_PW.0 {
                continue;
            }

            if attrs.contains(TpmaSession::ENCRYPT) {
                encrypt_session_idx = Some(i);
            }

            // An unloaded session slot is `TPM_RC_REFERENCE_S0 + i`; a loaded slot referenced
            // with the wrong session handle type is `TPM_RC_HANDLE` (C `RetrieveSessionData`).
            let Some(slot) = global_state.session_by_slot(session_handle) else {
                return Err(reference_s(i));
            };
            if slot.session_handle != session_handle {
                return Err(TpmRc::HANDLE.with(pos));
            }
            let session_state = slot;

            // A decrypt or encrypt session needs a symmetric algorithm (C `RetrieveSessionData`,
            // which runs for every session before any authorization check).
            if attrs.intersects(TpmaSession::DECRYPT | TpmaSession::ENCRYPT)
                && session_state.symmetric.is_none()
            {
                return Err(TpmRc::SYMMETRIC.with(pos));
            }

            // 2.4 Policy Session Auditing Restriction
            if attrs.contains(TpmaSession::AUDIT) && session_state.session_type != tpm2::TpmSe::HMAC
            {
                return Err(TpmRc::ATTRIBUTES.with(pos));
            }

            // 2.5 Exclusivity Validation Check
            if attrs.contains(TpmaSession::AUDIT_EXCLUSIVE)
                && !attrs.contains(TpmaSession::AUDIT_RESET)
                && session_state.audit_digest.is_some()
                && global_state.exclusive_audit_session != Some(session_handle)
            {
                return Err(TpmRc::EXCLUSIVE);
            }
        }

        if syntax_only {
            return Ok(());
        }

        if let Some(i) = encrypt_session_idx {
            let auth = &cmd.auth_sessions[i];
            let session_handle = auth.session_handle.0;
            let pos = Position::session((i + 1) as u8);
            if !(0x02000000..=0x03FFFFFF).contains(&session_handle) {
                return Err(TpmRc::VALUE.with(pos));
            }
            let session_state = global_state
                .session(session_handle)
                .ok_or(TpmRc::HANDLE.with(pos))?;
            match session_state.symmetric {
                Some(tpm2::TpmtSymDef::Cipher(sym_obj)) => {
                    if sym_obj.mode() != Some(TpmiAlgSymMode::CFB) {
                        return Err(TpmRc::MODE.with(pos));
                    }
                }
                Some(tpm2::TpmtSymDef::Xor(_)) => {}
                None => {
                    return Err(TpmRc::SYMMETRIC.with(pos));
                }
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
        global_state: &mut GlobalState,
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
                _bind_entity,
                _bound_entity,
                _is_policy,
                _is_auth_value_needed,
                _is_password_needed,
            ) = {
                let session_state = global_state
                    .session(session_handle)
                    .ok_or(TpmRc::HANDLE.with(pos))?;
                session_key_buf[..session_state.session_key_len]
                    .copy_from_slice(&session_state.session_key[..session_state.session_key_len]);
                session_key_len = session_state.session_key_len;
                (
                    session_state.nonce_tpm,
                    session_state.symmetric,
                    session_state.auth_hash,
                    session_state.bind_entity,
                    session_state.bound_entity,
                    session_state.session_type == TpmSe::Policy,
                    session_state.is_auth_value_needed,
                    session_state.is_password_needed,
                )
            };
            let (is_xor, key_bits, sym_obj) = match symmetric {
                Some(tpm2::TpmtSymDef::Cipher(sym_obj)) => {
                    if sym_obj.mode() != Some(TpmiAlgSymMode::CFB) {
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
                    self.handle_auth(global_state, cmd.handles[h_idx])
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
                        self.platform.crypto,
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
                        self.platform.crypto,
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
                    tpm2::crypto::decrypt(
                        self.platform.crypto,
                        sym_obj,
                        &derived_key[..(key_bits / 8) as usize],
                        &mut iv,
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
        let storage_mgr = StorageManager::new(&mut *self.platform.storage);
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
    fn authorized_object(
        &mut self,
        global_state: &GlobalState,
        handle: u32,
    ) -> Option<crate::handler::TransientObject> {
        if (0x80000000..=0x80FFFFFF).contains(&handle) {
            global_state.find_transient_object(handle).cloned()
        } else if (0x81000000..=0x81FFFFFF).contains(&handle) {
            self.load_persistent_object(global_state, handle).ok()
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
    fn is_policy_session_required(
        &mut self,
        global_state: &GlobalState,
        cc: TpmCc,
        handle_index: usize,
        handle: u32,
    ) -> bool {
        match command_auth_role(cc, handle_index) {
            AuthRole::Dup => true,
            AuthRole::Admin => {
                if global_state.find_active_sequence(handle).is_some() {
                    // A sequence object is a transient object whose adminWithPolicy is CLEAR.
                    false
                } else if (0x80000000..=0x81FFFFFF).contains(&handle) {
                    self.authorized_object(global_state, handle)
                        .is_none_or(|obj| {
                            obj.public
                                .object_attributes
                                .contains(tpm2::TpmaObject::ADMIN_WITH_POLICY)
                        })
                } else {
                    true
                }
            }
            AuthRole::User | AuthRole::None => {
                (20..=22).contains(&handle) && global_state.pcr_policy_alg.is_some()
            }
        }
    }

    /// Returns whether the authValue of `handle` may be used to authorize handle `handle_index`
    /// of command `cc` with a password or HMAC session (C `IsAuthValueAvailable()`):
    /// - permanent handles: only the hierarchies, `TPM_RH_LOCKOUT` and `TPM_RH_NULL`;
    /// - sequence objects: always;
    /// - other objects: only if the sensitive area is loaded (not public-only) and either
    ///   `userWithAuth` is SET or the ADMIN role is required and `adminWithPolicy` is CLEAR;
    /// - NV Indices: `TPMA_NV_AUTHWRITE` for write operations; for read operations PIN indices
    ///   need `TPMA_NV_WRITTEN` and `pinCount < pinLimit`, other indices `TPMA_NV_AUTHREAD`;
    /// - PCRs: always.
    fn is_auth_value_available(
        &mut self,
        global_state: &GlobalState,
        cc: TpmCc,
        handle_index: usize,
        handle: u32,
    ) -> bool {
        match Handle(handle).handle_type() {
            Some(TpmHt::Permanent) => matches!(
                Handle(handle),
                Handle::RH_OWNER
                    | Handle::RH_ENDORSEMENT
                    | Handle::RH_PLATFORM
                    | Handle::RH_LOCKOUT
                    | Handle::RH_NULL
                    | Handle::RH_AUTH_00
            ),
            Some(TpmHt::Transient) | Some(TpmHt::Persistent) => {
                if global_state.find_active_sequence(handle).is_some() {
                    return true;
                }
                let Some(obj) = self.authorized_object(global_state, handle) else {
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
        global_state: &GlobalState,
        cc: TpmCc,
        handle_index: usize,
        handle: u32,
    ) -> bool {
        match Handle(handle).handle_type() {
            Some(TpmHt::Transient) | Some(TpmHt::Persistent) => self
                .authorized_object(global_state, handle)
                .is_none_or(|obj| !obj.public_only),
            Some(TpmHt::NVIndex) => {
                let Some((_, nv_public)) = self.read_nv_index_public(handle) else {
                    return false;
                };
                // An empty authPolicy is reported by `check_policy_auth_session`.
                if nv_public.auth_policy.get_size() == 0
                    || self.is_policy_session_required(global_state, cc, handle_index, handle)
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
        StorageManager::new(&mut *self.platform.storage)
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
    fn update_nv_pin_count(&mut self, global_state: &mut GlobalState, handle: u32, success: bool) {
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
        let mut storage_mgr = StorageManager::new(&mut *self.platform.storage);
        if storage_mgr.write_item(handle, data_offset, &pin).is_ok() {
            global_state.update_nv |= if attrs.contains(tpm2::TpmaNv::ORDERLY) {
                UT_ORDERLY
            } else {
                UT_NV
            };
        }
    }

    /// Fails if the TPM is in DA lockout for the authValue about to be used (C
    /// `CheckLockedOut()`; `lockout_auth` selects the `lockoutAuth` check), and records that DA
    /// protection was used in this power cycle (`SU_DA_USED_VALUE`).
    fn check_da_lockout(
        &mut self,
        global_state: &mut GlobalState,
        lockout_auth: bool,
    ) -> Result<(), TpmRc> {
        self.check_locked_out(global_state, lockout_auth)?;
        if !global_state.da_used {
            global_state.da_used = true;
            if global_state.nv_available {
                global_state.orderly_state = 0xFFFE;
                let _ = self
                    .platform
                    .storage
                    .write_nv(4, &global_state.orderly_state.to_be_bytes());
            } else {
                global_state.clear_orderly = true;
            }
        }
        Ok(())
    }

    /// Registers a DA authorization failure (the side effects of C `IncrementLockout()` when DA
    /// applies): disables `lockoutAuth` if `lockout_auth`, otherwise increments `failedTries`
    /// (unless DA is disabled with `recoveryTime == 0`), and restarts the matching self-healing
    /// timer.
    fn register_da_failure(&mut self, global_state: &mut GlobalState, lockout_auth: bool) {
        if lockout_auth {
            global_state.lockout_auth_enabled = false;
            global_state.lockout_timer = global_state.tpm_time_ms as i64;
            // With lockoutRecovery == 0, lockoutAuth is re-enabled at the next startup anyway,
            // so NV is not updated (C `IncrementLockout()`).
            if global_state.lockout_recovery != 0 {
                if global_state.nv_available {
                    self.save_hierarchy_auths(global_state);
                } else {
                    global_state.da_pending_on_nv = true;
                }
            }
        } else {
            if global_state.recovery_time != 0 {
                global_state.failed_tries = global_state.failed_tries.saturating_add(1);
                if global_state.nv_available {
                    let _ = self
                        .platform
                        .storage
                        .write_nv(32, &global_state.failed_tries.to_be_bytes());
                } else {
                    global_state.da_pending_on_nv = true;
                }
            }
            global_state.self_heal_timer = global_state.tpm_time_ms as i64;
        }
        global_state.da_used = true;
        if global_state.nv_available {
            global_state.orderly_state = 0xFFFE;
            let _ = self
                .platform
                .storage
                .write_nv(4, &global_state.orderly_state.to_be_bytes());
        } else {
            global_state.clear_orderly = true;
        }
    }

    /// Helper to verify HMACs of authorization sessions.
    fn verify_session_hmacs(
        &mut self,
        global_state: &mut GlobalState,
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
            auth_handle_names[auth_handle_names_len] =
                handle_name(self, &mut *global_state, handle);
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
                let lockout_auth = handle == Handle::RH_LOCKOUT.0;
                let da_protected = self.has_da_protection(global_state, handle);

                // C `CheckAuthSession()`: a password session always uses the authValue, so DA
                // lockout is checked first, then whether the authValue may be used at all.
                if da_protected {
                    self.check_da_lockout(global_state, lockout_auth)?;
                }
                if self.is_policy_session_required(global_state, cc, h_idx, handle) {
                    return Err(TpmRc::AUTH_TYPE);
                }
                if !self.is_auth_value_available(global_state, cc, h_idx, handle) {
                    return Err(TpmRc::AUTH_UNAVAILABLE);
                }

                // C `CheckPWAuthSession()`: both values have their trailing zeros removed and
                // must then be identical (same length and contents).
                let expected_auth = self.handle_auth(global_state, handle);
                let provided_stripped = crate::util::strip_trailing_zeros(auth.hmac.get_buffer());
                let expected_stripped =
                    crate::util::strip_trailing_zeros(expected_auth.get_buffer());
                let auth_matches =
                    crate::util::constant_time_eq(expected_stripped, provided_stripped);
                self.update_nv_pin_count(global_state, handle, auth_matches);
                if !auth_matches {
                    let elen = expected_stripped.len().min(64);
                    global_state.debug_expected_auth[..elen]
                        .copy_from_slice(&expected_stripped[..elen]);
                    global_state.debug_expected_auth_len = elen;
                    let plen = provided_stripped.len().min(64);
                    global_state.debug_provided_auth[..plen]
                        .copy_from_slice(&provided_stripped[..plen]);
                    global_state.debug_provided_auth_len = plen;
                    // C `IncrementLockout()`: no DA side effects for a DA-exempt entity.
                    if da_protected {
                        self.register_da_failure(global_state, lockout_auth);
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
                let session_type = global_state
                    .session(session_handle)
                    .ok_or(TpmRc::HANDLE.with(pos))?
                    .session_type;
                if session_type == TpmSe::Trial {
                    return Err(TpmRc::ATTRIBUTES.with(pos));
                }
                // A session bound to a DA-protected entity (C `isDaBound`) is subject to DA
                // lockout however it is used, even if it authorizes nothing or a DA-exempt
                // entity (C `ParseSessionBuffer()`).
                let (is_da_bound, is_lockout_bound) = global_state
                    .session(session_handle)
                    .map_or((false, false), |s| (s.is_da_bound, s.is_lockout_bound));
                if is_da_bound {
                    self.check_da_lockout(global_state, is_lockout_bound)?;
                }
                if i >= cmd.session_to_handle_idx_len
                    && !auth.session_attributes.intersects(
                        TpmaSession::AUDIT | TpmaSession::ENCRYPT | TpmaSession::DECRYPT,
                    )
                {
                    return Err(TpmRc::ATTRIBUTES.with(pos));
                }

                let entity_auth = if i < cmd.session_to_handle_idx_len {
                    let h_idx = cmd.session_to_handle_idx[i];
                    self.handle_auth(global_state, cmd.handles[h_idx])
                } else {
                    OwnedAuth::default()
                };

                let dec_nonce = if i == 0 {
                    if let Some(dec_idx) = decrypt_session_idx {
                        if dec_idx != i {
                            let dec_handle = cmd.auth_sessions[dec_idx].session_handle.0;
                            global_state.session(dec_handle).map(|s| s.nonce_tpm)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                let enc_nonce = if i == 0 {
                    if let Some(enc_idx) = encrypt_session_idx {
                        if enc_idx != i && Some(enc_idx) != decrypt_session_idx {
                            let enc_handle = cmd.auth_sessions[enc_idx].session_handle.0;
                            global_state.session(enc_handle).map(|s| s.nonce_tpm)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                let entity_handle = if i < cmd.session_to_handle_idx_len {
                    let h_idx = cmd.session_to_handle_idx[i];
                    Some(cmd.handles[h_idx])
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
                    bind_entity,
                    bound_entity,
                    is_policy,
                    is_auth_value_needed,
                    is_password_needed,
                ) = {
                    let session_state = global_state
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
                        session_state.bind_entity,
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
                    Some(h) if bind_entity != Handle::RH_NULL => {
                        let name = self.handle_name(global_state, h);
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
                if let Some(s) = global_state.session_mut(session_handle) {
                    s.include_auth = include_auth;
                }

                let mut da_protected = false;
                if let Some(h) = entity_handle {
                    da_protected = self.has_da_protection(global_state, h);
                    // DA lockout only matters if the authValue is going to be used.
                    if include_auth && da_protected {
                        self.check_da_lockout(global_state, h == Handle::RH_LOCKOUT.0)?;
                    }
                    if is_policy {
                        if !self.is_entity_auth_policy_allowed(global_state, cc, h_idx, h) {
                            return Err(TpmRc::AUTH_UNAVAILABLE);
                        }
                    } else {
                        if self.is_policy_session_required(global_state, cc, h_idx, h) {
                            return Err(TpmRc::AUTH_TYPE);
                        }
                        if !self.is_auth_value_available(global_state, cc, h_idx, h) {
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
                    self.platform.crypto,
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
                    self.check_policy_auth_session(
                        global_state,
                        PolicyAuthCheck {
                            session_handle,
                            entity_handle: h,
                            handle_index: h_idx,
                            command_code,
                            parameters: cmd.parameters,
                            cp_hash: &cp_hash[..cp_hash_len],
                            handle_names: &auth_handle_names[..auth_handle_names_len],
                            pos,
                        },
                    )?;
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
                    self.update_nv_pin_count(global_state, h, auth_matches);
                }

                if !auth_matches {
                    // C `IncrementLockout()`: the failure counts against DA if the session is
                    // bound to a DA-protected entity (against lockoutAuth if bound to
                    // TPM_RH_LOCKOUT), or if the authValue of a DA-protected entity was used;
                    // otherwise it is reported as TPM_RC_BAD_AUTH without side effects.
                    if is_da_bound || (include_auth && da_protected) {
                        let lockout_auth =
                            is_lockout_bound || entity_handle == Some(Handle::RH_LOCKOUT.0);
                        self.register_da_failure(global_state, lockout_auth);
                        return Err(TpmRc::AUTH_FAIL.with(pos));
                    }
                    return Err(TpmRc::BAD_AUTH.with(pos));
                }

                let session_state = global_state
                    .session_mut(session_handle)
                    .ok_or(TpmRc::AUTH_FAIL.with(pos))?;
                session_state.nonce_caller = auth.nonce;

                if auth.session_attributes.0 & 0x80 != 0 {
                    session_state.audit_cp_hash[..cp_hash_len]
                        .copy_from_slice(&cp_hash[..cp_hash_len]);
                    session_state.audit_cp_hash_len = cp_hash_len;
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
    fn handle_policy_alg(
        &mut self,
        global_state: &GlobalState,
        handle: u32,
    ) -> Option<TpmiAlgHash> {
        if handle == Handle::RH_OWNER.0 {
            global_state.owner_alg
        } else if handle == Handle::RH_ENDORSEMENT.0 {
            global_state.endorsement_alg
        } else if handle == Handle::RH_PLATFORM.0 {
            global_state.platform_alg
        } else if handle == Handle::RH_LOCKOUT.0 {
            global_state.lockout_alg
        } else if let Some(obj) = global_state.find_transient_object(handle) {
            obj.public.name_alg
        } else if (0x81000000..=0x81FFFFFF).contains(&handle) {
            self.load_persistent_object(global_state, handle)
                .ok()
                .and_then(|obj| obj.public.name_alg)
        } else if Handle(handle).handle_type() == Some(TpmHt::NVIndex) {
            let storage_mgr = StorageManager::new(&mut *self.platform.storage);
            let metadata = storage_mgr.get_metadata(handle).ok()?;
            let read_len = core::cmp::min(metadata.data_size as usize, 1536);
            let mut read_buf = [0u8; 1536];
            storage_mgr
                .read_item(handle, 0, &mut read_buf[..read_len])
                .ok()?;
            let (_, nv_public, _, _) =
                crate::handler::nv_storage::unmarshal_nv_header(&read_buf[..read_len]).ok()?;
            Some(nv_public.name_alg)
        } else if (20..=22).contains(&handle) {
            global_state.pcr_policy_alg
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
    fn check_policy_auth_session(
        &mut self,
        global_state: &GlobalState,
        check: PolicyAuthCheck,
    ) -> Result<(), TpmRc> {
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

        let policy = self.handle_policy(global_state, entity_handle)?;
        let policy_alg = self.handle_policy_alg(global_state, entity_handle);
        let session = global_state
            .session(session_handle)
            .ok_or(TpmRc::HANDLE.with(pos))?;

        // IsAuthPolicyAvailable(): objects (other than sequence objects) and the PCR policy group
        // always have a policy available, even if it is empty; anything else needs a non-empty
        // authPolicy.
        let is_object = (0x80000000..=0x81FFFFFF).contains(&entity_handle)
            && global_state.find_active_sequence(entity_handle).is_none();
        let is_policy_pcr = (20..=22).contains(&entity_handle);
        if policy.get_size() == 0 && !is_object && !is_policy_pcr {
            return Err(TpmRc::AUTH_UNAVAILABLE);
        }

        // TPM2_PolicySecret() requires proof of the authValue of authHandle.
        if cc == TpmCc::PolicySecret && !session.is_password_needed && !session.is_auth_value_needed
        {
            return Err(TpmRc::MODE.with(pos));
        }

        if let Some(pcr_counter) = session.pcr_counter
            && pcr_counter != global_state.pcrs.update_counter
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
            if !global_state.nv_available {
                return Err(TpmRc::NV_UNAVAILABLE);
            }
            if session.timeout < global_state.tpm_time_ms
                || session.epoch != global_state.time_epoch
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
            let curr_locality = global_state.locality;
            if session.command_locality > 31 {
                if curr_locality != session.command_locality {
                    return Err(TpmRc::LOCALITY);
                }
            } else if curr_locality > 4 || (session.command_locality & (1 << curr_locality)) == 0 {
                return Err(TpmRc::LOCALITY);
            }
        }

        if session.policy_hash_len > 0 {
            let expected = &session.policy_hash[..session.policy_hash_len];
            let ok = if session.is_cp_hash_defined {
                expected == cp_hash
            } else if session.is_name_hash_defined {
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
                    self.platform.crypto,
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
            let storage_mgr = StorageManager::new(&mut *self.platform.storage);
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
            self.platform.crypto,
            auth_hash,
            template_bytes,
            &mut template_hash,
        )?;
        Ok(expected == &template_hash[..template_hash_len])
    }

    /// Process response parameters when authorization was validated inside the command handler.
    fn process_response_parameters_with_handler_validation(
        &mut self,
        global_state: &mut GlobalState,
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

        if param_size > 2048 {
            return Err(TpmRc::SIZE.to_rc());
        }
        let mut resp_params = [0u8; 2048];
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
                    _bind_entity,
                    _bound_entity,
                    _is_policy,
                    _is_auth_value_needed,
                    _is_password_needed,
                ) = {
                    let session_state = global_state
                        .session(session_handle)
                        .ok_or(TpmRc::HANDLE.with(Position::session((i + 1) as u8)))?;
                    session_key_buf[..session_state.session_key_len].copy_from_slice(
                        &session_state.session_key[..session_state.session_key_len],
                    );
                    session_key_len = session_state.session_key_len;
                    (
                        session_state.symmetric,
                        session_state.auth_hash,
                        session_state.bind_entity,
                        session_state.bound_entity,
                        session_state.session_type == TpmSe::Policy,
                        session_state.is_auth_value_needed,
                        session_state.is_password_needed,
                    )
                };

                let (is_xor, key_bits, sym_obj) = match symmetric {
                    Some(tpm2::TpmtSymDef::Cipher(sym_obj)) => {
                        if sym_obj.mode() != Some(TpmiAlgSymMode::CFB) {
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
                        self.handle_auth(global_state, cmd.handles[h_idx])
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
                        self.platform.crypto,
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
                        self.platform.crypto,
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
                    tpm2::crypto::encrypt(
                        self.platform.crypto,
                        sym_obj,
                        &derived_key[..(key_bits / 8) as usize],
                        &mut iv,
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
        if rp_hash_input_len > 2048 {
            return Err(TpmRc::SIZE.to_rc());
        }
        let mut rp_hash_input = [0u8; 2048];
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
                if global_state.exclusive_audit_session == Some(session_handle) {
                    resp_attrs |= 0x02;
                } else {
                    resp_attrs &= !0x02;
                }
            }

            let mut session_key_buf = [0u8; 128];
            let session_key_len;
            let (auth_hash, _nonce_caller, include_auth, policy_password) = {
                let session_state = global_state
                    .session(session_handle)
                    .ok_or(TpmRc::HANDLE.with(Position::session((i + 1) as u8)))?;
                session_key_buf[..session_state.session_key_len]
                    .copy_from_slice(&session_state.session_key[..session_state.session_key_len]);
                session_key_len = session_state.session_key_len;
                let is_policy = session_state.session_type == tpm2::TpmSe::Policy;
                let is_bound = session_state.bind_entity != Handle::RH_NULL
                    || session_state.bound_entity.get_size() > 0;
                let include_auth = (!is_policy && !is_bound)
                    || (is_policy
                        && (session_state.is_auth_value_needed
                            || session_state.is_password_needed))
                    || session_state.include_auth;
                (
                    session_state.auth_hash,
                    session_state.nonce_caller,
                    include_auth,
                    is_policy && session_state.is_password_needed,
                )
            };

            let mut rp_hash = [0u8; 64];
            let rp_hash_len = compute_hash(
                self.platform.crypto,
                auth_hash,
                &rp_hash_input[..rp_hash_input_len],
                &mut rp_hash,
            )?;

            let entity_auth = if i < cmd.session_to_handle_idx_len {
                let h_idx = cmd.session_to_handle_idx[i];
                if matches!(cc, TpmCc::SequenceComplete | TpmCc::EventSequenceComplete) {
                    cmd.handle_auths[h_idx]
                } else {
                    self.handle_auth(global_state, cmd.handles[h_idx])
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
                        self.platform.crypto,
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
            let (now_ms, time_epoch) = (global_state.tpm_time_ms, global_state.time_epoch);
            if let Some(session_state) = global_state.session_mut(session_handle) {
                if session_state.audit_cp_hash_len > 0 {
                    let mut extend_buf = [0u8; 192];
                    let d_len = session_state.audit_digest_len;
                    if let Some(ref d) = session_state.audit_digest {
                        extend_buf[..d_len].copy_from_slice(&d[..d_len]);
                    } else {
                        extend_buf[..d_len].fill(0);
                    }
                    let cp_len = session_state.audit_cp_hash_len;
                    extend_buf[d_len..d_len + cp_len]
                        .copy_from_slice(&session_state.audit_cp_hash[..cp_len]);
                    extend_buf[d_len + cp_len..d_len + cp_len + rp_hash_len]
                        .copy_from_slice(&rp_hash[..rp_hash_len]);

                    let mut new_digest = [0u8; 64];
                    let new_digest_len = compute_hash(
                        self.platform.crypto,
                        auth_hash,
                        &extend_buf[..d_len + cp_len + rp_hash_len],
                        &mut new_digest,
                    )?;
                    let mut d_array = [0u8; 64];
                    d_array[..new_digest_len].copy_from_slice(&new_digest[..new_digest_len]);
                    session_state.audit_digest = Some(d_array);
                    session_state.audit_digest_len = new_digest_len;
                    session_state.audit_cp_hash_len = 0;
                }
                session_state.nonce_tpm = nonce_tpm_new;
                if auth.session_attributes.0 & 0x80 != 0 {
                    session_state.bind_entity = Handle::RH_NULL;
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
                    session_state.is_name_hash_defined = false;
                    session_state.is_template_hash_defined = false;
                    session_state.is_auth_value_needed = false;
                    session_state.is_password_needed = false;
                    session_state.check_nv_written = false;
                    session_state.nv_written_state = false;
                }
            }

            if !continue_session {
                global_state.remove_session(session_handle);
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
        global_state: &mut GlobalState,
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
        if resp_params_size > 2048 {
            return Err(TpmRc::SIZE.to_rc());
        }
        let mut resp_params = [0u8; 2048];
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
                _bind_entity,
                _bound_entity,
                _is_policy,
                _is_auth_value_needed,
                _is_password_needed,
            ) = {
                let session_state = global_state
                    .session(session_handle)
                    .ok_or(TpmRc::HANDLE.with(Position::session((i + 1) as u8)))?;
                session_key_buf[..session_state.session_key_len]
                    .copy_from_slice(&session_state.session_key[..session_state.session_key_len]);
                session_key_len = session_state.session_key_len;
                (
                    session_state.symmetric,
                    session_state.auth_hash,
                    session_state.bind_entity,
                    session_state.bound_entity,
                    session_state.session_type == TpmSe::Policy,
                    session_state.is_auth_value_needed,
                    session_state.is_password_needed,
                )
            };

            let (is_xor, key_bits, sym_obj) = match symmetric {
                Some(tpm2::TpmtSymDef::Cipher(sym_obj)) => {
                    if sym_obj.mode() != Some(TpmiAlgSymMode::CFB) {
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
                    self.handle_auth(global_state, cmd.handles[h_idx])
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
                    self.platform.crypto,
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
                    self.platform.crypto,
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
                tpm2::crypto::encrypt(
                    self.platform.crypto,
                    sym_obj,
                    &derived_key[..(key_bits / 8) as usize],
                    &mut iv,
                    &mut resp_params[2..2 + first_param_size],
                )
                .map_err(|_| TpmRc::SYMMETRIC.with(Position::session(1)))?;
            }
        }

        let rp_hash_input_len = 4 + 4 + resp_params_size;
        if rp_hash_input_len > 2048 {
            return Err(TpmRc::SIZE.to_rc());
        }
        let mut rp_hash_input = [0u8; 2048];
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
                if global_state.exclusive_audit_session == Some(session_handle) {
                    resp_attrs |= 0x02;
                } else {
                    resp_attrs &= !0x02;
                }
            }

            let mut session_key_buf = [0u8; 128];
            let session_key_len;
            let (auth_hash, _nonce_caller, include_auth, policy_password) = {
                let session_state = global_state
                    .session(session_handle)
                    .ok_or(TpmRc::HANDLE.with(Position::session((i + 1) as u8)))?;
                session_key_buf[..session_state.session_key_len]
                    .copy_from_slice(&session_state.session_key[..session_state.session_key_len]);
                session_key_len = session_state.session_key_len;
                let is_policy = session_state.session_type == tpm2::TpmSe::Policy;
                let is_bound = session_state.bind_entity != Handle::RH_NULL
                    || session_state.bound_entity.get_size() > 0;
                let include_auth = (!is_policy && !is_bound)
                    || (is_policy
                        && (session_state.is_auth_value_needed
                            || session_state.is_password_needed))
                    || session_state.include_auth;
                (
                    session_state.auth_hash,
                    session_state.nonce_caller,
                    include_auth,
                    is_policy && session_state.is_password_needed,
                )
            };

            let mut rp_hash = [0u8; 64];
            let rp_hash_len = compute_hash(
                self.platform.crypto,
                auth_hash,
                &rp_hash_input[..rp_hash_input_len],
                &mut rp_hash,
            )?;

            let entity_auth = if i < cmd.session_to_handle_idx_len {
                let h_idx = cmd.session_to_handle_idx[i];
                if matches!(cc, TpmCc::SequenceComplete | TpmCc::EventSequenceComplete) {
                    cmd.handle_auths[h_idx]
                } else {
                    self.handle_auth(global_state, cmd.handles[h_idx])
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
                        self.platform.crypto,
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
            let (now_ms, time_epoch) = (global_state.tpm_time_ms, global_state.time_epoch);
            if let Some(session_state) = global_state.session_mut(session_handle) {
                if session_state.audit_cp_hash_len > 0 {
                    let mut extend_buf = [0u8; 192];
                    let d_len = session_state.audit_digest_len;
                    if let Some(ref d) = session_state.audit_digest {
                        extend_buf[..d_len].copy_from_slice(&d[..d_len]);
                    } else {
                        extend_buf[..d_len].fill(0);
                    }
                    let cp_len = session_state.audit_cp_hash_len;
                    extend_buf[d_len..d_len + cp_len]
                        .copy_from_slice(&session_state.audit_cp_hash[..cp_len]);
                    extend_buf[d_len + cp_len..d_len + cp_len + rp_hash_len]
                        .copy_from_slice(&rp_hash[..rp_hash_len]);

                    let mut new_digest = [0u8; 64];
                    let new_digest_len = compute_hash(
                        self.platform.crypto,
                        auth_hash,
                        &extend_buf[..d_len + cp_len + rp_hash_len],
                        &mut new_digest,
                    )?;
                    let mut d_array = [0u8; 64];
                    d_array[..new_digest_len].copy_from_slice(&new_digest[..new_digest_len]);
                    session_state.audit_digest = Some(d_array);
                    session_state.audit_digest_len = new_digest_len;
                    session_state.audit_cp_hash_len = 0;
                }
                session_state.nonce_tpm = nonce_tpm_new;
                if auth.session_attributes.0 & 0x80 != 0 {
                    session_state.bind_entity = Handle::RH_NULL;
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
                    session_state.is_name_hash_defined = false;
                    session_state.is_template_hash_defined = false;
                    session_state.is_auth_value_needed = false;
                    session_state.is_password_needed = false;
                    session_state.check_nv_written = false;
                    session_state.nv_written_state = false;
                }
            }

            if !continue_session {
                global_state.remove_session(session_handle);
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

    fn validate_command_handles(
        &mut self,
        global_state: &GlobalState,
        cc: TpmCc,
        handles: &[u32],
        handles_len: usize,
        _parameters: &[u8],
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

            // Handle types of the NV commands (`TPMI_RH_NV_INDEX`, `TPMI_RH_PLATFORM`,
            // `TPMI_RH_PROVISION`, `TPMI_RH_NV_AUTH`). The accessibility of NV Index handles
            // (C `NvIndexIsAccessible`) is checked in handle order by the loop below.
            if cc == TpmCc::NVUndefineSpaceSpecial && handles_len >= 2 {
                let nv_index = handles[0];
                let platform = handles[1];
                if Handle(nv_index).handle_type() != Some(TpmHt::NVIndex) {
                    return Err(TpmRc::VALUE.with(Position::handle(1)));
                }
                if platform != Handle::RH_PLATFORM.0 {
                    return Err(TpmRc::VALUE.with(Position::handle(2)));
                }
            } else if matches!(
                cc,
                TpmCc::NVUndefineSpace
                    | TpmCc::NVRead
                    | TpmCc::NVWrite
                    | TpmCc::NVIncrement
                    | TpmCc::NVExtend
                    | TpmCc::NVSetBits
                    | TpmCc::NVWriteLock
                    | TpmCc::NVReadLock
            ) && handles_len >= 2
            {
                if cc == TpmCc::NVUndefineSpace {
                    let auth_handle = handles[0];
                    if auth_handle != Handle::RH_OWNER.0 && auth_handle != Handle::RH_PLATFORM.0 {
                        return Err(TpmRc::VALUE.with(Position::handle(1)));
                    }
                }
                let nv_index = handles[1];
                if Handle(nv_index).handle_type() != Some(TpmHt::NVIndex) {
                    return Err(TpmRc::VALUE.with(Position::handle(2)));
                }
            } else if cc == TpmCc::NVChangeAuth && handles_len >= 1 {
                let nv_index = handles[0];
                if Handle(nv_index).handle_type() != Some(TpmHt::NVIndex) {
                    return Err(TpmRc::VALUE.with(Position::handle(1)));
                }
            } else if cc == TpmCc::NVCertify && handles_len >= 3 {
                // `signHandle`: TPMI_DH_OBJECT+, `authHandle`: TPMI_RH_NV_AUTH,
                // `nvIndex`: TPMI_RH_NV_INDEX.
                let sign_handle = handles[0];
                if sign_handle != Handle::RH_NULL.0 && !matches!(sign_handle >> 24, 0x80 | 0x81) {
                    return Err(TpmRc::VALUE.with(Position::handle(1)));
                }
                let nv_auth = handles[1];
                if nv_auth != Handle::RH_OWNER.0
                    && nv_auth != Handle::RH_PLATFORM.0
                    && Handle(nv_auth).handle_type() != Some(TpmHt::NVIndex)
                {
                    return Err(TpmRc::VALUE.with(Position::handle(2)));
                }
                let nv_index = handles[2];
                if Handle(nv_index).handle_type() != Some(TpmHt::NVIndex) {
                    return Err(TpmRc::VALUE.with(Position::handle(3)));
                }
            }
        }
        // Number of persistent objects already copied into a (temporary) object slot by this
        // command (`ObjectLoadEvict`).
        let mut persistent_loaded = 0usize;
        for (h_idx, &handle) in handles.iter().enumerate().take(handles_len) {
            let pos = Position::handle((h_idx + 1) as u8);
            // C `EntityGetLoadStatus`: every NV Index handle must be accessible
            // (`NvIndexIsAccessible`), whatever command it is passed to. Positions whose
            // interface type cannot hold an NV Index (objects, contexts, sessions, permanent
            // handles) reject it at handle unmarshaling instead (`TPM_RC_VALUE`, below).
            if Handle(handle).handle_type() == Some(TpmHt::NVIndex)
                && !expects_object_handle(cc, h_idx)
                && !is_expected_session_handle(cc, h_idx)
                && !expects_permanent_handle(cc, h_idx)
                && !matches!(
                    (cc, h_idx),
                    (TpmCc::CreateLoaded, 0) | (TpmCc::StartAuthSession, 0)
                )
            {
                self.check_nv_index_accessible(global_state, handle, pos)?;
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
                    if (handle & 0x00FF_FFFF) > 0x0000_FFFF {
                        return Err(TpmRc::VALUE.with(pos));
                    }
                    if let Some(obj) = global_state.find_transient_object(handle) {
                        if (obj.hierarchy == 0x40000001 && !global_state.sh_enable)
                            || (obj.hierarchy == 0x4000000B && !global_state.eh_enable)
                            || (obj.hierarchy == 0x4000000C && !global_state.ph_enable)
                        {
                            return Err(TpmRc::HIERARCHY.with(pos));
                        }
                    } else if global_state.find_active_sequence(handle).is_none() {
                        return Err(match h_idx {
                            0 => TpmRc::REFERENCE_H0,
                            1 => TpmRc::REFERENCE_H1,
                            _ => TpmRc::REFERENCE_H2,
                        });
                    }
                } else if handle >> 24 == 0x81 {
                    self.load_evict_status(global_state, cc, handle, pos, &mut persistent_loaded)?;
                } else {
                    // `TPMI_DH_OBJECT` accepts only transient and persistent handles
                    // (`TPMI_DH_OBJECT_Unmarshal`); permanent handles are invalid values,
                    // including for the parent handles of Create, Load and ObjectChangeAuth.
                    return Err(TpmRc::VALUE.with(pos));
                }
            } else if cc == TpmCc::CreateLoaded && h_idx == 0 {
                let mso = handle >> 24;
                if mso == 0x80 {
                    // Sequence objects are loaded objects; the handler rejects them as
                    // non-parents (`TPM_RC_TYPE + RC_H1`).
                    if global_state.find_transient_object(handle).is_none()
                        && global_state.find_active_sequence(handle).is_none()
                    {
                        return Err(TpmRc::REFERENCE_H0);
                    }
                } else if mso == 0x81 {
                    self.load_evict_status(global_state, cc, handle, pos, &mut persistent_loaded)?;
                } else if mso != 0x40 {
                    return Err(TpmRc::VALUE.with(pos));
                }
            } else if expects_context_handle(cc, h_idx) {
                // `TPMI_DH_CONTEXT` admits only HMAC/policy session and transient handles; every
                // other handle (persistent, permanent, ...) is `TPM_RC_VALUE` at its position.
                let mso = handle >> 24;
                if mso == 0x80 {
                    if (handle & 0x00FF_FFFF) > 0x0000_FFFF {
                        return Err(TpmRc::VALUE.with(pos));
                    }
                    if global_state.find_transient_object(handle).is_none()
                        && global_state.find_active_sequence(handle).is_none()
                    {
                        return Err(reference_h(h_idx));
                    }
                } else if mso == 0x02 || mso == 0x03 {
                    check_session_handle_status(global_state, handle, h_idx, mso == 0x03)?;
                } else {
                    return Err(TpmRc::VALUE.with(pos));
                }
            } else if cc == TpmCc::GetSessionAuditDigest && h_idx == 2 {
                // `sessionHandle` is a `TPMI_SH_HMAC`.
                if handle >> 24 != 0x02 {
                    return Err(TpmRc::VALUE.with(pos));
                }
                check_session_handle_status(global_state, handle, h_idx, false)?;
            } else if expects_policy_session_handle(cc, h_idx) {
                // `TPMI_SH_POLICY`: any other handle type is `TPM_RC_VALUE` at its position.
                if handle >> 24 != 0x03 {
                    return Err(TpmRc::VALUE.with(pos));
                }
                check_session_handle_status(global_state, handle, h_idx, true)?;
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
                        if global_state.find_transient_object(handle).is_none() {
                            return Err(TpmRc::REFERENCE_H0);
                        }
                    } else if handle >> 24 == 0x81 {
                        self.load_evict_status(
                            global_state,
                            cc,
                            handle,
                            pos,
                            &mut persistent_loaded,
                        )?;
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
                            | 0x40000010 // RH_AUTH_00 (VENDOR_PERMANENT)
                        );
                        if !is_valid_entity {
                            return Err(TpmRc::VALUE.with(pos));
                        }
                    } else if mso == 0x80 {
                        if global_state.find_transient_object(handle).is_none() {
                            return Err(TpmRc::REFERENCE_H1);
                        }
                    } else if mso == 0x81 {
                        self.load_evict_status(
                            global_state,
                            cc,
                            handle,
                            pos,
                            &mut persistent_loaded,
                        )?;
                    } else if mso == 0x00 && handle > 23 {
                        return Err(TpmRc::VALUE.with(pos));
                    }
                }
            } else if expects_permanent_handle(cc, h_idx) {
                if !(0x40000000..=0x40FFFFFF).contains(&handle) {
                    return Err(TpmRc::VALUE.with(pos));
                }
                // The exact `TPMI_RH_*` interface type of the handle (e.g. `TPMI_RH_ENDORSEMENT`,
                // `TPMI_RH_PROVISION`): any other value fails at handle unmarshaling.
                if let Some(allowed) = permanent_handle_type(cc, h_idx)
                    && !allowed.contains(&handle)
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
                );
                if !is_valid_hierarchy {
                    return Err(TpmRc::VALUE.with(pos));
                }
            } else if (0x40000000..=0x40FFFFFF).contains(&handle) {
                let is_valid_hierarchy = matches!(
                    handle,
                    0x40000001 // Owner
                    | 0x4000000B // Endorsement
                    | 0x4000000C // Platform
                    | 0x4000000A // Lockout
                    | 0x40000007 // Null
                    | 0x40000010 // RH_AUTH_00 (VENDOR_PERMANENT)
                );
                if !is_valid_hierarchy {
                    return Err(TpmRc::VALUE.with(pos));
                }
            } else if handle >> 24 == 0x80 {
                // Any other transient handle must reference a loaded object (`IsObjectPresent`).
                if global_state.find_transient_object(handle).is_none()
                    && global_state.find_active_sequence(handle).is_none()
                {
                    return Err(reference_h(h_idx));
                }
            } else if handle >> 24 == 0x81 {
                // Any other persistent handle is loaded like an object handle (`ObjectLoadEvict`).
                self.load_evict_status(global_state, cc, handle, pos, &mut persistent_loaded)?;
            }
            if (0x40000000..=0x40FFFFFF).contains(&handle)
                && !(cc == TpmCc::HierarchyControl && h_idx == 1)
                && cc != TpmCc::Load
            {
                // `VENDOR_PERMANENT_AUTH_HANDLE` (`TPM_RH_AUTH_00`) is part of the endorsement
                // hierarchy (`EntityGetLoadStatus`).
                if handle == Handle::RH_AUTH_00.0 && !global_state.eh_enable {
                    return Err(TpmRc::HIERARCHY.with(pos));
                }
                if handle == 0x40000001 && !global_state.sh_enable {
                    return Err(TpmRc::HIERARCHY.with(pos));
                }
                if handle == 0x4000000B && !global_state.eh_enable {
                    return Err(TpmRc::HIERARCHY.with(pos));
                }
                if handle == 0x4000000C && !global_state.ph_enable {
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
    ///    command, counted in `persistent_loaded`): otherwise `TPM_RC_OBJECT_MEMORY`.
    /// 3. An undefined persistent handle is `TPM_RC_HANDLE` at `pos`.
    /// 4. An endorsement-hierarchy object while `ehEnable` is clear is `TPM_RC_HANDLE` at `pos`,
    ///    except for `TPM2_EvictControl`.
    fn load_evict_status(
        &mut self,
        global_state: &GlobalState,
        cc: TpmCc,
        handle: u32,
        pos: Position,
        persistent_loaded: &mut usize,
    ) -> Result<(), TpmRc> {
        let hierarchy_enabled = if handle >= 0x8180_0000 {
            global_state.ph_enable
        } else {
            global_state.sh_enable
        };
        if !hierarchy_enabled {
            return Err(TpmRc::HANDLE.with(pos));
        }
        let used = global_state.transient_objects.iter().flatten().count()
            + global_state.active_sequences.iter().flatten().count()
            + *persistent_loaded;
        if used >= MAX_LOADED_OBJECTS {
            return Err(TpmRc::OBJECT_MEMORY);
        }
        let hierarchy = match self.read_persistent_object(handle) {
            Ok(obj) => obj.hierarchy,
            Err(err) if err == TpmRc::HANDLE.to_rc() => return Err(TpmRc::HANDLE.with(pos)),
            Err(err) => return Err(err),
        };
        if hierarchy == Handle::RH_ENDORSEMENT.0
            && !global_state.eh_enable
            && cc != TpmCc::EvictControl
        {
            return Err(TpmRc::HANDLE.with(pos));
        }
        *persistent_loaded += 1;
        Ok(())
    }

    /// Checks that NV Index `handle` is accessible (C `NvIndexIsAccessible`): the index must be
    /// defined, and its hierarchy must be enabled (`phEnableNV` for `TPMA_NV_PLATFORMCREATE`
    /// indices, `shEnable` otherwise).
    ///
    /// Returns `TPM_RC_HANDLE` at `pos` if the index is not accessible.
    fn check_nv_index_accessible(
        &mut self,
        global_state: &GlobalState,
        handle: u32,
        pos: Position,
    ) -> Result<(), TpmRc> {
        let storage = crate::storage::manager::StorageManager::new(&mut *self.platform.storage);
        let metadata = storage
            .get_metadata(handle)
            .map_err(|_| TpmRc::HANDLE.with(pos))?;
        let enabled = if tpm2::TpmaNv(metadata.attributes).contains(tpm2::TpmaNv::PLATFORMCREATE) {
            global_state.ph_enable_nv
        } else {
            global_state.sh_enable
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
        _global_state: &GlobalState,
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
        global_state: &mut GlobalState,
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

        if !global_state.initialized && cc != TpmCc::Startup {
            return Err(TpmRc::INITIALIZE);
        }

        let mut handler = CommandHandler::new(self, global_state);
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
            TpmCc::MAC => handler.mac(request),
            TpmCc::NVDefineSpace => handler.nv_define_space(request),
            TpmCc::NVUndefineSpace => handler.nv_undefine_space(request),
            TpmCc::NVUndefineSpaceSpecial => handler.nv_undefine_space_special(request),
            TpmCc::NVReadPublic => handler.nv_read_public(request),
            TpmCc::GetCapability => handler.get_capability(request),
            TpmCc::TestParms => handler.test_parms(request),
            TpmCc::SelfTest => handler.self_test(request),
            TpmCc::IncrementalSelfTest => handler.incremental_self_test(request),
            TpmCc::GetTestResult => handler.get_test_result(request),
            TpmCc::Certify => handler.certify(request),
            TpmCc::Quote => handler.quote(request),
            TpmCc::GetSessionAuditDigest => handler.get_session_audit_digest(request),
            TpmCc::GetCommandAuditDigest => handler.get_command_audit_digest(request),
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
            TpmCc::PolicyAuthValue => handler.policy_auth_value(request),
            TpmCc::PolicyPassword => handler.policy_password(request),
            TpmCc::PolicyPCR => handler.policy_pcr(request),
            TpmCc::Hash => handler.hash(request),
            TpmCc::HashSequenceStart => handler.hash_sequence_start(request),
            TpmCc::SequenceUpdate => handler.sequence_update(request),
            TpmCc::SequenceComplete => handler.sequence_complete(request),
            TpmCc::EventSequenceComplete => handler.event_sequence_complete(request),
            TpmCc::MACStart => handler.mac_start(request),
            TpmCc::PolicyRestart => handler.policy_restart(request),
            TpmCc::ECDHKeyGen => handler.ecdh_keygen(request),
            TpmCc::ECCParameters => handler.ecc_parameters(request),
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
        TpmCc::MAC => 1,
        TpmCc::NVDefineSpace => 1,
        TpmCc::NVUndefineSpace => 2,
        TpmCc::NVUndefineSpaceSpecial => 2,
        TpmCc::NVReadPublic => 1,
        TpmCc::GetCapability => 0,
        TpmCc::Certify => 2,
        TpmCc::Quote => 1,
        TpmCc::GetSessionAuditDigest => 3,
        TpmCc::GetCommandAuditDigest => 2,
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
        TpmCc::Hash => 0,
        TpmCc::HashSequenceStart => 0,
        TpmCc::SequenceUpdate => 1,
        TpmCc::SequenceComplete => 1,
        TpmCc::EventSequenceComplete => 2,
        TpmCc::MACStart => 1,
        TpmCc::TestParms => 0,
        TpmCc::ECCParameters => 0,
        TpmCc::IncrementalSelfTest => 0,
        TpmCc::GetTestResult => 0,
        TpmCc::PolicyRestart => 1,
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
            | TpmCc::SetPrimaryPolicy
            | TpmCc::NVGlobalWriteLock
            | TpmCc::GetCommandAuditDigest
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
    if matches!(cc, TpmCc::SequenceComplete | TpmCc::EventSequenceComplete) {
        attr |= tpm2::TpmaCc::FLUSHED;
    }
    attr
}

/// Returns `false` for the commands that have the `NO_SESSIONS` attribute in
/// `CommandAttributeData.h` (`IsSessionAllowed`): `TPM2_Startup`, `TPM2_ContextLoad`,
/// `TPM2_ContextSave` and `TPM2_FlushContext`. Sending them with `TPM_ST_SESSIONS` fails with
/// `TPM_RC_AUTH_CONTEXT`.
pub(crate) fn is_session_allowed(cc: TpmCc) -> bool {
    !matches!(
        cc,
        TpmCc::Startup | TpmCc::ContextLoad | TpmCc::ContextSave | TpmCc::FlushContext
    )
}

/// List of TPM 2.0 command codes supported by this engine implementation.
/// The command codes (`TpmCc`) are defined in TCG TPM 2.0 Library Specification Part 3: Commands.
pub(crate) const SUPPORTED_COMMANDS: [TpmCc; 103] = [
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
];

pub(crate) fn is_command_supported(cc: TpmCc) -> bool {
    SUPPORTED_COMMANDS.contains(&cc)
}

/// Returns whether `cc` allows a session with `TPMA_SESSION_DECRYPT` (i.e. its first command
/// parameter is a `TPM2B` that may be encrypted).
///
/// Mirrors the `DECRYPT_2` attribute in the C reference `CommandAttributeData.h`, restricted to
/// the commands in [`SUPPORTED_COMMANDS`]. Notably `TPM2_EncryptDecrypt` is absent because its
/// first parameter is a `TPMI_YES_NO`, not a `TPM2B`.
fn command_supports_decryption(cc: TpmCc) -> bool {
    matches!(
        cc,
        TpmCc::ActivateCredential
            | TpmCc::Certify
            | TpmCc::CertifyCreation
            | TpmCc::Commit
            | TpmCc::Create
            | TpmCc::CreateLoaded
            | TpmCc::CreatePrimary
            | TpmCc::Duplicate
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
            | TpmCc::NVExtend
            | TpmCc::NVWrite
            | TpmCc::ObjectChangeAuth
            | TpmCc::PCREvent
            | TpmCc::PCRSetAuthPolicy
            | TpmCc::PCRSetAuthValue
            | TpmCc::PolicyAuthorize
            | TpmCc::PolicyCounterTimer
            | TpmCc::PolicyCpHash
            | TpmCc::PolicyDuplicationSelect
            | TpmCc::PolicyNV
            | TpmCc::PolicyNameHash
            | TpmCc::PolicyPCR
            | TpmCc::PolicySecret
            | TpmCc::PolicySigned
            | TpmCc::PolicyTemplate
            | TpmCc::PolicyTicket
            | TpmCc::Quote
            | TpmCc::RSADecrypt
            | TpmCc::RSAEncrypt
            | TpmCc::Rewrap
            | TpmCc::SequenceComplete
            | TpmCc::SequenceUpdate
            | TpmCc::SetPrimaryPolicy
            | TpmCc::Sign
            | TpmCc::StartAuthSession
            | TpmCc::StirRandom
            | TpmCc::VerifySignature
    )
}

/// Returns whether `cc` allows a session with `TPMA_SESSION_ENCRYPT` (i.e. its first response
/// parameter is a `TPM2B` that may be encrypted).
///
/// Mirrors the `ENCRYPT_2` attribute in the C reference `CommandAttributeData.h`, restricted to
/// the commands in [`SUPPORTED_COMMANDS`].
fn command_supports_encryption(cc: TpmCc) -> bool {
    matches!(
        cc,
        TpmCc::ActivateCredential
            | TpmCc::Certify
            | TpmCc::CertifyCreation
            | TpmCc::Commit
            | TpmCc::Create
            | TpmCc::CreateLoaded
            | TpmCc::CreatePrimary
            | TpmCc::Duplicate
            | TpmCc::ECDHKeyGen
            | TpmCc::ECDHZGen
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
    )
}

fn command_resp_handles_size(cc: TpmCc) -> usize {
    match cc {
        TpmCc::CreatePrimary
        | TpmCc::StartAuthSession
        | TpmCc::ContextLoad
        | TpmCc::CreateLoaded
        | TpmCc::LoadExternal
        | TpmCc::Load
        | TpmCc::HashSequenceStart
        | TpmCc::MACStart => 4,
        _ => 0,
    }
}

fn compute_nv_name<C: CryptoProvider>(
    crypto: &C,
    name_alg: TpmiAlgHash,
    public_area_bytes: &[u8],
) -> Result<OwnedName, TpmRc> {
    let mut name_bytes = [0u8; 66];
    let offset = name_alg.marshal((&mut name_bytes[..2]).try_into().unwrap());
    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(crypto, name_alg, public_area_bytes, &mut digest_buf)
        .map_err(|_| TpmRc::FAILURE)?;
    let digest_slice = digest.digest();
    name_bytes[offset..offset + digest_slice.len()].copy_from_slice(digest_slice);
    OwnedName::from_bytes(&name_bytes[..offset + digest_slice.len()]).map_err(|_| TpmRc::FAILURE)
}

fn handle_name<C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>(
    ctx: &mut TpmEngine<'_, C, S, T, R>,
    global_state: &mut GlobalState,
    handle: u32,
) -> OwnedName {
    if global_state.find_active_sequence(handle).is_some() {
        return OwnedName::default();
    }
    for obj in global_state.transient_objects.iter().flatten() {
        if obj.handle == handle {
            return obj.name;
        }
    }
    if Handle(handle).handle_type() == Some(TpmHt::NVIndex) {
        let storage_mgr = StorageManager::new(&mut *ctx.platform.storage);
        if let Ok(metadata) = storage_mgr.get_metadata(handle) {
            let read_len = core::cmp::min(metadata.data_size as usize, 1536);
            let mut read_buf = [0u8; 1536];
            if storage_mgr
                .read_item(handle, 0, &mut read_buf[..read_len])
                .is_ok()
                && let Ok((_, nv_public_struct, _, _, hash_target)) =
                    crate::handler::nv_storage::unmarshal_nv_header_bytes(&read_buf[..read_len])
                && let Ok(nv_name) = compute_nv_name(
                    &*ctx.platform.crypto,
                    nv_public_struct.name_alg,
                    hash_target,
                )
            {
                return nv_name;
            }
        }
    } else if (0x81000000..=0x81FFFFFF).contains(&handle) {
        // A persistent object of a disabled hierarchy looks undefined (`ObjectLoadEvict`).
        if let Ok(obj) = ctx.load_persistent_object(global_state, handle) {
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
                | TpmCc::ClockSet
                | TpmCc::ClockRateAdjust
                | TpmCc::PCRAllocate
                | TpmCc::PCRSetAuthPolicy
                | TpmCc::GetTime
                | TpmCc::NVDefineSpace
                | TpmCc::NVGlobalWriteLock
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
        // TPMI_RH_HIERARCHY_AUTH / TPMI_RH_HIERARCHY_POLICY (ACTs are not implemented)
        TpmCc::HierarchyChangeAuth | TpmCc::SetPrimaryPolicy => {
            &[OWNER, ENDORSEMENT, PLATFORM, LOCKOUT]
        }
        // TPMI_RH_PROVISION
        TpmCc::EvictControl
        | TpmCc::ClockSet
        | TpmCc::ClockRateAdjust
        | TpmCc::NVDefineSpace
        | TpmCc::NVGlobalWriteLock => &[OWNER, PLATFORM],
        // TPMI_RH_CLEAR
        TpmCc::Clear | TpmCc::ClearControl => &[LOCKOUT, PLATFORM],
        // TPMI_RH_PLATFORM
        TpmCc::ChangePPS | TpmCc::ChangeEPS | TpmCc::PCRAllocate | TpmCc::PCRSetAuthPolicy => {
            &[PLATFORM]
        }
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
                | TpmCc::Commit
                | TpmCc::Rewrap
                | TpmCc::PolicySigned
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
        )
    } else {
        false
    }
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

/// Validates a session handle of the handle area (`TPMI_SH_HMAC` / `TPMI_SH_POLICY` /
/// `TPMI_DH_CONTEXT` unmarshaling followed by `EntityGetLoadStatus`): the handle must lie within
/// the session handle range (`TPM_RC_VALUE`), its slot must hold a loaded session
/// (`TPM_RC_REFERENCE_H0 + h_idx`), and that session must be of the type named by the handle
/// (`TPM_RC_HANDLE`).
fn check_session_handle_status(
    global_state: &GlobalState,
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
        | TpmCc::PolicyTicket => handle_index == 0,
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
                | TpmCc::Commit
                | TpmCc::Sign
                | TpmCc::RSADecrypt
                | TpmCc::ECDHZGen
                | TpmCc::MAC
                | TpmCc::NVDefineSpace
                | TpmCc::NVUndefineSpace
                | TpmCc::NVUndefineSpaceSpecial
                | TpmCc::Certify
                | TpmCc::Quote
                | TpmCc::GetSessionAuditDigest
                | TpmCc::GetCommandAuditDigest
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
        )
    } else {
        false
    }
}

/// Returns whether `cc` requires the ADMIN role for its handle at `handle_index`.
pub fn is_admin_role_auth(cc: TpmCc, handle_index: usize) -> bool {
    command_auth_role(cc, handle_index) == AuthRole::Admin
}

fn handle_is_authorized(
    global_state: &GlobalState,
    cc: TpmCc,
    handle_index: usize,
    handle: u32,
    auth_sessions: &[TpmsAuthCommand],
) -> bool {
    if handle_requires_auth(cc, handle_index) {
        return true;
    }
    for auth in auth_sessions {
        let session_handle = auth.session_handle.0;
        if let Some(session_state) = global_state.session(session_handle)
            && session_state.bind_entity.0 == handle
        {
            return true;
        }
    }
    false
}

fn compute_hash_and_hmac(
    crypto: &impl CryptoProvider,
    auth_hash: TpmiAlgHash,
    key: &[u8],
    updates_hash: &[&[u8]],
    updates_hmac: &[&[u8]],
    hash_out: &mut [u8],
    hmac_out: &mut [u8],
) -> Result<(usize, usize), TpmRc> {
    let mut hash_ctx =
        tpm2::crypto::HashCtx::new(crypto, auth_hash).map_err(|_| TpmRc::HASH.to_rc())?;
    for data in updates_hash {
        hash_ctx.update(data).map_err(|_| TpmRc::HASH.to_rc())?;
    }
    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = hash_ctx
        .finalize(&mut digest_buf)
        .map_err(|_| TpmRc::HASH.to_rc())?;
    let digest_slice = digest.digest();

    let mut hmac_state =
        tpm2::crypto::HmacCtx::new(crypto, auth_hash, key).map_err(|_| TpmRc::HASH.to_rc())?;
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
    crypto: &impl CryptoProvider,
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

    kdfa(
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
    crypto: &impl CryptoProvider,
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
    let mut mask = [0u8; 2048];
    if data_len > mask.len() {
        return Err(TpmRc::SIZE.to_rc());
    }
    let mask_buf = &mut mask[..data_len];
    kdfa(
        crypto, auth_hash, key, b"XOR", context_u, context_v, total_bits, mask_buf,
    )
    .map_err(|_| TpmRc::HASH.to_rc())?;
    for (d, m) in data.iter_mut().zip(mask_buf.iter()) {
        *d ^= *m;
    }
    Ok(())
}

fn compute_hash(
    crypto: &impl CryptoProvider,
    auth_hash: TpmiAlgHash,
    data: &[u8],
    hash_out: &mut [u8],
) -> Result<usize, TpmRc> {
    let mut digest_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(crypto, auth_hash, data, &mut digest_buf)
        .map_err(|_| TpmRc::HASH.to_rc())?;
    let slice = digest.digest();
    let len = slice.len();
    hash_out[..len].copy_from_slice(slice);
    Ok(len)
}

fn compute_response_hmac(
    crypto: &impl CryptoProvider,
    auth_hash: TpmiAlgHash,
    key: &[u8],
    updates_hmac: &[&[u8]],
    hmac_out: &mut [u8],
) -> Result<usize, TpmRc> {
    let mut hmac_state =
        tpm2::crypto::HmacCtx::new(crypto, auth_hash, key).map_err(|_| TpmRc::HASH.to_rc())?;
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
    )
}

pub(crate) fn infer_alg_from_digest_size(size: usize) -> Option<tpm2::TpmiAlgHash> {
    match size {
        20 => Some(tpm2::TpmiAlgHash::Sha1),
        32 => Some(tpm2::TpmiAlgHash::Sha256),
        48 => Some(tpm2::TpmiAlgHash::Sha384),
        64 => Some(tpm2::TpmiAlgHash::Sha512),
        _ => None,
    }
}

pub(crate) fn digest_to_tpmt_ha<'a>(
    alg: tpm2::TpmiAlgHash,
    digest: &'a OwnedDigest,
) -> tpm2::TpmtHa<'a> {
    let slice = digest.get_buffer();
    match alg {
        tpm2::TpmiAlgHash::Sha256 => tpm2::TpmtHa::Sha256(slice[..32].try_into().unwrap()),
        tpm2::TpmiAlgHash::Sha384 => tpm2::TpmtHa::Sha384(slice[..48].try_into().unwrap()),
        tpm2::TpmiAlgHash::Sha512 => tpm2::TpmtHa::Sha512(slice[..64].try_into().unwrap()),
        tpm2::TpmiAlgHash::Sm3_256 => tpm2::TpmtHa::Sm3_256(slice[..32].try_into().unwrap()),
        tpm2::TpmiAlgHash::Sha3_256 => tpm2::TpmtHa::Sha3_256(slice[..32].try_into().unwrap()),
        tpm2::TpmiAlgHash::Sha3_384 => tpm2::TpmtHa::Sha3_384(slice[..48].try_into().unwrap()),
        tpm2::TpmiAlgHash::Sha3_512 => tpm2::TpmtHa::Sha3_512(slice[..64].try_into().unwrap()),
        tpm2::TpmiAlgHash::Sha1 => tpm2::TpmtHa::Sha1(slice[..20].try_into().unwrap()),
    }
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
