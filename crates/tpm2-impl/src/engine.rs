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
use tpm2::{
    CommandHeader, Handle, ResponseHeader, TPM2_MAX_DIGEST_BUFFER, TpmCc, TpmHt, TpmSe, TpmSt,
};
use tpm2::{Marshal, Unmarshal};
use tpm2::{
    Tpm2bAuth, Tpm2bName, Tpm2bNonce, TpmaSession, TpmiAlgHash, TpmiAlgSymMode, TpmiStCommandTag,
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
/// Maximum number of active hash/HMAC sequences in RAM.
pub const MAX_ACTIVE_SEQUENCES: usize = 3;
/// Maximum sequence buffer size per active sequence.
pub const MAX_SEQUENCE_BUFFER: usize = 4096;

/// Buffer size for decrypted command parameters.
/// Sized to accommodate a full `TPM2B_MAX_BUFFER` (`TPM2_MAX_DIGEST_BUFFER` bytes of payload + 2 bytes size)
/// plus accompanying command parameters (e.g., handles, IVs, algorithm modes).
const DECRYPT_BUF_SIZE: usize = TPM2_MAX_DIGEST_BUFFER as usize + 128;
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
    /// An array holding session handles that have been saved to context blobs.
    pub saved_sessions: [Option<u32>; MAX_LOADED_SESSIONS],
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
    /// A secret nonce used to derive commit scalars (`r`) deterministically via KDFa per `CryptGenerateR`.
    pub commit_nonce: [u8; 64],
    /// The X coordinate of the point committed during the last TPM2_Commit (`E` if `P1` was present, else `L`).
    pub commit_x: [u8; 32],
    /// The P1 point passed to the last TPM2_Commit (`x || y`), if any.
    pub commit_p1: [u8; 64],
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
            saved_sessions: [None; MAX_LOADED_SESSIONS],
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
            commit_nonce: [0x5a; 64],
            commit_x: [0u8; 32],
            commit_p1: [0u8; 64],
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
        self.clock_offset = self.clock_offset.saturating_add(self.tpm_time_ms as i64);
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
            if let Some(session) = slot {
                if session.session_handle == handle {
                    if self.exclusive_audit_session == Some(handle) {
                        self.exclusive_audit_session = None;
                    }
                    return slot.take();
                }
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

    /// Finds the index in transient_objects of a transient object by its handle.
    pub fn find_transient_index(&self, handle: u32) -> Option<usize> {
        self.transient_objects
            .iter()
            .enumerate()
            .find_map(|(i, slot)| {
                if let Some(obj) = slot {
                    if obj.handle == handle {
                        return Some(i);
                    }
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
            if let Some(obj) = slot {
                if obj.handle == handle {
                    *slot = None;
                    self.transient_parents[i] = None;
                    return Ok(());
                }
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
            if let Some(seq) = slot {
                if seq.handle == handle {
                    *slot = None;
                    return Ok(());
                }
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
        (global_state.tpm_time_ms as i64 + global_state.clock_offset).max(0) as u64
    }

    /// Returns the current `TpmsClockInfo` structure.
    pub fn get_clock_info(&self, global_state: &GlobalState) -> tpm2::TpmsClockInfo {
        tpm2::TpmsClockInfo {
            clock: self.get_clock(global_state),
            reset_count: global_state.reset_count,
            restart_count: global_state.restart_count,
            safe: true,
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
                {
                    if let Ok((_, _, auth, _)) =
                        crate::handler::nv_storage::unmarshal_nv_header(&read_buf[..read_len])
                    {
                        return OwnedAuth::from(auth);
                    }
                }
            }
            OwnedAuth::default()
        } else if (0x81000000..=0x81FFFFFF).contains(&handle) {
            let storage_mgr = StorageManager::new(&mut *self.platform.storage);
            if let Ok(metadata) = storage_mgr.get_metadata(handle) {
                let read_len = core::cmp::min(metadata.data_size as usize, 512);
                let mut read_buf = [0u8; 512];
                if storage_mgr
                    .read_item(handle, 0, &mut read_buf[..read_len])
                    .is_ok()
                    && read_len > 32
                {
                    let mut slice = &read_buf[32..read_len];
                    if Tpm2bName::unmarshal(&mut slice).is_ok() {
                        if let Ok(auth) = OwnedAuth::unmarshal(&mut slice) {
                            return auth;
                        }
                    }
                }
            }
            OwnedAuth::default()
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
                {
                    if let Ok((_, nv_public_struct, _, _)) =
                        crate::handler::nv_storage::unmarshal_nv_header(&read_buf[..read_len])
                    {
                        return Ok(OwnedDigest::from(nv_public_struct.auth_policy));
                    }
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
                {
                    if let Ok((_, nv_public_struct, _, _)) =
                        crate::handler::nv_storage::unmarshal_nv_header(&read_buf[..read_len])
                    {
                        return !nv_public_struct.attributes.contains(tpm2::TpmaNv::NO_DA);
                    }
                }
            }
            return true;
        }
        false
    }

    /// Checks whether Dictionary Attack lockout applies (`CheckLockedOut()` in `SessionProcess.c`).
    /// If NV storage is unavailable during an orderly state (`orderly_state < 0xFFFE`), returns `TPM_RC_NV_UNAVAILABLE`.
    /// If a DA counter update was deferred while NV was unavailable (`da_pending_on_nv`) and NV is now available,
    /// flushes `failed_tries` to NV storage and clears `da_pending_on_nv`.
    pub(crate) fn check_locked_out(
        &mut self,
        global_state: &mut GlobalState,
        is_lockout_auth: bool,
    ) -> Result<(), TpmRc> {
        if !global_state.nv_available && global_state.orderly_state < 0xFFFE {
            return Err(TpmRc::NV_UNAVAILABLE);
        }
        if global_state.da_pending_on_nv && global_state.nv_available {
            let _ = self
                .platform
                .storage
                .write_nv(32, &global_state.failed_tries.to_be_bytes());
            global_state.da_pending_on_nv = false;
        }
        if is_lockout_auth {
            if !global_state.lockout_auth_enabled {
                return Err(TpmRc::LOCKOUT);
            }
        } else if global_state.recovery_time != 0
            && global_state.max_tries > 0
            && global_state.failed_tries >= global_state.max_tries
        {
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

    pub fn load_persistent_object(
        &mut self,
        global_state: &GlobalState,
        handle: u32,
    ) -> Result<TransientObject, TpmRc> {
        let storage = StorageManager::new(&mut *self.platform.storage);
        let metadata = storage
            .get_metadata(handle)
            .map_err(|_| TpmRc::HANDLE.to_rc())?;
        let mut buf = [0u8; 4096];
        storage
            .read_item(handle, 0, &mut buf[..metadata.data_size as usize])
            .map_err(|_| TpmRc::FAILURE)?;

        let mut slice = &buf[..metadata.data_size as usize];

        if slice.len() < 32 {
            return Err(TpmRc::FAILURE);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&slice[..32]);
        slice = &slice[32..];

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

        if hierarchy == tpm2::Handle::RH_OWNER.0 && !global_state.sh_enable {
            return Err(TpmRc::HIERARCHY.to_rc());
        }
        if hierarchy == tpm2::Handle::RH_ENDORSEMENT.0 && !global_state.eh_enable {
            return Err(TpmRc::HIERARCHY.to_rc());
        }
        if hierarchy == tpm2::Handle::RH_PLATFORM.0 && !global_state.ph_enable {
            return Err(TpmRc::HIERARCHY.to_rc());
        }

        Ok(TransientObject {
            handle,
            seed,
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
                if let Ok(marker) = u8::unmarshal(&mut slice) {
                    if marker == 0xAA {
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
                    }
                }
            }
        }
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

        let request_size = cmd_buf.len();
        if request_size < CommandHeader::MAX_SIZE {
            return Err(TpmRc::VALUE.to_rc());
        }

        // Parse command header: tag, size, and command code
        let mut slice = cmd_buf;
        let header = match CommandHeader::unmarshal(&mut slice) {
            Ok(h) => h,
            Err(_) => {
                let tag = u16::from_be_bytes([cmd_buf[0], cmd_buf[1]]);
                if tag != 0x8001 && tag != 0x8002 {
                    return Err(TpmRc::BAD_TAG);
                }
                return Err(TpmRc::VALUE.to_rc());
            }
        };
        let size = header.size as usize;
        if request_size < size {
            return Err(TpmRc::SIZE.to_rc());
        }
        let cc = header.code;
        let command_code = cc.code();

        if !is_command_supported(cc) {
            return Err(TpmRc::COMMAND_CODE);
        }

        // Update accumulated TPM time (`g_time` in C reference) by relative delta from platform timer.
        let raw_timer_ms = self.platform.timer.timer_read();
        let elapsed_ms = if let Some(prev_raw) = global_state.last_timer_read_ms {
            raw_timer_ms.saturating_sub(prev_raw)
        } else {
            0
        };
        global_state.last_timer_read_ms = Some(raw_timer_ms);
        global_state.tpm_time_ms = global_state.tpm_time_ms.saturating_add(elapsed_ms);

        // DASelfHeal() logic:
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
            }
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
                if !matches!(
                    cc,
                    TpmCc::Startup | TpmCc::ContextLoad | TpmCc::ContextSave | TpmCc::FlushContext
                ) {
                    global_state.exclusive_audit_session = None;
                }

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
                    self.check_unauthorized_handles(
                        global_state,
                        cc,
                        &handles,
                        handles_len,
                        &[],
                        0,
                    )?;
                    let params_len = size.saturating_sub(10 + handles_len * 4);
                    self.validate_command_handles(
                        global_state,
                        cc,
                        &handles,
                        handles_len,
                        &cmd_buf[10 + handles_len * 4..10 + handles_len * 4 + params_len],
                    )?;
                }

                self.execute_without_sessions(global_state, cmd_buf, resp_buf, cc, size)
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
        // 1. Parse Handles and Session Area
        let mut cmd =
            self.parse_command_and_sessions(global_state, cmd_buf, cc, command_code, request_size)?;
        self.validate_session_attributes(&cmd, global_state, command_code, true)?;
        self.validate_command_handles(
            global_state,
            cc,
            &cmd.handles,
            cmd.handles_len,
            cmd.parameters,
        )?;
        self.validate_session_attributes(&cmd, global_state, command_code, false)?;

        // 3. Parameter Decryption
        let has_decrypt_session = cmd.auth_sessions[..cmd.auth_sessions_len]
            .iter()
            .any(|auth| auth.session_attributes.0 & 0x20 != 0);

        if has_decrypt_session {
            self.execute_with_param_decryption(global_state, cmd, resp_buf, cc, command_code)
        } else {
            self.execute_after_decryption(global_state, &mut cmd, resp_buf, cc, command_code)
        }
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
    /// Performs the remaining execution pipeline for session-authenticated commands:
    /// 1. Verifies authorization session HMACs and validates handle authorization rules.
    /// 2. Dispatches command execution to the underlying handler via a session-less shadow buffer.
    /// 3. Processes the response, including parameter encryption (if `TPMA_SESSION_ENCRYPT` is set),
    ///    audit session tracking, nonce generation, and response HMAC computation.
    fn execute_after_decryption(
        &mut self,
        global_state: &mut GlobalState,
        cmd: &mut ParsedCommand,
        resp_buf: &mut [u8],
        cc: TpmCc,
        command_code: u32,
    ) -> Result<usize, TpmRc> {
        // 4. HMAC Verification for all Sessions
        self.verify_session_hmacs(global_state, cmd, command_code)?;
        self.check_unauthorized_handles(
            global_state,
            cc,
            &cmd.handles,
            cmd.handles_len,
            &cmd.session_to_handle_idx,
            cmd.session_to_handle_idx_len,
        )?;

        // 5. Execute Command via a Shadow Buffer
        let shadow_request_size =
            CommandHeader::MAX_SIZE + (cmd.handles_len * 4) + cmd.parameters.len();
        if shadow_request_size > 2048 {
            return Err(TpmRc::SIZE.to_rc());
        }
        let mut shadow_request = [0u8; 2048];
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
            if shadow_res.is_err() {
                for auth in &cmd.auth_sessions[..cmd.auth_sessions_len] {
                    let session_handle = auth.session_handle.0;
                    if let Some(session_state) = global_state.session_mut(session_handle) {
                        if session_state.session_type == tpm2::TpmSe::Policy {
                            session_state.policy_digest[..session_state.policy_digest_len].fill(0);
                        }
                    }
                }
            }
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
            return Err(TpmRc::SIZE.to_rc());
        }
        let auth_size = u32::from_be_bytes([
            cmd_buf[auth_size_offset],
            cmd_buf[auth_size_offset + 1],
            cmd_buf[auth_size_offset + 2],
            cmd_buf[auth_size_offset + 3],
        ]) as usize;
        if request_size < auth_size_offset + 4 + auth_size {
            return Err(TpmRc::SIZE.to_rc());
        }
        if auth_size > 512 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let mut auth_area_bytes = [0u8; 512];
        auth_area_bytes[..auth_size]
            .copy_from_slice(&cmd_buf[auth_size_offset + 4..auth_size_offset + 4 + auth_size]);

        let mut auth_sessions = [OwnedAuthCommand::default(); 3];
        let mut auth_sessions_len = 0;
        let mut unmarsh = &auth_area_bytes[..auth_size];
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

        // Map sessions to authorizing handles
        let mut session_to_handle_idx = [0usize; 3];
        let mut session_to_handle_idx_len = 0;
        let mut session_idx = 0;
        for (h_idx, &h) in handles.iter().enumerate().take(handles_len) {
            if handle_requires_auth(TpmCc::new(command_code), h_idx) {
                let is_optional = h == Handle::RH_NULL.0;
                let should_map = if is_optional {
                    let remaining_strict = remaining_strict_auth_handles(
                        command_code,
                        &handles[..handles_len],
                        h_idx + 1,
                        handles_len,
                    );
                    let available = auth_sessions_len - session_idx;
                    if available > remaining_strict {
                        session_idx += 1;
                        true
                    } else {
                        false
                    }
                } else {
                    session_idx += 1;
                    true
                };
                if should_map {
                    if session_to_handle_idx_len >= 3 {
                        return Err(TpmRc::SIZE.to_rc());
                    }
                    session_to_handle_idx[session_to_handle_idx_len] = h_idx;
                    session_to_handle_idx_len += 1;
                }
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
                // Self-authorization check: reject if session being used to authorize
                // is itself one of the command handles.
                if cmd.handles[..cmd.handles_len].contains(&session_handle) {
                    return Err(TpmRc::HANDLE.with(pos));
                }

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
                    continue;
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

            let session_state = global_state
                .session(session_handle)
                .ok_or(TpmRc::HANDLE.with(pos))?;

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

            let param_len = cmd.parameters.len();
            if param_len > 0 {
                if param_len < 2 {
                    return Err(TpmRc::SIZE.to_rc());
                }
                let param_size =
                    u16::from_be_bytes([cmd.parameters[0], cmd.parameters[1]]) as usize;
                if param_len < 2 + param_size {
                    return Err(TpmRc::SIZE.to_rc());
                }

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
                if i >= cmd.session_to_handle_idx_len {
                    return Err(TpmRc::SIZE.to_rc());
                }
                let h_idx = cmd.session_to_handle_idx[i];
                let handle = cmd.handles[h_idx];
                let is_admin = is_admin_role_auth(TpmCc::new(command_code), h_idx);

                let user_with_auth = if (0x80000000..=0x80FFFFFF).contains(&handle) {
                    global_state
                        .find_transient_object(handle)
                        .map(|obj| check_auth_type_allowed(obj.public.object_attributes, is_admin))
                        .unwrap_or(true)
                } else if (0x81000000..=0x81FFFFFF).contains(&handle) {
                    self.load_persistent_object(&*global_state, handle)
                        .map(|obj| check_auth_type_allowed(obj.public.object_attributes, is_admin))
                        .unwrap_or(true)
                } else {
                    true
                };

                if !user_with_auth {
                    return Err(TpmRc::AUTH_TYPE);
                }

                if self.has_da_protection(global_state, handle) {
                    self.check_locked_out(global_state, handle == 0x4000000A)?;
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
                }

                let expected_auth = self.handle_auth(global_state, handle);
                let provided_hmac = auth.hmac.get_buffer();
                let provided_stripped = crate::util::strip_trailing_zeros(provided_hmac);
                let expected_stripped =
                    crate::util::strip_trailing_zeros(expected_auth.get_buffer());
                let matches_exact =
                    crate::util::constant_time_eq(expected_stripped, provided_stripped);
                let matches_trimmed = !matches_exact
                    && !provided_stripped.is_empty()
                    && expected_stripped.len() > provided_stripped.len()
                    && crate::util::constant_time_eq(
                        &expected_stripped[..provided_stripped.len()],
                        provided_stripped,
                    );
                if !matches_exact && !matches_trimmed {
                    let elen = expected_stripped.len().min(64);
                    global_state.debug_expected_auth[..elen]
                        .copy_from_slice(&expected_stripped[..elen]);
                    global_state.debug_expected_auth_len = elen;
                    let plen = provided_stripped.len().min(64);
                    global_state.debug_provided_auth[..plen]
                        .copy_from_slice(&provided_stripped[..plen]);
                    global_state.debug_provided_auth_len = plen;
                    if self.has_da_protection(global_state, handle) {
                        if handle == 0x4000000A {
                            global_state.lockout_auth_enabled = false;
                            global_state.lockout_timer = global_state.tpm_time_ms as i64;
                            if !global_state.nv_available {
                                global_state.da_pending_on_nv = true;
                            }
                        } else {
                            if global_state.recovery_time != 0 {
                                global_state.failed_tries =
                                    global_state.failed_tries.saturating_add(1);
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
                        return Err(TpmRc::AUTH_FAIL.with(pos));
                    } else {
                        return Err(TpmRc::BAD_AUTH.with(pos));
                    }
                }
            } else {
                if !(0x02000000..=0x03FFFFFF).contains(&session_handle) {
                    return Err(TpmRc::VALUE.with(pos));
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

                if let Some(h) = entity_handle {
                    if self.has_da_protection(global_state, h) {
                        self.check_locked_out(global_state, h == 0x4000000A)?;
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
                    }
                }

                // Retrieve attributes first to avoid borrow-check conflicts
                let h_idx = if i < cmd.session_to_handle_idx_len {
                    cmd.session_to_handle_idx[i]
                } else {
                    9999
                };
                let is_admin = is_admin_role_auth(TpmCc::new(command_code), h_idx);

                let user_with_auth = if let Some(handle) = entity_handle {
                    if (0x80000000..=0x80FFFFFF).contains(&handle) {
                        global_state
                            .find_transient_object(handle)
                            .map(|obj| {
                                check_auth_type_allowed(obj.public.object_attributes, is_admin)
                            })
                            .unwrap_or(true)
                    } else if (0x81000000..=0x81FFFFFF).contains(&handle) {
                        self.load_persistent_object(&*global_state, handle)
                            .map(|obj| {
                                check_auth_type_allowed(obj.public.object_attributes, is_admin)
                            })
                            .unwrap_or(true)
                    } else {
                        true
                    }
                } else {
                    true
                };

                let mut handle_policy = None;
                if let Some(h) = entity_handle {
                    handle_policy = Some(self.handle_policy(&*global_state, h)?);
                }

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
                    let current_time = global_state.tpm_time_ms;
                    let is_expired = {
                        let session_state = global_state
                            .session(session_handle)
                            .ok_or(TpmRc::HANDLE.with(pos))?;
                        session_state.epoch != global_state.time_epoch
                            || (session_state.timeout != 0 && session_state.timeout < current_time)
                    };

                    if is_expired {
                        let _ = global_state.flush_session(session_handle);
                        return Err(TpmRc::EXPIRED.with(pos));
                    }

                    let curr_locality = global_state.locality;
                    let curr_pcr_update_counter = global_state.pcrs.update_counter;
                    let pcr_policy_alg = global_state.pcr_policy_alg;
                    let session_state = global_state
                        .session_mut(session_handle)
                        .ok_or(TpmRc::HANDLE.with(pos))?;

                    if session_state.session_type == TpmSe::Trial {
                        return Err(TpmRc::AUTH_TYPE);
                    }
                    if session_state.command_code != 0 && session_state.command_code != command_code
                    {
                        return Err(TpmRc::POLICY_FAIL.with(pos));
                    }

                    let is_policy = session_state.session_type == TpmSe::Policy;
                    if !is_policy && !user_with_auth {
                        return Err(TpmRc::AUTH_TYPE);
                    }

                    if is_policy {
                        if let Some(pcr_counter) = session_state.pcr_counter {
                            if pcr_counter != curr_pcr_update_counter {
                                return Err(TpmRc::PCR_CHANGED);
                            }
                        }
                        if session_state.command_locality != 0 {
                            if session_state.command_locality > 31 {
                                if curr_locality != session_state.command_locality {
                                    return Err(TpmRc::LOCALITY);
                                }
                            } else if curr_locality > 4
                                || (session_state.command_locality & (1 << curr_locality)) == 0
                            {
                                return Err(TpmRc::LOCALITY);
                            }
                        }
                        if session_state.check_nv_written {
                            let is_nv_index = if let Some(h) = entity_handle {
                                Handle(h).handle_type() == Some(TpmHt::NVIndex)
                            } else {
                                false
                            };
                            if !is_nv_index {
                                return Err(TpmRc::POLICY_FAIL.to_rc());
                            }
                            let h = entity_handle.unwrap();
                            let storage_mgr = StorageManager::new(&mut *self.platform.storage);
                            let metadata = storage_mgr
                                .get_metadata(h)
                                .map_err(|_| TpmRc::POLICY_FAIL.to_rc())?;
                            let read_len = core::cmp::min(metadata.data_size as usize, 1536);
                            let mut read_buf = [0u8; 1536];
                            storage_mgr
                                .read_item(h, 0, &mut read_buf[..read_len])
                                .map_err(|_| TpmRc::POLICY_FAIL.to_rc())?;
                            let (_, nv_public, _, _) =
                                crate::handler::nv_storage::unmarshal_nv_header(
                                    &read_buf[..read_len],
                                )
                                .map_err(|_| TpmRc::POLICY_FAIL.to_rc())?;
                            if nv_public.attributes.contains(tpm2::TpmaNv::WRITTEN)
                                != session_state.nv_written_state
                            {
                                return Err(TpmRc::POLICY_FAIL.to_rc());
                            }
                        }
                        if let Some(ref policy) = handle_policy {
                            if policy.get_size() == 0 {
                                return Err(TpmRc::AUTH_UNAVAILABLE);
                            }
                            if let Some(h) = entity_handle {
                                if (20..=22).contains(&h)
                                    && pcr_policy_alg != Some(session_state.auth_hash)
                                {
                                    return Err(TpmRc::POLICY_FAIL.with(pos));
                                }
                            }
                            if policy.get_size() as usize != session_state.policy_digest_len
                                || policy.get_buffer()
                                    != &session_state.policy_digest
                                        [..session_state.policy_digest_len]
                            {
                                return Err(TpmRc::POLICY_FAIL.with(pos));
                            }
                        }
                    }

                    let auth_hash = session_state.auth_hash;
                    let session_key_len = session_state.session_key_len;

                    // Copy session key out
                    session_key_buf[..session_key_len]
                        .copy_from_slice(&session_state.session_key[..session_key_len]);

                    (
                        auth_hash,
                        session_state.nonce_tpm,
                        session_key_len,
                        session_state.bind_entity,
                        session_state.bound_entity,
                        is_policy,
                        session_state.is_auth_value_needed,
                        session_state.is_password_needed,
                    )
                };

                let mut is_bound = false;
                if bind_entity != Handle::RH_NULL && i < cmd.session_to_handle_idx_len {
                    let h_idx = cmd.session_to_handle_idx[i];
                    let h = cmd.handles[h_idx];
                    if bind_entity == Handle(h) {
                        let entity_auth_stripped =
                            crate::util::strip_trailing_zeros(entity_auth.get_buffer());
                        let name = self.handle_name(global_state, h);
                        let name_bytes = name.get_buffer();
                        let mut name_buf = [0u8; 64];
                        name_buf[..name_bytes.len()].copy_from_slice(name_bytes);
                        for (p_auth, j) in ((64 - entity_auth_stripped.len())..64).enumerate() {
                            name_buf[j] ^= entity_auth_stripped[p_auth];
                        }
                        if let Ok(b_name) = Tpm2bName::from_bytes(&name_buf) {
                            is_bound = bound_entity == b_name;
                        }
                    }
                }

                let entity_auth_stripped =
                    crate::util::strip_trailing_zeros(entity_auth.get_buffer());
                let include_auth = (!is_policy && !is_bound)
                    || (is_policy && (is_auth_value_needed || is_password_needed));
                if let Some(s) = global_state.session_mut(session_handle) {
                    s.include_auth = include_auth;
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

                let provided_stripped = crate::util::strip_trailing_zeros(auth.hmac.get_buffer());
                let auth_matches = if is_policy && is_password_needed {
                    crate::util::constant_time_eq(provided_stripped, entity_auth_stripped)
                } else {
                    let computed_stripped =
                        crate::util::strip_trailing_zeros(&computed_hmac[..computed_hmac_len]);
                    crate::util::constant_time_eq(provided_stripped, computed_stripped)
                        || (is_policy && hmac_key_len == 0 && provided_stripped.is_empty())
                };

                if !auth_matches {
                    if let Some(h) = entity_handle {
                        if self.has_da_protection(global_state, h) {
                            if h == 0x4000000A {
                                global_state.lockout_auth_enabled = false;
                                global_state.lockout_timer = global_state.tpm_time_ms as i64;
                                if !global_state.nv_available {
                                    global_state.da_pending_on_nv = true;
                                }
                            } else {
                                if global_state.recovery_time != 0 {
                                    global_state.failed_tries =
                                        global_state.failed_tries.saturating_add(1);
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
                    }
                    if auth.session_attributes.contains(tpm2::TpmaSession::AUDIT) {
                        return Err(TpmRc::BAD_AUTH.with(pos));
                    } else {
                        return Err(TpmRc::AUTH_FAIL.with(pos));
                    }
                }

                let session_state = global_state
                    .session_mut(session_handle)
                    .ok_or(TpmRc::AUTH_FAIL.with(pos))?;
                session_state.nonce_caller = auth.nonce;

                if session_state.policy_hash_len > 0 {
                    if session_state.is_cp_hash_defined
                        && (session_state.policy_hash_len != cp_hash_len
                            || session_state.policy_hash[..cp_hash_len] != cp_hash[..cp_hash_len])
                    {
                        return Err(TpmRc::POLICY_FAIL.with(pos));
                    }
                    if session_state.is_name_hash_defined {
                        let mut name_hash_input = [0u8; 512];
                        let mut name_hash_offset = 0;
                        for name in &auth_handle_names[..auth_handle_names_len] {
                            let name_buf = name.get_buffer();
                            name_hash_input[name_hash_offset..name_hash_offset + name_buf.len()]
                                .copy_from_slice(name_buf);
                            name_hash_offset += name_buf.len();
                        }
                        let mut computed_name_hash = [0u8; 64];
                        let computed_name_hash_len = compute_hash(
                            self.platform.crypto,
                            auth_hash,
                            &name_hash_input[..name_hash_offset],
                            &mut computed_name_hash,
                        )?;

                        if computed_name_hash_len != session_state.policy_hash_len
                            || computed_name_hash[..computed_name_hash_len]
                                != session_state.policy_hash[..session_state.policy_hash_len]
                        {
                            return Err(TpmRc::POLICY_FAIL.with(pos));
                        }
                    }
                    if session_state.is_template_hash_defined {
                        if !matches!(
                            TpmCc::new(command_code),
                            TpmCc::Create | TpmCc::CreatePrimary | TpmCc::CreateLoaded
                        ) {
                            return Err(TpmRc::POLICY_FAIL.with(pos));
                        }
                        let mut ok = false;
                        if cmd.parameters.len() >= 2 {
                            let in_sensitive_size =
                                u16::from_be_bytes([cmd.parameters[0], cmd.parameters[1]]) as usize;
                            let template_offset = 2 + in_sensitive_size;
                            if cmd.parameters.len() >= template_offset + 2 {
                                let template_size = u16::from_be_bytes([
                                    cmd.parameters[template_offset],
                                    cmd.parameters[template_offset + 1],
                                ]) as usize;
                                if cmd.parameters.len() >= template_offset + 2 + template_size {
                                    let template_bytes = &cmd.parameters
                                        [template_offset + 2..template_offset + 2 + template_size];
                                    let mut computed_template_hash = [0u8; 64];
                                    let computed_template_hash_len = compute_hash(
                                        self.platform.crypto,
                                        auth_hash,
                                        template_bytes,
                                        &mut computed_template_hash,
                                    )?;
                                    if computed_template_hash_len == session_state.policy_hash_len
                                        && computed_template_hash[..computed_template_hash_len]
                                            == session_state.policy_hash
                                                [..session_state.policy_hash_len]
                                    {
                                        ok = true;
                                    }
                                }
                            }
                        }
                        if !ok {
                            return Err(TpmRc::POLICY_FAIL.with(pos));
                        }
                    }
                }

                if auth.session_attributes.0 & 0x80 != 0 {
                    session_state.audit_cp_hash[..cp_hash_len]
                        .copy_from_slice(&cp_hash[..cp_hash_len]);
                    session_state.audit_cp_hash_len = cp_hash_len;
                }
            }
        }
        Ok(())
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
            let mut resp_attrs = auth.session_attributes.0 & !0x60;
            if auth.session_attributes.0 & 0x80 != 0 {
                if global_state.exclusive_audit_session == Some(session_handle) {
                    resp_attrs |= 0x02;
                } else {
                    resp_attrs &= !0x02;
                }
            }

            let mut session_key_buf = [0u8; 128];
            let session_key_len;
            let (auth_hash, _nonce_caller, include_auth, _is_policy) = {
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
                    is_policy,
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
            let hmac_res_len = if hmac_key_len == 0 && auth.hmac.get_size() == 0 {
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
                if session_state.session_type == tpm2::TpmSe::Policy
                    && i < cmd.session_to_handle_idx_len
                {
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
            let mut resp_attrs = auth.session_attributes.0 & !0x60;
            if auth.session_attributes.0 & 0x80 != 0 {
                if global_state.exclusive_audit_session == Some(session_handle) {
                    resp_attrs |= 0x02;
                } else {
                    resp_attrs &= !0x02;
                }
            }

            let mut session_key_buf = [0u8; 128];
            let session_key_len;
            let (auth_hash, _nonce_caller, include_auth, _is_policy) = {
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
                    is_policy,
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
            let hmac_res_len = if hmac_key_len == 0 && auth.hmac.get_size() == 0 {
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
                if session_state.session_type == tpm2::TpmSe::Policy
                    && i < cmd.session_to_handle_idx_len
                {
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
        parameters: &[u8],
    ) -> Result<(), TpmRc> {
        if handles_len >= 1 {
            let auth_handle = handles[0];

            if cc == TpmCc::HierarchyControl {
                if auth_handle != Handle::RH_OWNER.0
                    && auth_handle != Handle::RH_PLATFORM.0
                    && auth_handle != Handle::RH_ENDORSEMENT.0
                {
                    return Err(TpmRc::VALUE.with(Position::handle(1)));
                }
                if parameters.len() >= 5 {
                    let enable = u32::from_be_bytes([
                        parameters[0],
                        parameters[1],
                        parameters[2],
                        parameters[3],
                    ]);
                    let state = parameters[4];
                    if state > 1 {
                        return Err(TpmRc::VALUE.with(Position::parameter(2)));
                    }
                    if enable == Handle::RH_ENDORSEMENT.0 {
                        if state == 0 {
                            if auth_handle != Handle::RH_PLATFORM.0
                                && auth_handle != Handle::RH_ENDORSEMENT.0
                            {
                                return Err(TpmRc::AUTH_TYPE);
                            }
                        } else if auth_handle != Handle::RH_PLATFORM.0 {
                            return Err(TpmRc::AUTH_TYPE);
                        }
                    } else if enable == Handle::RH_OWNER.0 {
                        if state == 0 {
                            if auth_handle != Handle::RH_OWNER.0
                                && auth_handle != Handle::RH_PLATFORM.0
                            {
                                return Err(TpmRc::AUTH_TYPE);
                            }
                        } else if auth_handle != Handle::RH_PLATFORM.0 {
                            return Err(TpmRc::AUTH_TYPE);
                        }
                    } else if enable == Handle::RH_PLATFORM.0 || enable == Handle::RH_PLATFORM_NV.0
                    {
                        if auth_handle != Handle::RH_PLATFORM.0 {
                            return Err(TpmRc::AUTH_TYPE);
                        }
                    } else {
                        return Err(TpmRc::VALUE.with(Position::parameter(1)));
                    }
                }
            }

            if cc == TpmCc::HierarchyChangeAuth
                && auth_handle != Handle::RH_OWNER.0
                && auth_handle != Handle::RH_ENDORSEMENT.0
                && auth_handle != Handle::RH_PLATFORM.0
                && auth_handle != Handle::RH_LOCKOUT.0
            {
                return Err(TpmRc::VALUE.with(Position::handle(1)));
            }

            if cc == TpmCc::NVUndefineSpaceSpecial && handles_len >= 2 {
                let nv_index = handles[0];
                let platform = handles[1];
                if Handle(nv_index).handle_type() != Some(TpmHt::NVIndex) {
                    return Err(TpmRc::VALUE.with(Position::handle(1)));
                }
                if platform != Handle::RH_PLATFORM.0 && platform != Handle::RH_OWNER.0 {
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
                if cc != TpmCc::NVUndefineSpace {
                    let storage =
                        crate::storage::manager::StorageManager::new(&mut *self.platform.storage);
                    match storage.get_metadata(nv_index) {
                        Ok(metadata) => {
                            let platform_create = tpm2::TpmaNv(metadata.attributes)
                                .contains(tpm2::TpmaNv::PLATFORMCREATE);
                            if platform_create {
                                if !global_state.ph_enable_nv {
                                    return Err(TpmRc::HANDLE.with(Position::handle(2)));
                                }
                            } else if !global_state.sh_enable {
                                return Err(TpmRc::HANDLE.with(Position::handle(2)));
                            }
                        }
                        Err(_) => {
                            return Err(TpmRc::HANDLE.with(Position::handle(2)));
                        }
                    }
                }
            } else if cc == TpmCc::NVChangeAuth && handles_len >= 1 {
                let nv_index = handles[0];
                if Handle(nv_index).handle_type() != Some(TpmHt::NVIndex) {
                    return Err(TpmRc::VALUE.with(Position::handle(1)));
                }
                let storage =
                    crate::storage::manager::StorageManager::new(&mut *self.platform.storage);
                match storage.get_metadata(nv_index) {
                    Ok(metadata) => {
                        let platform_create = tpm2::TpmaNv(metadata.attributes)
                            .contains(tpm2::TpmaNv::PLATFORMCREATE);
                        if platform_create {
                            if !global_state.ph_enable_nv {
                                return Err(TpmRc::HANDLE.with(Position::handle(1)));
                            }
                        } else if !global_state.sh_enable {
                            return Err(TpmRc::HANDLE.with(Position::handle(1)));
                        }
                    }
                    Err(_) => {
                        return Err(TpmRc::HANDLE.with(Position::handle(1)));
                    }
                }
            } else if cc == TpmCc::NVCertify && handles_len >= 3 {
                let nv_index = handles[2];
                if Handle(nv_index).handle_type() != Some(TpmHt::NVIndex) {
                    return Err(TpmRc::VALUE.with(Position::handle(3)));
                }
                let storage =
                    crate::storage::manager::StorageManager::new(&mut *self.platform.storage);
                match storage.get_metadata(nv_index) {
                    Ok(metadata) => {
                        let platform_create = tpm2::TpmaNv(metadata.attributes)
                            .contains(tpm2::TpmaNv::PLATFORMCREATE);
                        if platform_create {
                            if !global_state.ph_enable_nv {
                                return Err(TpmRc::HANDLE.with(Position::handle(3)));
                            }
                        } else if !global_state.sh_enable {
                            return Err(TpmRc::HANDLE.with(Position::handle(3)));
                        }
                    }
                    Err(_) => {
                        return Err(TpmRc::HANDLE.with(Position::handle(3)));
                    }
                }
            }
        }
        for (h_idx, &handle) in handles.iter().enumerate().take(handles_len) {
            let pos = Position::handle((h_idx + 1) as u8);
            if expects_object_handle(cc, h_idx) {
                if handle == Handle::RH_NULL.0 {
                    let allows_null = matches!(
                        (cc, h_idx),
                        (TpmCc::CertifyCreation, 0)
                            | (TpmCc::Duplicate, 1)
                            | (TpmCc::Certify, 1)
                            | (TpmCc::GetSessionAuditDigest, 1)
                            | (TpmCc::GetCommandAuditDigest, 1)
                    );
                    if !allows_null {
                        if cc == TpmCc::ReadPublic {
                            return Err(TpmRc::HANDLE.to_rc());
                        } else {
                            return Err(TpmRc::VALUE.with(pos));
                        }
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
                    if (handle & 0x00FF_FFFF) > 0x0080_FFFF {
                        return Err(TpmRc::VALUE.with(pos));
                    }
                    match self.load_persistent_object(global_state, handle) {
                        Ok(obj) => {
                            if (obj.hierarchy == 0x40000001 && !global_state.sh_enable)
                                || (obj.hierarchy == 0x4000000B && !global_state.eh_enable)
                                || (obj.hierarchy == 0x4000000C && !global_state.ph_enable)
                            {
                                return Err(TpmRc::HIERARCHY.with(pos));
                            }
                        }
                        Err(err) if err == TpmRc::HIERARCHY.to_rc() => {
                            return Err(TpmRc::HIERARCHY.with(pos));
                        }
                        Err(_) => {
                            if cc == TpmCc::ReadPublic {
                                return Err(TpmRc::HANDLE.with(pos));
                            }
                            return Err(match h_idx {
                                0 => TpmRc::REFERENCE_H0,
                                1 => TpmRc::REFERENCE_H1,
                                _ => TpmRc::REFERENCE_H2,
                            });
                        }
                    }
                } else if (0x40000000..=0x40FFFFFF).contains(&handle) {
                    if cc == TpmCc::Load || (cc == TpmCc::ObjectChangeAuth && h_idx == 1) {
                        // Load and ObjectChangeAuth allow primary object parent handles (hierarchy roots)
                    } else if cc == TpmCc::Create {
                        return Err(TpmRc::KEY.to_rc());
                    } else {
                        return Err(TpmRc::VALUE.with(pos));
                    }
                } else {
                    return Err(TpmRc::VALUE.with(pos));
                }
            } else if cc == TpmCc::CreateLoaded && h_idx == 0 {
                let mso = handle >> 24;
                if mso == 0x80 {
                    if global_state.find_transient_object(handle).is_none() {
                        return Err(TpmRc::REFERENCE_H0);
                    }
                } else if mso == 0x81 {
                    if self.load_persistent_object(global_state, handle).is_err() {
                        return Err(TpmRc::REFERENCE_H0);
                    }
                } else if mso != 0x40 {
                    return Err(TpmRc::VALUE.with(pos));
                }
            } else if expects_context_handle(cc, h_idx) {
                let mso = handle >> 24;
                if mso == 0x80 {
                    if (handle & 0x00FF_FFFF) > 0x0000_FFFF {
                        return Err(TpmRc::VALUE.with(pos));
                    }
                    if global_state.find_transient_object(handle).is_none()
                        && global_state.find_active_sequence(handle).is_none()
                    {
                        return Err(TpmRc::REFERENCE_H0);
                    }
                } else if mso == 0x81 {
                    if (handle & 0x00FF_FFFF) > 0x0080_FFFF {
                        return Err(TpmRc::VALUE.with(pos));
                    }
                    if self.load_persistent_object(global_state, handle).is_err() {
                        return Err(TpmRc::REFERENCE_H0);
                    }
                } else if mso == 0x40 {
                    let is_valid_entity = matches!(
                        handle,
                        0x40000001 | 0x4000000B | 0x4000000C | 0x4000000A | 0x40000007
                    );
                    if !is_valid_entity {
                        return Err(TpmRc::VALUE.to_rc());
                    }
                } else if mso == 0x02 || mso == 0x03 {
                    let max_handle = if mso == 0x02 {
                        0x02000000 + tpm2::TPM2_MAX_ACTIVE_SESSIONS - 1
                    } else {
                        0x03000000 + tpm2::TPM2_MAX_ACTIVE_SESSIONS - 1
                    };
                    if handle > max_handle {
                        return Err(TpmRc::VALUE.with(pos));
                    }
                } else {
                    return Err(TpmRc::VALUE.with(pos));
                }
            } else if cc == TpmCc::GetSessionAuditDigest && h_idx == 2 {
                if !(0x02000000..=0x03FFFFFF).contains(&handle) {
                    return Err(TpmRc::VALUE.with(pos));
                }
            } else if expects_policy_session_handle(cc, h_idx) {
                if (handle >> 24) != 0x03 || global_state.session(handle).is_none() {
                    if cc == TpmCc::PolicyRestart && global_state.session(handle).is_none() {
                        return Err(TpmRc::REFERENCE_H0);
                    }
                    return Err(if pos == Position::handle(2) {
                        TpmRc::HANDLE.with(pos)
                    } else {
                        TpmRc::VALUE.with(pos)
                    });
                }
            } else if cc == TpmCc::StartAuthSession && h_idx == 0 {
                if handle != Handle::RH_NULL.0 {
                    if handle >> 24 == 0x80 {
                        if global_state.find_transient_object(handle).is_none() {
                            return Err(TpmRc::REFERENCE_H0);
                        }
                    } else if handle >> 24 == 0x81 {
                        if self.load_persistent_object(global_state, handle).is_err() {
                            return Err(TpmRc::REFERENCE_H0);
                        }
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
                        if self.load_persistent_object(global_state, handle).is_err() {
                            return Err(TpmRc::REFERENCE_H1);
                        }
                    } else if mso == 0x01 {
                        let storage = crate::storage::manager::StorageManager::new(
                            &mut *self.platform.storage,
                        );
                        if let Ok(toc) = storage.read_toc() {
                            if !toc.iter().any(|i| i.in_use != 0 && i.handle == handle) {
                                return Err(TpmRc::REFERENCE_H1);
                            }
                        } else {
                            return Err(TpmRc::REFERENCE_H1);
                        }
                    } else if mso == 0x00 && handle > 23 {
                        return Err(TpmRc::VALUE.with(pos));
                    }
                }
            } else if expects_permanent_handle(cc, h_idx) {
                if !(0x40000000..=0x40FFFFFF).contains(&handle) {
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
                    return Err(match h_idx {
                        0 => TpmRc::VALUE.to_rc(),
                        1 => TpmRc::VALUE.with(Position::handle(1)),
                        _ => TpmRc::VALUE.with(Position::handle(2)),
                    });
                }
            }
            if (0x40000000..=0x40FFFFFF).contains(&handle)
                && !(cc == TpmCc::HierarchyControl && h_idx == 1)
                && cc != TpmCc::Load
            {
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

    /// Verifies that any handle requiring authorization but lacking a mapped session is allowed
    /// to be authorized with an empty password (requires USER_WITH_AUTH == 1 and empty authValue).
    fn check_unauthorized_handles(
        &mut self,
        global_state: &GlobalState,
        cc: TpmCc,
        handles: &[u32],
        handles_len: usize,
        session_to_handle_idx: &[usize],
        session_to_handle_idx_len: usize,
    ) -> Result<(), TpmRc> {
        for (h_idx, &handle) in handles[..handles_len].iter().enumerate() {
            if handle_requires_auth(cc, h_idx) {
                // Check if this handle has an associated session
                let mut has_session = false;
                for &mapped_h_idx in &session_to_handle_idx[..session_to_handle_idx_len] {
                    if mapped_h_idx == h_idx {
                        has_session = true;
                        break;
                    }
                }

                let is_admin = is_admin_role_auth(cc, h_idx);
                if !has_session {
                    if (0x80000000..=0x80FFFFFF).contains(&handle) {
                        if let Some(obj) = global_state.find_transient_object(handle) {
                            if !check_auth_type_allowed(obj.public.object_attributes, is_admin) {
                                return Err(TpmRc::AUTH_MISSING);
                            }
                            if obj.auth.get_size() > 0 {
                                return Err(TpmRc::AUTH_MISSING);
                            }
                        } else if let Some(seq) = global_state.find_active_sequence(handle) {
                            if seq.auth.get_size() > 0 {
                                return Err(TpmRc::AUTH_MISSING);
                            }
                        }
                    } else if (0x81000000..=0x81FFFFFF).contains(&handle) {
                        if let Ok(obj) = self.load_persistent_object(global_state, handle) {
                            if !check_auth_type_allowed(obj.public.object_attributes, is_admin) {
                                return Err(TpmRc::AUTH_MISSING);
                            }
                            if obj.auth.get_size() > 0 {
                                return Err(TpmRc::AUTH_MISSING);
                            }
                        }
                    } else if Handle(handle).handle_type() == Some(TpmHt::NVIndex) {
                        let storage_mgr = StorageManager::new(&mut *self.platform.storage);
                        if let Ok(metadata) = storage_mgr.get_metadata(handle) {
                            let read_len = core::cmp::min(metadata.data_size as usize, 1536);
                            let mut read_buf = [0u8; 1536];
                            if storage_mgr
                                .read_item(handle, 0, &mut read_buf[..read_len])
                                .is_ok()
                            {
                                if let Ok((_, _, auth, _)) =
                                    crate::handler::nv_storage::unmarshal_nv_header(
                                        &read_buf[..read_len],
                                    )
                                {
                                    if auth.get_size() > 0 {
                                        return Err(TpmRc::AUTH_MISSING);
                                    }
                                }
                            }
                        }
                    } else if handle < 24 {
                        if self.handle_auth(global_state, handle).get_size() > 0 {
                            return Err(TpmRc::AUTH_MISSING);
                        }
                    } else {
                        // Hierarchy handles
                        let hierarchy_auth_size = match handle {
                            0x40000001 => Some(global_state.owner_auth.get_size()),
                            0x4000000B => Some(global_state.endorsement_auth.get_size()),
                            0x4000000C => Some(global_state.platform_auth.get_size()),
                            0x4000000A => Some(global_state.lockout_auth.get_size()),
                            0x40000007 => Some(0), // Null hierarchy always empty
                            _ => None,
                        };
                        if let Some(size) = hierarchy_auth_size {
                            if size > 0 || cc == TpmCc::EvictControl {
                                return Err(TpmRc::AUTH_MISSING);
                            }
                        }
                    }
                }
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
    ) {
        attr |= tpm2::TpmaCc::NV;
    }
    if matches!(cc, TpmCc::HierarchyControl | TpmCc::Clear) {
        attr |= tpm2::TpmaCc::EXTENSIVE;
    }
    if matches!(
        cc,
        TpmCc::SequenceComplete
            | TpmCc::EventSequenceComplete
            | TpmCc::NVUndefineSpace
            | TpmCc::NVUndefineSpaceSpecial
    ) {
        attr |= tpm2::TpmaCc::FLUSHED;
    }
    attr
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

fn command_supports_decryption(cc: TpmCc) -> bool {
    cc == TpmCc::CreatePrimary
        || cc == TpmCc::PCREvent
        || cc == TpmCc::CreateLoaded
        || cc == TpmCc::Commit
        || cc == TpmCc::GetTime
        || cc == TpmCc::HierarchyChangeAuth
        || cc == TpmCc::SetPrimaryPolicy
        || cc == TpmCc::LoadExternal
        || cc == TpmCc::VerifySignature
        || cc == TpmCc::Sign
        || cc == TpmCc::EncryptDecrypt
        || cc == TpmCc::EncryptDecrypt2
        || cc == TpmCc::RSADecrypt
        || cc == TpmCc::RSAEncrypt
        || cc == TpmCc::ECDHZGen
        || cc == TpmCc::MAC
        || cc == TpmCc::NVDefineSpace
        || cc == TpmCc::Certify
        || cc == TpmCc::Quote
        || cc == TpmCc::GetSessionAuditDigest
        || cc == TpmCc::GetCommandAuditDigest
        || cc == TpmCc::CertifyCreation
        || cc == TpmCc::NVWrite
        || cc == TpmCc::NVExtend
        || cc == TpmCc::NVChangeAuth
        || cc == TpmCc::NVCertify
        || cc == TpmCc::Duplicate
        || cc == TpmCc::Import
        || cc == TpmCc::Load
        || cc == TpmCc::ObjectChangeAuth
        || cc == TpmCc::ActivateCredential
        || cc == TpmCc::PolicySecret
        || cc == TpmCc::PolicySigned
        || cc == TpmCc::PolicyAuthorize
        || cc == TpmCc::Create
        || cc == TpmCc::Hash
        || cc == TpmCc::SequenceUpdate
        || cc == TpmCc::SequenceComplete
        || cc == TpmCc::EventSequenceComplete
        || cc == TpmCc::StirRandom
}

fn command_supports_encryption(cc: TpmCc) -> bool {
    cc == TpmCc::GetRandom
        || cc == TpmCc::CreatePrimary
        || cc == TpmCc::CreateLoaded
        || cc == TpmCc::GetTime
        || cc == TpmCc::ReadPublic
        || cc == TpmCc::LoadExternal
        || cc == TpmCc::RSADecrypt
        || cc == TpmCc::ECDHZGen
        || cc == TpmCc::ECDHKeyGen
        || cc == TpmCc::EncryptDecrypt
        || cc == TpmCc::EncryptDecrypt2
        || cc == TpmCc::MAC
        || cc == TpmCc::NVReadPublic
        || cc == TpmCc::NVRead
        || cc == TpmCc::Certify
        || cc == TpmCc::Quote
        || cc == TpmCc::GetSessionAuditDigest
        || cc == TpmCc::GetCommandAuditDigest
        || cc == TpmCc::CertifyCreation
        || cc == TpmCc::NVCertify
        || cc == TpmCc::Duplicate
        || cc == TpmCc::Import
        || cc == TpmCc::Load
        || cc == TpmCc::Unseal
        || cc == TpmCc::ObjectChangeAuth
        || cc == TpmCc::MakeCredential
        || cc == TpmCc::ActivateCredential
        || cc == TpmCc::Create
        || cc == TpmCc::PolicySecret
        || cc == TpmCc::PolicySigned
        || cc == TpmCc::Hash
        || cc == TpmCc::SequenceComplete
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
            {
                if let Ok((_, nv_public_struct, _, _, hash_target)) =
                    crate::handler::nv_storage::unmarshal_nv_header_bytes(&read_buf[..read_len])
                {
                    if let Ok(nv_name) = compute_nv_name(
                        &*ctx.platform.crypto,
                        nv_public_struct.name_alg,
                        hash_target,
                    ) {
                        return nv_name;
                    }
                }
            }
        }
    } else if (0x81000000..=0x81FFFFFF).contains(&handle) {
        let storage_mgr = StorageManager::new(&mut *ctx.platform.storage);
        if let Ok(metadata) = storage_mgr.get_metadata(handle) {
            let read_len = core::cmp::min(metadata.data_size as usize, 512);
            let mut read_buf = [0u8; 512];
            if storage_mgr
                .read_item(handle, 0, &mut read_buf[..read_len])
                .is_ok()
                && read_len > 32
            {
                let mut slice = &read_buf[32..read_len];
                if let Ok(name) = OwnedName::unmarshal(&mut slice) {
                    return name;
                }
            }
        }
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
        )
    } else {
        false
    }
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
                | TpmCc::ECCParameters
                | TpmCc::ZGen2Phase
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
        )
    } else {
        false
    }
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

pub fn is_admin_role_auth(cc: TpmCc, handle_index: usize) -> bool {
    if handle_index == 0 {
        matches!(
            cc,
            TpmCc::Certify
                | TpmCc::ActivateCredential
                | TpmCc::ObjectChangeAuth
                | TpmCc::NVChangeAuth
                | TpmCc::HierarchyChangeAuth
        )
    } else {
        false
    }
}

fn check_auth_type_allowed(obj_attrs: tpm2::TpmaObject, is_admin: bool) -> bool {
    if is_admin {
        !obj_attrs.contains(tpm2::TpmaObject::ADMIN_WITH_POLICY)
    } else {
        obj_attrs.contains(tpm2::TpmaObject::USER_WITH_AUTH)
    }
}

fn remaining_strict_auth_handles(
    command_code: u32,
    handles: &[u32],
    start_idx: usize,
    handles_len: usize,
) -> usize {
    let mut count = 0;
    for (h_idx, &h) in handles[..handles_len].iter().enumerate().skip(start_idx) {
        if handle_requires_auth(TpmCc::new(command_code), h_idx) {
            let is_optional = h == tpm2::Handle::RH_NULL.0;
            if !is_optional {
                count += 1;
            }
        }
    }
    count
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
        if let Some(session_state) = global_state.session(session_handle) {
            if session_state.bind_entity.0 == handle {
                return true;
            }
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
