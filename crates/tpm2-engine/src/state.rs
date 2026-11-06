//! The TPM state that commands act on and mutate.
//!
//! The state is a hierarchy that follows how long each value lives, like the global data of
//! the TCG reference implementation (`Global.h`):
//!
//! - [`State`]: the top-level runtime state. Its own fields are volatile: loaded objects,
//!   sessions and sequences, per-command bookkeeping, *Time*, the PCRs and other values that
//!   are lost (or rebuilt) on `_TPM_Init`.
//! - [`Nv`] ([`State::nv`]): every value that is kept in NV storage, grouped by when it is
//!   written to NV and read back:
//!   - [`PersistentState`] (`gp`, `PERSISTENT_DATA`): written to NV as soon as it changes and
//!     read at `_TPM_Init`.
//!   - [`OrderlyState`] (`go`, `ORDERLY_DATA`): written to NV by every `TPM2_Shutdown` (and
//!     at the other points the reference writes `go`) and read at `_TPM_Init`.
//!   - [`ResetState`] (`gr`, `STATE_RESET_DATA`): written to NV by
//!     `TPM2_Shutdown(TPM_SU_STATE)` and read by `TPM2_Startup` (TPM Restart and TPM Resume).
//!   - [`ClearState`] (`gc`, `STATE_CLEAR_DATA`): written to NV by
//!     `TPM2_Shutdown(TPM_SU_STATE)` and read by `TPM2_Startup(TPM_SU_STATE)` (TPM Resume).
//!   - [`Nv::index`]: the platform-specific structure that holds the NV data
//!     ([`crate::Platform::IndexState`], an [`IndexState`](crate::storage::IndexState)): the NV Indices, the persistent
//!     objects and the engine's internal records, which keep the NV copy of the groups above.
//!
//! The NV layout of these values (the reserved NV header and the engine's internal NV
//! records) is defined in [`crate::storage::nv`]; the platform syncs the NV data with external
//! storage ([`crate::Platform::load_nv`], [`crate::Platform::store_nv`]).

use crate::Platform;
use crate::command_audit::CommandAuditList;
use crate::engine::{
    ActiveSequence, CLOCK_NOMINAL, COMMIT_NONCE_SIZE, DrbgState, MAX_ACTIVE_SEQUENCES,
    MAX_ACTIVE_SESSIONS, MAX_LOADED_OBJECTS, MAX_LOADED_SESSIONS, UT_NONE,
};
use crate::handler::{SessionState, TransientObject};
use crate::owned::{OwnedAuth, OwnedAuthCommand, OwnedDigest};
use crate::physical_presence::PpList;
use tpm2::Handle;
use tpm2::platform::PcrState;

/// The global, top-level, runtime state that commands act on and mutate.
///
/// The fields of `State` itself are volatile (see the [module documentation](self)); every
/// value that is kept in NV storage is in [`State::nv`], including the platform-specific
/// structure that holds the NV data ([`Nv::index`]).
pub struct State<P: Platform> {
    /// Indicates whether the TPM has been initialized (e.g., via TPM2_Startup).
    pub initialized: bool,
    /// The current locality of the TPM, used to enforce locality-based access controls.
    pub locality: u8,
    /// Indicates whether the Non-Volatile (NV) memory is available for read/write operations.
    pub nv_available: bool,
    /// Indicates if the internal NV state is verified and OK.
    pub g_nv_ok: bool,
    /// Orderly state of the previous power cycle as seen by the last `TPM2_Startup`, with the
    /// startup modifier flags removed (`g_prevOrderlyState`); `SU_NONE_VALUE` (0xFFFF) if the
    /// previous shutdown was not orderly.
    pub prev_orderly_state: u16,
    /// Flag indicating if NV should be updated at the end of a command (`g_updateNV`: `UT_NONE`, `UT_NV`, `UT_ORDERLY`).
    pub update_nv: u8,
    /// Flag indicating if command execution should cause the orderly state to be cleared (`g_clearOrderly`).
    pub clear_orderly: bool,
    /// Flag indicating whether the TPM is in a DRTM (Dynamic Root of Trust for Measurement) pre-startup state.
    pub drtm_pre_startup: bool,
    /// Tracks the transient handle of the active hash sequence being used for the DRTM/H-CRTM at Locality 4 (`g_DRTMHandle`).
    pub drtm_handle: u32,
    /// Flag indicating whether the TPM startup occurred at locality 3.
    pub startup_locality_3: bool,
    /// Flag indicating if Dictionary Attack (DA) mitigation logic is currently active.
    pub da_used: bool,
    /// Power was lost and no `TPM2_Startup` has completed since (`g_powerWasLost` of the TCG
    /// reference): kept across `_TPM_Init` ([`crate::TpmEngine::reset`]), set by the platform on
    /// power on and cleared by a successful `TPM2_Startup`. While it is set, `_TPM_Init`
    /// re-enables NV (`NvPowerOn()`).
    pub power_was_lost: bool,
    /// The platform timer was reset by a power on since the last time epoch was started
    /// (`s_timerStopped` of the TCG reference platform, set by `_plat__TimerReset()`): kept across
    /// `_TPM_Init` ([`crate::TpmEngine::reset`]) and consumed by the time update of the next
    /// `TPM2_Startup`, which then starts a new time epoch (`TimeUpdate()`:
    /// `if(_plat__TimerWasStopped()) { TimeNewEpoch(); }`).
    pub timer_stopped: bool,
    /// The platform timer was reset by a power on since the last `TPM2_Startup` (`s_timerReset`
    /// of the TCG reference platform, consumed by `DAStartup()` through `_plat__TimerWasReset()`):
    /// only then are the dictionary-attack timers rebased onto the new *Time*.
    pub timer_was_reset: bool,
    /// Flag indicating whether the Platform Hierarchy is enabled.
    pub ph_enable: bool,
    /// An array holding the currently loaded transient objects.
    pub transient_objects: [Option<TransientObject>; MAX_LOADED_OBJECTS],
    /// An array holding the active authorization sessions.
    pub active_sessions: [Option<SessionState>; MAX_LOADED_SESSIONS],
    /// An array holding the active hash sequences.
    pub active_sequences: [Option<ActiveSequence>; MAX_ACTIVE_SEQUENCES],
    /// Number of persistent objects referenced by the handle area of the command being executed.
    /// Each occupies one of the `MAX_LOADED_OBJECTS` object slots (shared with transient and
    /// sequence objects) for the duration of the command, like the temporary copy C
    /// `ObjectLoadEvict` makes. Reset at the start of every command.
    pub command_persistent_objects: usize,
    /// Vendor-specific platform unique details (`g_platformUniqueDetails` / `g_platformUniqueAuth`).
    /// Stores device-unique secrets and vendor-permanent data referenced by `VENDOR_PERMANENT` (`TPM_RH_AUTH_00`).
    pub platform_unique_details: OwnedAuth,
    /// Accumulated TPM uptime in milliseconds (`g_time` / `go.time` in C reference).
    pub tpm_time_ms: u64,
    /// Transient snapshot of the last platform timer read in milliseconds, used to compute elapsed delta.
    pub last_timer_read_ms: Option<u64>,
    /// Flag indicating whether Dictionary Attack failure parameters (`failed_tries` or `lockout_auth_enabled`)
    /// were updated in RAM while NV storage was unavailable (`s_DAPendingOnNV` in `ibmswtpm2`).
    pub da_pending_on_nv: bool,
    /// The parsed authorization sessions from the command header.
    pub parsed_auths: [OwnedAuthCommand; 3],
    /// The number of parsed authorization sessions.
    pub parsed_auths_len: usize,
    /// The cpHash of the current command for each authorization session (by its index in the
    /// authorization area) with the `audit` attribute, computed with the session's hash
    /// algorithm and consumed when the response extends the session's audit digest (C
    /// `s_auditSessionIndex` with the command's cpHash). A per-command value, not kept on the
    /// session.
    pub session_audit_cp_hashes: [Option<OwnedDigest>; 3],
    /// Flag indicating if the authorization sessions have been validated by the command handler.
    pub sessions_validated_by_handler: bool,
    /// The handle of the session that currently holds the exclusive audit lock, if any.
    pub exclusive_audit_session: Option<u32>,
    /// Indicates whether the TPM is currently executing a shadow command (which bypasses auth checks).
    pub in_shadow_execution: bool,
    /// Cumulative clock-rate divisor applied to elapsed platform time (`s_adjustRate` in the C
    /// platform `Clock.c`); `CLOCK_NOMINAL` means no adjustment. Changed by
    /// `TPM2_ClockRateAdjust` within `CLOCK_NOMINAL ± CLOCK_ADJUST_LIMIT`.
    pub clock_adjust_rate: u32,
    /// Platform milliseconds not yet consumed by rate-adjusted time updates
    /// (`timeNow - s_realTimePrevious` in the C platform `_plat__TimerRead()`).
    pub clock_adjust_remainder: u64,
    /// PCR state.
    pub pcrs: PcrState,
    /// Flag indicating that PCR allocation has changed and is pending a reboot.
    pub pcr_reconfig: bool,
    /// `cpHash` of the current command computed with the audit hash algorithm when the command
    /// is audited (`s_cpHashForCommandAudit`); consumed when the response is built.
    pub command_audit_cp_hash: Option<OwnedDigest>,
    /// Set by `TPM2_SetCommandCodeAuditStatus` when it changed the audit hash algorithm: that
    /// execution is not audited and leaves the digest cleared (the C reference marks this case
    /// with a digest size of 1).
    pub command_audit_alg_changed: bool,
    /// The Authenticated Countdown Timers (counters, policies, the state saved by
    /// `TPM2_Shutdown(TPM_SU_STATE)` and the tick bookkeeping).
    pub act: crate::act::ActState,
    /// Whether Physical Presence is asserted (`_plat__PhysicalPresenceAsserted()`), a platform
    /// input (the simulator's `PhysicalPresenceOn`/`Off` signals). The platform keeps it across
    /// `_TPM_Init`; `false` when the TPM is created.
    pub physical_presence: bool,
    /// All non-volatile state: the values that are kept in NV storage, grouped by when they
    /// are written to NV and read back ([`Nv`]).
    pub nv: Nv<P>,
}

/// Non-volatile state, the values of [`State`] that are kept in NV storage.
pub struct Nv<P: Platform> {
    /// Immediately persisted on change, read during `_TPM_Init` (`gp`).
    pub persistent: PersistentState,
    /// Always persisted on `TPM2_Shutdown`, read during `_TPM_Init` (`go`).
    pub orderly: OrderlyState,
    /// Persisted on `TPM2_Shutdown(TPM_SU_STATE)`, read during `TPM2_Startup` (`gr`).
    pub reset: ResetState,
    /// Persisted on `TPM2_Shutdown(TPM_SU_STATE)`, read during `TPM2_Startup(TPM_SU_STATE)`
    /// (`gc`).
    pub clear: ClearState,
    /// Platform-specific structure for holding the NV data: the NV Indices, the persistent
    /// objects and the engine's internal records, in which the engine keeps the NV copy of
    /// the groups above ([`crate::storage::nv`]).
    pub index: P::IndexState,
}

impl<P: Platform> Nv<P> {
    /// The non-volatile state of a new (unmanufactured) TPM whose NV data is held in `index`.
    pub fn new(index: P::IndexState) -> Self {
        Self {
            persistent: PersistentState::default(),
            orderly: OrderlyState::default(),
            reset: ResetState::default(),
            clear: ClearState::default(),
            index,
        }
    }
}

/// Data which is immediately persisted when modified (`gp`, `PERSISTENT_DATA` of the TCG
/// reference, and the persistent counters of the reserved NV header), read during
/// `_TPM_Init`.
#[derive(Debug, Clone)]
pub struct PersistentState {
    /// A counter that increments upon every TPM reset (TPM_PT_RESET_COUNT).
    pub reset_count: u32,
    /// The time epoch (`gp.timeEpoch`, a `CLOCK_NONCE`): incremented whenever the platform timer
    /// was stopped. `CLOCK_NONCE` is a `UINT32` in the reference profile (`CLOCK_STOPS` is
    /// `NO`).
    pub time_epoch: u32,
    /// Represents the orderly state of the TPM (e.g., TPM_SU_CLEAR, TPM_SU_STATE).
    pub orderly_state: u16,
    /// The total number of resets across the entire lifetime of the TPM.
    pub total_reset_count: u64,
    /// If true, the TPM2_Clear command is disabled.
    pub disable_clear: bool,
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
    /// The authorization value for the Owner (Storage) Hierarchy.
    pub owner_auth: OwnedAuth,
    /// The authorization value for the Endorsement Hierarchy.
    pub endorsement_auth: OwnedAuth,
    /// The authorization value for the Lockout Hierarchy.
    pub lockout_auth: OwnedAuth,
    /// The authorization policy for the Owner (Storage) Hierarchy.
    pub owner_policy: OwnedDigest,
    /// The authorization policy for the Endorsement Hierarchy.
    pub endorsement_policy: OwnedDigest,
    /// The authorization policy for the Lockout Hierarchy.
    pub lockout_policy: OwnedDigest,
    /// The hash algorithm used when setting the Owner policy.
    pub owner_alg: Option<tpm2::TpmiAlgHash>,
    /// The hash algorithm used when setting the Endorsement policy.
    pub endorsement_alg: Option<tpm2::TpmiAlgHash>,
    /// The hash algorithm used when setting the Lockout policy.
    pub lockout_alg: Option<tpm2::TpmiAlgHash>,
    /// Counter tracking the number of failed authorization attempts (`failedTries`).
    pub failed_tries: u32,
    /// Count of authorization failures before the lockout is imposed (`maxTries`).
    pub max_tries: u32,
    /// Time in seconds before the authorization failure count is automatically decremented (`recoveryTime`).
    pub recovery_time: u32,
    /// Time in seconds after a lockoutAuth failure before use of lockoutAuth is allowed (`lockoutRecovery`).
    pub lockout_recovery: u32,
    /// Flag indicating whether use of `TPM_RH_LOCKOUT` authorization is enabled (`gp.lockOutAuthEnabled`).
    pub lockout_auth_enabled: bool,
    /// Tracks the highest monotonic NV counter value ever allocated or incremented across the lifetime
    /// of the TPM (`s_maxCounter` in `ibmswtpm2`).
    pub max_counter: u64,
    /// Hash algorithm for the PCR policy group (PCRs 20-22, matching `gp.pcrPolicies.hashAlg`).
    pub pcr_policy_alg: Option<tpm2::TpmiAlgHash>,
    /// Policy digest for the PCR policy group (PCRs 20-22, matching `gp.pcrPolicies.policy`).
    pub pcr_policy: OwnedDigest,
    /// Number of command audit logs started (`gp.auditCounter`, `TPM_PT_AUDIT_COUNTER_0/1`).
    /// Persistent; reset to zero by `TPM2_Clear`.
    pub audit_counter: u64,
    /// Hash algorithm of the command audit digest (`gp.auditHashAlg`), changed by
    /// `TPM2_SetCommandCodeAuditStatus`. Persistent; `context_integrity_hash_alg()` at
    /// manufacture (SHA-512, or SHA-384 without SHA-512).
    pub audit_hash_alg: u16,
    /// The commands whose execution is recorded in the command audit digest
    /// (`gp.auditCommands`). Persistent.
    pub audit_commands: CommandAuditList,
    /// The commands that require Physical Presence when authorized with `TPM_RH_PLATFORM`
    /// (`gp.ppList`, changed by `TPM2_PP_Commands`). Persistent
    /// ([`crate::physical_presence`]).
    pub pp_list: PpList,
    /// The vendor-dependent algorithm set (`gp.algorithmSet`, `TPM_PT_ALGORITHM_SET`, changed
    /// by `TPM2_SetAlgorithmSet`). Persistent; 0 at manufacture.
    pub algorithm_set: u32,
}

/// Data which is always persisted on `TPM2_Shutdown` (`go`, `ORDERLY_DATA` of the TCG
/// reference), read during `_TPM_Init`.
#[derive(Debug, Clone)]
pub struct OrderlyState {
    /// Internal SP800-90A CTR_DRBG state (`go.drbgState`) preserved across orderly shutdowns.
    pub drbg_state: DrbgState,
    /// *Time* at the last `TPM2_Shutdown` (`go.time` of the TCG reference: `go.time = g_time;`),
    /// by which `TPM2_Startup` after an orderly shutdown and a power cycle rebases the
    /// dictionary-attack timers.
    pub shutdown_time_ms: u64,
    /// Timestamp in `tpm_time_ms` ticks (signed for startup offset adjustment) tracking `failed_tries` self-healing (`s_selfHealTimer` / `go.selfHealTimer`).
    pub self_heal_timer: i64,
    /// Timestamp in `tpm_time_ms` ticks (signed for startup offset adjustment) tracking `lockoutAuth` recovery (`s_lockoutTimer` / `go.lockoutTimer`).
    pub lockout_timer: i64,
    /// Offset added to the raw monotonic timer count to get the current TPM clock value (mutated via TPM2_ClockSet).
    pub clock_offset: i64,
    /// Whether the reported `Clock` is known not to have been rolled back (`go.clockSafe`).
    /// Cleared on a startup after an unorderly shutdown (`TimeStartup`) and set again whenever the
    /// clock is written to NV (`TimeClockUpdate`), by `TPM2_Clear`, and at manufacture.
    pub clock_safe: bool,
}

/// Data which is persisted on `TPM2_Shutdown(TPM_SU_STATE)` and restored by `TPM2_Startup` on
/// TPM Restart and TPM Resume (`gr`, `STATE_RESET_DATA` of the TCG reference); TPM Reset
/// re-initializes it.
#[derive(Debug, Clone)]
pub struct ResetState {
    /// A counter that increments upon every TPM restart (TPM_PT_RESTART_COUNT).
    pub restart_count: u32,
    /// A counter that increments upon every TPM clear operation (TPM_PT_CLEAR_COUNT).
    pub clear_count: u32,
    /// The seed value used for the Null Hierarchy.
    pub null_seed: [u8; 64],
    /// The actual length of the Null Hierarchy seed.
    pub null_seed_size: u16,
    /// The proof value for the Null Hierarchy.
    pub null_proof: [u8; 64],
    /// The actual length of the Null Hierarchy proof.
    pub null_proof_size: u16,
    /// Handles of the sessions whose context has been saved (and that are neither flushed nor
    /// loaded again), indexed by session slot (`handle & 0x00FF_FFFF`). Together with
    /// [`ResetState::saved_session_sequences`] this is the saved part of `gr.contextArray`.
    pub saved_sessions: [Option<u32>; MAX_ACTIVE_SESSIONS],
    /// Context sequence number (`TPMS_CONTEXT.sequence`) of the latest `TPM2_ContextSave` of
    /// the session in each slot of [`ResetState::saved_sessions`]. Only that context may be
    /// loaded again (`SequenceNumberForSavedContextIsValid`).
    pub saved_session_sequences: [u64; MAX_ACTIVE_SESSIONS],
    /// The commit counter (`gr.commitCounter`, a `UINT64`): incremented by every successful
    /// `TPM2_Commit`; its low 16 bits are the `counter` returned to the caller.
    pub commit_counter: u64,
    /// Bitmap of outstanding commitments (`gr.commitArray`). Bit `count & COMMIT_INDEX_MASK` is
    /// set by TPM2_Commit and cleared once an ECDAA signature consumes the commitment, so each
    /// committed `r` can be used for at most one signature.
    pub commit_array: [u8; 16],
    /// A secret nonce used to derive commit scalars (`r`) deterministically via KDFa per
    /// `CryptGenerateR` (`gr.commitNonce`).
    pub commit_nonce: [u8; COMMIT_NONCE_SIZE],
    /// A sequence number used for generating unique context identifiers for saved objects.
    pub context_counter: u64,
    pub object_context_counter: u64,
    /// The command audit digest register (`gr.commandAuditDigest`): empty when no audit log is
    /// in progress. Saved by `TPM2_Shutdown(TPM_SU_STATE)` and cleared on TPM Reset.
    pub command_audit_digest: OwnedDigest,
}

/// Data which is persisted on `TPM2_Shutdown(TPM_SU_STATE)` and restored by
/// `TPM2_Startup(TPM_SU_STATE)` on TPM Resume (`gc`, `STATE_CLEAR_DATA` of the TCG
/// reference); TPM Reset and TPM Restart re-initialize it.
#[derive(Debug, Clone)]
pub struct ClearState {
    /// Flag indicating whether the Storage Hierarchy is enabled.
    pub sh_enable: bool,
    /// Flag indicating whether the Endorsement Hierarchy is enabled.
    pub eh_enable: bool,
    /// Flag indicating whether the Platform Hierarchy NV operations are enabled.
    pub ph_enable_nv: bool,
    /// Whether the TPM is in the Read-Only mode of operation (`TPMA_STARTUP_CLEAR.readOnly`,
    /// `gc.readOnly`; set by `TPM2_ReadOnlyControl`, the `cc-read-only-control` feature, and
    /// always CLEAR without it). Part 2, TPMA_STARTUP_CLEAR: "*readOnly* is CLEAR on TPM Reset
    /// or TPM Restart and preserved by TPM Resume" (it is part of the state saved by
    /// `TPM2_Shutdown(TPM_SU_STATE)`). Like the reference's `gc`, it is kept by `_TPM_Init`
    /// ([`State::reset_in_place`]) until the next `TPM2_Startup`.
    pub read_only: bool,
    /// The authorization value for the Platform Hierarchy.
    pub platform_auth: OwnedAuth,
    /// The authorization policy for the Platform Hierarchy.
    pub platform_policy: OwnedDigest,
    /// The hash algorithm used when setting the Platform policy.
    pub platform_alg: Option<tpm2::TpmiAlgHash>,
    /// Per-PCR authorization value for the PCR authorization group (PCRs 20-22, matching `gc.pcrAuthValues`).
    pub pcr_auth_value: OwnedAuth,
}

impl<P: Platform> State<P> {
    /// The state of a new (unmanufactured) TPM whose NV data is held in `index`.
    pub fn new(index: P::IndexState) -> Self {
        Self {
            initialized: false,
            locality: 0,
            nv_available: true,
            g_nv_ok: false,
            prev_orderly_state: 0xFFFF,
            update_nv: UT_NONE,
            clear_orderly: false,
            drtm_pre_startup: false,
            drtm_handle: Handle::RH_UNASSIGNED.0,
            startup_locality_3: false,
            da_used: false,
            power_was_lost: true,
            timer_stopped: true,
            timer_was_reset: true,
            ph_enable: true,
            transient_objects: [const { None }; MAX_LOADED_OBJECTS],
            active_sessions: [const { None }; MAX_LOADED_SESSIONS],
            active_sequences: [const { None }; MAX_ACTIVE_SEQUENCES],
            command_persistent_objects: 0,
            platform_unique_details: OwnedAuth::default(),
            tpm_time_ms: 0,
            last_timer_read_ms: None,
            da_pending_on_nv: false,
            parsed_auths: [
                OwnedAuthCommand::default(),
                OwnedAuthCommand::default(),
                OwnedAuthCommand::default(),
            ],
            parsed_auths_len: 0,
            session_audit_cp_hashes: [None; 3],
            sessions_validated_by_handler: false,
            exclusive_audit_session: None,
            in_shadow_execution: false,
            clock_adjust_rate: CLOCK_NOMINAL,
            clock_adjust_remainder: 0,
            pcrs: PcrState::default(),
            pcr_reconfig: false,
            command_audit_cp_hash: None,
            command_audit_alg_changed: false,
            act: crate::act::ActState::default(),
            physical_presence: false,
            nv: Nv::new(index),
        }
    }

    /// Returns every value of the state to that of a new TPM ([`State::new`]) except the NV
    /// data structure [`Nv::index`], which is kept as it is.
    pub fn reinitialize(&mut self) {
        self.initialized = false;
        self.locality = 0;
        self.nv_available = true;
        self.g_nv_ok = false;
        self.prev_orderly_state = 0xFFFF;
        self.update_nv = UT_NONE;
        self.clear_orderly = false;
        self.drtm_pre_startup = false;
        self.drtm_handle = Handle::RH_UNASSIGNED.0;
        self.startup_locality_3 = false;
        self.da_used = false;
        self.power_was_lost = true;
        self.timer_stopped = true;
        self.timer_was_reset = true;
        self.ph_enable = true;
        self.transient_objects = [const { None }; MAX_LOADED_OBJECTS];
        self.active_sessions = [const { None }; MAX_LOADED_SESSIONS];
        self.active_sequences = [const { None }; MAX_ACTIVE_SEQUENCES];
        self.command_persistent_objects = 0;
        self.platform_unique_details = OwnedAuth::default();
        self.tpm_time_ms = 0;
        self.last_timer_read_ms = None;
        self.da_pending_on_nv = false;
        self.parsed_auths = [
            OwnedAuthCommand::default(),
            OwnedAuthCommand::default(),
            OwnedAuthCommand::default(),
        ];
        self.parsed_auths_len = 0;
        self.session_audit_cp_hashes = [None; 3];
        self.sessions_validated_by_handler = false;
        self.exclusive_audit_session = None;
        self.in_shadow_execution = false;
        self.clock_adjust_rate = CLOCK_NOMINAL;
        self.clock_adjust_remainder = 0;
        self.pcrs = PcrState::default();
        self.pcr_reconfig = false;
        self.command_audit_cp_hash = None;
        self.command_audit_alg_changed = false;
        self.act = crate::act::ActState::default();
        self.physical_presence = false;
        self.nv.persistent = PersistentState::default();
        self.nv.orderly = OrderlyState::default();
        self.nv.reset = ResetState::default();
        self.nv.clear = ClearState::default();
    }
}

impl<P: Platform> Default for State<P>
where
    P::IndexState: Default,
{
    fn default() -> Self {
        Self::new(P::IndexState::default())
    }
}

impl Default for PersistentState {
    fn default() -> Self {
        Self {
            reset_count: 0,
            time_epoch: 0,
            orderly_state: 0,
            total_reset_count: 0,
            disable_clear: false,
            sh_proof: [0; 64],
            eh_proof: [0; 64],
            ph_proof: [0; 64],
            sp_seed: [0; 64],
            pp_seed: [0; 64],
            ep_seed: [0; 64],
            // Unprovisioned until manufacture (`init_storage`) or the NV hierarchy record.
            sh_proof_size: 0,
            eh_proof_size: 0,
            ph_proof_size: 0,
            sp_seed_size: 0,
            pp_seed_size: 0,
            ep_seed_size: 0,
            owner_auth: OwnedAuth::default(),
            endorsement_auth: OwnedAuth::default(),
            lockout_auth: OwnedAuth::default(),
            owner_policy: OwnedDigest::default(),
            endorsement_policy: OwnedDigest::default(),
            lockout_policy: OwnedDigest::default(),
            owner_alg: None,
            endorsement_alg: None,
            lockout_alg: None,
            failed_tries: 0,
            max_tries: 3,
            recovery_time: 1000,
            lockout_recovery: 1000,
            lockout_auth_enabled: true,
            max_counter: 0,
            pcr_policy_alg: None,
            pcr_policy: OwnedDigest::default(),
            audit_counter: 0,
            audit_hash_alg: tpm2::Alg::from(crate::handler::context_integrity_hash_alg()).id(),
            audit_commands: CommandAuditList::manufacture_default(),
            pp_list: PpList::manufacture_default(),
            algorithm_set: 0,
        }
    }
}

impl Default for OrderlyState {
    fn default() -> Self {
        Self {
            drbg_state: DrbgState::default(),
            shutdown_time_ms: 0,
            self_heal_timer: 0,
            lockout_timer: 0,
            clock_offset: 0,
            clock_safe: true,
        }
    }
}

impl Default for ResetState {
    fn default() -> Self {
        Self {
            restart_count: 0,
            clear_count: 0,
            null_seed: [0; 64],
            null_seed_size: 0,
            null_proof: [0; 64],
            null_proof_size: 0,
            saved_sessions: [None; MAX_ACTIVE_SESSIONS],
            saved_session_sequences: [0; MAX_ACTIVE_SESSIONS],
            commit_counter: 0,
            commit_array: [0u8; 16],
            commit_nonce: [0x5a; COMMIT_NONCE_SIZE],
            context_counter: 0,
            object_context_counter: 0,
            command_audit_digest: OwnedDigest::default(),
        }
    }
}

impl Default for ClearState {
    fn default() -> Self {
        Self {
            sh_enable: true,
            eh_enable: true,
            ph_enable_nv: true,
            read_only: false,
            platform_auth: OwnedAuth::default(),
            platform_policy: OwnedDigest::default(),
            platform_alg: None,
            pcr_auth_value: OwnedAuth::default(),
        }
    }
}
