//! # TPM 2.0 Command Handlers
//!
//! This module contains individual command handlers (e.g., [random::get_random](random.rs), [pcr::pcr_read](pcr.rs)) grouped by functional category.
//!
//! ## Role and Scope
//!
//! Each handler is an extension of the [CommandHandler](mod.rs#L130-L133) struct. The handler infrastructure is responsible for:
//! - **Parameter Extraction**: Unmarshaling command-specific input arguments from the [RequestThenResponse](../req_resp.rs#L7-L9) buffer.
//! - **Core Action**: Implementing the specific logical steps, algorithm validations, and cryptographic transformations required for the command.
//! - **Response Assembly**: Marshaling command-specific output arguments back to the [Response](../req_resp.rs#L111-L113) buffer.
//!
//! ## Encapsulation Boundaries
//!
//! - **No Direct Session Management**: Handlers do not directly handle session HMAC validation, session parameter encryption, or session parameter decryption.
//!   These tasks are performed by the outer [TpmEngine](../engine.rs) before and after dispatching to the handler.
//! - **State Mutations via Engine**: Handlers do not directly mutate internal global state tables. Instead, they interact with the TPM state via safe methods
//!   on the mutable [TpmEngine](../engine.rs) reference (`self.context`).
//!
//! ## Handlers with Cryptographic Payload Responsibilities
//!
//! While outer session cryptographics are managed by the engine, several handlers perform command-specific cryptographic operations on user-supplied payloads:
//! - **Symmetric/Asymmetric Encryption**: [encrypt_decrypt::encrypt_decrypt](encrypt_decrypt.rs) (symmetric block ciphers), [crypt_ops::rsa_encrypt](crypt_ops.rs) / [crypt_ops::rsa_decrypt](crypt_ops.rs) (asymmetric key wrappers).
//! - **Integrity / MAC**: [crypt_ops::hmac](crypt_ops.rs) (computes HMAC).
//! - **Signature Validation**: [crypt_ops::verify_signature](crypt_ops.rs) (validates signature integrity).
//! - **Key Management Security**: [duplicate::duplicate](duplicate.rs) (encrypts object payloads for migration), [import::import](import.rs) (decrypts imported objects).

mod activate_credential;
pub(crate) mod capability;
mod certify;
mod change_eps;
mod change_pps;
mod clear;
mod clear_control;
mod clock_ops;
pub(crate) mod commit;
mod context_load;
mod context_save;
mod create;
mod create_loaded;
mod create_primary;
mod crypt_ops;
mod da;
mod duplicate;
mod ecdh;
mod encrypt_decrypt;
mod evict_control;
mod flush_context;
mod get_command_audit_digest;
mod get_session_audit_digest;
mod get_time;
mod hierarchy_change_auth;
mod hierarchy_control;
mod import;
mod load;
mod load_external;
mod make_credential;
pub(crate) mod nv_storage;
mod object_change_auth;
mod pcr;
mod policy_auth_value;
mod policy_authorize;
mod policy_authorize_nv;
mod policy_counter_timer;
mod policy_cp_hash;
mod policy_duplication_select;
mod policy_locality;
mod policy_name_hash;
mod policy_nv;
mod policy_nv_written;
mod policy_or;
mod policy_password;
mod policy_pcr;
mod policy_secret;
mod policy_signed;
mod policy_template;
mod policy_ticket;
mod quote;
mod random;
mod read_clock;
mod read_public;
#[cfg(feature = "reference-rng")]
pub(crate) mod reference_ops;
mod rewrap;
mod sequence;
pub(crate) mod session;
mod set_command_code_audit_status;
mod set_primary_policy;
mod shutdown;
mod startup;
mod testing;
mod unseal;

use crate::owned::{
    AuthCommandLike, OwnedAuth, OwnedAuthCommand, OwnedDigest, OwnedEccPoint, OwnedName,
    OwnedNonce, OwnedPublic, OwnedPublicKeyRsa, OwnedPublicParmsAndId, OwnedTpm2b,
};
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{GlobalState, TpmEngine};
use tpm2::Alg;
use tpm2::crypto::asymmetric::KeyParams;
use tpm2::crypto::kdf::kdfa_bits;
use tpm2::crypto::{
    CryptoError, CryptoProvider, Direction, HashStream, ModeIv, Rng, Symmetric, SymmetricKey,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmSe};
use tpm2::{Marshal, Unmarshal};
use tpm2::{
    Tpm2bAuth, Tpm2bDigest, Tpm2bNonce, TpmaObject, TpmaSession, TpmiAlgHash, TpmiAlgSymMode,
    TpmlPcrSelection, TpmsAuthResponse, TpmsEccParms, TpmsRsaParms, TpmtSymDef, TpmtSymDefObject,
};

/// The `qualifiedSigner` reported in attestation structures when `signHandle` is `TPM_RH_NULL`.
const ATTEST_NULL_SIGNER_NAME: [u8; 4] = Handle::RH_NULL.0.to_be_bytes();

/// The plain-text `firmwareVersion` reported in attestation structures:
/// `(TPM_PT_FIRMWARE_VERSION_1 << 32) | TPM_PT_FIRMWARE_VERSION_2`, which must agree with the
/// values reported by `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES)` (see `capability.rs`:
/// `FIRMWARE_VERSION_1 = 1`, `FIRMWARE_VERSION_2 = 0`).
pub(crate) const ATTEST_FIRMWARE_VERSION: u64 = 1u64 << 32;

/// The common header fields of an attestation structure (`TPMS_ATTEST`), as filled in by
/// `FillInAttestInfo()` in the reference implementation. Produced by
/// [`CommandHandler::compute_attest_fields`].
pub struct AttestHeader<'c> {
    /// `TPMS_ATTEST.qualifiedSigner`.
    pub qualified_signer: tpm2::Tpm2bName<'c>,
    /// `TPMS_ATTEST.extraData`.
    pub extra_data: tpm2::Tpm2bData<'c>,
    /// `TPMS_ATTEST.clockInfo` (possibly obfuscated).
    pub clock_info: tpm2::TpmsClockInfo,
    /// `TPMS_ATTEST.firmwareVersion` (possibly obfuscated).
    pub firmware_version: u64,
}

/// Represents an object loaded into the TPM's volatile memory.
/// This structure holds the state of a transient object, which could be a key or a data object,
/// that is actively being used by the TPM.
#[derive(Debug, Clone)]
pub struct TransientObject {
    /// The transient handle assigned to this object (e.g., in the 0x80xxxxxx range).
    pub handle: u32,
    /// The sensitive `seedValue` of the object (`TPMT_SENSITIVE.seedValue`). Only the first
    /// `seed_len` bytes are meaningful; for SYMCIPHER/KEYEDHASH objects and storage parents this
    /// is a `nameAlg`-sized value (up to 64 bytes for SHA-512) that is used in full as the key
    /// for the `STORAGE`/`INTEGRITY` KDFs of children. Non-parent asymmetric keys and public-only
    /// objects may have an empty seed.
    pub seed: [u8; 64],
    /// The number of meaningful bytes in `seed`.
    pub seed_len: usize,
    /// Set for objects loaded with `TPM2_LoadExternal` (C `attributes.external`). External
    /// objects can never act as parents (`ObjectIsParent` is FALSE for them).
    pub external: bool,
    /// Set for objects loaded with `TPM2_LoadExternal` without a sensitive area (C
    /// `attributes.publicOnly`). Such objects have neither an authValue nor an authPolicy
    /// available (`IsAuthValueAvailable`/`IsAuthPolicyAvailable` return FALSE).
    pub public_only: bool,
    /// The cryptographically derived name of the object.
    pub name: OwnedName,
    /// The authorization value or policy required to use this object.
    pub auth: OwnedAuth,
    /// The public area of the object, describing its attributes and public key.
    pub public: OwnedPublic,
    /// The encrypted private area of the object, containing sensitive data like the private key.
    pub private: [u8; 1536],
    /// The actual length of the data stored in the `private` array.
    pub private_len: usize,
    /// The qualified name of the object, recursively linking it to the hierarchy root.
    pub qualified_name: OwnedName,
    /// The handle of the hierarchy to which this object belongs (e.g., Owner, Platform, Endorsement, or Null).
    pub hierarchy: u32,
    /// Indicates whether the object has the `stClear` attribute, meaning its state should be cleared upon a TPM restart.
    pub st_clear: bool,
}

impl TransientObject {
    /// Returns the meaningful bytes of the object's `seedValue` (`seed[..seed_len]`).
    pub fn seed_bytes(&self) -> &[u8] {
        &self.seed[..self.seed_len]
    }

    /// Builds a `seed`/`seed_len` pair from a `seedValue` byte slice (truncated to 64 bytes,
    /// the largest supported digest size).
    pub fn seed_from_bytes(bytes: &[u8]) -> ([u8; 64], usize) {
        let mut seed = [0u8; 64];
        let len = core::cmp::min(bytes.len(), seed.len());
        seed[..len].copy_from_slice(&bytes[..len]);
        (seed, len)
    }
}

/// Represents the state of an active authorization session.
#[derive(Debug, Clone)]
pub struct SessionState {
    pub session_handle: u32,
    pub session_type: TpmSe,
    pub auth_hash: TpmiAlgHash,
    pub nonce_tpm: OwnedNonce,
    pub nonce_caller: OwnedNonce,
    pub session_key: [u8; 128],
    pub session_key_len: usize,
    pub symmetric: Option<TpmtSymDef>,
    pub bind_entity: Handle,
    pub bound_entity: OwnedName,
    pub audit_digest: Option<[u8; 64]>,
    pub audit_digest_len: usize,
    pub audit_cp_hash: [u8; 64],
    pub audit_cp_hash_len: usize,
    pub policy_hash: [u8; 64],
    pub policy_hash_len: usize,
    pub is_cp_hash_defined: bool,
    pub is_name_hash_defined: bool,
    pub is_template_hash_defined: bool,
    pub policy_digest: [u8; 64],
    pub policy_digest_len: usize,
    pub command_code: u32,
    pub start_time: u64,
    pub timeout: u64,
    pub epoch: u64,
    pub is_auth_value_needed: bool,
    pub is_password_needed: bool,
    pub pcr_counter: Option<u32>,
    pub check_nv_written: bool,
    pub nv_written_state: bool,
    pub command_locality: u8,
    pub include_auth: bool,
    /// The session was started with a DA-protected bind entity (C `isDaBound`: `bind !=
    /// TPM_RH_NULL && !IsDAExempted(bind)`), for every session type. Use of such a session is
    /// subject to dictionary-attack protection regardless of the entity it authorizes.
    pub is_da_bound: bool,
    /// The session is DA-bound to `TPM_RH_LOCKOUT` (C `isLockoutBound`).
    pub is_lockout_bound: bool,
}

/// Resolved parent object or hierarchy information returned by `resolve_parent_object_or_hierarchy`.
pub struct ResolvedParentInfo {
    pub req_auth: bool,
    pub seed_len: usize,
    pub qn_len: usize,
    pub hierarchy_val: u32,
    pub has_st_clear: bool,
    pub name_alg: TpmiAlgHash,
    pub sym_bits: u32,
    pub attributes: TpmaObject,
    pub is_derivation_parent: bool,
    /// Scheme-relevant properties of a parent *object* (`None` for hierarchy parents).
    pub scheme: Option<ParentSchemeInfo>,
}

/// Properties of a parent object needed by `SchemeChecks`/`PublicAttributesValidation`
/// when validating a child's public area.
#[derive(Debug, Clone, Copy)]
pub struct ParentSchemeInfo {
    /// The parent's own nameAlg (a non-duplicable storage child must use the same).
    pub name_alg: Option<TpmiAlgHash>,
    /// The parent's symmetric definition (RSA/ECC `symmetric`, or the SYMCIPHER definition).
    pub symmetric: Option<tpm2::TpmtSymDefObject>,
    /// Whether the parent is a derivation parent (restricted decrypt KEYEDHASH).
    pub is_derivation: bool,
}

/// Parameters for key derivation during key generation.
pub struct KeyDerivationArgs<'a> {
    pub gen_seed: Option<&'a [u8]>,
    pub obj_seed: &'a [u8],
    pub get_random_fallback: bool,
    pub fallback_sensitive_data: Option<&'a [u8]>,
}

/// Encrypts or decrypts `data` in place with the symmetric algorithm and block cipher mode of
/// `alg`, the key `key` and the IV `iv`. `iv` is updated in place with the chaining value for a
/// following call (`ivOut` of `TPM2_EncryptDecrypt`).
///
/// PORTING: this is exp's `tpm2::crypto::{encrypt, decrypt, encrypt_decrypt}(s, alg, key, iv,
/// ..)` on top of the upstream one-shot [`tpm2::crypto::encrypt_decrypt`]. It fails in the same
/// cases as exp (every caller maps any failure to its own response code), checked in exp's order
/// before `data` is touched:
/// - `alg.mode` is `None` or not a block cipher mode (`TPM_ALG_CMAC`):
///   [`CryptoError::Unsupported`] (exp: `unimplemented(TPM_ALG_NULL)` / an unsupported mode).
/// - `iv` is not exactly one block (16 bytes) long, or not empty for ECB:
///   [`CryptoError::Internal`] (exp: `invalid_iv()`).
/// - `key` does not have the key size of `alg.alg`: [`CryptoError::Internal`] (exp:
///   `invalid_key()`).
///
/// Errors of the backend itself (for example [`CryptoError::Unsupported`] for an algorithm or
/// mode it does not implement) are passed through.
pub fn sym_encrypt_decrypt(
    s: &impl Symmetric,
    alg: TpmtSymDefObject,
    key: &[u8],
    iv: &mut [u8],
    dir: Direction,
    data: &mut [u8],
) -> Result<(), CryptoError> {
    let mode = match alg.mode {
        Some(TpmiAlgSymMode::Cipher(mode)) => mode,
        _ => return Err(CryptoError::Unsupported),
    };
    let mode_iv = ModeIv::new(mode, iv).ok_or(CryptoError::Internal)?;
    let key = SymmetricKey::new(alg.alg, key).ok_or(CryptoError::Internal)?;
    tpm2::crypto::encrypt_decrypt(s, key, mode_iv, dir, data)
}

/// The context that all command handler functions are given access to in order for them to process
/// their given command.
pub struct CommandHandler<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync> {
    /// The engine (platform and TPM state) the command operates on.
    pub context: &'b mut TpmEngine<'a, C, S, T, R>,
}

/// Hash algorithm for context integrity, tickets and the other proof-keyed HMACs
/// (`CONTEXT_INTEGRITY_HASH_ALG`, reported as `TPM_PT_CONTEXT_HASH`).
///
/// TPM 2.0 Part 1, "Context Integrity Protection": the algorithm "is required to have the
/// highest security strength of any hash algorithm implemented on the TPM", i.e. SHA-512, or
/// SHA-384 when the installed profile has no SHA-512 ([`tpm2::profile::Profile::sha512`]; the C
/// references' `CONTEXT_HASH_ALGORITHM` follows `ALG_SHA512` the same way).
/// Tickets are HMACs with this algorithm (Part 2, `TPMT_TK_*`), and the hierarchy authValue
/// limit of `TPM2_HierarchyChangeAuth` is its digest size (Part 1, "Authorization Size
/// Convention").
pub(crate) fn context_integrity_hash_alg() -> TpmiAlgHash {
    if tpm2::profile::allows_algorithm(tpm2::Alg::SHA512) {
        TpmiAlgHash::Sha512
    } else {
        TpmiAlgHash::Sha384
    }
}

/// Returns the first `size` bytes of a Primary Seed or hierarchy proof buffer.
///
/// A size of 0 marks a value that was never provisioned (the TPM was not manufactured, or the
/// platform RNG failed during manufacture). Primary Seeds and proofs are secret random values
/// (TPM 2.0 Part 1, "Primary Seeds", "Hierarchy Proofs"), so an unprovisioned value is never
/// used as key material: this fails with `TPM_RC_FAILURE` instead.
pub(crate) fn provisioned_secret(buf: &[u8; 64], size: u16) -> Result<&[u8], TpmRc> {
    match buf.get(..size as usize) {
        Some(secret) if !secret.is_empty() => Ok(secret),
        _ => Err(TpmRc::FAILURE),
    }
}

/// The largest digest size of [`context_integrity_hash_alg`] (SHA-512): the capacity of every
/// ticket digest.
pub(crate) const TICKET_DIGEST_SIZE: usize = 64;

/// A ticket digest: an HMAC with [`context_integrity_hash_alg`].
pub(crate) type TicketDigest = crate::owned::OwnedTpm2b<TICKET_DIGEST_SIZE>;

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Creates a new `CommandHandler` object.
    pub fn new(context: &'b mut TpmEngine<'a, C, S, T, R>) -> Self {
        Self { context }
    }

    #[inline]
    pub fn state(&self) -> &GlobalState {
        &self.context.state
    }

    #[inline]
    pub fn state_mut(&mut self) -> &mut GlobalState {
        &mut self.context.state
    }

    #[inline]
    pub fn crypto(&self) -> &C {
        self.context.platform.crypto
    }

    #[inline]
    pub fn get_clock(&self) -> u64 {
        self.context.get_clock()
    }

    #[inline]
    pub fn get_clock_info(&self) -> tpm2::TpmsClockInfo {
        self.context.get_clock_info()
    }

    #[inline]
    pub fn get_time_info(&self) -> tpm2::TpmsTimeInfo {
        self.context.get_time_info()
    }

    /// Verifies that `auth_handle` is either `TPM_RH_OWNER` or `TPM_RH_PLATFORM` and that the
    /// command carried an authorization session for it.
    ///
    /// The authorization itself (password / HMAC / policy, including the `TPM_RC_BAD_AUTH`
    /// reported for these DA-exempt hierarchies) has already been verified by the engine
    /// (`verify_session_hmacs`) before the handler runs, so it is not re-checked here. A command
    /// without a session for a handle that requires authorization fails with
    /// `TPM_RC_AUTH_MISSING` regardless of the authValue (`CheckAuthNoSession`).
    pub fn validate_provision_auth(
        &mut self,
        auth_handle: u32,
        provided_auth: Option<impl Into<OwnedAuthCommand>>,
    ) -> Result<(), TpmRc> {
        if auth_handle != Handle::RH_PLATFORM.0 && auth_handle != Handle::RH_OWNER.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }
        if provided_auth.is_none() {
            return Err(TpmRc::AUTH_MISSING);
        }
        Ok(())
    }

    /// Verifies that `auth_handle` is `TPM_RH_PLATFORM`, that the platform hierarchy is enabled,
    /// and that the command carried an authorization session for it. See
    /// [`Self::validate_provision_auth`] for why the authorization is not re-verified here.
    pub fn validate_platform_auth(
        &mut self,
        auth_handle: u32,
        provided_auth: Option<impl Into<OwnedAuthCommand>>,
    ) -> Result<(), TpmRc> {
        if auth_handle != Handle::RH_PLATFORM.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        if !self.context.state.ph_enable {
            return Err(TpmRc::HIERARCHY.with(Position::handle(1)));
        }

        if provided_auth.is_none() {
            return Err(TpmRc::AUTH_MISSING);
        }
        Ok(())
    }

    /// Verifies that `auth_handle` is `TPM_RH_LOCKOUT` and that the command carried an
    /// authorization session for it.
    ///
    /// The dictionary-attack checks for `lockoutAuth` (`CheckLockedOut`: NV availability,
    /// pending DA writes and `lockOutAuthEnabled`) are performed by the engine during session
    /// verification and, as in the C reference, only when the session actually uses the
    /// authValue. They are deliberately not repeated here, so that a `lockoutPolicy` policy
    /// session without `TPM2_PolicyAuthValue`/`TPM2_PolicyPassword` keeps working while direct
    /// use of `lockoutAuth` is disabled.
    pub fn validate_lockout_auth(
        &mut self,
        auth_handle: u32,
        provided_auth: Option<impl Into<OwnedAuthCommand>>,
    ) -> Result<(), TpmRc> {
        if auth_handle != Handle::RH_LOCKOUT.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }
        if provided_auth.is_none() {
            return Err(TpmRc::AUTH_MISSING);
        }
        Ok(())
    }

    pub fn parse_and_validate_sessions(
        &mut self,
        request: &mut RequestThenResponse<'_, '_>,
    ) -> Result<([TpmsAuthResponse<'static>; 3], usize), TpmRc> {
        if !self.state().in_shadow_execution {
            self.state_mut().sessions_validated_by_handler = true;
        }
        let mut session_responses = [TpmsAuthResponse::default(); 3];
        let mut num_sessions = 0;

        let parsed_auths_len = self.state().parsed_auths_len;
        if parsed_auths_len > 0 {
            for auth in &self.state().parsed_auths[..parsed_auths_len] {
                let continue_bit = (auth.session_attributes.0 & 1) | 1;
                session_responses[num_sessions] = TpmsAuthResponse {
                    nonce: Tpm2bNonce::default(),
                    session_attributes: TpmaSession(continue_bit),
                    hmac: Tpm2bAuth::default(),
                };
                num_sessions += 1;
            }
            return Ok((session_responses, num_sessions));
        }

        let auth_size = if request.session_tag() == tpm2::TpmiStCommandTag::Sessions {
            request.read_be_u32().ok_or(TpmRc::SIZE.to_rc())?
        } else {
            0
        };

        if auth_size > 0 {
            let mut auth_slice = request
                .read_slice(auth_size as usize)
                .ok_or(TpmRc::SIZE.to_rc())?;
            while !auth_slice.is_empty() {
                if num_sessions >= 3 {
                    return Err(TpmRc::SIZE.with(Position::session(4)));
                }
                let auth = OwnedAuthCommand::unmarshal(&mut auth_slice).map_err(|e| {
                    e.with_position(Position::session((num_sessions + 1) as u8))
                        .to_rc()
                })?;

                self.state_mut().parsed_auths[num_sessions] = auth;
                self.state_mut().parsed_auths_len += 1;

                if auth.session_handle != Handle::RS_PW {
                    let sess_handle = auth.session_handle.0;
                    if self.state().session(sess_handle).is_none() {
                        let pos = match num_sessions {
                            0 => Position::handle(1),
                            1 => Position::handle(2),
                            _ => Position::handle(3),
                        };
                        return Err(TpmRc::HANDLE.with(pos));
                    }
                }

                let continue_bit = (auth.session_attributes.0 & 1) | 1;
                session_responses[num_sessions] = TpmsAuthResponse {
                    nonce: Tpm2bNonce::default(),
                    session_attributes: TpmaSession(continue_bit),
                    hmac: Tpm2bAuth::default(),
                };
                num_sessions += 1;
            }
        }

        Ok((session_responses, num_sessions))
    }

    /// Formats and writes the response payload and active session responses to the output buffer.
    pub fn write_response<
        HP: Marshal<MaxBuffer = [u8; NH]>,
        RP: Marshal<MaxBuffer = [u8; NR]>,
        const NH: usize,
        const NR: usize,
    >(
        &self,
        mut response: crate::req_resp::Response<'_, '_>,
        handles: Option<&HP>,
        rsp: Option<&RP>,
        session_responses: &[TpmsAuthResponse],
    ) -> Result<(), TpmRc> {
        if let Some(h) = handles {
            let mut buf = [0u8; NH];
            let len = h.marshal(&mut buf);
            response.write(&buf[..len]).map_err(|_| TpmRc::FAILURE)?;
        }

        let has_sessions = !session_responses.is_empty() && !self.state().in_shadow_execution;
        if has_sessions {
            let (param_len, buf) = if let Some(r) = rsp {
                let mut buf = [0u8; NR];
                let len = r.marshal(&mut buf);
                (len, Some(buf))
            } else {
                (0, None)
            };
            response
                .write(&(param_len as u32).to_be_bytes())
                .map_err(|_| TpmRc::FAILURE)?;
            if let Some(buf) = buf {
                response
                    .write(&buf[..param_len])
                    .map_err(|_| TpmRc::FAILURE)?;
            }
            for session_response in session_responses {
                let mut s_buf = [0u8; TpmsAuthResponse::MAX_SIZE];
                let len = session_response.marshal(&mut s_buf);
                response.write(&s_buf[..len]).map_err(|_| TpmRc::FAILURE)?;
            }
        } else if let Some(r) = rsp {
            let mut buf = [0u8; NR];
            let len = r.marshal(&mut buf);
            response.write(&buf[..len]).map_err(|_| TpmRc::FAILURE)?;
        }
        Ok(())
    }

    /// Formats and writes an empty response (no handles, no response parameters).
    pub fn write_response_none(
        &self,
        response: crate::req_resp::Response<'_, '_>,
        session_responses: &[TpmsAuthResponse],
    ) -> Result<(), TpmRc> {
        self.write_response::<(), (), 0, 0>(response, None, None, session_responses)
    }

    /// Formats and writes a response with only handles.
    pub fn write_response_handles<HP: Marshal<MaxBuffer = [u8; NH]>, const NH: usize>(
        &self,
        response: crate::req_resp::Response<'_, '_>,
        handles: &HP,
        session_responses: &[TpmsAuthResponse],
    ) -> Result<(), TpmRc> {
        self.write_response::<HP, (), NH, 0>(response, Some(handles), None, session_responses)
    }

    /// Formats and writes a response with only response parameters.
    pub fn write_response_rsp<RP: Marshal<MaxBuffer = [u8; NR]>, const NR: usize>(
        &self,
        response: crate::req_resp::Response<'_, '_>,
        rsp: &RP,
        session_responses: &[TpmsAuthResponse],
    ) -> Result<(), TpmRc> {
        self.write_response::<(), RP, 0, NR>(response, None, Some(rsp), session_responses)
    }

    /// Formats and writes a response with both handles and response parameters.
    pub fn write_response_all<
        HP: Marshal<MaxBuffer = [u8; NH]>,
        RP: Marshal<MaxBuffer = [u8; NR]>,
        const NH: usize,
        const NR: usize,
    >(
        &self,
        response: crate::req_resp::Response<'_, '_>,
        handles: &HP,
        rsp: &RP,
        session_responses: &[TpmsAuthResponse],
    ) -> Result<(), TpmRc> {
        self.write_response::<HP, RP, NH, NR>(response, Some(handles), Some(rsp), session_responses)
    }

    /// Formats and writes a response [`Message`](tpm2::Message) and the active session responses
    /// to the output buffer.
    ///
    /// Writes the response handle area (`rsp.handles()`), then the parameter area (`rsp`
    /// marshals only its parameters), preceded by `parameterSize` when the response carries
    /// sessions, and then the session responses. The output is byte-identical to
    /// [`Self::write_response_all`] (or [`Self::write_response_handles`],
    /// [`Self::write_response_rsp`], [`Self::write_response_none`]) called with the same handles
    /// and parameters: a response without parameters still gets a zero `parameterSize` when it
    /// carries sessions.
    pub fn write_response_message<M: tpm2::Message<MaxBuffer = [u8; N]>, const N: usize>(
        &self,
        mut response: crate::req_resp::Response<'_, '_>,
        rsp: &M,
        session_responses: &[TpmsAuthResponse],
    ) -> Result<(), TpmRc> {
        for handle in rsp.handles().as_ref() {
            let mut buf = [0u8; Handle::MAX_SIZE];
            let len = handle.marshal(&mut buf);
            response.write(&buf[..len]).map_err(|_| TpmRc::FAILURE)?;
        }
        self.write_response::<(), M, 0, N>(response, None, Some(rsp), session_responses)
    }

    /// Computes the cryptographic hash of a sequence of byte slices using the given hash algorithm.
    pub fn compute_hash(
        &self,
        hash_alg: TpmiAlgHash,
        buffers: &[&[u8]],
    ) -> Result<([u8; 64], usize), TpmRc> {
        let mut state =
            HashStream::new(self.crypto(), hash_alg).map_err(|_| TpmRc::VALUE.to_rc())?;
        for buf in buffers {
            state.update(buf).map_err(|_| TpmRc::FAILURE)?;
        }
        let mut digest_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let digest = state
            .finalize(&mut digest_buf)
            .map_err(|_| TpmRc::FAILURE)?;
        let len = digest.digest().len();
        Ok((digest_buf, len))
    }

    /// [`sym_encrypt_decrypt`] with this TPM's crypto provider: encrypts or decrypts `data` in
    /// place with the algorithm and mode of `alg`, `key` and `iv` (updated in place).
    pub fn sym_encrypt_decrypt(
        &self,
        alg: TpmtSymDefObject,
        key: &[u8],
        iv: &mut [u8],
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        sym_encrypt_decrypt(self.crypto(), alg, key, iv, dir, data)
    }

    /// Filters a PCR selection against the current PCR allocation (C `FilterPcr`).
    ///
    /// Bits beyond `sizeofSelect` are dropped, every bit of a selection whose bank is not in
    /// `pcr_allocation` is cleared, and the remaining bits are AND-ed with the allocated PCR
    /// mask of the bank. The returned list keeps the caller's hash order and `sizeofSelect`, so
    /// it can be reported as `pcrSelect` in creation data and quotes.
    pub fn filter_pcr_selection(&self, pcr_select: &TpmlPcrSelection) -> TpmlPcrSelection {
        let allocation = &self.context.state.pcrs.pcr_allocation;
        let mut filtered = TpmlPcrSelection::default();
        for in_sel in pcr_select.pcr_selections() {
            let mut bytes = [0u8; tpm2::TPM2_PCR_SELECT_MAX as usize];
            let requested = in_sel.pcr_select();
            if let Some(alloc) = allocation
                .pcr_selections()
                .find(|a| a.hash() == in_sel.hash())
            {
                let alloc_bits = alloc.pcr_select();
                for (i, byte) in bytes.iter_mut().enumerate().take(requested.len()) {
                    *byte = requested[i] & alloc_bits.get(i).copied().unwrap_or(0);
                }
            }
            if let Ok(sel) = tpm2::TpmsPcrSelection::new(in_sel.hash(), &bytes[..requested.len()]) {
                // The filtered list has the same number of entries as the input, which already
                // fit in a `TPML_PCR_SELECTION`.
                let _ = filtered.add(&sel);
            }
        }
        filtered
    }

    /// Computes the PCR digest of the selected PCRs using the specified hash algorithm
    /// (C `PCRComputeCurrentDigest`). The selection is first filtered against the PCR
    /// allocation (see [`Self::filter_pcr_selection`]), so unallocated PCRs are never hashed.
    pub fn compute_pcr_digest(
        &self,
        pcr_select: &TpmlPcrSelection,
        hash_alg: TpmiAlgHash,
    ) -> Result<OwnedDigest, TpmRc> {
        let mut state =
            HashStream::new(self.crypto(), hash_alg).map_err(|_| TpmRc::VALUE.to_rc())?;

        let filtered = self.filter_pcr_selection(pcr_select);
        for in_sel in filtered.pcr_selections() {
            let select_hash_alg = in_sel.hash();
            let selected = in_sel.pcr_select();

            // Iterate over the 24 PCRs in each bank (TPM 2.0 Library Specification Part 4, Section 8.1).
            for pcr in 0..24usize {
                let byte_idx = pcr / 8;
                let bit_idx = pcr % 8;
                if byte_idx < selected.len() && (selected[byte_idx] & (1 << bit_idx)) != 0 {
                    let pcrs = &self.context.state.pcrs;
                    let digest_bytes = match select_hash_alg {
                        TpmiAlgHash::Sha1 => &pcrs.sha1[pcr][..],
                        TpmiAlgHash::Sha256 => &pcrs.sha256[pcr][..],
                        TpmiAlgHash::Sha384 => &pcrs.sha384[pcr][..],
                        TpmiAlgHash::Sha512 => &pcrs.sha512[pcr][..],
                        TpmiAlgHash::Sm3_256 => &pcrs.sm3_256[pcr][..],
                        TpmiAlgHash::Sha3_256 => &pcrs.sha3_256[pcr][..],
                        TpmiAlgHash::Sha3_384 => &pcrs.sha3_384[pcr][..],
                        TpmiAlgHash::Sha3_512 => &pcrs.sha3_512[pcr][..],
                        #[allow(unreachable_patterns)]
                        _ => return Err(TpmRc::HASH.to_rc()),
                    };
                    state.update(digest_bytes).map_err(|_| TpmRc::FAILURE)?;
                }
            }
        }

        let mut digest_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let digest = state
            .finalize(&mut digest_buf)
            .map_err(|_| TpmRc::FAILURE)?;
        OwnedDigest::from_bytes(digest.digest()).map_err(|_| TpmRc::FAILURE)
    }

    /// Computes the name of a public structure using the designated name hashing algorithm.
    pub fn compute_name(
        &self,
        name_alg: Option<TpmiAlgHash>,
        public_area_bytes: &[u8],
    ) -> Result<OwnedName, TpmRc> {
        let name_alg_opt = name_alg;
        match name_alg_opt {
            None => Ok(OwnedName::default()),
            Some(alg) => {
                let (digest_bytes, digest_len) = self.compute_hash(alg, &[public_area_bytes])?;

                let mut name_bytes = [0u8; 66];
                let offset = alg.marshal((&mut name_bytes[0..2]).try_into().unwrap());
                name_bytes[offset..offset + digest_len]
                    .copy_from_slice(&digest_bytes[..digest_len]);

                OwnedName::from_bytes(&name_bytes[..offset + digest_len])
                    .map_err(|_| TpmRc::FAILURE)
            }
        }
    }

    /// Computes the qualified name of an object.
    pub fn compute_qualified_name(
        &self,
        name_alg: Option<TpmiAlgHash>,
        parent_qn: &[u8],
        object_name: &[u8],
    ) -> Result<OwnedName, TpmRc> {
        let name_alg_opt = name_alg;
        match name_alg_opt {
            None => Err(TpmRc::HASH.to_rc()),
            Some(alg) => {
                let (digest_bytes, digest_len) =
                    self.compute_hash(alg, &[parent_qn, object_name])?;

                let mut name_bytes = [0u8; 66];
                let offset = alg.marshal((&mut name_bytes[0..2]).try_into().unwrap());
                name_bytes[offset..offset + digest_len]
                    .copy_from_slice(&digest_bytes[..digest_len]);

                OwnedName::from_bytes(&name_bytes[..offset + digest_len])
                    .map_err(|_| TpmRc::FAILURE)
            }
        }
    }

    /// Generates key bytes and updates the public key/unique fields of `parms_and_id`.
    /// Returns the length of the generated private key.
    pub fn generate_key_and_unique(
        &self,
        name_alg: TpmiAlgHash,
        parms_and_id: &mut OwnedPublicParmsAndId,
        args: KeyDerivationArgs<'_>,
        actual_private_key: &mut [u8],
    ) -> Result<usize, TpmRc> {
        match parms_and_id {
            OwnedPublicParmsAndId::Ecc(parms, point) => {
                self.generate_ecc_key(parms, point, args.gen_seed, actual_private_key)
            }
            OwnedPublicParmsAndId::Rsa(parms, unique) => {
                self.generate_rsa_key(parms, unique, args.gen_seed, actual_private_key)
            }
            OwnedPublicParmsAndId::KeyedHash(_, unique) => {
                self.generate_keyed_hash_key(name_alg, args, unique, actual_private_key)
            }
            OwnedPublicParmsAndId::Sym(sym_def, unique) => self.generate_symmetric_key(
                name_alg,
                args,
                (sym_def.key_bits() as usize) / 8,
                unique,
                actual_private_key,
            ),
            OwnedPublicParmsAndId::Mldsa(_, _)
            | OwnedPublicParmsAndId::HashMldsa(_, _)
            | OwnedPublicParmsAndId::Mlkem(_, _) => Err(TpmRc::TYPE.to_rc()),
        }
    }

    /// Generates key bytes for an ECC curve and populates the public point coordinates.
    fn generate_ecc_key(
        &self,
        parms: &mut TpmsEccParms,
        point: &mut OwnedEccPoint,
        gen_seed_arg: Option<&[u8]>,
        actual_private_key: &mut [u8],
    ) -> Result<usize, TpmRc> {
        let curve = parms.curve_id;
        let mut priv_buf = [0u8; 128];
        let mut pub_buf = [0u8; 256];
        let (pub_len, priv_len) = self
            .crypto()
            .generate_key(
                Alg::ECC,
                Some(KeyParams::Ecc(curve)),
                &mut pub_buf,
                &mut priv_buf,
                gen_seed_arg,
            )
            .map_err(|_| TpmRc::FAILURE)?;
        actual_private_key[..priv_len].copy_from_slice(&priv_buf[..priv_len]);

        let param_size = pub_len / 2;
        let x =
            OwnedTpm2b::from_bytes(&pub_buf[..param_size]).expect("pub_buf contains X parameter");
        let y = OwnedTpm2b::from_bytes(&pub_buf[param_size..pub_len])
            .expect("pub_buf contains Y parameter");
        *point = OwnedEccPoint { x, y };
        Ok(priv_len)
    }

    /// Generates RSA key bytes and populates the public exponent and modulus.
    fn generate_rsa_key(
        &self,
        parms: &mut TpmsRsaParms,
        unique: &mut OwnedPublicKeyRsa,
        gen_seed_arg: Option<&[u8]>,
        actual_private_key: &mut [u8],
    ) -> Result<usize, TpmRc> {
        // `CryptRsaGenerateKey()`: an exponent below 65537 or not prime is `TPM_RC_RANGE`.
        // The crypto provider generates keys with the default exponent only, so any other
        // (valid) exponent is unsupported, which is `TPM_RC_RANGE` as well. TPM 2.0 Part 1,
        // RSA: "A TPM is required only to support a public exponent (*e*) of $2^{16}+1$.
        // Support for other exponents is allowed but discouraged." (The response code is not
        // specified; the TCG reference's is used.)
        // `RSA_DEFAULT_PUBLIC_EXPONENT`.
        const DEFAULT_EXPONENT: u32 = 65537;
        if parms.exponent != 0 && parms.exponent != DEFAULT_EXPONENT {
            return Err(TpmRc::RANGE.to_rc());
        }
        let mut priv_buf = [0u8; 1536];
        let mut pub_buf = [0u8; 512];
        let bits = parms.key_bits;
        let (pub_len, priv_len) = self
            .crypto()
            .generate_key(
                Alg::RSA,
                Some(KeyParams::Rsa(bits)),
                &mut pub_buf,
                &mut priv_buf,
                gen_seed_arg,
            )
            .map_err(|_| TpmRc::FAILURE)?;
        actual_private_key[..priv_len].copy_from_slice(&priv_buf[..priv_len]);
        let p = OwnedPublicKeyRsa::from_bytes(&pub_buf[..pub_len])
            .expect("generated public key has valid length");
        *unique = p;
        Ok(priv_len)
    }

    /// Derives or generates bytes for keyed hash objects, hashing them to get a unique identifier.
    fn generate_keyed_hash_key(
        &self,
        name_alg: TpmiAlgHash,
        args: KeyDerivationArgs<'_>,
        unique: &mut OwnedDigest,
        actual_private_key: &mut [u8],
    ) -> Result<usize, TpmRc> {
        let key_size = 32;
        let key_len = if let Some(data) = args.fallback_sensitive_data {
            let data_len = data.len();
            actual_private_key[..data_len].copy_from_slice(data);
            data_len
        } else if let Some(seed) = args.gen_seed {
            let mut generated_key = [0u8; 64];
            kdfa_bits(
                self.crypto(),
                name_alg,
                seed,
                b"Symmetric Key",
                &[],
                &[],
                (key_size * 8) as u32,
                &mut generated_key,
            )
            .map_err(|_| TpmRc::FAILURE)?;
            actual_private_key[..key_size].copy_from_slice(&generated_key[..key_size]);
            key_size
        } else if args.get_random_fallback {
            self.crypto()
                .get_random(&mut actual_private_key[..key_size])
                .map_err(|_| TpmRc::FAILURE)?;
            key_size
        } else {
            return Err(TpmRc::VALUE.to_rc());
        };

        let (digest_bytes, digest_len) =
            self.compute_hash(name_alg, &[args.obj_seed, &actual_private_key[..key_len]])?;
        *unique = OwnedDigest::from_bytes(&digest_bytes[..digest_len]).unwrap();
        Ok(key_len)
    }

    /// Derives or generates symmetric keys of specific target sizes, hashing them to get a unique identifier.
    fn generate_symmetric_key(
        &self,
        name_alg: TpmiAlgHash,
        args: KeyDerivationArgs<'_>,
        sym_key_size: usize,
        unique: &mut OwnedDigest,
        actual_private_key: &mut [u8],
    ) -> Result<usize, TpmRc> {
        let key_len = if let Some(data) = args.fallback_sensitive_data {
            let data_len = data.len();
            actual_private_key[..data_len].copy_from_slice(data);
            data_len
        } else if let Some(seed) = args.gen_seed {
            let mut generated_key = [0u8; 64];
            kdfa_bits(
                self.crypto(),
                name_alg,
                seed,
                b"Symmetric Key",
                &[],
                &[],
                (sym_key_size * 8) as u32,
                &mut generated_key,
            )
            .map_err(|_| TpmRc::FAILURE)?;
            actual_private_key[..sym_key_size].copy_from_slice(&generated_key[..sym_key_size]);
            sym_key_size
        } else if args.get_random_fallback {
            self.crypto()
                .get_random(&mut actual_private_key[..sym_key_size])
                .map_err(|_| TpmRc::FAILURE)?;
            sym_key_size
        } else {
            return Err(TpmRc::VALUE.to_rc());
        };

        let (digest_bytes, digest_len) =
            self.compute_hash(name_alg, &[args.obj_seed, &actual_private_key[..key_len]])?;
        *unique = OwnedDigest::from_bytes(&digest_bytes[..digest_len]).unwrap();
        Ok(key_len)
    }

    /// Verifies password authorization. If the session is of type `RS_PW`, compares the provided HMAC against
    /// the expected authorization value (with trailing zeros stripped, in constant time).
    /// If the session is not `RS_PW`, it returns `true` (meaning the session validation is bypassed here
    /// since it was already handled by the outer context).
    pub fn verify_password_auth(&self, auth: &impl AuthCommandLike, expected_auth: &[u8]) -> bool {
        if auth.session_handle() == Handle::RS_PW {
            let provided_hmac = auth.hmac_bytes();
            let provided_stripped = crate::util::strip_trailing_zeros(provided_hmac);
            let expected_stripped = crate::util::strip_trailing_zeros(expected_auth);
            crate::util::constant_time_eq(expected_stripped, provided_stripped)
        } else {
            true
        }
    }

    pub fn resolve_object(&mut self, handle: u32, pos: Position) -> Result<TransientObject, TpmRc> {
        if handle >> 24 == 0x80 {
            if self.context.state.find_active_sequence(handle).is_some() {
                return Err(TpmRc::KEY.with(pos));
            }
            if let Ok(obj) = self.context.lookup_transient_object(handle, pos) {
                return Ok(obj.clone());
            }
            self.context.lookup_transient_object(handle, pos).cloned()
        } else if handle >> 24 == 0x81 {
            // `ObjectLoadEvict`: an undefined persistent handle, or one whose hierarchy is
            // disabled, is `TPM_RC_HANDLE` at its position (never `TPM_RC_REFERENCE_Hx`).
            self.context
                .load_persistent_object(handle)
                .map_err(|_| TpmRc::HANDLE.with(pos))
        } else {
            Err(TpmRc::VALUE.with(pos))
        }
    }

    pub fn compute_auth_timeout(
        &self,
        session: &SessionState,
        expiration: i32,
        nonce_tpm: &tpm2::Tpm2bNonce,
    ) -> u64 {
        if expiration == 0 {
            0
        } else {
            let expiration_abs = expiration.unsigned_abs() as u64;
            let clock = self.context.state.tpm_time_ms;
            if nonce_tpm.get_buffer().is_empty() {
                expiration_abs * 1000 + (clock % 1000)
            } else {
                session.start_time + expiration_abs * 1000
            }
        }
    }

    pub fn policy_parameter_checks(
        &self,
        session: &SessionState,
        auth_timeout: u64,
        cp_hash_a: &Tpm2bDigest,
        nonce_tpm: &tpm2::Tpm2bNonce,
        blame: (Position, Position, Position),
    ) -> Result<(), TpmRc> {
        let (blame_nonce, blame_cp_hash, blame_expiration) = blame;

        if !nonce_tpm.get_buffer().is_empty()
            && nonce_tpm.get_buffer() != session.nonce_tpm.get_buffer()
        {
            return Err(TpmRc::NONCE.with(blame_nonce));
        }

        if auth_timeout != 0 {
            // Time cannot be compared while Clock is stopped (NV unavailable):
            // `RETURN_IF_NV_IS_NOT_AVAILABLE` in C `PolicyParameterChecks`.
            self.return_if_nv_is_not_available()?;
            let current_time = self.context.state.tpm_time_ms;
            if auth_timeout < current_time || session.epoch != self.context.state.time_epoch {
                return Err(TpmRc::EXPIRED.with(blame_expiration));
            }
        }

        if !cp_hash_a.get_buffer().is_empty() {
            if cp_hash_a.get_size() as usize != session.policy_digest_len {
                return Err(TpmRc::SIZE.with(blame_cp_hash));
            }
            if session.policy_hash_len != 0
                && cp_hash_a.get_buffer() != &session.policy_hash[..session.policy_hash_len]
            {
                return Err(TpmRc::CPHASH);
            }
        }

        Ok(())
    }

    pub fn get_dynamic_qualified_name(&self, obj: &TransientObject) -> OwnedName {
        obj.qualified_name
    }

    /// Computes the common header fields of an attestation structure (`TPMS_ATTEST`), mirroring
    /// `FillInAttestInfo()` in the reference implementation (`Attest_spt.c`).
    ///
    /// - For a null signer handle (`TPM_RH_NULL`), `qualified_signer` is `[0x40, 0x00, 0x00, 0x07]`.
    /// - For anonymous schemes (`TPM_ALG_ECDAA`), both `qualified_signer` and `extra_data` are
    ///   empty buffers (`size = 0`).
    /// - Otherwise, `qualified_signer` is the signer's qualified name and `extra_data` is
    ///   `qualifying_data`.
    /// - `clock_info` is the current clock and `firmware_version` is
    ///   `(TPM_PT_FIRMWARE_VERSION_1 << 32) | TPM_PT_FIRMWARE_VERSION_2`.
    /// - When the signer is `TPM_RH_NULL` or is not in the Endorsement or Platform hierarchy, the
    ///   privacy-sensitive `firmware_version`, `reset_count` and `restart_count` are obfuscated
    ///   (TPM 2.0 Part 1, "Privacy Administrator") by adding a value derived with
    ///   `KDFa(CONTEXT_INTEGRITY_HASH_ALG, shProof, "OBFUSCATE", qualifiedSigner, NULL, 128)`.
    pub fn compute_attest_fields<'c>(
        &self,
        signer_obj_opt: Option<&'c TransientObject>,
        scheme: &Option<tpm2::TpmtSigScheme>,
        qualifying_data: &tpm2::Tpm2bData<'c>,
    ) -> Result<AttestHeader<'c>, TpmRc> {
        let is_anonymous = matches!(scheme, Some(tpm2::TpmtSigScheme::Ecdaa(_)));
        let qualified_signer = match signer_obj_opt {
            None => {
                tpm2::Tpm2bName::from_bytes(&ATTEST_NULL_SIGNER_NAME).map_err(|_| TpmRc::FAILURE)?
            }
            Some(_) if is_anonymous => {
                tpm2::Tpm2bName::from_bytes(&[]).map_err(|_| TpmRc::FAILURE)?
            }
            Some(signer) => signer.qualified_name.as_tpm2b(),
        };

        let extra_data = if is_anonymous {
            tpm2::Tpm2bData::from_bytes(&[]).map_err(|_| TpmRc::FAILURE)?
        } else {
            *qualifying_data
        };

        let mut clock_info = self.get_clock_info();
        let mut firmware_version = ATTEST_FIRMWARE_VERSION;

        // Signers outside the Endorsement and Platform hierarchies (and TPM_RH_NULL) must not
        // reveal the plain reset/restart counts and firmware version.
        let needs_obfuscation = match signer_obj_opt {
            None => true,
            Some(signer) => {
                signer.hierarchy != Handle::RH_ENDORSEMENT.0
                    && signer.hierarchy != Handle::RH_PLATFORM.0
            }
        };
        if needs_obfuscation {
            let mut obfuscation = [0u8; 16];
            kdfa_bits(
                self.crypto(),
                context_integrity_hash_alg(),
                provisioned_secret(
                    &self.context.state.sh_proof,
                    self.context.state.sh_proof_size,
                )?,
                b"OBFUSCATE",
                qualified_signer.get_buffer(),
                &[],
                128,
                &mut obfuscation,
            )
            .map_err(|_| TpmRc::FAILURE)?;
            // The reference implementation reads the KDF output as two native UINT64 values
            // (little-endian on its reference platforms).
            let mut word0 = [0u8; 8];
            let mut word1 = [0u8; 8];
            word0.copy_from_slice(&obfuscation[..8]);
            word1.copy_from_slice(&obfuscation[8..]);
            let obfuscation0 = u64::from_le_bytes(word0);
            let obfuscation1 = u64::from_le_bytes(word1);
            firmware_version = firmware_version.wrapping_add(obfuscation0);
            clock_info.reset_count = clock_info
                .reset_count
                .wrapping_add((obfuscation1 >> 32) as u32);
            clock_info.restart_count = clock_info.restart_count.wrapping_add(obfuscation1 as u32);
        }

        Ok(AttestHeader {
            qualified_signer,
            extra_data,
            clock_info,
            firmware_version,
        })
    }

    /// Returns the proof of `hierarchy` (owner, endorsement, platform; anything else selects
    /// the null hierarchy) as `(buffer, length, hierarchy handle)`.
    ///
    /// Fails with `TPM_RC_FAILURE` if the proof is not provisioned (see
    /// [`provisioned_secret`]), and with `TPM_RC_FW_LIMITED`/`TPM_RC_SVN_LIMITED` for a
    /// firmware-limited/SVN-limited hierarchy.
    pub fn resolve_hierarchy_proof(&self, hierarchy: u32) -> Result<(&[u8], usize, u32), TpmRc> {
        // The proof of a firmware-limited or SVN-limited hierarchy is not available (the TCG
        // reference's `HierarchyGetProof()`), see `limited_hierarchy_error`.
        if let Some(rc) = crate::engine::limited_hierarchy_error(hierarchy) {
            return Err(rc.to_rc());
        }
        let gs = &self.context.state;
        let (proof, size, handle) = if hierarchy == 0x40000001 {
            (&gs.sh_proof, gs.sh_proof_size, 0x40000001)
        } else if hierarchy == 0x4000000B {
            (&gs.eh_proof, gs.eh_proof_size, 0x4000000B)
        } else if hierarchy == 0x4000000C {
            (&gs.ph_proof, gs.ph_proof_size, 0x4000000C)
        } else {
            (&gs.null_proof, gs.null_proof_size, 0x40000007)
        };
        let proof = provisioned_secret(proof, size)?;
        Ok((proof, proof.len(), handle))
    }

    pub fn compute_verified_ticket(
        &self,
        hierarchy: u32,
        digest: &[u8],
        key_name: &[u8],
    ) -> Result<TicketDigest, TpmRc> {
        self.compute_verified_ticket_with_meta(hierarchy, 0x8022, digest, key_name, &[])
    }

    pub fn compute_verified_ticket_with_meta(
        &self,
        hierarchy: u32,
        tag: u16,
        digest_or_message: &[u8],
        key_name: &[u8],
        metadata: &[u8],
    ) -> Result<TicketDigest, TpmRc> {
        let (proof_bytes, proof_len, _) = self.resolve_hierarchy_proof(hierarchy)?;

        let mut hmac_input = [0u8; 512];
        let mut offset = 0;

        hmac_input[offset..offset + 2].copy_from_slice(&tag.to_be_bytes());
        offset += 2;

        hmac_input[offset..offset + digest_or_message.len()].copy_from_slice(digest_or_message);
        offset += digest_or_message.len();

        hmac_input[offset..offset + key_name.len()].copy_from_slice(key_name);
        offset += key_name.len();

        hmac_input[offset..offset + metadata.len()].copy_from_slice(metadata);
        offset += metadata.len();

        let mut hmac_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let hmac_digest = tpm2::crypto::hmac(
            self.crypto(),
            context_integrity_hash_alg(),
            &proof_bytes[..proof_len],
            &hmac_input[..offset],
            &mut hmac_buf,
        )
        .map_err(|_| TpmRc::FAILURE)?;

        TicketDigest::new(hmac_digest.digest()).ok_or(TpmRc::FAILURE)
    }

    pub fn compute_hashcheck_ticket(
        &self,
        hierarchy: Handle,
        hash_alg: TpmiAlgHash,
        digest: &[u8],
    ) -> Result<TicketDigest, TpmRc> {
        // The proof of a firmware-limited or SVN-limited hierarchy is unavailable
        // (`resolve_hierarchy_proof`), whatever the hierarchy check below would say.
        if let Some(rc) = crate::engine::limited_hierarchy_error(hierarchy.0) {
            return Err(rc.to_rc());
        }
        if hierarchy != Handle::RH_NULL
            && hierarchy != Handle::RH_OWNER
            && hierarchy != Handle::RH_PLATFORM
            && hierarchy != Handle::RH_ENDORSEMENT
        {
            return Err(TpmRc::HIERARCHY.to_rc());
        }
        let (proof_bytes, proof_len, _) = self.resolve_hierarchy_proof(hierarchy.0)?;

        let mut hmac_input = [0u8; 512];
        let mut offset = 0;

        hmac_input[offset..offset + 2].copy_from_slice(&0x8024u16.to_be_bytes());
        offset += 2;

        offset += hash_alg.marshal((&mut hmac_input[offset..offset + 2]).try_into().unwrap());

        if offset + digest.len() > hmac_input.len() {
            return Err(TpmRc::SIZE.to_rc());
        }
        hmac_input[offset..offset + digest.len()].copy_from_slice(digest);
        offset += digest.len();

        let mut hmac_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let hmac_digest = tpm2::crypto::hmac(
            self.crypto(),
            context_integrity_hash_alg(),
            &proof_bytes[..proof_len],
            &hmac_input[..offset],
            &mut hmac_buf,
        )
        .map_err(|_| TpmRc::FAILURE)?;

        TicketDigest::new(hmac_digest.digest()).ok_or(TpmRc::FAILURE)
    }

    /// Validates the `policySession` handle (`TPMI_SH_POLICY`) of a policy command.
    ///
    /// Mirrors the C reference: a handle that is not a policy-session handle (`0x03xxxxxx`) fails
    /// unmarshaling with `TPM_RC_VALUE + pos`; a policy-session handle whose slot is not loaded is
    /// `TPM_RC_REFERENCE_H0 + index`; a loaded slot that holds an HMAC session is
    /// `TPM_RC_HANDLE + pos` (`EntityGetLoadStatus()`).
    ///
    /// Policy commands do not check the session's timeout or time epoch; expiration is only
    /// enforced when the policy session is used to authorize a command (C
    /// `CheckPolicyAuthSession()`).
    pub fn validate_policy_session(
        &mut self,
        session_handle: u32,
        pos: Position,
    ) -> Result<(), TpmRc> {
        if (session_handle >> 24) != 0x03 {
            return Err(TpmRc::VALUE.with(pos));
        }
        let Some(session) = self.context.state.session_by_slot(session_handle) else {
            return Err(match pos.handle_num() {
                Some(2) => TpmRc::REFERENCE_H1,
                Some(3) => TpmRc::REFERENCE_H2,
                _ => TpmRc::REFERENCE_H0,
            });
        };
        if session.session_type != TpmSe::Policy && session.session_type != TpmSe::Trial {
            return Err(TpmRc::HANDLE.with(pos));
        }
        Ok(())
    }

    /// Validates the structure of a Tpm2bName.
    /// A valid Name is either empty, a 4-byte handle, or a name hash.
    pub fn validate_name_structure(
        &self,
        name: &impl AsRef<[u8]>,
        pos: Position,
    ) -> Result<(), TpmRc> {
        let mut src = name.as_ref();
        let size = src.len();
        if size == 0 || size == 4 {
            return Ok(());
        }
        if src.len() < 2 {
            return Err(TpmRc::SIZE.with(pos));
        }
        let hash_alg = TpmiAlgHash::unmarshal(&mut src).map_err(|_| TpmRc::HASH.with(pos))?;
        if src.len() != hash_alg.digest_size() {
            return Err(TpmRc::SIZE.with(pos));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::req_resp::{RequestResponseCursor, Response};
    use crate::test_support::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
    use alloc::vec::Vec;
    use tpm2::commands::responses;
    use tpm2::platform::TpmPlatform;
    use tpm2::{AlgSym, Tpm2bName, TpmiAlgCipherMode};

    type TestHandler<'a, 'b> = CommandHandler<'a, 'b, FakeCrypto, FakeStorage, FakeTimer, FakeRng>;

    /// Where the response handle area starts (after the 10-byte response header).
    const RESPONSE_OFFSET: usize = 10;

    /// Runs `f` with a handler on fresh fake platform state.
    fn with_handler<T>(in_shadow_execution: bool, f: impl FnOnce(&TestHandler<'_, '_>) -> T) -> T {
        let mut crypto = FakeCrypto;
        let mut storage = FakeStorage::default();
        let mut timer = FakeTimer;
        let mut rng = FakeRng::new();
        let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &mut rng);
        let mut engine = crate::TpmEngine::new(platform).unwrap();
        engine.state.in_shadow_execution = in_shadow_execution;
        let handler = CommandHandler::new(&mut engine);
        f(&handler)
    }

    /// Returns the bytes that `write` writes after the response header.
    fn written(
        in_shadow_execution: bool,
        write: impl FnOnce(&TestHandler<'_, '_>, Response<'_, '_>) -> Result<(), TpmRc>,
    ) -> Vec<u8> {
        with_handler(in_shadow_execution, |handler| {
            let mut resp = [0u8; 512];
            let mut cursor = RequestResponseCursor::new(&[], &mut resp, RESPONSE_OFFSET);
            write(handler, cursor.request().into_response()).unwrap();
            let end = cursor.last_response_byte_written();
            cursor.response_mut()[RESPONSE_OFFSET..end].to_vec()
        })
    }

    fn session_response() -> TpmsAuthResponse<'static> {
        TpmsAuthResponse {
            nonce: Tpm2bNonce::from_bytes(&[1, 2, 3]).unwrap(),
            session_attributes: TpmaSession(1),
            hmac: Tpm2bAuth::from_bytes(&[4, 5]).unwrap(),
        }
    }

    #[test]
    fn write_response_message_matches_write_response_all() {
        let rsp = responses::LoadExternal {
            object_handle: Handle(0x8000_0001),
            name: Tpm2bName::from_bytes(&[0x00, 0x0B, 0xAA, 0xBB]).unwrap(),
        };
        let session = session_response();
        for shadow in [false, true] {
            for sessions in [&[][..], &[session][..], &[session, session][..]] {
                assert_eq!(
                    written(shadow, |h, r| h.write_response_message(r, &rsp, sessions)),
                    written(shadow, |h, r| h.write_response_all(
                        r,
                        &rsp.object_handle,
                        &rsp,
                        sessions
                    )),
                );
            }
        }

        // Handle area, then the parameters.
        let name_param = [0x00, 0x04, 0x00, 0x0B, 0xAA, 0xBB];
        let plain = written(false, |h, r| h.write_response_message(r, &rsp, &[]));
        assert_eq!(plain[..4], [0x80, 0x00, 0x00, 0x01]);
        assert_eq!(plain[4..], name_param);

        // With sessions: handle area, `parameterSize`, the parameters, then the sessions.
        let with_session = written(false, |h, r| h.write_response_message(r, &rsp, &[session]));
        assert_eq!(with_session[..4], [0x80, 0x00, 0x00, 0x01]);
        assert_eq!(with_session[4..8], [0x00, 0x00, 0x00, 0x06]);
        assert_eq!(with_session[8..14], name_param);
        assert_eq!(
            with_session[14..],
            [0x00, 0x03, 1, 2, 3, 0x01, 0x00, 0x02, 4, 5]
        );

        // Shadow execution never writes `parameterSize` or sessions.
        assert_eq!(
            written(true, |h, r| h.write_response_message(r, &rsp, &[session])),
            plain
        );
    }

    #[test]
    fn write_response_message_with_only_handles_matches_write_response_handles() {
        let rsp = responses::HMACStart {
            sequence_handle: Handle(0x8000_0002),
        };
        let session = session_response();
        for sessions in [&[][..], &[session][..]] {
            assert_eq!(
                written(false, |h, r| h.write_response_message(r, &rsp, sessions)),
                written(false, |h, r| h.write_response_handles(
                    r,
                    &rsp.sequence_handle,
                    sessions
                )),
            );
        }
        // A zero `parameterSize` follows the handle when sessions are present.
        assert_eq!(
            written(false, |h, r| h.write_response_message(r, &rsp, &[session]))[..8],
            [0x80, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn write_response_message_with_only_parameters_matches_write_response_rsp() {
        let rsp = responses::GetRandom {
            random_bytes: Tpm2bDigest::from_bytes(&[9, 8, 7]).unwrap(),
        };
        let session = session_response();
        for sessions in [&[][..], &[session][..]] {
            assert_eq!(
                written(false, |h, r| h.write_response_message(r, &rsp, sessions)),
                written(false, |h, r| h.write_response_rsp(r, &rsp, sessions)),
            );
        }
        assert_eq!(
            written(false, |h, r| h.write_response_message(r, &rsp, &[])),
            [0x00, 0x03, 9, 8, 7]
        );
    }

    #[test]
    fn write_response_message_of_empty_response_matches_write_response_none() {
        let session = session_response();
        for sessions in [&[][..], &[session][..]] {
            assert_eq!(
                written(false, |h, r| h.write_response_message(r, &(), sessions)),
                written(false, |h, r| h.write_response_none(r, sessions)),
            );
        }
        assert!(written(false, |h, r| h.write_response_message(r, &(), &[])).is_empty());
        assert_eq!(
            written(false, |h, r| h.write_response_message(r, &(), &[session]))[..4],
            [0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn write_response_message_reports_failure_when_the_buffer_is_full() {
        let rsp = responses::GetRandom {
            random_bytes: Tpm2bDigest::from_bytes(&[0; 32]).unwrap(),
        };
        let result = with_handler(false, |handler| {
            let mut resp = [0u8; RESPONSE_OFFSET + 8];
            let mut cursor = RequestResponseCursor::new(&[], &mut resp, RESPONSE_OFFSET);
            handler.write_response_message(cursor.request().into_response(), &rsp, &[])
        });
        assert_eq!(result, Err(TpmRc::FAILURE));
    }

    fn aes128_cfb() -> TpmtSymDefObject {
        TpmtSymDefObject {
            alg: AlgSym::Aes128,
            mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
        }
    }

    #[test]
    fn sym_encrypt_decrypt_runs_the_cipher_in_both_directions() {
        let key = [0x11u8; 16];
        let iv_in = [0x22u8; 16];
        // CFB accepts any data length.
        let plain = *b"0123456789abcdefXYZ";
        let mut data = plain;
        let mut iv = iv_in;
        sym_encrypt_decrypt(
            &FakeCrypto,
            aes128_cfb(),
            &key,
            &mut iv,
            Direction::Encrypt,
            &mut data,
        )
        .unwrap();
        // The fake cipher XORs the data with the key and the IV, and keeps the IV.
        for (encrypted, plain) in data.iter().zip(plain) {
            assert_eq!(*encrypted, plain ^ 0x11 ^ 0x22);
        }
        assert_eq!(iv, iv_in);

        sym_encrypt_decrypt(
            &FakeCrypto,
            aes128_cfb(),
            &key,
            &mut iv,
            Direction::Decrypt,
            &mut data,
        )
        .unwrap();
        assert_eq!(data, plain);
    }

    #[test]
    fn sym_encrypt_decrypt_without_a_cipher_mode_is_unsupported() {
        let mut data = [0xAA; 16];
        for mode in [None, Some(TpmiAlgSymMode::Cmac)] {
            let alg = TpmtSymDefObject {
                alg: AlgSym::Aes128,
                mode,
            };
            // The mode is checked first: the IV and key sizes are wrong as well.
            assert_eq!(
                sym_encrypt_decrypt(
                    &FakeCrypto,
                    alg,
                    &[0; 3],
                    &mut [0; 3],
                    Direction::Encrypt,
                    &mut data
                ),
                Err(CryptoError::Unsupported)
            );
        }
        assert_eq!(data, [0xAA; 16]);
    }

    #[test]
    fn sym_encrypt_decrypt_rejects_bad_iv_and_key_sizes() {
        let ecb = |alg| TpmtSymDefObject {
            alg,
            mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Ecb)),
        };
        let mut data = [0xAA; 16];
        // CFB needs a one-block IV.
        for iv_len in [0, 15, 17] {
            let mut iv = [0u8; 17];
            assert_eq!(
                sym_encrypt_decrypt(
                    &FakeCrypto,
                    aes128_cfb(),
                    &[0; 16],
                    &mut iv[..iv_len],
                    Direction::Encrypt,
                    &mut data
                ),
                Err(CryptoError::Internal)
            );
        }
        // ECB takes no IV.
        assert_eq!(
            sym_encrypt_decrypt(
                &FakeCrypto,
                ecb(AlgSym::Aes128),
                &[0; 16],
                &mut [0; 16],
                Direction::Encrypt,
                &mut data
            ),
            Err(CryptoError::Internal)
        );
        // The key must have the algorithm's key size.
        for key_len in [0, 15, 24, 32] {
            let key = [0u8; 32];
            assert_eq!(
                sym_encrypt_decrypt(
                    &FakeCrypto,
                    aes128_cfb(),
                    &key[..key_len],
                    &mut [0; 16],
                    Direction::Decrypt,
                    &mut data
                ),
                Err(CryptoError::Internal)
            );
        }
        assert_eq!(data, [0xAA; 16]);

        // ECB with an empty IV, and AES-256 with a 32-byte key, are accepted.
        sym_encrypt_decrypt(
            &FakeCrypto,
            ecb(AlgSym::Aes256),
            &[0x0F; 32],
            &mut [],
            Direction::Encrypt,
            &mut data,
        )
        .unwrap();
        assert_eq!(data, [0xA5; 16]);
    }

    #[test]
    fn handler_sym_encrypt_decrypt_uses_the_platform_crypto() {
        let mut data = [0x5A; 20];
        let mut iv = [0x01; 16];
        with_handler(false, |handler| {
            handler.sym_encrypt_decrypt(
                aes128_cfb(),
                &[0x10; 16],
                &mut iv,
                Direction::Encrypt,
                &mut data,
            )
        })
        .unwrap();
        assert_eq!(data, [0x5A ^ 0x10 ^ 0x01; 20]);
    }
}
