//! # TPM 2.0 Command Handlers
//!
//! This module contains individual command handlers (e.g., `random::get_random`, `pcr::pcr_read`) grouped by functional category.
//!
//! ## Role and Scope
//!
//! Each handler is an extension of the [`CommandHandler`] struct. The handler infrastructure is responsible for:
//! - **Parameter Extraction**: Unmarshaling command-specific input arguments from the `RequestThenResponse` buffer.
//! - **Core Action**: Implementing the specific logical steps, algorithm validations, and cryptographic transformations required for the command.
//! - **Response Assembly**: Marshaling command-specific output arguments back to the response buffer.
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
mod capability;
mod certify;
mod change_eps;
mod change_pps;
mod clear;
mod clear_control;
mod clock_ops;
mod commit;
mod context_load;
mod context_save;
mod create;
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
mod nv_storage;
mod object_change_auth;
mod object_helpers;
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
mod rewrap;
mod sequence;
mod session;
mod set_primary_policy;
mod shutdown;
mod startup;
mod testing;
mod unseal;

use crate::owned::{
    AuthCommandLike, OwnedAuth, OwnedAuthCommand, OwnedDigest, OwnedEccParameter, OwnedEccPoint,
    OwnedName, OwnedNonce, OwnedNvPublic, OwnedPrivateKeyRsa, OwnedPublic, OwnedPublicKeyRsa,
    OwnedPublicParmsAndId, OwnedSensitiveComposite, OwnedSensitiveData, OwnedSymKey,
};
use crate::req_resp::RequestThenResponse;
use crate::storage::NvStorage;
use crate::timer::TpmTimer;
use crate::{Crypto, GlobalState, TpmEngine};
use tpm2::crypto::{
    CryptoError, Ecc, EccPrivateKey, EccPublicKey, HashStream, Rsa, RsaPrivateKey, RsaPublicKey,
    kdfa,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmSe};
use tpm2::{Marshal, Unmarshal};
use tpm2::{
    Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bNonce, Tpm2bNvPublic, Tpm2bSymKey, TpmEccCurve,
    TpmaObject, TpmaSession, TpmiAlgHash, TpmiRsaKeyBits, TpmlPcrSelection, TpmsAuthResponse,
    TpmsEccParms, TpmsNvPublic, TpmsRsaParms, TpmtSymDef,
};

/// Represents an object loaded into the TPM's volatile memory.
/// This structure holds the state of a transient object, which could be a key or a data object,
/// that is actively being used by the TPM.
#[derive(Debug, Clone)]
pub struct TransientObject {
    /// The transient handle assigned to this object (e.g., in the 0x80xxxxxx range).
    pub handle: u32,
    /// The object's `seedValue` (`TPMT_SENSITIVE.seedValue`). For a storage parent, the
    /// symmetric and integrity keys protecting its children are derived from it.
    pub seed: OwnedDigest,
    /// The cryptographically derived name of the object.
    pub name: OwnedName,
    /// The authorization value or policy required to use this object.
    pub auth: OwnedAuth,
    /// The public area of the object, describing its attributes and public key.
    pub public: OwnedPublic,
    /// The sensitive area of the object (private key, symmetric key, or sealed data), in the
    /// compact `TPMU_SENSITIVE_COMPOSITE` form consumed by the `tpm2::crypto` traits.
    ///
    /// PORTING: replaces exp's `private: [u8; 1536]` + `private_len` blob.
    pub sensitive: OwnedSensitiveComposite,
    /// The qualified name of the object, recursively linking it to the hierarchy root.
    pub qualified_name: OwnedName,
    /// The handle of the hierarchy to which this object belongs (e.g., Owner, Platform, Endorsement, or Null).
    pub hierarchy: u32,
    /// Indicates whether the object has the `stClear` attribute, meaning its state should be cleared upon a TPM restart.
    pub st_clear: bool,
}

impl TransientObject {
    /// Maximum size of a record produced by [`TransientObject::marshal_persistent`].
    pub const MAX_PERSISTENT_SIZE: usize = OwnedDigest::MAX_SIZE
        + OwnedName::MAX_SIZE
        + OwnedAuth::MAX_SIZE
        + OwnedPublic::MAX_SIZE
        + OwnedSensitiveComposite::MAX_SIZE
        + OwnedName::MAX_SIZE
        + u32::MAX_SIZE;

    /// Serializes this object into the persistent (`TPM2_EvictControl`) NV record format:
    /// `seed | name | auth | public | sensitive | qualified_name | hierarchy(u32)`.
    ///
    /// `seed` is a `TPM2B_DIGEST`. `sensitive` is the `TPM2B`-encoded `TPMU_SENSITIVE_COMPOSITE`
    /// member (selected by `public.type` on load). Returns the number of bytes written.
    ///
    /// PORTING: exp stored a fixed 32-byte seed, truncating SHA-384 and SHA-512 seeds.
    pub fn marshal_persistent(&self, buf: &mut [u8]) -> Result<usize, TpmRc> {
        fn put<const N: usize>(
            t: &impl Marshal<MaxBuffer = [u8; N]>,
            buf: &mut [u8],
            offset: usize,
        ) -> Result<usize, TpmRc> {
            let mut tmp = [0u8; N];
            let len = t.marshal(&mut tmp);
            buf.get_mut(offset..offset + len)
                .ok_or(TpmRc::FAILURE)?
                .copy_from_slice(&tmp[..len]);
            Ok(offset + len)
        }
        let offset = put(&self.seed, buf, 0)?;
        let offset = put(&self.name, buf, offset)?;
        let offset = put(&self.auth, buf, offset)?;
        let offset = put(&self.public, buf, offset)?;
        let offset = put(&self.sensitive, buf, offset)?;
        let offset = put(&self.qualified_name, buf, offset)?;
        put(&self.hierarchy, buf, offset)
    }

    /// Deserializes a record written by [`TransientObject::marshal_persistent`].
    ///
    /// The returned object has `handle` set to `handle` and `st_clear == false`. Any malformed
    /// record yields [`TpmRc::FAILURE`].
    pub fn unmarshal_persistent(handle: u32, buf: &[u8]) -> Result<Self, TpmRc> {
        let mut slice = buf;
        let seed = OwnedDigest::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let name = OwnedName::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let auth = OwnedAuth::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let public = OwnedPublic::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let sensitive = OwnedSensitiveComposite::unmarshal_variant(public.algorithm(), &mut slice)
            .map_err(|_| TpmRc::FAILURE)?;
        let qualified_name = OwnedName::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        let hierarchy = u32::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
        Ok(Self {
            handle,
            seed,
            name,
            auth,
            public,
            sensitive,
            qualified_name,
            hierarchy,
            st_clear: false,
        })
    }

    /// Reads the Name and authValue from the start of a record written by
    /// [`TransientObject::marshal_persistent`] (they precede the variable-size public area, so
    /// `buf` may be a prefix of the record).
    pub fn persistent_name_and_auth(buf: &[u8]) -> Option<(OwnedName, OwnedAuth)> {
        let mut slice = buf;
        OwnedDigest::unmarshal(&mut slice).ok()?;
        let name = OwnedName::unmarshal(&mut slice).ok()?;
        let auth = OwnedAuth::unmarshal(&mut slice).ok()?;
        Some((name, auth))
    }
}

/// Types that can be written as the `authValue` part of an NV Index header.
pub(crate) trait NvHeaderAuth {
    fn marshal_auth(&self, buf: &mut [u8]) -> usize;
}

impl NvHeaderAuth for Tpm2bAuth<'_> {
    fn marshal_auth(&self, buf: &mut [u8]) -> usize {
        self.marshal((&mut buf[..Tpm2bAuth::MAX_SIZE]).try_into().unwrap())
    }
}

impl NvHeaderAuth for OwnedAuth {
    fn marshal_auth(&self, buf: &mut [u8]) -> usize {
        let auth: Tpm2bAuth<'_> = self.as_tpm2b();
        auth.marshal_auth(buf)
    }
}

/// Types that can be written as the `TPM2B_NV_PUBLIC` part of an NV Index header.
pub(crate) trait NvHeaderPub {
    fn marshal_pub(&self, buf: &mut [u8]) -> usize;
}

impl NvHeaderPub for Tpm2bNvPublic<'_> {
    fn marshal_pub(&self, buf: &mut [u8]) -> usize {
        self.marshal((&mut buf[..Tpm2bNvPublic::MAX_SIZE]).try_into().unwrap())
    }
}

impl NvHeaderPub for OwnedNvPublic {
    fn marshal_pub(&self, buf: &mut [u8]) -> usize {
        self.as_tpm2b().marshal_pub(buf)
    }
}

/// Writes an NV Index header (`authValue | TPM2B_NV_PUBLIC`) into `buf`, returning its length.
///
/// PORTING: moved here from exp's `handler/nv_storage.rs` because the engine and several
/// handlers (clear, policy_nv, nv_storage) share it. Do not redefine it in `nv_storage.rs`.
pub(crate) fn marshal_nv_header(
    auth: &impl NvHeaderAuth,
    public_info: &impl NvHeaderPub,
    buf: &mut [u8],
) -> Result<usize, TpmRc> {
    if buf.len() < Tpm2bAuth::MAX_SIZE + Tpm2bNvPublic::MAX_SIZE {
        return Err(TpmRc::FAILURE);
    }
    let mut offset = 0;
    offset += auth.marshal_auth(&mut buf[offset..]);
    offset += public_info.marshal_pub(&mut buf[offset..]);
    Ok(offset)
}

/// Parses an NV Index header, returning `(header_len, public, auth, public)` as owned values.
///
/// PORTING: moved here from exp's `handler/nv_storage.rs` (see [`marshal_nv_header`]).
pub(crate) fn unmarshal_nv_header(
    buf: &[u8],
) -> Result<(usize, OwnedNvPublic, OwnedAuth, OwnedNvPublic), TpmRc> {
    let (metadata_size, nv_public, auth, _, _) = unmarshal_nv_header_bytes(buf)?;
    let owned_pub = OwnedNvPublic::from(nv_public);
    let owned_auth = OwnedAuth::from(auth);
    Ok((metadata_size, owned_pub, owned_auth, owned_pub))
}

/// Parses an NV Index header, returning
/// `(header_len, public, auth, TPM2B_NV_PUBLIC, marshaled public bytes)` borrowed from `buf`.
///
/// PORTING: moved here from exp's `handler/nv_storage.rs` (see [`marshal_nv_header`]).
#[allow(clippy::type_complexity)]
pub(crate) fn unmarshal_nv_header_bytes(
    buf: &[u8],
) -> Result<
    (
        usize,
        TpmsNvPublic<'_>,
        Tpm2bAuth<'_>,
        Tpm2bNvPublic<'_>,
        &[u8],
    ),
    TpmRc,
> {
    let mut slice = buf;
    let auth = Tpm2bAuth::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
    let (pub_len, _) = slice.split_first_chunk::<2>().ok_or(TpmRc::FAILURE)?;
    let pub_len = usize::from(u16::from_be_bytes(*pub_len));
    let public_bytes = slice.get(2..2 + pub_len).ok_or(TpmRc::FAILURE)?;
    let public_info = Tpm2bNvPublic::unmarshal(&mut slice).map_err(|_| TpmRc::FAILURE)?;
    let metadata_size = buf.len() - slice.len();
    let nv_public = public_info.0;
    Ok((metadata_size, nv_public, auth, public_info, public_bytes))
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
}

/// Resolved parent object or hierarchy information returned by `resolve_parent_object_or_hierarchy`.
pub struct ResolvedParentInfo {
    pub req_auth: bool,
    pub seed_len: usize,
    pub qn_len: usize,
    pub hierarchy_val: u32,
    pub has_st_clear: bool,
    pub name_alg: TpmiAlgHash,
    pub sym_bits: u16,
    pub attributes: TpmaObject,
    pub is_derivation_parent: bool,
}

/// Parameters for key derivation during key generation.
pub struct KeyDerivationArgs<'a> {
    pub gen_seed: Option<&'a [u8]>,
    pub obj_seed: &'a [u8],
    pub get_random_fallback: bool,
    pub fallback_sensitive_data: Option<&'a [u8]>,
}

/// The context that all command handler functions are given access to in order for them to process
/// their given command.
pub struct CommandHandler<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> {
    pub context: &'b mut TpmEngine<'a, C, S, T>,
    pub global_state: &'b mut GlobalState,
}

impl<'a, 'b, C: Crypto, S: NvStorage, T: TpmTimer> CommandHandler<'a, 'b, C, S, T> {
    /// Creates a new `CommandHandler` object.
    pub fn new(context: &'b mut TpmEngine<'a, C, S, T>, global_state: &'b mut GlobalState) -> Self {
        Self {
            context,
            global_state,
        }
    }

    #[inline]
    pub fn state(&self) -> &GlobalState {
        self.global_state
    }

    #[inline]
    pub fn state_mut(&mut self) -> &mut GlobalState {
        self.global_state
    }

    /// Returns the crypto backend.
    ///
    /// The reference has the platform lifetime `'a` (not that of `&self`), so it can be held
    /// across `&mut self` calls such as [`CommandHandler::fill_random`].
    #[inline]
    pub fn crypto(&self) -> &'a C {
        self.context.platform.crypto
    }

    /// Fills `buf` from the TPM's global RNG ([`crate::TpmPlatform::rng`]).
    ///
    /// PORTING: replaces exp's `self.crypto().get_random(buf)`; needs `&mut self`.
    #[inline]
    pub fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), CryptoError> {
        self.context.fill_random(buf)
    }

    #[inline]
    pub fn get_clock(&self) -> u64 {
        self.context.get_clock(self.global_state)
    }

    #[inline]
    pub fn get_clock_info(&self) -> tpm2::TpmsClockInfo {
        self.context.get_clock_info(self.global_state)
    }

    #[inline]
    pub fn get_time_info(&self) -> tpm2::TpmsTimeInfo {
        self.context.get_time_info(self.global_state)
    }

    /// Verifies that `auth_handle` is either `TPM_RH_OWNER` or `TPM_RH_PLATFORM`, and checks password session authorization if needed.
    pub fn validate_provision_auth(
        &mut self,
        auth_handle: u32,
        provided_auth: Option<impl Into<OwnedAuthCommand>>,
    ) -> Result<(), TpmRc> {
        let provided_auth = provided_auth.map(Into::into);
        if auth_handle != Handle::RH_PLATFORM.0 && auth_handle != Handle::RH_OWNER.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        let expected_auth_struct = self.context.handle_auth(self.global_state, auth_handle);
        let expected_auth = expected_auth_struct.get_buffer();

        if let Some(auth) = provided_auth {
            if !self.verify_password_auth(&auth, expected_auth) {
                return Err(TpmRc::AUTH_FAIL.with(Position::session(1)));
            }
            Ok(())
        } else if !expected_auth.is_empty() {
            Err(TpmRc::AUTH_MISSING)
        } else {
            Ok(())
        }
    }

    /// Verifies that `auth_handle` is `TPM_RH_PLATFORM`, and checks password session authorization if needed.
    pub fn validate_platform_auth(
        &mut self,
        auth_handle: u32,
        provided_auth: Option<impl Into<OwnedAuthCommand>>,
    ) -> Result<(), TpmRc> {
        let provided_auth = provided_auth.map(Into::into);
        if auth_handle != Handle::RH_PLATFORM.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        if !self.global_state.ph_enable {
            return Err(TpmRc::HIERARCHY.with(Position::handle(1)));
        }

        let expected_auth_struct = self.context.handle_auth(self.global_state, auth_handle);
        let expected_auth = expected_auth_struct.get_buffer();

        if let Some(auth) = provided_auth {
            if !self.verify_password_auth(&auth, expected_auth) {
                return Err(TpmRc::AUTH_FAIL.with(Position::session(1)));
            }
            Ok(())
        } else if !expected_auth.is_empty() {
            Err(TpmRc::AUTH_MISSING)
        } else {
            Ok(())
        }
    }

    /// Verifies that `auth_handle` is `TPM_RH_LOCKOUT`, and checks password session authorization if needed.
    pub fn validate_lockout_auth(
        &mut self,
        auth_handle: u32,
        provided_auth: Option<impl Into<OwnedAuthCommand>>,
    ) -> Result<(), TpmRc> {
        let provided_auth = provided_auth.map(Into::into);
        if auth_handle != Handle::RH_LOCKOUT.0 {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        if !self.global_state.nv_available && self.global_state.orderly_state < 0xFFFE {
            return Err(TpmRc::NV_UNAVAILABLE);
        }
        if self.global_state.da_pending_on_nv && self.global_state.nv_available {
            let _ = self
                .context
                .platform
                .storage
                .write_nv(32, &self.global_state.failed_tries.to_be_bytes());
            self.global_state.da_pending_on_nv = false;
        }

        if !self.global_state.lockout_auth_enabled {
            return Err(TpmRc::LOCKOUT);
        }

        let expected_auth_struct = self.context.handle_auth(self.global_state, auth_handle);
        let expected_auth = expected_auth_struct.get_buffer();

        if let Some(auth) = provided_auth {
            if !self.verify_password_auth(&auth, expected_auth) {
                self.global_state.lockout_auth_enabled = false;
                self.global_state.lockout_timer =
                    i64::try_from(self.global_state.tpm_time_ms).unwrap_or(i64::MAX);
                if !self.global_state.nv_available {
                    self.global_state.da_pending_on_nv = true;
                }
                return Err(TpmRc::AUTH_FAIL.with(Position::session(1)));
            }
            Ok(())
        } else if !expected_auth.is_empty() {
            Err(TpmRc::AUTH_MISSING)
        } else {
            Ok(())
        }
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
            for _ in &self.state().parsed_auths[..parsed_auths_len] {
                session_responses[num_sessions] = TpmsAuthResponse {
                    nonce: Tpm2bNonce::default(),
                    session_attributes: TpmaSession::CONTINUE_SESSION,
                    hmac: Tpm2bData::default(),
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
                .read_slice(usize::try_from(auth_size).map_err(|_| TpmRc::SIZE.to_rc())?)
                .ok_or(TpmRc::SIZE.to_rc())?;
            while !auth_slice.is_empty() {
                if num_sessions >= 3 {
                    return Err(TpmRc::SIZE.with(Position::session(4)));
                }
                let auth = OwnedAuthCommand::unmarshal(&mut auth_slice)
                    .map_err(|e| e.fmt1().with(crate::util::session_position(num_sessions)))?;

                self.state_mut().parsed_auths[num_sessions] = auth;
                self.state_mut().parsed_auths_len += 1;

                if auth.session_handle != Handle::RS_PW {
                    let sess_handle = auth.session_handle.0;
                    if self.state().session(sess_handle).is_none() {
                        return Err(TpmRc::HANDLE.with(crate::util::handle_position(num_sessions)));
                    }
                }

                session_responses[num_sessions] = TpmsAuthResponse {
                    nonce: Tpm2bNonce::default(),
                    session_attributes: TpmaSession::CONTINUE_SESSION,
                    hmac: Tpm2bData::default(),
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
            let param_size = u32::try_from(param_len).map_err(|_| TpmRc::FAILURE)?;
            response
                .write(&param_size.to_be_bytes())
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

    /// Computes the cryptographic hash of a sequence of byte slices using the given hash algorithm.
    pub fn compute_hash(
        &self,
        hash_alg: TpmiAlgHash,
        buffers: &[&[u8]],
    ) -> Result<([u8; TpmiAlgHash::MAX_DIGEST_BYTES], usize), TpmRc> {
        let mut state =
            HashStream::new(self.crypto(), hash_alg).map_err(|_| TpmRc::VALUE.to_rc())?;
        for buf in buffers {
            state.update(buf).map_err(|_| TpmRc::FAILURE)?;
        }
        let mut digest_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
        let len = state
            .finalize(&mut digest_buf)
            .map_err(|_| TpmRc::FAILURE)?
            .digest()
            .len();
        Ok((digest_buf, len))
    }

    /// Computes the PCR digest of the selected PCRs using the specified hash algorithm.
    pub fn compute_pcr_digest(
        &self,
        pcr_select: &TpmlPcrSelection,
        hash_alg: TpmiAlgHash,
    ) -> Result<OwnedDigest, TpmRc> {
        let mut state =
            HashStream::new(self.crypto(), hash_alg).map_err(|_| TpmRc::VALUE.to_rc())?;

        for in_sel in pcr_select.as_slice() {
            let select_hash_alg = in_sel.hash;
            let pcr_select = in_sel.selection.pcrs();

            // Iterate over the 24 PCRs in each bank (TPM 2.0 Library Specification Part 4, Section 8.1).
            for pcr in 0..24usize {
                let byte_idx = pcr / 8;
                let bit_idx = pcr % 8;
                if byte_idx < pcr_select.len() && (pcr_select[byte_idx] & (1 << bit_idx)) != 0 {
                    let digest_bytes = match select_hash_alg {
                        TpmiAlgHash::Sha1 => &self.global_state.pcrs.sha1[pcr][..],
                        TpmiAlgHash::Sha256 => &self.global_state.pcrs.sha256[pcr][..],
                        TpmiAlgHash::Sha384 => &self.global_state.pcrs.sha384[pcr][..],
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

    /// Generates the sensitive area of a new object and updates the public key / `unique` field
    /// of `parms_and_id` to match.
    ///
    /// If `args.gen_seed` is set, asymmetric keys are generated deterministically from a
    /// [`Random::rng_seeded`](tpm2::crypto::Random::rng_seeded) RNG (primary / derived objects); otherwise the TPM's global RNG
    /// is used.
    ///
    /// PORTING: exp wrote the private key into an `actual_private_key: &mut [u8]` out-buffer and
    /// returned its length. This now returns the [`OwnedSensitiveComposite`] that is stored in
    /// [`TransientObject::sensitive`], and takes `&mut self` (it may draw from the global RNG).
    pub fn generate_key_and_unique(
        &mut self,
        name_alg: TpmiAlgHash,
        parms_and_id: &mut OwnedPublicParmsAndId,
        args: KeyDerivationArgs<'_>,
    ) -> Result<OwnedSensitiveComposite, TpmRc> {
        match parms_and_id {
            OwnedPublicParmsAndId::Ecc(parms, point) => {
                self.generate_ecc_key(parms, point, args.gen_seed)
            }
            OwnedPublicParmsAndId::Rsa(parms, unique) => {
                self.generate_rsa_key(parms, unique, args.gen_seed)
            }
            OwnedPublicParmsAndId::KeyedHash(_, unique) => {
                self.generate_keyed_hash_key(name_alg, args, unique)
            }
            OwnedPublicParmsAndId::Sym(sym_def, unique) => {
                self.generate_symmetric_key(name_alg, args, sym_def.alg.key_bytes(), unique)
            }
            OwnedPublicParmsAndId::Mldsa(_, _)
            | OwnedPublicParmsAndId::HashMldsa(_, _)
            | OwnedPublicParmsAndId::Mlkem(_, _) => Err(TpmRc::TYPE.to_rc()),
        }
    }

    /// Generates an ECC key pair on the curve of `parms` and populates the public point
    /// coordinates. Returns the secret scalar as [`OwnedSensitiveComposite::Ecc`].
    fn generate_ecc_key(
        &mut self,
        parms: &TpmsEccParms,
        point: &mut OwnedEccPoint,
        gen_seed_arg: Option<&[u8]>,
    ) -> Result<OwnedSensitiveComposite, TpmRc> {
        let crypto = self.crypto();
        let key = match gen_seed_arg {
            Some(seed) => {
                let mut rng = crypto.rng_seeded(seed).map_err(|_| TpmRc::FAILURE)?;
                Ecc::generate_key(crypto, &mut rng, parms.curve_id)
            }
            None => Ecc::generate_key(crypto, &mut self.context.platform.rng, parms.curve_id),
        }
        .map_err(|_| TpmRc::FAILURE)?;

        let mut x = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
        let mut y = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
        let public = key
            .public_key()
            .point(&mut x, &mut y)
            .map_err(|_| TpmRc::FAILURE)?;
        *point = OwnedEccPoint::from(public);

        let mut d = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
        let scalar = key.scalar(&mut d).map_err(|_| TpmRc::FAILURE)?;
        Ok(OwnedSensitiveComposite::Ecc(OwnedEccParameter::from(
            scalar,
        )))
    }

    /// Generates an RSA key pair of the size / exponent in `parms` and populates the public
    /// modulus. Returns the first prime factor as [`OwnedSensitiveComposite::Rsa`].
    fn generate_rsa_key(
        &mut self,
        parms: &TpmsRsaParms,
        unique: &mut OwnedPublicKeyRsa,
        gen_seed_arg: Option<&[u8]>,
    ) -> Result<OwnedSensitiveComposite, TpmRc> {
        let crypto = self.crypto();
        let key = match gen_seed_arg {
            Some(seed) => {
                let mut rng = crypto.rng_seeded(seed).map_err(|_| TpmRc::FAILURE)?;
                Rsa::generate_key(crypto, &mut rng, parms.key_bits, parms.exponent)
            }
            None => Rsa::generate_key(
                crypto,
                &mut self.context.platform.rng,
                parms.key_bits,
                parms.exponent,
            ),
        }
        .map_err(|_| TpmRc::FAILURE)?;

        let mut n = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
        let modulus = key
            .public_key()
            .modulus(&mut n)
            .map_err(|_| TpmRc::FAILURE)?;
        *unique = OwnedPublicKeyRsa::from(modulus);

        let mut p = [0u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES];
        let prime_p = key.prime_p(&mut p).map_err(|_| TpmRc::FAILURE)?;
        Ok(OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::from(
            prime_p,
        )))
    }

    /// Derives or generates bytes for keyed hash objects, hashing them to get a unique identifier.
    fn generate_keyed_hash_key(
        &mut self,
        name_alg: TpmiAlgHash,
        args: KeyDerivationArgs<'_>,
        unique: &mut OwnedDigest,
    ) -> Result<OwnedSensitiveComposite, TpmRc> {
        const KEY_SIZE: usize = 32;
        let mut generated_key = [0u8; KEY_SIZE];
        let key: &[u8] = if let Some(data) = args.fallback_sensitive_data {
            data
        } else if let Some(seed) = args.gen_seed {
            kdfa(
                self.crypto(),
                name_alg,
                seed,
                c"Symmetric Key",
                &[],
                &[],
                &mut generated_key,
            )
            .map_err(|_| TpmRc::FAILURE)?;
            &generated_key
        } else if args.get_random_fallback {
            self.fill_random(&mut generated_key)
                .map_err(|_| TpmRc::FAILURE)?;
            &generated_key
        } else {
            return Err(TpmRc::VALUE.to_rc());
        };

        let (digest_bytes, digest_len) = self.compute_hash(name_alg, &[args.obj_seed, key])?;
        *unique =
            OwnedDigest::from_bytes(&digest_bytes[..digest_len]).map_err(|_| TpmRc::FAILURE)?;
        let sensitive = OwnedSensitiveData::new(key).ok_or(TpmRc::FAILURE)?;
        Ok(OwnedSensitiveComposite::KeyedHash(sensitive))
    }

    /// Derives or generates symmetric keys of specific target sizes, hashing them to get a unique identifier.
    fn generate_symmetric_key(
        &mut self,
        name_alg: TpmiAlgHash,
        args: KeyDerivationArgs<'_>,
        sym_key_size: usize,
        unique: &mut OwnedDigest,
    ) -> Result<OwnedSensitiveComposite, TpmRc> {
        let mut generated_key = [0u8; Tpm2bSymKey::CAP];
        let key_buf = generated_key
            .get_mut(..sym_key_size)
            .ok_or(TpmRc::KEY_SIZE.to_rc())?;
        let key: &[u8] = if let Some(seed) = args.gen_seed {
            kdfa(
                self.crypto(),
                name_alg,
                seed,
                c"Symmetric Key",
                &[],
                &[],
                key_buf,
            )
            .map_err(|_| TpmRc::FAILURE)?;
            key_buf
        } else if args.get_random_fallback {
            self.fill_random(key_buf).map_err(|_| TpmRc::FAILURE)?;
            key_buf
        } else if let Some(data) = args.fallback_sensitive_data {
            data
        } else {
            return Err(TpmRc::VALUE.to_rc());
        };

        let (digest_bytes, digest_len) = self.compute_hash(name_alg, &[args.obj_seed, key])?;
        *unique =
            OwnedDigest::from_bytes(&digest_bytes[..digest_len]).map_err(|_| TpmRc::FAILURE)?;
        let sensitive = OwnedSymKey::new(key).ok_or(TpmRc::KEY_SIZE.to_rc())?;
        Ok(OwnedSensitiveComposite::Sym(sensitive))
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
            if self.global_state.find_active_sequence(handle).is_some() {
                return Err(TpmRc::KEY.with(pos));
            }
            self.context
                .lookup_transient_object(self.global_state, handle, pos)
                .cloned()
        } else if handle >> 24 == 0x81 {
            if (handle & 0x00FF_FFFF) > 0x0080_FFFF {
                return Err(TpmRc::VALUE.with(pos));
            }
            self.context
                .load_persistent_object(self.global_state, handle)
                .map_err(|_| {
                    if pos == Position::handle(1) {
                        TpmRc::REFERENCE_H0
                    } else if pos == Position::handle(2) {
                        TpmRc::REFERENCE_H1
                    } else {
                        TpmRc::REFERENCE_H2
                    }
                })
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
            let expiration_abs = u64::from(expiration.unsigned_abs());
            let clock = self.global_state.tpm_time_ms;
            if nonce_tpm.as_slice().is_empty() {
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

        if !nonce_tpm.as_slice().is_empty()
            && nonce_tpm.as_slice() != session.nonce_tpm.get_buffer()
        {
            return Err(TpmRc::NONCE.with(blame_nonce));
        }

        if auth_timeout != 0 {
            let current_time = self.global_state.tpm_time_ms;
            if auth_timeout < current_time || session.epoch != self.global_state.time_epoch {
                return Err(TpmRc::EXPIRED.with(blame_expiration));
            }
        }

        if !cp_hash_a.as_slice().is_empty() {
            if cp_hash_a.as_slice().len() != session.policy_digest_len {
                return Err(TpmRc::SIZE.with(blame_cp_hash));
            }
            if session.policy_hash_len != 0
                && cp_hash_a.as_slice() != &session.policy_hash[..session.policy_hash_len]
            {
                return Err(TpmRc::CPHASH);
            }
        }

        Ok(())
    }

    pub fn get_dynamic_qualified_name(&self, obj: &TransientObject) -> OwnedName {
        obj.qualified_name
    }

    /// Computes `qualified_signer` and `extra_data` for attestation structures (`TpmsAttest`)
    /// per TPM 2.0 Library Specification Part 3 (see `Attest_spt.c`).
    /// - For a null signer handle (`0x40000007` / `RHNull`), `qualified_signer` is `[0x40, 0x00, 0x00, 0x07]`.
    /// - For anonymous schemes (`TPM_ALG_ECDAA`), both `qualified_signer` and `extra_data` must be empty buffers (`size = 0`).
    /// - Otherwise, `qualified_signer` is `self.get_dynamic_qualified_name(signer)` and `extra_data` is `qualifying_data`.
    pub fn compute_attest_fields<'c>(
        &self,
        signer_obj_opt: Option<&'c TransientObject>,
        scheme: &Option<tpm2::TpmtSigScheme>,
        qualifying_data: &tpm2::Tpm2bData<'c>,
    ) -> Result<(tpm2::Tpm2bName<'c>, tpm2::Tpm2bData<'c>), TpmRc> {
        const RH_NULL_NAME: [u8; 4] = Handle::RH_NULL.0.to_be_bytes();
        let qualified_signer = match signer_obj_opt {
            None => tpm2::Tpm2bName::new(&RH_NULL_NAME).ok_or(TpmRc::FAILURE)?,
            Some(signer) => {
                if matches!(scheme, Some(tpm2::TpmtSigScheme::Ecdaa(_))) {
                    tpm2::Tpm2bName::default()
                } else {
                    signer.qualified_name.as_tpm2b()
                }
            }
        };

        let extra_data = if matches!(scheme, Some(tpm2::TpmtSigScheme::Ecdaa(_))) {
            tpm2::Tpm2bData::default()
        } else {
            *qualifying_data
        };

        Ok((qualified_signer, extra_data))
    }

    /// Computes the ephemeral secret scalar `r` for `TPM2_Commit` or ECDAA signing (`BnSignEcdaa`)
    /// deterministically via KDFa per `CryptGenerateR` in MS-TPM.
    pub fn compute_commit_r(
        &self,
        commit_counter: u16,
        name: &[u8],
        param_size: usize,
    ) -> Result<[u8; 256], TpmRc> {
        let mut r_buf = [0u8; 256];
        let mut cntr_bytes = [0u8; 8];
        cntr_bytes[6..8].copy_from_slice(&commit_counter.to_be_bytes());
        kdfa(
            self.crypto(),
            TpmiAlgHash::Sha256,
            &self.global_state.commit_nonce,
            c"ECDAA Commit",
            name,
            &cntr_bytes,
            r_buf.get_mut(..param_size).ok_or(TpmRc::FAILURE)?,
        )
        .map_err(|_| TpmRc::FAILURE)?;
        Ok(r_buf)
    }

    pub fn resolve_hierarchy_proof(&self, hierarchy: u32) -> (&[u8], usize, u32) {
        if hierarchy == 0x40000001 {
            (
                &self.global_state.sh_proof[..],
                usize::from(self.global_state.sh_proof_size),
                0x40000001,
            )
        } else if hierarchy == 0x4000000B {
            (
                &self.global_state.eh_proof[..],
                usize::from(self.global_state.eh_proof_size),
                0x4000000B,
            )
        } else if hierarchy == 0x4000000C {
            (
                &self.global_state.ph_proof[..],
                usize::from(self.global_state.ph_proof_size),
                0x4000000C,
            )
        } else {
            (
                &self.global_state.null_proof[..],
                usize::from(self.global_state.null_proof_size),
                0x40000007,
            )
        }
    }

    pub fn compute_verified_ticket(
        &self,
        hierarchy: u32,
        digest: &[u8],
        key_name: &[u8],
    ) -> Result<[u8; 32], TpmRc> {
        self.compute_verified_ticket_with_meta(hierarchy, 0x8022, digest, key_name, &[])
    }

    pub fn compute_verified_ticket_with_meta(
        &self,
        hierarchy: u32,
        tag: u16,
        digest_or_message: &[u8],
        key_name: &[u8],
        metadata: &[u8],
    ) -> Result<[u8; 32], TpmRc> {
        let (proof_bytes, proof_len, _) = self.resolve_hierarchy_proof(hierarchy);

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
            TpmiAlgHash::Sha256,
            &proof_bytes[..proof_len],
            &hmac_input[..offset],
            &mut hmac_buf,
        )
        .map_err(|_| TpmRc::FAILURE)?;

        let mut hmac_bytes = [0u8; 32];
        hmac_bytes.copy_from_slice(hmac_digest.digest());
        Ok(hmac_bytes)
    }

    pub fn compute_hashcheck_ticket(
        &self,
        hierarchy: Handle,
        hash_alg: TpmiAlgHash,
        digest: &[u8],
    ) -> Result<[u8; 32], TpmRc> {
        if hierarchy != Handle::RH_NULL
            && hierarchy != Handle::RH_OWNER
            && hierarchy != Handle::RH_PLATFORM
            && hierarchy != Handle::RH_ENDORSEMENT
        {
            return Err(TpmRc::HIERARCHY.to_rc());
        }
        let (proof_bytes, proof_len, _) = self.resolve_hierarchy_proof(hierarchy.0);

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
            TpmiAlgHash::Sha256,
            &proof_bytes[..proof_len],
            &hmac_input[..offset],
            &mut hmac_buf,
        )
        .map_err(|_| TpmRc::FAILURE)?;

        let mut hmac_bytes = [0u8; 32];
        hmac_bytes.copy_from_slice(hmac_digest.digest());
        Ok(hmac_bytes)
    }

    pub fn validate_policy_session(
        &mut self,
        session_handle: u32,
        pos: Position,
    ) -> Result<(), TpmRc> {
        if (session_handle >> 24) != 0x03 && (session_handle >> 24) != 0x02 {
            return Err(if pos == Position::handle(2) {
                TpmRc::HANDLE.with(pos)
            } else {
                TpmRc::VALUE.with(pos)
            });
        }
        let current_time = self.global_state.tpm_time_ms;
        let (is_expired, is_wrong_type) = {
            let session =
                self.global_state
                    .session(session_handle)
                    .ok_or(if pos == Position::handle(2) {
                        TpmRc::HANDLE.with(pos)
                    } else {
                        TpmRc::VALUE.with(pos)
                    })?;
            (
                session.epoch != self.global_state.time_epoch
                    || (session.timeout != 0 && session.timeout < current_time),
                session.session_type != TpmSe::Policy && session.session_type != TpmSe::Trial,
            )
        };

        if is_expired {
            return Err(TpmRc::EXPIRED.with(pos));
        }

        if is_wrong_type {
            return Err(if pos == Position::handle(2) {
                TpmRc::HANDLE.with(pos)
            } else {
                TpmRc::VALUE.with(pos)
            });
        }
        Ok(())
    }

    pub fn update_aliased_transient_objects(
        &mut self,
        new_handle: u32,
        new_name: &OwnedName,
        new_qualified_name: &OwnedName,
    ) {
        let mut old_handles = [0u32; 16];
        let mut num_old = 0;
        for old_obj in self.global_state.transient_objects.iter().flatten() {
            if old_obj.name == *new_name
                && old_obj.handle != new_handle
                && old_obj.qualified_name != *new_qualified_name
                && num_old < old_handles.len()
            {
                old_handles[num_old] = old_obj.handle;
                num_old += 1;
            }
        }
        if num_old == 0 {
            return;
        }

        // First, redirect any children whose transient_parents pointed to one of the old_handles
        for i in 0..self.global_state.transient_objects.len() {
            if let Some(parent_h) = self.global_state.transient_parents[i] {
                for &old_h in &old_handles[..num_old] {
                    if parent_h == old_h {
                        self.global_state.transient_parents[i] = Some(new_handle);
                    }
                }
            }
        }

        // Second, propagate qualified_name recomputation down the tree from new_handle
        let mut changed = true;
        while changed {
            changed = false;
            for i in 0..self.global_state.transient_objects.len() {
                if let Some(parent_h) = self.global_state.transient_parents[i] {
                    let parent_qn = if parent_h == new_handle {
                        *new_qualified_name
                    } else if let Some(parent_idx) =
                        self.global_state.find_transient_index(parent_h)
                    {
                        if let Some(p_obj) = &self.global_state.transient_objects[parent_idx] {
                            p_obj.qualified_name
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    };

                    let (name_alg, child_name, current_qn) =
                        if let Some(child_obj) = &self.global_state.transient_objects[i] {
                            (
                                child_obj.public.name_alg,
                                child_obj.name,
                                child_obj.qualified_name,
                            )
                        } else {
                            continue;
                        };

                    if let Ok(new_qn) = self.compute_qualified_name(
                        name_alg,
                        parent_qn.get_buffer(),
                        child_name.get_buffer(),
                    ) && current_qn != new_qn
                        && let Some(child_obj) = self.global_state.transient_objects[i].as_mut()
                    {
                        child_obj.qualified_name = new_qn;
                        changed = true;
                    }
                }
            }
        }

        // Third, clear the old aliased transient objects so their handles do not leak or occupy slots
        for i in 0..self.global_state.transient_objects.len() {
            if let Some(obj) = &self.global_state.transient_objects[i] {
                for &old_h in &old_handles[..num_old] {
                    if obj.handle == old_h {
                        self.global_state.transient_objects[i] = None;
                        self.global_state.transient_parents[i] = None;
                        break;
                    }
                }
            }
        }
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
