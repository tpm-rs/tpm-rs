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
mod rewrap;
mod sequence;
mod session;
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
use tpm2::crypto::kdf::kdfa;
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmSe};
use tpm2::{Marshal, Unmarshal};
use tpm2::{
    Tpm2bAuth, Tpm2bDigest, Tpm2bNonce, TpmaObject, TpmaSession, TpmiAlgHash, TpmlPcrSelection,
    TpmsAuthResponse, TpmsEccParms, TpmsRsaParms, TpmtSymDef,
};

/// Represents an object loaded into the TPM's volatile memory.
/// This structure holds the state of a transient object, which could be a key or a data object,
/// that is actively being used by the TPM.
#[derive(Debug, Clone)]
pub struct TransientObject {
    /// The transient handle assigned to this object (e.g., in the 0x80xxxxxx range).
    pub handle: u32,
    /// The random seed value associated with this object, used for key generation or derivation.
    pub seed: [u8; 32],
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
    pub sym_bits: u32,
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
pub struct CommandHandler<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync> {
    pub context: &'b mut TpmEngine<'a, C, S, T, R>,
    pub global_state: &'b mut GlobalState,
}

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Creates a new `CommandHandler` object.
    pub fn new(
        context: &'b mut TpmEngine<'a, C, S, T, R>,
        global_state: &'b mut GlobalState,
    ) -> Self {
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

    #[inline]
    pub fn crypto(&self) -> &C {
        self.context.platform.crypto
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
                self.global_state.lockout_timer = self.global_state.tpm_time_ms as i64;
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

    /// Computes the cryptographic hash of a sequence of byte slices using the given hash algorithm.
    pub fn compute_hash(
        &self,
        hash_alg: TpmiAlgHash,
        buffers: &[&[u8]],
    ) -> Result<([u8; 64], usize), TpmRc> {
        let mut state = tpm2::crypto::HashCtx::new(self.crypto(), hash_alg)
            .map_err(|_| TpmRc::VALUE.to_rc())?;
        for buf in buffers {
            state.update(buf).map_err(|_| TpmRc::FAILURE)?;
        }
        let mut digest_buf = [0u8; 64];
        let digest = state
            .finalize(&mut digest_buf)
            .map_err(|_| TpmRc::FAILURE)?;
        let len = digest.digest().len();
        Ok((digest_buf, len))
    }

    /// Computes the PCR digest of the selected PCRs using the specified hash algorithm.
    pub fn compute_pcr_digest(
        &self,
        pcr_select: &TpmlPcrSelection,
        hash_alg: TpmiAlgHash,
    ) -> Result<OwnedDigest, TpmRc> {
        let mut state = tpm2::crypto::HashCtx::new(self.crypto(), hash_alg)
            .map_err(|_| TpmRc::VALUE.to_rc())?;

        for in_sel in pcr_select.pcr_selections() {
            let select_hash_alg = in_sel.hash();
            let sizeof_select = in_sel.sizeof_select();

            // Iterate over the 24 PCRs in each bank (TPM 2.0 Library Specification Part 4, Section 8.1).
            for pcr in 0..24 {
                let byte_idx = (pcr / 8) as usize;
                let bit_idx = (pcr % 8) as usize;
                if byte_idx < sizeof_select as usize
                    && (in_sel.pcr_select()[byte_idx] & (1 << bit_idx)) != 0
                {
                    let digest_bytes = match select_hash_alg {
                        TpmiAlgHash::Sha1 => &self.global_state.pcrs.sha1[pcr as usize][..],
                        TpmiAlgHash::Sha256 => &self.global_state.pcrs.sha256[pcr as usize][..],
                        TpmiAlgHash::Sha384 => &self.global_state.pcrs.sha384[pcr as usize][..],
                        _ => return Err(TpmRc::HASH.to_rc()),
                    };
                    state.update(digest_bytes).map_err(|_| TpmRc::FAILURE)?;
                }
            }
        }

        let mut digest_buf = [0u8; 64];
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
            kdfa(
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
        let key_len = if let Some(seed) = args.gen_seed {
            let mut generated_key = [0u8; 64];
            kdfa(
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
        } else if let Some(data) = args.fallback_sensitive_data {
            let data_len = data.len();
            actual_private_key[..data_len].copy_from_slice(data);
            data_len
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
            if self.global_state.find_active_sequence(handle).is_some() {
                return Err(TpmRc::KEY.with(pos));
            }
            if let Ok(obj) = self
                .context
                .lookup_transient_object(self.global_state, handle, pos)
            {
                return Ok(obj.clone());
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
            let expiration_abs = expiration.unsigned_abs() as u64;
            let clock = self.global_state.tpm_time_ms;
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
            let current_time = self.global_state.tpm_time_ms;
            if auth_timeout < current_time || session.epoch != self.global_state.time_epoch {
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
        let qualified_signer = match signer_obj_opt {
            None => tpm2::Tpm2bName::from_bytes(&[0x40, 0x00, 0x00, 0x07])
                .map_err(|_| TpmRc::FAILURE)?,
            Some(signer) => {
                if matches!(scheme, Some(tpm2::TpmtSigScheme::Ecdaa(_))) {
                    tpm2::Tpm2bName::from_bytes(&[]).map_err(|_| TpmRc::FAILURE)?
                } else {
                    signer.qualified_name.as_tpm2b()
                }
            }
        };

        let extra_data = if matches!(scheme, Some(tpm2::TpmtSigScheme::Ecdaa(_))) {
            tpm2::Tpm2bData::from_bytes(&[]).map_err(|_| TpmRc::FAILURE)?
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
        let mut kdf_out = [0u8; 128];
        tpm2::crypto::kdf::kdfa(
            self.crypto(),
            tpm2::TpmiAlgHash::Sha256,
            &self.global_state.commit_nonce,
            b"ECDAA Commit",
            name,
            &cntr_bytes,
            (param_size * 8) as u32,
            &mut kdf_out[..param_size],
        )
        .map_err(|_| TpmRc::FAILURE)?;
        r_buf[..param_size].copy_from_slice(&kdf_out[..param_size]);
        Ok(r_buf)
    }

    pub fn resolve_hierarchy_proof(&self, hierarchy: u32) -> (&[u8], usize, u32) {
        if hierarchy == 0x40000001 {
            (
                &self.global_state.sh_proof[..],
                self.global_state.sh_proof_size as usize,
                0x40000001,
            )
        } else if hierarchy == 0x4000000B {
            (
                &self.global_state.eh_proof[..],
                self.global_state.eh_proof_size as usize,
                0x4000000B,
            )
        } else if hierarchy == 0x4000000C {
            (
                &self.global_state.ph_proof[..],
                self.global_state.ph_proof_size as usize,
                0x4000000C,
            )
        } else {
            (
                &self.global_state.null_proof[..],
                self.global_state.null_proof_size as usize,
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

        let mut hmac_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
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

        let mut hmac_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
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
        if is_expired {
            let _ = self.global_state.flush_session(session_handle);
            return Err(TpmRc::EXPIRED.with(pos));
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
                    ) {
                        if current_qn != new_qn {
                            if let Some(child_obj) = self.global_state.transient_objects[i].as_mut()
                            {
                                child_obj.qualified_name = new_qn;
                                changed = true;
                            }
                        }
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
