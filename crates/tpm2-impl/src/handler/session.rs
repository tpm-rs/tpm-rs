use crate::handler::{CommandHandler, SessionState};
use crate::req_resp::RequestThenResponse;
use crate::storage::{NvStorage, Tpm2Storage};
use crate::timer::TpmTimer;
use tpm2::Alg;
#[allow(unused_imports)]
use tpm2::TpmCc;
use tpm2::commands::responses;
use tpm2::commands::{
    PolicyRestart, PolicyRestartHandles, StartAuthSession, StartAuthSessionHandles,
    StartAuthSessionRespHandles,
};
use tpm2::crypto::kdf::{kdfa, kdfe};
use tpm2::crypto::{CryptoProvider, Rng};
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TPM2_MAX_ACTIVE_SESSIONS, TpmSe};
use tpm2::{
    Tpm2bAuth, Tpm2bNonce, TpmaObject, TpmaSession, TpmiAlgHash, TpmiAlgSymMode, TpmsAuthCommand,
    TpmsAuthResponse, Unmarshal,
};

impl<'a, 'b, C: CryptoProvider, S: NvStorage, T: TpmTimer, R: Rng + Sync>
    CommandHandler<'a, 'b, C, S, T, R>
{
    /// Handles the [TpmCc::StartAuthSession] (`0x11F`) command.
    ///
    /// # Description
    /// This command starts an authorization session (either HMAC, Policy, or Trial policy session)
    /// and returns the session handle and a TPM nonce.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 11.1 (TPM2_StartAuthSession).
    ///
    /// # Relationships
    /// - Starts a session that can be used for HMAC authorization, parameter encryption/decryption,
    ///   or policy building via commands like [TpmCc::PolicyPCR](policy_pcr.rs)
    ///   and [TpmCc::PolicySigned](policy_signed.rs).
    /// - Policy sessions can be restarted using [TpmCc::PolicyRestart](session.rs).
    pub fn start_auth_session(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;

        let handles = request.try_unmarshal::<StartAuthSessionHandles>()?;

        let mut session_responses = [TpmsAuthResponse::default(); 3];
        // Parse authorization sessions if present.
        let num_sessions =
            self.parse_auth_sessions_for_start_session(&mut request, &mut session_responses)?;

        let cmd = match request.try_unmarshal::<StartAuthSession>() {
            Ok(cmd) => cmd,
            Err(e) => {
                let mut slice = request.remaining_slice();
                if let Ok(_nonce) = tpm2::Tpm2bNonce::unmarshal(&mut slice)
                    && let Ok(_salt) = tpm2::Tpm2bEncryptedSecret::unmarshal(&mut slice)
                    && let Ok(_st) = tpm2::TpmSe::unmarshal(&mut slice)
                    && slice.len() >= 2
                {
                    let alg = u16::from_be_bytes([slice[0], slice[1]]);
                    if alg > 0x0080 {
                        return Err(TpmRc::VALUE.with(Position::parameter(4)));
                    }
                }
                return Err(e);
            }
        };

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // Validate symmetric block cipher mode (if not Null, mode must be CFB)
        if let Some(tpm2::TpmtSymDef::Cipher(sym_obj)) = cmd.symmetric
            && sym_obj.mode() != Some(TpmiAlgSymMode::CFB)
        {
            return Err(TpmRc::MODE.with(Position::parameter(4)));
        }

        // Generate nonceTPM
        let auth_hash_digest_size = cmd.auth_hash.digest_size();
        if auth_hash_digest_size == 0 {
            return Err(TpmRc::HASH.with(Position::parameter(5)));
        }

        let nonce_caller_len = cmd.nonce_caller.get_buffer().len();
        if nonce_caller_len < 16 || nonce_caller_len > auth_hash_digest_size {
            return Err(TpmRc::SIZE.with(Position::parameter(1)));
        }

        let mut nonce_tpm_bytes = [0u8; 64];
        self.context
            .platform
            .rng
            .get_random(&mut nonce_tpm_bytes[..nonce_caller_len])
            .map_err(|_| TpmRc::FAILURE)?;
        let nonce_tpm = Tpm2bNonce::from_bytes(&nonce_tpm_bytes[..nonce_caller_len])
            .map_err(|_| TpmRc::FAILURE)?;

        // Decrypt salt
        let mut decrypted_salt = [0u8; 64];
        let decrypted_salt_len = self.decrypt_session_salt(
            handles.tpm_key,
            cmd.encrypted_salt.get_buffer(),
            &nonce_tpm,
            &cmd.nonce_caller,
            &mut decrypted_salt,
        )?;

        // Retrieve auth value of bind entity
        let mut bind_auth = [0u8; 64];
        let bind_auth_len = self.retrieve_bind_auth(handles.bind, &mut bind_auth)?;
        let bind_auth_stripped = crate::util::strip_trailing_zeros(&bind_auth[..bind_auth_len]);

        // Generate unique session handle
        let session_handle = self.generate_session_handle(cmd.session_type)?;

        // Derive session key (if not Trial session)
        let (session_key, session_key_len) = self.derive_session_key(
            cmd.session_type,
            handles.tpm_key,
            handles.bind,
            bind_auth_stripped,
            &decrypted_salt[..decrypted_salt_len],
            cmd.auth_hash,
            &nonce_tpm,
            &cmd.nonce_caller,
            &cmd.symmetric,
        )?;

        // Only HMAC sessions are bound to an entity; a policy (or trial) session is never bound
        // (C `SessionCreate`, Session.c: `bind != TPM_RH_NULL && sessionType == TPM_SE_HMAC`).
        // The bind entity's authValue still contributes to the session key of every session type.
        let is_bound_session = handles.bind != Handle::RH_NULL && cmd.session_type == TpmSe::HMAC;
        let mut bound_entity = crate::owned::OwnedName::default();
        if is_bound_session {
            let bind_name = self.context.handle_name(self.global_state, handles.bind.0);
            bound_entity = compute_bound_entity(bind_name.get_buffer(), bind_auth_stripped)?;
        }
        let bind_entity = if is_bound_session {
            handles.bind
        } else {
            Handle::RH_NULL
        };
        // A DA-protected bind entity makes every use of the session subject to DA, for all
        // session types (C `SessionCreate`: `isDaBound`, `isLockoutBound`).
        let is_da_bound = handles.bind != Handle::RH_NULL
            && self
                .context
                .has_da_protection(self.global_state, handles.bind.0);
        let is_lockout_bound = is_da_bound && handles.bind == Handle::RH_LOCKOUT;

        // Add to active sessions
        let session_state = SessionState {
            session_handle,
            session_type: cmd.session_type,
            auth_hash: cmd.auth_hash,
            nonce_tpm: crate::owned::OwnedNonce::from(nonce_tpm),
            nonce_caller: crate::owned::OwnedNonce::from(cmd.nonce_caller),
            session_key,
            session_key_len,
            symmetric: cmd.symmetric,
            bind_entity,
            bound_entity,
            audit_digest: None,
            audit_digest_len: 0,
            audit_cp_hash: [0u8; 64],
            audit_cp_hash_len: 0,
            policy_hash: [0u8; 64],
            policy_hash_len: 0,
            is_cp_hash_defined: false,
            is_name_hash_defined: false,
            is_template_hash_defined: false,
            policy_digest: [0u8; 64],
            policy_digest_len: auth_hash_digest_size,
            command_code: 0,
            start_time: self.global_state.tpm_time_ms,
            timeout: 0,
            epoch: self.global_state.time_epoch,
            is_auth_value_needed: false,
            is_password_needed: false,
            pcr_counter: None,
            check_nv_written: false,
            nv_written_state: false,
            command_locality: 0,
            include_auth: false,
            is_da_bound,
            is_lockout_bound,
        };
        self.global_state.add_session(session_state)?;

        // Write response
        let resp_handles = StartAuthSessionRespHandles {
            session_handle: Handle(session_handle),
        };
        let rsp = responses::StartAuthSession { nonce_tpm };

        let response = request.into_response();

        self.write_response_all(
            response,
            &resp_handles,
            &rsp,
            &session_responses[..num_sessions],
        )?;

        Ok(())
    }

    /// Helper function to parse authorization sessions for start session command.
    fn parse_auth_sessions_for_start_session(
        &self,
        request: &mut RequestThenResponse<'_, '_>,
        session_responses: &mut [TpmsAuthResponse; 3],
    ) -> Result<usize, TpmRc> {
        let mut num_sessions = 0;
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
                let auth = TpmsAuthCommand::unmarshal(&mut auth_slice).map_err(|e| {
                    e.with_position(Position::session((num_sessions + 1) as u8))
                        .to_rc()
                })?;

                let continue_bit = (auth.session_attributes.0 & 1) | 1;
                session_responses[num_sessions] = TpmsAuthResponse {
                    nonce: Tpm2bNonce::default(),
                    session_attributes: TpmaSession(continue_bit),
                    hmac: Tpm2bAuth::default(),
                };
                num_sessions += 1;
            }
        }
        Ok(num_sessions)
    }

    /// Decrypts the session salt using the specified TPM key (via RSA-OAEP decryption or ECC key agreement).
    fn decrypt_session_salt(
        &mut self,
        tpm_key: Handle,
        encrypted_salt: &[u8],
        _nonce_tpm: &Tpm2bNonce,
        _nonce_caller: &Tpm2bNonce,
        decrypted_salt: &mut [u8; 64],
    ) -> Result<usize, TpmRc> {
        if tpm_key != Handle::RH_NULL {
            let handle_val = tpm_key.0;
            let key_obj = self.resolve_object(handle_val, Position::handle(1))?;

            // Same order as C `TPM2_StartAuthSession`: the key must be asymmetric
            // (`CryptIsAsymAlgorithm`), the secret must be non-empty, the sensitive area must be
            // loaded, and the key must be a decryption key.
            if !matches!(
                key_obj.public.parms_and_id,
                crate::owned::OwnedPublicParmsAndId::Rsa(..)
                    | crate::owned::OwnedPublicParmsAndId::Ecc(..)
            ) {
                return Err(TpmRc::KEY.with(Position::handle(1)));
            }
            if encrypted_salt.is_empty() {
                return Err(TpmRc::VALUE.with(Position::parameter(2)));
            }

            let handle_err = TpmRc::HANDLE.with(Position::handle(1));
            if key_obj.private_len == 0 {
                return Err(handle_err);
            }

            if !key_obj
                .public
                .object_attributes
                .contains(TpmaObject::DECRYPT)
            {
                return Err(TpmRc::ATTRIBUTES.with(Position::handle(1)));
            }

            match &key_obj.public.parms_and_id {
                crate::owned::OwnedPublicParmsAndId::Rsa(parms, _) => {
                    let expected_size = (parms.key_bits.0 / 8) as usize;
                    if encrypted_salt.is_empty() || encrypted_salt.len() != expected_size {
                        return Err(TpmRc::VALUE.with(Position::parameter(2)));
                    }
                    let mut plaintext_buf = [0u8; 512];
                    let name_alg = key_obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
                    let hash_alg = Alg::from(name_alg);

                    let decrypted_len = self
                        .crypto()
                        .decrypt(
                            Alg::OAEP,
                            hash_alg,
                            &key_obj.private[..key_obj.private_len],
                            encrypted_salt,
                            &mut plaintext_buf,
                            b"SECRET\0",
                        )
                        .map_err(|_| TpmRc::VALUE.with(Position::parameter(2)))?;

                    let name_alg_digest_size = name_alg.digest_size();
                    if name_alg_digest_size == 0 || decrypted_len > name_alg_digest_size {
                        return Err(TpmRc::VALUE.with(Position::parameter(2)));
                    }

                    decrypted_salt[..decrypted_len]
                        .copy_from_slice(&plaintext_buf[..decrypted_len]);
                    Ok(decrypted_len)
                }
                crate::owned::OwnedPublicParmsAndId::Ecc(ecc_parms, ecc_unique) => {
                    if encrypted_salt.is_empty() {
                        return Err(TpmRc::VALUE.with(Position::parameter(2)));
                    }
                    use tpm2::TpmsEccPoint;
                    use tpm2::Unmarshal;

                    let curve = ecc_parms.curve_id;
                    let param_size = match curve {
                        tpm2::TpmEccCurve::NistP192 => 24,
                        tpm2::TpmEccCurve::NistP224 => 28,
                        tpm2::TpmEccCurve::NistP256 | tpm2::TpmEccCurve::BNP256 => 32,
                        tpm2::TpmEccCurve::NistP384 => 48,
                        tpm2::TpmEccCurve::NistP521 => 66,
                        _ => return Err(TpmRc::CURVE.with(Position::handle(1))),
                    };

                    let mut slice = encrypted_salt;
                    let in_point_struct = TpmsEccPoint::unmarshal(&mut slice)
                        .map_err(|_| TpmRc::VALUE.with(Position::parameter(2)))?;
                    if !slice.is_empty() {
                        return Err(TpmRc::SIZE.with(Position::parameter(2)));
                    }

                    let in_x = in_point_struct.x.get_buffer();
                    let in_y = in_point_struct.y.get_buffer();
                    if in_x.len() > param_size || in_y.len() > param_size {
                        return Err(TpmRc::VALUE.with(Position::parameter(2)));
                    }

                    let mut raw_point = [0u8; 256];
                    raw_point[param_size - in_x.len()..param_size].copy_from_slice(in_x);
                    raw_point[param_size * 2 - in_y.len()..param_size * 2].copy_from_slice(in_y);

                    self.crypto()
                        .validate_point(curve, &raw_point[..param_size * 2])
                        .map_err(|_| TpmRc::VALUE.with(Position::parameter(2)))?;

                    let mut z_buf = [0u8; 256];
                    self.crypto()
                        .point_multiply(
                            curve,
                            &key_obj.private[..key_obj.private_len],
                            &raw_point[..param_size * 2],
                            &mut z_buf,
                        )
                        .map_err(|_| TpmRc::VALUE.with(Position::parameter(2)))?;

                    let name_alg = key_obj.public.name_alg.ok_or(TpmRc::HASH.to_rc())?;
                    let hash_size = name_alg.digest_size();
                    let z_x = &z_buf[..param_size];

                    let mut padded_in_x = [0u8; 128];
                    padded_in_x[param_size - in_x.len()..param_size].copy_from_slice(in_x);

                    let ek_x = ecc_unique.x.get_buffer();
                    let mut padded_ek_x = [0u8; 128];
                    padded_ek_x[param_size - ek_x.len()..param_size].copy_from_slice(ek_x);

                    let mut derived_salt = [0u8; 64];
                    let derived_salt_len = kdfe(
                        self.crypto(),
                        name_alg,
                        z_x,
                        b"SECRET",
                        &padded_in_x[..param_size],
                        &padded_ek_x[..param_size],
                        (hash_size * 8) as u32,
                        &mut derived_salt[..hash_size],
                    )
                    .map_err(|_| TpmRc::FAILURE)?;

                    decrypted_salt[..derived_salt_len]
                        .copy_from_slice(&derived_salt[..derived_salt_len]);
                    Ok(derived_salt_len)
                }
                // Non-asymmetric keys (e.g. TPM_ALG_SYMCIPHER) were rejected above.
                _ => Err(TpmRc::KEY.with(Position::handle(1))),
            }
        } else {
            if !encrypted_salt.is_empty() {
                return Err(TpmRc::VALUE.with(Position::parameter(2)));
            }
            Ok(0)
        }
    }

    /// Resolves the auth value for the session bind entity (permanent handles, PCRs, NV Indices,
    /// or transient/persistent objects).
    ///
    /// Mirrors the `bind` checks of C `TPM2_StartAuthSession`: a transient object whose sensitive
    /// area is not loaded (public-only) and a `TPM_NT_PIN_PASS` / `TPM_NT_PIN_FAIL` NV Index
    /// cannot be a bind entity (`TPM_RC_HANDLE + RC_StartAuthSession_bind`). For PCRs, the
    /// authValue is the PCR's group authValue (`PCRGetAuthValue`, non-empty only for PCRs in an
    /// auth group).
    fn retrieve_bind_auth(
        &mut self,
        bind: Handle,
        bind_auth: &mut [u8; 64],
    ) -> Result<usize, TpmRc> {
        if bind != Handle::RH_NULL {
            let bind_handle = bind.0;
            let handle_err = TpmRc::HANDLE.with(Position::handle(2));
            if (bind_handle >> 24) == 0x80 {
                match self.global_state.find_transient_object(bind_handle) {
                    None => return Err(TpmRc::REFERENCE_H1),
                    Some(obj) if obj.public_only => return Err(handle_err),
                    Some(_) => {}
                }
            } else if (bind_handle >> 24) == 0x81 {
                if self
                    .context
                    .load_persistent_object(self.global_state, bind_handle)
                    .is_err()
                {
                    return Err(TpmRc::REFERENCE_H1);
                }
            } else if (bind_handle >> 24) == 0x00 {
                if bind_handle > 23 {
                    return Err(handle_err);
                }
            } else if Handle(bind_handle).handle_type() == Some(tpm2::TpmHt::NVIndex) {
                let Some(nv_public) = self.read_nv_public(bind_handle) else {
                    return Err(TpmRc::REFERENCE_H1);
                };
                if matches!(
                    nv_public.attributes.get_index_type(),
                    Ok(tpm2::TpmNt::PinPass | tpm2::TpmNt::PinFail)
                ) {
                    return Err(handle_err);
                }
            } else if bind_handle != Handle::RH_OWNER.0
                && bind_handle != Handle::RH_ENDORSEMENT.0
                && bind_handle != Handle::RH_PLATFORM.0
                && bind_handle != Handle::RH_LOCKOUT.0
                && bind_handle != Handle::RH_AUTH_00.0
            {
                return Err(handle_err);
            }
            let auth_buf_struct = self.context.handle_auth(self.global_state, bind_handle);
            let auth_buf = auth_buf_struct.get_buffer();
            bind_auth[..auth_buf.len()].copy_from_slice(auth_buf);
            Ok(auth_buf.len())
        } else {
            Ok(0)
        }
    }

    /// Reads the public area of a defined NV Index.
    ///
    /// Returns `None` when `nv_index` is not defined (or its stored header cannot be parsed).
    pub(crate) fn read_nv_public(&mut self, nv_index: u32) -> Option<crate::owned::OwnedNvPublic> {
        let storage_mgr =
            crate::storage::manager::StorageManager::new(&mut *self.context.platform.storage);
        let metadata = storage_mgr.get_metadata(nv_index).ok()?;
        let mut read_buf = [0u8; 1536];
        let read_len = core::cmp::min(metadata.data_size as usize, read_buf.len());
        storage_mgr
            .read_item(nv_index, 0, &mut read_buf[..read_len])
            .ok()?;
        let (_, nv_public, _, _) =
            crate::handler::nv_storage::unmarshal_nv_header(&read_buf[..read_len]).ok()?;
        Some(nv_public)
    }

    /// Allocates a unique handle for the new session, avoiding conflicts in the global session map.
    fn generate_session_handle(&self, session_type: TpmSe) -> Result<u32, TpmRc> {
        let handle_prefix = match session_type {
            TpmSe::HMAC => 0x02000000,
            TpmSe::Policy => 0x03000000,
            TpmSe::Trial => 0x03000000,
        };

        for offset in 0..TPM2_MAX_ACTIVE_SESSIONS {
            let hmac_candidate = 0x02000000 | offset;
            let policy_candidate = 0x03000000 | offset;
            if self.global_state.session(hmac_candidate).is_none()
                && self.global_state.session(policy_candidate).is_none()
                && !self
                    .global_state
                    .saved_sessions
                    .contains(&Some(hmac_candidate))
                && !self
                    .global_state
                    .saved_sessions
                    .contains(&Some(policy_candidate))
            {
                return Ok(handle_prefix | offset);
            }
        }
        Err(TpmRc::SESSION_MEMORY)
    }

    /// Derives the cryptographic session key from bind auth and decrypted salt using KDFa,
    /// aligned with the requested hash algorithm and symmetric parameters.
    #[allow(clippy::too_many_arguments)]
    fn derive_session_key(
        &self,
        session_type: TpmSe,
        tpm_key: Handle,
        bind: Handle,
        bind_auth: &[u8],
        decrypted_salt: &[u8],
        auth_hash: TpmiAlgHash,
        nonce_tpm: &Tpm2bNonce,
        nonce_caller: &Tpm2bNonce,
        _symmetric: &Option<tpm2::TpmtSymDef>,
    ) -> Result<([u8; 128], usize), TpmRc> {
        if session_type != TpmSe::Trial && (tpm_key != Handle::RH_NULL || bind != Handle::RH_NULL) {
            let bind_auth_len = bind_auth.len();
            let decrypted_salt_len = decrypted_salt.len();
            let secret_len = bind_auth_len + decrypted_salt_len;
            if secret_len > 128 {
                return Err(TpmRc::FAILURE);
            }
            let mut secret = [0u8; 128];
            secret[..bind_auth_len].copy_from_slice(bind_auth);
            secret[bind_auth_len..secret_len].copy_from_slice(decrypted_salt);

            let auth_hash_digest_size = auth_hash.digest_size();

            let session_key_bits = (auth_hash_digest_size as u32) * 8;
            let derived_key_len = (session_key_bits.div_ceil(8)) as usize;
            if derived_key_len > 128 {
                return Err(TpmRc::FAILURE);
            }
            let mut derived_key = [0u8; 128];

            kdfa(
                self.crypto(),
                auth_hash,
                &secret[..secret_len],
                b"ATH",
                nonce_tpm.get_buffer(),
                nonce_caller.get_buffer(),
                session_key_bits,
                &mut derived_key[..derived_key_len],
            )
            .map_err(|_| TpmRc::FAILURE)?;

            Ok((derived_key, derived_key_len))
        } else {
            Ok(([0u8; 128], 0))
        }
    }

    /// Handles the [TpmCc::PolicyCommandCode] (`0x16C`) command.
    ///
    /// # Description
    /// This command binds a requirement to the policy session that it can only be used to authorize
    /// a command with the specified command code (`code`).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 23.11 (TPM2_PolicyCommandCode).
    ///
    /// # Relationships
    /// - Extends the policy digest of an active policy session created via [TpmCc::StartAuthSession](session.rs).
    pub fn policy_command_code(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal::<tpm2::commands::PolicyCommandCodeHandles>()?;
        let mut session_responses = [TpmsAuthResponse::default(); 3];
        let num_sessions =
            self.parse_auth_sessions_for_start_session(&mut request, &mut session_responses)?;
        let cmd = request.try_unmarshal::<tpm2::commands::PolicyCommandCode>()?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Retrieve session state details.
        let session_handle = handles.policy_session.0;
        let (auth_hash, policy_digest, policy_digest_len) = {
            let session_state = self
                .global_state
                .session(session_handle)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;
            if session_state.session_type != TpmSe::Policy
                && session_state.session_type != TpmSe::Trial
            {
                return Err(TpmRc::VALUE.with(Position::handle(1)));
            }
            // 2. A different command code must not already be set
            //    (`TPM_RCS_VALUE + RC_PolicyCommandCode_code`).
            if session_state.command_code != 0 && session_state.command_code != cmd.code.code() {
                return Err(TpmRc::VALUE.with(Position::parameter(1)));
            }
            (
                session_state.auth_hash,
                session_state.policy_digest,
                session_state.policy_digest_len,
            )
        };

        // 3. The code must be implemented (`TPM_RCS_POLICY_CC + RC_PolicyCommandCode_code`).
        //    Checked after the command code conflict, as in C `TPM2_PolicyCommandCode`.
        if !crate::engine::is_command_supported(cmd.code) {
            return Err(TpmRc::POLICY_CC.with(Position::parameter(1)));
        }

        // 5. Update policy digest.
        let mut updates = [0u8; 128];
        let mut offset = 0;
        if policy_digest_len > 0 {
            updates[..policy_digest_len].copy_from_slice(&policy_digest[..policy_digest_len]);
            offset += policy_digest_len;
        }
        let cc_val = tpm2::TpmCc::PolicyCommandCode.code();
        updates[offset..offset + 4].copy_from_slice(&cc_val.to_be_bytes());
        offset += 4;
        updates[offset..offset + 4].copy_from_slice(&cmd.code.code().to_be_bytes());
        offset += 4;

        let mut new_digest = [0u8; 64];
        let new_digest_len = compute_hash(
            self.crypto(),
            auth_hash,
            &updates[..offset],
            &mut new_digest,
        )?;

        // Now mutate the session state.
        {
            let session_state = self
                .global_state
                .session_mut(session_handle)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;
            session_state.policy_digest[..new_digest_len]
                .copy_from_slice(&new_digest[..new_digest_len]);
            session_state.policy_digest_len = new_digest_len;
            session_state.command_code = cmd.code.code();
        }

        let response = request.into_response();
        self.write_response_all(response, &(), &(), &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::PolicyGetDigest] (`0x18A`) command.
    ///
    /// # Description
    /// This command returns the current policy digest value of the active policy session.
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 23.19 (TPM2_PolicyGetDigest).
    ///
    /// # Relationships
    /// - Reads the accumulated policy digest of a session created via [TpmCc::StartAuthSession](session.rs).
    pub fn policy_get_digest(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal::<tpm2::commands::PolicyGetDigestHandles>()?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        // 1. Retrieve session state.
        let session_handle = handles.policy_session.0;
        let global_state = &self.global_state;
        let session_state = global_state
            .session(session_handle)
            .ok_or(TpmRc::VALUE.with(Position::handle(1)))?;

        // 2. Verify session type is Policy.
        if session_state.session_type != TpmSe::Policy && session_state.session_type != TpmSe::Trial
        {
            return Err(TpmRc::VALUE.with(Position::handle(1)));
        }

        // 3. Construct response.
        let policy_digest = tpm2::Tpm2bDigest::from_bytes(
            &session_state.policy_digest[..session_state.policy_digest_len],
        )
        .map_err(|_| TpmRc::FAILURE)?;
        let rsp = tpm2::commands::responses::PolicyGetDigest { policy_digest };

        let response = request.into_response();
        self.write_response_all(response, &(), &rsp, &session_responses[..num_sessions])?;
        Ok(())
    }

    /// Handles the [TpmCc::PolicyRestart] (`0x13F`) command.
    ///
    /// # Description
    /// This command resets the policy digest of the active session back to the zero digest and clears
    /// any bound constraints (such as cpHash, nameHash, or authValue requirement flags).
    ///
    /// # Spec Citation
    /// TCG TPM 2.0 Library Specification, Part 3: Commands, Section 11.2 (TPM2_PolicyRestart).
    ///
    /// # Relationships
    /// - Resets a policy session started by [TpmCc::StartAuthSession](session.rs).
    /// - Allows reusing an existing policy session handle for a fresh policy evaluation.
    pub fn policy_restart(
        &mut self,
        request_response: RequestThenResponse<'_, '_>,
    ) -> Result<(), TpmRc> {
        let mut request = request_response;
        let handles = request.try_unmarshal::<PolicyRestartHandles>()?;
        let (session_responses, num_sessions) = self.parse_and_validate_sessions(&mut request)?;

        let _cmd = request.try_unmarshal::<PolicyRestart>()?;
        if request.remaining_bytes() != 0 {
            return Err(TpmRc::SIZE.to_rc());
        }

        let session_handle = handles.session_handle.0;

        let auth_hash = {
            let session_state = self
                .global_state
                .session(session_handle)
                .ok_or(TpmRc::REFERENCE_H0)?;
            if session_state.session_type != TpmSe::Policy
                && session_state.session_type != TpmSe::Trial
            {
                return Err(TpmRc::VALUE.with(Position::handle(1)));
            }
            session_state.auth_hash
        };

        let auth_hash_digest_size = auth_hash.digest_size();

        // Mutate session state to initial state
        {
            let session_state = self
                .global_state
                .session_mut(session_handle)
                .ok_or(TpmRc::HANDLE.with(Position::handle(1)))?;

            session_state.policy_digest = [0u8; 64];
            session_state.policy_digest_len = auth_hash_digest_size;
            session_state.command_code = 0;
            session_state.is_auth_value_needed = false;
            session_state.is_password_needed = false;
            session_state.is_cp_hash_defined = false;
            session_state.is_name_hash_defined = false;
            session_state.is_template_hash_defined = false;
            // `u1.cpHash.b.size = 0` and `timeout = 0` in C `SessionResetPolicyData`.
            session_state.policy_hash = [0u8; 64];
            session_state.policy_hash_len = 0;
            session_state.timeout = 0;
            session_state.check_nv_written = false;
            session_state.nv_written_state = false;
            session_state.pcr_counter = None;
            session_state.command_locality = 0;
        }

        let response = request.into_response();
        self.write_response_all(response, &(), &(), &session_responses[..num_sessions])?;
        Ok(())
    }
}

/// Computes the bind value of an entity, as `SessionComputeBoundEntity` does in the C reference
/// (Session.c).
///
/// The entity Name is zero-padded to `sizeof(TPMU_NAME)` ([tpm2::Tpm2bName::CAP], 66 bytes when
/// SHA-512 is implemented) and the (trailing-zero-stripped) authValue is XORed into the last bytes
/// of that buffer. The result always has the full buffer size, so Names of every implemented
/// `nameAlg` (including 66-byte SHA-512 Names) are supported.
///
/// Used both when a session is bound in `TPM2_StartAuthSession` and when deciding whether an
/// authorized entity is the bind entity of an HMAC session (`IsSessionBindEntity`).
///
/// # Errors
/// Returns [TpmRc::FAILURE] if `name` or `auth` is larger than the bind buffer (cannot happen for
/// well-formed Names and authValues).
pub(crate) fn compute_bound_entity(
    name: &[u8],
    auth: &[u8],
) -> Result<crate::owned::OwnedName, TpmRc> {
    const BIND_SIZE: usize = tpm2::Tpm2bName::CAP;
    if name.len() > BIND_SIZE || auth.len() > BIND_SIZE {
        return Err(TpmRc::FAILURE);
    }
    let mut bind = [0u8; BIND_SIZE];
    bind[..name.len()].copy_from_slice(name);
    for (dst, src) in bind[BIND_SIZE - auth.len()..].iter_mut().zip(auth) {
        *dst ^= *src;
    }
    crate::owned::OwnedName::from_bytes(&bind).map_err(|_| TpmRc::FAILURE)
}

fn compute_hash<C: CryptoProvider>(
    crypto: &C,
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
