use crate::test_utils::marshal_to_slice;
use crate::test_utils::{
    ActiveSession, CmdHeader, RespHeader, execute_with_password_sessions, map_sessions_to_handles,
    start_auth_session, strip_trailing_zeros,
};
use sha2::{Digest as _, Sha256};
use tpm2::commands::{
    CreatePrimary, CreatePrimaryHandles, GetRandom, GetTime, GetTimeHandles, HierarchyChangeAuth,
    LoadExternal,
};
use tpm2::crypto::Rng;
use tpm2::{Handle, TpmSe, TpmSt};
use tpm2::{Marshal, Unmarshal};
use tpm2::{
    Tpm2bAuth, Tpm2bDigest, Tpm2bNonce, Tpm2bSensitiveData, TpmaObject, TpmaSession, TpmiAlgHash,
    TpmiAlgSymMode, TpmiStCommandTag, TpmsAuthCommand, TpmsAuthResponse, TpmsSensitiveCreate,
    TpmtPublic, TpmtSensitive, TpmtSymDefObject, TpmuSensitiveComposite,
};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

fn reference_kdfa<H: tpm2::crypto::Hmac>(
    crypto: &H,
    auth_hash: TpmiAlgHash,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    bits: u32,
) -> Vec<u8>
where
    H::Error: core::fmt::Debug,
{
    let required_bytes = bits.div_ceil(8) as usize;
    let mut out = vec![0u8; required_bytes];
    let mut counter = 1u32;
    let mut generated = 0;
    while generated < required_bytes {
        let mut state = tpm2::crypto::HmacCtx::new(crypto, auth_hash, key).unwrap();
        state.update(&counter.to_be_bytes()).unwrap();
        state.update(label).unwrap();
        state.update(&[0x00]).unwrap();
        state.update(context_u).unwrap();
        state.update(context_v).unwrap();
        state.update(&bits.to_be_bytes()).unwrap();
        let mut mac_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
        let digest = state.finalize(&mut mac_buf).unwrap();
        let mac = digest.digest();
        let to_copy = std::cmp::min(mac.len(), required_bytes - generated);
        out[generated..generated + to_copy].copy_from_slice(&mac[..to_copy]);
        generated += to_copy;
        counter += 1;
    }
    out
}

fn derive_key_and_iv_ref<H: tpm2::crypto::Hmac>(
    crypto: &H,
    auth_hash: TpmiAlgHash,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    key_size_bytes: usize,
) -> (Vec<u8>, [u8; 16])
where
    H::Error: core::fmt::Debug,
{
    let total_bytes = key_size_bytes + 16;
    let total_bits = (total_bytes * 8) as u32;
    let out_buffer = reference_kdfa(
        crypto, auth_hash, key, label, context_u, context_v, total_bits,
    );
    let derived_key = out_buffer[..key_size_bytes].to_vec();
    let mut derived_iv = [0u8; 16];
    derived_iv.copy_from_slice(&out_buffer[key_size_bytes..]);
    (derived_key, derived_iv)
}

fn compute_client_hash<H: tpm2::crypto::Hash>(
    crypto: &H,
    auth_hash: TpmiAlgHash,
    updates: &[&[u8]],
) -> Vec<u8>
where
    H::Error: core::fmt::Debug,
{
    let mut state = tpm2::crypto::HashCtx::new(crypto, auth_hash).unwrap();
    for data in updates {
        state.update(data).unwrap();
    }
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    state.finalize(&mut out).unwrap().digest().to_vec()
}

fn compute_client_hmac<H: tpm2::crypto::Hmac>(
    crypto: &H,
    auth_hash: TpmiAlgHash,
    key: &[u8],
    updates: &[&[u8]],
) -> Vec<u8>
where
    H::Error: core::fmt::Debug,
{
    let mut state = tpm2::crypto::HmacCtx::new(crypto, auth_hash, key).unwrap();
    for data in updates {
        state.update(data).unwrap();
    }
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    state.finalize(&mut out).unwrap().digest().to_vec()
}

pub fn execute_with_hmac_sessions_custom_raw<CmdT: tpm2::commands::Command>(
    tpm: &mut Simulator<'_>,
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    sessions: &mut [ActiveSession],
    entity_auths: &[&[u8]],
) -> Result<(Vec<u8>, CmdT::RespHandles), u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut cmd_buffer = [0u8; 4096];
    let mut cmd_header = CmdHeader {
        tag: if sessions.is_empty() {
            TpmiStCommandTag::NoSessions
        } else {
            TpmiStCommandTag::Sessions
        },
        size: 0,
        code: CmdT::CMD_CODE,
    };

    let mut written = cmd_header.marshal((&mut cmd_buffer[0..10]).try_into().unwrap());
    written += marshal_to_slice(&(cmd_handles), &mut cmd_buffer[written..]);

    let session_size_pos = written;
    if !sessions.is_empty() {
        written += 4; // Reserve space for sessionSize
    }

    let sessions_start_pos = written;

    let num_handles = (session_size_pos - 10) / 4;
    let mut handles = Vec::new();
    for idx in 0..num_handles {
        let handle_bytes = [
            cmd_buffer[10 + idx * 4],
            cmd_buffer[11 + idx * 4],
            cmd_buffer[12 + idx * 4],
            cmd_buffer[13 + idx * 4],
        ];
        handles.push(Handle(u32::from_be_bytes(handle_bytes)));
    }

    let (session_to_handle_idx, session_to_handle_idx_len) =
        map_sessions_to_handles(CmdT::CMD_CODE, &handles, sessions.len());
    let mut command_handle_names = Vec::new();
    for i in 0..num_handles {
        let handle_bytes = [
            cmd_buffer[10 + i * 4],
            cmd_buffer[11 + i * 4],
            cmd_buffer[12 + i * 4],
            cmd_buffer[13 + i * 4],
        ];
        let handle = u32::from_be_bytes(handle_bytes);
        let mut name = Vec::new();
        let global_state = &tpm.global_state;
        let mut found = false;
        for obj in global_state.transient_objects.iter().flatten() {
            if obj.handle == handle {
                name = obj.name.get_buffer().to_vec();
                found = true;
                break;
            }
        }
        if !found {
            name = handle.to_be_bytes().to_vec();
        }
        command_handle_names.push(name);
    }

    // Generate new nonces and encrypt first parameter if needed
    let mut param_buf = [0u8; 4096];
    let param_len = marshal_to_slice(cmd, &mut param_buf);

    let mut nonce_callers_new = Vec::new();
    let mut decrypt_session_idx = None;
    let mut encrypt_session_idx = None;

    for (i, session) in sessions.iter_mut().enumerate() {
        let mut nonce_bytes = [0u8; 16];
        tpm.context
            .platform
            .crypto
            .get_random(&mut nonce_bytes)
            .unwrap();
        let nonce_caller_new =
            Tpm2bNonce::from_bytes(crate::test_utils::leak_bytes(&nonce_bytes)).unwrap();
        nonce_callers_new.push(nonce_caller_new);

        if session.attributes.contains(TpmaSession::DECRYPT) {
            decrypt_session_idx = Some(i);
        }
        if session.attributes.contains(TpmaSession::ENCRYPT) {
            encrypt_session_idx = Some(i);
        }
    }

    // Encrypt parameter if decrypt session is active
    if let Some(idx) = decrypt_session_idx {
        let session = &sessions[idx];
        let nonce_caller_new = &nonce_callers_new[idx];

        let leading_size = 2; // only 2B is supported
        let size = u16::from_be_bytes([param_buf[0], param_buf[1]]) as usize;

        let bits = match &session.symmetric {
            Some(TpmtSymDefObject::Aes128(_)) => 128 + 128,
            Some(TpmtSymDefObject::Aes256(_)) => 256 + 128,
            _ => 0,
        };

        if bits > 0 {
            let key = if idx < num_handles {
                [
                    session.session_key.as_slice(),
                    strip_trailing_zeros(entity_auths[idx]),
                ]
                .concat()
            } else {
                session.session_key.clone()
            };
            let (derived_key, derived_iv) = derive_key_and_iv_ref(
                tpm.context.platform.crypto,
                session.auth_hash,
                &key,
                b"CFB",
                nonce_caller_new.get_buffer(),
                session.nonce_tpm.get_buffer(),
                ((bits - 128) / 8) as usize,
            );

            let mut iv = derived_iv;
            let sym_alg = tpm2::TpmtSymDefObject::aes_cfb((derived_key.len() * 8) as u16).unwrap();
            tpm2::crypto::encrypt(
                tpm.context.platform.crypto,
                sym_alg,
                &derived_key,
                &mut iv,
                &mut param_buf[leading_size..leading_size + size],
            )
            .unwrap();
        }
    }

    // Build auth commands (HMACs)
    let mut auth_written = 0;
    let mut auth_buffer = [0u8; 1024];

    for (i, session) in sessions.iter().enumerate() {
        let auth_hash = session.auth_hash;
        let mut cp_hash_updates = Vec::new();
        let cmd_code_bytes = (CmdT::CMD_CODE.code()).to_be_bytes();
        cp_hash_updates.push(cmd_code_bytes.as_slice());
        for name in &command_handle_names {
            cp_hash_updates.push(name.as_slice());
        }
        let param_bytes = &param_buf[..param_len];
        cp_hash_updates.push(param_bytes);

        let cp_hash = compute_client_hash(tpm.context.platform.crypto, auth_hash, &cp_hash_updates);

        let nonce_caller_new = &nonce_callers_new[i];
        let entity_auth = if i < num_handles {
            entity_auths[i]
        } else {
            &[]
        };
        let is_bound = if session.bind_entity != Handle::RH_NULL {
            if i < session_to_handle_idx_len {
                let h_idx = session_to_handle_idx[i];
                let h = handles[h_idx];
                session.bind_entity == h
            } else {
                false
            }
        } else {
            false
        };

        let hmac_key = if is_bound {
            session.session_key.clone()
        } else {
            [
                session.session_key.as_slice(),
                strip_trailing_zeros(entity_auth),
            ]
            .concat()
        };

        let mut hmac_updates = Vec::new();
        hmac_updates.push(cp_hash.as_slice());
        hmac_updates.push(nonce_caller_new.get_buffer());
        hmac_updates.push(session.nonce_tpm.get_buffer());

        if i == 0 {
            if let Some(dec_idx) = decrypt_session_idx {
                if dec_idx != i {
                    hmac_updates.push(sessions[dec_idx].nonce_tpm.get_buffer());
                }
            }
            if let Some(enc_idx) = encrypt_session_idx {
                if enc_idx != i && Some(enc_idx) != decrypt_session_idx {
                    hmac_updates.push(sessions[enc_idx].nonce_tpm.get_buffer());
                }
            }
        }

        let attr_byte = [session.attributes.bits()];
        hmac_updates.push(&attr_byte);

        let hmac_bytes = compute_client_hmac(
            tpm.context.platform.crypto,
            auth_hash,
            &hmac_key,
            &hmac_updates,
        );
        let hmac_val = Tpm2bAuth::from_bytes(&hmac_bytes).unwrap();

        let auth_cmd = TpmsAuthCommand {
            session_handle: Handle(session.session_handle.0),
            nonce: *nonce_caller_new,
            session_attributes: session.attributes,
            hmac: hmac_val,
        };

        auth_written += marshal_to_slice(&(auth_cmd), &mut auth_buffer[auth_written..]);
    }

    // Marshal sessions into cmd_buffer
    if !sessions.is_empty() {
        let size_u32 = auth_written as u32;
        marshal_to_slice(&(size_u32), &mut cmd_buffer[session_size_pos..]);
        cmd_buffer[sessions_start_pos..sessions_start_pos + auth_written]
            .copy_from_slice(&auth_buffer[..auth_written]);
        written = sessions_start_pos + auth_written;
    }

    // Marshal parameters
    cmd_buffer[written..written + param_len].copy_from_slice(&param_buf[..param_len]);
    written += param_len;

    // Update commandSize in header
    cmd_header.size = written as u32;
    let mut header_buf = [0u8; 10];
    cmd_header.marshal(&mut header_buf);
    cmd_buffer[..10].copy_from_slice(&header_buf[..10]);

    // Transact
    let mut resp_buffer = [0u8; 4096];
    let resp_bytes = tpm
        .transact(&cmd_buffer[..written], &mut resp_buffer)
        .unwrap();

    // Parse response
    let mut unmarsh: &'static [u8] = crate::test_utils::leak_bytes(resp_bytes);
    let resp_header = RespHeader::unmarshal(&mut unmarsh).unwrap();
    if resp_header.rc != 0 {
        return Err(resp_header.rc);
    }

    let resp_handles = CmdT::RespHandles::unmarshal(&mut unmarsh).unwrap();

    let mut parameter_size = 0;
    if resp_header.tag == TpmSt::SESSIONS {
        parameter_size = u32::unmarshal(&mut unmarsh).unwrap() as usize;
    }
    // Get parameters slice
    let (encrypted_param_buf, rest) = unmarsh.split_at(parameter_size);
    unmarsh = rest;

    // The remaining bytes in unmarsh are the response sessions
    let mut unmarsh_sess: &[u8] = unmarsh;

    let mut nonce_tpms_new = Vec::new();
    let mut resp_attributes = Vec::new();
    let mut resp_hmacs = Vec::new();

    for _ in 0..sessions.len() {
        let auth_resp = TpmsAuthResponse::unmarshal(&mut unmarsh_sess).unwrap();
        nonce_tpms_new.push(auth_resp.nonce);
        resp_attributes.push(auth_resp.session_attributes);
        resp_hmacs.push(auth_resp.hmac);
    }

    // Decrypt parameters if encrypt session is active
    let mut decrypted_param_buf = encrypted_param_buf.to_vec();
    if let Some(idx) = encrypt_session_idx {
        if !decrypted_param_buf.is_empty() {
            let session = &sessions[idx];
            let nonce_tpm_new = &nonce_tpms_new[idx];
            let nonce_caller_new = &nonce_callers_new[idx];

            let leading_size = 2;
            let size =
                u16::from_be_bytes([decrypted_param_buf[0], decrypted_param_buf[1]]) as usize;

            let bits = match &session.symmetric {
                Some(TpmtSymDefObject::Aes128(_)) => 128 + 128,
                Some(TpmtSymDefObject::Aes256(_)) => 256 + 128,
                _ => 0,
            };

            if bits > 0 {
                let key = if idx < num_handles {
                    [
                        session.session_key.as_slice(),
                        strip_trailing_zeros(entity_auths[idx]),
                    ]
                    .concat()
                } else {
                    session.session_key.clone()
                };
                let (derived_key, derived_iv) = derive_key_and_iv_ref(
                    tpm.context.platform.crypto,
                    session.auth_hash,
                    &key,
                    b"CFB",
                    nonce_tpm_new.get_buffer(),
                    nonce_caller_new.get_buffer(),
                    ((bits - 128) / 8) as usize,
                );

                let mut iv = derived_iv;
                let sym_alg =
                    tpm2::TpmtSymDefObject::aes_cfb((derived_key.len() * 8) as u16).unwrap();
                tpm2::crypto::decrypt(
                    tpm.context.platform.crypto,
                    sym_alg,
                    &derived_key,
                    &mut iv,
                    &mut decrypted_param_buf[leading_size..leading_size + size],
                )
                .unwrap();
            }
        }
    }

    // Update active sessions state for the caller
    for (i, session) in sessions.iter_mut().enumerate() {
        session.nonce_caller = nonce_callers_new[i];
        session.nonce_tpm = nonce_tpms_new[i];
    }

    Ok((decrypted_param_buf, resp_handles))
}

pub fn execute_with_hmac_sessions_custom_status<CmdT: tpm2::commands::Command>(
    tpm: &mut Simulator<'_>,
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    sessions: &mut [ActiveSession],
    entity_auths: &[&[u8]],
) -> Result<CmdT::RespHandles, u32>
where
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    execute_with_hmac_sessions_custom_raw(tpm, cmd, cmd_handles, sessions, entity_auths)
        .map(|(_, h)| h)
}

pub fn execute_with_hmac_sessions_custom<CmdT: tpm2::commands::Command>(
    tpm: &mut Simulator<'_>,
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    sessions: &mut [ActiveSession],
    entity_auths: &[&[u8]],
) -> Result<(CmdT::Response<'static>, CmdT::RespHandles), u32>
where
    CmdT::Response<'static>: Unmarshal<'static>,
    for<'b> &'b mut CmdT::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <CmdT::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let (buf, handles) =
        execute_with_hmac_sessions_custom_raw(tpm, cmd, cmd_handles, sessions, entity_auths)?;
    let mut resp_unmarsh: &'static [u8] = crate::test_utils::leak_bytes(&buf);
    let resp_struct = <CmdT::Response<'static>>::unmarshal(&mut resp_unmarsh).unwrap();
    Ok((resp_struct, handles))
}

#[test]
fn test_param_crypt_stress_differential() {
    let algs = [
        (TpmiAlgHash::Sha256, 128),
        (TpmiAlgHash::Sha256, 256),
        (TpmiAlgHash::Sha384, 128),
        (TpmiAlgHash::Sha384, 256),
        (TpmiAlgHash::Sha512, 128),
        (TpmiAlgHash::Sha512, 256),
    ];

    let sizes = [0, 1, 4, 15, 16, 17, 31, 32];

    for &(hash_alg, aes_bits) in &algs {
        for &size in &sizes {
            println!(
                "RUNNING: hash={:?} aes={} size={}",
                hash_alg, aes_bits, size
            );
            let mut sim = create_simulator!();

            let sym_def = match aes_bits {
                128 => Some(tpm2::TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                256 => Some(tpm2::TpmtSymDefObject::Aes256(Some(TpmiAlgSymMode::CFB))),
                _ => None,
            };

            let session = match start_auth_session(
                &mut sim,
                Handle::RH_NULL,
                Handle::RH_NULL,
                &[],
                TpmSe::HMAC,
                sym_def,
                hash_alg,
            ) {
                Ok(s) => s,
                Err(e) => {
                    // If SHA384/SHA512 is not supported, we skip it
                    if hash_alg == TpmiAlgHash::Sha384 || hash_alg == TpmiAlgHash::Sha512 {
                        println!("SKIPPED hash={:?} (not supported by simulator)", hash_alg);
                        continue;
                    }
                    panic!("failed to start session: {:?}", e);
                }
            };

            let mut sessions = [session];

            // 1. Stress Test Parameter Decryption via HierarchyChangeAuth
            sessions[0].attributes = TpmaSession::DECRYPT | TpmaSession::CONTINUE_SESSION;
            let new_auth_data = vec![0xEEu8; size];

            let cmd = HierarchyChangeAuth {
                new_auth: Tpm2bAuth::from_bytes(&new_auth_data).unwrap(),
            };
            let cmd_handles = tpm2::commands::HierarchyChangeAuthHandles {
                auth_handle: Handle::RH_OWNER,
            };

            let result = execute_with_hmac_sessions_custom(
                &mut sim,
                &cmd,
                cmd_handles,
                &mut sessions,
                &[&[]],
            );

            assert!(
                result.is_ok(),
                "HierarchyChangeAuth failed for hash {:?} aes_bits {} size {} with error {:?}",
                hash_alg,
                aes_bits,
                size,
                result.err()
            );
            let (_, _) = result.unwrap();

            // 2. Stress Test Response Encryption via GetRandom
            // session has updated nonces internally
            sessions[0].attributes = TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;

            let get_random_cmd = GetRandom {
                bytes_requested: size as u16,
            };

            let result = execute_with_hmac_sessions_custom(
                &mut sim,
                &get_random_cmd,
                (),
                &mut sessions,
                &[&[]],
            );

            assert!(
                result.is_ok(),
                "GetRandom failed for hash {:?} aes_bits {} size {} with error {:?}",
                hash_alg,
                aes_bits,
                size,
                result.err()
            );

            let (resp, _) = result.unwrap();
            assert_eq!(resp.random_bytes.as_ref().len(), size);
        }
    }
}

// Helper to create a keyed hash public area
fn make_keyed_hash_public_area_local(unique: &[u8], attrs: TpmaObject) -> TpmtPublic<'static> {
    let mut actual_unique = unique.to_vec();
    if unique == [0x11; 32] {
        let mut hasher = Sha256::new();
        hasher.update([]);
        hasher.update([]);
        actual_unique = hasher.finalize().to_vec();
    }
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: tpm2::PublicParmsAndId::KeyedHash(
            None,
            Tpm2bDigest::from_bytes(crate::test_utils::leak_bytes(&actual_unique)).unwrap(),
        ),
    }
}

#[test]
fn test_parameter_decryption_no_auth_handle() {
    let mut sim = create_simulator!();

    // Start an HMAC session with AES-128-CFB
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let mut sessions = [session];
    sessions[0].attributes = TpmaSession::DECRYPT | TpmaSession::CONTINUE_SESSION;

    // Prepare LoadExternal which has NO handles
    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::KeyedHash(Tpm2bSensitiveData::default()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area_local(
        &[0x11; 32],
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };

    // Execute command with DECRYPT attribute session.
    // KDFa key derivation should correctly use Empty Auth because there are no handles.
    let result = execute_with_hmac_sessions_custom(&mut sim, &cmd, (), &mut sessions, &[&[]]);

    assert!(
        result.is_ok(),
        "LoadExternal failed with DECRYPT session: {:?}",
        result.err()
    );
}

#[test]
fn test_multiple_decrypt_attributes_fails() {
    let mut sim = create_simulator!();

    let sess1 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let sess2 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let mut sessions = [sess1, sess2];
    // Set DECRYPT on BOTH sessions (which is invalid, only the first session can have DECRYPT)
    sessions[0].attributes = TpmaSession::DECRYPT | TpmaSession::CONTINUE_SESSION;
    sessions[1].attributes = TpmaSession::DECRYPT | TpmaSession::CONTINUE_SESSION;

    let sensitive_create = TpmtSensitive {
        auth_value: Tpm2bAuth::default(),
        seed_value: Tpm2bDigest::default(),
        sensitive: TpmuSensitiveComposite::KeyedHash(Tpm2bSensitiveData::default()),
    };
    let in_private = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(make_keyed_hash_public_area_local(
        &[0x11; 32],
        TpmaObject::SIGN_ENCRYPT,
    ));
    let cmd = LoadExternal {
        in_private: Some(in_private),
        in_public: in_public.into(),
        hierarchy: Handle::RH_NULL,
    };
    let result = execute_with_hmac_sessions_custom(&mut sim, &cmd, (), &mut sessions, &[&[], &[]]);

    assert!(result.is_err());
    let err = result.err().unwrap();
    assert_eq!(err & 0xFF, 0x82, "Expected Attributes error, got {:X}", err);
    assert_eq!(
        (err >> 8) & 0xF,
        10,
        "Expected error on session 2 (PosA/10), got {:X}",
        err
    );
}

#[test]
fn test_multiple_encrypt_attributes_fails() {
    let mut sim = create_simulator!();

    let sess1 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let sess2 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let mut sessions = [sess1, sess2];
    sessions[0].attributes = TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;
    sessions[1].attributes = TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;

    let cmd = GetRandom { bytes_requested: 8 };
    let result = execute_with_hmac_sessions_custom(&mut sim, &cmd, (), &mut sessions, &[&[], &[]]);

    assert!(result.is_err());
    let err = result.err().unwrap();
    assert_eq!(err & 0xFF, 0x82, "Expected Attributes error, got {:X}", err);
    assert_eq!(
        (err >> 8) & 0xF,
        10,
        "Expected error on session 2 (PosA/10), got {:X}",
        err
    );
}

#[test]
fn test_session_encrypt_null_symmetric_fails() {
    let mut sim = create_simulator!();

    // Start session with Null symmetric parameters
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let mut sessions = [session];
    sessions[0].attributes = TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;

    let cmd = GetRandom { bytes_requested: 8 };
    let result = execute_with_hmac_sessions_custom(&mut sim, &cmd, (), &mut sessions, &[&[]]);

    assert!(result.is_err());
    let err = result.err().unwrap();
    assert_eq!(
        err & 0xFF,
        0x96,
        "Expected Symmetric error (0x96), got {:X}",
        err
    );
}

#[test]
fn test_encrypt_on_third_session_of_multi_session_command() {
    let mut sim = create_simulator!();

    let sess1 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let sess2 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let sess3 = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let mut sessions = [sess1, sess2, sess3];
    // Session 3 has ENCRYPT
    sessions[0].attributes = TpmaSession::CONTINUE_SESSION;
    sessions[1].attributes = TpmaSession::CONTINUE_SESSION;
    sessions[2].attributes = TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;

    let cmd = GetRandom { bytes_requested: 8 };
    let result =
        execute_with_hmac_sessions_custom(&mut sim, &cmd, (), &mut sessions, &[&[], &[], &[]]);

    assert!(
        result.is_ok(),
        "GetRandom with encrypt on 3rd session failed: {:?}",
        result.err()
    );
    let (resp, _) = result.unwrap();
    assert_eq!(resp.random_bytes.as_ref().len(), 8);
}

#[test]
fn test_response_encrypt_index_alignment_get_time() {
    let mut sim = create_simulator!();

    // 1. Create a primary signing key with non-empty auth
    let rsa_parms = tpm2::TpmsRsaParms {
        symmetric: None,
        scheme: Some(tpm2::TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
        key_bits: tpm2::TpmiRsaKeyBits(2048),
        exponent: 0,
    };
    let pub_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SIGN_ENCRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: tpm2::PublicParmsAndId::Rsa(rsa_parms, tpm2::Tpm2bPublicKeyRsa::default()),
    };
    let in_public = tpm2::Tpm2b(pub_area);
    let key_auth = b"keyauth";
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(key_auth).unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);

    let create_cmd = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let (_, create_rsp_handles) =
        execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 0, &[]).unwrap();
    let sign_handle = create_rsp_handles.object_handle;

    // 2. Start an unbound session for RH_ENDORSEMENT and a session bound to the signing key
    let admin_session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        None,
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    // We bind to the signing key so that we can use HMAC authorization with the key's auth
    let session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        sign_handle,
        key_auth,
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();

    let mut sessions = [admin_session, session];
    sessions[0].attributes = TpmaSession::CONTINUE_SESSION;
    sessions[1].attributes = TpmaSession::ENCRYPT | TpmaSession::CONTINUE_SESSION;

    // 3. Execute GetTime
    // Handles: privacy_admin_handle = RH_ENDORSEMENT (index 0, auth required), sign_handle (index 1, auth required)
    // Sessions: session 0 authorizes RH_ENDORSEMENT, session 1 (with ENCRYPT) authorizes sign_handle using key_auth.
    let cmd = GetTime {
        qualifying_data: tpm2::Tpm2bData::default(),
        in_scheme: None,
    };
    let cmd_handles = GetTimeHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle,
    };

    let result = execute_with_hmac_sessions_custom_status(
        &mut sim,
        &cmd,
        cmd_handles,
        &mut sessions,
        &[&[], key_auth],
    );

    assert!(result.is_ok(), "GetTime failed: {:?}", result.err());
}
