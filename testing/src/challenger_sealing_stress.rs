#![forbid(unsafe_code)]
use crate::test_utils::marshal_to_slice;
use crate::test_utils::{CLIENT_CRYPTO, entity_name, max_loaded_sessions};

use crate::test_utils::{
    ActiveSession, CmdHeader, RespHeader, execute_with_password_sessions, map_sessions_to_handles,
    start_auth_session, strip_trailing_zeros,
};
use tpm2::commands::{
    Create, CreateHandles, CreatePrimary, CreatePrimaryHandles, FlushContext, Unseal, UnsealHandles,
};
use tpm2::crypto::Rng;
use tpm2::{Handle, TpmSe, TpmSt};
use tpm2::{Marshal, Unmarshal};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bName, Tpm2bNonce, Tpm2bPublicKeyRsa,
    Tpm2bSensitiveData, TpmaObject, TpmaSession, TpmiAlgHash, TpmiAlgSymMode, TpmiRsaKeyBits,
    TpmiStCommandTag, TpmlPcrSelection, TpmsAuthCommand, TpmsAuthResponse, TpmsRsaParms,
    TpmsSensitiveCreate, TpmtPublic, TpmtSymDefObject,
};
use tpm2_simulator::{Simulator, create_simulator};

// =========================================================================
// Helpers
// =========================================================================

fn get_rsa_srk_template() -> TpmtPublic<'static> {
    TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    }
}

fn create_srk(
    sim: &mut Simulator<'_>,
    srk_template: &TpmtPublic,
    srk_auth: &[u8],
) -> (Handle, Tpm2bName<'static>) {
    let sensitive_create = TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(srk_auth).unwrap(),
        data: Tpm2bSensitiveData::default(),
    };
    let in_sensitive = tpm2::Tpm2b(sensitive_create);
    let in_public = tpm2::Tpm2b(*srk_template);
    let create_primary = CreatePrimary {
        in_sensitive,
        in_public,
        ..Default::default()
    };
    let create_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };

    let (rsp, rsp_handles) =
        execute_with_password_sessions(sim, &create_primary, create_handles, 1, &[])
            .expect("could not call TPM2_CreatePrimary");

    (rsp_handles.object_handle, rsp.name)
}

fn flush_context(tpm: &mut Simulator<'_>, handle: Handle) -> Result<(), u32> {
    let cmd = FlushContext {
        flush_handle: handle,
    };
    execute_with_password_sessions(tpm, &cmd, (), 0, &[]).map(|_| ())
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

// Custom E2E execution helper that allows corrupting ciphertext parameters after encryption
// but before HMAC calculation, to verify correct parsing/unmarshalling failure handling.
fn execute_with_hmac_sessions_corrupt_ciphertext<CmdT: tpm2::commands::Command>(
    tpm: &mut Simulator<'_>,
    cmd: &CmdT,
    cmd_handles: CmdT::Handles,
    sessions: &mut [ActiveSession],
    entity_auths: &[&[u8]],
    corrupt_byte_offset: usize,
) -> Result<(CmdT::Response<'static>, CmdT::RespHandles), u32>
where
    CmdT::Response<'static>: tpm2::Unmarshal<'static>,
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
        written += 4;
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
        let name = entity_name(tpm, Handle(handle));
        command_handle_names.push(name);
    }

    let mut param_buf = [0u8; 4096];
    let param_len = marshal_to_slice(cmd, &mut param_buf);

    let mut nonce_callers_new = Vec::new();
    let mut decrypt_session_idx = None;

    for (i, session) in sessions.iter_mut().enumerate() {
        let mut nonce_bytes = [0u8; 16];
        CLIENT_CRYPTO.get_random(&mut nonce_bytes).unwrap();
        let nonce_caller_new =
            Tpm2bNonce::from_bytes(crate::test_utils::leak_bytes(&nonce_bytes)).unwrap();
        nonce_callers_new.push(nonce_caller_new);

        if session.attributes.contains(TpmaSession::DECRYPT) {
            decrypt_session_idx = Some(i);
        }
    }

    // Encrypt parameter
    if let Some(idx) = decrypt_session_idx {
        let session = &sessions[idx];
        let nonce_caller_new = &nonce_callers_new[idx];

        let leading_size = 2;
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
                CLIENT_CRYPTO,
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
                CLIENT_CRYPTO,
                sym_alg,
                &derived_key,
                &mut iv,
                &mut param_buf[leading_size..leading_size + size],
            )
            .unwrap();
        }
    }

    // Corrupt ciphertext parameter byte
    if param_len > corrupt_byte_offset {
        param_buf[corrupt_byte_offset] ^= 0xFF;
    }

    // Build HMACs using corrupted param_buf (so HMAC verification will PASS, but decryption will yield junk)
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

        let cp_hash = compute_client_hash(CLIENT_CRYPTO, auth_hash, &cp_hash_updates);

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
        let attr_byte = [session.attributes.bits()];
        hmac_updates.push(&attr_byte);

        let hmac_bytes = compute_client_hmac(CLIENT_CRYPTO, auth_hash, &hmac_key, &hmac_updates);
        let hmac_val = Tpm2bAuth::from_bytes(&hmac_bytes).unwrap();

        let auth_cmd = TpmsAuthCommand {
            session_handle: Handle(session.session_handle.0),
            nonce: *nonce_caller_new,
            session_attributes: session.attributes,
            hmac: hmac_val,
        };

        auth_written += marshal_to_slice(&(auth_cmd), &mut auth_buffer[auth_written..]);
    }

    if !sessions.is_empty() {
        let size_u32 = auth_written as u32;
        marshal_to_slice(&(size_u32), &mut cmd_buffer[session_size_pos..]);
        cmd_buffer[sessions_start_pos..sessions_start_pos + auth_written]
            .copy_from_slice(&auth_buffer[..auth_written]);
        written = sessions_start_pos + auth_written;
    }

    cmd_buffer[written..written + param_len].copy_from_slice(&param_buf[..param_len]);
    written += param_len;

    cmd_header.size = written as u32;
    let mut header_buf = [0u8; 10];
    cmd_header.marshal(&mut header_buf);
    cmd_buffer[..10].copy_from_slice(&header_buf[..10]);

    let mut resp_buffer = [0u8; 4096];
    let resp_bytes = tpm
        .transact(&cmd_buffer[..written], &mut resp_buffer)
        .unwrap();

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
    let (encrypted_param_buf, rest) = unmarsh.split_at(parameter_size);
    let mut unmarsh_sess: &[u8] = rest;

    let mut nonce_tpms_new = Vec::new();
    for _ in 0..sessions.len() {
        let auth_resp = TpmsAuthResponse::unmarshal(&mut unmarsh_sess).unwrap();
        nonce_tpms_new.push(auth_resp.nonce);
    }

    for (i, session) in sessions.iter_mut().enumerate() {
        session.nonce_caller = nonce_callers_new[i];
        session.nonce_tpm = nonce_tpms_new[i];
    }

    let mut resp_unmarsh: &'static [u8] = crate::test_utils::leak_bytes(encrypted_param_buf);
    let resp_struct = <CmdT::Response<'static>>::unmarshal(&mut resp_unmarsh).unwrap();

    Ok((resp_struct, resp_handles))
}

// =========================================================================
// Stress Tests
// =========================================================================

#[test]
fn test_sealing_session_exhaustion() {
    let mut sim = create_simulator!();
    let sym_null = None;

    // 1. Start max allowed active sessions in GlobalState
    let mut sessions = Vec::new();
    for _ in 0..max_loaded_sessions(&mut sim) {
        let session = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::HMAC,
            sym_null,
            TpmiAlgHash::Sha256,
        )
        .unwrap();
        sessions.push(session);
    }

    // 2. Try to start another session beyond capacity. It must fail with SessionMemory error (0x903)
    let res = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        sym_null,
        TpmiAlgHash::Sha256,
    );
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert_eq!(err, 0x903); // TPM_RC_SESSION_MEMORY

    // 3. Flush one session (say the first one) to free a slot
    let flushed_handle = sessions[0].session_handle;
    flush_context(&mut sim, flushed_handle).unwrap();

    // 4. Try starting a session again, it must succeed now
    let new_sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        sym_null,
        TpmiAlgHash::Sha256,
    );
    assert!(new_sess.is_ok());
    let new_sess = new_sess.unwrap();

    // 5. Clean up remaining sessions
    for session in sessions.iter().take(4).skip(1) {
        flush_context(&mut sim, session.session_handle).unwrap();
    }
    flush_context(&mut sim, new_sess.session_handle).unwrap();
}

#[test]
fn test_sealing_auth_value_zeros_and_padding() {
    let mut sim = create_simulator!();
    let srk_template = get_rsa_srk_template();
    let srk_auth = b"mySRK";
    let (srk_handle, _) = create_srk(&mut sim, &srk_template, srk_auth);

    // Case A: Empty auth sealing/unsealing
    {
        let data = b"empty_auth_secrets";
        let auth = b"";

        // Create
        let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(auth).unwrap(),
            data: Tpm2bSensitiveData::from_bytes(data).unwrap(),
        });
        let in_public = tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::NO_DA,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        });
        let create_cmd = Create {
            in_sensitive,
            in_public,
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        let create_handles = CreateHandles {
            parent_handle: srk_handle,
        };
        let (create_rsp, _) =
            execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, srk_auth)
                .unwrap();

        // Load
        let load_cmd = tpm2::commands::Load {
            in_private: create_rsp.out_private,
            in_public: create_rsp.out_public,
        };
        let load_handles = tpm2::commands::LoadHandles {
            parent_handle: srk_handle,
        };
        let (_, load_rsp_handles) =
            execute_with_password_sessions(&mut sim, &load_cmd, load_handles, 1, srk_auth).unwrap();

        // Unseal with empty auth
        let unseal_cmd = Unseal {};
        let unseal_handles = UnsealHandles {
            item_handle: load_rsp_handles.object_handle,
        };
        let (unseal_rsp, _) =
            execute_with_password_sessions(&mut sim, &unseal_cmd, unseal_handles, 1, auth).unwrap();
        assert_eq!(unseal_rsp.out_data.get_buffer(), data);

        flush_context(&mut sim, load_rsp_handles.object_handle).unwrap();
    }

    // Case B: Sealing with trailing zeros in auth, unsealing with stripped auth (E2E HMAC)
    {
        let data = b"padded_auth_secrets";
        let auth = b"p@ssw0rd\x00\x00\x00";

        // Create
        let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(auth).unwrap(),
            data: Tpm2bSensitiveData::from_bytes(data).unwrap(),
        });
        let in_public = tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::NO_DA,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        });
        let create_cmd = Create {
            in_sensitive,
            in_public,
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        let create_handles = CreateHandles {
            parent_handle: srk_handle,
        };
        let (create_rsp, _) =
            execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, srk_auth)
                .unwrap();

        // Load
        let load_cmd = tpm2::commands::Load {
            in_private: create_rsp.out_private,
            in_public: create_rsp.out_public,
        };
        let load_handles = tpm2::commands::LoadHandles {
            parent_handle: srk_handle,
        };
        let (_, load_rsp_handles) =
            execute_with_password_sessions(&mut sim, &load_cmd, load_handles, 1, srk_auth).unwrap();

        // Start HMAC session for unseal
        let mut sess = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::HMAC,
            None,
            TpmiAlgHash::Sha256,
        )
        .unwrap();
        sess.attributes = TpmaSession::CONTINUE_SESSION;

        // Verify unseal works when client uses stripped auth "p@ssw0rd"
        let unseal_cmd = Unseal {};
        let unseal_handles = UnsealHandles {
            item_handle: load_rsp_handles.object_handle,
        };
        let unseal_res = crate::test_utils::execute_with_hmac_sessions(
            &mut sim,
            &unseal_cmd,
            unseal_handles,
            &[],
            &mut [sess.clone()],
            &[b"p@ssw0rd"],
        );
        assert!(unseal_res.is_ok());
        let (unseal_rsp, _) = unseal_res.unwrap();
        assert_eq!(unseal_rsp.out_data.get_buffer(), data);

        flush_context(&mut sim, sess.session_handle).unwrap();
        flush_context(&mut sim, load_rsp_handles.object_handle).unwrap();
    }

    // Case C: Sealing with maximum size auth value (64 bytes)
    {
        let data = b"max_auth_secrets";
        let auth = [0xAAu8; 48];

        // Create
        let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(&auth).unwrap(),
            data: Tpm2bSensitiveData::from_bytes(data).unwrap(),
        });
        let in_public = tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha384),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::NO_DA,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        });
        let create_cmd = Create {
            in_sensitive,
            in_public,
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        let create_handles = CreateHandles {
            parent_handle: srk_handle,
        };
        let (create_rsp, _) =
            execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, srk_auth)
                .unwrap();

        // Load
        let load_cmd = tpm2::commands::Load {
            in_private: create_rsp.out_private,
            in_public: create_rsp.out_public,
        };
        let load_handles = tpm2::commands::LoadHandles {
            parent_handle: srk_handle,
        };
        let (_, load_rsp_handles) =
            execute_with_password_sessions(&mut sim, &load_cmd, load_handles, 1, srk_auth).unwrap();

        // Unseal
        let unseal_cmd = Unseal {};
        let unseal_handles = UnsealHandles {
            item_handle: load_rsp_handles.object_handle,
        };
        let (unseal_rsp, _) =
            execute_with_password_sessions(&mut sim, &unseal_cmd, unseal_handles, 1, &auth)
                .unwrap();
        assert_eq!(unseal_rsp.out_data.get_buffer(), data);

        flush_context(&mut sim, load_rsp_handles.object_handle).unwrap();
    }

    flush_context(&mut sim, srk_handle).unwrap();
}

#[test]
fn test_sealing_payload_boundaries() {
    let mut sim = create_simulator!();
    let srk_template = get_rsa_srk_template();
    let srk_auth = b"mySRK";
    let (srk_handle, _) = create_srk(&mut sim, &srk_template, srk_auth);

    // Case A: Sealing empty payload (0 bytes)
    {
        let data = b"";
        let auth = b"pwd";

        let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(auth).unwrap(),
            data: Tpm2bSensitiveData::from_bytes(data).unwrap(),
        });
        let in_public = tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::NO_DA,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        });
        let create_cmd = Create {
            in_sensitive,
            in_public,
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        let create_handles = CreateHandles {
            parent_handle: srk_handle,
        };
        // C CreateChecks (Object_spt.c:343-346): with sensitiveDataOrigin CLEAR
        // the caller must provide data, so an empty sealed payload is rejected
        // with TPM_RCS_ATTRIBUTES + RC_Create_inPublic (ATTRIBUTES+P2, 0x2C2).
        let res =
            execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, srk_auth);
        assert_eq!(res.err(), Some(0x2c2));
    }

    // Case B: Sealing maximum size payload (128 bytes for TPM2_MAX_SYM_DATA)
    {
        let data = [0xFFu8; tpm2::TPM2_MAX_SYM_DATA as usize];
        let auth = b"pwd";

        let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(auth).unwrap(),
            data: Tpm2bSensitiveData::from_bytes(&data).unwrap(),
        });
        let in_public = tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::NO_DA,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        });
        let create_cmd = Create {
            in_sensitive,
            in_public,
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        let create_handles = CreateHandles {
            parent_handle: srk_handle,
        };
        let (create_rsp, _) =
            execute_with_password_sessions(&mut sim, &create_cmd, create_handles, 1, srk_auth)
                .unwrap();

        // Load
        let load_cmd = tpm2::commands::Load {
            in_private: create_rsp.out_private,
            in_public: create_rsp.out_public,
        };
        let load_handles = tpm2::commands::LoadHandles {
            parent_handle: srk_handle,
        };
        let (_, load_rsp_handles) =
            execute_with_password_sessions(&mut sim, &load_cmd, load_handles, 1, srk_auth).unwrap();

        // Unseal
        let unseal_cmd = Unseal {};
        let unseal_handles = UnsealHandles {
            item_handle: load_rsp_handles.object_handle,
        };
        let (unseal_rsp, _) =
            execute_with_password_sessions(&mut sim, &unseal_cmd, unseal_handles, 1, auth).unwrap();
        assert_eq!(unseal_rsp.out_data.get_buffer(), data);

        flush_context(&mut sim, load_rsp_handles.object_handle).unwrap();
    }

    // Case C: Sealing payload that exceeds maximum size (129 bytes) -> must fail during creation of Tpm2bSensitiveData
    {
        let data = [0x55u8; tpm2::TPM2_MAX_SYM_DATA as usize + 1];
        let res = Tpm2bSensitiveData::from_bytes(&data);
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert_eq!(err, tpm2::errors::UnmarshalError::SIZE);
    }

    flush_context(&mut sim, srk_handle).unwrap();
}

#[test]
fn test_sealing_parameter_encryption_corruption() {
    let mut sim = create_simulator!();
    let srk_template = get_rsa_srk_template();
    let srk_auth = b"mySRK";
    let (srk_handle, _) = create_srk(&mut sim, &srk_template, srk_auth);

    // Start decrypt/encrypt session
    let mut sess = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    sess.attributes = TpmaSession::DECRYPT | TpmaSession::CONTINUE_SESSION;

    // Create sealed object with decrypt session
    let data = b"confidential";
    let auth = b"p@ss";
    let in_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(auth).unwrap(),
        data: Tpm2bSensitiveData::from_bytes(data).unwrap(),
    });
    let in_public = tpm2::Tpm2b(TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
    });
    let create_cmd = Create {
        in_sensitive,
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_handles = CreateHandles {
        parent_handle: srk_handle,
    };

    // Corrupt ciphertext parameter byte offset 10 (inside inside Tpm2bSensitiveCreate / userAuth / sensitiveData)
    // and verify that the TPM rejects the command during unmarshalling of decrypted junk parameters
    // rather than succeeding or crashing.
    let corrupt_res = execute_with_hmac_sessions_corrupt_ciphertext(
        &mut sim,
        &create_cmd,
        create_handles,
        &mut [sess.clone()],
        &[srk_auth],
        3, // corrupt byte 3 (inside user_auth size prefix)
    );
    assert!(corrupt_res.is_err());
    let err = corrupt_res.err().unwrap();
    // The unmarshalling of corrupted sensitive area should fail with standard parsing/size/value errors
    // rather than crash. E.g. TpmRc::SIZE or TpmRc::VALUE or similar (with parameter position P1).
    let rc_type = err & 0xBF;
    assert!(
        rc_type == 0x03
            || rc_type == 0x04
            || rc_type == 0x1C
            || rc_type == 0x15
            || rc_type == 0x95
            || rc_type == 0x84,
        "Expected unmarshal/parsing error, got: {:X}",
        err
    );

    flush_context(&mut sim, sess.session_handle).unwrap();
    flush_context(&mut sim, srk_handle).unwrap();
}
