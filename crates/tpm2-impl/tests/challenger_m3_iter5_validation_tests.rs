use common::marshal_to_slice;
use tpm2::Unmarshal;
use tpm2::errors::TpmRc;
extern crate alloc;

mod common;

use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage, FakeTimer};
use tpm2::commands::{
    Command, EncryptDecrypt, EncryptDecrypt2, EncryptDecrypt2Handles, EncryptDecryptHandles,
    PolicyAuthorize, PolicyAuthorizeHandles, PolicyCpHash, PolicyCpHashHandles,
    PolicyDuplicationSelect, PolicyDuplicationSelectHandles,
};
use tpm2::{Handle, Marshal, TpmCc, TpmSe};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bIv, Tpm2bMaxBuffer, Tpm2bName, Tpm2bNonce,
    TpmaObject, TpmaSession, TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode, TpmsAuthCommand,
    TpmtPublic, TpmtSymDefObject, TpmtTkVerified,
};
use tpm2_impl::TpmEngine;
use tpm2_impl::handler::SessionState;

fn setup_tpm<'a>(
    crypto: &'a mut TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a FakeRng,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    tpm2_impl::GlobalState,
) {
    let platform = tpm2_impl::TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;
    global_state.g_nv_ok = true;

    // Startup
    let startup_request = hex_literal::hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    (tpm, global_state)
}

fn execute_tpm_command_with_auths<C: Command>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &C::Handles,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <<C as Command>::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: Unmarshal<'static>,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    offset += marshal_to_slice(handles, &mut request_buf[offset..]);

    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4;
        let auth_start = offset;
        for auth in auths {
            let auth_slice: &mut [u8; TpmsAuthCommand::MAX_SIZE] = (&mut request_buf
                [offset..offset + TpmsAuthCommand::MAX_SIZE])
                .try_into()
                .map_err(|_| ())
                .unwrap();
            let auth_len = auth.marshal(auth_slice);
            offset += auth_len;
        }
        let auth_len = (offset - auth_start) as u32;
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    offset += marshal_to_slice(cmd, &mut request_buf[offset..]);

    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut response_buf = [0u8; 16384];
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    let params_offset = if resp_tag == 0x8002 { 14 } else { 10 };

    let mut unmarshal_buf: &'static [u8] =
        std::vec::Vec::leak(response_buf[params_offset..resp_size].to_vec());
    let resp =
        <C::Response<'static>>::unmarshal(&mut unmarshal_buf).map_err(|_| TpmRc::FAILURE.get())?;
    Ok(resp)
}

fn execute_tpm_command_with_corrupted_bytes<C: Command>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &C::Handles,
    cmd: &C,
    auths: &[TpmsAuthCommand],
    corrupt_fn: impl FnOnce(&mut [u8]),
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <<C as Command>::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: Unmarshal<'static>,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    offset += marshal_to_slice(handles, &mut request_buf[offset..]);

    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4;
        let auth_start = offset;
        for auth in auths {
            let auth_slice: &mut [u8; TpmsAuthCommand::MAX_SIZE] = (&mut request_buf
                [offset..offset + TpmsAuthCommand::MAX_SIZE])
                .try_into()
                .map_err(|_| ())
                .unwrap();
            let auth_len = auth.marshal(auth_slice);
            offset += auth_len;
        }
        let auth_len = (offset - auth_start) as u32;
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    let payload_start = offset;
    offset += marshal_to_slice(cmd, &mut request_buf[offset..]);

    corrupt_fn(&mut request_buf[payload_start..offset]);

    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut response_buf = [0u8; 16384];
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    let params_offset = if resp_tag == 0x8002 { 14 } else { 10 };

    let mut unmarshal_buf: &'static [u8] =
        std::vec::Vec::leak(response_buf[params_offset..resp_size].to_vec());
    let resp =
        <C::Response<'static>>::unmarshal(&mut unmarshal_buf).map_err(|_| TpmRc::FAILURE.get())?;
    Ok(resp)
}

#[test]
fn test_policy_duplication_select_invalid_inputs() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let session_handle = 0x03000001;
    let policy_session = SessionState {
        session_handle,
        session_type: TpmSe::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::from_bytes(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::from_bytes(&[1; 32]).unwrap()).into(),
        session_key: [0u8; 128],
        session_key_len: 0,
        symmetric: None,
        bind_entity: Handle::RH_NULL,
        bound_entity: Default::default(),
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
        policy_digest_len: 32,
        command_code: 0,
        start_time: 0,
        timeout: 0,
        epoch: global_state.time_epoch,
        is_auth_value_needed: false,
        is_password_needed: false,
        pcr_counter: None,
        check_nv_written: false,
        nv_written_state: false,
        command_locality: 0,
        include_auth: false,
        is_da_bound: false,
        is_lockout_bound: false,
    };
    global_state.add_session(policy_session).unwrap();

    let handles = PolicyDuplicationSelectHandles {
        policy_session: Handle(session_handle),
    };

    // 1. Invalid include_object (e.g. 2) -> Expects 0x95 (TPM_RC_SIZE)
    let cmd_invalid_include = PolicyDuplicationSelect {
        object_name: Tpm2bName::default(),
        new_parent_name: Tpm2bName::default(),
        include_object: true,
    };
    let res = execute_tpm_command_with_corrupted_bytes::<PolicyDuplicationSelect>(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd_invalid_include,
        &[],
        |buf| {
            buf[4] = 2;
        },
    );
    assert_eq!(
        res.err().unwrap(),
        TpmRc::VALUE
            .with(tpm2::errors::Position::parameter(3))
            .get()
    );

    // 2. Malformed object_name (size 3) -> Expects 0x01C4 or 0x01D5?
    let cmd_malformed_object_name = PolicyDuplicationSelect {
        object_name: Tpm2bName::from_bytes(&[0, 1, 2]).unwrap(),
        new_parent_name: Tpm2bName::default(),
        include_object: true,
    };
    let res = execute_tpm_command_with_auths::<PolicyDuplicationSelect>(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd_malformed_object_name,
        &[],
    );
    // C does not validate the structure of the names (TPM2B_NAME_Unmarshal only bounds the
    // size, and PolicyDuplicationSelect.c just hashes them), so this succeeds.
    assert!(
        res.is_ok(),
        "Malformed object_name must be accepted like C, got {:?}",
        res.err()
    );

    // 3. Malformed new_parent_name (size 3) -> Expects 0x02C4 or 0x02D5?
    let cmd_malformed_parent_name = PolicyDuplicationSelect {
        object_name: Tpm2bName::default(),
        new_parent_name: Tpm2bName::from_bytes(&[0, 1, 2]).unwrap(),
        include_object: true,
    };
    let res = execute_tpm_command_with_auths::<PolicyDuplicationSelect>(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd_malformed_parent_name,
        &[],
    );
    // The names are not validated (see above), but case 2 already set the session's nameHash,
    // so C returns bare TPM_RC_CPHASH (PolicyDuplicationSelect.c: `nameHash.t.size != 0`).
    assert_eq!(res.err(), Some(TpmRc::CPHASH.get()));
}

fn compute_hmac_in_test(
    crypto: &TestCryptoProvider,
    updates_hash: &[&[u8]],
    updates_hmac: &[&[u8]],
) -> [u8; 32] {
    use tpm2::crypto::{Finalize as _, Hash as _, Update as _};

    let mut hash_state = crypto.sha256().unwrap();
    for data in updates_hash {
        hash_state.update(data).unwrap();
    }
    let mut digest = [0u8; 32];
    hash_state.finalize(&mut digest).unwrap();

    let mut hmac_state = tpm2::crypto::HmacCtx::new(crypto, TpmiAlgHash::Sha256, &[]).unwrap();
    hmac_state.update(&digest).unwrap();
    for data in updates_hmac {
        hmac_state.update(data).unwrap();
    }
    let mut hmac_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let hmac_digest = hmac_state.finalize(&mut hmac_buf).unwrap();
    hmac_digest.digest().try_into().unwrap()
}

#[test]
fn test_policy_cp_hash_self_authorization() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // We use a valid policy session handle (0x03000001) in this test.
    let session_handle = 0x03000001;
    let policy_session = SessionState {
        session_handle,
        session_type: TpmSe::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::from_bytes(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::from_bytes(&[1; 32]).unwrap()).into(),
        session_key: [0u8; 128],
        session_key_len: 0,
        symmetric: None,
        bind_entity: Handle::RH_NULL,
        bound_entity: Default::default(),
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
        policy_digest_len: 32,
        command_code: 0,
        start_time: 0,
        timeout: 0,
        epoch: global_state.time_epoch,
        is_auth_value_needed: false,
        is_password_needed: false,
        pcr_counter: None,
        check_nv_written: false,
        nv_written_state: false,
        command_locality: 0,
        include_auth: false,
        is_da_bound: false,
        is_lockout_bound: false,
    };
    global_state.add_session(policy_session).unwrap();

    let handles = PolicyCpHashHandles {
        policy_session: Handle(session_handle),
    };
    let cmd = PolicyCpHash {
        cp_hash_a: Tpm2bDigest::from_bytes(&[0xaa; 32]).unwrap(),
    };

    // Calculate updates_hash and updates_hmac
    let command_code_bytes = (TpmCc::PolicyCpHash.code()).to_be_bytes();
    let name_bytes = session_handle.to_be_bytes(); // handle name of 0x03000001 is [0x03, 0x00, 0x00, 0x01]

    let mut cmd_buf = [0u8; 100];
    let cmd_len = marshal_to_slice(&cmd, &mut cmd_buf);
    let parameters = &cmd_buf[..cmd_len];

    let updates_hash: &[&[u8]] = &[&command_code_bytes, &name_bytes, parameters];

    let nonce_caller = [1u8; 32];
    let nonce_tpm = [2u8; 32];
    let attr_byte = [0x00u8];
    let updates_hmac: &[&[u8]] = &[&nonce_caller, &nonce_tpm, &attr_byte];

    let hmac_val = compute_hmac_in_test(&TestCryptoProvider, updates_hash, updates_hmac);

    // We pass the policy session itself as an auth session.
    let auths = [TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle),
        nonce: Tpm2bNonce::from_bytes(&nonce_caller).unwrap(),
        session_attributes: TpmaSession::default(),
        hmac: Tpm2bAuth::from_bytes(&hmac_val).unwrap(),
    }];

    // C has no "self-authorization" check; the session does not authorize any handle and has
    // none of audit/encrypt/decrypt set, so C ParseSessionBuffer returns
    // TPM_RC_ATTRIBUTES + RC_S1 (0x0982).
    let res = execute_tpm_command_with_auths::<PolicyCpHash>(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &auths,
    );
    let err_val = res.err().unwrap();
    println!(
        "PolicyCpHash self-authorization returned error: 0x{:08X}",
        err_val
    );
    assert_eq!(err_val, 0x982);
}

#[test]
fn test_policy_authorize_invalid_hierarchy() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let session_handle = 0x03000001;
    let policy_session = SessionState {
        session_handle,
        session_type: TpmSe::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::from_bytes(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::from_bytes(&[1; 32]).unwrap()).into(),
        session_key: [0u8; 128],
        session_key_len: 0,
        symmetric: None,
        bind_entity: Handle::RH_NULL,
        bound_entity: Default::default(),
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
        policy_digest_len: 32,
        command_code: 0,
        start_time: 0,
        timeout: 0,
        epoch: global_state.time_epoch,
        is_auth_value_needed: false,
        is_password_needed: false,
        pcr_counter: None,
        check_nv_written: false,
        nv_written_state: false,
        command_locality: 0,
        include_auth: false,
        is_da_bound: false,
        is_lockout_bound: false,
    };
    global_state.add_session(policy_session).unwrap();

    let handles = PolicyAuthorizeHandles {
        policy_session: Handle(session_handle),
    };

    // Use a ticket with an invalid hierarchy (e.g. 0x40000009 - RH_PW)
    let check_ticket = TpmtTkVerified::Verified(
        Handle(0x40000009),
        Tpm2bDigest::from_bytes(&[0; 32]).unwrap(),
    );

    let key_sign_bytes = [[0x00, 0x0b].as_slice(), [0x11; 32].as_slice()].concat();
    let cmd = PolicyAuthorize {
        approved_policy: Tpm2bDigest::from_bytes(&[0; 32]).unwrap(),
        policy_ref: Tpm2bNonce::default(),
        key_sign: Tpm2bName::from_bytes(&key_sign_bytes).unwrap(),
        check_ticket,
    };

    let res = execute_tpm_command_with_auths::<PolicyAuthorize>(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &[],
    );
    let err_val = res.err().unwrap();
    println!(
        "PolicyAuthorize invalid hierarchy returned error: 0x{:08X}",
        err_val
    );
    // Expecting 0x04C4 (value_for(Position::parameter(4)))
    assert_eq!(err_val, 0x04C4);
}

#[test]
fn test_encrypt_decrypt_invalid_decrypt_value() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let key_handle = 0x80000001;
    let transient_obj = tpm2_impl::handler::TransientObject {
        handle: key_handle,
        seed: {
            let mut s = [0u8; 64];
            s[..32].copy_from_slice(&[1u8; 32]);
            s
        },
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::from_bytes(&[1, 2, 3]).unwrap()).into(),
        auth: (Tpm2bAuth::from_bytes(b"password").unwrap()).into(),
        public: (TpmtPublic {
            object_attributes: TpmaObject::USER_WITH_AUTH,
            ..Default::default()
        })
        .into(),
        private: [0u8; 1536],
        private_len: 0,
        qualified_name: (Tpm2bName::from_bytes(&[1, 2, 3]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(transient_obj);

    let auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::default(),
        hmac: Tpm2bDigest::from_bytes(b"password").unwrap(),
    }];

    let handles = EncryptDecryptHandles {
        key_handle: Handle(key_handle),
    };
    let cmd = EncryptDecrypt {
        decrypt: false,
        mode: Some(TpmiAlgCipherMode::CFB),
        iv_in: Tpm2bIv::default(),
        in_data: Tpm2bMaxBuffer::default(),
    };

    let res = execute_tpm_command_with_corrupted_bytes::<EncryptDecrypt>(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &auths,
        |buf| {
            buf[0] = 2; // decrypt is the first parameter (1 byte)
        },
    );
    // Since bool unmarshalling now fails, it returns TPM_RC_VALUE + TPM_RC_P + TPM_RC_1 (0x1C4)
    assert_eq!(
        res.err().unwrap(),
        TpmRc::VALUE
            .with(tpm2::errors::Position::parameter(1))
            .get()
    );
}

#[test]
fn test_encrypt_decrypt2_invalid_decrypt_value() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let key_handle = 0x80000001;
    let transient_obj = tpm2_impl::handler::TransientObject {
        handle: key_handle,
        seed: {
            let mut s = [0u8; 64];
            s[..32].copy_from_slice(&[1u8; 32]);
            s
        },
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::from_bytes(&[1, 2, 3]).unwrap()).into(),
        auth: (Tpm2bAuth::from_bytes(b"password").unwrap()).into(),
        public: (TpmtPublic {
            object_attributes: TpmaObject::USER_WITH_AUTH,
            ..Default::default()
        })
        .into(),
        private: [0u8; 1536],
        private_len: 0,
        qualified_name: (Tpm2bName::from_bytes(&[1, 2, 3]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(transient_obj);

    let auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::default(),
        hmac: Tpm2bDigest::from_bytes(b"password").unwrap(),
    }];

    let handles = EncryptDecrypt2Handles {
        key_handle: Handle(key_handle),
    };
    let cmd = EncryptDecrypt2 {
        in_data: Tpm2bMaxBuffer::default(),
        decrypt: false,
        mode: Some(TpmiAlgCipherMode::CFB),
        iv_in: Tpm2bIv::default(),
    };

    let res = execute_tpm_command_with_corrupted_bytes::<EncryptDecrypt2>(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &auths,
        |buf| {
            buf[2] = 2; // in_data is empty (2 bytes size = 0), decrypt is at index 2 (1 byte)
        },
    );
    // Since bool unmarshalling now fails, it returns TPM_RC_VALUE + TPM_RC_P + TPM_RC_2 (0x2C4)
    assert_eq!(
        res.err().unwrap(),
        TpmRc::VALUE
            .with(tpm2::errors::Position::parameter(2))
            .get()
    );
}

#[test]
fn test_encrypt_decrypt_cmac_key_and_mode_rejection() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let key_handle = 0x80000001;
    let transient_obj = tpm2_impl::handler::TransientObject {
        handle: key_handle,
        seed: {
            let mut s = [0u8; 64];
            s[..32].copy_from_slice(&[1u8; 32]);
            s
        },
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::from_bytes(&[1, 2, 3]).unwrap()).into(),
        auth: (Tpm2bAuth::from_bytes(b"password").unwrap()).into(),
        public: (TpmtPublic {
            object_attributes: TpmaObject::USER_WITH_AUTH
                | TpmaObject::DECRYPT
                | TpmaObject::SIGN_ENCRYPT,
            parms_and_id: PublicParmsAndId::Sym(
                TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CMAC)),
                Tpm2bDigest::default(),
            ),
            ..Default::default()
        })
        .into(),
        private: [0u8; 1536],
        private_len: 16,
        qualified_name: (Tpm2bName::from_bytes(&[1, 2, 3]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(transient_obj);

    let auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::default(),
        hmac: Tpm2bDigest::from_bytes(b"password").unwrap(),
    }];

    // 1. EncryptDecrypt with mode = None on a key whose default mode is CMAC -> should return TPM_RC_MODE + TPM_RC_H + TPM_RC_1
    let handles = EncryptDecryptHandles {
        key_handle: Handle(key_handle),
    };
    let cmd = EncryptDecrypt {
        decrypt: false,
        mode: None,
        iv_in: Tpm2bIv::from_bytes(&[0u8; 16]).unwrap(),
        in_data: Tpm2bMaxBuffer::from_bytes(&[0u8; 16]).unwrap(),
    };
    let res = execute_tpm_command_with_corrupted_bytes::<EncryptDecrypt>(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &auths,
        |_| {},
    );
    assert_eq!(
        res.err().unwrap(),
        TpmRc::MODE.with(tpm2::errors::Position::handle(1)).get()
    );

    // 2. EncryptDecrypt with mode parameter corrupted to TPM_ALG_CMAC (0x003F) -> unmarshalling fails with TPM_RC_MODE + TPM_RC_P + TPM_RC_2
    let res_param = execute_tpm_command_with_corrupted_bytes::<EncryptDecrypt>(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &auths,
        |buf| {
            // decrypt is at index 0 (1 byte); mode is at index 1..3 (2 bytes)
            buf[1..3].copy_from_slice(&0x003Fu16.to_be_bytes());
        },
    );
    assert_eq!(
        res_param.err().unwrap(),
        TpmRc::MODE.with(tpm2::errors::Position::parameter(2)).get()
    );

    // 3. EncryptDecrypt2 with mode parameter corrupted to TPM_ALG_CMAC (0x003F) -> unmarshalling fails with TPM_RC_MODE + TPM_RC_P + TPM_RC_3
    let handles2 = EncryptDecrypt2Handles {
        key_handle: Handle(key_handle),
    };
    let cmd2 = EncryptDecrypt2 {
        in_data: Tpm2bMaxBuffer::from_bytes(&[0u8; 16]).unwrap(),
        decrypt: false,
        mode: None,
        iv_in: Tpm2bIv::from_bytes(&[0u8; 16]).unwrap(),
    };
    let res_param2 = execute_tpm_command_with_corrupted_bytes::<EncryptDecrypt2>(
        &mut tpm,
        &mut global_state,
        &handles2,
        &cmd2,
        &auths,
        |buf| {
            // in_data size is 2 bytes (16) + 16 bytes = 18 bytes; decrypt is at index 18 (1 byte); mode is at index 19..21 (2 bytes)
            buf[19..21].copy_from_slice(&0x003Fu16.to_be_bytes());
        },
    );
    assert_eq!(
        res_param2.err().unwrap(),
        TpmRc::MODE.with(tpm2::errors::Position::parameter(3)).get()
    );
}

#[test]
fn test_policy_duplication_select_name_size_limits() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let session_handle_1 = 0x03000001;
    let policy_session_1 = SessionState {
        session_handle: session_handle_1,
        session_type: TpmSe::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::from_bytes(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::from_bytes(&[1; 32]).unwrap()).into(),
        session_key: [0u8; 128],
        session_key_len: 0,
        symmetric: None,
        bind_entity: Handle::RH_NULL,
        bound_entity: Default::default(),
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
        policy_digest_len: 32,
        command_code: 0,
        start_time: 0,
        timeout: 0,
        epoch: global_state.time_epoch,
        is_auth_value_needed: false,
        is_password_needed: false,
        pcr_counter: None,
        check_nv_written: false,
        nv_written_state: false,
        command_locality: 0,
        include_auth: false,
        is_da_bound: false,
        is_lockout_bound: false,
    };
    global_state.add_session(policy_session_1).unwrap();

    let handles_1 = PolicyDuplicationSelectHandles {
        policy_session: Handle(session_handle_1),
    };

    // 1. A 66-byte name (SHA512 Name) when include_object is NO should succeed.
    let mut sha512_name = [0u8; 66];
    sha512_name[0..2].copy_from_slice(&0x0012u16.to_be_bytes()); // SHA512 alg id
    sha512_name[2..66].fill(0xaa);
    let object_name_66 = Tpm2bName::from_bytes(&sha512_name).unwrap();

    let cmd_66 = PolicyDuplicationSelect {
        object_name: object_name_66,
        new_parent_name: Tpm2bName::default(),
        include_object: false,
    };
    let res = execute_tpm_command_with_auths::<PolicyDuplicationSelect>(
        &mut tpm,
        &mut global_state,
        &handles_1,
        &cmd_66,
        &[],
    );
    assert!(
        res.is_ok(),
        "66-byte name failed when include_object is NO: {:?}",
        res
    );

    // 2. A 65-byte name should also succeed on a fresh session.
    let session_handle_2 = 0x03000002;
    let policy_session_2 = SessionState {
        session_handle: session_handle_2,
        session_type: TpmSe::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::from_bytes(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::from_bytes(&[1; 32]).unwrap()).into(),
        session_key: [0u8; 128],
        session_key_len: 0,
        symmetric: None,
        bind_entity: Handle::RH_NULL,
        bound_entity: Default::default(),
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
        policy_digest_len: 32,
        command_code: 0,
        start_time: 0,
        timeout: 0,
        epoch: global_state.time_epoch,
        is_auth_value_needed: false,
        is_password_needed: false,
        pcr_counter: None,
        check_nv_written: false,
        nv_written_state: false,
        command_locality: 0,
        include_auth: false,
        is_da_bound: false,
        is_lockout_bound: false,
    };
    global_state.add_session(policy_session_2).unwrap();

    let handles_2 = PolicyDuplicationSelectHandles {
        policy_session: Handle(session_handle_2),
    };

    let mut name_65 = [0u8; 65];
    name_65[0..2].copy_from_slice(&0x0012u16.to_be_bytes()); // SHA512 alg id
    name_65[2..65].fill(0xbb);
    let object_name_65 = Tpm2bName::from_bytes(&name_65).unwrap();

    let cmd_65 = PolicyDuplicationSelect {
        object_name: object_name_65,
        new_parent_name: Tpm2bName::default(),
        include_object: false,
    };
    let res = execute_tpm_command_with_auths::<PolicyDuplicationSelect>(
        &mut tpm,
        &mut global_state,
        &handles_2,
        &cmd_65,
        &[],
    );
    assert!(
        res.is_ok(),
        "65-byte name failed when include_object is NO: {:?}",
        res
    );
}
