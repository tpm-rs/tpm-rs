#![allow(clippy::unwrap_used, clippy::expect_used, deprecated)]

mod common;

use common::TestCryptoProvider;
use common::marshal_to_slice;
use common::{FakeRng, FakeStorage, FakeTimer};
use tpm2::commands::{
    Command, EncryptDecrypt, EncryptDecrypt2, Message, PolicyAuthorize, PolicyCpHash,
    PolicyDuplicationSelect, UnmarshalMessage,
};
use tpm2::crypto::{Finalize as _, Hash as _, HmacStream, Random as _, Update as _};
use tpm2::errors::TpmRc;
use tpm2::{
    AlgSym, Handle, Marshal, PublicParmsAndId, ResponseHeader, Tpm2bAuth, Tpm2bDigest, Tpm2bIv,
    Tpm2bMaxBuffer, Tpm2bName, Tpm2bNonce, TpmCc, TpmSe, TpmaObject, TpmaSession,
    TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode, TpmiStCommandTag, TpmsAuthCommand, TpmtPublic,
    TpmtSymDefObject, TpmtTkVerified, Unmarshal,
};
use tpm2_impl::TpmEngine;
use tpm2_impl::handler::SessionState;
use tpm2_impl::owned::{OwnedSensitiveComposite, OwnedSymKey};

fn setup_tpm<'a>(
    crypto: &'a TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    _rng: &'a FakeRng,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer>,
    tpm2_impl::GlobalState,
) {
    let rng = crypto.rng_seeded(&[0u8; 32]).unwrap();
    let platform = tpm2_impl::TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state).unwrap();
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
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: UnmarshalMessage<'static>,
{
    execute_tpm_command_with_corrupted_bytes(tpm, global_state, cmd, auths, |_| {})
}

fn execute_tpm_command_with_corrupted_bytes<C: Command>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &C,
    auths: &[TpmsAuthCommand],
    corrupt_fn: impl FnOnce(&mut [u8]),
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: UnmarshalMessage<'static>,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    for h in cmd.handles().as_ref() {
        request_buf[offset..offset + 4].copy_from_slice(&h.0.to_be_bytes());
        offset += 4;
    }

    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4;
        let auth_start = offset;
        for auth in auths {
            let mut auth_slice = [0u8; TpmsAuthCommand::MAX_SIZE];
            let auth_len = auth.marshal(&mut auth_slice);
            request_buf[offset..offset + auth_len].copy_from_slice(&auth_slice[..auth_len]);
            offset += auth_len;
        }
        let auth_len = u32::try_from(offset - auth_start).unwrap();
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    let payload_start = offset;
    offset += marshal_to_slice(cmd, &mut request_buf[offset..]);

    corrupt_fn(&mut request_buf[payload_start..offset]);

    let total_size = u32::try_from(offset).unwrap();
    request_buf[2..6].copy_from_slice(&total_size.to_be_bytes());

    let mut response_buf = [0u8; 16384];
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);
    assert!(resp_size >= ResponseHeader::MAX_SIZE);

    let mut resp_slice: &'static [u8] = std::vec::Vec::leak(response_buf[..resp_size].to_vec());
    let resp_header = ResponseHeader::unmarshal(&mut resp_slice).unwrap();
    if let Err(rc) = resp_header.rc {
        return Err(rc.get());
    }

    let mut resp_handles = <C::Response<'static> as Message>::Handles::default();
    for h in resp_handles.as_mut() {
        *h = Handle::unmarshal(&mut resp_slice).map_err(|_| TpmRc::FAILURE.get())?;
    }

    if resp_header.tag == TpmiStCommandTag::Sessions {
        let param_size = usize::try_from(u32::unmarshal(&mut resp_slice).unwrap()).unwrap();
        let mut param_slice = &resp_slice[..param_size];
        C::Response::unmarshal_with_handles(resp_handles, &mut param_slice)
            .map_err(|_| TpmRc::FAILURE.get())
    } else {
        C::Response::unmarshal_with_handles(resp_handles, &mut resp_slice)
            .map_err(|_| TpmRc::FAILURE.get())
    }
}

#[test]
fn test_policy_duplication_select_invalid_inputs() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let session_handle = 0x03000001;
    let policy_session = SessionState {
        session_handle,
        session_type: TpmSe::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::new(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::new(&[1; 32]).unwrap()).into(),
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
    };
    global_state.add_session(policy_session).unwrap();

    // 1. Invalid include_object (e.g. 2) -> Expects TPM_RC_VALUE at P3
    let cmd_invalid_include = PolicyDuplicationSelect {
        policy_session: Handle(session_handle),
        object_name: Tpm2bName::default(),
        new_parent_name: Tpm2bName::default(),
        include_object: true,
    };
    let res = execute_tpm_command_with_corrupted_bytes::<PolicyDuplicationSelect>(
        &mut tpm,
        &mut global_state,
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
        policy_session: Handle(session_handle),
        object_name: Tpm2bName::new(&[0, 1, 2]).unwrap(),
        new_parent_name: Tpm2bName::default(),
        include_object: true,
    };
    let res = execute_tpm_command_with_auths::<PolicyDuplicationSelect>(
        &mut tpm,
        &mut global_state,
        &cmd_malformed_object_name,
        &[],
    );
    let err_val = res.err().unwrap();
    assert!(
        err_val == 0x01C4 || err_val == 0x01D5 || err_val == 0x01C3,
        "Unexpected error code for malformed object_name: 0x{:08X}",
        err_val
    );

    // 3. Malformed new_parent_name (size 3) -> Expects 0x02C4 or 0x02D5?
    let cmd_malformed_parent_name = PolicyDuplicationSelect {
        policy_session: Handle(session_handle),
        object_name: Tpm2bName::default(),
        new_parent_name: Tpm2bName::new(&[0, 1, 2]).unwrap(),
        include_object: true,
    };
    let res = execute_tpm_command_with_auths::<PolicyDuplicationSelect>(
        &mut tpm,
        &mut global_state,
        &cmd_malformed_parent_name,
        &[],
    );
    let err_val = res.err().unwrap();
    assert!(
        err_val == 0x02C4 || err_val == 0x02D5 || err_val == 0x02C3,
        "Unexpected error code for malformed new_parent_name: 0x{:08X}",
        err_val
    );
}

fn compute_hmac_in_test(
    crypto: &TestCryptoProvider,
    updates_hash: &[&[u8]],
    updates_hmac: &[&[u8]],
) -> [u8; 32] {
    let mut hash_state = crypto.sha256().unwrap();
    for data in updates_hash {
        hash_state.update(data).unwrap();
    }
    let mut digest = [0u8; 32];
    hash_state.finalize(&mut digest).unwrap();

    let mut hmac_state = HmacStream::new(crypto, TpmiAlgHash::Sha256, &[]).unwrap();
    hmac_state.update(&digest).unwrap();
    for data in updates_hmac {
        hmac_state.update(data).unwrap();
    }
    let mut hmac_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let hmac_digest = hmac_state.finalize(&mut hmac_buf).unwrap();
    hmac_digest.digest().try_into().unwrap()
}

#[test]
fn test_policy_cp_hash_self_authorization() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let session_handle = 0x03000001;
    let policy_session = SessionState {
        session_handle,
        session_type: TpmSe::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::new(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::new(&[1; 32]).unwrap()).into(),
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
    };
    global_state.add_session(policy_session).unwrap();

    let cmd = PolicyCpHash {
        policy_session: Handle(session_handle),
        cp_hash_a: Tpm2bDigest::new(&[0xaa; 32]).unwrap(),
    };

    let command_code_bytes = (TpmCc::PolicyCpHash.code()).to_be_bytes();
    let name_bytes = session_handle.to_be_bytes();

    let mut cmd_buf = [0u8; 100];
    let cmd_len = marshal_to_slice(&cmd, &mut cmd_buf);
    let parameters = &cmd_buf[..cmd_len];

    let updates_hash: &[&[u8]] = &[&command_code_bytes, &name_bytes, parameters];

    let nonce_caller = [1u8; 32];
    let nonce_tpm = [2u8; 32];
    let attr_byte = [0x00u8];
    let updates_hmac: &[&[u8]] = &[&nonce_caller, &nonce_tpm, &attr_byte];

    let hmac_val = compute_hmac_in_test(&TestCryptoProvider, updates_hash, updates_hmac);

    let auths = [TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle),
        nonce: Tpm2bNonce::new(&nonce_caller).unwrap(),
        session_attributes: TpmaSession::default(),
        hmac: Tpm2bAuth::new(&hmac_val).unwrap(),
    }];

    let res =
        execute_tpm_command_with_auths::<PolicyCpHash>(&mut tpm, &mut global_state, &cmd, &auths);
    let err_val = res.err().unwrap();
    assert_eq!(err_val, 0x98B);
}

#[test]
fn test_policy_authorize_invalid_hierarchy() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let session_handle = 0x03000001;
    let policy_session = SessionState {
        session_handle,
        session_type: TpmSe::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::new(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::new(&[1; 32]).unwrap()).into(),
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
    };
    global_state.add_session(policy_session).unwrap();

    // Use a ticket with an invalid hierarchy (e.g. 0x40000009 - RH_PW)
    let check_ticket =
        TpmtTkVerified::Verified(Handle(0x40000009), Tpm2bDigest::new(&[0; 32]).unwrap());

    let key_sign_bytes = [[0x00, 0x0b].as_slice(), [0x11; 32].as_slice()].concat();
    let cmd = PolicyAuthorize {
        policy_session: Handle(session_handle),
        approved_policy: Tpm2bDigest::new(&[0; 32]).unwrap(),
        policy_ref: Tpm2bNonce::default(),
        key_sign: Tpm2bName::new(&key_sign_bytes).unwrap(),
        check_ticket,
    };

    let res =
        execute_tpm_command_with_auths::<PolicyAuthorize>(&mut tpm, &mut global_state, &cmd, &[]);
    let err_val = res.err().unwrap();
    assert_eq!(err_val, 0x04C4);
}

#[test]
fn test_encrypt_decrypt_invalid_decrypt_value() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let key_handle = 0x80000001;
    let transient_obj = tpm2_impl::handler::TransientObject {
        handle: key_handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[1u8; 32]).unwrap(),
        name: (Tpm2bName::new(&[1, 2, 3]).unwrap()).into(),
        auth: (Tpm2bAuth::new(b"password").unwrap()).into(),
        public: (TpmtPublic {
            object_attributes: TpmaObject::USER_WITH_AUTH,
            ..Default::default()
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Sym(OwnedSymKey::default()),
        qualified_name: (Tpm2bName::new(&[1, 2, 3]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(transient_obj);

    let auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::default(),
        hmac: Tpm2bDigest::new(b"password").unwrap(),
    }];

    #[allow(deprecated)]
    let cmd = EncryptDecrypt {
        key_handle: Handle(key_handle),
        decrypt: false,
        mode: Some(TpmiAlgCipherMode::Cfb),
        iv_in: Tpm2bIv::default(),
        in_data: Tpm2bMaxBuffer::default(),
    };

    #[allow(deprecated)]
    let res = execute_tpm_command_with_corrupted_bytes::<EncryptDecrypt>(
        &mut tpm,
        &mut global_state,
        &cmd,
        &auths,
        |buf| {
            buf[0] = 2; // decrypt is the first parameter (1 byte)
        },
    );
    assert_eq!(
        res.err().unwrap(),
        TpmRc::VALUE
            .with(tpm2::errors::Position::parameter(1))
            .get()
    );
}

#[test]
fn test_encrypt_decrypt2_invalid_decrypt_value() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let key_handle = 0x80000001;
    let transient_obj = tpm2_impl::handler::TransientObject {
        handle: key_handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[1u8; 32]).unwrap(),
        name: (Tpm2bName::new(&[1, 2, 3]).unwrap()).into(),
        auth: (Tpm2bAuth::new(b"password").unwrap()).into(),
        public: (TpmtPublic {
            object_attributes: TpmaObject::USER_WITH_AUTH,
            ..Default::default()
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Sym(OwnedSymKey::default()),
        qualified_name: (Tpm2bName::new(&[1, 2, 3]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(transient_obj);

    let auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::default(),
        hmac: Tpm2bDigest::new(b"password").unwrap(),
    }];

    let cmd = EncryptDecrypt2 {
        key_handle: Handle(key_handle),
        in_data: Tpm2bMaxBuffer::default(),
        decrypt: false,
        mode: Some(TpmiAlgCipherMode::Cfb),
        iv_in: Tpm2bIv::default(),
    };

    let res = execute_tpm_command_with_corrupted_bytes::<EncryptDecrypt2>(
        &mut tpm,
        &mut global_state,
        &cmd,
        &auths,
        |buf| {
            buf[2] = 2; // in_data is empty (2 bytes size = 0), decrypt is at index 2 (1 byte)
        },
    );
    assert_eq!(
        res.err().unwrap(),
        TpmRc::VALUE
            .with(tpm2::errors::Position::parameter(2))
            .get()
    );
}

#[test]
fn test_encrypt_decrypt_cmac_key_and_mode_rejection() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let key_handle = 0x80000001;
    let transient_obj = tpm2_impl::handler::TransientObject {
        handle: key_handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[1u8; 32]).unwrap(),
        name: (Tpm2bName::new(&[1, 2, 3]).unwrap()).into(),
        auth: (Tpm2bAuth::new(b"password").unwrap()).into(),
        public: (TpmtPublic {
            object_attributes: TpmaObject::USER_WITH_AUTH
                | TpmaObject::DECRYPT
                | TpmaObject::SIGN_ENCRYPT,
            parms_and_id: PublicParmsAndId::Sym(
                TpmtSymDefObject {
                    alg: AlgSym::Aes128,
                    mode: Some(TpmiAlgSymMode::Cmac),
                },
                Tpm2bDigest::default(),
            ),
            ..Default::default()
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Sym(OwnedSymKey::from_bytes(&[0u8; 16]).unwrap()),
        qualified_name: (Tpm2bName::new(&[1, 2, 3]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(transient_obj);

    let auths = [TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::default(),
        hmac: Tpm2bDigest::new(b"password").unwrap(),
    }];

    // 1. EncryptDecrypt with mode = None on a key whose default mode is CMAC -> should return TPM_RC_MODE + TPM_RC_H + TPM_RC_1
    #[allow(deprecated)]
    let cmd = EncryptDecrypt {
        key_handle: Handle(key_handle),
        decrypt: false,
        mode: None,
        iv_in: Tpm2bIv::new(&[0u8; 16]).unwrap(),
        in_data: Tpm2bMaxBuffer::new(&[0u8; 16]).unwrap(),
    };
    #[allow(deprecated)]
    let res = execute_tpm_command_with_corrupted_bytes::<EncryptDecrypt>(
        &mut tpm,
        &mut global_state,
        &cmd,
        &auths,
        |_| {},
    );
    assert_eq!(
        res.err().unwrap(),
        TpmRc::MODE.with(tpm2::errors::Position::handle(1)).get()
    );

    // 2. EncryptDecrypt with mode parameter corrupted to TPM_ALG_CMAC (0x003F) -> unmarshalling fails with TPM_RC_MODE + TPM_RC_P + TPM_RC_2
    #[allow(deprecated)]
    let res_param = execute_tpm_command_with_corrupted_bytes::<EncryptDecrypt>(
        &mut tpm,
        &mut global_state,
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
    let cmd2 = EncryptDecrypt2 {
        key_handle: Handle(key_handle),
        in_data: Tpm2bMaxBuffer::new(&[0u8; 16]).unwrap(),
        decrypt: false,
        mode: None,
        iv_in: Tpm2bIv::new(&[0u8; 16]).unwrap(),
    };
    let res_param2 = execute_tpm_command_with_corrupted_bytes::<EncryptDecrypt2>(
        &mut tpm,
        &mut global_state,
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
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let session_handle_1 = 0x03000001;
    let policy_session_1 = SessionState {
        session_handle: session_handle_1,
        session_type: TpmSe::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::new(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::new(&[1; 32]).unwrap()).into(),
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
    };
    global_state.add_session(policy_session_1).unwrap();

    // 1. A 66-byte name (SHA512 Name) when include_object is NO should succeed.
    let mut sha512_name = [0u8; 66];
    sha512_name[0..2].copy_from_slice(&0x0012u16.to_be_bytes());
    sha512_name[2..66].fill(0xaa);
    let object_name_66 = Tpm2bName::new(&sha512_name).unwrap();

    let cmd_66 = PolicyDuplicationSelect {
        policy_session: Handle(session_handle_1),
        object_name: object_name_66,
        new_parent_name: Tpm2bName::default(),
        include_object: false,
    };
    let res = execute_tpm_command_with_auths::<PolicyDuplicationSelect>(
        &mut tpm,
        &mut global_state,
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
        nonce_tpm: (Tpm2bNonce::new(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::new(&[1; 32]).unwrap()).into(),
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
    };
    global_state.add_session(policy_session_2).unwrap();

    let mut name_65 = [0u8; 65];
    name_65[0..2].copy_from_slice(&0x0012u16.to_be_bytes());
    name_65[2..65].fill(0xbb);
    let object_name_65 = Tpm2bName::new(&name_65).unwrap();

    let cmd_65 = PolicyDuplicationSelect {
        policy_session: Handle(session_handle_2),
        object_name: object_name_65,
        new_parent_name: Tpm2bName::default(),
        include_object: false,
    };
    let res = execute_tpm_command_with_auths::<PolicyDuplicationSelect>(
        &mut tpm,
        &mut global_state,
        &cmd_65,
        &[],
    );
    assert!(
        res.is_ok(),
        "65-byte name failed when include_object is NO: {:?}",
        res
    );
}
