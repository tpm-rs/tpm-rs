#![allow(clippy::unwrap_used, clippy::expect_used)]

extern crate alloc;

mod common;

use alloc::vec::Vec;
use common::{FakeRng, FakeStorage, FakeTimer, TestCryptoProvider, marshal_to_slice};
use hex_literal::hex;
use tpm2::commands::{
    Command, Duplicate, EvictControl, Import, Load, Message, PolicyCommandCode, PolicyGetDigest,
    Rewrap, UnmarshalMessage,
};
use tpm2::crypto::{Ecc, EccPrivateKey, EccPublicKey, Random, Rsa, RsaPrivateKey, RsaPublicKey};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    AlgSym, Handle, Marshal, PublicParmsAndId, ResponseHeader, Tpm2bAuth, Tpm2bData, Tpm2bDigest,
    Tpm2bName, Tpm2bNonce, Tpm2bPrivate, TpmCc, TpmSe, TpmaObject, TpmiAlgCipherMode, TpmiAlgHash,
    TpmiAlgSymMode, TpmiRsaKeyBits, TpmiStCommandTag, TpmsAuthCommand, TpmsRsaParms, TpmtPublic,
    TpmtSymDefObject, Unmarshal,
};
use tpm2_impl::handler::TransientObject;
use tpm2_impl::owned::{OwnedSensitiveComposite, OwnedSymKey};
use tpm2_impl::{TpmEngine, TpmPlatform};

struct PolicyCommandCodeHandles {
    pub policy_session: Handle,
}
struct PolicyGetDigestHandles {
    pub policy_session: Handle,
}
struct DuplicateHandles {
    pub object_handle: Handle,
    pub new_parent_handle: Handle,
}
struct ImportHandles {
    pub parent_handle: Handle,
}
struct LoadHandles {
    pub parent_handle: Handle,
}
struct EvictControlHandles {
    pub auth: Handle,
    pub object_handle: Handle,
}
struct RewrapHandles {
    pub old_parent: Handle,
    pub new_parent: Handle,
}

trait TestHandles {
    fn to_vec(&self) -> Vec<Handle>;
}

impl TestHandles for PolicyCommandCodeHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.policy_session]
    }
}
impl TestHandles for PolicyGetDigestHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.policy_session]
    }
}
impl TestHandles for DuplicateHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.object_handle, self.new_parent_handle]
    }
}
impl TestHandles for ImportHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.parent_handle]
    }
}
impl TestHandles for LoadHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.parent_handle]
    }
}
impl TestHandles for EvictControlHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.auth, self.object_handle]
    }
}
impl TestHandles for RewrapHandles {
    fn to_vec(&self) -> Vec<Handle> {
        vec![self.old_parent, self.new_parent]
    }
}

fn setup_tpm<'a>(
    crypto: &'a TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    _rng: &FakeRng,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer>,
    tpm2_impl::GlobalState,
) {
    let rng = crypto.rng_seeded(&[0u8; 32]).unwrap();
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state).unwrap();
    global_state.nv_available = true;
    global_state.locality = 0;
    global_state.g_nv_ok = true;

    // Startup
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    (tpm, global_state)
}

fn execute_tpm_command_with_auths<C: Command, H: TestHandles>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &H,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: UnmarshalMessage<'static>,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    let tag: u16 = if auths.is_empty() { 0x8001 } else { 0x8002 };
    request_buf[0..2].copy_from_slice(&tag.to_be_bytes());
    request_buf[6..10].copy_from_slice(&C::CMD_CODE.code().to_be_bytes());

    for h in handles.to_vec() {
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

    let cmd_len = marshal_to_slice(cmd, &mut request_buf[offset..]);
    offset += cmd_len;

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
fn test_policy_command_code_success_and_errors() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // 1. Session not found -> returns TpmRc::VALUE.with(Position::handle(1))
    let cmd = PolicyCommandCode {
        policy_session: Handle(0x03000009),
        code: TpmCc::Duplicate,
    };
    let handles = PolicyCommandCodeHandles {
        policy_session: Handle(0x03000009),
    };
    let res = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &handles, &cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::handle(1)).get())
    );

    // 2. Create an HMAC session instead of Policy session and check handle error
    let hmac_session = tpm2_impl::handler::SessionState {
        session_handle: 0x02000001,
        session_type: TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: Tpm2bNonce::default().into(),
        nonce_caller: Tpm2bNonce::default().into(),
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
        epoch: 0,
        is_auth_value_needed: false,
        is_password_needed: false,
        pcr_counter: None,
        check_nv_written: false,
        nv_written_state: false,
        command_locality: 0,
        include_auth: false,
    };
    global_state.add_session(hmac_session).unwrap();

    let handles = PolicyCommandCodeHandles {
        policy_session: Handle(0x02000001),
    };
    let cmd = PolicyCommandCode {
        policy_session: Handle(0x02000001),
        code: TpmCc::Duplicate,
    };
    let res = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &handles, &cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::handle(1)).get())
    );

    // 3. Create a valid Policy session
    let policy_session = tpm2_impl::handler::SessionState {
        session_handle: 0x03000001,
        session_type: TpmSe::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: Tpm2bNonce::default().into(),
        nonce_caller: Tpm2bNonce::default().into(),
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
        epoch: 0,
        is_auth_value_needed: false,
        is_password_needed: false,
        pcr_counter: None,
        check_nv_written: false,
        nv_written_state: false,
        command_locality: 0,
        include_auth: false,
    };
    global_state.add_session(policy_session).unwrap();

    // 4. Unsupported command code (e.g. TpmCc::PPCommands) -> returns TpmRc::POLICY_CC (0x120)
    let cmd_unsupported = PolicyCommandCode {
        policy_session: Handle(0x03000001),
        code: TpmCc::PPCommands,
    };
    let handles = PolicyCommandCodeHandles {
        policy_session: Handle(0x03000001),
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd_unsupported,
        &[],
    );
    assert_eq!(res.err(), Some(TpmRc::POLICY_CC.get()));

    // 5. Valid command code (e.g. TpmCc::Duplicate) -> returns Ok(())
    let cmd = PolicyCommandCode {
        policy_session: Handle(0x03000001),
        code: TpmCc::Duplicate,
    };
    let res = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &handles, &cmd, &[]);
    assert!(res.is_ok());

    // Verify policy_digest updated and command_code set
    {
        let session = global_state.session(0x03000001).unwrap();
        assert_eq!(session.command_code, TpmCc::Duplicate.code());
        assert_ne!(
            session.policy_digest[..session.policy_digest_len],
            [0u8; 32]
        );
    }

    // 6. Calling again with a different command code (e.g. TpmCc::Import) -> returns TpmRc::VALUE (0x44)
    let cmd_different = PolicyCommandCode {
        policy_session: Handle(0x03000001),
        code: TpmCc::Import,
    };
    let res =
        execute_tpm_command_with_auths(&mut tpm, &mut global_state, &handles, &cmd_different, &[]);
    assert_eq!(res.err(), Some(TpmRc::VALUE.get()));
}

#[test]
fn test_policy_get_digest() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // 1. Session not found -> returns TpmRc::VALUE.with(Position::handle(1))
    let cmd = PolicyGetDigest {
        policy_session: Handle(0x03000009),
    };
    let handles = PolicyGetDigestHandles {
        policy_session: Handle(0x03000009),
    };
    let res = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &handles, &cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::handle(1)).get())
    );

    // 2. Create an HMAC session instead of Policy session and check handle error
    let hmac_session = tpm2_impl::handler::SessionState {
        session_handle: 0x02000001,
        session_type: TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: Tpm2bNonce::default().into(),
        nonce_caller: Tpm2bNonce::default().into(),
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
        epoch: 0,
        is_auth_value_needed: false,
        is_password_needed: false,
        pcr_counter: None,
        check_nv_written: false,
        nv_written_state: false,
        command_locality: 0,
        include_auth: false,
    };
    global_state.add_session(hmac_session).unwrap();

    let handles = PolicyGetDigestHandles {
        policy_session: Handle(0x02000001),
    };
    let cmd = PolicyGetDigest {
        policy_session: Handle(0x02000001),
    };
    let res = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &handles, &cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::handle(1)).get())
    );

    // 3. Create a valid Policy session with mock digest
    let mut mock_digest = [0u8; 64];
    mock_digest[..32].copy_from_slice(&[0xa5; 32]);
    let policy_session = tpm2_impl::handler::SessionState {
        session_handle: 0x03000001,
        session_type: TpmSe::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: Tpm2bNonce::default().into(),
        nonce_caller: Tpm2bNonce::default().into(),
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
        policy_digest: mock_digest,
        policy_digest_len: 32,
        command_code: 0,
        start_time: 0,
        timeout: 0,
        epoch: 0,
        is_auth_value_needed: false,
        is_password_needed: false,
        pcr_counter: None,
        check_nv_written: false,
        nv_written_state: false,
        command_locality: 0,
        include_auth: false,
    };
    global_state.add_session(policy_session).unwrap();

    let handles = PolicyGetDigestHandles {
        policy_session: Handle(0x03000001),
    };
    let cmd = PolicyGetDigest {
        policy_session: Handle(0x03000001),
    };
    let res = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &handles, &cmd, &[]);
    assert!(res.is_ok());
    let resp = res.unwrap();
    assert_eq!(resp.policy_digest.as_slice(), &[0xa5; 32]);
}

#[test]
fn test_duplicate_import_load_roundtrip() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // 1. Setup target object (the key to duplicate)
    let target_rsa = Rsa::generate_key(
        tpm.platform.crypto,
        &mut tpm.platform.rng,
        TpmiRsaKeyBits::Rsa2048,
        0,
    )
    .unwrap();
    let mut target_mod_buf = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let target_modulus = target_rsa
        .public_key()
        .modulus(&mut target_mod_buf)
        .unwrap();
    let mut target_prime_buf = [0u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES];
    let target_prime_p = target_rsa.prime_p(&mut target_prime_buf).unwrap();

    let target_handle = 0x80000001;
    let target_public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits::Rsa2048,
                exponent: 0,
            },
            target_modulus,
        ),
    };
    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&target_public, &mut pub_buf);
    let handler = tpm2_impl::handler::CommandHandler::new(&mut tpm, &mut global_state);
    let target_name = handler
        .compute_name(target_public.name_alg, &pub_buf[..pub_len])
        .unwrap();

    let target_obj = TransientObject {
        handle: target_handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[2u8; 32]).unwrap(),
        name: target_name,
        auth: Tpm2bAuth::default().into(),
        public: target_public.into(),
        sensitive: OwnedSensitiveComposite::Rsa(target_prime_p.into()),
        qualified_name: target_name,
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(target_obj.clone());

    // 2. Setup parent key P
    let parent_rsa = Rsa::generate_key(
        tpm.platform.crypto,
        &mut tpm.platform.rng,
        TpmiRsaKeyBits::Rsa2048,
        0,
    )
    .unwrap();
    let mut parent_mod_buf = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let parent_modulus = parent_rsa
        .public_key()
        .modulus(&mut parent_mod_buf)
        .unwrap();
    let mut parent_prime_buf = [0u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES];
    let parent_prime_p = parent_rsa.prime_p(&mut parent_prime_buf).unwrap();

    let sym_alg = TpmtSymDefObject {
        alg: AlgSym::Aes128,
        mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
    };

    let parent_handle = 0x80000002;
    let parent_obj = TransientObject {
        handle: parent_handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[3u8; 32]).unwrap(),
        name: Tpm2bName::new(&[4, 5, 6]).unwrap().into(),
        auth: Tpm2bAuth::default().into(),
        public: TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::DECRYPT
                | TpmaObject::RESTRICTED
                | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: Some(sym_alg),
                    scheme: None,
                    key_bits: TpmiRsaKeyBits::Rsa2048,
                    exponent: 0,
                },
                parent_modulus,
            ),
        }
        .into(),
        sensitive: OwnedSensitiveComposite::Rsa(parent_prime_p.into()),
        qualified_name: Tpm2bName::new(&[4, 5, 6]).unwrap().into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[1] = Some(parent_obj);

    // 3. Test Duplicate Edge Cases:
    // A. Invalid target object handle -> returns TpmRc::REFERENCE_H0
    let dup_handles_bad = DuplicateHandles {
        object_handle: Handle(0x80000009),
        new_parent_handle: Handle(parent_handle),
    };
    let dup_cmd = Duplicate {
        object_handle: Handle(target_handle),
        new_parent_handle: Handle(parent_handle),
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &dup_handles_bad,
        &dup_cmd,
        &[],
    );
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H0.get()));

    // B. Target object has fixedParent attribute -> returns TpmRc::ATTRIBUTES.with(Position::handle(1))
    global_state.transient_objects[0]
        .as_mut()
        .unwrap()
        .public
        .object_attributes
        .insert(TpmaObject::FIXED_PARENT);
    let dup_handles = DuplicateHandles {
        object_handle: Handle(target_handle),
        new_parent_handle: Handle(parent_handle),
    };
    let res =
        execute_tpm_command_with_auths(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::handle(1)).get())
    );
    // restore FIXED_PARENT
    global_state.transient_objects[0]
        .as_mut()
        .unwrap()
        .public
        .object_attributes
        .remove(TpmaObject::FIXED_PARENT);

    // C. New parent handle not found -> returns TpmRc::REFERENCE_H1
    let dup_handles_bad_parent = DuplicateHandles {
        object_handle: Handle(target_handle),
        new_parent_handle: Handle(0x80000009),
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &dup_handles_bad_parent,
        &dup_cmd,
        &[],
    );
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H1.get()));

    // D. New parent is not asymmetric -> returns TpmRc::TYPE.with(Position::handle(2))
    let bad_parent_obj = TransientObject {
        handle: 0x80000003,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: Tpm2bName::default().into(),
        auth: Tpm2bAuth::default().into(),
        public: TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::DECRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Sym(sym_alg, Tpm2bDigest::default()),
        }
        .into(),
        sensitive: OwnedSensitiveComposite::Sym(OwnedSymKey::from_bytes(&[0; 16]).unwrap()),
        qualified_name: Tpm2bName::default().into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[2] = Some(bad_parent_obj);
    let dup_handles_bad_type = DuplicateHandles {
        object_handle: Handle(target_handle),
        new_parent_handle: Handle(0x80000003),
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &dup_handles_bad_type,
        &dup_cmd,
        &[],
    );
    assert_eq!(res.err(), Some(TpmRc::TYPE.with(Position::handle(2)).get()));
    global_state.transient_objects[2] = None;

    // 4. Success Duplicate with inner wrapper (AES-128 CFB)
    let dup_cmd_sym = Duplicate {
        object_handle: Handle(target_handle),
        new_parent_handle: Handle(parent_handle),
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: Some(sym_alg),
    };
    let dup_resp = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &dup_handles,
        &dup_cmd_sym,
        &[],
    )
    .expect("Duplicate failed");
    assert!(!dup_resp.encryption_key_out.as_slice().is_empty());
    assert!(!dup_resp.duplicate.as_slice().is_empty());
    assert!(!dup_resp.out_sym_seed.as_slice().is_empty());

    // 5. Test Import Edge Cases:
    let object_public_2b = tpm2::Tpm2b(target_public);
    // A. Object attributes contains fixedTPM or fixedParent -> returns TpmRc::ATTRIBUTES.with(Position::parameter(2))
    let mut bad_target_public = target_public;
    bad_target_public
        .object_attributes
        .insert(TpmaObject::FIXED_TPM);
    let bad_object_public_2b = tpm2::Tpm2b(bad_target_public);
    let import_handles = ImportHandles {
        parent_handle: Handle(parent_handle),
    };
    let import_cmd_bad = Import {
        parent_handle: Handle(parent_handle),
        encryption_key: dup_resp.encryption_key_out,
        object_public: bad_object_public_2b,
        duplicate: dup_resp.duplicate,
        in_sym_seed: dup_resp.out_sym_seed,
        symmetric_alg: Some(sym_alg),
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &import_handles,
        &import_cmd_bad,
        &[],
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::parameter(2)).get())
    );

    // B. Encryption key size mismatch -> returns TpmRc::SIZE.with(Position::parameter(1))
    let import_cmd_bad_key = Import {
        parent_handle: Handle(parent_handle),
        encryption_key: Tpm2bData::new(&[0u8; 32]).unwrap(), // 32 bytes instead of 16
        object_public: object_public_2b,
        duplicate: dup_resp.duplicate,
        in_sym_seed: dup_resp.out_sym_seed,
        symmetric_alg: Some(sym_alg),
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &import_handles,
        &import_cmd_bad_key,
        &[],
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::SIZE.with(Position::parameter(1)).get())
    );

    // C. Outer integrity HMAC mismatch -> returns TpmRc::INTEGRITY
    let mut tampered_bytes = dup_resp.duplicate.as_slice().to_vec();
    let last_idx = tampered_bytes.len() - 1;
    tampered_bytes[last_idx] ^= 1; // Tamper with the duplicate bytes
    let tampered_duplicate = Tpm2bPrivate::new(&tampered_bytes).unwrap();
    let import_cmd_bad_hmac = Import {
        parent_handle: Handle(parent_handle),
        encryption_key: dup_resp.encryption_key_out,
        object_public: object_public_2b,
        duplicate: tampered_duplicate,
        in_sym_seed: dup_resp.out_sym_seed,
        symmetric_alg: Some(sym_alg),
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &import_handles,
        &import_cmd_bad_hmac,
        &[],
    );
    assert_eq!(res.err(), Some(TpmRc::INTEGRITY.get()));

    // 6. Success Import
    let import_cmd = Import {
        parent_handle: Handle(parent_handle),
        encryption_key: dup_resp.encryption_key_out,
        object_public: object_public_2b,
        duplicate: dup_resp.duplicate,
        in_sym_seed: dup_resp.out_sym_seed,
        symmetric_alg: Some(sym_alg),
    };
    let import_resp = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &import_handles,
        &import_cmd,
        &[],
    )
    .expect("Import failed");
    assert!(!import_resp.out_private.as_slice().is_empty());

    // 7. Test Load Edge Cases:
    // A. Parent transient object not found -> returns TpmRc::REFERENCE_H0
    let load_handles_bad = LoadHandles {
        parent_handle: Handle(0x80000009),
    };
    let load_cmd = Load {
        parent_handle: Handle(parent_handle),
        in_private: import_resp.out_private,
        in_public: object_public_2b,
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &load_handles_bad,
        &load_cmd,
        &[],
    );
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H0.get()));

    // B. Parent key does not have DECRYPT and RESTRICTED -> returns TpmRc::TYPE.with(Position::handle(1))
    global_state.transient_objects[1]
        .as_mut()
        .unwrap()
        .public
        .object_attributes
        .remove(TpmaObject::RESTRICTED);
    let load_handles = LoadHandles {
        parent_handle: Handle(parent_handle),
    };
    let res =
        execute_tpm_command_with_auths(&mut tpm, &mut global_state, &load_handles, &load_cmd, &[]);
    assert_eq!(res.err(), Some(TpmRc::TYPE.with(Position::handle(1)).get()));
    // restore attributes
    global_state.transient_objects[1]
        .as_mut()
        .unwrap()
        .public
        .object_attributes
        .insert(TpmaObject::RESTRICTED);

    // C. Integrity HMAC verification failed for load -> returns TpmRc::INTEGRITY
    let mut tampered_bytes = import_resp.out_private.as_slice().to_vec();
    let last_idx = tampered_bytes.len() - 1;
    tampered_bytes[last_idx] ^= 1;
    let tampered_private = Tpm2bPrivate::new(&tampered_bytes).unwrap();
    let load_cmd_bad_hmac = Load {
        parent_handle: Handle(parent_handle),
        in_private: tampered_private,
        in_public: object_public_2b,
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &load_handles,
        &load_cmd_bad_hmac,
        &[],
    );
    assert_eq!(res.err(), Some(TpmRc::INTEGRITY.get()));

    // D. Name alg is invalid (neither SHA256 nor SHA384 nor SHA1) -> returns TpmRc::VALUE
    let mut bad_name_alg_public = target_public;
    bad_name_alg_public.name_alg = Some(TpmiAlgHash::Sm3_256);
    let bad_name_alg_public_2b = tpm2::Tpm2b(bad_name_alg_public);
    let load_cmd_bad_alg = Load {
        parent_handle: Handle(parent_handle),
        in_private: import_resp.out_private,
        in_public: bad_name_alg_public_2b,
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &load_handles,
        &load_cmd_bad_alg,
        &[],
    );
    assert_eq!(res.err(), Some(TpmRc::VALUE.get()));

    // 8. Success Load
    let load_resp =
        execute_tpm_command_with_auths(&mut tpm, &mut global_state, &load_handles, &load_cmd, &[])
            .expect("Load failed");
    assert!(!load_resp.name.as_slice().is_empty());

    // Verify loaded object is now in transient storage and matches target
    let loaded_obj = global_state
        .transient_objects
        .iter()
        .flatten()
        .find(|obj| obj.name.as_slice() == load_resp.name.as_slice())
        .expect("Loaded object not found in transient objects");
    assert_eq!(loaded_obj.auth.get_buffer(), target_obj.auth.get_buffer());
    assert_eq!(loaded_obj.sensitive, target_obj.sensitive);
}

/// Generates an RSA-2048 key and returns its public modulus and first prime.
fn rsa_key_parts(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
) -> (
    tpm2_impl::owned::OwnedPublicKeyRsa,
    tpm2_impl::owned::OwnedPrivateKeyRsa,
) {
    let key = Rsa::generate_key(
        tpm.platform.crypto,
        &mut tpm.platform.rng,
        TpmiRsaKeyBits::Rsa2048,
        0,
    )
    .unwrap();
    let mut mod_buf = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let mut prime_buf = [0u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES];
    (
        key.public_key().modulus(&mut mod_buf).unwrap().into(),
        key.prime_p(&mut prime_buf).unwrap().into(),
    )
}

/// Returns a loadable RSA-2048 signing key with `name_alg` and `seed`, in the Owner hierarchy.
fn rsa_signing_key(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    handle: u32,
    name_alg: TpmiAlgHash,
    seed: &[u8],
) -> TransientObject {
    let (modulus, prime) = rsa_key_parts(tpm);
    let public = TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits::Rsa2048,
                exponent: 0,
            },
            modulus.as_tpm2b(),
        ),
    };
    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&public, &mut pub_buf);
    let name = tpm2_impl::handler::CommandHandler::new(tpm, global_state)
        .compute_name(public.name_alg, &pub_buf[..pub_len])
        .unwrap();
    TransientObject {
        handle,
        seed: tpm2_impl::owned::OwnedDigest::new(seed).unwrap(),
        name,
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        sensitive: OwnedSensitiveComposite::Rsa(prime),
        qualified_name: name,
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

/// Returns a loadable RSA-2048 storage parent (AES-128-CFB) with `name_alg`, in the Owner
/// hierarchy.
fn rsa_storage_parent(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    handle: u32,
    name_alg: TpmiAlgHash,
) -> TransientObject {
    let (modulus, prime) = rsa_key_parts(tpm);
    TransientObject {
        handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[3u8; 32]).unwrap(),
        name: Tpm2bName::new(&[4, 5, 6]).unwrap().into(),
        auth: Tpm2bAuth::default().into(),
        public: TpmtPublic {
            name_alg: Some(name_alg),
            object_attributes: TpmaObject::DECRYPT
                | TpmaObject::RESTRICTED
                | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: Some(TpmtSymDefObject {
                        alg: AlgSym::Aes128,
                        mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
                    }),
                    scheme: None,
                    key_bits: TpmiRsaKeyBits::Rsa2048,
                    exponent: 0,
                },
                modulus.as_tpm2b(),
            ),
        }
        .into(),
        sensitive: OwnedSensitiveComposite::Rsa(prime),
        qualified_name: Tpm2bName::new(&[4, 5, 6]).unwrap().into(),
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

/// `TPM2_Duplicate` with only an outer wrapper and no inner encryption key.
fn duplicate_outer_only(
    object_handle: u32,
    new_parent_handle: u32,
) -> (DuplicateHandles, Duplicate<'static>) {
    (
        DuplicateHandles {
            object_handle: Handle(object_handle),
            new_parent_handle: Handle(new_parent_handle),
        },
        Duplicate {
            object_handle: Handle(object_handle),
            new_parent_handle: Handle(new_parent_handle),
            encryption_key_in: Tpm2bData::default(),
            symmetric_alg: None,
        },
    )
}

/// The outer duplication wrapper (its integrity HMAC and the keys derived from the seed) uses the
/// new parent's nameAlg, not the duplicated object's (TPM 2.0 Part 1, "Outer Duplication Wrapper").
#[test]
fn test_duplicate_outer_wrapper_uses_new_parent_name_alg() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // A SHA-384 signing key (with a SHA-384-sized seed) and a SHA-256 storage parent.
    let target_handle = 0x80000001;
    let parent_handle = 0x80000002;
    let target = rsa_signing_key(
        &mut tpm,
        &mut global_state,
        target_handle,
        TpmiAlgHash::Sha384,
        &[7u8; 48],
    );
    let target_seed = target.seed;
    let object_public = target.public.as_tpm2b();
    global_state.transient_objects[0] = Some(target.clone());
    global_state.transient_objects[1] = Some(rsa_storage_parent(
        &mut tpm,
        parent_handle,
        TpmiAlgHash::Sha256,
    ));

    // `duplicate` starts with the outer integrity HMAC.
    let (dup_handles, dup_cmd) = duplicate_outer_only(target_handle, parent_handle);
    let dup_resp =
        execute_tpm_command_with_auths(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[])
            .expect("Duplicate failed");
    let duplicate = dup_resp.duplicate.as_slice();
    assert_eq!(
        usize::from(u16::from_be_bytes([duplicate[0], duplicate[1]])),
        TpmiAlgHash::Sha256.digest_size()
    );

    // Import and load it back under the same parent; the full 48-byte seed survives.
    let import_resp = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &ImportHandles {
            parent_handle: Handle(parent_handle),
        },
        &Import {
            parent_handle: Handle(parent_handle),
            encryption_key: Tpm2bData::default(),
            object_public,
            duplicate: dup_resp.duplicate,
            in_sym_seed: dup_resp.out_sym_seed,
            symmetric_alg: None,
        },
        &[],
    )
    .expect("Import failed");
    let load_resp = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &LoadHandles {
            parent_handle: Handle(parent_handle),
        },
        &Load {
            parent_handle: Handle(parent_handle),
            in_private: import_resp.out_private,
            in_public: object_public,
        },
        &[],
    )
    .expect("Load failed");
    let loaded_obj = global_state
        .transient_objects
        .iter()
        .flatten()
        .find(|obj| obj.handle == load_resp.object_handle.0)
        .expect("Loaded object not found in transient objects");
    assert_eq!(loaded_obj.seed, target_seed);
}

/// `TPM2_Duplicate` accepts a persistent new parent.
#[test]
fn test_duplicate_to_persistent_parent() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let target_handle = 0x80000001;
    let parent_handle = 0x80000002;
    let persistent_parent = 0x81000001;
    global_state.transient_objects[0] = Some(rsa_signing_key(
        &mut tpm,
        &mut global_state,
        target_handle,
        TpmiAlgHash::Sha256,
        &[2u8; 32],
    ));
    global_state.transient_objects[1] = Some(rsa_storage_parent(
        &mut tpm,
        parent_handle,
        TpmiAlgHash::Sha256,
    ));

    let owner_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: tpm2::TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bAuth::default(),
    };
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &EvictControlHandles {
            auth: Handle::RH_OWNER,
            object_handle: Handle(parent_handle),
        },
        &EvictControl {
            auth: Handle::RH_OWNER,
            object_handle: Handle(parent_handle),
            persistent_handle: Handle(persistent_parent),
        },
        &[owner_auth],
    )
    .expect("EvictControl failed");

    let (dup_handles, dup_cmd) = duplicate_outer_only(target_handle, persistent_parent);
    let dup_resp =
        execute_tpm_command_with_auths(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[])
            .expect("Duplicate to a persistent parent failed");
    assert!(!dup_resp.out_sym_seed.as_slice().is_empty());
}

/// Returns a loadable NIST P-256 storage parent (AES-128-CFB, SHA-256), in the Owner hierarchy.
fn ecc_storage_parent(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    handle: u32,
) -> TransientObject {
    let key = Ecc::generate_key(
        tpm.platform.crypto,
        &mut tpm.platform.rng,
        tpm2::TpmEccCurve::NistP256,
    )
    .unwrap();
    let mut x_buf = [0u8; tpm2::TpmEccCurve::MAX_ECC_KEY_BYTES];
    let mut y_buf = [0u8; tpm2::TpmEccCurve::MAX_ECC_KEY_BYTES];
    let point = key.public_key().point(&mut x_buf, &mut y_buf).unwrap();
    let mut d_buf = [0u8; tpm2::TpmEccCurve::MAX_ECC_KEY_BYTES];
    let scalar = key.scalar(&mut d_buf).unwrap();
    TransientObject {
        handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[5u8; 32]).unwrap(),
        name: Tpm2bName::new(&[7, 8, 9]).unwrap().into(),
        auth: Tpm2bAuth::default().into(),
        public: TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::DECRYPT
                | TpmaObject::RESTRICTED
                | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Ecc(
                tpm2::TpmsEccParms {
                    symmetric: Some(TpmtSymDefObject {
                        alg: AlgSym::Aes128,
                        mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
                    }),
                    scheme: None,
                    curve_id: tpm2::TpmEccCurve::NistP256,
                    kdf: None,
                },
                point,
            ),
        }
        .into(),
        sensitive: OwnedSensitiveComposite::Ecc(scalar.into()),
        qualified_name: Tpm2bName::new(&[7, 8, 9]).unwrap().into(),
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

/// `TPM2_Rewrap` moves a duplication blob from an ECC parent to an RSA parent, and the result
/// imports under the RSA parent.
#[test]
fn test_rewrap_from_ecc_parent_to_rsa_parent() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let target_handle = 0x80000001;
    let ecc_parent = 0x80000002;
    let rsa_parent = 0x80000003;
    let target = rsa_signing_key(
        &mut tpm,
        &mut global_state,
        target_handle,
        TpmiAlgHash::Sha256,
        &[2u8; 32],
    );
    let object_public = target.public.as_tpm2b();
    global_state.transient_objects[0] = Some(target.clone());
    global_state.transient_objects[1] = Some(ecc_storage_parent(&mut tpm, ecc_parent));
    global_state.transient_objects[2] = Some(rsa_storage_parent(
        &mut tpm,
        rsa_parent,
        TpmiAlgHash::Sha256,
    ));

    let (dup_handles, dup_cmd) = duplicate_outer_only(target_handle, ecc_parent);
    let dup_resp =
        execute_tpm_command_with_auths(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[])
            .expect("Duplicate failed");

    let rewrap_resp = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &RewrapHandles {
            old_parent: Handle(ecc_parent),
            new_parent: Handle(rsa_parent),
        },
        &Rewrap {
            old_parent: Handle(ecc_parent),
            new_parent: Handle(rsa_parent),
            in_duplicate: dup_resp.duplicate,
            name: target.name.as_tpm2b(),
            in_sym_seed: dup_resp.out_sym_seed,
        },
        &[],
    )
    .expect("Rewrap failed");

    let import_resp = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &ImportHandles {
            parent_handle: Handle(rsa_parent),
        },
        &Import {
            parent_handle: Handle(rsa_parent),
            encryption_key: Tpm2bData::default(),
            object_public,
            duplicate: rewrap_resp.out_duplicate,
            in_sym_seed: rewrap_resp.out_sym_seed,
            symmetric_alg: None,
        },
        &[],
    )
    .expect("Import failed");
    execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &LoadHandles {
            parent_handle: Handle(rsa_parent),
        },
        &Load {
            parent_handle: Handle(rsa_parent),
            in_private: import_resp.out_private,
            in_public: object_public,
        },
        &[],
    )
    .expect("Load failed");
}
