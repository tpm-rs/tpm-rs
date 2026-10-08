use common::marshal_to_slice;
use tpm2::errors::{Position, TpmRc};

use tpm2::Unmarshal;
extern crate alloc;

mod common;

use common::{FakeRng, FakeStorage, FakeTimer};
use tpm2::commands::{
    Command, PolicyCommandCode, PolicyCommandCodeHandles, PolicyGetDigest, PolicyGetDigestHandles,
};
use tpm2::{Handle, Marshal, TpmCc};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bName, Tpm2bNonce, Tpm2bPrivate,
    Tpm2bPublicKeyRsa, TpmaObject, TpmiAlgHash, TpmsAuthCommand, TpmtPublic, TpmtSymDefObject,
};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::TransientObject;

use hex_literal::hex;
use tpm2::crypto::Rng;
use tpm2::crypto::{Asymmetric, AsymmetricSign};
use tpm2::crypto::{CryptoError, CryptoProvider};

struct StressTestCrypto;

impl_fake_hash!(StressTestCrypto);

impl AsymmetricSign for StressTestCrypto {
    fn sign_inner(
        &self,
        sign_alg: tpm2::Alg,
        _private_key: &[u8],
        _digest: tpm2::TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let len = match sign_alg {
            tpm2::Alg::ECDSA => {
                if signature_out.len() < 64 {
                    return Err(CryptoError::BufferTooSmall);
                }
                signature_out[..64].fill(0xee);
                64
            }
            _ => {
                if signature_out.len() < 256 {
                    return Err(CryptoError::BufferTooSmall);
                }
                signature_out[..256].fill(0xee);
                256
            }
        };
        Ok(len)
    }
}

impl Asymmetric for StressTestCrypto {
    fn verify_inner(
        &self,
        _sign_alg: tpm2::Alg,
        _public_key: &[u8],
        _digest: tpm2::TpmtHa<'_>,
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }
    fn encrypt(
        &self,
        scheme: tpm2::Alg,
        _hash_alg: tpm2::Alg,
        public_key: &[u8],
        data: &[u8],
        ciphertext: &mut [u8],
        _label: &[u8],
    ) -> Result<usize, CryptoError> {
        let len = data.len();
        let out_len = if scheme == tpm2::Alg::OAEP && !public_key.is_empty() {
            public_key.len()
        } else {
            len
        };
        if ciphertext.len() < out_len {
            return Err(CryptoError::BufferTooSmall);
        }
        ciphertext[..len].copy_from_slice(data);
        if out_len > len {
            ciphertext[len..out_len].fill(0);
        }
        Ok(out_len)
    }
    fn decrypt(
        &self,
        scheme: tpm2::Alg,
        _hash_alg: tpm2::Alg,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        _label: &[u8],
    ) -> Result<usize, CryptoError> {
        if private_key.is_empty() {
            return Err(CryptoError::HardwareFailure);
        }
        let len = if scheme == tpm2::Alg::OAEP && ciphertext.len() > 32 {
            32
        } else {
            ciphertext.len()
        };
        if plaintext.len() < len {
            return Err(CryptoError::BufferTooSmall);
        }
        plaintext[..len].copy_from_slice(&ciphertext[..len]);
        Ok(len)
    }
    fn generate_key(
        &self,
        scheme: tpm2::Alg,
        _params: Option<tpm2::crypto::asymmetric::KeyParams>,
        public_key: &mut [u8],
        private_key: &mut [u8],
        _seed: Option<&[u8]>,
    ) -> Result<(usize, usize), CryptoError> {
        match scheme {
            tpm2::Alg::RSA => {
                public_key[..256].fill(0xcc);
                private_key[..256].fill(0xdd);
                Ok((256, 256))
            }
            tpm2::Alg::ECC => {
                public_key[..64].fill(0xcc);
                private_key[..32].fill(0xdd);
                Ok((64, 32))
            }
            _ => Err(CryptoError::HardwareFailure),
        }
    }
    fn rsa_import_private_key(
        &self,
        modulus: &[u8],
        prime_p: &[u8],
        exponent: u32,
        private_key_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let _ = modulus;
        let _ = exponent;
        if private_key_out.len() < prime_p.len() * 2 {
            return Err(CryptoError::BufferTooSmall);
        }
        private_key_out[..prime_p.len()].copy_from_slice(prime_p);
        private_key_out[prime_p.len()..prime_p.len() * 2].copy_from_slice(prime_p);
        Ok(prime_p.len() * 2)
    }
    fn rsa_private_key_to_prime_p(
        &self,
        private_key: &[u8],
        prime_p_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let half_len = private_key.len() / 2;
        if prime_p_out.len() < half_len {
            return Err(CryptoError::BufferTooSmall);
        }
        prime_p_out[..half_len].copy_from_slice(&private_key[..half_len]);
        Ok(half_len)
    }
}

impl Rng for StressTestCrypto {
    fn get_random(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        dest.fill(0xaa);
        Ok(())
    }
}

impl CryptoProvider for StressTestCrypto {}

fn setup_tpm<'a>(
    crypto: &'a mut StressTestCrypto,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a FakeRng,
) -> (
    TpmEngine<'a, StressTestCrypto, FakeStorage, FakeTimer, FakeRng>,
    tpm2_impl::GlobalState,
) {
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
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

fn execute_tpm_command_with_auths<C: Command>(
    tpm: &mut TpmEngine<'_, StressTestCrypto, FakeStorage, FakeTimer, FakeRng>,
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

    // Tag
    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    // Command code
    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    let handles_slice: &mut <C::Handles as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C::Handles as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let handles_len = handles.marshal(handles_slice);
    offset += handles_len;

    // Marshal auth area if tag is 0x8002
    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4; // place holder for auth size
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

    let cmd_slice: &mut <C as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let cmd_len = cmd.marshal(cmd_slice);
    offset += cmd_len;

    // Fill in total Size
    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut response_buf = [0u8; 16384];
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);
    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    fn resp_handles_size(cc: tpm2::TpmCc) -> usize {
        match cc {
            tpm2::TpmCc::CreatePrimary
            | tpm2::TpmCc::StartAuthSession
            | tpm2::TpmCc::ContextLoad
            | tpm2::TpmCc::CreateLoaded
            | tpm2::TpmCc::LoadExternal
            | tpm2::TpmCc::Load => 4,
            _ => 0,
        }
    }

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    let handles_size = resp_handles_size(C::CMD_CODE);
    let params_offset = if resp_tag == 0x8002 {
        10 + handles_size + 4 // Skip header (10), handles, and parameter size (4)
    } else {
        10 + handles_size // Skip header (10) and handles
    };

    let mut unmarshal_buf: &'static [u8] =
        std::vec::Vec::leak(response_buf[params_offset..resp_size].to_vec());
    let resp =
        <C::Response<'static>>::unmarshal(&mut unmarshal_buf).map_err(|_| TpmRc::FAILURE.get())?;
    Ok(resp)
}

#[test]
fn test_policy_command_code_success_and_errors() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Session not found -> returns TpmRc::HANDLE (0x80)
    let cmd = PolicyCommandCode {
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
        session_type: tpm2::TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::default()).into(),
        nonce_caller: (Tpm2bNonce::default()).into(),
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
    let res = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &handles, &cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::handle(1)).get())
    );

    // 3. Create a valid Policy session
    let policy_session = tpm2_impl::handler::SessionState {
        session_handle: 0x03000001,
        session_type: tpm2::TpmSe::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::default()).into(),
        nonce_caller: (Tpm2bNonce::default()).into(),
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
        code: TpmCc::Duplicate,
    };
    let res = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &handles, &cmd, &[]);
    assert!(res.is_ok());

    // Verify policy_digest updated and command_code set
    {
        let session = global_state.session(0x03000001).unwrap();
        assert_eq!(session.command_code, (TpmCc::Duplicate.code()));
        assert_ne!(
            session.policy_digest[..session.policy_digest_len],
            [0u8; 32]
        );
    }

    // 6. Calling again with a different command code (e.g. TpmCc::Import) -> returns TpmRc::VALUE (0x44)
    let cmd_different = PolicyCommandCode {
        code: TpmCc::Import,
    };
    let res =
        execute_tpm_command_with_auths(&mut tpm, &mut global_state, &handles, &cmd_different, &[]);
    assert_eq!(res.err(), Some(TpmRc::VALUE.get()));
}

#[test]
fn test_policy_get_digest() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Session not found -> returns TpmRc::HANDLE
    let cmd = PolicyGetDigest {};
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
        session_type: tpm2::TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::default()).into(),
        nonce_caller: (Tpm2bNonce::default()).into(),
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
        session_type: tpm2::TpmSe::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::default()).into(),
        nonce_caller: (Tpm2bNonce::default()).into(),
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
    let res = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &handles, &cmd, &[]);
    assert!(res.is_ok());
    let resp = res.unwrap();
    assert_eq!(resp.policy_digest.get_buffer(), &[0xa5; 32]);
}

#[test]
fn test_duplicate_import_load_roundtrip() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Setup target object (the key to duplicate)
    let target_handle = 0x80000001;
    let target_public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH, // fixedParent and fixedTPM are clear
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            tpm2::TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(&[0x11; 256]).unwrap(),
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
        seed: [2u8; 32],
        name: target_name,
        auth: (Tpm2bAuth::default()).into(),
        public: (target_public).into(),
        private: [0x33; 1536],
        private_len: 256,
        qualified_name: target_name,
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(target_obj.clone());

    // 2. Setup parent key P
    let parent_handle = 0x80000002;
    let parent_obj = TransientObject {
        handle: parent_handle,
        seed: [3u8; 32],
        name: (Tpm2bName::from_bytes(&[4, 5, 6]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            // Restricted storage key attributes: DECRYPT | RESTRICTED | USER_WITH_AUTH
            object_attributes: TpmaObject::DECRYPT
                | TpmaObject::RESTRICTED
                | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                tpm2::TpmsRsaParms {
                    symmetric: Some(TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB))),
                    scheme: None,
                    key_bits: tpm2::TpmiRsaKeyBits(2048),
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::from_bytes(&[0xbb; 256]).unwrap(), // unique parent modulus
            ),
        })
        .into(),
        private: [0x55; 1536],
        private_len: 256,
        qualified_name: (Tpm2bName::from_bytes(&[4, 5, 6]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[1] = Some(parent_obj);

    // 3. Test Duplicate Edge Cases:
    // A. Invalid target object handle -> returns TpmRc::HANDLE.with(Position::handle(1))
    let dup_handles_bad = tpm2::commands::DuplicateHandles {
        object_handle: Handle(0x80000009),
        new_parent_handle: Handle(parent_handle),
    };
    let dup_cmd = tpm2::commands::Duplicate {
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
    let dup_handles = tpm2::commands::DuplicateHandles {
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

    // C. New parent handle not found -> returns TpmRc::HANDLE.with(Position::handle(2))
    let dup_handles_bad_parent = tpm2::commands::DuplicateHandles {
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
        seed: [0; 32],
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::DECRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Sym(
                TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB)),
                Tpm2bDigest::default(),
            ),
        })
        .into(),
        private: [0; 1536],
        private_len: 16,
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[2] = Some(bad_parent_obj);
    let dup_handles_bad_type = tpm2::commands::DuplicateHandles {
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
    let sym_alg = TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB));
    let dup_cmd_sym = tpm2::commands::Duplicate {
        encryption_key_in: Tpm2bData::default(), // TPM should generate one
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
    assert!(dup_resp.encryption_key_out.get_size() > 0);
    assert!(dup_resp.duplicate.get_size() > 0);
    assert!(dup_resp.out_sym_seed.get_size() > 0);

    // 5. Test Import Edge Cases:
    let object_public_2b = tpm2::Tpm2b(target_public);
    // A. Object attributes contains fixedTPM or fixedParent -> returns TpmRc::ATTRIBUTES.with(Position::parameter(2))
    let mut bad_target_public = target_public;
    bad_target_public
        .object_attributes
        .insert(TpmaObject::FIXED_TPM);
    let bad_object_public_2b = tpm2::Tpm2b(bad_target_public);
    let import_handles = tpm2::commands::ImportHandles {
        parent_handle: Handle(parent_handle),
    };
    let import_cmd_bad = tpm2::commands::Import {
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
    let import_cmd_bad_key = tpm2::commands::Import {
        encryption_key: Tpm2bData::from_bytes(&[0u8; 32]).unwrap(), // 32 bytes instead of 16
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
    let mut tampered_bytes = dup_resp.duplicate.get_buffer().to_vec();
    let last_idx = tampered_bytes.len() - 1;
    tampered_bytes[last_idx] ^= 1; // Tamper with the duplicate bytes
    let tampered_duplicate = Tpm2bPrivate::from_bytes(&tampered_bytes).unwrap();
    let import_cmd_bad_hmac = tpm2::commands::Import {
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
    let import_cmd = tpm2::commands::Import {
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
    assert!(import_resp.out_private.get_size() > 0);

    // 7. Test Load Edge Cases:
    // A. Parent transient object not found -> returns TpmRc::HANDLE
    let load_handles_bad = tpm2::commands::LoadHandles {
        parent_handle: Handle(0x80000009),
    };
    let load_cmd = tpm2::commands::Load {
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
    // Modify parent's attributes to remove RESTRICTED
    global_state.transient_objects[1]
        .as_mut()
        .unwrap()
        .public
        .object_attributes
        .remove(TpmaObject::RESTRICTED);
    let load_handles = tpm2::commands::LoadHandles {
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
    let mut tampered_bytes = import_resp.out_private.get_buffer().to_vec();
    let last_idx = tampered_bytes.len() - 1;
    tampered_bytes[last_idx] ^= 1; // Tamper with the private bytes
    let tampered_private = Tpm2bPrivate::from_bytes(&tampered_bytes).unwrap();
    let load_cmd_bad_hmac = tpm2::commands::Load {
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
    let load_cmd_bad_alg = tpm2::commands::Load {
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
    assert!(load_resp.name.get_size() > 0);

    // Verify loaded object is now in transient storage and matches target
    let loaded_obj = global_state
        .transient_objects
        .iter()
        .flatten()
        .find(|obj| obj.name == load_resp.name)
        .expect("Loaded object not found in transient objects");
    assert_eq!(loaded_obj.auth.get_buffer(), target_obj.auth.get_buffer());
    assert_eq!(
        &loaded_obj.private[..loaded_obj.private_len],
        &target_obj.private[..target_obj.private_len]
    );
}
