use common::marshal_to_slice;

use tpm2::{Marshal, Unmarshal};
extern crate alloc;

mod common;

use alloc::vec::Vec;
use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::Handle;
use tpm2::commands::{
    Certify, CertifyHandles, Command, Load, LoadHandles, ObjectChangeAuth, ObjectChangeAuthHandles,
};
use tpm2::crypto::Rng;
use tpm2::crypto::{Asymmetric, AsymmetricSign};
use tpm2::crypto::{CryptoError, CryptoProvider};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Alg, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bNonce, Tpm2bPublicKeyRsa,
    TpmaObject, TpmaSession, TpmiAlgHash, TpmsAuthCommand, TpmtPublic, TpmtSymDefObject,
};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::TransientObject;

struct ChallengerCrypto {
    crypto: TestCryptoProvider,
}

impl_delegate_hash!(ChallengerCrypto, crypto);

impl AsymmetricSign for ChallengerCrypto {
    fn sign_inner(
        &self,
        _sign_alg: Alg,
        _private_key: &[u8],
        _digest: tpm2::TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let len = 256;
        if signature_out.len() < len {
            return Err(CryptoError::BufferTooSmall);
        }
        signature_out[..len].fill(0xbb);
        Ok(len)
    }
}

impl Asymmetric for ChallengerCrypto {
    fn verify_inner(
        &self,
        sign_alg: Alg,
        public_key: &[u8],
        digest: tpm2::TpmtHa<'_>,
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.crypto
            .verify_inner(sign_alg, public_key, digest, signature)
    }
    fn encrypt(
        &self,
        scheme: Alg,
        hash_alg: Alg,
        public_key: &[u8],
        data: &[u8],
        ciphertext: &mut [u8],
        label: &[u8],
    ) -> Result<usize, CryptoError> {
        self.crypto
            .encrypt(scheme, hash_alg, public_key, data, ciphertext, label)
    }
    fn decrypt(
        &self,
        scheme: Alg,
        hash_alg: Alg,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        label: &[u8],
    ) -> Result<usize, CryptoError> {
        if private_key.iter().all(|&b| b == 0) {
            let len = ciphertext.len();
            plaintext[..len].copy_from_slice(ciphertext);
            Ok(len)
        } else {
            self.crypto
                .decrypt(scheme, hash_alg, private_key, ciphertext, plaintext, label)
        }
    }
    fn generate_key(
        &self,
        scheme: Alg,
        params: Option<tpm2::crypto::asymmetric::KeyParams>,
        public_key: &mut [u8],
        private_key: &mut [u8],
        seed: Option<&[u8]>,
    ) -> Result<(usize, usize), CryptoError> {
        self.crypto
            .generate_key(scheme, params, public_key, private_key, seed)
    }
    fn rsa_private_key_to_prime_p(
        &self,
        private_key: &[u8],
        prime_p_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if private_key.iter().all(|&b| b == 0) {
            let len = 128; // Standard size for 2048-bit RSA prime P (1024 bits)
            if prime_p_out.len() < len {
                return Err(CryptoError::BufferTooSmall);
            }
            prime_p_out[..len].fill(0xaa);
            Ok(len)
        } else {
            self.crypto
                .rsa_private_key_to_prime_p(private_key, prime_p_out)
        }
    }
    fn rsa_import_private_key(
        &self,
        modulus: &[u8],
        prime_p: &[u8],
        exponent: u32,
        private_key_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if modulus.iter().all(|&b| b == 0) {
            let len = 256;
            if private_key_out.len() < len {
                return Err(CryptoError::BufferTooSmall);
            }
            private_key_out[..len].fill(0);
            Ok(len)
        } else {
            self.crypto
                .rsa_import_private_key(modulus, prime_p, exponent, private_key_out)
        }
    }
}

impl Rng for ChallengerCrypto {
    fn get_random(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        self.crypto.get_random(dest)
    }
}

impl CryptoProvider for ChallengerCrypto {}

fn setup_tpm<'a>(
    crypto: &'a mut ChallengerCrypto,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a FakeRng,
) -> (
    TpmEngine<'a, ChallengerCrypto, FakeStorage, FakeTimer, FakeRng>,
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

fn execute_tpm_command<C: Command>(
    tpm: &mut TpmEngine<'_, ChallengerCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &C::Handles,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<(C::RespHandles, C::Response<'static>), u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <<C as Command>::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: Unmarshal<'static>,
{
    let mut request_buf = [0u8; 32768];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    let handles_slice: &mut <C::Handles as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C::Handles as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let handles_len = handles.marshal(handles_slice);
    offset += handles_len;

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

    let cmd_slice: &mut <C as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let cmd_len = cmd.marshal(cmd_slice);
    offset += cmd_len;
    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut response_buf = [0u8; 32768];
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut resp_offset = 10;
    let mut handles_slice = &response_buf[resp_offset..resp_size];
    let orig_handles_len = handles_slice.len();
    let resp_handles =
        C::RespHandles::unmarshal(&mut handles_slice).map_err(|_| TpmRc::FAILURE.get())?;

    let handles_len = orig_handles_len - handles_slice.len();
    resp_offset += handles_len;

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        resp_offset += 4; // Skip parameter size
    }

    let mut params_slice: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
    let resp_params =
        <C::Response<'static>>::unmarshal(&mut params_slice).map_err(|_| TpmRc::FAILURE.get())?;

    Ok((resp_handles, resp_params))
}

fn execute_tpm_certify<'a>(
    tpm: &mut TpmEngine<'_, ChallengerCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &CertifyHandles,
    cmd: &Certify,
    auths: &[TpmsAuthCommand],
    response_buf: &'a mut [u8; 32768],
) -> Result<<Certify<'static> as Command>::Response<'a>, u32> {
    let mut request_buf = [0u8; 32768];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(Certify::CMD_CODE.code()).to_be_bytes());

    let mut handles_buf = [0u8; CertifyHandles::MAX_SIZE];
    let handles_len = handles.marshal(&mut handles_buf);
    request_buf[offset..offset + handles_len].copy_from_slice(&handles_buf.as_ref()[..handles_len]);
    offset += handles_len;

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

    let mut cmd_buf = [0u8; Certify::MAX_SIZE];
    let cmd_len = cmd.marshal(&mut cmd_buf);
    request_buf[offset..offset + cmd_len].copy_from_slice(&cmd_buf.as_ref()[..cmd_len]);
    offset += cmd_len;
    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut resp_offset = 10;
    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        resp_offset += 4; // Skip parameter size
    }

    let mut params_slice = &response_buf[resp_offset..resp_size];
    Unmarshal::unmarshal(&mut params_slice).map_err(|_| TpmRc::FAILURE.get())
}

fn compute_name_from_bytes(name_alg: TpmiAlgHash, bytes: &[u8]) -> Tpm2bName<'static> {
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let d = tpm2::crypto::hash(&TestCryptoProvider, name_alg, bytes, &mut out)
        .unwrap()
        .digest();
    let mut res = [0u8; 66];
    name_alg.marshal((&mut res[0..2]).try_into().unwrap());
    res[2..2 + d.len()].copy_from_slice(d);
    Tpm2bName::from_bytes(std::vec::Vec::leak(res[..2 + d.len()].to_vec())).unwrap()
}

fn compute_qn(name_alg: TpmiAlgHash, parent_qn: &[u8], object_name: &[u8]) -> Tpm2bName<'static> {
    let mut data = Vec::new();
    data.extend_from_slice(parent_qn);
    data.extend_from_slice(object_name);
    compute_name_from_bytes(name_alg, &data)
}

fn make_parent_object(handle: u32, qn: Tpm2bName) -> TransientObject {
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
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
            Tpm2bPublicKeyRsa::from_bytes(&[0u8; 256]).unwrap(),
        ),
    };

    TransientObject {
        handle,
        seed: [1u8; 32],
        name: qn.into(),
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        private: [0u8; 1536],
        private_len: 256,
        qualified_name: qn.into(),
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

fn make_transient_object(
    handle: u32,
    name_alg: TpmiAlgHash,
    auth_val: &[u8],
    qualified_name: Tpm2bName,
) -> TransientObject {
    let public = TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, tpm2::Tpm2bDigest::default()),
    };

    let key_bytes = b"key_bytes_12345678";
    let mut private = [0u8; 1536];
    private[..key_bytes.len()].copy_from_slice(key_bytes);

    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&public, &mut pub_buf);

    let digest_bytes = compute_name_from_bytes(name_alg, &pub_buf[..pub_len]);

    TransientObject {
        handle,
        seed: [0u8; 32],
        name: digest_bytes.into(),
        auth: Tpm2bAuth::from_bytes(auth_val).unwrap().into(),
        public: public.into(),
        private,
        private_len: key_bytes.len(),
        qualified_name: qualified_name.into(),
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

fn make_transient_rsa_object(
    handle: u32,
    name_alg: TpmiAlgHash,
    auth_val: &[u8],
    qualified_name: Tpm2bName,
) -> TransientObject {
    let public = TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            tpm2::TpmsRsaParms {
                symmetric: None,
                scheme: Some(tpm2::TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(&[0u8; 256]).unwrap(),
        ),
    };

    let private = [0u8; 1536];
    let private_len = 256;

    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&public, &mut pub_buf);

    let digest_bytes = compute_name_from_bytes(name_alg, &pub_buf[..pub_len]);

    TransientObject {
        handle,
        seed: [0u8; 32],
        name: digest_bytes.into(),
        auth: Tpm2bAuth::from_bytes(auth_val).unwrap().into(),
        public: public.into(),
        private,
        private_len,
        qualified_name: qualified_name.into(),
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

#[test]
fn test_object_change_auth_success() {
    let crypto = TestCryptoProvider;
    let mut crypto = ChallengerCrypto { crypto };
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let parent_handle = 0x80000000;
    let object_handle = 0x80000001;

    let parent_qn = Tpm2bName::from_bytes(&[5, 6, 7, 8]).unwrap();
    let parent = make_parent_object(parent_handle, parent_qn);

    let dummy_qn = Tpm2bName::from_bytes(&[0; 4]).unwrap();
    let temp_obj =
        make_transient_rsa_object(object_handle, TpmiAlgHash::Sha256, b"oldauth", dummy_qn);
    let obj_name = temp_obj.name;

    let correct_qn = compute_qn(
        TpmiAlgHash::Sha256,
        parent_qn.get_buffer(),
        obj_name.get_buffer(),
    );
    let obj = make_transient_rsa_object(object_handle, TpmiAlgHash::Sha256, b"oldauth", correct_qn);

    global_state.transient_objects[0] = Some(parent);
    global_state.transient_objects[1] = Some(obj.clone());

    let handles = ObjectChangeAuthHandles {
        object_handle: Handle(object_handle),
        parent_handle: Handle(parent_handle),
    };
    let cmd = ObjectChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(b"newauth").unwrap(),
    };

    let old_auth_session = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(b"oldauth").unwrap(),
    };

    let (_, rsp) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &[old_auth_session],
    )
    .unwrap();

    global_state.transient_objects[1] = None;

    let temp_obj2 =
        make_transient_rsa_object(object_handle, TpmiAlgHash::Sha256, b"oldauth", dummy_qn);
    let in_public = tpm2::Tpm2b(temp_obj2.public.as_tpmt());

    let load_handles = LoadHandles {
        parent_handle: Handle(parent_handle),
    };
    let load_cmd = Load {
        in_private: rsp.out_private,
        in_public,
    };

    let (load_resp_handles, load_rsp) =
        execute_tpm_command(&mut tpm, &mut global_state, &load_handles, &load_cmd, &[]).unwrap();

    assert_eq!(load_rsp.name, obj_name);

    let target_handle = 0x80000003;
    let target_obj = make_transient_object(target_handle, TpmiAlgHash::Sha256, &[], dummy_qn);
    global_state.transient_objects[2] = Some(target_obj);

    let certify_handles = CertifyHandles {
        object_handle: Handle(target_handle),
        sign_handle: load_resp_handles.object_handle,
    };
    let certify_cmd = Certify {
        qualifying_data: tpm2::Tpm2bData::default(),
        in_scheme: None,
    };

    let target_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };
    let new_auth_session = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(b"newauth").unwrap(),
    };

    let mut response_buf = [0u8; 32768];
    let certify_res = execute_tpm_certify(
        &mut tpm,
        &mut global_state,
        &certify_handles,
        &certify_cmd,
        &[target_auth, new_auth_session],
        &mut response_buf,
    );
    match certify_res {
        Ok(_) => {}
        Err(e) => {
            panic!(
                "Failed to authenticate with new auth value! Error: 0x{:X}",
                e
            );
        }
    }
}

#[test]
fn test_object_change_auth_oversized_auth() {
    let crypto = TestCryptoProvider;
    let mut crypto = ChallengerCrypto { crypto };
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let parent_handle = 0x80000001;
    let object_handle = 0x80000002;

    let parent_qn = Tpm2bName::from_bytes(&[5, 6, 7, 8]).unwrap();
    let parent = make_parent_object(parent_handle, parent_qn);

    let dummy_qn = Tpm2bName::from_bytes(&[0; 4]).unwrap();
    let temp_obj = make_transient_object(object_handle, TpmiAlgHash::Sha256, b"oldauth", dummy_qn);
    let obj_name = temp_obj.name;
    let correct_qn = compute_qn(
        TpmiAlgHash::Sha256,
        parent_qn.get_buffer(),
        obj_name.get_buffer(),
    );
    let obj = make_transient_object(object_handle, TpmiAlgHash::Sha256, b"oldauth", correct_qn);

    global_state.transient_objects[0] = Some(parent);
    global_state.transient_objects[1] = Some(obj);

    let handles = ObjectChangeAuthHandles {
        object_handle: Handle(object_handle),
        parent_handle: Handle(parent_handle),
    };

    let cmd = ObjectChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(&[1u8; 33]).unwrap(),
    };

    let old_auth_session = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(b"oldauth").unwrap(),
    };

    let res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &[old_auth_session],
    );
    assert!(res.is_err());
    let err_code = res.err().unwrap();
    assert_eq!(err_code, TpmRc::SIZE.with(Position::parameter(1)).get());
}

#[test]
fn test_object_change_auth_mismatched_parent() {
    let crypto = TestCryptoProvider;
    let mut crypto = ChallengerCrypto { crypto };
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let parent_handle = 0x80000001;
    let object_handle = 0x80000002;
    let wrong_parent_handle = 0x80000003;

    let parent_qn = Tpm2bName::from_bytes(&[5, 6, 7, 8]).unwrap();
    let parent = make_parent_object(parent_handle, parent_qn);

    let dummy_qn = Tpm2bName::from_bytes(&[0; 4]).unwrap();
    let temp_obj = make_transient_object(object_handle, TpmiAlgHash::Sha256, b"oldauth", dummy_qn);
    let obj_name = temp_obj.name;
    let correct_qn = compute_qn(
        TpmiAlgHash::Sha256,
        parent_qn.get_buffer(),
        obj_name.get_buffer(),
    );
    let obj = make_transient_object(object_handle, TpmiAlgHash::Sha256, b"oldauth", correct_qn);

    let wrong_parent_qn = Tpm2bName::from_bytes(&[9, 9, 9, 9]).unwrap();
    let wrong_parent = make_parent_object(wrong_parent_handle, wrong_parent_qn);

    global_state.transient_objects[0] = Some(parent);
    global_state.transient_objects[1] = Some(obj);
    global_state.transient_objects[2] = Some(wrong_parent);

    let handles = ObjectChangeAuthHandles {
        object_handle: Handle(object_handle),
        parent_handle: Handle(wrong_parent_handle),
    };
    let cmd = ObjectChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(b"newauth").unwrap(),
    };

    let old_auth_session = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(b"oldauth").unwrap(),
    };

    let res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &[old_auth_session],
    );
    assert!(res.is_err());
    let err_code = res.err().unwrap();
    assert_eq!(err_code, TpmRc::TYPE.with(Position::handle(2)).get());
}

#[test]
fn test_object_change_auth_active_sequence() {
    let crypto = TestCryptoProvider;
    let mut crypto = ChallengerCrypto { crypto };
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let parent_handle = 0x80000001;
    let object_handle = 0x80000002;

    let parent_qn = Tpm2bName::from_bytes(&[5, 6, 7, 8]).unwrap();
    let parent = make_parent_object(parent_handle, parent_qn);

    let active_seq = tpm2_impl::ActiveSequence::new(
        object_handle,
        Tpm2bAuth::default(),
        tpm2_impl::SequenceType::Hash {
            alg: TpmiAlgHash::Sha256,
        },
    );
    global_state.active_sequences[0] = Some(active_seq);
    global_state.transient_objects[0] = Some(parent);

    let handles = ObjectChangeAuthHandles {
        object_handle: Handle(object_handle),
        parent_handle: Handle(parent_handle),
    };
    let cmd = ObjectChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(b"newauth").unwrap(),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]);
    assert!(res.is_err());
    let err_code = res.err().unwrap();
    assert_eq!(err_code, TpmRc::TYPE.with(Position::handle(1)).get());
}

#[test]
fn test_object_change_auth_on_nv_index() {
    let crypto = TestCryptoProvider;
    let mut crypto = ChallengerCrypto { crypto };
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let parent_handle = 0x40000001;
    let object_handle = 0x01400001; // NV Index

    let handles = ObjectChangeAuthHandles {
        object_handle: Handle(object_handle),
        parent_handle: Handle(parent_handle),
    };
    let cmd = ObjectChangeAuth {
        new_auth: Tpm2bAuth::from_bytes(b"newauth").unwrap(),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]);
    assert!(res.is_err());
    let err_code = res.err().unwrap();
    assert_eq!(err_code, TpmRc::VALUE.with(Position::handle(1)).get());
}
