use common::marshal_to_slice;

mod common;

use common::{FakeRng, FakeStorage, FakeTimer, TestCryptoProvider};
use hex_literal::hex;
use tpm2::commands::{Certify, Command, Load, Message, ObjectChangeAuth, UnmarshalMessage};
use tpm2::crypto::{Ecc, EccPrivateKey, EccPublicKey};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    AlgSym, Handle, Marshal, PublicParmsAndId, Tpm2b, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bName,
    Tpm2bNonce, Tpm2bPublicKeyRsa, TpmEccCurve, TpmaObject, TpmaSession, TpmiAlgCipherMode,
    TpmiAlgHash, TpmiAlgSymMode, TpmiRsaKeyBits, TpmsAuthCommand, TpmsEccParms, TpmsRsaParms,
    TpmtEccScheme, TpmtPublic, TpmtSymDefObject, Unmarshal,
};
use tpm2_impl::handler::TransientObject;
use tpm2_impl::owned::{
    OwnedEccParameter, OwnedPrivateKeyRsa, OwnedSensitiveComposite, OwnedSensitiveData,
};
use tpm2_impl::{TpmEngine, TpmPlatform};

fn setup_tpm<'a>(
    crypto: &'a TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    _rng: FakeRng,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer>,
    tpm2_impl::GlobalState,
) {
    let rng = tpm2::crypto::Random::rng_seeded(crypto, &[0u8; 32]).unwrap();
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
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut request_buf = [0u8; 32768];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    for handle in cmd.handles().as_ref() {
        request_buf[offset..offset + 4].copy_from_slice(&handle.0.to_be_bytes());
        offset += 4;
    }

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
        let auth_len = u32::try_from(offset - auth_start).unwrap();
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    let cmd_slice: &mut <C as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let cmd_len = cmd.marshal(cmd_slice);
    offset += cmd_len;
    let total_len = u32::try_from(offset).unwrap();
    request_buf[2..6].copy_from_slice(&total_len.to_be_bytes());

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
    let mut resp_handles = <C::Response<'static> as Message>::Handles::default();
    for h in resp_handles.as_mut() {
        *h = Handle::unmarshal(&mut handles_slice).map_err(|_| TpmRc::FAILURE.get())?;
    }

    let handles_len = orig_handles_len - handles_slice.len();
    resp_offset += handles_len;

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        resp_offset += 4; // Skip parameter size
    }

    let mut params_slice: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
    let resp_params =
        <C::Response<'static>>::unmarshal_with_handles(resp_handles, &mut params_slice)
            .map_err(|_| TpmRc::FAILURE.get())?;

    Ok(resp_params)
}

fn execute_tpm_certify<'a>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
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

    for handle in cmd.handles().as_ref() {
        request_buf[offset..offset + 4].copy_from_slice(&handle.0.to_be_bytes());
        offset += 4;
    }

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
        let auth_len = u32::try_from(offset - auth_start).unwrap();
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    let mut cmd_buf = [0u8; Certify::MAX_SIZE];
    let cmd_len = cmd.marshal(&mut cmd_buf);
    request_buf[offset..offset + cmd_len].copy_from_slice(&cmd_buf.as_ref()[..cmd_len]);
    offset += cmd_len;
    let total_len = u32::try_from(offset).unwrap();
    request_buf[2..6].copy_from_slice(&total_len.to_be_bytes());

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
    UnmarshalMessage::unmarshal_with_handles([], &mut params_slice)
        .map_err(|_| TpmRc::FAILURE.get())
}

fn compute_name_from_bytes(name_alg: TpmiAlgHash, bytes: &[u8]) -> Tpm2bName<'static> {
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let d = tpm2::crypto::hash(&TestCryptoProvider, name_alg, bytes, &mut out)
        .unwrap()
        .digest();
    let mut res = [0u8; 66];
    name_alg.marshal((&mut res[0..2]).try_into().unwrap());
    res[2..2 + d.len()].copy_from_slice(d);
    Tpm2bName::new(std::vec::Vec::leak(res[..2 + d.len()].to_vec())).unwrap()
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
            TpmsRsaParms {
                symmetric: Some(TpmtSymDefObject {
                    alg: AlgSym::Aes128,
                    mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
                }),
                scheme: None,
                key_bits: TpmiRsaKeyBits::Rsa2048,
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::new(&[0u8; 256]).unwrap(),
        ),
    };

    TransientObject {
        handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[1u8; 32]).unwrap(),
        name: qn.into(),
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::new(&[0u8; 128]).unwrap()),
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
        parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
    };

    let key_bytes = b"key_bytes_12345678";

    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&public, &mut pub_buf);

    let digest_bytes = compute_name_from_bytes(name_alg, &pub_buf[..pub_len]);

    TransientObject {
        handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: digest_bytes.into(),
        auth: Tpm2bAuth::new(auth_val).unwrap().into(),
        public: public.into(),
        sensitive: OwnedSensitiveComposite::KeyedHash(OwnedSensitiveData::new(key_bytes).unwrap()),
        qualified_name: qualified_name.into(),
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

fn make_transient_signing_object(
    handle: u32,
    name_alg: TpmiAlgHash,
    auth_val: &[u8],
    qualified_name: Tpm2bName,
) -> TransientObject {
    let mut rng = tpm2::crypto::Random::rng_seeded(&TestCryptoProvider, &[0u8; 32]).unwrap();
    let key = Ecc::generate_key(&TestCryptoProvider, &mut rng, TpmEccCurve::NistP256).unwrap();
    let mut x = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let mut y = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let point = key.public_key().point(&mut x, &mut y).unwrap();
    let mut d = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let scalar = key.scalar(&mut d).unwrap();

    let public = TpmtPublic {
        name_alg: Some(name_alg),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            point,
        ),
    };

    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&public, &mut pub_buf);

    let digest_bytes = compute_name_from_bytes(name_alg, &pub_buf[..pub_len]);

    TransientObject {
        handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: digest_bytes.into(),
        auth: Tpm2bAuth::new(auth_val).unwrap().into(),
        public: public.into(),
        sensitive: OwnedSensitiveComposite::Ecc(OwnedEccParameter::from(scalar)),
        qualified_name: qualified_name.into(),
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

#[test]
fn test_object_change_auth_success() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let parent_handle = 0x80000000;
    let object_handle = 0x80000001;

    let parent_qn = Tpm2bName::new(&[5, 6, 7, 8]).unwrap();
    let parent = make_parent_object(parent_handle, parent_qn);

    let dummy_qn = Tpm2bName::new(&[0; 4]).unwrap();
    let temp_obj =
        make_transient_signing_object(object_handle, TpmiAlgHash::Sha256, b"oldauth", dummy_qn);
    let obj_name = temp_obj.name;

    let correct_qn = compute_qn(
        TpmiAlgHash::Sha256,
        parent_qn.as_slice(),
        obj_name.get_buffer(),
    );
    let obj =
        make_transient_signing_object(object_handle, TpmiAlgHash::Sha256, b"oldauth", correct_qn);

    global_state.transient_objects[0] = Some(parent);
    global_state.transient_objects[1] = Some(obj.clone());

    let cmd = ObjectChangeAuth {
        object_handle: Handle(object_handle),
        parent_handle: Handle(parent_handle),
        new_auth: Tpm2bAuth::new(b"newauth").unwrap(),
    };

    let old_auth_session = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::new(b"oldauth").unwrap(),
    };

    let rsp = execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[old_auth_session]).unwrap();

    global_state.transient_objects[1] = None;

    let temp_obj2 =
        make_transient_signing_object(object_handle, TpmiAlgHash::Sha256, b"oldauth", dummy_qn);
    let in_public = Tpm2b(temp_obj2.public.as_tpmt());

    let load_cmd = Load {
        parent_handle: Handle(parent_handle),
        in_private: rsp.out_private,
        in_public,
    };

    let load_rsp = execute_tpm_command(&mut tpm, &mut global_state, &load_cmd, &[]).unwrap();

    assert_eq!(load_rsp.name, obj_name.as_tpm2b());

    let target_handle = 0x80000003;
    let target_obj = make_transient_object(target_handle, TpmiAlgHash::Sha256, &[], dummy_qn);
    global_state.transient_objects[2] = Some(target_obj);

    let certify_cmd = Certify {
        object_handle: Handle(target_handle),
        sign_handle: load_rsp.object_handle,
        qualifying_data: Tpm2bData::default(),
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
        hmac: Tpm2bAuth::new(b"newauth").unwrap(),
    };

    let mut response_buf = [0u8; 32768];
    let certify_res = execute_tpm_certify(
        &mut tpm,
        &mut global_state,
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
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let parent_handle = 0x80000001;
    let object_handle = 0x80000002;

    let parent_qn = Tpm2bName::new(&[5, 6, 7, 8]).unwrap();
    let parent = make_parent_object(parent_handle, parent_qn);

    let dummy_qn = Tpm2bName::new(&[0; 4]).unwrap();
    let temp_obj = make_transient_object(object_handle, TpmiAlgHash::Sha256, b"oldauth", dummy_qn);
    let obj_name = temp_obj.name;
    let correct_qn = compute_qn(
        TpmiAlgHash::Sha256,
        parent_qn.as_slice(),
        obj_name.get_buffer(),
    );
    let obj = make_transient_object(object_handle, TpmiAlgHash::Sha256, b"oldauth", correct_qn);

    global_state.transient_objects[0] = Some(parent);
    global_state.transient_objects[1] = Some(obj);

    let cmd = ObjectChangeAuth {
        object_handle: Handle(object_handle),
        parent_handle: Handle(parent_handle),
        new_auth: Tpm2bAuth::new(&[1u8; 33]).unwrap(),
    };

    let old_auth_session = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::new(b"oldauth").unwrap(),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[old_auth_session]);
    assert!(res.is_err());
    let err_code = res.err().unwrap();
    assert_eq!(err_code, TpmRc::SIZE.with(Position::parameter(1)).get());
}

#[test]
fn test_object_change_auth_mismatched_parent() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let parent_handle = 0x80000001;
    let object_handle = 0x80000002;
    let wrong_parent_handle = 0x80000003;

    let parent_qn = Tpm2bName::new(&[5, 6, 7, 8]).unwrap();
    let parent = make_parent_object(parent_handle, parent_qn);

    let dummy_qn = Tpm2bName::new(&[0; 4]).unwrap();
    let temp_obj = make_transient_object(object_handle, TpmiAlgHash::Sha256, b"oldauth", dummy_qn);
    let obj_name = temp_obj.name;
    let correct_qn = compute_qn(
        TpmiAlgHash::Sha256,
        parent_qn.as_slice(),
        obj_name.get_buffer(),
    );
    let obj = make_transient_object(object_handle, TpmiAlgHash::Sha256, b"oldauth", correct_qn);

    let wrong_parent_qn = Tpm2bName::new(&[9, 9, 9, 9]).unwrap();
    let wrong_parent = make_parent_object(wrong_parent_handle, wrong_parent_qn);

    global_state.transient_objects[0] = Some(parent);
    global_state.transient_objects[1] = Some(obj);
    global_state.transient_objects[2] = Some(wrong_parent);

    let cmd = ObjectChangeAuth {
        object_handle: Handle(object_handle),
        parent_handle: Handle(wrong_parent_handle),
        new_auth: Tpm2bAuth::new(b"newauth").unwrap(),
    };

    let old_auth_session = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::new(b"oldauth").unwrap(),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[old_auth_session]);
    assert!(res.is_err());
    let err_code = res.err().unwrap();
    assert_eq!(err_code, TpmRc::TYPE.with(Position::handle(2)).get());
}

#[test]
fn test_object_change_auth_active_sequence() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let parent_handle = 0x80000001;
    let object_handle = 0x80000002;

    let parent_qn = Tpm2bName::new(&[5, 6, 7, 8]).unwrap();
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

    let cmd = ObjectChangeAuth {
        object_handle: Handle(object_handle),
        parent_handle: Handle(parent_handle),
        new_auth: Tpm2bAuth::new(b"newauth").unwrap(),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]);
    assert!(res.is_err());
    let err_code = res.err().unwrap();
    assert_eq!(err_code, TpmRc::TYPE.with(Position::handle(1)).get());
}

#[test]
fn test_object_change_auth_on_nv_index() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let parent_handle = 0x40000001;
    let object_handle = 0x01400001; // NV Index

    let cmd = ObjectChangeAuth {
        object_handle: Handle(object_handle),
        parent_handle: Handle(parent_handle),
        new_auth: Tpm2bAuth::new(b"newauth").unwrap(),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &cmd, &[]);
    assert!(res.is_err());
    let err_code = res.err().unwrap();
    assert_eq!(err_code, TpmRc::VALUE.with(Position::handle(1)).get());
}
