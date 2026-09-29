use tpm2::{Marshal, Unmarshal};
extern crate alloc;

mod common;

use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::Handle;
use tpm2::commands::{
    Command, Create, CreateHandles, CreatePrimary, CreatePrimaryHandles, Import, ImportHandles,
    Unseal, UnsealHandles,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bPrivate,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmaObject, TpmiAlgHash, TpmiAlgSymMode, TpmiRsaKeyBits,
    TpmlPcrSelection, TpmsAuthCommand, TpmsRsaParms, TpmsSensitiveCreate, TpmtPublic,
    TpmtSymDefObject,
};
use tpm2_impl::{TpmEngine, TpmPlatform};

fn setup_tpm<'a>(
    crypto: &'a mut TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a FakeRng,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    tpm2_impl::GlobalState,
) {
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;
    global_state.g_nv_ok = true;

    // Startup(CLEAR)
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
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
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
    let mut request_buf = [0u8; 16384];
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

    let mut response_buf = [0u8; 16384];
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
        resp_offset += 4;
    }

    let mut params_slice: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
    let resp_params =
        <C::Response<'static>>::unmarshal(&mut params_slice).map_err(|_| TpmRc::FAILURE.get())?;

    Ok((resp_handles, resp_params))
}

#[test]
fn test_create_sign_and_decrypt_mutual_exclusivity() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Create a primary parent key
    let cp_handles = CreatePrimaryHandles {
        primary_handle: Handle(0x40000001),
    };
    let parent_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM
            | TpmaObject::SENSITIVE_DATA_ORIGIN,
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
    };
    let parent_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });
    let cp_cmd = CreatePrimary {
        in_sensitive: parent_sensitive,
        in_public: tpm2::Tpm2b(parent_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let (cp_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &cp_handles, &cp_cmd, &[]).unwrap();

    // 2. Create child key under parent with both SIGN_ENCRYPT and DECRYPT set on RSA (scheme=TPM_ALG_NULL)
    let child_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::DECRYPT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let create_handles = CreateHandles {
        parent_handle: cp_resp.object_handle,
    };
    let create_cmd = Create {
        in_sensitive: parent_sensitive,
        in_public: tpm2::Tpm2b(child_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &create_handles,
        &create_cmd,
        &[],
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::parameter(2)).get()),
        "TPM2_Create with both sign and decrypt set on RSA must fail with TPM_RC_ATTRIBUTES at Pos2"
    );
}

#[test]
fn test_import_invalid_attributes() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Create a primary parent key
    let cp_handles = CreatePrimaryHandles {
        primary_handle: Handle(0x40000001),
    };
    let parent_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM
            | TpmaObject::SENSITIVE_DATA_ORIGIN,
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
    };
    let parent_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });
    let cp_cmd = CreatePrimary {
        in_sensitive: parent_sensitive,
        in_public: tpm2::Tpm2b(parent_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let (cp_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &cp_handles, &cp_cmd, &[]).unwrap();

    // 2. Test Import with invalid encryption key size
    let child_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(&[0x22; 256]).unwrap(),
        ),
    };
    let import_handles = ImportHandles {
        parent_handle: cp_resp.object_handle,
    };
    let import_cmd_bad_size = Import {
        encryption_key: Tpm2bData::from_bytes(&[0u8; 32]).unwrap(), // 32 bytes instead of 16 for AES 128
        object_public: tpm2::Tpm2b(child_pub),
        duplicate: Tpm2bPrivate::from_bytes(&[0x11; 32]).unwrap(),
        in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&[0x22; 256]).unwrap(),
        symmetric_alg: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
    };
    let res_size = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &import_handles,
        &import_cmd_bad_size,
        &[],
    );
    assert_eq!(
        res_size.err(),
        Some(TpmRc::SIZE.with(Position::parameter(1)).get()),
        "TPM2_Import with invalid encryption_key size must return TPM_RC_SIZE at Pos1"
    );

    // 3. Test Import with fixedTPM attribute set (must be CLEAR for imported objects)
    let child_pub_bad_attrs = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::FIXED_TPM, // Invalid for import
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::from_bytes(&[0x22; 256]).unwrap(),
        ),
    };
    let import_cmd_bad_attrs = Import {
        encryption_key: Tpm2bData::from_bytes(&[0u8; 16]).unwrap(),
        object_public: tpm2::Tpm2b(child_pub_bad_attrs),
        duplicate: Tpm2bPrivate::from_bytes(&[0x11; 32]).unwrap(),
        in_sym_seed: Tpm2bEncryptedSecret::from_bytes(&[0x22; 256]).unwrap(),
        symmetric_alg: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
    };
    let res_attrs = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &import_handles,
        &import_cmd_bad_attrs,
        &[],
    );
    assert_eq!(
        res_attrs.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::parameter(2)).get()),
        "TPM2_Import with fixedTPM set must return TPM_RC_ATTRIBUTES at Pos2"
    );
}

#[test]
fn test_create_primary_sealed_data_unseal() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let secret_message = b"my_secret_data_1234";

    let primary_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_NULL,
    };
    let in_public = tpm2::Tpm2b(TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, tpm2::Tpm2bDigest::default()),
    });

    let primary_cmd = CreatePrimary {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::from_bytes(secret_message).unwrap(),
        }),
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };

    let (resp_handles, _) = execute_tpm_command::<CreatePrimary>(
        &mut tpm,
        &mut global_state,
        &primary_handles,
        &primary_cmd,
        &[],
    )
    .expect("CreatePrimary sealed data failed");

    let object_handle = resp_handles.object_handle;

    // Unseal the sealed data object
    let unseal_handles = UnsealHandles {
        item_handle: object_handle,
    };
    let unseal_cmd = Unseal {};
    let (_, unseal_resp) = execute_tpm_command::<Unseal>(
        &mut tpm,
        &mut global_state,
        &unseal_handles,
        &unseal_cmd,
        &[],
    )
    .expect("Unseal failed");

    assert_eq!(unseal_resp.out_data.get_buffer(), secret_message);
}

#[test]
fn test_create_invalid_public_type() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let primary_handles = CreatePrimaryHandles {
        primary_handle: Handle::RH_OWNER,
    };
    let parent_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT
            | TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH,
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
    };
    let parent_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });
    let cp_cmd = CreatePrimary {
        in_sensitive: parent_sensitive,
        in_public: tpm2::Tpm2b(parent_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let (cp_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &primary_handles, &cp_cmd, &[]).unwrap();

    let parent_handle = cp_resp.object_handle;
    // Build TPM2_Create request
    let mut raw_req = alloc::vec::Vec::new();
    raw_req.extend_from_slice(&0x8002u16.to_be_bytes()); // TPM_ST_SESSIONS
    raw_req.extend_from_slice(&0u32.to_be_bytes()); // placeholder size
    raw_req.extend_from_slice(&0x00000153u32.to_be_bytes()); // TPM_CC_Create (0x153)
    raw_req.extend_from_slice(&parent_handle.0.to_be_bytes()); // parentHandle

    // Auth session (Password session: handle 0x40000009, nonce 0, attrs 0, auth 0)
    let auth = TpmsAuthCommand {
        session_handle: tpm2::Handle(0x40000009),
        nonce: Tpm2bDigest::default(),
        session_attributes: tpm2::TpmaSession(0),
        hmac: Tpm2bAuth::default(),
    };
    let mut auth_buf = [0u8; TpmsAuthCommand::MAX_SIZE];
    let auth_len = auth.marshal(&mut auth_buf);
    raw_req.extend_from_slice(&(auth_len as u32).to_be_bytes());
    raw_req.extend_from_slice(&auth_buf[..auth_len]);

    // inSensitive: TPM2B_SENSITIVE_CREATE (size = 4, userAuth = 0, data = 0)
    raw_req.extend_from_slice(&4u16.to_be_bytes()); // size of sensitive data
    raw_req.extend_from_slice(&0u16.to_be_bytes()); // userAuth size
    raw_req.extend_from_slice(&0u16.to_be_bytes()); // data size

    // inPublic: TPM2B_PUBLIC with type = TPM_ALG_NULL (0x0010), nameAlg = SHA1 (0x0004), attrs = Sign (0x00040000), policy = 0, params...
    let mut pub_body = alloc::vec::Vec::new();
    pub_body.extend_from_slice(&0x0010u16.to_be_bytes()); // type = TPM_ALG_NULL
    pub_body.extend_from_slice(&0x0004u16.to_be_bytes()); // nameAlg = SHA1
    pub_body.extend_from_slice(&0x00040000u32.to_be_bytes()); // objectAttributes = Sign
    pub_body.extend_from_slice(&0u16.to_be_bytes()); // authPolicy size = 0
    pub_body.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric = NULL
    pub_body.extend_from_slice(&0x0018u16.to_be_bytes()); // scheme = ECDSA
    pub_body.extend_from_slice(&0x0004u16.to_be_bytes()); // scheme hash = SHA1
    pub_body.extend_from_slice(&0x0003u16.to_be_bytes()); // curveID = NIST_P256
    pub_body.extend_from_slice(&0x0010u16.to_be_bytes()); // kdf = NULL
    pub_body.extend_from_slice(&0u16.to_be_bytes()); // unique x size = 0
    pub_body.extend_from_slice(&0u16.to_be_bytes()); // unique y size = 0

    raw_req.extend_from_slice(&(pub_body.len() as u16).to_be_bytes());
    raw_req.extend_from_slice(&pub_body);

    // outsideInfo: TPM2B_DATA (size = 0)
    raw_req.extend_from_slice(&0u16.to_be_bytes());

    // creationPCR: TPML_PCR_SELECTION (count = 0)
    raw_req.extend_from_slice(&0u32.to_be_bytes());

    let total_len = raw_req.len() as u32;
    raw_req[2..6].copy_from_slice(&total_len.to_be_bytes());

    let mut resp = [0u8; 1024];
    let resp_len = tpm.execute_command_separate(&mut global_state, &raw_req, &mut resp);
    assert!(resp_len >= 10);
    let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
    assert_eq!(
        rc,
        TpmRc::TYPE.with(Position::parameter(2)).get(),
        "Expected TPM_RC_TYPE at Pos2 (0x28A), got 0x{:03X}",
        rc
    );
}

#[test]
fn test_tpma_reserved_bits_and_firmware_svn_limited() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let make_rsa_template = || TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM
            | TpmaObject::SENSITIVE_DATA_ORIGIN,
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
    };

    let valid_sensitive = tpm2::Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });

    let primary_handles = CreatePrimaryHandles {
        primary_handle: tpm2::Handle(0x40000001), // TPM_RH_OWNER
    };
    let cp_cmd = CreatePrimary {
        in_sensitive: valid_sensitive,
        in_public: tpm2::Tpm2b(make_rsa_template()),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let (cp_resp, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &primary_handles, &cp_cmd, &[]).unwrap();
    let parent_handle = cp_resp.object_handle;

    // 1. Test reserved bit in TPMA_OBJECT (bit 0 = 1) returns TPM_RC_RESERVED_BITS at parameter 2
    let mut template = make_rsa_template();
    template.object_attributes = TpmaObject(template.object_attributes.0 | 0x00000001);
    let create_cmd_bad_obj_attr = Create {
        in_sensitive: valid_sensitive,
        in_public: tpm2::Tpm2b(template),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_handles = CreateHandles { parent_handle };
    let err = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &create_handles,
        &create_cmd_bad_obj_attr,
        &[],
    )
    .unwrap_err();
    assert_eq!(err, TpmRc::RESERVED_BITS.with(Position::parameter(2)).get());

    // 2. Test reserved bit in TPMA_SESSION (bit 3 = 0x08) returns TPM_RC_RESERVED_BITS at session 1
    let good_template = make_rsa_template();
    let create_cmd_good = Create {
        in_sensitive: valid_sensitive,
        in_public: tpm2::Tpm2b(good_template),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let bad_session_auth = TpmsAuthCommand {
        session_handle: tpm2::Handle(0x40000009),
        nonce: Tpm2bDigest::default(),
        session_attributes: tpm2::TpmaSession(0x08), // reserved bit 3
        hmac: Tpm2bAuth::default(),
    };
    let err_sess = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &create_handles,
        &create_cmd_good,
        &[bad_session_auth],
    )
    .unwrap_err();
    assert_eq!(
        err_sess,
        TpmRc::RESERVED_BITS.with(Position::session(1)).get()
    );

    // 3. Test FIRMWARE_LIMITED and SVN_LIMITED unmarshal cleanly (not RESERVED_BITS)
    // but fail attribute validation with TPM_RC_ATTRIBUTES at parameter 2 when parent is not firmware/svn limited.
    for limited_flag in [TpmaObject::FIRMWARE_LIMITED, TpmaObject::SVN_LIMITED] {
        let mut lim_template = make_rsa_template();
        lim_template.object_attributes |= limited_flag;
        let create_cmd_lim = Create {
            in_sensitive: valid_sensitive,
            in_public: tpm2::Tpm2b(lim_template),
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        let err_lim = execute_tpm_command(
            &mut tpm,
            &mut global_state,
            &create_handles,
            &create_cmd_lim,
            &[],
        )
        .unwrap_err();
        assert_eq!(
            err_lim,
            TpmRc::ATTRIBUTES.with(Position::parameter(2)).get()
        );
    }
}
