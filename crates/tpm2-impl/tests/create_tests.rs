mod common;

use common::{FakeRng, FakeStorage, FakeTimer, TestCryptoProvider};
use hex_literal::hex;
use tpm2::commands::{Command, Create, CreatePrimary, Import, Message, UnmarshalMessage, Unseal};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    AlgSym, Handle, Marshal, PublicParmsAndId, Tpm2b, Tpm2bAuth, Tpm2bData, Tpm2bDigest,
    Tpm2bEncryptedSecret, Tpm2bPrivate, Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmaObject,
    TpmaSession, TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode, TpmiRsaKeyBits, TpmlPcrSelection,
    TpmsAuthCommand, TpmsRsaParms, TpmsSensitiveCreate, TpmtKeyedHashScheme, TpmtPublic,
    TpmtSymDefObject, Unmarshal,
};
use tpm2_impl::{TpmEngine, TpmPlatform};

const FIRMWARE_LIMITED: TpmaObject = TpmaObject(1 << 8);
const SVN_LIMITED: TpmaObject = TpmaObject(1 << 9);

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
    tpm.init_storage(&mut global_state).unwrap();
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
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut request_buf = [0u8; 16384];
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
    let mut resp_handles = <C::Response<'static> as Message>::Handles::default();
    for h in resp_handles.as_mut() {
        *h = Handle::unmarshal(&mut handles_slice).map_err(|_| TpmRc::FAILURE.get())?;
    }

    let handles_len = orig_handles_len - handles_slice.len();
    resp_offset += handles_len;

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        resp_offset += 4;
    }

    let mut params_slice: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
    let resp_params =
        <C::Response<'static>>::unmarshal_with_handles(resp_handles, &mut params_slice)
            .map_err(|_| TpmRc::FAILURE.get())?;

    Ok(resp_params)
}

const AES_128_CFB: TpmtSymDefObject = TpmtSymDefObject {
    alg: AlgSym::Aes128,
    mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
};

#[test]
fn test_create_sign_and_decrypt_mutual_exclusivity() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // 1. Create a primary parent key
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
                symmetric: Some(AES_128_CFB),
                scheme: None,
                key_bits: TpmiRsaKeyBits::Rsa2048,
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let parent_sensitive = Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });
    let cp_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: parent_sensitive,
        in_public: Tpm2b(parent_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let cp_resp = execute_tpm_command(&mut tpm, &mut global_state, &cp_cmd, &[]).unwrap();

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
                key_bits: TpmiRsaKeyBits::Rsa2048,
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let create_cmd = Create {
        parent_handle: cp_resp.object_handle,
        in_sensitive: parent_sensitive,
        in_public: Tpm2b(child_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &create_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::parameter(2)).get()),
        "TPM2_Create with both sign and decrypt set on RSA must fail with TPM_RC_ATTRIBUTES at Pos2"
    );
}

#[test]
fn test_import_invalid_attributes() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    // 1. Create a primary parent key
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
                symmetric: Some(AES_128_CFB),
                scheme: None,
                key_bits: TpmiRsaKeyBits::Rsa2048,
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let parent_sensitive = Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });
    let cp_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: parent_sensitive,
        in_public: Tpm2b(parent_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let cp_resp = execute_tpm_command(&mut tpm, &mut global_state, &cp_cmd, &[]).unwrap();

    // 2. Test Import with invalid encryption key size
    let child_pub = TpmtPublic {
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
            Tpm2bPublicKeyRsa::new(&[0x22; 256]).unwrap(),
        ),
    };
    let import_cmd_bad_size = Import {
        parent_handle: cp_resp.object_handle,
        encryption_key: Tpm2bData::new(&[0u8; 32]).unwrap(), // 32 bytes instead of 16 for AES 128
        object_public: Tpm2b(child_pub),
        duplicate: Tpm2bPrivate::new(&[0x11; 32]).unwrap(),
        in_sym_seed: Tpm2bEncryptedSecret::new(&[0x22; 256]).unwrap(),
        symmetric_alg: Some(AES_128_CFB),
    };
    let res_size = execute_tpm_command(&mut tpm, &mut global_state, &import_cmd_bad_size, &[]);
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
                key_bits: TpmiRsaKeyBits::Rsa2048,
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::new(&[0x22; 256]).unwrap(),
        ),
    };
    let import_cmd_bad_attrs = Import {
        parent_handle: cp_resp.object_handle,
        encryption_key: Tpm2bData::new(&[0u8; 16]).unwrap(),
        object_public: Tpm2b(child_pub_bad_attrs),
        duplicate: Tpm2bPrivate::new(&[0x11; 32]).unwrap(),
        in_sym_seed: Tpm2bEncryptedSecret::new(&[0x22; 256]).unwrap(),
        symmetric_alg: Some(AES_128_CFB),
    };
    let res_attrs = execute_tpm_command(&mut tpm, &mut global_state, &import_cmd_bad_attrs, &[]);
    assert_eq!(
        res_attrs.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::parameter(2)).get()),
        "TPM2_Import with fixedTPM set must return TPM_RC_ATTRIBUTES at Pos2"
    );
}

#[test]
fn test_create_primary_sealed_data_unseal() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let secret_message = b"my_secret_data_1234";

    let in_public = Tpm2b(TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
    });

    let primary_cmd = CreatePrimary {
        primary_handle: Handle::RH_NULL,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::new(secret_message).unwrap(),
        }),
        in_public,
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };

    let cp_resp =
        execute_tpm_command::<CreatePrimary>(&mut tpm, &mut global_state, &primary_cmd, &[])
            .expect("CreatePrimary sealed data failed");

    let object_handle = cp_resp.object_handle;

    // Unseal the sealed data object
    let unseal_cmd = Unseal {
        item_handle: object_handle,
    };
    let unseal_resp = execute_tpm_command::<Unseal>(&mut tpm, &mut global_state, &unseal_cmd, &[])
        .expect("Unseal failed");

    assert_eq!(unseal_resp.out_data.as_slice(), secret_message);
}

/// Creates an HMAC primary key in the owner hierarchy and returns its public `unique` field,
/// which the TPM derives from the object's seed.
fn create_hmac_primary_unique(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    auth_policy: &[u8],
) -> Vec<u8> {
    let cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate::default()),
        in_public: Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT
                | TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::new(auth_policy).unwrap(),
            parms_and_id: PublicParmsAndId::KeyedHash(
                Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
                Tpm2bDigest::default(),
            ),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let rsp = execute_tpm_command::<CreatePrimary>(tpm, global_state, &cmd, &[]).unwrap();
    match rsp.out_public.0.parms_and_id {
        PublicParmsAndId::KeyedHash(_, unique) => unique.as_slice().to_vec(),
        _ => panic!("unexpected public area type"),
    }
}

#[test]
fn test_create_primary_key_depends_on_whole_template() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

    let a1 = create_hmac_primary_unique(&mut tpm, &mut global_state, &[]);
    let a2 = create_hmac_primary_unique(&mut tpm, &mut global_state, &[]);
    let b = create_hmac_primary_unique(&mut tpm, &mut global_state, &[0x11; 32]);

    // The same template gives the same key; a template that differs only in its authPolicy
    // (not in `unique`) gives a different key.
    assert_eq!(a1, a2);
    assert_ne!(a1, b);
}

#[test]
fn test_create_invalid_public_type() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

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
                symmetric: Some(AES_128_CFB),
                scheme: None,
                key_bits: TpmiRsaKeyBits::Rsa2048,
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let parent_sensitive = Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });
    let cp_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: parent_sensitive,
        in_public: Tpm2b(parent_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let cp_resp = execute_tpm_command(&mut tpm, &mut global_state, &cp_cmd, &[]).unwrap();

    let parent_handle = cp_resp.object_handle;
    // Build TPM2_Create request
    let mut raw_req = Vec::new();
    raw_req.extend_from_slice(&0x8002u16.to_be_bytes()); // TPM_ST_SESSIONS
    raw_req.extend_from_slice(&0u32.to_be_bytes()); // placeholder size
    raw_req.extend_from_slice(&0x00000153u32.to_be_bytes()); // TPM_CC_Create (0x153)
    raw_req.extend_from_slice(&parent_handle.0.to_be_bytes()); // parentHandle

    // Auth session (Password session: handle 0x40000009, nonce 0, attrs 0, auth 0)
    let auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bDigest::default(),
        session_attributes: TpmaSession(0),
        hmac: Tpm2bAuth::default(),
    };
    let mut auth_buf = [0u8; TpmsAuthCommand::MAX_SIZE];
    let auth_len = auth.marshal(&mut auth_buf);
    raw_req.extend_from_slice(&u32::try_from(auth_len).unwrap().to_be_bytes());
    raw_req.extend_from_slice(&auth_buf[..auth_len]);

    // inSensitive: TPM2B_SENSITIVE_CREATE (size = 4, userAuth = 0, data = 0)
    raw_req.extend_from_slice(&4u16.to_be_bytes()); // size of sensitive data
    raw_req.extend_from_slice(&0u16.to_be_bytes()); // userAuth size
    raw_req.extend_from_slice(&0u16.to_be_bytes()); // data size

    // inPublic: TPM2B_PUBLIC with type = TPM_ALG_NULL (0x0010), nameAlg = SHA1 (0x0004), attrs = Sign (0x00040000), policy = 0, params...
    let mut pub_body = Vec::new();
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

    raw_req.extend_from_slice(&u16::try_from(pub_body.len()).unwrap().to_be_bytes());
    raw_req.extend_from_slice(&pub_body);

    // outsideInfo: TPM2B_DATA (size = 0)
    raw_req.extend_from_slice(&0u16.to_be_bytes());

    // creationPCR: TPML_PCR_SELECTION (count = 0)
    raw_req.extend_from_slice(&0u32.to_be_bytes());

    let total_len = u32::try_from(raw_req.len()).unwrap();
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
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, rng);

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
                symmetric: Some(AES_128_CFB),
                scheme: None,
                key_bits: TpmiRsaKeyBits::Rsa2048,
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };

    let valid_sensitive = Tpm2b(TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::default(),
        data: Tpm2bSensitiveData::default(),
    });

    let cp_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: valid_sensitive,
        in_public: Tpm2b(make_rsa_template()),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let cp_resp = execute_tpm_command(&mut tpm, &mut global_state, &cp_cmd, &[]).unwrap();
    let parent_handle = cp_resp.object_handle;

    // 1. Test reserved bit in TPMA_OBJECT (bit 0 = 1) returns TPM_RC_RESERVED_BITS at parameter 2
    let mut template = make_rsa_template();
    template.object_attributes = TpmaObject(template.object_attributes.0 | 0x00000001);
    let create_cmd_bad_obj_attr = Create {
        parent_handle,
        in_sensitive: valid_sensitive,
        in_public: Tpm2b(template),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let err = execute_tpm_command(&mut tpm, &mut global_state, &create_cmd_bad_obj_attr, &[])
        .unwrap_err();
    assert_eq!(err, TpmRc::RESERVED_BITS.with(Position::parameter(2)).get());

    // 2. Test reserved bit in TPMA_SESSION (bit 3 = 0x08) returns TPM_RC_RESERVED_BITS at session 1
    let good_template = make_rsa_template();
    let create_cmd_good = Create {
        parent_handle,
        in_sensitive: valid_sensitive,
        in_public: Tpm2b(good_template),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let bad_session_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bDigest::default(),
        session_attributes: TpmaSession(0x08), // reserved bit 3
        hmac: Tpm2bAuth::default(),
    };
    let err_sess = execute_tpm_command(
        &mut tpm,
        &mut global_state,
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
    for limited_flag in [FIRMWARE_LIMITED, SVN_LIMITED] {
        let mut lim_template = make_rsa_template();
        lim_template.object_attributes |= limited_flag;
        let create_cmd_lim = Create {
            parent_handle,
            in_sensitive: valid_sensitive,
            in_public: Tpm2b(lim_template),
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        let err_lim =
            execute_tpm_command(&mut tpm, &mut global_state, &create_cmd_lim, &[]).unwrap_err();
        assert_eq!(
            err_lim,
            TpmRc::ATTRIBUTES.with(Position::parameter(2)).get()
        );
    }
}
