use common::marshal_to_slice;
use tpm2::Alg;
use tpm2::errors::TpmRc;

use tpm2::{Marshal, Unmarshal};
mod common;

use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::Handle;
use tpm2::commands::Command;
use tpm2::crypto::Asymmetric;
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bName,
    Tpm2bPrivate, Tpm2bPublic, Tpm2bPublicKeyRsa, TpmaObject, TpmiAlgHash, TpmsAuthCommand,
    TpmsRsaParms, TpmtPublic, TpmtSymDefObject,
};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::TransientObject;

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
        resp_offset += 4; // Skip parameter size
    }

    let mut params_slice: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
    let resp_params =
        <C::Response<'static>>::unmarshal(&mut params_slice).map_err(|_| TpmRc::FAILURE.get())?;

    Ok((resp_handles, resp_params))
}

fn compute_key_name(crypto: &TestCryptoProvider, public: &TpmtPublic) -> Tpm2bName<'static> {
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(public, &mut buf);
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(crypto, TpmiAlgHash::Sha256, &buf[..len], &mut out)
        .unwrap()
        .digest();

    let mut name_bytes = [0u8; 34];
    name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    name_bytes[2..34].copy_from_slice(digest);
    Tpm2bName::from_bytes(std::vec::Vec::leak(name_bytes[..34].to_vec())).unwrap()
}

fn create_transient_key(
    crypto: &TestCryptoProvider,
    handle: u32,
    attrs: TpmaObject,
) -> TransientObject {
    let mut pub_buf = [0u8; 512];
    let mut priv_buf = [0u8; 2048];
    use tpm2::Alg;
    use tpm2::crypto::asymmetric::KeyParams;
    use tpm2::crypto::asymmetric::TpmiRsaKeyBits;

    let (pub_len, priv_len) = crypto
        .generate_key(
            Alg::RSA,
            Some(KeyParams::Rsa(TpmiRsaKeyBits(2048))),
            &mut pub_buf,
            &mut priv_buf,
            None,
        )
        .unwrap();

    let unique = Tpm2bPublicKeyRsa::from_bytes(&pub_buf[..pub_len]).unwrap();

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            unique,
        ),
    };
    let name = compute_key_name(crypto, &public);
    let mut private = [0u8; 1536];
    private[..priv_len].copy_from_slice(&priv_buf[..priv_len]);
    TransientObject {
        handle,
        seed: [0u8; 32],
        name: name.into(),
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        private,
        private_len: priv_len,
        qualified_name: name.into(),
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

fn create_transient_ecc_key(
    crypto: &TestCryptoProvider,
    handle: u32,
    attrs: TpmaObject,
    curve: tpm2::TpmEccCurve,
) -> TransientObject {
    let mut pub_buf = [0u8; 512];
    let mut priv_buf = [0u8; 2048];
    use tpm2::Alg;
    use tpm2::TpmEccCurve;
    use tpm2::crypto::asymmetric::KeyParams;

    let ecc_curve = if (curve as u16) == u16::from(tpm2::TpmEccCurve::NistP256) {
        TpmEccCurve::NistP256
    } else if (curve as u16) == u16::from(tpm2::TpmEccCurve::BNP256) {
        TpmEccCurve::BNP256
    } else {
        panic!("unsupported curve: {:?}", curve);
    };

    let (pub_len, priv_len) = crypto
        .generate_key(
            Alg::ECC,
            Some(KeyParams::Ecc(ecc_curve)),
            &mut pub_buf,
            &mut priv_buf,
            None,
        )
        .unwrap();

    let unique = tpm2::TpmsEccPoint {
        x: tpm2::Tpm2bEccParameter::from_bytes(&pub_buf[..pub_len / 2]).unwrap(),
        y: tpm2::Tpm2bEccParameter::from_bytes(&pub_buf[pub_len / 2..pub_len]).unwrap(),
    };

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            tpm2::TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: tpm2::TpmEccCurve::try_from(curve as u16).unwrap(),
                kdf: None,
            },
            unique,
        ),
    };
    let name = compute_key_name(crypto, &public);
    let mut private = [0u8; 1536];
    private[..priv_len].copy_from_slice(&priv_buf[..priv_len]);
    TransientObject {
        handle,
        seed: [0u8; 32],
        name: name.into(),
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        private,
        private_len: priv_len,
        qualified_name: name.into(),
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

#[test]
fn test_exhaustive_combinations_debug() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();

    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let parent_hash = TpmiAlgHash::Sha1;
    let sym_alg = None;

    let mut parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    parent.public.name_alg = Some(parent_hash);
    parent.name = compute_key_name(tpm.platform.crypto, &parent.public.as_tpmt()).into();
    parent.qualified_name = parent.name;
    global_state.transient_objects[0] = Some(parent.clone());

    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[1] = Some(target.clone());

    use tpm2::commands::{Duplicate, DuplicateHandles};
    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let dup_cmd = Duplicate {
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: sym_alg,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[]);
    assert!(res.is_ok());
}

#[test]
fn test_import_malformed_inner_blob_size() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Setup parent storage key (handle 0x80000001)
    let parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(parent.clone());

    // 2. Setup target signing key (handle 0x80000002)
    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[1] = Some(target.clone());

    // 3. Generate a valid duplicate output to get the correct seed/HMAC/etc.
    use tpm2::commands::{Duplicate, DuplicateHandles};
    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let dup_cmd = Duplicate {
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let (_, dup_resp) =
        execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[]).unwrap();

    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&target.public, &mut pub_buf);
    let object_public = Tpm2bPublic::from_bytes(&pub_buf[..pub_len]).unwrap();

    use tpm2::commands::{Import, ImportHandles};
    let imp_handles = ImportHandles {
        parent_handle: Handle(0x80000001),
    };

    // Scenario A: No inner wrapper, duplicate_bytes length < 2 (only 1 byte)
    {
        let bad_duplicate_1 = Tpm2bPrivate::from_bytes(&[0x00]).unwrap();
        let imp_cmd = Import {
            encryption_key: Tpm2bData::default(),
            object_public,
            duplicate: bad_duplicate_1,
            in_sym_seed: dup_resp.out_sym_seed,
            symmetric_alg: None,
        };
        let res = execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[]);
        assert_eq!(res.err(), Some(TpmRc::SIZE.get()));
    }

    // Scenario B: No inner wrapper, 2 + sensitive_size > duplicate_bytes length
    {
        // sensitive_size = 256 (0x0100), but total length is only 3 bytes
        let bad_duplicate_2 = Tpm2bPrivate::from_bytes(&[0x01, 0x00, 0x99]).unwrap();
        let imp_cmd = Import {
            encryption_key: Tpm2bData::default(),
            object_public,
            duplicate: bad_duplicate_2,
            in_sym_seed: dup_resp.out_sym_seed,
            symmetric_alg: None,
        };
        let res = execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[]);
        assert_eq!(res.err(), Some(TpmRc::SIZE.get()));
    }

    // Scenario C: Inner wrapper active (AES-128 CFB), but decrypted_inner is too short (< 2 bytes)
    // We pass an encryption key directly, and since parent_symmetric_is_null is true (parent has no symmetric wrapper),
    // no outer integrity check is performed.
    // The duplicate bytes are decrypted using the provided encryption key.
    // Let's pass a duplicate of length 1.
    {
        let encryption_key = Tpm2bData::from_bytes(&[0u8; 16]).unwrap();
        let bad_duplicate_3 = Tpm2bPrivate::from_bytes(&[0xaa]).unwrap();
        let sym_alg = Some(TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB)));
        let imp_cmd = Import {
            encryption_key,
            object_public,
            duplicate: bad_duplicate_3,
            in_sym_seed: Tpm2bEncryptedSecret::default(), // Empty seed
            symmetric_alg: sym_alg,
        };
        let res = execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[]);
        assert_eq!(res.err(), Some(TpmRc::SIZE.get()));
    }

    // Scenario D: Inner wrapper active, decrypted_inner is >= 2, but sensitive_offset + 2 > inner_blob_len
    // Let's set inner_integrity_len = 100, but inner_blob_len = 10.
    // Plaintext inner blob: [0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    // Since decrypted = ciphertext ^ key (for our test crypto), we can XOR plaintext with key to get ciphertext.
    {
        let encryption_key = Tpm2bData::from_bytes(&[0x55; 16]).unwrap();
        let mut plaintext = [0u8; 10];
        plaintext[0..2].copy_from_slice(&100u16.to_be_bytes()); // inner_integrity_len = 100
        for byte in &mut plaintext {
            *byte ^= 0x55; // XOR with the key byte to compute ciphertext
        }
        let bad_duplicate_4 = Tpm2bPrivate::from_bytes(&plaintext).unwrap();
        let sym_alg = Some(TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB)));
        let imp_cmd = Import {
            encryption_key,
            object_public,
            duplicate: bad_duplicate_4,
            in_sym_seed: Tpm2bEncryptedSecret::default(),
            symmetric_alg: sym_alg,
        };
        let res = execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[]);
        assert_eq!(res.err(), Some(TpmRc::SIZE.get()));
    }

    // Scenario E: Inner wrapper active, sensitive_offset + 2 <= inner_blob_len, but sensitive_offset + 2 + sensitive_size > inner_blob_len
    // Let's set inner_integrity_len = 4, sensitive_size = 500, but inner_blob_len = 10.
    // Plaintext inner blob:
    // bytes 0..2: [0x00, 0x04] (inner_integrity_len = 4)
    // bytes 2..6: integrity HMAC (dummy 4 bytes)
    // bytes 6..8: [0x01, 0xf4] (sensitive_size = 500)
    // bytes 8..10: dummy bytes
    {
        let encryption_key = Tpm2bData::from_bytes(&[0xcc; 16]).unwrap();
        let mut plaintext = [0u8; 10];
        plaintext[0..2].copy_from_slice(&4u16.to_be_bytes()); // integrity_len = 4
        plaintext[6..8].copy_from_slice(&500u16.to_be_bytes()); // sensitive_size = 500
        for byte in &mut plaintext {
            *byte ^= 0xcc;
        }
        let bad_duplicate_5 = Tpm2bPrivate::from_bytes(&plaintext).unwrap();
        let sym_alg = Some(TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB)));
        let imp_cmd = Import {
            encryption_key,
            object_public,
            duplicate: bad_duplicate_5,
            in_sym_seed: Tpm2bEncryptedSecret::default(),
            symmetric_alg: sym_alg,
        };
        let res = execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[]);
        assert_eq!(res.err(), Some(TpmRc::SIZE.get()));
    }

    // Scenario F: Integer overflow check (inner_integrity_len = 65535)
    // sensitive_offset = 2 + 65535 = 65537
    // inner_blob_len = 10.
    {
        let encryption_key = Tpm2bData::from_bytes(&[0x11; 16]).unwrap();
        let mut plaintext = [0u8; 10];
        plaintext[0..2].copy_from_slice(&65535u16.to_be_bytes());
        for byte in &mut plaintext {
            *byte ^= 0x11;
        }
        let bad_duplicate_6 = Tpm2bPrivate::from_bytes(&plaintext).unwrap();
        let sym_alg = Some(TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB)));
        let imp_cmd = Import {
            encryption_key,
            object_public,
            duplicate: bad_duplicate_6,
            in_sym_seed: Tpm2bEncryptedSecret::default(),
            symmetric_alg: sym_alg,
        };
        let res = execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[]);
        assert_eq!(res.err(), Some(TpmRc::SIZE.get()));
    }
}

#[test]
fn test_duplicate_invalid_parent_coordinates_zero_size() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Create a parent ECC storage key at 0x80000001
    let mut parent = create_transient_ecc_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
        tpm2::TpmEccCurve::NistP256,
    );
    // Tamper with the parent ECC key's coordinates: make unique.x and unique.y empty
    // Also set its symmetric algorithm to be non-Null so that outer wrapper encryption is performed.
    let mut pub_t = parent.public.as_tpmt();
    if let PublicParmsAndId::Ecc(ref mut parms, ref mut point) = pub_t.parms_and_id {
        parms.symmetric = Some(TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB)));
        point.x = tpm2::Tpm2bEccParameter::default(); // 0 size!
        point.y = tpm2::Tpm2bEccParameter::default(); // 0 size!
    }
    parent.public = pub_t.into();
    global_state.transient_objects[0] = Some(parent.clone());

    // 2. Create target signing key (handle 0x80000002)
    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[1] = Some(target.clone());

    // 3. Call Duplicate on target under the tampered parent key
    use tpm2::commands::{Duplicate, DuplicateHandles};
    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let dup_cmd = Duplicate {
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };

    // This should not panic or underflow. It should return Failure because ECDH point multiply fails with invalid coordinates
    let res = execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[]);
    assert_eq!(res.err(), Some(TpmRc::FAILURE.get()));
}
