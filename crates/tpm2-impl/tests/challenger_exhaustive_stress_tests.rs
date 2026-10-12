#![allow(clippy::unwrap_used, clippy::expect_used)]

extern crate alloc;

mod common;

use alloc::vec::Vec;
use common::{FakeRng, FakeStorage, FakeTimer, TestCryptoProvider, marshal_to_slice};
use hex_literal::hex;
use tpm2::commands::{Command, Duplicate, Import, Message, UnmarshalMessage};
use tpm2::crypto::{
    Ecc, EccPrivateKey, EccPublicKey, ModeIv, Random, Rsa, RsaPrivateKey, RsaPublicKey,
};
use tpm2::errors::TpmRc;
use tpm2::{
    Alg, AlgSym, Handle, Marshal, PublicParmsAndId, ResponseHeader, Tpm2b, Tpm2bAuth, Tpm2bData,
    Tpm2bDigest, Tpm2bEccParameter, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bPrivate, Tpm2bPublic,
    Tpm2bPublicKeyRsa, TpmEccCurve, TpmaObject, TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode,
    TpmiRsaKeyBits, TpmiStCommandTag, TpmsAuthCommand, TpmsEccParms, TpmsEccPoint, TpmsRsaParms,
    TpmtPublic, TpmtSymDefObject, Unmarshal,
};
use tpm2_impl::handler::TransientObject;
use tpm2_impl::owned::{
    OwnedEccParameter, OwnedPrivateKeyRsa, OwnedPublicParmsAndId, OwnedSensitiveComposite,
};
use tpm2_impl::{TpmEngine, TpmPlatform};

struct DuplicateHandles {
    pub object_handle: Handle,
    pub new_parent_handle: Handle,
}

struct ImportHandles {
    pub parent_handle: Handle,
}

trait TestHandles {
    fn to_vec(&self) -> Vec<Handle>;
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
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;
    global_state.g_nv_ok = true;

    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    (tpm, global_state)
}

fn execute_tpm_command<C: Command, H: TestHandles>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &H,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<(C::Response<'static>, C::Response<'static>), u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: UnmarshalMessage<'static> + Copy,
{
    let mut request_buf = [0u8; 8192];
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

    let mut response_buf = [0u8; 8192];
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
        let resp_params = C::Response::unmarshal_with_handles(resp_handles, &mut param_slice)
            .map_err(|_| TpmRc::FAILURE.get())?;
        Ok((resp_params, resp_params))
    } else {
        let resp_params = C::Response::unmarshal_with_handles(resp_handles, &mut resp_slice)
            .map_err(|_| TpmRc::FAILURE.get())?;
        Ok((resp_params, resp_params))
    }
}

fn compute_key_name(crypto: &TestCryptoProvider, public: &TpmtPublic) -> Tpm2bName<'static> {
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(public, &mut buf);
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = tpm2::crypto::hash(crypto, TpmiAlgHash::Sha256, &buf[..len], &mut out)
        .unwrap()
        .digest();

    let mut name_bytes = [0u8; 34];
    name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    name_bytes[2..34].copy_from_slice(digest);
    Tpm2bName::new(std::vec::Vec::leak(name_bytes[..34].to_vec())).unwrap()
}

fn create_transient_key(
    crypto: &TestCryptoProvider,
    handle: u32,
    attrs: TpmaObject,
) -> TransientObject {
    let mut rng = crypto.rng_seeded(&[0x42; 32]).unwrap();
    let key = Rsa::generate_key(crypto, &mut rng, TpmiRsaKeyBits::Rsa2048, 0).unwrap();
    let pub_key = key.public_key();
    let mut pub_buf = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let modulus = pub_key.modulus(&mut pub_buf).unwrap();
    let modulus_vec = std::vec::Vec::leak(modulus.as_slice().to_vec());
    let mut priv_buf = [0u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES];
    let prime_p = key.prime_p(&mut priv_buf).unwrap();

    let unique = Tpm2bPublicKeyRsa::new(modulus_vec).unwrap();

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits::Rsa2048,
                exponent: 0,
            },
            unique,
        ),
    };
    let name = compute_key_name(crypto, &public);
    TransientObject {
        handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: name.into(),
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        sensitive: OwnedSensitiveComposite::Rsa(
            OwnedPrivateKeyRsa::from_bytes(prime_p.as_slice()).unwrap(),
        ),
        qualified_name: name.into(),
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

fn create_transient_ecc_key(
    crypto: &TestCryptoProvider,
    handle: u32,
    attrs: TpmaObject,
    curve: TpmEccCurve,
) -> TransientObject {
    let mut rng = crypto.rng_seeded(&[0x43; 32]).unwrap();
    let key = Ecc::generate_key(crypto, &mut rng, curve).unwrap();
    let pub_key = key.public_key();
    let mut out_x = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let mut out_y = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let point = pub_key.point(&mut out_x, &mut out_y).unwrap();
    let x_vec = std::vec::Vec::leak(point.x.as_slice().to_vec());
    let y_vec = std::vec::Vec::leak(point.y.as_slice().to_vec());
    let mut priv_buf = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let priv_bytes = key.scalar(&mut priv_buf).unwrap();

    let unique = TpmsEccPoint {
        x: Tpm2bEccParameter::new(x_vec).unwrap(),
        y: Tpm2bEccParameter::new(y_vec).unwrap(),
    };

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: curve,
                kdf: None,
            },
            unique,
        ),
    };
    let name = compute_key_name(crypto, &public);
    TransientObject {
        handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: name.into(),
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        sensitive: OwnedSensitiveComposite::Ecc(
            OwnedEccParameter::from_bytes(priv_bytes.as_slice()).unwrap(),
        ),
        qualified_name: name.into(),
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

#[test]
fn test_exhaustive_combinations_debug() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();

    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

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
    global_state.transient_objects[0] = Some(parent);

    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[1] = Some(target);

    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let dup_cmd = Duplicate {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: sym_alg,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[]);
    assert!(res.is_ok());
}

#[test]
fn test_import_malformed_inner_blob_size() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(parent);

    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[1] = Some(target.clone());

    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let dup_cmd = Duplicate {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let (_, dup_resp) =
        execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[]).unwrap();

    let object_public: Tpm2bPublic = Tpm2b(target.public.as_tpmt());

    let imp_handles = ImportHandles {
        parent_handle: Handle(0x80000001),
    };

    let aes_128_cfb = TpmtSymDefObject {
        alg: AlgSym::Aes128,
        mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
    };

    // Scenario A: No inner wrapper, duplicate_bytes length < 2 (only 1 byte)
    {
        let bad_duplicate_1 = Tpm2bPrivate::new(&[0x00]).unwrap();
        let imp_cmd = Import {
            parent_handle: Handle(0x80000001),
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
        let bad_duplicate_2 = Tpm2bPrivate::new(&[0x01, 0x00, 0x99]).unwrap();
        let imp_cmd = Import {
            parent_handle: Handle(0x80000001),
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
    {
        let encryption_key = Tpm2bData::new(&[0u8; 16]).unwrap();
        let bad_duplicate_3 = Tpm2bPrivate::new(&[0xaa]).unwrap();
        let imp_cmd = Import {
            parent_handle: Handle(0x80000001),
            encryption_key,
            object_public,
            duplicate: bad_duplicate_3,
            in_sym_seed: Tpm2bEncryptedSecret::default(),
            symmetric_alg: Some(aes_128_cfb),
        };
        let res = execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[]);
        assert_eq!(res.err(), Some(TpmRc::SIZE.get()));
    }

    // Scenario D: Inner wrapper active, decrypted_inner is >= 2, but sensitive_offset + 2 > inner_blob_len
    {
        let key_bytes = [0x55u8; 16];
        let encryption_key = Tpm2bData::new(&key_bytes).unwrap();
        let mut plaintext = [0u8; 10];
        plaintext[0..2].copy_from_slice(&100u16.to_be_bytes());
        let mut iv = [0u8; 16];
        tpm2::crypto::encrypt(
            tpm.platform.crypto,
            tpm2::crypto::SymmetricKey::Aes128(&key_bytes),
            ModeIv::Cfb(&mut iv),
            &mut plaintext,
        )
        .unwrap();
        let bad_duplicate_4 = Tpm2bPrivate::new(&plaintext).unwrap();
        let imp_cmd = Import {
            parent_handle: Handle(0x80000001),
            encryption_key,
            object_public,
            duplicate: bad_duplicate_4,
            in_sym_seed: Tpm2bEncryptedSecret::default(),
            symmetric_alg: Some(aes_128_cfb),
        };
        let res = execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[]);
        assert_eq!(res.err(), Some(TpmRc::SIZE.get()));
    }

    // Scenario E: Inner wrapper active, sensitive_offset + 2 <= inner_blob_len, but sensitive_offset + 2 + sensitive_size > inner_blob_len
    {
        let key_bytes = [0xccu8; 16];
        let encryption_key = Tpm2bData::new(&key_bytes).unwrap();
        let mut plaintext = [0u8; 10];
        plaintext[0..2].copy_from_slice(&4u16.to_be_bytes());
        plaintext[6..8].copy_from_slice(&500u16.to_be_bytes());
        let mut iv = [0u8; 16];
        tpm2::crypto::encrypt(
            tpm.platform.crypto,
            tpm2::crypto::SymmetricKey::Aes128(&key_bytes),
            ModeIv::Cfb(&mut iv),
            &mut plaintext,
        )
        .unwrap();
        let bad_duplicate_5 = Tpm2bPrivate::new(&plaintext).unwrap();
        let imp_cmd = Import {
            parent_handle: Handle(0x80000001),
            encryption_key,
            object_public,
            duplicate: bad_duplicate_5,
            in_sym_seed: Tpm2bEncryptedSecret::default(),
            symmetric_alg: Some(aes_128_cfb),
        };
        let res = execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[]);
        assert_eq!(res.err(), Some(TpmRc::SIZE.get()));
    }

    // Scenario F: Integer overflow check (inner_integrity_len = 65535)
    {
        let key_bytes = [0x11u8; 16];
        let encryption_key = Tpm2bData::new(&key_bytes).unwrap();
        let mut plaintext = [0u8; 10];
        plaintext[0..2].copy_from_slice(&65535u16.to_be_bytes());
        let mut iv = [0u8; 16];
        tpm2::crypto::encrypt(
            tpm.platform.crypto,
            tpm2::crypto::SymmetricKey::Aes128(&key_bytes),
            ModeIv::Cfb(&mut iv),
            &mut plaintext,
        )
        .unwrap();
        let bad_duplicate_6 = Tpm2bPrivate::new(&plaintext).unwrap();
        let imp_cmd = Import {
            parent_handle: Handle(0x80000001),
            encryption_key,
            object_public,
            duplicate: bad_duplicate_6,
            in_sym_seed: Tpm2bEncryptedSecret::default(),
            symmetric_alg: Some(aes_128_cfb),
        };
        let res = execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[]);
        assert_eq!(res.err(), Some(TpmRc::SIZE.get()));
    }
}

#[test]
fn test_duplicate_invalid_parent_coordinates_zero_size() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let mut parent = create_transient_ecc_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
        TpmEccCurve::NistP256,
    );
    if let OwnedPublicParmsAndId::Ecc(ref mut parms, ref mut point) = parent.public.parms_and_id {
        parms.symmetric = Some(TpmtSymDefObject {
            alg: AlgSym::Aes128,
            mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
        });
        point.x = Tpm2bEccParameter::default().into();
        point.y = Tpm2bEccParameter::default().into();
    }
    global_state.transient_objects[0] = Some(parent);

    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[1] = Some(target);

    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let dup_cmd = Duplicate {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[]);
    assert_eq!(res.err(), Some(TpmRc::FAILURE.get()));
}
