use tpm2::errors::TpmRc;
use tpm2::{Marshal, Unmarshal};
mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::Handle;
use tpm2::commands::{Certify, CertifyHandles, Command};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bName, Tpm2bNonce, Tpm2bPublicKeyRsa,
    TpmEccCurve, TpmaObject, TpmaSession, TpmiAlgHash, TpmsAuthCommand, TpmsEccParms, TpmsEccPoint,
    TpmsRsaParms, TpmsSchemeEcdaa, TpmtEccScheme, TpmtPublic, TpmtRsaScheme, TpmtSigScheme,
    TpmuAttest,
};
use tpm2_impl::handler::{CommandHandler, TransientObject};
use tpm2_impl::{TpmEngine, TpmPlatform};

fn setup_tpm<'a>(
    crypto: &'a mut FakeCrypto,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a FakeRng,
) -> (
    TpmEngine<'a, FakeCrypto, FakeStorage, FakeTimer, FakeRng>,
    tpm2_impl::GlobalState,
) {
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    (tpm, global_state)
}

fn execute_tpm_certify<'a>(
    tpm: &mut TpmEngine<'_, FakeCrypto, FakeStorage, FakeTimer, FakeRng>,
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

#[test]
fn test_certify_qualified_name_and_signer_exact_accumulation() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let signer_handle = Handle(0x80000002);
    let signer_qn = Tpm2bName::from_bytes(&[10, 11, 12, 13]).unwrap();
    let signer_obj = TransientObject {
        handle: signer_handle.0,
        seed: [0u8; 32],
        name: (Tpm2bName::from_bytes(&[4, 5, 6]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::RESTRICTED
                | TpmaObject::SIGN_ENCRYPT
                | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                    key_bits: tpm2::TpmiRsaKeyBits(2048),
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::from_bytes(&[1, 2, 3]).unwrap(),
            ),
        })
        .into(),
        private: [0u8; 1536],
        private_len: 256,
        qualified_name: (signer_qn).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };

    let certified_handle = Handle(0x80000003);
    let certified_qn = Tpm2bName::from_bytes(&[20, 21, 22, 23]).unwrap();
    let certified_obj = TransientObject {
        handle: certified_handle.0,
        seed: [0u8; 32],
        name: (Tpm2bName::from_bytes(&[7, 8, 9]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: None,
                    key_bits: tpm2::TpmiRsaKeyBits(2048),
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::from_bytes(&[4, 5, 6]).unwrap(),
            ),
        })
        .into(),
        private: [0u8; 1536],
        private_len: 256,
        qualified_name: (certified_qn).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };

    global_state.transient_objects[0] = Some(signer_obj.clone());
    global_state.transient_parents[0] = Some(0x40000001);
    global_state.transient_objects[1] = Some(certified_obj.clone());
    global_state.transient_parents[1] = Some(0x40000001);

    let cmd = Certify {
        qualifying_data: Tpm2bData::from_bytes(&[99, 100]).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
    };
    let handles = CertifyHandles {
        object_handle: certified_handle,
        sign_handle: signer_handle,
    };

    let auths = [
        TpmsAuthCommand {
            session_handle: Handle(0x40000009),
            nonce: Tpm2bNonce::default(),
            session_attributes: TpmaSession::default(),
            hmac: Tpm2bAuth::default(),
        },
        TpmsAuthCommand {
            session_handle: Handle(0x40000009),
            nonce: Tpm2bNonce::default(),
            session_attributes: TpmaSession::default(),
            hmac: Tpm2bAuth::default(),
        },
    ];

    let mut response_buf = [0u8; 32768];
    let resp = execute_tpm_certify(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &auths,
        &mut response_buf,
    )
    .unwrap();
    let attest = resp.certify_info.0;
    let _ = attest.magic;
    assert_eq!(attest.qualified_signer.get_buffer(), signer_qn.get_buffer());

    if let TpmuAttest::Certify(cert_info) = attest.attested {
        assert_eq!(cert_info.name.get_buffer(), certified_obj.name.get_buffer());
        assert_eq!(
            cert_info.qualified_name.get_buffer(),
            certified_qn.get_buffer()
        );
    } else {
        panic!("Expected TpmuAttest::Certify");
    }
}

#[test]
fn test_aliased_primary_object_hierarchy_synchronization_in_certify() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let primary_handle_1 = 0x80000000u32;
    let rsa_child_handle = Handle(0x80000001u32);
    let certified_handle = Handle(0x80000002u32);
    let primary_handle_2 = 0x80000004u32;

    let primary_name = Tpm2bName::from_bytes(&[0x00, 0x0b, 0x01, 0x02, 0x03, 0x04]).unwrap();
    let primary_qn_1 = Tpm2bName::from_bytes(&[0x00, 0x0b, 0x11, 0x22, 0x33, 0x44]).unwrap();
    let rsa_child_name = Tpm2bName::from_bytes(&[0x00, 0x0b, 0x05, 0x06, 0x07, 0x08]).unwrap();
    let certified_name = Tpm2bName::from_bytes(&[0x00, 0x0b, 0x09, 0x0a, 0x0b, 0x0c]).unwrap();

    let (initial_child_qn, certified_qn) = {
        let handler = CommandHandler::new(&mut tpm, &mut global_state);
        let qn1 = handler
            .compute_qualified_name(
                Some(TpmiAlgHash::Sha256),
                primary_qn_1.get_buffer(),
                rsa_child_name.get_buffer(),
            )
            .unwrap();
        let qn2 = handler
            .compute_qualified_name(
                Some(TpmiAlgHash::Sha256),
                primary_qn_1.get_buffer(),
                certified_name.get_buffer(),
            )
            .unwrap();
        (qn1, qn2)
    };

    let primary_obj_1 = TransientObject {
        handle: primary_handle_1,
        seed: [0u8; 32],
        name: (primary_name).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
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
                    symmetric: None,
                    scheme: None,
                    key_bits: tpm2::TpmiRsaKeyBits(2048),
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::from_bytes(&[1, 2, 3]).unwrap(),
            ),
        })
        .into(),
        private: [0u8; 1536],
        private_len: 256,
        qualified_name: (primary_qn_1).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };

    let rsa_child_obj = TransientObject {
        handle: rsa_child_handle.0,
        seed: [0u8; 32],
        name: (rsa_child_name).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::RESTRICTED
                | TpmaObject::SIGN_ENCRYPT
                | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                    key_bits: tpm2::TpmiRsaKeyBits(2048),
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::from_bytes(&[1, 2, 3]).unwrap(),
            ),
        })
        .into(),
        private: [0u8; 1536],
        private_len: 256,
        qualified_name: (initial_child_qn),
        hierarchy: 0x40000001,
        st_clear: false,
    };

    let certified_obj = TransientObject {
        handle: certified_handle.0,
        seed: [0u8; 32],
        name: (certified_name).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: None,
                    key_bits: tpm2::TpmiRsaKeyBits(2048),
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::from_bytes(&[4, 5, 6]).unwrap(),
            ),
        })
        .into(),
        private: [0u8; 1536],
        private_len: 256,
        qualified_name: (certified_qn),
        hierarchy: 0x40000001,
        st_clear: false,
    };

    global_state.transient_objects[0] = Some(primary_obj_1);
    global_state.transient_parents[0] = Some(0x40000001);
    global_state.transient_objects[1] = Some(rsa_child_obj);
    global_state.transient_parents[1] = Some(primary_handle_1);

    // Simulate CreatePrimary under endorsement hierarchy creating Primary_Storage #2 at handle 0x80000004
    let primary_qn_2 = Tpm2bName::from_bytes(&[0x00, 0x0b, 0xaa, 0xbb, 0xcc, 0xdd]).unwrap();
    let expected_new_child_qn = {
        let handler = CommandHandler::new(&mut tpm, &mut global_state);
        handler
            .compute_qualified_name(
                Some(TpmiAlgHash::Sha256),
                primary_qn_2.get_buffer(),
                rsa_child_name.get_buffer(),
            )
            .unwrap()
    };

    let primary_obj_2 = TransientObject {
        handle: primary_handle_2,
        seed: [0u8; 32],
        name: (primary_name).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
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
                    symmetric: None,
                    scheme: None,
                    key_bits: tpm2::TpmiRsaKeyBits(2048),
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::from_bytes(&[1, 2, 3]).unwrap(),
            ),
        })
        .into(),
        private: [0u8; 1536],
        private_len: 256,
        qualified_name: (primary_qn_2).into(),
        hierarchy: 0x4000000b,
        st_clear: false,
    };
    {
        let mut handler = CommandHandler::new(&mut tpm, &mut global_state);
        handler.update_aliased_transient_objects(
            primary_handle_2,
            &primary_name.into(),
            &primary_qn_2.into(),
        );
    }

    // Assert the old aliased slot 0 is cleared
    assert!(global_state.transient_objects[0].is_none());
    assert!(global_state.transient_parents[0].is_none());

    global_state.transient_objects[0] = Some(primary_obj_2);
    global_state.transient_parents[0] = Some(0x4000000b);

    // Assert rsa_child parent and dynamic qualified name have been synchronized to handle 0x80000004
    assert_eq!(global_state.transient_parents[1], Some(primary_handle_2));
    assert_eq!(
        global_state.transient_objects[1]
            .as_ref()
            .unwrap()
            .qualified_name
            .get_buffer(),
        expected_new_child_qn.get_buffer()
    );

    global_state.transient_objects[0] = Some(certified_obj.clone());
    global_state.transient_parents[0] = Some(0x40000001);

    let cmd = Certify {
        qualifying_data: Tpm2bData::from_bytes(&[99, 100]).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
    };
    let handles = CertifyHandles {
        object_handle: certified_handle,
        sign_handle: rsa_child_handle,
    };
    let auths = [
        TpmsAuthCommand {
            session_handle: Handle(0x40000009),
            nonce: Tpm2bNonce::default(),
            session_attributes: TpmaSession::default(),
            hmac: Tpm2bAuth::default(),
        },
        TpmsAuthCommand {
            session_handle: Handle(0x40000009),
            nonce: Tpm2bNonce::default(),
            session_attributes: TpmaSession::default(),
            hmac: Tpm2bAuth::default(),
        },
    ];

    let mut response_buf = [0u8; 32768];
    let resp = execute_tpm_certify(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &auths,
        &mut response_buf,
    )
    .unwrap();
    let attest = resp.certify_info.0;
    let _ = attest.magic;
    assert_eq!(
        attest.qualified_signer.get_buffer(),
        expected_new_child_qn.get_buffer()
    );
}

#[test]
fn test_certify_with_ecdaa_scheme() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let certified_handle = Handle(0x80000001);
    let certified_obj = TransientObject {
        handle: certified_handle.0,
        seed: [0u8; 32],
        name: (Tpm2bName::from_bytes(&[1, 2, 3]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        })
        .into(),
        private: [0u8; 1536],
        private_len: 0,
        qualified_name: (Tpm2bName::from_bytes(&[1, 2, 3]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };

    let signer_handle = Handle(0x80000002);
    let signer_obj = TransientObject {
        handle: signer_handle.0,
        seed: [0u8; 32],
        name: (Tpm2bName::from_bytes(&[4, 5, 6]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Ecc(
                TpmsEccParms {
                    symmetric: None,
                    scheme: Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
                        hash_alg: TpmiAlgHash::Sha256,
                        count: 0,
                    })),
                    curve_id: TpmEccCurve::NistP256,
                    kdf: None,
                },
                TpmsEccPoint::default(),
            ),
        })
        .into(),
        private: [0x07u8; 1536],
        private_len: 32,
        qualified_name: (Tpm2bName::from_bytes(&[10, 11, 12, 13]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };

    global_state.transient_objects[0] = Some(certified_obj);
    global_state.transient_objects[1] = Some(signer_obj);

    let cmd = Certify {
        qualifying_data: Tpm2bData::from_bytes(&[0x11, 0x22]).unwrap(),
        in_scheme: Some(TpmtSigScheme::Ecdaa(TpmsSchemeEcdaa {
            hash_alg: TpmiAlgHash::Sha256,
            count: 1,
        })),
    };
    let handles = CertifyHandles {
        object_handle: certified_handle,
        sign_handle: signer_handle,
    };
    let auths = [
        TpmsAuthCommand {
            session_handle: Handle(0x40000009),
            nonce: Tpm2bNonce::default(),
            session_attributes: TpmaSession::default(),
            hmac: Tpm2bAuth::default(),
        },
        TpmsAuthCommand {
            session_handle: Handle(0x40000009),
            nonce: Tpm2bNonce::default(),
            session_attributes: TpmaSession::default(),
            hmac: Tpm2bAuth::default(),
        },
    ];

    let mut response_buf = [0u8; 32768];
    let resp = execute_tpm_certify(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &auths,
        &mut response_buf,
    )
    .expect("TPM2_Certify with TPMS_SCHEME_ECDAA must succeed");

    let attest = resp.certify_info.0;
    let _ = attest.magic;
    // Per TPM 2.0 Part 3 spec for ECDAA (anonymous signing):
    // qualified_signer, extra_data, and certified object's qualified_name must be empty
    assert_eq!(attest.qualified_signer.get_buffer(), &[]);
    assert_eq!(attest.extra_data.get_buffer(), &[]);
    if let tpm2::TpmuAttest::Certify(info) = attest.attested {
        assert_eq!(info.qualified_name.get_buffer(), &[]);
        assert_eq!(info.name.get_buffer(), &[1, 2, 3]);
    } else {
        panic!("Expected TpmuAttest::Certify");
    }

    // Verify signature is ECDAA variant
    match resp.signature {
        Some(tpm2::TpmtSignature::Ecdaa(sig)) => {
            assert_eq!(sig.hash, TpmiAlgHash::Sha256);
            assert_eq!(sig.signature_r.get_buffer().len(), 32);
            assert_eq!(sig.signature_s.get_buffer().len(), 32);
        }
        _ => panic!("Expected Some(TpmtSignature::Ecdaa)"),
    }
}
