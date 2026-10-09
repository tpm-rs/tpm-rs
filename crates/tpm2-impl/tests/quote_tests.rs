use tpm2::errors::TpmRc;
use tpm2::{Marshal, Unmarshal};
mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::Alg;
use tpm2::Handle;
use tpm2::commands::{Command, Quote, QuoteHandles};
use tpm2::crypto::Asymmetric;
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bName, Tpm2bNonce, Tpm2bPublicKeyRsa,
    TpmaObject, TpmaSession, TpmiAlgHash, TpmlPcrSelection, TpmsAttest, TpmsAuthCommand,
    TpmsPcrSelection, TpmsRsaParms, TpmtPublic, TpmtRsaScheme, TpmtSigScheme, TpmtSignature,
    TpmuAttest,
};
use tpm2_impl::handler::TransientObject;
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

fn execute_tpm_quote<'a>(
    tpm: &mut TpmEngine<'_, FakeCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &QuoteHandles,
    cmd: &Quote,
    auths: &[TpmsAuthCommand],
    response_buf: &'a mut [u8; 32768],
) -> Result<<Quote<'static> as Command>::Response<'a>, u32> {
    let mut request_buf = [0u8; 32768];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(Quote::CMD_CODE.code()).to_be_bytes());

    let mut handles_buf = [0u8; QuoteHandles::MAX_SIZE];
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

    let mut cmd_buf = [0u8; Quote::MAX_SIZE];
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
fn test_quote_rsa_success() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let signer_handle = Handle(0x80000002);
    let signer_obj = TransientObject {
        handle: signer_handle.0,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
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
        qualified_name: (Tpm2bName::from_bytes(&[4, 5, 6]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[1] = Some(signer_obj);

    // Extend PCR 0 with a test hash
    global_state.pcrs.sha256[0] = [0x42; 32];

    let handles = QuoteHandles {
        sign_handle: signer_handle,
    };
    let cmd = Quote {
        qualifying_data: Tpm2bData::from_bytes(&[10, 20, 30]).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
        pcr_select: TpmlPcrSelection::from_slice(&[TpmsPcrSelection::new(
            TpmiAlgHash::Sha256,
            &[0x01, 0x00, 0x00],
        )
        .unwrap()])
        .unwrap(),
    };

    let pw_auth = TpmsAuthCommand {
        session_handle: Handle(0x40000009), // TPM_RS_PW
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::default(),
        hmac: Tpm2bAuth::default(),
    };

    let mut response_buf = [0u8; 32768];
    let resp = execute_tpm_quote(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &[pw_auth],
        &mut response_buf,
    )
    .unwrap();

    let attest = resp.quoted.0;
    assert_eq!(attest.extra_data.get_buffer(), &[10, 20, 30]);

    match attest.attested {
        TpmuAttest::Quote(quote_info) => {
            assert_eq!(quote_info.pcr_select, cmd.pcr_select);
            assert_eq!(quote_info.pcr_digest.get_buffer(), &[0x42; 32]);
        }
        _ => panic!("Expected Quote attested info"),
    }

    let crypto = FakeCrypto;
    let mut quoted_buf = [0u8; TpmsAttest::MAX_SIZE];
    let quoted_len = attest.marshal(&mut quoted_buf);
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(
        &crypto,
        TpmiAlgHash::Sha256,
        &quoted_buf[..quoted_len],
        &mut out,
    )
    .unwrap();
    match resp.signature {
        Some(TpmtSignature::Rsassa(sig)) => {
            crypto
                .verify_inner(Alg::RSASSA, &[1, 2, 3], digest, sig.sig.get_buffer())
                .expect("Cryptographic signature verification failed");
        }
        _ => panic!("Expected RSASSA signature"),
    }
}

#[test]
fn test_quote_unsupported_scheme_fails() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let decrypt_handle = Handle(0x80000003);
    let decrypt_obj = TransientObject {
        handle: decrypt_handle.0,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::from_bytes(&[7, 8, 9]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
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
        qualified_name: (Tpm2bName::from_bytes(&[7, 8, 9]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[2] = Some(decrypt_obj);

    let handles = QuoteHandles {
        sign_handle: decrypt_handle,
    };
    let cmd = Quote {
        qualifying_data: Tpm2bData::default(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
        pcr_select: TpmlPcrSelection::from_slice(&[TpmsPcrSelection::new(
            TpmiAlgHash::Sha256,
            &[0x01, 0x00, 0x00],
        )
        .unwrap()])
        .unwrap(),
    };

    let pw_auth = TpmsAuthCommand {
        session_handle: Handle(0x40000009), // TPM_RS_PW
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::default(),
        hmac: Tpm2bAuth::default(),
    };

    let mut response_buf = [0u8; 32768];
    let res = execute_tpm_quote(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &[pw_auth],
        &mut response_buf,
    );
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(
        err == TpmRc::KEY.get()
            || err == TpmRc::SCHEME.get()
            || err == (TpmRc::KEY.get() + 0x100)
            || err == (TpmRc::SCHEME.get() + 0x100),
        "Expected Key or Scheme error, got 0x{:x}",
        err
    );
}

#[test]
fn test_quote_qualified_signer_exact_accumulation() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let signer_handle = Handle(0x80000002);
    let signer_qn = Tpm2bName::from_bytes(&[30, 31, 32, 33]).unwrap();
    let signer_obj = TransientObject {
        handle: signer_handle.0,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
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
    global_state.transient_objects[1] = Some(signer_obj.clone());
    global_state.transient_parents[1] = Some(0x40000001);

    let handles = QuoteHandles {
        sign_handle: signer_handle,
    };
    let cmd = Quote {
        qualifying_data: Tpm2bData::from_bytes(&[10, 20]).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
        pcr_select: TpmlPcrSelection::from_slice(&[TpmsPcrSelection::new(
            TpmiAlgHash::Sha256,
            &[0x01, 0x00, 0x00],
        )
        .unwrap()])
        .unwrap(),
    };

    let pw_auth = TpmsAuthCommand {
        session_handle: Handle(0x40000009),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::default(),
        hmac: Tpm2bAuth::default(),
    };

    let mut response_buf = [0u8; 32768];
    let resp = execute_tpm_quote(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &[pw_auth],
        &mut response_buf,
    )
    .unwrap();
    let attest = resp.quoted.0;
    let _ = attest.magic;
    assert_eq!(attest.qualified_signer.get_buffer(), signer_qn.get_buffer());
}
