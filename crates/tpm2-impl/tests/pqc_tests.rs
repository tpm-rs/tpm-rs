mod common;

use common::{FakeStorage, FakeTimer, TestCryptoProvider};
use hex_literal::hex;
use tpm2::commands::{
    Command, CreatePrimary, Decapsulate, Encapsulate, Message, SequenceUpdate, SignDigest,
    SignSequenceComplete, SignSequenceStart, UnmarshalMessage, VerifyDigestSignature,
    VerifySequenceComplete, VerifySequenceStart,
};
use tpm2::crypto::Random;
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    AlgSym, Handle, Marshal, PublicParmsAndId, Ticket, Tpm2b, Tpm2bAuth, Tpm2bData, Tpm2bDigest,
    Tpm2bMaxBuffer, Tpm2bNonce, Tpm2bPublicKeyMldsa, Tpm2bPublicKeyMlkem, Tpm2bSensitiveData,
    Tpm2bSignatureCtx, TpmSt, TpmaObject, TpmaSession, TpmiAlgCipherMode, TpmiAlgHash,
    TpmiAlgSymMode, TpmiMldsaParms, TpmiMlkemParms, TpmlPcrSelection, TpmsAuthCommand,
    TpmsMldsaParms, TpmsMlkemParms, TpmsSensitiveCreate, TpmtPublic, TpmtSymDefObject,
    TpmtTkHashcheck, Unmarshal,
};
use tpm2_impl::{GlobalState, TpmEngine, TpmPlatform};

fn setup_tpm<'a>(
    crypto: &'a TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer>,
    GlobalState,
) {
    let rng = crypto.rng_seeded(b"pqc_tests").unwrap();
    let platform = TpmPlatform::new(crypto, storage, timer, rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = GlobalState::default();
    tpm.init_storage(&mut global_state).unwrap();

    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(&mut global_state, &startup_request, &mut startup_response);

    (tpm, global_state)
}

fn pw_auth() -> TpmsAuthCommand<'static> {
    TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bAuth::default(),
    }
}

fn execute_tpm_command<C: Command>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut GlobalState,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, TpmRc>
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
        return Err(TpmRc::new(rc).unwrap());
    }

    let mut resp_offset = 10;
    let mut handles_slice = &response_buf[resp_offset..resp_size];
    let orig_handles_len = handles_slice.len();
    let mut resp_handles = <C::Response<'static> as Message>::Handles::default();
    for h in resp_handles.as_mut() {
        *h = Handle::unmarshal(&mut handles_slice).map_err(|_| TpmRc::FAILURE)?;
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
            .map_err(|_| TpmRc::FAILURE)?;

    Ok(resp_params)
}

#[test]
fn test_mlkem_encapsulate_decapsulate_round_trip() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::DECRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Mlkem(
                TpmsMlkemParms {
                    symmetric: None,
                    parameter_set: TpmiMlkemParms::Mlkem768,
                },
                Tpm2bPublicKeyMlkem::default(),
            ),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_rsp = execute_tpm_command(&mut tpm, &mut state, &create_cmd, &[pw_auth()]).unwrap();
    let key_handle = create_rsp.object_handle;

    let encap_rsp =
        execute_tpm_command(&mut tpm, &mut state, &Encapsulate { key_handle }, &[]).unwrap();

    let decap_rsp = execute_tpm_command(
        &mut tpm,
        &mut state,
        &Decapsulate {
            key_handle,
            ciphertext: encap_rsp.ciphertext,
        },
        &[pw_auth()],
    )
    .unwrap();

    assert_eq!(
        encap_rsp.shared_secret.as_slice(),
        decap_rsp.shared_secret.as_slice()
    );
}

#[test]
fn test_decapsulate_restricted_mlkem_key_returns_rc_attributes() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::RESTRICTED
                | TpmaObject::DECRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Mlkem(
                TpmsMlkemParms {
                    symmetric: Some(TpmtSymDefObject {
                        alg: AlgSym::Aes128,
                        mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
                    }),
                    parameter_set: TpmiMlkemParms::Mlkem768,
                },
                Tpm2bPublicKeyMlkem::default(),
            ),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_rsp = execute_tpm_command(&mut tpm, &mut state, &create_cmd, &[pw_auth()]).unwrap();
    let key_handle = create_rsp.object_handle;

    let encap_rsp =
        execute_tpm_command(&mut tpm, &mut state, &Encapsulate { key_handle }, &[]).unwrap();

    let err = execute_tpm_command(
        &mut tpm,
        &mut state,
        &Decapsulate {
            key_handle,
            ciphertext: encap_rsp.ciphertext,
        },
        &[pw_auth()],
    )
    .unwrap_err();

    assert_eq!(err, TpmRc::ATTRIBUTES.with(Position::handle(1)));
}

#[test]
fn test_mldsa_sign_digest_verify_digest_signature_round_trip() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::SIGN_ENCRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Mldsa(
                TpmsMldsaParms {
                    parameter_set: TpmiMldsaParms::Mldsa65,
                    allow_external_mu: true,
                },
                Tpm2bPublicKeyMldsa::default(),
            ),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_rsp = execute_tpm_command(&mut tpm, &mut state, &create_cmd, &[pw_auth()]).unwrap();
    let key_handle = create_rsp.object_handle;

    let mu = [0x42u8; 64];
    let sign_rsp = execute_tpm_command(
        &mut tpm,
        &mut state,
        &SignDigest {
            key_handle,
            context: Tpm2bSignatureCtx::default(),
            digest: Tpm2bDigest::new(&mu).unwrap(),
            validation: TpmtTkHashcheck::default(),
        },
        &[pw_auth()],
    )
    .unwrap();

    let verify_rsp = execute_tpm_command(
        &mut tpm,
        &mut state,
        &VerifyDigestSignature {
            key_handle,
            context: Tpm2bSignatureCtx::default(),
            digest: Tpm2bDigest::new(&mu).unwrap(),
            signature: sign_rsp.signature,
        },
        &[],
    )
    .unwrap();
    // ML-DSA over an external µ gets a NULL TPM_ST_DIGEST_VERIFIED ticket (errata 185).
    assert_eq!(verify_rsp.validation.tag(), TpmSt::DIGEST_VERIFIED);
    assert_eq!(verify_rsp.validation.hierarchy(), Handle::RH_NULL);
    assert!(verify_rsp.validation.digest().as_slice().is_empty());

    let mut bad_mu = mu;
    bad_mu[0] ^= 0xff;
    let err = execute_tpm_command(
        &mut tpm,
        &mut state,
        &VerifyDigestSignature {
            key_handle,
            context: Tpm2bSignatureCtx::default(),
            digest: Tpm2bDigest::new(&bad_mu).unwrap(),
            signature: sign_rsp.signature,
        },
        &[],
    )
    .unwrap_err();
    assert_eq!(err, TpmRc::SIGNATURE.with(Position::parameter(3)));
}

#[test]
fn test_mldsa_sign_and_verify_sequence_round_trip() {
    let crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let create_cmd = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::SIGN_ENCRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Mldsa(
                TpmsMldsaParms {
                    parameter_set: TpmiMldsaParms::Mldsa44,
                    allow_external_mu: false,
                },
                Tpm2bPublicKeyMldsa::default(),
            ),
        }),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let create_rsp = execute_tpm_command(&mut tpm, &mut state, &create_cmd, &[pw_auth()]).unwrap();
    let key_handle = create_rsp.object_handle;

    let ctx = Tpm2bSignatureCtx::new(b"test-context").unwrap();
    let chunk1 = b"Hello, ";
    let chunk2 = b"Post-Quantum TPM 2.0!";

    let sign_start_rsp = execute_tpm_command(
        &mut tpm,
        &mut state,
        &SignSequenceStart {
            auth: Tpm2bAuth::default(),
            key_handle,
            context: ctx,
        },
        &[],
    )
    .unwrap();
    let sign_seq_handle = sign_start_rsp.sequence_handle;

    execute_tpm_command(
        &mut tpm,
        &mut state,
        &SequenceUpdate {
            sequence_handle: sign_seq_handle,
            buffer: Tpm2bMaxBuffer::new(chunk1).unwrap(),
        },
        &[pw_auth()],
    )
    .unwrap();

    let sign_rsp = execute_tpm_command(
        &mut tpm,
        &mut state,
        &SignSequenceComplete {
            sequence_handle: sign_seq_handle,
            key_handle,
            buffer: Tpm2bMaxBuffer::new(chunk2).unwrap(),
        },
        &[pw_auth(), pw_auth()],
    )
    .unwrap();

    let verify_start_rsp = execute_tpm_command(
        &mut tpm,
        &mut state,
        &VerifySequenceStart {
            auth: Tpm2bAuth::default(),
            hint: Default::default(),
            key_handle,
            context: ctx,
        },
        &[],
    )
    .unwrap();
    let verify_seq_handle = verify_start_rsp.sequence_handle;

    execute_tpm_command(
        &mut tpm,
        &mut state,
        &SequenceUpdate {
            sequence_handle: verify_seq_handle,
            buffer: Tpm2bMaxBuffer::new(chunk1).unwrap(),
        },
        &[pw_auth()],
    )
    .unwrap();

    execute_tpm_command(
        &mut tpm,
        &mut state,
        &SequenceUpdate {
            sequence_handle: verify_seq_handle,
            buffer: Tpm2bMaxBuffer::new(chunk2).unwrap(),
        },
        &[pw_auth()],
    )
    .unwrap();

    let verify_rsp = execute_tpm_command(
        &mut tpm,
        &mut state,
        &VerifySequenceComplete {
            sequence_handle: verify_seq_handle,
            key_handle,
            signature: sign_rsp.signature,
        },
        &[pw_auth()],
    )
    .unwrap();
    // A key in the owner hierarchy gets a TPM_ST_MESSAGE_VERIFIED ticket.
    assert_eq!(verify_rsp.validation.tag(), TpmSt::MESSAGE_VERIFIED);
    assert_eq!(verify_rsp.validation.hierarchy(), Handle::RH_OWNER);
    assert_eq!(verify_rsp.validation.digest().as_slice().len(), 32);

    let bad_start_rsp = execute_tpm_command(
        &mut tpm,
        &mut state,
        &VerifySequenceStart {
            auth: Tpm2bAuth::default(),
            hint: Default::default(),
            key_handle,
            context: ctx,
        },
        &[],
    )
    .unwrap();
    let bad_seq_handle = bad_start_rsp.sequence_handle;

    execute_tpm_command(
        &mut tpm,
        &mut state,
        &SequenceUpdate {
            sequence_handle: bad_seq_handle,
            buffer: Tpm2bMaxBuffer::new(b"Tampered message!").unwrap(),
        },
        &[pw_auth()],
    )
    .unwrap();

    let err = execute_tpm_command(
        &mut tpm,
        &mut state,
        &VerifySequenceComplete {
            sequence_handle: bad_seq_handle,
            key_handle,
            signature: sign_rsp.signature,
        },
        &[pw_auth()],
    )
    .unwrap_err();
    assert_eq!(err, TpmRc::SIGNATURE.with(Position::parameter(1)));
}
