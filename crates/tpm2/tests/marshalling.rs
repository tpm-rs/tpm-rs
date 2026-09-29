use tpm2::commands::{responses, *};
use tpm2::errors::UnmarshalError;
use tpm2::*;

#[test]
fn test_marshal_struct_derive() {
    let name_buffer: [u8; 4] = [1, 2, 3, 4];
    let index_name = Tpm2bName::new(&name_buffer).unwrap();
    let nv_buffer = [24u8; 10];
    let nv_contents = Tpm2bMaxNvBuffer::new(&nv_buffer).unwrap();
    let info: TpmsNvCertifyInfo = TpmsNvCertifyInfo {
        index_name,
        offset: 10,
        nv_contents,
    };
    let mut marshal_buffer = [0u8; TpmsNvCertifyInfo::MAX_SIZE];
    let bytes = info.marshal(&mut marshal_buffer);

    // Build the expected output manually.
    let mut expected = Vec::with_capacity(bytes);
    expected.extend_from_slice(&(index_name.as_slice().len() as u16).to_be_bytes());
    expected.extend_from_slice(&name_buffer);
    expected.extend_from_slice(&info.offset.to_be_bytes());
    expected.extend_from_slice(&(nv_contents.as_slice().len() as u16).to_be_bytes());
    expected.extend_from_slice(&nv_buffer);

    assert_eq!(expected.len(), bytes);
    assert_eq!(expected, marshal_buffer[..expected.len()]);

    let mut slice = &marshal_buffer[..];
    let unmarshaled = TpmsNvCertifyInfo::unmarshal(&mut slice);
    assert_eq!(unmarshaled.unwrap(), info);
}

#[test]
fn test_marshal_enum_override() {
    let scheme = Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256));
    let mut buffer = [0u8; <Option<TpmtKeyedHashScheme>>::MAX_SIZE];
    assert!(scheme.marshal(&mut buffer) > 0);
}

#[test]
fn test_marshal_tpmt_public() {
    let aes_sym_def_obj = Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)));
    let mut buffer = [0u8; <Option<TpmtSymDefObject>>::MAX_SIZE];
    let marsh = aes_sym_def_obj.marshal(&mut buffer);
    assert_eq!(marsh, buffer.len());
    let rsa_scheme = Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256));

    let rsa_parms = TpmsRsaParms {
        symmetric: aes_sym_def_obj,
        scheme: rsa_scheme,
        key_bits: TpmiRsaKeyBits(2048),
        exponent: 2,
    };

    let pubkey_buf = [9u8; 24];
    let pubkey = Tpm2bPublicKeyRsa::new(&pubkey_buf).unwrap();

    let example = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::RESTRICTED | TpmaObject::SENSITIVE_DATA_ORIGIN,
        auth_policy: Tpm2bDigest::new(&[2, 2, 4, 4]).unwrap(),
        parms_and_id: PublicParmsAndId::Rsa(rsa_parms, pubkey),
    };

    // Test a round-trip marshaling and unmarshaling, confirm that we get the same output.
    let mut buffer = [0u8; TpmtPublic::MAX_SIZE];
    let marsh = example.marshal(&mut buffer);
    let expected: [u8; 56] = [
        0, 1, 0, 11, 0, 1, 0, 32, 0, 4, 2, 2, 4, 4, 0, 6, 0, 128, 0, 67, 0, 20, 0, 11, 8, 0, 0, 0,
        0, 2, 0, 24, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    ];
    assert_eq!(marsh, expected.len());
    assert_eq!(&buffer[..marsh], &expected[..]);
    let mut slice = &buffer[..];
    let mut unmarsh = TpmtPublic::unmarshal(&mut slice);
    let bytes_example = unmarsh.unwrap();
    assert_eq!(bytes_example.object_attributes, example.object_attributes);
    let mut remarsh_buffer = [1u8; TpmtPublic::MAX_SIZE];
    let remarsh = bytes_example.marshal(&mut remarsh_buffer);
    assert_eq!(remarsh, marsh);
    assert_eq!(remarsh_buffer[..marsh], buffer[..marsh]);

    // Test invalid selector value.
    let mut alg_buf = [0u8; Alg::MAX_SIZE];
    assert!(Alg::SHA256.marshal(&mut alg_buf) > 0);
    let mut alg_slice = &alg_buf[..];
    unmarsh = TpmtPublic::unmarshal(&mut alg_slice);
    assert_eq!(unmarsh.err(), Some(tpm2::errors::UnmarshalError::TYPE));

    // Test insufficient buffer.
    let mut short_slice = &[0x00u8][..];
    unmarsh = TpmtPublic::unmarshal(&mut short_slice);
    assert_eq!(
        unmarsh.err(),
        Some(tpm2::errors::UnmarshalError::INSUFFICIENT)
    );
}

#[test]
fn test_2b_struct() {
    let creation_data = TpmsCreationData {
        pcr_select: TpmlPcrSelection::from_slice(&[TpmsPcrSelection::new(
            TpmiAlgHash::Sha256,
            &[0xF, 0xF, 0xF],
        )
        .unwrap()])
        .unwrap(),
        pcr_digest: Tpm2bDigest::new(&[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9]).unwrap(),
        locality: TpmaLocality(0xA),
        parent_name_alg: Alg::SHA256,
        parent_name: Tpm2bName::new(&[0xA, 0xB, 0xC, 0xD, 0xE, 0xF]).unwrap(),
        parent_qualified_name: Tpm2bName::default(),
        outside_info: Tpm2bData::new(&[0x1; 32]).unwrap(),
    };
    let creation_data_2b: Tpm2bCreationData = Tpm2b(creation_data);
    let out_creation_data = creation_data_2b.0;
    assert_eq!(creation_data, out_creation_data);
}

#[test]
fn test_start_auth_session_marshalling() {
    // 1. Initialize all fields
    let handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };

    let nonce_caller_bytes = [0x11; 20];
    let nonce_caller = Tpm2bNonce::new(&nonce_caller_bytes).unwrap();
    let encrypted_salt_bytes = [0x22; 32];
    let encrypted_salt = Tpm2bEncryptedSecret::new(&encrypted_salt_bytes).unwrap();
    let symmetric = Some(TpmtSymDef::Cipher(TpmtSymDefObject::Aes128(Some(
        TpmiAlgSymMode::CFB,
    ))));

    let cmd = StartAuthSession {
        nonce_caller,
        encrypted_salt,
        session_type: TpmSe::Policy,
        symmetric,
        auth_hash: TpmiAlgHash::Sha256,
    };

    let resp_handles = StartAuthSessionRespHandles {
        session_handle: Handle(0x02000001),
    };

    let nonce_tpm_bytes = [0x33; 20];
    let nonce_tpm = Tpm2bNonce::new(&nonce_tpm_bytes).unwrap();
    let rsp = responses::StartAuthSession { nonce_tpm };

    // 2. Test marshalling and check expected layout & size
    // Handles
    let mut handles_buf = [0u8; StartAuthSessionHandles::MAX_SIZE];
    let handles_len = handles.marshal(&mut handles_buf);
    assert_eq!(handles_len, 8);
    let expected_handles: [u8; 8] = [
        0x40, 0x00, 0x00, 0x07, // tpm_key: RHNull (0x40000007)
        0x40, 0x00, 0x00, 0x07, // bind: RHNull (0x40000007)
    ];
    assert_eq!(handles_buf, expected_handles);

    // Command parameters
    let mut cmd_buf = [0u8; StartAuthSession::MAX_SIZE];
    let cmd_len = cmd.marshal(&mut cmd_buf);

    // Expected command parameters serialization layout:
    // - nonce_caller: 2 bytes size (20 = 0x0014) + 20 bytes [0x11; 20]
    // - encrypted_salt: 2 bytes size (32 = 0x0020) + 32 bytes [0x22; 32]
    // - session_type: 1 byte: TpmSe::Policy = 0x01
    // - symmetric: TpmtSymDefObject::Aes -> 2 bytes alg (AES = 0x0006) + 2 bytes keyBits (128 = 0x0080) + 2 bytes mode (CFB = 0x0043)
    // - auth_hash: TpmiAlgHash::Sha256 -> 2 bytes (0x000B)
    let mut expected_cmd = Vec::new();
    expected_cmd.extend_from_slice(&(20u16).to_be_bytes());
    expected_cmd.extend_from_slice(&nonce_caller_bytes);
    expected_cmd.extend_from_slice(&(32u16).to_be_bytes());
    expected_cmd.extend_from_slice(&encrypted_salt_bytes);
    expected_cmd.push(0x01); // session_type: Policy
    expected_cmd.extend_from_slice(&0x0006u16.to_be_bytes()); // AES
    expected_cmd.extend_from_slice(&128u16.to_be_bytes()); // 128 key bits
    expected_cmd.extend_from_slice(&0x0043u16.to_be_bytes()); // CFB mode
    expected_cmd.extend_from_slice(&0x000Bu16.to_be_bytes()); // SHA256

    assert_eq!(cmd_len, expected_cmd.len());
    assert_eq!(&cmd_buf[..cmd_len], expected_cmd.as_slice());

    // Resp Handles
    let mut resp_handles_buf = [0u8; StartAuthSessionRespHandles::MAX_SIZE];
    let resp_handles_len = resp_handles.marshal(&mut resp_handles_buf);
    assert_eq!(resp_handles_len, 4);
    let expected_resp_handles: [u8; 4] = [0x02, 0x00, 0x00, 0x01];
    assert_eq!(resp_handles_buf, expected_resp_handles);

    // Response parameters
    let mut rsp_buf = [0u8; <StartAuthSession as Command>::Response::MAX_SIZE];
    let rsp_len = rsp.marshal(&mut rsp_buf);
    // Expected response parameters serialization layout:
    // - nonce_tpm: 2 bytes size (20 = 0x0014) + 20 bytes [0x33; 20]
    let mut expected_rsp = Vec::new();
    expected_rsp.extend_from_slice(&(20u16).to_be_bytes());
    expected_rsp.extend_from_slice(&nonce_tpm_bytes);

    assert_eq!(rsp_len, expected_rsp.len());
    assert_eq!(&rsp_buf[..rsp_len], expected_rsp.as_slice());

    // 3. Test unmarshalling recovers exact original struct values
    let mut handles_slice = &handles_buf[..];
    let unmarshalled_handles = StartAuthSessionHandles::unmarshal(&mut handles_slice).unwrap();
    assert_eq!(unmarshalled_handles, handles);

    let mut cmd_slice = &cmd_buf[..cmd_len];
    let unmarshalled_cmd = StartAuthSession::unmarshal(&mut cmd_slice).unwrap();
    assert_eq!(unmarshalled_cmd, cmd);

    let mut resp_handles_slice = &resp_handles_buf[..];
    let unmarshalled_resp_handles =
        StartAuthSessionRespHandles::unmarshal(&mut resp_handles_slice).unwrap();
    assert_eq!(unmarshalled_resp_handles, resp_handles);

    let mut rsp_slice = &rsp_buf[..rsp_len];
    let unmarshalled_rsp =
        <StartAuthSession as Command>::Response::unmarshal(&mut rsp_slice).unwrap();
    assert_eq!(unmarshalled_rsp, rsp);
}

#[test]
fn test_hash_and_sequence_marshalling() {
    // ---- Test TPM2_Hash ----
    let data_bytes = [0x55; 32];
    let data = Tpm2bMaxBuffer::new(&data_bytes).unwrap();
    let hash_cmd = Hash {
        data,
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle::RH_NULL,
    };
    let mut hash_cmd_buf = [0u8; Hash::MAX_SIZE];
    let hash_cmd_len = hash_cmd.marshal(&mut hash_cmd_buf);

    let mut expected_hash_cmd = Vec::new();
    expected_hash_cmd.extend_from_slice(&(32u16).to_be_bytes());
    expected_hash_cmd.extend_from_slice(&data_bytes);
    expected_hash_cmd.extend_from_slice(&0x000Bu16.to_be_bytes()); // SHA256
    expected_hash_cmd.extend_from_slice(&0x40000007u32.to_be_bytes()); // RHNull (0x40000007)
    assert_eq!(hash_cmd_len, expected_hash_cmd.len());
    assert_eq!(&hash_cmd_buf[..hash_cmd_len], expected_hash_cmd.as_slice());

    let mut hash_cmd_slice = &hash_cmd_buf[..hash_cmd_len];
    let unmarshalled_hash_cmd = Hash::unmarshal(&mut hash_cmd_slice).unwrap();
    assert_eq!(unmarshalled_hash_cmd, hash_cmd);

    let out_hash = Tpm2bDigest::new(&[0x66; 32]).unwrap();
    let validation =
        TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::new(&[0x77; 32]).unwrap());
    let hash_resp = responses::Hash {
        out_hash,
        validation,
    };
    let mut hash_resp_buf = [0u8; <Hash as Command>::Response::MAX_SIZE];
    let hash_resp_len = hash_resp.marshal(&mut hash_resp_buf);

    let mut hash_resp_slice = &hash_resp_buf[..hash_resp_len];
    let unmarshalled_hash_resp =
        <Hash as Command>::Response::unmarshal(&mut hash_resp_slice).unwrap();
    assert_eq!(unmarshalled_hash_resp, hash_resp);

    // ---- Test TPM2_HashSequenceStart ----
    let auth = Tpm2bAuth::new(&[0x88; 20]).unwrap();
    let hash_seq_start_cmd = HashSequenceStart {
        auth,
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let mut hash_seq_start_cmd_buf = [0u8; HashSequenceStart::MAX_SIZE];
    let hash_seq_start_cmd_len = hash_seq_start_cmd.marshal(&mut hash_seq_start_cmd_buf);
    let mut hash_seq_start_cmd_slice = &hash_seq_start_cmd_buf[..hash_seq_start_cmd_len];
    let unmarshalled_hash_seq_start_cmd =
        HashSequenceStart::unmarshal(&mut hash_seq_start_cmd_slice).unwrap();
    assert_eq!(unmarshalled_hash_seq_start_cmd, hash_seq_start_cmd);

    let hash_seq_start_null_cmd = HashSequenceStart {
        auth,
        hash_alg: None,
    };
    let mut hash_seq_start_null_buf = [0u8; HashSequenceStart::MAX_SIZE];
    let hash_seq_start_null_len = hash_seq_start_null_cmd.marshal(&mut hash_seq_start_null_buf);
    let mut hash_seq_start_null_slice = &hash_seq_start_null_buf[..hash_seq_start_null_len];
    let unmarshalled_null_cmd =
        HashSequenceStart::unmarshal(&mut hash_seq_start_null_slice).unwrap();
    assert_eq!(unmarshalled_null_cmd, hash_seq_start_null_cmd);

    let hash_seq_start_handles = HashSequenceStartHandles {
        sequence_handle: Handle(0x80000001),
    };
    let mut hash_seq_start_handles_buf = [0u8; HashSequenceStartHandles::MAX_SIZE];
    let hash_seq_start_handles_len =
        hash_seq_start_handles.marshal(&mut hash_seq_start_handles_buf);
    let mut hash_seq_start_handles_slice =
        &hash_seq_start_handles_buf[..hash_seq_start_handles_len];
    let unmarshalled_hash_seq_start_handles =
        HashSequenceStartHandles::unmarshal(&mut hash_seq_start_handles_slice).unwrap();
    assert_eq!(unmarshalled_hash_seq_start_handles, hash_seq_start_handles);

    // ---- Test TPM2_SetPrimaryPolicy ----
    let set_primary_policy_cmd = SetPrimaryPolicy {
        auth_policy: Tpm2bDigest::default(),
        hash_alg: None,
    };
    let mut set_primary_policy_buf = [0u8; SetPrimaryPolicy::MAX_SIZE];
    let set_primary_policy_len = set_primary_policy_cmd.marshal(&mut set_primary_policy_buf);
    let mut set_primary_policy_slice = &set_primary_policy_buf[..set_primary_policy_len];
    let unmarshalled_set_primary_policy =
        SetPrimaryPolicy::unmarshal(&mut set_primary_policy_slice).unwrap();
    assert_eq!(unmarshalled_set_primary_policy, set_primary_policy_cmd);

    // ---- Test TPM2_SequenceUpdate ----
    let seq_update_handles = SequenceUpdateHandles {
        sequence_handle: Handle(0x80000001),
    };
    let mut seq_update_handles_buf = [0u8; SequenceUpdateHandles::MAX_SIZE];
    let seq_update_handles_len = seq_update_handles.marshal(&mut seq_update_handles_buf);
    let mut seq_update_handles_slice = &seq_update_handles_buf[..seq_update_handles_len];
    let unmarshalled_seq_update_handles =
        SequenceUpdateHandles::unmarshal(&mut seq_update_handles_slice).unwrap();
    assert_eq!(unmarshalled_seq_update_handles, seq_update_handles);

    let update_data = Tpm2bMaxBuffer::new(&[0x99; 64]).unwrap();
    let seq_update_cmd = SequenceUpdate {
        buffer: update_data,
    };
    let mut seq_update_cmd_buf = [0u8; SequenceUpdate::MAX_SIZE];
    let seq_update_cmd_len = seq_update_cmd.marshal(&mut seq_update_cmd_buf);
    let mut seq_update_cmd_slice = &seq_update_cmd_buf[..seq_update_cmd_len];
    let unmarshalled_seq_update_cmd = SequenceUpdate::unmarshal(&mut seq_update_cmd_slice).unwrap();
    assert_eq!(unmarshalled_seq_update_cmd, seq_update_cmd);

    // ---- Test TPM2_SequenceComplete ----
    let seq_complete_handles = SequenceCompleteHandles {
        sequence_handle: Handle(0x80000001),
    };
    let mut seq_complete_handles_buf = [0u8; SequenceCompleteHandles::MAX_SIZE];
    let seq_complete_handles_len = seq_complete_handles.marshal(&mut seq_complete_handles_buf);
    let mut seq_complete_handles_slice = &seq_complete_handles_buf[..seq_complete_handles_len];
    let unmarshalled_seq_complete_handles =
        SequenceCompleteHandles::unmarshal(&mut seq_complete_handles_slice).unwrap();
    assert_eq!(unmarshalled_seq_complete_handles, seq_complete_handles);

    let final_data = Tpm2bMaxBuffer::new(&[0xAA; 16]).unwrap();
    let seq_complete_cmd = SequenceComplete {
        buffer: final_data,
        hierarchy: Handle::RH_NULL,
    };
    let mut seq_complete_cmd_buf = [0u8; SequenceComplete::MAX_SIZE];
    let seq_complete_cmd_len = seq_complete_cmd.marshal(&mut seq_complete_cmd_buf);
    let mut seq_complete_cmd_slice = &seq_complete_cmd_buf[..seq_complete_cmd_len];
    let unmarshalled_seq_complete_cmd =
        SequenceComplete::unmarshal(&mut seq_complete_cmd_slice).unwrap();
    assert_eq!(unmarshalled_seq_complete_cmd, seq_complete_cmd);

    let result = Tpm2bDigest::new(&[0xBB; 32]).unwrap();
    let seq_complete_resp = responses::SequenceComplete { result, validation };
    let mut seq_complete_resp_buf = [0u8; <SequenceComplete as Command>::Response::MAX_SIZE];
    let seq_complete_resp_len = seq_complete_resp.marshal(&mut seq_complete_resp_buf);
    let mut seq_complete_resp_slice = &seq_complete_resp_buf[..seq_complete_resp_len];
    let unmarshalled_seq_complete_resp =
        <SequenceComplete as Command>::Response::unmarshal(&mut seq_complete_resp_slice).unwrap();
    assert_eq!(unmarshalled_seq_complete_resp, seq_complete_resp);

    // ---- Test TPM2_HMAC_Start ----
    let hmac_handles = HmacStartHandles {
        handle: Handle(0x80000001),
    };
    let mut hmac_handles_buf = [0u8; HmacStartHandles::MAX_SIZE];
    let hmac_handles_len = hmac_handles.marshal(&mut hmac_handles_buf);
    let mut hmac_handles_slice = &hmac_handles_buf[..hmac_handles_len];
    let unmarshalled_hmac_handles = HmacStartHandles::unmarshal(&mut hmac_handles_slice).unwrap();
    assert_eq!(unmarshalled_hmac_handles, hmac_handles);

    let auth = Tpm2bAuth::new(&[0x12; 20]).unwrap();
    let hmac_cmd = HmacStart {
        auth,
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let mut hmac_cmd_buf = [0u8; HmacStart::MAX_SIZE];
    let hmac_cmd_len = hmac_cmd.marshal(&mut hmac_cmd_buf);
    let mut hmac_cmd_slice = &hmac_cmd_buf[..hmac_cmd_len];
    let unmarshalled_hmac_cmd = HmacStart::unmarshal(&mut hmac_cmd_slice).unwrap();
    assert_eq!(unmarshalled_hmac_cmd, hmac_cmd);

    let hmac_resp_handles = HmacStartRespHandles {
        sequence_handle: Handle(0x80000002),
    };
    let mut hmac_resp_handles_buf = [0u8; HmacStartRespHandles::MAX_SIZE];
    let hmac_resp_handles_len = hmac_resp_handles.marshal(&mut hmac_resp_handles_buf);
    let mut hmac_resp_handles_slice = &hmac_resp_handles_buf[..hmac_resp_handles_len];
    let unmarshalled_hmac_resp_handles =
        HmacStartRespHandles::unmarshal(&mut hmac_resp_handles_slice).unwrap();
    assert_eq!(unmarshalled_hmac_resp_handles, hmac_resp_handles);
}

#[test]
fn test_tpml_digest_values_marshalling() {
    let lp =
        TpmlDigestValues::new(&[TpmtHa::Sha256(&[0xaa; 32]), TpmtHa::Sha256(&[0xbb; 32])])
            .unwrap();

    let mut buf = [0u8; TpmlDigestValues::MAX_SIZE];
    let len = lp.marshal(&mut buf);

    let mut reader = &buf[..len];
    let unmarshaled = TpmlDigestValues::unmarshal(&mut reader).unwrap();
    assert_eq!(unmarshaled, lp);

    // Test count > TPM2_NUM_PCR_BANKS (HASH_COUNT) fails with SIZE error.
    for invalid_count in [(TpmiAlgHash::HASH_COUNT + 1) as u32, 16, 17] {
        let mut invalid_buf = [0u8; 1024];
        invalid_buf[0..4].copy_from_slice(&invalid_count.to_be_bytes());
        let mut offset = 4;
        for _ in 0..invalid_count {
            invalid_buf[offset..offset + 2]
                .copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
            offset += 2 + 32; // 2 bytes alg ID + 32 bytes SHA256 digest
        }

        let mut reader = &invalid_buf[..offset];
        let err = TpmlDigestValues::unmarshal(&mut reader).unwrap_err();
        assert_eq!(err, tpm2::errors::UnmarshalError::SIZE);
    }
}

#[test]
fn test_tpml_pcr_selection_marshalling() {
    let selection = TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0xF, 0xF, 0xF]).unwrap();
    let lp = TpmlPcrSelection::new(&[selection]).unwrap();

    let mut buf = [0u8; TpmlPcrSelection::MAX_SIZE];
    let len = lp.marshal(&mut buf);

    let mut reader = &buf[..len];
    let unmarshaled = TpmlPcrSelection::unmarshal(&mut reader).unwrap();
    assert_eq!(unmarshaled, lp);

    // Test count > TPM2_NUM_PCR_BANKS (HASH_COUNT) fails with SIZE error.
    for invalid_count in [(TpmiAlgHash::HASH_COUNT + 1) as u32, 16, 17] {
        let mut invalid_buf = [0u8; 512];
        invalid_buf[0..4].copy_from_slice(&invalid_count.to_be_bytes());
        let mut offset = 4;
        for _ in 0..invalid_count {
            invalid_buf[offset..offset + 2]
                .copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
            invalid_buf[offset + 2] = 3; // sizeof_select
            invalid_buf[offset + 3..offset + 6].copy_from_slice(&[0u8; 3]); // pcr_select
            offset += 6;
        }

        let mut reader = &invalid_buf[..offset];
        let err = TpmlPcrSelection::unmarshal(&mut reader).unwrap_err();
        assert_eq!(err, tpm2::errors::UnmarshalError::SIZE);
    }

    // Verifying constructing TpmsPcrSelection with invalid bounds (length > 3) fails
    assert!(TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0xF, 0xF, 0xF, 0xF]).is_err());

    // Verifying constructing TpmsPcrSelect with invalid bounds (length > MAX or < MIN) fails
    assert!(TpmsPcrSelect::new(&[0xF; TpmsPcrSelect::MAX + 1]).is_err());
    assert!(TpmsPcrSelect::new(&[0xF; TpmsPcrSelect::MIN - 1]).is_err());

    // Verifying unmarshalling invalid bounds (sizeof_select != 3) fails
    let mut invalid_select_buf = [0u8; 10];
    invalid_select_buf[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    invalid_select_buf[2] = 4; // sizeof_select = 4 (invalid, != 3)
    invalid_select_buf[3..7].copy_from_slice(&[0xF; 4]);

    let mut reader = &invalid_select_buf[..7];
    let err = TpmsPcrSelection::unmarshal(&mut reader).unwrap_err();
    assert_eq!(err, tpm2::errors::UnmarshalError::VALUE);
}

#[test]
fn test_nv_undefine_space_marshalling() {
    let handles = NVUndefineSpaceHandles {
        auth_handle: Handle::RH_OWNER,
        nv_index: Handle(0x01000001),
    };
    let mut handles_buf = [0u8; NVUndefineSpaceHandles::MAX_SIZE];
    let handles_len = handles.marshal(&mut handles_buf);

    let mut expected_handles = Vec::new();
    expected_handles.extend_from_slice(&0x40000001u32.to_be_bytes()); // RHOwner (0x40000001)
    expected_handles.extend_from_slice(&0x01000001u32.to_be_bytes()); // NV Index 0x01000001

    assert_eq!(handles_len, expected_handles.len());
    assert_eq!(&handles_buf[..handles_len], expected_handles.as_slice());

    let mut handles_slice = &handles_buf[..handles_len];
    let unmarshalled_handles = NVUndefineSpaceHandles::unmarshal(&mut handles_slice).unwrap();
    assert_eq!(unmarshalled_handles, handles);

    let cmd = NVUndefineSpace {};
    let mut cmd_buf = [0u8; NVUndefineSpace::MAX_SIZE];
    let cmd_len = cmd.marshal(&mut cmd_buf);
    assert_eq!(cmd_len, 0);

    let mut cmd_slice = &cmd_buf[..cmd_len];
    let unmarshalled_cmd = NVUndefineSpace::unmarshal(&mut cmd_slice).unwrap();
    assert_eq!(unmarshalled_cmd, cmd);
}

#[test]
fn test_print_ecc_parent() {
    let public_area = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            TpmsEccParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint::default(),
        ),
    };
    let tpm2b_pub: Tpm2bPublic = Tpm2b(public_area);
    let mut buf = [0u8; Tpm2bPublic::MAX_SIZE];
    let len = tpm2b_pub.marshal(&mut buf);
    println!(
        "ECC Parent Tpm2bPublic bytes (len={}): {:02x?}",
        len,
        &buf[..len]
    );
}

#[test]
fn test_command_and_struct_validated_spec_types() {
    use tpm2::errors::UnmarshalError;

    // 1. HierarchyControl: state must be bool (TPMI_YES_NO)
    let hc = HierarchyControl {
        enable: Handle::RH_OWNER,
        state: true,
    };
    let mut hc_buf = [0u8; HierarchyControl::MAX_SIZE];
    let hc_len = hc.marshal(&mut hc_buf);
    assert_eq!(&hc_buf[..hc_len], &[0x40, 0x00, 0x00, 0x01, 0x01]);
    let mut hc_slice = &hc_buf[..hc_len];
    assert_eq!(HierarchyControl::unmarshal(&mut hc_slice), Ok(hc));

    // Invalid state (2, 0xFF) must fail unmarshalling with VALUE in parameter 2
    for invalid_state in [2u8, 0xFFu8] {
        let invalid_buf = [0x40, 0x00, 0x00, 0x01, invalid_state];
        let mut src = &invalid_buf[..];
        assert_eq!(
            HierarchyControl::unmarshal(&mut src),
            Err(UnmarshalError::VALUE.in_parameter(2))
        );
    }

    // 2. ClearControl: disable must be bool (TPMI_YES_NO)
    let cc = ClearControl { disable: false };
    let mut cc_buf = [0u8; ClearControl::MAX_SIZE];
    let cc_len = cc.marshal(&mut cc_buf);
    assert_eq!(&cc_buf[..cc_len], &[0x00]);
    let mut cc_slice = &cc_buf[..cc_len];
    assert_eq!(ClearControl::unmarshal(&mut cc_slice), Ok(cc));

    // Invalid disable (2, 0xFF) must fail unmarshalling with VALUE in parameter 1
    for invalid_disable in [2u8, 0xFFu8] {
        let invalid_buf = [invalid_disable];
        let mut src = &invalid_buf[..];
        assert_eq!(
            ClearControl::unmarshal(&mut src),
            Err(UnmarshalError::VALUE.in_parameter(1))
        );
    }

    // 3. ClockRateAdjust: rate_adjust must be TpmClockAdjust (TPM_CLOCK_ADJUST)
    let cra = ClockRateAdjust {
        rate_adjust: TpmClockAdjust::CoarseSlower,
    };
    let mut cra_buf = [0u8; ClockRateAdjust::MAX_SIZE];
    let cra_len = cra.marshal(&mut cra_buf);
    assert_eq!(&cra_buf[..cra_len], &[(-3i8) as u8]);
    let mut cra_slice = &cra_buf[..cra_len];
    assert_eq!(ClockRateAdjust::unmarshal(&mut cra_slice), Ok(cra));

    // Invalid rate_adjust (-4, 4, 42) must fail unmarshalling with VALUE in parameter 1
    for invalid_adj in [-4i8, 4i8, 42i8] {
        let invalid_buf = [invalid_adj as u8];
        let mut src = &invalid_buf[..];
        assert_eq!(
            ClockRateAdjust::unmarshal(&mut src),
            Err(UnmarshalError::VALUE.in_parameter(1))
        );
    }

    // 4. TpmsCommandAuditInfo: digest_alg must be Alg (TPM_ALG_ID)
    let audit_info = TpmsCommandAuditInfo {
        audit_counter: 42,
        digest_alg: Alg::SHA256,
        audit_digest: Tpm2bDigest::default(),
        command_digest: Tpm2bDigest::default(),
    };
    let mut audit_buf = [0u8; TpmsCommandAuditInfo::MAX_SIZE];
    let audit_len = audit_info.marshal(&mut audit_buf);
    let mut audit_slice = &audit_buf[..audit_len];
    assert_eq!(
        TpmsCommandAuditInfo::unmarshal(&mut audit_slice),
        Ok(audit_info)
    );

    // Reserved algorithm IDs (0x0000, 0x00C1, 0x8000, 0xFFFF) unmarshal cleanly as TPM_ALG_ID (UINT16 Constants)
    for raw_alg in [0x0000u16, 0x00C1u16, 0x8000u16, 0xFFFFu16] {
        let mut raw_buf = audit_buf;
        raw_buf[8..10].copy_from_slice(&raw_alg.to_be_bytes());
        let mut src = &raw_buf[..audit_len];
        let info = TpmsCommandAuditInfo::unmarshal(&mut src).unwrap();
        assert_eq!(info.digest_alg, Alg::from(raw_alg));
    }
}

#[test]
fn test_nv_digest_certify_info_and_tpmu_attest() {
    let nv_digest_info = TpmsNvDigestCertifyInfo {
        index_name: Tpm2bName::new(&[0x00, 0x0B, 0x11, 0x22]).unwrap(),
        nv_digest: Tpm2bDigest::new(&[0xAA; 32]).unwrap(),
    };

    let mut info_buf = [0u8; TpmsNvDigestCertifyInfo::MAX_SIZE];
    let info_len = nv_digest_info.marshal(&mut info_buf);
    let mut reader = &info_buf[..info_len];
    let unmarshaled_info = TpmsNvDigestCertifyInfo::unmarshal(&mut reader).unwrap();
    assert_eq!(unmarshaled_info, nv_digest_info);
    assert!(reader.is_empty());

    let attest = TpmsAttest {
        magic: TpmGenerated,
        qualified_signer: Tpm2bName::new(&[0x00, 0x0B, 0x33, 0x44]).unwrap(),
        extra_data: Tpm2bData::new(&[0x55, 0x66]).unwrap(),
        clock_info: TpmsClockInfo {
            clock: 12345,
            reset_count: 1,
            restart_count: 2,
            safe: true,
        },
        firmware_version: 0x0001_0002_0003_0004,
        attested: TpmuAttest::NvDigest(nv_digest_info),
    };
    assert_eq!(attest.attested_type(), TpmSt::ATTEST_NV_DIGEST);

    let mut attest_buf = [0u8; TpmsAttest::MAX_SIZE];
    let attest_len = attest.marshal(&mut attest_buf);
    let mut reader = &attest_buf[..attest_len];
    let unmarshaled_attest = TpmsAttest::unmarshal(&mut reader).unwrap();
    assert_eq!(unmarshaled_attest, attest);
    assert!(reader.is_empty());
}

#[test]
fn test_tpms_capability_data_all_variants() {
    // 1. TPM_CAP_ACT -> TpmsCapabilityData::ActData
    let act_entry = TpmsActData {
        handle: Handle(0x4000_0110),
        timeout: 3600,
        attributes: TpmaAct::SIGNALED | TpmaAct::PRESERVE_SIGNALED,
    };
    let act_list = TpmlActData::from_slice(&[act_entry]).unwrap();
    let cap_act = TpmsCapabilityData::ActData(act_list);
    let mut buf = [0u8; TpmsCapabilityData::MAX_SIZE];
    let len = cap_act.marshal(&mut buf);
    let mut reader = &buf[..len];
    assert_eq!(TpmsCapabilityData::unmarshal(&mut reader).unwrap(), cap_act);
    assert!(reader.is_empty());

    // Verify reserved bits in TpmaAct fail with RESERVED_BITS
    // Construct full 16-byte entry: 4 handle + 4 timeout + 4 attributes (with bit 2 set)
    let mut full_bad_act = [0u8; 20];
    full_bad_act[0..4].copy_from_slice(&(TpmCap::ACT as u32).to_be_bytes());
    full_bad_act[4..8].copy_from_slice(&1u32.to_be_bytes());
    full_bad_act[8..12].copy_from_slice(&0x4000_0110u32.to_be_bytes());
    full_bad_act[12..16].copy_from_slice(&100u32.to_be_bytes());
    full_bad_act[16..20].copy_from_slice(&0x0000_0004u32.to_be_bytes());
    let mut bad_reader = &full_bad_act[..];
    assert_eq!(
        TpmsCapabilityData::unmarshal(&mut bad_reader),
        Err(UnmarshalError::RESERVED_BITS)
    );

    // 2. TPM_CAP_PUB_KEYS -> TpmsCapabilityData::PubKeys
    let pub_key_list = TpmlPubKey::from_slice(&[]).unwrap();
    let cap_pub_keys = TpmsCapabilityData::PubKeys(pub_key_list);
    let len = cap_pub_keys.marshal(&mut buf);
    let mut reader = &buf[..len];
    assert_eq!(
        TpmsCapabilityData::unmarshal(&mut reader).unwrap(),
        cap_pub_keys
    );
    assert!(reader.is_empty());

    // 3. TPM_CAP_SPDM_SESSION_INFO -> TpmsCapabilityData::SpdmSessionInfo
    let spdm_info = TpmsSpdmSessionInfo {
        req_key_name: Tpm2bName::new(&[0x01, 0x02]).unwrap(),
        tpm_key_name: Tpm2bName::new(&[0x03, 0x04]).unwrap(),
    };
    let spdm_list = TpmlSpdmSessionInfo::from_slice(&[spdm_info]).unwrap();
    let cap_spdm = TpmsCapabilityData::SpdmSessionInfo(spdm_list);
    let len = cap_spdm.marshal(&mut buf);
    let mut reader = &buf[..len];
    assert_eq!(
        TpmsCapabilityData::unmarshal(&mut reader).unwrap(),
        cap_spdm
    );
    assert!(reader.is_empty());

    // 4. TPM_CAP_VENDOR_PROPERTY -> TpmsCapabilityData::VendorProperty
    let vendor_prop = Tpm2bVendorProperty::new(b"google-tpm-rs").unwrap();
    let vendor_list = TpmlVendorProperty::from_slice(&[vendor_prop]).unwrap();
    let cap_vendor = TpmsCapabilityData::VendorProperty(vendor_list);
    let len = cap_vendor.marshal(&mut buf);
    let mut reader = &buf[..len];
    assert_eq!(
        TpmsCapabilityData::unmarshal(&mut reader).unwrap(),
        cap_vendor
    );
    assert!(reader.is_empty());

    // Verify Tpm2bVendorProperty rejects size > 512
    assert!(Tpm2bVendorProperty::new(&[0u8; 513]).is_none());
}

#[test]
fn test_tpml_digest_count_validation() {
    let d1 = Tpm2bDigest::new(&[0x11; 32]).unwrap();
    let d2 = Tpm2bDigest::new(&[0x22; 32]).unwrap();

    // count = 0 -> TpmlDigest::unmarshal succeeds (valid for TPM2_PCR_Read with 0 PCRs)
    let zero_buf = 0u32.to_be_bytes();
    let mut src = &zero_buf[..];
    assert_eq!(TpmlDigest::unmarshal(&mut src).unwrap().as_slice().len(), 0);
    // PolicyOR::unmarshal rejects count = 0 with parameter 1 SIZE error
    let mut src = &zero_buf[..];
    assert_eq!(
        commands::PolicyOR::unmarshal(&mut src),
        Err(UnmarshalError::SIZE.in_parameter(1))
    );

    // count = 1 with no element bytes -> PolicyOR::unmarshal returns SIZE error immediately (before INSUFFICIENT)
    let one_no_elem_buf = 1u32.to_be_bytes();
    let mut src = &one_no_elem_buf[..];
    assert_eq!(
        commands::PolicyOR::unmarshal(&mut src),
        Err(UnmarshalError::SIZE.in_parameter(1))
    );
    // whereas general TpmlDigest::unmarshal attempts to read 1 element and returns INSUFFICIENT
    let mut src = &one_no_elem_buf[..];
    assert_eq!(
        TpmlDigest::unmarshal(&mut src),
        Err(UnmarshalError::INSUFFICIENT)
    );

    // count = 1 with element -> TpmlDigest::unmarshal succeeds (valid for TPM2_PCR_Read with 1 PCR)
    let one_list = TpmlDigest::from_slice(&[d1]).unwrap();
    let mut one_buf = [0u8; TpmlDigest::MAX_SIZE];
    let one_len = one_list.marshal(&mut one_buf);
    let mut src = &one_buf[..one_len];
    assert_eq!(TpmlDigest::unmarshal(&mut src).unwrap(), one_list);
    // PolicyOR::unmarshal rejects count = 1 with parameter 1 SIZE error
    let mut src = &one_buf[..one_len];
    assert_eq!(
        commands::PolicyOR::unmarshal(&mut src),
        Err(UnmarshalError::SIZE.in_parameter(1))
    );

    // count = 9 (> TPML_DIGEST_MAX_DIGESTS) -> SIZE error immediately
    let nine_buf = 9u32.to_be_bytes();
    let mut src = &nine_buf[..];
    assert_eq!(TpmlDigest::unmarshal(&mut src), Err(UnmarshalError::SIZE));
    let mut src = &nine_buf[..];
    assert_eq!(
        commands::PolicyOR::unmarshal(&mut src),
        Err(UnmarshalError::SIZE.in_parameter(1))
    );

    // count = 2 -> succeeds for both TpmlDigest::unmarshal and PolicyOR::unmarshal
    let two_list = TpmlDigest::from_slice(&[d1, d2]).unwrap();
    let mut two_buf = [0u8; TpmlDigest::MAX_SIZE];
    let two_len = two_list.marshal(&mut two_buf);
    let mut src = &two_buf[..two_len];
    assert_eq!(TpmlDigest::unmarshal(&mut src).unwrap(), two_list);
    let mut src = &two_buf[..two_len];
    assert_eq!(
        commands::PolicyOR::unmarshal(&mut src).unwrap().p_hash_list,
        two_list
    );
}

#[test]
fn test_ticket_and_context_hierarchy_and_tag_validation() {
    let valid_hierarchies = [
        Handle::RH_OWNER,
        Handle::RH_PLATFORM,
        Handle::RH_ENDORSEMENT,
        Handle::RH_NULL,
        Handle::RH_FW_OWNER,
        Handle::RH_FW_ENDORSEMENT,
        Handle::RH_FW_PLATFORM,
        Handle::RH_FW_NULL,
        Handle(0x4001_0000),
        Handle(0x4001_FFFF),
        Handle(0x4002_0005),
        Handle(0x4003_1234),
        Handle(0x4004_FFFF),
    ];

    for h in valid_hierarchies {
        let tk_creation = TpmtTkCreation::new(h, Tpm2bDigest::default());
        let mut buf = [0u8; TpmtTkCreation::MAX_SIZE];
        let len = tk_creation.marshal(&mut buf);
        let mut src = &buf[..len];
        assert_eq!(TpmtTkCreation::unmarshal(&mut src).unwrap(), tk_creation);

        let tk_verified = TpmtTkVerified::new(h, Tpm2bDigest::default());
        let mut verified_buf = [0u8; TpmtTkVerified::MAX_SIZE];
        let len = tk_verified.marshal(&mut verified_buf);
        let mut src = &verified_buf[..len];
        assert_eq!(TpmtTkVerified::unmarshal(&mut src).unwrap(), tk_verified);

        let tk_hashcheck = TpmtTkHashcheck::new(h, Tpm2bDigest::default());
        let len = tk_hashcheck.marshal(&mut buf);
        let mut src = &buf[..len];
        assert_eq!(TpmtTkHashcheck::unmarshal(&mut src).unwrap(), tk_hashcheck);

        let tk_auth = TpmtTkAuth::Signed(h, Tpm2bDigest::default());
        let len = tk_auth.marshal(&mut buf);
        let mut src = &buf[..len];
        assert_eq!(TpmtTkAuth::unmarshal(&mut src).unwrap(), tk_auth);
    }

    // Invalid tag AND invalid hierarchy must return TAG error first (not VALUE)
    let mut bad_tag_and_hierarchy = [0u8; 8];
    bad_tag_and_hierarchy[0..2].copy_from_slice(&0x9999u16.to_be_bytes()); // invalid tag
    bad_tag_and_hierarchy[2..6].copy_from_slice(&0x8000_0000u32.to_be_bytes()); // invalid hierarchy
    bad_tag_and_hierarchy[6..8].copy_from_slice(&0u16.to_be_bytes()); // empty digest
    let mut src = &bad_tag_and_hierarchy[..];
    assert_eq!(
        TpmtTkCreation::unmarshal(&mut src),
        Err(UnmarshalError::TAG)
    );
    let mut src = &bad_tag_and_hierarchy[..];
    assert_eq!(TpmtTkAuth::unmarshal(&mut src), Err(UnmarshalError::TAG));
    let mut src = &bad_tag_and_hierarchy[..];
    assert_eq!(
        TpmtTkVerified::unmarshal(&mut src),
        Err(UnmarshalError::TAG)
    );
    let mut src = &bad_tag_and_hierarchy[..];
    assert_eq!(
        TpmtTkHashcheck::unmarshal(&mut src),
        Err(UnmarshalError::TAG)
    );

    // Valid tag with invalid hierarchy must return VALUE
    let invalid_hierarchies = [
        0x8000_0000u32,
        0x0100_0000,
        0x4000_0002,
        0x4000_0144,
        0x4005_0000,
    ];
    for bad_h in invalid_hierarchies {
        let mut bad_h_buf = [0u8; 8];
        bad_h_buf[0..2].copy_from_slice(&TpmSt::CREATION.id().to_be_bytes());
        bad_h_buf[2..6].copy_from_slice(&bad_h.to_be_bytes());
        bad_h_buf[6..8].copy_from_slice(&0u16.to_be_bytes());
        let mut src = &bad_h_buf[..];
        assert_eq!(
            TpmtTkCreation::unmarshal(&mut src),
            Err(UnmarshalError::VALUE)
        );
    }
}

#[test]
fn test_command_handles_and_parameters_tpmi_validation() {
    use tpm2::commands::*;

    // 1. Command Handles validation & error position modifiers (.in_handle(n))
    // CreateHandles: parent_handle must be TPMI_DH_OBJECT (non-null)
    let mut slice = &[0x40, 0x00, 0x00, 0x07][..]; // RH_NULL not allowed
    assert_eq!(
        CreateHandles::unmarshal(&mut slice),
        Err(UnmarshalError::VALUE.in_handle(1))
    );

    // CertifyHandles: object_handle (H1: non-null object), sign_handle (H2: nullable object)
    let mut slice = &[0x80, 0x00, 0x00, 0x01, 0x40, 0x00, 0x00, 0x01][..]; // H2 = RH_OWNER invalid
    assert_eq!(
        CertifyHandles::unmarshal(&mut slice),
        Err(UnmarshalError::VALUE.in_handle(2))
    );

    // PolicyNVHandles: auth_handle (H1: NV_AUTH), nv_index (H2: NV_INDEX), policy_session (H3: SH_POLICY)
    let mut slice = &[
        0x40, 0x00, 0x00, 0x01, // H1: RH_OWNER (valid)
        0x01, 0x00, 0x00, 0x01, // H2: NV index (valid)
        0x02, 0x00, 0x00, 0x00, // H3: HMAC session (invalid for SH_POLICY)
    ][..];
    assert_eq!(
        PolicyNVHandles::unmarshal(&mut slice),
        Err(UnmarshalError::VALUE.in_handle(3))
    );

    // PCRExtendHandles: pcr_handle (H1: TPMI_DH_PCR 0..=23)
    let mut slice = &24u32.to_be_bytes()[..];
    assert_eq!(
        PCRExtendHandles::unmarshal(&mut slice),
        Err(UnmarshalError::VALUE.in_handle(1))
    );

    // 2. Handle-typed command parameters validation & error position modifiers (.in_parameter(n))
    // Hash: parameter 3 (hierarchy: TPMI_RH_HIERARCHY)
    let bad_hash = Hash {
        data: Tpm2bMaxBuffer::default(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle(0x8000_0000),
    };
    let mut buf = [0u8; Hash::MAX_SIZE];
    let len = bad_hash.marshal(&mut buf);
    let mut slice = &buf[..len];
    assert_eq!(
        Hash::unmarshal(&mut slice),
        Err(UnmarshalError::VALUE.in_parameter(3))
    );

    // SequenceComplete: parameter 2 (hierarchy: TPMI_RH_HIERARCHY)
    let bad_seq_complete = SequenceComplete {
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle(0x8000_0000),
    };
    let mut buf = [0u8; SequenceComplete::MAX_SIZE];
    let len = bad_seq_complete.marshal(&mut buf);
    let mut slice = &buf[..len];
    assert_eq!(
        SequenceComplete::unmarshal(&mut slice),
        Err(UnmarshalError::VALUE.in_parameter(2))
    );

    // EvictControl: parameter 1 (persistent_handle: TPMI_DH_PERSISTENT)
    let bad_evict = EvictControl {
        persistent_handle: Handle(0x8000_0000), // Transient instead of Persistent
    };
    let mut buf = [0u8; EvictControl::MAX_SIZE];
    let len = bad_evict.marshal(&mut buf);
    let mut slice = &buf[..len];
    assert_eq!(
        EvictControl::unmarshal(&mut slice),
        Err(UnmarshalError::VALUE.in_parameter(1))
    );

    // HierarchyControl: parameter 1 (enable: TPMI_RH_ENABLES)
    let bad_hc = HierarchyControl {
        enable: Handle(0x4000_0007), // RH_NULL not in TPMI_RH_ENABLES (non-nullable)
        state: true,
    };
    let mut buf = [0u8; HierarchyControl::MAX_SIZE];
    let len = bad_hc.marshal(&mut buf);
    let mut slice = &buf[..len];
    assert_eq!(
        HierarchyControl::unmarshal(&mut slice),
        Err(UnmarshalError::VALUE.in_parameter(1))
    );

    // PCRSetAuthPolicy: parameter 3 (pcr_num: TPMI_DH_PCR)
    let bad_pcr_policy = PCRSetAuthPolicy {
        auth_policy: Tpm2bDigest::default(),
        hash_alg: Some(TpmiAlgHash::Sha256),
        pcr_num: Handle(24),
    };
    let mut buf = [0u8; PCRSetAuthPolicy::MAX_SIZE];
    let len = bad_pcr_policy.marshal(&mut buf);
    let mut slice = &buf[..len];
    assert_eq!(
        PCRSetAuthPolicy::unmarshal(&mut slice),
        Err(UnmarshalError::VALUE.in_parameter(3))
    );

    // 3. Structure handle validation
    // TpmsAuthCommand with invalid session handle (0x80000000)
    let bad_auth = TpmsAuthCommand {
        session_handle: Handle(0x8000_0000),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession(0),
        hmac: Tpm2bAuth::default(),
    };
    let mut buf = [0u8; TpmsAuthCommand::MAX_SIZE];
    let len = bad_auth.marshal(&mut buf);
    let mut slice = &buf[..len];
    assert_eq!(
        TpmsAuthCommand::unmarshal(&mut slice),
        Err(UnmarshalError::VALUE)
    );
}

#[test]
fn test_tpmt_tk_verified_all_variants_and_metadata() {
    use tpm2::commands::{
        PolicyAuthorize, VerifyDigestSignatureRsp, VerifySequenceCompleteRsp, VerifySignatureRsp,
    };

    assert_eq!(
        TpmtTkVerified::MAX_SIZE,
        TpmSt::MAX_SIZE + Handle::MAX_SIZE + TpmiAlgHash::MAX_SIZE + Tpm2bDigest::MAX_SIZE
    );

    let hmac_bytes = [0xAAu8; 32];
    let hmac_digest = Tpm2bDigest::from_bytes(&hmac_bytes).unwrap();

    // 1. TPM_ST_VERIFIED (0x8022)
    let tk_v = TpmtTkVerified::new(Handle::RH_OWNER, hmac_digest);
    assert_eq!(tk_v.tag(), TpmSt::VERIFIED.id());
    assert_eq!(Ticket::tag(&tk_v), TpmSt::VERIFIED);
    assert_eq!(tk_v.hierarchy(), Handle::RH_OWNER);
    assert_eq!(tk_v.metadata(), TpmuTkVerifiedMeta::Verified);
    assert_eq!(tk_v.digest(), &hmac_digest);
    assert_eq!(tk_v.hmac(), &hmac_digest);

    let mut buf = [0u8; TpmtTkVerified::MAX_SIZE];
    let len = tk_v.marshal(&mut buf);
    assert_eq!(len, 2 + 4 + 2 + 32);
    assert_eq!(&buf[0..2], &0x8022u16.to_be_bytes());
    let mut src = &buf[..len];
    let unmarshaled_v = TpmtTkVerified::unmarshal(&mut src).unwrap();
    assert_eq!(unmarshaled_v, tk_v);
    assert!(src.is_empty());

    // 2. TPM_ST_MESSAGE_VERIFIED (0x8026)
    let tk_mv = TpmtTkVerified::new_message_verified(Handle::RH_ENDORSEMENT, hmac_digest);
    assert_eq!(tk_mv.tag(), TpmSt::MESSAGE_VERIFIED.id());
    assert_eq!(Ticket::tag(&tk_mv), TpmSt::MESSAGE_VERIFIED);
    assert_eq!(tk_mv.hierarchy(), Handle::RH_ENDORSEMENT);
    assert_eq!(tk_mv.metadata(), TpmuTkVerifiedMeta::MessageVerified);
    assert_eq!(tk_mv.digest(), &hmac_digest);
    assert_eq!(tk_mv.hmac(), &hmac_digest);

    let len = tk_mv.marshal(&mut buf);
    assert_eq!(len, 2 + 4 + 2 + 32);
    assert_eq!(&buf[0..2], &0x8026u16.to_be_bytes());
    let mut src = &buf[..len];
    let unmarshaled_mv = TpmtTkVerified::unmarshal(&mut src).unwrap();
    assert_eq!(unmarshaled_mv, tk_mv);
    assert!(src.is_empty());

    // VerifySequenceCompleteRsp round-trip with MessageVerified ticket
    let vsc_rsp = VerifySequenceCompleteRsp { validation: tk_mv };
    let mut rsp_buf = [0u8; VerifySequenceCompleteRsp::MAX_SIZE];
    let rsp_len = vsc_rsp.marshal(&mut rsp_buf);
    let mut rsp_src = &rsp_buf[..rsp_len];
    assert_eq!(
        VerifySequenceCompleteRsp::unmarshal(&mut rsp_src).unwrap(),
        vsc_rsp
    );

    // 3. TPM_ST_DIGEST_VERIFIED (0x8027) with TPMI_ALG_HASH metadata
    let tk_dv =
        TpmtTkVerified::new_digest_verified(Handle::RH_PLATFORM, TpmiAlgHash::Sha256, hmac_digest);
    assert_eq!(tk_dv.tag(), TpmSt::DIGEST_VERIFIED.id());
    assert_eq!(Ticket::tag(&tk_dv), TpmSt::DIGEST_VERIFIED);
    assert_eq!(tk_dv.hierarchy(), Handle::RH_PLATFORM);
    assert_eq!(
        tk_dv.metadata(),
        TpmuTkVerifiedMeta::DigestVerified(TpmiAlgHash::Sha256)
    );
    assert_eq!(tk_dv.digest(), &hmac_digest);
    assert_eq!(tk_dv.hmac(), &hmac_digest);

    let len = tk_dv.marshal(&mut buf);
    assert_eq!(len, 2 + 4 + 2 + 2 + 32);
    assert_eq!(&buf[0..2], &0x8027u16.to_be_bytes());
    assert_eq!(&buf[2..6], &Handle::RH_PLATFORM.0.to_be_bytes());
    assert_eq!(&buf[6..8], &Alg::SHA256.id().to_be_bytes());
    assert_eq!(&buf[8..10], &32u16.to_be_bytes());
    assert_eq!(&buf[10..42], &hmac_bytes);

    let mut src = &buf[..len];
    let unmarshaled_dv = TpmtTkVerified::unmarshal(&mut src).unwrap();
    assert_eq!(unmarshaled_dv, tk_dv);
    assert!(src.is_empty());

    // VerifyDigestSignatureRsp round-trip with DigestVerified ticket
    let vds_rsp = VerifyDigestSignatureRsp { validation: tk_dv };
    let mut rsp_buf = [0u8; VerifyDigestSignatureRsp::MAX_SIZE];
    let rsp_len = vds_rsp.marshal(&mut rsp_buf);
    let mut rsp_src = &rsp_buf[..rsp_len];
    assert_eq!(
        VerifyDigestSignatureRsp::unmarshal(&mut rsp_src).unwrap(),
        vds_rsp
    );

    // PolicyAuthorize round-trip with MessageVerified and DigestVerified tickets
    for check_ticket in [tk_v, tk_mv, tk_dv] {
        let pa = PolicyAuthorize {
            approved_policy: hmac_digest,
            policy_ref: Tpm2bNonce::from_bytes(&[1, 2, 3, 4]).unwrap(),
            key_sign: Tpm2bName::from_bytes(&[0x00, 0x0B, 0x11, 0x22]).unwrap(),
            check_ticket,
        };
        let mut pa_buf = [0u8; PolicyAuthorize::MAX_SIZE];
        let pa_len = pa.marshal(&mut pa_buf);
        let mut pa_src = &pa_buf[..pa_len];
        assert_eq!(PolicyAuthorize::unmarshal(&mut pa_src).unwrap(), pa);
        assert!(pa_src.is_empty());
    }

    // 4. Error cases for DigestVerified metadata
    // Invalid hash alg (0x0010 = TPM_ALG_NULL) in TPM_ST_DIGEST_VERIFIED must return HASH
    let mut bad_meta_buf = [0u8; 10];
    bad_meta_buf[0..2].copy_from_slice(&0x8027u16.to_be_bytes());
    bad_meta_buf[2..6].copy_from_slice(&Handle::RH_OWNER.0.to_be_bytes());
    bad_meta_buf[6..8].copy_from_slice(&Alg::NULL.id().to_be_bytes());
    bad_meta_buf[8..10].copy_from_slice(&0u16.to_be_bytes());
    let mut src = &bad_meta_buf[..];
    assert_eq!(
        TpmtTkVerified::unmarshal(&mut src),
        Err(UnmarshalError::HASH)
    );

    // Truncated before metadata in TPM_ST_DIGEST_VERIFIED must return INSUFFICIENT
    let mut src = &bad_meta_buf[..6];
    assert_eq!(
        TpmtTkVerified::unmarshal(&mut src),
        Err(UnmarshalError::INSUFFICIENT)
    );

    // VerifySignatureRsp round-trip
    let vs_rsp = VerifySignatureRsp { validation: tk_v };
    let mut rsp_buf = [0u8; VerifySignatureRsp::MAX_SIZE];
    let rsp_len = vs_rsp.marshal(&mut rsp_buf);
    let mut rsp_src = &rsp_buf[..rsp_len];
    assert_eq!(VerifySignatureRsp::unmarshal(&mut rsp_src).unwrap(), vs_rsp);
}

#[test]
fn test_bool_unmarshal() {
    // Invalid byte value (2) should return VALUE error and leave slice advanced by 1 byte (matching Marshal.c).
    let buf = [2u8, 0xAA, 0xBB];
    let mut src = &buf[..];
    assert_eq!(bool::unmarshal(&mut src), Err(UnmarshalError::VALUE));
    assert_eq!(src, &[0xAA, 0xBB]);

    // Invalid byte value (0xFF) should return VALUE error and consume the byte.
    let buf2 = [0xFFu8];
    let mut src2 = &buf2[..];
    assert_eq!(bool::unmarshal(&mut src2), Err(UnmarshalError::VALUE));
    assert!(src2.is_empty());

    // Empty slice should return INSUFFICIENT.
    let empty: [u8; 0] = [];
    let mut src3 = &empty[..];
    assert_eq!(
        bool::unmarshal(&mut src3),
        Err(UnmarshalError::INSUFFICIENT)
    );

    // Valid boolean unmarshal advances slice by 1 byte.
    let valid = [1u8, 0xCC];
    let mut src4 = &valid[..];
    assert_eq!(bool::unmarshal(&mut src4), Ok(true));
    assert_eq!(src4, &[0xCC]);
}

#[test]
fn test_specific_unmarshal_error_codes_and_positions() {
    use tpm2::{
        Tpm2bNvPublic, Tpm2bPublic, TpmiAlgKdf, TpmtKdfScheme,
        commands::{CreatePrimary, NVDefineSpace},
        errors::{Position, TpmRc},
    };

    // 1. Option<TpmiAlgKdf> and Option<TpmtKdfScheme> with invalid KDF alg (0x000B SHA256) -> UnmarshalError::KDF
    let bad_kdf_buf = [0x00u8, 0x0B, 0x00, 0x0B];
    let mut src = &bad_kdf_buf[..];
    assert_eq!(
        <Option<TpmiAlgKdf>>::unmarshal(&mut src),
        Err(UnmarshalError::KDF),
        "Invalid KDF algorithm ID must return UnmarshalError::KDF"
    );
    let mut src_scheme = &bad_kdf_buf[..];
    assert_eq!(
        <Option<TpmtKdfScheme>>::unmarshal(&mut src_scheme),
        Err(UnmarshalError::KDF),
        "Invalid KDF scheme selector must return UnmarshalError::KDF"
    );

    // 2. Tpm2bPublic with size == 0 -> UnmarshalError::SIZE
    let zero_pub_buf = [0x00u8, 0x00];
    let mut src_pub = &zero_pub_buf[..];
    assert_eq!(
        Tpm2bPublic::unmarshal(&mut src_pub),
        Err(UnmarshalError::SIZE),
        "Tpm2bPublic with size == 0 must return UnmarshalError::SIZE"
    );

    // 3. Tpm2bNvPublic with size == 0 -> UnmarshalError::SIZE
    let zero_nv_buf = [0x00u8, 0x00];
    let mut src_nv = &zero_nv_buf[..];
    assert_eq!(
        Tpm2bNvPublic::unmarshal(&mut src_nv),
        Err(UnmarshalError::SIZE),
        "Tpm2bNvPublic with size == 0 must return UnmarshalError::SIZE"
    );

    // 4. Tpm2bNvPublic with reserved bits in TPMA_NV (bit 8 = 0x00000100) -> UnmarshalError::RESERVED_BITS
    let default_hash_bytes = tpm2::Alg::from(tpm2::TpmiAlgHash::DEFAULT_HASH)
        .id()
        .to_be_bytes();
    let bad_nv_pub_buf = [
        0x00,
        0x0E, // size = 14
        0x01,
        0x00,
        0x00,
        0x01, // nvIndex
        default_hash_bytes[0],
        default_hash_bytes[1], // nameAlg = DEFAULT_HASH
        0x00,
        0x00,
        0x01,
        0x00, // attributes with reserved bit 8 set
        0x00,
        0x00, // authPolicy = empty
        0x00,
        0x00, // dataSize = 0
    ];
    let mut src_bad_nv = &bad_nv_pub_buf[..];
    assert_eq!(
        Tpm2bNvPublic::unmarshal(&mut src_bad_nv),
        Err(UnmarshalError::RESERVED_BITS),
        "Tpm2bNvPublic with reserved TPMA_NV bits must return UnmarshalError::RESERVED_BITS"
    );

    // 5. NVDefineSpace command unmarshalling attaches Parameter 2 position to publicInfo errors
    let mut nv_def_cmd_buf = [0u8; 18];
    nv_def_cmd_buf[0..2].copy_from_slice(&[0x00, 0x00]); // auth
    nv_def_cmd_buf[2..18].copy_from_slice(&bad_nv_pub_buf);
    let mut src_nv_cmd = &nv_def_cmd_buf[..];
    let err = NVDefineSpace::unmarshal(&mut src_nv_cmd).unwrap_err();
    assert_eq!(
        err.to_rc(),
        TpmRc::RESERVED_BITS.with(Position::parameter(2)),
        "NVDefineSpace unmarshal must attach Position::parameter(2) to publicInfo errors"
    );

    // 6. CreatePrimary command unmarshalling with size == 0 inPublic attaches Parameter 2 position to SIZE error
    let cp_cmd_buf = [0x00u8, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mut src_cp_cmd = &cp_cmd_buf[..];
    let err_cp = CreatePrimary::unmarshal(&mut src_cp_cmd).unwrap_err();
    assert_eq!(
        err_cp.to_rc(),
        TpmRc::SIZE.with(Position::parameter(2)),
        "CreatePrimary unmarshal with size == 0 inPublic must return TPM_RC_SIZE + P2"
    );
}

#[test]
fn test_rsa_key_bits_and_sensitive_and_ecc_point_unmarshalling() {
    use tpm2::commands::{CreatePrimary, ECDHZGen, LoadExternal};
    use tpm2::errors::{Position, TpmRc};
    use tpm2::{
        Tpm2bEccPoint, Tpm2bSensitive, Tpm2bSensitiveCreate, TpmiRsaKeyBits, TpmsNvPublic,
        TpmsRsaParms,
    };

    // 1. TpmiRsaKeyBits::try_from rejects unsupported key bit lengths (e.g. 512) with UnmarshalError::VALUE
    assert_eq!(
        TpmiRsaKeyBits::try_from(512),
        Err(UnmarshalError::VALUE),
        "TpmiRsaKeyBits::try_from(512) must fail with UnmarshalError::VALUE"
    );
    #[cfg(feature = "rsa2048")]
    assert_eq!(TpmiRsaKeyBits::try_from(2048), Ok(TpmiRsaKeyBits(2048)));

    // TpmsRsaParms::unmarshal with invalid scheme (0x0099) returns UnmarshalError::VALUE
    let bad_rsa_parms_buf = [0x00u8, 0x10, 0x00, 0x99, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mut src_bad_parms = &bad_rsa_parms_buf[..];
    assert_eq!(
        TpmsRsaParms::unmarshal(&mut src_bad_parms),
        Err(UnmarshalError::VALUE),
        "TpmsRsaParms::unmarshal with invalid scheme must return UnmarshalError::VALUE"
    );

    // TpmsNvPublic::unmarshal with invalid nvIndex (0x00000001) and invalid nameAlg (0x0001) returns UnmarshalError::VALUE (field 1 precedence)
    let bad_nv_pub_order = [
        0x00u8, 0x00, 0x00, 0x01, // nvIndex = 0x00000001 (invalid NV index handle)
        0x00, 0x01, // nameAlg = 0x0001 (RSA, invalid hash)
        0x00, 0x02, 0x00, 0x02, // attributes
        0x00, 0x00, // authPolicy
        0x00, 0x04, // dataSize
    ];
    let mut src_nv_order = &bad_nv_pub_order[..];
    assert_eq!(
        TpmsNvPublic::unmarshal(&mut src_nv_order),
        Err(UnmarshalError::VALUE),
        "TpmsNvPublic::unmarshal with invalid nvIndex must return UnmarshalError::VALUE before checking nameAlg"
    );

    // 2. Tpm2bSensitiveCreate rejects size == 0 with UnmarshalError::SIZE
    let zero_sens = [0x00u8, 0x00];
    let mut src_zero_sens = &zero_sens[..];
    assert_eq!(
        Tpm2bSensitiveCreate::unmarshal(&mut src_zero_sens),
        Err(UnmarshalError::SIZE),
        "Tpm2bSensitiveCreate with size == 0 must return UnmarshalError::SIZE"
    );

    // CreatePrimary with size == 0 inSensitive (param 1) returns TPM_RC_SIZE + P1
    let cp_zero_sens = [0x00u8, 0x00, 0x00, 0x00];
    let mut src_cp_zero = &cp_zero_sens[..];
    let err_cp_p1 = CreatePrimary::unmarshal(&mut src_cp_zero).unwrap_err();
    assert_eq!(
        err_cp_p1.to_rc(),
        TpmRc::SIZE.with(Position::parameter(1)),
        "CreatePrimary with size == 0 inSensitive must return TPM_RC_SIZE + P1"
    );

    // 3. Tpm2bSensitive with non-zero size validates inner TpmtSensitive
    let bad_sens = [0x00u8, 0x02, 0x00, 0x99];
    let mut src_bad_sens = &bad_sens[..];
    assert_eq!(
        Tpm2bSensitive::unmarshal(&mut src_bad_sens),
        Err(UnmarshalError::TYPE),
        "Tpm2bSensitive with invalid sensitiveType must return UnmarshalError::TYPE"
    );

    // LoadExternal with bad inPrivate (param 1) returns TPM_RC_TYPE + P1 even when inPublic (param 2) is size 0
    let le_bad_priv = [0x00u8, 0x02, 0x00, 0x99, 0x00, 0x00, 0x40, 0x00, 0x00, 0x07];
    let mut src_le = &le_bad_priv[..];
    let err_le = LoadExternal::unmarshal(&mut src_le).unwrap_err();
    assert_eq!(
        err_le.to_rc(),
        TpmRc::TYPE.with(Position::parameter(1)),
        "LoadExternal with invalid inPrivate sensitiveType must return TPM_RC_TYPE + P1"
    );

    // 4. Tpm2bEccPoint with non-zero size validates inner TpmsEccPoint
    let bad_pt = [0x00u8, 0x02, 0x00, 0x00];
    let mut src_bad_pt = &bad_pt[..];
    assert_eq!(
        Tpm2bEccPoint::unmarshal(&mut src_bad_pt),
        Err(UnmarshalError::INSUFFICIENT),
        "Tpm2bEccPoint with truncated inner TpmsEccPoint must return UnmarshalError::INSUFFICIENT"
    );
    let bad_pt_size = [0x00u8, 0x02, 0x00, 0x00, 0x00, 0x00];
    let mut src_bad_pt_size = &bad_pt_size[..];
    assert_eq!(
        Tpm2bEccPoint::unmarshal(&mut src_bad_pt_size),
        Err(UnmarshalError::SIZE),
        "Tpm2bEccPoint with mismatched inner TpmsEccPoint size must return UnmarshalError::SIZE"
    );

    // ECDHZGen rejects size == 0 inPoint with TPM_RC_SIZE + P1
    let zero_pt = [0x00u8, 0x00];
    let mut src_ecdh = &zero_pt[..];
    let err_ecdh = ECDHZGen::unmarshal(&mut src_ecdh).unwrap_err();
    assert_eq!(
        err_ecdh.to_rc(),
        TpmRc::SIZE.with(Position::parameter(1)),
        "ECDHZGen with size == 0 inPoint must return TPM_RC_SIZE + P1"
    );
}

#[test]
fn test_comprehensive_unmarshal_error_codes_and_handle_positions() {
    use tpm2::commands::DuplicateHandles;
    use tpm2::errors::{Position, TpmRc};
    use tpm2::{
        TpmEccCurve, TpmaAlgorithm, TpmaNv, TpmaObject, TpmaSession, TpmiAlgHash, TpmiAlgSymMode,
        TpmtKeyedHashScheme, TpmtSigScheme, TpmtSymDefObject,
    };

    // 1. Primitive integer buffer underflow -> INSUFFICIENT (0x09A)
    let mut empty = &[][..];
    assert_eq!(u8::unmarshal(&mut empty), Err(UnmarshalError::INSUFFICIENT));
    let mut one_byte = &[0x01u8][..];
    assert_eq!(
        u16::unmarshal(&mut one_byte),
        Err(UnmarshalError::INSUFFICIENT)
    );
    let mut three_bytes = &[0x01u8, 0x02, 0x03][..];
    assert_eq!(
        u32::unmarshal(&mut three_bytes),
        Err(UnmarshalError::INSUFFICIENT)
    );
    let mut seven_bytes = &[0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07][..];
    assert_eq!(
        u64::unmarshal(&mut seven_bytes),
        Err(UnmarshalError::INSUFFICIENT)
    );

    // 2. Reserved bits in attribute structures -> RESERVED_BITS (0x0A1)
    let mut alg_res = &0x0000_0010u32.to_be_bytes()[..];
    assert_eq!(
        TpmaAlgorithm::unmarshal(&mut alg_res),
        Err(UnmarshalError::RESERVED_BITS)
    );
    let mut obj_res = &0x0000_0001u32.to_be_bytes()[..];
    assert_eq!(
        TpmaObject::unmarshal(&mut obj_res),
        Err(UnmarshalError::RESERVED_BITS)
    );
    let mut obj_res_bit3 = &0x0000_0008u32.to_be_bytes()[..];
    assert_eq!(
        TpmaObject::unmarshal(&mut obj_res_bit3),
        Err(UnmarshalError::RESERVED_BITS)
    );
    let mut sess_res = &[0x08u8][..];
    assert_eq!(
        TpmaSession::unmarshal(&mut sess_res),
        Err(UnmarshalError::RESERVED_BITS)
    );
    let mut nv_res = &0x0000_0100u32.to_be_bytes()[..];
    assert_eq!(
        TpmaNv::unmarshal(&mut nv_res),
        Err(UnmarshalError::RESERVED_BITS)
    );

    // 3. Curve, Hash, Mode, Scheme, Symmetric specific error codes
    let mut bad_curve = &0x9999u16.to_be_bytes()[..];
    assert_eq!(
        TpmEccCurve::unmarshal(&mut bad_curve),
        Err(UnmarshalError::CURVE)
    );
    let mut bad_hash = &0x0001u16.to_be_bytes()[..]; // RSA is not a hash
    assert_eq!(
        TpmiAlgHash::unmarshal(&mut bad_hash),
        Err(UnmarshalError::HASH)
    );
    let mut bad_mode = &0x0001u16.to_be_bytes()[..];
    assert_eq!(
        <Option<TpmiAlgSymMode>>::unmarshal(&mut bad_mode),
        Err(UnmarshalError::MODE)
    );
    let mut bad_sig_scheme = &0x0001u16.to_be_bytes()[..];
    assert_eq!(
        <Option<TpmtSigScheme>>::unmarshal(&mut bad_sig_scheme),
        Err(UnmarshalError::SCHEME)
    );
    let mut bad_kh_scheme = &0x0001u16.to_be_bytes()[..];
    assert_eq!(
        <Option<TpmtKeyedHashScheme>>::unmarshal(&mut bad_kh_scheme),
        Err(UnmarshalError::VALUE)
    );
    let mut bad_sym = &0x0001u16.to_be_bytes()[..];
    assert_eq!(
        TpmtSymDefObject::unmarshal(&mut bad_sym),
        Err(UnmarshalError::SYMMETRIC)
    );

    // 4. Handle position modifiers (H1 / H2) on handle unmarshalling failure
    let mut h1_short = &[0x80u8, 0x00][..];
    let err_h1 = DuplicateHandles::unmarshal(&mut h1_short).unwrap_err();
    assert_eq!(
        err_h1.to_rc(),
        TpmRc::INSUFFICIENT.with(Position::handle(1))
    );

    let mut h2_short = &[0x80u8, 0x00, 0x00, 0x01, 0x80, 0x00][..];
    let err_h2 = DuplicateHandles::unmarshal(&mut h2_short).unwrap_err();
    assert_eq!(
        err_h2.to_rc(),
        TpmRc::INSUFFICIENT.with(Position::handle(2))
    );
}

#[test]
fn test_tpml_and_unmarshal_ref_on_failure() {
    use tpm2::{TpmlDigestValues, TpmlPcrSelection};

    let default_hash_bytes = tpm2::Alg::from(tpm2::TpmiAlgHash::DEFAULT_HASH)
        .id()
        .to_be_bytes();
    let tpml_pcr_buf = [
        0x00,
        0x00,
        0x00,
        0x01, // count = 1
        default_hash_bytes[0],
        default_hash_bytes[1],
        0x03,
        0xFF, // elem 0: truncated
    ];
    let mut src = &tpml_pcr_buf[..];
    assert_eq!(
        TpmlPcrSelection::unmarshal(&mut src),
        Err(UnmarshalError::INSUFFICIENT)
    );

    let tpml_ha_buf = [0x00, 0x00, 0x00, 0x01, 0x00, 0x01];
    let mut src_ha = &tpml_ha_buf[..];
    assert!(TpmlDigestValues::unmarshal(&mut src_ha).is_err());

    let elem =
        tpm2::TpmsPcrSelection::new(tpm2::TpmiAlgHash::DEFAULT_HASH, &[0xAA, 0xBB, 0xCC]).unwrap();
    let mut target_tpml = TpmlPcrSelection::from_slice(&[elem]).unwrap();
    let original_tpml = target_tpml;

    // 1. count > CAP
    let over_cap_buf = 100u32.to_be_bytes();
    assert_eq!(
        target_tpml.unmarshal_ref(&over_cap_buf),
        Err(UnmarshalError::SIZE)
    );
    assert_eq!(target_tpml.count(), 1);
    assert_eq!(target_tpml.as_slice(), &[elem]);
    assert_eq!(target_tpml, original_tpml);

    // 2. count < min_count
    let zero_count_buf = 0u32.to_be_bytes();
    assert_eq!(
        target_tpml.unmarshal_ref_with_min_count(&zero_count_buf, 1),
        Err(UnmarshalError::SIZE)
    );
    assert_eq!(target_tpml.count(), 1);
    assert_eq!(target_tpml.as_slice(), &[elem]);
    assert_eq!(target_tpml, original_tpml);

    // 3. Truncated element buffer
    assert_eq!(
        target_tpml.unmarshal_ref(&tpml_pcr_buf),
        Err(UnmarshalError::INSUFFICIENT)
    );
    assert_eq!(target_tpml.count(), 1);
    assert_eq!(target_tpml.as_slice(), &[elem]);
    assert_eq!(target_tpml, original_tpml);

    let mut target_clock = tpm2::TpmsClockInfo {
        clock: 42,
        reset_count: 7,
        restart_count: 3,
        safe: true,
    };
    let original_clock = target_clock;
    let bad_clock_buf = [0u8; 10];
    assert_eq!(
        target_clock.unmarshal_ref(&bad_clock_buf),
        Err(UnmarshalError::INSUFFICIENT)
    );
    assert_eq!(
        target_clock, original_clock,
        "unmarshal_ref modified target struct on failure"
    );

    let mut clock_bad_safe = [0u8; 18];
    clock_bad_safe[16] = 2;
    clock_bad_safe[17] = 0xEE;
    let mut src_clock = &clock_bad_safe[..];
    assert_eq!(
        tpm2::TpmsClockInfo::unmarshal(&mut src_clock),
        Err(UnmarshalError::VALUE)
    );
    assert_eq!(
        src_clock,
        &[0xEE],
        "Composite unmarshal must leave slice advanced past failed field"
    );
}

#[test]
fn test_tpm2b_template_and_context_data_raw_unmarshalling() {
    use tpm2::{Tpm2bContextData, Tpm2bTemplate};

    let empty_2b = [0x00u8, 0x00];
    let mut src_tmpl = &empty_2b[..];
    let tmpl = Tpm2bTemplate::unmarshal(&mut src_tmpl).expect("TPM2B_TEMPLATE size 0 valid");
    assert_eq!(tmpl.get_size(), 0);

    let arbitrary_tmpl = [0x00u8, 0x03, 0xDE, 0xAD, 0xBE];
    let mut src_tmpl2 = &arbitrary_tmpl[..];
    let tmpl2 = Tpm2bTemplate::unmarshal(&mut src_tmpl2).expect("TPM2B_TEMPLATE raw bytes valid");
    assert_eq!(tmpl2.get_buffer(), &[0xDE, 0xAD, 0xBE]);

    let mut src_ctx = &empty_2b[..];
    let ctx = Tpm2bContextData::unmarshal(&mut src_ctx).expect("TPM2B_CONTEXT_DATA size 0 valid");
    assert_eq!(ctx.get_size(), 0);

    let arbitrary_ctx = [0x00u8, 0x04, 0x01, 0x02, 0x03, 0x04];
    let mut src_ctx2 = &arbitrary_ctx[..];
    let ctx2 =
        Tpm2bContextData::unmarshal(&mut src_ctx2).expect("TPM2B_CONTEXT_DATA opaque bytes valid");
    assert_eq!(ctx2.get_buffer(), &[0x01, 0x02, 0x03, 0x04]);
}
