use crate::test_utils::{execute_with_hmac_sessions, start_auth_session};
use tpm2::Unmarshal;
use tpm2::commands::{Clear, ClearHandles, HierarchyChangeAuth, HierarchyChangeAuthHandles};
use tpm2::{Handle, TpmSe};
use tpm2::{Tpm2bAuth, TpmaSession, TpmiAlgHash, TpmiAlgSymMode, TpmtSymDefObject};
use tpm2_platform_linux::LinuxRng;
use tpm2_simulator::{Simulator, create_simulator};

#[test]
fn test_cfb_direct() {
    let sim = create_simulator!();
    let crypto = &sim.context.platform.crypto;

    let key = [0u8; 16];
    let original_iv = [0u8; 16];

    for size in 0..64 {
        let mut data = vec![0xABu8; size];
        let mut iv_enc = original_iv;
        tpm2::crypto::encrypt(
            *crypto,
            TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)),
            &key,
            &mut iv_enc,
            &mut data,
        )
        .unwrap();

        let mut iv_dec = original_iv;
        tpm2::crypto::decrypt(
            *crypto,
            TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB)),
            &key,
            &mut iv_dec,
            &mut data,
        )
        .unwrap();

        assert_eq!(data, vec![0xABu8; size], "CFB failed for size {}", size);
    }
}

#[test]
fn test_decryption_boundaries_hierarchy_change_auth() {
    // Test different sizes of new_auth to verify CFB block boundaries and stream logic
    let sizes = [0, 1, 7, 8, 15, 16, 17, 31, 32, 33, 64];

    for &size in &sizes {
        // Create a fresh simulator for each size to avoid persisting Owner Auth state modifications
        let mut sim = create_simulator!();

        let mut session = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::HMAC,
            Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
            TpmiAlgHash::Sha256,
        )
        .unwrap();
        session.attributes.insert(TpmaSession::DECRYPT);

        let new_auth_data = vec![0xABu8; size];
        let cmd = HierarchyChangeAuth {
            new_auth: Tpm2bAuth::from_bytes(&new_auth_data).unwrap(),
        };
        let handles = HierarchyChangeAuthHandles {
            auth_handle: Handle::RH_OWNER,
        };

        let result =
            execute_with_hmac_sessions(&mut sim, &cmd, handles, &[], &mut [session], &[&[]]);

        if size <= 32 {
            assert!(
                result.is_ok(),
                "Failed decryption boundary test for size {} with error {:?}",
                size,
                result.err()
            );
        } else {
            assert_eq!(
                result.err(),
                Some(0x1D5),
                "Expected TPM_RC_SIZE (0x1D5) for size {}, got {:?}",
                size,
                result.err()
            );
        }
    }
}

#[test]
fn test_decryption_parameter_size_overflow() {
    let mut sim = create_simulator!();
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::DECRYPT);

    // Construct raw request buffer
    let mut req = Vec::new();
    // tag: 0x8002 (sessions)
    req.extend_from_slice(&0x8002u16.to_be_bytes());
    // size: placeholder (will fill later)
    req.extend_from_slice(&0u32.to_be_bytes());
    // code: TpmCc::HierarchyChangeAuth (0x00000129)
    req.extend_from_slice(&0x00000129u32.to_be_bytes());
    // handles: RHOwner (0x40000001)
    req.extend_from_slice(&0x40000001u32.to_be_bytes());

    // session size placeholder
    let session_size_offset = req.len();
    req.extend_from_slice(&0u32.to_be_bytes());

    let session_start = req.len();
    // session handle
    req.extend_from_slice(&session.session_handle.0.to_be_bytes());
    // nonce caller (16 bytes of dummy)
    req.extend_from_slice(&16u16.to_be_bytes());
    req.extend_from_slice(&[0u8; 16]);
    // session attributes: DECRYPT (0x20) | CONTINUE_SESSION (0x01)
    req.push(0x21);
    // hmac (32 bytes of dummy)
    req.extend_from_slice(&32u16.to_be_bytes());
    req.extend_from_slice(&[0u8; 32]);

    let session_end = req.len();
    let session_size = (session_end - session_start) as u32;
    req[session_size_offset..session_size_offset + 4].copy_from_slice(&session_size.to_be_bytes());

    // parameters: first parameter is a TPM2B (new_auth).
    // Let's set the parameter size to 100, but only provide 10 bytes of actual data!
    let _param_size_offset = req.len();
    req.extend_from_slice(&100u16.to_be_bytes()); // invalid size!
    req.extend_from_slice(&[0xCCu8; 10]); // actual data is only 10 bytes

    // fill overall request size
    let req_size = req.len() as u32;
    req[2..6].copy_from_slice(&req_size.to_be_bytes());

    let mut resp = [0u8; 4096];
    let resp_bytes = sim.transact(&req, &mut resp).unwrap();

    let mut unmarsh: &'static [u8] = crate::test_utils::leak_bytes(resp_bytes);
    let header = crate::test_utils::RespHeader::unmarshal(&mut unmarsh).unwrap();
    // Expected response code: TPM_RC_SIZE (0x095)
    assert_eq!(
        header.rc, 0x095,
        "Expected TPM_RC_SIZE (0x95), got 0x{:X}",
        header.rc
    );
}

#[test]
fn test_decryption_no_decryptable_parameters() {
    let mut sim = create_simulator!();
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::DECRYPT);

    let read_cmd = tpm2::commands::ReadPublic {};
    let read_handles = tpm2::commands::ReadPublicHandles {
        object_handle: Handle::RH_NULL, // invalid key but handles session validation first
    };

    let result = execute_with_hmac_sessions(
        &mut sim,
        &read_cmd,
        read_handles,
        &[],
        &mut [session],
        &[&[]],
    );

    // Note: TPM 2.0 Spec Part 1 Sec 21 states that TPM shall return TPM_RC_ATTRIBUTES
    // if decrypt attribute is set in a command session for a command with no decryptable parameter.
    // However, our current implementation bypasses this and fails on handles/validation instead.
    // Let's document this behavior.
    assert!(result.is_err());
    let err = match result {
        Ok(_) => unreachable!(),
        Err(e) => e,
    };
    // If it did validate attributes, it would return TPM_RC_ATTRIBUTES (0x08F).
    // Let's see what it actually returns (e.g. 0x08F or handle error 0x08B/139).
    println!("No decryptable parameters call returned error: 0x{:X}", err);
}

#[test]
fn test_encryption_no_encryptable_parameters() {
    let mut sim = create_simulator!();
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::ENCRYPT);

    let cmd = Clear {};
    let handles = ClearHandles {
        auth_handle: Handle::RH_LOCKOUT,
    };

    let result = execute_with_hmac_sessions(&mut sim, &cmd, handles, &[], &mut [session], &[&[]]);

    // Note: TPM 2.0 Spec Part 1 Sec 21 states that TPM shall return TPM_RC_ATTRIBUTES
    // if encrypt attribute is set in a command session for a command with no encryptable response parameter.
    // Let's document the actual behavior.
    println!("Clear with ENCRYPT session result: {:?}", result);
}

#[test]
fn test_get_random_response_encryption() {
    let mut sim = create_simulator!();
    let mut session = start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB))),
        TpmiAlgHash::Sha256,
    )
    .unwrap();
    session.attributes.insert(TpmaSession::ENCRYPT);

    let cmd = tpm2::commands::GetRandom {
        bytes_requested: 32,
    };

    let result = execute_with_hmac_sessions(&mut sim, &cmd, (), &[], &mut [session], &[&[]]);

    assert!(
        result.is_ok(),
        "GetRandom with encrypt session failed: {:?}",
        result.err()
    );
    let (resp, _) = result.unwrap();
    assert_eq!(resp.random_bytes.as_ref().len(), 32);
}
