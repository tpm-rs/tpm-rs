use tpm2::errors::{Position, TpmRc};
mod common;

use common::TestCryptoProvider;
use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;

#[test]
fn test_sign_restricted_without_ticket_returns_rc_ticket() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup
    let startup_request = hex!(
        "8001" // tag
        "0000000c" // size
        "00000144" // command code
        "0000" // TPM_SU_CLEAR
    );
    let mut response = [0u8; 1024];
    tpm.execute_command_separate(&mut global_state, &startup_request[..], &mut response[..]);

    let key_handle = 0x80000001;
    let public = tpm2::TpmtPublic {
        name_alg: Some(tpm2::TpmiAlgHash::Sha256),
        object_attributes: tpm2::TpmaObject::RESTRICTED
            | tpm2::TpmaObject::SIGN_ENCRYPT
            | tpm2::TpmaObject::USER_WITH_AUTH,
        auth_policy: tpm2::Tpm2bDigest::default(),
        parms_and_id: tpm2::PublicParmsAndId::Rsa(
            tpm2::TpmsRsaParms {
                symmetric: None,
                scheme: Some(tpm2::TpmtRsaScheme::Rsassa(tpm2::TpmiAlgHash::Sha256)),
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            tpm2::Tpm2bPublicKeyRsa::default(),
        ),
    };
    let obj = tpm2_impl::handler::TransientObject {
        handle: key_handle,
        seed: [0u8; 32],
        name: (tpm2::Tpm2bName::default()).into(),
        auth: (tpm2::Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0xcc; 1536],
        private_len: 256,
        qualified_name: (tpm2::Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    // Now call TPM2_Sign with an empty/invalid ticket on this restricted key
    // Sign request structure:
    // keyHandle (4), auth area, digest (2 + 32), inScheme (2 + 2), validation (2 + 4 + 2 + 0)
    let mut sign_req = Vec::new();
    sign_req.extend_from_slice(&hex!("8002")); // tag: TPM_ST_SESSIONS
    sign_req.extend_from_slice(&[0, 0, 0, 0]); // placeholder for size
    sign_req.extend_from_slice(&hex!("0000015d")); // TPM_CC_Sign
    sign_req.extend_from_slice(&key_handle.to_be_bytes());
    // auth
    sign_req.extend_from_slice(&hex!("00000009 40000009 0000 01 0000"));
    // digest (32 bytes of 0x11)
    sign_req.extend_from_slice(&hex!("0020"));
    sign_req.extend_from_slice(&[0x11u8; 32]);
    // inScheme: RSASSA with SHA256
    sign_req.extend_from_slice(&hex!("0014 000b"));
    // validation ticket: tag 8024, hierarchy RH_NULL, empty digest
    sign_req.extend_from_slice(&hex!("8024 40000007 0000"));

    let req_len = sign_req.len() as u32;
    sign_req[2..6].copy_from_slice(&req_len.to_be_bytes());

    tpm.execute_command_separate(&mut global_state, &sign_req[..], &mut response[..]);
    let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    let expected_rc = TpmRc::TICKET.with(Position::parameter(3)).get();
    assert_eq!(
        rc, expected_rc,
        "Expected TPM_RC_TICKET ({:08x}) when signing restricted without valid ticket, got {:08x}",
        expected_rc, rc
    );
}

#[test]
fn test_sequential_sign_under_auth_sessions_executes_cleanly() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup
    let startup_request = hex!(
        "8001" // tag
        "0000000c" // size
        "00000144" // command code
        "0000" // TPM_SU_CLEAR
    );
    let mut response = [0u8; 1024];
    tpm.execute_command_separate(&mut global_state, &startup_request[..], &mut response[..]);

    let key_handle = 0x80000001;
    let public = tpm2::TpmtPublic {
        name_alg: Some(tpm2::TpmiAlgHash::Sha256),
        object_attributes: tpm2::TpmaObject::SIGN_ENCRYPT | tpm2::TpmaObject::USER_WITH_AUTH,
        auth_policy: tpm2::Tpm2bDigest::default(),
        parms_and_id: tpm2::PublicParmsAndId::KeyedHash(
            Some(tpm2::TpmtKeyedHashScheme::Hmac(tpm2::TpmiAlgHash::Sha256)),
            tpm2::Tpm2bDigest::default(),
        ),
    };
    let obj = tpm2_impl::handler::TransientObject {
        handle: key_handle,
        seed: [0u8; 32],
        name: (tpm2::Tpm2bName::default()).into(),
        auth: (tpm2::Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0xaa; 1536],
        private_len: 32,
        qualified_name: (tpm2::Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    // Run sequential sign operations using password session (0x40000009) to authorize key_handle
    for _ in 0..3 {
        let mut sign_req = Vec::new();
        sign_req.extend_from_slice(&hex!("8002")); // tag: TPM_ST_SESSIONS
        sign_req.extend_from_slice(&[0, 0, 0, 0]); // size placeholder
        sign_req.extend_from_slice(&hex!("0000015d")); // TPM_CC_Sign
        sign_req.extend_from_slice(&key_handle.to_be_bytes());
        // auth area: handle 0x40000009, nonce empty (0000), attributes (01), hmac empty (0000) -> 9 bytes
        sign_req.extend_from_slice(&hex!("00000009 40000009 0000 01 0000"));
        // digest (32 bytes of 0x22)
        sign_req.extend_from_slice(&hex!("0020"));
        sign_req.extend_from_slice(&[0x22u8; 32]);
        // inScheme: HMAC with SHA256
        sign_req.extend_from_slice(&hex!("0005 000b"));
        // validation ticket: tag 8024, hierarchy RH_NULL, empty digest
        sign_req.extend_from_slice(&hex!("8024 40000007 0000"));

        let req_len = sign_req.len() as u32;
        sign_req[2..6].copy_from_slice(&req_len.to_be_bytes());

        tpm.execute_command_separate(&mut global_state, &sign_req[..], &mut response[..]);
        let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
        assert_eq!(
            rc, 0,
            "Expected sequential TPM2_Sign to succeed under auth session, got {:08x}",
            rc
        );
    }
}

#[test]
fn test_sign_invalid_hash_alg_returns_rc_value() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup
    let startup_request = hex!(
        "8001" // tag
        "0000000c" // size
        "00000144" // command code
        "0000" // TPM_SU_CLEAR
    );
    let mut response = [0u8; 1024];
    tpm.execute_command_separate(&mut global_state, &startup_request[..], &mut response[..]);

    let key_handle = 0x80000001;
    let public = tpm2::TpmtPublic {
        name_alg: Some(tpm2::TpmiAlgHash::Sha256),
        object_attributes: tpm2::TpmaObject::SIGN_ENCRYPT | tpm2::TpmaObject::USER_WITH_AUTH,
        auth_policy: tpm2::Tpm2bDigest::default(),
        parms_and_id: tpm2::PublicParmsAndId::Rsa(
            tpm2::TpmsRsaParms {
                symmetric: None,
                scheme: Some(tpm2::TpmtRsaScheme::Rsassa(tpm2::TpmiAlgHash::Sha256)),
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            tpm2::Tpm2bPublicKeyRsa::default(),
        ),
    };
    let obj = tpm2_impl::handler::TransientObject {
        handle: key_handle,
        seed: [0u8; 32],
        name: (tpm2::Tpm2bName::default()).into(),
        auth: (tpm2::Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0xcc; 1536],
        private_len: 256,
        qualified_name: (tpm2::Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    // Call TPM2_Sign with an invalid hash algorithm in inScheme (e.g., SYMCIPHER 0x0025 inside RSASSA 0x0014)
    let mut sign_req = Vec::new();
    sign_req.extend_from_slice(&hex!("8002")); // tag: TPM_ST_SESSIONS
    sign_req.extend_from_slice(&[0, 0, 0, 0]); // size placeholder
    sign_req.extend_from_slice(&hex!("0000015d")); // TPM_CC_Sign
    sign_req.extend_from_slice(&key_handle.to_be_bytes());
    // auth
    sign_req.extend_from_slice(&hex!("00000009 40000009 0000 01 0000"));
    // digest (32 bytes of 0x11)
    sign_req.extend_from_slice(&hex!("0020"));
    sign_req.extend_from_slice(&[0x11u8; 32]);
    // inScheme: RSASSA (0x0014) with invalid hash alg (0x0025)
    sign_req.extend_from_slice(&hex!("0014 0025"));
    // validation ticket: tag 8024, hierarchy RH_NULL, empty digest
    sign_req.extend_from_slice(&hex!("8024 40000007 0000"));

    let req_len = sign_req.len() as u32;
    sign_req[2..6].copy_from_slice(&req_len.to_be_bytes());

    tpm.execute_command_separate(&mut global_state, &sign_req[..], &mut response[..]);
    let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    let expected_rc = TpmRc::HASH.with(tpm2::errors::Position::parameter(2)).get();
    assert_eq!(
        rc, expected_rc,
        "Expected TPM_RC_HASH + TPM_RC_P + TPM_RC_2 ({:08x}) when signing with invalid scheme hash alg, got {:08x}",
        expected_rc, rc
    );
}

#[test]
fn test_sequential_sign_under_policy_auth_session_executes_cleanly() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup
    let startup_request = hex!(
        "8001" // tag
        "0000000c" // size
        "00000144" // command code
        "0000" // TPM_SU_CLEAR
    );
    let mut response = [0u8; 1024];
    tpm.execute_command_separate(&mut global_state, &startup_request[..], &mut response[..]);

    let key_handle = 0x80000001;
    let public = tpm2::TpmtPublic {
        name_alg: Some(tpm2::TpmiAlgHash::Sha256),
        object_attributes: tpm2::TpmaObject::SIGN_ENCRYPT | tpm2::TpmaObject::USER_WITH_AUTH,
        auth_policy: tpm2::Tpm2bDigest::default(),
        parms_and_id: tpm2::PublicParmsAndId::KeyedHash(
            Some(tpm2::TpmtKeyedHashScheme::Hmac(tpm2::TpmiAlgHash::Sha256)),
            tpm2::Tpm2bDigest::default(),
        ),
    };
    let obj = tpm2_impl::handler::TransientObject {
        handle: key_handle,
        seed: [0u8; 32],
        name: (tpm2::Tpm2bName::default()).into(),
        auth: (tpm2::Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0xaa; 1536],
        private_len: 32,
        qualified_name: (tpm2::Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    // Start a Policy session (StartAuthSession: unbound, unseeded, sessionType = Policy)
    let mut start_req = Vec::new();
    start_req.extend_from_slice(&hex!("8001")); // tag: TPM_ST_NO_SESSIONS
    start_req.extend_from_slice(&[0, 0, 0, 0]); // size placeholder
    start_req.extend_from_slice(&hex!("00000176")); // TPM_CC_StartAuthSession
    start_req.extend_from_slice(&hex!("40000007 40000007")); // tpmKey = RH_NULL, bind = RH_NULL
    start_req.extend_from_slice(&hex!("0020")); // nonceCaller (32 bytes of 0x01)
    start_req.extend_from_slice(&[0x01u8; 32]);
    start_req.extend_from_slice(&hex!("0000")); // encryptedSalt
    start_req.extend_from_slice(&hex!("01")); // sessionType = Policy
    start_req.extend_from_slice(&hex!("0010 000b")); // symmetric = Null, authHash = SHA256

    let req_len = start_req.len() as u32;
    start_req[2..6].copy_from_slice(&req_len.to_be_bytes());
    tpm.execute_command_separate(&mut global_state, &start_req[..], &mut response[..]);
    let start_rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    assert_eq!(start_rc, 0, "StartAuthSession failed: {:08x}", start_rc);
    let session_handle =
        u32::from_be_bytes([response[10], response[11], response[12], response[13]]);

    // Run sequential sign operations using this Policy session_handle across multiple steps
    for step in 0..3 {
        // Step A: PolicyPassword to enable password authorization for this policy session
        let mut pp_req = Vec::new();
        pp_req.extend_from_slice(&hex!("8001")); // tag: TPM_ST_NO_SESSIONS
        pp_req.extend_from_slice(&[0, 0, 0, 0]); // size placeholder
        pp_req.extend_from_slice(&hex!("0000018c")); // TPM_CC_PolicyPassword
        pp_req.extend_from_slice(&session_handle.to_be_bytes());
        let req_len = pp_req.len() as u32;
        pp_req[2..6].copy_from_slice(&req_len.to_be_bytes());
        tpm.execute_command_separate(&mut global_state, &pp_req[..], &mut response[..]);
        let pp_rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
        assert_eq!(
            pp_rc, 0,
            "PolicyPassword step {} failed: {:08x}",
            step, pp_rc
        );

        // Step B: PolicyCommandCode for TPM_CC_Sign (0x015d)
        let mut pc_req = Vec::new();
        pc_req.extend_from_slice(&hex!("8001")); // tag: TPM_ST_NO_SESSIONS
        pc_req.extend_from_slice(&[0, 0, 0, 0]); // size placeholder
        pc_req.extend_from_slice(&hex!("0000016c")); // TPM_CC_PolicyCommandCode
        pc_req.extend_from_slice(&session_handle.to_be_bytes());
        pc_req.extend_from_slice(&hex!("0000015d")); // code: TPM_CC_Sign
        let req_len = pc_req.len() as u32;
        pc_req[2..6].copy_from_slice(&req_len.to_be_bytes());
        tpm.execute_command_separate(&mut global_state, &pc_req[..], &mut response[..]);
        let pc_rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
        assert_eq!(
            pc_rc, 0,
            "PolicyCommandCode step {} failed: {:08x}",
            step, pc_rc
        );

        if step == 0 {
            let policy_digest = global_state.session(session_handle).unwrap().policy_digest;
            let policy_len = global_state
                .session(session_handle)
                .unwrap()
                .policy_digest_len;
            global_state.transient_objects[0]
                .as_mut()
                .unwrap()
                .public
                .auth_policy = tpm2::Tpm2bDigest::from_bytes(&policy_digest[..policy_len])
                .unwrap()
                .into();
        }

        let mut sign_req = Vec::new();
        sign_req.extend_from_slice(&hex!("8002")); // tag: TPM_ST_SESSIONS
        sign_req.extend_from_slice(&[0, 0, 0, 0]); // size placeholder
        sign_req.extend_from_slice(&hex!("0000015d")); // TPM_CC_Sign
        sign_req.extend_from_slice(&key_handle.to_be_bytes());
        // auth area size (4) + session_handle (4), nonce empty (0000), attributes continueSession (01), hmac empty (0000)
        sign_req.extend_from_slice(&9u32.to_be_bytes());
        sign_req.extend_from_slice(&session_handle.to_be_bytes());
        sign_req.extend_from_slice(&hex!("0000 01 0000"));
        // digest (32 bytes of 0x22)
        sign_req.extend_from_slice(&hex!("0020"));
        sign_req.extend_from_slice(&[0x22u8; 32]);
        // inScheme: HMAC with SHA256
        sign_req.extend_from_slice(&hex!("0005 000b"));
        // validation ticket: tag 8024, hierarchy RH_NULL, empty digest
        sign_req.extend_from_slice(&hex!("8024 40000007 0000"));

        let req_len = sign_req.len() as u32;
        sign_req[2..6].copy_from_slice(&req_len.to_be_bytes());

        tpm.execute_command_separate(&mut global_state, &sign_req[..], &mut response[..]);
        let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
        assert_eq!(
            rc, 0,
            "Expected sequential TPM2_Sign step {} to succeed under Policy session, got {:08x}",
            step, rc
        );
    }
}

#[test]
fn test_verify_signature_unloaded_handle_returns_reference_h0() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup
    let startup_request = hex!(
        "8001" // tag
        "0000000c" // size
        "00000144" // command code
        "0000" // TPM_SU_CLEAR
    );
    let mut response = [0u8; 1024];
    tpm.execute_command_separate(&mut global_state, &startup_request[..], &mut response[..]);

    // Send VerifySignature with an unloaded transient handle 0x80000002
    let mut verify_req = Vec::new();
    verify_req.extend_from_slice(&hex!("8001")); // tag: TPM_ST_NO_SESSIONS
    verify_req.extend_from_slice(&[0, 0, 0, 0]); // size placeholder
    verify_req.extend_from_slice(&hex!("00000177")); // TPM_CC_VerifySignature
    verify_req.extend_from_slice(&0x80000002u32.to_be_bytes()); // unloaded handle
    // digest (32 bytes)
    verify_req.extend_from_slice(&hex!("0020"));
    verify_req.extend_from_slice(&[0x11u8; 32]);
    // signature (RSASSA with SHA256)
    verify_req.extend_from_slice(&hex!("0014 000b 0100"));
    verify_req.extend_from_slice(&[0xccu8; 256]);

    let req_len = verify_req.len() as u32;
    verify_req[2..6].copy_from_slice(&req_len.to_be_bytes());

    tpm.execute_command_separate(&mut global_state, &verify_req[..], &mut response[..]);
    let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    assert_eq!(
        rc,
        TpmRc::REFERENCE_H0.get(),
        "Expected TPM_RC_REFERENCE_H0 ({:08x}) for unloaded transient handle in VerifySignature, got {:08x}",
        TpmRc::REFERENCE_H0.get(),
        rc
    );
}

#[test]
fn test_sign_ecdaa_invalid_commit_returns_rc_value() {
    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup
    let startup_request = hex!(
        "8001" // tag
        "0000000c" // size
        "00000144" // command code
        "0000" // TPM_SU_CLEAR
    );
    let mut response = [0u8; 1024];
    tpm.execute_command_separate(&mut global_state, &startup_request[..], &mut response[..]);

    let key_handle = 0x80000001;
    let public = tpm2::TpmtPublic {
        name_alg: Some(tpm2::TpmiAlgHash::Sha256),
        object_attributes: tpm2::TpmaObject::SIGN_ENCRYPT
            | tpm2::TpmaObject::DECRYPT
            | tpm2::TpmaObject::USER_WITH_AUTH,
        auth_policy: tpm2::Tpm2bDigest::default(),
        parms_and_id: tpm2::PublicParmsAndId::Ecc(
            tpm2::TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            tpm2::TpmsEccPoint::default(),
        ),
    };
    let obj = tpm2_impl::handler::TransientObject {
        handle: key_handle,
        seed: [0u8; 32],
        name: (tpm2::Tpm2bName::default()).into(),
        auth: (tpm2::Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0xcc; 1536],
        private_len: 256,
        qualified_name: (tpm2::Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    // Send Sign with ECDAA, hashAlg = SHA1, count = 0
    let mut sign_req = Vec::new();
    sign_req.extend_from_slice(&hex!("8002")); // tag: TPM_ST_SESSIONS
    sign_req.extend_from_slice(&[0, 0, 0, 0]); // placeholder for size
    sign_req.extend_from_slice(&hex!("0000015d")); // TPM_CC_Sign
    sign_req.extend_from_slice(&key_handle.to_be_bytes());
    // auth
    sign_req.extend_from_slice(&hex!("00000009 40000009 0000 01 0000"));
    // digest (20 bytes of 0x11)
    sign_req.extend_from_slice(&hex!("0014"));
    sign_req.extend_from_slice(&[0x11u8; 20]);
    // inScheme: ECDAA with SHA1, count 0
    // ECDAA tag = 0x001a, SHA1 = 0x0004, count = 0x0000
    sign_req.extend_from_slice(&hex!("001a 0004 0000"));
    // validation ticket: tag 8024, hierarchy RH_NULL, empty digest
    sign_req.extend_from_slice(&hex!("8024 40000007 0000"));

    let req_len = sign_req.len() as u32;
    sign_req[2..6].copy_from_slice(&req_len.to_be_bytes());

    tpm.execute_command_separate(&mut global_state, &sign_req[..], &mut response[..]);
    let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    assert_eq!(
        rc,
        TpmRc::VALUE.with(Position::parameter(2)).get(),
        "Expected TPM_RC_VALUE for ECDAA sign with invalid commit status, got {:08x}",
        rc
    );
}
