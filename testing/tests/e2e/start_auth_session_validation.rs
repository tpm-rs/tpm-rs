//! TPM2_StartAuthSession parameter validation: session type, nonce sizes, symmetric modes and
//! handles.

use crate::_common::{
    create_primary, define_nv_empty_policy, define_pin_pass, ecc_signing_template,
    execute_with_corrupted_bytes, execute_with_hmac_sessions, execute_with_password_sessions,
    flush_context, hex, load_public_only_hmac_key, rc_of, run_pw, send, start_auth_session,
    start_bound, start_salted, to_digest,
};
use tpm2::commands::{
    CreatePrimary, HierarchyChangeAuth, LoadExternal, PCRSetAuthValue, StartAuthSession,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2b, Tpm2bAuth, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bNonce,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmNt, TpmSe, TpmaNv, TpmaObject, TpmiAlgHash,
    TpmiAlgSymMode, TpmiRsaKeyBits, TpmlPcrSelection, TpmsRsaParms, TpmsSensitiveCreate,
    TpmtPublic, TpmtSymDefObject, *,
};
use tpm2_simulator::create_simulator;

/// StartAuthSession with AES-128-CTR fails with MODE on parameter 4.
#[test]
fn ctr_symmetric_mode_rejected() {
    let mut sim = create_simulator!();

    // Send StartAuthSession with AES-128 and mode CTR (0x0040) instead of CFB (0x0043)
    // symmetric: algorithm AES (0006), keyBits AES-128 (0080), mode CTR (0040)
    let request = hex(concat!(
        "8001",
        "0000002f",
        "00000176",
        "40000007",
        "40000007",
        "00100102030405060708090a0b0c0d0e0f10",
        "0000",
        "01",
        "000600800040", // symmetric (AES-128-CTR)
        "000b",
    ));
    let response = send(&mut sim, &request);
    assert_eq!(response.len(), 10);
    let error_code = rc_of(&response);
    // Spec expects TPM_RC_MODE (0x4C9) on parameter 4.
    assert_eq!(
        error_code, 0x4C9,
        "Expected TPM_RC_MODE (0x4C9), got 0x{:03X}",
        error_code
    );
}

/// StartAuthSession with sessionType 0xFF fails with VALUE+P3.
#[test]
fn invalid_session_type_rejected() {
    let mut sim = create_simulator!();

    // Send StartAuthSession with invalid sessionType (0xFF)
    let request = hex(concat!(
        "8001",
        "0000002b",
        "00000176",
        "40000007",
        "40000007",
        "00100102030405060708090a0b0c0d0e0f10",
        "0000",
        "FF",
        "0010",
        "000b",
    ));
    let response = send(&mut sim, &request);
    assert_eq!(response.len(), 10);
    let error_code = rc_of(&response);
    // Expected TPM_RC_VALUE + P3 (0x3C4) for unmarshalling failure of sessionType
    // (TPMI_SH_AUTH_SESSION / TPM_SE)
    assert_eq!(
        error_code, 0x3C4,
        "Expected TPM_RC_VALUE + P3 (0x3C4) for invalid session type, got 0x{:03X}",
        error_code
    );
}

/// StartAuthSession accepts nonceCaller of 16..digest size bytes and rejects shorter or longer nonces.
///
/// 1. Nonce caller size validations (too small, too large, exact boundary).
#[test]
fn nonce_caller_size_bounds() {
    let mut sim = create_simulator!();

    // Valid size: 16 (exact lower boundary)
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert!(res.is_ok(), "Nonce size 16 should succeed: {:?}", res);
    let rsp = res.unwrap();
    flush_context(&mut sim, rsp.session_handle).unwrap();

    // Valid size: 32 (exact upper boundary for SHA256)
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 32]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert!(res.is_ok(), "Nonce size 32 should succeed: {:?}", res);
    let rsp = res.unwrap();
    flush_context(&mut sim, rsp.session_handle).unwrap();

    // Invalid size: 15 (too small)
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 15]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x1D5),
        "Nonce size 15 should return TPM_RC_SIZE (0x1D5)"
    );

    // Invalid size: 33 (too large for SHA256)
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 33]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x1D5),
        "Nonce size 33 should return TPM_RC_SIZE (0x1D5)"
    );

    // Invalid size: 21 (too large for SHA1, digest size 20)
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 21]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha1,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x1D5),
        "Nonce size 21 should return TPM_RC_SIZE for SHA1"
    );
}

/// Parameter encryption/decryption only supports CFB mode (TPM 2.0 Part 1,
/// 21.3). A black-box client cannot force a non-CFB mode into a live session,
/// so verify that the TPM refuses to create such a session in the first place:
/// `TPM2_StartAuthSession` must reject every symmetric mode other than CFB.
#[test]
fn only_cfb_symmetric_mode_accepted() {
    let mut sim = create_simulator!();
    for mode in [
        TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Ctr),
        TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Ofb),
        TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cbc),
        TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Ecb),
    ] {
        let res = start_auth_session(
            &mut sim,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::HMAC,
            Some(TpmtSymDefObject {
                alg: AlgSym::Aes128,
                mode: Some(mode),
            }),
            TpmiAlgHash::Sha256,
        );
        let err = res.expect_err("StartAuthSession accepted a non-CFB symmetric mode");
        // Strip the format-1 parameter number (bits 6 and 8..11).
        assert_eq!(
            err & 0xBF,
            tpm2::errors::TpmRc::MODE.get(),
            "mode {mode:?}: unexpected error {err:#x}"
        );
    }

    // CFB is accepted.
    start_auth_session(
        &mut sim,
        Handle::RH_NULL,
        Handle::RH_NULL,
        &[],
        TpmSe::HMAC,
        Some(TpmtSymDefObject {
            alg: AlgSym::Aes128,
            mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
        }),
        TpmiAlgHash::Sha256,
    )
    .expect("StartAuthSession with AES-128-CFB failed");
}

/// `TPM2_StartAuthSession` with a public-only `tpmKey` and a salt fails with
/// `TPM_RC_HANDLE` (C: tpmKey must have its private portion loaded).
#[test]
fn public_only_tpm_key_rejected() {
    let mut sim = create_simulator!();

    // Create an RSA decrypt key and load only its public area.
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::SENSITIVE_DATA_ORIGIN,
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
    let create = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: Tpm2b(public),
        outside_info: Tpm2bData::default(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let created = execute_with_password_sessions(&mut sim, &create, 1, &[])
        .unwrap_or_else(|rc| panic!("CreatePrimary failed: {rc:#x}"));
    let loaded = sim
        .execute(LoadExternal {
            in_private: None,
            in_public: created.out_public,
            hierarchy: Handle::RH_NULL,
        })
        .expect("LoadExternal failed");
    let key_handle = loaded.object_handle.0;

    // Send StartAuthSession command using the public-only key as tpmKey
    // and a non-empty encryptedSalt (e.g. 16 bytes).
    let mut request = hex(concat!(
        "8001",
        "0000003b",
        "00000176",
        "00000000",                             // tpmKey (patched below)
        "40000007",                             // bind (RHNull)
        "00100102030405060708090a0b0c0d0e0f10", // nonceCaller
        "00101112131415161718191a1b1c1d1e1f20", // encryptedSalt (non-empty)
        "01",                                   // sessionType
        "0010",                                 // symmetric
        "000b",                                 // authHash
    ));
    request[10..14].copy_from_slice(&key_handle.to_be_bytes());
    let response = send(&mut sim, &request);
    assert_eq!(response.len(), 10);
    let error_code = rc_of(&response);
    // Spec expects TPM_RC_HANDLE (0x18B) for public-only key.
    assert_eq!(
        error_code, 0x18B,
        "Expected TPM_RC_HANDLE (0x18B), got 0x{:03X}",
        error_code
    );
}

/// A raw StartAuthSession command (NULL tpmKey/bind) dispatches and succeeds.
#[test]
fn raw_unbound_unsalted_hmac_session() {
    let mut sim = create_simulator!();

    // Send StartAuthSession command (0x00000176)
    // tag: 8001
    // size: 0000002b (43)
    // cc: 00000176
    // tpm_key: 40000007 (RHNull)
    // bind: 40000007 (RHNull)
    // nonce_caller: 16 bytes
    // encrypted_salt: 0000 (size 0)
    // session_type: 01 (Policy)
    // symmetric: 0010 (Null)
    // auth_hash: 000b (SHA256)
    let request = hex(concat!(
        "8001",
        "0000002b",
        "00000176",
        "40000007",
        "40000007",
        "00100102030405060708090a0b0c0d0e0f10",
        "0000",
        "01",
        "0010",
        "000b",
    ));
    // Executing the command should succeed and return the session handle and nonceTPM
    let response = send(&mut sim, &request);
    assert_eq!(response.len(), 32);
    assert_eq!(&response[0..2], &hex("8001")[..]);
    assert_eq!(&response[2..6], &32u32.to_be_bytes());
    assert_eq!(&response[6..10], &0u32.to_be_bytes());
    assert_eq!(&response[10..14], &0x03000000u32.to_be_bytes());
    // A 16-byte nonceTPM (its value is random).
    assert_eq!(&response[14..16], &16u16.to_be_bytes());
}

/// HMAC sessions get 0x02 handles, policy/trial 0x03, and an invalid session type fails with VALUE.
///
/// 5. Session lookup prefix validation across different session types.
#[test]
fn session_handle_prefix_per_type() {
    let mut sim = create_simulator!();

    // HMAC Session: prefix should be 0x02xxxxxx
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let rsp = execute_with_password_sessions(&mut sim, &cmd, 0, &[]).unwrap();
    assert_eq!(
        rsp.session_handle.0 >> 24,
        0x02,
        "HMAC session handle should start with 0x02"
    );
    flush_context(&mut sim, rsp.session_handle).unwrap();

    // Policy Session: prefix should be 0x03xxxxxx
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let rsp = execute_with_password_sessions(&mut sim, &cmd, 0, &[]).unwrap();
    assert_eq!(
        rsp.session_handle.0 >> 24,
        0x03,
        "Policy session handle should start with 0x03"
    );
    flush_context(&mut sim, rsp.session_handle).unwrap();

    // Trial Session: prefix should be 0x03xxxxxx
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let rsp = execute_with_password_sessions(&mut sim, &cmd, 0, &[]).unwrap();
    assert_eq!(
        rsp.session_handle.0 >> 24,
        0x03,
        "Trial session handle should start with 0x03"
    );
    flush_context(&mut sim, rsp.session_handle).unwrap();

    // Invalid Session Type: TpmSe::try_from(0x02).unwrap() (should fail with TPM_RC_VALUE 0x3C4)
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_corrupted_bytes(&mut sim, &cmd, 0, &[], |buf| {
        buf[20] = 0x02; // corrupt session_type to invalid value 2
    });
    assert_eq!(
        res.err(),
        Some(0x3C4),
        "Invalid session type should return TPM_RC_VALUE + P3 (0x3C4)"
    );
}

/// StartAuthSession with a 15-byte nonceCaller fails with SIZE.
#[test]
fn short_nonce_caller_rejected() {
    let mut sim = create_simulator!();

    // Send StartAuthSession with nonceCaller of size 15 (too small, minimum is 16)
    // tag: 8001
    // size: 0000002a (42)
    // cc: 00000176
    // tpmKey: 40000007 (RHNull)
    // bind: 40000007 (RHNull)
    // nonceCaller: 000f (size 15) + 15 bytes
    // encryptedSalt: 0000 (empty)
    // sessionType: 01 (Policy)
    // symmetric: 0010 (Null)
    // authHash: 000b (SHA256)
    let request = hex(concat!(
        "8001",
        "0000002a",
        "00000176",
        "40000007",
        "40000007",
        "000f0102030405060708090a0b0c0d0e0f",
        "0000",
        "01",
        "0010",
        "000b",
    ));
    let response = send(&mut sim, &request);
    assert_eq!(response.len(), 10);
    let error_code = rc_of(&response);
    // Expected TPM_RC_SIZE (0x095) on parameter 1, which maps to 0x1D5
    assert_eq!(
        error_code, 0x1D5,
        "Expected TPM_RC_SIZE (0x1D5) for too small nonce, got 0x{:03X}",
        error_code
    );
}

/// AES-CFB and XOR-SHA256 are accepted; AES-CBC/CTR fail with MODE and XOR with NULL hash with HASH.
///
/// 4. Symmetric block cipher parameter combinations (invalid modes vs. valid CFB).
#[test]
fn symmetric_mode_and_xor_hash_validation() {
    let mut sim = create_simulator!();

    // Valid: Aes128 CFB
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: Some(tpm2::TpmtSymDef::Cipher(tpm2::TpmtSymDefObject {
            alg: AlgSym::Aes128,
            mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
        })),
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert!(res.is_ok(), "Aes128 CFB should succeed");
    let rsp = res.unwrap();
    flush_context(&mut sim, rsp.session_handle).unwrap();

    // Invalid: Aes128 CBC (should fail with TPM_RC_MODE 0x4C9)
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: Some(tpm2::TpmtSymDef::Cipher(tpm2::TpmtSymDefObject {
            alg: AlgSym::Aes128,
            mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cbc)),
        })),
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x4C9),
        "Aes128 CBC should return TPM_RC_MODE (0x4C9)"
    );

    // Invalid: Aes128 CTR (should fail with TPM_RC_MODE 0x4C9)
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: Some(tpm2::TpmtSymDef::Cipher(tpm2::TpmtSymDefObject {
            alg: AlgSym::Aes128,
            mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Ctr)),
        })),
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x4C9),
        "Aes128 CTR should return TPM_RC_MODE (0x4C9)"
    );

    // Valid: XOR with Sha256
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: Some(tpm2::TpmtSymDef::Xor(TpmiAlgHash::Sha256)),
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert!(res.is_ok(), "XOR with Sha256 should succeed");
    let rsp = res.unwrap();
    flush_context(&mut sim, rsp.session_handle).unwrap();

    // Invalid: XOR with NULL hash (should fail with TPM_RC_HASH 0x4C3)
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: Some(tpm2::TpmtSymDef::Xor(TpmiAlgHash::Sha256)),
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_corrupted_bytes(&mut sim, &cmd, 0, &[], |buf| {
        // symmetric starts at offset 21 (2 bytes Alg::XOR = 0x000A), followed by hash_alg at 23..25
        buf[23..25].copy_from_slice(&0x0010u16.to_be_bytes());
    });
    assert_eq!(
        res.err(),
        Some(0x4C3),
        "XOR with NULL hash should return TPM_RC_HASH (0x4C3)"
    );
}

/// StartAuthSession rejects symmetric tpmKey, checks empty salt first, rejects PIN/public-only bind entities; PCR bind uses authValue.
#[test]
fn tpm_key_salt_and_bind_entity_checks() {
    let mut sim = create_simulator!();

    // 1. A symmetric key cannot be tpmKey (TPM_RCS_KEY + RC_StartAuthSession_tpmKey).
    let sym_template = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject {
                alg: AlgSym::Aes128,
                mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
            },
            Tpm2bDigest::default(),
        ),
    };
    let (sym_key, _) = create_primary(&mut sim, sym_template);
    assert_eq!(
        start_salted(&mut sim, sym_key, Handle::RH_NULL, &[0x33; 16]),
        Err(TpmRc::KEY.with(Position::handle(1)).get())
    );

    // 2. Empty salt is checked before the DECRYPT attribute.
    let (sign_key, _) = create_primary(&mut sim, ecc_signing_template(TpmiAlgHash::Sha256));
    assert_eq!(
        start_salted(&mut sim, sign_key, Handle::RH_NULL, &[]),
        Err(TpmRc::VALUE.with(Position::parameter(2)).get())
    );

    // 4. PIN indices cannot be bind entities (TPM_RCS_HANDLE + RC_StartAuthSession_bind).
    let pin = 0x0150_0030;
    define_pin_pass(&mut sim, pin);
    assert_eq!(
        start_salted(&mut sim, Handle::RH_NULL, Handle(pin), &[]),
        Err(TpmRc::HANDLE.with(Position::handle(2)).get())
    );
    let mut fail_attrs = TpmaNv::OWNERWRITE | TpmaNv::AUTHREAD | TpmaNv::NO_DA;
    fail_attrs.set_type(TpmNt::PinFail);
    let pin_fail = 0x0150_0031;
    define_nv_empty_policy(&mut sim, pin_fail, fail_attrs, 8);
    assert_eq!(
        start_salted(&mut sim, Handle::RH_NULL, Handle(pin_fail), &[]),
        Err(TpmRc::HANDLE.with(Position::handle(2)).get())
    );

    // 4. Public-only objects cannot be bind entities.
    let public_only = load_public_only_hmac_key(&mut sim);
    assert_eq!(
        start_salted(&mut sim, Handle::RH_NULL, public_only, &[]),
        Err(TpmRc::HANDLE.with(Position::handle(2)).get())
    );

    // 3. Binding to a PCR in an auth group uses its authValue in the session key: an HMAC
    //    session bound to PCR 20 (authValue "abc") authorizes the owner with
    //    HMAC key = KDFa(authValue(PCR20)) || ownerAuth.
    run_pw(
        &mut sim,
        PCRSetAuthValue {
            pcr_handle: Handle(20),
            auth: to_digest(b"abc"),
        },
    )
    .expect("PCR_SetAuthValue");
    let mut session = start_bound(&mut sim, Handle(20), b"abc", TpmSe::HMAC);
    session
        .attributes
        .insert(tpm2::TpmaSession::CONTINUE_SESSION);
    execute_with_hmac_sessions(
        &mut sim,
        &HierarchyChangeAuth {
            auth_handle: Handle::RH_OWNER,
            new_auth: Tpm2bAuth::default(),
        },
        &[],
        &mut [session],
        &[&[]],
    )
    .expect("session bound to PCR 20 must derive its key from the PCR authValue");
}

/// A non-existent bind handle is rejected.
///
/// 9. Non-existent bind handle should fail
#[test]
fn unloaded_bind_handle_rejected() {
    let mut sim = create_simulator!();
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle(0x8000000F), // Unloaded transient handle
        nonce_caller: Tpm2bNonce::from_bytes(&[0u8; 16]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let res = execute_with_password_sessions(&mut sim, &cmd, 0, &[]);
    assert_eq!(
        res.err(),
        Some(0x911),
        "Non-existent bind handle should return ReferenceH1 (0x911)"
    );
}

/// StartAuthSession with XOR/SHA-256 symmetric parameters succeeds.
#[test]
fn xor_symmetric_accepted() {
    let mut sim = create_simulator!();

    // Start an HMAC auth session with XOR symmetric parameter (TPM_ALG_XOR=0x000a,
    // keyBits/hash=0x000b)
    let request = hex(concat!(
        "8001",                                 // tag
        "0000002d",                             // size: 45 bytes
        "00000176",                             // TPM_CC_StartAuthSession
        "40000007",                             // tpmKey: TPM_RH_NULL
        "40000007",                             // bind: TPM_RH_NULL
        "00100102030405060708090a0b0c0d0e0f10", // nonceCaller: 16 bytes
        "0000",                                 // encryptedSalt: size 0
        "00",                                   // sessionType: TPM_SE_HMAC
        "000a",                                 // symmetric: TPM_ALG_XOR
        "000b",                                 // keyBits: TPM_ALG_SHA256
        "000b",                                 // authHash: TPM_ALG_SHA256
    ));
    let response = send(&mut sim, &request);
    assert_eq!(response.len(), 32);
    assert_eq!(&response[0..2], &hex("8001")[..]);
    assert_eq!(&response[2..6], &32u32.to_be_bytes());
    assert_eq!(&response[6..10], &0u32.to_be_bytes()); // TPM_RC_SUCCESS
    assert_eq!(&response[10..14], &0x02000000u32.to_be_bytes()); // HMAC session handle
    assert_eq!(&response[14..16], &16u16.to_be_bytes()); // nonceTPM size
}

/// StartAuthSession with XOR and a NULL hash fails with HASH.
#[test]
fn xor_with_null_hash_rejected() {
    let mut sim = create_simulator!();

    // Start an HMAC auth session with XOR symmetric parameter but hash=TPM_ALG_NULL (0x0010)
    let request = hex(concat!(
        "8001",                                 // tag
        "0000002d",                             // size: 45 bytes
        "00000176",                             // TPM_CC_StartAuthSession
        "40000007",                             // tpmKey: TPM_RH_NULL
        "40000007",                             // bind: TPM_RH_NULL
        "00100102030405060708090a0b0c0d0e0f10", // nonceCaller: 16 bytes
        "0000",                                 // encryptedSalt: size 0
        "00",                                   // sessionType: TPM_SE_HMAC
        "000a",                                 // symmetric: TPM_ALG_XOR
        "0010",                                 // keyBits: TPM_ALG_NULL (invalid for XOR)
        "000b",                                 // authHash: TPM_ALG_SHA256
    ));
    let response = send(&mut sim, &request);
    assert_eq!(response.len(), 10);
    assert_eq!(&response[0..2], &hex("8001")[..]);
    let rc = rc_of(&response);
    assert_eq!(
        rc,
        tpm2::errors::TpmRc::HASH
            .with(tpm2::errors::Position::parameter(4))
            .get(),
        "Expected TPM_RC_HASH (0x04c3) for StartAuthSession with XOR symmetric having NULL hash"
    );
}
