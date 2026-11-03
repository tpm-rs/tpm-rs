mod common;

use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2_engine::{TpmEngine, TpmPlatform};

#[test]
fn test_get_command_audit_digest_with_zeroed_audit_hash_alg() {
    use common::FakeCrypto;
    use tpm2::{
        PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bPublicKeyRsa, TpmaObject,
        TpmiAlgHash, TpmsRsaParms, TpmtPublic,
    };
    use tpm2_engine::handler::TransientObject;

    let mut crypto = FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &mut rng);

    let mut tpm = TpmEngine::new(platform).unwrap();
    tpm.state.init_zeroed();
    // Intentionally test with audit_hash_alg = 0
    tpm.state.audit_hash_alg = 0;
    tpm.init_storage();

    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut response = [0u8; 1024];
    tpm.execute_command_separate(&startup_request[..], &mut response[..]);

    let key_handle = 0x80000001;
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::RESTRICTED
            | TpmaObject::SIGN_ENCRYPT
            | TpmaObject::USER_WITH_AUTH,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let obj = TransientObject {
        handle: key_handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private: [0xcc; tpm2_engine::handler::MAX_PRIVATE_KEY_SIZE],
        private_len: 256,
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    tpm.state.transient_objects[0] = Some(obj);

    let mut req = Vec::new();
    req.extend_from_slice(&hex!("8002"));
    req.extend_from_slice(&[0, 0, 0, 0]); // size placeholder
    req.extend_from_slice(&hex!("00000133")); // TPM_CC_GetCommandAuditDigest
    req.extend_from_slice(&0x4000000Bu32.to_be_bytes()); // RH_ENDORSEMENT
    req.extend_from_slice(&key_handle.to_be_bytes()); // signHandle
    req.extend_from_slice(&hex!(
        "00000012 40000009 0000 01 0000 40000009 0000 01 0000"
    ));
    req.extend_from_slice(&hex!("0003 616161"));
    req.extend_from_slice(&hex!("0014 0004"));

    let req_len = req.len() as u32;
    req[2..6].copy_from_slice(&req_len.to_be_bytes());

    let mut response_buf = [0u8; 16384];
    tpm.execute_command_separate(&req[..], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc, 0,
        "GetCommandAuditDigest should succeed without panic even if audit_hash_alg was 0, got rc: 0x{:08x}",
        rc
    );
}

/// Builds a `TPM2_SetCommandCodeAuditStatus(TPM_RH_OWNER)` command with an empty-password
/// session.
fn set_command_code_audit_status_cmd(
    audit_alg: u16,
    set_list: &[u32],
    clear_list: &[u32],
) -> Vec<u8> {
    let mut req = Vec::new();
    req.extend_from_slice(&hex!("8002 00000000 00000140 40000001"));
    req.extend_from_slice(&hex!("00000009 40000009 0000 01 0000"));
    req.extend_from_slice(&audit_alg.to_be_bytes());
    for list in [set_list, clear_list] {
        req.extend_from_slice(&(list.len() as u32).to_be_bytes());
        for cc in list {
            req.extend_from_slice(&cc.to_be_bytes());
        }
    }
    let len = req.len() as u32;
    req[2..6].copy_from_slice(&len.to_be_bytes());
    req
}

/// Executes `request` and returns the response code.
fn execute_rc(
    tpm: &mut TpmEngine<'_, common::FakeCrypto, FakeStorage, FakeTimer, FakeRng>,
    request: &[u8],
) -> u32 {
    let mut response = [0u8; 4096];
    tpm.execute_command_separate(request, &mut response);
    u32::from_be_bytes(response[6..10].try_into().unwrap())
}

/// An audit algorithm other than the manufacture default (the context integrity hash) and its
/// digest size: SHA-256, or SHA-384 with `context-hash-sha256` (where SHA-256 is the default).
const OTHER_AUDIT_ALG: (u16, u16) = if cfg!(feature = "context-hash-sha256") {
    (0x000C, 48)
} else {
    (0x000B, 32)
};

/// The audit list, algorithm and counter survive `_TPM_Init` (they are reloaded from NV), and
/// the audit digest is cleared by the TPM Reset that follows.
#[test]
fn command_audit_state_persists_across_tpm_init() {
    use tpm2::TpmCc;

    let mut crypto = common::FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &mut rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    tpm.state.init_zeroed();
    tpm.init_storage();
    let startup = hex!("8001 0000000c 00000144 0000");
    assert_eq!(execute_rc(&mut tpm, &startup), 0);

    // Manufacture default.
    let audited: Vec<TpmCc> = tpm.state.audit_commands.iter().collect();
    assert_eq!(audited, [TpmCc::SetCommandCodeAuditStatus]);
    assert_eq!(tpm.state.audit_counter, 0);

    // Add TPM2_GetRandom; the command itself is audited and starts a log.
    let cmd = set_command_code_audit_status_cmd(0x0010, &[0x17B], &[]);
    assert_eq!(execute_rc(&mut tpm, &cmd), 0);
    assert!(tpm.state.audit_commands.is_audited(TpmCc::GetRandom));
    assert_eq!(tpm.state.audit_counter, 1);
    assert_eq!(
        usize::from(tpm.state.command_audit_digest.get_size()),
        // The manufacture default is the context integrity hash.
        if cfg!(feature = "context-hash-sha256") {
            32
        } else {
            tpm2::TpmiAlgHash::MAX_DIGEST_BYTES
        }
    );

    // Change the algorithm: the digest is cleared and the counter unchanged.
    let cmd = set_command_code_audit_status_cmd(OTHER_AUDIT_ALG.0, &[], &[]);
    assert_eq!(execute_rc(&mut tpm, &cmd), 0);
    assert_eq!(tpm.state.audit_hash_alg, OTHER_AUDIT_ALG.0);
    assert_eq!(tpm.state.command_audit_digest.get_size(), 0);
    assert_eq!(tpm.state.audit_counter, 1);

    // An audited command starts a log of the other algorithm.
    let get_random = hex!("8001 0000000c 0000017b 0008");
    assert_eq!(execute_rc(&mut tpm, &get_random), 0);
    assert_eq!(tpm.state.audit_counter, 2);
    assert_eq!(tpm.state.command_audit_digest.get_size(), OTHER_AUDIT_ALG.1);

    // `_TPM_Init` without an orderly shutdown, then TPM Reset.
    tpm.reset();
    assert!(tpm.state.audit_commands.is_audited(TpmCc::GetRandom));
    assert_eq!(tpm.state.audit_hash_alg, OTHER_AUDIT_ALG.0);
    assert_eq!(tpm.state.audit_counter, 2);
    assert_eq!(execute_rc(&mut tpm, &startup), 0);
    assert_eq!(tpm.state.command_audit_digest.get_size(), 0);
}

/// An algorithm change combined with a command list is `TPM_RC_VALUE + P1` and changes
/// nothing; a failed audited command does not extend the digest.
#[test]
fn rejected_commands_leave_command_audit_state_unchanged() {
    use tpm2::TpmCc;

    let mut crypto = common::FakeCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let platform = TpmPlatform::new(&mut crypto, &mut storage, &mut timer, &mut rng);
    let mut tpm = TpmEngine::new(platform).unwrap();
    tpm.state.init_zeroed();
    tpm.init_storage();
    let startup = hex!("8001 0000000c 00000144 0000");
    assert_eq!(execute_rc(&mut tpm, &startup), 0);

    let cmd = set_command_code_audit_status_cmd(OTHER_AUDIT_ALG.0, &[0x17B], &[]);
    assert_eq!(execute_rc(&mut tpm, &cmd), 0x1C4);
    assert!(!tpm.state.audit_commands.is_audited(TpmCc::GetRandom));
    // The context integrity hash: SHA-512, or SHA-384 without it (SHA-256 with
    // `context-hash-sha256`).
    let default_alg = if cfg!(feature = "context-hash-sha256") {
        0x000B
    } else if tpm2::TpmiAlgHash::MAX_DIGEST_BYTES == 64 {
        0x000D
    } else {
        0x000C
    };
    assert_eq!(tpm.state.audit_hash_alg, default_alg);
    assert_eq!(tpm.state.audit_counter, 0);
    assert_eq!(tpm.state.command_audit_digest.get_size(), 0);

    // GetRandom with an oversized request still succeeds (it is clamped), so use a malformed
    // one: a trailing byte is TPM_RC_SIZE and must not be audited.
    let cmd = set_command_code_audit_status_cmd(0x0010, &[0x17B], &[]);
    assert_eq!(execute_rc(&mut tpm, &cmd), 0);
    let digest = tpm.state.command_audit_digest;
    let bad_get_random = hex!("8001 0000000d 0000017b 0008 00");
    assert_ne!(execute_rc(&mut tpm, &bad_get_random), 0);
    assert_eq!(tpm.state.command_audit_digest, digest);
    assert_eq!(tpm.state.audit_counter, 1);
}
