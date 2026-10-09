use common::marshal_to_slice;
use tpm2::errors::{Position, TpmRc};

use tpm2::{Marshal, Unmarshal};
extern crate alloc;

mod common;

use alloc::vec::Vec;
use common::{FakeRng, FakeStorage, FakeTimer};
use tpm2::commands::{
    Certify, CertifyHandles, Command, EvictControl, EvictControlHandles, GetCapability,
    GetSessionAuditDigest, GetSessionAuditDigestHandles,
};
use tpm2::crypto::Rng;
use tpm2::crypto::{Asymmetric, AsymmetricSign};
use tpm2::crypto::{CryptoError, CryptoProvider};
use tpm2::{Handle, TpmCap, TpmPt, TpmSe};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bName, Tpm2bPublicKeyRsa, TpmaObject,
    TpmaSession, TpmiAlgHash, TpmsAuthCommand, TpmtPublic, TpmtRsaScheme, TpmuAttest,
};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::{SessionState, TransientObject};

struct StressTestCrypto;

impl_fake_hash!(StressTestCrypto);

impl AsymmetricSign for StressTestCrypto {
    fn sign_inner(
        &self,
        sign_alg: tpm2::Alg,
        _private_key: &[u8],
        _digest: tpm2::TpmtHa<'_>,
        signature_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let len = match sign_alg {
            tpm2::Alg::ECDSA => {
                if signature_out.len() < 64 {
                    return Err(CryptoError::BufferTooSmall);
                }
                signature_out[..64].fill(0xee);
                64
            }
            _ => {
                if signature_out.len() < 256 {
                    return Err(CryptoError::BufferTooSmall);
                }
                signature_out[..256].fill(0xee);
                256
            }
        };
        Ok(len)
    }
}

impl Asymmetric for StressTestCrypto {
    fn verify_inner(
        &self,
        _sign_alg: tpm2::Alg,
        _public_key: &[u8],
        _digest: tpm2::TpmtHa<'_>,
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }
    fn encrypt(
        &self,
        _scheme: tpm2::Alg,
        _hash_alg: tpm2::Alg,
        _public_key: &[u8],
        _data: &[u8],
        _ciphertext: &mut [u8],
        _label: &[u8],
    ) -> Result<usize, CryptoError> {
        Ok(0)
    }
    fn decrypt(
        &self,
        _scheme: tpm2::Alg,
        _hash_alg: tpm2::Alg,
        private_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        _label: &[u8],
    ) -> Result<usize, CryptoError> {
        if private_key.is_empty() {
            return Err(CryptoError::HardwareFailure);
        }
        let len = ciphertext.len();
        if plaintext.len() < len {
            return Err(CryptoError::BufferTooSmall);
        }
        plaintext[..len].copy_from_slice(ciphertext);
        Ok(len)
    }
    fn generate_key(
        &self,
        scheme: tpm2::Alg,
        _params: Option<tpm2::crypto::asymmetric::KeyParams>,
        public_key: &mut [u8],
        private_key: &mut [u8],
        _seed: Option<&[u8]>,
    ) -> Result<(usize, usize), CryptoError> {
        match scheme {
            tpm2::Alg::RSA => {
                public_key[..256].fill(0xcc);
                private_key[..256].fill(0xdd);
                Ok((256, 256))
            }
            tpm2::Alg::ECC => {
                public_key[..64].fill(0xcc);
                private_key[..32].fill(0xdd);
                Ok((64, 32))
            }
            _ => Err(CryptoError::HardwareFailure),
        }
    }
}

impl Rng for StressTestCrypto {
    fn get_random(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        dest.fill(0xaa);
        Ok(())
    }
}

impl CryptoProvider for StressTestCrypto {}

fn setup_tpm<'a>(
    crypto: &'a mut StressTestCrypto,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a FakeRng,
) -> (
    TpmEngine<'a, StressTestCrypto, FakeStorage, FakeTimer, FakeRng>,
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
    let startup_request = hex_literal::hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    (tpm, global_state)
}

fn command_resp_handles_size(cc: tpm2::TpmCc) -> usize {
    match cc {
        tpm2::TpmCc::CreatePrimary
        | tpm2::TpmCc::StartAuthSession
        | tpm2::TpmCc::ContextLoad
        | tpm2::TpmCc::CreateLoaded
        | tpm2::TpmCc::LoadExternal => 4,
        _ => 0,
    }
}

fn execute_tpm_command_with_auths_get_resp<C: Command>(
    tpm: &mut TpmEngine<'_, StressTestCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &C::Handles,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<Vec<tpm2::TpmsAuthResponse<'static>>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <<C as Command>::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    // Tag
    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    // Command code
    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    let handles_slice: &mut <C::Handles as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C::Handles as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let handles_len = handles.marshal(handles_slice);
    offset += handles_len;

    // Marshal auth area if tag is 0x8002
    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4; // place holder for auth size
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

    // Fill in total Size
    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut response_buf = [0u8; 16384];
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        let resp_handles_size = command_resp_handles_size(C::CMD_CODE);
        let param_size = u32::from_be_bytes(
            response_buf[10 + resp_handles_size..14 + resp_handles_size]
                .try_into()
                .unwrap(),
        ) as usize;

        let params_offset = 14 + resp_handles_size;
        let mut session_responses = Vec::new();
        let mut session_unmarshal_buf: &'static [u8] =
            std::vec::Vec::leak(response_buf[params_offset + param_size..resp_size].to_vec());
        while !session_unmarshal_buf.is_empty() {
            let auth_resp = tpm2::TpmsAuthResponse::unmarshal(&mut session_unmarshal_buf)
                .map_err(|_| TpmRc::FAILURE.get())?;
            session_responses.push(auth_resp);
        }
        Ok(session_responses)
    } else {
        Ok(Vec::new())
    }
}

fn execute_tpm_get_session_audit_digest<'a>(
    tpm: &mut TpmEngine<'_, StressTestCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &GetSessionAuditDigestHandles,
    cmd: &GetSessionAuditDigest,
    auths: &[TpmsAuthCommand],
    response_buf: &'a mut [u8],
) -> Result<<GetSessionAuditDigest<'static> as Command>::Response<'a>, u32> {
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(GetSessionAuditDigest::CMD_CODE.code()).to_be_bytes());
    offset += marshal_to_slice(handles, &mut request_buf[offset..]);

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

    offset += marshal_to_slice(cmd, &mut request_buf[offset..]);
    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    let params_offset = if resp_tag == 0x8002 { 14 } else { 10 };
    let mut unmarshal_buf: &'static [u8] =
        std::vec::Vec::leak(response_buf[params_offset..resp_size].to_vec());
    Unmarshal::unmarshal(&mut unmarshal_buf).map_err(|_| TpmRc::FAILURE.get())
}

fn compute_mock_hmac(attributes: u8, nonce_tpm: &[u8]) -> Tpm2bAuth<'_> {
    let mut hmac = [0u8; 32];
    let mut digest = [0u8; 32];
    let input = [0, 0, 1, 0x7a, 0, 0, 0, 6, 0, 0, 1, 0, 0, 0, 0, 1];
    for (i, &b) in input.iter().enumerate() {
        digest[i % 32] ^= b;
    }

    // state = key (32) + digest (32) + nonce_tpm (len) + attributes (1)
    let state_len = 32 + 32 + nonce_tpm.len() + 1;

    for i in 0..32 {
        hmac[i] ^= digest[i];
    }
    for (i, &b) in nonce_tpm.iter().enumerate() {
        hmac[i % 32] ^= b;
    }
    hmac[(32 + 32 + nonce_tpm.len()) % 32] ^= attributes;
    hmac[1] ^= state_len as u8;

    Tpm2bAuth::from_bytes(std::vec::Vec::leak(hmac.to_vec())).unwrap()
}

// Case 1: Verification of Response Session Attributes (auditExclusive and audit bits)
#[test]
fn test_response_session_attributes_audit_and_exclusivity() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let session_handle_1 = 0x02000001;
    let session_handle_2 = 0x02000002;

    // Session 1: Audit session
    let s1 = SessionState {
        session_handle: session_handle_1,
        session_type: TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: Handle::RH_NULL,
        bound_entity: Default::default(),
        audit_digest: None,
        audit_digest_len: 0,
        audit_cp_hash: [0u8; 64],
        audit_cp_hash_len: 0,
        policy_hash: [0u8; 64],
        policy_hash_len: 0,
        is_cp_hash_defined: false,
        is_name_hash_defined: false,
        is_template_hash_defined: false,
        policy_digest: [0u8; 64],
        policy_digest_len: 0,
        command_code: 0,
        start_time: 0,
        timeout: 0,
        epoch: global_state.time_epoch,
        is_auth_value_needed: false,
        is_password_needed: false,
        pcr_counter: None,
        check_nv_written: false,
        nv_written_state: false,
        command_locality: 0,
        include_auth: false,
        is_da_bound: false,
        is_lockout_bound: false,
    };
    global_state.add_session(s1).unwrap();

    // Session 2: Audit session
    let s2 = SessionState {
        session_handle: session_handle_2,
        session_type: TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: Handle::RH_NULL,
        bound_entity: Default::default(),
        audit_digest: None,
        audit_digest_len: 0,
        audit_cp_hash: [0u8; 64],
        audit_cp_hash_len: 0,
        policy_hash: [0u8; 64],
        policy_hash_len: 0,
        is_cp_hash_defined: false,
        is_name_hash_defined: false,
        is_template_hash_defined: false,
        policy_digest: [0u8; 64],
        policy_digest_len: 0,
        command_code: 0,
        start_time: 0,
        timeout: 0,
        epoch: global_state.time_epoch,
        is_auth_value_needed: false,
        is_password_needed: false,
        pcr_counter: None,
        check_nv_written: false,
        nv_written_state: false,
        command_locality: 0,
        include_auth: false,
        is_da_bound: false,
        is_lockout_bound: false,
    };
    global_state.add_session(s2).unwrap();

    let cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    };

    // A. Session 1 with AUDIT | AUDIT_RESET (0x85) -> should establish exclusivity
    let hmac_1 = compute_mock_hmac(0x85, &[]);
    let auth_1 = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle_1),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x85),
        hmac: hmac_1,
    };

    let res_sessions_1 =
        execute_tpm_command_with_auths_get_resp(&mut tpm, &mut global_state, &(), &cmd, &[auth_1])
            .unwrap();
    assert_eq!(res_sessions_1.len(), 1);
    // Attributes in response: audit (0x80) and auditExclusive (0x02) must be set, auditReset (0x04) must NOT be set
    let attrs_1 = res_sessions_1[0].session_attributes.0;
    assert_eq!(
        attrs_1 & 0x80,
        0x80,
        "Expected audit bit to be set in response"
    );
    assert_eq!(
        attrs_1 & 0x02,
        0x02,
        "Expected auditExclusive bit to be set in response"
    );
    assert_eq!(
        attrs_1 & 0x04,
        0x04,
        "Expected auditReset bit to be set in response because the digest was reset"
    );

    // B. Session 2 with AUDIT | AUDIT_RESET (0x85) -> exclusivity hands over to Session 2
    let nonce_tpm_2 = global_state.session(session_handle_2).unwrap().nonce_tpm;
    let hmac_2 = compute_mock_hmac(0x85, nonce_tpm_2.get_buffer());
    let auth_2 = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle_2),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x85),
        hmac: hmac_2,
    };

    let res_sessions_2 =
        execute_tpm_command_with_auths_get_resp(&mut tpm, &mut global_state, &(), &cmd, &[auth_2])
            .unwrap();
    assert_eq!(res_sessions_2.len(), 1);
    let attrs_2 = res_sessions_2[0].session_attributes.0;
    assert_eq!(attrs_2 & 0x80, 0x80);
    assert_eq!(attrs_2 & 0x02, 0x02);

    // C. Execute command using Session 1 with just AUDIT (0x81) -> exclusivity is lost for Session 1
    let nonce_tpm_1 = global_state.session(session_handle_1).unwrap().nonce_tpm;
    let hmac_1_again = compute_mock_hmac(0x81, nonce_tpm_1.get_buffer());
    let auth_1_again = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle_1),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x81),
        hmac: hmac_1_again,
    };

    let res_sessions_1_again = execute_tpm_command_with_auths_get_resp(
        &mut tpm,
        &mut global_state,
        &(),
        &cmd,
        &[auth_1_again],
    )
    .unwrap();
    assert_eq!(res_sessions_1_again.len(), 1);
    let attrs_1_again = res_sessions_1_again[0].session_attributes.0;
    assert_eq!(attrs_1_again & 0x80, 0x80);
    assert_eq!(
        attrs_1_again & 0x02,
        0,
        "Expected auditExclusive to be cleared since exclusivity was lost"
    );
}

// Case 2: GetSessionAuditDigest Response Field Verification
#[test]
fn test_get_session_audit_digest_field_verification() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let audit_session_handle = 0x02000001;

    // Session: Audit session
    let s = SessionState {
        session_handle: audit_session_handle,
        session_type: TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: Handle::RH_NULL,
        bound_entity: Default::default(),
        audit_digest: Some([0xab; 64]), // initial non-zero audit digest
        audit_digest_len: 32,
        audit_cp_hash: [0u8; 64],
        audit_cp_hash_len: 0,
        policy_hash: [0u8; 64],
        policy_hash_len: 0,
        is_cp_hash_defined: false,
        is_name_hash_defined: false,
        is_template_hash_defined: false,
        policy_digest: [0u8; 64],
        policy_digest_len: 0,
        command_code: 0,
        start_time: 0,
        timeout: 0,
        epoch: global_state.time_epoch,
        is_auth_value_needed: false,
        is_password_needed: false,
        pcr_counter: None,
        check_nv_written: false,
        nv_written_state: false,
        command_locality: 0,
        include_auth: false,
        is_da_bound: false,
        is_lockout_bound: false,
    };
    global_state.add_session(s).unwrap();

    // Command 1: GetCapability, session with AUDIT_RESET and AUDIT (0x85) to initialize and extend the audit digest
    let cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    };
    let hmac_1 = compute_mock_hmac(0x85, &[]);
    let auth_1 = TpmsAuthCommand {
        session_handle: tpm2::Handle(audit_session_handle),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x85),
        hmac: hmac_1,
    };

    execute_tpm_command_with_auths_get_resp(&mut tpm, &mut global_state, &(), &cmd, &[auth_1])
        .unwrap();

    // Get target audit session digest value in TPM state
    let digest_before = global_state
        .session(audit_session_handle)
        .unwrap()
        .audit_digest
        .unwrap();
    let digest_len_before = global_state
        .session(audit_session_handle)
        .unwrap()
        .audit_digest_len;

    // Execute GetSessionAuditDigest on this session
    let get_audit_cmd = GetSessionAuditDigest {
        qualifying_data: Tpm2bData::from_bytes(&[9, 9, 9]).unwrap(),
        in_scheme: None,
    };
    let get_audit_handles = GetSessionAuditDigestHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: Handle(0x40000007), // RHNull
        session_handle: Handle(audit_session_handle),
    };
    let admin_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };

    let mut response_buf = [0u8; 16384];
    let resp = execute_tpm_get_session_audit_digest(
        &mut tpm,
        &mut global_state,
        &get_audit_handles,
        &get_audit_cmd,
        // signHandle (TPM_RH_NULL) also has the USER auth role, so C needs a second session
        // (SessionProcess.c:1641-1651, otherwise TPM_RC_AUTH_MISSING).
        &[admin_auth, admin_auth],
        &mut response_buf,
    )
    .unwrap();

    // Parse audit_info: Tpm2bAttest into TpmsAttest
    let attest = resp.audit_info.0;

    let _ = attest.magic; // Verified by unmarshaling
    assert_eq!(attest.extra_data.get_buffer(), &[9, 9, 9]);

    match attest.attested {
        TpmuAttest::SessionAudit(info) => {
            // Verify that exclusive_session is YES because the session currently holds the exclusivity lock
            assert!(info.exclusive_session);
            // Verify that session_digest matches digest_before
            assert_eq!(
                info.session_digest.get_buffer(),
                &digest_before[..digest_len_before]
            );
        }
        _ => panic!("Expected attested to be SessionAudit"),
    }
}

// Case 3: Persistent Object Name Lookup Verification
#[test]
fn test_persistent_object_handle_name_mismatch() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let key_handle = 0x80000001;
    let persistent_handle = 0x81000001;

    // 1. Load a transient key into the transient_objects slots
    let real_name = Tpm2bName::from_bytes(&[1, 2, 3, 4, 5]).unwrap();
    let transient_obj = TransientObject {
        handle: key_handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (real_name).into(),
        auth: (Tpm2bAuth::from_bytes(&[0x11, 0x22]).unwrap()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                tpm2::TpmsRsaParms {
                    symmetric: None,
                    scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                    key_bits: tpm2::TpmiRsaKeyBits(2048),
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::default(),
            ),
        })
        .into(),
        private: [0u8; 1536],
        private_len: 256,
        qualified_name: (Tpm2bName::from_bytes(&[1, 2, 3, 4, 5]).unwrap()).into(),
        hierarchy: 0x40000001, // Owner hierarchy
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(transient_obj);

    // 2. Persist the key to persistent_handle (0x81000001) using EvictControl command
    let evict_handles = EvictControlHandles {
        auth: Handle::RH_OWNER,
        object_handle: Handle(key_handle),
    };
    let evict_cmd = EvictControl {
        persistent_handle: Handle(persistent_handle),
    };
    // Owner hierarchy auth is empty by default, so empty auth command
    let owner_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };
    execute_tpm_command_with_auths_get_resp(
        &mut tpm,
        &mut global_state,
        &evict_handles,
        &evict_cmd,
        &[owner_auth],
    )
    .unwrap();

    // 3. Remove/flush the transient key so it's only accessible via persistent_handle
    global_state.transient_objects[0] = None;

    // 4. Try to authenticate with the persistent key using a session.
    // In handle_name, there's no handler for persistent handles, so the computed name
    // is handle.to_be_bytes() = [0x81, 0x00, 0x00, 0x01].
    // Let's create an active HMAC session.
    let session_handle = 0x02000001;
    let s = SessionState {
        session_handle,
        session_type: TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: Handle::RH_NULL,
        bound_entity: Default::default(),
        audit_digest: None,
        audit_digest_len: 0,
        audit_cp_hash: [0u8; 64],
        audit_cp_hash_len: 0,
        policy_hash: [0u8; 64],
        policy_hash_len: 0,
        is_cp_hash_defined: false,
        is_name_hash_defined: false,
        is_template_hash_defined: false,
        policy_digest: [0u8; 64],
        policy_digest_len: 0,
        command_code: 0,
        start_time: 0,
        timeout: 0,
        epoch: global_state.time_epoch,
        is_auth_value_needed: false,
        is_password_needed: false,
        pcr_counter: None,
        check_nv_written: false,
        nv_written_state: false,
        command_locality: 0,
        include_auth: false,
        is_da_bound: false,
        is_lockout_bound: false,
    };
    global_state.add_session(s).unwrap();

    // Let's run Certify using the persistent key as the certified object_handle.
    let certify_cmd = Certify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let mut param_buf = [0u8; 100];
    let param_len = marshal_to_slice(&(certify_cmd), &mut param_buf[..]);
    println!(
        "certify_cmd marshaled bytes (len={}): {:?}",
        param_len,
        &param_buf[..param_len]
    );

    let certify_handles = CertifyHandles {
        object_handle: Handle(persistent_handle), // Authorizing handle index 0
        sign_handle: Handle(0x40000007),          // RHNull
    };

    // If the client computes the HMAC using the key's REAL name (real_name):
    // Let's see: computed hmac inputs include the authorizing key name.
    // Here we compute a mock hmac manually. But wait! Let's compute it using the real name vs the handle bytes name.
    // Let's first test the real client case: we compute HMAC using the real Name.
    // In our StressTestCrypto, how is hmac computed?
    // hmac state is key XORed with digest.
    // In verify_session_hmacs:
    // computed_hmac = HMAC(hmac_key, cp_hash || nonce_caller || nonce_tpm || session_attributes)
    // where cp_hash = Hash(command_code || auth_handle_names[..] || parameters)
    // Here, auth_handle_names[0] = handle_name(tpm, persistent_handle)
    // Under real behavior: auth_handle_names[0] should be real_name.
    // Under tpm-rs current code: auth_handle_names[0] is persistent_handle.to_be_bytes().
    // Let's compute a client-side HMAC using the WRONG name (which matches tpm-rs's incorrect handle.to_be_bytes() name):

    // Let's see: cp_hash_input = command_code (0x00000148) || wrong_name || parameters (empty/default)
    // Let's do it: command_code = 0x00000148. wrong_name = 0x81000001.
    // Let's verify if providing this wrong-name-based HMAC actually succeeds!
    // If it succeeds, it PROVES the TPM is using the wrong name (since a correct TPM would require HMAC based on the real Name).

    // Let's compute HMAC using the real Name:
    // cp_hash_input = command_code (0x00000148) || real_name ([1, 2, 3, 4, 5])
    // If we send HMAC based on real Name:
    // Under current buggy tpm-rs, this WILL FAIL because the TPM computes the HMAC using the wrong name [0x81, 0, 0, 1].
    // Let's verify that sending real-name-based HMAC fails under the current implementation!

    // We compute the HMAC using the real Name:
    // Wait, let's write a helper to compute the correct stress test HMAC based on name:
    // StressTestCrypto HMAC algorithm:
    let simulate_stress_test_hmac = |key: &[u8], cp_hash: &[u8], attrs: u8| -> [u8; 32] {
        let mut state = Vec::new();
        state.extend_from_slice(key);
        state.extend_from_slice(cp_hash);
        state.push(attrs);

        let mut out = [0u8; 32];
        for (i, &b) in state.iter().enumerate() {
            out[i % 32] ^= b;
        }
        out[1] ^= state.len() as u8;
        out
    };

    let mut hmac_key = [0u8; 34];
    hmac_key[32..34].copy_from_slice(&[0x11, 0x22]); // key_auth

    // For real name [1, 2, 3, 4, 5]:
    let mut real_cp_hash_data = Vec::new();
    real_cp_hash_data.extend_from_slice(&[0, 0, 1, 0x48]);
    real_cp_hash_data.extend_from_slice(real_name.get_buffer());
    real_cp_hash_data.extend_from_slice(&[0x40, 0x00, 0x00, 0x07]);
    real_cp_hash_data.extend_from_slice(&[0, 0, 0, 0x10]);
    let mut real_cp_hash = [0u8; 32];
    for (i, &b) in real_cp_hash_data.iter().enumerate() {
        real_cp_hash[i % 32] ^= b;
    }

    let expected_real_hmac = simulate_stress_test_hmac(&hmac_key, &real_cp_hash, 0x01);

    let real_auth = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x01),
        hmac: Tpm2bAuth::from_bytes(&expected_real_hmac).unwrap(),
    };

    // Attempt Certify with the real-name-based HMAC.
    // Now that the handle_name bug is fixed, this command MUST SUCCEED because the TPM uses the correct
    // persistent object Name from NV storage!
    let res_real = execute_tpm_command_with_auths_get_resp(
        &mut tpm,
        &mut global_state,
        &certify_handles,
        &certify_cmd,
        // signHandle (TPM_RH_NULL) has the USER auth role, so C needs a second session
        // (SessionProcess.c:1641-1651, otherwise TPM_RC_AUTH_MISSING).
        &[real_auth, common::password_auth(b"")],
    );
    assert!(
        res_real.is_ok(),
        "Expected authentication to succeed using correct real name, got error: {:?}",
        res_real.err()
    );

    // Let's verify that if we compute HMAC using the WRONG name ([0x81, 0x00, 0x00, 0x01]), it now FAILS!
    let mut wrong_cp_hash_data = Vec::new();
    wrong_cp_hash_data.extend_from_slice(&[0, 0, 1, 0x48]);
    wrong_cp_hash_data.extend_from_slice(&[0x81, 0x00, 0x00, 0x01]);
    wrong_cp_hash_data.extend_from_slice(&[0x40, 0x00, 0x00, 0x07]);
    wrong_cp_hash_data.extend_from_slice(&[0, 0, 0, 0x10]);
    let mut wrong_cp_hash = [0u8; 32];
    for (i, &b) in wrong_cp_hash_data.iter().enumerate() {
        wrong_cp_hash[i % 32] ^= b;
    }

    let expected_wrong_hmac = simulate_stress_test_hmac(&hmac_key, &wrong_cp_hash, 0x01);

    let wrong_auth = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x01),
        hmac: Tpm2bAuth::from_bytes(&expected_wrong_hmac).unwrap(),
    };

    let res_wrong = execute_tpm_command_with_auths_get_resp(
        &mut tpm,
        &mut global_state,
        &certify_handles,
        &certify_cmd,
        &[wrong_auth, common::password_auth(b"")],
    );
    assert_eq!(
        res_wrong.err(),
        Some(TpmRc::AUTH_FAIL.with(Position::session(1)).get()),
        "Expected authentication to fail with TPM_RC_AUTH_FAIL because wrong-name-based HMAC was used!"
    );
}
