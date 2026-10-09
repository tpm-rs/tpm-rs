use common::marshal_to_slice;
use tpm2::Alg;
use tpm2::errors::{Position, TpmRc};

use tpm2::Unmarshal;
extern crate alloc;

mod common;

use common::{FakeRng, FakeStorage, FakeTimer};
use tpm2::commands::{
    Command, PolicyAuthorize, PolicyAuthorizeHandles, PolicyDuplicationSelect,
    PolicyDuplicationSelectHandles, PolicySigned, PolicySignedHandles, VerifySignature,
    VerifySignatureHandles,
};
use tpm2::crypto::{Asymmetric, AsymmetricSign};
use tpm2::{Handle, Marshal, TpmCc};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bNonce, Tpm2bPublicKeyRsa,
    TpmSe as Tpm2Se, TpmaObject, TpmiAlgHash, TpmsAuthCommand, TpmsEccPoint, TpmsRsaParms,
    TpmsSignatureEcc, TpmsSignatureRsa, TpmtPublic, TpmtSignature, TpmtTkVerified,
};

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    tpm2::crypto::hash(&TestCryptoProvider, TpmiAlgHash::Sha256, data, &mut out)
        .unwrap()
        .digest()
        .try_into()
        .unwrap()
}
use common::TestCryptoProvider;
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::{SessionState, TransientObject};

fn setup_tpm<'a>(
    crypto: &'a mut TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a FakeRng,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
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

fn execute_tpm_command_with_auths<C: Command>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &C::Handles,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <<C as Command>::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: Unmarshal<'static>,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

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

    let mut response_buf = [0u8; 16384];
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
    let resp =
        <C::Response<'static>>::unmarshal(&mut unmarshal_buf).map_err(|_| TpmRc::FAILURE.get())?;
    Ok(resp)
}

fn compute_key_name(_crypto: &TestCryptoProvider, public: &TpmtPublic) -> Tpm2bName<'static> {
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(public, &mut buf);
    let digest = sha256_bytes(&buf[..len]);

    let mut name_bytes = [0u8; 34];
    name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    name_bytes[2..34].copy_from_slice(&digest);
    Tpm2bName::from_bytes(std::vec::Vec::leak(name_bytes[..34].to_vec())).unwrap()
}

fn add_transient_object(global_state: &mut tpm2_impl::GlobalState, obj: TransientObject) {
    let slot = global_state
        .transient_objects
        .iter()
        .position(|s| s.is_none())
        .expect("No free transient object slots");
    global_state.transient_objects[slot] = Some(obj);
}

fn create_transient_ecc_key(
    crypto: &TestCryptoProvider,
    handle: u32,
    attrs: TpmaObject,
) -> (TransientObject, [u8; 1024], usize) {
    let mut pub_buf = [0u8; 512];
    let mut priv_buf = [0u8; 1024];
    use tpm2::Alg;

    let (_pub_len, priv_len) = crypto
        .generate_key(Alg::ECC, None, &mut pub_buf, &mut priv_buf, None)
        .unwrap();

    let x = tpm2::Tpm2bEccParameter::from_bytes(&pub_buf[..32]).unwrap();
    let y = tpm2::Tpm2bEccParameter::from_bytes(&pub_buf[32..64]).unwrap();

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            tpm2::TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: tpm2::TpmEccCurve::NistP256,
                kdf: None,
            },
            TpmsEccPoint { x, y },
        ),
    };
    let name = compute_key_name(crypto, &public);
    let mut private = [0u8; 1536];
    private[..priv_len].copy_from_slice(&priv_buf[..priv_len]);

    let obj = TransientObject {
        handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: name.into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private,
        private_len: priv_len,
        qualified_name: (name).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    (obj, priv_buf, priv_len)
}

fn create_transient_rsa_key(
    crypto: &TestCryptoProvider,
    handle: u32,
    attrs: TpmaObject,
) -> (TransientObject, [u8; 2048], usize) {
    let mut pub_buf = [0u8; 512];
    let mut priv_buf = [0u8; 2048];
    use tpm2::Alg;
    use tpm2::crypto::asymmetric::KeyParams;
    use tpm2::crypto::asymmetric::TpmiRsaKeyBits;

    let (pub_len, priv_len) = crypto
        .generate_key(
            Alg::RSA,
            Some(KeyParams::Rsa(TpmiRsaKeyBits(2048))),
            &mut pub_buf,
            &mut priv_buf,
            None,
        )
        .unwrap();

    let unique = Tpm2bPublicKeyRsa::from_bytes(&pub_buf[..pub_len]).unwrap();

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            unique,
        ),
    };
    let name = compute_key_name(crypto, &public);
    let mut private = [0u8; 1536];
    private[..priv_len].copy_from_slice(&priv_buf[..priv_len]);

    let obj = TransientObject {
        handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: name.into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        private,
        private_len: priv_len,
        qualified_name: (name).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    (obj, priv_buf, priv_len)
}

#[test]
fn test_policy_signed_ecc_correctness() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let key_handle = 0x80000001;
    let (signer_obj, priv_bytes, priv_len) = create_transient_ecc_key(
        tpm.platform.crypto,
        key_handle,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    add_transient_object(&mut global_state, signer_obj.clone());

    let session_handle = 0x03000001;
    let policy_session = SessionState {
        session_handle,
        session_type: Tpm2Se::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::from_bytes(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::from_bytes(&[1; 32]).unwrap()).into(),
        session_key: [0u8; 128],
        session_key_len: 0,
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
        policy_digest_len: 32,
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
    global_state.add_session(policy_session).unwrap();

    let nonce_tpm_input = Tpm2bNonce::from_bytes(&[2; 32]).unwrap();
    let expiration: i32 = -100;
    let policy_ref = Tpm2bNonce::from_bytes(&[5, 6, 7, 8]).unwrap();
    let cp_hash_a = Tpm2bDigest::default();

    // toBeSigned = nonceTPM (32) || expiration (4) || cpHashA (0) || policyRef (4)
    let mut to_be_signed = [0u8; 128];
    let mut offset = 0;
    to_be_signed[offset..offset + 32].copy_from_slice(nonce_tpm_input.get_buffer());
    offset += 32;
    to_be_signed[offset..offset + 4].copy_from_slice(&expiration.to_be_bytes());
    offset += 4;
    to_be_signed[offset..offset + cp_hash_a.get_size() as usize]
        .copy_from_slice(cp_hash_a.get_buffer());
    offset += cp_hash_a.get_size() as usize;
    to_be_signed[offset..offset + policy_ref.get_size() as usize]
        .copy_from_slice(policy_ref.get_buffer());
    offset += policy_ref.get_size() as usize;

    let digest_to_sign = sha256_bytes(&to_be_signed[..offset]);

    let mut raw_sig = [0u8; 512];
    tpm.platform
        .crypto
        .sign_inner(
            tpm2::Alg::ECDSA,
            &priv_bytes[..priv_len],
            tpm2::TpmtHa::Sha256(&digest_to_sign),
            &mut raw_sig,
        )
        .unwrap();

    let signature_r = tpm2::Tpm2bEccParameter::from_bytes(&raw_sig[..32]).unwrap();
    let signature_s = tpm2::Tpm2bEccParameter::from_bytes(&raw_sig[32..64]).unwrap();

    let auth = TpmtSignature::Ecdsa(TpmsSignatureEcc {
        hash: TpmiAlgHash::Sha256,
        signature_r,
        signature_s,
    });

    let handles = PolicySignedHandles {
        auth_object: Handle(key_handle),
        policy_session: Handle(session_handle),
    };
    let cmd = PolicySigned {
        nonce_tpm: nonce_tpm_input,
        cp_hash_a,
        policy_ref,
        expiration,
        auth,
    };

    let rsp =
        execute_tpm_command_with_auths(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();

    // Verify session state is updated
    let (_policy_digest, policy_digest_len) = {
        let s = global_state.session(session_handle).unwrap();
        (s.policy_digest, s.policy_digest_len)
    };

    // expected digest1 = SHA256(initial_digest (32) || TPM_CC_PolicySigned (4) || authName (34))
    // expected new_digest = SHA256(digest1 (32) || policyRef (4))
    let auth_name = tpm.handle_name(&mut global_state, key_handle);
    let mut expected_update1 = [0u8; 70];
    expected_update1[32..36].copy_from_slice(&(TpmCc::PolicySigned.code()).to_be_bytes());
    expected_update1[36..70].copy_from_slice(auth_name.get_buffer());
    let digest1 = sha256_bytes(&expected_update1);

    let mut expected_update2 = [0u8; 36];
    expected_update2[..32].copy_from_slice(&digest1);
    expected_update2[32..36].copy_from_slice(policy_ref.get_buffer());
    let expected_digest = sha256_bytes(&expected_update2);

    // Re-verify the updated policy digest in the session
    let final_session = global_state.session(session_handle).unwrap();
    assert_eq!(
        &final_session.policy_digest[..policy_digest_len],
        &expected_digest[..]
    );

    // Verify a ticket is returned because expiration < 0
    assert_eq!(rsp.policy_ticket.tag(), 0x8025);
    assert_ne!(rsp.policy_ticket.digest().get_size(), 0);
}

#[test]
fn test_policy_signed_rsa_correctness() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let key_handle = 0x80000001;
    let (signer_obj, priv_bytes, priv_len) = create_transient_rsa_key(
        tpm.platform.crypto,
        key_handle,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    add_transient_object(&mut global_state, signer_obj.clone());

    let session_handle = 0x03000001;
    let policy_session = SessionState {
        session_handle,
        session_type: Tpm2Se::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::from_bytes(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::from_bytes(&[1; 32]).unwrap()).into(),
        session_key: [0u8; 128],
        session_key_len: 0,
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
        policy_digest_len: 32,
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
    global_state.add_session(policy_session).unwrap();

    let nonce_tpm_input = Tpm2bNonce::from_bytes(&[2; 32]).unwrap();
    let expiration: i32 = 0; // No ticket
    let policy_ref = Tpm2bNonce::default();
    let cp_hash_a = Tpm2bDigest::default();

    // toBeSigned = nonceTPM (32) || expiration (4) || cpHashA (0) || policyRef (0)
    let mut to_be_signed = [0u8; 36];
    to_be_signed[..32].copy_from_slice(nonce_tpm_input.get_buffer());
    to_be_signed[32..36].copy_from_slice(&expiration.to_be_bytes());

    let digest_to_sign = sha256_bytes(&to_be_signed);

    let mut raw_sig = [0u8; 512];
    let sig_len = tpm
        .platform
        .crypto
        .sign_inner(
            tpm2::Alg::RSASSA,
            &priv_bytes[..priv_len],
            tpm2::TpmtHa::Sha256(&digest_to_sign),
            &mut raw_sig,
        )
        .unwrap();

    let sig = tpm2::Tpm2bPublicKeyRsa::from_bytes(&raw_sig[..sig_len]).unwrap();
    let auth = TpmtSignature::Rsassa(TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig,
    });

    let handles = PolicySignedHandles {
        auth_object: Handle(key_handle),
        policy_session: Handle(session_handle),
    };
    let cmd = PolicySigned {
        nonce_tpm: nonce_tpm_input,
        cp_hash_a,
        policy_ref,
        expiration,
        auth,
    };

    let rsp =
        execute_tpm_command_with_auths(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();

    // Verify session state is updated
    let (_policy_digest, policy_digest_len) = {
        let s = global_state.session(session_handle).unwrap();
        (s.policy_digest, s.policy_digest_len)
    };
    assert_ne!(policy_digest_len, 0);
    // Ticket should be empty because expiration is 0
    assert_eq!(rsp.policy_ticket.digest().get_size(), 0);
}

#[test]
fn test_policy_signed_incorrect_signature_fails() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let key_handle = 0x80000001;
    let (signer_obj, _priv_bytes, _priv_len) = create_transient_ecc_key(
        tpm.platform.crypto,
        key_handle,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    add_transient_object(&mut global_state, signer_obj);

    let session_handle = 0x03000001;
    let policy_session = SessionState {
        session_handle,
        session_type: Tpm2Se::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::from_bytes(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::from_bytes(&[1; 32]).unwrap()).into(),
        session_key: [0u8; 128],
        session_key_len: 0,
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
        policy_digest_len: 32,
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
    global_state.add_session(policy_session).unwrap();

    // Use a completely incorrect signature
    let signature_r = tpm2::Tpm2bEccParameter::from_bytes(&[0x99; 32]).unwrap();
    let signature_s = tpm2::Tpm2bEccParameter::from_bytes(&[0x99; 32]).unwrap();
    let auth = TpmtSignature::Ecdsa(TpmsSignatureEcc {
        hash: TpmiAlgHash::Sha256,
        signature_r,
        signature_s,
    });

    let handles = PolicySignedHandles {
        auth_object: Handle(key_handle),
        policy_session: Handle(session_handle),
    };
    let cmd = PolicySigned {
        nonce_tpm: Tpm2bNonce::from_bytes(&[2; 32]).unwrap(),
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: 0,
        auth,
    };

    let res = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &handles, &cmd, &[]);
    // Should fail with a signature/parameter verification error
    assert!(res.is_err());
}

#[test]
fn test_policy_authorize_rh_null_bypass_vulnerability() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let session_handle = 0x03000001;
    let policy_session = SessionState {
        session_handle,
        session_type: Tpm2Se::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::from_bytes(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::from_bytes(&[1; 32]).unwrap()).into(),
        session_key: [0u8; 128],
        session_key_len: 0,
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
        policy_digest: [0u8; 64], // initial policy digest is all zeros
        policy_digest_len: 32,
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
    global_state.add_session(policy_session).unwrap();

    let approved_policy = Tpm2bDigest::from_bytes(&[0; 32]).unwrap();
    let policy_ref = Tpm2bNonce::from_bytes(&[5, 6, 7, 8]).unwrap();

    let mut key_sign_bytes = [0u8; 34];
    key_sign_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    key_sign_bytes[2..34].copy_from_slice(&[0x11; 32]);
    let key_sign = Tpm2bName::from_bytes(&key_sign_bytes).unwrap();

    // Normally we need a signature from key_sign. But we use a ticket with RH_NULL (0x40000007).
    // Because the hierarchy is RH_NULL, the proof_len is 0 (empty proof).
    // The HMAC is computed over: 0x8022 (2 bytes) || aHash (32 bytes) || keySign name (34 bytes)
    // aHash = SHA256(approvedPolicy || policyRef)
    let mut a_hash_input = [0u8; 36];
    a_hash_input[..32].copy_from_slice(approved_policy.get_buffer());
    a_hash_input[32..36].copy_from_slice(policy_ref.get_buffer());
    let a_hash = sha256_bytes(&a_hash_input);

    let mut hmac_input = [0u8; 256];
    let mut offset = 0;
    hmac_input[offset..offset + 2].copy_from_slice(&0x8022u16.to_be_bytes());
    offset += 2;
    hmac_input[offset..offset + 32].copy_from_slice(&a_hash);
    offset += 32;
    hmac_input[offset..offset + key_sign.get_size() as usize]
        .copy_from_slice(key_sign.get_buffer());
    offset += key_sign.get_size() as usize;

    // Since proof is empty for RH_NULL, the HMAC is calculated using empty key
    let mut hmac_buf = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let computed_hmac = tpm2::crypto::hmac(
        &*tpm.platform.crypto,
        TpmiAlgHash::Sha256,
        &[],
        &hmac_input[..offset],
        &mut hmac_buf,
    )
    .unwrap();

    let check_ticket = TpmtTkVerified::Verified(
        Handle(0x40000007),
        Tpm2bDigest::from_bytes(computed_hmac.digest()).unwrap(),
    );

    let handles = PolicyAuthorizeHandles {
        policy_session: Handle(session_handle),
    };
    let cmd = PolicyAuthorize {
        approved_policy,
        policy_ref,
        key_sign,
        check_ticket,
    };

    // Execute PolicyAuthorize. It should fail because the ticket uses an empty key but the TPM uses the random null_proof!
    let res = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &handles, &cmd, &[]);
    assert!(
        res.is_err(),
        "Expected PolicyAuthorize to fail with forged RH_NULL ticket, but it succeeded!"
    );
    let err = res.err().unwrap();
    assert_eq!(err, TpmRc::VALUE.with(Position::parameter(4)).get());
}

#[test]
fn test_policy_authorize_verify_signature_ticket_mismatch() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Create a key in Owner hierarchy
    let key_handle = 0x80000001;
    let (signer_obj, priv_bytes, priv_len) = create_transient_ecc_key(
        tpm.platform.crypto,
        key_handle,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    add_transient_object(&mut global_state, signer_obj.clone());

    let approved_policy = Tpm2bDigest::from_bytes(&[0; 32]).unwrap();
    let policy_ref = Tpm2bNonce::from_bytes(&[5, 6, 7, 8]).unwrap();

    // 1. We compute aHash = SHA256(approvedPolicy || policyRef)
    let mut a_hash_input = [0u8; 36];
    a_hash_input[..32].copy_from_slice(approved_policy.get_buffer());
    a_hash_input[32..36].copy_from_slice(policy_ref.get_buffer());
    let a_hash = sha256_bytes(&a_hash_input);

    // 2. We sign aHash using our ECC key
    let mut raw_sig = [0u8; 512];
    tpm.platform
        .crypto
        .sign_inner(
            tpm2::Alg::ECDSA,
            &priv_bytes[..priv_len],
            tpm2::TpmtHa::Sha256(&a_hash),
            &mut raw_sig,
        )
        .unwrap();

    let signature_r = tpm2::Tpm2bEccParameter::from_bytes(&raw_sig[..32]).unwrap();
    let signature_s = tpm2::Tpm2bEccParameter::from_bytes(&raw_sig[32..64]).unwrap();
    let signature = TpmtSignature::Ecdsa(TpmsSignatureEcc {
        hash: TpmiAlgHash::Sha256,
        signature_r,
        signature_s,
    });

    // 3. Call VerifySignature to get a verification ticket
    let vs_handles = VerifySignatureHandles {
        key_handle: Handle(key_handle),
    };
    let vs_cmd = VerifySignature {
        digest: Tpm2bDigest::from_bytes(&a_hash).unwrap(),
        signature,
    };
    let vs_rsp =
        execute_tpm_command_with_auths(&mut tpm, &mut global_state, &vs_handles, &vs_cmd, &[])
            .unwrap();

    // Verify the ticket returned by VerifySignature
    let check_ticket = vs_rsp.validation;
    assert_eq!(check_ticket.tag(), 0x8022);
    assert_eq!(check_ticket.hierarchy().0, 0x40000001); // RH_OWNER

    // 4. Set up the policy session and call PolicyAuthorize
    let session_handle = 0x03000001;
    let policy_session = SessionState {
        session_handle,
        session_type: Tpm2Se::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::from_bytes(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::from_bytes(&[1; 32]).unwrap()).into(),
        session_key: [0u8; 128],
        session_key_len: 0,
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
        policy_digest_len: 32,
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
    global_state.add_session(policy_session).unwrap();

    let handles = PolicyAuthorizeHandles {
        policy_session: Handle(session_handle),
    };
    let cmd = PolicyAuthorize {
        approved_policy,
        policy_ref,
        key_sign: signer_obj.name.as_tpm2b(),
        check_ticket,
    };

    // 5. This command SHOULD succeed because VerifySignature now correctly computes the HMAC ticket.
    let res = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &handles, &cmd, &[]);
    assert!(
        res.is_ok(),
        "Expected PolicyAuthorize to succeed, but it failed: {:?}",
        res.err()
    );
}

#[test]
fn test_policy_duplication_select_name_66_success() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let session_handle = 0x03000001;
    let policy_session = SessionState {
        session_handle,
        session_type: Tpm2Se::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::from_bytes(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::from_bytes(&[1; 32]).unwrap()).into(),
        session_key: [0u8; 128],
        session_key_len: 0,
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
        policy_digest_len: 32,
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
    global_state.add_session(policy_session).unwrap();

    let mut object_name_bytes = [0u8; 66];
    object_name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha512).id().to_be_bytes()); // SHA512
    let object_name = Tpm2bName::from_bytes(&object_name_bytes).unwrap();

    let mut parent_name_bytes = [0u8; 34];
    parent_name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes()); // SHA256
    let new_parent_name = Tpm2bName::from_bytes(&parent_name_bytes).unwrap();

    let handles = PolicyDuplicationSelectHandles {
        policy_session: Handle(session_handle),
    };
    let cmd = PolicyDuplicationSelect {
        object_name,
        new_parent_name,
        include_object: false,
    };

    let res = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &handles, &cmd, &[]);
    assert!(
        res.is_ok(),
        "Expected PolicyDuplicationSelect to succeed for 66-byte name with include_object=NO, but failed: {:?}",
        res.err()
    );
}

#[test]
fn test_policy_duplication_select_name_67_rejected() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let session_handle = 0x03000001;
    let policy_session = SessionState {
        session_handle,
        session_type: Tpm2Se::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::from_bytes(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::from_bytes(&[1; 32]).unwrap()).into(),
        session_key: [0u8; 128],
        session_key_len: 0,
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
        policy_digest_len: 32,
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
    global_state.add_session(policy_session).unwrap();

    // Construct raw byte stream for the command.
    let mut request_buf = [0u8; 256];
    request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes()); // Tag
    request_buf[6..10].copy_from_slice(&0x00000188u32.to_be_bytes()); // Command code TPM_CC_PolicyDuplicationSelect
    request_buf[10..14].copy_from_slice(&session_handle.to_be_bytes()); // Handle: policy_session

    let mut offset = 14;
    // object_name: size 67
    request_buf[offset..offset + 2].copy_from_slice(&67u16.to_be_bytes());
    offset += 2;
    // Fill first 2 bytes with SHA512 alg id, then rest dummy bytes
    request_buf[offset..offset + 2]
        .copy_from_slice(&Alg::from(TpmiAlgHash::Sha512).id().to_be_bytes());
    offset += 67;

    // new_parent_name: size 34
    request_buf[offset..offset + 2].copy_from_slice(&34u16.to_be_bytes());
    offset += 2;
    request_buf[offset..offset + 2]
        .copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    offset += 34;

    // include_object: false (0)
    request_buf[offset] = 0;
    offset += 1;

    // Fill total command length field
    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut response_buf = [0u8; 256];
    let resp_size = tpm.execute_command_separate(
        &mut global_state,
        &request_buf[..offset],
        &mut response_buf[..],
    );
    assert!(resp_size >= 10, "Response is too short: {}", resp_size);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_ne!(
        rc, 0,
        "Expected PolicyDuplicationSelect to fail, but it succeeded!"
    );

    // We expect 0x1D5 (TPM_RC_SIZE + TPM_RC_P + TPM_RC_1) because Tpm2bName max size is 66, so 67 bytes fails during request parameter 1 unmarshalling.
    assert_eq!(
        rc, 0x1D5,
        "Expected error code 0x1D5 (TPM_RC_SIZE + TPM_RC_P + TPM_RC_1), but got: 0x{:X}",
        rc
    );
}

#[test]
fn test_policy_duplication_select_name_66_include_object_yes_success() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let session_handle = 0x03000001;
    let policy_session = SessionState {
        session_handle,
        session_type: Tpm2Se::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::from_bytes(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::from_bytes(&[1; 32]).unwrap()).into(),
        session_key: [0u8; 128],
        session_key_len: 0,
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
        policy_digest_len: 32,
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
    global_state.add_session(policy_session).unwrap();

    let mut object_name_bytes = [0u8; 66];
    object_name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha512).id().to_be_bytes()); // SHA512
    let object_name = Tpm2bName::from_bytes(&object_name_bytes).unwrap();

    let mut parent_name_bytes = [0u8; 34];
    parent_name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes()); // SHA256
    let new_parent_name = Tpm2bName::from_bytes(&parent_name_bytes).unwrap();

    let handles = PolicyDuplicationSelectHandles {
        policy_session: Handle(session_handle),
    };
    let cmd = PolicyDuplicationSelect {
        object_name,
        new_parent_name,
        include_object: true,
    };

    let res = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &handles, &cmd, &[]);
    assert!(
        res.is_ok(),
        "Expected PolicyDuplicationSelect to succeed for 66-byte name with include_object=YES, but failed: {:?}",
        res.err()
    );
}
