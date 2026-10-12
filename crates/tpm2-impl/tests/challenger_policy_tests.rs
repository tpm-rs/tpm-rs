#![allow(deprecated)]

use common::marshal_to_slice;
use tpm2::Alg;
use tpm2::errors::{Position, TpmRc};

extern crate alloc;

mod common;

use common::{FakeStorage, FakeTimer, TestCryptoProvider};
use tpm2::commands::{
    Command, Message, PolicyAuthorize, PolicyDuplicationSelect, PolicySigned, UnmarshalMessage,
    VerifySignature,
};
use tpm2::crypto::{
    Ecc, EccPrivateKey, EccPublicKey, EccSigScheme, Random, Rsa, RsaPrivateKey, RsaPublicKey,
    RsaSigScheme, Signing,
};
use tpm2::{Handle, Marshal, Ticket, TpmCc, TpmEccCurve, TpmSt, TpmiRsaKeyBits};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bNonce, TpmSe as Tpm2Se, TpmaObject,
    TpmiAlgHash, TpmsAuthCommand, TpmsRsaParms, TpmsSignatureEcc, TpmsSignatureRsa, TpmtHa,
    TpmtPublic, TpmtSignature, TpmtTkVerified,
};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::{SessionState, TransientObject};
use tpm2_impl::owned::OwnedSensitiveComposite;

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    tpm2::crypto::hash(&TestCryptoProvider, TpmiAlgHash::Sha256, data, &mut out)
        .unwrap()
        .digest()
        .try_into()
        .unwrap()
}

fn setup_tpm<'a>(
    crypto: &'a mut TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
) -> (
    TpmEngine<'a, TestCryptoProvider, FakeStorage, FakeTimer>,
    tpm2_impl::GlobalState,
) {
    let rng = crypto.rng_seeded(b"challenger_policy_tests").unwrap();
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
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    C::Response<'static>: UnmarshalMessage<'static>,
{
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(C::CMD_CODE.code()).to_be_bytes());

    for h in cmd.handles().as_ref() {
        request_buf[offset..offset + 4].copy_from_slice(&h.0.to_be_bytes());
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

    offset += marshal_to_slice(cmd, &mut request_buf[offset..]);

    let total_len = u32::try_from(offset).unwrap();
    request_buf[2..6].copy_from_slice(&total_len.to_be_bytes());

    let mut response_buf = [0u8; 16384];
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut resp_offset = 10;
    let mut resp_handles = <<C::Response<'static> as Message>::Handles>::default();
    for h in resp_handles.as_mut() {
        *h = Handle(u32::from_be_bytes(
            response_buf[resp_offset..resp_offset + 4]
                .try_into()
                .unwrap(),
        ));
        resp_offset += 4;
    }

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    let params_end = if resp_tag == 0x8002 {
        let param_size = usize::try_from(u32::from_be_bytes(
            response_buf[resp_offset..resp_offset + 4]
                .try_into()
                .unwrap(),
        ))
        .unwrap();
        resp_offset += 4;
        resp_offset + param_size
    } else {
        resp_size
    };

    let mut unmarshal_buf: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..params_end].to_vec());
    let resp = <C::Response<'static>>::unmarshal_with_handles(resp_handles, &mut unmarshal_buf)
        .map_err(|_| TpmRc::FAILURE.get())?;
    Ok(resp)
}

fn compute_key_name(_crypto: &TestCryptoProvider, public: &TpmtPublic) -> Tpm2bName<'static> {
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(public, &mut buf);
    let digest = sha256_bytes(&buf[..len]);

    let mut name_bytes = [0u8; 34];
    name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    name_bytes[2..34].copy_from_slice(&digest);
    Tpm2bName::new(std::vec::Vec::leak(name_bytes[..34].to_vec())).unwrap()
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
) -> (TransientObject, <TestCryptoProvider as Ecc>::PrivateKey) {
    let mut rng = crypto.rng_seeded(b"ecc_key").unwrap();
    let priv_key = Ecc::generate_key(crypto, &mut rng, TpmEccCurve::NistP256).unwrap();

    let mut out_x = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let mut out_y = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let point = priv_key.public_key().point(&mut out_x, &mut out_y).unwrap();

    let mut out_s = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let scalar = priv_key.scalar(&mut out_s).unwrap();

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            tpm2::TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: TpmEccCurve::NistP256,
                kdf: None,
            },
            point,
        ),
    };
    let name = compute_key_name(crypto, &public);

    let obj = TransientObject {
        handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: name.into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        sensitive: OwnedSensitiveComposite::Ecc(scalar.into()),
        qualified_name: name.into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    (obj, priv_key)
}

fn create_transient_rsa_key(
    crypto: &TestCryptoProvider,
    handle: u32,
    attrs: TpmaObject,
) -> (TransientObject, <TestCryptoProvider as Rsa>::PrivateKey) {
    let mut rng = crypto.rng_seeded(b"rsa_key").unwrap();
    let priv_key = Rsa::generate_key(crypto, &mut rng, TpmiRsaKeyBits::Rsa2048, 0).unwrap();

    let mut out_n = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let modulus = priv_key.public_key().modulus(&mut out_n).unwrap();

    let mut out_p = [0u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES];
    let prime_p = priv_key.prime_p(&mut out_p).unwrap();

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: None,
                scheme: None,
                key_bits: TpmiRsaKeyBits::Rsa2048,
                exponent: 0,
            },
            modulus,
        ),
    };
    let name = compute_key_name(crypto, &public);

    let obj = TransientObject {
        handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: name.into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        sensitive: OwnedSensitiveComposite::Rsa(prime_p.into()),
        qualified_name: name.into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    (obj, priv_key)
}

#[test]
fn test_policy_signed_ecc_correctness() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer);

    let key_handle = 0x80000001;
    let (signer_obj, priv_key) = create_transient_ecc_key(
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
        nonce_tpm: (Tpm2bNonce::new(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::new(&[1; 32]).unwrap()).into(),
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
    };
    global_state.add_session(policy_session).unwrap();

    let nonce_tpm_input = Tpm2bNonce::new(&[2; 32]).unwrap();
    let expiration: i32 = -100;
    let policy_ref = Tpm2bNonce::new(&[5, 6, 7, 8]).unwrap();
    let cp_hash_a = Tpm2bDigest::default();

    // toBeSigned = nonceTPM (32) || expiration (4) || cpHashA (0) || policyRef (4)
    let mut to_be_signed = [0u8; 128];
    let mut offset = 0;
    to_be_signed[offset..offset + 32].copy_from_slice(nonce_tpm_input.as_ref());
    offset += 32;
    to_be_signed[offset..offset + 4].copy_from_slice(&expiration.to_be_bytes());
    offset += 4;
    let cp_len = cp_hash_a.as_ref().len();
    to_be_signed[offset..offset + cp_len].copy_from_slice(cp_hash_a.as_ref());
    offset += cp_len;
    let ref_len = policy_ref.as_ref().len();
    to_be_signed[offset..offset + ref_len].copy_from_slice(policy_ref.as_ref());
    offset += ref_len;

    let digest_to_sign = sha256_bytes(&to_be_signed[..offset]);

    let mut sign_rng = tpm.platform.crypto.rng_seeded(b"sign_ecc").unwrap();
    let mut out_r = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let mut out_s = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let (signature_r, signature_s) = Signing::ecc_sign(
        tpm.platform.crypto,
        &mut sign_rng,
        &priv_key,
        EccSigScheme::Ecdsa,
        TpmtHa::Sha256(&digest_to_sign),
        &mut out_r,
        &mut out_s,
    )
    .unwrap();

    let auth = TpmtSignature::Ecdsa(TpmsSignatureEcc {
        hash: TpmiAlgHash::Sha256,
        signature_r,
        signature_s,
    });

    let cmd = PolicySigned {
        auth_object: Handle(key_handle),
        policy_session: Handle(session_handle),
        nonce_tpm: nonce_tpm_input,
        cp_hash_a,
        policy_ref,
        expiration,
        auth,
    };

    let rsp = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &cmd, &[]).unwrap();

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
    expected_update2[32..36].copy_from_slice(policy_ref.as_ref());
    let expected_digest = sha256_bytes(&expected_update2);

    // Re-verify the updated policy digest in the session
    let final_session = global_state.session(session_handle).unwrap();
    assert_eq!(
        &final_session.policy_digest[..policy_digest_len],
        &expected_digest[..]
    );

    // Verify a ticket is returned because expiration < 0
    assert_eq!(rsp.policy_ticket.tag(), TpmSt::AUTH_SIGNED);
    assert!(!rsp.policy_ticket.digest().as_ref().is_empty());
}

#[test]
fn test_policy_signed_rsa_correctness() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer);

    let key_handle = 0x80000001;
    let (signer_obj, priv_key) = create_transient_rsa_key(
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
        nonce_tpm: (Tpm2bNonce::new(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::new(&[1; 32]).unwrap()).into(),
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
    };
    global_state.add_session(policy_session).unwrap();

    let nonce_tpm_input = Tpm2bNonce::new(&[2; 32]).unwrap();
    let expiration: i32 = 0; // No ticket
    let policy_ref = Tpm2bNonce::default();
    let cp_hash_a = Tpm2bDigest::default();

    // toBeSigned = nonceTPM (32) || expiration (4) || cpHashA (0) || policyRef (0)
    let mut to_be_signed = [0u8; 36];
    to_be_signed[..32].copy_from_slice(nonce_tpm_input.as_ref());
    to_be_signed[32..36].copy_from_slice(&expiration.to_be_bytes());

    let digest_to_sign = sha256_bytes(&to_be_signed);

    let mut sign_rng = tpm.platform.crypto.rng_seeded(b"sign_rsa").unwrap();
    let mut out_sig = [0u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES];
    let sig = Signing::rsa_sign(
        tpm.platform.crypto,
        &mut sign_rng,
        &priv_key,
        RsaSigScheme::Rsassa,
        TpmtHa::Sha256(&digest_to_sign),
        &mut out_sig,
    )
    .unwrap();

    let auth = TpmtSignature::Rsassa(TpmsSignatureRsa {
        hash: TpmiAlgHash::Sha256,
        sig,
    });

    let cmd = PolicySigned {
        auth_object: Handle(key_handle),
        policy_session: Handle(session_handle),
        nonce_tpm: nonce_tpm_input,
        cp_hash_a,
        policy_ref,
        expiration,
        auth,
    };

    let rsp = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &cmd, &[]).unwrap();

    // Verify session state is updated
    let (_policy_digest, policy_digest_len) = {
        let s = global_state.session(session_handle).unwrap();
        (s.policy_digest, s.policy_digest_len)
    };
    assert_ne!(policy_digest_len, 0);
    // Ticket should be empty because expiration is 0
    assert!(rsp.policy_ticket.digest().as_ref().is_empty());
}

#[test]
fn test_policy_signed_incorrect_signature_fails() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer);

    let key_handle = 0x80000001;
    let (signer_obj, _priv_key) = create_transient_ecc_key(
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
        nonce_tpm: (Tpm2bNonce::new(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::new(&[1; 32]).unwrap()).into(),
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
    };
    global_state.add_session(policy_session).unwrap();

    // Use a completely incorrect signature
    let signature_r = tpm2::Tpm2bEccParameter::new(&[0x99; 32]).unwrap();
    let signature_s = tpm2::Tpm2bEccParameter::new(&[0x99; 32]).unwrap();
    let auth = TpmtSignature::Ecdsa(TpmsSignatureEcc {
        hash: TpmiAlgHash::Sha256,
        signature_r,
        signature_s,
    });

    let cmd = PolicySigned {
        auth_object: Handle(key_handle),
        policy_session: Handle(session_handle),
        nonce_tpm: Tpm2bNonce::new(&[2; 32]).unwrap(),
        cp_hash_a: Tpm2bDigest::default(),
        policy_ref: Tpm2bNonce::default(),
        expiration: 0,
        auth,
    };

    let res = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &cmd, &[]);
    // Should fail with a signature/parameter verification error
    assert!(res.is_err());
}

#[test]
fn test_policy_authorize_rh_null_bypass_vulnerability() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer);

    let session_handle = 0x03000001;
    let policy_session = SessionState {
        session_handle,
        session_type: Tpm2Se::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::new(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::new(&[1; 32]).unwrap()).into(),
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
    };
    global_state.add_session(policy_session).unwrap();

    let approved_policy = Tpm2bDigest::new(&[0; 32]).unwrap();
    let policy_ref = Tpm2bNonce::new(&[5, 6, 7, 8]).unwrap();

    let mut key_sign_bytes = [0u8; 34];
    key_sign_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    key_sign_bytes[2..34].copy_from_slice(&[0x11; 32]);
    let key_sign = Tpm2bName::new(&key_sign_bytes).unwrap();

    // Normally we need a signature from key_sign. But we use a ticket with RH_NULL (0x40000007).
    // Because the hierarchy is RH_NULL, the proof_len is 0 (empty proof).
    // The HMAC is computed over: 0x8022 (2 bytes) || aHash (32 bytes) || keySign name (34 bytes)
    // aHash = SHA256(approvedPolicy || policyRef)
    let mut a_hash_input = [0u8; 36];
    a_hash_input[..32].copy_from_slice(approved_policy.as_ref());
    a_hash_input[32..36].copy_from_slice(policy_ref.as_ref());
    let a_hash = sha256_bytes(&a_hash_input);

    let mut hmac_input = [0u8; 256];
    let mut offset = 0;
    hmac_input[offset..offset + 2].copy_from_slice(&0x8022u16.to_be_bytes());
    offset += 2;
    hmac_input[offset..offset + 32].copy_from_slice(&a_hash);
    offset += 32;
    let ks_len = key_sign.as_ref().len();
    hmac_input[offset..offset + ks_len].copy_from_slice(key_sign.as_ref());
    offset += ks_len;

    // Since proof is empty for RH_NULL, the HMAC is calculated using empty key
    let mut hmac_buf = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let computed_hmac = tpm2::crypto::hmac(
        tpm.platform.crypto,
        TpmiAlgHash::Sha256,
        &[],
        &hmac_input[..offset],
        &mut hmac_buf,
    )
    .unwrap();

    let check_ticket = TpmtTkVerified::Verified(
        Handle(0x40000007),
        Tpm2bDigest::new(computed_hmac.digest()).unwrap(),
    );

    let cmd = PolicyAuthorize {
        policy_session: Handle(session_handle),
        approved_policy,
        policy_ref,
        key_sign,
        check_ticket,
    };

    // Execute PolicyAuthorize. It should fail because the ticket uses an empty key but the TPM uses the random null_proof!
    let res = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &cmd, &[]);
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
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer);

    // Create a key in Owner hierarchy
    let key_handle = 0x80000001;
    let (signer_obj, priv_key) = create_transient_ecc_key(
        tpm.platform.crypto,
        key_handle,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    add_transient_object(&mut global_state, signer_obj.clone());

    let approved_policy = Tpm2bDigest::new(&[0; 32]).unwrap();
    let policy_ref = Tpm2bNonce::new(&[5, 6, 7, 8]).unwrap();

    // 1. We compute aHash = SHA256(approvedPolicy || policyRef)
    let mut a_hash_input = [0u8; 36];
    a_hash_input[..32].copy_from_slice(approved_policy.as_ref());
    a_hash_input[32..36].copy_from_slice(policy_ref.as_ref());
    let a_hash = sha256_bytes(&a_hash_input);

    // 2. We sign aHash using our ECC key
    let mut sign_rng = tpm.platform.crypto.rng_seeded(b"sign_auth").unwrap();
    let mut out_r = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let mut out_s = [0u8; TpmEccCurve::MAX_ECC_KEY_BYTES];
    let (signature_r, signature_s) = Signing::ecc_sign(
        tpm.platform.crypto,
        &mut sign_rng,
        &priv_key,
        EccSigScheme::Ecdsa,
        TpmtHa::Sha256(&a_hash),
        &mut out_r,
        &mut out_s,
    )
    .unwrap();
    let signature = TpmtSignature::Ecdsa(TpmsSignatureEcc {
        hash: TpmiAlgHash::Sha256,
        signature_r,
        signature_s,
    });

    // 3. Call VerifySignature to get a verification ticket
    let vs_cmd = VerifySignature {
        key_handle: Handle(key_handle),
        digest: Tpm2bDigest::new(&a_hash).unwrap(),
        signature,
    };
    let vs_rsp = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &vs_cmd, &[]).unwrap();

    // Verify the ticket returned by VerifySignature
    let check_ticket = vs_rsp.validation;
    assert_eq!(check_ticket.tag(), TpmSt::VERIFIED);
    assert_eq!(check_ticket.hierarchy().0, 0x40000001); // RH_OWNER

    // 4. Set up the policy session and call PolicyAuthorize
    let session_handle = 0x03000001;
    let policy_session = SessionState {
        session_handle,
        session_type: Tpm2Se::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::new(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::new(&[1; 32]).unwrap()).into(),
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
    };
    global_state.add_session(policy_session).unwrap();

    let cmd = PolicyAuthorize {
        policy_session: Handle(session_handle),
        approved_policy,
        policy_ref,
        key_sign: signer_obj.name.as_tpm2b(),
        check_ticket,
    };

    // 5. This command SHOULD succeed because VerifySignature now correctly computes the HMAC ticket.
    let res = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &cmd, &[]);
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
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer);

    let session_handle = 0x03000001;
    let policy_session = SessionState {
        session_handle,
        session_type: Tpm2Se::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::new(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::new(&[1; 32]).unwrap()).into(),
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
    };
    global_state.add_session(policy_session).unwrap();

    let mut object_name_bytes = [0u8; 66];
    object_name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha512).id().to_be_bytes()); // SHA512
    let object_name = Tpm2bName::new(&object_name_bytes).unwrap();

    let mut parent_name_bytes = [0u8; 34];
    parent_name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes()); // SHA256
    let new_parent_name = Tpm2bName::new(&parent_name_bytes).unwrap();

    let cmd = PolicyDuplicationSelect {
        policy_session: Handle(session_handle),
        object_name,
        new_parent_name,
        include_object: false,
    };

    let res = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &cmd, &[]);
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
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer);

    let session_handle = 0x03000001;
    let policy_session = SessionState {
        session_handle,
        session_type: Tpm2Se::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::new(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::new(&[1; 32]).unwrap()).into(),
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
    let total_len = u32::try_from(offset).unwrap();
    request_buf[2..6].copy_from_slice(&total_len.to_be_bytes());

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
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer);

    let session_handle = 0x03000001;
    let policy_session = SessionState {
        session_handle,
        session_type: Tpm2Se::Policy,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::new(&[2; 32]).unwrap()).into(),
        nonce_caller: (Tpm2bNonce::new(&[1; 32]).unwrap()).into(),
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
    };
    global_state.add_session(policy_session).unwrap();

    let mut object_name_bytes = [0u8; 66];
    object_name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha512).id().to_be_bytes()); // SHA512
    let object_name = Tpm2bName::new(&object_name_bytes).unwrap();

    let mut parent_name_bytes = [0u8; 34];
    parent_name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes()); // SHA256
    let new_parent_name = Tpm2bName::new(&parent_name_bytes).unwrap();

    let cmd = PolicyDuplicationSelect {
        policy_session: Handle(session_handle),
        object_name,
        new_parent_name,
        include_object: true,
    };

    let res = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &cmd, &[]);
    assert!(
        res.is_ok(),
        "Expected PolicyDuplicationSelect to succeed for 66-byte name with include_object=YES, but failed: {:?}",
        res.err()
    );
}
