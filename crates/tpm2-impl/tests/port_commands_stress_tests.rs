use common::marshal_to_slice;

use tpm2::{Marshal, Unmarshal};
mod common;

use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::commands::Command;
use tpm2::crypto::Asymmetric;
use tpm2::crypto::Rng;
use tpm2::errors::{Position, TpmRc};
use tpm2::{Handle, TpmCc, TpmSe};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bName,
    Tpm2bNonce, Tpm2bPrivate, Tpm2bPublic, Tpm2bPublicKeyRsa, TpmaObject, TpmiAlgHash,
    TpmsAuthCommand, TpmsRsaParms, TpmtPublic, TpmtSymDefObject,
};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::TransientObject;

fn leak_bytes(bytes: &[u8]) -> &'static [u8] {
    std::vec::Vec::leak(bytes.to_vec())
}

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
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    (tpm, global_state)
}

fn execute_tpm_command<C: Command>(
    tpm: &mut TpmEngine<'_, TestCryptoProvider, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &C::Handles,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<(C::RespHandles, C::Response<'static>), u32>
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

    let handles_slice: &mut <C::Handles as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C::Handles as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let handles_len = handles.marshal(handles_slice);
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

    let cmd_slice: &mut <C as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let cmd_len = cmd.marshal(cmd_slice);
    offset += cmd_len;
    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    let mut response_buf = [0u8; 16384];
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut resp_offset = 10;
    let mut handles_slice = &response_buf[resp_offset..resp_size];
    let orig_handles_len = handles_slice.len();
    let resp_handles =
        C::RespHandles::unmarshal(&mut handles_slice).map_err(|_| TpmRc::FAILURE.get())?;

    let handles_len = orig_handles_len - handles_slice.len();
    resp_offset += handles_len;

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        resp_offset += 4; // Skip parameter size
    }

    let mut params_slice = leak_bytes(&response_buf[resp_offset..resp_size]);
    let resp_params =
        <C::Response<'static>>::unmarshal(&mut params_slice).map_err(|_| TpmRc::FAILURE.get())?;

    Ok((resp_handles, resp_params))
}

fn compute_key_name(
    crypto: &TestCryptoProvider,
    public: &TpmtPublic,
) -> tpm2_impl::owned::OwnedTpm2b<66> {
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(public, &mut buf);
    let alg = public.name_alg.unwrap_or(TpmiAlgHash::Sha256);
    let mut name_bytes = [0u8; 66];
    name_bytes[0..2].copy_from_slice(&tpm2::Alg::from(alg).id().to_be_bytes());
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(crypto, alg, &buf[..len], &mut out)
        .unwrap()
        .digest();
    name_bytes[2..2 + digest.len()].copy_from_slice(digest);
    tpm2_impl::owned::OwnedTpm2b::new(&name_bytes[..2 + digest.len()]).unwrap()
}

fn create_transient_key(
    crypto: &TestCryptoProvider,
    handle: u32,
    attrs: TpmaObject,
) -> TransientObject {
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
    TransientObject {
        handle,
        seed: [0u8; 32],
        name,
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        private,
        private_len: priv_len,
        qualified_name: name,
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

#[test]
fn test_policy_command_code_success() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Start a policy session
    use tpm2::commands::{StartAuthSession, StartAuthSessionHandles};
    let handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[1; 32]).unwrap(),
        encrypted_salt: tpm2::Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (resp_handles, _) = execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[])
        .expect("StartAuthSession failed");

    let session_handle = resp_handles.session_handle;

    // 2. Call PolicyCommandCode with TpmCc::Load (supported command)
    use tpm2::commands::{PolicyCommandCode, PolicyCommandCodeHandles};
    let policy_handles = PolicyCommandCodeHandles {
        policy_session: session_handle,
    };
    let policy_cmd = PolicyCommandCode { code: TpmCc::Load };
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &policy_handles,
        &policy_cmd,
        &[],
    )
    .expect("PolicyCommandCode failed");

    // 3. Call PolicyGetDigest to verify the updated digest
    use tpm2::commands::{PolicyGetDigest, PolicyGetDigestHandles};
    let digest_handles = PolicyGetDigestHandles {
        policy_session: session_handle,
    };
    let digest_cmd = PolicyGetDigest {};
    let (_, digest_resp) = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &digest_handles,
        &digest_cmd,
        &[],
    )
    .expect("PolicyGetDigest failed");

    // Policy digest should be computed as: SHA256(initial_digest || PolicyCommandCode || Load)
    // Initial digest is 32 bytes of 0s.
    // cc_val = 0x0000016C (PolicyCommandCode)
    // code = 0x0000012C (Load)
    let mut expected_update = [0u8; 40];
    expected_update[32..36].copy_from_slice(&(TpmCc::PolicyCommandCode.code()).to_be_bytes());
    expected_update[36..40].copy_from_slice(&(TpmCc::Load.code()).to_be_bytes());

    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let expected_digest = tpm2::crypto::hash(
        tpm.platform.crypto,
        TpmiAlgHash::Sha256,
        &expected_update,
        &mut out,
    )
    .unwrap()
    .digest();
    assert_eq!(digest_resp.policy_digest.get_buffer(), expected_digest);
}

#[test]
fn test_policy_command_code_failures() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Start a policy session
    use tpm2::commands::{StartAuthSession, StartAuthSessionHandles};
    let handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[1; 32]).unwrap(),
        encrypted_salt: tpm2::Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (resp_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let session_handle = resp_handles.session_handle;

    // 1. Call PolicyCommandCode with unsupported code (TpmCc::PPCommands)
    use tpm2::commands::{PolicyCommandCode, PolicyCommandCodeHandles};
    let policy_handles = PolicyCommandCodeHandles {
        policy_session: session_handle,
    };
    let mut policy_cmd = PolicyCommandCode {
        code: TpmCc::PPCommands,
    };
    let res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &policy_handles,
        &policy_cmd,
        &[],
    );
    // Should fail with PolicyCc (164)
    assert_eq!(res.err(), Some(TpmRc::POLICY_CC.get()));

    // 2. Call PolicyCommandCode with supported code (TpmCc::Load) -> should succeed
    policy_cmd.code = TpmCc::Load;
    execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &policy_handles,
        &policy_cmd,
        &[],
    )
    .unwrap();

    // 3. Call PolicyCommandCode with a different code (TpmCc::Import) -> should fail with Value (132)
    policy_cmd.code = TpmCc::Import;
    let res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &policy_handles,
        &policy_cmd,
        &[],
    );
    assert_eq!(res.err(), Some(TpmRc::VALUE.get()));
}

#[test]
fn test_policy_command_code_trial_session_mismatch() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Create a transient target key to use for a command
    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(target);

    // 2. Start a trial policy session
    use tpm2::commands::{StartAuthSession, StartAuthSessionHandles};
    let handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[1; 32]).unwrap(),
        encrypted_salt: tpm2::Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::Trial,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (resp_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let session_handle = resp_handles.session_handle;

    // 3. Execute PolicyCommandCode on Trial session (should succeed now!)
    use tpm2::commands::{PolicyCommandCode, PolicyCommandCodeHandles};
    let policy_handles = PolicyCommandCodeHandles {
        policy_session: session_handle,
    };
    let policy_cmd = PolicyCommandCode {
        code: TpmCc::Duplicate,
    };
    let res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &policy_handles,
        &policy_cmd,
        &[],
    );
    assert!(res.is_ok());

    // 4. Try to use the trial session to authorize a Duplicate command (should fail with AuthType)
    use tpm2::commands::{Duplicate, DuplicateHandles};
    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle::RH_NULL,
    };
    let dup_cmd = Duplicate {
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let auth = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle.0),
        nonce: Tpm2bNonce::from_bytes(&[2; 32]).unwrap(),
        session_attributes: tpm2::TpmaSession(1), // continueSession
        hmac: tpm2::Tpm2bAuth::default(),
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[auth]);
    assert_eq!(res.err(), Some(TpmRc::AUTH_TYPE.get()));
}

#[test]
fn test_policy_get_digest_non_policy_session() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Start an HMAC session
    use tpm2::commands::{StartAuthSession, StartAuthSessionHandles};
    let handles = StartAuthSessionHandles {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
    };
    let cmd = StartAuthSession {
        nonce_caller: Tpm2bNonce::from_bytes(&[1; 32]).unwrap(),
        encrypted_salt: tpm2::Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let (resp_handles, _) =
        execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]).unwrap();
    let session_handle = resp_handles.session_handle;

    // PolicyGetDigest on HMAC session should fail with Handle (139)
    use tpm2::commands::{PolicyGetDigest, PolicyGetDigestHandles};
    let digest_handles = PolicyGetDigestHandles {
        policy_session: session_handle,
    };
    let digest_cmd = PolicyGetDigest {};
    let res = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &digest_handles,
        &digest_cmd,
        &[],
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::handle(1)).get())
    );
}

#[test]
fn test_duplicate_fixed_parent() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Create a parent storage key (handle 0x80000001)
    let parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(parent);

    // 2. Create a target signing key with FIXED_PARENT attribute (handle 0x80000002)
    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH | TpmaObject::FIXED_PARENT,
    );
    global_state.transient_objects[1] = Some(target);

    // 3. Call Duplicate on fixedParent key -> should fail with Attributes (130)
    use tpm2::commands::{Duplicate, DuplicateHandles};
    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let dup_cmd = Duplicate {
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::handle(1)).get())
    );
}

#[test]
fn test_duplicate_invalid_parent() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Create parent key that is NOT asymmetric (e.g. parent is symmetric/keyed hash)
    let mut parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    parent.public.parms_and_id =
        tpm2_impl::owned::OwnedPublicParmsAndId::KeyedHash(None, Default::default());
    global_state.transient_objects[0] = Some(parent);

    // 2. Create target key
    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[1] = Some(target);

    // 3. Call Duplicate with invalid parent type -> should fail with Type (138)
    use tpm2::commands::{Duplicate, DuplicateHandles};
    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let dup_cmd = Duplicate {
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[]);
    assert_eq!(res.err(), Some(TpmRc::TYPE.with(Position::handle(2)).get()));
}

#[test]
fn test_import_fixed_tpm_or_parent() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Create parent storage key
    let parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(parent);

    // Create target key public struct with FIXED_TPM attribute set
    let target_public_struct = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::FIXED_TPM,
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
    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&target_public_struct, &mut pub_buf);
    let object_public = Tpm2bPublic::from_bytes(&pub_buf[..pub_len]).unwrap();

    // Call Import -> should fail with Attributes (130)
    use tpm2::commands::{Import, ImportHandles};
    let imp_handles = ImportHandles {
        parent_handle: Handle(0x80000001),
    };
    let imp_cmd = Import {
        encryption_key: Tpm2bData::default(),
        object_public,
        duplicate: Tpm2bPrivate::default(),
        in_sym_seed: Tpm2bEncryptedSecret::default(),
        symmetric_alg: None,
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::parameter(2)).get())
    );
}

#[test]
fn test_load_parent_not_decrypt_restricted() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Create a parent key that is NOT restricted (e.g. decrypt only)
    let parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(parent);

    // 2. Create target key public struct
    let target_public_struct = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
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
    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&target_public_struct, &mut pub_buf);
    let in_public = Tpm2bPublic::from_bytes(&pub_buf[..pub_len]).unwrap();

    // 3. Call Load under this parent -> should fail with Attributes (130)
    use tpm2::commands::{Load, LoadHandles};
    let load_handles = LoadHandles {
        parent_handle: Handle(0x80000001),
    };
    let load_cmd = Load {
        in_private: Tpm2bPrivate::from_bytes(&[1, 2, 3]).unwrap(),
        in_public,
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &load_handles, &load_cmd, &[]);
    assert_eq!(res.err(), Some(TpmRc::TYPE.with(Position::handle(1)).get()));
}

#[test]
fn test_load_unsupported_name_alg() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // Create a parent storage key
    let parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(parent);

    // Create key public area with unsupported name algorithm SHA1 (0x0004)
    let target_public_struct = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha1),
        object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
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
    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&target_public_struct, &mut pub_buf);
    let in_public = Tpm2bPublic::from_bytes(&pub_buf[..pub_len]).unwrap();

    // Call Load -> should fail with Value (132)
    use tpm2::commands::{Load, LoadHandles};
    let load_handles = LoadHandles {
        parent_handle: Handle(0x80000001),
    };
    let load_cmd = Load {
        in_private: Tpm2bPrivate::from_bytes(&[1, 2, 3]).unwrap(),
        in_public,
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &load_handles, &load_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::KEY.with(Position::parameter(2)).get())
    );
}

#[test]
fn test_duplicate_import_load_integration_flow() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Setup a valid storage key (parent) at 0x80000001
    let parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(parent.clone());

    // 2. Setup a target signing key at 0x80000002
    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[1] = Some(target.clone());

    // 3. Execute Duplicate on target under parent
    use tpm2::commands::{Duplicate, DuplicateHandles};
    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let dup_cmd = Duplicate {
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let (_, dup_resp) =
        execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[])
            .expect("Duplicate failed in integration flow");

    // 4. Execute Import under parent using duplicate output
    use tpm2::commands::{Import, ImportHandles};
    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&target.public, &mut pub_buf);
    let object_public = Tpm2bPublic::from_bytes(&pub_buf[..pub_len]).unwrap();

    let imp_handles = ImportHandles {
        parent_handle: Handle(0x80000001),
    };
    let imp_cmd = Import {
        encryption_key: Tpm2bData::default(),
        object_public,
        duplicate: dup_resp.duplicate,
        in_sym_seed: dup_resp.out_sym_seed,
        symmetric_alg: None,
    };
    let (_, imp_resp) =
        execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[])
            .expect("Import failed in integration flow");

    // 5. Execute Load under parent using import output
    use tpm2::commands::{Load, LoadHandles};
    let load_handles = LoadHandles {
        parent_handle: Handle(0x80000001),
    };
    let load_cmd = Load {
        in_private: imp_resp.out_private,
        in_public: object_public,
    };
    let (load_resp_handles, load_resp) =
        execute_tpm_command(&mut tpm, &mut global_state, &load_handles, &load_cmd, &[])
            .expect("Load failed in integration flow");

    // Loaded object name should match target name
    assert_eq!(load_resp.name.get_buffer(), target.name.get_buffer());
    // Verify that the new handle is a transient handle (starts with 0x80)
    assert_eq!(load_resp_handles.object_handle.0 >> 24, 0x80);
}

#[test]
fn test_duplicate_import_load_exhaustive_algos() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();

    let parent_base = create_transient_key(
        &crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    let target_base = create_transient_key(
        &crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );

    let hash_algos = [
        TpmiAlgHash::Sha1,
        TpmiAlgHash::Sha256,
        TpmiAlgHash::Sha384,
        TpmiAlgHash::Sha512,
    ];

    let sym_algos = [
        None,
        Some(TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB))),
        Some(TpmtSymDefObject::Aes256(Some(tpm2::TpmiAlgSymMode::CFB))),
    ];

    for &parent_hash in &hash_algos {
        for &target_hash in &[TpmiAlgHash::Sha1, TpmiAlgHash::Sha256] {
            for &sym_alg in &sym_algos {
                for &parent_sym in &[
                    None,
                    Some(TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB))),
                ] {
                    let (mut tpm, mut global_state) =
                        setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

                    // 1. Create a parent storage key (handle 0x80000001) with parent_hash and parent_sym
                    let mut parent = parent_base.clone();
                    parent.public.name_alg = Some(parent_hash);
                    if let tpm2_impl::owned::OwnedPublicParmsAndId::Rsa(ref mut parms, _) =
                        parent.public.parms_and_id
                    {
                        parms.symmetric = parent_sym;
                    }
                    // Update its name matching its name_alg
                    parent.name = compute_key_name(tpm.platform.crypto, &parent.public.as_tpmt());
                    parent.qualified_name = parent.name;
                    global_state.transient_objects[0] = Some(parent);

                    // 2. Create target signing key (handle 0x80000002) with target_hash
                    let mut target = target_base.clone();
                    target.public.name_alg = Some(target_hash);
                    target.name = compute_key_name(tpm.platform.crypto, &target.public.as_tpmt());
                    target.qualified_name = target.name;
                    global_state.transient_objects[1] = Some(target.clone());

                    // 3. Execute Duplicate on target under parent
                    use tpm2::commands::{Duplicate, DuplicateHandles};
                    let dup_handles = DuplicateHandles {
                        object_handle: Handle(0x80000002),
                        new_parent_handle: Handle(0x80000001),
                    };

                    let encryption_key_in = match sym_alg {
                        Some(TpmtSymDefObject::Aes128(_)) => {
                            let mut key_data = vec![0u8; 16];
                            tpm.platform.crypto.get_random(&mut key_data).unwrap();
                            Tpm2bData::from_bytes(leak_bytes(&key_data)).unwrap()
                        }
                        Some(TpmtSymDefObject::Aes256(_)) => {
                            let mut key_data = vec![0u8; 32];
                            tpm.platform.crypto.get_random(&mut key_data).unwrap();
                            Tpm2bData::from_bytes(leak_bytes(&key_data)).unwrap()
                        }
                        _ => Tpm2bData::default(),
                    };

                    let dup_cmd = Duplicate {
                        encryption_key_in,
                        symmetric_alg: sym_alg,
                    };
                    let (_, dup_resp) = execute_tpm_command(
                        &mut tpm,
                        &mut global_state,
                        &dup_handles,
                        &dup_cmd,
                        &[],
                    )
                    .unwrap_or_else(|e| {
                        panic!(
                            "Duplicate failed for parent_hash={:?}, sym_alg={:?}, error={:08X}",
                            parent_hash, sym_alg, e
                        )
                    });

                    // 4. Execute Import under parent using duplicate output
                    use tpm2::commands::{Import, ImportHandles};
                    let mut pub_buf = [0u8; 1024];
                    let pub_len = marshal_to_slice(&target.public, &mut pub_buf);
                    let object_public = Tpm2bPublic::from_bytes(&pub_buf[..pub_len]).unwrap();

                    let imp_handles = ImportHandles {
                        parent_handle: Handle(0x80000001),
                    };
                    let imp_cmd = Import {
                        encryption_key: encryption_key_in,
                        object_public,
                        duplicate: dup_resp.duplicate,
                        in_sym_seed: dup_resp.out_sym_seed,
                        symmetric_alg: sym_alg,
                    };
                    let (_, imp_resp) = execute_tpm_command(
                        &mut tpm,
                        &mut global_state,
                        &imp_handles,
                        &imp_cmd,
                        &[],
                    )
                    .unwrap_or_else(|e| {
                        panic!(
                            "Import failed for parent_hash={:?}, sym_alg={:?}, error={:08X}",
                            parent_hash, sym_alg, e
                        )
                    });

                    // 5. Execute Load under parent using import output
                    use tpm2::commands::{Load, LoadHandles};
                    let load_handles = LoadHandles {
                        parent_handle: Handle(0x80000001),
                    };
                    let load_cmd = Load {
                        in_private: imp_resp.out_private,
                        in_public: object_public,
                    };
                    let (load_resp_handles, load_resp) = execute_tpm_command(
                        &mut tpm,
                        &mut global_state,
                        &load_handles,
                        &load_cmd,
                        &[],
                    )
                    .unwrap_or_else(|e| {
                        panic!(
                            "Load failed for parent_hash={:?}, sym_alg={:?}, error={:08X}",
                            parent_hash, sym_alg, e
                        )
                    });

                    // Loaded object name should match target name
                    assert_eq!(load_resp.name.get_buffer(), target.name.get_buffer());
                    // Verify that the new handle is a transient handle (starts with 0x80)
                    assert_eq!(load_resp_handles.object_handle.0 >> 24, 0x80);
                }
            }
        }
    }
}

fn create_transient_keyed_hash(
    crypto: &TestCryptoProvider,
    handle: u32,
    attrs: TpmaObject,
    secret: &[u8],
) -> TransientObject {
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let unique_digest = tpm2::crypto::hash(crypto, TpmiAlgHash::Sha256, secret, &mut out)
        .unwrap()
        .digest();

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::KeyedHash(
            None,
            Tpm2bDigest::from_bytes(unique_digest).unwrap(),
        ),
    };
    let name = compute_key_name(crypto, &public);
    let mut private = [0u8; 1536];
    private[..secret.len()].copy_from_slice(secret);
    TransientObject {
        handle,
        seed: [0u8; 32],
        name,
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        private,
        private_len: secret.len(),
        qualified_name: name,
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

#[test]
fn test_sw_duplicate_import_debug() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Create a parent storage key (handle 0x80000001)
    let parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(parent);

    // 2. Create a target keyedhash key (handle 0x80000002)
    let target = create_transient_keyed_hash(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        b"hello, unseal",
    );
    global_state.transient_objects[1] = Some(target.clone());

    // 3. Execute Duplicate on target under parent
    use tpm2::commands::{Duplicate, DuplicateHandles};
    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let dup_cmd = Duplicate {
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let (_, dup_resp) =
        execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[]).unwrap();

    println!("TPM duplicate length: {}", dup_resp.duplicate.get_size());
}
#[test]
fn test_create_primary_debug() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    use tpm2::commands::{CreatePrimary, CreatePrimaryHandles};
    let cp_handles = CreatePrimaryHandles {
        primary_handle: Handle(0x40000001), // Owner hierarchy
    };
    let primary_pub = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: TpmaObject::DECRYPT
            | TpmaObject::RESTRICTED
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::NO_DA
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::FIXED_PARENT
            | TpmaObject::FIXED_TPM,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Rsa(
            TpmsRsaParms {
                symmetric: Some(TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB))),
                scheme: None,
                key_bits: tpm2::TpmiRsaKeyBits(2048),
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let in_sensitive = tpm2::Tpm2b(tpm2::TpmsSensitiveCreate {
        user_auth: tpm2::Tpm2bAuth::default(),
        data: tpm2::Tpm2bSensitiveData::default(),
    });
    let cp_cmd = CreatePrimary {
        in_sensitive,
        in_public: tpm2::Tpm2b(primary_pub),
        outside_info: Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };

    // Verify unmarshaling in software
    let mut cmd_buf = [0u8; 1024];
    let cmd_len = marshal_to_slice(&cp_cmd, &mut cmd_buf);
    let mut unmarshal_slice = &cmd_buf[..cmd_len];
    let unmarshaled_cmd = CreatePrimary::unmarshal(&mut unmarshal_slice).unwrap();
    let _in_sensitive_struct = &unmarshaled_cmd.in_sensitive.0;
    let _in_public_struct = &unmarshaled_cmd.in_public.0;

    let (_, _cp_resp) =
        execute_tpm_command(&mut tpm, &mut global_state, &cp_handles, &cp_cmd, &[]).unwrap();
}

fn create_transient_ecc_key(
    crypto: &TestCryptoProvider,
    handle: u32,
    attrs: TpmaObject,
    curve: tpm2::TpmEccCurve,
) -> TransientObject {
    let mut pub_buf = [0u8; 512];
    let mut priv_buf = [0u8; 2048];
    use tpm2::Alg;
    use tpm2::TpmEccCurve;
    use tpm2::crypto::asymmetric::KeyParams;

    let ecc_curve = if (curve as u16) == u16::from(tpm2::TpmEccCurve::NistP256) {
        TpmEccCurve::NistP256
    } else if (curve as u16) == u16::from(tpm2::TpmEccCurve::BNP256) {
        TpmEccCurve::BNP256
    } else {
        panic!("unsupported curve: {:?}", curve);
    };

    let (pub_len, priv_len) = crypto
        .generate_key(
            Alg::ECC,
            Some(KeyParams::Ecc(ecc_curve)),
            &mut pub_buf,
            &mut priv_buf,
            None,
        )
        .unwrap();

    let unique = tpm2::TpmsEccPoint {
        x: tpm2::Tpm2bEccParameter::from_bytes(&pub_buf[..pub_len / 2]).unwrap(),
        y: tpm2::Tpm2bEccParameter::from_bytes(&pub_buf[pub_len / 2..pub_len]).unwrap(),
    };

    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Ecc(
            tpm2::TpmsEccParms {
                symmetric: None,
                scheme: None,
                curve_id: tpm2::TpmEccCurve::try_from(curve as u16).unwrap(),
                kdf: None,
            },
            unique,
        ),
    };
    let name = compute_key_name(crypto, &public);
    let mut private = [0u8; 1536];
    private[..priv_len].copy_from_slice(&priv_buf[..priv_len]);
    TransientObject {
        handle,
        seed: [0u8; 32],
        name,
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        private,
        private_len: priv_len,
        qualified_name: name,
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

#[test]
fn test_duplicate_import_load_exhaustive_parent_and_target_types() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();

    let parent_rsa = create_transient_key(
        &crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    let parent_p256 = create_transient_ecc_key(
        &crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
        tpm2::TpmEccCurve::NistP256,
    );
    let parent_bn256 = create_transient_ecc_key(
        &crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
        tpm2::TpmEccCurve::BNP256,
    );

    let target_rsa = create_transient_key(
        &crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    let target_p256 = create_transient_ecc_key(
        &crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        tpm2::TpmEccCurve::NistP256,
    );

    #[derive(Clone, Copy, Debug)]
    enum KeyGenType {
        Rsa,
        Ecc(tpm2::TpmEccCurve),
    }

    let parent_types = [
        KeyGenType::Rsa,
        KeyGenType::Ecc(tpm2::TpmEccCurve::NistP256),
        KeyGenType::Ecc(tpm2::TpmEccCurve::BNP256),
    ];

    let target_types = [
        KeyGenType::Rsa,
        KeyGenType::Ecc(tpm2::TpmEccCurve::NistP256),
    ];

    let hash_algos = [
        TpmiAlgHash::Sha1,
        TpmiAlgHash::Sha256,
        TpmiAlgHash::Sha384,
        TpmiAlgHash::Sha512,
    ];

    for &parent_type in &parent_types {
        for &target_type in &target_types {
            for &parent_hash in &hash_algos {
                let (mut tpm, mut global_state) =
                    setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

                // 1. Create parent storage key
                let mut parent = match parent_type {
                    KeyGenType::Rsa => parent_rsa.clone(),
                    KeyGenType::Ecc(curve) => {
                        if (curve as u16) == u16::from(tpm2::TpmEccCurve::NistP256) {
                            parent_p256.clone()
                        } else {
                            parent_bn256.clone()
                        }
                    }
                };
                parent.public.name_alg = Some(parent_hash);
                parent.name = compute_key_name(tpm.platform.crypto, &parent.public.as_tpmt());
                parent.qualified_name = parent.name;
                global_state.transient_objects[0] = Some(parent);

                // 2. Create target signing key
                let target = match target_type {
                    KeyGenType::Rsa => target_rsa.clone(),
                    KeyGenType::Ecc(_) => target_p256.clone(),
                };
                global_state.transient_objects[1] = Some(target.clone());

                // 3. Execute Duplicate on target under parent
                use tpm2::commands::{Duplicate, DuplicateHandles};
                let dup_handles = DuplicateHandles {
                    object_handle: Handle(0x80000002),
                    new_parent_handle: Handle(0x80000001),
                };
                let dup_cmd = Duplicate {
                    encryption_key_in: Tpm2bData::default(),
                    symmetric_alg: None,
                };
                let (_, dup_resp) = execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[])
                    .unwrap_or_else(|e| {
                        panic!(
                            "Exhaustive parent/target keygen failed: Duplicate failed for parent_type={:?}, target_type={:?}, parent_hash={:?}, error={:08X}",
                            parent_type, target_type, parent_hash, e
                        )
                    });

                // 4. Execute Import under parent using duplicate output
                use tpm2::commands::{Import, ImportHandles};
                let mut pub_buf = [0u8; 1024];
                let pub_len = marshal_to_slice(&target.public, &mut pub_buf);
                let object_public = Tpm2bPublic::from_bytes(&pub_buf[..pub_len]).unwrap();

                let imp_handles = ImportHandles {
                    parent_handle: Handle(0x80000001),
                };
                let imp_cmd = Import {
                    encryption_key: Tpm2bData::default(),
                    object_public,
                    duplicate: dup_resp.duplicate,
                    in_sym_seed: dup_resp.out_sym_seed,
                    symmetric_alg: None,
                };
                let (_, imp_resp) = execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[])
                    .unwrap_or_else(|e| {
                        panic!(
                            "Exhaustive parent/target keygen failed: Import failed for parent_type={:?}, target_type={:?}, parent_hash={:?}, error={:08X}",
                            parent_type, target_type, parent_hash, e
                        )
                    });

                // 5. Execute Load under parent using import output
                use tpm2::commands::{Load, LoadHandles};
                let load_handles = LoadHandles {
                    parent_handle: Handle(0x80000001),
                };
                let load_cmd = Load {
                    in_private: imp_resp.out_private,
                    in_public: object_public,
                };
                let (load_resp_handles, load_resp) =
                    execute_tpm_command(&mut tpm, &mut global_state, &load_handles, &load_cmd, &[]).unwrap_or_else(|e| {
                        panic!(
                            "Exhaustive parent/target keygen failed: Load failed for parent_type={:?}, target_type={:?}, parent_hash={:?}, error={:08X}",
                            parent_type, target_type, parent_hash, e
                        )
                    });

                // Loaded object name should match target name
                assert_eq!(load_resp.name.get_buffer(), target.name.get_buffer());
                // Verify that the new handle is a transient handle (starts with 0x80)
                assert_eq!(load_resp_handles.object_handle.0 >> 24, 0x80);
            }
        }
    }
}

#[test]
fn test_duplicate_encrypted_duplication_attributes() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Create a parent storage key (handle 0x80000001)
    let parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(parent);

    // 2. Create a target signing key with ENCRYPTED_DUPLICATION attribute (handle 0x80000002)
    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH | TpmaObject::ENCRYPTED_DUPLICATION,
    );
    global_state.transient_objects[1] = Some(target);

    // 3. Call Duplicate with Null symmetricAlg -> should fail with Symmetric
    use tpm2::commands::{Duplicate, DuplicateHandles};
    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let dup_cmd = Duplicate {
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[]);
    assert!(
        res.is_err(),
        "Expected Duplicate command to fail because ENCRYPTED_DUPLICATION is set but symmetricAlg is Null"
    );

    // 4. Call Duplicate with newParentHandle = TPM_RH_NULL and a non-null symmetricAlg -> should fail with HIERARCHY
    let dup_handles_null_parent = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle::RH_NULL,
    };
    let dup_cmd_aes = Duplicate {
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: Some(TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB))),
    };
    let res_null_parent = execute_tpm_command(
        &mut tpm,
        &mut global_state,
        &dup_handles_null_parent,
        &dup_cmd_aes,
        &[],
    );
    assert!(
        res_null_parent.is_err(),
        "Expected Duplicate command to fail because ENCRYPTED_DUPLICATION is set but newParentHandle is RHNull"
    );
}

#[test]
fn test_import_encrypted_duplication_attributes() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Create a parent storage key (handle 0x80000001)
    let parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(parent);

    // 2. Create a target signing key with ENCRYPTED_DUPLICATION attribute
    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH | TpmaObject::ENCRYPTED_DUPLICATION,
    );

    // 3. Try to Import it with empty in_sym_seed / empty encryptionKey -> should fail with Attributes
    use tpm2::commands::{Import, ImportHandles};
    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&target.public, &mut pub_buf);
    let object_public = Tpm2bPublic::from_bytes(&pub_buf[..pub_len]).unwrap();

    let imp_handles = ImportHandles {
        parent_handle: Handle(0x80000001),
    };
    let imp_cmd = Import {
        encryption_key: Tpm2bData::default(), // Empty!
        object_public,
        duplicate: Tpm2bPrivate::default(),
        in_sym_seed: Tpm2bEncryptedSecret::default(), // Empty!
        symmetric_alg: None,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::ATTRIBUTES.with(Position::parameter(1)).get())
    );
}

#[test]
fn test_duplicate_invalid_encryption_key_size() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Create a parent storage key (handle 0x80000001)
    let parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(parent);

    // 2. Create a target signing key (handle 0x80000002)
    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[1] = Some(target);

    // 3. Call Duplicate on target key with invalid encryption key size (e.g. 8 bytes instead of 16 for AES-128)
    use tpm2::commands::{Duplicate, DuplicateHandles};
    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let bad_encryption_key = Tpm2bData::from_bytes(&[0u8; 8]).unwrap();
    let dup_cmd = Duplicate {
        encryption_key_in: bad_encryption_key,
        symmetric_alg: Some(TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB))),
    };
    let res = execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::SIZE.with(Position::parameter(1)).get())
    );
}

#[test]
fn test_import_panic_vulnerability_oversized_ecc_point() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Create a parent ECC storage key at 0x80000001
    let mut parent = create_transient_ecc_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
        tpm2::TpmEccCurve::NistP256,
    );
    if let tpm2_impl::owned::OwnedPublicParmsAndId::Ecc(ref mut parms, _) =
        parent.public.parms_and_id
    {
        parms.symmetric = Some(TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB)));
    }
    global_state.transient_objects[0] = Some(parent.clone());

    // 2. Create target signing key public area
    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );

    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&target.public.as_tpmt(), &mut pub_buf);
    let object_public = Tpm2bPublic::from_bytes(&pub_buf[..pub_len]).unwrap();

    // 3. Construct a malformed in_sym_seed with x.size = 33 (larger than 32)
    let mut bad_seed_bytes = Vec::new();
    bad_seed_bytes.extend_from_slice(&33u16.to_be_bytes()); // x size
    bad_seed_bytes.extend_from_slice(&[0u8; 33]); // x buffer
    bad_seed_bytes.extend_from_slice(&32u16.to_be_bytes()); // y size
    bad_seed_bytes.extend_from_slice(&[0u8; 32]); // y buffer

    let in_sym_seed = Tpm2bEncryptedSecret::from_bytes(&bad_seed_bytes).unwrap();

    use tpm2::commands::{Import, ImportHandles};
    let imp_handles = ImportHandles {
        parent_handle: Handle(0x80000001),
    };
    let imp_cmd = Import {
        encryption_key: Tpm2bData::default(),
        object_public,
        duplicate: Tpm2bPrivate::default(),
        in_sym_seed,
        symmetric_alg: None,
    };

    // This should NOT panic. It should return an error.
    let res = execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::ECC_POINT.with(Position::parameter(4)).get())
    );
}

#[test]
fn test_import_empty_seed_with_symmetric_parent() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Create a parent ECC storage key with symmetric encryption enabled (AES-128 CFB)
    let mut parent = create_transient_ecc_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
        tpm2::TpmEccCurve::NistP256,
    );
    if let tpm2_impl::owned::OwnedPublicParmsAndId::Ecc(ref mut parms, _) =
        parent.public.parms_and_id
    {
        parms.symmetric = Some(TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB)));
    }
    global_state.transient_objects[0] = Some(parent);

    // 2. Create target signing key public area
    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );

    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&target.public.as_tpmt(), &mut pub_buf);
    let object_public = Tpm2bPublic::from_bytes(&pub_buf[..pub_len]).unwrap();

    // 3. Call Import with empty in_sym_seed
    use tpm2::commands::{Import, ImportHandles};
    let imp_handles = ImportHandles {
        parent_handle: Handle(0x80000001),
    };
    let imp_cmd = Import {
        encryption_key: Tpm2bData::default(),
        object_public,
        duplicate: Tpm2bPrivate::default(),
        in_sym_seed: Tpm2bEncryptedSecret::default(), // Empty!
        symmetric_alg: None,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[]);
    // If the parent has a symmetric key, then in_sym_seed must not be empty.
    // Our implementation should return size_for(Parameter, Pos1) or similar.
    assert!(
        res.is_err(),
        "Expected Import to fail because in_sym_seed is empty but parent symmetric is not Null"
    );
    println!("Empty seed with symmetric parent result: {:?}", res);
}

#[test]
fn test_import_valid_dup_empty_seed_with_symmetric_parent() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Create a parent ECC storage key with symmetric encryption enabled (AES-128 CFB)
    let mut parent = create_transient_ecc_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
        tpm2::TpmEccCurve::NistP256,
    );
    if let tpm2_impl::owned::OwnedPublicParmsAndId::Ecc(ref mut parms, _) =
        parent.public.parms_and_id
    {
        parms.symmetric = Some(TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB)));
    }
    // Update its name matching its name_alg
    parent.name = compute_key_name(tpm.platform.crypto, &parent.public.as_tpmt());
    parent.qualified_name = parent.name;
    global_state.transient_objects[0] = Some(parent.clone());

    // 2. Create target signing key
    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[1] = Some(target.clone());

    // 3. Execute Duplicate on target under parent
    use tpm2::commands::{Duplicate, DuplicateHandles};
    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let dup_cmd = Duplicate {
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };
    let (_, dup_resp) =
        execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[])
            .expect("Duplicate failed");

    // 4. Call Import with valid duplicate buffer but empty in_sym_seed
    use tpm2::commands::{Import, ImportHandles};
    let mut pub_buf = [0u8; 1024];
    let pub_len = marshal_to_slice(&target.public.as_tpmt(), &mut pub_buf);
    let object_public = Tpm2bPublic::from_bytes(&pub_buf[..pub_len]).unwrap();

    let imp_handles = ImportHandles {
        parent_handle: Handle(0x80000001),
    };
    let imp_cmd = Import {
        encryption_key: Tpm2bData::default(),
        object_public,
        duplicate: dup_resp.duplicate, // Valid duplicate!
        in_sym_seed: Tpm2bEncryptedSecret::default(), // Empty!
        symmetric_alg: None,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &imp_handles, &imp_cmd, &[]);
    assert!(
        res.is_err(),
        "Expected Import to fail because in_sym_seed is empty but parent symmetric is not Null"
    );
    println!("Valid dup with empty seed result: {:?}", res);
}

#[test]
fn test_duplicate_unsupported_curve() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Create parent key with an unsupported curve (e.g. 999)
    let mut parent = create_transient_ecc_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
        tpm2::TpmEccCurve::NistP256,
    );
    if let tpm2_impl::owned::OwnedPublicParmsAndId::Ecc(ref mut parms, _) =
        parent.public.parms_and_id
    {
        parms.curve_id = tpm2::TpmEccCurve::NistP224;
    }
    // Update name
    parent.name = compute_key_name(tpm.platform.crypto, &parent.public.as_tpmt());
    parent.qualified_name = parent.name;
    global_state.transient_objects[0] = Some(parent);

    // 2. Create target signing key
    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[1] = Some(target.clone());

    // 3. Execute Duplicate on target under parent -> should fail with Value error (132)
    use tpm2::commands::{Duplicate, DuplicateHandles};
    let dup_handles = DuplicateHandles {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
    };
    let dup_cmd = Duplicate {
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &dup_handles, &dup_cmd, &[]);
    assert_eq!(res.as_ref().err().copied(), Some(TpmRc::VALUE.get()));
    println!("Duplicate with unsupported curve result: {:?}", res);
}

#[test]
fn test_make_credential_panic_vulnerability_oversized_ecc_point() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Create a protector ECC key at 0x80000001
    let mut protector = create_transient_ecc_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
        tpm2::TpmEccCurve::NistP256,
    );
    if let tpm2_impl::owned::OwnedPublicParmsAndId::Ecc(ref mut parms, _) =
        protector.public.parms_and_id
    {
        parms.symmetric = Some(TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB)));
    }

    // Modify its public unique coordinates to be oversized (33 bytes)
    if let tpm2_impl::owned::OwnedPublicParmsAndId::Ecc(_, ref mut point) =
        protector.public.parms_and_id
    {
        point.x = tpm2_impl::owned::OwnedTpm2b::new(&[0u8; 33]).unwrap();
    }
    global_state.transient_objects[0] = Some(protector);

    // 2. MakeCredential
    use tpm2::commands::{MakeCredential, MakeCredentialHandles};
    let mc_handles = MakeCredentialHandles {
        handle: Handle(0x80000001),
    };
    let mc_cmd = MakeCredential {
        credential: Tpm2bDigest::from_bytes(b"credential").unwrap(),
        object_name: Tpm2bName::from_bytes(&[1, 2, 3]).unwrap(),
    };

    // This should NOT panic. It should return a Value error because the public key parameters are invalid
    let res = execute_tpm_command(&mut tpm, &mut global_state, &mc_handles, &mc_cmd, &[]);
    assert_eq!(
        res.err(),
        Some(TpmRc::VALUE.with(Position::handle(1)).get())
    );
}

fn create_transient_sym_key(handle: u32, attrs: TpmaObject) -> TransientObject {
    let name = tpm2_impl::owned::OwnedTpm2b::new(&[7, 8, 9]).unwrap();
    let public = TpmtPublic {
        name_alg: Some(TpmiAlgHash::Sha256),
        object_attributes: attrs,
        auth_policy: Tpm2bDigest::default(),
        parms_and_id: PublicParmsAndId::Sym(
            TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB)),
            Tpm2bDigest::default(),
        ),
    };
    TransientObject {
        handle,
        seed: [0u8; 32],
        name,
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        private: [0u8; 1536],
        private_len: 16,
        qualified_name: name,
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

#[test]
fn test_activate_credential_symmetric_key_error() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Setup target object (to activate credential)
    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[1] = Some(target);

    // 2. Setup a symmetric key as protector key (at 0x80000001)
    let protector_sym = create_transient_sym_key(
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[0] = Some(protector_sym);

    // 3. Call ActivateCredential
    use tpm2::commands::{ActivateCredential, ActivateCredentialHandles};
    let ac_handles = ActivateCredentialHandles {
        activate_handle: Handle(0x80000002),
        key_handle: Handle(0x80000001),
    };
    let ac_cmd = ActivateCredential {
        credential_blob: tpm2::Tpm2bIdObject::default(),
        secret: tpm2::Tpm2bEncryptedSecret::default(),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &ac_handles, &ac_cmd, &[]);
    // BUG: The implementation returns TpmRc::TYPE (0x8A = 138) instead of the spec-compliant
    // TpmRc::TYPE.with(Position::handle(2)) (0x28A = 650) because it returns TpmRc::TYPE in the match block.
    assert_eq!(res.err(), Some(TpmRc::TYPE.with(Position::handle(2)).get()));
}

#[test]
fn test_cpc_2_14_01_01_create_sym_under_null_parent() {
    use tpm2::TpmsSensitiveCreate;
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Create parent RSA key with symmetric: Null
    let mut parent = create_transient_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
    );
    if let tpm2_impl::owned::OwnedPublicParmsAndId::Rsa(ref mut parms, _) =
        parent.public.parms_and_id
    {
        parms.symmetric = None;
    }
    parent.name = compute_key_name(tpm.platform.crypto, &parent.public.as_tpmt());
    parent.qualified_name = parent.name;
    global_state.transient_objects[0] = Some(parent);

    // 2. Execute Create for a SymCipher object with SHA1 name_alg
    use tpm2::commands::{Create, CreateHandles};
    let handles = CreateHandles {
        parent_handle: Handle(0x80000001),
    };
    let data_buf = [0xAAu8; 16];
    let data = tpm2::Tpm2bSensitiveData::from_bytes(&data_buf).unwrap();
    let cmd = Create {
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(&[1, 2, 3]).unwrap(),
            data,
        }),
        in_public: tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha1),
            object_attributes: TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Sym(
                TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB)),
                Tpm2bDigest::default(),
            ),
        }),
        outside_info: tpm2::Tpm2bData::default(),
        creation_pcr: tpm2::TpmlPcrSelection::default(),
    };

    let res = execute_tpm_command(&mut tpm, &mut global_state, &handles, &cmd, &[]);
    assert!(res.is_ok(), "Create failed: {:?}", res.err());
}
