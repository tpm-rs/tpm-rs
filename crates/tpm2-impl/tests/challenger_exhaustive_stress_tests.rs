use common::marshal_to_slice;
use tpm2::Alg;
use tpm2::errors::TpmRc;

use tpm2::{Marshal, Unmarshal};
mod common;

use common::TestCryptoProvider;
use common::{FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::Handle;
use tpm2::commands::{Command, Message, UnmarshalMessage};
use tpm2::crypto::Asymmetric;
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bName, Tpm2bPublicKeyRsa, TpmaObject,
    TpmiAlgHash, TpmsAuthCommand, TpmsRsaParms, TpmtPublic, TpmtSymDefObject,
};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::TransientObject;

fn setup_tpm<'a>(
    crypto: &'a mut TestCryptoProvider,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a mut FakeRng,
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
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<C::Response<'static>, u32>
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
        let handle_slice: &mut <tpm2::Handle as Marshal>::MaxBuffer = (&mut request_buf
            [offset..offset + tpm2::Handle::MAX_SIZE])
            .try_into()
            .map_err(|_| ())
            .unwrap();
        let handle_len = handle.marshal(handle_slice);
        offset += handle_len;
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
    let mut resp_handles = <C::Response<'static> as Message>::Handles::default();
    for handle in resp_handles.as_mut() {
        *handle = tpm2::Handle::unmarshal(&mut handles_slice).map_err(|_| TpmRc::FAILURE.get())?;
    }

    let handles_len = orig_handles_len - handles_slice.len();
    resp_offset += handles_len;

    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        resp_offset += 4; // Skip parameter size
    }

    let mut params_slice: &'static [u8] =
        std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
    let resp_params = <C::Response<'static> as UnmarshalMessage>::unmarshal_with_handles(
        resp_handles,
        &mut params_slice,
    )
    .map_err(|_| TpmRc::FAILURE.get())?;

    Ok(resp_params)
}

fn compute_key_name(crypto: &TestCryptoProvider, public: &TpmtPublic) -> Tpm2bName<'static> {
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(public, &mut buf);
    let mut out = [0u8; tpm2::TpmtHa::MAX_DIGEST_SIZE];
    let digest = tpm2::crypto::hash(crypto, TpmiAlgHash::Sha256, &buf[..len], &mut out)
        .unwrap()
        .digest();

    let mut name_bytes = [0u8; 34];
    name_bytes[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    name_bytes[2..34].copy_from_slice(digest);
    Tpm2bName::from_bytes(std::vec::Vec::leak(name_bytes[..34].to_vec())).unwrap()
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
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: name.into(),
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        private,
        private_len: priv_len,
        qualified_name: name.into(),
        hierarchy: 0x40000001,
        st_clear: false,
    }
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
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: name.into(),
        auth: Tpm2bAuth::default().into(),
        public: public.into(),
        private,
        private_len: priv_len,
        qualified_name: name.into(),
        hierarchy: 0x40000001,
        st_clear: false,
    }
}

/// `TPM2_Duplicate` requires the DUP role, which always needs a policy session whose
/// `commandCode` is `TPM2_Duplicate` (C `IsPolicySessionRequired()` / `CheckPolicyAuthSession()`).
/// Installs such a session (its policyDigest equals the object's empty authPolicy) and returns the
/// authorization that uses it.
fn dup_policy_auth(global_state: &mut tpm2_impl::GlobalState) -> TpmsAuthCommand<'static> {
    const SESSION: u32 = 0x0300_0000;
    let _ = global_state.flush_session(SESSION);
    let mut session = common::make_test_session_state(
        SESSION,
        tpm2::TpmSe::Policy,
        TpmiAlgHash::Sha256,
        Default::default(),
        Default::default(),
        &[],
        None,
        Handle::RH_NULL,
    );
    session.command_code = u32::from(tpm2::TpmCc::Duplicate);
    global_state.add_session(session).unwrap();
    TpmsAuthCommand {
        session_handle: Handle(SESSION),
        nonce: Default::default(),
        session_attributes: tpm2::TpmaSession(0),
        hmac: Default::default(),
    }
}

#[test]
fn test_duplicate_invalid_parent_coordinates_zero_size() {
    let mut crypto = TestCryptoProvider;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let mut rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &mut rng);

    // 1. Create a parent ECC storage key at 0x80000001
    let mut parent = create_transient_ecc_key(
        tpm.platform.crypto,
        0x80000001,
        TpmaObject::DECRYPT | TpmaObject::RESTRICTED | TpmaObject::USER_WITH_AUTH,
        tpm2::TpmEccCurve::NistP256,
    );
    // Tamper with the parent ECC key's coordinates: make unique.x and unique.y empty
    // Also set its symmetric algorithm to be non-Null so that outer wrapper encryption is performed.
    let mut pub_t = parent.public.as_tpmt();
    if let PublicParmsAndId::Ecc(ref mut parms, ref mut point) = pub_t.parms_and_id {
        parms.symmetric = Some(TpmtSymDefObject {
            alg: tpm2::AlgSym::Aes128,
            mode: Some(tpm2::TpmiAlgSymMode::Cipher(tpm2::TpmiAlgCipherMode::Cfb)),
        });
        point.x = tpm2::Tpm2bEccParameter::default(); // 0 size!
        point.y = tpm2::Tpm2bEccParameter::default(); // 0 size!
    }
    parent.public = pub_t.into();
    global_state.transient_objects[0] = Some(parent.clone());

    // 2. Create target signing key (handle 0x80000002)
    let target = create_transient_key(
        tpm.platform.crypto,
        0x80000002,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
    );
    global_state.transient_objects[1] = Some(target.clone());

    // 3. Call Duplicate on target under the tampered parent key
    use tpm2::commands::Duplicate;
    let dup_cmd = Duplicate {
        object_handle: Handle(0x80000002),
        new_parent_handle: Handle(0x80000001),
        encryption_key_in: Tpm2bData::default(),
        symmetric_alg: None,
    };

    // This should not panic or underflow. It should return Failure because ECDH point multiply fails with invalid coordinates
    let dup_auth = dup_policy_auth(&mut global_state);
    let res = execute_tpm_command(&mut tpm, &mut global_state, &dup_cmd, &[dup_auth]);
    assert_eq!(res.err(), Some(TpmRc::FAILURE.get()));
}
