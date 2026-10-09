use common::marshal_to_slice;
use tpm2::Unmarshal;
use tpm2::errors::{Position, TpmRc};

extern crate alloc;

mod common;

use common::{FakeRng, FakeStorage, FakeTimer};
use tpm2::commands::{
    Certify, CertifyHandles, Command, GetCapability, GetSessionAuditDigest,
    GetSessionAuditDigestHandles,
};
use tpm2::{Handle, Marshal, TpmCap, TpmPt};
use tpm2::{
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bName, Tpm2bPublicKeyRsa, TpmaObject,
    TpmaSession, TpmiAlgHash, TpmsAuthCommand, TpmtPublic, TpmtRsaScheme, TpmtSigScheme,
    TpmtSignature, TpmtSymDefObject,
};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::TransientObject;

use hex_literal::hex;
use tpm2::crypto::Rng;
use tpm2::crypto::{Asymmetric, AsymmetricSign};
use tpm2::crypto::{CryptoError, CryptoProvider};

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
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    (tpm, global_state)
}

fn execute_tpm_command_with_auths<C: Command>(
    tpm: &mut TpmEngine<'_, StressTestCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &C::Handles,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<(), u32>
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
    tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    Ok(())
}

fn execute_tpm_command_with_corrupted_bytes<C: Command>(
    tpm: &mut TpmEngine<'_, StressTestCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &C::Handles,
    cmd: &C,
    auths: &[TpmsAuthCommand],
    corrupt_fn: impl FnOnce(&mut [u8]),
) -> Result<(), u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    for<'b> &'b mut <<C as Command>::Handles as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
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

    let payload_start = offset;
    let cmd_slice: &mut <C as Marshal>::MaxBuffer = (&mut request_buf
        [offset..offset + <C as Marshal>::MAX_SIZE])
        .try_into()
        .map_err(|_| ())
        .unwrap();
    let cmd_len = cmd.marshal(cmd_slice);
    offset += cmd_len;

    request_buf[2..6].copy_from_slice(&(offset as u32).to_be_bytes());

    corrupt_fn(&mut request_buf[payload_start..offset]);

    let mut response_buf = [0u8; 16384];
    tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    Ok(())
}

fn execute_tpm_certify<'a>(
    tpm: &mut TpmEngine<'_, StressTestCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &CertifyHandles,
    cmd: &Certify,
    auths: &[TpmsAuthCommand],
    response_buf: &'a mut [u8; 16384],
) -> Result<<Certify<'static> as Command>::Response<'a>, u32> {
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(Certify::CMD_CODE.code()).to_be_bytes());
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

fn execute_tpm_get_session_audit_digest<'a>(
    tpm: &mut TpmEngine<'_, StressTestCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &GetSessionAuditDigestHandles,
    cmd: &GetSessionAuditDigest,
    auths: &[TpmsAuthCommand],
    response_buf: &'a mut [u8; 16384],
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

fn execute_tpm_get_capability<'a>(
    tpm: &mut TpmEngine<'_, StressTestCrypto, FakeStorage, FakeTimer, FakeRng>,
    global_state: &mut tpm2_impl::GlobalState,
    handles: &(),
    cmd: &GetCapability,
    auths: &[TpmsAuthCommand],
    response_buf: &'a mut [u8; 16384],
) -> Result<<GetCapability as Command>::Response<'a>, u32> {
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(GetCapability::CMD_CODE.code()).to_be_bytes());
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

#[test]
fn test_get_capability_stress_and_bounds() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. property_count = 0 (should succeed with 0 items per TPM (2 as u16) Spec Section 30.1)
    let cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 0,
    };
    let resp = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &(), &cmd, &[]);
    assert!(resp.is_ok());

    // 2. property_count = u32::MAX (should succeed, bounds to max properties)
    let cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: u32::MAX,
    };
    let mut response_buf = [0u8; 16384];
    let resp = execute_tpm_get_capability(
        &mut tpm,
        &mut global_state,
        &(),
        &cmd,
        &[],
        &mut response_buf,
    )
    .expect("GetCapability with property_count=MAX failed");
    if let tpm2::TpmsCapabilityData::TpmProperties(ref props) = resp.capability_data {
        assert!(props.count() > 0);
        assert!(props.count() <= tpm2::TPM2_MAX_TPM_PROPERTIES);
    } else {
        panic!("Expected TpmProperties");
    }

    // 3. Invalid capability (e.g. 0x9999) -> should return TPM_RC_VALUE (132 / 0x84)
    let cmd = GetCapability {
        capability: TpmCap::Algs,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 5,
    };
    let res = execute_tpm_command_with_corrupted_bytes::<GetCapability>(
        &mut tpm,
        &mut global_state,
        &(),
        &cmd,
        &[],
        |buf| {
            buf[0..4].copy_from_slice(&0x9999u32.to_be_bytes());
        },
    );
    assert_eq!(
        res.err(),
        Some(
            TpmRc::VALUE
                .with(tpm2::errors::Position::parameter(1))
                .get()
        )
    );
}

#[test]
fn test_certify_errors_and_bounds() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let certified_handle = 0x80000001;
    let signer_handle = 0x80000002;

    // Load certified object
    let certified_obj = TransientObject {
        handle: certified_handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::from_bytes(&[1, 2, 3]).unwrap()).into(),
        auth: (Tpm2bAuth::from_bytes(&[0x11, 0x22]).unwrap()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                tpm2::TpmsRsaParms {
                    symmetric: None,
                    scheme: None,
                    key_bits: tpm2::TpmiRsaKeyBits(2048),
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::default(),
            ),
        })
        .into(),
        private: [0u8; 1536],
        private_len: 256,
        qualified_name: (Tpm2bName::from_bytes(&[1, 2, 3]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(certified_obj);

    // Setup default auth sessions
    // Certified object password is [0x11, 0x22]
    let certified_auth = TpmsAuthCommand {
        session_handle: tpm2::Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::from_bytes(&[0x11, 0x22]).unwrap(),
    };

    // Certified object empty auth session (useful when object handle is non-existent)
    let certified_empty_auth = TpmsAuthCommand {
        session_handle: tpm2::Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };

    let signer_auth = TpmsAuthCommand {
        session_handle: tpm2::Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(), // Empty password
    };

    // 1. Certified object invalid handle -> should fail with TpmRc::HANDLE
    let cmd = Certify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let handles = CertifyHandles {
        object_handle: Handle(0x80000009), // Non-existent
        sign_handle: Handle(0x40000007),   // RH_NULL
    };
    // Since 0x80000009 is non-existent, its auth is empty. Provide empty hmac.
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &[certified_empty_auth],
    );
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H0.get()));

    // 2. Sign key invalid handle -> should fail with TpmRc::HANDLE
    let handles = CertifyHandles {
        object_handle: Handle(certified_handle),
        sign_handle: Handle(0x80000009), // Non-existent
    };
    // Provide correct hmac for certified_handle, and empty hmac for non-existent sign key.
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &[certified_auth, signer_auth],
    );
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H1.get()));

    // 3. Load a signer key that is NOT a signing key (lacks SIGN_ENCRYPT attribute)
    let bad_signer_obj = TransientObject {
        handle: signer_handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::from_bytes(&[4, 5, 6]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH, // decrypt only!
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                tpm2::TpmsRsaParms {
                    symmetric: None,
                    scheme: None,
                    key_bits: tpm2::TpmiRsaKeyBits(2048),
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::default(),
            ),
        })
        .into(),
        private: [0u8; 1536],
        private_len: 256,
        qualified_name: (Tpm2bName::from_bytes(&[4, 5, 6]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[1] = Some(bad_signer_obj);

    let handles = CertifyHandles {
        object_handle: Handle(certified_handle),
        sign_handle: Handle(signer_handle),
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &[certified_auth, signer_auth],
    );
    // TPM_RC_KEY + RC_Certify_signHandle (H2).
    assert_eq!(res.err(), Some(0x29C));

    // 4. Load a signer key that has incorrect key type (e.g. Symmetric key instead of Asymmetric key)
    let sym_signer_obj = TransientObject {
        handle: signer_handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::from_bytes(&[4, 5, 6]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Sym(
                TpmtSymDefObject::Aes128(Some(tpm2::TpmiAlgSymMode::CFB)),
                Tpm2bDigest::default(),
            ),
        })
        .into(),
        private: [0u8; 1536],
        private_len: 16,
        qualified_name: (Tpm2bName::from_bytes(&[4, 5, 6]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[1] = Some(sym_signer_obj);

    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &[certified_auth, signer_auth],
    );
    // TPM_RC_KEY + RC_Certify_signHandle (H2).
    assert_eq!(res.err(), Some(0x29C));
}

#[test]
fn test_certify_signature_schemes() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let certified_handle = 0x80000001;
    let signer_handle = 0x80000002;

    // Load certified object
    let certified_obj = TransientObject {
        handle: certified_handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::from_bytes(&[1, 2, 3]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                tpm2::TpmsRsaParms {
                    symmetric: None,
                    scheme: None,
                    key_bits: tpm2::TpmiRsaKeyBits(2048),
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::default(),
            ),
        })
        .into(),
        private: [0u8; 1536],
        private_len: 256,
        qualified_name: (Tpm2bName::from_bytes(&[1, 2, 3]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(certified_obj);

    // 1. Signer key with fixed scheme RSASSA SHA256
    let signer_obj = TransientObject {
        handle: signer_handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::from_bytes(&[4, 5, 6]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
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
        qualified_name: (Tpm2bName::from_bytes(&[4, 5, 6]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[1] = Some(signer_obj);

    let handles = CertifyHandles {
        object_handle: Handle(certified_handle),
        sign_handle: Handle(signer_handle),
    };

    let certified_auth = TpmsAuthCommand {
        session_handle: tpm2::Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };
    let signer_auth = TpmsAuthCommand {
        session_handle: tpm2::Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };

    // 1.1 Requesting Null scheme should resolve to fixed scheme (RSASSA SHA256) -> Success
    let cmd = Certify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let mut response_buf = [0u8; 16384];
    let resp = execute_tpm_certify(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &[certified_auth, signer_auth],
        &mut response_buf,
    )
    .expect("Certify with Null scheme failed");
    assert!(matches!(resp.signature, Some(TpmtSignature::Rsassa(..))));

    // 1.2 Requesting RSAPSS scheme should fail since key scheme is fixed to RSASSA -> TpmRc::SCHEME
    let cmd = Certify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: Some(TpmtSigScheme::Rsapss(TpmiAlgHash::Sha256)),
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &[certified_auth, signer_auth],
    );
    // TPM_RC_SCHEME + RC_Certify_inScheme (P2).
    assert_eq!(res.err(), Some(0x2D2));

    // 1.3 Requesting RSASSA SHA384 (different hash) should fail -> TpmRc::SCHEME
    let cmd = Certify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha384)),
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &[certified_auth, signer_auth],
    );
    // TPM_RC_SCHEME + RC_Certify_inScheme (P2).
    assert_eq!(res.err(), Some(0x2D2));

    // 2. Restricted signer key
    let restricted_signer_obj = TransientObject {
        handle: signer_handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::from_bytes(&[4, 5, 6]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT
                | TpmaObject::RESTRICTED
                | TpmaObject::USER_WITH_AUTH,
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
        qualified_name: (Tpm2bName::from_bytes(&[4, 5, 6]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[1] = Some(restricted_signer_obj);

    // 2.1 Restricted key scheme hash MUST match name_alg (SHA256) -> Success
    let cmd = Certify {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let mut response_buf = [0u8; 16384];
    let resp = execute_tpm_certify(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &[certified_auth, signer_auth],
        &mut response_buf,
    )
    .expect("Certify with restricted key failed");
    assert!(matches!(resp.signature, Some(TpmtSignature::Rsassa(..))));
}

#[test]
fn test_get_session_audit_digest_errors() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    let signer_handle = 0x80000001;

    // Load signer object with fixed scheme RSASSA SHA256
    let signer_obj = TransientObject {
        handle: signer_handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::from_bytes(&[1, 2, 3]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
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
        qualified_name: (Tpm2bName::from_bytes(&[1, 2, 3]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(signer_obj);

    // Create an active session
    let audit_session_handle = 0x02000001;
    let session = tpm2_impl::handler::SessionState {
        session_handle: audit_session_handle,
        session_type: tpm2::TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: tpm2::Handle::RH_NULL,
        bound_entity: Default::default(),
        audit_digest: Some([0u8; 64]),
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
    global_state.add_session(session).unwrap();

    let admin_auth = TpmsAuthCommand {
        session_handle: tpm2::Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };
    let signer_auth = TpmsAuthCommand {
        session_handle: tpm2::Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };

    // 1. Session handle invalid -> should fail with TpmRc::HANDLE
    let cmd = GetSessionAuditDigest {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let handles = GetSessionAuditDigestHandles {
        privacy_admin_handle: Handle(0x4000000B), // TPM_RH_ENDORSEMENT
        sign_handle: Handle(signer_handle),
        session_handle: Handle(0x02000009), // Non-existent session
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &[admin_auth, signer_auth],
    );
    // An unloaded session in the handle area is TPM_RC_REFERENCE_H0 + index (here H2) per C
    // EntityGetLoadStatus (Entity.c), reported before any authorization processing.
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H2.get()));

    // 2. Sign handle invalid -> should fail with TpmRc::HANDLE
    let handles = GetSessionAuditDigestHandles {
        privacy_admin_handle: Handle(0x4000000B), // TPM_RH_ENDORSEMENT
        sign_handle: Handle(0x80000009),          // Non-existent key
        session_handle: Handle(audit_session_handle),
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &[admin_auth, signer_auth],
    );
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H1.get()));

    // 3. Valid params -> Success
    let handles = GetSessionAuditDigestHandles {
        privacy_admin_handle: Handle(0x4000000B), // TPM_RH_ENDORSEMENT
        sign_handle: Handle(signer_handle),
        session_handle: Handle(audit_session_handle),
    };
    let mut response_buf = [0u8; 16384];
    let resp = execute_tpm_get_session_audit_digest(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &[admin_auth, signer_auth],
        &mut response_buf,
    )
    .expect("GetSessionAuditDigest failed");
    assert!(matches!(resp.signature, Some(TpmtSignature::Rsassa(..))));

    // 4. Session exists but is not an audit session (no audit digest) -> type_for(Handle, Pos3) (0x38A)
    let non_audit_session_handle = 0x02000002;
    let non_audit_session = tpm2_impl::handler::SessionState {
        session_handle: non_audit_session_handle,
        session_type: tpm2::TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: tpm2::Handle::RH_NULL,
        bound_entity: Default::default(),
        audit_digest: None, // non-audit session
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
    global_state.add_session(non_audit_session).unwrap();

    let handles = GetSessionAuditDigestHandles {
        privacy_admin_handle: Handle(0x4000000B), // TPM_RH_ENDORSEMENT
        sign_handle: Handle(signer_handle),
        session_handle: Handle(non_audit_session_handle),
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &handles,
        &cmd,
        &[admin_auth, signer_auth],
    );
    assert_eq!(res.err(), Some(TpmRc::TYPE.with(Position::handle(3)).get()));
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

#[test]
fn test_challenger_audit_reset_and_format1_errors() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // 1. Verify AUDIT_RESET behavior
    let audit_session_handle = 0x02000001;
    let session = tpm2_impl::handler::SessionState {
        session_handle: audit_session_handle,
        session_type: tpm2::TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: tpm2::Handle::RH_NULL,
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
    global_state.add_session(session).unwrap();

    // Send GetCapability with continueSession (0x01) but NO auditReset (0x04)
    let cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    };
    let hmac = compute_mock_hmac(0x81, &[]);
    let auth = TpmsAuthCommand {
        session_handle: tpm2::Handle(audit_session_handle),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x81), // continueSession | audit
        hmac,
    };
    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &(), &cmd, &[auth])
        .expect("Command failed");

    // Verify audit digest is NOT reset (remains 0xab)
    let s = global_state.session(audit_session_handle).unwrap();
    assert_eq!(s.audit_digest.unwrap()[0], 0xab);

    // Send GetCapability with continueSession | auditReset (0x05)
    let nonce_tpm_1 = global_state
        .session(audit_session_handle)
        .unwrap()
        .nonce_tpm;
    let hmac = compute_mock_hmac(0x85, nonce_tpm_1.get_buffer());
    let auth = TpmsAuthCommand {
        session_handle: tpm2::Handle(audit_session_handle),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x85), // continueSession | audit | auditReset
        hmac,
    };
    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &(), &cmd, &[auth])
        .expect("Command failed");

    // Verify audit digest IS reset to all zeros and then extended
    let s = global_state.session(audit_session_handle).unwrap();
    let mut expected = [0u8; 64];
    expected[..24].copy_from_slice(&[
        0, 0, 1, 122, 0, 0, 1, 124, 1, 0, 1, 0, 6, 0, 0, 1, 1, 0, 0, 1, 0, 50, 46, 48,
    ]);
    assert_eq!(s.audit_digest.unwrap(), expected);
    assert_eq!(s.audit_digest_len, 32);

    // Verify other format 1 errors:
    // Handle 1 invalid: privacy_admin_handle = 0 (invalid admin handle)
    let handles = GetSessionAuditDigestHandles {
        privacy_admin_handle: Handle(0), // Invalid admin handle
        sign_handle: Handle(0x40000007),
        session_handle: Handle(audit_session_handle),
    };
    let get_audit_cmd = GetSessionAuditDigest {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let admin_auth = TpmsAuthCommand {
        session_handle: tpm2::Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &handles,
        &get_audit_cmd,
        &[admin_auth],
    );
    assert_eq!(
        res.as_ref().err(),
        Some(&TpmRc::VALUE.with(Position::handle(1)).get())
    );
    assert_eq!(res.err(), Some(0x184));
}

#[test]
fn test_challenger_remediation_stress_cases() {
    let mut crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&mut crypto, &mut storage, &mut timer, &rng);

    // ==========================================
    // 1. GetCapability Handles with property_count = 0
    // ==========================================
    // Load some transient objects to populate global state
    let obj1 = TransientObject {
        handle: 0x80000001,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::from_bytes(&[1, 2, 3]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                tpm2::TpmsRsaParms {
                    symmetric: None,
                    scheme: None,
                    key_bits: tpm2::TpmiRsaKeyBits(2048),
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::default(),
            ),
        })
        .into(),
        private: [0u8; 1536],
        private_len: 256,
        qualified_name: (Tpm2bName::from_bytes(&[1, 2, 3]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj1);

    // GetCapability with Handles, property_count = 0 (should succeed per TPM (2 as u16) Spec Section 30.1)
    let cmd = GetCapability {
        capability: TpmCap::Handles,
        property: 0x80000000,
        property_count: 0,
    };
    let resp = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &(), &cmd, &[]);
    assert!(resp.is_ok());

    // ==========================================
    // 2. Session exclusivity tracking
    // ==========================================
    let session_handle_1 = 0x02000001;
    let session_handle_2 = 0x02000002;

    let session_1 = tpm2_impl::handler::SessionState {
        session_handle: session_handle_1,
        session_type: tpm2::TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: tpm2::Handle::RH_NULL,
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
    let session_2 = tpm2_impl::handler::SessionState {
        session_handle: session_handle_2,
        session_type: tpm2::TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: tpm2::Handle::RH_NULL,
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
    global_state.add_session(session_1).unwrap();
    global_state.add_session(session_2).unwrap();

    // 2.1 Execute command with Session 1 (AUDIT set) -> sets exclusivity
    let cmd_get_cap = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FAMILY_INDICATOR),
        property_count: 1,
    };
    // Mock HMAC with audit attribute 0x81 (continueSession | audit)
    let hmac_1 = compute_mock_hmac(0x81, &[]);
    let auth_1 = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle_1),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x81),
        hmac: hmac_1,
    };
    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &(), &cmd_get_cap, &[auth_1])
        .unwrap();
    assert_eq!(global_state.exclusive_audit_session, Some(session_handle_1));

    // 2.2 Execute command with Session 2 (AUDIT set) -> changes exclusivity
    let nonce_tpm_2 = global_state.session(session_handle_2).unwrap().nonce_tpm;
    let hmac_2 = compute_mock_hmac(0x81, nonce_tpm_2.get_buffer());
    let auth_2 = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle_2),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x81),
        hmac: hmac_2,
    };
    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &(), &cmd_get_cap, &[auth_2])
        .unwrap();
    assert_eq!(global_state.exclusive_audit_session, Some(session_handle_2));

    // 2.3 Execute command with Session 1 and Session 2 (both AUDIT set) -> fails with TPM_RC_ATTRIBUTES on session 2 (0xA82)
    let nonce_tpm_1 = global_state.session(session_handle_1).unwrap().nonce_tpm;
    let nonce_tpm_2 = global_state.session(session_handle_2).unwrap().nonce_tpm;
    let hmac_1 = compute_mock_hmac(0x81, nonce_tpm_1.get_buffer());
    let hmac_2 = compute_mock_hmac(0x81, nonce_tpm_2.get_buffer());
    let auth_1 = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle_1),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x81),
        hmac: hmac_1,
    };
    let auth_2 = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle_2),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x81),
        hmac: hmac_2,
    };
    let resp = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &(),
        &cmd_get_cap,
        &[auth_1, auth_2],
    );
    assert_eq!(resp.err(), Some(0xA82));
    // exclusivity remains session_handle_2 because command failed validation before state update
    assert_eq!(global_state.exclusive_audit_session, Some(session_handle_2));

    // 2.4 Execute command with Session 1 (AUDIT and AUDIT_RESET set) -> regain exclusivity
    let nonce_tpm_1 = global_state.session(session_handle_1).unwrap().nonce_tpm;
    let hmac_1 = compute_mock_hmac(0x85, nonce_tpm_1.get_buffer());
    let auth_1 = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle_1),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x85),
        hmac: hmac_1,
    };
    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &(), &cmd_get_cap, &[auth_1])
        .unwrap();
    assert_eq!(global_state.exclusive_audit_session, Some(session_handle_1));

    // 2.5 Execute command WITHOUT sessions (or not audit session) -> exclusivity lost
    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &(), &cmd_get_cap, &[]).unwrap();
    assert_eq!(global_state.exclusive_audit_session, None);

    // 2.6 Regain exclusivity with Session 1 (AUDIT and AUDIT_RESET set)
    let nonce_tpm_1 = global_state.session(session_handle_1).unwrap().nonce_tpm;
    let hmac_1 = compute_mock_hmac(0x85, nonce_tpm_1.get_buffer());
    let auth_1 = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle_1),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x85),
        hmac: hmac_1,
    };
    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &(), &cmd_get_cap, &[auth_1])
        .unwrap();
    assert_eq!(global_state.exclusive_audit_session, Some(session_handle_1));

    // 2.7 Session completion (continueSession = 0) -> exclusivity lost
    let nonce_tpm_1 = global_state.session(session_handle_1).unwrap().nonce_tpm;
    let hmac_1 = compute_mock_hmac(0x80, nonce_tpm_1.get_buffer()); // continueSession = 0
    let auth_1 = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle_1),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x80),
        hmac: hmac_1,
    };
    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &(), &cmd_get_cap, &[auth_1])
        .unwrap();
    assert_eq!(global_state.exclusive_audit_session, None);
    assert!(global_state.session(session_handle_1).is_none()); // removed

    // Re-add Session 1
    let session_1 = tpm2_impl::handler::SessionState {
        session_handle: session_handle_1,
        session_type: tpm2::TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: tpm2::Handle::RH_NULL,
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
    global_state.add_session(session_1).unwrap();

    // Regain exclusivity
    let nonce_tpm_1 = global_state.session(session_handle_1).unwrap().nonce_tpm;
    let hmac_1 = compute_mock_hmac(0x81, nonce_tpm_1.get_buffer());
    let auth_1 = TpmsAuthCommand {
        session_handle: tpm2::Handle(session_handle_1),
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(0x81),
        hmac: hmac_1,
    };
    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &(), &cmd_get_cap, &[auth_1])
        .unwrap();
    assert_eq!(global_state.exclusive_audit_session, Some(session_handle_1));

    // 2.8 Session flush (flush context) -> exclusivity lost
    let flush_request = [
        0x80, 0x01, // Tag: NO_SESSIONS
        0x00, 0x00, 0x00, 0x0e, // Command size: 14
        0x00, 0x00, 0x01, 0x65, // CC: FlushContext (0x165)
        0x02, 0x00, 0x00, 0x01, // Handle: Session 1
    ];
    let mut flush_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &flush_request[..],
        &mut flush_response[..],
    );
    assert_eq!(global_state.exclusive_audit_session, None);
    assert!(global_state.session(session_handle_1).is_none());

    // ==========================================
    // 3. Non-audit sessions return TPM_RC_TYPE
    // ==========================================
    // Create an active session, but do NOT run any command with it as AUDIT.
    let session_handle_3 = 0x02000003;
    let session_3 = tpm2_impl::handler::SessionState {
        session_handle: session_handle_3,
        session_type: tpm2::TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: tpm2::Handle::RH_NULL,
        bound_entity: Default::default(),
        audit_digest: None, // No audit digest initialized
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
    global_state.add_session(session_3).unwrap();

    let signer_handle = 0x80000002;
    let signer_obj = TransientObject {
        handle: signer_handle,
        seed: [0u8; 64],
        seed_len: 32,
        external: false,
        public_only: false,
        name: (Tpm2bName::from_bytes(&[4, 5, 6]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
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
        qualified_name: (Tpm2bName::from_bytes(&[4, 5, 6]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[1] = Some(signer_obj);

    let get_audit_cmd = GetSessionAuditDigest {
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let get_audit_handles = GetSessionAuditDigestHandles {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: Handle(signer_handle),
        session_handle: Handle(session_handle_3),
    };
    let admin_auth = TpmsAuthCommand {
        session_handle: tpm2::Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };
    let signer_auth = TpmsAuthCommand {
        session_handle: tpm2::Handle::RS_PW,
        nonce: tpm2::Tpm2bNonce::default(),
        session_attributes: TpmaSession(1),
        hmac: Tpm2bAuth::default(),
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &get_audit_handles,
        &get_audit_cmd,
        &[admin_auth, signer_auth],
    );
    assert_eq!(res.err(), Some(TpmRc::TYPE.with(Position::handle(3)).get()));

    // ==========================================
    // 4. privacy_admin_handle validation restricts to endorsement/null hierarchies
    // ==========================================
    // Prepare a valid audit session (with audit_digest initialized)
    let audit_session_handle = 0x02000004;
    let audit_session = tpm2_impl::handler::SessionState {
        session_handle: audit_session_handle,
        session_type: tpm2::TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (tpm2::Tpm2bNonce::default()).into(),
        nonce_caller: (tpm2::Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: tpm2::Handle::RH_NULL,
        bound_entity: Default::default(),
        audit_digest: Some([0u8; 64]),
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
        epoch: 0,
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
    global_state.add_session(audit_session).unwrap();

    let invalid_handles = [
        Handle::RH_OWNER,
        Handle::RH_PLATFORM,
        Handle::RH_LOCKOUT,
        Handle::RH_NULL,
    ];
    for &h in &invalid_handles {
        let get_audit_handles = GetSessionAuditDigestHandles {
            privacy_admin_handle: h,
            sign_handle: Handle(signer_handle),
            session_handle: Handle(audit_session_handle),
        };
        let res = execute_tpm_command_with_auths(
            &mut tpm,
            &mut global_state,
            &get_audit_handles,
            &get_audit_cmd,
            &[admin_auth, signer_auth],
        );
        assert_eq!(
            res.err(),
            Some(TpmRc::VALUE.with(Position::handle(1)).get()),
            "Expected handle {:?} to be rejected with TPM_RC_VALUE at Pos1",
            h
        );
    }

    // Verify valid handle: only RHEndorsement is allowed by TPMI_RH_ENDORSEMENT (non-nullable)
    let valid_handles = [Handle::RH_ENDORSEMENT];
    for &h in &valid_handles {
        let get_audit_handles = GetSessionAuditDigestHandles {
            privacy_admin_handle: h,
            sign_handle: Handle(signer_handle),
            session_handle: Handle(audit_session_handle),
        };
        let res = execute_tpm_command_with_auths(
            &mut tpm,
            &mut global_state,
            &get_audit_handles,
            &get_audit_cmd,
            &[admin_auth, signer_auth],
        );
        assert!(
            res.is_ok(),
            "Expected handle {:?} to be accepted, but got: {:?}",
            h,
            res.err()
        );
    }
}
