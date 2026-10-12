#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::marshal_to_slice;
use common::{FakeCrypto, FakeHashCtx, FakeHmacCtx, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::commands::{
    Certify, Command, GetCapability, GetSessionAuditDigest, Message, UnmarshalMessage,
};
use tpm2::crypto::{
    Cmac, ConstantTimeEq, CryptoError, Direction, Ecc, Hash, Hmac, Mldsa, Mlkem, ModeIv, Random,
    Rsa, RsaPrivateKey, RsaPublicKey, RsaSigScheme, Signing, Symmetric,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    AlgSym, Handle, Marshal, PublicParmsAndId, ResponseHeader, Tpm2bAuth, Tpm2bData, Tpm2bDigest,
    Tpm2bName, Tpm2bNonce, Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmCap, TpmPt, TpmSe, TpmaObject,
    TpmaSession, TpmiAlgCipherMode, TpmiAlgHash, TpmiAlgSymMode, TpmiRsaKeyBits, TpmiStCommandTag,
    TpmsAuthCommand, TpmsCapabilityData, TpmsRsaParms, TpmtHa, TpmtPublic, TpmtRsaScheme,
    TpmtSigScheme, TpmtSignature, TpmtSymDefObject, Unmarshal,
};
use tpm2_impl::TpmEngine;
use tpm2_impl::TpmPlatform;
use tpm2_impl::handler::TransientObject;
use tpm2_impl::owned::{OwnedPrivateKeyRsa, OwnedSensitiveComposite, OwnedSymKey};

struct StressTestCrypto;

struct DummyRsaKey;

impl RsaPublicKey for DummyRsaKey {
    fn bits(&self) -> TpmiRsaKeyBits {
        TpmiRsaKeyBits::Rsa2048
    }

    fn exponent(&self) -> u32 {
        0
    }

    fn modulus<'a>(
        &self,
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
    ) -> Result<Tpm2bPublicKeyRsa<'a>, CryptoError> {
        out[..256].fill(0xcc);
        Ok(Tpm2bPublicKeyRsa::new(&out[..256]).unwrap())
    }
}

impl RsaPrivateKey for DummyRsaKey {
    type PublicKey = DummyRsaKey;

    fn public_key(&self) -> &Self::PublicKey {
        self
    }

    fn prime_p<'a>(
        &self,
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES],
    ) -> Result<Tpm2bPrivateKeyRsa<'a>, CryptoError> {
        out[..128].fill(0xdd);
        Ok(Tpm2bPrivateKeyRsa::new(&out[..128]).unwrap())
    }
}

impl Random for StressTestCrypto {
    type Rng = FakeRng;
    fn rng(&self) -> Result<FakeRng, CryptoError> {
        FakeCrypto.rng()
    }
    fn rng_seeded(&self, seed: &[u8]) -> Result<FakeRng, CryptoError> {
        FakeCrypto.rng_seeded(seed)
    }
}

impl Hash for StressTestCrypto {
    type Sha1Context = FakeHashCtx;
    fn sha1(&self) -> Result<Self::Sha1Context, CryptoError> {
        Hash::sha1(&FakeCrypto)
    }
    type Sha256Context = FakeHashCtx;
    fn sha256(&self) -> Result<Self::Sha256Context, CryptoError> {
        Hash::sha256(&FakeCrypto)
    }
    type Sha384Context = FakeHashCtx;
    fn sha384(&self) -> Result<Self::Sha384Context, CryptoError> {
        Hash::sha384(&FakeCrypto)
    }
    type Sha512Context = FakeHashCtx;
    fn sha512(&self) -> Result<Self::Sha512Context, CryptoError> {
        Hash::sha512(&FakeCrypto)
    }
    type Sm3_256Context = FakeHashCtx;
    fn sm3_256(&self) -> Result<Self::Sm3_256Context, CryptoError> {
        Hash::sm3_256(&FakeCrypto)
    }
    type Sha3_256Context = FakeHashCtx;
    fn sha3_256(&self) -> Result<Self::Sha3_256Context, CryptoError> {
        Hash::sha3_256(&FakeCrypto)
    }
    type Sha3_384Context = FakeHashCtx;
    fn sha3_384(&self) -> Result<Self::Sha3_384Context, CryptoError> {
        Hash::sha3_384(&FakeCrypto)
    }
    type Sha3_512Context = FakeHashCtx;
    fn sha3_512(&self) -> Result<Self::Sha3_512Context, CryptoError> {
        Hash::sha3_512(&FakeCrypto)
    }
}

impl Hmac for StressTestCrypto {
    type Sha1Context = FakeHmacCtx;
    fn sha1(&self, key: &[u8]) -> Result<Self::Sha1Context, CryptoError> {
        Hmac::sha1(&FakeCrypto, key)
    }
    type Sha256Context = FakeHmacCtx;
    fn sha256(&self, key: &[u8]) -> Result<Self::Sha256Context, CryptoError> {
        Hmac::sha256(&FakeCrypto, key)
    }
    type Sha384Context = FakeHmacCtx;
    fn sha384(&self, key: &[u8]) -> Result<Self::Sha384Context, CryptoError> {
        Hmac::sha384(&FakeCrypto, key)
    }
    type Sha512Context = FakeHmacCtx;
    fn sha512(&self, key: &[u8]) -> Result<Self::Sha512Context, CryptoError> {
        Hmac::sha512(&FakeCrypto, key)
    }
    type Sm3_256Context = FakeHmacCtx;
    fn sm3_256(&self, key: &[u8]) -> Result<Self::Sm3_256Context, CryptoError> {
        Hmac::sm3_256(&FakeCrypto, key)
    }
    type Sha3_256Context = FakeHmacCtx;
    fn sha3_256(&self, key: &[u8]) -> Result<Self::Sha3_256Context, CryptoError> {
        Hmac::sha3_256(&FakeCrypto, key)
    }
    type Sha3_384Context = FakeHmacCtx;
    fn sha3_384(&self, key: &[u8]) -> Result<Self::Sha3_384Context, CryptoError> {
        Hmac::sha3_384(&FakeCrypto, key)
    }
    type Sha3_512Context = FakeHmacCtx;
    fn sha3_512(&self, key: &[u8]) -> Result<Self::Sha3_512Context, CryptoError> {
        Hmac::sha3_512(&FakeCrypto, key)
    }
}

impl Cmac for StressTestCrypto {
    type Aes128Context = FakeHmacCtx;
    fn aes128(&self, key: &[u8; 16]) -> Result<Self::Aes128Context, CryptoError> {
        Cmac::aes128(&FakeCrypto, key)
    }
    type Aes192Context = FakeHmacCtx;
    fn aes192(&self, key: &[u8; 24]) -> Result<Self::Aes192Context, CryptoError> {
        Cmac::aes192(&FakeCrypto, key)
    }
    type Aes256Context = FakeHmacCtx;
    fn aes256(&self, key: &[u8; 32]) -> Result<Self::Aes256Context, CryptoError> {
        Cmac::aes256(&FakeCrypto, key)
    }
    type Sm4_128Context = FakeHmacCtx;
    fn sm4_128(&self, key: &[u8; 16]) -> Result<Self::Sm4_128Context, CryptoError> {
        Cmac::sm4_128(&FakeCrypto, key)
    }
    type Camellia128Context = FakeHmacCtx;
    fn camellia128(&self, key: &[u8; 16]) -> Result<Self::Camellia128Context, CryptoError> {
        Cmac::camellia128(&FakeCrypto, key)
    }
    type Camellia192Context = FakeHmacCtx;
    fn camellia192(&self, key: &[u8; 24]) -> Result<Self::Camellia192Context, CryptoError> {
        Cmac::camellia192(&FakeCrypto, key)
    }
    type Camellia256Context = FakeHmacCtx;
    fn camellia256(&self, key: &[u8; 32]) -> Result<Self::Camellia256Context, CryptoError> {
        Cmac::camellia256(&FakeCrypto, key)
    }
}

impl Symmetric for StressTestCrypto {
    fn aes128(
        &self,
        key: &[u8; 16],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        Symmetric::aes128(&FakeCrypto, key, mode, dir, data)
    }
    fn aes192(
        &self,
        key: &[u8; 24],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        Symmetric::aes192(&FakeCrypto, key, mode, dir, data)
    }
    fn aes256(
        &self,
        key: &[u8; 32],
        mode: ModeIv<'_>,
        dir: Direction,
        data: &mut [u8],
    ) -> Result<(), CryptoError> {
        Symmetric::aes256(&FakeCrypto, key, mode, dir, data)
    }
}

impl Rsa for StressTestCrypto {
    type PublicKey = DummyRsaKey;
    type PrivateKey = DummyRsaKey;

    fn load_public(
        &self,
        _bits: TpmiRsaKeyBits,
        _exponent: u32,
        _modulus: Tpm2bPublicKeyRsa<'_>,
    ) -> Result<Option<Self::PublicKey>, CryptoError> {
        Ok(Some(DummyRsaKey))
    }

    fn load_private(
        &self,
        _public: Self::PublicKey,
        _prime_p: Tpm2bPrivateKeyRsa<'_>,
    ) -> Result<Option<Self::PrivateKey>, CryptoError> {
        Ok(Some(DummyRsaKey))
    }
}

impl Ecc for StressTestCrypto {
    type PublicKey = !;
    type PrivateKey = !;
}

impl Signing for StressTestCrypto {
    fn rsa_sign<'a>(
        &self,
        _rng: &mut Self::Rng,
        _key: &<Self as Rsa>::PrivateKey,
        _scheme: RsaSigScheme,
        _digest: TpmtHa<'_>,
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
    ) -> Result<Tpm2bPublicKeyRsa<'a>, CryptoError> {
        out[..256].fill(0xee);
        Ok(Tpm2bPublicKeyRsa::new(&out[..256]).unwrap())
    }
}

impl Mlkem for StressTestCrypto {
    type PublicKey = !;
    type PrivateKey = !;
}

impl Mldsa for StressTestCrypto {
    type PublicKey = !;
    type PrivateKey = !;
    type MuContext = !;
}

impl ConstantTimeEq for StressTestCrypto {
    fn constant_time_eq<const N: usize>(&self, a: &[u8; N], b: &[u8; N]) -> bool {
        FakeCrypto.constant_time_eq(a, b)
    }
}

fn setup_tpm<'a>(
    crypto: &'a StressTestCrypto,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
    rng: &'a FakeRng,
) -> (
    TpmEngine<'a, StressTestCrypto, FakeStorage, FakeTimer>,
    tpm2_impl::GlobalState,
) {
    let platform = TpmPlatform::new(crypto, storage, timer, rng.clone());
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state).unwrap();
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
    tpm: &mut TpmEngine<'_, StressTestCrypto, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &C,
    auths: &[TpmsAuthCommand],
) -> Result<(), u32>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    execute_tpm_command_with_corrupted_bytes(tpm, global_state, cmd, auths, |_| {})
}

fn execute_tpm_command_with_corrupted_bytes<C: Command>(
    tpm: &mut TpmEngine<'_, StressTestCrypto, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &C,
    auths: &[TpmsAuthCommand],
    corrupt_fn: impl FnOnce(&mut [u8]),
) -> Result<(), u32>
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

    for h in cmd.handles().as_ref() {
        request_buf[offset..offset + 4].copy_from_slice(&h.0.to_be_bytes());
        offset += 4;
    }

    if !auths.is_empty() {
        let auth_len_offset = offset;
        offset += 4;
        let auth_start = offset;
        for auth in auths {
            let mut auth_slice = [0u8; TpmsAuthCommand::MAX_SIZE];
            let auth_len = auth.marshal(&mut auth_slice);
            request_buf[offset..offset + auth_len].copy_from_slice(&auth_slice[..auth_len]);
            offset += auth_len;
        }
        let auth_len = u32::try_from(offset - auth_start).unwrap();
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    let payload_start = offset;
    offset += marshal_to_slice(cmd, &mut request_buf[offset..]);

    let total_size = u32::try_from(offset).unwrap();
    request_buf[2..6].copy_from_slice(&total_size.to_be_bytes());

    corrupt_fn(&mut request_buf[payload_start..offset]);

    let mut response_buf = [0u8; 16384];
    tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    Ok(())
}

fn execute_tpm_command_resp<C: Command>(
    tpm: &mut TpmEngine<'_, StressTestCrypto, FakeStorage, FakeTimer>,
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
            let mut auth_slice = [0u8; TpmsAuthCommand::MAX_SIZE];
            let auth_len = auth.marshal(&mut auth_slice);
            request_buf[offset..offset + auth_len].copy_from_slice(&auth_slice[..auth_len]);
            offset += auth_len;
        }
        let auth_len = u32::try_from(offset - auth_start).unwrap();
        request_buf[auth_len_offset..auth_len_offset + 4].copy_from_slice(&auth_len.to_be_bytes());
    }

    offset += marshal_to_slice(cmd, &mut request_buf[offset..]);
    let total_size = u32::try_from(offset).unwrap();
    request_buf[2..6].copy_from_slice(&total_size.to_be_bytes());

    let mut response_buf = [0u8; 16384];
    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);
    assert!(resp_size >= ResponseHeader::MAX_SIZE);

    let mut resp_slice: &'static [u8] = std::vec::Vec::leak(response_buf[..resp_size].to_vec());
    let resp_header = ResponseHeader::unmarshal(&mut resp_slice).unwrap();
    if let Err(rc) = resp_header.rc {
        return Err(rc.get());
    }

    let mut resp_handles = <C::Response<'static> as Message>::Handles::default();
    for h in resp_handles.as_mut() {
        *h = Handle::unmarshal(&mut resp_slice).map_err(|_| TpmRc::FAILURE.get())?;
    }

    if resp_header.tag == TpmiStCommandTag::Sessions {
        let param_size = usize::try_from(u32::unmarshal(&mut resp_slice).unwrap()).unwrap();
        let mut param_slice = &resp_slice[..param_size];
        C::Response::unmarshal_with_handles(resp_handles, &mut param_slice)
            .map_err(|_| TpmRc::FAILURE.get())
    } else {
        C::Response::unmarshal_with_handles(resp_handles, &mut resp_slice)
            .map_err(|_| TpmRc::FAILURE.get())
    }
}

#[test]
fn test_get_capability_stress_and_bounds() {
    let crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // 1. property_count = 0
    let cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FamilyIndicator),
        property_count: 0,
    };
    let resp = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &cmd, &[]);
    assert!(resp.is_ok());

    // 2. property_count = u32::MAX (should succeed, bounds to max properties)
    let cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FamilyIndicator),
        property_count: u32::MAX,
    };
    let resp = execute_tpm_command_resp(&mut tpm, &mut global_state, &cmd, &[])
        .expect("GetCapability with property_count=MAX failed");
    if let TpmsCapabilityData::TpmProperties(ref props) = resp.capability_data {
        assert!(!props.as_slice().is_empty());
        assert!(props.as_slice().len() <= tpm2::TpmlTaggedTpmProperty::CAP);
    } else {
        panic!("Expected TpmProperties");
    }

    // 3. Invalid capability (e.g. 0x9999) -> should return TPM_RC_VALUE (132 / 0x84)
    let cmd = GetCapability {
        capability: TpmCap::Algs,
        property: u32::from(TpmPt::FamilyIndicator),
        property_count: 5,
    };
    let res = execute_tpm_command_with_corrupted_bytes::<GetCapability>(
        &mut tpm,
        &mut global_state,
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
    let crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let certified_handle = 0x80000001;
    let signer_handle = 0x80000002;

    // Load certified object
    let certified_obj = TransientObject {
        handle: certified_handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: (Tpm2bName::new(&[1, 2, 3]).unwrap()).into(),
        auth: (Tpm2bAuth::new(&[0x11, 0x22]).unwrap()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: None,
                    key_bits: TpmiRsaKeyBits::Rsa2048,
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::default(),
            ),
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::default()),
        qualified_name: (Tpm2bName::new(&[1, 2, 3]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(certified_obj);

    let certified_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bAuth::new(&[0x11, 0x22]).unwrap(),
    };

    let certified_empty_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bAuth::default(),
    };

    let signer_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bAuth::default(),
    };

    // 1. Certified object invalid handle -> should fail with TpmRc::REFERENCE_H0
    let cmd = Certify {
        object_handle: Handle(0x80000009),
        sign_handle: Handle(0x40000007),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let res =
        execute_tpm_command_with_auths(&mut tpm, &mut global_state, &cmd, &[certified_empty_auth]);
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H0.get()));

    // 2. Sign key invalid handle -> should fail with TpmRc::REFERENCE_H1
    let cmd = Certify {
        object_handle: Handle(certified_handle),
        sign_handle: Handle(0x80000009),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &cmd,
        &[certified_auth, signer_auth],
    );
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H1.get()));

    // 3. Load a signer key that is NOT a signing key (lacks SIGN_ENCRYPT attribute)
    let bad_signer_obj = TransientObject {
        handle: signer_handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: (Tpm2bName::new(&[4, 5, 6]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::DECRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: None,
                    key_bits: TpmiRsaKeyBits::Rsa2048,
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::default(),
            ),
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::default()),
        qualified_name: (Tpm2bName::new(&[4, 5, 6]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[1] = Some(bad_signer_obj);

    let cmd = Certify {
        object_handle: Handle(certified_handle),
        sign_handle: Handle(signer_handle),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &cmd,
        &[certified_auth, signer_auth],
    );
    assert_eq!(res.err(), Some(TpmRc::KEY.get()));

    // 4. Load a signer key that has incorrect key type (Symmetric key instead of Asymmetric key)
    let sym_signer_obj = TransientObject {
        handle: signer_handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: (Tpm2bName::new(&[4, 5, 6]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Sym(
                TpmtSymDefObject {
                    alg: AlgSym::Aes128,
                    mode: Some(TpmiAlgSymMode::Cipher(TpmiAlgCipherMode::Cfb)),
                },
                Tpm2bDigest::default(),
            ),
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Sym(OwnedSymKey::from_bytes(&[0u8; 16]).unwrap()),
        qualified_name: (Tpm2bName::new(&[4, 5, 6]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[1] = Some(sym_signer_obj);

    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &cmd,
        &[certified_auth, signer_auth],
    );
    assert_eq!(res.err(), Some(TpmRc::KEY.get()));
}

#[test]
fn test_certify_signature_schemes() {
    let crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let certified_handle = 0x80000001;
    let signer_handle = 0x80000002;

    // Load certified object
    let certified_obj = TransientObject {
        handle: certified_handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: (Tpm2bName::new(&[1, 2, 3]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: None,
                    key_bits: TpmiRsaKeyBits::Rsa2048,
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::default(),
            ),
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::default()),
        qualified_name: (Tpm2bName::new(&[1, 2, 3]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(certified_obj);

    // 1. Signer key with fixed scheme RSASSA SHA256
    let signer_obj = TransientObject {
        handle: signer_handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: (Tpm2bName::new(&[4, 5, 6]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                    key_bits: TpmiRsaKeyBits::Rsa2048,
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::default(),
            ),
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::default()),
        qualified_name: (Tpm2bName::new(&[4, 5, 6]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[1] = Some(signer_obj);

    let certified_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bAuth::default(),
    };
    let signer_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bAuth::default(),
    };

    // 1.1 Requesting Null scheme should resolve to fixed scheme (RSASSA SHA256) -> Success
    let cmd = Certify {
        object_handle: Handle(certified_handle),
        sign_handle: Handle(signer_handle),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let resp = execute_tpm_command_resp(
        &mut tpm,
        &mut global_state,
        &cmd,
        &[certified_auth, signer_auth],
    )
    .expect("Certify with Null scheme failed");
    assert!(matches!(resp.signature, Some(TpmtSignature::Rsassa(..))));

    // 1.2 Requesting RSAPSS scheme should fail since key scheme is fixed to RSASSA -> TpmRc::SCHEME
    let cmd = Certify {
        object_handle: Handle(certified_handle),
        sign_handle: Handle(signer_handle),
        qualifying_data: Tpm2bData::default(),
        in_scheme: Some(TpmtSigScheme::Rsapss(TpmiAlgHash::Sha256)),
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &cmd,
        &[certified_auth, signer_auth],
    );
    assert_eq!(res.err(), Some(TpmRc::SCHEME.get()));

    // 1.3 Requesting RSASSA SHA384 (different hash) should fail -> TpmRc::SCHEME
    let cmd = Certify {
        object_handle: Handle(certified_handle),
        sign_handle: Handle(signer_handle),
        qualifying_data: Tpm2bData::default(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha384)),
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &cmd,
        &[certified_auth, signer_auth],
    );
    assert_eq!(res.err(), Some(TpmRc::SCHEME.get()));

    // 2. Restricted signer key
    let restricted_signer_obj = TransientObject {
        handle: signer_handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: (Tpm2bName::new(&[4, 5, 6]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT
                | TpmaObject::RESTRICTED
                | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                    key_bits: TpmiRsaKeyBits::Rsa2048,
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::default(),
            ),
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::default()),
        qualified_name: (Tpm2bName::new(&[4, 5, 6]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[1] = Some(restricted_signer_obj);

    // 2.1 Restricted key scheme hash MUST match name_alg (SHA256) -> Success
    let cmd = Certify {
        object_handle: Handle(certified_handle),
        sign_handle: Handle(signer_handle),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let resp = execute_tpm_command_resp(
        &mut tpm,
        &mut global_state,
        &cmd,
        &[certified_auth, signer_auth],
    )
    .expect("Certify with restricted key failed");
    assert!(matches!(resp.signature, Some(TpmtSignature::Rsassa(..))));
}

#[test]
fn test_get_session_audit_digest_errors() {
    let crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    let signer_handle = 0x80000001;

    // Load signer object with fixed scheme RSASSA SHA256
    let signer_obj = TransientObject {
        handle: signer_handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: (Tpm2bName::new(&[1, 2, 3]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                    key_bits: TpmiRsaKeyBits::Rsa2048,
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::default(),
            ),
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::default()),
        qualified_name: (Tpm2bName::new(&[1, 2, 3]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(signer_obj);

    // Create an active session
    let audit_session_handle = 0x02000001;
    let session = tpm2_impl::handler::SessionState {
        session_handle: audit_session_handle,
        session_type: TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::default()).into(),
        nonce_caller: (Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: Handle::RH_NULL,
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
    };
    global_state.add_session(session).unwrap();

    let admin_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bAuth::default(),
    };
    let signer_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bAuth::default(),
    };

    // 1. Session handle invalid -> should fail with TpmRc::HANDLE at H3
    let cmd = GetSessionAuditDigest {
        privacy_admin_handle: Handle(0x4000000B),
        sign_handle: Handle(signer_handle),
        session_handle: Handle(0x02000009),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &cmd,
        &[admin_auth, signer_auth],
    );
    assert_eq!(
        res.err(),
        Some(TpmRc::HANDLE.with(Position::handle(3)).get())
    );

    // 2. Sign handle invalid -> should fail with TpmRc::REFERENCE_H1
    let cmd = GetSessionAuditDigest {
        privacy_admin_handle: Handle(0x4000000B),
        sign_handle: Handle(0x80000009),
        session_handle: Handle(audit_session_handle),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &cmd,
        &[admin_auth, signer_auth],
    );
    assert_eq!(res.err(), Some(TpmRc::REFERENCE_H1.get()));

    // 3. Valid params -> Success
    let cmd = GetSessionAuditDigest {
        privacy_admin_handle: Handle(0x4000000B),
        sign_handle: Handle(signer_handle),
        session_handle: Handle(audit_session_handle),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let resp = execute_tpm_command_resp(
        &mut tpm,
        &mut global_state,
        &cmd,
        &[admin_auth, signer_auth],
    )
    .expect("GetSessionAuditDigest failed");
    assert!(matches!(resp.signature, Some(TpmtSignature::Rsassa(..))));

    // 4. Session exists but is not an audit session (no audit digest) -> type_for(Handle, Pos3) (0x38A)
    let non_audit_session_handle = 0x02000002;
    let non_audit_session = tpm2_impl::handler::SessionState {
        session_handle: non_audit_session_handle,
        session_type: TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::default()).into(),
        nonce_caller: (Tpm2bNonce::default()).into(),
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
    };
    global_state.add_session(non_audit_session).unwrap();

    let cmd = GetSessionAuditDigest {
        privacy_admin_handle: Handle(0x4000000B),
        sign_handle: Handle(signer_handle),
        session_handle: Handle(non_audit_session_handle),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
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

    let state_len = 32 + 32 + nonce_tpm.len() + 1;

    for i in 0..32 {
        hmac[i] ^= digest[i];
    }
    for (i, &b) in nonce_tpm.iter().enumerate() {
        hmac[i % 32] ^= b;
    }
    hmac[(32 + 32 + nonce_tpm.len()) % 32] ^= attributes;
    hmac[1] ^= state_len.to_le_bytes()[0];

    Tpm2bAuth::new(std::vec::Vec::leak(hmac.to_vec())).unwrap()
}

#[test]
fn test_challenger_audit_reset_and_format1_errors() {
    let crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // 1. Verify AUDIT_RESET behavior
    let audit_session_handle = 0x02000001;
    let session = tpm2_impl::handler::SessionState {
        session_handle: audit_session_handle,
        session_type: TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::default()).into(),
        nonce_caller: (Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: Handle::RH_NULL,
        bound_entity: Default::default(),
        audit_digest: Some([0xab; 64]),
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
    };
    global_state.add_session(session).unwrap();

    // Send GetCapability with continueSession (0x01) | audit (0x80)
    let cmd = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FamilyIndicator),
        property_count: 1,
    };
    let hmac = compute_mock_hmac(0x81, &[]);
    let auth = TpmsAuthCommand {
        session_handle: Handle(audit_session_handle),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::from_bits_retain(0x81),
        hmac,
    };
    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &cmd, &[auth])
        .expect("Command failed");

    // Verify audit digest is NOT reset (remains 0xab)
    let s = global_state.session(audit_session_handle).unwrap();
    assert_eq!(s.audit_digest.unwrap()[0], 0xab);

    // Send GetCapability with continueSession | auditReset (0x85)
    let nonce_tpm_1 = global_state
        .session(audit_session_handle)
        .unwrap()
        .nonce_tpm;
    let hmac = compute_mock_hmac(0x85, nonce_tpm_1.get_buffer());
    let auth = TpmsAuthCommand {
        session_handle: Handle(audit_session_handle),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::from_bits_retain(0x85),
        hmac,
    };
    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &cmd, &[auth])
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
    let get_audit_cmd = GetSessionAuditDigest {
        privacy_admin_handle: Handle(0),
        sign_handle: Handle(0x40000007),
        session_handle: Handle(audit_session_handle),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let admin_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bAuth::default(),
    };
    let res =
        execute_tpm_command_with_auths(&mut tpm, &mut global_state, &get_audit_cmd, &[admin_auth]);
    assert_eq!(
        res.as_ref().err(),
        Some(&TpmRc::VALUE.with(Position::handle(1)).get())
    );
    assert_eq!(res.err(), Some(0x184));
}

#[test]
fn test_challenger_remediation_stress_cases() {
    let crypto = StressTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let rng = FakeRng::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer, &rng);

    // 1. GetCapability Handles with property_count = 0
    let obj1 = TransientObject {
        handle: 0x80000001,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: (Tpm2bName::new(&[1, 2, 3]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: None,
                    key_bits: TpmiRsaKeyBits::Rsa2048,
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::default(),
            ),
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::default()),
        qualified_name: (Tpm2bName::new(&[1, 2, 3]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj1);

    let cmd = GetCapability {
        capability: TpmCap::Handles,
        property: 0x80000000,
        property_count: 0,
    };
    let resp = execute_tpm_command_with_auths(&mut tpm, &mut global_state, &cmd, &[]);
    assert!(resp.is_ok());

    // 2. Session exclusivity tracking
    let session_handle_1 = 0x02000001;
    let session_handle_2 = 0x02000002;

    let session_1 = tpm2_impl::handler::SessionState {
        session_handle: session_handle_1,
        session_type: TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::default()).into(),
        nonce_caller: (Tpm2bNonce::default()).into(),
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
    };
    let session_2 = tpm2_impl::handler::SessionState {
        session_handle: session_handle_2,
        session_type: TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::default()).into(),
        nonce_caller: (Tpm2bNonce::default()).into(),
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
    };
    global_state.add_session(session_1).unwrap();
    global_state.add_session(session_2).unwrap();

    // 2.1 Execute command with Session 1 (AUDIT set) -> sets exclusivity
    let cmd_get_cap = GetCapability {
        capability: TpmCap::TPMProperties,
        property: u32::from(TpmPt::FamilyIndicator),
        property_count: 1,
    };
    let hmac_1 = compute_mock_hmac(0x81, &[]);
    let auth_1 = TpmsAuthCommand {
        session_handle: Handle(session_handle_1),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::from_bits_retain(0x81),
        hmac: hmac_1,
    };
    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &cmd_get_cap, &[auth_1]).unwrap();
    assert_eq!(global_state.exclusive_audit_session, Some(session_handle_1));

    // 2.2 Execute command with Session 2 (AUDIT set) -> changes exclusivity
    let nonce_tpm_2 = global_state.session(session_handle_2).unwrap().nonce_tpm;
    let hmac_2 = compute_mock_hmac(0x81, nonce_tpm_2.get_buffer());
    let auth_2 = TpmsAuthCommand {
        session_handle: Handle(session_handle_2),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::from_bits_retain(0x81),
        hmac: hmac_2,
    };
    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &cmd_get_cap, &[auth_2]).unwrap();
    assert_eq!(global_state.exclusive_audit_session, Some(session_handle_2));

    // 2.3 Execute command with Session 1 and Session 2 (both AUDIT set) -> fails with TPM_RC_ATTRIBUTES on session 2 (0xA82)
    let nonce_tpm_1 = global_state.session(session_handle_1).unwrap().nonce_tpm;
    let nonce_tpm_2 = global_state.session(session_handle_2).unwrap().nonce_tpm;
    let hmac_1 = compute_mock_hmac(0x81, nonce_tpm_1.get_buffer());
    let hmac_2 = compute_mock_hmac(0x81, nonce_tpm_2.get_buffer());
    let auth_1 = TpmsAuthCommand {
        session_handle: Handle(session_handle_1),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::from_bits_retain(0x81),
        hmac: hmac_1,
    };
    let auth_2 = TpmsAuthCommand {
        session_handle: Handle(session_handle_2),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::from_bits_retain(0x81),
        hmac: hmac_2,
    };
    let resp = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &cmd_get_cap,
        &[auth_1, auth_2],
    );
    assert_eq!(resp.err(), Some(0xA82));
    assert_eq!(global_state.exclusive_audit_session, Some(session_handle_2));

    // 2.4 Execute command with Session 1 (AUDIT and AUDIT_RESET set) -> regain exclusivity
    let nonce_tpm_1 = global_state.session(session_handle_1).unwrap().nonce_tpm;
    let hmac_1 = compute_mock_hmac(0x85, nonce_tpm_1.get_buffer());
    let auth_1 = TpmsAuthCommand {
        session_handle: Handle(session_handle_1),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::from_bits_retain(0x85),
        hmac: hmac_1,
    };
    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &cmd_get_cap, &[auth_1]).unwrap();
    assert_eq!(global_state.exclusive_audit_session, Some(session_handle_1));

    // 2.5 Execute command WITHOUT sessions -> exclusivity lost
    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &cmd_get_cap, &[]).unwrap();
    assert_eq!(global_state.exclusive_audit_session, None);

    // 2.6 Regain exclusivity with Session 1 (AUDIT and AUDIT_RESET set)
    let nonce_tpm_1 = global_state.session(session_handle_1).unwrap().nonce_tpm;
    let hmac_1 = compute_mock_hmac(0x85, nonce_tpm_1.get_buffer());
    let auth_1 = TpmsAuthCommand {
        session_handle: Handle(session_handle_1),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::from_bits_retain(0x85),
        hmac: hmac_1,
    };
    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &cmd_get_cap, &[auth_1]).unwrap();
    assert_eq!(global_state.exclusive_audit_session, Some(session_handle_1));

    // 2.7 Session completion (continueSession = 0) -> exclusivity lost
    let nonce_tpm_1 = global_state.session(session_handle_1).unwrap().nonce_tpm;
    let hmac_1 = compute_mock_hmac(0x80, nonce_tpm_1.get_buffer());
    let auth_1 = TpmsAuthCommand {
        session_handle: Handle(session_handle_1),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::from_bits_retain(0x80),
        hmac: hmac_1,
    };
    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &cmd_get_cap, &[auth_1]).unwrap();
    assert_eq!(global_state.exclusive_audit_session, None);
    assert!(global_state.session(session_handle_1).is_none());

    // Re-add Session 1
    let session_1 = tpm2_impl::handler::SessionState {
        session_handle: session_handle_1,
        session_type: TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::default()).into(),
        nonce_caller: (Tpm2bNonce::default()).into(),
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
    };
    global_state.add_session(session_1).unwrap();

    // Regain exclusivity
    let nonce_tpm_1 = global_state.session(session_handle_1).unwrap().nonce_tpm;
    let hmac_1 = compute_mock_hmac(0x81, nonce_tpm_1.get_buffer());
    let auth_1 = TpmsAuthCommand {
        session_handle: Handle(session_handle_1),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::from_bits_retain(0x81),
        hmac: hmac_1,
    };
    execute_tpm_command_with_auths(&mut tpm, &mut global_state, &cmd_get_cap, &[auth_1]).unwrap();
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

    // 3. Non-audit sessions return TPM_RC_TYPE
    let session_handle_3 = 0x02000003;
    let session_3 = tpm2_impl::handler::SessionState {
        session_handle: session_handle_3,
        session_type: TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::default()).into(),
        nonce_caller: (Tpm2bNonce::default()).into(),
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
    };
    global_state.add_session(session_3).unwrap();

    let signer_handle = 0x80000002;
    let signer_obj = TransientObject {
        handle: signer_handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: (Tpm2bName::new(&[4, 5, 6]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                    key_bits: TpmiRsaKeyBits::Rsa2048,
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::default(),
            ),
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::default()),
        qualified_name: (Tpm2bName::new(&[4, 5, 6]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[1] = Some(signer_obj);

    let get_audit_cmd = GetSessionAuditDigest {
        privacy_admin_handle: Handle::RH_ENDORSEMENT,
        sign_handle: Handle(signer_handle),
        session_handle: Handle(session_handle_3),
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };
    let admin_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bAuth::default(),
    };
    let signer_auth = TpmsAuthCommand {
        session_handle: Handle::RS_PW,
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::CONTINUE_SESSION,
        hmac: Tpm2bAuth::default(),
    };
    let res = execute_tpm_command_with_auths(
        &mut tpm,
        &mut global_state,
        &get_audit_cmd,
        &[admin_auth, signer_auth],
    );
    assert_eq!(res.err(), Some(TpmRc::TYPE.with(Position::handle(3)).get()));

    // 4. privacy_admin_handle validation restricts to endorsement hierarchy
    let audit_session_handle = 0x02000004;
    let audit_session = tpm2_impl::handler::SessionState {
        session_handle: audit_session_handle,
        session_type: TpmSe::HMAC,
        auth_hash: TpmiAlgHash::Sha256,
        nonce_tpm: (Tpm2bNonce::default()).into(),
        nonce_caller: (Tpm2bNonce::default()).into(),
        session_key: [0; 128],
        session_key_len: 32,
        symmetric: None,
        bind_entity: Handle::RH_NULL,
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
    };
    global_state.add_session(audit_session).unwrap();

    let invalid_handles = [
        Handle::RH_OWNER,
        Handle::RH_PLATFORM,
        Handle::RH_LOCKOUT,
        Handle::RH_NULL,
    ];
    for &h in &invalid_handles {
        let get_audit_cmd = GetSessionAuditDigest {
            privacy_admin_handle: h,
            sign_handle: Handle(signer_handle),
            session_handle: Handle(audit_session_handle),
            qualifying_data: Tpm2bData::default(),
            in_scheme: None,
        };
        let res = execute_tpm_command_with_auths(
            &mut tpm,
            &mut global_state,
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

    let valid_handles = [Handle::RH_ENDORSEMENT];
    for &h in &valid_handles {
        let get_audit_cmd = GetSessionAuditDigest {
            privacy_admin_handle: h,
            sign_handle: Handle(signer_handle),
            session_handle: Handle(audit_session_handle),
            qualifying_data: Tpm2bData::default(),
            in_scheme: None,
        };
        let res = execute_tpm_command_with_auths(
            &mut tpm,
            &mut global_state,
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
