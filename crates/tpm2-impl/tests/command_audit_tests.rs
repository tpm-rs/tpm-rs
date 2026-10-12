mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::commands::{Command, GetCommandAuditDigest};
use tpm2::crypto::{
    Cmac, ConstantTimeEq, CryptoError, Direction, Ecc, EccPrivateKey, EccPublicKey, Hash, Hmac,
    Mldsa, Mlkem, ModeIv, Random, Rsa, RsaPrivateKey, RsaPublicKey, RsaSigScheme, Signing,
    Symmetric,
};
use tpm2::errors::TpmRc;
use tpm2::{
    Handle, Marshal, PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter,
    Tpm2bName, Tpm2bNonce, Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmEccCurve, TpmaObject,
    TpmaSession, TpmiAlgHash, TpmiRsaKeyBits, TpmsAuthCommand, TpmsEccPoint, TpmsRsaParms, TpmtHa,
    TpmtPublic,
};
use tpm2_impl::handler::TransientObject;
use tpm2_impl::owned::{OwnedPrivateKeyRsa, OwnedSensitiveComposite};
use tpm2_impl::{TpmEngine, TpmPlatform};

struct FakeRsaPub {
    bits: TpmiRsaKeyBits,
    exponent: u32,
    modulus: Vec<u8>,
}

impl RsaPublicKey for FakeRsaPub {
    fn bits(&self) -> TpmiRsaKeyBits {
        self.bits
    }

    fn exponent(&self) -> u32 {
        self.exponent
    }

    fn modulus<'a>(
        &self,
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
    ) -> Result<Tpm2bPublicKeyRsa<'a>, CryptoError> {
        out[..self.modulus.len()].copy_from_slice(&self.modulus);
        Tpm2bPublicKeyRsa::new(&out[..self.modulus.len()]).ok_or(CryptoError::Internal)
    }
}

struct FakeRsaPriv {
    public: FakeRsaPub,
    prime_p: Vec<u8>,
}

impl RsaPrivateKey for FakeRsaPriv {
    type PublicKey = FakeRsaPub;

    fn public_key(&self) -> &Self::PublicKey {
        &self.public
    }

    fn prime_p<'a>(
        &self,
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PRIV_KEY_BYTES],
    ) -> Result<Tpm2bPrivateKeyRsa<'a>, CryptoError> {
        out[..self.prime_p.len()].copy_from_slice(&self.prime_p);
        Tpm2bPrivateKeyRsa::new(&out[..self.prime_p.len()]).ok_or(CryptoError::Internal)
    }
}

struct FakeEccPub {
    curve: TpmEccCurve,
    x: Vec<u8>,
    y: Vec<u8>,
}

impl EccPublicKey for FakeEccPub {
    fn curve(&self) -> TpmEccCurve {
        self.curve
    }

    fn point<'a>(
        &self,
        out_x: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
        out_y: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    ) -> Result<TpmsEccPoint<'a>, CryptoError> {
        out_x[..self.x.len()].copy_from_slice(&self.x);
        out_y[..self.y.len()].copy_from_slice(&self.y);
        Ok(TpmsEccPoint {
            x: Tpm2bEccParameter::new(&out_x[..self.x.len()]).ok_or(CryptoError::Internal)?,
            y: Tpm2bEccParameter::new(&out_y[..self.y.len()]).ok_or(CryptoError::Internal)?,
        })
    }
}

struct FakeEccPriv {
    public: FakeEccPub,
    scalar: Vec<u8>,
}

impl EccPrivateKey for FakeEccPriv {
    type PublicKey = FakeEccPub;

    fn public_key(&self) -> &Self::PublicKey {
        &self.public
    }

    fn scalar<'a>(
        &self,
        out: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    ) -> Result<Tpm2bEccParameter<'a>, CryptoError> {
        out[..self.scalar.len()].copy_from_slice(&self.scalar);
        Tpm2bEccParameter::new(&out[..self.scalar.len()]).ok_or(CryptoError::Internal)
    }
}

struct AuditTestCrypto;

impl Random for AuditTestCrypto {
    type Rng = FakeRng;
    fn rng(&self) -> Result<FakeRng, CryptoError> {
        FakeCrypto.rng()
    }
    fn rng_seeded(&self, seed: &[u8]) -> Result<FakeRng, CryptoError> {
        FakeCrypto.rng_seeded(seed)
    }
}

impl Hash for AuditTestCrypto {
    type Sha1Context = <FakeCrypto as Hash>::Sha1Context;
    fn sha1(&self) -> Result<Self::Sha1Context, CryptoError> {
        Hash::sha1(&FakeCrypto)
    }
    type Sha256Context = <FakeCrypto as Hash>::Sha256Context;
    fn sha256(&self) -> Result<Self::Sha256Context, CryptoError> {
        Hash::sha256(&FakeCrypto)
    }
    type Sha384Context = <FakeCrypto as Hash>::Sha384Context;
    fn sha384(&self) -> Result<Self::Sha384Context, CryptoError> {
        Hash::sha384(&FakeCrypto)
    }
    type Sha512Context = <FakeCrypto as Hash>::Sha512Context;
    fn sha512(&self) -> Result<Self::Sha512Context, CryptoError> {
        Hash::sha512(&FakeCrypto)
    }
    type Sm3_256Context = <FakeCrypto as Hash>::Sm3_256Context;
    fn sm3_256(&self) -> Result<Self::Sm3_256Context, CryptoError> {
        Hash::sm3_256(&FakeCrypto)
    }
    type Sha3_256Context = <FakeCrypto as Hash>::Sha3_256Context;
    fn sha3_256(&self) -> Result<Self::Sha3_256Context, CryptoError> {
        Hash::sha3_256(&FakeCrypto)
    }
    type Sha3_384Context = <FakeCrypto as Hash>::Sha3_384Context;
    fn sha3_384(&self) -> Result<Self::Sha3_384Context, CryptoError> {
        Hash::sha3_384(&FakeCrypto)
    }
    type Sha3_512Context = <FakeCrypto as Hash>::Sha3_512Context;
    fn sha3_512(&self) -> Result<Self::Sha3_512Context, CryptoError> {
        Hash::sha3_512(&FakeCrypto)
    }
}

impl Hmac for AuditTestCrypto {
    type Sha1Context = <FakeCrypto as Hmac>::Sha1Context;
    fn sha1(&self, key: &[u8]) -> Result<Self::Sha1Context, CryptoError> {
        Hmac::sha1(&FakeCrypto, key)
    }
    type Sha256Context = <FakeCrypto as Hmac>::Sha256Context;
    fn sha256(&self, key: &[u8]) -> Result<Self::Sha256Context, CryptoError> {
        Hmac::sha256(&FakeCrypto, key)
    }
    type Sha384Context = <FakeCrypto as Hmac>::Sha384Context;
    fn sha384(&self, key: &[u8]) -> Result<Self::Sha384Context, CryptoError> {
        Hmac::sha384(&FakeCrypto, key)
    }
    type Sha512Context = <FakeCrypto as Hmac>::Sha512Context;
    fn sha512(&self, key: &[u8]) -> Result<Self::Sha512Context, CryptoError> {
        Hmac::sha512(&FakeCrypto, key)
    }
    type Sm3_256Context = <FakeCrypto as Hmac>::Sm3_256Context;
    fn sm3_256(&self, key: &[u8]) -> Result<Self::Sm3_256Context, CryptoError> {
        Hmac::sm3_256(&FakeCrypto, key)
    }
    type Sha3_256Context = <FakeCrypto as Hmac>::Sha3_256Context;
    fn sha3_256(&self, key: &[u8]) -> Result<Self::Sha3_256Context, CryptoError> {
        Hmac::sha3_256(&FakeCrypto, key)
    }
    type Sha3_384Context = <FakeCrypto as Hmac>::Sha3_384Context;
    fn sha3_384(&self, key: &[u8]) -> Result<Self::Sha3_384Context, CryptoError> {
        Hmac::sha3_384(&FakeCrypto, key)
    }
    type Sha3_512Context = <FakeCrypto as Hmac>::Sha3_512Context;
    fn sha3_512(&self, key: &[u8]) -> Result<Self::Sha3_512Context, CryptoError> {
        Hmac::sha3_512(&FakeCrypto, key)
    }
}

impl Cmac for AuditTestCrypto {
    type Aes128Context = <FakeCrypto as Cmac>::Aes128Context;
    fn aes128(&self, key: &[u8; 16]) -> Result<Self::Aes128Context, CryptoError> {
        Cmac::aes128(&FakeCrypto, key)
    }
    type Aes192Context = <FakeCrypto as Cmac>::Aes192Context;
    fn aes192(&self, key: &[u8; 24]) -> Result<Self::Aes192Context, CryptoError> {
        Cmac::aes192(&FakeCrypto, key)
    }
    type Aes256Context = <FakeCrypto as Cmac>::Aes256Context;
    fn aes256(&self, key: &[u8; 32]) -> Result<Self::Aes256Context, CryptoError> {
        Cmac::aes256(&FakeCrypto, key)
    }
    type Sm4_128Context = <FakeCrypto as Cmac>::Sm4_128Context;
    fn sm4_128(&self, key: &[u8; 16]) -> Result<Self::Sm4_128Context, CryptoError> {
        Cmac::sm4_128(&FakeCrypto, key)
    }
    type Camellia128Context = <FakeCrypto as Cmac>::Camellia128Context;
    fn camellia128(&self, key: &[u8; 16]) -> Result<Self::Camellia128Context, CryptoError> {
        Cmac::camellia128(&FakeCrypto, key)
    }
    type Camellia192Context = <FakeCrypto as Cmac>::Camellia192Context;
    fn camellia192(&self, key: &[u8; 24]) -> Result<Self::Camellia192Context, CryptoError> {
        Cmac::camellia192(&FakeCrypto, key)
    }
    type Camellia256Context = <FakeCrypto as Cmac>::Camellia256Context;
    fn camellia256(&self, key: &[u8; 32]) -> Result<Self::Camellia256Context, CryptoError> {
        Cmac::camellia256(&FakeCrypto, key)
    }
}

impl Symmetric for AuditTestCrypto {
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

impl Rsa for AuditTestCrypto {
    type PublicKey = FakeRsaPub;
    type PrivateKey = FakeRsaPriv;

    fn load_public(
        &self,
        bits: TpmiRsaKeyBits,
        exponent: u32,
        modulus: Tpm2bPublicKeyRsa<'_>,
    ) -> Result<Option<Self::PublicKey>, CryptoError> {
        Ok(Some(FakeRsaPub {
            bits,
            exponent: if exponent == 0 { 65537 } else { exponent },
            modulus: modulus.as_slice().to_vec(),
        }))
    }

    fn load_private(
        &self,
        public: Self::PublicKey,
        prime_p: Tpm2bPrivateKeyRsa<'_>,
    ) -> Result<Option<Self::PrivateKey>, CryptoError> {
        Ok(Some(FakeRsaPriv {
            public,
            prime_p: prime_p.as_slice().to_vec(),
        }))
    }
}

impl Ecc for AuditTestCrypto {
    type PublicKey = FakeEccPub;
    type PrivateKey = FakeEccPriv;

    fn load_public(
        &self,
        curve: TpmEccCurve,
        point: TpmsEccPoint<'_>,
    ) -> Result<Option<Self::PublicKey>, CryptoError> {
        Ok(Some(FakeEccPub {
            curve,
            x: point.x.as_slice().to_vec(),
            y: point.y.as_slice().to_vec(),
        }))
    }

    fn load_private(
        &self,
        public: Self::PublicKey,
        scalar: Tpm2bEccParameter<'_>,
    ) -> Result<Option<Self::PrivateKey>, CryptoError> {
        Ok(Some(FakeEccPriv {
            public,
            scalar: scalar.as_slice().to_vec(),
        }))
    }
}

impl Signing for AuditTestCrypto {
    fn rsa_sign<'a>(
        &self,
        _rng: &mut Self::Rng,
        _key: &<Self as Rsa>::PrivateKey,
        _scheme: RsaSigScheme,
        digest: TpmtHa<'_>,
        out: &'a mut [u8; TpmiRsaKeyBits::MAX_PUB_KEY_BYTES],
    ) -> Result<Tpm2bPublicKeyRsa<'a>, CryptoError> {
        out[..256].fill(0x5a);
        for (i, &b) in digest.digest().iter().enumerate() {
            out[i % 256] ^= b;
        }
        Tpm2bPublicKeyRsa::new(&out[..256]).ok_or(CryptoError::Internal)
    }
}

impl Mlkem for AuditTestCrypto {
    type PublicKey = !;
    type PrivateKey = !;
}

impl Mldsa for AuditTestCrypto {
    type PublicKey = !;
    type PrivateKey = !;
    type MuContext = !;
}

impl ConstantTimeEq for AuditTestCrypto {
    fn constant_time_eq<const N: usize>(&self, a: &[u8; N], b: &[u8; N]) -> bool {
        FakeCrypto.constant_time_eq(a, b)
    }
}

fn setup_tpm<'a>(
    crypto: &'a AuditTestCrypto,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
) -> (
    TpmEngine<'a, AuditTestCrypto, FakeStorage, FakeTimer>,
    tpm2_impl::GlobalState,
) {
    let platform = TpmPlatform::new(crypto, storage, timer, FakeRng::new());
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);
    global_state.nv_available = true;
    global_state.locality = 0;
    global_state.g_nv_ok = true;

    // Startup(CLEAR)
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    (tpm, global_state)
}

fn execute_tpm_get_command_audit_digest<'a>(
    tpm: &mut TpmEngine<'_, AuditTestCrypto, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &GetCommandAuditDigest,
    auths: &[TpmsAuthCommand],
    response_buf: &'a mut [u8],
) -> Result<<GetCommandAuditDigest<'static> as Command>::Response<'a>, u32> {
    let mut request_buf = [0u8; 16384];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(GetCommandAuditDigest::CMD_CODE.code()).to_be_bytes());

    for h in tpm2::Message::handles(cmd) {
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

    let mut cmd_buf = [0u8; GetCommandAuditDigest::MAX_SIZE];
    let cmd_len = cmd.marshal(&mut cmd_buf);
    request_buf[offset..offset + cmd_len].copy_from_slice(&cmd_buf.as_ref()[..cmd_len]);
    offset += cmd_len;
    let total_len = u32::try_from(offset).unwrap();
    request_buf[2..6].copy_from_slice(&total_len.to_be_bytes());

    let resp_size =
        tpm.execute_command_separate(global_state, &request_buf[..offset], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    if rc != 0 {
        return Err(rc);
    }

    let mut resp_offset = 10;
    if !auths.is_empty() {
        let param_size = usize::try_from(u32::from_be_bytes(
            response_buf[resp_offset..resp_offset + 4]
                .try_into()
                .unwrap(),
        ))
        .unwrap();
        resp_offset += 4;
        let mut param_slice: &'static [u8] =
            std::vec::Vec::leak(response_buf[resp_offset..resp_offset + param_size].to_vec());
        tpm2::UnmarshalMessage::unmarshal_with_handles([], &mut param_slice)
            .map_err(|_| TpmRc::FAILURE.get())
    } else {
        let mut param_slice: &'static [u8] =
            std::vec::Vec::leak(response_buf[resp_offset..resp_size].to_vec());
        tpm2::UnmarshalMessage::unmarshal_with_handles([], &mut param_slice)
            .map_err(|_| TpmRc::FAILURE.get())
    }
}

#[test]
fn test_get_command_audit_digest() {
    let crypto = AuditTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer::new();
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer);

    // Call GetCommandAuditDigest with sign_handle: RHNull
    let audit_cmd = GetCommandAuditDigest {
        privacy_handle: Handle::RH_ENDORSEMENT,
        sign_handle: Handle::RH_NULL,
        qualifying_data: Tpm2bData::default(),
        in_scheme: None,
    };

    let auths = [TpmsAuthCommand {
        session_handle: Handle(0x40000009),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::default(),
        hmac: Tpm2bAuth::default(),
    }];

    let mut response_buf = [0u8; 16384];
    let resp = execute_tpm_get_command_audit_digest(
        &mut tpm,
        &mut global_state,
        &audit_cmd,
        &auths,
        &mut response_buf,
    )
    .expect("GetCommandAuditDigest failed");

    let _ = resp.audit_info.0.magic;
}

#[test]
fn test_get_command_audit_digest_with_rsa_signing_key() {
    let crypto = AuditTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let platform = TpmPlatform::new(&crypto, &mut storage, &mut timer, FakeRng::new());

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    // Startup
    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut response = [0u8; 1024];
    tpm.execute_command_separate(&mut global_state, &startup_request[..], &mut response[..]);

    let key_handle = 0x80000001u32;
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
                key_bits: TpmiRsaKeyBits::Rsa2048,
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let obj = TransientObject {
        handle: key_handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::default()),
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

    let mut req = Vec::new();
    req.extend_from_slice(&hex!("8002"));
    req.extend_from_slice(&[0, 0, 0, 0]); // size placeholder
    req.extend_from_slice(&hex!("00000133")); // TPM_CC_GetCommandAuditDigest
    req.extend_from_slice(&0x4000000Bu32.to_be_bytes()); // RH_ENDORSEMENT
    req.extend_from_slice(&key_handle.to_be_bytes()); // signHandle
    // Auth size + 2 auth sessions (each: handle=40000009, nonce=0, attr=01, hmac=0)
    req.extend_from_slice(&hex!(
        "00000012 40000009 0000 01 0000 40000009 0000 01 0000"
    ));
    // qualifyingData
    req.extend_from_slice(&hex!("0003 616161"));
    // inScheme: RSASSA (0x0014) SHA1 (0x0004)
    req.extend_from_slice(&hex!("0014 0004"));

    let req_len = u32::try_from(req.len()).unwrap();
    req[2..6].copy_from_slice(&req_len.to_be_bytes());

    let mut response_buf = [0u8; 16384];
    tpm.execute_command_separate(&mut global_state, &req[..], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(rc, 0, "GetCommandAuditDigest failed with rc: 0x{:08x}", rc);
}

#[test]
fn test_get_command_audit_digest_with_zeroed_audit_hash_alg() {
    let crypto = AuditTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let platform = TpmPlatform::new(&crypto, &mut storage, &mut timer, FakeRng::new());

    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    global_state.init_zeroed();
    // Intentionally test with audit_hash_alg = 0
    global_state.audit_hash_alg = 0;
    tpm.init_storage(&mut global_state);

    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut response = [0u8; 1024];
    tpm.execute_command_separate(&mut global_state, &startup_request[..], &mut response[..]);

    let key_handle = 0x80000001u32;
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
                key_bits: TpmiRsaKeyBits::Rsa2048,
                exponent: 0,
            },
            Tpm2bPublicKeyRsa::default(),
        ),
    };
    let obj = TransientObject {
        handle: key_handle,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: (Tpm2bName::default()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: public.into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::default()),
        qualified_name: (Tpm2bName::default()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[0] = Some(obj);

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

    let req_len = u32::try_from(req.len()).unwrap();
    req[2..6].copy_from_slice(&req_len.to_be_bytes());

    let mut response_buf = [0u8; 16384];
    tpm.execute_command_separate(&mut global_state, &req[..], &mut response_buf[..]);

    let rc = u32::from_be_bytes(response_buf[6..10].try_into().unwrap());
    assert_eq!(
        rc, 0,
        "GetCommandAuditDigest should succeed without panic even if audit_hash_alg was 0, got rc: 0x{:08x}",
        rc
    );
}
