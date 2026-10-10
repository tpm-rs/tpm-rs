mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::commands::{Certify, Command};
use tpm2::crypto::{
    Cmac, ConstantTimeEq, CryptoError, Direction, Ecc, EccPrivateKey, EccPublicKey, EccSigScheme,
    Hash, Hmac, Mldsa, Mlkem, ModeIv, Random, Rsa, RsaPrivateKey, RsaPublicKey, RsaSigScheme,
    Signing, Symmetric,
};
use tpm2::errors::TpmRc;
use tpm2::{
    Handle, Marshal, PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter,
    Tpm2bName, Tpm2bNonce, Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmEccCurve, TpmaObject,
    TpmaSession, TpmiAlgHash, TpmiRsaKeyBits, TpmsAuthCommand, TpmsEccParms, TpmsEccPoint,
    TpmsRsaParms, TpmsSchemeEcdaa, TpmtEccScheme, TpmtHa, TpmtPublic, TpmtRsaScheme, TpmtSigScheme,
    TpmuAttest,
};
use tpm2_impl::handler::{CommandHandler, TransientObject};
use tpm2_impl::owned::{
    OwnedEccParameter, OwnedPrivateKeyRsa, OwnedSensitiveComposite, OwnedSensitiveData,
};
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

struct CertifyTestCrypto;

impl Random for CertifyTestCrypto {
    type Rng = FakeRng;
    fn rng(&self) -> Result<FakeRng, CryptoError> {
        FakeCrypto.rng()
    }
    fn rng_seeded(&self, seed: &[u8]) -> Result<FakeRng, CryptoError> {
        FakeCrypto.rng_seeded(seed)
    }
}

impl Hash for CertifyTestCrypto {
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

impl Hmac for CertifyTestCrypto {
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

impl Cmac for CertifyTestCrypto {
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

impl Symmetric for CertifyTestCrypto {
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

impl Rsa for CertifyTestCrypto {
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

impl Ecc for CertifyTestCrypto {
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

impl Signing for CertifyTestCrypto {
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

    fn ecc_sign<'a>(
        &self,
        _rng: &mut Self::Rng,
        _key: &<Self as Ecc>::PrivateKey,
        scheme: EccSigScheme,
        digest: TpmtHa<'_>,
        out_r: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
        out_s: &'a mut [u8; TpmEccCurve::MAX_ECC_KEY_BYTES],
    ) -> Result<(Tpm2bEccParameter<'a>, Tpm2bEccParameter<'a>), CryptoError> {
        match scheme {
            EccSigScheme::Ecdaa(_) => {
                out_r[..32].fill(0);
                out_s[..32].fill(0);
            }
            _ => {
                out_r[..32].fill(0x5a);
                out_s[..32].fill(0x5a);
                for (i, &b) in digest.digest().iter().enumerate() {
                    out_r[i % 32] ^= b;
                }
            }
        }
        let r = Tpm2bEccParameter::new(&out_r[..32]).ok_or(CryptoError::Internal)?;
        let s = Tpm2bEccParameter::new(&out_s[..32]).ok_or(CryptoError::Internal)?;
        Ok((r, s))
    }
}

impl Mlkem for CertifyTestCrypto {
    type PublicKey = !;
    type PrivateKey = !;
}

impl Mldsa for CertifyTestCrypto {
    type PublicKey = !;
    type PrivateKey = !;
    type MuContext = !;
}

impl ConstantTimeEq for CertifyTestCrypto {
    fn constant_time_eq<const N: usize>(&self, a: &[u8; N], b: &[u8; N]) -> bool {
        FakeCrypto.constant_time_eq(a, b)
    }
}

fn setup_tpm<'a>(
    crypto: &'a CertifyTestCrypto,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
) -> (
    TpmEngine<'a, CertifyTestCrypto, FakeStorage, FakeTimer>,
    tpm2_impl::GlobalState,
) {
    let platform = TpmPlatform::new(crypto, storage, timer, FakeRng::new());
    let mut tpm = TpmEngine::new(platform).unwrap();
    let mut global_state = tpm2_impl::GlobalState::default();
    tpm.init_storage(&mut global_state);

    let startup_request = hex!("8001 0000000c 00000144 0000");
    let mut startup_response = [0u8; 256];
    tpm.execute_command_separate(
        &mut global_state,
        &startup_request[..],
        &mut startup_response[..],
    );
    (tpm, global_state)
}

fn execute_tpm_certify<'a>(
    tpm: &mut TpmEngine<'_, CertifyTestCrypto, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &Certify,
    auths: &[TpmsAuthCommand],
    response_buf: &'a mut [u8; 32768],
) -> Result<<Certify<'static> as Command>::Response<'a>, u32> {
    let mut request_buf = [0u8; 32768];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(Certify::CMD_CODE.code()).to_be_bytes());

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

    let mut cmd_buf = [0u8; Certify::MAX_SIZE];
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
    let resp_tag = u16::from_be_bytes([response_buf[0], response_buf[1]]);
    if resp_tag == 0x8002 {
        resp_offset += 4; // Skip parameter size
    }

    let mut params_slice = &response_buf[resp_offset..resp_size];
    tpm2::UnmarshalMessage::unmarshal_with_handles([], &mut params_slice)
        .map_err(|_| TpmRc::FAILURE.get())
}

#[test]
fn test_certify_qualified_name_and_signer_exact_accumulation() {
    let crypto = CertifyTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let signer_handle = Handle(0x80000002);
    let signer_qn = Tpm2bName::new(&[10, 11, 12, 13]).unwrap();
    let signer_obj = TransientObject {
        handle: signer_handle.0,
        seed: [0u8; 32],
        name: (Tpm2bName::new(&[4, 5, 6]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::RESTRICTED
                | TpmaObject::SIGN_ENCRYPT
                | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                    key_bits: TpmiRsaKeyBits::Rsa2048,
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::new(&[1, 2, 3]).unwrap(),
            ),
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::default()),
        qualified_name: (signer_qn).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };

    let certified_handle = Handle(0x80000003);
    let certified_qn = Tpm2bName::new(&[20, 21, 22, 23]).unwrap();
    let certified_obj = TransientObject {
        handle: certified_handle.0,
        seed: [0u8; 32],
        name: (Tpm2bName::new(&[7, 8, 9]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: None,
                    key_bits: TpmiRsaKeyBits::Rsa2048,
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::new(&[4, 5, 6]).unwrap(),
            ),
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::default()),
        qualified_name: (certified_qn).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };

    global_state.transient_objects[0] = Some(signer_obj.clone());
    global_state.transient_parents[0] = Some(0x40000001);
    global_state.transient_objects[1] = Some(certified_obj.clone());
    global_state.transient_parents[1] = Some(0x40000001);

    let cmd = Certify {
        object_handle: certified_handle,
        sign_handle: signer_handle,
        qualifying_data: Tpm2bData::new(&[99, 100]).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
    };

    let auths = [
        TpmsAuthCommand {
            session_handle: Handle(0x40000009),
            nonce: Tpm2bNonce::default(),
            session_attributes: TpmaSession::default(),
            hmac: Tpm2bAuth::default(),
        },
        TpmsAuthCommand {
            session_handle: Handle(0x40000009),
            nonce: Tpm2bNonce::default(),
            session_attributes: TpmaSession::default(),
            hmac: Tpm2bAuth::default(),
        },
    ];

    let mut response_buf = [0u8; 32768];
    let resp =
        execute_tpm_certify(&mut tpm, &mut global_state, &cmd, &auths, &mut response_buf).unwrap();
    let attest = resp.certify_info.0;
    let _ = attest.magic;
    assert_eq!(attest.qualified_signer.as_slice(), signer_qn.as_slice());

    if let TpmuAttest::Certify(cert_info) = attest.attested {
        assert_eq!(cert_info.name.as_slice(), certified_obj.name.get_buffer());
        assert_eq!(cert_info.qualified_name.as_slice(), certified_qn.as_slice());
    } else {
        panic!("Expected TpmuAttest::Certify");
    }
}

#[test]
fn test_aliased_primary_object_hierarchy_synchronization_in_certify() {
    let crypto = CertifyTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let primary_handle_1 = 0x80000000u32;
    let rsa_child_handle = Handle(0x80000001u32);
    let certified_handle = Handle(0x80000002u32);
    let primary_handle_2 = 0x80000004u32;

    let primary_name = Tpm2bName::new(&[0x00, 0x0b, 0x01, 0x02, 0x03, 0x04]).unwrap();
    let primary_qn_1 = Tpm2bName::new(&[0x00, 0x0b, 0x11, 0x22, 0x33, 0x44]).unwrap();
    let rsa_child_name = Tpm2bName::new(&[0x00, 0x0b, 0x05, 0x06, 0x07, 0x08]).unwrap();
    let certified_name = Tpm2bName::new(&[0x00, 0x0b, 0x09, 0x0a, 0x0b, 0x0c]).unwrap();

    let (initial_child_qn, certified_qn) = {
        let handler = CommandHandler::new(&mut tpm, &mut global_state);
        let qn1 = handler
            .compute_qualified_name(
                Some(TpmiAlgHash::Sha256),
                primary_qn_1.as_slice(),
                rsa_child_name.as_slice(),
            )
            .unwrap();
        let qn2 = handler
            .compute_qualified_name(
                Some(TpmiAlgHash::Sha256),
                primary_qn_1.as_slice(),
                certified_name.as_slice(),
            )
            .unwrap();
        (qn1, qn2)
    };

    let primary_obj_1 = TransientObject {
        handle: primary_handle_1,
        seed: [0u8; 32],
        name: (primary_name).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::RESTRICTED
                | TpmaObject::DECRYPT
                | TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: None,
                    key_bits: TpmiRsaKeyBits::Rsa2048,
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::new(&[1, 2, 3]).unwrap(),
            ),
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::default()),
        qualified_name: (primary_qn_1).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };

    let rsa_child_obj = TransientObject {
        handle: rsa_child_handle.0,
        seed: [0u8; 32],
        name: (rsa_child_name).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::RESTRICTED
                | TpmaObject::SIGN_ENCRYPT
                | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                    key_bits: TpmiRsaKeyBits::Rsa2048,
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::new(&[1, 2, 3]).unwrap(),
            ),
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::default()),
        qualified_name: initial_child_qn,
        hierarchy: 0x40000001,
        st_clear: false,
    };

    let certified_obj = TransientObject {
        handle: certified_handle.0,
        seed: [0u8; 32],
        name: (certified_name).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: None,
                    key_bits: TpmiRsaKeyBits::Rsa2048,
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::new(&[4, 5, 6]).unwrap(),
            ),
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::default()),
        qualified_name: certified_qn,
        hierarchy: 0x40000001,
        st_clear: false,
    };

    global_state.transient_objects[0] = Some(primary_obj_1);
    global_state.transient_parents[0] = Some(0x40000001);
    global_state.transient_objects[1] = Some(rsa_child_obj);
    global_state.transient_parents[1] = Some(primary_handle_1);

    // Simulate CreatePrimary under endorsement hierarchy creating Primary_Storage #2 at handle 0x80000004
    let primary_qn_2 = Tpm2bName::new(&[0x00, 0x0b, 0xaa, 0xbb, 0xcc, 0xdd]).unwrap();
    let expected_new_child_qn = {
        let handler = CommandHandler::new(&mut tpm, &mut global_state);
        handler
            .compute_qualified_name(
                Some(TpmiAlgHash::Sha256),
                primary_qn_2.as_slice(),
                rsa_child_name.as_slice(),
            )
            .unwrap()
    };

    let primary_obj_2 = TransientObject {
        handle: primary_handle_2,
        seed: [0u8; 32],
        name: (primary_name).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::RESTRICTED
                | TpmaObject::DECRYPT
                | TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: None,
                    key_bits: TpmiRsaKeyBits::Rsa2048,
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::new(&[1, 2, 3]).unwrap(),
            ),
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::default()),
        qualified_name: (primary_qn_2).into(),
        hierarchy: 0x4000000b,
        st_clear: false,
    };
    {
        let mut handler = CommandHandler::new(&mut tpm, &mut global_state);
        handler.update_aliased_transient_objects(
            primary_handle_2,
            &primary_name.into(),
            &primary_qn_2.into(),
        );
    }

    // Assert the old aliased slot 0 is cleared
    assert!(global_state.transient_objects[0].is_none());
    assert!(global_state.transient_parents[0].is_none());

    global_state.transient_objects[0] = Some(primary_obj_2);
    global_state.transient_parents[0] = Some(0x4000000b);

    // Assert rsa_child parent and dynamic qualified name have been synchronized to handle 0x80000004
    assert_eq!(global_state.transient_parents[1], Some(primary_handle_2));
    assert_eq!(
        global_state.transient_objects[1]
            .as_ref()
            .unwrap()
            .qualified_name
            .get_buffer(),
        expected_new_child_qn.get_buffer()
    );

    global_state.transient_objects[0] = Some(certified_obj.clone());
    global_state.transient_parents[0] = Some(0x40000001);

    let cmd = Certify {
        object_handle: certified_handle,
        sign_handle: rsa_child_handle,
        qualifying_data: Tpm2bData::new(&[99, 100]).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
    };
    let auths = [
        TpmsAuthCommand {
            session_handle: Handle(0x40000009),
            nonce: Tpm2bNonce::default(),
            session_attributes: TpmaSession::default(),
            hmac: Tpm2bAuth::default(),
        },
        TpmsAuthCommand {
            session_handle: Handle(0x40000009),
            nonce: Tpm2bNonce::default(),
            session_attributes: TpmaSession::default(),
            hmac: Tpm2bAuth::default(),
        },
    ];

    let mut response_buf = [0u8; 32768];
    let resp =
        execute_tpm_certify(&mut tpm, &mut global_state, &cmd, &auths, &mut response_buf).unwrap();
    let attest = resp.certify_info.0;
    let _ = attest.magic;
    assert_eq!(
        attest.qualified_signer.as_slice(),
        expected_new_child_qn.get_buffer()
    );
}

#[test]
fn test_certify_with_ecdaa_scheme() {
    let crypto = CertifyTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let certified_handle = Handle(0x80000001);
    let certified_obj = TransientObject {
        handle: certified_handle.0,
        seed: [0u8; 32],
        name: (Tpm2bName::new(&[1, 2, 3]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
        })
        .into(),
        sensitive: OwnedSensitiveComposite::KeyedHash(OwnedSensitiveData::default()),
        qualified_name: (Tpm2bName::new(&[1, 2, 3]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };

    let signer_handle = Handle(0x80000002);
    let signer_obj = TransientObject {
        handle: signer_handle.0,
        seed: [0u8; 32],
        name: (Tpm2bName::new(&[4, 5, 6]).unwrap()).into(),
        auth: (Tpm2bAuth::default()).into(),
        public: (TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Ecc(
                TpmsEccParms {
                    symmetric: None,
                    scheme: Some(TpmtEccScheme::Ecdaa(TpmsSchemeEcdaa {
                        hash_alg: TpmiAlgHash::Sha256,
                        count: 0,
                    })),
                    curve_id: TpmEccCurve::NistP256,
                    kdf: None,
                },
                TpmsEccPoint::default(),
            ),
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Ecc(OwnedEccParameter::new(&[0x07u8; 32]).unwrap()),
        qualified_name: (Tpm2bName::new(&[10, 11, 12, 13]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };

    global_state.transient_objects[0] = Some(certified_obj);
    global_state.transient_objects[1] = Some(signer_obj);

    let cmd = Certify {
        object_handle: certified_handle,
        sign_handle: signer_handle,
        qualifying_data: Tpm2bData::new(&[0x11, 0x22]).unwrap(),
        in_scheme: Some(TpmtSigScheme::Ecdaa(TpmsSchemeEcdaa {
            hash_alg: TpmiAlgHash::Sha256,
            count: 1,
        })),
    };
    let auths = [
        TpmsAuthCommand {
            session_handle: Handle(0x40000009),
            nonce: Tpm2bNonce::default(),
            session_attributes: TpmaSession::default(),
            hmac: Tpm2bAuth::default(),
        },
        TpmsAuthCommand {
            session_handle: Handle(0x40000009),
            nonce: Tpm2bNonce::default(),
            session_attributes: TpmaSession::default(),
            hmac: Tpm2bAuth::default(),
        },
    ];

    let mut response_buf = [0u8; 32768];
    let resp = execute_tpm_certify(&mut tpm, &mut global_state, &cmd, &auths, &mut response_buf)
        .expect("TPM2_Certify with TPMS_SCHEME_ECDAA must succeed");

    let attest = resp.certify_info.0;
    let _ = attest.magic;
    // Per TPM 2.0 Part 3 spec for ECDAA (anonymous signing):
    // qualified_signer, extra_data, and certified object's qualified_name must be empty
    assert_eq!(attest.qualified_signer.as_slice(), &[]);
    assert_eq!(attest.extra_data.as_slice(), &[]);
    if let tpm2::TpmuAttest::Certify(info) = attest.attested {
        assert_eq!(info.qualified_name.as_slice(), &[]);
        assert_eq!(info.name.as_slice(), &[1, 2, 3]);
    } else {
        panic!("Expected TpmuAttest::Certify");
    }

    // Verify signature is ECDAA variant
    match resp.signature {
        Some(tpm2::TpmtSignature::Ecdaa(sig)) => {
            assert_eq!(sig.hash, TpmiAlgHash::Sha256);
            assert_eq!(sig.signature_r.as_slice().len(), 32);
            assert_eq!(sig.signature_s.as_slice().len(), 32);
        }
        _ => panic!("Expected Some(TpmtSignature::Ecdaa)"),
    }
}
