mod common;

use common::{FakeCrypto, FakeRng, FakeStorage, FakeTimer};
use hex_literal::hex;
use tpm2::commands::{Command, Quote};
use tpm2::crypto::{
    Cmac, ConstantTimeEq, CryptoError, Direction, Ecc, EccPrivateKey, EccPublicKey, Hash, Hmac,
    Mldsa, Mlkem, ModeIv, Random, Rsa, RsaPrivateKey, RsaPublicKey, RsaSigScheme, Signing,
    Symmetric,
};
use tpm2::errors::TpmRc;
use tpm2::{
    Handle, Marshal, PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEccParameter,
    Tpm2bName, Tpm2bNonce, Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa, TpmEccCurve, TpmaObject,
    TpmaSession, TpmiAlgHash, TpmiRsaKeyBits, TpmlPcrSelection, TpmsAttest, TpmsAuthCommand,
    TpmsEccPoint, TpmsPcrSelect, TpmsPcrSelection, TpmsRsaParms, TpmtHa, TpmtPublic, TpmtRsaScheme,
    TpmtSigScheme, TpmtSignature, TpmuAttest,
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

struct QuoteTestCrypto;

impl Random for QuoteTestCrypto {
    type Rng = FakeRng;
    fn rng(&self) -> Result<FakeRng, CryptoError> {
        FakeCrypto.rng()
    }
    fn rng_seeded(&self, seed: &[u8]) -> Result<FakeRng, CryptoError> {
        FakeCrypto.rng_seeded(seed)
    }
}

impl Hash for QuoteTestCrypto {
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

impl Hmac for QuoteTestCrypto {
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

impl Cmac for QuoteTestCrypto {
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

impl Symmetric for QuoteTestCrypto {
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

impl Rsa for QuoteTestCrypto {
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

impl Ecc for QuoteTestCrypto {
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

impl Signing for QuoteTestCrypto {
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

    fn rsa_verify(
        &self,
        _key: &<Self as Rsa>::PublicKey,
        _scheme: RsaSigScheme,
        digest: TpmtHa<'_>,
        sig: &[u8],
    ) -> Result<bool, CryptoError> {
        if sig.len() != 256 {
            return Ok(false);
        }
        let mut expected = [0x5a; 256];
        for (i, &b) in digest.digest().iter().enumerate() {
            expected[i % 256] ^= b;
        }
        Ok(sig == expected)
    }
}

impl Mlkem for QuoteTestCrypto {
    type PublicKey = !;
    type PrivateKey = !;
}

impl Mldsa for QuoteTestCrypto {
    type PublicKey = !;
    type PrivateKey = !;
    type MuContext = !;
}

impl ConstantTimeEq for QuoteTestCrypto {
    fn constant_time_eq<const N: usize>(&self, a: &[u8; N], b: &[u8; N]) -> bool {
        FakeCrypto.constant_time_eq(a, b)
    }
}

fn setup_tpm<'a>(
    crypto: &'a QuoteTestCrypto,
    storage: &'a mut FakeStorage,
    timer: &'a mut FakeTimer,
) -> (
    TpmEngine<'a, QuoteTestCrypto, FakeStorage, FakeTimer>,
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

fn execute_tpm_quote<'a>(
    tpm: &mut TpmEngine<'_, QuoteTestCrypto, FakeStorage, FakeTimer>,
    global_state: &mut tpm2_impl::GlobalState,
    cmd: &Quote,
    auths: &[TpmsAuthCommand],
    response_buf: &'a mut [u8; 32768],
) -> Result<<Quote<'static> as Command>::Response<'a>, u32> {
    let mut request_buf = [0u8; 32768];
    let mut offset = 10;

    if auths.is_empty() {
        request_buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    } else {
        request_buf[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    }

    request_buf[6..10].copy_from_slice(&(Quote::CMD_CODE.code()).to_be_bytes());

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

    let mut cmd_buf = [0u8; Quote::MAX_SIZE];
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
fn test_quote_rsa_success() {
    let crypto = QuoteTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let signer_handle = Handle(0x80000002);
    let signer_obj = TransientObject {
        handle: signer_handle.0,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
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
        qualified_name: (Tpm2bName::new(&[4, 5, 6]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[1] = Some(signer_obj);

    // Extend PCR 0 with a test hash
    global_state.pcrs.sha256[0] = [0x42; 32];

    let cmd = Quote {
        sign_handle: signer_handle,
        qualifying_data: Tpm2bData::new(&[10, 20, 30]).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
        pcr_select: TpmlPcrSelection::new(&[TpmsPcrSelection {
            hash: TpmiAlgHash::Sha256,
            selection: TpmsPcrSelect::new(&[0x01, 0x00, 0x00]).unwrap(),
        }])
        .unwrap(),
    };

    let pw_auth = TpmsAuthCommand {
        session_handle: Handle(0x40000009), // TPM_RS_PW
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::default(),
        hmac: Tpm2bAuth::default(),
    };

    let mut response_buf = [0u8; 32768];
    let resp = execute_tpm_quote(
        &mut tpm,
        &mut global_state,
        &cmd,
        &[pw_auth],
        &mut response_buf,
    )
    .unwrap();

    let attest = resp.quoted.0;
    assert_eq!(attest.extra_data.as_slice(), &[10, 20, 30]);

    match attest.attested {
        TpmuAttest::Quote(quote_info) => {
            assert_eq!(quote_info.pcr_select, cmd.pcr_select);
            assert_eq!(quote_info.pcr_digest.as_slice(), &[0x42; 32]);
        }
        _ => panic!("Expected Quote attested info"),
    }

    let mut quoted_buf = [0u8; TpmsAttest::MAX_SIZE];
    let quoted_len = attest.marshal(&mut quoted_buf);
    let mut out = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    let digest = tpm2::crypto::hash(
        &crypto,
        TpmiAlgHash::Sha256,
        &quoted_buf[..quoted_len],
        &mut out,
    )
    .unwrap();
    match resp.signature {
        Some(TpmtSignature::Rsassa(sig)) => {
            let pub_key = Rsa::load_public(
                &crypto,
                TpmiRsaKeyBits::Rsa2048,
                0,
                Tpm2bPublicKeyRsa::new(&[1, 2, 3]).unwrap(),
            )
            .unwrap()
            .unwrap();
            assert!(
                crypto
                    .rsa_verify(&pub_key, RsaSigScheme::Rsassa, digest, sig.sig.as_slice())
                    .expect("Cryptographic signature verification failed")
            );
        }
        _ => panic!("Expected RSASSA signature"),
    }
}

#[test]
fn test_quote_unsupported_scheme_fails() {
    let crypto = QuoteTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let decrypt_handle = Handle(0x80000003);
    let decrypt_obj = TransientObject {
        handle: decrypt_handle.0,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
        name: (Tpm2bName::new(&[7, 8, 9]).unwrap()).into(),
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
                Tpm2bPublicKeyRsa::new(&[1, 2, 3]).unwrap(),
            ),
        })
        .into(),
        sensitive: OwnedSensitiveComposite::Rsa(OwnedPrivateKeyRsa::default()),
        qualified_name: (Tpm2bName::new(&[7, 8, 9]).unwrap()).into(),
        hierarchy: 0x40000001,
        st_clear: false,
    };
    global_state.transient_objects[2] = Some(decrypt_obj);

    let cmd = Quote {
        sign_handle: decrypt_handle,
        qualifying_data: Tpm2bData::default(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
        pcr_select: TpmlPcrSelection::new(&[TpmsPcrSelection {
            hash: TpmiAlgHash::Sha256,
            selection: TpmsPcrSelect::new(&[0x01, 0x00, 0x00]).unwrap(),
        }])
        .unwrap(),
    };

    let pw_auth = TpmsAuthCommand {
        session_handle: Handle(0x40000009), // TPM_RS_PW
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::default(),
        hmac: Tpm2bAuth::default(),
    };

    let mut response_buf = [0u8; 32768];
    let res = execute_tpm_quote(
        &mut tpm,
        &mut global_state,
        &cmd,
        &[pw_auth],
        &mut response_buf,
    );
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(
        err == TpmRc::KEY.get()
            || err == TpmRc::SCHEME.get()
            || err == (TpmRc::KEY.get() + 0x100)
            || err == (TpmRc::SCHEME.get() + 0x100),
        "Expected Key or Scheme error, got 0x{:x}",
        err
    );
}

#[test]
fn test_quote_qualified_signer_exact_accumulation() {
    let crypto = QuoteTestCrypto;
    let mut storage = FakeStorage::default();
    let mut timer = FakeTimer;
    let (mut tpm, mut global_state) = setup_tpm(&crypto, &mut storage, &mut timer);

    let signer_handle = Handle(0x80000002);
    let signer_qn = Tpm2bName::new(&[30, 31, 32, 33]).unwrap();
    let signer_obj = TransientObject {
        handle: signer_handle.0,
        seed: tpm2_impl::owned::OwnedDigest::new(&[0u8; 32]).unwrap(),
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
    global_state.transient_objects[1] = Some(signer_obj.clone());
    global_state.transient_parents[1] = Some(0x40000001);

    let cmd = Quote {
        sign_handle: signer_handle,
        qualifying_data: Tpm2bData::new(&[10, 20]).unwrap(),
        in_scheme: Some(TpmtSigScheme::Rsassa(TpmiAlgHash::Sha256)),
        pcr_select: TpmlPcrSelection::new(&[TpmsPcrSelection {
            hash: TpmiAlgHash::Sha256,
            selection: TpmsPcrSelect::new(&[0x01, 0x00, 0x00]).unwrap(),
        }])
        .unwrap(),
    };

    let pw_auth = TpmsAuthCommand {
        session_handle: Handle(0x40000009),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::default(),
        hmac: Tpm2bAuth::default(),
    };

    let mut response_buf = [0u8; 32768];
    let resp = execute_tpm_quote(
        &mut tpm,
        &mut global_state,
        &cmd,
        &[pw_auth],
        &mut response_buf,
    )
    .unwrap();
    let attest = resp.quoted.0;
    let _ = attest.magic;
    assert_eq!(attest.qualified_signer.as_slice(), signer_qn.as_slice());
}
