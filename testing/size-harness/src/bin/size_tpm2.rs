//! Freestanding binary-size harness for the `tpm2` crate.
//!
//! Links representative structure/command marshaling and `tpm2::crypto` runtime
//! dispatch over an opaque `black_box` stub backend so `bloaty` measures pure
//! `tpm2` Flash and RAM usage across `v184` and `v185` feature profiles.

#![no_std]
#![no_main]
#![deny(unsafe_code)]
#![forbid(unreachable_pub)]

use core::ffi::CStr;
use core::hint::black_box;
use core::panic::PanicInfo;

use tpm2::commands::{
    CreatePrimary, Decapsulate, Encapsulate, GetCapability, GetRandom, SignDigest,
    StartAuthSession, Startup, VerifyDigestSignature, responses,
};
use tpm2::crypto::backend::{
    Cmac, CmacState, Ecc, EccCurve, EdwardsCurve, Hash, HashState, Hmac, HmacState, Mldsa,
    MldsaKey, Mlkem, MlkemKey, MontgomeryCurve, PrivateKey, Rsa, RsaKey, Symmetric, SymmetricState,
};
use tpm2::crypto::{
    self, Block, CipherInput, CmacContext, Crypto, CryptoError, Direction, EccCoordBuffer,
    EccPrivateKey, EccPublicKey, HashContext, HmacContext, Random, Rng, RsaEncryptScheme,
    RsaModulusBuffer, RsaPrimeBuffer, RsaPrivateKey, RsaPublicKey, SignatureBuffer,
    SymmetricContext, SymmetricKey,
};
use tpm2::{
    AlgSym, Marshal, Tpm2bDigest, Tpm2bEccParameter, Tpm2bPrivateKeyRsa, Tpm2bPublicKeyRsa,
    TpmEccCurve, TpmiAlgCipherMode, TpmiAlgHash, TpmiRsaKeyBits, TpmsEccPoint, TpmtEccScheme,
    TpmtPublic, TpmtSensitive, TpmtSigScheme, TpmtSignature, Unmarshal, UnmarshalMessage,
};

#[cfg(feature = "v185")]
use tpm2::crypto::{
    MldsaPrivateKey, MldsaPubKeyBuffer, MldsaPublicKey, MldsaSeedBuffer, MlkemCiphertextBuffer,
    MlkemPrivateKey, MlkemPubKeyBuffer, MlkemPublicKey, MlkemSeedBuffer, MlkemSharedSecretBuffer,
};
#[cfg(feature = "v185")]
use tpm2::{
    Tpm2bKemCiphertext, Tpm2bPrivateKeyMldsa, Tpm2bPrivateKeyMlkem, Tpm2bPublicKeyMldsa,
    Tpm2bPublicKeyMlkem, TpmiMldsaParms, TpmiMlkemParms,
};

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[expect(unsafe_code, reason = "freestanding ELF entry point symbol")]
#[unsafe(no_mangle)]
extern "C" fn _start() -> ! {
    let raw = black_box([0u8; 128]);
    let _ = black_box(measure_marshaling(&raw));
    let _ = black_box(measure_crypto(&raw));
    loop {
        core::hint::spin_loop();
    }
}

#[inline(never)]
fn roundtrip<'a, T>(raw: &'a [u8], dst: &mut T::MaxBuffer) -> usize
where
    T: Marshal + Unmarshal<'a>,
    T::MaxBuffer: AsRef<[u8]>,
{
    let mut src = black_box(raw);
    let Ok(val) = T::unmarshal(&mut src) else {
        return 0;
    };
    let written = val.marshal(dst);
    black_box(&dst.as_ref()[..written]).len()
}

#[inline(never)]
fn roundtrip_msg<'a, M>(raw: &'a [u8], dst: &mut M::MaxBuffer) -> usize
where
    M: UnmarshalMessage<'a>,
    M::MaxBuffer: AsRef<[u8]>,
{
    let mut src = black_box(raw);
    let handles = black_box(M::Handles::default());
    let Ok(msg) = M::unmarshal_with_handles(handles, &mut src) else {
        return 0;
    };
    let _ = black_box(msg.handles());
    let written = msg.marshal(dst);
    black_box(&dst.as_ref()[..written]).len()
}

macro_rules! measure_type {
    ($ty:ty, $raw:expr) => {{
        let mut dst = [0u8; <$ty as Marshal>::MAX_SIZE];
        roundtrip::<$ty>($raw, &mut dst)
    }};
}

macro_rules! measure_msg {
    ($ty:ty, $raw:expr) => {{
        let mut dst = [0u8; <$ty as Marshal>::MAX_SIZE];
        roundtrip_msg::<$ty>($raw, &mut dst)
    }};
}

#[inline(never)]
fn measure_marshaling(raw: &[u8]) -> usize {
    let mut acc = 0usize;
    acc = acc.wrapping_add(measure_type!(TpmtPublic<'_>, raw));
    acc = acc.wrapping_add(measure_type!(TpmtSensitive<'_>, raw));
    acc = acc.wrapping_add(measure_type!(TpmtSignature<'_>, raw));
    acc = acc.wrapping_add(measure_msg!(Startup, raw));
    acc = acc.wrapping_add(measure_msg!(GetRandom, raw));
    acc = acc.wrapping_add(measure_msg!(responses::GetRandom<'_>, raw));
    acc = acc.wrapping_add(measure_msg!(GetCapability, raw));
    acc = acc.wrapping_add(measure_msg!(responses::GetCapability<'_>, raw));
    acc = acc.wrapping_add(measure_msg!(StartAuthSession<'_>, raw));
    acc = acc.wrapping_add(measure_msg!(responses::StartAuthSession<'_>, raw));
    acc = acc.wrapping_add(measure_msg!(CreatePrimary<'_>, raw));
    acc = acc.wrapping_add(measure_msg!(responses::CreatePrimary<'_>, raw));
    acc = acc.wrapping_add(measure_msg!(SignDigest<'_>, raw));
    acc = acc.wrapping_add(measure_msg!(responses::SignDigest<'_>, raw));
    acc = acc.wrapping_add(measure_msg!(VerifyDigestSignature<'_>, raw));
    acc = acc.wrapping_add(measure_msg!(responses::VerifyDigestSignature<'_>, raw));
    acc = acc.wrapping_add(measure_msg!(Encapsulate, raw));
    acc = acc.wrapping_add(measure_msg!(responses::Encapsulate<'_>, raw));
    acc = acc.wrapping_add(measure_msg!(Decapsulate<'_>, raw));
    acc = acc.wrapping_add(measure_msg!(responses::Decapsulate<'_>, raw));
    acc
}

// Minimal inhabited stub backend so LTO preserves all enabled `tpm2::crypto`
// dispatch variants without pulling external cryptographic crates into the ELF.

struct StubCrypto;
struct StubRng(u8);
struct StubState(u8);
struct StubKey(u8);
struct StubPub(u8);

#[inline(never)]
fn fill_opaque(tag: u8, out: &mut [u8]) -> Result<(), CryptoError> {
    if black_box(tag) == 0xff {
        return Err(CryptoError::Unsupported);
    }
    if let Some(first) = out.first_mut() {
        *first = black_box(tag);
    }
    black_box(out);
    Ok(())
}

#[inline(never)]
fn check_opaque(tag: u8, input: &[u8]) -> Result<bool, CryptoError> {
    if black_box(tag) == 0xff {
        return Err(CryptoError::Unsupported);
    }
    Ok(black_box(input.first().copied().unwrap_or(0)) == black_box(tag))
}

impl Rng for StubRng {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        fill_opaque(self.0, out)
    }

    fn stir_bytes(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let _ = check_opaque(self.0, data)?;
        Ok(())
    }
}

impl Random for StubCrypto {
    type Rng = StubRng;

    fn from_entropy() -> Result<Self::Rng, CryptoError> {
        Ok(StubRng(black_box(1)))
    }

    fn from_seed(seed: &[u8]) -> Result<Self::Rng, CryptoError> {
        Ok(StubRng(black_box(seed.first().copied().unwrap_or(2))))
    }
}

impl<const DIGEST_SIZE: usize> HashState<DIGEST_SIZE> for StubState {
    fn init() -> Result<Self, CryptoError> {
        Ok(Self(black_box(DIGEST_SIZE as u8)))
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let _ = check_opaque(self.0, data)?;
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8; DIGEST_SIZE]) -> Result<(), CryptoError> {
        fill_opaque(self.0, out)
    }
}

impl Hash for StubCrypto {
    type Sha1 = StubState;
    type Sha256 = StubState;
    type Sha384 = StubState;
    type Sha512 = StubState;
    type Sm3_256 = StubState;
    type Sha3_256 = StubState;
    type Sha3_384 = StubState;
    type Sha3_512 = StubState;
}

impl<const DIGEST_SIZE: usize> HmacState<DIGEST_SIZE> for StubState {
    fn init(key: &[u8]) -> Result<Self, CryptoError> {
        let _ = check_opaque(DIGEST_SIZE as u8, key)?;
        Ok(Self(black_box(DIGEST_SIZE as u8)))
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let _ = check_opaque(self.0, data)?;
        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8; DIGEST_SIZE]) -> Result<(), CryptoError> {
        fill_opaque(self.0, out)
    }
}

impl Hmac for StubCrypto {
    type Sha1 = StubState;
    type Sha256 = StubState;
    type Sha384 = StubState;
    type Sha512 = StubState;
    type Sm3_256 = StubState;
    type Sha3_256 = StubState;
    type Sha3_384 = StubState;
    type Sha3_512 = StubState;
}

impl<const KEY_SIZE: usize> CmacState<KEY_SIZE> for StubState {
    fn init(key: &[u8; KEY_SIZE]) -> Result<Self, CryptoError> {
        let _ = check_opaque(KEY_SIZE as u8, key)?;
        Ok(Self(black_box(KEY_SIZE as u8)))
    }

    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let _ = check_opaque(self.0, data)?;
        Ok(())
    }

    fn finalize(&mut self, out: &mut Block) -> Result<(), CryptoError> {
        fill_opaque(self.0, out)
    }
}

impl Cmac for StubCrypto {
    type Aes128 = StubState;
    type Aes192 = StubState;
    type Aes256 = StubState;
    type Sm4_128 = StubState;
    type Camellia128 = StubState;
    type Camellia192 = StubState;
    type Camellia256 = StubState;
}

impl<const KEY_SIZE: usize> SymmetricState<KEY_SIZE> for StubState {
    fn init(key: &[u8; KEY_SIZE]) -> Result<Self, CryptoError> {
        let _ = check_opaque(KEY_SIZE as u8, key)?;
        Ok(Self(black_box(KEY_SIZE as u8)))
    }

    fn ctr(&self, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        fill_opaque(self.0, iv)?;
        fill_opaque(self.0, data)
    }

    fn ofb(&self, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        fill_opaque(self.0, iv)?;
        fill_opaque(self.0, data)
    }

    fn cbc(&self, dir: Direction, iv: &mut Block, data: &mut [Block]) -> Result<(), CryptoError> {
        let _ = black_box(dir);
        if let Some(first) = data.first_mut() {
            fill_opaque(self.0, first)?;
        }
        fill_opaque(self.0, iv)
    }

    fn cfb(&self, dir: Direction, iv: &mut Block, data: &mut [u8]) -> Result<(), CryptoError> {
        let _ = black_box(dir);
        fill_opaque(self.0, iv)?;
        fill_opaque(self.0, data)
    }

    fn ecb(&self, dir: Direction, data: &mut [Block]) -> Result<(), CryptoError> {
        let _ = black_box(dir);
        if let Some(first) = data.first_mut() {
            fill_opaque(self.0, first)?;
        }
        Ok(())
    }
}

impl Symmetric for StubCrypto {
    type Aes128 = StubState;
    type Aes192 = StubState;
    type Aes256 = StubState;
    type Sm4_128 = StubState;
    type Camellia128 = StubState;
    type Camellia192 = StubState;
    type Camellia256 = StubState;
}

impl<const PUB_SIZE: usize, const PRIV_SIZE: usize, P> PrivateKey<PUB_SIZE, PRIV_SIZE, StubRng, P>
    for StubKey
{
    type PublicKey = StubPub;

    fn generate(rng: &mut StubRng, params: P) -> Result<Self, CryptoError> {
        let _ = black_box(&params);
        Ok(Self(black_box(rng.0 ^ (PUB_SIZE as u8))))
    }

    fn load(
        public: Self::PublicKey,
        private: &[u8; PRIV_SIZE],
    ) -> Result<Option<Self>, CryptoError> {
        if check_opaque(public.0, private)? {
            Ok(Some(Self(public.0)))
        } else {
            Ok(None)
        }
    }

    fn store(&self, out: &mut [u8; PRIV_SIZE]) -> Result<(), CryptoError> {
        fill_opaque(self.0, out)
    }

    fn as_public(&self) -> &Self::PublicKey {
        const PUB_REF: StubPub = StubPub(0);
        let _ = black_box(self.0);
        &PUB_REF
    }

    fn load_public(params: P, public: &[u8; PUB_SIZE]) -> Result<Option<StubPub>, CryptoError> {
        let _ = black_box(&params);
        if check_opaque(PUB_SIZE as u8, public)? {
            Ok(Some(StubPub(PUB_SIZE as u8)))
        } else {
            Ok(None)
        }
    }

    fn store_public(public: &StubPub, out: &mut [u8; PUB_SIZE]) -> Result<(), CryptoError> {
        fill_opaque(public.0, out)
    }
}

impl<const MOD_SIZE: usize, const PRIME_SIZE: usize> RsaKey<MOD_SIZE, PRIME_SIZE, StubRng>
    for StubKey
{
    fn exponent(public: &StubPub) -> u32 {
        u32::from(black_box(public.0)) | 0x10001
    }

    fn raw_encrypt(
        public: &StubPub,
        m: &[u8; MOD_SIZE],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        let _ = check_opaque(public.0, m)?;
        fill_opaque(public.0, out).map(Some)
    }

    fn raw_decrypt(
        &self,
        rng: &mut StubRng,
        c: &[u8; MOD_SIZE],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        let _ = check_opaque(rng.0, c)?;
        fill_opaque(self.0, out).map(Some)
    }

    fn oaep_encrypt(
        public: &StubPub,
        rng: &mut StubRng,
        hash: TpmiAlgHash,
        label: &[u8],
        m: &[u8],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        let _ = (black_box(hash), black_box(label), check_opaque(rng.0, m)?);
        fill_opaque(public.0, out).map(Some)
    }

    fn oaep_decrypt(
        &self,
        rng: &mut StubRng,
        hash: TpmiAlgHash,
        label: &[u8],
        c: &[u8; MOD_SIZE],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<usize>, CryptoError> {
        let _ = (black_box(hash), black_box(label), check_opaque(rng.0, c)?);
        fill_opaque(self.0, out)?;
        Ok(Some(black_box(16)))
    }

    fn rsaes_encrypt(
        public: &StubPub,
        rng: &mut StubRng,
        m: &[u8],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        let _ = check_opaque(rng.0, m)?;
        fill_opaque(public.0, out).map(Some)
    }

    fn rsaes_decrypt(
        &self,
        rng: &mut StubRng,
        c: &[u8; MOD_SIZE],
        out: &mut [u8; MOD_SIZE],
    ) -> Result<Option<usize>, CryptoError> {
        let _ = check_opaque(rng.0, c)?;
        fill_opaque(self.0, out)?;
        Ok(Some(black_box(16)))
    }

    fn rsassa_sign(
        &self,
        rng: &mut StubRng,
        digest: tpm2::TpmtHa<'_>,
        out: &mut [u8; MOD_SIZE],
    ) -> Result<(), CryptoError> {
        let _ = (black_box(rng.0), black_box(digest));
        fill_opaque(self.0, out)
    }

    fn rsassa_verify(
        public: &StubPub,
        digest: tpm2::TpmtHa<'_>,
        sig: &[u8; MOD_SIZE],
    ) -> Result<bool, CryptoError> {
        let _ = black_box(digest);
        check_opaque(public.0, sig)
    }

    fn rsapss_sign(
        &self,
        rng: &mut StubRng,
        digest: tpm2::TpmtHa<'_>,
        out: &mut [u8; MOD_SIZE],
    ) -> Result<(), CryptoError> {
        let _ = (black_box(rng.0), black_box(digest));
        fill_opaque(self.0, out)
    }

    fn rsapss_verify(
        public: &StubPub,
        digest: tpm2::TpmtHa<'_>,
        sig: &[u8; MOD_SIZE],
    ) -> Result<bool, CryptoError> {
        let _ = black_box(digest);
        check_opaque(public.0, sig)
    }
}

impl Rsa for StubCrypto {
    type Rsa1024 = StubKey;
    type Rsa2048 = StubKey;
    type Rsa3072 = StubKey;
    type Rsa4096 = StubKey;
}

impl<const COORD_SIZE: usize, const POINT_SIZE: usize> EccCurve<COORD_SIZE, POINT_SIZE, StubRng>
    for StubKey
{
    fn ecdh(
        &self,
        peer_public: &StubPub,
        out_x: &mut [u8; COORD_SIZE],
        out_y: &mut [u8; COORD_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        fill_opaque(self.0, out_x)?;
        fill_opaque(peer_public.0, out_y).map(Some)
    }

    fn sign(
        &self,
        rng: &mut StubRng,
        digest: &[u8],
        out_r: &mut [u8; COORD_SIZE],
        out_s: &mut [u8; COORD_SIZE],
    ) -> Result<(), CryptoError> {
        let _ = check_opaque(rng.0, digest)?;
        fill_opaque(self.0, out_r)?;
        fill_opaque(self.0, out_s)
    }

    fn verify(
        public: &StubPub,
        digest: &[u8],
        sig_r: &[u8; COORD_SIZE],
        sig_s: &[u8; COORD_SIZE],
    ) -> Result<bool, CryptoError> {
        let _ = (black_box(digest), black_box(sig_s));
        check_opaque(public.0, sig_r)
    }
}

impl<const KEY_SIZE: usize> EdwardsCurve<KEY_SIZE, StubRng> for StubKey {
    fn sign_message(
        &self,
        msg: &[&[u8]],
        out_r: &mut [u8; KEY_SIZE],
        out_s: &mut [u8; KEY_SIZE],
    ) -> Result<(), CryptoError> {
        let _ = black_box(msg);
        fill_opaque(self.0, out_r)?;
        fill_opaque(self.0, out_s)
    }

    fn sign_prehash(
        &self,
        prehash: &[u8; 64],
        out_r: &mut [u8; KEY_SIZE],
        out_s: &mut [u8; KEY_SIZE],
    ) -> Result<(), CryptoError> {
        let _ = check_opaque(self.0, prehash)?;
        fill_opaque(self.0, out_r)?;
        fill_opaque(self.0, out_s)
    }

    fn verify_message(
        public: &StubPub,
        msg: &[&[u8]],
        sig_r: &[u8; KEY_SIZE],
        sig_s: &[u8; KEY_SIZE],
    ) -> Result<bool, CryptoError> {
        let _ = (black_box(msg), black_box(sig_s));
        check_opaque(public.0, sig_r)
    }

    fn verify_prehash(
        public: &StubPub,
        prehash: &[u8; 64],
        sig_r: &[u8; KEY_SIZE],
        sig_s: &[u8; KEY_SIZE],
    ) -> Result<bool, CryptoError> {
        let _ = (black_box(prehash), black_box(sig_s));
        check_opaque(public.0, sig_r)
    }
}

impl<const KEY_SIZE: usize> MontgomeryCurve<KEY_SIZE, StubRng> for StubKey {
    fn ecdh(
        &self,
        peer_public: &StubPub,
        out_u: &mut [u8; KEY_SIZE],
    ) -> Result<Option<()>, CryptoError> {
        fill_opaque(self.0 ^ peer_public.0, out_u).map(Some)
    }
}

impl Ecc for StubCrypto {
    type NistP192 = StubKey;
    type NistP224 = StubKey;
    type NistP256 = StubKey;
    type NistP384 = StubKey;
    type NistP521 = StubKey;
    type BNP256 = StubKey;
    type BNP638 = StubKey;
    type SM2P256 = StubKey;
    type BpP256R1 = StubKey;
    type BpP384R1 = StubKey;
    type BpP512R1 = StubKey;
    type Ed25519 = StubKey;
    type Ed448 = StubKey;
    type X25519 = StubKey;
    type X448 = StubKey;
}

impl<const PUB_SIZE: usize, const SIG_SIZE: usize> MldsaKey<PUB_SIZE, SIG_SIZE, StubRng>
    for StubKey
{
    fn sign_message(
        &self,
        rng: &mut StubRng,
        context: &[u8],
        msg: &[&[u8]],
        out_sig: &mut [u8; SIG_SIZE],
    ) -> Result<(), CryptoError> {
        let _ = (black_box(rng.0), black_box(context), black_box(msg));
        fill_opaque(self.0, out_sig)
    }

    fn verify_message(
        public: &StubPub,
        context: &[u8],
        msg: &[&[u8]],
        sig: &[u8; SIG_SIZE],
    ) -> Result<bool, CryptoError> {
        let _ = (black_box(context), black_box(msg));
        check_opaque(public.0, sig)
    }

    fn sign_mu(
        &self,
        rng: &mut StubRng,
        mu: &[u8; 64],
        out_sig: &mut [u8; SIG_SIZE],
    ) -> Result<(), CryptoError> {
        let _ = check_opaque(rng.0, mu)?;
        fill_opaque(self.0, out_sig)
    }

    fn verify_mu(
        public: &StubPub,
        mu: &[u8; 64],
        sig: &[u8; SIG_SIZE],
    ) -> Result<bool, CryptoError> {
        let _ = black_box(mu);
        check_opaque(public.0, sig)
    }

    fn sign_prehash(
        &self,
        rng: &mut StubRng,
        context: &[u8],
        digest: tpm2::TpmtHa<'_>,
        out_sig: &mut [u8; SIG_SIZE],
    ) -> Result<(), CryptoError> {
        let _ = (black_box(rng.0), black_box(context), black_box(digest));
        fill_opaque(self.0, out_sig)
    }

    fn verify_prehash(
        public: &StubPub,
        context: &[u8],
        digest: tpm2::TpmtHa<'_>,
        sig: &[u8; SIG_SIZE],
    ) -> Result<bool, CryptoError> {
        let _ = (black_box(context), black_box(digest));
        check_opaque(public.0, sig)
    }
}

impl Mldsa for StubCrypto {
    type Mldsa44 = StubKey;
    type Mldsa65 = StubKey;
    type Mldsa87 = StubKey;
}

impl<const PUB_SIZE: usize, const CT_SIZE: usize> MlkemKey<PUB_SIZE, CT_SIZE, StubRng> for StubKey {
    fn encapsulate(
        public: &StubPub,
        rng: &mut StubRng,
        out_ct: &mut [u8; CT_SIZE],
        out_ss: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        fill_opaque(public.0, out_ct)?;
        fill_opaque(rng.0, out_ss)
    }

    fn decapsulate(&self, ct: &[u8; CT_SIZE], out_ss: &mut [u8; 32]) -> Result<(), CryptoError> {
        let _ = check_opaque(self.0, ct)?;
        fill_opaque(self.0, out_ss)
    }
}

impl Mlkem for StubCrypto {
    type Mlkem512 = StubKey;
    type Mlkem768 = StubKey;
    type Mlkem1024 = StubKey;
}

impl Crypto for StubCrypto {
    fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        black_box(a) == black_box(b)
    }
}

const LABEL: &CStr = c"STORAGE";

#[inline(never)]
fn measure_crypto(raw: &[u8]) -> Result<(), CryptoError> {
    let mut rng = StubCrypto::from_seed(raw)?;
    let mut scratch = [0u8; TpmiAlgHash::MAX_DIGEST_BYTES];
    StubCrypto::rand_bytes(&mut scratch)?;
    rng.stir_bytes(raw)?;
    let _ = black_box(StubCrypto::ct_eq(raw, &scratch));

    let hash_alg = black_box(TpmiAlgHash::Sha256);
    let _ = black_box(crypto::hash::<StubCrypto>(hash_alg, &[raw], &mut scratch)?);
    let mut hctx = HashContext::<StubCrypto>::new(hash_alg)?;
    hctx.update(raw)?;
    let _ = black_box(hctx.finalize(&mut scratch)?);
    crypto::kdfe::<StubCrypto>(hash_alg, raw, LABEL, (raw, raw), &mut scratch)?;

    let _ = black_box(crypto::hmac::<StubCrypto>(
        hash_alg,
        raw,
        &[raw],
        &mut scratch,
    )?);
    let mut mctx = HmacContext::<StubCrypto>::new(hash_alg, raw)?;
    mctx.update(raw)?;
    let _ = black_box(mctx.finalize(&mut scratch)?);
    crypto::kdfa::<StubCrypto>(hash_alg, raw, LABEL, (raw, raw), &mut scratch)?;
    crypto::kdfa_xor::<StubCrypto>(hash_alg, raw, LABEL, (raw, raw), &mut scratch)?;

    let sym_alg = black_box(AlgSym::Aes128);
    let sym_mode = black_box(TpmiAlgCipherMode::Cfb);
    let mut iv = black_box([0u8; AlgSym::BLOCK_SIZE]);
    let mut block_buf = black_box([0u8; 2 * AlgSym::BLOCK_SIZE]);
    if let Some(sym_key) = SymmetricKey::new(sym_alg, &raw[..16]) {
        if let Some(inp) = CipherInput::new(sym_mode, &mut iv, &mut block_buf) {
            sym_key.crypt::<StubCrypto>(black_box(Direction::Encrypt), inp)?;
        }
        let sctx = SymmetricContext::<StubCrypto>::new(sym_key)?;
        if let Some(inp) = CipherInput::new(sym_mode, &mut iv, &mut block_buf) {
            sctx.crypt(black_box(Direction::Decrypt), inp)?;
        }
        let mut mac_out = [0u8; AlgSym::BLOCK_SIZE];
        sym_key.cmac::<StubCrypto>(&[raw], &mut mac_out)?;
        let mut cctx = CmacContext::<StubCrypto>::new(sym_key)?;
        cctx.update(raw)?;
        cctx.finalize(&mut mac_out)?;
        let _ = black_box(mac_out);
    }

    let mut sig_buf: SignatureBuffer = [0u8; _];
    let rsa_bits = black_box(TpmiRsaKeyBits::Rsa2048);
    let rsa_priv = RsaPrivateKey::<StubCrypto>::generate(&mut rng, rsa_bits, black_box(0))?;
    let mut rsa_mod: RsaModulusBuffer = [0u8; _];
    let mut rsa_prime: RsaPrimeBuffer = [0u8; _];
    let _ = black_box(rsa_priv.modulus(&mut rsa_mod)?);
    if let Some(rsa_pub) = RsaPublicKey::<StubCrypto>::load(
        rsa_bits,
        black_box(65537),
        black_box(Tpm2bPublicKeyRsa::default()),
    )? {
        let scheme = black_box(RsaEncryptScheme::Oaep {
            hash: hash_alg,
            label: Some(LABEL),
        });
        let _ = black_box(rsa_pub.encrypt(&mut rng, scheme, raw, &mut rsa_mod)?);
        let sig = rsa_priv.sign(
            &mut rng,
            black_box(TpmtSigScheme::Rsapss(hash_alg)),
            &scratch[..32],
            &mut sig_buf,
        )?;
        let _ = black_box(rsa_pub.verify(&scratch[..32], sig)?);
        let prime_2b = rsa_priv.prime_p(&mut rsa_prime)?;
        let _ = black_box(RsaPrivateKey::<StubCrypto>::load(rsa_pub, prime_2b)?);
    }
    let _ = black_box(rsa_priv.decrypt(
        &mut rng,
        black_box(RsaEncryptScheme::Raw),
        raw,
        &mut rsa_mod,
    )?);

    let ecc_curve = black_box(TpmEccCurve::NistP256);
    let ecc_scheme = black_box(Some(TpmtEccScheme::Ecdsa(hash_alg)));
    let ecc_priv = EccPrivateKey::<StubCrypto>::generate(&mut rng, ecc_curve, ecc_scheme)?;
    let mut coord_x: EccCoordBuffer = [0u8; _];
    let mut coord_y: EccCoordBuffer = [0u8; _];
    let empty_pt = TpmsEccPoint {
        x: Tpm2bEccParameter::default(),
        y: Tpm2bEccParameter::default(),
    };
    if let Some(ecc_pub) = EccPublicKey::<StubCrypto>::load(ecc_curve, ecc_scheme, empty_pt)? {
        let _ = black_box(ecc_pub.point(&mut coord_x, &mut coord_y)?);
        let _ = black_box(ecc_priv.ecdh(&ecc_pub, &mut coord_x, &mut coord_y)?);
        let sig = ecc_priv.sign(
            &mut rng,
            black_box(TpmtSigScheme::Ecdsa(hash_alg)),
            &scratch[..32],
            &mut sig_buf,
        )?;
        let _ = black_box(ecc_pub.verify(&scratch[..32], sig)?);
        #[cfg(feature = "v185")]
        {
            let msg_sig = ecc_priv.sign_message(&[raw], &mut sig_buf)?;
            let _ = black_box(ecc_pub.verify_message(&[raw], msg_sig)?);
        }
        let scalar = ecc_priv.scalar(&mut coord_x)?;
        let _ = black_box(EccPrivateKey::<StubCrypto>::load(ecc_pub, scalar)?);
    }

    #[cfg(feature = "v185")]
    measure_pqc(&mut rng, hash_alg, raw, &mut sig_buf)?;

    let _ = black_box(Tpm2bPrivateKeyRsa::default());
    let _ = black_box(Tpm2bDigest::default());
    Ok(())
}

#[cfg(feature = "v185")]
#[inline(never)]
fn measure_pqc(
    rng: &mut StubRng,
    hash_alg: TpmiAlgHash,
    raw: &[u8],
    sig_buf: &mut SignatureBuffer,
) -> Result<(), CryptoError> {
    let mldsa_parms = black_box(TpmiMldsaParms::Mldsa65);
    let mldsa_priv = MldsaPrivateKey::<StubCrypto>::generate(rng, mldsa_parms)?;
    let mut mldsa_pk_buf: MldsaPubKeyBuffer = [0u8; _];
    let mut mldsa_seed_buf: MldsaSeedBuffer = [0u8; _];
    let _ = black_box(mldsa_priv.public(&mut mldsa_pk_buf)?);
    let mldsa_seed: Tpm2bPrivateKeyMldsa<'_> = mldsa_priv.seed(&mut mldsa_seed_buf)?;
    let mu = black_box([0u8; 64]);
    let sig_mu = mldsa_priv.sign_mu(rng, &mu, sig_buf)?;
    let _ = black_box(sig_mu);
    let sig_ph = mldsa_priv.sign_prehash(rng, hash_alg, raw, &mu[..32], sig_buf)?;
    let _ = black_box(sig_ph);
    let sig_msg = mldsa_priv.sign_message(rng, raw, &[raw], sig_buf)?;
    if let Some(mldsa_pub) =
        MldsaPublicKey::<StubCrypto>::load(mldsa_parms, black_box(Tpm2bPublicKeyMldsa::default()))?
    {
        let _ = black_box(mldsa_pub.public(&mut mldsa_pk_buf)?);
        let _ = black_box(mldsa_pub.verify(raw, &mu, sig_msg)?);
        let _ = black_box(mldsa_pub.verify_message(raw, &[raw], sig_msg)?);
        let _ = black_box(MldsaPrivateKey::<StubCrypto>::load(mldsa_pub, mldsa_seed)?);
    }

    let mlkem_parms = black_box(TpmiMlkemParms::Mlkem768);
    let mlkem_priv = MlkemPrivateKey::<StubCrypto>::generate(rng, mlkem_parms)?;
    let mut mlkem_pk_buf: MlkemPubKeyBuffer = [0u8; _];
    let mut mlkem_ct_buf: MlkemCiphertextBuffer = [0u8; _];
    let mut mlkem_seed_buf: MlkemSeedBuffer = [0u8; _];
    let mut mlkem_ss_buf: MlkemSharedSecretBuffer = [0u8; _];
    let _ = black_box(mlkem_priv.public(&mut mlkem_pk_buf)?);
    let mlkem_seed: Tpm2bPrivateKeyMlkem<'_> = mlkem_priv.seed(&mut mlkem_seed_buf)?;
    let _ = black_box(
        mlkem_priv.decapsulate(black_box(Tpm2bKemCiphertext::default()), &mut mlkem_ss_buf)?,
    );
    if let Some(mlkem_pub) =
        MlkemPublicKey::<StubCrypto>::load(mlkem_parms, black_box(Tpm2bPublicKeyMlkem::default()))?
    {
        let _ = black_box(mlkem_pub.public(&mut mlkem_pk_buf)?);
        let _ = black_box(mlkem_pub.encapsulate(rng, &mut mlkem_ct_buf, &mut mlkem_ss_buf)?);
        let _ = black_box(MlkemPrivateKey::<StubCrypto>::load(mlkem_pub, mlkem_seed)?);
    }
    Ok(())
}
