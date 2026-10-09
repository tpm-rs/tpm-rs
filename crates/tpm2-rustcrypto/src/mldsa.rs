//! [`Mldsa`]: ML-DSA signatures ([FIPS 204]).
//!
//! [FIPS 204]: https://csrc.nist.gov/pubs/fips/204/final

use alloc::boxed::Box;
use core::{convert::Infallible, fmt};

use ml_dsa::{
    EncodedVerifyingKey, ExpandedSigningKey, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Seed,
    Signature, VerifyingKey,
    common::{array::Array, typenum::U64},
    signature::rand_core::{TryCryptoRng, TryRng},
};
use rand_chacha::rand_core::RngCore;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update as _},
};
use tpm2::{
    Tpm2b, Tpm2bPrivateKeyMldsa, Tpm2bPublicKeyMldsa, Tpm2bSignatureCtx, Tpm2bSignatureMldsa,
    TpmiMldsaParms,
    crypto::{
        CryptoError, Finalize, Mldsa, MldsaMessage, MldsaPublicKey as _, Update, pre_hash_oid,
    },
};

use crate::{ChaChaRng, RustCrypto, copy_prefix};

/// Domain separator of `M'` for ML-DSA (FIPS 204, Algorithm 2).
const PURE: u8 = 0;
/// Domain separator of `M'` for HashML-DSA (FIPS 204, Algorithm 4).
const PRE_HASH: u8 = 1;

/// The message representative `µ`.
type Mu = Array<u8, U64>;

/// Evaluates `$body` with `$var` bound to the parameter-set-specific key
/// inside a [`Vk`] or [`Sk`].
macro_rules! dispatch {
    ($enum:ident, $value:expr, $var:ident => $body:expr) => {
        match $value {
            $enum::Mldsa44($var) => $body,
            $enum::Mldsa65($var) => $body,
            $enum::Mldsa87($var) => $body,
        }
    };
}

/// ML-DSA public key.
#[derive(Clone, PartialEq)]
pub struct MldsaPublicKey {
    key: Vk,
    /// `tr = H(pk, 64)`, which is hashed into `µ` (FIPS 204, Algorithm 7, line 6).
    tr: [u8; 64],
}

#[derive(Clone, PartialEq)]
enum Vk {
    Mldsa44(VerifyingKey<MlDsa44>),
    Mldsa65(VerifyingKey<MlDsa65>),
    Mldsa87(VerifyingKey<MlDsa87>),
}

/// ML-DSA private key.
#[derive(Clone)]
pub struct MldsaPrivateKey {
    public: MldsaPublicKey,
    // `ExpandedSigningKey` (rather than `SigningKey`) is the only `ml-dsa`
    // type that can sign an external `µ` with fresh randomness. It is boxed
    // because it is up to ~100 KiB.
    secret: Sk,
    seed: [u8; 32],
}

#[derive(Clone)]
enum Sk {
    Mldsa44(Box<ExpandedSigningKey<MlDsa44>>),
    Mldsa65(Box<ExpandedSigningKey<MlDsa65>>),
    Mldsa87(Box<ExpandedSigningKey<MlDsa87>>),
}

impl MldsaPublicKey {
    fn new(key: Vk) -> Self {
        let mut hasher = Shake256::default();
        dispatch!(Vk, &key, vk => hasher.update(&vk.encode()));
        let mut tr = [0u8; 64];
        hasher.finalize_xof_into(&mut tr);
        Self { key, tr }
    }
}

impl fmt::Debug for MldsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MldsaPublicKey")
            .field(&self.parameter_set())
            .finish()
    }
}

impl fmt::Debug for MldsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MldsaPrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl tpm2::crypto::MldsaPublicKey for MldsaPublicKey {
    fn parameter_set(&self) -> TpmiMldsaParms {
        match self.key {
            Vk::Mldsa44(_) => TpmiMldsaParms::Mldsa44,
            Vk::Mldsa65(_) => TpmiMldsaParms::Mldsa65,
            Vk::Mldsa87(_) => TpmiMldsaParms::Mldsa87,
        }
    }

    fn encoded<'a>(
        &self,
        out: &'a mut [u8; TpmiMldsaParms::MAX_PUB_KEY_BYTES],
    ) -> Result<Tpm2bPublicKeyMldsa<'a>, CryptoError> {
        let encoded = dispatch!(Vk, &self.key, vk => copy_prefix(out, &vk.encode()))?;
        Tpm2bPublicKeyMldsa::new(encoded).ok_or(CryptoError::Internal)
    }
}

impl tpm2::crypto::MldsaPrivateKey for MldsaPrivateKey {
    type PublicKey = MldsaPublicKey;

    fn public_key(&self) -> &MldsaPublicKey {
        &self.public
    }

    fn seed<'a>(&self, out: &'a mut [u8; 32]) -> Result<Tpm2bPrivateKeyMldsa<'a>, CryptoError> {
        *out = self.seed;
        Ok(Tpm2b(out))
    }
}

/// Streaming context computing the ML-DSA message representative `µ`
/// (FIPS 204, Algorithm 7, line 6), returned by [`Mldsa::mu_start`].
#[derive(Clone)]
pub struct MuContext(Shake256);

impl MuContext {
    /// Starts computing `µ = H(tr || M', 64)` for `key`, where
    /// `M' = domain || |ctx| || ctx || ...` (FIPS 204, Algorithms 2 and 4).
    fn new(
        key: &MldsaPublicKey,
        domain: u8,
        context: Tpm2bSignatureCtx<'_>,
    ) -> Result<Self, CryptoError> {
        let context = context.as_slice();
        // A `Tpm2bSignatureCtx` holds at most 255 bytes.
        let len = u8::try_from(context.len()).map_err(|_| CryptoError::Internal)?;
        let mut hasher = Shake256::default();
        hasher.update(&key.tr);
        hasher.update(&[domain, len]);
        hasher.update(context);
        Ok(Self(hasher))
    }
}

impl Update for MuContext {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.0.update(data);
        Ok(())
    }
}

impl Finalize<{ TpmiMldsaParms::MU_BYTES }> for MuContext {
    fn finalize(self, out: &mut [u8; TpmiMldsaParms::MU_BYTES]) -> Result<(), CryptoError> {
        self.0.finalize_xof_into(out);
        Ok(())
    }
}

/// Computes `µ` for `message` under `key`.
fn mu(key: &MldsaPublicKey, message: MldsaMessage<'_>) -> Result<Mu, CryptoError> {
    let mut mu = [0u8; TpmiMldsaParms::MU_BYTES];
    match message {
        MldsaMessage::Pure { context, message } => {
            let mut ctx = MuContext::new(key, PURE, context)?;
            ctx.update(message)?;
            ctx.finalize(&mut mu)?;
        }
        MldsaMessage::PreHash { context, digest } => {
            let mut ctx = MuContext::new(key, PRE_HASH, context)?;
            ctx.update(pre_hash_oid(digest.hash_alg()))?;
            ctx.update(digest.digest())?;
            ctx.finalize(&mut mu)?;
        }
        MldsaMessage::ExternalMu(external) => mu = *external,
    }
    Ok(Mu::from(mu))
}

/// Derives the key pair for seed `ξ` (`ML-DSA.KeyGen_internal`).
fn key_pair<P: MlDsaParams>(
    seed: &[u8; 32],
    wrap_public: fn(VerifyingKey<P>) -> Vk,
    wrap_secret: fn(Box<ExpandedSigningKey<P>>) -> Sk,
) -> MldsaPrivateKey {
    let secret = Box::new(ExpandedSigningKey::<P>::from_seed(&Seed::from(*seed)));
    MldsaPrivateKey {
        public: MldsaPublicKey::new(wrap_public(secret.verifying_key())),
        secret: wrap_secret(secret),
        seed: *seed,
    }
}

/// Decodes an encoded public key, or returns `None` if it has the wrong length.
fn decode<P: MlDsaParams>(key: &[u8]) -> Option<VerifyingKey<P>> {
    let key = EncodedVerifyingKey::<P>::try_from(key).ok()?;
    Some(VerifyingKey::decode(&key))
}

/// Signs `mu` with `key` using randomness from `rng`, and writes the encoded
/// signature to `out`.
fn sign_mu<'a, P: MlDsaParams>(
    key: &ExpandedSigningKey<P>,
    mu: &Mu,
    rng: &mut ChaChaRng,
    out: &'a mut [u8],
) -> Result<&'a [u8], CryptoError> {
    let signature = key
        .sign_mu_randomized(mu, &mut RandCore(rng))
        .map_err(|_| CryptoError::Internal)?;
    copy_prefix(out, &signature.encode())
}

/// Verifies the encoded `signature` over `mu` with `key`. Returns `false` if
/// `signature` has the wrong length or is malformed.
fn verify_mu<P: MlDsaParams>(key: &VerifyingKey<P>, mu: &Mu, signature: &[u8]) -> bool {
    Signature::<P>::try_from(signature).is_ok_and(|signature| key.verify_mu(mu, &signature))
}

/// Adapts a [`ChaChaRng`] to the `rand_core` 0.10 traits used by `ml-dsa`.
struct RandCore<'a>(&'a mut ChaChaRng);

impl TryRng for RandCore<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self.0.0.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(self.0.0.next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.0.0.fill_bytes(dst);
        Ok(())
    }
}

impl TryCryptoRng for RandCore<'_> {}

impl Mldsa for RustCrypto {
    type PublicKey = MldsaPublicKey;
    type PrivateKey = MldsaPrivateKey;
    type MuContext = MuContext;

    fn load_public(
        &self,
        parameter_set: TpmiMldsaParms,
        key: Tpm2bPublicKeyMldsa<'_>,
    ) -> Result<Option<MldsaPublicKey>, CryptoError> {
        // Every byte string of the right length is a valid encoding
        // (FIPS 204, Algorithm 23).
        let key = key.as_slice();
        let vk = match parameter_set {
            TpmiMldsaParms::Mldsa44 => decode(key).map(Vk::Mldsa44),
            TpmiMldsaParms::Mldsa65 => decode(key).map(Vk::Mldsa65),
            TpmiMldsaParms::Mldsa87 => decode(key).map(Vk::Mldsa87),
        };
        Ok(vk.map(MldsaPublicKey::new))
    }

    fn derive_key(
        &self,
        parameter_set: TpmiMldsaParms,
        seed: Tpm2bPrivateKeyMldsa<'_>,
    ) -> Result<MldsaPrivateKey, CryptoError> {
        Ok(match parameter_set {
            TpmiMldsaParms::Mldsa44 => key_pair(seed.0, Vk::Mldsa44, Sk::Mldsa44),
            TpmiMldsaParms::Mldsa65 => key_pair(seed.0, Vk::Mldsa65, Sk::Mldsa65),
            TpmiMldsaParms::Mldsa87 => key_pair(seed.0, Vk::Mldsa87, Sk::Mldsa87),
        })
    }

    fn mu_start(
        &self,
        key: &MldsaPublicKey,
        context: Tpm2bSignatureCtx<'_>,
    ) -> Result<MuContext, CryptoError> {
        MuContext::new(key, PURE, context)
    }

    /// Signs `message` with `key` (hedged, using randomness from `rng`).
    ///
    /// Never returns `Ok(None)`: `ml-dsa` keeps sampling until it finds a
    /// signature (it panics after about `2^16 / ℓ` attempts, which happens
    /// with negligible probability).
    fn sign<'a>(
        &self,
        rng: &mut ChaChaRng,
        key: &MldsaPrivateKey,
        message: MldsaMessage<'_>,
        out: &'a mut [u8; TpmiMldsaParms::MAX_SIG_BYTES],
    ) -> Result<Option<Tpm2bSignatureMldsa<'a>>, CryptoError> {
        let mu = mu(&key.public, message)?;
        let signature = dispatch!(Sk, &key.secret, sk => sign_mu(sk, &mu, rng, out))?;
        Tpm2bSignatureMldsa::new(signature)
            .ok_or(CryptoError::Internal)
            .map(Some)
    }

    fn verify(
        &self,
        key: &MldsaPublicKey,
        message: MldsaMessage<'_>,
        signature: Tpm2bSignatureMldsa<'_>,
    ) -> Result<bool, CryptoError> {
        let mu = mu(key, message)?;
        let signature = signature.as_slice();
        Ok(dispatch!(Vk, &key.key, vk => verify_mu(vk, &mu, signature)))
    }
}
