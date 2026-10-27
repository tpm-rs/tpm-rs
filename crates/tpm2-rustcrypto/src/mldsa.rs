#![allow(missing_docs)]
use crate::RngWrapper;

use ml_dsa::{Signature, VerifyingKey};
use shake::{ExtendableOutput, Shake256, Update, XofReader};

use tpm2::TpmtHa;
use tpm2::crypto::{
    CryptoError, Rng,
    backend::{AsymmetricKey, MldsaKey},
};

fn der_oid_for_hash(alg: tpm2::TpmiAlgHash) -> &'static [u8] {
    match alg {
        tpm2::TpmiAlgHash::Sha1 => &[0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a],
        tpm2::TpmiAlgHash::Sha256 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ],
        tpm2::TpmiAlgHash::Sha384 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        ],
        tpm2::TpmiAlgHash::Sha512 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        ],
        tpm2::TpmiAlgHash::Sm3_256 => &[0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x11],
        tpm2::TpmiAlgHash::Sha3_256 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
        ],
        tpm2::TpmiAlgHash::Sha3_384 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09,
        ],
        tpm2::TpmiAlgHash::Sha3_512 => &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a,
        ],
    }
}

fn compute_mu(
    public: &[u8],
    domain: u8,
    context: &[u8],
    parts: &[&[u8]],
) -> Result<[u8; 64], CryptoError> {
    let ctx_len = u8::try_from(context.len()).map_err(|_| CryptoError::Internal)?;
    let mut tr = [0u8; 64];
    let mut h_tr = Shake256::default();
    h_tr.update(public);
    h_tr.finalize_xof().read(&mut tr);

    let mut h_mu = Shake256::default();
    h_mu.update(&tr);
    h_mu.update(&[domain, ctx_len]);
    h_mu.update(context);
    for part in parts {
        h_mu.update(part);
    }
    let mut mu = [0u8; 64];
    h_mu.finalize_xof().read(&mut mu);
    Ok(mu)
}

macro_rules! impl_mldsa {
    ($name:ident, $keypair:ident, $mldsa:path, $pub_size:literal, $sig_size:literal) => {
        pub struct $name;

        pub struct $keypair {
            pub seed: [u8; 32],
            pub public: [u8; $pub_size],
        }

        impl $name {
            #[inline(never)]
            fn encode_vk_from_sk(sk: &ml_dsa::SigningKey<$mldsa>, out_pub: &mut [u8; $pub_size]) {
                let vk = sk.expanded_key().verifying_key();
                out_pub.copy_from_slice(vk.encode().as_ref());
            }

            #[inline(never)]
            fn derive_public(seed: &[u8; 32], out_pub: &mut [u8; $pub_size]) {
                let sk = ml_dsa::SigningKey::<$mldsa>::from_seed(seed.into());
                Self::encode_vk_from_sk(&sk, out_pub);
            }

            #[inline(never)]
            fn sign_with_sk(
                rng: &mut impl Rng,
                sk: &ml_dsa::SigningKey<$mldsa>,
                mu: &[u8; 64],
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                let mut wrapper = RngWrapper(rng);
                let sig = sk
                    .expanded_key()
                    .sign_mu_randomized(mu.into(), &mut wrapper)
                    .map_err(|_| CryptoError::Internal)?;
                out_sig.copy_from_slice(sig.encode().as_ref());
                Ok(())
            }

            #[inline(never)]
            fn sign_mu_inner(
                rng: &mut impl Rng,
                seed: &[u8; 32],
                mu: &[u8; 64],
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                let sk = ml_dsa::SigningKey::<$mldsa>::from_seed(seed.into());
                Self::sign_with_sk(rng, &sk, mu, out_sig)
            }

            #[inline(never)]
            fn verify_mu_inner(
                public: &[u8; $pub_size],
                mu: &[u8; 64],
                sig: &[u8; $sig_size],
            ) -> Result<bool, CryptoError> {
                let Some(s) = Signature::<$mldsa>::decode(sig.into()) else {
                    return Ok(false);
                };
                let vk = VerifyingKey::<$mldsa>::decode(public.into());
                Ok(vk.verify_mu(mu.into(), &s))
            }
        }

        impl AsymmetricKey<$pub_size, 32> for $name {
            type Public = [u8; $pub_size];
            type Private = $keypair;

            fn generate(rng: &mut impl Rng, _: ()) -> Result<Self::Private, CryptoError> {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed)?;
                let mut public = [0u8; $pub_size];
                Self::derive_public(&seed, &mut public);
                Ok($keypair { seed, public })
            }

            fn load_public(
                _: (),
                public: &[u8; $pub_size],
            ) -> Result<Option<Self::Public>, CryptoError> {
                Ok(Some(*public))
            }

            fn store_public(
                public: &Self::Public,
                out: &mut [u8; $pub_size],
            ) -> Result<(), CryptoError> {
                out.copy_from_slice(public);
                Ok(())
            }

            fn load_private(
                public: Self::Public,
                seed: &[u8; 32],
            ) -> Result<Option<Self::Private>, CryptoError> {
                let mut derived = [0u8; $pub_size];
                Self::derive_public(seed, &mut derived);
                if derived != public {
                    return Ok(None);
                }
                Ok(Some($keypair {
                    seed: *seed,
                    public,
                }))
            }

            fn store_private(
                private: &Self::Private,
                out: &mut [u8; 32],
            ) -> Result<(), CryptoError> {
                out.copy_from_slice(&private.seed);
                Ok(())
            }

            fn as_public(private: &Self::Private) -> &Self::Public {
                &private.public
            }
        }

        impl MldsaKey<$pub_size, $sig_size> for $name {
            fn sign_message(
                rng: &mut impl Rng,
                private: &Self::Private,
                context: &[u8],
                msg: &[&[u8]],
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                let mu = compute_mu(&private.public, 0x00, context, msg)?;
                Self::sign_mu(rng, private, &mu, out_sig)
            }

            fn verify_message(
                public: &Self::Public,
                context: &[u8],
                msg: &[&[u8]],
                sig: &[u8; $sig_size],
            ) -> Result<bool, CryptoError> {
                let mu = compute_mu(public, 0x00, context, msg)?;
                Self::verify_mu(public, &mu, sig)
            }

            fn sign_mu(
                rng: &mut impl Rng,
                private: &Self::Private,
                mu: &[u8; 64],
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                Self::sign_mu_inner(rng, &private.seed, mu, out_sig)
            }

            fn verify_mu(
                public: &Self::Public,
                mu: &[u8; 64],
                sig: &[u8; $sig_size],
            ) -> Result<bool, CryptoError> {
                Self::verify_mu_inner(public, mu, sig)
            }

            fn sign_prehash(
                rng: &mut impl Rng,
                private: &Self::Private,
                context: &[u8],
                digest: TpmtHa<'_>,
                out_sig: &mut [u8; $sig_size],
            ) -> Result<(), CryptoError> {
                let der_oid = der_oid_for_hash(digest.hash_alg());
                let mu = compute_mu(&private.public, 0x01, context, &[der_oid, digest.digest()])?;
                Self::sign_mu(rng, private, &mu, out_sig)
            }

            fn verify_prehash(
                public: &Self::Public,
                context: &[u8],
                digest: TpmtHa<'_>,
                sig: &[u8; $sig_size],
            ) -> Result<bool, CryptoError> {
                let der_oid = der_oid_for_hash(digest.hash_alg());
                let mu = compute_mu(public, 0x01, context, &[der_oid, digest.digest()])?;
                Self::verify_mu(public, &mu, sig)
            }
        }
    };
}

impl_mldsa!(Mldsa44Wrapper, Mldsa44KeyPair, ml_dsa::MlDsa44, 1312, 2420);
impl_mldsa!(Mldsa65Wrapper, Mldsa65KeyPair, ml_dsa::MlDsa65, 1952, 3309);
impl_mldsa!(Mldsa87Wrapper, Mldsa87KeyPair, ml_dsa::MlDsa87, 2592, 4627);
