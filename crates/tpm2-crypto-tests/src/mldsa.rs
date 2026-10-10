//! Tests for [`Mldsa`].

use sha3::{
    Shake256,
    digest::{ExtendableOutput as _, Update as _},
};
use tpm2::{
    Tpm2b, Tpm2bPublicKeyMldsa, Tpm2bSignatureCtx, Tpm2bSignatureMldsa, TpmiAlgHash,
    TpmiMldsaParms,
    crypto::{
        CryptoError, Finalize, Mldsa, MldsaMessage, MldsaPrivateKey, MldsaPublicKey, Update,
        pre_hash_oid,
    },
};

use crate::{
    Caps, Check, expect_support,
    util::{HASHES, MLDSA, assert_bytes, flip, pattern, same_size_hash, seeded_rng, tpmt_ha},
    vectors::mldsa as kat,
};

/// Returns the encoded public key of `key`.
pub(crate) fn encoded<K: MldsaPublicKey>(key: &K) -> Vec<u8> {
    let mut out = [0u8; TpmiMldsaParms::MAX_PUB_KEY_BYTES];
    key.encoded(&mut out)
        .check("MldsaPublicKey::encoded")
        .as_slice()
        .to_vec()
}

/// Returns the 32-byte `ξ` seed of `key`.
pub(crate) fn seed<K: MldsaPrivateKey>(key: &K) -> [u8; 32] {
    let mut out = [0u8; 32];
    let s = key.seed(&mut out).check("MldsaPrivateKey::seed");
    *s.0
}

/// Derives a key pair from `seed`, or returns `None` if `parms` is
/// (correctly) unsupported.
pub(crate) fn derive<C: Mldsa>(
    c: &C,
    caps: &Caps,
    parms: TpmiMldsaParms,
    seed: &[u8; 32],
) -> Option<C::PrivateKey> {
    let result = Mldsa::derive_key(c, parms, Tpm2b(seed));
    expect_support(caps.mldsa.contains(&parms), format!("{parms:?}"), result)
}

/// Loads an encoded public key, returning `None` if it is rejected.
pub(crate) fn load_public<C: Mldsa>(
    c: &C,
    parms: TpmiMldsaParms,
    bytes: &[u8],
) -> Option<C::PublicKey> {
    let pk = Tpm2bPublicKeyMldsa::new(bytes).expect("ML-DSA public key too long");
    Mldsa::load_public(c, parms, pk).check("Mldsa::load_public")
}

/// Builds a [`Tpm2bSignatureCtx`] from `ctx`.
pub(crate) fn sig_ctx(ctx: &[u8]) -> Tpm2bSignatureCtx<'_> {
    Tpm2bSignatureCtx::new(ctx).expect("ML-DSA context longer than 255 bytes")
}

/// Signs `message` with `key`.
pub(crate) fn sign<C: Mldsa>(
    c: &C,
    rng: &mut C::Rng,
    key: &C::PrivateKey,
    message: MldsaMessage<'_>,
) -> Result<Vec<u8>, CryptoError> {
    let mut out = [0u8; TpmiMldsaParms::MAX_SIG_BYTES];
    let sig = Mldsa::sign(c, rng, key, message, &mut out)?
        .expect("ML-DSA signing hit rejection-sampling limit");
    Ok(sig.as_slice().to_vec())
}

/// Verifies `signature` over `message` with `key`.
pub(crate) fn verify<C: Mldsa>(
    c: &C,
    key: &C::PublicKey,
    message: MldsaMessage<'_>,
    signature: &[u8],
) -> Result<bool, CryptoError> {
    let sig = Tpm2bSignatureMldsa::new(signature).expect("ML-DSA signature too long");
    Mldsa::verify(c, key, message, sig)
}

/// Computes the FIPS 204 message representative `µ = H(H(pk, 64) || M', 64)`
/// using the independent [`sha3::Shake256`] oracle, where
/// `M' = domain || |ctx| || ctx || body`.
pub(crate) fn reference_mu(pk: &[u8], domain: u8, ctx: &[u8], body: &[&[u8]]) -> [u8; 64] {
    let mut tr = [0u8; 64];
    let mut h_pk = Shake256::default();
    h_pk.update(pk);
    h_pk.finalize_xof_into(&mut tr);

    let ctx_len = u8::try_from(ctx.len()).expect("context too long");
    let mut h_mu = Shake256::default();
    h_mu.update(&tr);
    h_mu.update(&[domain, ctx_len]);
    h_mu.update(ctx);
    for part in body {
        h_mu.update(part);
    }
    let mut mu = [0u8; 64];
    h_mu.finalize_xof_into(&mut mu);
    mu
}

/// NIST ACVP `ML-DSA-keyGen-FIPS204` known answers for ML-DSA-44, ML-DSA-65,
/// and ML-DSA-87.
pub fn mldsa_keygen_kat<C: Mldsa>(c: &C, caps: &Caps) {
    for (parms, seed_bytes, expected_pk) in kat::KEYGEN {
        let Some(private) = derive(c, caps, parms, &seed_bytes) else {
            continue;
        };
        let public = private.public_key();
        assert_eq!(public.parameter_set(), parms);
        assert_bytes(&seed(&private), &seed_bytes, format!("{parms:?} seed"));
        assert_bytes(
            &encoded(public),
            expected_pk,
            format!("{parms:?} public key"),
        );
    }
}

/// NIST ACVP `ML-DSA-sigVer-FIPS204` (`externalMu = true`) known answers:
/// valid signatures and corrupted `z` / hint vectors for every parameter set.
pub fn mldsa_sigver_kat<C: Mldsa>(c: &C, caps: &Caps) {
    for v in kat::SIGVER {
        let pk_tpm2b = Tpm2bPublicKeyMldsa::new(v.pk).expect("valid KAT pk");
        let load_res = Mldsa::load_public(c, v.parameter_set, pk_tpm2b);
        let Some(public) = expect_support(
            caps.mldsa.contains(&v.parameter_set),
            format!("{:?}", v.parameter_set),
            load_res,
        ) else {
            continue;
        };
        let public = public.expect("valid KAT public key rejected");
        let what = format!("{:?} ACVP tcId {}", v.parameter_set, v.tc_id);
        let result = verify(c, &public, MldsaMessage::ExternalMu(&v.mu), v.sig);
        let Some(actual) = expect_support(caps.mldsa_external_mu, &what, result) else {
            continue;
        };
        assert_eq!(actual, v.valid, "{what}");
    }
}

/// Pure ML-DSA signing and verification round-trip across every parameter set,
/// with empty and non-empty contexts, plus negative checks (tampered
/// signature, wrong message, wrong context, wrong length, and domain
/// separation from `PreHash`).
pub fn mldsa_pure_roundtrip<C: Mldsa>(c: &C, caps: &Caps) {
    let mut rng = seeded_rng(c, "mldsa_pure_roundtrip");
    for &parms in MLDSA {
        let result = Mldsa::generate_key(c, &mut rng, parms);
        let Some(key) = expect_support(caps.mldsa.contains(&parms), format!("{parms:?}"), result)
        else {
            continue;
        };
        assert_eq!(key.public_key().parameter_set(), parms);
        let pk_bytes = encoded(key.public_key());
        assert_eq!(
            pk_bytes.len(),
            parms.pub_key_bytes(),
            "{parms:?}: public key length"
        );

        let reloaded = load_public(c, parms, &pk_bytes).expect("generated public key rejected");
        assert_eq!(reloaded.parameter_set(), parms);
        assert_bytes(
            &encoded(&reloaded),
            &pk_bytes,
            format!("{parms:?} reloaded public key"),
        );

        for (ctx, msg) in [
            (&b""[..], &b""[..]),
            (b"tpm-rs context", b"pure ML-DSA test message"),
        ] {
            let what = format!("{parms:?} Pure (ctx len {})", ctx.len());
            let pure = MldsaMessage::Pure {
                context: sig_ctx(ctx),
                message: msg,
            };
            let sig1 = sign(c, &mut rng, &key, pure).check(&what);
            assert_eq!(sig1.len(), parms.sig_bytes(), "{what}: signature length");
            assert!(
                verify(c, &reloaded, pure, &sig1).check(&what),
                "{what}: valid signature rejected"
            );

            // Hedged signing produces distinct signatures. (BoringSSL draws the randomness from its
            // own CSPRNG rather than from the RNG.)
            let sig2 = sign(c, &mut rng, &key, pure).check(&what);
            assert_ne!(sig1, sig2, "{what}: signing isn't randomized");
            assert!(
                verify(c, &reloaded, pure, &sig2).check(&what),
                "{what}: second signature rejected"
            );

            // Tampered signature (first byte in `c~` and last byte in `h`).
            for idx in [0, sig1.len() / 2, sig1.len() - 1] {
                assert!(
                    !verify(c, &reloaded, pure, &flip(&sig1, idx)).check(&what),
                    "{what}: signature with flipped byte {idx} accepted"
                );
            }

            // Wrong message and wrong context.
            let wrong_msg = MldsaMessage::Pure {
                context: sig_ctx(ctx),
                message: b"different message",
            };
            assert!(
                !verify(c, &reloaded, wrong_msg, &sig1).check(&what),
                "{what}: signature accepted for wrong message"
            );
            let other_ctx: &[u8] = if ctx.is_empty() { b"non-empty" } else { b"" };
            let wrong_ctx = MldsaMessage::Pure {
                context: sig_ctx(other_ctx),
                message: msg,
            };
            assert!(
                !verify(c, &reloaded, wrong_ctx, &sig1).check(&what),
                "{what}: signature accepted for wrong context"
            );

            // Wrong signature lengths.
            assert!(
                !verify(c, &reloaded, pure, &[]).check(&what),
                "{what}: empty signature accepted"
            );
            assert!(
                !verify(c, &reloaded, pure, &sig1[..sig1.len() - 1]).check(&what),
                "{what}: short signature accepted"
            );

            // Domain separation: a Pure signature does not verify as PreHash.
            if caps.mldsa_pre_hash.contains(&TpmiAlgHash::Sha256) {
                let pre_hash = MldsaMessage::PreHash {
                    context: sig_ctx(ctx),
                    digest: tpmt_ha(TpmiAlgHash::Sha256, &[0u8; 32]),
                };
                assert!(
                    !verify(c, &reloaded, pre_hash, &sig1).check(&what),
                    "{what}: Pure signature accepted as PreHash"
                );
            }
        }
    }
}

/// HashML-DSA ([`MldsaMessage::PreHash`]) round-trip across every parameter
/// set and hash algorithm, checking context binding, OID binding, and
/// agreement with the reference `M' = 1 || |ctx| || ctx || OID || PH(M)`
/// encoding.
pub fn mldsa_pre_hash_roundtrip<C: Mldsa>(c: &C, caps: &Caps) {
    let mut rng = seeded_rng(c, "mldsa_pre_hash_roundtrip");
    for (parms, seed_bytes, pk_bytes) in kat::KEYGEN {
        let Some(key) = derive(c, caps, parms, &seed_bytes) else {
            continue;
        };
        let ctx = b"HashML-DSA context";
        for &hash in HASHES {
            let what = format!("{parms:?} PreHash {hash:?}");
            let supported = caps.mldsa_pre_hash.contains(&hash);
            let digest_bytes = pattern(hash.digest_size(), 50);
            let msg = MldsaMessage::PreHash {
                context: sig_ctx(ctx),
                digest: tpmt_ha(hash, &digest_bytes),
            };
            let result = sign(c, &mut rng, &key, msg);
            let Some(sig) = expect_support(supported, &what, result) else {
                let dummy = vec![0u8; parms.sig_bytes()];
                let verify_res = verify(c, key.public_key(), msg, &dummy);
                expect_support(false, &what, verify_res);
                continue;
            };
            assert_eq!(sig.len(), parms.sig_bytes());
            assert!(
                verify(c, key.public_key(), msg, &sig).check(&what),
                "{what}: valid signature rejected"
            );

            // Tampered signature, tampered digest, and wrong context.
            assert!(
                !verify(c, key.public_key(), msg, &flip(&sig, 0)).check(&what),
                "{what}: corrupted signature accepted"
            );
            let flipped_digest = flip(&digest_bytes, 0);
            let bad_digest = MldsaMessage::PreHash {
                context: sig_ctx(ctx),
                digest: tpmt_ha(hash, &flipped_digest),
            };
            assert!(
                !verify(c, key.public_key(), bad_digest, &sig).check(&what),
                "{what}: corrupted digest accepted"
            );
            let bad_ctx = MldsaMessage::PreHash {
                context: sig_ctx(b"wrong context"),
                digest: tpmt_ha(hash, &digest_bytes),
            };
            assert!(
                !verify(c, key.public_key(), bad_ctx, &sig).check(&what),
                "{what}: wrong context accepted"
            );

            // Different hash algorithm with the same digest size (different OID).
            if let Some(other_hash) = same_size_hash(hash)
                && caps.mldsa_pre_hash.contains(&other_hash)
            {
                let wrong_oid = MldsaMessage::PreHash {
                    context: sig_ctx(ctx),
                    digest: tpmt_ha(other_hash, &digest_bytes),
                };
                assert!(
                    !verify(c, key.public_key(), wrong_oid, &sig).check(&what),
                    "{what}: signature accepted under {other_hash:?} OID"
                );
            }

            // If ExternalMu is supported, check that PreHash uses the exact
            // FIPS 204 Algorithm 4 `M'` encoding with `pre_hash_oid(hash)`.
            if caps.mldsa_external_mu {
                let mu = reference_mu(pk_bytes, 1, ctx, &[pre_hash_oid(hash), &digest_bytes]);
                assert!(
                    verify(c, key.public_key(), MldsaMessage::ExternalMu(&mu), &sig).check(&what),
                    "{what}: PreHash signature did not verify against reference ExternalMu"
                );
            }
        }
    }
}

/// Signing an externally computed `µ` ([`MldsaMessage::ExternalMu`]) produces
/// signatures that verify as [`MldsaMessage::Pure`], and vice versa.
pub fn mldsa_external_mu_matches_pure<C: Mldsa>(c: &C, caps: &Caps) {
    let mut rng = seeded_rng(c, "mldsa_external_mu_matches_pure");
    for (parms, seed_bytes, pk_bytes) in kat::KEYGEN {
        let Some(key) = derive(c, caps, parms, &seed_bytes) else {
            continue;
        };
        for ctx in [&b""[..], b"external mu context"] {
            let what = format!("{parms:?} ExternalMu (ctx len {})", ctx.len());
            let msg = b"message for external mu";
            let mu = reference_mu(pk_bytes, 0, ctx, &[msg]);
            let ext = MldsaMessage::ExternalMu(&mu);

            let result = sign(c, &mut rng, &key, ext);
            let Some(sig_from_mu) = expect_support(caps.mldsa_external_mu, &what, result) else {
                let dummy = vec![0u8; parms.sig_bytes()];
                let verify_res = verify(c, key.public_key(), ext, &dummy);
                expect_support(false, &what, verify_res);
                continue;
            };

            let pure = MldsaMessage::Pure {
                context: sig_ctx(ctx),
                message: msg,
            };
            assert!(
                verify(c, key.public_key(), pure, &sig_from_mu).check(&what),
                "{what}: ExternalMu signature rejected by Pure verify"
            );
            assert!(
                verify(c, key.public_key(), ext, &sig_from_mu).check(&what),
                "{what}: ExternalMu signature rejected by ExternalMu verify"
            );

            let sig_from_pure = sign(c, &mut rng, &key, pure).check(&what);
            assert!(
                verify(c, key.public_key(), ext, &sig_from_pure).check(&what),
                "{what}: Pure signature rejected by ExternalMu verify"
            );
            let mut bad_mu = mu;
            bad_mu[0] ^= 0x01;
            assert!(
                !verify(
                    c,
                    key.public_key(),
                    MldsaMessage::ExternalMu(&bad_mu),
                    &sig_from_pure
                )
                .check(&what),
                "{what}: signature accepted for modified mu"
            );
        }
    }
}

/// [`Mldsa::mu_start`] streams the message in chunks and produces the same
/// 64-byte `µ` as the independent SHAKE256 oracle, and round-trips with
/// [`MldsaMessage::Pure`].
pub fn mldsa_mu_start_matches_reference<C: Mldsa>(c: &C, caps: &Caps) {
    let mut rng = seeded_rng(c, "mldsa_mu_start_matches_reference");
    let data = pattern(300, 60);
    for (parms, seed_bytes, pk_bytes) in kat::KEYGEN {
        let Some(key) = derive(c, caps, parms, &seed_bytes) else {
            continue;
        };
        let public = key.public_key();
        for ctx in [&b""[..], b"mu_start context"] {
            let what = format!("{parms:?} mu_start (ctx len {})", ctx.len());
            let result = Mldsa::mu_start(c, public, sig_ctx(ctx));
            let Some(mut stream) = expect_support(caps.mldsa_mu_start, &what, result) else {
                continue;
            };
            for chunk in data.chunks(37) {
                stream.update(chunk).check("MuContext::update");
                stream.update(&[]).check("MuContext::update (empty)");
            }
            let mut mu = [0u8; TpmiMldsaParms::MU_BYTES];
            stream.finalize(&mut mu).check("MuContext::finalize");

            let expected = reference_mu(pk_bytes, 0, ctx, &[&data]);
            assert_bytes(&mu, &expected, &what);

            if caps.mldsa_external_mu {
                let sig = sign(c, &mut rng, &key, MldsaMessage::ExternalMu(&mu)).check(&what);
                let pure = MldsaMessage::Pure {
                    context: sig_ctx(ctx),
                    message: &data,
                };
                assert!(
                    verify(c, public, pure, &sig).check(&what),
                    "{what}: mu_start + ExternalMu signature rejected by Pure verify"
                );
            }
        }
    }
}

/// Public keys of the wrong length for the parameter set are rejected with
/// `Ok(None)`.
pub fn mldsa_load_public_rejects<C: Mldsa>(c: &C, caps: &Caps) {
    for (parms, _, pk) in kat::KEYGEN {
        let probe = Tpm2bPublicKeyMldsa::new(pk).expect("valid key");
        let result = Mldsa::load_public(c, parms, probe);
        let Some(loaded) =
            expect_support(caps.mldsa.contains(&parms), format!("{parms:?}"), result)
        else {
            continue;
        };
        assert!(loaded.is_some(), "{parms:?}: valid KAT key rejected");

        assert!(
            load_public(c, parms, &[]).is_none(),
            "{parms:?}: empty key accepted"
        );
        assert!(
            load_public(c, parms, &pk[..pk.len() - 1]).is_none(),
            "{parms:?}: short key accepted"
        );
        if pk.len() < Tpm2bPublicKeyMldsa::CAP {
            let long = [pk, &[0x00]].concat();
            assert!(
                load_public(c, parms, &long).is_none(),
                "{parms:?}: long key accepted"
            );
        }
    }
}

/// [`Mldsa::load_private`] accepts the matching 32-byte `ξ` seed and rejects a
/// mismatched seed with `Ok(None)`.
pub fn mldsa_load_private<C: Mldsa>(c: &C, caps: &Caps) {
    for (parms, seed_bytes, pk) in kat::KEYGEN {
        if !caps.mldsa.contains(&parms) {
            continue;
        }
        let public = load_public(c, parms, pk).expect("valid KAT key rejected");
        let private = Mldsa::load_private(c, public, Tpm2b(&seed_bytes))
            .check("Mldsa::load_private")
            .expect("matching seed rejected");
        assert_bytes(
            &seed(&private),
            &seed_bytes,
            format!("{parms:?} loaded seed"),
        );
        assert_bytes(
            &encoded(private.public_key()),
            pk,
            format!("{parms:?} loaded public key"),
        );

        let mut bad_seed = seed_bytes;
        bad_seed[0] ^= 0x01;
        let public = load_public(c, parms, pk).expect("valid KAT key rejected");
        let rejected =
            Mldsa::load_private(c, public, Tpm2b(&bad_seed)).check("Mldsa::load_private");
        assert!(rejected.is_none(), "{parms:?}: mismatched seed accepted");
    }
}
