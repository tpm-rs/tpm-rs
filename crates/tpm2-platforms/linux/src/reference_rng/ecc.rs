//! The C reference TPMs' random ECC operations (`CryptEccMain.c`, `CryptEccSignature.c` and
//! `TpmEcc_Signature_*.c` of the TCG reference implementation), linked from the original C
//! code: key generation (`TpmEcc_GenPrivateScalar()`, used for every ECC key and every ECDSA
//! nonce, and the point multiplication of the reference's big-number library) and signing
//! (ECDSA, SM2, EC-Schnorr). They are the test oracles of `tpm2_engine::asymmetric`, the Rust
//! implementations with the same draws (`oracles.rs`).
//!
//! Every function writes big-endian values padded to the coordinate (key) or order (signature)
//! size of the curve and returns that size.

use tpm2::TpmEccCurve;
use tpm2::errors::TpmRc;

use tpm2_engine::DrbgState;

use super::{RefRng, ffi};

/// Largest coordinate or order size of the supported curves (NIST P-521, or BN P-638).
const MAX_COORD_BYTES: usize = tpm2::TpmEccCurve::MAX_ECC_KEY_BYTES;

/// Splits `q` into the `x` and `y` halves of a point output buffer.
fn split_point(q: &mut [u8]) -> (&mut [u8], &mut [u8]) {
    let half = q.len() / 2;
    q.split_at_mut(half)
}

/// Joins the coordinates written to the front of each half of `q` (`len` bytes each) into
/// `x || y` at the front of `q`.
fn join_point(q: &mut [u8], len: usize) {
    let half = q.len() / 2;
    q.copy_within(half..half + len, len);
}

/// `CryptEccGenerateKey()`: generates a key pair on `curve` from `rand` (`None`: the TPM's
/// DRBG). Writes the private scalar to the front of `d` and `x || y` to the front of `q`, and
/// returns the coordinate size.
///
/// For a signing key (`sign`), the reference's FIPS pairwise consistency test is run as well,
/// which draws a digest and an ECDSA nonce from the TPM's DRBG (also when the key itself is drawn
/// from a seeded DRBG).
///
/// Errors: `TPM_RC_CURVE` for an unsupported curve, `TPM_RC_FAILURE` if the outputs are too small
/// or drawing fails.
pub fn generate_key(
    rng: &mut RefRng<'_>,
    rand: Option<&mut DrbgState>,
    curve: TpmEccCurve,
    sign: bool,
    d: &mut [u8],
    q: &mut [u8],
) -> Result<usize, TpmRc> {
    let (x, y) = split_point(q);
    let len = ffi::ecc_generate_key(rng, rand, curve.into(), sign, d, x, y)?;
    join_point(q, len);
    Ok(len)
}

/// `CryptEccNewKeyPair()`: an ephemeral key pair on `curve` from the TPM's DRBG (ECDH_KeyGen,
/// `CryptSecretEncrypt()` for ECC keys), written as by [`generate_key`].
pub fn new_key_pair(
    rng: &mut RefRng<'_>,
    curve: TpmEccCurve,
    d: &mut [u8],
    q: &mut [u8],
) -> Result<usize, TpmRc> {
    let (x, y) = split_point(q);
    let len = ffi::ecc_new_key_pair(rng, curve.into(), d, x, y)?;
    join_point(q, len);
    Ok(len)
}

/// The FIPS pairwise consistency test of `CryptEccGenerateKey()` for a signing key with private
/// scalar `d` on `curve`: signs a random digest of `min(d.len(), TpmiAlgHash::MAX_DIGEST_BYTES)`
/// bytes with ECDSA, both drawn
/// from the TPM's DRBG, and verifies the signature. The oracle of the tests that check that
/// `tpm2-engine`'s pairwise test (a digest drawn with `Rng::fill_bytes`, then
/// `tpm2_engine::asymmetric::ecdsa_sign`) draws the same.
#[cfg(test)]
pub fn pairwise_test(rng: &mut RefRng<'_>, curve: TpmEccCurve, d: &[u8]) -> Result<(), TpmRc> {
    ffi::ecc_pairwise_test(rng, curve.into(), d)
}

/// `TpmEcc_SignEcdsa()` (the ECDSA case of `CryptEccSign()`): signs `digest` with the private
/// scalar `d` on `curve`, drawing the nonces from `rand` (`None`: the TPM's DRBG). Writes `r` and
/// `s` (each padded to the order size) to the fronts of `r` and `s`, and returns the order size.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub fn sign_ecdsa(
    rng: &mut RefRng<'_>,
    rand: Option<&mut DrbgState>,
    curve: TpmEccCurve,
    d: &[u8],
    digest: &[u8],
    r: &mut [u8],
    s: &mut [u8],
) -> Result<usize, TpmRc> {
    let cap = MAX_COORD_BYTES.min(r.len()).min(s.len());
    ffi::ecdsa_sign(
        rng,
        rand,
        curve.into(),
        d,
        digest,
        &mut r[..cap],
        &mut s[..cap],
    )
}

/// `CryptEccSign()` with the signature scheme `scheme` (ECDSA, SM2 or EC-Schnorr) and its hash
/// `hash` (used by EC-Schnorr only): signs `digest` with the private scalar `d` on `curve`, drawing
/// the nonces from `rand` (`None`: the TPM's DRBG). Writes `r` and `s` (each padded to the order
/// size) to the fronts of `r` and `s`, and returns the order size.
#[allow(clippy::too_many_arguments)]
pub fn sign(
    rng: &mut RefRng<'_>,
    rand: Option<&mut DrbgState>,
    scheme: tpm2::Alg,
    hash: tpm2::TpmiAlgHash,
    curve: TpmEccCurve,
    d: &[u8],
    digest: &[u8],
    r: &mut [u8],
    s: &mut [u8],
) -> Result<usize, TpmRc> {
    let cap = MAX_COORD_BYTES.min(r.len()).min(s.len());
    ffi::ecc_sign(
        rng,
        rand,
        scheme.id(),
        tpm2::Alg::from(hash).id(),
        curve.into(),
        d,
        digest,
        &mut r[..cap],
        &mut s[..cap],
    )
}

#[cfg(test)]
mod tests {
    use super::super::drbg::{self, tests::FixedEntropy};
    use super::*;
    use tpm2::TpmiAlgHash;
    use tpm2_crypto_bssl::BsslCryptoProvider as Crypto;

    /// The TPM's DRBG, instantiated from fixed entropy.
    fn tpm_drbg() -> DrbgState {
        let mut state = DrbgState::default();
        let mut entropy = FixedEntropy(&[0x01, 0x23, 0x45, 0x67, 0x89], 0);
        drbg::instantiate(&mut RefRng {
            drbg: Some(&mut state),
            entropy: Some(&mut entropy),
            flags: None,
        })
        .unwrap();
        state
    }

    /// A context drawing from `state` with no entropy source.
    fn tpm(state: &mut DrbgState) -> RefRng<'_> {
        RefRng {
            drbg: Some(state),
            entropy: None,
            flags: None,
        }
    }

    #[test]
    fn generated_key_matches_the_backend_point() {
        for (curve, len) in [(TpmEccCurve::NistP256, 32), (TpmEccCurve::NistP384, 48)] {
            let mut seeded = drbg::instantiate_seeded(b"seed", b"ecc\0", b"", b"").unwrap();
            let (mut d, mut q) = ([0u8; 66], [0u8; 132]);
            let n = generate_key(
                &mut RefRng::seeded_only(),
                Some(&mut seeded),
                curve,
                false,
                &mut d,
                &mut q,
            )
            .unwrap();
            assert_eq!(n, len);
            let (mut x, mut y) = ([0u8; 66], [0u8; 66]);
            let expected =
                tpm2::crypto::ecc_mul_generator::<Crypto>(curve, &d[..n], &mut x, &mut y)
                    .unwrap()
                    .unwrap();
            assert_eq!(q[..n], *expected.x.as_slice());
            assert_eq!(q[n..2 * n], *expected.y.as_slice());
        }
    }

    #[test]
    fn signing_keys_run_the_pairwise_test_on_the_tpm_drbg() {
        let mut state = tpm_drbg();
        let mut seeded = drbg::instantiate_seeded(b"seed", b"ecc\0", b"", b"").unwrap();
        let (mut d, mut q) = ([0u8; 32], [0u8; 64]);
        let before = state;
        generate_key(
            &mut tpm(&mut state),
            Some(&mut seeded),
            TpmEccCurve::NistP256,
            true,
            &mut d,
            &mut q,
        )
        .unwrap();
        // The digest and the nonce were drawn from the TPM's DRBG.
        assert_eq!(state.reseed_counter, before.reseed_counter + 2);
        // Without a TPM DRBG, the pairwise test (and thereby the key generation) fails.
        let mut seeded = drbg::instantiate_seeded(b"seed", b"ecc\0", b"", b"").unwrap();
        assert_eq!(
            generate_key(
                &mut RefRng::seeded_only(),
                Some(&mut seeded),
                TpmEccCurve::NistP256,
                true,
                &mut d,
                &mut q,
            ),
            Err(TpmRc::FAILURE)
        );
        let before = state;
        pairwise_test(&mut tpm(&mut state), TpmEccCurve::NistP256, &d).unwrap();
        assert_eq!(state.reseed_counter, before.reseed_counter + 2);
    }

    /// The key pair [`sm2_and_schnorr_signatures_match_the_vectors`] signs with (`d`, `x || y`).
    const SIGNING_KEY: ([u8; 32], [u8; 64]) = (
        hex_literal::hex!("7409f4f9d086181e57e83eef7db68c7afe2cae4306df4d3a7cc2c3df5a913711"),
        hex_literal::hex!(
            "29bd3e4bbd95ba9ed516c859979bd6ae813d21804abb72f3782bbc989eb8cf81"
            "df3259ea1ebd7e6a928f07c7d4e9d535e51b667ccded46cb858385d53c1ba59b"
        ),
    );

    /// The SM2 and EC-Schnorr signatures (`scheme`, `hash`, `r`, `s`) of the linked
    /// `CryptEccSign()` in [`sm2_and_schnorr_signatures_match_the_vectors`], in the order they
    /// are drawn. `tpm2_engine` verifies the same signatures with its own verification
    /// (`ecc_schemes` tests, `reference_sm2_and_schnorr_signatures_verify`).
    const SIGNATURES: &[(tpm2::Alg, TpmiAlgHash, [u8; 32], [u8; 32])] = &[
        (
            tpm2::Alg::SM2,
            TpmiAlgHash::Sha1,
            hex_literal::hex!("b2c94d386bae95d62ff012c60bb53fa2650690c822d6f19597994b8d15e9aae6"),
            hex_literal::hex!("ae214303b08df066b1ce7dd5f3507e05b3131a6ae1df6d79527e2fa7062206e1"),
        ),
        (
            tpm2::Alg::ECSCHNORR,
            TpmiAlgHash::Sha1,
            hex_literal::hex!("00000000000000000000000098beba31e5ba04b06a1ba541a09ee0c390c03ec7"),
            hex_literal::hex!("601dbeb2cbc7d2986c2a555b7335ea477614ccb85b3719117f5723c8e52e511e"),
        ),
        (
            tpm2::Alg::SM2,
            TpmiAlgHash::Sha256,
            hex_literal::hex!("9642bded8063262d15f80250158991982f4b5c4d0c7f4fe2cc8050e68bb463cd"),
            hex_literal::hex!("4f54f067f499ec0383bbc777238c619526381465c31244696cde5a1207ec0b74"),
        ),
        (
            tpm2::Alg::ECSCHNORR,
            TpmiAlgHash::Sha256,
            hex_literal::hex!("32a2750b3aaac1413aef03586fd10d10faeb6497bdcec3172099133d6b6bc4d1"),
            hex_literal::hex!("62e2f2026ba486f5711abc8ed04e57eff4cfef274e0d9f613a31f08a9e221f6c"),
        ),
        (
            tpm2::Alg::SM2,
            TpmiAlgHash::Sha384,
            hex_literal::hex!("25b5683b68a37b8f593877c781053446277cf9f3a99859053c4edbedfd6af7da"),
            hex_literal::hex!("894879cd1e8acf76bedcca274b2b8cc15ddd190b27d4047d9dd18eb5fee1ee58"),
        ),
        (
            tpm2::Alg::ECSCHNORR,
            TpmiAlgHash::Sha384,
            hex_literal::hex!("909f41eb10bc83a75db25a10bef36eab9ced75cdec2520db540e69420249e3a4"),
            hex_literal::hex!("6d17a47a8f4251c5b44cd95f251ba73c882ba90f53ce486f7b300b1572c97251"),
        ),
        #[cfg(feature = "sha512")]
        (
            tpm2::Alg::SM2,
            TpmiAlgHash::Sha512,
            hex_literal::hex!("bbfbbbff69f919fc98a1dd0e0e37563bdb07adae6f69e86ed925e8bcaae6c9b6"),
            hex_literal::hex!("dcc7d5b0b9d337414b9bf08c4d32004a908f152d27cff2488071d3fa3974ad71"),
        ),
        #[cfg(feature = "sha512")]
        (
            tpm2::Alg::ECSCHNORR,
            TpmiAlgHash::Sha512,
            hex_literal::hex!("4a54c215d3c75be6bf9bf960c75eb8dc9e8f1a135c72d6e27261ee6b9da7cb82"),
            hex_literal::hex!("36244a8c64aaec6944035e94b6eaa4a96ed5404663cdcd12e7213933f816ef8f"),
        ),
    ];

    /// SM2 and EC-Schnorr signatures of the linked `CryptEccSign()`, for every implemented hash,
    /// are [`SIGNATURES`] (which verify with the engine's own verification).
    #[test]
    fn sm2_and_schnorr_signatures_match_the_vectors() {
        let mut state = tpm_drbg();
        let (mut d, mut q) = ([0u8; 32], [0u8; 64]);
        new_key_pair(&mut tpm(&mut state), TpmEccCurve::NistP256, &mut d, &mut q).unwrap();
        assert_eq!((d, q), SIGNING_KEY);
        let digest = [0x42u8; 64];
        for &(scheme, hash, expected_r, expected_s) in SIGNATURES {
            let (mut r, mut s) = ([0u8; 80], [0u8; 80]);
            let len = sign(
                &mut tpm(&mut state),
                None,
                scheme,
                hash,
                TpmEccCurve::NistP256,
                &d,
                &digest,
                &mut r,
                &mut s,
            )
            .unwrap_or_else(|e| panic!("{scheme:?} {hash:?}: {e:?}"));
            assert_eq!(len, 32);
            assert_eq!(
                (&r[..32], &s[..32]),
                (&expected_r[..], &expected_s[..]),
                "{scheme:?} {hash:?}"
            );
        }
    }

    /// ECDSA signatures are drawn from the selected DRBG (the signature itself is checked by the
    /// C pairwise test above, which verifies what it signs, and against C outputs in
    /// `vectors.rs`).
    #[test]
    fn ecdsa_nonces_come_from_the_selected_drbg() {
        let mut state = tpm_drbg();
        let (mut d, mut q) = ([0u8; 32], [0u8; 64]);
        new_key_pair(&mut tpm(&mut state), TpmEccCurve::NistP256, &mut d, &mut q).unwrap();
        let digest = [0x42u8; 32];
        let sign = |rng: &mut RefRng<'_>, rand: Option<&mut DrbgState>| {
            let (mut r, mut s) = ([0u8; 66], [0u8; 66]);
            let len = sign_ecdsa(
                rng,
                rand,
                TpmEccCurve::NistP256,
                &d,
                &digest,
                &mut r,
                &mut s,
            )
            .unwrap();
            assert_eq!(len, 32);
            assert!(r[..32].iter().any(|&b| b != 0) && s[..32].iter().any(|&b| b != 0));
            (r, s)
        };
        let seeded = drbg::instantiate_seeded(b"nonce", b"", b"", b"").unwrap();
        let (mut a, mut b) = (seeded, seeded);
        assert_eq!(
            sign(&mut RefRng::seeded_only(), Some(&mut a)),
            sign(&mut RefRng::seeded_only(), Some(&mut b))
        );
        let before = state;
        let first = sign(&mut tpm(&mut state), None);
        assert_ne!(state, before);
        assert_ne!(sign(&mut tpm(&mut state), None), first);
    }

    #[test]
    fn small_outputs_and_unsupported_curves_fail() {
        let mut state = tpm_drbg();
        assert_eq!(
            new_key_pair(
                &mut tpm(&mut state),
                TpmEccCurve::NistP256,
                &mut [0; 31],
                &mut [0; 64]
            ),
            Err(TpmRc::FAILURE)
        );
        // `TPM_ECC_NONE` (no longer a `TpmEccCurve`), passed to the C code directly.
        let (mut x, mut y) = ([0; 80], [0; 80]);
        assert_eq!(
            ffi::ecc_new_key_pair(&mut tpm(&mut state), 0, &mut [0; 80], &mut x, &mut y),
            Err(TpmRc::CURVE.to_rc())
        );
    }
}
