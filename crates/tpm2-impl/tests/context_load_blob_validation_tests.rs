//! Regression tests for `TPM2_ContextLoad` context-blob validation.
//!
//! The context blob returned by `TPM2_ContextSave` is
//! `integrity (TPM2B_DIGEST) || encrypted (TPM2B_CONTEXT_SENSITIVE)`, where
//! the encrypted plaintext is `sequence (8 bytes) || serialized entity`.
//! TPM 2.0 requires that:
//! - the integrity HMAC covers everything after the integrity value
//!   (Part 1, "Context Integrity Protection"), so any modification — including
//!   of the size field or appended bytes — yields `TPM_RC_INTEGRITY`
//!   (Part 3, TPM2_ContextLoad);
//! - a blob too short to hold the integrity value / protected data yields
//!   `TPM_RC_SIZE` (reference implementation: `TPM_RCS_SIZE + RC_ContextLoad_context`);
//! - only inconsistencies found *after* integrity verification (a decrypted
//!   sequence fingerprint mismatch, Part 1 "Context Confidentiality
//!   Protection") are treated as a TPM failure.
//!
//! The tests left here forge blobs with the TPM's internal hierarchy proof
//! (white-box); the black-box tests live in
//! `testing/src/impl_context_load_blob_validation_tests.rs`.

mod common;

use common::{
    FakeRng, FakeStorage, FakeTimer, RealCryptoEngine, TestCryptoProvider, execute_command,
    password_auth, setup_real_crypto_tpm,
};
use tpm2::commands::{ContextLoad, ContextSave, CreatePrimary, FlushContext};
use tpm2::crypto::{HmacStream, ModeIv, SymmetricKey};
use tpm2::errors::TpmRc;
use tpm2::{
    AlgSym, Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bContextData, Tpm2bDigest, Tpm2bSensitiveData,
    TpmEccCurve, TpmaObject, TpmiAlgHash, TpmsContext, TpmsEccParms, TpmsSensitiveCreate,
    TpmtEccScheme, TpmtPublic,
};

/// Offset of `encrypted.size` in the blob: `integrity.size (2) || integrity (64)` (the integrity
/// HMAC uses SHA-512, the strongest implemented hash).
const ENC_SIZE_OFFSET: usize = 2 + 64;
/// Size of the sequence fingerprint at the start of the encrypted plaintext.
const FINGERPRINT_SIZE: usize = 8;

/// Creates an ECDSA primary key under the owner hierarchy, saves its context
/// and flushes it. Returns the saved context.
fn save_object_context(tpm: &mut RealCryptoEngine<'_>) -> TpmsContext<'static> {
    let create = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(b"pass").unwrap(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::SIGN_ENCRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Ecc(
                TpmsEccParms {
                    symmetric: None,
                    scheme: Some(TpmtEccScheme::Ecdsa(TpmiAlgHash::Sha256)),
                    curve_id: TpmEccCurve::NistP256,
                    kdf: None,
                },
                tpm2::TpmsEccPoint::default(),
            ),
        }),
        ..Default::default()
    };
    let created =
        execute_command(tpm, &create, &[password_auth(b"")]).expect("CreatePrimary failed");
    let save = execute_command(
        tpm,
        &ContextSave {
            save_handle: created.object_handle,
        },
        &[],
    )
    .expect("ContextSave failed");
    flush(tpm, created.object_handle);
    save.context
}

fn flush(tpm: &mut RealCryptoEngine<'_>, handle: Handle) {
    execute_command(
        tpm,
        &FlushContext {
            flush_handle: handle,
        },
        &[],
    )
    .expect("FlushContext failed");
}

fn load(tpm: &mut RealCryptoEngine<'_>, context: TpmsContext<'static>) -> Result<Handle, u32> {
    execute_command(tpm, &ContextLoad { context }, &[]).map(|rsp| rsp.loaded_handle)
}

/// Returns `context` with its blob replaced by `blob`.
fn with_blob(context: TpmsContext<'static>, blob: Vec<u8>) -> TpmsContext<'static> {
    let mut context = context;
    context.context_blob = Tpm2bContextData::from_bytes(Vec::leak(blob)).unwrap();
    context
}

macro_rules! setup {
    ($tpm:ident) => {
        let mut crypto = TestCryptoProvider;
        let mut storage = FakeStorage::default();
        let mut timer = FakeTimer;
        let mut rng = FakeRng::new();
        let mut $tpm = setup_real_crypto_tpm(&mut crypto, &mut storage, &mut timer, &mut rng);
    };
}

/// Recomputes the context integrity HMAC over `enc_context` (white-box: uses
/// the owner hierarchy proof and `totalResetCount`).
fn forge_integrity(
    gs: &tpm2_impl::GlobalState,
    context: &TpmsContext<'_>,
    enc_context: &[u8],
) -> Vec<u8> {
    let crypto = TestCryptoProvider;
    let proof = &gs.sh_proof[..gs.sh_proof_size as usize];
    let mut hmac = HmacStream::new(&crypto, TpmiAlgHash::Sha512, proof).unwrap();
    hmac.update(&gs.total_reset_count.to_be_bytes()).unwrap();
    hmac.update(&context.sequence.to_be_bytes()).unwrap();
    hmac.update(&context.saved_handle.0.to_be_bytes()).unwrap();
    hmac.update(enc_context).unwrap();
    let mut out = [0u8; 64];
    hmac.finalize(&mut out).unwrap().digest().to_vec()
}

/// Builds `integrity || enc_context` with a correctly forged integrity value.
fn forge_blob(
    gs: &tpm2_impl::GlobalState,
    context: &TpmsContext<'_>,
    enc_context: &[u8],
) -> Vec<u8> {
    let integrity = forge_integrity(gs, context, enc_context);
    let mut blob = Vec::new();
    blob.extend_from_slice(&(integrity.len() as u16).to_be_bytes());
    blob.extend_from_slice(&integrity);
    blob.extend_from_slice(enc_context);
    blob
}

/// AES-128-CFB keystream for the context, as derived by the TPM
/// (white-box: uses the owner hierarchy proof).
fn context_cfb(
    gs: &tpm2_impl::GlobalState,
    context: &TpmsContext<'_>,
    data: &mut [u8],
    encrypt: bool,
) {
    let crypto = TestCryptoProvider;
    let proof = &gs.sh_proof[..gs.sh_proof_size as usize];
    let mut key_iv = [0u8; 32];
    tpm2::crypto::kdf::kdfa_bits(
        &crypto,
        TpmiAlgHash::Sha512,
        proof,
        b"CONTEXT",
        &context.sequence.to_be_bytes(),
        &context.saved_handle.0.to_be_bytes(),
        256,
        &mut key_iv,
    )
    .unwrap();
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&key_iv[16..]);
    let key = SymmetricKey::new(AlgSym::Aes128, &key_iv[..16]).unwrap();
    if encrypt {
        tpm2::crypto::encrypt(&crypto, key, ModeIv::Cfb(&mut iv), data).unwrap();
    } else {
        tpm2::crypto::decrypt(&crypto, key, ModeIv::Cfb(&mut iv), data).unwrap();
    }
}

/// The integrity value is genuine (white-box forged with the hierarchy proof)
/// but `encrypted.size` is inconsistent with the data: since only the TPM can
/// produce such a blob, this is a TPM failure.
#[test]
fn context_load_size_mismatch_behind_valid_integrity_is_failure() {
    setup!(tpm);
    let context = save_object_context(&mut tpm);
    let blob = context.context_blob.get_buffer();
    let mut enc_context = blob[ENC_SIZE_OFFSET..].to_vec();
    let size = u16::from_be_bytes([enc_context[0], enc_context[1]]);
    enc_context[..2].copy_from_slice(&(size - 1).to_be_bytes());
    let forged = forge_blob(&tpm.state, &context, &enc_context);
    assert_eq!(
        load(&mut tpm, with_blob(context, forged)),
        Err(TpmRc::FAILURE.get())
    );
}

/// The integrity value is genuine but the decrypted sequence fingerprint does
/// not match `context.sequence`: the TPM must treat this as a failure
/// (Part 1, "Context Confidentiality Protection").
#[test]
fn context_load_fingerprint_mismatch_is_failure() {
    setup!(tpm);
    let context = save_object_context(&mut tpm);
    let blob = context.context_blob.get_buffer();
    let mut enc_context = blob[ENC_SIZE_OFFSET..].to_vec();

    let mut plaintext = enc_context[2..].to_vec();
    context_cfb(&tpm.state, &context, &mut plaintext, false);
    assert_eq!(
        plaintext[..FINGERPRINT_SIZE],
        context.sequence.to_be_bytes(),
        "ContextSave must prepend the sequence fingerprint"
    );
    plaintext[FINGERPRINT_SIZE - 1] ^= 0x01;
    context_cfb(&tpm.state, &context, &mut plaintext, true);
    enc_context[2..].copy_from_slice(&plaintext);

    let forged = forge_blob(&tpm.state, &context, &enc_context);
    assert_eq!(
        load(&mut tpm, with_blob(context, forged)),
        Err(TpmRc::FAILURE.get())
    );
}

/// Sanity check for the forging helpers: re-forging an unmodified blob yields
/// the original blob, which loads.
#[test]
fn context_load_forged_unmodified_blob_loads() {
    setup!(tpm);
    let context = save_object_context(&mut tpm);
    let blob = context.context_blob.get_buffer().to_vec();
    let forged = forge_blob(&tpm.state, &context, &blob[ENC_SIZE_OFFSET..]);
    assert_eq!(forged, blob);
    load(&mut tpm, with_blob(context, forged)).expect("ContextLoad failed");
}
