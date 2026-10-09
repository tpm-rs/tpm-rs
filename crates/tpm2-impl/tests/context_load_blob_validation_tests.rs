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

mod common;

use common::{
    FakeRng, FakeStorage, FakeTimer, RealCryptoEngine, TestCryptoProvider, execute_command,
    password_auth, setup_real_crypto_tpm,
};
use tpm2::commands::{
    ContextLoad, ContextSave, ContextSaveHandles, CreatePrimary, CreatePrimaryHandles,
    FlushContext, ReadPublic, ReadPublicHandles, StartAuthSession, StartAuthSessionHandles,
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    Handle, PublicParmsAndId, Tpm2bAuth, Tpm2bContextData, Tpm2bDigest, Tpm2bEncryptedSecret,
    Tpm2bNonce, Tpm2bSensitiveData, TpmEccCurve, TpmSe, TpmaObject, TpmiAlgHash, TpmiAlgSymMode,
    TpmsContext, TpmsEccParms, TpmsSensitiveCreate, TpmtEccScheme, TpmtPublic, TpmtSymDefObject,
};

/// Offset of `encrypted.size` in the blob: `integrity.size (2) || integrity (32)`.
const ENC_SIZE_OFFSET: usize = 2 + 32;
/// Size of the sequence fingerprint at the start of the encrypted plaintext.
const FINGERPRINT_SIZE: usize = 8;

/// Creates an ECDSA primary key under the owner hierarchy, saves its context
/// and flushes it. Returns the saved context.
fn save_object_context(
    tpm: &mut RealCryptoEngine<'_>,
    gs: &mut tpm2_impl::GlobalState,
) -> TpmsContext<'static> {
    let create = CreatePrimary {
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
    let (handles, _) = execute_command(
        tpm,
        gs,
        &CreatePrimaryHandles {
            primary_handle: Handle::RH_OWNER,
        },
        &create,
        &[password_auth(b"")],
    )
    .expect("CreatePrimary failed");
    let (_, save) = execute_command(
        tpm,
        gs,
        &ContextSaveHandles {
            save_handle: handles.object_handle,
        },
        &ContextSave {},
        &[],
    )
    .expect("ContextSave failed");
    flush(tpm, gs, handles.object_handle);
    save.context
}

fn flush(tpm: &mut RealCryptoEngine<'_>, gs: &mut tpm2_impl::GlobalState, handle: Handle) {
    execute_command(
        tpm,
        gs,
        &(),
        &FlushContext {
            flush_handle: handle,
        },
        &[],
    )
    .expect("FlushContext failed");
}

fn load(
    tpm: &mut RealCryptoEngine<'_>,
    gs: &mut tpm2_impl::GlobalState,
    context: TpmsContext<'static>,
) -> Result<Handle, u32> {
    execute_command(tpm, gs, &(), &ContextLoad { context }, &[]).map(|(h, _)| h.loaded_handle)
}

/// Returns `context` with its blob replaced by `blob`.
fn with_blob(context: TpmsContext<'static>, blob: Vec<u8>) -> TpmsContext<'static> {
    let mut context = context;
    context.context_blob = Tpm2bContextData::from_bytes(Vec::leak(blob)).unwrap();
    context
}

/// Asserts that a context with `blob` is rejected with `expected`, and that
/// the TPM keeps working afterwards (the untouched `context` still loads).
fn assert_load_rejected(
    tpm: &mut RealCryptoEngine<'_>,
    gs: &mut tpm2_impl::GlobalState,
    context: TpmsContext<'static>,
    blob: Vec<u8>,
    expected: u32,
    what: &str,
) {
    assert_eq!(
        load(tpm, gs, with_blob(context, blob)),
        Err(expected),
        "{what}: unexpected ContextLoad result"
    );
    let handle = load(tpm, gs, context).expect("untouched context must still load");
    flush(tpm, gs, handle);
}

macro_rules! setup {
    ($tpm:ident, $gs:ident) => {
        let mut crypto = TestCryptoProvider;
        let mut storage = FakeStorage::default();
        let mut timer = FakeTimer;
        let rng = FakeRng::new();
        let (mut $tpm, mut $gs) =
            setup_real_crypto_tpm(&mut crypto, &mut storage, &mut timer, &rng);
    };
}

fn integrity_rc() -> u32 {
    TpmRc::INTEGRITY.get()
}

fn size_rc() -> u32 {
    TpmRc::SIZE.with(Position::parameter(1)).get()
}

#[test]
fn context_load_untouched_object_context_round_trips() {
    setup!(tpm, gs);
    let context = save_object_context(&mut tpm, &mut gs);
    let handle = load(&mut tpm, &mut gs, context).expect("ContextLoad failed");
    execute_command(
        &mut tpm,
        &mut gs,
        &ReadPublicHandles {
            object_handle: handle,
        },
        &ReadPublic {},
        &[],
    )
    .expect("loaded object must be usable");
}

#[test]
fn context_load_untouched_session_context_round_trips() {
    setup!(tpm, gs);
    let (session, _) = execute_command(
        &mut tpm,
        &mut gs,
        &StartAuthSessionHandles {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
        },
        &StartAuthSession {
            nonce_caller: Tpm2bNonce::from_bytes(&[7; 16]).unwrap(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::HMAC,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        },
        &[],
    )
    .expect("StartAuthSession failed");
    let (_, save) = execute_command(
        &mut tpm,
        &mut gs,
        &ContextSaveHandles {
            save_handle: session.session_handle,
        },
        &ContextSave {},
        &[],
    )
    .expect("ContextSave of session failed");
    assert_eq!(
        load(&mut tpm, &mut gs, save.context),
        Ok(session.session_handle)
    );
}

#[test]
fn context_load_enc_size_increased_returns_integrity() {
    setup!(tpm, gs);
    let context = save_object_context(&mut tpm, &mut gs);
    let mut blob = context.context_blob.get_buffer().to_vec();
    blob[ENC_SIZE_OFFSET] ^= 0x01; // +256: larger than the remaining data
    assert_load_rejected(&mut tpm, &mut gs, context, blob, integrity_rc(), "size+256");
}

#[test]
fn context_load_enc_size_decreased_returns_integrity() {
    setup!(tpm, gs);
    let context = save_object_context(&mut tpm, &mut gs);
    let mut blob = context.context_blob.get_buffer().to_vec();
    let size = u16::from_be_bytes([blob[ENC_SIZE_OFFSET], blob[ENC_SIZE_OFFSET + 1]]);
    blob[ENC_SIZE_OFFSET..ENC_SIZE_OFFSET + 2].copy_from_slice(&(size - 1).to_be_bytes());
    assert_load_rejected(&mut tpm, &mut gs, context, blob, integrity_rc(), "size-1");
}

#[test]
fn context_load_trailing_bytes_returns_integrity() {
    setup!(tpm, gs);
    let context = save_object_context(&mut tpm, &mut gs);
    let mut blob = context.context_blob.get_buffer().to_vec();
    blob.push(0xEE);
    assert_load_rejected(
        &mut tpm,
        &mut gs,
        context,
        blob,
        integrity_rc(),
        "trailing byte",
    );
}

#[test]
fn context_load_truncated_encrypted_data_returns_integrity() {
    setup!(tpm, gs);
    let context = save_object_context(&mut tpm, &mut gs);
    let mut blob = context.context_blob.get_buffer().to_vec();
    blob.pop();
    assert_load_rejected(
        &mut tpm,
        &mut gs,
        context,
        blob,
        integrity_rc(),
        "truncated",
    );
}

#[test]
fn context_load_tampered_integrity_or_payload_returns_integrity() {
    setup!(tpm, gs);
    let context = save_object_context(&mut tpm, &mut gs);
    let blob = context.context_blob.get_buffer().to_vec();
    for (what, offset) in [
        ("integrity", 2),
        ("encrypted first byte", ENC_SIZE_OFFSET + 2),
        ("encrypted last byte", blob.len() - 1),
    ] {
        let mut tampered = blob.clone();
        tampered[offset] ^= 0x01;
        assert_load_rejected(&mut tpm, &mut gs, context, tampered, integrity_rc(), what);
    }
}

#[test]
fn context_load_short_blobs_return_size() {
    setup!(tpm, gs);
    let context = save_object_context(&mut tpm, &mut gs);
    let blob = context.context_blob.get_buffer().to_vec();
    for (what, len) in [
        ("empty blob", 0),
        ("1 byte", 1),
        ("partial integrity", 10),
        ("integrity only", ENC_SIZE_OFFSET),
        ("integrity + size only", ENC_SIZE_OFFSET + 2),
        (
            "no room for fingerprint",
            ENC_SIZE_OFFSET + 2 + FINGERPRINT_SIZE - 1,
        ),
    ] {
        assert_load_rejected(
            &mut tpm,
            &mut gs,
            context,
            blob[..len].to_vec(),
            size_rc(),
            what,
        );
    }
}

#[test]
fn context_load_wrong_integrity_size_returns_size() {
    setup!(tpm, gs);
    let context = save_object_context(&mut tpm, &mut gs);
    let blob = context.context_blob.get_buffer().to_vec();
    // Re-encode the integrity value as a 20-byte digest.
    let mut tampered = Vec::new();
    tampered.extend_from_slice(&20u16.to_be_bytes());
    tampered.extend_from_slice(&blob[2..22]);
    tampered.extend_from_slice(&blob[ENC_SIZE_OFFSET..]);
    assert_load_rejected(
        &mut tpm,
        &mut gs,
        context,
        tampered,
        size_rc(),
        "20-byte integrity",
    );
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
    let mut hmac = tpm2::crypto::HmacCtx::new(&crypto, TpmiAlgHash::Sha256, proof).unwrap();
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
    tpm2::crypto::kdf::kdfa(
        &crypto,
        TpmiAlgHash::Sha256,
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
    let alg = TpmtSymDefObject::Aes128(Some(TpmiAlgSymMode::CFB));
    if encrypt {
        tpm2::crypto::encrypt(&crypto, alg, &key_iv[..16], &mut iv, data).unwrap();
    } else {
        tpm2::crypto::decrypt(&crypto, alg, &key_iv[..16], &mut iv, data).unwrap();
    }
}

/// The integrity value is genuine (white-box forged with the hierarchy proof)
/// but `encrypted.size` is inconsistent with the data: since only the TPM can
/// produce such a blob, this is a TPM failure.
#[test]
fn context_load_size_mismatch_behind_valid_integrity_is_failure() {
    setup!(tpm, gs);
    let context = save_object_context(&mut tpm, &mut gs);
    let blob = context.context_blob.get_buffer();
    let mut enc_context = blob[ENC_SIZE_OFFSET..].to_vec();
    let size = u16::from_be_bytes([enc_context[0], enc_context[1]]);
    enc_context[..2].copy_from_slice(&(size - 1).to_be_bytes());
    let forged = forge_blob(&gs, &context, &enc_context);
    assert_eq!(
        load(&mut tpm, &mut gs, with_blob(context, forged)),
        Err(TpmRc::FAILURE.get())
    );
}

/// The integrity value is genuine but the decrypted sequence fingerprint does
/// not match `context.sequence`: the TPM must treat this as a failure
/// (Part 1, "Context Confidentiality Protection").
#[test]
fn context_load_fingerprint_mismatch_is_failure() {
    setup!(tpm, gs);
    let context = save_object_context(&mut tpm, &mut gs);
    let blob = context.context_blob.get_buffer();
    let mut enc_context = blob[ENC_SIZE_OFFSET..].to_vec();

    let mut plaintext = enc_context[2..].to_vec();
    context_cfb(&gs, &context, &mut plaintext, false);
    assert_eq!(
        plaintext[..FINGERPRINT_SIZE],
        context.sequence.to_be_bytes(),
        "ContextSave must prepend the sequence fingerprint"
    );
    plaintext[FINGERPRINT_SIZE - 1] ^= 0x01;
    context_cfb(&gs, &context, &mut plaintext, true);
    enc_context[2..].copy_from_slice(&plaintext);

    let forged = forge_blob(&gs, &context, &enc_context);
    assert_eq!(
        load(&mut tpm, &mut gs, with_blob(context, forged)),
        Err(TpmRc::FAILURE.get())
    );
}

/// Sanity check for the forging helpers: re-forging an unmodified blob yields
/// the original blob, which loads.
#[test]
fn context_load_forged_unmodified_blob_loads() {
    setup!(tpm, gs);
    let context = save_object_context(&mut tpm, &mut gs);
    let blob = context.context_blob.get_buffer().to_vec();
    let forged = forge_blob(&gs, &context, &blob[ENC_SIZE_OFFSET..]);
    assert_eq!(forged, blob);
    load(&mut tpm, &mut gs, with_blob(context, forged)).expect("ContextLoad failed");
}
