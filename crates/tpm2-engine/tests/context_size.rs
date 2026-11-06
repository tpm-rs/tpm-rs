//! The sizes of the contexts `TPM2_ContextSave` returns, against the reported
//! `TPM_PT_MAX_OBJECT_CONTEXT`/`TPM_PT_MAX_SESSION_CONTEXT` (TPM 2.0 Part 2, TPM_PT: "the maximum
//! size of an object context that will be returned by TPM2_ContextSave()", "the maximum size of a
//! session context that will be returned by TPM2_ContextSave()"): every context fits them, and
//! with the `fixed-size-context` feature every context has exactly that size, so that a
//! `TPM2_ContextLoad` of `10 + TPM_PT_MAX_*_CONTEXT` octets (as Windows' TPM Base Services send it)
//! loads.

mod common;

use common::{
    FakeRng, FakeStorage, FakeTimer, RealCryptoEngine, TestCryptoProvider, execute_command,
    password_auth, setup_real_crypto_tpm,
};
use tpm2::commands::CreatePrimary;
use tpm2::{
    Handle, PublicParmsAndId, Tpm2b, Tpm2bDigest, TpmEccCurve, TpmaObject, TpmiAlgHash,
    TpmsEccParms, TpmtPublic, TpmtSymDefObject,
};

macro_rules! setup {
    ($tpm:ident) => {
        let mut crypto = TestCryptoProvider;
        let mut storage = FakeStorage::default();
        let mut timer = FakeTimer;
        let mut rng = FakeRng::new();
        let mut $tpm = setup_real_crypto_tpm(&mut crypto, &mut storage, &mut timer, &mut rng);
    };
}

/// Executes the raw command `cmd` (its `commandSize` is patched) and returns the response,
/// asserting `TPM_RC_SUCCESS`.
fn run(tpm: &mut RealCryptoEngine<'_>, cmd: &[u8]) -> Vec<u8> {
    let mut cmd = cmd.to_vec();
    let size = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&size.to_be_bytes());
    let mut rsp = [0u8; 8192];
    let len = tpm.execute_command_separate(&cmd, &mut rsp);
    assert_eq!(rsp[6..10], [0, 0, 0, 0], "command {:02x?}", &cmd[6..10]);
    rsp[..len].to_vec()
}

/// A raw command without sessions: the header (size patched by [`run`]) and `body`.
fn command(code: u32, body: &[u8]) -> Vec<u8> {
    let mut cmd = vec![0x80, 0x01, 0, 0, 0, 0];
    cmd.extend_from_slice(&code.to_be_bytes());
    cmd.extend_from_slice(body);
    cmd
}

fn handle_of(rsp: &[u8]) -> u32 {
    u32::from_be_bytes(rsp[10..14].try_into().unwrap())
}

/// `TPM_PT_MAX_OBJECT_CONTEXT` and `TPM_PT_MAX_SESSION_CONTEXT`.
fn max_context_sizes(tpm: &mut RealCryptoEngine<'_>) -> (usize, usize) {
    let mut body = Vec::new();
    body.extend_from_slice(&6u32.to_be_bytes()); // TPM_CAP_TPM_PROPERTIES
    body.extend_from_slice(&0x121u32.to_be_bytes()); // TPM_PT_MAX_OBJECT_CONTEXT
    body.extend_from_slice(&2u32.to_be_bytes());
    let rsp = run(tpm, &command(0x17A, &body));
    let property = |i: usize| {
        let at = 19 + 8 * i;
        let tag = u32::from_be_bytes(rsp[at..at + 4].try_into().unwrap());
        let value = u32::from_be_bytes(rsp[at + 4..at + 8].try_into().unwrap());
        (tag, value as usize)
    };
    let (object_tag, object) = property(0);
    let (session_tag, session) = property(1);
    assert_eq!((object_tag, session_tag), (0x121, 0x122));
    (object, session)
}

/// Saves `handle` and returns the `TPMS_CONTEXT`.
fn context_save(tpm: &mut RealCryptoEngine<'_>, handle: u32) -> Vec<u8> {
    run(tpm, &command(0x162, &handle.to_be_bytes()))[10..].to_vec()
}

/// Loads `context` followed by `padding` zero octets; returns the response code.
fn context_load(tpm: &mut RealCryptoEngine<'_>, context: &[u8], padding: usize) -> u32 {
    let mut cmd = command(0x161, context);
    cmd.resize(cmd.len() + padding, 0);
    let size = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&size.to_be_bytes());
    let mut rsp = [0u8; 8192];
    tpm.execute_command_separate(&cmd, &mut rsp);
    u32::from_be_bytes(rsp[6..10].try_into().unwrap())
}

fn flush(tpm: &mut RealCryptoEngine<'_>, handle: u32) {
    run(tpm, &command(0x165, &handle.to_be_bytes()));
}

/// A fixedTPM NIST P-256 storage primary key under the owner hierarchy.
fn storage_primary(tpm: &mut RealCryptoEngine<'_>) -> u32 {
    let create = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_public: Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::RESTRICTED
                | TpmaObject::DECRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Ecc(
                TpmsEccParms {
                    symmetric: Some(TpmtSymDefObject::aes_cfb(128).unwrap()),
                    scheme: None,
                    curve_id: TpmEccCurve::NistP256,
                    kdf: None,
                },
                tpm2::TpmsEccPoint::default(),
            ),
        }),
        in_sensitive: Default::default(),
        outside_info: Default::default(),
        creation_pcr: Default::default(),
    };
    execute_command(tpm, &create, &[password_auth(b"")])
        .expect("CreatePrimary")
        .object_handle
        .0
}

/// Checks the size of `context` against `max`, and that the context loads when it is padded to
/// `max` octets: always with `fixed-size-context` (no padding is needed), otherwise only if it
/// already has that size (trailing octets are `TPM_RC_SIZE`).
fn check_context(tpm: &mut RealCryptoEngine<'_>, context: &[u8], max: usize) -> u32 {
    assert!(context.len() <= max, "{} > {max}", context.len());
    if cfg!(feature = "fixed-size-context") {
        assert_eq!(context.len(), max);
    }
    let padding = max - context.len();
    let rc = context_load(tpm, context, padding);
    if padding == 0 {
        assert_eq!(rc, 0, "ContextLoad");
    } else {
        assert_eq!(rc, tpm2::errors::TpmRc::SIZE.to_rc().get(), "ContextLoad");
    }
    rc
}

#[test]
fn saved_contexts_fit_the_reported_maximum_sizes() {
    setup!(tpm);
    let (max_object, max_session) = max_context_sizes(&mut tpm);

    // A transient object.
    let key = storage_primary(&mut tpm);
    let context = context_save(&mut tpm, key);
    flush(&mut tpm, key);
    if check_context(&mut tpm, &context, max_object) != 0 {
        assert_eq!(context_load(&mut tpm, &context, 0), 0);
    }

    // A hash sequence object (empty auth, SHA-256).
    let rsp = run(&mut tpm, &command(0x186, &[0, 0, 0x00, 0x0B]));
    let sequence = handle_of(&rsp);
    let context = context_save(&mut tpm, sequence);
    flush(&mut tpm, sequence);
    if check_context(&mut tpm, &context, max_object) != 0 {
        assert_eq!(context_load(&mut tpm, &context, 0), 0);
    }

    // A policy session (unbound, unsalted, SHA-256): saving it moves it out of its slot.
    let mut body = Vec::new();
    body.extend_from_slice(&Handle::RH_NULL.0.to_be_bytes()); // tpmKey
    body.extend_from_slice(&Handle::RH_NULL.0.to_be_bytes()); // bind
    body.extend_from_slice(&[0, 16]);
    body.extend_from_slice(&[0x5A; 16]); // nonceCaller
    body.extend_from_slice(&[0, 0]); // encryptedSalt
    body.push(0x01); // TPM_SE_POLICY
    body.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric: TPM_ALG_NULL
    body.extend_from_slice(&0x000Bu16.to_be_bytes()); // authHash: SHA-256
    let rsp = run(&mut tpm, &command(0x176, &body));
    let session = handle_of(&rsp);
    let context = context_save(&mut tpm, session);
    if check_context(&mut tpm, &context, max_session) != 0 {
        assert_eq!(context_load(&mut tpm, &context, 0), 0);
    }
}
