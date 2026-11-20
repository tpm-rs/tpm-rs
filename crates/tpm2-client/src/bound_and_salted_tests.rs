//! Bound and salted HMAC session tests.
//!
//! These focus on how the TPM tracks the entity a session is bound to.

use tpm2::commands::{FlushContext, StartAuthSession};
use tpm2::errors::TpmRc;
use tpm2::*;
use tpm2_client::sessions::HmacSession;
use tpm2_client::{CryptoBackend, nv_name, run_command};
use tpm2_tcp::TcpSimulator;

use crate::{ALG, DIGEST_SIZE, NV_INDEX, RESP_BUFFER_SIZE, define_nv_index, get_lockout_counter, nonce_unchanged, nv_public, start, start_hmac_session, stop, write_nv_index};

/// The size of boundEntity, which is `sizeof(TPMU_NAME)` in the reference
/// code. Without SHA-512, its largest member is a 50-byte SHA-384 `TPMT_HA`,
/// but its `TPM_HANDLE` member aligns it to 4 bytes, which pads it to 52.
const BOUND_ENTITY_SIZE: usize = 52;

//
// Setup.
//

/// Starts an unsalted SHA-256 HMAC session bound to `bind`, whose authValue
/// is `bind_auth`.
fn start_bound_hmac_session(simulator: &mut TcpSimulator, bind: Handle, bind_auth: Tpm2bAuth) -> HmacSession {
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];

    let start_auth_session = StartAuthSession {
        tpm_key: Handle::RH_NULL.into(),
        bind: bind.into(),
        nonce_caller: Tpm2bNonce::new(&[42u8; DIGEST_SIZE]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: ALG,
    };
    let start_auth_session_rsp = run_command(&start_auth_session, &mut simulator.connection, resp_buffer).unwrap();

    HmacSession::new_bound_or_salted(
        start_auth_session_rsp.session_handle,
        start_auth_session.auth_hash,
        start_auth_session.nonce_caller,
        start_auth_session_rsp.nonce_tpm,
        bind_auth,
        Tpm2bDigest::default(), // unsalted
    )
    .unwrap()
}

//
// Tests.
//

/// The TPM recognises the entity a session is bound to by its boundEntity:
///
/// ```text
/// boundEntity := [Name || 000...000] XOR [000...000 || authValue]
/// ```
///
/// When authorizing the bound entity, authValue isn't part of the HMAC key,
/// as the session key already proves knowledge of it. When the authValues of
/// two NV indices are chosen so that their boundEntities collide, a session
/// bound to one authorizes the other without its authValue.
///
/// This needs both authValues, so it's no way to learn one. Otherwise,
/// authorizing the other index needs its authValue, and fails without it.
///
/// No authValue reaches the start of a Name's digest, so the other index is
/// searched for (by its handle) until those bytes match too.
fn bound_entity_collision(names_collide: bool) {
    let mut simulator = start(&format!("bound_entity_collision(names_collide: {names_collide})"));
    let resp_buffer: &mut [u8; RESP_BUFFER_SIZE] = &mut [0u8; RESP_BUFFER_SIZE];
    let mut last_nonce_bytes = [0u8; DIGEST_SIZE];

    // This session only defines the NV indices, as the session under test must be bound to one.
    let mut owner_session = start_hmac_session(&mut simulator);
    // Test that the nonce rolls (and assume that the HMAC changes with, proven by command success, where applicable).
    assert!(nonce_unchanged(&mut last_nonce_bytes, &owner_session.nonce_tpm()) == false);

    // A SHA-384 authValue (the largest an index with a SHA-384 nameAlg takes) reaches furthest into boundEntity.
    // It doesn't reach the Names' nameAlg, which they share, nor the first `UNCOVERED - 2` bytes of their digests.
    const AUTH_SIZE: usize = TpmiAlgHash::Sha384.digest_size();
    const UNCOVERED: usize = BOUND_ENTITY_SIZE - AUTH_SIZE;
    let nv_public_a = nv_public(
        TpmiAlgHash::Sha384,
        TpmaNv::AUTHREAD | TpmaNv::AUTHWRITE,
        Tpm2bDigest::default(), // session auth only
    );
    // The Names are zero-padded to the size of boundEntity.
    let mut name_buf_a = [0u8; Tpm2bName::CAP];
    nv_name::<CryptoBackend>(&nv_public_a, &mut name_buf_a).unwrap();

    // Find an index B whose Name matches A's where authValues can't reach.
    let mut nv_public_b = nv_public_a;
    let mut name_buf_b = [0u8; Tpm2bName::CAP];
    loop {
        nv_public_b.nv_index.0 += 1;
        nv_name::<CryptoBackend>(&nv_public_b, &mut name_buf_b).unwrap();
        if name_buf_a[..UNCOVERED] == name_buf_b[..UNCOVERED] {
            break;
        }
    }
    let nv_index_b = nv_public_b.nv_index;

    let auth_a = [42u8; AUTH_SIZE];
    let mut auth_b = [24u8; AUTH_SIZE];
    if names_collide {
        // NameA XOR authA == NameB XOR authB. Where authValues overlap padding, they match.
        for i in 0..AUTH_SIZE {
            auth_b[i] = auth_a[i] ^ name_buf_a[UNCOVERED + i] ^ name_buf_b[UNCOVERED + i];
        }
    }

    define_nv_index(&mut simulator, &nv_public_a, Tpm2bAuth::new(&auth_a).unwrap(), &mut owner_session, &mut last_nonce_bytes);
    define_nv_index(&mut simulator, &nv_public_b, Tpm2bAuth::new(&auth_b).unwrap(), &mut owner_session, &mut last_nonce_bytes);

    let flush_context = FlushContext {
        flush_handle: owner_session.handle(),
    };
    assert!(run_command(&flush_context, &mut simulator.connection, resp_buffer).is_ok());

    let mut session = start_bound_hmac_session(&mut simulator, NV_INDEX, Tpm2bAuth::new(&auth_a).unwrap());
    // Test that the nonce rolls (and assume that the HMAC changes with, proven by command success, where applicable).
    assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);

    // The session's authValue is left empty, as it would be for the bound entity.
    let failed_tries = get_lockout_counter(&mut simulator);
    let mut nv_write_rsp = write_nv_index(&mut simulator, &mut nv_public_b, nv_index_b, &mut session);
    if nv_write_rsp == Err(TpmRc::RETRY) {
        nv_write_rsp = write_nv_index(&mut simulator, &mut nv_public_b, nv_index_b, &mut session);
    }
    if names_collide {
        // The TPM mistook index B for the bound entity.
        assert!(nv_write_rsp.is_ok());
        assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == false);
    } else {
        // Index B's authValue was needed.
        assert!(nv_write_rsp.is_err());
        // An authorisation failure increments failedTries.
        assert_eq!(get_lockout_counter(&mut simulator), failed_tries + 1);
        // Failure doesn't update the nonce.
        assert!(nonce_unchanged(&mut last_nonce_bytes, &session.nonce_tpm()) == true);
    }

    assert!(stop(simulator, session.handle()).is_ok());
}

//
// Driver.
//
pub fn run() {
    bound_entity_collision(true);
    bound_entity_collision(false);
}
