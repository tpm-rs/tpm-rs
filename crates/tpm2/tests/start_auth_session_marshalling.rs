//! Client-side marshalling round trips of TPM2_StartAuthSession commands.

use tpm2::commands::{Message, StartAuthSession, UnmarshalMessage};
use tpm2::{
    AlgSym, Handle, Marshal, Tpm2bEncryptedSecret, Tpm2bNonce, TpmSe, TpmiAlgCipherMode,
    TpmiAlgHash, Unmarshal,
};

/// Marshals `item` into the front of `buf` and returns the marshalled length.
///
/// Marshals into a `MAX_SIZE` scratch buffer when `buf` is smaller than the
/// type's maximum size, so callers can pass right-sized buffers.
fn marshal_to_slice<M: Marshal>(item: &M, buf: &mut [u8]) -> usize
where
    for<'a> &'a mut M::MaxBuffer: TryFrom<&'a mut [u8]>,
{
    if buf.len() >= M::MAX_SIZE {
        item.marshal((&mut buf[..M::MAX_SIZE]).try_into().ok().unwrap())
    } else {
        let mut tmp = vec![0u8; M::MAX_SIZE];
        let len = item.marshal((&mut tmp[..M::MAX_SIZE]).try_into().ok().unwrap());
        buf[..len].copy_from_slice(&tmp[..len]);
        len
    }
}

/// Client-side: a StartAuthSession with caller nonce, encrypted salt and AES-128-CFB round-trips the caller nonce.
#[test]
fn aes128_cfb_salted_command_round_trips() {
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(b"1234567890123456").unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::from_bytes(b"some_encrypted_salt_data").unwrap(),
        session_type: TpmSe::HMAC,
        symmetric: Some(tpm2::TpmtSymDef::Cipher(tpm2::TpmtSymDefObject {
            alg: AlgSym::Aes128,
            mode: Some(TpmiAlgCipherMode::Cfb.into()),
        })),
        auth_hash: TpmiAlgHash::Sha256,
    };
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(&cmd, &mut buf);
    let mut unmarsh = &buf[..len];
    let decoded = StartAuthSession::unmarshal_with_handles(cmd.handles(), &mut unmarsh).unwrap();
    assert_eq!(
        cmd.nonce_caller.get_buffer(),
        decoded.nonce_caller.get_buffer()
    );
}

/// Client-side: a StartAuthSession with an empty caller nonce marshals.
#[test]
fn empty_nonce_command_marshals() {
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::default(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let mut buf = [0u8; 256];
    marshal_to_slice(&cmd, &mut buf);
}

/// Client-side: a trial StartAuthSession round-trips authHash for SHA-1/256/384/512.
#[test]
fn every_auth_hash_round_trips() {
    for hash in &[
        #[cfg(feature = "sha1")]
        TpmiAlgHash::Sha1,
        #[cfg(feature = "sha256")]
        TpmiAlgHash::Sha256,
        #[cfg(feature = "sha384")]
        TpmiAlgHash::Sha384,
        #[cfg(feature = "sha512")]
        TpmiAlgHash::Sha512,
    ] {
        let cmd = StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::default(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: TpmSe::Trial,
            symmetric: None,
            auth_hash: *hash,
        };
        let mut buf = [0u8; 1024];
        let len = marshal_to_slice(&cmd, &mut buf);
        let mut unmarsh = &buf[..len];
        let decoded =
            StartAuthSession::unmarshal_with_handles(cmd.handles(), &mut unmarsh).unwrap();
        assert_eq!(decoded.auth_hash, *hash);
    }
}

/// Client-side: HMAC, policy and trial session types round-trip through StartAuthSession marshalling.
#[test]
fn every_session_type_round_trips() {
    for st in &[TpmSe::HMAC, TpmSe::Policy, TpmSe::Trial] {
        let cmd = StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::default(),
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: *st,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        };
        let mut buf = [0u8; 1024];
        let len = marshal_to_slice(&cmd, &mut buf);
        let mut unmarsh = &buf[..len];
        let decoded =
            StartAuthSession::unmarshal_with_handles(cmd.handles(), &mut unmarsh).unwrap();
        assert_eq!(decoded.session_type, *st);
    }
}

/// Client-side: the StartAuthSession handle area with an arbitrary bind value (0x999999) marshals without panicking.
#[test]
fn handles_with_unknown_bind_marshal() {
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle(0x999999),
        nonce_caller: Tpm2bNonce::default(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    // The handle area: one big-endian `u32` per handle.
    let mut buf = [0u8; 128];
    for (i, handle) in cmd.handles().iter().enumerate() {
        marshal_to_slice(handle, &mut buf[4 * i..]);
    }
}

/// Client-side: the StartAuthSession handle area with an arbitrary tpmKey value (0x999999) marshals without panicking.
///
/// F1: StartAuthSession Marshalling Boundaries
#[test]
fn handles_with_unknown_tpm_key_marshal() {
    let cmd = StartAuthSession {
        tpm_key: Handle(0x999999),
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::default(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    // The handle area: one big-endian `u32` per handle.
    let mut buf = [0u8; 128];
    for (i, handle) in cmd.handles().iter().enumerate() {
        marshal_to_slice(handle, &mut buf[4 * i..]);
    }
}

/// Client-side: an unsalted HMAC StartAuthSession without symmetric marshals and unmarshals back to the same session type.
///
/// F1: StartAuthSession Marshalling
#[test]
fn hmac_session_without_symmetric_round_trips() {
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::default(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(&cmd, &mut buf);
    let mut unmarsh = &buf[..len];
    let decoded = StartAuthSession::unmarshal_with_handles(cmd.handles(), &mut unmarsh).unwrap();
    assert_eq!(cmd.session_type, decoded.session_type);
}

/// Client-side: a policy StartAuthSession with a 256-byte salt, AES-256-CFB and SHA-384 round-trips authHash.
#[test]
fn policy_aes256_sha384_command_round_trips() {
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(b"1234567890123456").unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::from_bytes(&[0u8; 256]).unwrap(),
        session_type: TpmSe::Policy,
        symmetric: Some(tpm2::TpmtSymDef::Cipher(tpm2::TpmtSymDefObject {
            alg: AlgSym::Aes256,
            mode: Some(TpmiAlgCipherMode::Cfb.into()),
        })),
        auth_hash: TpmiAlgHash::Sha384,
    };
    let mut buf = [0u8; 1024];
    let len = marshal_to_slice(&cmd, &mut buf);
    let mut unmarsh = &buf[..len];
    let decoded = StartAuthSession::unmarshal_with_handles(cmd.handles(), &mut unmarsh).unwrap();
    assert_eq!(cmd.auth_hash, decoded.auth_hash);
}

/// Client-side: a StartAuthSession carrying an encrypted salt (meant for tpmKey RH_NULL) marshals.
#[test]
fn salt_without_tpm_key_command_marshals() {
    let cmd = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::default(),
        encrypted_salt: Tpm2bEncryptedSecret::from_bytes(b"salt").unwrap(),
        session_type: TpmSe::HMAC,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let mut buf = [0u8; 256];
    marshal_to_slice(&cmd, &mut buf);
}

/// Client-side: a TPMT_SYM_DEF with AES and keyBits 999 fails to unmarshal.
#[test]
fn unknown_aes_key_bits_fail_unmarshal() {
    let bad_bytes = [0x00, 0x06, 0x03, 0xe7, 0x00, 0x43]; // Alg::AES (0x0006), 999 (0x03E7), Alg::CFB (0x0043)
    let mut slice = &bad_bytes[..];
    assert!(<Option<tpm2::TpmtSymDef>>::unmarshal(&mut slice).is_err());
}
