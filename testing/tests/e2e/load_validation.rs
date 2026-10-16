//! TPM2_Load validation: parent handle type, parent attributes and inPrivate size.

use crate::_common::{load_with_name as load, try_create_owner_primary as create_primary, *};
use testing::tpm::Tpm;
#[allow(deprecated)]
use tpm2::commands::{CreateLoaded, Load};
use tpm2::errors::{Position, TpmRc};
use tpm2::*;

// Adversarial test: loading a primary object via Load command with a hierarchy parent (should fail)
/// Load with a hierarchy as parentHandle fails with TPM_RC_VALUE + H1.
#[test]
#[allow(deprecated)]
fn load_with_hierarchy_parent_rejected() {
    let mut sim = Tpm::new();

    // Create the SRK (Primary Object) via CreateLoaded with RHOwner
    let mut srk_pub = get_ecc_srk_template();
    srk_pub.object_attributes = TpmaObject::SENSITIVE_DATA_ORIGIN
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::RESTRICTED
        | TpmaObject::DECRYPT;
    let in_public_srk = crate::test_utils::make_template(&srk_pub);
    let create_srk_cmd = CreateLoaded {
        parent_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: in_public_srk,
    };
    let create_srk_rsp = execute_with_password_sessions(&mut sim, &create_srk_cmd, 1, &[]).unwrap();
    let srk_handle = create_srk_rsp.object_handle;

    // Try to load the private area using Load command, passing Handle::RH_OWNER as parent.
    // This should fail because parent cannot be a hierarchy handle for Load command.
    let load_cmd = Load {
        parent_handle: Handle::RH_OWNER,
        in_private: create_srk_rsp.out_private,
        in_public: create_srk_rsp.out_public,
    };
    let res = execute_with_password_sessions(&mut sim, &load_cmd, 1, &[]);

    // We expect this to fail with TPM_RC_VALUE on handle 1 because parentHandle is TPMI_DH_OBJECT (cannot be a hierarchy handle).
    assert_eq!(
        res.unwrap_err(),
        TpmRc::VALUE.with(Position::handle(1)).get()
    );

    flush_context(&mut sim, srk_handle).unwrap();
}

/// Load of a SHA-1 named object with a malformed 3-byte inPrivate fails with TPM_RC_SIZE on inPrivate.
///
/// `TPM2_Load` of a SHA-1 named object with a malformed 3-byte `inPrivate`
/// fails with `TPM_RC_SIZE` on `inPrivate`.
#[test]
fn sha1_object_malformed_private_size_error() {
    let mut sim = Tpm::new();

    let parent = create_srk(&mut sim);

    // Key public area with name algorithm SHA1
    let target_public = rsa_public(
        TpmiAlgHash::Sha1,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        &[],
        None,
    );

    let res = load(
        &mut sim,
        parent,
        Tpm2bPrivate::from_bytes(&[1, 2, 3]).unwrap(),
        Tpm2b(target_public),
    );
    // SHA-1 is an implemented nameAlg in the C reference, so the public area is accepted; the
    // malformed 3-byte inPrivate then fails in UnwrapOuter's TPM2B_DIGEST_Unmarshal (size 0x0102
    // exceeds the digest buffer -> TPM_RC_SIZE), reported as RC_Load_inPrivate (P1).
    assert_eq!(
        res.err(),
        Some(TpmRc::SIZE.with(Position::parameter(1)).get())
    );
}

/// Load under a parent that is not a restricted decryption key fails with TPM_RC_TYPE on the parent.
///
/// `TPM2_Load` under a parent that is not a restricted decryption key fails
/// with `TPM_RC_TYPE` on the parent handle.
#[test]
fn unrestricted_parent_rejected() {
    let mut sim = Tpm::new();

    // 1. A parent key that is NOT restricted (decrypt only)
    let (parent, _) = create_primary(
        &mut sim,
        rsa_public(
            TpmiAlgHash::Sha256,
            TpmaObject::DECRYPT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::FIXED_PARENT
                | TpmaObject::FIXED_TPM,
            &[],
            None,
        ),
    )
    .expect("CreatePrimary failed");

    // 2. Target key public area
    let target_public = rsa_public(
        TpmiAlgHash::Sha256,
        TpmaObject::SIGN_ENCRYPT | TpmaObject::USER_WITH_AUTH,
        &[],
        None,
    );

    // 3. Call Load under this parent -> should fail with Type on the parent handle
    let res = load(
        &mut sim,
        parent,
        Tpm2bPrivate::from_bytes(&[1, 2, 3]).unwrap(),
        Tpm2b(target_public),
    );
    assert_eq!(res.err(), Some(TpmRc::TYPE.with(Position::handle(1)).get()));
}

/// A `decrypt` session with XOR obfuscation de-obfuscates a parameter of any size that fits the
/// command, so an oversized `inPrivate` (2169 octets) is rejected by its own unmarshaling with
/// `TPM_RC_SIZE + RC_P1`, not a bare `TPM_RC_SIZE` from a fixed-size mask (found by differential
/// fuzzing). TPM 2.0 Part 1, "XOR Parameter Obfuscation": "The obfuscated size of parameter is the
/// same as the size of the underlying parameter."
#[test]
fn oversized_private_under_xor_decrypt_session_is_a_parameter_size_error() {
    let mut tpm = Tpm::new();
    // ECC P-256 storage primary under the owner hierarchy.
    let mut cp = crate::_common::hex(concat!(
        "8002000000000000013140000001000000094000000900000100000004000000000",
        "01a0023000b00030072000000060080004300100003001000000000000000000000",
    ));
    let n = cp.len() as u32;
    cp[2..6].copy_from_slice(&n.to_be_bytes());
    let rsp = tpm.send_command(0, &cp);
    assert_eq!(&rsp[6..10], [0, 0, 0, 0], "CreatePrimary: {rsp:02x?}");
    let parent = rsp[10..14].to_vec();
    // Unbound, unsalted HMAC session with XOR/SHA-256 parameter obfuscation: its HMAC key is
    // empty, so a decrypt-only use carries an empty (null) HMAC.
    let sas = crate::_common::hex(concat!(
        "80010000002d00000176400000074000000700105a5b58595e5f5c5d5253505156575455",
        "000000000a000b000b",
    ));
    let rsp = tpm.send_command(0, &sas);
    assert_eq!(&rsp[6..10], [0, 0, 0, 0], "StartAuthSession: {rsp:02x?}");
    let session = rsp[10..14].to_vec();
    // Load(parent): password session for the parent, then the decrypt-only session.
    let mut cmd = vec![0x80, 0x02, 0, 0, 0, 0, 0, 0, 0x01, 0x57];
    cmd.extend_from_slice(&parent);
    let mut auth = vec![0x40, 0, 0, 9, 0, 0, 1, 0, 0];
    auth.extend_from_slice(&session);
    auth.extend_from_slice(&[0, 16]);
    auth.extend_from_slice(&[0x11; 16]);
    auth.extend_from_slice(&[0x21, 0, 0]);
    cmd.extend_from_slice(&(auth.len() as u32).to_be_bytes());
    cmd.extend_from_slice(&auth);
    cmd.extend_from_slice(&2169u16.to_be_bytes());
    cmd.extend(std::iter::repeat_n(0x42u8, 2169));
    cmd.extend_from_slice(&[0, 0]); // inPublic
    let n = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&n.to_be_bytes());
    let rsp = tpm.send_command(0, &cmd);
    assert_eq!(&rsp[6..10], 0x1D5u32.to_be_bytes(), "{rsp:02x?}");
}
