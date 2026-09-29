// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use tpm2::errors::UnmarshalError;
use tpm2::*;

#[test]
fn test_unmarshal_invalid_public_type() {
    let mut buf = [0u8; 12];
    buf[0] = 0x00;
    buf[1] = 10; // size of TpmtPublic
    buf[2] = 0x00;
    buf[3] = 0x00; // type = 0 (invalid)
    buf[4] = 0x00;
    buf[5] = 0x0B; // name_alg = SHA256
    // rest are 0 (attrs = 0, auth_policy size = 0)

    let mut slice: &[u8] = &buf;
    let res = Tpm2bPublic::unmarshal(&mut slice);
    assert_eq!(res.unwrap_err(), UnmarshalError::TYPE);
}

#[test]
fn test_tpm2b_public_validation() {
    // Reject size == 0
    let zero_buf = [0x00u8, 0x00];
    let mut slice = &zero_buf[..];
    assert_eq!(
        Tpm2bPublic::unmarshal(&mut slice),
        Err(UnmarshalError::SIZE)
    );
}

#[test]
fn test_tpm2b_nv_public_validation() {
    // Reject size == 0
    let zero_buf = [0x00u8, 0x00];
    let mut slice = &zero_buf[..];
    assert_eq!(
        Tpm2bNvPublic::unmarshal(&mut slice),
        Err(UnmarshalError::SIZE)
    );

    // Reject invalid inner TpmsNvPublic (reserved bits in TPMA_NV)
    let default_hash_bytes = Alg::from(TpmiAlgHash::DEFAULT_HASH).id().to_be_bytes();
    let bad_attr_buf = [
        0x00u8,
        0x0E, // size = 14
        0x01,
        0x00,
        0x00,
        0x01, // nv_index = 0x01000001
        default_hash_bytes[0],
        default_hash_bytes[1], // name_alg = DEFAULT_HASH
        0x00,
        0x00,
        0x01,
        0x00, // attributes with reserved bit 8 set
        0x00,
        0x00, // auth_policy size = 0
        0x00,
        0x00, // data_size = 0
    ];
    let mut slice = &bad_attr_buf[..];
    assert_eq!(
        Tpm2bNvPublic::unmarshal(&mut slice),
        Err(UnmarshalError::RESERVED_BITS)
    );
}

#[cfg(feature = "rsa4096")]
#[test]
fn test_tpm2b_private_max_size_accommodates_rsa_4096() {
    let expected_max = Tpm2bDigest::MAX_SIZE * 2 + Tpm2bSensitive::MAX_SIZE;
    assert_eq!(Tpm2bPrivate::MAX_BUFFER_SIZE, expected_max);
    #[cfg(any(feature = "sha512", feature = "sha3_512"))]
    const {
        assert!(
            Tpm2bPrivate::MAX_BUFFER_SIZE >= 1550,
            "Tpm2bPrivate::MAX_BUFFER_SIZE must be at least 1550 bytes for 4096-bit RSA CRT keys",
        );
    }

    let outer_digest = Tpm2bDigest::from_bytes(&[0xAA; Tpm2bDigest::MAX_BUFFER_SIZE]).unwrap();
    let inner_digest = Tpm2bDigest::from_bytes(&[0xBB; Tpm2bDigest::MAX_BUFFER_SIZE]).unwrap();
    let rsa_priv =
        Tpm2bPrivateKeyRsa::from_bytes(&[0xCC; Tpm2bPrivateKeyRsa::MAX_BUFFER_SIZE]).unwrap();
    let sensitive_struct = TpmtSensitive {
        auth_value: Tpm2bAuth::from_bytes(&[0xDD; Tpm2bAuth::MAX_BUFFER_SIZE]).unwrap(),
        seed_value: Tpm2bDigest::from_bytes(&[0xEE; Tpm2bDigest::MAX_BUFFER_SIZE]).unwrap(),
        sensitive: TpmuSensitiveComposite::Rsa(rsa_priv),
    };
    let sensitive_2b = Tpm2bSensitive::from_struct(&sensitive_struct).unwrap();

    let mut private_payload = [0u8; Tpm2bPrivate::MAX_BUFFER_SIZE];
    let mut offset = 0;
    offset += outer_digest.marshal(
        (&mut private_payload[offset..offset + Tpm2bDigest::MAX_SIZE])
            .try_into()
            .unwrap(),
    );
    offset += inner_digest.marshal(
        (&mut private_payload[offset..offset + Tpm2bDigest::MAX_SIZE])
            .try_into()
            .unwrap(),
    );
    offset += sensitive_2b.marshal(
        (&mut private_payload[offset..offset + Tpm2bSensitive::MAX_SIZE])
            .try_into()
            .unwrap(),
    );
    assert_eq!(offset, Tpm2bPrivate::MAX_BUFFER_SIZE);

    let priv_2b = Tpm2bPrivate::from_bytes(&private_payload[..offset]).unwrap();
    let mut wire_buf = [0u8; Tpm2bPrivate::MAX_SIZE + 4];
    let wire_len = priv_2b.marshal(
        (&mut wire_buf[..Tpm2bPrivate::MAX_SIZE])
            .try_into()
            .unwrap(),
    );
    let mut slice = &wire_buf[..wire_len];
    let unmarshaled = Tpm2bPrivate::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled.get_buffer(), &private_payload[..offset]);

    let oversize = (Tpm2bPrivate::MAX_BUFFER_SIZE + 1) as u16;
    wire_buf[..2].copy_from_slice(&oversize.to_be_bytes());
    let mut bad_slice = &wire_buf[..wire_len + 1];
    assert_eq!(
        Tpm2bPrivate::unmarshal(&mut bad_slice),
        Err(UnmarshalError::SIZE)
    );
}

#[test]
fn test_tpm2b_encrypted_secret_max_size_sizeof_tpmu_encrypted_secret() {
    let expected_max = [
        TpmsEccPoint::MAX_SIZE,
        TPM2_MAX_RSA_KEY_BYTES as usize,
        Tpm2bDigest::MAX_SIZE,
    ]
    .into_iter()
    .max()
    .unwrap();
    assert_eq!(Tpm2bEncryptedSecret::MAX_BUFFER_SIZE, expected_max);
    assert_eq!(TpmtPublicParms::MAX_ENCRYPTED_SECRET_BYTES, expected_max);
    const {
        assert!(
            Tpm2bEncryptedSecret::MAX_BUFFER_SIZE >= TpmsEccPoint::MAX_SIZE,
            "Tpm2bEncryptedSecret::MAX_BUFFER_SIZE must accommodate TpmsEccPoint (sizeof(TPMS_ECC_POINT))",
        );
        assert!(
            Tpm2bEncryptedSecret::MAX_BUFFER_SIZE >= TPM2_MAX_RSA_KEY_BYTES as usize,
            "Tpm2bEncryptedSecret::MAX_BUFFER_SIZE must accommodate TPM2_MAX_RSA_KEY_BYTES",
        );
        assert!(
            Tpm2bEncryptedSecret::MAX_BUFFER_SIZE >= Tpm2bDigest::MAX_SIZE,
            "Tpm2bEncryptedSecret::MAX_BUFFER_SIZE must accommodate Tpm2bDigest (sizeof(TPM2B_DIGEST))",
        );
    }

    // Test that a full TpmsEccPoint marshaled buffer can be stored in Tpm2bEncryptedSecret
    let ecc_point_payload = [0x5Au8; TpmsEccPoint::MAX_SIZE];
    let secret = Tpm2bEncryptedSecret::from_bytes(&ecc_point_payload).unwrap();
    assert_eq!(secret.get_buffer(), &ecc_point_payload[..]);

    // Test that an encrypted secret up to MAX_BUFFER_SIZE can be marshaled and unmarshaled
    let full_payload = [0xA5u8; Tpm2bEncryptedSecret::MAX_BUFFER_SIZE];
    let secret = Tpm2bEncryptedSecret::from_bytes(&full_payload).unwrap();
    let mut wire_buf = [0u8; Tpm2bEncryptedSecret::MAX_SIZE + 4];
    let wire_len = secret.marshal(
        (&mut wire_buf[..Tpm2bEncryptedSecret::MAX_SIZE])
            .try_into()
            .unwrap(),
    );
    let mut slice = &wire_buf[..wire_len];
    let unmarshaled = Tpm2bEncryptedSecret::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled.get_buffer(), &full_payload[..]);

    // Reject size exceeding MAX_BUFFER_SIZE
    let oversize = (Tpm2bEncryptedSecret::MAX_BUFFER_SIZE + 1) as u16;
    wire_buf[..2].copy_from_slice(&oversize.to_be_bytes());
    let mut bad_slice = &wire_buf[..wire_len + 1];
    assert_eq!(
        Tpm2bEncryptedSecret::unmarshal(&mut bad_slice),
        Err(UnmarshalError::SIZE)
    );
}

#[test]
fn test_tpm2b_signature_eddsa() {
    assert_eq!(
        Tpm2bSignatureEddsa::MAX_BUFFER_SIZE,
        2 * (TPM2_MAX_ECC_KEY_BYTES as usize)
    );
    assert_eq!(Tpm2bSignatureEddsa::CAP, 256);

    for size in [0usize, 64, 114, 256] {
        let payload = [0x42u8; 256];
        let sig = Tpm2bSignatureEddsa::from_bytes(&payload[..size]).unwrap();
        assert_eq!(sig.get_size() as usize, size);
        assert_eq!(sig.get_buffer(), &payload[..size]);

        let mut dst = [0u8; Tpm2bSignatureEddsa::MAX_SIZE];
        let len = sig.marshal(&mut dst);
        assert_eq!(len, 2 + size);
        let mut src = &dst[..len];
        let decoded = Tpm2bSignatureEddsa::unmarshal(&mut src).unwrap();
        assert_eq!(decoded, sig);
        assert!(src.is_empty());
    }

    // Oversize (> 256 bytes) must fail with UnmarshalError::SIZE
    let oversize_payload = [0x42u8; 257];
    assert_eq!(
        Tpm2bSignatureEddsa::from_bytes(&oversize_payload),
        Err(UnmarshalError::SIZE)
    );
    let mut wire = [0u8; 260];
    wire[0..2].copy_from_slice(&257u16.to_be_bytes());
    let mut src = &wire[..259];
    assert_eq!(
        Tpm2bSignatureEddsa::unmarshal(&mut src),
        Err(UnmarshalError::SIZE)
    );
}

#[test]
fn test_tpm2b_struct_and_template_unmarshal_insufficient_vs_size_precedence() {
    // 1. Tpm2b<T>::from_bytes: truncated inner structure returns INSUFFICIENT, trailing bytes return SIZE
    assert_eq!(
        Tpm2bSensitiveCreate::from_bytes(&[0x00, 0x00]),
        Err(UnmarshalError::INSUFFICIENT)
    );
    assert_eq!(
        Tpm2bSensitiveCreate::from_bytes(&[0x00, 0x00, 0x00, 0x00, 0xFF]),
        Err(UnmarshalError::SIZE)
    );

    // 2. Tpm2b<T>::unmarshal: when len > 0 and start_len == len, a truncated inner structure
    // that exhausts src returns INSUFFICIENT (matching C TPM Marshal.c and ibmswtpm2 Unmarshal.c).
    let truncated_sc = [0x00u8, 0x02, 0x00, 0x00]; // size = 2, userAuth.size = 0, data missing
    let mut s_sc = &truncated_sc[..];
    assert_eq!(
        Tpm2bSensitiveCreate::unmarshal(&mut s_sc),
        Err(UnmarshalError::INSUFFICIENT)
    );

    let default_hash_bytes = Alg::from(TpmiAlgHash::DEFAULT_HASH).id().to_be_bytes();
    let truncated_pub = [
        0x00u8,
        0x04,
        0x00,
        0x08,
        default_hash_bytes[0],
        default_hash_bytes[1],
    ]; // size = 4, type = KeyedHash, nameAlg = DEFAULT_HASH, truncated
    let mut s_pub = &truncated_pub[..];
    assert_eq!(
        Tpm2bPublic::unmarshal(&mut s_pub),
        Err(UnmarshalError::INSUFFICIENT)
    );

    // 3. Tpm2bPublic::unmarshal_with_flag / unmarshal_nullable: truncated inner structure returns INSUFFICIENT
    let truncated_pub_null = [0x00u8, 0x04, 0x00, 0x08, 0x00, 0x10]; // size = 4, type = KeyedHash, nameAlg = NULL, truncated
    let mut s_pub_null = &truncated_pub_null[..];
    assert_eq!(
        Tpm2bPublic::unmarshal_with_flag(&mut s_pub_null, true),
        Err(UnmarshalError::INSUFFICIENT)
    );

    // 4. Tpm2bTemplate::to_struct: truncated inner TpmtPublic returns INSUFFICIENT (consistent with unmarshal_to_public)
    let tmpl_buf = [0x00, 0x08, default_hash_bytes[0], default_hash_bytes[1]];
    let tmpl_truncated = Tpm2bTemplate::from_bytes(&tmpl_buf).unwrap();
    assert_eq!(
        tmpl_truncated.to_struct(),
        Err(UnmarshalError::INSUFFICIENT)
    );
    assert_eq!(
        tmpl_truncated.unmarshal_to_public(false),
        Err(UnmarshalError::INSUFFICIENT)
    );

    // 5. Tpm2bIdObject::to_struct: truncated integrity HMAC returns INSUFFICIENT
    let id_obj_empty = Tpm2bIdObject::from_bytes(&[]).unwrap();
    assert_eq!(id_obj_empty.to_struct(), Err(UnmarshalError::INSUFFICIENT));
    let id_obj_truncated_hmac = Tpm2bIdObject::from_bytes(&[0x00, 0x14, 0xAA]).unwrap();
    assert_eq!(
        id_obj_truncated_hmac.to_struct(),
        Err(UnmarshalError::INSUFFICIENT)
    );

    // 6. Tpm2bContextData::to_struct: truncated integrity or encrypted field returns INSUFFICIENT
    let ctx_empty = Tpm2bContextData::from_bytes(&[]).unwrap();
    assert_eq!(ctx_empty.to_struct(), Err(UnmarshalError::INSUFFICIENT));
    let ctx_missing_encrypted = Tpm2bContextData::from_bytes(&[0x00, 0x00]).unwrap();
    assert_eq!(
        ctx_missing_encrypted.to_struct(),
        Err(UnmarshalError::INSUFFICIENT)
    );
}

#[test]
fn test_max_sym_data_and_max_nv_buffer_size_limits() {
    // 1. Verify MAX_SYM_DATA = 128 (Tpm2bSensitiveData)
    assert_eq!(TPM2_MAX_SYM_DATA, 128);
    assert_eq!(Tpm2bSensitiveData::MAX_BUFFER_SIZE, 128);
    assert_eq!(Tpm2bSensitiveData::MAX_SIZE, 130);

    let valid_sym = [0xAAu8; 128];
    assert!(Tpm2bSensitiveData::from_bytes(&valid_sym).is_ok());
    for bad_len in [129usize, 256] {
        let mut wire = [0u8; 2 + 256];
        wire[0..2].copy_from_slice(&(bad_len as u16).to_be_bytes());
        let mut src = &wire[..2 + bad_len];
        assert_eq!(
            Tpm2bSensitiveData::unmarshal(&mut src),
            Err(UnmarshalError::SIZE)
        );
        assert_eq!(
            Tpm2bSensitiveData::from_bytes(&wire[2..2 + bad_len]),
            Err(UnmarshalError::SIZE)
        );
    }

    // 2. Verify MAX_NV_BUFFER_SIZE = 1024 (Tpm2bMaxNvBuffer)
    assert_eq!(TPM2_MAX_NV_BUFFER_SIZE, 1024);
    assert_eq!(Tpm2bMaxNvBuffer::MAX_BUFFER_SIZE, 1024);
    assert_eq!(Tpm2bMaxNvBuffer::MAX_SIZE, 1026);

    let valid_nv = [0xBBu8; 1024];
    assert!(Tpm2bMaxNvBuffer::from_bytes(&valid_nv).is_ok());
    for bad_len in [1025usize, 2048] {
        let mut wire = [0u8; 2 + 2048];
        wire[0..2].copy_from_slice(&(bad_len as u16).to_be_bytes());
        let mut src = &wire[..2 + bad_len];
        assert_eq!(
            Tpm2bMaxNvBuffer::unmarshal(&mut src),
            Err(UnmarshalError::SIZE)
        );
        assert_eq!(
            Tpm2bMaxNvBuffer::from_bytes(&wire[2..2 + bad_len]),
            Err(UnmarshalError::SIZE)
        );
    }
}

#[test]
fn test_tpm2b_signature_ctx_and_kem_ciphertext_max_buffer_sizes() {
    use tags::Tpm2bTag;

    // 1. Verify Tpm2bSignatureCtx::CAP = 255 (sizeof(TPMU_SIGNATURE_CTX) per Part 2 Section 11.3.5-11.3.6)
    assert_eq!(TPM2_MAX_SIGNATURE_CTX_SIZE, 255);
    assert_eq!(tags::SignatureCtx::CAP, 255);
    assert_eq!(Tpm2bSignatureCtx::CAP, 255);
    assert_eq!(Tpm2bSignatureCtx::MAX_BUFFER_SIZE, 255);
    assert_eq!(Tpm2bSignatureCtx::MAX_SIZE, 257);

    for valid_len in [0usize, 1, 2, 255] {
        let payload = [0x11u8; 255];
        let ctx = Tpm2bSignatureCtx::from_bytes(&payload[..valid_len]).unwrap();
        assert_eq!(ctx.get_size() as usize, valid_len);
        assert_eq!(ctx.get_buffer(), &payload[..valid_len]);

        let mut wire = [0u8; Tpm2bSignatureCtx::MAX_SIZE];
        let written = ctx.marshal(&mut wire);
        assert_eq!(written, 2 + valid_len);
        let mut src = &wire[..written];
        let decoded = Tpm2bSignatureCtx::unmarshal(&mut src).unwrap();
        assert_eq!(decoded, ctx);
        assert!(src.is_empty());
    }

    // Reject 256-byte (and larger) buffer with UnmarshalError::SIZE
    for bad_len in [256usize, 257, 512] {
        let mut wire = [0x22u8; 2 + 512];
        wire[0..2].copy_from_slice(&(bad_len as u16).to_be_bytes());
        let mut src = &wire[..2 + bad_len];
        assert_eq!(
            Tpm2bSignatureCtx::unmarshal(&mut src),
            Err(UnmarshalError::SIZE)
        );
        assert_eq!(
            Tpm2bSignatureCtx::from_bytes(&wire[2..2 + bad_len]),
            Err(UnmarshalError::SIZE)
        );
    }

    // 2. Verify Tpm2bKemCiphertext::CAP = 1568 (sizeof(TPMU_KEM_CIPHERTEXT) per Part 2 Section 10.4.10-10.4.11)
    assert_eq!(TPM2_MAX_MLKEM_CT_SIZE, 1568);
    assert_eq!(TPM2_MAX_KEM_CIPHERTEXT_SIZE, 1568);
    assert_eq!(tags::KemCiphertext::CAP, 1568);
    assert_eq!(Tpm2bKemCiphertext::CAP, 1568);
    assert_eq!(Tpm2bKemCiphertext::MAX_BUFFER_SIZE, 1568);
    assert_eq!(Tpm2bKemCiphertext::MAX_SIZE, 1570);

    for valid_len in [0usize, TpmsEccPoint::MAX_SIZE, 768, 1088, 1568] {
        let payload = [0x33u8; 1568];
        let ct = Tpm2bKemCiphertext::from_bytes(&payload[..valid_len]).unwrap();
        assert_eq!(ct.get_size() as usize, valid_len);
        assert_eq!(ct.get_buffer(), &payload[..valid_len]);

        let mut wire = [0u8; Tpm2bKemCiphertext::MAX_SIZE];
        let written = ct.marshal(&mut wire);
        assert_eq!(written, 2 + valid_len);
        let mut src = &wire[..written];
        let decoded = Tpm2bKemCiphertext::unmarshal(&mut src).unwrap();
        assert_eq!(decoded, ct);
        assert!(src.is_empty());
    }

    // Reject 1569-byte..=1600-byte (and larger) buffer with UnmarshalError::SIZE
    for bad_len in [1569usize, 1570, 1600, 2048] {
        let mut wire = [0x44u8; 2 + 2048];
        wire[0..2].copy_from_slice(&(bad_len as u16).to_be_bytes());
        let mut src = &wire[..2 + bad_len];
        assert_eq!(
            Tpm2bKemCiphertext::unmarshal(&mut src),
            Err(UnmarshalError::SIZE)
        );
        assert_eq!(
            Tpm2bKemCiphertext::from_bytes(&wire[2..2 + bad_len]),
            Err(UnmarshalError::SIZE)
        );
    }
}
