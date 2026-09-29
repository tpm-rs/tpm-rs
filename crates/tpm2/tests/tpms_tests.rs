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

use tpm2::errors::{TpmRc, UnmarshalError};
use tpm2::*;

#[test]
fn test_tpms_auth_response_hmac_uses_tpm2b_auth() {
    assert_eq!(
        TpmsAuthResponse::MAX_SIZE,
        Tpm2bNonce::MAX_SIZE + TpmaSession::MAX_SIZE + Tpm2bAuth::MAX_SIZE
    );
    let max_digest = TpmiAlgHash::MAX_DIGEST_BYTES;
    assert_eq!(
        TpmsAuthResponse::MAX_SIZE,
        (2 + max_digest) + 1 + (2 + max_digest)
    );

    // Max valid size for TPM2B_AUTH should succeed round-trip.
    let auth_resp = TpmsAuthResponse {
        nonce: Tpm2bNonce::from_bytes(&[0x11; TpmiAlgHash::MAX_DIGEST_BYTES]).unwrap(),
        session_attributes: TpmaSession(0x01),
        hmac: Tpm2bAuth::from_bytes(&[0x22; TpmiAlgHash::MAX_DIGEST_BYTES]).unwrap(),
    };
    let mut buf = [0u8; TpmsAuthResponse::MAX_SIZE];
    let written = auth_resp.marshal(&mut buf);
    let mut slice = &buf[..written];
    let unmarshaled = TpmsAuthResponse::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled, auth_resp);
    assert!(slice.is_empty());

    // MAX_DIGEST_BYTES + 1 and MAX_DIGEST_BYTES + 2 HMAC buffers (would fit in Tpm2bData which allows up to 2 + MAX_DIGEST_BYTES,
    // but must be rejected for Tpm2bAuth which allows up to MAX_DIGEST_BYTES).
    for size in [(max_digest + 1) as u16, (max_digest + 2) as u16] {
        let mut raw = [0u8; 2 + 0 + 1 + 2 + 66];
        // nonce size = 0
        raw[0] = 0x00;
        raw[1] = 0x00;
        // session_attributes = 0x01
        raw[2] = 0x01;
        // hmac size = max_digest + 1 or max_digest + 2
        raw[3] = (size >> 8) as u8;
        raw[4] = size as u8;
        let mut slice = &raw[..5 + size as usize];
        assert_eq!(
            TpmsAuthResponse::unmarshal(&mut slice),
            Err(UnmarshalError::SIZE)
        );
    }
}

#[test]
fn test_tpms_id_object_enc_identity_raw_encrypted_bytes() {
    let d_len = TpmiAlgHash::MAX_DIGEST_BYTES.min(32);
    let hmac = Tpm2bDigest::from_bytes(&[0xAA; 32][..d_len]).unwrap();
    // Simulated CFB-encrypted marshaled TPM2B_DIGEST (2 + d_len bytes: encrypted 2-byte size + d_len-byte digest).
    // The first two bytes are 0xFE, 0xDC (u16 = 65244 > 64), which would fail if parsed as plaintext Tpm2bDigest.
    let mut raw_ciphertext_buf = [0x55u8; 34];
    raw_ciphertext_buf[0] = 0xFE;
    raw_ciphertext_buf[1] = 0xDC;
    let raw_ciphertext = &raw_ciphertext_buf[..2 + d_len];

    let id_obj = TpmsIdObject::new(hmac, raw_ciphertext).unwrap();
    assert_eq!(id_obj.enc_identity(), raw_ciphertext);

    // Marshal TpmsIdObject directly and verify wire format:
    // [hmac size: 2 bytes][hmac: d_len bytes][raw_ciphertext: 2 + d_len bytes] (no extra u16 prefix before enc_identity!)
    let mut buf = [0u8; TpmsIdObject::MAX_SIZE];
    let written = id_obj.marshal(&mut buf);
    assert_eq!(written, 2 + d_len + (2 + d_len));
    assert_eq!(&buf[0..2], &(d_len as u16).to_be_bytes());
    assert_eq!(&buf[2..2 + d_len], &[0xAA; 32][..d_len]);
    assert_eq!(&buf[2 + d_len..written], raw_ciphertext);

    // Unmarshal back from raw wire bytes
    let mut slice = &buf[..written];
    let unmarshaled = TpmsIdObject::unmarshal(&mut slice).unwrap();
    assert!(slice.is_empty());
    assert_eq!(unmarshaled, id_obj);
    assert_eq!(unmarshaled.enc_identity(), raw_ciphertext);

    // Test Tpm2bIdObject::from_struct_in and to_struct roundtrip
    let mut id_obj_buf = [0u8; TpmsIdObject::MAX_SIZE];
    let id_obj_2b = Tpm2bIdObject::from_struct_in(&id_obj, &mut id_obj_buf).unwrap();
    assert_eq!(id_obj_2b.get_size() as usize, written);
    assert_eq!(id_obj_2b.get_buffer(), &buf[..written]);

    let recovered_struct = id_obj_2b.to_struct().unwrap();
    assert_eq!(recovered_struct, id_obj);

    // Test maximum enc_identity size (Tpm2bDigest::MAX_SIZE)
    let max_ciphertext = [0xFFu8; Tpm2bDigest::MAX_SIZE];
    let max_id_obj = TpmsIdObject::new(
        Tpm2bDigest::from_bytes(&[0xBB; TpmiAlgHash::MAX_DIGEST_BYTES]).unwrap(),
        &max_ciphertext,
    )
    .unwrap();
    let mut max_2b_buf = [0u8; TpmsIdObject::MAX_SIZE];
    let max_2b = Tpm2bIdObject::from_struct_in(&max_id_obj, &mut max_2b_buf).unwrap();
    assert_eq!(max_2b.get_size() as usize, TpmsIdObject::MAX_SIZE);
    assert_eq!(max_2b.to_struct().unwrap(), max_id_obj);

    // Exceeding Tpm2bDigest::MAX_SIZE (67 bytes) must return SIZE error
    let oversized_ciphertext = [0xFFu8; Tpm2bDigest::MAX_SIZE + 1];
    assert_eq!(
        TpmsIdObject::new(hmac, &oversized_ciphertext),
        Err(UnmarshalError::SIZE)
    );
    let mut bad_struct = id_obj;
    bad_struct.enc_identity_len = Tpm2bDigest::MAX_SIZE + 1;
    let mut bad_buf = [0u8; TpmsIdObject::MAX_SIZE];
    assert_eq!(
        Tpm2bIdObject::from_struct_in(&bad_struct, &mut bad_buf),
        Err(UnmarshalError::SIZE)
    );
}

#[test]
fn test_tpms_nv_public_data_size_max_nv_index_size_bounds() {
    let valid_nv_pub = TpmsNvPublic {
        nv_index: Handle(0x01000001),
        name_alg: TpmiAlgHash::DEFAULT_HASH,
        attributes: TpmaNv::OWNERWRITE | TpmaNv::OWNERREAD,
        auth_policy: Tpm2bDigest::default(),
        data_size: TPM2_MAX_NV_INDEX_SIZE,
    };
    let mut buf = [0u8; TpmsNvPublic::MAX_SIZE];
    let len = valid_nv_pub.marshal(&mut buf);
    let mut slice = &buf[..len];
    let unmarshaled = TpmsNvPublic::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled, valid_nv_pub);

    // data_size = 0 should also succeed
    let mut zero_size_pub = valid_nv_pub;
    zero_size_pub.data_size = 0;
    let len = zero_size_pub.marshal(&mut buf);
    let mut slice = &buf[..len];
    let unmarshaled = TpmsNvPublic::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled, zero_size_pub);

    // data_size = TPM2_MAX_NV_INDEX_SIZE + 1 (2049) must fail with UnmarshalError::SIZE
    let mut invalid_nv_pub = valid_nv_pub;
    invalid_nv_pub.data_size = TPM2_MAX_NV_INDEX_SIZE + 1;
    let len = invalid_nv_pub.marshal(&mut buf);
    let mut slice = &buf[..len];
    assert_eq!(
        TpmsNvPublic::unmarshal(&mut slice),
        Err(UnmarshalError::SIZE)
    );

    // data_size = u16::MAX (65535) must fail with UnmarshalError::SIZE
    let mut max_u16_pub = valid_nv_pub;
    max_u16_pub.data_size = u16::MAX;
    let len = max_u16_pub.marshal(&mut buf);
    let mut slice = &buf[..len];
    assert_eq!(
        TpmsNvPublic::unmarshal(&mut slice),
        Err(UnmarshalError::SIZE)
    );
}

#[test]
fn test_tpms_creation_data_parent_name_alg() {
    // 1. Default has parent_name_alg = Alg::NULL (per TPM 2.0 Part 2 Section 15.1 Table 238)
    let default_cd = TpmsCreationData::default();
    assert_eq!(default_cd.parent_name_alg, Alg::NULL);

    // Verify MAX_SIZE matches field sum with Alg::MAX_SIZE
    assert_eq!(
        TpmsCreationData::MAX_SIZE,
        TpmlPcrSelection::MAX_SIZE
            + Tpm2bDigest::MAX_SIZE
            + TpmaLocality::MAX_SIZE
            + Alg::MAX_SIZE
            + Tpm2bName::MAX_SIZE
            + Tpm2bName::MAX_SIZE
            + Tpm2bData::MAX_SIZE
    );

    // 2. Test round-trip with various Alg values:
    // - Alg::NULL (0x0010, permanent handle parent)
    // - Alg::SHA256 (0x000B, standard enabled hash)
    // - Alg::SHA512 (0x000D)
    // - Alg::SM3_256 (0x0012)
    // - Alg::RSA (0x0001, non-hash algorithm ID)
    // - Unenabled / arbitrary valid TPM_ALG_ID (e.g. 0x0070)
    let test_algs = [
        Alg::NULL,
        Alg::SHA256,
        Alg::SHA512,
        Alg::SM3_256,
        Alg::RSA,
        Alg::from(0x0070),
        Alg::from(0x00A5),
    ];

    let d_len = TpmiAlgHash::MAX_DIGEST_BYTES.min(32);
    for alg in test_algs {
        let cd = TpmsCreationData {
            pcr_select: TpmlPcrSelection::default(),
            pcr_digest: Tpm2bDigest::from_bytes(&[0x11; 32][..d_len]).unwrap(),
            locality: TpmaLocality(0x03),
            parent_name_alg: alg,
            parent_name: Tpm2bName::from_bytes(&[0x22; 34][..2 + d_len]).unwrap(),
            parent_qualified_name: Tpm2bName::from_bytes(&[0x33; 34][..2 + d_len]).unwrap(),
            outside_info: Tpm2bData::from_bytes(&[0x44; 16]).unwrap(),
        };

        let mut buf = [0u8; TpmsCreationData::MAX_SIZE];
        let written = cd.marshal(&mut buf);
        let mut slice = &buf[..written];
        let unmarshaled = TpmsCreationData::unmarshal(&mut slice)
            .expect("unmarshaling TpmsCreationData should succeed for any valid Alg");
        assert!(slice.is_empty());
        assert_eq!(unmarshaled, cd);
        assert_eq!(unmarshaled.parent_name_alg, alg);

        // Test Tpm2bCreationData round-trip
        let cd_2b = Tpm2bCreationData::from_struct(&cd).unwrap();
        let recovered = cd_2b.to_struct().unwrap();
        assert_eq!(recovered, cd);
        assert_eq!(recovered.parent_name_alg, alg);
    }
}

#[test]
fn test_tpms_nv_pin_counter_parameters() {
    assert_eq!(TpmsNvPinCounterParameters::MAX_SIZE, 8);
    assert_eq!(
        TpmsNvPinCounterParameters::default(),
        TpmsNvPinCounterParameters {
            pin_count: 0,
            pin_limit: 0,
        }
    );

    let params = TpmsNvPinCounterParameters {
        pin_count: 0x01020304,
        pin_limit: 0x05060708,
    };
    let mut buf = [0u8; TpmsNvPinCounterParameters::MAX_SIZE];
    let written = params.marshal(&mut buf);
    assert_eq!(written, 8);
    // pinCount is the most significant octets, pinLimit is the least significant octets (big-endian)
    assert_eq!(buf, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

    let mut slice = &buf[..written];
    let unmarshaled = TpmsNvPinCounterParameters::unmarshal(&mut slice).unwrap();
    assert!(slice.is_empty());
    assert_eq!(unmarshaled, params);

    // Short buffers (< 8 bytes) must fail with UnmarshalError::INSUFFICIENT
    for short_len in 0..8 {
        let mut short_slice = &buf[..short_len];
        assert_eq!(
            TpmsNvPinCounterParameters::unmarshal(&mut short_slice),
            Err(UnmarshalError::INSUFFICIENT)
        );
    }
}

#[test]
fn test_tpms_pcr_select() {
    assert_eq!(TpmsPcrSelect::MAX_SIZE, 1 + TPM2_PCR_SELECT_MAX as usize);
    assert_eq!(TpmsPcrSelect::MAX_SIZE, 4);

    // Default initializes sizeof_select = TPM2_PCR_SELECT_MIN (3) and pcr_select = [0; 3]
    let default_sel = TpmsPcrSelect::default();
    assert_eq!(default_sel.sizeof_select, TPM2_PCR_SELECT_MIN as u8);
    assert_eq!(default_sel.pcr_select, [0u8; TPM2_PCR_SELECT_MAX as usize]);
    assert_eq!(default_sel.sizeof_select(), 3);
    assert_eq!(default_sel.pcr_select(), &[0u8; 3]);

    // Constructor TpmsPcrSelect::new validation
    let sel = TpmsPcrSelect::new(&[0x01, 0x02, 0x80]).unwrap();
    assert_eq!(sel.sizeof_select, 3);
    assert_eq!(sel.pcr_select, [0x01, 0x02, 0x80]);
    assert_eq!(sel.sizeof_select(), 3);
    assert_eq!(sel.pcr_select(), &[0x01, 0x02, 0x80]);

    for invalid_len in [0usize, 1, 2, 4, 8] {
        let bytes = [0xAAu8; 8];
        assert_eq!(
            TpmsPcrSelect::new(&bytes[..invalid_len]),
            Err(TpmRc::VALUE.to_rc())
        );
    }

    // Marshal and Unmarshal roundtrip
    let mut buf = [0u8; TpmsPcrSelect::MAX_SIZE];
    let written = sel.marshal(&mut buf);
    assert_eq!(written, 4);
    assert_eq!(buf, [0x03, 0x01, 0x02, 0x80]);

    let mut slice = &buf[..written];
    let unmarshaled = TpmsPcrSelect::unmarshal(&mut slice).unwrap();
    assert!(slice.is_empty());
    assert_eq!(unmarshaled, sel);

    // Unmarshal empty buffer -> INSUFFICIENT
    let mut empty: &[u8] = &[];
    assert_eq!(
        TpmsPcrSelect::unmarshal(&mut empty),
        Err(UnmarshalError::INSUFFICIENT)
    );

    // Unmarshal with sizeof_select < TPM2_PCR_SELECT_MIN (0, 1, 2) -> VALUE
    // Even if buffer has no more bytes or has plenty of bytes, VALUE check happens first
    for bad_size in [0u8, 1, 2] {
        let raw = [bad_size, 0x11, 0x22, 0x33];
        let mut s1 = &raw[..1];
        assert_eq!(
            TpmsPcrSelect::unmarshal(&mut s1),
            Err(UnmarshalError::VALUE)
        );
        let mut s2 = &raw[..];
        assert_eq!(
            TpmsPcrSelect::unmarshal(&mut s2),
            Err(UnmarshalError::VALUE)
        );
    }

    // Unmarshal with sizeof_select > TPM2_PCR_SELECT_MAX (4, 5, 255) -> VALUE
    for bad_size in [4u8, 5, 255] {
        let raw = [bad_size, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut s1 = &raw[..1];
        assert_eq!(
            TpmsPcrSelect::unmarshal(&mut s1),
            Err(UnmarshalError::VALUE)
        );
        let mut s2 = &raw[..];
        assert_eq!(
            TpmsPcrSelect::unmarshal(&mut s2),
            Err(UnmarshalError::VALUE)
        );
    }

    // Unmarshal with valid sizeof_select (3) but truncated pcr_select bytes -> INSUFFICIENT
    for rem_len in 0..3 {
        let raw = [0x03u8, 0x11, 0x22, 0x33];
        let mut s = &raw[..1 + rem_len];
        assert_eq!(
            TpmsPcrSelect::unmarshal(&mut s),
            Err(UnmarshalError::INSUFFICIENT)
        );
    }

    // Clamping when sizeof_select > TPM2_PCR_SELECT_MAX does not panic in marshal or pcr_select
    let mut oversized = TpmsPcrSelect::new(&[0x11, 0x22, 0x33]).unwrap();
    oversized.sizeof_select = 255;
    assert_eq!(oversized.pcr_select(), &[0x11, 0x22, 0x33]);
    let mut buf = [0u8; TpmsPcrSelect::MAX_SIZE];
    let written = oversized.marshal(&mut buf);
    assert_eq!(written, 4);
    assert_eq!(buf, [0x03, 0x11, 0x22, 0x33]);
}

#[test]
fn test_tpms_tagged_pcr_select() {
    assert_eq!(
        TpmsTaggedPcrSelect::MAX_SIZE,
        4 + 1 + TPM2_PCR_SELECT_MAX as usize
    );
    assert_eq!(TpmsTaggedPcrSelect::MAX_SIZE, 8);

    // Default initializes size_of_select = TPM2_PCR_SELECT_MIN (3) and pcr_select = [0; 3]
    let default_tagged = TpmsTaggedPcrSelect::default();
    assert_eq!(default_tagged.tag(), TpmPtPcr::default());
    assert_eq!(default_tagged.size_of_select(), TPM2_PCR_SELECT_MIN as u8);
    assert_eq!(default_tagged.sizeof_select(), TPM2_PCR_SELECT_MIN as u8);
    assert_eq!(default_tagged.pcr_select(), &[0u8; 3]);

    // Constructor TpmsTaggedPcrSelect::new validation
    let tagged = TpmsTaggedPcrSelect::new(TpmPtPcr::SAVE, &[0xAA, 0xBB, 0xCC]).unwrap();
    assert_eq!(tagged.tag(), TpmPtPcr::SAVE);
    assert_eq!(tagged.size_of_select(), 3);
    assert_eq!(tagged.sizeof_select(), 3);
    assert_eq!(tagged.pcr_select(), &[0xAA, 0xBB, 0xCC]);

    for invalid_len in [0usize, 1, 2, 4, 8] {
        let bytes = [0x55u8; 8];
        assert_eq!(
            TpmsTaggedPcrSelect::new(TpmPtPcr::SAVE, &bytes[..invalid_len]),
            Err(TpmRc::VALUE.to_rc())
        );
    }

    // Marshal and Unmarshal roundtrip
    let mut buf = [0u8; TpmsTaggedPcrSelect::MAX_SIZE];
    let written = tagged.marshal(&mut buf);
    assert_eq!(written, 8);
    assert_eq!(&buf[0..4], &TpmPtPcr::SAVE.tag().to_be_bytes());
    assert_eq!(buf[4], 3);
    assert_eq!(&buf[5..8], &[0xAA, 0xBB, 0xCC]);

    let mut slice = &buf[..written];
    let unmarshaled = TpmsTaggedPcrSelect::unmarshal(&mut slice).unwrap();
    assert!(slice.is_empty());
    assert_eq!(unmarshaled, tagged);

    // Out-of-bounds public size_of_select (> 3) must be clamped in marshal and pcr_select without panicking
    for bad_size in [4u8, 5, 100, 255] {
        let oversized = TpmsTaggedPcrSelect {
            tag: TpmPtPcr::EXTEND_L0,
            size_of_select: bad_size,
            pcr_select: [0x12, 0x34, 0x56],
        };
        assert_eq!(oversized.pcr_select(), &[0x12, 0x34, 0x56]);
        let mut out = [0u8; TpmsTaggedPcrSelect::MAX_SIZE];
        let n = oversized.marshal(&mut out);
        assert_eq!(n, 8);
        assert_eq!(&out[0..4], &TpmPtPcr::EXTEND_L0.tag().to_be_bytes());
        assert_eq!(out[4], 3);
        assert_eq!(&out[5..8], &[0x12, 0x34, 0x56]);
    }
}
