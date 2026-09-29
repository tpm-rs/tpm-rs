use tpm2::commands::{Hash, HashSequenceStart, SequenceComplete, SequenceUpdate};
use tpm2::*;

#[test]
fn test_hash_cmd_layout_and_big_endian() {
    // TPM2_Hash (Command) Layout:
    // data: TPM2B_MAX_BUFFER (u16 size + bytes)
    // hash_alg: TPMI_ALG_HASH (u16)
    // hierarchy: TPMI_RH_HIERARCHY (u32 handle)

    let data_bytes = [0x11, 0x22, 0x33, 0x44];
    let cmd = Hash {
        data: Tpm2bMaxBuffer::from_bytes(&data_bytes).unwrap(),
        hash_alg: TpmiAlgHash::Sha256,
        hierarchy: Handle::RH_NULL, // 0x40000007
    };

    let mut buf = [0u8; Hash::MAX_SIZE];
    let len = cmd.marshal(&mut buf);

    let expected_bytes: &[u8] = &[
        0x00, 0x04, // size (u16) = 4
        0x11, 0x22, 0x33, 0x44, // buffer data
        0x00, 0x0B, // hash_alg (u16) = SHA256 (0x000B)
        0x40, 0x00, 0x00, 0x07, // hierarchy (u32) = RHNull (0x40000007)
    ];

    assert_eq!(len, expected_bytes.len());
    assert_eq!(&buf[..len], expected_bytes);

    // Roundtrip verification
    let mut slice = &buf[..len];
    let unmarshaled = Hash::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled, cmd);
    assert!(slice.is_empty());
}

#[test]
fn test_hash_sequence_start_cmd_layout_and_big_endian() {
    // TPM2_HashSequenceStart (Command) Layout:
    // auth: TPM2B_AUTH (u16 size + bytes)
    // hash_alg: TPMI_ALG_HASH (u16)

    let auth_bytes = [0xAA, 0xBB, 0xCC];
    let cmd = HashSequenceStart {
        auth: Tpm2bAuth::from_bytes(&auth_bytes).unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha384), // 0x000C
    };

    let mut buf = [0u8; HashSequenceStart::MAX_SIZE];
    let len = cmd.marshal(&mut buf);

    let expected_bytes: &[u8] = &[
        0x00, 0x03, // size (u16) = 3
        0xAA, 0xBB, 0xCC, // auth data
        0x00, 0x0C, // hash_alg (u16) = SHA384 (0x000C)
    ];

    assert_eq!(len, expected_bytes.len());
    assert_eq!(&buf[..len], expected_bytes);

    // Roundtrip verification
    let mut slice = &buf[..len];
    let unmarshaled = HashSequenceStart::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled, cmd);
    assert!(slice.is_empty());
}

#[test]
fn test_sequence_update_cmd_layout_and_big_endian() {
    // TPM2_SequenceUpdate (Command) Layout:
    // buffer: TPM2B_MAX_BUFFER (u16 size + bytes)

    let data_bytes = [0x99, 0x88];
    let cmd = SequenceUpdate {
        buffer: Tpm2bMaxBuffer::from_bytes(&data_bytes).unwrap(),
    };

    let mut buf = [0u8; SequenceUpdate::MAX_SIZE];
    let len = cmd.marshal(&mut buf);

    let expected_bytes: &[u8] = &[
        0x00, 0x02, // size (u16) = 2
        0x99, 0x88, // buffer data
    ];

    assert_eq!(len, expected_bytes.len());
    assert_eq!(&buf[..len], expected_bytes);

    // Roundtrip verification
    let mut slice = &buf[..len];
    let unmarshaled = SequenceUpdate::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled, cmd);
    assert!(slice.is_empty());
}

#[test]
fn test_sequence_complete_cmd_layout_and_big_endian() {
    // TPM2_SequenceComplete (Command) Layout:
    // buffer: TPM2B_MAX_BUFFER (u16 size + bytes)
    // hierarchy: TPMI_RH_HIERARCHY (u32 handle)

    let data_bytes = [0x55, 0x66, 0x77];
    let cmd = SequenceComplete {
        buffer: Tpm2bMaxBuffer::from_bytes(&data_bytes).unwrap(),
        hierarchy: Handle::RH_OWNER, // 0x40000001
    };

    let mut buf = [0u8; SequenceComplete::MAX_SIZE];
    let len = cmd.marshal(&mut buf);

    let expected_bytes: &[u8] = &[
        0x00, 0x03, // size (u16) = 3
        0x55, 0x66, 0x77, // buffer data
        0x40, 0x00, 0x00, 0x01, // hierarchy (u32) = RHOwner (0x40000001)
    ];

    assert_eq!(len, expected_bytes.len());
    assert_eq!(&buf[..len], expected_bytes);

    // Roundtrip verification
    let mut slice = &buf[..len];
    let unmarshaled = SequenceComplete::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled, cmd);
    assert!(slice.is_empty());
}

#[test]
fn test_marshalling_stress_buffer_sizes() {
    // Stress test marshalling and unmarshalling for all commands using various buffer sizes
    let test_sizes = [0, 1, 2, 4, 32, 128, 512, 1024];

    for &size in &test_sizes {
        let data_bytes = vec![0xEEu8; size];
        let max_buffer = Tpm2bMaxBuffer::from_bytes(&data_bytes).unwrap();
        let auth = Tpm2bAuth::from_bytes(&data_bytes[..core::cmp::min(size, 64)]).unwrap();

        // 1. Hash
        let hash_cmd = Hash {
            data: max_buffer,
            hash_alg: TpmiAlgHash::Sha256,
            hierarchy: Handle::RH_OWNER,
        };
        let mut buf1 = [0u8; Hash::MAX_SIZE];
        let len1 = hash_cmd.marshal(&mut buf1);
        let mut slice1 = &buf1[..len1];
        assert_eq!(Hash::unmarshal(&mut slice1).unwrap(), hash_cmd);
        assert!(slice1.is_empty());

        // 2. HashSequenceStart
        let start_cmd = HashSequenceStart {
            auth,
            hash_alg: Some(TpmiAlgHash::Sha512),
        };
        let mut buf2 = [0u8; HashSequenceStart::MAX_SIZE];
        let len2 = start_cmd.marshal(&mut buf2);
        let mut slice2 = &buf2[..len2];
        assert_eq!(
            HashSequenceStart::unmarshal(&mut slice2).unwrap(),
            start_cmd
        );
        assert!(slice2.is_empty());

        // 3. SequenceUpdate
        let update_cmd = SequenceUpdate { buffer: max_buffer };
        let mut buf3 = [0u8; SequenceUpdate::MAX_SIZE];
        let len3 = update_cmd.marshal(&mut buf3);
        let mut slice3 = &buf3[..len3];
        assert_eq!(SequenceUpdate::unmarshal(&mut slice3).unwrap(), update_cmd);
        assert!(slice3.is_empty());

        // 4. SequenceComplete
        let complete_cmd = SequenceComplete {
            buffer: max_buffer,
            hierarchy: Handle::RH_NULL,
        };
        let mut buf4 = [0u8; SequenceComplete::MAX_SIZE];
        let len4 = complete_cmd.marshal(&mut buf4);
        let mut slice4 = &buf4[..len4];
        assert_eq!(
            SequenceComplete::unmarshal(&mut slice4).unwrap(),
            complete_cmd
        );
        assert!(slice4.is_empty());
    }
}

#[test]
fn test_stress_handles() {
    // Stress test handle values (valid and invalid TPMI_RH_HIERARCHY values)
    let valid_handles = [
        Handle(0x40000001), // RHOwner
        Handle(0x40000007), // RHNull
        Handle(0x4000000B), // RHEndorsement
        Handle(0x4000000C), // RHPlatform
    ];

    for &handle in &valid_handles {
        let hash_cmd = Hash {
            data: Tpm2bMaxBuffer::default(),
            hash_alg: TpmiAlgHash::Sha256,
            hierarchy: handle,
        };
        let mut buf = [0u8; Hash::MAX_SIZE];
        let len = hash_cmd.marshal(&mut buf);
        let mut slice = &buf[..len];
        let unmarshaled = Hash::unmarshal(&mut slice).unwrap();
        assert_eq!(unmarshaled.hierarchy, handle);
    }

    let invalid_handles = [
        Handle(0),
        Handle(1),
        Handle(0x00000001),
        Handle(0x80000000),
        Handle(0xFFFFFFFF),
    ];

    for &handle in &invalid_handles {
        let hash_cmd = Hash {
            data: Tpm2bMaxBuffer::default(),
            hash_alg: TpmiAlgHash::Sha256,
            hierarchy: handle,
        };
        let mut buf = [0u8; Hash::MAX_SIZE];
        let len = hash_cmd.marshal(&mut buf);
        let mut slice = &buf[..len];
        assert_eq!(
            Hash::unmarshal(&mut slice).unwrap_err(),
            tpm2::errors::UnmarshalError::VALUE.in_parameter(3)
        );
    }
}

#[test]
fn test_unmarshal_errors_and_panic_safety() {
    // 1. Truncated buffers: not enough data to read u16 size field of Tpm2bMaxBuffer
    {
        let buf = [0u8; 1];
        let mut slice = &buf[..];
        assert_eq!(
            Hash::unmarshal(&mut slice).unwrap_err(),
            tpm2::errors::UnmarshalError::INSUFFICIENT.in_parameter(1)
        );
    }

    // 2. Size field specifies more data than available in buffer
    {
        let buf = [0x00, 0x05, 0xAA, 0xBB]; // declared size 5, only 2 bytes of data
        let mut slice = &buf[..];
        assert_eq!(
            SequenceUpdate::unmarshal(&mut slice).unwrap_err(),
            tpm2::errors::UnmarshalError::INSUFFICIENT.in_parameter(1)
        );
    }

    // 3. Size field specifies more data than the type's MAX_BUFFER_SIZE (1024)
    // Case A: buffer actually contains the declared bytes
    {
        let mut buf = vec![0u8; 1032];
        let large_size = 1025u16;
        buf[0..2].copy_from_slice(&large_size.to_be_bytes());
        let mut slice = buf.as_slice();
        assert_eq!(
            SequenceUpdate::unmarshal(&mut slice).unwrap_err(),
            tpm2::errors::UnmarshalError::SIZE.in_parameter(1)
        );
    }
    // Case B: buffer is smaller than the declared size
    {
        let mut buf = vec![0u8; 100];
        let large_size = 1025u16;
        buf[0..2].copy_from_slice(&large_size.to_be_bytes());
        let mut slice = buf.as_slice();
        assert_eq!(
            SequenceUpdate::unmarshal(&mut slice).unwrap_err(),
            tpm2::errors::UnmarshalError::SIZE.in_parameter(1)
        );
    }

    // 4. Missing subsequent fields
    // Hash has: data (Tpm2bMaxBuffer) + hash_alg (u16) + hierarchy (u32)
    // Provide data correctly, but omit hash_alg and hierarchy
    {
        let data = [0x11, 0x22];
        let mut buf = Vec::new();
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&data);
        // Omit hash_alg and hierarchy
        let mut slice = buf.as_slice();
        assert_eq!(
            Hash::unmarshal(&mut slice).unwrap_err(),
            tpm2::errors::UnmarshalError::INSUFFICIENT.in_parameter(2)
        );
    }

    // Provide data and hash_alg, but omit hierarchy
    {
        let data = [0x11, 0x22];
        let mut buf = Vec::new();
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&data);
        buf.extend_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
        // Omit hierarchy
        let mut slice = buf.as_slice();
        assert_eq!(
            Hash::unmarshal(&mut slice).unwrap_err(),
            tpm2::errors::UnmarshalError::INSUFFICIENT.in_parameter(3)
        );
    }

    // 5. Omit hierarchy in SequenceComplete
    {
        let data = [0x11, 0x22];
        let mut buf = Vec::new();
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&data);
        // Omit hierarchy
        let mut slice = buf.as_slice();
        assert_eq!(
            SequenceComplete::unmarshal(&mut slice).unwrap_err(),
            tpm2::errors::UnmarshalError::INSUFFICIENT.in_parameter(2)
        );
    }
}

#[test]
fn test_unmarshal_with_trailing_data() {
    let data_bytes = [0x11, 0x22];
    let cmd = SequenceUpdate {
        buffer: Tpm2bMaxBuffer::from_bytes(&data_bytes).unwrap(),
    };

    let mut buf = Vec::new();
    buf.extend_from_slice(&(data_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(&data_bytes);
    // Add trailing bytes
    buf.extend_from_slice(&[0x99, 0x99, 0x99]);

    let mut slice = buf.as_slice();
    let unmarshaled = SequenceUpdate::unmarshal(&mut slice).unwrap();
    assert_eq!(unmarshaled, cmd);

    // Trailing bytes should still be in the slice
    assert_eq!(slice, &[0x99, 0x99, 0x99]);
}
