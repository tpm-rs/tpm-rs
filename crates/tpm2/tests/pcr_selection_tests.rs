use tpm2::*;

struct Lcg {
    state: u64,
}

impl Lcg {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }
    fn next_u32(&mut self) -> u32 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.state >> 32) as u32
    }
    fn next_bytes(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(4) {
            let val = self.next_u32();
            let bytes = val.to_ne_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&bytes[..len]);
        }
    }
}

#[test]
fn test_pcr_selection_valid_bounds() {
    let len = TPM2_PCR_SELECT_MAX as usize;
    let mut pcr_select_data = [0u8; TPM2_PCR_SELECT_MAX as usize];
    for (i, val) in pcr_select_data.iter_mut().enumerate() {
        *val = i as u8 + 1;
    }
    let sel = TpmsPcrSelection::new(TpmiAlgHash::Sha256, &pcr_select_data).unwrap();
    assert_eq!(sel.sizeof_select(), len as u8);
    assert_eq!(sel.pcr_select(), &pcr_select_data);

    let mut buf = [0u8; TpmsPcrSelection::MAX_SIZE];
    let bytes_written = sel.marshal(&mut buf);
    assert_eq!(bytes_written, 2 + 1 + len);

    assert_eq!(
        u16::from_be_bytes([buf[0], buf[1]]),
        Alg::from(TpmiAlgHash::Sha256).id()
    );
    assert_eq!(buf[2], len as u8);
    assert_eq!(&buf[3..3 + len], &pcr_select_data);

    let mut reader = &buf[..bytes_written];
    let unmarshaled = TpmsPcrSelection::unmarshal(&mut reader).unwrap();
    assert_eq!(unmarshaled, sel);
    assert_eq!(reader.len(), 0);
}

#[test]
fn test_pcr_selection_invalid_bounds() {
    // Constructing with length < TPM2_PCR_SELECT_MIN (3) must fail with VALUE.
    for short_len in 0..TPM2_PCR_SELECT_MIN {
        let short_data = [0xAA; 3];
        let err = TpmsPcrSelection::new(TpmiAlgHash::Sha256, &short_data[..short_len]).unwrap_err();
        assert_eq!(err, tpm2::errors::TpmRc::VALUE);
        let err_sel = TpmsPcrSelect::new(&short_data[..short_len]).unwrap_err();
        assert_eq!(err_sel, tpm2::errors::TpmRc::VALUE);
    }

    // Constructing with length > 3 must fail with VALUE.
    let too_large_data = [1, 2, 3, 4];
    let err = TpmsPcrSelection::new(TpmiAlgHash::Sha256, &too_large_data).unwrap_err();
    assert_eq!(err, tpm2::errors::TpmRc::VALUE);

    // Unmarshalling a buffer with sizeof_select < TPM2_PCR_SELECT_MIN must fail with VALUE.
    for invalid_len in 0..(TPM2_PCR_SELECT_MIN as u8) {
        let mut buf = [0u8; 16];
        buf[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
        buf[2] = invalid_len;
        let mut reader = &buf[..3 + invalid_len as usize];
        let err = TpmsPcrSelection::unmarshal(&mut reader).unwrap_err();
        assert_eq!(err, tpm2::errors::UnmarshalError::VALUE);
    }

    // Unmarshalling a buffer with sizeof_select > TPM2_PCR_SELECT_MAX must fail with VALUE.
    for invalid_len in (TPM2_PCR_SELECT_MAX as u8 + 1)..=255 {
        let mut buf = [0u8; 300];
        buf[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
        buf[2] = invalid_len;
        let mut reader = &buf[..3 + invalid_len as usize];
        let err = TpmsPcrSelection::unmarshal(&mut reader).unwrap_err();
        assert_eq!(err, tpm2::errors::UnmarshalError::VALUE);
    }
}

#[test]
fn test_tagged_pcr_select_bounds() {
    // Default TpmsTaggedPcrSelect has valid size_of_select == TPM2_PCR_SELECT_MIN (3) and roundtrips.
    let default_tagged = TpmsTaggedPcrSelect::default();
    assert_eq!(default_tagged.size_of_select as usize, TPM2_PCR_SELECT_MIN);
    let mut buf = [0u8; TpmsTaggedPcrSelect::MAX_SIZE];
    let written = default_tagged.marshal(&mut buf);
    let mut reader = &buf[..written];
    let unmarshaled = TpmsTaggedPcrSelect::unmarshal(&mut reader).unwrap();
    assert_eq!(unmarshaled, default_tagged);
    assert!(reader.is_empty());

    // Validated constructor TpmsTaggedPcrSelect::new enforces TPM2_PCR_SELECT_MIN..=TPM2_PCR_SELECT_MAX.
    let constructed = TpmsTaggedPcrSelect::new(TpmPtPcr::SAVE, &[0x01, 0x02, 0x03]).unwrap();
    assert_eq!(constructed.tag(), TpmPtPcr::SAVE);
    assert_eq!(constructed.size_of_select(), 3);
    assert_eq!(constructed.pcr_select(), &[0x01, 0x02, 0x03]);
    for bad_len in [0usize, 1, 2, 4, 8] {
        let data = [0xAAu8; 8];
        let err = TpmsTaggedPcrSelect::new(TpmPtPcr::SAVE, &data[..bad_len]).unwrap_err();
        assert_eq!(err, tpm2::errors::TpmRc::VALUE);
    }

    // Mutating or constructing with size_of_select > TPM2_PCR_SELECT_MAX clamps during marshal without panicking.
    for bad_size in (TPM2_PCR_SELECT_MAX as u8 + 1)..=255 {
        let oversized = TpmsTaggedPcrSelect {
            tag: TpmPtPcr::SAVE,
            size_of_select: bad_size,
            pcr_select: [0xDE, 0xAD, 0xBE],
        };
        assert_eq!(oversized.pcr_select(), &[0xDE, 0xAD, 0xBE]);
        let mut out = [0u8; TpmsTaggedPcrSelect::MAX_SIZE];
        let n = oversized.marshal(&mut out);
        assert_eq!(n, TpmsTaggedPcrSelect::MAX_SIZE);
        assert_eq!(out[4], TPM2_PCR_SELECT_MAX as u8);
        assert_eq!(&out[5..8], &[0xDE, 0xAD, 0xBE]);
    }

    // Unmarshalling TpmsTaggedPcrSelect with size_of_select < TPM2_PCR_SELECT_MIN (0, 1, 2) must fail with VALUE.
    for invalid_len in 0..(TPM2_PCR_SELECT_MIN as u8) {
        let mut raw = [0u8; 16];
        // tag = TPM_PT_PCR_SAVE (0x00000000)
        raw[0..4].copy_from_slice(&0u32.to_be_bytes());
        raw[4] = invalid_len;
        let mut reader = &raw[..5 + invalid_len as usize];
        let err = TpmsTaggedPcrSelect::unmarshal(&mut reader).unwrap_err();
        assert_eq!(err, tpm2::errors::UnmarshalError::VALUE);
    }

    // Unmarshalling TpmsTaggedPcrSelect with size_of_select > TPM2_PCR_SELECT_MAX must fail with VALUE.
    for invalid_len in (TPM2_PCR_SELECT_MAX as u8 + 1)..=255 {
        let mut raw = [0u8; 300];
        raw[0..4].copy_from_slice(&0u32.to_be_bytes());
        raw[4] = invalid_len;
        let mut reader = &raw[..5 + invalid_len as usize];
        let err = TpmsTaggedPcrSelect::unmarshal(&mut reader).unwrap_err();
        assert_eq!(err, tpm2::errors::UnmarshalError::VALUE);
    }
}

#[test]
fn test_pcr_selection_truncated_buffers() {
    // If buffer doesn't have enough data to fill sizeof_select (when it is 3), it should fail with INSUFFICIENT.
    let mut buf = [0u8; 10];
    buf[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    buf[2] = TPM2_PCR_SELECT_MAX as u8; // 3

    // Provide fewer than 3 bytes for pcr_select
    for k in 0..TPM2_PCR_SELECT_MAX as usize {
        let mut reader = &buf[..3 + k];
        let err = TpmsPcrSelection::unmarshal(&mut reader).unwrap_err();
        assert_eq!(err, tpm2::errors::UnmarshalError::INSUFFICIENT);
    }

    // Too small buffers for header
    let mut buf = [0u8; 10];
    buf[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    for short_len in 0..3 {
        let mut reader = &buf[..short_len];
        let err = TpmsPcrSelection::unmarshal(&mut reader).unwrap_err();
        assert_eq!(err, tpm2::errors::UnmarshalError::INSUFFICIENT);
    }
}

#[test]
fn test_pcr_selection_fuzz_no_panics() {
    let mut prng = Lcg::new(42);
    for _ in 0..10000 {
        let buf_size = (prng.next_u32() % 21) as usize;
        let mut buf = [0u8; 20];
        prng.next_bytes(&mut buf[..buf_size]);

        let mut reader = &buf[..buf_size];
        let _ = TpmsPcrSelection::unmarshal(&mut reader);
    }
}

#[test]
fn test_tagged_property_and_pcr_select_open_tag_unmarshalling() {
    use tpm2::commands::responses::GetCapability as GetCapabilityRsp;
    use tpm2::{
        TpmPt, TpmPtPcr, TpmlTaggedPcrProperty, TpmlTaggedTpmProperty, TpmsCapabilityData,
        TpmsTaggedPcrSelect, TpmsTaggedProperty,
    };

    // 1. Test TpmsTaggedProperty with newly added spec constants (NONE, FIRMWARE_SVN,
    // FIRMWARE_MAX_SVN, ML_PARAMETER_SETS) and unrecognized vendor/future property tags.
    let props = [
        TpmsTaggedProperty {
            property: TpmPt::NONE,
            value: 0,
        },
        TpmsTaggedProperty {
            property: TpmPt::FIRMWARE_SVN,
            value: 12,
        },
        TpmsTaggedProperty {
            property: TpmPt::FIRMWARE_MAX_SVN,
            value: 64,
        },
        TpmsTaggedProperty {
            property: TpmPt::ML_PARAMETER_SETS,
            value: 0x07,
        },
        TpmsTaggedProperty {
            property: TpmPt::new(0x00000199), // Unrecognized PT_FIXED property
            value: 0x11223344,
        },
        TpmsTaggedProperty {
            property: TpmPt::new(0x00000299), // Unrecognized PT_VAR property
            value: 0x55667788,
        },
        TpmsTaggedProperty {
            property: TpmPt::new(0x80000001), // Vendor-defined property
            value: 0xAABBCCDD,
        },
    ];

    let list = TpmlTaggedTpmProperty::from_slice(&props).unwrap();
    let rsp = GetCapabilityRsp {
        more_data: false,
        capability_data: TpmsCapabilityData::TpmProperties(list),
    };

    let mut buf = [0u8; GetCapabilityRsp::MAX_SIZE];
    let written = rsp.marshal(&mut buf);
    let mut reader = &buf[..written];
    let unmarshaled_rsp = GetCapabilityRsp::unmarshal(&mut reader).unwrap();
    assert!(reader.is_empty());
    assert_eq!(unmarshaled_rsp, rsp);

    // 2. Test TpmsTaggedPcrSelect with extended locality properties (0x0B..=0x10),
    // additional policy/auth sets (0x15..=0x0212), and platform-specific PCR tags.
    let pcr_props = [
        TpmsTaggedPcrSelect {
            tag: TpmPtPcr::new(0x0000000B), // Extended locality attribute
            size_of_select: 3,
            pcr_select: [0x11, 0x22, 0x33],
        },
        TpmsTaggedPcrSelect {
            tag: TpmPtPcr::new(0x00000015), // 2nd TPM_PT_PCR_POLICY set
            size_of_select: 3,
            pcr_select: [0x44, 0x55, 0x66],
        },
        TpmsTaggedPcrSelect {
            tag: TpmPtPcr::new(0x00000213), // Future PCR property
            size_of_select: 3,
            pcr_select: [0x77, 0x88, 0x99],
        },
        TpmsTaggedPcrSelect {
            tag: TpmPtPcr::new(0x80000042), // Platform-specific PCR property
            size_of_select: 3,
            pcr_select: [0xAA, 0xBB, 0xCC],
        },
    ];

    let pcr_list = TpmlTaggedPcrProperty::from_slice(&pcr_props).unwrap();
    let pcr_rsp = GetCapabilityRsp {
        more_data: true,
        capability_data: TpmsCapabilityData::PcrProperties(pcr_list),
    };

    let mut pcr_buf = [0u8; GetCapabilityRsp::MAX_SIZE];
    let pcr_written = pcr_rsp.marshal(&mut pcr_buf);
    let mut pcr_reader = &pcr_buf[..pcr_written];
    let unmarshaled_pcr_rsp = GetCapabilityRsp::unmarshal(&mut pcr_reader).unwrap();
    assert!(pcr_reader.is_empty());
    assert_eq!(unmarshaled_pcr_rsp, pcr_rsp);
    assert!(matches!(
        unmarshaled_pcr_rsp.capability_data,
        TpmsCapabilityData::PcrProperties(_)
    ));
}
