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
fn test_tpms_pcr_selection_bounds() {
    // 1. Check valid size (3)
    let size = TPM2_PCR_SELECT_MAX as usize;
    let selected = vec![0x55u8; size];
    let pcr_sel = TpmsPcrSelection::new(TpmiAlgHash::Sha256, &selected).unwrap();
    assert_eq!(pcr_sel.sizeof_select(), size as u8);
    assert_eq!(pcr_sel.pcr_select(), &selected);

    // Marshal
    let mut buf = [0u8; TpmsPcrSelection::MAX_SIZE];
    let len = pcr_sel.marshal(&mut buf);
    assert_eq!(len, 2 + 1 + size);
    assert_eq!(
        u16::from_be_bytes([buf[0], buf[1]]),
        Alg::from(TpmiAlgHash::Sha256).id()
    );
    assert_eq!(buf[2], size as u8);
    assert_eq!(&buf[3..3 + size], &selected);

    // Unmarshal
    let mut reader = &buf[..len];
    let unmarshaled = TpmsPcrSelection::unmarshal(&mut reader).unwrap();
    assert_eq!(unmarshaled, pcr_sel);
    assert_eq!(reader.len(), 0);

    // 2. Check construction limits (sizeof_select > MAX or < MIN)
    let too_large = [0u8; TpmsPcrSelect::MAX + 1];
    assert!(TpmsPcrSelection::new(TpmiAlgHash::Sha256, &too_large).is_err());
    assert!(TpmsPcrSelect::new(&too_large).is_err());
    let too_small = [0u8; TpmsPcrSelect::MIN - 1];
    assert!(TpmsPcrSelection::new(TpmiAlgHash::Sha256, &too_small).is_err());
    assert!(TpmsPcrSelect::new(&too_small).is_err());

    // 3. Unmarshal outside limits (sizeof_select > TPM2_PCR_SELECT_MAX)
    for invalid_size in (TPM2_PCR_SELECT_MAX as u8 + 1)..=255 {
        let mut buf = [0u8; 300];
        buf[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
        buf[2] = invalid_size;
        let mut reader = &buf[..3 + invalid_size as usize];
        let err = TpmsPcrSelection::unmarshal(&mut reader).unwrap_err();
        assert_eq!(err, tpm2::errors::UnmarshalError::VALUE);
    }
}

#[test]
fn test_tpml_pcr_selection_bounds() {
    // 1. Valid counts (0..=HASH_COUNT)
    for count in 0..=TpmiAlgHash::HASH_COUNT {
        let mut selections = Vec::new();
        for i in 0..count {
            let pcr_sel = TpmsPcrSelection::new(
                TpmiAlgHash::Sha256,
                &vec![i as u8; TPM2_PCR_SELECT_MAX as usize],
            )
            .unwrap();
            selections.push(pcr_sel);
        }
        let list = TpmlPcrSelection::new(&selections).unwrap();
        assert_eq!(list.as_slice().len(), count);
        assert!(
            list.as_slice()
                .iter()
                .copied()
                .eq(selections.iter().copied())
        );

        // Marshal
        let mut buf = [0u8; TpmlPcrSelection::MAX_SIZE];
        let len = list.marshal(&mut buf);

        // Unmarshal
        let mut reader = &buf[..len];
        let unmarshaled = TpmlPcrSelection::unmarshal(&mut reader).unwrap();
        assert_eq!(unmarshaled, list);
        assert_eq!(reader.len(), 0);
    }

    // 2. Check construction limits (count > HASH_COUNT)
    let mut too_many_selections = Vec::new();
    for _ in 0..=TpmiAlgHash::HASH_COUNT {
        too_many_selections.push(TpmsPcrSelection::new(TpmiAlgHash::Sha256, &[0u8; 3]).unwrap());
    }
    assert!(TpmlPcrSelection::new(&too_many_selections).is_none());

    // 3. Unmarshal outside count limits (count > HASH_COUNT)
    for invalid_count in [
        (TpmiAlgHash::HASH_COUNT + 1) as u32,
        (TpmiAlgHash::HASH_COUNT + 2) as u32,
        16,
        17,
        50,
        1000,
        1000000,
    ] {
        let mut buf = Vec::new();
        buf.extend_from_slice(&invalid_count.to_be_bytes());
        for _ in 0..std::cmp::min(invalid_count, 20) {
            buf.extend_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes()); // hash
            buf.push(3); // sizeof_select = 3
            buf.extend_from_slice(&[0u8; 3]);
        }
        let mut reader = buf.as_slice();
        let err = TpmlPcrSelection::unmarshal(&mut reader).unwrap_err();
        assert_eq!(err, tpm2::errors::UnmarshalError::SIZE);
    }
}

#[test]
fn test_tpml_pcr_selection_malformed_elements() {
    // Test when the count is valid, but one of the TpmsPcrSelection inside has invalid size.
    let mut buf = Vec::new();
    buf.extend_from_slice(&2u32.to_be_bytes()); // count = 2

    // Element 0: hash=SHA256, sizeof_select=3, select=[1, 2, 3]
    buf.extend_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    buf.push(3);
    buf.extend_from_slice(&[1, 2, 3]);

    // Element 1: hash=SHA256, sizeof_select=4 (invalid!), select=[1, 2, 3, 4]
    buf.extend_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    buf.push(4);
    buf.extend_from_slice(&[1, 2, 3, 4]);

    let mut reader = buf.as_slice();
    let err = TpmlPcrSelection::unmarshal(&mut reader).unwrap_err();
    assert_eq!(err, tpm2::errors::UnmarshalError::VALUE);
}

#[test]
fn test_pcr_selection_fuzz_never_panics() {
    let mut prng = Lcg::new(1337);
    for _ in 0..20000 {
        let len = (prng.next_u32() % 129) as usize;
        let mut buf = vec![0u8; len];
        prng.next_bytes(&mut buf);

        let mut reader = buf.as_slice();
        let _ = TpmlPcrSelection::unmarshal(&mut reader);
    }
}
