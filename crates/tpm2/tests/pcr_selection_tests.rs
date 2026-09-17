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
    let len = TpmsPcrSelect::MAX;
    let mut pcr_select_data = [0u8; TpmsPcrSelect::MAX];
    for (i, val) in pcr_select_data.iter_mut().enumerate() {
        *val = i as u8 + 1;
    }
    let selection = TpmsPcrSelect::new(&pcr_select_data).unwrap();
    assert_eq!(selection.pcrs(), &pcr_select_data);
    let sel = TpmsPcrSelection {
        hash: TpmiAlgHash::Sha256,
        selection,
    };

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
    // Constructing with length > MAX or < MIN must fail.
    let too_large_data = [1; TpmsPcrSelect::MAX + 1];
    assert!(TpmsPcrSelect::new(&too_large_data).is_none());
    let too_small_data = [1; TpmsPcrSelect::MIN - 1];
    assert!(TpmsPcrSelect::new(&too_small_data).is_none());

    // Unmarshalling a buffer with sizeof_select > TpmsPcrSelect::MAX must fail.
    for invalid_len in (TpmsPcrSelect::MAX as u8 + 1)..=255 {
        let mut buf = [0u8; 300];
        buf[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
        buf[2] = invalid_len;
        let mut reader = &buf[..3 + invalid_len as usize];
        let err = TpmsPcrSelection::unmarshal(&mut reader).unwrap_err();
        assert_eq!(err, tpm2::errors::UnmarshalError);
    }
}

#[test]
fn test_pcr_selection_truncated_buffers() {
    // If buffer doesn't have enough data to fill sizeof_select (when it is 3), it should fail.
    let mut buf = [0u8; 10];
    buf[0..2].copy_from_slice(&Alg::from(TpmiAlgHash::Sha256).id().to_be_bytes());
    buf[2] = TpmsPcrSelect::MIN as u8; // 3

    // Provide fewer than 3 bytes for pcr_select
    for k in 0..TpmsPcrSelect::MIN {
        let mut reader = &buf[..3 + k];
        let err = TpmsPcrSelection::unmarshal(&mut reader).unwrap_err();
        assert_eq!(err, tpm2::errors::UnmarshalError);
    }

    // Too small buffers for header
    let buf = [0u8; 10];
    for short_len in 0..3 {
        let mut reader = &buf[..short_len];
        let err = TpmsPcrSelection::unmarshal(&mut reader).unwrap_err();
        assert_eq!(err, tpm2::errors::UnmarshalError);
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
