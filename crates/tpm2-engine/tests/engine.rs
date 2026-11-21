use tpm2::commands::{GetRandom, Shutdown, Startup, StirRandom};
use tpm2::crypto::{
    Crypto, CryptoError, Random, Rng,
    backend::{Cmac, Ecc, Hash, Hmac, Mldsa, Mlkem, Rsa, Symmetric},
};
use tpm2::errors::{Position, TpmRc};
use tpm2::{
    CommandHeader, Connection, Marshal, ResponseHeader, Tpm2bDigest, Tpm2bSensitiveData, TpmCc,
    TpmSt, TpmSu, TpmiStCommandTag, Unmarshal,
};
use tpm2_client::protocol::RESP_BUFFER_SIZE;
use tpm2_client::{ClientError, run_command};
use tpm2_engine::platform::{EvictData, IndexData, Platform};
use tpm2_engine::state::State;
use tpm2_engine::{Engine, MAX_COMMAND_SIZE, MAX_RESPONSE_SIZE, ResponseBufferTooSmall};

const NO_SESSIONS: u16 = TpmSt::NO_SESSIONS.id();
const SESSIONS: u16 = TpmSt::SESSIONS.id();

/// Deterministic test RNG configurable for injecting crypto failures.
struct TestRng<const FAIL_FILL: bool, const FAIL_STIR: bool> {
    state: u8,
}

impl<const FAIL_FILL: bool, const FAIL_STIR: bool> Rng for TestRng<FAIL_FILL, FAIL_STIR> {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), CryptoError> {
        if FAIL_FILL {
            return Err(CryptoError::Internal);
        }
        for byte in out {
            self.state = self.state.wrapping_add(1);
            *byte = self.state;
        }
        Ok(())
    }

    fn stir_bytes(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if FAIL_STIR {
            return Err(CryptoError::Internal);
        }
        for &byte in data {
            self.state = self.state.wrapping_add(byte ^ 0x5A);
        }
        Ok(())
    }
}

/// Minimal `Crypto` backend whose algorithm families are unbound (`!`) and
/// whose RNG behavior is controlled via const generics.
struct TestCrypto<const FAIL_INIT: bool, const FAIL_FILL: bool, const FAIL_STIR: bool>;

impl<const FI: bool, const FF: bool, const FS: bool> Random for TestCrypto<FI, FF, FS> {
    type Rng = TestRng<FF, FS>;

    fn from_entropy() -> Result<Self::Rng, CryptoError> {
        if FI {
            return Err(CryptoError::Internal);
        }
        Ok(TestRng { state: 0 })
    }

    fn from_seed(seed: &[u8]) -> Result<Self::Rng, CryptoError> {
        let state = seed.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        Ok(TestRng { state })
    }
}

impl<const FI: bool, const FF: bool, const FS: bool> Hash for TestCrypto<FI, FF, FS> {
    type Sha1 = !;
    type Sha256 = !;
    type Sha384 = !;
    type Sha512 = !;
    type Sm3_256 = !;
    type Sha3_256 = !;
    type Sha3_384 = !;
    type Sha3_512 = !;
}

impl<const FI: bool, const FF: bool, const FS: bool> Hmac for TestCrypto<FI, FF, FS> {
    type Sha1 = !;
    type Sha256 = !;
    type Sha384 = !;
    type Sha512 = !;
    type Sm3_256 = !;
    type Sha3_256 = !;
    type Sha3_384 = !;
    type Sha3_512 = !;
}

impl<const FI: bool, const FF: bool, const FS: bool> Cmac for TestCrypto<FI, FF, FS> {
    type Aes128 = !;
    type Aes192 = !;
    type Aes256 = !;
    type Sm4_128 = !;
    type Camellia128 = !;
    type Camellia192 = !;
    type Camellia256 = !;
}

impl<const FI: bool, const FF: bool, const FS: bool> Symmetric for TestCrypto<FI, FF, FS> {
    type Aes128 = !;
    type Aes192 = !;
    type Aes256 = !;
    type Sm4_128 = !;
    type Camellia128 = !;
    type Camellia192 = !;
    type Camellia256 = !;
}

impl<const FI: bool, const FF: bool, const FS: bool> Rsa for TestCrypto<FI, FF, FS> {
    type Rsa1024 = !;
    type Rsa2048 = !;
    type Rsa3072 = !;
    type Rsa4096 = !;
}

impl<const FI: bool, const FF: bool, const FS: bool> Ecc for TestCrypto<FI, FF, FS> {
    type NistP192 = !;
    type NistP224 = !;
    type NistP256 = !;
    type NistP384 = !;
    type NistP521 = !;
    type BNP256 = !;
    type BNP638 = !;
    type SM2P256 = !;
    type BpP256R1 = !;
    type BpP384R1 = !;
    type BpP512R1 = !;
    type Ed25519 = !;
    type Ed448 = !;
    type X25519 = !;
    type X448 = !;
}

impl<const FI: bool, const FF: bool, const FS: bool> Mldsa for TestCrypto<FI, FF, FS> {
    type Mldsa44 = !;
    type Mldsa65 = !;
    type Mldsa87 = !;
}

impl<const FI: bool, const FF: bool, const FS: bool> Mlkem for TestCrypto<FI, FF, FS> {
    type Mlkem512 = !;
    type Mlkem768 = !;
    type Mlkem1024 = !;
}

impl<const FI: bool, const FF: bool, const FS: bool> Crypto for TestCrypto<FI, FF, FS> {
    fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        a == b
    }
}

#[derive(Default)]
struct TestIndexState {
    marker: u32,
}

impl IndexData for TestIndexState {}

#[derive(Default)]
struct TestEvictData;

impl EvictData for TestEvictData {}

struct TestPlatform<const FI: bool = false, const FF: bool = false, const FS: bool = false>;

impl<const FI: bool, const FF: bool, const FS: bool> Platform for TestPlatform<FI, FF, FS> {
    type Crypto = TestCrypto<FI, FF, FS>;
    type IndexData = TestIndexState;
    type EvictData = TestEvictData;
}

type OkPlatform = TestPlatform<false, false, false>;

fn parse_error_response(rsp: &[u8]) -> TpmRc {
    assert_eq!(rsp.len(), ResponseHeader::MAX_SIZE);
    let mut cursor = rsp;
    let hdr = ResponseHeader::unmarshal(&mut cursor).unwrap();
    assert!(cursor.is_empty());
    assert_eq!(hdr.tag, TpmiStCommandTag::NoSessions);
    assert_eq!(hdr.size, ResponseHeader::MAX_SIZE as u32);
    hdr.rc.unwrap_err()
}

fn raw_cmd(tag: u16, size: u32, code: TpmCc, params: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(CommandHeader::MAX_SIZE + params.len());
    buf.extend_from_slice(&tag.to_be_bytes());
    buf.extend_from_slice(&size.to_be_bytes());
    buf.extend_from_slice(&code.code().to_be_bytes());
    buf.extend_from_slice(params);
    buf
}

fn startup_clear(engine: &mut Engine<'_, OkPlatform>) {
    let mut rsp = [0u8; RESP_BUFFER_SIZE];
    run_command(
        &Startup {
            startup_type: TpmSu::Clear,
        },
        engine,
        &mut rsp,
    )
    .unwrap();
}

#[test]
fn commands_before_startup_are_rejected() {
    let mut platform = OkPlatform {};
    let mut state = State::<OkPlatform>::default();
    let mut engine = Engine::init(&mut platform, &mut state);
    let mut rsp = [0u8; RESP_BUFFER_SIZE];

    assert_eq!(
        run_command(&GetRandom { bytes_requested: 8 }, &mut engine, &mut rsp,),
        Err(ClientError::Tpm(TpmRc::INITIALIZE))
    );
    assert_eq!(
        run_command(
            &StirRandom {
                in_data: Tpm2bSensitiveData::new(b"abc").unwrap(),
            },
            &mut engine,
            &mut rsp,
        ),
        Err(ClientError::Tpm(TpmRc::INITIALIZE))
    );
    assert_eq!(
        run_command(
            &Shutdown {
                shutdown_type: TpmSu::Clear,
            },
            &mut engine,
            &mut rsp,
        ),
        Err(ClientError::Tpm(TpmRc::INITIALIZE))
    );

    // Before Startup, every other command code (even an unimplemented one) is INITIALIZE.
    let mut fixed_rsp = [0u8; MAX_RESPONSE_SIZE];
    for code in [TpmCc::ReadClock, TpmCc::new(0xFFFF_FFFF)] {
        let unknown = raw_cmd(NO_SESSIONS, 10, code, &[]);
        let out = engine.execute_command(&unknown, &mut fixed_rsp);
        assert_eq!(parse_error_response(out), TpmRc::INITIALIZE);
    }
}

#[test]
fn startup_reset_restart_and_resume_lifecycle() {
    let mut platform = OkPlatform {};
    let mut state = State::<OkPlatform>::default();
    state.nv.index.marker = 7;
    let mut rsp = [0u8; RESP_BUFFER_SIZE];

    // Cold boot: Startup(State) rejected without clearing awaiting state.
    {
        let mut engine = Engine::init(&mut platform, &mut state);
        assert_eq!(
            run_command(
                &Startup {
                    startup_type: TpmSu::State,
                },
                &mut engine,
                &mut rsp,
            ),
            Err(ClientError::Tpm(TpmRc::VALUE.with(Position::parameter(1))))
        );
        assert!(engine.state().failure.is_none());

        // Wire-level Startup(Clear) writes a 10-byte success header.
        let startup_wire = raw_cmd(NO_SESSIONS, 12, TpmCc::Startup, &[0, 0]);
        let mut startup_rsp = [0xFFu8; MAX_RESPONSE_SIZE];
        let out = engine.execute_command(&startup_wire, &mut startup_rsp);
        assert_eq!(out, b"\x80\x01\x00\x00\x00\x0a\x00\x00\x00\x00");

        assert_eq!(engine.state().nv.persistent.reset_count, 1);
        assert_eq!(engine.state().nv.persistent.total_reset_count, 1);
        assert_eq!(engine.state().nv.persistent.orderly_state, None);
        assert_eq!(engine.state().nv.reset.restart_count, 0);
        assert_eq!(engine.state().nv.reset.clear_count, 0);

        // Second Startup after already started fails with INITIALIZE.
        assert_eq!(
            run_command(
                &Startup {
                    startup_type: TpmSu::Clear,
                },
                &mut engine,
                &mut rsp,
            ),
            Err(ClientError::Tpm(TpmRc::INITIALIZE))
        );

        // Shutdown(State) keeps TPM started; Startup without _TPM_Init still fails.
        run_command(
            &Shutdown {
                shutdown_type: TpmSu::State,
            },
            &mut engine,
            &mut rsp,
        )
        .unwrap();
        assert_eq!(
            engine.state().nv.persistent.orderly_state,
            Some(TpmSu::State)
        );
        assert_eq!(
            run_command(
                &Startup {
                    startup_type: TpmSu::State,
                },
                &mut engine,
                &mut rsp,
            ),
            Err(ClientError::Tpm(TpmRc::INITIALIZE))
        );
        // GetRandom does not nullify `orderly_state` (matching the reference implementation).
        let gr = run_command(&GetRandom { bytes_requested: 4 }, &mut engine, &mut rsp).unwrap();
        assert_eq!(gr.random_bytes.as_slice(), &[1, 2, 3, 4]);
    }

    // Boot 2: TPM Resume (Shutdown(State) -> _TPM_Init -> Startup(State)).
    {
        let mut engine = Engine::init(&mut platform, &mut state);
        assert_eq!(engine.state().nv.index.marker, 7);
        run_command(
            &Startup {
                startup_type: TpmSu::State,
            },
            &mut engine,
            &mut rsp,
        )
        .unwrap();
        assert_eq!(engine.state().nv.persistent.reset_count, 1);
        assert_eq!(engine.state().nv.persistent.total_reset_count, 1);
        assert_eq!(engine.state().nv.persistent.orderly_state, None);
        assert_eq!(engine.state().nv.reset.restart_count, 1);
        assert_eq!(engine.state().nv.reset.clear_count, 0);

        // RNG was re-instantiated at Startup, not carried across _TPM_Init.
        let gr = run_command(&GetRandom { bytes_requested: 2 }, &mut engine, &mut rsp).unwrap();
        assert_eq!(gr.random_bytes.as_slice(), &[1, 2]);

        run_command(
            &Shutdown {
                shutdown_type: TpmSu::State,
            },
            &mut engine,
            &mut rsp,
        )
        .unwrap();
    }

    // Boot 3: TPM Restart (Shutdown(State) -> _TPM_Init -> Startup(Clear)).
    {
        let mut engine = Engine::init(&mut platform, &mut state);
        startup_clear(&mut engine);
        assert_eq!(engine.state().nv.persistent.reset_count, 1);
        assert_eq!(engine.state().nv.persistent.total_reset_count, 1);
        assert_eq!(engine.state().nv.persistent.orderly_state, None);
        assert_eq!(engine.state().nv.reset.restart_count, 2);
        assert_eq!(engine.state().nv.reset.clear_count, 1);

        // Shutdown(State) overwritten by Shutdown(Clear).
        run_command(
            &Shutdown {
                shutdown_type: TpmSu::State,
            },
            &mut engine,
            &mut rsp,
        )
        .unwrap();
        run_command(
            &Shutdown {
                shutdown_type: TpmSu::Clear,
            },
            &mut engine,
            &mut rsp,
        )
        .unwrap();
        assert_eq!(
            engine.state().nv.persistent.orderly_state,
            Some(TpmSu::Clear)
        );
    }

    // Boot 4: Startup(State) after Shutdown(Clear) fails and preserves orderly_state.
    {
        let mut engine = Engine::init(&mut platform, &mut state);
        assert_eq!(
            run_command(
                &Startup {
                    startup_type: TpmSu::State,
                },
                &mut engine,
                &mut rsp,
            ),
            Err(ClientError::Tpm(TpmRc::VALUE.with(Position::parameter(1))))
        );
        assert_eq!(
            engine.state().nv.persistent.orderly_state,
            Some(TpmSu::Clear)
        );

        // Startup(Clear) performs TPM Reset and clears restart/clear counters.
        startup_clear(&mut engine);
        assert_eq!(engine.state().nv.persistent.reset_count, 2);
        assert_eq!(engine.state().nv.persistent.total_reset_count, 2);
        assert_eq!(engine.state().nv.reset.restart_count, 0);
        assert_eq!(engine.state().nv.reset.clear_count, 0);
        assert_eq!(engine.state().nv.persistent.orderly_state, None);
    }

    // Boot 5: Unorderly reset (no prior Shutdown) -> Startup(Clear) resets again.
    {
        let mut engine = Engine::init(&mut platform, &mut state);
        startup_clear(&mut engine);
        assert_eq!(engine.state().nv.persistent.reset_count, 3);
        assert_eq!(engine.state().nv.persistent.total_reset_count, 3);
        assert_eq!(engine.state().nv.index.marker, 7);
    }
}

#[test]
fn get_random_wire_format_and_bounds() {
    let mut platform = OkPlatform {};
    let mut state = State::<OkPlatform>::default();
    let mut engine = Engine::init(&mut platform, &mut state);
    startup_clear(&mut engine);

    // Zero-length request produces an empty TPM2B_DIGEST without advancing RNG.
    let mut rsp = [0u8; RESP_BUFFER_SIZE];
    let out = run_command(&GetRandom { bytes_requested: 0 }, &mut engine, &mut rsp).unwrap();
    assert_eq!(out.random_bytes.as_slice(), &[]);

    // Exact wire-format check for 12 bytes (10-byte header + 2-byte size + 12 bytes = 24 = 0x18).
    let req = b"\x80\x01\x00\x00\x00\x0c\x00\x00\x01\x7b\x00\x0c";
    let expected = b"\
        \x80\x01\
        \x00\x00\x00\x18\
        \x00\x00\x00\x00\
        \x00\x0c\
        \x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c";
    let mut fixed_rsp = [0xFFu8; MAX_RESPONSE_SIZE];
    let slice = engine.transact(req, &mut fixed_rsp).unwrap();
    assert_eq!(slice, expected);

    // Oversized requests clamp to Tpm2bDigest::CAP and advance monotonically.
    let mut expected_next = 0x0Du8;
    for req_len in [Tpm2bDigest::CAP as u16, 0x0FFF, u16::MAX] {
        let out = run_command(
            &GetRandom {
                bytes_requested: req_len,
            },
            &mut engine,
            &mut rsp,
        )
        .unwrap();
        let bytes = out.random_bytes.as_slice();
        assert_eq!(bytes.len(), Tpm2bDigest::CAP);
        for &b in bytes {
            assert_eq!(b, expected_next);
            expected_next = expected_next.wrapping_add(1);
        }
    }
}

#[test]
fn stir_random_updates_rng_state() {
    let mut platform = OkPlatform {};
    let mut state = State::<OkPlatform>::default();
    let mut engine = Engine::init(&mut platform, &mut state);
    startup_clear(&mut engine);
    let mut rsp = [0u8; RESP_BUFFER_SIZE];

    // Empty stir is permitted (a real DRBG reseeds with fresh entropy; TestRng leaves state as-is).
    run_command(
        &StirRandom {
            in_data: Tpm2bSensitiveData::new(&[]).unwrap(),
        },
        &mut engine,
        &mut rsp,
    )
    .unwrap();
    let before = run_command(&GetRandom { bytes_requested: 2 }, &mut engine, &mut rsp).unwrap();
    assert_eq!(before.random_bytes.as_slice(), &[1, 2]);

    // Non-empty stir alters subsequent GetRandom bytes.
    run_command(
        &StirRandom {
            in_data: Tpm2bSensitiveData::new(&[0x00]).unwrap(),
        },
        &mut engine,
        &mut rsp,
    )
    .unwrap();
    // TestRng adds (0x00 ^ 0x5A) == 0x5A to state (2 -> 0x5C), next draw starts at 0x5D.
    let after = run_command(&GetRandom { bytes_requested: 2 }, &mut engine, &mut rsp).unwrap();
    assert_eq!(after.random_bytes.as_slice(), &[0x5D, 0x5E]);

    // Maximum-size stir (128 bytes == Tpm2bSensitiveData::CAP) succeeds.
    let max_data = [0x5Au8; Tpm2bSensitiveData::CAP];
    run_command(
        &StirRandom {
            in_data: Tpm2bSensitiveData::new(&max_data).unwrap(),
        },
        &mut engine,
        &mut rsp,
    )
    .unwrap();
}

#[test]
fn transact_rejects_too_small_response_buffers() {
    let mut platform = OkPlatform {};
    let mut state = State::<OkPlatform>::default();
    let mut engine = Engine::init(&mut platform, &mut state);
    startup_clear(&mut engine);

    let req = raw_cmd(NO_SESSIONS, 12, TpmCc::GetRandom, &4u16.to_be_bytes());

    // Any buffer smaller than `MAX_RESPONSE_SIZE` fails before execution without advancing RNG.
    assert_eq!(engine.transact(&req, &mut []), Err(ResponseBufferTooSmall));
    let mut short = [0u8; MAX_RESPONSE_SIZE - 1];
    assert_eq!(
        engine.transact(&req, &mut short),
        Err(ResponseBufferTooSmall)
    );

    // A `MAX_RESPONSE_SIZE` buffer succeeds and starts from the very first RNG byte.
    let mut full = [0u8; MAX_RESPONSE_SIZE];
    let out = engine.transact(&req, &mut full).unwrap();
    assert_eq!(&out[ResponseHeader::MAX_SIZE..], &[0x00, 0x04, 1, 2, 3, 4]);
}

#[test]
fn header_validation_errors_and_precedence() {
    let mut platform = OkPlatform {};
    let mut state = State::<OkPlatform>::default();
    let mut engine = Engine::init(&mut platform, &mut state);
    let mut rsp = [0u8; MAX_RESPONSE_SIZE];

    // Truncated tag (0–1 bytes) and truncated size (2–5 bytes) return INSUFFICIENT.
    for cmd in [
        &b""[..],
        &b"\x80"[..],
        &b"\x80\x01"[..],
        &b"\x80\x01\x00\x00\x00"[..],
    ] {
        let out = engine.execute_command(cmd, &mut rsp);
        assert_eq!(parse_error_response(out), TpmRc::INSUFFICIENT.to_rc());
    }

    // Invalid command tag (both < 0x8000 and >= 0x8000) returns BAD_TAG (0x01E).
    for bad_tag in [0x0000u16, 0x1234, TpmSt::NULL.id(), 0x8003, u16::MAX] {
        let cmd = raw_cmd(bad_tag, 10, TpmCc::Startup, &[]);
        assert_eq!(
            parse_error_response(engine.execute_command(&cmd, &mut rsp)),
            TpmRc::BAD_TAG
        );
    }

    // Truncated header (6–9 bytes): mismatched size checks before CC -> COMMAND_SIZE.
    let short_mismatch = b"\x80\x01\x00\x00\x00\x0a\x00\x00\x01";
    assert_eq!(
        parse_error_response(engine.execute_command(short_mismatch, &mut rsp)),
        TpmRc::COMMAND_SIZE
    );
    // Matching 6-byte size cannot unmarshal command code -> INSUFFICIENT.
    let short_matching = b"\x80\x01\x00\x00\x00\x06";
    assert_eq!(
        parse_error_response(engine.execute_command(short_matching, &mut rsp)),
        TpmRc::INSUFFICIENT.to_rc()
    );

    // Full header with size mismatch wins over unimplemented command code.
    let wrong_size_unknown_cc = raw_cmd(NO_SESSIONS, 99, TpmCc::ReadClock, &[]);
    assert_eq!(
        parse_error_response(engine.execute_command(&wrong_size_unknown_cc, &mut rsp)),
        TpmRc::COMMAND_SIZE
    );
    let wrong_size_lo = raw_cmd(NO_SESSIONS, 10, TpmCc::Startup, &[0, 0]);
    assert_eq!(
        parse_error_response(engine.execute_command(&wrong_size_lo, &mut rsp)),
        TpmRc::COMMAND_SIZE
    );

    // Sessions rejected on Startup with AUTH_CONTEXT.
    let startup_sess = raw_cmd(SESSIONS, 12, TpmCc::Startup, &[0, 0]);
    assert_eq!(
        parse_error_response(engine.execute_command(&startup_sess, &mut rsp)),
        TpmRc::AUTH_CONTEXT
    );

    // Before Startup, GetRandom with sessions hits INITIALIZE before AUTH_CONTEXT.
    let pre_startup_sess = raw_cmd(SESSIONS, 12, TpmCc::GetRandom, &[0, 4]);
    assert_eq!(
        parse_error_response(engine.execute_command(&pre_startup_sess, &mut rsp)),
        TpmRc::INITIALIZE
    );

    startup_clear(&mut engine);

    // Unimplemented command code fails after startup.
    let unimpl = raw_cmd(NO_SESSIONS, 10, TpmCc::ReadClock, &[]);
    assert_eq!(
        parse_error_response(engine.execute_command(&unimpl, &mut rsp)),
        TpmRc::COMMAND_CODE
    );

    // Startup with sessions while already started hits INITIALIZE first.
    let post_startup_sess = raw_cmd(SESSIONS, 12, TpmCc::Startup, &[0, 0]);
    assert_eq!(
        parse_error_response(engine.execute_command(&post_startup_sess, &mut rsp)),
        TpmRc::INITIALIZE
    );

    // Temporary: until session handling is implemented, all commands reject TPM_ST_SESSIONS.
    for code in [TpmCc::Shutdown, TpmCc::GetRandom, TpmCc::StirRandom] {
        let sess_cmd = raw_cmd(SESSIONS, 12, code, &[0, 0]);
        assert_eq!(
            parse_error_response(engine.execute_command(&sess_cmd, &mut rsp)),
            TpmRc::AUTH_CONTEXT
        );
    }
}

#[test]
fn failure_mode_on_rng_init_error_across_startup_kinds() {
    type FailInitPlatform = TestPlatform<true, false, false>;
    let mut platform = FailInitPlatform {};
    let mut rsp = [0u8; RESP_BUFFER_SIZE];

    // Check Reset, Restart, and Resume paths all latch failure mode without partial NV updates.
    for (prev_orderly, startup_type) in [
        (Some(TpmSu::Clear), TpmSu::Clear), // Reset
        (Some(TpmSu::State), TpmSu::Clear), // Restart
        (Some(TpmSu::State), TpmSu::State), // Resume
    ] {
        let mut state = State::<FailInitPlatform>::default();
        state.nv.persistent.orderly_state = prev_orderly;
        state.nv.persistent.reset_count = 3;
        state.nv.persistent.total_reset_count = 5;
        state.nv.reset.restart_count = 2;
        state.nv.reset.clear_count = 1;

        let mut engine = Engine::init(&mut platform, &mut state);
        assert_eq!(
            run_command(&Startup { startup_type }, &mut engine, &mut rsp),
            Err(ClientError::Tpm(TpmRc::FAILURE))
        );
        assert!(engine.state().failure.is_some());
        assert_eq!(engine.state().nv.persistent.orderly_state, prev_orderly);
        assert_eq!(engine.state().nv.persistent.reset_count, 3);
        assert_eq!(engine.state().nv.persistent.total_reset_count, 5);
        assert_eq!(engine.state().nv.reset.restart_count, 2);
        assert_eq!(engine.state().nv.reset.clear_count, 1);

        // Sticky: every subsequent command (even empty or valid Startup) returns FAILURE.
        let mut fixed_rsp = [0u8; MAX_RESPONSE_SIZE];
        assert_eq!(
            parse_error_response(engine.execute_command(&[], &mut fixed_rsp)),
            TpmRc::FAILURE
        );
        assert_eq!(
            run_command(&Startup { startup_type }, &mut engine, &mut rsp),
            Err(ClientError::Tpm(TpmRc::FAILURE))
        );
    }
}

#[test]
fn failure_mode_on_get_random_and_recovery_via_init() {
    type FailFillPlatform = TestPlatform<false, true, false>;
    let mut platform = FailFillPlatform {};
    let mut state = State::<FailFillPlatform>::default();
    let mut rsp = [0u8; RESP_BUFFER_SIZE];

    {
        let mut engine = Engine::init(&mut platform, &mut state);
        run_command(
            &Startup {
                startup_type: TpmSu::Clear,
            },
            &mut engine,
            &mut rsp,
        )
        .unwrap();

        // GetRandom(0) does not call `fill_bytes`, so it succeeds.
        let empty = run_command(&GetRandom { bytes_requested: 0 }, &mut engine, &mut rsp).unwrap();
        assert!(empty.random_bytes.as_slice().is_empty());

        // Non-zero GetRandom enters sticky failure mode.
        assert_eq!(
            run_command(&GetRandom { bytes_requested: 4 }, &mut engine, &mut rsp),
            Err(ClientError::Tpm(TpmRc::FAILURE))
        );
        assert!(engine.state().failure.is_some());
        assert_eq!(
            run_command(
                &Shutdown {
                    shutdown_type: TpmSu::Clear,
                },
                &mut engine,
                &mut rsp,
            ),
            Err(ClientError::Tpm(TpmRc::FAILURE))
        );
    }

    // Re-running `_TPM_Init` exits failure mode while preserving NV.
    let mut engine = Engine::init(&mut platform, &mut state);
    assert!(engine.state().failure.is_none());
    assert_eq!(engine.state().nv.persistent.reset_count, 1);
    run_command(
        &Startup {
            startup_type: TpmSu::Clear,
        },
        &mut engine,
        &mut rsp,
    )
    .unwrap();
    assert!(engine.state().failure.is_none());
    assert_eq!(engine.state().nv.persistent.reset_count, 2);
}

#[test]
fn failure_mode_on_stir_random() {
    type FailStirPlatform = TestPlatform<false, false, true>;
    let mut platform = FailStirPlatform {};
    let mut state = State::<FailStirPlatform>::default();
    let mut rsp = [0u8; RESP_BUFFER_SIZE];

    let mut engine = Engine::init(&mut platform, &mut state);
    run_command(
        &Startup {
            startup_type: TpmSu::Clear,
        },
        &mut engine,
        &mut rsp,
    )
    .unwrap();

    assert_eq!(
        run_command(
            &StirRandom {
                in_data: Tpm2bSensitiveData::new(b"seed").unwrap(),
            },
            &mut engine,
            &mut rsp,
        ),
        Err(ClientError::Tpm(TpmRc::FAILURE))
    );
    assert!(engine.state().failure.is_some());
    assert_eq!(
        run_command(&GetRandom { bytes_requested: 4 }, &mut engine, &mut rsp),
        Err(ClientError::Tpm(TpmRc::FAILURE))
    );
}

#[test]
fn total_reset_count_overflow_enters_failure_mode() {
    let mut platform = OkPlatform {};
    let mut state = State::<OkPlatform>::default();
    state.nv.persistent.total_reset_count = u64::MAX;
    state.nv.persistent.reset_count = 10;
    let mut rsp = [0u8; RESP_BUFFER_SIZE];

    // Overflow causes FAILURE and leaves total_reset_count at u64::MAX.
    {
        let mut engine = Engine::init(&mut platform, &mut state);
        assert_eq!(
            run_command(
                &Startup {
                    startup_type: TpmSu::Clear,
                },
                &mut engine,
                &mut rsp,
            ),
            Err(ClientError::Tpm(TpmRc::FAILURE))
        );
        assert!(engine.state().failure.is_some());
        assert_eq!(engine.state().nv.persistent.total_reset_count, u64::MAX);
        assert_eq!(engine.state().nv.persistent.reset_count, 10);
    }
}

#[test]
fn max_sizes() {
    assert_eq!(
        MAX_COMMAND_SIZE,
        CommandHeader::MAX_SIZE + StirRandom::MAX_SIZE
    );
    assert_eq!(
        MAX_RESPONSE_SIZE,
        ResponseHeader::MAX_SIZE + Tpm2bDigest::MAX_SIZE
    );
}

#[test]
fn parameter_validation_errors() {
    let mut platform = OkPlatform {};
    let mut state = State::<OkPlatform>::default();
    let mut engine = Engine::init(&mut platform, &mut state);
    let mut rsp = [0u8; MAX_RESPONSE_SIZE];

    // Parameters that fail to unmarshal return INSUFFICIENT (for now).
    let truncated = raw_cmd(NO_SESSIONS, 11, TpmCc::Startup, &[0]);
    assert_eq!(
        parse_error_response(engine.execute_command(&truncated, &mut rsp)),
        TpmRc::INSUFFICIENT.to_rc()
    );
    // Trailing bytes after the parameters return SIZE.
    let trailing = raw_cmd(NO_SESSIONS, 13, TpmCc::Startup, &[0, 0, 0xFF]);
    assert_eq!(
        parse_error_response(engine.execute_command(&trailing, &mut rsp)),
        TpmRc::SIZE.to_rc()
    );

    startup_clear(&mut engine);

    let trailing = raw_cmd(NO_SESSIONS, 13, TpmCc::GetRandom, &[0, 4, 0]);
    assert_eq!(
        parse_error_response(engine.execute_command(&trailing, &mut rsp)),
        TpmRc::SIZE.to_rc()
    );

    // StirRandom with more than 128 bytes (and so more than MAX_COMMAND_SIZE).
    let mut params = vec![0xAA; 2 + Tpm2bSensitiveData::CAP + 1];
    params[..2].copy_from_slice(&((Tpm2bSensitiveData::CAP + 1) as u16).to_be_bytes());
    let oversized = raw_cmd(
        NO_SESSIONS,
        (CommandHeader::MAX_SIZE + params.len()) as u32,
        TpmCc::StirRandom,
        &params,
    );
    assert_eq!(
        parse_error_response(engine.execute_command(&oversized, &mut rsp)),
        TpmRc::INSUFFICIENT.to_rc()
    );
}
