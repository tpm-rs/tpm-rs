//! Saved contexts handed back and forth between `tpm-rs` and the C reference TPM of the target:
//! an object, hash/HMAC/event sequences and a policy session are saved by one TPM, loaded by the
//! other, used there, saved again and handed back, several times, and both TPMs continue to work
//! with them. `tpm-rs` saves the contexts of the C references byte for byte, so each TPM loads the
//! other's contexts.
//!
//! The two TPMs are separate (the `tpm-rs` side is not mirrored, the reference is driven through
//! uncompared `Execute` requests, `Reference::execute`), but share one seed, so they have the same
//! primary seeds and hierarchy proofs, which protect the contexts.
#![cfg(feature = "differential")]
// `TPM2_Sign` (`tpm2::commands::Sign`) is deprecated in favor of the digest-signing commands.
#![allow(deprecated)]

use crate::_common::{build_cmd, expected_hmac, password_auth, unmarshal_response};
use testing::differential::{Implementation, Reference};
use testing::seed::ReferenceSeed;
use testing::tpm::Tpm;
use tpm2::commands::{
    ContextLoad, ContextSave, CreatePrimary, EventSequenceComplete, FlushContext, GetRandom, HMAC,
    HMACStart, HashSequenceStart, PolicyAuthValue, PolicyCommandCode, PolicyGetDigest,
    PolicyPassword, ReadPublic, SequenceComplete, SequenceUpdate, Sign, StartAuthSession,
};
use tpm2::{
    Command, Handle, Marshal, PublicParmsAndId, Tpm2bAuth, Tpm2bDigest, Tpm2bMaxBuffer, Tpm2bNonce,
    Tpm2bPublicKeyRsa, Tpm2bSensitiveData, TpmCc, TpmSe, TpmaObject, TpmiAlgHash, TpmiRsaKeyBits,
    TpmsAuthCommand, TpmsContext, TpmsRsaParms, TpmsSensitiveCreate, TpmtKeyedHashScheme,
    TpmtPublic, TpmtRsaScheme, TpmtTkHashcheck,
};

/// `TPM_RC_RETRY` (a warning).
const TPM_RC_RETRY: u32 = 0x0000_0922;

/// Which of the two TPMs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    /// `tpm-rs`.
    Rs,
    /// The C reference TPM of the target.
    C,
}

impl Side {
    /// The other TPM.
    fn other(self) -> Self {
        match self {
            Side::Rs => Side::C,
            Side::C => Side::Rs,
        }
    }
}

/// A `tpm-rs` TPM and a C reference TPM with the same seed, driven separately.
struct Pair {
    rs: Tpm,
    c: Reference,
}

impl Pair {
    /// A new `tpm-rs` TPM and a new C reference TPM of the target with one seed (both
    /// powered on and started, like a new `Tpm`).
    fn new() -> Self {
        let seed = ReferenceSeed::choose();
        Self {
            rs: Tpm::with_seed_unmirrored(seed),
            c: Reference::launch(Implementation::TARGET, seed),
        }
    }

    /// Sends the raw command `cmd` to `side` and returns its response. The C reference answers
    /// the first DA-protected authorization after a boot with the `TPM_RC_RETRY` warning while
    /// it records `daUsed` in NV (`tpm-rs` records it inline; see the differential harness's
    /// `TPM_RC_RETRY` rule): like a TSS, the command is then re-issued once.
    fn raw(&mut self, side: Side, cmd: &[u8]) -> Vec<u8> {
        match side {
            Side::Rs => self.rs.send_command(cmd),
            Side::C => {
                let rsp = self.c.execute(cmd);
                if rsp.get(6..10) == Some(&TPM_RC_RETRY.to_be_bytes()[..]) {
                    self.c.execute(cmd)
                } else {
                    rsp
                }
            }
        }
    }

    /// Executes `cmd` with the authorization sessions `auths` on `side`, which must succeed,
    /// and returns its response.
    fn run<C: Command>(
        &mut self,
        side: Side,
        cmd: &C,
        auths: &[TpmsAuthCommand<'_>],
    ) -> C::Response<'static>
    where
        for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    {
        let rsp = self.raw(side, &build_cmd(cmd, auths));
        let rc = u32::from_be_bytes(rsp[6..10].try_into().unwrap());
        assert_eq!(rc, 0, "{:?} on {side:?} failed: {rc:#x}", C::CMD_CODE);
        unmarshal_response::<C>(&rsp).unwrap()
    }

    /// Executes `cmd` on both TPMs, which must give the same (successful) response, and returns
    /// it.
    fn both<C: Command>(&mut self, cmd: &C, auths: &[TpmsAuthCommand<'_>]) -> C::Response<'static>
    where
        for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
    {
        let bytes = build_cmd(cmd, auths);
        let rs = self.raw(Side::Rs, &bytes);
        let c = self.raw(Side::C, &bytes);
        assert_eq!(rs, c, "{:?}: the TPMs answered differently", C::CMD_CODE);
        let rc = u32::from_be_bytes(rs[6..10].try_into().unwrap());
        assert_eq!(rc, 0, "{:?} failed on both TPMs: {rc:#x}", C::CMD_CODE);
        unmarshal_response::<C>(&rs).unwrap()
    }

    /// Saves the context of `handle` on `side`.
    fn save(&mut self, side: Side, handle: Handle) -> TpmsContext<'static> {
        self.run(
            side,
            &ContextSave {
                save_handle: handle,
            },
            &[],
        )
        .context
    }

    /// Loads `context` on `side` and returns the handle of the loaded context.
    fn load(&mut self, side: Side, context: TpmsContext<'static>) -> Handle {
        self.run(side, &ContextLoad { context }, &[]).loaded_handle
    }

    /// Flushes `handle` on `side`.
    fn flush(&mut self, side: Side, handle: Handle) {
        self.run(
            side,
            &FlushContext {
                flush_handle: handle,
            },
            &[],
        );
    }

    /// Hands the context of `handle` from `from` to the other TPM: saves it, flushes it on
    /// `from`, loads it on the other TPM and returns its handle there.
    fn hand_over(&mut self, from: Side, handle: Handle) -> Handle {
        let context = self.save(from, handle);
        self.flush(from, handle);
        self.load(from.other(), context)
    }
}

/// The key of the keyed-hash object of [`create_hmac_key`].
const HMAC_KEY: &[u8] = b"context handover HMAC key";

/// Creates the same HMAC-SHA256 keyed-hash primary object (key [`HMAC_KEY`]) in the owner
/// hierarchy of both TPMs and returns its handle (the same in both).
fn create_hmac_key(pair: &mut Pair) -> Handle {
    let create = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::default(),
            data: Tpm2bSensitiveData::from_bytes(HMAC_KEY).unwrap(),
        }),
        in_public: tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::SIGN_ENCRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::KeyedHash(
                Some(TpmtKeyedHashScheme::Hmac(TpmiAlgHash::Sha256)),
                Tpm2bDigest::default(),
            ),
        }),
        outside_info: Default::default(),
        creation_pcr: Default::default(),
    };
    pair.both(&create, &[password_auth(b"")]).object_handle
}

/// Creates the same RSA-2048 RSASSA-SHA256 signing primary key (authValue `"rsa"`) in the owner
/// hierarchy of both TPMs and returns its handle (the same in both).
fn create_rsa_key(pair: &mut Pair) -> Handle {
    let create = CreatePrimary {
        primary_handle: Handle::RH_OWNER,
        in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
            user_auth: Tpm2bAuth::from_bytes(b"rsa").unwrap(),
            data: Tpm2bSensitiveData::default(),
        }),
        in_public: tpm2::Tpm2b(TpmtPublic {
            name_alg: Some(TpmiAlgHash::Sha256),
            object_attributes: TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::SIGN_ENCRYPT,
            auth_policy: Tpm2bDigest::default(),
            parms_and_id: PublicParmsAndId::Rsa(
                TpmsRsaParms {
                    symmetric: None,
                    scheme: Some(TpmtRsaScheme::Rsassa(TpmiAlgHash::Sha256)),
                    key_bits: TpmiRsaKeyBits::Rsa2048,
                    exponent: 0,
                },
                Tpm2bPublicKeyRsa::default(),
            ),
        }),
        outside_info: Default::default(),
        creation_pcr: Default::default(),
    };
    pair.both(&create, &[password_auth(b"")]).object_handle
}

/// The HMAC of `data` with the keyed-hash object `key` on `side`.
fn tpm_hmac(pair: &mut Pair, side: Side, key: Handle, data: &[u8]) -> Vec<u8> {
    let cmd = HMAC {
        handle: key,
        buffer: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    pair.run(side, &cmd, &[password_auth(b"")])
        .out_hmac
        .get_buffer()
        .to_vec()
}

/// The RSASSA signature of `digest` with the RSA key `key` on `side` (deterministic).
fn tpm_sign(pair: &mut Pair, side: Side, key: Handle, digest: &[u8]) -> Vec<u8> {
    let cmd = Sign {
        key_handle: key,
        digest: Tpm2bDigest::from_bytes(digest).unwrap(),
        in_scheme: None,
        validation: TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
    };
    let rsp = pair.raw(side, &build_cmd(&cmd, &[password_auth(b"rsa")]));
    assert_eq!(rsp[6..10], [0, 0, 0, 0], "TPM2_Sign on {side:?} failed");
    rsp
}

/// An object is handed back and forth between the TPMs (`TPM2_ContextSave` on one,
/// `TPM2_ContextLoad` on the other), several times and in both directions, and is used after
/// every handover: the keyed-hash key computes the expected HMAC, the RSA key (whose saved
/// private key is the packed CRT form) the signature both TPMs computed before, and its Name is
/// unchanged. Two contexts of one object saved in a row both load.
#[test]
fn object_contexts_round_trip_between_c_and_tpm_rs() {
    let mut pair = Pair::new();
    let hmac_key = create_hmac_key(&mut pair);
    let rsa_key = create_rsa_key(&mut pair);
    let digest = [0x5Au8; 32];
    let signature = tpm_sign(&mut pair, Side::C, rsa_key, &digest);
    assert_eq!(tpm_sign(&mut pair, Side::Rs, rsa_key, &digest), signature);
    let read_name = |pair: &mut Pair, side: Side, handle: Handle| {
        pair.run(
            side,
            &ReadPublic {
                object_handle: handle,
            },
            &[],
        )
        .name
        .get_buffer()
        .to_vec()
    };
    let hmac_name = read_name(&mut pair, Side::Rs, hmac_key);
    let rsa_name = read_name(&mut pair, Side::Rs, rsa_key);

    // Only one TPM holds the objects at a time: the C reference first.
    pair.flush(Side::Rs, hmac_key);
    pair.flush(Side::Rs, rsa_key);
    let (mut owner, mut hmac_key, mut rsa_key) = (Side::C, hmac_key, rsa_key);
    for round in 0..6u8 {
        hmac_key = pair.hand_over(owner, hmac_key);
        rsa_key = pair.hand_over(owner, rsa_key);
        owner = owner.other();
        let data = [round; 40];
        assert_eq!(
            tpm_hmac(&mut pair, owner, hmac_key, &data),
            expected_hmac(HMAC_KEY, &data),
            "round {round}: HMAC on {owner:?}"
        );
        assert_eq!(
            tpm_sign(&mut pair, owner, rsa_key, &digest),
            signature,
            "round {round}: signature on {owner:?}"
        );
        assert_eq!(read_name(&mut pair, owner, hmac_key), hmac_name);
        assert_eq!(read_name(&mut pair, owner, rsa_key), rsa_name);
    }

    // Two saves in a row: both contexts load on the other TPM, as two objects.
    let first = pair.save(owner, hmac_key);
    let second = pair.save(owner, hmac_key);
    assert_ne!(first.sequence, second.sequence);
    let other = owner.other();
    let a = pair.load(other, first);
    let b = pair.load(other, second);
    assert_ne!(a, b);
    for key in [a, b] {
        assert_eq!(
            tpm_hmac(&mut pair, other, key, b"twice"),
            expected_hmac(HMAC_KEY, b"twice")
        );
    }
    // The owner keeps working with its own copy.
    assert_eq!(
        tpm_hmac(&mut pair, owner, hmac_key, b"kept"),
        expected_hmac(HMAC_KEY, b"kept")
    );
}

/// The chunks a sequence receives, one per handover: sizes around the SHA-1/256 and
/// SHA-384/512 block sizes, so that the saved hash states have partly filled buffers (and, for
/// SHA-384/512, octets of earlier blocks after them).
const CHUNKS: [usize; 8] = [100, 37, 200, 128, 1, 300, 64, 129];

/// The message the sequences of [`sequence_contexts_continue_across_c_and_tpm_rs`] hash.
fn message() -> Vec<u8> {
    (0..CHUNKS.iter().sum::<usize>())
        .map(|i| (i * 31 + 7) as u8)
        .collect()
}

/// Feeds the chunks of [`message`] to the sequence `handle` (authValue `"seq"`), starting on
/// `side` and handing the sequence over to the other TPM after every chunk; returns the TPM and
/// handle that hold it at the end.
fn feed_with_handovers(pair: &mut Pair, mut side: Side, mut handle: Handle) -> (Side, Handle) {
    let message = message();
    let mut at = 0;
    for len in CHUNKS {
        let update = SequenceUpdate {
            sequence_handle: handle,
            buffer: Tpm2bMaxBuffer::from_bytes(&message[at..at + len]).unwrap(),
        };
        pair.run(side, &update, &[password_auth(b"seq")]);
        at += len;
        handle = pair.hand_over(side, handle);
        side = side.other();
    }
    (side, handle)
}

/// The digest of `data` with `alg` (client side).
fn client_hash(alg: TpmiAlgHash, data: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 64];
    tpm2::crypto::hash::<crate::_common::ClientCrypto>(alg, &[data], &mut out)
        .unwrap()
        .digest()
        .to_vec()
}

/// Hash, HMAC and event sequences continue across handovers: a sequence started on one TPM
/// receives every chunk of its message on alternating TPMs (saved by one, loaded by the other)
/// and completes on the last one with the digest, HMAC or digests of the whole message.
#[test]
fn sequence_contexts_continue_across_c_and_tpm_rs() {
    let mut pair = Pair::new();
    let message = message();
    let auth = Tpm2bAuth::from_bytes(b"seq").unwrap();

    for (alg, start) in [
        (TpmiAlgHash::Sha256, Side::C),
        (TpmiAlgHash::Sha384, Side::Rs),
        (TpmiAlgHash::Sha1, Side::C),
    ] {
        let handle = pair
            .run(
                start,
                &HashSequenceStart {
                    auth,
                    hash_alg: Some(alg),
                },
                &[],
            )
            .sequence_handle;
        let (side, handle) = feed_with_handovers(&mut pair, start, handle);
        let complete = SequenceComplete {
            sequence_handle: handle,
            buffer: Tpm2bMaxBuffer::default(),
            hierarchy: Handle::RH_NULL,
        };
        let digest = pair.run(side, &complete, &[password_auth(b"seq")]).result;
        assert_eq!(
            digest.get_buffer(),
            client_hash(alg, &message),
            "{alg:?} sequence"
        );
    }

    // An HMAC sequence (the key is needed only to start it).
    let key = create_hmac_key(&mut pair);
    let start = HMACStart {
        handle: key,
        auth,
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let handle = pair
        .run(Side::Rs, &start, &[password_auth(b"")])
        .sequence_handle;
    let (side, handle) = feed_with_handovers(&mut pair, Side::Rs, handle);
    let complete = SequenceComplete {
        sequence_handle: handle,
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let hmac = pair.run(side, &complete, &[password_auth(b"seq")]).result;
    assert_eq!(hmac.get_buffer(), expected_hmac(HMAC_KEY, &message));

    // An event sequence: the digests of every implemented hash.
    let handle = pair
        .run(
            Side::C,
            &HashSequenceStart {
                auth,
                hash_alg: None,
            },
            &[],
        )
        .sequence_handle;
    let (side, handle) = feed_with_handovers(&mut pair, Side::C, handle);
    let complete = EventSequenceComplete {
        pcr_handle: Handle::RH_NULL,
        sequence_handle: handle,
        buffer: Tpm2bMaxBuffer::default(),
    };
    let results = pair
        .run(
            side,
            &complete,
            &[password_auth(b""), password_auth(b"seq")],
        )
        .results;
    assert_ne!(results.digests().len(), 0);
    for digest in results.digests() {
        let alg = digest.hash_alg();
        let digest = *digest;
        assert_eq!(
            digest.digest(),
            client_hash(alg, &message),
            "{alg:?} of the event sequence"
        );
    }
}

/// `H(digest || code)` of a policy command without further parameters (client side).
fn extend_policy(digest: &[u8], cc: u32, extra: &[u8]) -> Vec<u8> {
    client_hash(
        TpmiAlgHash::Sha256,
        &[digest, &cc.to_be_bytes(), extra].concat(),
    )
}

/// A policy session continues across handovers: in every round one TPM loads the session,
/// extends its policy and saves it, while the other loads and saves its stale copy (so that both
/// track the saved session with the same context sequence); then the other TPM continues with
/// the context of the first. Both TPMs end with the policy digest of every command of both, and
/// stay in step (the same `TPM2_GetRandom` output afterwards).
#[test]
fn policy_session_continues_across_c_and_tpm_rs() {
    let mut pair = Pair::new();
    let start = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0x11; 32]).unwrap(),
        encrypted_salt: Default::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let session = pair.both(&start, &[]).session_handle;
    let save = ContextSave {
        save_handle: session,
    };
    let mut context = pair.both(&save, &[]).context;

    let mut expected = vec![0u8; 32];
    let mut active = Side::C;
    for round in 0..6 {
        // The active TPM continues the session...
        let handle = pair.load(active, context);
        match round % 3 {
            0 => {
                pair.run(
                    active,
                    &PolicyCommandCode {
                        policy_session: handle,
                        code: TpmCc::Unseal,
                    },
                    &[],
                );
                expected = extend_policy(
                    &expected,
                    TpmCc::PolicyCommandCode.code(),
                    &TpmCc::Unseal.code().to_be_bytes(),
                );
            }
            1 => {
                pair.run(
                    active,
                    &PolicyAuthValue {
                        policy_session: handle,
                    },
                    &[],
                );
                expected = extend_policy(&expected, TpmCc::PolicyAuthValue.code(), &[]);
            }
            _ => {
                pair.run(
                    active,
                    &PolicyPassword {
                        policy_session: handle,
                    },
                    &[],
                );
                // TPM2_PolicyPassword extends the digest like TPM2_PolicyAuthValue.
                expected = extend_policy(&expected, TpmCc::PolicyAuthValue.code(), &[]);
            }
        }
        let next = pair.save(active, handle);
        // ...while the other TPM loads and saves its stale copy.
        let passive = active.other();
        let stale = pair.load(passive, context);
        let discarded = pair.save(passive, stale);
        assert_eq!(discarded.sequence, next.sequence);
        context = next;
        active = passive;
    }

    let mut digests = Vec::new();
    for side in [Side::Rs, Side::C] {
        let handle = pair.load(side, context);
        let digest = pair.run(
            side,
            &PolicyGetDigest {
                policy_session: handle,
            },
            &[],
        );
        digests.push(digest.policy_digest.get_buffer().to_vec());
    }
    assert_eq!(digests[0], expected);
    assert_eq!(digests[1], expected);
    pair.both(
        &GetRandom {
            bytes_requested: 16,
        },
        &[],
    );
}
