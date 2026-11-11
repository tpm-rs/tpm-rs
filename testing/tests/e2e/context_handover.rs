//! Saved contexts handed over again and again: an object, hash/HMAC/event sequences and a policy
//! session are saved, flushed, loaded from the saved context, used and saved again, many times,
//! and the TPM keeps working with them (the HMACs, signatures, digests and policy digests are
//! those of the whole history).
//!
//! In a differential build this is a handover between `tpm-rs` and the C reference TPM of the
//! target in both directions, through the ordinary mirrored `Tpm`: the reference compares every
//! response byte for byte, so the `contextBlob` of each `TPM2_ContextSave` is the same on both
//! TPMs, and the `TPM2_ContextLoad` that follows sends that blob, which `tpm-rs` saved, to the
//! reference unchanged. Each TPM therefore loads the other's contexts, and every response after
//! every handover, including the results of the handed-over objects, sequences and sessions, is
//! identical on both.
// `TPM2_Sign` (`tpm2::commands::Sign`) is deprecated in favor of the digest-signing commands.
#![allow(deprecated)]

use crate::_common::{build_cmd, expected_hmac, password_auth, unmarshal_response};
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

/// Executes `cmd` with the authorization sessions `auths`, which must succeed, and returns its
/// response.
fn run<C: Command>(tpm: &mut Tpm, cmd: &C, auths: &[TpmsAuthCommand<'_>]) -> C::Response<'static>
where
    for<'b> &'b mut <C as Marshal>::MaxBuffer: TryFrom<&'b mut [u8]>,
{
    let rsp = tpm.send_command(&build_cmd(cmd, auths));
    let rc = u32::from_be_bytes(rsp[6..10].try_into().unwrap());
    assert_eq!(rc, 0, "{:?} failed: {rc:#x}", C::CMD_CODE);
    unmarshal_response::<C>(&rsp).unwrap()
}

/// Saves the context of `handle`.
fn save(tpm: &mut Tpm, handle: Handle) -> TpmsContext<'static> {
    run(
        tpm,
        &ContextSave {
            save_handle: handle,
        },
        &[],
    )
    .context
}

/// Loads `context` and returns the handle of the loaded context.
fn load(tpm: &mut Tpm, context: TpmsContext<'static>) -> Handle {
    run(tpm, &ContextLoad { context }, &[]).loaded_handle
}

/// Flushes `handle`.
fn flush(tpm: &mut Tpm, handle: Handle) {
    run(
        tpm,
        &FlushContext {
            flush_handle: handle,
        },
        &[],
    );
}

/// Hands the object or sequence `handle` over: saves its context, flushes it and loads the saved
/// context; returns the handle of the loaded context.
fn hand_over(tpm: &mut Tpm, handle: Handle) -> Handle {
    let context = save(tpm, handle);
    flush(tpm, handle);
    load(tpm, context)
}

/// The key of the keyed-hash object of [`create_hmac_key`].
const HMAC_KEY: &[u8] = b"context handover HMAC key";

/// Creates an HMAC-SHA256 keyed-hash primary object (key [`HMAC_KEY`]) in the owner hierarchy
/// and returns its handle.
fn create_hmac_key(tpm: &mut Tpm) -> Handle {
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
    run(tpm, &create, &[password_auth(b"")]).object_handle
}

/// Creates an RSA-2048 RSASSA-SHA256 signing primary key (authValue `"rsa"`) in the owner
/// hierarchy and returns its handle.
fn create_rsa_key(tpm: &mut Tpm) -> Handle {
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
    run(tpm, &create, &[password_auth(b"")]).object_handle
}

/// The HMAC of `data` with the keyed-hash object `key`.
fn tpm_hmac(tpm: &mut Tpm, key: Handle, data: &[u8]) -> Vec<u8> {
    let cmd = HMAC {
        handle: key,
        buffer: Tpm2bMaxBuffer::from_bytes(data).unwrap(),
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    run(tpm, &cmd, &[password_auth(b"")])
        .out_hmac
        .get_buffer()
        .to_vec()
}

/// The response to the RSASSA signing of `digest` with the RSA key `key` (deterministic).
fn tpm_sign(tpm: &mut Tpm, key: Handle, digest: &[u8]) -> Vec<u8> {
    let cmd = Sign {
        key_handle: key,
        digest: Tpm2bDigest::from_bytes(digest).unwrap(),
        in_scheme: None,
        validation: TpmtTkHashcheck::Hashcheck(Handle::RH_NULL, Tpm2bDigest::default()),
    };
    let rsp = tpm.send_command(&build_cmd(&cmd, &[password_auth(b"rsa")]));
    assert_eq!(rsp[6..10], [0, 0, 0, 0], "TPM2_Sign failed");
    rsp
}

/// The Name of the loaded object `handle`.
fn read_name(tpm: &mut Tpm, handle: Handle) -> Vec<u8> {
    run(
        tpm,
        &ReadPublic {
            object_handle: handle,
        },
        &[],
    )
    .name
    .get_buffer()
    .to_vec()
}

/// An object is handed over (`TPM2_ContextSave`, `TPM2_FlushContext`, `TPM2_ContextLoad` of the
/// saved context) several times and used after every handover: the keyed-hash key computes the
/// expected HMAC, the RSA key (whose saved private key is the packed CRT form) the signature it
/// computed before the first handover, and its Name is unchanged. Two contexts of one object
/// saved in a row both load, as two objects, while the original keeps working.
#[test]
fn object_contexts_round_trip_between_c_and_tpm_rs() {
    let mut tpm = Tpm::new();
    let mut hmac_key = create_hmac_key(&mut tpm);
    let mut rsa_key = create_rsa_key(&mut tpm);
    let digest = [0x5Au8; 32];
    let signature = tpm_sign(&mut tpm, rsa_key, &digest);
    let hmac_name = read_name(&mut tpm, hmac_key);
    let rsa_name = read_name(&mut tpm, rsa_key);

    for round in 0..6u8 {
        hmac_key = hand_over(&mut tpm, hmac_key);
        rsa_key = hand_over(&mut tpm, rsa_key);
        let data = [round; 40];
        assert_eq!(
            tpm_hmac(&mut tpm, hmac_key, &data),
            expected_hmac(HMAC_KEY, &data),
            "round {round}: HMAC"
        );
        assert_eq!(
            tpm_sign(&mut tpm, rsa_key, &digest),
            signature,
            "round {round}: signature"
        );
        assert_eq!(read_name(&mut tpm, hmac_key), hmac_name);
        assert_eq!(read_name(&mut tpm, rsa_key), rsa_name);
    }

    // Two saves in a row: both contexts load, as two objects (the RSA key is flushed to make
    // room: the references hold three transient objects).
    flush(&mut tpm, rsa_key);
    let first = save(&mut tpm, hmac_key);
    let second = save(&mut tpm, hmac_key);
    assert_ne!(first.sequence, second.sequence);
    let a = load(&mut tpm, first);
    let b = load(&mut tpm, second);
    assert_ne!(a, b);
    for key in [a, b] {
        assert_eq!(
            tpm_hmac(&mut tpm, key, b"twice"),
            expected_hmac(HMAC_KEY, b"twice")
        );
    }
    // The original keeps working.
    assert_eq!(
        tpm_hmac(&mut tpm, hmac_key, b"kept"),
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

/// Feeds the chunks of [`message`] to the sequence `handle` (authValue `"seq"`), handing the
/// sequence over after every chunk; returns the handle of the sequence at the end.
fn feed_with_handovers(tpm: &mut Tpm, mut handle: Handle) -> Handle {
    let message = message();
    let mut at = 0;
    for len in CHUNKS {
        let update = SequenceUpdate {
            sequence_handle: handle,
            buffer: Tpm2bMaxBuffer::from_bytes(&message[at..at + len]).unwrap(),
        };
        run(tpm, &update, &[password_auth(b"seq")]);
        at += len;
        handle = hand_over(tpm, handle);
    }
    handle
}

/// The digest of `data` with `alg` (client side).
fn client_hash(alg: TpmiAlgHash, data: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 64];
    tpm2::crypto::hash::<crate::_common::ClientCrypto>(alg, &[data], &mut out)
        .unwrap()
        .digest()
        .to_vec()
}

/// Hash, HMAC and event sequences continue across handovers: a sequence receives every chunk of
/// its message from a different saved context (saved, flushed and loaded after every chunk) and
/// completes with the digest, HMAC or digests of the whole message.
#[test]
fn sequence_contexts_continue_across_c_and_tpm_rs() {
    let mut tpm = Tpm::new();
    let message = message();
    let auth = Tpm2bAuth::from_bytes(b"seq").unwrap();

    for alg in [TpmiAlgHash::Sha256, TpmiAlgHash::Sha384, TpmiAlgHash::Sha1] {
        let handle = run(
            &mut tpm,
            &HashSequenceStart {
                auth,
                hash_alg: Some(alg),
            },
            &[],
        )
        .sequence_handle;
        let handle = feed_with_handovers(&mut tpm, handle);
        let complete = SequenceComplete {
            sequence_handle: handle,
            buffer: Tpm2bMaxBuffer::default(),
            hierarchy: Handle::RH_NULL,
        };
        let digest = run(&mut tpm, &complete, &[password_auth(b"seq")]).result;
        assert_eq!(
            digest.get_buffer(),
            client_hash(alg, &message),
            "{alg:?} sequence"
        );
    }

    // An HMAC sequence (the key is needed only to start it).
    let key = create_hmac_key(&mut tpm);
    let start = HMACStart {
        handle: key,
        auth,
        hash_alg: Some(TpmiAlgHash::Sha256),
    };
    let handle = run(&mut tpm, &start, &[password_auth(b"")]).sequence_handle;
    let handle = feed_with_handovers(&mut tpm, handle);
    let complete = SequenceComplete {
        sequence_handle: handle,
        buffer: Tpm2bMaxBuffer::default(),
        hierarchy: Handle::RH_NULL,
    };
    let hmac = run(&mut tpm, &complete, &[password_auth(b"seq")]).result;
    assert_eq!(hmac.get_buffer(), expected_hmac(HMAC_KEY, &message));

    // An event sequence: the digests of every implemented hash.
    let handle = run(
        &mut tpm,
        &HashSequenceStart {
            auth,
            hash_alg: None,
        },
        &[],
    )
    .sequence_handle;
    let handle = feed_with_handovers(&mut tpm, handle);
    let complete = EventSequenceComplete {
        pcr_handle: Handle::RH_NULL,
        sequence_handle: handle,
        buffer: Tpm2bMaxBuffer::default(),
    };
    let results = run(
        &mut tpm,
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

/// `H(digest || code || extra)` of a policy command (client side).
fn extend_policy(digest: &[u8], cc: u32, extra: &[u8]) -> Vec<u8> {
    client_hash(
        TpmiAlgHash::Sha256,
        &[digest, &cc.to_be_bytes(), extra].concat(),
    )
}

/// A policy session continues across handovers: in every round the saved session is loaded,
/// its policy extended and the session saved again. It ends with the policy digest of every
/// command, and the TPM stays in step (`TPM2_GetRandom` afterwards).
#[test]
fn policy_session_continues_across_c_and_tpm_rs() {
    let mut tpm = Tpm::new();
    let start = StartAuthSession {
        tpm_key: Handle::RH_NULL,
        bind: Handle::RH_NULL,
        nonce_caller: Tpm2bNonce::from_bytes(&[0x11; 32]).unwrap(),
        encrypted_salt: Default::default(),
        session_type: TpmSe::Policy,
        symmetric: None,
        auth_hash: TpmiAlgHash::Sha256,
    };
    let session = run(&mut tpm, &start, &[]).session_handle;
    let mut context = save(&mut tpm, session);

    let mut expected = vec![0u8; 32];
    for round in 0..6 {
        let handle = load(&mut tpm, context);
        match round % 3 {
            0 => {
                run(
                    &mut tpm,
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
                run(
                    &mut tpm,
                    &PolicyAuthValue {
                        policy_session: handle,
                    },
                    &[],
                );
                expected = extend_policy(&expected, TpmCc::PolicyAuthValue.code(), &[]);
            }
            _ => {
                run(
                    &mut tpm,
                    &PolicyPassword {
                        policy_session: handle,
                    },
                    &[],
                );
                // TPM2_PolicyPassword extends the digest like TPM2_PolicyAuthValue.
                expected = extend_policy(&expected, TpmCc::PolicyAuthValue.code(), &[]);
            }
        }
        context = save(&mut tpm, handle);
    }

    let handle = load(&mut tpm, context);
    let digest = run(
        &mut tpm,
        &PolicyGetDigest {
            policy_session: handle,
        },
        &[],
    );
    assert_eq!(digest.policy_digest.get_buffer(), expected);
    run(
        &mut tpm,
        &GetRandom {
            bytes_requested: 16,
        },
        &[],
    );
}

/// An object of the [`ResourceManager`]: an index into its saved contexts.
#[derive(Clone, Copy, Debug)]
struct Obj(usize);

/// A resource manager like the Linux kernel's `/dev/tpmrm0`, through which the software of a
/// guest reaches its vTPM: between two commands no object or session of the guest is loaded.
/// Before every command it loads every live session and the objects the command uses from the
/// contexts it saved after the previous command (`TPM2_ContextLoad`); after the command it saves
/// every loaded session and object (`TPM2_ContextSave`) and flushes the objects
/// (`TPM2_FlushContext`). Like a TSS, it keeps the Names of the objects, so that commands with
/// HMAC sessions need no `TPM2_ReadPublic`.
///
/// In a differential build each saved context is compared with the reference's, and each
/// `TPM2_ContextLoad` sends that context to both TPMs: before every command, each TPM loads
/// the contexts the other saved after the previous one.
struct ResourceManager {
    tpm: Tpm,
    /// The saved context and the Name of every object; `None` once the guest has closed it.
    objects: Vec<Option<(TpmsContext<'static>, Vec<u8>)>>,
    /// The objects loaded for the current command (index and handle).
    loaded: Vec<(usize, Handle)>,
    /// The live sessions and, between commands, their saved contexts.
    sessions: Vec<(Handle, Option<TpmsContext<'static>>)>,
    /// Commands of the guest so far.
    commands: usize,
    /// Contexts loaded so far.
    context_loads: usize,
}

impl ResourceManager {
    fn new() -> Self {
        Self {
            tpm: Tpm::new(),
            objects: Vec::new(),
            loaded: Vec::new(),
            sessions: Vec::new(),
            commands: 0,
            context_loads: 0,
        }
    }

    /// Sends one command of the guest (`f`, given the handles of `objects`, which it uses):
    /// loads every live session and `objects` before it and saves them after it.
    fn command<R>(&mut self, objects: &[Obj], f: impl FnOnce(&mut Self, &[Handle]) -> R) -> R {
        self.commands += 1;
        let tpm = &mut self.tpm;
        for (handle, context) in &mut self.sessions {
            let context = context.take().expect("a saved session");
            assert_eq!(load(tpm, context), *handle, "a session keeps its handle");
            self.context_loads += 1;
        }
        let mut handles = Vec::new();
        for obj in objects {
            let (context, _) = self.objects[obj.0].as_ref().expect("a live object");
            let context = *context;
            let handle = load(&mut self.tpm, context);
            self.loaded.push((obj.0, handle));
            handles.push(handle);
            self.context_loads += 1;
        }
        let result = f(self, &handles);
        let tpm = &mut self.tpm;
        for (handle, context) in &mut self.sessions {
            *context = Some(save(tpm, *handle));
        }
        for (index, handle) in self.loaded.drain(..) {
            let saved = save(tpm, handle);
            flush(tpm, handle);
            self.objects[index].as_mut().expect("a live object").0 = saved;
        }
        result
    }

    /// Takes over the object `handle` (Name `name`) the current command created or loaded.
    fn adopt_object(&mut self, handle: Handle, name: &[u8]) -> Obj {
        // The context is saved when the command ends.
        self.objects
            .push(Some((TpmsContext::default(), name.to_vec())));
        self.loaded.push((self.objects.len() - 1, handle));
        Obj(self.objects.len() - 1)
    }

    /// Takes over the session `handle` the current command started.
    fn adopt_session(&mut self, handle: Handle) {
        self.sessions.push((handle, None));
    }

    /// Forgets the session `handle` the current command ended (`continueSession` clear, or
    /// `TPM2_FlushContext`).
    fn end_session(&mut self, handle: Handle) {
        self.sessions.retain(|(h, _)| *h != handle);
    }

    /// The guest closes `obj`: the resource manager discards its saved context (no command).
    fn close(&mut self, obj: Obj) {
        self.objects[obj.0] = None;
    }

    /// The Name of `obj`.
    fn name(&self, obj: Obj) -> Vec<u8> {
        self.objects[obj.0]
            .as_ref()
            .expect("a live object")
            .1
            .clone()
    }
}

/// The SHA-256 bank of the PCRs, as the guest expects it.
struct PcrModel([Vec<u8>; 24]);

impl PcrModel {
    /// `TPM2_PCR_Extend` of `pcr` with the SHA-256 and SHA-384 digests of the event `data`, as
    /// firmware, boot loader and IMA measure an event into every allocated bank.
    fn extend(&mut self, rm: &mut ResourceManager, pcr: usize, data: &[u8]) {
        let sha256 = client_hash(TpmiAlgHash::Sha256, data);
        let sha384 = client_hash(TpmiAlgHash::Sha384, data);
        rm.command(&[], |rm, _| {
            let mut digests = tpm2::TpmlDigestValues::default();
            digests
                .add(&tpm2::TpmtHa::Sha256(sha256.as_slice().try_into().unwrap()))
                .unwrap();
            digests
                .add(&tpm2::TpmtHa::Sha384(sha384.as_slice().try_into().unwrap()))
                .unwrap();
            let cmd = tpm2::commands::PCRExtend {
                pcr_handle: Handle(pcr as u32),
                digests,
            };
            run(&mut rm.tpm, &cmd, &[password_auth(b"")]);
        });
        self.0[pcr] =
            crate::_common::compute_expected_extend(TpmiAlgHash::Sha256, &self.0[pcr], &sha256);
    }

    /// The `pcrDigest` of a quote of the SHA-256 PCRs `pcrs` (ascending).
    fn digest(&self, pcrs: &[usize]) -> Vec<u8> {
        let values: Vec<u8> = pcrs.iter().flat_map(|&i| self.0[i].clone()).collect();
        client_hash(TpmiAlgHash::Sha256, &values)
    }
}

/// A selection of SHA-256 PCRs.
fn sha256_selection(pcrs: &[usize]) -> tpm2::TpmlPcrSelection {
    let mut bitmap = [0u8; 3];
    for &pcr in pcrs {
        bitmap[pcr / 8] |= 1 << (pcr % 8);
    }
    let mut selection = tpm2::TpmlPcrSelection::default();
    selection
        .add(&tpm2::TpmsPcrSelection::new(TpmiAlgHash::Sha256, &bitmap).unwrap())
        .unwrap();
    selection
}

/// The PCR the disk encryption key is sealed to (Secure Boot state, like `systemd-cryptenroll
/// --tpm2-pcrs=7`).
const SEAL_PCRS: [usize; 1] = [7];

/// The PCRs a remote attestation quotes (firmware, boot loader and IMA measurements).
const QUOTE_PCRS: [usize; 11] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

/// Unlocks the disk with the sealed key (`systemd-cryptsetup`): starts a policy session (with
/// AES-128-CFB, so that the key leaves the TPM encrypted), satisfies `TPM2_PolicyPCR` and
/// unseals the key with it (three commands); the session ends with `TPM2_Unseal`.
fn unlock_disk(rm: &mut ResourceManager, sealed: Obj) -> Vec<u8> {
    let mut session = rm.command(&[], |rm, _| {
        let session = crate::_common::start_auth_session(
            &mut rm.tpm,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::Policy,
            Some(tpm2::TpmtSymDefObject {
                alg: tpm2::AlgSym::Aes128,
                mode: Some(tpm2::TpmiAlgSymMode::Cipher(tpm2::TpmiAlgCipherMode::Cfb)),
            }),
            TpmiAlgHash::Sha256,
        )
        .expect("TPM2_StartAuthSession (policy)");
        rm.adopt_session(session.session_handle);
        session
    });
    rm.command(&[], |rm, _| {
        let cmd = tpm2::commands::PolicyPCR {
            policy_session: session.session_handle,
            pcr_digest: Tpm2bDigest::default(),
            pcrs: sha256_selection(&SEAL_PCRS),
        };
        run(&mut rm.tpm, &cmd, &[]);
    });
    session.attributes = tpm2::TpmaSession::ENCRYPT;
    let name = rm.name(sealed);
    rm.command(&[sealed], |rm, h| {
        let rsp = crate::_common::execute_with_hmac_sessions(
            &mut rm.tpm,
            &tpm2::commands::Unseal { item_handle: h[0] },
            &[&name],
            core::slice::from_mut(&mut session),
            &[b""],
        )
        .unwrap_or_else(|rc| panic!("TPM2_Unseal: {rc:#x}"));
        rm.end_session(session.session_handle);
        rsp.out_data.get_buffer().to_vec()
    })
}

/// A long trace of what the software of a confidential VM does with its vTPM, through a
/// resource manager like the kernel's `/dev/tpmrm0`, which saves every object and session of
/// the guest after every command and loads the live sessions and the objects the next command
/// uses before it (a context handover before every command but the first, in a differential
/// build between `tpm-rs` and the C reference of the target, see [`ResourceManager`]). The guest:
///
/// 1. boots: the TSS reads the PCR banks, the firmware and the boot loader measure into
///    PCRs 0-9;
/// 2. enrolls a disk encryption key like `systemd-cryptenroll --tpm2-pcrs=7`: an ECC SRK, a
///    trial session for the `TPM2_PolicyPCR` digest, and a sealed object created with an HMAC
///    session that encrypts the key, and unlocks the disk like `systemd-cryptsetup`;
/// 3. enrolls for remote attestation (go-attestation, Keylime): an RSA EK, an ECC AK under the
///    SRK, and credential activation (`TPM2_MakeCredential`, `TPM2_PolicySecret` for the EK
///    policy, `TPM2_ActivateCredential`);
/// 4. runs: IMA measures into PCR 10 and the attestation agent answers periodic challenges
///    with `TPM2_PCR_Read` and `TPM2_Quote`;
/// 5. signs with a PIN-protected application key (a PKCS#11 token, an SSH agent):
///    `TPM2_Hash` and `TPM2_Sign` with an HMAC session (the PIN never in the clear), checked with
///    `TPM2_VerifySignature`, and a large document with a hash sequence;
/// 6. unlocks a second volume with the same sealed key.
///
/// Every result is checked: the unsealed key, the activated credential, the `pcrDigest` and
/// nonce of every quote, the digests and the signature checks. In a differential build every
/// command, the context saves and loads included, is compared with the C reference.
#[test]
fn vtpm_guest_trace_with_contexts_handed_over_before_every_command() {
    let mut rm = ResourceManager::new();
    let mut pcrs = PcrModel(core::array::from_fn(|_| vec![0u8; 32]));

    // 1. Boot. The TSS reads the allocated PCR banks; the firmware and the boot loader measure.
    rm.command(&[], |rm, _| {
        let cmd = tpm2::commands::GetCapability {
            capability: tpm2::TpmCap::PCRs,
            property: 0,
            property_count: 1,
        };
        run(&mut rm.tpm, &cmd, &[]);
    });
    for (pcr, event) in [
        (0, &b"EV_S_CRTM_VERSION / EV_EFI_PLATFORM_FIRMWARE_BLOB"[..]),
        (1, b"EV_EFI_VARIABLE_BOOT BootOrder"),
        (2, b"EV_EFI_BOOT_SERVICES_DRIVER"),
        (3, b"EV_SEPARATOR"),
        (4, b"EV_EFI_BOOT_SERVICES_APPLICATION shimx64.efi"),
        (5, b"EV_EFI_GPT_EVENT"),
        (6, b"EV_SEPARATOR"),
        (7, b"EV_EFI_VARIABLE_DRIVER_CONFIG SecureBoot PK KEK db dbx"),
        (4, b"EV_EFI_BOOT_SERVICES_APPLICATION grubx64.efi"),
        (8, b"grub_cmd: linux /vmlinuz root=/dev/mapper/root ro"),
        (9, b"/vmlinuz"),
        (9, b"/initrd.img"),
    ] {
        pcrs.extend(&mut rm, pcr, event);
    }

    // 2. Disk encryption: the SRK (TCG provisioning template, ECC P-256).
    let srk = rm.command(&[], |rm, _| {
        let create = CreatePrimary {
            primary_handle: Handle::RH_OWNER,
            in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate::default()),
            in_public: tpm2::Tpm2b(crate::_common::get_ecc_srk_template()),
            outside_info: Default::default(),
            creation_pcr: Default::default(),
        };
        let rsp = run(&mut rm.tpm, &create, &[password_auth(b"")]);
        rm.adopt_object(rsp.object_handle, rsp.name.get_buffer())
    });
    // The policy digest of PCR 7, with a trial session (`tpm2_createpolicy`).
    let trial = rm.command(&[], |rm, _| {
        let start = StartAuthSession {
            tpm_key: Handle::RH_NULL,
            bind: Handle::RH_NULL,
            nonce_caller: Tpm2bNonce::from_bytes(&[0x5E; 16]).unwrap(),
            encrypted_salt: Default::default(),
            session_type: TpmSe::Trial,
            symmetric: None,
            auth_hash: TpmiAlgHash::Sha256,
        };
        let session = run(&mut rm.tpm, &start, &[]).session_handle;
        rm.adopt_session(session);
        session
    });
    rm.command(&[], |rm, _| {
        let cmd = tpm2::commands::PolicyPCR {
            policy_session: trial,
            pcr_digest: Tpm2bDigest::default(),
            pcrs: sha256_selection(&SEAL_PCRS),
        };
        run(&mut rm.tpm, &cmd, &[]);
    });
    let policy = rm.command(&[], |rm, _| {
        let digest = run(
            &mut rm.tpm,
            &PolicyGetDigest {
                policy_session: trial,
            },
            &[],
        );
        digest.policy_digest.get_buffer().to_vec()
    });
    rm.command(&[], |rm, _| {
        flush(&mut rm.tpm, trial);
        rm.end_session(trial);
    });
    // `TPM2_PolicyPCR`: H(0 || TPM_CC_PolicyPCR || pcrs || H(PCR 7)).
    let selection = crate::_common::marshal_to_vec(&sha256_selection(&SEAL_PCRS));
    let expected_policy = client_hash(
        TpmiAlgHash::Sha256,
        &[
            &[0u8; 32][..],
            &TpmCc::PolicyPCR.code().to_be_bytes(),
            &selection,
            &pcrs.digest(&SEAL_PCRS),
        ]
        .concat(),
    );
    assert_eq!(policy, expected_policy, "PolicyPCR digest");
    // The HMAC session of the TSS: AES-128-CFB parameter encryption in both directions.
    let mut hmac_session = rm.command(&[], |rm, _| {
        let mut session = crate::_common::start_auth_session(
            &mut rm.tpm,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::HMAC,
            Some(tpm2::TpmtSymDefObject {
                alg: tpm2::AlgSym::Aes128,
                mode: Some(tpm2::TpmiAlgSymMode::Cipher(tpm2::TpmiAlgCipherMode::Cfb)),
            }),
            TpmiAlgHash::Sha256,
        )
        .expect("TPM2_StartAuthSession (HMAC)");
        session.attributes = tpm2::TpmaSession::CONTINUE_SESSION
            | tpm2::TpmaSession::DECRYPT
            | tpm2::TpmaSession::ENCRYPT;
        rm.adopt_session(session.session_handle);
        session
    });
    // The sealed disk encryption key, created with the key encrypted on its way in.
    let disk_key: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(37) ^ 0x6B).collect();
    let srk_name = rm.name(srk);
    let sealed_blob = rm.command(&[srk], |rm, h| {
        let cmd = tpm2::commands::Create {
            parent_handle: h[0],
            in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::default(),
                data: Tpm2bSensitiveData::from_bytes(&disk_key).unwrap(),
            }),
            in_public: tpm2::Tpm2b(crate::_common::sealed_template_with_policy(
                TpmaObject::NO_DA,
                &policy,
            )),
            outside_info: Default::default(),
            creation_pcr: Default::default(),
        };
        let rsp = crate::_common::execute_with_hmac_sessions(
            &mut rm.tpm,
            &cmd,
            &[&srk_name],
            core::slice::from_mut(&mut hmac_session),
            &[b""],
        )
        .unwrap_or_else(|rc| panic!("TPM2_Create (sealed): {rc:#x}"));
        (rsp.out_private, rsp.out_public)
    });
    let sealed = rm.command(&[srk], |rm, h| {
        let cmd = tpm2::commands::Load {
            parent_handle: h[0],
            in_private: sealed_blob.0,
            in_public: sealed_blob.1,
        };
        let rsp = run(&mut rm.tpm, &cmd, &[password_auth(b"")]);
        rm.adopt_object(rsp.object_handle, rsp.name.get_buffer())
    });
    assert_eq!(unlock_disk(&mut rm, sealed), disk_key, "unsealed disk key");

    // 3. Attestation enrollment: the RSA EK (TCG EK template), the AK and credential activation.
    let ek = rm.command(&[], |rm, _| {
        let create = CreatePrimary {
            primary_handle: Handle::RH_ENDORSEMENT,
            in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate::default()),
            in_public: tpm2::Tpm2b(crate::_common::rsa_ek_template()),
            outside_info: Default::default(),
            creation_pcr: Default::default(),
        };
        let rsp = run(&mut rm.tpm, &create, &[password_auth(b"")]);
        rm.adopt_object(rsp.object_handle, rsp.name.get_buffer())
    });
    let ek_name = rm.name(ek);
    rm.command(&[ek], |rm, h| {
        assert_eq!(read_name(&mut rm.tpm, h[0]), ek_name, "EK Name");
    });
    let ak_blob = rm.command(&[srk], |rm, h| {
        let cmd = tpm2::commands::Create {
            parent_handle: h[0],
            in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate::default()),
            in_public: tpm2::Tpm2b(crate::_common::get_ecc_sign_restricted_template()),
            outside_info: Default::default(),
            creation_pcr: Default::default(),
        };
        let rsp = run(&mut rm.tpm, &cmd, &[password_auth(b"")]);
        (rsp.out_private, rsp.out_public)
    });
    let ak = rm.command(&[srk], |rm, h| {
        let cmd = tpm2::commands::Load {
            parent_handle: h[0],
            in_private: ak_blob.0,
            in_public: ak_blob.1,
        };
        let rsp = run(&mut rm.tpm, &cmd, &[password_auth(b"")]);
        rm.adopt_object(rsp.object_handle, rsp.name.get_buffer())
    });
    let ak_name = rm.name(ak);
    // The attestation server's challenge for the AK, encrypted to the EK.
    let credential = b"attestation server credential";
    let challenge = rm.command(&[ek], |rm, h| {
        let cmd = tpm2::commands::MakeCredential {
            handle: h[0],
            credential: Tpm2bDigest::from_bytes(credential).unwrap(),
            object_name: tpm2::Tpm2bName::from_bytes(&ak_name).unwrap(),
        };
        let rsp = run(&mut rm.tpm, &cmd, &[]);
        (rsp.credential_blob, rsp.secret)
    });
    let mut ek_session = rm.command(&[], |rm, _| {
        let session = crate::_common::start_auth_session(
            &mut rm.tpm,
            Handle::RH_NULL,
            Handle::RH_NULL,
            &[],
            TpmSe::Policy,
            None,
            TpmiAlgHash::Sha256,
        )
        .expect("TPM2_StartAuthSession (EK policy)");
        rm.adopt_session(session.session_handle);
        session
    });
    rm.command(&[], |rm, _| {
        let cmd = tpm2::commands::PolicySecret {
            auth_handle: Handle::RH_ENDORSEMENT,
            policy_session: ek_session.session_handle,
            nonce_tpm: ek_session.nonce_tpm,
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: Tpm2bNonce::default(),
            expiration: 0,
        };
        run(&mut rm.tpm, &cmd, &[password_auth(b"")]);
    });
    let activated = rm.command(&[ak, ek], |rm, h| {
        let cmd = tpm2::commands::ActivateCredential {
            activate_handle: h[0],
            key_handle: h[1],
            credential_blob: challenge.0,
            secret: challenge.1,
        };
        let mut sessions = [hmac_session.clone(), ek_session.clone()];
        let rsp = crate::_common::execute_with_hmac_sessions(
            &mut rm.tpm,
            &cmd,
            &[&ak_name, &ek_name],
            &mut sessions,
            &[b"", b""],
        )
        .unwrap_or_else(|rc| panic!("TPM2_ActivateCredential: {rc:#x}"));
        [hmac_session, ek_session] = sessions;
        rm.end_session(ek_session.session_handle);
        rsp.cert_info.get_buffer().to_vec()
    });
    assert_eq!(activated, credential, "activated credential");
    // The EK is needed only for the enrollment.
    rm.close(ek);

    // 4. Runtime: IMA measures executables into PCR 10; the attestation agent answers the
    // verifier's challenges (PCR values and a quote over the nonce).
    for round in 0..12u8 {
        for file in ["/usr/bin/bash", "/usr/lib/systemd/systemd-journald"] {
            let event = format!("ima-ng sha256 {file} round {round}");
            pcrs.extend(&mut rm, 10, event.as_bytes());
        }
        rm.command(&[], |rm, _| {
            let cmd = tpm2::commands::PCRRead {
                pcr_selection_in: sha256_selection(&[10]),
            };
            let read = run(&mut rm.tpm, &cmd, &[]);
            assert_eq!(read.pcr_values.digests()[0].get_buffer(), pcrs.0[10]);
        });
        let nonce = client_hash(TpmiAlgHash::Sha256, &[round, 0x0A]);
        let expected_digest = pcrs.digest(&QUOTE_PCRS);
        rm.command(&[ak], |rm, h| {
            let cmd = tpm2::commands::Quote {
                sign_handle: h[0],
                qualifying_data: tpm2::Tpm2bData::from_bytes(&nonce).unwrap(),
                in_scheme: None,
                pcr_select: sha256_selection(&QUOTE_PCRS),
            };
            let rsp = run(&mut rm.tpm, &cmd, &[password_auth(b"")]);
            let attest = rsp.quoted.0;
            assert_eq!(
                attest.extra_data.get_buffer(),
                nonce,
                "round {round}: nonce"
            );
            let tpm2::TpmuAttest::Quote(info) = attest.attested else {
                panic!("round {round}: not a quote");
            };
            assert_eq!(
                info.pcr_digest.get_buffer(),
                expected_digest,
                "round {round}: pcrDigest"
            );
        });
    }

    // 5. A PIN-protected signing key of an application.
    let pin = b"123456";
    let app_key_blob = rm.command(&[srk], |rm, h| {
        let cmd = tpm2::commands::Create {
            parent_handle: h[0],
            in_sensitive: tpm2::Tpm2b(TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::from_bytes(pin).unwrap(),
                data: Tpm2bSensitiveData::default(),
            }),
            in_public: tpm2::Tpm2b(crate::_common::ecc_signing_template(TpmiAlgHash::Sha256)),
            outside_info: Default::default(),
            creation_pcr: Default::default(),
        };
        let rsp = crate::_common::execute_with_hmac_sessions(
            &mut rm.tpm,
            &cmd,
            &[&srk_name],
            core::slice::from_mut(&mut hmac_session),
            &[b""],
        )
        .unwrap_or_else(|rc| panic!("TPM2_Create (application key): {rc:#x}"));
        (rsp.out_private, rsp.out_public)
    });
    let app_key = rm.command(&[srk], |rm, h| {
        let cmd = tpm2::commands::Load {
            parent_handle: h[0],
            in_private: app_key_blob.0,
            in_public: app_key_blob.1,
        };
        let rsp = run(&mut rm.tpm, &cmd, &[password_auth(b"")]);
        rm.adopt_object(rsp.object_handle, rsp.name.get_buffer())
    });
    let app_key_name = rm.name(app_key);
    // Signs `digest` (with the hash check ticket `validation`) with the PIN through the HMAC
    // session and verifies the signature.
    let mut sign_and_verify = |rm: &mut ResourceManager,
                               digest: Vec<u8>,
                               validation: TpmtTkHashcheck<'static>| {
        // The PIN and the digest go in encrypted; the response of TPM2_Sign (a
        // `TPMT_SIGNATURE`, not a sized buffer) cannot be encrypted (`TPM_RC_ATTRIBUTES`),
        // so the TSS does not ask for it.
        hmac_session.attributes = tpm2::TpmaSession::CONTINUE_SESSION | tpm2::TpmaSession::DECRYPT;
        let signature = rm.command(&[app_key], |rm, h| {
            let cmd = Sign {
                key_handle: h[0],
                digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
                in_scheme: None,
                validation,
            };
            crate::_common::execute_with_hmac_sessions(
                &mut rm.tpm,
                &cmd,
                &[&app_key_name],
                core::slice::from_mut(&mut hmac_session),
                &[pin],
            )
            .unwrap_or_else(|rc| panic!("TPM2_Sign: {rc:#x}"))
            .signature
        });
        hmac_session.attributes = tpm2::TpmaSession::CONTINUE_SESSION
            | tpm2::TpmaSession::DECRYPT
            | tpm2::TpmaSession::ENCRYPT;
        rm.command(&[app_key], |rm, h| {
            let cmd = tpm2::commands::VerifySignature {
                key_handle: h[0],
                digest: Tpm2bDigest::from_bytes(&digest).unwrap(),
                signature,
            };
            run(&mut rm.tpm, &cmd, &[]);
        });
    };
    for message in 0..6u8 {
        let data: Vec<u8> = (0..200 + 40 * message as usize)
            .map(|i| (i as u8).wrapping_add(message))
            .collect();
        let (digest, validation) = rm.command(&[], |rm, _| {
            let cmd = tpm2::commands::Hash {
                data: Tpm2bMaxBuffer::from_bytes(&data).unwrap(),
                hash_alg: TpmiAlgHash::Sha256,
                hierarchy: Handle::RH_OWNER,
            };
            let rsp = run(&mut rm.tpm, &cmd, &[]);
            (rsp.out_hash.get_buffer().to_vec(), rsp.validation)
        });
        assert_eq!(digest, client_hash(TpmiAlgHash::Sha256, &data));
        sign_and_verify(&mut rm, digest, validation);
    }
    // A document larger than a command buffer, hashed with a sequence.
    let document: Vec<u8> = (0..4 * 1024 + 123)
        .map(|i| (i * 7 + i / 255) as u8)
        .collect();
    let sequence = rm.command(&[], |rm, _| {
        let start = HashSequenceStart {
            auth: Tpm2bAuth::default(),
            hash_alg: Some(TpmiAlgHash::Sha256),
        };
        let handle = run(&mut rm.tpm, &start, &[]).sequence_handle;
        rm.adopt_object(handle, &handle.0.to_be_bytes())
    });
    let (chunks, last) = document.split_at(document.len() - 123);
    for chunk in chunks.chunks(1024) {
        rm.command(&[sequence], |rm, h| {
            let cmd = SequenceUpdate {
                sequence_handle: h[0],
                buffer: Tpm2bMaxBuffer::from_bytes(chunk).unwrap(),
            };
            run(&mut rm.tpm, &cmd, &[password_auth(b"")]);
        });
    }
    let (digest, validation) = rm.command(&[sequence], |rm, h| {
        let cmd = SequenceComplete {
            sequence_handle: h[0],
            buffer: Tpm2bMaxBuffer::from_bytes(last).unwrap(),
            hierarchy: Handle::RH_OWNER,
        };
        let rsp = run(&mut rm.tpm, &cmd, &[password_auth(b"")]);
        // The sequence ends with the command.
        rm.loaded.retain(|(_, handle)| *handle != h[0]);
        (rsp.result.get_buffer().to_vec(), rsp.validation)
    });
    rm.close(sequence);
    assert_eq!(digest, client_hash(TpmiAlgHash::Sha256, &document));
    sign_and_verify(&mut rm, digest, validation);

    // 6. A second volume is unlocked with the same sealed key.
    assert_eq!(unlock_disk(&mut rm, sealed), disk_key, "unsealed disk key");

    assert!(rm.commands > 100, "{} commands", rm.commands);
    assert!(
        rm.context_loads > rm.commands,
        "{} context loads",
        rm.context_loads
    );
}
