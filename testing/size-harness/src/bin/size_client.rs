//! Freestanding binary-size harness for the `tpm2-client` crate.
//!
//! Exercises command execution with and without authorization sessions over a
//! `#![no_std]` stub [`Connection`] (`tpm2-client` `default-features = false`).

#![no_std]
#![no_main]
#![deny(unsafe_code)]
#![forbid(unreachable_pub)]

use core::hint::black_box;
use core::panic::PanicInfo;

use tpm2::commands::{CreatePrimary, Encapsulate, GetCapability, GetRandom, SignDigest, Startup};
use tpm2::{
    Connection, Handle, PublicParmsAndId, Tpm2b, Tpm2bData, Tpm2bDigest, Tpm2bSensitiveCreate,
    Tpm2bSignatureCtx, TpmCap, TpmSt, TpmSu, TpmaObject, TpmiAlgHash, TpmlPcrSelection,
    TpmsSensitiveCreate, TpmtPublic, TpmtTkHashcheck,
};
use tpm2_client::protocol::RESP_BUFFER_SIZE;
use tpm2_client::sessions::PasswordSession;
use tpm2_client::{run_command, run_command_with_sessions};

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

struct StubConn;

impl Connection for StubConn {
    type Error = !;

    #[inline(never)]
    fn transact<'a>(
        &mut self,
        cmd: &[u8],
        resp: &'a mut [u8],
    ) -> Result<&'a mut [u8], Self::Error> {
        let _ = black_box(cmd);
        let n = black_box(resp.len().min(64));
        Ok(black_box(&mut resp[..n]))
    }
}

#[expect(unsafe_code, reason = "freestanding ELF entry point symbol")]
#[unsafe(no_mangle)]
extern "C" fn _start() -> ! {
    let _ = black_box(measure_client());
    loop {
        core::hint::spin_loop();
    }
}

#[inline(never)]
fn measure_client() -> usize {
    let mut conn = StubConn;
    let mut resp = [0u8; RESP_BUFFER_SIZE];
    let mut acc = 0usize;

    let startup = Startup {
        startup_type: black_box(TpmSu::Clear),
    };
    if run_command(&startup, &mut conn, &mut resp).is_ok() {
        acc = acc.wrapping_add(1);
    }

    let get_random = GetRandom {
        bytes_requested: black_box(32),
    };
    if let Ok(out) = run_command(&get_random, &mut conn, &mut resp) {
        acc = acc.wrapping_add(out.random_bytes.as_slice().len());
    }

    let get_cap = GetCapability {
        capability: black_box(TpmCap::Algs),
        property: black_box(0),
        property_count: black_box(8),
    };
    if let Ok(out) = run_command(&get_cap, &mut conn, &mut resp) {
        acc = acc.wrapping_add(usize::from(out.more_data));
    }

    let encap = Encapsulate {
        key_handle: black_box(Handle::RS_PW),
    };
    if let Ok(out) = run_command(&encap, &mut conn, &mut resp) {
        acc = acc.wrapping_add(out.ciphertext.as_slice().len());
    }

    if let Some(pw) = PasswordSession::new(black_box(b"auth")) {
        let sign = SignDigest {
            key_handle: black_box(Handle::RS_PW),
            context: Tpm2bSignatureCtx::default(),
            digest: Tpm2bDigest::default(),
            validation: TpmtTkHashcheck::Hashcheck(Handle::RS_PW, Tpm2bDigest::default()),
        };
        if let Ok(out) = run_command_with_sessions(&sign, pw, &mut conn, &mut resp) {
            let _ = black_box(out);
            acc = acc.wrapping_add(2);
        }

        let create_primary = CreatePrimary {
            primary_handle: black_box(Handle::RS_PW),
            in_sensitive: Tpm2b(TpmsSensitiveCreate::default()),
            in_public: Tpm2b(TpmtPublic {
                name_alg: Some(TpmiAlgHash::Sha256),
                object_attributes: TpmaObject::empty(),
                auth_policy: Tpm2bDigest::default(),
                parms_and_id: PublicParmsAndId::KeyedHash(None, Tpm2bDigest::default()),
            }),
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        if let Ok(out) = run_command_with_sessions(&create_primary, (pw, pw), &mut conn, &mut resp)
        {
            acc = acc.wrapping_add(out.name.as_slice().len());
        }
    }

    let _ = black_box((TpmSt::HASHCHECK, Tpm2bSensitiveCreate::default()));
    acc
}
