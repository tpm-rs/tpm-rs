//! The FFI shell shared by the reference binaries (`mstpm20`, `ibmswtpm2`):
//! the entry points of the linked, patched C reference TPM (`difftest_*`,
//! exported by the symbol-isolated static library `testing/build.rs` links
//! into exactly one binary), the callbacks the patches call back into, and
//! the stdout takeover. This is the only `unsafe` code of the crate; all
//! logic lives in the safe [`testing::differential::server`].

#![allow(unsafe_code)]

use std::io::BufReader;

use testing::differential::Implementation;
use testing::differential::server::{
    self, ActiveRefState, Backend, DeriveKeyRequest, Signal, derive_object_cached,
    with_active_state,
};

unsafe extern "C" {
    fn difftest_init();
    fn difftest_advance_clock(ms: u64);
    fn difftest_signal_power_on();
    fn difftest_signal_power_off();
    fn difftest_signal_reset();
    fn difftest_signal_nv_on();
    fn difftest_signal_nv_off();
    fn difftest_signal_physical_presence_on();
    fn difftest_signal_physical_presence_off();
    fn difftest_signal_cancel_on();
    fn difftest_signal_cancel_off();
    fn difftest_signal_hash_start();
    fn difftest_signal_hash_data(data: *const u8, size: u32);
    fn difftest_signal_hash_end();
    fn difftest_run_command(
        locality: u8,
        in_buf: *const u8,
        in_size: u32,
        out_buf: *mut u8,
        out_cap: u32,
    ) -> u32;
}

unsafe extern "C" {
    fn dup(fd: i32) -> i32;
    fn dup2(old_fd: i32, new_fd: i32) -> i32;
}

/// Takes over stdout as the protocol channel: returns a file for the
/// original stdout and points file descriptor 1 at stderr, so output of
/// the C code cannot corrupt the protocol.
pub fn take_stdout() -> std::fs::File {
    use std::os::fd::FromRawFd as _;
    let fd = unsafe { dup(1) };
    assert!(fd >= 0, "dup(stdout) failed");
    assert!(unsafe { dup2(2, 1) } >= 0, "dup2(stderr, stdout) failed");
    unsafe { std::fs::File::from_raw_fd(fd) }
}

#[unsafe(no_mangle)]
pub extern "C" fn difftest_virtual_ms() -> u64 {
    with_active_state(|st| st.virtual_ms).unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn difftest_plat_rng_fill(buf: *mut u8, len: u16) {
    if buf.is_null() || len == 0 {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len as usize) };
    with_active_state(|st| {
        st.fill_plat_rng(slice);
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn difftest_take_nonce(size: u16, buffer: *mut u8) -> i32 {
    if buffer.is_null() || size == 0 {
        return 0;
    }
    let slice = unsafe { std::slice::from_raw_parts_mut(buffer, size as usize) };
    with_active_state(|st| i32::from(st.take_nonce(slice))).unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn difftest_peek_nonce(index: u32, size: u16, buffer: *mut u8) -> i32 {
    if buffer.is_null() || size == 0 {
        return 0;
    }
    let slice = unsafe { std::slice::from_raw_parts_mut(buffer, size as usize) };
    with_active_state(|st| i32::from(st.peek_nonce(index as usize, slice))).unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn difftest_will_override_object() -> i32 {
    with_active_state(|st| i32::from(st.will_override_object)).unwrap_or(0)
}

/// Lower bound on the capacity of `ContextLoad_In.context.contextBlob.t.buffer`
/// in the patched C reference: `sizeof(TPMS_CONTEXT_DATA)` contains a
/// `TPM2B_CONTEXT_SENSITIVE` of `MAX_CONTEXT_SIZE` (2264 in the patched
/// profile) plus the integrity digest, so 2264 bytes are always writable.
const C_CONTEXT_BLOB_CAPACITY: usize = 2264;

#[unsafe(no_mangle)]
pub extern "C" fn difftest_translate_context_blob(size: *mut u16, buffer: *mut u8) {
    if size.is_null() || buffer.is_null() {
        return;
    }
    let cur_size = unsafe { *size } as usize;
    if cur_size > C_CONTEXT_BLOB_CAPACITY {
        // Not a blob C could have produced; leave it for C to reject.
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts_mut(buffer, C_CONTEXT_BLOB_CAPACITY) };
    let incoming = slice[..cur_size].to_vec();
    with_active_state(|st| {
        if let Some(new_len) = st.translate_context_blob(&incoming, slice) {
            unsafe {
                *size = new_len as u16;
            }
        }
    });
}

fn copy_opt_bytes(
    size: *mut u16,
    buf: *mut u8,
    take_fn: impl FnOnce(&mut ActiveRefState) -> Option<Vec<u8>>,
) -> i32 {
    if size.is_null() || buf.is_null() {
        return 0;
    }
    with_active_state(|st| {
        let Some(bytes) = take_fn(st) else {
            return 0;
        };
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
            *size = bytes.len() as u16;
        }
        1
    })
    .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn difftest_get_recorded_ordinary_object(
    pub_size: *mut u16,
    pub_buf: *mut u8,
    priv_size: *mut u16,
    priv_buf: *mut u8,
) -> i32 {
    if pub_size.is_null() || pub_buf.is_null() || priv_size.is_null() || priv_buf.is_null() {
        return 0;
    }
    with_active_state(|st| {
        let Some((pub_bytes, priv_bytes)) = st.recorded_ordinary_object.take() else {
            return 0;
        };
        unsafe {
            std::ptr::copy_nonoverlapping(pub_bytes.as_ptr(), pub_buf, pub_bytes.len());
            *pub_size = pub_bytes.len() as u16;
            std::ptr::copy_nonoverlapping(priv_bytes.as_ptr(), priv_buf, priv_bytes.len());
            *priv_size = priv_bytes.len() as u16;
        }
        1
    })
    .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn difftest_get_recorded_signature(size: *mut u16, buf: *mut u8) -> i32 {
    copy_opt_bytes(size, buf, |st| st.recorded_signature.take())
}

#[unsafe(no_mangle)]
pub extern "C" fn difftest_get_recorded_secret(size: *mut u16, buf: *mut u8) -> i32 {
    copy_opt_bytes(size, buf, |st| st.recorded_secret.take())
}

#[unsafe(no_mangle)]
pub extern "C" fn difftest_get_recorded_inner_sym_key(size: *mut u16, buf: *mut u8) -> i32 {
    copy_opt_bytes(size, buf, |st| st.recorded_inner_sym_key.take())
}

#[unsafe(no_mangle)]
pub extern "C" fn difftest_get_recorded_rsa_encrypt(size: *mut u16, buf: *mut u8) -> i32 {
    copy_opt_bytes(size, buf, |st| st.recorded_rsa_encrypt.take())
}

#[unsafe(no_mangle)]
pub extern "C" fn difftest_get_recorded_ecdh(
    z_size: *mut u16,
    z_buf: *mut u8,
    pub_size: *mut u16,
    pub_buf: *mut u8,
) -> i32 {
    if z_size.is_null() || z_buf.is_null() || pub_size.is_null() || pub_buf.is_null() {
        return 0;
    }
    with_active_state(|st| {
        let Some((z_bytes, pub_bytes)) = st.recorded_ecdh.take() else {
            return 0;
        };
        unsafe {
            std::ptr::copy_nonoverlapping(z_bytes.as_ptr(), z_buf, z_bytes.len());
            *z_size = z_bytes.len() as u16;
            std::ptr::copy_nonoverlapping(pub_bytes.as_ptr(), pub_buf, pub_bytes.len());
            *pub_size = pub_bytes.len() as u16;
        }
        1
    })
    .unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub extern "C" fn difftest_derive_object(
    kdf_hash_alg: u16,
    parent_seed: *const u8,
    parent_seed_size: u16,
    label: *const u8,
    label_size: u16,
    context_u: *const u8,
    context_u_size: u16,
    context_v: *const u8,
    context_v_size: u16,
    obj_type: u16,
    name_alg: u16,
    object_attributes: u32,
    key_bits_or_curve: u16,
    fallback_data: *const u8,
    fallback_data_size: u16,
    out_seed_value: *mut u8,
    out_seed_value_size: *mut u16,
    out_private_key: *mut u8,
    out_private_key_size: *mut u16,
    out_unique_x: *mut u8,
    out_unique_x_size: *mut u16,
    out_unique_y: *mut u8,
    out_unique_y_size: *mut u16,
) -> i32 {
    let slice_or_empty = |ptr: *const u8, len: u16| -> &[u8] {
        if ptr.is_null() || len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(ptr, len as usize) }
        }
    };
    let req = DeriveKeyRequest {
        kdf_hash_alg,
        parent_seed: slice_or_empty(parent_seed, parent_seed_size).to_vec(),
        label: slice_or_empty(label, label_size).to_vec(),
        context_u: slice_or_empty(context_u, context_u_size).to_vec(),
        context_v: slice_or_empty(context_v, context_v_size).to_vec(),
        obj_type,
        name_alg,
        object_attributes,
        key_bits_or_curve,
        fallback_data: slice_or_empty(fallback_data, fallback_data_size).to_vec(),
    };
    let Some(derived) = derive_object_cached(&req) else {
        return 0;
    };
    unsafe {
        std::ptr::copy_nonoverlapping(
            derived.seed_value.as_ptr(),
            out_seed_value,
            derived.seed_value.len(),
        );
        *out_seed_value_size = derived.seed_value.len() as u16;

        std::ptr::copy_nonoverlapping(
            derived.private_key.as_ptr(),
            out_private_key,
            derived.private_key.len(),
        );
        *out_private_key_size = derived.private_key.len() as u16;

        std::ptr::copy_nonoverlapping(
            derived.unique_x.as_ptr(),
            out_unique_x,
            derived.unique_x.len(),
        );
        *out_unique_x_size = derived.unique_x.len() as u16;

        std::ptr::copy_nonoverlapping(
            derived.unique_y.as_ptr(),
            out_unique_y,
            derived.unique_y.len(),
        );
        *out_unique_y_size = derived.unique_y.len() as u16;
    }
    1
}

/// The linked C reference TPM.
struct CReference;

impl Backend for CReference {
    fn init(&mut self) {
        unsafe { difftest_init() };
    }

    fn advance_clock(&mut self, ms: u64) {
        unsafe { difftest_advance_clock(ms) };
    }

    fn signal(&mut self, signal: Signal) {
        unsafe {
            match signal {
                Signal::PowerOn => difftest_signal_power_on(),
                Signal::PowerOff => difftest_signal_power_off(),
                Signal::Reset => difftest_signal_reset(),
                Signal::NvOn => difftest_signal_nv_on(),
                Signal::NvOff => difftest_signal_nv_off(),
                Signal::PhysicalPresenceOn => difftest_signal_physical_presence_on(),
                Signal::PhysicalPresenceOff => difftest_signal_physical_presence_off(),
                Signal::CancelOn => difftest_signal_cancel_on(),
                Signal::CancelOff => difftest_signal_cancel_off(),
            }
        }
    }

    fn hash_start(&mut self) {
        unsafe { difftest_signal_hash_start() };
    }

    fn hash_data(&mut self, data: &[u8]) {
        unsafe { difftest_signal_hash_data(data.as_ptr(), data.len() as u32) };
    }

    fn hash_end(&mut self) {
        unsafe { difftest_signal_hash_end() };
    }

    fn run_command(&mut self, locality: u8, command: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 8192];
        let len = unsafe {
            difftest_run_command(
                locality,
                command.as_ptr(),
                command.len() as u32,
                out.as_mut_ptr(),
                out.len() as u32,
            )
        };
        out.truncate(len as usize);
        out
    }
}

/// Runs the reference process of `implementation` (see
/// [`testing::differential::server`]); the first argument names the test.
pub fn main(implementation: Implementation) {
    let test = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "<unknown>".into());
    let output = std::io::BufWriter::new(take_stdout());
    let input = BufReader::new(std::io::stdin().lock());
    server::serve(implementation, CReference, test, input, output);
}
