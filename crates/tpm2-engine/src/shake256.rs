//! Portable, backend-independent streaming SHAKE256 (FIPS 202) state.
//!
//! ML-DSA computes its message representative `mu` with SHAKE256 (FIPS 204, Algorithm 7 line 6),
//! over a message that a signing or verification sequence receives in parts. Like the SHA state
//! machine of [`crate::hash_state`], the state is explicit (the Keccak-f\[1600\] lanes and the
//! number of bytes absorbed into the current block), so that a running computation can be
//! exported in the form of OpenSSL's `KECCAK1600_CTX` ([`Shake256::to_openssl`]) and restored
//! ([`Shake256::from_openssl`]) by `TPM2_ContextSave`/`TPM2_ContextLoad`.

/// The SHAKE256 rate (block size) in bytes: `(1600 - 2 * 256) / 8`.
pub(crate) const SHAKE256_RATE: usize = 136;

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// The rotation offsets of the rho step, in the order of the pi step's lane walk.
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// The lane walk of the pi step (starting from lane 1).
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// Keccak-f\[1600\] (FIPS 202, Section 3.3) on `lanes` (lane `(x, y)` at index `x + 5 * y`).
fn keccak_f1600(lanes: &mut [u64; 25]) {
    for round_constant in ROUND_CONSTANTS {
        // theta
        let mut c = [0u64; 5];
        for (x, cx) in c.iter_mut().enumerate() {
            *cx = lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                lanes[x + 5 * y] ^= d;
            }
        }
        // rho and pi
        let mut current = lanes[1];
        for (&target, &rotation) in PI.iter().zip(RHO.iter()) {
            let next = lanes[target];
            lanes[target] = current.rotate_left(rotation);
            current = next;
        }
        // chi
        for y in 0..5 {
            let row = [
                lanes[5 * y],
                lanes[5 * y + 1],
                lanes[5 * y + 2],
                lanes[5 * y + 3],
                lanes[5 * y + 4],
            ];
            for x in 0..5 {
                lanes[5 * y + x] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
            }
        }
        // iota
        lanes[0] ^= round_constant;
    }
}

/// A running SHAKE256 computation (absorbing phase).
///
/// Like OpenSSL's `KECCAK1600_CTX` (`A`, `buf`, `bufsz`), the lanes hold only the blocks absorbed
/// so far and the bytes of the current, incomplete block are kept in `buf` until the block is
/// complete, so that the state can also be exported in the form of the TCG reference's
/// `OPENSSL_EXPORTED_SHAKE_STATE` ([`Shake256::to_openssl`]).
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Shake256 {
    /// The Keccak-f\[1600\] lanes after the last complete block (OpenSSL's `A`).
    lanes: [u64; 25],
    /// The bytes of the current block (`buf[..position]`; OpenSSL's `buf`).
    buf: [u8; SHAKE256_RATE],
    /// The number of bytes absorbed into the current block (`< SHAKE256_RATE`; OpenSSL's
    /// `bufsz`).
    position: usize,
}

impl Default for Shake256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Shake256 {
    /// A new computation (nothing absorbed).
    pub(crate) const fn new() -> Self {
        Self {
            lanes: [0; 25],
            buf: [0; SHAKE256_RATE],
            position: 0,
        }
    }

    /// XORs `byte` into `lanes` at byte offset `index` (lanes are little-endian).
    fn xor_byte(lanes: &mut [u64; 25], index: usize, byte: u8) {
        lanes[index / 8] ^= u64::from(byte) << (8 * (index % 8));
    }

    /// The lanes with the bytes of the current block XORed in.
    fn absorbed_lanes(&self) -> [u64; 25] {
        let mut lanes = self.lanes;
        for (index, &byte) in self.buf[..self.position].iter().enumerate() {
            Self::xor_byte(&mut lanes, index, byte);
        }
        lanes
    }

    /// Absorbs `data`.
    pub(crate) fn update(&mut self, data: &[u8]) {
        for &byte in data {
            self.buf[self.position] = byte;
            self.position += 1;
            if self.position == SHAKE256_RATE {
                self.lanes = self.absorbed_lanes();
                keccak_f1600(&mut self.lanes);
                self.position = 0;
            }
        }
    }

    /// Finishes the computation and squeezes `out.len()` bytes of output into `out`.
    pub(crate) fn finalize_into(self, out: &mut [u8]) {
        let mut lanes = self.absorbed_lanes();
        // The SHAKE domain separation and pad10*1 (FIPS 202, Sections 5.1 and 6.2).
        Self::xor_byte(&mut lanes, self.position, 0x1f);
        Self::xor_byte(&mut lanes, SHAKE256_RATE - 1, 0x80);
        for block in out.chunks_mut(SHAKE256_RATE) {
            keccak_f1600(&mut lanes);
            for (index, byte) in block.iter_mut().enumerate() {
                *byte = (lanes[index / 8] >> (8 * (index % 8))) as u8;
            }
        }
    }

    /// SHAKE256 of `data`, `out.len()` bytes long.
    pub(crate) fn digest(data: &[u8], out: &mut [u8]) {
        let mut shake = Self::new();
        shake.update(data);
        shake.finalize_into(out);
    }

    /// The state in OpenSSL's form (`KECCAK1600_CTX`, exported by the TCG reference's
    /// `OsslMldsaExportShake256State()`): the 25 lanes of the complete blocks (`A`, 200 octets,
    /// little-endian lanes), the number of bytes of the current block (`bufsz`) and those bytes
    /// (`buf[..bufsz]`).
    pub(crate) fn to_openssl(&self) -> ([u8; 200], usize, &[u8]) {
        let mut a = [0u8; 200];
        for (i, lane) in self.lanes.iter().enumerate() {
            a[i * 8..i * 8 + 8].copy_from_slice(&lane.to_le_bytes());
        }
        (a, self.position, &self.buf[..self.position])
    }

    /// Restores a state in OpenSSL's form ([`Shake256::to_openssl`]), or `None` if `pending` is
    /// not shorter than a block.
    pub(crate) fn from_openssl(a: &[u8; 200], pending: &[u8]) -> Option<Self> {
        if pending.len() >= SHAKE256_RATE {
            return None;
        }
        let mut lanes = [0u64; 25];
        for (i, lane) in lanes.iter_mut().enumerate() {
            let mut le = [0u8; 8];
            le.copy_from_slice(&a[i * 8..i * 8 + 8]);
            *lane = u64::from_le_bytes(le);
        }
        let mut buf = [0u8; SHAKE256_RATE];
        buf[..pending.len()].copy_from_slice(pending);
        Some(Self {
            lanes,
            buf,
            position: pending.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// SHAKE256 of the empty string (FIPS 202 examples), 64 bytes.
    #[test]
    fn empty_message() {
        let mut out = [0u8; 64];
        Shake256::digest(&[], &mut out);
        assert_eq!(
            out,
            hex!(
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
                "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
            )
        );
    }

    /// SHAKE256("abc"), 32 bytes.
    #[test]
    fn abc() {
        let mut out = [0u8; 32];
        Shake256::digest(b"abc", &mut out);
        assert_eq!(
            out,
            hex!("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739")
        );
    }

    /// Absorbing in parts, across block boundaries and through an export/import in OpenSSL's
    /// form, and squeezing more than one block gives the same output as one-shot absorbing.
    #[test]
    fn streaming_and_export_match_one_shot() {
        let data: [u8; 700] = core::array::from_fn(|i| (i * 7 + 3) as u8);
        let mut expected = [0u8; 300];
        Shake256::digest(&data, &mut expected);

        let mut shake = Shake256::new();
        shake.update(&data[..1]);
        shake.update(&data[1..136]);
        shake.update(&data[136..300]);
        let (lanes, bufsz, pending) = shake.to_openssl();
        // 300 = 2 * 136 + 28: two absorbed blocks and 28 pending bytes.
        assert_eq!(bufsz, 28);
        assert_eq!(pending, &data[272..300]);
        let mut shake = Shake256::from_openssl(&lanes, pending).unwrap();
        shake.update(&data[300..]);
        let mut out = [0u8; 300];
        shake.finalize_into(&mut out);
        assert_eq!(out, expected);
    }

    /// A state in OpenSSL's form with a full block pending is rejected.
    #[test]
    fn invalid_export_rejected() {
        let (lanes, _, _) = Shake256::new().to_openssl();
        assert!(Shake256::from_openssl(&lanes, &[0; SHAKE256_RATE]).is_none());
    }
}
