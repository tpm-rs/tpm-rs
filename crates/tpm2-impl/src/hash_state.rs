//! Portable, backend-independent streaming SHA-1, SHA-256, SHA-384, and SHA-512 state
//! machine matching `HASH_STATE` / `HASH_OBJECT` in `ibmswtpm2` (`CryptHash.h`).
//!
//! Storing explicit SHA state registers (`h`), processed byte count (`total_len`),
//! and incomplete block buffer (`block_buf`) allows in-flight cryptographic sequences
//! (`TPM2_HashSequenceStart`, `TPM2_HMAC_Start`, `TPM2_EventSequenceStart`) to be
//! seamlessly serialized, migrated across `ibmswtpm2` and `tpm_rs`, or saved/restored
//! via `TPM2_ContextSave` / `TPM2_ContextLoad`.

use tpm2::TpmiAlgHash;

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const K512: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// Portable streaming hash context matching `HASH_STATE` in `ibmswtpm2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamingHashState {
    /// Hash algorithm selector.
    pub alg: TpmiAlgHash,
    /// Intermediate SHA state registers ($H_0..H_7$).
    /// - SHA-1 uses `h[0..5]` (32-bit values stored in `u64`).
    /// - SHA-256 uses `h[0..8]` (32-bit values stored in `u64`).
    /// - SHA-384 / SHA-512 use `h[0..8]` (64-bit values).
    pub h: [u64; 8],
    /// Total bytes processed so far across all updates.
    pub total_len: u64,
    /// Unprocessed partial block buffer (up to 64 bytes for SHA-1/256, 128 bytes for SHA-384/512).
    pub block_buf: [u8; 128],
    /// Number of valid bytes currently buffered in `block_buf`.
    pub block_len: usize,
}

impl Default for StreamingHashState {
    fn default() -> Self {
        Self::new(TpmiAlgHash::Sha256)
    }
}

impl StreamingHashState {
    /// Serialized byte length of a single `StreamingHashState`.
    pub const SERIALIZED_SIZE: usize = 2 + 64 + 8 + 2 + 128;

    /// Initializes a new streaming hash state with FIPS 180-4 initial hash values ($H^{(0)}$).
    pub fn new(alg: TpmiAlgHash) -> Self {
        let h = match alg {
            TpmiAlgHash::Sha1 => [
                0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0, 0, 0, 0,
            ],
            TpmiAlgHash::Sha256 => [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            TpmiAlgHash::Sha384 => [
                0xcbbb9d5dc1059ed8,
                0x629a292a367cd507,
                0x9159015a3070dd17,
                0x152fecd8f70e5939,
                0x67332667ffc00b31,
                0x8eb44a8768581511,
                0xdb0c2e0d64f98fa7,
                0x47b5481dbefa4fa4,
            ],
            TpmiAlgHash::Sha512 => [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ],
            _ => [0; 8],
        };
        Self {
            alg,
            h,
            total_len: 0,
            block_buf: [0u8; 128],
            block_len: 0,
        }
    }

    /// Returns the block size in bytes for the algorithm (`64` for SHA-1/256, `128` for SHA-384/512).
    pub const fn block_size(&self) -> usize {
        match self.alg {
            TpmiAlgHash::Sha384 | TpmiAlgHash::Sha512 => 128,
            _ => 64,
        }
    }

    /// Returns the digest size in bytes for the algorithm.
    pub const fn digest_size(&self) -> usize {
        match self.alg {
            TpmiAlgHash::Sha1 => 20,
            TpmiAlgHash::Sha256 => 32,
            TpmiAlgHash::Sha384 => 48,
            TpmiAlgHash::Sha512 => 64,
            _ => 0,
        }
    }

    /// Updates the streaming hash state with a slice of input bytes.
    pub fn update(&mut self, mut data: &[u8]) {
        let blk_size = self.block_size();
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        if self.block_len > 0 {
            let needed = blk_size - self.block_len;
            if data.len() < needed {
                self.block_buf[self.block_len..self.block_len + data.len()].copy_from_slice(data);
                self.block_len += data.len();
                return;
            }
            self.block_buf[self.block_len..blk_size].copy_from_slice(&data[..needed]);
            let block = self.block_buf;
            self.compress_block(&block[..blk_size]);
            self.block_len = 0;
            data = &data[needed..];
        }

        while data.len() >= blk_size {
            self.compress_block(&data[..blk_size]);
            data = &data[blk_size..];
        }

        if !data.is_empty() {
            self.block_buf[..data.len()].copy_from_slice(data);
            self.block_len = data.len();
        }
    }

    /// Finalizes the hash computation and returns the digest bytes and digest length.
    pub fn finalize(&self) -> ([u8; 64], usize) {
        let mut state = *self;
        let blk_size = state.block_size();
        let bit_len = (state.total_len as u128) * 8;

        // Append 0x80 byte
        state.block_buf[state.block_len] = 0x80;
        state.block_len += 1;

        let len_bytes = if blk_size == 128 { 16 } else { 8 };
        if state.block_len + len_bytes > blk_size {
            for b in &mut state.block_buf[state.block_len..blk_size] {
                *b = 0;
            }
            let block = state.block_buf;
            state.compress_block(&block[..blk_size]);
            state.block_len = 0;
        }

        for b in &mut state.block_buf[state.block_len..blk_size - len_bytes] {
            *b = 0;
        }

        if blk_size == 128 {
            state.block_buf[blk_size - 16..blk_size].copy_from_slice(&bit_len.to_be_bytes());
        } else {
            state.block_buf[blk_size - 8..blk_size]
                .copy_from_slice(&(bit_len as u64).to_be_bytes());
        }
        let block = state.block_buf;
        state.compress_block(&block[..blk_size]);

        let mut out = [0u8; 64];
        let digest_len = state.digest_size();
        match state.alg {
            TpmiAlgHash::Sha1 => {
                for i in 0..5 {
                    out[i * 4..(i + 1) * 4].copy_from_slice(&(state.h[i] as u32).to_be_bytes());
                }
            }
            TpmiAlgHash::Sha256 => {
                for i in 0..8 {
                    out[i * 4..(i + 1) * 4].copy_from_slice(&(state.h[i] as u32).to_be_bytes());
                }
            }
            TpmiAlgHash::Sha384 => {
                for i in 0..6 {
                    out[i * 8..(i + 1) * 8].copy_from_slice(&state.h[i].to_be_bytes());
                }
            }
            TpmiAlgHash::Sha512 => {
                for i in 0..8 {
                    out[i * 8..(i + 1) * 8].copy_from_slice(&state.h[i].to_be_bytes());
                }
            }
            _ => {}
        }
        (out, digest_len)
    }

    /// Serializes the `StreamingHashState` into a fixed 204-byte buffer.
    pub fn serialize(&self, dst: &mut [u8]) -> usize {
        let alg_raw: u16 = tpm2::Alg::from(self.alg).into();
        dst[0..2].copy_from_slice(&alg_raw.to_be_bytes());
        let mut offset = 2;
        for reg in &self.h {
            dst[offset..offset + 8].copy_from_slice(&reg.to_be_bytes());
            offset += 8;
        }
        dst[offset..offset + 8].copy_from_slice(&self.total_len.to_be_bytes());
        offset += 8;
        dst[offset..offset + 2].copy_from_slice(&(self.block_len as u16).to_be_bytes());
        offset += 2;
        dst[offset..offset + 128].copy_from_slice(&self.block_buf);
        offset += 128;
        offset
    }

    /// Deserializes a `StreamingHashState` from a 204-byte slice.
    pub fn deserialize(src: &[u8]) -> Option<Self> {
        if src.len() < Self::SERIALIZED_SIZE {
            return None;
        }
        let alg_raw = u16::from_be_bytes([src[0], src[1]]);
        let alg = TpmiAlgHash::try_from(alg_raw).unwrap_or(TpmiAlgHash::Sha256);
        let mut offset = 2;
        let mut h = [0u64; 8];
        for reg in &mut h {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&src[offset..offset + 8]);
            *reg = u64::from_be_bytes(bytes);
            offset += 8;
        }
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&src[offset..offset + 8]);
        let total_len = u64::from_be_bytes(len_bytes);
        offset += 8;

        let block_len = u16::from_be_bytes([src[offset], src[offset + 1]]) as usize;
        offset += 2;
        if block_len > 128 {
            return None;
        }
        let mut block_buf = [0u8; 128];
        block_buf.copy_from_slice(&src[offset..offset + 128]);
        Some(Self {
            alg,
            h,
            total_len,
            block_buf,
            block_len,
        })
    }

    fn compress_block(&mut self, block: &[u8]) {
        match self.alg {
            TpmiAlgHash::Sha1 => self.compress_sha1(block),
            TpmiAlgHash::Sha256 => self.compress_sha256(block),
            TpmiAlgHash::Sha384 | TpmiAlgHash::Sha512 => self.compress_sha512(block),
            _ => {}
        }
    }

    fn compress_sha1(&mut self, block: &[u8]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = self.h[0] as u32;
        let mut b = self.h[1] as u32;
        let mut c = self.h[2] as u32;
        let mut d = self.h[3] as u32;
        let mut e = self.h[4] as u32;

        for (i, &wt) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a827999_u32),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1_u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc_u32),
                _ => (b ^ c ^ d, 0xca62c1d6_u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wt);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.h[0] = (self.h[0] as u32).wrapping_add(a) as u64;
        self.h[1] = (self.h[1] as u32).wrapping_add(b) as u64;
        self.h[2] = (self.h[2] as u32).wrapping_add(c) as u64;
        self.h[3] = (self.h[3] as u32).wrapping_add(d) as u64;
        self.h[4] = (self.h[4] as u32).wrapping_add(e) as u64;
    }

    fn compress_sha256(&mut self, block: &[u8]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.h[0] as u32;
        let mut b = self.h[1] as u32;
        let mut c = self.h[2] as u32;
        let mut d = self.h[3] as u32;
        let mut e = self.h[4] as u32;
        let mut f = self.h[5] as u32;
        let mut g = self.h[6] as u32;
        let mut h = self.h[7] as u32;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.h[0] = (self.h[0] as u32).wrapping_add(a) as u64;
        self.h[1] = (self.h[1] as u32).wrapping_add(b) as u64;
        self.h[2] = (self.h[2] as u32).wrapping_add(c) as u64;
        self.h[3] = (self.h[3] as u32).wrapping_add(d) as u64;
        self.h[4] = (self.h[4] as u32).wrapping_add(e) as u64;
        self.h[5] = (self.h[5] as u32).wrapping_add(f) as u64;
        self.h[6] = (self.h[6] as u32).wrapping_add(g) as u64;
        self.h[7] = (self.h[7] as u32).wrapping_add(h) as u64;
    }

    fn compress_sha512(&mut self, block: &[u8]) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&block[i * 8..(i + 1) * 8]);
            w[i] = u64::from_be_bytes(bytes);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];

        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K512[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
}

/// Computes an HMAC using `StreamingHashState` given a key, hash algorithm, and an already-updated
/// inner `StreamingHashState` (which was initialized with `ipad` at `MACStart`).
pub fn finalize_hmac_from_inner_state(
    hash_alg: TpmiAlgHash,
    key: &[u8],
    inner_state: &StreamingHashState,
) -> ([u8; 64], usize) {
    let (inner_digest, digest_len) = inner_state.finalize();
    let blk_size = inner_state.block_size();

    let mut k_prime = [0u8; 128];
    if key.len() > blk_size {
        let mut key_hash = StreamingHashState::new(hash_alg);
        key_hash.update(key);
        let (kh, kh_len) = key_hash.finalize();
        k_prime[..kh_len].copy_from_slice(&kh[..kh_len]);
    } else {
        k_prime[..key.len()].copy_from_slice(key);
    }

    let mut opad = [0x5cu8; 128];
    for i in 0..blk_size {
        opad[i] ^= k_prime[i];
    }

    let mut outer_state = StreamingHashState::new(hash_alg);
    outer_state.update(&opad[..blk_size]);
    outer_state.update(&inner_digest[..digest_len]);
    outer_state.finalize()
}

/// Initializes an inner `StreamingHashState` for HMAC by feeding `ipad` (`k_prime ^ 0x36`).
pub fn init_hmac_inner_state(hash_alg: TpmiAlgHash, key: &[u8]) -> StreamingHashState {
    let mut state = StreamingHashState::new(hash_alg);
    let blk_size = state.block_size();

    let mut k_prime = [0u8; 128];
    if key.len() > blk_size {
        let mut key_hash = StreamingHashState::new(hash_alg);
        key_hash.update(key);
        let (kh, kh_len) = key_hash.finalize();
        k_prime[..kh_len].copy_from_slice(&kh[..kh_len]);
    } else {
        k_prime[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 128];
    for i in 0..blk_size {
        ipad[i] ^= k_prime[i];
    }

    state.update(&ipad[..blk_size]);
    state
}
