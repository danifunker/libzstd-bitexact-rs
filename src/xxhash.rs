//! XXH64, as used by Zstandard for frame content checksums.
//!
//! Zstandard stores the low 32 bits of `XXH64(decompressed_frame, seed=0)` in
//! the frame footer when the checksum flag is set.

const PRIME1: u64 = 0x9E37_79B1_85EB_CA87;
const PRIME2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const PRIME3: u64 = 0x1656_67B1_9E37_79F9;
const PRIME4: u64 = 0x85EB_CA77_C2B2_AE63;
const PRIME5: u64 = 0x27D4_EB2F_1656_67C5;

#[inline]
fn round(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(PRIME2))
        .rotate_left(31)
        .wrapping_mul(PRIME1)
}

#[inline]
fn merge_round(hash: u64, acc: u64) -> u64 {
    (hash ^ round(0, acc))
        .wrapping_mul(PRIME1)
        .wrapping_add(PRIME4)
}

#[inline]
fn read_u64(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

#[inline]
fn read_u32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
}

/// One-shot XXH64.
pub(crate) fn xxh64(data: &[u8], seed: u64) -> u64 {
    let len = data.len();
    let mut pos = 0;

    let mut hash = if len >= 32 {
        let mut v1 = seed.wrapping_add(PRIME1).wrapping_add(PRIME2);
        let mut v2 = seed.wrapping_add(PRIME2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME1);
        while pos + 32 <= len {
            v1 = round(v1, read_u64(data, pos));
            v2 = round(v2, read_u64(data, pos + 8));
            v3 = round(v3, read_u64(data, pos + 16));
            v4 = round(v4, read_u64(data, pos + 24));
            pos += 32;
        }
        let mut h = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        h = merge_round(h, v1);
        h = merge_round(h, v2);
        h = merge_round(h, v3);
        merge_round(h, v4)
    } else {
        seed.wrapping_add(PRIME5)
    };

    hash = hash.wrapping_add(len as u64);

    while pos + 8 <= len {
        hash ^= round(0, read_u64(data, pos));
        hash = hash
            .rotate_left(27)
            .wrapping_mul(PRIME1)
            .wrapping_add(PRIME4);
        pos += 8;
    }
    if pos + 4 <= len {
        hash ^= u64::from(read_u32(data, pos)).wrapping_mul(PRIME1);
        hash = hash
            .rotate_left(23)
            .wrapping_mul(PRIME2)
            .wrapping_add(PRIME3);
        pos += 4;
    }
    while pos < len {
        hash ^= u64::from(data[pos]).wrapping_mul(PRIME5);
        hash = hash.rotate_left(11).wrapping_mul(PRIME1);
        pos += 1;
    }

    hash ^= hash >> 33;
    hash = hash.wrapping_mul(PRIME2);
    hash ^= hash >> 29;
    hash = hash.wrapping_mul(PRIME3);
    hash ^ (hash >> 32)
}

/// Incremental XXH64, for checksumming a frame's output as it is produced.
///
/// The streaming decoder evicts decoded bytes from its window once they pass
/// out of reach, so it cannot hash the whole frame at the end the way the
/// one-shot [`xxh64`] does; it feeds each block's output through `update` and
/// finalizes with `digest`. `digest` reproduces [`xxh64`] exactly: the same
/// four-lane combine for inputs of 32 bytes or more, the same `seed + PRIME5`
/// path for shorter ones, and the same 8/4/1-byte tail.
pub(crate) struct Xxh64 {
    v: [u64; 4],
    /// Bytes not yet formed into a full 32-byte stripe; always
    /// `total_len % 32` of them.
    buf: [u8; 32],
    buf_len: usize,
    total_len: u64,
    seed: u64,
}

impl Xxh64 {
    pub(crate) fn new(seed: u64) -> Self {
        Xxh64 {
            v: [
                seed.wrapping_add(PRIME1).wrapping_add(PRIME2),
                seed.wrapping_add(PRIME2),
                seed,
                seed.wrapping_sub(PRIME1),
            ],
            buf: [0; 32],
            buf_len: 0,
            total_len: 0,
            seed,
        }
    }

    fn stripe(&mut self, data: &[u8], at: usize) {
        let a = read_u64(data, at);
        let b = read_u64(data, at + 8);
        let c = read_u64(data, at + 16);
        let d = read_u64(data, at + 24);
        self.v[0] = round(self.v[0], a);
        self.v[1] = round(self.v[1], b);
        self.v[2] = round(self.v[2], c);
        self.v[3] = round(self.v[3], d);
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        // Top off a partially filled stripe buffer first.
        if self.buf_len > 0 {
            let need = 32 - self.buf_len;
            if data.len() < need {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            let (head, rest) = data.split_at(need);
            self.buf[self.buf_len..].copy_from_slice(head);
            let buf = self.buf;
            self.stripe(&buf, 0);
            self.buf_len = 0;
            data = rest;
        }

        // Consume whole stripes straight from the input.
        while data.len() >= 32 {
            self.stripe(data, 0);
            data = &data[32..];
        }

        // Stash the remainder (< 32 bytes) for next time / digest.
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub(crate) fn digest(&self) -> u64 {
        let mut hash = if self.total_len >= 32 {
            let [v1, v2, v3, v4] = self.v;
            let mut h = v1
                .rotate_left(1)
                .wrapping_add(v2.rotate_left(7))
                .wrapping_add(v3.rotate_left(12))
                .wrapping_add(v4.rotate_left(18));
            h = merge_round(h, v1);
            h = merge_round(h, v2);
            h = merge_round(h, v3);
            merge_round(h, v4)
        } else {
            self.seed.wrapping_add(PRIME5)
        };

        hash = hash.wrapping_add(self.total_len);

        let data = &self.buf[..self.buf_len];
        let len = self.buf_len;
        let mut pos = 0;
        while pos + 8 <= len {
            hash ^= round(0, read_u64(data, pos));
            hash = hash
                .rotate_left(27)
                .wrapping_mul(PRIME1)
                .wrapping_add(PRIME4);
            pos += 8;
        }
        if pos + 4 <= len {
            hash ^= u64::from(read_u32(data, pos)).wrapping_mul(PRIME1);
            hash = hash
                .rotate_left(23)
                .wrapping_mul(PRIME2)
                .wrapping_add(PRIME3);
            pos += 4;
        }
        while pos < len {
            hash ^= u64::from(data[pos]).wrapping_mul(PRIME5);
            hash = hash.rotate_left(11).wrapping_mul(PRIME1);
            pos += 1;
        }

        hash ^= hash >> 33;
        hash = hash.wrapping_mul(PRIME2);
        hash ^= hash >> 29;
        hash = hash.wrapping_mul(PRIME3);
        hash ^ (hash >> 32)
    }
}

#[cfg(test)]
mod tests {
    use super::{Xxh64, xxh64};

    #[test]
    fn known_vectors() {
        assert_eq!(xxh64(b"", 0), 0xEF46_DB37_51D8_E999);
        assert_eq!(xxh64(b"abc", 0), 0x44BC_2CF5_AD77_0999);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        // Every length crosses the <32 / >=32 boundary and assorted tails.
        for len in [0usize, 1, 7, 8, 31, 32, 33, 40, 64, 257, 1000] {
            let expected = xxh64(&data[..len], 0);
            // Feed the same bytes in a variety of chunkings.
            for chunk in [1usize, 3, 8, 13, 32, 33, 64, 999] {
                let mut h = Xxh64::new(0);
                for part in data[..len].chunks(chunk) {
                    h.update(part);
                }
                assert_eq!(h.digest(), expected, "len {len}, chunk {chunk}");
            }
        }
    }

    #[test]
    fn covers_all_tail_paths() {
        // Exercise the 32-byte stripe loop plus every tail combination.
        let data: Vec<u8> = (0..=255u8).collect();
        for len in [0, 1, 3, 4, 5, 8, 11, 16, 31, 32, 33, 63, 64, 100, 255] {
            // No assertion against fixed values here (covered end-to-end by
            // checksum verification in the differential tests); this only
            // checks determinism and absence of panics on every code path.
            assert_eq!(xxh64(&data[..len], 0), xxh64(&data[..len], 0));
        }
    }
}
