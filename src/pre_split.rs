//! The 1.5.7 pre-block splitter (`zstd_preSplit.c`): decides whether a full
//! 128 KiB block should be cut earlier because its content statistics shift
//! mid-block. `ZSTD_splitBlock` level 0 (`fromBorders`) serves the fast
//! strategy; levels 1..=4 (`byChunks`, 8 KiB granularity) serve the higher
//! strategies. Byte-level fidelity here directly decides block boundaries,
//! which the bit-exact differential tests pin down.

const HASHLOG_MAX: u32 = 10;
const HASHTABLESIZE: usize = 1 << HASHLOG_MAX;
const KNUTH: u32 = 0x9E37_79B9;

const THRESHOLD_PENALTY_RATE: u64 = 16;
const THRESHOLD_BASE: u64 = THRESHOLD_PENALTY_RATE - 2;
const THRESHOLD_PENALTY: i32 = 3;

const CHUNK_SIZE: usize = 8 << 10;
const SEGMENT_SIZE: usize = 512;

/// `Fingerprint`: a histogram of 2-byte-hash events plus the event count.
struct Fingerprint {
    events: Vec<u32>,
    nb_events: u64,
}

impl Fingerprint {
    fn new() -> Self {
        Fingerprint {
            events: vec![0u32; HASHTABLESIZE],
            nb_events: 0,
        }
    }
}

/// `hash2`: hash two bytes (or pass the first byte through when hashLog == 8).
fn hash2(p: &[u8], hash_log: u32) -> usize {
    debug_assert!((8..=HASHLOG_MAX).contains(&hash_log));
    if hash_log == 8 {
        return p[0] as usize;
    }
    let v = u16::from_le_bytes([p[0], p[1]]) as u32;
    (v.wrapping_mul(KNUTH) >> (32 - hash_log)) as usize
}

/// `addEvents_generic`.
fn add_events(fp: &mut Fingerprint, src: &[u8], sampling_rate: usize, hash_log: u32) {
    debug_assert!(src.len() >= 2);
    let limit = src.len() - 2 + 1;
    let mut n = 0usize;
    while n < limit {
        fp.events[hash2(&src[n..], hash_log)] += 1;
        n += sampling_rate;
    }
    fp.nb_events += (limit / sampling_rate) as u64;
}

/// `recordFingerprint_generic`: reset the live part of the table and count one
/// sample window.
fn record_fingerprint(fp: &mut Fingerprint, src: &[u8], sampling_rate: usize, hash_log: u32) {
    fp.events[..1usize << hash_log].fill(0);
    fp.nb_events = 0;
    add_events(fp, src, sampling_rate, hash_log);
}

/// `fpDistance`: cross-normalized L1 distance between two fingerprints.
fn fp_distance(fp1: &Fingerprint, fp2: &Fingerprint, hash_log: u32) -> u64 {
    let mut distance = 0u64;
    for n in 0..(1usize << hash_log) {
        distance += (fp1.events[n] as i64 * fp2.nb_events as i64
            - fp2.events[n] as i64 * fp1.nb_events as i64)
            .unsigned_abs();
    }
    distance
}

/// `compareFingerprints`: true when the two windows look "too different".
fn compare_fingerprints(
    refp: &Fingerprint,
    newfp: &Fingerprint,
    penalty: i32,
    hash_log: u32,
) -> bool {
    debug_assert!(refp.nb_events > 0 && newfp.nb_events > 0);
    let p50 = refp.nb_events * newfp.nb_events;
    let deviation = fp_distance(refp, newfp, hash_log);
    let threshold = p50 * (THRESHOLD_BASE + penalty as u64) / THRESHOLD_PENALTY_RATE;
    deviation >= threshold
}

fn merge_events(acc: &mut Fingerprint, newfp: &Fingerprint) {
    for n in 0..HASHTABLESIZE {
        acc.events[n] += newfp.events[n];
    }
    acc.nb_events += newfp.nb_events;
}

/// `ZSTD_splitBlock_byChunks` (levels 1..=4, passed here as 0..=3): scan in
/// 8 KiB chunks and split at the first chunk whose fingerprint diverges from
/// the accumulated past.
fn split_by_chunks(block: &[u8], level: usize) -> usize {
    const SAMPLING_RATES: [usize; 4] = [43, 11, 5, 1];
    const HASH_PARAMS: [u32; 4] = [8, 9, 10, 10];
    let rate = SAMPLING_RATES[level];
    let hash_log = HASH_PARAMS[level];
    let block_size = block.len();
    debug_assert_eq!(block_size, 128 << 10);

    let mut past = Fingerprint::new();
    let mut newf = Fingerprint::new();
    let mut penalty = THRESHOLD_PENALTY;

    record_fingerprint(&mut past, &block[..CHUNK_SIZE], rate, hash_log);
    let mut pos = CHUNK_SIZE;
    while pos <= block_size - CHUNK_SIZE {
        record_fingerprint(&mut newf, &block[pos..pos + CHUNK_SIZE], rate, hash_log);
        if compare_fingerprints(&past, &newf, penalty, hash_log) {
            return pos;
        }
        merge_events(&mut past, &newf);
        if penalty > 0 {
            penalty -= 1;
        }
        pos += CHUNK_SIZE;
    }
    block_size
}

/// `HIST_add`: plain byte histogram.
fn hist_add(events: &mut [u32], src: &[u8]) {
    for &b in src {
        events[b as usize] += 1;
    }
}

/// `ZSTD_splitBlock_fromBorders` (level 0, the fast-strategy default): compare
/// 512-byte fingerprints at the block borders, and refine against the middle.
fn split_from_borders(block: &[u8]) -> usize {
    let block_size = block.len();
    debug_assert_eq!(block_size, 128 << 10);

    let mut begin = Fingerprint::new();
    let mut end = Fingerprint::new();
    hist_add(&mut begin.events, &block[..SEGMENT_SIZE]);
    hist_add(&mut end.events, &block[block_size - SEGMENT_SIZE..]);
    begin.nb_events = SEGMENT_SIZE as u64;
    end.nb_events = SEGMENT_SIZE as u64;
    if !compare_fingerprints(&begin, &end, 0, 8) {
        return block_size;
    }

    let mut middle = Fingerprint::new();
    let mid_at = block_size / 2 - SEGMENT_SIZE / 2;
    hist_add(&mut middle.events, &block[mid_at..mid_at + SEGMENT_SIZE]);
    middle.nb_events = SEGMENT_SIZE as u64;

    let dist_from_begin = fp_distance(&begin, &middle, 8);
    let dist_from_end = fp_distance(&end, &middle, 8);
    let min_distance = (SEGMENT_SIZE * SEGMENT_SIZE / 3) as u64;
    if dist_from_begin.abs_diff(dist_from_end) < min_distance {
        return 64 << 10;
    }
    if dist_from_begin > dist_from_end {
        32 << 10
    } else {
        96 << 10
    }
}

/// `ZSTD_splitBlock`: `level` is the resolved split level, 0..=4.
pub(crate) fn split_block(block: &[u8], level: usize) -> usize {
    debug_assert!(level <= 4);
    if level == 0 {
        split_from_borders(block)
    } else {
        split_by_chunks(block, level - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Uniform content must not split; a hard statistical boundary must.
    #[test]
    fn split_reacts_to_content_shift() {
        let block_size = 128 << 10;
        let uniform = vec![b'x'; block_size];
        assert_eq!(split_block(&uniform, 0), block_size);

        // First half text-like, second half binary-ish: borders differ.
        let mut shifted = Vec::with_capacity(block_size);
        while shifted.len() < block_size / 2 {
            shifted.extend_from_slice(b"plain english words here ");
        }
        shifted.truncate(block_size / 2);
        let mut s = 0x1234_5678_9ABC_DEF0u64;
        while shifted.len() < block_size {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            shifted.extend_from_slice(&s.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes());
        }
        shifted.truncate(block_size);
        let cut = split_block(&shifted, 0);
        assert!(cut < block_size, "expected a split, got {cut}");
        assert!(
            matches!(cut, 32_768 | 65_536 | 98_304),
            "fromBorders cuts are quartiles, got {cut}"
        );

        for level in 1..=4usize {
            let cut = split_block(&shifted, level);
            assert!(
                cut < block_size && cut % (8 << 10) == 0,
                "byChunks level {level}: got {cut}"
            );
        }
    }
}
