//! Differential tests for [`libzstd_bitexact::compress_mt`] against C libzstd's
//! multithreaded compressor (`ZSTD_compress2` with `nbWorkers >= 1`).
//!
//! The oracle is the bundled C library built with the `zstdmt` feature; its MT
//! output is deterministic and independent of the worker count, so our
//! single-threaded job-splitting reproduction must be byte-identical. Inputs
//! span the single-job/​multi-job boundary, exact-multiple (trailing empty
//! block) sizes, explicit `jobSize`/​`overlapLog` overrides, and every strategy.

use libzstd_bitexact::compress_mt;
use zstd::zstd_safe::{self, CCtx, CParameter};

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

const WORDS: &[&[u8]] = &[
    b"alpha",
    b"bravo",
    b"charlie",
    b"delta",
    b"echo",
    b"foxtrot",
    b"golf",
    b"hotel",
    b"india",
    b"juliet",
    b"kilo",
    b"lima",
    b"mike",
    b"november",
];

/// Compressible-but-varied data so multiple jobs differ from each other.
fn word_salad(seed: u64, len: usize) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut d = Vec::with_capacity(len + 16);
    while d.len() < len {
        d.extend_from_slice(WORDS[rng.below(WORDS.len())]);
        d.push(b' ');
    }
    d.truncate(len);
    d
}

/// Oracle: C `ZSTD_compress2` with multithreading parameters set
/// (`nbWorkers`/`jobSize`/`overlapLog`; `0` means "C default").
fn oracle(
    src: &[u8],
    level: i32,
    workers: u32,
    job_size: u32,
    overlap_log: u32,
    checksum: bool,
) -> Vec<u8> {
    let mut cctx = CCtx::create();
    cctx.set_parameter(CParameter::CompressionLevel(level))
        .unwrap();
    cctx.set_parameter(CParameter::NbWorkers(workers))
        .expect("nbWorkers (oracle must be built with the `zstdmt` feature)");
    if job_size != 0 {
        cctx.set_parameter(CParameter::JobSize(job_size)).unwrap();
    }
    if overlap_log != 0 {
        cctx.set_parameter(CParameter::OverlapSizeLog(overlap_log))
            .unwrap();
    }
    if checksum {
        cctx.set_parameter(CParameter::ChecksumFlag(true)).unwrap();
    }
    let mut dst = Vec::with_capacity(zstd_safe::compress_bound(src.len()));
    cctx.compress2(&mut dst, src).expect("oracle compress2");
    dst
}

/// Assert `compress_mt` is byte-identical to the oracle and round-trips.
fn check(src: &[u8], level: i32, workers: u32, job_size: u32, overlap_log: u32, checksum: bool) {
    let theirs = oracle(src, level, workers, job_size, overlap_log, checksum);
    let mine = compress_mt(
        src,
        level,
        workers,
        job_size as u64,
        overlap_log as i32,
        checksum,
    )
    .unwrap_or_else(|e| {
        panic!(
            "compress_mt errored: level={level} workers={workers} jobSize={job_size} \
                 overlapLog={overlap_log} checksum={checksum} len={}: {e}",
            src.len()
        )
    });
    if mine != theirs {
        let first = mine
            .iter()
            .zip(theirs.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(mine.len().min(theirs.len()));
        panic!(
            "byte mismatch: level={level} workers={workers} jobSize={job_size} \
             overlapLog={overlap_log} len={} ours={} theirs={} first_diff_at={first}",
            src.len(),
            mine.len(),
            theirs.len(),
        );
    }
    let decoded = zstd::decode_all(&mine[..]).expect("decode");
    assert_eq!(
        decoded,
        src,
        "round-trip mismatch: level={level} len={}",
        src.len()
    );
}

/// Light: explicit `jobSize = 512 KiB` (the minimum) forces real multi-job
/// splitting at modest sizes, across strategies. Runs in debug + release.
#[test]
fn mt_small_jobs_are_bit_exact() {
    // 512 KiB sections; sizes straddle the section boundary, hit an exact
    // multiple (trailing empty block), and leave partial last jobs.
    let sizes = [
        512 * 1024 + 1,  // 2 jobs, 1-byte last segment
        700 * 1024,      // 2 jobs, partial last
        1024 * 1024,     // exact 2× -> 2 full + trailing empty block
        1300 * 1024,     // 3 jobs, partial last
        2 * 1024 * 1024, // exact 4×
    ];
    // Cover fast/dfast/lazy-family/btlazy2/btopt via the level→strategy map for
    // large inputs.
    for &level in &[1i32, 3, 6, 9, 12, 15, 17] {
        for &len in &sizes {
            let src = word_salad(0xC0FFEE ^ (len as u64), len);
            check(&src, level, 2, 512 * 1024, 0, false);
        }
    }
}

/// The MT-disable / single-job cases must equal the single-threaded frame.
#[test]
fn mt_single_job_equals_single_threaded() {
    for &level in &[1i32, 5, 12, 19] {
        for &len in &[0usize, 1000, 256 * 1024, 512 * 1024, 700 * 1024] {
            // <=512 KiB -> MT disabled; 700 KiB with default jobSize -> one job.
            let src = word_salad(0xABCD ^ (len as u64), len);
            let mt = compress_mt(&src, level, 4, 0, 0, false).unwrap();
            let st = libzstd_bitexact::compress(&src, level).unwrap();
            assert_eq!(
                mt, st,
                "single-job != single-threaded: level={level} len={len}"
            );
            // And it matches the oracle too.
            check(&src, level, 4, 0, 0, false);
        }
    }
}

/// Worker count must not change the bytes (job decomposition is deterministic).
#[test]
fn mt_output_independent_of_worker_count() {
    let src = word_salad(0x5151, 1500 * 1024);
    let base = compress_mt(&src, 6, 1, 512 * 1024, 0, false).unwrap();
    for workers in [1u32, 2, 3, 4, 8] {
        let c = compress_mt(&src, 6, workers, 512 * 1024, 0, false).unwrap();
        assert_eq!(c, base, "worker count changed bytes: workers={workers}");
        // The oracle is likewise worker-independent.
        check(&src, 6, workers, 512 * 1024, 0, false);
    }
}

/// Explicit `overlapLog` overrides (including `1` -> zero overlap, fully
/// independent jobs) and a couple of strategy-specific defaults.
#[test]
fn mt_overlap_overrides_are_bit_exact() {
    for &len in &[700 * 1024usize, 1024 * 1024 + 7, 1500 * 1024] {
        let src = word_salad(0x0E12 ^ len as u64, len);
        for overlap_log in [1u32, 3, 6, 9] {
            check(&src, 9, 2, 512 * 1024, overlap_log, false);
        }
    }
}

/// Heavy: C's *default* job size (no explicit `jobSize`) across every strategy,
/// with inputs large enough to split into multiple default-size jobs. Release
/// only (multi-MiB compression at high levels is slow in debug).
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "heavy differential test (multi-MiB at high levels); run in release"
)]
fn mt_default_jobsize_is_bit_exact() {
    // Default sections are >= 1 MiB (and ~2 MiB at low levels); 6 MiB guarantees
    // several jobs even at the largest default section size we hit here.
    for &level in &[1i32, 2, 4, 6, 9, 12, 15, 17, 19, 22] {
        for &len in &[3 * 1024 * 1024usize, 6 * 1024 * 1024 + 123] {
            let src = word_salad(0xBEEF ^ len as u64, len);
            check(&src, level, 4, 0, 0, false);
        }
    }
}

/// Cross-job LDM: one `ZSTDMT_serialState` LDM state shared across all jobs. LDM
/// auto-enables at level 22 once windowLog reaches 27, which a one-shot input only
/// does above 64 MiB. A 768 KiB block repeated past the 1 MiB overlap makes the
/// LDM find long matches reaching back **across job boundaries** (into the prefix
/// = the previous segment): the serial state generates each job's `rawSeqStore`
/// per segment, and the opt parser consumes it via a cursor persisting across the
/// job's blocks. `overlapLog 2` (overlap = 1 MiB > the 768 KiB match distance)
/// keeps every LDM offset inside `prefix ++ segment`, where C can represent it.
/// Very heavy (>64 MiB at level 22): release only.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "cross-job LDM needs a >64 MiB level-22 input; run in release"
)]
fn mt_cross_job_ldm_is_bit_exact() {
    let target = 65 * 1024 * 1024; // > 64 MiB so windowLog resizes up to 27 (LDM on)
    // (repeat-block size, overlapLog -> overlap, jobSize): the block repeats below
    // the overlap, so LDM matches reach back across jobs but stay in `prefix++seg`.
    let cases: &[(usize, u32, u32)] = &[
        (768 * 1024, 2, 4 * 1024 * 1024), // 1 MiB overlap, 4 MiB jobs (~16 jobs)
        (384 * 1024, 1, 2 * 1024 * 1024), // 512 KiB overlap, 2 MiB jobs (~32 jobs)
    ];
    for &(block_len, overlap_log, job_size) in cases {
        let block = word_salad(0x1D34_A210 ^ block_len as u64, block_len);
        let mut src = Vec::with_capacity(target + block.len());
        while src.len() < target {
            src.extend_from_slice(&block);
        }
        check(&src, 22, 2, job_size, overlap_log, false);
    }
}

/// An explicit `overlapLog` whose overlap exceeds `maxDictSize` (e.g. 9 at a
/// fast level, where the hash/chain tables are small) isn't supported: C would
/// index only the prefix suffix, which we don't port — so it must error
/// cleanly, never diverge. (The default `overlapLog` never trips this.)
#[test]
fn mt_oversized_overlap_errors_cleanly() {
    let src = word_salad(0x9, 1024 * 1024 + 1);
    assert!(
        compress_mt(&src, 1, 2, 0, 9, false).is_err(),
        "oversized overlap at a fast level must be a clean error"
    );
}

/// Content checksum (`ZSTD_c_checksumFlag`) with multithreading: the whole-input
/// digest is appended once after the last job (multi-job) or by the single job
/// itself. Across strategies, the single/multi-job boundary, and exact multiples.
#[test]
fn mt_checksum_is_bit_exact() {
    let sizes = [
        300 * 1024usize, // single job (< 512 KiB section) -> self-appended
        512 * 1024 + 1,  // 2 jobs
        1024 * 1024,     // exact 2× -> last full job is the end (no empty block)
        1300 * 1024,     // 3 jobs, partial last
    ];
    for &level in &[1i32, 3, 6, 9, 12, 17] {
        for &len in &sizes {
            let src = word_salad(0xC5 ^ (len as u64), len);
            check(&src, level, 2, 512 * 1024, 0, true);
        }
    }
}
