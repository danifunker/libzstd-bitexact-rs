//! Differential tests for multithreaded **streaming** compression
//! (`StreamEncoder::with_workers`) against C libzstd's `ZSTD_compressStream2`
//! with `nbWorkers >= 1`.
//!
//! Streaming MT engages for an unknown content size regardless of input length;
//! the input is buffered into `section_size` jobs as it arrives, and the trailing
//! empty-block job appears when the input ends exactly on a section boundary in a
//! later call — both schedule-dependent behaviors this exercises. The oracle is
//! the bundled C library built with the `zstdmt` feature.

use libzstd_bitexact_rs::{DecodeOptions, Dictionary, StreamEncoder};
use zstd::zstd_safe::{CCtx, CParameter, InBuffer, OutBuffer};

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

fn map_code(code: usize) -> std::io::Error {
    std::io::Error::other(zstd::zstd_safe::get_error_name(code))
}

/// Drive C `ZSTD_compressStream2` with the MT parameters over the chunk schedule:
/// each `chunks[i]` fed with `ZSTD_e_continue`, then `finish` with `ZSTD_e_end`.
fn oracle(
    level: i32,
    workers: u32,
    job_size: u32,
    overlap_log: u32,
    checksum: bool,
    chunks: &[&[u8]],
    finish: &[u8],
) -> Vec<u8> {
    use zstd_sys::ZSTD_EndDirective as Dir;
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

    let mut out = Vec::new();
    let mut scratch = vec![0u8; 1024 * 1024];
    let mut step = |cctx: &mut CCtx, out: &mut Vec<u8>, inb: &mut InBuffer, dir: Dir| -> usize {
        let mut outb = OutBuffer::around(&mut scratch[..]);
        let hint = cctx
            .compress_stream2(&mut outb, inb, dir)
            .map_err(map_code)
            .unwrap();
        let produced = outb.pos();
        out.extend_from_slice(&scratch[..produced]);
        hint
    };

    for &data in chunks {
        let mut inb = InBuffer::around(data);
        loop {
            step(&mut cctx, &mut out, &mut inb, Dir::ZSTD_e_continue);
            if inb.pos >= data.len() {
                break;
            }
        }
    }
    let mut inb = InBuffer::around(finish);
    loop {
        let hint = step(&mut cctx, &mut out, &mut inb, Dir::ZSTD_e_end);
        if hint == 0 && inb.pos == finish.len() {
            break;
        }
    }
    out
}

/// Drive our `StreamEncoder::with_workers` over the same schedule.
fn ours(
    level: i32,
    workers: u32,
    job_size: u64,
    overlap_log: i32,
    checksum: bool,
    chunks: &[&[u8]],
    finish: &[u8],
) -> Vec<u8> {
    let mut enc = StreamEncoder::new(level)
        .with_workers(workers, job_size, overlap_log)
        .with_checksum(checksum);
    let mut out = Vec::new();
    for &data in chunks {
        enc.compress(data, &mut out).unwrap();
    }
    enc.finish(finish, &mut out).unwrap();
    out
}

/// Assert byte-identical to the oracle and round-tripping (no checksum).
fn check(
    level: i32,
    workers: u32,
    job_size: u32,
    overlap_log: u32,
    chunks: &[&[u8]],
    finish: &[u8],
) {
    check_ck(level, workers, job_size, overlap_log, false, chunks, finish);
}

/// Assert byte-identical to the oracle and round-tripping, checksum-aware.
fn check_ck(
    level: i32,
    workers: u32,
    job_size: u32,
    overlap_log: u32,
    checksum: bool,
    chunks: &[&[u8]],
    finish: &[u8],
) {
    let theirs = oracle(
        level,
        workers,
        job_size,
        overlap_log,
        checksum,
        chunks,
        finish,
    );
    let mine = ours(
        level,
        workers,
        job_size as u64,
        overlap_log as i32,
        checksum,
        chunks,
        finish,
    );
    if mine != theirs {
        let first = mine
            .iter()
            .zip(theirs.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(mine.len().min(theirs.len()));
        panic!(
            "byte mismatch: level={level} workers={workers} jobSize={job_size} \
             overlapLog={overlap_log} nchunks={} finish={} ours={} theirs={} first_diff_at={first}",
            chunks.len(),
            finish.len(),
            mine.len(),
            theirs.len(),
        );
    }
    let mut expect = Vec::new();
    for &c in chunks {
        expect.extend_from_slice(c);
    }
    expect.extend_from_slice(finish);
    let decoded = zstd::decode_all(&mine[..]).expect("decode");
    assert_eq!(decoded, expect, "round-trip mismatch: level={level}");
}

/// Run a body through a spread of compress/finish schedules — different chunk
/// boundaries relative to the 512 KiB sections, and whether the input ends with
/// the `finish` call (no trailing empty block) or earlier (with one).
fn schedules(body: &[u8]) -> Vec<(Vec<&[u8]>, &[u8])> {
    let n = body.len();
    let h = n / 2;
    let mut s: Vec<(Vec<&[u8]>, &[u8])> = vec![
        (vec![body], &[]),                           // one push, finish empty
        (vec![&body[..h]], &body[h..]),              // push + finish carries input
        (vec![&body[..h], &body[h..]], &[]),         // two pushes, finish empty
        (vec![&body[..1], &body[1..h]], &body[h..]), // tiny first chunk
    ];
    // Exactly section-aligned splits exercise the boundary precisely.
    if n >= 512 * 1024 {
        let sec = 512 * 1024;
        s.push((vec![&body[..sec.min(n)]], &body[sec.min(n)..])); // first section, then rest
    }
    s
}

/// Multi-section streaming across strategies (`jobSize = 512 KiB`). Release only
/// (multi-MiB at high levels is slow in debug).
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "heavy differential test (multi-MiB across strategies); run in release"
)]
fn mt_stream_is_bit_exact() {
    for &level in &[1i32, 3, 6, 9, 12, 15, 17, 19] {
        for &n in &[700 * 1024usize, 1024 * 1024, 1300 * 1024] {
            let body = word_salad(0x57A2 ^ n as u64, n);
            for (chunks, finish) in schedules(&body) {
                check(level, 2, 512 * 1024, 0, &chunks, finish);
            }
        }
    }
}

/// A total that is an exact multiple of the section size: fed via `compress` the
/// frame is closed by a trailing empty block; fed so the last byte rides the
/// `finish` call it is not — both must match.
#[test]
fn mt_stream_exact_multiple_boundary() {
    let body = word_salad(0xE4AC, 1024 * 1024); // exactly 2× 512 KiB
    // compress whole, finish empty -> trailing empty block.
    check(6, 2, 512 * 1024, 0, &[&body[..]], &[]);
    // finish carries the last section exactly -> no empty block.
    check(
        6,
        2,
        512 * 1024,
        0,
        &[&body[..512 * 1024]],
        &body[512 * 1024..],
    );
    // two compress calls aligned on the boundary, finish empty.
    check(
        6,
        2,
        512 * 1024,
        0,
        &[&body[..512 * 1024], &body[512 * 1024..]],
        &[],
    );
}

/// Single-job streaming (total below one section) and a first-call `finish`
/// (the one-shot MT delegation) must match too.
#[test]
fn mt_stream_single_and_first_call() {
    // Below a section: one job, == single-threaded streaming.
    let small = word_salad(0x11, 300 * 1024);
    check(3, 4, 512 * 1024, 0, &[&small[..]], &[]);
    check(
        3,
        4,
        512 * 1024,
        0,
        &[&small[..100 * 1024]],
        &small[100 * 1024..],
    );

    // First-call finish above the MT floor: one-shot MT frame.
    let big = word_salad(0x22, 1500 * 1024);
    check(3, 4, 512 * 1024, 0, &[], &big);
    // First-call finish below the floor: single-threaded frame.
    let tiny = word_salad(0x33, 200 * 1024);
    check(3, 4, 512 * 1024, 0, &[], &tiny);
}

/// Content checksum with multithreaded streaming: the whole-input digest is
/// appended after the last job (multi-job) or by the single job itself. Covers
/// the single-job, multi-job, and exact-multiple (empty block then checksum)
/// cases, fed via several schedules.
#[test]
fn mt_stream_checksum_is_bit_exact() {
    for &level in &[1i32, 3, 6, 9, 17] {
        // Single job (< section): the job appends its own checksum.
        let small = word_salad(0x71 ^ level as u64, 300 * 1024);
        check_ck(level, 2, 512 * 1024, 0, true, &[&small[..]], &[]);
        check_ck(
            level,
            2,
            512 * 1024,
            0,
            true,
            &[&small[..100 * 1024]],
            &small[100 * 1024..],
        );

        // Multi-job: external append after the last job.
        let body = word_salad(0x72 ^ level as u64, 1300 * 1024);
        let h = body.len() / 2;
        check_ck(level, 2, 512 * 1024, 0, true, &[&body[..]], &[]);
        check_ck(level, 2, 512 * 1024, 0, true, &[&body[..h]], &body[h..]);
        check_ck(
            level,
            2,
            512 * 1024,
            0,
            true,
            &[&body[..h], &body[h..]],
            &[],
        );

        // Exact multiple via compress -> trailing empty block, then checksum.
        let exact = word_salad(0x73 ^ level as u64, 1024 * 1024);
        check_ck(level, 2, 512 * 1024, 0, true, &[&exact[..]], &[]);
        check_ck(
            level,
            2,
            512 * 1024,
            0,
            true,
            &[&exact[..512 * 1024]],
            &exact[512 * 1024..],
        );
    }

    // First-call finish with checksum (one-shot delegation, above the MT floor).
    let big = word_salad(0x74, 1500 * 1024);
    check_ck(3, 4, 512 * 1024, 0, true, &[], &big);
}

/// Drive C `ZSTD_compressStream2` with a loaded dictionary + MT parameters.
fn oracle_dict(
    level: i32,
    workers: u32,
    job_size: u32,
    dict: &[u8],
    chunks: &[&[u8]],
    finish: &[u8],
) -> Vec<u8> {
    use zstd_sys::ZSTD_EndDirective as Dir;
    let mut cctx = CCtx::create();
    cctx.set_parameter(CParameter::CompressionLevel(level))
        .unwrap();
    cctx.set_parameter(CParameter::NbWorkers(workers)).unwrap();
    cctx.set_parameter(CParameter::JobSize(job_size)).unwrap();
    cctx.load_dictionary(dict).unwrap();

    let mut out = Vec::new();
    let mut scratch = vec![0u8; 1024 * 1024];
    let mut step = |cctx: &mut CCtx, out: &mut Vec<u8>, inb: &mut InBuffer, dir: Dir| -> usize {
        let mut outb = OutBuffer::around(&mut scratch[..]);
        let hint = cctx
            .compress_stream2(&mut outb, inb, dir)
            .map_err(map_code)
            .unwrap();
        let produced = outb.pos();
        out.extend_from_slice(&scratch[..produced]);
        hint
    };
    for &data in chunks {
        let mut inb = InBuffer::around(data);
        loop {
            step(&mut cctx, &mut out, &mut inb, Dir::ZSTD_e_continue);
            if inb.pos >= data.len() {
                break;
            }
        }
    }
    let mut inb = InBuffer::around(finish);
    loop {
        let hint = step(&mut cctx, &mut out, &mut inb, Dir::ZSTD_e_end);
        if hint == 0 && inb.pos == finish.len() {
            break;
        }
    }
    out
}

/// A real ZDICT-trained dictionary (magic `0xEC30A437`): seeds job 0's entropy
/// tables, repeat offsets, and the frame's `Dictionary_ID`.
fn trained_dict() -> Vec<u8> {
    let mut rng = Rng::new(0x7A1A_ED01);
    let mut samples: Vec<u8> = Vec::new();
    let mut sizes: Vec<usize> = Vec::new();
    for _ in 0..4000 {
        let start = samples.len();
        let target = 24 + rng.below(128);
        while samples.len() - start < target {
            samples.extend_from_slice(WORDS[rng.below(WORDS.len())]);
            samples.push(b' ');
        }
        sizes.push(samples.len() - start);
    }
    let mut dict = vec![0u8; 16 * 1024];
    let dict_size = unsafe {
        zstd_sys::ZDICT_trainFromBuffer(
            dict.as_mut_ptr() as *mut core::ffi::c_void,
            dict.len(),
            samples.as_ptr() as *const core::ffi::c_void,
            sizes.as_ptr(),
            sizes.len() as core::ffi::c_uint,
        )
    };
    assert!(
        unsafe { zstd_sys::ZDICT_isError(dict_size) } == 0,
        "ZDICT_trainFromBuffer failed (code {dict_size})"
    );
    dict.truncate(dict_size);
    dict
}

/// Multithreaded streaming with a dictionary: C builds an internal CDict and
/// applies it to job 0 only (attach, unknown size); later jobs are plain overlap
/// jobs. Across strategies and chunk schedules. Byte-exact vs C and round-trips
/// through our decoder with the dictionary.
fn run_mt_dict(dict: &[u8]) {
    let dict_obj = Dictionary::new(dict).expect("dict parse");
    for &level in &[1i32, 3, 6, 9, 12, 17] {
        let body = word_salad(0xB0D7 ^ level as u64, 1300 * 1024);
        let h = body.len() / 2;
        // Unknown-size streaming (the attach path). A first-call `finish` would
        // auto-pledge a known size above the cutoff → the copy path, covered by
        // `mt_stream_{raw,trained}_dict_copy_is_bit_exact`.
        let cases: &[(Vec<&[u8]>, &[u8])] = &[
            (vec![&body[..]], &[]),
            (vec![&body[..h]], &body[h..]),
            (vec![&body[..h], &body[h..]], &[]),
            (vec![&body[..1], &body[1..h]], &body[h..]),
        ];
        for (chunks, finish) in cases {
            let theirs = oracle_dict(level, 2, 512 * 1024, dict, chunks, finish);
            let mut enc =
                StreamEncoder::with_dictionary(level, dict).with_workers(2, 512 * 1024, 0);
            let mut mine = Vec::new();
            for &c in chunks {
                enc.compress(c, &mut mine).unwrap();
            }
            enc.finish(finish, &mut mine).unwrap();
            if mine != theirs {
                let first = mine
                    .iter()
                    .zip(theirs.iter())
                    .position(|(a, b)| a != b)
                    .unwrap_or(mine.len().min(theirs.len()));
                panic!(
                    "MT dict mismatch: level={level} nchunks={} finish={} \
                     ours={} theirs={} first_diff_at={first}",
                    chunks.len(),
                    finish.len(),
                    mine.len(),
                    theirs.len(),
                );
            }
            let mut expect = Vec::new();
            for &c in chunks {
                expect.extend_from_slice(c);
            }
            expect.extend_from_slice(finish);
            // The frame references the dictionary (job 0), so decode with it.
            let decoded = DecodeOptions::new()
                .dictionary(&dict_obj)
                .decompress(&mine)
                .expect("decode with dict");
            assert_eq!(decoded, expect, "MT dict round-trip: level={level}");
        }
    }
}

#[test]
fn mt_stream_raw_dict_is_bit_exact() {
    run_mt_dict(&word_salad(0xD1C7, 16 * 1024));
}

#[test]
fn mt_stream_trained_dict_is_bit_exact() {
    run_mt_dict(&trained_dict());
}

/// MT + dictionary above the attach cutoff is the **copy** path
/// (`ZSTD_resetCCtx_byCopyingCDict`): a first-call `finish` auto-pledges a known
/// size > the strategy cutoff, so C resolves the frame cParams in `cpm_noAttachDict`
/// mode (dict-aware) and copies the de-tagged CDict tables into job 0's context
/// (the dict a contiguous extDict prefix); later jobs are plain overlap jobs over
/// those dict-aware frame cParams. Multi-job (jobSize 512 KiB). Byte-exact vs C and
/// round-trips through our decoder with the dictionary.
fn run_mt_dict_copy(dict: &[u8]) {
    let dict_obj = Dictionary::new(dict).expect("dict parse");
    for &level in &[1i32, 3, 6, 9, 12, 17] {
        for &n in &[700 * 1024usize, 1300 * 1024] {
            let body = word_salad(0xC0B7 ^ level as u64 ^ n as u64, n);
            // First-call `finish` ⇒ known size above the cutoff ⇒ the copy path.
            let theirs = oracle_dict(level, 2, 512 * 1024, dict, &[], &body);
            let enc = StreamEncoder::with_dictionary(level, dict).with_workers(2, 512 * 1024, 0);
            let mut mine = Vec::new();
            enc.finish(&body, &mut mine).unwrap();
            if mine != theirs {
                let first = mine
                    .iter()
                    .zip(theirs.iter())
                    .position(|(a, b)| a != b)
                    .unwrap_or(mine.len().min(theirs.len()));
                panic!(
                    "MT dict copy mismatch: level={level} n={n} \
                     ours={} theirs={} first_diff_at={first}",
                    mine.len(),
                    theirs.len(),
                );
            }
            let decoded = DecodeOptions::new()
                .dictionary(&dict_obj)
                .decompress(&mine)
                .expect("decode with dict");
            assert_eq!(
                decoded, body,
                "MT dict copy round-trip: level={level} n={n}"
            );
        }
    }
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "heavy differential test (multi-MiB across strategies); run in release"
)]
fn mt_stream_raw_dict_copy_is_bit_exact() {
    run_mt_dict_copy(&word_salad(0xD1C7, 16 * 1024));
}

/// A **trained** (ZDICT) dictionary on the MT copy path — bit-exact now that the
/// copy path resolves the post-block splitter from the frame cParams (the trained
/// dict's seeded entropy made the wrongly-enabled splitter actually split; the
/// enablement, not the entropy, was the bug — `task_51d658f2`).
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "heavy differential test (multi-MiB across strategies); run in release"
)]
fn mt_stream_trained_dict_copy_is_bit_exact() {
    run_mt_dict_copy(&trained_dict());
}

/// Drive C with a pledged content size set up front.
fn oracle_pledged(
    level: i32,
    workers: u32,
    job_size: u32,
    pledged: u64,
    chunks: &[&[u8]],
    finish: &[u8],
) -> Vec<u8> {
    use zstd_sys::ZSTD_EndDirective as Dir;
    let mut cctx = CCtx::create();
    cctx.set_parameter(CParameter::CompressionLevel(level))
        .unwrap();
    cctx.set_parameter(CParameter::NbWorkers(workers)).unwrap();
    cctx.set_parameter(CParameter::JobSize(job_size)).unwrap();
    cctx.set_pledged_src_size(Some(pledged)).unwrap();

    let mut out = Vec::new();
    let mut scratch = vec![0u8; 1024 * 1024];
    let mut step = |cctx: &mut CCtx, out: &mut Vec<u8>, inb: &mut InBuffer, dir: Dir| -> usize {
        let mut outb = OutBuffer::around(&mut scratch[..]);
        let hint = cctx
            .compress_stream2(&mut outb, inb, dir)
            .map_err(map_code)
            .unwrap();
        let produced = outb.pos();
        out.extend_from_slice(&scratch[..produced]);
        hint
    };
    for &data in chunks {
        let mut inb = InBuffer::around(data);
        loop {
            step(&mut cctx, &mut out, &mut inb, Dir::ZSTD_e_continue);
            if inb.pos >= data.len() {
                break;
            }
        }
    }
    let mut inb = InBuffer::around(finish);
    loop {
        let hint = step(&mut cctx, &mut out, &mut inb, Dir::ZSTD_e_end);
        if hint == 0 && inb.pos == finish.len() {
            break;
        }
    }
    out
}

/// A pledged (known) content size with multithreaded streaming: job 0 writes an
/// FCS header and the cParams resize to the known size. Covers the multi-job,
/// exact-multiple (empty-block), single-job (≤ MT floor → single-threaded), and
/// first-call (one-shot MT) cases.
#[test]
fn mt_stream_pledged_size_is_bit_exact() {
    for &level in &[1i32, 3, 6, 9, 17] {
        let body = word_salad(0x9E ^ level as u64, 1400 * 1024);
        let n = body.len() as u64;
        let h = body.len() / 2;
        let cases: &[(Vec<&[u8]>, &[u8])] = &[
            (vec![&body[..]], &[]),
            (vec![&body[..h]], &body[h..]),
            (vec![&body[..h], &body[h..]], &[]),
        ];
        for (chunks, finish) in cases {
            let theirs = oracle_pledged(level, 2, 512 * 1024, n, chunks, finish);
            let mut enc =
                StreamEncoder::with_pledged_src_size(level, n).with_workers(2, 512 * 1024, 0);
            let mut mine = Vec::new();
            for &c in chunks {
                enc.compress(c, &mut mine).unwrap();
            }
            enc.finish(finish, &mut mine).unwrap();
            assert_eq!(
                mine,
                theirs,
                "pledged byte mismatch: level={level} ours={} theirs={}",
                mine.len(),
                theirs.len()
            );
            assert_eq!(
                zstd::decode_all(&mine[..]).unwrap(),
                body,
                "pledged round-trip"
            );
        }

        // Exact multiple via compress + finish(empty) -> trailing empty block,
        // with the size pledged.
        let exact = word_salad(0x9F ^ level as u64, 1024 * 1024);
        let theirs = oracle_pledged(level, 2, 512 * 1024, exact.len() as u64, &[&exact[..]], &[]);
        let mut enc = StreamEncoder::with_pledged_src_size(level, exact.len() as u64).with_workers(
            2,
            512 * 1024,
            0,
        );
        let mut mine = Vec::new();
        enc.compress(&exact, &mut mine).unwrap();
        enc.finish(&[], &mut mine).unwrap();
        assert_eq!(
            mine, theirs,
            "pledged exact-multiple mismatch: level={level}"
        );
        assert_eq!(
            zstd::decode_all(&mine[..]).unwrap(),
            exact,
            "pledged exact round-trip: level={level}"
        );
    }

    // Pledged size <= MT floor -> MT disabled -> single-threaded frame.
    let small = word_salad(0x5, 300 * 1024);
    let theirs = oracle_pledged(
        3,
        2,
        512 * 1024,
        small.len() as u64,
        &[&small[..200 * 1024]],
        &small[200 * 1024..],
    );
    let mut enc =
        StreamEncoder::with_pledged_src_size(3, small.len() as u64).with_workers(2, 512 * 1024, 0);
    let mut mine = Vec::new();
    enc.compress(&small[..200 * 1024], &mut mine).unwrap();
    enc.finish(&small[200 * 1024..], &mut mine).unwrap();
    assert_eq!(mine, theirs, "small pledged (single-threaded) mismatch");
}

/// One mid-stream operation: a `compress` push or a `flush`.
#[derive(Clone, Copy)]
enum MidOp<'a> {
    Push(&'a [u8]),
    Flush,
}

/// Drive C with an explicit op sequence (mid ops, then a final `finish`).
fn oracle_ops(level: i32, workers: u32, job_size: u32, mid: &[MidOp], finish: &[u8]) -> Vec<u8> {
    use zstd_sys::ZSTD_EndDirective as Dir;
    let mut cctx = CCtx::create();
    cctx.set_parameter(CParameter::CompressionLevel(level))
        .unwrap();
    cctx.set_parameter(CParameter::NbWorkers(workers)).unwrap();
    cctx.set_parameter(CParameter::JobSize(job_size)).unwrap();

    let mut out = Vec::new();
    let mut scratch = vec![0u8; 1024 * 1024];
    let mut step = |cctx: &mut CCtx, out: &mut Vec<u8>, inb: &mut InBuffer, dir: Dir| -> usize {
        let mut outb = OutBuffer::around(&mut scratch[..]);
        let hint = cctx
            .compress_stream2(&mut outb, inb, dir)
            .map_err(map_code)
            .unwrap();
        let produced = outb.pos();
        out.extend_from_slice(&scratch[..produced]);
        hint
    };
    for op in mid {
        match *op {
            MidOp::Push(data) => {
                let mut inb = InBuffer::around(data);
                loop {
                    step(&mut cctx, &mut out, &mut inb, Dir::ZSTD_e_continue);
                    if inb.pos >= data.len() {
                        break;
                    }
                }
            }
            MidOp::Flush => {
                let mut inb = InBuffer::around(&[]);
                loop {
                    if step(&mut cctx, &mut out, &mut inb, Dir::ZSTD_e_flush) == 0 {
                        break;
                    }
                }
            }
        }
    }
    let mut inb = InBuffer::around(finish);
    loop {
        let hint = step(&mut cctx, &mut out, &mut inb, Dir::ZSTD_e_end);
        if hint == 0 && inb.pos == finish.len() {
            break;
        }
    }
    out
}

/// Drive our encoder with the same op sequence.
fn ours_ops(level: i32, workers: u32, job_size: u64, mid: &[MidOp], finish: &[u8]) -> Vec<u8> {
    let mut enc = StreamEncoder::new(level).with_workers(workers, job_size, 0);
    let mut out = Vec::new();
    for op in mid {
        match *op {
            MidOp::Push(data) => enc.compress(data, &mut out).unwrap(),
            MidOp::Flush => enc.flush(&mut out).unwrap(),
        }
    }
    enc.finish(finish, &mut out).unwrap();
    out
}

/// Mid-stream `flush` forces a partial-section job; the frame stays open and the
/// flushed segment's overlap still primes the next job. Across strategies.
#[test]
fn mt_stream_flush_is_bit_exact() {
    for &level in &[1i32, 3, 6, 9, 12, 17] {
        let body = word_salad(0xF10 ^ level as u64, 1400 * 1024);
        let p = |a: usize, b: usize| MidOp::Push(&body[a..b]);
        let schedules: &[(&[MidOp], &[u8])] = &[
            // flush mid-section (partial job), then more, then finish.
            (
                &[p(0, 200 * 1024), MidOp::Flush, p(200 * 1024, 900 * 1024)],
                &body[900 * 1024..],
            ),
            // flush right at a section boundary (no-op-ish: buffer already empty
            // after the full section emitted), then continue.
            (
                &[p(0, 512 * 1024), MidOp::Flush, p(512 * 1024, 1000 * 1024)],
                &body[1000 * 1024..],
            ),
            // multiple flushes.
            (
                &[
                    p(0, 100 * 1024),
                    MidOp::Flush,
                    MidOp::Flush,
                    p(100 * 1024, 300 * 1024),
                    MidOp::Flush,
                ],
                &body[300 * 1024..],
            ),
            // flush with nothing buffered (immediate), then push + finish.
            (&[MidOp::Flush, p(0, 700 * 1024)], &body[700 * 1024..]),
        ];
        for (mid, finish) in schedules {
            let theirs = oracle_ops(level, 2, 512 * 1024, mid, finish);
            let mine = ours_ops(level, 2, 512 * 1024, mid, finish);
            assert_eq!(
                mine,
                theirs,
                "flush byte mismatch: level={level} ours={} theirs={}",
                mine.len(),
                theirs.len(),
            );
            assert_eq!(
                zstd::decode_all(&mine[..]).expect("decode"),
                body,
                "flush round-trip mismatch: level={level}"
            );
        }
    }
}

/// Cross-job LDM in **streaming** mode: one `ZSTDMT_serialState` LDM state shared
/// across every job, generating each segment's `rawSeqStore` for the job to consume
/// as its externSeqStore (a cursor persisting across the job's blocks). The serial
/// state reads from an accumulated-history buffer (C's serial round buffer), with
/// `seg_bias` remapping absolute window indices to history positions.
///
/// Unlike one-shot — which needs a >64 MiB input for windowLog to resize up to 27 —
/// *unknown-size* streaming keeps windowLog at the level-22 default of 27, so LDM
/// auto-enables even for a small input (here ~6 MiB, driven through `MtStreamState`
/// because the first call is `compress`, not the one-shot first-call-`finish`
/// delegation). A repeated block smaller than the overlap makes the LDM find long
/// matches reaching back across job boundaries (into the prefix = the previous
/// segment) while keeping every offset inside `prefix ++ segment`, where C can
/// represent it. Because C has LDM on, a wrong (or absent) externSeqStore diverges,
/// so a pass confirms the serial-state plumbing. Release only (level 22 is slow in
/// debug).
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "cross-job LDM at level 22 is slow; run in release"
)]
fn mt_stream_cross_job_ldm_is_bit_exact() {
    // (repeat-block size, overlapLog -> overlap, jobSize): the block repeats below
    // the overlap, so LDM matches reach across jobs but stay in `prefix ++ segment`.
    let cases: &[(usize, u32, u32)] = &[
        (768 * 1024, 2, 2 * 1024 * 1024), // 1 MiB overlap, 2 MiB jobs (~3 jobs)
        (384 * 1024, 1, 1024 * 1024),     // 512 KiB overlap, 1 MiB jobs (~6 jobs)
    ];
    for &(block_len, overlap_log, job_size) in cases {
        let block = word_salad(0x5D34_A210 ^ block_len as u64, block_len);
        // ~6 MiB, deliberately not a section multiple: exercises the cross-job LDM
        // plus a partial final job (rather than a trailing empty block).
        let mut body = Vec::with_capacity(6 * 1024 * 1024 + block.len());
        while body.len() < 6 * 1024 * 1024 + 123 {
            body.extend_from_slice(&block);
        }
        let n = body.len();
        let (q, h) = (n / 4, n / 2);
        // Each schedule's first call is `compress` (Continue) ⇒ unknown-size
        // streaming (windowLog 27, LDM on) through `MtStreamState`.
        let scheds: &[(Vec<&[u8]>, &[u8])] = &[
            (vec![&body[..]], &[]),                      // one push, finish empty
            (vec![&body[..h]], &body[h..]),              // push + finish carries the tail
            (vec![&body[..q], &body[q..h]], &body[h..]), // two pushes + finish tail
        ];
        for (chunks, finish) in scheds {
            check(22, 2, job_size, overlap_log, chunks, finish);
        }
    }
}

/// Cross-job LDM streaming **past the window** (> `maxDist` = 128 MiB at level 22):
/// the serial state's history buffer fills and then drops its front (bytes older
/// than `maxDist` can never be matched), advancing `ldm_base` so `seg_bias` remaps
/// later absolute indices to the (shifted) history. C reaches the same point by
/// wrapping its round buffer and flipping the serial LDM window to extDict; both
/// are byte-identical because C's MT output is worker-count-independent (so the
/// wrap timing — which depends on the round-buffer capacity, hence on `nbWorkers`
/// — cannot affect the sequences). Very heavy (>128 MiB at level 22); manual run:
/// `cargo test --release -- --ignored mt_stream_cross_job_ldm_past_window`.
#[test]
#[ignore = "needs a >128 MiB level-22 input to exercise the history front-drop"]
fn mt_stream_cross_job_ldm_past_window() {
    // overlapLog 2 ⇒ 1 MiB overlap, 2 MiB jobs; a 768 KiB repeated block keeps LDM
    // offsets inside the overlap. ~140 MiB ⇒ input_pos passes maxDist (128 MiB), so
    // the last jobs run after at least one front-drop (`ldm_base > 0`).
    let block = word_salad(0x5D34_A210 ^ (768 * 1024), 768 * 1024);
    let target = 140 * 1024 * 1024 + 123;
    let mut body = Vec::with_capacity(target + block.len());
    while body.len() < target {
        body.extend_from_slice(&block);
    }
    let h = body.len() / 2;
    // First call `compress` ⇒ unknown-size streaming (windowLog 27, LDM on).
    check(22, 2, 2 * 1024 * 1024, 2, &[&body[..h]], &body[h..]);
}

/// Like [`oracle_dict`] but also pins `OverlapSizeLog`, so a small overlap keeps the
/// LDM matches inside `prefix ++ segment` while the input still spans several jobs —
/// the setup for exercising cross-job LDM together with a job-0 dictionary.
fn oracle_dict_overlap(
    level: i32,
    workers: u32,
    job_size: u32,
    overlap_log: u32,
    dict: &[u8],
    chunks: &[&[u8]],
    finish: &[u8],
) -> Vec<u8> {
    use zstd_sys::ZSTD_EndDirective as Dir;
    let mut cctx = CCtx::create();
    cctx.set_parameter(CParameter::CompressionLevel(level))
        .unwrap();
    cctx.set_parameter(CParameter::NbWorkers(workers)).unwrap();
    cctx.set_parameter(CParameter::JobSize(job_size)).unwrap();
    cctx.set_parameter(CParameter::OverlapSizeLog(overlap_log))
        .unwrap();
    cctx.load_dictionary(dict).unwrap();

    let mut out = Vec::new();
    let mut scratch = vec![0u8; 1024 * 1024];
    let mut step = |cctx: &mut CCtx, out: &mut Vec<u8>, inb: &mut InBuffer, dir: Dir| -> usize {
        let mut outb = OutBuffer::around(&mut scratch[..]);
        let hint = cctx
            .compress_stream2(&mut outb, inb, dir)
            .map_err(map_code)
            .unwrap();
        let produced = outb.pos();
        out.extend_from_slice(&scratch[..produced]);
        hint
    };
    for &data in chunks {
        let mut inb = InBuffer::around(data);
        loop {
            step(&mut cctx, &mut out, &mut inb, Dir::ZSTD_e_continue);
            if inb.pos >= data.len() {
                break;
            }
        }
    }
    let mut inb = InBuffer::around(finish);
    loop {
        let hint = step(&mut cctx, &mut out, &mut inb, Dir::ZSTD_e_end);
        if hint == 0 && inb.pos == finish.len() {
            break;
        }
    }
    out
}

/// Cross-job LDM **together with a job-0 dictionary** — the last ZSTDMT combination.
/// A dictionary loaded via `ZSTD_CCtx_loadDictionary` becomes a prebuilt CDict, so the
/// serial LDM state is reset with `dictSize == 0` (`ZSTDMT_serialState_reset`'s dict
/// fill is gated on `dictSize > 0` and skipped): the serial state runs over the
/// segments dict-obliviously, while job 0 attaches the CDict **and** also consumes its
/// segment's external LDM sequences (`ZSTDMT_serialState_genSequences` /
/// `applySequences` run for job 0 too, zstdmt:726/751). Unknown-size streaming keeps
/// windowLog at the level-22 default of 27, so LDM auto-enables for a small (~1.5 MiB)
/// input; `overlapLog 1` (512 KiB overlap) with 512 KiB jobs keeps every LDM offset
/// inside `prefix ++ segment` across ~3 jobs, with a 384 KiB repeated block reaching
/// back over the job boundary. The `word_salad` dict and body share the WORDS
/// vocabulary, so job 0's dictMatchState genuinely competes with the LDM candidates.
/// Byte-exact vs C and round-trips through our decoder with the dictionary.
fn run_mt_dict_cross_job_ldm(dict: &[u8]) {
    let dict_obj = Dictionary::new(dict).expect("dict parse");
    let (block_len, overlap_log, job_size) = (384 * 1024usize, 1u32, 512 * 1024u32);
    let block = word_salad(0x5D34_A210 ^ block_len as u64, block_len);
    // ~1.5 MiB, deliberately not a section multiple: ~3 jobs plus a partial final job
    // (rather than a trailing empty block).
    let mut body = Vec::with_capacity(3 * job_size as usize + block.len());
    while body.len() < 3 * job_size as usize + 123 {
        body.extend_from_slice(&block);
    }
    let n = body.len();
    let (q, h) = (n / 4, n / 2);
    // Each schedule's first call is `compress` (Continue) ⇒ unknown-size streaming
    // (windowLog 27, LDM on, the attach path) through `MtStreamState`.
    let scheds: &[(Vec<&[u8]>, &[u8])] = &[
        (vec![&body[..]], &[]),                      // one push, finish empty
        (vec![&body[..h]], &body[h..]),              // push + finish carries the tail
        (vec![&body[..q], &body[q..h]], &body[h..]), // two pushes + finish tail
    ];
    for (chunks, finish) in scheds {
        let theirs = oracle_dict_overlap(22, 2, job_size, overlap_log, dict, chunks, finish);
        let mut enc = StreamEncoder::with_dictionary(22, dict).with_workers(
            2,
            job_size as u64,
            overlap_log as i32,
        );
        let mut mine = Vec::new();
        for &c in chunks {
            enc.compress(c, &mut mine).unwrap();
        }
        enc.finish(finish, &mut mine).unwrap();
        if mine != theirs {
            let first = mine
                .iter()
                .zip(theirs.iter())
                .position(|(a, b)| a != b)
                .unwrap_or(mine.len().min(theirs.len()));
            panic!(
                "MT dict+LDM mismatch: nchunks={} finish={} ours={} theirs={} first_diff_at={first}",
                chunks.len(),
                finish.len(),
                mine.len(),
                theirs.len(),
            );
        }
        let mut expect = Vec::new();
        for &c in chunks {
            expect.extend_from_slice(c);
        }
        expect.extend_from_slice(finish);
        // The frame references the dictionary (job 0), so decode with it.
        let decoded = DecodeOptions::new()
            .dictionary(&dict_obj)
            .decompress(&mine)
            .expect("decode with dict");
        assert_eq!(decoded, expect, "MT dict+LDM round-trip");
    }
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "cross-job LDM at level 22 is slow; run in release"
)]
fn mt_stream_raw_dict_cross_job_ldm_is_bit_exact() {
    run_mt_dict_cross_job_ldm(&word_salad(0xD1C7, 16 * 1024));
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "cross-job LDM at level 22 is slow; run in release"
)]
fn mt_stream_trained_dict_cross_job_ldm_is_bit_exact() {
    run_mt_dict_cross_job_ldm(&trained_dict());
}
