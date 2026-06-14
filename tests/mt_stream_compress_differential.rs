//! Differential tests for multithreaded **streaming** compression
//! (`StreamEncoder::with_workers`) against C libzstd's `ZSTD_compressStream2`
//! with `nbWorkers >= 1`.
//!
//! Streaming MT engages for an unknown content size regardless of input length;
//! the input is buffered into `section_size` jobs as it arrives, and the trailing
//! empty-block job appears when the input ends exactly on a section boundary in a
//! later call — both schedule-dependent behaviors this exercises. The oracle is
//! the bundled C library built with the `zstdmt` feature.

use libzstd_bitexact::StreamEncoder;
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
    chunks: &[&[u8]],
    finish: &[u8],
) -> Vec<u8> {
    let mut enc = StreamEncoder::new(level).with_workers(workers, job_size, overlap_log);
    let mut out = Vec::new();
    for &data in chunks {
        enc.compress(data, &mut out).unwrap();
    }
    enc.finish(finish, &mut out).unwrap();
    out
}

/// Assert byte-identical to the oracle and round-tripping.
fn check(
    level: i32,
    workers: u32,
    job_size: u32,
    overlap_log: u32,
    chunks: &[&[u8]],
    finish: &[u8],
) {
    let theirs = oracle(level, workers, job_size, overlap_log, chunks, finish);
    let mine = ours(
        level,
        workers,
        job_size as u64,
        overlap_log as i32,
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

/// `flush`, a pledged size, dictionaries, and checksums with workers are not
/// supported yet — they must error cleanly, never diverge.
#[test]
fn mt_stream_unsupported_errors_cleanly() {
    let body = word_salad(0x44, 700 * 1024);
    let mut out = Vec::new();
    let mut enc = StreamEncoder::new(3).with_workers(2, 512 * 1024, 0);
    enc.compress(&body, &mut out).unwrap();
    assert!(enc.flush(&mut out).is_err(), "MT flush must error cleanly");

    let mut out2 = Vec::new();
    let r = StreamEncoder::with_pledged_src_size(3, body.len() as u64)
        .with_workers(2, 512 * 1024, 0)
        .compress(&body, &mut out2);
    assert!(r.is_err(), "MT + pledged size must error cleanly");
}
