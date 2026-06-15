//! Throughput benchmarks: this crate's [`compress`]/[`decompress`] vs the
//! bundled C libzstd 1.5.7 oracle (the same `zstd` crate the differential
//! tests use as the spec). Speeds are reported on the *original* (uncompressed)
//! size for both directions, matching `zstd -b` conventions, so the numbers
//! line up with upstream's own benchmark output.
//!
//! Run with:
//! ```text
//! cargo bench --bench throughput                 # full matrix
//! cargo bench --bench throughput -- 1 3 19       # only these levels
//! cargo bench --bench throughput -- quick        # one level, small input
//! ```
//! Tunables (env): `BENCH_SIZE_KIB` (default 1024), `BENCH_BUDGET_MS`
//! (default 500 ms per timed cell).
//!
//! No Criterion on purpose: a fixed-budget timer keeps this dependency-free, so
//! the pinned `Cargo.lock` (CI builds `--locked`) is untouched. Comparing
//! against another pure-Rust zstd crate would add a dev-dependency — a
//! deliberate lock bump — and is left as a follow-up.
//!
//! [`compress`]: libzstd_bitexact_rs::compress
//! [`decompress`]: libzstd_bitexact_rs::decompress

use std::hint::black_box;
use std::time::{Duration, Instant};

// --- deterministic corpora -------------------------------------------------

/// xorshift64* — the same deterministic generator the differential tests use.
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

/// English-ish prose: compressible (~3x), the common-case workload.
fn corpus_text(len: usize) -> Vec<u8> {
    const WORDS: &[&str] = &[
        "the",
        "quick",
        "brown",
        "fox",
        "jumps",
        "over",
        "lazy",
        "dog",
        "zstandard",
        "compression",
        "entropy",
        "sequence",
        "dictionary",
        "window",
    ];
    let mut rng = Rng::new(0xD1FF);
    let mut data = Vec::with_capacity(len + 16);
    while data.len() < len {
        data.extend_from_slice(WORDS[rng.below(WORDS.len())].as_bytes());
        data.push(b' ');
    }
    data.truncate(len);
    data
}

/// Structured records: highly compressible, lots of repeated keys/punctuation.
fn corpus_json(len: usize) -> Vec<u8> {
    const NAMES: &[&str] = &[
        "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
    ];
    let mut rng = Rng::new(0x5EED_F00D);
    let mut data = Vec::with_capacity(len + 128);
    let mut id = 1000u64;
    while data.len() < len {
        let name = NAMES[rng.below(NAMES.len())];
        let score = rng.below(10_000);
        let active = rng.below(2) == 0;
        let rec = format!(
            "{{\"id\":{id},\"user\":\"{name}\",\"score\":{}.{:02},\"active\":{active}}}\n",
            score / 100,
            score % 100,
        );
        data.extend_from_slice(rec.as_bytes());
        id += 1;
    }
    data.truncate(len);
    data
}

/// Incompressible (~1x): the match finder finds nothing, so this isolates
/// hashing + literal entropy throughput.
fn corpus_random(len: usize) -> Vec<u8> {
    let mut rng = Rng::new(0x0BAD_F00D);
    let mut data = Vec::with_capacity(len + 8);
    while data.len() < len {
        data.extend_from_slice(&rng.next_u64().to_le_bytes());
    }
    data.truncate(len);
    data
}

// --- timing ----------------------------------------------------------------

/// Run `op` for at least `budget`, return the mean wall-clock seconds per call.
/// A single warm-up call primes caches, the branch predictor, and the
/// allocator so the timed window measures steady state.
fn seconds_per_op(budget: Duration, mut op: impl FnMut()) -> f64 {
    op();
    let start = Instant::now();
    let mut iters = 0u64;
    loop {
        op();
        iters += 1;
        if start.elapsed() >= budget {
            break;
        }
    }
    start.elapsed().as_secs_f64() / iters as f64
}

fn mib_per_s(bytes: usize, secs: f64) -> f64 {
    (bytes as f64 / secs) / (1024.0 * 1024.0)
}

// --- output ----------------------------------------------------------------

fn header_compress() {
    println!(
        "{:<8} {:>4}  {:>9} {:>9}  {:>8}  {:>6}",
        "corpus", "lvl", "ours", "C", "ours/C", "ratio"
    );
    println!(
        "{:<8} {:>4}  {:>9} {:>9}  {:>8}  {:>6}",
        "", "", "MiB/s", "MiB/s", "", "x:1"
    );
}

fn row_compress(name: &str, level: i32, ours: f64, c: f64, ratio: f64) {
    println!(
        "{:<8} {:>4}  {:>9.1} {:>9.1}  {:>7.2}x  {:>6.2}",
        name,
        level,
        ours,
        c,
        ours / c,
        ratio
    );
}

fn header_decompress() {
    println!(
        "{:<8} {:>4}  {:>9} {:>9}  {:>8}",
        "corpus", "lvl", "ours", "C", "ours/C"
    );
    println!(
        "{:<8} {:>4}  {:>9} {:>9}  {:>8}",
        "", "", "MiB/s", "MiB/s", ""
    );
}

fn row_decompress(name: &str, level: i32, ours: f64, c: f64) {
    println!(
        "{:<8} {:>4}  {:>9.1} {:>9.1}  {:>7.2}x",
        name,
        level,
        ours,
        c,
        ours / c
    );
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

// --- driver ----------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let quick = args.iter().any(|a| a.as_str() == "quick");
    let level_filter: Vec<i32> = args.iter().filter_map(|a| a.parse::<i32>().ok()).collect();

    let size = if quick {
        128 * 1024
    } else {
        env_u64("BENCH_SIZE_KIB", 1024) as usize * 1024
    };
    let budget = Duration::from_millis(if quick {
        200
    } else {
        env_u64("BENCH_BUDGET_MS", 500)
    });
    let levels: Vec<i32> = if !level_filter.is_empty() {
        level_filter
    } else if quick {
        vec![3]
    } else {
        vec![1, 3, 6, 9, 12, 15, 19, 22]
    };

    let corpora: [(&str, Vec<u8>); 3] = [
        ("text", corpus_text(size)),
        ("json", corpus_json(size)),
        ("random", corpus_random(size)),
    ];

    println!();
    println!("libzstd-bitexact-rs throughput — ours vs C libzstd 1.5.7 (both single-threaded)");
    println!(
        "input {} KiB/corpus · budget {} ms/cell · speeds on original size · ours/C < 1.0 = slower",
        size / 1024,
        budget.as_millis()
    );

    println!("\n== compression ==");
    header_compress();
    for (name, data) in &corpora {
        let data = data.as_slice();
        for &level in &levels {
            let theirs = zstd::bulk::compress(data, level).expect("oracle compress");
            let ours = libzstd_bitexact_rs::compress(data, level).expect("our compress");
            assert_eq!(ours, theirs, "{name} L{level}: compression not bit-exact");
            let ratio = data.len() as f64 / theirs.len() as f64;

            let s_ours = seconds_per_op(budget, || {
                black_box(libzstd_bitexact_rs::compress(black_box(data), level).unwrap());
            });
            let s_c = seconds_per_op(budget, || {
                black_box(zstd::bulk::compress(black_box(data), level).unwrap());
            });
            row_compress(
                name,
                level,
                mib_per_s(data.len(), s_ours),
                mib_per_s(data.len(), s_c),
                ratio,
            );
        }
    }

    println!("\n== decompression ==");
    header_decompress();
    for (name, data) in &corpora {
        let data = data.as_slice();
        for &level in &levels {
            let frame = zstd::bulk::compress(data, level).expect("oracle compress");
            let frame = frame.as_slice();
            let cap = data.len();
            let back = libzstd_bitexact_rs::decompress(frame).expect("our decompress");
            assert_eq!(
                back.len(),
                data.len(),
                "{name} L{level}: decompress size mismatch"
            );

            let s_ours = seconds_per_op(budget, || {
                black_box(libzstd_bitexact_rs::decompress(black_box(frame)).unwrap());
            });
            let s_c = seconds_per_op(budget, || {
                black_box(zstd::bulk::decompress(black_box(frame), cap).unwrap());
            });
            row_decompress(
                name,
                level,
                mib_per_s(data.len(), s_ours),
                mib_per_s(data.len(), s_c),
            );
        }
    }
    println!();
}
