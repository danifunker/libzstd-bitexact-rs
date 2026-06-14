//! Differential tests for **CDict** dictionary compression
//! (`compress_with_cdict`), Task 2 increment 7 (Path B): the CDict /
//! `dictMatchState` path. The oracle is C libzstd 1.5.7's
//! `zstd::bulk::Compressor::with_dictionary` (= `ZSTD_compress_usingCDict`),
//! which produces **different bytes** than `ZSTD_compress_usingDict` (Path A,
//! [`compress_with_dict`]).
//!
//! All nine strategies are implemented (sub-commits 1-5). This test runs every
//! level and spans payload sizes on both sides of the attach/copy cutoff, so
//! both the **attach** (small `src`, dictMatchState matcher) and **copy** (large
//! `src`, de-tagged/reproduced tables) paths are exercised for each strategy —
//! including the lazy family's two backends (hash chain when the CDict windowLog
//! ≤ 14, the row finder above it), btlazy2's binary tree, and the optimal
//! parser — plus a round-trip through our own decoder.

use libzstd_bitexact::{
    DecodeOptions, Dictionary, compress_with_cdict, cparams_create_cdict_for_testing,
};

/// xorshift64* — deterministic, dependency-free test data generator.
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

/// A raw-content dictionary built from the same vocabulary as the payloads.
fn raw_dict_content() -> Vec<u8> {
    raw_dict_of_size(8192)
}

/// A larger raw dictionary, sized so the CDict's windowLog exceeds 14 at the
/// lazy-family levels — exercising the **row** match finder's dictMatchState arm
/// (the 8 KB dict stays on the hash chain). Kept at 24 KB: large enough for
/// windowLog 15, but below the smallest per-level `maxDictSize` so the dict is
/// loaded whole (C's suffix-only truncation for huge dicts is a separate,
/// not-yet-ported, cross-strategy concern — see `ZSTD_loadDictionaryContent`).
fn big_raw_dict_content() -> Vec<u8> {
    raw_dict_of_size(24 * 1024)
}

fn raw_dict_of_size(target: usize) -> Vec<u8> {
    let mut rng = Rng::new(0xD1C7_0001);
    let mut d = Vec::with_capacity(target);
    while d.len() < target {
        d.extend_from_slice(WORDS[rng.below(WORDS.len())]);
        d.push(b' ');
    }
    d
}

/// Train a real ZDICT-format dictionary (seeds the CDict entropy on Path B).
fn trained_dict() -> Vec<u8> {
    let mut rng = Rng::new(0x7DC7_BA01);
    let mut samples = Vec::new();
    let mut sizes = Vec::new();
    for _ in 0..3000 {
        let mut s = Vec::new();
        let n = 8 + rng.below(24);
        for _ in 0..n {
            s.extend_from_slice(WORDS[rng.below(WORDS.len())]);
            s.push(b' ');
        }
        sizes.push(s.len());
        samples.extend_from_slice(&s);
    }
    zstd::dict::from_continuous(&samples, &sizes, 16 * 1024).expect("dictionary training failed")
}

/// Payloads of assorted sizes spanning the 8 KB attach/copy cutoff.
fn payloads() -> Vec<Vec<u8>> {
    let mut rng = Rng::new(0x9A7E_F00D);
    let mut out = vec![Vec::new(), b"alpha bravo charlie".to_vec()];
    for &len in &[64usize, 500, 4096, 60_000] {
        let mut p = Vec::with_capacity(len);
        while p.len() < len {
            p.extend_from_slice(WORDS[rng.below(WORDS.len())]);
            p.push(b' ');
        }
        p.truncate(len);
        out.push(p);
    }
    out
}

/// C oracle: `ZSTD_compress_usingCDict` via the bulk `with_dictionary` wrapper.
fn oracle(src: &[u8], dict: &[u8], level: i32) -> Vec<u8> {
    let mut c = zstd::bulk::Compressor::with_dictionary(level, dict).unwrap();
    c.compress(src).unwrap()
}

const FAST: u32 = 1;
const DFAST: u32 = 2;
const GREEDY: u32 = 3;
const LAZY: u32 = 4;
const LAZY2: u32 = 5;
const BTLAZY2: u32 = 6;
const BTOPT: u32 = 7;
const BTULTRA: u32 = 8;
const BTULTRA2: u32 = 9;

/// Every level is now supported (all nine CDict strategies), as long as the
/// dictionary has more than 8 bytes of content (true for the test dicts).
fn supported_levels(_dict_len: usize) -> Vec<i32> {
    (-3..=22).collect()
}

/// Whether the CDict's lazy family would use the row finder (windowLog > 14) vs
/// the hash chain — mirrors `ZSTD_resolveRowMatchFinderMode`/`use_row_match_finder`.
fn cdict_uses_row(level: i32, dict_len: usize) -> bool {
    let cp = cparams_create_cdict_for_testing(level, dict_len as u64);
    matches!(cp[6], GREEDY | LAZY | LAZY2) && cp[0] > 14
}

/// Match-finder coverage observed: the lazy family's row / hash-chain hits
/// (greedy/lazy/lazy2), btlazy2's binary tree, and the optimal parser
/// (btopt/btultra/btultra2).
struct LazyCoverage {
    row: u64,
    chain: u64,
    bt: u64,
    opt: u64,
}

fn check_dict(dict_bytes: &[u8]) -> LazyCoverage {
    let dict_obj = Dictionary::new(dict_bytes).expect("dict parse");
    let levels = supported_levels(dict_bytes.len());
    let mut by_strategy = [0u64; 10];
    assert!(
        !levels.is_empty(),
        "expected some implemented-strategy CDict levels for a {}-byte dict",
        dict_bytes.len()
    );

    let mut attach = 0u64;
    let mut copy = 0u64;
    let mut lazy_row = 0u64;
    let mut lazy_chain = 0u64;
    let mut bt = 0u64;
    let mut opt = 0u64;
    for data in payloads() {
        for &level in &levels {
            let ours = compress_with_cdict(&data, dict_bytes, level).unwrap_or_else(|e| {
                panic!(
                    "compress_with_cdict errored (src={}, level={level}): {e}",
                    data.len()
                )
            });
            let theirs = oracle(&data, dict_bytes, level);
            assert_eq!(
                ours,
                theirs,
                "byte mismatch vs C with_dictionary: src={}, level={level}",
                data.len()
            );
            let decoded = DecodeOptions::new()
                .dictionary(&dict_obj)
                .decompress(&ours)
                .unwrap_or_else(|e| {
                    panic!("decode failed: src={}, level={level}: {e}", data.len())
                });
            assert_eq!(
                decoded,
                data,
                "round-trip mismatch: src={}, level={level}",
                data.len()
            );

            let strat = cparams_create_cdict_for_testing(level, dict_bytes.len() as u64)[6];
            by_strategy[strat as usize] += 1;
            // The strategy-specific attach/copy cutoff (fast 8K, dfast 16K,
            // greedy/lazy/lazy2/btlazy2/btopt 32K, btultra/btultra2 8K) decides
            // which reset path ran.
            let cutoff = match strat {
                GREEDY | LAZY | LAZY2 | BTLAZY2 | BTOPT => 32 * 1024,
                DFAST => 16 * 1024,
                _ => 8 * 1024,
            };
            if data.len() <= cutoff {
                attach += 1;
            } else {
                copy += 1;
            }
            if matches!(strat, GREEDY | LAZY | LAZY2) {
                if cdict_uses_row(level, dict_bytes.len()) {
                    lazy_row += 1;
                } else {
                    lazy_chain += 1;
                }
            }
            if strat == BTLAZY2 {
                bt += 1;
            }
            if matches!(strat, BTOPT | BTULTRA | BTULTRA2) {
                opt += 1;
            }
        }
    }
    assert!(
        attach > 0 && copy > 0,
        "must exercise both attach ({attach}) and copy ({copy}) paths"
    );
    let lazy_total =
        by_strategy[GREEDY as usize] + by_strategy[LAZY as usize] + by_strategy[LAZY2 as usize];
    assert!(
        lazy_total > 0,
        "must exercise the lazy family (greedy/lazy/lazy2)"
    );
    // Every CDict strategy must be exercised (all nine are now implemented).
    for s in FAST..=BTULTRA2 {
        assert!(
            by_strategy[s as usize] > 0,
            "strategy {s} not exercised for the {}-byte dict",
            dict_bytes.len()
        );
    }
    println!(
        "dict {} bytes: strategies {:?}, attach {attach}, copy {copy}, lazy_row {lazy_row}, lazy_chain {lazy_chain}, bt {bt}, opt {opt}",
        dict_bytes.len(),
        &by_strategy[1..=9],
    );
    LazyCoverage {
        row: lazy_row,
        chain: lazy_chain,
        bt,
        opt,
    }
}

#[test]
fn fast_cdict_raw_is_bit_exact_and_round_trips() {
    // The 8 KB dict keeps the lazy family on the hash-chain backend, and also
    // exercises btlazy2's binary tree and the optimal parser's dictMatchState
    // arm (attach + copy).
    let cov = check_dict(&raw_dict_content());
    assert!(cov.chain > 0, "8 KB dict should hit the hash-chain backend");
    assert!(
        cov.bt > 0,
        "8 KB dict should exercise btlazy2 (binary tree)"
    );
    assert!(cov.opt > 0, "8 KB dict should exercise the optimal parser");
}

#[test]
fn fast_cdict_trained_is_bit_exact_and_round_trips() {
    check_dict(&trained_dict());
}

#[test]
fn big_cdict_raw_exercises_row_finder() {
    // A 24 KB dict pushes the CDict windowLog past 14, so the lazy family uses
    // the row match finder's dictMatchState arm (attach and copy).
    let cov = check_dict(&big_raw_dict_content());
    assert!(cov.row > 0, "24 KB dict should hit the row backend");
}

fn ws(seed: u64, len: usize) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut d = Vec::with_capacity(len + 16);
    while d.len() < len {
        d.extend_from_slice(WORDS[rng.below(WORDS.len())]);
        d.push(b' ');
    }
    d.truncate(len);
    d
}

/// Regression for the `loadedDictEnd` / `checkDictValidity` port: a CDict **copy**
/// over an input that fills (or exceeds) the window keeps the whole dictionary
/// referenceable down to `lowLimit` (`ZSTD_getLowestMatchIndex`'s `isDictionary`
/// branch), and drops it only once its last byte leaves the window
/// (`ZSTD_checkDictValidity` / `ZSTD_window_enforceMaxDist`). The other copy
/// tests here use < 60 KB single-block inputs that never fill the window, so this
/// pins the window-filling behavior. Byte-exact vs `ZSTD_compress_usingCDict`.
///
/// At a fast level the resized window is `1 << 19`; `n = 524288` reaches exactly
/// the window (the dict stays valid — needs the `isDictionary` floor), and
/// `n = 716800` exceeds it (the dict is invalidated mid-frame). Without the port
/// these diverge megabytes-style at the first long backward match into the dict.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "heavy differential test (multi-hundred-KB); run in release"
)]
fn cdict_copy_window_filling_is_bit_exact() {
    // The specific dict+body below makes a long backward match reach into the
    // dictionary just past `maxDist`, which is exactly what the port fixes.
    let dict = ws(0xD1C7, 16 * 1024);
    let dict_obj = Dictionary::new(&dict).expect("dict parse");
    for &level in &[1i32, 2, 3] {
        let body = ws(0xC0B7 ^ level as u64 ^ 716800, 716800);
        for &n in &[400_000usize, 524_288, 716_800] {
            let src = &body[..n];
            let theirs = oracle(src, &dict, level);
            let mine = compress_with_cdict(src, &dict, level).unwrap();
            assert_eq!(
                mine, theirs,
                "cdict copy window-filling mismatch: level={level} n={n}"
            );
            let decoded = DecodeOptions::new()
                .dictionary(&dict_obj)
                .decompress(&mine)
                .expect("decode with dict");
            assert_eq!(decoded, src, "round-trip: level={level} n={n}");
        }
    }
}
