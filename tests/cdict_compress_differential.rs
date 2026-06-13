//! Differential tests for **CDict** dictionary compression
//! (`compress_with_cdict`), Task 2 increment 7 (Path B): the CDict /
//! `dictMatchState` path. The oracle is C libzstd 1.5.7's
//! `zstd::bulk::Compressor::with_dictionary` (= `ZSTD_compress_usingCDict`),
//! which produces **different bytes** than `ZSTD_compress_usingDict` (Path A,
//! [`compress_with_dict`]).
//!
//! Sub-commit 1 implements the **fast** strategy only. This test targets the
//! levels whose CDict uses the fast strategy and spans payload sizes on both
//! sides of the 8 KB attach/copy cutoff, so both the **attach** (small `src`,
//! dictMatchState matcher) and **copy** (large `src`, de-tagged tables) paths
//! are exercised, plus a round-trip through our own decoder.

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
    let mut rng = Rng::new(0xD1C7_0001);
    let mut d = Vec::with_capacity(8192);
    while d.len() < 8192 {
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

/// The levels whose CDict (for this dict size) uses the fast strategy.
fn fast_levels(dict_len: usize) -> Vec<i32> {
    (-3..=22)
        .filter(|&l| cparams_create_cdict_for_testing(l, dict_len as u64)[6] == FAST)
        .collect()
}

fn check_dict(dict_bytes: &[u8]) {
    let dict_obj = Dictionary::new(dict_bytes).expect("dict parse");
    let levels = fast_levels(dict_bytes.len());
    assert!(
        !levels.is_empty(),
        "expected some fast-strategy CDict levels for a {}-byte dict",
        dict_bytes.len()
    );

    let mut attach = 0u64;
    let mut copy = 0u64;
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

            if data.len() <= 8 * 1024 {
                attach += 1;
            } else {
                copy += 1;
            }
        }
    }
    assert!(
        attach > 0 && copy > 0,
        "must exercise both attach ({attach}) and copy ({copy}) paths"
    );
}

#[test]
fn fast_cdict_raw_is_bit_exact_and_round_trips() {
    check_dict(&raw_dict_content());
}

#[test]
fn fast_cdict_trained_is_bit_exact_and_round_trips() {
    check_dict(&trained_dict());
}
