//! Differential tests for **dictionary compression** (`compress_with_dict`),
//! Task 2 increment 1: raw (content-only) dictionaries, fast strategy, extDict
//! path. The oracle is C libzstd 1.5.7's `ZSTD_compress_usingDict` (via the safe
//! `zstd_safe::CCtx::compress_using_dict` wrapper) — NOT `with_dictionary`,
//! which is the separate CDict / dictMatchState path that produces different
//! bytes.
//!
//! For each (dict, payload, level) we resolve the strategy the dict-aware
//! cParams select (through the doc-hidden `cparams_for_testing` hook):
//!   * fast strategy  -> `compress_with_dict` must be byte-identical to the C
//!     oracle, and must round-trip through our own decoder with the dictionary;
//!   * any other strategy -> `compress_with_dict` must reject cleanly (the
//!     increment-1 gate), with no divergent output.

use libzstd_bitexact::{
    DecodeOptions, Dictionary, compress, compress_with_dict, cparams_for_testing,
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

/// A raw-content dictionary: plausible window history made of the same words the
/// payloads use, so the compressor actually emits matches into it.
fn raw_dict_content() -> Vec<u8> {
    let mut rng = Rng::new(0xD1C7_0001);
    let mut d = Vec::with_capacity(8192);
    while d.len() < 8192 {
        d.extend_from_slice(WORDS[rng.below(WORDS.len())]);
        d.push(b' ');
    }
    d
}

/// Payloads of assorted sizes, from the same vocabulary as the dictionary so
/// references into it are exercised. Sizes: 0, 19, 64, 500, 4096, 60000.
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

/// `ZSTD_strategy::ZSTD_fast` discriminant — element [6] of `cparams_for_testing`.
const FAST: u32 = 1;

/// The strategy our (and C's) dict-aware cParams select for a known srcSize.
fn strategy_of(level: i32, src_len: usize, dict_len: usize) -> u32 {
    cparams_for_testing(level, src_len as u64, dict_len as u64)[6]
}

/// C oracle: `ZSTD_compress_usingDict` (the extDict path) at `level`.
fn oracle(src: &[u8], dict: &[u8], level: i32) -> Vec<u8> {
    use zstd::zstd_safe;
    let mut dst = Vec::with_capacity(zstd_safe::compress_bound(src.len()));
    let mut cctx = zstd_safe::CCtx::create();
    cctx.compress_using_dict(&mut dst, src, dict, level)
        .expect("C oracle ZSTD_compress_usingDict failed");
    dst
}

#[test]
fn raw_dict_fast_is_bit_exact_and_round_trips_else_rejected() {
    let big = raw_dict_content();
    // Dictionary sizes spanning the C boundaries:
    //   < 8  -> dict ignored entirely (still influences cParams);
    //   == 8 -> extDict live but no table fill;
    //   9    -> fill loop runs zero times (boundary);
    //   >= 10 -> table actually populated.
    let dicts: Vec<Vec<u8>> = vec![
        Vec::new(),
        big[..7].to_vec(),
        big[..8].to_vec(),
        big[..9].to_vec(),
        big[..10].to_vec(),
        big[..64].to_vec(),
        big[..1024].to_vec(),
        big.clone(),
    ];
    // Negative + 1/2 resolve to fast at these sizes; 3/9/19 resolve to
    // dfast/lazy/opt, exercising the increment-1 gate.
    let levels = [-3, -1, 1, 2, 3, 9, 19];

    let mut fast_checks = 0u64;
    let mut gate_checks = 0u64;
    for dict in &dicts {
        for data in payloads() {
            for &level in &levels {
                let strat = strategy_of(level, data.len(), dict.len());
                let ours = compress_with_dict(&data, dict, level);

                if strat == FAST {
                    let ours = ours.unwrap_or_else(|e| {
                        panic!(
                            "compress_with_dict errored on fast config (dict={}, src={}, level={level}): {e}",
                            dict.len(),
                            data.len()
                        )
                    });
                    let theirs = oracle(&data, dict, level);
                    assert_eq!(
                        ours,
                        theirs,
                        "byte mismatch vs C: dict={}, src={}, level={level}",
                        dict.len(),
                        data.len()
                    );
                    // Independently round-trip through our decoder with the dict.
                    let dict_obj = Dictionary::new(dict).expect("raw dict parse");
                    let decoded = DecodeOptions::new()
                        .dictionary(&dict_obj)
                        .decompress(&ours)
                        .unwrap_or_else(|e| {
                            panic!(
                                "decode failed: dict={}, src={}, level={level}: {e}",
                                dict.len(),
                                data.len()
                            )
                        });
                    assert_eq!(
                        decoded,
                        data,
                        "round-trip mismatch: dict={}, src={}, level={level}",
                        dict.len(),
                        data.len()
                    );
                    fast_checks += 1;
                } else {
                    assert!(
                        ours.is_err(),
                        "non-fast strategy {strat} must be gated (dict={}, src={}, level={level})",
                        dict.len(),
                        data.len()
                    );
                    gate_checks += 1;
                }
            }
        }
    }
    assert!(
        fast_checks > 0 && gate_checks > 0,
        "matrix should exercise both the fast path ({fast_checks}) and the gate ({gate_checks})"
    );
}

/// An empty dictionary must behave exactly like no-dictionary `compress`.
#[test]
fn empty_dict_matches_plain_compress() {
    for data in payloads() {
        for level in [-1, 1, 2] {
            let with_empty = compress_with_dict(&data, &[], level).expect("fast, must succeed");
            let plain = compress(&data, level).expect("fast, must succeed");
            assert_eq!(
                with_empty,
                plain,
                "empty-dict output must equal plain compress: src={}, level={level}",
                data.len()
            );
        }
    }
}

/// A trained (ZDICT) dictionary is not supported yet and must be rejected
/// cleanly (never a divergent or panicking path).
#[test]
fn trained_dictionary_is_rejected() {
    // Minimal well-formed-enough header: the 4-byte ZSTD_MAGIC_DICTIONARY
    // followed by padding to clear the >= 8 byte length check.
    let mut trained = vec![0x37, 0xA4, 0x30, 0xEC]; // 0xEC30A437 little-endian
    trained.extend_from_slice(&[0u8; 60]);
    for data in payloads() {
        let r = compress_with_dict(&data, &trained, 1);
        assert!(
            r.is_err(),
            "trained dict must be rejected (src={})",
            data.len()
        );
    }
}
