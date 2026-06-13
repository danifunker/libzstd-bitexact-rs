//! Differential tests for **dictionary compression** (`compress_with_dict`),
//! Task 2 increments 1-2: raw (content-only) dictionaries, fast and dfast
//! strategies, extDict path. The oracle is C libzstd 1.5.7's
//! `ZSTD_compress_usingDict` (via the safe `zstd_safe::CCtx::compress_using_dict`
//! wrapper) — NOT `with_dictionary`, which is the separate CDict /
//! dictMatchState path that produces different bytes.
//!
//! For each (dict, payload, level) we resolve the strategy the dict-aware
//! cParams select (through the doc-hidden `cparams_for_testing` hook):
//!   * fast or dfast -> `compress_with_dict` must be byte-identical to the C
//!     oracle, and must round-trip through our own decoder with the dictionary;
//!   * any other strategy -> `compress_with_dict` must reject cleanly (the
//!     current gate), with no divergent output.

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

/// `ZSTD_strategy` discriminants — element [6] of `cparams_for_testing`. Used to
/// pick the greedy/lazy/lazy2 backend (row vs hash chain) and to assert
/// per-strategy coverage. All nine strategies are supported for raw dicts.
const GREEDY: u32 = 3;
const LAZY: u32 = 4;
const LAZY2: u32 = 5;

/// The (strategy, windowLog) our — and C's — dict-aware cParams select for a
/// known srcSize. windowLog decides the greedy/lazy/lazy2 backend: the row
/// finder when `windowLog > 14`, otherwise the hash chain.
fn strat_and_wlog(level: i32, src_len: usize, dict_len: usize) -> (u32, u32) {
    let cp = cparams_for_testing(level, src_len as u64, dict_len as u64);
    (cp[6], cp[0])
}

/// C oracle: `ZSTD_compress_usingDict` (the extDict path) at `level`. Works for
/// both raw and trained dictionaries — C auto-detects the `ZDICT` magic and
/// seeds the entropy tables accordingly.
fn oracle(src: &[u8], dict: &[u8], level: i32) -> Vec<u8> {
    use zstd::zstd_safe;
    let mut dst = Vec::with_capacity(zstd_safe::compress_bound(src.len()));
    let mut cctx = zstd_safe::CCtx::create();
    cctx.compress_using_dict(&mut dst, src, dict, level)
        .expect("C oracle ZSTD_compress_usingDict failed");
    dst
}

/// Build a real trained (`ZDICT`) dictionary from word-salad samples via the
/// bundled C dictionary trainer. Unlike a raw-content dictionary, the result
/// carries `ZSTD_MAGIC_DICTIONARY`, a nonzero dictionary ID, and precomputed
/// entropy tables — so it exercises the `ZSTD_loadCEntropy` seeding path
/// (Huffman + 3 FSE CTables + repeat offsets + dict ID), not just the matcher
/// fill. Training is `unsafe` raw FFI, which is fine in a test.
fn trained_dict() -> Vec<u8> {
    let mut rng = Rng::new(0x7A1A_ED01);
    // A few thousand small samples from the same vocabulary as the payloads, so
    // the trainer finds repeated content worth storing.
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
    // It really is a formatted dictionary: 0xEC30A437 little-endian.
    assert_eq!(
        &dict[..4],
        &[0x37, 0xA4, 0x30, 0xEC],
        "trained dict must start with the ZDICT magic"
    );
    dict
}

#[test]
fn raw_dict_all_strategies_are_bit_exact_and_round_trip() {
    let big = raw_dict_content();
    // Dictionary sizes spanning the C boundaries:
    //   < 8  -> dict ignored entirely (still influences cParams);
    //   == 8 -> extDict live but no table fill;
    //   9    -> fast fill runs zero times, the lazy/tree fill inserts one;
    //   >= 10 -> tables actually populated.
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
    // Levels -3,-1 and 1..=22 cover all nine strategies across tables 2 and 3:
    // fast/dfast/greedy/lazy/lazy2 (greedy/lazy/lazy2 in BOTH the row finder at
    // the 60000-byte payload, windowLog 17, and the hash chain at the small
    // payloads, windowLog 14), btlazy2, and btopt/btultra/btultra2. The coverage
    // assertions below fail loudly if any strategy class stops being exercised.
    let levels: Vec<i32> = [-3, -1].into_iter().chain(1..=22).collect();

    // Per-strategy and per-backend coverage, so nothing silently goes untested.
    let mut by_strategy = [0u64; 10]; // indexed by ZSTD_strategy discriminant (1..=9)
    let mut lazy_row = 0u64;
    let mut lazy_hc = 0u64;
    for dict in &dicts {
        for data in payloads() {
            for &level in &levels {
                let (strat, wlog) = strat_and_wlog(level, data.len(), dict.len());
                let ours = compress_with_dict(&data, dict, level).unwrap_or_else(|e| {
                    panic!(
                        "compress_with_dict errored (strat={strat}, dict={}, src={}, level={level}): {e}",
                        dict.len(),
                        data.len()
                    )
                });
                let theirs = oracle(&data, dict, level);
                assert_eq!(
                    ours,
                    theirs,
                    "byte mismatch vs C: strat={strat}, wlog={wlog}, dict={}, src={}, level={level}",
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
                by_strategy[strat as usize] += 1;
                // Which backend did the greedy/lazy/lazy2 family exercise?
                if matches!(strat, GREEDY | LAZY | LAZY2) {
                    if wlog > 14 {
                        lazy_row += 1;
                    } else {
                        lazy_hc += 1;
                    }
                }
            }
        }
    }
    // All nine strategies and both greedy/lazy/lazy2 backends must be exercised.
    for s in 1..=9u32 {
        assert!(
            by_strategy[s as usize] > 0,
            "strategy {s} was never exercised (counts={by_strategy:?})"
        );
    }
    assert!(
        lazy_row > 0 && lazy_hc > 0,
        "must exercise both the row finder ({lazy_row}) and the hash chain ({lazy_hc})"
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

/// A trained (`ZDICT`) dictionary must match C's `ZSTD_compress_usingDict`
/// byte-for-byte across every strategy, and round-trip through our own decoder.
/// This exercises the `ZSTD_loadCEntropy` seeding (Huffman + 3 FSE CTables +
/// repeat offsets) and the `Dictionary_ID` in the frame header on top of the
/// shared match-finder fill.
#[test]
fn trained_dict_all_strategies_are_bit_exact_and_round_trip() {
    let dict = trained_dict();
    // Levels -3,-1 and 1..=22 cover all nine strategies (a fixed dictionary size
    // means each rSize bucket walks fast..btultra2 as the level rises).
    let levels: Vec<i32> = [-3, -1].into_iter().chain(1..=22).collect();
    let dict_obj = Dictionary::new(&dict).expect("trained dict parse");

    let mut by_strategy = [0u64; 10];
    for data in payloads() {
        for &level in &levels {
            let (strat, wlog) = strat_and_wlog(level, data.len(), dict.len());
            let ours = compress_with_dict(&data, &dict, level).unwrap_or_else(|e| {
                panic!(
                    "compress_with_dict errored (strat={strat}, src={}, level={level}): {e}",
                    data.len()
                )
            });
            let theirs = oracle(&data, &dict, level);
            assert_eq!(
                ours,
                theirs,
                "byte mismatch vs C: strat={strat}, wlog={wlog}, src={}, level={level}",
                data.len()
            );
            // Independently round-trip through our decoder with the same dict.
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
            by_strategy[strat as usize] += 1;
        }
    }
    for s in 1..=9u32 {
        assert!(
            by_strategy[s as usize] > 0,
            "strategy {s} was never exercised (counts={by_strategy:?})"
        );
    }
}

/// A buffer that begins with the `ZDICT` magic but is otherwise malformed must
/// be rejected cleanly (never a divergent or panicking path).
#[test]
fn malformed_trained_dict_is_rejected() {
    // The 4-byte ZSTD_MAGIC_DICTIONARY followed by a dict ID and zero-filled
    // padding: long enough to be treated as a trained dict, but the entropy
    // tables cannot be parsed out of the zeros.
    let mut trained = vec![0x37, 0xA4, 0x30, 0xEC]; // 0xEC30A437 little-endian
    trained.extend_from_slice(&[0u8; 60]);
    for data in payloads() {
        let r = compress_with_dict(&data, &trained, 1);
        assert!(
            r.is_err(),
            "malformed trained dict must be rejected (src={})",
            data.len()
        );
    }
}
