//! `get_cparams` must derive exactly the same compression parameters as C
//! libzstd 1.5.7's `ZSTD_getCParams_internal`. We compare field-by-field against
//! the bundled C oracle `ZSTD_getCParams` over a (level × srcSize × dictSize)
//! matrix. This covers the new dictionary-aware derivation (Task 2: dictionary
//! compression) and re-validates the existing no-dictionary path.
//!
//! Two C subtleties the comparison must respect (see `ZSTD_getCParams` /
//! `ZSTD_getCParamRowSize` / `ZSTD_adjustCParams_internal` in `zstd_compress.c`):
//!
//! * `ZSTD_getCParams` maps a `0` srcSizeHint to `ZSTD_CONTENTSIZE_UNKNOWN`
//!   internally, then runs in mode `cpm_unknown`. For cParam math `cpm_unknown`
//!   is identical to `cpm_noAttachDict` (both merely `break` in the rowsize and
//!   adjust switches), so the oracle exercises the same path our
//!   `ZSTD_compress_usingDict` (extDict) port uses. We mirror the `0 → UNKNOWN`
//!   mapping when feeding our function so the inputs match.
//! * For an unknown source size *with* a dictionary, C's rowSize computation
//!   wraps in `U64` (`U64::MAX + dict + 500 ≡ dict + 499`); our port reproduces
//!   the wrap, and this matrix exercises it via the `src == 0` rows.
//!
//! The oracle is raw FFI (`unsafe`), so this lives in `tests/`: the library is
//! `#![forbid(unsafe_code)]`. `libzstd_bitexact::cparams_for_testing` is the
//! doc-hidden hook surfacing our derivation as plain integers (integration tests
//! cannot see the `pub(crate)` `get_cparams` / `CParams` / `Strategy`).

use libzstd_bitexact::cparams_for_testing;

/// `ZSTD_CONTENTSIZE_UNKNOWN` — what `ZSTD_getCParams` substitutes for a 0 hint.
const CONTENTSIZE_UNKNOWN: u64 = u64::MAX;

/// The C oracle's parameters as `[windowLog, chainLog, hashLog, searchLog,
/// minMatch, targetLength, strategy]`, matching `cparams_for_testing`'s order.
fn oracle(level: i32, src: u64, dict: u64) -> [u32; 7] {
    // SAFETY: `ZSTD_getCParams` is a pure function of three scalar arguments —
    // it reads no caller memory, allocates nothing, and cannot fail. The result
    // is a small POD struct of integers.
    let cp = unsafe { zstd_sys::ZSTD_getCParams(level, src, dict as usize) };
    [
        cp.windowLog,
        cp.chainLog,
        cp.hashLog,
        cp.searchLog,
        cp.minMatch,
        cp.targetLength,
        cp.strategy as u32,
    ]
}

#[test]
fn cparams_match_c_oracle_over_matrix() {
    // Levels: the clamp boundaries plus every named level. i32::MIN exercises
    // the clamp-before-negate in the negative-level acceleration factor; values
    // above ZSTD_MAX_CLEVEL exercise the upper clamp; 0 is "default" (level 3).
    let levels: Vec<i32> = {
        let mut v = vec![
            i32::MIN,
            -200_000,
            -131_072, // ZSTD_minCLevel() = -(1 << 17)
            -131_071,
            -1_000,
            -10,
            -3,
            -2,
            -1,
        ];
        v.extend(0..=22);
        v.extend([23, 24, 100, i32::MAX]);
        v
    };

    // Source sizes: the tableID thresholds (16 KB / 128 KB / 256 KB) and their
    // ±1 neighbours, the windowLog-resize threshold (1<<30) and its neighbours,
    // the hashSizeMin boundary (64), and 0 (→ UNKNOWN). A few large known sizes
    // exercise the no-resize / dictAndWindowLog paths.
    let srcs: Vec<u64> = vec![
        0,
        1,
        19,
        63,
        64,
        65,
        500,
        512,
        513,
        1024,
        16 * 1024 - 1,
        16 * 1024,
        16 * 1024 + 1,
        60_000,
        65_536,
        128 * 1024 - 1,
        128 * 1024,
        128 * 1024 + 1,
        256 * 1024 - 1,
        256 * 1024,
        256 * 1024 + 1,
        1 << 20,
        (1 << 30) - 1,
        1 << 30,
        (1 << 30) + 1,
        1 << 31,
        1 << 40,
    ];

    // Dictionary sizes: 0 (no dict), values around HASH_READ_SIZE (8), the
    // tableID thresholds, the windowLog-resize threshold, and oversized dicts
    // that drive dictAndWindowLog to ZSTD_WINDOWLOG_MAX.
    let dicts: Vec<u64> = vec![
        0,
        1,
        7,
        8,
        9,
        64,
        1024,
        8 * 1024,
        16 * 1024,
        32 * 1024,
        64 * 1024,
        112_640, // a representative trained-dictionary size
        128 * 1024,
        256 * 1024,
        1 << 20,
        (1 << 30) - 1,
        1 << 30,
        (1 << 30) + 1,
        1 << 31,
    ];

    let mut checked = 0u64;
    for &level in &levels {
        for &src in &srcs {
            for &dict in &dicts {
                // Mirror ZSTD_getCParams's `0 srcSizeHint → UNKNOWN` mapping so
                // our function receives the same effective source size the
                // oracle does.
                let src_hint = if src == 0 { CONTENTSIZE_UNKNOWN } else { src };
                let mine = cparams_for_testing(level, src_hint, dict);
                let theirs = oracle(level, src, dict);
                assert_eq!(
                    mine, theirs,
                    "cParams mismatch at level={level} src={src} dict={dict}\n\
                     mine [w,c,h,s,mm,tl,strat] = {mine:?}\n\
                     C    [w,c,h,s,mm,tl,strat] = {theirs:?}"
                );
                checked += 1;
            }
        }
    }
    // Guard against the matrix silently collapsing to nothing.
    assert_eq!(
        checked,
        levels.len() as u64 * srcs.len() as u64 * dicts.len() as u64
    );
    assert!(checked > 10_000, "matrix unexpectedly small: {checked}");
}
