//! One-shot compression (`ZSTD_compress`), aiming for **byte-identical output
//! to C libzstd 1.5.7**: parameter derivation (`ZSTD_getCParams` /
//! `ZSTD_adjustCParams`), the match finders, and frame assembly
//! (`ZSTD_writeFrameHeader` / `ZSTD_compress_frameChunk` /
//! `ZSTD_compressBlock_internal`).
//!
//! Current scope: **every compression level** (1-22 and the negative /
//! acceleration levels), any input size, no dictionary, no checksum — the
//! `ZSTD_compress` defaults. [`compress_with_dict`] additionally primes the
//! match finder from a raw dictionary (`ZSTD_compress_usingDict`, extDict
//! path), for raw dictionaries at every strategy (fast through btultra2). This
//! includes the configurations where C
//! auto-enables long-distance matching (`strategy >= btopt && windowLog >=
//! 27`, i.e. level 22 beyond 64 MiB), whose match finder ([`crate::ldm`]) is
//! bit-exact. All nine strategies are implemented: fast and
//! dfast here, greedy/lazy/lazy2/btlazy2 in [`crate::lazy`], and
//! btopt/btultra/btultra2 in [`crate::opt`]. Block boundaries follow
//! `ZSTD_optimalBlockSize` (the 1.5.7 pre-block splitter,
//! [`crate::pre_split`]); the bt-opt strategies additionally run the
//! post-block splitter ([`crate::post_split`]).

use crate::error::Error;
use crate::pre_split;
use crate::sequences_encode::{self, FseEntropyState, SeqStore};

/// `ZSTD_WINDOW_START_INDEX`: indices 0 and 1 are reserved, so a hash-table
/// entry of 0 always reads as "empty / out of window".
const WINDOW_START_INDEX: usize = 2;
const K_SEARCH_STRENGTH: u32 = 8;
const HASH_READ_SIZE: usize = 8;
const BLOCK_SIZE_MAX: usize = 128 * 1024;
const MIN_CBLOCK_SIZE: usize = 2;
const BLOCK_HEADER_SIZE: usize = 3;
const WINDOWLOG_ABSOLUTEMIN: u32 = 10;
const HASHLOG_MIN: u32 = 6;
/// `ZSTD_SHORT_CACHE_TAG_BITS`: the low bits of a CDict tagged-table entry hold
/// a hash tag; the high bits hold the index. Used by the `dictMatchState`
/// (CDict) match finders for fast/dfast.
const SHORT_CACHE_TAG_BITS: u32 = 8;
/// `ZSTD_WINDOWLOG_MAX` on 64-bit targets (`ZSTD_WINDOWLOG_MAX_64`).
const WINDOWLOG_MAX: u32 = 31;
/// `ZSTD_CONTENTSIZE_UNKNOWN`: the source size is not known in advance.
const CONTENTSIZE_UNKNOWN: u64 = u64::MAX;
const ZSTD_MAGIC: u32 = 0xFD2F_B528;
/// `ZSTD_MAGIC_DICTIONARY`: a dictionary of at least 8 bytes beginning with
/// this magic is a trained (ZDICT) dictionary rather than raw content.
const MAGIC_DICTIONARY: u32 = 0xEC30_A437;

// --- Compression parameters --------------------------------------------------

/// `ZSTD_strategy`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Debug)]
pub(crate) enum Strategy {
    Fast = 1,
    Dfast = 2,
    Greedy = 3,
    Lazy = 4,
    Lazy2 = 5,
    Btlazy2 = 6,
    Btopt = 7,
    Btultra = 8,
    Btultra2 = 9,
}

/// `ZSTD_compressionParameters`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CParams {
    pub window_log: u32,
    pub chain_log: u32,
    pub hash_log: u32,
    /// Unused by the fast strategy; read once the search strategies land.
    #[allow(dead_code)]
    pub search_log: u32,
    pub min_match: u32,
    pub target_length: u32,
    pub strategy: Strategy,
}

/// One `ZSTD_defaultCParameters` row: (W, C, H, S, L, TL, strategy).
type CParamsRow = (u32, u32, u32, u32, u32, u32, Strategy);

/// `ZSTD_defaultCParameters` (clevels.h, zstd 1.5.7): rows 0..=22 for the four
/// source-size classes. Row 0 is the base for negative levels.
#[rustfmt::skip]
const DEFAULT_CPARAMETERS: [[CParamsRow; 23]; 4] = {
    use Strategy::*;
    [
    [   /* "default" - for any srcSize > 256 KB */
        (19, 12, 13,  1,  6,  1, Fast),
        (19, 13, 14,  1,  7,  0, Fast),
        (20, 15, 16,  1,  6,  0, Fast),
        (21, 16, 17,  1,  5,  0, Dfast),
        (21, 18, 18,  1,  5,  0, Dfast),
        (21, 18, 19,  3,  5,  2, Greedy),
        (21, 18, 19,  3,  5,  4, Lazy),
        (21, 19, 20,  4,  5,  8, Lazy),
        (21, 19, 20,  4,  5, 16, Lazy2),
        (22, 20, 21,  4,  5, 16, Lazy2),
        (22, 21, 22,  5,  5, 16, Lazy2),
        (22, 21, 22,  6,  5, 16, Lazy2),
        (22, 22, 23,  6,  5, 32, Lazy2),
        (22, 22, 22,  4,  5, 32, Btlazy2),
        (22, 22, 23,  5,  5, 32, Btlazy2),
        (22, 23, 23,  6,  5, 32, Btlazy2),
        (22, 22, 22,  5,  5, 48, Btopt),
        (23, 23, 22,  5,  4, 64, Btopt),
        (23, 23, 22,  6,  3, 64, Btultra),
        (23, 24, 22,  7,  3, 256, Btultra2),
        (25, 25, 23,  7,  3, 256, Btultra2),
        (26, 26, 24,  7,  3, 512, Btultra2),
        (27, 27, 25,  9,  3, 999, Btultra2),
    ],
    [   /* for srcSize <= 256 KB */
        (18, 12, 13,  1,  5,  1, Fast),
        (18, 13, 14,  1,  6,  0, Fast),
        (18, 14, 14,  1,  5,  0, Dfast),
        (18, 16, 16,  1,  4,  0, Dfast),
        (18, 16, 17,  3,  5,  2, Greedy),
        (18, 17, 18,  5,  5,  2, Greedy),
        (18, 18, 19,  3,  5,  4, Lazy),
        (18, 18, 19,  4,  4,  4, Lazy),
        (18, 18, 19,  4,  4,  8, Lazy2),
        (18, 18, 19,  5,  4,  8, Lazy2),
        (18, 18, 19,  6,  4,  8, Lazy2),
        (18, 18, 19,  5,  4, 12, Btlazy2),
        (18, 19, 19,  7,  4, 12, Btlazy2),
        (18, 18, 19,  4,  4, 16, Btopt),
        (18, 18, 19,  4,  3, 32, Btopt),
        (18, 18, 19,  6,  3, 128, Btopt),
        (18, 19, 19,  6,  3, 128, Btultra),
        (18, 19, 19,  8,  3, 256, Btultra),
        (18, 19, 19,  6,  3, 128, Btultra2),
        (18, 19, 19,  8,  3, 256, Btultra2),
        (18, 19, 19, 10,  3, 512, Btultra2),
        (18, 19, 19, 12,  3, 512, Btultra2),
        (18, 19, 19, 13,  3, 999, Btultra2),
    ],
    [   /* for srcSize <= 128 KB */
        (17, 12, 12,  1,  5,  1, Fast),
        (17, 12, 13,  1,  6,  0, Fast),
        (17, 13, 15,  1,  5,  0, Fast),
        (17, 15, 16,  2,  5,  0, Dfast),
        (17, 17, 17,  2,  4,  0, Dfast),
        (17, 16, 17,  3,  4,  2, Greedy),
        (17, 16, 17,  3,  4,  4, Lazy),
        (17, 16, 17,  3,  4,  8, Lazy2),
        (17, 16, 17,  4,  4,  8, Lazy2),
        (17, 16, 17,  5,  4,  8, Lazy2),
        (17, 16, 17,  6,  4,  8, Lazy2),
        (17, 17, 17,  5,  4,  8, Btlazy2),
        (17, 18, 17,  7,  4, 12, Btlazy2),
        (17, 18, 17,  3,  4, 12, Btopt),
        (17, 18, 17,  4,  3, 32, Btopt),
        (17, 18, 17,  6,  3, 256, Btopt),
        (17, 18, 17,  6,  3, 128, Btultra),
        (17, 18, 17,  8,  3, 256, Btultra),
        (17, 18, 17, 10,  3, 512, Btultra),
        (17, 18, 17,  5,  3, 256, Btultra2),
        (17, 18, 17,  7,  3, 512, Btultra2),
        (17, 18, 17,  9,  3, 512, Btultra2),
        (17, 18, 17, 11,  3, 999, Btultra2),
    ],
    [   /* for srcSize <= 16 KB */
        (14, 12, 13,  1,  5,  1, Fast),
        (14, 14, 15,  1,  5,  0, Fast),
        (14, 14, 15,  1,  4,  0, Fast),
        (14, 14, 15,  2,  4,  0, Dfast),
        (14, 14, 14,  4,  4,  2, Greedy),
        (14, 14, 14,  3,  4,  4, Lazy),
        (14, 14, 14,  4,  4,  8, Lazy2),
        (14, 14, 14,  6,  4,  8, Lazy2),
        (14, 14, 14,  8,  4,  8, Lazy2),
        (14, 15, 14,  5,  4,  8, Btlazy2),
        (14, 15, 14,  9,  4,  8, Btlazy2),
        (14, 15, 14,  3,  4, 12, Btopt),
        (14, 15, 14,  4,  3, 24, Btopt),
        (14, 15, 14,  5,  3, 32, Btultra),
        (14, 15, 15,  6,  3, 64, Btultra),
        (14, 15, 15,  7,  3, 256, Btultra),
        (14, 15, 15,  5,  3, 48, Btultra2),
        (14, 15, 15,  6,  3, 128, Btultra2),
        (14, 15, 15,  7,  3, 256, Btultra2),
        (14, 15, 15,  8,  3, 256, Btultra2),
        (14, 15, 15,  8,  3, 512, Btultra2),
        (14, 15, 15,  9,  3, 512, Btultra2),
        (14, 15, 15, 10,  3, 999, Btultra2),
    ],
    ]
};

const ZSTD_MAX_CLEVEL: i32 = 22;
const ZSTD_CLEVEL_DEFAULT: i32 = 3;
/// `ZSTD_minCLevel` = -(1 << 17).
const ZSTD_MIN_CLEVEL: i32 = -(1 << 17);

fn highbit32(x: u32) -> u32 {
    debug_assert!(x >= 1);
    31 - x.leading_zeros()
}

/// `ZSTD_cycleLog`.
fn cycle_log(hash_log: u32, strat: Strategy) -> u32 {
    let bt_scale = (strat as i32 >= Strategy::Btlazy2 as i32) as u32;
    hash_log - bt_scale
}

/// `ZSTD_dictAndWindowLog`: the window log enlarged so the hash/chain logs can
/// reference both the dictionary and the live window (the zstd format treats the
/// whole dictionary as in-window if any one byte of it is). Used only to
/// downsize hashLog/chainLog. `src_size` must not be `CONTENTSIZE_UNKNOWN` — the
/// caller guards, as the C `assert` documents.
fn dict_and_window_log(window_log: u32, src_size: u64, dict_size: u64) -> u32 {
    // No dictionary ==> no change.
    if dict_size == 0 {
        return window_log;
    }
    let max_window_size = 1u64 << WINDOWLOG_MAX;
    let window_size = 1u64 << window_log;
    let dict_and_window_size = dict_size.wrapping_add(window_size);
    if window_size >= dict_size.wrapping_add(src_size) {
        // Window already large enough for dict + src.
        window_log
    } else if dict_and_window_size >= max_window_size {
        WINDOWLOG_MAX
    } else {
        // C truncates dictAndWindowSize to U32 before highbit32, then +1.
        highbit32((dict_and_window_size as u32).wrapping_sub(1)) + 1
    }
}

/// Which `ZSTD_CParamMode_e` the cParam derivation models. The two we need
/// derive the same row size but adjust the chosen parameters differently.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CParamMode {
    /// `ZSTD_cpm_noAttachDict` — `ZSTD_compress` and the `compress_usingDict`
    /// (extDict) path.
    NoAttachDict,
    /// `ZSTD_cpm_createCDict` — the parameters a CDict's own matchState is built
    /// with (an assumed small source, plus the short-cache hash/chain caps).
    CreateCDict,
}

/// `ZSTD_getCParams_internal` + `ZSTD_adjustCParams_internal` for mode
/// `ZSTD_cpm_noAttachDict` — the derivation used by `ZSTD_compress` and the
/// `ZSTD_compress_usingDict` (extDict) path. `src_size == CONTENTSIZE_UNKNOWN`
/// selects the unknown-size behavior; `dict_size == 0` means no dictionary.
/// Yields the same cParams as the public `ZSTD_getCParams` once that maps a 0
/// srcSizeHint to UNKNOWN (`cpm_unknown` and `cpm_noAttachDict` derive identical
/// cParams); `tests/cparams_differential.rs` checks this field-by-field.
pub(crate) fn get_cparams(level: i32, src_size: u64, dict_size: u64) -> CParams {
    get_cparams_mode(level, src_size, dict_size, CParamMode::NoAttachDict)
}

/// cParams for a CDict's own matchState (`ZSTD_getCParams_internal` mode
/// `ZSTD_cpm_createCDict`, source size unknown). These size the dictionary's
/// (tagged) tables and become the working tables on the CDict *copy* path.
pub(crate) fn get_cparams_create_cdict(level: i32, dict_size: u64) -> CParams {
    get_cparams_mode(
        level,
        CONTENTSIZE_UNKNOWN,
        dict_size,
        CParamMode::CreateCDict,
    )
}

fn get_cparams_mode(level: i32, src_size: u64, dict_size: u64, mode: CParamMode) -> CParams {
    // --- ZSTD_getCParamRowSize (createCDict & noAttachDict keep dictSize) ---
    let unknown = src_size == CONTENTSIZE_UNKNOWN;
    let r_size = if unknown && dict_size == 0 {
        CONTENTSIZE_UNKNOWN
    } else {
        // C: srcSizeHint + dictSize + (unknown && dict>0 ? 500 : 0) in U64.
        // When unknown, srcSizeHint is U64::MAX and the sum wraps exactly as C,
        // so an unknown src with a dict yields rSize = dictSize + 499.
        let added: u64 = if unknown && dict_size > 0 { 500 } else { 0 };
        src_size.wrapping_add(dict_size).wrapping_add(added)
    };
    let table_id = (r_size <= 256 * 1024) as usize
        + (r_size <= 128 * 1024) as usize
        + (r_size <= 16 * 1024) as usize;
    // Level 0 means "default"; negative levels use row 0 as their base.
    let row = if level == 0 {
        ZSTD_CLEVEL_DEFAULT
    } else {
        level.clamp(0, ZSTD_MAX_CLEVEL)
    } as usize;

    let (w, c, h, s, l, t, strat) = DEFAULT_CPARAMETERS[table_id][row];
    let mut cp = CParams {
        window_log: w,
        chain_log: c,
        hash_log: h,
        search_log: s,
        min_match: l,
        target_length: t,
        strategy: strat,
    };
    if level < 0 {
        // Acceleration factor for negative levels (clamp to ZSTD_minCLevel
        // before negating so i32::MIN can't overflow).
        cp.target_length = (-level.max(ZSTD_MIN_CLEVEL)) as u32;
    }

    adjust_cparams_internal(cp, src_size, dict_size, mode)
}

/// `ZSTD_adjustCParams_internal`: downsize a base parameter set for the actual
/// source and dictionary sizes. Reused with a CDict's own cParams to size the
/// attach path's working tables (`ZSTD_resetCCtx_byAttachingCDict`).
fn adjust_cparams_internal(
    mut cp: CParams,
    src_size: u64,
    dict_size: u64,
    mode: CParamMode,
) -> CParams {
    // `cpm_createCDict` assumes a small source (`minSrcSize = 513`) when the
    // size is unknown but a dictionary is present, so the window/hash downsizing
    // below runs against that assumed source instead of being skipped.
    let adj_src =
        if mode == CParamMode::CreateCDict && dict_size != 0 && src_size == CONTENTSIZE_UNKNOWN {
            513
        } else {
            src_size
        };
    // Resize windowLog down when the input (src + dict) is small.
    let max_window_resize = 1u64 << (WINDOWLOG_MAX - 1);
    if adj_src <= max_window_resize && dict_size <= max_window_resize {
        let t_size = (adj_src + dict_size) as u32;
        let hash_size_min = 1u32 << HASHLOG_MIN;
        let src_log = if t_size < hash_size_min {
            HASHLOG_MIN
        } else {
            highbit32(t_size - 1) + 1
        };
        if cp.window_log > src_log {
            cp.window_log = src_log;
        }
    }
    // Downsize hashLog/chainLog to the dict-aware window log. Skipped when the
    // source size is unknown, matching the C guard (dictAndWindowLog asserts a
    // known srcSize).
    if adj_src != CONTENTSIZE_UNKNOWN {
        let daw_log = dict_and_window_log(cp.window_log, adj_src, dict_size);
        let cyc_log = cycle_log(cp.chain_log, cp.strategy);
        if cp.hash_log > daw_log + 1 {
            cp.hash_log = daw_log + 1;
        }
        if cyc_log > daw_log {
            cp.chain_log -= cyc_log - daw_log;
        }
    }
    if cp.window_log < WINDOWLOG_ABSOLUTEMIN {
        cp.window_log = WINDOWLOG_ABSOLUTEMIN;
    }
    // `cpm_createCDict` with tagged indices (fast/dfast use the short cache):
    // hashLog and chainLog can use at most `32 - SHORT_CACHE_TAG_BITS(8)` bits.
    if mode == CParamMode::CreateCDict && matches!(cp.strategy, Strategy::Fast | Strategy::Dfast) {
        let max_short_cache_hash_log = 32 - SHORT_CACHE_TAG_BITS;
        cp.hash_log = cp.hash_log.min(max_short_cache_hash_log);
        cp.chain_log = cp.chain_log.min(max_short_cache_hash_log);
    }
    // Row-match-finder hashLog cap: (hashLog - rowLog + 8) <= 32. C
    // conservatively assumes row mode is on for the strategies that support it
    // (greedy..lazy2; useRowMatchFinder auto -> enable).
    if matches!(
        cp.strategy,
        Strategy::Greedy | Strategy::Lazy | Strategy::Lazy2
    ) {
        let row_log = cp.search_log.clamp(4, 6);
        let max_hash_log = (32 - 8) + row_log;
        if cp.hash_log > max_hash_log {
            cp.hash_log = max_hash_log;
        }
    }
    cp
}

/// Test hook for `tests/cparams_differential.rs`: `get_cparams` as
/// `[windowLog, chainLog, hashLog, searchLog, minMatch, targetLength,
/// strategy]` (strategy as its `ZSTD_strategy` discriminant, 1..=9). The
/// differential oracle is raw `unsafe` FFI, which `#![forbid(unsafe_code)]`
/// bars from the library, so it must run from `tests/` — and integration tests
/// can't reach these `pub(crate)` internals. Not part of the stable public API.
#[doc(hidden)]
pub fn cparams_for_testing(level: i32, src_size: u64, dict_size: u64) -> [u32; 7] {
    let cp = get_cparams(level, src_size, dict_size);
    [
        cp.window_log,
        cp.chain_log,
        cp.hash_log,
        cp.search_log,
        cp.min_match,
        cp.target_length,
        cp.strategy as u32,
    ]
}

/// Test hook for `tests/cdict_compress_differential.rs`: the CDict's own
/// `cpm_createCDict` cParams (so a test can pick levels whose CDict uses the
/// fast strategy). Same `[wlog, clog, hlog, slog, mml, tlen, strategy]` shape.
#[doc(hidden)]
pub fn cparams_create_cdict_for_testing(level: i32, dict_size: u64) -> [u32; 7] {
    let cp = get_cparams_create_cdict(level, dict_size);
    [
        cp.window_log,
        cp.chain_log,
        cp.hash_log,
        cp.search_log,
        cp.min_match,
        cp.target_length,
        cp.strategy as u32,
    ]
}

// --- Small shared helpers ------------------------------------------------------

pub(crate) fn read32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
}

pub(crate) fn read64(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

/// `ZSTD_count`: length of the common run of `data[a..]` and `data[b..]`,
/// reading no further than `limit` for the `a` cursor.
pub(crate) fn count_eq(data: &[u8], mut a: usize, mut b: usize, limit: usize) -> usize {
    let start = a;
    while a < limit && data[a] == data[b] {
        a += 1;
        b += 1;
    }
    a - start
}

/// `ZSTD_hashPtr` for `mls` in 4..=8 (8 is the double-fast long hash), hashing
/// the bytes of `data` at `at`.
pub(crate) fn hash_ptr(data: &[u8], at: usize, hlog: u32, mls: u32) -> usize {
    const PRIME4: u32 = 2654435761;
    const PRIME5: u64 = 889523592379;
    const PRIME6: u64 = 227718039650203;
    const PRIME7: u64 = 58295818150454627;
    const PRIME8: u64 = 0xCF1B_BCDC_B7A5_6463;
    match mls {
        5 => ((read64(data, at) << (64 - 40)).wrapping_mul(PRIME5) >> (64 - hlog)) as usize,
        6 => ((read64(data, at) << (64 - 48)).wrapping_mul(PRIME6) >> (64 - hlog)) as usize,
        7 => ((read64(data, at) << (64 - 56)).wrapping_mul(PRIME7) >> (64 - hlog)) as usize,
        8 => (read64(data, at).wrapping_mul(PRIME8) >> (64 - hlog)) as usize,
        _ => (read32(data, at).wrapping_mul(PRIME4) >> (32 - hlog)) as usize,
    }
}

/// `ZSTD_index_overlap_check`: whether a repcode index is far enough below the
/// prefix start that its 4-byte read stays clear of the dict/prefix seam (admits
/// prefix-side repcodes outright and dict-side ones only when safe).
pub(crate) fn index_overlap_check(prefix_lowest_index: u32, rep_index: u32) -> bool {
    prefix_lowest_index.wrapping_sub(1).wrapping_sub(rep_index) >= 3
}

// --- The window (ZSTD_window_t) ----------------------------------------------------

/// `ZSTD_window_t`, with the C `base`/`dictBase` pointers replaced by index
/// biases into the caller's history buffer: index `i` of the *current*
/// segment lives at `buf[i - seg_bias]` (so `base = buf - seg_bias`), and the
/// previous segment — the extDict, `i` in `[low_limit, dict_limit)` — lives
/// at `buf[i - dict_bias]`.
///
/// One-shot compression is a single contiguous segment with `seg_bias == 2`
/// (`ZSTD_WINDOW_START_INDEX`). Streaming wraps its input buffer once full;
/// the wrap makes the next chunk non-contiguous, which turns the whole live
/// window into the extDict exactly as `ZSTD_window_update` does.
pub(crate) struct Window {
    pub(crate) seg_bias: u32,
    pub(crate) dict_bias: u32,
    /// `window.lowLimit`: lowest valid index overall (extDict start).
    pub(crate) low_limit: u32,
    /// `window.dictLimit`: first index of the current segment.
    pub(crate) dict_limit: u32,
    /// `window.nextSrc` as (buffer position, index): where the next chunk
    /// must start to be contiguous, and the index it would get.
    next_src_pos: usize,
    next_src_idx: u32,
}

impl Window {
    /// `ZSTD_window_init` (plus the first-update segment flip baked in: the
    /// first chunk always starts a fresh segment at index 2 with an empty
    /// dict, so the flip is a no-op).
    pub(crate) fn new() -> Self {
        Window {
            seg_bias: WINDOW_START_INDEX as u32,
            dict_bias: WINDOW_START_INDEX as u32,
            low_limit: WINDOW_START_INDEX as u32,
            dict_limit: WINDOW_START_INDEX as u32,
            next_src_pos: 0,
            next_src_idx: WINDOW_START_INDEX as u32,
        }
    }

    /// The window state `ZSTD_compress_usingDict` reaches just before
    /// compressing `src`: the dictionary has been loaded (a contiguous first
    /// chunk) and the separately-buffered `src` appended non-contiguously, so
    /// the dict became the extDict. We model the two C buffers as one
    /// concatenated `dict ++ src`, so both segments share `pos = index -
    /// ZSTD_WINDOW_START_INDEX` and `seg_bias == dict_bias == 2`:
    /// `dict` is indices `[2, 2+dict_len)` (the extDict), `src` is
    /// `[2+dict_len, 2+dict_len+src_len)` (the current segment). `nextSrc`
    /// points one past `src`, so a later contiguous append would extend it.
    pub(crate) fn preloaded_ext_dict(dict_len: usize, src_len: usize) -> Self {
        let start = WINDOW_START_INDEX as u32;
        Window {
            seg_bias: start,
            dict_bias: start,
            low_limit: start,
            dict_limit: start + dict_len as u32,
            next_src_pos: dict_len + src_len,
            next_src_idx: start + (dict_len + src_len) as u32,
        }
    }

    /// The window state a ZSTDMT job (after the first) reaches: the previous
    /// job's overlap tail is supplied as a raw-content prefix that is
    /// **contiguous** with the segment in C's round buffer, so the window does
    /// *not* flip to extDict — it stays noDict, with the prefix as ordinary
    /// in-window history. (Contrast [`preloaded_ext_dict`](Self::preloaded_ext_dict),
    /// where the dict is a separate buffer.) The whole `prefix ++ segment` buffer
    /// is the current segment at indices `[2, 2 + total_len)`, with
    /// `lowLimit == dictLimit == 2`, so the noDict matchers reach back into the
    /// prefix as far as `maxDist` allows.
    pub(crate) fn preloaded_contiguous_prefix(total_len: usize) -> Self {
        let start = WINDOW_START_INDEX as u32;
        Window {
            seg_bias: start,
            dict_bias: start,
            low_limit: start,
            dict_limit: start,
            next_src_pos: total_len,
            next_src_idx: start + total_len as u32,
        }
    }

    /// The window state `ZSTD_resetCCtx_byAttachingCDict` reaches: the
    /// dictionary lives in a *separate* match state (the attached CDict), so the
    /// working window is non-extDict with `src` as its only segment, starting at
    /// `cdictEnd`. We model `content ++ src` as one buffer, so `src` is the
    /// current segment `[2 + content_len, ..)` and `lowLimit == dictLimit`
    /// (no extDict — dict matches come from the attached state instead).
    pub(crate) fn preloaded_attached_dict(content_len: usize, src_len: usize) -> Self {
        let start = WINDOW_START_INDEX as u32;
        let src_start = start + content_len as u32;
        Window {
            seg_bias: start,
            dict_bias: start,
            low_limit: src_start,
            dict_limit: src_start,
            next_src_pos: content_len + src_len,
            next_src_idx: start + (content_len + src_len) as u32,
        }
    }

    /// Like [`preloaded_attached_dict`](Self::preloaded_attached_dict) but for
    /// *streaming*: the source length is not known up front, so `nextSrc` points
    /// at the *start* of the source region (position `content_len`) rather than
    /// past it, and `window_preloaded` is left off so the first
    /// `compress_continue` registers each chunk contiguously (no extDict flip)
    /// via `ZSTD_window_update`. The dict still lives in the attached match state
    /// (`lowLimit == dictLimit`, no extDict); the concatenated `content ++ input`
    /// staging buffer keeps `dictIndexDelta == 0`.
    pub(crate) fn streaming_attached_dict(content_len: usize) -> Self {
        let start = WINDOW_START_INDEX as u32;
        let src_start = start + content_len as u32;
        Window {
            seg_bias: start,
            dict_bias: start,
            low_limit: src_start,
            dict_limit: src_start,
            next_src_pos: content_len,
            next_src_idx: src_start,
        }
    }

    /// `ZSTD_window_update`: register `buf[start..end]` as the next chunk.
    /// Returns whether it was contiguous with the previous one; if not, the
    /// current prefix becomes the extDict. Also shrinks the extDict when the
    /// new chunk overwrites part of it in the (shared) buffer.
    pub(crate) fn update(&mut self, start: usize, end: usize) -> bool {
        if start == end {
            return true;
        }
        let mut contiguous = true;
        if start != self.next_src_pos {
            self.low_limit = self.dict_limit;
            self.dict_limit = self.next_src_idx;
            self.dict_bias = self.seg_bias;
            // `base = ip - distanceFromBase`, i.e. `buf[start]` gets the next
            // index. C does this as pointer arithmetic, so `base` may legitimately
            // point *before* the buffer: a separate window (e.g. the LDM window,
            // updated over the same `dict ++ src` staging buffer but whose input
            // must start at `WINDOW_START_INDEX`) yields `seg_bias = 2 - content_len`,
            // which wraps. The U32 index domain wraps consistently, so the
            // downstream `pos + seg_bias` recovers the right indices — match
            // `wrapping_sub`/`wrapping_add` to C rather than tripping the debug
            // overflow check (release already wraps).
            self.seg_bias = self.next_src_idx.wrapping_sub(start as u32);
            if self.dict_limit - self.low_limit < HASH_READ_SIZE as u32 {
                // Too small extDict: forget it.
                self.low_limit = self.dict_limit;
            }
            contiguous = false;
        }
        self.next_src_pos = end;
        self.next_src_idx = self.seg_bias.wrapping_add(end as u32);
        // If input and dictionary overlap (same buffer), reduce the
        // dictionary to the part not overwritten by the input. Pointer
        // comparisons in C; signed offsets here since the dict bias can
        // exceed the buffer positions involved.
        let dict_bias = i64::from(self.dict_bias);
        if (end as i64 > i64::from(self.low_limit) - dict_bias)
            && ((start as i64) < i64::from(self.dict_limit) - dict_bias)
        {
            let high_input_idx = end as i64 + dict_bias;
            self.low_limit = if high_input_idx > i64::from(self.dict_limit) {
                self.dict_limit
            } else {
                high_input_idx as u32
            };
        }
        contiguous
    }

    /// `ZSTD_window_enforceMaxDist` (no dictionary): called before each
    /// block; slides `lowLimit` to `idx - maxDist` and drags `dictLimit`
    /// along once the extDict falls out of the window. (The C parameter is
    /// named `blockEnd`, but `ZSTD_compress_frameChunk` anchors it at the
    /// block *start* `ip`.)
    pub(crate) fn enforce_max_dist(&mut self, idx: u32, max_dist: u32) {
        if idx > max_dist {
            let new_low_limit = idx - max_dist;
            if self.low_limit < new_low_limit {
                self.low_limit = new_low_limit;
            }
            if self.dict_limit < self.low_limit {
                self.dict_limit = self.low_limit;
            }
        }
    }

    /// `ZSTD_window_hasExtDict`, which decides the dict mode
    /// (`ZSTD_matchState_dictMode`): extDict iff `lowLimit < dictLimit`.
    pub(crate) fn has_ext_dict(&self) -> bool {
        self.low_limit < self.dict_limit
    }

    /// The window mutation of `ZSTD_initStats_ultra` (btultra2's first-block
    /// double pass): forget the first pass's match history by sliding the
    /// index space past the block (`window.base -= srcSize; dictLimit +=
    /// srcSize; lowLimit = dictLimit`). `nextSrc` stays put as a pointer, so
    /// its index moves with the base.
    pub(crate) fn slide_for_init_stats(&mut self, src_size: usize) {
        self.seg_bias += src_size as u32;
        self.dict_limit += src_size as u32;
        self.low_limit = self.dict_limit;
        self.next_src_idx += src_size as u32;
    }

    /// `ZSTD_window_needOverflowCorrection`: the running index reached
    /// `ZSTD_CURRENT_MAX` (3500 MiB on 64-bit), so the 32-bit index space must
    /// be recycled. `block_end_pos` is the block end as a buffer position;
    /// its index is `block_end_pos + seg_bias`.
    pub(crate) fn needs_overflow_correction(&self, block_end_pos: usize) -> bool {
        const CURRENT_MAX: u32 = 3500 * (1 << 20);
        (block_end_pos as u32).wrapping_add(self.seg_bias) > CURRENT_MAX
    }

    /// `ZSTD_window_correctOverflow`: reduce every index by the returned
    /// `correction` so the window's high index drops back to roughly
    /// `maxDist`, keeping the low `cycleLog` bits unchanged (the chains and
    /// binary trees index modulo a power of two). The caller must apply the
    /// same `correction` to every stored table index. `block_start_pos` is
    /// the block start as a buffer position (`src` in C).
    pub(crate) fn correct_overflow(
        &mut self,
        cycle_log: u32,
        max_dist: u32,
        block_start_pos: usize,
    ) -> u32 {
        let cycle_size = 1u32 << cycle_log;
        let cycle_mask = cycle_size - 1;
        let curr = block_start_pos as u32 + self.seg_bias;
        let current_cycle = curr & cycle_mask;
        // Ensure newCurrent - maxDist >= ZSTD_WINDOW_START_INDEX.
        let current_cycle_correction = if current_cycle < WINDOW_START_INDEX as u32 {
            cycle_size.max(WINDOW_START_INDEX as u32)
        } else {
            0
        };
        let new_current = current_cycle + current_cycle_correction + max_dist.max(cycle_size);
        let correction = curr - new_current;

        // `base += correction` (indices drop by `correction`) becomes
        // `seg_bias -= correction` here; the dict segment moves in lockstep.
        self.seg_bias -= correction;
        self.dict_bias -= correction;
        self.next_src_idx -= correction;
        let floor = correction + WINDOW_START_INDEX as u32;
        self.low_limit = if self.low_limit < floor {
            WINDOW_START_INDEX as u32
        } else {
            self.low_limit - correction
        };
        self.dict_limit = if self.dict_limit < floor {
            WINDOW_START_INDEX as u32
        } else {
            self.dict_limit - correction
        };
        correction
    }
}

/// `ZSTD_count_2segments`: count the match length when `match` lives in the
/// extDict segment — count up to `mend`, then continue comparing from
/// `istart` (the prefix start). All arguments are buffer positions.
pub(crate) fn count_2segments(
    buf: &[u8],
    ip: usize,
    matched: usize,
    iend: usize,
    mend: usize,
    istart: usize,
) -> usize {
    let v_end = (ip + (mend - matched)).min(iend);
    let match_length = count_eq(buf, ip, matched, v_end);
    if matched + match_length != mend {
        return match_length;
    }
    match_length + count_eq(buf, ip + match_length, istart, iend)
}

/// `ZSTD_reduceTable_internal`: subtract `correction` from every stored index
/// after an overflow correction, squashing anything below the reserved
/// `WINDOW_START_INDEX` floor to 0 (an empty slot). `preserve_mark` keeps the
/// btlazy2 `DUBT_UNSORTED_MARK` (value 1) untouched.
pub(crate) fn reduce_table(table: &mut [u32], correction: u32, preserve_mark: bool) {
    const DUBT_UNSORTED_MARK: u32 = 1;
    let threshold = correction + WINDOW_START_INDEX as u32;
    for v in table.iter_mut() {
        if preserve_mark && *v == DUBT_UNSORTED_MARK {
            // keep the sort sentinel
        } else if *v < threshold {
            *v = 0;
        } else {
            *v -= correction;
        }
    }
}

// --- The ZSTD_fast match finder ---------------------------------------------------

/// Position bias: index `i` of the input maps to match index `i + 2`
/// (`ZSTD_WINDOW_START_INDEX`), so hash-table zeros are never valid matches.
/// `idx_to_pos(idx) = idx - 2` and vice versa.
struct FastCtx {
    hash_table: Vec<u32>,
    hlog: u32,
    mls: u32,
    step_size: usize,
    window_log: u32,
}

impl FastCtx {
    fn new(cparams: &CParams) -> Self {
        FastCtx {
            hash_table: vec![0u32; 1usize << cparams.hash_log],
            hlog: cparams.hash_log,
            // stepSize = targetLength + !targetLength + 1 (min 2).
            step_size: cparams.target_length as usize + (cparams.target_length == 0) as usize + 1,
            mls: cparams.min_match.clamp(4, 7),
            window_log: cparams.window_log,
        }
    }

    /// `ZSTD_reduceIndex` for the fast strategy: only the hash table.
    fn reduce_indices(&mut self, correction: u32) {
        reduce_table(&mut self.hash_table, correction, false);
    }
}

/// `ZSTD_fillHashTableForCCtx` (fast strategy, `dtlm_fast`, untagged): seed the
/// hash table from the dictionary content laid out at `data[0..dict_len]`,
/// before compressing `src`. Each inserted entry is a *biased* index
/// (`pos + ZSTD_WINDOW_START_INDEX`), matching how the matcher stores and reads
/// positions, so the dict entries are found as extDict candidates.
///
/// `nextToUpdate` starts at dict position 0; C's loop `ip + 3 < iend + 2` with
/// `iend = dictEnd - HASH_READ_SIZE` is, in buffer positions, `ip + 9 <
/// dict_len`. The caller guarantees `dict_len > HASH_READ_SIZE` (otherwise C's
/// `ZSTD_loadDictionaryContent` returns before the fill, leaving an empty
/// table).
fn fill_fast_hash_table_for_cctx(ctx: &mut FastCtx, data: &[u8], dict_len: usize) {
    let hlog = ctx.hlog;
    let mls = ctx.mls;
    let mut ip = 0usize;
    while ip + 9 < dict_len {
        let h = hash_ptr(data, ip, hlog, mls);
        ctx.hash_table[h] = (ip + WINDOW_START_INDEX) as u32;
        ip += 3;
    }
}

/// `ZSTD_writeTaggedIndex`: pack `(index, tag)` into a CDict hash bucket. The
/// low [`SHORT_CACHE_TAG_BITS`] bits of `hash_and_tag` are the tag; the rest is
/// the bucket. The index is stored shifted up, the tag in the low bits.
fn write_tagged_index(table: &mut [u32], hash_and_tag: usize, index: u32) {
    let hash = hash_and_tag >> SHORT_CACHE_TAG_BITS;
    let tag = (hash_and_tag as u32) & ((1 << SHORT_CACHE_TAG_BITS) - 1);
    table[hash] = (index << SHORT_CACHE_TAG_BITS) | tag;
}

/// `ZSTD_fillHashTableForCDict` (fast strategy, `dtlm_full`, **tagged**): seed a
/// CDict's own hash table from the dictionary content at `data[0..dict_len]`.
/// Buckets are addressed by `hashLog + SHORT_CACHE_TAG_BITS` bits and store
/// `(biasedIndex << 8) | tag`; `dtlm_full` also inserts the p=1,2 positions when
/// their bucket is still empty. The caller sizes `table` to `1 << hlog` and
/// guarantees `dict_len > HASH_READ_SIZE`.
fn fill_fast_hash_table_for_cdict(
    table: &mut [u32],
    data: &[u8],
    dict_len: usize,
    hlog: u32,
    mls: u32,
) {
    let h_bits = hlog + SHORT_CACHE_TAG_BITS;
    let mut ip = 0usize;
    while ip + 9 < dict_len {
        let curr = (ip + WINDOW_START_INDEX) as u32;
        write_tagged_index(table, hash_ptr(data, ip, h_bits, mls), curr);
        // dtlm_full: also load the in-between positions if their bucket is empty.
        for p in 1..3usize {
            let hash_and_tag = hash_ptr(data, ip + p, h_bits, mls);
            if table[hash_and_tag >> SHORT_CACHE_TAG_BITS] == 0 {
                write_tagged_index(table, hash_and_tag, curr + p as u32);
            }
        }
        ip += 3;
    }
}

/// `ZSTD_fillHashTableForCCtx` with `dtlm_full` (untagged): the de-tagged form of
/// a CDict fast table is identical to an untagged `dtlm_full` fill, since
/// `hashPtr(p, hLog+8) >> 8 == hashPtr(p, hLog)`. Used by the CDict **copy**
/// path, which reproduces the CDict tables in the working context.
fn fill_fast_hash_table_for_cctx_full(ctx: &mut FastCtx, data: &[u8], dict_len: usize) {
    let hlog = ctx.hlog;
    let mls = ctx.mls;
    let mut ip = 0usize;
    while ip + 9 < dict_len {
        let curr = (ip + WINDOW_START_INDEX) as u32;
        ctx.hash_table[hash_ptr(data, ip, hlog, mls)] = curr;
        for p in 1..3usize {
            let h = hash_ptr(data, ip + p, hlog, mls);
            if ctx.hash_table[h] == 0 {
                ctx.hash_table[h] = curr + p as u32;
            }
        }
        ip += 3;
    }
}

/// `ZSTD_compressBlock_fast_dictMatchState_generic`: the CDict **attach** match
/// finder. The dictionary is a separate (tagged) match state; `ctx` holds the
/// working context's own untagged table, which starts empty and fills as `src`
/// is parsed. In our `content ++ src` buffer the working window is non-extDict
/// (src begins at `dictEnd`), so `dictIndexDelta == 0` and both tables index the
/// same buffer; a dict match is taken only when the working table found nothing
/// (`matchIndex <= prefixStartIndex`), replicating the extDict parse. `data` is
/// `content ++ src`; the block is `data[block_start..block_end]` (= `src`),
/// `content_len` is the dictionary content length.
#[allow(clippy::too_many_arguments)]
fn compress_block_fast_dict_match_state(
    ctx: &mut FastCtx,
    store: &mut SeqStore,
    rep: &mut [u32; 3],
    data: &[u8],
    block_start: usize,
    block_end: usize,
    content_len: usize,
    dict_hash_table: &[u32],
    dict_hlog: u32,
) -> usize {
    let bias = WINDOW_START_INDEX;
    let hlog = ctx.hlog;
    let mls = ctx.mls;
    // dictMatchState uses stepSize = targetLength + !targetLength (no +1).
    let step_size = ctx.step_size - 1;
    let k_step_incr = 1usize << K_SEARCH_STRENGTH;
    let dict_h_bits = dict_hlog + SHORT_CACHE_TAG_BITS;
    let tag_mask = (1u32 << SHORT_CACHE_TAG_BITS) - 1;

    // Window geometry (concat buffer, `base`/`dictBase` bias both = 2).
    let prefix_start_index = (bias + content_len) as u32; // window.dictLimit (src start)
    let dict_start_index = bias as u32; // dms.window.dictLimit
    let prefix_start_pos = content_len; // prefix_start_index - bias
    let dict_end_pos = content_len; // dictEnd - bias (== prefix start; dictIndexDelta 0)
    let iend_pos = block_end;

    let iend = block_end + bias;
    if block_end - block_start < HASH_READ_SIZE {
        return block_end - block_start;
    }
    let ilimit = iend - HASH_READ_SIZE;
    let istart = block_start + bias;
    let dict_and_prefix_length = (istart - prefix_start_index as usize) + content_len;

    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];

    let mut anchor = istart;
    let mut ip0 = istart + (dict_and_prefix_length == 0) as usize;
    let mut ip1 = ip0 + step_size;

    while ip1 <= ilimit {
        let mut hash0 = hash_ptr(data, ip0 - bias, hlog, mls);
        let dict_hat0 = hash_ptr(data, ip0 - bias, dict_h_bits, mls);
        let mut dict_idx_tag = dict_hash_table[dict_hat0 >> SHORT_CACHE_TAG_BITS];
        let mut dict_tags_match = (dict_idx_tag & tag_mask) == (dict_hat0 as u32 & tag_mask);
        let mut match_index = ctx.hash_table[hash0];
        let mut curr = ip0 as u32;
        let mut step = step_size;
        let mut next_step = ip0 + k_step_incr;

        // The inner search loop yields the match length (with `ip0`/`anchor`/
        // offsets already updated and the sequence stored), or returns on
        // running out of input.
        let m_length = loop {
            let rep_index = curr.wrapping_add(1).wrapping_sub(offset_1);
            let hash1 = hash_ptr(data, ip1 - bias, hlog, mls);
            let dict_hat1 = hash_ptr(data, ip1 - bias, dict_h_bits, mls);
            ctx.hash_table[hash0] = curr;

            // 1. repcode at ip0 + 1.
            if index_overlap_check(prefix_start_index, rep_index)
                && read32(data, rep_index as usize - bias) == read32(data, (ip0 + 1) - bias)
            {
                let mend = if rep_index < prefix_start_index {
                    dict_end_pos
                } else {
                    iend_pos
                };
                let ml = 4 + count_2segments(
                    data,
                    (ip0 + 1 - bias) + 4,
                    (rep_index as usize - bias) + 4,
                    iend_pos,
                    mend,
                    prefix_start_pos,
                );
                ip0 += 1;
                store.store_seq(&data[anchor - bias..ip0 - bias], 1, ml as u32);
                break ml;
            }

            // 2. dictionary match (only when the working table found nothing).
            if dict_tags_match {
                let dict_match_index = dict_idx_tag >> SHORT_CACHE_TAG_BITS;
                if dict_match_index > dict_start_index
                    && read32(data, dict_match_index as usize - bias) == read32(data, ip0 - bias)
                    && match_index <= prefix_start_index
                {
                    let offset = curr - dict_match_index; // dictIndexDelta == 0
                    let mut ml = 4 + count_2segments(
                        data,
                        (ip0 - bias) + 4,
                        (dict_match_index as usize - bias) + 4,
                        iend_pos,
                        dict_end_pos,
                        prefix_start_pos,
                    );
                    let mut dm = dict_match_index as usize;
                    while ip0 > anchor
                        && dm > dict_start_index as usize
                        && data[(ip0 - bias) - 1] == data[(dm - bias) - 1]
                    {
                        ip0 -= 1;
                        dm -= 1;
                        ml += 1;
                    }
                    offset_2 = offset_1;
                    offset_1 = offset;
                    store.store_seq(&data[anchor - bias..ip0 - bias], offset + 3, ml as u32);
                    break ml;
                }
            }

            // 3. ordinary match in the working context.
            if match_index >= prefix_start_index
                && read32(data, match_index as usize - bias) == read32(data, ip0 - bias)
            {
                let offset = curr - match_index;
                let mut ml = 4 + count_eq(
                    data,
                    (ip0 - bias) + 4,
                    (match_index as usize - bias) + 4,
                    iend_pos,
                );
                let mut m = match_index as usize;
                while ip0 > anchor
                    && m > prefix_start_index as usize
                    && data[(ip0 - bias) - 1] == data[(m - bias) - 1]
                {
                    ip0 -= 1;
                    m -= 1;
                    ml += 1;
                }
                offset_2 = offset_1;
                offset_1 = offset;
                store.store_seq(&data[anchor - bias..ip0 - bias], offset + 3, ml as u32);
                break ml;
            }

            // Prepare the next iteration.
            dict_idx_tag = dict_hash_table[dict_hat1 >> SHORT_CACHE_TAG_BITS];
            dict_tags_match = (dict_idx_tag & tag_mask) == (dict_hat1 as u32 & tag_mask);
            match_index = ctx.hash_table[hash1];
            if ip1 >= next_step {
                step += 1;
                next_step += k_step_incr;
            }
            ip0 = ip1;
            ip1 += step;
            if ip1 > ilimit {
                rep[0] = offset_1;
                rep[1] = offset_2;
                return iend_pos - (anchor - bias);
            }
            curr = ip0 as u32;
            hash0 = hash1;
        };

        // Match found: advance past it, then fill the table and run the
        // immediate-repcode loop.
        ip0 += m_length;
        anchor = ip0;
        if ip0 <= ilimit {
            ctx.hash_table[hash_ptr(data, (curr as usize + 2) - bias, hlog, mls)] = curr + 2;
            ctx.hash_table[hash_ptr(data, (ip0 - 2) - bias, hlog, mls)] = (ip0 - 2) as u32;
            while ip0 <= ilimit {
                let current2 = ip0 as u32;
                let rep_index2 = current2.wrapping_sub(offset_2);
                if index_overlap_check(prefix_start_index, rep_index2)
                    && read32(data, rep_index2 as usize - bias) == read32(data, ip0 - bias)
                {
                    let rep_end2 = if rep_index2 < prefix_start_index {
                        dict_end_pos
                    } else {
                        iend_pos
                    };
                    let rep_length2 = 4 + count_2segments(
                        data,
                        (ip0 - bias) + 4,
                        (rep_index2 as usize - bias) + 4,
                        iend_pos,
                        rep_end2,
                        prefix_start_pos,
                    );
                    std::mem::swap(&mut offset_1, &mut offset_2);
                    store.store_seq(&data[anchor - bias..ip0 - bias], 1, rep_length2 as u32);
                    ctx.hash_table[hash_ptr(data, ip0 - bias, hlog, mls)] = current2;
                    ip0 += rep_length2;
                    anchor = ip0;
                } else {
                    break;
                }
            }
        }
        ip1 = ip0 + step_size;
    }

    rep[0] = offset_1;
    rep[1] = offset_2;
    iend_pos - (anchor - bias)
}

/// `ZSTD_compressBlock_fast` (noDict path), operating on the history buffer
/// `data` with the current block being `data[block_start..block_end]`.
///
/// `seg_bias` maps buffer positions to window indices (`idx = pos +
/// seg_bias`; 2 for a frame's first segment) and `lowest_valid` is
/// `window.dictLimit`, the lowest index of the current segment — both only
/// differ from 2 after a streaming buffer wrap.
///
/// Returns the size of the trailing literals; emits sequences into `store` and
/// updates `rep`. The `useCmov`/branch variants of the candidate test are
/// semantically identical, so a single form is used.
#[allow(clippy::too_many_arguments)]
fn compress_block_fast(
    ctx: &mut FastCtx,
    store: &mut SeqStore,
    rep: &mut [u32; 3],
    data: &[u8],
    block_start: usize,
    block_end: usize,
    seg_bias: usize,
    lowest_valid: usize,
) -> usize {
    let src_size = block_end - block_start;
    let hlog = ctx.hlog;
    let mls = ctx.mls;
    let step_size = ctx.step_size;
    // `ZSTD_getLowestPrefixIndex(ms, endIndex, windowLog)`: once the frame
    // outgrows the window, the lowest valid match index slides to
    // blockEnd - windowSize. (Biased indices, like everything below.)
    let max_distance = 1usize << ctx.window_log;
    let end_index = block_end + seg_bias;
    let prefix_start_index = if end_index - lowest_valid > max_distance {
        end_index - max_distance
    } else {
        lowest_valid
    };
    let k_step_incr: usize = 1 << (K_SEARCH_STRENGTH - 1);

    // All `ipN` variables are *biased* indices (buffer position + seg_bias),
    // matching the C pointer arithmetic `ip - base`.
    let bias = seg_bias;
    let to_pos = |idx: usize| idx - bias; // biased index -> data position
    let istart = block_start + bias;
    let iend = block_end + bias;
    if src_size < HASH_READ_SIZE {
        return src_size;
    }
    let ilimit = iend - HASH_READ_SIZE;

    let mut anchor = istart;
    let mut ip0 = istart;
    let mut ip1: usize;
    let mut ip2: usize;
    let mut ip3: usize;
    let mut current0: u32;

    let mut rep_offset1 = rep[0];
    let mut rep_offset2 = rep[1];
    let mut offset_saved1 = 0u32;
    let mut offset_saved2 = 0u32;

    let mut hash0: usize;
    let mut hash1: usize;
    let mut match_idx: u32;

    let mut step: usize;
    let mut next_step: usize;

    // Candidate test (`ZSTD_match4Found_*`): valid window index and 4 equal
    // bytes. The C cmov/branch variants are semantically identical.
    let found = |data: &[u8], cur: usize, idx: u32| -> bool {
        idx as usize >= prefix_start_index
            && read32(data, to_pos(cur)) == read32(data, to_pos(idx as usize))
    };

    ip0 += (ip0 == prefix_start_index) as usize; // skip the very first window position
    {
        // `ZSTD_getLowestPrefixIndex(ms, curr, windowLog)` — at the *block
        // start*, not the block end: when the window slides, maxRep is the
        // full window size, one block more than prefix_start_index allows.
        let curr = ip0;
        let window_low = if curr - lowest_valid > max_distance {
            curr - max_distance
        } else {
            lowest_valid
        };
        let max_rep = (curr - window_low) as u32;
        if rep_offset2 > max_rep {
            offset_saved2 = rep_offset2;
            rep_offset2 = 0;
        }
        if rep_offset1 > max_rep {
            offset_saved1 = rep_offset1;
            rep_offset1 = 0;
        }
    }

    'outer: loop {
        // _start:
        step = step_size;
        next_step = ip0 + k_step_incr;
        ip1 = ip0 + 1;
        ip2 = ip0 + step;
        ip3 = ip2 + 1;

        if ip3 >= ilimit {
            break 'outer;
        }

        hash0 = hash_ptr(data, to_pos(ip0), hlog, mls);
        hash1 = hash_ptr(data, to_pos(ip1), hlog, mls);
        match_idx = ctx.hash_table[hash0];

        loop {
            // Repcode candidate at ip2 (read before the table write, as in C).
            let rval = if rep_offset1 > 0 {
                read32(data, to_pos(ip2 - rep_offset1 as usize))
            } else {
                0
            };

            current0 = ip0 as u32;
            ctx.hash_table[hash0] = current0;

            // Check repcode at ip2.
            if rep_offset1 > 0 && read32(data, to_pos(ip2)) == rval {
                ip0 = ip2;
                let mut match0 = ip0 - rep_offset1 as usize;
                let ext = (data[to_pos(ip0) - 1] == data[to_pos(match0) - 1]) as usize;
                let mut m_length = ext;
                ip0 -= ext;
                match0 -= ext;
                let offcode = 1u32; // REPCODE1_TO_OFFBASE
                m_length += 4;
                ctx.hash_table[hash1] = ip1 as u32;
                // _match
                m_length += count_eq(
                    data,
                    to_pos(ip0) + m_length,
                    to_pos(match0) + m_length,
                    to_pos(iend),
                );
                store.store_seq(&data[to_pos(anchor)..to_pos(ip0)], offcode, m_length as u32);
                ip0 += m_length;
                anchor = ip0;
                post_match(
                    ctx,
                    store,
                    data,
                    &mut ip0,
                    &mut anchor,
                    current0,
                    &mut rep_offset1,
                    &mut rep_offset2,
                    ilimit,
                    iend,
                    hlog,
                    mls,
                    bias,
                );
                continue 'outer;
            }

            if found(data, ip0, match_idx) {
                ctx.hash_table[hash1] = ip1 as u32;
                offset_and_match(
                    ctx,
                    store,
                    data,
                    &mut ip0,
                    &mut anchor,
                    current0,
                    &mut rep_offset1,
                    &mut rep_offset2,
                    match_idx,
                    prefix_start_index,
                    ilimit,
                    iend,
                    hlog,
                    mls,
                    bias,
                );
                continue 'outer;
            }

            match_idx = ctx.hash_table[hash1];
            hash0 = hash1;
            hash1 = hash_ptr(data, to_pos(ip2), hlog, mls);
            ip0 = ip1;
            ip1 = ip2;
            ip2 = ip3;

            current0 = ip0 as u32;
            ctx.hash_table[hash0] = current0;

            if found(data, ip0, match_idx) {
                if step <= 4 {
                    ctx.hash_table[hash1] = ip1 as u32;
                }
                offset_and_match(
                    ctx,
                    store,
                    data,
                    &mut ip0,
                    &mut anchor,
                    current0,
                    &mut rep_offset1,
                    &mut rep_offset2,
                    match_idx,
                    prefix_start_index,
                    ilimit,
                    iend,
                    hlog,
                    mls,
                    bias,
                );
                continue 'outer;
            }

            match_idx = ctx.hash_table[hash1];
            hash0 = hash1;
            hash1 = hash_ptr(data, to_pos(ip2), hlog, mls);
            ip0 = ip1;
            ip1 = ip2;
            ip2 = ip0 + step;
            ip3 = ip1 + step;

            if ip2 >= next_step {
                step += 1;
                next_step += k_step_incr;
            }
            if ip3 >= ilimit {
                break 'outer;
            }
        }
    }

    // _cleanup: restore any invalidated repcodes for the next block.
    offset_saved2 = if offset_saved1 != 0 && rep_offset1 != 0 {
        offset_saved1
    } else {
        offset_saved2
    };
    rep[0] = if rep_offset1 != 0 {
        rep_offset1
    } else {
        offset_saved1
    };
    rep[1] = if rep_offset2 != 0 {
        rep_offset2
    } else {
        offset_saved2
    };

    to_pos(iend) - to_pos(anchor)
}

/// The `_offset` + `_match` tail for an ordinary (non-repcode) match: compute
/// the offset, extend backward, count forward, store, then run the
/// post-match repcode loop. Control then re-enters `_start`, whose own
/// `ip3 >= ilimit` check decides whether to clean up.
#[allow(clippy::too_many_arguments)]
fn offset_and_match(
    ctx: &mut FastCtx,
    store: &mut SeqStore,
    data: &[u8],
    ip0: &mut usize,
    anchor: &mut usize,
    current0: u32,
    rep_offset1: &mut u32,
    rep_offset2: &mut u32,
    match_idx: u32,
    prefix_start_index: usize,
    ilimit: usize,
    iend: usize,
    hlog: u32,
    mls: u32,
    bias: usize,
) {
    let to_pos = |idx: usize| idx - bias;
    let mut match0 = match_idx as usize;

    *rep_offset2 = *rep_offset1;
    *rep_offset1 = (*ip0 - match0) as u32;
    let offcode = *rep_offset1 + 3; // OFFSET_TO_OFFBASE
    let mut m_length = 4usize;

    // Backward extension.
    while *ip0 > *anchor
        && match0 > prefix_start_index
        && data[to_pos(*ip0) - 1] == data[to_pos(match0) - 1]
    {
        *ip0 -= 1;
        match0 -= 1;
        m_length += 1;
    }

    // Forward extension.
    m_length += count_eq(
        data,
        to_pos(*ip0) + m_length,
        to_pos(match0) + m_length,
        to_pos(iend),
    );
    store.store_seq(
        &data[to_pos(*anchor)..to_pos(*ip0)],
        offcode,
        m_length as u32,
    );
    *ip0 += m_length;
    *anchor = *ip0;

    post_match(
        ctx,
        store,
        data,
        ip0,
        anchor,
        current0,
        rep_offset1,
        rep_offset2,
        ilimit,
        iend,
        hlog,
        mls,
        bias,
    );
}

/// The shared post-match tail: fill the hash table at `current0+2` and
/// `ip0-2`, then greedily emit immediate repcode matches; control returns to
/// `_start`.
#[allow(clippy::too_many_arguments)]
fn post_match(
    ctx: &mut FastCtx,
    store: &mut SeqStore,
    data: &[u8],
    ip0: &mut usize,
    anchor: &mut usize,
    current0: u32,
    rep_offset1: &mut u32,
    rep_offset2: &mut u32,
    ilimit: usize,
    iend: usize,
    hlog: u32,
    mls: u32,
    bias: usize,
) {
    let to_pos = |idx: usize| idx - bias;
    if *ip0 <= ilimit {
        // Fill table.
        let c02 = current0 as usize + 2;
        let h = hash_ptr(data, to_pos(c02), hlog, mls);
        ctx.hash_table[h] = c02 as u32;
        let h2 = hash_ptr(data, to_pos(*ip0 - 2), hlog, mls);
        ctx.hash_table[h2] = (*ip0 - 2) as u32;

        if *rep_offset2 > 0 {
            while *ip0 <= ilimit
                && read32(data, to_pos(*ip0)) == read32(data, to_pos(*ip0 - *rep_offset2 as usize))
            {
                let r_length = count_eq(
                    data,
                    to_pos(*ip0) + 4,
                    to_pos(*ip0 - *rep_offset2 as usize) + 4,
                    to_pos(iend),
                ) + 4;
                std::mem::swap(rep_offset1, rep_offset2);
                let h = hash_ptr(data, to_pos(*ip0), hlog, mls);
                ctx.hash_table[h] = *ip0 as u32;
                *ip0 += r_length;
                store.store_seq(&[], 1, r_length as u32); // REPCODE1, no literals
                *anchor = *ip0;
            }
        }
    }
}

// --- The ZSTD_fast extDict match finder --------------------------------------------

/// The per-block two-segment geometry of `ZSTD_compressBlock_fast_extDict`,
/// shared by the matcher body and its match tail. Index space is the window's
/// (`idx = pos + bias` per segment); `*_pos` fields are buffer positions.
struct ExtDictView {
    seg_bias: usize,
    dict_bias: usize,
    /// `prefixStartIndex` (== `dictLimit` while the extDict is live).
    prefix_start_index: usize,
    /// `dictStart`: lowest valid extDict byte, as a buffer position.
    dict_start_pos: usize,
    /// `dictEnd`: one-past-the-end of the extDict, as a buffer position.
    dict_end_pos: usize,
    prefix_start_pos: usize,
    iend_pos: usize,
    ilimit: usize,
}

impl ExtDictView {
    fn pos_p(&self, idx: usize) -> usize {
        idx - self.seg_bias
    }
    /// Buffer position of `idx`, resolved through the segment the C code
    /// would pick (`idx < prefixStartIndex ? dictBase : base`).
    fn pos_seg(&self, idx: usize) -> usize {
        if idx < self.prefix_start_index {
            idx - self.dict_bias
        } else {
            idx - self.seg_bias
        }
    }
    fn match_end_pos(&self, idx: usize) -> usize {
        if idx < self.prefix_start_index {
            self.dict_end_pos
        } else {
            self.iend_pos
        }
    }
}

/// `ZSTD_compressBlock_fast_extDict_generic`: the fast matcher over a
/// two-segment window — matches may start in the extDict (the pre-wrap
/// streaming history) and run across the seam into the prefix.
fn compress_block_fast_extdict(
    ctx: &mut FastCtx,
    store: &mut SeqStore,
    rep: &mut [u32; 3],
    data: &[u8],
    block_start: usize,
    block_end: usize,
    win: &Window,
) -> usize {
    let src_size = block_end - block_start;
    let hlog = ctx.hlog;
    let mls = ctx.mls;
    let step_size = ctx.step_size;
    let k_step_incr: usize = 1 << (K_SEARCH_STRENGTH - 1);

    let seg_bias = win.seg_bias as usize;
    let istart = block_start + seg_bias;
    let iend = block_end + seg_bias;
    let end_index = iend;

    // ZSTD_getLowestMatchIndex(ms, endIndex, windowLog): lowest valid index
    // in either segment.
    let max_distance = 1usize << ctx.window_log;
    let lowest_valid = win.low_limit as usize;
    let dict_start_index = if end_index - lowest_valid > max_distance {
        end_index - max_distance
    } else {
        lowest_valid
    };
    let dict_limit = win.dict_limit as usize;
    let prefix_start_index = dict_start_index.max(dict_limit);

    // Switch to the "regular" variant if extDict is invalidated by maxDistance.
    if prefix_start_index == dict_start_index {
        return compress_block_fast(
            ctx,
            store,
            rep,
            data,
            block_start,
            block_end,
            seg_bias,
            dict_limit,
        );
    }
    if src_size < HASH_READ_SIZE {
        return src_size;
    }

    let w = ExtDictView {
        seg_bias,
        dict_bias: win.dict_bias as usize,
        prefix_start_index,
        dict_start_pos: dict_start_index - win.dict_bias as usize,
        dict_end_pos: prefix_start_index - win.dict_bias as usize,
        prefix_start_pos: prefix_start_index - seg_bias,
        iend_pos: block_end,
        ilimit: iend - HASH_READ_SIZE,
    };

    let mut anchor = istart;
    let mut ip0 = istart;
    let mut ip1: usize;
    let mut ip2: usize;
    let mut ip3: usize;
    let mut current0: u32;

    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];
    let mut offset_saved1 = 0u32;
    let mut offset_saved2 = 0u32;

    // No first-position skip here; note `>=` where the noDict variant uses `>`.
    {
        let curr = ip0 as u32;
        let max_rep = curr - dict_start_index as u32;
        if offset_2 >= max_rep {
            offset_saved2 = offset_2;
            offset_2 = 0;
        }
        if offset_1 >= max_rep {
            offset_saved1 = offset_1;
            offset_1 = 0;
        }
    }

    let mut hash0: usize;
    let mut hash1: usize;
    let mut idx: u32;

    let mut step: usize;
    let mut next_step: usize;

    'outer: loop {
        // _start:
        step = step_size;
        next_step = ip0 + k_step_incr;
        ip1 = ip0 + 1;
        ip2 = ip0 + step;
        ip3 = ip2 + 1;

        if ip3 >= w.ilimit {
            break 'outer;
        }

        hash0 = hash_ptr(data, w.pos_p(ip0), hlog, mls);
        hash1 = hash_ptr(data, w.pos_p(ip1), hlog, mls);
        idx = ctx.hash_table[hash0];

        loop {
            // Load the repcode match for ip[2]. The `(U32)(prefixStartIndex -
            // repIndex) >= 4` intentional-underflow test admits prefix-side
            // repcodes outright and dict-side ones only when the 4-byte read
            // stays below the seam.
            let current2 = ip2;
            let rep_index = current2.wrapping_sub(offset_1 as usize);
            let rval = if (prefix_start_index as u32).wrapping_sub(rep_index as u32) >= 4
                && offset_1 > 0
            {
                read32(data, w.pos_seg(rep_index))
            } else {
                read32(data, w.pos_p(ip2)) ^ 1 // guaranteed to not match
            };

            // Write back hash table entry.
            current0 = ip0 as u32;
            ctx.hash_table[hash0] = current0;

            // Check repcode at ip[2].
            if read32(data, w.pos_p(ip2)) == rval {
                ip0 = ip2;
                let mut match0 = rep_index;
                let match_seg_pos = w.pos_seg(match0);
                let ext = (data[w.pos_p(ip0) - 1] == data[match_seg_pos - 1]) as usize;
                let mut m_length = ext;
                ip0 -= ext;
                match0 -= ext;
                m_length += 4;
                extdict_match_tail(
                    ctx,
                    store,
                    data,
                    &mut ip0,
                    &mut anchor,
                    current0,
                    &mut offset_1,
                    &mut offset_2,
                    m_length,
                    1, // REPCODE1_TO_OFFBASE
                    match0,
                    hash1,
                    ip1,
                    &w,
                );
                continue 'outer;
            }

            {
                // Load + check match for ip[0] (validity vs dictStartIndex,
                // segment select vs prefixStartIndex, as in C).
                let mval = if idx as usize >= dict_start_index {
                    read32(data, w.pos_seg(idx as usize))
                } else {
                    read32(data, w.pos_p(ip0)) ^ 1
                };
                if read32(data, w.pos_p(ip0)) == mval {
                    extdict_offset_and_match(
                        ctx,
                        store,
                        data,
                        &mut ip0,
                        &mut anchor,
                        current0,
                        &mut offset_1,
                        &mut offset_2,
                        idx,
                        hash1,
                        ip1,
                        &w,
                    );
                    continue 'outer;
                }
            }

            // Lookup ip[1], hash ip[2], advance.
            idx = ctx.hash_table[hash1];
            hash0 = hash1;
            hash1 = hash_ptr(data, w.pos_p(ip2), hlog, mls);
            ip0 = ip1;
            ip1 = ip2;
            ip2 = ip3;

            current0 = ip0 as u32;
            ctx.hash_table[hash0] = current0;

            {
                let mval = if idx as usize >= dict_start_index {
                    read32(data, w.pos_seg(idx as usize))
                } else {
                    read32(data, w.pos_p(ip0)) ^ 1
                };
                if read32(data, w.pos_p(ip0)) == mval {
                    extdict_offset_and_match(
                        ctx,
                        store,
                        data,
                        &mut ip0,
                        &mut anchor,
                        current0,
                        &mut offset_1,
                        &mut offset_2,
                        idx,
                        hash1,
                        ip1,
                        &w,
                    );
                    continue 'outer;
                }
            }

            idx = ctx.hash_table[hash1];
            hash0 = hash1;
            hash1 = hash_ptr(data, w.pos_p(ip2), hlog, mls);
            ip0 = ip1;
            ip1 = ip2;
            ip2 = ip0 + step;
            ip3 = ip1 + step;

            if ip2 >= next_step {
                step += 1;
                next_step += k_step_incr;
            }
            if ip3 >= w.ilimit {
                break 'outer;
            }
        }
    }

    // _cleanup: same saved-offset rotation as the noDict variant.
    offset_saved2 = if offset_saved1 != 0 && offset_1 != 0 {
        offset_saved1
    } else {
        offset_saved2
    };
    rep[0] = if offset_1 != 0 {
        offset_1
    } else {
        offset_saved1
    };
    rep[1] = if offset_2 != 0 {
        offset_2
    } else {
        offset_saved2
    };

    iend - anchor
}

/// The `_offset` tail: compute the offset from `idx`, extend backward within
/// the match's segment, then fall into the shared `_match` tail.
#[allow(clippy::too_many_arguments)]
fn extdict_offset_and_match(
    ctx: &mut FastCtx,
    store: &mut SeqStore,
    data: &[u8],
    ip0: &mut usize,
    anchor: &mut usize,
    current0: u32,
    offset_1: &mut u32,
    offset_2: &mut u32,
    idx: u32,
    hash1: usize,
    ip1: usize,
    w: &ExtDictView,
) {
    let offset = current0 - idx;
    let mut match0 = idx as usize;
    let in_dict = match0 < w.prefix_start_index;
    let low_match_pos = if in_dict {
        w.dict_start_pos
    } else {
        w.prefix_start_pos
    };
    let match_bias = if in_dict { w.dict_bias } else { w.seg_bias };

    *offset_2 = *offset_1;
    *offset_1 = offset;
    let offcode = offset + 3; // OFFSET_TO_OFFBASE
    let mut m_length = 4usize;

    // Count the backwards match length (bounded by the match's segment).
    while *ip0 > *anchor
        && (match0 - match_bias) > low_match_pos
        && data[w.pos_p(*ip0) - 1] == data[match0 - match_bias - 1]
    {
        *ip0 -= 1;
        match0 -= 1;
        m_length += 1;
    }

    extdict_match_tail(
        ctx, store, data, ip0, anchor, current0, offset_1, offset_2, m_length, offcode, match0,
        hash1, ip1, w,
    );
}

/// The `_match` tail: two-segment forward count, sequence store, the
/// conditional ip1 hash write-back, table fill, and the immediate-repcode
/// loop with two-segment reads.
#[allow(clippy::too_many_arguments)]
fn extdict_match_tail(
    ctx: &mut FastCtx,
    store: &mut SeqStore,
    data: &[u8],
    ip0: &mut usize,
    anchor: &mut usize,
    current0: u32,
    offset_1: &mut u32,
    offset_2: &mut u32,
    mut m_length: usize,
    offcode: u32,
    match0: usize,
    hash1: usize,
    ip1: usize,
    w: &ExtDictView,
) {
    let hlog = ctx.hlog;
    let mls = ctx.mls;

    // Count the forward length across the dict/prefix seam.
    m_length += count_2segments(
        data,
        w.pos_p(*ip0) + m_length,
        w.pos_seg(match0) + m_length,
        w.iend_pos,
        w.match_end_pos(match0),
        w.prefix_start_pos,
    );
    store.store_seq(
        &data[w.pos_p(*anchor)..w.pos_p(*ip0)],
        offcode,
        m_length as u32,
    );
    *ip0 += m_length;
    *anchor = *ip0;

    // Write next hash table entry.
    if ip1 < *ip0 {
        ctx.hash_table[hash1] = ip1 as u32;
    }

    // Fill table and check for immediate repcode.
    if *ip0 <= w.ilimit {
        let c02 = current0 as usize + 2;
        let h = hash_ptr(data, w.pos_p(c02), hlog, mls);
        ctx.hash_table[h] = c02 as u32;
        let h2 = hash_ptr(data, w.pos_p(*ip0 - 2), hlog, mls);
        ctx.hash_table[h2] = (*ip0 - 2) as u32;

        while *ip0 <= w.ilimit {
            let rep_index2 = ip0.wrapping_sub(*offset_2 as usize);
            // ZSTD_index_overlap_check: repIndex2 must not straddle the seam.
            let no_overlap = (w.prefix_start_index as u32)
                .wrapping_sub(1)
                .wrapping_sub(rep_index2 as u32)
                >= 3;
            if !(no_overlap && *offset_2 > 0) {
                break;
            }
            let rep_match2_pos = w.pos_seg(rep_index2);
            if read32(data, rep_match2_pos) != read32(data, w.pos_p(*ip0)) {
                break;
            }
            let rep_length2 = count_2segments(
                data,
                w.pos_p(*ip0) + 4,
                rep_match2_pos + 4,
                w.iend_pos,
                w.match_end_pos(rep_index2),
                w.prefix_start_pos,
            ) + 4;
            std::mem::swap(offset_1, offset_2);
            store.store_seq(&[], 1, rep_length2 as u32);
            let h = hash_ptr(data, w.pos_p(*ip0), hlog, mls);
            ctx.hash_table[h] = *ip0 as u32;
            *ip0 += rep_length2;
            *anchor = *ip0;
        }
    }
}

// --- The ZSTD_dfast match finder ----------------------------------------------------

/// Double-fast keeps two tables: a long one hashing 8 bytes (`hashLog` bits)
/// and a short one hashing `mls` bytes (`chainLog` bits). Indices are biased
/// by [`WINDOW_START_INDEX`] like the fast matcher's.
struct DfastCtx {
    hash_long: Vec<u32>,
    hash_small: Vec<u32>,
    hlog_l: u32,
    hlog_s: u32,
    mls: u32,
    window_log: u32,
}

impl DfastCtx {
    fn new(cparams: &CParams) -> Self {
        DfastCtx {
            hash_long: vec![0u32; 1usize << cparams.hash_log],
            hash_small: vec![0u32; 1usize << cparams.chain_log],
            hlog_l: cparams.hash_log,
            hlog_s: cparams.chain_log,
            mls: cparams.min_match.clamp(4, 7),
            window_log: cparams.window_log,
        }
    }

    /// `ZSTD_reduceIndex` for dfast: the long (hash) and short (chain) tables.
    fn reduce_indices(&mut self, correction: u32) {
        reduce_table(&mut self.hash_long, correction, false);
        reduce_table(&mut self.hash_small, correction, false);
    }
}

/// `ZSTD_fillDoubleHashTableForCCtx` (dfast, `dtlm_fast`, untagged): seed both
/// dict tables from `data[0..dict_len]` before compressing `src`. Each step-3
/// position is inserted into the short table (`chainLog` bits, `mls`) and the
/// long table (`hashLog` bits, `mls == 8`), as a biased index. With `dtlm_fast`
/// only the `i == 0` position of each step is loaded, so the loop bound is the
/// same as the single-hash fill: `ip + 9 < dict_len` (C's `ip + 2 <= dictEnd -
/// HASH_READ_SIZE`). The caller guarantees `dict_len > HASH_READ_SIZE`.
fn fill_dfast_hash_tables_for_cctx(ctx: &mut DfastCtx, data: &[u8], dict_len: usize) {
    let hlog_l = ctx.hlog_l;
    let hlog_s = ctx.hlog_s;
    let mls = ctx.mls;
    let mut ip = 0usize;
    while ip + 9 < dict_len {
        let curr = (ip + WINDOW_START_INDEX) as u32;
        ctx.hash_small[hash_ptr(data, ip, hlog_s, mls)] = curr;
        ctx.hash_long[hash_ptr(data, ip, hlog_l, 8)] = curr;
        ip += 3;
    }
}

/// `ZSTD_fillDoubleHashTableForCDict` (dfast, `dtlm_full`, **tagged**): the short
/// table gets the `i == 0` position of each step; the long table gets `i == 0`
/// plus the `i == 1, 2` positions when their bucket is still empty. Both tables
/// are addressed with `+ SHORT_CACHE_TAG_BITS` extra bits and store tagged
/// indices. Caller sizes them `1 << hlog_l` / `1 << hlog_s`.
#[allow(clippy::too_many_arguments)]
fn fill_dfast_hash_tables_for_cdict(
    hash_long: &mut [u32],
    hash_small: &mut [u32],
    data: &[u8],
    dict_len: usize,
    hlog_l: u32,
    hlog_s: u32,
    mls: u32,
) {
    let h_bits_l = hlog_l + SHORT_CACHE_TAG_BITS;
    let h_bits_s = hlog_s + SHORT_CACHE_TAG_BITS;
    let mut ip = 0usize;
    while ip + 9 < dict_len {
        let curr = (ip + WINDOW_START_INDEX) as u32;
        for i in 0..3usize {
            let sm = hash_ptr(data, ip + i, h_bits_s, mls);
            let lg = hash_ptr(data, ip + i, h_bits_l, 8);
            if i == 0 {
                write_tagged_index(hash_small, sm, curr + i as u32);
            }
            if i == 0 || hash_long[lg >> SHORT_CACHE_TAG_BITS] == 0 {
                write_tagged_index(hash_long, lg, curr + i as u32);
            }
        }
        ip += 3;
    }
}

/// `ZSTD_fillDoubleHashTableForCCtx` with `dtlm_full` (untagged): the de-tagged
/// form of a dfast CDict, used by the copy path.
fn fill_dfast_hash_tables_for_cctx_full(ctx: &mut DfastCtx, data: &[u8], dict_len: usize) {
    let hlog_l = ctx.hlog_l;
    let hlog_s = ctx.hlog_s;
    let mls = ctx.mls;
    let mut ip = 0usize;
    while ip + 9 < dict_len {
        let curr = (ip + WINDOW_START_INDEX) as u32;
        for i in 0..3usize {
            let sm = hash_ptr(data, ip + i, hlog_s, mls);
            let lg = hash_ptr(data, ip + i, hlog_l, 8);
            if i == 0 {
                ctx.hash_small[sm] = curr + i as u32;
            }
            if i == 0 || ctx.hash_long[lg] == 0 {
                ctx.hash_long[lg] = curr + i as u32;
            }
        }
        ip += 3;
    }
}

/// `ZSTD_compressBlock_doubleFast_dictMatchState_generic`: the dfast CDict
/// **attach** match finder — the working context's own long+short tables plus
/// the attached CDict's tagged long+short tables, in the `content ++ src` buffer
/// (`dictIndexDelta == 0`). `data`/`block_start`/`block_end`/`content_len` as in
/// [`compress_block_fast_dict_match_state`]; `dict_hash_long`/`dict_hash_small`
/// are the CDict's tagged tables with base logs `dict_hlog_l`/`dict_hlog_s`.
#[allow(clippy::too_many_arguments)]
fn compress_block_dfast_dict_match_state(
    ctx: &mut DfastCtx,
    store: &mut SeqStore,
    rep: &mut [u32; 3],
    data: &[u8],
    block_start: usize,
    block_end: usize,
    content_len: usize,
    dict_hash_long: &[u32],
    dict_hash_small: &[u32],
    dict_hlog_l: u32,
    dict_hlog_s: u32,
) -> usize {
    let bias = WINDOW_START_INDEX;
    let hlog_l = ctx.hlog_l;
    let hlog_s = ctx.hlog_s;
    let mls = ctx.mls;
    let dict_h_bits_l = dict_hlog_l + SHORT_CACHE_TAG_BITS;
    let dict_h_bits_s = dict_hlog_s + SHORT_CACHE_TAG_BITS;
    let tag_mask = (1u32 << SHORT_CACHE_TAG_BITS) - 1;

    let prefix_lowest_index = (bias + content_len) as u32;
    let dict_start_index = bias as u32;
    let prefix_start_pos = content_len;
    let dict_end_pos = content_len;
    let iend_pos = block_end;

    let iend = block_end + bias;
    if block_end - block_start < HASH_READ_SIZE {
        return block_end - block_start;
    }
    let ilimit = iend - HASH_READ_SIZE;
    let istart = block_start + bias;
    let dict_and_prefix_length = (istart - prefix_lowest_index as usize) + content_len;

    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];

    let mut anchor = istart;
    let mut ip = istart + (dict_and_prefix_length == 0) as usize;

    'outer: while ip < ilimit {
        let curr = ip as u32;
        let h2 = hash_ptr(data, ip - bias, hlog_l, 8);
        let h = hash_ptr(data, ip - bias, hlog_s, mls);
        let dict_hat_l = hash_ptr(data, ip - bias, dict_h_bits_l, 8);
        let dict_hat_s = hash_ptr(data, ip - bias, dict_h_bits_s, mls);
        let dict_idx_tag_l = dict_hash_long[dict_hat_l >> SHORT_CACHE_TAG_BITS];
        let dict_idx_tag_s = dict_hash_small[dict_hat_s >> SHORT_CACHE_TAG_BITS];
        let dict_tags_match_l = (dict_idx_tag_l & tag_mask) == (dict_hat_l as u32 & tag_mask);
        let dict_tags_match_s = (dict_idx_tag_s & tag_mask) == (dict_hat_s as u32 & tag_mask);
        let match_index_l = ctx.hash_long[h2];
        let mut match_index_s = ctx.hash_small[h];
        let rep_index = curr + 1 - offset_1;
        ctx.hash_long[h2] = curr;
        ctx.hash_small[h] = curr;

        let m_length: usize;

        if index_overlap_check(prefix_lowest_index, rep_index)
            && read32(data, rep_index as usize - bias) == read32(data, (ip + 1) - bias)
        {
            // repcode
            let mend = if rep_index < prefix_lowest_index {
                dict_end_pos
            } else {
                iend_pos
            };
            m_length = 4 + count_2segments(
                data,
                (ip + 1 - bias) + 4,
                (rep_index as usize - bias) + 4,
                iend_pos,
                mend,
                prefix_start_pos,
            );
            ip += 1;
            store.store_seq(&data[anchor - bias..ip - bias], 1, m_length as u32);
        } else {
            // long / short match cascade. The labeled block yields
            // (offset, matchLength) with `ip` already rewound by the catch-up,
            // or `continue`s the outer loop when nothing is found.
            let (offset, ml) = 'found: {
                // prefix long match
                if match_index_l >= prefix_lowest_index
                    && read64(data, match_index_l as usize - bias) == read64(data, ip - bias)
                {
                    let mut ml = 8 + count_eq(
                        data,
                        (ip - bias) + 8,
                        (match_index_l as usize - bias) + 8,
                        iend_pos,
                    );
                    let off = curr - match_index_l;
                    let mut m = match_index_l as usize;
                    while ip > anchor
                        && m > prefix_lowest_index as usize
                        && data[(ip - bias) - 1] == data[(m - bias) - 1]
                    {
                        ip -= 1;
                        m -= 1;
                        ml += 1;
                    }
                    break 'found (off, ml);
                }
                // dict long match
                if dict_tags_match_l {
                    let dml = dict_idx_tag_l >> SHORT_CACHE_TAG_BITS;
                    if dml > dict_start_index
                        && read64(data, dml as usize - bias) == read64(data, ip - bias)
                    {
                        let mut ml = 8 + count_2segments(
                            data,
                            (ip - bias) + 8,
                            (dml as usize - bias) + 8,
                            iend_pos,
                            dict_end_pos,
                            prefix_start_pos,
                        );
                        let off = curr - dml;
                        let mut dm = dml as usize;
                        while ip > anchor
                            && dm > dict_start_index as usize
                            && data[(ip - bias) - 1] == data[(dm - bias) - 1]
                        {
                            ip -= 1;
                            dm -= 1;
                            ml += 1;
                        }
                        break 'found (off, ml);
                    }
                }

                // short candidate -> search a long match at ip+1; else give up.
                let short_found = if match_index_s > prefix_lowest_index {
                    read32(data, match_index_s as usize - bias) == read32(data, ip - bias)
                } else if dict_tags_match_s {
                    let dms = dict_idx_tag_s >> SHORT_CACHE_TAG_BITS;
                    match_index_s = dms;
                    dms > dict_start_index
                        && read32(data, dms as usize - bias) == read32(data, ip - bias)
                } else {
                    false
                };
                if !short_found {
                    ip += ((ip - anchor) >> K_SEARCH_STRENGTH) + 1;
                    continue 'outer;
                }

                // _search_next_long
                let hl3 = hash_ptr(data, (ip + 1) - bias, hlog_l, 8);
                let dict_hat_l3 = hash_ptr(data, (ip + 1) - bias, dict_h_bits_l, 8);
                let match_index_l3 = ctx.hash_long[hl3];
                let dict_idx_tag_l3 = dict_hash_long[dict_hat_l3 >> SHORT_CACHE_TAG_BITS];
                let dict_tags_match_l3 =
                    (dict_idx_tag_l3 & tag_mask) == (dict_hat_l3 as u32 & tag_mask);
                ctx.hash_long[hl3] = curr + 1;

                // prefix long +1 match
                if match_index_l3 >= prefix_lowest_index
                    && read64(data, match_index_l3 as usize - bias) == read64(data, (ip + 1) - bias)
                {
                    let mut ml = 8 + count_eq(
                        data,
                        (ip + 1 - bias) + 8,
                        (match_index_l3 as usize - bias) + 8,
                        iend_pos,
                    );
                    ip += 1;
                    let off = (curr + 1) - match_index_l3;
                    let mut m = match_index_l3 as usize;
                    while ip > anchor
                        && m > prefix_lowest_index as usize
                        && data[(ip - bias) - 1] == data[(m - bias) - 1]
                    {
                        ip -= 1;
                        m -= 1;
                        ml += 1;
                    }
                    break 'found (off, ml);
                }
                // dict long +1 match
                if dict_tags_match_l3 {
                    let dml3 = dict_idx_tag_l3 >> SHORT_CACHE_TAG_BITS;
                    if dml3 > dict_start_index
                        && read64(data, dml3 as usize - bias) == read64(data, (ip + 1) - bias)
                    {
                        let mut ml = 8 + count_2segments(
                            data,
                            (ip + 1 - bias) + 8,
                            (dml3 as usize - bias) + 8,
                            iend_pos,
                            dict_end_pos,
                            prefix_start_pos,
                        );
                        ip += 1;
                        let off = (curr + 1) - dml3;
                        let mut dm = dml3 as usize;
                        while ip > anchor
                            && dm > dict_start_index as usize
                            && data[(ip - bias) - 1] == data[(dm - bias) - 1]
                        {
                            ip -= 1;
                            dm -= 1;
                            ml += 1;
                        }
                        break 'found (off, ml);
                    }
                }

                // No long +1 match: take the short match found earlier.
                if match_index_s < prefix_lowest_index {
                    let mut ml = 4 + count_2segments(
                        data,
                        (ip - bias) + 4,
                        (match_index_s as usize - bias) + 4,
                        iend_pos,
                        dict_end_pos,
                        prefix_start_pos,
                    );
                    let off = curr - match_index_s;
                    let mut m = match_index_s as usize;
                    while ip > anchor
                        && m > dict_start_index as usize
                        && data[(ip - bias) - 1] == data[(m - bias) - 1]
                    {
                        ip -= 1;
                        m -= 1;
                        ml += 1;
                    }
                    (off, ml)
                } else {
                    let mut ml = 4 + count_eq(
                        data,
                        (ip - bias) + 4,
                        (match_index_s as usize - bias) + 4,
                        iend_pos,
                    );
                    let off = curr - match_index_s;
                    let mut m = match_index_s as usize;
                    while ip > anchor
                        && m > prefix_lowest_index as usize
                        && data[(ip - bias) - 1] == data[(m - bias) - 1]
                    {
                        ip -= 1;
                        m -= 1;
                        ml += 1;
                    }
                    (off, ml)
                }
            };

            // _match_found
            offset_2 = offset_1;
            offset_1 = offset;
            store.store_seq(&data[anchor - bias..ip - bias], offset + 3, ml as u32);
            m_length = ml;
        }

        // _match_stored
        ip += m_length;
        anchor = ip;
        if ip <= ilimit {
            // Complementary insertion (candidates could be > iend-8).
            let index_to_insert = curr + 2;
            ctx.hash_long[hash_ptr(data, index_to_insert as usize - bias, hlog_l, 8)] =
                index_to_insert;
            ctx.hash_long[hash_ptr(data, (ip - 2) - bias, hlog_l, 8)] = (ip - 2) as u32;
            ctx.hash_small[hash_ptr(data, index_to_insert as usize - bias, hlog_s, mls)] =
                index_to_insert;
            ctx.hash_small[hash_ptr(data, (ip - 1) - bias, hlog_s, mls)] = (ip - 1) as u32;

            while ip <= ilimit {
                let current2 = ip as u32;
                let rep_index2 = current2.wrapping_sub(offset_2);
                if index_overlap_check(prefix_lowest_index, rep_index2)
                    && read32(data, rep_index2 as usize - bias) == read32(data, ip - bias)
                {
                    let rep_end2 = if rep_index2 < prefix_lowest_index {
                        dict_end_pos
                    } else {
                        iend_pos
                    };
                    let rep_length2 = 4 + count_2segments(
                        data,
                        (ip - bias) + 4,
                        (rep_index2 as usize - bias) + 4,
                        iend_pos,
                        rep_end2,
                        prefix_start_pos,
                    );
                    std::mem::swap(&mut offset_1, &mut offset_2);
                    store.store_seq(&data[anchor - bias..ip - bias], 1, rep_length2 as u32);
                    ctx.hash_small[hash_ptr(data, ip - bias, hlog_s, mls)] = current2;
                    ctx.hash_long[hash_ptr(data, ip - bias, hlog_l, 8)] = current2;
                    ip += rep_length2;
                    anchor = ip;
                } else {
                    break;
                }
            }
        }
    }

    rep[0] = offset_1;
    rep[1] = offset_2;
    iend_pos - (anchor - bias)
}

/// `ZSTD_compressBlock_doubleFast` (noDict path). Same conventions as
/// [`compress_block_fast`]: biased indices, sequences into `store`, returns the
/// trailing-literals size, and `seg_bias` / `lowest_valid` map positions to
/// window indices after a streaming wrap (both are 2 for a frame's first
/// segment). The `ZSTD_selectAddr`/dummy-pointer constructs in C
/// are branchless forms of plain `idx >= prefixLowestIndex` validity tests
/// (the `+1` long probe is strictly `>`), which is how they appear here.
#[allow(clippy::too_many_arguments)]
fn compress_block_dfast(
    ctx: &mut DfastCtx,
    store: &mut SeqStore,
    rep: &mut [u32; 3],
    data: &[u8],
    block_start: usize,
    block_end: usize,
    seg_bias: usize,
    lowest_valid: usize,
) -> usize {
    let src_size = block_end - block_start;
    let hlog_l = ctx.hlog_l;
    let hlog_s = ctx.hlog_s;
    let mls = ctx.mls;

    // `ZSTD_getLowestPrefixIndex(ms, endIndex, windowLog)`.
    let max_distance = 1usize << ctx.window_log;
    let end_index = block_end + seg_bias;
    let prefix_start_index = if end_index - lowest_valid > max_distance {
        end_index - max_distance
    } else {
        lowest_valid
    };
    // kStepIncr = 1 << kSearchStrength (256) — twice the fast matcher's.
    let k_step_incr: usize = 1 << K_SEARCH_STRENGTH;

    let bias = seg_bias;
    let to_pos = |idx: usize| idx - bias;
    let istart = block_start + bias;
    let iend = block_end + bias;
    if src_size < HASH_READ_SIZE {
        return src_size;
    }
    let ilimit = iend - HASH_READ_SIZE;

    let mut anchor = istart;
    let mut ip = istart;
    let mut ip1: usize;

    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];
    let mut offset_saved1 = 0u32;
    let mut offset_saved2 = 0u32;

    // init: skip the very first window position.
    ip += (ip == prefix_start_index) as usize;
    {
        // `ZSTD_getLowestPrefixIndex(ms, current, windowLog)` at the *block
        // start* (not prefix_start_index, which derives from the block end):
        // when the window slides, maxRep spans the full window.
        let window_low = if ip - lowest_valid > max_distance {
            ip - max_distance
        } else {
            lowest_valid
        };
        let max_rep = (ip - window_low) as u32;
        if offset_2 > max_rep {
            offset_saved2 = offset_2;
            offset_2 = 0;
        }
        if offset_1 > max_rep {
            offset_saved1 = offset_1;
            offset_1 = 0;
        }
    }

    'outer: loop {
        let mut step = 1usize;
        let mut next_step = ip + k_step_incr;
        ip1 = ip + step;

        if ip1 > ilimit {
            break 'outer;
        }

        let mut hl0 = hash_ptr(data, to_pos(ip), hlog_l, 8);
        let mut idxl0 = ctx.hash_long[hl0];

        loop {
            let hs0 = hash_ptr(data, to_pos(ip), hlog_s, mls);
            let idxs0 = ctx.hash_small[hs0];
            let curr = ip;

            ctx.hash_long[hl0] = curr as u32;
            ctx.hash_small[hs0] = curr as u32;

            // Sequence bookkeeping shared by every match exit.
            let m_length: usize;
            let m_ip: usize;
            let hl1_for_writeback: Option<(usize, usize)>; // (hl1, ip1) when step < 4

            // Check noDict repcode at ip+1.
            if offset_1 > 0
                && read32(data, to_pos(ip + 1 - offset_1 as usize)) == read32(data, to_pos(ip + 1))
            {
                let len = count_eq(
                    data,
                    to_pos(ip + 1) + 4,
                    to_pos(ip + 1 - offset_1 as usize) + 4,
                    to_pos(iend),
                ) + 4;
                let seq_ip = ip + 1;
                store.store_seq(&data[to_pos(anchor)..to_pos(seq_ip)], 1, len as u32);
                m_length = len;
                m_ip = seq_ip;
                // (no hl1 write on the repcode path)
                ip = m_ip + m_length;
                anchor = ip;
                dfast_post_match(
                    ctx,
                    store,
                    data,
                    &mut ip,
                    &mut anchor,
                    curr,
                    &mut offset_1,
                    &mut offset_2,
                    ilimit,
                    iend,
                    bias,
                );
                continue 'outer;
            }

            let hl1 = hash_ptr(data, to_pos(ip1), hlog_l, 8);

            // Check prefix long match at ip (validity is `>=`, via selectAddr).
            if idxl0 as usize >= prefix_start_index
                && read64(data, to_pos(idxl0 as usize)) == read64(data, to_pos(ip))
            {
                let mut matchl0 = idxl0 as usize;
                let mut len = count_eq(data, to_pos(ip) + 8, to_pos(matchl0) + 8, to_pos(iend)) + 8;
                let offset = (ip - matchl0) as u32;
                while ip > anchor
                    && matchl0 > prefix_start_index
                    && data[to_pos(ip) - 1] == data[to_pos(matchl0) - 1]
                {
                    ip -= 1;
                    matchl0 -= 1;
                    len += 1;
                }
                m_length = len;
                m_ip = ip;
                hl1_for_writeback = if step < 4 { Some((hl1, ip1)) } else { None };
                dfast_match_found(
                    ctx,
                    store,
                    data,
                    &mut ip,
                    &mut anchor,
                    curr,
                    &mut offset_1,
                    &mut offset_2,
                    offset,
                    m_ip,
                    m_length,
                    hl1_for_writeback,
                    ilimit,
                    iend,
                    bias,
                );
                continue 'outer;
            }

            let idxl1 = ctx.hash_long[hl1];

            // Check prefix short match at ip (validity `>=`).
            if idxs0 as usize >= prefix_start_index
                && read32(data, to_pos(idxs0 as usize)) == read32(data, to_pos(ip))
            {
                // _search_next_long: extend the short match, then probe the
                // long table at ip1 for something better (validity strictly `>`).
                let mut matchs0 = idxs0 as usize;
                let mut len = count_eq(data, to_pos(ip) + 4, to_pos(matchs0) + 4, to_pos(iend)) + 4;
                let mut offset = (ip - matchs0) as u32;

                if idxl1 as usize > prefix_start_index
                    && read64(data, to_pos(idxl1 as usize)) == read64(data, to_pos(ip1))
                {
                    let l1len = count_eq(
                        data,
                        to_pos(ip1) + 8,
                        to_pos(idxl1 as usize) + 8,
                        to_pos(iend),
                    ) + 8;
                    if l1len > len {
                        ip = ip1;
                        len = l1len;
                        offset = (ip - idxl1 as usize) as u32;
                        matchs0 = idxl1 as usize;
                    }
                }

                while ip > anchor
                    && matchs0 > prefix_start_index
                    && data[to_pos(ip) - 1] == data[to_pos(matchs0) - 1]
                {
                    ip -= 1;
                    matchs0 -= 1;
                    len += 1;
                }

                m_length = len;
                m_ip = ip;
                hl1_for_writeback = if step < 4 { Some((hl1, ip1)) } else { None };
                dfast_match_found(
                    ctx,
                    store,
                    data,
                    &mut ip,
                    &mut anchor,
                    curr,
                    &mut offset_1,
                    &mut offset_2,
                    offset,
                    m_ip,
                    m_length,
                    hl1_for_writeback,
                    ilimit,
                    iend,
                    bias,
                );
                continue 'outer;
            }

            if ip1 >= next_step {
                step += 1;
                next_step += k_step_incr;
            }
            ip = ip1;
            ip1 += step;

            hl0 = hl1;
            idxl0 = idxl1;

            if ip1 > ilimit {
                break 'outer;
            }
        }
    }

    // _cleanup: rotate restored offsets exactly as the fast matcher does.
    offset_saved2 = if offset_saved1 != 0 && offset_1 != 0 {
        offset_saved1
    } else {
        offset_saved2
    };
    rep[0] = if offset_1 != 0 {
        offset_1
    } else {
        offset_saved1
    };
    rep[1] = if offset_2 != 0 {
        offset_2
    } else {
        offset_saved2
    };

    to_pos(iend) - to_pos(anchor)
}

/// `_match_found` + `_match_stored` for an ordinary double-fast match: update
/// the offset history, optionally write back the ip1 long hash, store the
/// sequence, then run the shared post-match tail.
#[allow(clippy::too_many_arguments)]
fn dfast_match_found(
    ctx: &mut DfastCtx,
    store: &mut SeqStore,
    data: &[u8],
    ip: &mut usize,
    anchor: &mut usize,
    curr: usize,
    offset_1: &mut u32,
    offset_2: &mut u32,
    offset: u32,
    m_ip: usize,
    m_length: usize,
    hl1_writeback: Option<(usize, usize)>,
    ilimit: usize,
    iend: usize,
    bias: usize,
) {
    let to_pos = |idx: usize| idx - bias;
    *offset_2 = *offset_1;
    *offset_1 = offset;

    if let Some((hl1, ip1)) = hl1_writeback {
        ctx.hash_long[hl1] = ip1 as u32;
    }

    store.store_seq(
        &data[to_pos(*anchor)..to_pos(m_ip)],
        offset + 3, // OFFSET_TO_OFFBASE
        m_length as u32,
    );
    *ip = m_ip + m_length;
    *anchor = *ip;

    dfast_post_match(
        ctx, store, data, ip, anchor, curr, offset_1, offset_2, ilimit, iend, bias,
    );
}

/// The `_match_stored` tail: complementary insertion into both tables, then
/// the greedy immediate-repcode loop.
#[allow(clippy::too_many_arguments)]
fn dfast_post_match(
    ctx: &mut DfastCtx,
    store: &mut SeqStore,
    data: &[u8],
    ip: &mut usize,
    anchor: &mut usize,
    curr: usize,
    offset_1: &mut u32,
    offset_2: &mut u32,
    ilimit: usize,
    iend: usize,
    bias: usize,
) {
    let to_pos = |idx: usize| idx - bias;
    let hlog_l = ctx.hlog_l;
    let hlog_s = ctx.hlog_s;
    let mls = ctx.mls;
    if *ip <= ilimit {
        // Complementary insertion: candidates could be > iend-8 before this.
        let index_to_insert = curr + 2;
        let h = hash_ptr(data, to_pos(index_to_insert), hlog_l, 8);
        ctx.hash_long[h] = index_to_insert as u32;
        let h = hash_ptr(data, to_pos(*ip - 2), hlog_l, 8);
        ctx.hash_long[h] = (*ip - 2) as u32;
        let h = hash_ptr(data, to_pos(index_to_insert), hlog_s, mls);
        ctx.hash_small[h] = index_to_insert as u32;
        let h = hash_ptr(data, to_pos(*ip - 1), hlog_s, mls);
        ctx.hash_small[h] = (*ip - 1) as u32;

        // Immediate repcode loop.
        while *ip <= ilimit
            && *offset_2 > 0
            && read32(data, to_pos(*ip)) == read32(data, to_pos(*ip - *offset_2 as usize))
        {
            let r_length = count_eq(
                data,
                to_pos(*ip) + 4,
                to_pos(*ip - *offset_2 as usize) + 4,
                to_pos(iend),
            ) + 4;
            std::mem::swap(offset_1, offset_2);
            let h = hash_ptr(data, to_pos(*ip), hlog_s, mls);
            ctx.hash_small[h] = *ip as u32;
            let h = hash_ptr(data, to_pos(*ip), hlog_l, 8);
            ctx.hash_long[h] = *ip as u32;
            store.store_seq(&[], 1, r_length as u32);
            *ip += r_length;
            *anchor = *ip;
        }
    }
}

// --- The ZSTD_dfast extDict match finder ---------------------------------------------

/// `ZSTD_compressBlock_doubleFast_extDict_generic`: double-fast over a
/// two-segment window. Unlike the rewritten noDict variant this is still the
/// classic single-cursor loop with `ip += (ip-anchor >> kSearchStrength) + 1`
/// advancement, and there is no `offsetSaved` rescue at the block start —
/// repcode validity is tested per use against `dictStartIndex` instead.
fn compress_block_dfast_extdict(
    ctx: &mut DfastCtx,
    store: &mut SeqStore,
    rep: &mut [u32; 3],
    data: &[u8],
    block_start: usize,
    block_end: usize,
    win: &Window,
) -> usize {
    let src_size = block_end - block_start;
    let hlog_l = ctx.hlog_l;
    let hlog_s = ctx.hlog_s;
    let mls = ctx.mls;

    let seg_bias = win.seg_bias as usize;
    let istart = block_start + seg_bias;
    let iend = block_end + seg_bias;
    let end_index = iend;

    // ZSTD_getLowestMatchIndex(ms, endIndex, windowLog).
    let max_distance = 1usize << ctx.window_log;
    let lowest_valid = win.low_limit as usize;
    let dict_start_index = if end_index - lowest_valid > max_distance {
        end_index - max_distance
    } else {
        lowest_valid
    };
    let dict_limit = win.dict_limit as usize;
    let prefix_start_index = dict_start_index.max(dict_limit);

    // If extDict is invalidated by maxDistance, switch to the "regular" variant.
    if prefix_start_index == dict_start_index {
        return compress_block_dfast(
            ctx,
            store,
            rep,
            data,
            block_start,
            block_end,
            seg_bias,
            dict_limit,
        );
    }
    if src_size < HASH_READ_SIZE {
        return src_size;
    }
    let ilimit = iend - HASH_READ_SIZE;

    let w = ExtDictView {
        seg_bias,
        dict_bias: win.dict_bias as usize,
        prefix_start_index,
        dict_start_pos: dict_start_index - win.dict_bias as usize,
        dict_end_pos: prefix_start_index - win.dict_bias as usize,
        prefix_start_pos: prefix_start_index - seg_bias,
        iend_pos: block_end,
        ilimit,
    };

    let mut anchor = istart;
    let mut ip = istart;
    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];

    // `ZSTD_index_overlap_check`: repIndex must be fully prefix-side, or far
    // enough below the seam that the 4-byte read stays inside the dict.
    let overlap_ok = |rep_index: u32| {
        (prefix_start_index as u32)
            .wrapping_sub(1)
            .wrapping_sub(rep_index)
            >= 3
    };

    // Search loop: `<` instead of `<=` because of the repcode check at ip+1.
    while ip < ilimit {
        let h_small = hash_ptr(data, w.pos_p(ip), hlog_s, mls);
        let match_index = ctx.hash_small[h_small] as usize;
        let h_long = hash_ptr(data, w.pos_p(ip), hlog_l, 8);
        let match_long_index = ctx.hash_long[h_long] as usize;

        let curr = ip;
        // offset_1 expected <= curr+1.
        let rep_index = (curr as u32 + 1).wrapping_sub(offset_1);
        ctx.hash_small[h_small] = curr as u32;
        ctx.hash_long[h_long] = curr as u32;

        let m_length: usize;

        // Check repcode at ip+1 (hence the validity bound at curr+1).
        if overlap_ok(rep_index)
            && offset_1 <= (curr + 1 - dict_start_index) as u32
            && read32(data, w.pos_seg(rep_index as usize)) == read32(data, w.pos_p(ip + 1))
        {
            let rep_idx = rep_index as usize;
            m_length = count_2segments(
                data,
                w.pos_p(ip + 1) + 4,
                w.pos_seg(rep_idx) + 4,
                w.iend_pos,
                w.match_end_pos(rep_idx),
                w.prefix_start_pos,
            ) + 4;
            ip += 1;
            store.store_seq(&data[w.pos_p(anchor)..w.pos_p(ip)], 1, m_length as u32);
        } else if match_long_index > dict_start_index
            && read64(data, w.pos_seg(match_long_index)) == read64(data, w.pos_p(ip))
        {
            // Long match, in either segment.
            let mut match_pos = w.pos_seg(match_long_index);
            let low_match_pos = if match_long_index < prefix_start_index {
                w.dict_start_pos
            } else {
                w.prefix_start_pos
            };
            let mut len = count_2segments(
                data,
                w.pos_p(ip) + 8,
                match_pos + 8,
                w.iend_pos,
                w.match_end_pos(match_long_index),
                w.prefix_start_pos,
            ) + 8;
            let offset = (curr - match_long_index) as u32;
            // Catch up, bounded by the match's segment.
            while ip > anchor
                && match_pos > low_match_pos
                && data[w.pos_p(ip) - 1] == data[match_pos - 1]
            {
                ip -= 1;
                match_pos -= 1;
                len += 1;
            }
            offset_2 = offset_1;
            offset_1 = offset;
            store.store_seq(
                &data[w.pos_p(anchor)..w.pos_p(ip)],
                offset + 3, // OFFSET_TO_OFFBASE
                len as u32,
            );
            m_length = len;
        } else if match_index > dict_start_index
            && read32(data, w.pos_seg(match_index)) == read32(data, w.pos_p(ip))
        {
            // Short match: probe the long table at ip+1 for something better.
            let h3 = hash_ptr(data, w.pos_p(ip + 1), hlog_l, 8);
            let match_index3 = ctx.hash_long[h3] as usize;
            ctx.hash_long[h3] = (curr + 1) as u32;

            let offset: u32;
            let mut len: usize;
            if match_index3 > dict_start_index
                && read64(data, w.pos_seg(match_index3)) == read64(data, w.pos_p(ip + 1))
            {
                let mut match_pos = w.pos_seg(match_index3);
                let low_match_pos = if match_index3 < prefix_start_index {
                    w.dict_start_pos
                } else {
                    w.prefix_start_pos
                };
                len = count_2segments(
                    data,
                    w.pos_p(ip + 1) + 8,
                    match_pos + 8,
                    w.iend_pos,
                    w.match_end_pos(match_index3),
                    w.prefix_start_pos,
                ) + 8;
                ip += 1;
                offset = (curr + 1 - match_index3) as u32;
                while ip > anchor
                    && match_pos > low_match_pos
                    && data[w.pos_p(ip) - 1] == data[match_pos - 1]
                {
                    ip -= 1;
                    match_pos -= 1;
                    len += 1;
                }
            } else {
                let mut match_pos = w.pos_seg(match_index);
                let low_match_pos = if match_index < prefix_start_index {
                    w.dict_start_pos
                } else {
                    w.prefix_start_pos
                };
                len = count_2segments(
                    data,
                    w.pos_p(ip) + 4,
                    match_pos + 4,
                    w.iend_pos,
                    w.match_end_pos(match_index),
                    w.prefix_start_pos,
                ) + 4;
                offset = (curr - match_index) as u32;
                while ip > anchor
                    && match_pos > low_match_pos
                    && data[w.pos_p(ip) - 1] == data[match_pos - 1]
                {
                    ip -= 1;
                    match_pos -= 1;
                    len += 1;
                }
            }
            offset_2 = offset_1;
            offset_1 = offset;
            store.store_seq(
                &data[w.pos_p(anchor)..w.pos_p(ip)],
                offset + 3, // OFFSET_TO_OFFBASE
                len as u32,
            );
            m_length = len;
        } else {
            ip += ((ip - anchor) >> K_SEARCH_STRENGTH) + 1;
            continue;
        }

        // Move to next sequence start.
        ip += m_length;
        anchor = ip;

        if ip <= ilimit {
            // Complementary insertion: candidates could be > iend-8 before this.
            let index_to_insert = curr + 2;
            let h = hash_ptr(data, w.pos_p(index_to_insert), hlog_l, 8);
            ctx.hash_long[h] = index_to_insert as u32;
            let h = hash_ptr(data, w.pos_p(ip - 2), hlog_l, 8);
            ctx.hash_long[h] = (ip - 2) as u32;
            let h = hash_ptr(data, w.pos_p(index_to_insert), hlog_s, mls);
            ctx.hash_small[h] = index_to_insert as u32;
            let h = hash_ptr(data, w.pos_p(ip - 1), hlog_s, mls);
            ctx.hash_small[h] = (ip - 1) as u32;

            // Check immediate repcode (offset_2), with two-segment reads.
            while ip <= ilimit {
                let current2 = ip as u32;
                let rep_index2 = current2.wrapping_sub(offset_2);
                if !(overlap_ok(rep_index2) && offset_2 <= current2 - dict_start_index as u32) {
                    break;
                }
                let rep2 = rep_index2 as usize;
                if read32(data, w.pos_seg(rep2)) != read32(data, w.pos_p(ip)) {
                    break;
                }
                let rep_length2 = count_2segments(
                    data,
                    w.pos_p(ip) + 4,
                    w.pos_seg(rep2) + 4,
                    w.iend_pos,
                    w.match_end_pos(rep2),
                    w.prefix_start_pos,
                ) + 4;
                std::mem::swap(&mut offset_1, &mut offset_2);
                store.store_seq(&[], 1, rep_length2 as u32); // REPCODE1, no literals
                let h = hash_ptr(data, w.pos_p(ip), hlog_s, mls);
                ctx.hash_small[h] = current2;
                let h = hash_ptr(data, w.pos_p(ip), hlog_l, 8);
                ctx.hash_long[h] = current2;
                ip += rep_length2;
                anchor = ip;
            }
        }
    }

    // Save reps for the next block — no offsetSaved rotation in this variant.
    rep[0] = offset_1;
    rep[1] = offset_2;

    iend - anchor
}

// --- Frame assembly ----------------------------------------------------------------

/// `ZSTD_isRLE`.
pub(crate) fn is_rle(src: &[u8]) -> bool {
    src.iter().all(|&b| b == src[0])
}

/// `ZSTD_writeFrameHeader`, no dictionary (dictID 0). `pledged` of `None` is
/// `ZSTD_CONTENTSIZE_UNKNOWN`; per `ZSTD_resetCCtx_internal` an unknown
/// pledged size clears the content-size flag, which both omits the FCS field
/// and disables the single-segment format.
fn write_frame_header(
    out: &mut Vec<u8>,
    cparams: &CParams,
    pledged: Option<u64>,
    checksum: bool,
    dict_id: u32,
) {
    let window_size = 1u64 << cparams.window_log;
    let content_size_flag = pledged.is_some();
    let pledged_src_size = pledged.unwrap_or(0);
    let single_segment = content_size_flag && window_size >= pledged_src_size;
    let fcs_code = if content_size_flag {
        (pledged_src_size >= 256) as u32
            + (pledged_src_size >= 65536 + 256) as u32
            + (pledged_src_size >= 0xFFFF_FFFF) as u32
    } else {
        0
    };
    // `ZSTD_writeFrameHeader`: the `Dictionary_ID` field is 0/1/2/4 bytes, and
    // its size code occupies the low two bits of the descriptor. The default
    // frame params keep `noDictIDFlag == 0`, so a nonzero dict ID is always
    // written (a zero dict ID — no dict, or a raw-content dict — emits no field).
    let did_size_code = (dict_id > 0) as u32 + (dict_id >= 256) as u32 + (dict_id >= 65536) as u32;
    let descriptor = (fcs_code << 6) as u8
        | ((single_segment as u8) << 5)
        | ((checksum as u8) << 2)
        | did_size_code as u8;

    out.extend_from_slice(&ZSTD_MAGIC.to_le_bytes());
    out.push(descriptor);
    if !single_segment {
        out.push(((cparams.window_log - WINDOWLOG_ABSOLUTEMIN) << 3) as u8);
    }
    match did_size_code {
        0 => {}
        1 => out.push(dict_id as u8),
        2 => out.extend_from_slice(&(dict_id as u16).to_le_bytes()),
        _ => out.extend_from_slice(&dict_id.to_le_bytes()),
    }
    match fcs_code {
        0 => {
            if single_segment {
                out.push(pledged_src_size as u8);
            }
        }
        1 => out.extend_from_slice(&((pledged_src_size - 256) as u16).to_le_bytes()),
        2 => out.extend_from_slice(&(pledged_src_size as u32).to_le_bytes()),
        _ => out.extend_from_slice(&pledged_src_size.to_le_bytes()),
    }
}

/// Append a block header (3 bytes LE: last flag, type, size).
pub(crate) fn push_block_header(out: &mut Vec<u8>, last: bool, block_type: u32, size: usize) {
    let v = (last as u32) | (block_type << 1) | ((size as u32) << 3);
    out.extend_from_slice(&v.to_le_bytes()[..3]);
}

/// `ZSTDcs_*`: the frame-level stage of a [`FrameCompressor`].
#[derive(PartialEq, Eq, Clone, Copy)]
enum Stage {
    /// Frame header not written yet (`ZSTDcs_init`).
    Init,
    /// Header written, no block flagged "last" yet (`ZSTDcs_ongoing`).
    Ongoing,
    /// A chunk was compressed with the last-block flag (`ZSTDcs_ending`).
    Ending,
}

/// The frame-compression half of `ZSTD_CCtx`: every piece of state that
/// persists across `ZSTD_compressContinue` calls. The one-shot [`compress`]
/// feeds a single chunk; the streaming encoder feeds successive chunks of its
/// input buffer.
pub(crate) struct FrameCompressor {
    cparams: CParams,
    matcher: Matcher,
    rep: [u32; 3],
    entropy: FseEntropyState,
    is_first_block: bool,
    /// `cctx->consumedSrcSize` / `cctx->producedCSize`. Their difference seeds
    /// the pre-splitter `savings` at each frame-chunk call; `produced`
    /// includes the frame header, exactly as in C.
    consumed: u64,
    produced: u64,
    /// `windowSize` per `ZSTD_resetCCtx_internal`:
    /// `max(1, min(1 << windowLog, pledgedSrcSize))`.
    window_size: usize,
    /// `cctx->blockSizeMax = min(ZSTD_BLOCKSIZE_MAX, windowSize)`.
    block_size_max: usize,
    /// `None` is `ZSTD_CONTENTSIZE_UNKNOWN`.
    pledged: Option<u64>,
    checksum: bool,
    xxh: crate::xxhash::Xxh64,
    stage: Stage,
    disable_literal_compression: bool,
    window: Window,
    /// `cctx->ldmState`, present when `ZSTD_resolveEnableLdm` (auto) turns
    /// long-distance matching on: `strategy >= btopt && windowLog >= 27`,
    /// i.e. level 22 at unknown or > 64 MiB content sizes.
    ldm: Option<crate::ldm::LdmState>,
    /// Set by `compress_with_dict`: the window has been arranged directly in
    /// the post-flip extDict state, so the first `compress_continue` must NOT
    /// run `ZSTD_window_update` (which would recompute the wrong segment
    /// boundary for the concatenated `dict ++ src` buffer). One-shot only.
    window_preloaded: bool,
    /// `cctx->dictID`: the `Dictionary_ID` written into the frame header. Zero
    /// for no dictionary or a raw-content dictionary (no `Dictionary_ID` field);
    /// nonzero only for a trained (`ZDICT`) dictionary loaded by
    /// [`compress_with_dict`].
    dict_id: u32,
    /// `ms->dictMatchState` for the CDict (Path B) *attach* path: the
    /// dictionary's own tagged match table(s), consulted by the dictMatchState
    /// match finders. `None` on every other path (no dict, extDict, or copy).
    dict_match_state: Option<DictMatchState>,
}

/// The dictionary's own (tagged) match table(s) referenced by an attached CDict
/// (`ms->dictMatchState`), per strategy. Held by [`FrameCompressor`] only on the
/// CDict attach path; the working context's own table(s) fill as `src` is parsed.
enum DictMatchState {
    Fast(FastDictMatchState),
    Dfast(DfastDictMatchState),
    Lazy(LazyDictMatchState),
    Opt(OptDictMatchState),
}

struct FastDictMatchState {
    /// Tagged hash table (`ZSTD_writeTaggedIndex`), sized `1 << hlog`.
    hash_table: Vec<u32>,
    hlog: u32,
    /// The dictionary content length (the prefix of the `content ++ src` buffer).
    content_len: usize,
}

/// The dfast variant: a long table (`hashLog + 8` bits, mls 8) and a short table
/// (`chainLog + 8` bits, mls), both tagged.
struct DfastDictMatchState {
    hash_long: Vec<u32>,
    hash_small: Vec<u32>,
    hlog_l: u32,
    hlog_s: u32,
    content_len: usize,
}

/// The greedy/lazy/lazy2 variant: the CDict's own (untagged) lazy match state —
/// hash chain or row table — built over the dict content with the CDict's
/// parameters and salt 0. Read-only during the attach search.
struct LazyDictMatchState {
    ms: Box<crate::lazy::LazyCtx>,
    content_len: usize,
}

/// The btopt/btultra/btultra2 variant: the CDict's own (untagged) optimal-parser
/// match state — the fully-sorted binary tree built over the dict content with
/// the CDict's parameters. Read-only during the attach search.
struct OptDictMatchState {
    ms: Box<crate::opt::OptCtx>,
    content_len: usize,
}

impl FrameCompressor {
    pub(crate) fn new(level: i32, pledged: Option<u64>, checksum: bool) -> Self {
        // Unknown content size selects the "default" srcSize class and skips
        // the window resize (`ZSTD_getCParamRowSize` returns
        // ZSTD_CONTENTSIZE_UNKNOWN for unknown srcSize without a dictionary).
        let cparams = get_cparams(level, pledged.unwrap_or(CONTENTSIZE_UNKNOWN), 0);
        Self::from_cparams(cparams, pledged, checksum)
    }

    /// Build a frame compressor from already-derived compression parameters.
    /// `ZSTD_compress` reaches this through [`new`](Self::new) (no-dict
    /// cParams); `compress_with_dict` derives dict-aware cParams and calls it
    /// directly.
    pub(crate) fn from_cparams(cparams: CParams, pledged: Option<u64>, checksum: bool) -> Self {
        let window_size_u64 = match pledged {
            Some(n) => (1u64 << cparams.window_log).min(n).max(1),
            None => 1u64 << cparams.window_log,
        };
        let block_size_max = (BLOCK_SIZE_MAX as u64).min(window_size_u64) as usize;
        let matcher = match cparams.strategy {
            Strategy::Dfast => Matcher::Dfast(DfastCtx::new(&cparams)),
            Strategy::Greedy | Strategy::Lazy | Strategy::Lazy2 | Strategy::Btlazy2 => {
                Matcher::Lazy(crate::lazy::LazyCtx::new(&cparams))
            }
            Strategy::Btopt | Strategy::Btultra | Strategy::Btultra2 => {
                Matcher::Opt(Box::new(crate::opt::OptCtx::new(&cparams)))
            }
            _ => Matcher::Fast(FastCtx::new(&cparams)),
        };
        // `ZSTD_literalsCompressionIsDisabled` in the default `ZSTD_ps_auto`
        // mode: the fast strategy with a nonzero target length (the negative
        // / acceleration levels) skips literal compression entirely.
        let disable_literal_compression =
            cparams.strategy == Strategy::Fast && cparams.target_length > 0;
        FrameCompressor {
            cparams,
            matcher,
            rep: [1, 4, 8],
            entropy: FseEntropyState::new(),
            is_first_block: true,
            consumed: 0,
            produced: 0,
            window_size: window_size_u64 as usize,
            block_size_max,
            pledged,
            checksum,
            xxh: crate::xxhash::Xxh64::new(0),
            stage: Stage::Init,
            disable_literal_compression,
            window: Window::new(),
            ldm: crate::ldm::LdmParams::auto(&cparams).map(crate::ldm::LdmState::new),
            window_preloaded: false,
            dict_id: 0,
            dict_match_state: None,
        }
    }

    pub(crate) fn window_size(&self) -> usize {
        self.window_size
    }

    pub(crate) fn block_size_max(&self) -> usize {
        self.block_size_max
    }

    /// For the streaming CDict-attach path: whether compressing a block ending at
    /// staging-buffer position `block_end` would carry the source past the window
    /// (`block_end + seg_bias > maxDist`), where C's `ZSTD_checkDictValidity` /
    /// `ZSTD_window_enforceMaxDist` would drop the attached dict or slide the
    /// window. That loadedDictEnd-aware machinery isn't ported, so the streaming
    /// encoder must stop with a clean error before this point. Always false when
    /// no dict is attached.
    pub(crate) fn cdict_attach_overflow(&self, block_end: usize) -> bool {
        self.dict_match_state.is_some()
            && (block_end + self.window.seg_bias as usize) as u64
                > (1u64 << self.cparams.window_log)
    }

    /// `ZSTD_compressContinue_internal` (frame mode): write the frame header
    /// on first use, then compress `data[chunk_start..chunk_end]` into one or
    /// more terminated blocks (`ZSTD_compress_frameChunk`).
    ///
    /// `data` is the frame's contiguous history buffer: every chunk must
    /// directly follow the previous one in the same buffer, so the match
    /// finders can reach back across chunk boundaries.
    pub(crate) fn compress_continue(
        &mut self,
        out: &mut Vec<u8>,
        data: &[u8],
        chunk_start: usize,
        chunk_end: usize,
        last_frame_chunk: bool,
    ) -> Result<(), Error> {
        let out_start = out.len();
        if self.stage == Stage::Init {
            write_frame_header(
                out,
                &self.cparams,
                self.pledged,
                self.checksum,
                self.dict_id,
            );
            self.stage = Stage::Ongoing;
        }
        if chunk_start == chunk_end {
            // Do not generate an empty block, but do count the header.
            self.produced += (out.len() - out_start) as u64;
            return Ok(());
        }

        // `ZSTD_window_update`: a non-contiguous chunk (the streaming input
        // buffer wrapped) turns the live window into the extDict.
        //
        // `compress_with_dict` pre-arranges the window in the post-flip extDict
        // state for the first (and, one-shot, only) chunk, so the first update
        // is skipped: running it on the concatenated `dict ++ src` buffer would
        // see `src` as contiguous with `dict` and miss the flip.
        if self.window_preloaded {
            self.window_preloaded = false;
        } else if !self.window.update(chunk_start, chunk_end) {
            // `ZSTD_compressContinue_internal`: a non-contiguous update
            // restarts table insertion at the new segment
            // (`ms->nextToUpdate = ms->window.dictLimit`).
            match &mut self.matcher {
                Matcher::Lazy(ctx) => ctx.next_to_update = self.window.dict_limit as usize,
                Matcher::Opt(ctx) => ctx.next_to_update = self.window.dict_limit as usize,
                _ => {}
            }
        }
        // The LDM state keeps its own window, updated in lockstep.
        if let Some(ldm) = &mut self.ldm {
            ldm.window.update(chunk_start, chunk_end);
        }
        if self.checksum {
            self.xxh.update(&data[chunk_start..chunk_end]);
        }

        let cparams = self.cparams;
        let mut savings: i64 = self.consumed as i64 - self.produced as i64;
        let mut pos = chunk_start;
        while pos < chunk_end {
            let remaining = chunk_end - pos;
            // ZSTD_optimalBlockSize: only full 128 KiB blocks are candidates
            // for pre-splitting, and only once at least 3 bytes of savings
            // are verified (so the first full block is never split). The
            // auto split level is `splitLevels[strategy]`.
            let block_size = if remaining < BLOCK_SIZE_MAX || self.block_size_max < BLOCK_SIZE_MAX {
                remaining.min(self.block_size_max)
            } else if savings < 3 {
                BLOCK_SIZE_MAX
            } else {
                const SPLIT_LEVELS: [usize; 10] = [0, 0, 1, 2, 2, 3, 3, 4, 4, 4];
                let split_level = SPLIT_LEVELS[cparams.strategy as usize];
                pre_split::split_block(&data[pos..pos + BLOCK_SIZE_MAX], split_level)
            };
            let last_block = last_frame_chunk && block_size == remaining;
            let block = &data[pos..pos + block_size];

            // `ZSTD_overflowCorrectIfNeeded`: once the running index reaches
            // 3500 MiB, recycle the 32-bit index space — slide the window and
            // subtract the same `correction` from every matcher table. Runs
            // before enforceMaxDist, exactly as `ZSTD_compress_frameChunk`
            // does. Lifts the streaming length limit entirely.
            let max_dist = 1u32 << cparams.window_log;
            if self.window.needs_overflow_correction(pos + block_size) {
                let cycle_log = cycle_log(cparams.chain_log, cparams.strategy);
                let correction = self.window.correct_overflow(cycle_log, max_dist, pos);
                match &mut self.matcher {
                    Matcher::Fast(ctx) => ctx.reduce_indices(correction),
                    Matcher::Dfast(ctx) => ctx.reduce_indices(correction),
                    Matcher::Lazy(ctx) => ctx.reduce_indices(correction),
                    Matcher::Opt(ctx) => ctx.reduce_indices(correction),
                }
            }

            // `ZSTD_window_enforceMaxDist` runs before every block, anchored
            // at the *block start* (`ip`, not `ip + blockSize` — that one
            // only feeds `ZSTD_checkDictValidity`); the dict mode below
            // (extDict vs noDict) is decided on the result. The matchers
            // tighten their own validity bound from the block end.
            let block_start_idx = pos as u32 + self.window.seg_bias;
            self.window.enforce_max_dist(block_start_idx, max_dist);

            // `Ensure hash/chain table insertion resumes no sooner than
            // lowLimit` (`ZSTD_compress_frameChunk`): after a slide or an
            // overflow correction, nextToUpdate may trail the new lowLimit.
            match &mut self.matcher {
                Matcher::Lazy(ctx) => {
                    ctx.next_to_update = ctx.next_to_update.max(self.window.low_limit as usize)
                }
                Matcher::Opt(ctx) => {
                    ctx.next_to_update = ctx.next_to_update.max(self.window.low_limit as usize)
                }
                _ => {}
            }

            // --- ZSTD_compressBlock_internal ---
            let mut c_size_kind: BlockKind;
            let mut body: Vec<u8> = Vec::new();

            // ZSTD_buildSeqStore: tiny blocks are not even attempted.
            if block_size < MIN_CBLOCK_SIZE + BLOCK_HEADER_SIZE + 1 + 1 {
                c_size_kind = BlockKind::Raw;
            } else {
                // `ZSTD_buildSeqStore`: "limited update after a very long
                // match" — cap how far nextToUpdate trails the block start.
                // Only the matchers that track nextToUpdate are affected.
                match &mut self.matcher {
                    Matcher::Lazy(ctx) => ctx.limit_update(pos + self.window.seg_bias as usize),
                    Matcher::Opt(ctx) => ctx.limit_update(pos + self.window.seg_bias as usize),
                    _ => {}
                }
                let mut store = SeqStore::new();
                let mut next_rep = self.rep;
                let last_ll_size = match &mut self.matcher {
                    Matcher::Fast(ctx) => {
                        // `ZSTD_selectBlockCompressor(strategy, ..,
                        // ZSTD_matchState_dictMode(ms))`: dictMatchState (an
                        // attached CDict) > extDict > noDict.
                        if let Some(DictMatchState::Fast(dms)) = &self.dict_match_state {
                            compress_block_fast_dict_match_state(
                                ctx,
                                &mut store,
                                &mut next_rep,
                                data,
                                pos,
                                pos + block_size,
                                dms.content_len,
                                &dms.hash_table,
                                dms.hlog,
                            )
                        } else if self.window.has_ext_dict() {
                            compress_block_fast_extdict(
                                ctx,
                                &mut store,
                                &mut next_rep,
                                data,
                                pos,
                                pos + block_size,
                                &self.window,
                            )
                        } else {
                            compress_block_fast(
                                ctx,
                                &mut store,
                                &mut next_rep,
                                data,
                                pos,
                                pos + block_size,
                                self.window.seg_bias as usize,
                                self.window.dict_limit as usize,
                            )
                        }
                    }
                    Matcher::Dfast(ctx) => {
                        if let Some(DictMatchState::Dfast(dms)) = &self.dict_match_state {
                            compress_block_dfast_dict_match_state(
                                ctx,
                                &mut store,
                                &mut next_rep,
                                data,
                                pos,
                                pos + block_size,
                                dms.content_len,
                                &dms.hash_long,
                                &dms.hash_small,
                                dms.hlog_l,
                                dms.hlog_s,
                            )
                        } else if self.window.has_ext_dict() {
                            compress_block_dfast_extdict(
                                ctx,
                                &mut store,
                                &mut next_rep,
                                data,
                                pos,
                                pos + block_size,
                                &self.window,
                            )
                        } else {
                            compress_block_dfast(
                                ctx,
                                &mut store,
                                &mut next_rep,
                                data,
                                pos,
                                pos + block_size,
                                self.window.seg_bias as usize,
                                self.window.dict_limit as usize,
                            )
                        }
                    }
                    Matcher::Lazy(ctx) => {
                        if let Some(DictMatchState::Lazy(dms)) = &self.dict_match_state {
                            crate::lazy::compress_block_lazy_dict_match_state(
                                ctx,
                                &mut store,
                                &mut next_rep,
                                data,
                                pos,
                                pos + block_size,
                                &self.window,
                                &dms.ms,
                                dms.content_len,
                            )
                        } else if self.window.has_ext_dict() {
                            crate::lazy::compress_block_lazy_extdict(
                                ctx,
                                &mut store,
                                &mut next_rep,
                                data,
                                pos,
                                pos + block_size,
                                &self.window,
                            )
                        } else {
                            crate::lazy::compress_block_lazy(
                                ctx,
                                &mut store,
                                &mut next_rep,
                                data,
                                pos,
                                pos + block_size,
                                &self.window,
                            )
                        }
                    }
                    Matcher::Opt(ctx) => {
                        let ext_dict = self.window.has_ext_dict();
                        // `ZSTD_selectBlockCompressor`: an attached CDict
                        // (dictMatchState) outranks extDict/noDict.
                        let opt_dms = match &self.dict_match_state {
                            Some(DictMatchState::Opt(d)) => Some(crate::opt::OptDms {
                                ms: d.ms.as_ref(),
                                content_len: d.content_len,
                            }),
                            _ => None,
                        };
                        // `ZSTD_buildSeqStore`: with LDM enabled, generate
                        // the block's raw sequences first; the opt parser
                        // takes them as extra candidates
                        // (`ZSTD_ldm_blockCompress`, btopt+ branch).
                        let mut ldm_seqs: Vec<crate::ldm::RawSeq> = Vec::new();
                        if let Some(ldm) = &mut self.ldm {
                            let capacity =
                                self.block_size_max / ldm.params.min_match_length as usize;
                            crate::ldm::generate_sequences(
                                ldm,
                                &mut ldm_seqs,
                                capacity,
                                data,
                                pos,
                                pos + block_size,
                            )?;
                        }
                        crate::opt::compress_block_opt(
                            ctx,
                            &mut store,
                            &mut next_rep,
                            data,
                            pos,
                            pos + block_size,
                            &mut self.window,
                            ext_dict,
                            if self.ldm.is_some() {
                                Some(&ldm_seqs)
                            } else {
                                None
                            },
                            Some(&self.entropy),
                            opt_dms.as_ref(),
                        )
                    }
                };
                let lits_from = block_size - last_ll_size;
                store.store_last_literals(&block[lits_from..]);

                // The post-block splitter (btopt+ with windowLog >= 17) takes
                // over block emission entirely: it may emit several blocks
                // from this one seqStore, with dRep/cRep reconciliation.
                if crate::post_split::block_splitter_enabled(&cparams) {
                    let c_size = crate::post_split::compress_block_split(
                        out,
                        &mut store,
                        &mut self.entropy,
                        &mut self.rep,
                        next_rep,
                        cparams.strategy as i32,
                        block,
                        last_block,
                        self.is_first_block,
                    )?;
                    savings += block_size as i64 - c_size as i64;
                    pos += block_size;
                    self.is_first_block = false;
                    continue;
                }

                match sequences_encode::entropy_compress_seq_store(
                    &store,
                    &self.entropy,
                    cparams.strategy as i32,
                    self.disable_literal_compression,
                    block_size,
                )? {
                    None => c_size_kind = BlockKind::Raw,
                    Some((b, next_entropy)) => {
                        body = b;
                        c_size_kind = BlockKind::Compressed;
                        // RLE-block override (not for the first block;
                        // decoder compat for zstd <= 1.4.3).
                        if !self.is_first_block && body.len() < 25 && is_rle(block) {
                            c_size_kind = BlockKind::Rle;
                        }
                        // Confirm repcodes + entropy only when actually
                        // emitting a compressed block (cSize > 1).
                        if c_size_kind == BlockKind::Compressed {
                            self.rep = next_rep;
                            self.entropy = next_entropy;
                        }
                    }
                }
            }

            let c_size = match c_size_kind {
                BlockKind::Raw => {
                    push_block_header(out, last_block, 0, block_size);
                    out.extend_from_slice(block);
                    BLOCK_HEADER_SIZE + block_size
                }
                BlockKind::Rle => {
                    push_block_header(out, last_block, 1, block_size);
                    out.push(block[0]);
                    BLOCK_HEADER_SIZE + 1
                }
                BlockKind::Compressed => {
                    push_block_header(out, last_block, 2, body.len());
                    out.extend_from_slice(&body);
                    BLOCK_HEADER_SIZE + body.len()
                }
            };

            savings += block_size as i64 - c_size as i64;
            pos += block_size;
            self.is_first_block = false;
        }

        // `if (lastFrameChunk && (op>ostart)) cctx->stage = ZSTDcs_ending;` —
        // a nonempty chunk always emits at least one block.
        if last_frame_chunk {
            self.stage = Stage::Ending;
        }
        self.consumed += (chunk_end - chunk_start) as u64;
        self.produced += (out.len() - out_start) as u64;
        if self.pledged.is_some_and(|n| self.consumed > n) {
            // `srcSize_wrong`: more input than pledged.
            return Err(Error::Encode("pledged source size exceeded"));
        }
        Ok(())
    }

    /// `ZSTD_compressEnd_public`: compress the final chunk, then write the
    /// epilogue (`ZSTD_writeEpilogue`: an empty last block if no block carried
    /// the last-block flag, plus the optional content checksum).
    pub(crate) fn compress_end(
        &mut self,
        out: &mut Vec<u8>,
        data: &[u8],
        chunk_start: usize,
        chunk_end: usize,
    ) -> Result<(), Error> {
        self.compress_continue(out, data, chunk_start, chunk_end, true)?;
        debug_assert!(self.stage != Stage::Init, "header is written above");
        if self.stage != Stage::Ending {
            // One last empty raw block to carry the end-of-frame mark.
            push_block_header(out, true, 0, 0);
        }
        if self.checksum {
            out.extend_from_slice(&(self.xxh.digest() as u32).to_le_bytes());
        }
        if self.pledged.is_some_and(|n| self.consumed != n) {
            // `srcSize_wrong`: pledged size must match exactly at frame end.
            return Err(Error::Encode("pledged source size not honored"));
        }
        Ok(())
    }
}

/// `ZSTD_compress`: one-shot frame compression with the simple-API defaults
/// (contentSize known and flagged, no checksum, no dictionary).
///
/// Bit-exact with C libzstd 1.5.7 for the supported scope (see module docs);
/// unsupported configurations return [`Error::Encode`] rather than diverging.
pub fn compress(src: &[u8], level: i32) -> Result<Vec<u8>, Error> {
    if src.len() as u64 >= u64::from(u32::MAX) - 2 {
        // Match indices are 32-bit; larger inputs need the C window-cycling
        // (overflow correction) machinery.
        return Err(Error::Encode("inputs >= 4 GiB are not supported yet"));
    }
    let mut fc = FrameCompressor::new(level, Some(src.len() as u64), false);
    let mut out = Vec::with_capacity(src.len() + (src.len() >> 8) + 64);
    fc.compress_end(&mut out, src, 0, src.len())?;
    Ok(out)
}

/// `ZSTD_compress_usingDict`: one-shot frame compression primed with a
/// dictionary, so the start of `src` can reference `dict`. Bit-exact with C
/// libzstd 1.5.7 for the supported scope; unsupported configurations return
/// [`Error::Encode`] rather than diverging.
///
/// Current scope: raw / content-only **and** trained (`ZDICT`) dictionaries at
/// **every strategy** (fast through btultra2). A trained dictionary seeds the
/// first block's entropy tables, repeat offsets, and the frame's
/// `Dictionary_ID`, exactly as `ZSTD_loadCEntropy` does. The only rejected
/// configuration is the rare large input where C would enable long-distance
/// matching with a dictionary (`windowLog >= 27` at btopt+). An empty `dict` is
/// equivalent to [`compress`]; a raw dict shorter than 8 bytes is ignored (as in
/// C), though it still influences the derived parameters. A malformed trained
/// dictionary yields [`Error::DictionaryCorrupted`].
pub fn compress_with_dict(src: &[u8], dict: &[u8], level: i32) -> Result<Vec<u8>, Error> {
    if dict.len() as u64 + src.len() as u64 >= u64::from(u32::MAX) - 2 {
        // Match indices are 32-bit; larger histories need overflow correction.
        return Err(Error::Encode("inputs >= 4 GiB are not supported yet"));
    }

    // cParams use the *whole* dictionary size, exactly as
    // `ZSTD_compress_usingDict` ->
    // `ZSTD_getParams_internal(level, srcSize, dictSize, cpm_noAttachDict)`.
    let cparams = get_cparams(level, src.len() as u64, dict.len() as u64);
    let pledged = Some(src.len() as u64);
    let mut fc = FrameCompressor::from_cparams(cparams, pledged, false);

    // Resolve the dictionary *content* — the bytes the match finder loads. For a
    // trained (`ZDICT`) dictionary (`ZSTD_loadZstdDictionary`), parse the entropy
    // section first and seed the first block's `prevCBlock` tables, repeat
    // offsets, and the frame's dict ID; the content is everything after that
    // header. For a raw-content dictionary the whole buffer is content.
    let content: &[u8] = if dict.len() >= 8 && read32(dict, 0) == MAGIC_DICTIONARY {
        let seed = crate::dict_encode::load_c_entropy(dict)?;
        fc.entropy = seed.entropy;
        fc.rep = seed.rep;
        fc.dict_id = seed.dict_id;
        &dict[seed.entropy_size..]
    } else if dict.len() < 8 {
        // `ZSTD_compress_insertDictionary` ignores a (raw) dict shorter than 8
        // bytes entirely — the cParams above still reflect its size; compress
        // `src` as a plain frame.
        let mut out = Vec::with_capacity(src.len() + (src.len() >> 8) + 64);
        fc.compress_end(&mut out, src, 0, src.len())?;
        return Ok(out);
    } else {
        dict
    };

    // C's `ZSTD_loadDictionaryContent` also seeds the dictionary into the LDM
    // tables (`ZSTD_ldm_fillHashTable`); that path isn't ported, so reject the
    // (large-input, btopt+) configurations where `ZSTD_resolveEnableLdm` turns
    // long-distance matching on rather than diverge. Unreachable at typical
    // sizes — LDM needs `windowLog >= 27`.
    if fc.ldm.is_some() {
        return Err(Error::Encode(
            "long-distance matching with a dictionary is not supported yet",
        ));
    }

    // `ZSTD_loadDictionaryContent` followed by the non-contiguous `src` append:
    // lay the history out as one buffer `content ++ src` and put the window
    // directly in the post-flip extDict state. For a trained dict `content` is
    // the post-entropy tail; for a raw dict it is the whole buffer.
    let content_len = content.len();
    let src_len = src.len();
    let mut data = Vec::with_capacity(content_len + src_len);
    data.extend_from_slice(content);
    data.extend_from_slice(src);

    prime_raw_prefix(&mut fc, &data, content_len);

    let mut out = Vec::with_capacity(src_len + (src_len >> 8) + 64);
    fc.compress_end(&mut out, &data, content_len, content_len + src_len)?;
    Ok(out)
}

/// `ZSTD_loadDictionaryContent` (raw content, `ZSTD_dtlm_fast`) followed by the
/// non-contiguous append: lay the history as one buffer `prefix ++ input` (the
/// prefix occupying `buf[..prefix_len]`), seed the strategy's match table(s)
/// from the prefix, and put the window directly in the post-flip extDict state
/// so the bit-exact extDict matchers run against it. Shared by
/// [`compress_with_dict`] (Path A, the dict as prefix) and the ZSTDMT job driver
/// ([`compress_mt`], where each non-first job sees the previous job's overlap
/// tail as a raw-content prefix). The caller has already seeded `fc.entropy` /
/// `fc.rep` (default `[1,4,8]` for raw content).
fn prime_raw_prefix(fc: &mut FrameCompressor, buf: &[u8], prefix_len: usize) {
    // Seed the strategy's table(s). Skipped when the prefix is `<=
    // HASH_READ_SIZE`, where C's `ZSTD_loadDictionaryContent` returns before
    // filling — the extDict is still live, just with empty tables.
    if prefix_len > HASH_READ_SIZE {
        match &mut fc.matcher {
            Matcher::Fast(ctx) => fill_fast_hash_table_for_cctx(ctx, buf, prefix_len),
            Matcher::Dfast(ctx) => fill_dfast_hash_tables_for_cctx(ctx, buf, prefix_len),
            Matcher::Lazy(ctx) => ctx.load_dictionary(buf, prefix_len),
            Matcher::Opt(ctx) => ctx.load_dictionary(buf, prefix_len),
        }
    }
    fc.window = Window::preloaded_ext_dict(prefix_len, buf.len() - prefix_len);
    fc.window_preloaded = true;
    // The window-preloaded path skips compress_continue's non-contiguous reset
    // (`ms->nextToUpdate = window.dictLimit`); apply it here so the lazy/opt
    // matchers resume insertion at the start of the input and never re-insert
    // prefix positions. (For a filled prefix, load_dictionary already left
    // nextToUpdate at dictLimit; this is what covers the no-fill `prefix_len ==
    // HASH_READ_SIZE` case, where leaving it at the prefix start would fabricate
    // prefix matches that C — whose post-flip base makes those indices hash
    // unrelated bytes — never finds. Fast/dfast don't track nextToUpdate.)
    match &mut fc.matcher {
        Matcher::Lazy(ctx) => ctx.next_to_update = fc.window.dict_limit as usize,
        Matcher::Opt(ctx) => ctx.next_to_update = fc.window.dict_limit as usize,
        _ => {}
    }
}

/// Like [`prime_raw_prefix`] but for a ZSTDMT job: the prefix is **contiguous**
/// with the segment (same round buffer in C), so the window stays **noDict**
/// (the prefix is in-window history, not extDict). Seeds the same match
/// table(s) from the prefix, then arranges the whole `prefix ++ segment` buffer
/// as one in-window segment so the noDict matchers reach back into the prefix.
fn prime_contiguous_prefix(fc: &mut FrameCompressor, buf: &[u8], prefix_len: usize) {
    if prefix_len > HASH_READ_SIZE {
        match &mut fc.matcher {
            Matcher::Fast(ctx) => fill_fast_hash_table_for_cctx(ctx, buf, prefix_len),
            Matcher::Dfast(ctx) => fill_dfast_hash_tables_for_cctx(ctx, buf, prefix_len),
            Matcher::Lazy(ctx) => ctx.load_dictionary(buf, prefix_len),
            Matcher::Opt(ctx) => ctx.load_dictionary(buf, prefix_len),
        }
    }
    fc.window = Window::preloaded_contiguous_prefix(buf.len());
    fc.window_preloaded = true;
    // Resume table insertion at the segment start (the prefix is already
    // filled); `ZSTD_loadDictionaryContent` leaves `nextToUpdate` here.
    let seg_start_idx = WINDOW_START_INDEX + prefix_len;
    match &mut fc.matcher {
        Matcher::Lazy(ctx) => ctx.next_to_update = seg_start_idx,
        Matcher::Opt(ctx) => ctx.next_to_update = seg_start_idx,
        _ => {}
    }
}

// --- ZSTDMT: multithreaded (job-splitting) compression -----------------------
//
// `zstdmt_compress.c`. C's multithreaded compressor splits the input into
// fixed-size *jobs* and compresses each one largely independently, with the
// previous job's tail supplied as a raw-content prefix ("overlap"). The
// resulting bytes differ from single-threaded output but are **deterministic
// and independent of the worker count** (job boundaries and per-job prefixes
// are pure arithmetic, not thread timing — see `ZSTDMT_compressStream_generic`
// / `ZSTDMT_createCompressionJob`). So we reproduce them by running the jobs
// *sequentially*: the library stays single-threaded and dependency-free.

/// `ZSTDMT_JOBSIZE_MIN` (`zstdmt_compress.h:33`): inputs at or below this skip
/// multithreading entirely (`ZSTD_CCtx_init_compressStream2`, zstd_compress.c).
const ZSTDMT_JOBSIZE_MIN: u64 = 512 * 1024;
/// `ZSTDMT_JOBSIZE_MAX` on a 64-bit target (`zstdmt_compress.h:36`).
const ZSTDMT_JOBSIZE_MAX: u64 = 1024 * 1024 * 1024;
/// `ZSTDMT_JOBLOG_MAX` on a 64-bit target (`zstdmt_compress.h:35`).
const ZSTDMT_JOBLOG_MAX: u32 = 30;

/// `ZSTDMT_computeOverlapSize` (`zstdmt_compress.c:1226`): how many bytes of the
/// previous job's tail each job loads as a raw-content prefix
/// (`mtctx->targetPrefixSize`). The non-LDM branch only (LDM-with-MT is gated
/// out before this is reached).
fn mt_overlap_size(cp: &CParams, overlap_log: i32) -> usize {
    // `ZSTDMT_overlapLog_default` (`:1198`) then `ZSTDMT_overlapLog` (`:1219`).
    let default_overlap_log = match cp.strategy {
        Strategy::Btultra2 => 9,
        Strategy::Btultra | Strategy::Btopt => 8,
        Strategy::Btlazy2 | Strategy::Lazy2 => 7,
        _ => 6,
    };
    let eff = if overlap_log == 0 {
        default_overlap_log
    } else {
        overlap_log
    };
    let overlap_rlog = 9 - eff;
    let ov_log = if overlap_rlog >= 8 {
        0
    } else {
        cp.window_log as i32 - overlap_rlog
    };
    if ov_log <= 0 { 0 } else { 1usize << ov_log }
}

/// `ZSTDMT_computeTargetJobLog` + the clamps in `ZSTDMT_initCStream_internal`
/// (`zstdmt_compress.c:1184` / `:1266-1309`): the per-job input size
/// (`mtctx->targetSectionSize`). Non-LDM branch only.
fn mt_target_section_size(cp: &CParams, job_size: u64, overlap_size: usize) -> usize {
    let mut tss = if job_size != 0 {
        // Explicit `ZSTD_c_jobSize`: clamped to `[MIN, MAX]` (not rounded to a
        // power of two, unlike the computed path).
        job_size.clamp(ZSTDMT_JOBSIZE_MIN, ZSTDMT_JOBSIZE_MAX) as usize
    } else {
        let target_job_log = (cp.window_log + 2).clamp(20, ZSTDMT_JOBLOG_MAX);
        1usize << target_job_log
    };
    // "job size must be >= overlap size" (`:1309`).
    if tss < overlap_size {
        tss = overlap_size;
    }
    tss
}

/// Compress one ZSTDMT job: a fresh frame-compressor (reset entropy + repcodes,
/// matching C's per-job `ZSTD_compressBegin_advanced_internal`) over the
/// `prefix ++ segment` buffer. The first job writes the frame header (its real
/// `pledgedSrcSize` is the whole frame); later jobs emit blocks only (their
/// would-be header is suppressed). Only the last job writes the epilogue.
fn compress_mt_job(
    out: &mut Vec<u8>,
    cparams: CParams,
    buf: &[u8],
    prefix_len: usize,
    pledged: u64,
    write_header: bool,
    is_last: bool,
) -> Result<(), Error> {
    let mut fc = FrameCompressor::from_cparams(cparams, Some(pledged), false);
    if prefix_len > 0 {
        prime_contiguous_prefix(&mut fc, buf, prefix_len);
    }
    if !write_header {
        // Non-first jobs emit blocks only — C overwrites their frame header.
        fc.stage = Stage::Ongoing;
    }
    let seg_start = prefix_len;
    let seg_end = buf.len();
    if is_last {
        fc.compress_end(out, buf, seg_start, seg_end)
    } else {
        fc.compress_continue(out, buf, seg_start, seg_end, false)
    }
}

/// `ZSTD_compress2` with `nbWorkers >= 1` (multithreaded / job-splitting mode).
/// Bit-exact with C libzstd 1.5.7's MT output, reproduced **single-threaded**:
/// the input is split into `jobSize`-byte jobs, each compressed with the
/// previous job's overlap tail as a raw-content prefix and reset repcodes, then
/// the per-job block streams are concatenated into one frame.
///
/// Because C's MT output is deterministic and independent of the actual worker
/// count, `nb_workers` only selects MT-vs-single-threaded: `0` (and any input
/// at or below `ZSTDMT_JOBSIZE_MIN` = 512 KiB, or any input that fits a single
/// job) produces exactly the single-threaded [`compress`] frame. `job_size` and
/// `overlap_log` of `0` mean "use C's defaults".
///
/// Current scope: no dictionary and no content checksum. Two rare
/// configurations return a clean [`Error::Encode`] rather than diverging:
/// long-distance matching with multithreading (`windowLog >= 27` at btopt+,
/// only reached by very large inputs), and an explicit `overlap_log` whose
/// overlap exceeds the indexable dictionary size (`maxDictSize`) — the default
/// `overlap_log` never does. Streaming, dictionaries, checksums, and cross-job
/// LDM are later increments.
pub fn compress_mt(
    src: &[u8],
    level: i32,
    nb_workers: u32,
    job_size: u64,
    overlap_log: i32,
) -> Result<Vec<u8>, Error> {
    if src.len() as u64 >= u64::from(u32::MAX) - 2 {
        return Err(Error::Encode("inputs >= 4 GiB are not supported yet"));
    }
    let src_len = src.len();

    // `ZSTD_CCtx_init_compressStream2`: multithreading is not invoked when the
    // source is small (`pledged <= ZSTDMT_JOBSIZE_MIN`), and `nbWorkers == 0` is
    // plain single-threaded. Both produce the single-threaded frame.
    if nb_workers == 0 || src_len as u64 <= ZSTDMT_JOBSIZE_MIN {
        return compress(src, level);
    }

    // cParams are resolved exactly as single-threaded (nbWorkers is not an
    // input): the whole-frame `pledgedSrcSize` is the known input size.
    let cparams = get_cparams(level, src_len as u64, 0);

    // C's MT path seeds/​shares LDM state across jobs via the serial state; that
    // is not ported, so reject the configs where `ZSTD_resolveEnableLdm` turns
    // it on (btopt+ with `windowLog >= 27`). Unreachable at typical sizes.
    if crate::ldm::LdmParams::auto(&cparams).is_some() {
        return Err(Error::Encode(
            "long-distance matching with multithreading is not supported yet",
        ));
    }

    let overlap_size = mt_overlap_size(&cparams, overlap_log);
    let section_size = mt_target_section_size(&cparams, job_size, overlap_size);

    // `ZSTD_loadDictionaryContent` only indexes the *suffix* of a prefix larger
    // than `maxDictSize` (zstd_compress.c:4962); that truncation isn't ported.
    // With the default `overlapLog` the overlap is always smaller than
    // `maxDictSize` for every strategy, so this never fires — but an explicit
    // large `overlapLog` (e.g. 9 at a fast level) can exceed it, so bail cleanly
    // there rather than diverge.
    let max_dict_size = 1u64 << ((cparams.hash_log + 3).max(cparams.chain_log + 1)).min(31);
    if overlap_size as u64 > max_dict_size {
        return Err(Error::Encode(
            "multithreaded overlap larger than the indexable dictionary size \
             is not supported yet",
        ));
    }

    // A single job (the whole input fits one section) is byte-identical to
    // single-threaded — including the `pledged <= 512 KiB` case handled above.
    if src_len < section_size {
        return compress(src, level);
    }

    // Multi-job: split into `section_size` segments; each non-first job sees the
    // last `overlap_size` bytes of the previous (full) segment as a raw prefix.
    let mut out = Vec::with_capacity(src_len + (src_len >> 8) + 64);
    let mut seg_start = 0usize;
    let mut first = true;
    loop {
        let seg_end = (seg_start + section_size).min(src_len);
        let seg_len = seg_end - seg_start;
        let more_after = seg_end < src_len;
        // The whole input is available at once (one-shot `e_end`), so the final
        // segment — full or partial — is itself the last job: C marks it
        // `endFrame` and writes the epilogue inline. (The separate trailing
        // empty-block job only arises in *streaming* mode, when an exactly
        // section-aligned input ends in a later call; that's a later increment.)
        let is_last = !more_after;

        let prefix_len = if first {
            0
        } else {
            overlap_size.min(seg_start)
        };
        let buf = &src[seg_start - prefix_len..seg_end];
        let pledged = if first {
            src_len as u64
        } else {
            seg_len as u64
        };
        compress_mt_job(&mut out, cparams, buf, prefix_len, pledged, first, is_last)?;

        if !more_after {
            break;
        }
        seg_start = seg_end;
        first = false;
    }
    Ok(out)
}

/// Parse a CDict's dictionary buffer (`ZSTD_compress_insertDictionary` for the
/// CDict): a trained (`ZDICT`) dict seeds the first block's entropy tables,
/// repeat offsets and ID; a raw dict uses the default block state and the whole
/// buffer as content. Returns `(content, entropy, rep, dictID)`.
#[allow(clippy::type_complexity)]
pub(crate) fn parse_cdict(dict: &[u8]) -> Result<(&[u8], FseEntropyState, [u32; 3], u32), Error> {
    if dict.len() >= 8 && read32(dict, 0) == MAGIC_DICTIONARY {
        let seed = crate::dict_encode::load_c_entropy(dict)?;
        Ok((
            &dict[seed.entropy_size..],
            seed.entropy,
            seed.rep,
            seed.dict_id,
        ))
    } else {
        Ok((dict, FseEntropyState::new(), [1, 4, 8], 0))
    }
}

/// Build the working [`FrameCompressor`] for the CDict ATTACH path
/// (`ZSTD_resetCCtx_byAttachingCDict`): working tables sized from the CDict
/// cParams adjusted for the source (dict zeroed by `cpm_attachDict`), windowLog
/// taken from the no-dict source cParams, and the CDict's own match state
/// (`ms->dictMatchState`) built over `content`. Shared by the one-shot
/// [`compress_with_cdict`] and the streaming attach path; the caller arranges
/// the history buffer with `content` as its prefix and sets the window. The
/// `entropy`/`rep`/`dictID` (`prevCBlock = cdict.cBlockState`) are set by the
/// caller.
pub(crate) fn attach_cdict_compressor(
    content: &[u8],
    cdict_cparams: CParams,
    level: i32,
    pledged: Option<u64>,
    checksum: bool,
) -> FrameCompressor {
    let content_len = content.len();
    let src_size = pledged.unwrap_or(CONTENTSIZE_UNKNOWN);
    let mut working = adjust_cparams_internal(cdict_cparams, src_size, 0, CParamMode::NoAttachDict);
    working.window_log = get_cparams(level, src_size, 0).window_log;
    let mut fc = FrameCompressor::from_cparams(working, pledged, checksum);

    let mls = cdict_cparams.min_match.clamp(4, 7);
    fc.dict_match_state = Some(match cdict_cparams.strategy {
        Strategy::Greedy | Strategy::Lazy | Strategy::Lazy2 | Strategy::Btlazy2 => {
            // The CDict's own lazy match state (its params, salt 0), filled over
            // the content; consulted read-only by the dictMatchState search. The
            // working context keeps its own empty tables, but its backend (hash
            // chain / row / binary tree) must match the CDict's
            // (`ZSTD_resetCCtx_byAttachingCDict` overrides useRowMatchFinder;
            // btlazy2 is always the binary tree).
            let cdict_uses_row = crate::lazy::use_row_match_finder(&cdict_cparams);
            let mut dms =
                crate::lazy::LazyCtx::with_row_match_finder(&cdict_cparams, cdict_uses_row);
            dms.use_cdict_hash_salt();
            dms.load_dictionary(content, content_len);
            fc.matcher = Matcher::Lazy(crate::lazy::LazyCtx::with_row_match_finder(
                &working,
                cdict_uses_row,
            ));
            DictMatchState::Lazy(LazyDictMatchState {
                ms: Box::new(dms),
                content_len,
            })
        }
        Strategy::Btopt | Strategy::Btultra | Strategy::Btultra2 => {
            // The CDict's own optimal-parser binary tree (its params); the
            // working OptCtx keeps its own empty tree (no backend to override).
            let mut dms = crate::opt::OptCtx::new(&cdict_cparams);
            dms.load_dictionary(content, content_len);
            DictMatchState::Opt(OptDictMatchState {
                ms: Box::new(dms),
                content_len,
            })
        }
        Strategy::Dfast => {
            let mut hash_long = vec![0u32; 1usize << cdict_cparams.hash_log];
            let mut hash_small = vec![0u32; 1usize << cdict_cparams.chain_log];
            fill_dfast_hash_tables_for_cdict(
                &mut hash_long,
                &mut hash_small,
                content,
                content_len,
                cdict_cparams.hash_log,
                cdict_cparams.chain_log,
                mls,
            );
            DictMatchState::Dfast(DfastDictMatchState {
                hash_long,
                hash_small,
                hlog_l: cdict_cparams.hash_log,
                hlog_s: cdict_cparams.chain_log,
                content_len,
            })
        }
        _ => {
            let mut hash_table = vec![0u32; 1usize << cdict_cparams.hash_log];
            fill_fast_hash_table_for_cdict(
                &mut hash_table,
                content,
                content_len,
                cdict_cparams.hash_log,
                mls,
            );
            DictMatchState::Fast(FastDictMatchState {
                hash_table,
                hlog: cdict_cparams.hash_log,
                content_len,
            })
        }
    });
    fc
}

/// `ZSTD_shouldAttachDict` / `attachDictSizeCutoffs`: the per-strategy
/// pledged-size threshold below which the CDict is attached rather than copied.
pub(crate) fn cdict_attach_cutoff(strategy: Strategy) -> usize {
    match strategy {
        Strategy::Greedy
        | Strategy::Lazy
        | Strategy::Lazy2
        | Strategy::Btlazy2
        | Strategy::Btopt => 32 * 1024,
        Strategy::Dfast => 16 * 1024,
        // fast, btultra, btultra2
        _ => 8 * 1024,
    }
}

/// What the streaming encoder needs to drive a CDict-attach frame: the
/// configured compressor and the staging buffer with the dict content as its
/// permanent prefix (`in_buff[..content_len]`), input staged from `content_len`.
pub(crate) struct StreamCdictInit {
    pub(crate) fc: FrameCompressor,
    pub(crate) in_buff: Vec<u8>,
    pub(crate) content_len: usize,
}

/// Prepare a streaming CDict-attach frame (`ZSTD_CCtx_loadDictionary` →
/// internal CDict → `ZSTD_resetCCtx_byAttachingCDict`, with the unknown / small
/// pledged size that attaches rather than copies). The dict content becomes a
/// permanent prefix of the staging buffer (the concat model, `dictIndexDelta
/// == 0`), and the window starts in the streaming-attach state so each chunk is
/// registered contiguously. The copy path (a large pledged size) is rejected
/// for now, as is a dictionary with <= 8 bytes of content.
pub(crate) fn streaming_cdict_init(
    dict: &[u8],
    level: i32,
    pledged: Option<u64>,
    checksum: bool,
) -> Result<StreamCdictInit, Error> {
    let (content, entropy, rep, dict_id) = parse_cdict(dict)?;
    let content_len = content.len();
    if content_len <= HASH_READ_SIZE {
        return Err(Error::Encode(
            "CDict (Path B): dictionaries with <= 8 bytes of content are not supported yet",
        ));
    }
    let cdict_cparams = get_cparams_create_cdict(level, dict.len() as u64);
    // Streaming defaults to an unknown size, which attaches. A pledged size above
    // the strategy cutoff would copy the dict (extDict) — not ported for streams.
    if pledged.is_some_and(|p| p as usize > cdict_attach_cutoff(cdict_cparams.strategy)) {
        return Err(Error::Encode(
            "streaming with a CDict above the attach cutoff (copy path) is not supported yet",
        ));
    }

    let mut fc = attach_cdict_compressor(content, cdict_cparams, level, pledged, checksum);
    fc.window = Window::streaming_attached_dict(content_len);
    fc.entropy = entropy;
    fc.rep = rep;
    fc.dict_id = dict_id;
    // Lazy/opt resume table insertion at the src start (the first contiguous
    // chunk's nextToUpdate floor also does this, but set it explicitly).
    match &mut fc.matcher {
        Matcher::Lazy(ctx) => ctx.next_to_update = fc.window.dict_limit as usize,
        Matcher::Opt(ctx) => ctx.next_to_update = fc.window.dict_limit as usize,
        _ => {}
    }

    let block_size = fc.block_size_max();
    let window_size = fc.window_size();
    let mut in_buff = vec![0u8; content_len + window_size + block_size];
    in_buff[..content_len].copy_from_slice(content);
    Ok(StreamCdictInit {
        fc,
        in_buff,
        content_len,
    })
}

/// `ZSTD_compress_usingCDict` (what `zstd::bulk::Compressor::with_dictionary`
/// uses): one-shot compression with the dictionary loaded as a **CDict**
/// (Path B). Produces **different bytes** than [`compress_with_dict`] (Path A):
/// the CDict tables are filled `dtlm_full` (tagged short cache), and the working
/// context either **attaches** the CDict (small inputs ≤ the strategy cutoff) or
/// **copies** its de-tagged tables (larger inputs).
///
/// Current scope: all nine strategies, both raw and trained dictionaries, on
/// both the attach and copy sides of the cutoff. The only rejected
/// configurations are a dictionary with <= 8 bytes of content and the rare
/// large-window case where C would enable long-distance matching with the dict
/// (`windowLog >= 27` at btopt+) — both return a clean [`Error::Encode`].
pub fn compress_with_cdict(src: &[u8], dict: &[u8], level: i32) -> Result<Vec<u8>, Error> {
    if dict.len() as u64 + src.len() as u64 >= u64::from(u32::MAX) - 2 {
        return Err(Error::Encode("inputs >= 4 GiB are not supported yet"));
    }

    // The CDict's own cParams (`cpm_createCDict`, the *whole* dict buffer size).
    let cdict_cparams = get_cparams_create_cdict(level, dict.len() as u64);
    // All nine strategies are supported; the only unsupported configurations are
    // tiny dictionaries (gated below) and the rare large-window LDM-with-dict
    // case (gated after the context is built).

    // Parse the dictionary (`ZSTD_compress_insertDictionary` for the CDict).
    let (content, entropy, rep, dict_id) = parse_cdict(dict)?;

    let content_len = content.len();
    let src_len = src.len();
    let src_size = src_len as u64;

    // A CDict with no usable content attaches nothing (C: "don't attach empty
    // dictionary"); that degenerate case isn't ported yet.
    if content_len <= HASH_READ_SIZE {
        return Err(Error::Encode(
            "CDict (Path B): dictionaries with <= 8 bytes of content are not supported yet",
        ));
    }

    // `ZSTD_shouldAttachDict`: attach iff srcSize <= the strategy cutoff,
    // otherwise copy the dict into the context.
    let attach = src_len <= cdict_attach_cutoff(cdict_cparams.strategy);

    let pledged = Some(src_size);
    let mut data = Vec::with_capacity(content_len + src_len);
    data.extend_from_slice(content);
    data.extend_from_slice(src);

    let mut fc = if attach {
        // `ZSTD_resetCCtx_byAttachingCDict` (the dms over `content`); arrange the
        // window over the concatenated `content ++ src` buffer in the post-reset
        // attach state (src begins at `cdictEnd`, no extDict).
        let mut fc = attach_cdict_compressor(content, cdict_cparams, level, pledged, false);
        fc.window = Window::preloaded_attached_dict(content_len, src_len);
        fc.window_preloaded = true;
        fc
    } else {
        // `ZSTD_resetCCtx_byCopyingCDict`: the window holds the dict as a prefix
        // (extDict on the `src` append) — i.e. the Path A flow with the CDict's
        // own cParams and windowLog overridden to the working context's.
        let mut working = cdict_cparams;
        working.window_log = get_cparams(level, src_size, dict.len() as u64).window_log;
        let mut fc = FrameCompressor::from_cparams(working, pledged, false);
        match cdict_cparams.strategy {
            Strategy::Greedy | Strategy::Lazy | Strategy::Lazy2 | Strategy::Btlazy2 => {
                // Lazy/btlazy2 tables aren't tagged (`ZSTD_CDictIndicesAreTagged`
                // is fast/dfast only), so the copied CDict tables equal a plain
                // Path A (`load_dictionary`) fill — same params, the CDict's
                // backend, and the CDict's salt (0, copied for the row finder).
                let cdict_uses_row = crate::lazy::use_row_match_finder(&cdict_cparams);
                let mut ctx = crate::lazy::LazyCtx::with_row_match_finder(&working, cdict_uses_row);
                ctx.use_cdict_hash_salt();
                ctx.load_dictionary(&data, content_len);
                fc.matcher = Matcher::Lazy(ctx);
            }
            Strategy::Btopt | Strategy::Btultra | Strategy::Btultra2 => {
                // btopt+ tables aren't tagged either: the copied CDict tree equals
                // a plain Path A `load_dictionary` fill over the working OptCtx.
                if let Matcher::Opt(ctx) = &mut fc.matcher {
                    ctx.load_dictionary(&data, content_len);
                }
            }
            // The de-tagged CDict fast/dfast table equals an untagged `dtlm_full`
            // fill, reproduced directly in the working tables.
            _ => match &mut fc.matcher {
                Matcher::Fast(ctx) => fill_fast_hash_table_for_cctx_full(ctx, &data, content_len),
                Matcher::Dfast(ctx) => {
                    fill_dfast_hash_tables_for_cctx_full(ctx, &data, content_len)
                }
                _ => {}
            },
        }
        fc.window = Window::preloaded_ext_dict(content_len, src_len);
        fc.window_preloaded = true;
        fc
    };

    // C's `ZSTD_loadDictionaryContent` seeds the dict into the LDM tables too;
    // that path isn't ported, so reject the (large-window) configurations where
    // `ZSTD_resolveEnableLdm` turns long-distance matching on (btopt+ with
    // windowLog >= 27) rather than diverge. Unreachable at typical sizes.
    if fc.ldm.is_some() {
        return Err(Error::Encode(
            "long-distance matching with a CDict is not supported yet",
        ));
    }

    // `prevCBlock = cdict.cBlockState` on both paths.
    fc.entropy = entropy;
    fc.rep = rep;
    fc.dict_id = dict_id;

    // Lazy/opt resume table insertion at the src start; the window-preloaded path
    // skips compress_continue's non-contiguous `nextToUpdate = dictLimit` reset.
    // (Fast/dfast don't track nextToUpdate; the attach window's dictLimit is the
    // src start, the copy window's is the dict/src seam — both the right resume
    // point.)
    match &mut fc.matcher {
        Matcher::Lazy(ctx) => ctx.next_to_update = fc.window.dict_limit as usize,
        Matcher::Opt(ctx) => ctx.next_to_update = fc.window.dict_limit as usize,
        _ => {}
    }

    let mut out = Vec::with_capacity(src_len + (src_len >> 8) + 64);
    fc.compress_end(&mut out, &data, content_len, content_len + src_len)?;
    Ok(out)
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum BlockKind {
    Raw,
    Rle,
    Compressed,
}

/// The per-strategy match-finder state held across a frame's blocks.
enum Matcher {
    Fast(FastCtx),
    Dfast(DfastCtx),
    Lazy(crate::lazy::LazyCtx),
    Opt(Box<crate::opt::OptCtx>),
}
