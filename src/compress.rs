//! One-shot compression (`ZSTD_compress`), aiming for **byte-identical output
//! to C libzstd 1.5.7**: parameter derivation (`ZSTD_getCParams` /
//! `ZSTD_adjustCParams`), the match finders, and frame assembly
//! (`ZSTD_writeFrameHeader` / `ZSTD_compress_frameChunk` /
//! `ZSTD_compressBlock_internal`).
//!
//! Current scope: **every compression level** (1-22 and the negative /
//! acceleration levels), any input size, no dictionary, no checksum — the
//! `ZSTD_compress` defaults. All nine strategies are implemented: fast and
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
const ZSTD_MAGIC: u32 = 0xFD2F_B528;

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
        (14, 15, 15,  5,  3, 32, Btultra),
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

/// `ZSTD_getCParams_internal` + `ZSTD_adjustCParams_internal`, specialized to
/// the no-dictionary one-shot case (`ZSTD_cpm_noAttachDict`, known srcSize).
pub(crate) fn get_cparams(level: i32, src_size: u64) -> CParams {
    // ZSTD_getCParamRowSize: srcSize known, no dict -> rSize = srcSize.
    let r_size = src_size;
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
        // Acceleration factor for negative levels.
        cp.target_length = (-level.max(ZSTD_MIN_CLEVEL)) as u32;
    }

    // --- ZSTD_adjustCParams_internal (srcSize known, dictSize 0) ---
    let max_window_resize = 1u64 << (31 - 1);
    if src_size <= max_window_resize {
        let t_size = src_size as u32;
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
    {
        // dictSize == 0 makes dictAndWindowLog collapse to windowLog.
        let dict_and_window_log = cp.window_log;
        let cyc_log = cycle_log(cp.chain_log, cp.strategy);
        if cp.hash_log > dict_and_window_log + 1 {
            cp.hash_log = dict_and_window_log + 1;
        }
        if cyc_log > dict_and_window_log {
            cp.chain_log -= cyc_log - dict_and_window_log;
        }
    }
    if cp.window_log < WINDOWLOG_ABSOLUTEMIN {
        cp.window_log = WINDOWLOG_ABSOLUTEMIN;
    }
    // Row-match-finder hashLog cap: (hashLog - rowLog + 8) <= 32. At this
    // point C conservatively assumes row mode is on for the strategies that
    // support it (greedy..lazy2).
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
    fn new() -> Self {
        Window {
            seg_bias: WINDOW_START_INDEX as u32,
            dict_bias: WINDOW_START_INDEX as u32,
            low_limit: WINDOW_START_INDEX as u32,
            dict_limit: WINDOW_START_INDEX as u32,
            next_src_pos: 0,
            next_src_idx: WINDOW_START_INDEX as u32,
        }
    }

    /// `ZSTD_window_update`: register `buf[start..end]` as the next chunk.
    /// Returns whether it was contiguous with the previous one; if not, the
    /// current prefix becomes the extDict. Also shrinks the extDict when the
    /// new chunk overwrites part of it in the (shared) buffer.
    fn update(&mut self, start: usize, end: usize) -> bool {
        if start == end {
            return true;
        }
        let mut contiguous = true;
        if start != self.next_src_pos {
            self.low_limit = self.dict_limit;
            self.dict_limit = self.next_src_idx;
            self.dict_bias = self.seg_bias;
            // base = ip - distanceFromBase, i.e. buf[start] gets the next index.
            self.seg_bias = self.next_src_idx - start as u32;
            if self.dict_limit - self.low_limit < HASH_READ_SIZE as u32 {
                // Too small extDict: forget it.
                self.low_limit = self.dict_limit;
            }
            contiguous = false;
        }
        self.next_src_pos = end;
        self.next_src_idx = self.seg_bias + end as u32;
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
    fn enforce_max_dist(&mut self, idx: u32, max_dist: u32) {
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
    fn has_ext_dict(&self) -> bool {
        self.low_limit < self.dict_limit
    }
}

/// `ZSTD_count_2segments`: count the match length when `match` lives in the
/// extDict segment — count up to `mend`, then continue comparing from
/// `istart` (the prefix start). All arguments are buffer positions.
fn count_2segments(
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
    hlog: u32,
    mls: u32,
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
        hlog,
        mls,
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
    let hlog = w.hlog;
    let mls = w.mls;

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
}

/// `ZSTD_compressBlock_doubleFast` (noDict path). Same conventions as
/// [`compress_block_fast`]: biased indices, sequences into `store`, returns the
/// trailing-literals size. The `ZSTD_selectAddr`/dummy-pointer constructs in C
/// are branchless forms of plain `idx >= prefixLowestIndex` validity tests
/// (the `+1` long probe is strictly `>`), which is how they appear here.
fn compress_block_dfast(
    ctx: &mut DfastCtx,
    store: &mut SeqStore,
    rep: &mut [u32; 3],
    data: &[u8],
    block_start: usize,
    block_end: usize,
) -> usize {
    let src_size = block_end - block_start;
    let hlog_l = ctx.hlog_l;
    let hlog_s = ctx.hlog_s;
    let mls = ctx.mls;

    let max_distance = 1usize << ctx.window_log;
    let end_index = block_end + WINDOW_START_INDEX;
    let prefix_start_index = if end_index - WINDOW_START_INDEX > max_distance {
        end_index - max_distance
    } else {
        WINDOW_START_INDEX
    };
    // kStepIncr = 1 << kSearchStrength (256) — twice the fast matcher's.
    let k_step_incr: usize = 1 << K_SEARCH_STRENGTH;

    let bias = WINDOW_START_INDEX;
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
        let window_low = if ip - WINDOW_START_INDEX > max_distance {
            ip - max_distance
        } else {
            WINDOW_START_INDEX
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

// --- Frame assembly ----------------------------------------------------------------

/// `ZSTD_isRLE`.
pub(crate) fn is_rle(src: &[u8]) -> bool {
    src.iter().all(|&b| b == src[0])
}

/// `ZSTD_writeFrameHeader`, no dictionary (dictID 0). `pledged` of `None` is
/// `ZSTD_CONTENTSIZE_UNKNOWN`; per `ZSTD_resetCCtx_internal` an unknown
/// pledged size clears the content-size flag, which both omits the FCS field
/// and disables the single-segment format.
fn write_frame_header(out: &mut Vec<u8>, cparams: &CParams, pledged: Option<u64>, checksum: bool) {
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
    let descriptor =
        (fcs_code << 6) as u8 | ((single_segment as u8) << 5) | ((checksum as u8) << 2);

    out.extend_from_slice(&ZSTD_MAGIC.to_le_bytes());
    out.push(descriptor);
    if !single_segment {
        out.push(((cparams.window_log - WINDOWLOG_ABSOLUTEMIN) << 3) as u8);
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
}

impl FrameCompressor {
    pub(crate) fn new(level: i32, pledged: Option<u64>, checksum: bool) -> Self {
        // Unknown content size selects the "default" srcSize class and skips
        // the window resize (`ZSTD_getCParamRowSize` returns
        // ZSTD_CONTENTSIZE_UNKNOWN for unknown srcSize without a dictionary).
        let cparams = get_cparams(level, pledged.unwrap_or(u64::MAX));
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
        }
    }

    pub(crate) fn window_size(&self) -> usize {
        self.window_size
    }

    pub(crate) fn block_size_max(&self) -> usize {
        self.block_size_max
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
            write_frame_header(out, &self.cparams, self.pledged, self.checksum);
            self.stage = Stage::Ongoing;
        }
        if chunk_start == chunk_end {
            // Do not generate an empty block, but do count the header.
            self.produced += (out.len() - out_start) as u64;
            return Ok(());
        }

        // Beyond ZSTD_CURRENT_MAX (3500 MiB of total index space) the C
        // encoder starts running overflow correction, which is not ported.
        const CURRENT_MAX: u64 = 3500 * (1 << 20);
        if u64::from(self.window.next_src_idx) + (chunk_end - chunk_start) as u64 > CURRENT_MAX {
            return Err(Error::Encode(
                "total input beyond 3500 MiB needs index overflow correction, \
                 which is not implemented yet",
            ));
        }
        // `ZSTD_window_update`: a non-contiguous chunk (the streaming input
        // buffer wrapped) turns the live window into the extDict, which only
        // the fast strategy's match finder supports so far.
        if !self.window.update(chunk_start, chunk_end) && self.cparams.strategy != Strategy::Fast {
            return Err(Error::Encode(
                "streaming beyond windowSize+blockSize requires the extDict \
                 match finders, which are only ported for the fast strategy \
                 (levels 1-2 and negative levels) so far",
            ));
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

            // `ZSTD_window_enforceMaxDist` runs before every block, anchored
            // at the *block start* (`ip`, not `ip + blockSize` — that one
            // only feeds `ZSTD_checkDictValidity`); the dict mode below
            // (extDict vs noDict) is decided on the result. The matchers
            // tighten their own validity bound from the block end.
            let block_start_idx = pos as u32 + self.window.seg_bias;
            self.window
                .enforce_max_dist(block_start_idx, 1u32 << cparams.window_log);

            // --- ZSTD_compressBlock_internal ---
            let mut c_size_kind: BlockKind;
            let mut body: Vec<u8> = Vec::new();

            // ZSTD_buildSeqStore: tiny blocks are not even attempted.
            if block_size < MIN_CBLOCK_SIZE + BLOCK_HEADER_SIZE + 1 + 1 {
                c_size_kind = BlockKind::Raw;
            } else {
                let mut store = SeqStore::new();
                let mut next_rep = self.rep;
                let last_ll_size = match &mut self.matcher {
                    Matcher::Fast(ctx) => {
                        // `ZSTD_selectBlockCompressor(strategy, ..,
                        // ZSTD_matchState_dictMode(ms))`.
                        if self.window.has_ext_dict() {
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
                    Matcher::Dfast(ctx) => compress_block_dfast(
                        ctx,
                        &mut store,
                        &mut next_rep,
                        data,
                        pos,
                        pos + block_size,
                    ),
                    Matcher::Lazy(ctx) => crate::lazy::compress_block_lazy(
                        ctx,
                        &mut store,
                        &mut next_rep,
                        data,
                        pos,
                        pos + block_size,
                    ),
                    Matcher::Opt(ctx) => crate::opt::compress_block_opt(
                        ctx,
                        &mut store,
                        &mut next_rep,
                        data,
                        pos,
                        pos + block_size,
                    ),
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
