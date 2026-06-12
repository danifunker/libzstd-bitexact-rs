//! One-shot compression (`ZSTD_compress`), aiming for **byte-identical output
//! to C libzstd 1.5.7**: parameter derivation (`ZSTD_getCParams` /
//! `ZSTD_adjustCParams`), the `ZSTD_fast` match finder, and frame assembly
//! (`ZSTD_writeFrameHeader` / `ZSTD_compress_frameChunk` /
//! `ZSTD_compressBlock_internal`).
//!
//! Current scope: levels whose resolved strategy is `ZSTD_fast` (levels 1-2
//! and the negative/acceleration levels), any input size, no dictionary, no
//! checksum — the `ZSTD_compress` defaults. Other strategies return
//! [`Error::Encode`] until their match finders are ported. Block boundaries
//! follow `ZSTD_optimalBlockSize`, including the 1.5.7 pre-block splitter
//! ([`crate::pre_split`]).

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
    // The row-match-finder hashLog cap only applies to greedy/lazy/lazy2
    // strategies; not the fast path.
    cp
}

// --- Small shared helpers ------------------------------------------------------

fn read32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
}

fn read64(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

/// `ZSTD_count`: length of the common run of `data[a..]` and `data[b..]`,
/// reading no further than `limit` for the `a` cursor.
fn count_eq(data: &[u8], mut a: usize, mut b: usize, limit: usize) -> usize {
    let start = a;
    while a < limit && data[a] == data[b] {
        a += 1;
        b += 1;
    }
    a - start
}

/// `ZSTD_hashPtr` for `mls` in 4..=7 (the fast strategy's range), hashing the
/// bytes of `data` at `at`.
fn hash_ptr(data: &[u8], at: usize, hlog: u32, mls: u32) -> usize {
    const PRIME4: u32 = 2654435761;
    const PRIME5: u64 = 889523592379;
    const PRIME6: u64 = 227718039650203;
    const PRIME7: u64 = 58295818150454627;
    match mls {
        5 => ((read64(data, at) << (64 - 40)).wrapping_mul(PRIME5) >> (64 - hlog)) as usize,
        6 => ((read64(data, at) << (64 - 48)).wrapping_mul(PRIME6) >> (64 - hlog)) as usize,
        7 => ((read64(data, at) << (64 - 56)).wrapping_mul(PRIME7) >> (64 - hlog)) as usize,
        _ => (read32(data, at).wrapping_mul(PRIME4) >> (32 - hlog)) as usize,
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
}

/// `ZSTD_compressBlock_fast` (noDict path), operating on the whole frame input
/// `data` with the current block being `data[block_start..block_end]`.
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
) -> usize {
    let src_size = block_end - block_start;
    let hlog = ctx.hlog;
    let mls = ctx.mls;
    let step_size = ctx.step_size;
    // `ZSTD_getLowestPrefixIndex` after `ZSTD_window_enforceMaxDist`: once the
    // frame outgrows the window, the lowest valid match index slides to
    // blockEnd - windowSize. (Biased indices, like everything below.)
    let max_distance = 1usize << ctx.window_log;
    let end_index = block_end + WINDOW_START_INDEX;
    let prefix_start_index = if end_index - WINDOW_START_INDEX > max_distance {
        end_index - max_distance
    } else {
        WINDOW_START_INDEX
    };
    let k_step_incr: usize = 1 << (K_SEARCH_STRENGTH - 1);

    // All `ipN` variables are *biased* indices (input position + 2), matching
    // the C pointer arithmetic `ip - base`.
    let bias = WINDOW_START_INDEX;
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
        let curr = ip0;
        let window_low = prefix_start_index; // within-window for our scope
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

// --- Frame assembly ----------------------------------------------------------------

/// `ZSTD_isRLE`.
fn is_rle(src: &[u8]) -> bool {
    src.iter().all(|&b| b == src[0])
}

/// `ZSTD_writeFrameHeader`, for the one-shot defaults: contentSize known and
/// flagged, no checksum, no dictionary.
fn write_frame_header(out: &mut Vec<u8>, cparams: &CParams, pledged_src_size: u64) {
    let window_size = 1u64 << cparams.window_log;
    let single_segment = window_size >= pledged_src_size;
    let fcs_code = (pledged_src_size >= 256) as u32
        + (pledged_src_size >= 65536 + 256) as u32
        + (pledged_src_size >= 0xFFFF_FFFF) as u32;
    let descriptor = (fcs_code << 6) as u8 | ((single_segment as u8) << 5);

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
fn push_block_header(out: &mut Vec<u8>, last: bool, block_type: u32, size: usize) {
    let v = (last as u32) | (block_type << 1) | ((size as u32) << 3);
    out.extend_from_slice(&v.to_le_bytes()[..3]);
}

/// `ZSTD_compress`: one-shot frame compression with the simple-API defaults.
///
/// Bit-exact with C libzstd 1.5.7 for the supported scope (see module docs);
/// unsupported configurations return [`Error::Encode`] rather than diverging.
pub fn compress(src: &[u8], level: i32) -> Result<Vec<u8>, Error> {
    let cparams = get_cparams(level, src.len() as u64);
    if cparams.strategy != Strategy::Fast {
        return Err(Error::Encode(
            "only the fast strategy (levels <= 2) is implemented so far",
        ));
    }
    if src.len() as u64 >= u64::from(u32::MAX) - 2 {
        // Match indices are 32-bit; larger inputs need the C window-cycling
        // (overflow correction) machinery.
        return Err(Error::Encode("inputs >= 4 GiB are not supported yet"));
    }

    // `ZSTD_literalsCompressionIsDisabled` in the default `ZSTD_ps_auto`
    // mode: the fast strategy with a nonzero target length (the negative /
    // acceleration levels) skips literal compression entirely.
    let disable_literal_compression =
        cparams.strategy == Strategy::Fast && cparams.target_length > 0;

    let mut out = Vec::with_capacity(src.len() + (src.len() >> 8) + 64);
    write_frame_header(&mut out, &cparams, src.len() as u64);

    let block_size_max = BLOCK_SIZE_MAX.min(1usize << cparams.window_log);
    let mut ctx = FastCtx::new(&cparams);
    let mut rep: [u32; 3] = [1, 4, 8];
    let mut entropy = FseEntropyState::new();
    let mut savings: i64 = 0;
    let mut is_first_block = true;

    let mut pos = 0usize;
    if src.is_empty() {
        // Epilogue only: a last, empty raw block.
        push_block_header(&mut out, true, 0, 0);
        return Ok(out);
    }

    while pos < src.len() {
        let remaining = src.len() - pos;
        // ZSTD_optimalBlockSize: only full 128 KiB blocks are candidates for
        // pre-splitting, and only once at least 3 bytes of savings are
        // verified (so the first block is never split). The auto split level
        // is `splitLevels[strategy]` — 0 (fromBorders) for the fast strategy.
        let block_size = if remaining < BLOCK_SIZE_MAX || block_size_max < BLOCK_SIZE_MAX {
            remaining.min(block_size_max)
        } else if savings < 3 {
            BLOCK_SIZE_MAX
        } else {
            const SPLIT_LEVELS: [usize; 10] = [0, 0, 1, 2, 2, 3, 3, 4, 4, 4];
            let split_level = SPLIT_LEVELS[cparams.strategy as usize];
            pre_split::split_block(&src[pos..pos + BLOCK_SIZE_MAX], split_level)
        };
        let last_block = block_size == remaining;
        let block = &src[pos..pos + block_size];

        // --- ZSTD_compressBlock_internal ---
        let mut c_size_kind: BlockKind;
        let mut body: Vec<u8> = Vec::new();

        // ZSTD_buildSeqStore: tiny blocks are not even attempted.
        if block_size < MIN_CBLOCK_SIZE + BLOCK_HEADER_SIZE + 1 + 1 {
            c_size_kind = BlockKind::Raw;
        } else {
            let mut store = SeqStore::new();
            let mut next_rep = rep;
            let last_ll_size = compress_block_fast(
                &mut ctx,
                &mut store,
                &mut next_rep,
                src,
                pos,
                pos + block_size,
            );
            let lits_from = block_size - last_ll_size;
            store.store_last_literals(&block[lits_from..]);

            match sequences_encode::entropy_compress_seq_store(
                &store,
                &entropy,
                cparams.strategy as i32,
                disable_literal_compression,
                block_size,
            )? {
                None => c_size_kind = BlockKind::Raw,
                Some((b, next_entropy)) => {
                    body = b;
                    c_size_kind = BlockKind::Compressed;
                    // RLE-block override (not for the first block; decoder
                    // compat for zstd <= 1.4.3).
                    if !is_first_block && body.len() < 25 && is_rle(block) {
                        c_size_kind = BlockKind::Rle;
                    }
                    // Confirm repcodes + entropy only when actually emitting a
                    // compressed block (cSize > 1).
                    if c_size_kind == BlockKind::Compressed {
                        rep = next_rep;
                        entropy = next_entropy;
                    }
                }
            }
        }

        let c_size = match c_size_kind {
            BlockKind::Raw => {
                push_block_header(&mut out, last_block, 0, block_size);
                out.extend_from_slice(block);
                BLOCK_HEADER_SIZE + block_size
            }
            BlockKind::Rle => {
                push_block_header(&mut out, last_block, 1, block_size);
                out.push(block[0]);
                BLOCK_HEADER_SIZE + 1
            }
            BlockKind::Compressed => {
                push_block_header(&mut out, last_block, 2, body.len());
                out.extend_from_slice(&body);
                BLOCK_HEADER_SIZE + body.len()
            }
        };

        savings += block_size as i64 - c_size as i64;
        pos += block_size;
        is_first_block = false;
    }

    Ok(out)
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum BlockKind {
    Raw,
    Rle,
    Compressed,
}
