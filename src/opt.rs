//! The optimal parser (`zstd_opt.c`): btopt (optLevel 0), btultra
//! (optLevel 2), and btultra2 (optLevel 2 + a first-block double pass that
//! seeds the statistics). Levels 16-22. In extDict mode (streaming past a
//! buffer wrap) btultra2 maps to the btultra entry point per the
//! `ZSTD_selectBlockCompressor` table — the stats pass is noDict-only.
//!
//! The parser prices every reachable position of a lookahead window using
//! adaptive symbol statistics (literals, literal lengths, match lengths,
//! offset codes), finds the cheapest "stretch" chain, and emits it. Match
//! candidates come from a binary tree (`ZSTD_insertBt1` / `ZSTD_updateTree` /
//! `ZSTD_insertBtAndGetAllMatches`), plus a 3-byte hash table when
//! `minMatch == 3`, plus the speculative repcode set.
//!
//! Port note: in 1.5.7 the shortest-path traversal contains `} {` (not
//! `} else {`) after the `lastStretch.litlen > 0` branch, making that branch
//! dead code — the unconditional block always wins. We reproduce the
//! *effective* behavior.

use crate::block::{LL_BITS, ML_BITS};
use crate::compress::{CParams, Strategy, Window, count_2segments, count_eq, hash_ptr, read32};
use crate::sequences_encode::{SeqStore, ll_code, ml_code};

const WINDOW_START_INDEX: usize = 2;
const ZSTD_OPT_NUM: usize = 1 << 12;
const ZSTD_OPT_SIZE: usize = ZSTD_OPT_NUM + 3;
const ZSTD_MAX_PRICE: i32 = 1 << 30;
const ZSTD_PREDEF_THRESHOLD: usize = 8;
const ZSTD_LITFREQ_ADD: u32 = 2;
const HASHLOG3_MAX: u32 = 17;
const BITCOST_ACCURACY: u32 = 8;
const BITCOST_MULTIPLIER: u32 = 1 << BITCOST_ACCURACY;
const MINMATCH: u32 = 3;
const MAX_LIT: usize = 255;
const MAX_LL: usize = 35;
const MAX_ML: usize = 52;
const MAX_OFF: usize = 31;

fn highbit32(x: u32) -> u32 {
    debug_assert!(x >= 1);
    31 - x.leading_zeros()
}

/// `ZSTD_bitWeight`.
fn bit_weight(stat: u32) -> u32 {
    highbit32(stat + 1) * BITCOST_MULTIPLIER
}

/// `ZSTD_fracWeight`.
fn frac_weight(raw_stat: u32) -> u32 {
    let stat = raw_stat + 1;
    let hb = highbit32(stat);
    let b_weight = hb * BITCOST_MULTIPLIER;
    let f_weight = (stat << BITCOST_ACCURACY) >> hb;
    b_weight + f_weight
}

/// `WEIGHT(stat, opt)`: btopt uses whole bits, ultra uses fractional bits.
fn weight(stat: u32, opt_level: i32) -> u32 {
    if opt_level != 0 {
        frac_weight(stat)
    } else {
        bit_weight(stat)
    }
}

/// `ZSTD_hash3Ptr`.
fn hash3_ptr(data: &[u8], at: usize, h: u32) -> usize {
    const PRIME3: u32 = 506_832_829;
    (((read32(data, at) << (32 - 24)).wrapping_mul(PRIME3)) >> (32 - h)) as usize
}

/// `ZSTD_readMINMATCH`: 3- or 4-byte comparison value.
fn read_minmatch(data: &[u8], at: usize, length: u32) -> u32 {
    if length == 3 {
        read32(data, at) << 8
    } else {
        read32(data, at)
    }
}

/// `ZSTD_updateRep` / `ZSTD_newRep`.
fn new_rep(rep: [u32; 3], off_base: u32, ll0: bool) -> [u32; 3] {
    let mut r = rep;
    if off_base > 3 {
        // full offset
        r[2] = r[1];
        r[1] = r[0];
        r[0] = off_base - 3;
    } else {
        let rep_code = off_base - 1 + ll0 as u32;
        if rep_code > 0 {
            let current_offset = if rep_code == 3 {
                r[0] - 1
            } else {
                r[rep_code as usize]
            };
            r[2] = if rep_code >= 2 { r[1] } else { r[2] };
            r[1] = r[0];
            r[0] = current_offset;
        }
    }
    r
}

#[derive(Clone, Copy, Default)]
struct Match {
    off: u32,
    len: u32,
}

#[derive(Clone, Copy, Default)]
struct Optimal {
    price: i32,
    off: u32,
    mlen: u32,
    litlen: u32,
    rep: [u32; 3],
}

/// The optimal parser's cross-block state (`ZSTD_MatchState_t` + `optState_t`).
pub(crate) struct OptCtx {
    hash_table: Vec<u32>,
    /// The binary tree (chainTable), 2 slots per node.
    bt: Vec<u32>,
    hash3: Vec<u32>,
    hash_log3: u32,
    /// Biased index of the next position to insert. Reset to
    /// `window.dictLimit` by the frame loop on a non-contiguous chunk
    /// (`ZSTD_compressContinue_internal`).
    pub(crate) next_to_update: usize,
    /// Per-block snapshots of the window geometry (C reads `ms->window`
    /// directly), refreshed by [`compress_block_opt`]: position-to-index
    /// bias of the current segment, `dictLimit`, `lowLimit`, and the dict
    /// segment's bias.
    base_bias: usize,
    dict_limit: usize,
    low_limit: usize,
    dict_bias: usize,

    opt_level: i32,
    is_ultra2: bool,
    /// `BOUNDED(3, minMatch, 6)`.
    mls: u32,
    sufficient_len: u32,
    search_log: u32,
    window_log: u32,
    hash_log: u32,
    chain_log: u32,

    // optState_t statistics.
    lit_freq: Vec<u32>,
    ll_freq: Vec<u32>,
    ml_freq: Vec<u32>,
    of_freq: Vec<u32>,
    lit_sum: u32,
    ll_sum: u32,
    ml_sum: u32,
    of_sum: u32,
    lit_sum_base: u32,
    ll_sum_base: u32,
    ml_sum_base: u32,
    of_sum_base: u32,
    price_predef: bool,

    opt: Vec<Optimal>,
    matches: Vec<Match>,
}

impl OptCtx {
    /// `ZSTD_buildSeqStore`'s "limited update after a very long match": pull
    /// `nextToUpdate` to within 384+192 of the block start. `curr` is the
    /// biased index of the block start (the caller computes it from the
    /// window, which carries any btultra2 initStats slide).
    pub(crate) fn limit_update(&mut self, curr: usize) {
        if curr > self.next_to_update + 384 {
            self.next_to_update = curr - 192.min(curr - self.next_to_update - 384);
        }
    }

    pub(crate) fn new(cparams: &CParams) -> Self {
        let mls = cparams.min_match.clamp(3, 6);
        let hash_log3 = if mls == 3 {
            HASHLOG3_MAX.min(cparams.window_log)
        } else {
            0
        };
        OptCtx {
            hash_table: vec![0u32; 1usize << cparams.hash_log],
            bt: vec![0u32; 1usize << cparams.chain_log],
            hash3: if hash_log3 > 0 {
                vec![0u32; 1usize << hash_log3]
            } else {
                Vec::new()
            },
            hash_log3,
            next_to_update: WINDOW_START_INDEX,
            base_bias: WINDOW_START_INDEX,
            dict_limit: WINDOW_START_INDEX,
            low_limit: WINDOW_START_INDEX,
            dict_bias: WINDOW_START_INDEX,
            opt_level: if cparams.strategy == Strategy::Btopt {
                0
            } else {
                2
            },
            is_ultra2: cparams.strategy == Strategy::Btultra2,
            mls,
            sufficient_len: cparams.target_length.min(ZSTD_OPT_NUM as u32 - 1),
            search_log: cparams.search_log,
            window_log: cparams.window_log,
            hash_log: cparams.hash_log,
            chain_log: cparams.chain_log,
            lit_freq: vec![0u32; MAX_LIT + 1],
            ll_freq: vec![0u32; MAX_LL + 1],
            ml_freq: vec![0u32; MAX_ML + 1],
            of_freq: vec![0u32; MAX_OFF + 1],
            lit_sum: 0,
            ll_sum: 0,
            ml_sum: 0,
            of_sum: 0,
            lit_sum_base: 0,
            ll_sum_base: 0,
            ml_sum_base: 0,
            of_sum_base: 0,
            price_predef: false,
            opt: vec![Optimal::default(); ZSTD_OPT_SIZE],
            matches: vec![Match::default(); ZSTD_OPT_SIZE],
        }
    }

    /// `ZSTD_getLowestMatchIndex(ms, curr, windowLog)`.
    fn window_low(&self, curr: u32) -> u32 {
        let lowest_valid = self.low_limit as u32;
        let max_distance = 1u32 << self.window_log;
        if curr - lowest_valid > max_distance {
            curr - max_distance
        } else {
            lowest_valid
        }
    }
}

// --- Price model -----------------------------------------------------------------

/// `ZSTD_setBasePrices` (literals always compressed at these levels).
fn set_base_prices(ctx: &mut OptCtx) {
    ctx.lit_sum_base = weight(ctx.lit_sum, ctx.opt_level);
    ctx.ll_sum_base = weight(ctx.ll_sum, ctx.opt_level);
    ctx.ml_sum_base = weight(ctx.ml_sum, ctx.opt_level);
    ctx.of_sum_base = weight(ctx.of_sum, ctx.opt_level);
}

/// `ZSTD_downscaleStats`.
fn downscale_stats(table: &mut [u32], shift: u32, base1: bool) -> u32 {
    let mut sum = 0u32;
    for v in table.iter_mut() {
        let base = if base1 { 1 } else { (*v > 0) as u32 };
        let new_stat = base + (*v >> shift);
        sum += new_stat;
        *v = new_stat;
    }
    sum
}

/// `ZSTD_scaleStats`.
fn scale_stats(table: &mut [u32], log_target: u32) -> u32 {
    let prevsum: u32 = table.iter().sum();
    let factor = prevsum >> log_target;
    if factor <= 1 {
        return prevsum;
    }
    downscale_stats(table, highbit32(factor), true)
}

/// `ZSTD_rescaleFreqs` (no-dictionary paths).
fn rescale_freqs(ctx: &mut OptCtx, block: &[u8]) {
    ctx.price_predef = false;
    if ctx.ll_sum == 0 {
        // First block: init.
        if block.len() <= ZSTD_PREDEF_THRESHOLD {
            ctx.price_predef = true;
        }
        // (No dictionary: the huf-repeat seeding branch is unreachable here —
        // a fresh frame starts with repeatMode none.)
        let mut lit_hist = [0u32; MAX_LIT + 1];
        for &b in block {
            lit_hist[b as usize] += 1;
        }
        ctx.lit_freq.copy_from_slice(&lit_hist);
        ctx.lit_sum = downscale_stats(&mut ctx.lit_freq, 8, false);

        #[rustfmt::skip]
        const BASE_LL_FREQS: [u32; MAX_LL + 1] = [
            4, 2, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1,
        ];
        ctx.ll_freq.copy_from_slice(&BASE_LL_FREQS);
        ctx.ll_sum = BASE_LL_FREQS.iter().sum();

        ctx.ml_freq.fill(1);
        ctx.ml_sum = (MAX_ML + 1) as u32;

        #[rustfmt::skip]
        const BASE_OF_FREQS: [u32; MAX_OFF + 1] = [
            6, 2, 1, 1, 2, 3, 4, 4,
            4, 3, 2, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1,
        ];
        ctx.of_freq.copy_from_slice(&BASE_OF_FREQS);
        ctx.of_sum = BASE_OF_FREQS.iter().sum();
    } else {
        // New block: scale down accumulated statistics.
        ctx.lit_sum = scale_stats(&mut ctx.lit_freq, 12);
        ctx.ll_sum = scale_stats(&mut ctx.ll_freq, 11);
        ctx.ml_sum = scale_stats(&mut ctx.ml_freq, 11);
        ctx.of_sum = scale_stats(&mut ctx.of_freq, 11);
    }
    set_base_prices(ctx);
}

/// `ZSTD_rawLiteralsCost` for a single literal (`LIT_PRICE`).
fn lit_price(ctx: &OptCtx, byte: u8) -> i32 {
    if ctx.price_predef {
        return (6 * BITCOST_MULTIPLIER) as i32;
    }
    let lit_price_max = ctx.lit_sum_base - BITCOST_MULTIPLIER;
    let mut p = weight(ctx.lit_freq[byte as usize], ctx.opt_level);
    if p > lit_price_max {
        p = lit_price_max;
    }
    (ctx.lit_sum_base - p) as i32
}

/// `ZSTD_litLengthPrice` (`LL_PRICE`).
fn ll_price(ctx: &OptCtx, lit_length: u32) -> i32 {
    if ctx.price_predef {
        return weight(lit_length, ctx.opt_level) as i32;
    }
    if lit_length == 128 * 1024 {
        return BITCOST_MULTIPLIER as i32 + ll_price(ctx, 128 * 1024 - 1);
    }
    let code = ll_code(lit_length) as usize;
    (LL_BITS[code] * BITCOST_MULTIPLIER + ctx.ll_sum_base) as i32
        - weight(ctx.ll_freq[code], ctx.opt_level) as i32
}

/// `LL_INCPRICE`.
fn ll_incprice(ctx: &OptCtx, lit_length: u32) -> i32 {
    ll_price(ctx, lit_length) - ll_price(ctx, lit_length - 1)
}

/// `ZSTD_getMatchPrice`.
fn get_match_price(ctx: &OptCtx, off_base: u32, match_length: u32) -> i32 {
    let off_code = highbit32(off_base);
    let ml_base = match_length - MINMATCH;
    if ctx.price_predef {
        return (weight(ml_base, ctx.opt_level) + (16 + off_code) * BITCOST_MULTIPLIER) as i32;
    }
    let mut price = (off_code * BITCOST_MULTIPLIER + ctx.of_sum_base) as i32
        - weight(ctx.of_freq[off_code as usize], ctx.opt_level) as i32;
    if ctx.opt_level < 2 && off_code >= 20 {
        price += ((off_code - 19) * 2 * BITCOST_MULTIPLIER) as i32;
    }
    let mlc = ml_code(ml_base) as usize;
    price += (ML_BITS[mlc] * BITCOST_MULTIPLIER + ctx.ml_sum_base) as i32
        - weight(ctx.ml_freq[mlc], ctx.opt_level) as i32;
    price += (BITCOST_MULTIPLIER / 5) as i32;
    price
}

/// `ZSTD_updateStats`.
fn update_stats(
    ctx: &mut OptCtx,
    lit_length: u32,
    literals: &[u8],
    off_base: u32,
    match_length: u32,
) {
    for &b in &literals[..lit_length as usize] {
        ctx.lit_freq[b as usize] += ZSTD_LITFREQ_ADD;
    }
    ctx.lit_sum += lit_length * ZSTD_LITFREQ_ADD;
    let llc = ll_code(lit_length) as usize;
    ctx.ll_freq[llc] += 1;
    ctx.ll_sum += 1;
    let ofc = highbit32(off_base) as usize;
    ctx.of_freq[ofc] += 1;
    ctx.of_sum += 1;
    let mlc = ml_code(match_length - MINMATCH) as usize;
    ctx.ml_freq[mlc] += 1;
    ctx.ml_sum += 1;
}

// --- Binary tree -----------------------------------------------------------------

/// `ZSTD_insertAndFindFirstIndexHash3`.
fn insert_and_find_first_index_hash3(
    ctx: &mut OptCtx,
    data: &[u8],
    next_to_update3: &mut usize,
    ip: usize,
) -> u32 {
    let to_pos = |idx: usize, bias: usize| idx - bias;
    let bias = ctx.base_bias;
    let mut idx = *next_to_update3;
    while idx < ip {
        let h = hash3_ptr(data, to_pos(idx, bias), ctx.hash_log3);
        ctx.hash3[h] = idx as u32;
        idx += 1;
    }
    *next_to_update3 = ip;
    ctx.hash3[hash3_ptr(data, to_pos(ip, bias), ctx.hash_log3)]
}

/// `ZSTD_insertBt1` (noDict and extDict): insert one position, returning how
/// many positions the update may skip forward. extDict candidate compares
/// resolve their segment by `matchIndex + matchLength >= dictLimit`, with
/// the C "preparation" rebase of the ordering-byte read across the seam.
fn insert_bt1(
    ctx: &mut OptCtx,
    data: &[u8],
    ip: usize,
    iend: usize,
    target: usize,
    ext_dict: bool,
) -> usize {
    let bias = ctx.base_bias;
    let to_pos = |idx: usize| idx - bias;
    let dict_limit = ctx.dict_limit;
    let dict_bias = ctx.dict_bias;
    let h = hash_ptr(data, to_pos(ip), ctx.hash_log, ctx.mls);
    let bt_mask = (1u32 << (ctx.chain_log - 1)) - 1;
    let mut match_index = ctx.hash_table[h];
    let mut common_length_smaller = 0usize;
    let mut common_length_larger = 0usize;
    let curr = ip as u32;
    let bt_low = curr.saturating_sub(bt_mask);
    let root = 2 * (curr & bt_mask) as usize;
    let mut smaller_slot: Option<usize> = Some(root);
    let mut larger_slot: Option<usize> = Some(root + 1);
    // windowLow is based on target: only positions valid at the end of the
    // tree update matter.
    let window_low = ctx.window_low(target as u32);
    let mut match_end_idx = curr + 8 + 1;
    let mut best_length = 8usize;
    let mut nb_compares = 1u32 << ctx.search_log;

    ctx.hash_table[h] = curr;

    while nb_compares > 0 && match_index >= window_low {
        let next = 2 * (match_index & bt_mask) as usize;
        let mut match_length = common_length_smaller.min(common_length_larger);
        let m = match_index as usize;

        // Position of `match[matchLength]` for the ordering byte, valid
        // after the count inside each branch.
        let m_read_pos = if !ext_dict || m + match_length >= dict_limit {
            match_length += count_eq(
                data,
                to_pos(ip) + match_length,
                m + match_length - bias,
                to_pos(iend),
            );
            m + match_length - bias
        } else {
            let m_pos = m - dict_bias;
            match_length += count_2segments(
                data,
                to_pos(ip) + match_length,
                m_pos + match_length,
                to_pos(iend),
                dict_limit - dict_bias,
                dict_limit - bias,
            );
            // Preparation for the next read of match[matchLength].
            if m + match_length >= dict_limit {
                m + match_length - bias
            } else {
                m_pos + match_length
            }
        };

        if match_length > best_length {
            best_length = match_length;
            if match_length > (match_end_idx - match_index) as usize {
                match_end_idx = match_index + match_length as u32;
            }
        }

        if ip + match_length == iend {
            break; // drop, to guarantee consistency
        }

        if data[m_read_pos] < data[to_pos(ip) + match_length] {
            if let Some(s) = smaller_slot {
                ctx.bt[s] = match_index;
            }
            common_length_smaller = match_length;
            if match_index <= bt_low {
                smaller_slot = None;
                break;
            }
            smaller_slot = Some(next + 1);
            match_index = ctx.bt[next + 1];
        } else {
            if let Some(l) = larger_slot {
                ctx.bt[l] = match_index;
            }
            common_length_larger = match_length;
            if match_index <= bt_low {
                larger_slot = None;
                break;
            }
            larger_slot = Some(next);
            match_index = ctx.bt[next];
        }
        nb_compares -= 1;
    }

    if let Some(s) = smaller_slot {
        ctx.bt[s] = 0;
    }
    if let Some(l) = larger_slot {
        ctx.bt[l] = 0;
    }

    let positions = if best_length > 384 {
        192.min(best_length - 384)
    } else {
        0
    };
    positions.max((match_end_idx - (curr + 8)) as usize)
}

/// `ZSTD_updateTree_internal`.
fn update_tree(ctx: &mut OptCtx, data: &[u8], ip: usize, iend: usize, ext_dict: bool) {
    let target = ip;
    let mut idx = ctx.next_to_update;
    while idx < target {
        let forward = insert_bt1(ctx, data, idx, iend, target, ext_dict);
        idx += forward;
    }
    ctx.next_to_update = target;
}

/// `ZSTD_insertBtAndGetAllMatches` (noDict and extDict). Returns the number
/// of matches stored in `ctx.matches`, in strictly increasing length order.
#[allow(clippy::too_many_arguments)]
fn insert_bt_and_get_all_matches(
    ctx: &mut OptCtx,
    data: &[u8],
    next_to_update3: &mut usize,
    ip: usize,
    iend: usize,
    rep: &[u32; 3],
    ll0: bool,
    length_to_beat: u32,
    ext_dict: bool,
) -> usize {
    let bias = ctx.base_bias;
    let to_pos = |idx: usize| idx - bias;
    let dict_bias = ctx.dict_bias;
    let sufficient_len = ctx.sufficient_len;
    let curr = ip as u32;
    let min_match = if ctx.mls == 3 { 3 } else { 4 };
    let h = hash_ptr(data, to_pos(ip), ctx.hash_log, ctx.mls);
    let bt_mask = (1u32 << (ctx.chain_log - 1)) - 1;
    let mut match_index = ctx.hash_table[h];
    let mut common_length_smaller = 0usize;
    let mut common_length_larger = 0usize;
    let dict_limit = ctx.dict_limit as u32;
    let bt_low = curr.saturating_sub(bt_mask);
    let window_low = ctx.window_low(curr);
    let match_low = window_low.max(1);
    let root = 2 * (curr & bt_mask) as usize;
    let mut smaller_slot: Option<usize> = Some(root);
    let mut larger_slot: Option<usize> = Some(root + 1);
    let mut match_end_idx = curr + 8 + 1;
    let mut mnum = 0usize;
    let mut nb_compares = 1u32 << ctx.search_log;

    let mut best_length = (length_to_beat - 1) as usize;

    // Check repcodes (speculative history).
    let last_r = 3 + ll0 as u32;
    let mut rep_code = ll0 as u32;
    while rep_code < last_r {
        let rep_offset = if rep_code == 3 {
            rep[0] - 1
        } else {
            rep[rep_code as usize]
        };
        let mut rep_len = 0usize;
        // `repOffset - 1 < curr - dictLimit` with intentional wrapping:
        // discards 0 and overlong offsets (`curr > repIndex >= dictLimit`).
        if rep_offset.wrapping_sub(1) < curr - dict_limit {
            let rep_index = curr - rep_offset;
            if rep_index >= window_low
                && read_minmatch(data, to_pos(ip), min_match)
                    == read_minmatch(data, to_pos(ip) - rep_offset as usize, min_match)
            {
                rep_len = count_eq(
                    data,
                    to_pos(ip) + min_match as usize,
                    to_pos(ip) + min_match as usize - rep_offset as usize,
                    to_pos(iend),
                ) + min_match as usize;
            }
        } else if ext_dict {
            // repIndex < dictLimit (or >= curr): the repcode source lives in
            // the extDict; validity also demands the 4-byte read stays below
            // the seam (`ZSTD_index_overlap_check`).
            let rep_index = curr.wrapping_sub(rep_offset);
            if rep_offset.wrapping_sub(1) < curr - window_low
                && (dict_limit - 1).wrapping_sub(rep_index) >= 3
                && read_minmatch(data, to_pos(ip), min_match)
                    == read_minmatch(data, rep_index as usize - dict_bias, min_match)
            {
                rep_len = count_2segments(
                    data,
                    to_pos(ip) + min_match as usize,
                    rep_index as usize - dict_bias + min_match as usize,
                    to_pos(iend),
                    dict_limit as usize - dict_bias,
                    dict_limit as usize - bias,
                ) + min_match as usize;
            }
        }
        if rep_len > best_length {
            best_length = rep_len;
            ctx.matches[mnum] = Match {
                off: rep_code - ll0 as u32 + 1,
                len: rep_len as u32,
            };
            mnum += 1;
            if rep_len as u32 > sufficient_len || ip + rep_len == iend {
                return mnum; // best possible: early exit
            }
        }
        rep_code += 1;
    }

    // HC3 match finder (only when nothing >= 3 found yet).
    if ctx.mls == 3 && best_length < 3 {
        let match_index3 = insert_and_find_first_index_hash3(ctx, data, next_to_update3, ip);
        if match_index3 >= match_low && curr - match_index3 < (1 << 18) {
            let mlen = if !ext_dict || match_index3 >= dict_limit {
                count_eq(
                    data,
                    to_pos(ip),
                    to_pos(match_index3 as usize),
                    to_pos(iend),
                )
            } else {
                count_2segments(
                    data,
                    to_pos(ip),
                    match_index3 as usize - dict_bias,
                    to_pos(iend),
                    dict_limit as usize - dict_bias,
                    dict_limit as usize - bias,
                )
            };
            if mlen >= 3 {
                best_length = mlen;
                ctx.matches[0] = Match {
                    off: (curr - match_index3) + 3,
                    len: mlen as u32,
                };
                mnum = 1;
                if mlen as u32 > sufficient_len || ip + mlen == iend {
                    ctx.next_to_update = curr as usize + 1; // skip insertion
                    return 1;
                }
            }
        }
    }

    ctx.hash_table[h] = curr;

    while nb_compares > 0 && match_index >= match_low {
        let next = 2 * (match_index & bt_mask) as usize;
        let mut match_length = common_length_smaller.min(common_length_larger);
        let m = match_index as usize;

        // Position of `match[matchLength]` for the ordering byte, valid
        // after the count inside each branch.
        let m_read_pos = if !ext_dict || m + match_length >= dict_limit as usize {
            match_length += count_eq(
                data,
                to_pos(ip) + match_length,
                m + match_length - bias,
                to_pos(iend),
            );
            m + match_length - bias
        } else {
            let m_pos = m - dict_bias;
            match_length += count_2segments(
                data,
                to_pos(ip) + match_length,
                m_pos + match_length,
                to_pos(iend),
                dict_limit as usize - dict_bias,
                dict_limit as usize - bias,
            );
            // Preparation for the next read of match[matchLength].
            if m + match_length >= dict_limit as usize {
                m + match_length - bias
            } else {
                m_pos + match_length
            }
        };

        if match_length > best_length {
            if match_length > (match_end_idx - match_index) as usize {
                match_end_idx = match_index + match_length as u32;
            }
            best_length = match_length;
            ctx.matches[mnum] = Match {
                off: (curr - match_index) + 3,
                len: match_length as u32,
            };
            mnum += 1;
            if match_length > ZSTD_OPT_NUM || ip + match_length == iend {
                break; // drop, to preserve bt consistency
            }
        }

        if data[m_read_pos] < data[to_pos(ip) + match_length] {
            if let Some(s) = smaller_slot {
                ctx.bt[s] = match_index;
            }
            common_length_smaller = match_length;
            if match_index <= bt_low {
                smaller_slot = None;
                break;
            }
            smaller_slot = Some(next + 1);
            match_index = ctx.bt[next + 1];
        } else {
            if let Some(l) = larger_slot {
                ctx.bt[l] = match_index;
            }
            common_length_larger = match_length;
            if match_index <= bt_low {
                larger_slot = None;
                break;
            }
            larger_slot = Some(next);
            match_index = ctx.bt[next];
        }
        nb_compares -= 1;
    }

    if let Some(s) = smaller_slot {
        ctx.bt[s] = 0;
    }
    if let Some(l) = larger_slot {
        ctx.bt[l] = 0;
    }

    ctx.next_to_update = (match_end_idx - 8) as usize; // skip repetitive patterns
    mnum
}

/// `ZSTD_btGetAllMatches_internal`.
#[allow(clippy::too_many_arguments)]
fn get_all_matches(
    ctx: &mut OptCtx,
    data: &[u8],
    next_to_update3: &mut usize,
    ip: usize,
    iend: usize,
    rep: &[u32; 3],
    ll0: bool,
    length_to_beat: u32,
    ext_dict: bool,
) -> usize {
    if ip < ctx.next_to_update {
        return 0; // skipped area
    }
    update_tree(ctx, data, ip, iend, ext_dict);
    insert_bt_and_get_all_matches(
        ctx,
        data,
        next_to_update3,
        ip,
        iend,
        rep,
        ll0,
        length_to_beat,
        ext_dict,
    )
}

// --- The optimal parser ---------------------------------------------------------

/// `ZSTD_compressBlock_btultra2`'s first-block stats-seeding double pass.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compress_block_opt(
    ctx: &mut OptCtx,
    store: &mut SeqStore,
    rep: &mut [u32; 3],
    data: &[u8],
    block_start: usize,
    block_end: usize,
    win: &mut Window,
    ext_dict: bool,
) -> usize {
    // Snapshot the window geometry (the C code reads `ms->window` directly).
    ctx.base_bias = win.seg_bias as usize;
    ctx.dict_limit = win.dict_limit as usize;
    ctx.low_limit = win.low_limit as usize;
    ctx.dict_bias = win.dict_bias as usize;

    let src_size = block_end - block_start;
    let curr = block_start + ctx.base_bias;
    // `ZSTD_compressBlock_btultra2` (a noDict-only entry point: extDict
    // blocks of the btultra2 strategy run `ZSTD_compressBlock_btultra_extDict`
    // per the `ZSTD_selectBlockCompressor` table, with no stats pass).
    if !ext_dict
        && ctx.is_ultra2
        && ctx.ll_sum == 0
        && store.sequences.is_empty()
        && win.dict_limit == win.low_limit
        && curr == ctx.dict_limit
        && src_size > ZSTD_PREDEF_THRESHOLD
    {
        // ZSTD_initStats_ultra: pass 1 into throwaway outputs, then forget
        // match history (slide the index space past this block) but keep the
        // entropy statistics.
        let mut tmp_rep = *rep;
        let mut tmp_store = SeqStore::new();
        compress_block_opt_generic(
            ctx,
            &mut tmp_store,
            &mut tmp_rep,
            data,
            block_start,
            block_end,
            false,
        );
        win.slide_for_init_stats(src_size);
        ctx.base_bias = win.seg_bias as usize;
        ctx.dict_limit = win.dict_limit as usize;
        ctx.low_limit = win.low_limit as usize;
        ctx.next_to_update = ctx.dict_limit;
    }
    compress_block_opt_generic(ctx, store, rep, data, block_start, block_end, ext_dict)
}

/// `ZSTD_compressBlock_opt_generic`. The driver itself is dictMode-agnostic
/// (it only prices and emits within the current block); the dict mode lives
/// in the match finder.
fn compress_block_opt_generic(
    ctx: &mut OptCtx,
    store: &mut SeqStore,
    rep: &mut [u32; 3],
    data: &[u8],
    block_start: usize,
    block_end: usize,
    ext_dict: bool,
) -> usize {
    let bias = ctx.base_bias;
    let to_pos = |idx: usize| idx - bias;
    let istart = block_start + bias;
    let iend = block_end + bias;
    let src_size = block_end - block_start;
    let i_limit: i64 = iend as i64 - 8;
    let prefix_start = ctx.dict_limit;
    let sufficient_len = ctx.sufficient_len as usize;
    let min_match = if ctx.mls == 3 { 3u32 } else { 4 };
    let opt_level = ctx.opt_level;
    let mut next_to_update3 = ctx.next_to_update;

    let mut ip = istart;
    let mut anchor = istart;

    rescale_freqs(ctx, &data[to_pos(istart)..to_pos(iend)]);
    let _ = src_size;
    ip += (ip == prefix_start) as usize;

    while (ip as i64) < i_limit {
        let mut last_stretch = Optimal::default();
        let mut cur: u32 = 0;
        let mut last_pos: u32 = 0;

        // Labeled block standing in for the C `goto _shortestPath`.
        let found = 'forward: {
            let litlen = (ip - anchor) as u32;
            let ll0 = litlen == 0;
            let nb_matches = get_all_matches(
                ctx,
                data,
                &mut next_to_update3,
                ip,
                iend,
                rep,
                ll0,
                min_match,
                ext_dict,
            );
            if nb_matches == 0 {
                ip += 1;
                break 'forward false;
            }

            // Initialize opt[0].
            ctx.opt[0].mlen = 0;
            ctx.opt[0].litlen = litlen;
            ctx.opt[0].price = ll_price(ctx, litlen);
            ctx.opt[0].rep = *rep;

            // Large match -> immediate encoding.
            {
                let max_ml = ctx.matches[nb_matches - 1].len;
                let max_off = ctx.matches[nb_matches - 1].off;
                if max_ml as usize > sufficient_len {
                    last_stretch.litlen = 0;
                    last_stretch.mlen = max_ml;
                    last_stretch.off = max_off;
                    cur = 0;
                    last_pos = max_ml;
                    break 'forward true;
                }
            }

            // Set prices for first matches at position 0.
            {
                let mut pos = 1u32;
                while pos < min_match {
                    ctx.opt[pos as usize].price = ZSTD_MAX_PRICE;
                    ctx.opt[pos as usize].mlen = 0;
                    ctx.opt[pos as usize].litlen = litlen + pos;
                    pos += 1;
                }
                for match_nb in 0..nb_matches {
                    let off_base = ctx.matches[match_nb].off;
                    let end = ctx.matches[match_nb].len;
                    while pos <= end {
                        let match_price = get_match_price(ctx, off_base, pos);
                        let sequence_price = ctx.opt[0].price + match_price;
                        ctx.opt[pos as usize].mlen = pos;
                        ctx.opt[pos as usize].off = off_base;
                        ctx.opt[pos as usize].litlen = 0;
                        ctx.opt[pos as usize].price = sequence_price + ll_price(ctx, 0);
                        pos += 1;
                    }
                }
                last_pos = pos - 1;
                ctx.opt[pos as usize].price = ZSTD_MAX_PRICE;
            }

            // Check further positions.
            cur = 1;
            let mut went_to_shortest = false;
            while cur <= last_pos {
                let inr = ip + cur as usize;

                // Fix current position with one literal if cheaper.
                {
                    let litlen = ctx.opt[cur as usize - 1].litlen + 1;
                    let price = ctx.opt[cur as usize - 1].price
                        + lit_price(ctx, data[to_pos(ip + cur as usize - 1)])
                        + ll_incprice(ctx, litlen);
                    if price <= ctx.opt[cur as usize].price {
                        let prev_match = ctx.opt[cur as usize];
                        ctx.opt[cur as usize] = ctx.opt[cur as usize - 1];
                        ctx.opt[cur as usize].litlen = litlen;
                        ctx.opt[cur as usize].price = price;
                        if opt_level >= 1
                            && prev_match.litlen == 0
                            && ll_incprice(ctx, 1) < 0
                            && ip + (cur as usize) < iend
                        {
                            let with1literal = prev_match.price
                                + lit_price(ctx, data[to_pos(ip + cur as usize)])
                                + ll_incprice(ctx, 1);
                            let with_more = price
                                + lit_price(ctx, data[to_pos(ip + cur as usize)])
                                + ll_incprice(ctx, litlen + 1);
                            if with1literal < with_more
                                && with1literal < ctx.opt[cur as usize + 1].price
                            {
                                let prev = cur - prev_match.mlen;
                                let new_reps = new_rep(
                                    ctx.opt[prev as usize].rep,
                                    prev_match.off,
                                    ctx.opt[prev as usize].litlen == 0,
                                );
                                ctx.opt[cur as usize + 1] = prev_match;
                                ctx.opt[cur as usize + 1].rep = new_reps;
                                ctx.opt[cur as usize + 1].litlen = 1;
                                ctx.opt[cur as usize + 1].price = with1literal;
                                if last_pos < cur + 1 {
                                    last_pos = cur + 1;
                                }
                            }
                        }
                    }
                }

                // Offset history materializes once the position is settled.
                if ctx.opt[cur as usize].litlen == 0 {
                    let prev = cur - ctx.opt[cur as usize].mlen;
                    let new_reps = new_rep(
                        ctx.opt[prev as usize].rep,
                        ctx.opt[cur as usize].off,
                        ctx.opt[prev as usize].litlen == 0,
                    );
                    ctx.opt[cur as usize].rep = new_reps;
                }

                // Last match must start at a minimum distance of 8 from oend.
                if (inr as i64) > i_limit {
                    cur += 1;
                    continue;
                }
                if cur == last_pos {
                    break;
                }
                if opt_level == 0
                    && ctx.opt[cur as usize + 1].price
                        <= ctx.opt[cur as usize].price + (BITCOST_MULTIPLIER / 2) as i32
                {
                    cur += 1;
                    continue; // skip unpromising positions
                }

                {
                    let ll0 = ctx.opt[cur as usize].litlen == 0;
                    let base_price = ctx.opt[cur as usize].price + ll_price(ctx, 0);
                    let opt_rep = ctx.opt[cur as usize].rep;
                    let nb_matches = get_all_matches(
                        ctx,
                        data,
                        &mut next_to_update3,
                        inr,
                        iend,
                        &opt_rep,
                        ll0,
                        min_match,
                        ext_dict,
                    );
                    if nb_matches == 0 {
                        cur += 1;
                        continue;
                    }

                    {
                        let longest_ml = ctx.matches[nb_matches - 1].len;
                        if longest_ml as usize > sufficient_len
                            || cur as usize + longest_ml as usize >= ZSTD_OPT_NUM
                            || (ip + cur as usize + longest_ml as usize) >= iend
                        {
                            last_stretch.mlen = longest_ml;
                            last_stretch.off = ctx.matches[nb_matches - 1].off;
                            last_stretch.litlen = 0;
                            last_pos = cur + longest_ml;
                            went_to_shortest = true;
                            break;
                        }
                    }

                    // Set prices using matches found at position cur.
                    for match_nb in 0..nb_matches {
                        let offset = ctx.matches[match_nb].off;
                        let last_ml = ctx.matches[match_nb].len;
                        let start_ml = if match_nb > 0 {
                            ctx.matches[match_nb - 1].len + 1
                        } else {
                            min_match
                        };
                        let mut mlen = last_ml;
                        while mlen >= start_ml {
                            let pos = cur + mlen;
                            let price = base_price + get_match_price(ctx, offset, mlen);
                            if pos > last_pos || price < ctx.opt[pos as usize].price {
                                while last_pos < pos {
                                    last_pos += 1;
                                    ctx.opt[last_pos as usize].price = ZSTD_MAX_PRICE;
                                    ctx.opt[last_pos as usize].litlen = 1; // != 0: not an end of match
                                }
                                ctx.opt[pos as usize].mlen = mlen;
                                ctx.opt[pos as usize].off = offset;
                                ctx.opt[pos as usize].litlen = 0;
                                ctx.opt[pos as usize].price = price;
                            } else if opt_level == 0 {
                                break; // early update abort
                            }
                            mlen -= 1;
                        }
                    }
                }
                ctx.opt[last_pos as usize + 1].price = ZSTD_MAX_PRICE;
                cur += 1;
            }

            if !went_to_shortest {
                last_stretch = ctx.opt[last_pos as usize];
                cur = last_pos - last_stretch.mlen;
            }
            break 'forward true;
        };

        if !found {
            continue;
        }

        // _shortestPath:
        if last_stretch.mlen == 0 {
            // No solution: all matches were converted into literals.
            ip += last_pos as usize;
            continue;
        }

        // Update offset history.
        if last_stretch.litlen == 0 {
            let reps = new_rep(
                ctx.opt[cur as usize].rep,
                last_stretch.off,
                ctx.opt[cur as usize].litlen == 0,
            );
            *rep = reps;
        } else {
            *rep = last_stretch.rep;
            cur -= last_stretch.litlen;
        }

        // Reverse traversal: convert stretches into sequences. Note: the
        // 1.5.7 source's `lastStretch.litlen > 0` branch here is dead code
        // (`} {`, not `} else {`), so only the unconditional form survives.
        {
            let store_end = cur as usize + 2;
            ctx.opt[store_end] = last_stretch;
            let mut store_start = store_end;
            let mut stretch_pos = cur as usize;

            loop {
                let next_stretch = ctx.opt[stretch_pos];
                ctx.opt[store_start].litlen = next_stretch.litlen;
                if next_stretch.mlen == 0 {
                    break; // reached beginning of segment
                }
                store_start -= 1;
                ctx.opt[store_start] = next_stretch;
                stretch_pos -= (next_stretch.litlen + next_stretch.mlen) as usize;
            }

            // Save sequences.
            for store_pos in store_start..=store_end {
                let llen = ctx.opt[store_pos].litlen;
                let mlen = ctx.opt[store_pos].mlen;
                let off_base = ctx.opt[store_pos].off;

                if mlen == 0 {
                    // Only literals: last "sequence" starts a new stream.
                    ip = anchor + llen as usize;
                    continue;
                }
                let lit_slice = &data[to_pos(anchor)..to_pos(anchor) + llen as usize];
                update_stats_then_store(ctx, store, llen, lit_slice, off_base, mlen);
                anchor += (llen + mlen) as usize;
                ip = anchor;
            }
            set_base_prices(ctx);
        }
    }

    to_pos(iend) - to_pos(anchor)
}

/// updateStats + storeSeq, split out to satisfy the borrow checker.
fn update_stats_then_store(
    ctx: &mut OptCtx,
    store: &mut SeqStore,
    llen: u32,
    literals: &[u8],
    off_base: u32,
    mlen: u32,
) {
    update_stats(ctx, llen, literals, off_base, mlen);
    store.store_seq(literals, off_base, mlen);
}
