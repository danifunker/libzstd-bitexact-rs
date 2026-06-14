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
use crate::huffman_encode::HufRepeat;
use crate::sequences_encode::{FseEntropyState, SeqStore, ll_code, ml_code};

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
    /// `ms->loadedDictEnd` (see [`crate::compress::Window`]): nonzero keeps the
    /// whole loaded dictionary referenceable in [`window_low`](Self::window_low).
    loaded_dict_end: u32,

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

    /// `ZSTD_reduceIndex` for the bt-opt strategies: the hash table, the
    /// binary tree (no unsorted mark — that is btlazy2's), and the 3-byte
    /// hash table when present. `nextToUpdate` shifts with the indices.
    pub(crate) fn reduce_indices(&mut self, correction: u32) {
        crate::compress::reduce_table(&mut self.hash_table, correction, false);
        crate::compress::reduce_table(&mut self.bt, correction, false);
        if self.hash_log3 > 0 {
            crate::compress::reduce_table(&mut self.hash3, correction, false);
        }
        self.next_to_update = self.next_to_update.saturating_sub(correction as usize);
    }

    /// `ZSTD_loadDictionaryContent`'s bt* branch for the optimal parser: seed
    /// the binary tree from the raw dictionary `data[0..dict_len]`. The dict is
    /// loaded as the current segment (noDict), so the window fields a fresh
    /// `OptCtx` left at `WINDOW_START_INDEX` are already the right state, and
    /// `update_tree`'s `window_low` resolves to `lowLimit` (the C `isDictionary`
    /// case). C fills a FULLY SORTED tree via `ZSTD_updateTree(ms, dictEnd -
    /// HASH_READ_SIZE, dictEnd)` (`ZSTD_insertBt1`, `ZSTD_noDict`) — the same
    /// fill btlazy2 uses; the 3-byte hash table is NOT seeded (`insertBt1` never
    /// touches it). `nextToUpdate` then jumps to `dictEnd`. The caller guarantees
    /// `dict_len > HASH_READ_SIZE` and a fresh context.
    pub(crate) fn load_dictionary(&mut self, data: &[u8], dict_len: usize) {
        const HASH_READ_SIZE: usize = 8;
        let fill_target = WINDOW_START_INDEX + dict_len - HASH_READ_SIZE;
        let iend = WINDOW_START_INDEX + dict_len;
        update_tree(self, data, fill_target, iend, false);
        self.next_to_update = WINDOW_START_INDEX + dict_len;
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
            loaded_dict_end: 0,
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

    /// `ZSTD_getLowestMatchIndex(ms, curr, windowLog)`. A loaded dictionary
    /// (`loadedDictEnd != 0`) stays referenceable down to `lowLimit`.
    fn window_low(&self, curr: u32) -> u32 {
        let lowest_valid = self.low_limit as u32;
        if self.loaded_dict_end != 0 {
            return lowest_valid;
        }
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

/// `ZSTD_rescaleFreqs`. `symbol_costs` is the first block's `prevCBlock`
/// entropy (`optPtr->symbolCosts`); when its Huffman table came from a
/// dictionary (`HUF_repeat_valid`) the first-block statistics are derived from
/// those tables instead of the raw histogram + base frequencies.
fn rescale_freqs(ctx: &mut OptCtx, block: &[u8], symbol_costs: Option<&FseEntropyState>) {
    ctx.price_predef = false;
    if ctx.ll_sum == 0 {
        // First block: init.
        if block.len() <= ZSTD_PREDEF_THRESHOLD {
            ctx.price_predef = true;
        }

        // A dictionary whose literals Huffman table spans the full value set is
        // presumed to carry representative statistics: derive the cost model
        // from the seeded tables (and force dynamic pricing).
        let dict_costs =
            symbol_costs.filter(|sc| sc.huf.repeat == HufRepeat::Valid && sc.huf.table.is_some());
        if let Some(sc) = dict_costs {
            ctx.price_predef = false;
            // Literals: `1 << (11 - nbBits)`, scaled to 2K (`HUF_getNbBitsFromCTable`).
            let huf = sc.huf.table.as_ref().unwrap();
            ctx.lit_sum = 0;
            for lit in 0..=MAX_LIT {
                let bit_cost = huf.nb_bits_of(lit as u32);
                ctx.lit_freq[lit] = if bit_cost != 0 {
                    1u32 << (11 - bit_cost)
                } else {
                    1
                };
                ctx.lit_sum += ctx.lit_freq[lit];
            }
            // The three sequence components: `1 << (10 - maxNbBits)`, scaled to
            // 1K (`FSE_getMaxNbBits`); a zero cost (symbol absent / past the
            // table) keeps the minimum frequency of 1.
            let seed_fse =
                |freq: &mut [u32], ct: &crate::fse_encode::FseCTable, max: usize| -> u32 {
                    let mut sum = 0u32;
                    for (s, slot) in freq.iter_mut().enumerate().take(max + 1) {
                        let bit_cost = ct.max_nb_bits(s as u32);
                        *slot = if bit_cost != 0 {
                            1u32 << (10 - bit_cost)
                        } else {
                            1
                        };
                        sum += *slot;
                    }
                    sum
                };
            ctx.ll_sum = seed_fse(&mut ctx.ll_freq, sc.ll.as_ref().unwrap(), MAX_LL);
            ctx.ml_sum = seed_fse(&mut ctx.ml_freq, sc.ml.as_ref().unwrap(), MAX_ML);
            ctx.of_sum = seed_fse(&mut ctx.of_freq, sc.of.as_ref().unwrap(), MAX_OFF);
        } else {
            // First block, no dictionary: literals from the raw histogram, the
            // sequence components from C's base frequency tables.
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
        }
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

/// An attached CDict's optimal-parser match state (`ms->dictMatchState`) for the
/// dictMatchState arm. In the concatenated `content ++ src` buffer the dict
/// occupies indices `[WINDOW_START_INDEX, WINDOW_START_INDEX + content_len)`, so
/// `dmsIndexDelta == 0` and a dict index maps to a position like the working
/// context's (`pos = index - WINDOW_START_INDEX`).
pub(crate) struct OptDms<'a> {
    pub(crate) ms: &'a OptCtx,
    pub(crate) content_len: usize,
}

/// `ZSTD_insertBtAndGetAllMatches` (noDict, extDict, and dictMatchState).
/// Returns the number of matches stored in `ctx.matches`, in strictly
/// increasing length order. `dms` (the attached CDict) is mutually exclusive
/// with `ext_dict`.
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
    dms: Option<&OptDms>,
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
        } else if let Some(att) = dms {
            // repIndex reaches into the attached dict. dmsLowLimit +
            // dmsIndexDelta == WINDOW_START_INDEX (concat delta 0); the repMatch
            // lives at `repIndex - WINDOW_START_INDEX`.
            let rep_index = curr.wrapping_sub(rep_offset);
            if rep_offset.wrapping_sub(1) < curr - WINDOW_START_INDEX as u32
                && (dict_limit - 1).wrapping_sub(rep_index) >= 3
                && read_minmatch(data, to_pos(ip), min_match)
                    == read_minmatch(data, rep_index as usize - WINDOW_START_INDEX, min_match)
            {
                rep_len = count_2segments(
                    data,
                    to_pos(ip) + min_match as usize,
                    (rep_index as usize - WINDOW_START_INDEX) + min_match as usize,
                    to_pos(iend),
                    att.content_len, // dmsEnd position
                    att.content_len, // prefixStart position (= src start)
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
                // dictMatchState: a break should also skip searching the dms.
                if dms.is_some() {
                    nb_compares = 0;
                }
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

    // `ZSTD_insertBtAndGetAllMatches` dictMatchState arm: descend the attached
    // CDict's own (fully sorted) binary tree with the compares left over. Concat
    // buffer ⇒ dmsIndexDelta == 0, so a dict index is a working index directly
    // and the post-seam match-pointer rebase is a no-op. Read-only on the dms.
    if nb_compares > 0 {
        if let Some(att) = dms {
            let d = att.ms;
            let dms_high_limit = (WINDOW_START_INDEX + att.content_len) as u32; // dmsSize
            let dms_low_limit = WINDOW_START_INDEX as u32; // dms.window.lowLimit
            let dms_bt_mask = (1u32 << (d.chain_log - 1)) - 1;
            let dms_bt_low = if dms_bt_mask < dms_high_limit - dms_low_limit {
                dms_high_limit - dms_bt_mask
            } else {
                dms_low_limit
            };
            let dms_h = hash_ptr(data, to_pos(ip), d.hash_log, ctx.mls);
            let mut dict_match_index = d.hash_table[dms_h];
            let mut common_smaller = 0usize;
            let mut common_larger = 0usize;
            while nb_compares > 0 && dict_match_index > dms_low_limit {
                let next = 2 * (dict_match_index & dms_bt_mask) as usize;
                let mut match_length = common_smaller.min(common_larger);
                let m_pos = dict_match_index as usize - WINDOW_START_INDEX;
                match_length += count_2segments(
                    data,
                    to_pos(ip) + match_length,
                    m_pos + match_length,
                    to_pos(iend),
                    att.content_len, // dmsEnd position
                    att.content_len, // prefixStart position
                );
                if match_length > best_length {
                    let match_index = dict_match_index; // + dmsIndexDelta (0)
                    if match_length > (match_end_idx - match_index) as usize {
                        match_end_idx = match_index + match_length as u32;
                    }
                    best_length = match_length;
                    ctx.matches[mnum] = Match {
                        off: (curr - match_index) + 3, // OFFSET_TO_OFFBASE
                        len: match_length as u32,
                    };
                    mnum += 1;
                    if match_length > ZSTD_OPT_NUM || ip + match_length == iend {
                        break;
                    }
                }
                if dict_match_index <= dms_bt_low {
                    break;
                }
                if data[m_pos + match_length] < data[to_pos(ip) + match_length] {
                    common_smaller = match_length;
                    dict_match_index = d.bt[next + 1];
                } else {
                    common_larger = match_length;
                    dict_match_index = d.bt[next];
                }
                nb_compares -= 1;
            }
        }
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
    dms: Option<&OptDms>,
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
        dms,
    )
}

// --- LDM candidate plumbing -------------------------------------------------------

/// `ZSTD_optLdm_t`: a cursor over the block's LDM raw sequences. The C code
/// copies the rawSeqStore *by value* into this struct, so every opt pass
/// (including the btultra2 stats pass) walks its own cursor from the start.
struct OptLdm<'a> {
    seqs: &'a [crate::ldm::RawSeq],
    pos: usize,
    pos_in_sequence: usize,
    start_pos_in_block: u32,
    end_pos_in_block: u32,
    offset: u32,
}

impl OptLdm<'_> {
    /// `ZSTD_optLdm_skipRawSeqStoreBytes`.
    fn skip_bytes(&mut self, nb_bytes: usize) {
        let mut curr_pos = (self.pos_in_sequence + nb_bytes) as u32;
        while curr_pos > 0 && self.pos < self.seqs.len() {
            let curr_seq = self.seqs[self.pos];
            if curr_pos >= curr_seq.lit_length + curr_seq.match_length {
                curr_pos -= curr_seq.lit_length + curr_seq.match_length;
                self.pos += 1;
            } else {
                self.pos_in_sequence = curr_pos as usize;
                break;
            }
        }
        if curr_pos == 0 || self.pos == self.seqs.len() {
            self.pos_in_sequence = 0;
        }
    }

    /// `ZSTD_opt_getNextMatchAndUpdateSeqStore`: compute the block-relative
    /// span of the next LDM match and advance the cursor past it.
    fn get_next_match(&mut self, curr_pos_in_block: u32, block_bytes_remaining: u32) {
        // No more matches in this block: never offer an LDM candidate again.
        if self.seqs.is_empty() || self.pos >= self.seqs.len() {
            self.start_pos_in_block = u32::MAX;
            self.end_pos_in_block = u32::MAX;
            return;
        }
        let curr_seq = self.seqs[self.pos];
        let curr_block_end_pos = curr_pos_in_block + block_bytes_remaining;
        // `(posInSequence < litLength) ? litLength - posInSequence : 0`.
        let literals_bytes_remaining = curr_seq
            .lit_length
            .saturating_sub(self.pos_in_sequence as u32);
        let match_bytes_remaining = if literals_bytes_remaining == 0 {
            curr_seq.match_length - (self.pos_in_sequence as u32 - curr_seq.lit_length)
        } else {
            curr_seq.match_length
        };

        // More literal bytes than bytes remaining in the block: no LDM here.
        if literals_bytes_remaining >= block_bytes_remaining {
            self.start_pos_in_block = u32::MAX;
            self.end_pos_in_block = u32::MAX;
            self.skip_bytes(block_bytes_remaining as usize);
            return;
        }

        self.start_pos_in_block = curr_pos_in_block + literals_bytes_remaining;
        self.end_pos_in_block = self.start_pos_in_block + match_bytes_remaining;
        self.offset = curr_seq.offset;

        if self.end_pos_in_block > curr_block_end_pos {
            // Match ends after the block does: use only the part within it.
            self.end_pos_in_block = curr_block_end_pos;
            self.skip_bytes((curr_block_end_pos - curr_pos_in_block) as usize);
        } else {
            self.skip_bytes((literals_bytes_remaining + match_bytes_remaining) as usize);
        }
    }
}

/// `ZSTD_optLdm_maybeAddMatch`: append the LDM candidate to `ctx.matches` if
/// it is longer than the current longest (preserving the length ordering).
fn opt_ldm_maybe_add_match(
    ctx: &mut OptCtx,
    nb_matches: &mut usize,
    opt_ldm: &OptLdm,
    curr_pos_in_block: u32,
    min_match: u32,
) {
    let pos_diff = curr_pos_in_block.wrapping_sub(opt_ldm.start_pos_in_block);
    let candidate_match_length = opt_ldm
        .end_pos_in_block
        .wrapping_sub(opt_ldm.start_pos_in_block)
        .wrapping_sub(pos_diff);

    // The current block position must lie inside the match.
    if curr_pos_in_block < opt_ldm.start_pos_in_block
        || curr_pos_in_block >= opt_ldm.end_pos_in_block
        || candidate_match_length < min_match
    {
        return;
    }

    if *nb_matches == 0
        || (candidate_match_length > ctx.matches[*nb_matches - 1].len && *nb_matches < ZSTD_OPT_NUM)
    {
        ctx.matches[*nb_matches] = Match {
            off: opt_ldm.offset + 3, // OFFSET_TO_OFFBASE
            len: candidate_match_length,
        };
        *nb_matches += 1;
    }
}

/// `ZSTD_optLdm_processMatchCandidate`.
fn opt_ldm_process_match_candidate(
    ctx: &mut OptCtx,
    opt_ldm: &mut OptLdm,
    nb_matches: &mut usize,
    curr_pos_in_block: u32,
    remaining_bytes: u32,
    min_match: u32,
) {
    if opt_ldm.seqs.is_empty() || opt_ldm.pos >= opt_ldm.seqs.len() {
        return;
    }

    if curr_pos_in_block >= opt_ldm.end_pos_in_block {
        if curr_pos_in_block > opt_ldm.end_pos_in_block {
            // Correct for "overshoots": this is not necessarily called at
            // the exact end of the previous LDM match.
            let pos_overshoot = curr_pos_in_block - opt_ldm.end_pos_in_block;
            opt_ldm.skip_bytes(pos_overshoot as usize);
        }
        opt_ldm.get_next_match(curr_pos_in_block, remaining_bytes);
    }
    opt_ldm_maybe_add_match(ctx, nb_matches, opt_ldm, curr_pos_in_block, min_match);
}

/// A persistent cursor into a pre-generated `rawSeqStore` (`{pos, posInSequence}`),
/// carried across the blocks of one ZSTDMT job — C's `zc->externSeqStore`. The
/// serial LDM state generates one `Vec<RawSeq>` per job **segment**; each block's
/// opt parse reads the cursor *read-only* (a by-value copy, so the btultra2 double
/// pass starts both passes from the same position), and after the block the driver
/// advances the cursor by the whole block size via [`skip_bytes`](Self::skip_bytes)
/// (`ZSTD_ldm_blockCompress` calls `ZSTD_ldm_skipRawSeqStoreBytes(rawSeqStore,
/// srcSize)`). Single-threaded LDM instead generates block-local sequences and
/// uses a fresh `(0, 0)` per block, so it always passes [`LdmCursor::default`].
#[derive(Clone, Copy, Default)]
pub(crate) struct LdmCursor {
    pos: usize,
    pos_in_sequence: usize,
}

impl LdmCursor {
    /// `ZSTD_ldm_skipRawSeqStoreBytes` (zstd_ldm.c:664): advance past `nb_bytes`
    /// of the segment (called per block with the block size).
    pub(crate) fn skip_bytes(&mut self, seqs: &[crate::ldm::RawSeq], nb_bytes: usize) {
        let mut curr_pos = (self.pos_in_sequence + nb_bytes) as u32;
        while curr_pos > 0 && self.pos < seqs.len() {
            let seq = seqs[self.pos];
            if curr_pos >= seq.lit_length + seq.match_length {
                curr_pos -= seq.lit_length + seq.match_length;
                self.pos += 1;
            } else {
                self.pos_in_sequence = curr_pos as usize;
                break;
            }
        }
        if curr_pos == 0 || self.pos == seqs.len() {
            self.pos_in_sequence = 0;
        }
    }
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
    ldm_seqs: Option<&[crate::ldm::RawSeq]>,
    ldm_cursor: LdmCursor,
    symbol_costs: Option<&FseEntropyState>,
    dms: Option<&OptDms>,
) -> usize {
    // Snapshot the window geometry (the C code reads `ms->window` directly).
    ctx.base_bias = win.seg_bias as usize;
    ctx.dict_limit = win.dict_limit as usize;
    ctx.low_limit = win.low_limit as usize;
    ctx.dict_bias = win.dict_bias as usize;
    ctx.loaded_dict_end = win.loaded_dict_end;

    let src_size = block_end - block_start;
    let curr = block_start + ctx.base_bias;
    // `ZSTD_compressBlock_btultra2` (a noDict-only entry point: extDict and
    // dictMatchState blocks of the btultra2 strategy run
    // `ZSTD_compressBlock_btultra_{extDict,dictMatchState}` per the
    // `ZSTD_selectBlockCompressor` table, with no stats pass).
    if !ext_dict
        && dms.is_none()
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
            ldm_seqs,
            ldm_cursor,
            symbol_costs,
            dms,
        );
        win.slide_for_init_stats(src_size);
        ctx.base_bias = win.seg_bias as usize;
        ctx.dict_limit = win.dict_limit as usize;
        ctx.low_limit = win.low_limit as usize;
        ctx.loaded_dict_end = win.loaded_dict_end;
        ctx.next_to_update = ctx.dict_limit;
    }
    compress_block_opt_generic(
        ctx,
        store,
        rep,
        data,
        block_start,
        block_end,
        ext_dict,
        ldm_seqs,
        ldm_cursor,
        symbol_costs,
        dms,
    )
}

/// `ZSTD_compressBlock_opt_generic`. The driver itself is dictMode-agnostic
/// (it only prices and emits within the current block); the dict mode lives
/// in the match finder.
#[allow(clippy::too_many_arguments)]
fn compress_block_opt_generic(
    ctx: &mut OptCtx,
    store: &mut SeqStore,
    rep: &mut [u32; 3],
    data: &[u8],
    block_start: usize,
    block_end: usize,
    ext_dict: bool,
    ldm_seqs: Option<&[crate::ldm::RawSeq]>,
    ldm_cursor: LdmCursor,
    symbol_costs: Option<&FseEntropyState>,
    dms: Option<&OptDms>,
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

    // The LDM candidate cursor (a by-value copy of the raw store in C, so
    // this pass owns its walk); primed before the prefix-start skip, i.e.
    // at block position 0 with the whole block remaining.
    let mut opt_ldm = OptLdm {
        seqs: ldm_seqs.unwrap_or(&[]),
        pos: ldm_cursor.pos,
        pos_in_sequence: ldm_cursor.pos_in_sequence,
        start_pos_in_block: 0,
        end_pos_in_block: 0,
        offset: 0,
    };
    opt_ldm.get_next_match(0, src_size as u32);

    rescale_freqs(ctx, &data[to_pos(istart)..to_pos(iend)], symbol_costs);
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
            let mut nb_matches = get_all_matches(
                ctx,
                data,
                &mut next_to_update3,
                ip,
                iend,
                rep,
                ll0,
                min_match,
                ext_dict,
                dms,
            );
            opt_ldm_process_match_candidate(
                ctx,
                &mut opt_ldm,
                &mut nb_matches,
                (ip - istart) as u32,
                (iend - ip) as u32,
                min_match,
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
                    let mut nb_matches = get_all_matches(
                        ctx,
                        data,
                        &mut next_to_update3,
                        inr,
                        iend,
                        &opt_rep,
                        ll0,
                        min_match,
                        ext_dict,
                        dms,
                    );
                    opt_ldm_process_match_candidate(
                        ctx,
                        &mut opt_ldm,
                        &mut nb_matches,
                        (inr - istart) as u32,
                        (iend - inr) as u32,
                        min_match,
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
