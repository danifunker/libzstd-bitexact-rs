//! The lazy match-finding framework (`zstd_lazy.c`, noDict paths): the shared
//! driver `ZSTD_compressBlock_lazy_generic` at depths 0/1/2 (greedy / lazy /
//! lazy2, levels 5-12) over two search backends:
//!
//! * the **hash-chain** finder (`ZSTD_HcFindBestMatch`), used when the row
//!   finder is disabled (`windowLog <= 14` after adjustment), and
//! * the **row-based** finder (`ZSTD_RowFindBestMatch`), a tag-table design
//!   whose SIMD paths are pure accelerators — the scalar form here produces
//!   identical match choices, byte-for-byte.
//!
//! Row hashing is salted. For a fresh one-shot context the salt is the fixed
//! constant `bitmix(0,8) ^ bitmix(0,4)` (a zeroed `ZSTD_CCtx` advanced once by
//! `ZSTD_advanceHashSalt`), which is what `ZSTD_compress` uses — reproduced
//! exactly here.

use crate::compress::{CParams, Strategy, count_eq, hash_ptr, read32, read64};
use crate::sequences_encode::SeqStore;

const WINDOW_START_INDEX: usize = 2;
const K_SEARCH_STRENGTH: u32 = 8;
const K_LAZY_SKIPPING_STEP: usize = 8;

const ROW_HASH_TAG_BITS: u32 = 8;
const ROW_HASH_TAG_MASK: u32 = (1 << ROW_HASH_TAG_BITS) - 1;
const ROW_HASH_CACHE_SIZE: usize = 8;
const ROW_HASH_CACHE_MASK: usize = ROW_HASH_CACHE_SIZE - 1;
const ROW_HASH_MAX_ENTRIES: usize = 64;

fn highbit32(x: u32) -> u32 {
    debug_assert!(x >= 1);
    31 - x.leading_zeros()
}

/// `ZSTD_bitmix` (XXH3_rrmxmx-based).
fn bitmix(mut val: u64, len: u64) -> u64 {
    val ^= val.rotate_right(49) ^ val.rotate_right(24);
    val = val.wrapping_mul(0x9FB2_1C65_1E98_DF25);
    val ^= (val >> 35).wrapping_add(len);
    val = val.wrapping_mul(0x9FB2_1C65_1E98_DF25);
    val ^ (val >> 28)
}

/// `ZSTD_hashPtrSalted` for `mls` in 4..=6 (the lazy framework's range): the
/// salt is XORed in after the multiply, before the final shift.
fn hash_ptr_salted(data: &[u8], at: usize, hbits: u32, mls: u32, salt: u64) -> usize {
    const PRIME4: u32 = 2654435761;
    const PRIME5: u64 = 889523592379;
    const PRIME6: u64 = 227718039650203;
    match mls {
        5 => {
            ((((read64(data, at) << (64 - 40)).wrapping_mul(PRIME5)) ^ salt) >> (64 - hbits))
                as usize
        }
        6 => {
            ((((read64(data, at) << (64 - 48)).wrapping_mul(PRIME6)) ^ salt) >> (64 - hbits))
                as usize
        }
        _ => (((read32(data, at).wrapping_mul(PRIME4)) ^ (salt as u32)) >> (32 - hbits)) as usize,
    }
}

/// `ZSTD_resolveRowMatchFinderMode` (auto): row finder for greedy..=lazy2 once
/// the (adjusted) window log exceeds 14.
pub(crate) fn use_row_match_finder(cparams: &CParams) -> bool {
    matches!(
        cparams.strategy,
        Strategy::Greedy | Strategy::Lazy | Strategy::Lazy2
    ) && cparams.window_log > 14
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum SearchMethod {
    HashChain,
    RowHash,
}

/// The lazy matcher's cross-block state (`ZSTD_MatchState_t` subset).
pub(crate) struct LazyCtx {
    method: SearchMethod,
    depth: u32,
    hash_table: Vec<u32>,
    /// Hash-chain only.
    chain_table: Vec<u32>,
    /// Row only: one tag byte per hash-table entry; entry 0 of each row is the
    /// circular head.
    tag_table: Vec<u8>,
    hash_cache: [u32; ROW_HASH_CACHE_SIZE],
    /// Biased index of the next position to insert (starts at 2).
    next_to_update: usize,
    lazy_skipping: bool,
    hash_salt: u64,
    row_hash_log: u32,
    row_log: u32,
    mls: u32,
    hash_log: u32,
    chain_log: u32,
    search_log: u32,
    window_log: u32,
}

impl LazyCtx {
    pub(crate) fn new(cparams: &CParams) -> Self {
        let method = if use_row_match_finder(cparams) {
            SearchMethod::RowHash
        } else {
            SearchMethod::HashChain
        };
        let depth = match cparams.strategy {
            Strategy::Lazy => 1,
            Strategy::Lazy2 => 2,
            _ => 0, // greedy
        };
        let row_log = cparams.search_log.clamp(4, 6);
        LazyCtx {
            method,
            depth,
            hash_table: vec![0u32; 1usize << cparams.hash_log],
            chain_table: if method == SearchMethod::HashChain {
                vec![0u32; 1usize << cparams.chain_log]
            } else {
                Vec::new()
            },
            tag_table: if method == SearchMethod::RowHash {
                vec![0u8; 1usize << cparams.hash_log]
            } else {
                Vec::new()
            },
            hash_cache: [0u32; ROW_HASH_CACHE_SIZE],
            next_to_update: WINDOW_START_INDEX,
            lazy_skipping: false,
            // ZSTD_advanceHashSalt on a zeroed CCtx (one-shot ZSTD_compress).
            hash_salt: bitmix(0, 8) ^ bitmix(0, 4),
            row_hash_log: cparams.hash_log - row_log,
            row_log,
            mls: cparams.min_match.clamp(4, 6),
            hash_log: cparams.hash_log,
            chain_log: cparams.chain_log,
            search_log: cparams.search_log,
            window_log: cparams.window_log,
        }
    }
}

// --- Hash-chain search -------------------------------------------------------

/// `ZSTD_insertAndFindFirstIndex_internal`: insert positions up to `target`
/// (one position only in lazy-skipping mode) and return the hash head for the
/// target position. All indices biased.
fn insert_and_find_first_index(ctx: &mut LazyCtx, data: &[u8], target: usize) -> u32 {
    let chain_mask = (1u32 << ctx.chain_log) - 1;
    let mut idx = ctx.next_to_update;
    while idx < target {
        let h = hash_ptr(data, idx - WINDOW_START_INDEX, ctx.hash_log, ctx.mls);
        ctx.chain_table[(idx as u32 & chain_mask) as usize] = ctx.hash_table[h];
        ctx.hash_table[h] = idx as u32;
        idx += 1;
        if ctx.lazy_skipping {
            break;
        }
    }
    ctx.next_to_update = target;
    ctx.hash_table[hash_ptr(data, target - WINDOW_START_INDEX, ctx.hash_log, ctx.mls)]
}

/// `ZSTD_HcFindBestMatch` (noDict): walk the chain from the hash head, keeping
/// the longest match. Writes `off_base` only when a better-than-3 match is
/// saved, exactly like the C `offsetPtr` contract.
fn hc_find_best_match(
    ctx: &mut LazyCtx,
    data: &[u8],
    ip: usize,
    iend: usize,
    off_base: &mut u64,
) -> usize {
    let to_pos = |idx: usize| idx - WINDOW_START_INDEX;
    let chain_size = 1u32 << ctx.chain_log;
    let chain_mask = chain_size - 1;
    let curr = ip as u32;
    let max_distance = 1u32 << ctx.window_log;
    let lowest_valid = WINDOW_START_INDEX as u32;
    let within_max_distance = if curr - lowest_valid > max_distance {
        curr - max_distance
    } else {
        lowest_valid
    };
    let low_limit = within_max_distance;
    let min_chain = curr.saturating_sub(chain_size);
    let mut nb_attempts = 1u32 << ctx.search_log;
    let mut ml: usize = 4 - 1;

    let mut match_index = insert_and_find_first_index(ctx, data, ip);

    while match_index >= low_limit && nb_attempts > 0 {
        let m = match_index as usize;
        // Quick filter: 4 bytes ending at the current best length.
        if read32(data, to_pos(m) + ml - 3) == read32(data, to_pos(ip) + ml - 3) {
            let current_ml = count_eq(data, to_pos(ip), to_pos(m), to_pos(iend));
            if current_ml > ml {
                ml = current_ml;
                *off_base = (curr - match_index) as u64 + 3; // OFFSET_TO_OFFBASE
                if ip + current_ml == iend {
                    break; // best possible
                }
            }
        }
        if match_index <= min_chain {
            break;
        }
        match_index = ctx.chain_table[(match_index & chain_mask) as usize];
        nb_attempts -= 1;
    }
    ml
}

// --- Row-based search ----------------------------------------------------------

/// `ZSTD_row_nextIndex`: cycle the row head backwards through [1, entries),
/// skipping slot 0 (which stores the head itself).
fn row_next_index(tag_row_head: &mut u8, row_mask: u32) -> usize {
    let mut next = (*tag_row_head as u32).wrapping_sub(1) & row_mask;
    if next == 0 {
        next = row_mask;
    }
    *tag_row_head = next as u8;
    next as usize
}

/// `ZSTD_row_fillHashCache`: precompute hashes for the next positions, bounded
/// by `i_limit` (a biased index, possibly negative for tiny blocks).
fn row_fill_hash_cache(ctx: &mut LazyCtx, data: &[u8], mut idx: usize, i_limit: i64) {
    let max_elems = if (idx as i64) > i_limit {
        0
    } else {
        (i_limit - idx as i64 + 1) as usize
    };
    let lim = idx + ROW_HASH_CACHE_SIZE.min(max_elems);
    while idx < lim {
        let hash = hash_ptr_salted(
            data,
            idx - WINDOW_START_INDEX,
            ctx.row_hash_log + ROW_HASH_TAG_BITS,
            ctx.mls,
            ctx.hash_salt,
        ) as u32;
        ctx.hash_cache[idx & ROW_HASH_CACHE_MASK] = hash;
        idx += 1;
    }
}

/// `ZSTD_row_nextCachedHash`: take the cached hash for `idx`, replacing it
/// with the hash of `idx + CACHE_SIZE`.
fn row_next_cached_hash(ctx: &mut LazyCtx, data: &[u8], idx: usize) -> u32 {
    let new_hash = hash_ptr_salted(
        data,
        idx + ROW_HASH_CACHE_SIZE - WINDOW_START_INDEX,
        ctx.row_hash_log + ROW_HASH_TAG_BITS,
        ctx.mls,
        ctx.hash_salt,
    ) as u32;
    let hash = ctx.hash_cache[idx & ROW_HASH_CACHE_MASK];
    ctx.hash_cache[idx & ROW_HASH_CACHE_MASK] = new_hash;
    hash
}

/// `ZSTD_row_update_internalImpl`: insert positions [start, end).
fn row_update_impl(ctx: &mut LazyCtx, data: &[u8], mut start: usize, end: usize, use_cache: bool) {
    let row_mask = (1u32 << ctx.row_log) - 1;
    while start < end {
        let hash = if use_cache {
            row_next_cached_hash(ctx, data, start)
        } else {
            hash_ptr_salted(
                data,
                start - WINDOW_START_INDEX,
                ctx.row_hash_log + ROW_HASH_TAG_BITS,
                ctx.mls,
                ctx.hash_salt,
            ) as u32
        };
        let rel_row = ((hash >> ROW_HASH_TAG_BITS) << ctx.row_log) as usize;
        let pos = {
            let head = &mut ctx.tag_table[rel_row];
            row_next_index(head, row_mask)
        };
        ctx.tag_table[rel_row + pos] = (hash & ROW_HASH_TAG_MASK) as u8;
        ctx.hash_table[rel_row + pos] = start as u32;
        start += 1;
    }
}

/// `ZSTD_row_update_internal`: catch up insertions to `target`, skipping the
/// bulk of very long gaps (the 384/96/32 rule).
fn row_update_internal(ctx: &mut LazyCtx, data: &[u8], target: usize, use_cache: bool) {
    const K_SKIP_THRESHOLD: usize = 384;
    const K_MAX_START: usize = 96;
    const K_MAX_END: usize = 32;
    let mut idx = ctx.next_to_update;

    if use_cache && target - idx > K_SKIP_THRESHOLD {
        let bound = idx + K_MAX_START;
        row_update_impl(ctx, data, idx, bound, use_cache);
        idx = target - K_MAX_END;
        // C passes `ip + 1` as the iLimit pointer here.
        row_fill_hash_cache(ctx, data, idx, (target + 1) as i64);
    }
    row_update_impl(ctx, data, idx, target, use_cache);
    ctx.next_to_update = target;
}

/// Scalar `ZSTD_row_getMatchMask` (groupWidth 1): bit `i` set when entry `i`'s
/// tag equals `tag`, rotated right by `head` within the row width.
fn row_get_match_mask(tag_row: &[u8], tag: u8, head: u32, row_entries: u32) -> u64 {
    let mut bits: u64 = 0;
    for (i, &t) in tag_row.iter().enumerate().take(row_entries as usize) {
        bits |= ((t == tag) as u64) << i;
    }
    // Rotate right by `head` within row_entries bits.
    if head == 0 {
        bits
    } else {
        let w = row_entries;
        ((bits >> head) | (bits << (w - head))) & (u64::MAX >> (64 - w))
    }
}

/// `ZSTD_RowFindBestMatch` (noDict).
fn row_find_best_match(
    ctx: &mut LazyCtx,
    data: &[u8],
    ip: usize,
    iend: usize,
    off_base: &mut u64,
) -> usize {
    let to_pos = |idx: usize| idx - WINDOW_START_INDEX;
    let curr = ip as u32;
    let max_distance = 1u32 << ctx.window_log;
    let lowest_valid = WINDOW_START_INDEX as u32;
    let within_max_distance = if curr - lowest_valid > max_distance {
        curr - max_distance
    } else {
        lowest_valid
    };
    let low_limit = within_max_distance;
    let row_entries = 1u32 << ctx.row_log;
    let row_mask = row_entries - 1;
    let capped_search_log = ctx.search_log.min(ctx.row_log);
    let mut nb_attempts = 1u32 << capped_search_log;
    let mut ml: usize = 4 - 1;

    // Update tables up to ip (cached) and fetch ip's hash.
    let hash: u32;
    if !ctx.lazy_skipping {
        row_update_internal(ctx, data, ip, true);
        hash = row_next_cached_hash(ctx, data, ip);
    } else {
        hash = hash_ptr_salted(
            data,
            to_pos(ip),
            ctx.row_hash_log + ROW_HASH_TAG_BITS,
            ctx.mls,
            ctx.hash_salt,
        ) as u32;
        ctx.next_to_update = ip;
    }

    let rel_row = ((hash >> ROW_HASH_TAG_BITS) << ctx.row_log) as usize;
    let tag = hash & ROW_HASH_TAG_MASK;
    let head = ctx.tag_table[rel_row] as u32 & row_mask;

    let mut match_buffer = [0u32; ROW_HASH_MAX_ENTRIES];
    let mut num_matches = 0usize;
    let mut matches = row_get_match_mask(
        &ctx.tag_table[rel_row..rel_row + row_entries as usize],
        tag as u8,
        head,
        row_entries,
    );

    while matches > 0 && nb_attempts > 0 {
        let match_pos = ((head + matches.trailing_zeros()) & row_mask) as usize;
        matches &= matches - 1;
        if match_pos == 0 {
            continue;
        }
        let match_index = ctx.hash_table[rel_row + match_pos];
        if match_index < low_limit {
            break;
        }
        match_buffer[num_matches] = match_index;
        num_matches += 1;
        nb_attempts -= 1;
    }

    // Insert the current position (speed opt mirrored from C: row[pos] is
    // nextToUpdate, which equals ip here, then advances past it).
    {
        let pos = {
            let head_byte = &mut ctx.tag_table[rel_row];
            row_next_index(head_byte, row_mask)
        };
        ctx.tag_table[rel_row + pos] = tag as u8;
        ctx.hash_table[rel_row + pos] = ctx.next_to_update as u32;
        ctx.next_to_update += 1;
    }

    for &match_index in &match_buffer[..num_matches] {
        let m = match_index as usize;
        // Quick filter: 4 bytes ending at the current best length.
        if read32(data, to_pos(m) + ml - 3) == read32(data, to_pos(ip) + ml - 3) {
            let current_ml = count_eq(data, to_pos(ip), to_pos(m), to_pos(iend));
            if current_ml > ml {
                ml = current_ml;
                *off_base = (curr - match_index) as u64 + 3;
                if ip + current_ml == iend {
                    break;
                }
            }
        }
    }
    ml
}

/// `ZSTD_searchMax`.
fn search_max(ctx: &mut LazyCtx, data: &[u8], ip: usize, iend: usize, off_base: &mut u64) -> usize {
    match ctx.method {
        SearchMethod::HashChain => hc_find_best_match(ctx, data, ip, iend, off_base),
        SearchMethod::RowHash => row_find_best_match(ctx, data, ip, iend, off_base),
    }
}

// --- The lazy driver -------------------------------------------------------------

/// `ZSTD_compressBlock_lazy_generic` (noDict), depths 0..=2. Same conventions
/// as the fast/dfast ports: biased indices, sequences into `store`, returns
/// the trailing-literals size.
pub(crate) fn compress_block_lazy(
    ctx: &mut LazyCtx,
    store: &mut SeqStore,
    rep: &mut [u32; 3],
    data: &[u8],
    block_start: usize,
    block_end: usize,
) -> usize {
    let to_pos = |idx: usize| idx - WINDOW_START_INDEX;
    let bias = WINDOW_START_INDEX;
    let istart = block_start + bias;
    let iend = block_end + bias;
    let i_limit: i64 = iend as i64
        - 8
        - if ctx.method == SearchMethod::RowHash {
            ROW_HASH_CACHE_SIZE as i64
        } else {
            0
        };
    let prefix_lowest = WINDOW_START_INDEX; // window.dictLimit (noDict)
    let depth = ctx.depth;

    let mut ip = istart;
    let mut anchor = istart;
    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];
    let mut offset_saved1 = 0u32;
    let mut offset_saved2 = 0u32;

    ip += (ip - prefix_lowest == 0) as usize;
    {
        let curr = ip as u32;
        let max_distance = 1u32 << ctx.window_log;
        let window_low = if curr - (prefix_lowest as u32) > max_distance {
            curr - max_distance
        } else {
            prefix_lowest as u32
        };
        let max_rep = curr - window_low;
        if offset_2 > max_rep {
            offset_saved2 = offset_2;
            offset_2 = 0;
        }
        if offset_1 > max_rep {
            offset_saved1 = offset_1;
            offset_1 = 0;
        }
    }

    ctx.lazy_skipping = false;
    if ctx.method == SearchMethod::RowHash {
        let from = ctx.next_to_update;
        row_fill_hash_cache(ctx, data, from, i_limit);
    }

    while (ip as i64) < i_limit {
        let mut match_length = 0usize;
        let mut off_base: u64 = 1; // REPCODE1_TO_OFFBASE
        let mut start = ip + 1;

        // Check repcode at ip+1.
        if offset_1 > 0
            && read32(data, to_pos(ip + 1 - offset_1 as usize)) == read32(data, to_pos(ip + 1))
        {
            match_length = count_eq(
                data,
                to_pos(ip + 1) + 4,
                to_pos(ip + 1 - offset_1 as usize) + 4,
                to_pos(iend),
            ) + 4;
            if depth == 0 {
                // goto _storeSequence
                store_and_repcodes(
                    ctx,
                    store,
                    data,
                    &mut ip,
                    &mut anchor,
                    start,
                    match_length,
                    off_base,
                    &mut offset_1,
                    &mut offset_2,
                    i_limit,
                    iend,
                );
                continue;
            }
        }

        // First search (depth 0).
        {
            let mut offbase_found: u64 = 999_999_999;
            let ml2 = search_max(ctx, data, ip, iend, &mut offbase_found);
            if ml2 > match_length {
                match_length = ml2;
                start = ip;
                off_base = offbase_found;
            }
        }

        if match_length < 4 {
            // Jump faster over incompressible sections.
            let step = ((ip - anchor) >> K_SEARCH_STRENGTH) + 1;
            ip += step;
            ctx.lazy_skipping = step > K_LAZY_SKIPPING_STEP;
            continue;
        }

        // Try to find a better solution.
        if depth >= 1 {
            while (ip as i64) < i_limit {
                ip += 1;
                if offset_1 > 0
                    && read32(data, to_pos(ip)) == read32(data, to_pos(ip - offset_1 as usize))
                {
                    let ml_rep = count_eq(
                        data,
                        to_pos(ip) + 4,
                        to_pos(ip - offset_1 as usize) + 4,
                        to_pos(iend),
                    ) + 4;
                    let gain2 = (ml_rep * 3) as i32;
                    let gain1 = (match_length * 3) as i32 - highbit32(off_base as u32) as i32 + 1;
                    if ml_rep >= 4 && gain2 > gain1 {
                        match_length = ml_rep;
                        off_base = 1;
                        start = ip;
                    }
                }
                {
                    let mut ofb_candidate: u64 = 999_999_999;
                    let ml2 = search_max(ctx, data, ip, iend, &mut ofb_candidate);
                    let gain2 = (ml2 * 4) as i32 - highbit32(ofb_candidate as u32) as i32;
                    let gain1 = (match_length * 4) as i32 - highbit32(off_base as u32) as i32 + 4;
                    if ml2 >= 4 && gain2 > gain1 {
                        match_length = ml2;
                        off_base = ofb_candidate;
                        start = ip;
                        continue; // search a better one
                    }
                }

                // Let's find an even better one.
                if depth == 2 && (ip as i64) < i_limit {
                    ip += 1;
                    if offset_1 > 0
                        && read32(data, to_pos(ip)) == read32(data, to_pos(ip - offset_1 as usize))
                    {
                        let ml_rep = count_eq(
                            data,
                            to_pos(ip) + 4,
                            to_pos(ip - offset_1 as usize) + 4,
                            to_pos(iend),
                        ) + 4;
                        let gain2 = (ml_rep * 4) as i32;
                        let gain1 =
                            (match_length * 4) as i32 - highbit32(off_base as u32) as i32 + 1;
                        if ml_rep >= 4 && gain2 > gain1 {
                            match_length = ml_rep;
                            off_base = 1;
                            start = ip;
                        }
                    }
                    {
                        let mut ofb_candidate: u64 = 999_999_999;
                        let ml2 = search_max(ctx, data, ip, iend, &mut ofb_candidate);
                        let gain2 = (ml2 * 4) as i32 - highbit32(ofb_candidate as u32) as i32;
                        let gain1 =
                            (match_length * 4) as i32 - highbit32(off_base as u32) as i32 + 7;
                        if ml2 >= 4 && gain2 > gain1 {
                            match_length = ml2;
                            off_base = ofb_candidate;
                            start = ip;
                            continue;
                        }
                    }
                }
                break; // nothing found: store previous solution
            }
        }

        // Catch up (real offsets only).
        if off_base > 3 {
            let offset = (off_base - 3) as usize;
            while start > anchor
                && start - offset > prefix_lowest
                && data[to_pos(start) - 1] == data[to_pos(start - offset) - 1]
            {
                start -= 1;
                match_length += 1;
            }
            offset_2 = offset_1;
            offset_1 = offset as u32;
        }

        store_and_repcodes(
            ctx,
            store,
            data,
            &mut ip,
            &mut anchor,
            start,
            match_length,
            off_base,
            &mut offset_1,
            &mut offset_2,
            i_limit,
            iend,
        );
    }

    // Rotate restored offsets exactly as the other matchers do.
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

/// `_storeSequence` + the immediate-repcode tail (noDict), shared by the
/// depth-0 repcode shortcut and the normal store path.
#[allow(clippy::too_many_arguments)]
fn store_and_repcodes(
    ctx: &mut LazyCtx,
    store: &mut SeqStore,
    data: &[u8],
    ip: &mut usize,
    anchor: &mut usize,
    start: usize,
    match_length: usize,
    off_base: u64,
    offset_1: &mut u32,
    offset_2: &mut u32,
    i_limit: i64,
    iend: usize,
) {
    let to_pos = |idx: usize| idx - WINDOW_START_INDEX;
    store.store_seq(
        &data[to_pos(*anchor)..to_pos(start)],
        off_base as u32,
        match_length as u32,
    );
    *ip = start + match_length;
    *anchor = *ip;

    if ctx.lazy_skipping {
        // Found a match: leave skipping mode and refill the row cache.
        if ctx.method == SearchMethod::RowHash {
            let from = ctx.next_to_update;
            row_fill_hash_cache(ctx, data, from, i_limit);
        }
        ctx.lazy_skipping = false;
    }

    // Immediate repcode loop.
    while (*ip as i64) <= i_limit
        && *offset_2 > 0
        && read32(data, to_pos(*ip)) == read32(data, to_pos(*ip - *offset_2 as usize))
    {
        let m_len = count_eq(
            data,
            to_pos(*ip) + 4,
            to_pos(*ip - *offset_2 as usize) + 4,
            to_pos(iend),
        ) + 4;
        std::mem::swap(offset_1, offset_2);
        store.store_seq(&[], 1, m_len as u32);
        *ip += m_len;
        *anchor = *ip;
    }
}
