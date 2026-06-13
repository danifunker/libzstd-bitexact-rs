//! The lazy match-finding framework (`zstd_lazy.c`): the shared drivers
//! `ZSTD_compressBlock_lazy_generic` (noDict) and
//! `ZSTD_compressBlock_lazy_extDict_generic` at depths 0/1/2 (greedy / lazy /
//! lazy2, levels 5-12) over two search backends:
//!
//! * the **hash-chain** finder (`ZSTD_HcFindBestMatch`), used when the row
//!   finder is disabled (`windowLog <= 14` after adjustment), and
//! * the **row-based** finder (`ZSTD_RowFindBestMatch`), a tag-table design
//!   whose SIMD paths are pure accelerators — the scalar form here produces
//!   identical match choices, byte-for-byte.
//!
//! Both backends carry the extDict candidate branch. The hash-chain extDict
//! path is unreachable through plain streaming (hash chains are only selected
//! when `windowLog <= 14`, which needs a small pledged content size, and a
//! stream that small never wraps its input buffer), but dictionary compression
//! reaches it: `compress_with_dict` on a greedy/lazy/lazy2 level whose dict-aware
//! `windowLog` lands at <= 14 (small `dict + src`) runs the hash-chain extDict
//! finder, differential-tested in `tests/dict_compress_differential.rs`.
//!
//! Row hashing is salted. For a fresh one-shot context the salt is the fixed
//! constant `bitmix(0,8) ^ bitmix(0,4)` (a zeroed `ZSTD_CCtx` advanced once by
//! `ZSTD_advanceHashSalt`), which is what `ZSTD_compress` uses — reproduced
//! exactly here.

use crate::compress::{
    CParams, Strategy, Window, count_2segments, count_eq, hash_ptr, index_overlap_check, read32,
    read64,
};
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
    BinaryTree,
}

/// `ZSTD_DUBT_UNSORTED_MARK`: sort-mark sentinel in the BT's second slot.
const DUBT_UNSORTED_MARK: u32 = 1;

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
    /// Biased index of the next position to insert (starts at 2). Reset to
    /// `window.dictLimit` by the frame loop on a non-contiguous chunk
    /// (`ZSTD_compressContinue_internal`).
    pub(crate) next_to_update: usize,
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
        Self::with_row_match_finder(cparams, use_row_match_finder(cparams))
    }

    /// Like [`new`](Self::new) but the row-vs-hash-chain backend is forced
    /// rather than derived from `cparams`. The CDict attach/copy resets
    /// (`ZSTD_resetCCtx_byAttachingCDict` / `…byCopyingCDict`) set the working
    /// context's `useRowMatchFinder` from the **CDict's** (line
    /// `params.useRowMatchFinder = cdict->useRowMatchFinder`), whose own
    /// windowLog decided it — that can differ from what the working cParams'
    /// (input-resized) windowLog would pick. Btlazy2 always uses the binary
    /// tree, ignoring `use_row`.
    pub(crate) fn with_row_match_finder(cparams: &CParams, use_row: bool) -> Self {
        let method = if cparams.strategy == Strategy::Btlazy2 {
            SearchMethod::BinaryTree
        } else if use_row {
            SearchMethod::RowHash
        } else {
            SearchMethod::HashChain
        };
        let depth = match cparams.strategy {
            Strategy::Lazy => 1,
            Strategy::Lazy2 | Strategy::Btlazy2 => 2,
            _ => 0, // greedy
        };
        let row_log = cparams.search_log.clamp(4, 6);
        LazyCtx {
            method,
            depth,
            hash_table: vec![0u32; 1usize << cparams.hash_log],
            chain_table: if method != SearchMethod::RowHash {
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

    /// `ZSTD_buildSeqStore`'s "limited update after a very long match": when
    /// the block starts more than 384 positions past `nextToUpdate` (a long
    /// match ran over the previous block's end), pull `nextToUpdate` to
    /// within 384+192 of the block start instead of catching up over the
    /// whole gap. `curr` is the biased index of the block start.
    pub(crate) fn limit_update(&mut self, curr: usize) {
        if curr > self.next_to_update + 384 {
            self.next_to_update = curr - 192.min(curr - self.next_to_update - 384);
        }
    }

    /// `ZSTD_reduceIndex` for the lazy family: the hash table always, plus the
    /// chain/BT table when one is allocated (hash-chain and binary-tree
    /// backends, not the row finder). btlazy2's BT preserves the unsorted
    /// mark. `nextToUpdate` shifts with the indices.
    pub(crate) fn reduce_indices(&mut self, correction: u32) {
        crate::compress::reduce_table(&mut self.hash_table, correction, false);
        if self.method != SearchMethod::RowHash {
            let preserve_mark = self.method == SearchMethod::BinaryTree;
            crate::compress::reduce_table(&mut self.chain_table, correction, preserve_mark);
        }
        self.next_to_update = self.next_to_update.saturating_sub(correction as usize);
    }

    /// `ZSTD_loadDictionaryContent`'s greedy/lazy/lazy2 branch: seed the match
    /// finder from the raw dictionary `data[0..dict_len]` before `src` is
    /// compressed. The row finder zeroes its tag table (already zero on a fresh
    /// `LazyCtx`) then runs `ZSTD_row_update` (uncached); the hash-chain finder
    /// runs `ZSTD_insertAndFindFirstIndex`. Both insert positions up to
    /// `dictEnd - HASH_READ_SIZE`, after which `nextToUpdate` jumps to `dictEnd`,
    /// so the final `HASH_READ_SIZE` dict positions are never inserted (exactly
    /// as in C). Reusing the very functions the matcher uses keeps the fill and
    /// the search hash-consistent. btlazy2 instead loads a FULLY SORTED tree via
    /// `ZSTD_updateTree` (`ZSTD_insertBt1`, noDict) — not the runtime unsorted
    /// DUBT. Caller guarantees `dict_len > HASH_READ_SIZE` and a fresh context
    /// (`next_to_update == WINDOW_START_INDEX`).
    pub(crate) fn load_dictionary(&mut self, data: &[u8], dict_len: usize) {
        const HASH_READ_SIZE: usize = 8;
        let seg_bias = WINDOW_START_INDEX;
        // Biased index of `dictEnd - HASH_READ_SIZE`, the fill's exclusive upper
        // bound (C passes this pointer to ZSTD_row_update / insertAndFind).
        let fill_target = WINDOW_START_INDEX + dict_len - HASH_READ_SIZE;
        match self.method {
            SearchMethod::RowHash => {
                row_update_internal(self, data, fill_target, false, seg_bias);
            }
            SearchMethod::HashChain => {
                let _ = insert_and_find_first_index(self, data, fill_target, seg_bias);
            }
            SearchMethod::BinaryTree => {
                // btlazy2: C loads the dict into a fully sorted binary tree via
                // ZSTD_updateTree (ZSTD_insertBt1, ZSTD_noDict), NOT the runtime
                // unsorted DUBT. windowLow is lowLimit for the whole fill
                // (isDictionary), i.e. WINDOW_START_INDEX.
                update_tree_nodict(
                    self,
                    data,
                    fill_target,
                    dict_len,
                    seg_bias,
                    WINDOW_START_INDEX as u32,
                );
            }
        }
        // `ms->nextToUpdate = iend - base`: resume insertion at the start of
        // `src`, never re-touching the dict's last few positions.
        self.next_to_update = WINDOW_START_INDEX + dict_len;
    }

    /// Zero the row-hash salt to match a CDict match state. `ZSTD_reset_matchState`
    /// always uses salt 0 when resetting a CDict (`forWho == ZSTD_resetTarget_CDict`),
    /// and `ZSTD_resetCCtx_byCopyingCDict` copies that salt into the working
    /// context. Call before [`load_dictionary`](Self::load_dictionary) so the row
    /// fill hashes with the same (zero) salt the dictMatchState search expects —
    /// the dms row finder reads tags with the *unsalted* `ZSTD_hashPtr`.
    pub(crate) fn use_cdict_hash_salt(&mut self) {
        self.hash_salt = 0;
    }
}

/// An attached CDict's match state (`ms->dictMatchState`) passed to the
/// dictMatchState search arms. In the concatenated `content ++ src` buffer the
/// dict occupies indices `[WINDOW_START_INDEX, WINDOW_START_INDEX + content_len)`,
/// so `dmsIndexDelta == 0` and a dict index maps to a buffer position exactly
/// like the working context's (`pos = index - WINDOW_START_INDEX`).
pub(crate) struct AttachedDict<'a> {
    ms: &'a LazyCtx,
    content_len: usize,
}

// --- Hash-chain search -------------------------------------------------------

/// `ZSTD_insertAndFindFirstIndex_internal`: insert positions up to `target`
/// (one position only in lazy-skipping mode) and return the hash head for the
/// target position. All indices biased; `seg_bias` maps them to positions.
fn insert_and_find_first_index(
    ctx: &mut LazyCtx,
    data: &[u8],
    target: usize,
    seg_bias: usize,
) -> u32 {
    let chain_mask = (1u32 << ctx.chain_log) - 1;
    let mut idx = ctx.next_to_update;
    while idx < target {
        let h = hash_ptr(data, idx - seg_bias, ctx.hash_log, ctx.mls);
        ctx.chain_table[(idx as u32 & chain_mask) as usize] = ctx.hash_table[h];
        ctx.hash_table[h] = idx as u32;
        idx += 1;
        if ctx.lazy_skipping {
            break;
        }
    }
    ctx.next_to_update = target;
    ctx.hash_table[hash_ptr(data, target - seg_bias, ctx.hash_log, ctx.mls)]
}

/// `ZSTD_HcFindBestMatch` (noDict and extDict): walk the chain from the hash
/// head, keeping the longest match. Writes `off_base` only when a
/// better-than-3 match is saved, exactly like the C `offsetPtr` contract.
/// Dict-side candidates skip the best-length quick filter and count across
/// the seam, exactly as in C.
#[allow(clippy::too_many_arguments)]
fn hc_find_best_match(
    ctx: &mut LazyCtx,
    data: &[u8],
    ip: usize,
    iend: usize,
    off_base: &mut u64,
    win: &Window,
    ext_dict: bool,
    dms: Option<&AttachedDict>,
) -> usize {
    let seg_bias = win.seg_bias as usize;
    let to_pos = |idx: usize| idx - seg_bias;
    let chain_size = 1u32 << ctx.chain_log;
    let chain_mask = chain_size - 1;
    let dict_limit = win.dict_limit as usize;
    let curr = ip as u32;
    let max_distance = 1u32 << ctx.window_log;
    let lowest_valid = win.low_limit;
    let within_max_distance = if curr - lowest_valid > max_distance {
        curr - max_distance
    } else {
        lowest_valid
    };
    let low_limit = within_max_distance;
    let min_chain = curr.saturating_sub(chain_size);
    let mut nb_attempts = 1u32 << ctx.search_log;
    let mut ml: usize = 4 - 1;

    let mut match_index = insert_and_find_first_index(ctx, data, ip, seg_bias);

    while match_index >= low_limit && nb_attempts > 0 {
        let m = match_index as usize;
        let mut current_ml = 0usize;
        if !ext_dict || m >= dict_limit {
            // Quick filter: 4 bytes ending at the current best length.
            if read32(data, to_pos(m) + ml - 3) == read32(data, to_pos(ip) + ml - 3) {
                current_ml = count_eq(data, to_pos(ip), to_pos(m), to_pos(iend));
            }
        } else {
            let dict_bias = win.dict_bias as usize;
            let match_pos = m - dict_bias;
            // matchIndex <= dictLimit-4 by table construction, so the 4-byte
            // read stays inside the dict segment.
            if read32(data, match_pos) == read32(data, to_pos(ip)) {
                current_ml = count_2segments(
                    data,
                    to_pos(ip) + 4,
                    match_pos + 4,
                    to_pos(iend),
                    dict_limit - dict_bias,
                    dict_limit - seg_bias,
                ) + 4;
            }
        }
        // Save best solution.
        if current_ml > ml {
            ml = current_ml;
            *off_base = (curr - match_index) as u64 + 3; // OFFSET_TO_OFFBASE
            if ip + current_ml == iend {
                break; // best possible
            }
        }
        if match_index <= min_chain {
            break;
        }
        match_index = ctx.chain_table[(match_index & chain_mask) as usize];
        nb_attempts -= 1;
    }

    // `ZSTD_HcFindBestMatch` dictMatchState arm: walk the attached CDict's own
    // hash chain with the search budget (`nbAttempts`) left after the working
    // chain. The dict is a separate match state; in our concat buffer
    // `dmsIndexDelta == 0`, so a dict index maps to a position like the working
    // context's and the saved offset is `curr - matchIndex` directly.
    if let Some(att) = dms {
        let d = att.ms;
        let dms_size = (WINDOW_START_INDEX + att.content_len) as u32; // dmsEnd - dmsBase
        let dms_lowest = WINDOW_START_INDEX as u32; // dms.window.dictLimit
        let dms_chain_size = 1u32 << d.chain_log;
        let dms_chain_mask = dms_chain_size - 1;
        let dms_min_chain = dms_size.saturating_sub(dms_chain_size);
        let dms_end_pos = att.content_len; // dmsEnd position
        let prefix_start_pos = att.content_len; // prefixStart (= src start)
        let mut mi = d.hash_table[hash_ptr(data, to_pos(ip), d.hash_log, ctx.mls)];
        while mi >= dms_lowest && nb_attempts > 0 {
            let match_pos = mi as usize - WINDOW_START_INDEX;
            let mut current_ml = 0usize;
            if read32(data, match_pos) == read32(data, to_pos(ip)) {
                current_ml = count_2segments(
                    data,
                    to_pos(ip) + 4,
                    match_pos + 4,
                    to_pos(iend),
                    dms_end_pos,
                    prefix_start_pos,
                ) + 4;
            }
            if current_ml > ml {
                ml = current_ml;
                *off_base = (curr - mi) as u64 + 3; // OFFSET_TO_OFFBASE, dmsIndexDelta 0
                if ip + current_ml == iend {
                    break;
                }
            }
            if mi <= dms_min_chain {
                break;
            }
            mi = d.chain_table[(mi & dms_chain_mask) as usize];
            nb_attempts -= 1;
        }
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
fn row_fill_hash_cache(
    ctx: &mut LazyCtx,
    data: &[u8],
    mut idx: usize,
    i_limit: i64,
    seg_bias: usize,
) {
    let max_elems = if (idx as i64) > i_limit {
        0
    } else {
        (i_limit - idx as i64 + 1) as usize
    };
    let lim = idx + ROW_HASH_CACHE_SIZE.min(max_elems);
    while idx < lim {
        let hash = hash_ptr_salted(
            data,
            idx - seg_bias,
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
fn row_next_cached_hash(ctx: &mut LazyCtx, data: &[u8], idx: usize, seg_bias: usize) -> u32 {
    let new_hash = hash_ptr_salted(
        data,
        idx + ROW_HASH_CACHE_SIZE - seg_bias,
        ctx.row_hash_log + ROW_HASH_TAG_BITS,
        ctx.mls,
        ctx.hash_salt,
    ) as u32;
    let hash = ctx.hash_cache[idx & ROW_HASH_CACHE_MASK];
    ctx.hash_cache[idx & ROW_HASH_CACHE_MASK] = new_hash;
    hash
}

/// `ZSTD_row_update_internalImpl`: insert positions [start, end).
fn row_update_impl(
    ctx: &mut LazyCtx,
    data: &[u8],
    mut start: usize,
    end: usize,
    use_cache: bool,
    seg_bias: usize,
) {
    let row_mask = (1u32 << ctx.row_log) - 1;
    while start < end {
        let hash = if use_cache {
            row_next_cached_hash(ctx, data, start, seg_bias)
        } else {
            hash_ptr_salted(
                data,
                start - seg_bias,
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
fn row_update_internal(
    ctx: &mut LazyCtx,
    data: &[u8],
    target: usize,
    use_cache: bool,
    seg_bias: usize,
) {
    const K_SKIP_THRESHOLD: usize = 384;
    const K_MAX_START: usize = 96;
    const K_MAX_END: usize = 32;
    let mut idx = ctx.next_to_update;

    if use_cache && target - idx > K_SKIP_THRESHOLD {
        let bound = idx + K_MAX_START;
        row_update_impl(ctx, data, idx, bound, use_cache, seg_bias);
        idx = target - K_MAX_END;
        // C passes `ip + 1` as the iLimit pointer here.
        row_fill_hash_cache(ctx, data, idx, (target + 1) as i64, seg_bias);
    }
    row_update_impl(ctx, data, idx, target, use_cache, seg_bias);
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

/// `ZSTD_RowFindBestMatch` (noDict and extDict). Dict-side candidates skip
/// the best-length quick filter and count across the seam, exactly as in C.
#[allow(clippy::too_many_arguments)]
fn row_find_best_match(
    ctx: &mut LazyCtx,
    data: &[u8],
    ip: usize,
    iend: usize,
    off_base: &mut u64,
    win: &Window,
    ext_dict: bool,
    dms: Option<&AttachedDict>,
) -> usize {
    let seg_bias = win.seg_bias as usize;
    let to_pos = |idx: usize| idx - seg_bias;
    let dict_limit = win.dict_limit as usize;
    let curr = ip as u32;
    let max_distance = 1u32 << ctx.window_log;
    let lowest_valid = win.low_limit;
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
        row_update_internal(ctx, data, ip, true, seg_bias);
        hash = row_next_cached_hash(ctx, data, ip, seg_bias);
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
        let mut current_ml = 0usize;
        if !ext_dict || m >= dict_limit {
            // Quick filter: 4 bytes ending at the current best length.
            if read32(data, to_pos(m) + ml - 3) == read32(data, to_pos(ip) + ml - 3) {
                current_ml = count_eq(data, to_pos(ip), to_pos(m), to_pos(iend));
            }
        } else {
            let dict_bias = win.dict_bias as usize;
            let match_pos = m - dict_bias;
            // matchIndex <= dictLimit-4 by table construction, so the 4-byte
            // read stays inside the dict segment.
            if read32(data, match_pos) == read32(data, to_pos(ip)) {
                current_ml = count_2segments(
                    data,
                    to_pos(ip) + 4,
                    match_pos + 4,
                    to_pos(iend),
                    dict_limit - dict_bias,
                    dict_limit - seg_bias,
                ) + 4;
            }
        }
        // Save best solution.
        if current_ml > ml {
            ml = current_ml;
            *off_base = (curr - match_index) as u64 + 3;
            if ip + current_ml == iend {
                break;
            }
        }
    }

    // `ZSTD_RowFindBestMatch` dictMatchState arm: probe the attached CDict's own
    // tag row with the search budget left after the working row. The dms tag row
    // is hashed with the CDict's `rowHashLog` but the *unsalted* `ZSTD_hashPtr`
    // (the CDict's salt is 0, so the salted fill and unsalted probe agree); the
    // row stride uses the shared `rowLog` (working searchLog == CDict searchLog).
    if let Some(att) = dms {
        let d = att.ms;
        let dms_lowest = WINDOW_START_INDEX as u32; // dms.window.dictLimit
        let dms_end_pos = att.content_len; // dmsEnd position
        let prefix_start_pos = att.content_len; // prefixStart (= src start)
        let dms_hash = hash_ptr_salted(
            data,
            to_pos(ip),
            d.row_hash_log + ROW_HASH_TAG_BITS,
            ctx.mls,
            d.hash_salt,
        ) as u32;
        let dms_rel_row = ((dms_hash >> ROW_HASH_TAG_BITS) << ctx.row_log) as usize;
        let dms_tag = dms_hash & ROW_HASH_TAG_MASK;
        let dms_head = d.tag_table[dms_rel_row] as u32 & row_mask;
        let mut dms_matches = row_get_match_mask(
            &d.tag_table[dms_rel_row..dms_rel_row + row_entries as usize],
            dms_tag as u8,
            dms_head,
            row_entries,
        );
        let mut dms_buffer = [0u32; ROW_HASH_MAX_ENTRIES];
        let mut dms_num = 0usize;
        while dms_matches > 0 && nb_attempts > 0 {
            let match_pos = ((dms_head + dms_matches.trailing_zeros()) & row_mask) as usize;
            dms_matches &= dms_matches - 1;
            if match_pos == 0 {
                continue;
            }
            let mi = d.hash_table[dms_rel_row + match_pos];
            if mi < dms_lowest {
                break;
            }
            dms_buffer[dms_num] = mi;
            dms_num += 1;
            nb_attempts -= 1;
        }
        for &mi in &dms_buffer[..dms_num] {
            let match_pos = mi as usize - WINDOW_START_INDEX;
            let mut current_ml = 0usize;
            if read32(data, match_pos) == read32(data, to_pos(ip)) {
                current_ml = count_2segments(
                    data,
                    to_pos(ip) + 4,
                    match_pos + 4,
                    to_pos(iend),
                    dms_end_pos,
                    prefix_start_pos,
                ) + 4;
            }
            if current_ml > ml {
                ml = current_ml;
                *off_base = (curr - mi) as u64 + 3; // dmsIndexDelta 0
                if ip + current_ml == iend {
                    break;
                }
            }
        }
    }
    ml
}

// --- Binary-tree search (btlazy2) ---------------------------------------------

/// `ZSTD_updateDUBT`: append positions [nextToUpdate, target) to their hash
/// chains as *unsorted* BT candidates (second slot = the sort mark).
fn update_dubt(ctx: &mut LazyCtx, data: &[u8], target: usize, seg_bias: usize) {
    let bt_log = ctx.chain_log - 1;
    let bt_mask = (1u32 << bt_log) - 1;
    let mut idx = ctx.next_to_update;
    while idx < target {
        let h = hash_ptr(data, idx - seg_bias, ctx.hash_log, ctx.mls);
        let slot = 2 * (idx as u32 & bt_mask) as usize;
        ctx.chain_table[slot] = ctx.hash_table[h];
        ctx.chain_table[slot + 1] = DUBT_UNSORTED_MARK;
        ctx.hash_table[h] = idx as u32;
        idx += 1;
    }
    ctx.next_to_update = target;
}

/// `ZSTD_insertBt1` specialized to `ZSTD_noDict` (one contiguous segment): sort
/// the position with biased index `curr` into the sorted binary tree, returning
/// how many positions the fill may skip forward (the C `forward` value). Used
/// only by the btlazy2 dictionary fill ([`update_tree_nodict`]) — C loads the
/// dict "fully sorted" via `ZSTD_updateTree`, so the extDict branch never runs
/// and `window_low` is constant (`lowLimit`, because `isDictionary` holds during
/// `ZSTD_loadDictionaryContent`). Mirrors [`crate::opt`]'s `insert_bt1` noDict
/// path on `LazyCtx`'s tables (`chain_table` is the two-slot BT).
fn insert_bt1_nodict(
    ctx: &mut LazyCtx,
    data: &[u8],
    curr: usize,
    iend_pos: usize,
    seg_bias: usize,
    window_low: u32,
) -> usize {
    let bt_mask = (1u32 << (ctx.chain_log - 1)) - 1;
    let ip_pos = curr - seg_bias;
    let h = hash_ptr(data, ip_pos, ctx.hash_log, ctx.mls);
    let mut match_index = ctx.hash_table[h];
    let mut common_length_smaller = 0usize;
    let mut common_length_larger = 0usize;
    let curr_u32 = curr as u32;
    let bt_low = curr_u32.saturating_sub(bt_mask);
    let root = 2 * (curr_u32 & bt_mask) as usize;
    let mut smaller_slot: Option<usize> = Some(root);
    let mut larger_slot: Option<usize> = Some(root + 1);
    let mut match_end_idx = curr_u32 + 8 + 1;
    let mut best_length = 8usize;
    let mut nb_compares = 1u32 << ctx.search_log;

    ctx.hash_table[h] = curr_u32;

    while nb_compares > 0 && match_index >= window_low {
        let next = 2 * (match_index & bt_mask) as usize;
        let mut match_length = common_length_smaller.min(common_length_larger);
        let m_pos = match_index as usize - seg_bias;
        match_length += count_eq(data, ip_pos + match_length, m_pos + match_length, iend_pos);

        if match_length > best_length {
            best_length = match_length;
            if match_length > (match_end_idx - match_index) as usize {
                match_end_idx = match_index + match_length as u32;
            }
        }

        if ip_pos + match_length == iend_pos {
            break; // equal: cannot order; drop, to keep the tree consistent
        }

        if data[m_pos + match_length] < data[ip_pos + match_length] {
            // match is smaller than current
            if let Some(s) = smaller_slot {
                ctx.chain_table[s] = match_index;
            }
            common_length_smaller = match_length;
            if match_index <= bt_low {
                smaller_slot = None;
                break;
            }
            smaller_slot = Some(next + 1);
            match_index = ctx.chain_table[next + 1];
        } else {
            // match is larger than current
            if let Some(l) = larger_slot {
                ctx.chain_table[l] = match_index;
            }
            common_length_larger = match_length;
            if match_index <= bt_low {
                larger_slot = None;
                break;
            }
            larger_slot = Some(next);
            match_index = ctx.chain_table[next];
        }
        nb_compares -= 1;
    }

    if let Some(s) = smaller_slot {
        ctx.chain_table[s] = 0;
    }
    if let Some(l) = larger_slot {
        ctx.chain_table[l] = 0;
    }

    let positions = if best_length > 384 {
        192.min(best_length - 384)
    } else {
        0
    };
    positions.max((match_end_idx - (curr_u32 + 8)) as usize)
}

/// `ZSTD_updateTree_internal` for `ZSTD_noDict`: sort positions
/// `[nextToUpdate, target)` into the binary tree. This is the btlazy2 dictionary
/// fill, `ZSTD_updateTree(ms, dictEnd - HASH_READ_SIZE, dictEnd)`.
fn update_tree_nodict(
    ctx: &mut LazyCtx,
    data: &[u8],
    target: usize,
    iend_pos: usize,
    seg_bias: usize,
    window_low: u32,
) {
    let mut idx = ctx.next_to_update;
    while idx < target {
        let forward = insert_bt1_nodict(ctx, data, idx, iend_pos, seg_bias, window_low);
        idx += forward;
    }
    ctx.next_to_update = target;
}

/// `ZSTD_insertDUBT1` (noDict and extDict): sort one previously unsorted
/// position into the binary tree rooted at its own slot. In extDict mode the
/// position being sorted may itself live in the dict segment (a pre-wrap
/// backlog entry), and each candidate compare resolves its segment by
/// `matchIndex + matchLength >= dictLimit`, rebasing the post-run ordering
/// byte into the prefix when the counted run crosses the seam.
#[allow(clippy::too_many_arguments)]
fn insert_dubt1(
    ctx: &mut LazyCtx,
    data: &[u8],
    curr: u32,
    iend: usize,
    nb_compares0: u32,
    bt_low: u32,
    win: &Window,
    ext_dict: bool,
) {
    let seg_bias = win.seg_bias as usize;
    let dict_bias = win.dict_bias as usize;
    let dict_limit = win.dict_limit as usize;
    let bt_mask = (1u32 << (ctx.chain_log - 1)) - 1;
    let mut common_length_smaller = 0usize;
    let mut common_length_larger = 0usize;
    let ip = curr as usize;
    // `ip` and its counting limit live in ip's own segment
    // (`curr >= dictLimit ? base/inputEnd : dictBase/dictEnd`).
    let ip_in_prefix = ip >= dict_limit;
    let ip_pos = if ip_in_prefix {
        ip - seg_bias
    } else {
        ip - dict_bias
    };
    let iend_pos = if ip_in_prefix {
        iend - seg_bias
    } else {
        dict_limit - dict_bias
    };
    let prefix_start_pos = dict_limit - seg_bias;
    let max_distance = 1u32 << ctx.window_log;
    let window_valid = win.low_limit;
    let window_low = if curr - window_valid > max_distance {
        curr - max_distance
    } else {
        window_valid
    };

    // smaller/larger "pointers" are slots in the chain table; None = dummy.
    let root = 2 * (curr & bt_mask) as usize;
    let mut smaller_slot: Option<usize> = Some(root);
    let mut larger_slot: Option<usize> = Some(root + 1);
    let mut match_index = ctx.chain_table[root];
    let mut nb_compares = nb_compares0;

    while nb_compares > 0 && match_index > window_low {
        let next = 2 * (match_index & bt_mask) as usize;
        let mut match_length = common_length_smaller.min(common_length_larger);
        let m = match_index as usize;

        // Position of `match[matchLength]` for the ordering byte, valid
        // after the count inside each branch.
        let m_read_pos = if !ext_dict || m + match_length >= dict_limit || !ip_in_prefix {
            // Single-segment count: the match bytes come from the prefix
            // unless both positions sit in the extDict.
            let m_bias = if !ext_dict || m + match_length >= dict_limit {
                seg_bias
            } else {
                dict_bias
            };
            match_length += count_eq(
                data,
                ip_pos + match_length,
                m + match_length - m_bias,
                iend_pos,
            );
            m + match_length - m_bias
        } else {
            // Match in the extDict, current position in the prefix.
            let m_pos = m - dict_bias;
            match_length += count_2segments(
                data,
                ip_pos + match_length,
                m_pos + match_length,
                iend_pos,
                dict_limit - dict_bias,
                prefix_start_pos,
            );
            // Preparation for the next read of match[matchLength].
            if m + match_length >= dict_limit {
                m + match_length - seg_bias
            } else {
                m_pos + match_length
            }
        };

        if ip_pos + match_length == iend_pos {
            break; // equal: drop to guarantee tree consistency
        }

        if data[m_read_pos] < data[ip_pos + match_length] {
            // match is smaller than current
            if let Some(s) = smaller_slot {
                ctx.chain_table[s] = match_index;
            }
            common_length_smaller = match_length;
            if match_index <= bt_low {
                smaller_slot = None;
                break;
            }
            smaller_slot = Some(next + 1);
            match_index = ctx.chain_table[next + 1];
        } else {
            // match is larger than current
            if let Some(l) = larger_slot {
                ctx.chain_table[l] = match_index;
            }
            common_length_larger = match_length;
            if match_index <= bt_low {
                larger_slot = None;
                break;
            }
            larger_slot = Some(next);
            match_index = ctx.chain_table[next];
        }
        nb_compares -= 1;
    }

    if let Some(s) = smaller_slot {
        ctx.chain_table[s] = 0;
    }
    if let Some(l) = larger_slot {
        ctx.chain_table[l] = 0;
    }
}

/// `ZSTD_DUBT_findBestMatch` (noDict and extDict): resolve the unsorted
/// backlog, then descend the tree keeping the best gain-adjusted match. Reads
/// *and* writes `off_base` (the gain rule compares against the incoming
/// sentinel). The extDict candidate compares resolve their segment by
/// `matchIndex + matchLength >= dictLimit` exactly as [`insert_dubt1`] does.
fn dubt_find_best_match(
    ctx: &mut LazyCtx,
    data: &[u8],
    ip: usize,
    iend: usize,
    off_base: &mut u64,
    win: &Window,
    ext_dict: bool,
) -> usize {
    let seg_bias = win.seg_bias as usize;
    let dict_bias = win.dict_bias as usize;
    let dict_limit = win.dict_limit as usize;
    let to_pos = |idx: usize| idx - seg_bias;
    let h = hash_ptr(data, to_pos(ip), ctx.hash_log, ctx.mls);
    let mut match_index = ctx.hash_table[h];

    let curr = ip as u32;
    let max_distance = 1u32 << ctx.window_log;
    let lowest_valid = win.low_limit;
    let window_low = if curr - lowest_valid > max_distance {
        curr - max_distance
    } else {
        lowest_valid
    };
    let bt_mask = (1u32 << (ctx.chain_log - 1)) - 1;
    let bt_low = curr.saturating_sub(bt_mask);
    let unsort_limit = bt_low.max(window_low);

    let mut nb_compares = 1u32 << ctx.search_log;
    let mut nb_candidates = nb_compares;
    let mut previous_candidate = 0u32;

    // Reach the end of the unsorted-candidates list, reversing it as we go.
    while match_index > unsort_limit
        && ctx.chain_table[2 * (match_index & bt_mask) as usize + 1] == DUBT_UNSORTED_MARK
        && nb_candidates > 1
    {
        ctx.chain_table[2 * (match_index & bt_mask) as usize + 1] = previous_candidate;
        previous_candidate = match_index;
        match_index = ctx.chain_table[2 * (match_index & bt_mask) as usize];
        nb_candidates -= 1;
    }

    // Nullify the last candidate if it is still unsorted (speed simplification).
    if match_index > unsort_limit
        && ctx.chain_table[2 * (match_index & bt_mask) as usize + 1] == DUBT_UNSORTED_MARK
    {
        ctx.chain_table[2 * (match_index & bt_mask) as usize] = 0;
        ctx.chain_table[2 * (match_index & bt_mask) as usize + 1] = 0;
    }

    // Batch-sort the stacked candidates.
    match_index = previous_candidate;
    while match_index != 0 {
        let next_candidate_idx = ctx.chain_table[2 * (match_index & bt_mask) as usize + 1];
        insert_dubt1(
            ctx,
            data,
            match_index,
            iend,
            nb_candidates,
            unsort_limit,
            win,
            ext_dict,
        );
        match_index = next_candidate_idx;
        nb_candidates += 1;
    }

    // Find the longest match by tree descent (re-inserting curr).
    {
        let mut common_length_smaller = 0usize;
        let mut common_length_larger = 0usize;
        let root = 2 * (curr & bt_mask) as usize;
        let mut smaller_slot: Option<usize> = Some(root);
        let mut larger_slot: Option<usize> = Some(root + 1);
        let mut match_end_idx = curr + 8 + 1;
        let mut best_length = 0usize;

        match_index = ctx.hash_table[h];
        ctx.hash_table[h] = curr;

        while nb_compares > 0 && match_index > window_low {
            let next = 2 * (match_index & bt_mask) as usize;
            let mut match_length = common_length_smaller.min(common_length_larger);
            let m = match_index as usize;

            // Position of `match[matchLength]` for the ordering byte, valid
            // after the count inside each branch.
            let m_read_pos = if !ext_dict || m + match_length >= dict_limit {
                match_length += count_eq(
                    data,
                    to_pos(ip) + match_length,
                    m + match_length - seg_bias,
                    to_pos(iend),
                );
                m + match_length - seg_bias
            } else {
                let m_pos = m - dict_bias;
                match_length += count_2segments(
                    data,
                    to_pos(ip) + match_length,
                    m_pos + match_length,
                    to_pos(iend),
                    dict_limit - dict_bias,
                    dict_limit - seg_bias,
                );
                // Preparation for the next read of match[matchLength].
                if m + match_length >= dict_limit {
                    m + match_length - seg_bias
                } else {
                    m_pos + match_length
                }
            };

            if match_length > best_length {
                if match_length > (match_end_idx - match_index) as usize {
                    match_end_idx = match_index + match_length as u32;
                }
                if 4 * (match_length as i32 - best_length as i32)
                    > highbit32(curr - match_index + 1) as i32 - highbit32(*off_base as u32) as i32
                {
                    best_length = match_length;
                    *off_base = (curr - match_index) as u64 + 3; // OFFSET_TO_OFFBASE
                }
                if ip + match_length == iend {
                    break; // equal: drop to guarantee consistency
                }
            }

            if data[m_read_pos] < data[to_pos(ip) + match_length] {
                if let Some(s) = smaller_slot {
                    ctx.chain_table[s] = match_index;
                }
                common_length_smaller = match_length;
                if match_index <= bt_low {
                    smaller_slot = None;
                    break;
                }
                smaller_slot = Some(next + 1);
                match_index = ctx.chain_table[next + 1];
            } else {
                if let Some(l) = larger_slot {
                    ctx.chain_table[l] = match_index;
                }
                common_length_larger = match_length;
                if match_index <= bt_low {
                    larger_slot = None;
                    break;
                }
                larger_slot = Some(next);
                match_index = ctx.chain_table[next];
            }
            nb_compares -= 1;
        }

        if let Some(s) = smaller_slot {
            ctx.chain_table[s] = 0;
        }
        if let Some(l) = larger_slot {
            ctx.chain_table[l] = 0;
        }

        // Skip repetitive patterns on the next update.
        ctx.next_to_update = (match_end_idx - 8) as usize;
        best_length
    }
}

/// `ZSTD_BtFindBestMatch`.
fn bt_find_best_match(
    ctx: &mut LazyCtx,
    data: &[u8],
    ip: usize,
    iend: usize,
    off_base: &mut u64,
    win: &Window,
    ext_dict: bool,
) -> usize {
    if ip < ctx.next_to_update {
        return 0; // skipped area
    }
    update_dubt(ctx, data, ip, win.seg_bias as usize);
    dubt_find_best_match(ctx, data, ip, iend, off_base, win, ext_dict)
}

/// `ZSTD_searchMax`. `dms` (`ms->dictMatchState`) is consulted only by the
/// hash-chain and row finders (the dictMatchState dispatch is greedy/lazy/lazy2);
/// the binary tree's dictMatchState arm is a separate increment, so it is never
/// reached with `dms.is_some()`.
#[allow(clippy::too_many_arguments)]
fn search_max(
    ctx: &mut LazyCtx,
    data: &[u8],
    ip: usize,
    iend: usize,
    off_base: &mut u64,
    win: &Window,
    ext_dict: bool,
    dms: Option<&AttachedDict>,
) -> usize {
    match ctx.method {
        SearchMethod::HashChain => {
            hc_find_best_match(ctx, data, ip, iend, off_base, win, ext_dict, dms)
        }
        SearchMethod::RowHash => {
            row_find_best_match(ctx, data, ip, iend, off_base, win, ext_dict, dms)
        }
        SearchMethod::BinaryTree => {
            bt_find_best_match(ctx, data, ip, iend, off_base, win, ext_dict)
        }
    }
}

// --- The lazy driver -------------------------------------------------------------

/// `ZSTD_compressBlock_lazy_generic` (noDict), depths 0..=2. Same conventions
/// as the fast/dfast ports: biased indices, sequences into `store`, returns
/// the trailing-literals size. `win` supplies the segment bias and
/// `dictLimit` (the prefix lowest index), which only differ from 2 after a
/// streaming buffer wrap whose extDict has aged out.
pub(crate) fn compress_block_lazy(
    ctx: &mut LazyCtx,
    store: &mut SeqStore,
    rep: &mut [u32; 3],
    data: &[u8],
    block_start: usize,
    block_end: usize,
    win: &Window,
) -> usize {
    let bias = win.seg_bias as usize;
    let to_pos = |idx: usize| idx - bias;
    let istart = block_start + bias;
    let iend = block_end + bias;
    let i_limit: i64 = iend as i64
        - 8
        - if ctx.method == SearchMethod::RowHash {
            ROW_HASH_CACHE_SIZE as i64
        } else {
            0
        };
    let prefix_lowest = win.dict_limit as usize; // prefixLowestIndex
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
        row_fill_hash_cache(ctx, data, from, i_limit, bias);
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
                    bias,
                );
                continue;
            }
        }

        // First search (depth 0).
        {
            let mut offbase_found: u64 = 999_999_999;
            let ml2 = search_max(ctx, data, ip, iend, &mut offbase_found, win, false, None);
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
                    let ml2 = search_max(ctx, data, ip, iend, &mut ofb_candidate, win, false, None);
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
                        let ml2 =
                            search_max(ctx, data, ip, iend, &mut ofb_candidate, win, false, None);
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
            bias,
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
    bias: usize,
) {
    let to_pos = |idx: usize| idx - bias;
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
            row_fill_hash_cache(ctx, data, from, i_limit, bias);
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

// --- The lazy dictMatchState driver (CDict attach) --------------------------------

/// `ZSTD_compressBlock_lazy_generic` with `dictMode == ZSTD_dictMatchState`,
/// depths 0..=2 — the CDict **attach** match finder. The dictionary lives in a
/// separate match state `dms` (its own filled tables, salt 0); `ctx` is the
/// working context, whose tables start empty and fill as `src` is parsed. We lay
/// the history out as one buffer `content ++ src`, so the working window is
/// non-extDict (src begins at `dictLimit`), `dmsIndexDelta == 0`, and a dict
/// index maps to a position like the working context's. Repcodes may reach into
/// the dict (validated by `ZSTD_index_overlap_check`, not a window-distance
/// bound). Note this is the **noDict-family** driver (skip step `((ip-anchor)>>8)
/// +1`), not the extDict one — C routes dictMatchState through
/// `ZSTD_compressBlock_lazy_generic`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compress_block_lazy_dict_match_state(
    ctx: &mut LazyCtx,
    store: &mut SeqStore,
    rep: &mut [u32; 3],
    data: &[u8],
    block_start: usize,
    block_end: usize,
    win: &Window,
    dms: &LazyCtx,
    content_len: usize,
) -> usize {
    let bias = win.seg_bias as usize;
    let to_pos = |idx: usize| idx - bias;
    let istart = block_start + bias;
    let iend = block_end + bias;
    let i_limit: i64 = iend as i64
        - 8
        - if ctx.method == SearchMethod::RowHash {
            ROW_HASH_CACHE_SIZE as i64
        } else {
            0
        };
    // window.dictLimit = src start; the dict (= content) ends here too.
    let prefix_start_index = win.dict_limit; // 2 + content_len
    let dict_end_pos = content_len; // dmsEnd position
    let prefix_lowest_pos = content_len; // prefixLowest position (src start)
    let depth = ctx.depth;
    let attached = AttachedDict {
        ms: dms,
        content_len,
    };

    let mut ip = istart;
    let mut anchor = istart;
    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];

    // dictAndPrefixLength = (ip - prefixLowest) + (dictEnd - dictLowest); for a
    // first block ip == prefixLowest, so this is the dict content length (> 0 by
    // the caller's gate), and there is no `ip += (… == 0)` bump. No offsetSaved
    // rescue in dictMatchState mode (C only does it for ZSTD_noDict); the reps
    // are assumed valid (`offset_1,2 <= dictAndPrefixLength`).
    let dict_and_prefix_length = (istart - prefix_start_index as usize) + content_len;
    ip += (dict_and_prefix_length == 0) as usize;

    ctx.lazy_skipping = false;
    if ctx.method == SearchMethod::RowHash {
        let from = ctx.next_to_update;
        row_fill_hash_cache(ctx, data, from, i_limit, bias);
    }

    while (ip as i64) < i_limit {
        let mut match_length = 0usize;
        let mut off_base: u64 = 1; // REPCODE1_TO_OFFBASE
        let mut start = ip + 1;

        // Check repcode at ip+1 (may reach into the dict).
        {
            let rep_index = (ip as u32).wrapping_add(1).wrapping_sub(offset_1);
            if index_overlap_check(prefix_start_index, rep_index) {
                let rep_pos = rep_index as usize - bias;
                if read32(data, rep_pos) == read32(data, to_pos(ip + 1)) {
                    let rep_end = if rep_index < prefix_start_index {
                        dict_end_pos
                    } else {
                        block_end
                    };
                    match_length = count_2segments(
                        data,
                        to_pos(ip + 1) + 4,
                        rep_pos + 4,
                        block_end,
                        rep_end,
                        prefix_lowest_pos,
                    ) + 4;
                    if depth == 0 {
                        store_and_repcodes_dms(
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
                            win,
                            block_end,
                            content_len,
                        );
                        continue;
                    }
                }
            }
        }

        // First search (depth 0).
        {
            let mut ofb_found: u64 = 999_999_999;
            let ml2 = search_max(
                ctx,
                data,
                ip,
                iend,
                &mut ofb_found,
                win,
                false,
                Some(&attached),
            );
            if ml2 > match_length {
                match_length = ml2;
                start = ip;
                off_base = ofb_found;
            }
        }

        if match_length < 4 {
            let step = ((ip - anchor) >> K_SEARCH_STRENGTH) + 1;
            ip += step;
            ctx.lazy_skipping = step > K_LAZY_SKIPPING_STEP;
            continue;
        }

        // Try to find a better solution.
        if depth >= 1 {
            while (ip as i64) < i_limit {
                ip += 1;
                // Check repcode.
                {
                    let rep_index = (ip as u32).wrapping_sub(offset_1);
                    if index_overlap_check(prefix_start_index, rep_index) {
                        let rep_pos = rep_index as usize - bias;
                        if read32(data, rep_pos) == read32(data, to_pos(ip)) {
                            let rep_end = if rep_index < prefix_start_index {
                                dict_end_pos
                            } else {
                                block_end
                            };
                            let ml_rep = count_2segments(
                                data,
                                to_pos(ip) + 4,
                                rep_pos + 4,
                                block_end,
                                rep_end,
                                prefix_lowest_pos,
                            ) + 4;
                            let gain2 = (ml_rep * 3) as i32;
                            let gain1 =
                                (match_length * 3) as i32 - highbit32(off_base as u32) as i32 + 1;
                            if ml_rep >= 4 && gain2 > gain1 {
                                match_length = ml_rep;
                                off_base = 1;
                                start = ip;
                            }
                        }
                    }
                }
                // Search match, depth 1.
                {
                    let mut ofb_candidate: u64 = 999_999_999;
                    let ml2 = search_max(
                        ctx,
                        data,
                        ip,
                        iend,
                        &mut ofb_candidate,
                        win,
                        false,
                        Some(&attached),
                    );
                    let gain2 = (ml2 * 4) as i32 - highbit32(ofb_candidate as u32) as i32;
                    let gain1 = (match_length * 4) as i32 - highbit32(off_base as u32) as i32 + 4;
                    if ml2 >= 4 && gain2 > gain1 {
                        match_length = ml2;
                        off_base = ofb_candidate;
                        start = ip;
                        continue;
                    }
                }

                // Let's find an even better one.
                if depth == 2 && (ip as i64) < i_limit {
                    ip += 1;
                    // Check repcode.
                    {
                        let rep_index = (ip as u32).wrapping_sub(offset_1);
                        if index_overlap_check(prefix_start_index, rep_index) {
                            let rep_pos = rep_index as usize - bias;
                            if read32(data, rep_pos) == read32(data, to_pos(ip)) {
                                let rep_end = if rep_index < prefix_start_index {
                                    dict_end_pos
                                } else {
                                    block_end
                                };
                                let ml_rep = count_2segments(
                                    data,
                                    to_pos(ip) + 4,
                                    rep_pos + 4,
                                    block_end,
                                    rep_end,
                                    prefix_lowest_pos,
                                ) + 4;
                                let gain2 = (ml_rep * 4) as i32;
                                let gain1 = (match_length * 4) as i32
                                    - highbit32(off_base as u32) as i32
                                    + 1;
                                if ml_rep >= 4 && gain2 > gain1 {
                                    match_length = ml_rep;
                                    off_base = 1;
                                    start = ip;
                                }
                            }
                        }
                    }
                    // Search match, depth 2.
                    {
                        let mut ofb_candidate: u64 = 999_999_999;
                        let ml2 = search_max(
                            ctx,
                            data,
                            ip,
                            iend,
                            &mut ofb_candidate,
                            win,
                            false,
                            Some(&attached),
                        );
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

        // Catch up (real offsets only), reaching into the dict when needed.
        if off_base > 3 {
            let offset = (off_base - 3) as usize;
            let match_index = start - offset; // biased index
            let in_dict = (match_index as u32) < prefix_start_index;
            let mut match_pos = match_index - bias; // = to_pos(start) - offset
            let m_start_pos = if in_dict { 0 } else { prefix_lowest_pos };
            while start > anchor
                && match_pos > m_start_pos
                && data[to_pos(start) - 1] == data[match_pos - 1]
            {
                start -= 1;
                match_pos -= 1;
                match_length += 1;
            }
            offset_2 = offset_1;
            offset_1 = offset as u32;
        }

        store_and_repcodes_dms(
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
            win,
            block_end,
            content_len,
        );
    }

    // Save reps for the next block (offsetSaved stays 0 in dictMatchState mode).
    rep[0] = offset_1;
    rep[1] = offset_2;

    to_pos(iend) - to_pos(anchor)
}

/// `_storeSequence` + the immediate-repcode tail of the dictMatchState driver:
/// two-segment reads with the dict reached via `dmsIndexDelta == 0`, repcode
/// validity by `ZSTD_index_overlap_check` (no window-distance bound).
#[allow(clippy::too_many_arguments)]
fn store_and_repcodes_dms(
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
    win: &Window,
    block_end: usize,
    content_len: usize,
) {
    let bias = win.seg_bias as usize;
    let to_pos = |idx: usize| idx - bias;
    let prefix_start_index = win.dict_limit;
    let dict_end_pos = content_len;
    let prefix_lowest_pos = content_len;

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
            row_fill_hash_cache(ctx, data, from, i_limit, bias);
        }
        ctx.lazy_skipping = false;
    }

    // Check immediate repcode.
    while (*ip as i64) <= i_limit {
        let rep_index = (*ip as u32).wrapping_sub(*offset_2);
        if !index_overlap_check(prefix_start_index, rep_index) {
            break;
        }
        let rep_pos = rep_index as usize - bias;
        if read32(data, to_pos(*ip)) != read32(data, rep_pos) {
            break;
        }
        let rep_end = if rep_index < prefix_start_index {
            dict_end_pos
        } else {
            block_end
        };
        let m_len = count_2segments(
            data,
            to_pos(*ip) + 4,
            rep_pos + 4,
            block_end,
            rep_end,
            prefix_lowest_pos,
        ) + 4;
        std::mem::swap(offset_1, offset_2);
        store.store_seq(&[], 1, m_len as u32);
        *ip += m_len;
        *anchor = *ip;
    }
}

// --- The lazy extDict driver --------------------------------------------------------

/// `ZSTD_compressBlock_lazy_extDict_generic`, depths 0..=2: the lazy driver
/// over the two-segment window. Unlike the noDict driver there is no
/// offsetSaved rescue at the block start — every repcode candidate is
/// validated per use against the window (`ZSTD_index_overlap_check` plus
/// `offset <= curr - windowLow`, with `windowLow` from
/// `ZSTD_getLowestMatchIndex` at the probe position).
pub(crate) fn compress_block_lazy_extdict(
    ctx: &mut LazyCtx,
    store: &mut SeqStore,
    rep: &mut [u32; 3],
    data: &[u8],
    block_start: usize,
    block_end: usize,
    win: &Window,
) -> usize {
    let seg_bias = win.seg_bias as usize;
    let dict_bias = win.dict_bias as usize;
    let to_pos = |idx: usize| idx - seg_bias;
    let istart = block_start + seg_bias;
    let iend = block_end + seg_bias;
    let i_limit: i64 = iend as i64
        - 8
        - if ctx.method == SearchMethod::RowHash {
            ROW_HASH_CACHE_SIZE as i64
        } else {
            0
        };
    let dict_limit = win.dict_limit as usize;
    let prefix_start_pos = dict_limit - seg_bias; // prefixStart
    let dict_end_pos = dict_limit - dict_bias; // dictEnd
    let dict_start_pos = win.low_limit as usize - dict_bias; // dictStart
    let depth = ctx.depth;
    let max_distance = 1u32 << ctx.window_log;

    let mut offset_1 = rep[0];
    let mut offset_2 = rep[1];

    // Buffer position of an index, resolved through its segment, and the
    // matching segment end (`repIndex < dictLimit ? dictBase : base` etc.).
    let pos_seg = |idx: usize| {
        if idx < dict_limit {
            idx - dict_bias
        } else {
            idx - seg_bias
        }
    };
    let match_end_pos = |idx: usize| {
        if idx < dict_limit {
            dict_end_pos
        } else {
            block_end
        }
    };
    // `ZSTD_getLowestMatchIndex(ms, curr, windowLog)`.
    let window_low_at = |curr: u32| {
        if curr - win.low_limit > max_distance {
            curr - max_distance
        } else {
            win.low_limit
        }
    };
    // `ZSTD_index_overlap_check(dictLimit, repIndex)`.
    let overlap_ok =
        |rep_index: u32| (dict_limit as u32).wrapping_sub(1).wrapping_sub(rep_index) >= 3;

    // Reset the lazy skipping state.
    ctx.lazy_skipping = false;

    let mut ip = istart;
    let mut anchor = istart;
    ip += (ip == dict_limit) as usize; // ip += (ip == prefixStart)
    if ctx.method == SearchMethod::RowHash {
        let from = ctx.next_to_update;
        row_fill_hash_cache(ctx, data, from, i_limit, seg_bias);
    }

    while (ip as i64) < i_limit {
        let mut match_length = 0usize;
        let mut off_base: u64 = 1; // REPCODE1_TO_OFFBASE
        let mut start = ip + 1;
        let mut curr = ip as u32;

        // Check repcode at ip+1 (hence the validity bound at curr+1).
        {
            let window_low = window_low_at(curr + 1);
            let rep_index = (curr + 1).wrapping_sub(offset_1);
            if overlap_ok(rep_index)
                && offset_1 <= (curr + 1) - window_low
                && read32(data, to_pos(ip + 1)) == read32(data, pos_seg(rep_index as usize))
            {
                let rep_idx = rep_index as usize;
                match_length = count_2segments(
                    data,
                    to_pos(ip + 1) + 4,
                    pos_seg(rep_idx) + 4,
                    block_end,
                    match_end_pos(rep_idx),
                    prefix_start_pos,
                ) + 4;
                if depth == 0 {
                    // goto _storeSequence
                    extdict_store_and_repcodes(
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
                        win,
                        block_end,
                    );
                    continue;
                }
            }
        }

        // First search (depth 0).
        {
            let mut ofb_candidate: u64 = 999_999_999;
            let ml2 = search_max(ctx, data, ip, iend, &mut ofb_candidate, win, true, None);
            if ml2 > match_length {
                match_length = ml2;
                start = ip;
                off_base = ofb_candidate;
            }
        }

        if match_length < 4 {
            // Jump faster over incompressible sections. Note the variant
            // difference: the noDict driver folds the +1 into `step` before
            // the lazy-skipping comparison, this one does not.
            let step = (ip - anchor) >> K_SEARCH_STRENGTH;
            ip += step + 1;
            ctx.lazy_skipping = step > K_LAZY_SKIPPING_STEP;
            continue;
        }

        // Try to find a better solution.
        if depth >= 1 {
            while (ip as i64) < i_limit {
                ip += 1;
                curr += 1;
                // Check repcode (C guards on `offBase`, which is never 0).
                {
                    let window_low = window_low_at(curr);
                    let rep_index = curr.wrapping_sub(offset_1);
                    if overlap_ok(rep_index)
                        && offset_1 <= curr - window_low
                        && read32(data, to_pos(ip)) == read32(data, pos_seg(rep_index as usize))
                    {
                        let rep_idx = rep_index as usize;
                        let rep_length = count_2segments(
                            data,
                            to_pos(ip) + 4,
                            pos_seg(rep_idx) + 4,
                            block_end,
                            match_end_pos(rep_idx),
                            prefix_start_pos,
                        ) + 4;
                        let gain2 = (rep_length * 3) as i32;
                        let gain1 =
                            (match_length * 3) as i32 - highbit32(off_base as u32) as i32 + 1;
                        if rep_length >= 4 && gain2 > gain1 {
                            match_length = rep_length;
                            off_base = 1;
                            start = ip;
                        }
                    }
                }
                // Search match, depth 1.
                {
                    let mut ofb_candidate: u64 = 999_999_999;
                    let ml2 = search_max(ctx, data, ip, iend, &mut ofb_candidate, win, true, None);
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
                    curr += 1;
                    // Check repcode.
                    {
                        let window_low = window_low_at(curr);
                        let rep_index = curr.wrapping_sub(offset_1);
                        if overlap_ok(rep_index)
                            && offset_1 <= curr - window_low
                            && read32(data, to_pos(ip)) == read32(data, pos_seg(rep_index as usize))
                        {
                            let rep_idx = rep_index as usize;
                            let rep_length = count_2segments(
                                data,
                                to_pos(ip) + 4,
                                pos_seg(rep_idx) + 4,
                                block_end,
                                match_end_pos(rep_idx),
                                prefix_start_pos,
                            ) + 4;
                            let gain2 = (rep_length * 4) as i32;
                            let gain1 =
                                (match_length * 4) as i32 - highbit32(off_base as u32) as i32 + 1;
                            if rep_length >= 4 && gain2 > gain1 {
                                match_length = rep_length;
                                off_base = 1;
                                start = ip;
                            }
                        }
                    }
                    // Search match, depth 2.
                    {
                        let mut ofb_candidate: u64 = 999_999_999;
                        let ml2 =
                            search_max(ctx, data, ip, iend, &mut ofb_candidate, win, true, None);
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

        // Catch up (real offsets only), bounded by the match's segment.
        if off_base > 3 {
            let offset = (off_base - 3) as usize;
            let match_index = start - offset;
            let in_dict = match_index < dict_limit;
            let mut match_pos = if in_dict {
                match_index - dict_bias
            } else {
                match_index - seg_bias
            };
            let m_start_pos = if in_dict {
                dict_start_pos
            } else {
                prefix_start_pos
            };
            while start > anchor
                && match_pos > m_start_pos
                && data[to_pos(start) - 1] == data[match_pos - 1]
            {
                start -= 1;
                match_pos -= 1;
                match_length += 1;
            }
            offset_2 = offset_1;
            offset_1 = offset as u32;
        }

        extdict_store_and_repcodes(
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
            win,
            block_end,
        );
    }

    // Save reps for the next block — no offsetSaved rotation in this variant.
    rep[0] = offset_1;
    rep[1] = offset_2;

    to_pos(iend) - to_pos(anchor)
}

/// `_storeSequence` + the immediate-repcode tail of the extDict driver:
/// two-segment reads with per-use window validity.
#[allow(clippy::too_many_arguments)]
fn extdict_store_and_repcodes(
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
    win: &Window,
    block_end: usize,
) {
    let seg_bias = win.seg_bias as usize;
    let dict_bias = win.dict_bias as usize;
    let to_pos = |idx: usize| idx - seg_bias;
    let dict_limit = win.dict_limit as usize;
    let max_distance = 1u32 << ctx.window_log;

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
            row_fill_hash_cache(ctx, data, from, i_limit, seg_bias);
        }
        ctx.lazy_skipping = false;
    }

    // Check immediate repcode.
    while (*ip as i64) <= i_limit {
        let rep_current = *ip as u32;
        let window_low = if rep_current - win.low_limit > max_distance {
            rep_current - max_distance
        } else {
            win.low_limit
        };
        let rep_index = rep_current.wrapping_sub(*offset_2);
        if !((dict_limit as u32).wrapping_sub(1).wrapping_sub(rep_index) >= 3
            && *offset_2 <= rep_current - window_low)
        {
            break;
        }
        let rep_idx = rep_index as usize;
        let rep_match_pos = if rep_idx < dict_limit {
            rep_idx - dict_bias
        } else {
            rep_idx - seg_bias
        };
        if read32(data, to_pos(*ip)) != read32(data, rep_match_pos) {
            break;
        }
        let rep_end_pos = if rep_idx < dict_limit {
            dict_limit - dict_bias
        } else {
            block_end
        };
        let m_len = count_2segments(
            data,
            to_pos(*ip) + 4,
            rep_match_pos + 4,
            block_end,
            rep_end_pos,
            dict_limit - seg_bias,
        ) + 4;
        std::mem::swap(offset_1, offset_2); // swap offset history
        store.store_seq(&[], 1, m_len as u32); // REPCODE1, no literals
        *ip += m_len;
        *anchor = *ip;
    }
}
