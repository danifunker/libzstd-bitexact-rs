//! The *post*-block splitter (`ZSTD_compressBlock_splitBlock`, zstd_compress.c):
//! after the match finder fills a seqStore for a full block, recursively probe
//! whether splitting the sequences into partitions and emitting each as its
//! own block (with its own entropy tables) is estimated cheaper, then emit the
//! partitions. Auto-enabled when `strategy >= btopt && windowLog >= 17`.
//!
//! Because partitions may be emitted raw or RLE (which a decoder processes
//! without touching repcode history), the splitter tracks two repcode
//! histories: `cRep` follows the seqStore exactly, `dRep` simulates the
//! decoder; diverging repcodes are rewritten as raw offsets
//! (`ZSTD_seqStore_resolveOffCodes`).

use crate::compress::CParams;
use crate::error::Error;
use crate::huffman_encode;
use crate::literals_encode::HufState;
use crate::sequences_encode::{
    self, FseEntropyState, LONG_NB_SEQ, LongLengthType, SeqDef, SeqStore, SeqView,
    SymbolEncodingType,
};

const MIN_SEQUENCES_BLOCK_SPLITTING: usize = 300;
const ZSTD_MAX_NB_BLOCK_SPLITS: usize = 196;
const COMPRESS_LITERALS_SIZE_MIN: usize = 63;
const RLE_MAX_LENGTH: usize = 25;
const BLOCK_HEADER_SIZE: usize = 3;

/// `ZSTD_resolveBlockSplitterMode` (auto).
pub(crate) fn block_splitter_enabled(cparams: &CParams) -> bool {
    use crate::compress::Strategy;
    matches!(
        cparams.strategy,
        Strategy::Btopt | Strategy::Btultra | Strategy::Btultra2
    ) && cparams.window_log >= 17
}

// --- Chunk derivation -------------------------------------------------------------

/// One partition window over the parent store (`ZSTD_deriveSeqStoreChunk`).
#[derive(Clone, Copy)]
struct Chunk {
    seq_start: usize,
    seq_end: usize,
    lit_start: usize,
    lit_end: usize,
    llt: LongLengthType,
    /// Relative to `seq_start`.
    llp: u32,
}

/// Literals bytes of sequences `[start, end)` (absolute long-length pos).
fn count_literals_bytes(store: &SeqStore, start: usize, end: usize) -> usize {
    let mut bytes = 0usize;
    for (i, seq) in store.sequences[start..end].iter().enumerate() {
        bytes += seq.lit_length as usize;
        if start + i == store.long_length_pos as usize
            && store.long_length_type == LongLengthType::LiteralLength
        {
            bytes += 0x10000;
        }
    }
    bytes
}

/// Match bytes of sequences `[start, end)`.
fn count_match_bytes(store: &SeqStore, start: usize, end: usize) -> usize {
    let mut bytes = 0usize;
    for (i, seq) in store.sequences[start..end].iter().enumerate() {
        bytes += seq.ml_base as usize + sequences_encode::MIN_MATCH as usize;
        if start + i == store.long_length_pos as usize
            && store.long_length_type == LongLengthType::MatchLength
        {
            bytes += 0x10000;
        }
    }
    bytes
}

/// `ZSTD_deriveSeqStoreChunk`.
fn derive_chunk(store: &SeqStore, start_idx: usize, end_idx: usize) -> Chunk {
    let lit_start = count_literals_bytes(store, 0, start_idx);
    // Long-length marker: kept only when it falls inside [start, end] (the
    // upper bound is inclusive in C — quirk preserved).
    let (llt, llp) = if store.long_length_type != LongLengthType::None {
        let pos = store.long_length_pos as usize;
        if pos < start_idx || pos > end_idx {
            (LongLengthType::None, 0)
        } else {
            (store.long_length_type, (pos - start_idx) as u32)
        }
    } else {
        (LongLengthType::None, 0)
    };
    let lit_end = if end_idx == store.sequences.len() {
        // Final chunk also covers possible last literals.
        store.literals.len()
    } else {
        // Recount with the chunk's own long-length view: a marker outside the
        // chunk no longer contributes its 0x10000.
        let mut bytes = 0usize;
        for (i, seq) in store.sequences[start_idx..end_idx].iter().enumerate() {
            bytes += seq.lit_length as usize;
            if llt == LongLengthType::LiteralLength && i == llp as usize {
                bytes += 0x10000;
            }
        }
        lit_start + bytes
    };
    Chunk {
        seq_start: start_idx,
        seq_end: end_idx,
        lit_start,
        lit_end,
        llt,
        llp,
    }
}

fn chunk_view<'a>(store: &'a SeqStore, chunk: &Chunk) -> SeqView<'a> {
    SeqView {
        sequences: &store.sequences[chunk.seq_start..chunk.seq_end],
        literals: &store.literals[chunk.lit_start..chunk.lit_end],
        long_length_type: chunk.llt,
        long_length_pos: chunk.llp,
    }
}

// --- Repcode reconciliation ---------------------------------------------------------

/// `ZSTD_updateRep`.
fn update_rep(rep: &mut [u32; 3], off_base: u32, ll0: bool) {
    if off_base > 3 {
        rep[2] = rep[1];
        rep[1] = rep[0];
        rep[0] = off_base - 3;
    } else {
        let rep_code = off_base - 1 + ll0 as u32;
        if rep_code > 0 {
            let current = if rep_code == 3 {
                rep[0] - 1
            } else {
                rep[rep_code as usize]
            };
            rep[2] = if rep_code >= 2 { rep[1] } else { rep[2] };
            rep[1] = rep[0];
            rep[0] = current;
        }
    }
}

/// `ZSTD_resolveRepcodeToRawOffset`.
fn resolve_repcode_to_raw(rep: &[u32; 3], off_base: u32, ll0: bool) -> u32 {
    let adjusted = off_base - 1 + ll0 as u32;
    if adjusted == 3 {
        return rep[0].wrapping_sub(1);
    }
    rep[adjusted as usize]
}

/// `ZSTD_seqStore_resolveOffCodes` over the chunk's sequences (relative llp).
fn resolve_off_codes(
    seqs: &mut [SeqDef],
    llt: LongLengthType,
    llp: u32,
    d_rep: &mut [u32; 3],
    c_rep: &mut [u32; 3],
) {
    let long_lit_idx = if llt == LongLengthType::LiteralLength {
        llp as usize
    } else {
        seqs.len()
    };
    for (idx, seq) in seqs.iter_mut().enumerate() {
        let ll0 = seq.lit_length == 0 && idx != long_lit_idx;
        let off_base = seq.off_base;
        if off_base <= 3 {
            let d_raw = resolve_repcode_to_raw(d_rep, off_base, ll0);
            let c_raw = resolve_repcode_to_raw(c_rep, off_base, ll0);
            if d_raw != c_raw {
                seq.off_base = c_raw + 3;
            }
        }
        update_rep(d_rep, seq.off_base, ll0);
        update_rep(c_rep, off_base, ll0);
    }
}

// --- Entropy estimation -------------------------------------------------------------

/// `ZSTD_buildBlockEntropyStats_literals`, estimation flavor: pick the
/// literals mode and produce the candidate table + description size.
fn build_entropy_stats_literals(
    literals: &[u8],
    prev: &HufState,
    optimal_depth: bool,
) -> (SymbolEncodingType, usize, HufState) {
    use crate::huffman_encode::HufRepeat;
    let src_size = literals.len();
    let candidate = prev.clone();

    let min_lit_size = if prev.repeat == HufRepeat::Valid {
        6
    } else {
        COMPRESS_LITERALS_SIZE_MIN
    };
    if src_size <= min_lit_size {
        return (SymbolEncodingType::Basic, 0, candidate);
    }

    let mut count = [0u32; 256];
    for &b in literals {
        count[b as usize] += 1;
    }
    let mut max_symbol = 255u32;
    while max_symbol > 0 && count[max_symbol as usize] == 0 {
        max_symbol -= 1;
    }
    let largest = *count.iter().max().unwrap() as usize;
    if largest == src_size {
        return (SymbolEncodingType::Rle, 0, candidate);
    }
    if largest <= (src_size >> 7) + 4 {
        return (SymbolEncodingType::Basic, 0, candidate);
    }

    let mut repeat = prev.repeat;
    if repeat == HufRepeat::Check
        && !prev
            .table
            .as_ref()
            .is_some_and(|t| huffman_encode::validate_ctable(t, &count, max_symbol))
    {
        repeat = HufRepeat::None;
    }

    let huff_log =
        huffman_encode::huf_optimal_table_log(11, src_size, max_symbol, &count, optimal_depth);
    let Ok(new_table) = huffman_encode::build_ctable(&count, max_symbol, huff_log) else {
        return (SymbolEncodingType::Basic, 0, candidate);
    };
    let new_c_size = huffman_encode::estimate_compressed_size(&new_table, &count, max_symbol);
    let Ok(desc) = huffman_encode::write_ctable(&new_table) else {
        return (SymbolEncodingType::Basic, 0, candidate);
    };
    let h_size = desc.len();

    if repeat != HufRepeat::None {
        let old = prev.table.as_ref().expect("repeat implies a table");
        let old_c_size = huffman_encode::estimate_compressed_size(old, &count, max_symbol);
        if old_c_size < src_size && (old_c_size <= h_size + new_c_size || h_size + 12 >= src_size) {
            return (SymbolEncodingType::Repeat, 0, candidate);
        }
    }
    if new_c_size + h_size >= src_size {
        return (SymbolEncodingType::Basic, 0, candidate);
    }
    (
        SymbolEncodingType::Compressed,
        h_size,
        HufState {
            table: Some(new_table),
            repeat: HufRepeat::Check,
        },
    )
}

/// `ZSTD_estimateBlockSize_literal`.
fn estimate_block_size_literal(
    literals: &[u8],
    h_type: SymbolEncodingType,
    des_size: usize,
    huf: &HufState,
    write_entropy: bool,
) -> usize {
    let lit_size = literals.len();
    let header_size = 3 + (lit_size >= 1024) as usize + (lit_size >= 16384) as usize;
    let single_stream = lit_size < 256;
    match h_type {
        SymbolEncodingType::Basic => lit_size,
        SymbolEncodingType::Rle => 1,
        SymbolEncodingType::Compressed | SymbolEncodingType::Repeat => {
            let mut count = [0u32; 256];
            for &b in literals {
                count[b as usize] += 1;
            }
            let mut max_symbol = 255u32;
            while max_symbol > 0 && count[max_symbol as usize] == 0 {
                max_symbol -= 1;
            }
            let Some(table) = huf.table.as_ref() else {
                return lit_size;
            };
            let mut est = huffman_encode::estimate_compressed_size(table, &count, max_symbol);
            if write_entropy {
                est += des_size;
            }
            if !single_stream {
                est += 6; // 4-stream jump table
            }
            est + header_size
        }
    }
}

/// `ZSTD_estimateBlockSize_symbolType`.
fn estimate_symbol_type(
    enc_type: SymbolEncodingType,
    codes: &[u8],
    max_code: u32,
    ctable: &crate::fse_encode::FseCTable,
    additional_bits: Option<&[u32]>,
    default_norm: &[i16],
    default_norm_log: u32,
) -> usize {
    let mut count = vec![0u32; max_code as usize + 1];
    for &c in codes {
        count[c as usize] += 1;
    }
    let mut max = max_code;
    while max > 0 && count[max as usize] == 0 {
        max -= 1;
    }

    let bits: u64 = match enc_type {
        SymbolEncodingType::Basic => {
            sequences_encode::cross_entropy_cost(default_norm, default_norm_log, &count, max)
        }
        SymbolEncodingType::Rle => 0,
        SymbolEncodingType::Compressed | SymbolEncodingType::Repeat => {
            match sequences_encode::fse_bit_cost(ctable, &count, max) {
                Some(c) => c,
                None => return codes.len() * 10,
            }
        }
    };
    let mut total_bits = bits;
    for &c in codes {
        total_bits += match additional_bits {
            Some(ab) => ab[c as usize] as u64,
            None => c as u64, // offsets: the code is the extra-bit count
        };
    }
    (total_bits >> 3) as usize
}

/// `ZSTD_buildEntropyStatisticsAndEstimateSubBlockSize`: run the stats build
/// against scratch state, then estimate the block size.
fn estimate_sub_block_size(
    view: &SeqView<'_>,
    prev_entropy: &FseEntropyState,
    strategy: i32,
    optimal_depth: bool,
) -> Result<usize, Error> {
    use crate::block::{
        LL_BITS, LL_DEFAULT_LOG, LL_DEFAULT_NORM, ML_BITS, ML_DEFAULT_LOG, ML_DEFAULT_NORM,
        OF_DEFAULT_LOG, OF_DEFAULT_NORM,
    };
    let (h_type, des_size, huf_candidate) =
        build_entropy_stats_literals(view.literals, &prev_entropy.huf, optimal_depth);

    let nb_seq = view.sequences.len();
    let seq_header_size = 1 + 1 + (nb_seq >= 128) as usize + (nb_seq >= LONG_NB_SEQ) as usize;

    let seq_estimate = if nb_seq != 0 {
        let mut scratch = prev_entropy.clone();
        let stats = sequences_encode::build_sequences_statistics(view, &mut scratch, strategy)?;
        let mut est = 0usize;
        est += estimate_symbol_type(
            stats.of_type,
            &stats.of_codes,
            sequences_encode::MAX_OFF,
            &stats.of_ct,
            None,
            &OF_DEFAULT_NORM,
            OF_DEFAULT_LOG,
        );
        est += estimate_symbol_type(
            stats.ll_type,
            &stats.ll_codes,
            sequences_encode::MAX_LL,
            &stats.ll_ct,
            Some(&LL_BITS),
            &LL_DEFAULT_NORM,
            LL_DEFAULT_LOG,
        );
        est += estimate_symbol_type(
            stats.ml_type,
            &stats.ml_codes,
            sequences_encode::MAX_ML,
            &stats.ml_ct,
            Some(&ML_BITS),
            &ML_DEFAULT_NORM,
            ML_DEFAULT_LOG,
        );
        est += stats.table_bytes.len(); // writeSeqEntropy = 1
        est + seq_header_size
    } else {
        seq_header_size
    };

    let lit_estimate = estimate_block_size_literal(
        view.literals,
        h_type,
        des_size,
        if h_type == SymbolEncodingType::Compressed {
            &huf_candidate
        } else {
            &prev_entropy.huf
        },
        h_type == SymbolEncodingType::Compressed,
    );

    Ok(lit_estimate + seq_estimate + BLOCK_HEADER_SIZE)
}

// --- Split derivation ---------------------------------------------------------------

/// `ZSTD_deriveBlockSplitsHelper`.
#[allow(clippy::too_many_arguments)]
fn derive_splits_helper(
    splits: &mut Vec<u32>,
    start_idx: usize,
    end_idx: usize,
    store: &SeqStore,
    prev_entropy: &FseEntropyState,
    strategy: i32,
    optimal_depth: bool,
) {
    if end_idx - start_idx < MIN_SEQUENCES_BLOCK_SPLITTING
        || splits.len() >= ZSTD_MAX_NB_BLOCK_SPLITS
    {
        return;
    }
    let mid_idx = (start_idx + end_idx) / 2;
    let full = derive_chunk(store, start_idx, end_idx);
    let first = derive_chunk(store, start_idx, mid_idx);
    let second = derive_chunk(store, mid_idx, end_idx);
    let (Ok(est_full), Ok(est_first), Ok(est_second)) = (
        estimate_sub_block_size(
            &chunk_view(store, &full),
            prev_entropy,
            strategy,
            optimal_depth,
        ),
        estimate_sub_block_size(
            &chunk_view(store, &first),
            prev_entropy,
            strategy,
            optimal_depth,
        ),
        estimate_sub_block_size(
            &chunk_view(store, &second),
            prev_entropy,
            strategy,
            optimal_depth,
        ),
    ) else {
        return;
    };
    if est_first + est_second < est_full {
        derive_splits_helper(
            splits,
            start_idx,
            mid_idx,
            store,
            prev_entropy,
            strategy,
            optimal_depth,
        );
        splits.push(mid_idx as u32);
        derive_splits_helper(
            splits,
            mid_idx,
            end_idx,
            store,
            prev_entropy,
            strategy,
            optimal_depth,
        );
    }
}

/// `ZSTD_deriveBlockSplits`.
fn derive_splits(
    store: &SeqStore,
    nb_seq: usize,
    prev_entropy: &FseEntropyState,
    strategy: i32,
    optimal_depth: bool,
) -> Vec<u32> {
    let mut splits = Vec::new();
    if nb_seq <= 4 {
        return splits;
    }
    derive_splits_helper(
        &mut splits,
        0,
        nb_seq,
        store,
        prev_entropy,
        strategy,
        optimal_depth,
    );
    splits
}

// --- Partition emission ----------------------------------------------------------------

/// `ZSTD_compressSeqStore_singleBlock`: compress one chunk into `out`
/// (header included). Commits `entropy` only for compressed output; resets
/// `d_rep` for raw/RLE output.
#[allow(clippy::too_many_arguments)]
fn compress_chunk_single_block(
    out: &mut Vec<u8>,
    store: &mut SeqStore,
    chunk: &Chunk,
    entropy: &mut FseEntropyState,
    d_rep: &mut [u32; 3],
    c_rep: &mut [u32; 3],
    src_part: &[u8],
    strategy: i32,
    last_block: bool,
    is_partition: bool,
    is_first_block: bool,
) -> Result<usize, Error> {
    use crate::compress::{is_rle, push_block_header};
    use crate::sequences_encode::FseRepeat;

    let d_rep_original = *d_rep;
    if is_partition {
        resolve_off_codes(
            &mut store.sequences[chunk.seq_start..chunk.seq_end],
            chunk.llt,
            chunk.llp,
            d_rep,
            c_rep,
        );
    }

    let view = chunk_view(store, chunk);
    let result = sequences_encode::entropy_compress_seq_view(
        &view,
        entropy,
        strategy,
        false, // literal compression never disabled at bt levels
        src_part.len(),
    )?;

    let c_size = match result {
        None => {
            push_block_header(out, last_block, 0, src_part.len());
            out.extend_from_slice(src_part);
            *d_rep = d_rep_original;
            BLOCK_HEADER_SIZE + src_part.len()
        }
        Some((body, next_entropy)) => {
            if !is_first_block && body.len() < RLE_MAX_LENGTH && is_rle(src_part) {
                push_block_header(out, last_block, 1, src_part.len());
                out.push(src_part[0]);
                *d_rep = d_rep_original;
                BLOCK_HEADER_SIZE + 1
            } else {
                *entropy = next_entropy;
                push_block_header(out, last_block, 2, body.len());
                out.extend_from_slice(&body);
                BLOCK_HEADER_SIZE + body.len()
            }
        }
    };

    if entropy.of_repeat == FseRepeat::Valid {
        entropy.of_repeat = FseRepeat::Check;
    }
    Ok(c_size)
}

/// `ZSTD_compressBlock_splitBlock_internal`: derive partitions and emit them.
/// Returns the total compressed size; `rep` is left holding the next block's
/// repcode history (the decoder-simulated `dRep` when partitions were used).
#[allow(clippy::too_many_arguments)]
pub(crate) fn compress_block_split(
    out: &mut Vec<u8>,
    store: &mut SeqStore,
    entropy: &mut FseEntropyState,
    rep: &mut [u32; 3],
    matcher_rep: [u32; 3],
    strategy: i32,
    block: &[u8],
    last_block: bool,
    is_first_block: bool,
) -> Result<usize, Error> {
    let nb_seq = store.sequences.len();
    let optimal_depth = strategy >= 8; // HUF_OPTIMAL_DEPTH_THRESHOLD
    let partitions = derive_splits(store, nb_seq, entropy, strategy, optimal_depth);

    let mut d_rep = *rep;
    let mut c_rep = *rep;

    if partitions.is_empty() {
        // No splits: ordinary single-block emission; the matcher's evolved
        // repcodes become the next block's history only when the block is
        // actually emitted compressed (C confirms via blockState swap).
        let chunk = derive_chunk(store, 0, nb_seq);
        let entropy_before = entropy.clone();
        let c_size = compress_chunk_single_block(
            out,
            store,
            &chunk,
            entropy,
            &mut d_rep,
            &mut c_rep,
            block,
            strategy,
            last_block,
            false,
            is_first_block,
        )?;
        // Compressed iff the entropy state was committed (raw/RLE leave it
        // untouched except the offcode Valid->Check rule, which C applies to
        // the kept state too). Detect commit by comparing block kind: a
        // compressed block was written when out's last block header type is 2.
        let _ = entropy_before;
        let header_at = out.len() - c_size;
        let block_type = (out[header_at] >> 1) & 3;
        if block_type == 2 {
            *rep = matcher_rep;
        }
        return Ok(c_size);
    }

    let mut total = 0usize;
    let mut src_bytes_total = 0usize;
    let mut ip_at = 0usize;
    let num_splits = partitions.len();
    let mut curr = derive_chunk(store, 0, partitions[0] as usize);

    for i in 0..=num_splits {
        let last_partition = i == num_splits;
        let mut src_bytes = count_literals_bytes(store, curr.seq_start, curr.seq_end)
            + count_match_bytes(store, curr.seq_start, curr.seq_end);
        src_bytes_total += src_bytes;
        let mut last_block_entire_src = false;

        let next = if last_partition {
            src_bytes += block.len() - src_bytes_total;
            last_block_entire_src = last_block;
            None
        } else {
            let end = if i + 1 == num_splits {
                nb_seq
            } else {
                partitions[i + 1] as usize
            };
            Some(derive_chunk(store, partitions[i] as usize, end))
        };

        let src_part = &block[ip_at..ip_at + src_bytes];
        let c_size_chunk = compress_chunk_single_block(
            out,
            store,
            &curr,
            entropy,
            &mut d_rep,
            &mut c_rep,
            src_part,
            strategy,
            last_block_entire_src,
            true,
            is_first_block,
        )?;
        ip_at += src_bytes;
        total += c_size_chunk;
        if let Some(n) = next {
            curr = n;
        }
    }

    *rep = d_rep;
    Ok(total)
}
