//! Huffman *compression*-side primitives: building the canonical code table
//! from a histogram (`HUF_buildCTable` = `HUF_sort` + `HUF_buildTree` +
//! `HUF_setMaxHeight` + `HUF_buildCTableFromTree`), serializing the table
//! (`HUF_writeCTable`, both the FSE-compressed-weights and the direct 4-bit
//! paths), and the one- and four-stream encoders. Ports of `huf_compress.c`
//! from the bundled zstd 1.5.7.
//!
//! The bitstream writer here is the modern zstd `HUF_CStream` (values packed
//! into the top of a 64-bit container, flushed from the bottom). The unrolled
//! / dual-container loop in C is purely an instruction-level-parallelism
//! optimization: it encodes the same symbols in the same reverse order and the
//! merged container holds them in the same bit positions, so a single-container
//! encode that flushes after every symbol produces byte-identical output (flush
//! timing never changes the bytes in this scheme). We therefore use the simple
//! form and verify by round-tripping through the decoder in [`crate::huffman`].
#![allow(dead_code)] // wired into the public compressor in a later milestone
#![allow(clippy::needless_range_loop)] // index loops mirror the C ports

use crate::error::Error;
use crate::fse_encode::{self, Normalized};

const HUF_TABLELOG_MAX: u32 = 12;
const HUF_TABLELOG_DEFAULT: u32 = 11;
const HUF_SYMBOLVALUE_MAX: usize = 255;
/// `STARTNODE`: first index used for internal tree nodes.
const STARTNODE: i32 = (HUF_SYMBOLVALUE_MAX + 1) as i32;

const RANK_POSITION_TABLE_SIZE: usize = 192;
const RANK_POSITION_MAX_COUNT_LOG: usize = 32;
const RANK_POSITION_LOG_BUCKETS_BEGIN: usize =
    (RANK_POSITION_TABLE_SIZE - 1) - RANK_POSITION_MAX_COUNT_LOG - 1;

fn highbit32(x: u32) -> u32 {
    debug_assert!(x >= 1);
    31 - x.leading_zeros()
}

fn rank_distinct_cutoff() -> u32 {
    RANK_POSITION_LOG_BUCKETS_BEGIN as u32 + highbit32(RANK_POSITION_LOG_BUCKETS_BEGIN as u32)
}

/// `HUF_getIndex`: bucket index for a symbol count.
fn huf_get_index(count: u32) -> u32 {
    let cutoff = rank_distinct_cutoff();
    if count < cutoff {
        count
    } else {
        highbit32(count) + RANK_POSITION_LOG_BUCKETS_BEGIN as u32
    }
}

/// One `nodeElt` of the working Huffman tree.
#[derive(Clone, Copy, Default)]
struct NodeElt {
    count: u32,
    parent: u16,
    byte: u8,
    nb_bits: u8,
}

/// A built Huffman compression table: per-symbol code length and canonical
/// code value, plus the table log (= max code length).
#[derive(Clone)]
pub(crate) struct HufCTable {
    pub(crate) table_log: u32,
    pub(crate) max_symbol: u32,
    nb_bits: [u8; HUF_SYMBOLVALUE_MAX + 1],
    code: [u16; HUF_SYMBOLVALUE_MAX + 1],
}

impl HufCTable {
    /// `HUF_getNbBitsFromCTable`: the code length of `symbol`, or 0 when the
    /// table does not cover it. Used to seed the optimal parser's literal cost
    /// model from a dictionary's Huffman table.
    pub(crate) fn nb_bits_of(&self, symbol: u32) -> u32 {
        if symbol > self.max_symbol {
            return 0;
        }
        u32::from(self.nb_bits[symbol as usize])
    }
}

/// `HUF_repeat`: whether a previous block's table may be reused.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) enum HufRepeat {
    #[default]
    None,
    Check,
    Valid,
}

/// `HUF_validateCTable`: the old table can encode the new histogram.
pub(crate) fn validate_ctable(ct: &HufCTable, count: &[u32], max_symbol: u32) -> bool {
    if ct.max_symbol < max_symbol {
        return false;
    }
    (0..=max_symbol as usize).all(|s| count[s] == 0 || ct.nb_bits[s] != 0)
}

/// `HUF_estimateCompressedSize`: stream bytes under `ct` for this histogram.
pub(crate) fn estimate_compressed_size(ct: &HufCTable, count: &[u32], max_symbol: u32) -> usize {
    let bits: u64 = (0..=max_symbol as usize)
        .map(|s| ct.nb_bits[s] as u64 * count[s] as u64)
        .sum();
    (bits >> 3) as usize
}

/// A node array with the C `-1` barrier slot: logical index `i` (which ranges
/// from `-1`) maps to `nodes[(i + 1) as usize]`.
struct Nodes(Vec<NodeElt>);
impl Nodes {
    fn new() -> Self {
        Nodes(vec![NodeElt::default(); 2 * (HUF_SYMBOLVALUE_MAX + 1) + 1])
    }
    fn get(&self, i: i32) -> NodeElt {
        self.0[(i + 1) as usize]
    }
    fn set(&mut self, i: i32, v: NodeElt) {
        self.0[(i + 1) as usize] = v;
    }
    fn count(&self, i: i32) -> u32 {
        self.0[(i + 1) as usize].count
    }
    fn set_count(&mut self, i: i32, c: u32) {
        self.0[(i + 1) as usize].count = c;
    }
    fn nb_bits(&self, i: i32) -> u8 {
        self.0[(i + 1) as usize].nb_bits
    }
    fn set_nb_bits(&mut self, i: i32, b: u8) {
        self.0[(i + 1) as usize].nb_bits = b;
    }
    fn parent(&self, i: i32) -> u16 {
        self.0[(i + 1) as usize].parent
    }
    fn set_parent(&mut self, i: i32, p: u16) {
        self.0[(i + 1) as usize].parent = p;
    }
}

/// `HUF_sort`: sort symbols `[0, max_symbol]` by count, decreasing, into
/// `huffNode[0..]`. Bucket by `HUF_getIndex`, then sort within each log-bucket.
fn huf_sort(nodes: &mut Nodes, count: &[u32], max_symbol: u32) {
    let alphabet = max_symbol as usize + 1;
    let mut base = [0u32; RANK_POSITION_TABLE_SIZE];
    let mut curr = [0u32; RANK_POSITION_TABLE_SIZE];

    for n in 0..alphabet {
        let lower = huf_get_index(count[n]) as usize;
        base[lower] += 1;
    }
    for n in (1..RANK_POSITION_TABLE_SIZE).rev() {
        base[n - 1] += base[n];
        curr[n - 1] = base[n - 1];
    }
    // Place each symbol into its bucket (huffNode logical indices start at 0).
    for n in 0..alphabet {
        let c = count[n];
        let r = huf_get_index(c) as usize + 1;
        let pos = curr[r] as usize;
        curr[r] += 1;
        nodes.set(
            pos as i32,
            NodeElt {
                count: c,
                byte: n as u8,
                parent: 0,
                nb_bits: 0,
            },
        );
    }
    // Sort within each distinct-count log bucket (descending by count).
    let cutoff = rank_distinct_cutoff() as usize;
    for n in cutoff..(RANK_POSITION_TABLE_SIZE - 1) {
        let bucket_size = (curr[n] - base[n]) as i32;
        let start = base[n] as i32;
        if bucket_size > 1 {
            huf_quicksort(nodes, start, start + bucket_size - 1);
        }
    }
}

fn node_count(nodes: &Nodes, i: i32) -> u32 {
    nodes.count(i)
}

/// Descending insertion sort over logical node indices `[low, high]`.
fn huf_insertion_sort(nodes: &mut Nodes, low: i32, high: i32) {
    for i in (low + 1)..=high {
        let key = nodes.get(i);
        let mut j = i - 1;
        while j >= low && nodes.count(j) < key.count {
            let v = nodes.get(j);
            nodes.set(j + 1, v);
            j -= 1;
        }
        nodes.set(j + 1, key);
    }
}

fn huf_quicksort(nodes: &mut Nodes, mut low: i32, mut high: i32) {
    const INSERTION_THRESHOLD: i32 = 8;
    while high - low >= INSERTION_THRESHOLD {
        // Partition on the rightmost element, descending.
        let pivot = node_count(nodes, high);
        let mut i = low - 1;
        for j in low..high {
            if nodes.count(j) > pivot {
                i += 1;
                let (a, b) = (nodes.get(i), nodes.get(j));
                nodes.set(i, b);
                nodes.set(j, a);
            }
        }
        let (a, b) = (nodes.get(i + 1), nodes.get(high));
        nodes.set(i + 1, b);
        nodes.set(high, a);
        let idx = i + 1;
        if idx - low < high - idx {
            huf_quicksort(nodes, low, idx - 1);
            low = idx + 1;
        } else {
            huf_quicksort(nodes, idx + 1, high);
            high = idx - 1;
        }
    }
    huf_insertion_sort(nodes, low, high);
}

/// `HUF_buildTree`: build the unlimited-depth tree, returning `nonNullRank`
/// (index of the smallest-count leaf).
fn huf_build_tree(nodes: &mut Nodes, max_symbol: u32) -> i32 {
    let mut node_nb = STARTNODE;
    let mut non_null_rank = max_symbol as i32;
    while nodes.count(non_null_rank) == 0 {
        non_null_rank -= 1;
    }
    let mut low_s = non_null_rank;
    let node_root = node_nb + low_s - 1;
    let mut low_n = node_nb;
    nodes.set_count(node_nb, nodes.count(low_s) + nodes.count(low_s - 1));
    nodes.set_parent(low_s, node_nb as u16);
    nodes.set_parent(low_s - 1, node_nb as u16);
    node_nb += 1;
    low_s -= 2;
    for n in node_nb..=node_root {
        nodes.set_count(n, 1u32 << 30);
    }
    nodes.set_count(-1, 1u32 << 31); // barrier

    while node_nb <= node_root {
        let n1 = if nodes.count(low_s) < nodes.count(low_n) {
            let v = low_s;
            low_s -= 1;
            v
        } else {
            let v = low_n;
            low_n += 1;
            v
        };
        let n2 = if nodes.count(low_s) < nodes.count(low_n) {
            let v = low_s;
            low_s -= 1;
            v
        } else {
            let v = low_n;
            low_n += 1;
            v
        };
        nodes.set_count(node_nb, nodes.count(n1) + nodes.count(n2));
        nodes.set_parent(n1, node_nb as u16);
        nodes.set_parent(n2, node_nb as u16);
        node_nb += 1;
    }

    // Distribute weights (unlimited height).
    nodes.set_nb_bits(node_root, 0);
    for n in (STARTNODE..=(node_root - 1)).rev() {
        let pb = nodes.nb_bits(nodes.parent(n) as i32);
        nodes.set_nb_bits(n, pb + 1);
    }
    for n in 0..=non_null_rank {
        let pb = nodes.nb_bits(nodes.parent(n) as i32);
        nodes.set_nb_bits(n, pb + 1);
    }
    non_null_rank
}

/// `HUF_setMaxHeight`: clamp the tree to `target_nb_bits`, rebalancing to keep
/// it a valid canonical Huffman tree. Returns the resulting max code length.
fn huf_set_max_height(nodes: &mut Nodes, last_non_null: i32, target_nb_bits: u32) -> u32 {
    let largest_bits = nodes.nb_bits(last_non_null) as u32;
    if largest_bits <= target_nb_bits {
        return largest_bits;
    }

    let mut total_cost: i32 = 0;
    let base_cost: i32 = 1 << (largest_bits - target_nb_bits);
    let mut n = last_non_null;

    while nodes.nb_bits(n) as u32 > target_nb_bits {
        total_cost += base_cost - (1 << (largest_bits - nodes.nb_bits(n) as u32));
        nodes.set_nb_bits(n, target_nb_bits as u8);
        n -= 1;
    }
    while nodes.nb_bits(n) as u32 == target_nb_bits {
        n -= 1;
    }

    total_cost >>= largest_bits - target_nb_bits;

    const NO_SYMBOL: u32 = 0xF0F0_F0F0;
    let mut rank_last = [NO_SYMBOL; (HUF_TABLELOG_MAX + 2) as usize];

    {
        let mut current_nb_bits = target_nb_bits;
        let mut pos = n;
        while pos >= 0 {
            let nb = nodes.nb_bits(pos) as u32;
            if nb >= current_nb_bits {
                pos -= 1;
                continue;
            }
            current_nb_bits = nb;
            rank_last[(target_nb_bits - current_nb_bits) as usize] = pos as u32;
            pos -= 1;
        }
    }

    while total_cost > 0 {
        let mut n_bits_to_decrease = (highbit32(total_cost as u32) + 1) as usize;
        while n_bits_to_decrease > 1 {
            let high_pos = rank_last[n_bits_to_decrease];
            let low_pos = rank_last[n_bits_to_decrease - 1];
            if high_pos == NO_SYMBOL {
                n_bits_to_decrease -= 1;
                continue;
            }
            if low_pos == NO_SYMBOL {
                break;
            }
            let high_total = nodes.count(high_pos as i32);
            let low_total = 2 * nodes.count(low_pos as i32);
            if high_total <= low_total {
                break;
            }
            n_bits_to_decrease -= 1;
        }
        while n_bits_to_decrease <= HUF_TABLELOG_MAX as usize
            && rank_last[n_bits_to_decrease] == NO_SYMBOL
        {
            n_bits_to_decrease += 1;
        }
        total_cost -= 1 << (n_bits_to_decrease - 1);
        let target = rank_last[n_bits_to_decrease] as i32;
        nodes.set_nb_bits(target, nodes.nb_bits(target) + 1);

        if rank_last[n_bits_to_decrease - 1] == NO_SYMBOL {
            rank_last[n_bits_to_decrease - 1] = rank_last[n_bits_to_decrease];
        }
        if rank_last[n_bits_to_decrease] == 0 {
            rank_last[n_bits_to_decrease] = NO_SYMBOL;
        } else {
            rank_last[n_bits_to_decrease] -= 1;
            let p = rank_last[n_bits_to_decrease] as i32;
            if nodes.nb_bits(p) as u32 != target_nb_bits - n_bits_to_decrease as u32 {
                rank_last[n_bits_to_decrease] = NO_SYMBOL;
            }
        }
    }

    while total_cost < 0 {
        if rank_last[1] == NO_SYMBOL {
            while nodes.nb_bits(n) as u32 == target_nb_bits {
                n -= 1;
            }
            nodes.set_nb_bits(n + 1, nodes.nb_bits(n + 1) - 1);
            rank_last[1] = (n + 1) as u32;
            total_cost += 1;
            continue;
        }
        let p = rank_last[1] as i32 + 1;
        nodes.set_nb_bits(p, nodes.nb_bits(p) - 1);
        rank_last[1] += 1;
        total_cost += 1;
    }

    target_nb_bits
}

/// `HUF_buildCTableFromTree`: assign canonical codes (by rank) into the table.
fn build_ctable_from_tree(
    nodes: &Nodes,
    non_null_rank: i32,
    max_symbol: u32,
    max_nb_bits: u32,
) -> HufCTable {
    let mut nb_per_rank = [0u16; (HUF_TABLELOG_MAX + 1) as usize];
    let mut val_per_rank = [0u16; (HUF_TABLELOG_MAX + 1) as usize];
    let mut nb_bits = [0u8; HUF_SYMBOLVALUE_MAX + 1];
    let mut code = [0u16; HUF_SYMBOLVALUE_MAX + 1];

    for n in 0..=non_null_rank {
        nb_per_rank[nodes.nb_bits(n) as usize] += 1;
    }
    let mut min: u16 = 0;
    for r in (1..=max_nb_bits as usize).rev() {
        val_per_rank[r] = min;
        min += nb_per_rank[r];
        min >>= 1;
    }
    // nbBits per symbol (symbol order).
    for n in 0..=non_null_rank {
        let node = nodes.get(n);
        nb_bits[node.byte as usize] = node.nb_bits;
    }
    // Code value within rank (symbol order).
    for s in 0..=max_symbol as usize {
        let b = nb_bits[s] as usize;
        if b > 0 {
            code[s] = val_per_rank[b];
            val_per_rank[b] += 1;
        }
    }

    HufCTable {
        table_log: max_nb_bits,
        max_symbol,
        nb_bits,
        code,
    }
}

/// `HUF_buildCTable_wksp`: build the compression table from a histogram.
pub(crate) fn build_ctable(
    count: &[u32],
    max_symbol: u32,
    max_nb_bits: u32,
) -> Result<HufCTable, Error> {
    let max_nb_bits = if max_nb_bits == 0 {
        HUF_TABLELOG_DEFAULT
    } else {
        max_nb_bits
    };
    if max_symbol as usize > HUF_SYMBOLVALUE_MAX {
        return Err(Error::Encode("huffman max symbol too large"));
    }
    let mut nodes = Nodes::new();
    huf_sort(&mut nodes, count, max_symbol);
    let non_null_rank = huf_build_tree(&mut nodes, max_symbol);
    let max_nb_bits = huf_set_max_height(&mut nodes, non_null_rank, max_nb_bits);
    if max_nb_bits > HUF_TABLELOG_MAX {
        return Err(Error::Encode("huffman table log too large"));
    }
    Ok(build_ctable_from_tree(
        &nodes,
        non_null_rank,
        max_symbol,
        max_nb_bits,
    ))
}

/// `HUF_readCTable`: reconstruct a compression table from a serialized table
/// description — the same weight encoding [`crate::huffman::read_table`] decodes
/// into a decode table, rebuilt here into encoder form (per-symbol code length
/// and canonical code). Used to seed a frame's literals table from a trained
/// (`ZDICT`) dictionary (`ZSTD_loadCEntropy`). Returns the table, whether any
/// symbol carries a zero weight (`hasZeroWeights`, which keeps a dictionary's
/// table at `HUF_repeat_check` rather than promoting it to `valid`), and the
/// number of input bytes consumed.
pub(crate) fn read_ctable(src: &[u8]) -> Result<(HufCTable, bool, usize), Error> {
    let (weights, table_log, consumed) = crate::huffman::read_weights(src)?;
    let nb_symbols = weights.len();
    let max_symbol = (nb_symbols - 1) as u32;
    // `*hasZeroWeights = (rankVal[0] > 0)`: the implicit last weight is always
    // >= 1, so this is exactly "some symbol has weight 0".
    let has_zero_weights = weights.contains(&0);

    // `nbBits[n] = (tableLog + 1 - w) & -(w != 0)`.
    let mut nb_bits = [0u8; HUF_SYMBOLVALUE_MAX + 1];
    for n in 0..nb_symbols {
        let w = u32::from(weights[n]);
        nb_bits[n] = if w == 0 { 0 } else { (table_log + 1 - w) as u8 };
    }

    // Canonical code value, assigned in symbol order within each code-length
    // rank — the inverse of the decoder's weight-ordered table fill.
    let mut nb_per_rank = [0u16; (HUF_TABLELOG_MAX + 2) as usize];
    for n in 0..nb_symbols {
        nb_per_rank[nb_bits[n] as usize] += 1;
    }
    let mut val_per_rank = [0u16; (HUF_TABLELOG_MAX + 2) as usize];
    let mut min: u16 = 0;
    for r in (1..=table_log as usize).rev() {
        val_per_rank[r] = min;
        min += nb_per_rank[r];
        min >>= 1;
    }
    let mut code = [0u16; HUF_SYMBOLVALUE_MAX + 1];
    for n in 0..nb_symbols {
        let b = nb_bits[n] as usize;
        code[n] = val_per_rank[b];
        val_per_rank[b] += 1;
    }

    Ok((
        HufCTable {
            table_log,
            max_symbol,
            nb_bits,
            code,
        },
        has_zero_weights,
        consumed,
    ))
}

// --- HUF_CStream: values packed into the top of a 64-bit container ----------

struct HufCStream {
    container: u64,
    bit_pos: usize,
    out: Vec<u8>,
}

impl HufCStream {
    fn new() -> Self {
        HufCStream {
            container: 0,
            bit_pos: 0,
            out: Vec::new(),
        }
    }

    /// `HUF_addBits`: shift the container down by `nb_bits` and OR the code in
    /// at the top.
    fn add_bits(&mut self, code: u16, nb_bits: u8) {
        let nb = nb_bits as u32;
        if nb == 0 {
            return;
        }
        self.container >>= nb;
        self.container |= (code as u64) << (64 - nb);
        self.bit_pos += nb as usize;
    }

    /// `HUF_flushBits`: emit the complete bytes at the bottom of the live region.
    fn flush(&mut self) {
        if self.bit_pos == 0 {
            return;
        }
        let nb_bytes = self.bit_pos >> 3;
        let extracted = self.container >> (64 - self.bit_pos);
        for i in 0..nb_bytes {
            self.out.push((extracted >> (8 * i)) as u8);
        }
        self.bit_pos &= 7;
    }

    /// `HUF_closeCStream`: add the end mark, flush, and emit the final byte.
    fn close(mut self) -> Vec<u8> {
        self.add_bits(1, 1); // end mark
        self.flush();
        if self.bit_pos > 0 {
            let extracted = self.container >> (64 - self.bit_pos);
            self.out.push(extracted as u8);
        }
        self.out
    }
}

/// `HUF_compress1X_usingCTable`: encode `src` as a single Huffman stream.
///
/// Symbols are encoded in reverse order; the resulting bytes are independent of
/// flush cadence, so we flush after each symbol.
pub(crate) fn compress1x(ct: &HufCTable, src: &[u8]) -> Vec<u8> {
    let mut bitc = HufCStream::new();
    for &b in src.iter().rev() {
        let s = b as usize;
        bitc.add_bits(ct.code[s], ct.nb_bits[s]);
        bitc.flush();
    }
    bitc.close()
}

/// `HUF_compress4X_usingCTable`: four streams with a 6-byte jump table holding
/// the compressed sizes of the first three. Returns an empty vector (C's
/// "return 0") when the input is too small for four streams or a sub-stream
/// overflows the 16-bit jump-table field.
pub(crate) fn compress4x(ct: &HufCTable, src: &[u8]) -> Vec<u8> {
    if src.len() < 12 {
        return Vec::new(); // no saving possible: too small for 4 streams
    }
    let segment = src.len().div_ceil(4);
    let mut out = vec![0u8; 6];
    let bounds = [
        (0, segment),
        (segment, 2 * segment),
        (2 * segment, 3 * segment),
        (3 * segment, src.len()),
    ];
    for (i, &(start, end)) in bounds.iter().enumerate() {
        let stream = compress1x(ct, &src[start..end]);
        if stream.is_empty() || stream.len() > 65535 {
            return Vec::new();
        }
        if i < 3 {
            let size = stream.len() as u16;
            out[2 * i] = size as u8;
            out[2 * i + 1] = (size >> 8) as u8;
        }
        out.extend_from_slice(&stream);
    }
    out
}

// --- HUF_writeCTable: serialize the table as symbol weights -----------------

/// `HUF_compressWeights`: FSE-compress the weight array, or signal that it is
/// not worthwhile (returns `None`).
fn compress_weights(weights: &[u8]) -> Option<Vec<u8>> {
    let wt_size = weights.len();
    if wt_size <= 1 {
        return None;
    }
    let mut count = [0u32; HUF_TABLELOG_MAX as usize + 1];
    let mut max_symbol = 0usize;
    for &w in weights {
        count[w as usize] += 1;
        max_symbol = max_symbol.max(w as usize);
    }
    let max_count = *count[..=max_symbol].iter().max().unwrap();
    if max_count as usize == wt_size {
        return None; // single symbol (RLE) — caller falls back to direct
    }
    if max_count == 1 {
        return None; // not compressible
    }
    let table_log = fse_encode::optimal_table_log(6, wt_size, max_symbol as u32);
    let norm = match fse_encode::normalize_count(
        &count,
        wt_size,
        max_symbol as u32,
        table_log,
        false, // useLowProbCount = 0 for the huffman header
    ) {
        Ok(Normalized::Table(n)) => n,
        _ => return None,
    };
    let mut out = fse_encode::write_ncount(&norm, max_symbol as u32, table_log).ok()?;
    let ctable = fse_encode::build_ctable(&norm, max_symbol as u32, table_log);
    out.extend_from_slice(&fse_encode::fse_compress_using_ctable(&ctable, weights));
    Some(out)
}

/// `HUF_writeCTable`: emit the table description the decoder's
/// [`crate::huffman::read_table`] reads.
pub(crate) fn write_ctable(ct: &HufCTable) -> Result<Vec<u8>, Error> {
    let max_symbol = ct.max_symbol as usize;
    let huff_log = ct.table_log;

    // Symbol weights: weight = (huffLog + 1 - nbBits), 0 for absent symbols.
    // Only the first `max_symbol` weights are written; the last is implicit.
    let mut weights = vec![0u8; max_symbol];
    for n in 0..max_symbol {
        let nb = ct.nb_bits[n] as u32;
        weights[n] = if nb == 0 {
            0
        } else {
            (huff_log + 1 - nb) as u8
        };
    }

    // Try FSE-compressed weights; use them only when clearly smaller.
    if let Some(fse) = compress_weights(&weights) {
        let h_size = fse.len();
        if h_size > 1 && h_size < max_symbol / 2 {
            let mut out = Vec::with_capacity(1 + h_size);
            out.push(h_size as u8);
            out.extend_from_slice(&fse);
            return Ok(out);
        }
    }

    // Direct representation: header 128 + (maxSymbol - 1), weights packed as
    // high-nibble-first nibble pairs.
    if max_symbol > (256 - 128) {
        return Err(Error::Encode("too many huffman symbols for direct table"));
    }
    let mut out = vec![(128 + (max_symbol - 1)) as u8];
    let mut padded = weights.clone();
    padded.push(0); // guard for an odd symbol count
    for n in (0..max_symbol).step_by(2) {
        out.push((padded[n] << 4) + padded[n + 1]);
    }
    Ok(out)
}

/// `HUF_optimalTableLog`: the cheap FSE-based estimate for low strategies, or
/// the probing depth search (`HUF_flags_optimalDepth`, strategies >= btultra):
/// try every table log from the alphabet minimum upward, keeping the one with
/// the smallest (estimated stream + table description) size, stopping once
/// sizes regress.
pub(crate) fn huf_optimal_table_log(
    max_table_log: u32,
    src_size: usize,
    max_symbol: u32,
    count: &[u32; HUF_SYMBOLVALUE_MAX + 1],
    optimal_depth: bool,
) -> u32 {
    if !optimal_depth {
        return fse_encode::optimal_table_log_internal(max_table_log, src_size, max_symbol, 1);
    }
    let cardinality = (0..=max_symbol as usize).filter(|&s| count[s] != 0).count() as u32;
    let min_table_log = highbit32(cardinality) + 1;
    let mut opt_size = usize::MAX - 1;
    let mut opt_log = max_table_log;
    for guess in min_table_log..=max_table_log {
        let Ok(ct) = build_ctable(count, max_symbol, guess) else {
            continue;
        };
        let max_bits = ct.table_log;
        if max_bits < guess && guess > min_table_log {
            break;
        }
        let Ok(desc) = write_ctable(&ct) else {
            continue;
        };
        let new_size = estimate_compressed_size(&ct, count, max_symbol) + desc.len();
        if new_size > opt_size + 1 {
            break;
        }
        if new_size < opt_size {
            opt_size = new_size;
            opt_log = guess;
        }
    }
    opt_log
}

/// The outcome of trying to Huffman-compress a literals payload, mirroring the
/// `HUF_compress_internal` return signals.
pub(crate) enum HufOutput {
    /// Not worth compressing — caller emits raw literals (`return 0`).
    Raw,
    /// A single symbol fills the input — caller emits an RLE block (`return 1`).
    Rle,
    /// A fresh table was built: `table description || stream(s)`, plus the
    /// table itself for the caller's next-block state.
    Compressed(Vec<u8>, Box<HufCTable>),
    /// The previous block's table was reused (`set_repeat`): stream(s) only.
    Repeat(Vec<u8>),
}

/// `SUSPECT_INCOMPRESSIBLE_SAMPLE_SIZE` and its ratio gate.
const SUSPECT_SAMPLE_SIZE: usize = 4096;
const SUSPECT_SAMPLE_RATIO: usize = 10;

/// `HUF_compressCTable_internal`'s compressibility gate: encode and reject if
/// the result didn't shrink.
fn encode_gated(
    ct: &HufCTable,
    src: &[u8],
    single_stream: bool,
    prefix_len: usize,
) -> Option<Vec<u8>> {
    let streams = if single_stream {
        compress1x(ct, src)
    } else {
        compress4x(ct, src)
    };
    if streams.is_empty() || prefix_len + streams.len() >= src.len() - 1 {
        return None; // not compressible enough
    }
    Some(streams)
}

/// Port of `HUF_compress_internal`, including the previous-table reuse paths:
/// build a fresh table and emit `table description || stream(s)`, or reuse
/// `prev` when estimated cheaper (`set_repeat`), with the same
/// incompressibility short-circuits as C. `single_stream` selects 1- vs
/// 4-stream coding; `suspect_uncompressible` enables the sampling pre-check;
/// `prefer_repeat` is `HUF_flags_preferRepeat` (low strategies, small inputs).
/// Uses the cheap FSE-based table-log estimate (the `optimalDepth` search of
/// the highest strategies is a later refinement).
pub(crate) fn huf_compress(
    src: &[u8],
    single_stream: bool,
    suspect_uncompressible: bool,
    prefer_repeat: bool,
    optimal_depth: bool,
    prev: Option<&HufCTable>,
    mut repeat: HufRepeat,
) -> HufOutput {
    let src_size = src.len();
    if src_size == 0 {
        return HufOutput::Raw;
    }

    // Heuristic: if the old table is valid, use it for small inputs.
    if prefer_repeat && repeat == HufRepeat::Valid {
        if let Some(prev) = prev {
            return match encode_gated(prev, src, single_stream, 0) {
                Some(streams) => HufOutput::Repeat(streams),
                None => HufOutput::Raw,
            };
        }
    }

    // If uncompressible data is suspected, histogram a head and tail sample
    // first; bail to raw when even the dominant symbols are rare.
    if suspect_uncompressible && src_size >= SUSPECT_SAMPLE_SIZE * SUSPECT_SAMPLE_RATIO {
        let largest_of = |chunk: &[u8]| {
            let mut count = [0u32; 256];
            for &b in chunk {
                count[b as usize] += 1;
            }
            *count.iter().max().unwrap() as usize
        };
        let largest_total = largest_of(&src[..SUSPECT_SAMPLE_SIZE])
            + largest_of(&src[src_size - SUSPECT_SAMPLE_SIZE..]);
        if largest_total <= ((2 * SUSPECT_SAMPLE_SIZE) >> 7) + 4 {
            return HufOutput::Raw;
        }
    }

    let mut count = [0u32; HUF_SYMBOLVALUE_MAX + 1];
    for &b in src {
        count[b as usize] += 1;
    }
    let mut max_symbol = 0u32;
    let mut largest = 0u32;
    for (s, &c) in count.iter().enumerate() {
        if c != 0 {
            max_symbol = s as u32;
        }
        largest = largest.max(c);
    }
    if largest as usize == src_size {
        return HufOutput::Rle; // single symbol
    }
    if (largest as usize) <= (src_size >> 7) + 4 {
        return HufOutput::Raw; // heuristic: not compressible enough
    }

    // Check validity of the previous table against this block's histogram.
    if repeat == HufRepeat::Check && !prev.is_some_and(|p| validate_ctable(p, &count, max_symbol)) {
        repeat = HufRepeat::None;
    }
    // Heuristic: use the existing table for small inputs.
    if prefer_repeat && repeat != HufRepeat::None {
        if let Some(prev) = prev {
            return match encode_gated(prev, src, single_stream, 0) {
                Some(streams) => HufOutput::Repeat(streams),
                None => HufOutput::Raw,
            };
        }
    }

    let huff_log = huf_optimal_table_log(
        HUF_TABLELOG_DEFAULT,
        src_size,
        max_symbol,
        &count,
        optimal_depth,
    );
    let ct = match build_ctable(&count, max_symbol, huff_log) {
        Ok(ct) => ct,
        Err(_) => return HufOutput::Raw,
    };
    let table = match write_ctable(&ct) {
        Ok(t) => t,
        Err(_) => return HufOutput::Raw,
    };
    let h_size = table.len();

    // Is reusing the previous table cheaper than describing the new one?
    if repeat != HufRepeat::None {
        if let Some(prev) = prev {
            let old_size = estimate_compressed_size(prev, &count, max_symbol);
            let new_size = estimate_compressed_size(&ct, &count, max_symbol);
            if old_size <= h_size + new_size || h_size + 12 >= src_size {
                return match encode_gated(prev, src, single_stream, 0) {
                    Some(streams) => HufOutput::Repeat(streams),
                    None => HufOutput::Raw,
                };
            }
        }
    }

    if h_size + 12 >= src_size {
        return HufOutput::Raw;
    }
    match encode_gated(&ct, src, single_stream, h_size) {
        Some(streams) => {
            let mut out = table;
            out.extend_from_slice(&streams);
            HufOutput::Compressed(out, Box::new(ct))
        }
        None => HufOutput::Raw,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::huffman;

    /// Histogram of `data` over byte symbols, returning (counts, max_symbol).
    fn histogram(data: &[u8]) -> (Vec<u32>, u32) {
        let mut count = vec![0u32; 256];
        let mut max_symbol = 0u32;
        for &b in data {
            count[b as usize] += 1;
            max_symbol = max_symbol.max(b as u32);
        }
        (count, max_symbol)
    }

    /// Build a table, write it, encode `data`, then decode via the C-tested
    /// huffman decoder and require the bytes back.
    fn round_trip(data: &[u8], four_streams: bool) {
        let (count, max_symbol) = histogram(data);
        let ct = build_ctable(&count, max_symbol, 0).unwrap();

        // Table description must parse and rebuild on the decoder side.
        let table_bytes = write_ctable(&ct).unwrap();
        let (table, _used) = huffman::read_table(&table_bytes).unwrap();

        let encoded = if four_streams {
            compress4x(&ct, data)
        } else {
            compress1x(&ct, data)
        };
        let decoded = if four_streams {
            huffman::decode_four_streams(&table, &encoded, data.len()).unwrap()
        } else {
            huffman::decode_single_stream(&table, &encoded, data.len()).unwrap()
        };
        assert_eq!(
            decoded, data,
            "huffman round-trip mismatch (4x={four_streams})"
        );
    }

    /// A smoothly skewed sample over `[0, alphabet)`: each draw is the min of
    /// two uniforms (a triangular distribution), so every symbol below the max
    /// appears with a spread of frequencies and there are always ≥2 distinct
    /// symbols. `alphabet` is kept ≤ 129 so `max_symbol ≤ 128` and the direct
    /// weight-writing path is valid (the FSE-weights path is exercised
    /// separately).
    fn sample(seed: u64, len: usize, alphabet: u32) -> Vec<u8> {
        let mut s = seed | 1;
        let mut next = || {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            s.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        (0..len)
            .map(|_| {
                let a = next() % alphabet as u64;
                let b = next() % alphabet as u64;
                a.min(b) as u8
            })
            .collect()
    }

    /// All 256 symbols present with geometrically decreasing frequencies, so the
    /// weight array is smooth and FSE-compressible — driving the FSE-weights
    /// path of `write_ctable` (and `max_symbol == 255`).
    fn full_alphabet_geometric() -> Vec<u8> {
        let mut data = Vec::new();
        for s in 0u32..256 {
            let freq = 1 + (4000usize >> (s / 16));
            data.extend(std::iter::repeat_n(s as u8, freq));
        }
        data
    }

    #[test]
    fn single_stream_round_trip() {
        for &alphabet in &[2u32, 5, 16, 60, 100, 129] {
            let data = sample(0xABCD_0001 ^ alphabet as u64, 5000, alphabet);
            round_trip(&data, false);
        }
        round_trip(&full_alphabet_geometric(), false);
    }

    #[test]
    fn four_stream_round_trip() {
        for &alphabet in &[3u32, 8, 32, 128, 129] {
            let data = sample(0x1234_0001 ^ alphabet as u64, 20_000, alphabet);
            round_trip(&data, true);
        }
        round_trip(&full_alphabet_geometric(), true);
    }

    #[test]
    fn skewed_distribution_needs_height_limiting() {
        // A geometric-ish distribution drives the unlimited tree past 12 bits,
        // exercising HUF_setMaxHeight; the round-trip proves the clamp is valid.
        let mut data = Vec::new();
        let mut freq = 1usize << 16;
        for sym in 0u8..20 {
            for _ in 0..freq.max(1) {
                data.push(sym);
            }
            freq /= 2;
        }
        let (count, max_symbol) = histogram(&data);
        let ct = build_ctable(&count, max_symbol, 0).unwrap();
        assert!(ct.table_log <= HUF_TABLELOG_MAX);
        round_trip(&data, false);
        round_trip(&data, true);
    }

    #[test]
    fn write_ctable_round_trips_through_reader() {
        // A small alphabet exercises the direct 4-bit path; the full geometric
        // alphabet (max_symbol = 255) forces the FSE-compressed-weights path.
        let small = sample(7, 30_000, 50);
        for data in [small, full_alphabet_geometric()] {
            let (count, max_symbol) = histogram(&data);
            let ct = build_ctable(&count, max_symbol, 0).unwrap();
            let bytes = write_ctable(&ct).unwrap();
            let (table, used) = huffman::read_table(&bytes).unwrap();
            assert_eq!(used, bytes.len(), "table description length");
            // Re-encode/decode using the reader-built table to confirm the
            // weights describe the same code lengths.
            let encoded = compress1x(&ct, &data);
            let decoded = huffman::decode_single_stream(&table, &encoded, data.len()).unwrap();
            assert_eq!(decoded, data);
        }
    }
}
