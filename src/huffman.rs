//! Huffman decoding for the literals section.
//!
//! Ports `HUF_readStats` (weight decoding), `HUF_readDTableX1` (single-symbol
//! decode table construction), and the one- and four-stream decoders.

use crate::bits::ReverseBitReader;
use crate::error::Error;
use crate::fse;

/// `HUF_TABLELOG_MAX`: the largest decode table the format allows.
const MAX_TABLE_LOG: u32 = 12;
/// Weights can be at most `MAX_TABLE_LOG` (a weight `w` stands for a code of
/// `table_log + 1 - w` bits).
const MAX_WEIGHT: u32 = MAX_TABLE_LOG;
/// The FSE table compressing the weights is limited to an accuracy log of 6.
const WEIGHT_FSE_MAX_LOG: u32 = 6;

#[derive(Clone, Copy)]
struct HufEntry {
    symbol: u8,
    nb_bits: u8,
}

pub(crate) struct HuffmanTable {
    table_log: u32,
    entries: Vec<HufEntry>,
}

/// Read a Huffman table description and build the decode table.
///
/// Returns the table and the number of bytes consumed from `src`.
pub(crate) fn read_table(src: &[u8]) -> Result<(HuffmanTable, usize), Error> {
    let header = *src
        .first()
        .ok_or(Error::Corrupted("missing huffman header"))?;

    let (mut weights, consumed) = if header < 128 {
        // FSE-compressed weights; `header` is the compressed size.
        let payload = src
            .get(1..1 + header as usize)
            .ok_or(Error::Corrupted("huffman weights overrun input"))?;
        let nc = fse::read_ncount(payload, 255, WEIGHT_FSE_MAX_LOG)?;
        let table = fse::build_dtable(&nc.counts, nc.table_log)?;
        let stream = &payload[nc.bytes_consumed..];
        let weights = fse::decode_interleaved(&table, stream, 255)?;
        (weights, 1 + header as usize)
    } else {
        // Direct representation: `header - 127` weights, packed as nibbles,
        // high nibble first.
        let n = (header - 127) as usize;
        let n_bytes = n.div_ceil(2);
        let payload = src
            .get(1..1 + n_bytes)
            .ok_or(Error::Corrupted("huffman weights overrun input"))?;
        let mut weights = Vec::with_capacity(n);
        for i in 0..n {
            let b = payload[i / 2];
            weights.push(if i % 2 == 0 { b >> 4 } else { b & 0x0F });
        }
        (weights, 1 + n_bytes)
    };

    // The weights listed in the stream cover all symbols but the last; the
    // last symbol's weight is implicit: it completes the sum of
    // `2^(weight-1)` to the next power of two.
    let mut total: u32 = 0;
    for &w in &weights {
        if u32::from(w) > MAX_WEIGHT {
            return Err(Error::Corrupted("huffman weight too large"));
        }
        if w > 0 {
            total += 1u32 << (w - 1);
        }
    }
    if total == 0 {
        return Err(Error::Corrupted("huffman table has no weights"));
    }
    let table_log = 32 - total.leading_zeros();
    if table_log > MAX_TABLE_LOG {
        return Err(Error::Corrupted("huffman code lengths too long"));
    }
    let rest = (1u32 << table_log) - total;
    if !rest.is_power_of_two() {
        return Err(Error::Corrupted(
            "huffman weights do not sum to a power of two",
        ));
    }
    let last_weight = rest.trailing_zeros() + 1;
    weights.push(last_weight as u8);
    if weights.len() > 256 {
        return Err(Error::Corrupted("too many huffman symbols"));
    }

    Ok((build(&weights, table_log)?, consumed))
}

/// Build the single-symbol decode table (`HUF_readDTableX1`): symbols are
/// placed in weight order (longest codes first), in natural symbol order
/// within each weight, each occupying `2^(weight-1)` consecutive entries.
fn build(weights: &[u8], table_log: u32) -> Result<HuffmanTable, Error> {
    let table_size = 1usize << table_log;

    let mut rank_count = [0usize; (MAX_WEIGHT + 1) as usize + 1];
    for &w in weights {
        rank_count[w as usize] += 1;
    }
    let mut rank_next = [0usize; (MAX_WEIGHT + 1) as usize + 1];
    let mut cur = 0usize;
    for w in 1..=MAX_WEIGHT as usize {
        rank_next[w] = cur;
        cur += rank_count[w] << (w - 1);
    }
    debug_assert_eq!(cur, table_size, "weight sum must fill the table exactly");

    let mut entries = vec![
        HufEntry {
            symbol: 0,
            nb_bits: 0
        };
        table_size
    ];
    for (symbol, &w) in weights.iter().enumerate() {
        if w == 0 {
            continue;
        }
        let w = w as usize;
        let len = 1usize << (w - 1);
        let nb_bits = (table_log + 1 - w as u32) as u8;
        for e in &mut entries[rank_next[w]..rank_next[w] + len] {
            e.symbol = symbol as u8;
            e.nb_bits = nb_bits;
        }
        rank_next[w] += len;
    }

    Ok(HuffmanTable { table_log, entries })
}

/// Decode exactly `count` symbols from one backward bitstream.
fn decode_stream_into(
    table: &HuffmanTable,
    src: &[u8],
    count: usize,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    let mut br = ReverseBitReader::new(src)?;
    for _ in 0..count {
        let idx = br.peek(table.table_log) as usize;
        let e = table.entries[idx];
        br.consume(u32::from(e.nb_bits));
        out.push(e.symbol);
    }
    if !br.finished_exactly() {
        return Err(Error::Corrupted("huffman stream not fully consumed"));
    }
    Ok(())
}

/// Decode a single-stream literals payload (`HUF_decompress1X1`).
pub(crate) fn decode_single_stream(
    table: &HuffmanTable,
    src: &[u8],
    regenerated_size: usize,
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(regenerated_size);
    decode_stream_into(table, src, regenerated_size, &mut out)?;
    Ok(out)
}

/// Decode a four-stream literals payload (`HUF_decompress4X1`).
///
/// The payload starts with a six-byte jump table holding the compressed sizes
/// of the first three streams; the fourth runs to the end. The first three
/// streams each regenerate `ceil(size / 4)` bytes, the last the remainder.
pub(crate) fn decode_four_streams(
    table: &HuffmanTable,
    src: &[u8],
    regenerated_size: usize,
) -> Result<Vec<u8>, Error> {
    let jump = src
        .get(..6)
        .ok_or(Error::Corrupted("missing huffman jump table"))?;
    let s1 = u16::from_le_bytes([jump[0], jump[1]]) as usize;
    let s2 = u16::from_le_bytes([jump[2], jump[3]]) as usize;
    let s3 = u16::from_le_bytes([jump[4], jump[5]]) as usize;
    let rest = &src[6..];
    if s1 + s2 + s3 >= rest.len() {
        return Err(Error::Corrupted("huffman jump table overruns input"));
    }

    let segment = regenerated_size.div_ceil(4);
    let last = regenerated_size as i64 - 3 * segment as i64;
    if last <= 0 {
        return Err(Error::Corrupted("four-stream literals too short"));
    }

    let mut out = Vec::with_capacity(regenerated_size);
    decode_stream_into(table, &rest[..s1], segment, &mut out)?;
    decode_stream_into(table, &rest[s1..s1 + s2], segment, &mut out)?;
    decode_stream_into(table, &rest[s1 + s2..s1 + s2 + s3], segment, &mut out)?;
    decode_stream_into(table, &rest[s1 + s2 + s3..], last as usize, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_weights_roundtrip() {
        // Three explicit weights (header 127 + 3), nibbles 2, 2, 1 -> symbols
        // 0..2; total = 2 + 2 + 1 = 5, table_log = 3, rest = 3 -> invalid
        // (not a power of two). Use weights 2, 2, 2: total 6, table_log 3,
        // rest 2 -> last weight 2: four symbols with codes of 2 bits each...
        // total becomes 8 = 2^3 exactly.
        let desc = [127 + 3, 0x22, 0x20];
        let (table, consumed) = read_table(&desc).unwrap();
        assert_eq!(consumed, 3);
        assert_eq!(table.table_log, 3);
        // Each weight-2 symbol covers 2 of 8 entries with 2-bit codes.
        assert!(table.entries.iter().all(|e| e.nb_bits == 2));
    }

    #[test]
    fn rejects_invalid_weight_sum() {
        // Weights 2, 2, 1: total 5, rest 3 is not a power of two.
        let desc = [127 + 3, 0x22, 0x10];
        assert!(read_table(&desc).is_err());
    }
}
