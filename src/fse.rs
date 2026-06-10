//! Finite State Entropy (tANS) decoding.
//!
//! Ports of `FSE_readNCount`, `FSE_buildDTable`, and the interleaved
//! two-state decode loop of `FSE_decompress_usingDTable` from the C sources.
//! The table layout (the "spread" of symbols over states) is normative: a
//! decoder must reproduce it exactly to read valid streams, so this follows
//! the C construction step by step.

use crate::bits::{ForwardBitReader, ReverseBitReader};
use crate::error::Error;

#[derive(Clone, Copy, Debug)]
pub(crate) struct FseEntry {
    pub symbol: u8,
    pub nb_bits: u8,
    /// `(next_state_counter << nb_bits) - table_size`; the decoder's next
    /// state is `base + read(nb_bits)`.
    pub base: u16,
}

pub(crate) struct FseTable {
    pub table_log: u32,
    pub entries: Vec<FseEntry>,
}

impl FseTable {
    /// One-entry table that always yields `symbol` and consumes no bits,
    /// used for the RLE sequence-table mode (`ZSTD_buildSeqTable_rle`).
    pub(crate) fn rle(symbol: u8) -> Self {
        FseTable {
            table_log: 0,
            entries: vec![FseEntry {
                symbol,
                nb_bits: 0,
                base: 0,
            }],
        }
    }
}

/// A decoded normalized-count table description.
pub(crate) struct NCount {
    pub counts: Vec<i16>,
    pub table_log: u32,
    pub bytes_consumed: usize,
}

/// Read an FSE table description (`FSE_readNCount`).
///
/// `src` is the remaining input; the function discovers how many bytes the
/// description occupies and reports it in [`NCount::bytes_consumed`].
pub(crate) fn read_ncount(
    src: &[u8],
    max_symbol: u32,
    max_table_log: u32,
) -> Result<NCount, Error> {
    let mut br = ForwardBitReader::new(src);
    let table_log = br.read(4) + 5;
    if table_log > max_table_log {
        return Err(Error::Corrupted("FSE accuracy log too large"));
    }
    let table_size: i32 = 1 << table_log;

    // `remaining` carries an extra +1 so a probability of exactly
    // `table_size` remains representable; the stream is valid only if it
    // lands on exactly 1.
    let mut remaining: i32 = table_size + 1;
    let mut threshold: i32 = table_size;
    let mut nb_bits: u32 = table_log + 1;
    let mut counts: Vec<i16> = Vec::new();
    let mut previous0 = false;

    while remaining > 1 {
        if previous0 {
            // A zero count is followed by 2-bit repeat flags: the value 3
            // adds three more zero-probability symbols and another flag
            // follows; 0..=2 add that many and end the run.
            loop {
                let flag = br.read(2);
                let zeros = if flag == 3 { 3 } else { flag };
                counts.extend(std::iter::repeat_n(0, zeros as usize));
                if counts.len() > max_symbol as usize + 1 {
                    return Err(Error::Corrupted("FSE table describes too many symbols"));
                }
                if flag != 3 {
                    break;
                }
            }
        }
        if counts.len() > max_symbol as usize {
            return Err(Error::Corrupted("FSE table describes too many symbols"));
        }

        // Counts use a variable-width encoding: values below `max` fit in
        // `nb_bits - 1` bits, the rest need `nb_bits` (with the top range
        // folded down by `max`). Invariant: threshold == 1 << (nb_bits - 1).
        let max = (2 * threshold - 1) - remaining;
        let low = br.peek(nb_bits - 1) as i32;
        let mut count: i32;
        if low < max {
            count = low;
            br.consume(nb_bits - 1);
        } else {
            let v = br.peek(nb_bits) as i32;
            count = if v >= threshold { v - max } else { v };
            br.consume(nb_bits);
        }
        // The stored value is shifted by one: 0 encodes the "less than one"
        // probability (-1), which still occupies one state slot.
        count -= 1;
        remaining -= count.abs();
        counts.push(count as i16);
        previous0 = count == 0;
        if remaining < 1 {
            return Err(Error::Corrupted("FSE counts exceed table size"));
        }
        while remaining < threshold && threshold > 1 {
            nb_bits -= 1;
            threshold >>= 1;
        }
    }

    if br.bits_consumed() > src.len() * 8 {
        return Err(Error::SrcSizeWrong);
    }
    Ok(NCount {
        counts,
        table_log,
        bytes_consumed: br.bits_consumed().div_ceil(8),
    })
}

/// Build a decoding table from normalized counts (`FSE_buildDTable`).
pub(crate) fn build_dtable(counts: &[i16], table_log: u32) -> Result<FseTable, Error> {
    let table_size = 1usize << table_log;
    let mut symbols = vec![0u8; table_size];
    let mut symbol_next = vec![0u32; counts.len()];

    // "Less than one" probability symbols get the highest state slots.
    let mut high_threshold = table_size as i64 - 1;
    for (s, &c) in counts.iter().enumerate() {
        if c == -1 {
            if high_threshold < 0 {
                return Err(Error::Corrupted("FSE counts exceed table size"));
            }
            symbols[high_threshold as usize] = s as u8;
            high_threshold -= 1;
            symbol_next[s] = 1;
        } else {
            symbol_next[s] = c as u32;
        }
    }

    // Spread symbols over the remaining states with the normative step.
    let step = (table_size >> 1) + (table_size >> 3) + 3;
    let mask = table_size - 1;
    let mut pos = 0usize;
    for (s, &c) in counts.iter().enumerate() {
        for _ in 0..c.max(0) {
            symbols[pos] = s as u8;
            pos = (pos + step) & mask;
            while pos as i64 > high_threshold {
                pos = (pos + step) & mask;
            }
        }
    }
    if pos != 0 {
        return Err(Error::Corrupted("FSE table spread did not complete"));
    }

    // Derive bit counts and state bases from each symbol's occurrence rank.
    let mut entries = Vec::with_capacity(table_size);
    for &symbol in &symbols {
        let next = symbol_next[symbol as usize];
        symbol_next[symbol as usize] += 1;
        debug_assert!(next > 0);
        let nb_bits = table_log - (31 - next.leading_zeros());
        let base = (next << nb_bits) - table_size as u32;
        entries.push(FseEntry {
            symbol,
            nb_bits: nb_bits as u8,
            base: base as u16,
        });
    }
    Ok(FseTable { table_log, entries })
}

/// A decoder state register over an [`FseTable`].
pub(crate) struct FseState<'t> {
    table: &'t FseTable,
    state: usize,
}

impl<'t> FseState<'t> {
    pub(crate) fn new(table: &'t FseTable, br: &mut ReverseBitReader<'_>) -> Self {
        let state = br.read(table.table_log) as usize;
        FseState { table, state }
    }

    pub(crate) fn symbol(&self) -> u8 {
        self.table.entries[self.state].symbol
    }

    pub(crate) fn advance(&mut self, br: &mut ReverseBitReader<'_>) {
        let e = self.table.entries[self.state];
        self.state = e.base as usize + br.read(u32::from(e.nb_bits)) as usize;
    }
}

/// Decode a stream with two interleaved FSE states until the bitstream is
/// exhausted (`FSE_decompress_usingDTable`). Used for Huffman weights, where
/// the symbol count is not known up front.
pub(crate) fn decode_interleaved(
    table: &FseTable,
    src: &[u8],
    max_out: usize,
) -> Result<Vec<u8>, Error> {
    let mut br = ReverseBitReader::new(src)?;
    let mut s1 = FseState::new(table, &mut br);
    let mut s2 = FseState::new(table, &mut br);
    let mut out = Vec::new();

    // Mirrors the C loop: each iteration emits from one state and advances
    // it; when advancing overdraws the bitstream, the *other* state's symbol
    // (already valid) is flushed and decoding ends. The capacity check keeps
    // room for that flush symbol, exactly like the `omax - 2` guard in C.
    loop {
        if out.len() + 2 > max_out {
            return Err(Error::Corrupted("FSE output exceeds limit"));
        }
        out.push(s1.symbol());
        s1.advance(&mut br);
        if br.bits_remaining() < 0 {
            out.push(s2.symbol());
            break;
        }
        if out.len() + 2 > max_out {
            return Err(Error::Corrupted("FSE output exceeds limit"));
        }
        out.push(s2.symbol());
        s2.advance(&mut br);
        if br.bits_remaining() < 0 {
            out.push(s1.symbol());
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rle_table_always_yields_symbol() {
        let t = FseTable::rle(42);
        let data = [0x01u8]; // empty payload, just the padding bit
        let mut br = ReverseBitReader::new(&data).unwrap();
        let mut s = FseState::new(&t, &mut br);
        for _ in 0..10 {
            assert_eq!(s.symbol(), 42);
            s.advance(&mut br);
        }
        assert!(br.finished_exactly());
    }

    #[test]
    fn build_dtable_uniform_two_symbols() {
        // Two symbols, equal probability, accuracy log 5 (the format's
        // minimum — the spread step only cycles fully for sizes >= 16).
        let t = build_dtable(&[16, 16], 5).unwrap();
        assert_eq!(t.entries.len(), 32);
        assert_eq!(t.entries.iter().filter(|e| e.symbol == 0).count(), 16);
        assert_eq!(t.entries.iter().filter(|e| e.symbol == 1).count(), 16);
        // With probability table_size/2, every state reads exactly one bit.
        assert!(t.entries.iter().all(|e| e.nb_bits == 1));
    }

    #[test]
    fn ncount_rejects_oversized_accuracy_log() {
        // First nibble encodes table_log - 5; 0xF -> table_log 20.
        assert!(read_ncount(&[0xFF, 0xFF], 35, 9).is_err());
    }
}
