//! FSE *compression*-side primitives: choosing the table log, normalizing a
//! symbol histogram onto a power-of-two table, and serializing that
//! distribution. Ports of `FSE_optimalTableLog`, `FSE_normalizeCount` (with
//! its `rtbTable` rounding and the `FSE_normalizeM2` fallback), and
//! `FSE_writeNCount` from the C sources — the inverses of the decoder's
//! `FSE_readNCount` in [`crate::fse`].
//!
//! Verification: the NCount bit-encoding is canonical for a given
//! `(counts, tableLog)`, so a faithful `write_ncount` produces byte-identical
//! output to C's `FSE_writeNCount`. The unit tests confirm it by
//! round-tripping distributions (including zstd's own predefined sequence
//! tables) through the decoder's `read_ncount`, which is itself
//! differential-tested against C.
#![allow(dead_code)]
// wired into the public compressor in a later milestone
// The symbol loops index `count` and `norm` in lockstep and mirror the C
// `for (s=0; s<=maxSymbolValue; s++)` exactly; an enumerate() rewrite would
// only obscure the port and still need the second array by index.
#![allow(clippy::needless_range_loop)]

use crate::error::Error;

const FSE_MIN_TABLELOG: u32 = 5;
const FSE_MAX_TABLELOG: u32 = 12;
const FSE_DEFAULT_TABLELOG: u32 = 6;

/// `BIT_highbit32`: index of the most-significant set bit (`floor(log2 x)`).
/// Callers guarantee `x >= 1`.
fn highbit32(x: u32) -> u32 {
    debug_assert!(x >= 1);
    31 - x.leading_zeros()
}

/// `FSE_minTableLog`: the smallest table log that can represent the alphabet.
fn min_table_log(src_size: usize, max_symbol: u32) -> u32 {
    debug_assert!(src_size > 1 && max_symbol >= 1);
    let min_bits_src = highbit32(src_size as u32) + 1;
    let min_bits_symbols = highbit32(max_symbol) + 2;
    min_bits_src.min(min_bits_symbols)
}

/// `FSE_optimalTableLog` (with the default `minus = 2`).
pub(crate) fn optimal_table_log(max_table_log: u32, src_size: usize, max_symbol: u32) -> u32 {
    debug_assert!(src_size > 1);
    // The subtraction underflows for tiny sources exactly as in C; the wrapped
    // (huge) value then loses the `< table_log` comparison, leaving table_log
    // untouched — which is the intended behavior.
    let max_bits_src = highbit32((src_size - 1) as u32).wrapping_sub(2);
    let mut table_log = if max_table_log == 0 {
        FSE_DEFAULT_TABLELOG
    } else {
        max_table_log
    };
    let min_bits = min_table_log(src_size, max_symbol);
    if max_bits_src < table_log {
        table_log = max_bits_src;
    }
    if min_bits > table_log {
        table_log = min_bits;
    }
    table_log.clamp(FSE_MIN_TABLELOG, FSE_MAX_TABLELOG)
}

/// The result of normalizing a histogram.
pub(crate) enum Normalized {
    /// A single symbol carries the entire count; the caller uses RLE mode.
    Rle(u8),
    /// Normalized counts, length `max_symbol + 1`. A count of `-1` is the
    /// "less than one" probability that still occupies one state slot.
    Table(Vec<i16>),
}

/// `FSE_normalizeCount`: scale `count` (summing to `total`) onto a table of
/// `2^table_log` states. `use_low_prob` selects the `-1` low-probability
/// marker (`lowProbCount`) as in the C parameter of the same name.
pub(crate) fn normalize_count(
    count: &[u32],
    total: usize,
    max_symbol: u32,
    table_log: u32,
    use_low_prob: bool,
) -> Result<Normalized, Error> {
    let table_log = if table_log == 0 {
        FSE_DEFAULT_TABLELOG
    } else {
        table_log
    };
    if table_log < FSE_MIN_TABLELOG {
        return Err(Error::Encode("FSE table log too small"));
    }
    if table_log > FSE_MAX_TABLELOG {
        return Err(Error::Encode("FSE table log too large"));
    }
    if table_log < min_table_log(total, max_symbol) {
        return Err(Error::Encode("FSE table log below the alphabet minimum"));
    }

    // `rtbTable` and the rounding step are verbatim from `FSE_normalizeCount`.
    const RTB: [u64; 8] = [0, 473195, 504333, 520860, 550000, 700000, 750000, 830000];
    let low_prob_count: i16 = if use_low_prob { -1 } else { 1 };
    let scale: u64 = 62 - table_log as u64;
    let step: u64 = (1u64 << 62) / total as u64;
    let v_step: u64 = 1u64 << (scale - 20);
    let mut still_to_distribute: i32 = 1i32 << table_log;
    let mut largest: usize = 0;
    let mut largest_p: i16 = 0;
    let low_threshold: u32 = (total >> table_log) as u32;

    let mut norm = vec![0i16; (max_symbol + 1) as usize];

    for s in 0..=max_symbol as usize {
        let c = count[s];
        if c as usize == total {
            return Ok(Normalized::Rle(s as u8)); // rle special case
        }
        if c == 0 {
            norm[s] = 0;
            continue;
        }
        if c <= low_threshold {
            norm[s] = low_prob_count;
            still_to_distribute -= 1;
        } else {
            let mut proba: i16 = ((c as u64 * step) >> scale) as i16;
            if proba < 8 {
                let rest_to_beat = v_step * RTB[proba as usize];
                proba += ((c as u64 * step) - ((proba as u64) << scale) > rest_to_beat) as i16;
            }
            if proba > largest_p {
                largest_p = proba;
                largest = s;
            }
            norm[s] = proba;
            still_to_distribute -= proba as i32;
        }
    }

    if -still_to_distribute >= (norm[largest] >> 1) as i32 {
        // Corner case: the leftover would more than halve the largest symbol.
        normalize_m2(
            &mut norm,
            table_log,
            count,
            total,
            max_symbol,
            low_prob_count,
        )?;
    } else {
        norm[largest] += still_to_distribute as i16;
    }
    Ok(Normalized::Table(norm))
}

/// `FSE_normalizeM2`: the slower, exact fallback normalization.
fn normalize_m2(
    norm: &mut [i16],
    table_log: u32,
    count: &[u32],
    mut total: usize,
    max_symbol: u32,
    low_prob_count: i16,
) -> Result<(), Error> {
    const NOT_YET_ASSIGNED: i16 = -2;
    let mut distributed: u32 = 0;
    let low_threshold = (total >> table_log) as u32;
    let mut low_one = ((total as u64 * 3) >> (table_log + 1)) as u32;

    for s in 0..=max_symbol as usize {
        if count[s] == 0 {
            norm[s] = 0;
            continue;
        }
        if count[s] <= low_threshold {
            norm[s] = low_prob_count;
            distributed += 1;
            total -= count[s] as usize;
            continue;
        }
        if count[s] <= low_one {
            norm[s] = 1;
            distributed += 1;
            total -= count[s] as usize;
            continue;
        }
        norm[s] = NOT_YET_ASSIGNED;
    }
    let mut to_distribute = (1u32 << table_log) - distributed;
    if to_distribute == 0 {
        return Ok(());
    }

    if (total as u32) / to_distribute > low_one {
        // Risk of rounding some symbol to zero — promote the small ones to 1.
        low_one = ((total as u64 * 3) / (to_distribute as u64 * 2)) as u32;
        for s in 0..=max_symbol as usize {
            if norm[s] == NOT_YET_ASSIGNED && count[s] <= low_one {
                norm[s] = 1;
                distributed += 1;
                total -= count[s] as usize;
            }
        }
        to_distribute = (1u32 << table_log) - distributed;
    }

    if distributed == max_symbol + 1 {
        // Everything is poor (near-incompressible): dump the rest on the max.
        let mut max_v = 0usize;
        let mut max_c = 0u32;
        for s in 0..=max_symbol as usize {
            if count[s] > max_c {
                max_v = s;
                max_c = count[s];
            }
        }
        norm[max_v] += to_distribute as i16;
        return Ok(());
    }

    if total == 0 {
        // Every symbol fell under a low threshold; hand out the remainder
        // round-robin to the already-positive entries.
        let alphabet = (max_symbol + 1) as usize;
        let mut s = 0usize;
        while to_distribute > 0 {
            if norm[s] > 0 {
                to_distribute -= 1;
                norm[s] += 1;
            }
            s = (s + 1) % alphabet;
        }
        return Ok(());
    }

    let v_step_log: u64 = 62 - table_log as u64;
    let mid: u64 = (1u64 << (v_step_log - 1)) - 1;
    let r_step: u64 = (((1u64 << v_step_log) * to_distribute as u64) + mid) / total as u64;
    let mut tmp_total: u64 = mid;
    for s in 0..=max_symbol as usize {
        if norm[s] == NOT_YET_ASSIGNED {
            let end = tmp_total + count[s] as u64 * r_step;
            let s_start = (tmp_total >> v_step_log) as u32;
            let s_end = (end >> v_step_log) as u32;
            let weight = s_end - s_start;
            if weight < 1 {
                return Err(Error::Encode("FSE normalize weight underflow"));
            }
            norm[s] = weight as i16;
            tmp_total = end;
        }
    }
    Ok(())
}

/// `FSE_writeNCount`: serialize a normalized distribution into the header bytes
/// the decoder's `read_ncount` consumes.
pub(crate) fn write_ncount(
    norm: &[i16],
    max_symbol: u32,
    table_log: u32,
) -> Result<Vec<u8>, Error> {
    let table_size: i32 = 1i32 << table_log;
    let alphabet_size = max_symbol + 1;
    let mut out: Vec<u8> = Vec::new();
    let mut bit_stream: u32 = 0;
    let mut bit_count: i32 = 0;
    let mut symbol: u32 = 0;
    let mut previous_is0 = false;

    let mut remaining: i32 = table_size + 1; // +1 for extra accuracy
    let mut threshold: i32 = table_size;
    let mut nb_bits: i32 = table_log as i32 + 1;

    // Table log.
    bit_stream += table_log - FSE_MIN_TABLELOG; // bit_count == 0
    bit_count += 4;

    while symbol < alphabet_size && remaining > 1 {
        if previous_is0 {
            let mut start = symbol;
            while symbol < alphabet_size && norm[symbol as usize] == 0 {
                symbol += 1;
            }
            if symbol == alphabet_size {
                break; // incorrect distribution, handled by the remaining check
            }
            while symbol >= start + 24 {
                start += 24;
                bit_stream += 0xFFFFu32 << bit_count;
                out.push(bit_stream as u8);
                out.push((bit_stream >> 8) as u8);
                bit_stream >>= 16;
            }
            while symbol >= start + 3 {
                start += 3;
                bit_stream += 3u32 << bit_count;
                bit_count += 2;
            }
            bit_stream += (symbol - start) << bit_count;
            bit_count += 2;
            if bit_count > 16 {
                out.push(bit_stream as u8);
                out.push((bit_stream >> 8) as u8);
                bit_stream >>= 16;
                bit_count -= 16;
            }
        }
        {
            let raw = norm[symbol as usize] as i32;
            symbol += 1;
            let max = (2 * threshold - 1) - remaining;
            remaining -= raw.abs();
            let mut count = raw + 1; // +1 for extra accuracy
            if count >= threshold {
                count += max;
            }
            bit_stream += (count as u32) << bit_count;
            bit_count += nb_bits;
            bit_count -= (count < max) as i32;
            previous_is0 = count == 1;
            if remaining < 1 {
                return Err(Error::Encode("FSE write: incorrect distribution"));
            }
            while remaining < threshold {
                nb_bits -= 1;
                threshold >>= 1;
            }
        }
        if bit_count > 16 {
            out.push(bit_stream as u8);
            out.push((bit_stream >> 8) as u8);
            bit_stream >>= 16;
            bit_count -= 16;
        }
    }

    if remaining != 1 {
        return Err(Error::Encode("FSE write: distribution not normalized"));
    }

    // Flush the trailing bits: write up to two bytes but only keep
    // `(bit_count + 7) / 8` of them, matching how C advances `out`.
    let base = out.len();
    out.push(bit_stream as u8);
    out.push((bit_stream >> 8) as u8);
    out.truncate(base + ((bit_count + 7) / 8) as usize);
    Ok(out)
}

// --- FSE compression table + encoding -------------------------------------
//
// Ports of `FSE_buildCTable`, the `BIT_CStream` forward bit-writer, and
// `FSE_compress_usingCTable_generic`. The encoder writes bits LSB-first into a
// 64-bit container (the static size-dependent join structure below is fixed to
// the 64-bit container we use); the resulting byte stream is exactly what the
// decoder's `decode_interleaved` (a port of `FSE_decompress_usingDTable`)
// reads back. Round-trip tests rely on that pairing.

/// One symbol's `FSE_symbolCompressionTransform`.
#[derive(Clone, Copy)]
struct SymbolTransform {
    /// Stored as the C `U32` (it encodes a biased bit count); used via wrapping
    /// adds, so keep it `u32`.
    delta_nb_bits: u32,
    delta_find_state: i32,
}

/// An FSE compression table (`FSE_CTable`): the next-state lookup plus the
/// per-symbol transforms.
pub(crate) struct FseCTable {
    table_log: u32,
    next_state: Vec<u16>,
    symbol_tt: Vec<SymbolTransform>,
}

/// `FSE_buildCTable`: lay out the encoding table for a normalized distribution.
pub(crate) fn build_ctable(norm: &[i16], max_symbol: u32, table_log: u32) -> FseCTable {
    let table_size = 1usize << table_log;
    let table_mask = table_size - 1;
    // FSE_TABLESTEP — the same spread step as the decoder's table build.
    let step = (table_size >> 1) + (table_size >> 3) + 3;
    let mut high_threshold = table_size - 1;

    // Symbol start positions; low-probability (-1) symbols are parked at the
    // top of the table, descending from high_threshold.
    let mut cumul = vec![0u32; (max_symbol + 2) as usize];
    let mut table_symbol = vec![0u8; table_size];
    for u in 1..=(max_symbol as usize + 1) {
        if norm[u - 1] == -1 {
            cumul[u] = cumul[u - 1] + 1;
            table_symbol[high_threshold] = (u - 1) as u8;
            high_threshold -= 1;
        } else {
            cumul[u] = cumul[u - 1] + norm[u - 1] as u32;
        }
    }
    cumul[(max_symbol + 1) as usize] = (table_size + 1) as u32;

    // Spread the symbols over the table with the normative step.
    let mut position = 0usize;
    for symbol in 0..=max_symbol as usize {
        let freq = norm[symbol].max(0);
        for _ in 0..freq {
            table_symbol[position] = symbol as u8;
            position = (position + step) & table_mask;
            while position > high_threshold {
                position = (position + step) & table_mask; // low-proba area
            }
        }
    }
    debug_assert_eq!(position, 0, "spread must cover the whole table");

    // Next-state table, in symbol order.
    let mut next_state = vec![0u16; table_size];
    for u in 0..table_size {
        let s = table_symbol[u] as usize;
        next_state[cumul[s] as usize] = (table_size + u) as u16;
        cumul[s] += 1;
    }

    // Symbol transforms (deltaNbBits uses wrapping arithmetic, as in C).
    let mut symbol_tt = vec![
        SymbolTransform {
            delta_nb_bits: 0,
            delta_find_state: 0,
        };
        (max_symbol + 1) as usize
    ];
    let mut total: i32 = 0;
    for s in 0..=max_symbol as usize {
        match norm[s] {
            0 => {
                // Filled for FSE_getMaxNbBits compatibility; never encoded.
                symbol_tt[s].delta_nb_bits =
                    ((table_log + 1) << 16).wrapping_sub(1u32 << table_log);
            }
            -1 | 1 => {
                symbol_tt[s].delta_nb_bits = (table_log << 16).wrapping_sub(1u32 << table_log);
                symbol_tt[s].delta_find_state = total - 1;
                total += 1;
            }
            n => {
                let max_bits_out = table_log - highbit32((n - 1) as u32);
                let min_state_plus = (n as u32) << max_bits_out;
                symbol_tt[s].delta_nb_bits = (max_bits_out << 16).wrapping_sub(min_state_plus);
                symbol_tt[s].delta_find_state = total - n as i32;
                total += n as i32;
            }
        }
    }

    FseCTable {
        table_log,
        next_state,
        symbol_tt,
    }
}

/// `BIT_CStream_t`: forward LSB-first bit writer over a 64-bit container.
struct BitCStream {
    container: u64,
    bit_pos: usize,
    out: Vec<u8>,
}

impl BitCStream {
    fn new() -> Self {
        BitCStream {
            container: 0,
            bit_pos: 0,
            out: Vec::new(),
        }
    }

    /// `BIT_addBits`: append the low `nb_bits` of `value` at the current
    /// position.
    fn add_bits(&mut self, value: u64, nb_bits: u32) {
        self.container |= (value & crate::bits::mask64(nb_bits)) << self.bit_pos;
        self.bit_pos += nb_bits as usize;
    }

    /// `BIT_flushBits`: emit the whole bytes accumulated, keeping the remainder.
    fn flush_bits(&mut self) {
        let nb_bytes = self.bit_pos >> 3;
        let bytes = self.container.to_le_bytes();
        self.out.extend_from_slice(&bytes[..nb_bytes]);
        self.bit_pos &= 7;
        self.container >>= (nb_bytes * 8) as u32;
    }

    /// `BIT_closeCStream`: write the end-mark bit (the decoder's padding bit),
    /// flush, and emit any final partial byte.
    fn close(mut self) -> Vec<u8> {
        self.add_bits(1, 1);
        self.flush_bits();
        if self.bit_pos > 0 {
            self.out.push(self.container as u8);
        }
        self.out
    }
}

/// `FSE_initCState2`: seed a state from the first (last-consumed) symbol.
fn init_cstate2(ct: &FseCTable, symbol: usize) -> i64 {
    let stt = ct.symbol_tt[symbol];
    let nb_bits_out = (stt.delta_nb_bits.wrapping_add(1 << 15)) >> 16;
    let value0 = (nb_bits_out << 16).wrapping_sub(stt.delta_nb_bits);
    let idx = ((value0 >> nb_bits_out) as i64 + stt.delta_find_state as i64) as usize;
    ct.next_state[idx] as i64
}

/// `FSE_encodeSymbol`: emit the bits for `symbol` and advance `state`.
fn encode_symbol(bitc: &mut BitCStream, ct: &FseCTable, state: &mut i64, symbol: usize) {
    let stt = ct.symbol_tt[symbol];
    let nb_bits_out = ((*state + stt.delta_nb_bits as i64) >> 16) as u32;
    bitc.add_bits(*state as u64, nb_bits_out);
    let idx = ((*state >> nb_bits_out) + stt.delta_find_state as i64) as usize;
    *state = ct.next_state[idx] as i64;
}

/// `FSE_flushCState`: write the final state value.
fn flush_cstate(bitc: &mut BitCStream, ct: &FseCTable, state: i64) {
    bitc.add_bits(state as u64, ct.table_log);
    bitc.flush_bits();
}

/// `FSE_compress_usingCTable`: encode `src` with `ct`, returning the bitstream.
///
/// The join structure is fixed to the 64-bit container (`64 > FSE_MAX_TABLELOG*4+7`),
/// so each loop encodes four symbols between flushes. `src` must be longer than
/// two bytes and contain only symbols with a nonzero normalized count.
pub(crate) fn fse_compress_using_ctable(ct: &FseCTable, src: &[u8]) -> Vec<u8> {
    let n = src.len();
    debug_assert!(n > 2);
    let mut bitc = BitCStream::new();
    let mut ip = n;
    let take = |i: &mut usize| {
        *i -= 1;
        src[*i] as usize
    };

    let (mut cstate1, mut cstate2);
    if n & 1 == 1 {
        cstate1 = init_cstate2(ct, take(&mut ip));
        cstate2 = init_cstate2(ct, take(&mut ip));
        let s = take(&mut ip);
        encode_symbol(&mut bitc, ct, &mut cstate1, s);
        bitc.flush_bits();
    } else {
        cstate2 = init_cstate2(ct, take(&mut ip));
        cstate1 = init_cstate2(ct, take(&mut ip));
    }

    // Join to a multiple of four (the `srcSize & 2` test is on n-2).
    if ((n - 2) & 2) != 0 {
        let s2 = take(&mut ip);
        encode_symbol(&mut bitc, ct, &mut cstate2, s2);
        let s1 = take(&mut ip);
        encode_symbol(&mut bitc, ct, &mut cstate1, s1);
        bitc.flush_bits();
    }

    // Four symbols per iteration on a 64-bit container.
    while ip > 0 {
        let a = take(&mut ip);
        encode_symbol(&mut bitc, ct, &mut cstate2, a);
        let b = take(&mut ip);
        encode_symbol(&mut bitc, ct, &mut cstate1, b);
        let c = take(&mut ip);
        encode_symbol(&mut bitc, ct, &mut cstate2, c);
        let d = take(&mut ip);
        encode_symbol(&mut bitc, ct, &mut cstate1, d);
        bitc.flush_bits();
    }

    flush_cstate(&mut bitc, ct, cstate2);
    flush_cstate(&mut bitc, ct, cstate1);
    bitc.close()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fse;

    /// zstd's predefined offset-code distribution (`OF_defaultNorm`, log 5).
    #[rustfmt::skip]
    const OF_DEFAULT_NORM: [i16; 29] = [
         1, 1, 1, 1, 1, 1, 2, 2,
         2, 1, 1, 1, 1, 1, 1, 1,
         1, 1, 1, 1, 1, 1, 1, 1,
        -1,-1,-1,-1,-1,
    ];

    /// zstd's predefined literal-length distribution (`LL_defaultNorm`, log 6).
    #[rustfmt::skip]
    const LL_DEFAULT_NORM: [i16; 36] = [
         4, 3, 2, 2, 2, 2, 2, 2,
         2, 2, 2, 2, 2, 1, 1, 1,
         2, 2, 2, 2, 2, 2, 2, 2,
         2, 3, 2, 1, 1, 1, 1, 1,
        -1,-1,-1,-1,
    ];

    /// Read a written header back through the (C-verified) decoder and compare,
    /// padding the recovered counts with the implicit trailing zeros.
    fn round_trip(norm: &[i16], table_log: u32, max_log: u32) {
        let max_symbol = norm.len() as u32 - 1;
        let bytes = write_ncount(norm, max_symbol, table_log).expect("write");
        let nc = fse::read_ncount(&bytes, max_symbol, max_log).expect("read back");
        assert_eq!(nc.table_log, table_log, "table log round-trips");
        let mut got = nc.counts;
        assert!(got.len() <= norm.len());
        got.resize(norm.len(), 0);
        assert_eq!(got, norm, "normalized counts round-trip");
        assert_eq!(nc.bytes_consumed, bytes.len(), "header length round-trips");
    }

    #[test]
    fn predefined_tables_round_trip() {
        round_trip(&OF_DEFAULT_NORM, 5, 8);
        round_trip(&LL_DEFAULT_NORM, 6, 9);
    }

    #[test]
    fn optimal_table_log_matches_reference_cases() {
        // Small alphabet, modest source: bounded by the source-accuracy term.
        assert_eq!(optimal_table_log(0, 6, 5), 5);
        // Larger source raises the accuracy toward the default/cap.
        assert_eq!(optimal_table_log(9, 100_000, 35), 9);
        // Never below the format minimum.
        assert!(optimal_table_log(0, 3, 1) >= FSE_MIN_TABLELOG);
    }

    /// A normalized distribution must spend exactly `2^tableLog` states (a `-1`
    /// low-probability symbol still costs one state).
    fn assert_sums_to_table(norm: &[i16], table_log: u32) {
        let used: i32 = norm
            .iter()
            .map(|&p| if p == -1 { 1 } else { p as i32 })
            .sum();
        assert_eq!(used, 1i32 << table_log, "uses the whole table");
    }

    #[test]
    fn normalize_then_round_trip_synthetic_histograms() {
        let histograms: &[&[u32]] = &[
            &[5, 5, 5, 5, 5, 5, 5, 5],                         // uniform
            &[100, 50, 25, 12, 6, 3, 2, 1, 1],                 // skewed with low-prob tail
            &[1000, 1, 1, 1, 1, 1, 1, 1],                      // one dominant symbol
            &[7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7], // even, larger alphabet
            &[3, 3, 4, 2, 9, 1, 1, 5, 8, 2],                   // irregular (exercises rounding)
        ];
        for &hist in histograms {
            let total: usize = hist.iter().map(|&c| c as usize).sum();
            let max_symbol = hist.len() as u32 - 1;
            let table_log = optimal_table_log(9, total, max_symbol);
            match normalize_count(hist, total, max_symbol, table_log, true).unwrap() {
                Normalized::Table(norm) => {
                    assert_sums_to_table(&norm, table_log);
                    // Every present symbol keeps a nonzero slot.
                    for (s, &c) in hist.iter().enumerate() {
                        if c > 0 {
                            assert_ne!(norm[s], 0, "symbol {s} dropped");
                        }
                    }
                    round_trip(&norm, table_log, 12);
                }
                Normalized::Rle(_) => panic!("unexpected RLE for a multi-symbol histogram"),
            }
        }
    }

    #[test]
    fn single_symbol_histogram_is_rle() {
        let hist = [0u32, 42, 0, 0];
        match normalize_count(&hist, 42, 3, 6, true).unwrap() {
            Normalized::Rle(s) => assert_eq!(s, 1),
            Normalized::Table(_) => panic!("expected RLE"),
        }
    }

    /// Build matching compression and decompression tables, FSE-encode a symbol
    /// stream, then decode it with the (C-verified) `decode_interleaved`. The
    /// encoder and that decoder are an exact `FSE_compress`/`FSE_decompress`
    /// pair, so a faithful encoder round-trips byte-for-byte.
    #[test]
    fn fse_encode_decode_round_trip() {
        let mut state = 0x243F_6A88_85A3_08D3u64; // deterministic xorshift
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };

        let histograms: &[&[u32]] = &[
            &[100, 50, 25, 12, 6, 3, 2, 1],
            &[5, 5, 5, 5, 5, 5, 5, 5],
            &[400, 1, 1, 1, 1, 1, 200, 50, 3, 9],
        ];
        for hist in histograms {
            let total: usize = hist.iter().map(|&c| c as usize).sum();
            let max_symbol = hist.len() as u32 - 1;
            let table_log = optimal_table_log(9, total, max_symbol);
            let norm = match normalize_count(hist, total, max_symbol, table_log, true).unwrap() {
                Normalized::Table(n) => n,
                Normalized::Rle(_) => unreachable!(),
            };
            let ct = build_ctable(&norm, max_symbol, table_log);
            let dt = fse::build_dtable(&norm, table_log).unwrap();

            // Only symbols with a nonzero normalized count are encodable.
            let encodable: Vec<u8> = (0..=max_symbol as usize)
                .filter(|&s| norm[s] != 0)
                .map(|s| s as u8)
                .collect();

            // Lengths covering every parity / join branch of the encoder.
            for &len in &[3usize, 4, 5, 6, 7, 8, 9, 64, 257, 1000] {
                let symbols: Vec<u8> = (0..len)
                    .map(|_| encodable[(next() % encodable.len() as u64) as usize])
                    .collect();
                let encoded = fse_compress_using_ctable(&ct, &symbols);
                let decoded = fse::decode_interleaved(&dt, &encoded, len + 16).unwrap();
                assert_eq!(decoded, symbols, "round-trip mismatch at len {len}");
            }
        }
    }
}
