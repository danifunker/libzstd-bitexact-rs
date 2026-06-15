//! Compressed-block decoding: literals section, sequences section, and
//! sequence execution.
//!
//! Ports `ZSTD_decodeLiteralsBlock`, `ZSTD_decodeSeqHeaders`, and the
//! `ZSTD_decompressSequences` decode/execute loop.

use crate::bits::ReverseBitReader;
use crate::dictionary::Dictionary;
use crate::error::Error;
use crate::fse::{self, FseState, FseTable};
use crate::huffman::{self, HuffmanTable};

/// `ZSTD_BLOCKSIZE_MAX`.
pub(crate) const BLOCK_SIZE_MAX: usize = 128 * 1024;

// --- Sequence code tables (verified against lib/common/zstd_internal.h and
// --- lib/decompress/zstd_decompress_internal.h of facebook/zstd).

#[rustfmt::skip]
pub(crate) const LL_BITS: [u32; 36] = [
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     1,  1,  1,  1,  2,  2,  3,  3,
     4,  6,  7,  8,  9, 10, 11, 12,
    13, 14, 15, 16,
];

#[rustfmt::skip]
const LL_BASE: [u32; 36] = [
        0,      1,      2,      3,      4,      5,      6,      7,
        8,      9,     10,     11,     12,     13,     14,     15,
       16,     18,     20,     22,     24,     28,     32,     40,
       48,     64,   0x80,  0x100,  0x200,  0x400,  0x800, 0x1000,
   0x2000, 0x4000, 0x8000, 0x10000,
];

#[rustfmt::skip]
pub(crate) const ML_BITS: [u32; 53] = [
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,
     1,  1,  1,  1,  2,  2,  3,  3,
     4,  4,  5,  7,  8,  9, 10, 11,
    12, 13, 14, 15, 16,
];

#[rustfmt::skip]
const ML_BASE: [u32; 53] = [
        3,      4,      5,      6,      7,      8,      9,     10,
       11,     12,     13,     14,     15,     16,     17,     18,
       19,     20,     21,     22,     23,     24,     25,     26,
       27,     28,     29,     30,     31,     32,     33,     34,
       35,     37,     39,     41,     43,     47,     51,     59,
       67,     83,     99,   0x83,  0x103,  0x203,  0x403,  0x803,
   0x1003, 0x2003, 0x4003, 0x8003, 0x10003,
];

#[rustfmt::skip]
pub(crate) const LL_DEFAULT_NORM: [i16; 36] = [
     4, 3, 2, 2, 2, 2, 2, 2,
     2, 2, 2, 2, 2, 1, 1, 1,
     2, 2, 2, 2, 2, 2, 2, 2,
     2, 3, 2, 1, 1, 1, 1, 1,
    -1,-1,-1,-1,
];
pub(crate) const LL_DEFAULT_LOG: u32 = 6;

#[rustfmt::skip]
pub(crate) const ML_DEFAULT_NORM: [i16; 53] = [
     1, 4, 3, 2, 2, 2, 2, 2,
     2, 1, 1, 1, 1, 1, 1, 1,
     1, 1, 1, 1, 1, 1, 1, 1,
     1, 1, 1, 1, 1, 1, 1, 1,
     1, 1, 1, 1, 1, 1, 1, 1,
     1, 1, 1, 1, 1, 1,-1,-1,
    -1,-1,-1,-1,-1,
];
pub(crate) const ML_DEFAULT_LOG: u32 = 6;

#[rustfmt::skip]
pub(crate) const OF_DEFAULT_NORM: [i16; 29] = [
     1, 1, 1, 1, 1, 1, 2, 2,
     2, 1, 1, 1, 1, 1, 1, 1,
     1, 1, 1, 1, 1, 1, 1, 1,
    -1,-1,-1,-1,-1,
];
pub(crate) const OF_DEFAULT_LOG: u32 = 5;

pub(crate) struct SeqTableSpec {
    default_norm: &'static [i16],
    default_log: u32,
    /// Largest valid symbol (`MaxLL` / `MaxOff` / `MaxML`).
    pub(crate) max_symbol: u32,
    /// Largest valid accuracy log (`LLFSELog` / `OffFSELog` / `MLFSELog`).
    pub(crate) max_log: u32,
}

pub(crate) const LL_SPEC: SeqTableSpec = SeqTableSpec {
    default_norm: &LL_DEFAULT_NORM,
    default_log: LL_DEFAULT_LOG,
    max_symbol: 35,
    max_log: 9,
};
pub(crate) const OF_SPEC: SeqTableSpec = SeqTableSpec {
    default_norm: &OF_DEFAULT_NORM,
    default_log: OF_DEFAULT_LOG,
    max_symbol: 31,
    max_log: 8,
};
pub(crate) const ML_SPEC: SeqTableSpec = SeqTableSpec {
    default_norm: &ML_DEFAULT_NORM,
    default_log: ML_DEFAULT_LOG,
    max_symbol: 52,
    max_log: 9,
};

/// Entropy state that persists across the blocks of one frame: the Huffman
/// table (for treeless literals), the three FSE tables (for repeat mode),
/// and the three most recent offsets.
pub(crate) struct FrameContext {
    pub huffman: Option<HuffmanTable>,
    pub ll: Option<FseTable>,
    pub of: Option<FseTable>,
    pub ml: Option<FseTable>,
    pub rep: [u64; 3],
}

impl FrameContext {
    pub(crate) fn new() -> Self {
        FrameContext {
            huffman: None,
            ll: None,
            of: None,
            ml: None,
            // `repStartValue`: the repeat-offset history starts as 1, 4, 8.
            rep: [1, 4, 8],
        }
    }

    /// Seed a frame context from a dictionary (`ZSTD_decompress_insertDictionary`).
    ///
    /// A formatted dictionary supplies the Huffman and FSE tables (so the
    /// first block may use `Repeat_Mode`) and the dictionary-relative repeat
    /// offsets; a raw-content dictionary supplies neither and behaves like
    /// [`FrameContext::new`]. With no dictionary, this is exactly
    /// [`FrameContext::new`].
    pub(crate) fn with_dictionary(dict: Option<&Dictionary>) -> Self {
        match dict {
            None => Self::new(),
            Some(d) => FrameContext {
                huffman: d.huffman().cloned(),
                ll: d.ll().cloned(),
                of: d.of().cloned(),
                ml: d.ml().cloned(),
                rep: d.rep(),
            },
        }
    }
}

/// Decode one compressed block into `out`.
///
/// `frame_base` is the offset in `out` where the current frame started:
/// matches reaching past it draw from `dict_content` (the dictionary window
/// preceding the frame), and may not reach past the start of that.
/// `block_size_max` is `min(window_size, 128 KiB)`; `limit` caps `out.len()`
/// overall.
pub(crate) fn decode_compressed_block(
    ctx: &mut FrameContext,
    src: &[u8],
    out: &mut Vec<u8>,
    frame_base: usize,
    dict_content: &[u8],
    block_size_max: usize,
    limit: usize,
) -> Result<(), Error> {
    let (literals, consumed) = decode_literals(ctx, src, block_size_max)?;
    decode_and_execute_sequences(
        ctx,
        &src[consumed..],
        &literals,
        out,
        frame_base,
        dict_content,
        block_size_max,
        limit,
    )
}

/// Decode the literals section. Returns the literals and the number of bytes
/// consumed from `src`.
pub(crate) fn decode_literals(
    ctx: &mut FrameContext,
    src: &[u8],
    block_size_max: usize,
) -> Result<(Vec<u8>, usize), Error> {
    let b0 = *src
        .first()
        .ok_or(Error::Corrupted("missing literals header"))? as usize;
    let lit_type = b0 & 3;
    let size_format = (b0 >> 2) & 3;
    let trunc = Error::Corrupted("literals section truncated");

    if lit_type == 0 || lit_type == 1 {
        // Raw or RLE literals.
        let (regen, header) = match size_format {
            0 | 2 => (b0 >> 3, 1usize),
            1 => {
                let b1 = *src.get(1).ok_or(trunc)? as usize;
                ((b0 >> 4) | (b1 << 4), 2)
            }
            _ => {
                let b1 = *src.get(1).ok_or(trunc)? as usize;
                let b2 = *src.get(2).ok_or(trunc)? as usize;
                ((b0 >> 4) | (b1 << 4) | (b2 << 12), 3)
            }
        };
        if regen > block_size_max {
            return Err(Error::Corrupted("literals exceed block size limit"));
        }
        if lit_type == 0 {
            let data = src.get(header..header + regen).ok_or(trunc)?;
            Ok((data.to_vec(), header + regen))
        } else {
            let byte = *src.get(header).ok_or(trunc)?;
            Ok((vec![byte; regen], header + 1))
        }
    } else {
        // Huffman-compressed (2) or treeless/repeat (3) literals.
        let (four_streams, regen, compressed, header) = match size_format {
            0 | 1 => {
                let b1 = *src.get(1).ok_or(trunc)? as usize;
                let b2 = *src.get(2).ok_or(trunc)? as usize;
                let regen = (b0 >> 4) | ((b1 & 0x3F) << 4);
                let compressed = (b1 >> 6) | (b2 << 2);
                (size_format == 1, regen, compressed, 3usize)
            }
            2 => {
                let b1 = *src.get(1).ok_or(trunc)? as usize;
                let b2 = *src.get(2).ok_or(trunc)? as usize;
                let b3 = *src.get(3).ok_or(trunc)? as usize;
                let regen = (b0 >> 4) | (b1 << 4) | ((b2 & 3) << 12);
                let compressed = (b2 >> 2) | (b3 << 6);
                (true, regen, compressed, 4)
            }
            _ => {
                let b1 = *src.get(1).ok_or(trunc)? as usize;
                let b2 = *src.get(2).ok_or(trunc)? as usize;
                let b3 = *src.get(3).ok_or(trunc)? as usize;
                let b4 = *src.get(4).ok_or(trunc)? as usize;
                let regen = (b0 >> 4) | (b1 << 4) | ((b2 & 0x3F) << 12);
                let compressed = (b2 >> 6) | (b3 << 2) | (b4 << 10);
                (true, regen, compressed, 5)
            }
        };
        if regen > block_size_max {
            return Err(Error::Corrupted("literals exceed block size limit"));
        }
        let mut payload = src.get(header..header + compressed).ok_or(trunc)?;
        if lit_type == 2 {
            let (table, used) = huffman::read_table(payload)?;
            ctx.huffman = Some(table);
            payload = &payload[used..];
        }
        let table = ctx.huffman.as_ref().ok_or(Error::Corrupted(
            "treeless literals without a previous table",
        ))?;
        let literals = if four_streams {
            huffman::decode_four_streams(table, payload, regen)?
        } else {
            huffman::decode_single_stream(table, payload, regen)?
        };
        Ok((literals, header + compressed))
    }
}

/// Install the FSE table for one sequence component according to its
/// compression mode (`ZSTD_buildSeqTable`).
fn build_sequence_table(
    slot: &mut Option<FseTable>,
    mode: u8,
    input: &mut &[u8],
    spec: &SeqTableSpec,
) -> Result<(), Error> {
    match mode {
        // Predefined_Mode
        0 => *slot = Some(fse::build_dtable(spec.default_norm, spec.default_log)?),
        // RLE_Mode: one byte holding the single symbol.
        1 => {
            let symbol = *input
                .first()
                .ok_or(Error::Corrupted("missing RLE sequence symbol"))?;
            if u32::from(symbol) > spec.max_symbol {
                return Err(Error::Corrupted("RLE sequence symbol out of range"));
            }
            *slot = Some(FseTable::rle(symbol));
            *input = &input[1..];
        }
        // FSE_Compressed_Mode
        2 => {
            let nc = fse::read_ncount(input, spec.max_symbol, spec.max_log)?;
            *slot = Some(fse::build_dtable(&nc.counts, nc.table_log)?);
            *input = &input[nc.bytes_consumed..];
        }
        // Repeat_Mode: keep the table from the previous block.
        _ => {
            if slot.is_none() {
                return Err(Error::Corrupted("repeat mode without a previous table"));
            }
        }
    }
    Ok(())
}

/// Resolve an offset value against the repeat-offset history, updating it.
///
/// Mirrors `ZSTD_decodeSequence`: values above 3 are literal offsets
/// (`value - 3`); 1..=3 select recent offsets, shifted by one when the
/// sequence has no literals (in which case "repeat offset 3" means
/// `rep[0] - 1`).
fn resolve_offset(of_value: u64, lit_len: u64, rep: &mut [u64; 3]) -> Result<u64, Error> {
    if of_value > 3 {
        let offset = of_value - 3;
        rep[2] = rep[1];
        rep[1] = rep[0];
        rep[0] = offset;
        return Ok(offset);
    }
    let index = of_value + u64::from(lit_len == 0);
    match index {
        1 => Ok(rep[0]),
        2 => {
            rep.swap(0, 1);
            Ok(rep[0])
        }
        3 => {
            let offset = rep[2];
            rep[2] = rep[1];
            rep[1] = rep[0];
            rep[0] = offset;
            Ok(offset)
        }
        _ => {
            let offset = rep[0] - 1;
            if offset == 0 {
                return Err(Error::Corrupted("repeat offset underflow"));
            }
            rep[2] = rep[1];
            rep[1] = rep[0];
            rep[0] = offset;
            Ok(offset)
        }
    }
}

/// Append `len` bytes of a match into `out`.
///
/// The match source lies `offset` bytes back in the virtual history
/// `dict_content` followed by `out[frame_base..]`. `cur` is the frame output
/// already produced (`out.len() - frame_base`). When the match reaches no
/// further than the frame's own output (`offset <= cur`) it is a pure
/// in-buffer copy with the usual run-extending overlap; otherwise it begins in
/// the dictionary window and is copied byte by byte (this only happens near
/// the start of a dictionary-compressed frame).
#[inline]
fn copy_match(
    out: &mut Vec<u8>,
    frame_base: usize,
    dict_content: &[u8],
    offset: usize,
    len: usize,
) {
    let cur = out.len() - frame_base;
    debug_assert!(offset >= 1 && offset <= cur + dict_content.len());

    if offset <= cur {
        if offset == 1 {
            let byte = out[out.len() - 1];
            out.resize(out.len() + len, byte);
            return;
        }
        if offset >= len {
            let start = out.len() - offset;
            out.extend_from_within(start..start + len);
            return;
        }
        let mut remaining = len;
        while remaining > 0 {
            let chunk = remaining.min(offset);
            let start = out.len() - offset;
            out.extend_from_within(start..start + chunk);
            remaining -= chunk;
        }
        return;
    }

    // The match starts inside the dictionary window. Index `i` of the match
    // reads virtual byte `dict_content.len() + cur - offset + i`, where the
    // virtual buffer is `dict_content ++ out[frame_base..]` and grows as we
    // append — a standard overlapping copy spanning the dict/output seam.
    let dlen = dict_content.len();
    let start_v = dlen + cur - offset;
    for i in 0..len {
        let s = start_v + i;
        let b = if s < dlen {
            dict_content[s]
        } else {
            out[frame_base + (s - dlen)]
        };
        out.push(b);
    }
}

#[allow(clippy::too_many_arguments)]
fn decode_and_execute_sequences(
    ctx: &mut FrameContext,
    src: &[u8],
    literals: &[u8],
    out: &mut Vec<u8>,
    frame_base: usize,
    dict_content: &[u8],
    block_size_max: usize,
    limit: usize,
) -> Result<(), Error> {
    let block_start = out.len();

    // Number_of_Sequences.
    let b0 = *src
        .first()
        .ok_or(Error::Corrupted("missing sequence count"))? as usize;
    let (nb_seq, mut pos) = if b0 < 128 {
        (b0, 1usize)
    } else if b0 < 255 {
        let b1 = *src
            .get(1)
            .ok_or(Error::Corrupted("missing sequence count"))? as usize;
        (((b0 - 128) << 8) + b1, 2)
    } else {
        let b1 = *src
            .get(1)
            .ok_or(Error::Corrupted("missing sequence count"))? as usize;
        let b2 = *src
            .get(2)
            .ok_or(Error::Corrupted("missing sequence count"))? as usize;
        (b1 + (b2 << 8) + 0x7F00, 3)
    };

    if nb_seq == 0 {
        if src.len() != pos {
            return Err(Error::Corrupted(
                "trailing bytes after empty sequence section",
            ));
        }
        if out.len() + literals.len() > limit {
            return Err(Error::OutputTooLarge);
        }
        out.extend_from_slice(literals);
        return Ok(());
    }

    let modes = *src
        .get(pos)
        .ok_or(Error::Corrupted("missing sequence modes"))?;
    pos += 1;
    if modes & 3 != 0 {
        return Err(Error::Corrupted("reserved sequence mode bits set"));
    }
    let mut input = &src[pos..];
    build_sequence_table(&mut ctx.ll, modes >> 6, &mut input, &LL_SPEC)?;
    build_sequence_table(&mut ctx.of, (modes >> 4) & 3, &mut input, &OF_SPEC)?;
    build_sequence_table(&mut ctx.ml, (modes >> 2) & 3, &mut input, &ML_SPEC)?;

    let ll_table = ctx.ll.as_ref().expect("set above");
    let of_table = ctx.of.as_ref().expect("set above");
    let ml_table = ctx.ml.as_ref().expect("set above");
    let mut rep = ctx.rep;

    let mut br = ReverseBitReader::new(input)?;
    // Initial states, in stream order: literals length, offset, match length.
    let mut ll_state = FseState::new(ll_table, &mut br);
    let mut of_state = FseState::new(of_table, &mut br);
    let mut ml_state = FseState::new(ml_table, &mut br);

    // Decode all sequences first, then execute them — a deliberate two-pass
    // split (C interleaves the two). Keeping decode and execution in separate
    // loops lets the backward bit reader and the three FSE states stay in
    // registers across the whole decode loop instead of being spilled by the
    // output-buffer writes of an interleaved execution; it measurably speeds up
    // decompression. Accept/reject and the emitted bytes are unchanged: the FSE
    // decode never reads `out` and the execution never touches the bit reader,
    // so the two passes are independent. (`lit_len`/`match_len` fit a `u32` —
    // each is bounded by the 128 KiB block size — while `offset` can exceed it.)
    let mut decoded: Vec<(u32, usize, u32)> = Vec::with_capacity(nb_seq);
    for i in 0..nb_seq {
        let ll_code = ll_state.symbol() as usize;
        let of_code = of_state.symbol() as u32;
        let ml_code = ml_state.symbol() as usize;

        // Extra bits are read offset first, then match length, then
        // literals length.
        let of_value = (1u64 << of_code) + br.read(of_code);
        let match_len = u64::from(ML_BASE[ml_code]) + br.read(ML_BITS[ml_code]);
        let lit_len = u64::from(LL_BASE[ll_code]) + br.read(LL_BITS[ll_code]);
        let offset = resolve_offset(of_value, lit_len, &mut rep)?;

        // States update after every sequence but the last, in the order
        // literals length, match length, offset.
        if i + 1 < nb_seq {
            ll_state.advance(&mut br);
            ml_state.advance(&mut br);
            of_state.advance(&mut br);
        }
        if br.bits_remaining() < 0 {
            return Err(Error::Corrupted("sequence bitstream overdrawn"));
        }
        decoded.push((lit_len as u32, offset as usize, match_len as u32));
    }

    let mut lit_pos = 0usize;
    for (lit_len, offset, match_len) in decoded {
        let lit_len = lit_len as usize;
        if lit_len > literals.len() - lit_pos {
            return Err(Error::Corrupted(
                "sequence consumes more literals than available",
            ));
        }
        out.extend_from_slice(&literals[lit_pos..lit_pos + lit_len]);
        lit_pos += lit_len;

        // Available history is the frame output so far plus the dictionary
        // window that precedes it (`oLitEnd - virtualStart` in the C decoder).
        let history = (out.len() - frame_base) as u64 + dict_content.len() as u64;
        if offset as u64 > history {
            return Err(Error::Corrupted("match offset beyond frame history"));
        }
        copy_match(out, frame_base, dict_content, offset, match_len as usize);

        if out.len() - block_start > block_size_max {
            return Err(Error::Corrupted("block output exceeds block size limit"));
        }
        if out.len() > limit {
            return Err(Error::OutputTooLarge);
        }
    }

    if !br.finished_exactly() {
        return Err(Error::Corrupted("sequence bitstream not fully consumed"));
    }

    // Remaining literals are copied verbatim after the last sequence.
    out.extend_from_slice(&literals[lit_pos..]);
    if out.len() - block_start > block_size_max {
        return Err(Error::Corrupted("block output exceeds block size limit"));
    }
    if out.len() > limit {
        return Err(Error::OutputTooLarge);
    }
    ctx.rep = rep;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_match_handles_overlap() {
        let mut out = b"abc".to_vec();
        copy_match(&mut out, 0, &[], 3, 7);
        assert_eq!(out, b"abcabcabca");

        let mut out = b"xy".to_vec();
        copy_match(&mut out, 0, &[], 1, 4);
        assert_eq!(out, b"xyyyyy");

        let mut out = b"hello world".to_vec();
        copy_match(&mut out, 0, &[], 11, 5);
        assert_eq!(out, b"hello worldhello");
    }

    #[test]
    fn copy_match_reaches_into_dictionary() {
        // Virtual history is `dict ++ out[frame_base..]`. Here frame_base = 2
        // (the leading "XX" is prior-frame output, off limits); the dictionary
        // holds "DICT", and the frame output so far is "ab", so the virtual
        // buffer is "DICTab".
        let dict = b"DICT";

        // Straddle the seam: offset 4 from position 6 starts at 'C', copying
        // "CT" from the dictionary and "ab" from the frame output.
        let mut out = b"XXab".to_vec();
        copy_match(&mut out, 2, dict, 4, 4);
        assert_eq!(&out[2..], b"abCTab");

        // A match wholly inside the dictionary.
        let mut out = b"XX".to_vec();
        copy_match(&mut out, 2, dict, 4, 4);
        assert_eq!(&out[2..], b"DICT");

        // A match straddling the seam that then run-extends over itself:
        // "CT" from the dictionary, then the freshly written bytes repeat.
        let mut out = b"XX".to_vec();
        copy_match(&mut out, 2, dict, 2, 5);
        assert_eq!(&out[2..], b"CTCTC");
    }

    #[test]
    fn repeat_offsets_follow_spec() {
        let mut rep = [1, 4, 8];
        // Literal offset: value 10 -> offset 7, history shifts.
        assert_eq!(resolve_offset(10, 5, &mut rep).unwrap(), 7);
        assert_eq!(rep, [7, 1, 4]);
        // Repeat offset 1 with literals: no change.
        assert_eq!(resolve_offset(1, 5, &mut rep).unwrap(), 7);
        assert_eq!(rep, [7, 1, 4]);
        // Repeat offset 2: swaps.
        assert_eq!(resolve_offset(2, 5, &mut rep).unwrap(), 1);
        assert_eq!(rep, [1, 7, 4]);
        // Repeat offset 3: rotates.
        assert_eq!(resolve_offset(3, 5, &mut rep).unwrap(), 4);
        assert_eq!(rep, [4, 1, 7]);
        // No literals: value 1 selects rep[1].
        assert_eq!(resolve_offset(1, 0, &mut rep).unwrap(), 1);
        assert_eq!(rep, [1, 4, 7]);
        // No literals: value 3 means rep[0] - 1.
        let mut rep = [5, 10, 20];
        assert_eq!(resolve_offset(3, 0, &mut rep).unwrap(), 4);
        assert_eq!(rep, [4, 5, 10]);
        // ... which is corruption when rep[0] is 1.
        let mut rep = [1, 4, 8];
        assert!(resolve_offset(3, 0, &mut rep).is_err());
    }
}
