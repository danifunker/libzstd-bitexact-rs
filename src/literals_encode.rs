//! Literals-section encoder (`ZSTD_compressLiterals` and its `set_basic` /
//! `set_rle` special cases). Chooses among raw, RLE, and Huffman-compressed
//! literals and writes the section header that [`crate::block::decode_literals`]
//! reads back. Ports of `zstd_compress_literals.c` (bundled zstd 1.5.7).
//!
//! `set_repeat` (treeless literals, reusing the previous block's Huffman table)
//! is deferred to the block compressor (M4), since it needs cross-block state;
//! this module always builds a fresh table for the compressed case.
//!
//! Verified by round-tripping the emitted section through the decoder.
#![allow(dead_code)] // wired into the public compressor in a later milestone

use crate::huffman_encode::{self, HufOutput};

// Literals block types (the low 2 bits of the section header).
const SET_BASIC: u32 = 0; // raw
const SET_RLE: u32 = 1;
const SET_COMPRESSED: u32 = 2;

/// `ZSTD_noCompressLiterals`: a raw literals section.
pub(crate) fn raw_literals(src: &[u8]) -> Vec<u8> {
    let n = src.len();
    let fl_size = 1 + (n > 31) as usize + (n > 4095) as usize;
    let mut out = Vec::with_capacity(fl_size + n);
    write_basic_header(&mut out, SET_BASIC, n, fl_size);
    out.extend_from_slice(src);
    out
}

/// `ZSTD_compressRleLiteralsBlock`: an RLE literals section (one repeated byte).
pub(crate) fn rle_literals(src: &[u8]) -> Vec<u8> {
    let n = src.len();
    let fl_size = 1 + (n > 31) as usize + (n > 4095) as usize;
    let mut out = Vec::with_capacity(fl_size + 1);
    write_basic_header(&mut out, SET_RLE, n, fl_size);
    out.push(src[0]);
    out
}

/// Shared header writer for the raw/RLE (`set_basic` / `set_rle`) shapes.
fn write_basic_header(out: &mut Vec<u8>, set_type: u32, n: usize, fl_size: usize) {
    let n = n as u32;
    match fl_size {
        1 => out.push((set_type + (n << 3)) as u8), // 2 - 1 - 5
        2 => {
            let v = set_type + (1 << 2) + (n << 4); // 2 - 2 - 12
            out.extend_from_slice(&(v as u16).to_le_bytes());
        }
        _ => {
            let v = set_type + (3 << 2) + (n << 4); // 2 - 2 - 20
            let b = v.to_le_bytes();
            out.extend_from_slice(&b[..3]);
        }
    }
}

/// `ZSTD_minLiteralsToCompress` (no previous table): minimum literal count
/// before compression is even attempted, tightening with strategy.
fn min_literals_to_compress(strategy: i32) -> usize {
    let shift = (9 - strategy).clamp(0, 3);
    8usize << shift
}

/// `ZSTD_minGain`: minimum byte savings required to keep a compressed section
/// (also applied at whole-block level by the sequences encoder).
pub(crate) fn min_gain(src_size: usize, strategy: i32) -> usize {
    let minlog = if strategy >= 8 {
        strategy as u32 - 1
    } else {
        6
    };
    (src_size >> minlog) + 2
}

/// `ZSTD_compressLiterals`: pick the best literals representation for `src` at
/// the given compression `strategy` (1..=9), returning the section bytes.
/// `suspect_uncompressible` enables the sampling short-circuit for inputs the
/// caller already believes are high-entropy (`HUF_flags_suspectUncompressible`);
/// `disable_literal_compression` forces raw literals
/// (`ZSTD_literalsCompressionIsDisabled` — true in `ZSTD_ps_auto` mode for the
/// fast strategy with a nonzero target length, i.e. the negative levels).
pub(crate) fn compress_literals(
    src: &[u8],
    strategy: i32,
    suspect_uncompressible: bool,
    disable_literal_compression: bool,
) -> Vec<u8> {
    let n = src.len();
    if disable_literal_compression {
        return raw_literals(src);
    }
    if n < min_literals_to_compress(strategy) {
        return raw_literals(src);
    }

    // 4-stream coding for larger inputs (no table reuse here).
    let single_stream = n < 256;

    match huffman_encode::huf_compress(src, single_stream, suspect_uncompressible) {
        HufOutput::Raw => raw_literals(src),
        HufOutput::Rle => rle_literals(src),
        HufOutput::Compressed(payload) => {
            let c_lit_size = payload.len();
            if c_lit_size >= n - min_gain(n, strategy) {
                return raw_literals(src);
            }
            let mut out = compressed_header(n, c_lit_size, single_stream);
            out.extend_from_slice(&payload);
            out
        }
    }
}

/// Write the `set_compressed` section header (`lhSize` of 3/4/5 bytes).
fn compressed_header(src_size: usize, c_lit_size: usize, single_stream: bool) -> Vec<u8> {
    let lh_size = 3 + (src_size >= 1024) as usize + (src_size >= 16384) as usize;
    let four = (!single_stream) as u32;
    let srcs = src_size as u32;
    let clits = c_lit_size as u32;
    let mut out = Vec::with_capacity(lh_size);
    match lh_size {
        3 => {
            // 2 - 2 - 10 - 10
            let lhc = SET_COMPRESSED + (four << 2) + (srcs << 4) + (clits << 14);
            out.extend_from_slice(&lhc.to_le_bytes()[..3]);
        }
        4 => {
            // 2 - 2 - 14 - 14
            let lhc = SET_COMPRESSED + (2 << 2) + (srcs << 4) + (clits << 18);
            out.extend_from_slice(&lhc.to_le_bytes());
        }
        _ => {
            // 2 - 2 - 18 - 18
            let lhc = SET_COMPRESSED + (3 << 2) + (srcs << 4) + (clits << 22);
            out.extend_from_slice(&lhc.to_le_bytes());
            out.push((c_lit_size >> 10) as u8);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{self, BLOCK_SIZE_MAX, FrameContext};

    /// Decode an emitted section with a fresh context and require the literals
    /// back, with the whole section consumed.
    fn assert_round_trip(literals: &[u8]) {
        let section = compress_literals(literals, 3, false, false);
        let mut ctx = FrameContext::new();
        let (decoded, used) = block::decode_literals(&mut ctx, &section, BLOCK_SIZE_MAX)
            .unwrap_or_else(|e| panic!("decode of {}-byte literals failed: {e}", literals.len()));
        assert_eq!(decoded, literals, "literals round-trip mismatch");
        assert_eq!(used, section.len(), "section length mismatch");
    }

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

    #[test]
    fn tiny_inputs_stay_raw() {
        for n in 0..40usize {
            let data = sample(0x1111 ^ n as u64, n, 20);
            assert_round_trip(&data);
        }
    }

    #[test]
    fn rle_literals_round_trip() {
        for &n in &[1usize, 5, 50, 5000, 100_000] {
            assert_round_trip(&vec![0xABu8; n]);
        }
    }

    #[test]
    fn compressible_literals_use_huffman_and_round_trip() {
        // Skewed alphabets compress; sizes span the 1-stream/4-stream split and
        // the 3/4/5-byte header sizes (256, 1 KiB, 16 KiB thresholds).
        for &alphabet in &[8u32, 40, 120] {
            for &len in &[200usize, 300, 2000, 20_000, 70_000] {
                assert_round_trip(&sample(0xC0DE ^ (len as u64), len, alphabet));
            }
        }
    }

    #[test]
    fn incompressible_literals_fall_back_to_raw() {
        // Near-uniform bytes over the full alphabet: Huffman can't help, so the
        // encoder must fall back to a raw section that still round-trips.
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        let data: Vec<u8> = (0..10_000)
            .map(|_| {
                s ^= s >> 12;
                s ^= s << 25;
                s ^= s >> 27;
                (s.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33) as u8
            })
            .collect();
        assert_round_trip(&data);
    }
}
