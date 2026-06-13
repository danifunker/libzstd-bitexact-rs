//! Encoder-side trained-dictionary parsing (`ZSTD_loadCEntropy`).
//!
//! A trained (`ZDICT`) dictionary carries precomputed entropy tables that seed
//! the *first* block's `prevCBlock` entropy: a literals Huffman table, three FSE
//! tables (offset / match-length / literal-length), and three repeat offsets.
//! Reusing them lets the first block encode in `Repeat_Mode` (or at least skip
//! re-describing a table), which is exactly what makes a trained dictionary's
//! output differ from a raw-content one.
//!
//! The decoder's [`crate::dictionary`] parses the same header into *decode*
//! tables; the encoder needs its own *compression* tables, so this module reads
//! the Huffman table with [`crate::huffman_encode::read_ctable`] and the FSE
//! tables with [`crate::fse::read_ncount`] + [`crate::fse_encode::build_ctable`].
//! Layout and validation follow `ZSTD_loadCEntropy` (zstd_compress.c) byte for
//! byte. The match-finder fill over the dictionary *content* (everything after
//! this header) is identical to the raw-dictionary path and runs separately.

use crate::block::{LL_SPEC, ML_SPEC, OF_SPEC};
use crate::error::Error;
use crate::huffman_encode::{self, HufRepeat};
use crate::literals_encode::HufState;
use crate::sequences_encode::{FseEntropyState, FseRepeat};
use crate::{fse, fse_encode};

/// `BIT_highbit32`: index of the most-significant set bit. Callers guarantee
/// `x >= 1`.
fn highbit32(x: u32) -> u32 {
    debug_assert!(x >= 1);
    31 - x.leading_zeros()
}

/// The entropy state a trained dictionary seeds into a frame's first block,
/// plus the offset where the dictionary *content* begins (`ZSTD_loadCEntropy`'s
/// return value) and the dictionary ID for the frame header.
pub(crate) struct DictCEntropy {
    /// Seed for `FrameCompressor.entropy` (`prevCBlock->entropy`).
    pub(crate) entropy: FseEntropyState,
    /// Seed for `FrameCompressor.rep` (`prevCBlock->rep`).
    pub(crate) rep: [u32; 3],
    /// `Dictionary_ID`, written into the frame header.
    pub(crate) dict_id: u32,
    /// Bytes consumed by magic + ID + entropy tables + reps; the content (used
    /// for the match-finder fill) is `dict[entropy_size..]`.
    pub(crate) entropy_size: usize,
}

/// `ZSTD_dictNCountRepeat`: a dictionary FSE table is reusable as a
/// `Repeat_Mode` candidate (`FSE_repeat_valid`) only if it covers every symbol
/// up to `max_symbol` with a nonzero probability; otherwise it stays
/// `FSE_repeat_check` so the cost-based selection re-validates it per block.
fn dict_ncount_repeat(norm: &[i16], dict_max_symbol: u32, max_symbol: u32) -> FseRepeat {
    if dict_max_symbol < max_symbol {
        return FseRepeat::Check;
    }
    // A "less than one" probability is stored as -1, still a present symbol; only
    // an exact zero means the table cannot encode that symbol.
    if norm[..=max_symbol as usize].contains(&0) {
        return FseRepeat::Check;
    }
    FseRepeat::Valid
}

/// `ZSTD_loadCEntropy`: parse the entropy section of a trained dictionary into
/// encoder tables. `dict` is the whole dictionary buffer; the caller has
/// verified it is at least 8 bytes and begins with `ZSTD_MAGIC_DICTIONARY`.
pub(crate) fn load_c_entropy(dict: &[u8]) -> Result<DictCEntropy, Error> {
    let corrupt = Error::DictionaryCorrupted;
    // Skip the magic number (already checked) and read the 4-byte dictionary ID.
    let dict_id = u32::from_le_bytes(dict.get(4..8).ok_or(corrupt)?.try_into().unwrap());
    let mut pos = 8usize;

    // Literals Huffman CTable. The table is only promoted to `HUF_repeat_valid`
    // when it has no zero weights and spans the full 256-symbol alphabet;
    // otherwise it stays `check`.
    let (huf_ct, has_zero_weights, used) =
        huffman_encode::read_ctable(dict.get(pos..).ok_or(corrupt)?).map_err(|_| corrupt)?;
    let huf_repeat = if !has_zero_weights && huf_ct.max_symbol == 255 {
        HufRepeat::Valid
    } else {
        HufRepeat::Check
    };
    pos += used;

    // Offset-code FSE CTable. C builds it over the full `MaxOff` alphabet ("fill
    // all offset symbols to avoid garbage at end of table"), so pad the read
    // distribution with zeros up to `MaxOff + 1`. Its repeat mode is deferred
    // until the content size is known.
    let of_nc = fse::read_ncount(
        dict.get(pos..).ok_or(corrupt)?,
        OF_SPEC.max_symbol,
        OF_SPEC.max_log,
    )
    .map_err(|_| corrupt)?;
    let of_dict_max = (of_nc.counts.len() - 1) as u32;
    let mut of_norm = of_nc.counts;
    of_norm.resize(OF_SPEC.max_symbol as usize + 1, 0);
    let of_ct = fse_encode::build_ctable(&of_norm, OF_SPEC.max_symbol, of_nc.table_log);
    pos += of_nc.bytes_consumed;

    // Match-length FSE CTable, built over the actual maximum symbol read.
    let ml_nc = fse::read_ncount(
        dict.get(pos..).ok_or(corrupt)?,
        ML_SPEC.max_symbol,
        ML_SPEC.max_log,
    )
    .map_err(|_| corrupt)?;
    let ml_dict_max = (ml_nc.counts.len() - 1) as u32;
    let ml_ct = fse_encode::build_ctable(&ml_nc.counts, ml_dict_max, ml_nc.table_log);
    let ml_repeat = dict_ncount_repeat(&ml_nc.counts, ml_dict_max, ML_SPEC.max_symbol);
    pos += ml_nc.bytes_consumed;

    // Literal-length FSE CTable.
    let ll_nc = fse::read_ncount(
        dict.get(pos..).ok_or(corrupt)?,
        LL_SPEC.max_symbol,
        LL_SPEC.max_log,
    )
    .map_err(|_| corrupt)?;
    let ll_dict_max = (ll_nc.counts.len() - 1) as u32;
    let ll_ct = fse_encode::build_ctable(&ll_nc.counts, ll_dict_max, ll_nc.table_log);
    let ll_repeat = dict_ncount_repeat(&ll_nc.counts, ll_dict_max, LL_SPEC.max_symbol);
    pos += ll_nc.bytes_consumed;

    // Three 32-bit repeat offsets precede the dictionary content.
    let reps = dict.get(pos..pos + 12).ok_or(corrupt)?;
    let mut rep = [0u32; 3];
    for (i, slot) in rep.iter_mut().enumerate() {
        *slot = u32::from_le_bytes(reps[4 * i..4 * i + 4].try_into().unwrap());
    }
    pos += 12;

    let entropy_size = pos;
    let dict_content_size = dict.len() - entropy_size;

    // Offcode repeat mode: every offset value `<= dictContentSize + 128 KB` must
    // be representable for the dictionary's table to be reusable.
    let mut offcode_max = OF_SPEC.max_symbol;
    if dict_content_size as u64 <= u64::from(u32::MAX) - 128 * 1024 {
        let max_offset = (dict_content_size as u32).wrapping_add(128 * 1024);
        offcode_max = highbit32(max_offset);
    }
    let of_repeat = dict_ncount_repeat(&of_norm, of_dict_max, offcode_max.min(OF_SPEC.max_symbol));

    // Every repcode must be nonzero and reach no further back than the content.
    for &r in &rep {
        if r == 0 || r as usize > dict_content_size {
            return Err(corrupt);
        }
    }

    Ok(DictCEntropy {
        entropy: FseEntropyState {
            huf: HufState {
                table: Some(huf_ct),
                repeat: huf_repeat,
            },
            ll: Some(ll_ct),
            ll_repeat,
            of: Some(of_ct),
            of_repeat,
            ml: Some(ml_ct),
            ml_repeat,
        },
        rep,
        dict_id,
        entropy_size,
    })
}
