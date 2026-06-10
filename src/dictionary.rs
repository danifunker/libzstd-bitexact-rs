//! Dictionary parsing (`ZSTD_loadDEntropy` / raw-content dictionaries).
//!
//! A Zstandard dictionary is either:
//!
//! * **Formatted** (the `ZDICT` / trained format): the magic number
//!   `0xEC30A437`, a 4-byte dictionary ID, the entropy tables (one Huffman
//!   table, then three FSE tables in offset / match-length / literal-length
//!   order), three 32-bit repeat offsets, and finally the dictionary content.
//! * **Raw content**: any other buffer, used verbatim as window history with
//!   no precomputed entropy tables and the default repeat offsets.
//!
//! The entropy tables and repeat offsets seed the per-frame decoding context
//! exactly as `ZSTD_decompress_insertDictionary` does in the C sources, so the
//! first block of a dictionary-compressed frame may use `Repeat_Mode` tables
//! and dictionary-relative repeat offsets.

use crate::block::{LL_SPEC, ML_SPEC, OF_SPEC};
use crate::error::Error;
use crate::fse::{self, FseTable};
use crate::huffman::{self, HuffmanTable};

/// `ZSTD_MAGIC_DICTIONARY`.
const DICT_MAGIC: u32 = 0xEC30_A437;

/// A parsed Zstandard dictionary, ready to seed decompression.
///
/// Build one with [`Dictionary::new`] (which auto-detects the formatted and
/// raw-content cases) or [`Dictionary::raw_content`]. Pass it to
/// [`DecodeOptions::dictionary`](crate::DecodeOptions::dictionary).
pub struct Dictionary {
    id: u32,
    content: Vec<u8>,
    huffman: Option<HuffmanTable>,
    ll: Option<FseTable>,
    of: Option<FseTable>,
    ml: Option<FseTable>,
    rep: [u64; 3],
}

impl Dictionary {
    /// Parse a dictionary buffer.
    ///
    /// A buffer that begins with the `ZDICT` magic number is parsed as a
    /// formatted dictionary; anything else is treated as raw content, matching
    /// the C library's `ZSTD_isFrameMagic`/raw-content fallback. A buffer that
    /// begins with the magic but is malformed yields [`Error::DictionaryCorrupted`].
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() >= 8 && u32::from_le_bytes(bytes[..4].try_into().unwrap()) == DICT_MAGIC {
            Self::parse_formatted(bytes)
        } else {
            Ok(Self::raw_content(bytes))
        }
    }

    /// Treat `content` as a raw-content dictionary: window history with the
    /// default repeat offsets and no precomputed entropy tables. The
    /// dictionary ID is zero.
    pub fn raw_content(content: &[u8]) -> Self {
        Dictionary {
            id: 0,
            content: content.to_vec(),
            huffman: None,
            ll: None,
            of: None,
            ml: None,
            // `repStartValue`, as for a frame with no dictionary.
            rep: [1, 4, 8],
        }
    }

    /// The dictionary ID, or zero for a raw-content dictionary (or a formatted
    /// dictionary that declares ID zero).
    pub fn id(&self) -> u32 {
        self.id
    }

    fn parse_formatted(bytes: &[u8]) -> Result<Self, Error> {
        let corrupt = Error::DictionaryCorrupted;
        let id = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let mut pos = 8usize;

        // Entropy tables, in the order `ZSTD_loadDEntropy` reads them: one
        // Huffman table for literals, then the offset, match-length, and
        // literal-length FSE tables.
        let (huffman, used) =
            huffman::read_table(bytes.get(pos..).ok_or(corrupt)?).map_err(|_| corrupt)?;
        pos += used;
        let of = read_dict_fse(bytes, &mut pos, &OF_SPEC)?;
        let ml = read_dict_fse(bytes, &mut pos, &ML_SPEC)?;
        let ll = read_dict_fse(bytes, &mut pos, &LL_SPEC)?;

        // Three 32-bit repeat offsets precede the content.
        let reps = bytes.get(pos..pos + 12).ok_or(corrupt)?;
        let content = bytes[pos + 12..].to_vec();
        let mut rep = [0u64; 3];
        for (i, slot) in rep.iter_mut().enumerate() {
            let r = u32::from_le_bytes(reps[4 * i..4 * i + 4].try_into().unwrap()) as u64;
            // `if (rep==0 || rep > dictContentSize) corrupted` in the C loader.
            if r == 0 || r > content.len() as u64 {
                return Err(corrupt);
            }
            *slot = r;
        }

        Ok(Dictionary {
            id,
            content,
            huffman: Some(huffman),
            ll: Some(ll),
            of: Some(of),
            ml: Some(ml),
            rep,
        })
    }

    pub(crate) fn content(&self) -> &[u8] {
        &self.content
    }

    pub(crate) fn huffman(&self) -> Option<&HuffmanTable> {
        self.huffman.as_ref()
    }

    pub(crate) fn ll(&self) -> Option<&FseTable> {
        self.ll.as_ref()
    }

    pub(crate) fn of(&self) -> Option<&FseTable> {
        self.of.as_ref()
    }

    pub(crate) fn ml(&self) -> Option<&FseTable> {
        self.ml.as_ref()
    }

    pub(crate) fn rep(&self) -> [u64; 3] {
        self.rep
    }
}

/// Read one FSE table description from a dictionary's entropy section,
/// advancing `pos`. Maps any parse failure to [`Error::DictionaryCorrupted`],
/// since a formatted dictionary that fails here is malformed rather than a
/// truncated frame.
fn read_dict_fse(
    bytes: &[u8],
    pos: &mut usize,
    spec: &crate::block::SeqTableSpec,
) -> Result<FseTable, Error> {
    let corrupt = Error::DictionaryCorrupted;
    let nc = fse::read_ncount(
        bytes.get(*pos..).ok_or(corrupt)?,
        spec.max_symbol,
        spec.max_log,
    )
    .map_err(|_| corrupt)?;
    let table = fse::build_dtable(&nc.counts, nc.table_log).map_err(|_| corrupt)?;
    *pos += nc.bytes_consumed;
    Ok(table)
}
