//! Top-level decompression: frame iteration and the block loop
//! (`ZSTD_decompressMultiFrame` / `ZSTD_decompressFrame`).

use crate::block::{self, BLOCK_SIZE_MAX, FrameContext};
use crate::dictionary::Dictionary;
use crate::error::Error;
use crate::frame;
use crate::xxhash::xxh64;

pub(crate) const ZSTD_MAGIC: u32 = 0xFD2F_B528;
pub(crate) const SKIPPABLE_MAGIC_MASK: u32 = 0xFFFF_FFF0;
pub(crate) const SKIPPABLE_MAGIC: u32 = 0x184D_2A50;

/// Cap on speculative preallocation from the declared content size, so a
/// frame header lying about its size cannot trigger a huge allocation.
const MAX_PREALLOC: u64 = 32 << 20;

/// `ZSTD_WINDOWLOG_MAX` on 64-bit targets: the largest window log the format
/// permits, and the default ceiling [`DecodeOptions`] enforces. It is also the
/// hard cap — raising [`DecodeOptions::window_log_max`] above it has no effect,
/// since larger windows are invalid regardless.
pub const WINDOW_LOG_MAX: u32 = 31;

/// Configurable decompression: an output-size limit, a maximum accepted window
/// log, and an optional dictionary.
///
/// ```
/// use libzstd_bitexact::DecodeOptions;
/// let frame = [0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x05, 0x2B, 0x00, 0x00, b'a'];
/// let out = DecodeOptions::new().limit(1 << 20).decompress(&frame).unwrap();
/// assert_eq!(out, b"aaaaa");
/// ```
#[derive(Clone)]
pub struct DecodeOptions<'d> {
    limit: usize,
    window_log_max: u32,
    dictionary: Option<&'d Dictionary>,
}

impl Default for DecodeOptions<'_> {
    fn default() -> Self {
        DecodeOptions {
            limit: usize::MAX,
            window_log_max: WINDOW_LOG_MAX,
            dictionary: None,
        }
    }
}

impl<'d> DecodeOptions<'d> {
    /// Default options: no output limit, window log up to [`WINDOW_LOG_MAX`],
    /// no dictionary.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fail with [`Error::OutputTooLarge`] once the output would exceed
    /// `limit` bytes. Use this on untrusted input to defuse decompression
    /// bombs.
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// Reject frames whose declared window log exceeds `window_log_max`
    /// (`ZSTD_d_windowLogMax`). Values above [`WINDOW_LOG_MAX`] are treated as
    /// [`WINDOW_LOG_MAX`].
    pub fn window_log_max(mut self, window_log_max: u32) -> Self {
        self.window_log_max = window_log_max;
        self
    }

    /// Decode using `dictionary` as window history and entropy-table seed
    /// (`ZSTD_decompress_usingDict`). The dictionary applies to every frame in
    /// the input.
    pub fn dictionary(mut self, dictionary: &'d Dictionary) -> Self {
        self.dictionary = Some(dictionary);
        self
    }

    pub(crate) fn limit_value(&self) -> usize {
        self.limit
    }

    pub(crate) fn window_log_max_value(&self) -> u32 {
        self.window_log_max
    }

    pub(crate) fn dictionary_value(&self) -> Option<&'d Dictionary> {
        self.dictionary
    }

    /// Decompress a sequence of frames with these options.
    pub fn decompress(&self, src: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        let mut input = src;
        while !input.is_empty() {
            if input.len() < 4 {
                return Err(Error::SrcSizeWrong);
            }
            let magic = u32::from_le_bytes(input[..4].try_into().unwrap());
            if magic == ZSTD_MAGIC {
                input = self.decode_frame(&input[4..], &mut out)?;
            } else if magic & SKIPPABLE_MAGIC_MASK == SKIPPABLE_MAGIC {
                if input.len() < 8 {
                    return Err(Error::SrcSizeWrong);
                }
                let size = u32::from_le_bytes(input[4..8].try_into().unwrap()) as usize;
                input = input.get(8 + size..).ok_or(Error::SrcSizeWrong)?;
            } else {
                return Err(Error::UnknownMagic(magic));
            }
        }
        Ok(out)
    }

    /// Decode one frame (after its magic) into `out`; returns the rest of the
    /// input following the frame.
    fn decode_frame<'a>(&self, src: &'a [u8], out: &mut Vec<u8>) -> Result<&'a [u8], Error> {
        let header = frame::parse(src, self.window_log_max)?;

        // Resolve the dictionary against the frame's declared ID. A frame ID
        // of zero accepts whatever dictionary the caller supplied (raw-content
        // dictionaries always carry ID zero); a non-zero ID must match.
        let dict = match (self.dictionary, header.dict_id) {
            (_, 0) => self.dictionary,
            (Some(d), id) if d.id() == id => Some(d),
            (Some(d), id) => {
                return Err(Error::DictionaryWrong {
                    expected: id,
                    actual: d.id(),
                });
            }
            (None, id) => return Err(Error::DictionaryRequired(id)),
        };
        let dict_content = dict.map_or(&[][..], Dictionary::content);

        let frame_base = out.len();
        if let Some(fcs) = header.content_size {
            if fcs as u128 + frame_base as u128 > self.limit as u128 {
                return Err(Error::OutputTooLarge);
            }
            out.reserve(fcs.min(MAX_PREALLOC) as usize);
        }
        let block_size_max = header.window_size.min(BLOCK_SIZE_MAX as u64) as usize;

        let mut ctx = FrameContext::with_dictionary(dict);
        let mut input = &src[header.header_len..];
        loop {
            let bh = input.get(..3).ok_or(Error::SrcSizeWrong)?;
            let raw = u32::from(bh[0]) | u32::from(bh[1]) << 8 | u32::from(bh[2]) << 16;
            input = &input[3..];
            let last = raw & 1 != 0;
            let block_type = (raw >> 1) & 3;
            let size = (raw >> 3) as usize;

            match block_type {
                // Raw_Block: `size` bytes copied verbatim.
                0 => {
                    if size > block_size_max {
                        return Err(Error::Corrupted("block size exceeds block size limit"));
                    }
                    let data = input.get(..size).ok_or(Error::SrcSizeWrong)?;
                    if out.len() + size > self.limit {
                        return Err(Error::OutputTooLarge);
                    }
                    out.extend_from_slice(data);
                    input = &input[size..];
                }
                // RLE_Block: one byte, repeated `size` times.
                1 => {
                    if size > block_size_max {
                        return Err(Error::Corrupted("block size exceeds block size limit"));
                    }
                    let byte = *input.first().ok_or(Error::SrcSizeWrong)?;
                    if out.len() + size > self.limit {
                        return Err(Error::OutputTooLarge);
                    }
                    out.resize(out.len() + size, byte);
                    input = &input[1..];
                }
                // Compressed_Block.
                2 => {
                    if size > block_size_max {
                        return Err(Error::Corrupted("block size exceeds block size limit"));
                    }
                    let data = input.get(..size).ok_or(Error::SrcSizeWrong)?;
                    block::decode_compressed_block(
                        &mut ctx,
                        data,
                        out,
                        frame_base,
                        dict_content,
                        block_size_max,
                        self.limit,
                    )?;
                    input = &input[size..];
                }
                _ => return Err(Error::BlockTypeInvalid),
            }

            if last {
                break;
            }
        }

        if let Some(fcs) = header.content_size {
            if (out.len() - frame_base) as u64 != fcs {
                return Err(Error::FrameContentSizeMismatch);
            }
        }

        if header.has_checksum {
            let stored = input.get(..4).ok_or(Error::SrcSizeWrong)?;
            let expected = u32::from_le_bytes(stored.try_into().unwrap());
            let actual = xxh64(&out[frame_base..], 0) as u32;
            if expected != actual {
                return Err(Error::ChecksumMismatch { expected, actual });
            }
            input = &input[4..];
        }

        Ok(input)
    }
}

/// Decompress a sequence of Zstandard frames (and/or skippable frames).
///
/// This is the equivalent of `ZSTD_decompress`: all frames in `src` are
/// decoded back to back and their contents concatenated. Trailing bytes that
/// do not form a complete frame are an error. Empty input yields empty
/// output.
pub fn decompress(src: &[u8]) -> Result<Vec<u8>, Error> {
    DecodeOptions::new().decompress(src)
}

/// Like [`decompress`], but fails with [`Error::OutputTooLarge`] once the
/// output would exceed `limit` bytes. Use this on untrusted input to defuse
/// decompression bombs.
pub fn decompress_with_limit(src: &[u8], limit: usize) -> Result<Vec<u8>, Error> {
    DecodeOptions::new().limit(limit).decompress(src)
}
