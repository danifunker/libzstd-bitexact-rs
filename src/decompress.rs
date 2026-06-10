//! Top-level decompression: frame iteration and the block loop
//! (`ZSTD_decompressMultiFrame` / `ZSTD_decompressFrame`).

use crate::block::{self, BLOCK_SIZE_MAX, FrameContext};
use crate::error::Error;
use crate::frame;
use crate::xxhash::xxh64;

const ZSTD_MAGIC: u32 = 0xFD2F_B528;
const SKIPPABLE_MAGIC_MASK: u32 = 0xFFFF_FFF0;
const SKIPPABLE_MAGIC: u32 = 0x184D_2A50;

/// Cap on speculative preallocation from the declared content size, so a
/// frame header lying about its size cannot trigger a huge allocation.
const MAX_PREALLOC: u64 = 32 << 20;

/// Decompress a sequence of Zstandard frames (and/or skippable frames).
///
/// This is the equivalent of `ZSTD_decompress`: all frames in `src` are
/// decoded back to back and their contents concatenated. Trailing bytes that
/// do not form a complete frame are an error. Empty input yields empty
/// output.
pub fn decompress(src: &[u8]) -> Result<Vec<u8>, Error> {
    decompress_with_limit(src, usize::MAX)
}

/// Like [`decompress`], but fails with [`Error::OutputTooLarge`] once the
/// output would exceed `limit` bytes. Use this on untrusted input to defuse
/// decompression bombs.
pub fn decompress_with_limit(src: &[u8], limit: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut input = src;
    while !input.is_empty() {
        if input.len() < 4 {
            return Err(Error::SrcSizeWrong);
        }
        let magic = u32::from_le_bytes(input[..4].try_into().unwrap());
        if magic == ZSTD_MAGIC {
            input = decode_frame(&input[4..], &mut out, limit)?;
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
fn decode_frame<'a>(src: &'a [u8], out: &mut Vec<u8>, limit: usize) -> Result<&'a [u8], Error> {
    let header = frame::parse(src)?;
    if header.dict_id != 0 {
        return Err(Error::DictionaryRequired(header.dict_id));
    }
    let frame_base = out.len();
    if let Some(fcs) = header.content_size {
        if fcs as u128 + frame_base as u128 > limit as u128 {
            return Err(Error::OutputTooLarge);
        }
        out.reserve(fcs.min(MAX_PREALLOC) as usize);
    }
    let block_size_max = header.window_size.min(BLOCK_SIZE_MAX as u64) as usize;

    let mut ctx = FrameContext::new();
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
                if out.len() + size > limit {
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
                if out.len() + size > limit {
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
                    block_size_max,
                    limit,
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
