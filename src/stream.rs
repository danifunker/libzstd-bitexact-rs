//! Streaming decompression (`ZSTD_decompressStream` semantics).
//!
//! [`StreamDecoder`] wraps any [`Read`] source of compressed data and itself
//! implements [`Read`], producing the decompressed bytes. Unlike the one-shot
//! [`decompress`](crate::decompress), it does not hold the whole compressed
//! input or the whole output in memory: it buffers just enough compressed
//! bytes to decode the next block, and keeps a **sliding window** of recent
//! output (at most the frame's `windowSize`, plus the block in flight) so that
//! matches can reach back while older output is evicted as soon as it passes
//! out of window range. Memory use is therefore bounded by the frame's window,
//! not its content.
//!
//! The decode itself reuses the same block decoder as the one-shot path
//! ([`crate::block::decode_compressed_block`]); the only difference is the
//! windowed output buffer. A dictionary's content is seeded into that window
//! as initial history (so dictionary-relative matches are ordinary in-window
//! copies), and its entropy tables seed the first block's context exactly as
//! in the one-shot path.

use std::io::{self, Read};

use crate::block::{self, BLOCK_SIZE_MAX, FrameContext};
use crate::decompress::{DecodeOptions, SKIPPABLE_MAGIC, SKIPPABLE_MAGIC_MASK, ZSTD_MAGIC};
use crate::error::Error;
use crate::frame;
use crate::xxhash::Xxh64;

/// The most bytes a frame header can occupy after the magic number
/// (descriptor + window descriptor + 4-byte dict ID + 8-byte content size).
const MAX_FRAME_HEADER: usize = 14;

/// Map a decoder error into the `io::Error` that [`Read`] must report.
fn invalid(e: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// Per-frame decoding state, live while inside a frame.
struct FrameState {
    ctx: FrameContext,
    /// Sliding window: recent output plus any seeded dictionary history.
    win: Vec<u8>,
    /// Window size in bytes; the window is trimmed to its last `window` bytes
    /// after each block.
    window: usize,
    block_size_max: usize,
    has_checksum: bool,
    content_size: Option<u64>,
    xxh: Xxh64,
    /// Frame output produced so far (excludes any seeded dictionary prefix).
    produced: u64,
}

enum Phase {
    /// Between frames: expecting a frame or skippable magic, or clean EOF.
    FrameStart,
    /// Inside a skippable frame, with this many payload bytes left to drop.
    Skippable(usize),
    /// Decoding the block sequence of the current frame.
    Blocks,
    /// Block sequence finished; expecting the optional checksum.
    Footer,
    /// The whole input has been consumed.
    Done,
}

/// A streaming Zstandard decompressor over a [`Read`] source.
///
/// ```no_run
/// use std::io::Read;
/// use libzstd_bitexact_rs::StreamDecoder;
///
/// # fn main() -> std::io::Result<()> {
/// let file = std::fs::File::open("data.zst")?;
/// let mut decoder = StreamDecoder::new(file);
/// let mut out = Vec::new();
/// decoder.read_to_end(&mut out)?;
/// # Ok(())
/// # }
/// ```
pub struct StreamDecoder<'d, R: Read> {
    reader: R,
    options: DecodeOptions<'d>,

    /// Compressed input buffered from `reader`; `in_pos` marks how much has
    /// been consumed.
    in_buf: Vec<u8>,
    in_pos: usize,
    eof: bool,

    phase: Phase,
    frame: Option<FrameState>,

    /// The most recently decoded block's output, drained to callers across
    /// `read` calls; `out_pos` marks how much has been handed out.
    out_ready: Vec<u8>,
    out_pos: usize,

    /// Total output produced across all frames, for the output-size limit.
    total: u64,
}

impl<R: Read> StreamDecoder<'static, R> {
    /// Wrap `reader` with default options (no output limit, window log up to
    /// the format maximum, no dictionary).
    pub fn new(reader: R) -> Self {
        Self::with_options(reader, DecodeOptions::new())
    }
}

impl<'d, R: Read> StreamDecoder<'d, R> {
    /// Wrap `reader`, taking the output limit, maximum window log, and optional
    /// dictionary from `options`.
    pub fn with_options(reader: R, options: DecodeOptions<'d>) -> Self {
        StreamDecoder {
            reader,
            options,
            in_buf: Vec::new(),
            in_pos: 0,
            eof: false,
            phase: Phase::FrameStart,
            frame: None,
            out_ready: Vec::new(),
            out_pos: 0,
            total: 0,
        }
    }

    /// Drop already-consumed input so the buffer does not grow without bound.
    fn compact(&mut self) {
        if self.in_pos > 0 {
            self.in_buf.drain(..self.in_pos);
            self.in_pos = 0;
        }
    }

    fn avail(&self) -> usize {
        self.in_buf.len() - self.in_pos
    }

    /// Pull from `reader` until at least `n` bytes are buffered, or EOF.
    /// Returns whether `n` bytes are now available.
    fn fill(&mut self, n: usize) -> io::Result<bool> {
        let mut tmp = [0u8; 1 << 16];
        while self.avail() < n && !self.eof {
            let got = self.reader.read(&mut tmp)?;
            if got == 0 {
                self.eof = true;
                break;
            }
            self.in_buf.extend_from_slice(&tmp[..got]);
        }
        Ok(self.avail() >= n)
    }

    /// Produce the next block's output into `out_ready`. Returns `Ok(false)`
    /// only at a clean end of input; otherwise `Ok(true)` once `out_ready` has
    /// fresh bytes (it may loop over empty blocks, footers, and frame headers
    /// first).
    fn decode_more(&mut self) -> io::Result<bool> {
        loop {
            self.compact();
            match self.phase {
                Phase::Done => return Ok(false),
                Phase::FrameStart => {
                    if !self.fill(4)? {
                        // EOF: clean only if no partial frame is buffered.
                        if self.avail() == 0 {
                            self.phase = Phase::Done;
                            return Ok(false);
                        }
                        return Err(invalid(Error::SrcSizeWrong));
                    }
                    let magic = u32::from_le_bytes(
                        self.in_buf[self.in_pos..self.in_pos + 4]
                            .try_into()
                            .unwrap(),
                    );
                    if magic == ZSTD_MAGIC {
                        self.in_pos += 4;
                        self.start_frame()?;
                    } else if magic & SKIPPABLE_MAGIC_MASK == SKIPPABLE_MAGIC {
                        if !self.fill(8)? {
                            return Err(invalid(Error::SrcSizeWrong));
                        }
                        let size = u32::from_le_bytes(
                            self.in_buf[self.in_pos + 4..self.in_pos + 8]
                                .try_into()
                                .unwrap(),
                        ) as usize;
                        self.in_pos += 8;
                        self.phase = Phase::Skippable(size);
                    } else {
                        return Err(invalid(Error::UnknownMagic(magic)));
                    }
                }
                Phase::Skippable(0) => self.phase = Phase::FrameStart,
                Phase::Skippable(left) => {
                    if self.avail() == 0 && !self.fill(1)? {
                        return Err(invalid(Error::SrcSizeWrong));
                    }
                    let take = left.min(self.avail());
                    self.in_pos += take;
                    self.phase = Phase::Skippable(left - take);
                }
                Phase::Blocks => {
                    if self.decode_block()? {
                        return Ok(true);
                    }
                }
                Phase::Footer => self.finish_frame()?,
            }
        }
    }

    /// Parse the current frame's header and set up its window and context.
    fn start_frame(&mut self) -> io::Result<()> {
        let _ = self.fill(MAX_FRAME_HEADER)?; // best effort; headers are short
        let header = match frame::parse(
            &self.in_buf[self.in_pos..],
            self.options.window_log_max_value(),
        ) {
            Ok(h) => h,
            // Having filled all we could, a still-short header is truncation.
            Err(Error::SrcSizeWrong) => return Err(invalid(Error::SrcSizeWrong)),
            Err(e) => return Err(invalid(e)),
        };

        // Resolve the dictionary against the frame's declared ID, exactly as
        // the one-shot path does.
        let dict = match (self.options.dictionary_value(), header.dict_id) {
            (_, 0) => self.options.dictionary_value(),
            (Some(d), id) if d.id() == id => Some(d),
            (Some(d), id) => {
                return Err(invalid(Error::DictionaryWrong {
                    expected: id,
                    actual: d.id(),
                }));
            }
            (None, id) => return Err(invalid(Error::DictionaryRequired(id))),
        };

        self.in_pos += header.header_len;

        let mut win = Vec::new();
        if let Some(d) = dict {
            win.extend_from_slice(d.content());
        }
        let window = header.window_size.min(usize::MAX as u64) as usize;
        self.frame = Some(FrameState {
            ctx: FrameContext::with_dictionary(dict),
            win,
            window,
            block_size_max: header.window_size.min(BLOCK_SIZE_MAX as u64) as usize,
            has_checksum: header.has_checksum,
            content_size: header.content_size,
            xxh: Xxh64::new(0),
            produced: 0,
        });
        self.phase = Phase::Blocks;
        Ok(())
    }

    /// Decode one block into the window. Returns whether it produced output;
    /// sets the phase to `Footer` after the last block.
    fn decode_block(&mut self) -> io::Result<bool> {
        if !self.fill(3)? {
            return Err(invalid(Error::SrcSizeWrong));
        }
        let p = self.in_pos;
        let raw = u32::from(self.in_buf[p])
            | u32::from(self.in_buf[p + 1]) << 8
            | u32::from(self.in_buf[p + 2]) << 16;
        let last = raw & 1 != 0;
        let block_type = (raw >> 1) & 3;
        let size = (raw >> 3) as usize;
        self.in_pos += 3;

        let body_needed = match block_type {
            1 => 1,        // RLE: a single byte
            0 | 2 => size, // Raw / Compressed: the whole block
            _ => return Err(invalid(Error::BlockTypeInvalid)),
        };
        if !self.fill(body_needed)? {
            return Err(invalid(Error::SrcSizeWrong));
        }

        let block_size_max = self.frame.as_ref().unwrap().block_size_max;
        if size > block_size_max {
            return Err(invalid(Error::Corrupted(
                "block size exceeds block size limit",
            )));
        }

        let body_start = self.in_pos;
        let fr = self.frame.as_mut().unwrap();
        let before = fr.win.len();
        match block_type {
            // Raw_Block.
            0 => {
                fr.win
                    .extend_from_slice(&self.in_buf[body_start..body_start + size]);
                self.in_pos += size;
            }
            // RLE_Block.
            1 => {
                let byte = self.in_buf[body_start];
                fr.win.resize(fr.win.len() + size, byte);
                self.in_pos += 1;
            }
            // Compressed_Block: the window is the output buffer, with all prior
            // history (including any dictionary prefix) already in it, so the
            // block decoder needs no separate dictionary slice.
            _ => {
                let body = &self.in_buf[body_start..body_start + size];
                block::decode_compressed_block(
                    &mut fr.ctx,
                    body,
                    &mut fr.win,
                    0,
                    &[],
                    block_size_max,
                    usize::MAX,
                )
                .map_err(invalid)?;
                self.in_pos += size;
            }
        }

        // Hand the freshly decoded bytes to the output queue and feed them to
        // the running checksum before any of them can be evicted.
        let new = &fr.win[before..];
        self.total += new.len() as u64;
        if self.total > self.options.limit_value() as u64 {
            return Err(invalid(Error::OutputTooLarge));
        }
        self.out_ready.extend_from_slice(new);
        fr.xxh.update(new);
        fr.produced += new.len() as u64;

        // Trim the window back to its last `window` bytes; everything older is
        // now out of match range.
        if fr.win.len() > fr.window {
            let drop = fr.win.len() - fr.window;
            fr.win.drain(..drop);
        }

        if last {
            self.phase = Phase::Footer;
        }
        Ok(!self.out_ready.is_empty())
    }

    /// Verify the frame's content size and checksum, then arm the next frame.
    fn finish_frame(&mut self) -> io::Result<()> {
        let fr = self.frame.take().expect("frame state present in Footer");

        if let Some(fcs) = fr.content_size {
            if fr.produced != fcs {
                return Err(invalid(Error::FrameContentSizeMismatch));
            }
        }

        if fr.has_checksum {
            if !self.fill(4)? {
                return Err(invalid(Error::SrcSizeWrong));
            }
            let stored = u32::from_le_bytes(
                self.in_buf[self.in_pos..self.in_pos + 4]
                    .try_into()
                    .unwrap(),
            );
            self.in_pos += 4;
            let actual = fr.xxh.digest() as u32;
            if stored != actual {
                return Err(invalid(Error::ChecksumMismatch {
                    expected: stored,
                    actual,
                }));
            }
        }

        self.phase = Phase::FrameStart;
        Ok(())
    }
}

impl<R: Read> Read for StreamDecoder<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.out_pos < self.out_ready.len() {
                let n = (self.out_ready.len() - self.out_pos).min(buf.len());
                buf[..n].copy_from_slice(&self.out_ready[self.out_pos..self.out_pos + n]);
                self.out_pos += n;
                return Ok(n);
            }
            self.out_ready.clear();
            self.out_pos = 0;
            if !self.decode_more()? {
                return Ok(0);
            }
        }
    }
}
