//! Streaming compression with `ZSTD_compressStream2` semantics, aiming for
//! **byte-identical output to C libzstd 1.5.7** for the same sequence of
//! compress/flush/finish operations.
//!
//! This is a port of the buffered-mode path (`ZSTD_bm_buffered`, the
//! `ZSTD_compressStream2` default): input is staged in an internal buffer of
//! `windowSize + blockSize` bytes (`ZSTD_resetCCtx_internal`) and compressed
//! one `blockSize` chunk at a time through the shared frame machinery
//! ([`crate::compress::FrameCompressor`] = `ZSTD_compressContinue` /
//! `ZSTD_compressEnd`). The output-side staging buffer of the C code is pure
//! plumbing (bytes are identical with any output capacity), so it is not
//! reproduced.
//!
//! Parameter derivation differs from the one-shot path exactly as in C: with
//! no pledged content size, `ZSTD_getCParamsFromCCtxParams` resolves with
//! `ZSTD_CONTENTSIZE_UNKNOWN`, which selects the "default" srcSize class and
//! skips the window resize — so a stream compressed in chunks legitimately
//! differs from `ZSTD_compress` of the same bytes (windowed frame header, no
//! content size) unless the size is pledged up front or the whole input is
//! handed to the first [`StreamEncoder::finish`] call (the C auto-pledge).
//!
//! Current scope: when the staged stream outgrows the input buffer
//! (`windowSize + blockSize` bytes — 640 KiB at level 1 up to 64 MiB+ at the
//! top levels), the buffer wraps and the previous segment becomes an
//! *extDict*. All nine strategies' extDict match finders are ported, so
//! every level streams without length limits (up to the C
//! overflow-correction threshold of 3500 MiB) — except configurations where
//! C auto-enables long-distance matching (`strategy >= btopt && windowLog >=
//! 27`, i.e. level 22 at unknown content size). LDM is ported
//! ([`crate::ldm`]) but not yet bit-exact on large inputs, so those
//! configurations report a clean [`Error::Encode`] instead of diverging.

use crate::compress::FrameCompressor;
use crate::error::Error;

/// `ZSTD_EndDirective`.
#[derive(PartialEq, Eq, Clone, Copy)]
enum EndOp {
    Continue,
    Flush,
    End,
}

/// Streaming Zstandard encoder (`ZSTD_compressStream2` semantics).
///
/// Output produced by a given sequence of [`compress`](Self::compress),
/// [`flush`](Self::flush) and [`finish`](Self::finish) calls is byte-identical
/// to C libzstd 1.5.7 fed the same input chunks with the same
/// `ZSTD_e_continue` / `ZSTD_e_flush` / `ZSTD_e_end` directives.
///
/// ```
/// let mut out = Vec::new();
/// let mut enc = libzstd_bitexact::StreamEncoder::new(3);
/// enc.compress(b"hello ", &mut out).unwrap();
/// enc.compress(b"world", &mut out).unwrap();
/// enc.finish(b"", &mut out).unwrap();
/// assert_eq!(libzstd_bitexact::decompress(&out).unwrap(), b"hello world");
/// ```
pub struct StreamEncoder {
    level: i32,
    /// `ZSTD_CCtx_setPledgedSrcSize`: applies at (deferred) init time.
    requested_pledged: Option<u64>,
    checksum: bool,
    /// `None` until the first operation (`zcss_init`): parameters are
    /// resolved lazily so that a first-call `finish` can auto-pledge.
    state: Option<StreamState>,
    frame_ended: bool,
}

struct StreamState {
    fc: FrameCompressor,
    /// The C `inBuff`, `windowSize + blockSize` bytes.
    in_buff: Vec<u8>,
    /// `zcs->inToCompress` / `zcs->inBuffPos` / `zcs->inBuffTarget`.
    in_to_compress: usize,
    in_buff_pos: usize,
    in_buff_target: usize,
}

impl StreamEncoder {
    /// A streaming encoder with unknown content size (the
    /// `ZSTD_compressStream2` default).
    pub fn new(level: i32) -> Self {
        StreamEncoder {
            level,
            requested_pledged: None,
            checksum: false,
            state: None,
            frame_ended: false,
        }
    }

    /// `ZSTD_CCtx_setPledgedSrcSize`: declare the total content size up
    /// front. Compression parameters are then derived from it exactly as in
    /// the one-shot path, the frame header carries the content size, and the
    /// stream errors if the fed input does not match the pledge. Note that C
    /// overrides the pledge when the *first* operation is `finish` (the input
    /// of that call becomes the pledge); this port is faithful to that.
    pub fn with_pledged_src_size(level: i32, size: u64) -> Self {
        StreamEncoder {
            level,
            requested_pledged: Some(size),
            checksum: false,
            state: None,
            frame_ended: false,
        }
    }

    /// Enable the content checksum (`ZSTD_c_checksumFlag`): XXH64 of the
    /// content, low 32 bits appended to the frame.
    ///
    /// # Panics
    /// If streaming has already started (the flag applies at init time).
    pub fn with_checksum(mut self, on: bool) -> Self {
        assert!(
            self.state.is_none(),
            "checksum flag must be set before streaming starts"
        );
        self.checksum = on;
        self
    }

    /// `ZSTD_compressStream2(.., ZSTD_e_continue)`: consume `input`, appending
    /// any output produced to `out`. Input is buffered internally; output is
    /// only produced once full blocks are available.
    pub fn compress(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        self.stream_op(input, EndOp::Continue, out)
    }

    /// `ZSTD_compressStream2(.., ZSTD_e_flush)`: compress whatever is
    /// buffered and emit it, ending the current block. The frame stays open.
    pub fn flush(&mut self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.stream_op(&[], EndOp::Flush, out)
    }

    /// `ZSTD_compressStream2(.., ZSTD_e_end)`: consume `input` (pass `b""`
    /// for none), then end the frame — last block, optional checksum.
    ///
    /// When this is the *first* operation on the encoder, C auto-pledges the
    /// content size from this call's input, making the result byte-identical
    /// to the one-shot `ZSTD_compress2`; this port does the same.
    pub fn finish(mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        self.stream_op(input, EndOp::End, out)
    }

    /// `ZSTD_CCtx_init_compressStream2` + `ZSTD_compressBegin_internal`
    /// (buffered): resolve parameters (auto-pledging if the first operation
    /// is `ZSTD_e_end`) and size the input staging buffer.
    fn init(&mut self, end_op: EndOp, in_size: usize) {
        let pledged = if end_op == EndOp::End {
            // "auto-determine pledgedSrcSize" — overrides any prior pledge.
            Some(in_size as u64)
        } else {
            self.requested_pledged
        };
        let fc = FrameCompressor::new(self.level, pledged, self.checksum);
        let block_size = fc.block_size_max();
        let in_buff_size = fc.window_size() + block_size;
        // `inBuffTarget = blockSizeMax + (blockSizeMax == pledgedSrcSize)`:
        // for a pledge of exactly one block, avoid the automatic flush on
        // reaching end of block, which would cost a 3-byte empty last block.
        let in_buff_target = block_size + (pledged == Some(block_size as u64)) as usize;
        self.state = Some(StreamState {
            fc,
            in_buff: vec![0u8; in_buff_size],
            in_to_compress: 0,
            in_buff_pos: 0,
            in_buff_target,
        });
    }

    /// `ZSTD_compressStream_generic`, buffered mode. The output never blocks
    /// (we append to a `Vec`), so the `zcss_flush` stage disappears and the
    /// loop alternates load → compress until the directive is satisfied.
    fn stream_op(&mut self, mut input: &[u8], op: EndOp, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.frame_ended {
            return Err(Error::Encode("frame already finished"));
        }
        if self.state.is_none() {
            self.init(op, input.len());
        }
        let st = self.state.as_mut().expect("initialized above");
        let block_size = st.fc.block_size_max();

        loop {
            // zcss_load: complete loading into the input buffer.
            let to_load = st.in_buff_target - st.in_buff_pos;
            let loaded = to_load.min(input.len());
            st.in_buff[st.in_buff_pos..st.in_buff_pos + loaded].copy_from_slice(&input[..loaded]);
            st.in_buff_pos += loaded;
            input = &input[loaded..];
            if op == EndOp::Continue && st.in_buff_pos < st.in_buff_target {
                // Not enough input to fill a full block: stop here.
                break;
            }
            if op == EndOp::Flush && st.in_buff_pos == st.in_to_compress {
                // Nothing pending.
                break;
            }

            // Compress the staged chunk.
            let last_block = op == EndOp::End && input.is_empty();
            if last_block {
                st.fc
                    .compress_end(out, &st.in_buff, st.in_to_compress, st.in_buff_pos)?;
                self.frame_ended = true;
            } else {
                st.fc.compress_continue(
                    out,
                    &st.in_buff,
                    st.in_to_compress,
                    st.in_buff_pos,
                    false,
                )?;
            }

            // Prepare the next block; past the buffer end, wrap to the start.
            // The wrapped chunk is non-contiguous, turning the live window
            // into the extDict.
            st.in_buff_target = st.in_buff_pos + block_size;
            if st.in_buff_target > st.in_buff.len() {
                st.in_buff_pos = 0;
                st.in_buff_target = block_size;
            }
            st.in_to_compress = st.in_buff_pos;
            if self.frame_ended {
                break;
            }
        }
        Ok(())
    }
}
