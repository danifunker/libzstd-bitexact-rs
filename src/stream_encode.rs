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
//! *extDict*. All nine strategies' extDict match finders are ported, and
//! index overflow correction recycles the 32-bit index space past 3500 MiB,
//! so every level streams without any length limit — including the
//! configurations where C auto-enables long-distance matching (`strategy >=
//! btopt && windowLog >= 27`, i.e. level 22 at unknown content size), whose
//! LDM match finder ([`crate::ldm`]) is bit-exact.
//!
//! [`StreamEncoder::with_workers`] switches to the **multithreaded** streaming
//! path (`ZSTD_compressStream2` with `nbWorkers >= 1`), reproduced
//! single-threaded by buffering the input into job-sized sections
//! ([`crate::compress::MtStreamState`] / [`crate::compress_mt`]).

use crate::compress::{FrameCompressor, MtStreamState, ZSTDMT_JOBSIZE_MIN, compress_mt};
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
    /// `ZSTD_CCtx_loadDictionary`: the dictionary primes the frame via an
    /// internally-built CDict (Path B). `None` for plain streaming.
    dict: Option<Vec<u8>>,
    /// `ZSTD_c_nbWorkers` / `ZSTD_c_jobSize` / `ZSTD_c_overlapLog`: when
    /// `nb_workers >= 1` the stream uses the multithreaded job-splitting path
    /// (reproduced single-threaded via [`MtStreamState`]).
    nb_workers: u32,
    job_size: u64,
    overlap_log: i32,
    /// `None` until the first operation (`zcss_init`): parameters are
    /// resolved lazily so that a first-call `finish` can auto-pledge.
    state: Option<StreamState>,
    /// Set instead of `state` when the multithreaded streaming path is active.
    mt_state: Option<MtStreamState>,
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
            dict: None,
            nb_workers: 0,
            job_size: 0,
            overlap_log: 0,
            state: None,
            mt_state: None,
            frame_ended: false,
        }
    }

    /// A streaming encoder primed with a dictionary (`ZSTD_CCtx_loadDictionary`
    /// semantics: an internal CDict is built and **attached**, Path B). Output is
    /// byte-identical to C `ZSTD_compressStream2` after `ZSTD_CCtx_loadDictionary`
    /// (e.g. `zstd::stream::write::Encoder::with_dictionary`) for the same
    /// operations.
    ///
    /// Current scope: the unknown-content-size (attach) path — the natural
    /// streaming case. A stream whose source grows past the window (so C would
    /// drop the attached dictionary) returns a clean [`Error::Encode`]; so does a
    /// pledged size above the strategy's attach cutoff (the copy path) and a
    /// dictionary with <= 8 bytes of content. Raw and trained dictionaries are
    /// both supported.
    pub fn with_dictionary(level: i32, dict: &[u8]) -> Self {
        StreamEncoder {
            level,
            requested_pledged: None,
            checksum: false,
            dict: if dict.is_empty() {
                None
            } else {
                Some(dict.to_vec())
            },
            nb_workers: 0,
            job_size: 0,
            overlap_log: 0,
            state: None,
            mt_state: None,
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
            dict: None,
            nb_workers: 0,
            job_size: 0,
            overlap_log: 0,
            state: None,
            mt_state: None,
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

    /// `ZSTD_c_nbWorkers` (+ optional `ZSTD_c_jobSize` / `ZSTD_c_overlapLog`,
    /// `0` = C default): enable multithreaded streaming. C's MT output is
    /// deterministic and worker-count-independent, so this reproduces it
    /// **single-threaded** (see [`crate::compress_mt`]).
    ///
    /// Current scope: unknown-size streaming (the default) via
    /// [`compress`](Self::compress) + [`finish`](Self::finish). A first-call
    /// `finish` below `ZSTDMT_JOBSIZE_MIN` (512 KiB) produces the single-threaded
    /// frame, and above it the one-shot MT frame. [`flush`](Self::flush), a
    /// pledged size, a dictionary, and a checksum with workers are not supported
    /// yet (clean [`Error::Encode`]).
    ///
    /// # Panics
    /// If streaming has already started (workers apply at init time).
    pub fn with_workers(mut self, nb_workers: u32, job_size: u64, overlap_log: i32) -> Self {
        assert!(
            self.state.is_none() && self.mt_state.is_none(),
            "workers must be set before streaming starts"
        );
        self.nb_workers = nb_workers;
        self.job_size = job_size;
        self.overlap_log = overlap_log;
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
    fn init(&mut self, end_op: EndOp, in_size: usize) -> Result<(), Error> {
        // Multithreaded streaming engages for an unknown content size (the
        // normal streaming case — a first-call `finish` is handled in
        // `stream_op`). The supported scope is plain unknown-size streaming.
        if self.nb_workers > 0 && end_op != EndOp::End {
            if self.dict.is_some() || self.checksum {
                return Err(Error::Encode(
                    "multithreaded streaming with a dictionary or checksum is not supported yet",
                ));
            }
            if self.requested_pledged.is_some() {
                return Err(Error::Encode(
                    "multithreaded streaming with a pledged size is not supported yet",
                ));
            }
            self.mt_state = Some(MtStreamState::new(
                self.level,
                self.job_size,
                self.overlap_log,
            )?);
            return Ok(());
        }
        let pledged = if end_op == EndOp::End {
            // "auto-determine pledgedSrcSize" — overrides any prior pledge.
            Some(in_size as u64)
        } else {
            self.requested_pledged
        };
        // `inBuffTarget = blockSizeMax + (blockSizeMax == pledgedSrcSize)`: for a
        // pledge of exactly one block, avoid the automatic flush on reaching end
        // of block, which would cost a 3-byte empty last block.
        let one_block_pledge = |bs: usize| (pledged == Some(bs as u64)) as usize;
        self.state = Some(if let Some(dict) = &self.dict {
            // `ZSTD_CCtx_loadDictionary` → internal CDict → attach. The dict
            // content is a permanent prefix of the staging buffer; input is staged
            // (and the first chunk compressed) from `content_len`.
            let init =
                crate::compress::streaming_cdict_init(dict, self.level, pledged, self.checksum)?;
            let block_size = init.fc.block_size_max();
            let in_buff_target = init.content_len + block_size + one_block_pledge(block_size);
            StreamState {
                fc: init.fc,
                in_buff: init.in_buff,
                in_to_compress: init.content_len,
                in_buff_pos: init.content_len,
                in_buff_target,
            }
        } else {
            let fc = FrameCompressor::new(self.level, pledged, self.checksum);
            let block_size = fc.block_size_max();
            let in_buff_size = fc.window_size() + block_size;
            StreamState {
                fc,
                in_buff: vec![0u8; in_buff_size],
                in_to_compress: 0,
                in_buff_pos: 0,
                in_buff_target: block_size + one_block_pledge(block_size),
            }
        });
        Ok(())
    }

    /// Drive the multithreaded streaming path: buffer `input` into jobs
    /// ([`MtStreamState`]). `flush` is not supported yet (it would force a
    /// partial-section job, changing the decomposition).
    fn mt_drive(&mut self, input: &[u8], op: EndOp, out: &mut Vec<u8>) -> Result<(), Error> {
        match op {
            EndOp::Continue => self.mt_state.as_mut().unwrap().push(input, out),
            EndOp::End => {
                self.mt_state.as_mut().unwrap().end(input, out)?;
                self.frame_ended = true;
                Ok(())
            }
            EndOp::Flush => Err(Error::Encode(
                "multithreaded streaming flush is not supported yet",
            )),
        }
    }

    /// `ZSTD_compressStream_generic`, buffered mode. The output never blocks
    /// (we append to a `Vec`), so the `zcss_flush` stage disappears and the
    /// loop alternates load → compress until the directive is satisfied.
    fn stream_op(&mut self, mut input: &[u8], op: EndOp, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.frame_ended {
            return Err(Error::Encode("frame already finished"));
        }
        if self.state.is_none() && self.mt_state.is_none() {
            // A first-call `finish` auto-pledges the content size. With workers and
            // a size above the MT floor, C delegates to `ZSTD_compress2` — the
            // one-shot MT frame (known size), not unknown-size streaming.
            if op == EndOp::End
                && self.nb_workers > 0
                && self.dict.is_none()
                && !self.checksum
                && self.requested_pledged.is_none()
                && input.len() as u64 > ZSTDMT_JOBSIZE_MIN
            {
                out.extend_from_slice(&compress_mt(
                    input,
                    self.level,
                    self.nb_workers,
                    self.job_size,
                    self.overlap_log,
                )?);
                self.frame_ended = true;
                return Ok(());
            }
            self.init(op, input.len())?;
        }
        if self.mt_state.is_some() {
            return self.mt_drive(input, op, out);
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

            // Streaming CDict attach: stop cleanly before the source grows past
            // the window (where C's checkDictValidity/enforceMaxDist would drop
            // the attached dict — that loadedDictEnd machinery isn't ported).
            if st.fc.cdict_attach_overflow(st.in_buff_pos) {
                return Err(Error::Encode(
                    "streaming source outgrew the window with an attached dictionary \
                     (large dict streams are not supported yet)",
                ));
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
