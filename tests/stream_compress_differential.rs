//! Streaming-compression bit-exactness: our `StreamEncoder` must produce
//! **byte-identical output** to C libzstd 1.5.7's `ZSTD_compressStream2` for
//! the same sequence of continue/flush/end operations — including the
//! unknown-content-size frame headers, the buffered block scheduling, the
//! auto-pledge on a first-call end, and the pledged-size quirks.
//!
//! Scope note: streams larger than `windowSize + blockSize` wrap the C input
//! buffer and flip the window into extDict mode; until the extDict match
//! finders are ported, our encoder reports a clean error there (covered by
//! `oversized_stream_errors_cleanly_instead_of_diverging`).

use libzstd_bitexact::StreamEncoder;
use zstd::zstd_safe::{CCtx, CParameter, InBuffer, OutBuffer};

/// xorshift64* — deterministic test data generator.
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(len + 8);
        while v.len() < len {
            v.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        v.truncate(len);
        v
    }
}

fn word_salad(seed: u64, len: usize) -> Vec<u8> {
    const WORDS: &[&[u8]] = &[
        b"the",
        b"quick",
        b"brown",
        b"fox",
        b"jumps",
        b"over",
        b"lazy",
        b"dog",
        b"zstandard",
        b"compression",
        b"entropy",
        b"sequence",
    ];
    let mut rng = Rng::new(seed);
    let mut data = Vec::with_capacity(len + 16);
    while data.len() < len {
        data.extend_from_slice(WORDS[rng.below(WORDS.len())]);
        data.push(b' ');
    }
    data.truncate(len);
    data
}

fn mixed_runs(seed: u64, len: usize) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut data = Vec::new();
    while data.len() < len {
        if rng.below(2) == 0 {
            let b = (rng.next_u64() & 0xFF) as u8;
            data.extend(std::iter::repeat_n(b, 1 + rng.below(400)));
        } else {
            let n = 1 + rng.below(60);
            let r = rng.bytes(n);
            data.extend_from_slice(&r);
        }
    }
    data.truncate(len);
    data
}

/// One step of a streaming schedule; every schedule implicitly ends with
/// `ZSTD_e_end` carrying `finish_input`.
#[derive(Clone, Copy)]
enum Step<'a> {
    Push(&'a [u8]),
    Flush,
}

/// Drive the real C `ZSTD_compressStream2` through the same schedule.
fn oracle_stream(
    level: i32,
    pledged: Option<u64>,
    checksum: bool,
    steps: &[Step],
    finish_input: &[u8],
) -> std::io::Result<Vec<u8>> {
    use zstd_sys::ZSTD_EndDirective as Dir;
    let mut cctx = CCtx::create();
    cctx.set_parameter(CParameter::CompressionLevel(level))
        .map_err(map_code)?;
    if checksum {
        cctx.set_parameter(CParameter::ChecksumFlag(true))
            .map_err(map_code)?;
    }
    if pledged.is_some() {
        cctx.set_pledged_src_size(pledged).map_err(map_code)?;
    }

    let mut out = Vec::new();
    let mut scratch = vec![0u8; 512 * 1024];
    let mut step_once = |cctx: &mut CCtx,
                         out: &mut Vec<u8>,
                         input: &mut InBuffer,
                         dir: Dir|
     -> std::io::Result<usize> {
        let mut outb = OutBuffer::around(&mut scratch[..]);
        let hint = cctx
            .compress_stream2(&mut outb, input, dir)
            .map_err(map_code)?;
        let produced = outb.pos();
        out.extend_from_slice(&scratch[..produced]);
        Ok(hint)
    };

    for step in steps {
        match step {
            Step::Push(data) => {
                // Call at least once even for empty input: a real
                // `ZSTD_compressStream2(.., ZSTD_e_continue)` call initializes
                // the stream (fixing the content size as unknown) regardless
                // of input size, and ours does the same.
                let mut inb = InBuffer::around(data);
                loop {
                    step_once(&mut cctx, &mut out, &mut inb, Dir::ZSTD_e_continue)?;
                    if inb.pos >= data.len() {
                        break;
                    }
                }
            }
            Step::Flush => {
                let mut inb = InBuffer::around(&[]);
                loop {
                    if step_once(&mut cctx, &mut out, &mut inb, Dir::ZSTD_e_flush)? == 0 {
                        break;
                    }
                }
            }
        }
    }
    let mut inb = InBuffer::around(finish_input);
    loop {
        let hint = step_once(&mut cctx, &mut out, &mut inb, Dir::ZSTD_e_end)?;
        if hint == 0 && inb.pos == finish_input.len() {
            break;
        }
    }
    Ok(out)
}

fn map_code(code: usize) -> std::io::Error {
    std::io::Error::other(zstd::zstd_safe::get_error_name(code))
}

/// Drive our `StreamEncoder` through the same schedule.
fn our_stream(
    level: i32,
    pledged: Option<u64>,
    checksum: bool,
    steps: &[Step],
    finish_input: &[u8],
) -> Result<Vec<u8>, libzstd_bitexact::Error> {
    let mut enc = match pledged {
        Some(n) => StreamEncoder::with_pledged_src_size(level, n),
        None => StreamEncoder::new(level),
    }
    .with_checksum(checksum);
    let mut out = Vec::new();
    for step in steps {
        match step {
            Step::Push(data) => enc.compress(data, &mut out)?,
            Step::Flush => enc.flush(&mut out)?,
        }
    }
    enc.finish(finish_input, &mut out)?;
    Ok(out)
}

/// Assert byte-identical streams, and that the frame decodes back to the
/// full input through our own (independently C-verified) decoder.
fn assert_stream_bit_exact(
    level: i32,
    pledged: Option<u64>,
    checksum: bool,
    steps: &[Step],
    finish_input: &[u8],
    label: &str,
) {
    let theirs = oracle_stream(level, pledged, checksum, steps, finish_input)
        .unwrap_or_else(|e| panic!("oracle failed on {label} at level {level}: {e}"));
    let ours = our_stream(level, pledged, checksum, steps, finish_input)
        .unwrap_or_else(|e| panic!("we failed on {label} at level {level}: {e}"));
    if ours != theirs {
        let at = ours
            .iter()
            .zip(theirs.iter())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| ours.len().min(theirs.len()));
        panic!(
            "{label} level {level}: NOT bit-exact — ours {} bytes, C {} bytes, first divergence at {at} \
             (ours[{at}..]={:02X?}, theirs[{at}..]={:02X?})",
            ours.len(),
            theirs.len(),
            &ours[at..(at + 8).min(ours.len())],
            &theirs[at..(at + 8).min(theirs.len())],
        );
    }
    let mut full = Vec::new();
    for step in steps {
        if let Step::Push(d) = step {
            full.extend_from_slice(d);
        }
    }
    full.extend_from_slice(finish_input);
    let back = libzstd_bitexact::decompress(&ours).expect("our frame must decode");
    assert_eq!(back, full, "{label}: round-trip mismatch");
}

/// Split `data` into `Push` steps of `chunk` bytes.
fn chunked(data: &[u8], chunk: usize) -> Vec<Step<'_>> {
    data.chunks(chunk.max(1)).map(Step::Push).collect()
}

// --- Empty frames -------------------------------------------------------------

#[test]
fn empty_streams_are_bit_exact() {
    for level in [1, 3, 6, 13, 19, -1] {
        // First call is `end`: auto-pledge of 0 — single-segment empty frame,
        // identical to the one-shot.
        assert_stream_bit_exact(level, None, false, &[], b"", "finish-only-empty");
        let one_shot = libzstd_bitexact::compress(b"", level).unwrap();
        assert_eq!(
            our_stream(level, None, false, &[], b"").unwrap(),
            one_shot,
            "finish-only empty must equal the one-shot frame"
        );

        // A prior (no-op) flush forces init with unknown content size: the
        // empty frame becomes a windowed one. Quirky but C-faithful.
        assert_stream_bit_exact(
            level,
            None,
            false,
            &[Step::Flush],
            b"",
            "flush-then-finish-empty",
        );
        assert_ne!(
            our_stream(level, None, false, &[Step::Flush], b"").unwrap(),
            one_shot,
            "unknown-size empty frame is windowed, not single-segment"
        );

        // Empty pushes are no-ops.
        assert_stream_bit_exact(
            level,
            None,
            false,
            &[Step::Push(b""), Step::Push(b""), Step::Push(b"")],
            b"",
            "empty-pushes",
        );
    }
}

// --- First-call end == one-shot (the C auto-pledge shortcut) -------------------

#[test]
fn first_call_finish_equals_one_shot() {
    for &len in &[1usize, 7, 1000, 100_000, 300_000] {
        let data = word_salad(0x57E0 ^ len as u64, len);
        for level in [1, 3, 9, 13, 19, 22] {
            assert_stream_bit_exact(level, None, false, &[], &data, "first-call-finish");
            let ours = our_stream(level, None, false, &[], &data).unwrap();
            let one_shot = libzstd_bitexact::compress(&data, level).unwrap();
            assert_eq!(ours, one_shot, "auto-pledged finish must equal one-shot");
        }
    }
}

// --- Chunked feeding, unknown content size -------------------------------------

#[test]
fn chunked_streams_are_bit_exact() {
    // Unknown content size resolves parameters from the "default" srcSize
    // class regardless of how much data eventually flows — so even small
    // streams differ from the one-shot and must be checked against the
    // streaming oracle. Totals stay below windowSize + blockSize (640 KiB at
    // level 1) until the extDict matchers land.
    let text = word_salad(0xC4A1, 300_000);
    let mixed = mixed_runs(0xC4A2, 300_000);
    let random = Rng::new(0xC4A3).bytes(300_000);

    for data in [&text, &mixed, &random] {
        for &chunk in &[1usize << 10, 65_536, 131_072, 131_073] {
            for level in [1, 2, 3, 5, 9] {
                assert_stream_bit_exact(
                    level,
                    None,
                    false,
                    &chunked(data, chunk),
                    b"",
                    &format!("chunk-{chunk}"),
                );
            }
        }
    }
    // Higher levels: fewer chunk shapes, text only (runtime).
    for &chunk in &[65_536usize, 131_072] {
        for level in [13, 17, 19, 22] {
            assert_stream_bit_exact(
                level,
                None,
                false,
                &chunked(&text, chunk),
                b"",
                &format!("chunk-{chunk}-high"),
            );
        }
    }
    // Byte-at-a-time dribble (small total, cheap levels).
    let small = word_salad(0xC4A4, 10_000);
    for level in [1, 3] {
        assert_stream_bit_exact(level, None, false, &chunked(&small, 1), b"", "chunk-1");
        assert_stream_bit_exact(level, None, false, &chunked(&small, 7), b"", "chunk-7");
    }
    // Trailing data on the finish call itself.
    for level in [1, 3, 13] {
        let (head, tail) = text.split_at(200_000);
        assert_stream_bit_exact(
            level,
            None,
            false,
            &chunked(head, 50_000),
            tail,
            "finish-with-tail",
        );
    }
}

// --- Flush behavior -------------------------------------------------------------

#[test]
fn flush_patterns_are_bit_exact() {
    let text = word_salad(0xF1A5, 400_000);
    let mixed = mixed_runs(0xF1A6, 300_000);

    // Flush after every chunk: every block boundary is forced.
    for data in [&text[..300_000], &mixed[..]] {
        for level in [1, 3, 6] {
            let mut steps = Vec::new();
            for c in data.chunks(50_000) {
                steps.push(Step::Push(c));
                steps.push(Step::Flush);
            }
            assert_stream_bit_exact(level, None, false, &steps, b"", "flush-every-chunk");
        }
    }

    // One flush mid-stream; blocks after it start at unaligned offsets.
    for level in [1, 3, 9, 13, 19] {
        let steps = [
            Step::Push(&text[..70_000]),
            Step::Flush,
            Step::Push(&text[70_000..300_000]),
        ];
        assert_stream_bit_exact(level, None, false, &steps, b"", "flush-mid");
    }

    // Double flush (second is a no-op), flush before any data, flush at a
    // 128 KiB block boundary (buffer is exactly empty), tiny pieces around
    // flushes.
    for level in [1, 3, 13] {
        let steps = [
            Step::Flush,
            Step::Push(&text[..10_000]),
            Step::Flush,
            Step::Flush,
            Step::Push(&text[10_000..131_072]),
            Step::Flush,
            Step::Push(&text[131_072..131_073]),
            Step::Flush,
            Step::Push(&text[131_073..200_000]),
        ];
        assert_stream_bit_exact(level, None, false, &steps, b"", "flush-edges");
    }

    // Exactly one full block via continue (auto-compresses), then finish:
    // costs an empty last block, unlike a 128 KiB pledge.
    for level in [1, 3, 13] {
        assert_stream_bit_exact(
            level,
            None,
            false,
            &[Step::Push(&text[..131_072])],
            b"",
            "exact-block-no-pledge",
        );
    }
}

// --- Pledged content size --------------------------------------------------------

#[test]
fn pledged_size_streams_are_bit_exact() {
    let data = word_salad(0x91ED, 100_000);

    // Pledge + chunked feeding: parameters and header come from the real
    // size; the result equals the one-shot frame.
    for level in [1, 3, 9, 19] {
        assert_stream_bit_exact(
            level,
            Some(100_000),
            false,
            &chunked(&data, 30_000),
            b"",
            "pledged-chunked",
        );
        let ours = our_stream(level, Some(100_000), false, &chunked(&data, 30_000), b"").unwrap();
        let one_shot = libzstd_bitexact::compress(&data, level).unwrap();
        assert_eq!(ours, one_shot, "pledged stream must equal one-shot");
    }

    // A pledge of exactly blockSize (128 KiB): the +1 inBuffTarget quirk
    // defers compression so the single block is the last block.
    let block = word_salad(0x91EE, 131_072);
    for level in [1, 3] {
        assert_stream_bit_exact(
            level,
            Some(131_072),
            false,
            &chunked(&block, 40_000),
            b"",
            "pledged-exact-block",
        );
        let pledged =
            our_stream(level, Some(131_072), false, &chunked(&block, 40_000), b"").unwrap();
        let unpledged = our_stream(level, None, false, &chunked(&block, 40_000), b"").unwrap();
        assert_ne!(pledged, unpledged, "the quirk must change the frame");
    }

    // Pledge with a mid-stream flush.
    for level in [1, 9] {
        let steps = [
            Step::Push(&data[..40_000]),
            Step::Flush,
            Step::Push(&data[40_000..]),
        ];
        assert_stream_bit_exact(level, Some(100_000), false, &steps, b"", "pledged-flush");
    }

    // Lying about the pledge errors instead of emitting a bogus frame.
    let mut enc = StreamEncoder::with_pledged_src_size(3, 1000);
    let mut out = Vec::new();
    enc.compress(&data[..50_000], &mut out)
        .expect_err("overfeeding a pledge must fail");

    let mut enc = StreamEncoder::with_pledged_src_size(3, 50_000);
    let mut out = Vec::new();
    enc.compress(&data[..10_000], &mut out).unwrap();
    enc.finish(b"", &mut out)
        .expect_err("underfeeding a pledge must fail");
}

// --- Content checksum -------------------------------------------------------------

#[test]
fn checksummed_streams_are_bit_exact() {
    let data = mixed_runs(0xC4EC, 250_000);
    for level in [1, 3, 13] {
        assert_stream_bit_exact(
            level,
            None,
            true,
            &chunked(&data, 60_000),
            b"",
            "checksum-chunked",
        );
        let with = our_stream(level, None, true, &chunked(&data, 60_000), b"").unwrap();
        let without = our_stream(level, None, false, &chunked(&data, 60_000), b"").unwrap();
        assert_eq!(with.len(), without.len() + 4, "checksum adds 4 bytes");
    }
    // Checksum on an empty windowed frame and on a first-call finish.
    assert_stream_bit_exact(3, None, true, &[Step::Flush], b"", "checksum-empty");
    assert_stream_bit_exact(3, None, true, &[], &data[..1000], "checksum-finish-only");
}

// --- The current scope limit -------------------------------------------------------

#[test]
fn oversized_stream_errors_cleanly_instead_of_diverging() {
    // Level 1, unknown size: windowSize + blockSize = 640 KiB. Past that the
    // C input buffer wraps into extDict mode, which is not ported yet — we
    // must fail loudly, never emit different bytes.
    let data = word_salad(0x0CEA, 1 << 20);
    let mut enc = StreamEncoder::new(1);
    let mut out = Vec::new();
    let err = (|| -> Result<(), libzstd_bitexact::Error> {
        enc.compress(&data, &mut out)?;
        Ok(())
    })()
    .expect_err("wrapping the input buffer must error until extDict lands");
    let msg = format!("{err}");
    assert!(msg.contains("extDict"), "unexpected error: {msg}");
}
