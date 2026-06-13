//! Streaming-compression bit-exactness: our `StreamEncoder` must produce
//! **byte-identical output** to C libzstd 1.5.7's `ZSTD_compressStream2` for
//! the same sequence of continue/flush/end operations — including the
//! unknown-content-size frame headers, the buffered block scheduling, the
//! auto-pledge on a first-call end, and the pledged-size quirks.
//!
//! Scope note: streams larger than `windowSize + blockSize` wrap the C input
//! buffer and flip the window into extDict mode. All nine strategies'
//! extDict match finders are ported (multi-wrap parity covered by
//! `wrapped_streams_are_bit_exact_at_{fast,dfast,lazy,btlazy2,btopt}_levels`).
//! Long-distance matching (which C auto-enables for level 22 at unknown
//! content size) is bit-exact, covered by `ldm_streams_are_bit_exact` and
//! `ldm_one_shot_above_64mib_is_bit_exact`.

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
    // Higher levels: fewer chunk shapes, text only (runtime). Level 22 at
    // unknown content size enables long-distance matching (windowLog 27);
    // its bit-exactness is covered in depth by `ldm_streams_are_bit_exact`.
    for &chunk in &[65_536usize, 131_072] {
        for level in [13, 17, 19, 21, 22] {
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

// --- Streams beyond the input buffer (wrap + extDict, fast strategy) -------------

/// Streams that outgrow `windowSize + blockSize` wrap the staging buffer:
/// the live window becomes the extDict and matches reach across the seam.
/// Levels resolving to the fast strategy (1, 2, negatives at unknown size)
/// must stay bit-exact through multiple wraps.
#[test]
fn wrapped_streams_are_bit_exact_at_fast_levels() {
    // Level 1 wraps every 640 KiB, level 2 every 1.125 MiB.
    let text = word_salad(0x3A91, 4 << 20);
    for level in [1, 2, -1, -3] {
        assert_stream_bit_exact(
            level,
            None,
            false,
            &chunked(&text, 100_001),
            b"",
            "wrap-text-4M",
        );
    }

    // Mixed runs with periodic flushes across wraps.
    let mixed = mixed_runs(0x3A92, 2 << 20);
    for level in [1, 2] {
        let mut steps = Vec::new();
        for (i, c) in mixed.chunks(90_000).enumerate() {
            steps.push(Step::Push(c));
            if i % 3 == 2 {
                steps.push(Step::Flush);
            }
        }
        assert_stream_bit_exact(level, None, false, &steps, b"", "wrap-flush-mixed-2M");
    }

    // Incompressible data: raw blocks, negative savings, and the
    // dict-overlap lowLimit shrink with content that never matches.
    let random = Rng::new(0x3A93).bytes(3 << 20);
    assert_stream_bit_exact(
        1,
        None,
        false,
        &chunked(&random, 131_072),
        b"",
        "wrap-random-3M",
    );

    // Periodic data with the period just under the window size: repcodes
    // and matches constantly reach back into the extDict segment.
    let mut periodic = Vec::with_capacity(2_000_000);
    let unit: Vec<u8> = (0..510_000u32).map(|i| (i * 37 + 11) as u8).collect();
    while periodic.len() < 2_000_000 {
        periodic.extend_from_slice(&unit);
    }
    periodic.truncate(2_000_000);
    for level in [1, -1] {
        assert_stream_bit_exact(
            level,
            None,
            false,
            &chunked(&periodic, 131_072),
            b"",
            "wrap-periodic-2M",
        );
    }

    // Pledged size and checksum still hold across wraps.
    let data = &text[..3 << 20];
    assert_stream_bit_exact(
        1,
        Some(data.len() as u64),
        false,
        &chunked(data, 131_072),
        b"",
        "wrap-pledged-3M",
    );
    assert_stream_bit_exact(
        1,
        None,
        true,
        &chunked(data, 200_003),
        b"",
        "wrap-checksum-3M",
    );
}

// --- Streams beyond the input buffer (wrap + extDict, dfast strategy) -------------

/// Levels 3-4 resolve to dfast at unknown content size (windowLog 21: the
/// buffer wraps every 2.125 MiB). Wrapped streams must stay bit-exact through
/// the extDict phase, the extDict-aged-out fallback inside the matcher, and
/// the return to the noDict matcher with a nonzero segment bias.
#[test]
#[cfg_attr(debug_assertions, ignore = "heavy differential test, run in release")]
fn wrapped_streams_are_bit_exact_at_dfast_levels() {
    // ~7 MiB: three full wraps. Block-aligned chunks make a lap line up
    // exactly with the buffer, which is what lets `enforceMaxDist` age the
    // extDict out completely (noDict with seg_bias != 2); the odd-sized
    // chunks keep every other alignment honest.
    let text = word_salad(0x3B01, 7 << 20);
    for level in [3, 4] {
        for &chunk in &[100_001usize, 131_072, 131_073] {
            assert_stream_bit_exact(
                level,
                None,
                false,
                &chunked(&text, chunk),
                b"",
                &format!("dfast-wrap-text-7M-chunk-{chunk}"),
            );
        }
    }

    // 64 KiB chunks (two chunks per block) across one wrap.
    let mixed = mixed_runs(0x3B02, 3 << 20);
    for level in [3, 4] {
        assert_stream_bit_exact(
            level,
            None,
            false,
            &chunked(&mixed, 65_536),
            b"",
            "dfast-wrap-mixed-3M",
        );
    }

    // Tiny chunks (7 bytes) across a single wrap.
    let small = word_salad(0x3B03, (2 << 20) + 300_000);
    assert_stream_bit_exact(
        3,
        None,
        false,
        &chunked(&small, 7),
        b"",
        "dfast-wrap-chunk-7",
    );

    // Mixed runs with periodic flushes across wraps.
    for level in [3, 4] {
        let mut steps = Vec::new();
        for (i, c) in mixed.chunks(90_000).enumerate() {
            steps.push(Step::Push(c));
            if i % 3 == 2 {
                steps.push(Step::Flush);
            }
        }
        assert_stream_bit_exact(level, None, false, &steps, b"", "dfast-wrap-flush-mixed");
    }

    // Incompressible data: raw blocks and the dict-overlap lowLimit shrink.
    let random = Rng::new(0x3B04).bytes(3 << 20);
    assert_stream_bit_exact(
        3,
        None,
        false,
        &chunked(&random, 131_072),
        b"",
        "dfast-wrap-random-3M",
    );

    // Periodic data with the period just under the 2 MiB window: matches and
    // repcodes constantly reach back into the extDict segment.
    let mut periodic = Vec::with_capacity(7 << 20);
    let unit: Vec<u8> = (0..2_000_000u32).map(|i| (i * 37 + 11) as u8).collect();
    while periodic.len() < 7 << 20 {
        periodic.extend_from_slice(&unit);
    }
    periodic.truncate(7 << 20);
    for level in [3, 4] {
        assert_stream_bit_exact(
            level,
            None,
            false,
            &chunked(&periodic, 131_072),
            b"",
            "dfast-wrap-periodic-7M",
        );
    }

    // Pledged size and checksum still hold across wraps.
    let data = &text[..3 << 20];
    assert_stream_bit_exact(
        3,
        Some(data.len() as u64),
        false,
        &chunked(data, 131_072),
        b"",
        "dfast-wrap-pledged-3M",
    );
    assert_stream_bit_exact(
        3,
        None,
        true,
        &chunked(data, 200_003),
        b"",
        "dfast-wrap-checksum-3M",
    );
}

// --- Streams beyond the input buffer (wrap + extDict, greedy/lazy/lazy2) ----------

/// Levels 5-12 resolve to greedy/lazy/lazy2 at unknown content size, all in
/// row-matcher mode (windowLog 21-22: the buffer wraps every 2.125 / 4.125
/// MiB). Wrapped streams must stay bit-exact through the extDict phase and
/// the return to the noDict driver with a nonzero segment bias.
#[test]
#[cfg_attr(debug_assertions, ignore = "heavy differential test, run in release")]
fn wrapped_streams_are_bit_exact_at_lazy_levels() {
    // ~7 MiB at a 2 MiB window: three full wraps, all three depths. The
    // block-aligned chunk size lets `enforceMaxDist` age the extDict out
    // completely (noDict driver with seg_bias != 2); the odd sizes keep
    // every other alignment honest.
    let text = word_salad(0x3C01, 7 << 20);
    for level in [5, 6, 8] {
        for &chunk in &[100_001usize, 131_072, 131_073] {
            assert_stream_bit_exact(
                level,
                None,
                false,
                &chunked(&text, chunk),
                b"",
                &format!("lazy-wrap-text-7M-chunk-{chunk}"),
            );
        }
    }
    // Level 7 (lazy, depth 1) and 64 KiB chunks across one wrap.
    let mixed = mixed_runs(0x3C02, 3 << 20);
    for level in [5, 7] {
        assert_stream_bit_exact(
            level,
            None,
            false,
            &chunked(&mixed, 65_536),
            b"",
            "lazy-wrap-mixed-3M",
        );
    }

    // Levels 9 and 12 use windowLog 22: wrap at 4.125 MiB.
    let big = word_salad(0x3C03, 9 << 20);
    for level in [9, 12] {
        assert_stream_bit_exact(
            level,
            None,
            false,
            &chunked(&big, 131_072),
            b"",
            "lazy2-wrap-text-9M",
        );
    }

    // Tiny chunks (7 bytes) across a single wrap.
    let small = word_salad(0x3C04, (2 << 20) + 300_000);
    assert_stream_bit_exact(
        5,
        None,
        false,
        &chunked(&small, 7),
        b"",
        "lazy-wrap-chunk-7",
    );

    // Mixed runs with periodic flushes across wraps.
    for level in [5, 8] {
        let mut steps = Vec::new();
        for (i, c) in mixed.chunks(90_000).enumerate() {
            steps.push(Step::Push(c));
            if i % 3 == 2 {
                steps.push(Step::Flush);
            }
        }
        assert_stream_bit_exact(level, None, false, &steps, b"", "lazy-wrap-flush-mixed");
    }

    // Incompressible data: raw blocks, lazy-skipping mode (2 KiB of misses)
    // across the wrap, and the dict-overlap lowLimit shrink.
    let random = Rng::new(0x3C05).bytes(3 << 20);
    for level in [5, 8] {
        assert_stream_bit_exact(
            level,
            None,
            false,
            &chunked(&random, 131_072),
            b"",
            "lazy-wrap-random-3M",
        );
    }

    // Periodic data with the period just under the 2 MiB window: matches and
    // repcodes constantly reach back into the extDict segment.
    let mut periodic = Vec::with_capacity(5 << 20);
    let unit: Vec<u8> = (0..2_000_000u32).map(|i| (i * 37 + 11) as u8).collect();
    while periodic.len() < 5 << 20 {
        periodic.extend_from_slice(&unit);
    }
    periodic.truncate(5 << 20);
    for level in [6, 8] {
        assert_stream_bit_exact(
            level,
            None,
            false,
            &chunked(&periodic, 131_072),
            b"",
            "lazy-wrap-periodic-5M",
        );
    }

    // Pledged size and checksum still hold across wraps.
    let data = &text[..3 << 20];
    assert_stream_bit_exact(
        7,
        Some(data.len() as u64),
        false,
        &chunked(data, 131_072),
        b"",
        "lazy-wrap-pledged-3M",
    );
    assert_stream_bit_exact(
        7,
        None,
        true,
        &chunked(data, 200_003),
        b"",
        "lazy-wrap-checksum-3M",
    );
}

// --- Streams beyond the input buffer (wrap + extDict, btlazy2) --------------------

/// Levels 13-15 resolve to btlazy2 at unknown content size (windowLog 22:
/// the buffer wraps every 4.125 MiB). The DUBT keeps an unsorted backlog
/// across the wrap, so post-wrap searches batch-sort pre-wrap (dict-segment)
/// positions — `insertDUBT1` with a dict-side `curr` — besides the
/// two-segment candidate compares.
#[test]
#[cfg_attr(debug_assertions, ignore = "heavy differential test, run in release")]
fn wrapped_streams_are_bit_exact_at_btlazy2_levels() {
    // ~9.5 MiB: two full wraps; block-aligned chunks let the extDict age out
    // (noDict with seg_bias != 2), odd sizes keep alignments honest.
    let text = word_salad(0x3D01, (9 << 20) + (1 << 19));
    for level in [13, 15] {
        for &chunk in &[131_072usize, 131_073] {
            assert_stream_bit_exact(
                level,
                None,
                false,
                &chunked(&text, chunk),
                b"",
                &format!("btlazy2-wrap-text-9M-chunk-{chunk}"),
            );
        }
    }

    // Mixed runs with periodic flushes across one wrap (level 14).
    let mixed = mixed_runs(0x3D02, 5 << 20);
    let mut steps = Vec::new();
    for (i, c) in mixed.chunks(90_000).enumerate() {
        steps.push(Step::Push(c));
        if i % 3 == 2 {
            steps.push(Step::Flush);
        }
    }
    assert_stream_bit_exact(14, None, false, &steps, b"", "btlazy2-wrap-flush-mixed-5M");

    // Incompressible data across one wrap.
    let random = Rng::new(0x3D03).bytes(5 << 20);
    assert_stream_bit_exact(
        13,
        None,
        false,
        &chunked(&random, 131_072),
        b"",
        "btlazy2-wrap-random-5M",
    );

    // Periodic data with the period just under the 4 MiB window.
    let mut periodic = Vec::with_capacity(9 << 20);
    let unit: Vec<u8> = (0..4_000_000u32).map(|i| (i * 37 + 11) as u8).collect();
    while periodic.len() < 9 << 20 {
        periodic.extend_from_slice(&unit);
    }
    periodic.truncate(9 << 20);
    assert_stream_bit_exact(
        13,
        None,
        false,
        &chunked(&periodic, 131_072),
        b"",
        "btlazy2-wrap-periodic-9M",
    );

    // Pledged size and checksum still hold across wraps.
    let data = &text[..5 << 20];
    assert_stream_bit_exact(
        14,
        Some(data.len() as u64),
        false,
        &chunked(data, 131_072),
        b"",
        "btlazy2-wrap-pledged-5M",
    );
    assert_stream_bit_exact(
        14,
        None,
        true,
        &chunked(data, 200_003),
        b"",
        "btlazy2-wrap-checksum-5M",
    );
}

// --- Streams beyond the input buffer (wrap + extDict, btopt/btultra/btultra2) -----

/// Levels 16-22 resolve to the bt-opt strategies. At unknown content size
/// level 16 wraps every 4.125 MiB and levels 17-19 every 8.125 MiB (levels
/// 20-22 use 32 MiB+ windows — same code paths, impractical input sizes).
/// Besides the two-segment `ZSTD_insertBtAndGetAllMatches`, this covers the
/// post-block splitter over extDict blocks, and for btultra2 the
/// `ZSTD_initStats_ultra` window slide interacting with a later wrap (and
/// the extDict remap of btultra2 onto the btultra block compressor).
#[test]
#[cfg_attr(debug_assertions, ignore = "heavy differential test, run in release")]
fn wrapped_streams_are_bit_exact_at_btopt_levels() {
    // Level 16 (btopt, 4 MiB window): ~9.5 MiB makes two full wraps;
    // block-aligned chunks let the extDict age out completely.
    let text = word_salad(0x3E01, (9 << 20) + (1 << 19));
    for &chunk in &[131_072usize, 131_073] {
        assert_stream_bit_exact(
            16,
            None,
            false,
            &chunked(&text, chunk),
            b"",
            &format!("btopt-wrap-text-9M-chunk-{chunk}"),
        );
    }

    // Levels 17 (btopt), 18 (btultra), 19 (btultra2): 8 MiB window, one wrap.
    for level in [17, 18, 19] {
        assert_stream_bit_exact(
            level,
            None,
            false,
            &chunked(&text, 131_072),
            b"",
            "btopt-wrap-text-9M-high",
        );
    }

    // Mixed runs with periodic flushes across a level-16 wrap.
    let mixed = mixed_runs(0x3E02, 5 << 20);
    let mut steps = Vec::new();
    for (i, c) in mixed.chunks(90_000).enumerate() {
        steps.push(Step::Push(c));
        if i % 3 == 2 {
            steps.push(Step::Flush);
        }
    }
    assert_stream_bit_exact(16, None, false, &steps, b"", "btopt-wrap-flush-mixed-5M");

    // Incompressible data across one wrap.
    let random = Rng::new(0x3E03).bytes(5 << 20);
    assert_stream_bit_exact(
        16,
        None,
        false,
        &chunked(&random, 131_072),
        b"",
        "btopt-wrap-random-5M",
    );

    // Periodic data with the period just under the 4 MiB window.
    let mut periodic = Vec::with_capacity(9 << 20);
    let unit: Vec<u8> = (0..4_000_000u32).map(|i| (i * 37 + 11) as u8).collect();
    while periodic.len() < 9 << 20 {
        periodic.extend_from_slice(&unit);
    }
    periodic.truncate(9 << 20);
    assert_stream_bit_exact(
        16,
        None,
        false,
        &chunked(&periodic, 131_072),
        b"",
        "btopt-wrap-periodic-9M",
    );

    // Levels 20-21 never wrap at test-friendly sizes (32/64 MiB windows),
    // but multi-block streaming at unknown content size (btultra2 initStats
    // slide + block scheduling) still needs parity beyond the small chunked
    // tests. (Level 22 adds LDM on top, covered by `ldm_streams_are_bit_exact`.)
    let big = &text[..5 << 20];
    for level in [20, 21] {
        assert_stream_bit_exact(
            level,
            None,
            false,
            &chunked(big, 131_073),
            b"",
            "btultra2-nowrap-5M",
        );
    }

    // Pledged size and checksum still hold across wraps.
    let data = &text[..5 << 20];
    assert_stream_bit_exact(
        16,
        Some(data.len() as u64),
        false,
        &chunked(data, 131_072),
        b"",
        "btopt-wrap-pledged-5M",
    );
    assert_stream_bit_exact(
        19,
        None,
        true,
        &chunked(&text, 200_003),
        b"",
        "btultra2-wrap-checksum-9M",
    );
}

// --- Long-distance matching (level 22 at unknown content size) ---------------------

/// Level 22 at unknown content size resolves to windowLog 27, where C
/// auto-enables long-distance matching (`ZSTD_resolveEnableLdm` fires for
/// `strategy >= btopt` with `windowLog` at least 27). The LDM match finder
/// ([`crate::ldm`]) generates raw-sequence candidates that the optimal parser
/// consumes; this output must be byte-identical to C.
///
/// The bit-exactness hazard lives across block boundaries: zstd 1.5.7's
/// `ZSTD_ldm_gear_reset` is a no-op (a missing rolling-hash writeback), so
/// every block's gear hash is seeded from the same constant and the first
/// `minMatchLength` splits of a *populated*-table block are where a faithful
/// port and a "corrected" one diverge. Several blocks of word salad (which
/// has abundant long-range repeats) exercise exactly that.
#[test]
#[cfg_attr(debug_assertions, ignore = "level 22 + LDM; runs in release (CI gate)")]
fn ldm_streams_are_bit_exact() {
    let text = word_salad(0x1D40, 4 << 20);
    for &chunk in &[65_536usize, 131_072, 200_000] {
        assert_stream_bit_exact(22, None, false, &chunked(&text, chunk), b"", "ldm-stream");
    }
    // Whole input in a single push, and trailing data carried on the finish.
    assert_stream_bit_exact(22, None, false, &[Step::Push(&text)], b"", "ldm-one-push");
    let (head, tail) = text.split_at(2 << 20);
    assert_stream_bit_exact(
        22,
        None,
        false,
        &chunked(head, 300_000),
        tail,
        "ldm-finish-tail",
    );

    // A second seed, with a mid-stream flush forcing an unaligned block start.
    let other = word_salad(0x1D31, 2 << 20);
    let mut steps = Vec::new();
    for c in other.chunks(300_000) {
        steps.push(Step::Push(c));
        steps.push(Step::Flush);
    }
    assert_stream_bit_exact(22, None, false, &steps, b"", "ldm-flush");

    // A small *pledged* size at level 22 keeps windowLog below 27: no LDM,
    // still bit-exact (also covered throughout the one-shot suites).
    let small = word_salad(0x3E01, 100_000);
    assert_stream_bit_exact(
        22,
        Some(small.len() as u64),
        false,
        &chunked(&small, 30_000),
        b"",
        "level22-small-pledge",
    );
}

/// The one-shot LDM enable cliff: a *known* content size above 64 MiB also
/// resolves to windowLog 27 and enables LDM (the configuration that, before
/// LDM was bit-exact, returned a clean error). Heavy — compresses 64 MiB+ at
/// the slowest level — so it runs only when explicitly requested.
#[test]
#[ignore = "compresses 64 MiB+ at level 22 to exercise the one-shot LDM cliff; minutes-long"]
fn ldm_one_shot_above_64mib_is_bit_exact() {
    let data = word_salad(0x1D40, (64 << 20) + 1);
    let ours = libzstd_bitexact::compress(&data, 22).expect("LDM one-shot must succeed");
    let theirs = zstd::bulk::compress(&data, 22).expect("C one-shot oracle");
    assert_eq!(
        ours.len(),
        theirs.len(),
        "one-shot > 64 MiB at level 22 (LDM): length differs"
    );
    assert!(
        ours == theirs,
        "one-shot > 64 MiB at level 22 (LDM): not bit-exact"
    );
    let back = libzstd_bitexact::decompress(&ours).expect("round-trip");
    assert_eq!(back, data, "round-trip mismatch");
}

// --- Index overflow correction (> 3500 MiB streams) --------------------------------

/// Once the running index reaches `ZSTD_CURRENT_MAX` (3500 MiB), C recycles
/// the 32-bit index space (`ZSTD_window_correctOverflow` + `ZSTD_reduceIndex`).
/// Streaming past that point must stay byte-identical. This drives ~3.7 GiB
/// of repeating word-salad through both encoders at level 1 (fast strategy,
/// 512 KiB window) — generated on the fly so it never lives in RAM all at
/// once — and compares the full compressed output. Heavy: minutes-long, runs
/// only when explicitly requested.
#[test]
#[ignore = "streams 3.7 GiB to cross the 3500 MiB overflow-correction threshold; minutes-long"]
fn overflow_correction_streams_are_bit_exact() {
    use zstd_sys::ZSTD_EndDirective as Dir;

    let level = 1;
    // A 256 KiB unit (< the level-1 512 KiB window) so the repeats produce
    // in-window matches that populate — and, across the overflow boundary,
    // must be reduced in — the hash table.
    let unit = word_salad(0xABCD, 256 * 1024);
    let total: u64 = 3700 * (1 << 20); // 3.7 GiB > 3500 MiB

    // C oracle, driven directly so the input is never fully materialized.
    let mut cctx = CCtx::create();
    cctx.set_parameter(CParameter::CompressionLevel(level))
        .unwrap();
    let mut their_out = Vec::new();
    let mut scratch = vec![0u8; 1 << 20];
    let mut enc = StreamEncoder::new(level);
    let mut our_out = Vec::new();

    let mut fed: u64 = 0;
    let mut k = 0usize;
    while fed < total {
        // One unit per step (256 KiB), cycling the seed slightly so it is not
        // pure RLE but still highly compressible.
        let chunk = &unit[..];
        let mut inb = InBuffer::around(chunk);
        loop {
            let mut outb = OutBuffer::around(&mut scratch[..]);
            cctx.compress_stream2(&mut outb, &mut inb, Dir::ZSTD_e_continue)
                .map_err(map_code)
                .unwrap();
            let p = outb.pos();
            their_out.extend_from_slice(&scratch[..p]);
            if inb.pos >= chunk.len() {
                break;
            }
        }
        enc.compress(chunk, &mut our_out).unwrap();
        // Keep the comparison incremental so divergence is caught early and
        // the buffers do not grow without bound on a mismatch.
        let n = our_out.len().min(their_out.len());
        assert_eq!(
            our_out[..n],
            their_out[..n],
            "overflow-correction stream diverged after {fed} bytes (step {k})"
        );
        fed += chunk.len() as u64;
        k += 1;
    }
    // Flush the frame end on both sides and compare the remainder.
    loop {
        let mut inb = InBuffer::around(&[][..]);
        let mut outb = OutBuffer::around(&mut scratch[..]);
        let hint = cctx
            .compress_stream2(&mut outb, &mut inb, Dir::ZSTD_e_end)
            .map_err(map_code)
            .unwrap();
        let p = outb.pos();
        their_out.extend_from_slice(&scratch[..p]);
        if hint == 0 {
            break;
        }
    }
    enc.finish(b"", &mut our_out).unwrap();
    assert_eq!(
        our_out, their_out,
        "overflow-correction frame not bit-exact"
    );
    eprintln!(
        "overflow correction OK: {} MiB in -> {} bytes out",
        total >> 20,
        our_out.len()
    );
}
