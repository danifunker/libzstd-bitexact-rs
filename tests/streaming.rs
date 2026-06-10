//! Differential tests for the streaming decoder. The C libzstd is the oracle:
//! whatever it compresses, `StreamDecoder` must reproduce byte-for-byte, and
//! the result must not depend on how the compressed input is chunked.

use libzstd_bitexact::{DecodeOptions, Dictionary, StreamDecoder};
use std::io::{self, Read, Write};
use zstd::zstd_safe::CParameter;

/// xorshift64* — deterministic, dependency-free test data generator.
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
        let mut v = Vec::with_capacity(len);
        while v.len() < len {
            v.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        v.truncate(len);
        v
    }
}

/// A `Read` source that hands out at most `chunk` bytes per call, to force the
/// decoder across frame-header, block, and footer boundaries at every offset.
struct ChunkedReader<'a> {
    data: &'a [u8],
    pos: usize,
    chunk: usize,
}
impl Read for ChunkedReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.chunk.min(buf.len()).min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

fn stream_decode(frame: &[u8], chunk: usize) -> io::Result<Vec<u8>> {
    let reader = ChunkedReader {
        data: frame,
        pos: 0,
        chunk,
    };
    let mut decoder = StreamDecoder::new(reader);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

fn stream_decode_opts(frame: &[u8], chunk: usize, opts: DecodeOptions) -> io::Result<Vec<u8>> {
    let reader = ChunkedReader {
        data: frame,
        pos: 0,
        chunk,
    };
    let mut decoder = StreamDecoder::with_options(reader, opts);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

fn datasets() -> Vec<(&'static str, Vec<u8>)> {
    let mut rng = Rng::new(0x57EA_3001);
    let words: &[&[u8]] = &[
        b"the",
        b"quick",
        b"brown",
        b"fox",
        b"jumps",
        b"over",
        b"lazy",
        b"dog",
        b"zstandard",
        b"stream",
        b"window",
        b"block",
    ];
    let mut text = Vec::with_capacity(200_000);
    while text.len() < 200_000 {
        text.extend_from_slice(words[rng.below(words.len())]);
        text.push(b' ');
    }
    vec![
        ("empty", Vec::new()),
        ("tiny", b"hello".to_vec()),
        ("zeros-100k", vec![0u8; 100_000]),
        (
            "cycle-40k",
            (0..40_000u32).map(|i| (i % 251) as u8).collect(),
        ),
        ("random-50k", rng.bytes(50_000)),
        ("text-200k", text),
    ]
}

const CHUNKS: [usize; 6] = [1, 3, 7, 64, 1000, 1 << 16];

#[test]
fn bulk_frames_decode_identically_at_every_chunking() {
    for (name, data) in datasets() {
        for level in [1, 3, 9, 19] {
            let frame = zstd::bulk::compress(&data, level).unwrap();
            for &chunk in &CHUNKS {
                let out = stream_decode(&frame, chunk)
                    .unwrap_or_else(|e| panic!("{name} L{level} chunk {chunk}: {e}"));
                assert_eq!(out, data, "{name} L{level} chunk {chunk}");
            }
        }
    }
}

#[test]
fn streaming_frames_decode_identically_at_every_chunking() {
    // The streaming encoder emits window-descriptor frames with no declared
    // content size — the shape that most exercises the windowed decode path.
    for (name, data) in datasets() {
        for level in [1, 3, 19] {
            let frame = zstd::stream::encode_all(&data[..], level).unwrap();
            for &chunk in &CHUNKS {
                let out = stream_decode(&frame, chunk)
                    .unwrap_or_else(|e| panic!("streaming {name} L{level} chunk {chunk}: {e}"));
                assert_eq!(out, data, "streaming {name} L{level} chunk {chunk}");
            }
        }
    }
}

#[test]
fn checksummed_frames_verify_and_corruption_is_caught() {
    for (name, data) in datasets() {
        let mut enc = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
        enc.include_checksum(true).unwrap();
        enc.write_all(&data).unwrap();
        let frame = enc.finish().unwrap();

        for &chunk in &[1usize, 7, 1 << 16] {
            let out = stream_decode(&frame, chunk)
                .unwrap_or_else(|e| panic!("checksummed {name} chunk {chunk}: {e}"));
            assert_eq!(out, data, "checksummed {name}");
        }

        // Flipping the final checksum byte must be detected.
        if !data.is_empty() {
            let mut bad = frame.clone();
            let last = bad.len() - 1;
            bad[last] ^= 0xFF;
            assert!(
                stream_decode(&bad, 64).is_err(),
                "{name}: bad checksum accepted"
            );
        }
    }
}

#[test]
fn multi_frame_and_skippable() {
    let a = b"first frame payload ".repeat(800);
    let b = b"second distinct payload ".repeat(500);
    let mut stream = zstd::bulk::compress(&a, 3).unwrap();
    stream.extend_from_slice(&0x184D_2A50u32.to_le_bytes());
    stream.extend_from_slice(&5u32.to_le_bytes());
    stream.extend_from_slice(b"skip!");
    stream.extend_from_slice(&zstd::stream::encode_all(&b[..], 19).unwrap());

    let expected: Vec<u8> = a.iter().chain(b.iter()).copied().collect();
    for &chunk in &[1usize, 3, 64, 1 << 16] {
        assert_eq!(
            stream_decode(&stream, chunk).unwrap(),
            expected,
            "chunk {chunk}"
        );
    }
}

#[test]
fn dictionary_streaming_round_trip() {
    let words: &[&[u8]] = &[b"alpha", b"bravo", b"charlie", b"delta", b"echo"];
    let mut rng = Rng::new(0xD1C7_5EED);

    // A raw-content dictionary and a trained one.
    let mut raw = Vec::new();
    while raw.len() < 4096 {
        raw.extend_from_slice(words[rng.below(words.len())]);
        raw.push(b' ');
    }
    let mut samples = Vec::new();
    let mut sizes = Vec::new();
    for _ in 0..3000 {
        let mut s = Vec::new();
        for _ in 0..(8 + rng.below(16)) {
            s.extend_from_slice(words[rng.below(words.len())]);
            s.push(b' ');
        }
        sizes.push(s.len());
        samples.extend_from_slice(&s);
    }
    let trained = zstd::dict::from_continuous(&samples, &sizes, 16 * 1024).unwrap();

    let mut data = Vec::new();
    while data.len() < 20_000 {
        data.extend_from_slice(words[rng.below(words.len())]);
        data.push(b' ');
    }

    for dict_bytes in [raw, trained] {
        let dict = Dictionary::new(&dict_bytes).unwrap();
        for level in [3, 19] {
            let mut c = zstd::bulk::Compressor::with_dictionary(level, &dict_bytes).unwrap();
            let frame = c.compress(&data).unwrap();
            for &chunk in &[1usize, 7, 1 << 16] {
                let out = stream_decode_opts(&frame, chunk, DecodeOptions::new().dictionary(&dict))
                    .unwrap_or_else(|e| panic!("dict L{level} chunk {chunk}: {e}"));
                assert_eq!(out, data, "dict L{level} chunk {chunk}");
            }
        }
    }
}

/// Read the window log out of a windowed (non-single-segment) frame header.
fn window_log_of(frame: &[u8]) -> u32 {
    assert_eq!(frame[4] & 0x20, 0, "expected a windowed frame");
    10 + (frame[5] >> 3) as u32
}

fn encode_with_window_log(data: &[u8], window_log: u32) -> Vec<u8> {
    let mut enc = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
    enc.set_parameter(CParameter::WindowLog(window_log))
        .unwrap();
    enc.set_parameter(CParameter::ContentSizeFlag(false))
        .unwrap();
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// The defining property of streaming decode: a window smaller than the
/// content forces the decoder to evict old output mid-frame, yet matches must
/// still resolve to the correct bytes.
#[test]
fn small_window_forces_eviction_but_decodes_correctly() {
    let mut rng = Rng::new(0xE71C_7000);
    let mut data = Vec::with_capacity(400_000);
    while data.len() < 400_000 {
        // Repetitive enough that the encoder emits long-range matches, but the
        // window (128 KiB) is well under the 400 KiB content.
        data.extend_from_slice(b"window eviction stress ");
        if rng.below(20) == 0 {
            let n = rng.below(64);
            data.extend_from_slice(&rng.bytes(n));
        }
    }

    let frame = encode_with_window_log(&data, 17); // 128 KiB window
    assert!(window_log_of(&frame) <= 18, "expected a sub-content window");
    for &chunk in &[7usize, 1000, 1 << 16] {
        let out = stream_decode(&frame, chunk).unwrap();
        assert_eq!(out, data, "eviction decode mismatch at chunk {chunk}");
    }
}

#[test]
fn window_log_max_is_enforced() {
    let mut rng = Rng::new(0x1A2B_3C4D);
    let mut data = Vec::with_capacity(150_000);
    while data.len() < 150_000 {
        data.extend_from_slice(b"alpha bravo charlie ");
        let _ = rng.next_u64();
    }
    let frame = encode_with_window_log(&data, 19);
    let actual = window_log_of(&frame);

    // At or above the frame's window log: accepted, correct bytes.
    let ok = stream_decode_opts(&frame, 64, DecodeOptions::new().window_log_max(actual)).unwrap();
    assert_eq!(ok, data);
    // Below it: rejected.
    assert!(
        stream_decode_opts(&frame, 64, DecodeOptions::new().window_log_max(actual - 1)).is_err(),
        "window log {actual} accepted under a tighter windowLogMax"
    );
}

#[test]
fn output_limit_is_enforced() {
    let data = vec![7u8; 1 << 20];
    let frame = zstd::bulk::compress(&data, 3).unwrap();
    assert!(stream_decode_opts(&frame, 1 << 16, DecodeOptions::new().limit(1000)).is_err());
    assert_eq!(
        stream_decode_opts(&frame, 1 << 16, DecodeOptions::new().limit(1 << 20)).unwrap(),
        data
    );
}

#[test]
fn truncation_errors_and_never_panics() {
    let data = b"streaming truncation corpus ".repeat(2000);
    let frame = zstd::stream::encode_all(&data[..], 6).unwrap();
    for len in 1..frame.len() {
        // A truncated stream must error cleanly (never a panic, never a silent
        // short read masquerading as success).
        let r = stream_decode(&frame[..len], 13);
        assert!(r.is_err(), "truncation to {len} unexpectedly succeeded");
    }
}
