//! Differential tests: the real C libzstd (via the `zstd` crate) is the
//! oracle. Everything it compresses, we must decompress to identical bytes.

use std::io::Write;

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

/// A spread of datasets chosen to exercise every block and literals type:
/// incompressible (raw blocks), constant (RLE), text-like (FSE+Huffman),
/// and match-heavy (long offsets, repeat offsets).
fn datasets() -> Vec<(&'static str, Vec<u8>)> {
    let mut rng = Rng::new(0x5EED_CAFE_F00D_0001);
    let mut sets: Vec<(&'static str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("one-byte", vec![42]),
        ("hello", b"hello world".to_vec()),
        ("zeros-100k", vec![0u8; 100_000]),
        (
            "cycle-10k",
            (0..10_000u32).map(|i| (i % 251) as u8).collect(),
        ),
        ("random-1m", rng.bytes(1 << 20)),
    ];

    // Text-like: random words, highly compressible with entropy coding and
    // short matches — the bread-and-butter zstd case.
    let words: Vec<&[u8]> = vec![
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
        b"literal",
        b"offset",
    ];
    let mut text = Vec::with_capacity(600_000);
    while text.len() < 600_000 {
        text.extend_from_slice(words[rng.below(words.len())]);
        text.push(b' ');
        if rng.below(12) == 0 {
            text.push(b'\n');
        }
    }
    sets.push(("text-600k", text));

    // Match-heavy: a base pattern repeated with sparse mutations, which
    // produces long matches and exercises the repeat-offset history.
    let base = rng.bytes(1024);
    let mut repetitive = Vec::with_capacity(400_000);
    while repetitive.len() < 400_000 {
        let mut chunk = base.clone();
        if rng.below(4) != 0 {
            let at = rng.below(chunk.len());
            chunk[at] ^= 0xA5;
        }
        repetitive.extend_from_slice(&chunk);
    }
    sets.push(("repetitive-400k", repetitive));

    // Low-entropy bytes: stresses FSE-compressed literal paths and tiny
    // Huffman alphabets.
    let low_entropy: Vec<u8> = (0..200_000).map(|_| (rng.below(4) * 7) as u8).collect();
    sets.push(("low-entropy-200k", low_entropy));

    // Mixed runs: alternating constant runs and random spans of random
    // lengths, hitting RLE literals and block-type switches.
    let mut runs = Vec::with_capacity(300_000);
    while runs.len() < 300_000 {
        if rng.below(2) == 0 {
            let b = (rng.next_u64() & 0xFF) as u8;
            let n = 1 + rng.below(2000);
            runs.extend(std::iter::repeat_n(b, n));
        } else {
            let n = 1 + rng.below(500);
            let r = rng.bytes(n);
            runs.extend_from_slice(&r);
        }
    }
    sets.push(("mixed-runs-300k", runs));

    sets
}

const LEVELS: [i32; 7] = [1, 3, 5, 9, 13, 19, 22];

#[test]
fn c_bulk_compress_rust_decompress() {
    for (name, data) in datasets() {
        for level in LEVELS {
            let compressed = zstd::bulk::compress(&data, level)
                .unwrap_or_else(|e| panic!("oracle failed compressing {name} at {level}: {e}"));
            let decompressed = libzstd_bitexact_rs::decompress(&compressed)
                .unwrap_or_else(|e| panic!("failed to decompress {name} at level {level}: {e}"));
            assert_eq!(decompressed, data, "mismatch on {name} at level {level}");
        }
    }
}

#[test]
fn c_streaming_compress_rust_decompress() {
    // The streaming encoder produces frames without a declared content size
    // and with window-descriptor headers — a different header shape than
    // `bulk`.
    for (name, data) in datasets() {
        for level in [1, 3, 9, 19] {
            let compressed = zstd::stream::encode_all(&data[..], level).unwrap();
            let decompressed = libzstd_bitexact_rs::decompress(&compressed)
                .unwrap_or_else(|e| panic!("failed on streaming {name} at {level}: {e}"));
            assert_eq!(
                decompressed, data,
                "mismatch on streaming {name} at level {level}"
            );
        }
    }
}

#[test]
fn checksummed_frames_verify() {
    for (name, data) in datasets() {
        let mut encoder = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
        encoder.include_checksum(true).unwrap();
        encoder.write_all(&data).unwrap();
        let compressed = encoder.finish().unwrap();
        let decompressed = libzstd_bitexact_rs::decompress(&compressed)
            .unwrap_or_else(|e| panic!("failed on checksummed {name}: {e}"));
        assert_eq!(decompressed, data, "mismatch on checksummed {name}");
    }
}

#[test]
fn corrupted_checksum_is_rejected() {
    let data = datasets().swap_remove(6).1; // text-600k
    let mut encoder = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
    encoder.include_checksum(true).unwrap();
    encoder.write_all(&data).unwrap();
    let mut compressed = encoder.finish().unwrap();
    // The checksum is the final four bytes of the frame.
    let last = compressed.len() - 1;
    compressed[last] ^= 0xFF;
    assert!(matches!(
        libzstd_bitexact_rs::decompress(&compressed),
        Err(libzstd_bitexact_rs::Error::ChecksumMismatch { .. })
    ));
}

#[test]
fn multi_frame_and_skippable_concatenation() {
    let a = b"first frame payload".repeat(500);
    let b = b"second, different payload".repeat(300);
    let mut stream = zstd::bulk::compress(&a, 3).unwrap();
    // A skippable frame in the middle (magic 0x184D2A50, 4-byte size).
    stream.extend_from_slice(&0x184D_2A50u32.to_le_bytes());
    stream.extend_from_slice(&5u32.to_le_bytes());
    stream.extend_from_slice(b"skip!");
    stream.extend_from_slice(&zstd::bulk::compress(&b, 19).unwrap());

    let decompressed = libzstd_bitexact_rs::decompress(&stream).unwrap();
    let expected: Vec<u8> = a.iter().chain(b.iter()).copied().collect();
    assert_eq!(decompressed, expected);
}

#[test]
fn every_truncation_errors_and_never_panics() {
    let data = b"truncation test corpus ".repeat(2000);
    let compressed = zstd::bulk::compress(&data, 3).unwrap();
    for len in 1..compressed.len() {
        let r = libzstd_bitexact_rs::decompress(&compressed[..len]);
        assert!(
            r.is_err(),
            "truncation to {len} bytes unexpectedly succeeded"
        );
    }
}

#[test]
fn random_corruptions_never_panic() {
    let mut rng = Rng::new(0xBAD5_EED5_0000_0042);
    let data = b"corruption test corpus, semi-compressible 0123456789 ".repeat(2000);
    let compressed = zstd::bulk::compress(&data, 6).unwrap();
    for _ in 0..2000 {
        let mut copy = compressed.clone();
        let flips = 1 + rng.below(4);
        for _ in 0..flips {
            let at = rng.below(copy.len());
            copy[at] ^= 1 << rng.below(8);
        }
        // Must terminate without panicking; both Ok and Err are acceptable
        // (a flipped bit can land in an unused or self-correcting spot, and
        // this frame carries no checksum).
        let _ = libzstd_bitexact_rs::decompress_with_limit(&copy, 16 << 20);
    }
}

#[test]
fn output_limit_is_enforced() {
    let data = vec![7u8; 1 << 20];
    let compressed = zstd::bulk::compress(&data, 3).unwrap();
    assert!(matches!(
        libzstd_bitexact_rs::decompress_with_limit(&compressed, 1000),
        Err(libzstd_bitexact_rs::Error::OutputTooLarge)
    ));
    assert_eq!(
        libzstd_bitexact_rs::decompress_with_limit(&compressed, 1 << 20).unwrap(),
        data
    );
}

/// Cross-check accept/reject parity with the oracle on small random inputs:
/// any byte soup we accept, the C decoder must accept with identical output.
#[test]
fn no_false_accepts_on_random_input() {
    let mut rng = Rng::new(0x0DDB_A110_0000_0007);
    let magic = 0xFD2F_B528u32.to_le_bytes();
    for _ in 0..20_000 {
        let mut soup = vec![0u8; 4 + rng.below(64)];
        for b in soup.iter_mut() {
            *b = (rng.next_u64() & 0xFF) as u8;
        }
        soup[..4].copy_from_slice(&magic);
        if let Ok(ours) = libzstd_bitexact_rs::decompress_with_limit(&soup, 1 << 20) {
            let theirs = zstd::bulk::decompress(&soup, 1 << 20)
                .unwrap_or_else(|e| panic!("we accepted {soup:02X?} but C rejects it: {e}"));
            assert_eq!(ours, theirs, "divergent decode of {soup:02X?}");
        }
    }
}
