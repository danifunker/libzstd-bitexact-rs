//! THE bit-exactness tests: our `compress` output must be **byte-identical**
//! to the C libzstd 1.5.7 oracle (`ZSTD_compress` via `zstd::bulk::compress`)
//! for the supported scope — fast-strategy levels, inputs that don't engage
//! the (unported) pre-block splitter.

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

/// Assert byte-identical output vs the C oracle, and that the result decodes
/// back to the input through our own (independently C-verified) decoder.
fn assert_bit_exact(data: &[u8], level: i32, label: &str) {
    let theirs = zstd::bulk::compress(data, level)
        .unwrap_or_else(|e| panic!("oracle failed on {label} at level {level}: {e}"));
    let ours = libzstd_bitexact::compress(data, level)
        .unwrap_or_else(|e| panic!("we failed on {label} at level {level}: {e}"));
    if ours != theirs {
        // Find the first divergence for a useful failure message.
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
    let back = libzstd_bitexact::decompress(&ours).expect("our frame must decode");
    assert_eq!(back, data, "{label}: round-trip mismatch");
}

const FAST_LEVELS: [i32; 4] = [1, 2, -1, -3];

#[test]
fn empty_and_tiny_inputs_are_bit_exact() {
    for level in FAST_LEVELS {
        assert_bit_exact(b"", level, "empty");
        assert_bit_exact(b"a", level, "one byte");
        assert_bit_exact(b"abcdef", level, "six bytes");
        assert_bit_exact(b"abcdefg", level, "seven bytes");
        assert_bit_exact(b"abcdefgh", level, "eight bytes");
        assert_bit_exact(b"hello world hello world", level, "short repeat");
    }
}

#[test]
fn text_like_inputs_are_bit_exact() {
    for &len in &[
        100usize, 999, 4096, 16384, 16385, 65535, 65536, 100_000, 131_072,
    ] {
        let data = word_salad(0xD1FF ^ len as u64, len);
        for level in FAST_LEVELS {
            assert_bit_exact(&data, level, &format!("text-{len}"));
        }
    }
}

#[test]
fn run_heavy_inputs_are_bit_exact() {
    for &len in &[50usize, 1000, 30_000, 131_072] {
        let data = vec![0xAAu8; len];
        for level in FAST_LEVELS {
            assert_bit_exact(&data, level, &format!("all-same-{len}"));
        }
    }
    // Alternating runs and unique bytes: exercises RLE-literals + repcodes.
    let mut rng = Rng::new(0x0BAD_F00D);
    let mut runs = Vec::new();
    while runs.len() < 100_000 {
        if rng.below(2) == 0 {
            let b = (rng.next_u64() & 0xFF) as u8;
            runs.extend(std::iter::repeat_n(b, 1 + rng.below(300)));
        } else {
            let n = 1 + rng.below(40);
            let r = rng.bytes(n);
            runs.extend_from_slice(&r);
        }
    }
    runs.truncate(100_000);
    for level in FAST_LEVELS {
        assert_bit_exact(&runs, level, "mixed-runs");
    }
}

#[test]
fn incompressible_inputs_are_bit_exact_including_multiblock() {
    let mut rng = Rng::new(0x1C04);
    // Random data: raw blocks. Multi-block sizes keep savings < 3, so the
    // unported pre-splitter is never engaged.
    for &len in &[100usize, 4096, 131_072, 200_000, 400_000] {
        let data = rng.bytes(len);
        for level in FAST_LEVELS {
            // Level 2 resolves to dfast (not yet ported) in the
            // 128 KiB < srcSize <= 256 KiB class.
            if level == 2 && (131_072 + 1..=262_144).contains(&len) {
                assert!(matches!(
                    libzstd_bitexact::compress(&data, level),
                    Err(libzstd_bitexact::Error::Encode(_))
                ));
                continue;
            }
            assert_bit_exact(&data, level, &format!("random-{len}"));
        }
    }
}

#[test]
fn structured_binary_inputs_are_bit_exact() {
    // Record-like data: fixed-stride fields with shared prefixes — a typical
    // repcode-friendly shape.
    let mut data = Vec::new();
    let mut rng = Rng::new(0xBEEF);
    for i in 0u32..6000 {
        data.extend_from_slice(b"RECRD");
        data.extend_from_slice(&i.to_le_bytes());
        data.extend_from_slice(&(rng.next_u64() as u32 & 0xF).to_le_bytes());
        data.extend_from_slice(&[0u8; 4]);
    }
    for level in FAST_LEVELS {
        assert_bit_exact(&data, level, "records");
    }
}

#[test]
fn cycles_and_period_edges_are_bit_exact() {
    // Short periods stress the repcode fast path and backward extension.
    for &period in &[1usize, 2, 3, 4, 5, 7, 8, 16, 255] {
        let unit: Vec<u8> = (0..period).map(|i| (i * 37 + 11) as u8).collect();
        let mut data = Vec::with_capacity(70_000);
        while data.len() < 70_000 {
            data.extend_from_slice(&unit);
        }
        data.truncate(70_000);
        for level in FAST_LEVELS {
            assert_bit_exact(&data, level, &format!("period-{period}"));
        }
    }
}

#[test]
fn multiblock_compressible_inputs_are_bit_exact() {
    // Beyond 128 KiB with verified savings, block boundaries come from the
    // pre-block splitter (`ZSTD_splitBlock`) — boundary choices must match C
    // exactly for the frames to be identical.
    for &len in &[150_000usize, 300_000, 1_000_000] {
        let data = word_salad(0x5EED ^ len as u64, len);
        for level in [1, -1, -3] {
            assert_bit_exact(&data, level, &format!("text-multiblock-{len}"));
        }
    }
    // Content that *shifts* statistics mid-stream actually triggers splits.
    let mut shifting = Vec::new();
    let mut rng = Rng::new(0x517F);
    while shifting.len() < 700_000 {
        let kind = rng.below(3);
        let n = 30_000 + rng.below(150_000);
        match kind {
            0 => {
                let from = shifting.len();
                while shifting.len() < from + n {
                    shifting.extend_from_slice(b"steady prose section with words ");
                }
            }
            1 => {
                let b = (rng.next_u64() & 0xFF) as u8;
                shifting.extend(std::iter::repeat_n(b, n));
            }
            _ => {
                let r = rng.bytes(n);
                shifting.extend_from_slice(&r);
            }
        }
    }
    shifting.truncate(700_000);
    for level in [1, -1, -3] {
        assert_bit_exact(&shifting, level, "shifting-content");
    }
    // Level 2 beyond 256 KiB resolves to the fast strategy again.
    let big = word_salad(0xB16, 400_000);
    assert_bit_exact(&big, 2, "text-multiblock-level2-400k");

    // Literal-heavy: 6-bit random bytes yield few matches but Huffman-friendly
    // literals with stationary statistics — the habitat of treeless
    // (`set_repeat`) literals sections in later blocks.
    let mut rng = Rng::new(0x111E);
    let mut lit_heavy = Vec::with_capacity(500_000 + 8);
    while lit_heavy.len() < 500_000 {
        let r = rng.next_u64();
        for k in 0..8 {
            lit_heavy.push(((r >> (8 * k)) as u8) & 0x3F);
        }
    }
    lit_heavy.truncate(500_000);
    assert_bit_exact(&lit_heavy, 1, "literal-heavy-500k");
}

#[test]
fn unsupported_scope_errors_cleanly_instead_of_diverging() {
    // Levels resolving to unported strategies are explicit errors, never
    // silently different bytes.
    assert!(matches!(
        libzstd_bitexact::compress(b"hello", 3),
        Err(libzstd_bitexact::Error::Encode(_))
    ));
}
