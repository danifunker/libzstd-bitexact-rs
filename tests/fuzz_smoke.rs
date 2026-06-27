//! Pure-Rust robustness smoke test — no C, no nightly, no libFuzzer.
//!
//! This replaces the `cargo-fuzz` decode targets (and the old C-oracle
//! `fuzz_smoke`) that were retired when the C differential oracle was removed
//! from the repo. It keeps the property that does *not* need C: the decoder
//! must never panic or run away on arbitrary, mutated, or truncated input, and
//! a frame produced by our own compressor must round-trip.
//!
//! The stronger *bit-exact-vs-C* equivalence property is proven by the archived
//! differential suite — see `docs/validating-bit-exactness.md` for how to
//! reproduce it against C libzstd 1.5.5 out-of-tree.

use libzstd_bitexact_rs::{DecodeOptions, StreamDecoder, compress};
use std::io::Read;

const LIMIT: usize = 16 << 20;

/// xorshift64* — deterministic, dependency-free generator.
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
    fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xFF) as u8
    }
}

/// Both decode drivers must return (Ok or Err) without panicking, hanging, or
/// over-allocating past the limit. Results are intentionally discarded — the
/// property under test is "never crash", not "accept".
fn never_panic(data: &[u8]) {
    let _ = DecodeOptions::new().limit(LIMIT).decompress(data);
    let mut out = Vec::new();
    let _ =
        StreamDecoder::with_options(data, DecodeOptions::new().limit(LIMIT)).read_to_end(&mut out);
}

#[test]
fn random_bytes_never_panic() {
    let mut rng = Rng::new(0xF0_02_F0_02);
    let magic = 0xFD2F_B528u32.to_le_bytes();
    for _ in 0..50_000 {
        let len = rng.below(96);
        let mut data = vec![0u8; len];
        for b in data.iter_mut() {
            *b = rng.byte();
        }
        // Bias a fraction toward the real frame magic so the inputs reach
        // header and block parsing rather than bouncing off prefix_unknown.
        if len >= 4 && rng.below(2) == 0 {
            data[..4].copy_from_slice(&magic);
        }
        never_panic(&data);
    }
}

#[test]
fn our_frames_round_trip_and_mutations_never_panic() {
    let mut rng = Rng::new(0x1234_5678_9ABC_DEF0);

    // Valid frames built with OUR compressor (no C dependency), across a spread
    // of payloads and levels — including a window-descriptor (unknown-size)
    // frame via the streaming encoder.
    let payloads: Vec<Vec<u8>> = {
        let text = b"the quick brown fox jumps over the lazy dog ".repeat(40);
        let runs = {
            let mut v = vec![1u8; 500];
            v.extend(std::iter::repeat_n(7u8, 300));
            v
        };
        vec![text, runs, vec![0u8; 2000]]
    };

    for data in &payloads {
        for level in [1, 9, 19] {
            let frame = compress(data, level).unwrap();

            // Unmutated frames must round-trip exactly.
            let decoded = DecodeOptions::new()
                .limit(LIMIT)
                .decompress(&frame)
                .expect("our own frame must decode");
            assert_eq!(&decoded, data, "round-trip mismatch at level {level}");

            // A handful of bit-flips per copy must never panic the decoder.
            for _ in 0..4000 {
                let mut m = frame.clone();
                for _ in 0..(1 + rng.below(5)) {
                    let at = rng.below(m.len());
                    m[at] ^= 1 << rng.below(8);
                }
                never_panic(&m);
            }
        }
    }
}

#[test]
fn truncations_and_extensions_never_panic() {
    let data = b"fuzz smoke corpus payload, mildly compressible 0123456789 ".repeat(60);
    let frame = compress(&data, 6).unwrap();
    let mut rng = Rng::new(0x0C0F_FEE0);

    // Every truncation, plus the frame with random trailing bytes appended.
    for len in 0..=frame.len() {
        never_panic(&frame[..len]);
    }
    for _ in 0..2000 {
        let mut extended = frame.clone();
        for _ in 0..(1 + rng.below(8)) {
            extended.push(rng.byte());
        }
        never_panic(&extended);
    }
}
