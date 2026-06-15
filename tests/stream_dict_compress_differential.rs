//! Streaming compression **with a dictionary** (`StreamEncoder::with_dictionary`):
//! byte-identical output to C libzstd 1.5.7's `ZSTD_compressStream2` after
//! `ZSTD_CCtx_loadDictionary` (what `zstd::stream::*::Encoder::with_dictionary`
//! does). Loading a dictionary into a streaming context builds an internal CDict
//! and **attaches** it (Path B, unknown content size), so this exercises the
//! dictMatchState match finders across *multiple* blocks (the one-shot
//! `tests/cdict_compress_differential.rs` only ever compresses a single block).
//!
//! Scope: the attach path within the window. A stream whose source outgrows the
//! window (where C drops the attached dict) returns a clean error — covered by
//! `large_dict_stream_errors_cleanly`.

use libzstd_bitexact_rs::{DecodeOptions, Dictionary, StreamEncoder};
use zstd::zstd_safe::{CCtx, CParameter, InBuffer, OutBuffer};

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
}

const WORDS: &[&[u8]] = &[
    b"alpha",
    b"bravo",
    b"charlie",
    b"delta",
    b"echo",
    b"foxtrot",
    b"golf",
    b"hotel",
    b"india",
    b"juliet",
    b"kilo",
    b"lima",
    b"mike",
    b"november",
];

fn word_salad(seed: u64, len: usize) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut d = Vec::with_capacity(len + 16);
    while d.len() < len {
        d.extend_from_slice(WORDS[rng.below(WORDS.len())]);
        d.push(b' ');
    }
    d.truncate(len);
    d
}

fn raw_dict() -> Vec<u8> {
    word_salad(0xD1C7_0001, 8192)
}

/// Train a real ZDICT-format dictionary (seeds the CDict entropy on Path B).
fn trained_dict() -> Vec<u8> {
    let mut rng = Rng::new(0x7DC7_BA01);
    let mut samples = Vec::new();
    let mut sizes = Vec::new();
    for _ in 0..3000 {
        let mut s = Vec::new();
        let n = 8 + rng.below(24);
        for _ in 0..n {
            s.extend_from_slice(WORDS[rng.below(WORDS.len())]);
            s.push(b' ');
        }
        sizes.push(s.len());
        samples.extend_from_slice(&s);
    }
    zstd::dict::from_continuous(&samples, &sizes, 16 * 1024).expect("dictionary training failed")
}

fn map_code(code: usize) -> std::io::Error {
    std::io::Error::other(zstd::zstd_safe::get_error_name(code))
}

/// Drive C `ZSTD_compressStream2` with a loaded dictionary over the chunk
/// schedule: each `chunks[i]` is fed with `ZSTD_e_continue`, then `finish` with
/// `ZSTD_e_end`.
fn oracle(level: i32, dict: &[u8], chunks: &[&[u8]], finish: &[u8]) -> Vec<u8> {
    use zstd_sys::ZSTD_EndDirective as Dir;
    let mut cctx = CCtx::create();
    cctx.set_parameter(CParameter::CompressionLevel(level))
        .unwrap();
    cctx.load_dictionary(dict).unwrap();

    let mut out = Vec::new();
    let mut scratch = vec![0u8; 256 * 1024];
    let mut step = |cctx: &mut CCtx, out: &mut Vec<u8>, inb: &mut InBuffer, dir: Dir| -> usize {
        let mut outb = OutBuffer::around(&mut scratch[..]);
        let hint = cctx
            .compress_stream2(&mut outb, inb, dir)
            .map_err(map_code)
            .unwrap();
        let produced = outb.pos();
        out.extend_from_slice(&scratch[..produced]);
        hint
    };

    for &data in chunks {
        let mut inb = InBuffer::around(data);
        loop {
            step(&mut cctx, &mut out, &mut inb, Dir::ZSTD_e_continue);
            if inb.pos >= data.len() {
                break;
            }
        }
    }
    let mut inb = InBuffer::around(finish);
    loop {
        let hint = step(&mut cctx, &mut out, &mut inb, Dir::ZSTD_e_end);
        if hint == 0 && inb.pos == finish.len() {
            break;
        }
    }
    out
}

/// Drive our `StreamEncoder` over the same schedule.
fn ours(level: i32, dict: &[u8], chunks: &[&[u8]], finish: &[u8]) -> Vec<u8> {
    let mut enc = StreamEncoder::with_dictionary(level, dict);
    let mut out = Vec::new();
    for &data in chunks {
        enc.compress(data, &mut out).unwrap();
    }
    enc.finish(finish, &mut out).unwrap();
    out
}

fn check(dict: &[u8]) {
    let dict_obj = Dictionary::new(dict).expect("dict parse");
    // ~12 KB of source, split into uneven chunks (so blocks straddle the chunk
    // boundaries), kept well within every level's window.
    let body = word_salad(0x5712_3456, 12_000);
    let schedules: &[(&[&[u8]], &[u8])] = &[
        (&[&body[..]], &[]),                                  // one push, empty finish
        (&[&body[..5000]], &body[5000..]),                    // push + finish carries input
        (&[&body[..3000], &body[3000..7000]], &body[7000..]), // two pushes + finish
        (
            &[&body[..1], &body[1..2000], &body[2000..2001]],
            &body[2001..],
        ), // tiny chunks
    ];

    for level in -3..=22 {
        for (chunks, finish) in schedules {
            let theirs = oracle(level, dict, chunks, finish);
            let mine = ours(level, dict, chunks, finish);
            assert_eq!(
                mine,
                theirs,
                "byte mismatch: level={level}, schedule chunks={}, finish={}",
                chunks.len(),
                finish.len()
            );
            let decoded = DecodeOptions::new()
                .dictionary(&dict_obj)
                .decompress(&mine)
                .unwrap_or_else(|e| panic!("decode failed: level={level}: {e}"));
            let mut expect = Vec::new();
            for &c in *chunks {
                expect.extend_from_slice(c);
            }
            expect.extend_from_slice(finish);
            assert_eq!(decoded, expect, "round-trip mismatch: level={level}");
        }
    }
}

#[test]
fn stream_dict_raw_is_bit_exact() {
    check(&raw_dict());
}

#[test]
fn stream_dict_trained_is_bit_exact() {
    check(&trained_dict());
}

#[test]
fn large_dict_stream_errors_cleanly() {
    // A source far larger than the window: C would drop the attached dictionary
    // (checkDictValidity); we don't port that yet, so we must error rather than
    // diverge. The bytes emitted before the error are still bit-exact.
    let dict = raw_dict();
    let big = word_salad(0xBEEF, 8 * 1024 * 1024);
    let mut enc = StreamEncoder::with_dictionary(1, &dict);
    let mut out = Vec::new();
    // Feed it in chunks until it (cleanly) refuses.
    let mut errored = false;
    for chunk in big.chunks(64 * 1024) {
        if enc.compress(chunk, &mut out).is_err() {
            errored = true;
            break;
        }
    }
    if !errored {
        errored = enc.finish(&[], &mut out).is_err();
    }
    assert!(
        errored,
        "a multi-megabyte dict stream must error cleanly, not diverge"
    );
}
