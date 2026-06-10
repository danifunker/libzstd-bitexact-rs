//! Differential tests for dictionary decompression and the `windowLogMax`
//! parameter. The C libzstd (via the `zstd` crate) is the oracle: anything it
//! compresses with a dictionary, we must decompress to identical bytes, and
//! our accept/reject decisions for oversized windows must match its own.

use libzstd_bitexact::{DecodeOptions, Dictionary, Error};
use std::io::Write;
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

/// A raw-content dictionary: plausible window history made of the same words
/// the payloads use, so the compressor actually emits matches into it.
fn raw_dict_content() -> Vec<u8> {
    let mut rng = Rng::new(0xD1C7_0001);
    let mut d = Vec::with_capacity(8192);
    while d.len() < 8192 {
        d.extend_from_slice(WORDS[rng.below(WORDS.len())]);
        d.push(b' ');
    }
    d
}

/// Train a real ZDICT-format dictionary from many small samples.
fn trained_dict(seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
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

/// Payloads of assorted sizes, drawn from the same vocabulary so dictionary
/// references are exercised.
fn payloads() -> Vec<Vec<u8>> {
    let mut rng = Rng::new(0x9A7E_F00D);
    let mut out = vec![Vec::new(), b"alpha bravo charlie".to_vec()];
    for &len in &[64usize, 500, 4096, 60_000] {
        let mut p = Vec::with_capacity(len);
        while p.len() < len {
            p.extend_from_slice(WORDS[rng.below(WORDS.len())]);
            p.push(b' ');
        }
        p.truncate(len);
        out.push(p);
    }
    out
}

fn c_compress_with_dict(data: &[u8], dict: &[u8], level: i32) -> Vec<u8> {
    let mut c = zstd::bulk::Compressor::with_dictionary(level, dict).unwrap();
    c.compress(data).unwrap()
}

#[test]
fn raw_content_dictionary_round_trip() {
    let dict_bytes = raw_dict_content();
    let dict = Dictionary::new(&dict_bytes).unwrap();
    assert_eq!(dict.id(), 0, "raw-content dictionaries carry no ID");

    for level in [1, 3, 9, 19] {
        for data in payloads() {
            let comp = c_compress_with_dict(&data, &dict_bytes, level);
            let out = DecodeOptions::new()
                .dictionary(&dict)
                .decompress(&comp)
                .unwrap_or_else(|e| panic!("raw dict level {level}, {} bytes: {e}", data.len()));
            assert_eq!(out, data, "raw dict mismatch at level {level}");
        }
    }
}

#[test]
fn trained_dictionary_round_trip() {
    let dict_bytes = trained_dict(0x7DC7_BA01);
    let dict = Dictionary::new(&dict_bytes).unwrap();
    assert_ne!(dict.id(), 0, "a trained dictionary declares a non-zero ID");

    for level in [1, 3, 9, 19] {
        for data in payloads() {
            let comp = c_compress_with_dict(&data, &dict_bytes, level);
            let out = DecodeOptions::new()
                .dictionary(&dict)
                .decompress(&comp)
                .unwrap_or_else(|e| {
                    panic!("trained dict level {level}, {} bytes: {e}", data.len())
                });
            assert_eq!(out, data, "trained dict mismatch at level {level}");
        }
    }
}

#[test]
fn multi_frame_with_dictionary() {
    let dict_bytes = trained_dict(0x37A4_30EC);
    let dict = Dictionary::new(&dict_bytes).unwrap();
    let a = payloads().swap_remove(4); // 4096 bytes
    let b = payloads().swap_remove(2); // 64 bytes

    let mut stream = c_compress_with_dict(&a, &dict_bytes, 6);
    stream.extend_from_slice(&c_compress_with_dict(&b, &dict_bytes, 19));

    let out = DecodeOptions::new()
        .dictionary(&dict)
        .decompress(&stream)
        .unwrap();
    let expected: Vec<u8> = a.iter().chain(b.iter()).copied().collect();
    assert_eq!(out, expected);
}

#[test]
fn wrong_dictionary_id_is_rejected() {
    let dict_a = trained_dict(0xAAAA_0001);
    let dict_b = trained_dict(0xBBBB_0002);
    let da = Dictionary::new(&dict_a).unwrap();
    let db = Dictionary::new(&dict_b).unwrap();
    assert_ne!(da.id(), db.id(), "the two trainings must differ in ID");

    let data = payloads().swap_remove(3); // 500 bytes
    let comp = c_compress_with_dict(&data, &dict_a, 3);

    // Right dictionary: ok. Wrong ID: DictionaryWrong. No dictionary at all:
    // DictionaryRequired (the frame names a non-zero ID).
    assert_eq!(
        DecodeOptions::new()
            .dictionary(&da)
            .decompress(&comp)
            .unwrap(),
        data
    );
    assert!(matches!(
        DecodeOptions::new().dictionary(&db).decompress(&comp),
        Err(Error::DictionaryWrong { expected, actual })
            if expected == da.id() && actual == db.id()
    ));
    assert!(matches!(
        DecodeOptions::new().decompress(&comp),
        Err(Error::DictionaryRequired(id)) if id == da.id()
    ));
}

/// Decoding a raw-content-dictionary frame *without* the dictionary must agree
/// with the C oracle decoding it the same way — both reject, or both produce
/// identical (wrong) bytes. Never a silent divergence.
#[test]
fn missing_raw_dictionary_matches_oracle() {
    let dict_bytes = raw_dict_content();
    for data in payloads() {
        let comp = c_compress_with_dict(&data, &dict_bytes, 9);
        let ours = DecodeOptions::new().limit(1 << 20).decompress(&comp);
        let theirs = zstd::bulk::decompress(&comp, 1 << 20);
        match (&ours, &theirs) {
            (Ok(o), Ok(t)) => assert_eq!(o, t, "divergent dict-less decode"),
            (Err(_), Err(_)) => {}
            (o, t) => panic!("accept/reject mismatch without dict: ours={o:?} theirs={t:?}"),
        }
    }
}

#[test]
fn corrupted_dictionary_input_never_panics() {
    let dict_bytes = trained_dict(0xC0FF_EE01);
    let dict = Dictionary::new(&dict_bytes).unwrap();
    let data = payloads().swap_remove(4);
    let compressed = c_compress_with_dict(&data, &dict_bytes, 6);

    let mut rng = Rng::new(0xBADD_1C70);
    for _ in 0..3000 {
        let mut copy = compressed.clone();
        let flips = 1 + rng.below(4);
        for _ in 0..flips {
            let at = rng.below(copy.len());
            copy[at] ^= 1 << rng.below(8);
        }
        // Must terminate cleanly with either outcome; the frame has no checksum.
        let _ = DecodeOptions::new()
            .dictionary(&dict)
            .limit(16 << 20)
            .decompress(&copy);
    }

    // A dictionary buffer that claims the ZDICT magic but is truncated must be
    // a clean error, not a panic.
    let mut bad = dict_bytes.clone();
    bad.truncate(16);
    assert!(matches!(
        Dictionary::new(&bad),
        Err(Error::DictionaryCorrupted)
    ));
}

/// Read the window log out of a windowed (non-single-segment) frame header.
fn window_log_of(frame: &[u8]) -> u32 {
    assert_eq!(frame[4] & 0x20, 0, "expected a windowed frame");
    10 + (frame[5] >> 3) as u32
}

/// Produce a windowed frame with (approximately) the requested window log.
fn encode_with_window_log(data: &[u8], window_log: u32) -> Vec<u8> {
    let mut enc = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
    enc.set_parameter(CParameter::WindowLog(window_log))
        .unwrap();
    enc.set_parameter(CParameter::ContentSizeFlag(false))
        .unwrap();
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// Decode through the C *streaming* API, which (unlike the one-shot
/// `ZSTD_decompressDCtx` behind `bulk::Decompressor`) honors the
/// `ZSTD_d_windowLogMax` parameter and rejects frames whose window exceeds it.
fn c_decompress_window_log_max(frame: &[u8], wlm: u32) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut dec = zstd::stream::read::Decoder::new(frame).map_err(|e| e.to_string())?;
    dec.window_log_max(wlm).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    dec.read_to_end(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

#[test]
fn window_log_max_matches_oracle() {
    let mut rng = Rng::new(0x5EED_0F00);
    let mut data = Vec::with_capacity(200_000);
    while data.len() < 200_000 {
        data.extend_from_slice(WORDS[rng.below(WORDS.len())]);
        data.push(b' ');
    }

    for target in [17u32, 19, 21, 23] {
        let frame = encode_with_window_log(&data, target);
        let actual = window_log_of(&frame);

        for delta in [-2i32, -1, 0, 1] {
            let max = actual as i32 + delta;
            if max < 10 {
                continue; // below the format's minimum window log
            }
            let max = max as u32;
            let ours = DecodeOptions::new().window_log_max(max).decompress(&frame);
            let theirs = c_decompress_window_log_max(&frame, max);

            assert_eq!(
                ours.is_ok(),
                theirs.is_ok(),
                "windowLogMax {max} (frame log {actual}): ours_ok={}, theirs_ok={}",
                ours.is_ok(),
                theirs.is_ok()
            );
            if let Ok(out) = ours {
                assert_eq!(out, data, "data mismatch at windowLogMax {max}");
            } else {
                assert!(matches!(ours, Err(Error::WindowTooLarge)));
            }
        }
    }
}
