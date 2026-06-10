//! Error-code parity audit. For malformed input, our accept/reject decision
//! must match the C oracle's, and when both accept they must produce identical
//! bytes. This complements the random-corruption probes with two things:
//!
//! * a *systematic* single-byte-flip sweep over real frames — at every byte
//!   position and every bit, we and C must agree (both reject, or both accept
//!   with identical output); and
//! * *targeted* cases that pin each `ZSTD_ErrorCode` class to the specific
//!   [`Error`] variant we report, documenting the mapping.

use libzstd_bitexact::{DecodeOptions, Dictionary, Error};
use std::io::Write;

const CAP: usize = 64 << 20;

fn our_decode(frame: &[u8]) -> Result<Vec<u8>, Error> {
    libzstd_bitexact::decompress_with_limit(frame, CAP)
}

fn c_decode(frame: &[u8]) -> Result<Vec<u8>, String> {
    zstd::bulk::decompress(frame, CAP).map_err(|e| e.to_string())
}

/// Assert our outcome agrees with C's: both reject, or both accept the same
/// bytes. A one-sided accept (or two different accepted outputs) is a parity
/// bug — exactly what the audit is meant to surface.
fn assert_parity(frame: &[u8], context: &str) {
    match (our_decode(frame), c_decode(frame)) {
        (Ok(ours), Ok(theirs)) => {
            assert_eq!(ours, theirs, "{context}: both accepted but outputs differ");
        }
        (Err(_), Err(_)) => {}
        (ours, theirs) => panic!(
            "{context}: accept/reject mismatch — ours_ok={}, theirs_ok={}",
            ours.is_ok(),
            theirs.is_ok()
        ),
    }
}

fn sample(name: &str) -> Vec<u8> {
    match name {
        "text" => b"the quick brown fox jumps over the lazy dog. ".repeat(64),
        "runs" => {
            let mut v = vec![0u8; 800];
            v.extend(std::iter::repeat_n(0x41u8, 600));
            v.extend((0..400u32).map(|i| (i % 7) as u8));
            v
        }
        _ => unreachable!(),
    }
}

/// The heart of the audit: flip every bit of every byte of a real frame and
/// require parity with C on each mutation.
#[test]
fn single_byte_flips_preserve_parity() {
    let mut frames: Vec<(String, Vec<u8>)> = Vec::new();
    for name in ["text", "runs"] {
        let data = sample(name);
        for level in [1, 3, 19] {
            frames.push((
                format!("{name}-bulk-L{level}"),
                zstd::bulk::compress(&data, level).unwrap(),
            ));
        }
        // A frame carrying a content checksum, to exercise checksum_wrong.
        let mut enc = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
        enc.include_checksum(true).unwrap();
        enc.write_all(&data).unwrap();
        frames.push((format!("{name}-checksummed"), enc.finish().unwrap()));
    }

    for (label, frame) in &frames {
        for pos in 0..frame.len() {
            for bit in 0..8u32 {
                let mut m = frame.clone();
                m[pos] ^= 1 << bit;
                assert_parity(&m, &format!("{label} flip @{pos} bit {bit}"));
            }
        }
    }
}

/// Truncating a valid frame at any length must be rejected by both decoders.
#[test]
fn truncation_parity() {
    let data = sample("text");
    let frame = zstd::bulk::compress(&data, 7).unwrap();
    // Length 0 is the legitimate empty-input case (both accept, empty output);
    // any non-empty prefix of a real frame is incomplete and must be rejected.
    assert_parity(&frame[..0], "empty input");
    for len in 1..frame.len() {
        assert_parity(&frame[..len], &format!("truncated to {len}"));
        assert!(
            our_decode(&frame[..len]).is_err(),
            "accepted truncation to {len}"
        );
    }
}

#[test]
fn unknown_magic_maps_to_unknown_magic() {
    let frame = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    assert!(matches!(our_decode(&frame), Err(Error::UnknownMagic(_))));
    assert!(c_decode(&frame).is_err());
}

#[test]
fn reserved_descriptor_bit_maps_to_frame_header_invalid() {
    // Descriptor 0x08 sets the reserved bit.
    let frame = [0x28, 0xB5, 0x2F, 0xFD, 0x08, 0x00, 0x00, 0x00, 0x00];
    assert!(matches!(
        our_decode(&frame),
        Err(Error::FrameHeaderInvalid(_))
    ));
    assert!(c_decode(&frame).is_err());
}

#[test]
fn oversized_window_maps_to_window_too_large() {
    // Window byte 0xC8: exponent 25 -> window log 35, past the format maximum.
    let frame = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0xC8, 0x01, 0x00, 0x00];
    assert!(matches!(our_decode(&frame), Err(Error::WindowTooLarge)));
    assert!(c_decode(&frame).is_err());
}

#[test]
fn reserved_block_type_maps_to_block_type_invalid() {
    // Single-segment header (content size 5), then a block header with the
    // reserved type 3: byte0 = (size<<3) | (3<<1) | last = 0x07.
    let frame = [0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x05, 0x07, 0x00, 0x00];
    assert!(matches!(our_decode(&frame), Err(Error::BlockTypeInvalid)));
    assert!(c_decode(&frame).is_err());
}

#[test]
fn content_size_mismatch_is_detected() {
    // A small single-segment frame declares its content size in one byte at
    // index 5; bumping it makes the declared size disagree with the regen.
    let data = b"abcdefghij".to_vec(); // 10 bytes, <= 255 -> 1-byte FCS
    let mut frame = zstd::bulk::compress(&data, 1).unwrap();
    assert_eq!(frame[4] & 0x20, 0x20, "expected a single-segment frame");
    frame[5] = frame[5].wrapping_add(1); // declare one byte too many
    assert!(matches!(
        our_decode(&frame),
        Err(Error::FrameContentSizeMismatch)
    ));
    assert!(c_decode(&frame).is_err());
}

#[test]
fn checksum_mismatch_is_detected() {
    let data = sample("text");
    let mut enc = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
    enc.include_checksum(true).unwrap();
    enc.write_all(&data).unwrap();
    let mut frame = enc.finish().unwrap();
    let last = frame.len() - 1;
    frame[last] ^= 0xFF;
    assert!(matches!(
        our_decode(&frame),
        Err(Error::ChecksumMismatch { .. })
    ));
    assert!(c_decode(&frame).is_err());
}

#[test]
fn dictionary_required_and_wrong_are_distinguished() {
    // Build two trained dictionaries with distinct IDs.
    fn train(seed: u64) -> Vec<u8> {
        let words: &[&[u8]] = &[b"alpha", b"bravo", b"charlie", b"delta", b"echo"];
        let mut x = seed | 1;
        let mut rnd = || {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33) as usize
        };
        let mut samples = Vec::new();
        let mut sizes = Vec::new();
        for _ in 0..3000 {
            let mut s = Vec::new();
            for _ in 0..(8 + rnd() % 16) {
                s.extend_from_slice(words[rnd() % words.len()]);
                s.push(b' ');
            }
            sizes.push(s.len());
            samples.extend_from_slice(&s);
        }
        zstd::dict::from_continuous(&samples, &sizes, 16 * 1024).unwrap()
    }

    let dict_a = train(0xA1);
    let dict_b = train(0xB2);
    let da = Dictionary::new(&dict_a).unwrap();
    let db = Dictionary::new(&dict_b).unwrap();
    assert_ne!(da.id(), db.id());

    let data = b"alpha bravo charlie delta echo ".repeat(40);
    let frame = {
        let mut c = zstd::bulk::Compressor::with_dictionary(3, &dict_a).unwrap();
        c.compress(&data).unwrap()
    };

    // No dictionary: required. Wrong dictionary: wrong. Both rejected by C too.
    assert!(matches!(
        DecodeOptions::new().decompress(&frame),
        Err(Error::DictionaryRequired(id)) if id == da.id()
    ));
    assert!(matches!(
        DecodeOptions::new().dictionary(&db).decompress(&frame),
        Err(Error::DictionaryWrong { .. })
    ));
    assert!(c_decode(&frame).is_err(), "C should need the dictionary");

    // A malformed formatted dictionary is reported as corrupted.
    let mut broken = dict_a.clone();
    broken.truncate(20);
    assert!(matches!(
        Dictionary::new(&broken),
        Err(Error::DictionaryCorrupted)
    ));
}
