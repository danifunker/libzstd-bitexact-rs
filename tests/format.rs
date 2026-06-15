//! Handcrafted format vectors: byte-level frames built by hand from
//! RFC 8878, exercising paths and error cases independently of the oracle.

use libzstd_bitexact_rs::{Error, decompress, decompress_with_limit};

const MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Single-segment frame, 1-byte content size, one RLE block: "aaaaa".
#[test]
fn handcrafted_rle_frame() {
    // Block header (u24 LE): size 5 << 3 | type RLE (1) << 1 | last (1).
    let frame = [
        MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], 0x20,
        0x05, // descriptor: single segment; FCS = 5
        0x2B, 0x00, 0x00, // block header
        b'a',
    ];
    assert_eq!(decompress(&frame).unwrap(), b"aaaaa");
}

/// Windowed frame (no content size), one raw block.
#[test]
fn handcrafted_raw_frame() {
    let payload = b"raw block payload";
    let mut frame = Vec::new();
    frame.extend_from_slice(&MAGIC);
    frame.push(0x00); // descriptor: nothing set
    frame.push(0x00); // window descriptor: 1 KiB
    let header = ((payload.len() as u32) << 3) | 1; // raw type (0), last
    frame.extend_from_slice(&header.to_le_bytes()[..3]);
    frame.extend_from_slice(payload);
    assert_eq!(decompress(&frame).unwrap(), payload);
}

/// An empty frame: declared content size 0, one empty raw last block.
#[test]
fn handcrafted_empty_frame() {
    let frame = [
        MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], 0x20, 0x00, // single segment, FCS = 0
        0x01, 0x00, 0x00, // empty raw last block
    ];
    assert_eq!(decompress(&frame).unwrap(), b"");
}

#[test]
fn empty_input_is_empty_output() {
    // Matches ZSTD_decompress, which returns 0 for empty input.
    assert_eq!(decompress(&[]).unwrap(), b"");
}

#[test]
fn skippable_frame_alone() {
    let mut data = Vec::new();
    data.extend_from_slice(&0x184D_2A5Fu32.to_le_bytes()); // last skippable magic variant
    data.extend_from_slice(&3u32.to_le_bytes());
    data.extend_from_slice(b"xyz");
    assert_eq!(decompress(&data).unwrap(), b"");
}

#[test]
fn unknown_magic_is_rejected() {
    assert!(matches!(
        decompress(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00]),
        Err(Error::UnknownMagic(0xEFBE_ADDE))
    ));
}

#[test]
fn partial_magic_is_src_size_wrong() {
    assert!(matches!(decompress(&MAGIC[..3]), Err(Error::SrcSizeWrong)));
}

#[test]
fn reserved_block_type_is_rejected() {
    let frame = [
        MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], 0x20, 0x05, 0x07, 0x00,
        0x00, // type 3 (reserved), last
    ];
    assert!(matches!(decompress(&frame), Err(Error::BlockTypeInvalid)));
}

#[test]
fn reserved_descriptor_bit_is_rejected() {
    let frame = [MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], 0x08, 0x00];
    assert!(matches!(
        decompress(&frame),
        Err(Error::FrameHeaderInvalid(_))
    ));
}

#[test]
fn dictionary_frames_are_reported() {
    // Descriptor 0x01: 1-byte dictionary ID follows the window descriptor.
    let frame = [
        MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], 0x01, 0x00,
        0x07, // dict id flag, window, dict id = 7
        0x01, 0x00, 0x00, // empty raw last block
    ];
    assert!(matches!(
        decompress(&frame),
        Err(Error::DictionaryRequired(7))
    ));
}

#[test]
fn content_size_mismatch_is_rejected() {
    // Declares 9 bytes but regenerates 5.
    let frame = [
        MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], 0x20, 0x09, 0x2B, 0x00, 0x00, b'a',
    ];
    assert!(matches!(
        decompress(&frame),
        Err(Error::FrameContentSizeMismatch)
    ));
}

#[test]
fn rle_block_respects_output_limit() {
    // A 100 KiB RLE block decodes from ~10 bytes; the limit must stop it.
    let size: u32 = 100 * 1024;
    let mut frame = Vec::new();
    frame.extend_from_slice(&MAGIC);
    frame.push(0x00);
    frame.push(0x7F); // window descriptor: large enough window
    let header = (size << 3) | 0b011;
    frame.extend_from_slice(&header.to_le_bytes()[..3]);
    frame.push(b'z');
    assert!(matches!(
        decompress_with_limit(&frame, 4096),
        Err(Error::OutputTooLarge)
    ));
    assert_eq!(decompress(&frame).unwrap(), vec![b'z'; size as usize]);
}

#[test]
fn trailing_garbage_after_frame_is_rejected() {
    let mut frame = vec![
        MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], 0x20, 0x05, 0x2B, 0x00, 0x00, b'a',
    ];
    frame.extend_from_slice(&[1, 2, 3]);
    assert!(decompress(&frame).is_err());
}

/// Block size fields larger than the window's block limit are corruption.
#[test]
fn oversized_block_is_rejected() {
    // Window descriptor 0x00 -> 1 KiB window, so blocks are capped at 1 KiB.
    let payload = vec![0u8; 2048];
    let mut frame = Vec::new();
    frame.extend_from_slice(&MAGIC);
    frame.push(0x00);
    frame.push(0x00);
    let header = ((payload.len() as u32) << 3) | 1;
    frame.extend_from_slice(&header.to_le_bytes()[..3]);
    frame.extend_from_slice(&payload);
    assert!(matches!(decompress(&frame), Err(Error::Corrupted(_))));
}
