//! Frame header parsing (`ZSTD_getFrameHeader`).

use crate::decompress::WINDOW_LOG_MAX;
use crate::error::Error;

pub(crate) struct FrameHeader {
    /// Declared decompressed size of the frame, when present.
    pub content_size: Option<u64>,
    /// Window size; equal to the content size for single-segment frames.
    pub window_size: u64,
    /// Dictionary ID, 0 when absent.
    pub dict_id: u32,
    pub has_checksum: bool,
    /// Header length in bytes, not counting the 4-byte magic.
    pub header_len: usize,
}

/// Parse a frame header. `src` starts immediately after the magic number.
///
/// `window_log_max` is the largest window log to accept (`ZSTD_d_windowLogMax`);
/// it is clamped to [`WINDOW_LOG_MAX`], the hard format limit, so a larger
/// value never accepts an invalid window.
pub(crate) fn parse(src: &[u8], window_log_max: u32) -> Result<FrameHeader, Error> {
    let max_log = u64::from(window_log_max.min(WINDOW_LOG_MAX));
    let descriptor = *src.first().ok_or(Error::SrcSizeWrong)?;
    let dict_id_flag = (descriptor & 3) as usize;
    let has_checksum = descriptor & 0x04 != 0;
    if descriptor & 0x08 != 0 {
        return Err(Error::FrameHeaderInvalid("reserved descriptor bit set"));
    }
    let single_segment = descriptor & 0x20 != 0;
    let fcs_flag = (descriptor >> 6) as usize;
    let mut pos = 1usize;

    let mut window_size = 0u64;
    if !single_segment {
        let wd = u64::from(*src.get(pos).ok_or(Error::SrcSizeWrong)?);
        pos += 1;
        let exponent = wd >> 3;
        let mantissa = wd & 7;
        if 10 + exponent > max_log {
            return Err(Error::WindowTooLarge);
        }
        let base = 1u64 << (10 + exponent);
        window_size = base + (base >> 3) * mantissa;
    }

    let dict_id_len = [0usize, 1, 2, 4][dict_id_flag];
    let dict_id = read_le(src, &mut pos, dict_id_len)? as u32;

    let fcs_len = if single_segment {
        [1usize, 2, 4, 8][fcs_flag]
    } else {
        [0usize, 2, 4, 8][fcs_flag]
    };
    let content_size = if fcs_len == 0 {
        None
    } else {
        let raw = read_le(src, &mut pos, fcs_len)?;
        // The 2-byte field is biased by 256 (sizes 0..=255 use 1 byte or none).
        Some(if fcs_len == 2 { raw + 256 } else { raw })
    };

    if single_segment {
        // No window descriptor: the whole frame is one segment and the
        // window is the content size itself, still subject to the window
        // limit (`windowSize > maxWindowSize` in `ZSTD_decompressFrame`).
        window_size = content_size.expect("single-segment frames always carry a content size");
        if window_size > 1u64 << max_log {
            return Err(Error::WindowTooLarge);
        }
    }

    Ok(FrameHeader {
        content_size,
        window_size,
        dict_id,
        has_checksum,
        header_len: pos,
    })
}

fn read_le(src: &[u8], pos: &mut usize, n: usize) -> Result<u64, Error> {
    let bytes = src.get(*pos..*pos + n).ok_or(Error::SrcSizeWrong)?;
    *pos += n;
    let mut v = 0u64;
    for (i, &b) in bytes.iter().enumerate() {
        v |= u64::from(b) << (8 * i);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_segment_with_one_byte_fcs() {
        // Descriptor 0x20: single segment, FCS flag 0 -> 1-byte content size.
        let h = parse(&[0x20, 0x05], WINDOW_LOG_MAX).unwrap();
        assert_eq!(h.content_size, Some(5));
        assert_eq!(h.window_size, 5);
        assert_eq!(h.dict_id, 0);
        assert!(!h.has_checksum);
        assert_eq!(h.header_len, 2);
    }

    #[test]
    fn windowed_with_checksum() {
        // Descriptor 0x04: checksum, window descriptor follows.
        // Window byte 0x08: exponent 1, mantissa 0 -> 2 KiB.
        let h = parse(&[0x04, 0x08], WINDOW_LOG_MAX).unwrap();
        assert_eq!(h.content_size, None);
        assert_eq!(h.window_size, 2048);
        assert!(h.has_checksum);
        assert_eq!(h.header_len, 2);
    }

    #[test]
    fn two_byte_fcs_is_biased() {
        // Descriptor 0x60: single segment + FCS flag 1 -> 2-byte FCS + 256.
        let h = parse(&[0x60, 0x00, 0x01], WINDOW_LOG_MAX).unwrap();
        assert_eq!(h.content_size, Some(256 + 256));
    }

    #[test]
    fn rejects_reserved_bit() {
        assert!(matches!(
            parse(&[0x08, 0x00], WINDOW_LOG_MAX),
            Err(Error::FrameHeaderInvalid(_))
        ));
    }

    #[test]
    fn window_log_max_bounds_the_window_descriptor() {
        // Window byte 0x90: exponent 18 -> window log 28.
        assert!(parse(&[0x00, 0x90], 28).is_ok());
        assert!(matches!(
            parse(&[0x00, 0x90], 27),
            Err(Error::WindowTooLarge)
        ));
        // Values above the format maximum are clamped, never widened.
        assert!(matches!(
            parse(&[0x00, 0xF8], 60),
            Err(Error::WindowTooLarge)
        ));
    }
}
