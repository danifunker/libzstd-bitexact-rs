//! Bitstream readers.
//!
//! Zstandard uses two kinds of bitstreams:
//!
//! * a **forward** little-endian bitstream for FSE table descriptions
//!   (`FSE_readNCount` in the C sources), consumed least-significant bit
//!   first, starting at the first byte;
//! * a **backward** bitstream for FSE/Huffman-coded payloads (`BIT_DStream_t`
//!   in the C sources): bits are written least-significant-bit first, the
//!   last byte carries a final `1` padding bit marking the end, and the
//!   decoder consumes bits starting from just below that padding bit, moving
//!   toward the beginning of the buffer.

use crate::error::Error;

#[inline]
pub(crate) fn mask64(n: u32) -> u64 {
    if n >= 64 { u64::MAX } else { (1u64 << n) - 1 }
}

/// Forward little-endian bit reader used for FSE table headers.
///
/// Reads past the end of the buffer yield zero bits, mirroring the zero-padded
/// scratch buffer the C implementation uses for short inputs; callers must
/// validate `bits_consumed()` against the real input length afterwards, which
/// is exactly what `FSE_readNCount` does.
pub(crate) struct ForwardBitReader<'a> {
    data: &'a [u8],
    bit_pos: usize,
}

impl<'a> ForwardBitReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, bit_pos: 0 }
    }

    /// Peek at the next `n` bits (`n <= 32`) without consuming them.
    pub(crate) fn peek(&self, n: u32) -> u32 {
        debug_assert!(n <= 32);
        if n == 0 {
            return 0;
        }
        let byte = self.bit_pos / 8;
        let shift = self.bit_pos % 8;
        let mut buf = [0u8; 8];
        if byte < self.data.len() {
            let take = (self.data.len() - byte).min(8);
            buf[..take].copy_from_slice(&self.data[byte..byte + take]);
        }
        ((u64::from_le_bytes(buf) >> shift) & mask64(n)) as u32
    }

    pub(crate) fn consume(&mut self, n: u32) {
        self.bit_pos += n as usize;
    }

    pub(crate) fn read(&mut self, n: u32) -> u32 {
        let v = self.peek(n);
        self.consume(n);
        v
    }

    pub(crate) fn bits_consumed(&self) -> usize {
        self.bit_pos
    }
}

/// Backward bit reader used for FSE and Huffman payload streams.
///
/// `bits_remaining` may go negative: that corresponds to the
/// `BIT_DStream_overflow` state in the C implementation (an attempt to read
/// more bits than the stream holds). Reads that cross the start of the stream
/// return the available bits in their correct (top) positions with the
/// missing low bits as zero; on valid streams such reads only ever happen
/// where the C decoder also stops using the affected value.
pub(crate) struct ReverseBitReader<'a> {
    data: &'a [u8],
    bits_remaining: i64,
}

impl<'a> ReverseBitReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Result<Self, Error> {
        let last = *data.last().ok_or(Error::Corrupted("empty bitstream"))?;
        if last == 0 {
            return Err(Error::Corrupted("bitstream has no initialization bit"));
        }
        let padding = i64::from(last.leading_zeros()) + 1;
        Ok(Self {
            data,
            bits_remaining: data.len() as i64 * 8 - padding,
        })
    }

    pub(crate) fn bits_remaining(&self) -> i64 {
        self.bits_remaining
    }

    /// True when every payload bit has been consumed, exactly
    /// (`BIT_endOfDStream` in the C sources).
    pub(crate) fn finished_exactly(&self) -> bool {
        self.bits_remaining == 0
    }

    /// Peek at the next `n` bits (`n <= 56`) without consuming them.
    ///
    /// The next bits to be read are the highest-numbered remaining bits of
    /// the stream; they form the high bits of the returned value, matching
    /// `BIT_lookBits`.
    pub(crate) fn peek(&self, n: u32) -> u64 {
        debug_assert!(n <= 56);
        if n == 0 || self.bits_remaining <= 0 {
            return 0;
        }
        let avail = self.bits_remaining.min(i64::from(n)) as u32;
        let lowest_bit = (self.bits_remaining - i64::from(avail)) as usize;
        self.extract(lowest_bit, avail) << (n - avail)
    }

    pub(crate) fn consume(&mut self, n: u32) {
        self.bits_remaining -= i64::from(n);
    }

    pub(crate) fn read(&mut self, n: u32) -> u64 {
        let v = self.peek(n);
        self.consume(n);
        v
    }

    /// Extract bits `[from_bit, from_bit + n)` of the stream, where bit `i`
    /// is bit `i % 8` of byte `i / 8` (LSB-first across little-endian bytes).
    fn extract(&self, from_bit: usize, n: u32) -> u64 {
        let byte = from_bit / 8;
        let shift = from_bit % 8;
        let mut buf = [0u8; 8];
        let take = (self.data.len() - byte).min(8);
        buf[..take].copy_from_slice(&self.data[byte..byte + take]);
        (u64::from_le_bytes(buf) >> shift) & mask64(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_reader_reads_lsb_first() {
        // 0b1101_0110, 0b0000_0001
        let mut br = ForwardBitReader::new(&[0xD6, 0x01]);
        assert_eq!(br.read(3), 0b110);
        assert_eq!(br.read(5), 0b11010);
        assert_eq!(br.read(4), 0b0001);
        assert_eq!(br.bits_consumed(), 12);
        // Past the end: zeros.
        assert_eq!(br.read(8), 0);
    }

    #[test]
    fn reverse_reader_strips_padding_and_reads_backward() {
        // Stream written forward as: 5 bits 0b10001, then 3 bits 0b011, then
        // the padding bit. Byte 0 = 0b011_10001 = 0x71, byte 1 = 0b0000_0001.
        let mut br = ReverseBitReader::new(&[0x71, 0x01]).unwrap();
        assert_eq!(br.bits_remaining(), 8);
        assert_eq!(br.read(3), 0b011);
        assert_eq!(br.read(5), 0b10001);
        assert!(br.finished_exactly());
    }

    #[test]
    fn reverse_reader_zero_fills_past_start() {
        // Single byte 0b0000_0101: padding bit at position 2, payload = "01".
        let mut br = ReverseBitReader::new(&[0x05]).unwrap();
        assert_eq!(br.bits_remaining(), 2);
        // Peeking 4 bits with only 2 available: the two real bits land in the
        // top positions, missing bits are zero.
        assert_eq!(br.peek(4), 0b0100);
        br.consume(4);
        assert_eq!(br.bits_remaining(), -2);
        assert!(!br.finished_exactly());
    }

    #[test]
    fn reverse_reader_rejects_empty_and_zero_padding() {
        assert!(ReverseBitReader::new(&[]).is_err());
        assert!(ReverseBitReader::new(&[0x00]).is_err());
    }
}
