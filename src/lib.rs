//! A pure-Rust reimplementation of [Zstandard](https://facebook.github.io/zstd/),
//! built to be **bit-exact** with the reference C implementation.
//!
//! Decompression is implemented today, including dictionaries (raw-content and
//! trained/`ZDICT`), a configurable `windowLogMax`, and a [`Read`]-based
//! [`StreamDecoder`] with a bounded sliding window. Every decoding table and
//! loop is a faithful port of its counterpart in the C sources, and the crate
//! is continuously differential-tested against the real libzstd. Bit-exact
//! compression is the project's larger goal — see `ROADMAP.md`.
//!
//! [`decompress`] and [`decompress_with_limit`] cover the common one-shot
//! cases; [`DecodeOptions`] composes an output limit, a maximum window log,
//! and a [`Dictionary`]; [`StreamDecoder`] decodes incrementally from any
//! reader.
//!
//! [`Read`]: std::io::Read
//!
//! ```
//! // A tiny handcrafted frame: single-segment, content size 5, one RLE
//! // block repeating `a` five times.
//! let frame = [0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x05, 0x2B, 0x00, 0x00, b'a'];
//! assert_eq!(libzstd_bitexact::decompress(&frame).unwrap(), b"aaaaa");
//! ```

#![forbid(unsafe_code)]

mod bits;
mod block;
mod decompress;
mod dictionary;
mod error;
mod frame;
mod fse;
mod fse_encode;
mod huffman;
mod huffman_encode;
mod literals_encode;
mod stream;
mod xxhash;

pub use decompress::{DecodeOptions, WINDOW_LOG_MAX, decompress, decompress_with_limit};
pub use dictionary::Dictionary;
pub use error::Error;
pub use stream::StreamDecoder;
