//! A pure-Rust reimplementation of [Zstandard](https://facebook.github.io/zstd/),
//! built to be **bit-exact** with the reference C implementation.
//!
//! Decompression is implemented today; every decoding table and loop is a
//! faithful port of its counterpart in the C sources, and the crate is
//! continuously differential-tested against the real libzstd. Bit-exact
//! compression is the project's larger goal — see `ROADMAP.md`.
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
mod error;
mod frame;
mod fse;
mod huffman;
mod xxhash;

pub use decompress::{decompress, decompress_with_limit};
pub use error::Error;
