//! A pure-Rust reimplementation of [Zstandard](https://facebook.github.io/zstd/),
//! built to be **bit-exact** with the reference C implementation.
//!
//! Decompression is complete: dictionaries (raw-content and trained/`ZDICT`),
//! a configurable `windowLogMax`, and a [`Read`]-based [`StreamDecoder`] with
//! a bounded sliding window. [`compress`] produces frames **byte-identical to
//! C libzstd 1.5.7 at every level** (1–22 and the negative levels), and
//! [`StreamEncoder`] mirrors `ZSTD_compressStream2` flush/end behavior (see
//! its docs for the current streaming length scope). Every table and loop is
//! a faithful port of its counterpart in the C sources, and the crate is
//! continuously differential-tested against the real libzstd — see
//! `ROADMAP.md` for what remains.
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
mod compress;
mod decompress;
mod dictionary;
mod error;
mod frame;
mod fse;
mod fse_encode;
mod huffman;
mod huffman_encode;
mod lazy;
mod ldm;
mod literals_encode;
mod opt;
mod post_split;
mod pre_split;
mod sequences_encode;
mod stream;
mod stream_encode;
mod xxhash;

pub use compress::compress;
#[doc(hidden)]
pub use compress::cparams_for_testing;
pub use decompress::{DecodeOptions, WINDOW_LOG_MAX, decompress, decompress_with_limit};
pub use dictionary::Dictionary;
pub use error::Error;
pub use stream::StreamDecoder;
pub use stream_encode::StreamEncoder;
