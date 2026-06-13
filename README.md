# libzstd-bitexact-rs

A pure-Rust reimplementation of [Zstandard](https://github.com/facebook/zstd),
built to be **bit-exact** with the reference C implementation.

Most Rust compression ports settle for "produces valid output". This project
holds itself to a stricter standard: for any input, behavior indistinguishable
from C libzstd — identical decompressed bytes, matching accept/reject
decisions on malformed data, and identical *compressed* bytes at **every
compression level** (pinned to the zstd version bundled by `zstd-sys`,
currently 1.5.7). Bit-exactness is enforced mechanically, by
differential-testing every code path against the real libzstd, not by review.

## Status

| Area | State |
|---|---|
| Decompression (frames, raw/RLE/compressed blocks) | ✅ implemented |
| FSE, Huffman (1- and 4-stream), sequences, repeat offsets | ✅ implemented |
| Content checksums (XXH64), skippable frames, multi-frame input | ✅ implemented |
| Dictionaries (raw-content and trained/ZDICT) | ✅ implemented |
| `windowLogMax` enforcement | ✅ implemented |
| Streaming decompression (`Read`-based, bounded sliding window) | ✅ implemented |
| Differential harness, error-parity audit, `cargo-fuzz` targets | ✅ in CI |
| **Compression, bit-exact with C — every level (1–22 and negatives)** | ✅ byte-identical, differential-tested |
| Streaming compression (`ZSTD_compressStream2` flush/end parity) | ✅ byte-identical; unlimited length at every level¹ |
| Dictionary compression, multithreaded mode | ⬜ planned — see [ROADMAP.md](ROADMAP.md) |

¹ Streams longer than `windowSize + blockSize` turn the C window into an
*extDict*; the extDict match finders are ported for all nine strategies, and
index overflow correction recycles the 32-bit index space past 3500 MiB, so
every level streams without any length limit. The one carve-out:
configurations where C auto-enables long-distance matching (`strategy >=
btopt && windowLog >= 27` — level 22 at unknown or > 64 MiB content sizes)
return a clean error instead of diverging; LDM is ported but not yet
bit-exact on large inputs.

## Usage

```rust
let data = libzstd_bitexact::decompress(&compressed_bytes)?;

// On untrusted input, cap the output size to defuse decompression bombs:
let data = libzstd_bitexact::decompress_with_limit(&compressed_bytes, 64 << 20)?;

// Dictionaries, output limits, and a maximum window log compose through the
// DecodeOptions builder:
use libzstd_bitexact::{DecodeOptions, Dictionary};
let dict = Dictionary::new(&dictionary_bytes)?;
let data = DecodeOptions::new()
    .dictionary(&dict)
    .limit(64 << 20)
    .window_log_max(27)
    .decompress(&compressed_bytes)?;

// Streaming: wrap any Read source; memory stays bounded by the frame's
// window rather than its content.
use std::io::Read;
use libzstd_bitexact::StreamDecoder;
let mut out = Vec::new();
StreamDecoder::new(compressed_reader).read_to_end(&mut out)?;

// Compression: byte-identical to ZSTD_compress at every level (1-22,
// and negative levels for faster-than-1 modes).
let frame = libzstd_bitexact::compress(&data, 19)?;

// Streaming compression: byte-identical to ZSTD_compressStream2 for the
// same sequence of operations (continue/flush/end, pledged sizes,
// checksums). Note that without a pledged size, parameters resolve as
// "content size unknown", exactly as in C.
let mut enc = libzstd_bitexact::StreamEncoder::new(3);
let mut frame = Vec::new();
enc.compress(&data, &mut frame)?;
enc.flush(&mut frame)?;
enc.finish(b"", &mut frame)?;
```

## Design principles

- **The C implementation is the specification.** Where RFC 8878 and the zstd
  sources allow latitude, this crate does what `lib/decompress` does. Every
  table-construction routine is a line-by-line port of its C counterpart
  (`FSE_buildDTable`'s spread step, `HUF_readDTableX1`'s rank fill, …), with
  the C function named in the comments.
- **Differential testing as ground truth.** The test suite compresses a
  spread of datasets with the real libzstd (via the `zstd` crate's C
  bindings) at levels 1–22, in bulk and streaming modes, with and without
  checksums and dictionaries (raw-content and trained), and requires
  byte-identical round-trips. The streaming decoder is fed the same frames
  at chunk sizes from one byte up, and must reproduce identical output
  regardless of how the input is split. The `windowLogMax` knob is checked
  for accept/reject parity against C's streaming decoder. Random-input probes
  assert we never accept data the C decoder rejects.
- **No `unsafe`, no dependencies.** The library is `#![forbid(unsafe_code)]`
  and dependency-free; the C oracle appears only as a dev-dependency.
- **Correctness first, speed second.** Optimizations come only after parity
  is locked in by tests.

## Testing

```sh
cargo test            # unit + handcrafted vectors + differential suite
cargo test --release  # same, optimized (used in CI)
```

The differential suite (`tests/differential.rs`) needs to build the bundled C
libzstd, so a C compiler is required for development — but not to use the
crate.

There are also `cargo-fuzz` targets under `fuzz/` that compare against the C
decoder — `decode_never_panic` (arbitrary input must never panic or run away
on memory) and `decode_equivalence` (anything we accept, C must accept and
decode identically):

```sh
cargo +nightly fuzz run decode_equivalence
```

Both properties also run deterministically over a generated corpus in
`tests/fuzz_smoke.rs`, so plain `cargo test` exercises them without a nightly
toolchain.

## License

[BSD 3-Clause](LICENSE), matching upstream zstd. This is an independent
reimplementation; it is not affiliated with or endorsed by Meta.
