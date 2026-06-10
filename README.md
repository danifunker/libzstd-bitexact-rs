# libzstd-bitexact-rs

A pure-Rust reimplementation of [Zstandard](https://github.com/facebook/zstd),
built to be **bit-exact** with the reference C implementation.

Most Rust compression ports settle for "produces valid output". This project
holds itself to a stricter standard: for any input, the goal is behavior
indistinguishable from C libzstd — identical decompressed bytes, matching
accept/reject decisions on malformed data, and (the long-term goal) identical
*compressed* bytes for every compression level. Bit-exactness is enforced
mechanically, by differential-testing every code path against the real
libzstd, not by review.

## Status

| Area | State |
|---|---|
| Decompression (frames, raw/RLE/compressed blocks) | ✅ implemented |
| FSE, Huffman (1- and 4-stream), sequences, repeat offsets | ✅ implemented |
| Content checksums (XXH64), skippable frames, multi-frame input | ✅ implemented |
| Differential test harness vs. C libzstd | ✅ in CI |
| Streaming decompression API | ⬜ planned |
| Dictionaries | ⬜ planned |
| Compression (bit-exact with C, all levels) | ⬜ planned — see [ROADMAP.md](ROADMAP.md) |

## Usage

```rust
let data = libzstd_bitexact::decompress(&compressed_bytes)?;

// On untrusted input, cap the output size to defuse decompression bombs:
let data = libzstd_bitexact::decompress_with_limit(&compressed_bytes, 64 << 20)?;
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
  checksums, and requires byte-identical round-trips. Random-input probes
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

## License

[BSD 3-Clause](LICENSE), matching upstream zstd. This is an independent
reimplementation; it is not affiliated with or endorsed by Meta.
