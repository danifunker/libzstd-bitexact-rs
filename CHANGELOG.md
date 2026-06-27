# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The version number encodes the targeted upstream zstd release: this `0.155.x`
line is bit-exact with zstd **1.5.5** (the parallel `0.157.x` line targets
**1.5.7**), and the patch component counts this crate's own fixes against that
target.

## [Unreleased]

## [0.155.1]

Documentation and packaging only — the library is unchanged from 0.155.0 and
remains byte-identical to C libzstd 1.5.5.

- Removed the C-libzstd differential oracle (the `zstd` / `zstd-sys` dev-deps,
  the `*_differential.rs` suite, the throughput bench, and the `fuzz/` package)
  so the whole project builds and tests in **pure Rust with no C toolchain**.
  `Cargo.lock` now resolves to this crate alone.
- The bit-exactness proof is archived in git at tag `v0.155.0` and reproduced
  out-of-tree — see `docs/validating-bit-exactness.md`.
- Kept pure-Rust robustness coverage as `tests/fuzz_smoke.rs` (frames built with
  this crate's own compressor, then mutated/truncated to assert the decoder
  never panics).
- Corrected crate documentation that still claimed "1.5.7" output to "1.5.5".

## [0.155.0]

First release of the **zstd 1.5.5** line — byte-identical to C libzstd **1.5.5**.
Shares the (format-stable) decoder with the 1.5.7 line; the compressor is
retargeted to 1.5.5 by reverse-porting the 1.5.6/1.5.7 changes: dropped the 1.5.6
pre-block splitter, reverted the dfast `+1`-long selection and the dfast
`dictMatchState` else-if arms, reverted the optimal parser to the 1.5.5 sequence
DP and the LDM parameters to the 1.5.5 defaults, and restored 1.5.5's lenient
handling of reserved sequence-mode bits. Verified byte-identical to C libzstd
1.5.5 across all nine strategies, dictionaries, LDM, and ZSTDMT.

## [0.157.0]

First release. A pure-Rust, `#![forbid(unsafe_code)]`, zero-runtime-dependency
Zstandard implementation that is **byte-identical to C libzstd 1.5.7**, enforced
by differential testing against the real library on every code path.

### Decompression

- Frame parsing: headers, skippable frames, multi-frame input.
- Raw / RLE / compressed blocks; FSE and Huffman (1- and 4-stream) entropy
  decoding; sequence decoding with repeat-offset history.
- XXH64 content checksums.
- Dictionaries: raw-content and trained (`ZDICT`), with `dictID` validation and
  `extDict` matches across the dictionary/output seam.
- Configurable `windowLogMax` (accept/reject parity with C's streaming decoder)
  and an output-size limit to defuse decompression bombs.
- `Read`-based streaming decoder with a bounded sliding window.
- Error-code parity audit and `cargo-fuzz` targets (never-panic and
  decode-equivalence vs the C decoder), mirrored in a deterministic CI test.

### Compression (byte-identical to `ZSTD_compress`)

- Every level, 1–22 and the negative levels, across all nine strategies
  (`fast`, `dfast`, `greedy`, `lazy`, `lazy2`, `btlazy2`, `btopt`, `btultra`,
  `btultra2`), including the optimal parser and both block splitters.
- Streaming compression with `ZSTD_compressStream2` flush/end parity, pledged
  sizes, and content checksums; unlimited stream length (extDict match finders
  for all strategies plus index overflow correction).
- Long-distance matching (auto-enabled exactly as C does).
- Dictionary compression: raw and trained, both the `usingDict`/`extDict` path
  and the `CDict`/`dictMatchState` path (with the attach-vs-copy heuristic).
- Multithreaded (`ZSTDMT`) mode, reproduced single-threaded (C's output is
  worker-count-independent): one-shot and streaming, checksums, flush/pledged
  sizes, dictionaries, and cross-job LDM.

### Performance

- Throughput benchmark harness (`cargo bench`) comparing against the C oracle.
- Word-at-a-time match extension (compression) and a register-resident
  bit-reader plus two-pass sequence decoding (decompression).

[Unreleased]: https://github.com/danifunker/libzstd-bitexact-rs/compare/v0.155.1...HEAD
[0.155.1]: https://github.com/danifunker/libzstd-bitexact-rs/releases/tag/v0.155.1
[0.155.0]: https://github.com/danifunker/libzstd-bitexact-rs/releases/tag/v0.155.0
[0.157.0]: https://github.com/danifunker/libzstd-bitexact-rs/releases/tag/v0.157.0
