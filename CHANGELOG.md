# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

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

[Unreleased]: https://github.com/danifunker/libzstd-bitexact-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/danifunker/libzstd-bitexact-rs/releases/tag/v0.1.0
