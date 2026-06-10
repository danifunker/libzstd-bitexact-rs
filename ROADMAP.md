# Roadmap

The destination: a drop-in pure-Rust libzstd whose observable behavior —
decompressed bytes, compressed bytes at every level, and accept/reject
decisions — is bit-identical to the C implementation.

## M0 — Project skeleton ✅

- [x] Crate scaffolding, CI, differential-test harness against C libzstd.

## M1 — Decompression ✅

- [x] Frame parsing (headers, skippable frames, multi-frame input).
- [x] Raw / RLE / compressed blocks.
- [x] FSE: `FSE_readNCount`, `FSE_buildDTable`, interleaved decode.
- [x] Huffman: weight decoding (direct + FSE), 1- and 4-stream literals.
- [x] Sequences: all four table modes, repeat-offset history, execution.
- [x] XXH64 content checksums.
- [x] Differential round-trips vs. C libzstd, levels 1–22, bulk + streaming.

## M2 — Decompression completeness

- [ ] Streaming decompression (`ZSTD_decompressStream` semantics, window
      enforcement, `windowLogMax` parameter).
- [ ] Dictionaries: raw-content and trained (entropy-table + rep-offset
      initialization from `ZDICT` format), `dictID` validation.
- [ ] Long-distance matching frames (windows beyond 128 MiB).
- [ ] Error-code parity audit: map every C `ZSTD_ErrorCode` path and assert
      matching rejection in differential fuzzing.
- [ ] Fuzzing: `cargo-fuzz` targets comparing against the C decoder
      (decode-equivalence and never-panic).

## M3 — Entropy encoders (the foundation of bit-exact compression)

Compressed output parity requires reproducing the C encoder's *decisions*,
not just emitting valid streams. Bottom-up:

- [ ] `FSE_normalizeCount` (exact rounding rules) and `FSE_writeNCount`.
- [ ] FSE compression tables (`FSE_buildCTable`) and encoding loop.
- [ ] Huffman tree construction (`HUF_buildCTable`, including the
      `maxTableLog` adjustment and rank rules) and 1/4-stream encoding.
- [ ] Literals-section encoder, including the C heuristics for choosing
      raw / RLE / compressed / treeless modes and stream counts.

## M4 — Block compression, level by level

- [ ] Sequence emission and `ZSTD_entropyCompressSeqStore` parity.
- [ ] Match finders, in C-strategy order: `fast`, `dfast`, `greedy`, `lazy`,
      `lazy2`, `btlazy2`, `btopt`, `btultra`, `btultra2` — each gated by a
      differential test asserting byte-identical compressed output.
- [ ] Parameter tables (`ZSTD_defaultCParameters`) and
      `ZSTD_adjustCParams` logic, so every (level, srcSize) pair picks the
      same parameters as C.
- [ ] Block splitter and `ZSTD_compressBlock` decision points (RLE/raw
      block fallbacks, `ZSTD_maybeRLE`, …).

## M5 — Full API parity

- [ ] One-shot `compress` bit-exact for levels 1–22 (verified against
      multiple upstream zstd releases, pinned per version).
- [ ] Streaming compression; flush/end behavior parity.
- [ ] Dictionary compression.
- [ ] Multithreaded mode (`ZSTDMT`) — job splitting parity.

## M6 — Performance

- [ ] Benchmarks vs. C and vs. other Rust implementations.
- [ ] Optimize hot loops (bit reader containers, 4-at-a-time Huffman
      decode, sequence-execution wildcopies) without breaking the
      `forbid(unsafe_code)` guarantee.

## Versioning note

"Bit-exact compression" is only meaningful against a pinned upstream
version: zstd's compressed output changes between releases. The plan is to
target the zstd version bundled by the `zstd-sys` oracle (currently 1.5.7)
and record the pin explicitly once M3 work begins.
