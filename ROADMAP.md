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

## M2 — Decompression completeness ✅

- [x] Dictionaries: raw-content and trained (entropy-table + rep-offset
      initialization from `ZDICT` format), `dictID` validation. Matches that
      reach back into the dictionary window (the `extDict` case) are handled
      across the dict/output seam. Exposed via `DecodeOptions::dictionary`.
- [x] `windowLogMax` parameter (`DecodeOptions::window_log_max`), enforced on
      both windowed and single-segment frames and clamped to the format
      maximum. Accept/reject parity is differential-tested against C's
      streaming decoder (the one-shot `ZSTD_decompressDCtx` path ignores the
      parameter and always allows up to `ZSTD_WINDOWLOG_MAX`, which our default
      matches).
- [x] Streaming decompression (`ZSTD_decompressStream` semantics): a
      `Read`-based `StreamDecoder` that buffers compressed input across
      arbitrary chunk boundaries and keeps a bounded sliding window, evicting
      output once it passes out of match range (memory bounded by the frame's
      window, not its content). Content checksums are verified incrementally.
- [x] Long-distance matching frames (windows beyond 128 MiB). LDM is an
      encoder-side decision; the decoder only sees larger offsets and window
      descriptors, both already handled, so this needed no new decoder code —
      confirmed by differential round-trips of LDM-enabled frames and frames
      whose window log exceeds 27.
- [x] Error-code parity audit. A systematic single-byte-flip sweep over real
      frames (including checksummed ones) requires our accept/reject decision —
      and the output when accepted — to match C at every byte and bit, and
      targeted cases pin each error class (bad magic, reserved descriptor bit,
      window too large, reserved block type, content-size mismatch, checksum
      mismatch, dictionary required/wrong/corrupted, truncation) to the
      specific `Error` variant we report.
- [x] Fuzzing: `cargo-fuzz` targets in `fuzz/` (`decode_never_panic` and
      `decode_equivalence`) comparing against the C decoder. The same two
      properties run deterministically over a generated corpus in
      `tests/fuzz_smoke.rs`, so CI exercises them without a nightly toolchain.

## M3 — Entropy encoders (the foundation of bit-exact compression) ✅

Compressed output parity requires reproducing the C encoder's *decisions*,
not just emitting valid streams. Bottom-up:

> Verification note: the `zstd` crate oracle exposes only whole-frame
> compress/decompress, not the FSE/Huffman internals, so the M3 primitives
> cannot be bit-exact-checked against C in isolation — that happens
> end-to-end once a full block can be emitted (M4). In the meantime each
> primitive is a line-by-line C port verified by round-tripping through the
> decoder (which *is* differential-tested against C) plus invariant checks.

- [x] `FSE_optimalTableLog`, `FSE_normalizeCount` (exact `rtbTable` rounding +
      the `normalizeM2` fallback) and `FSE_writeNCount` in `src/fse_encode.rs`.
      Verified by round-tripping normalized distributions — including zstd's
      own predefined LL/OF tables — through the decoder's `read_ncount`, since
      the NCount bit-encoding is canonical for a given `(counts, tableLog)`.
- [x] FSE compression tables (`FSE_buildCTable`) and the encoding loop
      (`BIT_CStream` writer + `FSE_compress_usingCTable`). Verified by the
      strongest available check: a full FSE encode→decode round-trip, decoding
      our output with the C-tested `decode_interleaved` — an exact
      `FSE_compress`/`FSE_decompress` pair — across every parity/join branch.
- [x] Huffman tree construction (`HUF_buildCTable` = `HUF_sort` +
      `HUF_buildTree` + `HUF_setMaxHeight` + canonical-code assignment),
      `HUF_writeCTable` (both the direct 4-bit and FSE-compressed-weights
      paths), and the 1- and 4-stream encoders (`src/huffman_encode.rs`). The
      modern `HUF_CStream` (top-packed container) is reproduced; the unrolled
      dual-container loop is an ILP optimization that yields the same bytes as
      a single-container reverse encode, so the simple form is used. Verified by
      encode→decode round-trips through the C-tested decoder (including a
      distribution that drives the height-limiting clamp) and a
      `write_ctable`→`read_table` round-trip over both weight paths.
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
