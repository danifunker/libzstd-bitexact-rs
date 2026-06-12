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
- [x] Literals-section encoder (`src/literals_encode.rs`), including the C
      heuristics for choosing raw / RLE / compressed / treeless modes and
      stream counts (treeless landed with the cross-block state in M4).

## M4 — Block compression, level by level ✅

This is where byte-exact-vs-C parity is finally tested *end-to-end*: once a
match finder and frame assembly exist, the differential tests compare our
compressed bytes against the C oracle's directly. **Complete: one-shot
`compress(src, level)` is byte-identical to C libzstd 1.5.7 for every level
(1-22 and the negative levels), any input size.**

- [x] Sequence emission and `ZSTD_entropyCompressSeqStore`
      (`src/sequences_encode.rs`): `ZSTD_seqToCodes` (LL/ML code tables +
      long-length markers), `ZSTD_selectEncodingType` (both the
      strategy-based heuristic branch and the cost-comparison branch with
      `ZSTD_fseBitCost`/entropy/cross-entropy/NCount costing),
      `ZSTD_buildCTable` (RLE byte, repeat copy, default tables, and the
      last-sequence count adjustment), the 64-bit `ZSTD_encodeSequences`
      interleaved bitstream, and the block-body shell with the
      literals-section call, prev/next entropy double-buffering, the
      1.3.4-decoder-bug fallback, and the min-gain raw-block gate. Verified
      by decoding emitted blocks with the C-differential-tested decoder:
      handcrafted repcode/real-offset cases, all three sequence-count header
      forms, all four table modes (including Repeat across blocks), the
      long-literal-length marker, and matcher-generated stores at strategies
      1/3/6/9.
- [x] **`fast` — BIT-EXACT.** `src/compress.rs` ports the `ZSTD_fast` match
      finder (hash functions, pipelined search loop, step acceleration,
      repcode fast path, backward extension), and the public `compress(src,
      level)` produces **byte-identical frames to C** for fast-strategy levels
      (1, 2, and the negative/acceleration levels, which also required the
      `ZSTD_ps_auto` rule disabling literal compression when
      `fast && targetLength > 0`). Gated by `tests/compress_differential.rs`:
      byte-for-byte equality with `ZSTD_compress` across text, runs, periods,
      structured records, random multi-block data, and size edges.
- [x] **`dfast` — BIT-EXACT.** `ZSTD_compressBlock_doubleFast` (noDict): the
      two-table long/short search with its `>=`/`>` validity asymmetry, the
      repcode-at-`ip+1` probe, the long-match-at-`ip1` upgrade, step
      acceleration at `1 << kSearchStrength`, conditional `hl1` write-back,
      and the dual-table complementary insertions. Gated by byte-exact
      differential tests at every dfast level of all four srcSize classes
      (levels 2-4 depending on class), including 1 MB multi-block inputs that
      engage the `byChunks` pre-splitter. Inputs too small to run any match
      finder (< 7 bytes) are now exact at *every* level.
- [x] **`greedy` / `lazy` / `lazy2` — BIT-EXACT** (levels up to 12). The
      shared `ZSTD_compressBlock_lazy_generic` driver (`src/lazy.rs`, depths
      0/1/2: the depth ladder with its exact gain comparisons, lazy-skipping
      step acceleration, catch-up, and immediate-repcode loop) over both
      search backends: `ZSTD_HcFindBestMatch` (hash chains, used when the
      adjusted windowLog ≤ 14) and the row-based `ZSTD_RowFindBestMatch`
      (tag table with circular row heads, hash cache, the 384/96/32 update
      skip, and the salted hash — the one-shot salt is the deterministic
      `bitmix(0,8)^bitmix(0,4)` of a fresh CCtx). The row finder's SIMD paths
      are accelerators only; the scalar port produces identical bytes.
      Includes the row-mode hashLog cap in `ZSTD_adjustCParams`. Gated by
      byte-exact differential tests at every greedy/lazy/lazy2 level of all
      four srcSize classes, both backends, plus multi-block 1 MB inputs.
- [x] **`btlazy2` — BIT-EXACT** (levels up to 15). The dual-use binary tree
      (`ZSTD_updateDUBT` unsorted-candidate insertion, `ZSTD_insertDUBT1`
      batch sorting, `ZSTD_DUBT_findBestMatch` with the reversed unsorted
      chain, gain-adjusted best-match rule, and the `matchEndIdx - 8`
      repetition skip) as a third backend of the lazy driver at depth 2.
      Gated at the btlazy2 levels of every srcSize class plus multi-block.
- [x] **`btopt` / `btultra` / `btultra2` — BIT-EXACT** (levels 13-22; **all
      22 levels now produce byte-identical frames to C**). Three pieces landed
      together (`src/opt.rs`, `src/post_split.rs`):
      * The optimal parser: price model (`ZSTD_fracWeight`/`bitWeight`,
        `rescaleFreqs` first-block init + cross-block scaling,
        `updateStats`), `ZSTD_insertBt1`/`updateTree`,
        `ZSTD_insertBtAndGetAllMatches` (speculative repcode scan, the
        minMatch-3 hash table, sorted match collection), the stretch-pricing
        forward pass with its exact gain rules, and btultra2's
        first-block stats-seeding double pass (window rewind emulated by
        index biasing). The 1.5.7 `} {` dead-branch quirk in the
        shortest-path traversal is reproduced as its *effective* behavior.
      * `HUF_optimalTableLog`'s probing depth search
        (`HUF_flags_optimalDepth`, strategies >= btultra).
      * The **post-block splitter** (`ZSTD_compressBlock_splitBlock`,
        auto-on for btopt+ with windowLog >= 17): recursive
        estimate-and-bisect over the seqStore
        (`ZSTD_buildBlockEntropyStats` + `ZSTD_estimateBlockSize`),
        partition emission with dRep/cRep repcode reconciliation
        (`ZSTD_seqStore_resolveOffCodes`), per-partition entropy
        commits, and RLE/raw partition fallbacks.
      Gated by byte-exact differential tests at levels 13-22 over all four
      srcSize classes, periodic/mixed/random corpora, and multi-block inputs
      combining both splitters.
- [x] Parameter tables (`ZSTD_defaultCParameters`, all four srcSize classes)
      and `ZSTD_adjustCParams_internal` (window resize, hash/chain clamping,
      cycle log), verified against the C `ZSTD_getCParams` via FFI probing and
      end-to-end by the byte-exact frame headers.
- [x] Block splitter and multi-block parity: `ZSTD_splitBlock`
      (`src/pre_split.rs`, both the `fromBorders` level used by fast and the
      `byChunks` levels for higher strategies), the sliding-window match floor
      (`ZSTD_window_enforceMaxDist` / `ZSTD_getLowestPrefixIndex` — the lowest
      valid match index moves to `blockEnd − windowSize` once the frame
      outgrows the window), and treeless literals (`set_repeat`: the
      `HUF_repeat` validate/estimate reuse logic and the cross-block Huffman
      state). With these, arbitrarily large inputs are byte-exact at the fast
      levels — including 1 MB+ frames whose windows slide, content that
      actually triggers pre-splits, and literal-heavy data that reuses
      Huffman tables across blocks.

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
