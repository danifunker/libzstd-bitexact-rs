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

- [x] Streaming compression; flush/end behavior parity. `StreamEncoder`
      (`src/stream_encode.rs`) ports the buffered `ZSTD_compressStream_generic`
      path over a refactored `FrameCompressor` (= the frame half of
      `ZSTD_CCtx`, with `ZSTD_compressContinue` / `ZSTD_compressEnd` /
      `ZSTD_writeEpilogue` semantics and the consumed/produced counters that
      seed the pre-splitter savings across chunks). Covers: deferred init
      with auto-pledge on a first-call end (== the one-shot frame),
      unknown-content-size parameter resolution (windowed header, no FCS),
      pledged sizes (including the exact-blockSize `inBuffTarget` quirk and
      pledge enforcement), `ZSTD_e_flush` scheduling, content checksums, and
      the input-buffer wrap: `ZSTD_window_update` segment flips with the
      overlap `lowLimit` shrink, `ZSTD_window_enforceMaxDist` (anchored at
      the block *start*, as `ZSTD_compress_frameChunk` actually does), and
      `ZSTD_compressBlock_fast_extDict` — so fast-strategy levels stream
      without length limits (up to C's 3500 MiB overflow-correction
      threshold). All gated by `tests/stream_compress_differential.rs`
      against `ZSTD_compressStream2` with matched operation schedules.
      Found and fixed along the way: the fast/dfast noDict ports derived
      `maxRep` from the block end instead of `ZSTD_getLowestPrefixIndex` at
      the block start, zeroing near-window repcodes C keeps (pinned by a
      mutation-tested crafted regression).
- [x] extDict match finders for the remaining strategies, lifting the
      streaming length limit at every level: dfast
      (`ZSTD_compressBlock_doubleFast_extDict_generic`), the lazy family
      (`ZSTD_compressBlock_lazy_extDict_generic` over the row, hash-chain
      and DUBT backends, the latter including dict-side backlog sorting in
      `ZSTD_insertDUBT1`), and the bt-opt strategies
      (`ZSTD_insertBtAndGetAllMatches` extDict mode; btultra2's extDict
      blocks map to the btultra entry point per
      `ZSTD_selectBlockCompressor`, and its initStats slide now moves the
      shared window exactly like `ZSTD_initStats_ultra` moves
      `window.base`). Found and fixed along the way: a missing piece of
      `ZSTD_buildSeqStore` — the "limited update after a very long match"
      clamp on `nextToUpdate` — whose absence silently flipped the row
      updater's gap-skip rule and planted divergent tables (surfaced only
      megabytes later when a wrapped stream looked the entries up).
      All gated by per-strategy multi-wrap differential tests in
      `tests/stream_compress_differential.rs`.
- [x] Long-distance matching (LDM, `zstd_ldm.c`): C auto-enables it for
      `strategy >= btopt && windowLog >= 27` (`ZSTD_resolveEnableLdm`),
      i.e. level 22 at unknown or > 64 MiB content sizes. **Ported and
      bit-exact** (`src/ldm.rs`: the gear-hash splitter, the XXH64-fingerprint
      bucket table, `ZSTD_ldm_generateSequences`, and the optimal-parser
      candidate plumbing `ZSTD_optLdm_*` in `src/opt.rs`). The decisive
      subtlety: zstd 1.5.7's `ZSTD_ldm_gear_reset` is a no-op (missing the
      `state->rolling = hash;` writeback), so the gear hash is never re-seeded
      at a block/skip boundary — every block's split scan starts from the
      `ZSTD_ldm_gear_init` constant. Re-seeding it shifts each block's first
      `minMatchLength` splits and fabricates extra raw matches once the table
      is populated; `GearHash::reset` matches the C no-op bug-for-bug. Verified
      by `ldm_streams_are_bit_exact` (level-22 unknown-size streaming) and
      `ldm_one_shot_above_64mib_is_bit_exact` (the > 64 MiB one-shot cliff).
- [x] Index overflow correction (`ZSTD_window_correctOverflow` +
      `ZSTD_reduceIndex`), run per block from `ZSTD_compress_frameChunk`:
      once the running index reaches `ZSTD_CURRENT_MAX` (3500 MiB) the
      window slides and every matcher table is reduced by the same
      `correction` (the segmented `Window` shifts its biases instead of a
      base pointer; `reduce_table` squashes indices below the reserved floor
      and preserves btlazy2's unsorted mark). Streaming is now unbounded;
      one-shot inputs remain capped at 4 GiB − 2 (the whole input is indexed
      in a single `window_update`, so its high index must fit in `u32`).
      Gated by a heavy `#[ignore]` differential test that streams 3.7 GiB
      across the threshold (`overflow_correction_streams_are_bit_exact`).
- [ ] One-shot `compress` bit-exact verified against multiple upstream zstd
      releases, pinned per version (currently pinned to the single 1.5.7
      oracle bundled by `zstd-sys`).
- [x] Dictionary compression. Both C dict paths are bit-exact for all nine
      strategies, raw and trained (`ZDICT`): `compress_with_dict`
      (`ZSTD_compress_usingDict`, the extDict/prefix path), `compress_with_cdict`
      (`ZSTD_compress_usingCDict` / `with_dictionary`, the CDict
      `dictMatchState` path with the attach/copy heuristic), and
      `StreamEncoder::with_dictionary` (streaming, the attach path). Deferred,
      inert at tested sizes: `loadedDictEnd`-aware `enforceMaxDist` /
      `checkDictValidity` (window-filling dict streams) and `maxDictSize`
      suffix-truncation (dicts larger than the indexable table size).
- [ ] Multithreaded mode (`ZSTDMT`) — job-splitting parity.
   - [x] **One-shot `compress_mt` — BIT-EXACT.** `ZSTD_compress2` with
         `nbWorkers >= 1`, reproduced **single-threaded** (C's MT output is
         deterministic and worker-count-independent — only the job decomposition
         matters, so no threads are needed and the library stays zero-dep). The
         input is split into `jobSize`-byte jobs (`ZSTDMT_computeTargetJobLog`
         + clamps); each job after the first sees the previous job's overlap tail
         (`ZSTDMT_computeOverlapSize`) as a **contiguous raw-content prefix**
         (noDict, in-window history — *not* extDict, since C's round buffer keeps
         prefix and segment adjacent), with reset repcodes and fresh entropy; the
         first job writes the frame header, later jobs emit blocks only, the last
         writes the epilogue. Below `ZSTDMT_JOBSIZE_MIN` (512 KiB) or a single
         job, the output is the single-threaded frame exactly. Gated by
         `tests/mt_compress_differential.rs` against the `zstdmt`-built C oracle:
         byte-identical across every strategy, default and explicit
         `jobSize`/`overlapLog`, the single/multi-job boundary, and exact-multiple
         sizes. (Cross-job LDM and streaming MT followed as the increments below;
         a one-shot dictionary is still a later increment.)
   - [x] **Streaming `ZSTDMT` — BIT-EXACT** (`StreamEncoder::with_workers`).
         `ZSTD_compressStream2` with `nbWorkers >= 1` at an unknown content size:
         input is buffered into `section_size` jobs as it arrives
         (`ZSTDMT_compressStream_generic`), each compressed by the same per-job
         machinery as the one-shot path. Reproduces C's exact loop semantics: a
         job is the frame end only when `e_end` arrives with the input fully
         consumed (otherwise `e_end` is downgraded to `e_flush`), so the trailing
         empty-block job appears precisely when the input ends on a section
         boundary in a later call. A first-call `finish` delegates to the
         single-threaded frame (≤ 512 KiB) or the one-shot MT frame (above).
         Bounded memory (one `overlap + section` staging buffer). Gated by
         `tests/mt_stream_compress_differential.rs` across strategies, chunk
         schedules, exact-multiple boundaries, and the single-job / first-call
         cases. (`flush`, a pledged size, dictionaries, and cross-job LDM with
         workers followed as the increments below.)
   - [x] **`ZSTDMT` content checksum — BIT-EXACT** (one-shot + streaming). The
         digest is over the whole input (C's serial state updates it per job
         segment); job 0 keeps the checksum flag so the frame header carries the
         bit and a **single** job appends its own digest, while a multi-job frame
         clears the flag on every job and appends the 4-byte digest once after
         the last job (`ZSTDMT_flushProduced`, including after a trailing empty
         block). Gated by `mt_checksum_is_bit_exact` /
         `mt_stream_checksum_is_bit_exact`.
   - [x] **`ZSTDMT` streaming `flush` + pledged content size — BIT-EXACT.**
         `flush` emits the buffered partial section as a non-last job (the frame
         stays open, the overlap still primes the next job). A pledged size
         resolves cParams from the known size and makes job 0 write an FCS header
         (engagement: workers + unknown size, or a pledge above 512 KiB; a
         first-call `finish` delegates to the one-shot MT frame). Gated by
         `mt_stream_flush_is_bit_exact` / `mt_stream_pledged_size_is_bit_exact`.
   - [x] **`ZSTDMT` streaming with a dictionary — BIT-EXACT** (raw + trained,
         `StreamEncoder::with_dictionary().with_workers()`). C applies the
         dictionary to **job 0 only** (`jobs[0].cdict`): job 0 is a Path-B CDict
         **attach** over `content ++ segment0`, writing the frame header with the
         dictID; later jobs are plain overlap jobs. The decisive subtlety:
         loading a dictionary resolves the frame cParams in `ZSTD_cpm_attachDict`
         mode, which **zeroes the dict size** (`getCParamRowSize` +
         `adjustCParams_internal`), so the section/overlap and every job's base
         cParams are the plain **no-dict** ones — only job 0's dict tables use the
         createCDict cParams (so job 0 is exactly `streaming_cdict_init`'s
         compressor). Gated by `mt_stream_raw_dict_is_bit_exact` /
         `mt_stream_trained_dict_is_bit_exact`.
   - [x] **`ZSTDMT` streaming dictionary, COPY path — BIT-EXACT (raw).** A known
         frame size above the attach cutoff resolves the frame cParams in
         `cpm_noAttachDict` mode (dict-aware) and **copies** the de-tagged CDict
         tables into job 0's context (the dict a contiguous extDict prefix) —
         exactly `compress_with_cdict`'s copy branch. Reaching multi-block copy
         unmasked the unported `loadedDictEnd` mechanism (`ZSTD_getLowestMatchIndex`'s
         isDictionary branch + `checkDictValidity` + `enforceMaxDist`), now ported
         across all extDict matchers (`Window::loaded_dict_end`). Gated by
         `mt_stream_raw_dict_copy_is_bit_exact`; a **trained** dict on the copy path
         is a separate pre-existing `compress_with_cdict` divergence, so it is a
         clean error (`mt_stream_trained_dict_copy_errors_cleanly`).
   - [x] **`ZSTDMT` cross-job LDM — BIT-EXACT (one-shot + streaming).** One
         continuous `LdmState` (C's `ZSTDMT_serialState`) shared across all jobs
         generates each segment's `rawSeqStore`, which the job consumes as its
         externSeqStore (a cursor persisting across the job's blocks); the job's own
         LDM is disabled. Auto-enables for `strategy >= btopt && windowLog >= 27` —
         level 22 one-shot above 64 MiB, or *any* unknown-size streaming (windowLog
         stays 27). Streaming keeps the serial history in an accumulated buffer back
         to `maxDist` (C's serial round buffer), front-dropping older bytes (never
         matched) and remapping absolute window indices via `seg_bias` — byte-identical
         to C's round-buffer wrap + extDict flip because C's MT output is
         worker-count-independent. Gated by `mt_cross_job_ldm_is_bit_exact`,
         `mt_stream_cross_job_ldm_is_bit_exact`, and (manual, >128 MiB)
         `mt_stream_cross_job_ldm_past_window`.
   - [x] **One-shot `compress_mt` with a dictionary — BIT-EXACT (raw).**
         `compress_mt_with_dict` = `ZSTD_compress2` + `NbWorkers` + `loadDictionary`.
         A one-shot frame pledges the known srcSize, which once MT engages (> 512 KiB)
         always exceeds the attach cutoff, so job 0 takes the CDict **copy** path;
         the engaged case drives the streaming `MtStreamState` with the whole input
         as a single `e_end`. `nbWorkers == 0` or an input at or below the MT floor
         runs single-threaded with the CDict (`compress_with_cdict`, now checksum-aware).
         Gated by `mt_one_shot_dict_is_bit_exact`, `mt_one_shot_trained_dict_attach_is_bit_exact`,
         and `mt_one_shot_trained_dict_copy_is_bit_exact`.
   - [x] **CDict copy post-block-splitter resolves from the frame cParams — BIT-EXACT
         trained-dict copy (`task_51d658f2`).** The copy path enabled the post-block
         splitter on the *copied CDict* strategy, but C resolves `postBlockSplitter`
         once from the **frame** cParams (`ZSTD_resolveBlockSplitterMode`) before
         `ZSTD_resetCCtx_byCopyingCDict` overwrites cParams with the CDict's own. The
         CDict uses createCDict params (513-byte hint), whose strategy can sit at/above
         btopt while the frame strategy is below it (e.g. level 15: frame btlazy2, cdict
         btultra) — so we split where C did not, and a trained dict's seeded entropy made
         the wrongly-enabled splitter actually split. `FrameCompressor.post_block_splitter`
         now mirrors C's resolved switch (default `block_splitter_enabled(&cparams)`,
         overridden by the CDict attach/copy paths from the frame cParams). Fixes
         standalone `compress_with_cdict` copy (any dict) and un-gates MT + trained-dict
         copy. Gated by `cdict_copy_multiblock_post_split_is_bit_exact` (multi-block, the
         prior CDict tests were single-block ≤ 60 KiB) + the MT trained-copy tests.
   - [ ] Remaining `ZSTDMT`: MT + dict + LDM together (the serial state's dict-fill is
         unported) — a clean error.

## M6 — Performance

- [ ] Benchmarks vs. C and vs. other Rust implementations.
- [ ] Optimize hot loops (bit reader containers, 4-at-a-time Huffman
      decode, sequence-execution wildcopies) without breaking the
      `forbid(unsafe_code)` guarantee.

## Versioning note

"Bit-exact compression" is only meaningful against a pinned upstream
version: zstd's compressed output changes between releases. The target is the
zstd version bundled by the `zstd-sys` oracle — **zstd 1.5.7**
(`zstd-sys 2.0.16+zstd.1.5.7`). The pin is now recorded explicitly: `Cargo.lock`
is committed and CI builds with `--locked`, so the oracle version (and the whole
resolved graph) can only move via a deliberate `cargo update`. A future
`zstd-sys` release bundling a newer zstd will therefore not silently break the
differential suite — adopting it is a conscious step (bump the lock, then update
the Rust implementation to match the new upstream output).
