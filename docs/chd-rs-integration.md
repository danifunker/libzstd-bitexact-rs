# Bit-exact zstd 1.5.5 for chd-rs

**Status:** `libzstd-bitexact-rs` **0.155.0** is published to crates.io (2026-06-19)
and is byte-for-byte identical to C **libzstd 1.5.5** for both compression and
decompression. This note explains what that gives chd-rs, how to wire it in, and
the handful of edge cases left unported — none of which touch chdman's actual
code path.

## Why a 1.5.5-specific encoder

- Reference **chdman compresses every hunk at level 22** (`ZSTD_maxCLevel()`), via
  `ZSTD_initCStream` + `ZSTD_compressStream2(…, ZSTD_e_end)` — unknown pledged
  size, no dictionary.
- zstd **1.5.5 and 1.5.7 emit different bytes at level 22** (empirically, 4 of 5
  sample inputs differ). The block splitter (new in 1.5.6), the btultra2 optimal
  parser, the long-distance-matcher defaults, and several dfast/dict match-
  selection rules were all retuned across 1.5.6 → 1.5.7.
- **Decode is format-stable** (RFC 8878): a 1.5.7 decoder reads 1.5.5 streams
  perfectly, so *reading* CHDs never needed this. But CHD container
  **byte-identity** with a reference chdman build — which bundles zstd 1.5.5 —
  requires an encoder that matches 1.5.5 exactly. (CHD's internal SHA1 is over the
  *raw* data, so a 1.5.7-compressed CHD is still **valid**; it just isn't
  **byte-identical** to what stock chdman produces.)

This crate is that encoder. The sibling `0.157.x` line of the same crate is the
1.5.7-targeted build, kept for projects that want to match current upstream.

## Dependency

```toml
[dependencies]
libzstd-bitexact-rs = "=0.155"
```

⚠️ **Pin `=0.155`.** A bare `cargo add libzstd-bitexact-rs` resolves to the
**0.157.x** line (zstd 1.5.7). Cargo's 0.x semver treats 0.155 and 0.157 as
incompatible — so `"0.155"` won't auto-bump to 0.157 — but write `=0.155` so the
intent is unmistakable. The crate is pure Rust, `#![forbid(unsafe_code)]`, with
zero runtime dependencies.

## The chdman code path, mapped

chdman's per-hunk flow is **unknown-size streaming at level 22 with no
dictionary**. The matching call is:

```rust
use libzstd_bitexact_rs::StreamEncoder;

fn compress_hunk_zstd(hunk: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    // new(22) == ZSTD_initCStream(level = 22): UNKNOWN pledged size.
    StreamEncoder::new(22)
        .finish(hunk, &mut out)   // == ZSTD_compressStream2(.., ZSTD_e_end)
        .expect("zstd compress");
    out
}
```

Two details that decide byte-identity:

- **Use `StreamEncoder::new(22)`, not `with_pledged_src_size`.** chdman does not
  pledge the hunk size, so the frame header carries no content size and the
  compression parameters keep level 22's full `windowLog` of 27 (which also
  auto-enables long-distance matching). Pledging the size downsizes `windowLog`
  and changes the output bytes.
- **No custom parameters.** chdman uses stock level-22 defaults — do not set
  `windowLog`, LDM, or worker options, or the output diverges.

If a future chd-rs has the whole hunk in memory and prefers one-shot,
`compress(hunk, 22)` is byte-identical to `new(22).finish(hunk, …)` for a single
`e_end` — both resolve parameters the same way. For the CD-ROM zstd codec
(`cdzs`), the same per-frame encoder applies to each sub-stream; only the framing
around it differs.

## What is verified bit-exact (vs the C 1.5.5 oracle)

The crate is continuously differential-tested: every test compresses with this
crate **and** the bundled C libzstd 1.5.5 (dev-dependency
`zstd-sys 2.0.9+zstd.1.5.5`), asserts the bytes are identical, then round-trips
through the decoder.

- All **9 strategies** (fast, dfast, greedy, lazy, lazy2, btlazy2, btopt,
  btultra, btultra2) at **levels 1–22 and the negative levels**.
- **Long-distance matching**, including the level-22 / windowLog-27 path chdman
  exercises.
- **Dictionaries** (raw-content and trained/ZDICT), both the `usingDict`/extDict
  path and the CDict/dictMatchState path, one-shot and streaming.
- **Multithreaded** (ZSTDMT): one-shot and streaming, with checksum,
  dictionaries, and cross-job LDM.
- **Decoder**: full Zstd decode plus 1.5.5's exact accept/reject behavior on
  malformed input.

At publish: 17 differential test binaries green; CI green on Linux, macOS, and
Windows, plus a debug-assert build and lint.

## Public API quick reference

- **One-shot compress:** `compress(src, level)`, `compress_with_dict`,
  `compress_with_cdict`, `compress_mt`, `compress_mt_with_dict`.
- **Streaming compress:** `StreamEncoder::{new, with_dictionary,
  with_pledged_src_size, with_checksum, with_workers}`, then `compress`
  (`e_continue`) / `flush` (`e_flush`) / `finish` (`e_end`).
- **Decompress:** `decompress`, `decompress_with_limit`, `DecodeOptions` (output
  limit + `windowLogMax` + `Dictionary`), `StreamDecoder` (`Read`-based).
- **Types:** `Dictionary`, `Error`, `WINDOW_LOG_MAX`.

## Gaps / deferred items

None of these touch chdman's path (level 22, no dictionary, hunk-sized inputs).
Listed for completeness.

1. **Decode: non-canonical `nbSeq == 0` (opposite-direction strictness).**
   1.5.5 requires an empty sequences section to be the single canonical byte
   `0x00`, and *rejects* the 2-byte form (`0x80 0x00`) with `srcSize_wrong`. This
   crate's decoder (inherited from the 1.5.7 line) *accepts* the 2-byte form when
   no trailing bytes follow — so for that one hand-crafted shape we are **more
   lenient** than 1.5.5, the reverse of the reserved-sequence-mode-bits edge that
   *was* reverted for 1.5.5 parity. It is unreachable from any real or
   this-crate-produced frame (the compressor only ever emits the canonical byte),
   and the systematic single-bit-flip parity sweep never hits it, so it was left
   unported. Only relevant if chd-rs needs exact 1.5.5 *reject* parity on
   adversarial/hand-crafted input.

2. **maxDictSize suffix truncation for large dictionaries (≥ ~32 KB).**
   For dictionaries that exceed a per-level cap, C (`ZSTD_loadDictionaryContent`)
   keeps only a trailing suffix; this crate loads the whole dictionary. Affects
   only dictionary compression with a large dict — not chdman's no-dict hunk path.

3. **4 GiB input ceiling.** Inputs where `dict + src ≥ 4 GiB − 2` return a clean
   `Error::Encode`. CHD hunks are kilobytes, so irrelevant.

4. **CDict with ≤ 8 bytes of content** is rejected with a clean error (degenerate;
   real dictionaries are far larger).

5. **Large-window LDM *with a dictionary*** (windowLog ≥ 27 at btopt+ *and* a
   dictionary) is rejected with a clean error. chdman uses no dictionary, so this
   never triggers; plain LDM *without* a dict at level 22 is fully supported.

6. **Cosmetic: crate-level rustdoc still says "1.5.7."** On the 0.155 line the
   top-of-`lib.rs` summary line wasn't retargeted, so docs.rs for 0.155.0 reads
   "byte-identical to C libzstd 1.5.7." The behavior is 1.5.5; only the doc string
   is stale. Worth a one-line fix in the next 0.155.x.

## Re-verifying after chd-rs changes

- `cargo test --release` in this crate runs the full differential suite (it builds
  C zstd 1.5.5 as the oracle; needs a C toolchain).
- When chd-rs adds or changes a zstd call site, the cheapest guard is a
  differential unit test on the chd-rs side: compress the same bytes with
  `libzstd-bitexact-rs` and with a known zstd-1.5.5 reference (or a stored golden
  CHD), and assert equality. Because decode is format-stable, a pure round-trip
  will **not** catch encoder drift — compare the *compressed* bytes.
