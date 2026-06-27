# Validating the bit-exactness claims

This crate claims **byte-for-byte parity with C libzstd 1.5.5** — identical
compressed bytes at every level, identical decompressed bytes, and matching
accept/reject decisions on malformed input. Those claims are real and were
proven mechanically. This document shows how to **reproduce that proof yourself**,
even though the repository itself contains **no C code and no C dependency**.

## Why there's no C in this repo

The crate is pure Rust, `#![forbid(unsafe_code)]`, with zero dependencies — and,
on this `0.155.x` (zstd 1.5.5) line, zero **dev**-dependencies too. Building or
testing it needs only a Rust toolchain; nothing compiles C.

The proof of bit-exactness is inherently a *differential* test: it compares this
crate's output against the **real C libzstd 1.5.5**, used as an oracle. That
oracle (`zstd` / `zstd-sys`, which vendors and compiles the C library) was kept
strictly as a dev-dependency and the whole differential suite was **removed from
the working tree once `0.155.0` was published and CI-green** — so day-to-day
development never drags in a C toolchain. The suite is preserved, intact, in git
history and is trivially restorable for re-verification (below).

The C oracle is only ever fetched and compiled into Cargo's per-user cache
(`~/.cargo`), never into this repository — so reproducing the proof does **not**
add any C to the repo.

## Where the proof lives

Tag **`v0.155.0`** (commit `3518deb`) is the published release commit. It still
carries the full differential suite and the pinned C oracle:

- oracle dev-deps: **`zstd = "=0.13.0"`** and **`zstd-sys = "=2.0.9+zstd.1.5.5"`**
  (the releases that bundle C libzstd **1.5.5**), recorded in that tag's
  `Cargo.lock`.
- the test binaries it gates (all against the C oracle): `compress_differential`,
  `stream_compress_differential`, `dict_compress_differential`,
  `cdict_compress_differential`, `stream_dict_compress_differential`,
  `mt_compress_differential`, `mt_stream_compress_differential`,
  `cparams_differential`, `differential`, `dictionary`, `streaming`,
  `long_distance`, `error_parity`, `fuzz_smoke`.

The **compiled library is unchanged** between the current `HEAD` and the proven
`v0.155.0`: the only differences in `src/` since the tag are documentation
comments (the `1.5.7`→`1.5.5` doc-string corrections shipped in `0.155.1`), which
the compiler ignores. Tests, the bench, the fuzz package, and the dev-deps were
removed afterward, but no compressor or decoder code changed. Confirm there is no
behavioral change for yourself:

```sh
git diff v0.155.0 HEAD -- src/      # only //! / /// comment lines, no code
```

Because the compiled compressor/decoder is identical, the proof recorded at the
tag applies verbatim to the current code.

## Reproducing the proof (out-of-tree)

You need a C toolchain (MSVC, clang, or gcc) for this — and *only* for this. Use
a throwaway git worktree so your checkout and this repo stay C-free.

### Option A — validate at the release tag (simplest)

```sh
git worktree add ../zstd155-verify v0.155.0
cd ../zstd155-verify
cargo test --release --locked        # builds C libzstd 1.5.5 in ~/.cargo, runs the full differential suite
cd -
git worktree remove ../zstd155-verify
```

`--locked` forces the exact pinned oracle (`zstd-sys 2.0.9+zstd.1.5.5`);
bit-exactness is only meaningful against one upstream release, so the pin must
not drift. A green run is the proof: every assertion compares our bytes against
the C oracle's and requires equality.

### Option B — run the archived suite against the current code

To prove *today's* `HEAD` rather than the tag, restore just the test surface and
oracle onto a worktree of the current branch:

```sh
git worktree add ../zstd155-head HEAD
cd ../zstd155-head
git checkout v0.155.0 -- tests benches Cargo.toml Cargo.lock   # re-adds the suite + the zstd/zstd-sys dev-deps
cargo test --release
cd -
git worktree remove --force ../zstd155-head
```

Since `src/` is identical between `HEAD` and the tag (verified above), Options A
and B exercise the same compressor and decoder; B just proves it without
trusting the "src unchanged" check.

## What the suite verifies

- **Compression**: every level (`-3..=22`) across all nine strategies (fast,
  dfast, greedy, lazy, lazy2, btlazy2, btopt, btultra, btultra2), bulk and
  streaming, byte-identical to C.
- **Dictionaries**: raw-content and trained/ZDICT, both the `usingDict`/extDict
  path and the CDict/`dictMatchState` path, one-shot and streaming.
- **Multithreaded** (`ZSTDMT` job-splitting): one-shot and streaming, with
  checksums, dictionaries, and cross-job long-distance matching.
- **Long-distance matching** (including the level-22 / windowLog-27 path).
- **Decode**: round-trips of C-produced frames, fed whole and at every streaming
  chunk size; `windowLogMax` accept/reject parity; random-input probes that
  assert we never accept data C rejects (`error_parity`, `fuzz_smoke`).
- **Parameter derivation**: `ZSTD_getCParams` parity via FFI (`cparams_differential`).

## Independent CI evidence

The release commit `3518deb` (tag `v0.155.0`) ran the full suite **green on
Linux, macOS, and Windows**, plus a debug-assert build and lint, on PR #1 of the
GitHub repository. That run compiled the bundled C libzstd 1.5.5 and asserted
byte-equality across the matrix above.

## In-repo checks (no C required)

What ships and runs in pure Rust still exercises the format directly:

```sh
cargo test            # in-crate unit tests + tests/format.rs decode vectors + tests/fuzz_smoke.rs robustness
```

`tests/fuzz_smoke.rs` builds frames with this crate's own compressor, then
mutates and truncates them to assert the decoder never panics — the robustness
half of the old fuzz targets, kept C-free. It does not re-prove bit-exactness
against C; that's what the archived differential suite above is for.
