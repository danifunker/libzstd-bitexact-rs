# libzstd-bitexact-rs — development guide

Pure-Rust Zstandard aiming for bit-exact parity with C libzstd. Decompression
is implemented; compression parity is the long-term goal (see ROADMAP.md).

## Commands

- `cargo test` — full suite (unit + handcrafted vectors + differential).
- `cargo test --release` — what CI gates on for the heavy differential tests.
- `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` — CI lints.
- The differential tests build the bundled C libzstd via the `zstd` crate, so
  a C toolchain (MSVC here) must be available.

## Architecture

One frame decode = `decompress.rs` (frame/block loop) → `block.rs` (literals
+ sequences + execution) → `huffman.rs` / `fse.rs` (entropy) → `bits.rs`
(forward reader for FSE headers, backward reader for payload streams).
`frame.rs` parses headers; `xxhash.rs` checks content checksums;
`block.rs::FrameContext` carries the per-frame state (Huffman table, three
FSE tables for repeat mode, repeat-offset history).

## Non-negotiable invariants

- **The C implementation is the spec.** Decode-table layouts are normative:
  the FSE spread step and Huffman rank fill must match `FSE_buildDTable` /
  `HUF_readDTableX1` exactly. Each port names its C counterpart in comments —
  keep that traceability when editing.
- Sequence decoding order is fixed: per sequence read extra bits OF→ML→LL,
  update states LL→ML→OF, and skip the update for the last sequence.
- `#![forbid(unsafe_code)]` and zero runtime dependencies stay.
- Sequence-code constants in `block.rs` were verified verbatim against
  `lib/common/zstd_internal.h` and `lib/decompress/zstd_decompress_internal.h`
  of facebook/zstd — don't "fix" them by intuition.
- New decoder behavior needs a differential test against the C oracle, not
  just a hand-written expectation. When accept/reject behavior differs from
  C intentionally (e.g. unsupported features), note it in the code.

## Gotchas

- The backward bit reader's `bits_remaining` going negative is the C
  `BIT_DStream_overflow` state — several loops (FSE weight decode) rely on
  detecting it *after* the fact; don't turn it into an early error.
- `FSE_readNCount` discovers its own byte length; callers slice the stream
  with `bytes_consumed`.
- The FSE spread step only cycles fully for table sizes ≥ 16; the format's
  minimum accuracy log (5) guarantees that, but unit tests must not build
  smaller tables (except via `FseTable::rle`).
