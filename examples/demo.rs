//! Quick demonstration: compress with the real C libzstd, decompress with
//! this crate, and verify the round-trip.
//!
//! ```sh
//! cargo run --example demo [files...]
//! ```
//!
//! With no arguments, it demonstrates on this repository's own sources.

use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let files = if args.is_empty() {
        vec![
            "README.md".to_string(),
            "Cargo.toml".to_string(),
            "src/block.rs".to_string(),
        ]
    } else {
        args
    };

    for path in files {
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("skipping {path}: {e}");
                continue;
            }
        };
        println!("{path} ({} bytes)", data.len());

        for level in [1, 3, 19] {
            let compressed =
                zstd::bulk::compress(&data, level).expect("C libzstd failed to compress");
            let decompressed =
                libzstd_bitexact::decompress(&compressed).expect("our decoder failed");
            assert_eq!(decompressed, data, "round-trip mismatch!");
            println!(
                "  level {level:>2}: {:>7} bytes compressed by C zstd -> decompressed by us: {} bytes, identical ✓",
                compressed.len(),
                decompressed.len()
            );
        }

        // Once more with a content checksum, which our decoder verifies.
        let mut encoder = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
        encoder.include_checksum(true).unwrap();
        encoder.write_all(&data).unwrap();
        let compressed = encoder.finish().unwrap();
        let decompressed = libzstd_bitexact::decompress(&compressed).expect("checksum frame");
        assert_eq!(decompressed, data);
        println!("  checksummed frame: XXH64 verified ✓");
    }
}
