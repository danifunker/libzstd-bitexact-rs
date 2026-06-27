//! Quick demonstration: compress and decompress with this crate, verifying the
//! round-trip — all in pure Rust, no C dependency.
//!
//! ```sh
//! cargo run --example demo [files...]
//! ```
//!
//! With no arguments, it demonstrates on this repository's own sources.

use libzstd_bitexact_rs::{compress, decompress};

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
            let compressed = compress(&data, level).expect("compression failed");
            let decompressed = decompress(&compressed).expect("our decoder failed");
            assert_eq!(decompressed, data, "round-trip mismatch!");
            let ratio = if compressed.is_empty() {
                0.0
            } else {
                data.len() as f64 / compressed.len() as f64
            };
            println!(
                "  level {level:>2}: {:>7} -> {:>7} bytes ({ratio:.2}x), round-trip identical ✓",
                data.len(),
                compressed.len(),
            );
        }
    }
}
