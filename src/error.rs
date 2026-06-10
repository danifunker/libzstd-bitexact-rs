use std::fmt;

/// Errors produced while decoding a Zstandard stream.
///
/// The taxonomy intentionally mirrors the error conditions of the C libzstd
/// (`ZSTD_ErrorCode`) so that accept/reject behavior can be compared in
/// differential tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input ended before a complete frame could be decoded
    /// (`ZSTD_error_srcSize_wrong`).
    SrcSizeWrong,
    /// The first four bytes of a frame are neither the Zstandard magic
    /// number nor a skippable-frame magic (`ZSTD_error_prefix_unknown`).
    UnknownMagic(u32),
    /// The frame header violates the specification
    /// (`ZSTD_error_frameParameter_unsupported`).
    FrameHeaderInvalid(&'static str),
    /// The declared window size exceeds what this decoder supports
    /// (`ZSTD_error_frameParameter_windowTooLarge`).
    WindowTooLarge,
    /// A block used the reserved block type (`ZSTD_error_corruption_detected`).
    BlockTypeInvalid,
    /// The compressed data is malformed (`ZSTD_error_corruption_detected`).
    Corrupted(&'static str),
    /// The frame's XXH64 content checksum did not match
    /// (`ZSTD_error_checksum_wrong`).
    ChecksumMismatch { expected: u32, actual: u32 },
    /// The frame was compressed with a dictionary, but none was supplied to
    /// the decoder (`ZSTD_error_dictionary_wrong`). The payload is the
    /// dictionary ID the frame asks for.
    DictionaryRequired(u32),
    /// A dictionary was supplied, but its ID does not match the one the frame
    /// requires (`ZSTD_error_dictionary_wrong`).
    DictionaryWrong { expected: u32, actual: u32 },
    /// A supplied dictionary buffer began with the `ZDICT` magic but could not
    /// be parsed (`ZSTD_error_dictionary_corrupted`).
    DictionaryCorrupted,
    /// The frame declared a content size that does not match the number of
    /// bytes actually regenerated (`ZSTD_error_corruption_detected`).
    FrameContentSizeMismatch,
    /// Decoding would exceed the output limit given to
    /// [`decompress_with_limit`](crate::decompress_with_limit).
    OutputTooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::SrcSizeWrong => write!(f, "input is truncated or has trailing garbage"),
            Error::UnknownMagic(m) => write!(f, "unknown frame magic number {m:#010x}"),
            Error::FrameHeaderInvalid(why) => write!(f, "invalid frame header: {why}"),
            Error::WindowTooLarge => write!(f, "frame window size is too large"),
            Error::BlockTypeInvalid => write!(f, "reserved block type"),
            Error::Corrupted(why) => write!(f, "corrupted compressed data: {why}"),
            Error::ChecksumMismatch { expected, actual } => write!(
                f,
                "content checksum mismatch: stored {expected:#010x}, computed {actual:#010x}"
            ),
            Error::DictionaryRequired(id) => {
                write!(f, "frame requires dictionary {id}, but none was supplied")
            }
            Error::DictionaryWrong { expected, actual } => write!(
                f,
                "wrong dictionary: frame requires ID {expected}, supplied dictionary has ID {actual}"
            ),
            Error::DictionaryCorrupted => write!(f, "supplied dictionary is malformed"),
            Error::FrameContentSizeMismatch => {
                write!(
                    f,
                    "regenerated size does not match the declared frame content size"
                )
            }
            Error::OutputTooLarge => write!(f, "decompressed output exceeds the configured limit"),
        }
    }
}

impl std::error::Error for Error {}
