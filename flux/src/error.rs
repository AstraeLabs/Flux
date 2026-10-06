use alloc::string::String;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("buffer too short: need {need} bytes, have {have} (while parsing {what})")]
    BufferTooShort {
        need: usize,
        have: usize,
        what: &'static str,
    },

    #[error("largesize indicated but buffer too short: need {need}, have {have}")]
    LargesizeBufferTooShort {
        need: usize,
        have: usize,
    },

    #[error("uuid box indicated but buffer too short: need {need}, have {have}")]
    UuidBufferTooShort {
        need: usize,
        have: usize,
    },

    #[error("box size {size} is smaller than header ({header_size} bytes)")]
    BoxSizeUnderflow {
        size: u64,
        header_size: usize,
    },

    #[error("serialize: output buffer too small — need {need}, have {have}")]
    OutputBufferTooSmall {
        need: usize,
        have: usize,
    },

    #[error("invalid {field}: {reason} (value: 0x{value:X})")]
    InvalidValue {
        field: &'static str,
        value: u64,
        reason: &'static str,
    },

    #[error("unexpected box: expected {expected}")]
    UnexpectedBox {
        expected: &'static str,
    },

    #[error("invalid input: {0}")]
    InvalidInput(&'static str),

    #[error("codec {codec} has no ISOBMFF/fMP4 carriage in this crate")]
    UnsupportedCodec {
        codec: &'static str,
    },

    #[error("CENC scheme '{scheme}' has no cipher implementation in this crate")]
    UnsupportedCencScheme {
        scheme: bitforge::CencScheme,
    },

    #[error("sample entry '{fourcc}' has no CodecConfig reconstruction in this crate")]
    UnsupportedSampleEntry {
        fourcc: String,
    },

    #[error(
        "cannot CMAF-mux track {track_id} (subtitle format {format}): \
         CodecConfig::Subtitle has no ISOBMFF re-mux sample entry in this crate yet"
    )]
    UnmuxableSubtitleTrack {
        track_id: u32,
        format: crate::pipeline::SubtitleFormat,
    },

    #[error("{what} buffer exceeded its {cap}-byte cap and was dropped")]
    BufferCapExceeded {
        what: &'static str,
        cap: usize,
    },
}
