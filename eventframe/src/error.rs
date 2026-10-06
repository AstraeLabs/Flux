//! Error type for `emsg` (MPEG-DASH Event Message Box) parsing and serialization.
/// Convenience alias for `Result<T, Error>`.
pub type Result<T> = core::result::Result<T, Error>;


#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
/// Errors from parsing or serializing an `emsg` box.
pub enum Error {
    #[error("buffer too short: need {need}, have {have} ({what})")]
    /// Input is shorter than a required field.
    BufferTooShort {
        /// Bytes required.
        need: usize,
        /// Bytes available.
        have: usize,
        /// Name of the field.
        what: &'static str,
    },

    #[error("output buffer too small: need {need}, have {have}")]
    /// Output buffer is smaller than the serialized box.
    OutputBufferTooSmall {
        /// Bytes required.
        need: usize,
        /// Bytes available.
        have: usize,
    },

    #[error("not an emsg box: type {found:?}")]
    /// The box type is not `emsg`.
    NotEmsg {
        /// The four-character type found.
        found: [u8; 4],
    },

    #[error("invalid emsg box size {size}: {reason}")]
    /// The declared box size is invalid.
    InvalidSize {
        /// The declared size.
        size: u32,
        /// Why the string is invalid.
        reason: &'static str,
    },

    #[error("unsupported emsg version {version} (expected 0 or 1)")]
    /// The box version is not 0 or 1.
    UnsupportedVersion {
        /// The version found.
        version: u8,
    },

    #[error("invalid {field} string: {reason}")]
    /// A C string field could not be decoded.
    InvalidString {
        /// Name of the field.
        field: &'static str,
        /// Why the string is invalid.
        reason: &'static str,
    },

    #[error("field {what} value {value} does not fit in {bits} bits")]
    /// A value does not fit its wire field.
    FieldTooWide {
        /// Name of the field.
        what: &'static str,
        /// The value that was too wide.
        value: u64,
        /// Bits the field allows.
        bits: u32,
    },
}
