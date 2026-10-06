//! Canonical `Parse` and `Serialize` traits for the DVB crate family.

use alloc::vec::Vec;

/// Parse a DVB structure from raw bytes. Borrowing allowed via `<'a>`; the

pub trait Parse<'a>: Sized {
    /// Error type.
    type Error;
    /// Parses `bytes` into `Self`.
    fn parse(bytes: &'a [u8]) -> Result<Self, Self::Error>;
}

/// Serializes a value into bytes.
pub trait Serialize {
    /// Error type.
    type Error;
    /// Exact number of bytes `serialize_into` writes.
    fn serialized_len(&self) -> usize;
    /// Writes into `buf`, returning the byte count.
    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Serializes into a new `Vec`.
    fn to_bytes(&self) -> Vec<u8>
    where
        Self::Error: core::fmt::Debug,
    {
        let mut v = alloc::vec![0u8; self.serialized_len()];
        self.serialize_into(&mut v)
            .expect("serialize_into must succeed when buffer is exactly serialized_len()");
        v
    }
}
