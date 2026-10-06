//! Common Encryption (CENC) scheme identity — ISO/IEC 23001-7 §4.

/// Four-character code for the `cenc` (AES-CTR, full-sample) scheme.
pub const SCHEME_CENC: [u8; 4] = *b"cenc";
/// Four-character code for the `cbcs` (AES-CBC, pattern) scheme.
pub const SCHEME_CBCS: [u8; 4] = *b"cbcs";
/// Four-character code for `cbc1`.
pub const SCHEME_CBC1: [u8; 4] = *b"cbc1";
/// Four-character code for `cens`.
pub const SCHEME_CENS: [u8; 4] = *b"cens";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
/// Common Encryption protection scheme.
pub enum CencScheme {
    /// AES-CTR, full sample.
    Cenc,
    /// AES-CBC with pattern encryption.
    Cbcs,
    /// AES-CBC, continuous chain across subsamples.
    Cbc1,
    /// AES-CTR with pattern encryption.
    Cens,
}

impl CencScheme {
    /// Scheme name, e.g. `cenc`.
    pub fn name(&self) -> &'static str {
        match self {
            CencScheme::Cenc => "cenc",
            CencScheme::Cbcs => "cbcs",
            CencScheme::Cbc1 => "cbc1",
            CencScheme::Cens => "cens",
        }
    }

    /// Four-character code of this scheme.
    pub fn to_four_cc(&self) -> [u8; 4] {
        match self {
            CencScheme::Cenc => SCHEME_CENC,
            CencScheme::Cbcs => SCHEME_CBCS,
            CencScheme::Cbc1 => SCHEME_CBC1,
            CencScheme::Cens => SCHEME_CENS,
        }
    }

    /// Parses a scheme from its four-character code.
    pub fn from_four_cc(four_cc: &[u8; 4]) -> Option<Self> {
        match *four_cc {
            SCHEME_CENC => Some(CencScheme::Cenc),
            SCHEME_CBCS => Some(CencScheme::Cbcs),
            SCHEME_CBC1 => Some(CencScheme::Cbc1),
            SCHEME_CENS => Some(CencScheme::Cens),
            _ => None,
        }
    }
}

crate::impl_spec_display!(CencScheme);