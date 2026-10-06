//! The `emsg` `FullBox` version field — DASH-IF IOP Part 10 §6.1 / Table 6-2.

/// The `emsg` `FullBox` version, selecting the presentation-time encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub enum EmsgVersion {
    /// Version 0: time relative to the segment.
    SegmentRelative,
    /// Version 1: absolute time on the representation.
    RepresentationRelative,
}

/// Version number 0.
pub const VERSION_0: u8 = 0;
/// Version number 1.
pub const VERSION_1: u8 = 1;

impl EmsgVersion {
    /// Maps a version number to the enum, or `None`.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            VERSION_0 => Some(EmsgVersion::SegmentRelative),
            VERSION_1 => Some(EmsgVersion::RepresentationRelative),
            _ => None,
        }
    }

    /// Version number of this variant.
    pub fn to_u8(self) -> u8 {
        match self {
            EmsgVersion::SegmentRelative => VERSION_0,
            EmsgVersion::RepresentationRelative => VERSION_1,
        }
    }

    /// Name of this variant.
    pub fn name(&self) -> &'static str {
        match self {
            EmsgVersion::SegmentRelative => "segment relative (v0)",
            EmsgVersion::RepresentationRelative => "representation relative (v1)",
        }
    }
}

bitforge::impl_spec_display!(EmsgVersion);