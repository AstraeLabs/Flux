//! `emsg` — MPEG-DASH Event Message Box.

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::version::EmsgVersion;

/// Box type `emsg`.
pub const EMSG_BOX_TYPE: [u8; 4] = *b"emsg";
/// Length of the FullBox header in bytes.
pub const FULLBOX_HEADER_LEN: usize = 12;
/// FullBox flags for `emsg` (always zero).
pub const EMSG_FLAGS: u32 = 0;
/// Null byte ending a C string.
pub const STRING_TERMINATOR: u8 = 0x00;

const U32_LEN: usize = 4;
const U64_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
/// Presentation time, relative (v0) or absolute (v1).
pub enum PresentationTime {
    /// Time relative to the segment start (v0).
    Delta(u32),
    /// Absolute time on the representation timeline (v1).
    Absolute(u64),
}

impl PresentationTime {
    /// Box version that carries this form.
    pub fn version(self) -> EmsgVersion {
        match self {
            PresentationTime::Delta(_) => EmsgVersion::SegmentRelative,
            PresentationTime::Absolute(_) => EmsgVersion::RepresentationRelative,
        }
    }

    /// Wire field name for this form.
    pub fn name(&self) -> &'static str {
        match self {
            PresentationTime::Delta(_) => "presentation_time_delta",
            PresentationTime::Absolute(_) => "presentation_time",
        }
    }
}

bitforge::impl_spec_display!(PresentationTime, Delta, Absolute);

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
/// A parsed DASH `emsg` event message box.
pub struct EmsgBox<'a> {
    /// URI identifying the event scheme.
    pub scheme_id_uri: &'a str,
    /// Scheme-specific value string.
    pub value: &'a str,
    /// Ticks per second for the time fields.
    pub timescale: u32,
    /// Presentation time of the event.
    pub presentation_time: PresentationTime,
    /// Event duration in `timescale` units.
    pub event_duration: u32,
    /// Event identifier.
    pub id: u32,
    #[cfg_attr(feature = "serde", serde(skip))]
    /// Opaque scheme-specific payload.
    pub message_data: &'a [u8],
}

impl<'a> EmsgBox<'a> {
    /// Box version required for this box's time form.
    pub fn version(&self) -> EmsgVersion {
        self.presentation_time.version()
    }

    /// Whether the scheme is SCTE-35.
    pub fn is_scte35(&self) -> bool {
        self.scheme_id_uri.starts_with(SCTE35_SCHEME_PREFIX)
    }

    /// Total serialized size, including the FullBox header.
    pub fn serialized_len(&self) -> usize {
        FULLBOX_HEADER_LEN + self.body_len()
    }

    fn body_len(&self) -> usize {
        let strings = self.scheme_id_uri.len()
            + 1
            + self.value.len()
            + 1;
        let ints = match self.presentation_time {

            PresentationTime::Delta(_) => U32_LEN * 4,

            PresentationTime::Absolute(_) => U32_LEN * 3 + U64_LEN,
        };
        strings + ints + self.message_data.len()
    }

    /// Parses an `emsg` box, including its FullBox header.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < FULLBOX_HEADER_LEN {
            return Err(Error::BufferTooShort {
                need: FULLBOX_HEADER_LEN,
                have: data.len(),
                what: "emsg FullBox header",
            });
        }

        let size = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let box_type = [data[4], data[5], data[6], data[7]];
        if box_type != EMSG_BOX_TYPE {
            return Err(Error::NotEmsg { found: box_type });
        }
        let version = data[8];

        if (size as usize) < FULLBOX_HEADER_LEN {
            return Err(Error::InvalidSize {
                size,
                reason: "size smaller than the FullBox header (0/1 large-size forms unsupported)",
            });
        }
        if size as usize > data.len() {
            return Err(Error::InvalidSize {
                size,
                reason: "size exceeds available bytes",
            });
        }

        let version = EmsgVersion::from_u8(version).ok_or(Error::UnsupportedVersion { version })?;

        let body = &data[FULLBOX_HEADER_LEN..size as usize];

        match version {
            EmsgVersion::SegmentRelative => Self::parse_v0(body),
            EmsgVersion::RepresentationRelative => Self::parse_v1(body),
        }
    }

    fn parse_v0(body: &'a [u8]) -> Result<Self> {
        let (scheme_id_uri, rest) = parse_cstr(body, "scheme_id_uri")?;
        let (value, rest) = parse_cstr(rest, "value")?;

        let need = U32_LEN * 4;
        if rest.len() < need {
            return Err(Error::BufferTooShort {
                need,
                have: rest.len(),
                what: "emsg v0 integer fields",
            });
        }
        let timescale = read_u32(&rest[0..U32_LEN]);
        let delta = read_u32(&rest[U32_LEN..U32_LEN * 2]);
        let event_duration = read_u32(&rest[U32_LEN * 2..U32_LEN * 3]);
        let id = read_u32(&rest[U32_LEN * 3..U32_LEN * 4]);
        let message_data = &rest[need..];

        Ok(EmsgBox {
            scheme_id_uri,
            value,
            timescale,
            presentation_time: PresentationTime::Delta(delta),
            event_duration,
            id,
            message_data,
        })
    }

    fn parse_v1(body: &'a [u8]) -> Result<Self> {
        let need = U32_LEN + U64_LEN + U32_LEN + U32_LEN;
        if body.len() < need {
            return Err(Error::BufferTooShort {
                need,
                have: body.len(),
                what: "emsg v1 integer fields",
            });
        }
        let timescale = read_u32(&body[0..U32_LEN]);
        let presentation_time = read_u64(&body[U32_LEN..U32_LEN + U64_LEN]);
        let mut off = U32_LEN + U64_LEN;
        let event_duration = read_u32(&body[off..off + U32_LEN]);
        off += U32_LEN;
        let id = read_u32(&body[off..off + U32_LEN]);
        off += U32_LEN;

        let (scheme_id_uri, rest) = parse_cstr(&body[off..], "scheme_id_uri")?;
        let (value, message_data) = parse_cstr(rest, "value")?;

        Ok(EmsgBox {
            scheme_id_uri,
            value,
            timescale,
            presentation_time: PresentationTime::Absolute(presentation_time),
            event_duration,
            id,
            message_data,
        })
    }

    /// Serializes into `out`, returning the bytes written.
    pub fn serialize_into(&self, out: &mut [u8]) -> Result<usize> {
        let total = self.serialized_len();
        if out.len() < total {
            return Err(Error::OutputBufferTooSmall {
                need: total,
                have: out.len(),
            });
        }
        if total > u32::MAX as usize {
            return Err(Error::FieldTooWide {
                what: "size",
                value: total as u64,
                bits: 32,
            });
        }

        out[0..U32_LEN].copy_from_slice(&(total as u32).to_be_bytes());
        out[4..8].copy_from_slice(&EMSG_BOX_TYPE);
        out[8] = self.version().to_u8();

        out[9] = 0;
        out[10] = 0;
        out[11] = 0;

        let mut off = FULLBOX_HEADER_LEN;
        match self.presentation_time {
            PresentationTime::Delta(delta) => {
                off = write_cstr(out, off, self.scheme_id_uri);
                off = write_cstr(out, off, self.value);
                off = write_u32(out, off, self.timescale);
                off = write_u32(out, off, delta);
                off = write_u32(out, off, self.event_duration);
                off = write_u32(out, off, self.id);
            }
            PresentationTime::Absolute(pt) => {
                off = write_u32(out, off, self.timescale);
                off = write_u64(out, off, pt);
                off = write_u32(out, off, self.event_duration);
                off = write_u32(out, off, self.id);
                off = write_cstr(out, off, self.scheme_id_uri);
                off = write_cstr(out, off, self.value);
            }
        }
        out[off..off + self.message_data.len()].copy_from_slice(self.message_data);
        off += self.message_data.len();
        debug_assert_eq!(off, total);
        Ok(off)
    }

    /// Serializes into a new `Vec`.
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        let mut out = alloc::vec![0u8; self.serialized_len()];
        self.serialize_into(&mut out)?;
        Ok(out)
    }
}

/// URN prefix of SCTE-35 scheme IDs.
pub const SCTE35_SCHEME_PREFIX: &str = "urn:scte:scte35";

fn parse_cstr<'a>(data: &'a [u8], field: &'static str) -> Result<(&'a str, &'a [u8])> {
    let term = data
        .iter()
        .position(|&b| b == STRING_TERMINATOR)
        .ok_or(Error::InvalidString {
            field,
            reason: "missing null terminator",
        })?;
    let s = core::str::from_utf8(&data[..term]).map_err(|_| Error::InvalidString {
        field,
        reason: "invalid UTF-8",
    })?;
    Ok((s, &data[term + 1..]))
}

fn write_cstr(out: &mut [u8], off: usize, s: &str) -> usize {
    let bytes = s.as_bytes();
    out[off..off + bytes.len()].copy_from_slice(bytes);
    let term = off + bytes.len();
    out[term] = STRING_TERMINATOR;
    term + 1
}

fn read_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn read_u64(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

fn write_u32(out: &mut [u8], off: usize, v: u32) -> usize {
    out[off..off + U32_LEN].copy_from_slice(&v.to_be_bytes());
    off + U32_LEN
}

fn write_u64(out: &mut [u8], off: usize, v: u64) -> usize {
    out[off..off + U64_LEN].copy_from_slice(&v.to_be_bytes());
    off + U64_LEN
}