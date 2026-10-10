//! Sample-timing and segment-index boxes — ISO/IEC 14496-12:2015 §8.6/§8.16.

use crate::error::{Error, Result};
use alloc::vec::Vec;

use bitforge::{Parse, Serialize};

const BOX_HEADER_SIZE: usize = 8;
const FULLBOX_EXTRA_SIZE: usize = 4;

const STTS_TYPE: u32 = u32::from_be_bytes(*b"stts");
const CTTS_TYPE: u32 = u32::from_be_bytes(*b"ctts");
const CSLG_TYPE: u32 = u32::from_be_bytes(*b"cslg");
const ELST_TYPE: u32 = u32::from_be_bytes(*b"elst");
const SIDX_TYPE: u32 = u32::from_be_bytes(*b"sidx");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SttsEntry {
    pub sample_count: u32,
    pub sample_delta: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TimeToSampleBox {
    pub version: u8,
    pub flags: u32,
    pub entries: Vec<SttsEntry>,
}

impl TimeToSampleBox {

    pub fn parse_body(body: &[u8]) -> Result<Self> {
        if body.len() < FULLBOX_EXTRA_SIZE + 4 {
            return Err(Error::BufferTooShort {
                need: FULLBOX_EXTRA_SIZE + 4,
                have: body.len(),
                what: "stts body",
            });
        }
        let version = body[0];
        let flags = u32::from_be_bytes([0, body[1], body[2], body[3]]);
        let entry_count = u32::from_be_bytes([body[4], body[5], body[6], body[7]]) as usize;
        let mut c = FULLBOX_EXTRA_SIZE + 4;
        let mut entries = Vec::with_capacity(super::bounded_capacity(
            entry_count,
            8,
            body.len().saturating_sub(c),
        ));
        for _ in 0..entry_count {
            if body.len() < c + 8 {
                return Err(Error::BufferTooShort {
                    need: c + 8,
                    have: body.len(),
                    what: "stts entry",
                });
            }
            let sample_count = u32::from_be_bytes([body[c], body[c + 1], body[c + 2], body[c + 3]]);
            let sample_delta =
                u32::from_be_bytes([body[c + 4], body[c + 5], body[c + 6], body[c + 7]]);
            entries.push(SttsEntry {
                sample_count,
                sample_delta,
            });
            c += 8;
        }
        Ok(Self {
            version,
            flags,
            entries,
        })
    }
}

impl<'a> Parse<'a> for TimeToSampleBox {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < BOX_HEADER_SIZE + FULLBOX_EXTRA_SIZE + 4 {
            return Err(Error::BufferTooShort {
                need: BOX_HEADER_SIZE + FULLBOX_EXTRA_SIZE + 4,
                have: bytes.len(),
                what: "stts box",
            });
        }
        let ty = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if ty != STTS_TYPE {
            return Err(Error::InvalidValue {
                field: "box_type",
                value: ty as u64,
                reason: "expected stts",
            });
        }
        Self::parse_body(&bytes[BOX_HEADER_SIZE..])
    }
}

impl Serialize for TimeToSampleBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        BOX_HEADER_SIZE + FULLBOX_EXTRA_SIZE + 4 + self.entries.len() * 8
    }
    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut c = 0;
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"stts");
        c += 4;
        buf[c] = self.version;
        let fb = self.flags.to_be_bytes();
        buf[c + 1] = fb[1];
        buf[c + 2] = fb[2];
        buf[c + 3] = fb[3];
        c += 4;
        buf[c..c + 4].copy_from_slice(&(self.entries.len() as u32).to_be_bytes());
        c += 4;
        for entry in &self.entries {
            buf[c..c + 4].copy_from_slice(&entry.sample_count.to_be_bytes());
            buf[c + 4..c + 8].copy_from_slice(&entry.sample_delta.to_be_bytes());
            c += 8;
        }
        Ok(c)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct CttsEntry {
    pub sample_count: u32,

    pub sample_offset: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct CompositionOffsetBox {
    pub version: u8,
    pub flags: u32,
    pub entries: Vec<CttsEntry>,
}

impl CompositionOffsetBox {

    pub fn parse_body(body: &[u8]) -> Result<Self> {
        if body.len() < FULLBOX_EXTRA_SIZE + 4 {
            return Err(Error::BufferTooShort {
                need: FULLBOX_EXTRA_SIZE + 4,
                have: body.len(),
                what: "ctts body",
            });
        }
        let version = body[0];
        let flags = u32::from_be_bytes([0, body[1], body[2], body[3]]);
        let entry_count = u32::from_be_bytes([body[4], body[5], body[6], body[7]]) as usize;
        let entry_size: usize = 8;
        let mut c = FULLBOX_EXTRA_SIZE + 4;
        let mut entries = Vec::with_capacity(super::bounded_capacity(
            entry_count,
            8,
            body.len().saturating_sub(c),
        ));
        for _ in 0..entry_count {
            if body.len() < c + entry_size {
                return Err(Error::BufferTooShort {
                    need: c + entry_size,
                    have: body.len(),
                    what: "ctts entry",
                });
            }
            let sample_count = u32::from_be_bytes([body[c], body[c + 1], body[c + 2], body[c + 3]]);
            let raw_offset =
                u32::from_be_bytes([body[c + 4], body[c + 5], body[c + 6], body[c + 7]]);
            let sample_offset = raw_offset as i32;
            entries.push(CttsEntry {
                sample_count,
                sample_offset,
            });
            c += entry_size;
        }
        Ok(Self {
            version,
            flags,
            entries,
        })
    }
}

impl<'a> Parse<'a> for CompositionOffsetBox {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < BOX_HEADER_SIZE + FULLBOX_EXTRA_SIZE + 4 {
            return Err(Error::BufferTooShort {
                need: BOX_HEADER_SIZE + FULLBOX_EXTRA_SIZE + 4,
                have: bytes.len(),
                what: "ctts box",
            });
        }
        let ty = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if ty != CTTS_TYPE {
            return Err(Error::InvalidValue {
                field: "box_type",
                value: ty as u64,
                reason: "expected ctts",
            });
        }
        Self::parse_body(&bytes[BOX_HEADER_SIZE..])
    }
}

impl Serialize for CompositionOffsetBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        BOX_HEADER_SIZE + FULLBOX_EXTRA_SIZE + 4 + self.entries.len() * 8
    }
    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut c = 0;
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"ctts");
        c += 4;
        buf[c] = self.version;
        let fb = self.flags.to_be_bytes();
        buf[c + 1] = fb[1];
        buf[c + 2] = fb[2];
        buf[c + 3] = fb[3];
        c += 4;
        buf[c..c + 4].copy_from_slice(&(self.entries.len() as u32).to_be_bytes());
        c += 4;
        for entry in &self.entries {
            buf[c..c + 4].copy_from_slice(&entry.sample_count.to_be_bytes());
            buf[c + 4..c + 8].copy_from_slice(&(entry.sample_offset as u32).to_be_bytes());
            c += 8;
        }
        Ok(c)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct CompositionToDecodeBox {
    pub version: u8,
    pub flags: u32,
    pub composition_to_dts_shift: i64,
    pub least_decode_to_display_delta: i64,
    pub greatest_decode_to_display_delta: i64,
    pub composition_start_time: i64,
    pub composition_end_time: i64,
}

impl CompositionToDecodeBox {

    pub fn parse_body(body: &[u8]) -> Result<Self> {
        if body.len() < FULLBOX_EXTRA_SIZE + 4 {
            return Err(Error::BufferTooShort {
                need: FULLBOX_EXTRA_SIZE + 4,
                have: body.len(),
                what: "cslg body",
            });
        }
        let version = body[0];
        let flags = u32::from_be_bytes([0, body[1], body[2], body[3]]);
        let payload = &body[FULLBOX_EXTRA_SIZE..];
        let (fld_size, have): (usize, &str) = if version == 0 {
            (4, "cslg v0 field")
        } else {
            (8, "cslg v1 field")
        };
        if payload.len() < fld_size * 5 {
            return Err(Error::BufferTooShort {
                need: FULLBOX_EXTRA_SIZE + fld_size * 5,
                have: body.len(),
                what: have,
            });
        }
        let mut c = 0usize;
        let read_i64 = |buf: &[u8], off: usize, sz: usize| -> i64 {
            if sz == 4 {
                i32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as i64
            } else {
                i64::from_be_bytes([
                    buf[off],
                    buf[off + 1],
                    buf[off + 2],
                    buf[off + 3],
                    buf[off + 4],
                    buf[off + 5],
                    buf[off + 6],
                    buf[off + 7],
                ])
            }
        };
        let composition_to_dts_shift = read_i64(payload, c, fld_size);
        c += fld_size;
        let least_decode_to_display_delta = read_i64(payload, c, fld_size);
        c += fld_size;
        let greatest_decode_to_display_delta = read_i64(payload, c, fld_size);
        c += fld_size;
        let composition_start_time = read_i64(payload, c, fld_size);
        c += fld_size;
        let composition_end_time = read_i64(payload, c, fld_size);
        Ok(Self {
            version,
            flags,
            composition_to_dts_shift,
            least_decode_to_display_delta,
            greatest_decode_to_display_delta,
            composition_start_time,
            composition_end_time,
        })
    }
}

impl<'a> Parse<'a> for CompositionToDecodeBox {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < BOX_HEADER_SIZE + FULLBOX_EXTRA_SIZE + 4 {
            return Err(Error::BufferTooShort {
                need: BOX_HEADER_SIZE + FULLBOX_EXTRA_SIZE + 4,
                have: bytes.len(),
                what: "cslg box",
            });
        }
        let ty = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if ty != CSLG_TYPE {
            return Err(Error::InvalidValue {
                field: "box_type",
                value: ty as u64,
                reason: "expected cslg",
            });
        }
        Self::parse_body(&bytes[BOX_HEADER_SIZE..])
    }
}

impl Serialize for CompositionToDecodeBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        let fld = if self.version == 0 { 4 } else { 8 };
        BOX_HEADER_SIZE + FULLBOX_EXTRA_SIZE + fld * 5
    }
    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut c = 0;
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"cslg");
        c += 4;
        buf[c] = self.version;
        let fb = self.flags.to_be_bytes();
        buf[c + 1] = fb[1];
        buf[c + 2] = fb[2];
        buf[c + 3] = fb[3];
        c += 4;
        let write_i64 = |buf: &mut [u8], off: usize, sz: usize, v: i64| {
            if sz == 4 {
                buf[off..off + 4].copy_from_slice(&(v as i32).to_be_bytes());
            } else {
                buf[off..off + 8].copy_from_slice(&v.to_be_bytes());
            }
        };
        let fld = if self.version == 0 { 4 } else { 8 };
        write_i64(buf, c, fld, self.composition_to_dts_shift);
        c += fld;
        write_i64(buf, c, fld, self.least_decode_to_display_delta);
        c += fld;
        write_i64(buf, c, fld, self.greatest_decode_to_display_delta);
        c += fld;
        write_i64(buf, c, fld, self.composition_start_time);
        c += fld;
        write_i64(buf, c, fld, self.composition_end_time);
        Ok(c + fld)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct EditListEntry {
    pub segment_duration: u64,
    pub media_time: i64,
    pub media_rate_integer: i16,
    pub media_rate_fraction: i16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct EditListBox {
    pub version: u8,
    pub flags: u32,
    pub entries: Vec<EditListEntry>,
}

impl EditListBox {

    pub fn parse_body(body: &[u8]) -> Result<Self> {
        if body.len() < FULLBOX_EXTRA_SIZE + 4 {
            return Err(Error::BufferTooShort {
                need: FULLBOX_EXTRA_SIZE + 4,
                have: body.len(),
                what: "elst body",
            });
        }
        let version = body[0];
        let flags = u32::from_be_bytes([0, body[1], body[2], body[3]]);
        let entry_count = u32::from_be_bytes([body[4], body[5], body[6], body[7]]) as usize;
        let entry_size: usize = if version == 0 { 4 + 4 + 4 } else { 8 + 8 + 4 };
        let mut c = FULLBOX_EXTRA_SIZE + 4;
        let mut entries = Vec::with_capacity(super::bounded_capacity(
            entry_count,
            entry_size,
            body.len().saturating_sub(c),
        ));
        for _ in 0..entry_count {
            if body.len() < c + entry_size {
                return Err(Error::BufferTooShort {
                    need: c + entry_size,
                    have: body.len(),
                    what: "elst entry",
                });
            }
            let (segment_duration, media_time) = if version == 0 {
                let sd =
                    u32::from_be_bytes([body[c], body[c + 1], body[c + 2], body[c + 3]]) as u64;
                let mt_raw =
                    u32::from_be_bytes([body[c + 4], body[c + 5], body[c + 6], body[c + 7]]);
                let mt = mt_raw as i32 as i64;
                c += 8;
                (sd, mt)
            } else {
                let sd = u64::from_be_bytes([
                    body[c],
                    body[c + 1],
                    body[c + 2],
                    body[c + 3],
                    body[c + 4],
                    body[c + 5],
                    body[c + 6],
                    body[c + 7],
                ]);
                let mt = i64::from_be_bytes([
                    body[c + 8],
                    body[c + 9],
                    body[c + 10],
                    body[c + 11],
                    body[c + 12],
                    body[c + 13],
                    body[c + 14],
                    body[c + 15],
                ]);
                c += 16;
                (sd, mt)
            };
            let mr_int = i16::from_be_bytes([body[c], body[c + 1]]);
            let mr_frac = i16::from_be_bytes([body[c + 2], body[c + 3]]);
            c += 4;
            entries.push(EditListEntry {
                segment_duration,
                media_time,
                media_rate_integer: mr_int,
                media_rate_fraction: mr_frac,
            });
        }
        Ok(Self {
            version,
            flags,
            entries,
        })
    }
}

impl<'a> Parse<'a> for EditListBox {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < BOX_HEADER_SIZE + FULLBOX_EXTRA_SIZE + 4 {
            return Err(Error::BufferTooShort {
                need: BOX_HEADER_SIZE + FULLBOX_EXTRA_SIZE + 4,
                have: bytes.len(),
                what: "elst box",
            });
        }
        let ty = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if ty != ELST_TYPE {
            return Err(Error::InvalidValue {
                field: "box_type",
                value: ty as u64,
                reason: "expected elst",
            });
        }
        Self::parse_body(&bytes[BOX_HEADER_SIZE..])
    }
}

impl Serialize for EditListBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        let entry_wire = if self.version == 0 { 12 } else { 20 };
        BOX_HEADER_SIZE + FULLBOX_EXTRA_SIZE + 4 + self.entries.len() * entry_wire
    }
    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut c = 0;
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"elst");
        c += 4;
        buf[c] = self.version;
        let fb = self.flags.to_be_bytes();
        buf[c + 1] = fb[1];
        buf[c + 2] = fb[2];
        buf[c + 3] = fb[3];
        c += 4;
        buf[c..c + 4].copy_from_slice(&(self.entries.len() as u32).to_be_bytes());
        c += 4;
        for entry in &self.entries {
            if self.version == 0 {
                buf[c..c + 4].copy_from_slice(&(entry.segment_duration as u32).to_be_bytes());
                buf[c + 4..c + 8].copy_from_slice(&(entry.media_time as u32).to_be_bytes());
                c += 8;
            } else {
                buf[c..c + 8].copy_from_slice(&entry.segment_duration.to_be_bytes());
                buf[c + 8..c + 16].copy_from_slice(&entry.media_time.to_be_bytes());
                c += 16;
            }
            buf[c..c + 2].copy_from_slice(&entry.media_rate_integer.to_be_bytes());
            buf[c + 2..c + 4].copy_from_slice(&entry.media_rate_fraction.to_be_bytes());
            c += 4;
        }
        Ok(c)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SidxReference {
    pub reference_type: u8,
    pub referenced_size: u32,
    pub subsegment_duration: u32,
    pub starts_with_sap: u8,
    pub sap_type: u8,
    pub sap_delta_time: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SegmentIndexBox {
    pub version: u8,
    pub flags: u32,
    pub reference_id: u32,
    pub timescale: u32,
    pub earliest_presentation_time: u64,
    pub first_offset: u64,
    pub references: Vec<SidxReference>,
}

impl SegmentIndexBox {

    pub fn parse_body(body: &[u8]) -> Result<Self> {
        if body.len() < FULLBOX_EXTRA_SIZE + 4 + 4 + 4 + 2 {
            return Err(Error::BufferTooShort {
                need: FULLBOX_EXTRA_SIZE + 4 + 4 + 4 + 2,
                have: body.len(),
                what: "sidx body",
            });
        }
        let version = body[0];
        let flags = u32::from_be_bytes([0, body[1], body[2], body[3]]);
        let hdr_need = FULLBOX_EXTRA_SIZE + 4 + 4 + if version == 0 { 8 } else { 16 } + 2 + 2;
        if body.len() < hdr_need {
            return Err(Error::BufferTooShort {
                need: hdr_need,
                have: body.len(),
                what: "sidx body (version-dependent header)",
            });
        }
        let mut c = FULLBOX_EXTRA_SIZE;
        let reference_id = u32::from_be_bytes([body[c], body[c + 1], body[c + 2], body[c + 3]]);
        c += 4;
        let timescale = u32::from_be_bytes([body[c], body[c + 1], body[c + 2], body[c + 3]]);
        c += 4;
        let (ept, first_offset) = if version == 0 {
            let ept = u32::from_be_bytes([body[c], body[c + 1], body[c + 2], body[c + 3]]) as u64;
            c += 4;
            let fo = u32::from_be_bytes([body[c], body[c + 1], body[c + 2], body[c + 3]]) as u64;
            c += 4;
            (ept, fo)
        } else {
            let ept = u64::from_be_bytes([
                body[c],
                body[c + 1],
                body[c + 2],
                body[c + 3],
                body[c + 4],
                body[c + 5],
                body[c + 6],
                body[c + 7],
            ]);
            c += 8;
            let fo = u64::from_be_bytes([
                body[c],
                body[c + 1],
                body[c + 2],
                body[c + 3],
                body[c + 4],
                body[c + 5],
                body[c + 6],
                body[c + 7],
            ]);
            c += 8;
            (ept, fo)
        };
        if body.len() < c + 4 {
            return Err(Error::BufferTooShort {
                need: c + 4,
                have: body.len(),
                what: "sidx reserved+count",
            });
        }
        c += 2;
        let reference_count = u16::from_be_bytes([body[c], body[c + 1]]) as usize;
        c += 2;

        let mut references = Vec::with_capacity(super::bounded_capacity(
            reference_count,
            12,
            body.len().saturating_sub(c),
        ));
        for _ in 0..reference_count {
            if body.len() < c + 12 {
                return Err(Error::BufferTooShort {
                    need: c + 12,
                    have: body.len(),
                    what: "sidx reference entry",
                });
            }

            let raw_ref = u32::from_be_bytes([body[c], body[c + 1], body[c + 2], body[c + 3]]);
            let reference_type = ((raw_ref >> 31) & 1) as u8;
            let referenced_size = raw_ref & 0x7FFF_FFFF;
            c += 4;
            let subsegment_duration =
                u32::from_be_bytes([body[c], body[c + 1], body[c + 2], body[c + 3]]);
            c += 4;

            let raw_sap = u32::from_be_bytes([body[c], body[c + 1], body[c + 2], body[c + 3]]);
            let starts_with_sap = ((raw_sap >> 31) & 1) as u8;
            let sap_type = ((raw_sap >> 28) & 0x7) as u8;
            let sap_delta_time = raw_sap & 0x0FFF_FFFF;
            c += 4;
            references.push(SidxReference {
                reference_type,
                referenced_size,
                subsegment_duration,
                starts_with_sap,
                sap_type,
                sap_delta_time,
            });
        }
        Ok(Self {
            version,
            flags,
            reference_id,
            timescale,
            earliest_presentation_time: ept,
            first_offset,
            references,
        })
    }
}

impl<'a> Parse<'a> for SegmentIndexBox {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < BOX_HEADER_SIZE + FULLBOX_EXTRA_SIZE + 4 {
            return Err(Error::BufferTooShort {
                need: BOX_HEADER_SIZE + FULLBOX_EXTRA_SIZE + 4,
                have: bytes.len(),
                what: "sidx box",
            });
        }
        let ty = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if ty != SIDX_TYPE {
            return Err(Error::InvalidValue {
                field: "box_type",
                value: ty as u64,
                reason: "expected sidx",
            });
        }
        Self::parse_body(&bytes[BOX_HEADER_SIZE..])
    }
}

impl Serialize for SegmentIndexBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        let time_size: usize = if self.version == 0 { 4 } else { 8 };
        BOX_HEADER_SIZE
            + FULLBOX_EXTRA_SIZE
            + 4
            + 4
            + time_size
            + time_size
            + 2
            + 2
            + self.references.len() * 12
    }
    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut c = 0;
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"sidx");
        c += 4;
        buf[c] = self.version;
        let fb = self.flags.to_be_bytes();
        buf[c + 1] = fb[1];
        buf[c + 2] = fb[2];
        buf[c + 3] = fb[3];
        c += 4;
        buf[c..c + 4].copy_from_slice(&self.reference_id.to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(&self.timescale.to_be_bytes());
        c += 4;
        if self.version == 0 {
            buf[c..c + 4].copy_from_slice(&(self.earliest_presentation_time as u32).to_be_bytes());
            c += 4;
            buf[c..c + 4].copy_from_slice(&(self.first_offset as u32).to_be_bytes());
            c += 4;
        } else {
            buf[c..c + 8].copy_from_slice(&self.earliest_presentation_time.to_be_bytes());
            c += 8;
            buf[c..c + 8].copy_from_slice(&self.first_offset.to_be_bytes());
            c += 8;
        }
        buf[c..c + 2].copy_from_slice(&0u16.to_be_bytes()); // reserved
        c += 2;
        buf[c..c + 2].copy_from_slice(&(self.references.len() as u16).to_be_bytes());
        c += 2;
        for r in &self.references {
            let raw_ref = ((r.reference_type as u32) << 31) | (r.referenced_size & 0x7FFF_FFFF);
            buf[c..c + 4].copy_from_slice(&raw_ref.to_be_bytes());
            c += 4;
            buf[c..c + 4].copy_from_slice(&r.subsegment_duration.to_be_bytes());
            c += 4;
            let raw_sap = ((r.starts_with_sap as u32) << 31)
                | ((r.sap_type as u32) << 28)
                | (r.sap_delta_time & 0x0FFF_FFFF);
            buf[c..c + 4].copy_from_slice(&raw_sap.to_be_bytes());
            c += 4;
        }
        Ok(c)
    }
}

#[cfg(test)]
mod hardening_tests {
    use super::*;

    fn fullbox_body(count: u32, extra: &[u8]) -> Vec<u8> {
        let mut v = alloc::vec![0, 0, 0, 0];
        v.extend_from_slice(&count.to_be_bytes());
        v.extend_from_slice(extra);
        v
    }

    #[test]
    fn sidx_follows_the_iso_layout_and_round_trips() {
        let mut b: Vec<u8> = Vec::new();
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(b"sidx");
        b.extend_from_slice(&[0, 0, 0, 0]);
        b.extend_from_slice(&1u32.to_be_bytes());
        b.extend_from_slice(&90_000u32.to_be_bytes());
        b.extend_from_slice(&1_000u32.to_be_bytes());
        b.extend_from_slice(&2_000u32.to_be_bytes());
        b.extend_from_slice(&0u16.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&(0x8000_0000u32 | 1234).to_be_bytes());
        b.extend_from_slice(&3_000u32.to_be_bytes());
        b.extend_from_slice(&(0x9000_0000u32 | 5).to_be_bytes());
        let len = b.len() as u32;
        b[0..4].copy_from_slice(&len.to_be_bytes());

        let parsed = SegmentIndexBox::parse(&b).unwrap();
        assert_eq!(parsed.references.len(), 1);
        assert_eq!(parsed.references[0].referenced_size, 1234);
        assert_eq!(parsed.references[0].reference_type, 1);
        assert_eq!(parsed.references[0].sap_type, 1);
        assert_eq!(parsed.references[0].sap_delta_time, 5);
        assert_eq!(parsed.first_offset, 2_000);

        let mut out = alloc::vec![0u8; parsed.serialized_len()];
        let n = parsed.serialize_into(&mut out).unwrap();
        assert_eq!(&out[..n], &b[..]);
    }

    #[test]
    fn stts_ctts_elst_huge_count_errors() {
        let b = fullbox_body(u32::MAX, &[0; 8]);
        assert!(TimeToSampleBox::parse_body(&b).is_err());
        assert!(CompositionOffsetBox::parse_body(&b).is_err());
        assert!(EditListBox::parse_body(&b).is_err());
        let b = fullbox_body(0, &[]);
        assert!(TimeToSampleBox::parse_body(&b).unwrap().entries.is_empty());
    }

    #[test]
    fn sidx_truncated_headers_error() {
        for version in [0u8, 1] {
            // Passes the old minimum-length check (14 bytes) but not the real header size.
            let mut b = alloc::vec![version, 0, 0, 0];
            b.extend_from_slice(&[0; 10]);
            assert!(SegmentIndexBox::parse_body(&b).is_err());
        }
        // v0 header complete, reference_count huge, no entries.
        let mut b = alloc::vec![0u8, 0, 0, 0];
        b.extend_from_slice(&[0; 16]);
        b.extend_from_slice(&[0xFF, 0xFF]);
        assert!(SegmentIndexBox::parse_body(&b).is_err());
    }
}
