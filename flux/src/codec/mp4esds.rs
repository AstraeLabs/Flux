//! MPEG-4 elementary-stream descriptor chain (`esds` box)

use crate::box_types::BoxHeader;
use crate::error::{Error, Result};
use alloc::vec::Vec;
use bitforge::{Parse, Serialize};
use core::fmt;

const BOX_HEADER_SIZE: usize = 8;

const FULLBOX_EXTRA: usize = 4;

const TAG_ES_DESCRIPTOR: u8 = 0x03;
const TAG_DECODER_CONFIG: u8 = 0x04;
const TAG_DECODER_SPECIFIC_INFO: u8 = 0x05;
const TAG_SL_CONFIG: u8 = 0x06;

const MAX_DESCRIPTOR_SIZE: usize = 268_435_455;

const MAX_VARINT_BYTES: usize = 4;

const VARINT_WIDTH_FIXED: usize = 4;

const DECODER_CONFIG_FIXED: usize = 13;

fn read_u24_be(bytes: &[u8], cursor: &mut usize, what: &'static str) -> Result<u32> {
    if *cursor + 3 > bytes.len() {
        return Err(Error::BufferTooShort {
            need: *cursor + 3,
            have: bytes.len(),
            what,
        });
    }
    let v = u32::from_be_bytes([0, bytes[*cursor], bytes[*cursor + 1], bytes[*cursor + 2]]);
    *cursor += 3;
    Ok(v)
}

fn read_u32_be(bytes: &[u8], cursor: &mut usize, what: &'static str) -> Result<u32> {
    if *cursor + 4 > bytes.len() {
        return Err(Error::BufferTooShort {
            need: *cursor + 4,
            have: bytes.len(),
            what,
        });
    }
    let v = u32::from_be_bytes([
        bytes[*cursor],
        bytes[*cursor + 1],
        bytes[*cursor + 2],
        bytes[*cursor + 3],
    ]);
    *cursor += 4;
    Ok(v)
}

fn parse_varint(bytes: &[u8], cursor: &mut usize) -> Result<(usize, usize)> {
    let start = *cursor;
    let mut value: usize = 0;
    loop {
        if *cursor >= bytes.len() {
            return Err(Error::BufferTooShort {
                need: *cursor + 1,
                have: bytes.len(),
                what: "descriptor size varint",
            });
        }
        let b = bytes[*cursor];
        *cursor += 1;
        value = (value << 7) | (b & 0x7F) as usize; // bounded by MAX_VARINT_BYTES (<= 28 bits)
        let bytes_so_far = *cursor - start;
        if bytes_so_far > MAX_VARINT_BYTES {
            return Err(Error::InvalidValue {
                field: "descriptor size varint",
                value: bytes_so_far as u64,
                reason: "varint longer than 4 bytes",
            });
        }
        if (b & 0x80) == 0 {
            break;
        }
    }
    if value > MAX_DESCRIPTOR_SIZE {
        return Err(Error::InvalidValue {
            field: "descriptor size",
            value: value as u64,
            reason: "exceeds maximum descriptor size (2^28-1)",
        });
    }
    Ok((value, *cursor - start))
}

fn write_varint_fixed(buf: &mut [u8], cursor: &mut usize, value: usize) -> Result<()> {
    if *cursor + 4 > buf.len() {
        return Err(Error::OutputBufferTooSmall {
            need: *cursor + 4,
            have: buf.len(),
        });
    }
    buf[*cursor] = 0x80 | ((value >> 21) as u8);
    buf[*cursor + 1] = 0x80 | ((value >> 14) as u8);
    buf[*cursor + 2] = 0x80 | ((value >> 7) as u8);
    buf[*cursor + 3] = (value & 0x7F) as u8;
    *cursor += 4;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ObjectTypeIndication(pub u8);

impl ObjectTypeIndication {
    pub fn name(&self) -> &str {
        match self.0 {
            0x20 => "MPEG-4 Visual",
            0x21 => "AVC / H.264",
            0x22 => "AVC parameter sets",
            0x40 => "MPEG-4 Audio / AAC",
            0x60 => "MPEG-2 Video Simple",
            0x61 => "MPEG-2 Video Main",
            0x62 => "MPEG-2 Video SNR",
            0x63 => "MPEG-2 Video Spatial",
            0x64 => "MPEG-2 Video High",
            0x65 => "MPEG-2 Video 422",
            0x66 => "MPEG-2 AAC LC",
            0x67 => "MPEG-2 AAC Main",
            0x68 => "MPEG-2 AAC SSR",
            0x69 => "MPEG-2 Audio (13818-3)",
            0x6A => "MPEG-1 Visual (11172-2)",
            0x6B => "MPEG-1 Audio (11172-3)",
            0x6C => "JPEG",
            0x6E => "JPEG 2000",
            0xFF => "no object type",
            _ => "user-private",
        }
    }
}

impl fmt::Display for ObjectTypeIndication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{:02X})", self.name(), self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct StreamType(pub u8);

impl StreamType {
    pub fn name(&self) -> &str {
        match self.0 {
            0x01 => "ObjectDescriptorStream",
            0x02 => "ClockReferenceStream",
            0x03 => "SceneDescriptionStream",
            0x04 => "VisualStream",
            0x05 => "AudioStream",
            0x06 => "MPEG7Stream",
            0x07 => "IPMPStream",
            0x08 => "ObjectContentInfoStream",
            0x09 => "MPEGJStream",
            0x0A..=0x1F => "reserved",
            0x20..=0x3F => "user-private",
            _ => "forbidden",
        }
    }
}

impl fmt::Display for StreamType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{:02X})", self.name(), self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct DecoderSpecificInfo {
    pub data: Vec<u8>,
}

impl DecoderSpecificInfo {
    const TAG: u8 = TAG_DECODER_SPECIFIC_INFO;
}

impl<'a> Parse<'a> for DecoderSpecificInfo {
    type Error = Error;

    fn parse(body: &'a [u8]) -> Result<Self> {
        Ok(Self {
            data: body.to_vec(),
        })
    }
}

impl Serialize for DecoderSpecificInfo {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        1 + VARINT_WIDTH_FIXED + self.data.len()
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut cursor = 0usize;
        buf[cursor] = Self::TAG;
        cursor += 1;
        write_varint_fixed(buf, &mut cursor, self.data.len())?;
        buf[cursor..cursor + self.data.len()].copy_from_slice(&self.data);
        cursor += self.data.len();
        Ok(cursor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SLConfigDescriptor {
    pub body: Vec<u8>,
}

impl SLConfigDescriptor {
    const TAG: u8 = TAG_SL_CONFIG;
}

impl<'a> Parse<'a> for SLConfigDescriptor {
    type Error = Error;

    fn parse(body: &'a [u8]) -> Result<Self> {
        Ok(Self {
            body: body.to_vec(),
        })
    }
}

impl Serialize for SLConfigDescriptor {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        1 + VARINT_WIDTH_FIXED + self.body.len()
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut cursor = 0usize;
        buf[cursor] = Self::TAG;
        cursor += 1;
        write_varint_fixed(buf, &mut cursor, self.body.len())?;
        buf[cursor..cursor + self.body.len()].copy_from_slice(&self.body);
        cursor += self.body.len();
        Ok(cursor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct DecoderConfigDescriptor {
    pub object_type_indication: ObjectTypeIndication,
    pub stream_type: StreamType,
    pub up_stream: bool,
    pub buffer_size_db: u32,
    pub max_bitrate: u32,
    pub avg_bitrate: u32,
    pub decoder_specific_info: Option<DecoderSpecificInfo>,
}

impl DecoderConfigDescriptor {
    const TAG: u8 = TAG_DECODER_CONFIG;
}

impl<'a> Parse<'a> for DecoderConfigDescriptor {
    type Error = Error;

    fn parse(body: &'a [u8]) -> Result<Self> {
        let mut cursor = 0usize;

        if cursor >= body.len() {
            return Err(Error::BufferTooShort {
                need: 1,
                have: body.len(),
                what: "objectTypeIndication",
            });
        }
        let oti = ObjectTypeIndication(body[cursor]);
        cursor += 1;

        if cursor >= body.len() {
            return Err(Error::BufferTooShort {
                need: cursor + 1,
                have: body.len(),
                what: "streamType/upStream",
            });
        }
        let st_byte = body[cursor];
        let stream_type_val = (st_byte >> 2) & 0x3F;
        let up_stream = ((st_byte >> 1) & 0x01) != 0;
        let _reserved = (st_byte & 0x01) != 0;
        cursor += 1;

        let buffer_size_db = read_u24_be(body, &mut cursor, "bufferSizeDB")?;

        let max_bitrate = read_u32_be(body, &mut cursor, "maxBitrate")?;

        let avg_bitrate = read_u32_be(body, &mut cursor, "avgBitrate")?;

        let mut decoder_specific_info = None;
        while cursor < body.len() {
            if cursor >= body.len() {
                break;
            }
            let sub_tag = body[cursor];
            cursor += 1;
            let (sub_size, _) = parse_varint(body, &mut cursor)?;
            let sub_body = if cursor + sub_size <= body.len() {
                &body[cursor..cursor + sub_size]
            } else {
                return Err(Error::BufferTooShort {
                    need: cursor + sub_size,
                    have: body.len(),
                    what: "DecoderConfigDescriptor sub_descriptor body",
                });
            };

            if sub_tag == TAG_DECODER_SPECIFIC_INFO {
                decoder_specific_info = Some(DecoderSpecificInfo::parse(sub_body)?);
            }
            cursor += sub_size;
        }

        Ok(Self {
            object_type_indication: oti,
            stream_type: StreamType(stream_type_val),
            up_stream,
            buffer_size_db,
            max_bitrate,
            avg_bitrate,
            decoder_specific_info,
        })
    }
}

impl Serialize for DecoderConfigDescriptor {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        1
            + VARINT_WIDTH_FIXED
            + DECODER_CONFIG_FIXED
            + self.decoder_specific_info.as_ref().map_or(0, |dsi| dsi.serialized_len())
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut cursor = 0usize;
        buf[cursor] = Self::TAG;
        cursor += 1;
        let body_size = DECODER_CONFIG_FIXED
            + self
                .decoder_specific_info
                .as_ref()
                .map_or(0, |dsi| dsi.serialized_len());
        write_varint_fixed(buf, &mut cursor, body_size)?;
        buf[cursor] = self.object_type_indication.0;
        cursor += 1;
        buf[cursor] = ((self.stream_type.0 & 0x3F) << 2) | ((self.up_stream as u8) << 1) | 0x01;
        cursor += 1;
        buf[cursor..cursor + 3].copy_from_slice(&[
            (self.buffer_size_db >> 16) as u8,
            (self.buffer_size_db >> 8) as u8,
            self.buffer_size_db as u8,
        ]);
        cursor += 3;
        buf[cursor..cursor + 4].copy_from_slice(&self.max_bitrate.to_be_bytes());
        cursor += 4;
        buf[cursor..cursor + 4].copy_from_slice(&self.avg_bitrate.to_be_bytes());
        cursor += 4;
        if let Some(ref dsi) = self.decoder_specific_info {
            cursor += dsi.serialize_into(&mut buf[cursor..])?;
        }
        Ok(cursor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ESDescriptor {
    pub es_id: u16,
    pub stream_dependence_flag: bool,
    pub url_flag: bool,
    pub ocr_stream_flag: bool,
    pub stream_priority: u8,
    pub depends_on_es_id: Option<u16>,
    pub url: Option<alloc::string::String>,
    pub ocr_es_id: Option<u16>,
    pub decoder_config: Option<DecoderConfigDescriptor>,
    pub sl_config: Option<SLConfigDescriptor>,
}

impl ESDescriptor {
    const TAG: u8 = TAG_ES_DESCRIPTOR;
}

impl<'a> Parse<'a> for ESDescriptor {
    type Error = Error;

    fn parse(body: &'a [u8]) -> Result<Self> {
        let mut cursor = 0usize;

        if cursor + 2 > body.len() {
            return Err(Error::BufferTooShort {
                need: cursor + 2,
                have: body.len(),
                what: "ES_ID",
            });
        }
        let es_id = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
        cursor += 2;

        if cursor >= body.len() {
            return Err(Error::BufferTooShort {
                need: cursor + 1,
                have: body.len(),
                what: "ES flags byte",
            });
        }
        let flags = body[cursor];
        cursor += 1;
        let stream_dependence_flag = (flags & 0x80) != 0;
        let url_flag = (flags & 0x40) != 0;
        let ocr_stream_flag = (flags & 0x20) != 0;
        let stream_priority = flags & 0x1F;

        let depends_on_es_id = if stream_dependence_flag {
            if cursor + 2 > body.len() {
                return Err(Error::BufferTooShort {
                    need: cursor + 2,
                    have: body.len(),
                    what: "dependsOn_ES_ID",
                });
            }
            let v = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
            cursor += 2;
            Some(v)
        } else {
            None
        };

        let url = if url_flag {
            if cursor >= body.len() {
                return Err(Error::BufferTooShort {
                    need: cursor + 1,
                    have: body.len(),
                    what: "URLLength",
                });
            }
            let url_len = body[cursor] as usize;
            cursor += 1;
            if cursor + url_len > body.len() {
                return Err(Error::BufferTooShort {
                    need: cursor + url_len,
                    have: body.len(),
                    what: "URLstring",
                });
            }
            let u = alloc::string::String::from_utf8_lossy(&body[cursor..cursor + url_len])
                .into_owned();
            cursor += url_len;
            Some(u)
        } else {
            None
        };

        let ocr_es_id = if ocr_stream_flag {
            if cursor + 2 > body.len() {
                return Err(Error::BufferTooShort {
                    need: cursor + 2,
                    have: body.len(),
                    what: "OCR_ES_Id",
                });
            }
            let v = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
            cursor += 2;
            Some(v)
        } else {
            None
        };

        let mut decoder_config = None;
        let mut sl_config = None;
        while cursor < body.len() {
            if cursor >= body.len() {
                break;
            }
            let sub_tag = body[cursor];
            cursor += 1;
            let (sub_size, _) = parse_varint(body, &mut cursor)?;
            if cursor + sub_size > body.len() {
                return Err(Error::BufferTooShort {
                    need: cursor + sub_size,
                    have: body.len(),
                    what: "ES_Descriptor sub-descriptor body",
                });
            }
            let sub_body = &body[cursor..cursor + sub_size];

            match sub_tag {
                TAG_DECODER_CONFIG => {
                    decoder_config = Some(DecoderConfigDescriptor::parse(sub_body)?);
                }
                TAG_SL_CONFIG => {
                    sl_config = Some(SLConfigDescriptor::parse(sub_body)?);
                }
                _ => {}
            }
            cursor += sub_size;
        }

        Ok(Self {
            es_id,
            stream_dependence_flag,
            url_flag,
            ocr_stream_flag,
            stream_priority,
            depends_on_es_id,
            url,
            ocr_es_id,
            decoder_config,
            sl_config,
        })
    }
}

impl Serialize for ESDescriptor {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        let body_size = 2 + 1
            + if self.stream_dependence_flag { 2 } else { 0 }
            + if self.url_flag {
                1 + self.url.as_ref().map_or(0, |u| u.len())
            } else { 0 }
            + if self.ocr_stream_flag { 2 } else { 0 };

        1
            + VARINT_WIDTH_FIXED
            + body_size
            + self.decoder_config.as_ref().map_or(0, |dc| dc.serialized_len())
            + self.sl_config.as_ref().map_or(0, |sl| sl.serialized_len())
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut cursor = 0usize;
        buf[cursor] = Self::TAG;
        cursor += 1;

        let mut body_size = 2 + 1;
        if self.stream_dependence_flag {
            body_size += 2;
        }
        if self.url_flag {
            body_size += 1 + self.url.as_ref().map_or(0, |u| u.len());
        }
        if self.ocr_stream_flag {
            body_size += 2;
        }
        let sub_len = self
            .decoder_config
            .as_ref()
            .map_or(0, |dc| dc.serialized_len())
            + self.sl_config.as_ref().map_or(0, |sl| sl.serialized_len());
        body_size += sub_len;

        write_varint_fixed(buf, &mut cursor, body_size)?;

        buf[cursor..cursor + 2].copy_from_slice(&self.es_id.to_be_bytes());
        cursor += 2;

        let mut flags = self.stream_priority & 0x1F;
        if self.stream_dependence_flag {
            flags |= 0x80;
        }
        if self.url_flag {
            flags |= 0x40;
        }
        if self.ocr_stream_flag {
            flags |= 0x20;
        }
        buf[cursor] = flags;
        cursor += 1;

        if let Some(ref dep) = self.depends_on_es_id {
            buf[cursor..cursor + 2].copy_from_slice(&dep.to_be_bytes());
            cursor += 2;
        }

        if let Some(ref u) = self.url {
            buf[cursor] = u.len() as u8;
            cursor += 1;
            buf[cursor..cursor + u.len()].copy_from_slice(u.as_bytes());
            cursor += u.len();
        }

        if let Some(ref ocr) = self.ocr_es_id {
            buf[cursor..cursor + 2].copy_from_slice(&ocr.to_be_bytes());
            cursor += 2;
        }

        if let Some(ref dc) = self.decoder_config {
            cursor += dc.serialize_into(&mut buf[cursor..])?;
        }
        if let Some(ref sl) = self.sl_config {
            cursor += sl.serialize_into(&mut buf[cursor..])?;
        }

        Ok(cursor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct EsdsBox {
    pub es_descriptor: ESDescriptor,
}

impl EsdsBox {
    pub fn parse_box(data: &[u8]) -> Result<Self> {
        let header = BoxHeader::parse(data)?;
        if !header.box_type.is(b"esds") {
            return Err(Error::InvalidValue {
                field: "box_type",
                value: header.box_type.to_u32() as u64,
                reason: "expected 'esds'",
            });
        }
        let end = usize::try_from(header.size).unwrap_or(usize::MAX);
        let body = data
            .get(header.header_size()..end)
            .ok_or(Error::BufferTooShort {
                need: end,
                have: data.len(),
                what: "esds box body",
            })?;
        Self::parse_body(body)
    }

    pub fn parse_body(body: &[u8]) -> Result<Self> {
        if body.len() < FULLBOX_EXTRA {
            return Err(Error::BufferTooShort {
                need: FULLBOX_EXTRA,
                have: body.len(),
                what: "esds FullBox header",
            });
        }
        let payload = &body[FULLBOX_EXTRA..];

        let mut cursor = 0usize;
        if cursor >= payload.len() {
            return Err(Error::BufferTooShort {
                need: 1,
                have: payload.len(),
                what: "ES_Descriptor tag",
            });
        }
        let tag = payload[cursor];
        cursor += 1;
        if tag != TAG_ES_DESCRIPTOR {
            return Err(Error::InvalidValue {
                field: "descriptor_tag",
                value: tag as u64,
                reason: "expected ES_DescrTag (0x03) in esds box",
            });
        }
        let (size, _) = parse_varint(payload, &mut cursor)?;
        let es_body = cursor
            .checked_add(size)
            .and_then(|end| payload.get(cursor..end))
            .ok_or(Error::BufferTooShort {
                need: cursor.saturating_add(size),
                have: payload.len(),
                what: "ES_Descriptor body",
            })?;
        let es_descriptor = ESDescriptor::parse(es_body)?;

        Ok(Self { es_descriptor })
    }

    pub fn new(es_descriptor: ESDescriptor) -> Self {
        Self { es_descriptor }
    }
}

impl Serialize for EsdsBox {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        BOX_HEADER_SIZE + FULLBOX_EXTRA + self.es_descriptor.serialized_len()
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut cursor = 0usize;
        let size32 = need as u32;
        buf[cursor..cursor + 4].copy_from_slice(&size32.to_be_bytes());
        cursor += 4;
        buf[cursor..cursor + 4].copy_from_slice(b"esds");
        cursor += 4;
        buf[cursor..cursor + 4].copy_from_slice(&[0, 0, 0, 0]);
        cursor += 4;
        cursor += self.es_descriptor.serialize_into(&mut buf[cursor..])?;
        Ok(cursor)
    }
}

#[cfg(test)]
mod hardening_tests {
    use super::*;

    #[test]
    fn esds_descriptor_size_beyond_payload_errors() {
        // FullBox extra + ES_DescrTag + 4-byte varint size = 0x0FFF_FFFF, no body.
        let body = [0, 0, 0, 0, TAG_ES_DESCRIPTOR, 0xFF, 0xFF, 0xFF, 0x7F];
        assert!(EsdsBox::parse_body(&body).is_err());
    }

    #[test]
    fn esds_box_size_beyond_data_errors() {
        let mut data = alloc::vec![0, 0, 0x10, 0x00];
        data.extend_from_slice(b"esds");
        data.extend_from_slice(&[0; 8]);
        assert!(EsdsBox::parse_box(&data).is_err());
    }
}
