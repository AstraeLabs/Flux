//! ISO/IEC 14496-30 subtitle sample entries — `stpp` (TTML/IMSC) and `wvtt` (WebVTT).

use crate::error::{Error, Result};
use alloc::string::String;
use alloc::vec::Vec;
use bitforge::{Parse, Serialize};

const BOX_HDR: usize = 8;

fn parse_cstring(buf: &[u8], pos: usize) -> Result<(String, usize)> {
    let rest = &buf[pos..];
    let nul = rest
        .iter()
        .position(|&b| b == 0)
        .ok_or(Error::BufferTooShort {
            need: pos + rest.len() + 1,
            have: buf.len(),
            what: "null-terminated string",
        })?;
    let s = core::str::from_utf8(&rest[..nul]).map_err(|_| Error::InvalidValue {
        field: "utf8 string",
        value: 0,
        reason: "invalid UTF-8 in null-terminated string",
    })?;
    Ok((String::from(s), pos + nul + 1))
}

fn cstring_len(s: &str) -> usize {
    s.len() + 1
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct XmlSubtitleSampleEntry {
    pub data_reference_index: u16,
    pub namespace: String,
    pub schema_location: String,
    pub auxiliary_mime_types: String,
    pub extra_boxes: Vec<crate::init_segment::OpaqueBox>,
}

impl XmlSubtitleSampleEntry {

    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            data_reference_index: 1,
            namespace: namespace.into(),
            schema_location: String::new(),
            auxiliary_mime_types: String::new(),
            extra_boxes: Vec::new(),
        }
    }

    pub fn bare_parse(bytes: &[u8]) -> Result<Self> {

        if bytes.len() < 19 {
            return Err(Error::BufferTooShort {
                need: 19,
                have: bytes.len(),
                what: "stpp",
            });
        }

        let body = &bytes[8..];
        let data_reference_index = u16::from_be_bytes([body[6], body[7]]);
        let pos = 8usize;
        let (namespace, pos) = parse_cstring(body, pos)?;
        let (schema_location, pos) = parse_cstring(body, pos)?;
        let (auxiliary_mime_types, mut pos) = parse_cstring(body, pos)?;

        let mut extra_boxes = Vec::new();
        while pos + BOX_HDR <= body.len() {
            let sz = u32::from_be_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]])
                as usize;
            if sz < BOX_HDR {
                break;
            }
            let end = (pos + sz).min(body.len());
            let bt = [body[pos + 4], body[pos + 5], body[pos + 6], body[pos + 7]];
            let data = body[pos + BOX_HDR..end].to_vec();
            extra_boxes.push(crate::init_segment::OpaqueBox::new(bt, data));
            pos += sz;
        }

        Ok(Self {
            data_reference_index,
            namespace,
            schema_location,
            auxiliary_mime_types,
            extra_boxes,
        })
    }
}

impl<'a> Parse<'a> for XmlSubtitleSampleEntry {
    type Error = Error;

    fn parse(bytes: &'a [u8]) -> Result<Self> {
        Self::bare_parse(bytes)
    }
}

impl Serialize for XmlSubtitleSampleEntry {
    type Error = Error;

    fn serialized_len(&self) -> usize {

        let mut n = BOX_HDR + 8;

        n += cstring_len(&self.namespace);
        n += cstring_len(&self.schema_location);
        n += cstring_len(&self.auxiliary_mime_types);

        for eb in &self.extra_boxes {
            n += eb.serialized_len();
        }
        n
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut c = 0usize;

        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"stpp");
        c += 4;

        c += 6;
        buf[c..c + 2].copy_from_slice(&self.data_reference_index.to_be_bytes());
        c += 2;

        buf[c..c + self.namespace.len()].copy_from_slice(self.namespace.as_bytes());
        c += self.namespace.len();
        buf[c] = 0;
        c += 1;

        buf[c..c + self.schema_location.len()].copy_from_slice(self.schema_location.as_bytes());
        c += self.schema_location.len();
        buf[c] = 0;
        c += 1;

        buf[c..c + self.auxiliary_mime_types.len()]
            .copy_from_slice(self.auxiliary_mime_types.as_bytes());
        c += self.auxiliary_mime_types.len();
        buf[c] = 0;
        c += 1;

        for eb in &self.extra_boxes {
            c += eb.serialize_into(&mut buf[c..])?;
        }
        Ok(c)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct WebVttConfigurationBox {

    pub config: String,
}

impl WebVttConfigurationBox {

    pub fn new(config: impl Into<String>) -> Self {
        Self {
            config: config.into(),
        }
    }

    pub fn bare_parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < BOX_HDR {
            return Err(Error::BufferTooShort {
                need: BOX_HDR,
                have: bytes.len(),
                what: "vttC",
            });
        }
        let body = &bytes[BOX_HDR..];
        let config = core::str::from_utf8(body).map_err(|_| Error::InvalidValue {
            field: "vttC config",
            value: 0,
            reason: "invalid UTF-8 in vttC config string",
        })?;
        Ok(Self {
            config: String::from(config),
        })
    }
}

impl<'a> Parse<'a> for WebVttConfigurationBox {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        Self::bare_parse(bytes)
    }
}

impl Serialize for WebVttConfigurationBox {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        BOX_HDR + self.config.len()
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut c = 0usize;
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"vttC");
        c += 4;
        buf[c..c + self.config.len()].copy_from_slice(self.config.as_bytes());
        c += self.config.len();
        Ok(c)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct CuePayloadBox {

    pub cue_text: String,
}

impl CuePayloadBox {

    pub fn new(cue_text: impl Into<String>) -> Self {
        Self {
            cue_text: cue_text.into(),
        }
    }

    pub fn bare_parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < BOX_HDR {
            return Err(Error::BufferTooShort {
                need: BOX_HDR,
                have: bytes.len(),
                what: "payl",
            });
        }
        let body = &bytes[BOX_HDR..];
        let s = core::str::from_utf8(body).map_err(|_| Error::InvalidValue {
            field: "payl cue_text",
            value: 0,
            reason: "invalid UTF-8 in payl cue_text",
        })?;
        Ok(Self {
            cue_text: String::from(s),
        })
    }
}

impl<'a> Parse<'a> for CuePayloadBox {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        Self::bare_parse(bytes)
    }
}

impl Serialize for CuePayloadBox {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        BOX_HDR + self.cue_text.len()
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut c = 0usize;
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"payl");
        c += 4;
        buf[c..c + self.cue_text.len()].copy_from_slice(self.cue_text.as_bytes());
        c += self.cue_text.len();
        Ok(c)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct CueSettingsBox {

    pub settings: String,
}

impl CueSettingsBox {

    pub fn new(settings: impl Into<String>) -> Self {
        Self {
            settings: settings.into(),
        }
    }

    pub fn bare_parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < BOX_HDR {
            return Err(Error::BufferTooShort {
                need: BOX_HDR,
                have: bytes.len(),
                what: "sttg",
            });
        }
        let body = &bytes[BOX_HDR..];
        let s = core::str::from_utf8(body).map_err(|_| Error::InvalidValue {
            field: "sttg settings",
            value: 0,
            reason: "invalid UTF-8 in sttg settings",
        })?;
        Ok(Self {
            settings: String::from(s),
        })
    }
}

impl<'a> Parse<'a> for CueSettingsBox {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        Self::bare_parse(bytes)
    }
}

impl Serialize for CueSettingsBox {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        BOX_HDR + self.settings.len()
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut c = 0usize;
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"sttg");
        c += 4;
        buf[c..c + self.settings.len()].copy_from_slice(self.settings.as_bytes());
        c += self.settings.len();
        Ok(c)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct CueIdBox {

    pub cue_id: String,
}

impl CueIdBox {

    pub fn new(cue_id: impl Into<String>) -> Self {
        Self {
            cue_id: cue_id.into(),
        }
    }

    pub fn bare_parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < BOX_HDR {
            return Err(Error::BufferTooShort {
                need: BOX_HDR,
                have: bytes.len(),
                what: "iden",
            });
        }
        let body = &bytes[BOX_HDR..];
        let s = core::str::from_utf8(body).map_err(|_| Error::InvalidValue {
            field: "iden cue_id",
            value: 0,
            reason: "invalid UTF-8 in iden cue_id",
        })?;
        Ok(Self {
            cue_id: String::from(s),
        })
    }
}

impl<'a> Parse<'a> for CueIdBox {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        Self::bare_parse(bytes)
    }
}

impl Serialize for CueIdBox {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        BOX_HDR + self.cue_id.len()
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut c = 0usize;
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"iden");
        c += 4;
        buf[c..c + self.cue_id.len()].copy_from_slice(self.cue_id.as_bytes());
        c += self.cue_id.len();
        Ok(c)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct VttCueBox {
    pub payload: CuePayloadBox,
    pub settings: Option<CueSettingsBox>,
    pub cue_id: Option<CueIdBox>,
}

impl VttCueBox {

    pub fn new(payload: impl Into<String>) -> Self {
        Self {
            payload: CuePayloadBox::new(payload),
            settings: None,
            cue_id: None,
        }
    }

    pub fn bare_parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < BOX_HDR {
            return Err(Error::BufferTooShort {
                need: BOX_HDR,
                have: bytes.len(),
                what: "vttc",
            });
        }
        let body = &bytes[BOX_HDR..];
        let mut payload: Option<CuePayloadBox> = None;
        let mut settings: Option<CueSettingsBox> = None;
        let mut cue_id: Option<CueIdBox> = None;
        let mut pos = 0usize;
        while pos + BOX_HDR <= body.len() {
            let sz = u32::from_be_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]])
                as usize;
            if sz < BOX_HDR {
                break;
            }
            let end = (pos + sz).min(body.len());
            let child = &body[pos..end];
            let fourcc = &child[4..8];
            match fourcc {
                b"payl" => payload = Some(CuePayloadBox::bare_parse(child)?),
                b"sttg" => settings = Some(CueSettingsBox::bare_parse(child)?),
                b"iden" => cue_id = Some(CueIdBox::bare_parse(child)?),
                _ => {}
            }
            pos += sz;
        }
        let payload = payload.ok_or(Error::BufferTooShort {
            need: 0,
            have: 0,
            what: "vttc missing required payl child",
        })?;
        Ok(Self {
            payload,
            settings,
            cue_id,
        })
    }
}

impl<'a> Parse<'a> for VttCueBox {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        Self::bare_parse(bytes)
    }
}

impl Serialize for VttCueBox {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        let mut n = BOX_HDR + self.payload.serialized_len();
        if let Some(s) = &self.settings {
            n += s.serialized_len();
        }
        if let Some(i) = &self.cue_id {
            n += i.serialized_len();
        }
        n
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut c = 0usize;
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"vttc");
        c += 4;
        c += self.payload.serialize_into(&mut buf[c..])?;
        if let Some(s) = &self.settings {
            c += s.serialize_into(&mut buf[c..])?;
        }
        if let Some(i) = &self.cue_id {
            c += i.serialize_into(&mut buf[c..])?;
        }
        Ok(c)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct VttEmptyCueBox;

impl VttEmptyCueBox {

    pub fn bare_parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < BOX_HDR {
            return Err(Error::BufferTooShort {
                need: BOX_HDR,
                have: bytes.len(),
                what: "vtte",
            });
        }
        Ok(Self)
    }
}

impl<'a> Parse<'a> for VttEmptyCueBox {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        Self::bare_parse(bytes)
    }
}

impl Serialize for VttEmptyCueBox {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        BOX_HDR
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = BOX_HDR;
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        buf[..4].copy_from_slice(&(BOX_HDR as u32).to_be_bytes());
        buf[4..8].copy_from_slice(b"vtte");
        Ok(BOX_HDR)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct WvttSampleEntry {

    pub data_reference_index: u16,

    pub config: WebVttConfigurationBox,

    pub extra_boxes: Vec<crate::init_segment::OpaqueBox>,
}

impl WvttSampleEntry {

    pub fn new(config: impl Into<String>) -> Self {
        Self {
            data_reference_index: 1,
            config: WebVttConfigurationBox::new(config),
            extra_boxes: Vec::new(),
        }
    }

    pub fn bare_parse(bytes: &[u8]) -> Result<Self> {

        if bytes.len() < 24 {
            return Err(Error::BufferTooShort {
                need: 24,
                have: bytes.len(),
                what: "wvtt",
            });
        }
        let body = &bytes[BOX_HDR..];
        let data_reference_index = u16::from_be_bytes([body[6], body[7]]);

        let mut pos = 8usize;
        let mut config: Option<WebVttConfigurationBox> = None;
        let mut extra_boxes: Vec<crate::init_segment::OpaqueBox> = Vec::new();

        while pos + BOX_HDR <= body.len() {
            let sz = u32::from_be_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]])
                as usize;
            if sz < BOX_HDR {
                break;
            }
            let end = (pos + sz).min(body.len());
            let child = &body[pos..end];
            let fourcc = &child[4..8];
            match fourcc {
                b"vttC" => config = Some(WebVttConfigurationBox::bare_parse(child)?),
                _ => {
                    let mut bt = [0u8; 4];
                    bt.copy_from_slice(fourcc);
                    extra_boxes.push(crate::init_segment::OpaqueBox::new(
                        bt,
                        child[BOX_HDR..].to_vec(),
                    ));
                }
            }
            pos += sz;
        }

        let config = config.ok_or(Error::BufferTooShort {
            need: 0,
            have: 0,
            what: "wvtt missing required vttC child",
        })?;

        Ok(Self {
            data_reference_index,
            config,
            extra_boxes,
        })
    }
}

impl<'a> Parse<'a> for WvttSampleEntry {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        Self::bare_parse(bytes)
    }
}

impl Serialize for WvttSampleEntry {
    type Error = Error;

    fn serialized_len(&self) -> usize {

        let mut n = BOX_HDR + 8 + self.config.serialized_len();
        for eb in &self.extra_boxes {
            n += eb.serialized_len();
        }
        n
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut c = 0usize;
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"wvtt");
        c += 4;

        c += 6;
        buf[c..c + 2].copy_from_slice(&self.data_reference_index.to_be_bytes());
        c += 2;

        c += self.config.serialize_into(&mut buf[c..])?;

        for eb in &self.extra_boxes {
            c += eb.serialize_into(&mut buf[c..])?;
        }
        Ok(c)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ClosedCaptionSampleEntry {
    pub data_reference_index: u16,
}

impl ClosedCaptionSampleEntry {
    pub fn new() -> Self {
        Self {
            data_reference_index: 1,
        }
    }

    pub fn bare_parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 16 {
            return Err(Error::BufferTooShort {
                need: 16,
                have: bytes.len(),
                what: "c608",
            });
        }
        let body = &bytes[BOX_HDR..];
        let data_reference_index = u16::from_be_bytes([body[6], body[7]]);
        Ok(Self {
            data_reference_index,
        })
    }
}

impl Default for ClosedCaptionSampleEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Parse<'a> for ClosedCaptionSampleEntry {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        Self::bare_parse(bytes)
    }
}

impl Serialize for ClosedCaptionSampleEntry {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        BOX_HDR + 8
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut c = 0usize;
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"c608");
        c += 4;

        c += 6;
        buf[c..c + 2].copy_from_slice(&self.data_reference_index.to_be_bytes());
        c += 2;
        Ok(c)
    }
}