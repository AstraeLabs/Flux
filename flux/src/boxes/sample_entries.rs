//! AVC/HEVC sample entries and their config boxes — ISO/IEC 14496-15:2017 §5.4, §8.4.
//!
//! | Sample entry | Four-CC | Params in sample entry | Params in-band |
//! |---------------|---------|----------------------|----------------|
//! | `avc1`        | avc1    | yes                   | no             |

use crate::avc_config::{AVCConfigurationBox, AVCDecoderConfigurationRecord};
use crate::error::{Error, Result};
use crate::hevc_config::{HEVCConfigurationBox, HEVCDecoderConfigurationRecord};
use alloc::vec::Vec;
use bitforge::Serialize;

const VISUAL_SAMPLE_ENTRY_SIZE: usize = 78;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct VisualSampleEntryFields {
    pub data_reference_index: u16,
    pub width: u16,
    pub height: u16,
    pub horizontal_resolution: u32,
    pub vertical_resolution: u32,
    pub data_size: u32,
    pub frame_count: u16,
    pub compressorname: [u8; 32],
    pub depth: u16,
    pub predefined: u16,
}

impl Default for VisualSampleEntryFields {
    fn default() -> Self {
        Self {
            data_reference_index: 1,
            width: 0,
            height: 0,
            horizontal_resolution: 0x00480000,
            vertical_resolution: 0x00480000,
            data_size: 0,
            frame_count: 1,
            compressorname: [0u8; 32],
            depth: 0x0018,
            predefined: 0xFFFF,
        }
    }
}

impl VisualSampleEntryFields {

    pub const fn serialized_len() -> usize {
        VISUAL_SAMPLE_ENTRY_SIZE
    }

    pub fn parse_body(bytes: &[u8], what: &'static str) -> Result<Self> {
        if bytes.len() < 8 + VISUAL_SAMPLE_ENTRY_SIZE {
            return Err(Error::BufferTooShort {
                need: 8 + VISUAL_SAMPLE_ENTRY_SIZE,
                have: bytes.len(),
                what,
            });
        }
        let body = &bytes[8..];
        Ok(Self {
            data_reference_index: u16::from_be_bytes([body[6], body[7]]),
            width: u16::from_be_bytes([body[24], body[25]]),
            height: u16::from_be_bytes([body[26], body[27]]),
            horizontal_resolution: u32::from_be_bytes([body[28], body[29], body[30], body[31]]),
            vertical_resolution: u32::from_be_bytes([body[32], body[33], body[34], body[35]]),
            data_size: u32::from_be_bytes([body[36], body[37], body[38], body[39]]),
            frame_count: u16::from_be_bytes([body[40], body[41]]),
            compressorname: {
                let mut c = [0u8; 32];
                c.copy_from_slice(&body[42..74]);
                c
            },
            depth: u16::from_be_bytes([body[74], body[75]]),
            predefined: u16::from_be_bytes([body[76], body[77]]),
        })
    }

    pub fn serialize_body_into(&self, buf: &mut [u8]) -> Result<usize> {
        self.serialize_into(buf)
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < VISUAL_SAMPLE_ENTRY_SIZE {
            return Err(Error::OutputBufferTooSmall {
                need: VISUAL_SAMPLE_ENTRY_SIZE,
                have: buf.len(),
            });
        }
        let mut cursor = 0usize;

        cursor += 6;

        buf[cursor..cursor + 2].copy_from_slice(&self.data_reference_index.to_be_bytes());
        cursor += 2;

        cursor += 16;

        buf[cursor..cursor + 2].copy_from_slice(&self.width.to_be_bytes());
        cursor += 2;

        buf[cursor..cursor + 2].copy_from_slice(&self.height.to_be_bytes());
        cursor += 2;

        buf[cursor..cursor + 4].copy_from_slice(&self.horizontal_resolution.to_be_bytes());
        cursor += 4;

        buf[cursor..cursor + 4].copy_from_slice(&self.vertical_resolution.to_be_bytes());
        cursor += 4;

        buf[cursor..cursor + 4].copy_from_slice(&self.data_size.to_be_bytes());
        cursor += 4;

        buf[cursor..cursor + 2].copy_from_slice(&self.frame_count.to_be_bytes());
        cursor += 2;

        buf[cursor..cursor + 32].copy_from_slice(&self.compressorname);
        cursor += 32;

        buf[cursor..cursor + 2].copy_from_slice(&self.depth.to_be_bytes());
        cursor += 2;

        buf[cursor..cursor + 2].copy_from_slice(&self.predefined.to_be_bytes());
        cursor += 2;

        Ok(cursor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct OpaqueBox {
    pub box_type: [u8; 4],
    pub data: Vec<u8>,
}

impl OpaqueBox {
    fn serialized_len(&self) -> usize {
        8 + self.data.len()
    }
    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        buf[..4].copy_from_slice(&(need as u32).to_be_bytes());
        buf[4..8].copy_from_slice(&self.box_type);
        buf[8..8 + self.data.len()].copy_from_slice(&self.data);
        Ok(need)
    }
}

pub(crate) fn find_config_box<'a>(region: &'a [u8], fourcc: &[u8; 4]) -> Option<&'a [u8]> {
    let mut off = 0usize;
    while off + 8 <= region.len() {
        let size = u32::from_be_bytes([
            region[off],
            region[off + 1],
            region[off + 2],
            region[off + 3],
        ]) as usize;
        if size < 8 {
            break;
        }
        let ty = &region[off + 4..off + 8];
        if ty == fourcc {
            return Some(&region[off..off + size]);
        }
        off += size;
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AVCSampleEntry {

    pub codec_type: [u8; 4],

    pub visual: VisualSampleEntryFields,

    pub config: AVCConfigurationBox,

    pub extra_boxes: Vec<OpaqueBox>,
}

impl AVCSampleEntry {

    pub fn bare_parse(bytes: &[u8]) -> Result<Self> {
        use crate::avc_config::AVCConfigurationBox;
        if bytes.len() < 8 + 78 + 8 {
            return Err(Error::BufferTooShort {
                need: 8 + 78 + 8,
                have: bytes.len(),
                what: "avc1 bare",
            });
        }
        let codec_type = [bytes[4], bytes[5], bytes[6], bytes[7]];
        let body = &bytes[8..];
        let data_reference_index = u16::from_be_bytes([body[6], body[7]]);
        let width = u16::from_be_bytes([body[24], body[25]]);
        let height = u16::from_be_bytes([body[26], body[27]]);
        let horizontal_resolution = u32::from_be_bytes([body[28], body[29], body[30], body[31]]);
        let vertical_resolution = u32::from_be_bytes([body[32], body[33], body[34], body[35]]);
        let data_size = u32::from_be_bytes([body[36], body[37], body[38], body[39]]);
        let frame_count = u16::from_be_bytes([body[40], body[41]]);
        let mut compressorname = [0u8; 32];
        compressorname.copy_from_slice(&body[42..74]);
        let depth = u16::from_be_bytes([body[74], body[75]]);
        let predefined = u16::from_be_bytes([body[76], body[77]]);
        let visual = VisualSampleEntryFields {
            data_reference_index,
            width,
            height,
            horizontal_resolution,
            vertical_resolution,
            data_size,
            frame_count,
            compressorname,
            depth,
            predefined,
        };

        let config_region = &body[78..];
        if let Some(avcc) = find_config_box(config_region, b"avcC") {

            let config = if avcc.len() > 8 {
                AVCConfigurationBox::parse_body(&avcc[8..])?
            } else {
                return Err(Error::BufferTooShort {
                    need: 8,
                    have: avcc.len(),
                    what: "avcC body",
                });
            };

            let avcc_start = avcc.as_ptr() as usize - config_region.as_ptr() as usize;
            let avcc_end = avcc_start + avcc.len();
            let mut extra_boxes = Vec::new();
            let mut eb_off = avcc_end;
            while eb_off + 8 <= config_region.len() {
                let eb_sz = u32::from_be_bytes([
                    config_region[eb_off],
                    config_region[eb_off + 1],
                    config_region[eb_off + 2],
                    config_region[eb_off + 3],
                ]) as usize;
                if eb_sz < 8 {
                    break;
                }
                let bt = [
                    config_region[eb_off + 4],
                    config_region[eb_off + 5],
                    config_region[eb_off + 6],
                    config_region[eb_off + 7],
                ];
                let d = config_region[eb_off + 8..eb_off + eb_sz.min(config_region.len() - eb_off)]
                    .to_vec();
                extra_boxes.push(OpaqueBox {
                    box_type: bt,
                    data: d,
                });
                eb_off += eb_sz;
            }
            Ok(Self {
                codec_type,
                visual,
                config,
                extra_boxes,
            })
        } else {
            Err(Error::BufferTooShort {
                need: 0,
                have: 0,
                what: "avc1 missing avcC",
            })
        }
    }

    pub fn new_avc1(config: AVCDecoderConfigurationRecord) -> Self {
        let compressorname = {
            let mut c = [0u8; 32];
            c[0] = 11;
            c[1..11].copy_from_slice(b"AVC Coding");
            c
        };
        Self {
            codec_type: *b"avc1",
            visual: VisualSampleEntryFields {
                compressorname,
                ..VisualSampleEntryFields::default()
            },
            config: AVCConfigurationBox::new(config),
            extra_boxes: Vec::new(),
        }
    }

    pub fn new_avc3(config: AVCDecoderConfigurationRecord) -> Self {
        let mut s = Self::new_avc1(config);
        s.codec_type = *b"avc3";
        s
    }
}

impl Serialize for AVCSampleEntry {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        let mut n = 8 + VisualSampleEntryFields::serialized_len() + self.config.serialized_len();
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
        let mut cursor = 0usize;
        let size32 = need as u32;
        buf[cursor..cursor + 4].copy_from_slice(&size32.to_be_bytes());
        cursor += 4;
        buf[cursor..cursor + 4].copy_from_slice(&self.codec_type);
        cursor += 4;
        cursor += self.visual.serialize_into(&mut buf[cursor..])?;
        cursor += self.config.serialize_into(&mut buf[cursor..])?;
        for eb in &self.extra_boxes {
            cursor += eb.serialize_into(&mut buf[cursor..])?;
        }
        Ok(cursor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Mp4vSampleEntry {

    pub visual: VisualSampleEntryFields,

    pub config_boxes: Vec<crate::init_segment::OpaqueBox>,
}

impl Mp4vSampleEntry {

    pub const FOURCC: [u8; 4] = *b"mp4v";

    pub fn bare_parse(bytes: &[u8]) -> Result<Self> {
        let visual = VisualSampleEntryFields::parse_body(bytes, "mp4v")?;

        let region = &bytes[8 + VISUAL_SAMPLE_ENTRY_SIZE..];
        let config_boxes = parse_trailing_boxes(region);
        Ok(Self {
            visual,
            config_boxes,
        })
    }
}

impl Serialize for Mp4vSampleEntry {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        let mut n = 8 + VisualSampleEntryFields::serialized_len();
        for b in &self.config_boxes {
            n += b.serialized_len();
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
        let mut cursor = 0usize;
        buf[cursor..cursor + 4].copy_from_slice(&(need as u32).to_be_bytes());
        cursor += 4;
        buf[cursor..cursor + 4].copy_from_slice(&Self::FOURCC);
        cursor += 4;
        cursor += self.visual.serialize_into(&mut buf[cursor..])?;
        for b in &self.config_boxes {
            cursor += b.serialize_into(&mut buf[cursor..])?;
        }
        Ok(cursor)
    }
}

fn parse_trailing_boxes(region: &[u8]) -> Vec<crate::init_segment::OpaqueBox> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 8 <= region.len() {
        let sz = u32::from_be_bytes([
            region[off],
            region[off + 1],
            region[off + 2],
            region[off + 3],
        ]) as usize;
        if sz < 8 || off + sz > region.len() {
            break;
        }
        let bt = [
            region[off + 4],
            region[off + 5],
            region[off + 6],
            region[off + 7],
        ];
        out.push(crate::init_segment::OpaqueBox::new(
            bt,
            region[off + 8..off + sz].to_vec(),
        ));
        off += sz;
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct HEVCSampleEntry {

    pub codec_type: [u8; 4],

    pub visual: VisualSampleEntryFields,

    pub config: HEVCConfigurationBox,

    pub extra_boxes: Vec<OpaqueBox>,
}

impl HEVCSampleEntry {

    pub fn bare_parse(bytes: &[u8]) -> Result<Self> {
        use crate::hevc_config::HEVCConfigurationBox;
        if bytes.len() < 8 + 78 + 8 {
            return Err(Error::BufferTooShort {
                need: 8 + 80 + 8,
                have: bytes.len(),
                what: "hvc1 bare",
            });
        }
        let codec_type = [bytes[4], bytes[5], bytes[6], bytes[7]];
        let body = &bytes[8..];
        let data_reference_index = u16::from_be_bytes([body[6], body[7]]);
        let width = u16::from_be_bytes([body[24], body[25]]);
        let height = u16::from_be_bytes([body[26], body[27]]);
        let horizontal_resolution = u32::from_be_bytes([body[28], body[29], body[30], body[31]]);
        let vertical_resolution = u32::from_be_bytes([body[32], body[33], body[34], body[35]]);
        let data_size = u32::from_be_bytes([body[36], body[37], body[38], body[39]]);
        let frame_count = u16::from_be_bytes([body[40], body[41]]);
        let mut compressorname = [0u8; 32];
        compressorname.copy_from_slice(&body[42..74]);
        let depth = u16::from_be_bytes([body[74], body[75]]);
        let predefined = u16::from_be_bytes([body[76], body[77]]);
        let visual = VisualSampleEntryFields {
            data_reference_index,
            width,
            height,
            horizontal_resolution,
            vertical_resolution,
            data_size,
            frame_count,
            compressorname,
            depth,
            predefined,
        };
        let config_region = &body[78..];
        if let Some(hvcc) = find_config_box(config_region, b"hvcC") {
            let config = if hvcc.len() > 8 {
                HEVCConfigurationBox::parse_body(&hvcc[8..])?
            } else {
                return Err(Error::BufferTooShort {
                    need: 8,
                    have: hvcc.len(),
                    what: "hvcC body",
                });
            };
            Ok(Self {
                codec_type,
                visual,
                config,
                extra_boxes: Vec::new(),
            })
        } else {
            Err(Error::BufferTooShort {
                need: 0,
                have: 0,
                what: "hvc1 missing hvcC",
            })
        }
    }

    pub fn new_hvc1(config: HEVCDecoderConfigurationRecord) -> Self {
        let compressorname = {
            let mut c = [0u8; 32];
            c[0] = 12;
            c[1..12].copy_from_slice(b"HEVC Coding");
            c
        };
        Self {
            codec_type: *b"hvc1",
            visual: VisualSampleEntryFields {
                compressorname,
                ..VisualSampleEntryFields::default()
            },
            config: HEVCConfigurationBox::new(config),
            extra_boxes: Vec::new(),
        }
    }

    pub fn new_hev1(config: HEVCDecoderConfigurationRecord) -> Self {
        let mut s = Self::new_hvc1(config);
        s.codec_type = *b"hev1";
        s
    }
}

impl Serialize for HEVCSampleEntry {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        let mut n = 8 + VisualSampleEntryFields::serialized_len() + self.config.serialized_len();
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
        let mut cursor = 0usize;
        let size32 = need as u32;
        buf[cursor..cursor + 4].copy_from_slice(&size32.to_be_bytes());
        cursor += 4;
        buf[cursor..cursor + 4].copy_from_slice(&self.codec_type);
        cursor += 4;
        cursor += self.visual.serialize_into(&mut buf[cursor..])?;
        cursor += self.config.serialize_into(&mut buf[cursor..])?;
        for eb in &self.extra_boxes {
            cursor += eb.serialize_into(&mut buf[cursor..])?;
        }
        Ok(cursor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct VVCSampleEntry {
    pub codec_type: [u8; 4],
    pub visual: VisualSampleEntryFields,
    pub config: crate::vvc_config::VvcConfigurationBox,
    pub extra_boxes: Vec<OpaqueBox>,
}

impl VVCSampleEntry {

    pub fn bare_parse(bytes: &[u8]) -> Result<Self> {
        use crate::vvc_config::VvcConfigurationBox;
        if bytes.len() < 8 + 78 + 8 {
            return Err(Error::BufferTooShort {
                need: 8 + 80 + 8,
                have: bytes.len(),
                what: "vvc1 bare",
            });
        }
        let codec_type = [bytes[4], bytes[5], bytes[6], bytes[7]];
        let visual = VisualSampleEntryFields::parse_body(bytes, "vvc1")?;
        let config_region = &bytes[8 + VISUAL_SAMPLE_ENTRY_SIZE..];
        if let Some(vvcc) = find_config_box(config_region, b"vvcC") {
            let config = if vvcc.len() > 8 {
                VvcConfigurationBox::parse_body(&vvcc[8..])?
            } else {
                return Err(Error::BufferTooShort {
                    need: 8,
                    have: vvcc.len(),
                    what: "vvcC body",
                });
            };
            Ok(Self {
                codec_type,
                visual,
                config,
                extra_boxes: Vec::new(),
            })
        } else {
            Err(Error::BufferTooShort {
                need: 0,
                have: 0,
                what: "vvc1 missing vvcC",
            })
        }
    }

    pub fn new_vvc1(config: crate::vvc_config::VvcConfigurationBox) -> Self {
        let compressorname = {
            let mut c = [0u8; 32];
            c[0] = 10;
            c[1..11].copy_from_slice(b"VVC Coding");
            c
        };
        Self {
            codec_type: *b"vvc1",
            visual: VisualSampleEntryFields {
                compressorname,
                ..VisualSampleEntryFields::default()
            },
            config,
            extra_boxes: Vec::new(),
        }
    }

    pub fn new_vvi1(config: crate::vvc_config::VvcConfigurationBox) -> Self {
        let mut s = Self::new_vvc1(config);
        s.codec_type = *b"vvi1";
        s
    }
}

impl Serialize for VVCSampleEntry {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        let mut n = 8 + VisualSampleEntryFields::serialized_len() + self.config.serialized_len();
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
        let mut cursor = 0usize;
        let size32 = need as u32;
        buf[cursor..cursor + 4].copy_from_slice(&size32.to_be_bytes());
        cursor += 4;
        buf[cursor..cursor + 4].copy_from_slice(&self.codec_type);
        cursor += 4;
        cursor += self.visual.serialize_into(&mut buf[cursor..])?;
        cursor += self.config.serialize_into(&mut buf[cursor..])?;
        for eb in &self.extra_boxes {
            cursor += eb.serialize_into(&mut buf[cursor..])?;
        }
        Ok(cursor)
    }
}