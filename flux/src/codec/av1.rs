//! AV1 in ISOBMFF — `av01` VisualSampleEntry + `av1C` config box.

use crate::error::{Error, Result};
use crate::sample_entries::VisualSampleEntryFields;
use alloc::vec::Vec;
use bitforge::{Parse, Serialize};

pub const AV1C_FOURCC: [u8; 4] = *b"av1C";
pub const AV01_FOURCC: [u8; 4] = *b"av01";
const AV1C_FIXED_LEN: usize = 4;
const BOX_HDR: usize = 8;
const MARKER_BIT: u8 = 0x80;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Av1ConfigurationBox {
    pub version: u8,
    pub seq_profile: u8,
    pub seq_level_idx_0: u8,
    pub seq_tier_0: bool,
    pub high_bitdepth: bool,
    pub twelve_bit: bool,
    pub monochrome: bool,
    pub chroma_subsampling_x: bool,
    pub chroma_subsampling_y: bool,
    pub chroma_sample_position: u8,
    pub initial_presentation_delay_minus_one: Option<u8>,
    pub config_obus: Vec<u8>,
}

impl<'a> Parse<'a> for Av1ConfigurationBox {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < AV1C_FIXED_LEN {
            return Err(Error::BufferTooShort {
                need: AV1C_FIXED_LEN,
                have: bytes.len(),
                what: "av1C body",
            });
        }
        let b0 = bytes[0];
        if (b0 & MARKER_BIT) == 0 {
            return Err(Error::InvalidValue {
                field: "av1C marker",
                value: b0 as u64,
                reason: "marker bit must be 1",
            });
        }
        let version = b0 & 0x7F;
        let b1 = bytes[1];
        let seq_profile = b1 >> 5;
        let seq_level_idx_0 = b1 & 0x1F;
        let b2 = bytes[2];
        let seq_tier_0 = (b2 & 0x80) != 0;
        let high_bitdepth = (b2 & 0x40) != 0;
        let twelve_bit = (b2 & 0x20) != 0;
        let monochrome = (b2 & 0x10) != 0;
        let chroma_subsampling_x = (b2 & 0x08) != 0;
        let chroma_subsampling_y = (b2 & 0x04) != 0;
        let chroma_sample_position = b2 & 0x03;
        let b3 = bytes[3];
        let ipd_present = (b3 & 0x10) != 0;
        let initial_presentation_delay_minus_one = if ipd_present { Some(b3 & 0x0F) } else { None };
        let config_obus = bytes[AV1C_FIXED_LEN..].to_vec();
        Ok(Self {
            version,
            seq_profile,
            seq_level_idx_0,
            seq_tier_0,
            high_bitdepth,
            twelve_bit,
            monochrome,
            chroma_subsampling_x,
            chroma_subsampling_y,
            chroma_sample_position,
            initial_presentation_delay_minus_one,
            config_obus,
        })
    }
}

impl Serialize for Av1ConfigurationBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        AV1C_FIXED_LEN + self.config_obus.len()
    }
    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        buf[0] = MARKER_BIT | (self.version & 0x7F);
        buf[1] = (self.seq_profile << 5) | (self.seq_level_idx_0 & 0x1F);
        buf[2] = ((self.seq_tier_0 as u8) << 7)
            | ((self.high_bitdepth as u8) << 6)
            | ((self.twelve_bit as u8) << 5)
            | ((self.monochrome as u8) << 4)
            | ((self.chroma_subsampling_x as u8) << 3)
            | ((self.chroma_subsampling_y as u8) << 2)
            | (self.chroma_sample_position & 0x03);
        buf[3] = match self.initial_presentation_delay_minus_one {
            Some(d) => 0x10 | (d & 0x0F),
            None => 0x00,
        };
        buf[AV1C_FIXED_LEN..need].copy_from_slice(&self.config_obus);
        Ok(need)
    }
}

const OBU_TYPE_SEQUENCE_HEADER: u8 = 1;

fn read_obu_leb128(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value: u64 = 0;
    for i in 0..8 {
        let byte = *data.get(*pos)?;
        *pos += 1;
        value |= u64::from(byte & 0x7F) << (i * 7);
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

fn av1_seq_header_dimensions(payload: &[u8]) -> Option<(u16, u16)> {
    use crate::bitreader::BitReader;

    let mut r = BitReader::from_rbsp(payload, "AV1 sequence_header_obu").ok()?;

    let _seq_profile = r.read_bits(3, "seq_profile").ok()?;
    let _still_picture = r.read_flag("still_picture").ok()?;
    let reduced_still_picture_header = r.read_flag("reduced_still_picture_header").ok()?;

    if reduced_still_picture_header {
        let _seq_level_idx_0 = r.read_bits(5, "seq_level_idx[0]").ok()?;
    } else {
        let timing_info_present_flag = r.read_flag("timing_info_present_flag").ok()?;
        let mut decoder_model_info_present_flag = false;
        if timing_info_present_flag {
            let _num_units_in_display_tick = r.read_bits(32, "num_units_in_display_tick").ok()?;
            let _time_scale = r.read_bits(32, "time_scale").ok()?;
            let equal_picture_interval = r.read_flag("equal_picture_interval").ok()?;
            if equal_picture_interval {
                return None;
            }
            decoder_model_info_present_flag =
                r.read_flag("decoder_model_info_present_flag").ok()?;
            if decoder_model_info_present_flag {
                let _buffer_delay_length_minus_1 =
                    r.read_bits(5, "buffer_delay_length_minus_1").ok()?;
                let _num_units_in_decoding_tick =
                    r.read_bits(32, "num_units_in_decoding_tick").ok()?;
                let _buffer_removal_time_length_minus_1 =
                    r.read_bits(5, "buffer_removal_time_length_minus_1").ok()?;
                let _frame_presentation_time_length_minus_1 =
                    r.read_bits(5, "frame_presentation_time_length_minus_1").ok()?;
            }
        }
        let initial_display_delay_present_flag =
            r.read_flag("initial_display_delay_present_flag").ok()?;
        let operating_points_cnt_minus_1 = r.read_bits(5, "operating_points_cnt_minus_1").ok()?;
        for _ in 0..=operating_points_cnt_minus_1 {
            let _operating_point_idc = r.read_bits(12, "operating_point_idc[i]").ok()?;
            let seq_level_idx = r.read_bits(5, "seq_level_idx[i]").ok()?;
            if seq_level_idx > 7 {
                let _seq_tier = r.read_flag("seq_tier[i]").ok()?;
            }
            if decoder_model_info_present_flag {
                let decoder_model_present_for_this_op = r
                    .read_flag("decoder_model_present_for_this_op[i]")
                    .ok()?;
                if decoder_model_present_for_this_op {
                    return None;
                }
            }
            if initial_display_delay_present_flag {
                let initial_display_delay_present_for_this_op = r
                    .read_flag("initial_display_delay_present_for_this_op[i]")
                    .ok()?;
                if initial_display_delay_present_for_this_op {
                    let _initial_display_delay_minus_1 =
                        r.read_bits(4, "initial_display_delay_minus_1[i]").ok()?;
                }
            }
        }
    }

    let frame_width_bits_minus_1 = r.read_bits(4, "frame_width_bits_minus_1").ok()? as usize;
    let frame_height_bits_minus_1 = r.read_bits(4, "frame_height_bits_minus_1").ok()? as usize;
    let max_frame_width_minus_1 = r
        .read_bits(frame_width_bits_minus_1 + 1, "max_frame_width_minus_1")
        .ok()?;
    let max_frame_height_minus_1 = r
        .read_bits(frame_height_bits_minus_1 + 1, "max_frame_height_minus_1")
        .ok()?;

    Some((
        (max_frame_width_minus_1 + 1) as u16,
        (max_frame_height_minus_1 + 1) as u16,
    ))
}

impl Av1ConfigurationBox {
    pub fn dimensions(&self) -> Option<(u16, u16)> {
        let data = &self.config_obus;
        let mut pos = 0usize;
        while pos < data.len() {
            let first = *data.get(pos)?;
            let obu_type = (first >> 3) & 0x0F;
            let extension_flag = (first >> 2) & 1;
            let has_size_field = (first >> 1) & 1;
            pos += 1;
            if extension_flag == 1 {
                pos += 1;
            }
            let payload_len = if has_size_field == 1 {
                read_obu_leb128(data, &mut pos)? as usize
            } else {
                data.len().checked_sub(pos)?
            };
            let payload_start = pos;
            let payload_end = payload_start.checked_add(payload_len)?;
            if payload_end > data.len() {
                return None;
            }
            if obu_type == OBU_TYPE_SEQUENCE_HEADER {
                return av1_seq_header_dimensions(&data[payload_start..payload_end]);
            }
            pos = payload_end;
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Av1SampleEntry {
    pub visual: VisualSampleEntryFields,
    pub config: Av1ConfigurationBox,
}

impl Av1SampleEntry {
    pub fn parse_entry(bytes: &[u8]) -> Result<Self> {
        let visual = VisualSampleEntryFields::parse_body(bytes, "av01")?;
        let region = &bytes[BOX_HDR + VisualSampleEntryFields::serialized_len()..];
        let av1c = crate::sample_entries::find_config_box(region, &AV1C_FOURCC).ok_or(
            Error::BufferTooShort {
                need: 0,
                have: 0,
                what: "av01 missing av1C",
            },
        )?;
        let config = Av1ConfigurationBox::parse(&av1c[BOX_HDR..])?;
        Ok(Self { visual, config })
    }
}

impl Serialize for Av1SampleEntry {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        BOX_HDR + VisualSampleEntryFields::serialized_len() + BOX_HDR + self.config.serialized_len()
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
        buf[c..c + 4].copy_from_slice(&AV01_FOURCC);
        c += 4;
        c += self.visual.serialize_body_into(&mut buf[c..])?;
        let av1c_len = BOX_HDR + self.config.serialized_len();
        buf[c..c + 4].copy_from_slice(&(av1c_len as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(&AV1C_FOURCC);
        c += 4;
        c += self.config.serialize_into(&mut buf[c..])?;
        Ok(c)
    }
}
