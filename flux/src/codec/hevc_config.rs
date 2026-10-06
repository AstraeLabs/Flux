//! HEVC decoder configuration record (`hvcC`)

use crate::error::{Error, Result};
use crate::nalu_types::{HevcNalArray, HevcNalUnit};
use alloc::vec::Vec;
use bitforge::{Parse, Serialize};
use core::fmt;

const VALID_LENGTH_SIZES: [u8; 3] = [0, 1, 3];

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct HEVCDecoderConfigurationRecord {
    pub configuration_version: u8,
    pub general_profile_space: u8,
    pub general_tier_flag: bool,
    pub general_profile_idc: u8,
    pub general_profile_compatibility_flags: u32,
    pub general_constraint_indicator_flags: u64,
    pub general_level_idc: u8,
    pub min_spatial_segmentation_idc: u16,
    pub parallelism_type: u8,
    pub chroma_format_idc: u8,
    pub bit_depth_luma_minus8: u8,
    pub bit_depth_chroma_minus8: u8,
    pub avg_frame_rate: u16,
    pub constant_frame_rate: u8,
    pub num_temporal_layers: u8,
    pub temporal_id_nested: bool,
    pub length_size_minus_one: u8,
    pub arrays: Vec<HevcNalArray>,
}

impl HEVCDecoderConfigurationRecord {
    pub fn is_valid_length_size(v: u8) -> bool {
        (v == 0) | (v == 1) | (v == 3)
    }

    pub fn dimensions(&self) -> Option<(u16, u16)> {
        const HEVC_SPS_NUT: u8 = 33;
        let sps = self
            .arrays
            .iter()
            .find(|a| a.nal_unit_type == HEVC_SPS_NUT)
            .and_then(|a| a.nalus.first())?;
        let info = crate::sps::decode_hevc_sps(&sps.0).ok()?;
        Some((info.width as u16, info.height as u16))
    }
}

impl<'a> Parse<'a> for HEVCDecoderConfigurationRecord {
    type Error = Error;

    fn parse(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = 0usize;

        let configuration_version = read_u8(bytes, &mut cursor, "HEVC configurationVersion")?;

        let b1 = read_u8(bytes, &mut cursor, "general_profile_space/tier/idc")?;
        let general_profile_space = (b1 >> 6) & 0x03;
        let general_tier_flag = ((b1 >> 5) & 0x01) != 0;
        let general_profile_idc = b1 & 0x1F;

        let general_profile_compatibility_flags =
            read_u32(bytes, &mut cursor, "general_profile_compatibility_flags")?;

        let general_constraint_indicator_flags =
            read_u48(bytes, &mut cursor, "general_constraint_indicator_flags")?;

        let general_level_idc = read_u8(bytes, &mut cursor, "general_level_idc")?;

        let msid_bytes = read_u16(bytes, &mut cursor, "min_spatial_segmentation_idc")?;
        let _reserved_msid = (msid_bytes >> 12) & 0x0F;
        let min_spatial_segmentation_idc = msid_bytes & 0x0FFF;

        let b_pt = read_u8(bytes, &mut cursor, "parallelismType")?;
        let _reserved_pt = (b_pt >> 2) & 0x3F;
        let parallelism_type = b_pt & 0x03;

        let b_cf = read_u8(bytes, &mut cursor, "chroma_format_idc")?;
        let _reserved_cf = (b_cf >> 2) & 0x3F;
        let chroma_format_idc = b_cf & 0x03;

        let b_bdl = read_u8(bytes, &mut cursor, "bit_depth_luma_minus8")?;
        let _reserved_bdl = (b_bdl >> 3) & 0x1F;
        let bit_depth_luma_minus8 = b_bdl & 0x07;

        let b_bdc = read_u8(bytes, &mut cursor, "bit_depth_chroma_minus8")?;
        let _reserved_bdc = (b_bdc >> 3) & 0x1F;
        let bit_depth_chroma_minus8 = b_bdc & 0x07;

        let avg_frame_rate = read_u16(bytes, &mut cursor, "avgFrameRate")?;

        let b_cfr = read_u8(bytes, &mut cursor, "constantFrameRate/temporal")?;
        let constant_frame_rate = (b_cfr >> 6) & 0x03;
        let num_temporal_layers = (b_cfr >> 3) & 0x07;
        let temporal_id_nested = ((b_cfr >> 2) & 0x01) != 0;
        let length_size_minus_one = b_cfr & 0x03;
        if !VALID_LENGTH_SIZES.contains(&length_size_minus_one) {
            return Err(Error::InvalidValue {
                field: "lengthSizeMinusOne",
                value: length_size_minus_one as u64,
                reason: "must be 0, 1, or 3 (value 2 is invalid per ISO/IEC 14496-15:2017 §8.3.3)",
            });
        }

        let num_arrays = read_u8(bytes, &mut cursor, "numOfArrays")? as usize;

        let mut arrays = Vec::with_capacity(num_arrays);
        for _ in 0..num_arrays {
            let b_arr = read_u8(bytes, &mut cursor, "NAL array header")?;
            let array_completeness = (b_arr >> 7) != 0;
            let _reserved_arr = (b_arr >> 6) & 0x01;
            let nal_unit_type = b_arr & 0x3F;

            let num_nalus = read_u16(bytes, &mut cursor, "numNalus")? as usize;

            let mut nalus = Vec::with_capacity(num_nalus);
            for _ in 0..num_nalus {
                let nal_unit_len = read_u16(bytes, &mut cursor, "nalUnitLength")? as usize;
                if cursor + nal_unit_len > bytes.len() {
                    return Err(Error::BufferTooShort {
                        need: cursor + nal_unit_len,
                        have: bytes.len(),
                        what: "HEVC nalUnit",
                    });
                }
                let nalu_data = bytes[cursor..cursor + nal_unit_len].to_vec();
                cursor += nal_unit_len;
                nalus.push(HevcNalUnit(nalu_data));
            }

            arrays.push(HevcNalArray {
                array_completeness,
                nal_unit_type,
                nalus,
            });
        }

        Ok(Self {
            configuration_version,
            general_profile_space,
            general_tier_flag,
            general_profile_idc,
            general_profile_compatibility_flags,
            general_constraint_indicator_flags,
            general_level_idc,
            min_spatial_segmentation_idc,
            parallelism_type,
            chroma_format_idc,
            bit_depth_luma_minus8,
            bit_depth_chroma_minus8,
            avg_frame_rate,
            constant_frame_rate,
            num_temporal_layers,
            temporal_id_nested,
            length_size_minus_one,
            arrays,
        })
    }
}

impl Serialize for HEVCDecoderConfigurationRecord {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        1 + 1
            + 4
            + 6
            + 1
            + 2
            + 1
            + 1
            + 1
            + 1
            + 2
            + 1
            + 1
            + self
                .arrays
                .iter()
                .map(|a| {
                    3 + a.nalus.iter().map(|n| 2 + n.0.len()).sum::<usize>()
                })
                .sum::<usize>()
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

        buf[cursor] = self.configuration_version;
        cursor += 1;

        buf[cursor] = ((self.general_profile_space & 0x03) << 6)
            | (if self.general_tier_flag { 0x20 } else { 0 })
            | (self.general_profile_idc & 0x1F);
        cursor += 1;

        buf[cursor..cursor + 4]
            .copy_from_slice(&self.general_profile_compatibility_flags.to_be_bytes());
        cursor += 4;

        let ciflags = self.general_constraint_indicator_flags;
        buf[cursor..cursor + 6].copy_from_slice(&[
            ((ciflags >> 40) & 0xFF) as u8,
            ((ciflags >> 32) & 0xFF) as u8,
            ((ciflags >> 24) & 0xFF) as u8,
            ((ciflags >> 16) & 0xFF) as u8,
            ((ciflags >> 8) & 0xFF) as u8,
            (ciflags & 0xFF) as u8,
        ]);
        cursor += 6;

        buf[cursor] = self.general_level_idc;
        cursor += 1;

        let msid = 0xF000 | (self.min_spatial_segmentation_idc & 0x0FFF);
        buf[cursor..cursor + 2].copy_from_slice(&msid.to_be_bytes());
        cursor += 2;

        buf[cursor] = 0xFC | (self.parallelism_type & 0x03);
        cursor += 1;

        buf[cursor] = 0xFC | (self.chroma_format_idc & 0x03);
        cursor += 1;

        buf[cursor] = 0xF8 | (self.bit_depth_luma_minus8 & 0x07);
        cursor += 1;

        buf[cursor] = 0xF8 | (self.bit_depth_chroma_minus8 & 0x07);
        cursor += 1;

        buf[cursor..cursor + 2].copy_from_slice(&self.avg_frame_rate.to_be_bytes());
        cursor += 2;

        buf[cursor] = ((self.constant_frame_rate & 0x03) << 6)
            | ((self.num_temporal_layers & 0x07) << 3)
            | (if self.temporal_id_nested { 0x04 } else { 0x00 })
            | (self.length_size_minus_one & 0x03);
        cursor += 1;

        buf[cursor] = self.arrays.len() as u8;
        cursor += 1;

        for arr in &self.arrays {
            let first_byte =
                (if arr.array_completeness { 0x80u8 } else { 0 }) | (arr.nal_unit_type & 0x3F);
            buf[cursor] = first_byte;
            cursor += 1;

            let num = arr.nalus.len();
            buf[cursor..cursor + 2].copy_from_slice(&(num as u16).to_be_bytes());
            cursor += 2;

            for nalu in &arr.nalus {
                let len = nalu.0.len();
                buf[cursor..cursor + 2].copy_from_slice(&(len as u16).to_be_bytes());
                cursor += 2;
                buf[cursor..cursor + len].copy_from_slice(&nalu.0);
                cursor += len;
            }
        }

        Ok(cursor)
    }
}

impl fmt::Display for HEVCDecoderConfigurationRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HEVC(tier={}, profile_idc={}, level={}, lenSize={}, arrays={})",
            if self.general_tier_flag {
                "high"
            } else {
                "main"
            },
            self.general_profile_idc,
            self.general_level_idc,
            self.length_size_minus_one + 1,
            self.arrays.len(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct HEVCConfigurationBox {
    pub config: HEVCDecoderConfigurationRecord,
}

impl HEVCConfigurationBox {
    pub fn parse_body(body: &[u8]) -> Result<Self> {
        let config = HEVCDecoderConfigurationRecord::parse(body)?;
        Ok(Self { config })
    }

    pub fn new(config: HEVCDecoderConfigurationRecord) -> Self {
        Self { config }
    }
}

impl Serialize for HEVCConfigurationBox {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        8 + self.config.serialized_len()
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
        buf[cursor..cursor + 4].copy_from_slice(b"hvcC");
        cursor += 4;
        cursor += self.config.serialize_into(&mut buf[cursor..])?;
        Ok(cursor)
    }
}

fn read_u8(bytes: &[u8], cursor: &mut usize, what: &'static str) -> Result<u8> {
    if *cursor >= bytes.len() {
        return Err(Error::BufferTooShort {
            need: *cursor + 1,
            have: bytes.len(),
            what,
        });
    }
    let v = bytes[*cursor];
    *cursor += 1;
    Ok(v)
}

fn read_u16(bytes: &[u8], cursor: &mut usize, what: &'static str) -> Result<u16> {
    if *cursor + 2 > bytes.len() {
        return Err(Error::BufferTooShort {
            need: *cursor + 2,
            have: bytes.len(),
            what,
        });
    }
    let v = u16::from_be_bytes([bytes[*cursor], bytes[*cursor + 1]]);
    *cursor += 2;
    Ok(v)
}

fn read_u32(bytes: &[u8], cursor: &mut usize, what: &'static str) -> Result<u32> {
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

fn read_u48(bytes: &[u8], cursor: &mut usize, what: &'static str) -> Result<u64> {
    if *cursor + 6 > bytes.len() {
        return Err(Error::BufferTooShort {
            need: *cursor + 6,
            have: bytes.len(),
            what,
        });
    }
    let v = (bytes[*cursor] as u64) << 40
        | (bytes[*cursor + 1] as u64) << 32
        | (bytes[*cursor + 2] as u64) << 24
        | (bytes[*cursor + 3] as u64) << 16
        | (bytes[*cursor + 4] as u64) << 8
        | bytes[*cursor + 5] as u64;
    *cursor += 6;
    Ok(v)
}