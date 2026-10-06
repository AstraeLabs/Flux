//! AVC decoder configuration record (`avcC`)

use crate::error::{Error, Result};
use crate::nalu_types::{AvcPps, AvcSps, AvcSpsExt};
use alloc::vec::Vec;
use bitforge::{Parse, Serialize};
use core::fmt;

const VALID_LENGTH_SIZES: [u8; 3] = [0, 1, 3];

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AVCDecoderConfigurationRecord {
    pub configuration_version: u8,
    pub profile_indication: u8,
    pub profile_compatibility: u8,
    pub level_indication: u8,
    pub length_size_minus_one: u8,
    pub sps: Vec<AvcSps>,
    pub pps: Vec<AvcPps>,
    pub chroma_format: Option<u8>,
    pub bit_depth_luma_minus8: Option<u8>,
    pub bit_depth_chroma_minus8: Option<u8>,
    pub sps_ext: Vec<AvcSpsExt>,
}

impl AVCDecoderConfigurationRecord {
    fn has_high_profile_ext(profile: u8) -> bool {
        crate::sps::is_high_profile(profile)
    }

    pub fn dimensions(&self) -> Option<(u16, u16)> {
        let info = crate::sps::decode_avc_sps(&self.sps.first()?.0).ok()?;
        Some((info.width as u16, info.height as u16))
    }
}

impl<'a> Parse<'a> for AVCDecoderConfigurationRecord {
    type Error = Error;

    fn parse(bytes: &'a [u8]) -> Result<Self> {
        let mut cursor = 0usize;

        let configuration_version = read_u8(bytes, &mut cursor, "configurationVersion")?;

        let profile_indication = read_u8(bytes, &mut cursor, "AVCProfileIndication")?;

        let profile_compatibility = read_u8(bytes, &mut cursor, "profile_compatibility")?;

        let level_indication = read_u8(bytes, &mut cursor, "AVCLevelIndication")?;

        let b4 = read_u8(bytes, &mut cursor, "lengthSizeMinusOne byte")?;
        let _reserved_6 = (b4 >> 2) & 0x3F;
        let length_size_minus_one = b4 & 0x03;
        if !VALID_LENGTH_SIZES.contains(&length_size_minus_one) {
            return Err(Error::InvalidValue {
                field: "lengthSizeMinusOne",
                value: length_size_minus_one as u64,
                reason: "must be 0, 1, or 3 (value 2 is invalid per ISO/IEC 14496-15:2017 §5.3.3)",
            });
        }

        let b5 = read_u8(bytes, &mut cursor, "numOfSequenceParameterSets byte")?;
        let _reserved_3 = (b5 >> 5) & 0x07;
        let num_sps = (b5 & 0x1F) as usize;
        if num_sps == 0 {
            return Err(Error::InvalidValue {
                field: "numOfSequenceParameterSets",
                value: 0,
                reason: "an AVCDecoderConfigurationRecord must declare at least one SPS \
                         (ISO/IEC 14496-15:2017 §5.3.3); a conformant encoder never emits 0",
            });
        }

        let mut sps = Vec::with_capacity(num_sps);
        for _ in 0..num_sps {
            let nalu = read_nalu_16(bytes, &mut cursor, "SPS")?;
            sps.push(AvcSps(nalu));
        }

        let num_pps = read_u8(bytes, &mut cursor, "numOfPictureParameterSets")? as usize;

        let mut pps = Vec::with_capacity(num_pps);
        for _ in 0..num_pps {
            let nalu = read_nalu_16(bytes, &mut cursor, "PPS")?;
            pps.push(AvcPps(nalu));
        }

        let mut chroma_format = None;
        let mut bit_depth_luma_minus8 = None;
        let mut bit_depth_chroma_minus8 = None;
        let mut sps_ext = Vec::new();

        if Self::has_high_profile_ext(profile_indication) && cursor < bytes.len() {
            let b_cf = read_u8(bytes, &mut cursor, "chroma_format byte")?;
            let _reserved_cf = (b_cf >> 2) & 0x3F;
            let cf = b_cf & 0x03;
            chroma_format = Some(cf);

            let b_bdl = read_u8(bytes, &mut cursor, "bit_depth_luma_minus8 byte")?;
            let _reserved_bdl = (b_bdl >> 3) & 0x1F;
            let bdl = b_bdl & 0x07;
            bit_depth_luma_minus8 = Some(bdl);

            let b_bdc = read_u8(bytes, &mut cursor, "bit_depth_chroma_minus8 byte")?;
            let _reserved_bdc = (b_bdc >> 3) & 0x1F;
            let bdc = b_bdc & 0x07;
            bit_depth_chroma_minus8 = Some(bdc);

            let num_sps_ext = read_u8(bytes, &mut cursor, "numOfSequenceParameterSetExt")? as usize;

            sps_ext = Vec::with_capacity(num_sps_ext);
            for _ in 0..num_sps_ext {
                let nalu = read_nalu_16(bytes, &mut cursor, "SPSExt")?;
                sps_ext.push(AvcSpsExt(nalu));
            }
        }

        Ok(Self {
            configuration_version,
            profile_indication,
            profile_compatibility,
            level_indication,
            length_size_minus_one,
            sps,
            pps,
            chroma_format,
            bit_depth_luma_minus8,
            bit_depth_chroma_minus8,
            sps_ext,
        })
    }
}

impl Serialize for AVCDecoderConfigurationRecord {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        let mut len = 6usize;
        for sps in &self.sps {
            len += 2 + sps.0.len();
        }
        len += 1;
        for pps in &self.pps {
            len += 2 + pps.0.len();
        }
        if self.chroma_format.is_some() {
            len += 4;
            for sps_ext in &self.sps_ext {
                len += 2 + sps_ext.0.len();
            }
        }
        len
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

        buf[cursor] = self.profile_indication;
        cursor += 1;

        buf[cursor] = self.profile_compatibility;
        cursor += 1;

        buf[cursor] = self.level_indication;
        cursor += 1;

        buf[cursor] = 0xFC | (self.length_size_minus_one & 0x03);
        cursor += 1;

        let num_sps = self.sps.len();
        buf[cursor] = 0xE0 | ((num_sps as u8) & 0x1F);
        cursor += 1;

        for sps in &self.sps {
            let len = sps.0.len() as u16;
            buf[cursor..cursor + 2].copy_from_slice(&len.to_be_bytes());
            cursor += 2;
            buf[cursor..cursor + sps.0.len()].copy_from_slice(&sps.0);
            cursor += sps.0.len();
        }

        let num_pps = self.pps.len();
        buf[cursor] = num_pps as u8;
        cursor += 1;

        for pps in &self.pps {
            let len = pps.0.len() as u16;
            buf[cursor..cursor + 2].copy_from_slice(&len.to_be_bytes());
            cursor += 2;
            buf[cursor..cursor + pps.0.len()].copy_from_slice(&pps.0);
            cursor += pps.0.len();
        }

        if self.chroma_format.is_some() {
            let cf = self.chroma_format.unwrap_or(0);
            buf[cursor] = 0xFC | (cf & 0x03);
            cursor += 1;

            let bdl = self.bit_depth_luma_minus8.unwrap_or(0);
            buf[cursor] = 0xF8 | (bdl & 0x07);
            cursor += 1;

            let bdc = self.bit_depth_chroma_minus8.unwrap_or(0);
            buf[cursor] = 0xF8 | (bdc & 0x07);
            cursor += 1;

            let num_sps_ext = self.sps_ext.len();
            buf[cursor] = num_sps_ext as u8;
            cursor += 1;

            for sps_ext in &self.sps_ext {
                let len = sps_ext.0.len() as u16;
                buf[cursor..cursor + 2].copy_from_slice(&len.to_be_bytes());
                cursor += 2;
                buf[cursor..cursor + sps_ext.0.len()].copy_from_slice(&sps_ext.0);
                cursor += sps_ext.0.len();
            }
        }

        Ok(cursor)
    }
}

impl fmt::Display for AVCDecoderConfigurationRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AVC(profile={}, compat=0x{:02x}, level={}, lenSize={}, sps={}, pps={})",
            self.profile_indication,
            self.profile_compatibility,
            self.level_indication,
            self.length_size_minus_one + 1,
            self.sps.len(),
            self.pps.len(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AVCConfigurationBox {
    pub config: AVCDecoderConfigurationRecord,
}

impl AVCConfigurationBox {
    pub fn parse_body(body: &[u8]) -> Result<Self> {
        let config = AVCDecoderConfigurationRecord::parse(body)?;
        Ok(Self { config })
    }

    pub fn new(config: AVCDecoderConfigurationRecord) -> Self {
        Self { config }
    }
}

impl Serialize for AVCConfigurationBox {
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
        buf[cursor..cursor + 4].copy_from_slice(b"avcC");
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

fn read_nalu_16(bytes: &[u8], cursor: &mut usize, what: &'static str) -> Result<Vec<u8>> {
    if *cursor + 2 > bytes.len() {
        return Err(Error::BufferTooShort {
            need: *cursor + 2,
            have: bytes.len(),
            what,
        });
    }
    let len = u16::from_be_bytes([bytes[*cursor], bytes[*cursor + 1]]) as usize;
    *cursor += 2;

    if *cursor + len > bytes.len() {
        return Err(Error::BufferTooShort {
            need: *cursor + len,
            have: bytes.len(),
            what,
        });
    }
    let data = bytes[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(data)
}