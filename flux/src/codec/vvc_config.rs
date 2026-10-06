//! VVC / H.266 decoder configuration record (`vvcC`)

use crate::error::{Error, Result};
use alloc::vec::Vec;
use bitforge::{Parse, Serialize};
use core::fmt;

const VALID_LENGTH_SIZES: [u8; 3] = [0, 1, 3];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub enum VvcNalUnitType {
    Opi,
    Dci,
    Vps,
    Sps,
    Pps,
    PrefixAps,
    Other(u8),
}

impl VvcNalUnitType {
    pub const OPI: u8 = 12;
    pub const DCI: u8 = 13;
    pub const VPS: u8 = 14;
    pub const SPS: u8 = 15;
    pub const PPS: u8 = 16;
    pub const PREFIX_APS: u8 = 17;

    pub fn from_u8(v: u8) -> Self {
        match v {
            Self::OPI => VvcNalUnitType::Opi,
            Self::DCI => VvcNalUnitType::Dci,
            Self::VPS => VvcNalUnitType::Vps,
            Self::SPS => VvcNalUnitType::Sps,
            Self::PPS => VvcNalUnitType::Pps,
            Self::PREFIX_APS => VvcNalUnitType::PrefixAps,
            other => VvcNalUnitType::Other(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            VvcNalUnitType::Opi => Self::OPI,
            VvcNalUnitType::Dci => Self::DCI,
            VvcNalUnitType::Vps => Self::VPS,
            VvcNalUnitType::Sps => Self::SPS,
            VvcNalUnitType::Pps => Self::PPS,
            VvcNalUnitType::PrefixAps => Self::PREFIX_APS,
            VvcNalUnitType::Other(v) => v,
        }
    }

    pub fn has_num_nalus_field(self) -> bool {
        !matches!(self, VvcNalUnitType::Dci | VvcNalUnitType::Opi)
    }

    pub fn name(&self) -> &'static str {
        match self {
            VvcNalUnitType::Opi => "OPI_NUT",
            VvcNalUnitType::Dci => "DCI_NUT",
            VvcNalUnitType::Vps => "VPS_NUT",
            VvcNalUnitType::Sps => "SPS_NUT",
            VvcNalUnitType::Pps => "PPS_NUT",
            VvcNalUnitType::PrefixAps => "PREFIX_APS_NUT",
            VvcNalUnitType::Other(_) => "reserved",
        }
    }
}

bitforge::impl_spec_display!(VvcNalUnitType, Other);

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct VvcNalArray {
    pub array_completeness: bool,
    pub nal_unit_type: u8,
    pub nalus: Vec<Vec<u8>>,
}

impl VvcNalArray {
    pub fn new(array_completeness: bool, nal_unit_type: u8, nalus: Vec<Vec<u8>>) -> Self {
        Self {
            array_completeness,
            nal_unit_type,
            nalus,
        }
    }

    pub fn kind(&self) -> VvcNalUnitType {
        VvcNalUnitType::from_u8(self.nal_unit_type)
    }

    fn serialized_len(&self) -> usize {
        let count_field = if self.kind().has_num_nalus_field() {
            2
        } else {
            0
        };
        1 + count_field + self.nalus.iter().map(|n| 2 + n.len()).sum::<usize>()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct VvcPtlRecord {
    pub num_bytes_constraint_info: u8,
    pub general_profile_idc: u8,
    pub general_tier_flag: bool,
    pub general_level_idc: u8,
    pub ptl_frame_only_constraint_flag: bool,
    pub ptl_multilayer_enabled_flag: bool,
    pub general_constraint_info: Vec<u8>,
    pub sublayer_level_present: Vec<bool>,
    pub sublayer_level_idc: Vec<u8>,
    pub sub_profile_idc: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct VvcDecoderConfigurationRecord {
    pub length_size_minus_one: u8,
    pub ptl_present: bool,
    pub ols_idx: u16,
    pub num_sublayers: u8,
    pub constant_frame_rate: u8,
    pub chroma_format_idc: u8,
    pub bit_depth_minus8: u8,
    pub ptl: Option<VvcPtlRecord>,
    pub max_picture_width: u16,
    pub max_picture_height: u16,
    pub avg_frame_rate: u16,
    pub arrays: Vec<VvcNalArray>,
}

impl VvcDecoderConfigurationRecord {
    pub fn is_valid_length_size(v: u8) -> bool {
        VALID_LENGTH_SIZES.contains(&v)
    }

    pub fn sps(&self) -> Option<&[u8]> {
        self.arrays
            .iter()
            .find(|a| a.kind() == VvcNalUnitType::Sps)
            .and_then(|a| a.nalus.first())
            .map(|n| n.as_slice())
    }

    pub fn dimensions(&self) -> Option<(u16, u16)> {
        let sps = self.sps()?;
        let info = crate::sps::decode_vvc_sps(sps).ok()?;
        Some((info.width as u16, info.height as u16))
    }

}

impl<'a> Parse<'a> for VvcDecoderConfigurationRecord {
    type Error = Error;

    fn parse(bytes: &'a [u8]) -> Result<Self> {
        let mut r = VvcBitReader::new(bytes);

        let _reserved0 = r.bits(5, "vvcC reserved")?;
        let length_size_minus_one = r.bits(2, "LengthSizeMinusOne")? as u8;
        if !Self::is_valid_length_size(length_size_minus_one) {
            return Err(Error::InvalidValue {
                field: "LengthSizeMinusOne",
                value: length_size_minus_one as u64,
                reason: "must be 0, 1, or 3 (value 2 is invalid per ISO/IEC 14496-15:2022 §11.3.2.1)",
            });
        }
        let ptl_present = r.flag("ptl_present_flag")?;

        let (
            ols_idx,
            num_sublayers,
            constant_frame_rate,
            chroma_format_idc,
            bit_depth_minus8,
            ptl,
            max_picture_width,
            max_picture_height,
            avg_frame_rate,
        ) = if ptl_present {
            let ols_idx = r.bits(9, "ols_idx")? as u16;
            let num_sublayers = r.bits(3, "num_sublayers")? as u8;
            let constant_frame_rate = r.bits(2, "constant_frame_rate")? as u8;
            let chroma_format_idc = r.bits(2, "chroma_format_idc")? as u8;
            let bit_depth_minus8 = r.bits(3, "bit_depth_minus8")? as u8;
            let _reserved1 = r.bits(5, "vvcC reserved")?;

            let ptl = parse_ptl(&mut r, num_sublayers)?;

            let max_picture_width = r.bits(16, "max_picture_width")? as u16;
            let max_picture_height = r.bits(16, "max_picture_height")? as u16;
            let avg_frame_rate = r.bits(16, "avg_frame_rate")? as u16;
            (
                ols_idx,
                num_sublayers,
                constant_frame_rate,
                chroma_format_idc,
                bit_depth_minus8,
                Some(ptl),
                max_picture_width,
                max_picture_height,
                avg_frame_rate,
            )
        } else {
            (0, 0, 0, 0, 0, None, 0, 0, 0)
        };

        let num_arrays = r.bits(8, "num_of_arrays")? as usize;
        let mut arrays = Vec::with_capacity(num_arrays);
        for _ in 0..num_arrays {
            let array_completeness = r.flag("array_completeness")?;
            let _reserved = r.bits(2, "vvcC array reserved")?;
            let nal_unit_type = r.bits(5, "NAL_unit_type")? as u8;
            let kind = VvcNalUnitType::from_u8(nal_unit_type);

            let num_nalus = if kind.has_num_nalus_field() {
                r.bits(16, "num_nalus")? as usize
            } else {
                1
            };

            let mut nalus = Vec::with_capacity(num_nalus);
            for _ in 0..num_nalus {
                let nal_len = r.bits(16, "nalUnitLength")? as usize;
                let nalu = r.take_bytes(nal_len, "nalUnit")?;
                nalus.push(nalu);
            }
            arrays.push(VvcNalArray {
                array_completeness,
                nal_unit_type,
                nalus,
            });
        }

        Ok(Self {
            length_size_minus_one,
            ptl_present,
            ols_idx,
            num_sublayers,
            constant_frame_rate,
            chroma_format_idc,
            bit_depth_minus8,
            ptl,
            max_picture_width,
            max_picture_height,
            avg_frame_rate,
            arrays,
        })
    }
}

impl Serialize for VvcDecoderConfigurationRecord {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        let mut n = 1usize;
        if self.ptl_present {
            n += 3;
            if let Some(ptl) = &self.ptl {
                n += ptl_serialized_len(ptl);
            }
            n += 6;
        }
        n += 1;
        n += self
            .arrays
            .iter()
            .map(|a| a.serialized_len())
            .sum::<usize>();
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
        let mut w = VvcBitWriter::new(buf);

        w.bits(0x1F, 5);
        w.bits(self.length_size_minus_one as u64 & 0x3, 2);
        w.flag(self.ptl_present);

        if self.ptl_present {
            w.bits(self.ols_idx as u64 & 0x1FF, 9);
            w.bits(self.num_sublayers as u64 & 0x7, 3);
            w.bits(self.constant_frame_rate as u64 & 0x3, 2);
            w.bits(self.chroma_format_idc as u64 & 0x3, 2);
            w.bits(self.bit_depth_minus8 as u64 & 0x7, 3);
            w.bits(0x1F, 5);

            if let Some(ptl) = &self.ptl {
                write_ptl(&mut w, ptl);
            }

            w.bits(self.max_picture_width as u64, 16);
            w.bits(self.max_picture_height as u64, 16);
            w.bits(self.avg_frame_rate as u64, 16);
        }

        w.bits(self.arrays.len() as u64 & 0xFF, 8);
        for arr in &self.arrays {
            w.flag(arr.array_completeness);
            w.bits(0, 2);
            w.bits(arr.nal_unit_type as u64 & 0x1F, 5);
            let kind = arr.kind();
            if kind.has_num_nalus_field() {
                w.bits(arr.nalus.len() as u64 & 0xFFFF, 16);
            }
            for nalu in &arr.nalus {
                w.bits(nalu.len() as u64 & 0xFFFF, 16);
                w.bytes(nalu);
            }
        }

        Ok(w.finish())
    }
}

impl fmt::Display for VvcDecoderConfigurationRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.ptl {
            Some(ptl) => write!(
                f,
                "VVC(profile_idc={}, tier={}, level={}, lenSize={}, arrays={})",
                ptl.general_profile_idc,
                if ptl.general_tier_flag {
                    "high"
                } else {
                    "main"
                },
                ptl.general_level_idc,
                self.length_size_minus_one + 1,
                self.arrays.len(),
            ),
            None => write!(
                f,
                "VVC(no PTL, lenSize={}, arrays={})",
                self.length_size_minus_one + 1,
                self.arrays.len(),
            ),
        }
    }
}

const VVCC_VERSION: u8 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct VvcConfigurationBox {
    pub version: u8,
    pub flags: u32,
    pub config: VvcDecoderConfigurationRecord,
}

impl VvcConfigurationBox {
    pub fn parse_body(body: &[u8]) -> Result<Self> {
        if body.len() < 4 {
            return Err(Error::BufferTooShort {
                need: 4,
                have: body.len(),
                what: "vvcC FullBox header",
            });
        }
        let version = body[0];
        let flags = u32::from_be_bytes([0, body[1], body[2], body[3]]);
        let config = VvcDecoderConfigurationRecord::parse(&body[4..])?;
        Ok(Self {
            version,
            flags,
            config,
        })
    }

    pub fn new(config: VvcDecoderConfigurationRecord) -> Self {
        Self {
            version: VVCC_VERSION,
            flags: 0,
            config,
        }
    }
}

impl Serialize for VvcConfigurationBox {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        8 + 4 + self.config.serialized_len()
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
        buf[cursor..cursor + 4].copy_from_slice(b"vvcC");
        cursor += 4;
        buf[cursor] = self.version;
        cursor += 1;
        buf[cursor..cursor + 3].copy_from_slice(&self.flags.to_be_bytes()[1..]);
        cursor += 3;
        cursor += self.config.serialize_into(&mut buf[cursor..])?;
        Ok(cursor)
    }
}

fn parse_ptl(r: &mut VvcBitReader, num_sublayers: u8) -> Result<VvcPtlRecord> {
    let _reserved = r.bits(2, "VvcPTLRecord reserved")?;
    let num_bytes_constraint_info = r.bits(6, "num_bytes_constraint_info")? as u8;
    let general_profile_idc = r.bits(7, "general_profile_idc")? as u8;
    let general_tier_flag = r.flag("general_tier_flag")?;
    let general_level_idc = r.bits(8, "general_level_idc")? as u8;
    let ptl_frame_only_constraint_flag = r.flag("ptl_frame_only_constraint_flag")?;
    let ptl_multilayer_enabled_flag = r.flag("ptl_multilayer_enabled_flag")?;

    let general_constraint_info = if num_bytes_constraint_info > 0 {
        let bits = (num_bytes_constraint_info as usize) * 8 - 2;
        r.bits_vec(bits, "general_constraint_info")?
    } else {
        let _reserved = r.bits(6, "VvcPTLRecord reserved")?;
        Vec::new()
    };

    let mut sublayer_level_present = Vec::new();
    let mut sublayer_level_idc = Vec::new();
    if num_sublayers > 1 {
        let flag_count = (num_sublayers - 1) as usize;
        for _ in 0..flag_count {
            sublayer_level_present.push(r.flag("ptl_sublayer_level_present_flag[i]")?);
        }
        r.align("ptl_reserved_zero_bit")?;
        for &present in &sublayer_level_present {
            if present {
                sublayer_level_idc.push(r.bits(8, "sublayer_level_idc[i]")? as u8);
            }
        }
    }

    let num_sub_profiles = r.bits(8, "ptl_num_sub_profiles")? as usize;
    let mut sub_profile_idc = Vec::with_capacity(num_sub_profiles);
    for _ in 0..num_sub_profiles {
        sub_profile_idc.push(r.bits(32, "general_sub_profile_idc[j]")? as u32);
    }

    Ok(VvcPtlRecord {
        num_bytes_constraint_info,
        general_profile_idc,
        general_tier_flag,
        general_level_idc,
        ptl_frame_only_constraint_flag,
        ptl_multilayer_enabled_flag,
        general_constraint_info,
        sublayer_level_present,
        sublayer_level_idc,
        sub_profile_idc,
    })
}

fn write_ptl(w: &mut VvcBitWriter, ptl: &VvcPtlRecord) {
    w.bits(0, 2);
    w.bits(ptl.num_bytes_constraint_info as u64 & 0x3F, 6);
    w.bits(ptl.general_profile_idc as u64 & 0x7F, 7);
    w.flag(ptl.general_tier_flag);
    w.bits(ptl.general_level_idc as u64, 8);
    w.flag(ptl.ptl_frame_only_constraint_flag);
    w.flag(ptl.ptl_multilayer_enabled_flag);

    if ptl.num_bytes_constraint_info > 0 {
        let bits = (ptl.num_bytes_constraint_info as usize) * 8 - 2;
        w.bits_vec(&ptl.general_constraint_info, bits);
    } else {
        w.bits(0, 6);
    }

    if !ptl.sublayer_level_present.is_empty() {
        for &present in &ptl.sublayer_level_present {
            w.flag(present);
        }
        w.align();
        let mut idc = ptl.sublayer_level_idc.iter();
        for &present in &ptl.sublayer_level_present {
            if present && let Some(&v) = idc.next() {
                w.bits(v as u64, 8);
            }
        }
    }

    w.bits(ptl.sub_profile_idc.len() as u64 & 0xFF, 8);
    for &sp in &ptl.sub_profile_idc {
        w.bits(sp as u64, 32);
    }
}

fn ptl_serialized_len(ptl: &VvcPtlRecord) -> usize {
    let mut bits = 3 * 8;
    if ptl.num_bytes_constraint_info > 0 {
        bits += 2 + ((ptl.num_bytes_constraint_info as usize) * 8 - 2);
    } else {
        bits += 8;
    }
    if !ptl.sublayer_level_present.is_empty() {
        bits += ptl.sublayer_level_present.len().div_ceil(8) * 8;
        bits += ptl.sublayer_level_idc.len() * 8;
    }
    bits += 8;
    bits += ptl.sub_profile_idc.len() * 32;
    bits / 8
}

struct VvcBitReader<'a> {
    data: &'a [u8],
    bit_pos: usize,
}

impl<'a> VvcBitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, bit_pos: 0 }
    }

    fn bits(&mut self, n: usize, what: &'static str) -> Result<u64> {
        if n > 64 || self.bit_pos + n > self.data.len() * 8 {
            return Err(Error::BufferTooShort {
                need: (self.bit_pos + n).div_ceil(8),
                have: self.data.len(),
                what,
            });
        }
        let mut val = 0u64;
        for _ in 0..n {
            let byte_idx = self.bit_pos / 8;
            let bit_in_byte = 7 - (self.bit_pos % 8);
            let bit = ((self.data[byte_idx] >> bit_in_byte) & 1) as u64;
            val = (val << 1) | bit;
            self.bit_pos += 1;
        }
        Ok(val)
    }

    fn bits_vec(&mut self, n: usize, what: &'static str) -> Result<Vec<u8>> {
        if self.bit_pos + n > self.data.len() * 8 {
            return Err(Error::BufferTooShort {
                need: (self.bit_pos + n).div_ceil(8),
                have: self.data.len(),
                what,
            });
        }
        let mut out = alloc::vec![0u8; n.div_ceil(8)];
        for i in 0..n {
            let byte_idx = self.bit_pos / 8;
            let bit_in_byte = 7 - (self.bit_pos % 8);
            let bit = (self.data[byte_idx] >> bit_in_byte) & 1;
            if bit != 0 {
                out[i / 8] |= 1 << (7 - (i % 8));
            }
            self.bit_pos += 1;
        }
        Ok(out)
    }

    fn flag(&mut self, what: &'static str) -> Result<bool> {
        Ok(self.bits(1, what)? != 0)
    }

    fn align(&mut self, what: &'static str) -> Result<()> {
        while !self.bit_pos.is_multiple_of(8) {
            let _ = self.bits(1, what)?;
        }
        Ok(())
    }

    fn take_bytes(&mut self, len: usize, what: &'static str) -> Result<Vec<u8>> {
        debug_assert_eq!(self.bit_pos % 8, 0, "take_bytes requires byte alignment");
        let start = self.bit_pos / 8;
        let end = start + len;
        if end > self.data.len() {
            return Err(Error::BufferTooShort {
                need: end,
                have: self.data.len(),
                what,
            });
        }
        self.bit_pos += len * 8;
        Ok(self.data[start..end].to_vec())
    }
}

struct VvcBitWriter<'a> {
    buf: &'a mut [u8],
    bit_pos: usize,
}

impl<'a> VvcBitWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, bit_pos: 0 }
    }

    fn bits(&mut self, val: u64, n: usize) {
        for i in (0..n).rev() {
            let bit = ((val >> i) & 1) as u8;
            let byte_idx = self.bit_pos / 8;
            let bit_in_byte = 7 - (self.bit_pos % 8);
            if bit != 0 {
                self.buf[byte_idx] |= 1 << bit_in_byte;
            }
            self.bit_pos += 1;
        }
    }

    fn bits_vec(&mut self, data: &[u8], n: usize) {
        for i in 0..n {
            let bit = (data[i / 8] >> (7 - (i % 8))) & 1;
            let byte_idx = self.bit_pos / 8;
            let bit_in_byte = 7 - (self.bit_pos % 8);
            if bit != 0 {
                self.buf[byte_idx] |= 1 << bit_in_byte;
            }
            self.bit_pos += 1;
        }
    }

    fn flag(&mut self, v: bool) {
        self.bits(v as u64, 1);
    }

    fn align(&mut self) {
        while !self.bit_pos.is_multiple_of(8) {
            self.bit_pos += 1;
        }
    }

    fn bytes(&mut self, data: &[u8]) {
        debug_assert_eq!(self.bit_pos % 8, 0, "bytes() requires byte alignment");
        let start = self.bit_pos / 8;
        self.buf[start..start + data.len()].copy_from_slice(data);
        self.bit_pos += data.len() * 8;
    }

    fn finish(&self) -> usize {
        self.bit_pos.div_ceil(8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_with_wide_gci(num_bytes_constraint_info: u8) -> VvcDecoderConfigurationRecord {
        let bits = (num_bytes_constraint_info as usize)
            .saturating_mul(8)
            .saturating_sub(2);
        let mut general_constraint_info: Vec<u8> = (0..bits.div_ceil(8))
            .map(|i| 0xA5u8.wrapping_add(i as u8))
            .collect();
        let used_bits_in_last_byte = bits % 8;
        if used_bits_in_last_byte != 0
            && let Some(last) = general_constraint_info.last_mut()
        {
            *last &= 0xFFu8 << (8 - used_bits_in_last_byte);
        }

        VvcDecoderConfigurationRecord {
            length_size_minus_one: 3,
            ptl_present: true,
            ols_idx: 0,
            num_sublayers: 1,
            constant_frame_rate: 0,
            chroma_format_idc: 1,
            bit_depth_minus8: 0,
            ptl: Some(VvcPtlRecord {
                num_bytes_constraint_info,
                general_profile_idc: 1,
                general_tier_flag: false,
                general_level_idc: 93,
                ptl_frame_only_constraint_flag: true,
                ptl_multilayer_enabled_flag: false,
                general_constraint_info,
                sublayer_level_present: Vec::new(),
                sublayer_level_idc: Vec::new(),
                sub_profile_idc: Vec::new(),
            }),
            max_picture_width: 1280,
            max_picture_height: 536,
            avg_frame_rate: 0,
            arrays: Vec::new(),
        }
    }

    #[test]
    fn parses_general_constraint_info_wider_than_64_bits() {
        let record = record_with_wide_gci(12);

        let len = record.serialized_len();
        let mut buf = alloc::vec![0u8; len];
        let written = record.serialize_into(&mut buf).unwrap();
        assert_eq!(written, len);

        let parsed = VvcDecoderConfigurationRecord::parse(&buf).unwrap();
        assert_eq!(parsed, record);
        assert_eq!(parsed.ptl.unwrap().general_constraint_info.len(), 94usize.div_ceil(8));
    }

    #[test]
    fn round_trips_zero_length_constraint_info() {
        let record = record_with_wide_gci(0);
        let len = record.serialized_len();
        let mut buf = alloc::vec![0u8; len];
        record.serialize_into(&mut buf).unwrap();
        let parsed = VvcDecoderConfigurationRecord::parse(&buf).unwrap();
        assert_eq!(parsed, record);
    }
}