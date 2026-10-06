//! DTS audio in ISOBMFF — `dtsc`/`dtsh`/`dtsl`/`dtse` AudioSampleEntry + `ddts` config box.

use crate::error::{Error, Result};
use bitforge::{Parse, Serialize};

pub const DDTS_FOURCC: [u8; 4] = *b"ddts";

pub const DTSC_FOURCC: [u8; 4] = *b"dtsc";
pub const DTSH_FOURCC: [u8; 4] = *b"dtsh";
pub const DTSL_FOURCC: [u8; 4] = *b"dtsl";
pub const DTSE_FOURCC: [u8; 4] = *b"dtse";

pub const DDTS_BODY_LEN: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct DtsSpecificBox {
    pub dts_sampling_frequency: u32,
    pub max_bitrate: u32,
    pub avg_bitrate: u32,
    pub pcm_sample_depth: u8,
    pub frame_duration: u8,
    pub stream_construction: u8,
    pub core_lfe_present: bool,
    pub core_layout: u8,
    pub core_size: u16,
    pub stereo_downmix: bool,
    pub representation_type: u8,
    pub channel_layout: u16,
    pub multi_asset_flag: bool,
    pub lbr_duration_mod: bool,
    pub reserved_box_present: bool,
}

impl DtsSpecificBox {
    fn encode_packed_word(&self) -> u32 {
        let mut w: u32 = 0;
        w |= (u32::from(self.frame_duration) & 0x03) << 30;
        w |= (u32::from(self.stream_construction) & 0x1F) << 25;
        w |= u32::from(self.core_lfe_present) << 24;
        w |= (u32::from(self.core_layout) & 0x3F) << 18;
        w |= (u32::from(self.core_size) & 0x3FFF) << 4;
        w |= u32::from(self.stereo_downmix) << 3;
        w |= u32::from(self.representation_type) & 0x07;
        w
    }

    fn decode_packed_word(w: u32) -> (u8, u8, bool, u8, u16, bool, u8) {
        let frame_duration = ((w >> 30) & 0x03) as u8;
        let stream_construction = ((w >> 25) & 0x1F) as u8;
        let core_lfe_present = ((w >> 24) & 0x01) != 0;
        let core_layout = ((w >> 18) & 0x3F) as u8;
        let core_size = ((w >> 4) & 0x3FFF) as u16;
        let stereo_downmix = ((w >> 3) & 0x01) != 0;
        let representation_type = (w & 0x07) as u8;
        (
            frame_duration,
            stream_construction,
            core_lfe_present,
            core_layout,
            core_size,
            stereo_downmix,
            representation_type,
        )
    }

    fn encode_flags_byte(&self) -> u8 {
        let mut b: u8 = 0;
        if self.multi_asset_flag {
            b |= 0x80;
        }
        if self.lbr_duration_mod {
            b |= 0x40;
        }
        if self.reserved_box_present {
            b |= 0x20;
        }
        b
    }
}

impl<'a> Parse<'a> for DtsSpecificBox {
    type Error = Error;

    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < DDTS_BODY_LEN {
            return Err(Error::BufferTooShort {
                need: DDTS_BODY_LEN,
                have: bytes.len(),
                what: "ddts",
            });
        }
        let dts_sampling_frequency = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let max_bitrate = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let avg_bitrate = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let pcm_sample_depth = bytes[12];
        let packed = u32::from_be_bytes([bytes[13], bytes[14], bytes[15], bytes[16]]);
        let (
            frame_duration,
            stream_construction,
            core_lfe_present,
            core_layout,
            core_size,
            stereo_downmix,
            representation_type,
        ) = Self::decode_packed_word(packed);
        let channel_layout = u16::from_be_bytes([bytes[17], bytes[18]]);
        let flags_byte = bytes[19];
        let multi_asset_flag = (flags_byte & 0x80) != 0;
        let lbr_duration_mod = (flags_byte & 0x40) != 0;
        let reserved_box_present = (flags_byte & 0x20) != 0;

        Ok(Self {
            dts_sampling_frequency,
            max_bitrate,
            avg_bitrate,
            pcm_sample_depth,
            frame_duration,
            stream_construction,
            core_lfe_present,
            core_layout,
            core_size,
            stereo_downmix,
            representation_type,
            channel_layout,
            multi_asset_flag,
            lbr_duration_mod,
            reserved_box_present,
        })
    }
}

impl Serialize for DtsSpecificBox {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        DDTS_BODY_LEN
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = DDTS_BODY_LEN;
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        buf[0..4].copy_from_slice(&self.dts_sampling_frequency.to_be_bytes());
        buf[4..8].copy_from_slice(&self.max_bitrate.to_be_bytes());
        buf[8..12].copy_from_slice(&self.avg_bitrate.to_be_bytes());
        buf[12] = self.pcm_sample_depth;
        buf[13..17].copy_from_slice(&self.encode_packed_word().to_be_bytes());
        buf[17..19].copy_from_slice(&self.channel_layout.to_be_bytes());
        buf[19] = self.encode_flags_byte();
        Ok(need)
    }
}