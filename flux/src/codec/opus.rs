//! Opus in ISOBMFF — `Opus` AudioSampleEntry + `dOps` config box.

use crate::error::{Error, Result};
use alloc::vec::Vec;
use bitforge::{Parse, Serialize};

pub const DOPS_FOURCC: [u8; 4] = *b"dOps";
pub const OPUS_FOURCC: [u8; 4] = *b"Opus";
const DOPS_FIXED_LEN: usize = 11;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct OpusSpecificBox {
    pub version: u8,
    pub output_channel_count: u8,
    pub pre_skip: u16,
    pub input_sample_rate: u32,
    pub output_gain: i16,
    pub channel_mapping_family: u8,
    pub channel_mapping: Option<ChannelMappingTable>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ChannelMappingTable {
    pub stream_count: u8,
    pub coupled_count: u8,
    pub channel_mapping: Vec<u8>,
}

impl<'a> Parse<'a> for OpusSpecificBox {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < DOPS_FIXED_LEN {
            return Err(Error::BufferTooShort {
                need: DOPS_FIXED_LEN,
                have: bytes.len(),
                what: "dOps body",
            });
        }
        let version = bytes[0];
        let output_channel_count = bytes[1];
        let pre_skip = u16::from_be_bytes([bytes[2], bytes[3]]);
        let input_sample_rate = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let output_gain = i16::from_be_bytes([bytes[8], bytes[9]]);
        let channel_mapping_family = bytes[10];
        let channel_mapping = if channel_mapping_family != 0 {
            if bytes.len() < DOPS_FIXED_LEN + 2 {
                return Err(Error::BufferTooShort {
                    need: DOPS_FIXED_LEN + 2,
                    have: bytes.len(),
                    what: "dOps channel mapping",
                });
            }
            let stream_count = bytes[11];
            let coupled_count = bytes[12];
            let map_start = DOPS_FIXED_LEN + 2;
            let map_end = (map_start + output_channel_count as usize).min(bytes.len());
            Some(ChannelMappingTable {
                stream_count,
                coupled_count,
                channel_mapping: bytes[map_start..map_end].to_vec(),
            })
        } else {
            None
        };
        Ok(Self {
            version,
            output_channel_count,
            pre_skip,
            input_sample_rate,
            output_gain,
            channel_mapping_family,
            channel_mapping,
        })
    }
}

impl Serialize for OpusSpecificBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        let mut n = DOPS_FIXED_LEN;
        if let Some(ref m) = self.channel_mapping {
            n += 2 + m.channel_mapping.len();
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
        buf[0] = self.version;
        buf[1] = self.output_channel_count;
        buf[2..4].copy_from_slice(&self.pre_skip.to_be_bytes());
        buf[4..8].copy_from_slice(&self.input_sample_rate.to_be_bytes());
        buf[8..10].copy_from_slice(&self.output_gain.to_be_bytes());
        buf[10] = self.channel_mapping_family;
        if let Some(ref m) = self.channel_mapping {
            buf[11] = m.stream_count;
            buf[12] = m.coupled_count;
            buf[13..13 + m.channel_mapping.len()].copy_from_slice(&m.channel_mapping);
        }
        Ok(need)
    }
}
