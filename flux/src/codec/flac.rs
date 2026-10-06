//! FLAC in ISOBMFF — `fLaC` AudioSampleEntry + `dfLa` config box.

use crate::error::{Error, Result};
use alloc::vec::Vec;
use bitforge::{Parse, Serialize};

pub const DFLA_FOURCC: [u8; 4] = *b"dfLa";
pub const FLAC_FOURCC: [u8; 4] = *b"fLaC";
const FULL_HDR: usize = 4;
const METADATA_BLOCK_HDR: usize = 4;
pub const BLOCK_TYPE_STREAMINFO: u8 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FlacMetadataBlock {
    pub last: bool,
    pub block_type: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FlacSpecificBox {
    pub version: u8,
    pub flags: u32,
    pub blocks: Vec<FlacMetadataBlock>,
}

impl FlacSpecificBox {
    pub fn streaminfo(&self) -> Option<&[u8]> {
        self.blocks
            .first()
            .filter(|b| b.block_type == BLOCK_TYPE_STREAMINFO)
            .map(|b| b.data.as_slice())
    }
}

impl<'a> Parse<'a> for FlacSpecificBox {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < FULL_HDR {
            return Err(Error::BufferTooShort {
                need: FULL_HDR,
                have: bytes.len(),
                what: "dfLa body",
            });
        }
        let version = bytes[0];
        let flags = u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]);
        let mut blocks = Vec::new();
        let mut off = FULL_HDR;
        while off + METADATA_BLOCK_HDR <= bytes.len() {
            let hdr = bytes[off];
            let last = (hdr & 0x80) != 0;
            let block_type = hdr & 0x7F;
            let length =
                u32::from_be_bytes([0, bytes[off + 1], bytes[off + 2], bytes[off + 3]]) as usize;
            let data_start = off + METADATA_BLOCK_HDR;
            let data_end = (data_start + length).min(bytes.len());
            blocks.push(FlacMetadataBlock {
                last,
                block_type,
                data: bytes[data_start..data_end].to_vec(),
            });
            off = data_end;
            if last {
                break;
            }
        }
        Ok(Self {
            version,
            flags,
            blocks,
        })
    }
}

impl Serialize for FlacSpecificBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        let mut n = FULL_HDR;
        for b in &self.blocks {
            n += METADATA_BLOCK_HDR + b.data.len();
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
        let fb = self.flags.to_be_bytes();
        buf[1..4].copy_from_slice(&fb[1..]);
        let mut off = FULL_HDR;
        for b in &self.blocks {
            buf[off] = ((b.last as u8) << 7) | (b.block_type & 0x7F);
            let len = b.data.len() as u32;
            let lb = len.to_be_bytes();
            buf[off + 1..off + 4].copy_from_slice(&lb[1..]);
            off += METADATA_BLOCK_HDR;
            buf[off..off + b.data.len()].copy_from_slice(&b.data);
            off += b.data.len();
        }
        Ok(need)
    }
}
