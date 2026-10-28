//! TrueHD (MLP) audio in ISOBMFF — `mlpa` AudioSampleEntry + MLP config box.

use crate::error::{Error, Result};
use bitforge::{Parse, Serialize};

pub const MLPA_FOURCC: [u8; 4] = *b"mlpa";
pub const MLP_BODY_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct MlpSpecificBox {
    pub version: u8,
    pub revision: u8,
    pub start_offset: u32,
    pub frame_size: u16,
    pub frame_size_bytes: u16,
    pub reserved: u16,
}

impl MlpSpecificBox {
    pub fn new() -> Self {
        Self {
            version: 0,
            revision: 0,
            start_offset: 0,
            frame_size: 0,
            frame_size_bytes: 0,
            reserved: 0,
        }
    }
}

impl Default for MlpSpecificBox {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Parse<'a> for MlpSpecificBox {
    type Error = Error;

    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < MLP_BODY_LEN {
            return Err(Error::BufferTooShort {
                need: MLP_BODY_LEN,
                have: bytes.len(),
                what: "mlp body",
            });
        }
        Ok(Self {
            version: bytes[0],
            revision: bytes[1],
            start_offset: u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
            frame_size: u16::from_be_bytes([bytes[6], bytes[7]]),
            frame_size_bytes: u16::from_be_bytes([bytes[8], bytes[9]]),
            reserved: u16::from_be_bytes([bytes[10], bytes[11]]),
        })
    }
}

impl Serialize for MlpSpecificBox {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        MLP_BODY_LEN
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = MLP_BODY_LEN;
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        buf[0] = self.version;
        buf[1] = self.revision;
        buf[2..6].copy_from_slice(&self.start_offset.to_be_bytes());
        buf[6..8].copy_from_slice(&self.frame_size.to_be_bytes());
        buf[8..10].copy_from_slice(&self.frame_size_bytes.to_be_bytes());
        buf[10..12].copy_from_slice(&self.reserved.to_be_bytes());
        Ok(need)
    }
}
