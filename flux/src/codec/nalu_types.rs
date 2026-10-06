//! NAL unit byte-slice newtypes and typed arrays for AVC/HEVC decoder config records.

use crate::error::{Error, Result};
use alloc::vec::Vec;
use bitforge::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AvcSps(pub Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AvcPps(pub Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AvcSpsExt(pub Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct HevcNalUnit(pub Vec<u8>);

impl HevcNalUnit {
    const LENGTH_FIELD_SIZE: usize = 2;
}

impl Serialize for HevcNalUnit {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        Self::LENGTH_FIELD_SIZE + self.0.len()
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let len = self.0.len();
        buf[..2].copy_from_slice(&(len as u16).to_be_bytes());
        buf[2..need].copy_from_slice(&self.0);
        Ok(need)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct HevcNalArray {
    pub array_completeness: bool,
    pub nal_unit_type: u8,
    pub nalus: Vec<HevcNalUnit>,
}

impl HevcNalArray {
    pub fn new(array_completeness: bool, nal_unit_type: u8, nalus: Vec<HevcNalUnit>) -> Self {
        Self {
            array_completeness,
            nal_unit_type,
            nalus,
        }
    }
}

impl Serialize for HevcNalArray {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        3 + self.nalus.iter().map(|n| n.serialized_len()).sum::<usize>()
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
        let first_byte =
            (if self.array_completeness { 0x80u8 } else { 0u8 }) | (self.nal_unit_type & 0x3F);
        buf[cursor] = first_byte;
        cursor += 1;

        let count = self.nalus.len();
        buf[cursor..cursor + 2].copy_from_slice(&(count as u16).to_be_bytes());
        cursor += 2;

        for nalu in &self.nalus {
            cursor += nalu.serialize_into(&mut buf[cursor..])?;
        }

        Ok(cursor)
    }
}
