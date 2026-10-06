//! AC-4 in ISOBMFF — `ac-4` AudioSampleEntry + `dac4` config box.

use crate::error::{Error, Result};
use alloc::vec::Vec;
use bitforge::{Parse, Serialize};

pub const DAC4_FOURCC: [u8; 4] = *b"dac4";
pub const AC4_FOURCC: [u8; 4] = *b"ac-4";

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Ac4SpecificBox {

    pub ac4_dsi: Vec<u8>,
}

impl Ac4SpecificBox {

    pub fn new(ac4_dsi: Vec<u8>) -> Self {
        Self { ac4_dsi }
    }
}

impl<'a> Parse<'a> for Ac4SpecificBox {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        Ok(Self {
            ac4_dsi: bytes.to_vec(),
        })
    }
}

impl Serialize for Ac4SpecificBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        self.ac4_dsi.len()
    }
    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        buf[..need].copy_from_slice(&self.ac4_dsi);
        Ok(need)
    }
}
