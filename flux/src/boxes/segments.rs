//! Segment-level ISOBMFF boxes — ISO/IEC 14496-12:2015.

use crate::error::{Error, Result};
use alloc::vec::Vec;
use bitforge::Serialize;

pub const FTYP: [u8; 4] = *b"ftyp";

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
struct BrandBox {
    major_brand: [u8; 4],
    minor_version: u32,
    compatible_brands: Vec<[u8; 4]>,
}

impl BrandBox {
    fn body_len(&self) -> usize {

        4 + 4 + self.compatible_brands.len() * 4
    }

    fn parse_body(body: &[u8]) -> Result<Self> {
        if body.len() < 8 {
            return Err(Error::BufferTooShort {
                need: 8,
                have: body.len(),
                what: "ftyp/styp body",
            });
        }
        let major_brand = [body[0], body[1], body[2], body[3]];
        let minor_version = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
        let mut compatible_brands = Vec::new();
        let mut off = 8;
        while off + 4 <= body.len() {
            compatible_brands.push([body[off], body[off + 1], body[off + 2], body[off + 3]]);
            off += 4;
        }
        Ok(Self {
            major_brand,
            minor_version,
            compatible_brands,
        })
    }

    fn serialize_into(&self, four_cc: &[u8; 4], buf: &mut [u8]) -> Result<usize> {
        let need = 8 + self.body_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        buf[0..4].copy_from_slice(&(need as u32).to_be_bytes());
        buf[4..8].copy_from_slice(four_cc);
        buf[8..12].copy_from_slice(&self.major_brand);
        buf[12..16].copy_from_slice(&self.minor_version.to_be_bytes());
        let mut off = 16;
        for brand in &self.compatible_brands {
            buf[off..off + 4].copy_from_slice(brand);
            off += 4;
        }
        Ok(need)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FileTypeBox {
    pub major_brand: [u8; 4],
    pub minor_version: u32,
    pub compatible_brands: Vec<[u8; 4]>,
}

impl FileTypeBox {

    pub fn parse_box(bytes: &[u8]) -> Result<Self> {
        let b = BrandBox::parse_body(box_body(bytes, &FTYP)?)?;
        Ok(Self {
            major_brand: b.major_brand,
            minor_version: b.minor_version,
            compatible_brands: b.compatible_brands,
        })
    }

    fn brand(&self) -> BrandBox {
        BrandBox {
            major_brand: self.major_brand,
            minor_version: self.minor_version,
            compatible_brands: self.compatible_brands.clone(),
        }
    }
}

impl Serialize for FileTypeBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        8 + self.brand().body_len()
    }
    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        self.brand().serialize_into(&FTYP, buf)
    }
}

fn box_body<'a>(bytes: &'a [u8], four_cc: &[u8; 4]) -> Result<&'a [u8]> {
    if bytes.len() < 8 {
        return Err(Error::BufferTooShort {
            need: 8,
            have: bytes.len(),
            what: "box header",
        });
    }
    if bytes[4..8] != *four_cc {
        return Err(Error::UnexpectedBox {
            expected: "ftyp/styp",
        });
    }
    let size = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if size < 8 || size > bytes.len() {
        return Err(Error::BufferTooShort {
            need: size,
            have: bytes.len(),
            what: "box size",
        });
    }
    Ok(&bytes[8..size])
}