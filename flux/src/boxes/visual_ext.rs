//! Visual sample-entry extension boxes — ISO/IEC 14496-12:2015 §12.1.4–5.

use alloc::vec::Vec;
use bitforge::{Parse, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct PixelAspectRatioBox {
    pub h_spacing: u32,
    pub v_spacing: u32,
}

impl<'a> Parse<'a> for PixelAspectRatioBox {
    type Error = Error;

    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < 8 {
            return Err(Error::BufferTooShort {
                need: 8,
                have: bytes.len(),
                what: "pasp body",
            });
        }
        let h_spacing = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let v_spacing = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        Ok(Self {
            h_spacing,
            v_spacing,
        })
    }
}

impl Serialize for PixelAspectRatioBox {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        8
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < 8 {
            return Err(Error::OutputBufferTooSmall {
                need: 8,
                have: buf.len(),
            });
        }
        buf[..4].copy_from_slice(&self.h_spacing.to_be_bytes());
        buf[4..8].copy_from_slice(&self.v_spacing.to_be_bytes());
        Ok(8)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct CleanApertureBox {
    pub clean_aperture_width_n: u32,
    pub clean_aperture_width_d: u32,
    pub clean_aperture_height_n: u32,
    pub clean_aperture_height_d: u32,
    pub horiz_off_n: u32,
    pub horiz_off_d: u32,
    pub vert_off_n: u32,
    pub vert_off_d: u32,
}

impl<'a> Parse<'a> for CleanApertureBox {
    type Error = Error;

    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < 32 {
            return Err(Error::BufferTooShort {
                need: 32,
                have: bytes.len(),
                what: "clap body",
            });
        }
        let clean_aperture_width_n = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let clean_aperture_width_d = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let clean_aperture_height_n =
            u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let clean_aperture_height_d =
            u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let horiz_off_n = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let horiz_off_d = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        let vert_off_n = u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
        let vert_off_d = u32::from_be_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
        Ok(Self {
            clean_aperture_width_n,
            clean_aperture_width_d,
            clean_aperture_height_n,
            clean_aperture_height_d,
            horiz_off_n,
            horiz_off_d,
            vert_off_n,
            vert_off_d,
        })
    }
}

impl Serialize for CleanApertureBox {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        32
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < 32 {
            return Err(Error::OutputBufferTooSmall {
                need: 32,
                have: buf.len(),
            });
        }
        let mut c = 0usize;
        buf[c..c + 4].copy_from_slice(&self.clean_aperture_width_n.to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(&self.clean_aperture_width_d.to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(&self.clean_aperture_height_n.to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(&self.clean_aperture_height_d.to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(&self.horiz_off_n.to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(&self.horiz_off_d.to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(&self.vert_off_n.to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(&self.vert_off_d.to_be_bytes());
        Ok(32)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub enum ColourType {
    Nclx,
    RIcc,
    Prof,
    Unknown([u8; 4]),
}

impl ColourType {
    pub fn name(&self) -> &'static str {
        match self {
            ColourType::Nclx => "nclx",
            ColourType::RIcc => "rICC",
            ColourType::Prof => "prof",
            ColourType::Unknown(_) => "reserved",
        }
    }
}

impl core::fmt::Display for ColourType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ColourType::Unknown(code) => {
                write!(
                    f,
                    "{}(0x{:02X}{:02X}{:02X}{:02X})",
                    self.name(),
                    code[0],
                    code[1],
                    code[2],
                    code[3]
                )
            }
            other => f.write_str(other.name()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct NclxColourInfo {
    pub colour_primaries: u16,
    pub transfer_characteristics: u16,
    pub matrix_coefficients: u16,
    pub full_range_flag: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ColourInformationBox {
    pub colour_type: [u8; 4],
    pub nclx: Option<NclxColourInfo>,
    pub icc_profile: Vec<u8>,
}

impl<'a> Parse<'a> for ColourInformationBox {
    type Error = Error;

    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return Err(Error::BufferTooShort {
                need: 4,
                have: bytes.len(),
                what: "colr body",
            });
        }
        let colour_type = [bytes[0], bytes[1], bytes[2], bytes[3]];
        let rest = &bytes[4..];

        match &colour_type {
            b"nclx" => {
                if rest.len() < 7 {
                    return Err(Error::BufferTooShort {
                        need: 7,
                        have: rest.len(),
                        what: "colr nclx params",
                    });
                }
                let colour_primaries = u16::from_be_bytes([rest[0], rest[1]]);
                let transfer_characteristics = u16::from_be_bytes([rest[2], rest[3]]);
                let matrix_coefficients = u16::from_be_bytes([rest[4], rest[5]]);
                let full_range_flag = (rest[6] >> 7) != 0;
                Ok(Self {
                    colour_type,
                    nclx: Some(NclxColourInfo {
                        colour_primaries,
                        transfer_characteristics,
                        matrix_coefficients,
                        full_range_flag,
                    }),
                    icc_profile: Vec::new(),
                })
            }
            b"rICC" | b"prof" => Ok(Self {
                colour_type,
                nclx: None,
                icc_profile: rest.to_vec(),
            }),
            _ => Ok(Self {
                colour_type,
                nclx: None,
                icc_profile: rest.to_vec(),
            }),
        }
    }
}

impl Serialize for ColourInformationBox {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        let mut n = 4;
        match &self.colour_type {
            b"nclx" => {
                n += 7;
            }
            _ => {
                n += self.icc_profile.len();
            }
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
        let mut c = 0usize;
        buf[c..c + 4].copy_from_slice(&self.colour_type);
        c += 4;
        match &self.colour_type {
            b"nclx" => {
                if let Some(nclx) = &self.nclx {
                    buf[c..c + 2].copy_from_slice(&nclx.colour_primaries.to_be_bytes());
                    c += 2;
                    buf[c..c + 2].copy_from_slice(&nclx.transfer_characteristics.to_be_bytes());
                    c += 2;
                    buf[c..c + 2].copy_from_slice(&nclx.matrix_coefficients.to_be_bytes());
                    c += 2;
                    buf[c] = (nclx.full_range_flag as u8) << 7;
                    c += 1;
                }
            }
            _ => {
                buf[c..c + self.icc_profile.len()].copy_from_slice(&self.icc_profile);
                c += self.icc_profile.len();
            }
        }
        Ok(c)
    }
}
