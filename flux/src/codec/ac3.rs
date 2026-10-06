//! AC-3 and Enhanced AC-3 in ISOBMFF

use crate::error::{Error, Result};
use alloc::vec::Vec;
use bitforge::{Parse, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Ac3SpecificBox {
    pub fscod: u8,
    pub bsid: u8,
    pub bsmod: u8,
    pub acmod: u8,
    pub lfeon: bool,
    pub bit_rate_code: u8,
}

impl Ac3SpecificBox {
    pub fn channel_count(&self) -> u8 {
        acmod_channels(self.acmod)
    }
}

impl<'a> Parse<'a> for Ac3SpecificBox {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {

        if bytes.len() < 3 {
            return Err(Error::BufferTooShort {
                need: 3,
                have: bytes.len(),
                what: "dac3 body",
            });
        }
        let mut bit_pos = 0usize;
        let fscod = read_bits(bytes, &mut bit_pos, 2, "fscod")? as u8;
        let bsid = read_bits(bytes, &mut bit_pos, 5, "bsid")? as u8;
        let bsmod = read_bits(bytes, &mut bit_pos, 3, "bsmod")? as u8;
        let acmod = read_bits(bytes, &mut bit_pos, 3, "acmod")? as u8;
        let lfeon = read_bits(bytes, &mut bit_pos, 1, "lfeon")? != 0;
        let bit_rate_code = read_bits(bytes, &mut bit_pos, 5, "bit_rate_code")? as u8;
        let _reserved = read_bits(bytes, &mut bit_pos, 5, "reserved")?;
        Ok(Self {
            fscod,
            bsid,
            bsmod,
            acmod,
            lfeon,
            bit_rate_code,
        })
    }
}

impl Serialize for Ac3SpecificBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        3
    }
    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < 3 {
            return Err(Error::OutputBufferTooSmall {
                need: 3,
                have: buf.len(),
            });
        }
        let mut bit_pos = 0usize;
        write_bits(buf, &mut bit_pos, 2, self.fscod as u64);
        write_bits(buf, &mut bit_pos, 5, self.bsid as u64);
        write_bits(buf, &mut bit_pos, 3, self.bsmod as u64);
        write_bits(buf, &mut bit_pos, 3, self.acmod as u64);
        write_bits(buf, &mut bit_pos, 1, self.lfeon as u64);
        write_bits(buf, &mut bit_pos, 5, self.bit_rate_code as u64);
        write_bits(buf, &mut bit_pos, 5, 0);
        Ok(3)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Ec3Substream {
    pub fscod: u8,
    pub bsid: u8,
    pub asvc: bool,
    pub bsmod: u8,
    pub acmod: u8,
    pub lfeon: bool,
    pub num_dep_sub: u8,

    pub chan_loc: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Ec3SpecificBox {
    pub data_rate: u16,

    pub num_ind_sub: u8,
    pub substreams: Vec<Ec3Substream>,
}

impl Ec3SpecificBox {
    pub fn channel_count(&self) -> u8 {
        self.substreams
            .first()
            .map(|s| acmod_channels(s.acmod))
            .unwrap_or(0)
    }
}

fn ec3_substream_serialized_len(_sub: &Ec3Substream) -> usize {

    3
}

impl<'a> Parse<'a> for Ec3SpecificBox {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < 2 {
            return Err(Error::BufferTooShort {
                need: 2,
                have: bytes.len(),
                what: "dec3 body",
            });
        }
        let mut bit_pos = 0usize;
        let data_rate = read_bits(bytes, &mut bit_pos, 13, "data_rate")? as u16;
        let num_ind_sub = read_bits(bytes, &mut bit_pos, 3, "num_ind_sub")? as u8;
        let num_sub = num_ind_sub as usize + 1;

        let need_bytes = 2 + num_sub
            * ec3_substream_serialized_len(&Ec3Substream {
                fscod: 0,
                bsid: 0,
                asvc: false,
                bsmod: 0,
                acmod: 0,
                lfeon: false,
                num_dep_sub: 0,
                chan_loc: None,
            });
        if bytes.len() < need_bytes {
            return Err(Error::BufferTooShort {
                need: need_bytes,
                have: bytes.len(),
                what: "dec3 substreams",
            });
        }

        let mut substreams = Vec::with_capacity(num_sub);
        for _ in 0..num_sub {
            let fscod = read_bits(bytes, &mut bit_pos, 2, "fscod")? as u8;
            let bsid = read_bits(bytes, &mut bit_pos, 5, "bsid")? as u8;
            let _res1 = read_bits(bytes, &mut bit_pos, 1, "reserved")?;
            let asvc = read_bits(bytes, &mut bit_pos, 1, "asvc")? != 0;
            let bsmod = read_bits(bytes, &mut bit_pos, 3, "bsmod")? as u8;
            let acmod = read_bits(bytes, &mut bit_pos, 3, "acmod")? as u8;
            let lfeon = read_bits(bytes, &mut bit_pos, 1, "lfeon")? != 0;
            let _res3 = read_bits(bytes, &mut bit_pos, 3, "reserved")?;
            let num_dep_sub = read_bits(bytes, &mut bit_pos, 4, "num_dep_sub")? as u8;
            let chan_loc = if num_dep_sub > 0 {
                Some(read_bits(bytes, &mut bit_pos, 9, "chan_loc")? as u16)
            } else {
                let _res1 = read_bits(bytes, &mut bit_pos, 1, "reserved")?;
                None
            };
            substreams.push(Ec3Substream {
                fscod,
                bsid,
                asvc,
                bsmod,
                acmod,
                lfeon,
                num_dep_sub,
                chan_loc,
            });
        }

        Ok(Self {
            data_rate,
            num_ind_sub,
            substreams,
        })
    }
}

impl Serialize for Ec3SpecificBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {

        2 + self
            .substreams
            .iter()
            .map(|s| if s.num_dep_sub > 0 { 4 } else { 3 })
            .sum::<usize>()
    }
    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut bit_pos = 0usize;
        write_bits(buf, &mut bit_pos, 13, self.data_rate as u64);
        write_bits(buf, &mut bit_pos, 3, self.num_ind_sub as u64);
        for sub in &self.substreams {
            write_bits(buf, &mut bit_pos, 2, sub.fscod as u64);
            write_bits(buf, &mut bit_pos, 5, sub.bsid as u64);
            write_bits(buf, &mut bit_pos, 1, 0);
            write_bits(buf, &mut bit_pos, 1, sub.asvc as u64);
            write_bits(buf, &mut bit_pos, 3, sub.bsmod as u64);
            write_bits(buf, &mut bit_pos, 3, sub.acmod as u64);
            write_bits(buf, &mut bit_pos, 1, sub.lfeon as u64);
            write_bits(buf, &mut bit_pos, 3, 0);
            write_bits(buf, &mut bit_pos, 4, sub.num_dep_sub as u64);
            if sub.num_dep_sub > 0 {
                write_bits(buf, &mut bit_pos, 9, sub.chan_loc.unwrap_or(0) as u64);
            } else {
                write_bits(buf, &mut bit_pos, 1, 0);
            }
        }
        Ok(need)
    }
}

fn read_bits(data: &[u8], bit_pos: &mut usize, n: usize, _what: &'static str) -> Result<u64> {
    if n > 64 {
        return Err(Error::InvalidValue {
            field: _what,
            value: n as u64,
            reason: "bit count > 64",
        });
    }
    let end = *bit_pos + n;
    let need_bytes = end.div_ceil(8);
    if data.len() < need_bytes {
        return Err(Error::BufferTooShort {
            need: need_bytes,
            have: data.len(),
            what: _what,
        });
    }
    let mut val: u64 = 0;
    for _ in 0..n {
        let byte_idx = *bit_pos / 8;
        let bit_in_byte = 7 - (*bit_pos % 8);
        let bit = ((data[byte_idx] >> bit_in_byte) & 1) as u64;
        val = (val << 1) | bit;
        *bit_pos += 1;
    }
    Ok(val)
}

fn write_bits(buf: &mut [u8], bit_pos: &mut usize, n: usize, val: u64) {
    for i in (0..n).rev() {
        let byte_idx = *bit_pos / 8;
        let bit_in_byte = 7 - (*bit_pos % 8);
        let bit = ((val >> i) & 1) as u8;
        buf[byte_idx] = (buf[byte_idx] & !(1 << bit_in_byte)) | (bit << bit_in_byte);
        *bit_pos += 1;
    }
}

fn acmod_channels(acmod: u8) -> u8 {
    match acmod {
        0 => 2,
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 3,
        5 => 4,
        6 => 4,
        _ => 5,
    }
}