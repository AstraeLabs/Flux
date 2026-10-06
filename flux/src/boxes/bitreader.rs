//! Exp-Golomb bit reader over an RBSP byte stream.

use crate::error::{Error, Result};
use alloc::vec::Vec;

fn unescape(nal: &[u8]) -> Vec<u8> {
    let n = nal.len();
    let mut out = Vec::with_capacity(n);
    let mut i = 0;
    while i < n {
        if i + 2 < n && nal[i] == 0 && nal[i + 1] == 0 && nal[i + 2] == 3 {
            out.push(0);
            out.push(0);
            i += 3;
        } else {
            out.push(nal[i]);
            i += 1;
        }
    }
    out
}

pub struct BitReader {
    data: Vec<u8>,
    bit_pos: usize,
}

impl BitReader {
    pub fn from_rbsp(data: &[u8], what: &'static str) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::BufferTooShort {
                need: 1,
                have: 0,
                what,
            });
        }
        Ok(Self {
            data: data.to_vec(),
            bit_pos: 0,
        })
    }

    pub fn with_unescape(nal_body: &[u8], what: &'static str) -> Result<Self> {
        let rbsp = unescape(nal_body);
        if rbsp.is_empty() {
            return Err(Error::BufferTooShort {
                need: 1,
                have: 0,
                what,
            });
        }
        Ok(Self {
            data: rbsp,
            bit_pos: 0,
        })
    }

    fn has_bits(&self, n: usize) -> bool {
        self.bit_pos + n <= self.data.len() * 8
    }

    pub fn read_bits(&mut self, n: usize, what: &'static str) -> Result<u64> {
        if n > 64 || !self.has_bits(n) {
            return Err(Error::BufferTooShort {
                need: self.bit_pos + n,
                have: self.data.len() * 8,
                what,
            });
        }
        if n == 0 {
            return Ok(0);
        }
        let mut val: u64 = 0;
        for _ in 0..n {
            let byte_idx = self.bit_pos / 8;
            let bit_in_byte = 7 - (self.bit_pos % 8);
            let bit = ((self.data[byte_idx] >> bit_in_byte) & 1) as u64;
            val = (val << 1) | bit;
            self.bit_pos += 1;
        }
        Ok(val)
    }

    pub fn read_flag(&mut self, what: &'static str) -> Result<bool> {
        Ok(self.read_bits(1, what)? != 0)
    }

    pub fn align_to_byte(&mut self, what: &'static str) -> Result<()> {
        while !self.bit_pos.is_multiple_of(8) {
            let _ = self.read_bits(1, what)?;
        }
        Ok(())
    }

    pub fn read_ue(&mut self, what: &'static str) -> Result<u64> {
        let mut leading_zero_bits: u32 = 0;
        while self.has_bits(1) && self.read_bits(1, what)? == 0 {
            leading_zero_bits += 1;
        }
        if leading_zero_bits > 0 && !self.has_bits(leading_zero_bits as usize) {
            return Err(Error::BufferTooShort {
                need: self.bit_pos + leading_zero_bits as usize,
                have: self.data.len() * 8,
                what,
            });
        }
        if leading_zero_bits == 0 {
            return Ok(0);
        }
        let info = self.read_bits(leading_zero_bits as usize, what)?;
        Ok((1u64 << leading_zero_bits) - 1 + info)
    }

    pub fn read_se(&mut self, what: &'static str) -> Result<i64> {
        let code_num = self.read_ue(what)?;
        if code_num & 1 == 0 {
            Ok(-((code_num >> 1) as i64))
        } else {
            Ok(((code_num + 1) >> 1) as i64)
        }
    }
}