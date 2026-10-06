//! Common Encryption boxes

use crate::error::{Error, Result};
use alloc::vec::Vec;
use bitforge::{Parse, Serialize};

const BOX_HDR: usize = 8;
const FULL_HDR: usize = 4;

pub use bitforge::cenc::CencScheme;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TrackEncryptionBox {
    pub version: u8,
    pub default_crypt_byte_block: u8,
    pub default_skip_byte_block: u8,
    pub default_is_protected: u8,
    pub default_per_sample_iv_size: u8,
    pub default_kid: [u8; 16],
    pub default_constant_iv: Option<Vec<u8>>,
}

impl TrackEncryptionBox {
    pub fn parse_body(bytes: &[u8], version: u8) -> Result<Self> {
        let min = 1 + 1 + 1 + 16;
        if bytes.len() < min {
            return Err(Error::BufferTooShort {
                need: min,
                have: bytes.len(),
                what: "tenc body",
            });
        }
        let mut offset = 0usize;
        let _reserved = bytes[offset];
        offset += 1;
        let (crypt_byte_block, skip_byte_block) = if version == 0 {
            let _reserved2 = bytes[offset];
            offset += 1;
            (0u8, 0u8)
        } else {
            let v = bytes[offset];
            offset += 1;
            (v >> 4, v & 0x0F)
        };
        let is_protected = bytes[offset];
        offset += 1;
        let iv_size = bytes[offset];
        offset += 1;
        let mut kid = [0u8; 16];
        kid.copy_from_slice(&bytes[offset..offset + 16]);
        offset += 16;

        let constant_iv = if is_protected == 1 && iv_size == 0 {
            if bytes.len() < offset + 1 {
                return Err(Error::BufferTooShort {
                    need: offset + 1,
                    have: bytes.len(),
                    what: "tenc constant_IV_size",
                });
            }
            let iv_len = bytes[offset] as usize;
            offset += 1;
            if bytes.len() < offset + iv_len {
                return Err(Error::BufferTooShort {
                    need: offset + iv_len,
                    have: bytes.len(),
                    what: "tenc constant_IV",
                });
            }
            let iv = bytes[offset..offset + iv_len].to_vec();
            Some(iv)
        } else {
            None
        };
        Ok(Self {
            version,
            default_crypt_byte_block: crypt_byte_block,
            default_skip_byte_block: skip_byte_block,
            default_is_protected: is_protected,
            default_per_sample_iv_size: iv_size,
            default_kid: kid,
            default_constant_iv: constant_iv,
        })
    }

    pub fn parse_box(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < BOX_HDR + FULL_HDR {
            return Err(Error::BufferTooShort {
                need: BOX_HDR + FULL_HDR,
                have: bytes.len(),
                what: "tenc header",
            });
        }
        let version = bytes[8];
        let _flags = u32::from_be_bytes([0, bytes[9], bytes[10], bytes[11]]);
        Self::parse_body(&bytes[BOX_HDR + FULL_HDR..], version)
    }
}

impl Serialize for TrackEncryptionBox {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        let mut n = BOX_HDR + FULL_HDR + 2 + 1 + 1 + 16;
        if let Some(ref iv) = self.default_constant_iv {
            n += 1 + iv.len();
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
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"tenc");
        c += 4;
        buf[c] = self.version;
        c += 1;
        buf[c] = 0;
        c += 1;
        buf[c] = 0;
        c += 1;
        buf[c] = 0;
        c += 1;
        buf[c] = 0;
        c += 1;
        if self.version == 0 {
            buf[c] = 0;
            c += 1;
        } else {
            buf[c] = (self.default_crypt_byte_block << 4) | (self.default_skip_byte_block & 0x0F);
            c += 1;
        }
        buf[c] = self.default_is_protected;
        c += 1;
        buf[c] = self.default_per_sample_iv_size;
        c += 1;
        buf[c..c + 16].copy_from_slice(&self.default_kid);
        c += 16;
        if let Some(ref iv) = self.default_constant_iv {
            buf[c] = iv.len() as u8;
            c += 1;
            buf[c..c + iv.len()].copy_from_slice(iv);
            c += iv.len();
        }
        Ok(c)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SampleEncryptionEntry {
    pub initialization_vector: Vec<u8>,
    pub subsamples: Vec<SubSampleEntry>,
    pub is_encrypted: bool,
    pub explicit_kid: Option<[u8; 16]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SubSampleEntry {
    pub bytes_of_clear_data: u16,
    pub bytes_of_protected_data: u32,
}

pub const SENC_FLAG_USE_SUBSAMPLE_ENCRYPTION: u32 = 0x000002;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SampleEncryptionBox {
    pub version: u8,
    pub flags: u32,
    pub per_sample_iv_size: u8,
    pub entries: Vec<SampleEncryptionEntry>,
}

const SENC_SAMPLE_COUNT_LEN: usize = 4;
const SENC_SUBSAMPLE_COUNT_LEN: usize = 2;

impl SampleEncryptionBox {
    pub fn parse_body(
        bytes: &[u8],
        version: u8,
        flags: u32,
        per_sample_iv_size: u8,
    ) -> Result<Self> {
        if bytes.len() < SENC_SAMPLE_COUNT_LEN {
            return Err(Error::BufferTooShort {
                need: SENC_SAMPLE_COUNT_LEN,
                have: bytes.len(),
                what: "senc sample_count",
            });
        }
        let sample_count = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let mut offset = SENC_SAMPLE_COUNT_LEN;
        let iv_sz = per_sample_iv_size as usize;
        let use_subs = (flags & SENC_FLAG_USE_SUBSAMPLE_ENCRYPTION) != 0;

        let min_entry_len = iv_sz
            + if use_subs {
                SENC_SUBSAMPLE_COUNT_LEN
            } else {
                0
            };
        if min_entry_len == 0 {
            return Ok(Self {
                version,
                flags,
                per_sample_iv_size,
                entries: Vec::new(),
            });
        } else {
            let need = sample_count
                .checked_mul(min_entry_len)
                .and_then(|n| n.checked_add(offset))
                .ok_or(Error::InvalidInput("senc sample_count overflows the body"))?;
            if need > bytes.len() {
                return Err(Error::BufferTooShort {
                    need,
                    have: bytes.len(),
                    what: "senc entries (sample_count exceeds what the box can hold)",
                });
            }
        }

        let mut entries = Vec::with_capacity(sample_count);
        for _ in 0..sample_count {
            if bytes.len() < offset + iv_sz {
                return Err(Error::BufferTooShort {
                    need: offset + iv_sz,
                    have: bytes.len(),
                    what: "senc IV",
                });
            }
            let iv = bytes[offset..offset + iv_sz].to_vec();
            offset += iv_sz;
            let mut subsamples = Vec::new();
            if use_subs {
                if bytes.len() < offset + 2 {
                    return Err(Error::BufferTooShort {
                        need: offset + 2,
                        have: bytes.len(),
                        what: "senc subsample_count",
                    });
                }
                let sub_count = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
                offset += 2;
                for _ in 0..sub_count {
                    if bytes.len() < offset + 6 {
                        return Err(Error::BufferTooShort {
                            need: offset + 6,
                            have: bytes.len(),
                            what: "senc subsample",
                        });
                    }
                    let bytes_clear = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
                    offset += 2;
                    let bytes_protected = u32::from_be_bytes([
                        bytes[offset],
                        bytes[offset + 1],
                        bytes[offset + 2],
                        bytes[offset + 3],
                    ]);
                    offset += 4;
                    subsamples.push(SubSampleEntry {
                        bytes_of_clear_data: bytes_clear,
                        bytes_of_protected_data: bytes_protected,
                    });
                }
            }
            entries.push(SampleEncryptionEntry {
                initialization_vector: iv,
                subsamples,
                is_encrypted: true,
                explicit_kid: None,
            });
        }
        Ok(Self {
            version,
            flags,
            per_sample_iv_size,
            entries,
        })
    }
}

impl Serialize for SampleEncryptionBox {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        let mut n = BOX_HDR + FULL_HDR + 4;
        for e in &self.entries {
            n += e.initialization_vector.len();
            if (self.flags & SENC_FLAG_USE_SUBSAMPLE_ENCRYPTION) != 0 {
                n += 2;
                n += e.subsamples.len() * 6;
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
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"senc");
        c += 4;
        buf[c] = self.version;
        c += 1;
        let fb = self.flags.to_be_bytes();
        buf[c..c + 3].copy_from_slice(&fb[1..]);
        c += 3;
        buf[c..c + 4].copy_from_slice(&(self.entries.len() as u32).to_be_bytes());
        c += 4;
        for e in &self.entries {
            buf[c..c + e.initialization_vector.len()].copy_from_slice(&e.initialization_vector);
            c += e.initialization_vector.len();
            if (self.flags & SENC_FLAG_USE_SUBSAMPLE_ENCRYPTION) != 0 {
                buf[c..c + 2].copy_from_slice(&(e.subsamples.len() as u16).to_be_bytes());
                c += 2;
                for s in &e.subsamples {
                    buf[c..c + 2].copy_from_slice(&s.bytes_of_clear_data.to_be_bytes());
                    c += 2;
                    buf[c..c + 4].copy_from_slice(&s.bytes_of_protected_data.to_be_bytes());
                    c += 4;
                }
            }
        }
        Ok(c)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ProtectionSystemSpecificHeaderBox {
    pub version: u8,
    pub system_id: [u8; 16],
    pub kids: Vec<[u8; 16]>,
    pub data: Vec<u8>,
}

impl ProtectionSystemSpecificHeaderBox {
    pub fn parse_box(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < BOX_HDR + FULL_HDR {
            return Err(Error::BufferTooShort {
                need: BOX_HDR + FULL_HDR,
                have: bytes.len(),
                what: "pssh header",
            });
        }
        let version = bytes[8];
        Self::parse_body(&bytes[BOX_HDR + FULL_HDR..], version)
    }

    pub fn to_vec(&self) -> Result<Vec<u8>> {
        let mut buf = alloc::vec![0u8; self.serialized_len()];
        let n = self.serialize_into(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn parse_body(bytes: &[u8], version: u8) -> Result<Self> {
        if bytes.len() < 16 + 4 {
            return Err(Error::BufferTooShort {
                need: 16 + 4,
                have: bytes.len(),
                what: "pssh SystemID+DataSize",
            });
        }
        let mut system_id = [0u8; 16];
        system_id.copy_from_slice(&bytes[0..16]);
        let mut offset = 16usize;
        let mut kids = Vec::new();
        if version > 0 {
            if bytes.len() < offset + 4 {
                return Err(Error::BufferTooShort {
                    need: offset + 4,
                    have: bytes.len(),
                    what: "pssh KID_count",
                });
            }
            let kid_count = u32::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]) as usize;
            offset += 4;
            let kid_needed = kid_count * 16;
            if bytes.len() < offset + kid_needed {
                return Err(Error::BufferTooShort {
                    need: offset + kid_needed,
                    have: bytes.len(),
                    what: "pssh KIDs",
                });
            }
            for i in 0..kid_count {
                let mut kid = [0u8; 16];
                kid.copy_from_slice(&bytes[offset + i * 16..offset + (i + 1) * 16]);
                kids.push(kid);
            }
            offset += kid_needed;
        }
        let data_size = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;
        if bytes.len() < offset + data_size {
            return Err(Error::BufferTooShort {
                need: offset + data_size,
                have: bytes.len(),
                what: "pssh Data",
            });
        }
        let data = bytes[offset..offset + data_size].to_vec();
        Ok(Self {
            version,
            system_id,
            kids,
            data,
        })
    }
}

impl Serialize for ProtectionSystemSpecificHeaderBox {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        let mut n = BOX_HDR + FULL_HDR + 16 + 4 + self.data.len();
        if self.version > 0 {
            n += 4 + self.kids.len() * 16;
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
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"pssh");
        c += 4;
        buf[c] = self.version;
        c += 1;
        buf[c] = 0;
        c += 1;
        buf[c] = 0;
        c += 1;
        buf[c] = 0;
        c += 1;
        buf[c..c + 16].copy_from_slice(&self.system_id);
        c += 16;
        if self.version > 0 {
            buf[c..c + 4].copy_from_slice(&(self.kids.len() as u32).to_be_bytes());
            c += 4;
            for kid in &self.kids {
                buf[c..c + 16].copy_from_slice(kid);
                c += 16;
            }
        }
        buf[c..c + 4].copy_from_slice(&(self.data.len() as u32).to_be_bytes());
        c += 4;
        buf[c..c + self.data.len()].copy_from_slice(&self.data);
        c += self.data.len();
        Ok(c)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SampleAuxInfoSizesBox {
    pub version: u8,
    pub flags: u32,
    pub aux_info_type: Option<u32>,
    pub aux_info_type_parameter: Option<u32>,
    pub default_sample_info_size: u8,
    pub sample_info_sizes: Vec<u8>,
}

impl SampleAuxInfoSizesBox {
    pub fn parse_box(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < BOX_HDR + FULL_HDR {
            return Err(Error::BufferTooShort {
                need: BOX_HDR + FULL_HDR,
                have: bytes.len(),
                what: "saiz header",
            });
        }
        let version = bytes[8];
        let flags = u32::from_be_bytes([0, bytes[9], bytes[10], bytes[11]]);
        Self::parse_body(&bytes[BOX_HDR + FULL_HDR..], version, flags)
    }

    pub fn parse_body(bytes: &[u8], version: u8, flags: u32) -> Result<Self> {
        let mut offset = 0usize;
        let (aux_info_type, aux_info_type_parameter) = if (flags & 0x01) != 0 {
            if bytes.len() < 8 {
                return Err(Error::BufferTooShort {
                    need: 8,
                    have: bytes.len(),
                    what: "saiz aux_info_type",
                });
            }
            let ty = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let param = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            offset = 8;
            (Some(ty), Some(param))
        } else {
            (None, None)
        };
        if bytes.len() < offset + 1 + 4 {
            return Err(Error::BufferTooShort {
                need: offset + 5,
                have: bytes.len(),
                what: "saiz default_sample_info_size+sample_count",
            });
        }
        let default_size = bytes[offset];
        offset += 1;
        let sample_count = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;
        let sample_info_sizes = if default_size == 0 {
            if bytes.len() < offset + sample_count {
                return Err(Error::BufferTooShort {
                    need: offset + sample_count,
                    have: bytes.len(),
                    what: "saiz sample_info_size",
                });
            }
            bytes[offset..offset + sample_count].to_vec()
        } else {
            Vec::new()
        };
        Ok(Self {
            version,
            flags,
            aux_info_type,
            aux_info_type_parameter,
            default_sample_info_size: default_size,
            sample_info_sizes,
        })
    }
}

impl Serialize for SampleAuxInfoSizesBox {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        let mut n = BOX_HDR + FULL_HDR;
        if (self.flags & 0x01) != 0 {
            n += 8;
        }
        n += 1 + 4;
        if self.default_sample_info_size == 0 {
            n += self.sample_info_sizes.len();
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
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"saiz");
        c += 4;
        buf[c] = self.version;
        c += 1;
        let fb = self.flags.to_be_bytes();
        buf[c..c + 3].copy_from_slice(&fb[1..]);
        c += 3;
        if (self.flags & 0x01) != 0 {
            let ty = self.aux_info_type.unwrap_or(0);
            let param = self.aux_info_type_parameter.unwrap_or(0);
            buf[c..c + 4].copy_from_slice(&ty.to_be_bytes());
            c += 4;
            buf[c..c + 4].copy_from_slice(&param.to_be_bytes());
            c += 4;
        }
        buf[c] = self.default_sample_info_size;
        c += 1;
        let sample_count = self.sample_info_sizes.len() as u32;
        buf[c..c + 4].copy_from_slice(&sample_count.to_be_bytes());
        c += 4;
        if self.default_sample_info_size == 0 {
            buf[c..c + self.sample_info_sizes.len()].copy_from_slice(&self.sample_info_sizes);
            c += self.sample_info_sizes.len();
        }
        Ok(c)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SampleAuxInfoOffsetsBox {
    pub version: u8,
    pub flags: u32,
    pub aux_info_type: Option<u32>,
    pub aux_info_type_parameter: Option<u32>,
    pub offsets: Vec<u64>,
}

impl SampleAuxInfoOffsetsBox {
    pub fn parse_box(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < BOX_HDR + FULL_HDR {
            return Err(Error::BufferTooShort {
                need: BOX_HDR + FULL_HDR,
                have: bytes.len(),
                what: "saio header",
            });
        }
        let version = bytes[8];
        let flags = u32::from_be_bytes([0, bytes[9], bytes[10], bytes[11]]);
        Self::parse_body(&bytes[BOX_HDR + FULL_HDR..], version, flags)
    }

    pub fn parse_body(bytes: &[u8], version: u8, flags: u32) -> Result<Self> {
        let mut offset = 0usize;
        let (aux_info_type, aux_info_type_parameter) = if (flags & 0x01) != 0 {
            if bytes.len() < 8 {
                return Err(Error::BufferTooShort {
                    need: 8,
                    have: bytes.len(),
                    what: "saio aux_info_type",
                });
            }
            let ty = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let param = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            offset = 8;
            (Some(ty), Some(param))
        } else {
            (None, None)
        };
        if bytes.len() < offset + 4 {
            return Err(Error::BufferTooShort {
                need: offset + 4,
                have: bytes.len(),
                what: "saio entry_count",
            });
        }
        let entry_count = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;
        let offset_sz = if version == 0 { 4 } else { 8 };
        let offsets_needed = entry_count
            .checked_mul(offset_sz)
            .ok_or(Error::InvalidInput("saio entry_count overflows the body"))?;
        if bytes.len() < offset + offsets_needed {
            return Err(Error::BufferTooShort {
                need: offset + offsets_needed,
                have: bytes.len(),
                what: "saio offsets",
            });
        }
        let mut offsets = Vec::with_capacity(entry_count);
        for i in 0..entry_count {
            let o = if version == 0 {
                u32::from_be_bytes([
                    bytes[offset + i * 4],
                    bytes[offset + i * 4 + 1],
                    bytes[offset + i * 4 + 2],
                    bytes[offset + i * 4 + 3],
                ]) as u64
            } else {
                u64::from_be_bytes([
                    bytes[offset + i * 8],
                    bytes[offset + i * 8 + 1],
                    bytes[offset + i * 8 + 2],
                    bytes[offset + i * 8 + 3],
                    bytes[offset + i * 8 + 4],
                    bytes[offset + i * 8 + 5],
                    bytes[offset + i * 8 + 6],
                    bytes[offset + i * 8 + 7],
                ])
            };
            offsets.push(o);
        }
        Ok(Self {
            version,
            flags,
            aux_info_type,
            aux_info_type_parameter,
            offsets,
        })
    }
}

impl Serialize for SampleAuxInfoOffsetsBox {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        let mut n = BOX_HDR + FULL_HDR;
        if (self.flags & 0x01) != 0 {
            n += 8;
        }
        n += 4;
        n += self.offsets.len() * if self.version == 0 { 4 } else { 8 };
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
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"saio");
        c += 4;
        buf[c] = self.version;
        c += 1;
        let fb = self.flags.to_be_bytes();
        buf[c..c + 3].copy_from_slice(&fb[1..]);
        c += 3;
        if (self.flags & 0x01) != 0 {
            let ty = self.aux_info_type.unwrap_or(0);
            let param = self.aux_info_type_parameter.unwrap_or(0);
            buf[c..c + 4].copy_from_slice(&ty.to_be_bytes());
            c += 4;
            buf[c..c + 4].copy_from_slice(&param.to_be_bytes());
            c += 4;
        }
        buf[c..c + 4].copy_from_slice(&(self.offsets.len() as u32).to_be_bytes());
        c += 4;
        if self.version == 0 {
            for &off in &self.offsets {
                buf[c..c + 4].copy_from_slice(&(off as u32).to_be_bytes());
                c += 4;
            }
        } else {
            for &off in &self.offsets {
                buf[c..c + 8].copy_from_slice(&off.to_be_bytes());
                c += 8;
            }
        }
        Ok(c)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct OriginalFormatBox {
    pub data_format: [u8; 4],
}

impl<'a> Parse<'a> for OriginalFormatBox {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < BOX_HDR + 4 {
            return Err(Error::BufferTooShort {
                need: BOX_HDR + 4,
                have: bytes.len(),
                what: "frma",
            });
        }
        let mut df = [0u8; 4];
        df.copy_from_slice(&bytes[BOX_HDR..BOX_HDR + 4]);
        Ok(Self { data_format: df })
    }
}

impl Serialize for OriginalFormatBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        BOX_HDR + 4
    }
    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        buf[..4].copy_from_slice(&(need as u32).to_be_bytes());
        buf[4..8].copy_from_slice(b"frma");
        buf[8..12].copy_from_slice(&self.data_format);
        Ok(need)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SchemeTypeBox {
    pub version: u8,
    pub flags: u32,
    pub scheme_type: [u8; 4],
    pub scheme_version: u32,
    pub scheme_uri: Option<Vec<u8>>,
}

impl SchemeTypeBox {
    pub fn parse_body(bytes: &[u8], _version: u8, flags: u32) -> Result<Self> {
        if bytes.len() < 8 {
            return Err(Error::BufferTooShort {
                need: 8,
                have: bytes.len(),
                what: "schm body",
            });
        }
        let mut scheme_type = [0u8; 4];
        scheme_type.copy_from_slice(&bytes[0..4]);
        let scheme_version = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let scheme_uri = if (flags & 0x000001) != 0 {
            Some(bytes[8..].to_vec())
        } else {
            None
        };
        Ok(Self {
            version: _version,
            flags,
            scheme_type,
            scheme_version,
            scheme_uri,
        })
    }
}

impl Serialize for SchemeTypeBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        let mut n = BOX_HDR + FULL_HDR + 8;
        if let Some(ref uri) = self.scheme_uri {
            n += uri.len();
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
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"schm");
        c += 4;
        buf[c] = self.version;
        c += 1;
        let fb = self.flags.to_be_bytes();
        buf[c..c + 3].copy_from_slice(&fb[1..]);
        c += 3;
        buf[c..c + 4].copy_from_slice(&self.scheme_type);
        c += 4;
        buf[c..c + 4].copy_from_slice(&self.scheme_version.to_be_bytes());
        c += 4;
        if let Some(ref uri) = self.scheme_uri {
            buf[c..c + uri.len()].copy_from_slice(uri);
            c += uri.len();
        }
        Ok(c)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SchemeInformationBox {
    pub tenc: Option<TrackEncryptionBox>,
    pub extra_boxes: Vec<crate::init_segment::OpaqueBox>,
}

impl<'a> Parse<'a> for SchemeInformationBox {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        let body = &bytes[BOX_HDR..];
        let mut tenc = None;
        let mut extra_boxes = Vec::new();
        let mut off = 0usize;
        while off + 8 <= body.len() {
            let sz = u32::from_be_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]])
                as usize;
            if sz < 8 {
                break;
            }
            let end = (off + sz).min(body.len());
            let boxtype = [body[off + 4], body[off + 5], body[off + 6], body[off + 7]];
            if &boxtype == b"tenc" {
                tenc = Some(TrackEncryptionBox::parse_box(&body[off..end])?);
            } else {
                extra_boxes.push(crate::init_segment::OpaqueBox {
                    box_type: boxtype,
                    data: body[off + 8..end].to_vec(),
                });
            }
            off += sz;
        }
        Ok(Self { tenc, extra_boxes })
    }
}

impl Serialize for SchemeInformationBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        let mut n = BOX_HDR;
        if let Some(ref t) = self.tenc {
            n += t.serialized_len();
        }
        for b in &self.extra_boxes {
            n += b.serialized_len();
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
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"schi");
        c += 4;
        if let Some(ref t) = self.tenc {
            c += t.serialize_into(&mut buf[c..])?;
        }
        for b in &self.extra_boxes {
            c += b.serialize_into(&mut buf[c..])?;
        }
        Ok(c)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ProtectionSchemeInfoBox {
    pub original_format: OriginalFormatBox,
    pub scheme_type: Option<SchemeTypeBox>,
    pub scheme_info: Option<SchemeInformationBox>,
    pub extra_boxes: Vec<crate::init_segment::OpaqueBox>,
}

impl<'a> Parse<'a> for ProtectionSchemeInfoBox {
    type Error = Error;
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        let body = &bytes[BOX_HDR..];
        if body.len() < 8 + 4 {
            return Err(Error::BufferTooShort {
                need: 8 + 4,
                have: bytes.len(),
                what: "sinf (frma)",
            });
        }
        let frma_sz = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
        let original_format = OriginalFormatBox::parse(&body[0..frma_sz])?;

        let mut off = frma_sz;
        let mut scheme_type = None;
        let mut scheme_info = None;
        let mut extra_boxes = Vec::new();

        while off + 8 <= body.len() {
            let sz = u32::from_be_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]])
                as usize;
            if sz < 8 {
                break;
            }
            let end = (off + sz).min(body.len());
            let boxtype = [body[off + 4], body[off + 5], body[off + 6], body[off + 7]];
            match &boxtype {
                b"schm" => {
                    scheme_type = Some(SchemeTypeBox::parse_body(
                        &body[off + BOX_HDR + FULL_HDR..end],
                        body[off + BOX_HDR],
                        u32::from_be_bytes([
                            0,
                            body[off + BOX_HDR + 1],
                            body[off + BOX_HDR + 2],
                            body[off + BOX_HDR + 3],
                        ]),
                    )?);
                }
                b"schi" => {
                    scheme_info = Some(SchemeInformationBox::parse(&body[off..end])?);
                }
                _ => {
                    extra_boxes.push(crate::init_segment::OpaqueBox {
                        box_type: boxtype,
                        data: body[off + 8..end].to_vec(),
                    });
                }
            }
            off += sz;
        }
        Ok(Self {
            original_format,
            scheme_type,
            scheme_info,
            extra_boxes,
        })
    }
}

impl Serialize for ProtectionSchemeInfoBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        let mut n = BOX_HDR;
        n += self.original_format.serialized_len();
        if let Some(ref st) = self.scheme_type {
            n += st.serialized_len();
        }
        if let Some(ref si) = self.scheme_info {
            n += si.serialized_len();
        }
        for b in &self.extra_boxes {
            n += b.serialized_len();
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
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"sinf");
        c += 4;
        c += self.original_format.serialize_into(&mut buf[c..])?;
        if let Some(ref st) = self.scheme_type {
            c += st.serialize_into(&mut buf[c..])?;
        }
        if let Some(ref si) = self.scheme_info {
            c += si.serialize_into(&mut buf[c..])?;
        }
        for b in &self.extra_boxes {
            c += b.serialize_into(&mut buf[c..])?;
        }
        Ok(c)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ConstantIvSenc {
    #[default]
    Emit,
    Omit,
}

impl ConstantIvSenc {
    pub fn name(&self) -> &'static str {
        match self {
            ConstantIvSenc::Emit => "emit",
            ConstantIvSenc::Omit => "omit",
        }
    }
}

#[cfg(test)]
mod senc_truncation_tests {
    use super::*;

    fn one_entry_two_subsamples() -> SampleEncryptionEntry {
        SampleEncryptionEntry {
            initialization_vector: alloc::vec![0u8; 8],
            subsamples: alloc::vec![
                SubSampleEntry { bytes_of_clear_data: 5, bytes_of_protected_data: 1200 },
                SubSampleEntry { bytes_of_clear_data: 0, bytes_of_protected_data: 600 },
            ],
            is_encrypted: true,
            explicit_kid: None,
        }
    }

    fn senc_body(entry: SampleEncryptionEntry) -> (Vec<u8>, u32, u8) {
        let flags = SENC_FLAG_USE_SUBSAMPLE_ENCRYPTION;
        let iv_size = entry.initialization_vector.len() as u8;
        let box_ = SampleEncryptionBox {
            version: 0,
            flags,
            per_sample_iv_size: iv_size,
            entries: alloc::vec![entry],
        };
        let mut buf = alloc::vec![0u8; box_.serialized_len()];
        box_.serialize_into(&mut buf).expect("serialize a well-formed senc box");
        (buf[BOX_HDR + FULL_HDR..].to_vec(), flags, iv_size)
    }

    #[test]
    fn full_senc_body_parses_and_round_trips() {
        let entry = one_entry_two_subsamples();
        let (body, flags, iv_size) = senc_body(entry.clone());

        let parsed = SampleEncryptionBox::parse_body(&body, 0, flags, iv_size)
            .expect("a complete, untruncated senc body must parse");
        assert_eq!(parsed.entries, alloc::vec![entry]);
    }

    #[test]
    fn body_truncated_by_2_bytes_matches_the_1206_vs_1204_production_error() {
        let (body, flags, iv_size) = senc_body(one_entry_two_subsamples());
        let truncated = &body[..body.len() - 2];

        let err = SampleEncryptionBox::parse_body(truncated, 0, flags, iv_size).unwrap_err();
        match err {
            Error::BufferTooShort { need, have, what } => {
                assert_eq!(have, truncated.len());
                assert_eq!(need - have, 2, "shortfall must match the exact 2-byte gap seen in production");
                assert_eq!(what, "senc subsample");
            }
            other => panic!("expected BufferTooShort while parsing the subsample table, got {other:?}"),
        }
    }

    #[test]
    fn body_truncated_by_4_bytes_matches_the_600_vs_596_production_error() {
        let (body, flags, iv_size) = senc_body(one_entry_two_subsamples());
        let truncated = &body[..body.len() - 4];

        let err = SampleEncryptionBox::parse_body(truncated, 0, flags, iv_size).unwrap_err();
        match err {
            Error::BufferTooShort { need, have, what } => {
                assert_eq!(have, truncated.len());
                assert_eq!(need - have, 4, "shortfall must match the exact 4-byte gap seen in production");
                assert_eq!(what, "senc subsample");
            }
            other => panic!("expected BufferTooShort while parsing the subsample table, got {other:?}"),
        }
    }

    #[test]
    fn a_1_byte_short_body_is_still_rejected_not_silently_misparsed() {
        let (body, flags, iv_size) = senc_body(one_entry_two_subsamples());
        let truncated = &body[..body.len() - 1];

        let err = SampleEncryptionBox::parse_body(truncated, 0, flags, iv_size);
        assert!(err.is_err(), "a body short by even 1 byte must never parse as Ok");
    }
}

bitforge::impl_spec_display!(ConstantIvSenc);