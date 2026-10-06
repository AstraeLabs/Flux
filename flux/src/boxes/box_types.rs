//! ISOBMFF Box/FullBox layer — ISO/IEC 14496-12:2015 §4.2.

use crate::error::{Error, Result};
use bitforge::{Parse, Serialize};
use core::fmt;

pub const SIZE_INDICATES_LARGESIZE: u32 = 1;
pub const SIZE_TO_EOF: u32 = 0;
pub const UUID_TYPE_BYTES: [u8; 4] = *b"uuid";
pub const BOX_HEADER_MIN_SIZE: usize = 8;
pub const LARGESIZE_SIZE: usize = 8;
pub const UUID_TYPE_SIZE: usize = 16;
pub const FULLBOX_EXTRA_SIZE: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct BoxType(pub [u8; 4]);

impl BoxType {

    pub const fn from_bytes(b: [u8; 4]) -> Self {
        Self(b)
    }

    pub fn from_u32(v: u32) -> Self {
        Self(v.to_be_bytes())
    }

    pub fn to_u32(self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    pub fn is(&self, literal: &[u8; 4]) -> bool {
        self.0 == *literal
    }

    pub fn name(&self) -> &'static str {

        match &self.0 {
            b"ftyp" => "ftyp",
            b"moov" => "moov",
            b"moof" => "moof",
            b"trak" => "trak",
            b"mdia" => "mdia",
            b"minf" => "minf",
            b"stbl" => "stbl",
            b"dinf" => "dinf",
            b"edts" => "edts",
            b"mvex" => "mvex",
            b"mvhd" => "mvhd",
            b"tkhd" => "tkhd",
            b"mdhd" => "mdhd",
            b"hdlr" => "hdlr",
            b"vmhd" => "vmhd",
            b"smhd" => "smhd",
            b"stsd" => "stsd",
            b"stts" => "stts",
            b"stsc" => "stsc",
            b"stsz" => "stsz",
            b"stco" => "stco",
            b"co64" => "co64",
            b"ctts" => "ctts",
            b"stss" => "stss",
            b"stsh" => "stsh",
            b"elst" => "elst",
            b"dref" => "dref",
            b"tref" => "tref",
            b"mdat" => "mdat",
            b"free" => "free",
            b"skip" => "skip",
            b"uuid" => "uuid",
            b"mfhd" => "mfhd",
            b"traf" => "traf",
            b"tfhd" => "tfhd",
            b"trun" => "trun",
            b"tfdt" => "tfdt",
            b"sidx" => "sidx",
            b"styp" => "styp",
            b"mfra" => "mfra",
            b"tfra" => "tfra",
            b"mfro" => "mfro",
            b"emsg" => "emsg",
            b"avc1" => "avc1",
            b"mp4a" => "mp4a",
            b"enca" => "enca",
            b"encv" => "encv",
            b"hvc1" => "hvc1",
            b"avcC" => "avcC",
            b"hvcC" => "hvcC",
            b"avc2" => "avc2",
            b"avc3" => "avc3",
            b"avc4" => "avc4",
            b"hev1" => "hev1",
            _ => "<unknown>",
        }
    }
}

impl fmt::Display for BoxType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &b in &self.0 {
            if b.is_ascii_graphic() || b == b' ' {
                f.write_str(core::str::from_utf8(&[b]).unwrap_or("?"))?;
            } else {
                write!(f, "\\x{b:02x}")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct BoxHeader {
    pub size: u64,
    pub box_type: BoxType,
    pub usertype: Option<[u8; UUID_TYPE_SIZE]>,
    has_largesize: bool,
}

impl BoxHeader {

    pub fn header_size(&self) -> usize {
        let mut sz = BOX_HEADER_MIN_SIZE;
        if self.has_largesize {
            sz += LARGESIZE_SIZE;
        }
        if self.box_type.is(b"uuid") {
            sz += UUID_TYPE_SIZE;
        }
        sz
    }

    pub fn new(size: u64, box_type: BoxType, usertype: Option<[u8; UUID_TYPE_SIZE]>) -> Self {
        let has_largesize = size > u32::MAX as u64;
        Self {
            size,
            box_type,
            usertype,
            has_largesize,
        }
    }
}

impl<'a> Parse<'a> for BoxHeader {
    type Error = Error;

    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < BOX_HEADER_MIN_SIZE {
            return Err(Error::BufferTooShort {
                need: BOX_HEADER_MIN_SIZE,
                have: bytes.len(),
                what: "BoxHeader",
            });
        }

        let raw_size = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let box_type = BoxType::from_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        let mut cursor = BOX_HEADER_MIN_SIZE;

        let size: u64 = if raw_size == SIZE_INDICATES_LARGESIZE {
            if bytes.len() < cursor + LARGESIZE_SIZE {
                return Err(Error::LargesizeBufferTooShort {
                    need: cursor + LARGESIZE_SIZE,
                    have: bytes.len(),
                });
            }
            let v = u64::from_be_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
                bytes[cursor + 4],
                bytes[cursor + 5],
                bytes[cursor + 6],
                bytes[cursor + 7],
            ]);
            cursor += LARGESIZE_SIZE;
            v
        } else {
            raw_size as u64
        };

        if size != 0 && size < cursor as u64 {
            return Err(Error::BoxSizeUnderflow {
                size,
                header_size: cursor,
            });
        }

        let usertype = if box_type.is(b"uuid") {
            if bytes.len() < cursor + UUID_TYPE_SIZE {
                return Err(Error::UuidBufferTooShort {
                    need: cursor + UUID_TYPE_SIZE,
                    have: bytes.len(),
                });
            }
            let mut ut = [0u8; UUID_TYPE_SIZE];
            ut.copy_from_slice(&bytes[cursor..cursor + UUID_TYPE_SIZE]);
            Some(ut)
        } else {
            None
        };

        let has_largesize = raw_size == SIZE_INDICATES_LARGESIZE;

        Ok(Self {
            size,
            box_type,
            usertype,
            has_largesize,
        })
    }
}

impl Serialize for BoxHeader {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        self.header_size()
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.header_size();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }

        let mut cursor = 0usize;
        if self.size > u32::MAX as u64 {

            buf[0..4].copy_from_slice(&SIZE_INDICATES_LARGESIZE.to_be_bytes());
            cursor += 4;
            buf[cursor..cursor + 4].copy_from_slice(&self.box_type.to_u32().to_be_bytes());
            cursor += 4;
            buf[cursor..cursor + 8].copy_from_slice(&self.size.to_be_bytes());
            cursor += 8;
        } else {
            let size32 = self.size as u32;
            buf[0..4].copy_from_slice(&size32.to_be_bytes());
            cursor += 4;
            buf[cursor..cursor + 4].copy_from_slice(&self.box_type.to_u32().to_be_bytes());
            cursor += 4;
            if size32 == SIZE_INDICATES_LARGESIZE {

            }
        }

        if self.box_type.is(b"uuid")
            && let Some(ut) = &self.usertype
        {
            buf[cursor..cursor + UUID_TYPE_SIZE].copy_from_slice(ut);
            cursor += UUID_TYPE_SIZE;
        }

        Ok(cursor)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FullBoxHeader {
    pub box_header: BoxHeader,
    pub version: u8,
    pub flags: u32,
}

impl FullBoxHeader {

    pub fn new(box_header: BoxHeader, version: u8, flags: u32) -> Self {
        debug_assert!(flags <= 0xFFFFFF, "flags must fit in 24 bits");
        Self {
            box_header,
            version,
            flags,
        }
    }
}

impl<'a> Parse<'a> for FullBoxHeader {
    type Error = Error;

    fn parse(bytes: &'a [u8]) -> Result<Self> {
        let box_header = BoxHeader::parse(bytes)?;
        let hdr_sz = box_header.header_size();

        if bytes.len() < hdr_sz + FULLBOX_EXTRA_SIZE {
            return Err(Error::BufferTooShort {
                need: hdr_sz + FULLBOX_EXTRA_SIZE,
                have: bytes.len(),
                what: "FullBoxHeader",
            });
        }

        let version = bytes[hdr_sz];
        let flags =
            u32::from_be_bytes([0, bytes[hdr_sz + 1], bytes[hdr_sz + 2], bytes[hdr_sz + 3]]);

        Ok(Self {
            box_header,
            version,
            flags,
        })
    }
}

impl Serialize for FullBoxHeader {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        self.box_header.serialized_len() + FULLBOX_EXTRA_SIZE
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let base_len = self.box_header.serialized_len();
        let need = base_len + FULLBOX_EXTRA_SIZE;
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }

        let cursor = self.box_header.serialize_into(buf)?;
        buf[cursor] = self.version;
        let flag_bytes = self.flags.to_be_bytes();
        buf[cursor + 1] = flag_bytes[1];
        buf[cursor + 2] = flag_bytes[2];
        buf[cursor + 3] = flag_bytes[3];
        Ok(cursor + FULLBOX_EXTRA_SIZE)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BoxRef<'a> {

    pub header: BoxHeader,

    pub body: &'a [u8],
}

pub fn parse_box<'a>(bytes: &'a [u8]) -> Result<(BoxRef<'a>, usize)> {
    let header = BoxHeader::parse(bytes)?;
    let hdr_sz = header.header_size();

    let body: &'a [u8] = if header.size == SIZE_TO_EOF as u64 {

        &bytes[hdr_sz..]
    } else {
        let total = header.size as usize;
        if total < hdr_sz {
            return Err(Error::BoxSizeUnderflow {
                size: header.size,
                header_size: hdr_sz,
            });
        }
        if bytes.len() < total {
            return Err(Error::BufferTooShort {
                need: total,
                have: bytes.len(),
                what: "BoxRef body",
            });
        }
        &bytes[hdr_sz..total]
    };

    let consumed = if header.size == 0 {
        bytes.len()
    } else {
        header.size as usize
    };

    Ok((BoxRef { header, body }, consumed))
}

#[derive(Debug, Clone)]
pub struct BoxIter<'a> {
    remaining: &'a [u8],
}

impl<'a> BoxIter<'a> {

    pub fn new(data: &'a [u8]) -> Self {
        Self { remaining: data }
    }
}

impl<'a> Iterator for BoxIter<'a> {
    type Item = Result<(BoxRef<'a>, usize)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }

        match parse_box(self.remaining) {
            Ok((box_ref, consumed)) => {
                self.remaining = &self.remaining[consumed.min(self.remaining.len())..];
                Some(Ok((box_ref, consumed)))
            }
            Err(e) => {

                self.remaining = &[];
                Some(Err(e))
            }
        }
    }
}

pub fn box_iter(data: &[u8]) -> BoxIter<'_> {
    BoxIter::new(data)
}