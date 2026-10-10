//! Movie Fragment boxes - ISO/IEC 14496-12:2015 Â§8.8.

use crate::error::{Error, Result};
use alloc::vec::Vec;
use bitforge::Serialize;

const BOX_HEADER_SIZE: usize = 8;
const FULLBOX_EXTRA_SIZE: usize = 4;

pub const TFHD_BASE_DATA_OFFSET_PRESENT: u32 = 0x000001;
pub const TFHD_SAMPLE_DESCRIPTION_INDEX_PRESENT: u32 = 0x000002;
pub const TFHD_DEFAULT_SAMPLE_DURATION_PRESENT: u32 = 0x000008;
pub const TFHD_DEFAULT_SAMPLE_SIZE_PRESENT: u32 = 0x000010;
pub const TFHD_DEFAULT_SAMPLE_FLAGS_PRESENT: u32 = 0x000020;
pub const TFHD_DURATION_IS_EMPTY: u32 = 0x010000;
pub const TFHD_DEFAULT_BASE_IS_MOOF: u32 = 0x020000;

pub const TRUN_DATA_OFFSET_PRESENT: u32 = 0x000001;
pub const TRUN_FIRST_SAMPLE_FLAGS_PRESENT: u32 = 0x000004;
pub const TRUN_SAMPLE_DURATION_PRESENT: u32 = 0x000100;
pub const TRUN_SAMPLE_SIZE_PRESENT: u32 = 0x000200;
pub const TRUN_SAMPLE_FLAGS_PRESENT: u32 = 0x000400;
pub const TRUN_SAMPLE_COMPOSITION_TIME_OFFSET_PRESENT: u32 = 0x000800;

fn read_ver_flags(body: &[u8]) -> Result<(u8, u32)> {
    if body.len() < 4 {
        return Err(Error::BufferTooShort {
            need: 4,
            have: body.len(),
            what: "FullBox version/flags",
        });
    }
    let ver = body[0];
    let flags = u32::from_be_bytes([0, body[1], body[2], body[3]]);
    Ok((ver, flags))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct MovieFragmentHeaderBox {
    pub sequence_number: u32,
}

impl MovieFragmentHeaderBox {
    pub fn new(sequence_number: u32) -> Self {
        Self { sequence_number }
    }
    pub fn parse_body(body: &[u8]) -> Result<Self> {
        let (_ver, _flags) = read_ver_flags(body)?;
        let payload = &body[FULLBOX_EXTRA_SIZE..];
        if payload.len() < 4 {
            return Err(Error::BufferTooShort {
                need: 4,
                have: payload.len(),
                what: "mfhd.seq",
            });
        }
        Ok(Self {
            sequence_number: u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]),
        })
    }
}

impl Serialize for MovieFragmentHeaderBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        BOX_HEADER_SIZE + FULLBOX_EXTRA_SIZE + 4
    }
    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut c = 0;
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"mfhd");
        c += 4;
        buf[c..c + 4].copy_from_slice(&[0, 0, 0, 0]);
        c += 4;
        buf[c..c + 4].copy_from_slice(&self.sequence_number.to_be_bytes());
        Ok(c + 4)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TrackFragmentHeaderBox {
    pub flags: u32,
    pub track_id: u32,
    pub base_data_offset: Option<u64>,
    pub sample_description_index: Option<u32>,
    pub default_sample_duration: Option<u32>,
    pub default_sample_size: Option<u32>,
    pub default_sample_flags: Option<u32>,
}

impl TrackFragmentHeaderBox {
    pub fn parse_body(body: &[u8]) -> Result<Self> {
        let (_ver, flags) = read_ver_flags(body)?;
        let mut c = FULLBOX_EXTRA_SIZE;
        if body.len() < c + 4 {
            return Err(Error::BufferTooShort {
                need: c + 4,
                have: body.len(),
                what: "tfhd.track_id",
            });
        }
        let tid = u32::from_be_bytes([body[c], body[c + 1], body[c + 2], body[c + 3]]);
        c += 4;

        let v_bdo = if flags & TFHD_BASE_DATA_OFFSET_PRESENT != 0 {
            if body.len() < c + 8 {
                return Err(Error::BufferTooShort {
                    need: c + 8,
                    have: body.len(),
                    what: "tfhd.bdo",
                });
            }
            let v = u64::from_be_bytes([
                body[c],
                body[c + 1],
                body[c + 2],
                body[c + 3],
                body[c + 4],
                body[c + 5],
                body[c + 6],
                body[c + 7],
            ]);
            c += 8;
            Some(v)
        } else {
            None
        };
        let v_sdi = if flags & TFHD_SAMPLE_DESCRIPTION_INDEX_PRESENT != 0 {
            if body.len() < c + 4 {
                return Err(Error::BufferTooShort {
                    need: c + 4,
                    have: body.len(),
                    what: "tfhd.sdi",
                });
            }
            let v = u32::from_be_bytes([body[c], body[c + 1], body[c + 2], body[c + 3]]);
            c += 4;
            Some(v)
        } else {
            None
        };
        let v_dsd = if flags & TFHD_DEFAULT_SAMPLE_DURATION_PRESENT != 0 {
            if body.len() < c + 4 {
                return Err(Error::BufferTooShort {
                    need: c + 4,
                    have: body.len(),
                    what: "tfhd.dsd",
                });
            }
            let v = u32::from_be_bytes([body[c], body[c + 1], body[c + 2], body[c + 3]]);
            c += 4;
            Some(v)
        } else {
            None
        };
        let v_dss = if flags & TFHD_DEFAULT_SAMPLE_SIZE_PRESENT != 0 {
            if body.len() < c + 4 {
                return Err(Error::BufferTooShort {
                    need: c + 4,
                    have: body.len(),
                    what: "tfhd.dss",
                });
            }
            let v = u32::from_be_bytes([body[c], body[c + 1], body[c + 2], body[c + 3]]);
            c += 4;
            Some(v)
        } else {
            None
        };
        let v_dsf = if flags & TFHD_DEFAULT_SAMPLE_FLAGS_PRESENT != 0 {
            if body.len() < c + 4 {
                return Err(Error::BufferTooShort {
                    need: c + 4,
                    have: body.len(),
                    what: "tfhd.dsf",
                });
            }
            let v = u32::from_be_bytes([body[c], body[c + 1], body[c + 2], body[c + 3]]);

            Some(v)
        } else {
            None
        };
        Ok(TrackFragmentHeaderBox {
            flags,
            track_id: tid,
            base_data_offset: v_bdo,
            sample_description_index: v_sdi,
            default_sample_duration: v_dsd,
            default_sample_size: v_dss,
            default_sample_flags: v_dsf,
        })
    }
}

impl Serialize for TrackFragmentHeaderBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        let mut n = BOX_HEADER_SIZE + FULLBOX_EXTRA_SIZE + 4;
        if self.flags & TFHD_BASE_DATA_OFFSET_PRESENT != 0 {
            n += 8;
        }
        if self.flags & TFHD_SAMPLE_DESCRIPTION_INDEX_PRESENT != 0 {
            n += 4;
        }
        if self.flags & TFHD_DEFAULT_SAMPLE_DURATION_PRESENT != 0 {
            n += 4;
        }
        if self.flags & TFHD_DEFAULT_SAMPLE_SIZE_PRESENT != 0 {
            n += 4;
        }
        if self.flags & TFHD_DEFAULT_SAMPLE_FLAGS_PRESENT != 0 {
            n += 4;
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
        let mut c = 0;
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"tfhd");
        c += 4;
        buf[c] = 0;
        let fb = self.flags.to_be_bytes();
        buf[c + 1] = fb[1];
        buf[c + 2] = fb[2];
        buf[c + 3] = fb[3];
        c += 4;
        buf[c..c + 4].copy_from_slice(&self.track_id.to_be_bytes());
        c += 4;
        if self.flags & TFHD_BASE_DATA_OFFSET_PRESENT != 0 {
            buf[c..c + 8].copy_from_slice(&self.base_data_offset.unwrap_or(0).to_be_bytes());
            c += 8;
        }
        if self.flags & TFHD_SAMPLE_DESCRIPTION_INDEX_PRESENT != 0 {
            buf[c..c + 4]
                .copy_from_slice(&self.sample_description_index.unwrap_or(1).to_be_bytes());
            c += 4;
        }
        if self.flags & TFHD_DEFAULT_SAMPLE_DURATION_PRESENT != 0 {
            buf[c..c + 4].copy_from_slice(&self.default_sample_duration.unwrap_or(0).to_be_bytes());
            c += 4;
        }
        if self.flags & TFHD_DEFAULT_SAMPLE_SIZE_PRESENT != 0 {
            buf[c..c + 4].copy_from_slice(&self.default_sample_size.unwrap_or(0).to_be_bytes());
            c += 4;
        }
        if self.flags & TFHD_DEFAULT_SAMPLE_FLAGS_PRESENT != 0 {
            buf[c..c + 4].copy_from_slice(&self.default_sample_flags.unwrap_or(0).to_be_bytes());
            c += 4;
        }
        Ok(c)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TrackFragmentBaseMediaDecodeTimeBox {
    version: u8,
    v0: u32,
    v1: u64,
}

impl TrackFragmentBaseMediaDecodeTimeBox {
    pub fn new_v0(t: u32) -> Self {
        Self {
            version: 0,
            v0: t,
            v1: t as u64,
        }
    }
    pub fn new_v1(t: u64) -> Self {
        Self {
            version: 1,
            v0: t as u32,
            v1: t,
        }
    }
    pub fn base_media_decode_time(&self) -> u64 {
        self.v1
    }
    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn parse_body(body: &[u8]) -> Result<Self> {
        let (ver, _flags) = read_ver_flags(body)?;
        let payload = &body[FULLBOX_EXTRA_SIZE..];
        if ver == 0 {
            if payload.len() < 4 {
                return Err(Error::BufferTooShort {
                    need: 4,
                    have: payload.len(),
                    what: "tfdt.v0",
                });
            }
            let v = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            Ok(Self {
                version: ver,
                v0: v,
                v1: v as u64,
            })
        } else {
            if payload.len() < 8 {
                return Err(Error::BufferTooShort {
                    need: 8,
                    have: payload.len(),
                    what: "tfdt.v1",
                });
            }
            let v = u64::from_be_bytes([
                payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
                payload[7],
            ]);
            Ok(Self {
                version: ver,
                v0: v as u32,
                v1: v,
            })
        }
    }
}

impl Serialize for TrackFragmentBaseMediaDecodeTimeBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        BOX_HEADER_SIZE + FULLBOX_EXTRA_SIZE + if self.version == 0 { 4 } else { 8 }
    }
    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut c = 0;
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"tfdt");
        c += 4;
        buf[c] = self.version;
        buf[c + 1] = 0;
        buf[c + 2] = 0;
        buf[c + 3] = 0;
        c += 4;
        if self.version == 0 {
            buf[c..c + 4].copy_from_slice(&self.v0.to_be_bytes());
            c += 4;
        } else {
            buf[c..c + 8].copy_from_slice(&self.v1.to_be_bytes());
            c += 8;
        }
        Ok(c)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TrunSample {
    pub sample_duration: Option<u32>,
    pub sample_size: Option<u32>,
    pub sample_flags: Option<u32>,
    pub sample_composition_time_offset: Option<i64>,
}
impl TrunSample {
    pub const fn new() -> Self {
        Self {
            sample_duration: None,
            sample_size: None,
            sample_flags: None,
            sample_composition_time_offset: None,
        }
    }
}
impl Default for TrunSample {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TrackFragmentRunBox {
    pub version: u8,
    pub tr_flags: u32,
    pub data_offset: Option<i32>,
    pub first_sample_flags: Option<u32>,
    pub samples: Vec<TrunSample>,
}

/// Cap on `sample_count` when a `trun` carries no per-sample fields (so no data bounds it).
const MAX_TRUN_SAMPLES_NO_FIELDS: usize = 1 << 24;

impl TrackFragmentRunBox {
    pub fn parse_body(body: &[u8]) -> Result<Self> {
        let (ver, tr_flags) = read_ver_flags(body)?;
        let payload = &body[FULLBOX_EXTRA_SIZE..];
        if payload.len() < 4 {
            return Err(Error::BufferTooShort {
                need: 4,
                have: payload.len(),
                what: "trun.sc",
            });
        }
        let mut c = 0usize;
        let sc = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
        c += 4;

        let data_offset = if tr_flags & TRUN_DATA_OFFSET_PRESENT != 0 {
            if payload.len() < c + 4 {
                return Err(Error::BufferTooShort {
                    need: c + 4,
                    have: payload.len(),
                    what: "trun.do",
                });
            }
            let v =
                i32::from_be_bytes([payload[c], payload[c + 1], payload[c + 2], payload[c + 3]]);
            c += 4;
            Some(v)
        } else {
            None
        };
        let fsf = if tr_flags & TRUN_FIRST_SAMPLE_FLAGS_PRESENT != 0 {
            if payload.len() < c + 4 {
                return Err(Error::BufferTooShort {
                    need: c + 4,
                    have: payload.len(),
                    what: "trun.fsf",
                });
            }
            let v =
                u32::from_be_bytes([payload[c], payload[c + 1], payload[c + 2], payload[c + 3]]);
            c += 4;
            Some(v)
        } else {
            None
        };

        let has_dur = tr_flags & TRUN_SAMPLE_DURATION_PRESENT != 0;
        let has_sz = tr_flags & TRUN_SAMPLE_SIZE_PRESENT != 0;
        let has_flg = tr_flags & TRUN_SAMPLE_FLAGS_PRESENT != 0;
        let has_cto = tr_flags & TRUN_SAMPLE_COMPOSITION_TIME_OFFSET_PRESENT != 0;

        let stride = 4 * (has_dur as usize + has_sz as usize + has_flg as usize + has_cto as usize);
        if stride > 0 {
            if sc > payload.len().saturating_sub(c) / stride {
                return Err(Error::BufferTooShort {
                    need: c.saturating_add(sc.saturating_mul(stride)),
                    have: payload.len(),
                    what: "trun sample table",
                });
            }
        } else if sc > MAX_TRUN_SAMPLES_NO_FIELDS {
            return Err(Error::InvalidValue {
                field: "trun.sample_count",
                value: sc as u64,
                reason: "too many samples for a trun without per-sample fields",
            });
        }
        let mut samples = Vec::with_capacity(sc);
        for _ in 0..sc {
            let mut s = TrunSample::new();
            if has_dur {
                if payload.len() < c + 4 {
                    return Err(Error::BufferTooShort {
                        need: c + 4,
                        have: payload.len(),
                        what: "trun.dur",
                    });
                }
                s.sample_duration = Some(u32::from_be_bytes([
                    payload[c],
                    payload[c + 1],
                    payload[c + 2],
                    payload[c + 3],
                ]));
                c += 4;
            }
            if has_sz {
                if payload.len() < c + 4 {
                    return Err(Error::BufferTooShort {
                        need: c + 4,
                        have: payload.len(),
                        what: "trun.sz",
                    });
                }
                s.sample_size = Some(u32::from_be_bytes([
                    payload[c],
                    payload[c + 1],
                    payload[c + 2],
                    payload[c + 3],
                ]));
                c += 4;
            }
            if has_flg {
                if payload.len() < c + 4 {
                    return Err(Error::BufferTooShort {
                        need: c + 4,
                        have: payload.len(),
                        what: "trun.flg",
                    });
                }
                s.sample_flags = Some(u32::from_be_bytes([
                    payload[c],
                    payload[c + 1],
                    payload[c + 2],
                    payload[c + 3],
                ]));
                c += 4;
            }
            if has_cto {
                if payload.len() < c + 4 {
                    return Err(Error::BufferTooShort {
                        need: c + 4,
                        have: payload.len(),
                        what: "trun.cto",
                    });
                }
                if ver == 1 {
                    s.sample_composition_time_offset = Some(i32::from_be_bytes([
                        payload[c],
                        payload[c + 1],
                        payload[c + 2],
                        payload[c + 3],
                    ]) as i64);
                } else {
                    s.sample_composition_time_offset = Some(u32::from_be_bytes([
                        payload[c],
                        payload[c + 1],
                        payload[c + 2],
                        payload[c + 3],
                    ]) as i64);
                }
                c += 4;
            }
            samples.push(s);
        }
        Ok(TrackFragmentRunBox {
            version: ver,
            tr_flags,
            data_offset,
            first_sample_flags: fsf,
            samples,
        })
    }

    pub fn record_stride(flags: u32) -> usize {
        let mut n = 0u32;
        if flags & TRUN_SAMPLE_DURATION_PRESENT != 0 {
            n += 1;
        }
        if flags & TRUN_SAMPLE_SIZE_PRESENT != 0 {
            n += 1;
        }
        if flags & TRUN_SAMPLE_FLAGS_PRESENT != 0 {
            n += 1;
        }
        if flags & TRUN_SAMPLE_COMPOSITION_TIME_OFFSET_PRESENT != 0 {
            n += 1;
        }
        (n * 4) as usize
    }
}

impl Serialize for TrackFragmentRunBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        let mut n = BOX_HEADER_SIZE + FULLBOX_EXTRA_SIZE + 4;
        if self.tr_flags & TRUN_DATA_OFFSET_PRESENT != 0 {
            n += 4;
        }
        if self.tr_flags & TRUN_FIRST_SAMPLE_FLAGS_PRESENT != 0 {
            n += 4;
        }
        n + self.samples.len() * Self::record_stride(self.tr_flags)
    }
    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        let mut c = 0;
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"trun");
        c += 4;
        buf[c] = self.version;
        let fb = self.tr_flags.to_be_bytes();
        buf[c + 1] = fb[1];
        buf[c + 2] = fb[2];
        buf[c + 3] = fb[3];
        c += 4;
        buf[c..c + 4].copy_from_slice(&(self.samples.len() as u32).to_be_bytes());
        c += 4;
        if self.tr_flags & TRUN_DATA_OFFSET_PRESENT != 0 {
            buf[c..c + 4].copy_from_slice(&self.data_offset.unwrap_or(0).to_be_bytes());
            c += 4;
        }
        if self.tr_flags & TRUN_FIRST_SAMPLE_FLAGS_PRESENT != 0 {
            buf[c..c + 4].copy_from_slice(&self.first_sample_flags.unwrap_or(0).to_be_bytes());
            c += 4;
        }
        let has_dur = self.tr_flags & TRUN_SAMPLE_DURATION_PRESENT != 0;
        let has_sz = self.tr_flags & TRUN_SAMPLE_SIZE_PRESENT != 0;
        let has_flg = self.tr_flags & TRUN_SAMPLE_FLAGS_PRESENT != 0;
        let has_cto = self.tr_flags & TRUN_SAMPLE_COMPOSITION_TIME_OFFSET_PRESENT != 0;
        for s in &self.samples {
            if has_dur {
                buf[c..c + 4].copy_from_slice(&s.sample_duration.unwrap_or(0).to_be_bytes());
                c += 4;
            }
            if has_sz {
                buf[c..c + 4].copy_from_slice(&s.sample_size.unwrap_or(0).to_be_bytes());
                c += 4;
            }
            if has_flg {
                buf[c..c + 4].copy_from_slice(&s.sample_flags.unwrap_or(0).to_be_bytes());
                c += 4;
            }
            if has_cto {
                let cto = s.sample_composition_time_offset.unwrap_or(0);
                let bytes: [u8; 4] = if self.version == 1 {
                    (cto as i32).to_be_bytes()
                } else {
                    (cto as u32).to_be_bytes()
                };
                buf[c..c + 4].copy_from_slice(&bytes);
                c += 4;
            }
        }
        Ok(c)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TrackFragmentBox {
    pub tfhd: TrackFragmentHeaderBox,
    pub tfdt: Option<TrackFragmentBaseMediaDecodeTimeBox>,
    pub trun: Vec<TrackFragmentRunBox>,
}

impl TrackFragmentBox {
    pub fn parse_body(body: &[u8]) -> Result<Self> {
        use crate::box_types::parse_box;
        let mut tfhd: Option<TrackFragmentHeaderBox> = None;
        let mut tfdt: Option<TrackFragmentBaseMediaDecodeTimeBox> = None;
        let mut trun: Vec<TrackFragmentRunBox> = Vec::new();
        let mut remaining = body;
        while !remaining.is_empty() {
            let (bx, consumed) = parse_box(remaining)?;
            if bx.header.box_type.is(b"tfhd") {
                tfhd = Some(TrackFragmentHeaderBox::parse_body(bx.body)?);
            } else if bx.header.box_type.is(b"tfdt") {
                tfdt = Some(TrackFragmentBaseMediaDecodeTimeBox::parse_body(bx.body)?);
            } else if bx.header.box_type.is(b"trun") {
                trun.push(TrackFragmentRunBox::parse_body(bx.body)?);
            }
            if consumed == 0 {
                break;
            }
            remaining = &remaining[consumed.min(remaining.len())..];
        }
        let tfhd = tfhd.ok_or(Error::BufferTooShort {
            need: 1,
            have: 0,
            what: "traf missing tfhd",
        })?;
        if trun.is_empty() {
            return Err(Error::BufferTooShort {
                need: 1,
                have: 0,
                what: "traf missing trun",
            });
        }
        Ok(TrackFragmentBox { tfhd, tfdt, trun })
    }
}

impl Serialize for TrackFragmentBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        let mut n = BOX_HEADER_SIZE + self.tfhd.serialized_len();
        if let Some(ref t) = self.tfdt {
            n += t.serialized_len();
        }
        for r in &self.trun {
            n += r.serialized_len();
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
        let mut c = 0;
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"traf");
        c += 4;
        c += self.tfhd.serialize_into(&mut buf[c..])?;
        if let Some(ref t) = self.tfdt {
            c += t.serialize_into(&mut buf[c..])?;
        }
        for r in &self.trun {
            c += r.serialize_into(&mut buf[c..])?;
        }
        Ok(c)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct MovieFragmentBox {
    pub mfhd: MovieFragmentHeaderBox,
    pub traf: Vec<TrackFragmentBox>,
}

impl MovieFragmentBox {
    pub fn parse_body(body: &[u8]) -> Result<Self> {
        use crate::box_types::parse_box;
        let mut mfhd: Option<MovieFragmentHeaderBox> = None;
        let mut traf: Vec<TrackFragmentBox> = Vec::new();
        let mut remaining = body;
        while !remaining.is_empty() {
            let (bx, consumed) = parse_box(remaining)?;
            if bx.header.box_type.is(b"mfhd") {
                mfhd = Some(MovieFragmentHeaderBox::parse_body(bx.body)?);
            } else if bx.header.box_type.is(b"traf") {
                traf.push(TrackFragmentBox::parse_body(bx.body)?);
            }
            if consumed == 0 {
                break;
            }
            remaining = &remaining[consumed.min(remaining.len())..];
        }
        let mfhd = mfhd.ok_or(Error::BufferTooShort {
            need: 1,
            have: 0,
            what: "moof missing mfhd",
        })?;
        if traf.is_empty() {
            return Err(Error::BufferTooShort {
                need: 1,
                have: 0,
                what: "moof missing traf",
            });
        }
        Ok(MovieFragmentBox { mfhd, traf })
    }
}

impl Serialize for MovieFragmentBox {
    type Error = Error;
    fn serialized_len(&self) -> usize {
        let mut n = BOX_HEADER_SIZE + self.mfhd.serialized_len();
        for t in &self.traf {
            n += t.serialized_len();
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
        let mut c = 0;
        buf[c..c + 4].copy_from_slice(&(need as u32).to_be_bytes());
        c += 4;
        buf[c..c + 4].copy_from_slice(b"moof");
        c += 4;
        c += self.mfhd.serialize_into(&mut buf[c..])?;
        for t in &self.traf {
            c += t.serialize_into(&mut buf[c..])?;
        }
        Ok(c)
    }
}

const SENC_ENTRIES_OFFSET: u64 = 16;
const SAIZ_SUBSAMPLE_COUNT_SIZE: usize = 2;
const SAIZ_SUBSAMPLE_ENTRY_SIZE: usize = 6;

pub struct FragmentProtection<'a> {
    pub track_id: u32,
    pub entries: &'a [crate::cenc::SampleEncryptionEntry],
    pub per_sample_iv_size: u8,
}

struct CencFragmentBoxes {
    senc: crate::cenc::SampleEncryptionBox,
    saiz: crate::cenc::SampleAuxInfoSizesBox,
    saio: crate::cenc::SampleAuxInfoOffsetsBox,
}

impl CencFragmentBoxes {
    fn added_len(&self) -> usize {
        self.senc.serialized_len() + self.saiz.serialized_len() + self.saio.serialized_len()
    }
}

fn build_cenc_fragment_boxes(p: &FragmentProtection<'_>) -> Result<Option<CencFragmentBoxes>> {
    let use_subsamples = p.entries.iter().any(|e| !e.subsamples.is_empty());
    if p.per_sample_iv_size == 0 && !use_subsamples {
        return Ok(None);
    }
    let flags = if use_subsamples {
        crate::cenc::SENC_FLAG_USE_SUBSAMPLE_ENCRYPTION
    } else {
        0
    };
    let senc = crate::cenc::SampleEncryptionBox {
        version: 0,
        flags,
        per_sample_iv_size: p.per_sample_iv_size,
        entries: p.entries.to_vec(),
    };

    let mut sizes = Vec::with_capacity(p.entries.len());
    for e in p.entries {
        let mut sz = p.per_sample_iv_size as usize;
        if use_subsamples {
            sz += SAIZ_SUBSAMPLE_COUNT_SIZE + e.subsamples.len() * SAIZ_SUBSAMPLE_ENTRY_SIZE;
        }
        if sz > u8::MAX as usize {
            return Err(Error::InvalidInput(
                "protect_media_segment: per-sample aux info size exceeds 255 bytes (saiz sample_info_size is u8)",
            ));
        }
        sizes.push(sz as u8);
    }
    let uniform = sizes
        .first()
        .copied()
        .filter(|first| sizes.iter().all(|s| s == first));
    let saiz = crate::cenc::SampleAuxInfoSizesBox {
        version: 0,
        flags: 0,
        aux_info_type: None,
        aux_info_type_parameter: None,
        default_sample_info_size: uniform.unwrap_or(0),
        sample_info_sizes: if uniform.is_some() { Vec::new() } else { sizes },
    };
    let saio = crate::cenc::SampleAuxInfoOffsetsBox {
        version: 0,
        flags: 0,
        aux_info_type: None,
        aux_info_type_parameter: None,
        offsets: alloc::vec![0u64],
    };
    Ok(Some(CencFragmentBoxes { senc, saiz, saio }))
}

pub fn protect_media_segment(
    media_segment: &[u8],
    protections: &[FragmentProtection<'_>],
) -> Result<Vec<u8>> {
    if protections.is_empty() {
        return Ok(media_segment.to_vec());
    }

    let mut prefix_len = 0usize;
    let mut moof_len = None;
    for step in crate::box_types::box_iter(media_segment) {
        let (box_ref, consumed) = step?;
        if box_ref.header.box_type.is(b"moof") {
            moof_len = Some(consumed);
            break;
        }
        prefix_len += consumed;
    }
    let moof_len = moof_len.ok_or(Error::UnexpectedBox { expected: "moof" })?;
    let moof_bytes = &media_segment[prefix_len..prefix_len + moof_len];
    let suffix = &media_segment[prefix_len + moof_len..];

    let mut moof = MovieFragmentBox::parse_body(&moof_bytes[BOX_HEADER_SIZE..])?;

    let mut built: Vec<Option<CencFragmentBoxes>> = (0..moof.traf.len()).map(|_| None).collect();
    for p in protections {
        let idx = moof
            .traf
            .iter()
            .position(|t| t.tfhd.track_id == p.track_id)
            .ok_or(Error::InvalidInput(
                "protect_media_segment: track_id not present in moof",
            ))?;
        let sample_count: usize = moof.traf[idx].trun.iter().map(|r| r.samples.len()).sum();
        if sample_count != p.entries.len() {
            return Err(Error::InvalidInput(
                "protect_media_segment: entries.len() must equal the traf's total trun sample count",
            ));
        }
        built[idx] = build_cenc_fragment_boxes(p)?;
    }

    let base_lens: Vec<usize> = moof.traf.iter().map(|t| t.serialized_len()).collect();
    let final_lens: Vec<usize> = base_lens
        .iter()
        .zip(&built)
        .map(|(&base, b)| base + b.as_ref().map(CencFragmentBoxes::added_len).unwrap_or(0))
        .collect();

    let mfhd_len = moof.mfhd.serialized_len();
    let new_moof_len = BOX_HEADER_SIZE + mfhd_len + final_lens.iter().sum::<usize>();
    let delta = (new_moof_len as i64).saturating_sub(moof_len as i64);

    let mut running = (BOX_HEADER_SIZE + mfhd_len) as u64;
    for (i, traf) in moof.traf.iter_mut().enumerate() {
        if let Some(b) = built[i].as_mut() {
            let senc_start = running + base_lens[i] as u64;
            b.saio.offsets[0] = senc_start + SENC_ENTRIES_OFFSET;
        }
        running += final_lens[i] as u64;

        for run in &mut traf.trun {
            if run.tr_flags & TRUN_DATA_OFFSET_PRESENT != 0 {
                let new_off = i64::from(run.data_offset.unwrap_or(0))
                    .checked_add(delta)
                    .and_then(|v| i32::try_from(v).ok())
                    .ok_or(Error::InvalidInput(
                        "protect_media_segment: trun data_offset overflows i32 after moof resize",
                    ))?;
                run.data_offset = Some(new_off);
            }
        }
    }

    let mut moof_out = alloc::vec![0u8; new_moof_len];
    moof_out[0..4].copy_from_slice(
        &u32::try_from(new_moof_len)
            .map_err(|_| Error::InvalidInput("protect_media_segment: moof too large"))?
            .to_be_bytes(),
    );
    moof_out[4..8].copy_from_slice(b"moof");
    let mut c = BOX_HEADER_SIZE;
    c += moof.mfhd.serialize_into(&mut moof_out[c..])?;
    for (i, traf) in moof.traf.iter().enumerate() {
        let start = c;
        c += traf.serialize_into(&mut moof_out[c..])?;
        if let Some(b) = &built[i] {
            c += b.senc.serialize_into(&mut moof_out[c..])?;
            c += b.saiz.serialize_into(&mut moof_out[c..])?;
            c += b.saio.serialize_into(&mut moof_out[c..])?;
            let final_len = u32::try_from(c - start)
                .map_err(|_| Error::InvalidInput("protect_media_segment: traf too large"))?;
            moof_out[start..start + 4].copy_from_slice(&final_len.to_be_bytes());
        }
    }
    if c != new_moof_len {
        return Err(Error::InvalidInput(
            "moof length/senc offset consistency check failed",
        ));
    }

    let mut out = Vec::with_capacity(prefix_len + new_moof_len + suffix.len());
    out.extend_from_slice(&media_segment[..prefix_len]);
    out.extend_from_slice(&moof_out);
    out.extend_from_slice(suffix);
    Ok(out)
}

#[cfg(test)]
mod hardening_tests {
    use super::*;

    fn trun_body(flags: u32, sample_count: u32, rest: &[u8]) -> Vec<u8> {
        let mut v = alloc::vec![0u8];
        v.extend_from_slice(&flags.to_be_bytes()[1..]);
        v.extend_from_slice(&sample_count.to_be_bytes());
        v.extend_from_slice(rest);
        v
    }

    #[test]
    fn trun_huge_sample_count_with_fields_errors() {
        let b = trun_body(TRUN_SAMPLE_SIZE_PRESENT, 0xFFFF_FFFF, &[0; 8]);
        assert!(TrackFragmentRunBox::parse_body(&b).is_err());
    }

    #[test]
    fn trun_huge_sample_count_without_fields_errors() {
        let b = trun_body(0, 0xFFFF_FFFF, &[]);
        assert!(TrackFragmentRunBox::parse_body(&b).is_err());
    }

    #[test]
    fn trun_zero_samples_ok() {
        let b = trun_body(TRUN_SAMPLE_SIZE_PRESENT, 0, &[]);
        assert!(TrackFragmentRunBox::parse_body(&b).unwrap().samples.is_empty());
    }
}
