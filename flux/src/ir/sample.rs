//! Coded access units — [`Sample`], [`SampleFlags`], [`Provenance`].

use bytes::Bytes;

use crate::annexb::annexb_to_length_prefixed;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SampleFlags {
    pub is_sync: bool,
}

impl SampleFlags {
    pub const SYNC: SampleFlags = SampleFlags { is_sync: true };
    pub const NON_SYNC: SampleFlags = SampleFlags { is_sync: false };

    pub fn new(is_sync: bool) -> Self {
        Self { is_sync }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Provenance {
    pub wire_dts: Option<u64>,
    pub wire_pts: Option<u64>,
}

impl Provenance {
    pub fn new(wire_dts: Option<u64>, wire_pts: Option<u64>) -> Self {
        Self { wire_dts, wire_pts }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Sample {
    pub data: Bytes,
    pub dts: Option<i64>,
    pub pts: Option<i64>,
    pub duration: Option<u32>,
    pub flags: SampleFlags,
    pub provenance: Option<Provenance>,
}

impl Sample {
    pub fn new(
        data: impl Into<Bytes>,
        dts: Option<i64>,
        pts: Option<i64>,
        duration: Option<u32>,
        is_sync: bool,
    ) -> Self {
        Self {
            data: data.into(),
            dts,
            pts,
            duration,
            flags: SampleFlags::new(is_sync),
            provenance: None,
        }
    }

    pub fn from_annexb(
        annexb: &[u8],
        dts: Option<i64>,
        pts: Option<i64>,
        duration: Option<u32>,
        is_sync: bool,
    ) -> Self {
        Self {
            data: annexb_to_length_prefixed(annexb).into(),
            dts,
            pts,
            duration,
            flags: SampleFlags::new(is_sync),
            provenance: None,
        }
    }

    pub fn from_raw(
        data: impl Into<Bytes>,
        dts: Option<i64>,
        pts: Option<i64>,
        duration: Option<u32>,
    ) -> Self {
        Self {
            data: data.into(),
            dts,
            pts,
            duration,
            flags: SampleFlags::SYNC,
            provenance: None,
        }
    }

    pub fn with_provenance(mut self, p: Provenance) -> Self {
        self.provenance = Some(p);
        self
    }

    pub fn composition_offset(&self) -> i32 {
        match (self.dts, self.pts) {
            (Some(d), Some(p)) => (p - d) as i32,
            _ => 0,
        }
    }
}

