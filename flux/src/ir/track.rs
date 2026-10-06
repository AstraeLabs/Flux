//! Elementary track identity + crypto — [`Track`], [`TrackSpec`], [`TrackEncryption`].

use alloc::vec::Vec;

use super::{CodecConfig, Sample};

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TrackSpec {
    pub track_id: u32,
    pub timescale: u32,
    pub config: CodecConfig,
    pub edit_list: Option<crate::timing::EditListBox>,
}

impl TrackSpec {
    pub fn new(track_id: u32, timescale: u32, config: CodecConfig) -> Self {
        Self {
            track_id,
            timescale,
            config,
            edit_list: None,
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Track {
    pub spec: TrackSpec,
    pub samples: Vec<Sample>,
    pub start_decode_time: u64,
    pub encryption: Option<TrackEncryption>,
}

impl Track {
    pub fn new(spec: TrackSpec, samples: Vec<Sample>) -> Self {
        Self {
            spec,
            samples,
            start_decode_time: 0,
            encryption: None,
        }
    }

    pub fn track_id(&self) -> u32 {
        self.spec.track_id
    }

    pub fn timescale(&self) -> u32 {
        self.spec.timescale
    }

    pub fn config(&self) -> &CodecConfig {
        &self.spec.config
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TrackEncryption {
    pub scheme: crate::cenc::CencScheme,
    pub tenc: crate::cenc::TrackEncryptionBox,
    pub samples: Vec<crate::cenc::SampleEncryptionEntry>,
    pub constant_iv_senc: crate::cenc::ConstantIvSenc,
}

impl TrackEncryption {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scheme: crate::cenc::CencScheme,
        tenc: crate::cenc::TrackEncryptionBox,
        samples: Vec<crate::cenc::SampleEncryptionEntry>,
        constant_iv_senc: crate::cenc::ConstantIvSenc,
    ) -> Self {
        Self {
            scheme,
            tenc,
            samples,
            constant_iv_senc,
        }
    }
}
